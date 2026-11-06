"""The admin's documentation tools: an IT asset inventory, a wiki and a
password vault, running as real software on a server of the lab.

A real IT department writes things down in three places. The inventory
knows every machine, what is in it and who sits at it; the wiki holds the
runbooks (how a server is built, what to do when it breaks); the vault holds
the passwords of the service accounts, shared with the team and with nobody
else. In winlab all three run on the "Admin tools server" of the device
shelf, a Debian 12 machine (the Debian cloud team's image, appliances.py
``debian12``), and the student manages them from a browser on a lab PC (Edge
on a Windows machine, Firefox on the Admin workstation), as at work.

What was chosen, and why:

- Inventory: GLPI (GPL-3.0-or-later, glpi-project.org), PHP on Apache with
  MariaDB, and the GLPI Agent (GPL-2.0-or-later) on the Windows machines,
  which sends their hardware and software to GLPI's native inventory. It is
  what small IT departments run, it installs from a tarball on a plain LAMP
  stack whose every package is in Debian 12's archive (PHP 8.2, MariaDB
  10.11), and the agent is one MSI that rolls out by hand or by Group
  Policy. NetBox (Apache-2.0) was the alternative: it documents racks,
  cables and IP addresses, not PCs and their owners, and it wants Python
  packages from PyPI and Redis that Debian 12 does not carry in the versions
  it needs, so it would not install cleanly offline from packs.
- Wiki: DokuWiki (GPL-2.0-or-later, dokuwiki.org): flat text files, no
  database, the classic admin's runbook wiki. Debian 12 no longer packages
  it, so its own stable tarball is fetched.
- Vault: Vaultwarden (AGPL-3.0-only), the Bitwarden-compatible server, with
  the Bitwarden web vault (GPL-3.0) inside its image. It publishes no
  standalone binary, only container images, so the image is pulled from
  Docker Hub's registry API here (winlab/containers.py, every layer checked
  against its digest, the tag pinned to its index digest) and runs under
  Debian's own docker.io. Organisations and collections, the sharing a team
  needs, are free in it.

Nothing is bundled. Everything is fetched on this PC by a winlab command
(``winlab docs fetch``, or Setup) into three packs (winlab/debpacks.py) for
the debian12 image: ``glpi`` (Apache, PHP, MariaDB from the Debian archive
and GLPI's release tarball from its GitHub release), ``dokuwiki`` (Apache and
PHP, and DokuWiki's stable tarball) and ``vaultwarden`` (docker.io and the
image tar). The machine's Settings plug each in as a stick. The GLPI Agent
MSI comes from its GitHub release onto a "GLPI Agent" stick for the PCs, and
the lab's staff directory (winlab/people.py) onto a "Staff directory" stick,
because the student sets each PC's owner from it.

Hands-on: winlab installs and configures none of it. The device comes as a
plain Debian 12 server; the student installs each package from its stick,
creates the database, runs GLPI's web installer, DokuWiki's install.php and
Vaultwarden's first account, and puts TLS in front of the vault (with a
certificate from the lab's CA when the lab has one, or a self-signed one).

Grading reads the end state inside the machine through the guest runner,
never with the student's app passwords: GLPI's tables through MariaDB's
root socket (the database name read from GLPI's own config_db.php), the
wiki's page files, and Vaultwarden's SQLite database through python3 (in
the image for cloud-init), where organisations, members and collection
links are plain rows even though every item in them is encrypted.

What is checksum-verified how: the Vaultwarden image by its pinned index
digest and each blob's digest; GLPI and the GLPI Agent by the SHA-256 digest
GitHub publishes for each release asset (refused when there is none);
DokuWiki publishes no checksum, so winlab records the SHA-256 it got, as it
does for k3s's install.sh. None of these URLs could be checked from the
sandbox this was written in, except Docker Hub's registry, which answered
for the pinned Vaultwarden tag and digest.
"""

from __future__ import annotations

import json
import re
import shutil
import tarfile
import time
from pathlib import Path

from . import adminui, paths
from .adminui import AdminGui, Target
from .bootstrap import BootstrapError, _download_to, _get

DEVICE = "doctools"
ROLE = "doc-tools"
IMAGE = "debian12"
PACKS = ("glpi", "dokuwiki", "vaultwarden")
DOWNLOAD_ID = "glpi-agent"   # node vars downloads = ["glpi-agent"] on the PCs
JOB = "glpiagent-fetch"
GITHUB_API = "https://api.github.com/repos"

# GLPI: the 11.0 line, which runs on Debian 12's PHP 8.2 and MariaDB 10.11.
GLPI = "GLPI"
GLPI_LICENSE = "GPL-3.0-or-later"
GLPI_REPO = "glpi-project/glpi"
GLPI_LINE = "11."
GLPI_ASSET = r"^glpi-(\d+\.\d+\.\d+)\.tgz$"
GLPI_PAGE = "https://glpi-project.org/"
GLPI_PORT = 80

AGENT = "GLPI Agent"
AGENT_LICENSE = "GPL-2.0-or-later"
AGENT_REPO = "glpi-project/glpi-agent"
AGENT_ASSET = r"^GLPI-Agent-(\d+(?:\.\d+)+)-x64\.msi$"
AGENT_PAGE = "https://glpi-agent.readthedocs.io/"
AGENT_SERVICE = "glpi-agent"
AGENT_SIZE_TEXT = "about 20 MB"
AGENT_STICK_LABEL = "GLPIAGENT"
AGENT_STEP_LABEL = "Fetch the GLPI Agent (its GitHub release)"

DOKUWIKI = "DokuWiki"
DOKUWIKI_LICENSE = "GPL-2.0-or-later"
DOKUWIKI_URL = "https://download.dokuwiki.org/src/dokuwiki/dokuwiki-stable.tgz"
DOKUWIKI_PAGE = "https://www.dokuwiki.org/"
DOKUWIKI_PATH = "/dokuwiki/"

VAULTWARDEN = "Vaultwarden"
VAULTWARDEN_LICENSE = "AGPL-3.0-only (web vault GPL-3.0)"
# The tag and the digest of its multi-platform index, as Docker Hub served
# them when this was pinned: the pull is refused if the index differs.
VAULTWARDEN_TAG = "1.37.4"
VAULTWARDEN_DIGEST = "sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055"
VAULTWARDEN_REF = f"vaultwarden/server:{VAULTWARDEN_TAG}@{VAULTWARDEN_DIGEST}"
VAULTWARDEN_PAGE = "https://github.com/dani-garcia/vaultwarden"
VAULT_PORT = 8443

STAFF_STICK_LABEL = "HR"
STAFF_CSV = "Staff directory.csv"
STAFF_TXT = "Staff directory.txt"


class DocsError(Exception):
    pass


# debpacks.fetch catches a pack's extra-files error by this name.
ExtraError = DocsError


# ------------------------------------------------------- GitHub releases
def pick_asset(assets: list[dict], pattern: str) -> dict | None:
    hit = sorted((a for a in assets if re.match(pattern, str(a.get("name", "")))), key=lambda a: a["name"])
    return hit[0] if hit else None


def asset_sha256(asset: dict) -> str:
    """The SHA-256 GitHub publishes for a release asset ('' when none)."""
    digest = str(asset.get("digest") or "")
    sha = digest.split(":", 1)[1].lower() if digest.lower().startswith("sha256:") else ""
    return sha if re.fullmatch(r"[0-9a-f]{64}", sha) else ""


def pick_release(releases: list[dict], line: str = "") -> dict | None:
    """The newest published release (no draft, no pre-release) whose tag
    starts with ``line`` ('11.' for GLPI 11.x), by version, not by date."""
    def key(r: dict) -> tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"\d+", str(r.get("tag_name", ""))))
    ok = [r for r in releases if isinstance(r, dict) and not r.get("draft") and not r.get("prerelease")
          and str(r.get("tag_name", "")).lstrip("v").startswith(line)]
    return max(ok, key=key) if ok else None


def github_asset(repo: str, pattern: str, line: str = "", get=_get) -> dict:
    """{version, file, url, sha256} of a project's release asset. The
    SHA-256 must be published (GitHub's asset digest): an asset without one
    is refused rather than fetched unverified."""
    url = f"{GITHUB_API}/{repo}/releases?per_page=30" if line else f"{GITHUB_API}/{repo}/releases/latest"
    try:
        doc = json.loads(get(url, timeout=30).decode("utf-8"))
    except (BootstrapError, ValueError) as exc:
        raise DocsError(f"GitHub does not answer for {repo} ({exc}); try again later") from exc
    rel = pick_release(doc if isinstance(doc, list) else [doc], line)
    if rel is None:
        raise DocsError(f"{repo} has no published release{' of the ' + line + 'x line' if line else ''}")
    asset = pick_asset(list(rel.get("assets") or []), pattern)
    if asset is None:
        raise DocsError(f"{repo} {rel.get('tag_name')} has no file matching {pattern}")
    sha = asset_sha256(asset)
    if not sha:
        raise DocsError(f"{repo} {rel.get('tag_name')}: GitHub publishes no SHA-256 for {asset['name']}; "
                        "winlab does not fetch it unverified")
    m = re.match(pattern, asset["name"])
    return {"version": m.group(1) if m and m.groups() else str(rel.get("tag_name", "")).lstrip("v"),
            "file": str(asset["name"]), "url": str(asset["browser_download_url"]), "sha256": sha}


# --------------------------------------------- the packs' extra files
def _tar_members(path: Path) -> list[str]:
    try:
        with tarfile.open(path, "r:*") as tf:
            return tf.getnames()
    except (tarfile.TarError, OSError) as exc:
        raise DocsError(f"{path.name} is not a readable tarball ({exc})") from exc


def dokuwiki_version(path: Path) -> str:
    """The release a DokuWiki tarball holds, from its VERSION file
    ('2025-05-14b "Librarian"'), or '' when it has none."""
    try:
        with tarfile.open(path, "r:*") as tf:
            for m in tf.getmembers():
                if re.fullmatch(r"[^/]+/VERSION", m.name) and m.isfile():
                    fh = tf.extractfile(m)
                    return fh.read(200).decode("utf-8", "replace").strip() if fh else ""
    except (tarfile.TarError, OSError):
        return ""
    return ""


def _sha256(p: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _fetch_glpi(d: Path, get, download, say) -> dict:
    a = github_asset(GLPI_REPO, GLPI_ASSET, GLPI_LINE, get)
    say(f"{GLPI} {a['version']} from {a['url']}")
    try:
        download(a["url"], d / a["file"], expect_sha=a["sha256"], label=a["file"])
    except BootstrapError as exc:
        raise DocsError(str(exc)) from exc
    if not any(n.endswith("glpi/index.php") or n.endswith("glpi/public/index.php") for n in _tar_members(d / a["file"])):
        raise DocsError(f"{a['file']} holds no glpi/ tree")
    return {"name": GLPI, "version": a["version"], "license": GLPI_LICENSE, "file": a["file"],
            "sha256": a["sha256"], "checksum": "published", "source": a["url"]}


def _fetch_dokuwiki(d: Path, get, download, say) -> dict:
    name = "dokuwiki-stable.tgz"
    say(f"{DOKUWIKI} stable from {DOKUWIKI_URL} (DokuWiki publishes no checksum: winlab records the SHA-256 it got)")
    try:
        download(DOKUWIKI_URL, d / name, label=name)
    except BootstrapError as exc:
        raise DocsError(str(exc)) from exc
    if not any(re.fullmatch(r"[^/]+/doku\.php", n) for n in _tar_members(d / name)):
        (d / name).unlink(missing_ok=True)
        raise DocsError(f"{DOKUWIKI_URL} is not a DokuWiki release (no doku.php in it)")
    version = dokuwiki_version(d / name)
    return {"name": DOKUWIKI, "version": version, "license": DOKUWIKI_LICENSE, "file": name,
            "sha256": _sha256(d / name), "checksum": "recorded", "source": DOKUWIKI_URL}


# A seam the tests replace: the registry's HTTP transport.
def _transport():
    from . import containers
    return containers.http_open


def _fetch_vaultwarden(d: Path, say) -> dict:
    from . import containers
    entry = {"ref": VAULTWARDEN_REF, "os": "linux"}
    say(f"{VAULTWARDEN} {VAULTWARDEN_TAG} from Docker Hub ({VAULTWARDEN_DIGEST[:19]}…)")
    try:
        rec = containers.fetch_image(entry, containers.Registry(_transport()), say)
    except containers.ContainerError as exc:
        raise DocsError(str(exc)) from exc
    finally:
        cache = containers.store() / "cache" / "blobs"
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
    src = containers.images_dir() / rec["file"]
    shutil.move(str(src), str(d / rec["file"]))
    return {"name": VAULTWARDEN, "version": VAULTWARDEN_TAG, "license": VAULTWARDEN_LICENSE,
            "file": rec["file"], "sha256": _sha256(d / rec["file"]), "digest": rec["digest"],
            "checksum": "digests", "source": rec["source"], "image": f"vaultwarden/server:{VAULTWARDEN_TAG}"}


def fetch_extra(pack, d: Path, closure, get, download, say) -> dict:
    """After a pack's .debs (debpacks.fetch): the application itself."""
    if pack.id == "glpi":
        rec = _fetch_glpi(d, get, download, say)
    elif pack.id == "dokuwiki":
        rec = _fetch_dokuwiki(d, get, download, say)
    elif pack.id == "vaultwarden":
        rec = _fetch_vaultwarden(d, say)
    else:
        raise DocsError(f"no extra files for pack {pack.id}")
    rec["files"] = [rec["file"], "INSTALL.txt"]
    (d / "INSTALL.txt").write_text(install_text(pack.id, rec), encoding="utf-8", newline="\r\n")
    return rec


def extra_ready(d: Path, man: dict) -> bool:
    files = (man.get("extra") or {}).get("files") or []
    return bool(files) and all((d / f).is_file() and (d / f).stat().st_size > 0 for f in files)


def install_text(pack_id: str, rec: dict) -> str:
    """The note beside the application on its stick: where to start, never
    the configuration itself (the lessons walk through it)."""
    head = [f"{rec['name']} {rec.get('version', '')} ({rec['license']})",
            f"from {rec['source']}, fetched {time.strftime('%Y-%m-%d')}, "
            + {"published": "checked against the SHA-256 GitHub publishes for it.",
               "recorded": f"SHA-256 {rec['sha256']} (recorded: the project publishes none).",
               "digests": f"index {VAULTWARDEN_DIGEST}, every layer checked against its digest."}[rec["checksum"]],
            "", "First install the packages from this stick (README.txt). Then:"]
    if pack_id == "glpi":
        body = [f"  sudo tar -xzf /mnt/winlab-pack/{rec['file']} -C /var/www",
                "  sudo chown -R www-data:www-data /var/www/glpi",
                "  an Apache site whose DocumentRoot is /var/www/glpi/public (GLPI 11), a database and its",
                "  user in MariaDB, then the web installer at http://<this server>/ from a lab PC."]
    elif pack_id == "dokuwiki":
        body = [f"  sudo tar -xzf /mnt/winlab-pack/{rec['file']} -C /var/www",
                "  sudo mv /var/www/dokuwiki-* /var/www/dokuwiki   (the folder carries the release's date)",
                "  sudo chown -R www-data:www-data /var/www/dokuwiki",
                "  an Apache Alias /dokuwiki for it, then http://<this server>/dokuwiki/install.php from a lab PC,",
                "  and delete install.php when it is done."]
    else:
        body = [f"  sudo docker load -i /mnt/winlab-pack/{rec['file']}",
                f"  docker images shows {rec.get('image', '')}. Run it with its data in a folder of this",
                "  server (-v /srv/vaultwarden:/data) and TLS (ROCKET_TLS), published on port 8443;",
                "  the web vault only works over https."]
    return "\n".join(head + body) + "\n"


# ------------------------------------------------------- the GLPI Agent
def agent_dir() -> Path:
    return paths.RUNTIME / "glpi-agent"


def agent_meta() -> dict:
    try:
        return json.loads((agent_dir() / "agent.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def agent_ready() -> bool:
    m = agent_meta()
    f = agent_dir() / m.get("file", "-")
    return bool(m.get("file")) and f.is_file() and f.stat().st_size > 0


def fetch_agent(progress=None, get=_get, download=_download_to) -> dict:
    """The current GLPI Agent MSI for 64-bit Windows from its GitHub release,
    checked against the SHA-256 GitHub publishes for it."""
    say = progress or (lambda _m: None)
    a = github_asset(AGENT_REPO, AGENT_ASSET, "", get)
    d = agent_dir()
    d.mkdir(parents=True, exist_ok=True)
    say(f"{AGENT} {a['version']} from {a['url']}")
    try:
        download(a["url"], d / a["file"], expect_sha=a["sha256"], label=a["file"])
    except BootstrapError as exc:
        raise DocsError(str(exc)) from exc
    m = {"name": AGENT, "version": a["version"], "license": AGENT_LICENSE, "file": a["file"],
         "sha256": a["sha256"], "source": a["url"], "fetched": time.strftime("%Y-%m-%d")}
    (d / "agent.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
    for f in d.iterdir():
        if f.name not in (a["file"], "agent.json"):
            f.unlink()
    say(f"{AGENT} {a['version']} ready: {d}")
    return m


def agent_readme(m: dict, server: str = "tools01.corp.lab") -> str:
    msi = m.get("file", "GLPI-Agent-x64.msi")
    return "\r\n".join([
        f"{AGENT} {m.get('version', '')} ({AGENT_LICENSE}), from {m.get('source', AGENT_REPO)}",
        f"fetched {m.get('fetched', '?')}, checked against the SHA-256 GitHub publishes for it.", "",
        "By hand, on each Windows machine (an elevated prompt, the stick is D: or E:):",
        f"  msiexec /i E:\\{msi} /quiet SERVER=http://{server}/front/inventory.php RUNNOW=1",
        f"  Get-Service {AGENT_SERVICE}   (Running, Automatic); it sends an inventory now and then once a day.", "",
        "By Group Policy: copy the MSI to a share every computer account can read (\\\\fs01\\Software), then",
        "a computer startup script that runs the same msiexec line from the share, or a Software",
        "installation package with a transform that sets SERVER (the MSI alone does not know your server).", "",
        "In GLPI first: Administration > Inventory > Enable inventory. Otherwise GLPI refuses what agents send.",
        "",
    ])


def agent_stick_files() -> dict[str, bytes]:
    if not agent_ready():
        raise DocsError(f"the {AGENT} is not on this PC yet: winlab docs fetch agent (or Images, {AGENT})")
    m = agent_meta()
    return {m["file"]: (agent_dir() / m["file"]).read_bytes(), "README.txt": agent_readme(m).encode("utf-8")}


# ------------------------------------------------- the staff directory
def staff_stick_files(lab) -> dict[str, bytes]:
    """The lab's staff directory as HR hands it to IT: a CSV and a printout."""
    from . import people
    staff = people.load(lab)
    return {STAFF_CSV: people.directory_csv(staff).encode("utf-8"),
            STAFF_TXT: people.directory_text(staff, lab.domain or "corp.lab").encode("utf-8")}


# ------------------------------------------------------------ the sticks
STICKS = {"agent": ("GLPI Agent", "glpi-agent", AGENT_STICK_LABEL),
          "staff": ("Staff directory", "staff-directory", STAFF_STICK_LABEL)}


def to_stick(lab, kind: str) -> dict:
    """A new stick on the lab's media shelf: the GLPI Agent or the staff
    directory."""
    from . import media, mediashelf
    if kind not in STICKS:
        raise DocsError(f"which stick? {', '.join(STICKS)}")
    title, base, label = STICKS[kind]
    files = agent_stick_files() if kind == "agent" else staff_stick_files(lab)
    if kind == "agent":
        title += f" ({agent_meta().get('version', '')})"
    sid = mediashelf._new_id(lab.name, base)
    d = mediashelf.shelf_dir(lab.name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", label)
    except media.MediaError as exc:
        raise DocsError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files), "mb": sum(len(b) for b in files.values()) >> 20}


# ------------------------------------------------------------- the lab
def tools_node(lab):
    """The lab's Admin tools server, or None."""
    from . import appliance
    return next((n for n in lab.node_list() if appliance.device_of(n) == DEVICE), None)


def wants_agent(lab) -> list[str]:
    return [n.id for n in lab.node_list() if DOWNLOAD_ID in (n.vars.get("downloads") or [])]


def shelf_view(lab) -> dict | None:
    """What the media shelf offers for this lab (None: nothing, the buttons
    stay hidden)."""
    if tools_node(lab) is None and not wants_agent(lab):
        return None
    return {"agent": agent_ready(), "staff": True}


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """The GLPI Agent fetch, for a lab whose PCs name it; the three packs
    come through mail.setup_steps (the tools server's vars packs)."""
    who = wants_agent(lab)
    if not who or "glpi-agent" in set(have or ()):
        return []
    return [{"id": "glpi-agent", "label": AGENT_STEP_LABEL, "done": agent_ready(), "blocked": False,
             "hint": f"{', '.join(who)} install it from the GLPI Agent stick: the 64-bit MSI, {AGENT_LICENSE}, "
                     f"checked against the SHA-256 GitHub publishes, {AGENT_SIZE_TEXT} once",
             "link": AGENT_PAGE, "job": JOB}]


def fault_params(lab) -> dict[str, str]:
    n = tools_node(lab)
    nic = n.primary_nic if n is not None else None
    name = (n.hostname or n.id).lower() if n is not None else "the tools server"
    host = f"{name}.{lab.domain}" if n is not None and lab.domain else name
    return {"toolsserver": host, "toolsip": nic.ip if nic and nic.ip else ""}


def act(dash, action: str, params: dict) -> dict:
    """wb-docs-stick writes the GLPI Agent or the staff directory stick."""
    if action == "wb-docs-stick":
        kind = str(params.get("kind", ""))
        try:
            r = to_stick(dash.lab, kind)
        except DocsError as exc:
            return {"ok": False, "message": str(exc), "fetch": kind == "agent" and not agent_ready(), "job": JOB}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto a machine", "stick": r["id"]}
    return {"ok": False, "message": f"unknown docs action {action!r}"}


# ------------------------------------------------------------ status
def summary() -> dict:
    from . import debpacks
    m = agent_meta()
    packs = {}
    for pid in PACKS:
        man = debpacks.manifest(pid)
        packs[pid] = {"ready": debpacks.ready(pid), "version": (man.get("extra") or {}).get("version", ""),
                      "fetched": man.get("fetched", "")}
    return {"agent": {"ready": agent_ready(), "version": m.get("version", ""), "fetched": m.get("fetched", ""),
                      "license": AGENT_LICENSE, "page": AGENT_PAGE,
                      "size_mb": round((agent_dir() / m["file"]).stat().st_size / 1048576, 1) if agent_ready() else 0},
            "packs": packs}


def render_status() -> str:
    s = summary()
    a = s["agent"]
    lines = ["the admin's documentation tools (Admin tools server, debian12)", ""]
    for pid, p in s["packs"].items():
        state = f"ready ({p['version'] or '?'}, fetched {p['fetched']})" if p["ready"] else "not fetched"
        lines.append(f"  pack {pid:<12} {state}")
    lines.append(f"  {'glpi-agent':<17} " + (f"ready {a['version']}, fetched {a['fetched']}" if a["ready"]
                                            else f"not fetched ({AGENT_SIZE_TEXT})"))
    lines += ["", "  fetch:       winlab docs fetch [agent|packs|all]  (the packs need the debian12 image first)",
              "  onto sticks: winlab docs stick <lab> agent|staff, or the media shelf", ""]
    return "\n".join(lines)


def fetch(what: str = "all", progress=None) -> list[str]:
    """`winlab docs fetch`: the agent and/or the three packs; returns the
    errors (one failing part does not stop the others)."""
    from . import debpacks
    say = progress or (lambda _m: None)
    errors = []
    if what in ("agent", "all"):
        try:
            fetch_agent(say)
        except DocsError as exc:
            errors.append(f"{AGENT}: {exc}")
    if what in ("packs", "all"):
        for pid in PACKS:
            try:
                debpacks.fetch(pid, progress=say)
            except debpacks.PackError as exc:
                errors.append(f"pack {pid}: {exc}")
    if what not in ("agent", "packs", "all"):
        errors.append(f"fetch what? agent, packs or all, not {what!r}")
    return errors


# ------------------------------------------------------------- the GUIs
def _address(lab, node) -> str:
    nic = node.primary_nic
    return nic.ip if nic is not None and nic.ip else (node.hostname or node.id).lower()


GLPI_GUI = AdminGui(
    software=f"{GLPI} {GLPI_LINE}x (asset inventory)", scheme="http", port=GLPI_PORT, path="/",
    sign_in="the accounts GLPI's installer creates; change their passwords or disable them first, GLPI warns until you do",
    license=GLPI_LICENSE,
    note="Once you install it from the glpi pack: computers, their owners and what the GLPI Agent reports from each PC.")
WIKI_GUI = AdminGui(
    software=f"{DOKUWIKI} (runbook wiki)", scheme="http", port=80, path=DOKUWIKI_PATH,
    sign_in="the superuser you create in install.php", license=DOKUWIKI_LICENSE,
    note="Once you install it from the dokuwiki pack: a runbook page per server under runbooks:, pages are text files.")
VAULT_GUI = AdminGui(
    software=f"{VAULTWARDEN} {VAULTWARDEN_TAG} (password vault)", scheme="https", port=VAULT_PORT, path="/",
    sign_in="the account you create on its first page (then turn sign-ups off)", license=VAULTWARDEN_LICENSE,
    note="Once you load and run it from the vaultwarden pack, with TLS: the web vault refuses plain http.")


def _node_gui(lab, node):
    from . import appliance
    return GLPI_GUI if appliance.device_of(node) == DEVICE else None


def _targets(lab) -> list[Target]:
    from . import appliance, webmin
    out = []
    for node in lab.node_list():
        if appliance.device_of(node) == DEVICE:
            host = _address(lab, node)
            out.append(Target(webmin.target_key(node.id, "wiki"), "Wiki", host, WIKI_GUI))
            out.append(Target(webmin.target_key(node.id, "vault"), "Vault", host, VAULT_GUI))
    return out


adminui.register(node_gui=_node_gui, targets=_targets)


# ------------------------------------------------------------ the drills
def _wiki_root() -> str:
    # The folder DokuWiki was unpacked into, wherever under /var/www.
    return 'r=$(dirname "$(find /var/www -maxdepth 3 -name doku.php 2>/dev/null | head -1)"); '


def _faults():
    from .guestfaults import LINUX, WINDOWS, GuestFault
    need_agent = ("if (-not (Get-Service " + AGENT_SERVICE + " -ErrorAction SilentlyContinue)) { "
                  "'no GLPI Agent on this PC: roll it out first (lesson it-docs-inventory)'; exit 1 }; ")
    need_wiki = (_wiki_root() + '[ "$r" != . ] && [ -d "$r/data/pages" ] || { echo "no DokuWiki under /var/www on '
                 'this server: install it first (lesson it-docs-wiki)"; exit 1; }; ')
    need_glpi = ("command -v mariadb >/dev/null 2>&1 && ls /var/www/*/config/config_db.php /etc/glpi/config_db.php "
                 ">/dev/null 2>&1 || { echo 'no GLPI with its MariaDB database on this server: install it first "
                 "(lesson it-docs-inventory)'; exit 1; }; ")
    return [
        GuestFault(
            id="docs-agent-stopped",
            os=WINDOWS,
            title="A PC stops showing up in the inventory",
            teaches="that an inventory is only as fresh as its agents: the GLPI Agent service, its start type, "
                    "and the Last contact GLPI shows for each agent",
            symptom="in GLPI (Administration > Inventory > Agents) this PC's Last contact stays days old while "
                    "the others are from today; software installed on it since never appears",
            apply=(need_agent + f"Stop-Service {AGENT_SERVICE} -Force; Set-Service {AGENT_SERVICE} -StartupType "
                   "Disabled; 'broken'"),
            clear=(f"Set-Service {AGENT_SERVICE} -StartupType Automatic -ErrorAction SilentlyContinue; "
                   f"Start-Service {AGENT_SERVICE} -ErrorAction SilentlyContinue; 'ok'"),
            hints=(
                "GLPI is not wrong: it shows what agents send. Which machine stopped sending? In GLPI, Administration "
                "> Inventory > Agents, sort by Last contact. Then look on that PC.",
                f"On the PC: Get-Service {AGENT_SERVICE} | Select-Object Status, StartType. Stopped, and set to "
                "Disabled, so a restart does not bring it back either.",
                f"Set-Service {AGENT_SERVICE} -StartupType Automatic; Start-Service {AGENT_SERVICE}. To send at once "
                "instead of waiting a day: open http://127.0.0.1:62354 on the PC and press Force an Inventory. "
                "Last contact in GLPI becomes now.",
            ),
            verify=(f"$s = Get-Service {AGENT_SERVICE} -ErrorAction SilentlyContinue; "
                    "[bool]($s -and $s.Status -eq 'Running' -and $s.StartType -eq 'Automatic')"),
        ),
        GuestFault(
            id="docs-wiki-readonly",
            images=(IMAGE,),
            os=LINUX,
            title="The wiki shows pages and will not save an edit",
            teaches="who the web server runs as (www-data), which DokuWiki folders it must write (data/pages, "
                    "meta, attic, cache, locks) and reading the error DokuWiki and Apache give",
            symptom="editing a runbook ends in 'Sorry, you can't edit this page' or a red 'Writing ... not possible' "
                    "message; reading still works, so nobody noticed until the next incident",
            apply=(need_wiki + 'stat -c %U:%G "$r/data" > /root/.winlab-wiki-owner; chown -R root:root "$r/data" '
                   '&& chmod -R go-w "$r/data" && echo broken'),
            clear=(_wiki_root() + 'o=$(cat /root/.winlab-wiki-owner 2>/dev/null || echo www-data:www-data); '
                   '[ "$r" != . ] && chown -R "$o" "$r/data"; rm -f /root/.winlab-wiki-owner; echo ok'),
            shell="sh",
            hints=(
                "Reading works and writing does not: think files, not the network. Which user writes them? Apache "
                "runs PHP as www-data (ps -o user= -C apache2 | sort -u).",
                "ls -ld /var/www/dokuwiki/data /var/www/dokuwiki/data/pages: owned by root, not writable by "
                "www-data. DokuWiki's own check, Admin > Configuration Settings, names each folder it cannot write.",
                "sudo chown -R www-data:www-data /var/www/dokuwiki/data, then edit and save a page. sudo -u www-data "
                "test -w /var/www/dokuwiki/data/pages && echo ok proves it from the shell.",
            ),
            verify=(_wiki_root() + 'for x in pages meta attic cache locks; do runuser -u www-data -- test -w '
                    '"$r/data/$x" || { echo False; exit 0; }; done; echo True'),
        ),
        GuestFault(
            id="docs-glpi-db-down",
            images=(IMAGE,),
            os=LINUX,
            title="GLPI answers with a database connection error after a reboot",
            teaches="the layers under a web application (Apache, PHP, MariaDB), systemctl is-enabled versus "
                    "is-active, and reading GLPI's own error page and logs",
            symptom="http://{toolsserver}/ shows GLPI's 'A link to the SQL server could not be established' page; "
                    "agents' inventories are refused, so nothing new arrives",
            apply=(need_glpi + "systemctl disable --now mariadb >/dev/null 2>&1 && echo broken"),
            clear="systemctl enable --now mariadb >/dev/null 2>&1; echo ok",
            shell="sh",
            hints=(
                "GLPI itself is up: Apache answered. The page names the layer underneath: the database. Is it "
                "running? systemctl status mariadb.",
                "Inactive (dead), and systemctl is-enabled mariadb says disabled: it would not come back after a "
                "reboot either. journalctl -u mariadb -n 20 shows it was stopped, not crashed.",
                "sudo systemctl enable --now mariadb. Reload GLPI's page; then on a PC force an agent inventory and "
                "watch Last contact move.",
            ),
            verify=("systemctl is-active -q mariadb && systemctl is-enabled -q mariadb && echo True || echo False"),
        ),
    ]


FAULT_IDS = ("docs-agent-stopped", "docs-wiki-readonly", "docs-glpi-db-down")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
