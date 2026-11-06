"""Security operations in a sealed lab: the tools a defender runs every day,
carried in on sticks, installed and configured by the student.

The security-ops lab (content/labs/security-ops.toml) has no internet, like
every lab. What it needs from outside is fetched here, on this PC, checked,
and written onto sticks on the lab's media shelf. Nothing is bundled with
winlab, and nothing is installed or configured for the student: the lessons
walk through each tool inside the machines.

- Wazuh, the SIEM: the 'wazuh' pack (winlab/debpacks.py) resolves the
  manager, the indexer, the dashboard and Filebeat from Wazuh's own signed
  apt repository against the Ubuntu image, every component on one 4.x
  release. Its extra files (fetch_extra below) are the Windows agent MSI of
  that same release, checked against the SHA-512 Wazuh publishes for it, and
  the certificate tool, its config.yml, Filebeat's configuration, Wazuh's
  index template and Filebeat module, whose SHA-256 winlab records (Wazuh
  publishes none for them). The agent goes onto a "Wazuh agent" stick of its
  own for the Windows machines.
- Greenbone Community Edition, the vulnerability scanner: Greenbone's own
  compose file, read from its documentation, names the images (gvmd, gsa,
  ospd-openvas, openvas-scanner, pg-gvm, redis and the feed data images:
  vulnerability tests, notus, SCAP, CERT-Bund, DFN-CERT, data objects, report
  formats, the GPG key). Each is pulled from registry.community.greenbone.net
  through containers.Registry, every layer checked against its digest, and
  pinned: by the digest winlab ships for it (GB_PINS) or, until one is
  shipped, by the digest the first fetch saw, kept in a lock file that every
  later fetch must match (--repin moves it on purpose). The images and the
  compose file go onto as many "Greenbone" sticks as they need. It scans the
  lab's own machines and nothing else: there is nothing else to reach.
- Software to deploy: 7-Zip's 64-bit MSI from its GitHub release (pinned,
  checked against the SHA-256 GitHub publishes) for Group Policy software
  installation, and Chocolatey's own package (chocolatey.<version>.nupkg,
  pinned, checked against the SHA-512 the community feed publishes) for an
  internal feed on a share. They go onto a "Software" stick.
- Microsoft's Security Compliance Toolkit: the baselines (one zip per
  product), Policy Analyzer and LGPO come under Microsoft's terms, so the
  user downloads them from Microsoft (SCT_PAGE) and winlab only finds them on
  this PC and writes them onto an "SCT" stick, as updates.py does with .msu
  files. `winlab secops sct-fetch <link> --yes` downloads one from a
  download.microsoft.com link the user pastes, with their consent.

Eight graded faults register with guestfaults: a WEF source that can no
longer read its Security log, a Wazuh agent pointed at a server that is gone,
a scan target that stopped answering ping, a standalone server whose legacy
audit policy overrides the baseline's, the software share that computers
cannot read, Chocolatey sent back to the internet, a certificate weeks from
expiry that autoenrolment will never renew, and the daily report's log folder
locked against the gMSA.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import time
import urllib.parse
import zipfile
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to, _get


class SecopsError(Exception):
    pass


# debpacks.fetch catches a pack's extra-files error by this name.
ExtraError = SecopsError


def store() -> Path:
    return paths.RUNTIME / "secops"


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _meta(f: Path) -> dict:
    try:
        d = json.loads(f.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


# ================================================================ software
SEVENZIP = "7-Zip"
SEVENZIP_VERSION = "25.01"
SEVENZIP_REPO = "ip7z/7zip"
SEVENZIP_FILE = "7z2501-x64.msi"
SEVENZIP_LICENSE = "LGPL-2.1-or-later with the unRAR restriction (some parts BSD-3-Clause)"
SEVENZIP_PAGE = "https://www.7-zip.org/"
CHOCO = "Chocolatey CLI"
CHOCO_VERSION = "2.5.1"
CHOCO_LICENSE = "Apache-2.0"
CHOCO_FEED = "https://community.chocolatey.org/api/v2"
CHOCO_PAGE = "https://docs.chocolatey.org/en-us/choco/setup/#completely-offline-install"
GITHUB_API = "https://api.github.com/repos"
SOFTWARE_SIZE_TEXT = "about 8 MB"
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # an MSI is an OLE compound file


def software_dir() -> Path:
    return store() / "software"


def software_meta() -> dict:
    return _meta(software_dir() / "software.json")


def software_ready() -> bool:
    files = software_meta().get("files") or {}
    return {"7zip", "chocolatey"} <= set(files) and all(
        (software_dir() / f["file"]).is_file() for f in files.values())


def sevenzip_asset(get=_get) -> dict:
    """The pinned 7-Zip MSI on its GitHub release, with the SHA-256 GitHub
    publishes for it; refused when GitHub publishes none."""
    from .doctools import asset_sha256
    url = f"{GITHUB_API}/{SEVENZIP_REPO}/releases/tags/{SEVENZIP_VERSION}"
    try:
        doc = json.loads(get(url, timeout=30).decode("utf-8"))
    except (BootstrapError, ValueError) as exc:
        raise SecopsError(f"GitHub does not answer for {SEVENZIP_REPO} {SEVENZIP_VERSION} ({exc})") from exc
    asset = next((a for a in doc.get("assets") or [] if isinstance(a, dict) and a.get("name") == SEVENZIP_FILE), None)
    if asset is None:
        raise SecopsError(f"{SEVENZIP_REPO} {SEVENZIP_VERSION} has no {SEVENZIP_FILE}")
    sha = asset_sha256(asset)
    if not sha:
        raise SecopsError(f"GitHub publishes no SHA-256 for {SEVENZIP_FILE}; winlab does not fetch it unverified")
    return {"file": SEVENZIP_FILE, "url": str(asset.get("browser_download_url") or ""), "sha256": sha}


def parse_feed_hash(xml: str) -> str:
    """The package's SHA-512 as hex, from the NuGet v2 feed's entry
    (<d:PackageHash> is base64, <d:PackageHashAlgorithm> says SHA512)."""
    algo = re.search(r"<d:PackageHashAlgorithm>\s*([^<]+?)\s*</d:PackageHashAlgorithm>", xml)
    h = re.search(r"<d:PackageHash>\s*([A-Za-z0-9+/=]+)\s*</d:PackageHash>", xml)
    if not h or (algo and algo.group(1).upper() != "SHA512"):
        return ""
    try:
        raw = base64.b64decode(h.group(1), validate=True)
    except ValueError:
        return ""
    return raw.hex() if len(raw) == 64 else ""


def choco_package(get=_get) -> dict:
    url = f"{CHOCO_FEED}/Packages(Id='chocolatey',Version='{CHOCO_VERSION}')"
    try:
        sha = parse_feed_hash(get(url, timeout=30).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise SecopsError(f"the Chocolatey feed does not answer ({exc})") from exc
    if not sha:
        raise SecopsError(f"the feed publishes no SHA-512 for chocolatey {CHOCO_VERSION}; not fetched unverified")
    return {"file": f"chocolatey.{CHOCO_VERSION}.nupkg", "url": f"{CHOCO_FEED}/package/chocolatey/{CHOCO_VERSION}",
            "sha512": sha}


def fetch_software(progress=None, get=_get, download=_download_to) -> dict:
    say = progress or (lambda _m: None)
    d = software_dir()
    d.mkdir(parents=True, exist_ok=True)
    files = {}
    a = sevenzip_asset(get)
    say(f"{SEVENZIP} {SEVENZIP_VERSION} from {a['url']}")
    try:
        download(a["url"], d / a["file"], expect_sha=a["sha256"], label=a["file"])
    except BootstrapError as exc:
        raise SecopsError(str(exc)) from exc
    with (d / a["file"]).open("rb") as fh:
        if fh.read(8) != OLE_MAGIC:
            raise SecopsError(f"{a['file']} is not an MSI")
    files["7zip"] = {"name": SEVENZIP, "version": SEVENZIP_VERSION, "license": SEVENZIP_LICENSE,
                     "file": a["file"], "sha256": a["sha256"], "source": a["url"], "checksum": "GitHub's SHA-256"}
    c = choco_package(get)
    say(f"{CHOCO} {CHOCO_VERSION} from {c['url']}")
    try:
        download(c["url"], d / c["file"], expect_sha=c["sha512"], label=c["file"])
    except BootstrapError as exc:
        raise SecopsError(str(exc)) from exc
    try:
        with zipfile.ZipFile(d / c["file"]) as z:
            if "chocolatey.nuspec" not in z.namelist():
                raise SecopsError(f"{c['file']} holds no chocolatey.nuspec")
    except zipfile.BadZipFile as exc:
        raise SecopsError(f"{c['file']} is not a NuGet package") from exc
    files["chocolatey"] = {"name": CHOCO, "version": CHOCO_VERSION, "license": CHOCO_LICENSE, "file": c["file"],
                           "sha512": c["sha512"], "source": c["url"], "checksum": "the feed's SHA-512"}
    m = {"fetched": time.strftime("%Y-%m-%d"), "files": files}
    (d / "software.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
    keep = {f["file"] for f in files.values()} | {"software.json"}
    for f in d.iterdir():
        if f.name not in keep:
            f.unlink()
    say(f"software ready: {d}")
    return m


def software_readme(m: dict) -> str:
    f = m.get("files", {})
    z, c = f.get("7zip", {}), f.get("chocolatey", {})
    return "\r\n".join([
        "Software to deploy, fetched on the winlab PC (never inside the lab):",
        f"  {z.get('file', '')}  {SEVENZIP} {z.get('version', '')} ({SEVENZIP_LICENSE}),",
        f"      from {z.get('source', '')}, checked against GitHub's SHA-256",
        f"  {c.get('file', '')}  {CHOCO} {c.get('version', '')} ({CHOCO_LICENSE}),",
        f"      from {c.get('source', '')}, checked against the feed's SHA-512", "",
        "Group Policy software installation (lesson gpo-software-install):",
        "  copy the MSI to a share every computer account can read, e.g. \\\\srv01\\Software,",
        "  and assign it to computers by its UNC path, never by a drive letter.", "",
        "An internal Chocolatey feed (lesson chocolatey-internal-feed):",
        "  the nupkg holds choco itself: expand it (it is a zip), run tools\\chocolateyInstall.ps1,",
        "  then put it and your own packages in a folder share and make that the only source.",
        "",
    ])


# ===================================================== Security Compliance Toolkit
SCT_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=55319"
SCT_LICENSE = ("Microsoft's licence terms for the Security Compliance Toolkit, accepted by you when you download "
               "it; never shipped or passed on by winlab")
SCT_HOSTS = ("download.microsoft.com",)
SCT_STICK_LABEL = "SCT"
SCT_KINDS = {"baseline": "Security baseline", "lgpo": "LGPO", "policyanalyzer": "Policy Analyzer"}


def sct_dir() -> Path:
    return store() / "sct"


def sct_kind(name: str) -> str:
    """What a downloaded zip is, from its name as Microsoft serves it:
    LGPO.zip, PolicyAnalyzer.zip, 'Windows Server 2025 Security Baseline.zip'."""
    n = name.lower()
    if not n.endswith(".zip"):
        return ""
    if re.fullmatch(r"lgpo(\s*\(\d+\))?\.zip", n):
        return "lgpo"
    if n.startswith("policyanalyzer"):
        return "policyanalyzer"
    if "security baseline" in n or n.endswith("baseline.zip"):
        return "baseline"
    return ""


def describe_sct(path: Path, where: str = "") -> dict | None:
    """One toolkit zip on this PC: what it is and whether it holds what the
    lessons use (a baseline's GPOs folder and import scripts, LGPO.exe,
    PolicyAnalyzer.exe). A zip that does not is still listed, flagged."""
    kind = sct_kind(path.name)
    if not kind:
        return None
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return {"file": path.name, "path": str(path), "kind": kind, "title": SCT_KINDS[kind], "where": where,
                "ok": False, "note": "not a readable zip", "mb": 0, "gpos": 0}
    low = [n.lower() for n in names]
    gpos = len({m.group(1) for n in low for m in [re.search(r"gpos/(\{[0-9a-f-]{36}\})/", n)] if m})
    if kind == "baseline":
        ok = gpos > 0
        note = (f"{gpos} GPO backups" + (", Baseline-ADImport.ps1" if any(n.endswith("baseline-adimport.ps1") for n in low) else "")
                + (", Baseline-LocalInstall.ps1" if any(n.endswith("baseline-localinstall.ps1") for n in low) else "")
                if ok else "no GPOs folder in it")
    elif kind == "lgpo":
        ok = any(n.endswith("lgpo.exe") for n in low)
        note = "LGPO.exe" if ok else "no LGPO.exe in it"
    else:
        ok = any(n.endswith("policyanalyzer.exe") for n in low)
        note = "PolicyAnalyzer.exe" if ok else "no PolicyAnalyzer.exe in it"
    return {"file": path.name, "path": str(path), "kind": kind, "title": SCT_KINDS[kind], "where": where,
            "ok": ok, "note": note, "mb": round(path.stat().st_size / 1048576, 1), "gpos": gpos}


def sct_search_dirs() -> list[tuple[str, Path]]:
    from . import updates
    return [("winlab's SCT folder", sct_dir())] + updates.search_dirs()


def sct_scan() -> list[dict]:
    """Every toolkit zip on this PC, once each (by name and size)."""
    out, seen = [], set()
    for where, d in sct_search_dirs():
        try:
            files = sorted(p for p in d.iterdir() if p.is_file())
        except OSError:
            continue
        for p in files:
            row = describe_sct(p, where)
            if row is None:
                continue
            key = (p.name.lower(), p.stat().st_size)
            if key not in seen:
                seen.add(key)
                out.append(row)
    out.sort(key=lambda r: (list(SCT_KINDS).index(r["kind"]), r["file"].lower()))
    return out


def sct_ready(rows: list[dict] | None = None) -> bool:
    """A baseline, LGPO and Policy Analyzer: what the lessons need."""
    kinds = {r["kind"] for r in (sct_scan() if rows is None else rows) if r["ok"]}
    return set(SCT_KINDS) <= kinds


def check_sct_link(url: str) -> str:
    u = urllib.parse.urlparse(url.strip())
    host = (u.hostname or "").lower()
    if u.scheme != "https" or not any(host == h or host.endswith("." + h) for h in SCT_HOSTS):
        raise SecopsError("that is not a Microsoft download link: copy it from the toolkit's download page "
                          f"({SCT_PAGE}), it starts https://download.microsoft.com/")
    name = Path(urllib.parse.unquote(u.path)).name
    if not sct_kind(name):
        raise SecopsError(f"{name or 'the link'} is not one of the toolkit's zips (a baseline, LGPO.zip, PolicyAnalyzer.zip)")
    return name


def sct_fetch(url: str, consent: bool = False) -> Path:
    """Downloads one toolkit zip from Microsoft onto this PC, once the user
    said yes to Microsoft's terms; never into a lab."""
    if not consent:
        raise SecopsError("winlab downloads Microsoft's toolkit only when you say so: " + SCT_LICENSE)
    name = check_sct_link(url)
    try:
        return _download_to(url.strip(), sct_dir() / name, label=name)
    except BootstrapError as exc:
        raise SecopsError(str(exc)) from exc


def sct_pick(wanted: list[str] | None = None) -> list[dict]:
    rows = [r for r in sct_scan() if r["ok"]]
    if not wanted or wanted == ["all"]:
        return rows
    low = [w.lower() for w in wanted]
    return [r for r in rows if r["file"].lower() in low or r["kind"] in low]


def sct_readme(rows: list[dict]) -> str:
    lines = ["Microsoft Security Compliance Toolkit, downloaded by you from Microsoft", f"({SCT_PAGE}),",
             "written onto this stick by winlab under Microsoft's terms. Nothing here is winlab's.", ""]
    for r in rows:
        lines.append(f"  SCT\\{r['file']}  {r['title']}: {r['note']}")
    lines += ["", "On the domain controller: expand the baseline, then in its Scripts folder",
              "  .\\Baseline-ADImport.ps1   imports every GPO backup as a GPO (none is linked).",
              "On a standalone server: expand LGPO.zip next to the baseline's Scripts folder, then",
              "  .\\Baseline-LocalInstall.ps1 with the switch for its role (read the script's help first).",
              "Policy Analyzer: expand it anywhere, Add the baseline's GPOs folder as a policy rule set,",
              "  then compare it with the effective state of this machine.", ""]
    return "\r\n".join(lines)


# ==================================================================== Wazuh
WAZUH = "Wazuh"
WAZUH_LINE = "4."
WAZUH_LICENSE = "GPL-2.0 (Wazuh); indexer and dashboard Apache-2.0"
WAZUH_PKGS = "https://packages.wazuh.com"
WAZUH_RAW = "https://raw.githubusercontent.com/wazuh/wazuh"
WAZUH_PAGE = "https://documentation.wazuh.com/current/installation-guide/index.html"
FILEBEAT_MODULE = "wazuh-filebeat-0.4.tar.gz"
WAZUH_STICK_LABEL = "WAZUHAGENT"


def upstream(version: str) -> str:
    """'4.12.0-1' -> '4.12.0' (no epoch, no Debian revision)."""
    v = version.split(":", 1)[-1]
    return v.rsplit("-", 1)[0] if "-" in v else v


def wazuh_version(closure) -> str:
    """The one release every Wazuh component of the pack is on: the
    manager, the indexer and the dashboard must agree (Wazuh supports no
    mix), and it is a 4.x release."""
    got = {d.name: upstream(d.version) for d in closure if d.name in ("wazuh-manager", "wazuh-indexer", "wazuh-dashboard")}
    if "wazuh-manager" not in got:
        raise SecopsError("the pack resolved no wazuh-manager")
    v = got["wazuh-manager"]
    if not v.startswith(WAZUH_LINE):
        raise SecopsError(f"the repository offers Wazuh {v}; the lessons are written for {WAZUH_LINE}x")
    odd = {k: x for k, x in got.items() if x != v}
    if odd:
        raise SecopsError(f"Wazuh components disagree ({', '.join(f'{k} {x}' for k, x in odd.items())} against the "
                          f"manager's {v}); fetch again once the repository has all of {v}")
    return v


def parse_sha512(text: str, name: str) -> str:
    """The SHA-512 in a .sha512 file (hash, then optionally the file name)."""
    for line in text.splitlines():
        parts = line.strip().split()
        if parts and re.fullmatch(r"[0-9a-fA-F]{128}", parts[0]) and (len(parts) == 1 or parts[-1].lstrip("*") == name):
            return parts[0].lower()
    return ""


def wazuh_files(v: str) -> list[dict]:
    """The extra files for release v: (name, url, how it is checked)."""
    mm = ".".join(v.split(".")[:2])
    agent = f"wazuh-agent-{v}-1.msi"
    return [
        {"file": agent, "url": f"{WAZUH_PKGS}/4.x/windows/{agent}",
         "sha512_url": f"{WAZUH_PKGS}/4.x/checksums/wazuh/{v}/{agent}.sha512", "what": "the Windows agent"},
        {"file": "wazuh-certs-tool.sh", "url": f"{WAZUH_PKGS}/{mm}/wazuh-certs-tool.sh",
         "what": "makes the TLS certificates of the indexer, the manager and the dashboard"},
        {"file": "config.yml", "url": f"{WAZUH_PKGS}/{mm}/config.yml", "what": "the certificate tool's node list"},
        {"file": "filebeat.yml", "url": f"{WAZUH_PKGS}/{mm}/tpl/wazuh/filebeat/filebeat.yml",
         "what": "Filebeat's configuration for Wazuh"},
        {"file": "wazuh-template.json", "url": f"{WAZUH_RAW}/v{v}/extensions/elasticsearch/7.x/wazuh-template.json",
         "what": "the alerts index template"},
        {"file": FILEBEAT_MODULE, "url": f"{WAZUH_PKGS}/4.x/filebeat/{FILEBEAT_MODULE}",
         "what": "Filebeat's Wazuh module"},
    ]


def fetch_extra(pack, d: Path, closure, get, download, say) -> dict:
    """After the wazuh pack's .debs (debpacks.fetch): the agent MSI of the
    same release and the files Wazuh's step-by-step install fetches."""
    if pack.id != "wazuh":
        raise SecopsError(f"no extra files for pack {pack.id}")
    v = wazuh_version(closure)
    rows = []
    for f in wazuh_files(v):
        say(f"{f['file']} ({f['what']})")
        sha = ""
        if f.get("sha512_url"):
            try:
                sha = parse_sha512(get(f["sha512_url"], timeout=30).decode("utf-8", "replace"), f["file"])
            except BootstrapError as exc:
                raise SecopsError(f"Wazuh publishes no checksum for {f['file']} at {f['sha512_url']} ({exc})") from exc
            if not sha:
                raise SecopsError(f"{f['sha512_url']} holds no SHA-512 for {f['file']}")
        try:
            download(f["url"], d / f["file"], expect_sha=sha, label=f["file"])
        except BootstrapError as exc:
            raise SecopsError(str(exc)) from exc
        if f["file"].endswith(".msi"):
            with (d / f["file"]).open("rb") as fh:
                if fh.read(8) != OLE_MAGIC:
                    raise SecopsError(f"{f['file']} is not an MSI")
        rows.append({"file": f["file"], "source": f["url"], "what": f["what"],
                     "sha512" if sha else "sha256": sha or _sha256(d / f["file"]),
                     "checksum": "Wazuh's SHA-512" if sha else "recorded (Wazuh publishes none)"})
    (d / "INSTALL.txt").write_text(wazuh_install_text(v, rows), encoding="utf-8", newline="\r\n")
    return {"name": WAZUH, "version": v, "license": WAZUH_LICENSE, "agent": rows[0]["file"], "rows": rows,
            "files": [r["file"] for r in rows] + ["INSTALL.txt"]}


def extra_ready(d: Path, man: dict) -> bool:
    files = (man.get("extra") or {}).get("files") or []
    return bool(files) and all((d / f).is_file() and (d / f).stat().st_size > 0 for f in files)


def wazuh_install_text(v: str, rows: list[dict]) -> str:
    """Where to start, never the configuration itself (lesson wazuh-siem)."""
    lines = [f"{WAZUH} {v} ({WAZUH_LICENSE}), from {WAZUH_PKGS}", ""]
    for r in rows:
        how = f"SHA-512 {r['sha512'][:16]}... (Wazuh's)" if r.get("sha512") else f"SHA-256 {r['sha256'][:16]}... (recorded)"
        lines.append(f"  {r['file']:<28} {r['what']}; {how}")
    lines += ["", "First install the packages from this stick (README.txt), in Wazuh's order: the indexer,",
              "the manager and Filebeat, then the dashboard. Certificates first:",
              "  cp /mnt/winlab-pack/wazuh-certs-tool.sh /mnt/winlab-pack/config.yml ~/",
              "  edit config.yml (one indexer, one server, one dashboard: this machine's name and address),",
              "  bash ~/wazuh-certs-tool.sh -A   then copy each node's certificates where its guide says.",
              "The Windows agent goes onto the Wazuh agent stick (winlab secops stick <lab> wazuh-agent).", ""]
    return "\r\n".join(lines)


def wazuh_ready() -> bool:
    from . import debpacks
    return debpacks.ready("wazuh")


def wazuh_agent() -> dict:
    """The agent MSI inside the fetched pack: {file, path, version, sha512}."""
    from . import debpacks
    man = debpacks.manifest("wazuh")
    ex = man.get("extra") or {}
    name = ex.get("agent", "")
    row = next((r for r in ex.get("rows", []) if r.get("file") == name), {})
    p = debpacks.pack_dir("wazuh") / name if name else None
    if not name or p is None or not p.is_file():
        return {}
    return {"file": name, "path": str(p), "version": ex.get("version", ""), "sha512": row.get("sha512", "")}


def wazuh_agent_readme(a: dict, manager: str = "siem01.corp.lab") -> str:
    return "\r\n".join([
        f"Wazuh agent {a.get('version', '')} for Windows ({WAZUH_LICENSE.split(';')[0]}), from {WAZUH_PKGS},",
        "checked against the SHA-512 Wazuh publishes for it. The same release as the server.", "",
        "By hand, in an elevated prompt on the Windows machine (the stick is D: or E:):",
        f"  msiexec /i E:\\{a.get('file', 'wazuh-agent.msi')} /q WAZUH_MANAGER=\"{manager}\" WAZUH_AGENT_GROUP=\"windows\"",
        "  NET START WazuhSvc", "",
        "By Group Policy: copy the MSI to \\\\srv01\\Software and assign it to computers with a transform,",
        "or a startup script that runs the same msiexec line from the share.", "",
    ])


# ================================================================ Greenbone
GREENBONE = "Greenbone Community Edition"
GB_REGISTRY = "registry.community.greenbone.net"
GB_REPO_PREFIX = "community/"
GB_COMPOSE_URLS = ("https://greenbone.github.io/docs/latest/_static/compose.yaml",
                   "https://greenbone.github.io/docs/latest/_static/docker-compose.yml")
GB_PAGE = "https://greenbone.github.io/docs/latest/22.4/container/index.html"
GB_SIZE_TEXT = "about 2 to 3 GB, most of it feed data"
GB_STICK_MB = 1900
GB_STICK_LABEL = "GREENBONE"
JOB = "secops-fetch"
# Digests winlab ships for the images, image name (registry/repo:tag) ->
# sha256 digest of what the registry serves for that tag. An image with one
# is fetched by it and nothing else is accepted. Images without one are
# pinned by the lock file on this PC: the first fetch records the digest it
# got, every later fetch must get the same (--repin to move on).
GB_PINS: dict[str, str] = {}
GB_LICENSES = {
    "gvmd": "AGPL-3.0-or-later", "gsa": "AGPL-3.0-or-later", "gsad": "AGPL-3.0-or-later",
    "ospd-openvas": "AGPL-3.0-or-later", "openvas-scanner": "GPL-2.0-or-later", "openvasd": "GPL-2.0-or-later",
    "notus-scanner": "AGPL-3.0-or-later", "pg-gvm": "GPL-3.0-or-later", "gvm-tools": "GPL-3.0-or-later",
    "gvm-libs": "GPL-2.0-or-later", "gvm-config": "AGPL-3.0-or-later", "pg-gvm-migrator": "GPL-3.0-or-later",
    "redis-server": "BSD-3-Clause (Redis 7.2 and earlier)", "mqtt-broker": "EPL-2.0 / EDL-1.0 (Eclipse Mosquitto)",
    "nginx": "BSD-2-Clause",
    "vulnerability-tests": "Greenbone Community Feed: the NASL tests GPL-2.0-or-later",
    "notus-data": "Greenbone Community Feed: GPL-2.0-or-later",
    "scap-data": "Greenbone Community Feed: NVD CVE and CPE data (public domain, NIST)",
    "cert-bund-data": "Greenbone Community Feed: CERT-Bund advisories (BSI's terms)",
    "dfn-cert-data": "Greenbone Community Feed: DFN-CERT advisories (DFN-CERT's terms)",
    "data-objects": "Greenbone Community Feed: GPL-2.0-or-later", "report-formats": "Greenbone Community Feed: GPL-2.0-or-later",
    "gpg-data": "Greenbone Community Feed: Greenbone's public signing key",
}


def gb_dir() -> Path:
    return store() / "greenbone"


def gb_meta() -> dict:
    return _meta(gb_dir() / "greenbone.json")


def gb_lock() -> dict[str, str]:
    d = _meta(gb_dir() / "lock.json")
    return {k: v for k, v in d.items() if isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v)}


def gb_ready() -> bool:
    m = gb_meta()
    return bool(m.get("images")) and (gb_dir() / "compose.yaml").is_file() and all(
        (gb_dir() / r["file"]).is_file() for r in m["images"])


def parse_compose_images(text: str) -> list[str]:
    """The image of every service in a compose file, in order, once each."""
    out = []
    for m in re.finditer(r"^\s*image:\s*['\"]?([^'\"\s#]+)['\"]?\s*(?:#.*)?$", text, re.MULTILINE):
        ref = m.group(1)
        if ref not in out:
            out.append(ref)
    return out


def gb_license(ref: str) -> str:
    from .containers import parse_ref
    name = parse_ref(ref).repo.rsplit("/", 1)[-1]
    return GB_LICENSES.get(name, "Greenbone's (see the image's own licence files)")


def check_gb_refs(refs: list[str]) -> list:
    """Only Greenbone's own registry: a compose file that names anything
    else is refused rather than half fetched."""
    from .containers import ContainerError, parse_ref
    if not refs:
        raise SecopsError("Greenbone's compose file names no images")
    out, bad = [], []
    for r in refs:
        try:
            ref = parse_ref(r)
        except ContainerError as exc:
            raise SecopsError(str(exc)) from exc
        if ref.registry != GB_REGISTRY or not ref.repo.startswith(GB_REPO_PREFIX):
            bad.append(r)
        out.append(ref)
    if bad:
        raise SecopsError(f"Greenbone's compose file names images outside {GB_REGISTRY}: {', '.join(bad)}; "
                          "winlab fetches only Greenbone's own images")
    return out


def gb_pin(full: str, lock: dict[str, str]) -> str:
    return GB_PINS.get(full) or lock.get(full, "")


def _gb_transport():
    from . import containers
    return containers.http_open


def fetch_greenbone(progress=None, get=_get, transport=None, repin: bool = False) -> dict:
    """The compose file from Greenbone's documentation and every image it
    names, pinned, onto this PC."""
    from . import containers
    say = progress or (lambda _m: None)
    compose, src = b"", ""
    for url in GB_COMPOSE_URLS:
        try:
            compose = get(url, timeout=30)
            src = url
            break
        except BootstrapError:
            continue
    text = compose.decode("utf-8", "replace")
    if not src or "services:" not in text:
        raise SecopsError(f"Greenbone's compose file is not where its documentation keeps it ({GB_COMPOSE_URLS[0]})")
    refs = check_gb_refs(parse_compose_images(text))
    say(f"{GREENBONE}: {len(refs)} images named in {src}")
    d = gb_dir()
    d.mkdir(parents=True, exist_ok=True)
    lock = {} if repin else gb_lock()
    client = containers.Registry(transport or _gb_transport())
    recs = []
    try:
        for i, ref in enumerate(refs, 1):
            pin = gb_pin(ref.full, lock)
            entry = {"ref": f"{ref.familiar}@{pin}" if pin else ref.familiar, "os": "linux"}
            say(f"{i}/{len(refs)} {ref.familiar}" + (f" (pinned {pin[:19]}...)" if pin else " (first fetch: pinning it)"))
            try:
                rec = containers.fetch_image(entry, client, say)
            except containers.ContainerError as exc:
                hint = (" The pinned digest is gone from the registry: winlab secops fetch greenbone --repin "
                        "takes what the tag serves now." if pin else "")
                raise SecopsError(f"{exc}{hint}") from exc
            got = pin or rec["digest"]
            src_tar = containers.images_dir() / rec["file"]
            shutil.move(str(src_tar), str(d / rec["file"]))
            lock[ref.full] = got
            recs.append({"ref": ref.familiar, "full": ref.full, "file": rec["file"], "digest": got,
                         "size": (d / rec["file"]).stat().st_size, "license": gb_license(ref.familiar),
                         "pinned_by": "winlab" if ref.full in GB_PINS else "lock"})
    finally:
        cache = containers.store() / "cache" / "blobs"
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
    (d / "compose.yaml").write_bytes(compose)
    (d / "lock.json").write_text(json.dumps(lock, indent=1, sort_keys=True), encoding="utf-8")
    m = {"name": GREENBONE, "fetched": time.strftime("%Y-%m-%d"), "compose": src,
         "compose_sha256": hashlib.sha256(compose).hexdigest(), "images": recs}
    (d / "greenbone.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
    keep = {r["file"] for r in recs} | {"compose.yaml", "lock.json", "greenbone.json"}
    for f in d.iterdir():
        if f.name not in keep:
            f.unlink()
    say(f"{GREENBONE} ready: {d}")
    return m


def plan_sticks(recs: list[dict], cap_mb: float | None = None) -> list[list[dict]]:
    """The images spread over sticks, biggest first, each stick under the
    cap; one image bigger than a stick is refused."""
    cap = (GB_STICK_MB if cap_mb is None else cap_mb) * 1048576
    sticks: list[list[dict]] = []
    room: list[int] = []
    for r in sorted(recs, key=lambda r: -r["size"]):
        if r["size"] > cap:
            raise SecopsError(f"{r['ref']} is {r['size'] >> 20} MB, more than a stick holds")
        i = next((k for k, left in enumerate(room) if left >= r["size"]), None)
        if i is None:
            sticks.append([])
            room.append(cap)
            i = len(sticks) - 1
        sticks[i].append(r)
        room[i] -= r["size"]
    return sticks


def gb_readme(part: int, parts: int, recs: list[dict], m: dict) -> str:
    lines = [f"{GREENBONE}, stick {part} of {parts}, fetched on the winlab PC {m.get('fetched', '')}.",
             f"compose.yaml from {m.get('compose', '')} (sha256 {m.get('compose_sha256', '')[:16]}...).",
             "Every image was pulled from Greenbone's registry, each layer checked against its digest,", "and pinned:", ""]
    for r in sorted(recs, key=lambda r: r["ref"]):
        lines.append(f"  {r['file']}")
        lines.append(f"      {r['ref']}  {r['digest'][:19]}...  {r['size'] >> 20} MB  ({r['license']})")
    lines += ["", "On the scanner (Docker from the docker pack):",
              "  sudo mkdir -p /mnt/gb && sudo mount LABEL=" + GB_STICK_LABEL + str(part) + " /mnt/gb",
              "  for f in /mnt/gb/*.tar; do sudo docker load -i \"$f\"; done",
              "  (every stick, one after the other), then from stick 1:",
              "  mkdir -p ~/greenbone && cp /mnt/gb/compose.yaml ~/greenbone/",
              "  cd ~/greenbone && sudo docker compose -p greenbone-community-edition up -d", "",
              "Nothing is pulled from the internet: every image is already in Docker. The feed data",
              "images copy their data into volumes at the first start; give gvmd time to load it.",
              "Scan only this lab's own machines.", ""]
    return "\r\n".join(lines)


# =================================================================== sticks
KINDS = ("software", "sct", "wazuh-agent", "greenbone")
STICK_TITLES = {"software": "Software", "sct": "Security Compliance Toolkit", "wazuh-agent": "Wazuh agent",
                "greenbone": "Greenbone"}


def ready(kind: str) -> bool:
    return {"software": software_ready, "sct": sct_ready, "wazuh-agent": lambda: bool(wazuh_agent()),
            "greenbone": gb_ready}[kind]()


def fetch(kind: str, progress=None, repin: bool = False) -> None:
    if kind == "software":
        fetch_software(progress)
    elif kind == "greenbone":
        fetch_greenbone(progress, repin=repin)
    elif kind == "wazuh":
        from . import debpacks
        try:
            debpacks.fetch("wazuh", progress=progress)
        except debpacks.PackError as exc:
            raise SecopsError(str(exc)) from exc
    elif kind == "sct":
        raise SecopsError(f"the toolkit is yours to download from Microsoft ({SCT_PAGE}); put the zips in your "
                          "Downloads folder, or winlab secops sct-fetch <download link> --yes")
    else:
        raise SecopsError("fetch what? software, greenbone or wazuh (the toolkit you download yourself)")


def stick_sets(kind: str, wanted: list[str] | None = None) -> list[tuple[str, str, dict[str, bytes]]]:
    """(title, label, files) for each stick a kind needs: Greenbone takes
    several, the rest one."""
    if kind == "software":
        if not software_ready():
            raise SecopsError("the software is not on this PC yet: winlab secops fetch software (or Setup)")
        m = software_meta()
        files = {f["file"]: (software_dir() / f["file"]).read_bytes() for f in m["files"].values()}
        files["README.txt"] = software_readme(m).encode("utf-8")
        return [(f"Software ({SEVENZIP} {SEVENZIP_VERSION}, choco {CHOCO_VERSION})", "SOFTWARE", files)]
    if kind == "sct":
        rows = sct_pick(wanted)
        if not rows:
            raise SecopsError(f"no Security Compliance Toolkit zips on this PC: download them from {SCT_PAGE} "
                              "(a baseline, LGPO.zip and PolicyAnalyzer.zip) into your Downloads folder")
        files = {f"SCT/{r['file']}": Path(r["path"]).read_bytes() for r in rows}
        files["README.txt"] = sct_readme(rows).encode("utf-8")
        return [(f"Security Compliance Toolkit ({len(rows)})", SCT_STICK_LABEL, files)]
    if kind == "wazuh-agent":
        a = wazuh_agent()
        if not a:
            raise SecopsError("the Wazuh agent comes with the wazuh pack: winlab packs fetch wazuh (or Setup)")
        return [(f"Wazuh agent {a['version']}", WAZUH_STICK_LABEL,
                 {a["file"]: Path(a["path"]).read_bytes(), "README.txt": wazuh_agent_readme(a).encode("utf-8")})]
    if kind == "greenbone":
        if not gb_ready():
            raise SecopsError("Greenbone is not on this PC yet: winlab secops fetch greenbone (or Setup)")
        m = gb_meta()
        plan = plan_sticks(m["images"])
        out = []
        for i, recs in enumerate(plan, 1):
            files = {r["file"]: (gb_dir() / r["file"]).read_bytes() for r in recs}
            files["compose.yaml"] = (gb_dir() / "compose.yaml").read_bytes()
            files["README.txt"] = gb_readme(i, len(plan), recs, m).encode("utf-8")
            out.append((f"Greenbone {i} of {len(plan)}", f"{GB_STICK_LABEL}{i}", files))
        return out
    raise SecopsError(f"which stick? {', '.join(KINDS)}")


def to_stick(lab_name: str, kind: str, wanted: list[str] | None = None) -> dict:
    """New sticks on the lab's media shelf."""
    from . import media, mediashelf
    sets = stick_sets(kind, wanted)
    d = mediashelf.shelf_dir(lab_name, "sticks")
    ids, mb = [], 0
    for title, label, files in sets:
        sid = mediashelf._new_id(lab_name, kind if len(sets) == 1 else f"{kind}-{len(ids) + 1}")
        try:
            media.write_stick(files, d / f"{sid}.img", label)
        except media.MediaError as exc:
            raise SecopsError(str(exc)) from exc
        (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
        ids.append(sid)
        mb += sum(len(b) for b in files.values()) >> 20
    return {"ids": ids, "id": ids[0], "title": sets[0][0] if len(sets) == 1 else f"{STICK_TITLES[kind]} ({len(sets)} sticks)",
            "files": sum(len(s[2]) for s in sets), "mb": mb}


# =================================================================== status
def summary() -> dict:
    sw, gb, a = software_meta(), gb_meta(), wazuh_agent()
    rows = sct_scan()
    return {
        "software": {"ready": software_ready(), "fetched": sw.get("fetched", ""), "sevenzip": SEVENZIP_VERSION,
                     "choco": CHOCO_VERSION, "size_text": SOFTWARE_SIZE_TEXT, "page": SEVENZIP_PAGE},
        "greenbone": {"ready": gb_ready(), "fetched": gb.get("fetched", ""), "images": len(gb.get("images", [])),
                      "size_mb": round(sum(r.get("size", 0) for r in gb.get("images", [])) / 1048576, 1),
                      "pinned": len(GB_PINS), "locked": len(gb_lock()), "size_text": GB_SIZE_TEXT, "page": GB_PAGE},
        "wazuh": {"ready": wazuh_ready(), "agent": a.get("file", ""), "version": a.get("version", ""),
                  "page": WAZUH_PAGE},
        "sct": {"ready": sct_ready(rows), "rows": rows, "page": SCT_PAGE, "license": SCT_LICENSE},
        "store": str(store()),
    }


def render_status() -> str:
    s = summary()
    sw, gb, wz, sct = s["software"], s["greenbone"], s["wazuh"], s["sct"]
    lines = [f"security operations store: {s['store']}", "",
             f"  software    {'ready, fetched ' + sw['fetched'] if sw['ready'] else 'not fetched (' + SOFTWARE_SIZE_TEXT + ')'}: "
             f"{SEVENZIP} {SEVENZIP_VERSION} MSI, {CHOCO} {CHOCO_VERSION} nupkg",
             f"  greenbone   {('ready, ' + str(gb['images']) + ' images, ' + str(gb['size_mb']) + ' MB, fetched ' + gb['fetched']) if gb['ready'] else 'not fetched (' + GB_SIZE_TEXT + ')'}"
             f"; {gb['pinned']} pinned by winlab, {gb['locked']} by this PC's lock file",
             f"  wazuh       {'ready, agent ' + wz['agent'] if wz['ready'] else 'not fetched: winlab packs fetch wazuh'}",
             f"  sct         {'ready' if sct['ready'] else 'incomplete'}: {len(sct['rows'])} zip(s) found; download from {SCT_PAGE}"]
    for r in sct["rows"]:
        lines.append(f"              {r['title']:<18} {r['file']}  ({r['note']}; {r['where']})")
    lines += ["", "  fetch:  winlab secops fetch software|greenbone|wazuh [--repin]",
              "  sticks: winlab secops stick <lab> software|sct|wazuh-agent|greenbone, or the media shelf", ""]
    return "\n".join(lines)


# ------------------------------------------------------------- the desktop
DOWNLOADS = {"software": "software", "sct": "sct", "greenbone": "greenbone", "wazuh-agent": "wazuh-agent"}


def _who(lab, key: str) -> list[str]:
    return [n.id for n in lab.node_list() if key in (n.vars.get("downloads") or [])]


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """Setup's steps for what this lab's machines name (node vars downloads):
    the software and Greenbone are fetched by a job; the toolkit is the
    user's own download, so its step only says where to get it. The wazuh
    pack (and its agent) comes through the packs' own step."""
    have = set(have or ())
    steps = []
    for key, label, size, hint in (
            ("software", f"Fetch the software to deploy ({SEVENZIP} MSI, Chocolatey)", SOFTWARE_SIZE_TEXT,
             "from 7-Zip's GitHub release and the Chocolatey feed, pinned and checked"),
            ("greenbone", f"Fetch {GREENBONE} (Greenbone's registry)", GB_SIZE_TEXT,
             "the images its compose file names, feed data included, pinned by digest")):
        who = _who(lab, key)
        if not who or f"secops-{key}" in have:
            continue
        steps.append({"id": f"secops-{key}", "label": label, "done": ready(key), "blocked": False,
                      "hint": f"{', '.join(who)} use it from a stick: {hint}, {size} once",
                      "job": JOB, "kind": key})
    who = _who(lab, "sct")
    if who and "secops-sct" not in have:
        steps.append({"id": "secops-sct", "label": "Download Microsoft's Security Compliance Toolkit",
                      "done": sct_ready(), "blocked": not sct_ready(), "link": SCT_PAGE,
                      "hint": f"{', '.join(who)} use it from the SCT stick: download a baseline, LGPO.zip and "
                              "PolicyAnalyzer.zip from Microsoft into your Downloads folder; winlab writes them "
                              "onto the stick and never ships them"})
    return steps


def shelf_view(lab) -> dict | None:
    """Which secops sticks this lab's shelf offers, and whether each is
    ready (None for a lab that names none)."""
    keys = [k for k in KINDS if _who(lab, k)]
    if not keys:
        return None
    return {k: ready(k) for k in keys}


def act(dash, action: str, params: dict) -> dict:
    """wb-secops-stick writes one kind of stick onto the shelf."""
    if action == "wb-secops-stick":
        kind = str(params.get("kind", ""))
        if kind not in KINDS:
            return {"ok": False, "message": f"which stick? {', '.join(KINDS)}"}
        try:
            r = to_stick(dash.lab.name, kind)
        except SecopsError as exc:
            return {"ok": False, "message": str(exc), "fetch": kind in ("software", "greenbone") and not ready(kind),
                    "job": JOB, "kind": kind}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto a machine", "stick": r["id"]}
    return {"ok": False, "message": f"unknown security operations action {action!r}"}


# ------------------------------------------------------------------ the CLI
def add_cli(sub) -> None:
    sp = sub.add_parser("secops", help="security operations media: Greenbone, the software to deploy, the Wazuh "
                                       "agent and Microsoft's Security Compliance Toolkit, onto sticks")
    ss = sp.add_subparsers(dest="seccmd", metavar="<op>")
    ss.add_parser("status", help="what is on this PC, and where the toolkit zips were found")
    f = ss.add_parser("fetch", help="fetch software, greenbone or wazuh onto this PC")
    f.add_argument("what", choices=("software", "greenbone", "wazuh"))
    f.add_argument("--repin", action="store_true", help="Greenbone: take the digests the tags serve now")
    st = ss.add_parser("stick", help="write sticks onto a lab's media shelf")
    st.add_argument("lab")
    st.add_argument("kind", choices=KINDS)
    st.add_argument("names", nargs="*", help="sct: only these zips (file names, or baseline, lgpo, policyanalyzer)")
    sf = ss.add_parser("sct-fetch", help="download one toolkit zip from a download.microsoft.com link")
    sf.add_argument("url")
    sf.add_argument("--yes", action="store_true", help="you accept Microsoft's terms: download it now")


def run_cli(args) -> int:
    import sys
    op = getattr(args, "seccmd", None) or "status"
    try:
        if op == "fetch":
            fetch(args.what, progress=lambda m: print(f"  {m}"), repin=args.repin)
        elif op == "stick":
            r = to_stick(args.lab, args.kind, args.names or None)
            print(f"{r['title']} is on {args.lab}'s media shelf as {', '.join(r['ids'])} ({r['files']} files, {r['mb']} MB)")
            return 0
        elif op == "sct-fetch":
            ok = args.yes
            if not ok and sys.stdin.isatty():
                print(f"Download {check_sct_link(args.url)} from Microsoft onto this PC?\n  {SCT_LICENSE}")
                ok = input("Download it? [y/N] ").strip().lower() in ("y", "yes")
            if not ok:
                print("nothing downloaded (run again with --yes to accept Microsoft's terms)", file=sys.stderr)
                return 3
            print(f"saved: {sct_fetch(args.url, consent=True)}")
            return 0
        print(render_status())
        return 0
    except SecopsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


# =============================================================== the drills
_WINLAB_DIR = "New-Item -ItemType Directory -Path 'C:\\winlab' -Force | Out-Null; "
_HTTPS = "'IIS:\\SslBindings\\0.0.0.0!443'"
_AE_TASK = "-TaskPath '\\Microsoft\\Windows\\CertificateServicesClient\\' -TaskName 'SystemTask'"
_AGENT_DIR = "$d = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'; "
_LSA = "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'"


def _locked_acl(path_ps: str, readers: str) -> str:
    """PowerShell that replaces a folder's ACL with Administrators and SYSTEM
    in full and one reader group, nothing inherited: 'someone tidied it'."""
    return ("$n = New-Object System.Security.AccessControl.DirectorySecurity; $n.SetAccessRuleProtection($true, $false); "
            "foreach ($id in 'BUILTIN\\Administrators', 'NT AUTHORITY\\SYSTEM') { $n.AddAccessRule((New-Object "
            "System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', "
            "'None', 'Allow'))) }; "
            f"$n.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object "
            f"System.Security.Principal.NTAccount('{readers}')), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', "
            f"'None', 'Allow'))); Set-Acl -Path {path_ps} -AclObject $n; ")


def _restore_acl(path_ps: str, saved: str) -> str:
    return (f"if (Test-Path -Path '{saved}') {{ $a = Get-Acl -Path {path_ps}; "
            f"$a.SetSecurityDescriptorSddlForm((Get-Content -Path '{saved}' -Raw).Trim()); Set-Acl -Path {path_ps} "
            f"-AclObject $a; Remove-Item -Path '{saved}' -Force }}; ")


# Legacy (category) audit settings in the local security database, as an
# old hardening script would leave them: process tracking off, logons
# success only.
_LEGACY_INF = ("Set-Content -Path 'C:\\winlab\\audit-legacy.inf' -Encoding Unicode -Value @('[Unicode]', 'Unicode=yes', "
               "'[Event Audit]', 'AuditProcessTracking = 0', 'AuditLogonEvents = 1', '[Version]', "
               "'signature=\"$CHICAGO$\"', 'Revision=1'); ")

_CHOCO_ROWS = ("$rows = @(choco source list --limit-output 2>$null | ForEach-Object { ,($_ -split '\\|') } | "
               "Where-Object { $_.Count -ge 3 }); ")


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [
        GuestFault(
            id="wef-reader-removed",
            title="One PC's logons stopped arriving at the event collector",
            os=WINDOWS,
            teaches="how a source-initiated subscription reads the Security log (the forwarder runs as Network "
                    "Service, which must be in Event Log Readers), wecutil gr on the collector, and the "
                    "Forwarding/Operational log on the source",
            symptom="Forwarded Events on the collector still gets System events and other machines' logons, but "
                    "nothing from this machine's Security log since this morning; wecutil gr shows the source "
                    "with an error",
            apply=("$g = Get-LocalGroup -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue; "
                   "if (-not $g) { 'no local Event Log Readers group here (a domain controller?): break it on a member' } "
                   "else { Remove-LocalGroupMember -SID 'S-1-5-32-573' -Member 'S-1-5-20' -ErrorAction SilentlyContinue; "
                   "Restart-Service -Name WinRM -Force; 'broken' }"),
            clear=("Add-LocalGroupMember -SID 'S-1-5-32-573' -Member 'S-1-5-20' -ErrorAction SilentlyContinue; "
                   "Restart-Service -Name WinRM -Force; 'ok'"),
            hints=(
                "Start at the collector: wecutil gr <subscription> lists every source with its state and the last "
                "error it reported. This machine is there, and the error is about reading a channel, not about "
                "reaching the collector. On the machine itself, Get-WinEvent -LogName "
                "Microsoft-Windows-Forwarding/Operational -MaxEvents 10 says the same from its side.",
                "The forwarder is part of WinRM and runs as NT AUTHORITY\\NETWORK SERVICE. The Security log only lets "
                "Event Log Readers (S-1-5-32-573) read it: Get-LocalGroupMember -SID S-1-5-32-573 lists who is in "
                "it now. Network Service is missing, which is why System events still flow and Security ones do not.",
                "Add it back: Add-LocalGroupMember -SID S-1-5-32-573 -Member S-1-5-20, then Restart-Service WinRM so "
                "the forwarder reads with its new token. Make it stick for every source: the GPO that configures "
                "forwarding should own the group (Restricted Groups, or a Group Policy Preference for local groups).",
            ),
            verify=("$m = @(Get-LocalGroupMember -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue | "
                    "Where-Object { $_.SID.Value -eq 'S-1-5-20' }); "
                    "[bool]($m.Count -gt 0 -and (Get-Service -Name WinRM).Status -eq 'Running')"),
        ),
        GuestFault(
            id="wazuh-agent-wrong-manager",
            title="The PC shows Disconnected in the Wazuh dashboard",
            os=WINDOWS,
            teaches="where a Wazuh agent keeps its server (ossec.conf, <client><server><address>), reading "
                    "ossec.log and wazuh-agent.state, and why an agent never re-enrols by itself after a change",
            symptom="the Wazuh dashboard lists this machine as Disconnected and no new alerts come from it; the "
                    "PC itself works and WazuhSvc says Running",
            apply=(_AGENT_DIR + "$c = Join-Path $d 'ossec.conf'; "
                   "if (-not (Test-Path -Path $c)) { 'no Wazuh agent on this machine: install it first (lesson wazuh-siem)' } "
                   "else { " + _WINLAB_DIR + "if (-not (Test-Path -Path 'C:\\winlab\\ossec.conf.winlab')) { "
                   "Copy-Item -Path $c -Destination 'C:\\winlab\\ossec.conf.winlab' }; "
                   "$t = [System.IO.File]::ReadAllText($c); $re = New-Object System.Text.RegularExpressions.Regex('<address>[^<]*</address>'); "
                   "[System.IO.File]::WriteAllText($c, $re.Replace($t, '<address>siem-old.{domain}</address>', 1)); "
                   "Restart-Service -Name WazuhSvc -Force; 'broken' }"),
            clear=(_AGENT_DIR + "if (Test-Path -Path 'C:\\winlab\\ossec.conf.winlab') { Copy-Item -Path "
                   "'C:\\winlab\\ossec.conf.winlab' -Destination (Join-Path $d 'ossec.conf') -Force; Remove-Item -Path "
                   "'C:\\winlab\\ossec.conf.winlab' -Force }; Restart-Service -Name WazuhSvc -Force -ErrorAction "
                   "SilentlyContinue; 'ok'"),
            hints=(
                "The service runs, so ask the agent what it is doing: Get-Content \"${env:ProgramFiles(x86)}\\"
                "ossec-agent\\ossec.log\" -Tail 20, and Get-Content \"${env:ProgramFiles(x86)}\\ossec-agent\\"
                "wazuh-agent.state\": status is not connected, and the log keeps failing to reach a server.",
                "Which server? The agent reads it from ossec.conf under <client><server><address>. It names "
                "siem-old.{domain}, which Resolve-DnsName cannot find; the SIEM is siem01. Someone tidied the "
                "configuration from an old template.",
                "Put the SIEM's name back in <address> (an elevated Notepad, or the Wazuh agent manager), then "
                "Restart-Service WazuhSvc. wazuh-agent.state says status='connected' within a minute and the "
                "dashboard shows the agent Active. For a fleet, the address belongs in the MSI's WAZUH_MANAGER at "
                "install time or in a centralised agent.conf, not in hand edits.",
            ),
            verify=(_AGENT_DIR + "$s = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue; "
                    "$st = Get-Content -Path (Join-Path $d 'wazuh-agent.state') -ErrorAction SilentlyContinue | Out-String; "
                    "$conf = Get-Content -Path (Join-Path $d 'ossec.conf') -ErrorAction SilentlyContinue | Out-String; "
                    "[bool]($s -and $s.Status -eq 'Running' -and $st -match \"status='connected'\" -and $conf -notmatch 'siem-old')"),
        ),
        GuestFault(
            id="scan-target-no-ping",
            title="Greenbone says the server is dead; it is not",
            os=WINDOWS,
            teaches="a scanner's alive test (ICMP ping by default) and what a host that does not answer it gets "
                    "(no scan at all), the File and Printer Sharing echo rules, and allowing the scanner without "
                    "opening the machine to everyone",
            symptom="the weekly Greenbone task finishes in a minute with 0 results for this machine and the "
                    "report says the host was considered dead; everyone can still use it",
            apply=(_WINLAB_DIR + "$r = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow "
                   "-ErrorAction SilentlyContinue | Where-Object { $f = $_ | Get-NetFirewallPortFilter; "
                   "$f.Protocol -eq 'ICMPv4' -and \"$($f.IcmpType)\" -match '^(8|Any)' }); "
                   "if ($r.Count) { Add-Content -Path 'C:\\winlab\\ping-rules.txt' -Value ($r | ForEach-Object { $_.Name }) }; "
                   "$r | Disable-NetFirewallRule; Set-NetFirewallProfile -Profile Domain, Private -Enabled True; "
                   "'broken: ' + $r.Count + ' echo rule(s) off'"),
            clear=("if (Test-Path -Path 'C:\\winlab\\ping-rules.txt') { Get-Content -Path 'C:\\winlab\\ping-rules.txt' "
                   "| Where-Object { $_ } | ForEach-Object { Enable-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue }; "
                   "Remove-Item -Path 'C:\\winlab\\ping-rules.txt' -Force }; 'ok'"),
            hints=(
                "Read the report before the machine: the result count is zero and the host's details say it was "
                "considered dead, so nothing was scanned. The task's target uses an alive test; open the target "
                "in Configuration > Targets and read which one. Then from the scanner: ping -c 2 <this machine>.",
                "The default alive test is ICMP ping. On this machine, Get-NetFirewallRule -DisplayGroup 'File and "
                "Printer Sharing' | Where-Object DisplayName -like '*Echo*' | Format-Table Name, Enabled, Profile: "
                "the echo request rules are switched off, so the firewall drops the scanner's ping and the scanner "
                "never tries a port.",
                "Allow echo requests again (Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In, or a rule of your own "
                "with -RemoteAddress set to the scanner's address only), ping from scan01, and run the task again. "
                "Changing the target's alive test to Consider Alive also scans it, more slowly; it hides the next "
                "machine that really is down.",
            ),
            verify=("$r = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue | "
                    "Where-Object { $f = $_ | Get-NetFirewallPortFilter; $f.Protocol -eq 'ICMPv4' -and "
                    "\"$($f.IcmpType)\" -match '^(8|Any)' }); [bool]($r.Count -gt 0)"),
        ),
        GuestFault(
            id="baseline-audit-override",
            title="The audit script fails on process creation after every policy refresh",
            os=WINDOWS,
            teaches="advanced audit policy (subcategories) against the legacy categories, the security option "
                    "that makes the subcategories win (SCENoApplyLegacyAuditPolicy), and why a fix with auditpol "
                    "comes undone",
            symptom="the CIS-style audit script reports Process Creation and Logon failure auditing off; "
                    "auditpol /set puts them back, and the next policy refresh (or secedit) turns them off again; "
                    "no 4688 events since",
            apply=(_WINLAB_DIR + f"$v = (Get-ItemProperty -Path {_LSA} -Name SCENoApplyLegacyAuditPolicy "
                   "-ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy; "
                   "if (-not (Test-Path -Path 'C:\\winlab\\audit-override.txt')) { Set-Content -Path "
                   "'C:\\winlab\\audit-override.txt' -Value ([string]$v); auditpol /backup /file:C:\\winlab\\audit-before.csv "
                   "| Out-Null }; "
                   f"Set-ItemProperty -Path {_LSA} -Name SCENoApplyLegacyAuditPolicy -Value 0 -Type DWord; "
                   + _LEGACY_INF
                   + "secedit /configure /db C:\\winlab\\audit-legacy.sdb /cfg C:\\winlab\\audit-legacy.inf "
                   "/areas SECURITYPOLICY /quiet | Out-Null; 'broken'"),
            clear=("$v = Get-Content -Path 'C:\\winlab\\audit-override.txt' -ErrorAction SilentlyContinue; "
                   f"if (\"$v\".Trim() -eq '') {{ $v = '1' }}; Set-ItemProperty -Path {_LSA} -Name "
                   "SCENoApplyLegacyAuditPolicy -Value ([int]\"$v\".Trim()) -Type DWord; "
                   "if (Test-Path -Path 'C:\\winlab\\audit-before.csv') { auditpol /restore "
                   "/file:C:\\winlab\\audit-before.csv | Out-Null }; Remove-Item -Path 'C:\\winlab\\audit-override.txt', "
                   "'C:\\winlab\\audit-before.csv', 'C:\\winlab\\audit-legacy.*' -Force -ErrorAction SilentlyContinue; 'ok'"),
            hints=(
                "Do not trust the last thing you set; read what the machine does now: auditpol /get /subcategory:"
                "\"Process Creation\" and /subcategory:\"Logon\". Then ask which policy wins: there are two audit "
                "systems on Windows, the nine legacy categories (secpol.msc, Local Policies, Audit Policy) and the "
                "fifty-odd subcategories (Advanced Audit Policy Configuration).",
                "One security option decides between them: Audit: Force audit policy subcategory settings to override "
                "audit policy category settings, stored as SCENoApplyLegacyAuditPolicy under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa. It is 0 now, and the local security database holds "
                "legacy settings (secedit /export /cfg C:\\winlab\\now.inf /areas SECURITYPOLICY, then read [Event "
                "Audit]): process tracking 0, logons success only. Every refresh applies the categories over your "
                "subcategories.",
                "Turn the option back on (secpol.msc, Security Options, Enabled; the baseline sets it), then set the "
                "subcategories again: auditpol /set /subcategory:\"Process Creation\" /success:enable and "
                "/subcategory:\"Logon\" /success:enable /failure:enable, or re-apply the baseline with LGPO. "
                "secedit /refreshpolicy machine_policy /enforce or a restart must leave them on.",
            ),
            verify=(f"$f = (Get-ItemProperty -Path {_LSA} -Name SCENoApplyLegacyAuditPolicy -ErrorAction "
                    "SilentlyContinue).SCENoApplyLegacyAuditPolicy; "
                    "$p = (auditpol /get /subcategory:\"Process Creation\") -join ' '; "
                    "$l = (auditpol /get /subcategory:\"Logon\") -join ' '; "
                    "[bool]($f -eq 1 -and $p -match 'Success' -and $l -match 'Success and Failure')"),
        ),
        GuestFault(
            id="gpo-msi-share-denied",
            title="The new PCs never get 7-Zip, and the share works for everyone",
            os=WINDOWS,
            teaches="who reads a software installation package (the computer account, at startup, before anyone "
                    "logs on), NTFS against share permissions, and the Application Management events on the PC",
            symptom="PCs restarted twice still have no 7-Zip; users browsing \\\\<server>\\Software see the MSI "
                    "and can even run it by hand",
            apply=("$s = Get-SmbShare -Name 'Software' -ErrorAction SilentlyContinue; "
                   "if (-not $s) { 'no share called Software on this machine: build it first (lesson gpo-software-install)' } "
                   "else { " + _WINLAB_DIR + "if (-not (Test-Path -Path 'C:\\winlab\\software-acl.txt')) { "
                   "Set-Content -Path 'C:\\winlab\\software-acl.txt' -Value (Get-Acl -Path $s.Path).Sddl }; "
                   + _locked_acl("$s.Path", "Domain Users") + "'broken' }"),
            clear=("$s = Get-SmbShare -Name 'Software' -ErrorAction SilentlyContinue; if ($s) { "
                   + _restore_acl("$s.Path", "C:\\winlab\\software-acl.txt") + "}; 'ok'"),
            hints=(
                "Look on a PC first: Get-WinEvent -LogName Application -MaxEvents 30 | Where-Object ProviderName "
                "-match 'Application Management' shows the install failing at startup with access denied, and "
                "gpresult /r /scope computer shows the GPO applied. So the policy arrives and the package cannot be "
                "read.",
                "Who reads the package? At startup nobody is logged on: the PC's computer account (CORP\\PC01$) reads "
                "\\\\<server>\\Software. Users are Domain Users, computers are Domain Computers. On the server, "
                "Get-SmbShareAccess -Name Software and Get-Acl (Get-SmbShare Software).Path | Format-List "
                "AccessToString: the folder's NTFS permissions were reset to Administrators, SYSTEM and Domain Users "
                "only, with inheritance off.",
                "Give computers read again: icacls <folder> /grant \"Domain Computers:(OI)(CI)RX\" (Authenticated "
                "Users also covers computer accounts). Then restart a PC: the install runs before the logon screen, "
                "and Get-Package 7-Zip* or the Programs list shows it.",
            ),
            verify=("$s = Get-SmbShare -Name 'Software' -ErrorAction SilentlyContinue; $ok = $false; "
                    "if ($s) { foreach ($r in (Get-Acl -Path $s.Path).Access) { $sid = ''; "
                    "try { $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } "
                    "catch { $sid = '' }; "
                    "$rx = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute; "
                    "if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $rx) -eq $rx -and "
                    "($sid -eq 'S-1-5-11' -or $sid -eq 'S-1-1-0' -or $sid -match '-515$')) { $ok = $true } } }; $ok"),
        ),
        GuestFault(
            id="choco-source-internet",
            title="choco install hangs and then cannot find a package that is on the share",
            os=WINDOWS,
            teaches="Chocolatey's sources (choco source list), why a sealed network keeps only its internal feed, "
                    "and reading what choco tried before it gave up",
            symptom="choco install corp-7zip -y waits, then says the package was not found with the source(s) "
                    "listed; the package is on the internal feed and other PCs install it",
            apply=("if (-not (Get-Command -Name choco -ErrorAction SilentlyContinue)) { 'no Chocolatey on this machine: "
                   "install it first (lesson chocolatey-internal-feed)' } else { " + _WINLAB_DIR + _CHOCO_ROWS
                   + "$on = @($rows | Where-Object { $_[2] -eq 'False' }); "
                   "if (-not (Test-Path -Path 'C:\\winlab\\choco-sources.txt')) { Set-Content -Path "
                   "'C:\\winlab\\choco-sources.txt' -Value ($on | ForEach-Object { $_[0] }) }; "
                   "foreach ($r in $on) { choco source disable --name=\"$($r[0])\" | Out-Null }; "
                   "choco source add --name=chocolatey --source=https://community.chocolatey.org/api/v2/ --priority=0 "
                   "| Out-Null; choco source enable --name=chocolatey | Out-Null; 'broken' }"),
            clear=("if (Get-Command -Name choco -ErrorAction SilentlyContinue) { "
                   "Get-Content -Path 'C:\\winlab\\choco-sources.txt' -ErrorAction SilentlyContinue | Where-Object { $_ } | "
                   "ForEach-Object { choco source enable --name=\"$_\" | Out-Null }; "
                   "choco source disable --name=chocolatey | Out-Null; "
                   "Remove-Item -Path 'C:\\winlab\\choco-sources.txt' -Force -ErrorAction SilentlyContinue }; 'ok'"),
            hints=(
                "Ask choco where it looks: choco source list. Then run the install with --verbose (or read "
                "C:\\ProgramData\\chocolatey\\logs\\chocolatey.log): each source it tried, and how each failed.",
                "Only one source is enabled, community.chocolatey.org, and the lab has no internet: the name does "
                "not resolve, choco waits for it and reports the package missing. The internal feed is still in the "
                "list, disabled. Somebody followed an internet how-to on this PC.",
                "choco source enable --name=<your internal source>, then choco source disable --name=chocolatey (or "
                "choco source remove). choco install corp-7zip -y now installs from the share. On a fleet the sources "
                "belong in your install script or a GPO-run script, so one PC cannot drift.",
            ),
            verify=("if (-not (Get-Command -Name choco -ErrorAction SilentlyContinue)) { 'False' } else { " + _CHOCO_ROWS
                    + "$on = @($rows | Where-Object { $_[2] -eq 'False' }); "
                    "$net = @($on | Where-Object { $_[1] -match 'chocolatey\\.org' }); "
                    "[bool]($net.Count -eq 0 -and $on.Count -gt 0) }"),
        ),
        GuestFault(
            id="cert-renewal-stalled",
            roles=("iis",),
            title="The expiry report lists the web certificate with nine days left, and nothing renews it",
            os=WINDOWS,
            teaches="reading what a binding serves before it fails, who renews a certificate (autoenrolment, "
                    "the CertificateServicesClient task, a template), and replacing a stopgap before it expires",
            symptom="this morning's certificate expiry report flags the HTTPS certificate on this server: nine "
                    "days left; the site works today; certutil -pulse changes nothing",
            apply=("Import-Module WebAdministration; " + _WINLAB_DIR
                   + f"$b = Get-Item {_HTTPS} -ErrorAction SilentlyContinue; "
                   "if ($b -and -not (Test-Path -Path 'C:\\winlab\\renew-thumb.txt')) { Set-Content -Path "
                   "'C:\\winlab\\renew-thumb.txt' -Value $b.Thumbprint }; "
                   "$fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName; "
                   "$c = New-SelfSignedCertificate -DnsName $fqdn -CertStoreLocation 'Cert:\\LocalMachine\\My' "
                   "-NotBefore (Get-Date).AddDays(-81) -NotAfter (Get-Date).AddDays(9) -FriendlyName 'web (stopgap)'; "
                   f"if ($b) {{ Remove-Item {_HTTPS} }}; New-Item {_HTTPS} -Value $c | Out-Null; "
                   f"Disable-ScheduledTask {_AE_TASK} | Out-Null; 'broken'"),
            clear=("Import-Module WebAdministration; $t = Get-Content -Path 'C:\\winlab\\renew-thumb.txt' -ErrorAction "
                   "SilentlyContinue; $c = $null; if ($t) { $c = Get-Item -Path \"Cert:\\LocalMachine\\My\\$t\" "
                   "-ErrorAction SilentlyContinue }; "
                   f"if ($c) {{ Remove-Item {_HTTPS} -ErrorAction SilentlyContinue; New-Item {_HTTPS} -Value $c | Out-Null }}; "
                   "Get-ChildItem -Path 'Cert:\\LocalMachine\\My' | Where-Object { $_.FriendlyName -eq 'web (stopgap)' } "
                   "| Where-Object { -not $c -or $_.Thumbprint -ne $c.Thumbprint } | Remove-Item -ErrorAction SilentlyContinue; "
                   f"Enable-ScheduledTask {_AE_TASK} | Out-Null; "
                   "Remove-Item -Path 'C:\\winlab\\renew-thumb.txt' -Force -ErrorAction SilentlyContinue; 'ok'"),
            hints=(
                "Read what the site serves, not what you think it has: (Get-Item IIS:\\SslBindings\\0.0.0.0!443)."
                "Thumbprint, then Get-Item Cert:\\LocalMachine\\My\\<thumbprint> | Format-List Subject, Issuer, "
                "FriendlyName, NotAfter. The issuer is the server itself: a self-signed stopgap, which no CA and no "
                "autoenrolment will ever renew.",
                "And the real certificate would not have renewed either: autoenrolment runs from a scheduled task, "
                "Get-ScheduledTask -TaskPath \\Microsoft\\Windows\\CertificateServicesClient\\ shows SystemTask "
                "Disabled. certutil -pulse asks that machinery to run, which is why it did nothing.",
                "Enable-ScheduledTask -TaskPath \\Microsoft\\Windows\\CertificateServicesClient\\ -TaskName SystemTask; "
                "certutil -pulse (or Get-Certificate -Template <your web template> -DnsName <fqdn> -CertStoreLocation "
                "Cert:\\LocalMachine\\My); bind the CA's certificate to 0.0.0.0!443 and only then remove the stopgap. "
                "Run your expiry report again: nothing under 30 days.",
            ),
            verify=("Import-Module WebAdministration; "
                    f"$t = (Get-Item {_HTTPS} -ErrorAction SilentlyContinue).Thumbprint; $c = $null; "
                    "if ($t) { $c = Get-Item -Path \"Cert:\\LocalMachine\\My\\$t\" -ErrorAction SilentlyContinue }; "
                    f"$task = Get-ScheduledTask {_AE_TASK} -ErrorAction SilentlyContinue; "
                    "[bool]($c -and $c.NotAfter -gt (Get-Date).AddDays(20) -and $c.Issuer -ne $c.Subject -and $task "
                    "-and $task.State -ne 'Disabled')"),
        ),
        GuestFault(
            id="report-log-denied",
            title="No daily report this morning, and the task says it ran",
            os=WINDOWS,
            teaches="a scheduled task's Last Run Result, running a script the way the task does (as the gMSA, "
                    "not as you), NTFS for a service account, and a report that tells you when it fails",
            symptom="the admin mailbox has no daily report today; the task in Task Scheduler ran on time, its "
                    "Last Run Result is not 0x0, and the log under C:\\Scripts\\Logs stopped yesterday",
            apply=("$p = 'C:\\Scripts\\Logs'; "
                   "if (-not (Test-Path -Path $p)) { 'no C:\\Scripts\\Logs on this machine: build the report first "
                   "(lesson scheduled-report-gmsa)' } else { " + _WINLAB_DIR
                   + "if (-not (Test-Path -Path 'C:\\winlab\\report-logs-acl.txt')) { Set-Content -Path "
                   "'C:\\winlab\\report-logs-acl.txt' -Value (Get-Acl -Path $p).Sddl }; "
                   + _locked_acl("$p", "BUILTIN\\Users")
                   + "Set-Content -Path 'C:\\winlab\\report-broken-at.txt' -Value (Get-Date).Ticks; 'broken' }"),
            clear=("$p = 'C:\\Scripts\\Logs'; if (Test-Path -Path $p) { "
                   + _restore_acl("$p", "C:\\winlab\\report-logs-acl.txt")
                   + "}; Remove-Item -Path 'C:\\winlab\\report-broken-at.txt' -Force -ErrorAction SilentlyContinue; 'ok'"),
            hints=(
                "Start from the task, not the mailbox: Get-ScheduledTask | Where-Object { $_.Principal.UserId -like "
                "'*$' } | Get-ScheduledTaskInfo shows LastRunTime and LastTaskResult. A result of 1 is your script's "
                "own failure. Then read the Application log for the script's own event (it writes one when it "
                "fails, if you built it that way) and the last lines of the newest file in C:\\Scripts\\Logs.",
                "Running the script yourself proves nothing: you are an administrator, the task is the gMSA. What "
                "can the gMSA do in the log folder? Get-Acl C:\\Scripts\\Logs | Format-List AccessToString: "
                "Administrators, SYSTEM and Users read only, inheritance off. The account cannot write its log, and "
                "a script with $ErrorActionPreference = 'Stop' stops there, before it sends the mail.",
                "Grant the gMSA modify on the folder: icacls C:\\Scripts\\Logs /grant \"CORP\\svc-report$:(OI)(CI)M\". "
                "Run the task now (Start-ScheduledTask), check LastTaskResult is 0, the log has today's lines and "
                "the report is in the admin mailbox. Then make a failure visible: the script's catch block should "
                "write an error event and mail that it failed.",
            ),
            verify=("$at = [long]0; $f = 'C:\\winlab\\report-broken-at.txt'; "
                    "if (Test-Path -Path $f) { $at = [long]((Get-Content -Path $f -Raw).Trim()) }; "
                    "$t = @(Get-ScheduledTask | Where-Object { \"$($_.Principal.UserId)\" -match '\\$$' -and "
                    "\"$($_.Actions.Arguments)\" -match 'Scripts' }); "
                    "$ok = @($t | Where-Object { $i = $_ | Get-ScheduledTaskInfo; $i.LastTaskResult -eq 0 -and "
                    "$i.LastRunTime.Ticks -gt $at }); [bool]($t.Count -gt 0 -and $ok.Count -eq $t.Count)"),
        ),
    ]


FAULT_IDS = ("wef-reader-removed", "wazuh-agent-wrong-manager", "scan-target-no-ping", "baseline-audit-override",
             "gpo-msi-share-denied", "choco-source-internet", "cert-renewal-stalled", "report-log-denied")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
