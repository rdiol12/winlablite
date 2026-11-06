"""Windows updates for an isolated lab: Microsoft's own packages, carried in.

A lab has no Internet, so it is patched the way a disconnected network is.
The student downloads the cumulative updates from the Microsoft Update
Catalog (https://www.catalog.update.microsoft.com) on their own PC: the
.msu files, and the servicing stack update or checkpoint update an article
says must go first. The Updates window lists what is on this PC, says which
Windows build each one brings and which lab machines it fits, and writes the
chosen packages onto a patch stick or burns them onto a disc, on the lab's
media shelf. From there it is the student's work inside the machines: wusa
or DISM /Add-Package by hand, or a WSUS server (wsus01) with the clients
pointed at http://wsus01:8530 by Group Policy; and an in-place upgrade from
the newer Windows DVD in the drive (setup.exe /auto upgrade).

Nothing here installs, approves or configures anything for the student, and
winlab never ships an update: Microsoft's packages are downloaded by the
user, onto the user's PC, under their Windows licence. `winlab updates fetch
<link>` downloads one from a Catalog download link the user pastes, with
their consent, as `winlab bootstrap` and `winlab mecm prepare` fetch from
their publishers; it only talks to Microsoft's download hosts.

Where packages are found: images/updates (winlab's updates folder), the image
store's downloads folder, and the user's Downloads, Desktop and Documents
(the top level). A package's KB number, OS and architecture come from the
Catalog's file name (windows10.0-kb5044281-x64_<sha1>.msu); an .msu is a
cabinet, and the servicing stack it carries (SSU-<build>-x64.cab) is read
from its file list. The build a KB brings comes from a short table of
known releases, or from the user's own note (`winlab updates label`), since
the KB article's title says it: "KB5044281 (OS Build 20348.2762)".

Four graded faults register with guestfaults: the Windows Update service
disabled, the WSUS client pointed at a server that is gone, the servicing
stack's own service (Windows Modules Installer) disabled, and a Windows 11
PC whose scan source policy sends its quality updates to Windows Update.
"""

from __future__ import annotations

import json
import re
import struct
import urllib.parse
from pathlib import Path

from . import images, paths

CATALOG_URL = "https://www.catalog.update.microsoft.com"
LICENSE = ("Microsoft's update packages, under the terms of your Windows licence; downloaded by "
           "you onto this PC, never shipped or passed on by winlab")
FOLDER = "updates"
NOTES = "builds.json"          # the user's own KB -> build notes
STICK_LABEL = "UPDATES"
README = "UPDATES.TXT"
DISC_MAX = 8 * 1024**3          # a dual-layer DVD
FETCH_HOSTS = ("download.windowsupdate.com", "catalog.sf.dl.delivery.mp.microsoft.com",
               "download.microsoft.com", "delivery.mp.microsoft.com")
_KB = re.compile(r"(?i)(?<![a-z0-9])kb(\d{6,8})")
_CATALOG_NAME = re.compile(r"(?i)^windows(\d+\.\d+)-kb(\d{6,8})-(x64|x86|arm64)")
_SSU = re.compile(r"(?i)^ssu-(\d{5})\.(\d{1,5})-")
_BUILD = re.compile(r"^(\d{5})\.(\d{1,5})$")

# What each base build is, and the catalog images it fits.
FAMILIES = {
    "17763": ("Windows Server 2019 / Windows 10 1809", ("ws2019",)),
    "19044": ("Windows 10 21H2", ("win10",)),
    "19045": ("Windows 10 22H2", ("win10",)),
    "20348": ("Windows Server 2022", ("ws2022",)),
    "22621": ("Windows 11 22H2", ("win11",)),
    "22631": ("Windows 11 23H2", ("win11",)),
    "26100": ("Windows 11 24H2 / Windows Server 2025", ("ws2025", "win11")),
}
# Known releases, from Microsoft's update history pages: KB -> (build, kind).
# kind: cu (a cumulative update), ssu (a servicing stack update that must go
# in first), checkpoint (a checkpoint cumulative update later ones build on).
KNOWN = {
    "KB5005112": ("17763", "ssu"),
    "KB5044277": ("17763.6414", "cu"),
    "KB5046615": ("17763.6532", "cu"),
    "KB5044273": ("19045.5011", "cu"),
    "KB5046613": ("19045.5131", "cu"),
    "KB5044281": ("20348.2762", "cu"),
    "KB5046616": ("20348.2849", "cu"),
    "KB5044285": ("22631.4317", "cu"),
    "KB5046633": ("22631.4460", "cu"),
    "KB5043080": ("26100.1742", "checkpoint"),
    "KB5044284": ("26100.2033", "cu"),
    "KB5046617": ("26100.2314", "cu"),
}
KIND_TITLE = {"cu": "Cumulative update", "ssu": "Servicing stack update", "checkpoint": "Checkpoint cumulative update",
              "update": "Update", "wsus-export": "WSUS metadata export"}
_ORDER = {"ssu": 0, "checkpoint": 1, "cu": 2, "update": 3, "wsus-export": 4}


class UpdatesError(Exception):
    pass


# ---------------------------------------------------------------- folders
def updates_dir() -> Path:
    """winlab's updates folder, beside the Windows images."""
    return paths.images_dir() / FOLDER


def search_dirs() -> list[tuple[str, Path]]:
    from . import readiness
    out = [("updates folder", updates_dir()), ("image downloads", paths.downloads_dir())]
    for p in readiness.search_dirs():
        if all(p.resolve() != q.resolve() for _, q in out if q.exists()):
            out.append((p.name or str(p), p))
    return out


def notes() -> dict[str, str]:
    try:
        data = json.loads((updates_dir() / NOTES).read_text(encoding="utf-8"))
        return {str(k).upper(): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def label(kb: str, build: str) -> dict:
    """The user's own note of the build a KB brings (from its article's title)."""
    kb = kb.upper() if kb.upper().startswith("KB") else f"KB{kb}"
    if not re.fullmatch(r"KB\d{6,8}", kb):
        raise UpdatesError(f"{kb} is not a KB number")
    if build and not _BUILD.match(build):
        raise UpdatesError("a build is written like 20348.2762 (OS build, a dot, the revision)")
    n = notes()
    if build:
        n[kb] = build
    else:
        n.pop(kb, None)
    updates_dir().mkdir(parents=True, exist_ok=True)
    (updates_dir() / NOTES).write_text(json.dumps(n, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return {"kb": kb, "build": build}


# ------------------------------------------------------------- cabinets
def cab_names(path: Path, limit: int = 4096) -> list[str]:
    """The file names in a cabinet (an .msu is one): read from its CFFILE
    entries, nothing decompressed."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(36)
            if len(head) < 36 or head[:4] != b"MSCF":
                return []
            coff = struct.unpack_from("<I", head, 16)[0]
            count = struct.unpack_from("<H", head, 28)[0]
            fh.seek(coff)
            blob = fh.read(min(count, limit) * 280)
    except OSError:
        return []
    out, pos = [], 0
    for _ in range(min(count, limit)):
        if pos + 16 > len(blob):
            break
        end = blob.find(b"\0", pos + 16)
        if end < 0:
            break
        out.append(blob[pos + 16:end].decode("latin-1"))
        pos = end + 1
    return out


# --------------------------------------------------------------- packages
def describe(path: Path, where: str = "", known: dict | None = None) -> dict | None:
    """One package file as the Updates window shows it; None for a file
    that is not a Windows update."""
    name = path.name
    low = name.lower()
    if low.endswith(".xml.gz"):
        kind, kb, ver, arch = "wsus-export", "", "", ""
    elif low.endswith((".msu", ".cab")):
        m = _CATALOG_NAME.match(name)
        k = _KB.search(name)
        if not m and not k:
            return None
        kb = "KB" + (m.group(2) if m else k.group(1))
        ver, arch = (m.group(1), m.group(3).lower()) if m else ("", "")
        if not arch:
            a = re.search(r"(?i)(x64|amd64|x86|arm64)", name)
            arch = ("x64" if a.group(1).lower() == "amd64" else a.group(1).lower()) if a else ""
        kind = "update"
    else:
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    build, ssu = "", ""
    if kb:
        k = KNOWN.get(kb)
        if k:
            build, kind = k
        build = (known if known is not None else notes()).get(kb, build)
        if kind == "update" and _BUILD.match(build):
            kind = "cu"
    if low.endswith(".msu"):
        for inner in cab_names(path):
            s = _SSU.match(inner)
            if s:
                ssu = f"{s.group(1)}.{s.group(2)}"
                build = build or s.group(1)
    base = build.split(".")[0] if build else ""
    fam, fits = FAMILIES.get(base, ("", ()))
    if not fam and ver:
        fam = {"10.0": "Windows 10 / Windows Server 2016-2022", "11.0": "Windows 11 / Windows Server 2025"}.get(ver, "")
    return {"id": kb or path.stem.split(".")[0], "kb": kb, "file": name, "path": str(path), "where": where,
            "mb": max(1, size >> 20) if size else 0, "bytes": size, "kind": kind,
            "kind_title": KIND_TITLE.get(kind, "Update"), "os": fam, "build": build, "ssu": ssu,
            "arch": arch, "fits": list(fits)}


def scan() -> list[dict]:
    """Every update package on this PC, in the order they install: servicing
    stack first, then a checkpoint, then the cumulative updates by build."""
    found: dict[str, dict] = {}
    known = notes()
    for where, root in search_dirs():
        if not root.is_dir():
            continue
        deep = root == updates_dir()
        try:
            files = sorted(root.rglob("*") if deep else root.iterdir())
        except OSError:
            continue
        for f in files:
            if not f.is_file() or f.name.lower() in found:
                continue
            d = describe(f, where, known)
            if d:
                found[f.name.lower()] = d
    def key(d):
        b = d["build"].split(".") + ["0"]
        return (d["os"] or "~", _ORDER.get(d["kind"], 9), int(b[0] or 0), int(b[1] or 0), d["file"].lower())
    return sorted(found.values(), key=key)


def machines(lab) -> list[dict]:
    """The lab's Windows machines (a workbench machine installed by hand
    too) and the build their media installs."""
    out = []
    for n in lab.node_list():
        base = n.image[:-5] if n.image.endswith("-core") else n.image
        if not images.CATALOG.get(base) or not images.CATALOG[base].kind.startswith("windows-"):
            continue
        ed = images.edition(n.image)
        build = str((ed or {}).get("build") or "")
        if not build:
            lo, hi = images.BUILDS.get(base, (0, 0))
            build = str(lo) if lo and lo == hi else ""
        out.append({"id": n.id, "image": base, "build": build, "os": images.CATALOG[base].short})
    return out


def fitting(pkg: dict, lab) -> list[str]:
    """The lab machines a package is for: the same base build when the
    machine's media was read, the same catalog image otherwise."""
    base = pkg["build"].split(".")[0] if pkg["build"] else ""
    out = []
    for m in machines(lab):
        if m["build"] and base:
            if m["build"] == base:
                out.append(m["id"])
        elif m["image"] in pkg["fits"]:
            out.append(m["id"])
    return out


def pick(wanted: list[str], pkgs: list[dict] | None = None) -> list[dict]:
    """Packages by KB number, file name or 'all', in install order."""
    pkgs = scan() if pkgs is None else pkgs
    if not wanted:
        raise UpdatesError("choose at least one update")
    if [w.lower() for w in wanted] == ["all"]:
        if not pkgs:
            raise UpdatesError(f"no updates on this PC yet: download them from {CATALOG_URL}")
        return pkgs
    out = []
    for w in wanted:
        key = w.strip().upper()
        key = key if key.startswith("KB") or "." in key else f"KB{key}"
        hits = [p for p in pkgs if p["kb"] == key or p["file"].upper() == w.strip().upper()]
        if not hits:
            raise UpdatesError(f"no update {w} on this PC: winlab updates list shows them")
        out += [h for h in hits if h not in out]
    return [p for p in pkgs if p in out]


def readme(chosen: list[dict]) -> str:
    """The list that goes on the media, in install order."""
    lines = ["Windows updates, in the order they install", ""]
    for i, p in enumerate(chosen, 1):
        lines.append(f"{i}. {p['kb'] or p['file']}  {p['kind_title']}" + (f", {p['os']}" if p["os"] else "")
                     + (f", OS build {p['build']}" if "." in p["build"] else ""))
        lines.append(f"   {_media_path(p)}")
    lines += ["", f"Downloaded from the Microsoft Update Catalog ({CATALOG_URL}).", ""]
    return "\r\n".join(lines)


def _media_path(p: dict) -> str:
    return ("WSUS/" if p["kind"] == "wsus-export" else "Updates/") + p["file"]


# ------------------------------------------------------------ the media
def to_stick(lab_name: str, wanted: list[str], title: str = "") -> dict:
    """The chosen packages written onto a new USB stick on the lab's shelf."""
    from . import media, mediashelf
    chosen = pick(wanted)
    total = sum(p["bytes"] for p in chosen)
    if total > (media.MAX_MB - 64) * 1024 * 1024:
        raise UpdatesError(f"those take {total >> 20} MB and a stick holds {media.MAX_MB} MB: burn them to a disc")
    files = {_media_path(p): Path(p["path"]).read_bytes() for p in chosen}
    files[README] = readme(chosen).encode("utf-8")
    title = title or "Patch stick " + " ".join(p["kb"] for p in chosen if p["kb"])[:40].strip()
    sid = mediashelf._new_id(lab_name, "patch-" + "-".join(p["kb"].lower() for p in chosen if p["kb"])[:20])
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise UpdatesError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title.strip()}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title.strip(), "files": len(chosen), "mb": total >> 20}


def to_disc(lab_name: str, wanted: list[str], label_: str = "") -> dict:
    """The chosen packages burned onto a new disc on the lab's shelf."""
    from . import isowrite, mediashelf
    chosen = pick(wanted)
    total = sum(p["bytes"] for p in chosen)
    if total > DISC_MAX:
        raise UpdatesError(f"those take {total >> 20} MB: more than a dual-layer DVD; burn two discs")
    vol = re.sub(r"[^A-Za-z0-9_]", "_", label_ or STICK_LABEL)[:32].upper() or STICK_LABEL
    d = mediashelf.shelf_dir(lab_name, "discs")
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"{vol.lower()}.iso"
    i = 2
    while dest.exists():
        dest, i = d / f"{vol.lower()}-{i}.iso", i + 1
    note = dest.with_suffix(".txt.tmp")
    note.write_text(readme(chosen), encoding="utf-8")
    try:
        w = isowrite.IsoWriter(vol)
        for p in chosen:
            w.add_file(p["path"], _media_path(p))
        w.add_file(note, README)
        w.write(dest.with_suffix(".tmp"))
    except (isowrite.IsoWriteError, OSError) as exc:
        dest.with_suffix(".tmp").unlink(missing_ok=True)
        raise UpdatesError(str(exc)) from exc
    finally:
        note.unlink(missing_ok=True)
    dest.with_suffix(".tmp").replace(dest)
    return {"ref": f"file:{dest.resolve()}", "title": vol, "files": len(chosen), "mb": total >> 20}


# ------------------------------------------------------------- fetching
def check_link(url: str) -> str:
    """A Catalog download link, refused unless it is Microsoft's and a package."""
    u = urllib.parse.urlparse(url.strip())
    host = (u.hostname or "").lower()
    if u.scheme not in ("https", "http") or not any(host == h or host.endswith("." + h) for h in FETCH_HOSTS):
        raise UpdatesError("that is not a Microsoft download link: copy the link from the Catalog's Download window")
    name = Path(urllib.parse.unquote(u.path)).name
    if not name.lower().endswith((".msu", ".cab")):
        raise UpdatesError("the link must end in .msu or .cab")
    return name


def fetch(url: str, consent: bool = False) -> Path:
    """Downloads one package from Microsoft onto this PC (the updates folder),
    once the user said yes; never into a lab."""
    if not consent:
        raise UpdatesError("winlab downloads Microsoft's packages only when you say so: " + LICENSE)
    from .bootstrap import BootstrapError, _download_to
    name = check_link(url)
    try:
        return _download_to(url.strip(), updates_dir() / name, label=name)
    except BootstrapError as exc:
        raise UpdatesError(str(exc)) from exc


# ------------------------------------------------------------ the desktop
def act(dash, action: str, params: dict) -> dict:
    """The Updates window (webui actions upd-*): read-only lists, and the
    physical act of writing a stick or burning a disc."""
    lab = dash.lab
    try:
        if action == "upd-list":
            pkgs = scan()
            for p in pkgs:
                p["for"] = fitting(p, lab)
            return {"ok": True, "packages": pkgs, "machines": machines(lab), "folder": str(updates_dir()),
                    "catalog": CATALOG_URL, "license": LICENSE}
        wanted = [w for w in str(params.get("kbs") or "").replace(";", ",").split(",") if w.strip()]
        if action == "upd-stick":
            r = to_stick(lab.name, wanted, str(params.get("title") or ""))
            return {"ok": True, "stick": r["id"],
                    "message": f"{r['title']}: {r['files']} package(s), {r['mb']} MB, on the media shelf"}
        if action == "upd-disc":
            r = to_disc(lab.name, wanted, str(params.get("label") or ""))
            return {"ok": True, "disc": r["ref"],
                    "message": f"disc {r['title']} burned with {r['files']} package(s), {r['mb']} MB, on the media shelf"}
        if action == "upd-label":
            r = label(str(params.get("kb") or ""), str(params.get("build") or "").strip())
            return {"ok": True, "message": f"{r['kb']}: OS build {r['build']}" if r["build"] else f"{r['kb']}: note removed"}
    except (UpdatesError, OSError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown updates action {action!r}"}


# -------------------------------------------------------------- the CLI
def add_cli(sub) -> None:
    up = sub.add_parser("updates", help="Windows updates you downloaded: list them, put them on a stick or a disc")
    us = up.add_subparsers(dest="updcmd", metavar="<op>")
    ls = us.add_parser("list", help="the update packages on this PC, the build each brings, the machines it fits")
    ls.add_argument("--lab", default="", help="say which of this lab's machines each one fits")
    for op, what in (("stick", "write packages onto a new patch stick on the lab's media shelf"),
                     ("disc", "burn packages onto a new disc on the lab's media shelf")):
        p = us.add_parser(op, help=what)
        p.add_argument("lab")
        p.add_argument("kbs", nargs="+", help="KB numbers or file names, or all")
        p.add_argument("--title" if op == "stick" else "--label", default="")
    lb = us.add_parser("label", help="note the OS build a KB brings (its article's title says it)")
    lb.add_argument("kb")
    lb.add_argument("build", nargs="?", default="", help="like 20348.2762; leave out to forget the note")
    ft = us.add_parser("fetch", help="download one package from a Microsoft Update Catalog link onto this PC")
    ft.add_argument("url")
    ft.add_argument("--yes", action="store_true", help="you agree: download it now")


def render(pkgs: list[dict], lab=None) -> str:
    if not pkgs:
        return (f"no Windows updates on this PC yet. Download the cumulative update (.msu) for each Windows "
                f"you run from {CATALOG_URL}\ninto {updates_dir()} or your Downloads folder.")
    out = [f"{'KB':<11}{'kind':<30}{'OS build':<12}{'MB':>6}  for / file"]
    for p in pkgs:
        fits = ", ".join(fitting(p, lab)) if lab is not None else p["os"]
        out.append(f"{p['kb'] or '-':<11}{p['kind_title']:<30}{p['build'] or '?':<12}{p['mb']:>6}  {fits or p['os'] or '?'}")
        out.append(f"{'':<11}{p['file']}" + (f"  (servicing stack {p['ssu']} inside)" if p["ssu"] else "")
                   + f"  [{p['where']}]")
    return "\n".join(out)


def run_cli(args) -> int:
    import sys
    op = args.updcmd or "list"
    try:
        if op == "list":
            lab = None
            if getattr(args, "lab", ""):
                from . import schema
                lab = schema.load(args.lab)
            print(render(scan(), lab))
        elif op in ("stick", "disc"):
            from . import schema
            lab = schema.load(args.lab)
            r = to_stick(lab.name, args.kbs, args.title) if op == "stick" else to_disc(lab.name, args.kbs, args.label)
            print(f"{r['title']}: {r['files']} package(s), {r['mb']} MB, on {lab.name}'s media shelf "
                  f"(winlab media {lab.name} <machine> {'plug' if op == 'stick' else 'insert'} ...)")
        elif op == "label":
            r = label(args.kb, args.build)
            print(f"{r['kb']}: OS build {r['build']}" if r["build"] else f"{r['kb']}: note removed")
        elif op == "fetch":
            ok = args.yes
            if not ok and sys.stdin.isatty():
                print(f"Download {check_link(args.url)} from Microsoft onto this PC?\n  {LICENSE}")
                ok = input("Download it? [y/N] ").strip().lower() in ("y", "yes")
            if not ok:
                print("nothing downloaded (run again with --yes to agree)", file=sys.stderr)
                return 3
            print(f"saved: {fetch(args.url, consent=True)}")
        return 0
    except (UpdatesError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - schema.LabError and friends
        print(f"error: {exc}", file=sys.stderr)
        return 1


# ----------------------------------------------------------- guest faults
_WU_POL = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [
        GuestFault(
            id="wu-service-disabled",
            title="Updates will not install: the Windows Update service is disabled",
            os=WINDOWS,
            teaches="which service each update tool needs (wusa and Windows Update need wuauserv, DISM needs only the "
                    "servicing stack), reading an error code to its service, and service start types",
            symptom="double-clicking the .msu or wusa says 'Installer encountered an error: 0x80070422'; Settings > "
                    "Windows Update says updates could not be installed; the machine never shows up in WSUS again",
            apply="Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue; Set-Service -Name wuauserv -StartupType Disabled",
            clear="Set-Service -Name wuauserv -StartupType Manual; Start-Service -Name wuauserv",
            hints=(
                "Read the code, not the words: 0x80070422 is Win32 error 1058, 'the service cannot be started, either "
                "because it is disabled or because it has no enabled devices'. So the question is which service the "
                "installer needs. Get-WinEvent -LogName Setup -MaxEvents 20 shows the wusa attempts.",
                "wusa.exe and Windows Update both use the Windows Update service, wuauserv: Get-Service wuauserv | "
                "Select-Object Status, StartType says Stopped and Disabled. DISM /Online /Add-Package would still work "
                "(it talks to the servicing stack directly), which is a way round, not a fix.",
                "Set-Service -Name wuauserv -StartupType Manual (its normal start type: it starts on demand), then run "
                "the .msu again with wusa <file>.msu /quiet /norestart. Note that on Windows 10, 11 and Server 2019 on, "
                "the Windows Update Medic Service may repair this on its own after a while: do not count on it.",
            ),
            verify="$s = Get-Service -Name wuauserv; [bool]($s.StartType -ne 'Disabled')",
        ),
        GuestFault(
            id="wsus-wrong-server",
            roles=("domain-join",),
            title="The machine asks an update server that no longer exists",
            os=WINDOWS,
            teaches="where a client's update server comes from (the policy registry values, from a GPO or written "
                    "locally), gpresult to tell which, and checking the exact URL and port the client uses",
            symptom="Windows Update fails with 0x8024401c or 0x80072ee2 on this machine only, and it stops reporting "
                    "to WSUS; the WSUS server is up and other machines report fine",
            apply=("New-Item -Path '" + _WU_POL + "\\AU' -Force | Out-Null; "
                   "Set-ItemProperty -Path '" + _WU_POL + "' -Name WUServer -Value 'http://wsus-old.{domain}:8530'; "
                   "Set-ItemProperty -Path '" + _WU_POL + "' -Name WUStatusServer -Value 'http://wsus-old.{domain}:8530'; "
                   "Set-ItemProperty -Path '" + _WU_POL + "\\AU' -Name UseWUServer -Value 1 -Type DWord; "
                   "Restart-Service -Name wuauserv -Force -ErrorAction SilentlyContinue"),
            clear=("Set-ItemProperty -Path '" + _WU_POL + "' -Name WUServer -Value 'http://{wsus}:8530'; "
                   "Set-ItemProperty -Path '" + _WU_POL + "' -Name WUStatusServer -Value 'http://{wsus}:8530'; "
                   "gpupdate /target:computer /force | Out-Null"),
            hints=(
                "Ask the client where it goes: (Get-ItemProperty " + _WU_POL + ").WUServer and the AU subkey's "
                "UseWUServer. Then test exactly that: Test-NetConnection with the host name and port in the URL. "
                "Compare with a machine that works.",
                "These are policy values: something wrote them. gpresult /r /scope computer lists the GPOs that applied "
                "(the WSUS one, if the domain has it); gpresult /h report.html shows which GPO set 'Specify intranet "
                "Microsoft update service location', or none, which means a local leftover (an old image, a script).",
                "Put the right server back: gpupdate /target:computer /force re-applies the domain's GPO over the "
                "leftover; with no GPO, set WUServer and WUStatusServer to http://{wsus}:8530 yourself. Then "
                "Restart-Service wuauserv and UsoClient StartScan (or wuauclt /detectnow on Server 2016): the machine "
                "reports to WSUS again.",
            ),
            verify=("$p = Get-ItemProperty -Path '" + _WU_POL + "' -ErrorAction SilentlyContinue; "
                    "$u = Get-ItemProperty -Path '" + _WU_POL + "\\AU' -ErrorAction SilentlyContinue; "
                    "$c = New-Object System.Net.Sockets.TcpClient; "
                    "try { $ok = $c.ConnectAsync('{wsus}', 8530).Wait(5000) } catch { $ok = $false }; $c.Close(); "
                    "[bool]($p -and [string]$p.WUServer -match '^https?://{wsus}([.:/]|$)' -and "
                    "[string]$p.WUStatusServer -match '^https?://{wsus}([.:/]|$)' -and $u -and $u.UseWUServer -eq 1 -and $ok)"),
        ),
        GuestFault(
            id="servicing-stack-broken",
            title="Every update package fails, by hand and by DISM",
            os=WINDOWS,
            teaches="the servicing stack (Windows Modules Installer, TrustedInstaller, and CBS) that every package goes "
                    "through, its logs (CBS.log, dism.log), and the order servicing needs: servicing stack first",
            symptom="wusa fails with 0x80070422 and DISM /Online /Add-Package stops with 'Error: 1058'; Get-WindowsPackage "
                    "-Online fails too, while the Windows Update service itself is running",
            apply=("Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue; "
                   "Set-Service -Name TrustedInstaller -StartupType Disabled"),
            clear="Set-Service -Name TrustedInstaller -StartupType Manual",
            hints=(
                "Both tools fail, so look below them. DISM writes C:\\Windows\\Logs\\DISM\\dism.log and the servicing "
                "stack writes C:\\Windows\\Logs\\CBS\\CBS.log: Get-Content C:\\Windows\\Logs\\DISM\\dism.log -Tail 40 "
                "shows the session failing to start. Error 1058 means a disabled service.",
                "Every package, whichever tool installs it, goes through the Windows Modules Installer service "
                "(TrustedInstaller), the servicing stack's engine: Get-Service TrustedInstaller | Select-Object Status, "
                "StartType says Disabled. (wuauserv is fine: that is why this is not the Windows Update service fault.)",
                "Set-Service -Name TrustedInstaller -StartupType Manual (it starts on demand), then DISM /Online "
                "/Add-Package /PackagePath:<the .msu> again. The other servicing-stack failure looks like 0x800f0823 "
                "(CBS_E_NEW_SERVICING_STACK_REQUIRED): the update needs a newer servicing stack, so install the SSU "
                "its KB article names first, then the cumulative update.",
            ),
            verify=("$s = Get-Service -Name TrustedInstaller; "
                    "[bool]($s.StartType -ne 'Disabled' -and (Get-WindowsPackage -Online -ErrorAction SilentlyContinue | "
                    "Select-Object -First 1))"),
        ),
        GuestFault(
            id="wu-scan-source-wrong",
            roles=("domain-join",),
            title="One PC skips the WSUS approvals and asks Windows Update for its quality updates",
            os=WINDOWS,
            teaches="the scan source policy (Specify source service for specific classes of Windows Updates), "
                    "which on Windows 11 decides per class whether WSUS or Windows Update is asked, and telling a "
                    "GPO's value from a local leftover with gpresult",
            symptom="the WSUS console shows the PC reporting, but the quality updates approved for its group never "
                    "install; Settings > Windows Update on that PC fails with 0x8024402c or 'We couldn't connect "
                    "to the update service', while the other PCs install from WSUS",
            apply=("foreach ($k in '" + _WU_POL + "', '" + _WU_POL + "\\AU') { "
                   "if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null } }; "
                   "Set-ItemProperty -Path '" + _WU_POL + "' -Name SetPolicyDrivenUpdateSourceForQualityUpdates "
                   "-Value 0 -Type DWord; "
                   "Set-ItemProperty -Path '" + _WU_POL + "\\AU' -Name UseUpdateClassPolicySource -Value 1 -Type DWord; "
                   "Restart-Service -Name wuauserv -Force -ErrorAction SilentlyContinue"),
            clear=("Set-ItemProperty -Path '" + _WU_POL + "' -Name SetPolicyDrivenUpdateSourceForQualityUpdates "
                   "-Value 1 -Type DWord; gpupdate /target:computer /force | Out-Null"),
            hints=(
                "The PC reports to WSUS, so the server name is right; the question is which source it asks for "
                "which kind of update. Get-ItemProperty " + _WU_POL + " | Format-List SetPolicyDriven*: one class "
                "has 0, which means Windows Update, and this lab has no Internet.",
                "gpresult /h report.html on that PC: your GPO's 'Specify source service for specific classes of "
                "Windows Updates' sets the classes it lists, and nothing in the report set the quality-update "
                "value to Windows Update. A value no GPO wrote is a local leftover (an image, a script, a "
                "colleague's test) and gpupdate will not touch it unless a GPO sets that same value.",
                "Make the GPO say it for every class: in the scan source policy tick Quality Updates as well as the "
                "others (each ticked class = WSUS, value 1), so the domain owns the value; gpupdate /force, then "
                "Restart-Service wuauserv and UsoClient StartScan. The PC now takes its quality updates from "
                "{wsus} again.",
            ),
            verify=("$p = Get-ItemProperty -Path '" + _WU_POL + "' -ErrorAction SilentlyContinue; "
                    "[bool]($p -and $p.SetPolicyDrivenUpdateSourceForQualityUpdates -eq 1)"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
