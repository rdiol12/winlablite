"""Microsoft Configuration Manager: the media the mecm role installs from.

Configuration Manager needs more than its own setup files before a primary
site will install: the Windows ADK (Deployment Tools and User State
Migration Tool) and its Windows PE add-on, the Microsoft ODBC Driver 18 for
SQL Server, and setup's prerequisite downloads (setupdl). A real admin
downloads them all on a machine with Internet and carries them to the
server; the lab has no Internet, so winlab does the same and burns them onto
one disc image, mecm.iso, which the role puts in the machine's DVD drive.

Nothing here is downloaded by winlab or shipped with it: Microsoft's
licences let the customer download and use these, not pass them on. The
student downloads the Configuration Manager evaluation (it extracts itself
to a folder), the ADK and Windows PE add-on installers, and the ODBC driver
MSI, all from Microsoft; `winlab mecm prepare` finds them in Downloads,
runs the two ADK installers and setupdl in their documented offline-layout
modes on this PC (Windows only), and writes the disc.

Disc layout (Joliet names):
    CM\\        the extracted Configuration Manager media (SMSSETUP\\BIN\\X64\\setup.exe)
    ADK\\       adksetup.exe with its offline Installers folder
    WINPE\\     adkwinpesetup.exe with its offline Installers folder
    PREREQS\\   setup's prerequisite downloads (setupdl /NOUI)
    ODBC\\      msodbcsql.msi (ODBC Driver 18 for SQL Server, x64)
    winlab-mecm.json   what went in, and from where
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

MEDIA_ID = "mecm"
EVAL_PAGE = "https://www.microsoft.com/en-us/evalcenter/evaluate-microsoft-endpoint-configuration-manager"
ADK_PAGE = "https://learn.microsoft.com/windows-hardware/get-started/adk-install"
ODBC_PAGE = "https://learn.microsoft.com/sql/connect/odbc/download-odbc-driver-for-sql-server"
LICENSE = ("Microsoft Configuration Manager evaluation (180 days, non-production), the Windows ADK "
           "and Windows PE add-on, and the Microsoft ODBC Driver 18 for SQL Server, each under "
           "Microsoft's own licence terms; downloaded by you, never redistributed by winlab")
MANIFEST = "winlab-mecm.json"
SETUP = ("SMSSETUP", "BIN", "X64", "setup.exe")
SETUPDL = ("SMSSETUP", "BIN", "X64", "setupdl.exe")
ADK_EXE = "adksetup.exe"
WINPE_EXE = "adkwinpesetup.exe"
_ODBC = re.compile(r"^msodbcsql.*\.msi$", re.IGNORECASE)
_PREREQ = re.compile(r"^configmgr.*\.cab$", re.IGNORECASE)


class MecmError(Exception):
    pass


@dataclass
class Parts:
    cm: Path | None = None        # extracted media folder
    adk: Path | None = None       # adksetup.exe, or a folder with its offline layout
    winpe: Path | None = None     # adkwinpesetup.exe, or its layout folder
    odbc: Path | None = None      # msodbcsql.msi
    prereqs: Path | None = None   # setupdl's output folder

    def as_dict(self) -> dict:
        return {k: (str(v) if v else "") for k, v in self.__dict__.items()}


# ------------------------------------------------------------------ finding
def _ci(folder: Path, *parts: str) -> Path | None:
    """folder/parts matched without regard to case (the media's own
    capitalisation varies between releases)."""
    cur = folder
    for p in parts:
        try:
            if not cur.is_dir():
                return None
            nxt = next((c for c in cur.iterdir() if c.name.lower() == p.lower()), None)
        except OSError:  # a folder this account may not list
            return None
        if nxt is None:
            return None
        cur = nxt
    return cur


def is_cm_media(folder: Path) -> bool:
    f = _ci(folder, *SETUP)
    return bool(f and f.is_file())


def is_layout(folder: Path, exe: str) -> bool:
    """An ADK installer next to the Installers folder its /layout wrote."""
    e, inst = _ci(folder, exe), _ci(folder, "Installers")
    return bool(e and e.is_file() and inst and inst.is_dir() and any(inst.iterdir()))


def is_prereqs(folder: Path) -> bool:
    try:
        return any(_PREREQ.match(c.name) for c in folder.iterdir() if c.is_file())
    except OSError:
        return False


_JUNCTION = 0xA0000003   # IO_REPARSE_TAG_MOUNT_POINT (stat names it on Windows only)


def _is_link(p: Path) -> bool:
    """A symlink, or a Windows directory junction. A Windows
    profile's Documents holds the legacy junctions "My Music", "My Pictures"
    and "My Videos", which point elsewhere and deny listing to everyone: a
    walk follows none of them."""
    try:
        st = os.lstat(p)
    except OSError:
        return True
    return stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) == _JUNCTION


def _subfolders(folder: Path) -> list[Path]:
    out = []
    for c in folder.iterdir():
        try:
            if not _is_link(c) and c.is_dir():
                out.append(c)
        except OSError:
            pass
    return sorted(out)


def _walk(folder: Path, depth: int):
    """folder and the folders under it, depth levels down, never through a
    link and never into a folder this account may not list."""
    try:
        subs = _subfolders(folder)
    except OSError:
        return
    yield folder
    if depth <= 0:
        return
    for c in subs:
        yield from _walk(c, depth - 1)


def find_parts(folders: list[Path], depth: int = 3) -> Parts:
    """Looks through folders (Downloads, Desktop, Documents, or one the
    student names) for the pieces, up to depth folders down."""
    p = Parts()
    for root in folders:
        if not root.is_dir():
            continue
        for d in _walk(root, depth):
            if p.cm is None and is_cm_media(d):
                p.cm = d
            if is_layout(d, ADK_EXE):
                p.adk = d
            elif p.adk is None and _ci(d, ADK_EXE):
                p.adk = _ci(d, ADK_EXE)
            if is_layout(d, WINPE_EXE):
                p.winpe = d
            elif p.winpe is None and _ci(d, WINPE_EXE):
                p.winpe = _ci(d, WINPE_EXE)
            if p.prereqs is None and is_prereqs(d):
                p.prereqs = d
            if p.odbc is None:
                try:
                    p.odbc = next((c for c in sorted(d.iterdir()) if c.is_file() and _ODBC.match(c.name)), None)
                except OSError:
                    pass
    return p


def missing(p: Parts, on_windows: bool | None = None) -> list[str]:
    """What is still needed, as sentences a student can act on."""
    win = (os.name == "nt") if on_windows is None else on_windows
    out = []
    if p.cm is None:
        out.append("the Configuration Manager media: download the evaluation from "
                   f"{EVAL_PAGE}, run it and let it extract to a folder (in Downloads)")
    if p.adk is None:
        out.append(f"the Windows ADK installer (adksetup.exe) from {ADK_PAGE}")
    elif not p.adk.is_dir() and not win:
        out.append("the ADK's offline layout: run adksetup.exe /layout <folder> on a Windows PC "
                   "and point winlab at that folder")
    if p.winpe is None:
        out.append(f"the Windows PE add-on installer (adkwinpesetup.exe) from {ADK_PAGE}")
    elif not p.winpe.is_dir() and not win:
        out.append("the Windows PE add-on's offline layout: run adkwinpesetup.exe /layout <folder> "
                   "on a Windows PC")
    if p.odbc is None:
        out.append(f"the Microsoft ODBC Driver 18 for SQL Server, x64 (msodbcsql.msi) from {ODBC_PAGE}")
    if p.prereqs is None and p.cm is not None and not win:
        out.append("setup's prerequisite downloads: run SMSSETUP\\BIN\\X64\\setupdl.exe /NOUI <folder> "
                   "on a Windows PC with Internet")
    return out


# ---------------------------------------------------------------- preparing
def _run(cmd: list[str], what: str, say, run=subprocess.run) -> None:
    say(f"{what}: {' '.join(cmd)}")
    try:
        cp = run(cmd, capture_output=True, text=True)
    except OSError as exc:
        raise MecmError(f"{what} could not start: {exc}") from exc
    if cp.returncode not in (0, 3010):
        tail = ((cp.stdout or "") + (cp.stderr or "")).strip()[-400:]
        raise MecmError(f"{what} exited {cp.returncode}" + (f": {tail}" if tail else ""))


def prepare(parts: Parts, dest: Path | None = None, progress=None, run=subprocess.run,
            on_windows: bool | None = None, work: Path | None = None) -> dict:
    """Completes what can be completed on this PC (the ADK layouts and the
    prerequisite downloads, which need Windows and Internet), then writes
    the disc. Returns what images.installer_meta now records."""
    from . import images as im

    say = progress or (lambda _m: None)
    win = (os.name == "nt") if on_windows is None else on_windows
    gaps = missing(parts, win)
    if gaps:
        raise MecmError("still needed for the Configuration Manager media: " + "; ".join(gaps))
    dest = dest or im.installer_path(MEDIA_ID)
    dest.parent.mkdir(parents=True, exist_ok=True)
    own_work = work is None
    work = work or Path(tempfile.mkdtemp(prefix="winlab-mecm-", dir=str(dest.parent)))
    work.mkdir(parents=True, exist_ok=True)
    try:
        return _prepare(parts, dest, say, run, work)
    finally:
        if own_work:
            shutil.rmtree(work, ignore_errors=True)


def _prepare(parts: Parts, dest: Path, say, run, work: Path) -> dict:
    from . import images as im
    from .isowrite import IsoWriter

    adk, winpe, prereqs = parts.adk, parts.winpe, parts.prereqs
    if adk and not adk.is_dir():
        out = work / "ADK"
        _run([str(adk), "/quiet", "/layout", str(out)], "downloading the ADK's offline layout "
             "(about 1.5 GB)", say, run)
        adk = out
    if winpe and not winpe.is_dir():
        out = work / "WINPE"
        _run([str(winpe), "/quiet", "/layout", str(out)], "downloading the Windows PE add-on's "
             "offline layout (about 3 GB)", say, run)
        winpe = out
    if prereqs is None:
        out = work / "PREREQS"
        out.mkdir(parents=True, exist_ok=True)
        tool = _ci(parts.cm, *SETUPDL)
        if tool is None:
            raise MecmError(f"{parts.cm} has no SMSSETUP\\BIN\\X64\\setupdl.exe")
        _run([str(tool), "/NOUI", str(out)],
             "downloading Configuration Manager's prerequisite files (setupdl)", say, run)
        prereqs = out
    for label, folder, exe in (("ADK", adk, ADK_EXE), ("Windows PE add-on", winpe, WINPE_EXE)):
        if not is_layout(folder, exe):
            raise MecmError(f"the {label} layout in {folder} has no {exe} and Installers folder")
    if not is_prereqs(prereqs):
        raise MecmError(f"{prereqs} holds no ConfigMgr*.cab: the prerequisite download did not finish")

    w = IsoWriter("MECM_MEDIA")
    counts = {}
    for disc, folder in (("CM", parts.cm), ("ADK", adk), ("WINPE", winpe), ("PREREQS", prereqs)):
        say(f"adding {disc} from {folder}")
        counts[disc] = w.add_tree(folder, disc)
    w.add_file(parts.odbc, f"ODBC/{parts.odbc.name}")
    manifest = {"made": time.strftime("%Y-%m-%d %H:%M"), "license": LICENSE,
                "sources": {"cm": str(parts.cm), "adk": str(parts.adk), "winpe": str(parts.winpe),
                            "odbc": str(parts.odbc), "prereqs": str(parts.prereqs or "setupdl")},
                "files": counts}
    mf = work / MANIFEST
    mf.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    w.add_file(mf, MANIFEST)
    total = w.total_bytes()
    say(f"writing {dest.name}: {total / 1024 ** 3:.1f} GB")
    shown = [-1]

    def tick(done: int, whole: int) -> None:
        pct = int(done * 100 / whole) if whole else 100
        if pct >= shown[0] + 2:
            shown[0] = pct
            say(f"writing {dest.name}: {pct}%")
    w.write(dest, progress=tick)
    problems = check_iso(dest)
    if problems:
        raise MecmError(f"{dest.name} was written but does not read back: {'; '.join(problems)}")
    meta = im._write_installer_meta(MEDIA_ID, name=dest.name, size=dest.stat().st_size,
                                    prepared=manifest["made"], sources=manifest["sources"],
                                    files=counts)
    say(f"Configuration Manager media ready: {dest} ({dest.stat().st_size / 1024 ** 3:.1f} GB)")
    return meta


def check_iso(path: Path) -> list[str]:
    """What a disc lacks for the mecm role; empty when it is complete."""
    from .iso9660 import Iso, IsoError
    try:
        with Iso(path) as iso:
            out = []
            if not iso.exists("CM/" + "/".join(SETUP)):
                out.append("no CM\\SMSSETUP\\BIN\\X64\\setup.exe")
            if not iso.exists(f"ADK/{ADK_EXE}") or not iso.exists("ADK/Installers"):
                out.append("no ADK offline layout")
            if not iso.exists(f"WINPE/{WINPE_EXE}") or not iso.exists("WINPE/Installers"):
                out.append("no Windows PE offline layout")
            if not iso.exists("PREREQS") or not any(_PREREQ.match(e.name) for e in iso.listdir("PREREQS")):
                out.append("no prerequisite downloads")
            if not iso.exists("ODBC") or not any(_ODBC.match(e.name) for e in iso.listdir("ODBC")):
                out.append("no ODBC driver")
            return out
    except (IsoError, OSError) as exc:
        return [f"cannot read it: {exc}"]


def ready() -> bool:
    from . import images as im
    p = im.installer_path(MEDIA_ID)
    return p.exists() and not check_iso(p)


def status(folders: list[Path] | None = None) -> dict:
    from . import images as im, readiness
    p = im.installer_path(MEDIA_ID)
    found = find_parts(readiness.search_dirs() if folders is None else folders)
    return {"ready": p.exists(), "iso": str(p), "size": p.stat().st_size if p.exists() else 0,
            "meta": im.installer_meta(MEDIA_ID), "found": found.as_dict(),
            "missing": missing(found)}


def render_status(st: dict) -> str:
    lines = [f"Configuration Manager media: {'ready' if st['ready'] else 'not prepared'}"
             + (f", {st['iso']} ({st['size'] / 1024 ** 3:.1f} GB)" if st["ready"] else "")]
    labels = {"cm": "media (extracted)", "adk": "Windows ADK", "winpe": "Windows PE add-on",
              "odbc": "ODBC Driver 18", "prereqs": "prerequisite downloads"}
    for k, label in labels.items():
        v = st["found"].get(k) or ""
        lines.append(f"  {label:<24} {v or '-'}")
    if st["missing"]:
        lines.append("still needed:")
        lines += [f"  - {m}" for m in st["missing"]]
    elif not st["ready"]:
        lines.append("everything is here: winlab mecm prepare")
    return "\n".join(lines)
