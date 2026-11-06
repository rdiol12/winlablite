"""The User State Migration Tool (USMT): the disc a lab migrates users with.

USMT (scanstate.exe, loadstate.exe, usmtutils.exe and the MigDocs, MigApp
and MigUser rule files) ships only inside the Windows ADK, as its User State
Migration Tool feature. An admin installs that one feature on a deployment
server and shares its amd64 folder; the PCs run scanstate and loadstate
from the share. A lab has no Internet, so the ADK comes in on a disc.

Nothing here is downloaded by winlab or shipped with it. The student
downloads the ADK installer (adksetup.exe) from Microsoft. `winlab usmt
prepare` then writes one of two discs onto the lab's shelf:

  * when USMT is already installed on this PC (an ADK on a Windows PC puts
    it under Windows Kits\\10\\Assessment and Deployment Kit), or the student
    copied its amd64 folder into Downloads: that folder, about 40 MB, as
    USMT\\amd64 (no setup needed in the lab, a copy is enough);
  * otherwise the ADK's offline layout (adksetup.exe /layout, run on this PC
    on Windows the way `winlab mecm prepare` does, or a layout folder the
    student made), about 1.5 GB, as ADK\\: the student installs only the
    USMT feature on dep01 from it.

Disc layout (Joliet names):
    USMT\\amd64\\   scanstate.exe, loadstate.exe, MigDocs.xml, ... (when found)
    ADK\\          adksetup.exe with its Installers folder (otherwise)
    winlab-usmt.json   what went in, and from where
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .mecm import ADK_EXE, ADK_PAGE, _ci, _run, _walk, is_layout
from .officemedia import DEFAULT_LAB, write_disc

DISC = "usmt"
LABEL = "USMT"
LICENSE = ("The Windows ADK and its User State Migration Tool, under Microsoft's own licence "
           "terms; downloaded by you, never redistributed by winlab")
MANIFEST = "winlab-usmt.json"
TOOLS = ("scanstate.exe", "loadstate.exe", "migdocs.xml")
AMD64 = 0x8664
INSTALLED = ("Windows Kits", "10", "Assessment and Deployment Kit", "User State Migration Tool", "amd64")


class UsmtMediaError(Exception):
    pass


@dataclass
class Parts:
    usmt: Path | None = None     # a USMT amd64 folder
    adk: Path | None = None      # adksetup.exe, or its offline layout folder

    def as_dict(self) -> dict:
        return {k: (str(v) if v else "") for k, v in self.__dict__.items()}


# ------------------------------------------------------------------ finding
def pe_machine(exe: Path) -> int:
    """The machine field of a Windows program's PE header (0x8664 for x64,
    0x14c for x86, 0xaa64 for Arm64); 0 when it is not a PE file."""
    try:
        with open(exe, "rb") as fh:
            head = fh.read(64)
            if len(head) < 64 or head[:2] != b"MZ":
                return 0
            (off,) = struct.unpack_from("<I", head, 0x3C)
            fh.seek(off)
            pe = fh.read(6)
    except OSError:
        return 0
    if len(pe) < 6 or pe[:4] != b"PE\0\0":
        return 0
    return struct.unpack_from("<H", pe, 4)[0]


def is_usmt(folder: Path) -> bool:
    """A USMT folder for 64-bit Windows: the tools and rule files, and
    scanstate.exe built for x64 (the ADK puts x86 and arm64 beside it)."""
    if not all(_ci(folder, t) for t in TOOLS):
        return False
    m = pe_machine(_ci(folder, "scanstate.exe"))
    return m == AMD64 or (m == 0 and folder.name.lower() == "amd64")


def installed_dirs() -> list[Path]:
    """Where an ADK installed on this Windows PC keeps USMT."""
    out = []
    for var in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(var)
        if base:
            p = Path(base).joinpath(*INSTALLED)
            if p not in out:
                out.append(p)
    return out


def find_parts(folders: list[Path], depth: int = 4) -> Parts:
    p = Parts()
    for root in folders:
        if not root.is_dir():
            continue
        for d in _walk(root, depth):
            if p.usmt is None and is_usmt(d):
                p.usmt = d
            if is_layout(d, ADK_EXE):
                p.adk = d
            elif p.adk is None and _ci(d, ADK_EXE):
                p.adk = _ci(d, ADK_EXE)
    return p


def missing(p: Parts, on_windows: bool | None = None) -> list[str]:
    win = (os.name == "nt") if on_windows is None else on_windows
    if p.usmt is not None:
        return []
    if p.adk is None:
        return [f"the Windows ADK installer (adksetup.exe) from {ADK_PAGE}, or a USMT amd64 "
                "folder copied from a PC where the ADK is installed"]
    if not p.adk.is_dir() and not win:
        return ["the ADK's offline layout: run adksetup.exe /layout <folder> on a Windows PC "
                "and point winlab at that folder"]
    return []


# ---------------------------------------------------------------- the disc
def prepare(parts: Parts, lab_name: str = DEFAULT_LAB, dest: Path | None = None, progress=None,
            run=None, on_windows: bool | None = None, work: Path | None = None) -> dict:
    import subprocess
    from .officemedia import disc_path
    say = progress or (lambda _m: None)
    run = run or subprocess.run
    win = (os.name == "nt") if on_windows is None else on_windows
    gaps = missing(parts, win)
    if gaps:
        raise UsmtMediaError("still needed for the USMT disc: " + "; ".join(gaps))
    dest = dest or disc_path(lab_name, DISC)
    dest.parent.mkdir(parents=True, exist_ok=True)
    own_work = work is None
    work = work or Path(tempfile.mkdtemp(prefix="winlab-usmt-", dir=str(dest.parent)))
    work.mkdir(parents=True, exist_ok=True)
    try:
        return _prepare(parts, dest, say, run, work)
    finally:
        if own_work:
            shutil.rmtree(work, ignore_errors=True)


def _prepare(parts: Parts, dest: Path, say, run, work: Path) -> dict:
    from .isowrite import IsoWriteError, IsoWriter
    from .mecm import MecmError

    w = IsoWriter(LABEL)
    counts = {}
    try:
        if parts.usmt is not None:
            say(f"adding USMT from {parts.usmt}")
            counts["USMT"] = w.add_tree(parts.usmt, "USMT/amd64")
        else:
            adk = parts.adk
            if not adk.is_dir():
                out = work / "ADK"
                try:
                    _run([str(adk), "/quiet", "/layout", str(out)],
                         "downloading the ADK's offline layout (about 1.5 GB)", say, run)
                except MecmError as exc:
                    raise UsmtMediaError(str(exc)) from exc
                adk = out
            if not is_layout(adk, ADK_EXE):
                raise UsmtMediaError(f"the ADK layout in {adk} has no {ADK_EXE} and Installers folder")
            say(f"adding the ADK layout from {adk}")
            counts["ADK"] = w.add_tree(adk, "ADK")
        manifest = {"made": time.strftime("%Y-%m-%d %H:%M"), "license": LICENSE,
                    "sources": {"usmt": str(parts.usmt or ""), "adk": str(parts.adk or "")},
                    "files": counts}
        mf = work / MANIFEST
        mf.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        w.add_file(mf, MANIFEST)
        write_disc(w, dest, say)
    except (IsoWriteError, OSError) as exc:
        raise UsmtMediaError(f"the disc could not be written: {exc}") from exc
    problems = check_iso(dest)
    if problems:
        raise UsmtMediaError(f"{dest.name} was written but does not read back: {'; '.join(problems)}")
    say(f"USMT disc ready: {dest} ({dest.stat().st_size / 1024 ** 2:.0f} MB)")
    return manifest


def check_iso(path: Path) -> list[str]:
    from .iso9660 import Iso, IsoError
    try:
        with Iso(path) as iso:
            if iso.exists("USMT/amd64/scanstate.exe") and iso.exists("USMT/amd64/loadstate.exe"):
                return []
            if iso.exists(f"ADK/{ADK_EXE}") and iso.exists("ADK/Installers"):
                return []
            return ["neither USMT\\amd64\\scanstate.exe nor an ADK offline layout"]
    except (IsoError, OSError) as exc:
        return [f"cannot read it: {exc}"]


def status(lab_name: str = DEFAULT_LAB, folders: list[Path] | None = None) -> dict:
    from . import readiness
    from .officemedia import disc_path
    p = disc_path(lab_name, DISC)
    found = find_parts(readiness.search_dirs() + installed_dirs() if folders is None else folders)
    return {"ready": p.exists() and not check_iso(p), "iso": str(p),
            "size": p.stat().st_size if p.exists() else 0, "found": found.as_dict(),
            "missing": missing(found)}


def render_status(st: dict) -> str:
    lines = [f"USMT disc: {'ready' if st['ready'] else 'not prepared'}"
             + (f", {st['iso']} ({st['size'] / 1024 ** 2:.0f} MB)" if st["ready"] else "")]
    labels = {"usmt": "USMT amd64 folder", "adk": "Windows ADK"}
    for k, label in labels.items():
        lines.append(f"  {label:<24} {st['found'].get(k) or '-'}")
    if st["missing"]:
        lines.append("still needed:")
        lines += [f"  - {m}" for m in st["missing"]]
    elif not st["ready"]:
        lines.append("everything is here: winlab usmt prepare")
    return "\n".join(lines)
