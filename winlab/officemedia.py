"""Microsoft 365 Apps for enterprise: the disc a lab installs Office from.

A company with no Internet on its desktops (or one that does not want five
hundred PCs each pulling 3 GB from Microsoft) installs Office from a share:
an admin runs the Office Deployment Tool (ODT) once on a machine with
Internet, `setup.exe /download configuration.xml`, which writes the Office
source (Office\\Data\\...) into a folder, copies it to a file server, and the
PCs install and update from there. A lab has no Internet, so winlab does the
admin's first half on the student's own PC and carries the result in on a
disc; the student builds the share, writes the install configuration and
runs setup inside the lab.

Nothing here is downloaded by winlab or shipped with it. The student
downloads the ODT (officedeploymenttool_*.exe) from the Microsoft Download
Center, and, if they like, the Administrative Template files for Microsoft
365 Apps (admintemplates_x64_*.exe). `winlab office prepare` finds them in
Downloads, extracts them and runs `setup.exe /download` with a download
configuration it writes (Windows only: the ODT is a Windows program), or
takes an Office source the student downloaded themselves, and writes the
disc onto the lab's media shelf.

The source is 3 to 4 GB, far over what a stick holds, so it is a disc.

Disc layout (Joliet names):
    ODT\\           setup.exe and Microsoft's sample configuration files
    OFFICE\\Office\\Data\\...   the Office source setup /download wrote
    ADMX\\          the Office administrative templates (when found)
    download.xml   the configuration the source was downloaded with
    winlab-office.json   channel, version, edition, and where it all came from
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import quoteattr

from .mecm import _ci, _run, _walk

DISC = "office"                  # office.iso on the lab's shelf
LABEL = "M365_APPS"
DEFAULT_LAB = "windows11-desktops"
ODT_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=49117"
ADMX_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=49030"
LICENSE = ("Office Deployment Tool, Microsoft 365 Apps for enterprise and its administrative "
           "templates, under Microsoft's own licence terms (Microsoft 365 Apps needs a "
           "subscription licence to activate); downloaded by you, never redistributed by winlab")
MANIFEST = "winlab-office.json"
PRODUCT = "O365ProPlusRetail"    # Microsoft 365 Apps for enterprise
CHANNELS = ("MonthlyEnterprise", "SemiAnnual", "Current", "SemiAnnualPreview")
_ODT = re.compile(r"^officedeploymenttool.*\.exe$", re.IGNORECASE)
_ADMX = re.compile(r"^admintemplates_(x64|x86).*\.exe$", re.IGNORECASE)
_SAMPLE = re.compile(r"^configuration.*\.xml$", re.IGNORECASE)
_CAB = re.compile(r"^v(64|32)(_[\d.]+)?\.cab$", re.IGNORECASE)
_VERSION = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


class OfficeMediaError(Exception):
    pass


@dataclass
class Parts:
    odt: Path | None = None       # officedeploymenttool_*.exe, or the folder it extracted to
    source: Path | None = None    # a folder holding Office\Data (what setup /download wrote)
    admx: Path | None = None      # admintemplates_*.exe, or the folder it extracted to

    def as_dict(self) -> dict:
        return {k: (str(v) if v else "") for k, v in self.__dict__.items()}


# ------------------------------------------------------------------ finding
def is_odt(folder: Path) -> bool:
    """The ODT extracted: setup.exe beside Microsoft's sample configurations."""
    try:
        return bool(_ci(folder, "setup.exe")) and any(
            _SAMPLE.match(c.name) for c in folder.iterdir() if c.is_file())
    except OSError:
        return False


def is_source(folder: Path) -> bool:
    """A folder setup /download filled: Office\\Data\\v64.cab (or v32.cab)."""
    data = _ci(folder, "Office", "Data")
    try:
        return bool(data and data.is_dir() and any(_CAB.match(c.name) for c in data.iterdir()))
    except OSError:
        return False


def is_admx(folder: Path) -> bool:
    f = _ci(folder, "admx", "office16.admx")
    return bool(f and f.is_file())


def source_info(folder: Path) -> dict:
    """The build and edition of an Office source, read from its file names."""
    data = _ci(folder, "Office", "Data")
    out = {"version": "", "edition": ""}
    if not data:
        return out
    try:
        kids = sorted(data.iterdir(), key=lambda c: c.name)
    except OSError:
        return out
    vers = [c.name for c in kids if c.is_dir() and _VERSION.match(c.name)]
    if vers:
        out["version"] = max(vers, key=lambda v: tuple(int(x) for x in v.split(".")))
    eds = {m.group(1) for c in kids if (m := _CAB.match(c.name))}
    out["edition"] = ",".join(sorted(eds, reverse=True))
    return out


def find_parts(folders: list[Path], depth: int = 3) -> Parts:
    p = Parts()
    for root in folders:
        if not root.is_dir():
            continue
        for d in _walk(root, depth):
            if p.source is None and is_source(d):
                p.source = d
            if is_odt(d):
                if p.odt is None or not p.odt.is_dir():
                    p.odt = d
            if is_admx(d):
                if p.admx is None or not p.admx.is_dir():
                    p.admx = d
            try:
                files = sorted(c for c in d.iterdir() if c.is_file())
            except OSError:
                continue
            for f in files:
                if p.odt is None and _ODT.match(f.name):
                    p.odt = f
                if p.admx is None and _ADMX.match(f.name) and "x64" in f.name.lower():
                    p.admx = f
    return p


def missing(p: Parts, on_windows: bool | None = None) -> list[str]:
    win = (os.name == "nt") if on_windows is None else on_windows
    out = []
    if p.odt is None:
        out.append(f"the Office Deployment Tool (officedeploymenttool_*.exe) from {ODT_PAGE}")
    elif not p.odt.is_dir() and not win:
        out.append("the Office Deployment Tool extracted: on a Windows PC run "
                   "officedeploymenttool_*.exe /quiet /extract:<folder> and point winlab at that folder")
    if p.source is None and not win:
        out.append("the Office source: on a Windows PC with Internet, run the ODT's setup.exe "
                   "/download with a download configuration (winlab office xml prints one) "
                   "and point winlab at the folder it filled")
    if p.admx is not None and not p.admx.is_dir() and not win:
        out.append("the administrative templates extracted: on a Windows PC run "
                   "admintemplates_x64_*.exe /quiet /extract:<folder> (or leave them out with --no-admx)")
    return out


# ------------------------------------------------------------- configuration
def download_xml(source_path: str | Path, channel: str = "MonthlyEnterprise", edition: str = "64",
                 language: str = "en-us") -> str:
    """The configuration setup /download reads: which product, channel,
    edition and language to fetch, and where to put it. Only the download:
    the install configuration is the student's to write, in the lab."""
    if channel not in CHANNELS:
        raise OfficeMediaError(f"the channel is one of {', '.join(CHANNELS)}")
    if edition not in ("64", "32"):
        raise OfficeMediaError("the edition is 64 or 32")
    if not re.match(r"^[a-z]{2,3}-[a-z]{2,4}$", language, re.IGNORECASE):
        raise OfficeMediaError(f"{language!r} is not a language tag like en-us")
    return ("<Configuration>\n"
            f"  <Add SourcePath={quoteattr(str(source_path))} OfficeClientEdition=\"{edition}\" "
            f"Channel=\"{channel}\">\n"
            f"    <Product ID=\"{PRODUCT}\">\n"
            f"      <Language ID=\"{language.lower()}\" />\n"
            "    </Product>\n"
            "  </Add>\n"
            "</Configuration>\n")


# ---------------------------------------------------------------- the disc
def disc_path(lab_name: str = DEFAULT_LAB, name: str = DISC) -> Path:
    from .mediashelf import shelf_dir
    return shelf_dir(lab_name, "discs") / f"{name}.iso"


def write_disc(w, dest: Path, say) -> None:
    """Writes an IsoWriter to dest beside a .tmp, with progress in steps."""
    total = w.total_bytes()
    say(f"writing {dest.name}: {total / 1024 ** 3:.1f} GB")
    shown = [-1]

    def tick(done: int, whole: int) -> None:
        pct = int(done * 100 / whole) if whole else 100
        if pct >= shown[0] + 2:
            shown[0] = pct
            say(f"writing {dest.name}: {pct}%")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    w.write(tmp, progress=tick)
    tmp.replace(dest)


def prepare(parts: Parts, lab_name: str = DEFAULT_LAB, channel: str = "MonthlyEnterprise",
            edition: str = "64", language: str = "en-us", dest: Path | None = None, progress=None,
            run=None, on_windows: bool | None = None, work: Path | None = None) -> dict:
    """Extracts and downloads what is still needed (Windows only), then
    writes the disc. Returns the manifest written onto it."""
    import subprocess
    say = progress or (lambda _m: None)
    run = run or subprocess.run
    win = (os.name == "nt") if on_windows is None else on_windows
    gaps = missing(parts, win)
    if gaps:
        raise OfficeMediaError("still needed for the Microsoft 365 Apps disc: " + "; ".join(gaps))
    download_xml("x", channel, edition, language)          # refuses a bad channel before any work
    dest = dest or disc_path(lab_name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    own_work = work is None
    work = work or Path(tempfile.mkdtemp(prefix="winlab-office-", dir=str(dest.parent)))
    work.mkdir(parents=True, exist_ok=True)
    try:
        return _prepare(parts, dest, channel, edition, language, say, run, work)
    finally:
        if own_work:
            shutil.rmtree(work, ignore_errors=True)


def _prepare(parts: Parts, dest: Path, channel: str, edition: str, language: str, say, run,
             work: Path) -> dict:
    from .isowrite import IsoWriteError, IsoWriter
    from .mecm import MecmError

    def step(cmd, what):
        try:
            _run(cmd, what, say, run)
        except MecmError as exc:
            raise OfficeMediaError(str(exc)) from exc

    odt, source, admx = parts.odt, parts.source, parts.admx
    if odt and not odt.is_dir():
        out = work / "ODT"
        step([str(odt), "/quiet", f"/extract:{out}"], "extracting the Office Deployment Tool")
        odt = out
    if not is_odt(odt):
        raise OfficeMediaError(f"{odt} has no setup.exe beside the sample configuration files")
    xml_text = ""
    if source is None:
        source = work / "OFFICE"
        source.mkdir(parents=True, exist_ok=True)
        xml_text = download_xml(source, channel, edition, language)
        xml = work / "download.xml"
        xml.write_text(xml_text, encoding="utf-8")
        step([str(_ci(odt, "setup.exe")), "/download", str(xml)],
             f"downloading Microsoft 365 Apps ({channel}, {edition}-bit, {language}; 3 to 4 GB)")
    if not is_source(source):
        raise OfficeMediaError(f"{source} holds no Office\\Data\\v64.cab: the download did not finish")
    if admx and not admx.is_dir():
        out = work / "ADMX"
        step([str(admx), "/quiet", f"/extract:{out}"], "extracting the Office administrative templates")
        admx = out if is_admx(out) else None
    info = source_info(source)

    w = IsoWriter(LABEL)
    counts = {}
    try:
        n = 0
        for f in sorted(c for c in odt.iterdir() if c.is_file()):
            w.add_file(f, f"ODT/{f.name}")
            n += 1
        counts["ODT"] = n
        say(f"adding the Office source from {source}")
        counts["OFFICE"] = w.add_tree(_ci(source, "Office"), "OFFICE/Office")
        if admx:
            say(f"adding the administrative templates from {admx}")
            counts["ADMX"] = w.add_tree(admx, "ADMX")
        manifest = {"made": time.strftime("%Y-%m-%d %H:%M"), "license": LICENSE,
                    "product": PRODUCT, "channel": channel if xml_text else "",
                    "version": info["version"], "edition": info["edition"],
                    "language": language if xml_text else "",
                    "sources": {k: str(v or "") for k, v in
                                (("odt", parts.odt), ("source", parts.source or "setup /download"),
                                 ("admx", parts.admx))},
                    "files": counts}
        if xml_text:
            (work / "download-disc.xml").write_text(
                download_xml(r"C:\Office", channel, edition, language), encoding="utf-8")
            w.add_file(work / "download-disc.xml", "download.xml")
        mf = work / MANIFEST
        mf.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        w.add_file(mf, MANIFEST)
        write_disc(w, dest, say)
    except (IsoWriteError, OSError) as exc:
        raise OfficeMediaError(f"the disc could not be written: {exc}") from exc
    problems = check_iso(dest)
    if problems:
        raise OfficeMediaError(f"{dest.name} was written but does not read back: {'; '.join(problems)}")
    say(f"Microsoft 365 Apps disc ready: {dest} ({dest.stat().st_size / 1024 ** 3:.1f} GB), "
        f"build {info['version'] or 'unknown'}")
    return manifest


def check_iso(path: Path) -> list[str]:
    from .iso9660 import Iso, IsoError
    try:
        with Iso(path) as iso:
            out = []
            if not iso.exists("ODT/setup.exe"):
                out.append("no ODT\\setup.exe")
            if not iso.exists("OFFICE/Office/Data") or not any(
                    _CAB.match(e.name) for e in iso.listdir("OFFICE/Office/Data")):
                out.append("no Office source (OFFICE\\Office\\Data\\v64.cab)")
            return out
    except (IsoError, OSError) as exc:
        return [f"cannot read it: {exc}"]


def status(lab_name: str = DEFAULT_LAB, folders: list[Path] | None = None) -> dict:
    from . import readiness
    p = disc_path(lab_name)
    found = find_parts(readiness.search_dirs() if folders is None else folders)
    return {"ready": p.exists() and not check_iso(p), "iso": str(p),
            "size": p.stat().st_size if p.exists() else 0, "found": found.as_dict(),
            "missing": missing(found)}


def render_status(st: dict) -> str:
    lines = [f"Microsoft 365 Apps disc: {'ready' if st['ready'] else 'not prepared'}"
             + (f", {st['iso']} ({st['size'] / 1024 ** 3:.1f} GB)" if st["ready"] else "")]
    labels = {"odt": "Office Deployment Tool", "source": "Office source", "admx": "admin templates"}
    for k, label in labels.items():
        lines.append(f"  {label:<24} {st['found'].get(k) or '-'}")
    if st["missing"]:
        lines.append("still needed:")
        lines += [f"  - {m}" for m in st["missing"]]
    elif not st["ready"]:
        lines.append("everything is here: winlab office prepare")
    return "\n".join(lines)
