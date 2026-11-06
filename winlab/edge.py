"""Microsoft Edge for Business, carried into an isolated lab.

The windows11-desktops lessons manage Edge the way a company's desktop team
does: the Edge policy templates (msedge.admx, msedgeupdate.admx and their
.adml language files) go into the domain's Group Policy central store, the
Edge MSI is deployed from a share on dep01, and the policies (homepage,
startup pages, IE mode with an Enterprise Mode site list, the update pin)
come from GPOs the student writes.

A lab has no Internet, so the student downloads both files from Microsoft's
Edge for Business page (https://www.microsoft.com/edge/business/download) on
their own PC: the Windows 64-bit MSI (MicrosoftEdgeEnterpriseX64.msi) and
"Get policy files" (MicrosoftEdgePolicyTemplates.zip, or the older .cab that
wraps the same zip). `winlab edge status` says whether winlab can find them
(winlab's edge folder beside the images, the image downloads folder, the
user's Downloads, Desktop and Documents) and `winlab edge stick <lab>` writes
them, unchanged, onto an EDGE stick on the lab's media shelf. Unpacking the
templates, copying them into SYSVOL and deploying the MSI is the student's
work inside the machines.

winlab never downloads, ships or passes on either file: they are Microsoft's,
under Microsoft's licence terms for Edge, downloaded by the user.

One graded fault registers with guestfaults: the central store's msedge.adml
gone, so the Group Policy editor cannot show the Edge settings.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import paths

PAGE = "https://www.microsoft.com/edge/business/download"
LICENSE = ("Microsoft Edge and its policy templates, under Microsoft's licence terms for Edge; downloaded by "
           "you onto this PC from Microsoft, never shipped or passed on by winlab")
FOLDER = "edge"
STICK_LABEL = "EDGE"
README = "README.TXT"
STABLE_APP_ID = "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"   # Edge Update's id for the Stable channel
_MSI = re.compile(r"(?i)^MicrosoftEdgeEnterprise(X64|X86|ARM64)(\s*\(\d+\))?\.msi$")
_TEMPLATES = re.compile(r"(?i)^MicrosoftEdgePolicyTemplates(\s*\(\d+\))?\.(zip|cab)$")
_ARCH_ORDER = {"x64": 0, "arm64": 1, "x86": 2}


class EdgeError(Exception):
    pass


def edge_dir() -> Path:
    """winlab's own Edge folder, beside the Windows images."""
    return paths.images_dir() / FOLDER


def search_dirs() -> list[Path]:
    from . import readiness
    out: list[Path] = []
    for p in [edge_dir(), paths.downloads_dir(), *readiness.search_dirs()]:
        if p.is_dir() and all(p.resolve() != q.resolve() for q in out):
            out.append(p)
    return out


def find(dirs: list[Path] | None = None) -> dict:
    """The newest Edge MSI (x64 first) and policy templates found, or None
    for each; a file name the browser numbered on a second download counts."""
    msis: list[tuple[int, float, Path]] = []
    tpls: list[tuple[float, Path]] = []
    for d in search_dirs() if dirs is None else dirs:
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for f in entries:
            if not f.is_file():
                continue
            m = _MSI.match(f.name)
            if m:
                msis.append((_ARCH_ORDER.get(m.group(1).lower(), 9), -f.stat().st_mtime, f))
            elif _TEMPLATES.match(f.name):
                tpls.append((-f.stat().st_mtime, f))
    msi = sorted(msis)[0][2] if msis else None
    tpl = sorted(tpls)[0][1] if tpls else None
    return {"msi": msi, "templates": tpl}


def arch(msi: Path) -> str:
    m = _MSI.match(msi.name)
    return m.group(1).lower() if m else ""


def missing(found: dict) -> list[str]:
    out = []
    if not found.get("msi"):
        out.append(f"the Edge MSI: on {PAGE} choose the Stable channel, the latest build, Windows 64-bit, "
                   "and download (MicrosoftEdgeEnterpriseX64.msi)")
    if not found.get("templates"):
        out.append(f"the policy templates: on {PAGE}, 'Get policy files' (MicrosoftEdgePolicyTemplates.zip)")
    return out


def readme(found: dict) -> str:
    lines = ["Microsoft Edge for Business, as Microsoft publishes it", ""]
    if found.get("msi"):
        lines += [f"Edge\\{found['msi'].name}", "  the Edge installer for a whole computer; deploy it from a share "
                  "(\\\\dep01\\Software\\Edge) by Group Policy or a script", ""]
    if found.get("templates"):
        lines += [f"Edge\\{found['templates'].name}",
                  "  the policy templates: windows\\admx\\msedge.admx, msedgeupdate.admx and the language folders "
                  "(en-US\\msedge.adml ...) go into the central store,",
                  "  \\\\corp.lab\\SYSVOL\\corp.lab\\Policies\\PolicyDefinitions. A .cab holds the zip: expand it first.",
                  ""]
    lines += [f"Downloaded by you from {PAGE}.", "winlab copied these files unchanged; it never ships them.", ""]
    return "\r\n".join(lines)


def stick_files(found: dict) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for key in ("msi", "templates"):
        if found.get(key):
            p = Path(found[key])
            name = re.sub(r"\s*\(\d+\)(?=\.\w+$)", "", p.name)   # MicrosoftEdgeEnterpriseX64 (1).msi -> ...X64.msi
            files[f"Edge/{name}"] = p.read_bytes()
    return files


def to_stick(lab_name: str, found: dict | None = None) -> dict:
    """Both files written onto a new EDGE stick on the lab's media shelf."""
    from . import media, mediashelf
    found = find() if found is None else found
    need = missing(found)
    if need:
        raise EdgeError("download from Microsoft first:\n  " + "\n  ".join(need))
    files = stick_files(found)
    files[README] = readme(found).encode("utf-8")
    title = "Microsoft Edge for Business"
    sid = mediashelf._new_id(lab_name, "edge")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise EdgeError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files) - 1,
            "mb": sum(len(v) for v in files.values()) >> 20}


def render_status(found: dict | None = None) -> str:
    found = find() if found is None else found
    out = []
    for key, what in (("msi", "Edge MSI"), ("templates", "policy templates")):
        p = found.get(key)
        out.append(f"{what:<18}" + (f"{p}  ({p.stat().st_size >> 20} MB)" if p else "not found"))
    need = missing(found)
    if need:
        out += ["", f"Download from Microsoft on this PC (winlab looks in {edge_dir()}, the image downloads "
                "folder, and your Downloads, Desktop and Documents):"]
        out += [f"  {n}" for n in need]
    else:
        out += ["", "ready: winlab edge stick <lab> writes both onto an EDGE stick on the lab's media shelf"]
    out += ["", LICENSE]
    return "\n".join(out)


# -------------------------------------------------------------- the CLI
def add_cli(sub) -> None:
    ed = sub.add_parser("edge", help="Microsoft Edge for Business (the MSI and the policy templates) you "
                                     "downloaded from Microsoft, written onto a stick for a lab")
    es = ed.add_subparsers(dest="edgecmd", metavar="<op>")
    es.add_parser("status", help="whether winlab finds the Edge MSI and MicrosoftEdgePolicyTemplates on this PC")
    st = es.add_parser("stick", help="write both onto a new EDGE stick on the lab's media shelf")
    st.add_argument("lab")


def run_cli(args) -> int:
    import sys
    try:
        if (args.edgecmd or "status") == "status":
            print(render_status())
            return 0
        from . import schema
        lab = schema.load(args.lab)
        r = to_stick(lab.name)
        print(f"{r['title']}: {r['files']} file(s), {r['mb']} MB, on {lab.name}'s media shelf as {r['id']} "
              f"(winlab media {lab.name} <machine> plug {r['id']})")
        return 0
    except (EdgeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - schema.LabError and friends
        print(f"error: {exc}", file=sys.stderr)
        return 1


# ------------------------------------------------------------- the fault
_STORE = "C:\\Windows\\SYSVOL\\domain\\Policies\\PolicyDefinitions"
_PARKED = "C:\\Windows\\Temp\\winlab-msedge.adml"


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [
        GuestFault(
            id="edge-adml-missing",
            roles=("ad-ds",),
            title="The Group Policy editor cannot show the Edge settings",
            os=WINDOWS,
            teaches="how the central store pairs each .admx with a language file (.adml) in a folder named for "
                    "the editor's language, reading the editor's error to the file it names, and replacing "
                    "templates as a matching pair from one release",
            symptom="editing any GPO, the Group Policy Management Editor says 'Resource $(string.<name>) "
                    "referenced in attribute displayName could not be found. File "
                    "\\\\{domain}\\SysVol\\{domain}\\Policies\\PolicyDefinitions\\msedge.admx'; the Microsoft Edge "
                    "folder is missing under Administrative Templates; the PCs' Edge policies still apply",
            apply=("$s = '" + _STORE + "'; $f = Join-Path $s 'en-US\\msedge.adml'; "
                   "if (Test-Path $f) { Move-Item -Path $f -Destination '" + _PARKED + "' -Force }"),
            clear=("$s = '" + _STORE + "'; if (Test-Path '" + _PARKED + "') { "
                   "Move-Item -Path '" + _PARKED + "' -Destination (Join-Path $s 'en-US\\msedge.adml') -Force }"),
            hints=(
                "Read the error to the end: it names a file and a string. The .admx defines the settings, but "
                "every name and explanation the editor shows comes from a matching .adml in a language folder "
                "beside it. Look in \\\\{domain}\\SYSVOL\\{domain}\\Policies\\PolicyDefinitions and its en-US folder.",
                "Get-ChildItem the central store for msedge.* and the en-US folder for msedge.*: the .admx is "
                "there and its en-US\\msedge.adml is not. The PCs are fine because a GPO stores registry values, "
                "not templates: the templates only feed the editor.",
                "Put the language file back from the same release as the .admx: expand MicrosoftEdgePolicyTemplates "
                "again (the copy on the EDGE stick) and copy windows\\admx\\en-US\\msedge.adml into the central "
                "store's en-US folder. Close and reopen the editor. Copying an .adml from another release can fail "
                "the other way, with strings the .admx does not know.",
            ),
            verify=("$s = '" + _STORE + "'; "
                    "[bool]((Test-Path (Join-Path $s 'msedge.admx')) -and (Test-Path (Join-Path $s 'en-US\\msedge.adml')))"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
