"""A network as one file: save it, open it on another PC, go back to an
earlier version.

A network file (``.wlnet``) holds the design, not the machines: every
machine with its hardware and cabling, the switches with their VLANs and
trunks, the router's interfaces and DHCP pools, the device settings typed on
their consoles, and where everything sits on the canvas. It is small (a few
kilobytes), so it goes by mail or on a stick like any document. Opened on
another PC, the machines are built fresh there from that PC's own Windows
media; their disks never travel in it (a whole lab with its disks is
``winlab lab export``).

Inside it is a zip of ``network.toml`` (the lab definition winlab itself
writes) and ``manifest.json``. The lab's Administrator password is left out:
each PC makes its own.

Save points are network files kept beside the lab (``var/netsaves/<lab>``):
take one before trying something, and restore it to put the design back.
"""

from __future__ import annotations

import copy
import io
import json
import re
import time
import tomllib
import zipfile
from pathlib import Path

from . import __version__, editor, paths, schema
from .model import Lab
from .schema import LabError

EXT = ".wlnet"
FORMAT = 1
NETWORK = "network.toml"
MANIFEST = "manifest.json"
MAX_BYTES = 4 * 1024 * 1024
LAB_NAME = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
# A save point's id is when it was made; a second one in the same second
# gets -2, -3... (20261029-101500-2) rather than wait for the clock.
POINT_ID = re.compile(r"^\d{8}-\d{6}(?:-[1-9]\d{0,3})?$")


class NetFileError(Exception):
    pass


def dumps(lab: Lab, note: str = "") -> bytes:
    """The network file's bytes for ``lab``."""
    design = copy.deepcopy(lab)
    design.password_in_toml = False
    design.admin_password = ""
    text = editor.emit(design)
    manifest = {
        "format": FORMAT, "kind": "winlab-network", "lab": lab.name,
        "description": lab.description, "winlab": __version__,
        "saved": time.strftime("%Y-%m-%dT%H:%M:%S"), "note": note,
        "machines": len(lab.nodes), "switches": len(lab.networks),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(MANIFEST, json.dumps(manifest, indent=1) + "\n")
        z.writestr(NETWORK, text)
    return buf.getvalue()


def read(data: bytes) -> tuple[dict, dict]:
    """(manifest, the parsed network.toml) of a network file, checked."""
    if len(data) > MAX_BYTES:
        raise NetFileError("that is not a network file: it is far too big")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            manifest = json.loads(z.read(MANIFEST).decode("utf-8"))
            if z.getinfo(NETWORK).file_size > MAX_BYTES:
                raise NetFileError("that network file is damaged")
            raw = tomllib.loads(z.read(NETWORK).decode("utf-8"))
    except (zipfile.BadZipFile, KeyError, ValueError, UnicodeDecodeError) as exc:
        raise NetFileError(f"that is not a winlab network file ({exc})") from None
    if manifest.get("kind") != "winlab-network":
        raise NetFileError("that is not a winlab network file")
    if int(manifest.get("format", 0)) > FORMAT:
        raise NetFileError(f"this network was saved by a newer winlab ({manifest.get('winlab')}); "
                           "update winlab to open it")
    raw.get("lab", {}).pop("admin_password", None)
    return manifest, raw


def _taken(name: str) -> bool:
    """A lab of that name exists: a plain file, or a pack entry (locked or not)."""
    from . import content
    p = paths.LABS / f"{name}.toml"
    return p.exists() or content.exists(p) or content.locked(p)


def _free_name(want: str) -> str:
    want = re.sub(r"[^a-z0-9-]+", "-", want.lower()).strip("-") or "network"
    if not want[0].isalpha():
        want = "net-" + want
    want = want[:28]
    name, n = want, 2
    # A name whose old machines' disks are still here is skipped too: the
    # new network's machines would boot from them.
    while _taken(name) or any(paths.lab_dir(name).glob("*/*.qcow2")):
        name, n = f"{want}-{n}", n + 1
    return name


def _write(raw: dict, dest: Path, name: str, keep: Lab | None = None) -> Lab:
    """Build, validate and write the lab definition ``raw`` as ``name``.
    ``keep``: the lab being restored, whose own password setting stays."""
    raw.setdefault("lab", {})["name"] = name
    try:
        lab = schema._build(raw, dest)
        lab.password_in_toml = bool(keep and keep.password_in_toml)
        lab.admin_password = keep.admin_password if lab.password_in_toml else ""
        text = editor.emit(lab)
    except (LabError, KeyError, TypeError, ValueError) as exc:
        raise NetFileError(f"the network in that file does not load: {exc}") from None
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".toml.tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        lab = schema.load(tmp)
    except LabError as exc:
        tmp.unlink(missing_ok=True)
        raise NetFileError(f"the network in that file does not load: {exc}") from None
    tmp.replace(dest)
    lab.source_path = dest
    return lab


def open_bytes(data: bytes, name: str = "") -> Lab:
    """A network file brought in as a new lab (its own name, or the next free
    one: my-office-2). Its machines have no disks yet."""
    manifest, raw = read(data)
    if name:
        name = name.strip().lower()
        if not LAB_NAME.match(name):
            raise NetFileError("a network's name is 2-32 lower-case letters, digits and dashes")
        if _taken(name):
            raise NetFileError(f"there is already a lab called {name}")
        if any(paths.lab_dir(name).glob("*/*.qcow2")):
            raise NetFileError(f"{paths.lab_dir(name)} still holds the disks of machines of a lab once "
                               f"called {name}; delete that folder or choose another name")
    else:
        name = _free_name(str(raw.get("lab", {}).get("name") or manifest.get("lab") or "network"))
    return _write(raw, paths.LABS / f"{name}.toml", name)


def save(lab: Lab, dest: str | Path) -> Path:
    """Write the network file; ``dest`` is a file or a folder to put it in."""
    dest = Path(dest).expanduser()
    if dest.is_dir() or not dest.suffix:
        dest = dest / f"{lab.name}{EXT}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(dumps(lab))
    return dest


# ---------------------------------------------------------------- save points
def points_dir(lab_name: str) -> Path:
    return paths.VAR / "netsaves" / lab_name


def savepoint(lab: Lab, note: str = "") -> dict:
    d = points_dir(lab.name)
    d.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    # two in one second: the next number after the newest of that second
    # (not a gap a deleted one left, which would sort before it)
    n = max((_point_order(f)[1] for f in d.glob(f"{stamp}*{EXT}") if POINT_ID.match(f.stem)), default=0)
    pid = f"{stamp}-{n + 1}" if n else stamp
    (d / f"{pid}{EXT}").write_bytes(dumps(lab, note.strip()[:120]))
    return {"id": pid, "note": note.strip()[:120]}


def _point_order(f: Path) -> tuple[str, int]:
    """Oldest to newest: by time, then the -2, -3 of the same second."""
    n = f.stem[16:]
    return f.stem[:15], int(n) if n.isdigit() else 1


def savepoints(lab_name: str) -> list[dict]:
    out = []
    for f in sorted(points_dir(lab_name).glob(f"*{EXT}"), key=_point_order, reverse=True):
        try:
            manifest, _ = read(f.read_bytes())
        except (OSError, NetFileError):
            continue
        out.append({"id": f.stem, "saved": manifest.get("saved", ""), "note": manifest.get("note", ""),
                    "machines": manifest.get("machines", 0), "switches": manifest.get("switches", 0)})
    return out


def restore(lab: Lab, point_id: str, running: bool = False) -> Lab:
    """Put the design back as it was at save point ``point_id``. The current
    design becomes a save point first, so a restore can itself be undone.
    Machines' disks stay as they are; a machine the save point does not
    have keeps its disks for when it comes back."""
    if running:
        raise NetFileError(f"turn {lab.name} off before you restore an earlier version")
    if not POINT_ID.match(point_id):
        raise NetFileError("no such save point")
    f = points_dir(lab.name) / f"{point_id}{EXT}"
    if not f.exists():
        raise NetFileError("no such save point")
    _, raw = read(f.read_bytes())
    savepoint(lab, f"before restoring {point_id}")
    return _write(raw, Path(lab.source_path), lab.name, keep=lab)


def delete_point(lab_name: str, point_id: str) -> None:
    if not POINT_ID.match(point_id):
        raise NetFileError("no such save point")
    (points_dir(lab_name) / f"{point_id}{EXT}").unlink(missing_ok=True)
