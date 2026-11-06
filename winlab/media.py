"""Removable media for a machine, the way a PC has them: a DVD drive you
put a disc in and eject, and a USB port you plug a stick into, while the
machine runs.

A stick is a FAT16 image winlab writes on the host from files it has (the
driver stick: Red Hat's virtio-win drivers and installer for the machine's
Windows, plus any vendor packages the user drops in images/drivers) or from
any folder the user names, so files get into an isolated machine the way an
admin carries them to a server: on a stick. The disc is any ISO in the image
store. Both go in and out through QMP on a running machine (Windows plays
the chime and shows the drive) and are remembered for the next start.
Nothing here opens a path from the machine back to the host: the stick is a
copy, the disc is read-only, and the machine's network stays as it was.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import fatfs, paths, state
from .qmp import Qmp, QmpError

STICK_FILE = "stick.img"
STICK_ID = "wlstick"          # the block node and the USB device, both
DVD_ID = "cdattach"           # the drive the provider always gives a Windows machine
STICK_LABEL_DRIVERS = "DRIVERS"
STICK_LABEL_FILES = "WINLAB"
MIN_MB = 16
MAX_MB = 2048
DRIVERS_DIR = "drivers"       # images/drivers: the user's own vendor packages
README = """This stick was written by winlab on your PC.

Drivers for this machine's virtual hardware, as Red Hat publishes them
(virtio-win, signed): one folder per device, one subfolder per Windows
version, amd64 inside. Install one with Device Manager (Update driver,
Browse my computer, point at this stick, Include subfolders), with
pnputil /add-driver <drive>:\\*.inf /subdirs /install, or run
virtio-win-guest-tools.exe, Red Hat's own installer, like any vendor's.

Anything under your images\\drivers folder on the host PC is copied here
too, under its own folder name, so your Intel, NVIDIA or Realtek packages
arrive the same way. winlab never downloads those for you.
"""


class MediaError(Exception):
    pass


# ------------------------------------------------------------------ images
def stick_path(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id / STICK_FILE


def drivers_dir() -> Path:
    return paths.images_dir() / DRIVERS_DIR


def user_packages() -> dict[str, bytes]:
    """The vendor packages the user keeps in images/drivers, each folder or
    file under its own name."""
    out: dict[str, bytes] = {}
    root = drivers_dir()
    if not root.exists():
        return out
    for f in sorted(root.rglob("*")):
        if f.is_file():
            out[f.relative_to(root).as_posix()] = f.read_bytes()
    return out


def driver_files(image_id: str) -> dict[str, bytes]:
    """The driver stick's contents for a machine on this Windows image."""
    from . import virtio
    files = virtio.stick_tree(image_id)
    for name, data in user_packages().items():
        files.setdefault(name, data)
    files["README.txt"] = README.encode("utf-8")
    return files


def size_for(files: dict[str, bytes]) -> int:
    """A stick size in MB with room for the directories: a fifth over the
    content plus a little, 16 MB at least, FAT16's 2 GB at most."""
    total = sum(len(v) for v in files.values()) + 64 * 1024 * len(files)
    mb = (total * 6 // 5) // (1024 * 1024) + 8
    mb = max(MIN_MB, ((mb + 15) // 16) * 16)
    if mb > MAX_MB:
        raise MediaError(f"the files take {total >> 20} MB; a stick holds at most {MAX_MB} MB")
    return mb


def write_stick(files: dict[str, bytes], dest: Path, label: str = STICK_LABEL_FILES) -> Path:
    if not files:
        raise MediaError("nothing to put on the stick")
    img = fatfs.disk(size_for(files), label[:11])
    for name, data in files.items():
        img.add_file(name, data)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".img.tmp")
    img.write(tmp)
    tmp.replace(dest)
    return dest


def folder_files(folder: str | Path) -> dict[str, bytes]:
    root = Path(folder).expanduser()
    if root.is_file():
        return {root.name: root.read_bytes()}
    if not root.is_dir():
        raise MediaError(f"no such folder: {root}")
    out = {f.relative_to(root).as_posix(): f.read_bytes() for f in sorted(root.rglob("*")) if f.is_file()}
    if not out:
        raise MediaError(f"{root} holds no files")
    return out


# ----------------------------------------------------------------- running
def _qmp_port(lab_name: str, node_id: str) -> int:
    """The running machine's monitor port, 0 when it is not running."""
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not state.pid_alive(ns.pid):
        return 0
    return ns.qmp_port


def plug(lab_name: str, node_id: str, files: dict[str, bytes], label: str = STICK_LABEL_FILES,
         qmp=Qmp) -> dict:
    """Writes the stick and plugs it into the machine: now, through QMP,
    when it runs (a stick already in the port comes out first); otherwise
    the provider adds it at the next start."""
    if not files:
        raise MediaError("nothing to put on the stick")
    size_for(files)  # too big: refused before the stick in the port comes out
    dest = stick_path(lab_name, node_id)
    port = _qmp_port(lab_name, node_id)
    if port:
        _unplug_live(port, qmp)
    write_stick(files, dest, label)
    live = _plug_live(port, node_id, dest, qmp)
    _shelf_port(lab_name, node_id, {"title": STICK_TITLES.get(label, "Files stick")})
    return {"path": str(dest), "size_mb": dest.stat().st_size >> 20, "files": len(files),
            "live": live}


BLANK_GB = (8, 16, 32, 64)


def plug_blank(lab_name: str, node_id: str, gb: int, qmp=Qmp) -> dict:
    """A new, empty stick straight from its packet: no partition and no file
    system, so Windows asks to format it (Disk Management, diskpart, then
    BitLocker To Go or a recovery drive). Sparse: it takes no room on this
    PC until the machine writes to it."""
    if gb not in BLANK_GB:
        raise MediaError(f"a blank stick is {', '.join(str(g) for g in BLANK_GB)} GB")
    dest = stick_path(lab_name, node_id)
    port = _qmp_port(lab_name, node_id)
    if port:
        _unplug_live(port, qmp)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as fh:
        fh.truncate(gb * 1024**3)
    live = _plug_live(port, node_id, dest, qmp)
    _shelf_port(lab_name, node_id, {"title": f"{gb} GB stick", "blank": True})
    return {"path": str(dest), "size_mb": gb * 1024, "files": 0, "live": live}


def _plug_live(port: int, node_id: str, dest: Path, qmp=Qmp) -> bool:
    if not port:
        return False
    try:
        with qmp(port) as mon:
            mon.call("blockdev-add", driver="raw", **{"node-name": STICK_ID},
                     file={"driver": "file", "filename": str(dest)})
            mon.call("device_add", driver="usb-storage", id=STICK_ID, drive=STICK_ID,
                     bus="xhci.0", removable=True)
    except (QmpError, OSError) as exc:
        raise MediaError(f"{node_id}: could not plug the stick in: {exc}") from exc
    return True


def _unplug_live(port: int, qmp=Qmp) -> bool:
    try:
        with qmp(port) as mon:
            try:
                mon.call("device_del", id=STICK_ID)
            except QmpError as exc:
                if "not found" not in str(exc).lower():
                    raise
                return False
            # The USB device goes at once; the block node right after.
            for _ in range(20):
                try:
                    mon.call("blockdev-del", **{"node-name": STICK_ID})
                    break
                except QmpError:
                    time.sleep(0.25)
        return True
    except (QmpError, OSError) as exc:
        raise MediaError(f"could not unplug the stick: {exc}") from exc


def unplug(lab_name: str, node_id: str, qmp=Qmp) -> bool:
    """Takes the stick out (live when the machine runs) and forgets it."""
    port = _qmp_port(lab_name, node_id)
    was = False
    if port:
        was = _unplug_live(port, qmp)
    p = stick_path(lab_name, node_id)
    if p.exists():
        p.unlink()
        was = True
    _shelf_port(lab_name, node_id, None)
    return was


STICK_TITLES = {STICK_LABEL_DRIVERS: "Driver stick", "WLPACK": "Package stick"}


def _shelf_port(lab_name: str, node_id: str, meta: dict | None) -> None:
    """The media shelf's record of port 1 (mediashelf.py) follows this
    module's stick."""
    from . import mediashelf
    mediashelf.note_port(lab_name, node_id, 0, meta)


def insert(lab_name: str, node_id: str, iso: Path, qmp=Qmp) -> bool:
    """Puts a disc in the running machine's DVD drive. Returns False when
    the machine is not running (the lab definition's `iso` setting covers
    the next start)."""
    port = _qmp_port(lab_name, node_id)
    if not port:
        return False
    try:
        with qmp(port) as mon:
            mon.call("blockdev-change-medium", id=DVD_ID, filename=str(iso), format="raw",
                     **{"read-only-mode": "read-only"})
    except (QmpError, OSError) as exc:
        raise MediaError(f"{node_id}: could not insert the disc: {exc}") from exc
    from . import mediashelf
    mediashelf.note_drive0(lab_name, node_id, iso)
    return True


def eject(lab_name: str, node_id: str, qmp=Qmp) -> bool:
    port = _qmp_port(lab_name, node_id)
    if not port:
        return False
    try:
        with qmp(port) as mon:
            mon.call("eject", id=DVD_ID, force=True)
    except (QmpError, OSError) as exc:
        raise MediaError(f"{node_id}: could not eject: {exc}") from exc
    from . import mediashelf
    mediashelf.note_drive0(lab_name, node_id, None)
    return True


def status(lab_name: str, node_id: str) -> dict:
    p = stick_path(lab_name, node_id)
    return {"stick": p.exists(), "stick_mb": (p.stat().st_size >> 20) if p.exists() else 0,
            "packages": sorted({k.split("/", 1)[0] for k in user_packages()})}
