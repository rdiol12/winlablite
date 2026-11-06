"""The media shelf: a lab's discs and USB sticks as things you pick up.

The shelf holds every disc this PC has for the lab (the Windows DVDs and the
SQL Server or Configuration Manager media in the image store, the ISOs the
user added, driver and tool ISOs in the downloads folder, and the discs
winlab burned for this lab) and the lab's USB sticks (blank, or written
from a folder). A disc goes into a machine's DVD drive and comes out with
Eject, from the desktop, from the machine's screen window or from inside
Windows (its own Eject is noticed and the disc is back on the shelf). A
stick goes into one of the machine's USB ports and, pulled out, goes back
on the shelf with whatever the machine wrote on it, the way a real stick
keeps its files. Both work while the machine runs (QMP), and what is in each
drive and port stays there across a shutdown, as on a PC.

What is where lives in the machine's folder (media.json), beside its disks
and its firmware's settings; a stick is one image file that moves between
the shelf folder (var/labs/<lab>/media/sticks) and the machine's port.
The machine's boot order is kept there too: with the DVD drive first, a
disc in the drive at power-on boots (Windows media says "Press any key to
boot from CD or DVD" and, if no key is pressed, the PC boots its disk).
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

from . import images, paths, state
from .model import LINUX
from .qmp import Qmp, QmpError

MEDIA_FILE = "media.json"
SHELF = "media"               # the lab folder's shelf: sticks/ and discs/
MAX_DRIVES = 2
PORTS = 4
AHCI_PORTS = 6                # what the ICH9 SATA controller has
SYNC_EVERY = 3.0
BOOT_DISK, BOOT_DVD = "disk", "dvd"
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


class ShelfError(Exception):
    pass


# ----------------------------------------------------------------- names
def drive_id(i: int) -> str:
    """The QEMU id of DVD drive i: drive 0 is the one every Windows machine
    always has (media.DVD_ID)."""
    return "cdattach" if i == 0 else f"cdattach{i}"


def port_id(i: int) -> str:
    return "wlstick" if i == 0 else f"wlstick{i}"


def port_file(node_dir: Path, i: int) -> Path:
    """The image of the stick in USB port i (port 0 is media.py's stick)."""
    return node_dir / ("stick.img" if i == 0 else f"stick{i}.img")


def _node_dir(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id


def shelf_dir(lab_name: str, what: str) -> Path:
    return paths.lab_dir(lab_name) / SHELF / what


def drives(node) -> int:
    """DVD drives in the machine: a Windows PC has one (a second one is a
    part fitted in the case); a Linux machine none unless its definition
    keeps a disc in one."""
    if node.kind == LINUX:
        return 1 if node.vars.get("iso") else 0
    try:
        n = int(node.vars.get("dvd_drives") or 1)
    except (TypeError, ValueError):
        n = 1
    return max(1, min(MAX_DRIVES, n))


def ports(node) -> int:
    from .appliance import device_of
    return 0 if device_of(node) else PORTS


# ---------------------------------------------------------------- records
def _load(node_dir: Path) -> dict:
    try:
        data = json.loads((node_dir / MEDIA_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(node_dir: Path, data: dict) -> None:
    node_dir.mkdir(parents=True, exist_ok=True)
    tmp = node_dir / (MEDIA_FILE + ".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(node_dir / MEDIA_FILE)


def _def_iso(node) -> str:
    iso = str(node.vars.get("iso") or "")
    return "" if iso in ("none", node.image) else iso


def drive_ref(node_dir: Path, node, i: int) -> str:
    """The disc in drive i, as a reference ('' for an empty drive). Drive 0
    follows the lab definition's `iso` until the disc is changed by hand;
    a new `iso` in the definition wins again."""
    rec = (_load(node_dir).get("dvd") or {}).get(str(i))
    if i == 0 and (not isinstance(rec, dict) or rec.get("def", "") != _def_iso(node)):
        return f"image:{_def_iso(node)}" if _def_iso(node) else ""
    return str((rec or {}).get("disc") or "")


def _set_drive(node_dir: Path, node, i: int, ref: str) -> None:
    data = _load(node_dir)
    entry = {"disc": ref}
    if i == 0:
        entry["def"] = _def_iso(node)
    data.setdefault("dvd", {})[str(i)] = entry
    _save(node_dir, data)


def note_drive0(lab_name: str, node_id: str, path: Path | None) -> None:
    """media.insert / eject on drive 0 record what they did here, so the
    shelf knows the disc is in (and it stays there across a restart)."""
    from . import schema
    try:
        node = schema.load(lab_name).nodes.get(node_id)
    except Exception:  # noqa: BLE001 - a lab being edited elsewhere; nothing to record
        return
    if node is not None:
        _set_drive(_node_dir(lab_name, node_id), node, 0, ref_for(lab_name, path) if path else "")


def note_port(lab_name: str, node_id: str, i: int, meta: dict | None) -> None:
    data = _load(_node_dir(lab_name, node_id))
    usb = data.setdefault("usb", {})
    if not meta and str(i) not in usb:
        return
    if meta:
        usb[str(i)] = meta
    else:
        usb.pop(str(i), None)
    _save(_node_dir(lab_name, node_id), data)


def boot_first(node_dir: Path) -> str:
    return BOOT_DVD if _load(node_dir).get("boot") == BOOT_DVD else BOOT_DISK


def set_boot(lab_name: str, node, first: str) -> None:
    if first not in (BOOT_DISK, BOOT_DVD):
        raise ShelfError("the machine boots from its disk or its DVD drive first")
    if first == BOOT_DVD and not drives(node):
        raise ShelfError(f"{node.id} has no DVD drive")
    d = _node_dir(lab_name, node.id)
    data = _load(d)
    data["boot"] = first
    _save(d, data)


# ----------------------------------------------------------------- discs
def _roots() -> list[Path]:
    return [paths.images_dir().resolve(), paths.VAR.resolve()]


def resolve(ref: str) -> Path:
    """A disc reference's ISO file: 'image:<id>' (an installer or an ISO the
    user added) or 'file:<path>' inside the image store or winlab's var."""
    kind, _, rest = ref.partition(":")
    if kind == "image" and rest:
        from .providers.qemu import QemuProvider
        return QemuProvider.iso_path(rest)
    if kind == "file" and rest:
        p = Path(rest).resolve()
        if p.suffix.lower() == ".iso" and any(p.is_relative_to(r) for r in _roots()):
            return p
    raise ShelfError(f"no such disc: {ref}")


def ref_for(lab_name: str, path: Path) -> str:
    p = Path(path)
    if p.parent.resolve() == paths.downloads_dir().resolve():
        sid = p.stem
        if sid in images.CATALOG or sid in images.custom_images():
            return f"image:{sid}"
    return f"file:{p.resolve()}"


def volume_label(iso: Path) -> str:
    """The disc's own label, from its primary volume descriptor."""
    try:
        with open(iso, "rb") as fh:
            fh.seek(16 * 2048)
            pvd = fh.read(72)
        if pvd[1:6] == b"CD001":
            return pvd[40:72].decode("ascii", "replace").strip()
    except OSError:
        pass
    return ""


def _disc(ref: str, title: str, kind: str, p: Path) -> dict:
    try:
        mb = p.stat().st_size >> 20
    except OSError:
        mb = 0
    return {"ref": ref, "title": title, "kind": kind, "mb": mb}


def discs(lab_name: str) -> list[dict]:
    """Every disc on the shelf: kind is windows, media (SQL Server,
    Configuration Manager), iso (one the user added), drivers, tools or
    burned (made by winlab for this lab)."""
    out: list[dict] = []
    seen: set[Path] = set()
    for i, e in images.CATALOG.items():
        if i in images.SHARES_INSTALLER or e.kind == LINUX:
            continue
        p = images.installer_path(i)
        if p.exists():
            out.append(_disc(f"image:{i}", e.short or e.title, "media" if e.kind == images.MEDIA else "windows", p))
            seen.add(p.resolve())
    for c in images.custom_images().values():
        if c.iso.exists():
            out.append(_disc(f"image:{c.id}", c.title, "iso", c.iso))
            seen.add(c.iso.resolve())
    dl = paths.downloads_dir()
    for p in sorted(dl.glob("*.iso")) if dl.exists() else []:
        if p.resolve() not in seen:
            kind = "drivers" if "virtio" in p.name.lower() or "driver" in p.name.lower() else "tools"
            out.append(_disc(f"file:{p.resolve()}", volume_label(p) or p.stem, kind, p))
    lab = paths.lab_dir(lab_name)
    burned = sorted(shelf_dir(lab_name, "discs").glob("*.iso")) + sorted(lab.glob("*/*.iso")) if lab.exists() else []
    for p in burned:
        label = volume_label(p) or p.stem
        if p.name == "guide-checks.iso":
            label = f"Check disc ({p.parent.name})"
        out.append(_disc(f"file:{p.resolve()}", label, "burned", p))
    return out


def burn(lab_name: str, folder: str | Path, label: str = "") -> dict:
    """A folder burned to a new disc on the shelf (not in any drive yet)."""
    from . import isowrite
    folder = Path(str(folder)).expanduser()
    if not folder.is_dir():
        raise ShelfError(f"no such folder: {folder}")
    label = re.sub(r"[^A-Za-z0-9_]", "_", label or folder.name)[:32] or "DISC"
    w = isowrite.IsoWriter(label.upper())
    try:
        count = w.add_tree(folder)
        if not count:
            raise ShelfError(f"{folder} holds no files")
        if w.total_bytes() > 4 * 1024**3:
            raise ShelfError("that folder is over 4 GB; a disc holds less")
        dest = shelf_dir(lab_name, "discs") / f"{label.lower()}.iso"
        dest.parent.mkdir(parents=True, exist_ok=True)
        w.write(dest.with_suffix(".tmp"))
    except isowrite.IsoWriteError as exc:
        raise ShelfError(str(exc)) from exc
    dest.with_suffix(".tmp").replace(dest)
    # the shelf lists its discs by their resolved path (a Windows short name
    # such as RUNNER~1 in TEMP spelled out), so the new one is named the same way
    return {**_disc(f"file:{dest.resolve()}", label.upper(), "burned", dest), "files": count}


def find_disc(lab_name: str, what: str) -> str:
    """A disc by its reference, image id, title or label."""
    if ":" in what:
        return what
    for d in discs(lab_name):
        if what in (d["ref"].split(":", 1)[1], d["title"]) or what.lower() == d["title"].lower() \
                or Path(d["ref"].split(":", 1)[1]).stem == what.lower():
            return d["ref"]
    if what in images.CATALOG or what in images.custom_images():
        return f"image:{what}"
    raise ShelfError(f"no disc '{what}' on the shelf: winlab media <lab> <node> list shows them")


# ---------------------------------------------------------------- sticks
def _stick_meta(p: Path) -> dict:
    try:
        return json.loads(p.with_suffix(".json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def sticks(lab_name: str) -> list[dict]:
    """The sticks lying on the shelf."""
    out = []
    d = shelf_dir(lab_name, "sticks")
    for p in sorted(d.glob("*.img")) if d.exists() else []:
        meta = _stick_meta(p)
        out.append({"id": p.stem, "title": meta.get("title") or "USB stick",
                    "mb": p.stat().st_size >> 20, "blank": bool(meta.get("blank"))})
    return out


def _new_id(lab_name: str, base: str) -> str:
    base = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")[:24] or "stick"
    taken = {s["id"] for s in sticks(lab_name)}
    for i in range(1, 1000):
        sid = base if i == 1 else f"{base}-{i}"
        if sid not in taken:
            return sid
    raise ShelfError("the shelf is full")


def _put_on_shelf(lab_name: str, img: Path, meta: dict) -> str:
    sid = meta.get("id") if _ID.match(str(meta.get("id") or "")) else ""
    d = shelf_dir(lab_name, "sticks")
    if not sid or (d / f"{sid}.img").exists():
        sid = _new_id(lab_name, meta.get("title") or "stick")
    d.mkdir(parents=True, exist_ok=True)
    img.replace(d / f"{sid}.img")
    meta = {**meta, "id": sid}
    (d / f"{sid}.json").write_text(json.dumps(meta) + "\n", encoding="utf-8")
    return sid


def new_blank(lab_name: str, gb: int) -> dict:
    """A new stick in its packet: no partition, no file system (sparse)."""
    from .media import BLANK_GB
    if gb not in BLANK_GB:
        raise ShelfError(f"a blank stick is {', '.join(str(g) for g in BLANK_GB)} GB")
    title = f"{gb} GB stick"
    sid = _new_id(lab_name, f"blank-{gb}gb")
    d = shelf_dir(lab_name, "sticks")
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"{sid}.img", "wb") as fh:
        fh.truncate(gb * 1024**3)
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title, "blank": True}) + "\n",
                                   encoding="utf-8")
    return {"id": sid, "title": title, "mb": gb * 1024}


def new_from_folder(lab_name: str, folder: str | Path, title: str = "") -> dict:
    """A stick written on this PC with a folder's files (a copy: the folder
    itself is never shared with the lab)."""
    from . import media
    try:
        files = media.folder_files(folder)
        title = title or Path(str(folder)).expanduser().name or "Files"
        sid = _new_id(lab_name, title)
        d = shelf_dir(lab_name, "sticks")
        media.write_stick(files, d / f"{sid}.img", re.sub(r"[^A-Z0-9_]", "_", title.upper())[:11] or "WINLAB")
    except media.MediaError as exc:
        raise ShelfError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files)}


def throw_away(lab_name: str, what: str) -> str:
    """A stick or a burned disc off the shelf for good."""
    d = shelf_dir(lab_name, "sticks")
    if _ID.match(what) and (d / f"{what}.img").exists():
        title = _stick_meta(d / f"{what}.img").get("title") or what
        (d / f"{what}.img").unlink()
        (d / f"{what}.json").unlink(missing_ok=True)
        return title
    if what.startswith("file:"):
        p = resolve(what)
        if p.parent == shelf_dir(lab_name, "discs").resolve() and p.exists():
            p.unlink()
            return p.stem
    raise ShelfError("only a stick or a disc burned onto the shelf can be thrown away")


# ----------------------------------------------------------- the machine
def _qmp_port(lab_name: str, node_id: str) -> int:
    from .media import _qmp_port as port
    return port(lab_name, node_id)


def _title(lab_name: str, ref: str, catalog: dict | None = None) -> dict:
    if catalog is None:
        catalog = {d["ref"]: d for d in discs(lab_name)}
    d = catalog.get(ref)
    if d:
        return {k: d[k] for k in ("ref", "title", "kind")}
    name = ref.split(":", 1)[-1]
    return {"ref": ref, "title": Path(name).stem if ref.startswith("file:") else name, "kind": "iso"}


def contents(lab_name: str, node, catalog: dict | None = None) -> dict:
    """What is in the machine's drives and ports, and what it boots first."""
    nd = _node_dir(lab_name, node.id)
    usb = _load(nd).get("usb") or {}
    out_d = []
    for i in range(drives(node)):
        ref = drive_ref(nd, node, i)
        out_d.append({"index": i, "disc": _title(lab_name, ref, catalog) if ref else None})
    out_p = []
    for i in range(ports(node)):
        f = port_file(nd, i)
        stick = None
        if f.exists():
            meta = usb.get(str(i)) or {}
            stick = {"id": meta.get("id", ""), "title": meta.get("title") or "USB stick",
                     "mb": f.stat().st_size >> 20}
        out_p.append({"index": i, "stick": stick})
    return {"drives": out_d, "ports": out_p, "boot": boot_first(nd)}


def _node(lab, node_id: str):
    node = lab.nodes.get(node_id)
    if node is None:
        raise ShelfError(f"no such machine {node_id}")
    return node


def insert(lab, node_id: str, ref: str, drive: int | None = None, qmp=Qmp) -> dict:
    """A disc from the shelf into a drive: the one named, or the first empty
    one (the first drive when all are full: its disc comes out first)."""
    node = _node(lab, node_id)
    n = drives(node)
    if not n:
        raise ShelfError(f"{node_id} has no DVD drive; give it a USB stick")
    nd = _node_dir(lab.name, node_id)
    if drive is None:
        drive = next((i for i in range(n) if not drive_ref(nd, node, i)), 0)
    if not 0 <= drive < n:
        raise ShelfError(f"{node_id} has {n} DVD drive{'s' if n > 1 else ''}")
    iso = resolve(ref)
    if not iso.exists():
        raise ShelfError(f"the disc's image is gone from this PC: {iso}")
    port = _qmp_port(lab.name, node_id)
    if port:
        try:
            with qmp(port) as mon:
                mon.call("blockdev-change-medium", id=drive_id(drive), filename=str(iso), format="raw",
                         **{"read-only-mode": "read-only"})
        except (QmpError, OSError) as exc:
            raise ShelfError(f"{node_id}: could not put the disc in: {exc}") from exc
    _set_drive(nd, node, drive, ref)
    return {"drive": drive, "live": bool(port), **_title(lab.name, ref)}


def eject(lab, node_id: str, drive: int = 0, qmp=Qmp) -> dict | None:
    """The disc out of the drive and back on the shelf; None if it was empty."""
    node = _node(lab, node_id)
    if not 0 <= drive < drives(node):
        raise ShelfError(f"{node_id} has no DVD drive {drive + 1}")
    nd = _node_dir(lab.name, node_id)
    ref = drive_ref(nd, node, drive)
    port = _qmp_port(lab.name, node_id)
    if port:
        try:
            with qmp(port) as mon:
                mon.call("eject", id=drive_id(drive), force=True)
        except (QmpError, OSError) as exc:
            raise ShelfError(f"{node_id}: could not eject: {exc}") from exc
    _set_drive(nd, node, drive, "")
    return _title(lab.name, ref) if ref else None


def _plug_live(port: int, i: int, img: Path, qmp=Qmp) -> None:
    with qmp(port) as mon:
        mon.call("blockdev-add", driver="raw", **{"node-name": port_id(i)},
                 file={"driver": "file", "filename": str(img)})
        try:
            mon.call("device_add", driver="usb-storage", id=port_id(i), drive=port_id(i),
                     bus="xhci.0", removable=True)
        except QmpError:
            mon.call("blockdev-del", **{"node-name": port_id(i)})
            raise


def _unplug_live(port: int, i: int, qmp=Qmp) -> None:
    with qmp(port) as mon:
        try:
            mon.call("device_del", id=port_id(i))
        except QmpError as exc:
            if "not found" not in str(exc).lower():
                raise
            return
        for _ in range(20):  # the USB device goes at once; its block node right after
            try:
                mon.call("blockdev-del", **{"node-name": port_id(i)})
                return
            except QmpError:
                time.sleep(0.25)


def plug(lab, node_id: str, stick_id: str, port: int | None = None, qmp=Qmp) -> dict:
    """A stick from the shelf into a USB port (the first free one)."""
    node = _node(lab, node_id)
    n = ports(node)
    if not n:
        raise ShelfError(f"{node_id} has no USB port")
    src = shelf_dir(lab.name, "sticks") / f"{stick_id}.img"
    if not _ID.match(stick_id) or not src.exists():
        raise ShelfError(f"no stick '{stick_id}' on the shelf")
    nd = _node_dir(lab.name, node_id)
    if port is None:
        port = next((i for i in range(n) if not port_file(nd, i).exists()), -1)
        if port < 0:
            raise ShelfError(f"every USB port of {node_id} is taken: pull a stick out first")
    if not 0 <= port < n:
        raise ShelfError(f"{node_id} has USB ports 1 to {n}")
    dest = port_file(nd, port)
    if dest.exists():
        raise ShelfError(f"USB port {port + 1} of {node_id} has a stick in it")
    meta = {**_stick_meta(src), "id": stick_id}
    nd.mkdir(parents=True, exist_ok=True)
    src.replace(dest)
    src.with_suffix(".json").unlink(missing_ok=True)
    mon = _qmp_port(lab.name, node_id)
    try:
        if mon:
            _plug_live(mon, port, dest, qmp)
    except (QmpError, OSError) as exc:
        _put_on_shelf(lab.name, dest, meta)
        raise ShelfError(f"{node_id}: could not plug the stick in: {exc}") from exc
    note_port(lab.name, node_id, port, meta)
    return {"port": port, "live": bool(mon), "title": meta.get("title") or "USB stick", "id": stick_id}


def unplug(lab, node_id: str, port: int = 0, qmp=Qmp) -> dict | None:
    """The stick out of the port and back on the shelf, with its files."""
    node = _node(lab, node_id)
    nd = _node_dir(lab.name, node_id)
    f = port_file(nd, port)
    if not 0 <= port < max(1, ports(node)) or not f.exists():
        return None
    mon = _qmp_port(lab.name, node_id)
    if mon:
        try:
            _unplug_live(mon, port, qmp)
        except (QmpError, OSError) as exc:
            raise ShelfError(f"{node_id}: could not pull the stick out: {exc}") from exc
    meta = (_load(nd).get("usb") or {}).get(str(port)) or {"title": "USB stick"}
    sid = _put_on_shelf(lab.name, f, meta)
    note_port(lab.name, node_id, port, None)
    return {"id": sid, "title": meta.get("title") or "USB stick", "live": bool(mon)}


# ---------------------------------------------------- the guest's own eject
_synced: dict[str, float] = {}
_sync_lock = threading.Lock()


def sync(lab, node, qmp=Qmp) -> bool:
    """Reads the running machine's drives: a tray Windows opened (Eject in
    File Explorer) puts the disc back on the shelf. True when that changed
    anything."""
    port = _qmp_port(lab.name, node.id)
    if not port or not drives(node):
        return False
    try:
        with qmp(port, timeout=2.0) as mon:
            blocks = mon.call("query-block") or []
            nd = _node_dir(lab.name, node.id)
            changed = False
            for i in range(drives(node)):
                b = next((x for x in blocks if x.get("device") == drive_id(i)
                          or str(x.get("qdev", "")).rstrip("/").split("/")[-1] == drive_id(i)), None)
                if b is None or not drive_ref(nd, node, i):
                    continue
                if b.get("tray_open") or not b.get("inserted"):
                    if b.get("inserted"):
                        try:
                            mon.call("blockdev-remove-medium", id=drive_id(i))
                        except QmpError:
                            pass
                    _set_drive(nd, node, i, "")
                    changed = True
            return changed
    except (QmpError, OSError, TypeError):
        return False


def view(lab, running: set[str], qmp=Qmp) -> dict:
    """The shelf and every machine's drives and ports, for the desktop. The
    running machines' trays are read at most every few seconds."""
    with _sync_lock:
        due = time.monotonic() - _synced.get(lab.name, 0.0) > SYNC_EVERY
        if due:
            _synced[lab.name] = time.monotonic()
    if due:
        for nid in sorted(running):
            node = lab.nodes.get(nid)
            if node is not None:
                sync(lab, node, qmp)
    catalog = {d["ref"]: d for d in discs(lab.name)}
    machines = {n.id: contents(lab.name, n, catalog) for n in lab.node_list()}
    where: dict[str, list[str]] = {}
    for nid, c in machines.items():
        for d in c["drives"]:
            if d["disc"]:
                where.setdefault(d["disc"]["ref"], []).append(nid)
    return {"discs": [{**d, "in": where.get(d["ref"], [])} for d in catalog.values()],
            "sticks": sticks(lab.name), "machines": machines,
            "blank_gb": [8, 16, 32, 64]}


# ------------------------------------------------------- what QEMU is given
def provider_discs(lab_name: str, node, default0: Path | None) -> list[Path | None]:
    """The ISO in each DVD drive at power-on (drive 0's default is what the
    definition's `iso` gives)."""
    nd = _node_dir(lab_name, node.id)
    out: list[Path | None] = []
    for i in range(drives(node)):
        rec = (_load(nd).get("dvd") or {}).get(str(i))
        if i == 0 and (not isinstance(rec, dict) or rec.get("def", "") != _def_iso(node)):
            out.append(default0)
            continue
        ref = str((rec or {}).get("disc") or "")
        try:
            p = resolve(ref) if ref else None
        except ShelfError:
            p = None
        out.append(p if p is not None and p.exists() else None)
    return out or [default0]


def describe(lab_name: str, node) -> list[str]:
    c = contents(lab_name, node)
    lines = [f"boots from: {'the DVD drive, then its disk' if c['boot'] == BOOT_DVD else 'its disk'}"]
    for d in c["drives"]:
        lines.append(f"DVD drive {d['index'] + 1}: {d['disc']['title'] if d['disc'] else 'empty'}")
    for p in c["ports"]:
        s = p["stick"]
        lines.append(f"USB port {p['index'] + 1}: {s['title'] + ' (' + str(s['mb']) + ' MB)' if s else 'empty'}")
    return lines


def act(dash, params: dict) -> dict:
    """The desktop's media actions (workbench `wb-media`)."""
    from . import naming
    lab = dash.lab
    op = str(params.get("op") or "")
    node_id = naming.resolve(lab, str(params.get("node") or "")) if params.get("node") else ""
    who = naming.display(lab, node_id) if node_id else ""

    def num(key: str) -> int | None:
        v = params.get(key)
        return None if v in (None, "") else int(v)
    try:
        if op == "insert":
            r = insert(lab, node_id, str(params.get("disc") or ""), num("drive"))
            return {"ok": True, "message": f"{r['title']} is in {who}'s DVD drive"
                    + ("" if r["live"] else " (the machine is off: it is there at power-on)")}
        if op == "eject":
            r = eject(lab, node_id, num("drive") or 0)
            return {"ok": True, "message": f"{r['title']} is back on the shelf" if r else "the drive was empty"}
        if op == "plug":
            r = plug(lab, node_id, str(params.get("stick") or ""), num("port"))
            return {"ok": True, "message": f"{r['title']} is in USB port {r['port'] + 1} of {who}"
                    + ("" if r["live"] else " (the machine is off: it is there at power-on)")}
        if op == "unplug":
            r = unplug(lab, node_id, num("port") or 0)
            return {"ok": True, "message": f"{r['title']} is back on the shelf, with its files" if r
                    else "nothing in that port"}
        if op == "boot":
            set_boot(lab.name, _node(lab, node_id), str(params.get("first") or ""))
            st = state.load(lab.name)
            on = bool(st and node_id in st.running())
            return {"ok": True, "message": f"{who} boots from its "
                    + ("DVD drive first" if params.get("first") == BOOT_DVD else "disk first")
                    + (": from its next power-on" if on else "")}
        if op == "blank":
            r = new_blank(lab.name, int(params.get("gb") or 16))
            return {"ok": True, "message": f"a new {r['title']} is on the shelf", "stick": r["id"]}
        if op == "stick":
            r = new_from_folder(lab.name, str(params.get("folder") or ""))
            return {"ok": True, "message": f"{r['files']} files written to a stick on the shelf", "stick": r["id"]}
        if op == "burn":
            r = burn(lab.name, str(params.get("folder") or ""), str(params.get("label") or ""))
            return {"ok": True, "message": f"{r['files']} files burned to disc {r['title']}, on the shelf",
                    "disc": r["ref"]}
        if op == "toss":
            return {"ok": True, "message": f"{throw_away(lab.name, str(params.get('what') or ''))} thrown away"}
        if op == "state":
            node = _node(lab, node_id)
            sync(lab, node)
            return {"ok": True, **contents(lab.name, node), "discs": discs(lab.name), "sticks": sticks(lab.name)}
        if op == "shelf":
            st = state.load(lab.name)
            return {"ok": True, **view(lab, set(st.running()) if st else set())}
    except (ShelfError, ValueError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown media action {op!r}"}
