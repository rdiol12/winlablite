"""The disks of a machine, managed like a server's drive cage.

Every data disk sits in a bay on a bus Windows drives with its own inbox
drivers: SATA (the Intel ICH9 AHCI controller, storahci), SAS (an LSI SAS1068
host bus adapter, lsi_sas) or NVMe (stornvme). A virtio machine has Red Hat's
virtio-blk in every bay instead, whatever was asked. The user fits a disk of
a size and a bus, takes any one out, pulls one while the machine runs
(winlab/hardware.py), fits a new blank one in a bay, or makes one fail.

A failing disk is what a dying drive is: slow (a throttle on its requests)
and with bad sectors, regions of the image where every read and write fails
with an I/O error (blkdebug, as a pull uses), so Windows logs disk errors
(disk Event 7 "bad block", 153 "retried") while most of the disk still
works; a mirror or a pool member goes unhealthy and the admin replaces it
before it dies. An NVMe disk also raises its SMART critical warning
(reliability degraded), which Windows shows as the drive's health.

The bus of each disk is in the lab file (node.vars["disk_bus"], one word a
bay, all-SATA left out). Which disks fail, and which drive is in each bay (a new
blank disk is another drive, with its own serial number), are kept in the
machine's folder (disks.json), never in the lab file: a network saved or
shared does not carry a broken disk.

Each bay also has its locate LED (Identify, as a RAID controller's drive
view and its management software turn on): a flag in disks.json, lit blue
on the machine's front panel, so the admin pulls the right drive. Bay -1
is the system disk's.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import hardware, paths, state
from .hardware import HardwareError
from .media import _qmp_port
from .qmp import Qmp, QmpError

BUSES = ("sata", "sas", "nvme")
TITLE = {"sata": "SATA", "sas": "SAS", "nvme": "NVMe", "virtio": "virtio"}
MAX_BAYS = 8
MAX_SATA = 3            # the AHCI controller's six ports hold the system disk, the Setup or provisioning DVD and the DVD drive too
SIZES_GB = (8, 10, 20, 40, 64, 128, 256)
STATE_FILE = "disks.json"
SAS_HBA = "wlsas"
NVME_WARN = 0x04        # SMART critical warning bit 2: NVM subsystem reliability degraded
SLOW_IOPS = 80          # a failing disk retries: it answers at a crawl
SLOW_BPS = 8 << 20
BAD_FIRST_MB = 8        # the first bad sector, then one every BAD_EVERY_MB of the image
BAD_EVERY_MB = 32
BAD_MAX = 128


class DiskError(HardwareError):
    pass


def device_id(index: int) -> str:
    return f"data{index}dev"


def sick_node(index: int) -> str:
    return f"data{index}-sick"


def slow_node(index: int) -> str:
    return f"data{index}-slow"


def throttle_group(index: int) -> str:
    return f"data{index}-tg"


# ------------------------------------------------------------------ buses
def _virtio(node) -> bool:
    from .providers.qemu import uses_virtio
    return uses_virtio(node)


def asked_buses(node) -> list[str]:
    """The bus the lab file names for each data disk (SATA when it names none)."""
    words = str(node.vars.get("disk_bus") or "").split()
    return [(words[i] if i < len(words) and words[i] in BUSES else "sata")
            for i in range(len(node.data_disks_gb))]


def buses(node) -> list[str]:
    """Each data disk's bus as the machine is really built."""
    if _virtio(node):
        return ["virtio"] * len(node.data_disks_gb)
    return asked_buses(node)


def _store_buses(node, out: list[str]) -> None:
    if all(b == "sata" for b in out):
        node.vars.pop("disk_bus", None)
    else:
        node.vars["disk_bus"] = " ".join(out)


# ------------------------------------------------------------------ state
def _load(node_dir: Path) -> dict:
    try:
        data = json.loads((node_dir / STATE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(node_dir: Path, data: dict) -> None:
    data = {"failing": sorted(set(data.get("failing", []))),
            "gen": {k: v for k, v in sorted(data.get("gen", {}).items()) if v},
            "next": int(data.get("next", 0)),
            "locate": sorted({int(i) for i in data.get("locate", [])})}
    p = node_dir / STATE_FILE
    if not data["failing"] and not data["gen"] and not data["next"] and not data["locate"]:
        p.unlink(missing_ok=True)
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data) + "\n", encoding="utf-8")


def failing_in(node_dir: Path, count: int | None = None) -> set[int]:
    try:
        out = {int(i) for i in _load(node_dir).get("failing", [])}
    except (TypeError, ValueError):
        return set()
    return {i for i in out if count is None or 0 <= i < count}


def located(node_dir: Path) -> set[int]:
    """The bays whose locate LED is on (-1: the system disk's bay)."""
    try:
        return {int(i) for i in _load(node_dir).get("locate", [])}
    except (TypeError, ValueError):
        return set()


def set_locate(lab_name: str, node, index: int, on: bool) -> None:
    """The locate LED of a bay on or off (the system disk's is bay -1)."""
    if index != -1:
        _check(node, index)
    ndir = _dir(lab_name, node.id)
    data = _load(ndir)
    cur = {int(i) for i in data.get("locate", [])}
    data["locate"] = sorted(cur | {index} if on else cur - {index})
    _save(ndir, data)


# What the controller reports of each drive QEMU presents: its model string
# and firmware revision, as Get-PhysicalDisk and a RAID controller list them.
DRIVE_MODEL = {"sata": ("QEMU HARDDISK", "2.5+"), "sas": ("QEMU HARDDISK", "2.5+"),
               "nvme": ("QEMU NVMe Ctrl", "1.0"), "virtio": ("virtio-blk", "")}


def generation(node_dir: Path, index: int) -> int:
    try:
        return int(_load(node_dir).get("gen", {}).get(str(index), 0))
    except (TypeError, ValueError, AttributeError):
        return 0


def serial(node_id: str, index: int, gen: int) -> str:
    """A drive's serial number: the same drive keeps it in any bay, a new
    one has its own (gen numbers the machine's drives; 0 is one winlab made
    before drives had numbers, named by its bay)."""
    key = f"{node_id}/drive{gen}" if gen else f"{node_id}/{index}/0"
    return "WL" + hashlib.sha1(key.encode()).hexdigest()[:12].upper()


def bad_sectors(gb: int) -> list[int]:
    """The 512-byte sectors of the image that fail: a few early ones, where
    a new volume's first files land, then spread over the disk."""
    every = max(BAD_EVERY_MB, gb * 1024 // BAD_MAX)
    mb = range(BAD_FIRST_MB, gb * 1024 + 64, every)
    return [m * 2048 for m in list(mb)[:BAD_MAX]]


def _rules(gb: int) -> list[dict]:
    return [{"event": e, "sector": s, "errno": hardware.EIO}
            for s in bad_sectors(gb) for e in ("read_aio", "write_aio")]


# --------------------------------------------------------- QEMU arguments
def controller_args(node) -> list[str]:
    """The SAS host bus adapter, when a bay is on it."""
    return ["-device", f"mptsas1068,id={SAS_HBA}"] if "sas" in buses(node) else []


def drive_args(node_dir: Path, node, index: int, path: Path, ahci_slot: int) -> list[str]:
    """One data disk of a regular-PC machine: its drive, through the failing
    disk's filters when it fails, and the device on its bus."""
    bus = asked_buses(node)[index]
    gb = node.data_disks_gb[index]
    gen = generation(node_dir, index)
    sick = index in failing_in(node_dir)
    out: list[str] = []
    if sick:
        out += ["-object", f"throttle-group,id={throttle_group(index)},"
                           f"x-iops-total={SLOW_IOPS},x-bps-total={SLOW_BPS}"]
        drive = (f"id=data{index},if=none,format=qcow2,cache=writeback,node-name={hardware.fmt_node(index)},"
                 f"file.driver=blkdebug,file.node-name={sick_node(index)}")
        for k, r in enumerate(_rules(gb)):
            drive += (f",file.inject-error.{k}.event={r['event']},file.inject-error.{k}.sector={r['sector']}"
                      f",file.inject-error.{k}.errno={r['errno']}")
        drive += (f",file.image.driver=throttle,file.image.throttle-group={throttle_group(index)},"
                  f"file.image.node-name={slow_node(index)},file.image.file.driver=file,"
                  f"file.image.file.filename={path},file.image.file.node-name={hardware.file_node(index)}")
    else:
        drive = (f"id=data{index},file={path},if=none,format=qcow2,cache=writeback,"
                 f"discard=unmap,detect-zeroes=unmap,node-name={hardware.fmt_node(index)},file.node-name={hardware.file_node(index)}")
    out += ["-drive", drive]
    # A disk winlab always made keeps QEMU's own serial; a new one has its own.
    sn = f",serial={serial(node.id, index, gen)}" if gen or bus == "nvme" else ""
    if bus == "nvme":
        out += ["-device", f"nvme,id={device_id(index)},drive=data{index}{sn}"
                           + (f",smart_critical_warning={NVME_WARN}" if sick else "")]
    elif bus == "sas":
        out += ["-device", f"scsi-hd,id={device_id(index)},bus={SAS_HBA}.0,scsi-id={index},drive=data{index}{sn}"]
    else:
        out += ["-device", f"ide-hd,id={device_id(index)},bus=ahci.{ahci_slot},drive=data{index}{sn}"]
    return out


# ------------------------------------------------------------- operations
def _off(lab_name: str, node, what: str) -> None:
    if _qmp_port(lab_name, node.id):
        raise DiskError(f"shut {node.id} down before you {what}")
    if node.id in state.suspended(lab_name):
        raise DiskError(f"{node.id} is suspended (hibernated): resume it and shut it down "
                        f"before you {what}, or Windows cannot wake it")


def _check(node, index: int) -> None:
    n = len(node.data_disks_gb)
    if not 0 <= index < n:
        raise DiskError(f"{node.id} has no data disk in bay {index + 1} "
                        f"(it has {n} data disk bay{'s' if n != 1 else ''})")


def _dir(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id


def add(lab, node, gb: int, bus: str = "sata") -> int:
    """A new blank disk in the next free bay; its index."""
    from . import editor
    bus = (bus or "sata").lower()
    if bus not in BUSES:
        raise DiskError(f"a disk is {', '.join(TITLE[b] for b in BUSES)}, not {bus}")
    _off(lab.name, node, "fit a disk")
    if len(node.data_disks_gb) >= MAX_BAYS:
        raise DiskError(f"{node.id} has all {MAX_BAYS} drive bays full")
    old = asked_buses(node)
    if bus == "sata" and not _virtio(node) and old.count("sata") >= MAX_SATA:
        raise DiskError(f"the SATA controller has room for {MAX_SATA} data disks: fit this one as SAS or NVMe")
    try:
        editor.set_node(lab, node.id, add_disk_gb=int(gb))
    except editor.EditError as exc:
        raise DiskError(str(exc)) from None
    i = len(node.data_disks_gb) - 1
    _store_buses(node, old + [bus])
    # Whatever an earlier disk in this bay left behind is not this disk.
    ndir = _dir(lab.name, node.id)
    (ndir / f"data{i}.qcow2").unlink(missing_ok=True)
    hardware.forget(lab.name, node.id, i)
    forget(lab.name, node.id, i, bump=True)
    return i


def remove(lab, node, index: int) -> None:
    """Take the disk in a bay out of the machine for good: its image is
    thrown away and the bays after it move up one (as they are numbered)."""
    _check(node, index)
    _off(lab.name, node, "take a disk out")
    ndir = _dir(lab.name, node.id)
    n = len(node.data_disks_gb)
    (ndir / f"data{index}.qcow2").unlink(missing_ok=True)
    for j in range(index + 1, n):
        src = ndir / f"data{j}.qcow2"
        if src.exists():
            src.replace(ndir / f"data{j - 1}.qcow2")
    shift = lambda s: {i if i < index else i - 1 for i in s if i != index}  # noqa: E731
    hardware._save(lab.name, node.id, shift(hardware.pulled(lab.name, node.id)))
    data = _load(ndir)
    gen = {int(k): v for k, v in data.get("gen", {}).items() if str(k).isdigit()}
    _save(ndir, {"failing": shift(failing_in(ndir)), "next": data.get("next", 0),
                 "gen": {str(i if i < index else i - 1): v for i, v in gen.items() if i != index},
                 "locate": shift(located(ndir))})
    b = asked_buses(node)
    b.pop(index)
    node.data_disks_gb.pop(index)
    _store_buses(node, b)


def set_bus(lab, node, index: int, bus: str) -> None:
    """Move a disk to another bus (its data goes with it)."""
    _check(node, index)
    bus = (bus or "").lower()
    if bus not in BUSES:
        raise DiskError(f"a disk is {', '.join(TITLE[b] for b in BUSES)}, not {bus}")
    _off(lab.name, node, "move a disk to another bus")
    b = asked_buses(node)
    if bus == "sata" and b[index] != "sata" and not _virtio(node) and b.count("sata") >= MAX_SATA:
        raise DiskError(f"the SATA controller has room for {MAX_SATA} data disks")
    b[index] = bus
    _store_buses(node, b)


def fail(lab_name: str, node, index: int, qmp=Qmp) -> bool:
    """Make the disk in a bay start failing; True when it was live."""
    _check(node, index)
    ndir = _dir(lab_name, node.id)
    if index in failing_in(ndir):
        raise DiskError(f"the disk in bay {index + 1} of {node.id} is already failing")
    port = _qmp_port(lab_name, node.id)
    live = bool(port) and index not in hardware.pulled(lab_name, node.id)
    if live:
        try:
            with qmp(port) as mon:
                mon.call("object-add", **{"qom-type": "throttle-group", "id": throttle_group(index),
                                          "x-iops-total": SLOW_IOPS, "x-bps-total": SLOW_BPS})
                mon.call("blockdev-add", driver="blkdebug", **{"node-name": sick_node(index),
                         "inject-error": _rules(node.data_disks_gb[index])},
                         image={"driver": "throttle", "node-name": slow_node(index),
                                "throttle-group": throttle_group(index), "file": hardware.file_node(index)})
                mon.call("blockdev-reopen", options=[{"driver": "qcow2", "node-name": hardware.fmt_node(index),
                                                      "file": sick_node(index)}])
                if buses(node)[index] == "nvme":
                    mon.call("qom-set", path=f"/machine/peripheral/{device_id(index)}",
                             property="smart_critical_warning", value=NVME_WARN)
        except (QmpError, OSError) as exc:
            raise DiskError(f"{node.id}: could not make the disk in bay {index + 1} fail: {exc}") from exc
    data = _load(ndir)
    data["failing"] = sorted(failing_in(ndir) | {index})
    _save(ndir, data)
    return live


def heal(lab_name: str, node, index: int, qmp=Qmp) -> bool:
    """Undo a failing disk (the instructor's undo; an admin replaces it)."""
    _check(node, index)
    ndir = _dir(lab_name, node.id)
    if index not in failing_in(ndir):
        raise DiskError(f"the disk in bay {index + 1} of {node.id} is not failing")
    port = _qmp_port(lab_name, node.id)
    live = bool(port) and index not in hardware.pulled(lab_name, node.id)
    if live:
        try:
            with qmp(port) as mon:
                mon.call("blockdev-reopen", options=[{"driver": "qcow2", "node-name": hardware.fmt_node(index),
                                                      "file": hardware.file_node(index)}])
                for call, arg in (("blockdev-del", {"node-name": sick_node(index)}),
                                  ("object-del", {"id": throttle_group(index)})):
                    try:
                        mon.call(call, **arg)
                    except QmpError:
                        pass  # started failing: the filters went with the reopen
                if buses(node)[index] == "nvme":
                    mon.call("qom-set", path=f"/machine/peripheral/{device_id(index)}",
                             property="smart_critical_warning", value=0)
        except (QmpError, OSError) as exc:
            raise DiskError(f"{node.id}: could not mend the disk in bay {index + 1}: {exc}") from exc
    data = _load(ndir)
    data["failing"] = sorted(failing_in(ndir) - {index})
    _save(ndir, data)
    return live


def replace(lab_name: str, node, index: int) -> None:
    """A new blank drive (a new serial number) in the bay, pulled, failing
    or healthy: the old one and its data are thrown away."""
    _check(node, index)
    _off(lab_name, node, "fit a new disk")
    hardware.replace(lab_name, node, index, _dir(lab_name, node.id) / f"data{index}.qcow2")
    forget(lab_name, node.id, index, bump=True)


def forget(lab_name: str, node_id: str, index: int, bump: bool = False) -> None:
    """The bay holds another drive now: not failing, and, with bump, a new
    drive number (so a new serial number)."""
    ndir = _dir(lab_name, node_id)
    data = _load(ndir)
    data["failing"] = sorted(failing_in(ndir) - {index})
    gen = dict(data.get("gen", {}))
    if bump:
        data["next"] = max([int(data.get("next", 0))] + [int(v) for v in gen.values()]) + 1
        gen[str(index)] = data["next"]
    else:
        gen.pop(str(index), None)
    data["gen"] = gen
    _save(ndir, data)


def health(pulled: bool, sick: bool, made: bool) -> str:
    return "pulled" if pulled else "failing" if sick else "healthy" if made else "new"


def status(lab_name: str, node) -> list[dict]:
    """Each bay as the Disks window shows it."""
    ndir = _dir(lab_name, node.id)
    n = len(node.data_disks_gb)
    out_of_bay = hardware.pulled_in(ndir, n)
    sick = failing_in(ndir, n)
    lit = located(ndir)
    bs = buses(node)
    rows = []
    for i, gb in enumerate(node.data_disks_gb):
        gen = generation(ndir, i)
        model, fw = DRIVE_MODEL.get(bs[i], ("", ""))
        rows.append({"index": i, "bay": i + 1, "gb": gb, "bus": bs[i], "bus_title": TITLE[bs[i]],
                     "health": health(i in out_of_bay, i in sick, (ndir / f"data{i}.qcow2").exists()),
                     "pulled": i in out_of_bay, "failing": i in sick,
                     "serial": serial(node.id, i, gen) if gen or bs[i] == "nvme" else "",
                     "generation": gen, "model": model, "firmware": fw, "locate": i in lit})
    return rows


def summary(lab_name: str, node) -> dict:
    """The machine and its bays, for the Disks window."""
    running = bool(_qmp_port(lab_name, node.id))
    rows = status(lab_name, node)
    virtio = _virtio(node)
    return {"node": node.id, "running": running, "virtio": virtio,
            "suspended": node.id in state.suspended(lab_name),
            "system_gb": int(node.vars.get("disk_gb") or 0),
            "system_model": DRIVE_MODEL["virtio" if virtio else "sata"][0],
            "system_firmware": DRIVE_MODEL["virtio" if virtio else "sata"][1],
            "system_locate": -1 in located(_dir(lab_name, node.id)),
            "disks": rows, "max_bays": MAX_BAYS, "max_sata": MAX_SATA,
            "buses": [] if virtio else list(BUSES), "sizes": list(SIZES_GB)}


# ----------------------------------------------------- the desktop's actions
def act(dash, action: str, params: dict) -> dict:
    """The Disks window: disk-list, disk-add, disk-rm, disk-bus, disk-pull,
    disk-back, disk-replace, disk-fail, disk-heal, disk-locate."""
    from . import editor, naming
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    node = lab.nodes.get(node_id)
    if node is None:
        return {"ok": False, "message": "no such machine"}
    name = naming.display(lab, node_id)
    try:
        if action == "disk-list":
            return {"ok": True, **summary(lab.name, node)}
        if action == "disk-add":
            i = add(lab, node, int(params.get("gb") or 20), str(params.get("bus") or "sata"))
            editor.save(lab); dash.reload()
            return {"ok": True, "message": f"a new {node.data_disks_gb[i]} GB {TITLE[buses(node)[i]]} disk "
                    f"in bay {i + 1} of {name}" + (": Windows finds it offline and not initialised" if node.is_windows else ", blank")}
        if action == "disk-locate":
            sys_bay = str(params.get("disk")) == "sys"
            i = -1 if sys_bay else int(params.get("disk", -2))
            on = str(params.get("on", "1")) in ("1", "true", "True")
            set_locate(lab.name, node, i, on)
            where = "the system disk's bay" if sys_bay else f"bay {i + 1}"
            return {"ok": True, "message": f"the locate LED of {where} of {name} is {'on: it blinks blue' if on else 'off'}"}
        i = int(params.get("disk", -1))
        if action == "disk-rm":
            remove(lab, node, i)
            editor.save(lab); dash.reload()
            return {"ok": True, "message": f"the disk in bay {i + 1} is out of {name} for good"}
        if action == "disk-bus":
            set_bus(lab, node, i, str(params.get("bus") or ""))
            editor.save(lab); dash.reload()
            return {"ok": True, "message": f"bay {i + 1} of {name} is on the {TITLE[asked_buses(node)[i]]} bus now"}
        if action == "disk-pull":
            live = hardware.pull(lab.name, node, i)
            return {"ok": True, "message": f"the disk in bay {i + 1} is pulled out of {name}"
                    + (": it stops answering now" if live else "; its bay is empty at the next start")}
        if action == "disk-back":
            hardware.put_back(lab.name, node, i)
            return {"ok": True, "message": f"the disk is back in bay {i + 1} of {name}, with its data"}
        if action == "disk-replace":
            replace(lab.name, node, i)
            return {"ok": True, "message": f"a new blank {node.data_disks_gb[i]} GB disk in bay {i + 1} of {name}"}
        if action == "disk-fail":
            live = fail(lab.name, node, i)
            return {"ok": True, "message": f"the disk in bay {i + 1} of {name} is failing"
                    + (": slow, with bad sectors, from now" if live else " from its next start")}
        if action == "disk-heal":
            heal(lab.name, node, i)
            return {"ok": True, "message": f"the disk in bay {i + 1} of {name} works again"}
    except (ValueError, HardwareError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown disk action {action!r}"}


# ---------------------------------------------------------------- the CLI
OPS = {"list": "the machine's drive bays: bus, size, health",
       "add": "fit a new blank disk (machine off)",
       "rm": "take the disk in a bay out for good (machine off)",
       "bus": "move a disk to another bus (machine off)",
       "pull": "pull a disk out of its bay (live: it stops answering at once)",
       "back": "put a pulled disk back, with its data (machine off)",
       "replace": "fit a new blank disk in a bay, pulled, failing or not (machine off)",
       "fail": "make a disk fail: slow, with bad sectors (live or at the next start)",
       "heal": "undo a failing disk"}


def add_cli(sub) -> None:
    """The `winlab disk` parser."""
    dp = sub.add_parser("disk", help="a machine's disks: fit, take out, pull, replace, make one fail")
    dp.add_argument("lab")
    dp.add_argument("node")
    ds = dp.add_subparsers(dest="diskcmd", metavar="<op>")
    for op, what in OPS.items():
        p = ds.add_parser(op, help=what)
        if op == "add":
            p.add_argument("--gb", type=int, default=20, help="its size (default 20)")
            p.add_argument("--bus", choices=BUSES, default="sata", help="SATA (default), SAS or NVMe")
        elif op != "list":
            p.add_argument("bay", type=int, help="the bay: 1 is the first data disk")
        if op == "bus":
            p.add_argument("to", choices=BUSES)


def render(rows: list[dict], node_id: str, running: bool) -> str:
    out = [f"{node_id} ({'running' if running else 'off'}): system disk + {len(rows)} data disk bay(s)"]
    for r in rows:
        out.append(f"  bay {r['bay']}: {r['gb']:>5} GB  {r['bus_title']:<6} {r['health']}"
                   + (f"  serial {r['serial']}" if r["serial"] else ""))
    return "\n".join(out)


def run_cli(args) -> int:
    import sys
    from . import editor
    try:
        lab = editor.load_for_edit(args.lab)
        node = lab.nodes.get(args.node)
        if node is None:
            print(f"no such node '{args.node}' in {lab.name}", file=sys.stderr)
            return 2
        op = args.diskcmd or "list"
        if op == "list":
            print(render(status(lab.name, node), node.id, bool(_qmp_port(lab.name, node.id))))
            return 0
        if op == "add":
            i = add(lab, node, args.gb, args.bus)
            editor.save(lab)
            print(f"a new {args.gb} GB {TITLE[buses(node)[i]]} disk in bay {i + 1}")
            return 0
        i = args.bay - 1
        if op == "rm":
            remove(lab, node, i); editor.save(lab)
            print(f"the disk in bay {args.bay} is out for good")
        elif op == "bus":
            set_bus(lab, node, i, args.to); editor.save(lab)
            print(f"bay {args.bay} is on the {TITLE[args.to]} bus")
        elif op == "pull":
            live = hardware.pull(lab.name, node, i)
            print(f"bay {args.bay} pulled" + (": the disk stops answering now" if live
                                               else "; it is empty at the next start"))
        elif op == "back":
            hardware.put_back(lab.name, node, i)
            print(f"the disk is back in bay {args.bay}, with its data")
        elif op == "replace":
            replace(lab.name, node, i)
            print(f"a new blank {node.data_disks_gb[i]} GB disk in bay {args.bay}")
        elif op == "fail":
            live = fail(lab.name, node, i)
            print(f"the disk in bay {args.bay} is failing" + (" now" if live else " from the next start"))
        elif op == "heal":
            heal(lab.name, node, i)
            print(f"the disk in bay {args.bay} works again")
        return 0
    except (editor.EditError, editor.LabError, HardwareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
