"""A machine's system disk as a part that can die and be replaced.

The data disks sit in bays (winlab/disks.py); the system disk is the drive
the machine boots from, and on a real server it dies too. Here it dies the
way a dead drive does: while the machine runs every request it gets fails
(the same filter a pulled data disk sits behind, winlab/hardware.py), so
Windows stops at once with a blue screen (CRITICAL_PROCESS_DIED or
KERNEL_DATA_INPAGE_ERROR); from the next power-on the drive does not answer
at all and the firmware finds nothing to boot.

With the machine off, a new blank drive of the same size goes in its place
(its own serial number; the old drive, its data and the checkpoints kept on
it are thrown away). What follows is the admin's job: boot the Windows
Server DVD, Repair your computer, Troubleshoot, System Image Recovery, and
restore the last full-server backup (winlab/wsbackup.py walks it through).
Mending a dead disk is the instructor's undo.

What died and which drive is fitted are kept in the machine's folder
(sysdisk.json), never in the lab file, as disks.json is.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from . import paths, state
from .hardware import FAIL_EVENTS, EIO, HardwareError
from .media import _qmp_port
from .qmp import Qmp, QmpError

STATE_FILE = "sysdisk.json"
FMT_NODE, FILE_NODE, GONE_NODE = "sys-fmt", "sys-file", "sys-gone"
BLANK_MB = 32           # a fitted drive with less than this written has had nothing restored onto it
DEFAULT_GB = 64


class SysDiskError(HardwareError):
    pass


def _dir(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id


def disk_file(lab_name: str, node_id: str) -> Path:
    return _dir(lab_name, node_id) / "system.qcow2"


def _load(node_dir: Path) -> dict:
    try:
        data = json.loads((node_dir / STATE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(node_dir: Path, data: dict) -> None:
    data = {k: v for k, v in data.items() if v}
    p = node_dir / STATE_FILE
    if not data:
        p.unlink(missing_ok=True)
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")


def dead(node_dir: Path) -> bool:
    return bool(_load(node_dir).get("dead"))


def generation(node_dir: Path) -> int:
    """0 for the drive the machine was built with, then one more for each
    new drive fitted."""
    try:
        return int(_load(node_dir).get("gen", 0))
    except (TypeError, ValueError):
        return 0


def serial(node_id: str, gen: int) -> str:
    return "WL" + hashlib.sha1(f"{node_id}/system{gen}".encode()).hexdigest()[:12].upper()


# --------------------------------------------------------- QEMU arguments
def drive_opts() -> str:
    """Names on the system disk's -drive, so a live death can swap its file."""
    return f",node-name={FMT_NODE},file.node-name={FILE_NODE}"


def device_opts(node_dir: Path, node_id: str) -> str:
    """A new drive has its own serial number; the first keeps QEMU's."""
    gen = generation(node_dir)
    return f",serial={serial(node_id, gen)}" if gen else ""


def present(node_dir: Path) -> bool:
    """A dead system disk does not answer the firmware at power-on."""
    return not dead(node_dir)


# ------------------------------------------------------------- operations
def _off(lab_name: str, node, what: str) -> None:
    if _qmp_port(lab_name, node.id):
        raise SysDiskError(f"shut {node.id} down before you {what}")
    if node.id in state.suspended(lab_name):
        raise SysDiskError(f"{node.id} is suspended (hibernated): resume it and shut it down before you {what}")


def _windows(node) -> None:
    if not node.is_windows:
        raise SysDiskError(f"{node.id} is not a Windows machine: its system disk is the appliance's own")


def die(lab_name: str, node, qmp=Qmp) -> bool:
    """The system disk dies; True when the machine was running (it stops
    with a blue screen: every read and write fails from now)."""
    _windows(node)
    nd = _dir(lab_name, node.id)
    if dead(nd):
        raise SysDiskError(f"the system disk of {node.id} is already dead")
    port = _qmp_port(lab_name, node.id)
    if port:
        rules = [{"event": e, "errno": EIO} for e in FAIL_EVENTS]
        try:
            with qmp(port) as mon:
                mon.call("blockdev-add", driver="blkdebug", **{"node-name": GONE_NODE},
                         image=FILE_NODE, **{"inject-error": rules})
                mon.call("blockdev-reopen", options=[{"driver": "qcow2", "node-name": FMT_NODE,
                                                      "file": GONE_NODE}])
        except (QmpError, OSError) as exc:
            raise SysDiskError(f"{node.id}: could not kill its system disk: {exc} "
                               "(a machine started before winlab named its system disk: restart it first)") from exc
    data = _load(nd)
    data["dead"] = True
    _save(nd, data)
    return bool(port)


def mend(lab_name: str, node, qmp=Qmp) -> bool:
    """Undo a death (the instructor's undo; an admin replaces the drive)."""
    nd = _dir(lab_name, node.id)
    if not dead(nd):
        raise SysDiskError(f"the system disk of {node.id} is not dead")
    port = _qmp_port(lab_name, node.id)
    live = False
    if port:
        try:
            with qmp(port) as mon:
                try:
                    mon.call("blockdev-reopen", options=[{"driver": "qcow2", "node-name": FMT_NODE,
                                                          "file": FILE_NODE}])
                    live = True
                    mon.call("blockdev-del", **{"node-name": GONE_NODE})
                except QmpError:
                    pass  # it died before this start: the machine has no system disk until the next one
        except OSError as exc:
            raise SysDiskError(f"{node.id}: could not mend its system disk: {exc}") from exc
    data = _load(nd)
    data.pop("dead", None)
    _save(nd, data)
    return live


def size_gb(lab_name: str, node) -> int:
    """The system disk's size: what its image says, else what the lab asks."""
    p = disk_file(lab_name, node.id)
    if p.exists():
        try:
            out = subprocess.run([str(paths.qemu_img()), "info", "-U", "--output=json", str(p)],
                                 capture_output=True, timeout=60)
            if out.returncode == 0:
                return max(1, int(json.loads(out.stdout)["virtual-size"]) >> 30)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            pass
    try:
        return int(node.vars.get("disk_gb") or 0) or DEFAULT_GB
    except (TypeError, ValueError):
        return DEFAULT_GB


def replace(lab_name: str, node) -> int:
    """A new blank drive of the same size in place of the system disk (dead
    or not); its size in GB. The old drive and everything on it, its
    checkpoints too, are gone. The firmware's NVRAM is the motherboard's and
    stays."""
    from . import images
    _windows(node)
    _off(lab_name, node, "fit a new system disk")
    gb = size_gb(lab_name, node)
    p = disk_file(lab_name, node.id)
    p.unlink(missing_ok=True)
    images.create_blank(p, gb)
    nd = _dir(lab_name, node.id)
    data = _load(nd)
    data.pop("dead", None)
    data["gen"] = generation(nd) + 1
    data["gb"] = gb
    _save(nd, data)
    return gb


def written_mb(path: Path) -> int:
    """What is on the drive's file, in MB: the blocks it holds where the
    file system counts them, else its size (Windows has no st_blocks; a
    qcow2 file there grows only as the guest writes)."""
    try:
        st = path.stat()
    except OSError:
        return 0
    blocks = getattr(st, "st_blocks", None)
    return ((blocks * 512) if blocks is not None else st.st_size) >> 20


def status(lab_name: str, node) -> dict:
    """The system disk as the Disks window shows it: healthy, dead, new
    (a blank drive just fitted) or replaced (a fitted drive with something
    on it: restored or reinstalled)."""
    nd = _dir(lab_name, node.id)
    gen = generation(nd)
    p = disk_file(lab_name, node.id)
    if dead(nd):
        health = "dead"
    elif gen and written_mb(p) < BLANK_MB:
        health = "new"
    elif gen:
        health = "replaced"
    else:
        health = "healthy"
    gb = int(_load(nd).get("gb") or 0) or (size_gb(lab_name, node) if p.exists() else 0)
    return {"health": health, "dead": health == "dead", "generation": gen, "gb": gb,
            "serial": serial(node.id, gen) if gen else "", "windows": node.is_windows,
            "server": node.kind == "windows-server",
            "written_mb": written_mb(p) if p.exists() else 0}


# ----------------------------------------------------- the desktop's actions
def act(dash, action: str, params: dict) -> dict:
    """sysdisk-state, sysdisk-die, sysdisk-mend, sysdisk-replace."""
    from . import naming
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    node = lab.nodes.get(node_id)
    if node is None:
        return {"ok": False, "message": "no such machine"}
    name = naming.display(lab, node_id)
    try:
        if action == "sysdisk-state":
            return {"ok": True, **status(lab.name, node)}
        if action == "sysdisk-die":
            live = die(lab.name, node)
            return {"ok": True, "message": f"the system disk of {name} is dead"
                    + (": Windows stops with a blue screen" if live
                       else "; at its next power-on it finds nothing to boot")}
        if action == "sysdisk-mend":
            live = mend(lab.name, node)
            return {"ok": True, "message": f"the system disk of {name} works again"
                    + ("" if live or not _qmp_port(lab.name, node.id) else " from its next start")}
        if action == "sysdisk-replace":
            gb = replace(lab.name, node)
            return {"ok": True, "message": f"a new blank {gb} GB system disk is in {name}: boot the "
                    "Windows Server DVD and restore the last full-server backup onto it"}
    except (ValueError, HardwareError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown system disk action {action!r}"}


# ---------------------------------------------------------------- the CLI
OPS = {"status": "the system disk: healthy, dead, a new blank one, or replaced",
       "die": "the system disk dies (live: Windows stops with a blue screen)",
       "mend": "undo a dead system disk",
       "replace": "fit a new blank system disk of the same size (machine off)"}


def add_cli(sub) -> None:
    p = sub.add_parser("sysdisk", help="a machine's system disk: make it die, fit a new blank one")
    p.add_argument("lab")
    p.add_argument("node")
    p.add_argument("op", nargs="?", choices=list(OPS), default="status",
                   help="; ".join(f"{k}: {v}" for k, v in OPS.items()))


def run_cli(args) -> int:
    import sys
    from . import schema
    try:
        lab = schema.load(args.lab)
        node = lab.nodes.get(args.node)
        if node is None:
            print(f"no such node '{args.node}' in {lab.name}", file=sys.stderr)
            return 2
        if args.op == "status":
            s = status(lab.name, node)
            print(f"{node.id}: system disk {s['health']}" + (f", serial {s['serial']}" if s["serial"] else "")
                  + (f", {s['written_mb']} MB written" if s["generation"] else ""))
        elif args.op == "die":
            live = die(lab.name, node)
            print(f"the system disk of {node.id} is dead" + (" now" if live else " from its next start"))
        elif args.op == "mend":
            mend(lab.name, node)
            print(f"the system disk of {node.id} works again")
        else:
            print(f"a new blank {replace(lab.name, node)} GB system disk is in {node.id}")
        return 0
    except (HardwareError, Exception) as exc:  # noqa: BLE001 - a lab file error reads the same
        print(f"error: {exc}", file=sys.stderr)
        return 1
