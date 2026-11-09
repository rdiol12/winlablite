"""Hardware events on a machine: its data disks sit in hot-swap drive bays.

A disk pulled out of a running machine stops answering at once, the way a
dead or yanked drive does: every read and write the machine sends it fails.
Windows notices the way it does on a real server: a mirrored volume shows
Failed Redundancy, a Storage Spaces pool goes Degraded, a lone volume
reports I/O errors in the event log. (QEMU's SATA controller cannot drop a
device while it runs, so the drive's image is put behind a filter that
fails every request; the machine still lists the drive until it restarts.)

From the next start the bay is empty. With the machine off the disk goes
back in with its data (the mirror resynchronises), or a new blank disk of
the same size goes in its place (the student rebuilds the mirror or repairs
the pool onto it). Which bays are pulled is kept in the machine's folder.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import paths
from .media import _qmp_port
from .qmp import Qmp, QmpError

BAYS_FILE = "bays.json"
# The block layer's events a format driver raises for the data it moves:
# a request on any of them fails with EIO.
FAIL_EVENTS = ("read_aio", "write_aio", "flush_to_disk", "flush_to_os")
EIO = 5


class HardwareError(Exception):
    pass


def fmt_node(index: int) -> str:
    """The data disk's format node, named on its -drive by the provider."""
    return f"data{index}-fmt"


def file_node(index: int) -> str:
    return f"data{index}-file"


def gone_node(index: int) -> str:
    return f"data{index}-gone"


def _bays(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id / BAYS_FILE


def pulled(lab_name: str, node_id: str, count: int | None = None) -> set[int]:
    """The data disks (0 = the first) that are out of their bays."""
    return pulled_in(paths.lab_dir(lab_name) / node_id, count)


def pulled_in(node_dir: Path, count: int | None = None) -> set[int]:
    try:
        data = json.loads((node_dir / BAYS_FILE).read_text(encoding="utf-8"))
        out = {int(i) for i in data.get("pulled", [])}
    except (OSError, ValueError, TypeError, AttributeError):
        return set()
    return {i for i in out if count is None or 0 <= i < count}


def _save(lab_name: str, node_id: str, out: set[int]) -> None:
    p = _bays(lab_name, node_id)
    if not out:
        p.unlink(missing_ok=True)
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"pulled": sorted(out)}) + "\n", encoding="utf-8")


def _check(node, index: int) -> None:
    if not 0 <= index < len(node.data_disks_gb):
        raise HardwareError(f"{node.id} has no data disk in bay {index + 1} "
                            f"(it has {len(node.data_disks_gb)} data disk bay{'s' if len(node.data_disks_gb) != 1 else ''})")


def pull(lab_name: str, node, index: int, qmp=Qmp) -> bool:
    """Pull data disk ``index`` out of its bay; True when it was live."""
    _check(node, index)
    out = pulled(lab_name, node.id)
    if index in out:
        raise HardwareError(f"the disk in bay {index + 1} of {node.id} is already out")
    port = _qmp_port(lab_name, node.id)
    if port:
        rules = [{"event": e, "errno": EIO} for e in FAIL_EVENTS]
        try:
            with qmp(port) as mon:
                mon.call("blockdev-add", driver="blkdebug", **{"node-name": gone_node(index)},
                         image=file_node(index), **{"inject-error": rules})
                mon.call("blockdev-reopen", options=[{"driver": "qcow2", "node-name": fmt_node(index),
                                                      "file": gone_node(index)}])
        except (QmpError, OSError) as exc:
            raise HardwareError(f"{node.id}: could not pull the disk in bay {index + 1}: {exc}") from exc
    out.add(index)
    _save(lab_name, node.id, out)
    return bool(port)


def _off(lab_name: str, node, what: str) -> None:
    if _qmp_port(lab_name, node.id):
        raise HardwareError(f"shut {node.id} down before you {what}")


def put_back(lab_name: str, node, index: int) -> None:
    """The same disk back in its bay, with its data, for the next start."""
    _check(node, index)
    _off(lab_name, node, "put the disk back")
    out = pulled(lab_name, node.id)
    if index not in out:
        raise HardwareError(f"the disk in bay {index + 1} of {node.id} was never pulled")
    out.discard(index)
    _save(lab_name, node.id, out)


def reseat(lab_name: str, node, index: int, qmp=Qmp) -> None:
    """The same disk back in its hot-swap bay while the machine runs: the
    filter that failed every request comes off, and the drive answers again
    with its data. Only a disk that was in the machine when it started (and
    was pulled live) can go back live: a bay that was empty at power-on has
    no drive the controller knows."""
    _check(node, index)
    out = pulled(lab_name, node.id)
    if index not in out:
        raise HardwareError(f"the disk in bay {index + 1} of {node.id} was never pulled")
    port = _qmp_port(lab_name, node.id)
    if not port:
        put_back(lab_name, node, index)
        return
    from . import disks
    try:
        with qmp(port) as mon:
            names = {n.get("node-name") for n in (mon.call("query-named-block-nodes") or [])}
            if gone_node(index) not in names:
                raise HardwareError(f"bay {index + 1} of {node.id} was empty when it started: shut it down to "
                                    "put the disk back")
            sick = index in disks.failing_in(paths.lab_dir(lab_name) / node.id)
            under = disks.sick_node(index) if sick and disks.sick_node(index) in names else file_node(index)
            mon.call("blockdev-reopen", options=[{"driver": "qcow2", "node-name": fmt_node(index), "file": under}])
            mon.call("blockdev-del", **{"node-name": gone_node(index)})
    except (QmpError, OSError) as exc:
        raise HardwareError(f"{node.id}: could not put the disk back in bay {index + 1}: {exc}") from exc
    out.discard(index)
    _save(lab_name, node.id, out)


def replace(lab_name: str, node, index: int, disk_path: Path) -> None:
    """A new blank disk of the same size in the bay: the old one's image is
    thrown away, and the next start makes an empty one."""
    _check(node, index)
    _off(lab_name, node, "fit a new disk")
    disk_path.unlink(missing_ok=True)
    out = pulled(lab_name, node.id)
    out.discard(index)
    _save(lab_name, node.id, out)


def forget(lab_name: str, node_id: str, index: int) -> None:
    """A disk taken out of the machine for good leaves no pulled bay behind."""
    out = pulled(lab_name, node_id)
    if index in out:
        out.discard(index)
        _save(lab_name, node_id, out)


def status(lab_name: str, node) -> list[dict]:
    out = pulled(lab_name, node.id, len(node.data_disks_gb))
    return [{"index": i, "gb": gb, "pulled": i in out} for i, gb in enumerate(node.data_disks_gb)]
