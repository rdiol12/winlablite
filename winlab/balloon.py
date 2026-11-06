"""Shrinking running machines so another can boot (the virtio balloon).

Every machine starts with a virtio-balloon device. With the driver in the
guest (bases prepared with the virtio-win drivers, see virtio.py), QEMU can
ask a running Windows machine to give some of its memory back: the guest
pins pages into the balloon and QEMU discards them on the host.

That last part only works where the host can discard a page of process
memory: Linux and the BSDs (madvise). QEMU on Windows has no such call, so
there the balloon moves memory inside the guest but the host keeps every
byte committed (QEMU's own ram_block_discard_range reports MADVISE not
available). So on a Windows host no machine is shrunk while it runs, and
what fits a lab into the host is the lean trim at boot (membudget). On the
appliance and any Linux host, `lab up` reclaims from the machines already
running before it refuses to boot another.
"""

from __future__ import annotations

import sys
import time

from . import images
from .model import Lab, Node
from .qmp import Qmp, QmpError

MIB = 1024 * 1024
STEP_MB = 256
WHY_NOT = ("on a Windows host QEMU cannot hand a machine's ballooned memory back to "
           "the system, so running machines are not shrunk; the lean trim at boot "
           "is what fits them")


def host_can_reclaim() -> bool:
    return sys.platform != "win32"


def candidates(lab: Lab, running: dict) -> list[Node]:
    """Running Windows machines whose base carries the balloon driver."""
    out: list[Node] = []
    for node in lab.node_list():
        ns = running.get(node.id)
        if not ns or not getattr(ns, "qmp_port", 0):
            continue
        if not node.is_windows or node.vars.get("virtio") is False:
            continue
        if not images.base_virtio(node.image):
            continue
        out.append(node)
    return out


def plan(lab: Lab, nodes: list[Node], deficit_mb: int) -> dict[str, int]:
    """Target size per machine, in MB: round-robin steps down toward each
    machine's trim floor until the deficit is covered."""
    sizes = {n.id: n.memory_mb for n in nodes}
    floors = {n.id: n.trim_floor_mb for n in nodes}
    left = deficit_mb
    while left > 0:
        moved = False
        for n in nodes:
            slack = sizes[n.id] - floors[n.id]
            if slack <= 0 or left <= 0:
                continue
            step = min(STEP_MB, slack)
            sizes[n.id] -= step
            left -= step
            moved = True
        if not moved:
            break
    return {nid: mb for nid, mb in sizes.items() if mb != lab.nodes[nid].memory_mb}


def reclaim(lab: Lab, running: dict, deficit_mb: int, qmp_factory=Qmp,
            wait: float = 15.0) -> tuple[int, list[str]]:
    """Asks the running machines for `deficit_mb` between them and waits for
    the guests to answer. Returns (MB actually given back, notes for the
    user). A machine whose driver does not answer keeps its memory."""
    if not host_can_reclaim():
        return 0, [WHY_NOT]
    nodes = candidates(lab, running)
    if not nodes:
        return 0, ["no running machine has the balloon driver to give memory back"]
    targets = plan(lab, nodes, deficit_mb)
    if not targets:
        return 0, ["the running machines are already at their floors"]
    notes: list[str] = []
    for nid, mb in targets.items():
        try:
            with qmp_factory(running[nid].qmp_port) as q:
                q.call("balloon", value=mb * MIB)
        except QmpError as exc:
            notes.append(f"  {nid}: balloon request failed: {exc}")
            targets.pop(nid, None)
    freed = 0
    deadline = time.monotonic() + wait
    pending = dict(targets)
    actual: dict[str, int] = {}
    while pending and time.monotonic() < deadline:
        for nid in list(pending):
            try:
                with qmp_factory(running[nid].qmp_port) as q:
                    got = int((q.call("query-balloon") or {}).get("actual", 0)) // MIB
            except (QmpError, TypeError, ValueError):
                continue
            actual[nid] = got
            if got <= pending[nid] + STEP_MB // 4:
                pending.pop(nid)
        if pending:
            time.sleep(0.5)
    for nid, mb in targets.items():
        got = actual.get(nid, lab.nodes[nid].memory_mb)
        gave = lab.nodes[nid].memory_mb - got
        if gave > 0:
            freed += gave
            notes.append(f"  {nid}: gave back {gave} MB (now {got} MB) so the new machines fit")
        else:
            notes.append(f"  {nid}: no answer from its balloon driver; keeps {lab.nodes[nid].memory_mb} MB")
    return freed, notes


def relax(lab: Lab, running: dict, qmp_factory=Qmp) -> list[str]:
    """Lets every running machine have its defined memory again, after
    another machine stopped and the memory it held is free."""
    if not host_can_reclaim():
        return []
    out: list[str] = []
    for node in candidates(lab, running):
        try:
            with qmp_factory(running[node.id].qmp_port) as q:
                cur = int((q.call("query-balloon") or {}).get("actual", 0)) // MIB
                if cur and cur < node.memory_mb:
                    q.call("balloon", value=node.memory_mb * MIB)
                    out.append(node.id)
        except (QmpError, TypeError, ValueError):
            continue
    return out
