"""Host memory budget for `lab up`.

A Windows guest touches all of its memory while it boots, so the RAM a lab
asks for is RAM the host must really have free. Starting more than that does
not fail cleanly: QEMU dies with an allocation error on Windows hosts, or the
host pages until nothing responds. So before anything boots, winlab works out
what the machines it is about to start need, and if the host is short it first
trims machines toward their floor (never below it, see floor: Node.trim_floor_mb,
raised for a machine whose packs need more, like Wazuh's indexer)
and otherwise refuses with a plain explanation of what would fit.

It also decides *which* machines to start: an exercise or `--only` names a
few, and the domain controller they depend on comes along automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Lab

# What QEMU itself costs per machine beyond guest RAM (device model, video
# memory, the accelerator's bookkeeping), measured loosely on WHPX and KVM.
QEMU_OVERHEAD_MB = 160
# Headroom left for the host so the desktop stays usable once the lab is up.
HOST_MARGIN_MB = 512
TRIM_STEP_MB = 256


class BudgetError(Exception):
    pass


def floor(node) -> int:
    """The least this machine may be trimmed to: its OS's floor, raised to
    what the software it is built to run needs (the min_mb of the packs its
    node vars name: Wazuh's indexer, a database), never above what the lab
    gives it."""
    from .debpacks import PACKS
    v = (getattr(node, "vars", None) or {}).get("packs") or []
    need = max((PACKS[p].min_mb for p in (v if isinstance(v, list) else [v]) if p in PACKS), default=0)
    return max(node.trim_floor_mb, min(need, node.memory_mb))


@dataclass
class Budget:
    nodes: list[str]                 # machines to start, in the lab's boot order
    need_mb: int                     # guest RAM + overhead for those (and the fabric)
    avail_mb: int                    # host RAM free now; 0 when it could not be read
    trimmed: dict[str, tuple[int, int]] = field(default_factory=dict)  # id -> (from, to)
    added: list[str] = field(default_factory=list)  # pulled in as dependencies
    notes: list[str] = field(default_factory=list)  # what the balloon reclaimed, or why not

    @property
    def fits(self) -> bool:
        return not self.avail_mb or self.need_mb + HOST_MARGIN_MB <= self.avail_mb


def with_dependencies(lab: Lab, wanted: list[str]) -> tuple[list[str], list[str]]:
    """The wanted machines plus the forest root DC, without which a domain
    member cannot resolve the domain, log on or apply policy. Returned in boot
    order, with the ids that were added."""
    unknown = [n for n in wanted if n not in lab.nodes]
    if unknown:
        raise BudgetError(f"no such machine in lab '{lab.name}': {', '.join(unknown)}")
    from . import sites
    chosen = set(wanted)
    added: list[str] = []

    def take(nid: str) -> None:
        if nid not in chosen:
            chosen.add(nid)
            added.append(nid)

    dcs = [n for n in lab.node_list() if "ad-ds" in n.roles]
    roots = [n for n in dcs if n.vars.get("forest_root")]
    for nid in wanted:
        if not lab.nodes[nid].is_windows or "ad-ds" in lab.nodes[nid].roles:
            continue
        # A member at a site with its own domain controller logs on there
        # (the replica); elsewhere it needs the forest root.
        here = sites.site_of_node(lab, nid)
        local = [d for d in dcs if here and sites.site_of_node(lab, d.id) == here]
        for d in (local or roots)[:1]:
            take(d.id)
    # A machine that leases its address needs the lab's DHCP server up too
    # (the fabric relays to it; without the lease there is no network at all).
    leasing = [nid for nid in wanted
               if lab.nodes[nid].is_windows and any(n.dhcp for n in lab.nodes[nid].nics)]
    if leasing:
        for node in lab.node_list():
            if "dhcp" in node.roles:
                take(node.id)
                break
    # Two sites only meet through their gateways, but a member at a site with
    # its own DC works without the tunnel; lessons about the tunnel name the
    # gateways in `nodes` themselves.
    order = [n.id for n in lab.node_list() if n.id in chosen]
    return order, added


def _need(lab: Lab, ids: list[str], fabric_mb: int) -> int:
    total = sum(lab.nodes[n].memory_mb + QEMU_OVERHEAD_MB for n in ids)
    if fabric_mb:
        total += fabric_mb + QEMU_OVERHEAD_MB
    return total


def plan(lab: Lab, start: list[str], fabric_mb: int, avail_mb: int) -> Budget:
    """Budget for starting `start` (ids not already running) plus the fabric
    when fabric_mb is non-zero. Trims memory toward each machine's floor when
    the host is short, recording what it changed; does not touch the lab."""
    sizes = {n: lab.nodes[n].memory_mb for n in start}
    b = Budget(nodes=list(start), need_mb=_need(lab, start, fabric_mb), avail_mb=avail_mb)
    if b.fits:
        return b

    deficit = b.need_mb + HOST_MARGIN_MB - avail_mb
    # Round-robin in small steps so every machine gives up a similar share,
    # rather than one machine being cut to its floor while others stay roomy.
    while deficit > 0:
        progressed = False
        for n in start:
            slack = sizes[n] - floor(lab.nodes[n])
            if slack <= 0 or deficit <= 0:
                continue
            step = min(TRIM_STEP_MB, slack)
            sizes[n] -= step
            deficit -= step
            progressed = True
        if not progressed:
            break

    b.trimmed = {n: (lab.nodes[n].memory_mb, sizes[n]) for n in start
                 if sizes[n] != lab.nodes[n].memory_mb}
    b.need_mb -= sum(old - new for old, new in b.trimmed.values())
    return b


def apply(lab: Lab, b: Budget) -> None:
    """Boot the trimmed machines at their trimmed size. Only this run: the
    lab definition on disk keeps what its author asked for."""
    for n, (_, new) in b.trimmed.items():
        lab.nodes[n].memory_mb = new


def floor_mb(lab: Lab, ids: list[str], fabric_mb: int) -> int:
    """The least these machines can boot in, every one at its floor."""
    total = sum(floor(lab.nodes[n]) + QEMU_OVERHEAD_MB for n in ids)
    return total + (fabric_mb + QEMU_OVERHEAD_MB if fabric_mb else 0)


def explain(lab: Lab, b: Budget) -> list[str]:
    """Lines for the user: what was added, trimmed, or why it will not fit."""
    out: list[str] = []
    if b.added:
        out.append(f"  also starting {', '.join(b.added)}: the domain controller the "
                   f"other machines need")
    for n, (old, new) in b.trimmed.items():
        out.append(f"  {n}: {old} MB -> {new} MB for this run, to fit the "
                   f"{b.avail_mb / 1024:.1f} GiB free")
    out.extend(b.notes)
    if not b.fits:
        out.append(
            f"not enough memory: these machines need {b.need_mb / 1024:.1f} GiB even at "
            f"their minimum, and {b.avail_mb / 1024:.1f} GiB is free "
            f"(winlab keeps {HOST_MARGIN_MB} MB for the host)."
        )
        from .servercore import budget_hint
        out.extend(budget_hint(lab, b.nodes))
        out.append("  close other programs, or boot fewer machines: a lesson's "
                   "'Start these machines' button in the Lab guide, `winlab learn start <id>`, "
                   "`--only <node,...>`; or pass --force to start anyway")
    return out


def gib(mb: int) -> str:
    return f"{mb / 1024:.1f} GiB"
