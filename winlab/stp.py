"""Spanning tree on the workbench's switches, and the loops it is there for.

A second cable between two switches, or a ring of three, is a loop: a
broadcast goes round it for ever, copied at every switch, until the network
drowns (a broadcast storm). Spanning tree is how switches live with spare
cables: they elect a root bridge (lowest priority, then lowest address),
every other switch keeps its cheapest way to the root (its root port), each
cable gets one designated end, and every port left over blocks.

How it is real. The machines' ports are all on the router's one VLAN-aware
bridge (winlab/netplan.py), so the cables between switches get bridges of
their own on the router: each switch with a cable to another switch is a
kernel bridge there (stp<N>, its alias the switch's name), each
switch-to-switch cable a veth pair between two of them (stp<N>g<port>), and
the switch at the top of each tree is joined to the router's bridge by one
more pair (stp<N>fa / stp<N>lab), the way its machines' frames come in. The
kernel runs classic 802.1D on those bridges (stp_state 1) for a switch in
`spanning-tree mode pvst`, and one tree serves every VLAN: VLAN 1's settings
(priority, on or off) are the switch's.

`spanning-tree mode rapid-pvst` is real rapid spanning tree (802.1w) when
mstpd is on the router (winlab/mstpd.py): the kernel does 802.1D only, and
mstpd (GPL-2.0-or-later, github.com/mstpd/mstpd) is the Linux daemon that
runs RSTP on a bridge the kernel hands it. It is not packaged for Alpine
(neither main nor community of the router's release, nor edge's testing),
so winlab's own workflow builds it from the pinned upstream release as
static programs and publishes them with their source; preparation fetches
that asset onto this PC and the repository volume carries it to the router.
The start script below then starts mstpd, names the rapid switches' bridges
in /run/winlab-rstp (winlab's /sbin/bridge-stp says yes to the kernel for
those, so their stp_state is 2, user STP), and sets each one up with
mstpctl: protocol rstp, the bridge priority, and per port the cost, the
priority, PortFast as an admin edge port and BPDU guard (which mstpd
enforces itself: the first BPDU on a guarded port shuts it). Roles and
states in `show spanning-tree` are then what mstpctl reports. A switch left
in pvst keeps the kernel's 802.1D, and RSTP falls back to 802.1D on a cable
to it, as the standard says. Without mstpd (no build published yet, or not
fetched) rapid-pvst only shortens the kernel's forward delay (4 s instead of
15 s), and the consoles say so. One tree serves every VLAN either way: Rapid
PVST+'s per-VLAN instances are not made here.

`spanning-tree mode mst` is MSTP (802.1s) in the same mstpd, with the region
typed under `spanning-tree mst configuration` (winlab/mst.py): mstpctl sets
the bridge to mstp, its region name and revision (setmstconfid), creates
each instance and maps its VLANs (setvid2fid, setfid2mstid), and sets each
instance's bridge priority. mstpd sends the region's configuration digest in
its BPDUs, so two switches whose name, revision or VLAN map differ really
are two regions, joined at boundary ports. The router's bridges keep one
state per port, so every VLAN forwards along the CIST (instance 0); the
other instances are elected and shown, not separate forwarding paths.

With spanning tree off on a loop the kernel floods for real: frames go round
the veths and come back into the router's bridge, which floods them to every
machine on the VLAN and learns their addresses on the wrong port. The PC is
protected by a token bucket on every one of those veths (STORM_RATE,
INTO_LAB_RATE), so a storm here is about two thousand frames a second where a
real gigabit port carries 1.4 million; the canvas and the consoles say so.

The roles and states on the canvas and in `show spanning-tree` are worked
out here from the same settings the kernel gets (802.1D's election,
compute()); when the router runs, the canvas and the console read the
kernel's own port states and counters (LIVE_CMD).

What the console sets lives with the switch's other settings in the lab
file ([devices."sw:<id>"]); a spare cable between two switches is
"xcable:<other>" (how many) on the switch whose name sorts first. A new
switch ships with PVST on at priority 32768, as Cisco's do.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from dataclasses import dataclass, field

from . import devcli, paths, state

GI1 = "GigabitEthernet0/1"
MODES = ("pvst", "rapid-pvst", "mst")
FAST = ("rapid-pvst", "mst")   # the modes mstpd runs
PRIORITY = 32768
GIG_COST = 4              # 1 Gbit/s, Cisco's short path cost
FAST_COST = 19            # 100 Mbit/s
PORT_PRIORITY = 128
FORWARD_DELAY = {"pvst": 15, "rapid-pvst": 4, "mst": 4}   # seconds, on the kernel's 802.1D
RSTP_FORWARD_DELAY = 15   # rapid-pvst in mstpd: the standard's and Cisco's default
HELLO, MAX_AGE = 2, 20
STORM_RATE = "1mbit"      # every switch-to-switch veth
INTO_LAB_RATE = "512kbit"  # what a loop sends back into the router's bridge
STORM_PPS = 300           # more broadcast frames a second than this on a cable: a storm
CAP_TEXT = ("winlab caps it (1 Mbit/s a cable, about 2,000 small frames a second, and half that back into "
            "the router's switch) so the lab never eats this PC; a real storm runs at line rate, 1.4 million "
            "frames a second on a gigabit port")
KERNEL_NOTE = ("the router's kernel runs classic 802.1D for the switches (one tree for every VLAN, "
               "VLAN 1's settings); mstpd is not on the router")
RSTP_NOTE = ("rapid spanning tree (802.1w) runs in mstpd on the router for this switch "
             "(one tree for every VLAN, VLAN 1's settings)")
MST_NOTE = ("MSTP (802.1s) runs in mstpd on the router for this switch, with its region's name, revision "
            "and VLAN map; every VLAN forwards along the CIST (instance 0)")
_RSTP_ROLE = {"Root": "Root", "Designated": "Desg", "Alternate": "Altn", "Backup": "Back",
              "Disabled": "Disa", "Master": "Mstr"}
_RSTP_STATE = {"forwarding": "FWD", "learning": "LRN", "discarding": "BLK"}
_STATES = {"0": "DIS", "1": "LIS", "2": "LRN", "3": "FWD", "4": "BLK"}


# ------------------------------------------------------------------ cables
@dataclass(frozen=True)
class End:
    sw: str
    port: str


@dataclass
class Cable:
    id: str
    a: End
    b: End
    kind: str        # "trunk" (a's uplink into b) or "extra" (a spare cable)

    def ends(self) -> tuple[End, End]:
        return self.a, self.b

    def far(self, end: End) -> End:
        return self.b if end == self.a else self.a


def gi(n: int) -> str:
    return f"GigabitEthernet0/{n}"


def gi_no(port: str) -> int:
    m = re.search(r"(\d+)$", port)
    return int(m.group(1)) if m else 0


def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


def extra_pairs(lab) -> list[tuple[str, str, int]]:
    """(a, b, k) per spare cable between switches a and b (a sorts first)."""
    out = []
    for sw in devcli.switches(lab):
        for k, v in _own(lab, sw).items():
            if k.startswith("xcable:"):
                try:
                    n = int(v)
                except ValueError:
                    continue
                out += [(sw, k[7:], i) for i in range(max(0, n))]
    return sorted(out)


def cables(lab) -> list[Cable]:
    """Every cable between two switches: the uplinks (Gi0/1 into a port of
    the switch above, Gi0/2 up), then the spare ones on the next free
    gigabit ports of each end."""
    sws = devcli.switches(lab)
    nxt = {s: 2 + len(devcli.downlinks(lab, s)) for s in sws}
    out = []
    for s in sws:
        up = devcli.upstream(lab, s)
        if up in sws:
            port = dict((b, p) for p, b in devcli.downlinks(lab, up)).get(s, "")
            out.append(Cable(f"t:{s}", End(s, GI1), End(up, port), "trunk"))
    for a, b, k in extra_pairs(lab):
        if a not in sws or b not in sws or a == b or max(nxt[a], nxt[b]) > devcli.GIG_PORTS:
            continue
        out.append(Cable(f"x:{a}:{b}:{k}", End(a, gi(nxt[a])), End(b, gi(nxt[b])), "extra"))
        nxt[a] += 1
        nxt[b] += 1
    return out


def free_gig(lab, sw: str) -> int:
    """Gigabit ports left on a switch for another cable below it or beside it."""
    used = sum(1 for c in cables(lab) for e in c.ends() if e.sw == sw and e.port != GI1)
    return devcli.GIG_PORTS - 1 - used


def top(lab, sw: str) -> str:
    """The switch at the top of the tree of uplinks this one hangs in."""
    seen = {sw}
    while True:
        up = devcli.upstream(lab, sw)
        if up not in lab.networks or up in seen:
            return sw
        seen.add(up)
        sw = up


def trees(lab) -> list[tuple[str, list[str]]]:
    """(top, its switches) per tree of two switches or more."""
    groups: dict[str, list[str]] = {}
    for sw in devcli.switches(lab):
        groups.setdefault(top(lab, sw), []).append(sw)
    return [(t, sorted(m)) for t, m in sorted(groups.items()) if len(m) > 1]


def ports_of(lab, sw: str, cabs: list[Cable] | None = None) -> list[tuple[End, Cable]]:
    out = [(e, c) for c in (cables(lab) if cabs is None else cabs) for e in c.ends() if e.sw == sw]
    return sorted(out, key=lambda x: gi_no(x[0].port))


# ------------------------------------------------------------------ settings
def mode(lab, sw: str) -> str:
    return _own(lab, sw).get("stp-mode") or "pvst"


def rstp_ready() -> bool:
    """mstpd's build is fetched onto this PC, so the router runs rapid-pvst
    as RSTP (winlab/mstpd.py)."""
    from . import mstpd
    return mstpd.ready()


def note(lab, sw: str) -> str:
    """What runs this switch's spanning tree on the router, in a line."""
    m = mode(lab, sw)
    if m == "mst" and rstp_ready():
        return MST_NOTE
    return RSTP_NOTE if m == "rapid-pvst" and rstp_ready() else KERNEL_NOTE


def vlan_on(lab, sw: str, tag: int = 1) -> bool:
    return not _own(lab, sw).get(f"stp-off:{tag}")


def priority(lab, sw: str, tag: int = 1) -> int:
    if mode(lab, sw) == "mst":   # the CIST's priority: spanning-tree mst 0 priority (winlab/mst.py)
        try:
            return int(_own(lab, sw).get("mst-prio:0") or PRIORITY)
        except ValueError:
            return PRIORITY
    try:
        return int(_own(lab, sw).get(f"stp-prio:{tag}") or PRIORITY)
    except ValueError:
        return PRIORITY


def port_cost(lab, end: End) -> int:
    try:
        return int(_own(lab, end.sw).get(f"stp-cost:{end.port}") or GIG_COST)
    except ValueError:
        return GIG_COST


def port_priority(lab, end: End) -> int:
    try:
        return int(_own(lab, end.sw).get(f"stp-pri:{end.port}") or PORT_PRIORITY)
    except ValueError:
        return PORT_PRIORITY


def port_id(lab, end: End) -> tuple[int, int]:
    """Cisco numbers a 2950's ports 1-24 (Fa) then 25 up (Gi)."""
    return port_priority(lab, end), 24 + gi_no(end.port)


def bridge_mac(lab, sw: str) -> str:
    """A switch's own address: fixed for the switch, but no order to it, as
    on real hardware (so the root, left alone, is whichever is lowest)."""
    h = hashlib.sha256(f"winlab-switch/{lab.name}/{sw}".encode()).digest()
    return "02:57:4c:%02x:%02x:%02x" % (h[0], h[1], h[2])


def bridge_id(lab, sw: str) -> tuple[int, str]:
    return priority(lab, sw), bridge_mac(lab, sw)


def edge(lab, sw: str, key: str, gig: bool) -> bool:
    """PortFast: by hand on the port, or by default on every access port.
    A trunk (gigabit) port takes it only as `spanning-tree portfast trunk`."""
    v = _own(lab, sw).get(f"stp-edge:{key}", "")
    if v == "no":
        return False
    if gig:
        return v == "trunk"
    return bool(v) or bool(_own(lab, sw).get("stp-edge-default"))


def guarded(lab, sw: str, key: str, gig: bool) -> bool:
    v = _own(lab, sw).get(f"stp-guard:{key}", "")
    if v:
        return v == "yes"
    return bool(_own(lab, sw).get("stp-guard-default")) and edge(lab, sw, key, gig)


def shut(lab, end: End) -> bool:
    return bool(_own(lab, end.sw).get(f"shut:{end.port}"))


# ------------------------------------------------------------------ the election
@dataclass
class PortState:
    end: End
    cable: str
    far: End
    role: str = ""        # root, desg, altn, back; "" where spanning tree is off
    state: str = "FWD"    # FWD, BLK, down (shut or the far end is), err (err-disabled)
    cost: int = GIG_COST
    pid: tuple[int, int] = (PORT_PRIORITY, 25)
    edge: bool = False
    guard: bool = False
    po: str = ""          # the port-channel a bundled cable is in (winlab/etherchannel.py)
    twin: bool = False    # a bundled cable other than the channel's first: shown as the channel


@dataclass
class Bridge:
    sw: str
    on: bool
    mode: str
    bid: tuple[int, str]
    root: str = ""        # the root bridge's switch ("" when spanning tree is off)
    root_bid: tuple[int, str] = (0, "")
    cost: int = 0
    root_port: str = ""
    cpu: int = 3


@dataclass
class Result:
    cables: list[Cable] = field(default_factory=list)
    ports: dict[End, PortState] = field(default_factory=dict)
    bridges: dict[str, Bridge] = field(default_factory=dict)
    loop: list[str] = field(default_factory=list)      # cable ids on a loop that forwards
    storm: list[str] = field(default_factory=list)     # switches on it
    err: set = field(default_factory=set)

    def of(self, sw: str) -> list[PortState]:
        return sorted((p for e, p in self.ports.items() if e.sw == sw), key=lambda p: gi_no(p.end.port))


class _UF:
    def __init__(self):
        self.p: dict = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _bpdu_in(lab, end: End, cab: Cable, live: list[Cable], on: dict[str, bool]) -> bool:
    """Whether BPDUs arrive on a port: the switch at the far end runs
    spanning tree (every port sends them as its link comes up), or it does
    not and floods on the BPDUs of a switch behind it that does."""
    adj: dict[str, list[tuple[str, str]]] = {}
    for c in live:
        if c.id != cab.id:
            adj.setdefault(c.a.sw, []).append((c.b.sw, c.id))
            adj.setdefault(c.b.sw, []).append((c.a.sw, c.id))
    start = cab.far(end).sw
    todo, seen = [start], {start}
    while todo:
        s = todo.pop()
        if on.get(s):
            return True
        for nxt, _ in adj.get(s, []):
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return False


def compute(lab) -> Result:
    """802.1D's election over the switches' cables, from the consoles'
    settings: port roles and states, err-disabled ports (BPDU guard) and,
    with spanning tree off somewhere, the loops that forward."""
    res = Result(cables=cables(lab))
    tops = {s: top(lab, s) for s in devcli.switches(lab)}
    on = {s: vlan_on(lab, s) for s in tops}
    cabs = [c for c in res.cables if tops.get(c.a.sw) == tops.get(c.b.sw)]
    for s in tops:
        res.bridges[s] = Bridge(s, on[s], mode(lab, s), bridge_id(lab, s))
    # BPDU guard: a guarded port that hears a BPDU is err-disabled (and
    # stays so until shutdown / no shutdown, the record "stp-err:<port>").
    err = {e for c in cabs for e in c.ends() if _own(lab, e.sw).get(f"stp-err:{e.port}")}
    while True:
        live = [c for c in cabs if not any(e in err or shut(lab, e) for e in c.ends())]
        new = {e for c in live for e in c.ends()
               if guarded(lab, e.sw, e.port, True) and _bpdu_in(lab, e, c, live, on)}
        if new <= err:
            break
        err |= new
    res.err = err
    for c in res.cables:
        for e in c.ends():
            st = PortState(e, c.id, c.far(e), cost=port_cost(lab, e), pid=port_id(lab, e),
                           edge=edge(lab, e.sw, e.port, True), guard=guarded(lab, e.sw, e.port, True))
            if e in err:
                st.state = "err"
            elif c not in live:
                st.state = "down"
            res.ports[e] = st
    from . import etherchannel  # a channel's cables are one port; a misconfigured channel is err-disabled
    live, twins = etherchannel.fold(lab, res, live)
    # LANs: a cable is one; a switch with spanning tree off is a hub that
    # joins every cable it has into one (it floods BPDUs like any frame).
    uf = _UF()
    for c in live:
        uf.union(c.a, c.b)
    for s, is_on in on.items():
        mine = [e for c in live for e in c.ends() if e.sw == s]
        if not is_on:
            for e in mine[1:]:
                uf.union(mine[0], e)
    lans: dict = {}
    for c in live:
        for e in c.ends():
            if on[e.sw]:
                lans.setdefault(uf.find(e), []).append(e)
    # Bridges that hear each other, and their root: the lowest bridge id.
    graph: dict[str, set] = {s: set() for s in tops if on[s]}
    for ends in lans.values():
        for x in ends:
            graph[x.sw].update(y.sw for y in ends)
    done: set = set()
    for s in sorted(graph):
        if s in done:
            continue
        comp, todo = {s}, [s]
        while todo:
            for n in graph[todo.pop()]:
                if n not in comp:
                    comp.add(n)
                    todo.append(n)
        done |= comp
        _elect(lab, res, comp, {k: v for k, v in lans.items() if v[0].sw in comp})
    etherchannel.unfold(res, twins)
    # Loops: cables that forward at both ends and close a circle.
    fwd = [c for c in live if all(res.ports[e].state == "FWD" for e in c.ends())]
    for c in fwd:
        rest = [d for d in fwd if d.id != c.id]
        if _joined(rest, c.a.sw, c.b.sw):
            res.loop.append(c.id)
    res.storm = sorted({e.sw for c in fwd if c.id in res.loop for e in c.ends()})
    for s in res.storm:
        res.bridges[s].cpu = 99
    return res


def _joined(cabs: list[Cable], a: str, b: str) -> bool:
    adj: dict[str, set] = {}
    for c in cabs:
        adj.setdefault(c.a.sw, set()).add(c.b.sw)
        adj.setdefault(c.b.sw, set()).add(c.a.sw)
    todo, seen = [a], {a}
    while todo:
        s = todo.pop()
        if s == b:
            return True
        for n in adj.get(s, ()):
            if n not in seen:
                seen.add(n)
                todo.append(n)
    return False


def _elect(lab, res: Result, comp: set, lans: dict) -> None:
    br = res.bridges
    root = min(comp, key=lambda s: br[s].bid)
    dist = {s: None for s in comp}
    dist[root] = 0
    # Dijkstra: crossing a LAN into a bridge costs that bridge's port.
    left = set(comp)
    while left:
        s = min((x for x in left if dist[x] is not None), key=lambda x: (dist[x], br[x].bid), default=None)
        if s is None:
            break
        left.discard(s)
        for ends in lans.values():
            if not any(e.sw == s for e in ends):
                continue
            for e in ends:
                if e.sw != s:
                    d = dist[s] + res.ports[e].cost
                    if dist[e.sw] is None or d < dist[e.sw]:
                        dist[e.sw] = d
    vec = lambda e: (dist[e.sw], br[e.sw].bid, res.ports[e].pid)  # noqa: E731
    desig = {k: min(ends, key=vec) for k, ends in lans.items()}
    lan_of = {e: k for k, ends in lans.items() for e in ends}
    for s in comp:
        b = br[s]
        b.root, b.root_bid, b.cost = root, br[root].bid, dist[s] or 0
        if s == root:
            continue
        cands = []
        for e, k in lan_of.items():
            d = desig[k]
            if e.sw == s and d.sw != s:
                cands.append(((dist[d.sw] + res.ports[e].cost, br[d.sw].bid, res.ports[d].pid,
                               res.ports[e].pid), e))
        if cands:
            b.root_port = min(cands)[1].port
    for e, k in lan_of.items():
        p = res.ports[e]
        if desig[k] == e:
            p.role = "desg"
        elif br[e.sw].root_port == e.port:
            p.role = "root"
        else:
            p.role = "back" if desig[k].sw == e.sw else "altn"
            p.state = "BLK"


def cut_off(lab, sw: str) -> bool:
    """Whether a switch's uplink trunk is down (shut, or err-disabled by BPDU
    guard) with no other cable leading round to the switch above: then its
    VLANs are networks of their own (Lab.segment_id)."""
    if not any(k.startswith(("shut:Gigabit", "stp-err:", "stp-guard", "ec-err:", "po-shut:")) for d in lab.devices.values() for k in d):
        return False
    up = devcli.upstream(lab, sw)
    if up not in lab.networks:
        return False
    res = compute(lab)
    live = [c for c in res.cables if all(res.ports[e].state not in ("down", "err") for e in c.ends())]
    return not _joined(live, sw, up)


def refresh(lab) -> list[str]:
    """Records the ports BPDU guard has just err-disabled (they stay so until
    shutdown / no shutdown), and says what each switch logs about it."""
    out = []
    for e in compute(lab).err:
        own = lab.devices.setdefault(f"sw:{e.sw}", {})
        if not own.get(f"stp-err:{e.port}"):
            own[f"stp-err:{e.port}"] = "yes"
            short = devcli.short_if(e.port)
            out.append(f"{devcli.hostname(lab, 'sw:' + e.sw)}: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on "
                       f"port {short} with BPDU Guard enabled. Disabling port.\n"
                       f"%PM-4-ERR_DISABLE: bpduguard error detected on {short}, putting {short} in "
                       f"err-disable state")
    from . import etherchannel  # EtherChannel misconfiguration guard (channel-misconfig)
    return out + etherchannel.refresh(lab)


def forget(lab, sw: str) -> None:
    """A switch taken off the canvas takes its spare cables with it."""
    for d in [d for k, d in lab.devices.items() if k.startswith("sw:")]:
        d.pop(f"xcable:{sw}", None)


# ------------------------------------------------------------------ the router
def native_vid(plan) -> int:
    """The VLAN the bridges' BPDUs travel in between the switch bridges
    (untagged on their ports): one no segment uses."""
    used = {s.vid for s in plan.segments.values()}
    return next(v for v in range(4094, 1, -1) if v not in used)


def render(plan, reset: bool = False) -> list[str]:
    """The switch bridges on the router: shell for its start script, or to
    rebuild them while it runs (reset)."""
    lab = plan.lab
    groups = trees(lab)
    if not groups and not reset:
        return []
    out = ["### switches cabled to switches: a kernel bridge each, spanning tree on them (winlab/stp.py)",
           "# pvst switches: the kernel's 802.1D; rapid-pvst switches: RSTP in mstpd when it is on the router "
           "(winlab/mstpd.py), else 802.1D with a 4 s forward delay. One tree for every VLAN (VLAN 1's settings).",
           f"# Every veth is capped ({STORM_RATE}; {INTO_LAB_RATE} back into {plan_bridge()}): a loop "
           f"with spanning tree off floods for real, but slowly enough to keep the PC usable.",
           "for i in $(ls /sys/class/net 2>/dev/null | grep '^stp'); do ip link del $i 2>/dev/null; done; true"]
    res = compute(lab)
    idx = {s: i for i, s in enumerate(devcli.switches(lab), 1)}
    native = native_vid(plan)
    fast = [s for _, members in groups for s in members if res.bridges[s].on and res.bridges[s].mode in FAST]
    out += _rstp_start([f"stp{idx[s]}" for s in fast])
    bonds: dict[str, dict[str, str]] = {}
    # Ports BPDU guard err-disabled on a rapid-pvst switch: mstpd enforces the
    # guard itself, so it gets the BPDU (the far end up, unless shut there).
    by_mstpd: dict[End, str] = {}
    for e in res.err:
        if e.sw in fast and _own(lab, e.sw).get(f"stp-err:{e.port}"):
            by_mstpd[e] = "BPDU guard, which mstpd enforces on the first BPDU"
            far = res.ports[e].far
            if not shut(lab, far) and far not in res.err:
                by_mstpd[far] = f"the far end of {e.sw} {devcli.short_if(e.port)}, err-disabled by BPDU guard in mstpd"
    for tp, members in groups:
        vids = sorted({plan.segment_of(n.id).vid for s in members for n in devcli.vlans_of(lab, s)})
        out.append(f"# tree under {tp}: {', '.join(members)}; VLANs {', '.join(map(str, vids))}")
        links: list[str] = []   # the ports' links, set once mstpd has the bridges (BPDU guard sees the first BPDU)
        for s in members:
            br, b = f"stp{idx[s]}", res.bridges[s]
            out += [f"ip link add {br} type bridge vlan_filtering 1 vlan_default_pvid 0 "
                    f"stp_state {1 if b.on else 0} priority {b.bid[0]} "
                    f"forward_delay {FORWARD_DELAY[b.mode] * 100} hello_time {HELLO * 100} "
                    f"max_age {MAX_AGE * 100} || true",
                    f"ip link set dev {br} address {b.bid[1]} alias {s} || true",
                    f"ip link set {br} type bridge mcast_snooping 0 2>/dev/null || true",
                    f"ip link set {br} up"]
        tree_cabs = [c for c in res.cables if c.a.sw in members and c.b.sw in members]
        for c in tree_cabs:
            out.append(f"ip link add {_if(idx, c.a)} type veth peer name {_if(idx, c.b)} || true"
                       f"   # {c.a.sw} {devcli.short_if(c.a.port)} - {c.b.sw} {devcli.short_if(c.b.port)}")
        for s in members:
            br = f"stp{idx[s]}"
            from . import etherchannel  # channels that formed: a bond of their cables, one bridge port
            pre, bonded, post = etherchannel.render_switch(lab, s, idx[s], res, br, native, vids)
            bonds[s] = bonded
            out += pre
            for e, c in ports_of(lab, s, tree_cabs):
                p, dev = res.ports[e], _if(idx, e)
                if e.port in bonded and p.state not in ("down", "err"):
                    out += etherchannel.member_lines(dev, bonded[e.port], STORM_RATE)
                    continue
                out += [f"ip link set {dev} master {br}",
                        f"bridge vlan add dev {dev} vid {native} pvid untagged"]
                out += [f"bridge vlan add dev {dev} vid {v}" for v in vids]
                out += [f"bridge link set dev {dev} cost {p.cost} priority {p.pid[0] // 4}"
                        + (" guard on" if p.guard else "") + " 2>/dev/null || true",
                        f"tc qdisc replace dev {dev} root tbf rate {STORM_RATE} burst 8kb latency 100ms || true"]
                if e in by_mstpd:
                    # BPDU guard in mstpd: both ends up, and mstpd shuts the guarded one itself on the
                    # first BPDU from the far end; without mstpd the kernel's link down stands in.
                    links.append(f'if [ -n "$wl_mstpd" ]; then ip link set {dev} up; else ip link set {dev} down; fi'
                                 f"   # {p.state}: {by_mstpd[e]}")
                else:
                    links.append(f"ip link set {dev} {'down' if p.state in ('down', 'err') else 'up'}"
                                 + (f"   # {p.state}" if p.state in ("down", "err") else ""))
            out += post
        i = idx[tp]
        out += [f"# {tp}'s machines' frames come in from the router's bridge here",
                f"ip link add stp{i}fa type veth peer name stp{i}lab || true",
                f"ip link set stp{i}fa master stp{i}", f"ip link set stp{i}lab master {plan_bridge()}"]
        for dev in (f"stp{i}fa", f"stp{i}lab"):
            out += [f"bridge vlan add dev {dev} vid {v}" for v in vids]
        out += [f"tc qdisc replace dev stp{i}fa root tbf rate {INTO_LAB_RATE} burst 8kb latency 100ms || true",
                f"tc qdisc replace dev stp{i}lab root tbf rate {STORM_RATE} burst 8kb latency 100ms || true"]
        for s in members:
            if s in fast:
                out += _rstp_bridge(lab, s, idx, res, tree_cabs, bonds.get(s, {}), fa=(s == tp))
        out += links + [f"ip link set stp{i}fa up", f"ip link set stp{i}lab up"]
    from . import etherchannel  # PAgP: winlab's own speaker on the desirable and auto ports
    out += etherchannel.pagp_lines(plan, reset)
    out.append("")
    return out


def _rstp_start(bridges: list[str]) -> list[str]:
    """mstpd onto the router and running, and the bridges it is to take,
    before the bridges are made (the kernel asks /sbin/bridge-stp as each
    one's spanning tree goes on). With no rapid-pvst switch: the list emptied,
    so every bridge keeps the kernel's 802.1D."""
    from . import mstpd
    if not bridges:
        return [f"rm -f {mstpd.RSTP_LIST}"]
    return (["# rapid-pvst: rapid spanning tree (802.1w) in mstpd, from the repository volume when it was "
             "fetched (winlab/mstpd.py)"]
            + mstpd.router_lines()
            + [f'if [ -n "$wl_mstpd" ]; then pidof mstpd >/dev/null 2>&1 || {{ {mstpd.MSTPD}; sleep 0.5; }}; '
               f"printf '%s\\n' {' '.join(bridges)} > {mstpd.RSTP_LIST}; "
               f"else rm -f {mstpd.RSTP_LIST}; echo 'winlab: mstpd is not on the router: rapid-pvst runs as "
               f"802.1D with a {FORWARD_DELAY['rapid-pvst']} s forward delay' > /dev/kmsg 2>/dev/null; fi"])


def _rstp_bridge(lab, sw: str, idx: dict, res: Result, cabs: list[Cable], bonded: dict[str, str],
                 fa: bool) -> list[str]:
    """One rapid-pvst switch's bridge handed to mstpd and set as the console
    says: RSTP, the bridge priority, and per port its cost, priority, PortFast
    (an admin edge port) and BPDU guard. Only when the kernel did hand it
    over (stp_state 2); otherwise the kernel's 802.1D keeps it."""
    from . import mstpd
    i, m, b = idx[sw], mstpd.MSTPCTL, res.bridges[sw]
    br = f"stp{i}"
    out = [f'if [ -n "$wl_mstpd" ] && [ "$(cat /sys/class/net/{br}/bridge/stp_state 2>/dev/null)" = 2 ]; then'
           f"   # {sw}: {b.mode}",
           f"  {m} addbridge {br} || true",
           f"  {m} setforcevers {br} {'mstp' if b.mode == 'mst' else 'rstp'} || true",
           f"  {m} settreeprio {br} 0 {b.bid[0] // 4096} || true"]
    if b.mode == "mst":
        from . import mst  # the region: name, revision, instances and their VLANs, their priorities
        out += [f"  {line}" for line in mst.mstpctl_lines(lab, sw, m, br)]
    seen = set()
    for e, _c in ports_of(lab, sw, cabs):
        p = res.ports[e]
        dev = bonded.get(e.port) or _if(idx, e)
        if dev in seen:
            continue
        seen.add(dev)
        out += [f"  {m} setportp2p {br} {dev} yes || true",
                f"  {m} setportpathcost {br} {dev} {p.cost} || true",
                f"  {m} settreeportprio {br} {dev} 0 {p.pid[0] // 16} || true",
                f"  {m} setportadminedge {br} {dev} {'yes' if p.edge else 'no'} || true",
                f"  {m} setbpduguard {br} {dev} {'yes' if p.guard else 'no'} || true"]
    if fa:
        # The way into the router's bridge, where the machines are: no switch speaks there.
        out += [f"  {m} setportp2p {br} stp{i}fa yes || true", f"  {m} setportadminedge {br} stp{i}fa yes || true"]
    return out + ["fi"]


def plan_bridge() -> str:
    from .netplan import BRIDGE
    return BRIDGE


def _if(idx: dict, e: End) -> str:
    return f"stp{idx[e.sw]}g{gi_no(e.port)}"


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


LIVE_CMD = ("echo '#stp'; for d in /sys/class/net/stp*; do n=${d##*/}; "
            "if [ -d $d/bridge ]; then echo \"B $n $(cat $d/bridge/stp_state) $(cat $d/bridge/bridge_id) "
            "$(cat $d/bridge/root_id)\"; for p in $d/brif/*; do [ -e $p/state ] && "
            "echo \"P $n ${p##*/} $(cat $p/state)\"; done; "
            # A bridge mstpd runs (stp_state 2): its protocol, and each port as mstpctl reports it.
            "if [ \"$(cat $d/bridge/stp_state)\" = 2 ] && [ -x /usr/local/sbin/mstpctl ]; then "
            "echo \"M $n $(/usr/local/sbin/mstpctl showbridge $n force-protocol-version 2>/dev/null)\"; "
            "for p in $d/brif/*; do q=${p##*/}; echo \"R $n $q $(/usr/local/sbin/mstpctl showportparams $n $q "
            "enabled role state bpdu-guard-error oper-edge-port 2>/dev/null | tr '\\n' ' ')\"; done; fi; "
            "else echo \"T $n $(cat $d/statistics/tx_packets)\"; "
            "fi; done; echo \"C $(head -n 1 /proc/stat)\"")


def parse_live(text: str) -> dict:
    """LIVE_CMD's lines: bridges (stp_state, own and root id), port states
    by veth, packets sent by veth, and the router's CPU counters."""
    out = {"bridges": {}, "ports": {}, "tx": {}, "cpu": [], "rstp": {}, "roles": {}}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "M":
            out["rstp"][parts[1]] = parts[2]          # force-protocol-version: rstp (or stp, mstp)
        elif len(parts) == 8 and parts[0] == "R":
            # mstpctl showportparams: enabled role state bpdu-guard-error oper-edge-port
            out["roles"][parts[2]] = {"bridge": parts[1], "enabled": parts[3] == "yes", "role": parts[4],
                                      "state": parts[5], "guard_err": parts[6] == "yes", "edge": parts[7] == "yes"}
        elif len(parts) >= 5 and parts[0] == "B":
            out["bridges"][parts[1]] = {"on": parts[2] != "0", "id": parts[3], "root": parts[4]}
        elif len(parts) == 4 and parts[0] == "P":
            out["ports"][parts[2]] = _STATES.get(parts[3], parts[3])
        elif len(parts) == 3 and parts[0] == "T" and parts[2].isdigit():
            out["tx"][parts[1]] = int(parts[2])
        elif len(parts) > 4 and parts[0] == "C" and parts[1] == "cpu":
            out["cpu"] = [int(x) for x in parts[2:] if x.isdigit()]
    return out


def ifnames(lab) -> dict[str, str]:
    """Each switch end's veth on the router: "<sw> <port>" -> stp<N>g<P>."""
    idx = {s: i for i, s in enumerate(devcli.switches(lab), 1)}
    return {f"{e.sw} {e.port}": _if(idx, e) for c in cables(lab) for e in c.ends()}


# ------------------------------------------------------------------ the canvas
def view(lab) -> dict:
    """The switch-to-switch cables with their ends' roles and states, each
    switch's spanning tree, and a storm when a loop forwards."""
    res = compute(lab)
    if not res.cables:
        return {"cables": [], "switches": {}, "storm": None, "drill": drill_view(lab)}
    names = ifnames(lab)

    def end(e: End) -> dict:
        p = res.ports[e]
        return {"sw": e.sw, "port": devcli.short_if(e.port), "role": p.role, "state": p.state,
                "iface": names.get(f"{e.sw} {e.port}", "")}
    cabs = [{"id": c.id, "kind": c.kind, "a": end(c.a), "b": end(c.b), "loop": c.id in res.loop}
            for c in res.cables]
    sws = {s: {"on": b.on, "mode": b.mode, "priority": b.bid[0], "root": bool(b.on and b.root == s),
               "root_sw": b.root, "cpu": b.cpu, "cost": b.cost, "root_port": devcli.short_if(b.root_port)}
           for s, b in res.bridges.items() if any(e.sw == s for c in res.cables for e in c.ends())}
    storm = None
    if res.loop:
        storm = {"switches": res.storm, "cables": res.loop, "cap": CAP_TEXT,
                 "off": [s for s in res.storm if not res.bridges[s].on]}
    return {"cables": cabs, "switches": sws, "storm": storm, "drill": drill_view(lab)}


# ------------------------------------------------------------------ actions
class StpError(Exception):
    pass


def act(dash, action: str, params: dict) -> dict:
    try:
        if action == "wb-stp-cable":
            return _cable(dash, str(params.get("a", "")), str(params.get("b", "")))
        if action == "wb-stp-unplug":
            return _unplug(dash, str(params.get("id", "")))
        if action == "wb-stp-live":
            return live(dash)
        if action == "wb-stp-drill":
            return drill(dash, str(params.get("op", "")), params)
    except StpError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown spanning-tree action {action!r}"}


def _cable(dash, a: str, b: str) -> dict:
    """A spare cable from a free gigabit port of one switch into another."""
    from .workbench import _save, _sync
    lab = dash.lab
    sws = devcli.switches(lab)
    if a not in sws or b not in sws:
        raise StpError("drop the cable on another switch")
    if a == b:
        raise StpError("a cable from a switch back into itself: winlab keeps both ends on two switches")
    if top(lab, a) != top(lab, b):
        raise StpError(f"{a} and {b} are not in one switched network: cable one's uplink (Gi0/1) "
                       f"into the other first")
    for s in (a, b):
        if free_gig(lab, s) < 1:
            raise StpError(f"{s} has no free gigabit port (Gi0/2 to Gi0/{devcli.GIG_PORTS})")
    x, y = sorted((a, b))
    own = lab.devices.setdefault(f"sw:{x}", {})
    own[f"xcable:{y}"] = str(int(own.get(f"xcable:{y}") or 0) + 1)
    said = refresh(lab)
    _save(dash)
    res = compute(lab)
    c = [c for c in res.cables if c.kind == "extra" and {c.a.sw, c.b.sw} == {x, y}][-1]
    pa, pb = (c.a, c.b) if c.a.sw == a else (c.b, c.a)
    msg = f"{a} {devcli.short_if(pa.port)} to {b} {devcli.short_if(pb.port)} (trunk)"
    if c.id in res.loop:
        msg += ": a loop, and spanning tree is off on " + ", ".join(
            s for s in res.storm if not res.bridges[s].on) + " - a broadcast storm when the network runs"
    else:
        blocked = [p for p in res.ports.values() if p.state == "BLK"]
        if blocked:
            msg += ": a loop; spanning tree blocks " + ", ".join(
                f"{p.end.sw} {devcli.short_if(p.end.port)}" for p in blocked)
    return {"ok": True, "message": msg + "".join("; " + x.split("\n")[0] for x in said) + _sync(dash)}


def _unplug(dash, cid: str) -> dict:
    from .workbench import _save, _sync
    lab = dash.lab
    m = re.match(r"^x:([^:]+):([^:]+):\d+$", cid)
    if not m:
        raise StpError("that is not a spare cable between two switches (an uplink comes out by its own menu)")
    x, y = m.groups()
    own = lab.devices.get(f"sw:{x}", {})
    n = int(own.get(f"xcable:{y}") or 0)
    if n < 1:
        raise StpError("no such cable")
    if n == 1:
        own.pop(f"xcable:{y}", None)
    else:
        own[f"xcable:{y}"] = str(n - 1)
    _save(dash)
    return {"ok": True, "message": f"cable between {x} and {y} pulled out{_sync(dash)}"}


def live(dash) -> dict:
    """The kernel's own spanning tree on the running router."""
    from .workbench import _running
    lab = dash.lab
    if "fabric" not in _running(lab.name):
        return {"ok": False, "message": "the router is off"}
    from .cli import _fabric_runner
    run, why = _fabric_runner(lab.name)
    if not run:
        return {"ok": False, "message": why}
    try:
        text = run(LIVE_CMD, timeout=15)
    except Exception as exc:  # the serial channel: any failure is "not now"
        return {"ok": False, "message": str(exc)}
    finally:
        close = getattr(run, "close", None)
        if close:
            close()
    return {"ok": True, "t": time.time(), **parse_live(text)}


# ------------------------------------------------------------------ drills
# Graded faults in the manner of winlab/faults.py: a fault is put into the
# user's own network without a word, the canvas and the consoles show its
# symptom, a hint ladder leads to it, and Check my fix proves it gone.
def _pt(text: str) -> str:
    """A drill text in the desktop's language (content/i18n/content/<lang>/problems.json)."""
    from .content import problem_text
    return problem_text(text)


@dataclass(frozen=True)
class Drill:
    id: str
    title: str
    teaches: str
    symptom: str
    hints: tuple[str, ...]
    fix: str


DRILLS: dict[str, Drill] = {}


def _d(d: Drill) -> None:
    DRILLS[d.id] = d


_d(Drill("loop", "A second cable made a loop, and spanning tree is off",
         "how a loop becomes a broadcast storm, why one switch running spanning tree on the loop is "
         "enough to stop it, and reading show spanning-tree",
         "the network crawls or stops; the switches' CPUs are at 99%; ping loses most replies",
         ("Something floods. Look at the cables between the switches, and on each switch's console run "
          "show processes cpu: a switch busy forwarding the same frames again and again is in a loop.",
          "{a} and {b} have two cables between them (show cdp neighbors on {a}), and show spanning-tree "
          "on both says the instance for VLAN 1 does not exist: nothing blocks the second path.",
          "Turn spanning tree back on: on {a} (or {b}) type configure terminal, then spanning-tree vlan 1. "
          "Or pull the second cable out ({a} {pa})."),
         "spanning tree back on (spanning-tree vlan 1), or the spare cable out"))
_d(Drill("guard", "BPDU guard on an uplink",
         "what BPDU guard is for (ports to machines, never to switches), err-disabled ports and how they "
         "come back",
         "every machine on {a} reaches the others on {a} but nothing beyond it",
         ("The machines on one switch reach each other and nothing else. Look at that switch's uplink: "
          "show interfaces status on {a}.",
          "{a}'s {pa} is err-disabled: show spanning-tree interface lists it, and the log said "
          "%PM-4-ERR_DISABLE: bpduguard error detected. BPDU guard shuts a port the moment a switch "
          "speaks on it; on an uplink, one always does.",
          "On {a}: configure terminal, interface {pa_long}, no spanning-tree bpduguard, then shutdown "
          "and no shutdown to bring the port back."),
         "no spanning-tree bpduguard on the uplink, then shutdown and no shutdown"))


def _drill_path(lab_name: str):
    return paths.lab_dir(lab_name) / "stp-drill.json"


def drill_state(lab_name: str) -> dict | None:
    try:
        return json.loads(_drill_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _drill_save(lab_name: str, data: dict | None) -> None:
    state.save_json(_drill_path(lab_name), data)


def _words(lab, d: dict) -> dict:
    host = lambda s: devcli.hostname(lab, f"sw:{s}")  # noqa: E731
    return {"a": host(d["a"]), "b": host(d["b"]), "pa": devcli.short_if(d.get("pa", "")),
            "pa_long": d.get("pa", "")}


def drill_view(lab) -> dict | None:
    d = drill_state(lab.name)
    if not d:
        return None
    k = DRILLS[d["id"]]
    w = _words(lab, d)
    return {"id": k.id, "shown": int(d.get("hints", 0)), "of": len(k.hints),
            "hints": [_pt(h).format(**w) for h in k.hints[:int(d.get("hints", 0))]],
            "symptom": _pt(k.symptom).format(**w), "done": bool(d.get("done")),
            "title": _pt(k.title) if d.get("done") else "", "fix": _pt(k.fix) if d.get("done") else ""}


def drill(dash, op: str, params: dict, runner=None) -> dict:
    from .workbench import _save, _sync
    lab = dash.lab
    d = drill_state(lab.name)
    if op == "start":
        if d and not d.get("done"):
            raise StpError("a fault is already hidden in this network: find it, or give up")
        return _drill_start(dash, str(params.get("id") or "") or random.choice(sorted(DRILLS)))
    if not d:
        raise StpError("no spanning-tree fault in this network")
    k = DRILLS[d["id"]]
    if op == "hint":
        d["hints"] = min(len(k.hints), int(d.get("hints", 0)) + 1)
        _drill_save(lab.name, d)
        return {"ok": True, "message": _pt(k.hints[d["hints"] - 1]).format(**_words(lab, d))}
    if op == "check":
        res = check(lab, d, runner)
        if res["passed"]:
            d["done"] = True
            _drill_save(lab.name, d)
        return res
    if op in ("undo", "close"):
        if op == "undo" and not d.get("done"):
            for k_, v in d.get("was", {}).items():
                sw, key = k_.split("|", 1)
                own = lab.devices.setdefault(f"sw:{sw}", {})
                if v is None:
                    own.pop(key, None)
                else:
                    own[key] = v
            lab.devices.get(f"sw:{d['a']}", {}).pop(f"stp-err:{d.get('pa', '')}", None)
            _save(dash)
            _drill_save(lab.name, None)
            return {"ok": True, "message": f"put back: it was {_pt(k.title).lower()}{_sync(dash)}"}
        _drill_save(lab.name, None)
        return {"ok": True, "message": ""}
    raise StpError(f"unknown drill step {op!r}")


def _drill_start(dash, did: str) -> dict:
    from .workbench import _save, _sync
    lab = dash.lab
    if did not in DRILLS:
        raise StpError(f"no drill {did!r}")
    pairs = [(s, devcli.upstream(lab, s)) for s in devcli.switches(lab)
             if devcli.upstream(lab, s) in lab.networks]
    if not pairs:
        raise StpError("build two switches first, one's uplink (Gi0/1) cabled into the other")
    a, b = random.choice(sorted(pairs))
    was: dict = {}

    def put(sw, key, val):
        own = lab.devices.setdefault(f"sw:{sw}", {})
        was.setdefault(f"{sw}|{key}", own.get(key))
        if val is None:
            own.pop(key, None)
        else:
            own[key] = val
    if did == "loop":
        if free_gig(lab, a) < 1 or free_gig(lab, b) < 1:
            raise StpError(f"{a} or {b} has no free gigabit port for a second cable")
        x, y = sorted((a, b))
        put(x, f"xcable:{y}", str(int(_own(lab, x).get(f"xcable:{y}") or 0) + 1))
        put(a, "stp-off:1", "yes")
        put(b, "stp-off:1", "yes")
        c = [c for c in cables(lab) if c.kind == "extra" and {c.a.sw, c.b.sw} == {a, b}][-1]
        pa = (c.a if c.a.sw == a else c.b).port
    else:
        pa = GI1
        put(a, f"stp-guard:{GI1}", "yes")
        put(b, "stp-off:1", None)
        put(a, "stp-off:1", None)
    refresh(lab)
    _save(dash)
    _drill_save(lab.name, {"id": did, "a": a, "b": b, "pa": pa, "was": was, "hints": 0,
                           "at": int(time.time())})
    return {"ok": True, "message": "something in the switches is broken; find it with the canvas and the "
                                   "consoles, then Check my fix" + _sync(dash)}


def check(lab, d: dict, runner=None) -> dict:
    """Check my fix: the network as the lab file has it, and, while the
    router runs, the kernel's own counters (no cable floods)."""
    res = compute(lab)
    w = _words(lab, d)
    rows = []
    if d["id"] == "loop":
        rows.append(("no loop forwards: spanning tree blocks the spare path, or it is gone", not res.loop))
    else:
        e = End(d["a"], GI1)
        p = res.ports.get(e)
        rows.append((f"BPDU guard is off on {w['a']}'s uplink",
                     not guarded(lab, d["a"], GI1, True)))
        rows.append((f"{w['a']}'s uplink forwards again", p is not None and p.state in ("FWD", "BLK")))
    if runner is not None and d["id"] == "loop":
        rows.append(("the router's switch bridges are quiet (kernel counters)", not storming(runner)))
    passed = all(ok for _, ok in rows)
    k = DRILLS[d["id"]]
    msg = (f"fixed: it was {_pt(k.title).lower()}. The fix: {_pt(k.fix)}." if passed else
           "not yet: " + "; ".join(t for t, ok in rows if not ok))
    return {"ok": True, "passed": passed, "message": msg,
            "results": [{"check": t, "passed": ok} for t, ok in rows]}


def storming(runner, gap: float = 1.0) -> bool:
    """Two reads of the veths' counters a moment apart: any cable sending
    more than STORM_PPS frames a second is flooding."""
    a = parse_live(runner(LIVE_CMD, timeout=15))["tx"]
    time.sleep(gap)
    b = parse_live(runner(LIVE_CMD, timeout=15))["tx"]
    return any((b.get(k, 0) - v) / gap > STORM_PPS for k, v in a.items())


# ------------------------------------------------------------------ the console
# The switch's command line (winlab/devcli.py) gets these; `con` is its
# Console, whose mode and interface (s.ctx) the commands work in.
def add_specs(con, add, U, C, I) -> None:
    add("show spanning-tree", lambda a: show(con), "Spanning tree topology", U)
    add("show spanning-tree vlan <num>", lambda a: show(con, a[0]), "VLAN Switch Spanning Trees", U)
    add("show spanning-tree summary", lambda a: show_summary(con), "Summary of port states", U)
    add("show spanning-tree interface <line>", lambda a: show_iface(con, a[0]), "Spanning Tree interface status", U)
    add("show processes cpu", lambda a: show_cpu(con), "CPU utilization", U)
    add("spanning-tree mode <line>", lambda a: set_mode(con, a[0]), "Spanning tree operating mode", C)
    add("spanning-tree vlan <line>", lambda a: set_vlan(con, a[0], True), "VLAN Switch Spanning Tree", C)
    add("no spanning-tree vlan <line>", lambda a: set_vlan(con, a[0], False), "Negate a command or set its defaults", C)
    add("spanning-tree portfast default", lambda a: _global(con, "stp-edge-default", True),
        "Enable portfast by default on all access ports", C)
    add("no spanning-tree portfast default", lambda a: _global(con, "stp-edge-default", False),
        "Negate a command or set its defaults", C)
    add("spanning-tree portfast bpduguard default", lambda a: _global(con, "stp-guard-default", True),
        "Enable bpdu guard by default on all portfast ports", C)
    add("no spanning-tree portfast bpduguard default", lambda a: _global(con, "stp-guard-default", False),
        "Negate a command or set its defaults", C)
    add("spanning-tree portfast", lambda a: set_edge(con, ""), "Enable an interface to move directly to forwarding on link up", I)
    add("spanning-tree portfast <line>", lambda a: set_edge(con, a[0]), "Enable an interface to move directly to forwarding on link up", I)
    add("no spanning-tree portfast", lambda a: set_edge(con, "disable"), "Negate a command or set its defaults", I)
    add("spanning-tree bpduguard <line>", lambda a: set_guard(con, a[0]), "Don't accept BPDUs on this interface", I)
    add("no spanning-tree bpduguard", lambda a: set_guard(con, ""), "Negate a command or set its defaults", I)
    add("spanning-tree cost <num>", lambda a: set_port(con, "cost", a[0]), "Change an interface's spanning tree port path cost", I)
    add("no spanning-tree cost", lambda a: set_port(con, "cost", ""), "Negate a command or set its defaults", I)
    add("spanning-tree port-priority <num>", lambda a: set_port(con, "pri", a[0]), "Change an interface's spanning tree port priority", I)
    add("no spanning-tree port-priority", lambda a: set_port(con, "pri", ""), "Negate a command or set its defaults", I)
    from . import mst  # spanning-tree mode mst: the region, the instances, show spanning-tree mst
    mst.add_specs(con, add, U, C)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def _done(con, live: bool = True) -> str:
    """Saves (and pushes into the running router) a change, with what the
    switches log about it: ports BPDU guard err-disabled, a storm starting."""
    lab = con.lab
    try:   # the change is already in con.lab: the loop before it is the saved file's
        from .schema import load
        before = set(compute(load(lab.name)).loop)
    except Exception:  # a lab never saved: nothing looped before
        before = set()
    said = refresh(lab)
    note = con._save(live=live)
    res = compute(con.lab)
    if set(res.loop) - before:
        sws = ", ".join(devcli.hostname(con.lab, f"sw:{s}") for s in res.storm)
        said.append(f"%SW_MATM-4-MACFLAP_NOTIF: Host {_flap_mac(con.lab)} in vlan 1 is flapping between "
                    f"ports: a switching loop through {sws}\n% {CAP_TEXT}")
    return "\n".join(said + ([note.strip()] if note.strip() else []))


def _flap_mac(lab) -> str:
    from .netplan import compile_topology
    try:
        ports = compile_topology(lab, check_ports=False).links
    except Exception:  # a lab mid-edit: any address will do for the log line
        ports = []
    return devcli.dotted_mac(ports[0].mac) if ports else "0050.5600.0001"


def _tags(text: str) -> list[int]:
    out = []
    for part in text.replace(" ", "").split(","):
        m = re.match(r"^(\d+)(?:-(\d+))?$", part)
        if not m:
            raise devcli.CliError("% Invalid VLAN list: use 1, 10,20 or 1-5")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not 1 <= lo <= hi <= 4094:
            raise devcli.CliError("% VLAN ids are 1 to 4094")
        out += list(range(lo, hi + 1))
    return out


def set_mode(con, text: str) -> str:
    want = text.strip().lower()
    hit = [m for m in MODES + ("mst",) if m.startswith(want)] if want else []
    if want in MODES:
        hit = [want]
    if len(hit) != 1:
        raise devcli.CliError("% Invalid input: spanning-tree mode pvst | rapid-pvst | mst")
    own = _mine(con)
    if hit[0] == "pvst":
        own.pop("stp-mode", None)
    else:
        own["stp-mode"] = hit[0]
    out = _done(con)
    if hit[0] == "rapid-pvst":
        if rstp_ready():
            tail = f"% {RSTP_NOTE}: roles, edge ports and BPDU guard are mstpd's, read with show spanning-tree"
        else:
            tail = (f"% {KERNEL_NOTE} yet (winlab images prepare fabric fetches it once its build is published): "
                    f"rapid-pvst here is 802.1D with a {FORWARD_DELAY['rapid-pvst']} s forward delay")
        out = (out + "\n" if out else "") + tail
    elif hit[0] == "mst":
        from . import mst
        out = (out + "\n" if out else "") + mst.mode_note(con)
    return out


def set_vlan(con, text: str, on: bool) -> str:
    """spanning-tree vlan <list> [priority <n> | root primary|secondary]."""
    words = text.split()
    if not words:
        raise devcli.CliError("% Incomplete command.")
    tags, rest = _tags(words[0]), [w.lower() for w in words[1:]]
    own, lab, sw = _mine(con), con.lab, _sw(con)
    if not on:
        if rest and not "priority".startswith(rest[0]):
            raise devcli.CliError("% Invalid input: no spanning-tree vlan <list> [priority]")
        for t in tags:
            if rest:
                own.pop(f"stp-prio:{t}", None)
            else:
                own[f"stp-off:{t}"] = "yes"
    elif not rest:
        for t in tags:
            own.pop(f"stp-off:{t}", None)
    elif "priority".startswith(rest[0]) and len(rest) == 2:
        try:
            p = int(rest[1])
        except ValueError:
            raise devcli.CliError("% Invalid input: priority 0 to 61440, in steps of 4096") from None
        if not 0 <= p <= 61440 or p % 4096:
            raise devcli.CliError("% Bridge Priority must be in increments of 4096.\n% Allowed values are:\n  "
                                  + " ".join(str(4096 * i) for i in range(16)))
        for t in tags:
            own[f"stp-prio:{t}"] = str(p)
    elif "root".startswith(rest[0]) and len(rest) == 2 and rest[1] in ("primary", "secondary"):
        if rest[1] == "secondary":
            p = 28672
        else:
            b = compute(lab).bridges.get(sw)
            rp = b.root_bid[0] if b and b.root and b.root != sw else PRIORITY
            p = 24576 if rp > 24576 else max(0, rp - 4096)
        for t in tags:
            own[f"stp-prio:{t}"] = str(p)
    else:
        raise devcli.CliError("% Invalid input: spanning-tree vlan <list> [priority <n> | root primary | "
                              "root secondary]")
    out = _done(con)
    if 1 not in tags:
        out = (out + "\n" if out else "") + (f"% Kept for VLAN {','.join(map(str, tags))}; {note(lab, sw)}, "
                                             f"so VLAN 1's settings decide")
    return out


def _global(con, key: str, on: bool) -> str:
    if on:
        _mine(con)[key] = "yes"
    else:
        _mine(con).pop(key, None)
    out = _done(con)
    if on and key == "stp-edge-default":
        out = (out + "\n" if out else "") + ("%Warning: this command enables portfast by default on all "
                                             "interfaces. You should now disable portfast explicitly on "
                                             "switched ports leading to hubs, switches and bridges as they "
                                             "may create temporary bridging loops.")
    return out


def _port_key(con) -> tuple[str, bool]:
    """The interface being configured, as the settings name it: a gigabit
    port by its name, an access port by the machine cable in it (so it
    follows the cable, as the port's other settings do)."""
    ctx = con.s.ctx
    if ctx.startswith("GigabitEthernet"):
        return ctx, True
    link = con._port_link()
    return (link.label if link else ctx), False


_EDGE_WARN = ("%Warning: portfast should only be enabled on ports connected to a single host. Connecting "
              "hubs, concentrators, switches, bridges, etc... to this interface when portfast is enabled, "
              "can cause temporary bridging loops.\nUse with CAUTION")


def set_edge(con, how: str) -> str:
    key, gig = _port_key(con)
    how = how.strip().lower()
    own = _mine(con)
    if how in ("disable", "no"):
        own[f"stp-edge:{key}"] = "no"
        return _done(con, live=False)
    if how and not any(w.startswith(how) for w in ("edge", "trunk")):
        raise devcli.CliError("% Invalid input: spanning-tree portfast [edge | trunk | disable]")
    trunk = bool(how) and "trunk".startswith(how)
    if gig and not trunk:
        own[f"stp-edge:{key}"] = "yes"
        _done(con, live=False)
        return (f"{_EDGE_WARN}\n\n%Portfast has been configured on {con.s.ctx} but will only have effect "
                f"when the interface is in a non-trunking mode.")
    own[f"stp-edge:{key}"] = "trunk" if gig else "yes"
    out = _done(con, live=gig)
    if gig and mode(con.lab, _sw(con)) in FAST and rstp_ready():
        tail = (f"{_EDGE_WARN}\n\n%Portfast has been configured on {con.s.ctx}: an edge port in mstpd, "
                f"forwarding at once (a BPDU there makes it an ordinary port again)")
    elif gig:
        tail = (f"%Warning: portfast trunk on {con.s.ctx}: the switch lists it as an edge port, but "
                f"{KERNEL_NOTE} and the kernel's 802.1D has no edge ports, so the router still waits out "
                f"the forward delay (spanning-tree mode rapid-pvst makes it real once mstpd is fetched)")
    else:
        tail = f"{_EDGE_WARN}\n\n%Portfast has been configured on {con.s.ctx}."
    return (out + "\n" if out else "") + tail


def set_guard(con, how: str) -> str:
    key, gig = _port_key(con)
    how = how.strip().lower()
    own = _mine(con)
    if not how:
        own.pop(f"stp-guard:{key}", None)
    elif "enable".startswith(how):
        own[f"stp-guard:{key}"] = "yes"
    elif "disable".startswith(how):
        own[f"stp-guard:{key}"] = "no"
    else:
        raise devcli.CliError("% Invalid input: spanning-tree bpduguard enable | disable")
    return _done(con, live=gig)


def set_port(con, what: str, value: str) -> str:
    key, gig = _port_key(con)
    own = _mine(con)
    if not value:
        own.pop(f"stp-{what}:{key}", None)
        return _done(con, live=gig)
    try:
        n = int(value)
    except ValueError:
        raise devcli.CliError("% Invalid input: a number") from None
    if what == "cost" and not 1 <= n <= 200000000:
        raise devcli.CliError("% Port path cost 1 to 200000000")
    if what == "pri" and (not 0 <= n <= 240 or n % 16):
        raise devcli.CliError("% Port Priority in increments of 16 is required\n% Allowed values are:\n  "
                              + " ".join(str(16 * i) for i in range(16)))
    own[f"stp-{what}:{key}"] = str(n)
    return _done(con, live=gig)


def gi_shutdown(con, name: str, down: bool) -> str:
    """shutdown / no shutdown on a gigabit port: takes a switch-to-switch
    cable's link down (or brings it back), and no shutdown is what brings a
    port back from err-disabled."""
    lab, sw = con.lab, _sw(con)
    here = [p for p in compute(lab).of(sw) if p.end.port == name]
    if not here:
        if name == GI1 and devcli.uplinked(lab, sw):
            raise devcli.CliError("% The uplink to the router comes out on the canvas (drag it), or shut "
                                  "the router's port at the router")
        raise devcli.CliError(f"% nothing is cabled to {devcli.short_if(name)}")
    own = _mine(con)
    if down:
        own[f"shut:{name}"] = "yes"
    else:
        own.pop(f"shut:{name}", None)
        own.pop(f"stp-err:{name}", None)
    said = _done(con)
    if down:
        msg = f"%LINK-5-CHANGED: Interface {name}, changed state to administratively down"
    elif any(p.state == "err" for p in compute(con.lab).of(sw) if p.end.port == name):
        msg = ""
    else:
        msg = (f"%LINK-3-UPDOWN: Interface {name}, changed state to up\n"
               f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to up")
    return "\n".join(x for x in (msg, said) if x)


# ---- show
def _live_read(con) -> dict:
    """LIVE_CMD's answer from the running router (parse_live), or {}."""
    if not con.powered():
        return {}
    try:
        data = parse_live(con._on_router(LIVE_CMD, timeout=15))
    except devcli.CliError:
        return {}
    return data if data["bridges"] or data["ports"] else {}


def _live_states(con, data: dict | None = None) -> dict[str, str]:
    """The kernel's port states, by "<sw> <port>", when the router runs."""
    data = _live_read(con) if data is None else data
    if not data:
        return {}
    names = ifnames(con.lab)
    return {k: data["ports"][v] for k, v in names.items() if v in data["ports"]}


def _rstp_live(con, data: dict) -> dict[str, dict]:
    """What mstpctl reports for this switch's ports, by port name, when mstpd
    runs its bridge; {} otherwise (the kernel's 802.1D, or the router off)."""
    if not data or not data.get("roles"):
        return {}
    sw = _sw(con)
    out = {}
    for key, dev in ifnames(con.lab).items():
        s, _, port = key.partition(" ")
        if s == sw and dev in data["roles"]:
            out[port] = data["roles"][dev]
    return out


def _rstp_cell(r: dict) -> tuple[str, str]:
    """(Role, Sts) of a port as mstpctl reports it, in IOS's words."""
    if r["guard_err"]:
        return "Desg", "BKN*"
    if not r["enabled"]:
        return "Disa", "DIS"
    return _RSTP_ROLE.get(r["role"], r["role"][:4]), _RSTP_STATE.get(r["state"], r["state"][:3].upper())


_ROLE = {"root": "Root", "desg": "Desg", "altn": "Altn", "back": "Back", "": "Desg"}


def _fa_rows(con) -> list[str]:
    lab, sw = con.lab, _sw(con)
    rows = []
    running = con._running() if con.powered() else set()
    for i, link in enumerate(con._ports(), 1):
        if link.node_id not in running or devcli.held_down(lab, link):
            continue
        e = edge(lab, sw, link.label, False)
        rows.append(f"{f'Fa0/{i}':<20}{'Desg':<5}{'FWD':<4}{FAST_COST:<10}{f'{PORT_PRIORITY}.{i}':<9}"
                    f"P2p{' Edge' if e else ''}")
    return rows


def _gi_rows(con, res: Result, live: dict[str, str], rstp: dict[str, dict] | None = None) -> list[str]:
    sw, rows = _sw(con), []
    for p in res.of(sw):
        if p.state == "down" or p.twin:
            continue
        r = (rstp or {}).get(p.end.port) if not p.po else None
        if r is not None:
            # mstpd runs this switch: its role and state for the port, as mstpctl reports them.
            role, st = _rstp_cell(r)
            edge, guard_err = r["edge"], r["guard_err"]
        else:
            st = "BKN*" if p.state == "err" else live.get(f"{sw} {p.end.port}", p.state)
            role = "Desg" if p.state == "err" else _ROLE[p.role]
            edge, guard_err = p.edge, p.state == "err" and bool(_own(con.lab, sw).get(f"stp-err:{p.end.port}"))
        err = st == "BKN*"
        rows.append(f"{p.po or devcli.short_if(p.end.port):<20}{role:<5}{st:<3} {p.cost:<9}"
                    f"{f'{p.pid[0]}.{p.pid[1]}':<9}P2p{' Edge' if edge else ''}"
                    + ((" *BPDU_GUARD (err-disabled)" if guard_err or _own(con.lab, sw).get(f"stp-err:{p.end.port}")
                        else " *CHANNEL_MISCONFIG (err-disabled)") if err else ""))
    return rows


_HEAD = [f"{'Interface':<20}{'Role':<5}{'Sts':<4}{'Cost':<10}{'Prio.Nbr':<9}Type",
         f"{'-' * 19} {'-' * 4} {'-' * 3} {'-' * 9} {'-' * 8} {'-' * 32}"]


def show(con, vlan: str = "") -> str:
    lab, sw = con.lab, _sw(con)
    tags = [n.vlan_no for n in devcli.vlans_of(lab, sw)]
    if vlan:
        try:
            want = int(vlan)
        except ValueError:
            raise devcli.CliError("% Invalid VLAN id") from None
        if want not in tags:
            return f"Spanning tree instance(s) for vlan {want} does not exist."
        tags = [want]
    if not vlan_on(lab, sw):
        return "\n".join(f"Spanning tree instance(s) for vlan {t} does not exist." for t in tags)
    res = compute(lab)
    b = res.bridges[sw]
    data = _live_read(con)
    live = _live_states(con, data)
    rstp = _rstp_live(con, data)
    proto = data.get("rstp", {}).get(_bridge_of(lab, sw), "") if data else ""
    in_mstpd = bool(proto) or (not data and b.mode in FAST and rstp_ready())
    fd = RSTP_FORWARD_DELAY if in_mstpd else FORWARD_DELAY[b.mode]
    say = (MST_NOTE if b.mode == "mst" else RSTP_NOTE) if in_mstpd else KERNEL_NOTE
    out = []
    if b.mode == "mst":   # one instance, the CIST, for every VLAN: MST0
        tags = [1]
    for t in tags:
        if t != 1:
            what = "Spanning tree disabled for this VLAN" if not vlan_on(lab, sw, t) else "Shares VLAN 1's tree"
            out += [f"VLAN{t:04d}", f"  {what} ({say})", ""]
            continue
        rb = res.bridges.get(b.root) or b
        shown = proto or ({"rapid-pvst": "rstp", "mst": "mstp"}.get(b.mode, "ieee"))
        ext = 0 if b.mode == "mst" else t
        out += ["MST0" if b.mode == "mst" else f"VLAN{t:04d}",
                f"  Spanning tree enabled protocol {'ieee' if shown == 'stp' else shown}",
                f"  Root ID    Priority    {rb.bid[0] + ext}", f"             Address     {devcli.dotted_mac(rb.bid[1])}"]
        if not b.root or b.root == sw:
            out.append("             This bridge is the root")
        else:
            out += [f"             Cost        {b.cost}",
                    f"             Port        {24 + gi_no(b.root_port)} ({b.root_port})"]
        out += [f"             Hello Time   {HELLO} sec  Max Age {MAX_AGE} sec  Forward Delay {fd} sec", "",
                f"  Bridge ID  Priority    {b.bid[0] + ext}  (priority {b.bid[0]} sys-id-ext {ext})",
                f"             Address     {devcli.dotted_mac(b.bid[1])}",
                f"             Hello Time   {HELLO} sec  Max Age {MAX_AGE} sec  Forward Delay {fd} sec",
                "             Aging Time  300 sec", ""] + _HEAD + _fa_rows(con) + _gi_rows(con, res, live, rstp) + [""]
    if rstp:
        out.append(f"! {say}; roles and states as mstpctl reports them")
    elif in_mstpd:
        out.append(f"! {say}; roles worked out by winlab until the router runs")
    else:
        out.append(f"! {KERNEL_NOTE}" + ("; port states read from it" if live else ""))
    return "\n".join(out)


def _bridge_of(lab, sw: str) -> str:
    idx = {s: i for i, s in enumerate(devcli.switches(lab), 1)}
    return f"stp{idx.get(sw, 0)}"


def show_iface(con, text: str) -> str:
    name = devcli.parse_if(text, con._if_names())
    sw = _sw(con)
    p = next((p for p in compute(con.lab).of(sw) if p.end.port == name), None)
    if p is None or not vlan_on(con.lab, sw):
        return f"no spanning tree info available for {devcli.short_if(name)}"
    st, role = ("BKN*" if p.state == "err" else p.state), _ROLE[p.role]
    r = _rstp_live(con, _live_read(con)).get(name) if not p.po else None
    if r is not None:
        role, st = _rstp_cell(r)
    return "\n".join([_HEAD[0].replace("Interface", "Vlan     "), _HEAD[1],
                      f"{'VLAN0001':<20}{role:<5}{st:<3} {p.cost:<9}{f'{p.pid[0]}.{p.pid[1]}':<9}P2p"
                      + (" Edge" if (r["edge"] if r is not None else p.edge) else "")
                      + (" *BPDU_GUARD (err-disabled)" if st == "BKN*" else "")])


def show_summary(con) -> str:
    lab, sw = con.lab, _sw(con)
    res = compute(lab)
    b = res.bridges[sw]
    own = _own(lab, sw)
    rows = [p for p in res.of(sw) if p.state != "down"]
    on = vlan_on(lab, sw)
    out = [f"Switch is in {b.mode} mode", f"Root bridge for: {'VLAN0001' if on and b.root == sw else 'none'}",
           f"{'Portfast Default':<29}is {'enabled' if own.get('stp-edge-default') else 'disabled'}",
           f"{'PortFast BPDU Guard Default':<29}is {'enabled' if own.get('stp-guard-default') else 'disabled'}",
           "", f"{'Name':<23}{'Blocking':<9}{'Listening':<10}{'Learning':<9}{'Forwarding':<11}STP Active",
           f"{'-' * 22} {'-' * 8} {'-' * 9} {'-' * 8} {'-' * 10} {'-' * 10}"]
    if on:
        blk = sum(1 for p in rows if p.state in ("BLK", "err"))
        fwd = sum(1 for p in rows if p.state == "FWD") + len(_fa_rows(con))
        out.append(f"{'VLAN0001':<23}{blk:<9}{0:<10}{0:<9}{fwd:<11}{blk + fwd}")
    out.append(f"! {note(lab, sw)}")
    return "\n".join(out)


def show_cpu(con) -> str:
    b = compute(con.lab).bridges.get(_sw(con))
    cpu = b.cpu if b else 3
    out = [f"CPU utilization for five seconds: {cpu}%/{max(0, cpu - 2)}%; one minute: {max(1, cpu - 4)}%; "
           f"five minutes: {max(1, cpu - 9)}%"]
    if cpu > 90:
        out.append("% Busy forwarding the same broadcasts round a switching loop. (A figure winlab works out "
                   f"from the loop: the switch has no processor of its own here. {CAP_TEXT}.)")
    return "\n".join(out)


def run_lines(lab, sw: str) -> list[str]:
    """What show running-config says about spanning tree on a switch."""
    own = _own(lab, sw)
    out = [f"spanning-tree mode {mode(lab, sw)}"]
    if own.get("stp-edge-default"):
        out.append("spanning-tree portfast default")
    if own.get("stp-guard-default"):
        out.append("spanning-tree portfast bpduguard default")
    for k in sorted(own, key=lambda k: (k.split(":")[0], int(k.rsplit(":", 1)[-1]) if k.rsplit(":", 1)[-1].isnumeric() else 0)):
        if k.startswith("stp-off:"):
            out.append(f"no spanning-tree vlan {k[8:]}")
        elif k.startswith("stp-prio:"):
            out.append(f"spanning-tree vlan {k[9:]} priority {own[k]}")
    from . import mst  # spanning-tree mst configuration and the instances' priorities
    out += mst.run_lines(lab, sw)
    out.append("!")
    return out


def iface_lines(lab, sw: str, key: str, gig: bool) -> list[str]:
    """Spanning tree lines under one interface in show running-config."""
    own, out = _own(lab, sw), []
    v = own.get(f"stp-edge:{key}", "")
    if v in ("trunk", "yes", "no"):
        out.append({"trunk": " spanning-tree portfast trunk", "yes": " spanning-tree portfast",
                    "no": " spanning-tree portfast disable"}[v])
    g = own.get(f"stp-guard:{key}", "")
    if g:
        out.append(f" spanning-tree bpduguard {'enable' if g == 'yes' else 'disable'}")
    if own.get(f"stp-cost:{key}"):
        out.append(f" spanning-tree cost {own[f'stp-cost:{key}']}")
    if own.get(f"stp-pri:{key}"):
        out.append(f" spanning-tree port-priority {own[f'stp-pri:{key}']}")
    if gig and own.get(f"shut:{key}"):
        out.append(" shutdown")
    return out


def spare_ports(lab, sw: str) -> dict[str, str]:
    """A switch's gigabit ports with a spare cable in, to the switch at the
    other end (for show interfaces status and CDP)."""
    out = {}
    for c in cables(lab):
        if c.kind == "extra":
            for e in c.ends():
                if e.sw == sw:
                    out[e.port] = c.far(e).sw
    return out


# ------------------------------------------------------------------ the troubleshooting ticket
# A first-line ticket on campus-vlans (content/lessons/ts-bpdu-guard-floor-switch.toml):
# the night's change moved core and floor to Rapid PVST+ and gave core's port
# to the floor switch PortFast and BPDU guard, as if a desk were there. The
# floor switch is a switch: its BPDUs err-disable the port, and the floor's
# PCs lose the network. Broken from outside the PC like netbasics' tickets
# (its _sw_break: what changed is kept, Give up puts it back, the PC's
# address is left for the verify); with mstpd on the router, mstpd is what
# shuts the port.
QUICK = True   # the break takes seconds (guestfaults.host_break_is_quick)
GUARD_TICKET = "rstp-bpduguard-errdisabled"
HOSTS = {"stp-guard": "winlab.stp:guard_break"}


def _guard_change(lab, plan, node: str, was: list):
    from . import portsec
    from .netbasics import NetBasicsError, _put, _where
    sw, _, _link, _net = _where(lab, plan, node)
    up = devcli.upstream(lab, sw)
    if up not in devcli.switches(lab):
        raise NetBasicsError(f"{node}'s switch is cabled to the router, not to another switch: this ticket "
                             f"needs a PC on a switch below another (campus-vlans: pc-b on floor)")
    port_u = dict((b, p) for p, b in devcli.downlinks(lab, up)).get(sw, "")
    if not port_u:
        raise NetBasicsError(f"no port of {up} leads to {sw}")
    for s in (up, sw):
        _put(lab, was, f"sw:{s}", "stp-mode", "rapid-pvst")
        _put(lab, was, f"sw:{s}", "stp-off:1", None)
    _put(lab, was, f"sw:{up}", f"stp-edge:{port_u}", "trunk")
    _put(lab, was, f"sw:{up}", f"stp-guard:{port_u}", "yes")
    lines = []
    for e in sorted(compute(lab).err, key=lambda e: (e.sw, e.port)):
        if not _own(lab, e.sw).get(f"stp-err:{e.port}"):
            _put(lab, was, f"sw:{e.sw}", f"stp-err:{e.port}", "yes")
            short = devcli.short_if(e.port)
            lines.append((e.sw, f"%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port {short} with BPDU Guard "
                                f"enabled. Disabling port.\n%PM-4-ERR_DISABLE: bpduguard error detected on "
                                f"{short}, putting {short} in err-disable state"))
    for s, text in lines:
        portsec.log(lab.name, f"sw:{s}", [text], lab=lab)
    return (f"{devcli.hostname(lab, 'sw:' + up)} {devcli.short_if(port_u)} has PortFast and BPDU guard; "
            f"{devcli.hostname(lab, 'sw:' + sw)} speaks spanning tree there"), None


def guard_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    from .netbasics import _sw_break
    return _sw_break(GUARD_TICKET, lab_name, node, clear, _guard_change)


def register_faults(reg) -> None:
    from .guestfaults import LINUX, GuestFault
    from .netbasics import FROM_OUTSIDE, VERIFY_LINK
    reg(GuestFault(
        id=GUARD_TICKET, host="stp-guard", os=LINUX, shell="sh", images=("ubuntu",),
        title="BPDU guard err-disabled the port the floor switch is plugged into",
        teaches="Rapid PVST+ edge ports (PortFast) and BPDU guard, err-disabled ports, show spanning-tree and "
                "show logging on the switch above, and putting a port that leads to a switch back as an "
                "ordinary spanning-tree port",
        symptom="after last night's change on the core switch (Rapid PVST+, and PortFast with BPDU guard "
                "on its desk ports) the PCs on the floor switch have no network at all; the PCs on core are fine",
        apply=FROM_OUTSIDE, clear="echo 'Give up puts the switches back as they were'",
        hints=("The PCs on core work and every PC behind floor is cut off: look at the one cable between "
               "the two switches, from the switch above (core).",
               "show spanning-tree on core: its port to floor reads BKN* *BPDU_GUARD (err-disabled), and show "
               "logging has SPANTREE-2-BLOCK_BPDUGUARD. show running-config shows spanning-tree portfast trunk "
               "and spanning-tree bpduguard enable under that port: settings for a desk, on a port that leads "
               "to a switch.",
               "interface gi0/2 on core: no spanning-tree bpduguard and no spanning-tree portfast (a port to a "
               "switch is neither), then shutdown and no shutdown: an err-disabled port stays down until it is "
               "brought back by hand."),
        verify=VERIFY_LINK))


# ------------------------------------------------------------------ the exercise's checks
# content/exercises/rapid-spanning-tree.toml, graded from the lab file (what
# the consoles set) on campus-vlans: core and floor; what mstpd does with it
# is the lesson's [[verify]] on the router.
def _pair(lab) -> tuple[str, str]:
    sws = devcli.switches(lab)
    if "core" not in sws or "floor" not in sws:
        raise ValueError("this check is for campus-vlans: switches core and floor")
    return "core", "floor"


def check_rapid(lab) -> tuple[bool, str]:
    core, floor = _pair(lab)
    modes = {s: mode(lab, s) for s in (core, floor)}
    if any(m != "rapid-pvst" for m in modes.values()):
        return False, "spanning-tree mode: " + ", ".join(f"{s} {m}" for s, m in modes.items()) + "; both must be rapid-pvst"
    if not all(vlan_on(lab, s) for s in (core, floor)):
        return False, "spanning tree is off for VLAN 1 on a switch: spanning-tree vlan 1"
    return True, "core and floor run rapid-pvst"


def check_ring(lab) -> tuple[bool, str]:
    core, floor = _pair(lab)
    res = compute(lab)
    extra = [c for c in res.cables if c.kind == "extra" and {c.a.sw, c.b.sw} == {core, floor}]
    if not extra:
        return False, "no second cable between floor and core: drag a free gigabit port of floor onto core"
    if res.bridges[floor].root != core or res.bridges[core].root != core:
        return False, "core is not the root bridge: spanning-tree vlan 1 root primary on core"
    altn = [p for p in res.of(floor) if p.role == "altn"]
    if not altn:
        return False, "floor has no alternate port: both cables to core must be up"
    return True, f"core is root; floor's {devcli.short_if(altn[0].end.port)} is the alternate port"


def check_guards(lab) -> tuple[bool, str]:
    core, floor = _pair(lab)
    res = compute(lab)
    bad = [p for s in (core, floor) for p in res.of(s) if p.state == "err" or p.guard or p.edge]
    if bad:
        return False, ("PortFast, BPDU guard or err-disabled left on a port between the switches: "
                       + ", ".join(f"{p.end.sw} {devcli.short_if(p.end.port)}" for p in bad))
    if any(shut(lab, e) for c in res.cables for e in c.ends()):
        return False, "a port between the switches is still shut: no shutdown"
    return True, "the cables between the switches are ordinary spanning-tree ports, all up"


def check_desk(lab) -> tuple[bool, str]:
    from . import netplan
    plan = netplan.compile_topology(lab, check_ports=False)
    link = next((l for l in plan.ports_for("pc-b") if l.nic_index == 0), None)
    if link is None:
        return False, "pc-b has no cable"
    sw = devcli.port_no(lab, plan, link.label)
    if not sw:
        return False, "pc-b is not on a switch port"
    if not (edge(lab, sw[0], link.label, False) and guarded(lab, sw[0], link.label, False)):
        return False, (f"pc-b's port (Fa0/{sw[1]} on {sw[0]}) needs spanning-tree portfast and "
                       f"spanning-tree bpduguard enable")
    return True, f"pc-b's port Fa0/{sw[1]} is an edge port with BPDU guard"


def _register_checks() -> None:
    from . import exercises
    for name, fn in (("rstp-rapid", check_rapid), ("rstp-ring", check_ring),
                     ("rstp-guards", check_guards), ("rstp-desk", check_desk)):
        exercises.register_winlab_check(name, fn)


_register_checks()
