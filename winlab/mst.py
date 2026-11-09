"""MST (802.1s) on the workbench's switches: ``spanning-tree mode mst``,
the region typed under ``spanning-tree mst configuration`` (``name``,
``revision``, ``instance <n> vlan <list>``), and ``spanning-tree mst <n>
priority | root``.

A region is the switches that agree on all three: name, revision and which
VLAN is in which instance. Inside a region every instance has its own root
and port roles; between regions (or towards a switch that runs PVST+ or
RSTP) the ports are boundary ports and only the CIST, instance 0, crosses.
Two switches that were meant to be one region and differ in a letter of the
name or the revision number are two regions: the instances' roots are not
what the design said, and show spanning-tree mst says Bound on the ports
between them.

How it is real: an MST switch's bridge on the router is handed to mstpd (the
daemon winlab/mstpd.py brings, which stp.render starts for rapid-pvst too)
with protocol mstp, the region (mstpctl setmstconfid <revision> <name>),
each instance (createtree), its VLANs (setvid2fid, setfid2mstid: one FID per
instance) and its priority (settreeprio). mstpd puts the region's
configuration digest in its BPDUs, as the standard says, and finds the
boundary ports itself. The VLAN numbers in that map are the ones typed at
the console, so two switches with the same lines are one region whatever
VLAN ids the router's bridge uses inside. The router's bridges keep one
forwarding state per port, so every VLAN follows the CIST's port states; the
instances' roots and roles (show spanning-tree mst <n>) are elected and
shown but are not separate forwarding paths. Without mstpd fetched, mode mst
is the kernel's 802.1D with a short forward delay, as rapid-pvst is, and the
console says so.

The roles in show spanning-tree mst are worked out here (instance_view)
from the same settings mstpd gets; instance 0's are the CIST's
(stp.compute), with the ports to another region marked as boundary.

Settings ([devices."sw:<id>"]): ``stp-mode`` = mst; ``mst-name``;
``mst-rev``; ``mst-inst:<n>`` = its VLANs; ``mst-prio:<n>`` = the bridge
priority in instance <n> (0 is the CIST's).
"""

from __future__ import annotations

import heapq
import shlex

from . import devcli

MODE = "config-mst"
MAX_INSTANCE = 4094
MAX_INSTANCES = 16        # a Catalyst's 16 (0 and 15 more)
HOPS = 20


def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


# ------------------------------------------------------------------ the region
def config(own: dict) -> dict:
    """{"name", "rev", "inst": {n: set of VLANs}} as kept."""
    inst = {}
    for k, v in own.items():
        if k.startswith("mst-inst:"):
            try:
                tags = devcli.vlan_set(v) or set()
                inst[int(k[9:])] = tags
            except ValueError:
                continue
    try:
        rev = int(own.get("mst-rev") or 0)
    except ValueError:
        rev = 0
    return {"name": own.get("mst-name", ""), "rev": rev, "inst": inst}


def region_key(lab, sw: str) -> tuple:
    """What two switches must agree on to be one region (the configuration
    identifier: name, revision, and the digest of the VLAN map)."""
    c = config(_own(lab, sw))
    vmap = tuple(sorted((v, n) for n, tags in c["inst"].items() for v in tags))
    return c["name"], c["rev"], vmap


def instance_of(own: dict, vlan: int) -> int:
    for n, tags in config(own)["inst"].items():
        if vlan in tags:
            return n
    return 0


def instance_priority(lab, sw: str, n: int) -> int:
    from .stp import PRIORITY
    try:
        return int(_own(lab, sw).get(f"mst-prio:{n}") or PRIORITY)
    except ValueError:
        return PRIORITY


def mstpctl_lines(lab, sw: str, m: str, br: str) -> list[str]:
    """What stp._rstp_bridge sends mstpd for an MST switch's region."""
    c = config(_own(lab, sw))
    out = [f"{m} setmstconfid {br} {c['rev']} {shlex.quote(c['name'])} || true"]
    for n, tags in sorted(c["inst"].items()):
        out.append(f"{m} createtree {br} {n} || true")
    if c["inst"]:
        out.append(f"{m} setvid2fid {br} " + " ".join(f"{n}:{devcli.vlan_text(t)}" for n, t in sorted(c["inst"].items())
                                                      if t) + " || true")
        out.append(f"{m} setfid2mstid {br} " + " ".join(f"{n}:{n}" for n in sorted(c["inst"])) + " || true")
    for n in sorted(c["inst"]):
        out.append(f"{m} settreeprio {br} {n} {instance_priority(lab, sw, n) // 4096} || true")
    return out


def region(lab, res, sw: str) -> set[str]:
    """The switches in sw's region: MST switches with the same identifier,
    joined by cables that are up."""
    from .stp import mode
    if mode(lab, sw) != "mst":
        return {sw}
    key = region_key(lab, sw)
    seen, todo = {sw}, [sw]
    while todo:
        s = todo.pop()
        for c in res.cables:
            ends = c.ends()
            if not any(e.sw == s for e in ends):
                continue
            if any(res.ports[e].state in ("down", "err") for e in ends):
                continue
            far = next(e.sw for e in ends if e.sw != s) if ends[0].sw != ends[1].sw else s
            if far not in seen and mode(lab, far) == "mst" and region_key(lab, far) == key \
                    and res.bridges[far].on:
                seen.add(far)
                todo.append(far)
    return seen


def boundary(lab, res, sw: str) -> dict[str, str]:
    """sw's ports that lead out of its region: port -> Bound(RSTP) | Bound(PVST)."""
    from .stp import mode
    mine = region(lab, res, sw)
    out = {}
    for e, p in res.ports.items():
        if e.sw != sw or p.state == "down":
            continue
        if p.far.sw not in mine:
            out[e.port] = "Bound(PVST)" if mode(lab, p.far.sw) == "pvst" else "Bound(RSTP)"
    return out


def instance_view(lab, res, sw: str, n: int) -> dict:
    """Instance n as sw's region elects it: {"root", "root_prio", "cost",
    "root_port", "ports": {port: (role, state)}}. Instance 0 is the CIST
    (stp.compute)."""
    from .stp import bridge_mac
    b = res.bridges[sw]
    if n == 0:
        bound = boundary(lab, res, sw)
        ports = {}
        for p in res.of(sw):
            if p.state == "down" or p.twin:
                continue
            ports[p.end.port] = (p.role or "desg", p.state)
        return {"root": b.root or sw, "root_prio": b.root_bid[0] if b.root else b.bid[0], "cost": b.cost,
                "root_port": b.root_port, "ports": ports, "bound": bound}
    mine = region(lab, res, sw)
    bid = {s: (instance_priority(lab, s, n), bridge_mac(lab, s)) for s in mine}
    root = min(mine, key=lambda s: bid[s])
    live = [c for c in res.cables if c.a.sw in mine and c.b.sw in mine and c.a.sw != c.b.sw
            and not any(res.ports[e].state in ("down", "err") for e in c.ends())]
    dist = {s: None for s in mine}
    dist[root] = 0
    heap = [(0, bid[root], root)]
    while heap:
        d, _, s = heapq.heappop(heap)
        if dist[s] is not None and d > dist[s]:
            continue
        for c in live:
            for e in c.ends():
                if e.sw == s:
                    far = c.far(e)
                    nd = d + res.ports[far].cost
                    if dist[far.sw] is None or nd < dist[far.sw]:
                        dist[far.sw] = nd
                        heapq.heappush(heap, (nd, bid[far.sw], far.sw))
    vec = lambda e: (dist[e.sw] if dist[e.sw] is not None else 1 << 30, bid[e.sw], res.ports[e].pid)  # noqa: E731
    rp = {}
    for s in mine:
        if s == root:
            continue
        cands = [((vec(c.far(e))[0] + res.ports[e].cost, bid[c.far(e).sw], res.ports[c.far(e)].pid,
                   res.ports[e].pid), e.port) for c in live for e in c.ends() if e.sw == s]
        if cands:
            rp[s] = min(cands)[1]
    ports = {}
    for c in live:
        a, z = c.ends()
        desg = min((a, z), key=vec)
        for e in (a, z):
            if e.sw != sw:
                continue
            if e == desg:
                ports[e.port] = ("desg", "FWD")
            elif rp.get(sw) == e.port:
                ports[e.port] = ("root", "FWD")
            else:
                ports[e.port] = ("altn", "BLK")
    bound = boundary(lab, res, sw)
    for p in res.of(sw):
        if p.end.port in bound and p.state != "down":
            ports[p.end.port] = (p.role or "desg", p.state)   # a boundary port follows the CIST
    return {"root": root, "root_prio": bid[root][0], "cost": dist.get(sw) or 0, "root_port": rp.get(sw, ""),
            "ports": ports, "bound": bound}


# ------------------------------------------------------------------ the console
WORDS = {("spanning-tree", "mst"): "Multiple spanning tree configuration",
         ("show", "spanning-tree", "mst"): "Multiple spanning trees",
         ("spanning-tree", "mst", "configuration"): "Enter MST configuration submode"}


def add_specs(con, add, U, C) -> None:
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    devcli.MODE_PROMPTS.setdefault(MODE, "config-mst")
    M = (MODE,)
    add("spanning-tree mst configuration", lambda a: enter(con), "Enter MST configuration submode", C)
    add("spanning-tree mst <line>", lambda a: set_priority(con, a[0], True), "Multiple spanning tree configuration", C)
    add("no spanning-tree mst <line>", lambda a: set_priority(con, a[0], False), "Negate a command or set its defaults", C)
    add("no spanning-tree mst configuration", lambda a: clear_region(con), "Negate a command or set its defaults", C)
    add("name <line>", lambda a: _edit(con, "name", a[0]), "Set configuration name", M)
    add("no name", lambda a: _edit(con, "name", ""), "Negate a command or set its defaults", M)
    add("revision <num>", lambda a: _edit(con, "rev", a[0]), "Set configuration revision number", M)
    add("no revision", lambda a: _edit(con, "rev", "0"), "Negate a command or set its defaults", M)
    add("instance <num> vlan <line>", lambda a: _instance(con, a[0], a[1], True), "Map vlans to an MST instance", M)
    add("no instance <num> vlan <line>", lambda a: _instance(con, a[0], a[1], False), "Negate a command or set its defaults", M)
    add("no instance <num>", lambda a: _instance(con, a[0], "", False), "Negate a command or set its defaults", M)
    add("show current", lambda a: show_config(con, current=True), "Display MST configuration currently used", M)
    add("show pending", lambda a: show_config(con, current=False), "Display the new MST configuration to be applied", M)
    add("abort", lambda a: abort(con), "Exit region configuration mode, aborting changes", M)
    add("exit", lambda a: leave(con, "config"), "Exit region configuration mode, applying changes", M)
    add("end", lambda a: leave(con, "enable"), "Exit region configuration mode, applying changes", M)
    add("do <line>", con._do, "To run exec commands in config mode", M)
    add("show spanning-tree mst", lambda a: show_mst(con, ""), "Multiple spanning trees", U)
    add("show spanning-tree mst <line>", lambda a: show_mst(con, a[0]), "Multiple spanning trees", U)
    add("show spanning-tree mst configuration", lambda a: show_config(con, current=True), "Configuration", U)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def mode_note(con) -> str:
    from .stp import FORWARD_DELAY, KERNEL_NOTE, MST_NOTE, rstp_ready
    if rstp_ready():
        return f"% {MST_NOTE}: set the region under spanning-tree mst configuration"
    return (f"% {KERNEL_NOTE} yet (winlab images prepare fabric fetches it once its build is published): "
            f"mst here is 802.1D with a {FORWARD_DELAY['mst']} s forward delay, the region is kept and shown")


def enter(con) -> str:
    c = config(_mine(con))
    con._mst_pending = {"name": c["name"], "rev": c["rev"], "inst": {n: set(t) for n, t in c["inst"].items()}}
    con.s.mode, con.s.ctx = MODE, ""
    return ""


def _pending(con) -> dict:
    p = getattr(con, "_mst_pending", None)
    if p is None:
        enter(con)
        p = con._mst_pending
    return p


def _edit(con, what: str, value: str) -> str:
    p = _pending(con)
    if what == "name":
        if len(value) > 32:
            raise devcli.CliError("% The name is 32 characters at most")
        p["name"] = value.strip()
    else:
        if not value.isdigit() or not 0 <= int(value) <= 65535:
            raise devcli.CliError("% Revision 0 to 65535")
        p["rev"] = int(value)
    return ""


def _instance(con, n: str, text: str, on: bool) -> str:
    i = int(n)
    if not 1 <= i <= MAX_INSTANCE:
        raise devcli.CliError(f"% Instance 1 to {MAX_INSTANCE} (0 is the CIST: every VLAN not mapped elsewhere)")
    p = _pending(con)
    if not text:
        p["inst"].pop(i, None)
        return ""
    w = text.split()
    if w and w[0].lower() in ("vlan", "vlans"):
        w = w[1:]
    try:
        tags = devcli.vlan_set(" ".join(w).replace(" ", ""))
    except ValueError:
        tags = None
    if not tags:
        raise devcli.CliError("% Invalid input: instance <n> vlan <list>, as 10 or 10,20-29")
    if any(not 1 <= t <= 4094 for t in tags):
        raise devcli.CliError("% VLAN ids are 1 to 4094")
    if on:
        if i not in p["inst"] and len(p["inst"]) >= MAX_INSTANCES - 1:
            raise devcli.CliError(f"% At most {MAX_INSTANCES - 1} instances besides the CIST")
        for other in p["inst"].values():   # a VLAN is in one instance: it moves
            other -= tags
        p["inst"][i] = p["inst"].get(i, set()) | tags
    else:
        p["inst"][i] = p["inst"].get(i, set()) - tags
    p["inst"] = {k: v for k, v in p["inst"].items() if v}
    return ""


def apply(con) -> str:
    """The pending region becomes the switch's (exit, end, or a global
    command typed in the submode)."""
    p = getattr(con, "_mst_pending", None)
    con._mst_pending = None
    if p is None:
        return ""
    own = _mine(con)
    before = config(own)
    if before["name"] == p["name"] and before["rev"] == p["rev"] and before["inst"] == p["inst"]:
        return ""
    for k in [k for k in own if k.startswith("mst-inst:")]:
        del own[k]
    for n, tags in p["inst"].items():
        own[f"mst-inst:{n}"] = devcli.vlan_text(tags)
    for key, v in (("mst-name", p["name"]), ("mst-rev", str(p["rev"]) if p["rev"] else "")):
        if v:
            own[key] = v
        else:
            own.pop(key, None)
    from .stp import _done
    return _done(con)


def leave(con, to: str) -> str:
    out = apply(con)
    con.s.mode, con.s.ctx = to, ""
    if to == "enable":
        out = (out + "\n" if out else "") + "%SYS-5-CONFIG_I: Configured from console by console"
    return out


def abort(con) -> str:
    con._mst_pending = None
    con.s.mode, con.s.ctx = "config", ""
    return ""


def clear_region(con) -> str:
    own = _mine(con)
    for k in [k for k in own if k.startswith(("mst-inst:", "mst-name", "mst-rev"))]:
        del own[k]
    from .stp import _done
    return _done(con)


def set_priority(con, text: str, on: bool) -> str:
    """spanning-tree mst <list> priority <n> | root primary | root secondary."""
    from .stp import PRIORITY, _done, compute
    w = text.lower().split()
    if not w:
        raise devcli.CliError("% Incomplete command.")
    try:
        insts = sorted(devcli.vlan_set(w[0]) or set()) if w[0] != "0" else [0]
    except ValueError:
        insts = []
    if w[0] == "0":
        insts = [0]
    elif w[0].startswith("0,") or w[0].startswith("0-"):
        insts = [0] + sorted(devcli.vlan_set(w[0][2:]) or set())
    if not insts or any(not 0 <= i <= MAX_INSTANCE for i in insts):
        raise devcli.CliError("% Invalid input: spanning-tree mst <instance list> priority <n> | root primary | "
                              "root secondary")
    own, rest = _mine(con), w[1:]
    if not on:
        for i in insts:
            own.pop(f"mst-prio:{i}", None)
        return _done(con)
    if len(rest) == 2 and "priority".startswith(rest[0]):
        try:
            p = int(rest[1])
        except ValueError:
            p = -1
        if not 0 <= p <= 61440 or p % 4096:
            raise devcli.CliError("% Bridge Priority must be in increments of 4096.\n% Allowed values are:\n  "
                                  + " ".join(str(4096 * i) for i in range(16)))
    elif len(rest) == 2 and "root".startswith(rest[0]) and rest[1] in ("primary", "secondary"):
        if rest[1] == "secondary":
            p = 28672
        else:
            res = compute(con.lab)
            sw = _sw(con)
            best = min((instance_view(con.lab, res, sw, i)["root_prio"] for i in insts), default=PRIORITY) \
                if sw in res.bridges else PRIORITY
            p = 24576 if best > 24576 else max(0, best - 4096)
    else:
        raise devcli.CliError("% Invalid input: spanning-tree mst <instance list> priority <n> | root primary | "
                              "root secondary")
    for i in insts:
        own[f"mst-prio:{i}"] = str(p)
    return _done(con)


def _vlans_text(c: dict, n: int) -> str:
    if n:
        return devcli.vlan_text(c["inst"].get(n, set()))
    used = set().union(*c["inst"].values()) if c["inst"] else set()
    return devcli.vlan_text(set(range(1, 4095)) - used)


def show_config(con, current: bool = True) -> str:
    if current:
        c = config(_mine(con))
    else:
        c = dict(_pending(con))
    out = [f"{'Name':<10}[{c['name']}]", f"Revision  {c['rev']:<6}Instances configured {len(c['inst']) + 1}", "",
           "Instance  Vlans mapped", f"{'-' * 8}  {'-' * 69}"]
    for n in [0] + sorted(c["inst"]):
        out.append(f"{n:<10}{_vlans_text(c, n)}")
    out.append("-" * 79)
    if not current:
        out.insert(0, "Pending MST configuration")
    return "\n".join(out)


_ROLE = {"root": "Root", "desg": "Desg", "altn": "Altn", "back": "Back", "": "Desg"}


def show_mst(con, text: str) -> str:
    from .stp import FAST_COST, HELLO, MAX_AGE, PORT_PRIORITY, bridge_mac, compute, mode, vlan_on
    lab, sw = con.lab, _sw(con)
    w = text.split()
    if w and "configuration".startswith(w[0].lower()):
        return show_config(con, current=True)
    if mode(lab, sw) != "mst":
        return "% Switch is not in mst mode"
    c = config(_own(lab, sw))
    if w:
        try:
            insts = sorted(devcli.vlan_set(w[0]) or set()) if w[0] != "0" else [0]
        except ValueError:
            raise devcli.CliError("% Invalid input: show spanning-tree mst [<instance>]") from None
    else:
        insts = [0] + sorted(c["inst"])
    if not vlan_on(lab, sw):
        return "% Spanning tree is off on this switch (no spanning-tree vlan 1)"
    res = compute(lab)
    from .stp import FORWARD_DELAY, RSTP_FORWARD_DELAY, rstp_ready
    fd = RSTP_FORWARD_DELAY if rstp_ready() else FORWARD_DELAY["mst"]
    out = []
    for n in insts:
        if n and n not in c["inst"]:
            out.append(f"% MST instance {n} does not exist")
            continue
        v = instance_view(lab, res, sw, n)
        prio = instance_priority(lab, sw, n) if n else res.bridges[sw].bid[0]
        out += [f"##### MST{n:<6}vlans mapped:   {_vlans_text(c, n)}",
                f"Bridge        address {devcli.dotted_mac(bridge_mac(lab, sw))}  priority      {prio + n} "
                f"({prio} sysid {n})"]
        if v["root"] == sw:
            out.append(f"Root          this switch for {'the CIST' if n == 0 else f'MST{n}'}")
        else:
            out += [f"Root          address {devcli.dotted_mac(bridge_mac(lab, v['root']))}  priority      "
                    f"{v['root_prio'] + n} ({v['root_prio']} sysid {n})",
                    f"              port    {devcli.short_if(v['root_port']) if v['root_port'] else '-':<8}"
                    f"cost          {v['cost']:<9}rem hops {HOPS - 1}"]
        if n == 0:
            out += [f"Operational   hello time {HELLO} , forward delay {fd}, max age {MAX_AGE}, txholdcount 6",
                    f"Configured    hello time {HELLO} , forward delay {fd}, max age {MAX_AGE}, max hops    {HOPS}"]
        out += ["", f"{'Interface':<17}{'Role':<5}{'Sts':<4}{'Cost':<10}{'Prio.Nbr':<9}Type",
                f"{'-' * 16} {'-' * 4} {'-' * 3} {'-' * 9} {'-' * 8} {'-' * 32}"]
        running = con._running() if con.powered() else set()
        for i, link in enumerate(con._ports(), 1):
            if link is None or link.node_id not in running or devcli.held_down(lab, link):
                continue
            out.append(f"{f'Fa0/{i}':<17}{'Desg':<5}{'FWD':<4}{FAST_COST:<10}{f'{PORT_PRIORITY}.{i}':<9}P2p Edge")
        for p in res.of(sw):
            if p.end.port not in v["ports"] or p.twin:
                continue
            role, st = v["ports"][p.end.port]
            st = "BKN*" if st == "err" else st
            typ = "P2p" + (f" {v['bound'][p.end.port]}" if p.end.port in v["bound"] else "")
            out.append(f"{p.po or devcli.short_if(p.end.port):<17}{_ROLE.get(role, 'Desg'):<5}{st:<3} "
                       f"{p.cost:<9} {f'{p.pid[0]}.{p.pid[1]}':<9}{typ}")
        out.append("")
    from .stp import note
    out.append(f"! {note(lab, sw)}")
    return "\n".join(out)


def run_lines(lab, sw: str) -> list[str]:
    """What show running-config says: the region, and each instance's priority."""
    own = _own(lab, sw)
    c = config(own)
    out = []
    if c["name"] or c["rev"] or c["inst"]:
        out.append("spanning-tree mst configuration")
        if c["name"]:
            out.append(f" name {c['name']}")
        if c["rev"]:
            out.append(f" revision {c['rev']}")
        out += [f" instance {n} vlan {devcli.vlan_text(t)}" for n, t in sorted(c["inst"].items())]
    for k in sorted((k for k in own if k.startswith("mst-prio:")), key=lambda k: int(k[9:])):
        out.append(f"spanning-tree mst {k[9:]} priority {own[k]}")
    return out


# ------------------------------------------------------------------ the exercise's checks
# content/exercises/mst-regions.toml, graded from the lab file on campus-vlans.
def _pair(lab) -> tuple[str, str]:
    sws = devcli.switches(lab)
    if "core" not in sws or "floor" not in sws:
        raise ValueError("this check is for campus-vlans: switches core and floor")
    return "core", "floor"


def check_mode(lab) -> tuple[bool, str]:
    from .stp import mode, vlan_on
    core, floor = _pair(lab)
    modes = {s: mode(lab, s) for s in (core, floor)}
    if any(m != "mst" for m in modes.values()):
        return False, "spanning-tree mode: " + ", ".join(f"{s} {m}" for s, m in modes.items()) + "; both must be mst"
    if not all(vlan_on(lab, s) for s in (core, floor)):
        return False, "spanning tree is off on a switch"
    return True, "core and floor run MST"


def check_region(lab) -> tuple[bool, str]:
    core, floor = _pair(lab)
    a, b = config(_own(lab, core)), config(_own(lab, floor))
    if a["name"] != "CAMPUS" or a["rev"] != 1:
        return False, f"core's region is [{a['name']}] revision {a['rev']}: name CAMPUS, revision 1"
    if a["inst"].get(1) != {10} or a["inst"].get(2) != {20}:
        return False, "core: instance 1 vlan 10 and instance 2 vlan 20"
    if region_key(lab, core) != region_key(lab, floor):
        return False, (f"floor is in another region: [{b['name']}] revision {b['rev']}, instances "
                       + ", ".join(f"{n}={devcli.vlan_text(t)}" for n, t in sorted(b["inst"].items()))
                       + " (all three must match core's)")
    return True, "core and floor are one region: CAMPUS, revision 1, VLAN 10 in MST1, VLAN 20 in MST2"


def check_roots(lab) -> tuple[bool, str]:
    from .stp import compute
    core, floor = _pair(lab)
    res = compute(lab)
    bad = []
    for n, want in ((0, core), (1, core), (2, floor)):
        got = instance_view(lab, res, core, n)["root"]
        if got != want:
            bad.append(f"MST{n}'s root is {got}, not {want}")
    return (not bad, "; ".join(bad) or "core is root of MST0 and MST1, floor of MST2")


def _register_checks() -> None:
    from . import exercises
    for name, fn in (("mst-mode", check_mode), ("mst-region", check_region), ("mst-roots", check_roots)):
        exercises.register_winlab_check(name, fn)


_register_checks()
