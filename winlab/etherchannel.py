"""EtherChannel on the workbench's switches: two or more cables between two
switches bundled into one logical link (a port-channel).

``interface range gi0/2 - 3`` then ``channel-group 1 mode active`` puts
ports into channel group 1; ``interface port-channel 1`` configures the
bundle; ``show etherchannel summary`` says what came of it. The modes are
IOS's: ``on`` (bundle without asking), ``active`` / ``passive`` (LACP,
802.3ad) and ``desirable`` / ``auto`` (PAgP, Cisco's own protocol).

How it is real. The cables between switches are veth pairs between the
switches' kernel bridges on the router (winlab/stp.py). A channel that
forms is a Linux bond on each side, the members' veths its slaves and the
bond one port of the switch's bridge, so spanning tree sees one link and
blocks neither cable: mode 802.3ad for LACP (``lacp_active off`` for
passive), balance-xor for ``on``, the hash from ``port-channel
load-balance``. The kernel's LACP then runs between the two bonds for
real: LACPDUs on the wire, the partner's system address, aggregator ids
(``show etherchannel detail`` and ``show lacp neighbor`` read them from
/proc/net/bonding while the router runs).

Whether two ends can form a channel is worked out here from both
switches' modes, with IOS's rules (compute()): on with on; LACP when at
least one end is active; PAgP when at least one end is desirable. Ends
that cannot bundle stand alone (I) as ordinary ports, and spanning tree
blocks the extra cables. ``on`` facing anything but ``on`` is the classic
mistake: a Catalyst's EtherChannel misconfiguration guard err-disables the
``on`` side (channel-misconfig), and so does winlab, until shutdown / no
shutdown on the port-channel after the modes are fixed.

PAgP is Cisco's own protocol and Linux bonding speaks only LACP, so PAgP is
spoken by winlab-pagpd (winlab/pagpd.py), winlab's own small PAgP speaker,
on the router: real PAgP frames (01:00:0c:cc:cc:cc, SNAP 0x0104, the layout
Wireshark decodes) on every desirable or auto port, desirable ports asking,
auto ports answering. Those ports start as ordinary ports of the switch's
bridge; the speaker moves a port into the channel's bond (balance-xor, a
non-LACP mode) only once PAgP agrees with the far end, and back out when it
stops agreeing, so auto with auto never forms because neither end asks.
``show pagp neighbor`` and ``show etherchannel summary`` read the speaker's
state (/run/winlab-pagp.json) while the router runs; offline they show what
PAgP's rules predict (compute()). The fabric's nftables drops PAgP frames
at the bridges so a PDU never floods onto another cable. The speaker runs
on Python 3 from the lab's own Alpine package volume
(alpineovl.APPLIANCE_PACKAGES), like winlab-hsrpd; it was tested against
itself only, never against a Cisco switch, and the consoles say so.

Settings live with the switch's others ([devices."sw:<id>"]):
``chgrp:<port>`` = "<group> <mode>", ``po:<n>`` (the interface exists),
``po-desc:<n>``, ``po-shut:<n>``, ``ec-lb`` (load-balance) and, as state
not configuration, ``ec-err:<n>`` (err-disabled).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import devcli

MODES = ("on", "active", "passive", "desirable", "auto")
PROTO = {"on": "", "active": "LACP", "passive": "LACP", "desirable": "PAgP", "auto": "PAgP"}
GROUPS = 6                 # a 2960 has channel groups 1 to 6
PO_COST = 3                # spanning tree's short cost of a 2 Gbit/s bundle
LB = {"src-mac": "layer2", "dst-mac": "layer2", "src-dst-mac": "layer2",
      "src-ip": "layer2+3", "dst-ip": "layer2+3", "src-dst-ip": "layer2+3"}
LB_DEFAULT = "src-mac"
LB_WORDS = {"src-mac": "Source MAC address", "dst-mac": "Destination MAC address",
            "src-dst-mac": "Source XOR Destination MAC address", "src-ip": "Source IP address",
            "dst-ip": "Destination IP address", "src-dst-ip": "Source XOR Destination IP address"}
PAGP_NOTE = ("% PAgP here is winlab-pagpd, winlab's own PAgP speaker on the lab router (Linux bonding speaks "
             "only LACP): real PAgP frames on the cables, desirable asks, auto only answers, and the ports bundle "
             "(a Linux bond, balance-xor) once both ends agree. Tested against itself, not against a Cisco switch.")
SPEAKER = "/usr/local/sbin/winlab-pagpd"
SPEAKER_CONF = "/etc/winlab-pagp.json"
SPEAKER_STATE = "/run/winlab-pagp.json"
SPEAKER_PID = "/run/winlab-pagpd.pid"
SPEAKER_LOG = "/var/log/winlab-pagp.log"
PAGP_TABLE = "winlab_pagp"
LIVE_CMD = "for f in /proc/net/bonding/stp*; do [ -e $f ] && echo \"#bond ${f##*/}\" && cat $f; done; true"


# ------------------------------------------------------------------ settings
def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


def member_of(lab, sw: str, port: str) -> tuple[int, str]:
    """(group, mode) of a port, or (0, "")."""
    v = _own(lab, sw).get(f"chgrp:{port}", "")
    parts = v.split()
    if len(parts) == 2 and parts[0].isdigit() and parts[1] in MODES:
        return int(parts[0]), parts[1]
    return 0, ""


def _port_order(port: str) -> tuple[int, int]:
    m = re.search(r"(\d+)$", port)
    return (1 if port.startswith("Gigabit") else 0, int(m.group(1)) if m else 0)


def groups(lab, sw: str) -> dict[int, list[str]]:
    """{group: its member ports, in port order} for a switch."""
    out: dict[int, list[str]] = {}
    for k in _own(lab, sw):
        if k.startswith("chgrp:"):
            n, _ = member_of(lab, sw, k[6:])
            if n:
                out.setdefault(n, []).append(k[6:])
    return {n: sorted(p, key=_port_order) for n, p in sorted(out.items())}


def channels(lab, sw: str) -> list[int]:
    """Every port-channel the switch has: groups with members, and interfaces made by hand."""
    own = _own(lab, sw)
    made = {int(k[3:]) for k in own if k.startswith("po:") and k[3:].isdigit()}
    return sorted(made | set(groups(lab, sw)))


def mode_of(lab, sw: str, n: int) -> str:
    ports = groups(lab, sw).get(n, [])
    modes = [member_of(lab, sw, p)[1] for p in ports]
    if "active" in modes:
        return "active"
    return modes[0] if modes else ""


def lb(lab, sw: str) -> str:
    return _own(lab, sw).get("ec-lb") or LB_DEFAULT


def po_name(n: int) -> str:
    return f"Port-channel{n}"


# ------------------------------------------------------------------ what forms
@dataclass
class State:
    flags: dict = field(default_factory=dict)      # (sw, port) -> P I s D
    err: set = field(default_factory=set)          # (sw, n) err-disabled, kept or just found
    found: set = field(default_factory=set)        # (sw, n) err-disabled just now (misconfig guard)
    bundles: dict = field(default_factory=dict)    # ((sw, n), (sw, n)) -> [cable ids]
    far: dict = field(default_factory=dict)        # (sw, port) -> (sw, port) across a cable

    def po_flag(self, sw: str, n: int, members: list[str]) -> str:
        if (sw, n) in self.err:
            return "SD"
        return "SU" if any(self.flags.get((sw, p)) == "P" for p in members) else "SD"


def _switch_far(lab) -> dict:
    from . import stp
    far = {}
    for c in stp.cables(lab):
        far[(c.a.sw, c.a.port)] = (c.b.sw, c.b.port)
        far[(c.b.sw, c.b.port)] = (c.a.sw, c.a.port)
    return far


def _down(lab, sw: str, port: str) -> bool:
    own = _own(lab, sw)
    n, _ = member_of(lab, sw, port)
    return bool(own.get(f"shut:{port}") or own.get(f"stp-err:{port}") or (n and own.get(f"po-shut:{n}")))


def _host_plugged(lab, sw: str, port: str, plugged) -> bool:
    """Whether a machine (or the router, on a top switch's Gi0/1) is at the far end.
    `plugged` is {switch: its machine port numbers}, or None to take every
    machine port as plugged (spanning tree only asks about gigabit cables)."""
    if port.startswith("GigabitEthernet"):
        return port == "GigabitEthernet0/1" and devcli.uplinked(lab, sw)
    m = re.match(r"^FastEthernet0/(\d+)$", port)
    if not m:
        return False
    return plugged is None or int(m.group(1)) in plugged.get(sw, set())


def plugged_ports(lab, plan) -> dict[str, set[int]]:
    """{switch: the FastEthernet port numbers with a machine in}."""
    return {sw: {i for i, l in enumerate(links, 1) if l is not None}
            for sw, links in devcli.switch_ports(lab, plan).items()}


def compute(lab, plugged=None) -> State:
    """Each member port's flag as show etherchannel summary prints it, the
    channels err-disabled, and the bundles that form between two switches."""
    st = State(far=_switch_far(lab))
    sws = devcli.switches(lab)
    for sw in sws:
        for k in _own(lab, sw):
            if k.startswith("ec-err:") and k[7:].isdigit():
                st.err.add((sw, int(k[7:])))
    # EtherChannel misconfiguration guard: an 'on' channel whose cables reach
    # a far end that is not 'on' (LACP, PAgP, or no channel at all) hears
    # spanning tree from several far ports at once, and is err-disabled.
    for sw in sws:
        for n, ports in groups(lab, sw).items():
            if (sw, n) in st.err or mode_of(lab, sw, n) != "on" or _own(lab, sw).get(f"po-shut:{n}"):
                continue
            for p in ports:
                f = st.far.get((sw, p))
                if f is None or _down(lab, sw, p) or _down(lab, *f):
                    continue
                fn, fm = member_of(lab, *f)
                if fm != "on" and (f[0], fn) not in st.err:
                    st.found.add((sw, n))
                    break
    st.err |= st.found
    for sw in sws:
        for n, ports in groups(lab, sw).items():
            for p in ports:
                st.flags[(sw, p)] = _flag(lab, st, sw, n, p, plugged)
            # Members that bundle with different far ends: the most go together, the rest are suspended.
            by: dict = {}
            for p in ports:
                f = st.far.get((sw, p))
                if st.flags[(sw, p)] == "P" and f is not None:
                    by.setdefault((f[0], member_of(lab, *f)[0]), []).append(p)
            if len(by) > 1:
                keep = max(by.values(), key=len)
                for k, ps in by.items():
                    if ps is not keep:
                        for p in ps:
                            st.flags[(sw, p)] = "s"
    from . import stp
    for c in stp.cables(lab):
        a, b = (c.a.sw, c.a.port), (c.b.sw, c.b.port)
        if st.flags.get(a) == "P" and st.flags.get(b) == "P":
            key = tuple(sorted([(c.a.sw, member_of(lab, *a)[0]), (c.b.sw, member_of(lab, *b)[0])]))
            st.bundles.setdefault(key, []).append(c.id)
    return st


def _flag(lab, st: State, sw: str, n: int, p: str, plugged) -> str:
    m = member_of(lab, sw, p)[1]
    if (sw, n) in st.err or _down(lab, sw, p):
        return "D"
    f = st.far.get((sw, p))
    if f is None:
        if not _host_plugged(lab, sw, p, plugged):
            return "D"
        # A machine or the router at the far end: they speak neither LACP
        # nor PAgP, so only 'on' bundles (and nothing checks it).
        return "P" if m == "on" else "I"
    fn, fm = member_of(lab, *f)
    if _down(lab, *f) or (fn and (f[0], fn) in st.err):
        return "D"
    if m == "on":
        return "P" if fm == "on" else "D"
    if PROTO[m] == "LACP":
        return "P" if PROTO.get(fm) == "LACP" and "active" in (m, fm) else "I"
    return "P" if PROTO.get(fm) == "PAgP" and "desirable" in (m, fm) else "I"


def refresh(lab) -> list[str]:
    """Records the channels the misconfiguration guard has just err-disabled,
    with what their switches log."""
    out = []
    st = compute(lab)
    for sw, n in sorted(st.found):
        own = lab.devices.setdefault(f"sw:{sw}", {})
        if own.get(f"ec-err:{n}"):
            continue
        own[f"ec-err:{n}"] = "yes"
        host = devcli.hostname(lab, f"sw:{sw}")
        lines = [f"%PM-4-ERR_DISABLE: channel-misconfig (STP) error detected on Po{n}, putting "
                 f"{devcli.short_if(p)} in err-disable state" for p in groups(lab, sw).get(n, [])]
        lines.append(f"%PM-4-ERR_DISABLE: channel-misconfig (STP) error detected on Po{n}, putting Po{n} in "
                     f"err-disable state")
        out.append(f"{host}: " + f"\n{host}: ".join(lines))
    return out


# ------------------------------------------------------------------ spanning tree (winlab/stp.py)
def fold(lab, res, live: list) -> tuple[list, dict]:
    """stp.compute's cables as spanning tree sees them: a misconfigured or
    shut channel's cables are down (err-disabled on its own side), and the
    cables of a channel that formed are one port, the first standing for
    the rest. Returns the cables left and {cable id: the one standing for it}."""
    st = compute(lab)
    dead = set()
    for c in live:
        for e in c.ends():
            n, _ = member_of(lab, e.sw, e.port)
            if not n:
                continue
            if (e.sw, n) in st.err:
                res.ports[e].state = "err"
                res.ports[c.far(e)].state = "down"
                dead.add(c.id)
            elif _own(lab, e.sw).get(f"po-shut:{n}"):
                res.ports[e].state = "down"
                res.ports[c.far(e)].state = "down"
                dead.add(c.id)
    keep = [c for c in live if c.id not in dead]
    twins: dict[str, str] = {}
    by_id = {c.id: c for c in keep}
    for key, ids in st.bundles.items():
        cabs = sorted((by_id[i] for i in ids if i in by_id), key=lambda c: devcli.short_if(c.a.port))
        if not cabs:
            continue
        rep = cabs[0]
        for c in cabs:
            for e in c.ends():
                res.ports[e].po = f"Po{member_of(lab, e.sw, e.port)[0]}"
                if len(cabs) > 1:
                    res.ports[e].cost = PO_COST
            if c is not rep:
                twins[c.id] = rep.id
    return [c for c in keep if c.id not in twins], twins


def unfold(res, twins: dict) -> None:
    """The cables a channel's first cable stood for take its role and state."""
    by_id = {c.id: c for c in res.cables}
    for tid, rid in twins.items():
        t, r = by_id[tid], by_id[rid]
        for e in t.ends():
            same = r.a if r.a.sw == e.sw else r.b
            p, q = res.ports[e], res.ports[same]
            p.role, p.state, p.cost, p.twin = q.role, q.state, q.cost, True


def bond_name(i: int, n: int) -> str:
    return f"stp{i}po{n}"


def render_switch(lab, sw: str, i: int, res, br: str, native: int, vids: list[int]):
    """The bonds a switch's channels are on the router: (lines making them,
    {member port: bond}, lines putting them in the switch's bridge)."""
    from . import stp
    st = compute(lab)
    pre, post, bonded = [], [], {}
    for n, ports in groups(lab, sw).items():
        bond, mode = bond_name(i, n), mode_of(lab, sw, n)
        pol = LB[lb(lab, sw)]
        if PROTO.get(mode) == "PAgP":
            # The members stay ports of the bridge; winlab-pagpd moves them into the bond once PAgP agrees.
            if not pagp_members(lab, st, sw, n):
                continue
            pre += [f"ip link add {bond} type bond mode balance-xor miimon 100 xmit_hash_policy {pol} || true"
                    f"   # {sw} Po{n}: PAgP {mode}; winlab-pagpd bundles the members when PAgP agrees",
                    f"ip link set dev {bond} alias {sw}-Po{n} || true"]
            ps = res.ports.get(stp.End(sw, ports[0]))
            post += [f"ip link set {bond} master {br}", f"bridge vlan add dev {bond} vid {native} pvid untagged"]
            post += [f"bridge vlan add dev {bond} vid {v}" for v in vids]
            post += [f"bridge link set dev {bond} cost {PO_COST} priority "
                     f"{(ps.pid[0] if ps else stp.PORT_PRIORITY) // 4} 2>/dev/null || true", f"ip link set {bond} up"]
            continue
        mine = [p for p in ports if st.flags.get((sw, p)) == "P" and (sw, p) in st.far]
        if not mine:
            continue
        if mode == "on":
            pre.append(f"ip link add {bond} type bond mode balance-xor miimon 100 xmit_hash_policy {pol} || true"
                       f"   # {sw} Po{n}: mode on, no negotiation")
        else:
            mac = stp.bridge_mac(lab, sw)
            passive = " lacp_active off" if mode in ("passive",) else ""
            pre.append(f"ip link add {bond} type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy {pol} "
                       f"ad_actor_system {mac}{passive} 2>/dev/null || ip link add {bond} type bond mode 802.3ad "
                       f"miimon 100 lacp_rate fast || true   # {sw} Po{n}: LACP {mode}")
        pre.append(f"ip link set dev {bond} alias {sw}-Po{n} || true")
        for p in mine:
            bonded[p] = bond
        e = stp.End(sw, mine[0])
        ps = res.ports.get(e)
        cost = ps.cost if ps else PO_COST
        pri = (ps.pid[0] if ps else stp.PORT_PRIORITY) // 4
        post += [f"ip link set {bond} master {br}",
                 f"bridge vlan add dev {bond} vid {native} pvid untagged"]
        post += [f"bridge vlan add dev {bond} vid {v}" for v in vids]
        post += [f"bridge link set dev {bond} cost {cost} priority {pri} 2>/dev/null || true",
                 f"ip link set {bond} up"]
    return pre, bonded, post


def pagp_members(lab, st: State, sw: str, n: int) -> list[str]:
    """A PAgP group's ports winlab-pagpd speaks on: cabled to another switch
    and not down (shut, err-disabled)."""
    return [p for p in groups(lab, sw).get(n, []) if (sw, p) in st.far and st.flags.get((sw, p)) != "D"]


def pagp_conf(plan) -> list[dict]:
    """winlab-pagpd's ports: per desirable or auto port, its veth, the bond
    it joins, and how it goes back into its switch's bridge."""
    from . import stp
    lab = plan.lab
    st = compute(lab)
    idx = {s: i for i, s in enumerate(devcli.switches(lab), 1)}
    out = []
    groups_ = stp.trees(lab)
    native = stp.native_vid(plan) if groups_ else 0
    for _, members in groups_:
        vids = sorted({plan.segment_of(nw.id).vid for s in members for nw in devcli.vlans_of(lab, s)})
        for sw in members:
            for n in groups(lab, sw):
                if PROTO.get(mode_of(lab, sw, n)) != "PAgP":
                    continue
                for p in pagp_members(lab, st, sw, n):
                    if st.far[(sw, p)][0] not in members:
                        continue
                    e = stp.End(sw, p)
                    out.append({"dev": f"stp{idx[sw]}g{stp.gi_no(p)}", "switch": sw, "port": p,
                                "mode": member_of(lab, sw, p)[1], "group": n,
                                "device_id": stp.bridge_mac(lab, sw),
                                "device_name": devcli.hostname(lab, f"sw:{sw}")[:64],
                                "port_name": devcli.short_if(p), "ifindex": stp.port_id(lab, e)[1],
                                "bond": bond_name(idx[sw], n), "bridge": f"stp{idx[sw]}", "native": native,
                                "vids": vids, "cost": stp.port_cost(lab, e),
                                "priority": stp.port_priority(lab, e) // 4})
    return out


def speaker_source() -> bytes:
    from pathlib import Path
    from . import pagpd
    return Path(pagpd.__file__).read_bytes()


def speaker_hash() -> str:
    import hashlib
    return hashlib.sha256(speaker_source()).hexdigest()


def _speaker_lines() -> list[str]:
    import base64
    import gzip
    blob = base64.b64encode(gzip.compress(speaker_source(), mtime=0)).decode()
    wrapped = "\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
    return [f"mkdir -p {SPEAKER.rsplit('/', 1)[0]}",
            f"base64 -d > {SPEAKER}.gz <<'WLPAGPD'\n{wrapped}\nWLPAGPD",
            f"gunzip -c {SPEAKER}.gz > {SPEAKER} && chmod 755 {SPEAKER}; rm -f {SPEAKER}.gz"]


# nftables on the router: PAgP frames stop at every bridge (the speaker reads
# them on the veth first, with a raw socket). @ll,112,64 is the LLC/SNAP
# header after the 14-octet Ethernet header: AA-AA-03, OUI 00-00-0C, PID 0x0104.
PAGP_NFT = (f"table bridge {PAGP_TABLE} {{\n chain forward {{\n"
            "  type filter hook forward priority -200; policy accept;\n"
            "  ether daddr 01:00:0c:cc:cc:cc @ll,112,64 0xaaaa0300000c0104 drop\n }\n}")


def pagp_lines(plan, reset: bool = False) -> list[str]:
    """The router's PAgP: nftables keeping PAgP frames off the bridges, the
    speaker installed (Python 3 from the lab's package volume), its file
    written, and the speaker started or told to read it again; stopped when
    no port speaks PAgP (on a rebuild). Nothing at all for a lab with no
    desirable or auto port, so such a lab's script is as it was."""
    import json
    from . import ioshsrp
    ports = pagp_conf(plan)
    stop = [f"p=$(cat {SPEAKER_PID} 2>/dev/null); [ -n \"$p\" ] && kill \"$p\" 2>/dev/null; "
            f"rm -f {SPEAKER_PID} {SPEAKER_CONF}",
            f"nft delete table bridge {PAGP_TABLE} 2>/dev/null; true"]
    if not ports:
        return (["# PAgP: no desirable or auto port"] + stop) if reset else []
    conf = json.dumps({"ports": ports}, indent=1, sort_keys=True)
    out = ["# PAgP: winlab's own speaker, winlab-pagpd (winlab/pagpd.py), on the desirable and auto ports",
           f"nft delete table bridge {PAGP_TABLE} 2>/dev/null",
           f"nft -f - <<'WLPAGPNFT' || true\n{PAGP_NFT}\nWLPAGPNFT",
           ioshsrp.INSTALL,
           f"if [ \"$(sha256sum {SPEAKER} 2>/dev/null | cut -c1-64)\" != {speaker_hash()} ]; then"]
    out += _speaker_lines() + ["fi"]
    out += [f"cat > {SPEAKER_CONF} <<'WLPAGP'\n{conf}\nWLPAGP",
            f"p=$(cat {SPEAKER_PID} 2>/dev/null)",
            f"if [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null; then kill -HUP \"$p\"; "
            f"else setsid python3 {SPEAKER} -c {SPEAKER_CONF} -l {SPEAKER_LOG} </dev/null >/dev/null 2>&1 & "
            f"echo $! > {SPEAKER_PID}; fi"]
    return out


def member_lines(dev: str, bond: str, rate: str) -> list[str]:
    return [f"ip link set {dev} down", f"ip link set {dev} master {bond}",
            f"tc qdisc replace dev {dev} root tbf rate {rate} burst 8kb latency 100ms || true",
            f"ip link set {dev} up"]


# ------------------------------------------------------------------ the running router
def parse_live(text: str) -> dict:
    """/proc/net/bonding: per bond its mode, active aggregator and per slave
    its link, aggregator and partner."""
    bonds: dict = {}
    cur = slave = None
    section = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("#bond "):
            cur = bonds.setdefault(line[6:].strip(), {"mode": "", "active": "", "slaves": {}})
            slave, section = None, ""
            continue
        low = line.lower()
        if low.startswith("active aggregator info"):
            section = "active"
            continue
        if low.startswith("details partner"):
            section = "partner"
            continue
        if low.startswith("details actor"):
            section = "actor"
            continue
        if cur is None or ":" not in line:
            continue
        k, _, v = (x.strip() for x in line.partition(":"))
        kl = k.lower()
        if kl == "bonding mode":
            cur["mode"] = v
        elif kl == "slave interface":
            slave = cur["slaves"].setdefault(v, {"mii": "", "agg": "", "partner": ""})
            section = ""
        elif kl == "aggregator id":
            if slave is None and section == "active":
                cur["active"] = v
            elif slave is not None:
                slave["agg"] = v
        elif kl == "mii status" and slave is not None:
            slave["mii"] = v
        elif kl == "system mac address" and slave is not None and section == "partner":
            slave["partner"] = v
    return bonds


def live_flags(lab, data: dict) -> dict:
    """{(sw, port): flag} for the bonded members, from the kernel."""
    from . import stp
    names = {v: k for k, v in stp.ifnames(lab).items()}
    out = {}
    for bond in data.values():
        lacp = "802.3ad" in bond["mode"]
        for dev, s in bond["slaves"].items():
            key = names.get(dev)
            if not key:
                continue
            sw, port = key.split(" ", 1)
            if s["mii"] != "up":
                out[(sw, port)] = "D"
            elif lacp and (s["partner"] in ("", "00:00:00:00:00:00") or (bond["active"] and s["agg"] != bond["active"])):
                out[(sw, port)] = "s"
            else:
                out[(sw, port)] = "P"
    return out


def _live(con) -> dict:
    if not con.powered():
        return {}
    try:
        return parse_live(con._on_router(LIVE_CMD, timeout=15))
    except devcli.CliError:
        return {}


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    """The switch's EtherChannel commands (devcli.Console._specs)."""
    add("channel-group <num> mode <line>", lambda a: set_group(con, a[0], a[1]), "Etherchannel/port bundling configuration", I)
    add("no channel-group", lambda a: no_group(con), "Negate a command or set its defaults", I)
    add("no channel-group <line>", lambda a: no_group(con), "Negate a command or set its defaults", I)
    add("channel-protocol <line>", lambda a: set_protocol(con, a[0]), "Select the channel protocol (LACP, PAgP)", I)
    add("no channel-protocol", lambda a: set_protocol(con, ""), "Negate a command or set its defaults", I)
    add("interface port-channel <num>", lambda a: (enter(con, f"po{a[0]}"), "")[1], "Ethernet Channel of interfaces", C + I)
    add("no interface port-channel <num>", lambda a: remove(con, int(a[0])), "Delete a port-channel interface", C)
    add("port-channel load-balance <line>", lambda a: set_lb(con, a[0]), "EtherChannel Load-Balancing Configuration", C)
    add("no port-channel load-balance", lambda a: set_lb(con, ""), "Negate a command or set its defaults", C)
    add("show etherchannel", lambda a: show_listing(con), "EtherChannel information", U)
    add("show etherchannel summary", lambda a: show_summary(con), "One-line summary per channel-group", U)
    add("show etherchannel detail", lambda a: show_detail(con), "Detail information", U)
    add("show etherchannel port-channel", lambda a: show_detail(con), "Port-channel information", U)
    add("show etherchannel load-balance", lambda a: show_lb(con), "Load-balance/frame-distribution scheme among ports in port-channel", U)
    add("show lacp neighbor", lambda a: show_lacp(con), "Display neighbor information", U)
    add("show lacp sys-id", lambda a: show_sysid(con), "LACP System ID", U)
    add("show pagp neighbor", lambda a: show_pagp(con), "Neighbor information", U)
    add("show interfaces port-channel <num>", lambda a: show_iface(con, f"po{a[0]}"), "Ethernet Channel of interfaces", U)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def po_number(text: str) -> int:
    """'po1', 'Port-channel 1', 'port-ch1' -> 1; 0 when it is not a port-channel."""
    m = re.match(r"^\s*([A-Za-z-]+)\s*(\d+)\s*$", text or "")
    if not m:
        return 0
    word = m.group(1).lower()
    if len(word) >= 2 and "port-channel".startswith(word):
        return int(m.group(2))
    return 0


def enter(con, text: str) -> bool:
    """interface port-channel <n>: True when the text named one (the mode is then entered)."""
    n = po_number(text)
    if not n:
        return False
    if not 1 <= n <= GROUPS:
        raise devcli.CliError(f"% Invalid input detected at '^' marker.\n% Port-channel numbers here are 1 to {GROUPS}")
    own = devcli.settings(con.lab, con.device)
    if not own.get(f"po:{n}"):
        own[f"po:{n}"] = "yes"
        con._save(live=False)
    con.s.ctx, con.s.mode = po_name(n), "config-if"
    return True


def _in_po(con) -> int:
    if con.device == devcli.ROUTER or con.s.mode != "config-if" or not con.s.ctx.startswith("Port-channel"):
        return 0
    return int(con.s.ctx[len("Port-channel"):] or 0)


def on_po(con, spec, args):
    """A command typed under interface port-channel: its description and
    shutdown are the port-channel's own; the rest goes to its member ports,
    as IOS hands a port-channel's configuration down to them. None when the
    console is not configuring a port-channel."""
    if list(spec.words[:2]) == ["interface", "port-channel"] and con.device != devcli.ROUTER:
        return spec.run(args) or ""     # also from interface range: it leaves the range
    n = _in_po(con)
    if not n or spec.run in (con._end, con._cfg_exit, con._do, con._interface, con._interface_range):
        return None
    words = [w for w in spec.words if not w.startswith("<")]
    own = devcli.settings(con.lab, con.device)
    if words[:1] == ["description"]:
        own[f"po-desc:{n}"] = args[0][:120]
        con._save(live=False)
        return ""
    if words[:2] == ["no", "description"]:
        own.pop(f"po-desc:{n}", None)
        con._save(live=False)
        return ""
    if words in (["shutdown"], ["no", "shutdown"]):
        return po_shutdown(con, n, words == ["shutdown"])
    if spec.run in (con._interface, con._interface_range) or words[:1] in (["channel-group"], ["channel-protocol"]) \
            or words[:2] == ["no", "channel-group"]:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    members = groups(con.lab, _sw(con)).get(n, [])
    outs = []
    try:
        for p in members:
            con.s.ctx = p
            try:
                outs.append(spec.run(args) or "")
            except devcli.CliError as exc:
                outs.append(str(exc))
    finally:
        con.s.mode, con.s.ctx = "config-if", po_name(n)
    return "\n".join(o for o in outs if o)


def _states(lab, sw: str) -> dict[int, str]:
    st = compute(lab)
    return {n: st.po_flag(sw, n, groups(lab, sw).get(n, [])) for n in channels(lab, sw)}


def _done(con, before: dict[int, str]) -> str:
    """Saves (pushing into the running router), and says what changed: a
    port-channel up or down, a channel err-disabled, a loop."""
    from . import stp
    said = stp._done(con)
    after = _states(con.lab, _sw(con))
    logs = []
    for n, f in sorted(after.items()):
        was = before.get(n, "SD")
        if f == "SU" and was != "SU":
            logs += [f"%LINK-3-UPDOWN: Interface Port-channel{n}, changed state to up",
                     f"%LINEPROTO-5-UPDOWN: Line protocol on Interface Port-channel{n}, changed state to up"]
        elif f != "SU" and was == "SU":
            logs += [f"%LINEPROTO-5-UPDOWN: Line protocol on Interface Port-channel{n}, changed state to down",
                     f"%LINK-3-UPDOWN: Interface Port-channel{n}, changed state to down"]
    return "\n".join(x for x in logs + [said] if x)


def _pick(word: str, choices, what: str) -> str:
    w = word.strip().lower()
    if w in choices:
        return w
    hit = [c for c in choices if c.startswith(w)] if w else []
    if len(hit) == 1:
        return hit[0]
    if len(hit) > 1:
        raise devcli.CliError(f'% Ambiguous command:  "{what}"')
    raise devcli.CliError("% Invalid input detected at '^' marker.")


def set_group(con, num: str, text: str) -> str:
    port = con.s.ctx
    if not port.startswith(("FastEthernet", "GigabitEthernet")):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    n = int(num)
    if not 1 <= n <= GROUPS:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    words = text.split()
    if not words:
        raise devcli.CliError("% Incomplete command.")
    mode = _pick(words[0], MODES, f"channel-group {num} mode {text}")
    lab, sw = con.lab, _sw(con)
    own = devcli.settings(lab, con.device)
    short = devcli.short_if(port)
    others = [p for p in groups(lab, sw).get(n, []) if p != port]
    if others and PROTO[member_of(lab, sw, others[0])[1]] != PROTO[mode]:
        raise devcli.CliError(f"Command rejected (Port-channel{n}, {short}): Invalid etherchnl mode")
    want = own.get(f"chproto:{port}", "")
    if want and PROTO[mode] and want != PROTO[mode].lower():
        raise devcli.CliError(f"Command rejected (Channel protocol mismatch for interface {short} in group {n}): "
                              f"the interface can not be added to the channel group")
    before = _states(lab, sw)
    made = n not in channels(lab, sw)
    own[f"chgrp:{port}"] = f"{n} {mode}"
    own[f"po:{n}"] = "yes"
    notes = []
    if made:
        notes.append(f"Creating a port-channel interface Port-channel {n}")
        if PROTO[mode] == "PAgP":
            notes.append(PAGP_NOTE)
    out = _done(con, before)
    return "\n".join(x for x in notes + [out] if x)


def no_group(con) -> str:
    port = con.s.ctx
    lab, sw = con.lab, _sw(con)
    n, _ = member_of(lab, sw, port)
    if not n:
        return ""
    own = devcli.settings(lab, con.device)
    before = _states(lab, sw)
    own.pop(f"chgrp:{port}", None)   # an err-disabled port-channel stays so: shutdown / no shutdown clears it
    return _done(con, before)


def set_protocol(con, text: str) -> str:
    port = con.s.ctx
    own = devcli.settings(con.lab, con.device)
    if not text:
        own.pop(f"chproto:{port}", None)
        con._save(live=False)
        return ""
    want = _pick(text, ("lacp", "pagp"), f"channel-protocol {text}")
    _, mode = member_of(con.lab, _sw(con), port)
    if mode and PROTO[mode] and PROTO[mode].lower() != want:
        raise devcli.CliError(f"Command rejected: the interface {devcli.short_if(port)} is already part of a "
                              f"channel with a different type of protocol enabled")
    own[f"chproto:{port}"] = want
    con._save(live=False)
    return ""


def po_shutdown(con, n: int, down: bool) -> str:
    lab, sw = con.lab, _sw(con)
    own = devcli.settings(lab, con.device)
    before = _states(lab, sw)
    if down:
        own[f"po-shut:{n}"] = "yes"
    else:
        own.pop(f"po-shut:{n}", None)
        own.pop(f"ec-err:{n}", None)    # shutdown / no shutdown: out of err-disabled
    out = _done(con, before)
    head = (f"%LINK-5-CHANGED: Interface Port-channel{n}, changed state to administratively down" if down else "")
    return "\n".join(x for x in (head, out) if x)


def remove(con, n: int) -> str:
    lab, sw = con.lab, _sw(con)
    if n not in channels(lab, sw):
        raise devcli.CliError("% Interface not found")
    own = devcli.settings(lab, con.device)
    before = _states(lab, sw)
    for p in groups(lab, sw).get(n, []):
        own.pop(f"chgrp:{p}", None)
    for k in (f"po:{n}", f"po-desc:{n}", f"po-shut:{n}", f"ec-err:{n}"):
        own.pop(k, None)
    return _done(con, before)


def set_lb(con, text: str) -> str:
    own = devcli.settings(con.lab, con.device)
    if not text.strip():
        own.pop("ec-lb", None)
    else:
        word = _pick(text, tuple(LB), f"port-channel load-balance {text}")
        if word == LB_DEFAULT:
            own.pop("ec-lb", None)
        else:
            own["ec-lb"] = word
    from . import stp
    return stp._done(con)


# ---- show
_FLAGS = ["Flags:  D - down        P - bundled in port-channel",
          "        I - stand-alone s - suspended",
          "        H - Hot-standby (LACP only)",
          "        R - Layer3      S - Layer2",
          "        U - in use      f - failed to allocate aggregator", "",
          "        M - not in use, minimum links not met",
          "        u - unsuitable for bundling",
          "        w - waiting to be aggregated",
          "        d - default port", ""]


def _flags(con) -> tuple[State, dict]:
    try:
        plugged = plugged_ports(con.lab, con.plan)
    except Exception:  # a lab mid-edit: take the machine ports as plugged
        plugged = None
    st = compute(con.lab, plugged)
    flags = dict(st.flags)
    data = _live(con)
    if data:
        flags.update({k: v for k, v in live_flags(con.lab, data).items() if flags.get(k) == "P"})
    flags.update({k: pagp_flag(v) for k, v in _pagp_live(con).items()})
    return st, flags


def pagp_flag(entry: dict) -> str:
    """A port's flag from winlab-pagpd's state: P bundled (in the bond), w
    agreed but not yet in the bond, I stand-alone, s suspended, D down."""
    state = entry.get("state", "D")
    if state == "P":
        return "P" if entry.get("bundled") else "w"
    return state if state in ("I", "s", "D") else "D"


def parse_pagp(text: str) -> dict:
    """winlab-pagpd's state file: {(switch, port): its entry}."""
    import json
    try:
        data = json.loads(text or "")
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {(p.get("switch", ""), p.get("port", "")): p for p in data.get("ports", []) if isinstance(p, dict)}


def _pagp_live(con) -> dict:
    """The speaker's state for this switch's ports, while the router runs."""
    lab, sw = con.lab, _sw(con)
    if not con.powered() or not any(PROTO.get(mode_of(lab, sw, n)) == "PAgP" for n in groups(lab, sw)):
        return {}
    try:
        got = parse_pagp(con._on_router(f"cat {SPEAKER_STATE} 2>/dev/null", timeout=15))
    except devcli.CliError:
        return {}
    return {k: v for k, v in got.items() if k[0] == sw}


def show_summary(con) -> str:
    lab, sw = con.lab, _sw(con)
    st, flags = _flags(con)
    grp = groups(lab, sw)
    chans = channels(lab, sw)
    out = list(_FLAGS) + ["", f"Number of channel-groups in use: {len(chans)}",
                          f"Number of aggregators:           {len(chans)}", "",
                          "Group  Port-channel  Protocol    Ports",
                          "------+-------------+-----------+-----------------------------------------------"]
    for n in chans:
        members = grp.get(n, [])
        pf = "SD" if (sw, n) in st.err else ("SU" if any(flags.get((sw, p)) == "P" for p in members) else "SD")
        proto = PROTO.get(mode_of(lab, sw, n), "") or "-"
        ports = "  ".join(f"{devcli.short_if(p)}({flags.get((sw, p), 'D')})" for p in members)
        out.append(f"{n:<7}{f'Po{n}({pf})':<14}{proto:<12}{ports}".rstrip())
    if any(PROTO.get(mode_of(lab, sw, n)) == "PAgP" for n in chans):
        out += ["", PAGP_NOTE]
    return "\n".join(out)


def show_listing(con) -> str:
    lab, sw = con.lab, _sw(con)
    out = ["                Channel-group listing:", "                ----------------------", ""]
    for n in channels(lab, sw):
        members = groups(lab, sw).get(n, [])
        out += [f"Group: {n}", "----------", "Group state = L2", f"Ports: {len(members)}   Maxports = 8",
                "Port-channels: 1 Max Port-channels = 1",
                f"Protocol:   {PROTO.get(mode_of(lab, sw, n), '') or '-'}", "Minimum Links: 0", ""]
    return "\n".join(out).rstrip()


def show_detail(con) -> str:
    lab, sw = con.lab, _sw(con)
    st, flags = _flags(con)
    out = []
    for n in channels(lab, sw):
        members = groups(lab, sw).get(n, [])
        mode = mode_of(lab, sw, n)
        up = [p for p in members if flags.get((sw, p)) == "P"]
        out += [f"Group: {n}", "----------", "Group state = L2", f"Ports: {len(members)}   Maxports = 8",
                f"Protocol:   {PROTO.get(mode, '') or '-'}", "                Ports in the group:",
                "                -------------------"]
        for p in members:
            f = flags.get((sw, p), "D")
            far = st.far.get((sw, p))
            state = {"P": "Up Mstr Assoc In-Bndl", "I": "Up Indep", "s": "Up Susp", "D": "Down",
                     "w": "Up Waiting"}.get(f, "Down")
            out += [f"Port: {devcli.short_if(p)}", "------------", "",
                    f"Port state    = {state}",
                    f"Channel group = {n}           Mode = {member_of(lab, sw, p)[1].capitalize()}",
                    f"Port-channel  = {'Po' + str(n) if f == 'P' else 'null'}",
                    f"Protocol      = {PROTO.get(member_of(lab, sw, p)[1], '') or '-'}"]
            if far and f == "P":
                out.append(f"Partner       = {devcli.hostname(lab, 'sw:' + far[0])} {devcli.short_if(far[1])} "
                           f"(system {devcli.dotted_mac(_bridge_mac(lab, far[0]))})")
            out.append("")
        pf = st.po_flag(sw, n, members) if (sw, n) not in st.err else "SD"
        out += ["                Port-channels in the group:", "                ---------------------------", "",
                f"Port-channel: Po{n}    ({'Primary Aggregator' if PROTO.get(mode) == 'LACP' else 'Primary aggregator'})",
                "------------", "",
                f"Age of the Port-channel   = never" if pf == "SD" else "Age of the Port-channel   = up",
                "Logical slot/port   = 2/" + str(n) + f"          Number of ports = {len(up)}",
                f"Port state          = {'Port-channel Ag-Inuse' if pf == 'SU' else 'Port-channel Ag-Not-Inuse'}",
                f"Protocol            = {PROTO.get(mode, '') or '-'}",
                f"Load share          = {lb(lab, sw)} (Linux bonding: xmit_hash_policy {LB[lb(lab, sw)]})", ""]
    return "\n".join(out).rstrip() or "% No channel groups are configured"


def _bridge_mac(lab, sw: str) -> str:
    from . import stp
    return stp.bridge_mac(lab, sw)


def show_lb(con) -> str:
    m = lb(con.lab, _sw(con))
    used = LB_WORDS[m]
    nonip = used if "MAC" in used else "Source XOR Destination MAC address" if m == "src-dst-ip" else \
        "Source MAC address" if m == "src-ip" else "Destination MAC address"
    return "\n".join(["EtherChannel Load-Balancing Configuration:", f"        {m}", "",
                      "EtherChannel Load-Balancing Addresses Used Per-Protocol:",
                      f"Non-IP: {nonip}", f"  IPv4: {used}", f"  IPv6: {used}"])


def show_lacp(con) -> str:
    lab, sw = con.lab, _sw(con)
    st, flags = _flags(con)
    out = ["Flags:  S - Device is requesting Slow LACPDUs", "        F - Device is requesting Fast LACPDUs",
           "        A - Device is in Active mode       P - Device is in Passive mode", ""]
    for n in channels(lab, sw):
        if PROTO.get(mode_of(lab, sw, n)) != "LACP":
            continue
        out += [f"Channel group {n} neighbors", "", "Partner's information:", "",
                "                  LACP port                        Admin  Oper   Port    Port",
                "Port      Flags   Priority  Dev ID          Age    key    Key    Number  State"]
        for p in groups(lab, sw).get(n, []):
            far = st.far.get((sw, p))
            if not far or flags.get((sw, p)) not in ("P", "s"):
                continue
            fm = member_of(lab, *far)[1]
            if PROTO.get(fm) != "LACP":
                continue
            fl = "F" + ("A" if fm == "active" else "P")
            num = 0x100 + 24 + int(re.search(r"(\d+)$", far[1]).group(1))
            out.append(f"{devcli.short_if(p):<10}{fl:<8}{32768:<10}{devcli.dotted_mac(_bridge_mac(lab, far[0])):<16}"
                       f"{'1s':<7}{'0x0':<7}{'0x' + format(member_of(lab, *far)[0], 'X'):<7}{hex(num):<8}"
                       f"{'0x3D' if flags.get((sw, p)) == 'P' else '0x45'}")
        out.append("")
    return "\n".join(out).rstrip()


def show_sysid(con) -> str:
    return f"32768, {devcli.dotted_mac(_bridge_mac(con.lab, _sw(con)))}"


def show_pagp(con) -> str:
    lab, sw = con.lab, _sw(con)
    st, flags = _flags(con)
    live = _pagp_live(con)
    out = ["Flags:  S - Device is sending Slow hello.  C - Device is in Consistent state.",
           "        A - Device is in Auto mode.        P - Device learns on physical port.", ""]
    for n in channels(lab, sw):
        if PROTO.get(mode_of(lab, sw, n)) != "PAgP":
            continue
        out += [f"Channel group {n} neighbors",
                "          Partner              Partner          Partner         Partner Group",
                "Port      Name                 Device ID        Port       Age  Flags   Cap."]
        for p in groups(lab, sw).get(n, []):
            if live:
                nb = (live.get((sw, p)) or {}).get("neighbor")
                if not nb:
                    continue
                f = int(nb.get("flags", 0))
                from . import pagpd
                fl = ("S" if f & pagpd.F_SLOW else "") + ("C" if f & pagpd.F_CONSISTENT else "") + \
                     ("A" if f & pagpd.F_AUTO else "") + "P"
                out.append(f"{devcli.short_if(p):<10}{str(nb.get('name', ''))[:20]:<21}"
                           f"{devcli.dotted_mac(str(nb.get('device_id', ''))):<17}{str(nb.get('port', ''))[:10]:<11}"
                           f"{str(int(float(nb.get('age', 0)))) + 's':<5}{fl:<8}{format(int(nb.get('group_cap', 0)), 'X')}")
                continue
            far = st.far.get((sw, p))
            if not far or PROTO.get(member_of(lab, *far)[1]) != "PAgP" or flags.get((sw, p)) == "D":
                continue
            fm = member_of(lab, *far)[1]
            if fm == "auto" and member_of(lab, sw, p)[1] == "auto":
                continue      # neither end asks: an auto port never hears from an auto port
            fl = "SC" + ("A" if fm == "auto" else "") + "P"
            out.append(f"{devcli.short_if(p):<10}{devcli.hostname(lab, 'sw:' + far[0])[:20]:<21}"
                       f"{devcli.dotted_mac(_bridge_mac(lab, far[0])):<17}{devcli.short_if(far[1]):<11}"
                       f"{'1s':<5}{fl:<8}{format(member_of(lab, *far)[0], 'X')}")
        out.append("")
    out.append("! read from winlab-pagpd on the lab router" if live else
               "! the router is off: what PAgP's rules predict (winlab-pagpd speaks it when the router runs)")
    out.append(PAGP_NOTE)
    return "\n".join(out)


def show_iface(con, text: str) -> str:
    n = po_number(text)
    lab, sw = con.lab, _sw(con)
    if n not in channels(lab, sw):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    st, flags = _flags(con)
    own = _own(lab, sw)
    members = groups(lab, sw).get(n, [])
    up = [p for p in members if flags.get((sw, p)) == "P"]
    if own.get(f"po-shut:{n}"):
        head = f"Port-channel{n} is administratively down, line protocol is down (disabled)"
    elif (sw, n) in st.err:
        head = f"Port-channel{n} is down, line protocol is down (err-disabled)"
    elif up and con.powered():
        head = f"Port-channel{n} is up, line protocol is up (connected)"
    else:
        head = f"Port-channel{n} is down, line protocol is down (notconnect)"
    mac = devcli.dotted_mac(_bridge_mac(lab, sw))
    out = [head, f"  Hardware is EtherChannel, address is {mac} (bia {mac})"]
    if own.get(f"po-desc:{n}"):
        out.append(f"  Description: {own[f'po-desc:{n}']}")
    out += [f"  MTU 1500 bytes, BW {1000000 * max(1, len(up))} Kbit/sec, DLY 10 usec,",
            "     reliability 255/255, txload 1/255, rxload 1/255", "  Encapsulation ARPA, loopback not set",
            "  Keepalive set (10 sec)", "  Full-duplex, 1000Mb/s, link type is auto, media type is unknown",
            "  input flow-control is off, output flow-control is unsupported"]
    if up:
        out.append("  Members in this channel: " + " ".join(devcli.short_if(p) for p in up))
    out += ["  ARP type: ARPA, ARP Timeout 04:00:00", "  Last input never, output never, output hang never"]
    return "\n".join(out)


def run_lines(lab, sw: str) -> tuple[list[str], dict[str, list[str]], list[str]]:
    """show running-config: (global lines, {port: lines under it}, the port-channel interfaces)."""
    own = _own(lab, sw)
    glob = [f"port-channel load-balance {own['ec-lb']}"] if own.get("ec-lb") else []
    under: dict[str, list[str]] = {}
    for n, ports in groups(lab, sw).items():
        for p in ports:
            lines = []
            if own.get(f"chproto:{p}"):
                lines.append(f" channel-protocol {own[f'chproto:{p}']}")
            lines.append(f" channel-group {n} mode {member_of(lab, sw, p)[1]}")
            under[p] = lines
    for k, v in own.items():
        if k.startswith("chproto:") and k[8:] not in under:
            under[k[8:]] = [f" channel-protocol {v}"]
    pos = []
    for n in channels(lab, sw):
        pos.append(f"interface Port-channel{n}")
        if own.get(f"po-desc:{n}"):
            pos.append(f" description {own[f'po-desc:{n}']}")
        members = groups(lab, sw).get(n, [])
        if members and all(p.startswith("Gigabit") for p in members):
            pos.append(" switchport mode trunk")
        if own.get(f"po-shut:{n}"):
            pos.append(" shutdown")
        pos.append("!")
    return glob, under, pos
