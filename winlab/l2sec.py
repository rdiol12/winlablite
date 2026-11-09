"""Private VLANs, storm control, IPv6 RA guard, DHCPv6 guard and IPv6 port
ACLs on the workbench's switches.

* Private VLANs split one VLAN (the primary, which keeps the subnet and the
  gateway) into secondary VLANs: an isolated one, whose ports reach only the
  promiscuous ports, and community ones, whose ports reach each other and
  the promiscuous ports. ``vlan <n>`` then ``private-vlan primary |
  isolated | community`` and ``private-vlan association <list>`` under the
  primary; on a port ``switchport mode private-vlan host`` with
  ``switchport private-vlan host-association <primary> <secondary>``, or
  ``switchport mode private-vlan promiscuous`` with ``switchport
  private-vlan mapping <primary> <list>``. The router's own address in the
  primary VLAN is always reachable: it is the gateway, on the promiscuous
  side, as a router on a promiscuous port is. A host port whose association
  is not complete (the primary not primary, the secondary not associated)
  is inactive and passes nothing, as on a Catalyst.
* Storm control: ``storm-control broadcast | multicast | unicast level
  <percent> | pps <n> | bps <n>`` on an access port, and ``storm-control
  action shutdown | trap``. Over the level, the excess is dropped; with
  shutdown the port is err-disabled (cause storm-control, which errdisable
  recovery knows), with trap the switch logs it (and its SNMP traps, if
  set, carry that log line: winlab/nms.py).
* RA guard: ``ipv6 nd raguard policy <name>`` (``device-role host |
  router``, ``trusted-port``) and ``ipv6 nd raguard attach-policy
  [<name>]`` on a port: router advertisements and redirects that come in on
  a host port are dropped, so a box that advertises itself as a router
  (a home router, a misconfigured server) cannot become the PCs' IPv6
  gateway. On Gi0/1 of a switch cabled to the router a host policy drops the
  router's own advertisements towards the switch's ports (a mistake the
  troubleshooting lesson makes).
* DHCPv6 guard: ``ipv6 dhcp guard policy <name>`` (``device-role client |
  server``, ``trusted-port``) and ``ipv6 dhcp guard attach-policy
  [<name>]``: DHCPv6 server and relay messages (from UDP port 547) that come
  in on a client port are dropped.
* IPv6 port ACLs: ``ipv6 traffic-filter <list> in`` on an access port, the
  lists of winlab/acl6.py.

How it is real. Every machine's cable is a port of the router's bridge
(winlab/netplan.py), and port security already keeps an nftables table of
the bridge family for the switches' ports (portsec.TABLE). This module adds
its rules to that table through the same render and live path, the way DHCP
snooping does (render() returns the parts portsec.render puts in place):

* private VLANs are a base chain on the bridge's forward hook: for each
  port in a private VLAN, a rule that drops what it sends to the ports it
  may not reach (the bridge's forward hook sees each copy of a flooded
  frame with its output port, so broadcasts are filtered too). The ports are
  grouped by the bridge VLAN they are in, so an isolated port on one switch
  cannot reach an isolated port on another switch across the trunk either.
* storm control is nftables' limit (a token bucket, what tc police is) on
  the frames that come in on the port, by destination address (broadcast,
  multicast, unicast), with a counter of what it dropped. A port's tc slot
  (ingress / clsact) is taken by speed and duplex (winlab/iosl2.py) and the
  visitor's laptop (portsec), so the policer is in the table. With action
  shutdown a watcher on the router disables the bridge port the moment the
  counter moves (WATCH_SH) and leaves a file the app reads back
  (live_cmd), then err-disables the port in the switch's configuration and
  takes the machine's link down, as port security's shutdown does.
* RA guard and DHCPv6 guard are rules on the port's incoming ICMPv6 type
  134 and 137, and UDP from port 547; RA guard on the uplink is a rule in
  the table's output chain, on what the router's bridge sends to the
  switch's ports.
* a port ACL is a jump to a chain of the list's entries (acl6.chain_body),
  each with its counter; a permit returns to the port chain, so port
  security and the rest still run after it.

Settings ([devices."sw:<id>"]): ``pvlan:<vlan>`` = primary | isolated |
community; ``pvlan-assoc:<vlan>`` = the secondary VLANs; per port (the
cable's label, as port security keys them, or the port's name):
``pvlan-mode:`` = host | promiscuous, ``pvlan-host:`` = "<primary>
<secondary>", ``pvlan-map:`` = "<primary> <list>", ``storm-b:``,
``storm-m:``, ``storm-u:`` = "<rising> [<falling>]" or "pps <n> [<n>]" or
"bps <n> [<n>]", ``storm-act:`` = "shutdown" and/or "trap",
``raguard-port:``, ``d6guard-port:`` = a policy's name, ``acl6-in:``;
per policy ``raguard:<name>`` = host | router (``raguard-trust:<name>``),
``d6guard:<name>`` = client | server (``d6guard-trust:<name>``).
"""

from __future__ import annotations

import re

from . import devcli

CAUSE = "storm-control"
KINDS = {"b": "broadcast", "m": "multicast", "u": "unicast"}
FIELDS = ("pvlan-mode", "pvlan-host", "pvlan-map", "storm-b", "storm-m", "storm-u", "storm-act",
          "raguard-port", "d6guard-port", "acl6-in")
PORT_RATE = 100_000_000      # a FastEthernet port, bit/s: what a percentage level is of
UPLINK = "GigabitEthernet0/1"
PV_TYPES = ("primary", "isolated", "community")
DEFAULT_POLICY = "default"


def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


def _ifname(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


# ------------------------------------------------------------------ private VLANs
def pv_type(own: dict, tag: int) -> str:
    return own.get(f"pvlan:{tag}", "")


def assoc(own: dict, tag: int) -> set[int]:
    try:
        return devcli.vlan_set(own.get(f"pvlan-assoc:{tag}", "")) or set()
    except ValueError:
        return set()


def _pair(text: str) -> tuple[int, set[int]]:
    w = (text or "").split()
    try:
        return int(w[0]), (devcli.vlan_set(w[1]) or set()) if len(w) > 1 else set()
    except (ValueError, IndexError):
        return 0, set()


def port_role(lab, sw: str, key: str, tag: int) -> tuple[str, int, set[int]]:
    """(role, primary, secondaries) of a port in VLAN `tag`: role is
    "normal", "isolated", "community", "promiscuous" or "inactive"; for a
    host port its one secondary, for a promiscuous port the ones it maps."""
    own = _own(lab, sw)
    mode = own.get(f"pvlan-mode:{key}", "")
    if mode == "host":
        p, ss = _pair(own.get(f"pvlan-host:{key}", ""))
        s = min(ss) if len(ss) == 1 else 0
        if (p == tag and pv_type(own, p) == "primary" and s in assoc(own, p)
                and pv_type(own, s) in ("isolated", "community")):
            return pv_type(own, s), p, {s}
        return "inactive", p, ({s} if s else set())
    if mode == "promiscuous":
        p, ss = _pair(own.get(f"pvlan-map:{key}", ""))
        if p != tag or pv_type(own, p) != "primary":
            return "inactive", p, ss
        ok = {s for s in ss if s in assoc(own, p) and pv_type(own, s) in ("isolated", "community")}
        return "promiscuous", p, ok
    return "normal", 0, set()


def reach(a: tuple, b: tuple) -> bool:
    """Whether two ports of one bridge VLAN may exchange frames, by their
    (role, primary, secondaries)."""
    ra, rb = a[0], b[0]
    if "inactive" in (ra, rb):
        return False
    hosts = ("isolated", "community")
    if ra not in hosts and rb not in hosts:
        return True               # normal and promiscuous ports are all in the primary VLAN
    if ra in hosts and rb in hosts:
        return ra == rb == "community" and a[2] == b[2]
    host, other = (a, b) if ra in hosts else (b, a)
    return other[0] == "promiscuous" and bool(host[2] & other[2])


def _ports(lab, plan) -> list:
    from . import portsec
    return [p for p in portsec.all_ports(lab, plan) if p.iface]


def _tag(lab, link) -> int:
    net = lab.networks.get(link.network_id)
    return net.vlan_no if net is not None else 1


def pv_active(lab) -> bool:
    return any(k.startswith(("pvlan-mode:",)) for sw in devcli.switches(lab) for k in _own(lab, sw))


def pv_roles(lab, plan) -> dict:
    """{port iface: (role, primary, secondaries, port)} for every machine port."""
    return {p.iface: port_role(lab, p.sw, p.key, _tag(lab, p.link)) + (p,) for p in _ports(lab, plan)}


# ------------------------------------------------------------------ storm control
def level(text: str) -> tuple[str, float, float]:
    """A kept level -> (unit "%" | "pps" | "bps", rising, falling)."""
    w = (text or "").split()
    unit = "%"
    if w and w[0] in ("pps", "bps"):
        unit, w = w[0], w[1:]
    try:
        rise = float(w[0])
        fall = float(w[1]) if len(w) > 1 else rise
    except (ValueError, IndexError):
        return "", 0.0, 0.0
    return unit, rise, fall


def _num(t: str) -> float:
    """1000, 1k, 10m, 1g (IOS's bps and pps suffixes)."""
    m = re.match(r"^(\d+(?:\.\d+)?)([kmg]?)$", t.lower())
    if not m:
        raise ValueError(t)
    return float(m.group(1)) * {"": 1, "k": 1e3, "m": 1e6, "g": 1e9}[m.group(2)]


def parse_level(text: str) -> str:
    """'1.00', '1.00 0.50', 'pps 500 [400]', 'bps 10m [5m]' -> the kept form."""
    w = text.lower().split()
    unit = ""
    if w and w[0] in ("pps", "bps"):
        unit, w = w[0], w[1:]
    if not 1 <= len(w) <= 2:
        raise devcli.CliError("% Invalid input: storm-control ... level <0.00-100.00> [<falling>] | "
                              "pps <rising> [<falling>] | bps <rising> [<falling>]")
    try:
        vals = [_num(x) if unit else float(x) for x in w]
    except ValueError:
        raise devcli.CliError("% Invalid input: a level is a number") from None
    if not unit and not all(0 <= v <= 100 for v in vals):
        raise devcli.CliError("% A level in percent is 0.00 to 100.00 of the port's bandwidth")
    if unit and not all(0 <= v <= 1e10 for v in vals):
        raise devcli.CliError("% Rate out of range")
    if len(vals) == 2 and vals[1] > vals[0]:
        raise devcli.CliError("% The falling threshold cannot be above the rising one")
    fmt = (lambda v: f"{v:.2f}") if not unit else (lambda v: str(int(v)))
    return " ".join(([unit] if unit else []) + [fmt(v) for v in vals])


def show_level(unit: str, v: float) -> str:
    if unit == "%":
        return f"{v:.2f}%"
    n = int(v)
    for div, suf in ((1e9, "g"), (1e6, "m"), (1e3, "k")):
        if n >= div and n % int(div) == 0:
            return f"{int(n // div)}{suf}{unit}"
    return f"{n}{unit}"


def nft_limit(text: str) -> str:
    """A level as an nftables limit on what exceeds it ("" when every frame
    of the kind is dropped: level 0)."""
    unit, rise, _ = level(text)
    if unit == "pps":
        n = max(1, int(rise))
        return f"limit rate over {n}/second burst {n} packets " if rise > 0 else ""
    bps = rise / 100 * PORT_RATE if unit == "%" else rise
    if bps <= 0:
        return ""
    b = max(1, int(bps / 8))
    return f"limit rate over {b} bytes/second burst {max(b, 1600)} bytes "


_MATCH = {"b": "ether daddr ff:ff:ff:ff:ff:ff ",
          "m": "ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 ether daddr != ff:ff:ff:ff:ff:ff ",
          "u": "ether daddr & 01:00:00:00:00:00 == 00:00:00:00:00:00 "}


def actions(own: dict, key: str) -> set[str]:
    return set(own.get(f"storm-act:{key}", "").split())


def storm_active(lab) -> bool:
    return any(k.startswith(("storm-b:", "storm-m:", "storm-u:")) for sw in devcli.switches(lab)
               for k in _own(lab, sw))


# ------------------------------------------------------------------ RA guard, DHCPv6 guard
def policy_role(own: dict, kind: str, name: str) -> str:
    """The device role a port's attached policy gives it ("" when trusted)."""
    if own.get(f"{kind}-trust:{name}"):
        return ""
    if name == DEFAULT_POLICY and f"{kind}:{name}" not in own:
        return "host" if kind == "raguard" else "client"
    return own.get(f"{kind}:{name}", "host" if kind == "raguard" else "client")


def guard_active(lab) -> bool:
    return any(k.startswith(("raguard-port:", "d6guard-port:", "acl6-in:")) for sw in devcli.switches(lab)
               for k in _own(lab, sw))


def active(lab) -> bool:
    return pv_active(lab) or storm_active(lab) or guard_active(lab)


# ------------------------------------------------------------------ the router
WATCH_SH = """#!/bin/sh
# Storm control's shutdown (winlab/l2sec.py): the moment a port's storm
# counter moves, its bridge port is disabled: err-disabled.
R={run}
while :; do
  for p in {ports}; do
    [ -e $R/$p.storm ] && continue
    for k in b m u; do
      n=$(nft list counter bridge {table} storm_${{k}}_$p 2>/dev/null | sed -n 's/.*packets \\([0-9]*\\).*/\\1/p')
      if [ "${{n:-0}}" -gt 0 ]; then
        bridge link set dev $p state 0
        echo "$(date +%s) $k" > $R/$p.storm
        echo "$(date +%s) $p {cause} $k" >> $R/events
        break
      fi
    done
  done
  sleep 1
done
"""


def render(plan, run: str, table: str) -> dict:
    """This module's parts of the port table (portsec.render puts them in
    place): {"pre", "sets", "rules" (the ports chain), "local" (the output
    chain), "chains" (whole chains of their own), "post"}."""
    lab = plan.lab
    stop = (f"[ -f {run}/storm-watch.pid ] && kill $(cat {run}/storm-watch.pid) 2>/dev/null; "
            f"rm -f {run}/*.storm {run}/storm-watch.pid; true")
    parts = {"pre": [stop], "sets": [], "rules": [], "local": [], "chains": [], "post": []}
    if not active(lab):
        return parts
    sets, rules, local, chains = parts["sets"], parts["rules"], parts["local"], parts["chains"]
    ports = _ports(lab, plan)
    shut = []
    for p in ports:
        own, i, k = _own(lab, p.sw), p.iface, p.key
        tag = f"   # {devcli.hostname(lab, 'sw:' + p.sw)} {p.short} ({p.label})"
        # storm control: the excess of each kind is dropped and counted
        for kind in KINDS:
            lv = own.get(f"storm-{kind}:{k}")
            if not lv:
                continue
            sets.append(f"  counter storm_{kind}_{i} {{ }}{tag}: storm-control {KINDS[kind]} level {lv}")
            rules.append(f"    iifname \"{i}\" {_MATCH[kind]}{nft_limit(lv)}counter name storm_{kind}_{i} drop")
            if "shutdown" in actions(own, k) and not p.err and i not in shut:
                shut.append(i)
        # RA guard and DHCPv6 guard on the port
        rg = own.get(f"raguard-port:{k}")
        if rg and policy_role(own, "raguard", rg) == "host":
            sets.append(f"  counter rag_{i} {{ }}{tag}: RA guard ({rg}), device-role host")
            rules.append(f"    iifname \"{i}\" ether type ip6 meta l4proto ipv6-icmp icmpv6 type "
                         f"{{ nd-router-advert, nd-redirect }} counter name rag_{i} drop")
        dg = own.get(f"d6guard-port:{k}")
        if dg and policy_role(own, "d6guard", dg) == "client":
            sets.append(f"  counter d6g_{i} {{ }}{tag}: DHCPv6 guard ({dg}), device-role client")
            rules.append(f"    iifname \"{i}\" ether type ip6 meta l4proto udp udp sport 547 counter name d6g_{i} drop")
        # an IPv6 port ACL
        acl = own.get(f"acl6-in:{k}")
        from . import acl6
        if acl and acl6.exists(own, acl):
            ch = f"acl6_{_ifname(p.sw)}_{_ifname(acl)}"
            if not any(c[0] == f"  chain {ch} {{" for c in chains):
                chains.append([f"  chain {ch} {{"] + [f"    {r}" for r in acl6.chain_body(own, acl, "return")]
                              + ["  }"])
            rules.append(f"    iifname \"{i}\" ether type ip6 jump {ch}{tag}: ipv6 traffic-filter {acl} in")
    # RA guard on the uplink to the router: the router's own advertisements
    for sw in devcli.switches(lab):
        own = _own(lab, sw)
        rg = own.get(f"raguard-port:{UPLINK}")
        mine = [p.iface for p in ports if p.sw == sw]
        if rg and mine and devcli.uplinked(lab, sw) and policy_role(own, "raguard", rg) == "host":
            n = _ifname(sw)
            sets.append(f"  counter ragup_{n} {{ }}   # {devcli.hostname(lab, 'sw:' + sw)}: RA guard ({rg}, "
                        f"device-role host) on Gi0/1, the router's own advertisements")
            local.append(f"    oifname {{ {', '.join(chr(34) + i + chr(34) for i in mine)} }} ether type ip6 "
                         f"meta l4proto ipv6-icmp icmpv6 type {{ nd-router-advert, nd-redirect }} "
                         f"counter name ragup_{n} drop")
    # private VLANs: what each port may not reach, on the bridge's forward hook
    if pv_active(lab):
        roles = pv_roles(lab, plan)
        body = []
        by_vid: dict[int, list[str]] = {}
        for i, r in roles.items():
            by_vid.setdefault(plan.vid_of(r[3].link), []).append(i)
        for vid, members in sorted(by_vid.items()):
            for i in members:
                r = roles[i]
                if r[0] == "normal" and all(roles[j][0] == "normal" for j in members):
                    continue
                p = r[3]
                tag = f"   # {devcli.hostname(lab, 'sw:' + p.sw)} {p.short} ({p.label}) {r[0]}"
                if r[0] == "inactive":
                    sets.append(f"  counter pvl_{i} {{ }}{tag}: no valid private-VLAN association")
                    body += [f"    iifname \"{i}\" counter name pvl_{i} drop",
                             f"    oifname \"{i}\" counter name pvl_{i} drop"]
                    continue
                blocked = [j for j in members if j != i and not reach(r, roles[j]) and roles[j][0] != "inactive"]
                if blocked:
                    sets.append(f"  counter pvl_{i} {{ }}{tag}")
                    body.append(f"    iifname \"{i}\" oifname {{ {', '.join(chr(34) + j + chr(34) for j in blocked)} }} "
                                f"counter name pvl_{i} drop")
        if body:
            chains.append(["  chain pvlan {", "    type filter hook forward priority -200; policy accept;"]
                          + body + ["  }"])
    if shut:
        parts["post"] += [f"cat > {run}/storm-watch.sh <<'WINLAB_EOF'",
                          WATCH_SH.format(run=run, ports=" ".join(shut), table=table, cause=CAUSE).rstrip("\n"),
                          "WINLAB_EOF", f"chmod +x {run}/storm-watch.sh",
                          f"setsid {run}/storm-watch.sh >/dev/null 2>&1 </dev/null & echo $! > {run}/storm-watch.pid"]
    return parts


def live_cmd(run: str) -> str:
    return f"echo '#storm'; for f in {run}/*.storm; do [ -e \"$f\" ] && echo \"$(basename $f .storm) $(cat $f)\"; done; "


def parse(storm: list[str], nft: str) -> dict:
    """{"storm": {iface: (when, kind)}, "count": {counter name: packets}}."""
    st = {}
    for line in storm:
        w = line.split()
        if len(w) >= 3 and w[1].isdigit():
            st[w[0]] = (int(w[1]), w[2])
    count = {m.group(1): int(m.group(2)) for m in
             re.finditer(r"counter ((?:storm_[bmu]|rag|ragup|d6g|pvl)_\w+) \{\s*packets (\d+)", nft or "")}
    return {"storm": st, "count": count}


# ------------------------------------------------------------------ settling what the router says
def _storm_lines(p, kind: str, shutdown: bool) -> list[str]:
    s = p.short
    if shutdown:
        return [f"%STORM_CONTROL-3-SHUTDOWN: A packet storm was detected on {s}. The interface has been disabled.",
                f"%PM-4-ERR_DISABLE: {CAUSE} error detected on {s}, putting {s} in err-disable state",
                f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {p.name}, changed state to down",
                f"%LINK-3-UPDOWN: Interface {p.name}, changed state to down"]
    return [f"%STORM_CONTROL-3-FILTERED: A {KINDS[kind].capitalize()} storm detected on {s}. A packet filter "
            f"action has been applied on the interface."]


def settle(lab, plan, live: dict | None, rt: dict, now: float, said: dict, links: list) -> None:
    """A port the storm watcher disabled is err-disabled (storm-control);
    storms filtered and RAs, DHCPv6 answers and private-VLAN frames dropped
    since the last look go into the switch's log."""
    data = (live or {}).get("l2")
    if not data:
        return
    gen = (live or {}).get("psec", {}).get("gen", "")
    seen = rt.setdefault("l2c", {})
    handled = rt.setdefault("stormseen", {})
    for p in _ports(lab, plan):
        i, own = p.iface, lab.devices.setdefault(f"sw:{p.sw}", {})
        hit = data["storm"].get(i)
        if hit and handled.get(i) == hit[0]:
            pass   # what the watcher said before the port came back, not yet rebuilt
        elif hit and not p.err and not own.get(f"shut:{p.label}"):
            handled[i] = hit[0]
            own[f"psec-err:{p.label}"] = f"00:00:00:00:00:00 {int(now)} {CAUSE}"
            said.setdefault(p.sw, []).append("\n".join(_storm_lines(p, hit[1], True)))
            links.append((p.link, False))
            continue
        for name, c in data["count"].items():
            if not name.endswith(f"_{i}") or name.startswith("ragup_"):
                continue
            was = seen.get(name, [gen, 0])
            base = int(was[1]) if was[0] == gen else 0
            seen[name] = [gen, c]
            if c <= base:
                continue
            if name.startswith("storm_"):
                if "trap" in actions(own, p.key) or "shutdown" not in actions(own, p.key):
                    said.setdefault(p.sw, []).append(_storm_lines(p, name[6], False)[0])
            elif name.startswith("rag_"):
                said.setdefault(p.sw, []).append(
                    f"%SISF-4-PAK_DROP: Message dropped A={p.short} M=RA (RA guard: device-role host), "
                    f"{c - base} on {p.short}")
            elif name.startswith("d6g_"):
                said.setdefault(p.sw, []).append(
                    f"%SISF-4-PAK_DROP: Message dropped A={p.short} M=DHCPv6 server message (DHCPv6 guard: "
                    f"device-role client), {c - base} on {p.short}")


# ------------------------------------------------------------------ the console
WORDS = {
    ("private-vlan",): "Configure a private VLAN", ("switchport", "private-vlan"): "Set the private VLAN configuration",
    ("storm-control",): "storm configuration", ("storm-control", "broadcast"): "Broadcast address storm control",
    ("storm-control", "multicast"): "Multicast address storm control",
    ("storm-control", "unicast"): "Unicast address storm control",
    ("storm-control", "action"): "Action to take for storm-control",
    ("show", "storm-control"): "Show storm control configuration",
    ("show", "vlan", "private-vlan"): "Private VLAN information",
    ("ipv6", "nd", "raguard"): "RA guard", ("ipv6", "dhcp", "guard"): "Configure DHCPv6 guard",
    ("ipv6", "nd"): "IPv6 interface Neighbor Discovery subcommands", ("ipv6", "dhcp"): "IPv6 DHCP interface subcommands",
    ("show", "ipv6", "nd"): "Show Neighbor Discovery information",
    ("show", "ipv6", "dhcp"): "IPv6 DHCP",
}
RG, DG = ("config-ra-guard",), ("config-dhcp-guard",)


def add_specs(con, add, U, C, I, V) -> None:
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    devcli.MODE_PROMPTS.setdefault("config-ra-guard", "config-ra-guard")
    devcli.MODE_PROMPTS.setdefault("config-dhcp-guard", "config-dhcp-guard")
    # private VLANs
    for t, h in (("primary", "Configure the VLAN as a primary private VLAN"),
                 ("isolated", "Configure the VLAN as an isolated private VLAN"),
                 ("community", "Configure the VLAN as a community private VLAN")):
        add(f"private-vlan {t}", lambda a, t=t: _pv_type(con, t), h, V)
    add("no private-vlan <line>", lambda a: _pv_no(con, a[0]), "Negate a command or set its defaults", V)
    add("private-vlan association <line>", lambda a: _pv_assoc(con, a[0]), "Configure association between private VLANs", V)
    add("no private-vlan association", lambda a: _pv_assoc(con, ""), "Negate a command or set its defaults", V)
    add("switchport mode private-vlan <line>", lambda a: _pv_mode(con, a[0]), "Set private-vlan mode", I)
    add("switchport private-vlan host-association <num> <num>", lambda a: _pv_host(con, a[0], a[1]),
        "Set the private VLAN host association", I)
    add("no switchport private-vlan host-association", lambda a: _pv_clear(con, "pvlan-host"),
        "Negate a command or set its defaults", I)
    add("switchport private-vlan mapping <num> <line>", lambda a: _pv_map(con, a[0], a[1]),
        "Set the private VLAN promiscuous mapping", I)
    add("no switchport private-vlan mapping", lambda a: _pv_clear(con, "pvlan-map"),
        "Negate a command or set its defaults", I)
    add("show vlan private-vlan", lambda a: show_pvlan(con), "Private VLAN information", U)
    add("show vlan private-vlan type", lambda a: show_pvlan_type(con), "Private VLAN type", U)
    add("show interfaces private-vlan mapping", lambda a: show_pv_mapping(con), "Private VLAN mapping information", U)
    # storm control
    for kind, word in KINDS.items():
        add(f"storm-control {word} level <line>", lambda a, k=kind: _storm(con, k, a[0]),
            f"Set storm suppression level on this interface", I)
        add(f"no storm-control {word} level", lambda a, k=kind: _storm(con, k, ""),
            "Negate a command or set its defaults", I)
    add("storm-control action <line>", lambda a: _storm_act(con, a[0], True), "Action to take for storm-control", I)
    add("no storm-control action <line>", lambda a: _storm_act(con, a[0], False), "Negate a command or set its defaults", I)
    add("show storm-control", lambda a: show_storm(con, ""), "Show storm control configuration", U)
    add("show storm-control <line>", lambda a: show_storm(con, a[0]), "Show storm control configuration", U)
    # RA guard
    add("ipv6 nd raguard policy <name>", lambda a: _policy(con, "raguard", a[0]), "Define a RA guard policy", C + RG + DG)
    add("no ipv6 nd raguard policy <name>", lambda a: _no_policy(con, "raguard", a[0]), "Negate a command or set its defaults", C)
    add("device-role <line>", lambda a: _role(con, a[0], True), "Sets the role of the device attached to the port", RG + DG)
    add("no device-role", lambda a: _role(con, "", False), "Negate a command or set its defaults", RG + DG)
    add("trusted-port", lambda a: _trusted(con, True), "Setup trusted port", RG + DG)
    add("no trusted-port", lambda a: _trusted(con, False), "Negate a command or set its defaults", RG + DG)
    add("end", con._end, "Exit from configure mode", RG + DG)
    add("exit", con._cfg_exit, "Exit from policy configuration mode", RG + DG)
    add("do <line>", con._do, "To run exec commands in config mode", RG + DG)
    add("ipv6 nd raguard attach-policy", lambda a: _attach(con, "raguard", DEFAULT_POLICY, True), "Apply a policy", I)
    add("ipv6 nd raguard attach-policy <name>", lambda a: _attach(con, "raguard", a[0], True), "Apply a policy", I)
    add("no ipv6 nd raguard attach-policy", lambda a: _attach(con, "raguard", "", False), "Negate a command or set its defaults", I)
    add("no ipv6 nd raguard attach-policy <name>", lambda a: _attach(con, "raguard", "", False),
        "Negate a command or set its defaults", I)
    add("show ipv6 nd raguard policy", lambda a: show_policy(con, "raguard", ""), "RA guard policy", U)
    add("show ipv6 nd raguard policy <name>", lambda a: show_policy(con, "raguard", a[0]), "RA guard policy", U)
    # DHCPv6 guard
    add("ipv6 dhcp guard policy <name>", lambda a: _policy(con, "d6guard", a[0]), "Configure DHCPv6 guard policy", C + RG + DG)
    add("no ipv6 dhcp guard policy <name>", lambda a: _no_policy(con, "d6guard", a[0]), "Negate a command or set its defaults", C)
    add("ipv6 dhcp guard attach-policy", lambda a: _attach(con, "d6guard", DEFAULT_POLICY, True), "Apply a policy", I)
    add("ipv6 dhcp guard attach-policy <name>", lambda a: _attach(con, "d6guard", a[0], True), "Apply a policy", I)
    add("no ipv6 dhcp guard attach-policy", lambda a: _attach(con, "d6guard", "", False), "Negate a command or set its defaults", I)
    add("no ipv6 dhcp guard attach-policy <name>", lambda a: _attach(con, "d6guard", "", False),
        "Negate a command or set its defaults", I)
    add("show ipv6 dhcp guard policy", lambda a: show_policy(con, "d6guard", ""), "DHCPv6 guard policy", U)
    add("show ipv6 dhcp guard policy <name>", lambda a: show_policy(con, "d6guard", a[0]), "DHCPv6 guard policy", U)


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def _done(con, live: bool = True) -> str:
    from . import portsec
    return portsec.done(con, live)


def _key(con, gig_ok: bool = False) -> str:
    ctx = con.s.ctx
    if ctx.startswith("FastEthernet"):
        from . import portsec
        return portsec.write_key(con)
    if gig_ok and ctx == UPLINK:
        return ctx
    raise devcli.CliError("% This is set on an access port (Fa0/1 to Fa0/24)"
                          + (" or on Gi0/1, the uplink" if gig_ok else "") + ", not on "
                          + devcli.short_if(ctx))


# ---- private VLANs
def _vlan_here(con) -> int:
    return int(con.s.ctx)


def _pv_type(con, text: str) -> str:
    w = text.lower().split()
    if w and "association".startswith(w[0]) and len(w[0]) > 1:
        return _pv_assoc(con, " ".join(text.split()[1:]))
    hit = [t for t in PV_TYPES if w and t.startswith(w[0])]
    if len(w) != 1 or len(hit) != 1:
        raise devcli.CliError("% Invalid input: private-vlan primary | isolated | community | association <list>")
    tag = _vlan_here(con)
    if tag == 1 or tag >= 1002:
        raise devcli.CliError(f"% VLAN {tag} cannot be a private VLAN: 2 to 1001 only")
    own = _mine(con)
    if hit[0] != "primary" and own.get(f"pvlan-assoc:{tag}"):
        own.pop(f"pvlan-assoc:{tag}", None)
    own[f"pvlan:{tag}"] = hit[0]
    return _done(con)


def _pv_no(con, text: str) -> str:
    w = text.lower().split()
    if w and "association".startswith(w[0]) and len(w[0]) > 1:
        return _pv_assoc(con, "")
    tag = _vlan_here(con)
    own = _mine(con)
    own.pop(f"pvlan:{tag}", None)
    own.pop(f"pvlan-assoc:{tag}", None)
    return _done(con)


def _pv_assoc(con, text: str) -> str:
    tag = _vlan_here(con)
    own = _mine(con)
    if not text.strip():
        own.pop(f"pvlan-assoc:{tag}", None)
        return _done(con)
    if pv_type(own, tag) != "primary":
        raise devcli.CliError(f"% VLAN {tag} is not a primary VLAN: private-vlan primary first")
    try:
        want = devcli.edit_vlans(assoc(own, tag) or set(), text)
    except ValueError:
        raise devcli.CliError("% Invalid input: private-vlan association [add | remove] <list>") from None
    want = want or set()
    if any(s in (1, tag) or s >= 1002 for s in want):
        raise devcli.CliError("% A secondary VLAN is 2 to 1001, not the primary itself")
    if want:
        own[f"pvlan-assoc:{tag}"] = devcli.vlan_text(want)
    else:
        own.pop(f"pvlan-assoc:{tag}", None)
    out = _done(con)
    odd = sorted(s for s in want if pv_type(own, s) not in ("isolated", "community"))
    if odd:
        out = (out + "\n" if out else "") + (f"% VLAN {devcli.vlan_text(set(odd))} is not yet an isolated or "
                                             f"community VLAN: the association takes effect once it is")
    return out


def _pv_mode(con, text: str) -> str:
    w = text.lower().split()
    hit = [m for m in ("host", "promiscuous") if len(w) == 1 and m.startswith(w[0])]
    if len(hit) != 1:
        raise devcli.CliError("% Invalid input: switchport mode private-vlan host | promiscuous")
    key = _key(con)
    _mine(con)[f"pvlan-mode:{key}"] = hit[0]
    out = _done(con)
    need = "host-association" if hit[0] == "host" else "mapping"
    if not _mine(con).get(f"pvlan-{'host' if hit[0] == 'host' else 'map'}:{key}"):
        out = (out + "\n" if out else "") + (f"% {devcli.short_if(con.s.ctx)} is inactive until it has its "
                                             f"switchport private-vlan {need}")
    return out


def _pv_vlan(con, primary: int) -> str:
    """The port into the primary VLAN, where its subnet is (as switchport
    access vlan does: the cable's network)."""
    if con._port_link() is None:
        raise devcli.CliError(f"% nothing is plugged into {con.s.ctx}: cable a machine to it on the canvas first")
    return con._access_vlan([str(primary)]) or ""


def _pv_host(con, p: str, s: str) -> str:
    pi, si = int(p), int(s)
    if not (2 <= pi <= 1001 and 2 <= si <= 1001) or pi == si:
        raise devcli.CliError("% Invalid input: switchport private-vlan host-association <primary> <secondary>")
    key = _key(con)
    _mine(con)[f"pvlan-host:{key}"] = f"{pi} {si}"
    note = _pv_vlan(con, pi)
    out = _done(con)
    own = _mine(con)
    role = port_role(con.lab, _sw(con), key, pi)
    tail = []
    if own.get(f"pvlan-mode:{key}") != "host":
        tail.append(f"% Kept; it takes effect once the port is in switchport mode private-vlan host")
    elif role[0] == "inactive":
        tail.append(f"% {devcli.short_if(con.s.ctx)} is inactive: VLAN {pi} must be a primary VLAN associated "
                    f"with VLAN {si}, and VLAN {si} isolated or community (show vlan private-vlan)")
    return "\n".join(x for x in [note, out] + tail if x)


def _pv_map(con, p: str, text: str) -> str:
    pi = int(p)
    if not 2 <= pi <= 1001:
        raise devcli.CliError("% Invalid input: switchport private-vlan mapping <primary> [add | remove] <list>")
    key = _key(con)
    own = _mine(con)
    have = _pair(own.get(f"pvlan-map:{key}", ""))
    try:
        want = devcli.edit_vlans(have[1] if have[0] == pi else set(), text) or set()
    except ValueError:
        raise devcli.CliError("% Invalid input: switchport private-vlan mapping <primary> [add | remove] <list>") from None
    own[f"pvlan-map:{key}"] = f"{pi} {devcli.vlan_text(want) or 'none'}"
    note = _pv_vlan(con, pi)
    return "\n".join(x for x in [note, _done(con)] if x)


def _pv_clear(con, field: str) -> str:
    key = _key(con)
    _mine(con).pop(f"{field}:{key}", None)
    return _done(con)


def leave(con) -> None:
    """switchport mode access | trunk on a port that was a private-VLAN port."""
    link = con._port_link()
    if link is None:
        return
    own = _mine(con)
    for k in (link.label, con.s.ctx):
        own.pop(f"pvlan-mode:{k}", None)


def _rows(con) -> list[tuple[int, int, str, list[str]]]:
    """(primary, secondary, type, ports) as show vlan private-vlan lists them."""
    lab, sw = con.lab, _sw(con)
    own = _own(lab, sw)
    rows = []
    roles = {}
    for i, link in enumerate(con._ports(), 1):
        if link is None:
            continue
        from . import portsec
        key = portsec.conf_key(own, link.label, i)
        roles[f"Fa0/{i}"] = port_role(lab, sw, key, _tag(lab, link))
    prim = sorted(int(k[6:]) for k, v in own.items() if k.startswith("pvlan:") and v == "primary")
    done = set()
    for p in prim:
        for s in sorted(assoc(own, p)):
            t = pv_type(own, s) or "non-operational"
            ports = [n for n, r in roles.items() if (r[0] in ("isolated", "community") and r[1] == p and s in r[2])
                     or (r[0] == "promiscuous" and r[1] == p and s in r[2])]
            rows.append((p, s, t, ports))
            done.add(s)
        if not assoc(own, p):
            rows.append((p, 0, "", [n for n, r in roles.items() if r[0] == "promiscuous" and r[1] == p]))
    for k, v in sorted(own.items()):
        if k.startswith("pvlan:") and v != "primary" and int(k[6:]) not in done:
            rows.append((0, int(k[6:]), v, []))
    return rows


def show_pvlan(con) -> str:
    out = [f"{'Primary':<8}{'Secondary':<10}{'Type':<18}Ports",
           f"{'-' * 7} {'-' * 9} {'-' * 17} {'-' * 42}"]
    for p, s, t, ports in _rows(con):
        out.append(f"{p or 'none':<8}{s or 'none':<10}{t:<18}{', '.join(ports)}".rstrip())
    return "\n".join(out)


def show_pvlan_type(con) -> str:
    own = _mine(con)
    out = [f"{'Vlan':<5}{'Type':<18}", f"{'-' * 4} {'-' * 17}"]
    for k, v in sorted(own.items(), key=lambda kv: (len(kv[0]), kv[0])):
        if k.startswith("pvlan:"):
            out.append(f"{k[6:]:<5}{v}")
    return "\n".join(out)


def show_pv_mapping(con) -> str:
    lab, sw = con.lab, _sw(con)
    own = _own(lab, sw)
    out = [f"{'Interface':<10}{'Secondary VLAN':<15}Type", f"{'-' * 9} {'-' * 14} {'-' * 17}"]
    from . import portsec
    for i, link in enumerate(con._ports(), 1):
        if link is None:
            continue
        r = port_role(lab, sw, portsec.conf_key(own, link.label, i), _tag(lab, link))
        if r[0] == "promiscuous":
            out += [f"{f'Fa0/{i}':<10}{s:<15}{pv_type(own, s)}" for s in sorted(r[2])]
    return "\n".join(out)


# ---- storm control
def _storm(con, kind: str, text: str) -> str:
    key = _key(con)
    own = _mine(con)
    if not text:
        own.pop(f"storm-{kind}:{key}", None)
    else:
        own[f"storm-{kind}:{key}"] = parse_level(text)
    return _done(con)


def _storm_act(con, text: str, on: bool) -> str:
    w = text.lower().split()
    hit = [x for x in ("shutdown", "trap") if len(w) == 1 and x.startswith(w[0])]
    if len(hit) != 1:
        raise devcli.CliError("% Invalid input: storm-control action shutdown | trap")
    key = _key(con)
    own = _mine(con)
    have = actions(own, key)
    have = have | {hit[0]} if on else have - {hit[0]}
    if have:
        own[f"storm-act:{key}"] = " ".join(sorted(have))
    else:
        own.pop(f"storm-act:{key}", None)
    return _done(con)


def show_storm(con, text: str) -> str:
    from . import portsec
    w = text.lower().split()
    kind = "b"
    only = ""
    for t in w:
        hit = [k for k, v in KINDS.items() if v.startswith(t)]
        if len(hit) == 1 and len(t) > 1:
            kind = hit[0]
        else:
            only = devcli.parse_if(t, con._if_names())
    data = portsec.live_of(con).get("l2") or {}
    own = _mine(con)
    out = [f"{'Interface':<11}{'Filter State':<15}{'Upper':<13}{'Lower':<13}Current",
           f"{'-' * 9}  {'-' * 13}  {'-' * 11}  {'-' * 11}  {'-' * 10}"]
    for p in portsec.ports_of(con.lab, con.plan, _sw(con)):
        if only and p.name != only:
            continue
        lv = own.get(f"storm-{kind}:{p.key}")
        if not lv:
            continue
        unit, rise, fall = level(lv)
        if p.err and p.cause == CAUSE:
            state = "Link Down"
        elif data.get("count", {}).get(f"storm_{kind}_{p.iface}", 0) > 0:
            state = "Blocking"
        else:
            state = "Forwarding"
        out.append(f"{p.short:<11}{state:<15}{show_level(unit, rise):>11}  {show_level(unit, fall):>11}  "
                   f"{'n/a':>10}")
    return "\n".join(out)


# ---- RA guard and DHCPv6 guard
_POLICY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


def _policy(con, kind: str, name: str) -> str:
    if not _POLICY.match(name):
        raise devcli.CliError("% Invalid policy name")
    own = _mine(con)
    own.setdefault(f"{kind}:{name}", "host" if kind == "raguard" else "client")
    con.s.mode = "config-ra-guard" if kind == "raguard" else "config-dhcp-guard"
    con.s.ctx = name
    return _done(con, live=False)


def _no_policy(con, kind: str, name: str) -> str:
    own = _mine(con)
    own.pop(f"{kind}:{name}", None)
    own.pop(f"{kind}-trust:{name}", None)
    return _done(con)


def _kind(con) -> str:
    return "raguard" if con.s.mode == "config-ra-guard" else "d6guard"


def _role(con, text: str, on: bool) -> str:
    kind = _kind(con)
    roles = ("host", "router", "monitor", "switch") if kind == "raguard" else ("client", "server", "monitor")
    own = _mine(con)
    if not on:
        own[f"{kind}:{con.s.ctx}"] = roles[0]
        return _done(con)
    w = text.lower().split()
    hit = [r for r in roles if len(w) == 1 and r.startswith(w[0])]
    if len(hit) != 1:
        raise devcli.CliError(f"% Invalid input: device-role {' | '.join(roles)}")
    own[f"{kind}:{con.s.ctx}"] = hit[0]
    out = _done(con)
    if hit[0] in ("monitor", "switch"):
        out = (out + "\n" if out else "") + (f"% Kept: device-role {hit[0]} filters nothing here (a port "
                                             f"towards a switch or an analyser)")
    return out


def _trusted(con, on: bool) -> str:
    kind = _kind(con)
    own = _mine(con)
    if on:
        own[f"{kind}-trust:{con.s.ctx}"] = "yes"
    else:
        own.pop(f"{kind}-trust:{con.s.ctx}", None)
    return _done(con)


def _attach(con, kind: str, name: str, on: bool) -> str:
    key = _key(con, gig_ok=True)
    own = _mine(con)
    if on:
        own[f"{kind}-port:{key}"] = name
    else:
        own.pop(f"{kind}-port:{key}", None)
    out = _done(con)
    if on and name != DEFAULT_POLICY and f"{kind}:{name}" not in own:
        out = (out + "\n" if out else "") + (f"% Policy {name} does not exist yet: the port takes its "
                                             f"defaults (device-role {'host' if kind == 'raguard' else 'client'})")
    return out


def _targets(con, kind: str, name: str) -> list[str]:
    own = _mine(con)
    out = []
    from . import portsec
    for i, link in enumerate(con._ports(), 1):
        key = portsec.conf_key(own, link.label, i) if link is not None else f"FastEthernet0/{i}"
        for k in {key, f"FastEthernet0/{i}"}:
            if own.get(f"{kind}-port:{k}") == name:
                out.append(f"Fa0/{i}")
                break
    if own.get(f"{kind}-port:{UPLINK}") == name:
        out.append("Gi0/1")
    return out


def show_policy(con, kind: str, name: str) -> str:
    own = _mine(con)
    names = sorted({k.split(":", 1)[1] for k in own if k.startswith(f"{kind}:")}
                   | {v for k, v in own.items() if k.startswith(f"{kind}-port:")})
    feature = "RA guard" if kind == "raguard" else "DHCP Guard"
    out = []
    for n in names:
        if name and n != name:
            continue
        role = own.get(f"{kind}:{n}", "host" if kind == "raguard" else "client")
        out += [f"{'RA guard' if kind == 'raguard' else 'Dhcp guard'} policy {n} configuration:",
                f"  device-role {role}"]
        if own.get(f"{kind}-trust:{n}"):
            out.append("  trusted-port")
        t = _targets(con, kind, n)
        out.append(f"Policy {n} is applied on the following targets:")
        if t:
            out.append(f"{'Target':<21}{'Type':<6}{'Policy':<21}{'Feature':<15}Target range")
            out += [f"{x:<21}{'PORT':<6}{n:<21}{feature:<15}vlan all" for x in t]
        out.append("")
    return "\n".join(out).rstrip()


# ------------------------------------------------------------------ show running-config
def _insert_after_block(out: list[str], head: str, lines: list[str]) -> None:
    if not lines or head not in out:
        return
    at = out.index(head) + 1
    while at < len(out) and out[at].startswith(" "):
        at += 1
    out[at:at] = lines


def run_lines(con, out: list[str]) -> list[str]:
    """This module's lines in a switch's show running-config: the policies
    and IPv6 lists before the interfaces, private-VLAN types under each
    VLAN, and each port's lines under it."""
    from . import acl6, portsec
    lab, sw = con.lab, _sw(con)
    own = _own(lab, sw)
    out = list(out)
    glob = []
    for kind, word in (("raguard", "ipv6 nd raguard policy"), ("d6guard", "ipv6 dhcp guard policy")):
        for n in sorted(k.split(":", 1)[1] for k in own if k.startswith(f"{kind}:")):
            glob.append(f"{word} {n}")
            dflt = "host" if kind == "raguard" else "client"
            if own.get(f"{kind}:{n}", dflt) != dflt:
                glob.append(f" device-role {own[f'{kind}:{n}']}")
            if own.get(f"{kind}-trust:{n}"):
                glob.append(" trusted-port")
            glob.append("!")
    glob += acl6.run_lines(own)
    if glob and "interface FastEthernet0/1" in out:
        at = out.index("interface FastEthernet0/1")
        out[at:at] = glob
    for k, v in sorted(own.items()):
        if k.startswith("pvlan:"):
            tag = int(k[6:])
            lines = [f" private-vlan {v}"]
            if v == "primary" and assoc(own, tag):
                lines.append(f" private-vlan association {devcli.vlan_text(assoc(own, tag))}")
            _insert_after_block(out, f"vlan {tag}", lines)
    ports = devcli.switch_ports(lab, con.plan).get(sw, [])
    for i in range(1, devcli.SWITCH_PORTS + 1):
        link = ports[i - 1] if i <= len(ports) else None
        key = portsec.conf_key(own, link.label, i) if link else f"FastEthernet0/{i}"
        out = _port_lines(own, key, f"interface FastEthernet0/{i}", out)
    return _port_lines(own, UPLINK, f"interface {UPLINK}", out)


def _port_lines(own: dict, key: str, head: str, out: list[str]) -> list[str]:
    from . import acl6
    if head not in out:
        return out
    lines = []
    mode = own.get(f"pvlan-mode:{key}")
    if own.get(f"pvlan-host:{key}"):
        lines.append(f" switchport private-vlan host-association {own[f'pvlan-host:{key}']}")
    if own.get(f"pvlan-map:{key}"):
        p, ss = _pair(own[f"pvlan-map:{key}"])
        lines.append(f" switchport private-vlan mapping {p} {devcli.vlan_text(ss) or 'none'}")
    if mode:
        lines.append(f" switchport mode private-vlan {mode}")
    for kind, word in KINDS.items():
        if own.get(f"storm-{kind}:{key}"):
            lv = own[f"storm-{kind}:{key}"]
            unit, rise, fall = level(lv)
            text = lv if unit != "%" or rise != fall else f"{rise:.2f}"
            lines.append(f" storm-control {word} level {text}")
    for a in sorted(actions(own, key)):
        lines.append(f" storm-control action {a}")
    lines += acl6.iface_lines(own, key)
    for kind, word in (("raguard", "ipv6 nd raguard"), ("d6guard", "ipv6 dhcp guard")):
        n = own.get(f"{kind}-port:{key}")
        if n:
            lines.append(f" {word} attach-policy" + ("" if n == DEFAULT_POLICY else f" {n}"))
    if not lines:
        return out
    at = out.index(head) + 1
    end = at
    while end < len(out) and out[end].startswith(" "):
        end += 1
    body = out[at:end]
    if mode:   # a private-VLAN port is not an access port of its VLAN
        body = [b for b in body if not b.startswith((" switchport access vlan", " switchport mode access"))]
    out[at:end] = body + lines
    return out
