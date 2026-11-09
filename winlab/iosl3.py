"""The lab router's layer 3 as typed at its console: static routes, access
lists on its interfaces, and NAT between the lab's networks.

What is typed is kept with the router's other settings in the lab file
([devices."router"]) and is made real on the router (an Alpine VM) by the
script render() writes, which winlab/netplan.py runs at its start and
winlab/livenet.py runs again whenever it changes:

* ``ip route <net> <mask> <next hop | interface> [distance]`` is a kernel
  route of the router's own (``proto 120``, flushed and written again: not
  186, which is FRRouting's number for BGP, winlab/iosrouting.py);
* an access list applied with ``ip access-group <list> in|out`` is an
  nftables chain on that interface's SVI: the entries in order, each with a
  counter (what ``show access-lists`` prints as matches), and the implicit
  ``deny any`` at the end;
* ``ip nat inside|outside`` with ``ip nat inside source list <n> interface
  <if> overload`` is masquerade from the inside interfaces out of that one,
  for the addresses the list permits; ``ip nat inside source static <local>
  <global>`` maps one address both ways. NAT stays inside the lab: the
  router's only interfaces are its SVIs on the lab's switches, so "outside"
  is always another lab network, never this PC or the internet;
* ``ip nat pool <name> <start> <end> netmask <mask> | prefix-length <n>``
  with ``ip nat inside source list <n> pool <name> [overload]`` translates
  to the pool's addresses. With overload it is PAT across the pool (nftables
  ``snat to <start>-<end>``). Without it, each inside host takes one pool
  address of its own for as long as IOS keeps a simple translation (24
  hours, or until ``clear ip nat translation *``): every pool address is an
  nftables dynamic set of size one, a host already in a set goes out as that
  address, a new host is added to the first set that is free, and when every
  set is full the packet is dropped and counted as a miss, which is IOS's
  pool exhaustion (``show ip nat statistics``: allocated, misses). A pool
  address in the outside interface's own subnet is answered for there (an
  address of its own on that interface, as a static entry's is); one in
  another block must be routed to the router by the far side, as an ISP
  routes a customer's public block.

Settings: ``route:<net>/<len> <target>`` = distance;
``acl:<name>`` = standard entries, ``xacl:<name>`` = extended entries
(each ``<seq> <entry>``, ';'-separated); ``acltype:<name>`` for a named
list; ``acl-in:<if>`` / ``acl-out:<if>`` = list; ``nat:<if>`` = inside |
outside; ``natsrc:<list>`` = ``<if> overload`` or ``pool <name>
[overload]``; ``natstatic:<local>`` = global; ``natpool:<name>`` = ``<start>
<end> <prefix length>`` (and ``natpool-pl:<name>`` when it was typed as
prefix-length).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

ROUTE_PROTO = 120
TABLE_ACL = "wlacl"
TABLE_NAT = "wlnat"
POOL_MAX = 254         # addresses in a pool without overload: one set and two rules each
NAT_TIMEOUT = "24h"    # IOS's ip nat translation timeout for a simple translation (86400 s)

# The port names IOS knows (a few common ones), and ICMP's message names.
PORTS = {"bgp": 179, "bootpc": 68, "bootps": 67, "domain": 53, "echo": 7, "ftp": 21, "ftp-data": 20,
         "isakmp": 500, "ldap": 389, "ntp": 123, "pop3": 110, "smtp": 25, "snmp": 161,
         "snmptrap": 162, "syslog": 514, "tacacs": 49, "telnet": 23, "tftp": 69, "www": 80,
         "443": 443, "22": 22, "3389": 3389}
PORT_NAMES = {80: "www", 53: "domain", 23: "telnet", 21: "ftp", 25: "smtp", 110: "pop3", 69: "tftp",
              67: "bootps", 68: "bootpc", 161: "snmp", 162: "snmptrap", 123: "ntp", 514: "syslog",
              389: "ldap", 179: "bgp", 500: "isakmp", 20: "ftp-data", 49: "tacacs", 7: "echo"}
ICMP = {"echo": "echo-request", "echo-reply": "echo-reply", "unreachable": "destination-unreachable",
        "time-exceeded": "time-exceeded", "redirect": "redirect"}
PROTOS = {"ip": 0, "tcp": 6, "udp": 17, "icmp": 1, "gre": 47, "esp": 50, "ahp": 51, "ospf": 89,
          "eigrp": 88, "pim": 103}


class AclError(ValueError):
    """What the console prints for an entry it cannot take."""


# ------------------------------------------------------------------ lists
def std_range(name: str) -> bool:
    return name.isdigit() and (1 <= int(name) <= 99 or 1300 <= int(name) <= 1999)


def ext_range(name: str) -> bool:
    return name.isdigit() and (100 <= int(name) <= 199 or 2000 <= int(name) <= 2699)


def kind_of(own: dict, name: str) -> str:
    """standard | extended | "" (no such list)."""
    if f"xacl:{name}" in own:
        return "extended"
    if f"acl:{name}" in own:
        return "standard"
    return own.get(f"acltype:{name}", "")


def entries(own: dict, name: str) -> list[tuple[int, str]]:
    """(sequence, entry) of a list, in order. Entries kept before lists had
    sequence numbers are numbered 10, 20, ... as IOS shows them."""
    raw = str(own.get(f"xacl:{name}", own.get(f"acl:{name}", "")))
    out, last = [], 0
    for part in [p.strip() for p in raw.split(";") if p.strip()]:
        m = re.match(r"^(\d+)\s+(.*)$", part)
        seq, text = (int(m.group(1)), m.group(2)) if m else (last + 10, part)
        out.append((seq, text))
        last = seq
    return sorted(out)


def _store(own: dict, name: str, kind: str, rows: list[tuple[int, str]]) -> None:
    key = ("xacl:" if kind == "extended" else "acl:") + name
    own[key] = ";".join(f"{s} {t}" for s, t in sorted(rows))


def add_entry(own: dict, name: str, kind: str, text: str, seq: int | None = None) -> str:
    """Adds an entry (parsed and kept in IOS's own form) to a list; returns
    the entry as kept."""
    have = kind_of(own, name)
    if have and have != kind:
        raise AclError(f"% Access list {name} is an {have} list")
    entry = std_entry(text) if kind == "standard" else ext_entry(text)
    rows = entries(own, name)
    if seq is None:
        seq = (rows[-1][0] if rows else 0) + 10
    elif any(s == seq for s, _ in rows):
        raise AclError(f"% Duplicate sequence number")
    if any(t == entry for _, t in rows):
        return entry  # the same entry again: IOS keeps one
    _store(own, name, kind, rows + [(seq, entry)])
    return entry


def remove_seq(own: dict, name: str, seq: int) -> bool:
    kind = kind_of(own, name)
    rows = entries(own, name)
    left = [(s, t) for s, t in rows if s != seq]
    if len(left) == len(rows):
        return False
    _store(own, name, kind, left)
    return True


def remove_list(own: dict, name: str) -> bool:
    found = False
    for k in (f"acl:{name}", f"xacl:{name}", f"acltype:{name}"):
        found = own.pop(k, None) is not None or found
    return found


def names(own: dict) -> list[str]:
    """Every list, numbered ones first in number order, then named ones."""
    found = {k.split(":", 1)[1] for k in own if k.startswith(("acl:", "xacl:", "acltype:"))}
    return sorted(found, key=lambda n: (0, int(n), "") if n.isdigit() else (1, 0, n))


# ---- entries
def _wild(tokens: list[str], i: int) -> tuple[tuple[str, str], int]:
    """'any' | 'host A' | 'A W' at tokens[i] -> ((address, wildcard), next i)."""
    if i >= len(tokens):
        raise AclError("% Incomplete command.")
    t = tokens[i].lower()
    try:
        if t == "any":
            return ("0.0.0.0", "255.255.255.255"), i + 1
        if t == "host":
            return (str(ipaddress.IPv4Address(tokens[i + 1])), "0.0.0.0"), i + 2
        addr = ipaddress.IPv4Address(tokens[i])
        if i + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[i + 1]):
            wild = ipaddress.IPv4Address(tokens[i + 1])
            return (str(ipaddress.IPv4Address(int(addr) & ~int(wild) & 0xFFFFFFFF)), str(wild)), i + 2
        return (str(addr), "0.0.0.0"), i + 1
    except (ValueError, IndexError):
        raise AclError("% Invalid input detected at '^' marker.") from None


def _show_wild(aw: tuple[str, str]) -> str:
    addr, wild = aw
    if wild == "255.255.255.255":
        return "any"
    if wild == "0.0.0.0":
        return f"host {addr}"
    return f"{addr} {wild}"


def std_entry(text: str) -> str:
    """'permit host 10.0.0.5', 'deny 10.0.0.0 0.0.0.255', 'permit any' ->
    'permit 10.0.0.0/24' (how winlab/nms.py has always kept them)."""
    w = text.split()
    if not w or w[0] not in ("permit", "deny"):
        raise AclError("% Invalid input detected at '^' marker.")
    rest = [x for x in w[1:] if x != "log"]
    (addr, wild), i = _wild(rest, 0)
    if i != len(rest):
        raise AclError("% Invalid input detected at '^' marker.")
    try:
        mask = ipaddress.IPv4Address(int(ipaddress.IPv4Address(wild)) ^ 0xFFFFFFFF)
        net = ipaddress.IPv4Network(f"{addr}/{mask}")
    except ValueError:
        raise AclError("% A standard list here takes a contiguous wildcard (0.0.0.255, 0.0.255.255)") from None
    return f"{w[0]} {net}"


def _ports(tokens: list[str], i: int, proto: str) -> tuple[str, int]:
    """eq|neq|lt|gt <port> | range <a> <b> -> ('eq 80', next i), or ('', i)."""
    if i >= len(tokens) or proto not in ("tcp", "udp") or tokens[i] not in ("eq", "neq", "lt", "gt", "range"):
        return "", i
    op = tokens[i]
    n = 2 if op == "range" else 1
    vals = []
    for t in tokens[i + 1:i + 1 + n]:
        v = PORTS.get(t.lower(), int(t) if t.isdigit() else None)
        if v is None or not 0 <= v <= 65535:
            raise AclError(f"% Invalid input detected at '^' marker.")
        vals.append(str(v))
    if len(vals) != n:
        raise AclError("% Incomplete command.")
    return f"{op} {' '.join(vals)}", i + 1 + n


def ext_entry(text: str) -> str:
    """An extended entry, checked and kept in one form:
    '<permit|deny> <proto> <src> [ports] <dst> [ports] [established|<icmp type>] [log]'."""
    w = text.split()
    if len(w) < 2 or w[0] not in ("permit", "deny"):
        raise AclError("% Invalid input detected at '^' marker.")
    proto = w[1].lower()
    if proto not in PROTOS and not (proto.isdigit() and 0 <= int(proto) <= 255):
        raise AclError("% Invalid input detected at '^' marker.")
    src, i = _wild(w, 2)
    sport, i = _ports(w, i, proto)
    dst, i = _wild(w, i)
    dport, i = _ports(w, i, proto)
    extra = []
    while i < len(w):
        t = w[i].lower()
        if t == "established" and proto == "tcp":
            extra.append(t)
        elif proto == "icmp" and t in ICMP and not any(x in ICMP for x in extra):
            extra.append(t)
        elif t == "log":
            extra.append(t)
        else:
            raise AclError("% Invalid input detected at '^' marker.")
        i += 1
    parts = [w[0], proto, _show_wild(src)] + ([sport] if sport else []) + [_show_wild(dst)] \
        + ([dport] if dport else []) + extra
    return " ".join(parts)


def show_entry(entry: str) -> str:
    """An entry as show access-lists prints it (port names, 'host' gone
    in standard lists)."""
    w = entry.split()
    if len(w) == 2 and "/" in w[1]:   # standard, kept as a CIDR
        net = ipaddress.IPv4Network(w[1])
        if net.prefixlen == 0:
            return f"{w[0]} any"
        if net.prefixlen == 32:
            return f"{w[0]} {net.network_address}"
        return f"{w[0]} {net.network_address}, wildcard bits {net.hostmask}"
    out = []
    for j, t in enumerate(w):
        if j > 0 and w[j - 1] in ("eq", "neq", "lt", "gt") and t.isdigit() and int(t) in PORT_NAMES:
            t = PORT_NAMES[int(t)]
        out.append(t)
    return " ".join(out)


def run_entry(entry: str) -> str:
    """An entry as show running-config prints it."""
    w = entry.split()
    if len(w) == 2 and "/" in w[1]:
        net = ipaddress.IPv4Network(w[1])
        where = "any" if net.prefixlen == 0 else (f"host {net.network_address}" if net.prefixlen == 32
                                                  else f"{net.network_address} {net.hostmask}")
        return f"{w[0]} {where}"
    return show_entry(entry)


# ---- matching (the same decision the router's nftables makes)
def _match_addr(aw: tuple[str, str], ip: str) -> bool:
    addr, wild = aw
    care = ~int(ipaddress.IPv4Address(wild)) & 0xFFFFFFFF
    return int(ipaddress.IPv4Address(ip)) & care == int(ipaddress.IPv4Address(addr)) & care


def parse(entry: str) -> dict:
    """An entry kept by std_entry/ext_entry, taken apart."""
    w = entry.split()
    if len(w) == 2 and "/" in w[1]:
        net = ipaddress.IPv4Network(w[1])
        return {"action": w[0], "proto": "ip", "src": (str(net.network_address), str(net.hostmask)),
                "dst": ("0.0.0.0", "255.255.255.255"), "sport": "", "dport": "", "extra": []}
    proto = w[1]
    src, i = _wild(w, 2)
    sport, i = _ports(w, i, proto)
    dst, i = _wild(w, i)
    dport, i = _ports(w, i, proto)
    return {"action": w[0], "proto": proto, "src": src, "dst": dst, "sport": sport, "dport": dport,
            "extra": w[i:]}


def _port_ok(spec: str, port: int | None) -> bool:
    if not spec:
        return True
    if port is None:
        return False
    op, *vals = spec.split()
    v = [int(x) for x in vals]
    return {"eq": port == v[0], "neq": port != v[0], "lt": port < v[0], "gt": port > v[0],
            "range": len(v) == 2 and v[0] <= port <= v[1]}[op]


def decide(own: dict, name: str, src: str, dst: str = "0.0.0.0", proto: str = "ip",
           sport: int | None = None, dport: int | None = None) -> tuple[str, int]:
    """What a list does with a packet: ('permit'|'deny', the sequence that
    matched, 0 for the implicit deny at the end)."""
    for seq, entry in entries(own, name):
        e = parse(entry)
        if e["proto"] not in ("ip", proto) and not (e["proto"].isdigit() and PROTOS.get(proto) == int(e["proto"])):
            continue
        if not (_match_addr(e["src"], src) and _match_addr(e["dst"], dst)):
            continue
        if not (_port_ok(e["sport"], sport) and _port_ok(e["dport"], dport)):
            continue
        return e["action"], seq
    return "deny", 0


# ------------------------------------------------------------------ nftables
def _nft_addr(field_: str, aw: tuple[str, str]) -> str:
    addr, wild = aw
    if wild == "255.255.255.255":
        return ""
    care = ~int(ipaddress.IPv4Address(wild)) & 0xFFFFFFFF
    prefix = bin(care).count("1")
    if care == (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF:
        return f"ip {field_} {addr}/{prefix} " if prefix < 32 else f"ip {field_} {addr} "
    return f"ip {field_} & {ipaddress.IPv4Address(care)} == {addr} "


def _nft_ports(proto: str, field_: str, spec: str) -> str:
    if not spec:
        return ""
    op, *v = spec.split()
    if op == "range":
        return f"{proto} {field_} {v[0]}-{v[1]} "
    return f"{proto} {field_} {({'eq': '', 'neq': '!= ', 'lt': '< ', 'gt': '> '}[op])}{v[0]} "


def nft_rule(entry: str, comment: str) -> str:
    """One entry as an nftables rule with its own counter."""
    e = parse(entry)
    proto = e["proto"]
    out = ""
    if proto in ("tcp", "udp", "icmp"):
        out += f"meta l4proto {proto} "
    elif proto != "ip":
        out += f"meta l4proto {PROTOS.get(proto, proto)} "
    out += _nft_addr("saddr", e["src"]) + _nft_addr("daddr", e["dst"])
    out += _nft_ports(proto, "sport", e["sport"]) + _nft_ports(proto, "dport", e["dport"])
    if "established" in e["extra"]:
        out += "tcp flags & (ack | rst) != 0 "
    for t in e["extra"]:
        if t in ICMP:
            out += f"icmp type {ICMP[t]} "
    verdict = "accept" if e["action"] == "permit" else "drop"
    return f"{out}counter {verdict} comment \"{comment}\""


def _chain(name: str) -> str:
    return "acl_" + re.sub(r"[^A-Za-z0-9_]", "_", name)


# ------------------------------------------------------------------ the router
def _own(lab) -> dict:
    return lab.devices.get("router", {})


def svi_for(lab, plan, ifname: str) -> str:
    """The router's Linux interface for an IOS interface that routes a
    network now, or ""."""
    from . import devcli
    if ifname.startswith("Tunnel"):  # interface Tunnel<n> (winlab/vti.py)
        from . import vti
        return vti.tunnel_dev(lab, ifname)
    net = devcli.iface_net(lab, ifname)
    if net is None or not net.routed or _own(lab).get(f"ip:{ifname}") != net.id:
        return ""
    try:
        return plan.segment_of(net.id).svi
    except KeyError:
        return ""


def routes(own: dict) -> list[tuple[ipaddress.IPv4Network, str, int]]:
    """(network, next hop address or interface name, distance)."""
    out = []
    for k, v in own.items():
        if k.startswith("route:"):
            net, _, target = k[6:].partition(" ")
            try:
                out.append((ipaddress.IPv4Network(net), target, int(v or 1)))
            except ValueError:
                continue
    return sorted(out, key=lambda r: (int(r[0].network_address), r[0].prefixlen, r[1]))


def best(stat: list) -> list:
    """(destination, distance, text) per static route whose next hop is
    reachable -> the ones the routing table keeps: per destination only the
    lowest administrative distance (a floating route stays out until the
    better one goes), equal ones side by side."""
    low: dict = {}
    for d, dist, _ in stat:
        low[d] = min(low.get(d, 256), dist)
    return [(d, dist, how) for d, dist, how in stat if dist == low[d]]


def pools(own: dict) -> dict[str, tuple[str, str, int]]:
    """name -> (start, end, prefix length) of the ip nat pool lines."""
    out = {}
    for k, v in own.items():
        if k.startswith("natpool:"):
            w = v.split()
            if len(w) == 3 and w[2].isdigit():
                out[k[8:]] = (w[0], w[1], int(w[2]))
    return dict(sorted(out.items()))


def pool_addrs(start: str, end: str) -> list[str]:
    a, b = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
    return [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]


def _setname(pool: str, i: int) -> str:
    return f"p_{re.sub(r'[^A-Za-z0-9_]', '_', pool)}_{i}"


def _rule_target(how: str) -> tuple[str, str, bool]:
    """'<if> overload' | 'pool <name> [overload]' -> (interface, pool, overload)."""
    w = how.split()
    if w and w[0] == "pool" and len(w) >= 2:
        return "", w[1], "overload" in w[2:]
    return (w[0] if w else ""), "", True


def render(plan, reset: bool = False) -> list[str]:
    """Shell for the router: its static routes, the access lists on its
    interfaces, NAT. Empty when none is set and nothing must be undone."""
    lab = plan.lab
    own = _own(lab)
    rts = routes(own)
    applied = {k: v for k, v in own.items() if k.startswith(("acl-in:", "acl-out:"))}
    nat = {k[4:]: v for k, v in own.items() if k.startswith("nat:")}
    rules = {k[7:]: v for k, v in own.items() if k.startswith("natsrc:")}
    statics = {k[10:]: v for k, v in own.items() if k.startswith("natstatic:")}
    from . import acl6  # IPv6 lists on the interfaces: their own ip6 table
    v6 = acl6.render(plan, reset)
    if not (rts or applied or rules or statics or v6) and not reset:
        return []
    out = ["### the router's layer 3 as typed at its console (winlab/iosl3.py)",
           f"ip route flush proto {ROUTE_PROTO} 2>/dev/null || true",
           f"nft delete table ip {TABLE_ACL} 2>/dev/null || true",
           f"nft delete table ip {TABLE_NAT} 2>/dev/null || true",
           f"for a in $(cat /run/winlab-natips 2>/dev/null); do ip addr del $a 2>/dev/null; done; : > /run/winlab-natips"]
    tracked = {k[12:] for k in own if k.startswith("route-track:")}
    for net, target, dist in rts:
        if f"{net} {target}" in tracked:
            out.append(f"# ip route {net} {target} track: winlab-slad installs it while its object is Up")
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            how = f"via {target}"
        else:
            dev = svi_for(lab, plan, target)
            if not dev:
                out.append(f"# ip route {net} {target}: {target} is down, not installed")
                continue
            how = f"dev {dev}"
        out.append(f"ip route replace {net} {how} proto {ROUTE_PROTO} metric {dist} 2>/dev/null || true")
    # access lists: a chain per list and direction use, jumped to by interface
    fwd, inp, chains = [], [], {}
    for k, name in sorted(applied.items()):
        way, ifname = k.split(":", 1)
        dev = svi_for(lab, plan, ifname)
        if not dev or not kind_of(own, name):
            continue  # a list that does not exist permits everything, as on IOS
        ch = _chain(name)
        if ch not in chains:
            body = [nft_rule(t, f"{name} {s}") for s, t in entries(own, name)]
            chains[ch] = body + [f"counter drop comment \"{name} implicit deny\""]
        if way == "acl-in":
            fwd.append(f"iifname \"{dev}\" jump {ch}")
            inp.append(f"iifname \"{dev}\" jump {ch}")
        else:
            fwd.append(f"oifname \"{dev}\" jump {ch}")
    if chains:
        out += ["nft -f - <<'EOF' || true", f"table ip {TABLE_ACL} {{"]
        for ch, body in sorted(chains.items()):
            out += [f"  chain {ch} {{"] + [f"    {r}" for r in body] + ["  }"]
        out += ["  chain forward {", "    type filter hook forward priority -5; policy accept;"]
        out += [f"    {r}" for r in fwd] + ["  }"]
        out += ["  chain input {", "    type filter hook input priority -5; policy accept;"]
        out += [f"    {r}" for r in inp] + ["  }", "}", "EOF"]
    # NAT between the lab's networks
    inside = sorted(filter(None, (svi_for(lab, plan, i) for i, v in nat.items() if v == "inside")))
    post, pre, sel, extra_ips = [], [], {}, []
    outside = sorted(filter(None, (svi_for(lab, plan, i) for i, v in nat.items() if v == "outside")))
    have_pools = pools(own)
    sets: list[str] = []
    for lst, how in sorted(rules.items()):
        ifname, pool, over = _rule_target(how)
        if pool:
            if pool not in have_pools or not outside or not inside or not kind_of(own, lst):
                continue
            devs = outside
        else:
            dev = svi_for(lab, plan, ifname)
            if not dev or not inside or nat.get(ifname) != "outside" or not kind_of(own, lst):
                continue
            devs = [dev]
        ch = "nat_" + _chain(lst)[4:]
        body = []
        for s, t in entries(own, lst):
            e = parse(t)
            cond = _nft_addr("saddr", e["src"]) + _nft_addr("daddr", e["dst"])
            if e["action"] != "permit":
                body.append(f"{cond}counter return comment \"{lst} {s}\"")
            elif not pool:
                body.append(f"{cond}counter masquerade comment \"{lst} {s}\"")
            else:
                body.append(f"{cond}counter jump pool_{_chain(pool)[4:]} comment \"{lst} {s}\"")
        sel[ch] = body
        if pool and f"pool_{_chain(pool)[4:]}" not in sel:
            start, end, plen = have_pools[pool]
            addrs = pool_addrs(start, end)
            pch = f"pool_{_chain(pool)[4:]}"
            if over:
                sel[pch] = [f"counter snat to {start}-{end} comment \"pool {pool} overload\""]
            else:
                pbody = []
                for i, a in enumerate(addrs[:POOL_MAX]):
                    sn = _setname(pool, i)
                    sets.append(f"  set {sn} {{ type ipv4_addr; size 1; flags dynamic,timeout; timeout {NAT_TIMEOUT}; }}")
                    pbody.append(f"ip saddr @{sn} update @{sn} {{ ip saddr }} counter snat to {a} comment \"pool {pool} {a}\"")
                for i, a in enumerate(addrs[:POOL_MAX]):
                    sn = _setname(pool, i)
                    pbody.append(f"add @{sn} {{ ip saddr }} counter snat to {a} comment \"pool {pool} {a} new\"")
                pbody.append(f"counter drop comment \"pool {pool} exhausted\"")
                sel[pch] = pbody
            for dev in outside:
                net = _dev_net(lab, plan, dev)
                for a in addrs[:POOL_MAX]:
                    if net is not None and ipaddress.IPv4Address(a) in net.net and a != net.router_ip:
                        extra_ips.append((a, dev))
        quoted = ", ".join(chr(34) + d + chr(34) for d in devs)
        quoted = quoted if len(devs) == 1 else "{ " + quoted + " }"
        post.append(f"iifname {{ {', '.join(chr(34) + d + chr(34) for d in inside)} }} oifname {quoted} jump {ch}")
    for local, glob in sorted(statics.items()):
        if not outside or not inside:
            continue
        for dev in outside:
            pre.append(f"iifname \"{dev}\" ip daddr {glob} counter dnat to {local}")
            post.insert(0, f"oifname \"{dev}\" ip saddr {local} counter snat to {glob}")
            extra_ips.append((glob, dev))
    if post or pre:
        out += ["nft -f - <<'EOF' || true", f"table ip {TABLE_NAT} {{"] + sets
        for ch, body in sorted(sel.items()):
            out += [f"  chain {ch} {{"] + [f"    {r}" for r in body] + ["  }"]
        out += ["  chain prerouting {", "    type nat hook prerouting priority -100; policy accept;"]
        out += [f"    {r}" for r in pre] + ["  }"]
        out += ["  chain postrouting {", "    type nat hook postrouting priority 100; policy accept;"]
        out += [f"    {r}" for r in post] + ["  }", "}", "EOF"]
        # A static global address is answered for on the outside network.
        for glob, dev in extra_ips:
            out.append(f"ip addr add {glob}/32 dev {dev} 2>/dev/null && echo {glob}/32 dev {dev} >> /run/winlab-natips || true")
    out += v6
    out.append("")
    return out


def _dev_net(lab, plan, dev: str):
    """The lab network whose SVI is this Linux device, or None."""
    for net in lab.networks.values():
        try:
            if plan.segment_of(net.id).svi == dev:
                return net
        except KeyError:
            continue
    return None


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


def forget_iface(own: dict, ifname: str) -> None:
    for k in (f"acl-in:{ifname}", f"acl-out:{ifname}", f"nat:{ifname}", f"acl6-in:{ifname}", f"acl6-out:{ifname}"):
        own.pop(k, None)


# ------------------------------------------------------------------ reading
ACL_LIVE_CMD = f"nft list table ip {TABLE_ACL} 2>/dev/null"
NAT_LIVE_CMD = "conntrack -L -n 2>/dev/null; conntrack -L -g 2>/dev/null"


def parse_counters(text: str) -> dict[tuple[str, int], int]:
    """'counter packets 12 bytes 900 ... comment "OFFICE 10"' -> {(list, seq): packets}."""
    out: dict[tuple[str, int], int] = {}
    for line in text.splitlines():
        m = re.search(r'counter packets (\d+) bytes \d+.*comment "(\S+) (\d+)"', line)
        if m:
            key = (m.group(2), int(m.group(3)))
            out[key] = out.get(key, 0) + int(m.group(1))
    return out


def parse_conntrack(text: str) -> list[tuple[str, str, str, str, str]]:
    """conntrack -L lines that were translated -> (proto, inside global,
    inside local, outside local, outside global) as show ip nat
    translations prints them."""
    out, seen = [], set()
    for line in text.splitlines():
        w = line.split()
        if not w:
            continue
        proto = w[0]
        kv = [tuple(x.split("=", 1)) for x in w if "=" in x]
        src = [v for k, v in kv if k == "src"]
        dst = [v for k, v in kv if k == "dst"]
        sp = [v for k, v in kv if k == "sport"]
        dp = [v for k, v in kv if k == "dport"]
        if len(src) < 2 or len(dst) < 2:
            continue
        osrc, odst, rsrc, rdst = src[0], dst[0], src[1], dst[1]
        if rdst == osrc and rsrc == odst:
            continue  # not translated
        port = lambda xs, i: (":" + xs[i]) if len(xs) > i else ""  # noqa: E731
        if rdst != osrc:     # source NAT: the reply comes back to the global address
            row = (proto, rdst + port(dp, 1), osrc + port(sp, 0), odst + port(dp, 0), odst + port(dp, 0))
        else:                # static (destination) NAT seen from outside
            row = (proto, odst + port(dp, 0), rsrc + port(sp, 1), osrc + port(sp, 0), osrc + port(sp, 0))
        if row not in seen:
            seen.add(row)
            out.append(row)
    return out


# ------------------------------------------------------------------ the console
def run_lines(own: dict) -> list[str]:
    """The router's lines in show running-config: NAT, routes, lists."""
    out = []
    for name, (start, end, plen) in pools(own).items():
        mask = (f"prefix-length {plen}" if own.get(f"natpool-pl:{name}")
                else f"netmask {ipaddress.IPv4Network(f'0.0.0.0/{plen}').netmask}")
        out.append(f"ip nat pool {name} {start} {end} {mask}")
    for lst, how in sorted((k[7:], v) for k, v in own.items() if k.startswith("natsrc:")):
        out.append(f"ip nat inside source list {lst} " + (how if how.startswith("pool ") else f"interface {how}"))
    for local, glob in sorted((k[10:], v) for k, v in own.items() if k.startswith("natstatic:")):
        out.append(f"ip nat inside source static {local} {glob}")
    for net, target, dist in routes(own):
        obj = own.get(f"route-track:{net} {target}")
        out.append(f"ip route {net.network_address} {net.netmask} {target}" + (f" {dist}" if dist != 1 else "")
                   + (f" track {obj}" if obj else ""))
    out += ["!"] if out else []
    for name in names(own):
        kind = kind_of(own, name)
        rows = entries(own, name)
        if name.isdigit():
            out += [f"access-list {name} {run_entry(t)}" for _, t in rows]
        else:
            out.append(f"ip access-list {kind} {name}")
            out += [f" {run_entry(t)}" for _, t in rows]
    out += ["!"] if names(own) else []
    return out


def add_specs(con, add, U, E, C, IF) -> None:
    """The router's commands for routes, lists and NAT (winlab/devcli.py)."""
    N = ("config-std-nacl", "config-ext-nacl")
    add("ip route <ip> <mask> <line>", lambda a: _route(con, a, True), "Establish static routes", C)
    add("no ip route <ip> <mask> <line>", lambda a: _route(con, a, False), "Negate a command or set its defaults", C)
    add("no ip route <ip> <mask>", lambda a: _route(con, a + [""], False), "Negate a command or set its defaults", C)
    add("access-list <num> <line>", lambda a: _numbered(con, a[0], a[1]), "Add an access list entry", C)
    add("no access-list <num>", lambda a: _no_list(con, a[0]), "Negate a command or set its defaults", C)
    add("ip access-list standard <name>", lambda a: _named(con, a[0], "standard"), "Standard Access List", C + N)
    add("ip access-list extended <name>", lambda a: _named(con, a[0], "extended"), "Extended Access List", C + N)
    add("no ip access-list standard <name>", lambda a: _no_list(con, a[0]), "Negate a command or set its defaults", C)
    add("no ip access-list extended <name>", lambda a: _no_list(con, a[0]), "Negate a command or set its defaults", C)
    add("permit <line>", lambda a: _entry(con, "permit " + a[0]), "Specify packets to forward", N)
    add("deny <line>", lambda a: _entry(con, "deny " + a[0]), "Specify packets to reject", N)
    add("remark <line>", lambda a: "", "Access list entry comment", N)
    add("<num> <line>", lambda a: _seq_entry(con, a[0], a[1]), "Sequence Number", N)
    add("no <num>", lambda a: _no_seq(con, a[0]), "Negate a command or set its defaults", N)
    add("ip access-group <name> <line>", lambda a: _group(con, a[0], a[1], True), "Specify access control for packets", IF)
    add("no ip access-group <name> <line>", lambda a: _group(con, a[0], a[1], False), "Negate a command or set its defaults", IF)
    add("no ip access-group <line>", lambda a: _group(con, "", a[0], False), "Negate a command or set its defaults", IF)
    add("ip nat inside", lambda a: _nat_side(con, "inside"), "Inside interface for address translation", IF)
    add("ip nat outside", lambda a: _nat_side(con, "outside"), "Outside interface for address translation", IF)
    add("no ip nat inside", lambda a: _nat_side(con, ""), "Negate a command or set its defaults", IF)
    add("no ip nat outside", lambda a: _nat_side(con, ""), "Negate a command or set its defaults", IF)
    add("ip nat inside source list <name> interface <line>", lambda a: _nat_rule(con, a[0], a[1], True),
        "Specify access list describing local addresses", C)
    add("no ip nat inside source list <name> interface <line>", lambda a: _nat_rule(con, a[0], a[1], False),
        "Negate a command or set its defaults", C)
    add("ip nat pool <name> <ip> <ip> <line>", lambda a: _nat_pool(con, a[0], a[1], a[2], a[3]),
        "Define pool of addresses", C)
    add("no ip nat pool <name>", lambda a: _no_pool(con, a[0]), "Negate a command or set its defaults", C)
    add("no ip nat pool <name> <line>", lambda a: _no_pool(con, a[0]), "Negate a command or set its defaults", C)
    add("ip nat inside source list <name> pool <name>", lambda a: _nat_pool_rule(con, a[0], a[1], "", True),
        "Name pool of global addresses", C)
    add("ip nat inside source list <name> pool <name> <line>",
        lambda a: _nat_pool_rule(con, a[0], a[1], a[2], True), "Name pool of global addresses", C)
    add("no ip nat inside source list <name> pool <name>", lambda a: _nat_pool_rule(con, a[0], a[1], "", False),
        "Negate a command or set its defaults", C)
    add("no ip nat inside source list <name> pool <name> <line>",
        lambda a: _nat_pool_rule(con, a[0], a[1], a[2], False), "Negate a command or set its defaults", C)
    add("ip nat inside source static <ip> <ip>", lambda a: _nat_static(con, a[0], a[1], True),
        "Specify static local->global mapping", C)
    add("no ip nat inside source static <ip> <ip>", lambda a: _nat_static(con, a[0], a[1], False),
        "Negate a command or set its defaults", C)
    add("show access-lists", lambda a: show_lists(con, ""), "List access lists", U)
    add("show access-lists <name>", lambda a: show_lists(con, a[0]), "List access lists", U)
    add("show ip access-lists", lambda a: show_lists(con, ""), "List IP access lists", U)
    add("show ip access-lists <name>", lambda a: show_lists(con, a[0]), "List IP access lists", U)
    add("show ip nat translations", lambda a: show_nat(con), "Translation entries", U)
    add("show ip nat statistics", lambda a: show_nat_stats(con), "Translation statistics", U)
    add("clear ip nat translation *", lambda a: _clear_nat(con), "Delete all dynamic translations", E)
    add("clear access-list counters", lambda a: _clear_counters(con), "Clear access list statistical information", E)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _err(exc) -> Exception:
    from . import devcli
    return devcli.CliError(str(exc))


def _done(con) -> str:
    return con._save().strip()


def _route(con, a, on: bool) -> str:
    from . import devcli
    try:
        net = ipaddress.IPv4Network(f"{a[0]}/{a[1]}")
    except ValueError:
        try:
            ipaddress.IPv4Network(f"{a[0]}/{a[1]}", strict=False)
            raise devcli.CliError("%Inconsistent address and mask")
        except ValueError:
            raise devcli.CliError("% Invalid input detected at '^' marker.") from None
    w = a[2].split()
    own = _own_c(con)
    if not on and not w:
        for k in [k for k in own if k.startswith((f"route:{net} ", f"route-track:{net} "))]:
            del own[k]
        return _done(con)
    obj = None
    if "track" in [x.lower() for x in w]:   # ip route ... track <object> (winlab/iossla.py)
        i = [x.lower() for x in w].index("track")
        if i + 1 >= len(w) or not w[i + 1].isdigit() or not 1 <= int(w[i + 1]) <= 1000:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        obj = int(w[i + 1])
        w = w[:i] + w[i + 2:]
    if not w:
        raise devcli.CliError("% Incomplete command.")
    target = w[0]
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        target = str(ipaddress.IPv4Address(target))
    else:
        from . import vti  # a route into interface Tunnel<n>
        target = vti.tunnel_name(target) or devcli.parse_if(target, con._if_names(), sub=True)
    dist = 1
    if len(w) > 1:
        if not w[1].isdigit() or not 1 <= int(w[1]) <= 255:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        dist = int(w[1])
    key = f"route:{net} {target}"
    from . import iossla
    if on:
        own[key] = str(dist)
        iossla.route_track(own, net, target, obj)
    elif own.pop(key, None) is None:
        return "%No matching route to delete"
    else:
        iossla.route_track(own, net, target, None)
    note = _done(con)
    if on and obj and f"track:{obj}" not in own:
        note = "\n".join(x for x in (f"% Track object {obj} does not exist yet: the route stays out of the table "
                                      f"until it is Up", note) if x)
    return note


def _numbered(con, name: str, text: str) -> str:
    from . import devcli
    own = _own_c(con)
    kind = "standard" if std_range(name) else "extended" if ext_range(name) else ""
    if not kind:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    w = text.split()
    if w and w[0] == "remark":
        return ""
    try:
        add_entry(own, name, kind, text)
    except AclError as exc:
        raise _err(exc) from None
    return _done(con)


def _named(con, name: str, kind: str) -> str:
    from . import devcli
    own = _own_c(con)
    if name.isdigit() and not (std_range(name) if kind == "standard" else ext_range(name)):
        raise devcli.CliError(f"% Invalid access list name.")
    have = kind_of(own, name)
    if have and have != kind:
        raise devcli.CliError(f"% A named {have} IP access list with this name already exists")
    if not have and not name.isdigit():
        own[f"acltype:{name}"] = kind
    con.s.mode = "config-std-nacl" if kind == "standard" else "config-ext-nacl"
    con.s.ctx = name
    con._save(live=False)
    return ""


def _entry(con, text: str, seq: int | None = None) -> str:
    own = _own_c(con)
    kind = "standard" if con.s.mode == "config-std-nacl" else "extended"
    try:
        add_entry(own, con.s.ctx, kind, text, seq)
    except AclError as exc:
        raise _err(exc) from None
    return _done(con)


def _seq_entry(con, seq: str, text: str) -> str:
    from . import devcli
    if not seq.isdigit() or not 1 <= int(seq) <= 2147483647:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    w = text.split()
    if not w or w[0] not in ("permit", "deny"):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    return _entry(con, text, int(seq))


def _no_seq(con, seq: str) -> str:
    from . import devcli
    if not seq.isdigit():
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    remove_seq(_own_c(con), con.s.ctx, int(seq))
    return _done(con)


def _no_list(con, name: str) -> str:
    remove_list(_own_c(con), name)
    return _done(con)


def _group(con, name: str, way: str, on: bool) -> str:
    from . import devcli
    w = way.split()
    if not name and len(w) == 2:   # no ip access-group <list> in|out, read by the shorter form
        name, way = w
    way = way.strip().lower()
    if way not in ("in", "out"):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    key = f"acl-{way}:{con.s.ctx}"
    if on:
        own[key] = name
    else:
        own.pop(key, None)
    return _done(con)


def _nat_side(con, side: str) -> str:
    own = _own_c(con)
    if side:
        own[f"nat:{con.s.ctx}"] = side
    else:
        own.pop(f"nat:{con.s.ctx}", None)
    return _done(con)


def _nat_rule(con, lst: str, rest: str, on: bool) -> str:
    from . import devcli
    w = rest.split()
    if not w:
        raise devcli.CliError("% Incomplete command.")
    ifname = devcli.parse_if(w[0], con._if_names(), sub=True)
    extra = [x for x in w[1:] if x.lower() != "overload"]
    if extra:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    if on:
        own[f"natsrc:{lst}"] = f"{ifname} overload"
    else:
        own.pop(f"natsrc:{lst}", None)
    return _done(con)


def _nat_pool(con, name: str, start: str, end: str, rest: str) -> str:
    from . import devcli
    try:
        a, b = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
    except ValueError:
        raise devcli.CliError("% Invalid input detected at '^' marker.") from None
    w = rest.split()
    if len(w) != 2:
        raise devcli.CliError("% Incomplete command." if len(w) < 2 else "% Invalid input detected at '^' marker.")
    word = w[0].lower()
    try:
        if word[:1] == "n" and "netmask".startswith(word):
            plen = ipaddress.IPv4Network(f"0.0.0.0/{w[1]}").prefixlen
            typed_pl = False
        elif word[:1] == "p" and "prefix-length".startswith(word):
            plen = int(w[1])
            if not 1 <= plen <= 32:
                raise ValueError
            typed_pl = True
        else:
            raise ValueError
    except ValueError:
        raise devcli.CliError("% Invalid input detected at '^' marker.") from None
    if int(b) < int(a):
        raise devcli.CliError("%End address less than starting address")
    if ipaddress.IPv4Network(f"{a}/{plen}", strict=False) != ipaddress.IPv4Network(f"{b}/{plen}", strict=False):
        raise devcli.CliError("%Start and end addresses on different subnets")
    own = _own_c(con)
    in_use = [k[7:] for k, v in own.items() if k.startswith("natsrc:") and _rule_target(v)[1] == name]
    old = own.get(f"natpool:{name}")
    new = f"{a} {b} {plen}"
    if old and old != new and in_use:
        raise devcli.CliError(f"%Pool {name} in use, cannot redefine")
    own[f"natpool:{name}"] = new
    if typed_pl:
        own[f"natpool-pl:{name}"] = "yes"
    else:
        own.pop(f"natpool-pl:{name}", None)
    note = _done(con)
    n = int(b) - int(a) + 1
    if n > POOL_MAX:
        note = (note + "\n" if note else "") + (f"% A pool without overload uses its first {POOL_MAX} addresses here "
                                                 f"(one nftables set each); with overload, all {n}")
    return note


def _no_pool(con, name: str) -> str:
    from . import devcli
    own = _own_c(con)
    if f"natpool:{name}" not in own:
        raise devcli.CliError(f"%Pool {name} not found")
    if any(k.startswith("natsrc:") and _rule_target(v)[1] == name for k, v in own.items()):
        raise devcli.CliError(f"%Pool {name} in use, cannot destroy")
    own.pop(f"natpool:{name}", None)
    own.pop(f"natpool-pl:{name}", None)
    return _done(con)


def _nat_pool_rule(con, lst: str, pool: str, rest: str, on: bool) -> str:
    from . import devcli
    extra = [x.lower() for x in rest.split()]
    if len(extra) > 1 or any(not "overload".startswith(x) for x in extra):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    if on:
        note = "" if f"natpool:{pool}" in own else \
            f"% Pool {pool} is not defined yet: the rule takes effect once ip nat pool {pool} ... is typed"
        own[f"natsrc:{lst}"] = f"pool {pool}" + (" overload" if extra else "")
        done = _done(con)
        return "\n".join(x for x in (note, done) if x)
    if own.get(f"natsrc:{lst}", "").split()[:2] == ["pool", pool]:
        own.pop(f"natsrc:{lst}", None)
    return _done(con)


def _nat_static(con, local: str, glob: str, on: bool) -> str:
    from . import devcli
    try:
        local, glob = str(ipaddress.IPv4Address(local)), str(ipaddress.IPv4Address(glob))
    except ValueError:
        raise devcli.CliError("% Invalid input detected at '^' marker.") from None
    own = _own_c(con)
    if on:
        for k, v in own.items():
            if k.startswith("natstatic:") and v == glob and k != f"natstatic:{local}":
                raise devcli.CliError(f"% {glob} already mapped ({k[10:]} -> {glob})")
        own[f"natstatic:{local}"] = glob
    else:
        own.pop(f"natstatic:{local}", None)
    return _done(con)


def show_lists(con, only: str) -> str:
    own = con.lab.devices.get("router", {})
    counts: dict = {}
    if con.powered() and any(k.startswith(("acl-in:", "acl-out:")) for k in own):
        try:
            counts = parse_counters(con._on_router(ACL_LIVE_CMD, timeout=10))
        except Exception:  # noqa: BLE001 - the list still shows without its counters
            counts = {}
    out = []
    for name in names(own):
        if only and name != only:
            continue
        kind = kind_of(own, name)
        out.append(f"{kind.capitalize()} IP access list {name}")
        for seq, t in entries(own, name):
            hits = counts.get((name, seq), 0)
            out.append(f"    {seq} {show_entry(t)}" + (f" ({hits} match{'es' if hits != 1 else ''})" if hits else ""))
    return "\n".join(out)


def show_nat(con) -> str:
    own = con.lab.devices.get("router", {})
    rows = []
    for local, glob in sorted((k[10:], v) for k, v in own.items() if k.startswith("natstatic:")):
        rows.append(("---", glob, local, "---", "---"))
    if con.powered():
        try:
            rows += parse_conntrack(con._on_router(NAT_LIVE_CMD, timeout=15))
        except Exception:  # noqa: BLE001
            pass
    out = [f"{'Pro':<4}{'Inside global':<22}{'Inside local':<22}{'Outside local':<22}Outside global"]
    out += [f"{p:<4}{a:<22}{b:<22}{c:<22}{d}" for p, a, b, c, d in rows]
    return "\n".join(out)


NAT_TABLE_CMD = f"nft list table ip {TABLE_NAT} 2>/dev/null"


def parse_pool_state(text: str) -> dict[str, dict]:
    """nft list table ip wlnat -> {pool: {"allocated": {inside: global},
    "misses": n}} for the pools without overload."""
    out: dict[str, dict] = {}
    owner: dict[str, tuple[str, str]] = {}   # set name -> (pool, address)
    for line in text.splitlines():
        m = re.search(r'add @(p_\S+) \{ ip saddr \} .*snat to (\S+) comment "pool (\S+) ', line)
        if m:
            owner[m.group(1)] = (m.group(3), m.group(2))
    elems: dict[str, list[str]] = {}
    cur = ""
    for line in text.splitlines():
        m = re.match(r"\s*set (p_\S+) \{", line)
        if m:
            cur = m.group(1)
            continue
        if cur and "elements" in line:
            elems[cur] = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line.split("=", 1)[1])
        if cur and line.strip() == "}":
            cur = ""
        m = re.search(r'counter packets (\d+) bytes \d+ drop comment "pool (\S+) exhausted"', line)
        if m:
            out.setdefault(m.group(2), {"allocated": {}, "misses": 0})["misses"] = int(m.group(1))
    for sn, (pool, addr) in owner.items():
        d = out.setdefault(pool, {"allocated": {}, "misses": 0})
        for host in elems.get(sn, []):
            d["allocated"][host] = addr
    return out


def show_nat_stats(con) -> str:
    own = con.lab.devices.get("router", {})
    side = lambda s: ", ".join(k[4:] for k, v in sorted(own.items()) if k.startswith("nat:") and v == s)  # noqa: E731
    rows = show_nat(con).splitlines()[1:]
    state: dict = {}
    have = pools(own)
    if have and con.powered():
        try:
            state = parse_pool_state(con._on_router(NAT_TABLE_CMD, timeout=10))
        except Exception:  # noqa: BLE001 - the pools still show, with nothing allocated
            state = {}
    out = [f"Total active translations: {len(rows)}",
           f"Outside interfaces:\n  {side('outside')}", f"Inside interfaces:\n  {side('inside')}",
           "Dynamic mappings:"]
    for i, (k, v) in enumerate(sorted((k, v) for k, v in own.items() if k.startswith("natsrc:")), 1):
        ifname, pool, over = _rule_target(v)
        if not pool:
            out.append(f"-- Inside Source\n[Id: {i}] access-list {k[7:]} interface {ifname} refcount {len(rows)}")
            continue
        out.append(f"-- Inside Source\n[Id: {i}] access-list {k[7:]} pool {pool}" + (" overload" if over else "")
                   + f" refcount {len(rows)}")
        if pool not in have:
            out.append(f" pool {pool}: not defined (ip nat pool {pool} ...)")
            continue
        start, end, plen = have[pool]
        addrs = pool_addrs(start, end)
        st = state.get(pool, {"allocated": {}, "misses": 0})
        if over:
            used = {r.split()[1].split(":")[0] for r in rows if len(r.split()) > 1}
            alloc = len(used & set(addrs))
        else:
            alloc = len(set(st["allocated"].values()))
        total = len(addrs)
        out += [f" pool {pool}: netmask {ipaddress.IPv4Network(f'0.0.0.0/{plen}').netmask}",
                f"\tstart {start} end {end}",
                f"\ttype generic, total addresses {total}, allocated {alloc} ({alloc * 100 // max(total, 1)}%), "
                f"misses {st['misses']}"]
    return "\n".join(out)


# The pools' dynamic sets go with the translations, so their addresses are free again.
CLEAR_NAT_CMD = (f"for s in $(nft list table ip {TABLE_NAT} 2>/dev/null | sed -n 's/^[[:space:]]*set \\(p_[^ ]*\\) .*/\\1/p'); "
                 f"do nft flush set ip {TABLE_NAT} \"$s\"; done; conntrack -F 2>/dev/null; true")


def _clear_nat(con) -> str:
    con._on_router(CLEAR_NAT_CMD, timeout=10)
    return ""


def _clear_counters(con) -> str:
    con._on_router(f"nft reset counters table ip {TABLE_ACL} >/dev/null 2>&1; true", timeout=10)
    return ""
