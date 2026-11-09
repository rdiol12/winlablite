"""IPv6 access lists, typed at the router's and the switches' consoles.

``ipv6 access-list <name>`` makes a named list and enters its mode, where
each ``permit`` or ``deny`` line is an entry: a protocol (ipv6, tcp, udp,
icmp, or a number), a source and a destination (``any``, ``host <address>``
or ``<prefix>/<len>``), ports for TCP and UDP (``eq``, ``neq``, ``lt``,
``gt``, ``range``), an ICMPv6 message for icmp (``echo-request``,
``nd-ns``, ``router-advertisement``...) and ``log``. ``sequence <n>`` puts
an entry at a place of its own; entries are numbered 10, 20... otherwise.
Every list ends, as on IOS, with three entries nobody typed:

    permit icmp any any nd-na
    permit icmp any any nd-ns
    deny ipv6 any any

so neighbour discovery survives a list that permits nothing else, unless an
entry typed above them (a ``deny ipv6 any any log`` at the end, the habit
IPv4 lists teach) denies it first: then the hosts on that link cannot
resolve the router's address, and nothing works. That is a classic ticket
(content/lessons/ts-ipv6-acl-blocks-nd.toml).

How it is real:

* on the router, ``ipv6 traffic-filter <list> in | out`` on an interface is
  an nftables table of the ip6 family (TABLE): a chain per list, each entry
  a rule with its own counter (what ``show ipv6 access-list`` prints as
  matches), then the implicit three. ``in`` filters what the interface's
  SVI receives, forwarded or for the router itself (neighbour discovery
  included), ``out`` what the router forwards out of it; what the router
  sends itself is not filtered, as on IOS. Built by iosl3.render, so it is
  pushed into the running router like the IPv4 lists;
* on a switch, ``ipv6 traffic-filter <list> in`` on an access port is a port
  ACL: the same rules in the bridge family, in the table port security uses
  (portsec.TABLE, winlab/l2sec.py), on the frames that come in on that
  port. Port ACLs filter inbound only, as on a Catalyst.

Settings, on the router and on a switch alike: ``acl6:<name>`` = entries
``<seq> <entry>``, ';'-separated (an empty value is an empty list);
``acl6-in:<if>`` / ``acl6-out:<if>`` = the list on an interface (a switch's
access port by the cable in it, as its other settings are).
"""

from __future__ import annotations

import ipaddress
import re

TABLE = "wlacl6"
MODE = "config-ipv6-acl"
PROTOS = {"ipv6": 0, "tcp": 6, "udp": 17, "icmp": 58, "esp": 50, "ahp": 51, "sctp": 132, "pcp": 108}
PORTS = {"www": 80, "domain": 53, "telnet": 23, "ftp": 21, "ftp-data": 20, "smtp": 25, "pop3": 110,
         "tftp": 69, "bootps": 67, "bootpc": 68, "snmp": 161, "ntp": 123, "syslog": 514, "bgp": 179,
         "ssh": 22, "https": 443, "dhcpv6-client": 546, "dhcpv6-server": 547}
PORT_NAMES = {v: k for k, v in PORTS.items() if k not in ("ssh", "https")}
# IOS's ICMPv6 message names -> nftables' icmpv6 type names.
ICMP6 = {"echo-request": "echo-request", "echo-reply": "echo-reply", "nd-ns": "nd-neighbor-solicit",
         "nd-na": "nd-neighbor-advert", "router-advertisement": "nd-router-advert",
         "router-solicitation": "nd-router-solicit", "redirect": "nd-redirect",
         "unreachable": "destination-unreachable", "packet-too-big": "packet-too-big",
         "time-exceeded": "time-exceeded", "parameter-problem": "parameter-problem"}
IMPLICIT = ["permit icmp any any nd-na", "permit icmp any any nd-ns", "deny ipv6 any any"]
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class Acl6Error(ValueError):
    """What the console prints for an entry it cannot take."""


# ------------------------------------------------------------------ the lists
def names(own: dict) -> list[str]:
    return sorted(k[5:] for k in own if k.startswith("acl6:"))


def exists(own: dict, name: str) -> bool:
    return f"acl6:{name}" in own


def entries(own: dict, name: str) -> list[tuple[int, str]]:
    out = []
    for part in [p.strip() for p in str(own.get(f"acl6:{name}", "")).split(";") if p.strip()]:
        m = re.match(r"^(\d+)\s+(.*)$", part)
        if m:
            out.append((int(m.group(1)), m.group(2)))
    return sorted(out)


def _store(own: dict, name: str, rows: list[tuple[int, str]]) -> None:
    own[f"acl6:{name}"] = ";".join(f"{s} {t}" for s, t in sorted(rows))


def add_entry(own: dict, name: str, text: str, seq: int | None = None) -> str:
    entry = parse_entry(text)
    rows = entries(own, name)
    if any(t == entry for _, t in rows):
        return entry   # the same entry again: IOS keeps one
    if seq is None:
        seq = (rows[-1][0] if rows else 0) + 10
    elif any(s == seq for s, _ in rows):
        raise Acl6Error("% Duplicate sequence number")
    _store(own, name, rows + [(seq, entry)])
    return entry


def remove(own: dict, name: str, text: str = "", seq: int | None = None) -> bool:
    rows = entries(own, name)
    if seq is not None:
        left = [(s, t) for s, t in rows if s != seq]
    else:
        entry = parse_entry(text)
        left = [(s, t) for s, t in rows if t != entry]
    if len(left) == len(rows):
        return False
    _store(own, name, left)
    return True


# ------------------------------------------------------------------ parsing
def _addr(tokens: list[str], i: int) -> tuple[str, int]:
    """any | host <a> | <prefix>/<len> at tokens[i] -> (kept form, next i)."""
    if i >= len(tokens):
        raise Acl6Error("% Incomplete command.")
    t = tokens[i].lower()
    try:
        if t == "any":
            return "any", i + 1
        if t == "host":
            return f"host {ipaddress.IPv6Address(tokens[i + 1])}", i + 2
        if "/" in t:
            net = ipaddress.IPv6Network(t, strict=False)
            return (f"host {net.network_address}" if net.prefixlen == 128 else str(net)), i + 1
    except (ValueError, IndexError):
        pass
    raise Acl6Error("% Invalid input detected at '^' marker: an address is any, host <address> or "
                    "<prefix>/<length>")


def _ports(tokens: list[str], i: int, proto: str) -> tuple[str, int]:
    if i >= len(tokens) or proto not in ("tcp", "udp") or tokens[i] not in ("eq", "neq", "lt", "gt", "range"):
        return "", i
    op, n = tokens[i], 2 if tokens[i] == "range" else 1
    vals = []
    for t in tokens[i + 1:i + 1 + n]:
        v = PORTS.get(t.lower(), int(t) if t.isdigit() else None)
        if v is None or not 0 <= v <= 65535:
            raise Acl6Error("% Invalid input detected at '^' marker.")
        vals.append(str(v))
    if len(vals) != n:
        raise Acl6Error("% Incomplete command.")
    return f"{op} {' '.join(vals)}", i + 1 + n


def parse_entry(text: str) -> str:
    """'<permit|deny> <proto> <src> [ports] <dst> [ports] [icmp type] [log]',
    checked and kept in one form (addresses compressed, ports as numbers)."""
    w = text.split()
    if len(w) < 2 or w[0].lower() not in ("permit", "deny"):
        raise Acl6Error("% Invalid input detected at '^' marker.")
    proto = w[1].lower()
    if proto not in PROTOS and not (proto.isdigit() and 0 <= int(proto) <= 255):
        raise Acl6Error("% Invalid input detected at '^' marker: the protocol is ipv6, tcp, udp, icmp or a number")
    src, i = _addr(w, 2)
    sport, i = _ports(w, i, proto)
    dst, i = _addr(w, i)
    dport, i = _ports(w, i, proto)
    extra = []
    while i < len(w):
        t = w[i].lower()
        if proto == "icmp" and t in ICMP6 and not any(x in ICMP6 for x in extra):
            extra.append(t)
        elif t == "log" and "log" not in extra:
            extra.append(t)
        else:
            raise Acl6Error("% Invalid input detected at '^' marker.")
        i += 1
    return " ".join([w[0].lower(), proto, src] + ([sport] if sport else []) + [dst]
                    + ([dport] if dport else []) + extra)


def parse(entry: str) -> dict:
    w = entry.split()
    proto = w[1]
    src, i = _addr(w, 2)
    sport, i = _ports(w, i, proto)
    dst, i = _addr(w, i)
    dport, i = _ports(w, i, proto)
    icmp = next((t for t in w[i:] if t in ICMP6), "")
    return {"action": w[0], "proto": proto, "src": src, "dst": dst, "sport": sport, "dport": dport,
            "icmp": icmp, "log": "log" in w[i:]}


def up(entry: str) -> str:
    """An entry as IOS prints it: addresses in capitals, well-known ports by name."""
    out = []
    w = entry.split()
    for j, t in enumerate(w):
        if ":" in t:
            t = t.upper()
        elif j > 0 and w[j - 1] in ("eq", "neq", "lt", "gt") and t.isdigit() and int(t) in PORT_NAMES:
            t = PORT_NAMES[int(t)]
        out.append(t)
    return " ".join(out)


# ------------------------------------------------------------------ matching (what nftables decides)
def _addr_ok(spec: str, ip: str) -> bool:
    if spec == "any":
        return True
    a = ipaddress.IPv6Address(ip)
    if spec.startswith("host "):
        return a == ipaddress.IPv6Address(spec[5:])
    return a in ipaddress.IPv6Network(spec)


def _port_ok(spec: str, port: int | None) -> bool:
    if not spec:
        return True
    if port is None:
        return False
    op, *vals = spec.split()
    v = [int(x) for x in vals]
    return {"eq": port == v[0], "neq": port != v[0], "lt": port < v[0], "gt": port > v[0],
            "range": len(v) == 2 and v[0] <= port <= v[1]}[op]


def decide(own: dict, name: str, src: str, dst: str, proto: str = "ipv6", sport: int | None = None,
           dport: int | None = None, icmp: str = "") -> tuple[str, str]:
    """What a list does with a packet: ('permit'|'deny', the sequence that
    matched, or 'implicit nd' / 'implicit deny')."""
    rows = [(str(s), t) for s, t in entries(own, name)] + [("implicit nd", IMPLICIT[0]),
                                                           ("implicit nd", IMPLICIT[1]),
                                                           ("implicit deny", IMPLICIT[2])]
    for seq, entry in rows:
        e = parse(entry)
        if e["proto"] != "ipv6" and e["proto"] != proto and str(PROTOS.get(proto, -1)) != e["proto"]:
            continue
        if not (_addr_ok(e["src"], src) and _addr_ok(e["dst"], dst)):
            continue
        if not (_port_ok(e["sport"], sport) and _port_ok(e["dport"], dport)):
            continue
        if e["icmp"] and e["icmp"] != icmp:
            continue
        return e["action"], seq
    return "deny", "implicit deny"


# ------------------------------------------------------------------ nftables
def _nft_addr(field_: str, spec: str) -> str:
    if spec == "any":
        return ""
    return f"ip6 {field_} {spec[5:] if spec.startswith('host ') else spec} "


def _nft_ports(proto: str, field_: str, spec: str) -> str:
    if not spec:
        return ""
    op, *v = spec.split()
    if op == "range":
        return f"{proto} {field_} {v[0]}-{v[1]} "
    return f"{proto} {field_} {({'eq': '', 'neq': '!= ', 'lt': '< ', 'gt': '> '}[op])}{v[0]} "


def nft_rule(entry: str, comment: str) -> str:
    """One entry as an nftables rule with its own counter (ip6 or bridge
    family alike: the bridge's rules put ``ether type ip6`` in front)."""
    e = parse(entry)
    proto, out = e["proto"], ""
    if proto == "icmp":
        out += "meta l4proto ipv6-icmp "
    elif proto in ("tcp", "udp"):
        out += f"meta l4proto {proto} "
    elif proto != "ipv6":
        out += f"meta l4proto {PROTOS.get(proto, proto)} "
    out += _nft_addr("saddr", e["src"]) + _nft_addr("daddr", e["dst"])
    out += _nft_ports(proto, "sport", e["sport"]) + _nft_ports(proto, "dport", e["dport"])
    if e["icmp"]:
        out += f"icmpv6 type {ICMP6[e['icmp']]} "
    if e["log"]:
        out += f"log prefix \"{comment[:100]}: \" "
    return f"{out}counter {'accept' if e['action'] == 'permit' else 'drop'} comment \"{comment}\""


def chain_body(own: dict, name: str, verdict_ok: str = "accept") -> list[str]:
    """A list's rules, then the implicit three. In the bridge family a
    permit must not end the chain other features run in, so verdict_ok is
    'return' there."""
    body = [nft_rule(t, f"{name} {s}") for s, t in entries(own, name)]
    body += [f"meta l4proto ipv6-icmp icmpv6 type {{ nd-neighbor-advert, nd-neighbor-solicit }} counter "
             f"accept comment \"{name} implicit nd\"", f"counter drop comment \"{name} implicit deny\""]
    if verdict_ok != "accept":
        body = [b.replace(" accept comment", f" {verdict_ok} comment") for b in body]
    return body


def chain_name(name: str) -> str:
    return "acl6_" + re.sub(r"[^A-Za-z0-9_]", "_", name)


def render(plan, reset: bool = False) -> list[str]:
    """The router's IPv6 lists on its interfaces (from iosl3.render)."""
    from .iosl3 import svi_for
    lab = plan.lab
    own = lab.devices.get("router", {})
    applied = sorted((k, v) for k, v in own.items() if k.startswith(("acl6-in:", "acl6-out:")))
    if not applied and not reset:
        return []
    out = ["# IPv6 access lists on the router's interfaces (winlab/acl6.py)",
           f"nft delete table ip6 {TABLE} 2>/dev/null || true"]
    fwd, inp, chains = [], [], {}
    for k, name in applied:
        way, ifname = k.split(":", 1)
        dev = svi_for(lab, plan, ifname)
        if not dev or not exists(own, name):
            continue   # a list that does not exist filters nothing, as on IOS
        ch = chain_name(name)
        chains.setdefault(ch, chain_body(own, name))
        if way == "acl6-in":
            fwd.append(f"iifname \"{dev}\" jump {ch}")
            inp.append(f"iifname \"{dev}\" jump {ch}")
        else:
            fwd.append(f"oifname \"{dev}\" jump {ch}")
    if chains:
        out += ["nft -f - <<'WLACL6' || true", f"table ip6 {TABLE} {{"]
        for ch, body in sorted(chains.items()):
            out += [f"  chain {ch} {{"] + [f"    {r}" for r in body] + ["  }"]
        out += ["  chain forward {", "    type filter hook forward priority -5; policy accept;"]
        out += [f"    {r}" for r in fwd] + ["  }"]
        out += ["  chain input {", "    type filter hook input priority -5; policy accept;"]
        out += [f"    {r}" for r in inp] + ["  }", "}", "WLACL6"]
    return out


LIVE_CMD = f"nft list table ip6 {TABLE} 2>/dev/null"


def parse_counters(text: str) -> dict[tuple[str, str], int]:
    """'counter packets 3 bytes 240 ... comment "GUEST 10"' -> {(list, '10'): 3}
    (and 'implicit nd' / 'implicit deny' for the three nobody typed)."""
    out: dict[tuple[str, str], int] = {}
    for line in (text or "").splitlines():
        m = re.search(r'counter packets (\d+) bytes \d+.*comment "(\S+) ((?:\d+)|implicit nd|implicit deny)"', line)
        if m:
            key = (m.group(2), m.group(3))
            out[key] = out.get(key, 0) + int(m.group(1))
    return out


# ------------------------------------------------------------------ show and running-config
def show(own: dict, only: str = "", counts: dict | None = None) -> str:
    counts = counts or {}
    out = []
    for name in names(own):
        if only and name != only:
            continue
        out.append(f"IPv6 access list {name}")
        for seq, t in entries(own, name):
            n = counts.get((name, str(seq)), 0)
            out.append(f"    {up(t)}" + (f" ({n} match{'es' if n != 1 else ''})" if n else "") + f" sequence {seq}")
    if only and not out:
        return ""
    return "\n".join(out)


def run_lines(own: dict) -> list[str]:
    out = []
    for name in names(own):
        out.append(f"ipv6 access-list {name}")
        for k, (seq, t) in enumerate(entries(own, name), 1):
            out.append(f" {up(t)}" if seq == 10 * k else f" sequence {seq} {up(t)}")
        out.append("!")
    return out


def iface_lines(own: dict, key: str) -> list[str]:
    return [f" ipv6 traffic-filter {own[f'acl6-{way}:{key}']} {way}" for way in ("in", "out")
            if own.get(f"acl6-{way}:{key}")]


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, E, C, IF, switch: bool = False) -> None:
    """ipv6 access-list and its mode, ipv6 traffic-filter on an interface,
    show and clear (the router's and the switches' consoles)."""
    from . import devcli
    M = (MODE,)
    devcli.WORD_HELP.setdefault(("ipv6", "access-list"), "Configure access lists")
    devcli.WORD_HELP.setdefault(("ipv6", "traffic-filter"), "Access control list for packets")
    devcli.WORD_HELP.setdefault(("show", "ipv6", "access-list"), "Summary of access lists")
    devcli.WORD_HELP.setdefault(("show", "ipv6"), "IPv6 information")
    devcli.WORD_HELP.setdefault(("ipv6",), "IPv6 interface subcommands")
    devcli.MODE_PROMPTS.setdefault(MODE, MODE)
    add("ipv6 access-list <name>", lambda a: _list(con, a[0]), "Configure access lists", C + M)
    add("no ipv6 access-list <name>", lambda a: _no_list(con, a[0]), "Negate a command or set its defaults", C)
    add("permit <line>", lambda a: _entry(con, "permit " + a[0]), "Specify packets to forward", M)
    add("deny <line>", lambda a: _entry(con, "deny " + a[0]), "Specify packets to reject", M)
    add("sequence <num> <line>", lambda a: _seq(con, a[0], a[1]), "Sequence number for this entry", M)
    add("no sequence <num>", lambda a: _no_entry(con, "", a[0]), "Negate a command or set its defaults", M)
    add("no permit <line>", lambda a: _no_entry(con, "permit " + a[0], ""), "Negate a command or set its defaults", M)
    add("no deny <line>", lambda a: _no_entry(con, "deny " + a[0], ""), "Negate a command or set its defaults", M)
    add("remark <line>", lambda a: "", "Access list entry comment", M)
    add("end", con._end, "Exit from configure mode", M)
    add("exit", con._cfg_exit, "Exit from access-list configuration mode", M)
    add("do <line>", con._do, "To run exec commands in config mode", M)
    add("ipv6 traffic-filter <name> <line>", lambda a: _filter(con, a[0], a[1], True, switch),
        "Access control list for packets", IF)
    add("no ipv6 traffic-filter <name> <line>", lambda a: _filter(con, a[0], a[1], False, switch),
        "Negate a command or set its defaults", IF)
    add("show ipv6 access-list", lambda a: _show(con, ""), "Summary of access lists", U)
    add("show ipv6 access-list <name>", lambda a: _show(con, a[0]), "Summary of access lists", U)
    add("clear ipv6 access-list", lambda a: _clear(con), "Clear IPv6 access list statistical information", E)


def _own(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, con.device)


def _err(exc) -> Exception:
    from . import devcli
    return devcli.CliError(str(exc))


def _done(con) -> str:
    if con.device != "router":
        from . import portsec   # a switch's port ACLs are in the port table
        return portsec.done(con)
    return con._save().strip()


def _list(con, name: str) -> str:
    from . import devcli
    if not _NAME.match(name):
        raise devcli.CliError("% Invalid access list name: a letter, then letters, digits, '-', '_' or '.'")
    own = _own(con)
    own.setdefault(f"acl6:{name}", "")
    con.s.mode, con.s.ctx = MODE, name
    con._save(live=False)
    return ""


def _no_list(con, name: str) -> str:
    own = _own(con)
    if own.pop(f"acl6:{name}", None) is None:
        return ""
    return _done(con)


def _entry(con, text: str, seq: int | None = None) -> str:
    try:
        add_entry(_own(con), con.s.ctx, text, seq)
    except Acl6Error as exc:
        raise _err(exc) from None
    return _done(con)


def _seq(con, seq: str, text: str) -> str:
    from . import devcli
    if not seq.isdigit() or not 1 <= int(seq) <= 4294967295:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    return _entry(con, text, int(seq))


def _no_entry(con, text: str, seq: str) -> str:
    from . import devcli
    try:
        hit = remove(_own(con), con.s.ctx, text, int(seq) if seq else None)
    except (Acl6Error, ValueError) as exc:
        raise _err(exc) from None
    if not hit:
        raise devcli.CliError("% No such entry in the list")
    return _done(con)


def port_key(con) -> str:
    """The interface being configured, as a switch keeps its settings."""
    from . import devcli
    ctx = con.s.ctx
    if ctx.startswith("FastEthernet"):
        from . import portsec
        return portsec.write_key(con)
    raise devcli.CliError("% A port ACL goes on an access port (Fa0/1 to Fa0/24): the gigabit ports here are "
                          "trunks between switches and to the router")


def _filter(con, name: str, way: str, on: bool, switch: bool) -> str:
    from . import devcli
    w = way.split()
    if len(w) != 1 or w[0].lower() not in ("in", "out"):
        raise devcli.CliError("% Invalid input detected at '^' marker: ipv6 traffic-filter <list> in | out")
    way = w[0].lower()
    own = _own(con)
    if switch:
        if way == "out":
            raise devcli.CliError("% Port ACLs filter inbound only on this switch: ipv6 traffic-filter <list> in")
        key = port_key(con)
    else:
        key = con.s.ctx
    k = f"acl6-{way}:{key}"
    if on:
        own[k] = name
    elif own.get(k) in (name, None):
        own.pop(k, None)
    out = _done(con)
    if on and not exists(own, name):
        out = (out + "\n" if out else "") + (f"% IPv6 access list {name} does not exist yet: until it does, "
                                             f"nothing is filtered")
    return out


def _counts(con) -> dict:
    if not con.powered():
        return {}
    try:
        if con.device == "router":
            return parse_counters(con._on_router(LIVE_CMD, timeout=10))
        from .portsec import TABLE as PT
        return parse_counters(con._on_router(f"nft list table bridge {PT} 2>/dev/null", timeout=10))
    except Exception:  # noqa: BLE001 - the list still shows without its counters
        return {}


def _show(con, name: str) -> str:
    own = _own(con)
    if not any(k.startswith(("acl6-in:", "acl6-out:")) for k in own):
        return show(own, name)
    return show(own, name, _counts(con))


def _clear(con) -> str:
    from .portsec import TABLE as PT
    cmd = (f"nft reset counters table ip6 {TABLE} >/dev/null 2>&1; true" if con.device == "router"
           else f"nft reset counters table bridge {PT} >/dev/null 2>&1; true")
    try:
        con._on_router(cmd, timeout=10)
    except Exception:  # noqa: BLE001 - nothing running: nothing counted
        pass
    return ""
