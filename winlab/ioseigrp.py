"""EIGRP typed at the lab router's console, made real by FRRouting's eigrpd.

``router eigrp <as>`` and what follows it become a ``router eigrp`` block in
the router's /etc/frr/frr.conf (written whole by winlab/iosrouting.py, which
starts eigrpd in /etc/frr/daemons only while EIGRP is configured), and the
interface lines (``delay``, ``bandwidth``, ``ip hello-interval eigrp``,
``ip hold-time eigrp``) become eigrpd's interface lines. eigrpd speaks EIGRP
(RFC 7868) on the wire: real hellos to 224.0.0.10, real updates, the DUAL
topology table with successors and feasible successors, routes installed by
zebra at administrative distance 90, so a route EIGRP and OSPF (110) both
know is EIGRP's, as on IOS. The router it peers with in the lab is rtr-edge
(Ubuntu with FRRouting's eigrpd from the frr pack); on real gear both ends
would be Cisco routers. ``show ip eigrp neighbors``, ``topology [all-links]``
and ``interfaces`` read eigrpd (it has no JSON output, so its text is parsed)
and print the IOS layout with the console's interface names; ``show ip route
eigrp`` reads zebra's JSON and prints code D.

What FRRouting's eigrpd does not do, read from its source (FRRouting 10.2,
eigrpd/) and its documentation, and what the console says about it:

* Its own project calls it alpha. Seen on FRRouting 8.4.4 here (two and three
  routers in network namespaces): neighbours, the topology table, the
  classic metric (256 x (10^7/bandwidth + delay)), ``delay`` changing it, a
  feasible successor listed beside the successor, the AS number check, routes
  at distance 90. Also seen: an eigrpd restarted while its neighbour stayed
  up did not relearn the neighbour's routes until both ends restarted, a
  router whose successor's link went down kept the stale entry instead of
  moving to the feasible successor, ``clear ip eigrp neighbors`` stopped
  eigrpd, and changing an interface's ``delay`` on a running router could
  leave stale entries. So ``clear ip eigrp neighbors`` is refused, and the
  lessons say to restart FRRouting on both routers when the table looks
  stale. The lab router runs Alpine's FRRouting 10.2.2, not tried here.
* No redistribution: eigrpd takes ``redistribute`` but its code drops what
  zebra sends (eigrp_zebra_read_route is empty) and ignores external routes
  arriving from neighbours, so there are no EX (170) routes. ``redistribute``
  under ``router eigrp`` is refused, saying so; ``redistribute eigrp <as>``
  under ``router ospf`` works (that is ospfd).
* No stub routing (``eigrp stub``), no summarisation (``ip summary-address
  eigrp``: "not implemented yet" in its northbound code), no named mode
  (``router eigrp <name>``), no static neighbours (``neighbor``), no
  split-horizon setting. Authentication: eigrpd holds the commands and some
  MD5 code, but its own interface view prints "Authentication mode is not
  set" whatever is configured and it was not tried; the console refuses
  ``ip authentication`` rather than teach something it cannot show working.
* ``auto-summary`` is never done (FRRouting has no automatic summarisation),
  so ``no auto-summary`` is taken and ``auto-summary`` says so.
* ``bandwidth`` is passed to eigrpd (its own ``eigrp bandwidth``); in the
  8.4.4 test the advertised metric followed ``delay`` and not always
  ``bandwidth``. It does not change OSPF's cost here.
* One EIGRP process, in the global table (no ``address-family ipv4 vrf``).

Settings (in [devices."router"]): ``eigrp`` = the AS; ``eigrp-rid``;
``eigrp-net:<address> <wildcard>`` (wildcard "" for a classful network);
``eigrp-pasdef``; ``eigrp-pas:<if>`` = yes | no; ``eigrp-var``;
``eigrp-maxp``; ``eigrp-k`` = "k1 k2 k3 k4 k5"; ``eigrp-log``;
``eigrp-delay:<if>``; ``eigrp-bw:<if>``; ``eigrp-hello:<if>``;
``eigrp-hold:<if>``.

How it is tested: tests/test_winlab.py checks the console, the frr.conf it
writes (router eigrp before the interface lines, the order eigrpd's
configuration needs: interface lines first are refused at start), and the
parsers against eigrpd's own output captured from FRRouting 8.4.4 in network
namespaces.
"""

from __future__ import annotations

import ipaddress
import re

ASN_KEY = "eigrp"
DISTANCE = 90

NO_REDIST = ("% EIGRP on this router (FRRouting's eigrpd) does not redistribute: it takes the command but\n"
             "% drops the routes, and it has no external (EX) routes at all. Put the network in EIGRP with a\n"
             "% network statement instead; redistribute eigrp <as> under router ospf does work.")
NO_STUB = ("% eigrp stub is not in this router: FRRouting's eigrpd has no stub routing. A router that should\n"
           "% not be asked for routes it cannot give is a design point to discuss, not one to type here.")
NO_NAMED = ("% Named-mode EIGRP (router eigrp <name>, address-family ipv4 autonomous-system) is not in this\n"
            "% router: FRRouting's eigrpd takes only the classic mode, router eigrp <AS number 1-65535>.")
NO_AUTH = ("% EIGRP authentication is not in this router: FRRouting's eigrpd holds the commands but reports\n"
           "% no authentication in use, so a key here would teach something it cannot show working.")
NO_SUMMARY = ("% ip summary-address eigrp is not in this router: FRRouting's eigrpd answers \"summary command\n"
              "% not implemented yet\".")
NO_CLEAR = ("% clear ip eigrp neighbors is not in this router: FRRouting's eigrpd (alpha) stopped on it in\n"
            "% testing. To start the adjacency again, no network / network the link here, or restart frr on rtr-edge.")
AUTO_SUM = ("% Automatic summarisation is not in this router: FRRouting's eigrpd never summarises, which is\n"
            "% what no auto-summary asks for (and the IOS 15 default).")


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def asn(own: dict) -> str:
    return own.get(ASN_KEY, "")


def nets(own: dict) -> list[tuple[str, str]]:
    """(address, wildcard or "") of the network statements."""
    out = []
    for k in own:
        if k.startswith("eigrp-net:"):
            addr, _, wild = k[10:].partition(" ")
            out.append((addr, wild))
    return sorted(out, key=lambda r: (int(ipaddress.IPv4Address(r[0])), r[1]))


def prefix(addr: str, wild: str) -> ipaddress.IPv4Network | None:
    from .iosrouting import _classful, _wild_prefix
    return _wild_prefix(addr, wild) if wild else _classful(addr)


def passive(own: dict, ifname: str) -> bool:
    v = own.get(f"eigrp-pas:{ifname}", "")
    return v == "yes" or (bool(own.get("eigrp-pasdef")) and v != "no")


def active(own: dict) -> bool:
    return bool(asn(own))


# ------------------------------------------------------------------ frr.conf
def frr_lines(plan) -> list[str]:
    """The router eigrp block and, after it, the interfaces' eigrp lines:
    eigrpd refuses an interface's eigrp lines before its instance exists
    (seen on 8.4.4: 'Configuration failed ... validation'), so they come
    second, in interface blocks of their own."""
    from .iosrouting import svi_map
    own = _own(plan.lab)
    a = asn(own)
    if not a:
        return []
    svis = svi_map(plan.lab, plan)
    out = [f"router eigrp {a}"]
    if own.get("eigrp-rid"):
        out.append(f" eigrp router-id {own['eigrp-rid']}")
    for name, dev in sorted(svis.items(), key=lambda kv: kv[1]):
        if passive(own, name):
            out.append(f" passive-interface {dev}")
    if own.get("eigrp-var"):
        out.append(f" variance {own['eigrp-var']}")
    if own.get("eigrp-maxp"):
        out.append(f" maximum-paths {own['eigrp-maxp']}")
    if own.get("eigrp-k"):
        out.append(f" metric weights {own['eigrp-k']} 0")
    for addr, wild in nets(own):
        n = prefix(addr, wild)
        if n is not None:
            out.append(f" network {n}")
    out += ["exit", "!"]
    for name, dev in sorted(svis.items(), key=lambda kv: kv[1]):
        body = []
        if own.get(f"eigrp-delay:{name}"):
            body.append(f" delay {own[f'eigrp-delay:{name}']}")
        if own.get(f"eigrp-bw:{name}"):
            body.append(f" eigrp bandwidth {own[f'eigrp-bw:{name}']}")
        if own.get(f"eigrp-hello:{name}"):
            body.append(f" ip hello-interval eigrp {own[f'eigrp-hello:{name}']}")
        if own.get(f"eigrp-hold:{name}"):
            body.append(f" ip hold-time eigrp {own[f'eigrp-hold:{name}']}")
        if body:
            out += [f"interface {dev}"] + body + ["exit", "!"]
    return out


# ------------------------------------------------------------------ show running-config
def iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    if own.get(f"eigrp-bw:{ifname}"):
        out.append(f" bandwidth {own[f'eigrp-bw:{ifname}']}")
    if own.get(f"eigrp-delay:{ifname}"):
        out.append(f" delay {own[f'eigrp-delay:{ifname}']}")
    a = asn(own) or "1"
    if own.get(f"eigrp-hello:{ifname}"):
        out.append(f" ip hello-interval eigrp {a} {own[f'eigrp-hello:{ifname}']}")
    if own.get(f"eigrp-hold:{ifname}"):
        out.append(f" ip hold-time eigrp {a} {own[f'eigrp-hold:{ifname}']}")
    return out


def run_lines(own: dict) -> list[str]:
    a = asn(own)
    if not a:
        return []
    out = [f"router eigrp {a}"]
    if own.get("eigrp-k"):
        out.append(f" metric weights 0 {own['eigrp-k']}")
    for addr, wild in nets(own):
        out.append(f" network {addr}" + (f" {wild}" if wild else ""))
    if own.get("eigrp-pasdef"):
        out.append(" passive-interface default")
    for k, v in sorted(own.items()):
        if k.startswith("eigrp-pas:"):
            name = k[10:]
            if v == "yes" and not own.get("eigrp-pasdef"):
                out.append(f" passive-interface {name}")
            elif v == "no" and own.get("eigrp-pasdef"):
                out.append(f" no passive-interface {name}")
    if own.get("eigrp-var"):
        out.append(f" variance {own['eigrp-var']}")
    if own.get("eigrp-maxp"):
        out.append(f" maximum-paths {own['eigrp-maxp']}")
    if own.get("eigrp-rid"):
        out.append(f" eigrp router-id {own['eigrp-rid']}")
    return out + ["!"]


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, E, C, IF, RM) -> None:
    from . import devcli
    for k, v in {("show", "ip", "eigrp"): "IP-EIGRP show commands", ("eigrp",): "EIGRP specific commands",
                 ("metric",): "Modify metrics and parameters for advertisement",
                 ("variance",): "Control load balancing variance",
                 ("delay",): "Specify interface throughput delay",
                 ("bandwidth",): "Set bandwidth informational parameter"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    add("no router eigrp <line>", lambda a: _no_eigrp(con, a[0]), "Negate a command or set its defaults", C)
    add("network <ip> <ip>", lambda a: net_cmd(con, a[0], a[1], True), "Enable routing on an IP network", RM)
    add("no network <ip> <ip>", lambda a: net_cmd(con, a[0], a[1], False), "Negate a command or set its defaults", RM)
    add("eigrp router-id <ip>", lambda a: _opt(con, "eigrp-rid", _ip(a[0])), "router-id for this EIGRP process", RM)
    add("no eigrp router-id", lambda a: _opt(con, "eigrp-rid", ""), "Negate a command or set its defaults", RM)
    add("no eigrp router-id <ip>", lambda a: _opt(con, "eigrp-rid", ""), "Negate a command or set its defaults", RM)
    add("eigrp log-neighbor-changes", lambda a: _opt(con, "eigrp-log", "yes"), "Enable/Disable EIGRP neighbor logging", RM)
    add("no eigrp log-neighbor-changes", lambda a: _opt(con, "eigrp-log", ""), "Negate a command or set its defaults", RM)
    add("eigrp stub", lambda a: _in(con) and NO_STUB, "Set IP-EIGRP as stubbed router", RM)
    add("eigrp stub <line>", lambda a: _in(con) and NO_STUB, "Set IP-EIGRP as stubbed router", RM)
    add("variance <num>", lambda a: _num(con, "eigrp-var", a[0], 1, 128), "Control load balancing variance", RM)
    add("no variance", lambda a: _opt(con, "eigrp-var", ""), "Negate a command or set its defaults", RM)
    add("no variance <num>", lambda a: _opt(con, "eigrp-var", ""), "Negate a command or set its defaults", RM)
    add("maximum-paths <num>", lambda a: _num(con, "eigrp-maxp", a[0], 1, 32), "Forward packets over multiple paths", RM)
    add("no maximum-paths", lambda a: _opt(con, "eigrp-maxp", ""), "Negate a command or set its defaults", RM)
    add("metric weights <line>", lambda a: _weights(con, a[0]), "Modify metric coefficients", RM)
    add("no metric weights", lambda a: _opt(con, "eigrp-k", ""), "Negate a command or set its defaults", RM)
    add("no metric weights <line>", lambda a: _opt(con, "eigrp-k", ""), "Negate a command or set its defaults", RM)
    add("auto-summary", lambda a: _in(con) and AUTO_SUM, "Enable automatic network number summarization", RM)
    # interfaces
    add("bandwidth <num>", lambda a: _if_num(con, "bw", a[0], 1, 10000000), "Set bandwidth informational parameter", IF)
    add("no bandwidth", lambda a: _if_num(con, "bw", "", 0, 0), "Negate a command or set its defaults", IF)
    add("no bandwidth <num>", lambda a: _if_num(con, "bw", "", 0, 0), "Negate a command or set its defaults", IF)
    add("delay <num>", lambda a: _if_num(con, "delay", a[0], 1, 16777215), "Specify interface throughput delay", IF)
    add("no delay", lambda a: _if_num(con, "delay", "", 0, 0), "Negate a command or set its defaults", IF)
    add("no delay <num>", lambda a: _if_num(con, "delay", "", 0, 0), "Negate a command or set its defaults", IF)
    add("ip hello-interval eigrp <num> <num>", lambda a: _if_timer(con, "hello", a[0], a[1]), "Enhanced Interior Gateway Routing Protocol (EIGRP)", IF)
    add("no ip hello-interval eigrp <num>", lambda a: _if_timer(con, "hello", a[0], ""), "Negate a command or set its defaults", IF)
    add("no ip hello-interval eigrp <num> <num>", lambda a: _if_timer(con, "hello", a[0], ""), "Negate a command or set its defaults", IF)
    add("ip hold-time eigrp <num> <num>", lambda a: _if_timer(con, "hold", a[0], a[1]), "Enhanced Interior Gateway Routing Protocol (EIGRP)", IF)
    add("no ip hold-time eigrp <num>", lambda a: _if_timer(con, "hold", a[0], ""), "Negate a command or set its defaults", IF)
    add("no ip hold-time eigrp <num> <num>", lambda a: _if_timer(con, "hold", a[0], ""), "Negate a command or set its defaults", IF)
    add("ip authentication <line>", lambda a: NO_AUTH, "authentication subcommands", IF)
    add("ip summary-address eigrp <line>", lambda a: NO_SUMMARY, "Enhanced Interior Gateway Routing Protocol (EIGRP)", IF)
    # what the router knows
    add("show ip eigrp neighbors", lambda a: show_neighbors(con), "IP-EIGRP neighbors", U)
    add("show ip eigrp neighbors detail", lambda a: show_neighbors(con, detail=True), "Show detailed peer information", U)
    add("show ip eigrp topology", lambda a: show_topology(con, False), "IP-EIGRP Topology Table", U)
    add("show ip eigrp topology all-links", lambda a: show_topology(con, True), "Show all links in topology table", U)
    add("show ip eigrp interfaces", lambda a: show_interfaces(con), "IP-EIGRP interfaces", U)
    add("show ip route eigrp", lambda a: _route(con), "Enhanced Interior Gateway Routing Protocol (EIGRP)", U)
    add("clear ip eigrp neighbors", lambda a: NO_CLEAR, "IP-EIGRP neighbors", E)
    add("clear ip eigrp neighbors <line>", lambda a: NO_CLEAR, "IP-EIGRP neighbors", E)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _ip(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None


def _in(con) -> bool:
    if not con.s.ctx.startswith("eigrp:"):
        raise _err("% Invalid input detected at '^' marker.")
    return True


def router_eigrp(con, text: str) -> str:
    """router eigrp <as> (classic mode); a name is named mode."""
    w = text.split()
    if len(w) != 1:
        raise _err("% Invalid input detected at '^' marker.")
    if not w[0].isdigit():
        return NO_NAMED
    a = int(w[0])
    if not 1 <= a <= 65535:
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    have = asn(own)
    if have and have != str(a):
        raise _err(f"% EIGRP is already running here as AS {have}: this router runs one EIGRP process "
                   f"(no router eigrp {have} first)")
    con.s.mode, con.s.ctx = "config-router", f"eigrp:{a}"
    if not have:
        own[ASN_KEY] = str(a)
        own.setdefault("eigrp-log", "yes")
        return _done(con)
    con._save(live=False)
    return ""


def _no_eigrp(con, text: str) -> str:
    own = _own_c(con)
    w = text.split()
    if not w or not w[0].isdigit():
        return NO_NAMED if w else ""
    if asn(own) != str(int(w[0])):
        return ""
    for k in [k for k in own if k == ASN_KEY or k.startswith("eigrp-")]:
        del own[k]
    return _done(con)


def net_cmd(con, addr: str, wild: str, on: bool) -> str:
    _in(con)
    addr = _ip(addr)
    if wild:
        wild = _ip(wild)
        if prefix(addr, wild) is None:
            raise _err("% EIGRP: this router takes a contiguous wildcard (0.0.0.255, 0.0.3.255, 0.0.0.0)")
        n = prefix(addr, wild)
        addr = str(n.network_address) if n.prefixlen else addr
    key = f"eigrp-net:{addr} {wild}"
    own = _own_c(con)
    if on:
        own[key] = "yes"
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def passive_cmd(con, text: str, on: bool) -> str:
    from . import devcli
    own = _own_c(con)
    if text.strip().lower() in ("default", "d", "de", "def", "defa", "defau", "defaul"):
        if on:
            own["eigrp-pasdef"] = "yes"
        else:
            own.pop("eigrp-pasdef", None)
        for k in [k for k in own if k.startswith("eigrp-pas:")]:
            del own[k]
        return _done(con)
    name = devcli.parse_if(text.strip(), con._if_names(), sub=True)
    if on == bool(own.get("eigrp-pasdef")):
        own.pop(f"eigrp-pas:{name}", None)
    else:
        own[f"eigrp-pas:{name}"] = "yes" if on else "no"
    return _done(con)


def _opt(con, key: str, value: str) -> str:
    _in(con)
    own = _own_c(con)
    had = own.get(key)
    if value:
        own[key] = value
    elif own.pop(key, None) is None:
        return ""
    note = _done(con)
    if key == "eigrp-rid" and had and had != value:
        note = "% EIGRP: the new router ID takes over when the neighbours are formed again" + (f"\n{note}" if note else "")
    return note


def _num(con, key: str, text: str, lo: int, hi: int) -> str:
    if not lo <= int(text) <= hi:
        raise _err("% Invalid input detected at '^' marker.")
    return _opt(con, key, str(int(text)))


def _weights(con, text: str) -> str:
    """IOS: metric weights <tos 0> k1 k2 k3 k4 k5."""
    _in(con)
    w = text.split()
    if len(w) != 6 or not all(x.isdigit() and int(x) <= 255 for x in w) or w[0] != "0":
        raise _err("% Invalid input detected at '^' marker.")
    note = _opt(con, "eigrp-k", " ".join(str(int(x)) for x in w[1:]))
    return ("% EIGRP: the K values must match on both ends, or the neighbours drop each other (K-value mismatch)"
            + (f"\n{note}" if note else ""))


def _if_num(con, what: str, value: str, lo: int, hi: int) -> str:
    own = _own_c(con)
    key = f"eigrp-{what}:{con.s.ctx}"
    if value:
        if not lo <= int(value) <= hi:
            raise _err("% Invalid input detected at '^' marker.")
        own[key] = str(int(value))
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def _if_timer(con, what: str, a: str, value: str) -> str:
    own = _own_c(con)
    if asn(own) and a != asn(own):
        return f"% EIGRP AS {a} is not running here (router eigrp {asn(own)})"
    return _if_num(con, what, value, 1, 65535)


def redistribute_cmd(con, rest: str, on: bool) -> str:
    return NO_REDIST


# ------------------------------------------------------------------ reading eigrpd
_NBR = re.compile(r"^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)")
_PFX = re.compile(r"^([PA])\s+(\d+\.\d+\.\d+\.\d+/\d+), (\d+) successors, FD is (\d+)")
_VIA = re.compile(r"^\s+via (Connected|\d+\.\d+\.\d+\.\d+)(?: \((\d+)/(\d+)\))?, (\S+)")
_IFROW = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*/\s*(\d+)\s+.*?(\d+)\s+(\d+)\s*$")
_AS = re.compile(r"AS\((\d+)\)(?:/ID\((\d+\.\d+\.\d+\.\d+)\))?")


def parse_neighbors(text: str) -> list[dict]:
    """eigrpd's 'show ip eigrp neighbors': H, address, interface, hold
    (or '-'), uptime, SRTT, RTO, Q count, sequence number."""
    out = []
    for line in text.splitlines():
        m = _NBR.match(line)
        if m:
            out.append({"h": int(m.group(1)), "addr": m.group(2), "dev": m.group(3), "hold": m.group(4),
                        "rto": int(m.group(7)), "q": int(m.group(8)), "seq": int(m.group(9))})
    return out


def parse_topology(text: str) -> dict:
    """eigrpd's topology table: its AS and router ID, and per prefix its
    state, successor count, feasible distance and the paths (next hop or
    Connected, computed/reported distance, interface)."""
    head = _AS.search(text)
    out = {"as": head.group(1) if head else "", "rid": (head.group(2) or "") if head else "", "routes": []}
    cur = None
    for line in text.splitlines():
        m = _PFX.match(line)
        if m:
            cur = {"state": m.group(1), "prefix": m.group(2), "successors": int(m.group(3)), "fd": int(m.group(4)),
                   "via": []}
            out["routes"].append(cur)
            continue
        v = _VIA.match(line)
        if v and cur is not None:
            hop = {"via": v.group(1), "cd": int(v.group(2) or 0), "rd": int(v.group(3) or 0), "dev": v.group(4)}
            if hop not in cur["via"]:   # eigrpd 8.4 sometimes prints a connected path three times
                cur["via"].append(hop)
    return out


def parse_interfaces(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _IFROW.match(line.strip())
        if m and m.group(1) not in ("Interface",):
            out.append({"dev": m.group(1), "bw": int(m.group(2)), "delay": int(m.group(3)), "peers": int(m.group(4)),
                        "hello": int(m.group(7)), "hold": int(m.group(8))})
    return out


def feasible(route: dict) -> list[dict]:
    """The paths that meet the feasibility condition: reported distance
    below the feasible distance (the successors among them)."""
    return [h for h in route["via"] if h["via"] != "Connected" and h["rd"] < route["fd"]]


def _read(con, cmd: str) -> str | None:
    from .iosrouting import _frr_note, _vtysh
    if not asn(_own(con.lab)):
        return None
    text = _vtysh(con, cmd)
    if text.strip().startswith("%"):
        return _frr_note(text) or ""
    return text


def _names(con) -> dict[str, str]:
    from .iosrouting import svi_map
    return {dev: name for name, dev in svi_map(con.lab, con.plan).items()}


def show_neighbors(con, detail: bool = False) -> str:
    from . import devcli
    text = _read(con, "show ip eigrp neighbors detail" if detail else "show ip eigrp neighbors")
    if not text:
        return text or ""
    rev = _names(con)
    a = asn(_own(con.lab))
    out = [f"EIGRP-IPv4 Neighbors for AS({a})",
           f"{'H':<4}{'Address':<24}{'Interface':<23}{'Hold':>5} {'Uptime':<9}{'SRTT':>5}{'RTO':>6}{'Q':>4}{'Seq':>5}",
           f"{'':<51}{'(sec)':>5} {'':<9}{'(ms)':>5}{'':>6}{'Cnt':>4}{'Num':>5}"]
    for i, r in enumerate(parse_neighbors(text)):
        name = devcli.short_if(rev.get(r["dev"], r["dev"]))
        # eigrpd keeps no uptime or round-trip time: '-' rather than a made-up figure
        out.append(f"{i:<4}{r['addr']:<24}{name:<23}{r['hold']:>5} {'-':<9}{'-':>5}{r['rto']:>6}{r['q']:>4}{r['seq']:>5}")
    return "\n".join(out)


def show_topology(con, all_links: bool) -> str:
    from . import devcli
    text = _read(con, "show ip eigrp topology all-links" if all_links else "show ip eigrp topology")
    if not text:
        return text or ""
    rev = _names(con)
    t = parse_topology(text)
    out = [f"EIGRP-IPv4 Topology Table for AS({t['as'] or asn(_own(con.lab))})/ID({t['rid'] or '0.0.0.0'})", "",
           "Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply,",
           "       r - reply Status, s - sia Status", ""]
    for r in t["routes"]:
        out.append(f"{r['state']} {r['prefix']}, {r['successors']} successors, FD is {r['fd']}")
        for h in r["via"]:
            name = rev.get(h["dev"], h["dev"])
            if h["via"] == "Connected":
                out.append(f"        via Connected, {name}")
            else:
                out.append(f"        via {h['via']} ({h['cd']}/{h['rd']}), {name}")
    return "\n".join(out)


def show_interfaces(con) -> str:
    from . import devcli
    text = _read(con, "show ip eigrp interfaces")
    if not text:
        return text or ""
    rev = _names(con)
    a = asn(_own(con.lab))
    out = [f"EIGRP-IPv4 Interfaces for AS({a})",
           f"{'':<30}Xmit Queue   PeerQ        Mean   Pacing Time   Multicast    Pending",
           f"{'Interface':<23}{'Peers':<7}Un/Reliable  Un/Reliable  SRTT   Un/Reliable   Flow Timer   Routes"]
    for r in parse_interfaces(text):
        name = devcli.short_if(rev.get(r["dev"], r["dev"]))
        out.append(f"{name:<23}{r['peers']:>5}{'0/0':>11}{'0/0':>13}{0:>7}{'0/0':>13}{0:>13}{0:>9}")
    return "\n".join(out)


def _route(con) -> str:
    from .iosrouting import show_route
    return show_route(con, "", only="eigrp")


def protocols(con) -> list[str]:
    """The EIGRP part of show ip protocols."""
    own = _own(con.lab)
    a = asn(own)
    if not a:
        return []
    k = (own.get("eigrp-k") or "1 0 1 0 0").split()
    out = [f"Routing Protocol is \"eigrp {a}\"",
           "  Outgoing update filter list for all interfaces is not set",
           "  Incoming update filter list for all interfaces is not set",
           f"  EIGRP-IPv4 Protocol for AS({a})",
           f"    Metric weight K1={k[0]}, K2={k[1]}, K3={k[2]}, K4={k[3]}, K5={k[4]}",
           f"    Router-ID: {own.get('eigrp-rid', '(chosen at start: the highest interface address)')}",
           f"      Distance: internal {DISTANCE} external 170",
           f"      Maximum path: {own.get('eigrp-maxp', '4')}",
           f"      Maximum metric variance {own.get('eigrp-var', '1')}",
           "", "  Automatic Summarization: disabled", "  Routing for Networks:"]
    for addr, wild in nets(own):
        out.append(f"    {prefix(addr, wild)}")
    pas = [n for n, _, _ in con.router_ifaces() if passive(own, n)]
    if pas:
        out.append("  Passive Interface(s):")
        out += [f"    {p}" for p in pas]
    out += ["  Routing Information Sources:", "    Gateway         Distance      Last Update",
            f"  Distance: internal {DISTANCE} external 170", ""]
    return out


# ------------------------------------------------------------------ the drill (on rtr-edge)
STATE_DIR = "/var/lib/winlab"


def _faults():
    from .guestfaults import LINUX, GuestFault
    from .routing import NEED_FRR
    saved = f"{STATE_DIR}/ts-eigrp-as"
    block = f"{STATE_DIR}/ts-eigrp-block.conf"
    # The router eigrp block of the running configuration, less its first line.
    body = ("vtysh -c 'show running-config' | awk '/^router eigrp [0-9]+/{f=1; next} "
            "f && /^(exit|!)/{f=0} f'")
    return [
        GuestFault(
            id="eigrp-as-mismatch",
            images=("ubuntu",),
            title="rtr-edge and the lab router run EIGRP but never become neighbours",
            os=LINUX,
            teaches="what two EIGRP routers must agree on before they become neighbours (the autonomous system "
                    "number in every packet's header, the K values, a common subnet), and reading show ip eigrp "
                    "neighbors and show running-config on both ends instead of restarting FRRouting",
            symptom="show ip eigrp neighbors is empty on both routers, the D routes are gone (the lab router falls "
                    "back to OSPF's O routes if OSPF still runs), yet the routers ping each other",
            apply=(NEED_FRR + f"mkdir -p {STATE_DIR}; "
                   "as=$(vtysh -c 'show running-config' | awk '/^router eigrp [0-9]+/{print $3; exit}'); "
                   "[ -n \"$as\" ] || { echo 'no EIGRP on this router: build it first (lesson "
                   "router-console-eigrp)'; exit 1; }; "
                   f"echo \"$as\" > {saved}; new=$((as + 1)); "
                   f"{{ echo \"router eigrp $new\"; {body}; echo exit; }} > {block}; "
                   "vtysh -c 'configure terminal' -c \"no router eigrp $as\" >/dev/null 2>&1; "
                   f"vtysh -f {block} >/dev/null 2>&1; vtysh -c 'write memory' >/dev/null 2>&1; "
                   # eigrpd is alpha: start it again on the saved file rather than trust a live change
                   "systemctl restart frr; echo broken"),
            clear=(f"as=$(cat {saved} 2>/dev/null); [ -n \"$as\" ] || exit 0; "
                   "now=$(vtysh -c 'show running-config' | awk '/^router eigrp [0-9]+/{print $3; exit}'); "
                   f"{{ echo \"router eigrp $as\"; {body}; echo exit; }} > {block}; "
                   "[ -n \"$now\" ] && vtysh -c 'configure terminal' -c \"no router eigrp $now\" >/dev/null 2>&1; "
                   f"vtysh -f {block} >/dev/null 2>&1; vtysh -c 'write memory' >/dev/null 2>&1; "
                   f"systemctl restart frr; rm -f {saved} {block}; echo ok"),
            shell="sh",
            hints=(
                "Start with what each router sees: sudo vtysh -c 'show ip eigrp neighbors' here, show ip eigrp "
                "neighbors on the lab router's console. Both empty while ping 10.80.0.2 works: the link is "
                "fine, so EIGRP itself refuses.",
                "Every EIGRP packet carries its autonomous system number, and a router drops packets of another "
                "AS without a word. Compare the first line of the process: sudo vtysh -c 'show running-config' "
                "here (router eigrp ...) and show running-config on the console, or the AS in the header of "
                "show ip eigrp topology on both.",
                "Put rtr-edge back in the lab router's AS: sudo vtysh, configure terminal, no router eigrp <wrong>, "
                "router eigrp <right>, the same network lines again, end, write memory; then sudo systemctl "
                "restart frr (eigrpd is alpha and settles best from a fresh start). The neighbour appears within "
                "a hello or two and the D routes come back.",
            ),
            verify=("as=$(vtysh -c 'show running-config' 2>/dev/null | awk '/^router eigrp [0-9]+/{print $3; exit}'); "
                    f"[ -n \"$as\" ] && [ \"$as\" = \"$(cat {saved} 2>/dev/null || echo $as)\" ] && "
                    "vtysh -c 'show ip eigrp neighbors' 2>/dev/null | grep -q ' 10\\.80\\.0\\.2 ' "
                    "&& echo True || echo False"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
