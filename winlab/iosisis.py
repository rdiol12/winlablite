"""IS-IS typed at the lab router's console, made real by FRRouting's isisd.

``router isis [<tag>]`` and what follows it become a ``router isis`` block
in the router's /etc/frr/frr.conf (winlab/iosrouting.py writes it and starts
isisd in /etc/frr/daemons only while IS-IS is configured), and ``ip router
isis [<tag>]`` on an interface becomes isisd's interface line. isisd speaks
IS-IS (ISO 10589, RFC 1195 for IPv4) on the wire: real hellos (IIHs) to the
IS-IS multicast MACs straight over Ethernet, link-state PDUs flooded per
level, SPF per level, routes installed by zebra at administrative distance
115. The router it peers with in the lab is rtr-edge (Ubuntu with FRRouting
from the frr pack); on real gear both would be Cisco routers.

* ``net <NET>``: the area and system ID, as on IOS (49.0001.0000.0000.0002.00:
  area 49.0001, system ID 0000.0000.0002, selector 00). Up to three NETs.
* ``is-type level-1 | level-1-2 | level-2-only`` and, on an interface,
  ``isis circuit-type`` with the same words: isisd's own commands. Two
  routers form a level-1 adjacency only in the same area; a level-2
  adjacency forms across areas. A level-1-only router and a level-2-only
  router never become neighbours.
* ``metric-style narrow | wide | transition``: IOS's default is narrow (6-bit
  metrics, the old TLVs) and isisd's is wide, so the console writes the
  style into isisd's file always (narrow unless typed). A narrow router and a
  wide one become neighbours but do not take each other's routes: type
  ``metric-style wide`` on both, as Cisco recommends.
* ``isis metric <n>``, ``isis network point-to-point``, ``passive-interface``
  (isisd's ``isis passive``: the subnet is advertised, no hellos are sent),
  ``log-adjacency-changes``.
* ``show isis neighbors`` (and ``show clns neighbors``) read isisd's
  neighbour detail and print IOS's table (one row per neighbour, its type
  L1, L2 or L1L2); ``show isis database`` is isisd's own; ``show ip route
  isis`` reads zebra's JSON and prints code i with L1 or L2, read from
  ``show isis route``.

Not in this router, and the console says so: IS-IS authentication
(``isis password``, ``area-password``, ``domain-password``: isisd has them,
the lessons do not use them yet), summary addresses, IPv6 IS-IS (the IPv6
lessons use OSPFv3), ``redistribute`` into IS-IS.

Settings (in [devices."router"]): ``isis`` = the tag ("" for none);
``isis-net:<NET>`` = yes; ``isis-type``; ``isis-style``; ``isis-log``;
``isis-pasdef``; ``isis-pas:<if>`` = yes | no; ``isis-if:<if>`` = the tag
("" for none); ``isis-ctype:<if>``; ``isis-metric:<if>``;
``isis-p2p:<if>``.
"""

from __future__ import annotations

import re

DISTANCE = 115
TYPES = ("level-1", "level-1-2", "level-2-only")
STYLES = ("narrow", "wide", "transition")
FRR_TAG = "winlab"   # isisd wants a name; IOS's router isis may have none

NO_AUTH = ("% IS-IS authentication is not in this router's lessons yet: FRRouting's isisd has area-password\n"
           "% and isis password, but the console does not write them. Keep the adjacency open for now.")
NO_SUMMARY = "% summary-address is not in this router: winlab does not write isisd's summaries."
NO_REDIST = ("% redistribute under router isis is not in this router: put the interfaces in IS-IS with\n"
             "% ip router isis instead.")
NO_V6 = "% IPv6 IS-IS is not in this router: the IPv6 lessons route with OSPFv3."


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def active(own: dict) -> bool:
    return "isis" in own


def tag(own: dict) -> str:
    return own.get("isis", "")


def frr_tag(own: dict) -> str:
    return tag(own) or FRR_TAG


def nets(own: dict) -> list[str]:
    return sorted(k[9:] for k in own if k.startswith("isis-net:"))


def ifaces(own: dict) -> list[str]:
    return sorted(k[8:] for k in own if k.startswith("isis-if:"))


def passive(own: dict, ifname: str) -> bool:
    v = own.get(f"isis-pas:{ifname}", "")
    return v == "yes" or (bool(own.get("isis-pasdef")) and v != "no")


def valid_net(text: str) -> str:
    """A NET in IOS's dotted hex: an area of 1 to 13 octets, a 6-octet
    system ID, a selector of 00. Returns it in lower case, or ""."""
    t = text.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{2}(\.[0-9a-f]{2,4})+", t):
        return ""
    digits = t.replace(".", "")
    if len(digits) % 2 or not 16 <= len(digits) <= 40 or not digits.endswith("00"):
        return ""
    return t


def area_of(net: str) -> str:
    d = net.replace(".", "")
    area = d[:-14]
    return ".".join([area[:2]] + [area[i:i + 4] for i in range(2, len(area), 4)])


def system_id(net: str) -> str:
    d = net.replace(".", "")[-14:-2]
    return f"{d[0:4]}.{d[4:8]}.{d[8:12]}"


# ------------------------------------------------------------------ frr.conf
def frr_lines(plan) -> list[str]:
    """The router isis block, then the interfaces' isis lines."""
    from .iosrouting import svi_map
    own = _own(plan.lab)
    if not active(own):
        return []
    t = frr_tag(own)
    out = [f"router isis {t}"]
    for n in nets(own):
        out.append(f" net {n}")
    out.append(f" is-type {own.get('isis-type', 'level-1-2')}")
    out.append(f" metric-style {own.get('isis-style', 'narrow')}")
    if own.get("isis-log"):
        out.append(" log-adjacency-changes")
    out += ["exit", "!"]
    svis = svi_map(plan.lab, plan)
    # IOS's passive-interface under router isis puts the interface in IS-IS,
    # advertised and silent; isisd wants it in the process and passive.
    for name in sorted(set(ifaces(own)) | {n for n in svis if passive(own, n)}):
        dev = svis.get(name)
        if not dev:
            continue
        body = [f" ip router isis {t}"]
        if own.get(f"isis-ctype:{name}"):
            body.append(f" isis circuit-type {own[f'isis-ctype:{name}']}")
        if own.get(f"isis-metric:{name}"):
            body.append(f" isis metric {own[f'isis-metric:{name}']}")
        if own.get(f"isis-p2p:{name}"):
            body.append(" isis network point-to-point")
        if passive(own, name):
            body.append(" isis passive")
        out += [f"interface {dev}"] + body + ["exit", "!"]
    return out


# ------------------------------------------------------------------ show running-config
def iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    if f"isis-if:{ifname}" in own:
        t = own[f"isis-if:{ifname}"]
        out.append(" ip router isis" + (f" {t}" if t else ""))
    if own.get(f"isis-ctype:{ifname}"):
        out.append(f" isis circuit-type {own[f'isis-ctype:{ifname}']}")
    if own.get(f"isis-p2p:{ifname}"):
        out.append(" isis network point-to-point")
    if own.get(f"isis-metric:{ifname}"):
        out.append(f" isis metric {own[f'isis-metric:{ifname}']}")
    return out


def run_lines(own: dict) -> list[str]:
    if not active(own):
        return []
    out = ["router isis" + (f" {tag(own)}" if tag(own) else "")]
    out += [f" net {n}" for n in nets(own)]
    if own.get("isis-type"):
        out.append(f" is-type {own['isis-type']}")
    if own.get("isis-style"):
        out.append(f" metric-style {own['isis-style']}")
    if own.get("isis-log"):
        out.append(" log-adjacency-changes")
    if own.get("isis-pasdef"):
        out.append(" passive-interface default")
    for k, v in sorted(own.items()):
        if k.startswith("isis-pas:"):
            name = k[9:]
            if v == "yes" and not own.get("isis-pasdef"):
                out.append(f" passive-interface {name}")
            elif v == "no" and own.get("isis-pasdef"):
                out.append(f" no passive-interface {name}")
    return out + ["!"]


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, IF, RM) -> None:
    from . import devcli
    for k, v in {("router", "isis"): "ISO IS-IS", ("is-type",): "IS Level for this routing process (OSI only)",
                 ("metric-style",): "Use old-style (ISO 10589) or new-style packet formats",
                 ("isis",): "IS-IS commands", ("ip", "router"): "IP router interface commands",
                 ("show", "isis"): "IS-IS routing information", ("show", "clns"): "CLNS network information",
                 ("net",): "A Network Entity Title for this process (OSI only)"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    add("router isis", lambda a: router_isis(con, ""), "ISO IS-IS", C + RM + ("config-router-af",))
    add("router isis <name>", lambda a: router_isis(con, a[0]), "ISO routing area tag", C + RM + ("config-router-af",))
    add("no router isis", lambda a: no_isis(con, ""), "Negate a command or set its defaults", C)
    add("no router isis <name>", lambda a: no_isis(con, a[0]), "Negate a command or set its defaults", C)
    # <line>, not <name>: under router ospf or eigrp, "net ..." is IOS's
    # abbreviation of network, and goes on to it (net_cmd)
    add("net <line>", lambda a: net_cmd(con, a[0], True), "A Network Entity Title for this process (OSI only)", RM)
    add("no net <line>", lambda a: net_cmd(con, a[0], False), "Negate a command or set its defaults", RM)
    add("is-type <name>", lambda a: _choice(con, "isis-type", a[0], TYPES), "IS Level for this routing process (OSI only)", RM)
    add("no is-type", lambda a: _choice(con, "isis-type", "", TYPES), "Negate a command or set its defaults", RM)
    add("no is-type <name>", lambda a: _choice(con, "isis-type", "", TYPES), "Negate a command or set its defaults", RM)
    add("metric-style <name>", lambda a: _choice(con, "isis-style", a[0], STYLES), "Use old-style (ISO 10589) or new-style packet formats", RM)
    add("no metric-style", lambda a: _choice(con, "isis-style", "", STYLES), "Negate a command or set its defaults", RM)
    add("no metric-style <name>", lambda a: _choice(con, "isis-style", "", STYLES), "Negate a command or set its defaults", RM)
    add("area-password <line>", lambda a: _in(con) and NO_AUTH, "Configure the authentication password for an area", RM)
    add("domain-password <line>", lambda a: _in(con) and NO_AUTH, "Set the authentication password for a routing domain", RM)
    add("summary-address <line>", lambda a: _summary(con, a[0]), "Configure IP address summaries", RM)
    add("address-family ipv6", lambda a: _in(con) and NO_V6, "Address family", RM)
    add("ip router isis", lambda a: _if(con, "", True), "IS-IS Routing for IP", IF)
    add("ip router isis <name>", lambda a: _if(con, a[0], True), "Routing process tag", IF)
    add("no ip router isis", lambda a: _if(con, "", False), "Negate a command or set its defaults", IF)
    add("no ip router isis <name>", lambda a: _if(con, a[0], False), "Negate a command or set its defaults", IF)
    add("isis circuit-type <name>", lambda a: _if_opt(con, "ctype", a[0], TYPES), "Configure circuit type for interface", IF)
    add("no isis circuit-type", lambda a: _if_opt(con, "ctype", "", TYPES), "Negate a command or set its defaults", IF)
    add("no isis circuit-type <name>", lambda a: _if_opt(con, "ctype", "", TYPES), "Negate a command or set its defaults", IF)
    add("isis metric <num>", lambda a: _if_metric(con, a[0]), "Configure the metric for interface", IF)
    add("no isis metric", lambda a: _if_metric(con, ""), "Negate a command or set its defaults", IF)
    add("no isis metric <line>", lambda a: _if_metric(con, ""), "Negate a command or set its defaults", IF)
    add("isis network point-to-point", lambda a: _if_opt(con, "p2p", "yes", ("yes",)), "point-to-point network", IF)
    add("no isis network point-to-point", lambda a: _if_opt(con, "p2p", "", ("yes",)), "Negate a command or set its defaults", IF)
    add("isis password <line>", lambda a: NO_AUTH, "Configure the authentication password for interface", IF)
    add("ipv6 router isis <line>", lambda a: NO_V6, "IS-IS Routing for IPv6", IF)
    add("ipv6 router isis", lambda a: NO_V6, "IS-IS Routing for IPv6", IF)
    add("show isis neighbors", lambda a: show_neighbors(con), "IS-IS neighbors", U)
    add("show isis neighbors detail", lambda a: show_neighbors(con, detail=True), "Show detailed information", U)
    add("show clns neighbors", lambda a: show_neighbors(con), "CLNS neighbor adjacencies", U)
    add("show isis database", lambda a: _frr(con, "show isis database"), "IS-IS link state database", U)
    add("show isis database detail", lambda a: _frr(con, "show isis database detail"), "Detailed link state database information", U)
    add("show isis topology", lambda a: _frr(con, "show isis topology"), "IS-IS paths to Intermediate Systems", U)
    add("show ip route isis", lambda a: _route(con), "ISO IS-IS", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _in(con) -> bool:
    if not con.s.ctx.startswith("isis:"):
        raise _bad()
    return True


def _summary(con, text: str) -> str:
    """summary-address: OSPF's external summary under router ospf
    (winlab/iosospfx.py), not in this router under router isis."""
    if con.s.ctx.startswith("ospf:"):
        from . import iosospfx
        return iosospfx.summary_cmd(con, text, True)
    _in(con)
    return NO_SUMMARY


def _tagword(text: str) -> str:
    if text and not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", text):
        raise _bad()
    return text


def router_isis(con, text: str) -> str:
    t = _tagword(text)
    own = _own_c(con)
    if active(own) and tag(own) != t:
        have = tag(own)
        raise _err(f"% IS-IS is already running here{' as ' + have if have else ' with no tag'}: this router runs "
                   f"one IS-IS process (no router isis{' ' + have if have else ''} first)")
    con.s.mode, con.s.ctx = "config-router", f"isis:{t}"
    if not active(own):
        own["isis"] = t
        return _done(con)
    con._save(live=False)
    return ""


def no_isis(con, text: str) -> str:
    own = _own_c(con)
    if not active(own) or tag(own) != text:
        return ""
    for k in [k for k in own if k == "isis" or k.startswith("isis-")]:
        del own[k]
    return _done(con)


def net_cmd(con, text: str, on: bool) -> str:
    if not con.s.ctx.startswith("isis:"):
        spec, args = con._match(("" if on else "no ") + "network " + text, con.s.mode)
        return spec.run(args) or ""
    n = valid_net(text)
    if not n:
        raise _err("% Invalid input detected at '^' marker.\n% A NET is the area, a 6-octet system ID and 00, "
                   "in dotted hex: 49.0001.0000.0000.0002.00")
    own = _own_c(con)
    key = f"isis-net:{n}"
    if not on:
        if own.pop(key, None) is None:
            return ""
        return _done(con)
    others = nets(own)
    if n in others:
        return ""
    if others and system_id(others[0]) != system_id(n):
        raise _err(f"% Incorrect system ID: every NET of a router carries the same one ({system_id(others[0])})")
    if len(others) >= 3:
        raise _err("% IS-IS: a router has at most 3 area addresses")
    own[key] = "yes"
    return _done(con)


def _choice(con, key: str, value: str, allowed: tuple[str, ...]) -> str:
    _in(con)
    own = _own_c(con)
    if value:
        full = [a for a in allowed if a.startswith(value.lower())]
        if value.lower() in allowed:
            full = [value.lower()]
        if len(full) != 1:
            raise _bad()
        own[key] = full[0]
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def _if(con, text: str, on: bool) -> str:
    t = _tagword(text)
    own = _own_c(con)
    key = f"isis-if:{con.s.ctx}"
    if not on:
        if own.pop(key, None) is None:
            return ""
        return _done(con)
    if active(own) and tag(own) != t:
        raise _err(f"% IS-IS process {t or '(no tag)'} is not running here: router isis "
                   f"{tag(own) or '(no tag)'} is")
    own[key] = t
    note = "" if active(own) else (f"% IS-IS: start the process too (router isis{' ' + t if t else ''}, then net "
                                   "<NET>)")
    if not active(own):
        own["isis"] = t
    done = _done(con)
    return "\n".join(x for x in (note, done) if x)


def _if_opt(con, what: str, value: str, allowed: tuple[str, ...]) -> str:
    own = _own_c(con)
    key = f"isis-{what}:{con.s.ctx}"
    if value:
        full = [a for a in allowed if a.startswith(value.lower())]
        if value.lower() in allowed:
            full = [value.lower()]
        if len(full) != 1:
            raise _bad()
        own[key] = full[0]
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def _if_metric(con, value: str) -> str:
    own = _own_c(con)
    key = f"isis-metric:{con.s.ctx}"
    if value:
        hi = 63 if own.get("isis-style", "narrow") == "narrow" else 16777214
        if not 1 <= int(value) <= hi:
            raise _err(f"% Invalid input detected at '^' marker.\n% With metric-style "
                       f"{own.get('isis-style', 'narrow')} the metric is 1 to {hi}")
        own[key] = str(int(value))
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def passive_cmd(con, text: str, on: bool) -> str:
    from . import devcli
    own = _own_c(con)
    if text.strip().lower() in ("default", "d", "de", "def", "defa", "defau", "defaul"):
        if on:
            own["isis-pasdef"] = "yes"
        else:
            own.pop("isis-pasdef", None)
        for k in [k for k in own if k.startswith("isis-pas:")]:
            del own[k]
        return _done(con)
    name = devcli.parse_if(text.strip(), con._if_names(), sub=True)
    if on == bool(own.get("isis-pasdef")):
        own.pop(f"isis-pas:{name}", None)
    else:
        own[f"isis-pas:{name}"] = "yes" if on else "no"
    return _done(con)


def log_cmd(con, on: bool) -> str:
    own = _own_c(con)
    if on:
        own["isis-log"] = "yes"
    elif own.pop("isis-log", None) is None:
        return ""
    return _done(con)


# ------------------------------------------------------------------ reading isisd
_ADJ = re.compile(r"Interface: (\S+), Level: (\d), State: (\w+)(?:, Expires in (\S+))?")


def parse_neighbors(text: str) -> list[dict]:
    """isisd's 'show isis neighbor detail': per neighbour (a line of its own,
    the system ID or the hostname it announced) its interface, level, state,
    expiry, circuit type, LAN ID and IPv4 addresses. One adjacency per
    level, as isisd lists them."""
    out: list[dict] = []
    cur: dict | None = None
    name = ""
    want_ip = False
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("Area "):
            want_ip = False
            continue
        m = _ADJ.search(s)
        if m:
            cur = {"system": name, "dev": m.group(1).rstrip(","), "level": int(m.group(2)), "state": m.group(3),
                   "expires": m.group(4) or "", "ctype": "", "lan": "", "ips": [], "snpa": ""}
            out.append(cur)
            want_ip = False
            continue
        if cur is not None and s.startswith("Circuit type:"):
            cur["ctype"] = s.split(":", 1)[1].split(",")[0].strip()
            continue
        if cur is not None and s.startswith("SNPA:"):
            parts = dict(p.split(":", 1) for p in s.split(", ") if ":" in p)
            cur["snpa"] = parts.get("SNPA", "").strip()
            cur["lan"] = parts.get("LAN id", "").strip()
            continue
        if s.startswith("IPv4 Address"):
            want_ip = True
            continue
        if want_ip and cur is not None and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", s):
            cur["ips"].append(s)
            continue
        if s.endswith(":") or ":" in s:
            want_ip = False
            continue
        if len(raw) - len(raw.lstrip()) <= 2 and re.fullmatch(r"[\w.-]+", s):
            name = s
            want_ip = False
    return out


def merge(adjs: list[dict]) -> list[dict]:
    """One row per neighbour and interface, its type L1, L2 or L1L2 from the
    levels that are Up (IOS's show isis neighbors)."""
    rows: dict[tuple[str, str], dict] = {}
    for a in adjs:
        r = rows.setdefault((a["system"], a["dev"]), {**a, "levels": set(), "up": False})
        r["levels"].add(a["level"])
        r["up"] = r["up"] or a["state"].lower() == "up"
        r["ips"] = r["ips"] or a["ips"]
        r["state"] = "UP" if r["up"] else a["state"].upper()
    for r in rows.values():
        r["type"] = "L1L2" if r["levels"] == {1, 2} else f"L{min(r['levels'])}"
    return list(rows.values())


def parse_route_levels(text: str) -> dict[str, str]:
    """isisd's 'show isis route': which level each prefix was learnt at
    (its tables are headed 'IS-IS L1 IPv4 routing table:' and 'L2')."""
    out: dict[str, str] = {}
    level = ""
    for line in (text or "").splitlines():
        m = re.search(r"IS-IS (L[12]) IPv4 routing table", line)
        if m:
            level = m.group(1)
            continue
        p = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s", line)
        if p and level:
            out.setdefault(p.group(1), level)
    return out


def _read(con, cmd: str) -> str | None:
    from .iosrouting import _frr_note, _vtysh
    if not active(_own(con.lab)):
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
    text = _read(con, "show isis neighbor detail")
    if not text:
        return text or ""
    rev = _names(con)
    own = _own(con.lab)
    out = [f"Tag {tag(own) or 'null'}:",
           f"{'System Id':<16}{'Type':<5}{'Interface':<14}{'IP Address':<16}{'State':<6}{'Holdtime':<9}Circuit Id"]
    for r in merge(parse_neighbors(text)):
        name = devcli.short_if(rev.get(r["dev"], r["dev"]))
        hold = re.sub(r"s$", "", r["expires"]) or "-"
        out.append(f"{r['system'][:15]:<16}{r['type']:<5}{name:<14}{(r['ips'][:1] or ['-'])[0]:<16}"
                   f"{r['state']:<6}{hold:<9}{r['lan'] or '-'}")
        if detail:
            out.append(f"  Area Address(es): {', '.join(area_of(n) for n in nets(own)) or '-'}")
            out.append(f"  SNPA: {r['snpa'] or '-'}")
            out.append(f"  Circuit type: {r['ctype'] or '-'}")
    return "\n".join(out)


def _frr(con, cmd: str) -> str:
    from .iosrouting import _map_ifaces
    text = _read(con, cmd)
    if not text:
        return text or ""
    return _map_ifaces(con, text.rstrip())


def levels(con) -> dict[str, str]:
    text = _read(con, "show isis route")
    return parse_route_levels(text or "")


def _route(con) -> str:
    from .iosrouting import show_route
    return show_route(con, "", only="isis")


def protocols(con) -> list[str]:
    own = _own(con.lab)
    if not active(own):
        return []
    out = [f"Routing Protocol is \"isis{' ' + tag(own) if tag(own) else ''}\"",
           "  Outgoing update filter list for all interfaces is not set",
           "  Incoming update filter list for all interfaces is not set",
           f"  IS-IS Level: {own.get('isis-type', 'level-1-2')}",
           f"  Metric style: {own.get('isis-style', 'narrow')}",
           "  Routing for Networks:"]
    out += [f"    {n}" for n in ifaces(own)]
    pas = [n for n, _, _ in con.router_ifaces() if passive(own, n)]
    if pas:
        out.append("  Passive Interface(s):")
        out += [f"    {p}" for p in pas]
    out += ["  Routing Information Sources:", "    Gateway         Distance      Last Update",
            f"  Distance: ({DISTANCE})", ""]
    return out

