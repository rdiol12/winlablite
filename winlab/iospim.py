"""IP multicast typed at the lab router's console, made real by FRRouting's
pimd (PIM sparse mode, RFC 7761, and IGMP).

``ip multicast-routing`` turns the router into a multicast router: pimd is
started in /etc/frr/daemons (winlab/iosrouting.py writes it) and opens the
kernel's multicast routing socket, so the Linux kernel forwards multicast by
the (S,G) and (*,G) entries pimd installs. Without it IOS takes ``ip pim``
on an interface but forwards nothing, and so does this router (pimd is not
started, and the console warns as IOS does).

* ``ip pim sparse-mode`` on an interface is pimd's ``ip pim`` there, with
  ``ip igmp`` beside it: IOS turns IGMP on with PIM, pimd needs both lines.
  ``ip igmp version 2|3`` and ``ip pim dr-priority <n>`` are pimd's
  ``ip igmp version`` and ``ip pim drpriority``.
* ``ip pim rp-address <address> [<acl>]`` is pimd's static RP, ``ip pim rp
  <address> <group range>``: with no ACL for every group (224.0.0.0/4); with
  a standard ACL, one range per permit line of it (its address and
  wildcard, which must be contiguous), as IOS maps the ACL's groups to the
  RP. The same line is pimd's on FRRouting 8.4 (rtr-edge, Ubuntu) and is
  still taken by FRRouting 10 (the lab router, Alpine), which shows it
  under ``router pim``.
* ``show ip pim neighbor``, ``show ip pim interface``, ``show ip pim rp
  mapping``, ``show ip mroute`` and ``show ip igmp groups`` read pimd (its
  JSON where it has it) and print IOS's layout with the console's interface
  names. Uptimes and timers are pimd's; IOS's flags in ``show ip mroute``
  are derived from what pimd reports (S for every sparse entry, C when IGMP
  asked for the group on an outgoing interface, T on (S,G) entries the
  source's traffic is flowing on), not copied from it.

What the console refuses, saying so: ``ip pim dense-mode`` and
``sparse-dense-mode`` (pimd is sparse mode only: no flooding and pruning),
Auto-RP and BSR (``ip pim send-rp-announce``, ``ip pim bsr-candidate``:
pimd has a BSR client but no Cisco Auto-RP), bidirectional PIM and
``ip pim ssm`` (pimd's SSM range is fixed at 232.0.0.0/8 here).

A host joins a group with IGMP; a Linux PC can do it with nothing extra:
``sudo ip address add 239.1.1.1/32 dev eth0 autojoin`` (iproute2 joins
the group and the kernel answers the router's IGMP queries for it).

Settings (in [devices."router"]): ``mcast-routing`` = yes; ``pim:<if>`` =
sparse-mode; ``pim-dr:<if>``; ``igmp-ver:<if>``; ``pim-rp:<address>`` =
the ACL or "".
"""

from __future__ import annotations

import ipaddress
import json
import re

ALL_GROUPS = "224.0.0.0/4"

NO_DENSE = ("% PIM dense mode is not in this router: FRRouting's pimd is sparse mode only (no flood and prune).\n"
            "% Use ip pim sparse-mode and a rendezvous point (ip pim rp-address).")
NO_AUTORP = ("% Auto-RP and BSR candidates are not in this router: FRRouting's pimd has no Cisco Auto-RP. Give\n"
             "% every router the same static RP with ip pim rp-address <address>.")
NO_BIDIR = "% Bidirectional PIM is not in this router: FRRouting's pimd does not do it."
NO_SSM = ("% ip pim ssm is not in this router: pimd's source-specific range stays the default, 232.0.0.0/8\n"
          "% (IGMPv3 joins with a source for those groups work as they are).")
NO_MCAST = ("WARNING: \"ip multicast-routing\" is not configured,\n"
            "         IP Multicast packets will not be forwarded")


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def routing(own: dict) -> bool:
    return bool(own.get("mcast-routing"))


def pim_ifaces(own: dict) -> list[str]:
    return sorted(k[4:] for k in own if k.startswith("pim:"))


def rps(own: dict) -> list[tuple[str, str]]:
    """(RP address, ACL or "") of the static RPs."""
    return sorted(((k[7:], v) for k, v in own.items() if k.startswith("pim-rp:")),
                  key=lambda r: int(ipaddress.IPv4Address(r[0])))


def active(own: dict) -> bool:
    return routing(own) or bool(pim_ifaces(own)) or bool(rps(own))


def runs(own: dict) -> bool:
    """pimd is started: multicast routing on and PIM on an interface."""
    return routing(own) and bool(pim_ifaces(own))


def acl_ranges(own: dict, acl: str) -> list[str]:
    """The group ranges a standard ACL permits, as pimd's prefixes: one per
    permit line (host -> /32, any -> 224.0.0.0/4, address and contiguous
    wildcard -> its prefix). Deny lines and a missing or extended ACL give
    none (the console keeps a standard entry as 'permit <prefix>')."""
    from . import iosl3
    if iosl3.kind_of(own, acl) != "standard":
        return []
    out = []
    for _, line in iosl3.entries(own, acl):
        w = line.split()
        if len(w) < 2 or w[0] != "permit":
            continue
        try:
            n = ipaddress.IPv4Network(w[1], strict=False)
        except ValueError:
            continue
        out.append(ALL_GROUPS if n.prefixlen == 0 else str(n))
    return out


def rp_ranges(own: dict) -> list[tuple[str, str]]:
    """(RP, group range) for pimd."""
    out = []
    for rp, acl in rps(own):
        for rng in (acl_ranges(own, acl) if acl else [ALL_GROUPS]):
            out.append((rp, rng))
    return out


def rp_for(own: dict, group: str) -> str:
    """The RP of a group: the longest matching range, as pimd picks it."""
    best, plen = "", -1
    try:
        g = ipaddress.IPv4Address(group)
    except ValueError:
        return ""
    for rp, rng in rp_ranges(own):
        n = ipaddress.IPv4Network(rng, strict=False)
        if g in n and n.prefixlen > plen:
            best, plen = rp, n.prefixlen
    return best


# ------------------------------------------------------------------ frr.conf
def frr_lines(plan) -> list[str]:
    """The static RPs, then the PIM interfaces' lines."""
    from .iosrouting import svi_map
    own = _own(plan.lab)
    if not runs(own):
        return []
    out = [f"ip pim rp {rp} {rng}" for rp, rng in rp_ranges(own)]
    out += ["!"] if out else []
    svis = svi_map(plan.lab, plan)
    for name in pim_ifaces(own):
        dev = svis.get(name)
        if not dev:
            continue
        body = [" ip pim", " ip igmp"]
        if own.get(f"igmp-ver:{name}"):
            body.append(f" ip igmp version {own[f'igmp-ver:{name}']}")
        if own.get(f"pim-dr:{name}"):
            body.append(f" ip pim drpriority {own[f'pim-dr:{name}']}")
        out += [f"interface {dev}"] + body + ["exit", "!"]
    return out


# ------------------------------------------------------------------ show running-config
def global_lines(own: dict) -> list[str]:
    """ip multicast-routing, printed before the interfaces as on IOS."""
    return ["ip multicast-routing", "!"] if routing(own) else []


def iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    if own.get(f"pim:{ifname}"):
        out.append(f" ip pim {own[f'pim:{ifname}']}")
    if own.get(f"pim-dr:{ifname}"):
        out.append(f" ip pim dr-priority {own[f'pim-dr:{ifname}']}")
    if own.get(f"igmp-ver:{ifname}"):
        out.append(f" ip igmp version {own[f'igmp-ver:{ifname}']}")
    return out


def run_lines(own: dict) -> list[str]:
    out = [f"ip pim rp-address {rp}" + (f" {acl}" if acl else "") for rp, acl in rps(own)]
    return out + (["!"] if out else [])


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, IF) -> None:
    from . import devcli
    for k, v in {("ip", "multicast-routing"): "Enable IP multicast forwarding",
                 ("ip", "pim"): "PIM interface commands", ("ip", "igmp"): "IGMP interface commands",
                 ("show", "ip", "pim"): "PIM information", ("show", "ip", "mroute"): "IP multicast routing table",
                 ("show", "ip", "igmp"): "IGMP information"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    add("ip multicast-routing", lambda a: _global(con, True), "Enable IP multicast forwarding", C)
    add("no ip multicast-routing", lambda a: _global(con, False), "Negate a command or set its defaults", C)
    add("ip pim rp-address <ip>", lambda a: _rp(con, a[0], "", True), "PIM RP-address (Rendezvous Point)", C)
    add("ip pim rp-address <ip> <name>", lambda a: _rp(con, a[0], a[1], True), "PIM RP-address (Rendezvous Point)", C)
    add("ip pim rp-address <ip> <name> override", lambda a: _rp(con, a[0], a[1], True), "Overrides dynamically learnt RP mappings", C)
    add("no ip pim rp-address <ip>", lambda a: _rp(con, a[0], "", False), "Negate a command or set its defaults", C)
    add("no ip pim rp-address <ip> <line>", lambda a: _rp(con, a[0], "", False), "Negate a command or set its defaults", C)
    add("ip pim send-rp-announce <line>", lambda a: NO_AUTORP, "Auto-RP send RP announcement", C)
    add("ip pim send-rp-discovery <line>", lambda a: NO_AUTORP, "Auto-RP send RP discovery message (as RP-mapping agent)", C)
    add("ip pim bsr-candidate <line>", lambda a: NO_AUTORP, "Candidate bootstrap router (candidate BSR)", C)
    add("ip pim rp-candidate <line>", lambda a: NO_AUTORP, "To be a PIMv2 RP candidate", C)
    add("ip pim bidir-enable", lambda a: NO_BIDIR, "Enable Bidir-PIM", C)
    add("ip pim ssm <line>", lambda a: NO_SSM, "Configure Source Specific Multicast", C)
    add("ip pim sparse-mode", lambda a: _if_pim(con, "sparse-mode"), "Enable PIM sparse-mode operation", IF)
    add("ip pim dense-mode", lambda a: NO_DENSE, "Enable PIM dense-mode operation", IF)
    add("ip pim sparse-dense-mode", lambda a: NO_DENSE, "Enable PIM sparse-dense-mode operation", IF)
    add("no ip pim", lambda a: _if_pim(con, ""), "Negate a command or set its defaults", IF)
    add("no ip pim sparse-mode", lambda a: _if_pim(con, ""), "Negate a command or set its defaults", IF)
    add("ip pim dr-priority <num>", lambda a: _if_num(con, "pim-dr", a[0], 0, 4294967295), "PIM router DR priority", IF)
    add("no ip pim dr-priority", lambda a: _if_num(con, "pim-dr", "", 0, 0), "Negate a command or set its defaults", IF)
    add("no ip pim dr-priority <num>", lambda a: _if_num(con, "pim-dr", "", 0, 0), "Negate a command or set its defaults", IF)
    add("ip igmp version <num>", lambda a: _if_num(con, "igmp-ver", a[0], 2, 3), "IGMP version", IF)
    add("no ip igmp version", lambda a: _if_num(con, "igmp-ver", "", 0, 0), "Negate a command or set its defaults", IF)
    add("no ip igmp version <num>", lambda a: _if_num(con, "igmp-ver", "", 0, 0), "Negate a command or set its defaults", IF)
    add("show ip pim neighbor", lambda a: show_neighbors(con), "PIM neighbor information", U)
    add("show ip pim interface", lambda a: show_interfaces(con), "PIM interface information", U)
    add("show ip pim rp mapping", lambda a: show_rp_mapping(con), "Show group-to-RP mappings", U)
    add("show ip pim rp", lambda a: show_rp_mapping(con), "PIM Rendezvous Point (RP) information", U)
    add("show ip mroute", lambda a: show_mroute(con, ""), "IP multicast routing table", U)
    add("show ip mroute <ip>", lambda a: show_mroute(con, a[0]), "Group address", U)
    add("show ip igmp groups", lambda a: show_igmp_groups(con), "IGMP group membership information", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _global(con, on: bool) -> str:
    own = _own_c(con)
    if on:
        if own.get("mcast-routing"):
            return ""
        own["mcast-routing"] = "yes"
    elif own.pop("mcast-routing", None) is None:
        return ""
    return _done(con)


def _rp(con, addr: str, acl: str, on: bool) -> str:
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        raise _bad() from None
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        raise _err(f"% {ip} is not a valid unicast address for an RP")
    own = _own_c(con)
    key = f"pim-rp:{ip}"
    if not on:
        if own.pop(key, None) is None:
            return ""
        return _done(con)
    note = ""
    if acl:
        from . import iosl3
        if not iosl3.entries(own, acl):
            note = f"% Access list {acl} is not configured yet: the RP serves no group until it has permit lines"
        elif not acl_ranges(own, acl):
            note = f"% Access list {acl} permits no group range this router can use (a contiguous wildcard)"
    for k, v in own.items():
        if k.startswith("pim-rp:") and k != key and v == acl:
            raise _err(f"% {'ACL ' + acl if acl else 'All groups'} already mapped to RP {k[7:]}: "
                       f"no ip pim rp-address {k[7:]} first")
    own[key] = acl
    done = _done(con)
    return "\n".join(x for x in (note, done) if x)


def _if_pim(con, mode: str) -> str:
    own = _own_c(con)
    key = f"pim:{con.s.ctx}"
    if mode:
        new = own.get(key) != mode
        own[key] = mode
        done = _done(con) if new else ""
        warn = "" if routing(own) else NO_MCAST
        return "\n".join(x for x in (warn, done) if x)
    if own.pop(key, None) is None:
        return ""
    own.pop(f"pim-dr:{con.s.ctx}", None)
    return _done(con)


def _if_num(con, what: str, value: str, lo: int, hi: int) -> str:
    own = _own_c(con)
    key = f"{what}:{con.s.ctx}"
    if value:
        if not lo <= int(value) <= hi:
            raise _bad()
        own[key] = str(int(value))
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


# ------------------------------------------------------------------ reading pimd
def _read(con, cmd: str) -> str | None:
    """pimd's answer, or None when there is nothing to ask (no multicast
    routing typed), or "" with a note when FRRouting is not there."""
    from .iosrouting import _frr_note, _vtysh
    if not runs(_own(con.lab)):
        return None
    text = _vtysh(con, cmd)
    if text.strip().startswith("%"):
        return None if not _frr_note(text) else _frr_note(text)
    return text


def _json(text: str | None):
    try:
        return json.loads(text or "")
    except ValueError:
        return None


def _names(con) -> dict[str, str]:
    from .iosrouting import svi_map
    return {dev: name for name, dev in svi_map(con.lab, con.plan).items()}


def _short(con, dev: str) -> str:
    from . import devcli
    return devcli.short_if(_names(con).get(dev, dev))


def _hms(text) -> str:
    """pimd's '00:01:02' or '1d02h03m' or seconds -> IOS's 00:01:02."""
    if isinstance(text, (int, float)):
        s = int(text)
        return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"
    text = str(text or "").strip()
    if re.fullmatch(r"\d{1,3}:\d{2}:\d{2}", text):
        return text.zfill(8)
    if re.fullmatch(r"\d{1,2}:\d{2}", text):
        return "00:" + text.zfill(5)
    s = 0
    for n, unit in re.findall(r"(\d+)([dhms])", text):
        s += int(n) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
    if not re.search(r"\d[dhms]", text):
        return text or "--:--:--"
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def parse_neighbors(text: str) -> list[dict]:
    """pimd's show ip pim neighbor json: {interface: {address: {...}}}; or
    its text table (Interface Neighbor Uptime Holdtime DR Pri)."""
    data = _json(text)
    out = []
    if isinstance(data, dict):
        for dev, nbrs in data.items():
            if not isinstance(nbrs, dict):
                continue
            for addr, n in nbrs.items():
                if not isinstance(n, dict):
                    continue
                out.append({"dev": n.get("interface", dev), "addr": n.get("neighbor", addr),
                            "uptime": _hms(n.get("upTime", "")), "expires": _hms(n.get("holdTime", "")),
                            "prio": int(n.get("drPriority", 1) or 1)})
        return out
    for line in (text or "").splitlines():
        m = re.match(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$", line.strip())
        if m:
            out.append({"dev": m.group(1), "addr": m.group(2), "uptime": _hms(m.group(3)),
                        "expires": _hms(m.group(4)), "prio": int(m.group(5))})
    return out


def parse_interfaces(text: str) -> list[dict]:
    """pimd's show ip pim interface json: {interface: {address, state,
    pimDesignatedRouter, pimNeighbors, ...}}."""
    data = _json(text)
    out = []
    if isinstance(data, dict):
        for dev, i in data.items():
            if not isinstance(i, dict) or dev == "pimreg" or dev.startswith("pimreg"):
                continue
            nbrs = i.get("pimNeighbors", i.get("neighbors", 0))
            out.append({"dev": dev, "addr": i.get("address", ""), "nbrs": len(nbrs) if isinstance(nbrs, (dict, list)) else int(nbrs or 0),
                        "dr": i.get("pimDesignatedRouter", i.get("drAddress", "")),
                        "prio": i.get("drPriority", 1)})
    return out


def parse_mroute(text: str) -> list[dict]:
    """pimd's show ip mroute json: {group: {source: {iif, oil: {interface:
    {...}}}}}, a source of '*' being a (*,G) entry."""
    data = _json(text)
    out = []
    if not isinstance(data, dict):
        return out
    for group, sources in data.items():
        if not isinstance(sources, dict):
            continue
        try:
            ipaddress.IPv4Address(group)
        except ValueError:
            continue
        for source, e in sources.items():
            if not isinstance(e, dict):
                continue
            oil = e.get("oil", {}) if isinstance(e.get("oil"), dict) else {}
            outs = []
            up = ""
            for dev, o in oil.items():
                if dev.startswith("pimreg"):
                    continue
                o = o if isinstance(o, dict) else {}
                up = up or o.get("upTime", "")
                outs.append({"dev": o.get("outboundInterface", dev), "uptime": _hms(o.get("upTime", "")),
                             "igmp": bool(o.get("protocolIgmp") or o.get("protocolLocal")),
                             "pim": bool(o.get("protocolPim"))})
            out.append({"group": group, "source": "*" if source in ("*", "0.0.0.0") else source,
                        "iif": e.get("iif", e.get("inboundInterface", "")) or "",
                        "installed": bool(e.get("installed", True)), "uptime": _hms(up or e.get("upTime", "")),
                        "oil": outs})
    out.sort(key=lambda r: (int(ipaddress.IPv4Address(r["group"])), r["source"] != "*", r["source"]))
    return out


def parse_igmp_groups(text: str) -> list[dict]:
    """pimd's show ip igmp groups json: {interface: {groups: [{group,
    timer, uptime, source?}]}} beside totals."""
    data = _json(text)
    out = []
    if not isinstance(data, dict):
        return out
    for dev, i in data.items():
        if not isinstance(i, dict):
            continue
        for g in i.get("groups", []) or []:
            if isinstance(g, dict) and g.get("group"):
                out.append({"dev": dev, "group": g["group"], "uptime": _hms(g.get("uptime", "")),
                            "expires": _hms(g.get("timer", "")), "version": g.get("version", "")})
    out.sort(key=lambda r: (int(ipaddress.IPv4Address(r["group"])), r["dev"]))
    return out


# ------------------------------------------------------------------ the shows
def _off(con) -> str:
    own = _own(con.lab)
    if not routing(own):
        return "% IP multicast routing is not enabled (ip multicast-routing)"
    return ""


def show_neighbors(con) -> str:
    text = _read(con, "show ip pim neighbor json")
    if text is None:
        return _off(con)
    out = ["PIM Neighbor Table",
           "Mode: B - Bidir Capable, DR - Designated Router, N - Default DR Priority,",
           "      P - Proxy Capable, S - State Refresh Capable, G - GenID Capable,",
           "      L - DR Load-balancing Capable",
           "Neighbor          Interface                Uptime/Expires    Ver   DR",
           "Address                                                            Prio/Mode"]
    if not text:
        return "\n".join(out)
    dr = {i["dev"]: i["dr"] for i in parse_interfaces(_read(con, "show ip pim interface json") or "")}
    for n in parse_neighbors(text):
        mode = " / DR" if dr.get(n["dev"]) == n["addr"] else " /"
        out.append(f"{n['addr']:<18}{_short(con, n['dev']):<25}{n['uptime'] + '/' + n['expires']:<18}"
                   f"v2{n['prio']:>6}{mode} G")
    return "\n".join(out)


def show_interfaces(con) -> str:
    text = _read(con, "show ip pim interface json")
    if text is None:
        return _off(con)
    out = ["Address          Interface                Ver/   Nbr    Query  DR         DR",
           "                                          Mode   Count  Intvl  Prior"]
    own = _own(con.lab)
    for i in parse_interfaces(text or ""):
        name = _names(con).get(i["dev"], i["dev"])
        prio = own.get(f"pim-dr:{name}", "1")
        out.append(f"{i['addr']:<17}{_short(con, i['dev']):<25}v2/S   {i['nbrs']:<7}30     {prio:<11}{i['dr'] or '0.0.0.0'}")
    return "\n".join(out)


def show_rp_mapping(con) -> str:
    own = _own(con.lab)
    if not routing(own):
        return _off(con)
    out = ["PIM Group-to-RP Mappings", ""]
    for rp, acl in rps(own):
        ranges = acl_ranges(own, acl) if acl else [ALL_GROUPS]
        for rng in ranges:
            out.append(f"Group(s): {rng}, Static" + (f" (ACL {acl})" if acl else ""))
            out.append(f"    RP: {rp} (?)")
    return "\n".join(out)


MROUTE_HEAD = ["IP Multicast Routing Table",
               "Flags: D - Dense, S - Sparse, B - Bidir Group, s - SSM Group, C - Connected,",
               "       L - Local, P - Pruned, R - RP-bit set, F - Register flag,",
               "       T - SPT-bit set, J - Join SPT",
               "Outgoing interface flags: H - Hardware switched, A - Assert winner, p - PIM Join",
               " Timers: Uptime/Expires",
               " Interface state: Interface, Next-Hop or VCD, State/Mode", ""]


def show_mroute(con, group: str) -> str:
    if group:
        try:
            group = str(ipaddress.IPv4Address(group))
        except ValueError:
            raise _bad() from None
    text = _read(con, "show ip mroute json")
    if text is None:
        return _off(con)
    own = _own(con.lab)
    out = list(MROUTE_HEAD)
    for r in parse_mroute(text or ""):
        if group and r["group"] != group:
            continue
        ssm = ipaddress.IPv4Address(r["group"]) in ipaddress.IPv4Network("232.0.0.0/8")
        flags = "s" if ssm else "S"
        if any(o["igmp"] for o in r["oil"]):
            flags += "C"
        if not r["oil"]:
            flags += "P"
        rp = rp_for(own, r["group"])
        if r["source"] == "*":
            head = f"(*, {r['group']}), {r['uptime']}/stopped, RP {rp or '0.0.0.0'}, flags: {flags}"
        else:
            head = f"({r['source']}, {r['group']}), {r['uptime']}/stopped, flags: {flags}T"
        # pimreg is pimd's register tunnel: on the RP a (*,G) has no upstream, IOS's Null
        iif = (_short(con, r["iif"]) if r["iif"] and r["iif"] not in ("<iif?>", "none") and not r["iif"].startswith("pimreg")
               else "Null")
        out += [head, f"  Incoming interface: {iif}, RPF nbr 0.0.0.0" if iif == "Null" else f"  Incoming interface: {iif}",
                "  Outgoing interface list:" + ("" if r["oil"] else " Null")]
        for o in r["oil"]:
            out.append(f"    {_short(con, o['dev'])}, Forward/Sparse, {o['uptime']}/stopped")
        out.append("")
    return "\n".join(out).rstrip()


def show_igmp_groups(con) -> str:
    text = _read(con, "show ip igmp groups json")
    if text is None:
        return _off(con)
    out = ["IGMP Connected Group Membership",
           "Group Address    Interface                Uptime    Expires   Last Reporter   Group Accounted"]
    for g in parse_igmp_groups(text or ""):
        out.append(f"{g['group']:<17}{_short(con, g['dev']):<25}{g['uptime']:<10}{g['expires']}")
    return "\n".join(out)
