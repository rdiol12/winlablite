"""BGP path control and MP-BGP VPNv4 at the lab router's console, made real
by FRRouting's bgpd (winlab/iosrouting.py writes the lines into its
``router bgp`` block of /etc/frr/frr.conf).

Per neighbour, the IOS words are bgpd's own:

* ``neighbor <ip> route-map <name> in|out``, ``prefix-list <name> in|out``,
  ``filter-list <as-path list> in|out`` (winlab/iosrpolicy.py defines the
  objects), ``weight <n>``, ``next-hop-self``, ``route-reflector-client``,
  ``update-source <interface>`` (a Loopback: winlab/iosmpls.py),
  ``ebgp-multihop [<ttl>]`` and ``fall-over bfd`` (bgpd's ``neighbor <ip>
  bfd`` with the interface's BFD timers as a profile, winlab/iosbfd.py).
* ``neighbor <ip> send-community [standard|extended|both]``: IOS sends no
  community unless told to; bgpd sends them all by default, so the console
  writes ``no neighbor <ip> send-community ...`` for what IOS would not
  send. A community set by a route-map out reaches the peer only with
  send-community, as on IOS.

For the router: ``bgp cluster-id``, ``bgp default local-preference``,
``bgp always-compare-med``, ``bgp deterministic-med``, ``bgp bestpath
as-path ignore``, ``bgp bestpath med missing-as-worst``, ``bgp bestpath
compare-routerid``: bgpd's own commands.

MPLS L3VPN: ``address-family vpnv4`` with ``neighbor <ip> activate`` (IOS
adds ``send-community extended`` itself, and so does the console) is bgpd's
``address-family ipv4 vpn``; a VRF with an RD and route targets
(winlab/iosmpls.py) becomes ``router bgp <as> vrf <name>`` with ``rd vpn
export``, ``rt vpn import|export``, ``label vpn export auto`` and ``import
vpn`` / ``export vpn``; ``address-family ipv4 vrf <name>`` takes
``redistribute connected|static`` and ``network``. BGP to a customer's router
inside a VRF (PE-CE eBGP) is not in this router: the console says so.

``show ip bgp`` and its variants are bgpd's table, which already has IOS's
columns (Network, Next Hop, Metric, LocPrf, Weight, Path); the console takes
away the lines only FRRouting prints (RPKI, nexthop codes, vrf id).

Settings: ``bgp-rmin:<ip>``, ``bgp-rmout:<ip>``, ``bgp-plin:<ip>``,
``bgp-plout:<ip>``, ``bgp-flin:<ip>``, ``bgp-flout:<ip>``, ``bgp-weight:<ip>``,
``bgp-nhs:<ip>``, ``bgp-rrc:<ip>``, ``bgp-upd:<ip>`` = interface,
``bgp-mhop:<ip>`` = ttl, ``bgp-bfd:<ip>``, ``bgp-sc:<ip>`` = standard |
extended | both; ``bgp-cluster``, ``bgp-lp``, ``bgp-opt:<option>``;
``bgp-vpn:<ip>``, ``bgp-vpnsc:<ip>``; ``bgp-vrf:<vrf>``,
``bgp-vrfredist:<vrf>:<source>`` = options, ``bgp-vrfnet:<vrf>:<prefix>``.
"""

from __future__ import annotations

import ipaddress
import re

OPTIONS = {"always-compare-med": "bgp always-compare-med", "deterministic-med": "bgp deterministic-med",
           "as-path-ignore": "bgp bestpath as-path ignore", "med-missing-as-worst": "bgp bestpath med missing-as-worst",
           "compare-routerid": "bgp bestpath compare-routerid"}
NO_PECE = ("% BGP to a customer's router inside a VRF (PE-CE) is not in this router: redistribute connected or "
           "static under address-family ipv4 vrf instead")


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


# ------------------------------------------------------------------ where the console is
def sub_af(con) -> str:
    """"" (IPv4 unicast), "vpnv4" or "vrf:<name>": the address family the
    console's router bgp prompt is in."""
    if not con.s.ctx.startswith("bgp:") or con.s.mode != "config-router-af":
        return ""
    parts = con.s.ctx.split(":", 2)
    return parts[2] if len(parts) > 2 else ""


def base_ctx(ctx: str) -> str:
    if ctx.startswith("bgp:"):
        return ":".join(ctx.split(":")[:2])
    return ctx


def vrf_bgp(own: dict) -> list[str]:
    from .iosmpls import rts
    from .iosrouting import vrfs
    out = []
    for name in vrfs(own):
        if own.get(f"bgp-vrf:{name}") or (own.get(f"vrf:{name}") and any(rts(own, name).values())):
            out.append(name)
    return out


def bfd_peer_profile(own: dict, lab, plan, ip: str) -> str:
    """The BFD profile of the interface a neighbour is on ("" for none)."""
    from . import iosbfd, iosrouting
    svis = iosrouting.svi_map(lab, plan)
    for name in svis:
        net = lab.networks.get(own.get(f"ip:{name}", ""))
        if net is not None and ipaddress.IPv4Address(ip) in net.net and own.get(f"bfd-if:{name}"):
            return iosbfd.profile(svis[name])
    return ""


# ------------------------------------------------------------------ frr.conf
def frr_global(own: dict) -> list[str]:
    out = []
    if own.get("bgp-cluster"):
        out.append(f" bgp cluster-id {own['bgp-cluster']}")
    if own.get("bgp-lp"):
        out.append(f" bgp default local-preference {own['bgp-lp']}")
    out += [f" {OPTIONS[k]}" for k in OPTIONS if own.get(f"bgp-opt:{k}")]
    return out


def frr_nbr_global(own: dict, plan, ip: str) -> list[str]:
    from . import iosmpls
    out = []
    if own.get(f"bgp-upd:{ip}"):
        src = iosmpls.address_of(own, own[f"bgp-upd:{ip}"]) or iosmpls.dev_of(own[f"bgp-upd:{ip}"])
        if src:
            out.append(f" neighbor {ip} update-source {src}")
    if own.get(f"bgp-mhop:{ip}"):
        out.append(f" neighbor {ip} ebgp-multihop {own[f'bgp-mhop:{ip}']}")
    if own.get(f"bgp-bfd:{ip}") and plan is not None:
        prof = bfd_peer_profile(own, plan.lab, plan, ip)
        if prof:
            out += [f" neighbor {ip} bfd", f" neighbor {ip} bfd profile {prof}"]
    return out


def _sc_negations(ip: str, sc: str) -> list[str]:
    out = []
    if sc not in ("standard", "both"):
        out.append(f"  no neighbor {ip} send-community")
    if sc not in ("extended", "both"):
        out.append(f"  no neighbor {ip} send-community extended")
    return out


def frr_nbr_af(own: dict, ip: str) -> list[str]:
    out = _sc_negations(ip, own.get(f"bgp-sc:{ip}", ""))
    if own.get(f"bgp-rrc:{ip}"):
        out.append(f"  neighbor {ip} route-reflector-client")
    if own.get(f"bgp-nhs:{ip}"):
        out.append(f"  neighbor {ip} next-hop-self")
    if own.get(f"bgp-weight:{ip}"):
        out.append(f"  neighbor {ip} weight {own[f'bgp-weight:{ip}']}")
    for key, word in (("pl", "prefix-list"), ("fl", "filter-list"), ("rm", "route-map")):
        for way in ("in", "out"):
            if own.get(f"bgp-{key}{way}:{ip}"):
                out.append(f"  neighbor {ip} {word} {own[f'bgp-{key}{way}:{ip}']} {way}")
    return out


def frr_extra_afs(own: dict, nbrs: list[str]) -> list[str]:
    vpn = [ip for ip in nbrs if own.get(f"bgp-vpn:{ip}")]
    if not vpn:
        return []
    out = [" !", " address-family ipv4 vpn"]
    for ip in vpn:
        out.append(f"  neighbor {ip} activate")
        sc = own.get(f"bgp-vpnsc:{ip}", "")
        if sc not in ("extended", "both"):
            out.append(f"  no neighbor {ip} send-community extended")
    return out + [" exit-address-family"]


def frr_vrf_blocks(own: dict) -> list[str]:
    from .iosmpls import rts
    from .iosrouting import _redist, bgp_as
    asn = bgp_as(own)
    out = []
    for name in vrf_bgp(own):
        out.append(f"router bgp {asn} vrf {name}")
        if own.get("bgp-rid"):
            out.append(f" bgp router-id {own['bgp-rid']}")
        out += [" no bgp ebgp-requires-policy", " !", " address-family ipv4 unicast"]
        out += [f"  network {k.split(':', 2)[2]}" for k in sorted(own) if k.startswith(f"bgp-vrfnet:{name}:")]
        out += ["  " + _redist(k.split(":", 2)[2], v, False) for k, v in sorted(own.items())
                if k.startswith(f"bgp-vrfredist:{name}:")]
        t = rts(own, name)
        if own.get(f"vrf:{name}"):
            out += ["  label vpn export auto", f"  rd vpn export {own[f'vrf:{name}']}"]
        if t["import"]:
            out.append(f"  rt vpn import {' '.join(t['import'])}")
        if t["export"]:
            out.append(f"  rt vpn export {' '.join(t['export'])}")
        if t["export"] and own.get(f"vrf:{name}"):
            out.append("  export vpn")
        if t["import"]:
            out.append("  import vpn")
        out += [" exit-address-family", "exit", "!"]
    return out


# ------------------------------------------------------------------ show running-config
def run_global(own: dict) -> list[str]:
    return frr_global(own)


def run_nbr_global(own: dict, ip: str) -> list[str]:
    out = []
    if own.get(f"bgp-upd:{ip}"):
        out.append(f" neighbor {ip} update-source {own[f'bgp-upd:{ip}']}")
    if own.get(f"bgp-mhop:{ip}"):
        out.append(f" neighbor {ip} ebgp-multihop {own[f'bgp-mhop:{ip}']}")
    if own.get(f"bgp-bfd:{ip}"):
        out.append(f" neighbor {ip} fall-over bfd")
    return out


def run_nbr_af(own: dict, ip: str) -> list[str]:
    out = []
    sc = own.get(f"bgp-sc:{ip}", "")
    if sc:
        out.append(f"  neighbor {ip} send-community" + ("" if sc == "standard" else f" {sc}"))
    if own.get(f"bgp-rrc:{ip}"):
        out.append(f"  neighbor {ip} route-reflector-client")
    if own.get(f"bgp-nhs:{ip}"):
        out.append(f"  neighbor {ip} next-hop-self")
    if own.get(f"bgp-weight:{ip}"):
        out.append(f"  neighbor {ip} weight {own[f'bgp-weight:{ip}']}")
    for key, word in (("pl", "prefix-list"), ("fl", "filter-list"), ("rm", "route-map")):
        for way in ("in", "out"):
            if own.get(f"bgp-{key}{way}:{ip}"):
                out.append(f"  neighbor {ip} {word} {own[f'bgp-{key}{way}:{ip}']} {way}")
    return out


def run_extra_afs(own: dict, nbrs: list[str]) -> list[str]:
    out = []
    vpn = [ip for ip in nbrs if own.get(f"bgp-vpn:{ip}")]
    if vpn:
        out += [" !", " address-family vpnv4"]
        for ip in vpn:
            out.append(f"  neighbor {ip} activate")
            sc = own.get(f"bgp-vpnsc:{ip}", "")
            if sc:
                out.append(f"  neighbor {ip} send-community {sc}")
        out.append(" exit-address-family")
    for name in sorted(k[8:] for k in own if k.startswith("bgp-vrf:")):
        out += [" !", f" address-family ipv4 vrf {name}"]
        out += [f"  redistribute {k.split(':', 2)[2]}" + (f" {v}" if v else "") for k, v in sorted(own.items())
                if k.startswith(f"bgp-vrfredist:{name}:")]
        for k in sorted(own):
            if k.startswith(f"bgp-vrfnet:{name}:"):
                n = ipaddress.IPv4Network(k.split(":", 2)[2])
                out.append(f"  network {n.network_address} mask {n.netmask}")
        out.append(" exit-address-family")
    return out


# ------------------------------------------------------------------ the console
WORDS = {("address-family", "vpnv4"): "Address family", ("bgp", "bestpath"): "Change the default bestpath selection",
         ("bgp", "cluster-id"): "Configure Route-Reflector Cluster-id",
         ("bgp", "default"): "Configure BGP defaults", ("bgp", "always-compare-med"): "Allow comparing MED from different neighbors",
         ("bgp", "deterministic-med"): "Pick the best-MED path among paths advertised from the neighboring AS",
         ("show", "ip", "bgp", "vpnv4"): "Display VPNv4 NLRI specific information"}


def add_specs(con, add, U, RM, RAF) -> None:
    from . import devcli
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    R = RM + RAF
    add("address-family vpnv4", lambda a: enter_af(con, "vpnv4"), "Address family", R)
    add("address-family vpnv4 unicast", lambda a: enter_af(con, "vpnv4"), "Address Family Modifier", R)
    add("address-family ipv4 vrf <name>", lambda a: enter_af(con, f"vrf:{a[0]}"), "Specify parameters for a VPN Routing/Forwarding instance", R)
    add("no address-family vpnv4", lambda a: no_af(con, "vpnv4"), "Negate a command or set its defaults", RM)
    add("no address-family vpnv4 unicast", lambda a: no_af(con, "vpnv4"), "Negate a command or set its defaults", RM)
    add("no address-family ipv4 vrf <name>", lambda a: no_af(con, f"vrf:{a[0]}"), "Negate a command or set its defaults", RM)
    for word, key in (("route-map", "rm"), ("prefix-list", "pl"), ("filter-list", "fl")):
        add(f"neighbor <ip> {word} <name> <name>", lambda a, k=key: nbr_policy(con, a[0], k, a[1], a[2], True),
            "Apply route map to neighbor" if key == "rm" else "Filter updates to/from this neighbor", R)
        add(f"no neighbor <ip> {word} <name> <name>", lambda a, k=key: nbr_policy(con, a[0], k, a[1], a[2], False),
            "Negate a command or set its defaults", R)
    add("neighbor <ip> send-community", lambda a: send_community(con, a[0], "standard", True), "Send Community attribute to this neighbor", R)
    add("neighbor <ip> send-community <name>", lambda a: send_community(con, a[0], a[1], True), "Send Community attribute to this neighbor", R)
    add("no neighbor <ip> send-community", lambda a: send_community(con, a[0], "standard", False), "Negate a command or set its defaults", R)
    add("no neighbor <ip> send-community <name>", lambda a: send_community(con, a[0], a[1], False), "Negate a command or set its defaults", R)
    for word, key in (("route-reflector-client", "rrc"), ("next-hop-self", "nhs"), ("fall-over bfd", "bfd")):
        add(f"neighbor <ip> {word}", lambda a, k=key: nbr_flag(con, a[0], k, "yes"), "Configure a neighbor option", R)
        add(f"no neighbor <ip> {word}", lambda a, k=key: nbr_flag(con, a[0], k, ""), "Negate a command or set its defaults", R)
    add("neighbor <ip> weight <num>", lambda a: nbr_num(con, a[0], "weight", a[1], 0, 65535), "Set default weight for routes from this neighbor", R)
    add("no neighbor <ip> weight", lambda a: nbr_flag(con, a[0], "weight", ""), "Negate a command or set its defaults", R)
    add("no neighbor <ip> weight <num>", lambda a: nbr_flag(con, a[0], "weight", ""), "Negate a command or set its defaults", R)
    add("neighbor <ip> ebgp-multihop", lambda a: nbr_num(con, a[0], "mhop", "255", 1, 255), "Allow EBGP neighbors not on directly connected networks", RM)
    add("neighbor <ip> ebgp-multihop <num>", lambda a: nbr_num(con, a[0], "mhop", a[1], 1, 255), "Allow EBGP neighbors not on directly connected networks", RM)
    add("no neighbor <ip> ebgp-multihop", lambda a: nbr_flag(con, a[0], "mhop", ""), "Negate a command or set its defaults", RM)
    add("neighbor <ip> update-source <line>", lambda a: update_source(con, a[0], a[1]), "Source of routing updates", RM)
    add("no neighbor <ip> update-source", lambda a: update_source(con, a[0], ""), "Negate a command or set its defaults", RM)
    add("no neighbor <ip> update-source <line>", lambda a: update_source(con, a[0], ""), "Negate a command or set its defaults", RM)
    add("bgp cluster-id <ip>", lambda a: router_opt(con, "bgp-cluster", _ip(a[0])), "Configure Route-Reflector Cluster-id", RM)
    add("no bgp cluster-id", lambda a: router_opt(con, "bgp-cluster", ""), "Negate a command or set its defaults", RM)
    add("no bgp cluster-id <ip>", lambda a: router_opt(con, "bgp-cluster", ""), "Negate a command or set its defaults", RM)
    add("bgp default local-preference <num>", lambda a: router_opt(con, "bgp-lp", _num(a[0], 0, 4294967295)), "local preference (higher=more preferred)", RM)
    add("no bgp default local-preference", lambda a: router_opt(con, "bgp-lp", ""), "Negate a command or set its defaults", RM)
    add("no bgp default local-preference <num>", lambda a: router_opt(con, "bgp-lp", ""), "Negate a command or set its defaults", RM)
    for words, key in (("bgp always-compare-med", "always-compare-med"), ("bgp deterministic-med", "deterministic-med"),
                       ("bgp bestpath as-path ignore", "as-path-ignore"), ("bgp bestpath med missing-as-worst", "med-missing-as-worst"),
                       ("bgp bestpath compare-routerid", "compare-routerid")):
        add(words, lambda a, k=key: router_opt(con, f"bgp-opt:{k}", "yes"), "Change the default bestpath selection", RM)
        add("no " + words, lambda a, k=key: router_opt(con, f"bgp-opt:{k}", ""), "Negate a command or set its defaults", RM)
    add("show ip bgp <ip>", lambda a: show_bgp(con, f"show ip bgp {_ip_or_net(a[0])}"), "IP prefix <network>", U)
    add("show ip bgp <ip> <mask>", lambda a: show_bgp(con, f"show ip bgp {_prefix(a[0], a[1])}"), "IP prefix <network>/<length>", U)
    add("show ip bgp neighbors <ip> advertised-routes", lambda a: show_bgp(con, f"show ip bgp neighbors {_ip(a[0])} advertised-routes"), "Display the routes advertised to a BGP neighbor", U)
    add("show ip bgp neighbors <ip> routes", lambda a: show_bgp(con, f"show ip bgp neighbors {_ip(a[0])} routes"), "Display routes learned from neighbor", U)
    add("show ip bgp neighbors <ip> received-routes", lambda a: show_bgp(con, f"show ip bgp neighbors {_ip(a[0])} routes"), "Display the received routes from neighbor", U)
    add("show ip bgp community <line>", lambda a: show_bgp(con, f"show ip bgp community {a[0]}"), "Display routes matching the communities", U)
    add("show ip bgp filter-list <name>", lambda a: show_bgp(con, f"show ip bgp filter-list {a[0]}"), "Display routes conforming to the filter-list", U)
    add("show ip bgp prefix-list <name>", lambda a: show_bgp(con, f"show ip bgp prefix-list {a[0]}"), "Display routes conforming to the prefix-list", U)
    add("show ip bgp route-map <name>", lambda a: show_bgp(con, f"show ip bgp route-map {a[0]}"), "Display routes matching the route-map", U)
    add("show ip bgp vpnv4 all", lambda a: show_bgp(con, "show bgp ipv4 vpn"), "Display information about all VPNv4 NLRIs", U)
    add("show ip bgp vpnv4 all summary", lambda a: show_bgp(con, "show bgp ipv4 vpn summary"), "Summary of BGP neighbor status", U)
    add("show ip bgp vpnv4 vrf <name>", lambda a: show_bgp(con, f"show bgp vrf {a[0]} ipv4 unicast"), "Display information for a VPN Routing/Forwarding instance", U)
    add("show ip bgp vpnv4 rd <name>", lambda a: show_bgp(con, f"show bgp ipv4 vpn rd {a[0]}"), "Display information for a route distinguisher", U)
    add("show bgp vpnv4 unicast all", lambda a: show_bgp(con, "show bgp ipv4 vpn"), "Display information about all VPNv4 NLRIs", U)
    add("show bgp vpnv4 unicast all summary", lambda a: show_bgp(con, "show bgp ipv4 vpn summary"), "Summary of BGP neighbor status", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _ip(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise _bad() from None


def _ip_or_net(text: str) -> str:
    """An address, or a prefix as A.B.C.D/len (IOS takes both after show ip bgp)."""
    if "/" not in text:
        return _ip(text)
    try:
        return str(ipaddress.IPv4Network(text))
    except ValueError:
        raise _bad() from None


def _prefix(addr: str, mask: str) -> str:
    try:
        return str(ipaddress.IPv4Network(f"{addr}/{mask}"))
    except ValueError:
        raise _bad() from None


def _num(text: str, lo: int, hi: int) -> str:
    if not text.isdigit() or not lo <= int(text) <= hi:
        raise _bad()
    return str(int(text))


def _in_bgp(con) -> None:
    if not con.s.ctx.startswith("bgp:"):
        raise _bad()


def _nbr(con, ip: str) -> tuple[dict, str]:
    _in_bgp(con)
    ip = _ip(ip)
    own = _own_c(con)
    if f"bgp-nbr:{ip}" not in own:
        raise _err("% Specify remote-as or peer-group commands first")
    return own, ip


def enter_af(con, which: str) -> str:
    _in_bgp(con)
    own = _own_c(con)
    if which.startswith("vrf:"):
        from .iosrouting import vrfs
        name = which[4:]
        if name not in vrfs(own):
            raise _err(f"%VRF {name} undefined")
        if not own.get(f"vrf:{name}"):
            raise _err(f"% VRF {name} does not have an RD configured.")
        new = f"bgp-vrf:{name}" not in own
        own[f"bgp-vrf:{name}"] = "yes"
    else:
        new = False
    con.s.mode, con.s.ctx = "config-router-af", f"{base_ctx(con.s.ctx)}:{which}"
    return _done(con) if new else (con._save(live=False) or "")


def no_af(con, which: str) -> str:
    _in_bgp(con)
    own = _own_c(con)
    if which == "vpnv4":
        keys = [k for k in own if k.startswith(("bgp-vpn:", "bgp-vpnsc:"))]
    else:
        name = which[4:]
        keys = [k for k in own if k == f"bgp-vrf:{name}" or k.startswith((f"bgp-vrfredist:{name}:",
                                                                           f"bgp-vrfnet:{name}:"))]
    for k in keys:
        del own[k]
    return _done(con) if keys else ""


def vpn_activate(con, ip: str, on: bool) -> str:
    """neighbor <ip> activate under address-family vpnv4: IOS adds
    send-community extended with it."""
    own, ip = _nbr(con, ip)
    if on:
        own[f"bgp-vpn:{ip}"] = "yes"
        own.setdefault(f"bgp-vpnsc:{ip}", "extended")
    else:
        own.pop(f"bgp-vpn:{ip}", None)
        own.pop(f"bgp-vpnsc:{ip}", None)
    return _done(con)


def _plain_af(con) -> None:
    af = sub_af(con)
    if af:
        raise _err(NO_PECE if af.startswith("vrf:") else "% Invalid input detected at '^' marker.")


def nbr_policy(con, ip: str, key: str, name: str, way: str, on: bool) -> str:
    _plain_af(con)
    own, ip = _nbr(con, ip)
    if way not in ("in", "out"):
        raise _bad()
    if not re.match(r"^[A-Za-z0-9_.-]{1,63}$", name):
        raise _bad()
    k = f"bgp-{key}{way}:{ip}"
    if on:
        own[k] = name
    elif own.pop(k, None) is None:
        return ""
    return _done(con)


def send_community(con, ip: str, kind: str, on: bool) -> str:
    kinds = [k for k in ("standard", "extended", "both") if k.startswith(kind.lower())]
    if len(kinds) != 1:
        raise _bad()
    kind = kinds[0]
    af = sub_af(con)
    if af.startswith("vrf:"):
        raise _err(NO_PECE)
    own, ip = _nbr(con, ip)
    key = f"bgp-vpnsc:{ip}" if af == "vpnv4" else f"bgp-sc:{ip}"
    have = own.get(key, "")
    want = {"": set(), "standard": {"s"}, "extended": {"e"}, "both": {"s", "e"}}[have]
    delta = {"standard": {"s"}, "extended": {"e"}, "both": {"s", "e"}}[kind]
    want = want | delta if on else want - delta
    new = {frozenset(): "", frozenset({"s"}): "standard", frozenset({"e"}): "extended",
           frozenset({"s", "e"}): "both"}[frozenset(want)]
    if new:
        own[key] = new
    else:
        own.pop(key, None)
    return _done(con)


def nbr_flag(con, ip: str, key: str, value: str) -> str:
    if key != "bfd":
        _plain_af(con)
    own, ip = _nbr(con, ip)
    if key == "rrc" and value and own.get(f"bgp-nbr:{ip}") != own.get("bgp"):
        raise _err("% Invalid command for an EBGP neighbor: a route reflector's clients are iBGP peers (same AS)")
    k = f"bgp-{key}:{ip}"
    if value:
        own[k] = value
    elif own.pop(k, None) is None:
        return ""
    note = ""
    if key == "bfd" and value:
        from . import iosbfd
        if not iosbfd.has_interval_for(con, ip):
            note = (f"% BFD: the interface towards {ip} has no bfd interval yet; the session starts once it has one "
                    "(interface ..., bfd interval 300 min_rx 300 multiplier 3)")
    done = _done(con)
    return "\n".join(x for x in (note, done) if x)


def nbr_num(con, ip: str, key: str, value: str, lo: int, hi: int) -> str:
    if key != "mhop":
        _plain_af(con)
    own, ip = _nbr(con, ip)
    own[f"bgp-{key}:{ip}"] = _num(value, lo, hi)
    return _done(con)


def update_source(con, ip: str, text: str) -> str:
    from . import iosmpls
    own, ip = _nbr(con, ip)
    if not text:
        if own.pop(f"bgp-upd:{ip}", None) is None:
            return ""
        return _done(con)
    name = iosmpls.loopback_name(text)
    if not name:
        from . import devcli
        name = devcli.parse_if(text.strip(), con._if_names(), sub=True)
    own[f"bgp-upd:{ip}"] = name
    return _done(con)


def router_opt(con, key: str, value: str) -> str:
    _in_bgp(con)
    own = _own_c(con)
    if value:
        own[key] = value
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def vrf_net(con, addr: str, mask: str, on: bool) -> str:
    from .iosrouting import _classful
    name = sub_af(con)[4:]
    try:
        net = ipaddress.IPv4Network(f"{addr}/{mask}") if mask else _classful(addr)
    except ValueError:
        raise _bad() from None
    own = _own_c(con)
    key = f"bgp-vrfnet:{name}:{net}"
    if on:
        own[key] = "yes"
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def vrf_redist(con, rest: str, on: bool) -> str:
    name = sub_af(con)[4:]
    w = rest.split()
    if not w or w[0] not in ("connected", "static"):
        raise _err("% In a VRF this router redistributes connected and static routes into BGP")
    opts = w[1:]
    keep = []
    i = 0
    while i < len(opts):
        if opts[i] in ("metric", "route-map") and i + 1 < len(opts):
            keep += opts[i:i + 2]
            i += 2
        else:
            raise _bad()
    own = _own_c(con)
    key = f"bgp-vrfredist:{name}:{w[0]}"
    if on:
        own[key] = " ".join(keep)
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


# ------------------------------------------------------------------ show ip bgp
_DROP = re.compile(r"^(RPKI validation codes|Nexthop codes|Default local pref|Displayed\s+\d+ routes|"
                   r"Total number of prefixes|\s*Last update:)")


def ios_text(text: str) -> str:
    """bgpd's show ip bgp, less what only FRRouting prints."""
    out = []
    for line in text.splitlines():
        if _DROP.match(line):
            continue
        line = re.sub(r", vrf id \d+", "", line)
        line = line.replace("Status codes:  s suppressed", "Status codes: s suppressed")
        out.append(line.rstrip())
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def show_bgp(con, cmd: str) -> str:
    from .iosrouting import _frr_note, _map_ifaces, _vtysh, bgp_as
    if not bgp_as(_own(con.lab)):
        return "% BGP not active"
    text = _vtysh(con, cmd)
    if text.strip().startswith("%") and text.strip() in ("%off", "%down", "%nofrr"):
        return _frr_note(text)
    return _map_ifaces(con, ios_text(text))
