"""Loopback interfaces, MPLS with LDP and MPLS L3VPN at the lab router's
console, made real by Linux's MPLS forwarding and FRRouting's ldpd and bgpd.

* ``interface Loopback<n>`` with ``ip address`` is a Linux dummy interface
  on the router (``wllo<n>``), always up unless shut down: an address that
  does not depend on any cable, which OSPF advertises as a host route and
  LDP and iBGP use as the router's identity.
* ``mpls ip`` on an interface turns MPLS on there: the kernel takes
  labelled packets on it (``net.mpls.conf.<dev>.input``; the router loads
  the mpls_router and mpls_iptunnel modules of its Alpine kernel and sets
  ``net.mpls.platform_labels``) and ldpd sends LDP hellos on it.
  ``mpls ldp router-id <interface> [force]`` is ldpd's router ID and
  transport address; without it, IOS's choice (the highest loopback
  address, else the highest address of an MPLS interface).
  ``mpls ldp autoconfig`` under ``router ospf`` runs LDP on every OSPF
  interface. zebra installs the labels LDP agrees into the kernel's MPLS
  table: ``show mpls forwarding-table`` reads them.
* A VRF's ``route-target import|export|both <rt>`` (with its ``rd``) is
  what MP-BGP needs for an L3VPN: winlab/iosbgpx.py writes bgpd's ``router
  bgp <as> vrf <name>`` from them, and its VPN routes travel labelled over
  the LDP path to the other PE's loopback.

The other provider edge router in the lab is rtr-edge (Ubuntu with
FRRouting from the frr pack), configured by the student with ldpd and
bgpd's own commands, as the lessons show.

Settings: ``lo:<n>`` = address/length; ``lo-desc:<n>``; ``lo-shut:<n>``;
``mpls-if:<if>`` = yes; ``mpls-rid`` = ``<interface>[ force]``;
``mpls-off`` (no mpls ip, globally); ``ospf-ldpauto:<pid>`` = yes;
``vrf-rti:<vrf>:<rt>`` / ``vrf-rte:<vrf>:<rt>`` = yes.
"""

from __future__ import annotations

import ipaddress
import json
import re

DEV = "wllo"
MODE = "config-if-lo"
LO_LIST = "/run/winlab-loopbacks"
_LO = re.compile(r"^\s*lo(?:o(?:p(?:b(?:a(?:c(?:k)?)?)?)?)?)?\s*(\d{1,9})\s*$", re.I)
_RT = re.compile(r"^(\d{1,10}:\d{1,10}|\d+\.\d+\.\d+\.\d+:\d{1,5})$")


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


# ------------------------------------------------------------------ loopbacks
def loopback_name(text: str) -> str:
    m = _LO.match(text or "")
    return f"Loopback{int(m.group(1))}" if m else ""


def loopbacks(own: dict) -> list[tuple[str, str]]:
    """(name, address/length or "") of the loopbacks, in number order."""
    out = []
    for k, v in own.items():
        if k.startswith("lo:") and k[3:].isdigit():
            out.append((int(k[3:]), f"Loopback{k[3:]}", v))
    return [(n, v) for _, n, v in sorted(out)]


def dev_of(name: str) -> str:
    return f"{DEV}{name[8:]}" if name.startswith("Loopback") else ""


def address_of(own: dict, name: str) -> str:
    """The address of an interface of the router: a loopback's here."""
    if name.startswith("Loopback"):
        v = own.get(f"lo:{name[8:]}", "")
        return v.split("/")[0] if v and not own.get(f"lo-shut:{name[8:]}") else ""
    return ""


def loopback_map(own: dict) -> dict[str, str]:
    return {name: dev_of(name) for name, _ in loopbacks(own)}


# ------------------------------------------------------------------ settings
def mpls_ifs(own: dict) -> list[str]:
    return sorted(k[8:] for k in own if k.startswith("mpls-if:"))


def active(own: dict) -> bool:
    return any(k.startswith(("lo:", "mpls-if:", "vrf-rti:", "vrf-rte:", "ospf-ldpauto:")) for k in own)


def ldp_ifaces(lab, plan) -> dict[str, str]:
    """IOS name -> device of the interfaces LDP runs on: mpls ip, and with
    mpls ldp autoconfig every OSPF interface."""
    from .iosrouting import _wild_prefix, ospf_nets, ospf_pids, svi_map
    own = _own(lab)
    if own.get("mpls-off"):
        return {}
    svis = svi_map(lab, plan)
    out = {n: svis[n] for n in mpls_ifs(own) if n in svis}
    for pid in ospf_pids(own):
        if not own.get(f"ospf-ldpauto:{pid}"):
            continue
        nets = [_wild_prefix(a, w) for a, w, _ in ospf_nets(own, pid)]
        for name, dev in svis.items():
            net = lab.networks.get(own.get(f"ip:{name}", ""))
            if net is None or own.get(f"vrf-if:{name}", "") != own.get(f"ospf:{pid}", ""):
                continue
            if own.get(f"ospf-area:{name}", "").split()[:1] == [str(pid)] or any(
                    n is not None and ipaddress.IPv4Address(net.router_ip) in n for n in nets):
                out[name] = dev
    return out


def wants_ldp(lab, plan) -> bool:
    return bool(ldp_ifaces(lab, plan)) if plan is not None else bool(mpls_ifs(_own(lab)))


def router_id(lab, plan) -> str:
    """mpls ldp router-id, or IOS's own choice: the highest loopback, else
    the highest address of an MPLS interface."""
    own = _own(lab)
    rid = own.get("mpls-rid", "").split()
    if rid:
        a = address_of(own, rid[0])
        if not a:
            net = lab.networks.get(own.get(f"ip:{rid[0]}", ""))
            a = net.router_ip if net is not None else ""
        if a:
            return a
    los = [address_of(own, n) for n, _ in loopbacks(own)]
    los = [a for a in los if a]
    if los:
        return max(los, key=lambda a: int(ipaddress.IPv4Address(a)))
    addrs = []
    for name in ldp_ifaces(lab, plan):
        net = lab.networks.get(own.get(f"ip:{name}", ""))
        if net is not None:
            addrs.append(net.router_ip)
    return max(addrs, key=lambda a: int(ipaddress.IPv4Address(a))) if addrs else ""


def rts(own: dict, vrf: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"import": [], "export": []}
    for k in sorted(own):
        if k.startswith(f"vrf-rti:{vrf}:"):
            out["import"].append(k.split(":", 2)[2])
        elif k.startswith(f"vrf-rte:{vrf}:"):
            out["export"].append(k.split(":", 2)[2])
    return out


# ------------------------------------------------------------------ the router's script
def kernel_lines(plan) -> list[str]:
    """Loopbacks as dummy interfaces; MPLS forwarding on the interfaces LDP
    runs on (before zebra starts, so it sees the kernel's MPLS)."""
    own = _own(plan.lab)
    want = [dev_of(n) for n, _ in loopbacks(own)]
    out = [f"for d in $(cat {LO_LIST} 2>/dev/null); do case \" {' '.join(want)} \" in *\" $d \"*) ;; "
           f"*) ip link del \"$d\" 2>/dev/null;; esac; done"]
    for name, addr in loopbacks(own):
        dev = dev_of(name)
        out += [f"ip link add {dev} type dummy 2>/dev/null || true", f"ip addr flush dev {dev} 2>/dev/null || true"]
        if addr:
            out.append(f"ip addr add {addr} dev {dev}   # {name}")
        out.append(f"ip link set {dev} {'down' if own.get('lo-shut:' + name[8:]) else 'up'}")
    out.append(f"echo '{' '.join(want)}' > {LO_LIST}" if want else f"rm -f {LO_LIST}")
    ldp = ldp_ifaces(plan.lab, plan)
    if ldp:
        out += ["# MPLS forwarding (Linux's mpls_router): the labels zebra installs for LDP and the VPNs",
                "modprobe mpls_router 2>/dev/null; modprobe mpls_iptunnel 2>/dev/null; modprobe mpls_gso 2>/dev/null; true",
                "[ -d /proc/sys/net/mpls ] || echo 'winlab: this kernel has no MPLS forwarding (mpls_router)' > /dev/kmsg",
                "echo 100000 > /proc/sys/net/mpls/platform_labels 2>/dev/null || true"]
        for name, dev in sorted(ldp.items(), key=lambda kv: kv[1]):
            out.append(f"echo 1 > /proc/sys/net/mpls/conf/{dev}/input 2>/dev/null || true   # {name}")
        from .iosrouting import vrfs
        for v in vrfs(own):
            out.append(f"echo 1 > /proc/sys/net/mpls/conf/{v}/input 2>/dev/null || true")
    return out


# ------------------------------------------------------------------ frr.conf
def frr_lines(plan) -> list[str]:
    ldp = ldp_ifaces(plan.lab, plan)
    if not ldp:
        return []
    rid = router_id(plan.lab, plan)
    out = ["mpls ldp"]
    if rid:
        out.append(f" router-id {rid}")
    out += [" !", " address-family ipv4"]
    if rid:
        out.append(f"  discovery transport-address {rid}")
    out += [f"  interface {dev}" for _, dev in sorted(ldp.items(), key=lambda kv: kv[1])]
    out += [" exit-address-family", "exit", "!"]
    return out


# ------------------------------------------------------------------ show running-config
def global_lines(own: dict) -> list[str]:
    out = []
    if own.get("mpls-off"):
        out.append("no mpls ip")
    if mpls_ifs(own) or own.get("mpls-rid"):
        out.append("mpls label protocol ldp")
    if own.get("mpls-rid"):
        out.append(f"mpls ldp router-id {own['mpls-rid']}")
    return out + (["!"] if out else [])


def loopback_blocks(own: dict) -> list[str]:
    out = []
    for name, addr in loopbacks(own):
        n = name[8:]
        out.append(f"interface {name}")
        if own.get(f"lo-desc:{n}"):
            out.append(f" description {own[f'lo-desc:{n}']}")
        if addr:
            i = ipaddress.IPv4Interface(addr)
            out.append(f" ip address {i.ip} {i.netmask}")
        else:
            out.append(" no ip address")
        if own.get(f"lo-shut:{n}"):
            out.append(" shutdown")
        out.append("!")
    return out


def iface_lines(own: dict, ifname: str) -> list[str]:
    return [" mpls ip"] if own.get(f"mpls-if:{ifname}") else []


def vrf_lines(own: dict, vrf: str) -> list[str]:
    t = rts(own, vrf)
    both = [r for r in t["import"] if r in t["export"]]
    out = [f" route-target both {r}" for r in both]
    out += [f" route-target export {r}" for r in t["export"] if r not in both]
    out += [f" route-target import {r}" for r in t["import"] if r not in both]
    return out


def ospf_run_lines(own: dict, pid: int) -> list[str]:
    return [" mpls ldp autoconfig"] if own.get(f"ospf-ldpauto:{pid}") else []


def brief_rows(con) -> list[str]:
    own = _own(con.lab)
    rows = []
    for name, addr in loopbacks(own):
        ip = addr.split("/")[0] if addr else "unassigned"
        st = ("administratively down", "down") if own.get(f"lo-shut:{name[8:]}") else ("up", "up")
        rows.append(f"{name:<23}{ip:<16}{'YES':<4}{'manual' if addr else 'unset':<7}{st[0]:<22}{st[1]}")
    return rows


def connected(own: dict) -> list[tuple]:
    out = []
    for name, addr in loopbacks(own):
        if addr and not own.get(f"lo-shut:{name[8:]}"):
            i = ipaddress.IPv4Interface(addr)
            out.append((i.network, name, str(i.ip)))
    return out


# ------------------------------------------------------------------ the console
WORDS = {("mpls",): "Configure MPLS parameters", ("mpls", "ip"): "Dynamic MPLS forwarding for IP",
         ("mpls", "ldp"): "Label Distribution Protocol", ("mpls", "label"): "Label properties",
         ("route-target",): "Specify Target VPN Extended Communities",
         ("show", "mpls"): "MPLS information", ("show", "mpls", "ldp"): "Show LDP information"}


def add_specs(con, add, U, C, IF, RM, VM, VAF) -> None:
    from . import devcli
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    devcli.MODE_PROMPTS[MODE] = "config-if"
    L = (MODE,)
    add("end", con._end, "Exit from configure mode", L)
    add("exit", lambda a: _exit(con), "Exit from interface configuration mode", L)
    add("do <line>", con._do, "To run exec commands in config mode", L)
    add("ip address <ip> <mask>", lambda a: lo_ip(con, a[0], a[1]), "Set the IP address of an interface", L)
    add("no ip address", lambda a: lo_ip(con, "", ""), "Negate a command or set its defaults", L)
    add("no ip address <line>", lambda a: lo_ip(con, "", ""), "Negate a command or set its defaults", L)
    add("description <line>", lambda a: lo_opt(con, "desc", a[0]), "Interface specific description", L)
    add("no description", lambda a: lo_opt(con, "desc", ""), "Negate a command or set its defaults", L)
    add("shutdown", lambda a: lo_opt(con, "shut", "yes"), "Shutdown the selected interface", L)
    add("no shutdown", lambda a: lo_opt(con, "shut", ""), "Negate a command or set its defaults", L)
    add("mpls ip", lambda a: if_mpls(con, True), "Configure dynamic MPLS forwarding for IP", IF)
    add("no mpls ip", lambda a: if_mpls(con, False), "Negate a command or set its defaults", IF)
    add("mpls ip", lambda a: glob_mpls(con, True), "Dynamic MPLS forwarding for IP", C)
    add("no mpls ip", lambda a: glob_mpls(con, False), "Negate a command or set its defaults", C)
    add("mpls label protocol ldp", lambda a: "", "Use LDP (default)", C + IF)
    add("mpls label protocol tdp", lambda a: "% TDP is not in this router: LDP is", "Use TDP", C + IF)
    add("mpls ldp router-id <name>", lambda a: ldp_rid(con, a[0], ""), "Select interface for LDP router-id", C)
    add("mpls ldp router-id <name> force", lambda a: ldp_rid(con, a[0], "force"), "Forcibly change the LDP router-id", C)
    add("no mpls ldp router-id", lambda a: ldp_rid(con, "", ""), "Negate a command or set its defaults", C)
    add("no mpls ldp router-id <line>", lambda a: ldp_rid(con, "", ""), "Negate a command or set its defaults", C)
    add("mpls ldp autoconfig", lambda a: autoconfig(con, True), "Configure LDP automatic configuration", RM)
    add("mpls ldp autoconfig <line>", lambda a: autoconfig(con, True), "Configure LDP automatic configuration", RM)
    add("no mpls ldp autoconfig", lambda a: autoconfig(con, False), "Negate a command or set its defaults", RM)
    add("no mpls ldp autoconfig <line>", lambda a: autoconfig(con, False), "Negate a command or set its defaults", RM)
    add("route-target <name> <name>", lambda a: route_target(con, a[0], a[1], True), "Specify Target VPN Extended Communities", VM + VAF)
    add("no route-target <name> <name>", lambda a: route_target(con, a[0], a[1], False), "Negate a command or set its defaults", VM + VAF)
    add("show mpls interfaces", lambda a: show_interfaces(con), "Per-interface MPLS forwarding information", U)
    add("show mpls ldp neighbor", lambda a: show_ldp_neighbor(con), "Display LDP neighbor information", U)
    add("show mpls ldp discovery", lambda a: show_ldp_discovery(con), "Display LDP discovery process information", U)
    add("show mpls ldp bindings", lambda a: show_ldp_bindings(con), "Show the LDP Label Information Base (LIB)", U)
    add("show mpls forwarding-table", lambda a: show_forwarding(con), "Show the Label Forwarding Information Base (LFIB)", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _exit(con) -> str:
    con.s.mode, con.s.ctx = "config", ""
    return ""


def enter(con, text: str) -> str:
    name = loopback_name(text)
    own = _own_c(con)
    key = f"lo:{name[8:]}"
    out = ""
    if key not in own:
        own[key] = ""
        out = (f"%LINK-3-UPDOWN: Interface {name}, changed state to up\n"
               f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to up")
    con.s.mode, con.s.ctx = MODE, name
    con._save()
    return out


def no_loopback(con, text: str) -> str:
    name = loopback_name(text)
    own = _own_c(con)
    n = name[8:]
    keys = [k for k in own if k in (f"lo:{n}", f"lo-desc:{n}", f"lo-shut:{n}")]
    for k in keys:
        del own[k]
    for k in [k for k in own if k.startswith("bgp-upd:") and own[k] == name]:
        del own[k]
    return _done(con) if keys else ""


def lo_ip(con, addr: str, mask: str) -> str:
    own = _own_c(con)
    key = f"lo:{con.s.ctx[8:]}"
    if not addr:
        own[key] = ""
        return _done(con)
    try:
        i = ipaddress.IPv4Interface(f"{addr}/{mask}")
    except ValueError:
        raise _bad() from None
    if i.network.prefixlen < 32 and i.ip == i.network.network_address:
        raise _err("% Bad mask /%d for address %s" % (i.network.prefixlen, i.ip))
    for net in con.lab.networks.values():
        if net.net.overlaps(i.network):
            raise _err(f"% {i.network} overlaps with the lab network {net.id} ({net.net})")
    for name, other in loopbacks(own):
        if name != con.s.ctx and other and ipaddress.IPv4Interface(other).network.overlaps(i.network):
            raise _err(f"% {i.network} overlaps with {name}")
    own[key] = str(i)
    return _done(con)


def lo_opt(con, what: str, value: str) -> str:
    own = _own_c(con)
    key = f"lo-{what}:{con.s.ctx[8:]}"
    if value:
        own[key] = value
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def if_mpls(con, on: bool) -> str:
    own = _own_c(con)
    key = f"mpls-if:{con.s.ctx}"
    if on:
        own[key] = "yes"
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def glob_mpls(con, on: bool) -> str:
    own = _own_c(con)
    if on:
        if own.pop("mpls-off", None) is None:
            return ""
    else:
        own["mpls-off"] = "yes"
    return _done(con)


def ldp_rid(con, text: str, force: str) -> str:
    from . import devcli
    own = _own_c(con)
    if not text:
        if own.pop("mpls-rid", None) is None:
            return ""
        return _done(con)
    name = loopback_name(text) or devcli.parse_if(text.strip(), con._if_names(), sub=True)
    own["mpls-rid"] = name + (" force" if force else "")
    note = "" if force or not ldp_ifaces(con.lab, con.plan) else \
        "% LDP: the new router ID is taken when LDP next starts (add force to take it now)"
    done = _done(con)
    return "\n".join(x for x in (note, done) if x)


def autoconfig(con, on: bool) -> str:
    kind, _, pid = con.s.ctx.partition(":")
    if kind != "ospf":
        raise _bad()
    own = _own_c(con)
    key = f"ospf-ldpauto:{pid}"
    if on:
        own[key] = "yes"
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def route_target(con, way: str, rt: str, on: bool) -> str:
    ways = [w for w in ("import", "export", "both") if w.startswith(way.lower())]
    if len(ways) != 1 or not _RT.match(rt):
        raise _bad()
    own = _own_c(con)
    vrf = con.s.ctx
    keys = {"import": [f"vrf-rti:{vrf}:{rt}"], "export": [f"vrf-rte:{vrf}:{rt}"],
            "both": [f"vrf-rti:{vrf}:{rt}", f"vrf-rte:{vrf}:{rt}"]}[ways[0]]
    for k in keys:
        if on:
            own[k] = "yes"
        else:
            own.pop(k, None)
    note = "" if own.get(f"vrf:{vrf}") or not on else \
        f"% VRF {vrf}: set an rd too: MP-BGP carries the VRF's routes only with a route distinguisher"
    done = _done(con)
    return "\n".join(x for x in (note, done) if x)


def forget_vrf(own: dict, vrf: str) -> None:
    for k in [k for k in own if k.startswith((f"vrf-rti:{vrf}:", f"vrf-rte:{vrf}:", f"bgp-vrfredist:{vrf}:",
                                              f"bgp-vrfnet:{vrf}:")) or k == f"bgp-vrf:{vrf}"]:
        del own[k]


def forget_pid(own: dict, pid: int) -> None:
    own.pop(f"ospf-ldpauto:{pid}", None)


# ------------------------------------------------------------------ show mpls
def _read(con, *cmds: str) -> str | None:
    from .iosrouting import _frr_note, _vtysh
    if not ldp_ifaces(con.lab, con.plan):
        return None
    text = _vtysh(con, *cmds)
    if text.strip().startswith("%"):
        return _frr_note(text) or ""
    return text


def _rev(con) -> dict[str, str]:
    from .iosrouting import svi_map
    out = {dev: name for name, dev in svi_map(con.lab, con.plan).items()}
    out.update({dev: name for name, dev in loopback_map(_own(con.lab)).items()})
    return out


def show_interfaces(con) -> str:
    own = _own(con.lab)
    ldp = ldp_ifaces(con.lab, con.plan)
    if not ldp:
        return ""
    out = [f"{'Interface':<23}{'IP':<15}{'Tunnel':<9}{'BGP':<4}{'Static':<7}Operational"]
    for name, net, up in con.router_ifaces():
        if name not in ldp:
            continue
        oper = "Yes" if con._router_status(name, up)[1] == "up" else "No"
        out.append(f"{name:<23}{'Yes (ldp)':<15}{'No':<9}{'No':<4}{'No':<7}{oper}")
    return "\n".join(out)


_NBR = re.compile(r"^ipv4\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)")
_DISC = re.compile(r"^ipv4\s+(\d+\.\d+\.\d+\.\d+)\s+(Link|Targeted)\s+(\S+)\s+(\d+)$", re.I)
_BIND = re.compile(r"^ipv4\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)")


def parse_ldp_neighbors(text: str) -> list[dict]:
    """ldpd's show mpls ldp neighbor: AF, ID, State, Remote Address, Uptime."""
    out = []
    for line in (text or "").splitlines():
        m = _NBR.match(line.strip())
        if m:
            out.append({"id": m.group(1), "state": m.group(2), "addr": m.group(3), "uptime": m.group(4)})
    return out


def parse_discovery(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        m = _DISC.match(line.strip())
        if m:
            out.append({"id": m.group(1), "type": m.group(2), "source": m.group(3), "hold": m.group(4)})
    return out


def parse_bindings(text: str) -> list[dict]:
    """ldpd's show mpls ldp binding: AF, Destination, Nexthop, Local Label,
    Remote Label, In Use."""
    out = []
    for line in (text or "").splitlines():
        m = _BIND.match(line.strip())
        if m:
            out.append({"prefix": m.group(1), "nexthop": m.group(2), "local": m.group(3), "remote": m.group(4),
                        "inuse": m.group(5).lower() == "yes"})
    return out


def show_ldp_neighbor(con) -> str:
    text = _read(con, "show mpls ldp neighbor", "show mpls ldp discovery")
    if not text:
        return text or ""
    rid = router_id(con.lab, con.plan) or "0.0.0.0"
    disc = parse_discovery(text)
    rev = _rev(con)
    out = []
    for n in parse_ldp_neighbors(text):
        st = "Oper" if n["state"].upper() == "OPERATIONAL" else n["state"].capitalize()
        out += [f"    Peer LDP Ident: {n['id']}:0; Local LDP Ident {rid}:0",
                f"\tTCP connection: {n['addr']}.646 - {rid}",
                f"\tState: {st}; Downstream",
                f"\tUp time: {n['uptime']}",
                "\tLDP discovery sources:"]
        out += [f"\t  {rev.get(d['source'], d['source'])}" for d in disc if d["id"] == n["id"]]
    return "\n".join(out)


def show_ldp_discovery(con) -> str:
    text = _read(con, "show mpls ldp discovery")
    if not text:
        return text or ""
    rid = router_id(con.lab, con.plan) or "0.0.0.0"
    rev = _rev(con)
    out = [" Local LDP Identifier:", f"    {rid}:0", "    Discovery Sources:", "    Interfaces:"]
    for d in parse_discovery(text):
        out += [f"\t{rev.get(d['source'], d['source'])} (ldp): xmit/recv", f"\t    LDP Id: {d['id']}:0"]
    return "\n".join(out)


def _label(v: str) -> str:
    return {"imp-null": "imp-null", "exp-null": "exp-null", "-": "-"}.get(v, v)


def show_ldp_bindings(con) -> str:
    text = _read(con, "show mpls ldp binding")
    if not text:
        return text or ""
    rows: dict[str, dict] = {}
    for b in parse_bindings(text):
        r = rows.setdefault(b["prefix"], {"local": b["local"], "remote": []})
        if b["remote"] not in ("-", ""):
            r["remote"].append((b["nexthop"], b["remote"]))
    out = []
    for prefix, r in sorted(rows.items(), key=lambda kv: (int(ipaddress.IPv4Network(kv[0]).network_address),
                                                          ipaddress.IPv4Network(kv[0]).prefixlen)):
        out += [f"  lib entry: {prefix}, rev 1", f"\tlocal binding:  label: {_label(r['local'])}"]
        out += [f"\tremote binding: lsr: {lsr}:0, label: {_label(lbl)}" for lsr, lbl in r["remote"]]
    return "\n".join(out)


def parse_mpls_table(text: str) -> dict[int, list[dict]]:
    """zebra's show mpls table json: in label -> its next hops (out label,
    address, device)."""
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out: dict[int, list[dict]] = {}
    if not isinstance(data, dict):
        return out
    for k, v in data.items():
        if not isinstance(v, dict):
            continue
        try:
            inl = int(v.get("inLabel", k))
        except (TypeError, ValueError):
            continue
        hops = []
        for h in v.get("nexthops", []) if isinstance(v.get("nexthops"), list) else []:
            outl = h.get("outLabel", h.get("outLabelStack", [""])[0] if h.get("outLabelStack") else "")
            hops.append({"out": outl, "ip": h.get("nexthop", ""), "dev": h.get("interface", ""),
                         "type": h.get("type", "")})
        out[inl] = hops
    return out


def show_forwarding(con) -> str:
    text = _read(con, "show mpls ldp binding")
    if text is None:
        return ""
    if not text:
        return ""
    from .iosrouting import _vtysh
    table = parse_mpls_table(_vtysh(con, "show mpls table json"))
    rev = _rev(con)
    from . import devcli
    by_local = {}
    for b in parse_bindings(text):
        if b["local"].isdigit():
            by_local.setdefault(int(b["local"]), b["prefix"])
    out = [f"{'Local':<11}{'Outgoing':<11}{'Prefix':<17}{'Bytes Label':<14}{'Outgoing':<11}Next Hop",
           f"{'Label':<11}{'Label':<11}{'or Tunnel Id':<17}{'Switched':<14}{'interface':<11}"]
    for inl in sorted(set(table) | set(by_local)):
        hops = table.get(inl) or [{"out": "", "ip": "", "dev": "", "type": ""}]
        prefix = by_local.get(inl, "")
        for h in hops:
            o = str(h["out"])
            outl = "Pop Label" if o in ("3", "implicit-null") else ("No Label" if o in ("", "None") else o)
            dev = devcli.short_if(rev.get(h["dev"], h["dev"])) if h["dev"] else ""
            out.append(f"{inl:<11}{outl:<11}{(prefix or ('VPN route' if h['type'].upper().startswith('BGP') else '')):<17}"
                       f"{'0':<14}{dev:<11}{h['ip']}")
    return "\n".join(out)
