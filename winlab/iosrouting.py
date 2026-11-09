"""The lab router as a router that talks to other routers: OSPF, EIGRP and BGP
typed at its console, VRFs (VRF-lite) that keep networks apart, and VRRP and
HSRP with a second gateway.

Everything typed is kept with the router's other settings in the lab file
([devices."router"]) and is made real on the router (the Alpine VM that is
the lab's switches and router) by what render() writes, which
winlab/netplan.py runs at its start; live_script() brings a running router
in line when a command changes it (winlab/livenet.py):

* ``router ospf``, ``router bgp`` and ``vrrp`` on an interface become an
  FRRouting configuration, /etc/frr/frr.conf, written whole from the
  console's settings. FRRouting (zebra, ospfd, bgpd, vrrpd) is the same
  routing suite the Ubuntu routers of winlab/routing.py run, so the lab
  router peers with them as one router with another: real hellos, real
  OPEN messages, real VRRP advertisements on the wire. It is installed from
  the lab's own Alpine package volume the first time the console asks for
  it (alpineovl.APPLIANCE_PACKAGES), never from the Internet. A change to a
  running router is applied as FRRouting's own commands (the lines that
  went away removed with ``no``, then the file read again), so an
  adjacency survives a new ``network`` line, as on IOS;
* ``vrf definition`` / ``ip vrf`` is a Linux VRF device with a routing
  table of its own, and ``vrf forwarding`` on an interface enslaves that
  interface's SVI to it: the network's connected route moves out of the
  main table, so it is routed only with the networks in the same VRF;
* ``router eigrp`` is FRRouting's eigrpd (winlab/ioseigrp.py, which says
  what eigrpd lacks: it is alpha by its own project's word, with no stub,
  no redistribution, no authentication, no named mode), routes at distance
  90 beside OSPF's 110;
* ``standby`` (HSRP) is winlab's own HSRP speaker, winlab-hsrpd
  (winlab/hsrpd.py, winlab/ioshsrp.py): no open-source router speaks HSRP,
  so winlab wrote one from the published packet formats; rtr-edge runs the
  same speaker, and on real gear both ends would be Cisco routers;
* ``show ip route`` reads the routes zebra selected (``vtysh -c 'show ip
  route json'``) beside the connected and static ones, and ``show ip ospf
  neighbor``, ``show ip eigrp neighbors``, ``show ip bgp summary``, ``show
  vrrp`` and ``show standby`` read the daemons.

What is not here, and why:

* More than one OSPF process in one VRF: FRRouting's ospfd runs one
  instance per VRF, so a second ``router ospf <pid>`` there is refused
  with that reason, and the process number is the console's own label.
* Overlapping addresses in two VRFs: winlab gives every network of a lab
  its own subnet (the console refuses an overlapping ``ip address``), so a
  VRF here separates routing, not address plans.

Settings (``<if>`` an IOS interface name, ``<pid>`` an OSPF process):
``ospf:<pid>`` = its VRF ("" for the global table); ``ospf-rid:<pid>``;
``ospf-net:<pid>:<address> <wildcard>`` = area; ``ospf-pasdef:<pid>``;
``ospf-pas:<pid>:<if>`` = yes | no; ``ospf-dio:<pid>`` = what follows
``default-information originate``; ``ospf-redist:<pid>:<source>`` = its
options; ``ospf-log:<pid>``; ``ospf-cost:<if>``, ``ospf-prio:<if>``,
``ospf-hello:<if>``, ``ospf-dead:<if>``, ``ospf-p2p:<if>``,
``ospf-area:<if>`` = ``<pid> <area>``. ``bgp`` = the AS; ``bgp-rid``;
``bgp-nbr:<ip>`` = remote AS; ``bgp-desc:<ip>``; ``bgp-shut:<ip>``;
``bgp-noact:<ip>``; ``bgp-dorig:<ip>``; ``bgp-net:<prefix>``;
``bgp-redist:<source>``; ``bgp-log``. ``vrf:<name>`` = route
distinguisher; ``vrf-kind:<name>`` = definition | ip; ``vrf-af:<name>``;
``vrf-desc:<name>``; ``vrf-table:<name>`` = its kernel table;
``vrf-if:<if>`` = the VRF; ``vroute:<vrf> <prefix> <target>`` = distance.
``vrrp:<if>:<group>`` = virtual address; ``vrrp-prio:<if>:<group>``;
``vrrp-nopre:<if>:<group>``; ``vrrp-adv:<if>:<group>``;
``vrrp-desc:<if>:<group>``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex

FRR_CONF = "/etc/frr/frr.conf"
FRR_DAEMONS = "/etc/frr/daemons"
FRR_INIT = "/usr/lib/frr/frrinit.sh"
VRF_LIST = "/run/winlab-vrfs"
VRRP_LIST = "/run/winlab-vrrp"
VROUTE_PROTO = 121   # not one of FRRouting's (11, 186-198): zebra would sweep it
TABLE_BASE = 1001
DAEMONS = ("bgpd", "ospfd", "ospf6d", "ripd", "ripngd", "isisd", "pimd", "ldpd", "nhrpd", "eigrpd",
           "babeld", "sharpd", "pbrd", "bfdd", "fabricd", "vrrpd", "pathd")
_VRF_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,14}$")
# Names the router's own devices have: a VRF may not take one.
_TAKEN = re.compile(r"^(lab0|lo|eth\d|stp|vr\d|wl|br|bond|dummy|gre|tun|sit|ip6)", re.I)
_IP = re.compile(r"^\d+\.\d+\.\d+\.\d+$")



def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


# ------------------------------------------------------------------ settings
def _own(lab) -> dict:
    return lab.devices.get("router", {})


def ospf_pids(own: dict) -> list[int]:
    return sorted(int(k[5:]) for k in own if k.startswith("ospf:") and k[5:].isdigit())


def ospf_nets(own: dict, pid: int) -> list[tuple[str, str, str]]:
    """(address, wildcard, area) of a process's network statements."""
    out = []
    for k, v in own.items():
        if k.startswith(f"ospf-net:{pid}:"):
            addr, _, wild = k.split(":", 2)[2].partition(" ")
            out.append((addr, wild, v))
    return sorted(out, key=lambda r: (int(ipaddress.IPv4Address(r[0])), r[1]))


def bgp_as(own: dict) -> str:
    return own.get("bgp", "")


def bgp_nbrs(own: dict) -> list[str]:
    return sorted((k[8:] for k in own if k.startswith("bgp-nbr:")), key=lambda a: int(ipaddress.IPv4Address(a)))


def bgp_nets(own: dict) -> list[ipaddress.IPv4Network]:
    return sorted((ipaddress.IPv4Network(k[8:]) for k in own if k.startswith("bgp-net:")),
                  key=lambda n: (int(n.network_address), n.prefixlen))


def vrfs(own: dict) -> list[str]:
    return sorted(k[4:] for k in own if k.startswith("vrf:"))


def vrf_of(own: dict, ifname: str) -> str:
    return own.get(f"vrf-if:{ifname}", "")


def vrrp_groups(own: dict, ifname: str = "") -> list[tuple[str, int, str]]:
    """(interface, group, virtual address)."""
    out = []
    for k, v in own.items():
        if k.startswith("vrrp:"):
            name, _, grp = k[5:].rpartition(":")
            if (not ifname or name == ifname) and grp.isdigit():
                out.append((name, int(grp), v))
    return sorted(out)


def vroutes(own: dict) -> list[tuple[str, ipaddress.IPv4Network, str, int]]:
    """(vrf, network, next hop or interface, distance) of ip route vrf."""
    out = []
    for k, v in own.items():
        if k.startswith("vroute:"):
            vrf, net, target = (k[7:].split(" ") + ["", ""])[:3]
            try:
                out.append((vrf, ipaddress.IPv4Network(net), target, int(v or 1)))
            except ValueError:
                continue
    return sorted(out, key=lambda r: (r[0], int(r[1].network_address), r[1].prefixlen, r[2]))


def active(lab) -> bool:
    """Whether the console has anything of this module's: routing protocols,
    VRFs, VRRP."""
    from . import ioseigrp, ioshsrp, iossla, iosv6  # IPv6 typed at the console: addresses, RAs, static routes, OSPFv3
    own = _own(lab)
    return (any(k.startswith(("ospf:", "vrf:", "vrrp:", "vroute:")) or k == "bgp" for k in own) or iosv6.active(own)
            or ioseigrp.active(own) or ioshsrp.active(own) or iossla.active(own) or _more_active(own))


def _more_active(own: dict) -> bool:
    """GLBP (winlab's own speaker), PIM and IS-IS (FRRouting's pimd, isisd)."""
    from . import iosglbp, iosisis, iospim
    from . import iosbfd, iosmpls, iosrpolicy  # BFD, loopbacks and MPLS, route-maps and prefix-lists
    return (iosglbp.active(own) or iospim.active(own) or iosisis.active(own) or iosmpls.active(own)
            or iosrpolicy.active(own) or iosbfd.active(own))


def wants_frr(own: dict) -> bool:
    from . import ioseigrp, iosv6
    from . import iosisis, iospim
    return (bool(ospf_pids(own) or bgp_as(own) or any(k.startswith("vrrp:") for k in own)) or iosv6.wants_frr(own)
            or ioseigrp.active(own) or iosisis.active(own) or iospim.runs(own)
            or any(k.startswith(("mpls-if:", "ospf-ldpauto:")) for k in own))


def _wild_prefix(addr: str, wild: str) -> ipaddress.IPv4Network | None:
    """'10.80.0.0 0.0.0.255' -> 10.80.0.0/24, None for a wildcard with holes."""
    try:
        care = ~int(ipaddress.IPv4Address(wild)) & 0xFFFFFFFF
        a = ipaddress.IPv4Address(addr)
    except ValueError:
        return None
    n = bin(care).count("1")
    if care != (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF:
        return None
    return ipaddress.IPv4Network(f"{ipaddress.IPv4Address(int(a) & care)}/{n}")


def _classful(addr: str) -> ipaddress.IPv4Network:
    a = ipaddress.IPv4Address(addr)
    first = int(addr.split(".")[0])
    plen = 8 if first < 128 else 16 if first < 192 else 24
    return ipaddress.IPv4Network(f"{a}/{plen}", strict=False)


def _area(text: str) -> str:
    """An OSPF area as IOS takes it: a number or a dotted quad."""
    if text.isdigit() and int(text) <= 4294967295:
        return text
    if _IP.match(text):
        return str(ipaddress.IPv4Address(text))
    raise _err("% Invalid input detected at '^' marker.")


# ------------------------------------------------------------------ the router's interfaces
def svi_map(lab, plan) -> dict[str, str]:
    """IOS interface name -> the router's Linux device, for the ones that
    route a network now."""
    from . import devcli, iosl3
    out = {}
    own = _own(lab)
    names = set(devcli.router_port_names(lab))
    names |= {k.split(":", 1)[1] for k in own if k.startswith(("sub:", "dot1q:", "ip:"))}
    for name in sorted(names):
        dev = iosl3.svi_for(lab, plan, name)
        if dev:
            out[name] = dev
    return out


def _macvlan(dev: str, grp: int) -> str:
    vid = dev.split(".")[-1]
    return f"vr{vid}x{grp}"[:15]


def vmac(grp: int) -> str:
    return f"00:00:5e:00:01:{grp:02x}"


# ------------------------------------------------------------------ FRRouting's configuration
def _redist(src: str, opts: str, ospf: bool) -> str:
    """IOS's redistribute source, as FRRouting names it: the console's
    static routes are kernel routes on the router (winlab/iosl3.py), so
    'static' is FRRouting's 'kernel'."""
    w = src.split()
    proto = {"static": "kernel", "connected": "connected", "ospf": "ospf", "bgp": "bgp", "eigrp": "eigrp"}[w[0]]
    line = f"redistribute {proto}"
    m = re.search(r"\bmetric (\d+)", opts)
    if m:
        line += f" metric {m.group(1)}"
    if ospf:
        t = re.search(r"\bmetric-type ([12])", opts)
        if t:
            line += f" metric-type {t.group(1)}"
    r = re.search(r"\broute-map (\S+)", opts)
    if r:
        line += f" route-map {r.group(1)}"
    return line


def frr_conf(plan) -> str:
    """/etc/frr/frr.conf from the console's settings; "" when the router
    runs no routing protocol and no VRRP."""
    from . import devcli, iosv6
    lab = plan.lab
    own = _own(lab)
    if not wants_frr(own):
        return ""
    svis = svi_map(lab, plan)
    out = ["! generated by winlab from the router's console (winlab/iosrouting.py)",
           "frr defaults traditional", f"hostname {devcli.ios_name(lab, devcli.ROUTER)}",
           "log syslog informational", "service integrated-vtysh-config", "!"]
    from . import iosospfauth  # key chains first: the interfaces name them
    out += iosospfauth.frr_keychain_lines(own)
    from . import iosbfd, iosbgpx, iosmpls, iosospfx, iosrpolicy  # BFD, BGP policy and VPNs, MPLS, OSPF areas
    out += iosbfd.frr_lines(plan)
    pids = ospf_pids(own)
    for name, dev in sorted(svis.items(), key=lambda kv: kv[1]):
        body = []
        if pids:
            if own.get(f"ospf-area:{name}"):
                body.append(f" ip ospf area {own[f'ospf-area:{name}'].split()[1]}")
            for key, word in (("cost", "cost"), ("prio", "priority"), ("hello", "hello-interval"),
                              ("dead", "dead-interval")):
                if own.get(f"ospf-{key}:{name}"):
                    body.append(f" ip ospf {word} {own[f'ospf-{key}:{name}']}")
            if own.get(f"ospf-p2p:{name}"):
                body.append(" ip ospf network point-to-point")
            body += iosospfauth.frr_iface_lines(own, name)
            body += iosbfd.frr_iface_lines(own, name, dev)
            for pid in pids:
                if own.get(f"ospf:{pid}", "") != vrf_of(own, name):
                    continue
                pas = own.get(f"ospf-pas:{pid}:{name}", "")
                if pas == "yes" and not own.get(f"ospf-pasdef:{pid}"):
                    body.append(" ip ospf passive")
                elif pas == "no" and own.get(f"ospf-pasdef:{pid}"):
                    body.append(" no ip ospf passive")
        for _, grp, vip in vrrp_groups(own, name):
            body.append(f" vrrp {grp} version 2")
            if own.get(f"vrrp-prio:{name}:{grp}"):
                body.append(f" vrrp {grp} priority {own[f'vrrp-prio:{name}:{grp}']}")
            if own.get(f"vrrp-adv:{name}:{grp}"):
                body.append(f" vrrp {grp} advertisement-interval {int(own[f'vrrp-adv:{name}:{grp}']) * 1000}")
            if own.get(f"vrrp-nopre:{name}:{grp}"):
                body.append(f" no vrrp {grp} preempt")
            body.append(f" vrrp {grp} ip {vip}")
        body += iosv6.frr_iface_lines(own, name)
        if body:
            out += [f"interface {dev}"] + body + ["exit", "!"]
    for pid in pids:
        vrf = own.get(f"ospf:{pid}", "")
        out.append("router ospf" + (f" vrf {vrf}" if vrf else ""))
        if own.get(f"ospf-rid:{pid}"):
            out.append(f" ospf router-id {own[f'ospf-rid:{pid}']}")
        if own.get(f"ospf-log:{pid}"):
            out.append(" log-adjacency-changes")
        if own.get(f"ospf-pasdef:{pid}"):
            out.append(" passive-interface default")
        out += iosospfauth.frr_area_lines(own, pid)
        out += iosospfx.frr_lines(own, pid)
        for addr, wild, area in ospf_nets(own, pid):
            net = _wild_prefix(addr, wild)
            if net is not None:
                out.append(f" network {net} area {area}")
        for k, v in sorted(own.items()):
            if k.startswith(f"ospf-redist:{pid}:"):
                out.append(" " + _redist(k.split(":", 2)[2], v, True))
        if f"ospf-dio:{pid}" in own:
            dio = own[f"ospf-dio:{pid}"]
            line = " default-information originate"
            line += " always" if "always" in dio.split() else ""
            m = re.search(r"\bmetric (\d+)", dio)
            line += f" metric {m.group(1)}" if m else ""
            t = re.search(r"\bmetric-type ([12])", dio)
            line += f" metric-type {t.group(1)}" if t else ""
            out.append(line)
        out += ["exit", "!"]
    from . import ioseigrp  # router eigrp, then its interface lines (eigrpd wants that order)
    out += ioseigrp.frr_lines(plan)
    from . import iosisis, iospim  # router isis then its interfaces (isisd); PIM's RPs and interfaces (pimd)
    out += iosisis.frr_lines(plan)
    out += iospim.frr_lines(plan)
    asn = bgp_as(own)
    if asn:
        out.append(f"router bgp {asn}")
        if own.get("bgp-rid"):
            out.append(f" bgp router-id {own['bgp-rid']}")
        if own.get("bgp-log"):
            out.append(" bgp log-neighbor-changes")
        # IOS sends and takes eBGP routes with no policy; FRRouting, by
        # RFC 8212, refuses to without one unless told otherwise.
        out.append(" no bgp ebgp-requires-policy")
        # and, as IOS does, announces a network only when exactly it is in the table
        out.append(" bgp network import-check")
        out += iosbgpx.frr_global(own)
        for ip in bgp_nbrs(own):
            out.append(f" neighbor {ip} remote-as {own[f'bgp-nbr:{ip}']}")
            if own.get(f"bgp-desc:{ip}"):
                out.append(f" neighbor {ip} description {own[f'bgp-desc:{ip}']}")
            if own.get(f"bgp-shut:{ip}"):
                out.append(f" neighbor {ip} shutdown")
            out += iosbgpx.frr_nbr_global(own, plan, ip)
        af = [f"  network {n}" for n in bgp_nets(own)]
        af += ["  " + _redist(k[11:], v, False) for k, v in sorted(own.items()) if k.startswith("bgp-redist:")]
        for ip in bgp_nbrs(own):
            if own.get(f"bgp-noact:{ip}"):
                af.append(f"  no neighbor {ip} activate")
            if own.get(f"bgp-dorig:{ip}"):
                af.append(f"  neighbor {ip} default-originate")
            af += iosbgpx.frr_nbr_af(own, ip)
        if af:
            out += [" !", " address-family ipv4 unicast"] + af + [" exit-address-family"]
        out += iosbgpx.frr_extra_afs(own, bgp_nbrs(own))
        out += ["exit", "!"]
        out += iosbgpx.frr_vrf_blocks(own)
    out += iosmpls.frr_lines(plan)
    out += iosrpolicy.frr_lines(own)
    out += iosv6.frr_global_lines(plan)
    return "\n".join(out) + "\n"


def daemons_file(own: dict) -> str:
    from . import ioseigrp, iosisis, iospim, iosv6
    on = {"ospfd": bool(ospf_pids(own)), "bgpd": bool(bgp_as(own)), "eigrpd": ioseigrp.active(own),
          "vrrpd": any(k.startswith("vrrp:") for k in own), "ospf6d": bool(iosv6.ospf_pids(own)),
          "isisd": iosisis.active(own), "pimd": iospim.runs(own),
          "bfdd": any(k.startswith("bfd-if:") for k in own),
          "ldpd": not own.get("mpls-off") and any(k.startswith(("mpls-if:", "ospf-ldpauto:")) for k in own)}
    lines = ["# generated by winlab (winlab/iosrouting.py): the daemons the router's console needs"]
    lines += [f"{d}={'yes' if on.get(d) else 'no'}" for d in DAEMONS]
    lines += ["vtysh_enable=yes", 'zebra_options="  -A 127.0.0.1 -s 90000000"',
              'mgmtd_options="  -A 127.0.0.1"', 'staticd_options="-A 127.0.0.1"']
    lines += [f'{d}_options="  -A 127.0.0.1"' for d in ("bgpd", "ospfd", "ospf6d", "vrrpd", "eigrpd", "isisd", "pimd",
                                                                "bfdd", "ldpd")]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ the router's script
def _vrf_lines(plan) -> list[str]:
    """The VRF devices and which SVI is in which; idempotent, so a running
    router's routes stay where they are when nothing about them changed."""
    lab = plan.lab
    own = _own(lab)
    names = vrfs(own)
    svis = svi_map(lab, plan)
    if not names and not any(k.startswith("vrf-if:") for k in own):
        return [f"for v in $(cat {VRF_LIST} 2>/dev/null); do ip link del \"$v\" 2>/dev/null; done; rm -f {VRF_LIST}"]
    out = ["# a socket in the main table answers on a VRF's interfaces too (DHCP, the console's ping)",
           "for k in tcp udp raw; do echo 1 > /proc/sys/net/ipv4/${k}_l3mdev_accept 2>/dev/null; done; true",
           f"old=\"$(cat {VRF_LIST} 2>/dev/null)\"",
           f"for v in $old; do case \" {' '.join(names)} \" in *\" $v \"*) ;; *) ip link del \"$v\" 2>/dev/null;; esac; done"]
    for name in names:
        table = own.get(f"vrf-table:{name}", TABLE_BASE)
        out += [f"ip link add {name} type vrf table {table} 2>/dev/null || true",
                f"ip link set {name} up",
                # A lookup that finds nothing in the VRF's table must stop there, not
                # fall through to the main table (the kernel's VRF documentation).
                f"ip route replace unreachable default metric 4278198272 table {table} 2>/dev/null || true"]
    out.append(f"echo '{' '.join(names)}' > {VRF_LIST}")
    for ifname, dev in sorted(svis.items(), key=lambda kv: kv[1]):
        vrf = vrf_of(own, ifname)
        if vrf in names:
            out.append(f"ip link set {dev} master {vrf}   # {ifname} in VRF {vrf}")
        else:
            out.append(f"m=$(ip -o link show dev {dev} 2>/dev/null | sed -n 's/.* master \\([^ ]*\\) .*/\\1/p'); "
                       f"case \" $old {' '.join(names)} \" in *\" $m \"*) [ -n \"$m\" ] && ip link set {dev} nomaster;; esac")
    tables = sorted({own.get(f"vrf-table:{n}", str(TABLE_BASE)) for n in names})
    for t in tables:
        out.append(f"ip route flush table {t} proto {VROUTE_PROTO} 2>/dev/null || true")
    for vrf, net, target, dist in vroutes(own):
        if vrf not in names:
            continue
        table = own.get(f"vrf-table:{vrf}", TABLE_BASE)
        if _IP.match(target):
            how = f"via {target}"
        else:
            dev = svis.get(target)
            if not dev or vrf_of(own, target) != vrf:
                out.append(f"# ip route vrf {vrf} {net} {target}: {target} is not up in {vrf}, not installed")
                continue
            how = f"dev {dev}"
        out.append(f"ip route replace {net} {how} table {table} proto {VROUTE_PROTO} metric {dist} 2>/dev/null || true")
    return out


def _vrrp_lines(plan) -> list[str]:
    """Each VRRP group's virtual interface (a macvlan with the group's
    virtual MAC, holding the virtual address), as FRRouting's vrrpd uses it:
    it brings the interface up when this router is master and holds it
    down (protodown) when it is backup."""
    lab = plan.lab
    own = _own(lab)
    svis = svi_map(lab, plan)
    want = []
    out = []
    for ifname, grp, vip in vrrp_groups(own):
        dev = svis.get(ifname)
        if not dev:
            out.append(f"# vrrp {grp} on {ifname}: the interface is down, no virtual router")
            continue
        net = ipaddress.IPv4Interface(f"{vip}/{plan.lab.networks[_net_id(own, ifname)].prefixlen}") \
            if _net_id(own, ifname) in plan.lab.networks else None
        if net is None:
            continue
        mv = _macvlan(dev, grp)
        want.append(mv)
        vrf = vrf_of(own, ifname)
        out += [f"ip link add {mv} link {dev} addrgenmode random type macvlan mode bridge 2>/dev/null || true",
                f"ip link set dev {mv} address {vmac(grp)}",
                f"ip addr replace {net} dev {mv}"]
        out += [f"ip link set dev {mv} master {vrf}"] if vrf in vrfs(own) else []
        out += [f"ip link set dev {mv} up",
                # The real interface must not answer ARP for the virtual
                # address: the virtual MAC does, from whichever router is master.
                f"echo 1 > /proc/sys/net/ipv4/conf/{dev}/arp_ignore 2>/dev/null || true"]
    clean = (f"for m in $(cat {VRRP_LIST} 2>/dev/null); do case \" {' '.join(want)} \" in *\" $m \"*) ;; "
             f"*) ip link del \"$m\" 2>/dev/null;; esac; done")
    return [clean] + out + ([f"echo '{' '.join(want)}' > {VRRP_LIST}"] if want else [f"rm -f {VRRP_LIST}"])


def _net_id(own: dict, ifname: str) -> str:
    return own.get(f"ip:{ifname}", "")


def _write_files(conf: str, daemons: str) -> list[str]:
    return ["mkdir -p /etc/frr",
            f"cat > {FRR_DAEMONS} <<'WLFRRD'\n{daemons}WLFRRD",
            f"cat > {FRR_CONF} <<'WLFRR'\n{conf}WLFRR",
            ": > /etc/frr/vtysh.conf; echo 'service integrated-vtysh-config' > /etc/frr/vtysh.conf",
            "chown -R frr:frr /etc/frr 2>/dev/null || true"]


INSTALL = ("command -v vtysh >/dev/null 2>&1 || apk add --no-network frr >/dev/null 2>&1 || "
           "echo 'winlab: FRRouting is not on the package volume (winlab images prepare fabric)' > /dev/kmsg")


def render(plan, reset: bool = False) -> list[str]:
    """The router's start script: VRFs, VRRP's virtual interfaces, and
    FRRouting started on the configuration the console has. Empty when
    nothing is set and nothing must be undone."""
    own = _own(plan.lab)
    if not active(plan.lab) and not reset:
        return []
    out = ["", "### OSPF, EIGRP, BGP, VRFs, VRRP and HSRP as typed at the router's console (winlab/iosrouting.py)"]
    out += _vrf_lines(plan)
    out += _vrrp_lines(plan)
    from . import ioshsrp, iossla  # winlab's own HSRP speaker (winlab/hsrpd.py), IP SLA (winlab/slad.py)
    out += iossla.router_lines(plan)
    out += ioshsrp.router_lines(plan)
    from . import iosglbp  # winlab's own GLBP speaker (winlab/glbpd.py)
    out += iosglbp.router_lines(plan)
    from . import iosv6  # IPv6 forwarding and addresses, before zebra reads the interfaces
    out += iosv6.kernel_lines(plan, reset)
    from . import iosmpls  # loopbacks, and MPLS forwarding before zebra starts
    out += iosmpls.kernel_lines(plan)
    conf = frr_conf(plan)
    if conf:
        out += [INSTALL] + _write_files(conf, daemons_file(own))
        out.append(f"{FRR_INIT} restart >/dev/null 2>&1 || true")
    else:
        out.append(f"[ -x {FRR_INIT} ] && {FRR_INIT} stop >/dev/null 2>&1 || true")
    out.append("")
    return out


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


# ---- a running router: FRRouting's own commands for what changed
def _tree(text: str) -> list[tuple[str, ...]]:
    """frr.conf as paths: ('router bgp 65000', 'address-family ipv4 unicast',
    'network 10.0.0.0/24'), in order; comments, '!' and exits dropped."""
    out: list[tuple[str, ...]] = []
    stack: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("!") or raw.strip() in ("exit", "exit-address-family",
                                                                             "exit-vrf", "end"):
            if raw.strip() in ("exit", "exit-vrf"):
                stack = []
            elif raw.strip() == "exit-address-family":
                stack = stack[:1]
            continue
        depth = len(raw) - len(raw.lstrip(" "))
        while stack and stack[-1][0] >= depth:
            stack.pop()
        path = tuple(s for _, s in stack) + (raw.strip(),)
        out.append(path)
        if raw.strip().startswith(("interface ", "router ", "address-family ", "vrf ", "key chain ", "key ",
                                   "route-map ", "mpls ldp", "profile ")) or raw.strip() == "bfd":
            stack.append((depth, raw.strip()))
    return out


_FIXED = ("frr defaults", "hostname", "log syslog", "service integrated-vtysh-config", "frr version")


def delta(old: str, new: str) -> list[list[str]]:
    """vtysh command lists that take away what is in `old` and not in
    `new` (a block that went whole: 'no router ospf'; a line: 'no' it in
    its block). What `new` adds is read from the file after."""
    have, want = _tree(old), set(_tree(new))
    gone_blocks: set[tuple[str, ...]] = set()
    cmds: list[list[str]] = []
    heads = {p[:-1] for p in have if len(p) > 1}
    for path in have:
        if path in want or any(path[:len(g)] == g for g in gone_blocks):
            continue
        last = path[-1]
        if len(path) == 1:
            if last.startswith(_FIXED):
                continue
            if path in heads and (last.startswith(("router ", "vrf ", "key chain ", "route-map ", "mpls ldp"))
                                  or last == "bfd"):
                gone_blocks.add(path)
                cmds.append(["configure terminal", "no " + last, "end"])
            elif path in heads:
                continue  # an interface: its lines are taken away one by one
            else:
                cmds.append(["configure terminal", _negate(last), "end"])
            continue
        if path in heads and path[-1].startswith("address-family"):
            gone_blocks.add(path)
            cmds.append(["configure terminal", *path[:-1], "no " + last, "end"])
            continue
        cmds.append(["configure terminal", *path[:-1], _negate(last), "end"])
    return cmds


def _negate(line: str) -> str:
    return line[3:] if line.startswith("no ") else "no " + line


READ_CMD = (f"cat {FRR_CONF} 2>/dev/null; echo '#winlab-daemons'; cat {FRR_DAEMONS} 2>/dev/null; "
            "echo '#winlab-up'; pgrep -x zebra >/dev/null 2>&1 && echo up")


def live_script(plan, runner) -> list[str]:
    """What a running router runs for a change typed at the console: the
    VRFs and virtual interfaces as render() has them, then FRRouting
    brought in line without a restart when only its configuration changed
    (a new daemon, or FRRouting not running yet, starts it again)."""
    own = _own(plan.lab)
    out = ["", "### OSPF, EIGRP, BGP, VRFs, VRRP and HSRP changed at the console (winlab/iosrouting.py)"]
    out += _vrf_lines(plan) + _vrrp_lines(plan)
    from . import ioshsrp, iossla
    out += iossla.router_lines(plan, runner)
    out += ioshsrp.router_lines(plan, runner)
    from . import iosglbp
    out += iosglbp.router_lines(plan, runner)
    from . import iosv6
    out += iosv6.kernel_lines(plan, reset=True)
    from . import iosmpls
    out += iosmpls.kernel_lines(plan)
    conf = frr_conf(plan)
    if not conf:
        return out + [f"[ -x {FRR_INIT} ] && {FRR_INIT} stop >/dev/null 2>&1 || true",
                      f"rm -f {FRR_CONF}"]
    try:
        text = runner(READ_CMD, timeout=20) or ""
    except Exception:  # noqa: BLE001 - read nothing: start it again from the file
        text = ""
    old_conf, _, rest = text.partition("#winlab-daemons")
    old_daemons, _, up = rest.partition("#winlab-up")
    daemons = daemons_file(own)
    out += [INSTALL] + _write_files(conf, daemons)
    if "up" not in up or old_daemons.strip() != daemons.strip():
        return out + [f"{FRR_INIT} restart >/dev/null 2>&1 || true"]
    for cmd in delta(old_conf, conf):
        out.append("vtysh " + " ".join(f"-c {shlex.quote(c)}" for c in cmd) + " >/dev/null 2>&1 || true")
    # Then the whole file again, less what only a start reads (frr defaults).
    body = "\n".join(l for l in conf.splitlines() if not l.startswith(("frr defaults", "frr version")))
    out += [f"cat > /run/winlab-frr-apply.conf <<'WLFRR'\n{body}\nWLFRR",
            "vtysh -f /run/winlab-frr-apply.conf >/dev/null 2>&1 || true"]
    return out


# ------------------------------------------------------------------ show running-config
def vrf_lines(own: dict) -> list[str]:
    from . import iosospfauth  # key chain blocks print before the VRFs and the interfaces, as on IOS
    out = iosospfauth.keychain_run_lines(own)
    from . import iospim  # ip multicast-routing prints with the global lines, before the interfaces
    out += iospim.global_lines(own)
    for name in vrfs(own):
        kind = own.get(f"vrf-kind:{name}", "definition")
        out.append(f"vrf definition {name}" if kind == "definition" else f"ip vrf {name}")
        if own.get(f"vrf-desc:{name}"):
            out.append(f" description {own[f'vrf-desc:{name}']}")
        if own.get(f"vrf:{name}"):
            out.append(f" rd {own[f'vrf:{name}']}")
        from . import iosmpls
        out += iosmpls.vrf_lines(own, name)
        if kind == "definition" and own.get(f"vrf-af:{name}"):
            out += [" !", " address-family ipv4", " exit-address-family"]
        out.append("!")
    from . import iosmpls  # mpls label protocol, mpls ldp router-id
    out += iosmpls.global_lines(own)
    return out


def iface_pre(own: dict, ifname: str) -> list[str]:
    """The lines IOS prints before an interface's address: its VRF."""
    vrf = vrf_of(own, ifname)
    if not vrf:
        return []
    return [f" ip vrf forwarding {vrf}" if own.get(f"vrf-kind:{vrf}") == "ip" else f" vrf forwarding {vrf}"]


def iface_lines(own: dict, ifname: str) -> list[str]:
    from . import ioseigrp, iosglbp, ioshsrp, iosisis, iospim
    out = ioseigrp.iface_lines(own, ifname) + ioshsrp.iface_lines(own, ifname) + iosglbp.iface_lines(own, ifname)
    out += iospim.iface_lines(own, ifname) + iosisis.iface_lines(own, ifname)
    for _, grp, vip in vrrp_groups(own, ifname):
        if own.get(f"vrrp-desc:{ifname}:{grp}"):
            out.append(f" vrrp {grp} description {own[f'vrrp-desc:{ifname}:{grp}']}")
        out.append(f" vrrp {grp} ip {vip}")
        if own.get(f"vrrp-adv:{ifname}:{grp}"):
            out.append(f" vrrp {grp} timers advertise {own[f'vrrp-adv:{ifname}:{grp}']}")
        if own.get(f"vrrp-nopre:{ifname}:{grp}"):
            out.append(f" no vrrp {grp} preempt")
        if own.get(f"vrrp-prio:{ifname}:{grp}"):
            out.append(f" vrrp {grp} priority {own[f'vrrp-prio:{ifname}:{grp}']}")
        from . import iossla
        out += iossla.vrrp_lines(own, ifname, grp)
    if own.get(f"ospf-area:{ifname}"):
        pid, area = own[f"ospf-area:{ifname}"].split()
        out.append(f" ip ospf {pid} area {area}")
    for key, word in (("cost", "cost"), ("prio", "priority"), ("hello", "hello-interval"), ("dead", "dead-interval")):
        if own.get(f"ospf-{key}:{ifname}"):
            out.append(f" ip ospf {word} {own[f'ospf-{key}:{ifname}']}")
    if own.get(f"ospf-p2p:{ifname}"):
        out.append(" ip ospf network point-to-point")
    from . import iosospfauth
    out += iosospfauth.iface_lines(own, ifname)
    from . import iosbfd, iosmpls
    out += iosbfd.iface_lines(own, ifname) + iosmpls.iface_lines(own, ifname)
    return out


def _mask(n: ipaddress.IPv4Network) -> str:
    return f"{n.network_address} mask {n.netmask}"


def run_lines(con) -> list[str]:
    """router ospf, router bgp and ip route vrf, as show running-config
    prints them after the interfaces."""
    own = _own(con.lab)
    out = []
    for pid in ospf_pids(own):
        vrf = own.get(f"ospf:{pid}", "")
        out.append(f"router ospf {pid}" + (f" vrf {vrf}" if vrf else ""))
        if own.get(f"ospf-rid:{pid}"):
            out.append(f" router-id {own[f'ospf-rid:{pid}']}")
        if own.get(f"ospf-log:{pid}"):
            out.append(" log-adjacency-changes")
        from . import iosospfauth
        out += iosospfauth.area_run_lines(own, pid)
        from . import iosbfd, iosmpls, iosospfx
        out += iosospfx.run_lines(own, pid) + iosmpls.ospf_run_lines(own, pid) + iosbfd.ospf_run_lines(own, pid)
        for k, v in sorted(own.items()):
            if k.startswith(f"ospf-redist:{pid}:"):
                out.append(f" redistribute {k.split(':', 2)[2]}" + (f" {v}" if v else ""))
        if own.get(f"ospf-pasdef:{pid}"):
            out.append(" passive-interface default")
        for k, v in sorted(own.items()):
            if k.startswith(f"ospf-pas:{pid}:"):
                name = k.split(":", 2)[2]
                if v == "yes" and not own.get(f"ospf-pasdef:{pid}"):
                    out.append(f" passive-interface {name}")
                elif v == "no" and own.get(f"ospf-pasdef:{pid}"):
                    out.append(f" no passive-interface {name}")
        for addr, wild, area in ospf_nets(own, pid):
            out.append(f" network {addr} {wild} area {area}")
        if f"ospf-dio:{pid}" in own:
            out.append(" default-information originate" + (f" {own[f'ospf-dio:{pid}']}" if own[f"ospf-dio:{pid}"] else ""))
        out.append("!")
    from . import ioseigrp, iosisis
    out += ioseigrp.run_lines(own)
    out += iosisis.run_lines(own)
    asn = bgp_as(own)
    if asn:
        out.append(f"router bgp {asn}")
        if own.get("bgp-rid"):
            out.append(f" bgp router-id {own['bgp-rid']}")
        if own.get("bgp-log"):
            out.append(" bgp log-neighbor-changes")
        from . import iosbgpx
        out += iosbgpx.run_global(own)
        for ip in bgp_nbrs(own):
            out.append(f" neighbor {ip} remote-as {own[f'bgp-nbr:{ip}']}")
            if own.get(f"bgp-desc:{ip}"):
                out.append(f" neighbor {ip} description {own[f'bgp-desc:{ip}']}")
            if own.get(f"bgp-shut:{ip}"):
                out.append(f" neighbor {ip} shutdown")
            out += iosbgpx.run_nbr_global(own, ip)
        out += [" !", " address-family ipv4"]
        for k, v in sorted(own.items()):
            if k.startswith("bgp-redist:"):
                out.append(f"  redistribute {k[11:]}" + (f" {v}" if v else ""))
        out += [f"  network {_mask(n)}" if n.prefixlen != _classful(str(n.network_address)).prefixlen
                else f"  network {n.network_address}" for n in bgp_nets(own)]
        for ip in bgp_nbrs(own):
            if not own.get(f"bgp-noact:{ip}"):
                out.append(f"  neighbor {ip} activate")
            if own.get(f"bgp-dorig:{ip}"):
                out.append(f"  neighbor {ip} default-originate")
            out += iosbgpx.run_nbr_af(own, ip)
        out += [" exit-address-family"] + iosbgpx.run_extra_afs(own, bgp_nbrs(own)) + ["!"]
    vr = vroutes(own)
    for vrf, net, target, dist in vr:
        out.append(f"ip route vrf {vrf} {net.network_address} {net.netmask} {target}" + (f" {dist}" if dist != 1 else ""))
    out += ["!"] if vr else []
    from . import iospim
    out += iospim.run_lines(own)
    from . import iosrpolicy  # ip as-path, ip community-list, ip prefix-list, route-map
    out += iosrpolicy.run_lines(own)
    return out


# ------------------------------------------------------------------ the console
WORDS = {
    ("router", "ospf"): "Open Shortest Path First (OSPF)", ("router", "bgp"): "Border Gateway Protocol (BGP)",
    ("router", "eigrp"): "Enhanced Interior Gateway Routing Protocol (EIGRP)",
    ("show", "ip", "ospf"): "OSPF information", ("show", "ip", "bgp"): "BGP information",
    ("show", "ip", "route"): "IP routing table", ("show", "ip", "vrf"): "VPN Routing/Forwarding instance information",
    ("show", "vrf"): "VPN Routing/Forwarding instance information", ("show", "vrrp"): "VRRP information",
    ("vrf",): "VRF commands", ("ip", "vrf"): "Configure an IP VPN Routing/Forwarding instance",
    ("ip", "ospf"): "OSPF interface commands", ("vrrp",): "VRRP Interface configuration commands",
    ("standby",): "HSRP interface configuration commands", ("neighbor",): "Specify a neighbor router",
    ("address-family",): "Enter Address Family command mode", ("default-information",): "Control distribution of default information",
    ("passive-interface",): "Suppress routing updates on an interface", ("redistribute",): "Redistribute information from another routing protocol",
    ("bgp",): "BGP specific commands", ("clear", "ip", "ospf"): "OSPF clear commands",
    ("clear", "ip", "bgp"): "Clear BGP connections", ("network",): "Enable routing on an IP network",
    ("router-id",): "router-id for this OSPF process", ("router",): "Enable a routing process",
    ("do",): "To run exec commands in config mode", ("rd",): "Specify Route Distinguisher",
}
RM, RAF, VM, VAF = ("config-router",), ("config-router-af",), ("config-vrf",), ("config-vrf-af",)
MODES = RM + RAF + VM + VAF


def add_specs(con, add, U, E, C, IF) -> None:
    """The router's commands for OSPF, BGP, VRFs and VRRP (winlab/devcli.py)."""
    from . import devcli
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    R = RM + RAF
    add("end", con._end, "Exit from configure mode", MODES)
    add("exit", lambda a: _exit(con), "Exit from routing protocol configuration mode", MODES)
    add("do <line>", con._do, "To run exec commands in config mode", MODES)
    # the processes
    add("router ospf <num>", lambda a: _ospf(con, a[0], ""), "Open Shortest Path First (OSPF)", C + MODES)
    add("router ospf <num> vrf <name>", lambda a: _ospf(con, a[0], a[1]), "VPN Routing/Forwarding Instance", C + MODES)
    add("no router ospf <num>", lambda a: _no_ospf(con, a[0]), "Negate a command or set its defaults", C)
    add("router bgp <num>", lambda a: _bgp(con, a[0]), "Border Gateway Protocol (BGP)", C + MODES)
    add("no router bgp <num>", lambda a: _no_bgp(con, a[0]), "Negate a command or set its defaults", C)
    from . import ioseigrp, ioshsrp  # EIGRP (FRRouting's eigrpd) and HSRP (winlab's own speaker)
    add("router eigrp <line>", lambda a: ioseigrp.router_eigrp(con, a[0]), "Enhanced Interior Gateway Routing Protocol (EIGRP)", C + MODES)
    # inside router ospf / router bgp
    add("router-id <ip>", lambda a: _rid(con, a[0]), "router-id for this OSPF process", RM)
    add("no router-id", lambda a: _rid(con, ""), "Negate a command or set its defaults", RM)
    add("network <ip> <ip> area <name>", lambda a: _ospf_net(con, a, True), "Enable routing on an IP network", RM)
    add("no network <ip> <ip> area <name>", lambda a: _ospf_net(con, a, False), "Negate a command or set its defaults", RM)
    add("network <ip> mask <mask>", lambda a: _bgp_net(con, a[0], a[1], True), "Specify a network to announce via BGP", R)
    add("network <ip>", lambda a: _bgp_net(con, a[0], "", True), "Specify a network to announce via BGP", R)
    add("no network <ip> mask <mask>", lambda a: _bgp_net(con, a[0], a[1], False), "Negate a command or set its defaults", R)
    add("no network <ip>", lambda a: _bgp_net(con, a[0], "", False), "Negate a command or set its defaults", R)
    add("passive-interface <line>", lambda a: _passive(con, a[0], True), "Suppress routing updates on an interface", RM)
    add("no passive-interface <line>", lambda a: _passive(con, a[0], False), "Negate a command or set its defaults", RM)
    add("default-information originate", lambda a: _dio(con, "", True), "Distribute a default route", RM)
    add("default-information originate <line>", lambda a: _dio(con, a[0], True), "Distribute a default route", RM)
    add("no default-information originate", lambda a: _dio(con, "", False), "Negate a command or set its defaults", RM)
    add("redistribute <line>", lambda a: _redistribute(con, a[0], True), "Redistribute information from another routing protocol", R)
    add("no redistribute <line>", lambda a: _redistribute(con, a[0], False), "Negate a command or set its defaults", R)
    add("log-adjacency-changes", lambda a: _flag(con, "log", True), "Log changes in adjacency state", RM)
    add("log-adjacency-changes detail", lambda a: _flag(con, "log", True), "Log all state changes", RM)
    add("no log-adjacency-changes", lambda a: _flag(con, "log", False), "Negate a command or set its defaults", RM)
    add("bgp router-id <ip>", lambda a: _rid(con, a[0]), "Override configured router identifier", RM)
    add("no bgp router-id", lambda a: _rid(con, ""), "Negate a command or set its defaults", RM)
    add("bgp log-neighbor-changes", lambda a: _flag(con, "log", True), "Log neighbor up/down and reset reason", RM)
    add("no bgp log-neighbor-changes", lambda a: _flag(con, "log", False), "Negate a command or set its defaults", RM)
    add("no auto-summary", lambda a: "", "Negate a command or set its defaults", R)
    add("no synchronization", lambda a: "", "Negate a command or set its defaults", R)
    add("neighbor <ip> remote-as <num>", lambda a: _nbr_as(con, a[0], a[1]), "Specify a BGP neighbor", RM)
    add("neighbor <ip> description <line>", lambda a: _nbr_opt(con, a[0], "desc", a[1]), "Neighbor specific description", RM)
    add("neighbor <ip> shutdown", lambda a: _nbr_opt(con, a[0], "shut", "yes"), "Administratively shut down this neighbor", RM)
    add("neighbor <ip> activate", lambda a: _nbr_opt(con, a[0], "noact", ""), "Enable the Address Family for this Neighbor", R)
    add("neighbor <ip> default-originate", lambda a: _nbr_opt(con, a[0], "dorig", "yes"), "Originate default route to this neighbor", R)
    add("no neighbor <ip>", lambda a: _no_nbr(con, a[0]), "Negate a command or set its defaults", RM)
    add("no neighbor <ip> remote-as <num>", lambda a: _no_nbr(con, a[0]), "Negate a command or set its defaults", RM)
    add("no neighbor <ip> description", lambda a: _nbr_opt(con, a[0], "desc", ""), "Negate a command or set its defaults", RM)
    add("no neighbor <ip> description <line>", lambda a: _nbr_opt(con, a[0], "desc", ""), "Negate a command or set its defaults", RM)
    add("no neighbor <ip> shutdown", lambda a: _nbr_opt(con, a[0], "shut", ""), "Negate a command or set its defaults", RM)
    add("no neighbor <ip> activate", lambda a: _nbr_opt(con, a[0], "noact", "yes"), "Negate a command or set its defaults", R)
    add("no neighbor <ip> default-originate", lambda a: _nbr_opt(con, a[0], "dorig", ""), "Negate a command or set its defaults", R)
    add("address-family ipv4", lambda a: _af(con), "Address family", RM + VM)
    add("address-family ipv4 unicast", lambda a: _af(con), "Address Family modifier", RM + VM)
    add("exit-address-family", lambda a: _exit_af(con), "Exit from Address Family configuration mode", RAF + VAF)
    # interfaces
    add("ip ospf cost <num>", lambda a: _if_ospf(con, "cost", a[0], 1, 65535), "Interface cost", IF)
    add("ip ospf priority <num>", lambda a: _if_ospf(con, "prio", a[0], 0, 255), "Router priority", IF)
    add("ip ospf hello-interval <num>", lambda a: _if_ospf(con, "hello", a[0], 1, 65535), "Time between HELLO packets", IF)
    add("ip ospf dead-interval <num>", lambda a: _if_ospf(con, "dead", a[0], 1, 65535), "Interval after which a neighbor is declared dead", IF)
    add("ip ospf network point-to-point", lambda a: _if_ospf(con, "p2p", "yes", 0, 0), "Specify OSPF point-to-point network", IF)
    add("ip ospf network broadcast", lambda a: _if_ospf(con, "p2p", "", 0, 0), "Specify OSPF broadcast multi-access network", IF)
    add("ip ospf <num> area <name>", lambda a: _if_area(con, a[0], a[1]), "Process ID", IF)
    add("no ip ospf <line>", lambda a: _no_if_ospf(con, a[0]), "Negate a command or set its defaults", IF)
    add("vrf forwarding <name>", lambda a: _vrf_fwd(con, a[0], "definition"), "Configure forwarding table", IF)
    add("ip vrf forwarding <name>", lambda a: _vrf_fwd(con, a[0], "ip"), "Configure forwarding table", IF)
    add("no vrf forwarding", lambda a: _vrf_fwd(con, "", "definition"), "Negate a command or set its defaults", IF)
    add("no vrf forwarding <name>", lambda a: _vrf_fwd(con, "", "definition"), "Negate a command or set its defaults", IF)
    add("no ip vrf forwarding", lambda a: _vrf_fwd(con, "", "ip"), "Negate a command or set its defaults", IF)
    add("no ip vrf forwarding <name>", lambda a: _vrf_fwd(con, "", "ip"), "Negate a command or set its defaults", IF)
    add("vrrp <num> <line>", lambda a: _vrrp(con, a[0], a[1], True), "VRRP Interface configuration commands", IF)
    add("no vrrp <num>", lambda a: _vrrp(con, a[0], "", False), "Negate a command or set its defaults", IF)
    add("no vrrp <num> <line>", lambda a: _vrrp(con, a[0], a[1], False), "Negate a command or set its defaults", IF)
    # VRFs
    add("vrf definition <name>", lambda a: _vrf(con, a[0], "definition"), "VRF definition", C + VM + VAF)
    add("ip vrf <name>", lambda a: _vrf(con, a[0], "ip"), "Configure an IP VPN Routing/Forwarding instance", C + VM + VAF)
    add("no vrf definition <name>", lambda a: _no_vrf(con, a[0]), "Negate a command or set its defaults", C)
    add("no ip vrf <name>", lambda a: _no_vrf(con, a[0]), "Negate a command or set its defaults", C)
    add("rd <name>", lambda a: _rd(con, a[0]), "Specify Route Distinguisher", VM)
    add("no rd <line>", lambda a: _rd(con, ""), "Negate a command or set its defaults", VM)
    add("no rd", lambda a: _rd(con, ""), "Negate a command or set its defaults", VM)
    add("description <line>", lambda a: _vrf_desc(con, a[0]), "VRF specific description", VM)
    add("no description", lambda a: _vrf_desc(con, ""), "Negate a command or set its defaults", VM)
    add("ip route vrf <name> <ip> <mask> <line>", lambda a: _vroute(con, a, True), "Configure static route for a VPN Routing/Forwarding instance", C)
    add("no ip route vrf <name> <ip> <mask> <line>", lambda a: _vroute(con, a, False), "Negate a command or set its defaults", C)
    add("no ip route vrf <name> <ip> <mask>", lambda a: _vroute(con, a + [""], False), "Negate a command or set its defaults", C)
    # what the router knows
    add("show ip route ospf", lambda a: show_route(con, "", only="ospf"), "Open Shortest Path First (OSPF)", U)
    add("show ip route bgp", lambda a: show_route(con, "", only="bgp"), "Border Gateway Protocol (BGP)", U)
    add("show ip route connected", lambda a: show_route(con, "", only="connected"), "Connected", U)
    add("show ip route static", lambda a: show_route(con, "", only="static"), "Static routes", U)
    add("show ip route vrf <name>", lambda a: show_route(con, a[0]), "Display routes from a VPN Routing/Forwarding instance", U)
    add("show ip ospf", lambda a: _frr_show(con, "show ip ospf"), "OSPF information", U)
    add("show ip ospf neighbor", lambda a: show_ospf_neighbor(con), "Neighbor list", U)
    add("show ip ospf interface", lambda a: _frr_show(con, "show ip ospf interface"), "Interface information", U)
    add("show ip ospf interface brief", lambda a: show_ospf_brief(con), "Brief summary of OSPF interface information", U)
    add("show ip ospf interface <line>", lambda a: _frr_show(con, "show ip ospf interface", a[0]), "Interface information", U)
    add("show ip ospf database", lambda a: _frr_show(con, "show ip ospf database"), "Database summary", U)
    for kind, hlp in (("router", "Router link states"), ("network", "Network link states"),
                      ("summary", "Network summary link states"), ("asbr-summary", "ASBR summary link states"),
                      ("external", "External link states"), ("nssa-external", "NSSA external link states")):
        add(f"show ip ospf database {kind}", lambda a, k=kind: _frr_show(con, f"show ip ospf database {k}"), hlp, U)
    add("show ip ospf border-routers", lambda a: _frr_show(con, "show ip ospf border-routers"), "Border and boundary router information", U)
    add("show ip ospf virtual-links", lambda a: _frr_show(con, "show ip ospf interface"), "Virtual link information", U)
    add("show ip bgp", lambda a: _frr_show(con, "show ip bgp"), "BGP information", U)
    add("show ip bgp summary", lambda a: _frr_show(con, "show ip bgp summary"), "Summary of BGP neighbor status", U)
    add("show ip bgp neighbors", lambda a: _frr_show(con, "show ip bgp neighbors"), "Detailed information on TCP and BGP neighbor connections", U)
    add("show ip bgp neighbors <ip>", lambda a: _frr_show(con, f"show ip bgp neighbors {_ip(a[0])}"), "Neighbor to display information about", U)
    add("show ip vrf", lambda a: show_vrf(con), "VPN Routing/Forwarding instance information", U)
    add("show vrf", lambda a: show_vrf(con), "VPN Routing/Forwarding instance information", U)
    add("show vrrp", lambda a: _frr_show(con, "show vrrp"), "VRRP information", U)
    add("show vrrp brief", lambda a: show_vrrp_brief(con), "Brief output", U)
    add("clear ip ospf process", lambda a: _clear(con, "clear ip ospf process"), "Reset OSPF process", E)
    add("clear ip bgp *", lambda a: _clear(con, "clear bgp *"), "Clear all peers", E)
    add("clear ip bgp <ip>", lambda a: _clear(con, f"clear bgp {_ip(a[0])}"), "BGP neighbor address to clear", E)
    add("clear ip bgp * soft", lambda a: _clear(con, "clear bgp * soft"), "Soft reconfiguration", E)
    for d in ("in", "out"):
        add(f"clear ip bgp * soft {d}", lambda a, d=d: _clear(con, f"clear bgp * soft {d}"), "Soft reconfiguration " + ("inbound" if d == "in" else "outbound") + " update", E)
        add(f"clear ip bgp <ip> soft {d}", lambda a, d=d: _clear(con, f"clear bgp {_ip(a[0])} soft {d}"), "Soft reconfiguration " + ("inbound" if d == "in" else "outbound") + " update", E)
    add("clear ip bgp <ip> soft", lambda a: _clear(con, f"clear bgp {_ip(a[0])} soft"), "Soft reconfiguration", E)
    add("ping vrf <name> <ip>", lambda a: _vping(con, a[0], a[1]), "VPN Routing/Forwarding instance name", U)
    add("traceroute vrf <name> <ip>", lambda a: _vtrace(con, a[0], a[1]), "VPN Routing/Forwarding instance name", U)
    ioseigrp.add_specs(con, add, U, E, C, IF, RM)
    ioshsrp.add_specs(con, add, U, IF)
    from . import iosospfauth  # OSPF authentication and key chains
    iosospfauth.add_specs(con, add, U, C, IF, RM)
    from . import iosglbp  # GLBP (winlab's own speaker)
    iosglbp.add_specs(con, add, U, IF)
    from . import iosisis, iospim  # IS-IS (FRRouting's isisd) and PIM sparse mode (pimd)
    iosisis.add_specs(con, add, U, C, IF, RM)
    iospim.add_specs(con, add, U, C, IF)
    from . import iosbfd, iosbgpx, iosmpls, iosospfx, iosrpolicy  # the CCNP routing commands
    iosrpolicy.add_specs(con, add, U, C)
    iosbgpx.add_specs(con, add, U, RM, RAF)
    iosospfx.add_specs(con, add, RM)
    iosbfd.add_specs(con, add, U, IF, RM)
    iosmpls.add_specs(con, add, U, C, IF, RM, VM, VAF)


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


def _exit(con) -> str:
    m = con.s.mode
    if m == "config-router-af":
        from .iosbgpx import base_ctx
        con.s.mode, con.s.ctx = "config-router", base_ctx(con.s.ctx)
    elif m == "config-vrf-af":
        con.s.mode = "config-vrf"
    else:
        con.s.mode, con.s.ctx = "config", ""
    return ""


def _af(con) -> str:
    if con.s.mode == "config-router":
        if not con.s.ctx.startswith("bgp:"):
            raise _err("% Invalid input detected at '^' marker.")
        con.s.mode = "config-router-af"
        return ""
    own = _own_c(con)
    if own.get(f"vrf-kind:{con.s.ctx}") == "ip":
        raise _err("% Invalid input detected at '^' marker.")
    own[f"vrf-af:{con.s.ctx}"] = "yes"
    con.s.mode = "config-vrf-af"
    con._save(live=False)
    return ""


def _exit_af(con) -> str:
    from .iosbgpx import base_ctx
    con.s.mode = "config-router" if con.s.mode == "config-router-af" else "config-vrf"
    con.s.ctx = base_ctx(con.s.ctx)
    return ""


# ---- OSPF
def _pid(text: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise _err("% Invalid input detected at '^' marker.")
    return int(text)


def _ospf(con, pid_text: str, vrf: str) -> str:
    pid = _pid(pid_text)
    own = _own_c(con)
    if vrf and vrf not in vrfs(own):
        raise _err(f"% VRF {vrf} not configured")
    if f"ospf:{pid}" in own and own[f"ospf:{pid}"] != vrf:
        raise _err(f"% OSPF process {pid} is in {'VRF ' + own[f'ospf:{pid}'] if own[f'ospf:{pid}'] else 'the global table'}: "
                   f"no router ospf {pid} first")
    for other in ospf_pids(own):
        if other != pid and own.get(f"ospf:{other}", "") == vrf:
            raise _err(f"% This router runs one OSPF process per VRF (FRRouting's ospfd): process {other} "
                       f"already routes {'VRF ' + vrf if vrf else 'the global table'}")
    new = f"ospf:{pid}" not in own
    own[f"ospf:{pid}"] = vrf
    con.s.mode, con.s.ctx = "config-router", f"ospf:{pid}"
    return _done(con) if new else (con._save(live=False) or "")


def _no_ospf(con, pid_text: str) -> str:
    pid = _pid(pid_text)
    own = _own_c(con)
    if f"ospf:{pid}" not in own:
        return ""
    for k in [k for k in own if k in (f"ospf:{pid}", f"ospf-rid:{pid}", f"ospf-pasdef:{pid}", f"ospf-dio:{pid}",
                                      f"ospf-log:{pid}")
              or k.startswith((f"ospf-net:{pid}:", f"ospf-pas:{pid}:", f"ospf-redist:{pid}:"))]:
        del own[k]
    for k in [k for k in own if k.startswith("ospf-area:") and own[k].split()[0] == str(pid)]:
        del own[k]
    from . import iosospfauth
    iosospfauth.forget_pid(own, pid)
    from . import iosbfd, iosmpls, iosospfx
    iosospfx.forget_pid(own, pid)
    iosbfd.forget_pid(own, pid)
    iosmpls.forget_pid(own, pid)
    return _done(con)


def _cur(con) -> tuple[str, str]:
    kind, _, ident = con.s.ctx.partition(":")
    return kind, ident


def _rid(con, ip: str) -> str:
    kind, ident = _cur(con)
    if kind in ("eigrp", "isis"):   # IOS: eigrp router-id; IS-IS's ID is in its NET
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    key = f"ospf-rid:{ident}" if kind == "ospf" else "bgp-rid"
    if ip:
        ip = _ip(ip)
    had = own.get(key)
    if ip:
        own[key] = ip
    else:
        own.pop(key, None)
    note = _done(con)
    if kind == "ospf" and had and had != ip:
        note = ("% OSPF: Reload or use \"clear ip ospf process\" command, for this to take effect"
                + (f"\n{note}" if note else ""))
    return note


def _ospf_net(con, a, on: bool) -> str:
    kind, pid = _cur(con)
    if kind != "ospf":
        raise _err("% Invalid input detected at '^' marker.")
    addr, wild, area = _ip(a[0]), _ip(a[1]), _area(a[2])
    if _wild_prefix(addr, wild) is None:
        raise _err("% OSPF: this router takes a contiguous wildcard (0.0.0.255, 0.0.3.255, 0.0.0.0)")
    net = _wild_prefix(addr, wild)
    key = f"ospf-net:{pid}:{net.network_address} {wild}"
    own = _own_c(con)
    if on:
        for k, v in own.items():
            if k == key and v != area:
                raise _err(f"% OSPF: \"network {net.network_address} {wild} area {v}\" is already configured: "
                           f"no network {net.network_address} {wild} area {v} first")
        own[key] = area
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def _passive(con, text: str, on: bool) -> str:
    from . import devcli, ioseigrp
    kind, pid = _cur(con)
    if kind == "eigrp":
        return ioseigrp.passive_cmd(con, text, on)
    if kind == "isis":
        from . import iosisis
        return iosisis.passive_cmd(con, text, on)
    if kind != "ospf":
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    if text.strip().lower() in ("default", "d", "de", "def", "defa", "defau", "defaul"):
        if on:
            own[f"ospf-pasdef:{pid}"] = "yes"
        else:
            own.pop(f"ospf-pasdef:{pid}", None)
        for k in [k for k in own if k.startswith(f"ospf-pas:{pid}:")]:
            del own[k]
        return _done(con)
    name = devcli.parse_if(text.strip(), con._if_names(), sub=True)
    default = bool(own.get(f"ospf-pasdef:{pid}"))
    if on == default:
        own.pop(f"ospf-pas:{pid}:{name}", None)
    else:
        own[f"ospf-pas:{pid}:{name}"] = "yes" if on else "no"
    return _done(con)


def _dio(con, rest: str, on: bool) -> str:
    kind, pid = _cur(con)
    if kind != "ospf":
        raise _err("% Invalid input detected at '^' marker.")
    w = rest.split()
    i, keep = 0, []
    while i < len(w):
        if w[i] == "always":
            keep.append("always")
            i += 1
        elif w[i] in ("metric", "metric-type") and i + 1 < len(w) and w[i + 1].isdigit():
            if w[i] == "metric-type" and w[i + 1] not in ("1", "2"):
                raise _err("% Invalid input detected at '^' marker.")
            keep += w[i:i + 2]
            i += 2
        else:
            raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    if on:
        own[f"ospf-dio:{pid}"] = " ".join(keep)
    else:
        own.pop(f"ospf-dio:{pid}", None)
    return _done(con)


def _redistribute(con, rest: str, on: bool) -> str:
    from . import ioseigrp
    kind, ident = _cur(con)
    if kind == "eigrp":
        return ioseigrp.redistribute_cmd(con, rest, on)
    if kind == "isis":
        from . import iosisis
        return iosisis.NO_REDIST
    from . import iosbgpx
    af = iosbgpx.sub_af(con)
    if af.startswith("vrf:"):
        return iosbgpx.vrf_redist(con, rest, on)
    if af:
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    w = rest.split()
    if not w or w[0] not in ("connected", "static", "ospf", "bgp", "eigrp"):
        if w and w[0] in ("rip", "isis"):
            raise _err(f"% {w[0].upper()} is not running on this router")
        raise _err("% Invalid input detected at '^' marker.")
    src = w[0]
    opts = w[1:]
    if src in ("ospf", "bgp", "eigrp"):
        if not opts or not opts[0].isdigit():
            raise _err("% Incomplete command.")
        if src == "eigrp" and opts[0] != ioseigrp.asn(own):
            raise _err(f"% EIGRP is not running with AS {opts[0]}")
        if src == "ospf" and int(opts[0]) not in ospf_pids(own):
            raise _err(f"% OSPF process {opts[0]} is not running")
        if src == "bgp" and opts[0] != bgp_as(own):
            raise _err(f"% BGP is not running with AS {opts[0]}")
        if kind == src:
            raise _err("% Invalid input detected at '^' marker.")
        src, opts = f"{src} {opts[0]}", opts[1:]
    i, keep = 0, []
    while i < len(opts):
        t = opts[i]
        if t == "subnets" and kind == "ospf":
            keep.append(t)
            i += 1
        elif t in ("metric", "metric-type") and i + 1 < len(opts) and opts[i + 1].isdigit():
            keep += opts[i:i + 2]
            i += 2
        elif t == "route-map" and i + 1 < len(opts) and re.match(r"^[A-Za-z0-9_.-]{1,63}$", opts[i + 1]):
            keep += opts[i:i + 2]
            i += 2
        elif t == "tag" and kind == "ospf":
            raise _err("% This router's OSPF (FRRouting's ospfd) tags redistributed routes with a route-map: "
                       "route-map <name> permit 10, set tag <n>, then redistribute ... route-map <name>")
        else:
            raise _err("% Invalid input detected at '^' marker.")
    key = (f"ospf-redist:{ident}:" if kind == "ospf" else "bgp-redist:") + src
    if on:
        own[key] = " ".join(keep)
    else:
        own.pop(key, None)
    note = _done(con)
    if on and kind == "ospf" and "subnets" not in keep and src in ("connected", "static"):
        # IOS 15 without subnets carries only classful networks; FRRouting
        # always carries subnets. Say so rather than pretend.
        note = ("% Only classful networks will be redistributed (on IOS); this router's OSPF (FRRouting) "
                "carries subnets either way: add subnets to say what it does") + (f"\n{note}" if note else "")
    return note


def _flag(con, what: str, on: bool) -> str:
    kind, ident = _cur(con)
    if kind == "isis":
        from . import iosisis
        return iosisis.log_cmd(con, on)
    own = _own_c(con)
    key = f"ospf-{what}:{ident}" if kind == "ospf" else f"bgp-{what}"
    if on:
        own[key] = "yes"
    else:
        own.pop(key, None)
    return _done(con)


# ---- BGP
def _bgp(con, asn: str) -> str:
    if not asn.isdigit() or not 1 <= int(asn) <= 4294967295:
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    have = bgp_as(own)
    if have and have != str(int(asn)):
        raise _err(f"% BGP is already running; AS is {have}")
    con.s.mode, con.s.ctx = "config-router", f"bgp:{int(asn)}"
    if not have:
        own["bgp"] = str(int(asn))
        own.setdefault("bgp-log", "yes")
        return _done(con)
    con._save(live=False)
    return ""


def _no_bgp(con, asn: str) -> str:
    own = _own_c(con)
    if bgp_as(own) != asn:
        return "% BGP is not running with this AS" if bgp_as(own) else ""
    for k in [k for k in own if k == "bgp" or k.startswith("bgp-")]:
        del own[k]
    return _done(con)


def _bgp_net(con, addr: str, mask: str, on: bool) -> str:
    kind, _ = _cur(con)
    if kind == "eigrp" and not mask:   # network <classful network> under router eigrp
        from . import ioseigrp
        return ioseigrp.net_cmd(con, addr, "", on)
    if kind != "bgp":
        raise _err("% Invalid input detected at '^' marker.")
    from . import iosbgpx
    af = iosbgpx.sub_af(con)
    if af.startswith("vrf:"):
        return iosbgpx.vrf_net(con, addr, mask, on)
    if af:
        raise _err("% Invalid input detected at '^' marker.")
    try:
        net = ipaddress.IPv4Network(f"{addr}/{mask}") if mask else _classful(addr)
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None
    own = _own_c(con)
    if on:
        own[f"bgp-net:{net}"] = "yes"
    elif own.pop(f"bgp-net:{net}", None) is None:
        return ""
    return _done(con)


def _nbr_as(con, ip: str, asn: str) -> str:
    kind, _ = _cur(con)
    if kind != "bgp":
        raise _err("% Invalid input detected at '^' marker.")
    from . import iosbgpx
    if iosbgpx.sub_af(con).startswith("vrf:"):
        raise _err(iosbgpx.NO_PECE)
    ip = _ip(ip)
    if not asn.isdigit() or not 1 <= int(asn) <= 4294967295:
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    own[f"bgp-nbr:{ip}"] = str(int(asn))
    return _done(con)


def _nbr_opt(con, ip: str, what: str, value: str) -> str:
    kind, _ = _cur(con)
    if kind != "bgp":
        raise _err("% Invalid input detected at '^' marker.")
    from . import iosbgpx
    af = iosbgpx.sub_af(con)
    if af == "vpnv4" and what == "noact":
        return iosbgpx.vpn_activate(con, ip, not value)
    if af:
        raise _err(iosbgpx.NO_PECE if af.startswith("vrf:") else "% Invalid input detected at '^' marker.")
    ip = _ip(ip)
    own = _own_c(con)
    if f"bgp-nbr:{ip}" not in own:
        raise _err("% Specify remote-as or peer-group commands first")
    if what == "desc" and value and not re.match(r"^[\w .,:/()-]{1,80}$", value):
        raise _err("% A description is up to 80 letters, digits, spaces and .,:/()-")
    if value:
        own[f"bgp-{what}:{ip}"] = value
    else:
        own.pop(f"bgp-{what}:{ip}", None)
    return _done(con)


def _no_nbr(con, ip: str) -> str:
    kind, _ = _cur(con)
    if kind != "bgp":
        raise _err("% Invalid input detected at '^' marker.")
    ip = _ip(ip)
    own = _own_c(con)
    for k in [k for k in own if k.startswith("bgp-") and k.endswith(f":{ip}")]:
        del own[k]
    return _done(con)


# ---- interfaces
def _if_ospf(con, key: str, value: str, lo: int, hi: int) -> str:
    if value and value != "yes" and not (value.isdigit() and lo <= int(value) <= hi):
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    if value:
        own[f"ospf-{key}:{con.s.ctx}"] = str(int(value)) if value.isdigit() else value
    else:
        own.pop(f"ospf-{key}:{con.s.ctx}", None)
    return _done(con)


def _if_area(con, pid: str, area: str) -> str:
    p = _pid(pid)
    own = _own_c(con)
    if f"ospf:{p}" not in own:
        own[f"ospf:{p}"] = vrf_of(own, con.s.ctx)
    own[f"ospf-area:{con.s.ctx}"] = f"{p} {_area(area)}"
    return _done(con)


def _no_if_ospf(con, rest: str) -> str:
    w = rest.split()
    keys = {"cost": "cost", "priority": "prio", "hello-interval": "hello", "dead-interval": "dead",
            "network": "p2p"}
    if w and w[0].isdigit():
        key = "area"
    else:
        hit = [v for k, v in keys.items() if w and k.startswith(w[0].lower())]
        if len(hit) != 1:
            raise _err("% Invalid input detected at '^' marker.")
        key = hit[0]
    _own_c(con).pop(f"ospf-{key}:{con.s.ctx}", None)
    return _done(con)


def _vrf_fwd(con, name: str, kind: str) -> str:
    from . import devcli
    own = _own_c(con)
    ifname = con.s.ctx
    old = vrf_of(own, ifname)
    if name:
        if name not in vrfs(own):
            raise _err(f"% VRF {name} not configured")
        have = own.get(f"vrf-kind:{name}", "definition")
        if have != kind:
            raise _err(f"% Use '{'ip vrf forwarding' if have == 'ip' else 'vrf forwarding'}' command for VRF '{name}'")
    if name == old:
        return ""
    note = []
    if own.get(f"ip:{ifname}"):
        net = con.lab.networks.get(own[f"ip:{ifname}"])
        addr = net.router_ip if net is not None else ""
        verb = f"enabling VRF {name}" if name else f"disabling VRF {old}"
        note.append(f"% Interface {ifname} IP address {addr} removed due to {verb}")
        own.pop(f"ip:{ifname}", None)
        for k in [k for k in own if k.startswith("vrrp") and k.split(":")[1] == ifname]:
            del own[k]
    if name:
        own[f"vrf-if:{ifname}"] = name
    else:
        own.pop(f"vrf-if:{ifname}", None)
    devcli.refresh_routed(con.lab)
    done = _done(con)
    return "\n".join(note + ([done] if done else []))


def _vrrp(con, grp_text: str, rest: str, on: bool) -> str:
    if not grp_text.isdigit() or not 1 <= int(grp_text) <= 255:
        raise _err("% Invalid input detected at '^' marker.")
    grp = int(grp_text)
    ifname = con.s.ctx
    own = _own_c(con)
    w = rest.split()
    key = f"{ifname}:{grp}"
    if not on and not w:
        for k in [k for k in own if k.startswith("vrrp") and (k.endswith(f":{key}") or k.startswith(f"vrrp-track:{key}:"))]:
            del own[k]
        return _done(con)
    if not w:
        raise _err("% Incomplete command.")
    word = w[0].lower()
    opts = {"ip": "ip", "priority": "prio", "preempt": "nopre", "timers": "adv", "description": "desc",
            "shutdown": "shutdown", "track": "track"}
    hit = [k for k in opts if k.startswith(word)]
    if len(hit) != 1:
        raise _err("% Invalid input detected at '^' marker.")
    what = hit[0]
    if what == "shutdown":
        raise _err("% vrrp <group> shutdown is not in this router: no vrrp <group> takes the group away")
    if what == "track":   # vrrp <g> track <object> [decrement <n>] (winlab/iossla.py lowers vrrpd's priority)
        if len(w) < 2 or not w[1].isdigit() or not 1 <= int(w[1]) <= 1000:
            raise _err("% Invalid input detected at '^' marker.")
        tkey = f"vrrp-track:{key}:{int(w[1])}"
        if not on:
            own.pop(tkey, None)
            return _done(con)
        if f"vrrp:{key}" not in own:
            raise _err(f"% VRRP group {grp} has no virtual address yet: vrrp {grp} ip <address> first")
        dec = 10
        if len(w) > 2:
            if len(w) != 4 or not "decrement".startswith(w[2].lower()) or not w[3].isdigit() or not 1 <= int(w[3]) <= 254:
                raise _err("% Invalid input detected at '^' marker.")
            dec = int(w[3])
        own[tkey] = str(dec)
        note = _done(con)
        if f"track:{int(w[1])}" not in own:
            note = "\n".join(x for x in (f"% Track object {int(w[1])} does not exist yet: it counts as Down", note) if x)
        return note
    if what != "ip" and on and f"vrrp:{key}" not in own and what != "description":
        raise _err(f"% VRRP group {grp} has no virtual address yet: vrrp {grp} ip <address> first")
    if what == "ip":
        if not on:
            for k in [k for k in own if k.startswith("vrrp") and (k.endswith(f":{key}") or k.startswith(f"vrrp-track:{key}:"))]:
                del own[k]
            return _done(con)
        if len(w) < 2:
            raise _err("% Incomplete command.")
        vip = _ip(w[1])
        net = con.lab.networks.get(own.get(f"ip:{ifname}", ""))
        if net is None:
            raise _err(f"% {ifname} has no IP address: give it one first (ip address ...)")
        if ipaddress.IPv4Address(vip) not in net.net or vip in (str(net.net.network_address),
                                                                str(net.net.broadcast_address)):
            raise _err(f"% Address {vip} is not in {ifname}'s subnet {net.net}")
        if vip == net.router_ip:
            raise _err(f"% {vip} is this interface's own address: the virtual address is a third one, which "
                       f"both gateways share (this router keeps its own apart, as an IOS backup would)")
        for k, v in own.items():
            if k.startswith("vrrp:") and v == vip and k != f"vrrp:{key}":
                raise _err(f"% Address {vip} is already the virtual address of group {k.rsplit(':', 1)[1]}")
        own[f"vrrp:{key}"] = vip
    elif what == "priority":
        if on:
            if len(w) < 2 or not w[1].isdigit() or not 1 <= int(w[1]) <= 254:
                raise _err("% Invalid input detected at '^' marker.")
            own[f"vrrp-prio:{key}"] = str(int(w[1]))
        else:
            own.pop(f"vrrp-prio:{key}", None)
    elif what == "preempt":
        if on:
            own.pop(f"vrrp-nopre:{key}", None)
        else:
            own[f"vrrp-nopre:{key}"] = "yes"
    elif what == "timers":
        if on:
            if len(w) < 3 or not "advertise".startswith(w[1].lower()) or not w[2].isdigit() \
                    or not 1 <= int(w[2]) <= 40:
                raise _err("% Invalid input detected at '^' marker.")
            own[f"vrrp-adv:{key}"] = str(int(w[2]))
        else:
            own.pop(f"vrrp-adv:{key}", None)
    elif what == "description":
        text = " ".join(rest.split()[1:])
        if on:
            if not re.match(r"^[\w .,:/()-]{1,80}$", text):
                raise _err("% A description is up to 80 letters, digits, spaces and .,:/()-")
            own[f"vrrp-desc:{key}"] = text
        else:
            own.pop(f"vrrp-desc:{key}", None)
    return _done(con)


# ---- VRFs
def _vrf(con, name: str, kind: str) -> str:
    own = _own_c(con)
    if not _VRF_NAME.match(name) or _TAKEN.match(name):
        raise _err("% This router keeps a VRF's name to 15 letters, digits, - or _, starting with a letter "
                   "and not one of its own interface names: it is a Linux device on the router")
    have = own.get(f"vrf-kind:{name}") if name in vrfs(own) else ""
    if have and have != kind:
        raise _err(f"% VRF {name} is a '{'ip vrf' if have == 'ip' else 'vrf definition'}': "
                   f"configure it with {'ip vrf' if have == 'ip' else 'vrf definition'} {name}")
    if not have:
        used = {int(v) for k, v in own.items() if k.startswith("vrf-table:") and v.isdigit()}
        table = next(t for t in range(TABLE_BASE, TABLE_BASE + 4000) if t not in used)
        own[f"vrf:{name}"] = ""
        own[f"vrf-kind:{name}"] = kind
        own[f"vrf-table:{name}"] = str(table)
    con.s.mode, con.s.ctx = "config-vrf", name
    return _done(con) if not have else (con._save(live=False) or "")


def _no_vrf(con, name: str) -> str:
    from . import devcli
    own = _own_c(con)
    if name not in vrfs(own):
        return f"% VRF {name} not configured"
    note = []
    for k in [k for k in own if k.startswith("vrf-if:") and own[k] == name]:
        ifname = k[7:]
        if own.get(f"ip:{ifname}"):
            net = con.lab.networks.get(own[f"ip:{ifname}"])
            note.append(f"% Interface {ifname} IP address {net.router_ip if net is not None else ''} "
                        f"removed due to disabling VRF {name}")
            own.pop(f"ip:{ifname}", None)
        del own[k]
    for k in [k for k in own if k.split(":", 1)[-1] == name and k.startswith(("vrf:", "vrf-kind:", "vrf-af:",
                                                                              "vrf-desc:", "vrf-table:"))]:
        del own[k]
    for k in [k for k in own if k.startswith(f"vroute:{name} ")]:
        del own[k]
    from . import iosmpls
    iosmpls.forget_vrf(own, name)
    for pid in ospf_pids(own):
        if own.get(f"ospf:{pid}") == name:
            for k in [k for k in own if k == f"ospf:{pid}" or k.startswith((f"ospf-net:{pid}:", f"ospf-pas:{pid}:"))]:
                del own[k]
    devcli.refresh_routed(con.lab)
    done = _done(con)
    return "\n".join(note + ([done] if done else []))


def _rd(con, value: str) -> str:
    own = _own_c(con)
    name = con.s.ctx
    if value:
        if not re.match(r"^(\d+|\d+\.\d+\.\d+\.\d+):\d+$", value):
            raise _err("% Invalid input detected at '^' marker.")
        if own.get(f"vrf:{name}") and own[f"vrf:{name}"] != value:
            raise _err(f"% Do \"no rd {own[f'vrf:{name}']}\" before redefining the VRF route distinguisher")
    own[f"vrf:{name}"] = value
    con._save(live=False)
    return ""


def _vrf_desc(con, text: str) -> str:
    own = _own_c(con)
    if text and not re.match(r"^[\w .,:/()-]{1,80}$", text):
        raise _err("% A description is up to 80 letters, digits, spaces and .,:/()-")
    if text:
        own[f"vrf-desc:{con.s.ctx}"] = text
    else:
        own.pop(f"vrf-desc:{con.s.ctx}", None)
    con._save(live=False)
    return ""


def _vroute(con, a, on: bool) -> str:
    from . import devcli
    name, addr, mask, rest = a[0], a[1], a[2], a[3]
    own = _own_c(con)
    if name not in vrfs(own):
        raise _err(f"% VRF {name} not configured")
    try:
        net = ipaddress.IPv4Network(f"{addr}/{mask}")
    except ValueError:
        raise _err("%Inconsistent address and mask") from None
    w = rest.split()
    if not on and not w:
        for k in [k for k in own if k.startswith(f"vroute:{name} {net} ")]:
            del own[k]
        return _done(con)
    if not w:
        raise _err("% Incomplete command.")
    target = str(ipaddress.IPv4Address(w[0])) if _IP.match(w[0]) else devcli.parse_if(w[0], con._if_names(), sub=True)
    dist = 1
    if len(w) > 1:
        if not w[1].isdigit() or not 1 <= int(w[1]) <= 255:
            raise _err("% Invalid input detected at '^' marker.")
        dist = int(w[1])
    key = f"vroute:{name} {net} {target}"
    if on:
        own[key] = str(dist)
    elif own.pop(key, None) is None:
        return "%No matching route to delete"
    return _done(con)


# ------------------------------------------------------------------ reading the router
def _vtysh(con, *cmds: str, timeout: float = 15) -> str:
    """What FRRouting answers on the router; a console line when it is not
    there or not running."""
    if not con.powered():
        return "%off"
    args = " ".join(f"-c {shlex.quote(c)}" for c in cmds)
    text = con._on_router(f"command -v vtysh >/dev/null 2>&1 || {{ echo '%nofrr'; exit 0; }}; "
                          f"pgrep -x zebra >/dev/null 2>&1 || {{ echo '%down'; exit 0; }}; vtysh {args} 2>&1",
                          timeout=timeout)
    return text or ""


def _frr_note(text: str) -> str:
    """A console line for FRRouting missing; nothing (as IOS prints) for a
    router that is off or a daemon that has not started yet."""
    if text.strip() == "%nofrr":
        return ("% FRRouting is not on this router yet: it installs from the lab's package volume the first time "
                "a routing protocol is configured (an older volume needs winlab images prepare fabric)")
    return ""


def _map_ifaces(con, text: str) -> str:
    """FRRouting names the router's Linux devices; the console names its
    interfaces."""
    svis = svi_map(con.lab, con.plan)
    from . import iosmpls
    svis.update(iosmpls.loopback_map(_own(con.lab)))
    for ifname, dev in sorted(svis.items(), key=lambda kv: -len(kv[1])):
        text = re.sub(rf"(?<![\w.]){re.escape(dev)}(?![\w.])", ifname, text)
        for _, grp, _ in vrrp_groups(_own(con.lab), ifname):
            text = re.sub(rf"(?<![\w.]){re.escape(_macvlan(dev, grp))}(?![\w.])", f"{ifname}-vrrp{grp}", text)
    return text


def _frr_show(con, cmd: str, arg: str = "") -> str:
    from . import devcli
    if arg:
        name = devcli.parse_if(arg.strip(), con._if_names(), sub=True)
        dev = svi_map(con.lab, con.plan).get(name)
        if not dev:
            return ""
        cmd = f"{cmd} {dev}"
    own = _own(con.lab)
    if "ospf" in cmd and not ospf_pids(own):
        return ""
    if "bgp" in cmd and not bgp_as(own):
        return "% BGP not active"
    if "vrrp" in cmd and not any(k.startswith("vrrp:") for k in own):
        return ""
    text = _vtysh(con, cmd)
    if text.strip().startswith("%"):
        return _frr_note(text)
    if "bgp" in cmd:
        from .iosbgpx import ios_text
        text = ios_text(text)
    return _map_ifaces(con, text.rstrip())


def _clear(con, cmd: str) -> str:
    text = _vtysh(con, cmd)
    return _frr_note(text) if text.strip().startswith("%") else ""


def _dead(text: str) -> str:
    """FRRouting's '36.712s' / '1m02s' -> IOS's 00:00:36."""
    s = 0
    for n, unit in re.findall(r"(\d+(?:\.\d+)?)([hms])", text):
        s += int(float(n)) * {"h": 3600, "m": 60, "s": 1}[unit]
    if not re.search(r"\d[hms]", text):
        m = re.match(r"^(\d+):(\d+):(\d+)", text)
        if m:
            return text[:8]
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


_NBR = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(.*?)\s*(\d+\.\d+\.\d+\.\d+)\s+(\S+)")


def parse_ospf_neighbors(text: str) -> list[dict]:
    """FRRouting's show ip ospf neighbor, row by row (with or without its
    Up Time column)."""
    out = []
    for line in text.splitlines():
        m = _NBR.match(line.strip())
        if not m:
            continue
        times = m.group(4).split()
        out.append({"id": m.group(1), "pri": int(m.group(2)), "state": m.group(3),
                    "dead": times[-1] if times else "", "addr": m.group(5), "dev": m.group(6).split(":")[0]})
    return out


def ios_state(state: str) -> str:
    st, _, role = state.partition("/")
    st = {"2-way": "2WAY", "full": "FULL", "init": "INIT", "exstart": "EXSTART", "exchange": "EXCHANGE",
          "loading": "LOADING", "down": "DOWN", "attempt": "ATTEMPT"}.get(st.lower(), st.upper())
    role = {"dr": "DR", "backup": "BDR", "bdr": "BDR", "drother": "DROTHER", "-": "  -", "": "  -"}.get(role.lower(), role.upper())
    return f"{st}/{role}"


def show_ospf_neighbor(con) -> str:
    if not ospf_pids(_own(con.lab)):
        return ""
    text = _vtysh(con, "show ip ospf neighbor")
    if text.strip().startswith("%"):
        return _frr_note(text)
    rev = {dev: name for name, dev in svi_map(con.lab, con.plan).items()}
    rows = parse_ospf_neighbors(text)
    out = ["", f"{'Neighbor ID':<16}{'Pri':>3}   {'State':<16}{'Dead Time':<12}{'Address':<16}Interface"]
    for r in rows:
        out.append(f"{r['id']:<16}{r['pri']:>3}   {ios_state(r['state']):<16}{_dead(r['dead']):<12}"
                   f"{r['addr']:<16}{rev.get(r['dev'], r['dev'])}")
    return "\n".join(out)


def show_ospf_brief(con) -> str:
    own = _own(con.lab)
    pids = ospf_pids(own)
    if not pids:
        return ""
    from . import devcli
    text = _vtysh(con, "show ip ospf interface json")
    try:
        data = json.loads(text) if not text.strip().startswith("%") else {}
    except ValueError:
        data = {}
    ifs = data.get("interfaces", data) if isinstance(data, dict) else {}
    rev = {dev: name for name, dev in svi_map(con.lab, con.plan).items()}
    out = [f"{'Interface':<12}{'PID':<6}{'Area':<16}{'IP Address/Mask':<20}{'Cost':<6}{'State':<6}Nbrs F/C"]
    for dev, d in sorted(ifs.items()) if isinstance(ifs, dict) else []:
        if not isinstance(d, dict) or not d.get("ospfEnabled", True):
            continue
        name = rev.get(dev, dev)
        pid = next((p for p in pids if own.get(f"ospf:{p}", "") == vrf_of(own, name)), pids[0])
        area = str(d.get("area", "")).split()[0] if d.get("area") is not None else ""
        addr = f"{d.get('ipAddress', '')}/{d.get('ipAddressPrefixlen', '')}"
        state = {"DR": "DR", "Backup": "BDR", "DROther": "DROTH", "Point-To-Point": "P2P"}.get(d.get("state", ""),
                                                                                             d.get("state", "")[:5])
        nbrs = f"{d.get('nbrAdjacentCount', 0)}/{d.get('nbrCount', 0)}"
        out.append(f"{devcli.short_if(name):<12}{pid:<6}{area:<16}{addr:<20}{d.get('cost', ''):<6}{state:<6}{nbrs}")
    return "\n".join(out)


def vrrp_states(text: str) -> dict[str, str]:
    """`ip -d -o link show` of the virtual interfaces -> Master | Backup |
    Init by name: vrrpd holds a backup's interface down (protodown on) and
    a master's up, so the kernel says which this router is."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)", line)
        if not m:
            continue
        if "protodown on" in line:
            out[m.group(1)] = "Backup"
        elif "LOWER_UP" in line:
            out[m.group(1)] = "Master"
        else:
            out[m.group(1)] = "Init"
    return out


def show_vrrp_brief(con) -> str:
    from . import devcli
    own = _own(con.lab)
    groups = vrrp_groups(own)
    if not groups:
        return ""
    svis = svi_map(con.lab, con.plan)
    names = {(i, g): _macvlan(svis[i], g) for i, g, _ in groups if i in svis}
    states: dict[str, str] = {}
    if names and con.powered():
        try:
            states = vrrp_states(con._on_router(
                " ".join(f"ip -d -o link show dev {m} 2>/dev/null;" for m in names.values()), timeout=10))
        except Exception:  # noqa: BLE001 - the groups still show, as Init
            states = {}
    out = [f"{'Interface':<14}{'Grp':<5}{'Pri':<5}{'Time':<6}{'Own':<4}{'Pre':<4}{'State':<9}{'Master addr':<16}Group addr"]
    for ifname, grp, vip in groups:
        state = states.get(names.get((ifname, grp), ""), "Init")
        prio = own.get(f"vrrp-prio:{ifname}:{grp}", "100")
        adv = int(own.get(f"vrrp-adv:{ifname}:{grp}", "1")) * 1000
        pre = "N" if own.get(f"vrrp-nopre:{ifname}:{grp}") else "Y"
        net = con.lab.networks.get(own.get(f"ip:{ifname}", ""))
        master = (net.router_ip if net is not None else "") if state == "Master" else "unknown"
        out.append(f"{devcli.short_if(ifname):<14}{grp:<5}{prio:<5}{adv:<6}{'':<4}{pre:<4}{state:<9}{master:<16}{vip}")
    return "\n".join(out)


def show_vrf(con) -> str:
    from . import devcli
    own = _own(con.lab)
    out = [f"  {'Name':<33}{'Default RD':<22}Interfaces"]
    for name in vrfs(own):
        ifs = [devcli.short_if(k[7:]) for k, v in sorted(own.items()) if k.startswith("vrf-if:") and v == name]
        out.append(f"  {name:<33}{own.get(f'vrf:{name}') or '<not set>':<22}{ifs[0] if ifs else ''}")
        out += [f"  {'':<33}{'':<22}{i}" for i in ifs[1:]]
    return "\n".join(out) if len(out) > 1 else ""


def _vping(con, vrf: str, ip: str) -> str:
    from . import devcli
    if vrf not in vrfs(_own(con.lab)):
        return f"% VRF {vrf} does not have a usable source address"
    ip = _ip(ip)
    text = con._on_router(f"ping -c 5 -W 2 -I {shlex.quote(vrf)} {ip} 2>&1", timeout=20)
    return devcli.format_ping(ip, text)


def _vtrace(con, vrf: str, ip: str) -> str:
    if vrf not in vrfs(_own(con.lab)):
        return f"% VRF {vrf} does not have a usable source address"
    ip = _ip(ip)
    text = con._on_router(f"traceroute -n -q 1 -w 2 -m 10 -i {shlex.quote(vrf)} {ip} 2>&1", timeout=40)
    out = ["Type escape sequence to abort.", f"Tracing the route to {ip}", "VRF info: (vrf in name/id, vrf out name/id)", ""]
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if m:
            out.append(f"  {m.group(1):>2} {m.group(2).strip()}")
    return "\n".join(out)


# ---- show ip route
CODES = ["Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP",
         "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area",
         "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2",
         "       E1 - OSPF external type 1, E2 - OSPF external type 2",
         "       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2",
         "       * - candidate default, U - per-user static route, o - ODR"]


def parse_routes(text: str) -> list[dict]:
    """zebra's show ip route json: the selected OSPF, EIGRP, IS-IS and BGP routes."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for prefix, entries in (data.items() if isinstance(data, dict) else []):
        for e in entries if isinstance(entries, list) else []:
            if e.get("protocol") not in ("ospf", "bgp", "eigrp", "isis") or not e.get("selected"):
                continue
            hops = [(h.get("ip", ""), h.get("interfaceName", "")) for h in e.get("nexthops", [])
                    if h.get("active", True)]
            out.append({"prefix": prefix, "proto": e["protocol"], "distance": int(e.get("distance", 0)),
                        "metric": int(e.get("metric", 0)), "uptime": e.get("uptime", ""), "hops": hops})
    return out


def show_route(con, vrf: str, only: str = "") -> str:
    """The routing table of the global table or of one VRF: connected and
    local routes of the interfaces that are up, static routes whose next
    hop is reachable, and the OSPF and BGP routes zebra selected."""
    from . import devcli, iosl3
    lab = con.lab
    own = _own(lab)
    if vrf and vrf not in vrfs(own):
        return f"% IP routing table {vrf} does not exist"
    conn = []
    for name, net, up in con.router_ifaces():
        if net is not None and net.routed and vrf_of(own, name) == vrf and con._router_status(name, up)[0] == "up":
            conn.append((net.net, name, net.router_ip))
    if not vrf:
        from . import iosmpls  # interface Loopback<n>
        conn += iosmpls.connected(own)
    stat = []
    from . import iossla  # ip route ... track <n>: out of the table while the object is Down
    hidden = iossla.hidden_routes(con) if not vrf else set()
    statics = ([(d, t, dist) for d, t, dist in iosl3.routes(own) if f"{d} {t}" not in hidden] if not vrf else
               [(d, t, dist) for v, d, t, dist in vroutes(own) if v == vrf])
    for dest, target, dist in statics:
        if _IP.match(target):
            if any(ipaddress.IPv4Address(target) in n for n, _, _ in conn):
                stat.append((dest, dist, f"[{dist}/0] via {target}"))
        elif any(nm == target for _, nm, _ in conn):
            stat.append((dest, dist, f"is directly connected, {target}"))
    stat = iosl3.best(stat)
    dyn = []
    if wants_frr(own) and con.powered():
        text = _vtysh(con, f"show ip route vrf {vrf} json" if vrf else "show ip route json")
        if not text.strip().startswith("%"):
            dyn = parse_routes(text)
    # A static route and a learnt one to the same place: the lower
    # administrative distance is in the table (a floating static behind OSPF).
    learnt: dict = {}
    for r in dyn:
        try:
            learnt[ipaddress.IPv4Network(r["prefix"])] = min(learnt.get(ipaddress.IPv4Network(r["prefix"]), 256),
                                                             int(r["distance"]))
        except (ValueError, KeyError, TypeError):
            continue
    sdist = {d: dist for d, dist, _ in stat}
    stat = [(d, how) for d, dist, how in stat if dist <= learnt.get(d, 256)]
    rev = {dev: name for name, dev in svi_map(lab, con.plan).items()}
    rows = []
    if only in ("", "connected"):
        for n, name, ip in conn:
            rows.append((n, f"C        {n} is directly connected, {name}"))
            if n.prefixlen < 32:
                rows.append((ipaddress.IPv4Network(f"{ip}/32"), f"L        {ip}/32 is directly connected, {name}"))
    if only in ("", "static"):
        for d, how in stat:
            rows.append((d, f"S{'*' if d.prefixlen == 0 else ' '}       {d} {how}"))
    default = next((v.split("via ")[-1] for d, v in stat if d.prefixlen == 0 and "via" in v), "")
    lvl: dict[str, str] = {}
    okind: dict[str, str] = {}
    if any(r["proto"] == "ospf" for r in dyn) and only in ("", "ospf") and not vrf:
        from . import iosospfx  # O IA, O E1/E2, O N1/N2 from ospfd's own table
        okind = iosospfx.route_kinds(con)
    if any(r["proto"] == "isis" for r in dyn) and only in ("", "isis"):
        from . import iosisis  # i L1 / i L2: the level isisd learnt the prefix at
        lvl = iosisis.levels(con)
    for r in dyn:
        try:
            d = ipaddress.IPv4Network(r["prefix"])
        except ValueError:
            continue
        code = {"ospf": "O", "eigrp": "D", "isis": "i"}.get(r["proto"], "B")
        if only and only != r["proto"]:
            continue
        if d in sdist and r["distance"] > sdist[d]:
            continue
        star = "*" if d.prefixlen == 0 else " "
        hops = r["hops"] or [("", "")]
        first = True
        for ip, dev in hops:
            where = f"via {ip}" if ip else "is directly connected"
            tail = f", {r['uptime']}" + (f", {rev.get(dev, dev)}" if code in ("O", "D", "i") and dev else "")
            kind = f"{code}{star}" + (lvl.get(r["prefix"], "L2") if code == "i" else "")
            if code == "O" and okind.get(r["prefix"]):
                kind = f"O{star}{okind[r['prefix']]}"
            lead = f"{kind:<9}{d} " if first else f"{'':<10}{'':<{len(str(d))}}"
            rows.append((d, f"{lead}[{r['distance']}/{r['metric']}] {where}{tail}"))
            first = False
        if d.prefixlen == 0 and not default and hops[0][0]:
            default = hops[0][0]
    rows.sort(key=lambda r: (int(r[0].network_address), r[0].prefixlen))
    head = ([f"Routing Table: {vrf}"] if vrf else []) + CODES + [
        "", (f"Gateway of last resort is {default} to network 0.0.0.0" if default
             else "Gateway of last resort is not set"), ""]
    if only:
        head = []
    return "\n".join(head + [r for _, r in rows])


# ---- show ip protocols
def show_protocols(con) -> str:
    from . import devcli
    own = _own(con.lab)
    out = ["*** IP Routing is NSF aware ***", ""]
    for pid in ospf_pids(own):
        vrf = own.get(f"ospf:{pid}", "")
        areas = sorted({a for _, _, a in ospf_nets(own, pid)} |
                       {v.split()[1] for k, v in own.items() if k.startswith("ospf-area:") and v.split()[0] == str(pid)})
        out += [f"Routing Protocol is \"ospf {pid}\"" + (f" (VRF {vrf})" if vrf else ""),
                "  Outgoing update filter list for all interfaces is not set",
                "  Incoming update filter list for all interfaces is not set",
                f"  Router ID {own.get(f'ospf-rid:{pid}', '(chosen at start: the highest interface address)')}"]
        if f"ospf-dio:{pid}" in own:
            out.append("  It is an autonomous system boundary router")
        redist = [k.split(":", 2)[2] for k in sorted(own) if k.startswith(f"ospf-redist:{pid}:")]
        if redist:
            out.append(" Redistributing External Routes from,")
            out += [f"    {r}" for r in redist]
        from . import iosospfx
        areas = sorted(set(areas) | set(iosospfx.all_areas(own, pid)), key=lambda a: int(iosospfx._area_key(a)))
        normal, stub, nssa = iosospfx.area_counts(own, pid, areas)
        out += [f"  Number of areas in this router is {normal + stub + nssa}. {normal} normal {stub} stub {nssa} nssa",
                "  Maximum path: 4", "  Routing for Networks:"]
        out += [f"    {a} {w} area {ar}" for a, w, ar in ospf_nets(own, pid)]
        ifs = [k.split(":", 1)[1] for k, v in sorted(own.items()) if k.startswith("ospf-area:") and v.split()[0] == str(pid)]
        if ifs:
            out.append("  Routing on Interfaces Configured Explicitly (Area " + ", ".join(
                sorted({own[f'ospf-area:{i}'].split()[1] for i in ifs})) + "):")
            out += [f"    {i}" for i in ifs]
        pas = [k.split(":", 2)[2] for k, v in sorted(own.items()) if k.startswith(f"ospf-pas:{pid}:") and v == "yes"]
        if own.get(f"ospf-pasdef:{pid}"):
            keep = {k.split(":", 2)[2] for k, v in own.items() if k.startswith(f"ospf-pas:{pid}:") and v == "no"}
            pas = [n for n, _, _ in con.router_ifaces() if n not in keep]
        if pas:
            out.append("  Passive Interface(s):")
            out += [f"    {p}" for p in pas]
        out += ["  Routing Information Sources:", "    Gateway         Distance      Last Update",
                "  Distance: (default is 110)", ""]
    from . import ioseigrp, iosisis
    out += ioseigrp.protocols(con)
    out += iosisis.protocols(con)
    asn = bgp_as(own)
    if asn:
        out += [f"Routing Protocol is \"bgp {asn}\"",
                "  Outgoing update filter list for all interfaces is not set",
                "  Incoming update filter list for all interfaces is not set",
                "  IGP synchronization is disabled", "  Automatic route summarization is disabled"]
        redist = [k[11:] for k in sorted(own) if k.startswith("bgp-redist:")]
        if redist:
            out.append(f"  Redistributing: {', '.join(redist)}")
        out.append("  Neighbor(s):")
        out.append("    Address          FiltIn FiltOut DistIn DistOut Weight RouteMap")
        out += [f"    {ip}" for ip in bgp_nbrs(own)]
        out += ["  Maximum path: 1", "  Routing Information Sources:", "    Gateway         Distance      Last Update",
                "  Distance: external 20 internal 200 local 200", ""]
    return "\n".join(out).rstrip() + "\n"


def other_protocol(text: str) -> str:
    """router <anything else>: what the console says about it."""
    w = text.split()
    return ("% This router runs OSPF (router ospf <process>), EIGRP (router eigrp <as>), IS-IS (router isis [<tag>]) "
            "and BGP (router bgp <as>); "
            f"{(w[0].upper() + ' is') if w else 'that is'} not in it")
