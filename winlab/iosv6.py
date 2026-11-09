"""IPv6 on the lab router's console and the switches' management interfaces:
``ipv6 unicast-routing``, addresses (static, EUI-64, link-local), router
advertisements, IPv6 static routes (default, network, host, floating) and
OSPFv3, typed as on IOS and made real on the router (the Alpine VM that is
the lab's switches and router).

IPv6 on the lab router is OFF until the student turns it on. Every lab's
router starts as winlab/netplan.py makes it: net.ipv6.conf.all.forwarding=0
and accept_ra=0, so a lab nobody types IPv6 into is exactly what it was
before this module, and the ipv6-dual-stack lab (winlab/ipv6.py), whose
IPv6 routers are Ubuntu machines joined by a core segment the lab router is
not cabled to, keeps working whatever its console is told. Only these
commands change that:

* ``ipv6 unicast-routing`` sets net.ipv6.conf.all.forwarding=1 and loads an
  nftables table (``ip6 winlab_v6``) whose forward chain drops every IPv6
  packet that does not come in and go out of the router's own interfaces
  with IPv6 on them: the router forwards IPv6 between the lab's networks the
  student gave addresses, and nowhere else. ``no ipv6 unicast-routing``
  sets forwarding back to 0 and removes the table. As on IOS, the router
  sends router advertisements only while it routes IPv6;
* ``ipv6 address`` (``<address>/<len>``, ``<prefix>/64 eui-64``, ``<fe80::x>
  link-local``) and ``ipv6 enable`` on a router port or sub-interface are
  kernel addresses on that interface's SVI (``ip -6 addr``), as its IPv4
  address is. The EUI-64 interface identifier is computed on the router from
  the SVI's real MAC address (flip bit 7 of the first octet, FFFE in the
  middle), the same address the kernel derives its own link-local from; a
  typed link-local replaces the kernel's. Once the console has any IPv6
  setting, an interface with none of its own has IPv6 switched off
  (disable_ipv6), as an IOS interface without ``ipv6 enable`` or an address
  has no IPv6 at all; with no IPv6 setting anywhere nothing is touched;
* ``ipv6 nd`` (``ra suppress``, ``prefix``, ``managed-config-flag``,
  ``other-config-flag``, ``ra dns server``) is zebra's own ``ipv6 nd``
  (FRRouting, the suite winlab/iosrouting.py already runs on the router):
  real router advertisements, every 200 seconds with a router lifetime of
  1800 as on IOS, each on-link /64
  advertised for SLAAC unless ``ipv6 nd prefix ... no-advertise`` or
  ``no-autoconfig`` says otherwise, so Windows and Ubuntu clients configure
  themselves from them;
* ``ipv6 route`` is FRRouting's staticd: the administrative distance makes a
  floating static real (it is installed only when the better route goes),
  ``::/0`` is the default route, a /128 a host route, a link-local next hop
  needs its interface (as on IOS), and ``ipv6 route vrf`` puts one in a VRF
  of winlab/iosrouting.py;
* ``ipv6 router ospf <pid>`` (``router-id``, ``passive-interface``,
  ``default-information originate``) and ``ipv6 ospf <pid> area <a>`` on an
  interface are FRRouting's ospf6d (OSPFv3), which speaks to the Ubuntu
  routers' ospf6d as one router to another. As with OSPFv2 (iosrouting.py)
  the process number is the console's label: ospf6d runs one instance;
* every ``show ipv6`` reads the router: addresses, joined multicast groups,
  DAD and reachable time from the kernel, the RA settings from zebra
  (``vtysh -c 'show interface'``), routes from zebra (``show ipv6 route
  json``) beside the kernel's own addresses, neighbours from ``ip -6
  neigh``, OSPFv3 neighbours from ospf6d. ``ping ipv6``, ``ping <v6>`` and
  ``traceroute <v6>`` run on the router (busybox ping and traceroute).

Any prefix is accepted, the documentation prefix 2001:db8::/32 that CCNA
material uses included, not only ULA (fd00::/8) as the rest of winlab uses.
That does not weaken isolation: the lab has no uplink, the router has no
path to this PC or the Internet, and the forward chain above only passes
packets between the lab's own interfaces, so a "global" prefix here is as
private as a ULA one. The ipv6-dual-stack lab keeps its ULA plan.

What is not here, and why:

* An interface with IPv6 and no IPv4 address. winlab builds the router's
  side of a network (the SVI) from the network's IPv4 address, so the
  router's IPv6 is dual stack: the console keeps the IPv6 lines of an
  interface without ``ip address`` and says they take effect once it has
  one.
* ``ipv6 address ... anycast``: Linux has no configured anycast address. A
  router does answer its subnet-router anycast address (the prefix with an
  all-zero interface ID) on every link while it forwards, and ``show ipv6
  interface`` lists those from /proc/net/anycast6.
* DHCPv6 (``ipv6 dhcp relay destination``, ``ipv6 dhcp pool``): FRRouting has
  no DHCPv6 relay or server, and a second DHCP engine beside the router's
  dnsmasq is not worth what it would cost to keep in step. The console says
  so; SLAAC with the DNS server in the RA (``ipv6 nd ra dns server``, RFC
  8106, which Windows 10 1703 and later read) covers what a client needs, and
  stateful DHCPv6 is taught on Windows Server in the ipv6-dual-stack lab.
* A link-local next hop is pinged with its interface after it (``ping ipv6
  FE80::2 GigabitEthernet0/1/0``): IOS asks for the output interface in a
  prompt instead.
* ``show ipv6 route`` lists no ``L FF00::/8 via Null0``: Linux keeps
  multicast in its local table, not as a route to a null interface.
* Ages in ``show ipv6 neighbors`` are "-": the kernel keeps the state, not
  an age in minutes.

On a switch, ``ipv6 address`` (static, EUI-64 from the management
interface's own MAC, ``autoconfig``) on a VLAN interface with a management
address is that address in the switch's namespace (winlab/iosl2.py); the
switch is an IPv6 host there and takes its default router from the
router's advertisements, as an IOS switch does.

How it was tested: the router never boots in the test suite (its package
mirror is not reachable there), so tests/test_winlab.py checks the console
(parsing, refusals, running-config), the EUI-64 arithmetic, the shell
function that computes it on the router (run under sh against a fake
/sys/class/net), the FRRouting configuration, the sysctl and nftables
lines, and the show commands against recorded kernel and FRRouting output.

Settings (``<if>`` an IOS interface name): ``v6routing``; ``v6addr:<if>
<address>/<len>`` = "" | "eui-64" (an eui-64 key holds the prefix);
``v6ll:<if>``; ``v6en:<if>``; ``v6ra-sup:<if>``; ``v6pfx:<if> <prefix>`` =
its options; ``v6m:<if>``; ``v6o:<if>``; ``v6dns:<if>``; ``v6route:<vrf or
-> <prefix> <target>`` = distance (target an address, an interface, or
``<if>,<address>``); ``v6ospf:<pid>``; ``v6ospf-rid:<pid>``;
``v6ospf-dio:<pid>``; ``v6ospf-pas:<pid>:<if>``; ``v6ospf-area:<if>`` =
``<pid> <area>``; ``v6ospf-cost:<if>``. On a switch: ``v6svi:<vlan>
<address>/<len>`` = "" | "eui-64"; ``v6svi-auto:<vlan>``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re

RUN = "/run/winlab-v6"
NFT_TABLE = "winlab_v6"
RA_INTERVAL = 200   # IOS's default; FRRouting's own is 600
RA_LIFETIME = 1800  # IOS's default; FRRouting's own is three intervals
_DOTTED = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

NO_DHCP = ("% DHCPv6 is not in this router: FRRouting has no DHCPv6 relay or server. Let the clients use\n"
           "% SLAAC and give them the DNS server in the router advertisement (ipv6 nd ra dns server <address>),\n"
           "% or put a DHCPv6 server on the client's own link (the ipv6-dual-stack lab does, on Windows Server).")
NO_ANYCAST = ("% This router takes no configured anycast address (Linux has none). While it routes IPv6 it\n"
              "% answers the subnet-router anycast address of every prefix it has (the prefix with an all-zero\n"
              "% interface ID): show ipv6 interface lists them, marked [ANY].")
NOT_ROUTING = "% IPv6 routing not enabled"

WORDS = {
    ("ipv6",): "IPv6 interface subcommands", ("show", "ipv6"): "IPv6 information",
    ("show", "ipv6", "interface"): "IPv6 interface status and configuration",
    ("show", "ipv6", "route"): "Show IPv6 route table entries",
    ("show", "ipv6", "neighbors"): "Show IPv6 neighbor cache entries",
    ("show", "ipv6", "ospf"): "OSPF information", ("ipv6", "nd"): "IPv6 interface Neighbor Discovery subcommands",
    ("ipv6", "route"): "Configure static routes", ("ipv6", "router"): "Enable an IPV6 routing process",
    ("ipv6", "unicast-routing"): "Enable unicast routing", ("ipv6", "address"): "Configure IPv6 address on interface",
    ("ipv6", "ospf"): "OSPF interface commands", ("ping", "ipv6"): "IPv6 echo",
    ("traceroute", "ipv6"): "IPv6 trace", ("clear", "ipv6"): "IPv6 clear commands",
}
RTR = ("config-rtr",)


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def up(addr) -> str:
    """IOS prints IPv6 addresses in capitals."""
    return str(addr).upper()


# ------------------------------------------------------------------ EUI-64
def eui64_iid(mac: str) -> int:
    """The modified EUI-64 interface identifier of a MAC address (RFC 4291
    appendix A): FFFE in the middle, the universal/local bit (bit 7 of the
    first octet) flipped."""
    raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", mac))
    if len(raw) != 6:
        raise ValueError(f"not a MAC address: {mac}")
    return int.from_bytes(bytes([raw[0] ^ 0x02]) + raw[1:3] + b"\xff\xfe" + raw[3:6], "big")


def eui64(prefix, mac: str) -> ipaddress.IPv6Address:
    net = ipaddress.IPv6Network(str(prefix), strict=False)
    return ipaddress.IPv6Address((int(net.network_address) & ~((1 << 64) - 1)) | eui64_iid(mac))


def high64(prefix) -> str:
    """The upper four groups of a prefix, as the router's shell function takes them."""
    net = ipaddress.IPv6Network(str(prefix), strict=False)
    return ":".join(f"{int(g, 16):x}" for g in net.network_address.exploded.split(":")[:4])


# wl_eui64 <dev> <upper four groups>: the EUI-64 address on a device, from its MAC (busybox sh).
EUI_FN = ("wl_eui64() { m=$(cat ${WL_NET:-/sys/class/net}/$1/address 2>/dev/null); [ -n \"$m\" ] || return 1; "
          "o=$(echo \"$m\" | tr ':' ' '); set -- \"$2\" $o; "
          "printf '%s:%x:%x:%x:%x\\n' \"$1\" $(( ((0x$2 ^ 2) << 8) | 0x$3 )) $(( (0x$4 << 8) | 0xff )) "
          "$(( 0xfe00 | 0x$5 )) $(( (0x$6 << 8) | 0x$7 )); }")


# ------------------------------------------------------------------ settings
def _own(lab) -> dict:
    return lab.devices.get("router", {})


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def routing(own: dict) -> bool:
    return bool(own.get("v6routing"))


def addrs(own: dict, ifname: str) -> list[tuple[ipaddress.IPv6Interface, bool]]:
    """(address or prefix with its length, eui-64) typed on an interface."""
    out = []
    pre = f"v6addr:{ifname} "
    for k, v in own.items():
        if k.startswith(pre):
            try:
                out.append((ipaddress.IPv6Interface(k[len(pre):]), v == "eui-64"))
            except ValueError:
                continue
    return sorted(out, key=lambda r: (int(r[0].network.network_address), r[0].network.prefixlen, int(r[0].ip)))


def enabled(own: dict, ifname: str) -> bool:
    return bool(addrs(own, ifname) or own.get(f"v6ll:{ifname}") or own.get(f"v6en:{ifname}"))


def ifaces(own: dict) -> list[str]:
    names = set()
    for k in own:
        if k.startswith("v6addr:"):
            names.add(k[7:].split(" ")[0])
        elif k.startswith(("v6ll:", "v6en:", "v6ra-sup:", "v6m:", "v6o:", "v6dns:", "v6ospf-area:", "v6ospf-cost:")):
            names.add(k.split(":", 1)[1])
        elif k.startswith("v6pfx:"):
            names.add(k[6:].split(" ")[0])
    return sorted(names)


def nd_prefixes(own: dict, ifname: str) -> dict[str, str]:
    pre = f"v6pfx:{ifname} "
    return {k[len(pre):]: v for k, v in own.items() if k.startswith(pre)}


def routes(own: dict) -> list[tuple[str, ipaddress.IPv6Network, str, int]]:
    """(vrf or "", prefix, target, distance) of ipv6 route."""
    out = []
    for k, v in own.items():
        if k.startswith("v6route:"):
            parts = k[8:].split(" ")
            if len(parts) != 3:
                continue
            try:
                out.append(("" if parts[0] == "-" else parts[0], ipaddress.IPv6Network(parts[1]), parts[2],
                            int(v or 1)))
            except ValueError:
                continue
    return sorted(out, key=lambda r: (r[0], int(r[1].network_address), r[1].prefixlen, r[2]))


def ospf_pids(own: dict) -> list[int]:
    return sorted(int(k[7:]) for k in own if k.startswith("v6ospf:") and k[7:].isdigit())


def active(own: dict) -> bool:
    """Whether the console has any IPv6 setting of the router's."""
    return any(k == "v6routing" or k.startswith(("v6addr:", "v6ll:", "v6en:", "v6route:", "v6ospf"))
               for k in own)


def wants_frr(own: dict) -> bool:
    """FRRouting runs for IPv6 when the router routes it (router
    advertisements are zebra's), has static routes (staticd) or OSPFv3."""
    return routing(own) or any(k.startswith(("v6route:", "v6ospf:")) for k in own)


# ------------------------------------------------------------------ the router's script
def _svis(plan) -> dict[str, str]:
    from . import iosrouting
    return iosrouting.svi_map(plan.lab, plan)


def _sig(own: dict, ifname: str) -> str:
    parts = [own.get(f"v6ll:{ifname}", "")] + [f"{a}{'e' if e else ''}" for a, e in addrs(own, ifname)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def kernel_lines(plan, reset: bool = False) -> list[str]:
    """Shell for the router: forwarding, the interfaces' IPv6 addresses
    (each set again only when what was typed on it changed, or its SVI was
    made again), and the forward chain. With no IPv6 setting left, undoes
    what an earlier run did; with none ever, nothing."""
    lab = plan.lab
    own = _own(lab)
    routed = sorted({seg.svi for seg in plan.segments.values() if seg.network.routed})
    if not active(own):
        if not reset:
            return []
        back = " ".join(routed)
        return ["# no IPv6 at the console: the lab router back to forwarding none (winlab/iosv6.py)",
                f"if [ -d {RUN} ]; then sysctl -qw net.ipv6.conf.all.forwarding=0 2>/dev/null; "
                f"nft delete table ip6 {NFT_TABLE} 2>/dev/null; for d in {back}; do p=/proc/sys/net/ipv6/conf/$d; "
                "[ -e $p ] || continue; echo 1 > $p/disable_ipv6; echo 0 > $p/disable_ipv6; done; "
                f"rm -rf {RUN}; fi; true"]
    svis = _svis(plan)
    rev = {dev: name for name, dev in svis.items()}
    out = ["", "### IPv6 as typed at the router's console (winlab/iosv6.py)", EUI_FN, f"mkdir -p {RUN}",
           f"sysctl -qw net.ipv6.conf.all.forwarding={1 if routing(own) else 0} 2>/dev/null || true"
           + ("   # ipv6 unicast-routing" if routing(own) else "")]
    on = []
    for dev in routed:
        name = rev.get(dev, "")
        if not name:
            continue  # not one of the console's interfaces (a site's or a firewall's segment): left as it is
        p = f"/proc/sys/net/ipv6/conf/{dev}"
        if not enabled(own, name):
            out.append(f"[ -e {p} ] && echo 1 > {p}/disable_ipv6; rm -f {RUN}/{dev}   # no IPv6 on {name}")
            continue
        on.append(dev)
        body = [f"echo 1 > {p}/keep_addr_on_down", f"echo 1 > {p}/disable_ipv6", f"echo 0 > {p}/disable_ipv6"]
        ll = own.get(f"v6ll:{name}")
        if ll:
            body += [f"ip -6 addr flush dev {dev} scope link", f"ip -6 addr add {ll}/64 dev {dev}"]
        for a, eui in addrs(own, name):
            if eui:
                body.append(f"a=$(wl_eui64 {dev} {high64(a.network)}) && ip -6 addr add $a/{a.network.prefixlen} "
                            f"dev {dev}")
            else:
                body.append(f"ip -6 addr add {a} dev {dev}")
        body.append(f"echo \"$s\" > {RUN}/{dev}")
        out += [f"# {name}", f"s=\"{_sig(own, name)} $(cat /sys/class/net/{dev}/ifindex 2>/dev/null)\"",
                f"if [ -e {p} ] && [ \"$(cat {RUN}/{dev} 2>/dev/null)\" != \"$s\" ]; then"]
        out += [f"  {b} 2>/dev/null" for b in body] + ["fi"]
    out += nft_lines(own, on)
    out.append("")
    return out


def nft_lines(own: dict, devs: list[str]) -> list[str]:
    """IPv6 crosses the router only between its own interfaces that have
    IPv6: whatever else the router VM has, nothing is forwarded there."""
    if not routing(own):
        return [f"nft delete table ip6 {NFT_TABLE} 2>/dev/null || true"]
    rule = []
    if devs:
        s = ", ".join(f'"{d}"' for d in devs)
        rule = [f"    iifname {{ {s} }} oifname {{ {s} }} accept"]
    return (["nft -f - <<'WLV6' || true", f"table ip6 {NFT_TABLE}", f"delete table ip6 {NFT_TABLE}",
             f"table ip6 {NFT_TABLE} {{", "  chain forward {",
             "    type filter hook forward priority -10; policy drop;"] + rule + ["  }", "}", "WLV6"])


# ------------------------------------------------------------------ FRRouting's configuration
def frr_iface_lines(own: dict, ifname: str) -> list[str]:
    """The lines under ``interface <dev>`` in frr.conf: router
    advertisements (sent only while the router routes IPv6, as on IOS) and
    OSPFv3."""
    body = []
    if routing(own) and enabled(own, ifname) and not own.get(f"v6ra-sup:{ifname}"):
        body += [f" ipv6 nd ra-interval {RA_INTERVAL}", f" ipv6 nd ra-lifetime {RA_LIFETIME}", " no ipv6 nd suppress-ra"]
        typed = nd_prefixes(own, ifname)
        seen = set()
        for a, _ in addrs(own, ifname):
            p = str(a.network)
            if p in seen:
                continue
            seen.add(p)
            if p not in typed:
                body.append(f" ipv6 nd prefix {p}")
        for p, opts in sorted(typed.items()):
            w = opts.split()
            if "no-advertise" in w:
                continue
            line = f" ipv6 nd prefix {p}"
            nums = [x for x in w if x.isdigit() or x == "infinite"]
            if len(nums) >= 2:
                line += f" {nums[0]} {nums[1]}"
            line += " off-link" if "off-link" in w else ""
            line += " no-autoconfig" if "no-autoconfig" in w else ""
            body.append(line)
        if own.get(f"v6m:{ifname}"):
            body.append(" ipv6 nd managed-config-flag")
        if own.get(f"v6o:{ifname}"):
            body.append(" ipv6 nd other-config-flag")
        for d in own.get(f"v6dns:{ifname}", "").split():
            body.append(f" ipv6 nd rdnss {d}")
    area = own.get(f"v6ospf-area:{ifname}", "")
    if area and ospf_pids(own):
        pid, a = area.split()
        body.append(f" ipv6 ospf6 area {a}")
        if own.get(f"v6ospf-cost:{ifname}"):
            body.append(f" ipv6 ospf6 cost {own[f'v6ospf-cost:{ifname}']}")
        if own.get(f"v6ospf-pas:{pid}:{ifname}"):
            body.append(" ipv6 ospf6 passive")
    return body


def _how(target: str, svis: dict[str, str]) -> str:
    """A route's target as staticd takes it; "" when its interface is down."""
    ifname, _, nh = target.partition(",")
    if ":" in ifname:  # an address alone
        return ifname
    dev = svis.get(ifname)
    if not dev:
        return ""
    return f"{nh} {dev}" if nh else dev


def frr_global_lines(plan) -> list[str]:
    """ipv6 route (global, then per VRF) and router ospf6, after the
    interfaces in frr.conf."""
    own = _own(plan.lab)
    svis = _svis(plan)
    out: list[str] = []
    by_vrf: dict[str, list[str]] = {}
    for vrf, net, target, dist in routes(own):
        how = _how(target, svis)
        if not how:
            out.append(f"! ipv6 route {net} {target}: the interface is down, not installed")
            continue
        by_vrf.setdefault(vrf, []).append(f"ipv6 route {net} {how}" + (f" {dist}" if dist != 1 else ""))
    out += by_vrf.pop("", [])
    out += ["!"] if out else []
    for vrf in sorted(by_vrf):
        out += [f"vrf {vrf}"] + [f" {l}" for l in by_vrf[vrf]] + ["exit-vrf", "!"]
    for pid in ospf_pids(own)[:1]:
        out.append("router ospf6")
        if own.get(f"v6ospf-rid:{pid}"):
            out.append(f" ospf6 router-id {own[f'v6ospf-rid:{pid}']}")
        if f"v6ospf-dio:{pid}" in own:
            out.append(" default-information originate" + (" always" if own[f"v6ospf-dio:{pid}"] == "always" else ""))
        out += ["exit", "!"]
    return out


# ------------------------------------------------------------------ show running-config
def global_lines(own: dict) -> list[str]:
    return ["ipv6 unicast-routing", "!"] if routing(own) else []


def iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    if own.get(f"v6ll:{ifname}"):
        out.append(f" ipv6 address {up(own[f'v6ll:{ifname}'])} link-local")
    for a, eui in addrs(own, ifname):
        out.append(f" ipv6 address {up(a.network)} eui-64" if eui else f" ipv6 address {up(a)}")
    if own.get(f"v6en:{ifname}"):
        out.append(" ipv6 enable")
    for p, opts in sorted(nd_prefixes(own, ifname).items()):
        out.append(f" ipv6 nd prefix {up(p)}" + (f" {opts}" if opts else ""))
    if own.get(f"v6m:{ifname}"):
        out.append(" ipv6 nd managed-config-flag")
    if own.get(f"v6o:{ifname}"):
        out.append(" ipv6 nd other-config-flag")
    for d in own.get(f"v6dns:{ifname}", "").split():
        out.append(f" ipv6 nd ra dns server {up(d)}")
    if own.get(f"v6ra-sup:{ifname}"):
        out.append(" ipv6 nd ra suppress" + (" all" if own[f"v6ra-sup:{ifname}"] == "all" else ""))
    if own.get(f"v6ospf-cost:{ifname}"):
        out.append(f" ipv6 ospf cost {own[f'v6ospf-cost:{ifname}']}")
    if own.get(f"v6ospf-area:{ifname}"):
        pid, area = own[f"v6ospf-area:{ifname}"].split()
        out.append(f" ipv6 ospf {pid} area {area}")
    return out


def run_lines(own: dict) -> list[str]:
    out = []
    for vrf, net, target, dist in routes(own):
        ifname, _, nh = target.partition(",")
        tgt = up(ifname) if ":" in ifname else ifname + (f" {up(nh)}" if nh else "")
        out.append("ipv6 route " + (f"vrf {vrf} " if vrf else "") + f"{up(net)} {tgt}"
                   + (f" {dist}" if dist != 1 else ""))
    out += ["!"] if out else []
    for pid in ospf_pids(own):
        out.append(f"ipv6 router ospf {pid}")
        if own.get(f"v6ospf-rid:{pid}"):
            out.append(f" router-id {own[f'v6ospf-rid:{pid}']}")
        if f"v6ospf-dio:{pid}" in own:
            out.append(" default-information originate" + (" always" if own[f"v6ospf-dio:{pid}"] == "always" else ""))
        for k in sorted(own):
            if k.startswith(f"v6ospf-pas:{pid}:"):
                out.append(f" passive-interface {k.split(':', 2)[2]}")
        out.append("!")
    return out


# ------------------------------------------------------------------ parsing what is typed
def _v6(text: str) -> ipaddress.IPv6Address:
    try:
        return ipaddress.IPv6Address(text.strip().split("%")[0])
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None


def _v6if(text: str) -> ipaddress.IPv6Interface:
    if "/" not in text:
        raise _err("% Incomplete command.")
    try:
        a = ipaddress.IPv6Interface(text)
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None
    if a.network.prefixlen == 0:
        raise _err("% Invalid input detected at '^' marker.")
    return a


def parse_address(text: str) -> tuple[str, object]:
    """``ipv6 address`` as typed -> ("ll", address) | ("eui", prefix) |
    ("addr", address/len)."""
    w = text.split()
    if not w:
        raise _err("% Incomplete command.")
    opt = w[1].lower() if len(w) > 1 else ""
    if len(w) > 2:
        raise _err("% Invalid input detected at '^' marker.")
    if opt and "link-local".startswith(opt) and len(opt) >= 2:
        a = _v6(w[0])
        if not a.is_link_local:
            raise _err(f"% {up(a)} is not a link-local address (FE80::/10)")
        return "ll", a
    if opt and "anycast".startswith(opt):
        raise _err(NO_ANYCAST)
    a = _v6if(w[0])
    if opt and "eui-64".startswith(opt):
        if a.network.prefixlen > 64:
            raise _err(f"% EUI-64 fills the last 64 bits: the prefix must be /64 or shorter, not /{a.network.prefixlen}")
        return "eui", ipaddress.IPv6Interface(f"{a.network.network_address}/{a.network.prefixlen}")
    if opt:
        raise _err("% Invalid input detected at '^' marker.")
    if a.ip.is_link_local:
        raise _err(f"% {up(a.ip)} is link-local: ipv6 address {up(a.ip)} link-local")
    if a.ip.is_multicast or a.ip.is_unspecified or a.ip.is_loopback:
        raise _err(f"% {up(a)} is not a unicast address")
    if a.network.prefixlen < 127 and a.ip == a.network.network_address:
        raise _err(f"% {up(a.ip)} is the subnet-router anycast address of {up(a.network)}: give the interface a "
                   f"host address, or eui-64")
    return "addr", a


def parse_route(text: str) -> tuple[str, ipaddress.IPv6Network, str, int]:
    """``ipv6 route [vrf <name>] <prefix> <next hop | interface [next hop]>
    [distance]`` -> (vrf, prefix, target, distance)."""
    w = text.split()
    vrf = ""
    if w and w[0].lower() == "vrf":
        if len(w) < 2:
            raise _err("% Incomplete command.")
        vrf, w = w[1], w[2:]
    if len(w) < 2:
        raise _err("% Incomplete command.")
    if "/" not in w[0]:
        raise _err("% Invalid input detected at '^' marker.")
    try:
        net = ipaddress.IPv6Network(w[0], strict=False)
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None
    rest = w[1:]
    dist = 1
    if rest and rest[-1].isdigit():
        dist = int(rest.pop())
        if not 1 <= dist <= 254:
            raise _err("% Invalid input detected at '^' marker.")
    if not rest or len(rest) > 2:
        raise _err("% Incomplete command." if not rest else "% Invalid input detected at '^' marker.")
    return vrf, net, "\x00".join(rest), dist


def _target(con, raw: str) -> str:
    """A route's target as kept: an address, an interface's full name, or both."""
    from . import devcli
    parts = raw.split("\x00")
    if ":" in parts[0] and "/" not in parts[0] and len(parts) == 1:
        nh = _v6(parts[0])
        if nh.is_multicast or nh.is_unspecified:
            raise _err("% Invalid next hop address")
        if nh.is_link_local:
            raise _err("% Interface has to be specified for a link-local nexthop")
        return str(nh)
    name = devcli.parse_if(parts[0], con._if_names(), sub=True)
    if len(parts) == 2:
        nh = _v6(parts[1])
        if nh.is_multicast or nh.is_unspecified:
            raise _err("% Invalid next hop address")
        return f"{name},{nh}"
    return name


# ------------------------------------------------------------------ the console: global
def _done(con, note: str = "") -> str:
    out = con._save().strip()
    return "\n".join(x for x in (note, out) if x)


def _unicast_routing(con, on: bool) -> str:
    own = _own_c(con)
    if on:
        own["v6routing"] = "yes"
    elif own.pop("v6routing", None) is None:
        return ""
    return _done(con)


def _route(con, text: str, on: bool) -> str:
    from . import iosrouting
    own = _own_c(con)
    if not on and len(text.split()) in (1, 3) and "/" in text.split()[-1]:
        # no ipv6 route <prefix> / no ipv6 route vrf <name> <prefix>: every route to it
        w = text.split()
        vrf = w[1] if len(w) == 3 else ""
        try:
            net = ipaddress.IPv6Network(w[-1], strict=False)
        except ValueError:
            raise _err("% Invalid input detected at '^' marker.") from None
        gone = [k for k in own if k.startswith(f"v6route:{vrf or '-'} {net} ")]
        if not gone:
            return "% No matching route to delete"
        for k in gone:
            del own[k]
        return _done(con)
    vrf, net, raw, dist = parse_route(text)
    if vrf and vrf not in iosrouting.vrfs(own):
        raise _err(f"% VRF {vrf} does not exist")
    target = _target(con, raw)
    key = f"v6route:{vrf or '-'} {net} {target}"
    if on:
        own[key] = str(dist)
        return _done(con)
    if own.pop(key, None) is None:
        return "% No matching route to delete"
    return _done(con)


def _rid(text: str) -> str:
    if not _DOTTED.match(text):
        raise _err("% Invalid input detected at '^' marker.")
    return str(ipaddress.IPv4Address(text))


def _router_ospf(con, pid_text: str) -> str:
    own = _own_c(con)
    if not routing(own):
        raise _err(NOT_ROUTING)
    pid = int(pid_text)
    if not 1 <= pid <= 65535:
        raise _err("% Invalid input detected at '^' marker.")
    others = [p for p in ospf_pids(own) if p != pid]
    if others:
        raise _err(f"% This router runs one OSPFv3 process (FRRouting's ospf6d): process {others[0]} is it")
    new = f"v6ospf:{pid}" not in own
    own[f"v6ospf:{pid}"] = ""
    con.s.mode, con.s.ctx = "config-rtr", f"v6ospf:{pid}"
    return _done(con) if new else (con._save(live=False) or "").strip()


def _no_router_ospf(con, pid_text: str) -> str:
    own = _own_c(con)
    pid = pid_text
    if f"v6ospf:{pid}" not in own:
        return ""
    for k in [k for k in own if k in (f"v6ospf:{pid}", f"v6ospf-rid:{pid}", f"v6ospf-dio:{pid}")
              or k.startswith(f"v6ospf-pas:{pid}:")
              or (k.startswith("v6ospf-area:") and own[k].split()[0] == pid)]:
        del own[k]
    return _done(con)


def _cur_pid(con) -> str:
    return con.s.ctx.split(":", 1)[1]


def _ospf_rid(con, ip: str) -> str:
    own = _own_c(con)
    pid = _cur_pid(con)
    had = own.get(f"v6ospf-rid:{pid}")
    if ip:
        own[f"v6ospf-rid:{pid}"] = _rid(ip)
    else:
        own.pop(f"v6ospf-rid:{pid}", None)
    note = _done(con)
    if had and had != ip:
        note = ("% OSPFv3: Reload or use \"clear ipv6 ospf process\" command, for this to take effect"
                + (f"\n{note}" if note else ""))
    return note


def _ospf_passive(con, text: str, on: bool) -> str:
    from . import devcli
    own = _own_c(con)
    pid = _cur_pid(con)
    name = devcli.parse_if(text, con._if_names(), sub=True)
    if on:
        own[f"v6ospf-pas:{pid}:{name}"] = "yes"
    elif own.pop(f"v6ospf-pas:{pid}:{name}", None) is None:
        return ""
    return _done(con)


def _ospf_dio(con, rest: str, on: bool) -> str:
    own = _own_c(con)
    pid = _cur_pid(con)
    if on:
        if rest and rest.strip().lower() not in ("always",):
            raise _err("% Invalid input detected at '^' marker.")
        own[f"v6ospf-dio:{pid}"] = rest.strip().lower()
    elif own.pop(f"v6ospf-dio:{pid}", None) is None:
        return ""
    return _done(con)


def _rtr_exit(con) -> str:
    con.s.mode, con.s.ctx = "config", ""
    return ""


# ------------------------------------------------------------------ the console: an interface
def _ctx(con) -> str:
    return con.s.ctx


def _later(con, name: str) -> str:
    """A note when the interface is not routing yet, so its IPv6 waits."""
    from . import iosrouting
    if iosrouting.svi_map(con.lab, con.plan).get(name):
        return ""
    return (f"% Saved. {name} is not routing yet (no cable, shut down, or no ip address): this router builds an\n"
            f"% interface from its IPv4 network, so its IPv6 is dual stack and starts with the ip address.")


def _address(con, text: str) -> str:
    own = _own_c(con)
    name = _ctx(con)
    kind, val = parse_address(text)
    if kind == "ll":
        for k, v in own.items():
            if k.startswith("v6ll:") and k != f"v6ll:{name}" and v == str(val):
                raise _err(f"% {up(val)} is already the link-local address of {k[5:]}")
        own[f"v6ll:{name}"] = str(val)
        return _done(con, _later(con, name))
    net = val.network
    for k in own:
        if k.startswith("v6addr:"):
            other, _, a = k[7:].partition(" ")
            try:
                onet = ipaddress.IPv6Interface(a).network
            except ValueError:
                continue
            if other != name and (net.overlaps(onet)):
                raise _err(f"% {up(net)} overlaps with {other}")
    if kind == "eui":
        own[f"v6addr:{name} {val}"] = "eui-64"
    else:
        own[f"v6addr:{name} {val}"] = ""
    return _done(con, _later(con, name))


def _no_address(con, text: str) -> str:
    own = _own_c(con)
    name = _ctx(con)
    if not text.strip():
        gone = [k for k in own if k.startswith(f"v6addr:{name} ") or k == f"v6ll:{name}"]
    else:
        kind, val = parse_address(text)
        gone = [f"v6ll:{name}"] if kind == "ll" and own.get(f"v6ll:{name}") == str(val) else \
            [k for k in own if k == f"v6addr:{name} {val}"]
    if not gone:
        return "" if not text.strip() else "% Address not found on this interface"
    for k in gone:
        own.pop(k, None)
    return _done(con)


def _flag(con, key: str, value: str) -> str:
    own = _own_c(con)
    k = f"{key}:{_ctx(con)}"
    if value:
        own[k] = value
    elif own.pop(k, None) is None:
        return ""
    return _done(con)


def _nd_prefix(con, text: str, on: bool) -> str:
    own = _own_c(con)
    w = text.split()
    if not w:
        raise _err("% Incomplete command.")
    if "/" not in w[0]:
        raise _err("% Invalid input detected at '^' marker.")
    try:
        p = ipaddress.IPv6Network(w[0], strict=False)
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None
    key = f"v6pfx:{_ctx(con)} {p}"
    if not on:
        if own.pop(key, None) is None:
            return ""
        return _done(con)
    opts = []
    nums = [x for x in w[1:] if x.isdigit() or x.lower() == "infinite"]
    if nums and len(nums) != 2:
        raise _err("% Incomplete command.")
    for x in w[1:]:
        lx = x.lower()
        if lx.isdigit() or lx == "infinite":
            opts.append(lx)
        elif "no-advertise".startswith(lx) and len(lx) > 3:
            opts.append("no-advertise")
        elif "no-autoconfig".startswith(lx) and len(lx) > 3:
            opts.append("no-autoconfig")
        elif "off-link".startswith(lx) and len(lx) > 1:
            opts.append("off-link")
        else:
            raise _err("% Invalid input detected at '^' marker.")
    if nums and nums[0] != "infinite" and nums[1] != "infinite" and int(nums[1]) > int(nums[0]):
        raise _err("% Preferred lifetime must not be longer than the valid lifetime")
    own[key] = " ".join(opts)
    return _done(con)


def _rdnss(con, text: str, on: bool) -> str:
    own = _own_c(con)
    k = f"v6dns:{_ctx(con)}"
    have = own.get(k, "").split()
    w = text.split()
    if on:
        a = str(_v6(w[0])) if w else ""
        if not a:
            raise _err("% Incomplete command.")
        if a not in have:
            have.append(a)
    else:
        if w:
            a = str(_v6(w[0]))
            if a not in have:
                return ""
            have.remove(a)
        else:
            have = []
    if have:
        own[k] = " ".join(have)
    else:
        own.pop(k, None)
    return _done(con)


def _if_ospf(con, pid_text: str, area_text: str, on: bool) -> str:
    from . import iosrouting
    own = _own_c(con)
    name = _ctx(con)
    if on:
        if not routing(own):
            raise _err(NOT_ROUTING)
        pid = int(pid_text)
        others = [p for p in ospf_pids(own) if p != pid]
        if others:
            raise _err(f"% This router runs one OSPFv3 process (FRRouting's ospf6d): process {others[0]} is it")
        area = iosrouting._area(area_text)
        own[f"v6ospf:{pid}"] = ""
        own[f"v6ospf-area:{name}"] = f"{pid} {area}"
        note = "" if enabled(own, name) else \
            f"% {name} has no IPv6 yet: OSPFv3 runs on it once it has (ipv6 enable or an ipv6 address)"
        return _done(con, note)
    if own.pop(f"v6ospf-area:{name}", None) is None:
        return ""
    return _done(con)


def _if_cost(con, text: str) -> str:
    if text and not (text.isdigit() and 1 <= int(text) <= 65535):
        raise _err("% Invalid input detected at '^' marker.")
    return _flag(con, "v6ospf-cost", text)


# ------------------------------------------------------------------ reading the router
_ADDR = re.compile(r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet6\s+([0-9a-fA-F:]+)/(\d+)\s+(.*)$")


def parse_addrs(text: str) -> dict[str, list[dict]]:
    """``ip -6 -o addr show`` -> device -> [{addr, plen, scope, flags}]."""
    out: dict[str, list[dict]] = {}
    for line in (text or "").splitlines():
        m = _ADDR.match(line.strip())
        if not m:
            continue
        rest = m.group(4)
        sc = re.search(r"scope (\S+)", rest)
        out.setdefault(m.group(1), []).append({
            "addr": ipaddress.IPv6Address(m.group(2)), "plen": int(m.group(3)),
            "scope": sc.group(1) if sc else "global",
            "flags": [f for f in ("tentative", "dadfailed", "deprecated") if f in rest.split()]})
    return out


def _mark(a: dict, eui_nets: list) -> str:
    tags = []
    if any(a["addr"] in n for n in eui_nets) and (int(a["addr"]) >> 24) & 0xFFFF == 0xFFFE:
        tags.append("EUI")
    if "dadfailed" in a["flags"]:
        tags.append("DUP")
    elif "tentative" in a["flags"]:
        tags.append("TEN")
    return f" [{'/'.join(tags)}]" if tags else ""


def _run(con, cmd: str, timeout: float = 15) -> str:
    if not con.powered():
        return ""
    try:
        return con._on_router(cmd, timeout=timeout) or ""
    except Exception:  # noqa: BLE001 - a router that cannot be asked shows nothing, as when it is off
        return ""


def show_brief(con) -> str:
    from . import iosrouting
    own = _own(con.lab)
    svis = iosrouting.svi_map(con.lab, con.plan)
    have = parse_addrs(_run(con, "ip -6 -o addr show 2>/dev/null"))
    rows = []
    for name, net, isup in con.router_ifaces():
        status, proto = con._router_status(name, isup)
        rows.append(f"{name:<23}[{status}/{proto}]")
        dev = svis.get(name)
        got = have.get(dev, []) if dev and enabled(own, name) else []
        if not got:
            rows.append("    unassigned")
            continue
        for a in sorted(got, key=lambda a: (a["scope"] != "link", int(a["addr"]))):
            rows.append(f"    {up(a['addr'])}" + (" [TEN]" if "tentative" in a["flags"] else "")
                        + (" [DUP]" if "dadfailed" in a["flags"] else ""))
    return "\n".join(rows)


def _anycast(text: str, dev: str) -> list[ipaddress.IPv6Address]:
    out = []
    for line in text.splitlines():
        w = line.split()
        if len(w) >= 3 and w[1] == dev and re.fullmatch(r"[0-9a-f]{32}", w[2]):
            out.append(ipaddress.IPv6Address(int(w[2], 16)))
    return out


IFACE_CMD = ("ip -6 -o addr show dev {d} 2>/dev/null; echo '#m'; ip -6 maddr show dev {d} 2>/dev/null; "
             "echo '#a'; cat /proc/net/anycast6 2>/dev/null; echo '#v'; cat /sys/class/net/{d}/mtu "
             "/proc/sys/net/ipv6/conf/{d}/dad_transmits /proc/sys/net/ipv6/neigh/{d}/base_reachable_time_ms "
             "/proc/sys/net/ipv6/icmp/ratelimit /proc/sys/net/ipv6/conf/{d}/forwarding 2>/dev/null; echo '#nd'; "
             "pgrep -x zebra >/dev/null 2>&1 && vtysh -c 'show interface {d}' 2>/dev/null")


def format_iface(name: str, status: str, proto: str, own: dict, dev: str, text: str) -> str:
    """show ipv6 interface <if>, from what IFACE_CMD read on the router."""
    parts = dict.fromkeys(("a", "m", "any", "v", "nd"), "")
    head, _, rest = text.partition("#m")
    parts["a"] = head
    parts["m"], _, rest = rest.partition("#a")
    parts["any"], _, rest = rest.partition("#v")
    parts["v"], _, parts["nd"] = rest.partition("#nd")
    addrs_ = parse_addrs(parts["a"]).get(dev, [])
    eui_nets = [a.network for a, e in addrs(own, name) if e]
    out = [f"{name} is {status}, line protocol is {proto}"]
    ll = [a for a in addrs_ if a["scope"] == "link"]
    gl = [a for a in addrs_ if a["scope"] != "link"]
    if not ll and not gl:
        out.append("  IPv6 is enabled, link-local address is not yet assigned" if enabled(own, name)
                   else "  IPv6 is disabled")
        return "\n".join(out)
    if ll:
        out.append(f"  IPv6 is {'tentative' if 'tentative' in ll[0]['flags'] else 'enabled'}, link-local address is "
                   f"{up(ll[0]['addr'])}{_mark(ll[0], [])}")
    out.append("  No Virtual link-local address(es):")
    any_ = _anycast(parts["any"], dev)
    if gl or any_:
        out.append("  Global unicast address(es):")
        for a in sorted(gl, key=lambda a: int(a["addr"])):
            net = ipaddress.IPv6Network(f"{a['addr']}/{a['plen']}", strict=False)
            out.append(f"    {up(a['addr'])}, subnet is {up(net)}{_mark(a, eui_nets)}")
        for a in any_:
            if a.is_link_local:
                continue
            net = next((ipaddress.IPv6Network(f"{g['addr']}/{g['plen']}", strict=False) for g in gl
                        if a in ipaddress.IPv6Network(f"{g['addr']}/{g['plen']}", strict=False)), None)
            out.append(f"    {up(a)}, subnet is {up(net) if net else up(a) + '/128'} [ANY]")
    groups = re.findall(r"inet6\s+(ff0[0-9a-f]:\S*)", parts["m"], re.I)
    groups = [g for g in groups if not g.lower().startswith("ff01:")]
    if groups:
        out.append("  Joined group address(es):")
        out += [f"    {up(ipaddress.IPv6Address(g))}" for g in dict.fromkeys(groups)]
    vals = parts["v"].split()
    if len(vals) >= 1:
        out.append(f"  MTU is {vals[0]} bytes")
    if len(vals) >= 4:
        out.append(f"  ICMP error messages limited to one every {vals[3]} milliseconds")
    out.append("  ICMP redirects are enabled")
    if len(vals) >= 2:
        n = int(vals[1]) if vals[1].isdigit() else 1
        out.append(f"  ND DAD is enabled, number of DAD attempts: {n}" if n else "  ND DAD is disabled")
    if len(vals) >= 3:
        out.append(f"  ND reachable time is {vals[2]} milliseconds (using {vals[2]})")
    nd = [l.strip() for l in parts["nd"].splitlines() if l.strip().startswith(("ND ", "Hosts use"))]
    fwd = len(vals) >= 5 and vals[4] == "1"
    if nd and any("router advertisements" in l for l in nd):
        out += [f"  {l}" for l in nd]
    elif fwd:
        out.append("  ND RAs are suppressed (all)" if own.get(f"v6ra-sup:{name}") == "all"
                   else "  ND RAs are suppressed (periodic)")
        out.append("  Hosts use stateless autoconfig for addresses.")
    return "\n".join(out)


def show_iface(con, arg: str = "") -> str:
    from . import devcli, iosrouting
    own = _own(con.lab)
    svis = iosrouting.svi_map(con.lab, con.plan)
    want = devcli.parse_if(arg.strip(), con._if_names(), sub=True) if arg.strip() else ""
    out = []
    for name, net, isup in con.router_ifaces():
        if want and name != want:
            continue
        if not enabled(own, name):
            continue
        status, proto = con._router_status(name, isup)
        dev = svis.get(name, "")
        text = _run(con, IFACE_CMD.format(d=dev)) if dev else ""
        out.append(format_iface(name, status, proto, own, dev, text))
    return "\n".join(out)


CODES = ["Codes: C - Connected, L - Local, S - Static, U - Per-user Static route",
         "       B - BGP, R - RIP, H - NHRP, I1 - ISIS L1",
         "       I2 - ISIS L2, IA - ISIS interarea, IS - ISIS summary, D - EIGRP",
         "       EX - EIGRP external, ND - ND Default, NDp - ND Prefix, DCE - Destination",
         "       NDr - Redirect, RL - RPL, O - OSPF Intra, OI - OSPF Inter",
         "       OE1 - OSPF ext 1, OE2 - OSPF ext 2, ON1 - OSPF NSSA ext 1",
         "       ON2 - OSPF NSSA ext 2, la - LISP alt, lr - LISP site-registrations",
         "       ld - LISP dyn-eid, lA - LISP away, a - Application"]


def parse_routes(text: str) -> list[dict]:
    """zebra's show ipv6 route json: the selected static and OSPFv3 routes."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for prefix, entries in (data.items() if isinstance(data, dict) else []):
        for e in entries if isinstance(entries, list) else []:
            if e.get("protocol") not in ("static", "ospf6") or not e.get("selected"):
                continue
            hops = [(h.get("ip", ""), h.get("interfaceName", ""), bool(h.get("directlyConnected")))
                    for h in e.get("nexthops", []) if h.get("active", True)]
            out.append({"prefix": prefix, "proto": e["protocol"], "distance": int(e.get("distance", 0)),
                        "metric": int(e.get("metric", 0)), "hops": hops, "type": e.get("ospf6Type", "")})
    return out


def format_routes(conn: list[tuple], locs: list[tuple], dyn: list[dict], rev: dict[str, str], vrf: str,
                  only: str) -> str:
    """show ipv6 route: conn the (network, interface) of the interfaces that
    are up, locs their (address, interface), dyn zebra's selected routes."""
    rows = []
    if only in ("", "connected"):
        for net, name in conn:
            rows.append((net, 1, [f"C   {up(net)} [0/0]", f"     via {name}, directly connected"]))
    if only in ("", "local"):
        for a, name in locs:
            n = ipaddress.IPv6Network(f"{a}/128")
            rows.append((n, 2, [f"L   {up(n)} [0/0]", f"     via {name}, receive"]))
    for r in dyn:
        try:
            d = ipaddress.IPv6Network(r["prefix"])
        except ValueError:
            continue
        kind = "static" if r["proto"] == "static" else "ospf"
        if only and only != kind:
            continue
        code = "S" if kind == "static" else {"E1": "OE1", "E2": "OE2", "IA": "OI"}.get(r["type"], "O")
        lines = [f"{code:<4}{up(d)} [{r['distance']}/{r['metric']}]"]
        for ip, dev, _direct in r["hops"] or [("", "", False)]:
            name = rev.get(dev, dev)
            if ip and (ipaddress.IPv6Address(ip).is_link_local or kind == "ospf") and name:
                lines.append(f"     via {up(ip)}, {name}")
            elif ip:
                lines.append(f"     via {up(ip)}")
            elif name:
                lines.append(f"     via {name}, directly connected")
        rows.append((d, 0, lines))
    rows.sort(key=lambda r: (int(r[0].network_address), r[0].prefixlen, r[1]))
    body = [l for _, _, ls in rows for l in ls]
    if only:
        return "\n".join(body)
    return "\n".join([f"IPv6 Routing Table - {vrf or 'default'} - {len(rows)} entries"] + CODES + [""] + body)


def show_route(con, only: str = "", vrf: str = "") -> str:
    from . import iosrouting
    lab = con.lab
    own = _own(lab)
    if vrf and vrf not in iosrouting.vrfs(own):
        return f"% IPv6 routing table {vrf} does not exist"
    svis = iosrouting.svi_map(lab, con.plan)
    rev = {dev: name for name, dev in svis.items()}
    text = _run(con, "ip -6 -o addr show scope global 2>/dev/null; echo '#json'; pgrep -x zebra >/dev/null 2>&1 && "
                     + (f"vtysh -c 'show ipv6 route vrf {vrf} json'" if vrf else "vtysh -c 'show ipv6 route json'")
                     + " 2>/dev/null", timeout=20)
    kern, _, js = text.partition("#json")
    have = parse_addrs(kern)
    conn: list[tuple] = []
    locs: list[tuple] = []
    for name, net, isup in con.router_ifaces():
        dev = svis.get(name)
        if not dev or not enabled(own, name) or iosrouting.vrf_of(own, name) != vrf:
            continue
        if con._router_status(name, isup)[0] != "up":
            continue
        for a in have.get(dev, []):
            if a["scope"] == "global" and "tentative" not in a["flags"] and "dadfailed" not in a["flags"]:
                n = ipaddress.IPv6Network(f"{a['addr']}/{a['plen']}", strict=False)
                if (n, name) not in conn:
                    conn.append((n, name))
                locs.append((a["addr"], name))
    dyn = parse_routes(js.strip()) if js.strip() else []
    return format_routes(conn, locs, dyn, rev, vrf, only)


_STATES = {"REACHABLE": "REACH", "STALE": "STALE", "DELAY": "DELAY", "PROBE": "PROBE", "INCOMPLETE": "INCMP",
           "PERMANENT": "REACH"}


def format_neighbors(text: str, rev: dict[str, str]) -> str:
    from . import devcli
    rows = [f"{'IPv6 Address':<42}{'Age':>3} {'Link-layer Addr':<15} {'State':<5} Interface"]
    for line in text.splitlines():
        w = line.split()
        if len(w) < 3 or "dev" not in w:
            continue
        dev = w[w.index("dev") + 1]
        if dev not in rev:
            continue
        state = next((_STATES[x] for x in w if x in _STATES), "")
        if not state:
            continue
        mac = w[w.index("lladdr") + 1] if "lladdr" in w else ""
        try:
            a = ipaddress.IPv6Address(w[0])
        except ValueError:
            continue
        rows.append(f"{up(a):<42}{'-':>3} {devcli.dotted_mac(mac) if mac else '-':<15} {state:<5} "
                    f"{devcli.short_if(rev[dev])}")
    return "\n".join(rows)


def show_neighbors(con) -> str:
    from . import iosrouting
    rev = {dev: name for name, dev in iosrouting.svi_map(con.lab, con.plan).items()}
    return format_neighbors(_run(con, "ip -6 neigh show 2>/dev/null"), rev)


_NBR6 = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+([A-Za-z]+)/([A-Za-z]+)\s+(\S+)\s+([^\s\[]+)\[")


def format_ospf_neighbors(text: str, pid: int, rid: str, rev: dict[str, str]) -> str:
    """FRRouting's show ipv6 ospf6 neighbor, as IOS's show ipv6 ospf neighbor."""
    m = re.search(r"Router-ID\s*:?\s*(\d+\.\d+\.\d+\.\d+)", text)
    rid = m.group(1) if m else rid
    out = [f"{'':12}OSPFv3 Router with ID ({rid or '0.0.0.0'}) (Process ID {pid})", "",
           f"{'Neighbor ID':<16}{'Pri':>3}   {'State':<16}{'Dead Time':<12}{'Interface ID':<16}Interface"]
    for line in text.splitlines():
        n = _NBR6.match(line.strip())
        if not n:
            continue
        ifst = n.group(5)
        role = {"DR": "DR", "BDR": "BDR", "DROther": "DROTHER", "PointToPoint": "-"}.get(ifst, ifst.upper())
        state = f"{n.group(4).upper()}/{role}" if role != "-" else f"{n.group(4).upper()}/  -"
        dead = n.group(3)
        out.append(f"{n.group(1):<16}{n.group(2):>3}   {state:<16}{dead:<12}{'-':<16}{rev.get(n.group(7), n.group(7))}")
    return "\n".join(out)


def show_ospf_neighbor(con) -> str:
    from . import iosrouting
    own = _own(con.lab)
    pids = ospf_pids(own)
    if not pids:
        return ""
    text = _run(con, "pgrep -x ospf6d >/dev/null 2>&1 || { echo '%down'; exit 0; }; "
                     "vtysh -c 'show ipv6 ospf6' -c 'show ipv6 ospf6 neighbor' 2>&1")
    if not text.strip() or text.strip() == "%down":
        return ""
    rev = {dev: name for name, dev in iosrouting.svi_map(con.lab, con.plan).items()}
    return format_ospf_neighbors(text, pids[0], own.get(f"v6ospf-rid:{pids[0]}", ""), rev)


def show_ospf(con) -> str:
    from . import iosrouting
    if not ospf_pids(_own(con.lab)):
        return ""
    text = iosrouting._vtysh(con, "show ipv6 ospf6")
    if text.strip().startswith("%"):
        return iosrouting._frr_note(text)
    return iosrouting._map_ifaces(con, text.rstrip())


def _clear_ospf(con) -> str:
    from . import iosrouting
    text = iosrouting._vtysh(con, "clear ipv6 ospf6 process")
    return iosrouting._frr_note(text) if text.strip().startswith("%") else ""


def _clear_neighbors(con) -> str:
    from . import iosrouting
    for dev in iosrouting.svi_map(con.lab, con.plan).values():
        _run(con, f"ip -6 neigh flush dev {dev} 2>/dev/null")
    return ""


# ------------------------------------------------------------------ ping and traceroute
def _dest(con, text: str, out_if: str = "") -> tuple[str, str]:
    """(what to ping on the router, what to print)."""
    from . import devcli, iosrouting
    a = _v6(text)
    if a.is_link_local:
        if not out_if.strip():
            raise _err(f"% {up(a)} is link-local: give the output interface after it "
                       f"(ping ipv6 {up(a)} GigabitEthernet0/1/0)")
        name = devcli.parse_if(out_if.strip(), con._if_names(), sub=True)
        dev = iosrouting.svi_map(con.lab, con.plan).get(name)
        if not dev:
            raise _err(f"% {name} is not up")
        return f"{a}%{dev}", up(a)
    return str(a), up(a)


def ping(con, text: str, out_if: str = "") -> str:
    from . import devcli
    target, shown = _dest(con, text, out_if)
    res = con._on_router(f"ping -c 5 -W 2 {target} 2>&1", timeout=20)
    return devcli.format_ping(shown, res)


def traceroute(con, text: str) -> str:
    target, shown = _dest(con, text)
    res = con._on_router(f"traceroute -6 -n -q 1 -w 2 -m 10 {target} 2>&1", timeout=40)
    out = ["Type escape sequence to abort.", f"Tracing the route to {shown}", ""]
    for line in res.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if m:
            hop = re.sub(r"[0-9a-fA-F:]{2,}(?=\s|$)", lambda x: x.group(0).upper() if ":" in x.group(0) else x.group(0),
                         m.group(2).strip())
            out.append(f"  {m.group(1):>2} {hop}")
    return "\n".join(out)


# ------------------------------------------------------------------ registering the router's commands
def _register_words() -> None:
    from . import devcli
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    devcli.MODE_PROMPTS.setdefault("config-rtr", "config-rtr")


def add_specs(con, add, U, E, C, IF) -> None:
    """The router's IPv6 commands (winlab/devcli.py)."""
    _register_words()
    # global
    add("ipv6 unicast-routing", lambda a: _unicast_routing(con, True), "Enable unicast routing", C)
    add("no ipv6 unicast-routing", lambda a: _unicast_routing(con, False), "Negate a command or set its defaults", C)
    add("ipv6 route <line>", lambda a: _route(con, a[0], True), "Configure static routes", C)
    add("no ipv6 route <line>", lambda a: _route(con, a[0], False), "Negate a command or set its defaults", C)
    add("ipv6 router ospf <num>", lambda a: _router_ospf(con, a[0]), "Open Shortest Path First (OSPF)", C + RTR)
    add("no ipv6 router ospf <num>", lambda a: _no_router_ospf(con, a[0]), "Negate a command or set its defaults", C)
    add("ipv6 dhcp <line>", lambda a: NO_DHCP, "Configure IPv6 DHCP", C + IF)
    add("ipv6 address autoconfig", lambda a: "% This is a router: give it an address (ipv6 address <address>/<len> or "
        "<prefix>/64 eui-64)", "Obtain address using autoconfiguration", IF)
    # ipv6 router ospf
    add("end", con._end, "Exit from configure mode", RTR)
    add("exit", lambda a: _rtr_exit(con), "Exit from routing protocol configuration mode", RTR)
    add("do <line>", con._do, "To run exec commands in config mode", RTR)
    add("router-id <ip>", lambda a: _ospf_rid(con, a[0]), "router-id for this OSPF process", RTR)
    add("no router-id", lambda a: _ospf_rid(con, ""), "Negate a command or set its defaults", RTR)
    add("passive-interface <line>", lambda a: _ospf_passive(con, a[0], True), "Suppress routing updates on an interface", RTR)
    add("no passive-interface <line>", lambda a: _ospf_passive(con, a[0], False), "Negate a command or set its defaults", RTR)
    add("default-information originate", lambda a: _ospf_dio(con, "", True), "Distribute a default route", RTR)
    add("default-information originate <line>", lambda a: _ospf_dio(con, a[0], True), "Distribute a default route", RTR)
    add("no default-information originate", lambda a: _ospf_dio(con, "", False), "Negate a command or set its defaults", RTR)
    add("log-adjacency-changes", lambda a: "", "Log changes in adjacency state", RTR)
    # an interface
    add("ipv6 address <line>", lambda a: _address(con, a[0]), "Configure IPv6 address on interface", IF)
    add("no ipv6 address", lambda a: _no_address(con, ""), "Negate a command or set its defaults", IF)
    add("no ipv6 address <line>", lambda a: _no_address(con, a[0]), "Negate a command or set its defaults", IF)
    add("ipv6 enable", lambda a: _flag(con, "v6en", "yes"), "Enable IPv6 on interface", IF)
    add("no ipv6 enable", lambda a: _flag(con, "v6en", ""), "Negate a command or set its defaults", IF)
    add("ipv6 nd ra suppress", lambda a: _flag(con, "v6ra-sup", "yes"), "Suppress IPv6 Router Advertisements", IF)
    add("ipv6 nd ra suppress all", lambda a: _flag(con, "v6ra-sup", "all"), "Suppress all IPv6 RA", IF)
    add("ipv6 nd suppress-ra", lambda a: _flag(con, "v6ra-sup", "yes"), "Suppress IPv6 Router Advertisements", IF)
    add("no ipv6 nd ra suppress", lambda a: _flag(con, "v6ra-sup", ""), "Negate a command or set its defaults", IF)
    add("no ipv6 nd ra suppress all", lambda a: _flag(con, "v6ra-sup", ""), "Negate a command or set its defaults", IF)
    add("no ipv6 nd suppress-ra", lambda a: _flag(con, "v6ra-sup", ""), "Negate a command or set its defaults", IF)
    add("ipv6 nd prefix <line>", lambda a: _nd_prefix(con, a[0], True), "Configure IPv6 Routing Prefix Advertisement", IF)
    add("no ipv6 nd prefix <line>", lambda a: _nd_prefix(con, a[0], False), "Negate a command or set its defaults", IF)
    add("ipv6 nd managed-config-flag", lambda a: _flag(con, "v6m", "yes"), "Hosts should use DHCP for address config", IF)
    add("no ipv6 nd managed-config-flag", lambda a: _flag(con, "v6m", ""), "Negate a command or set its defaults", IF)
    add("ipv6 nd other-config-flag", lambda a: _flag(con, "v6o", "yes"), "Hosts should use DHCP for non-address config", IF)
    add("no ipv6 nd other-config-flag", lambda a: _flag(con, "v6o", ""), "Negate a command or set its defaults", IF)
    add("ipv6 nd ra dns server <line>", lambda a: _rdnss(con, a[0], True), "Configure DNS server address", IF)
    add("no ipv6 nd ra dns server", lambda a: _rdnss(con, "", False), "Negate a command or set its defaults", IF)
    add("no ipv6 nd ra dns server <line>", lambda a: _rdnss(con, a[0], False), "Negate a command or set its defaults", IF)
    add("ipv6 ospf <num> area <name>", lambda a: _if_ospf(con, a[0], a[1], True), "Process ID", IF)
    add("no ipv6 ospf <num> area <name>", lambda a: _if_ospf(con, a[0], a[1], False), "Negate a command or set its defaults", IF)
    add("no ipv6 ospf <num> area", lambda a: _if_ospf(con, a[0], "", False), "Negate a command or set its defaults", IF)
    add("ipv6 ospf cost <num>", lambda a: _if_cost(con, a[0]), "Interface cost", IF)
    add("no ipv6 ospf cost", lambda a: _if_cost(con, ""), "Negate a command or set its defaults", IF)
    # what the router knows
    add("show ipv6 interface", lambda a: show_iface(con), "IPv6 interface status and configuration", U)
    add("show ipv6 interface brief", lambda a: show_brief(con), "Brief summary of IPv6 status and configuration", U)
    add("show ipv6 interface <line>", lambda a: show_iface(con, a[0]), "IPv6 interface status and configuration", U)
    add("show ipv6 route", lambda a: show_route(con), "Show IPv6 route table entries", U)
    add("show ipv6 route static", lambda a: show_route(con, "static"), "Static routes", U)
    add("show ipv6 route connected", lambda a: show_route(con, "connected"), "Connected routes", U)
    add("show ipv6 route local", lambda a: show_route(con, "local"), "Local routes", U)
    add("show ipv6 route ospf", lambda a: show_route(con, "ospf"), "Open Shortest Path First (OSPF)", U)
    add("show ipv6 route vrf <name>", lambda a: show_route(con, "", a[0]), "Display routes from a VPN Routing/Forwarding instance", U)
    add("show ipv6 neighbors", lambda a: show_neighbors(con), "Show IPv6 neighbor cache entries", U)
    add("show ipv6 ospf", lambda a: show_ospf(con), "OSPF information", U)
    add("show ipv6 ospf neighbor", lambda a: show_ospf_neighbor(con), "Neighbor list", U)
    add("clear ipv6 ospf process", lambda a: _clear_ospf(con), "Reset OSPF process", E)
    add("clear ipv6 neighbors", lambda a: _clear_neighbors(con), "Delete IPv6 neighbor cache entries", E)
    add("ping ipv6 <ip>", lambda a: ping(con, a[0]), "IPv6 echo", U)
    add("ping ipv6 <ip> <line>", lambda a: ping(con, a[0], a[1]), "Output interface", U)
    add("traceroute ipv6 <ip>", lambda a: traceroute(con, a[0]), "IPv6 trace", U)


# ------------------------------------------------------------------ a switch's management interface
def sw_addrs(own: dict, tag: int) -> list[tuple[ipaddress.IPv6Interface, bool]]:
    pre = f"v6svi:{tag} "
    out = []
    for k, v in own.items():
        if k.startswith(pre):
            try:
                out.append((ipaddress.IPv6Interface(k[len(pre):]), v == "eui-64"))
            except ValueError:
                continue
    return sorted(out, key=lambda r: (int(r[0].ip), r[0].network.prefixlen))


def sw_sig(own: dict, tag: int) -> str:
    """What the switch's IPv6 on a VLAN is, for its namespace's signature (winlab/iosl2.py)."""
    parts = [f"{a}{'e' if e else ''}" for a, e in sw_addrs(own, tag)]
    return ",".join(parts) + ("+auto" if own.get(f"v6svi-auto:{tag}") else "")


def sw_lines(lab, sw: str, tag: int, ns: str, dev: str) -> list[str]:
    """The switch's IPv6 in its management namespace: no SLAAC unless
    ipv6 address autoconfig, the addresses typed (EUI-64 from the
    namespace port's own MAC, the one winlab/iosl2.py gives it)."""
    from . import iosl2
    own = lab.devices.get(f"sw:{sw}", {})
    out = [f"ip netns exec {ns} sh -c 'echo {1 if own.get(f'v6svi-auto:{tag}') else 0} > "
           f"/proc/sys/net/ipv6/conf/{dev}/autoconf' 2>/dev/null || true"]
    for a, eui in sw_addrs(own, tag):
        addr = f"{eui64(a.network, iosl2.mac_of(lab, sw, tag))}/{a.network.prefixlen}" if eui else str(a)
        out.append(f"ip -n {ns} -6 addr replace {addr} dev {dev} 2>/dev/null || true")
    return out


def _sw_tag(con) -> int:
    if not con.s.ctx.startswith("Vlan"):
        raise _err("% IPv6 addresses may not be configured on L2 links.")
    return int(con.s.ctx[4:])


def _sw_address(con, text: str, on: bool) -> str:
    from . import devcli
    own = devcli.settings(con.lab, con.device)
    tag = _sw_tag(con)
    if text.strip().lower().startswith("autoc"):
        if on:
            own[f"v6svi-auto:{tag}"] = "yes"
        else:
            own.pop(f"v6svi-auto:{tag}", None)
        return con._save().strip()
    if not on and not text.strip():
        for k in [k for k in own if k.startswith(f"v6svi:{tag} ") or k == f"v6svi-auto:{tag}"]:
            del own[k]
        return con._save().strip()
    kind, val = parse_address(text)
    if kind == "ll":
        raise _err("% This switch keeps the link-local address its interface derives from its MAC (EUI-64)")
    key = f"v6svi:{tag} {val}"
    if not on:
        if own.pop(key, None) is None:
            return "% Address not found on this interface"
        return con._save().strip()
    own[key] = "eui-64" if kind == "eui" else ""
    note = "" if own.get(f"svi:{tag}") else (
        f"% Saved. Vlan{tag} has no IPv4 management address: the switch's management interface is built from\n"
        f"% its ip address, so its IPv6 starts with it.")
    out = con._save().strip()
    return "\n".join(x for x in (note, out) if x)


def sw_show_brief(con) -> str:
    """The switch's VLAN interfaces and the IPv6 addresses its management
    namespace has (iosl2 numbers the namespace's ports in VLAN order)."""
    from . import devcli, iosl2
    sw = devcli.switch_id(con.device)
    ns = iosl2.netns(con.lab, sw)
    have = parse_addrs(_run(con, f"ip -n {ns} -6 -o addr show 2>/dev/null")) if ns else {}
    built = [t for t, _ in iosl2.svis(con.lab, sw)]
    rows = []
    for name, addr, isup in con.svis():
        tag = int(name[4:])
        state = "up/up" if isup and addr else "up/down" if isup else "administratively down/down"
        rows.append(f"{name:<23}[{state}]")
        got = have.get(f"{ns}n{built.index(tag)}", []) if ns and tag in built else []
        if not got:
            rows.append("    unassigned")
        for a in sorted(got, key=lambda a: (a["scope"] != "link", int(a["addr"]))):
            rows.append(f"    {up(a['addr'])}")
    return "\n".join(rows)


def sw_ping(con, text: str) -> str:
    from . import devcli, iosl2
    a = _v6(text)
    ns = iosl2.netns(con.lab, devcli.switch_id(con.device))
    if not ns:
        return (f"Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to {up(a)}, timeout is 2 seconds:\n"
                ".....\nSuccess rate is 0 percent (0/5)")
    res = con._on_router(f"ip netns exec {ns} ping -c 5 -W 2 {a} 2>&1", timeout=20)
    return devcli.format_ping(up(a), res)


def add_switch_specs(con, add, U, C, I) -> None:
    """A switch's IPv6 management address (winlab/devcli.py)."""
    _register_words()
    add("ipv6 address <line>", lambda a: _sw_address(con, a[0], True), "Configure IPv6 address on interface", I)
    add("no ipv6 address", lambda a: _sw_address(con, "", False), "Negate a command or set its defaults", I)
    add("no ipv6 address <line>", lambda a: _sw_address(con, a[0], False), "Negate a command or set its defaults", I)
    add("show ipv6 interface brief", lambda a: sw_show_brief(con), "Brief summary of IPv6 status and configuration", U)
    add("ping ipv6 <ip>", lambda a: sw_ping(con, a[0]), "IPv6 echo", U)


def sw_iface_lines(own: dict, tag: int) -> list[str]:
    out = [f" ipv6 address {up(a.network)} eui-64" if e else f" ipv6 address {up(a)}" for a, e in sw_addrs(own, tag)]
    if own.get(f"v6svi-auto:{tag}"):
        out.append(" ipv6 address autoconfig")
    return out


# ------------------------------------------------------------------ the troubleshooting drill
def _faults():
    from .guestfaults import LINUX, GuestFault
    conf = "/etc/sysctl.d/60-ipv6-hardening.conf"
    return [
        GuestFault(
            id="ipv6-forwarding-off",
            images=("ubuntu",),
            title="The workshop is unreachable over IPv6, though the router next to it answers",
            os=LINUX,
            teaches="that a router forwards IPv6 only when told to (ipv6 unicast-routing on IOS, "
                    "net.ipv6.conf.all.forwarding on Linux), that a host's own addresses keep answering while "
                    "it forwards nothing, finding the hop where a traceroute stops, and that a setting in "
                    "/etc/sysctl.d comes back at every boot",
            symptom="from the lab router's console ping ipv6 to the Ubuntu router's own address answers, but "
                    "ping and traceroute to the PC behind it stop at that router; IPv4 still works",
            apply=("command -v vtysh >/dev/null 2>&1 || { echo 'no FRRouting on this machine: build the IPv6 "
                   "routes first (lesson ipv6-static-routes)'; exit 1; }; "
                   "[ \"$(sysctl -n net.ipv6.conf.all.forwarding)\" = 1 ] || { echo 'this machine does not forward "
                   "IPv6 yet: build it first (lesson ipv6-static-routes)'; exit 1; }; "
                   f"printf '# IPv6 hardening baseline\\nnet.ipv6.conf.all.forwarding = 0\\n' > {conf}; "
                   "sysctl -qw net.ipv6.conf.all.forwarding=0; echo broken"),
            clear=f"rm -f {conf}; sysctl -qw net.ipv6.conf.all.forwarding=1; echo ok",
            shell="sh",
            hints=(
                "From the lab router's console: traceroute ipv6 to the PC's address. The last hop that answers is "
                "the router that stopped forwarding. ping ipv6 to that router's own address still answers: a "
                "router that does not forward is still a healthy host.",
                "On that Ubuntu router: sysctl net.ipv6.conf.all.forwarding. 0 means it is a host for IPv6, as an "
                "IOS router without ipv6 unicast-routing is. Then grep -r forwarding /etc/sysctl.d to see what set "
                "it, and whether it comes back at the next boot.",
                "Remove the line that sets it to 0 (or the file), then sudo sysctl --system, or set "
                "net.ipv6.conf.all.forwarding=1 in your own file. traceroute ipv6 from the console reaches the PC "
                "again.",
            ),
            verify=("[ \"$(sysctl -n net.ipv6.conf.all.forwarding)\" = 1 ] && ! grep -rqsE "
                    "'^\\s*net\\.ipv6\\.conf\\.all\\.forwarding\\s*=\\s*0' /etc/sysctl.d /etc/sysctl.conf "
                    "&& echo True || echo False"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
