"""Topology compiler: lab model -> links, addresses and fabric config.

Node NICs are QEMU `socket` netdevs: L2 point-to-point links over loopback TCP.
No TAP driver and no user-mode NIC is ever created, so no lab machine has a path
to the host or the internet.

A socket netdev is strictly point-to-point, so the shared broadcast domains come
from the fabric VM: one VLAN-aware Linux bridge, every node link a tagged port on
it, one SVI per segment for routing.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field

from .model import Impairment, Lab, Network, stable_mac, stable_port

ACCESS = "access"
TRUNK = "trunk"

BRIDGE = "lab0"
AUTO_VID_BASE = 100


@dataclass
class Link:
    """One P2P L2 cable between a node NIC and a fabric bridge port."""

    node_id: str
    nic_index: int
    network_id: str
    mac: str
    port: int
    fabric_iface: str
    mode: str = ACCESS
    trunk_vlans: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.node_id}:nic{self.nic_index}"

    @property
    def plugged(self) -> bool:
        return bool(self.network_id)


PARK_VID_BASE = 2000


def park_vid(port: int) -> int:
    """The VLAN an empty network port sits in on the router's switch: one of
    its own, so a card with no cable reaches nothing, and still a port, so a
    cable can go in while everything runs."""
    return PARK_VID_BASE + (port - 29000) % 2000


@dataclass
class SegmentPlan:
    network: Network
    vid: int = 0
    members: list[Link] = field(default_factory=list)
    serves_dhcp: bool = False
    relay_to: list[str] = field(default_factory=list)
    relay_via: str = ""

    @property
    def svi(self) -> str:
        return f"{BRIDGE}.{self.vid}"


@dataclass
class TopologyPlan:
    lab: Lab
    # Every network card's cable to the router's switch, plugged or not
    # (what QEMU and the router are built from) ...
    ports: list[Link] = field(default_factory=list)
    segments: dict[str, SegmentPlan] = field(default_factory=dict)
    # A network on a switch cabled to another switch, to the segment it is
    # part of there (Lab.segment_id): it has no segment of its own.
    joined: dict[str, str] = field(default_factory=dict)
    fabric_cpus: int = 1
    fabric_memory_mb: int = 512
    # The ports the running router was started with or given since, by
    # label; a port missing here is one a running router does not have yet.
    pinned: dict[str, dict] = field(default_factory=dict)

    @property
    def links(self) -> list[Link]:
        """... and the ones with a cable in, which is what addresses, DHCP,
        roles and the map work from."""
        return [l for l in self.ports if l.plugged]

    def links_for(self, node_id: str) -> list[Link]:
        return [l for l in self.links if l.node_id == node_id]

    def ports_for(self, node_id: str) -> list[Link]:
        return [l for l in self.ports if l.node_id == node_id]

    def segment_of(self, network_id: str) -> SegmentPlan:
        return self.segments[self.joined.get(network_id, network_id)]

    @property
    def fabric_link_count(self) -> int:
        return len(self.ports)

    def vid_of(self, link: Link) -> int:
        return self.segment_of(link.network_id).vid if link.plugged else park_vid(link.port)


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _allocate_port(lab_name: str, node_id: str, index: int, taken: set[int]) -> int:
    probe = stable_port(lab_name, node_id, index)
    for _ in range(2000):
        if probe not in taken and _port_is_free(probe):
            taken.add(probe)
            return probe
        probe = 29000 + ((probe - 29000 + 1) % 2000)
    raise RuntimeError("no free loopback port available for the fabric links")


def _assign_vids(lab: Lab, segments: dict[str, SegmentPlan],
                 fixed: dict[str, int] | None = None) -> None:
    """Declared VLAN ids win; segments that omit one get a stable auto id so
    that every segment is a real VLAN either way. `fixed` holds the ids a
    running router already uses, which a switch added since must not take."""
    fixed = fixed or {}
    declared = {s.network.vlan for s in segments.values() if s.network.vlan}
    for vid in declared:
        if not 1 <= vid <= 4094:
            raise ValueError(f"vlan id {vid} is outside the valid 1-4094 range")
    declared |= {v for k, v in fixed.items() if k in segments}

    next_auto = AUTO_VID_BASE
    for seg in sorted(segments.values(), key=lambda s: s.network.id):
        if seg.network.vlan:
            seg.vid = seg.network.vlan
            continue
        if seg.network.id in fixed:
            seg.vid = fixed[seg.network.id]
            continue
        while next_auto in declared:
            next_auto += 1
        seg.vid = next_auto
        declared.add(next_auto)
        next_auto += 1


def compile_topology(lab: Lab, check_ports: bool = True) -> TopologyPlan:
    plan = TopologyPlan(lab=lab)
    if not check_ports:
        # The router is running: its ports keep the numbers, names and VLANs
        # it was started with (winlab/livenet.py), whatever was added since.
        from . import livenet
        plan.pinned = livenet.pinned_ports(lab.name)
    fixed_vids = {}
    if plan.pinned:
        from . import livenet
        fixed_vids = livenet.pinned_vids(lab.name)

    for net in lab.networks.values():
        seg_id = lab.segment_id(net.id)
        if seg_id == net.id:
            plan.segments[net.id] = SegmentPlan(network=net)
        else:
            plan.joined[net.id] = seg_id
    _assign_vids(lab, plan.segments, fixed_vids)

    taken: set[int] = {int(p["port"]) for p in plan.pinned.values()}
    iface_index = 1  # eth0 on the fabric is its own management/console nic

    for node in lab.node_list():
        for idx, nic in enumerate(node.nics):
            pin = plan.pinned.get(f"{node.id}:nic{idx}")
            if pin:
                port = int(pin["port"])
            elif check_ports or plan.pinned:
                # A port the running router does not have yet must be one
                # nothing on this PC listens on, so it can be added live.
                port = _allocate_port(lab.name, node.id, idx, taken)
            else:
                port = stable_port(lab.name, node.id, idx)
                while port in taken:
                    port = 29000 + ((port - 29000 + 1) % 2000)
                taken.add(port)

            if not nic.mac:
                nic.mac = stable_mac(lab.name, node.id, idx)

            trunk = [n for n in getattr(nic, "trunk", []) if n in lab.networks]
            link = Link(
                node_id=node.id,
                nic_index=idx,
                network_id=nic.network if nic.network in lab.networks else "",
                mac=nic.mac,
                port=port,
                fabric_iface=(str(pin.get("iface", "")) if pin
                              else "" if plan.pinned else f"eth{iface_index}"),
                mode=TRUNK if trunk else ACCESS,
                trunk_vlans=trunk,
            )
            iface_index += 1
            plan.ports.append(link)
            if link.plugged:
                plan.segment_of(link.network_id).members.append(link)

    _plan_services(lab, plan)
    _size_fabric(plan)
    return plan


def _plan_services(lab: Lab, plan: TopologyPlan) -> None:
    """Decide, per segment, whether the router hands out addresses or relays
    to a DHCP server. The router serves a pool only when one was set up on it
    (`ip dhcp pool` on its console, or `dhcp = true` for an ISP's handoff in
    the lab file); a segment with neither a pool nor a server gets nothing,
    and its machines sit on 169.254 addresses until the student builds one,
    as on a real LAN with no DHCP server."""
    servers: list[tuple[str, str]] = []  # (segment_id, address)
    for node in lab.nodes.values():
        if "dhcp" not in node.roles:
            continue
        for nic in node.nics:
            if nic.ip:
                servers.append((plan.joined.get(nic.network, nic.network), nic.ip))

    for seg in plan.segments.values():
        net = seg.network
        wants = any(
            nic.dhcp
            for node in lab.nodes.values()
            for nic in node.nics
            if plan.joined.get(nic.network, nic.network) == net.id
        )
        if not wants:
            # Laptops on the real air (winlab/vwifi.py): their wlan0 asks
            # here, through the AP, with no lab card on the segment.
            from . import vwifi
            wants = vwifi.wants_dhcp(lab, net.id)
        if not wants or not net.routed:
            # A switch the router is not cabled to: only a server on the
            # switch itself can hand out addresses there.
            continue

        if net.dhcp:
            seg.serves_dhcp = True
            continue

        local = [addr for seg_id, addr in servers if seg_id == net.id]
        if local:
            # Server shares the broadcast domain; no relay needed.
            continue

        remote = [(seg_id, addr) for seg_id, addr in servers if seg_id != net.id]
        if remote:
            seg.relay_to = [addr for _, addr in remote]
            seg.relay_via = plan.segment_of(remote[0][0]).svi


# The router-and-switches machine grows with its port count, as a bigger
# switch has a bigger CPU: (up to this many ports, vCPUs, MB). Its memory is
# Alpine running from RAM with its packages (roughly 250 MB) plus each port's
# buffers and the bridge's tables; its vCPUs carry the forwarding, the
# spanning tree and the routing daemons, and every busy port's interrupts.
# QEMU itself adds about 1 MB per port on this PC's side (measured: 42 MB
# with no ports, 70 MB with 24), which membudget's per-machine overhead covers.
FABRIC_SIZES = ((8, 1, 512), (16, 2, 768), (32, 3, 1024))
FABRIC_MAX = (4, 1280)


def _size_fabric(plan: TopologyPlan) -> None:
    n = plan.fabric_link_count
    cpus, mb = next(((c, m) for top, c, m in FABRIC_SIZES if n <= top), FABRIC_MAX)
    # never more vCPUs than this PC has threads
    plan.fabric_cpus = max(1, min(cpus, os.cpu_count() or 1))
    plan.fabric_memory_mb = mb


# --------------------------------------------------------------------------
# Fabric guest configuration
# --------------------------------------------------------------------------


def render_fabric_setup(plan: TopologyPlan) -> str:
    """Shell script executed inside the fabric VM at boot.

    Deliberately plain iproute2/bridge/tc/nftables commands rather than a
    config file format, so a student can read it and see exactly what a
    switch-router is doing.
    """
    lab = plan.lab
    out: list[str] = [
        "#!/bin/sh",
        "# generated by winlab -- regenerate with 'winlab lab plan --fabric-script'",
        f"# lab: {lab.name}",
        "",
        "# pgrep, pkill and pidof keep to this VM's own processes, never another router's (winlab/routers.py)",
        __import__("winlab.routers", fromlist=["SHELL_GUARD"]).SHELL_GUARD,
        "",
        "sysctl -w net.ipv4.ip_forward=1 >/dev/null",
        "sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null",
        "# IPv6 is not the lab router's until its console says ipv6 unicast-routing",
        "# (winlab/iosv6.py): it forwards none and takes no address from a router",
        "# advertisement, so IPv6 crosses only routers the student builds",
        "sysctl -qw net.ipv6.conf.all.forwarding=0 2>/dev/null || true",
        "sysctl -qw net.ipv6.conf.default.accept_ra=0 2>/dev/null || true",
        "sysctl -qw net.ipv6.conf.default.autoconf=0 2>/dev/null || true",
        "",
        "### vlan-aware switch",
        f"ip link del {BRIDGE} 2>/dev/null || true",
        "# multicast floods to every port of the VLAN, as on an office switch with no",
        "# IGMP querier: network discovery (LLMNR, mDNS, SSDP, WS-Discovery) finds the",
        "# other PCs on the LAN",
        f"ip link add name {BRIDGE} type bridge vlan_filtering 1 vlan_default_pvid 0",
        f"ip link set {BRIDGE} type bridge mcast_snooping 0 2>/dev/null || true",
        f"ip link set {BRIDGE} up",
        "",
        "### ports",
    ]

    for link in plan.ports:
        if not link.plugged:
            out.append(f"ip link set {link.fabric_iface} up")
            out.append(f"ip link set {link.fabric_iface} master {BRIDGE}")
            out.append(f"bridge vlan del dev {link.fabric_iface} vid 1 2>/dev/null || true")
            out.append(f"bridge vlan add dev {link.fabric_iface} vid {park_vid(link.port)} pvid untagged"
                       f"   # {link.label}: no cable")
            continue
        seg = plan.segment_of(link.network_id)
        out.append(f"ip link set {link.fabric_iface} up")
        out.append(f"ip link set {link.fabric_iface} master {BRIDGE}")
        out.append(f"bridge vlan del dev {link.fabric_iface} vid 1 2>/dev/null || true")
        if link.mode == TRUNK:
            carried = [seg.vid] + [plan.segment_of(n).vid for n in link.trunk_vlans]
            out.append(
                f"bridge vlan add dev {link.fabric_iface} vid {seg.vid} pvid untagged"
                f"   # {link.label} native"
            )
            for vid in sorted(set(carried) - {seg.vid}):
                out.append(
                    f"bridge vlan add dev {link.fabric_iface} vid {vid}"
                    f"   # {link.label} tagged"
                )
        else:
            out.append(
                f"bridge vlan add dev {link.fabric_iface} vid {seg.vid} pvid untagged"
                f"   # {link.label} -> {link.network_id}"
            )
    out.append("")

    out.append("### gateways (one svi per vlan)")
    for seg in sorted(plan.segments.values(), key=lambda s: s.vid):
        net = seg.network
        out.append(f"# {net.id}: {net.cidr} vlan {seg.vid}")
        out.extend(svi_lines(seg))
    out.append("")

    # The other routers: each a network stack of its own (winlab/routers.py),
    # before the SSH servers that listen inside them (winlab/iosssh.py).
    from . import routers
    out.extend(routers.render(plan))
    out.extend(_render_sites(plan))
    out.extend(_render_impairment(plan))
    from . import wan
    out.extend(wan.render(plan))
    from . import power  # servers' management ports and the Wake-on-LAN listener
    out.extend(power.render(plan))
    from . import stp  # switches cabled to switches: kernel bridges running spanning tree
    out.extend(stp.render(plan))
    from . import nms  # snmpd and chrony as the consoles set them (snmp-server, ntp server)
    out.extend(nms.render(plan))
    from . import portsec  # port security and 802.1X on the access ports
    out.extend(portsec.render(plan))
    from . import wpaent  # WPA2-Enterprise: 802.1X on the laptops' wireless ports
    out.extend(wpaent.render(plan))
    from . import vwifi  # real 802.11 for the Linux laptops: vwifi-server on the hidden air VLAN
    out.extend(vwifi.render(plan))
    out.extend(_render_dhcp(plan))
    out.extend(_render_firewall(plan))
    from . import iosl3  # static routes, access lists and NAT typed at the router's console
    out.extend(iosl3.render(plan))
    from . import iosrouting  # OSPF, BGP, VRFs and VRRP typed at the router's console (FRRouting)
    out.extend(iosrouting.render(plan))
    from . import iosl2  # the switches' management addresses, port speeds, trunks to the router
    out.extend(iosl2.render(plan))
    from . import routerpolicy  # tunnels and IPsec, the zone firewall and QoS typed at the router's console
    out.extend(routerpolicy.render(plan))
    from . import vswitch  # internal and external virtual switches: the router's way to this PC and out
    out.extend(vswitch.render(plan))
    out.extend(dark_lines(plan))  # a switch that is off: its router interface has no link

    out.append("echo 'winlab fabric ready' > /dev/kmsg 2>/dev/null || true")
    out.append("")
    return "\n".join(out)


def svi_lines(seg: SegmentPlan) -> list[str]:
    """The router's interface on a segment, or, for a switch the router is
    not cabled to, none: the VLAN exists only on the switch ports."""
    net = seg.network
    if not net.routed:
        return [f"# {net.id} is not cabled to the router: switch ports only"]
    return [
        f"bridge vlan add dev {BRIDGE} vid {seg.vid} self",
        f"ip link add link {BRIDGE} name {seg.svi} type vlan id {seg.vid}",
        f"ip addr replace {net.router_ip}/{net.prefixlen} dev {seg.svi}",
        f"ip link set {seg.svi} up",
    ]


def dark_svis(plan: TopologyPlan) -> dict[str, str]:
    """The router's interfaces whose switch is powered off, svi -> network:
    no link, so no connected route (winlab/devcli.py switch_off). The
    switches cabled below one are cut off it by Lab.segment_id."""
    from .devcli import switch_off
    return {seg.svi: sid for sid, seg in sorted(plan.segments.items())
            if seg.network.routed and switch_off(plan.lab, seg.network.home)}


def dark_lines(plan: TopologyPlan, was: dict[str, str] | None = None) -> list[str]:
    """Takes those interfaces down, last thing in a script; `was` (the ones
    dark before) come back up when their switch is on again."""
    dark = dark_svis(plan)
    back = [svi for svi in (was or {}) if svi not in dark]
    if not dark and not back:
        return []
    out = ["### switches powered off: the router's interface toward each has no link"]
    out += [f"ip link set {svi} down 2>/dev/null || true   # {sid}" for svi, sid in dark.items()]
    out += [f"ip link set {svi} up 2>/dev/null || true   # {was[svi]}: its switch is on again" for svi in back]
    return out + [""]


def site_table(lab: Lab, site: str) -> int:
    """The policy-routing table a site's segments look up first."""
    ids = sorted(lab.sites)
    return 100 + ids.index(site)


INTERNET_TABLE = 99
"""The table a wan segment's traffic looks up first: every site's prefix is
a blackhole there, because the Internet has no route to private networks;
a site is reached from outside only through its gateway's outside address
(a tunnel, a port forward), as it is in life."""


def _render_sites(plan: TopologyPlan) -> list[str]:
    """Sites only meet through their gateways: packets entering the router
    from a site's segment look up that site's table first, where every other
    site's prefix points at this site's gateway machine (or is a blackhole
    when the site has none); everything else falls through to the main
    table, so routing inside a site is unchanged."""
    from . import sites
    lab = plan.lab
    if not lab.sites:
        return []
    # Azure virtual networks (winlab/azure.py): peered ones reach each other
    # directly; a VPN gateway carries only what its connection names.
    from . import azure as _azure
    peers = _azure.peered_sites(lab)
    reach = _azure.gateway_reach(lab)
    transit = _azure.transit_sites(lab)
    out = ["### sites: routed freely inside a site; other sites only through the gateway",
           "# (policy routing by ingress interface, one table per site; see 'winlab lab plan')"]
    for site in sorted(lab.sites.values(), key=lambda x: x.id):
        table = site_table(lab, site.id)
        gw = sites.gateway_of(lab, site.id)
        via_site = site.id
        if gw is None and site.id in transit:
            # a spoke that uses its hub's VPN gateway (gateway transit)
            gw, via_site = sites.gateway_of(lab, transit[site.id]), transit[site.id]
        out.append(f"# {site.id}: table {table}"
                   + (f", gateway {gw.node.id} at {gw.inside_ip}" if gw else ", no gateway"))
        out.append(f"ip route flush table {table} 2>/dev/null || true")
        for other in sorted(lab.sites.values(), key=lambda x: x.id):
            if other.id == site.id:
                continue
            for onet in sites.networks_of(lab, other.id):
                cidr = onet.cidr
                if (site.id, other.id) in peers and onet.id in plan.segments:
                    out.append(f"ip route add {cidr} dev {plan.segment_of(onet.id).svi} table {table}"
                               f"   # {other.id}: peered")
                elif gw and other.id != via_site and (via_site not in reach or _azure.within(cidr, reach[via_site])):
                    dev = plan.segment_of(gw.inside_network).svi
                    out.append(f"ip route add {cidr} via {gw.inside_ip} dev {dev} table {table}"
                               f"   # {other.id} via {gw.node.id}")
                else:
                    out.append(f"ip route add blackhole {cidr} table {table}   # {other.id}: unreachable")
        for net in sites.networks_of(lab, site.id):
            svi = plan.segment_of(net.id).svi
            out.append(f"ip rule add iif {svi} lookup {table} priority {1000 + table}")
            # The gateway shares a VLAN with the machines it serves; without
            # this the router would send them ICMP redirects to bypass it.
            out.append(f"sysctl -qw net.ipv4.conf.{svi}.send_redirects=0 || true")
    wans = [n for n in sorted(lab.networks.values(), key=lambda x: (x.net, x.id)) if n.wan and n.id in plan.segments]
    prefixes = [c for site in sorted(lab.sites) for c in sites.prefixes_of(lab, site)]
    if wans and prefixes:
        out.append(f"# the Internet (wan segments): table {INTERNET_TABLE}, no route to any site's "
                   f"prefixes; only the gateways' outside addresses are reachable from there")
        out.append(f"ip route flush table {INTERNET_TABLE} 2>/dev/null || true")
        for cidr in prefixes:
            out.append(f"ip route add blackhole {cidr} table {INTERNET_TABLE}   # private: unroutable from the Internet")
        for net in wans:
            out.append(f"ip rule add iif {plan.segment_of(net.id).svi} lookup {INTERNET_TABLE} "
                       f"priority {1000 + INTERNET_TABLE}")
    out.append("")
    return out


def _render_impairment(plan: TopologyPlan) -> list[str]:
    """netem goes on the SVI, so it conditions traffic routed INTO the segment
    and leaves traffic switched within the segment at full speed."""
    out: list[str] = []
    for seg in sorted(plan.segments.values(), key=lambda s: s.vid):
        imp: Impairment = seg.network.impair
        if not imp.active or not seg.network.routed:
            continue
        dev = seg.svi
        out.append(f"### impairment routed into {seg.network.id} (intra-segment stays fast)")
        out.append(f"tc qdisc del dev {dev} root 2>/dev/null || true")
        if imp.rate_mbit:
            out.append(
                f"tc qdisc add dev {dev} root handle 1: tbf rate {imp.rate_mbit}mbit "
                f"burst 32kbit latency 400ms || true"
            )
            parent = "parent 1:1 handle 10:"
        else:
            parent = "root"
        netem = f"tc qdisc add dev {dev} {parent} netem"
        if imp.delay_ms:
            netem += f" delay {imp.delay_ms}ms"
            if imp.jitter_ms:
                netem += f" {imp.jitter_ms}ms distribution normal"
        if imp.loss_pct:
            netem += f" loss {imp.loss_pct}%"
        out.append(netem + " || true")
        out.append("")
    return out


def _render_dhcp(plan: TopologyPlan) -> list[str]:
    """dnsmasq on the fabric: a DHCP server on the segments given a pool and a relay on the segments whose server sits elsewhere
    (dnsmasq's own dhcp-relay, since ISC's dhcrelay is no longer an Alpine
    package). DNS stays off (port=0): the lab's DNS is the DC's."""
    out: list[str] = []
    serving = [s for s in plan.segments.values() if s.serves_dhcp]
    # ip helper-address typed on the router (winlab/imaging.py): a PXE client's
    # broadcast also goes to the WDS server; a pool the router serves wins, as on IOS.
    from .imaging import helpers
    helped = {s.network.id: helpers(plan.lab, s.network.id) for s in plan.segments.values() if not s.serves_dhcp}
    relaying = [s for s in plan.segments.values() if s.relay_to or helped.get(s.network.id)]
    # Azure's own DHCP on a virtual network's subnets (winlab/azure.py): each
    # VM's NIC gets the address the platform gave it, reserved by its MAC.
    from .azure import azure_dhcp, vnet_dns
    az = {k: v for k, v in azure_dhcp(plan.lab).items() if k in plan.segments}
    if not serving and not relaying and not az:
        return out

    conf = "/etc/dnsmasq.d/winlab.conf"
    out.append("### fabric DHCP service and relays (dnsmasq)")
    out.append("mkdir -p /etc/dnsmasq.d")
    out.append(f": > {conf}")
    out.append(f"printf 'bind-interfaces\\nno-resolv\\nport=0\\n' >> {conf}")
    for seg in sorted(serving, key=lambda s: s.vid):
        net = seg.network
        opts = pool_options(plan.lab, net)
        out.append(f"printf 'interface={seg.svi}\\n' >> {conf}")
        for lo, hi in pool_ranges(plan.lab, net):
            out.append(
                f"printf 'dhcp-range={seg.svi},{lo},{hi},{net.netmask},{opts['lease']}\\n' >> {conf}"
            )
        # What the pool hands out is what its options say (on the router's
        # console: default-router, dns-server, domain-name); a lab file's
        # pool gives the gateway, the domain's DNS and its name.
        if opts["router"]:
            out.append(f"printf 'dhcp-option={seg.svi},3,{','.join(opts['router'])}\\n' >> {conf}")
        else:
            out.append(f"printf 'dhcp-option={seg.svi},3\\n' >> {conf}")
        if opts["dns"]:
            out.append(
                f"printf 'dhcp-option={seg.svi},6,{','.join(opts['dns'])}\\n' >> {conf}"
            )
        if opts["domain"]:
            out.append(
                f"printf 'dhcp-option={seg.svi},15,{opts['domain']}\\n' >> {conf}"
            )
        # PXE, as typed into the router's console (next-server, bootfile):
        # siaddr and file in the reply, and options 66/67 for the same.
        own = plan.lab.devices.get("router", {})
        server, name = own.get(f"next:{net.id}", ""), own.get(f"file:{net.id}", "")
        if server or name:
            out.append(f"printf '%s\\n' 'dhcp-boot=tag:{seg.svi},{name},,{server}' >> {conf}")
            if server:
                out.append(f"printf '%s\\n' 'dhcp-option={seg.svi},66,{server}' >> {conf}")
            if name:
                out.append(f"printf '%s\\n' 'dhcp-option={seg.svi},67,{name}' >> {conf}")
    for seg in sorted(relaying, key=lambda s: s.vid):
        targets = sorted(set(seg.relay_to) | set(helped.get(seg.network.id, [])))
        out.append(f"### DHCP relay: {seg.network.id} -> {', '.join(targets)} via {seg.relay_via}")
        out.append(f"printf 'interface={seg.svi}\\n' >> {conf}")
        for target in targets:
            # Requests arriving on the segment's SVI go to the server as unicast
            # with the SVI address as giaddr, so the server picks that scope.
            out.append(f"printf 'dhcp-relay={seg.network.router_ip},{target}\\n' >> {conf}")
    for nid, hosts in sorted(az.items()):
        seg = plan.segment_of(nid)
        net = seg.network
        out.append(f"### Azure DHCP: {nid} (each NIC's address, reserved by MAC)")
        out.append(f"printf 'interface={seg.svi}\\n' >> {conf}")
        out.append(f"printf 'dhcp-range={seg.svi},{net.net.network_address},static,{net.netmask},infinite\\n' >> {conf}")
        out.append(f"printf 'dhcp-option={seg.svi},3,{net.router_ip}\\n' >> {conf}")
        dns = vnet_dns(plan.lab, nid)
        if dns:
            out.append(f"printf 'dhcp-option={seg.svi},6,{','.join(dns)}\\n' >> {conf}")
        out.append(f"printf 'dhcp-option={seg.svi},15,internal.cloudapp.example\\n' >> {conf}")
        for mac, ip in hosts:
            out.append(f"printf 'dhcp-host={mac},{ip}\\n' >> {conf}")
    out.append("rc-service dnsmasq restart 2>/dev/null || dnsmasq -C " + conf + " || true")
    out.append("")
    return out


def dhcp_range(net: Network) -> tuple[str, str]:
    """The pool the fabric hands out on a segment of a lab file's own: hosts
    50 to 149, clear of the static addresses labs put low in the subnet."""
    hosts = list(net.net.hosts())
    return str(hosts[min(49, len(hosts) - 2)]), str(hosts[min(148, len(hosts) - 1)])


def _pool_name(lab: Lab, net: Network) -> str:
    own = lab.devices.get("router", {})
    return next((k[5:] for k, v in sorted(own.items()) if k.startswith("pool:") and v == net.id), "")


def pool_ranges(lab: Lab, net: Network) -> list[tuple[str, str]]:
    """The addresses the router hands out on a network, as runs (lo, hi). A
    pool typed at the console hands out its whole subnet but the router's
    own address and what `ip dhcp excluded-address` keeps back, as IOS does;
    a lab file's pool (no excluded addresses typed) keeps to hosts 50-149."""
    own = lab.devices.get("router", {})
    excl = []
    for k, v in own.items():
        if k.startswith("dhcp-excl:"):
            try:
                excl.append((int(ipaddress.IPv4Address(k[10:])), int(ipaddress.IPv4Address(v))))
            except ValueError:
                continue
    if not lab.workbench and not excl:
        return [dhcp_range(net)]
    hosts = [int(h) for h in net.net.hosts()]
    gw = {int(ipaddress.IPv4Address(net.router_ip))}
    free = [h for h in hosts if h not in gw and not any(lo <= h <= hi for lo, hi in excl)]
    runs: list[tuple[str, str]] = []
    start = prev = None
    for h in free:
        if start is None:
            start = prev = h
        elif h == prev + 1:
            prev = h
        else:
            runs.append((str(ipaddress.IPv4Address(start)), str(ipaddress.IPv4Address(prev))))
            start = prev = h
    if start is not None:
        runs.append((str(ipaddress.IPv4Address(start)), str(ipaddress.IPv4Address(prev))))
    return runs


def pool_options(lab: Lab, net: Network) -> dict:
    """What a pool hands out besides an address: its gateways (option 3),
    DNS servers (6), domain name (15) and lease. A pool typed in a workbench
    lab hands out only what was typed (IOS's default lease, a day); a lab
    file's pool gives the network's gateway, the domain's DNS servers and
    its name, for 8 hours."""
    own = lab.devices.get("router", {})
    name = _pool_name(lab, net)
    typed = lambda k: own.get(f"{k}:{name}", "") if name else ""  # noqa: E731
    lease = typed("poollease")
    if lease == "infinite":
        secs = "infinite"
    elif lease:
        d, h, m = (list(map(int, lease.split())) + [0, 0])[:3]
        secs = str(d * 86400 + h * 3600 + m * 60)
    else:
        secs = "86400" if lab.workbench else "8h"
    if lab.workbench:
        return {"router": typed("poolgw").split(), "dns": typed("pooldns").split(),
                "domain": typed("pooldom"), "lease": secs}
    plan_dns = _dns_for(TopologyPlan(lab=lab), net)
    return {"router": typed("poolgw").split() or [net.default_gateway],
            "dns": typed("pooldns").split() or plan_dns,
            "domain": typed("pooldom") or lab.domain, "lease": secs}


def dhcp_mode(plan: TopologyPlan, seg: SegmentPlan) -> str:
    """How machines on a segment get addresses: ``fabric`` (a pool on the
    router), ``relay`` (forwarded to a Windows DHCP server elsewhere),
    ``server`` (a Windows DHCP server on the segment itself) or ``static``
    (by hand, or nothing until the student builds a DHCP server)."""
    if seg.serves_dhcp:
        return "fabric"
    if seg.relay_to:
        return "relay"
    for node in plan.lab.nodes.values():
        if "dhcp" in node.roles and any(n.network == seg.network.id for n in node.nics):
            return "server"
    return "static"


def dns_for(plan: TopologyPlan, net: Network) -> list[str]:
    """The DNS servers a segment's DHCP clients are pointed at."""
    return _dns_for(plan, net)


def _dns_for(plan: TopologyPlan, net: Network) -> list[str]:
    """Domain members must resolve against a domain controller, never a public
    resolver. Pointing a member at the wrong DNS server is the single most
    common way to break an AD lab, so the fabric never offers itself."""
    same_segment: list[str] = []
    same_site: list[str] = []
    elsewhere: list[str] = []
    for node in plan.lab.nodes.values():
        if "dns" not in node.roles and "ad-ds" not in node.roles:
            continue
        for nic in node.nics:
            if not nic.ip:
                continue
            if nic.network == net.id:
                same_segment.append(nic.ip)
            elif net.site and plan.lab.networks[nic.network].site == net.site:
                same_site.append(nic.ip)
            else:
                elsewhere.append(nic.ip)
    return same_segment + same_site + elsewhere


def svi_of(plan: TopologyPlan) -> dict[str, str]:
    """segment id -> the router interface (svi) that serves it."""
    return {seg.network.id: seg.svi for seg in plan.segments.values()}


def _render_firewall(plan: TopologyPlan) -> list[str]:
    if plan.lab.firewall.enabled:
        from . import firewall
        return (["### zone firewall (Azure NSG model: one table per segment and direction,",
                 "# lowest priority first, first match decides; counters per rule)",
                 "nft -f - <<'EOF' || true"]
                + firewall.render_nft(plan.lab, svi_of(plan)) + ["EOF", ""])
    return _render_firewall_off(plan)


def _render_firewall_off(plan: TopologyPlan) -> list[str]:
    wan = [s for s in plan.segments.values() if s.network.wan]
    if not wan:
        return []
    out = [
        "### zones",
        "# The wan segment is a simulated ISP edge. It is still entirely inside",
        "# the lab: there is no interface here that reaches the host or internet.",
        "nft -f - <<'EOF' || true",
        "table inet winlab {",
        "  chain forward {",
        "    type filter hook forward priority 0; policy accept;",
    ]
    for seg in wan:
        out.append(f"    iifname \"{seg.svi}\" ct state new counter comment \"inbound from wan\"")
    out.extend(["  }", "}", "EOF", ""])
    return out


# --------------------------------------------------------------------------
# Human-readable plan output
# --------------------------------------------------------------------------


def describe(plan: TopologyPlan) -> str:
    lab = plan.lab
    lines: list[str] = []
    lines.append(f"lab        {lab.name}")
    if lab.description:
        lines.append(f"           {lab.description}")
    lines.append(f"domain     {lab.domain}  (netbios {lab.netbios})")
    lines.append(
        f"footprint  {len(lab.nodes)} nodes + 1 fabric, "
        f"{lab.total_cpus() + plan.fabric_cpus} vcpu, "
        f"{(lab.total_memory_mb() + plan.fabric_memory_mb) / 1024:.1f} GiB ram"
    )
    win = [n for n in lab.node_list() if n.is_windows]
    stock = [n.id for n in win if not n.lean]
    if win and len(stock) < len(win):
        where = f"  (stock Windows: {', '.join(stock)})" if stock else ""
        lines.append(
            "lean       on: idle services, telemetry, Widgets, OneDrive and Defender "
            f"(on servers no role wants it on) are off; lean = false keeps stock Windows{where}"
        )
    elif win:
        lines.append("lean       off: stock Windows on every machine")
    if lab.sandbox:
        lines.append("free play  no lessons, nothing graded: add machines in Build or "
                     "'winlab node add', break and rebuild at will")
    if lab.firewall.enabled:
        own = len(lab.firewall.rules)
        lines.append(f"firewall   zone firewall on: NSG-style tables on every segment, "
                     f"{own} rule{'s' if own != 1 else ''} of the lab's own plus the defaults "
                     f"('winlab fw {lab.name} list')")
    lines.append("")

    from . import sites as _sites
    site_lines = _sites.describe(lab)
    if site_lines:
        lines.extend(site_lines)
        lines.append("")

    lines.append(f"networks ({BRIDGE}: vlan-aware bridge, one svi per vlan)")
    for seg in sorted(plan.segments.values(), key=lambda s: s.vid):
        net = seg.network
        tags = []
        if net.site:
            tags.append(f"site {net.site}")
        if net.wan:
            tags.append("wan-edge")
        if seg.serves_dhcp:
            tags.append("fabric dhcp")
        if seg.relay_to:
            tags.append(f"dhcp relay -> {','.join(sorted(set(seg.relay_to)))}")
        if not net.routed:
            tags.append("not cabled to the router")
        if net.impair.active:
            bits = []
            if net.impair.delay_ms:
                bits.append(f"{net.impair.delay_ms}ms")
            if net.impair.jitter_ms:
                bits.append(f"+/-{net.impair.jitter_ms}ms")
            if net.impair.loss_pct:
                bits.append(f"{net.impair.loss_pct}% loss")
            if net.impair.rate_mbit:
                bits.append(f"{net.impair.rate_mbit}mbit")
            tags.append("routed-in: " + " ".join(bits))
        suffix = f"   [{'; '.join(tags)}]" if tags else ""
        auto = "" if net.vlan else " (auto)"
        lines.append(
            f"  vlan {seg.vid:<4}{auto:<7} {net.id:<12} {net.cidr:<18} "
            f"gw {net.router_ip:<15} {seg.svi}{suffix}"
        )
        if net.description:
            lines.append(f"  {'':<24} {net.description}")
    lines.append("")

    lines.append("nodes (boot order)")
    from .images import base_virtio
    for node in lab.node_list():
        roles = ",".join(node.roles) if node.roles else "-"
        devices = ""
        if node.is_windows:
            virtio = node.vars.get("virtio") is not False and base_virtio(node.image)
            devices = "  virtio" if virtio else "  emulated nic/disk"
        if node.firmware:  # set in the lab file (winlab/firmware.py)
            from .firmware import TITLES
            devices += f"  firmware: {TITLES.get(node.firmware, node.firmware)}"
        lines.append(
            f"  {node.boot_order:>3}  {node.id:<10} {node.kind:<15} {node.image:<10} "
            f"{node.cpus}c/{node.memory_mb}m  roles: {roles}{devices}"
        )
        for link in plan.links_for(node.id):
            nic = node.nics[link.nic_index]
            addr = nic.ip or "dhcp"
            seg = plan.segment_of(link.network_id)
            port_kind = f"trunk+{len(link.trunk_vlans)}" if link.mode == TRUNK else "access"
            lines.append(
                f"       nic{link.nic_index} {link.network_id:<10} {addr:<15} "
                f"{nic.mac}  -> {link.fabric_iface} "
                f"{port_kind} vlan {seg.vid} (tcp/{link.port})"
            )
    lines.append("")
    from . import vswitch
    if vswitch.active(plan.lab):
        lines.append(
            f"isolation  {plan.fabric_link_count} loopback L2 links, 0 host-bridged nics, "
            f"1 user-mode nic on the router ({vswitch.describe(plan.lab)})"
        )
        return "\n".join(lines)
    lines.append(
        f"isolation  {plan.fabric_link_count} loopback L2 links, 0 host-bridged nics, "
        f"0 user-mode nics -> no path to host or internet"
    )
    return "\n".join(lines)
