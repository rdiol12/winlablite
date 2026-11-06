"""Lab object model. Provider-agnostic."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field

WINDOWS_SERVER = "windows-server"
WINDOWS_CLIENT = "windows-client"
LINUX = "linux"
FABRIC = "fabric"
# Any operating system the user installs by hand from their own ISO (another
# Linux, a firewall appliance, an older Windows). winlab boots it, wires its
# NICs into the lab and snapshots it, but runs no agent or roles inside it.
CUSTOM = "custom"

KINDS = {WINDOWS_SERVER, WINDOWS_CLIENT, LINUX, FABRIC, CUSTOM}

# What a Windows machine's virtual hardware looks like from inside:
#   pc      a regular PC: Intel 82574L network card, Intel ICH9 SATA (AHCI),
#           Intel HD Audio, USB 3 (xHCI), a DVD drive, a standard display;
#           every device has a driver in Windows itself, Device Manager
#           reads like a desktop's. The default.
#   virtio  Red Hat's paravirtual devices (network, disk, memory balloon),
#           less CPU per packet and block, drivers from the virtio-win
#           package the base was prepared with.
HARDWARE_PC = "pc"
HARDWARE_VIRTIO = "virtio"
HARDWARE = {"", HARDWARE_PC, HARDWARE_VIRTIO}

# The least memory a lab may define a machine with: Microsoft's documented
# minimums for Windows (2 GB for Server with Desktop Experience and, with the
# install-time check bypassed, for Windows 11), and a usable floor for Server
# Core (Microsoft documents 2 GB for 2025 and documented 1 GB for 2016-2022;
# a Core machine serving a lab's roles runs at 1 GB, to be confirmed on real
# hardware). The shipped labs define every Windows machine with a desktop at
# 2 GB and the Server Core ones at 1.5 GB: stock Windows runs there, and the
# Low-memory profile (`lean = true` on a lab or a node, the switch in the
# Machines window) makes it comfortable on a small PC.
MIN_MEMORY_MB = {WINDOWS_SERVER: 2048, WINDOWS_CLIENT: 2048, LINUX: 512, FABRIC: 256}
CORE_MIN_MEMORY_MB = 1024
# How far `lab up` may trim an installed machine for one run when the host is
# short. Installation needs the minimum above; a running Server with Desktop
# Experience serving a lab's roles is fine at 1.5 GB, the way Hyper-V Dynamic
# Memory runs it below its startup size. Windows 11 is not trimmed below 2 GB.
TRIM_FLOOR_MB = {WINDOWS_SERVER: 1536, WINDOWS_CLIENT: 2048, LINUX: 512, FABRIC: 256}
# What winlab sets a new machine to, and what "Use recommended" puts back:
# the sizes the shipped labs run on, so a lab built from them fits 8 GB.
RECOMMENDED_MEMORY_MB = {WINDOWS_SERVER: 2048, WINDOWS_CLIENT: 2048, LINUX: 512, CUSTOM: 2048}
RECOMMENDED_CORE_MEMORY_MB = 1536
RECOMMENDED_CPUS = {WINDOWS_SERVER: 2, WINDOWS_CLIENT: 2, LINUX: 1, CUSTOM: 2}


@dataclass
class Impairment:
    """Link conditioning applied on the fabric side of a segment."""

    delay_ms: int = 0
    jitter_ms: int = 0
    loss_pct: float = 0.0
    rate_mbit: int = 0

    @property
    def active(self) -> bool:
        return bool(self.delay_ms or self.jitter_ms or self.loss_pct or self.rate_mbit)


@dataclass
class Network:
    id: str
    cidr: str
    vlan: int | None = None
    gateway: str | None = None
    dhcp: bool = False
    wan: bool = False
    description: str = ""
    # The site this segment belongs to (a [[site]] id), when the lab has
    # several: the router routes freely within a site and sends traffic for
    # another site to that site's gateway machine, so two sites only meet
    # through the WAN and whatever tunnel their gateways build.
    site: str = ""
    impair: Impairment = field(default_factory=Impairment)
    # The machine whose address on this segment is the hosts' default
    # gateway (a firewall appliance between the segment and the rest): the
    # lab router keeps its own address on the segment for DHCP, relaying and
    # the map, but the machines send everything to this one.
    gateway_node: str = ""
    hosts_gateway: str = ""   # resolved by the schema from gateway_node
    # Whether the lab router has an interface on this segment: a switch
    # cabled to the router in the workbench. A segment that is not routed is
    # a switch on its own: its machines reach one another and nothing else,
    # and nobody hands out addresses until a machine on it serves DHCP.
    routed: bool = True
    # A VLAN the student made on a workbench switch's console: the switch
    # (the network it was made on, drawn as one box on the canvas) and the
    # VLAN number typed there. A switch's own network is its VLAN 1.
    switch: str = ""
    tag: int = 0
    # On a switch: the switch its uplink (Gi0/1) is cabled to, when that is
    # another switch rather than the router. The cable is a trunk, so each
    # of this switch's VLANs is the same segment as the VLAN with the same
    # number on that switch (when it has one): see Lab.segment_id.
    upstream: str = ""

    @property
    def vlan_no(self) -> int:
        """The VLAN number the switch's console shows for this network."""
        return self.tag or 1

    @property
    def home(self) -> str:
        """The switch (canvas box) this network's ports are on."""
        return self.switch or self.id

    @property
    def net(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def router_ip(self) -> str:
        """The lab router's own address on the segment."""
        if self.gateway:
            return self.gateway
        return str(next(self.net.hosts()))

    @property
    def default_gateway(self) -> str:
        """What the machines on the segment use as their default gateway:
        the firewall named by gateway_node, else the lab router."""
        return self.hosts_gateway or self.router_ip

    @property
    def prefixlen(self) -> int:
        return self.net.prefixlen

    @property
    def netmask(self) -> str:
        return str(self.net.netmask)


@dataclass
class Nic:
    network: str
    ip: str | None = None
    mac: str = ""
    dns: list[str] = field(default_factory=list)
    # `network` stays the native (untagged) VLAN.
    trunk: list[str] = field(default_factory=list)

    @property
    def dhcp(self) -> bool:
        return self.ip is None

    @property
    def plugged(self) -> bool:
        """A network card with no cable in it has an empty `network`: the
        machine sees "Network cable unplugged" until one goes in."""
        return bool(self.network)


# Peripherals a Windows admin is expected to connect and manage. Each has a real
# configuration flow in the role scripts, not just a label.
PRINTER = "printer"          # shared, AD-published print queue
SCANNER = "scanner"          # scan-to-folder SMB destination
NAS = "nas"                  # iSCSI target the client mounts as a block disk
FILESHARE = "fileshare"      # SMB share mapped as a network drive
VOIP = "voip"                # IP phone provisioned via DHCP options 66/150
CAMERA = "camera"            # IP camera / NVR network endpoint + firewall
UPS = "ups"                  # monitored UPS (network/USB) the server watches
LABEL_PRINTER = "label-printer"  # thermal/label queue (raw, no driver munging)
DEVICE_KINDS = {PRINTER, SCANNER, NAS, FILESHARE, VOIP, CAMERA, UPS, LABEL_PRINTER}


@dataclass
class Device:
    """A peripheral hosted by a node and shared to the lab: a print queue, or a
    scan-to-folder destination (the real enterprise scanner pattern)."""

    kind: str
    name: str
    shared: bool = True
    driver: str = ""          # printer driver; blank = a sensible in-box default
    location: str = ""
    vars: dict[str, object] = field(default_factory=dict)


@dataclass
class Node:
    id: str
    image: str
    kind: str = WINDOWS_SERVER
    cpus: int = 2
    memory_mb: int = 2048
    hostname: str = ""
    nics: list[Nic] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    data_disks_gb: list[int] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    boot_order: int = 50
    # Start order pacing: the next machines wait until this one's winlab agent
    # answers (Windows only), then this many seconds more. Both skipped while
    # the machine is still installing.
    wait_ready: bool = False
    start_delay: int = 0
    description: str = ""
    vars: dict[str, object] = field(default_factory=dict)
    # HARDWARE_PC or HARDWARE_VIRTIO; blank means the default (pc).
    hardware: str = ""
    # The Low-memory profile (dscroles.build_lean) on this Windows machine:
    # idle services, telemetry, Widgets, OneDrive and, on a server no role
    # wants it on, Defender off, so a server serves at 1.5 GB and Windows 11
    # is usable at 2 GB. Off by default: machines run stock Windows.
    lean: bool = False
    # Nested virtualization: the machine's CPU shows VT-x so Hyper-V can run
    # inside it. Only the KVM appliance can give that (WHPX on Windows does
    # not pass VT-x through); elsewhere the machine starts without it.
    nested: bool = False
    # The firmware (winlab/firmware.py): "uefi", "uefi-secure" (UEFI with
    # Secure Boot) or "bios"; blank keeps winlab's default (UEFI where QEMU
    # has it).
    firmware: str = ""

    @property
    def is_windows(self) -> bool:
        return self.kind in (WINDOWS_SERVER, WINDOWS_CLIENT)

    @property
    def is_server_core(self) -> bool:
        if self.kind != WINDOWS_SERVER:
            return False
        from .servercore import is_core_image  # a template made from a Core machine is Core too
        return is_core_image(self.image)

    @property
    def wants_virtio(self) -> bool:
        """Asked for Red Hat's paravirtual devices (`hardware = "virtio"`;
        the older `virtio = false` var means a regular PC)."""
        return self.hardware == HARDWARE_VIRTIO and self.vars.get("virtio") is not False

    @property
    def memory_floor_mb(self) -> int:
        if self.image == "openwrt":
            return 128  # the access points' and the UPS card's firmware (winlab/openwrt.py)
        if self.is_server_core:
            return CORE_MIN_MEMORY_MB
        return MIN_MEMORY_MB.get(self.kind, 512)

    @property
    def trim_floor_mb(self) -> int:
        if self.kind == CUSTOM:
            return self.memory_mb  # unknown OS: never run it below what it asked for
        if self.is_server_core:
            return CORE_MIN_MEMORY_MB
        return min(self.memory_floor_mb, TRIM_FLOOR_MB.get(self.kind, 512))

    @property
    def primary_nic(self) -> Nic | None:
        return self.nics[0] if self.nics else None

    @property
    def recommended_hardware(self) -> tuple[int, int]:
        """(cpus, memory_mb) winlab would give this machine."""
        if self.is_server_core:
            return RECOMMENDED_CPUS[WINDOWS_SERVER], RECOMMENDED_CORE_MEMORY_MB
        return (RECOMMENDED_CPUS.get(self.kind, 2),
                RECOMMENDED_MEMORY_MB.get(self.kind, MIN_MEMORY_MB.get(self.kind, 2048)))


@dataclass
class Site:
    """A place with its own segments and its own way out: an office, a
    branch, a cloud region. `gateway` names the machine with one adapter on
    a segment of this site and one on the WAN; the router hands it every
    packet bound for another site (winlab/sites.py)."""

    id: str
    description: str = ""
    gateway: str = ""


@dataclass
class FirewallRule:
    """One rule in a segment's zone firewall, in the Azure network security
    group model: evaluated lowest priority first, the first match decides.
    `source` and `destination` take an address, a CIDR, a segment id, a
    machine id, or the tags Any, VirtualNetwork and Internet (winlab/firewall.py)."""

    name: str
    priority: int
    direction: str = "inbound"
    segment: str = ""
    source: str = "Any"
    destination: str = "Any"
    ports: str = "*"
    protocol: str = "Any"
    action: str = "Allow"
    description: str = ""
    builtin: bool = False     # one of the default rules every segment gets


@dataclass
class Firewall:
    """The zone firewall on the lab router: off, the router forwards everything
    between segments; on, every segment gets the default rules and the lab's
    own, rendered into nftables on the fabric."""

    enabled: bool = False
    rules: list[FirewallRule] = field(default_factory=list)


@dataclass
class Names:
    """What the student called the services they build, where winlab would
    otherwise pick: the file server's main share, the AD sites (keyed by the
    `site` var the machines carry) and the DHCP scopes (keyed by network id).
    Empty means winlab's default (winlab/naming.py)."""

    share: str = ""
    sites: dict[str, str] = field(default_factory=dict)
    scopes: dict[str, str] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not (self.share or self.sites or self.scopes)


@dataclass
class Lab:
    name: str
    domain: str = "corp.lab"
    netbios: str = "CORP"
    description: str = ""
    # Empty in the definition means "generated per lab" (see secrets.py);
    # schema.load fills it in. password_in_toml records which it was, so the
    # editor never writes a generated one back into the file.
    admin_password: str = ""
    password_in_toml: bool = False
    timezone: str = "UTC"
    locale: str = "en-US"
    networks: dict[str, Network] = field(default_factory=dict)
    sites: dict[str, Site] = field(default_factory=dict)
    nodes: dict[str, Node] = field(default_factory=dict)
    exercises: list[str] = field(default_factory=list)
    source_path: str = ""
    lean: bool = False  # the default for nodes that do not say
    # Free play: no lessons, problems or grading attach to this lab. The
    # desktop hides the Lab guide and Problems and opens Build instead.
    sandbox: bool = False
    # A capstone lab: machines start bare and the student builds the services,
    # so a DHCP client may wait for a DHCP server that does not exist yet.
    bare: bool = False
    # A network the student builds from nothing in the workbench: it may
    # start with no machines and no switches, machines may have empty
    # network ports, and nothing is graded (it is a sandbox and a bare lab).
    workbench: bool = False
    # The inherited company scenario (winlab/inherited.py): the one lab that
    # does not start empty; and the locked server room (winlab/serverroom.py),
    # whose machines' screens open only after walking there.
    inherited: bool = False
    server_room: bool = False
    # Where each device sits on the workbench canvas: machine ids, "router"
    # and "net:<id>" for a switch, to [x, y].
    layout: dict[str, list[int]] = field(default_factory=dict)
    # What was typed into the consoles of the devices that have no screen
    # (winlab/devcli.py): "router" and "sw:<id>" to settings such as
    # hostname, a port's description, or a port that is shut down.
    devices: dict[str, dict[str, str]] = field(default_factory=dict)
    # The rack (winlab/rack.py): racks, patch panels, where each device sits
    # ("<rack>:<U>"), asset tags, serial numbers and cable labels.
    rack: dict = field(default_factory=dict)
    # A client job (winlab/campus.py): the site the lab is, and what was
    # pulled, terminated, patched and installed on it.
    campus: dict = field(default_factory=dict)
    firewall: Firewall = field(default_factory=Firewall)
    names: Names = field(default_factory=Names)

    def segment_id(self, network_id: str) -> str:
        """The network whose broadcast domain this one is part of: itself,
        unless it is on a switch cabled to another switch, where it is the
        VLAN with the same number up the trunk (if that switch has it)."""
        seen = {network_id}
        while True:
            net = self.networks.get(network_id)
            box = self.networks.get(net.home) if net else None
            up = box.upstream if box else ""
            if not up or up in seen or self._cut_off(net.home):
                return network_id
            seen.add(up)
            # Which VLAN up there this one is: the trunk's ends may not allow
            # it, or have other native VLANs (winlab/devcli.py trunk_tag).
            from .devcli import trunk_tag
            tag = trunk_tag(self, net.home, up, net.vlan_no)
            nxt = next((n.id for n in self.networks.values()
                        if n.home == up and n.vlan_no == tag), "") if tag else ""
            if not nxt:
                return network_id
            network_id = nxt

    def _cut_off(self, sw: str) -> bool:
        """A switch whose uplink trunk is shut or err-disabled, with no other
        cable round to the switch above (winlab/stp.py)."""
        from .stp import cut_off
        return cut_off(self, sw)

    def node_list(self) -> list[Node]:
        """Boot order, then id, so plans are deterministic."""
        return sorted(self.nodes.values(), key=lambda n: (n.boot_order, n.id))

    def nodes_on(self, network_id: str) -> list[Node]:
        return [n for n in self.node_list() if any(c.network == network_id for c in n.nics)]

    def total_memory_mb(self) -> int:
        return sum(n.memory_mb for n in self.nodes.values())

    def total_cpus(self) -> int:
        return sum(n.cpus for n in self.nodes.values())


def stable_mac(lab_name: str, node_id: str, index: int) -> str:
    """Stable across rebuilds so DHCP leases and AD machine identity survive."""
    seed = f"{lab_name}/{node_id}/{index}".encode()
    h = hashlib.sha256(seed).digest()
    return "52:54:00:%02x:%02x:%02x" % (h[0], h[1], h[2])


def stable_port(lab_name: str, node_id: str, index: int, base: int = 29000) -> int:
    """Collisions are resolved by the planner, not here."""
    seed = f"{lab_name}/{node_id}/{index}".encode()
    h = hashlib.sha256(seed).digest()
    return base + ((h[3] << 8 | h[4]) % 2000)
