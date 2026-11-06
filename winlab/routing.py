"""Dynamic routing by hand: OSPF between the sites, eBGP to an ISP, on
routers the student builds.

The routers are real machines: Ubuntu Server (Canonical's cloud image) with
FRRouting, whose vtysh shell speaks the Cisco-like language a network
engineer meets at work (configure terminal, router ospf, router bgp, show ip
route). They sit on segments the lab router does not route (routed = false
in the lab file), so the lab router is only the switches between them and
never a hidden path: until the student turns on forwarding and brings up a
routing protocol, the sites cannot reach each other, which is the honest
starting point. The lab is content/labs/dynamic-routing.toml.

What is fetched, and from where: the 'frr' pack (winlab/debpacks.py), the
dependency closure of frr, frr-pythontools and traceroute resolved against
Ubuntu 24.04's archive (archive.ubuntu.com and security.ubuntu.com, every
.deb checked against the SHA-256 the archive's index gives), about 5 MB,
onto this PC. A lab names it in a router's node vars (packs = ["frr"]), so
Setup offers the fetch (mail.setup_steps) and the machine's Settings offers
the stick; the student mounts it and installs from it with apt, offline.
Nothing reaches the lab from outside and the lab reaches nothing outside:
no NAT, no forwarded port, no path from any router to this PC.

What winlab does not do, and why:

* In this lab the lab router stays out of the topology: every segment is
  routed = false, so it is only the switches. The lab router can speak
  OSPF, BGP and VRRP itself (`router ospf`, `router bgp`, `vrrp` at its
  console, winlab/devcli.py, made real by FRRouting from Alpine's
  community repository on the router appliance, winlab/iosrouting.py);
  the router-protocols lab is where it peers with Ubuntu routers like
  these, built the same way from the same pack. Here the routers to
  configure are the Ubuntu machines.
* A Windows Server router is not part of the lab, to keep it small (four
  routers and three PCs fit in under 5 GB). Windows RRAS still speaks BGP
  (Install-RemoteAccess -VpnType RoutingOnly, then Add-BgpRouter and
  Add-BgpPeer) and can peer with rtr-isp if a Windows Server is added from
  the Workbench shelf; its OSPF was removed after Windows Server 2008 R2, so
  it cannot take part in the OSPF lessons.
* No router is configured for the student, and no role does it: the drills
  below break what the student built, and refuse to run on a router that
  has no FRRouting yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PACK = "frr"
STATE_DIR = "/var/lib/winlab"
FAULT_IDS = ("ospf-hello-mismatch", "ospf-mtu-exstart", "bgp-wrong-remote-as")


class RoutingError(Exception):
    pass


# --------------------------------------------------------------- the lab
@dataclass
class Link:
    """A segment between routers (a transit link) and who sits on it."""
    network: str
    cidr: str
    ends: list[tuple[str, str, str]] = field(default_factory=list)   # (router, eth name, address)


def routers(lab) -> list:
    """The machines the lab says are routers: those that install the frr pack."""
    from .mail import hand_packs
    return [n for n in lab.node_list() if PACK in hand_packs(n)]


def eth_of(node, network_id: str) -> str:
    """The name the card on a network comes up with inside the machine:
    cloud-init names them eth0, eth1... in the lab file's order."""
    for i, nic in enumerate(node.nics):
        if nic.network == network_id:
            return f"eth{i}"
    return ""


def links(lab) -> list[Link]:
    """Segments with two or more routers on them, in address order."""
    rs = routers(lab)
    out = []
    for net in sorted(lab.networks.values(), key=lambda n: (n.net, n.id)):
        ends = [(r.id, eth_of(r, net.id), nic.ip) for r in rs for nic in r.nics
                if nic.network == net.id and nic.ip]
        if len(ends) >= 2:
            out.append(Link(net.id, net.cidr, ends))
    return out


def lans(lab) -> list[tuple]:
    """(network, router, its address there, the hosts on it): the segments a
    router is the default gateway of."""
    ids = {r.id for r in routers(lab)}
    out = []
    for net in sorted(lab.networks.values(), key=lambda n: (n.net, n.id)):
        if net.gateway_node in ids:
            hosts = [(n, c.ip) for n in lab.nodes_on(net.id) if n.id != net.gateway_node
                     for c in n.nics if c.network == net.id and c.ip]
            out.append((net, lab.nodes[net.gateway_node], net.hosts_gateway, hosts))
    return out


def plan_lines(lab) -> list[str]:
    """The routing layout of a lab, for `winlab routing status <lab>`."""
    rs = routers(lab)
    if not rs:
        return [f"{lab.name}: no routers (no machine installs the {PACK} pack)"]
    out = [f"{lab.name}: {len(rs)} routers, every segment off the lab router"]
    for r in rs:
        cards = ", ".join(f"{eth_of(r, c.network)} {c.ip} ({c.network})" for c in r.nics if c.ip)
        out.append(f"  {r.id:<10} {cards}")
    for ln in links(lab):
        out.append(f"  link {ln.network:<14} {ln.cidr:<18} "
                   + " <-> ".join(f"{who} {eth} {ip}" for who, eth, ip in ln.ends))
    for net, r, ip, hosts in lans(lab):
        out.append(f"  lan  {net.id:<14} {net.cidr:<18} {r.id} {ip}; "
                   + (", ".join(f"{h.id} {a}" for h, a in hosts) or "no hosts"))
    return out


# ------------------------------------------------------------ the pack
def status() -> dict:
    from . import appliances, debpacks
    st = debpacks.status(PACK)
    st["image_ready"] = appliances.ready(st["image"])
    return st


def render_status(lab=None) -> str:
    st = status()
    state = (f"ready ({st['count']} packages, {st['size_mb']} MB, fetched {st['fetched']})"
             if st["ready"] else f"not fetched (about {st['typical_mb']} MB)")
    lines = [f"  frr pack     {state}",
             f"               {st['title']}: installs {', '.join(st['install'])}",
             "               from the Ubuntu archive, onto a stick each router installs from by hand"]
    if not st["ready"]:
        lines.append("               then:    winlab routing fetch"
                     + ("" if st["image_ready"] else "  (after: winlab images fetch ubuntu)"))
    if lab is not None:
        lines += [""] + plan_lines(lab)
    return "\n".join(lines) + "\n"


def fetch(progress=None, **kw) -> dict:
    """The frr pack, resolved against the Ubuntu image (fetched first)."""
    from . import appliances, debpacks
    if not appliances.ready("ubuntu"):
        raise RoutingError("fetch the Ubuntu image first (winlab images fetch ubuntu): the frr pack "
                           "is resolved against what that image already has")
    try:
        return debpacks.fetch(PACK, progress=progress, **kw)
    except debpacks.PackError as exc:
        raise RoutingError(str(exc)) from exc


# ------------------------------------------------------------- the drills
NEED_FRR = ("command -v vtysh >/dev/null 2>&1 || { echo 'no FRRouting on this machine: install it from the frr "
            "pack first (lesson foundation-dynamic-routing)'; exit 1; }; ")
# The first card with an OSPF neighbour in Full state: its name is what
# 'show ip ospf neighbor' prints before the colon in the Interface column.
FULL_IFC = ("vtysh -c 'show ip ospf neighbor' 2>/dev/null | awk '/Full\\//{for(i=1;i<=NF;i++) "
            "if($i ~ /^eth[0-9]+:/){split($i,a,\":\"); print a[1]; exit}}'")


def _full_on(ifc_file: str) -> str:
    """sh that prints True when the card named in the file has a Full neighbour."""
    return (f"i=$(cat {ifc_file} 2>/dev/null); [ -n \"$i\" ] && vtysh -c 'show ip ospf neighbor' 2>/dev/null | "
            f"grep -qE \"Full/.* $i:\" ")


def _faults():
    from .guestfaults import LINUX, GuestFault
    hello = f"{STATE_DIR}/ts-ospf-hello.ifc"
    mtu = f"{STATE_DIR}/ts-ospf-mtu.ifc"
    peer = f"{STATE_DIR}/ts-bgp-peer"
    mtu_file = "/etc/netplan/60-tunnel-test.yaml"
    return [
        GuestFault(
            id="ospf-hello-mismatch",
            images=("ubuntu",),
            title="A branch router lost its OSPF neighbour and the far site's routes went with it",
            os=LINUX,
            teaches="what two OSPF routers must agree on before they become neighbours (area, subnet, hello "
                    "and dead intervals, authentication, MTU for the database exchange), and reading "
                    "show ip ospf interface on both ends instead of restarting FRRouting",
            symptom="the PC behind this router can no longer reach the site on one side; show ip ospf neighbor "
                    "has one neighbour fewer than before, and the routes learned through it are gone",
            apply=(NEED_FRR + f"mkdir -p {STATE_DIR}; i=$({FULL_IFC}); "
                   "[ -n \"$i\" ] || { echo 'no OSPF neighbour in Full state on this router: build OSPF first "
                   "(lesson ospf-single-area)'; exit 1; }; "
                   f"echo \"$i\" > {hello}; "
                   "vtysh -c 'configure terminal' -c \"interface $i\" -c 'ip ospf hello-interval 25' "
                   "-c 'ip ospf dead-interval 100' -c 'end' -c 'write memory' >/dev/null && "
                   "vtysh -c \"clear ip ospf interface $i\" >/dev/null 2>&1; echo broken"),
            clear=(f"i=$(cat {hello} 2>/dev/null); [ -n \"$i\" ] && vtysh -c 'configure terminal' -c \"interface $i\" "
                   "-c 'no ip ospf hello-interval' -c 'no ip ospf dead-interval' -c 'end' -c 'write memory' "
                   f">/dev/null; rm -f {hello}; echo ok"),
            shell="sh",
            hints=(
                "Start with what this router sees: sudo vtysh -c 'show ip ospf neighbor'. Which neighbour is "
                "missing, and on which card was it? The routing table (show ip route ospf) lost what came "
                "through that card.",
                "Compare the card on both ends: sudo vtysh -c 'show ip ospf interface ethN' here and on the "
                "neighbour. Look at the line 'Timer intervals configured, Hello ..., Dead ...'. Hellos with "
                "different timers are thrown away, so the neighbour times out. The log says so too: "
                "sudo journalctl -u frr | grep -i mismatch.",
                "Put the timers back the same on both ends: configure terminal, interface ethN, no ip ospf "
                "hello-interval, no ip ospf dead-interval, end, then write memory. The neighbour comes back to "
                "Full within a hello or two; show ip route ospf has the far site's routes again.",
            ),
            verify=(f"{_full_on(hello)}&& echo True || echo False"),
        ),
        GuestFault(
            id="ospf-mtu-exstart",
            images=("ubuntu",),
            title="Two routers see each other in OSPF but never become Full: stuck in ExStart",
            os=LINUX,
            teaches="the OSPF neighbour states (Down, Init, 2-Way, ExStart, Exchange, Loading, Full), why the "
                    "database exchange checks the interface MTU, and why 'ip ospf mtu-ignore' hides the fault "
                    "instead of fixing it",
            symptom="show ip ospf neighbor lists the neighbour, but its state sits at ExStart or Exchange and "
                    "never reaches Full; no routes come from it, although ping across the link works",
            apply=(NEED_FRR + f"mkdir -p {STATE_DIR}; i=$({FULL_IFC}); "
                   "[ -n \"$i\" ] || { echo 'no OSPF neighbour in Full state on this router: build OSPF first "
                   "(lesson ospf-single-area)'; exit 1; }; "
                   f"echo \"$i\" > {mtu}; n=${{i#eth}}; "
                   f"printf 'network:\\n  version: 2\\n  ethernets:\\n    nic%s:\\n      mtu: 1400\\n' \"$n\" > {mtu_file}; "
                   f"chmod 600 {mtu_file}; ip link set \"$i\" mtu 1400 && "
                   "vtysh -c \"clear ip ospf interface $i\" >/dev/null 2>&1; echo broken"),
            clear=(f"i=$(cat {mtu} 2>/dev/null); rm -f {mtu_file}; [ -n \"$i\" ] && ip link set \"$i\" mtu 1500 && "
                   f"vtysh -c \"clear ip ospf interface $i\" >/dev/null 2>&1; rm -f {mtu}; echo ok"),
            shell="sh",
            hints=(
                "Read the state, not just the list: sudo vtysh -c 'show ip ospf neighbor'. A neighbour that "
                "stays in ExStart or Exchange found the other router (hellos work) but cannot exchange the "
                "database. Ping works, so the link is up.",
                "The database description packets carry the interface MTU, and a router refuses packets "
                "announcing an MTU larger than its own. Compare: ip link show ethN here and on the neighbour, "
                "and sudo vtysh -c 'show ip ospf interface ethN' (MTU mismatch detection is on). The log "
                "names it: sudo journalctl -u frr | grep -i mtu.",
                "Set the card back to 1500: sudo ip link set ethN mtu 1500, and make it stay so: grep -r mtu "
                "/etc/netplan finds the file that lowers it on every boot (remove it; sudo netplan get "
                "shows the result). Do not reach for ip ospf mtu-ignore: the routers would go Full while "
                "large packets still die on that link.",
            ),
            verify=(f"i=$(cat {mtu} 2>/dev/null); [ -n \"$i\" ] && ip -o link show \"$i\" | grep -q 'mtu 1500 ' && "
                    "! grep -rqs 'mtu: 1400' /etc/netplan && ! vtysh -c 'show running-config' | grep -q mtu-ignore && "
                    f"{_full_on(mtu)}&& echo True || echo False"),
        ),
        GuestFault(
            id="bgp-wrong-remote-as",
            images=("ubuntu",),
            title="The BGP session to the ISP never comes up: neighbour stuck in Active",
            os=LINUX,
            teaches="how an eBGP session is built (TCP 179, then OPEN messages that carry each side's AS), "
                    "the BGP states (Idle, Connect, Active, OpenSent, OpenConfirm, Established), and reading "
                    "the NOTIFICATION a peer sends back",
            symptom="show bgp summary lists the ISP's neighbour in Active (or Idle) instead of a prefix count; "
                    "the Internet routes and the default are gone, and the branches cannot reach inet01",
            apply=(NEED_FRR + f"mkdir -p {STATE_DIR}; "
                   "as=$(vtysh -c 'show running-config' | awk '/^router bgp [0-9]+/{print $3; exit}'); "
                   "[ -n \"$as\" ] || { echo 'no BGP on this router: build the eBGP session first (lesson "
                   "bgp-ebgp-peering)'; exit 1; }; "
                   "set -- $(vtysh -c 'show running-config' | awk -v as=\"$as\" '$1==\"neighbor\" && "
                   "$3==\"remote-as\" && $4 ~ /^[0-9]+$/ && $4 != as {print $2, $4; exit}'); "
                   "[ -n \"$2\" ] || { echo 'no eBGP neighbour on this router (a remote-as other than its own '"
                   "\"$as\"')'; exit 1; }; "
                   f"echo \"$1 $2 $as\" > {peer}; "
                   "vtysh -c 'configure terminal' -c \"router bgp $as\" -c \"neighbor $1 remote-as $(($2 + 1))\" "
                   "-c 'end' -c 'write memory' >/dev/null; vtysh -c \"clear bgp $1\" >/dev/null 2>&1; echo broken"),
            clear=(f"set -- $(cat {peer} 2>/dev/null); [ -n \"$3\" ] && vtysh -c 'configure terminal' "
                   "-c \"router bgp $3\" -c \"neighbor $1 remote-as $2\" -c 'end' -c 'write memory' >/dev/null; "
                   f"rm -f {peer}; echo ok"),
            shell="sh",
            hints=(
                "sudo vtysh -c 'show bgp summary': the ISP's neighbour shows a state (Active, Idle, Connect) "
                "where an Established session shows how many prefixes it received. Ping the neighbour's "
                "address: the link is fine, so this is BGP itself.",
                "Ask why the session closes: sudo vtysh -c 'show bgp neighbors <address>' ends with the last "
                "reset and the NOTIFICATION, and sudo journalctl -u frr | grep -i notification shows the OPEN "
                "being refused. An OPEN carries the sender's AS; each side checks it against the remote-as it "
                "was told for that neighbour.",
                "The remote-as here is not the ISP's AS (rtr-isp's show running-config, or its OPEN in the "
                "log, says which it is). Fix it: configure terminal, router bgp <your AS>, neighbor <address> "
                "remote-as <the ISP's AS>, end, write memory. Established within seconds; show ip route bgp "
                "has the Internet's routes again.",
            ),
            verify=(f"set -- $(cat {peer} 2>/dev/null); [ -n \"$1\" ] && vtysh -c \"show bgp neighbors $1\" "
                    "2>/dev/null | grep -q 'BGP state = Established' && echo True || echo False"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
