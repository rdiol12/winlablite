"""Network fault and attack scenarios run on the fabric.

Each scenario is a named set of shell commands applied inside the fabric VM
(over its serial channel), so the student can watch a real network misbehave
and practise diagnosing it. Because everything runs on the fabric's real Linux
stack, the failures are genuine, not simulated: a duplicate IP really answers
ARP for the same address, netem really drops frames, a rogue dnsmasq really
races the legitimate DHCP server.

Scenarios are reversible: `clear` removes them and restores normal operation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Scenario:
    id: str
    title: str
    category: str          # impairment | conflict | attack | reachability
    teaches: str
    apply_cmds: list[str] = field(default_factory=list)
    clear_cmds: list[str] = field(default_factory=list)
    observe: str = ""      # what to run on probe01 to see it
    needs_firewall: bool = False   # only meaningful with the zone firewall on
    symptom: str = ""      # what a user reports: the card's title until it is solved
    hints: tuple[str, ...] = ()    # the ladder: where to look first, the cause last


SCENARIOS: dict[str, Scenario] = {}


def _reg(s: Scenario) -> None:
    SCENARIOS[s.id] = s


_reg(Scenario(
    id="latency",
    title="High latency + jitter on a segment",
    category="impairment",
    teaches="how RTT and jitter degrade SMB/RDP/replication; reading ping vs iperf",
    apply_cmds=[
        "tc qdisc replace dev {dev} root netem delay 150ms 40ms distribution normal",
    ],
    clear_cmds=["tc qdisc del dev {dev} root || true"],
    observe="ping -c 5 {gw}",
))

_reg(Scenario(
    id="loss",
    title="Packet loss",
    category="impairment",
    teaches="retransmission, TCP throughput collapse, why UDP services stutter",
    apply_cmds=["tc qdisc replace dev {dev} root netem loss 15%"],
    clear_cmds=["tc qdisc del dev {dev} root || true"],
    observe="ping -c 20 {gw}",
))

_reg(Scenario(
    id="ip-conflict",
    title="Duplicate IP address conflict",
    category="conflict",
    teaches="why a host intermittently drops off; reading ARP tables and gratuitous ARP",
    apply_cmds=[
        # The fabric claims a host address already assigned to a node, so ARP
        # now has two MACs answering for one IP -- a real conflict.
        "ip addr add {victim}/{prefix} dev {dev} 2>/dev/null || true",
        "arping -c 3 -A -I {dev} {victim} 2>/dev/null || true",
    ],
    clear_cmds=["ip addr del {victim}/{prefix} dev {dev} 2>/dev/null || true"],
    observe="arping -c 3 {victim} ; ip neigh show",
))

_reg(Scenario(
    id="rogue-dhcp",
    title="Rogue DHCP server",
    category="attack",
    teaches="DHCP races, wrong gateway/DNS handed out, why clients land on a bad config",
    apply_cmds=[
        "mkdir -p /etc/dnsmasq.d",
        "printf 'interface={dev}\\ndhcp-range={rogue_lo},{rogue_hi},2m\\n"
        "dhcp-option={dev},3,{victim}\\ndhcp-option={dev},6,{victim}\\n' "
        "> /etc/dnsmasq.d/rogue.conf",
        "dnsmasq -C /etc/dnsmasq.d/rogue.conf --pid-file=/var/run/rogue.pid || true",
    ],
    clear_cmds=[
        "kill $(cat /var/run/rogue.pid 2>/dev/null) 2>/dev/null || true",
        "rm -f /etc/dnsmasq.d/rogue.conf /var/run/rogue.pid",
    ],
    observe="(on a client) ipconfig /release ; ipconfig /renew",
))

_reg(Scenario(
    id="dns-poison",
    title="DNS cache poisoning / spoofed answers",
    category="attack",
    teaches="why a name resolves to the wrong host; trusting the wrong resolver",
    apply_cmds=[
        "mkdir -p /etc/dnsmasq.d",
        "printf 'interface={dev}\\naddress=/{spoof_name}/{victim}\\n' "
        "> /etc/dnsmasq.d/poison.conf",
        "dnsmasq -C /etc/dnsmasq.d/poison.conf --pid-file=/var/run/poison.pid || true",
    ],
    clear_cmds=[
        "kill $(cat /var/run/poison.pid 2>/dev/null) 2>/dev/null || true",
        "rm -f /etc/dnsmasq.d/poison.conf /var/run/poison.pid",
    ],
    observe="nslookup {spoof_name} {gw}",
))

_reg(Scenario(
    id="blackhole",
    title="Routing blackhole for a subnet",
    category="reachability",
    teaches="asymmetric reachability, why one subnet is unreachable while others work",
    apply_cmds=["ip route add blackhole {target_cidr}"],
    clear_cmds=["ip route del blackhole {target_cidr} 2>/dev/null || true"],
    observe="ping -c 3 {target_host} ; traceroute {target_host}",
))

_reg(Scenario(
    id="mtu-blackhole",
    title="MTU mismatch / PMTU blackhole",
    category="reachability",
    teaches="why small pings work but large transfers hang; path MTU discovery",
    apply_cmds=[
        "ip link set dev {dev} mtu 1400",
        "iptables -A FORWARD -p icmp --icmp-type fragmentation-needed -j DROP || true",
    ],
    clear_cmds=[
        "ip link set dev {dev} mtu 1500 || true",
        "iptables -D FORWARD -p icmp --icmp-type fragmentation-needed -j DROP 2>/dev/null || true",
    ],
    observe="ping -c 2 -s 1472 -M do {gw}",
))

_reg(Scenario(
    id="port-block",
    title="Firewall blocks a service port",
    category="reachability",
    teaches="distinguishing 'service down' from 'port filtered'; reading a port scan",
    apply_cmds=["iptables -A FORWARD -p tcp --dport {port} -j DROP"],
    clear_cmds=["iptables -D FORWARD -p tcp --dport {port} -j DROP 2>/dev/null || true"],
    observe="nmap -p {port} {target_host}  (or Test-NetConnection on a client)",
))

_reg(Scenario(
    id="nsg-deny",
    title="A deny rule hides at the top of a zone firewall table",
    category="reachability",
    teaches="reading the effective rules on the router, not their names; why no allow "
            "rule below a deny can ever win",
    needs_firewall=True,
    apply_cmds=[
        # Inserted at the top of the segment's inbound table, named like an
        # allow rule, with a drop verdict: the classic badly-named rule.
        "nft insert rule inet winlab {nsg_in} ip saddr {other_cidr} tcp dport 445 "
        "counter drop comment \"100 allow-smb-{other}\"",
    ],
    clear_cmds=[
        "for h in $(nft -a list chain inet winlab {nsg_in} | grep 'allow-smb-{other}' | "
        "sed -n 's/.*handle \\([0-9]*\\).*/\\1/p'); do "
        "nft delete rule inet winlab {nsg_in} handle $h; done; true",
    ],
    observe="Test-NetConnection <a server on the segment> -Port 445 from {other}; "
            "winlab fw <lab> live",
))

_reg(Scenario(
    id="vpn-block",
    title="The ISP drops IPsec: the site-to-site VPN goes down",
    category="reachability",
    teaches="telling a tunnel failure from a routing one; reading IKE and ESP on the wire, "
            "the VPN interface state on the gateway, and what still works without the tunnel",
    apply_cmds=[
        # The provider's edge (the WAN segment the fault targets) stops
        # forwarding IKE (udp 500/4500) and ESP, the two things a site-to-site
        # tunnel is made of. Everything else on the WAN keeps flowing.
        "iptables -I FORWARD -i {dev} -p esp -j DROP",
        "iptables -I FORWARD -i {dev} -p udp --dport 500 -j DROP",
        "iptables -I FORWARD -i {dev} -p udp --dport 4500 -j DROP",
    ],
    clear_cmds=[
        "iptables -D FORWARD -i {dev} -p esp -j DROP 2>/dev/null || true",
        "iptables -D FORWARD -i {dev} -p udp --dport 500 -j DROP 2>/dev/null || true",
        "iptables -D FORWARD -i {dev} -p udp --dport 4500 -j DROP 2>/dev/null || true",
    ],
    observe="Get-VpnS2SInterface on the Windows gateway; tcpdump -ni {dev} 'udp port 500 or esp' "
            "on the router",
))

_reg(Scenario(
    id="link-flap",
    title="Flapping link",
    category="impairment",
    teaches="intermittent outages, why monitoring sees a port bounce",
    apply_cmds=[
        "(for i in 1 2 3 4 5; do ip link set {fabric_iface} down; sleep 3; "
        "ip link set {fabric_iface} up; sleep 5; done) &",
    ],
    clear_cmds=["ip link set {fabric_iface} up || true"],
    observe="ping {gw}  (watch it drop and recover)",
))


# What the users see, and the hint ladder, per scenario. A card or lesson
# shows the symptom; the title (the cause) only once it is fixed or the
# second hint is open, as for the problems inside machines (guestfaults.py).
_SEEN: dict[str, tuple[str, tuple[str, ...]]] = {
    "latency": ("Everything on one network feels slow: file copies crawl and remote sessions lag", (
        "Measure before you guess: ping the gateway from a machine on that network and from one elsewhere. Compare the times.",
        "Round trips of a hundred milliseconds or more, varying from one reply to the next, inside one building point at the path, not the servers.",
        "Something on the router's interface for that network delays every frame. Look at the queueing on the interface (tc qdisc show) on the router.")),
    "loss": ("Users on one network say pages half load and calls break up", (
        "Ping long enough to see a pattern: 20 pings or more to the gateway, and read the loss line at the end.",
        "A steady share of lost replies with normal times for the rest is loss on the path, not a busy server.",
        "The router's interface for that network drops a share of frames on purpose. Look at its queueing discipline (tc qdisc show).")),
    "ip-conflict": ("One machine drops off the network now and then, and comes back by itself", (
        "When it drops, look at the ARP table on a neighbour (arp -a or ip neigh): which MAC answers for its address?",
        "Two different MACs answering for one IP address at different times is a duplicate address.",
        "Find the second owner of the address: arping it, compare the MAC with the machine's own, and remove the extra address.")),
    "rogue-dhcp": ("New and restarted machines get the wrong gateway or DNS and cannot reach anything", (
        "On an affected client, ipconfig /all: which DHCP server gave the lease, and what gateway and DNS did it hand out?",
        "If the lease came from an address that is not your DHCP server, a second DHCP server answers on that network.",
        "Find the host at that address and stop its DHCP service; then release and renew on the clients.")),
    "dns-poison": ("One internal site opens the wrong page, or none, for everyone on a network", (
        "Resolve the name with nslookup against each DNS server you have. Do they agree?",
        "An answer that differs from the zone on your DNS server comes from somewhere else on the path.",
        "Something on the router answers DNS for that name before your server does. Find the extra resolver or record there and remove it.")),
    "blackhole": ("One subnet cannot be reached from here; every other subnet works", (
        "Ping the far subnet's gateway and a host on it, then traceroute: where does the path stop?",
        "If the trace dies at the router with no error back, the router has a route that leads nowhere.",
        "Read the router's routing table (ip route) for a more specific route to that subnet that should not be there.")),
    "mtu-blackhole": ("Small things work (ping, logon) but large transfers and some web pages hang", (
        "Ping the gateway with growing packet sizes and the do-not-fragment flag. Where does it stop answering?",
        "If large packets vanish with no 'fragmentation needed' reply, path MTU discovery cannot work.",
        "Compare the MTU of the router's interfaces (ip link) and look for a filter dropping ICMP 'fragmentation needed'.")),
    "port-block": ("One service on a server stops answering, though the server pings and the service runs", (
        "Test the port itself from a client (Test-NetConnection server -Port n). Timeout or refused?",
        "A timeout with the service listening means something on the path filters that port.",
        "Read the router's forwarding rules (iptables -L FORWARD -n -v) for a rule that drops that port.")),
    "nsg-deny": ("File shares on one network stopped opening from another, though the servers are up", (
        "Test TCP 445 from the client side (Test-NetConnection) and read the zone firewall's live table on the router.",
        "Read the rules in the order they are applied, by their verdict, not by their names: the first match wins.",
        "A rule near the top of that network's inbound table drops SMB from the other network, whatever its name says.")),
    "vpn-block": ("The branch office lost everything at head office; the Internet still works there", (
        "Check the tunnel itself first: the VPN interface state on the gateway (Get-VpnS2SInterface).",
        "If the Internet works but the tunnel will not come up, look for IKE (UDP 500, 4500) and ESP on the wire.",
        "The provider's edge drops IKE and ESP. Read the forwarding rules on the WAN interface of the router.")),
    "link-flap": ("Users on one network get dropped for a few seconds, again and again", (
        "Leave a continuous ping to the gateway running and watch when it drops and when it comes back.",
        "Regular short outages that recover by themselves are a link going down and up, not a busy server.",
        "Look at the router's interface state and its log (ip link, dmesg): the link toward that network bounces.")),
}
for _id, (_symptom, _hints) in _SEEN.items():
    SCENARIOS[_id].symptom, SCENARIOS[_id].hints = _symptom, _hints


def hint(scenario_id: str, n: int) -> str:
    """Hint n (1-based) of a scenario's ladder."""
    s = SCENARIOS.get(scenario_id)
    if not s:
        raise KeyError(scenario_id)
    if n < 1 or n > len(s.hints):
        raise IndexError(n)
    return s.hints[n - 1]


def categories() -> dict[str, list[Scenario]]:
    out: dict[str, list[Scenario]] = {}
    for s in SCENARIOS.values():
        out.setdefault(s.category, []).append(s)
    return out


def render_catalog() -> str:
    lines = ["network fault & attack scenarios", ""]
    for cat, items in sorted(categories().items()):
        lines.append(f"{cat}:")
        for s in sorted(items, key=lambda x: x.id):
            lines.append(f"  {s.id:<14} {s.title}")
            lines.append(f"  {'':<14} teaches: {s.teaches}")
        lines.append("")
    lines.append("apply:   winlab net <lab> fault <id> [--on <segment>] [--param k=v ...]")
    lines.append("         nsg-deny needs the zone firewall on (winlab fw <lab> on)")
    lines.append("clear:   winlab net <lab> fault <id> --clear")
    return "\n".join(lines)


def build_commands(
    scenario_id: str, params: dict[str, str], clear: bool
) -> list[str]:
    s = SCENARIOS.get(scenario_id)
    if not s:
        raise KeyError(scenario_id)
    tmpl = s.clear_cmds if clear else s.apply_cmds
    out = []
    for cmd in tmpl:
        try:
            out.append(cmd.format(**params))
        except KeyError as exc:
            raise KeyError(f"scenario '{scenario_id}' needs parameter {exc}") from exc
    return out
