"""IPv6 beside IPv4: a ULA prefix, router advertisements, DHCPv6, AAAA and
ip6.arpa records, OSPFv3, and clients that speak both, all set up by hand.

The lab is content/labs/ipv6-dual-stack.toml. IPv4 there is the lab
router's, as in every other lab: the two LANs are routed, the foundation
lesson builds the domain and DHCPv4 on dc01, and the lab router relays
lan-b's DHCPv4 to it. IPv6 belongs to the student alone. The lab router
forwards no IPv6 and accepts no router advertisement (netplan.py writes
net.ipv6.conf.all.forwarding=0 and default.accept_ra=0 into every fabric),
so the only IPv6 paths are the two Ubuntu routers the student builds, joined
by a core segment the lab router is not cabled to. Until the student builds
them, every machine has only its link-local fe80:: address, which is the
honest starting point.

The student picks nothing up for free: the static ULA addresses on the
routers (FRRouting's `ipv6 address`), net.ipv6.conf.all.forwarding, the
router advertisements (zebra's `ipv6 nd`: prefix, M and O flags, RDNSS and
DNSSL), OSPFv3 between the routers (ospf6d), dc01's static address, DHCPv6
stateless and then stateful on Windows Server's DHCP, the AAAA records and
the fd12:3456:789a::/48 reverse zone in AD DNS, Windows' prefix policy
table, and the firewall rules for ICMPv6.

What is fetched, and from where: the 'ipv6-router' pack (frr,
frr-pythontools, ndisc6, traceroute and their libraries, about 5 MB) and the
'ipv6-tools' pack (ndisc6, traceroute, under 1 MB), dependency closures
resolved against Ubuntu 24.04's archive (archive.ubuntu.com and
security.ubuntu.com), every .deb checked against the SHA-256 the archive's
index gives (winlab/debpacks.py), onto this PC. Setup offers both
(mail.setup_steps); the machine's Settings plugs each in as a stick, from
which the student installs with apt, offline. Nothing reaches the lab from
outside and the lab reaches nothing outside: no NAT, no NAT64 or DNS64, no
forwarded port, no global IPv6 prefix and no path from any router to this
PC. The lab uses a ULA prefix (fd00::/8) precisely because it never leaves
the lab.

What winlab does not do, and why:

* The workbench router (winlab/devcli.py) gets no `ipv6 address`, `ipv6
  unicast-routing` or `ipv6 nd`. The lab router is the IPv4 plumbing every
  lab shares; if it also routed IPv6 or sent router advertisements, every
  segment would gain a second IPv6 router that the student did not build,
  and the RA and OSPFv3 lessons would be about which router wins. The
  router appliance also has nothing to send RAs with: busybox has no RA
  daemon, its dnsmasq could (enable-ra) but would need a second
  configuration engine in devcli kept in step with the IPv4 one, and radvd
  or FRRouting would have to be added to the appliance volume every lab
  prepares (apkrepo.py, alpineovl.APPLIANCE_PACKAGES). Not worth
  destabilising the console every lab uses; the IPv6 routers are the Ubuntu
  machines.
* No DHCPv6 relay on lan-b. FRRouting has no DHCPv6 relay, so pc02 and lnx01
  take their addresses by SLAAC and their DNS server and search domain from
  the RA (RDNSS and DNSSL, RFC 8106, which Windows 10 1703 and later read).
  isc-dhcp-relay (dhcrelay -6) would do it but is deprecated upstream, and
  stateful DHCPv6 is taught on lan-a, where dc01 is on the link.
* No IPv6 to the Internet, no NAT64/DNS64, no 6to4 or Teredo: there is no
  Internet in the lab, and a transition mechanism that pretends there is
  would teach the wrong thing.
* No machine is configured for the student, and no role does it: the drills
  below break what the student built and refuse to run until it exists.
"""

from __future__ import annotations

import ipaddress

PACKS = ("ipv6-router", "ipv6-tools")
ROUTER_PACK = "ipv6-router"
STATE_DIR = "/var/lib/winlab"
WIN_STATE = "C:\\ProgramData\\winlab"
FAULT_IDS = ("ipv6-ra-off", "dhcpv6-wrong-prefix", "ipv6-aaaa-missing", "icmpv6-blocked")


class Ipv6Error(Exception):
    pass


# --------------------------------------------------------------- the lab
def addresses(node) -> list[str]:
    """The static IPv6 address (with its prefix length) of each card, in
    card order, from the node's vars ipv6; "" for a card with none."""
    v = node.vars.get("ipv6") or []
    v = v if isinstance(v, list) else [v]
    out = [str(x) for x in v][: len(node.nics)]
    return out + [""] * (len(node.nics) - len(out))


def routers(lab) -> list:
    """The machines the lab makes IPv6 routers: those that install the
    ipv6-router pack."""
    from .mail import hand_packs
    return [n for n in lab.node_list() if ROUTER_PACK in hand_packs(n)]


def prefixes(lab) -> dict[str, str]:
    """network id -> its IPv6 /64, read from the static addresses on it."""
    out: dict[str, str] = {}
    for n in lab.node_list():
        for nic, a in zip(n.nics, addresses(n)):
            if a and nic.network not in out:
                out[nic.network] = str(ipaddress.ip_interface(a).network)
    return out


def site_prefix(lab) -> str:
    """The lab's /48 (the ULA prefix every /64 sits in), or ""."""
    nets = list(prefixes(lab).values())
    return str(ipaddress.ip_network(nets[0]).supernet(new_prefix=48)) if nets else ""


def static_hosts(lab) -> list[tuple]:
    """(node, network id, address) for every static IPv6 address."""
    return [(n, nic.network, str(ipaddress.ip_interface(a).ip))
            for n in lab.node_list() for nic, a in zip(n.nics, addresses(n)) if a]


def plan_lines(lab) -> list[str]:
    """The IPv6 plan of a lab, for `winlab ipv6 status <lab>`."""
    pre = prefixes(lab)
    if not pre:
        return [f"{lab.name}: no IPv6 plan (no machine has vars ipv6)"]
    rs = {r.id for r in routers(lab)}
    out = [f"{lab.name}: ULA {site_prefix(lab)}, {len(rs)} IPv6 routers you build; "
           "the lab router forwards no IPv6"]
    for net_id, p in pre.items():
        net = lab.networks[net_id]
        who = ", ".join(f"{n.id} {ip}" + (f" (eth{n.nics.index(c)})" if n.id in rs else "")
                        for n, nid, ip in static_hosts(lab) if nid == net_id
                        for c in n.nics if c.network == net_id)
        dyn = [n.id for n in lab.nodes_on(net_id) if not any(nid == net_id for m, nid, _ in static_hosts(lab) if m is n)]
        out.append(f"  {net_id:<8} {p:<26} IPv4 {net.cidr:<16} {who}"
                   + (f"; from the router or DHCPv6: {', '.join(dyn)}" if dyn else ""))
    return out


def fault_params(lab) -> dict[str, str]:
    """The drills' parameters (guestfaults.lab_params): the Linux host with
    a fixed IPv6 address (its name and address, for the AAAA drill) and the
    DHCP server's own /64 (the scope the DHCPv6 drill moves)."""
    out: dict[str, str] = {}
    hosts = static_hosts(lab)
    lnx = next(((n, ip) for n, _, ip in hosts if n.kind == "linux" and n not in routers(lab)), None)
    if lnx is not None:
        out["v6host"] = (lnx[0].hostname or lnx[0].id).lower()
        out["v6hostip"] = lnx[1]
    dhcp = next((n for n in lab.node_list() if "dhcp" in n.roles), None)
    if dhcp is not None:
        mine = [a for a in addresses(dhcp) if a]
        if mine:
            out["v6prefix"] = str(ipaddress.ip_interface(mine[0]).network.network_address)
    return out


# ------------------------------------------------------------ the packs
def status() -> list[dict]:
    from . import appliances, debpacks
    out = []
    for p in PACKS:
        st = debpacks.status(p)
        st["image_ready"] = appliances.ready(st["image"])
        out.append(st)
    return out


def render_status(lab=None) -> str:
    sts = status()
    lines = ["IPv6 lab (ipv6-dual-stack): what this PC fetches", ""]
    for st in sts:
        state = (f"ready ({st['count']} packages, {st['size_mb']} MB, fetched {st['fetched']})"
                 if st["ready"] else f"not fetched (about {st['typical_mb']} MB)")
        lines.append(f"  pack {st['id']:<12} {state}")
        lines.append(f"  {'':<17} {st['title']}")
    if not all(st["ready"] for st in sts):
        lines += ["", "  then:  winlab ipv6 fetch   (or winlab packs fetch ipv6-router / ipv6-tools)"
                  + ("" if all(st["image_ready"] for st in sts) else "  (after: winlab images fetch ubuntu)")]
    lines.append("  from the Ubuntu archive, onto a stick each machine installs from by hand")
    if lab is not None:
        lines += [""] + plan_lines(lab)
    return "\n".join(lines) + "\n"


def fetch(progress=None, refresh: bool = False, get=None, download=None) -> list[dict]:
    """Both packs, resolved against the Ubuntu image (fetched first), each
    .deb checked against the SHA-256 the archive's index gives."""
    from . import appliances, debpacks
    if not appliances.ready("ubuntu"):
        raise Ipv6Error("fetch the Ubuntu image first (winlab images fetch ubuntu): the IPv6 packs are "
                        "resolved against what that image already has")
    extra = {k: v for k, v in (("get", get), ("download", download)) if v is not None}
    out = []
    for p in PACKS:
        try:
            out.append(debpacks.fetch(p, progress=progress, refresh=refresh, **extra))
        except debpacks.PackError as exc:
            raise Ipv6Error(f"{p}: {exc}") from exc
    return out


# ------------------------------------------------------------- the drills
NEED_FRR = ("command -v vtysh >/dev/null 2>&1 || { echo 'no FRRouting on this machine: install it from the "
            "ipv6-router pack first (lesson ipv6-addressing-basics)'; exit 1; }; ")
# The first interface that sends router advertisements: FRRouting's running
# configuration says 'no ipv6 nd suppress-ra' inside its block.
RA_IFC = ("vtysh -c 'show running-config' 2>/dev/null | awk '$1==\"interface\"{ifc=$2} "
          "/^ *no ipv6 nd suppress-ra/{print ifc; exit}'")


def _block(ifc: str) -> str:
    """sh printing the running-config block of the interface named by $ifc."""
    return (f"vtysh -c 'show running-config' 2>/dev/null | awk -v i=\"{ifc}\" "
            "'$1==\"interface\"{on=($2==i); next} /^(exit|!)/{on=0} on'")


def _faults():
    from .guestfaults import LINUX, WINDOWS, GuestFault
    ra = f"{STATE_DIR}/ts-ipv6-ra.ifc"
    scope = f"{WIN_STATE}\\ts-dhcpv6.txt"
    aaaa = f"{WIN_STATE}\\ts-aaaa.txt"
    rule = "WinLab-Baseline-ICMPv6-In"
    ptrs = ("$hits = foreach ($rz in (Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -and "
            "$_.ZoneName -like '*.ip6.arpa' })) { Get-DnsServerResourceRecord -ZoneName $rz.ZoneName -RRType Ptr "
            "-ErrorAction SilentlyContinue | Where-Object { $_.RecordData.PtrDomainName -eq \"$n.$z.\" } | "
            "ForEach-Object { [pscustomobject]@{ Zone = $rz.ZoneName; Rec = $_ } } }; ")
    return [
        GuestFault(
            id="ipv6-ra-off",
            images=("ubuntu",),
            title="The PCs on a LAN lost IPv6: only fe80:: addresses and no IPv6 default route",
            os=LINUX,
            teaches="what a router advertisement carries (the prefix for SLAAC, the default router and its "
                    "lifetime, the M and O flags, RDNSS), how a host forgets the router at once when the "
                    "router lifetime drops to 0, and finding a silent router with rdisc6 instead of "
                    "reconfiguring every client",
            symptom="lnx01's ip -6 route has no default any more; a PC whose adapter restarts comes back with "
                    "only a link-local fe80:: address; IPv4 still works everywhere",
            apply=(NEED_FRR + f"mkdir -p {STATE_DIR}; i=$({RA_IFC}); "
                   "[ -n \"$i\" ] || { echo 'no interface sends router advertisements on this router: set them "
                   "up first (lesson ipv6-slaac-ra)'; exit 1; }; "
                   f"echo \"$i\" > {ra}; "
                   "vtysh -c 'configure terminal' -c \"interface $i\" -c 'ipv6 nd ra-lifetime 0' -c 'end' "
                   ">/dev/null; sleep 12; "
                   "vtysh -c 'configure terminal' -c \"interface $i\" -c 'ipv6 nd suppress-ra' -c 'end' "
                   "-c 'write memory' >/dev/null; echo broken"),
            clear=(f"i=$(cat {ra} 2>/dev/null); [ -n \"$i\" ] && vtysh -c 'configure terminal' -c \"interface $i\" "
                   "-c 'no ipv6 nd ra-lifetime' -c 'no ipv6 nd suppress-ra' -c 'end' -c 'write memory' >/dev/null; "
                   f"rm -f {ra}; echo ok"),
            shell="sh",
            hints=(
                "Start on a client: ip -6 addr and ip -6 route on lnx01 (no default via fe80::), "
                "Get-NetIPAddress -AddressFamily IPv6 on pc02 after Restart-NetAdapter (only fe80::). Then ask "
                "the link for a router: sudo rdisc6 eth0 on lnx01. No answer means no router is advertising.",
                "On the router: sudo vtysh -c 'show interface eth0' lists the ND settings when it advertises "
                "(ND advertised router lifetime, Hosts use stateless autoconfig) and prints nothing about ND when "
                "it does not. show running-config shows what changed in the interface's block.",
                "Turn the advertisements back on with a real router lifetime: configure terminal, interface "
                "eth0, no ipv6 nd suppress-ra, no ipv6 nd ra-lifetime, end, write memory. Within an RA interval "
                "rdisc6 answers, lnx01 has its default route via the router's fe80:: address and pc02 its "
                "SLAAC address again.",
            ),
            verify=(f"i=$(cat {ra} 2>/dev/null); [ -n \"$i\" ] && b=$({_block('$i')}) && "
                    "printf '%s\\n' \"$b\" | grep -q 'no ipv6 nd suppress-ra' && "
                    "! printf '%s\\n' \"$b\" | grep -q 'ipv6 nd ra-lifetime 0' && echo True || echo False"),
        ),
        GuestFault(
            id="dhcpv6-wrong-prefix",
            roles=("dhcp",),
            title="PCs that ask DHCPv6 for an address get nothing: the scope is on the wrong prefix",
            os=WINDOWS,
            teaches="how a Windows DHCPv6 server picks the scope for a request (the prefix of the link the "
                    "request arrived on, its own address there), why a scope for a prefix no interface has "
                    "never answers, and that DHCPv6 hands out addresses and options but never a gateway",
            symptom="pc01 has no DHCPv6 address after ipconfig /renew6 (only fe80::), Get-DhcpServerv6Lease has "
                    "no lease on the LAN's prefix, and IPv4 DHCP is untouched",
            apply=("$s = Get-DhcpServerv6Scope -ErrorAction SilentlyContinue | Select-Object -First 1; "
                   "if (-not $s) { 'no DHCPv6 scope on this server: create it first (lesson ipv6-dhcpv6-windows)'; "
                   "exit 1 }; "
                   f"New-Item -ItemType Directory -Force -Path '{WIN_STATE}' | Out-Null; "
                   "$p = $s.Prefix.ToString(); $b = [System.Net.IPAddress]::Parse($p).GetAddressBytes(); "
                   "$b[7] = $b[7] -bxor 0x10; $w = ([System.Net.IPAddress]::new($b)).ToString(); "
                   f"\"$p|$w|$($s.Name)\" | Set-Content -Path '{scope}'; "
                   "Remove-DhcpServerv6Scope -Prefix $p -Force; "
                   "Add-DhcpServerv6Scope -Prefix $w -Name $s.Name -State Active; 'broken'"),
            clear=(f"$f = Get-Content -Path '{scope}' -ErrorAction SilentlyContinue; if ($f) {{ "
                   "$p, $w, $n = $f.Split('|'); Remove-DhcpServerv6Scope -Prefix $w -Force -ErrorAction "
                   "SilentlyContinue; if (-not (Get-DhcpServerv6Scope -Prefix $p -ErrorAction SilentlyContinue)) "
                   f"{{ Add-DhcpServerv6Scope -Prefix $p -Name $n -State Active }}; Remove-Item '{scope}' }}; 'ok'"),
            hints=(
                "On pc01: ipconfig /all shows no DHCPv6-assigned address, and ipconfig /renew6 waits and gives "
                "up. The router still advertises the M flag (Get-NetIPInterface -AddressFamily IPv6 shows "
                "ManagedAddressConfiguration Enabled on pc01's adapter), so pc01 asks; nobody answers.",
                "On dc01: Get-DhcpServerv6Scope lists the scope's prefix; compare it with dc01's own address on "
                "the LAN (Get-NetIPAddress -AddressFamily IPv6 -PrefixOrigin Manual). The server answers a "
                "request only from a scope whose prefix is the link's. The DHCP Server log (Microsoft-Windows-"
                "DHCPv6-Server or the DhcpSrvLog-*.log under C:\\Windows\\System32\\dhcp) says nothing was offered.",
                "Put the scope on the LAN's prefix, {v6prefix}/64: Remove-DhcpServerv6Scope -Prefix <the wrong "
                "one> -Force, then Add-DhcpServerv6Scope -Prefix {v6prefix} -Name lan-a -State Active (and any "
                "exclusion you had). ipconfig /renew6 on pc01 gets an address; Get-DhcpServerv6Lease -Prefix "
                "{v6prefix} lists it.",
            ),
            verify=("$ok = [bool](Get-DhcpServerv6Scope -Prefix '{v6prefix}' -ErrorAction SilentlyContinue); "
                    "$bad = @(Get-DhcpServerv6Scope -ErrorAction SilentlyContinue | Where-Object { "
                    "$_.Prefix.ToString() -ne '{v6prefix}' }).Count; $ok -and $bad -eq 0"),
        ),
        GuestFault(
            id="ipv6-aaaa-missing",
            roles=("dns", "ad-ds"),
            title="lnx01 answers on IPv6 by address but not by name, and its address has no name either",
            os=WINDOWS,
            teaches="which records make a host reachable over IPv6 by name (AAAA in the forward zone, PTR in "
                    "the ip6.arpa zone, the nibble format of a reverse name), why a Linux host with a fixed "
                    "address needs them typed in, and testing each record on its own with Resolve-DnsName",
            symptom="ping -6 lnx01.corp.lab from a PC says it could not find the host (or falls back to IPv4), "
                    "while ping fd12:3456:789a:2::25 answers; Resolve-DnsName on the address returns no name",
            apply=("$n = '{v6host}'; $z = '{domain}'; "
                   "$r = @(Get-DnsServerResourceRecord -ZoneName $z -Name $n -RRType AAAA -ErrorAction "
                   "SilentlyContinue); if (-not $r) { \"no AAAA record for $n.$z yet: add it first (lesson "
                   "ipv6-dns-aaaa-reverse)\"; exit 1 }; "
                   f"New-Item -ItemType Directory -Force -Path '{WIN_STATE}' | Out-Null; "
                   "($r | ForEach-Object { $_.RecordData.IPv6Address.ToString() }) -join ',' | Set-Content -Path "
                   f"'{aaaa}'; "
                   "$r | Remove-DnsServerResourceRecord -ZoneName $z -Force; " + ptrs
                   + "foreach ($h in @($hits)) { if ($h) { $h.Rec | Remove-DnsServerResourceRecord -ZoneName "
                   "$h.Zone -Force } }; 'broken'"),
            clear=("$n = '{v6host}'; $z = '{domain}'; "
                   f"$f = Get-Content -Path '{aaaa}' -ErrorAction SilentlyContinue; if ($f) {{ "
                   "foreach ($a in $f.Split(',')) { Add-DnsServerResourceRecordAAAA -ZoneName $z -Name $n "
                   "-IPv6Address $a -CreatePtr -ErrorAction SilentlyContinue }; "
                   f"Remove-Item '{aaaa}' }}; 'ok'"),
            hints=(
                "Test the name and the address apart, on dc01 or a PC: Resolve-DnsName {v6host}.{domain} -Type "
                "AAAA -DnsOnly, then Resolve-DnsName {v6hostip} (a reverse lookup). Each that fails is a record "
                "to look for. ping -6 {v6hostip} answering proves the network is fine.",
                "In DNS Manager (or Get-DnsServerResourceRecord -ZoneName {domain} -Name {v6host}) the host has "
                "an A record and no AAAA. The reverse zone for the lab's /48 (a name ending in ip6.arpa, "
                "Get-DnsServerZone) has no PTR for it. A Linux server with a fixed address registers nothing "
                "itself: these records are typed in.",
                "Add both in one go: Add-DnsServerResourceRecordAAAA -ZoneName {domain} -Name {v6host} "
                "-IPv6Address {v6hostip} -CreatePtr. Resolve-DnsName {v6host}.{domain} -Type AAAA returns "
                "{v6hostip}, and Resolve-DnsName {v6hostip} returns {v6host}.{domain}.",
            ),
            verify=("$a = @((Resolve-DnsName -Name '{v6host}.{domain}' -Type AAAA -Server 127.0.0.1 -DnsOnly "
                    "-ErrorAction SilentlyContinue | Where-Object Type -eq 'AAAA').IPAddress); "
                    "$p = @((Resolve-DnsName -Name '{v6hostip}' -Type PTR -Server 127.0.0.1 -DnsOnly -ErrorAction "
                    "SilentlyContinue | Where-Object Type -eq 'PTR').NameHost); "
                    "($a -contains '{v6hostip}') -and ($p -contains '{v6host}.{domain}')"),
        ),
        GuestFault(
            id="icmpv6-blocked",
            title="Nothing reaches this PC over IPv6, although it has its address and IPv4 works",
            os=WINDOWS,
            teaches="why IPv6 cannot work without ICMPv6 (neighbour solicitations and advertisements replace "
                    "ARP, router advertisements bring the prefix and the gateway, Packet Too Big replaces "
                    "fragmentation by routers), and why a hardening rule that blocks ICMPv6 inbound breaks "
                    "far more than ping (RFC 4890)",
            symptom="from lnx01 and from the other LAN, ping -6 to this PC fails and ip -6 neigh shows its "
                    "address FAILED or INCOMPLETE; ping by IPv4 answers, and the PC itself still has its "
                    "IPv6 address",
            apply=(f"Remove-NetFirewallRule -Name '{rule}' -ErrorAction SilentlyContinue; "
                   f"New-NetFirewallRule -Name '{rule}' -DisplayName 'Baseline 2.4: block inbound ICMPv6' "
                   "-Group 'Security baseline' -Direction Inbound -Protocol ICMPv6 -Action Block -Profile Any "
                   "| Out-Null; 'broken'"),
            clear=f"Remove-NetFirewallRule -Name '{rule}' -ErrorAction SilentlyContinue; 'ok'",
            hints=(
                "From lnx01: ping -6 -c 2 <this PC's address>, then ip -6 neigh. A neighbour stuck in "
                "INCOMPLETE or FAILED means this PC never answered the neighbour solicitation: the IPv6 "
                "version of ARP gets no reply. IPv4 answering rules out the cable.",
                "On this PC, list what blocks inbound: Get-NetFirewallRule -Direction Inbound -Action Block "
                "-Enabled True | Get-NetFirewallPortFilter shows a rule with Protocol ICMPv6. A block rule "
                "beats every allow rule, including Core Networking's Neighbor Discovery rules.",
                "Remove the blanket block (Remove-NetFirewallRule or Disable-NetFirewallRule on it). If policy "
                "wants ICMPv6 limited, block only what RFC 4890 lets you: never types 1-4 (errors, Packet Too "
                "Big), 133-137 (router and neighbour discovery). ping -6 from lnx01 answers again.",
            ),
            verify=("$bad = @(Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction "
                    "SilentlyContinue | Get-NetFirewallPortFilter | Where-Object { $_.Protocol -in "
                    "@('ICMPv6', '58') }).Count; $bad -eq 0"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
