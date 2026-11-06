"""Every lab starts empty: fresh Windows installs with no addresses, no domain
and no DHCP. A lab's first lesson is to build that foundation by hand, from
the lab's own plan, and this module writes that lesson and its graded
exercise for each lab that needs one.

The files are content like any other lesson (content/lessons/foundation-<lab>.toml
and content/exercises/foundation-<lab>.toml), generated here so they always
match the lab definition; the test suite regenerates them and compares.

    python -m winlab.foundation          # rewrite the files
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

from . import netplan, paths, schema
from .model import Lab, Node

# ad-ds-basics teaches the foundation in its own lessons, capstone is the
# build-it-all exam, sandbox is free play: none of them gets one.
LABS = ("automation", "backup-recovery", "containers", "enterprise-multisite", "every-role", "failover-cluster", "hybrid-cloud", "imaging",
        "databases", "intrusion-detection", "ipv6-dual-stack", "it-docs", "linux-by-hand", "mail", "vm-host-by-hand",
        "security-ops",
        "patching", "perimeter", "remote-access", "time-and-kerberos", "web-farm", "web-proxy", "windows11-desktops")
# Labs with no domain whose machines are routers the student builds (they
# install the frr pack, winlab/routing.py): their foundation is the routers'
# ground floor instead of a forest (render_routers).
ROUTER_LABS = ("dynamic-routing",)
WINDOWS = ("windows-server", "windows-client")


def _q(s: str) -> str:
    """A TOML basic string."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _scope_range(net: ipaddress.IPv4Network) -> tuple[str, str]:
    # The same pool the dhcp role uses, so later lessons find the scope they expect.
    hosts = list(net.hosts())
    if len(hosts) < 160:
        return str(hosts[len(hosts) // 4]), str(hosts[-2])
    return str(net.network_address + 50), str(net.network_address + 150)


def plan(lab: Lab) -> dict:
    """What the foundation is in this lab: the forest root domain controller,
    the DHCP scopes it serves, and the Windows members in its own site. Replica
    DCs, other sites, Linux and appliances have lessons of their own."""
    topo = netplan.compile_topology(lab, check_ports=False)
    nets = dict(lab.networks)
    dcs = [n for n in lab.node_list() if "ad-ds" in n.roles and n.kind in WINDOWS]
    if not dcs:
        raise ValueError(f"{lab.name}: no domain controller in the plan")
    dc = dcs[0]
    site = nets[dc.nics[0].network].site
    # A machine with one leg on the Internet (a VPN edge) still lives in the site.
    inside = lambda n: [c for c in n.nics if not nets[c.network].wan]
    in_site = lambda n: bool(inside(n)) and all(nets[c.network].site in (site, "") for c in inside(n))
    members = [n for n in lab.node_list()
               if n is not dc and n.kind in WINDOWS and "domain-join" in n.roles and in_site(n)]
    scopes = []
    for node in lab.node_list():
        if "dhcp" not in node.roles or node is not dc:
            continue
        own = nets[dc.nics[0].network]
        targets = [own] + [nets[s.network.id] for s in topo.segments.values()
                           if {c.ip for c in dc.nics if c.ip} & set(s.relay_to)]
        for net in targets:
            lo, hi = _scope_range(net.net)
            scopes.append({"network": net.id, "subnet": str(net.net.network_address),
                           "mask": str(net.net.netmask), "lo": lo, "hi": hi,
                           "gateway": net.default_gateway})
    return {"dc": dc, "members": members, "scopes": scopes, "nets": nets}


def _addr_step(node: Node, nets: dict, dns: str) -> str | None:
    static = [c for c in node.nics if c.ip and not nets[c.network].wan]
    if not static:
        return None
    parts = []
    for c in static:
        net = nets[c.network]
        # A machine that is itself its segment's gateway (a VPN edge, a
        # router: gateway_node) gets no default gateway via its own address.
        gw = (f" -DefaultGateway {net.default_gateway}"
              if net.default_gateway and c is static[0] and net.default_gateway != c.ip else "")
        parts.append(f"New-NetIPAddress -InterfaceIndex <n> -IPAddress {c.ip} -PrefixLength {net.prefixlen}{gw}"
                     f" (the adapter on {net.id})")
    many = len(static) > 1
    return (f"On {node.id}, give it its address{'es' if many else ''}: Get-NetAdapter shows the interface"
            f"{'s; match each to its network by MAC in the machine Settings' if many else ''}, then "
            + "; ".join(parts) + f". Point its DNS at {dns}: Set-DnsClientServerAddress -InterfaceIndex <n> "
            f"-ServerAddresses {dns}.")


def _people(lab: Lab, dc: Node) -> dict | None:
    """The company's OUs, people and groups, when later lessons in the lab use
    them (the plan gives the DC ou-structure or users-groups): the same names
    the roles would make, typed in by the student."""
    if "ou-structure" not in dc.roles and "users-groups" not in dc.roles:
        return None
    from . import dsc  # noqa: F401  (dscroles is imported through dsc)
    from .dscroles import DEFAULT_GROUPS, DEFAULT_OUS, DEFAULT_USERS
    base = ",".join(f"DC={p}" for p in lab.domain.split("."))
    ous = [str(o) for o in (dc.vars.get("ous") or DEFAULT_OUS)]
    users = [u for u in (dc.vars.get("users") or DEFAULT_USERS) if u.get("sam")]
    users = [{"sam": u["sam"], "name": u.get("name") or u["sam"], "dept": u.get("dept") or ""} for u in users]
    groups = [g for g in DEFAULT_GROUPS if g["members"]]
    top = ous[0].split("/")[0]
    subs = [o.split("/", 1)[1] for o in ous if "/" in o]
    users_ou = f"OU=Users,OU={top},{base}" if f"{top}/Users" in ous else f"CN=Users,{base}"
    groups_ou = f"OU=Groups,OU={top},{base}" if f"{top}/Groups" in ous else f"CN=Users,{base}"
    who = ", ".join(f"{u['sam']} ({u['name']}{', ' + u['dept'] if u['dept'] else ''})" for u in users)
    grp = "; ".join(f"{g['name']} ({g['scope']}, holding {', '.join(g['members'])})" for g in groups)
    step = (f"Lay the company out in Active Directory on {dc.id}; later lessons use these names. The OU {top} "
            f"with {', '.join(subs)} under it: New-ADOrganizationalUnit {top}, then New-ADOrganizationalUnit "
            f"Users -Path 'OU={top},{base}' and so on. The people, in {users_ou}: {who}. Make each with "
            f"New-ADUser -Name 'Alice Smith' -SamAccountName asmith -Department Sales -Path '{users_ou}' "
            f"-AccountPassword (Read-Host -AsSecureString) -Enabled $true. The groups, in {groups_ou}: {grp}; "
            f"New-ADGroup, then Add-ADGroupMember.")
    return {"step": step, "users": users, "groups": groups, "users_ou": users_ou, "groups_ou": groups_ou}


def render_routers(lab: Lab) -> tuple[str, str]:
    """The foundation of a lab of routers the student builds (a lab with no
    domain, whose machines install the frr pack, winlab/routing.py): the
    cards checked against the plan, FRRouting installed from the stick,
    forwarding switched on, every link and every PC's gateway answering."""
    from . import routing
    rs = routing.routers(lab)
    lks = routing.links(lab)
    lans = routing.lans(lab)
    pcs = [h for _, _, _, hosts in lans for h, _ in hosts if h.image == "ubuntu" and h not in rs]
    lid = f"foundation-{lab.name}"
    names = [r.id for r in rs] + [p.id for p in pcs]
    first = rs[0].id
    cards = "; ".join(f"{r.id}: " + ", ".join(f"{routing.eth_of(r, c.network)} {c.ip}/{lab.networks[c.network].prefixlen} "
                                             f"({c.network})" for c in r.nics if c.ip) for r in rs)
    pings = "; ".join(f"{a[0]} pings {b[2]} ({b[0]}), {b[0]} pings {a[2]}"
                      for ln in lks for a, b in [ln.ends[:2]])
    gws = "; ".join(f"{h.id} pings {ip} ({r.id})" for net, r, ip, hosts in lans for h, _ in hosts if h in pcs)
    far = next(((h, ip) for net, r, _, hosts in reversed(lans) for h, ip in hosts if h in pcs), None)
    steps = [
        f"Start {', '.join(names)}. Each one is a fresh Ubuntu Server: its name, its addresses and nothing else. "
        "Log on as ubuntu with the lab password (the key in the taskbar has it). No machine routes yet and no "
        "routing software is installed: the sites cannot reach each other, and that is where you start.",
        f"Match each card to its network before you configure anything: ip -br addr on every router. The plan: "
        f"{cards}. A router whose cards you mix up advertises the wrong networks later.",
        f"Install FRRouting on each router, from the frr package stick (the lab has no internet): in Machines open "
        f"the router's Settings and press Plug the frr package stick. Then sudo mkdir -p /mnt/winlab-pack; sudo mount "
        f"LABEL=WLPACK /mnt/winlab-pack; cat /mnt/winlab-pack/README.txt and follow it to install frr frr-pythontools "
        f"traceroute. Pull the stick out (Settings) and plug it into the next router.",
        "A Linux machine drops packets that are not addressed to it until you tell it to forward them. On each "
        "router: echo net.ipv4.ip_forward=1 | sudo tee /etc/sysctl.d/90-router.conf, then sudo sysctl --system. "
        "sysctl net.ipv4.ip_forward reads 1; FRRouting's own view: sudo vtysh -c 'show ip forwarding'.",
        f"Prove every link before any routing protocol: {pings}. Every ping answers, because both ends share a "
        f"subnet. A ping that fails here is a cabling or addressing problem, and no protocol will fix it.",
    ]
    if gws:
        steps.append(f"Each PC reaches its own router: {gws}. ip route on a PC shows its default gateway.")
    if far:
        steps.append(f"Now look at what is missing: sudo vtysh -c 'show ip route' on {first} lists only its "
                     f"connected networks (C>*), and from {pcs[0].id} ping {far[1]} ({far[0].id}) fails. The routers "
                     f"forward, but nobody has told them where the other sites are. The next lessons do, with OSPF "
                     f"and BGP instead of static routes.")
    steps.append("Press Check my work. Every later lesson in this lab builds on what you just made.")

    lesson = [
        "# Generated by winlab/foundation.py from the lab definition: edit the lab, then",
        "# python -m winlab.foundation. Hand edits are overwritten.",
        "[lesson]",
        f"id = {_q(lid)}",
        f"title = {_q('Build this lab from empty: routers that forward, links that answer')}",
        'module = "start"',
        "order = 5",
        f"lab = {_q(lab.name)}",
        f"node = {_q(first)}",
        f"nodes = [{', '.join(_q(n) for n in names)}]",
        f"exercise = {_q(lid)}",
        f"minutes = {20 + 5 * len(rs)}",
        f"summary = {_q(f'The routers of {lab.name} are plain Ubuntu servers. Check their cards, install FRRouting from the stick, turn on forwarding and prove every link, by hand.')}",
        "why = '''",
        "A router is a computer that forwards packets between its networks and keeps a",
        "table of where every network is. Here each one is an Ubuntu server with a card",
        "on every segment it joins, and none of them forwards anything yet. The lab router",
        "is only the switches: the sites are joined by nothing but the routers you build,",
        "so whatever works later works because you made it work. First the ground floor:",
        "the right address on the right card, forwarding on, every link answering.",
        "'''",
        "concepts = [",
        '  "Connected routes: a router knows the subnets of its own cards and nothing else until it is told",',
        '  "net.ipv4.ip_forward: a Linux host forwards between its cards only when this is 1",',
        '  "FRRouting: zebra keeps the routing table and writes it to the kernel; ospfd and bgpd speak the protocols; vtysh is the shell",',
        "]",
        "steps = [",
        *(f"  {_q(s)}," for s in steps),
        "]",
        "pitfalls = [",
        '  "sysctl -w net.ipv4.ip_forward=1 is gone after a reboot; the file in /etc/sysctl.d keeps it.",',
        '  "The cards are named in the order the lab file lists them (eth0 first): check with ip -br addr, never assume.",',
        "]",
        "further = [",
        '  "FRRouting documentation: Installation and Basic Setup (vtysh, /etc/frr/daemons)",',
        '  "Ubuntu Server documentation: Configuring networks (netplan)",',
        "]",
        "",
        "[[verify]]",
        'label = "the routing table and forwarding"',
        f"node = {_q(first)}",
        "cmd = \"sysctl net.ipv4.ip_forward; vtysh -c 'show ip route'\"",
        'shell = "sh"',
        "",
        "[[quiz]]",
        'q = "A router with forwarding on and no routing protocol knows routes to which networks?"',
        'answer = "Only the subnets of its own cards (connected routes)"',
        'wrong = ["Every network in the lab", "Only its default gateway", "None at all"]',
        'why = "Connected routes come from the addresses on its cards; everything else must be learned or typed in."',
        "",
        "[[quiz]]",
        'q = "Which setting makes a Linux machine forward packets between its cards?"',
        'answer = "net.ipv4.ip_forward = 1"',
        'wrong = ["net.ipv4.conf.all.rp_filter = 0", "ospfd=yes in /etc/frr/daemons", "A default route"]',
        'why = "Without it the kernel drops packets that are not addressed to the machine itself."',
        "",
    ]

    checks = []
    for r in rs:
        checks.append((f"FRRouting is installed and running on {r.id}", r.id,
                       "dpkg-query -W -f='${Status}' frr 2>/dev/null | grep -q 'ok installed' && systemctl is-active -q frr "
                       "&& echo yes || echo no", "yes", 2,
                       "Plug the frr package stick into it (Settings), mount LABEL=WLPACK and install frr from it as the "
                       "README on the stick says"))
        checks.append((f"{r.id} forwards packets, also after a reboot", r.id,
                       "[ \"$(sysctl -n net.ipv4.ip_forward)\" = 1 ] && grep -rqsE '^[[:space:]]*net\\.ipv4\\.ip_forward[[:space:]]*=[[:space:]]*1' "
                       "/etc/sysctl.conf /etc/sysctl.d && echo yes || echo no", "yes", 1,
                       "echo net.ipv4.ip_forward=1 | sudo tee /etc/sysctl.d/90-router.conf; sudo sysctl --system"))
    for ln in lks:
        (a, _, aip), (b, _, bip) = ln.ends[:2]
        checks.append((f"{a} reaches {b} across {ln.network}", a,
                       f"ping -c 2 -W 2 {bip} >/dev/null 2>&1 && echo yes || echo no", "yes", 1,
                       f"ip -br addr on both: {a} needs {aip}/{lab.networks[ln.network].prefixlen} on the card on "
                       f"{ln.network}, {b} needs {bip}"))
    for net, r, ip, hosts in lans:
        for h, _ in hosts:
            if h in pcs:
                checks.append((f"{h.id} reaches its gateway {r.id}", h.id,
                               f"ping -c 2 -W 2 {ip} >/dev/null 2>&1 && echo yes || echo no", "yes", 1,
                               f"ip route on {h.id} names {ip} as the default gateway; ip -br addr on {r.id} shows {ip} "
                               f"on the card on {net.id}"))
    ex = [
        "# Generated by winlab/foundation.py from the lab definition (python -m winlab.foundation).",
        "[exercise]",
        f"id = {_q(lid)}",
        f"title = {_q(f'{lab.name} built from empty')}",
        f"lab = {_q(lab.name)}",
        "reset_nodes = []",
        f"nodes = [{', '.join(_q(n) for n in names)}]",
        'brief = """',
        f"The routers of {lab.name} are fresh Ubuntu servers with their addresses and",
        "nothing else. Install FRRouting on each, make each one forward, and prove",
        "every link and every PC's gateway.",
        '"""',
        "tasks = [",
        *(f"  {_q(t)}," for t in (
            [f"Install frr from the frr package stick on {', '.join(r.id for r in rs)}",
             "Turn on IPv4 forwarding on every router, in a file under /etc/sysctl.d",
             "Ping across every link between routers"]
            + (["Ping each PC's gateway from the PC"] if pcs else []))),
        "]",
    ]
    for name, node, script, expect, weight, hint in checks:
        ex += ["", "[[check]]", f"name = {_q(name)}", f"node = {_q(node)}", 'shell = "sh"', f"script = {_q(script)}",
               f"expect = {_q(expect)}", f"weight = {weight}", f"hint = {_q(hint)}"]
    return "\n".join(lesson), "\n".join(ex) + "\n"


def render(lab: Lab) -> tuple[str, str]:
    """(lesson TOML, exercise TOML) for the lab's foundation."""
    from . import routing
    if not any("ad-ds" in n.roles for n in lab.node_list()) and routing.routers(lab):
        return render_routers(lab)
    p = plan(lab)
    dc, members, scopes, nets = p["dc"], p["members"], p["scopes"], p["nets"]
    dc_ip = next(c.ip for c in dc.nics if c.ip)
    lid = f"foundation-{lab.name}"
    names = [dc.id] + [m.id for m in members]
    steps = [f"Start {', '.join(names)}. Each one is a fresh Windows install, as it comes out of the box: "
             "no fixed address, no domain, nothing configured. Log on as Administrator (the key in the taskbar has the password)."]
    a = _addr_step(dc, nets, dc_ip)
    if a:
        steps.append(a.replace(f"Point its DNS at {dc_ip}", "Point its DNS at itself"))
    steps.append(f"Make {dc.id} the first domain controller of a new forest: Install-WindowsFeature AD-Domain-Services "
                 f"-IncludeManagementTools, then Install-ADDSForest -DomainName {lab.domain} -DomainNetbiosName "
                 f"{lab.netbios} -InstallDns. It asks for a Directory Services Restore Mode password and restarts. "
                 f"Log on again as {lab.netbios}\\Administrator.")
    if scopes:
        sc = "; ".join(f"Add-DhcpServerv4Scope -Name {s['network']} -StartRange {s['lo']} -EndRange {s['hi']} "
                       f"-SubnetMask {s['mask']}, then Set-DhcpServerv4OptionValue -ScopeId {s['subnet']}"
                       + (f" -Router {s['gateway']}" if s["gateway"] else "")
                       + f" -DnsServer {dc_ip} -DnsDomain {lab.domain}" for s in scopes)
        steps.append(f"Hand out addresses: on {dc.id}, Install-WindowsFeature DHCP -IncludeManagementTools, "
                     f"Add-DhcpServerInDC, then one scope per network it serves: {sc}.")
    people = _people(lab, dc)
    if people:
        steps.append(people["step"])
    for m in members:
        a = _addr_step(m, nets, dc_ip)
        if a:
            steps.append(a)
    joins = [m.id for m in members]
    if joins:
        steps.append(f"Join {', '.join(joins)} to {lab.domain}: {'on each, ' if len(joins) > 1 else ''}Add-Computer -DomainName {lab.domain} "
                     f"-Credential {lab.netbios}\\Administrator -Restart. A machine that gets its address from DHCP "
                     f"(ipconfig /all shows the lease and {dc_ip} as DNS) needs nothing else first.")
    steps.append("Press Check my work. Every later lesson in this lab builds on what you just made.")

    lesson = [
        "# Generated by winlab/foundation.py from the lab definition: edit the lab, then",
        "# python -m winlab.foundation. Hand edits are overwritten.",
        "[lesson]",
        f"id = {_q(lid)}",
        f"title = {_q('Build this lab from empty: addresses, the domain, DHCP')}",
        'module = "start"',
        "order = 5",
        f"lab = {_q(lab.name)}",
        f"node = {_q(dc.id)}",
        f"nodes = [{', '.join(_q(n) for n in names)}]",
        f"exercise = {_q(lid)}",
        f"minutes = {45 + 10 * len(members)}",
        f"summary = {_q(f'Every machine in {lab.name} starts as a fresh install. Give them their addresses, build the {lab.domain} forest, hand out DHCP and join the members, by hand.')}",
        "why = '''",
        "Nobody hands you a working network on your first day in a new building: someone",
        "racked fresh servers, and you make them a company. Every lab in winlab starts the",
        "same way, as plain Windows installs with no fixed address and no domain, because",
        "doing it again in a new layout is how the order sticks: addresses first, then the",
        "domain controller, then DHCP, then the members, each one pointing at the DC for DNS.",
        "'''",
        "concepts = [",
        '  "Order matters: a member cannot join before it can resolve the domain through the DC\'s DNS",',
        '  "The first DC creates the forest; it also runs DNS for the domain",',
        '  "DHCP on a domain controller must be authorized in AD before it hands out a lease",',
        "]",
        "steps = [",
        *(f"  {_q(s)}," for s in steps),
        "]",
        "pitfalls = [",
        '  "Joining before the DNS points at the DC fails with \'domain could not be contacted\'; fix DNS, not the join.",',
        '  "A server given a fixed address but no DNS server cannot find the domain either; set both.",',
        "]",
        "further = [",
        '  "Microsoft Learn: Install Active Directory Domain Services",',
        '  "Microsoft Learn: Deploy DHCP using Windows PowerShell",',
        "]",
        "",
        "[[verify]]",
        'label = "the domain"',
        f"node = {_q(dc.id)}",
        'cmd = "Get-ADDomain | Select-Object DNSRoot, NetBIOSName, PDCEmulator"',
        "",
        "[[quiz]]",
        'q = "What must a server have before it can join the domain?"',
        'answer = "A DNS server that knows the domain, normally the DC"',
        'wrong = ["A DHCP lease", "The same subnet as the DC", "A restart"]',
        'why = "The join finds a DC through DNS SRV records."',
        "",
        "[[quiz]]",
        'q = "Why authorize a Windows DHCP server in AD?"',
        'answer = "An unauthorized domain-joined DHCP server refuses to hand out leases"',
        'wrong = ["To create the scope", "To open the firewall", "To set the gateway"]',
        'why = "It stops rogue DHCP servers inside the domain."',
        "",
    ]

    checks = [("the forest exists and dc is its domain controller", dc.id,
               "(Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot", lab.domain, 3,
               f"Install-WindowsFeature AD-Domain-Services -IncludeManagementTools; Install-ADDSForest -DomainName {lab.domain} -DomainNetbiosName {lab.netbios} -InstallDns")]
    for n in [dc] + members:
        for c in n.nics:
            if c.ip and not nets[c.network].wan:
                checks.append((f"{n.id} has {c.ip}", n.id,
                               f"[bool](Get-NetIPAddress -IPAddress {c.ip} -ErrorAction SilentlyContinue)", "True", 1,
                               f"New-NetIPAddress -InterfaceIndex <n> -IPAddress {c.ip} -PrefixLength {nets[c.network].prefixlen}"))
    for s in scopes:
        checks.append((f"a DHCP scope for {s['network']}", dc.id,
                       f"[bool](Get-DhcpServerv4Scope -ScopeId {s['subnet']} -ErrorAction SilentlyContinue)", "True", 2,
                       f"Install-WindowsFeature DHCP -IncludeManagementTools; Add-DhcpServerInDC; Add-DhcpServerv4Scope -Name {s['network']} -StartRange {s['lo']} -EndRange {s['hi']} -SubnetMask {s['mask']}"))
    if people:
        for u in people["users"]:
            checks.append((f"{u['name']} has an account", dc.id,
                           f"[bool](Get-ADUser -Filter \"SamAccountName -eq '{u['sam']}'\" -ErrorAction SilentlyContinue)",
                           "True", 1, f"New-ADUser -Name '{u['name']}' -SamAccountName {u['sam']} -Department {u['dept']} "
                           f"-Path '{people['users_ou']}' -AccountPassword (Read-Host -AsSecureString) -Enabled $true"))
        for g in people["groups"]:
            checks.append((f"{g['name']} holds {', '.join(g['members'])}", dc.id,
                           f"(Get-ADGroupMember -Identity '{g['name']}' -ErrorAction SilentlyContinue | Measure-Object).Count",
                           str(len(g["members"])), 1,
                           f"New-ADGroup -Name {g['name']} -GroupScope {g['scope']} -Path '{people['groups_ou']}'; "
                           f"Add-ADGroupMember -Identity {g['name']} -Members {','.join(g['members'])}"))
    for m in members:
        checks.append((f"{m.id} is joined to {lab.domain}", m.id,
                       "(Get-CimInstance Win32_ComputerSystem).Domain", lab.domain, 2,
                       f"Set-DnsClientServerAddress -InterfaceIndex <n> -ServerAddresses {dc_ip}; Add-Computer -DomainName {lab.domain} -Restart"))
    ex = [
        "# Generated by winlab/foundation.py from the lab definition (python -m winlab.foundation).",
        "[exercise]",
        f"id = {_q(lid)}",
        f"title = {_q(f'{lab.name} built from empty')}",
        f"lab = {_q(lab.name)}",
        "reset_nodes = []",
        f"nodes = [{', '.join(_q(n) for n in names)}]",
        'brief = """',
        f"The machines of {lab.name} are fresh installs. Give them their addresses, make",
        f"{dc.id} the first domain controller of {lab.domain}, "
        + ("set up DHCP on it, " if scopes else "")
        + "and join the members.",
        '"""',
        "tasks = [",
        *(f"  {_q(t)}," for t in (
            [f"Give every server its fixed address and point its DNS at {dc_ip}",
             f"Promote {dc.id}: a new forest, {lab.domain}"]
            + ([f"Authorize DHCP on {dc.id} and create a scope for {', '.join(s['network'] for s in scopes)}"] if scopes else [])
            + ([f"Join {', '.join(m.id for m in members)} to {lab.domain}"] if members else []))),
        "]",
    ]
    for name, node, script, expect, weight, hint in checks:
        name = name.replace("dc is", f"{dc.id} is")
        ex += ["", "[[check]]", f"name = {_q(name)}", f"node = {_q(node)}", f"script = {_q(script)}",
               f"expect = {_q(expect)}", f"weight = {weight}", f"hint = {_q(hint)}"]
    return "\n".join(lesson), "\n".join(ex) + "\n"


def files(lab_name: str) -> dict[Path, str]:
    lab = schema.load(lab_name)
    lesson, ex = render(lab)
    return {paths.ROOT / "content" / "lessons" / f"foundation-{lab_name}.toml": lesson,
            paths.ROOT / "content" / "exercises" / f"foundation-{lab_name}.toml": ex}


def main() -> int:
    for name in LABS + ROUTER_LABS:
        for path, text in files(name).items():
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(paths.ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
