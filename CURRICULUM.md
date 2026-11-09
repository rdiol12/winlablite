# Curriculum

winlab trial: the lessons of its three labs, in order.

## Start

- **Find your way around the lab** (20 min): Boot the lab, reach a machine three ways, and learn how a lesson is checked.

## Identity

- **Promote the first domain controller** (60 min): Turn a plain server into the forest root domain controller with DNS.
- **Join a member server to the domain** (30 min): Point a server's DNS at the domain controller, join it, and prove the secure channel.
- **Create an OU, a user and a global group** (35 min): Give a department a home in the directory and the group that permissions flow through.
- **Onboard the new starters** (60 min): Turn HR's new-starter sheet into accounts, groups, folders and home drives, then watch the staff sign in and work.
- **Automate joiners from HR's CSV** (50 min): Turn the one-off Import-Csv loop into a script HR's weekly sheet runs through on its own: checked, logged, safe to run twice.
- **A mover: someone changes department** (35 min): Move a person from Sales to Finance: same account, new attributes, swapped groups, no leftover access, and the home folder on Finance's share.
- **Map a network drive with Group Policy** (40 min): Deliver a drive letter to every Sales logon from one place, with a Group Policy Preference.
- **The AD Recycle Bin: bring back a deleted OU with its people and groups** (30 min): Turn the Recycle Bin on before you need it, then restore a whole deleted OU, parent first, with every attribute and group membership.

## Network

- **First-time setup of a switch over the console cable** (30 min): A switch out of the box has no address to reach it on: plug the blue console cable into a PC, open a terminal on its COM port at 9600 8N1, and give the switch its name, banner and port descriptions from its own command line.
- **DNS zones, forwarders and scavenging** (35 min): Read the zones a DC hosts, send outside queries somewhere useful, and stop stale records piling up.
- **DHCP scopes, options and reservations** (30 min): Hand out addresses, gateways and DNS from one place, and pin the machines that must not move.
- **Switching loops, spanning tree and the root bridge** (45 min): A spare cable between switches is a loop. Spanning tree blocks it; you decide which switch is the root.
- **Port security and 802.1X: who may plug into a switch port** (60 min): Lock a desk port to the PC that belongs there, watch a visitor's laptop err-disable it, then make the port ask NPS who is plugging in.
- **OSPF on the lab router: a neighbour across the office LAN** (50 min): Turn on OSPF at the lab router's console and on an Ubuntu router with FRRouting, watch them elect a designated router on a shared LAN, keep the other interfaces quiet, and reach the workshop's network nobody typed a route for.
- **eBGP from the lab router to an ISP, and the way out for the whole office** (45 min): Peer the lab router (AS 65000) with the ISP's router (AS 65100) over eBGP, announce the company's networks with network statements, learn the Internet's, and hand the way out to the workshop's router with an OSPF default route.
- **A VRF for the guest network: one router, two routing tables** (35 min): Put the guest network into a VRF of its own at the lab router's console, so the same router that routes the office no longer routes guests to it: a separate routing table, not an access list.
- **VRRP: one gateway address, two routers behind it** (45 min): Give the office a virtual gateway, 10.80.0.1, shared by the lab router and rtr-edge with VRRP. Point the PC at it, take the master's interface down, and watch the backup take the address over.
- **EtherChannel: two cables between switches as one link, with LACP** (50 min): Bundle two switch-to-switch cables into a port-channel with LACP, read show etherchannel summary, and break it the classic way: on against active.
- **SPAN: mirror a server's switch port to a PC running Wireshark** (45 min): A switch only sends a PC its own traffic. Copy a server's port to a listening PC with monitor session, and read the server's conversations in Wireshark.
- **SSH to the switch: keys, local users and the vty lines** (40 min): Give corp's switch a management address, an RSA key and a local admin, allow only SSH on its vty lines, and log in from pc01 with ssh instead of the console cable.
- **QoS on the router: classify, mark, shape and share a slow line** (60 min): Use the Modular QoS CLI on the router: class-maps that sort traffic, a policy-map that gives voice priority, guarantees file copies a share and marks them, a shaper that turns the user LAN into a 20 Mbit/s line, and the counters that prove each class saw its traffic.

## Workloads

- **A file server: share and NTFS permissions, access-based enumeration** (40 min): Two permission layers decide what a user sees and can do; learn which one to touch.

## Security

- **Install a firewall by hand: OPNsense or pfSense CE, interfaces, first rules** (60 min): Put a real BSD firewall on an empty two-port PC from its own installer, assign WAN and LAN on its console, finish it from a lab PC's browser, then write the first rule and compare OPNsense with pfSense CE.
- **A zone-based firewall on the router: servers and users in their own zones** (60 min): Split the office into a server LAN and a user LAN on the router, put each in a security zone, and let the users reach only the services a domain member needs, with return traffic tracked statefully.
- **Site-to-site IPsec on the router: IKEv2 and a tunnel interface to a branch** (75 min): Join a branch office to the office over an untrusted network with IKEv2 and IPsec: build every IKEv2 and IPsec part on the router, a static virtual tunnel interface, and the branch's own end with strongSwan on Linux.

## Troubleshoot

- **The member that cannot find its domain** (25 min): Group Policy stops applying and domain logons fail on one server; everything else is fine.
- **The server is up but the service is not** (20 min): Clients report the DNS server is gone; the server pings and you can log on.
- **A user is locked out again and again** (25 min): Alice is locked out within minutes of being unlocked; she swears she typed it right.
- **The password that worked yesterday** (15 min): A user is told to change a password they cannot change from where they are.
- **Kerberos fails because the clock drifted** (20 min): Domain logons to one server fail with a clock skew error; local logons work.
- **The share that vanished** (20 min): Every Sales user's S: drive shows a red cross; the files are still on the server.
- **Ping works, RDP does not** (20 min): Administrators cannot Remote Desktop to a server that is otherwise fine.
- **Server Manager cannot get data** (20 min): PowerShell remoting and Server Manager stop reaching a server that pings and takes RDP.
- **RDP times out, and there is no block rule** (20 min): Remote Desktop is allowed on the server, it is listening, and the connection still times out.
- **The disk that filled up** (20 min): Logons are slow, services fail to write, and the server says low disk space.
- **The server that is suddenly slow** (15 min): Everything on one server crawls; the CPU is pinned at 100 percent.
- **Domain users cannot sign in to one server** (25 min): Local accounts sign in, domain accounts get 'the trust relationship failed'; the network is fine.
- **Nobody can find the domain controller** (30 min): The DC is up, DNS answers, and members say no domain controller could be contacted.
- **New PCs get no address** (25 min): Machines on the network work; a rebuilt PC gets 169.254 and nothing else.
- **A service crashed in the night and nobody restarted it** (25 min): After the night's patching DNS is down on the DC; it was not stopped by anyone and did not come back.

## Operations

- **Who is hammering the file server?** (45 min): The file server is slow and the office is busy: read the load with Resource Monitor, Get-SmbSession, Get-SmbOpenFile and performance counters, then find the person and the job behind it.
