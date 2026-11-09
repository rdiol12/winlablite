"""CDP and LLDP on the lab router and the workbench's switches, and the voice
VLAN an access port gives an IP phone.

``show cdp neighbors`` and ``show lldp neighbors`` list what the device
heard on its ports, read from the discovery daemon's own table and laid
out as IOS prints them. ``cdp run`` / ``no cdp run`` and ``lldp run`` /
``no lldp run`` switch the protocols on the whole device (CDP is on and LLDP
off out of the box, as on a Catalyst); ``cdp enable``, ``lldp transmit`` and
``lldp receive`` do it per interface. ``switchport voice vlan <n>`` on an
access port carries the phone's VLAN tagged beside the data VLAN, and LLDP-MED
tells the phone which VLAN that is.

How it is real. The daemon is lldpd (ISC licence), Alpine's ``lldpd``
package from the lab's own package volume (alpineovl.APPLIANCE_PACKAGES),
installed on the router the first time it is needed, as FRRouting is. Each
device runs its own lldpd for each protocol: ``<device>-cdp`` speaks CDPv2
only (``-ccccc -ll``: CDPv1 off, CDPv2 sent whether or not a peer was heard,
LLDP off) every 60 seconds with a 180 second holdtime, IOS's CDP timers;
``<device>-lldp`` speaks LLDP only (``-l``), every 30 seconds with a 120 second
TTL, and a switch's also speaks LLDP-MED as a network connectivity device
(``-M 4``). One daemon per device and protocol is what lets each device
have its own system name, platform and capabilities, and lets ``no cdp
enable`` on one port leave LLDP running there (lldpd's per-port status
covers every protocol a daemon speaks). Each daemon is given exactly the
interfaces that are that device's ports (``-I``), its own control socket
(``-u``) and its own configuration (``-O``: system name, description,
platform, capabilities, each port's IOS name as its port ID, the per-port
LLDP status, the voice VLAN's LLDP-MED network policy):

* a switch's FastEthernet port is the router's bridge port for the machine
  cabled there (winlab/netplan.py), so the switch's daemons hear the machine
  itself: an IP phone (the ipphone role runs lldpd as an LLDP-MED endpoint,
  class III), an Ubuntu machine once the student installs lldpd from the
  ``lldpd`` pack, an OpenWrt access point if lldpd is installed on it. A
  Windows machine sends no LLDP out of the box (its LLDP driver only
  listens, for Data Center Bridging), so its port shows nothing, and the
  console says so;
* a switch-to-switch cable is a veth pair between two switch bridges
  (winlab/stp.py), so the two switches' daemons hear each other over the
  same wire their frames cross;
* between the router and a switch there is no wire on the router: the
  router's port is its own VLAN interfaces on the lab bridge. A veth pair
  (``wldr<h>`` - ``wlds<h>``, in no bridge, no address) stands in for that
  one cable and carries the two daemons' CDP and LLDP frames and nothing
  else; it is down while the router's port is shut down. That cable is a
  stand-in, the protocol on it is not.

A Catalyst does not pass CDP on to its other ports; a Linux bridge floods
CDP's multicast like any other, so a bridge rule (nftables, table bridge
winlab_cdp) drops CDP frames the bridges would forward. LLDP's address is
one a bridge never forwards.

What is not here, and why:

* CDP's voice VLAN (the Appliance VLAN TLV a Catalyst sends to Cisco phones):
  lldpd does not send it. A phone learns the voice VLAN from LLDP-MED's
  network policy, which the lab's phones read: ``lldp run`` must be on for
  them to find it, as for any non-Cisco phone.
* ``cdp timer`` / ``cdp holdtime`` and LLDP's timers: the daemons run IOS's
  defaults and the commands are not offered.
* What a show prints about the neighbour's software is what the neighbour
  sent: the lab's own switches and router say they are winlab consoles with
  lldpd on Linux, never a Cisco IOS version.

Tested in the sandbox without lldpd: the lldpd and lldpcli command lines
and configuration files are checked against lldpd's manual (1.0.x), the
show commands against keyvalue output written as lldpcli's kv writer
prints it, and the shell with sh -n.

Settings ([devices."router"] and [devices."sw:<id>"]; ``<key>`` a router
interface's name, a switch port's machine cable (pc01:nic0) or its name
when nothing is plugged in): ``cdp-off`` (no cdp run), ``lldp-run``,
``nocdp:<key>``, ``nolldptx:<key>``, ``nolldprx:<key>``; on a switch
``voice:<cable>`` = the voice VLAN, with that VLAN's network tagged on the
card's port (Nic.trunk, which the router's bridge follows).

The ts-voice-vlan-wrong problem (``voice-vlan-wrong``, register_faults) is
broken from outside the phone: host_break sets the phone's port to a voice
VLAN one off from the configured one, as a mistyped ``switchport voice vlan``
would. It is held in the lab folder (``lldp-fault.json``), not in the lab
file, so a dashboard that has the lab open cannot write it away; the show
commands and the LLDP-MED policy follow it, while the bridge keeps tagging
the VLAN the port had, so the phone tags frames nobody carries. Setting the
voice VLAN on that port again clears it.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass, field

from . import devcli

RUN = "/run/winlab-lldp"
NFT_TABLE = "winlab_cdp"
CDP_MAC = "01:00:0c:cc:cc:cc"
CDP_TIMER, CDP_HOLD = 60, 180
LLDP_TIMER, LLDP_HOLD = 30, 120
LLDP_REINIT = 2
VOICE_COS, VOICE_DSCP = 5, 46
INSTALL = ("command -v lldpd >/dev/null 2>&1 || apk add --no-network lldpd >/dev/null 2>&1 || "
           "echo 'winlab: lldpd is not on the package volume (winlab images prepare fabric)' > /dev/kmsg")
NO_DAEMON = ("% lldpd is not on the router: its package volume predates CDP and LLDP here. Prepare the router "
             "again (winlab images prepare fabric) and power the network on again.")
ID_TYPES = ("mac", "local", "ifname", "ifalias", "ip", "unhandled", "unknown")
WORD_HELP = {
    ("cdp",): "Global CDP configuration subcommands", ("lldp",): "Global LLDP configuration subcommands",
    ("show", "cdp", "neighbors"): "CDP neighbor entries", ("show", "lldp"): "LLDP information",
    ("show", "lldp", "neighbors"): "LLDP neighbor entries", ("switchport", "voice"): "Voice appliance attributes",
}


# ------------------------------------------------------------------ settings
def _own(lab, device: str) -> dict:
    return lab.devices.get(device, {})


def cdp_run(lab, device: str) -> bool:
    return not _own(lab, device).get("cdp-off")


def lldp_run(lab, device: str) -> bool:
    return bool(_own(lab, device).get("lldp-run"))


def port_state(lab, device: str, key: str) -> tuple[bool, bool, bool]:
    """(CDP, LLDP transmit, LLDP receive) on one interface."""
    own = _own(lab, device)
    cdp = cdp_run(lab, device) and not own.get(f"nocdp:{key}")
    run = lldp_run(lab, device)
    return cdp, run and not own.get(f"nolldptx:{key}"), run and not own.get(f"nolldprx:{key}")


def tag(device: str) -> str:
    """The device's name on the router: r for the router, s<hash> for a switch."""
    if device == devcli.ROUTER:
        return "r"
    return "s" + hashlib.sha256(devcli.switch_id(device).encode()).hexdigest()[:6]


def link_names(sw: str) -> tuple[str, str]:
    """The stand-in cable between the router and switch `sw`: (router end, switch end)."""
    h = hashlib.sha256(sw.encode()).hexdigest()[:6]
    return f"wldr{h}", f"wlds{h}"


@dataclass
class Port:
    name: str      # the IOS interface name
    iface: str     # the router's interface the daemon runs on ("" when nothing is cabled)
    key: str       # the settings key
    node: str = ""  # the machine cabled to it


def ports(lab, plan, device: str) -> list[Port]:
    """A device's interfaces, in IOS order, with the router interface each one is."""
    out: list[Port] = []
    if device == devcli.ROUTER:
        for name, sw in devcli.router_ports(lab):
            ok = bool(sw) and devcli.uplinked(lab, sw) and not devcli.upstream(lab, sw)
            out.append(Port(name, link_names(sw)[0] if ok else "", name))
        return out
    sw = devcli.switch_id(device)
    from . import stp
    links = devcli.switch_ports(lab, plan).get(sw, [])
    for i in range(1, devcli.SWITCH_PORTS + 1):
        link = links[i - 1] if i <= len(links) else None
        if link is not None:
            out.append(Port(f"FastEthernet0/{i}", link.fabric_iface or "", link.label, link.node_id))
        else:
            out.append(Port(f"FastEthernet0/{i}", "", f"FastEthernet0/{i}"))
    gis = stp.ifnames(lab)
    for name in devcli.gig_names():
        dev = gis.get(f"{sw} {name}", "")
        if not dev and name == stp.GI1 and devcli.uplinked(lab, sw) and not devcli.upstream(lab, sw):
            dev = link_names(sw)[1]
        out.append(Port(name, dev, name))
    return out


def devices(lab) -> list[str]:
    return [devcli.ROUTER] + [f"sw:{s}" for s in devcli.switches(lab) if not devcli.switch_off(lab, s)]


def _mgmt(lab, plan, device: str) -> str:
    """The address the device advertises: the router's first interface
    address, a switch's management address (interface vlan)."""
    if device == devcli.ROUTER:
        own = _own(lab, device)
        for name, _sw in devcli.router_ports(lab):
            for k in sorted(own):
                if k.startswith("ip:") and k[3:].split(".")[0] == name:
                    net = lab.networks.get(own[k])
                    if net is not None and net.routed and net.router_ip:
                        return str(net.router_ip)
        return ""
    from . import iosl2
    addrs = iosl2.svis(lab, devcli.switch_id(device))
    return addrs[0][1].split("/")[0] if addrs else ""


# ------------------------------------------------------------------ the daemons
@dataclass
class Instance:
    name: str
    args: list[str]
    conf: list[str]
    ifaces: list[str] = field(default_factory=list)

    def line(self) -> str:
        return " ".join(shlex.quote(a) for a in ["lldpd"] + self.args)

    def sig(self) -> str:
        return hashlib.sha256((self.line() + "\n" + "\n".join(self.conf)).encode()).hexdigest()[:12]


def _q(text: str) -> str:
    """A value in an lldpcli configuration line: double-quoted, nothing that ends it."""
    return '"' + re.sub(r'["\\\n]', "", text) + '"'


def system_lines(lab, device: str, timer: int, hold: int, mgmt: str) -> list[str]:
    name = devcli.ios_name(lab, device)
    router = device == devcli.ROUTER
    platform = "cisco " + devcli.MODEL[devcli.ROUTER if router else "switch"]
    desc = (f"winlab {'router' if router else 'switch'} console ({devcli.MODEL[devcli.ROUTER if router else 'switch']}"
            f", IOS-like); discovery by lldpd on the lab router, Linux")
    out = [f"configure system hostname {_q(name)}", f"configure system description {_q(desc)}",
           f"configure system platform {_q(platform)}",
           f"configure system capabilities enabled {'router' if router else 'bridge'}",
           f"configure lldp tx-interval {timer}", f"configure lldp tx-hold {hold // timer}"]
    if not mgmt:
        out.append("unconfigure lldp management-addresses-advertisements")
    return out


def instances(lab, plan) -> list[Instance]:
    """The daemons the devices' settings ask for."""
    out: list[Instance] = []
    for device in devices(lab):
        t = tag(device)
        mgmt = _mgmt(lab, plan, device)
        cabled = [p for p in ports(lab, plan, device) if p.iface]
        sw = devcli.switch_id(device)
        for proto in ("cdp", "lldp"):
            name = f"{t}-{proto}"
            use, port_lines = [], []
            for p in cabled:
                cdp, tx, rx = port_state(lab, device, p.key)
                if proto == "cdp" and not cdp:
                    continue
                if proto == "lldp" and not (tx or rx):
                    continue
                use.append(p.iface)
                port_lines.append(f"configure ports {p.iface} lldp portidsubtype local "
                                  f"{devcli.short_if(p.name)} description {p.name}")
                if proto == "lldp" and not (tx and rx):
                    port_lines.append(f"configure ports {p.iface} lldp status {'tx-only' if tx else 'rx-only'}")
                if proto == "lldp" and sw:
                    v = voice_vlan(lab, sw, p.key)
                    if v:
                        port_lines.append(f"configure ports {p.iface} med policy application voice tagged "
                                          f"vlan {v} priority voice dscp {VOICE_DSCP}")
            if not use:
                continue
            timer, hold = (CDP_TIMER, CDP_HOLD) if proto == "cdp" else (LLDP_TIMER, LLDP_HOLD)
            args = ["-u", f"{RUN}/{name}.sock", "-p", f"{RUN}/{name}.pid", "-I", ",".join(use), "-C", "!*",
                    "-H", "0", "-O", f"{RUN}/{name}.conf"]
            args += ["-ll", "-ccccc"] if proto == "cdp" else ["-l"]
            if proto == "lldp" and sw:
                args += ["-M", "4"]
            if mgmt:
                args += ["-m", mgmt]
            out.append(Instance(name, args, system_lines(lab, device, timer, hold, mgmt) + port_lines, use))
    return out


def stand_ins(lab) -> list[tuple[str, str, bool]]:
    """(router end, switch end, up) per switch cabled straight into a router port."""
    out = []
    for name, sw in devcli.router_ports(lab):
        if sw and devcli.uplinked(lab, sw) and not devcli.upstream(lab, sw):
            r, s = link_names(sw)
            up = not devcli.router_shut(lab, name) and not devcli.switch_off(lab, sw)
            out.append((r, s, up))
    return out


def render(plan, reset: bool = False) -> list[str]:
    """Shell for the router: the stand-in cables, the CDP bridge rule and
    one lldpd per device and protocol, started again only when its command
    line or configuration changed (it runs at the end of winlab/iosl2.py's
    lines, after the switch bridges and their veths exist)."""
    lab = plan.lab
    want = instances(lab, plan)
    links = stand_ins(lab)
    if not want and not links and not reset:
        return []
    out = ["# CDP and LLDP: an lldpd per device and protocol (winlab/lldp.py)", f"mkdir -p {RUN}",
           f"nft delete table bridge {NFT_TABLE} 2>/dev/null; nft -f - <<'WLCDPNFT' || true",
           f"table bridge {NFT_TABLE} {{",
           "  chain forward {",
           "    type filter hook forward priority -200; policy accept;",
           f"    ether daddr {CDP_MAC} drop comment \"a switch keeps CDP to itself\"",
           "  }",
           "}",
           "WLCDPNFT"]
    keep = "|".join(sorted({x for r, s, _ in links for x in (r, s)})) or "-"
    out.append(f"for i in $(ls /sys/class/net 2>/dev/null | grep '^wld[rs]'); do case $i in {keep}) ;; "
               f"*) ip link del $i 2>/dev/null;; esac; done; true")
    for r, s, up in links:
        out += [f"[ -e /sys/class/net/{r} ] || ip link add {r} type veth peer name {s} || true"
                f"   # stand-in for the router-to-switch cable: discovery frames only",
                f"sysctl -qw net.ipv6.conf.{r}.disable_ipv6=1 net.ipv6.conf.{s}.disable_ipv6=1 2>/dev/null || true",
                f"ip link set {r} {'up' if up else 'down'}; ip link set {s} {'up' if up else 'down'}"]
    names = "|".join(i.name for i in want) or "-"
    out.append(f"for p in {RUN}/*.pid; do [ -f \"$p\" ] || continue; n=${{p##*/}}; n=${{n%.pid}}; "
               f"case $n in {names}) ;; *) kill $(cat \"$p\") 2>/dev/null; rm -f \"$p\" {RUN}/$n.sock {RUN}/$n.sig;; "
               f"esac; done; true")
    if want:
        out.append(INSTALL)
        out.append("if command -v lldpd >/dev/null 2>&1; then")
        for inst in want:
            base = f"{RUN}/{inst.name}"
            out += [f"cat > {base}.conf <<'WLLLDP'", *inst.conf, "WLLLDP",
                    f"if [ \"$(cat {base}.sig 2>/dev/null)\" != {inst.sig()} ] || "
                    f"! kill -0 \"$(cat {base}.pid 2>/dev/null)\" 2>/dev/null; then",
                    f"  [ -f {base}.pid ] && kill \"$(cat {base}.pid)\" 2>/dev/null && sleep 1",
                    f"  rm -f {base}.pid {base}.sock",
                    f"  {inst.line()} && echo {inst.sig()} > {base}.sig",
                    "fi"]
        out.append("fi")
    out.append("")
    return out


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


# ------------------------------------------------------------------ lldpcli's table
@dataclass
class Neighbor:
    iface: str
    via: str = ""
    age: int = 0
    chassis_type: str = ""
    chassis_id: str = ""
    name: str = ""
    descr: str = ""
    mgmt: list[str] = field(default_factory=list)
    caps: dict[str, bool] = field(default_factory=dict)   # capability -> enabled
    port_type: str = ""
    port_id: str = ""
    port_descr: str = ""
    ttl: int = 0
    pvid: int = 0
    med_type: str = ""
    med_caps: list[str] = field(default_factory=list)
    policies: list[dict] = field(default_factory=list)
    inventory: dict[str, str] = field(default_factory=dict)

    @property
    def port(self) -> str:
        return devcli.dotted_mac(self.port_id) if self.port_type == "mac" else self.port_id

    @property
    def remaining(self) -> int:
        return max(0, self.ttl - self.age) if self.ttl else 0

    @property
    def cdp(self) -> bool:
        return self.via.upper().startswith("CDP")

    @property
    def device_id(self) -> str:
        return self.name or self.chassis_id

    @property
    def platform(self) -> str:
        return self.descr.split(" running on ", 1)[0].strip() if " running on " in self.descr else ""

    @property
    def software(self) -> str:
        return self.descr.split(" running on ", 1)[1].strip() if " running on " in self.descr else self.descr


def parse_age(text: str) -> int:
    """lldpcli's '1 day, 02:03:04' as seconds."""
    m = re.match(r"^\s*(\d+)\s+days?,\s*(\d+):(\d+):(\d+)", text or "")
    if not m:
        return 0
    d, h, mi, s = (int(x) for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + s


def parse_keyvalue(text: str) -> list[Neighbor]:
    """`lldpcli -f keyvalue show neighbors details`: one Neighbor per
    remote port, in the order lldpcli lists them (a new one starts at each
    interface's via= line)."""
    out: list[Neighbor] = []
    cur: Neighbor | None = None
    policy: dict | None = None
    for raw in (text or "").splitlines():
        if "=" not in raw or not raw.startswith("lldp."):
            continue
        key, _, val = raw.partition("=")
        parts = key.split(".", 2)
        if len(parts) < 3:
            continue
        iface, rest = parts[1], parts[2]
        if rest == "via" or cur is None or cur.iface != iface:
            cur = Neighbor(iface)
            out.append(cur)
            policy = None
        if rest == "via":
            cur.via = val
        elif rest == "age":
            cur.age = parse_age(val)
        elif rest.startswith("chassis."):
            sub = rest[8:]
            if sub in ID_TYPES:
                cur.chassis_type, cur.chassis_id = sub, val
            elif sub == "name":
                cur.name = val
            elif sub == "descr":
                cur.descr = val
            elif sub == "mgmt-ip":
                cur.mgmt.append(val)
            elif sub.endswith(".enabled"):
                cur.caps[sub[:-8]] = val == "on"
        elif rest.startswith("port."):
            sub = rest[5:]
            if sub in ID_TYPES:
                cur.port_type, cur.port_id = sub, val
            elif sub == "descr":
                cur.port_descr = val
            elif sub == "ttl" and val.isdigit():
                cur.ttl = int(val)
        elif rest == "vlan.vlan-id" and val.isdigit():
            cur.pvid = cur.pvid or int(val)
        elif rest.startswith("lldp-med."):
            sub = rest[9:]
            if sub == "device-type":
                cur.med_type = val
            elif sub.endswith(".available") and not sub.startswith("policy"):
                cur.med_caps.append(sub[:-10])
            elif sub == "policy.apptype":
                policy = {"apptype": val}
                cur.policies.append(policy)
            elif sub.startswith("policy.") and policy is not None:
                policy[sub[7:]] = val
            elif sub.startswith("inventory."):
                cur.inventory[sub[10:]] = val
    return [n for n in out if n.via]


# ------------------------------------------------------------------ formatting
_CDP_CAP = {"Router": "R", "Bridge": "S", "Station": "H", "Tel": "P", "Repeater": "r", "Wlan": "T",
            "Other": "", "Docsis": ""}
_CDP_WORD = {"Router": "Router", "Bridge": "Switch", "Station": "Host", "Tel": "Phone", "Repeater": "Repeater",
             "Wlan": "Trans-Bridge"}
_LLDP_CAP = {"Router": "R", "Bridge": "B", "Tel": "T", "Docsis": "C", "Wlan": "W", "Repeater": "P",
             "Station": "S", "Other": "O"}
CDP_HEAD = ["Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge",
            "                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone, ",
            "                  D - Remote, C - CVTA, M - Two-port Mac Relay ", ""]
LLDP_HEAD = ["Capability codes:", "    (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device",
             "    (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other", ""]


def cdp_if(name: str) -> str:
    """'FastEthernet0/1' -> 'Fas 0/1' (CDP's brief table); other names as they are."""
    m = re.match(r"^(FastEthernet|GigabitEthernet|TenGigabitEthernet|Ethernet)(\d.*)$", name)
    if not m:
        return name
    return {"FastEthernet": "Fas", "GigabitEthernet": "Gig", "TenGigabitEthernet": "Ten",
            "Ethernet": "Eth"}[m.group(1)] + " " + m.group(2)


def _local(n: Neighbor, ifmap: dict[str, str]) -> str:
    return ifmap.get(n.iface, n.iface)


def cdp_brief(neigh: list[Neighbor], ifmap: dict[str, str]) -> str:
    rows = [n for n in neigh if n.cdp]
    out = CDP_HEAD + [f"{'Device ID':<17}{'Local Intrfce':<18}{'Holdtme':<11}{'Capability':<12}{'Platform':<10}Port ID"]
    for n in rows:
        caps = " ".join(c for c in (_CDP_CAP.get(k, "") for k, on in n.caps.items() if on) if c)
        plat = n.platform.replace("cisco ", "", 1)[:9]
        dev = n.device_id
        head = f"{dev:<17}" if len(dev) <= 16 else f"{dev}\n{'':<17}"
        out.append(f"{head}{cdp_if(_local(n, ifmap)):<18}{n.remaining:<11}{caps:>10}  {plat:<10}"
                   f"{cdp_if(n.port_id)}".rstrip())
    out += ["", f"Total cdp entries displayed : {len(rows)}"]
    return "\n".join(out)


def cdp_detail(neigh: list[Neighbor], ifmap: dict[str, str]) -> str:
    rows = [n for n in neigh if n.cdp]
    out = []
    for n in rows:
        caps = " ".join(_CDP_WORD[k] for k, on in n.caps.items() if on and k in _CDP_WORD)
        out += ["-------------------------", f"Device ID: {n.device_id}", "Entry address(es): "]
        out += [f"  IP address: {ip}" for ip in n.mgmt if "." in ip]
        out += [f"Platform: {n.platform or 'unknown'},  Capabilities: {caps} ",
                f"Interface: {_local(n, ifmap)},  Port ID (outgoing port): {n.port_id}",
                f"Holdtime : {n.remaining} sec", "", "Version :", n.software, "",
                "advertisement version: 2"]
        if n.pvid:
            out.append(f"Native VLAN: {n.pvid}")
        out += ["Duplex: full", ""]
    out.append(f"Total cdp entries displayed : {len(rows)}")
    return "\n".join(out)


def _caps_lldp(caps: dict[str, bool], enabled: bool) -> str:
    return ",".join(_LLDP_CAP[k] for k, on in caps.items() if k in _LLDP_CAP and (on or not enabled))


def lldp_brief(neigh: list[Neighbor], ifmap: dict[str, str]) -> str:
    rows = [n for n in neigh if not n.cdp]
    out = LLDP_HEAD + [f"{'Device ID':<20}{'Local Intf':<15}{'Hold-time':<11}{'Capability':<16}Port ID"]
    for n in rows:
        dev = n.device_id[:20]
        out.append(f"{dev:<20}{devcli.short_if(_local(n, ifmap)):<15}{n.ttl:<11}"
                   f"{_caps_lldp(n.caps, True):<16}{n.port}".rstrip())
    out += ["", f"Total entries displayed: {len(rows)}"]
    return "\n".join(out)


def _chassis(n: Neighbor) -> str:
    return devcli.dotted_mac(n.chassis_id) if n.chassis_type == "mac" else n.chassis_id


_MED_CODE = {"Capabilities": "", "Policy": "NP", "Location": "LI", "MDI/PSE": "PS", "MDI/PD": "PD",
             "Inventory": "IN"}


def _med_type(text: str) -> str:
    m = re.search(r"Class (I{1,3}|IV)\b", text or "")
    if "Network Connectivity" in (text or ""):
        return "Network Connectivity"
    return f"Endpoint Class {m.group(1)}" if m else (text or "unknown")


def lldp_detail(neigh: list[Neighbor], ifmap: dict[str, str]) -> str:
    rows = [n for n in neigh if not n.cdp]
    out = []
    for n in rows:
        out += ["------------------------------------------------",
                f"Local Intf: {devcli.short_if(_local(n, ifmap))}", f"Chassis id: {_chassis(n)}",
                f"Port id: {n.port}", f"Port Description: {n.port_descr or '- not advertised'}",
                f"System Name: {n.name or '- not advertised'}", "", "System Description: ", n.descr, "",
                f"Time remaining: {n.remaining} seconds",
                f"System Capabilities: {_caps_lldp(n.caps, False)}",
                f"Enabled Capabilities: {_caps_lldp(n.caps, True)}", "Management Addresses:"]
        out += [f"    IP{'V6' if ':' in ip else ''}: {ip}" for ip in n.mgmt] or ["    - not advertised"]
        out += ["Auto Negotiation - not supported", "Physical media capabilities - not advertised",
                "Media Attachment Unit type - not advertised",
                f"Vlan ID: {n.pvid}" if n.pvid else "Vlan ID: - not advertised"]
        if n.med_type:
            codes = ", ".join(c for c in (_MED_CODE.get(x, "") for x in n.med_caps) if c)
            out += ["", "MED Information:", "", "    MED Codes:",
                    "          (NP) Network Policy, (LI) Location Identification",
                    "          (PS) Power Source Entity, (PD) Power Device", "          (IN) Inventory", ""]
            inv = n.inventory
            if inv:
                out.append("    Inventory information")
                for k, word in (("hardware", "H/W revision"), ("firmware", "F/W revision"),
                                ("software", "S/W revision"), ("serial", "Serial number"),
                                ("manufacturer", "Manufacturer"), ("model", "Model")):
                    if inv.get(k):
                        out.append(f"      {word}: {inv[k]}")
            else:
                out.append("    Inventory information - not advertised")
            out += [f"    Capabilities: {codes}", f"    Device type: {_med_type(n.med_type)}"]
            for p in n.policies:
                vid = p.get("vlan.vid", "")
                where = (f"VLAN {vid}, tagged" if vid and vid.isdigit() else
                         "VLAN priority-tagged" if vid == "priority" else "untagged")
                if p.get("defined") == "no":
                    where = "unknown"
                out.append(f"    Network Policy({p.get('apptype', '')}): {where}, "
                           f"Layer-2 priority: {p.get('pcp', '0')}, DSCP: {p.get('dscp', '0')}")
            out.append("    Location - not advertised")
        out.append("")
    out.append(f"Total entries displayed: {len(rows)}")
    return "\n".join(out)


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    for k, v in WORD_HELP.items():
        devcli.WORD_HELP.setdefault(k, v)
    router = con.device == devcli.ROUTER
    IF = I if router else I + ("config-if-range",)
    add("cdp run", lambda a: _global(con, "cdp-off", False), "Enable CDP", C)
    add("no cdp run", lambda a: _global(con, "cdp-off", True), "Negate a command or set its defaults", C)
    add("lldp run", lambda a: _global(con, "lldp-run", True), "Enable LLDP", C)
    add("no lldp run", lambda a: _global(con, "lldp-run", False), "Negate a command or set its defaults", C)
    add("cdp enable", lambda a: _port(con, "nocdp", False), "Enable CDP on interface", IF)
    add("no cdp enable", lambda a: _port(con, "nocdp", True), "Negate a command or set its defaults", IF)
    add("lldp transmit", lambda a: _port(con, "nolldptx", False), "Enable LLDP transmission on interface", IF)
    add("no lldp transmit", lambda a: _port(con, "nolldptx", True), "Negate a command or set its defaults", IF)
    add("lldp receive", lambda a: _port(con, "nolldprx", False), "Enable LLDP reception on interface", IF)
    add("no lldp receive", lambda a: _port(con, "nolldprx", True), "Negate a command or set its defaults", IF)
    add("show cdp", lambda a: show_cdp(con), "CDP information", U)
    add("show cdp neighbors", lambda a: show_neighbors(con, "cdp", ""), "CDP neighbor entries", U)
    add("show cdp neighbors detail", lambda a: show_neighbors(con, "cdp", "", True), "Show detailed information", U)
    add("show cdp neighbors <line>", lambda a: show_neighbors(con, "cdp", a[0]), "CDP neighbor entries", U)
    add("show cdp entry <line>", lambda a: show_entry(con, "cdp", a[0]), "Information for specific neighbor entry", U)
    add("show cdp interface", lambda a: show_interface(con, "cdp", ""), "CDP interface status and configuration", U)
    add("show cdp interface <line>", lambda a: show_interface(con, "cdp", a[0]),
        "CDP interface status and configuration", U)
    add("show lldp", lambda a: show_lldp(con), "LLDP information", U)
    add("show lldp neighbors", lambda a: show_neighbors(con, "lldp", ""), "LLDP neighbor entries", U)
    add("show lldp neighbors detail", lambda a: show_neighbors(con, "lldp", "", True), "Show detailed information", U)
    add("show lldp neighbors <line>", lambda a: show_neighbors(con, "lldp", a[0]), "LLDP neighbor entries", U)
    add("show lldp entry <line>", lambda a: show_entry(con, "lldp", a[0]), "Information for specific neighbor entry", U)
    add("show lldp interface", lambda a: show_interface(con, "lldp", ""), "LLDP interface status and configuration", U)
    add("show lldp interface <line>", lambda a: show_interface(con, "lldp", a[0]),
        "LLDP interface status and configuration", U)
    if not router:
        add("switchport voice vlan <line>", lambda a: set_voice(con, a[0]), "Vlan for voice traffic", IF)
        add("no switchport voice vlan", lambda a: set_voice(con, ""), "Negate a command or set its defaults", IF)


def _global(con, key: str, on: bool) -> str:
    own = devcli.settings(con.lab, con.device)
    if on:
        own[key] = "yes"
    else:
        own.pop(key, None)
    return con._save().strip()


def iface_key(con) -> str:
    """The settings key of the interface being configured."""
    ctx = con.s.ctx
    if con.device == devcli.ROUTER:
        if "." in ctx or not ctx.startswith("GigabitEthernet"):
            raise devcli.CliError("% CDP and LLDP run on the router's physical ports, not on "
                                  f"{devcli.short_if(ctx)}")
        return ctx
    if ctx.startswith(("Vlan", "Port-channel")):
        raise devcli.CliError(f"% Set CDP and LLDP on the switch's ports, not on {ctx}")
    link = con._port_link() if ctx.startswith("FastEthernet") else None
    return link.label if link is not None else ctx


def _port(con, what: str, off: bool) -> str:
    key = f"{what}:{iface_key(con)}"
    own = devcli.settings(con.lab, con.device)
    if off:
        own[key] = "yes"
    else:
        own.pop(key, None)
    return con._save().strip()


# ---- the voice VLAN
FAULT_FILE = "lldp-fault.json"


def _fault_path(lab_name: str):
    from . import paths
    return paths.lab_dir(lab_name) / FAULT_FILE


def fault(lab) -> dict:
    """The voice-vlan-wrong problem's port, when it is broken: {sw, label, vlan}."""
    import json
    try:
        f = json.loads(_fault_path(getattr(lab, "name", "") or "-").read_text())
    except (OSError, ValueError):
        return {}
    return f if isinstance(f, dict) and str(f.get("vlan", "")).isdigit() else {}


def voice_vlan(lab, sw: str, label: str, real: bool = False) -> int:
    """The port's voice VLAN as the switch shows and advertises it (a broken
    problem's VLAN when it is broken), or with real=True the one its
    settings hold (what the bridge tags)."""
    f = {} if real else fault(lab)
    if f.get("sw") == sw and f.get("label") == label:
        return int(f["vlan"])
    v = _own(lab, f"sw:{sw}").get(f"voice:{label}", "")
    return int(v) if str(v).isdigit() else 0


def voice_trunk(lab, sw: str, label: str) -> list[str]:
    """What a card's Nic.trunk is on an access port: the voice VLAN's
    network, tagged beside the data VLAN, or nothing."""
    tag_ = voice_vlan(lab, sw, label, real=True)
    net = devcli.vlan_net(lab, sw, tag_) if tag_ else None
    return [net.id] if net is not None else []


def set_voice(con, text: str) -> str:
    lab, sw = con.lab, devcli.switch_id(con.device)
    if not con.s.ctx.startswith("FastEthernet"):
        raise devcli.CliError(f"% Voice VLAN is set on an access port, not on {devcli.short_if(con.s.ctx)}")
    link = con._port_link()
    if link is None:
        raise devcli.CliError(f"% nothing is plugged into {con.s.ctx}: cable the phone to it on the canvas first")
    own = devcli.settings(lab, con.device)
    nic = lab.nodes[link.node_id].nics[link.nic_index]
    f = fault(lab)
    if f.get("sw") == sw and f.get("label") == link.label:
        _fault_path(lab.name).unlink(missing_ok=True)
    if not text:
        own.pop(f"voice:{link.label}", None)
        if own.get(f"mode:{link.label}") != "trunk":
            nic.trunk = []
        return con._save().strip()
    w = text.strip().lower()
    if not w.isdigit() and any(x.startswith(w) for x in ("dot1p", "none", "untagged")):
        raise devcli.CliError(f"% switchport voice vlan {w} is not offered here: the phone tags its frames with "
                              f"the voice VLAN's number (switchport voice vlan <1-4094>)")
    if not w.isdigit() or not 1 <= int(w) <= 4094:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    tag_ = int(w)
    if own.get(f"mode:{link.label}") == "trunk":
        raise devcli.CliError("% The voice VLAN is for an access port: switchport mode access first")
    data = lab.networks[link.network_id]
    if data.vlan_no == tag_:
        raise devcli.CliError(f"% VLAN {tag_} is this port's access VLAN: the voice VLAN must be another one")
    note = ""
    net = devcli.vlan_net(lab, sw, tag_)
    if net is None:
        net, _ = con._make_vlan(tag_)
        note = f"% Voice VLAN does not exist. Creating vlan {tag_}"
    # The phone tags with the VLAN's number, so that network takes the number
    # as its VLAN id on the router (as a trunk to a machine does).
    seg = lab.segment_id(net.id)
    try:
        from .netplan import compile_topology
        used = {s.vid: sid for sid, s in compile_topology(lab, check_ports=False).segments.items()}
    except Exception:  # noqa: BLE001 - a plan that does not compile: the lab file's own ids only
        used = {}
    used.update({n.vlan: lab.segment_id(n.id) for n in lab.networks.values() if n.vlan})
    if used.get(tag_, seg) != seg:
        raise devcli.CliError(f"% VLAN {tag_} cannot be tagged on this port: that number is another network's "
                              f"VLAN id on the router here")
    if lab.networks[seg].vlan != tag_:
        lab.networks[seg].vlan = tag_
    own[f"voice:{link.label}"] = str(tag_)
    nic.trunk = [net.id]
    said = con._save().strip()
    return "\n".join(x for x in (note, said) if x)


def voice_line(lab, sw: str, label: str) -> str:
    """show interfaces switchport's Voice VLAN line."""
    tag_ = voice_vlan(lab, sw, label)
    if not tag_:
        return "Voice VLAN: none"
    net = devcli.vlan_net(lab, sw, tag_)
    return f"Voice VLAN: {tag_} ({net.description if net is not None and net.description else f'VLAN{tag_:04d}'})"


# ---- show
def _ifmap(con) -> dict[str, str]:
    return {p.iface: p.name for p in ports(con.lab, con.plan, con.device) if p.iface}


READ = ("command -v lldpcli >/dev/null 2>&1 || echo '#nolldpd'; "
        "for i in {inst}; do echo \"#inst $i\"; p={run}/$i.pid; "
        "[ -f $p ] && kill -0 $(cat $p) 2>/dev/null && echo '#running' && "
        "lldpcli -u {run}/$i.sock -f keyvalue show neighbors details 2>&1; done; echo '#end'")


def read(con, protos: tuple[str, ...]) -> tuple[list[Neighbor], set[str], bool]:
    """(neighbours, protocols whose daemon runs, lldpd installed) from the router."""
    t = tag(con.device)
    text = con._on_router(READ.format(inst=" ".join(f"{t}-{p}" for p in protos), run=RUN), timeout=20)
    running, neigh, body, inst = set(), [], [], ""
    for line in (text or "").splitlines():
        if line.startswith("#inst "):
            if inst and body:
                neigh += parse_keyvalue("\n".join(body))
            inst, body = line.split()[1].split("-")[-1], []
        elif line == "#running":
            running.add(inst)
        elif line == "#end":
            break
        else:
            body.append(line)
    if inst and body:
        neigh += parse_keyvalue("\n".join(body))
    return neigh, running, "#nolldpd" not in (text or "")


def _filter_if(con, text: str) -> tuple[str, bool]:
    """'g0/0/0 detail' -> (the full interface name or "", detail)."""
    words = text.split()
    detail = bool(words) and "detail".startswith(words[-1].lower()) and len(words[-1]) >= 2
    if detail:
        words = words[:-1]
    if not words:
        return "", detail
    return devcli.parse_if(" ".join(words), con._if_names()), detail


def _quiet_ports(con, neigh: list[Neighbor]) -> list[str]:
    """Notes for the switch's cabled ports nobody spoke LLDP on: why."""
    if con.device == devcli.ROUTER:
        return []
    heard = {n.iface for n in neigh}
    out = []
    lab = con.lab
    for p in ports(lab, con.plan, con.device):
        if not p.node or not p.iface or p.iface in heard:
            continue
        node = lab.nodes.get(p.node)
        if node is None:
            continue
        who = f"{devcli.short_if(p.name)} ({p.node})"
        if node.kind != "linux":
            out.append(f"% {who}: Windows sends no LLDP out of the box (its LLDP driver only listens)")
        elif "ipphone" in (node.roles or []):
            out.append(f"% {who}: the phone sends LLDP-MED once it has started; give it a minute")
        elif node.image in ("ubuntu", "debian12", "debian13-cloud"):
            out.append(f"% {who}: a Linux machine sends LLDP once lldpd runs on it (the lldpd pack)")
    return out


def show_neighbors(con, proto: str, text: str, detail: bool = False) -> str:
    lab = con.lab
    if proto == "cdp" and not cdp_run(lab, con.device):
        return "% CDP is not enabled"
    if proto == "lldp" and not lldp_run(lab, con.device):
        return "% LLDP is not enabled"
    only, more = _filter_if(con, text) if text else ("", False)
    detail = detail or more
    neigh, running, have = read(con, (proto,))
    if not have:
        return NO_DAEMON
    ifmap = _ifmap(con)
    if only:
        neigh = [n for n in neigh if ifmap.get(n.iface) == only]
    fmt = {("cdp", False): cdp_brief, ("cdp", True): cdp_detail,
           ("lldp", False): lldp_brief, ("lldp", True): lldp_detail}[(proto, detail)]
    out = fmt(neigh, ifmap)
    if proto not in running and any(p.iface for p in ports(lab, con.plan, con.device)):
        out += f"\n% The {proto.upper()} daemon is not running for this device yet: give the router a few seconds"
    if proto == "lldp" and not only:
        notes = _quiet_ports(con, neigh)
        if notes:
            out += "\n" + "\n".join(notes)
    return out


def show_entry(con, proto: str, text: str) -> str:
    lab = con.lab
    if proto == "cdp" and not cdp_run(lab, con.device):
        return "% CDP is not enabled"
    if proto == "lldp" and not lldp_run(lab, con.device):
        return "% LLDP is not enabled"
    neigh, _, have = read(con, (proto,))
    if not have:
        return NO_DAEMON
    want = text.split()[0] if text.split() else "*"
    pick = [n for n in neigh if want == "*" or n.device_id == want or n.device_id.startswith(want.rstrip("*"))
            and want.endswith("*")]
    fmt = cdp_detail if proto == "cdp" else lldp_detail
    if not pick:
        return ""
    return fmt(pick, _ifmap(con)).rsplit("\n", 1)[0].rstrip()


def show_cdp(con) -> str:
    if not cdp_run(con.lab, con.device):
        return "% CDP is not enabled"
    return "\n".join(["Global CDP information:", f"\tSending CDP packets every {CDP_TIMER} seconds",
                      f"\tSending a holdtime value of {CDP_HOLD} seconds",
                      "\tSending CDPv2 advertisements is  enabled"])


def show_lldp(con) -> str:
    if not lldp_run(con.lab, con.device):
        return "% LLDP is not enabled"
    return "\n".join(["", "Global LLDP Information:", "    Status: ACTIVE",
                      f"    LLDP advertisements are sent every {LLDP_TIMER} seconds",
                      f"    LLDP hold time advertised is {LLDP_HOLD} seconds",
                      f"    LLDP interface reinitialisation delay is {LLDP_REINIT} seconds"])


def _status(con, p: Port) -> str:
    lab = con.lab
    if con.device == devcli.ROUTER:
        if devcli.router_shut(lab, p.name):
            return "administratively down"
        return "up" if p.iface else "down"
    own = _own(lab, con.device)
    if own.get(f"shut:{p.key}"):
        return "administratively down"
    return "up" if p.iface else "down"


def show_interface(con, proto: str, text: str) -> str:
    lab = con.lab
    if proto == "cdp" and not cdp_run(lab, con.device):
        return "% CDP is not enabled"
    if proto == "lldp" and not lldp_run(lab, con.device):
        return "% LLDP is not enabled"
    only = devcli.parse_if(text, con._if_names()) if text.strip() else ""
    out = []
    for p in ports(lab, con.plan, con.device):
        if only and p.name != only:
            continue
        cdp, tx, rx = port_state(lab, con.device, p.key)
        st = _status(con, p)
        if proto == "cdp":
            if not cdp:
                continue
            out += [f"{p.name} is {st}, line protocol is {'up' if st == 'up' else 'down'}", "  Encapsulation ARPA",
                    f"  Sending CDP packets every {CDP_TIMER} seconds", f"  Holdtime is {CDP_HOLD} seconds"]
        else:
            up = st == "up"
            out += [f"{p.name}:", f"    Tx: {'enabled' if tx else 'disabled'}",
                    f"    Rx: {'enabled' if rx else 'disabled'}",
                    f"    Tx state: {'IDLE' if up and tx else 'INIT'}",
                    f"    Rx state: {'WAIT FOR FRAME' if up and rx else 'WAIT PORT OPER'}", ""]
    if proto == "cdp" and not only:
        n = sum(1 for p in ports(lab, con.plan, con.device) if port_state(lab, con.device, p.key)[0])
        up = sum(1 for p in ports(lab, con.plan, con.device)
                 if port_state(lab, con.device, p.key)[0] and _status(con, p) == "up")
        out += [f" cdp enabled interfaces : {n}", f" interfaces up          : {up}",
                f" interfaces down        : {n - up}"]
    return "\n".join(out).rstrip()


# ------------------------------------------------------------------ show running-config
def run_lines(con, out: list[str]) -> list[str]:
    """show running-config with this module's lines where IOS prints them:
    no cdp run and lldp run before the lines, and under each interface its
    voice VLAN, no cdp enable and no lldp transmit / receive."""
    lab, own = con.lab, _own(con.lab, con.device)
    out = list(out)
    glob = (["no cdp run"] if own.get("cdp-off") else []) + (["lldp run"] if own.get("lldp-run") else [])
    sw = devcli.switch_id(con.device)
    for p in ports(lab, con.plan, con.device):
        head = f"interface {p.name}"
        if head not in out:
            continue
        k = out.index(head) + 1
        end = k
        while end < len(out) and out[end].startswith(" "):
            end += 1
        under = []
        if own.get(f"nocdp:{p.key}"):
            under.append(" no cdp enable")
        if own.get(f"nolldptx:{p.key}"):
            under.append(" no lldp transmit")
        if own.get(f"nolldprx:{p.key}"):
            under.append(" no lldp receive")
        out[end:end] = under
        v = voice_vlan(lab, sw, p.key) if sw else 0
        if v:
            sp = [i for i in range(k, end) if out[i].startswith(" switchport")]
            at = (sp[-1] + 1) if sp else (k + 1 if k < end and out[k].startswith(" description") else k)
            out[at:at] = [f" switchport voice vlan {v}"]
    if glob:
        j = next((i for i, line in enumerate(out) if line.startswith(("banner motd", "line con 0"))), len(out))
        out[j:j] = glob + ["!"]
    return out


# ------------------------------------------------------------------ the ts problem
def register_faults(reg) -> None:
    from .guestfaults import LINUX, GuestFault
    reg(GuestFault(
        id="voice-vlan-wrong",
        images=("alpine",),
        roles=("ipphone",),
        host="voice-vlan",
        title="The phone's switch port advertises the wrong voice VLAN",
        os=LINUX,
        shell="sh",
        teaches="switchport voice vlan and LLDP-MED's network policy, reading show interfaces switchport and "
                "show lldp neighbors detail, and what a phone does with the VLAN it is told",
        symptom="the phone was working; now it has no address and cannot reach the phone system, while the PC "
                "beside it is fine",
        apply="echo 'this problem is set from outside the phone: winlab break <phone> voice-vlan-wrong changes its "
              "switch port'",
        clear="echo 'set the voice VLAN on the phone port again: switchport voice vlan <n>'",
        hints=(
            "On the phone: ip -o addr shows a VLAN subinterface (eth0.<n>) with no IPv4 address. The phone "
            "tags its frames with the VLAN the switch port told it about.",
            "On the switch: show interfaces <port> switchport and show lldp neighbors detail. Which voice VLAN "
            "does the port advertise, and which VLAN has the router's voice subinterface and DHCP pool?",
            "In the port's configuration, switchport voice vlan with the right number. The phone moves within "
            "about a minute (lldpcli show neighbors on the phone shows the new policy).",
        ),
        verify="ip -o -4 addr show 2>/dev/null | awk '$2 ~ /[.][0-9]+(@|$)/ {f=1} END {print f ? \"True\" : "
               "\"False\"}'",
    ))


def break_port(lab, plan, node: str) -> dict:
    """The fault record for a phone's port: its switch, cable and a voice
    VLAN near the right one that no network uses. ValueError when the
    phone is not on a switch port with a voice VLAN."""
    label = f"{node}:nic0"
    where = devcli.port_no(lab, plan, label)
    if not where:
        raise ValueError(f"{node} is not cabled to a workbench switch port")
    sw = where[0]
    right = voice_vlan(lab, sw, label, real=True)
    if not right:
        raise ValueError(f"{node}'s switch port has no voice VLAN yet: do the cdp-lldp-voice-vlan lesson first "
                         f"(switchport voice vlan <n> on its port)")
    used = set()
    for n in lab.networks.values():
        used |= {getattr(n, "vlan_no", 0) or 0, n.vlan or 0}
    for wrong in (right + 1, right - 1, right + 10, right + 100):
        if 1 < wrong <= 4094 and wrong not in used:
            return {"sw": sw, "label": label, "vlan": wrong, "was": right}
    raise ValueError("no free VLAN number near the voice VLAN")


def host_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    """`winlab break <phone> voice-vlan-wrong` and the Break button: the
    record goes in the lab folder and the router's lldpd is given it."""
    import json
    from . import netplan, schema
    try:
        lab = schema.load(lab_name)
        plan = netplan.compile_topology(lab, check_ports=False)
    except Exception as exc:  # noqa: BLE001 - a lab that does not load cannot be broken
        return False, str(exc)
    path = _fault_path(lab_name)
    if clear:
        path.unlink(missing_ok=True)
        msg = "the port advertises its own voice VLAN again"
    else:
        try:
            rec = break_port(lab, plan, node)
        except ValueError as exc:
            return False, str(exc)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rec))
        msg = f"{node}'s switch port now advertises a wrong voice VLAN"
    from .cli import _fabric_runner
    run, why = _fabric_runner(lab_name)
    if not run:
        return True, f"{msg}; {why}, so the router's lldpd takes it at the next lab start"
    try:
        run("\n".join(render(plan)), timeout=120)
    finally:
        run.close()
    say(msg)
    return True, msg
