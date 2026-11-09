"""More routers than one: each a router of its own, as in a company network
with a core router, a branch router and an edge router.

The lab router (``[devices."router"]``) is the one every lab has. A
workbench can hold more: ``[devices."router:<id>"]``, each with its own IOS
console, its own ports cabled to switches, its own routing table, its own
OSPF/BGP/EIGRP, ACLs, NAT, DHCP pools, tunnels and firewall, and its own
power switch.

How it is real. All the lab's switches and routers live in the one small
Alpine VM behind the workbench (winlab/netplan.py). Each extra router is a
separate Linux network stack in it, the way a container is: its own network
namespace (interfaces, addresses, routes, ARP, nftables, conntrack), its own
process namespace (its own FRRouting, dnsmasq, strongSwan, winlab-hsrpd, so
``pkill`` on one router never touches another) and its own private /etc,
/var and /run (an overlay over the VM's, so its frr.conf and DHCP leases are
its own). A cable from one of its ports to a switch is a veth pair: one end
is that router's GigabitEthernet port, the other a trunk port on the
switches' bridge carrying the switch's VLANs, as a router's uplink to a
switch is. The routers meet only over those cables: a packet from one to
another crosses the switch, and OSPF between them is real hellos on a VLAN.

Because each router is its own stack, powering one off (its front panel's
switch, ``power`` = ``off``) takes only that router's interfaces and
processes away; the lab router, the switches and the other routers keep
running, as when one box in a rack loses power.

Everything the lab router's console does is reused for these routers: the
console and the start script work on a view of the lab (view()) in which
``devices["router"]`` is this router's settings and each network's routed
flag and gateway address are this router's, so the same code renders the
same commands, which run inside this router's namespaces (wrap()).

What it does not do (yet), and says so: a cable straight from one router to
another (cable both to a switch, in a VLAN of their own, as a transit link);
SSH, SNMP and NTP served by these routers (the lab router's only); a lab
file's own sites and Azure networks stay on the lab router.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import ipaddress
import shlex
from collections.abc import MutableMapping

PREFIX = "router:"
RUN = "/run/winlab-routers"
MAX_ROUTERS = 8
MODEL = "ISR4321/K9"
_ID_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-")


class RouterError(Exception):
    pass


# The router VM's own scripts see every process, the other routers' too
# (their process namespaces are inside the VM's). So that `pkill dnsmasq` or
# `pgrep -x charon` on the lab router never reaches another router's, its
# scripts start with these: pgrep, pkill and pidof that keep to the VM's own
# processes. Inside another router they are not defined: there the tools
# already see only that router's processes.
SHELL_GUARD = (
    "WL_PIDNS=$(readlink /proc/1/ns/pid 2>/dev/null); "
    "_wlroot() { [ \"$(readlink /proc/$1/ns/pid 2>/dev/null)\" = \"$WL_PIDNS\" ]; }; "
    "pgrep() { _o=$(command pgrep \"$@\") || return 1; _r=1; for _p in $_o; do _wlroot $_p && { echo $_p; _r=0; }; done; return $_r; }; "
    "pidof() { _o=$(command pidof \"$@\") || return 1; _r=1; _l=; for _p in $_o; do _wlroot $_p && { _l=\"$_l $_p\"; _r=0; }; done; "
    "[ $_r = 0 ] && echo $_l; return $_r; }; "
    "pkill() { _s=TERM; case \"$1\" in -[A-Z]*|-[0-9]*) _s=${1#-}; shift;; esac; _o=$(command pgrep \"$@\") || return 1; "
    "_r=1; for _p in $_o; do _wlroot $_p && kill -$_s $_p 2>/dev/null && _r=0; done; return $_r; }"
)


# ------------------------------------------------------------------ which
def key(rid: str) -> str:
    """The lab file's devices key for a router: "router" for the lab
    router, "router:<id>" for the others."""
    return "router" if rid in ("", "router") else PREFIX + rid


def rid_of(device: str) -> str:
    """The router id in a device name ("router:core" -> "core"), "" for the
    lab router or anything else."""
    return device[len(PREFIX):] if device.startswith(PREFIX) else ""


def is_router(device: str) -> bool:
    return device == "router" or (device.startswith(PREFIX) and len(device) > len(PREFIX))


def extra(lab) -> list[str]:
    """The ids of the routers beside the lab router, sorted."""
    devs = getattr(lab, "_real", lab).devices
    return sorted(k[len(PREFIX):] for k in devs if k.startswith(PREFIX) and len(k) > len(PREFIX))


def powered(lab, rid: str) -> bool:
    devs = getattr(lab, "_real", lab).devices
    return devs.get(key(rid), {}).get("power") != "off"


def short(rid: str) -> str:
    """Four hex digits naming the router in the VM's interface names (15
    characters at most): stable for an id, whatever other routers exist."""
    return hashlib.sha256(rid.encode()).hexdigest()[:4]


def netns(rid: str) -> str:
    return f"wlr-{short(rid)}"


def check_id(lab, rid: str) -> str:
    rid = (rid or "").strip().lower()
    if not rid or len(rid) > 20 or not set(rid) <= _ID_OK or rid[0] == "-":
        raise RouterError("a router's id is 1-20 letters, digits or dashes")
    if rid == "router" or key(rid) in lab.devices:
        raise RouterError(f"there is already a router {rid!r}")
    return rid


def add(lab, rid: str = "") -> str:
    """A new router from the box: every port shut down, no addresses, no
    hostname ("Router"), as an ISR comes. Returns its id."""
    from . import devcli
    if len(extra(lab)) >= MAX_ROUTERS:
        raise RouterError(f"the bench holds the lab router and {MAX_ROUTERS} more")
    if not rid:
        n = 2
        while key(f"r{n}") in lab.devices:
            n += 1
        rid = f"r{n}"
    rid = check_id(lab, rid)
    own = lab.devices.setdefault(key(rid), {})
    own[devcli.MIGRATED] = "2"
    for name in devcli.ROUTER_IFS:
        own[f"shut:{name}"] = "yes"
    return rid


def remove(lab, rid: str) -> None:
    lab.devices.pop(key(rid), None)
    lab.layout.pop(key(rid), None)


# ------------------------------------------------------------------ views
class DeviceView(MutableMapping):
    """lab.devices as one router sees it: "router" is that router's own
    settings; every other device is the lab's."""

    def __init__(self, devices: dict, rid: str):
        self._d = devices
        self._k = key(rid)

    def _map(self, k):
        return self._k if k == "router" else k

    def __getitem__(self, k):
        return self._d[self._map(k)]

    def __setitem__(self, k, v):
        self._d[self._map(k)] = v

    def __delitem__(self, k):
        del self._d[self._map(k)]

    def __iter__(self):
        for k in list(self._d):
            if k == "router":
                continue
            yield "router" if k == self._k else k

    def __len__(self):
        return sum(1 for _ in self)


_OWN = ("gateway", "routed", "dhcp")


class NetView:
    """A network as one router sees it: whether this router routes it, its
    address there, whether it hands out addresses there. The rest (the
    subnet, the switch, the VLAN) is the network's own, written through."""

    def __init__(self, net, own: dict):
        object.__setattr__(self, "_net", net)
        object.__setattr__(self, "_own", own)
        object.__setattr__(self, "_mem", {"routed": False, "dhcp": False})

    def __getattr__(self, name):
        if name == "gateway":
            return self._own.get(f"gw:{self._net.id}") or None
        if name in ("routed", "dhcp"):
            return self._mem[name]
        if name in ("wan", "site", "gateway_node", "hosts_gateway"):
            # The sites, the WAN and the firewalls' networks are the lab
            # router's business: for another router they are plain VLANs.
            return "" if name != "wan" else False
        return getattr(self._net, name)

    def __setattr__(self, name, value):
        if name == "gateway":
            k = f"gw:{self._net.id}"
            if value:
                self._own[k] = str(value)
            else:
                self._own.pop(k, None)
        elif name in ("routed", "dhcp"):
            self._mem[name] = bool(value)
        else:
            setattr(self._net, name, value)

    def __repr__(self):
        return f"NetView({self._net.id!r})"

    # Network's derived properties, worked out from this view's fields.
    @property
    def router_ip(self) -> str:
        return self.gateway or str(next(self.net.hosts()))

    @property
    def default_gateway(self) -> str:
        return self.router_ip

    @property
    def net(self):
        return ipaddress.ip_network(self._net.cidr, strict=False)

    @property
    def prefixlen(self) -> int:
        return self.net.prefixlen

    @property
    def netmask(self) -> str:
        return str(self.net.netmask)


class LabView:
    """The lab as one of the extra routers sees it (module docstring)."""

    def __init__(self, lab, rid: str):
        object.__setattr__(self, "_real", lab)
        object.__setattr__(self, "_rid", rid)
        own = lab.devices.setdefault(key(rid), {})
        object.__setattr__(self, "devices", DeviceView(lab.devices, rid))
        object.__setattr__(self, "networks", {nid: NetView(n, own) for nid, n in lab.networks.items()})
        from . import devcli
        devcli.refresh_routed(self)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __setattr__(self, name, value):
        setattr(self._real, name, value)

    @property
    def router_id(self) -> str:
        return self._rid

    def segment_id(self, network_id: str) -> str:
        return self._real.segment_id(network_id)

    def nodes_on(self, network_id: str):
        return self._real.nodes_on(network_id)

    def node_list(self):
        return self._real.node_list()


def view(lab, rid: str):
    """The lab as router `rid` sees it; the lab itself for the lab router."""
    if rid in ("", "router"):
        return getattr(lab, "_real", lab)
    real = getattr(lab, "_real", lab)
    if key(rid) not in real.devices:
        raise RouterError(f"no router {rid!r} on the bench")
    return LabView(real, rid)


def plan_view(plan, rid: str, v=None):
    """The topology plan as router `rid` sees it: the same VLANs (they are
    the switches'), this router's view of each network, and its own DHCP
    pools; it relays DHCP only where ``ip helper-address`` was typed on it,
    as IOS does."""
    if rid in ("", "router"):
        return plan
    from . import netplan
    v = v if v is not None else view(plan.lab, rid)
    p = copy.copy(plan)
    p.lab = v
    p.segments = {sid: dataclasses.replace(seg, network=v.networks[seg.network.id], serves_dhcp=False,
                                           relay_to=[], relay_via="")
                  for sid, seg in plan.segments.items()}
    netplan._plan_services(v, p)
    for seg in p.segments.values():
        seg.relay_to, seg.relay_via = [], ""
    p.pinned = {}
    return p


# ------------------------------------------------------------------ cables
def ports(lab, plan, rid: str) -> list[dict]:
    """This router's cables: per port with a switch on the far end, the
    port, the switch, the VLAN ids the cable carries (the switch's VLANs, its
    own VLAN 1 untagged) and the veth names."""
    from . import devcli
    v = view(lab, rid)
    out = []
    for j, (name, sw) in enumerate(devcli.router_ports(v)):
        if not sw:
            continue
        native = 0
        tagged: list[int] = []
        for net in devcli.vlans_of(v, sw):
            try:
                vid = plan.segment_of(net.id).vid
            except KeyError:
                continue
            if net.id == sw:
                native = vid
            else:
                tagged.append(vid)
        out.append({"port": name, "switch": sw, "native": native, "tagged": sorted(set(tagged) - {native}),
                    "outer": f"r{short(rid)}p{devcli.ROUTER_IFS.index(name)}",
                    "inner": f"gi{devcli.ROUTER_IFS.index(name)}",
                    # a switch powered off takes the link away, as a real one does
                    "shut": devcli.router_shut(v, name) or devcli.switch_off(lab, sw)})
    return out


def _mac(rid: str) -> str:
    h = hashlib.sha256(f"router/{rid}".encode()).digest()
    return "52:54:01:%02x:%02x:%02x" % (h[0], h[1], h[2])


def port_lines(lab, plan, rid: str) -> list[str]:
    """The cables: veth pairs between the switches' bridge and this
    router's own (made again from nothing, which is idempotent)."""
    ns = netns(rid)
    out = [f"# router {rid}: its cables to the switches"]
    for k in range(len(_all_ifs())):
        out.append(f"ip link del r{short(rid)}p{k} 2>/dev/null || true")
    for p in ports(lab, plan, rid):
        o, i = p["outer"], p["inner"]
        out += [
            f"ip link add {o} type veth peer name {i} netns {ns}",
            f"ip link set {o} master lab0",
            f"bridge vlan del dev {o} vid 1 2>/dev/null || true",
        ]
        if p["native"]:
            out.append(f"bridge vlan add dev {o} vid {p['native']} pvid untagged   # {p['switch']} VLAN 1")
        for vid in p["tagged"]:
            out.append(f"bridge vlan add dev {o} vid {vid}")
        out += [
            f"ip netns exec {ns} ip link set {i} master lab0",
            f"ip netns exec {ns} bridge vlan del dev {i} vid 1 2>/dev/null || true",
        ]
        if p["native"]:
            out.append(f"ip netns exec {ns} bridge vlan add dev {i} vid {p['native']} pvid untagged")
        for vid in p["tagged"]:
            out.append(f"ip netns exec {ns} bridge vlan add dev {i} vid {vid}")
        state = "down" if p["shut"] else "up"
        out += [f"ip link set {o} {state}", f"ip netns exec {ns} ip link set {i} {state}"]
    return out


def _all_ifs() -> list[str]:
    from . import devcli
    return devcli.ROUTER_IFS


# ------------------------------------------------------------------ direct cables
LINK_POOL = "100.64.0.0/10"   # where a new direct cable's subnet starts, until a port is given an address


def link_ends(lab, net_id: str) -> list[tuple[str, str]]:
    """(router device, port) at each end of a direct cable."""
    from . import devcli
    real = getattr(lab, "_real", lab)
    out = []
    for dev in ["router"] + [key(r) for r in extra(real)]:
        v = view(real, rid_of(dev))
        port = devcli.cabled_ports(v).get(net_id)
        if port:
            out.append((dev, port))
    return out


def links(lab) -> list[dict]:
    real = getattr(lab, "_real", lab)
    return [{"id": nid, "ends": [{"dev": d, "port": p} for d, p in link_ends(real, nid)]}
            for nid, net in sorted(real.networks.items()) if getattr(net, "link", False)]


def connect(lab, a: str, aport: str, b: str, bport: str) -> str:
    """A cable straight from router `a`'s port to router `b`'s ("router" or
    "router:<id>"): a segment of its own with these two ports on it and
    nothing else, as a crossover between two routers is. Returns its id."""
    from . import devcli, editor
    real = getattr(lab, "_real", lab)
    if a == b:
        raise RouterError("both ends are on the same router")
    for dev in (a, b):
        if not is_router(dev) or key(rid_of(dev)) not in real.devices and dev != "router":
            raise RouterError(f"no router {dev!r} on the bench")
    n = 1
    while f"link{n}" in real.networks:
        n += 1
    nid = f"link{n}"
    cidr = editor.next_free_subnet(real, base=LINK_POOL, prefix=30)
    net = editor.add_network(real, nid, cidr=cidr)
    net.routed, net.link = False, True
    try:
        for dev, port in ((a, aport), (b, bport)):
            v = view(real, rid_of(dev))
            if port and port in devcli.cabled_ports(v).values():
                raise RouterError(f"{devcli.short_if(port)} on {devcli.hostname(v, 'router')} already has a cable in it")
            devcli.plug_router(v, nid, port)
    except (RouterError, devcli.CliError):
        disconnect(real, nid)
        raise
    return nid


def disconnect(lab, net_id: str) -> None:
    """The direct cable out of both routers, and gone."""
    from . import devcli, editor
    real = getattr(lab, "_real", lab)
    for dev, _port in link_ends(real, net_id):
        v = view(real, rid_of(dev))
        own = v.devices.get("router", {})
        own.pop(devcli.RPORT + net_id, None)
        own.pop(f"gw:{net_id}", None)
        for k in [k for k, val in own.items() if k.startswith(("ip:", "sub:")) and val == net_id]:
            del own[k]
        devcli.refresh_routed(v)
    if net_id in real.networks:
        editor.remove_network(real, net_id)


# ------------------------------------------------------------------ inside
def svi_lines(plan, rid: str) -> list[str]:
    from . import netplan
    p = plan_view(plan, rid)
    out = ["### gateways (one svi per vlan this router has an address in)"]
    vids = set()
    for pr in ports(plan.lab, plan, rid):
        vids |= {pr["native"], *pr["tagged"]}
    for seg in sorted(p.segments.values(), key=lambda s: s.vid):
        if seg.vid not in vids:
            continue
        out.append(f"ip link del {seg.svi} 2>/dev/null || true")
        if seg.network.routed:
            out.extend(netplan.svi_lines(seg))
    return out


def module_lines(plan, rid: str, reset: bool = False) -> dict[str, list[str]]:
    """What the lab router's console modules make of this router's
    settings, per module (the same code the lab router runs)."""
    from . import iosl3, iosrouting, netplan, nms, routerpolicy
    p = plan_view(plan, rid)
    v = p.lab
    snmp = bool(nms.communities(v, "router") or (nms.traps_on(v, "router") and nms.trap_hosts(v, "router")))
    return {
        # its own SNMP agent (and NTP client), as the lab router's (winlab/nms.py)
        "nms": nms.push_script(v).splitlines() if snmp or nms.ntp_servers(v, "router") else [
            "pkill -x snmpd 2>/dev/null || true"],
        "svis": svi_lines(plan, rid),
        "dhcp": netplan._render_dhcp(p) or [
            ": > /etc/dnsmasq.d/winlab.conf 2>/dev/null || true", "pkill dnsmasq 2>/dev/null || true"],
        "l3": iosl3.render(p, reset=reset),
        "rt": iosrouting.render(p, reset=reset),
        "pol": routerpolicy.render(p, reset=reset),
    }


def _hash(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def hashes(plan, rid: str) -> dict[str, str]:
    """What livenet compares to see what changed on a running router."""
    lab = plan.lab
    out = {"power": "on" if powered(lab, rid) else "off", "ports": _hash(port_lines(lab, plan, rid))}
    if out["power"] == "on":
        out.update({k: _hash(v) for k, v in module_lines(plan, rid).items()})
    return out


INNER_SETUP = r"""
set -e
F=$1
mkdir -p "$F"
mount -t tmpfs wlr "$F"
mkdir -p "$F/eu" "$F/ew" "$F/vu" "$F/vw"
mount -t overlay wlr -o lowerdir=/etc,upperdir="$F/eu",workdir="$F/ew" /etc
mount -t overlay wlr -o lowerdir=/var,upperdir="$F/vu",workdir="$F/vw" /var
mount -t tmpfs wlr /run
mount -t tmpfs wlr /tmp
mount -t proc proc /proc
set +e
trap 'exit 0' TERM
while :; do sleep 3600 & wait $!; done
"""


def start_lines(rid: str) -> list[str]:
    """The router's own namespaces (module docstring): a network namespace,
    and in it a process and mount namespace whose first process keeps it
    alive; its pid in the VM is kept in RUN/<id>.pid for wrap()."""
    ns = netns(rid)
    pidf = f"{RUN}/{short(rid)}.pid"
    fs = f"{RUN}/{short(rid)}.fs"
    setup = shlex.quote(INNER_SETUP)
    return [
        f"### router {rid}: a network stack, processes and files of its own",
        f"mkdir -p {RUN}",
        "modprobe overlay 2>/dev/null || true",
        f"ip netns add {ns}",
        f"ip netns exec {ns} ip link set lo up",
        f"ip netns exec {ns} ip link add name lab0 type bridge vlan_filtering 1 vlan_default_pvid 0",
        f"ip netns exec {ns} ip link set lab0 address {_mac(rid)}",
        f"ip netns exec {ns} ip link set lab0 type bridge mcast_snooping 0 2>/dev/null || true",
        f"ip netns exec {ns} ip link set lab0 up",
        f"ip netns exec {ns} sysctl -qw net.ipv4.ip_forward=1",
        f"ip netns exec {ns} sysctl -qw net.ipv6.conf.all.forwarding=0 2>/dev/null || true",
        f"ip netns exec {ns} sysctl -qw net.ipv6.conf.default.accept_ra=0 2>/dev/null || true",
        f"setsid ip netns exec {ns} unshare --pid --fork --mount --propagation private "
        f"sh -c {setup} wlr {fs} </dev/null >/dev/null 2>&1 &",
        "WLR_P=$!",
        "WLR_C=''",
        "for _ in $(seq 1 50); do WLR_C=$(command pgrep -P $WLR_P | head -n1); "
        "[ -n \"$WLR_C\" ] && [ -e /proc/$WLR_C/ns/pid ] && break; sleep 0.1; done",
        f"echo $WLR_C > {pidf}",
        "for _ in $(seq 1 50); do grep -q ' /tmp ' /proc/$WLR_C/mounts 2>/dev/null && break; sleep 0.1; done",
    ]


def stop_lines(rid: str) -> list[str]:
    """The router's power off: its processes (all in its process
    namespace, so killing the first kills them all) and its namespace with
    its interfaces and its ends of the cables."""
    ns = netns(rid)
    pidf = f"{RUN}/{short(rid)}.pid"
    return [
        f"# router {rid}: off",
        f"[ -f {pidf} ] && kill -9 $(cat {pidf}) 2>/dev/null; rm -f {pidf}",
        f"ip netns del {ns} 2>/dev/null || true",
    ]


def wrap(rid: str, cmd: str) -> str:
    """A shell command run inside router `rid` (its interfaces, processes
    and files), as its console's show, ping and debug commands are."""
    pidf = f"{RUN}/{short(rid)}.pid"
    return (f"WLR_C=$(cat {pidf} 2>/dev/null); if [ -z \"$WLR_C\" ] || ! kill -0 $WLR_C 2>/dev/null; then "
            f"echo '% the router is off'; else nsenter -t $WLR_C -n -m -p sh -c {shlex.quote(cmd)}; fi")


def inside(rid: str, lines: list[str]) -> list[str]:
    """Lines to run inside the router, as one script (a here-document, so
    their own here-documents and quoting are untouched)."""
    if not lines:
        return []
    pidf = f"{RUN}/{short(rid)}.pid"
    tag = f"WLR_{short(rid).upper()}_EOF"
    # Packages go onto the VM itself, before the router's private /etc
    # would keep their users and files to itself.
    from . import ioshsrp, iosrouting
    first = [l for l in (iosrouting.INSTALL, ioshsrp.INSTALL) if l in lines]
    return first + [f"nsenter -t $(cat {pidf}) -n -m -p sh -s <<'{tag}'", *lines, tag]


def full_lines(plan, rid: str) -> list[str]:
    """Router `rid` from power on: namespaces, cables, then what its
    console holds."""
    lab = plan.lab
    out = stop_lines(rid)
    if not powered(lab, rid):
        return out
    out += start_lines(rid)
    out += port_lines(lab, plan, rid)
    mods = module_lines(plan, rid)
    body: list[str] = []
    for k in ("svis", "dhcp", "l3", "rt", "pol", "nms"):
        body += mods[k]
    out += inside(rid, body)
    return out


def render(plan) -> list[str]:
    """The extra routers, for the router VM's start script."""
    lab = plan.lab
    ids = extra(lab)
    if not ids:
        return []
    out = ["### the other routers (winlab/routers.py)"]
    for rid in ids:
        out += full_lines(plan, rid)
    out.append("")
    return out


def live_lines(plan, rid: str, old: dict | None, runner=None) -> tuple[list[str], dict]:
    """What brings running router `rid` in line with its settings, given
    the hashes it was last brought in line with (None: not built yet).
    Returns the lines and the new hashes."""
    new = hashes(plan, rid)
    lab = plan.lab
    if not old or old.get("power") != new["power"]:
        return full_lines(plan, rid), new
    if old == new:
        return [], new
    out: list[str] = []
    if old.get("ports") != new["ports"]:
        out += port_lines(lab, plan, rid)
    mods = module_lines(plan, rid, reset=True)
    body: list[str] = []
    for k in ("svis", "dhcp", "l3", "pol", "nms"):
        if old.get(k) != new.get(k):
            body += mods[k]
    if old.get("rt") != new.get("rt"):
        from . import iosrouting
        p = plan_view(plan, rid)
        sub = (lambda cmd, timeout=30: runner(wrap(rid, cmd), timeout=timeout)) if runner else None
        body += iosrouting.live_script(p, sub) if sub else mods["rt"]
    out += inside(rid, body)
    return out, new


def gone_lines(rid: str) -> list[str]:
    return stop_lines(rid)
