"""The consoles of the devices that have no screen: the lab router and the
switches of the workbench.

A real router or switch is set up from its console port, with a command
line in the manner of Cisco IOS: ``enable``, ``configure terminal``,
``interface GigabitEthernet0/1``, ``ip address ...``, ``show ...``. This is
that command line, and what is typed into it changes the real network: an
interface address is the router's address on that switch (its subnet),
``shutdown`` takes the switch off the router, a DHCP pool makes the router
hand out addresses there, a switch port shut down drops the link of the
machine plugged into it. ``show`` reads the running router (its ARP table,
DHCP leases, its switch's MAC table) and ``ping`` and ``traceroute`` run on
it.

Words may be shortened while they stay unambiguous (``sh ip int br``),
``?`` lists what may come next, Tab completes a word. A device's settings
that have no other home (hostname, port descriptions, ports shut down) are
kept in the lab file under ``[devices."router"]`` and ``[devices."sw:<id>"]``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

from . import editor, imaging, naming, state

ROUTER = "router"
SWITCH_PORTS = 24
# The lab router is an ISR 4321: two onboard gigabit ports, and a NIM with
# eight more fitted when the canvas has more switches than that.
ONBOARD = ["GigabitEthernet0/0/0", "GigabitEthernet0/0/1"]
NIM = [f"GigabitEthernet0/1/{i}" for i in range(8)]
ROUTER_IFS = ONBOARD + NIM
# A switch's gigabit ports: Gi0/1 is its uplink (to the router or to another
# switch), Gi0/2 up are for switches cabled below it. A real 2960-24TT has
# two; four here so a ring of three switches has its spare cables.
GIG_PORTS = 4
MODEL = {ROUTER: "ISR4321/K9", "switch": "WS-C2960-24TT-L"}
PLATFORM = {ROUTER: "ISR4321", "switch": "WS-C2960-"}
# A DHCP pool's settings in [devices."router"], by pool name.
POOL_KEYS = ("pool", "poolnet", "poolgw", "pooldns", "pooldom", "poollease")
# What a PXE boot file name may be (it goes into dnsmasq's configuration).
BOOTFILE_RE = re.compile(r"^[A-Za-z0-9._/\\-]{1,120}$")
_HOST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,62}$")


class CliError(Exception):
    """A message for the console, printed as typed by the device."""


@dataclass
class Spec:
    words: list[str]
    run: object
    help: str
    modes: tuple[str, ...]


@dataclass
class Session:
    device: str
    mode: str = "user"            # idle, user, enable, config, config-if, dhcp-config, ...
    ctx: str = ""                 # the interface, pool, line or list being configured
    history: list[str] = field(default_factory=list)
    ask: dict | None = None       # a question the device asked (a password, [confirm])
    authed: bool = False          # past the console line's login
    boot: int = 0                 # the router's start this session belongs to


# ------------------------------------------------------------------ helpers
def device_kind(device: str) -> str:
    from .routers import is_router  # the lab router and the others (winlab/routers.py)
    return ROUTER if is_router(device) else "switch"


def switch_id(device: str) -> str:
    return device[3:] if device.startswith("sw:") else ""


def settings(lab, device: str) -> dict[str, str]:
    return lab.devices.setdefault(device, {})


def hostname(lab, device: str) -> str:
    """What the canvas and winlab's messages call the device: its hostname
    once one was typed, else the switch's id on the canvas."""
    own = lab.devices.get(device, {}).get("hostname")
    if own:
        return own
    return "Router" if device == ROUTER else (switch_id(device) or "Switch")


def ios_name(lab, device: str) -> str:
    """The device's own hostname, as its prompt shows it: a new switch is
    "Switch" and a new router "Router", as they come out of the box."""
    return lab.devices.get(device, {}).get("hostname") or ("Router" if device == ROUTER else "Switch")


def switches(lab) -> list[str]:
    """The switches on the canvas: networks that are not a VLAN made on
    another switch's console."""
    return sorted(nid for nid, net in lab.networks.items() if not net.switch and not getattr(net, "link", False))


def vlans_of(lab, sw: str) -> list:
    """A switch's VLANs, its own (VLAN 1) first, then by number."""
    return sorted((n for n in lab.networks.values() if n.home == sw), key=lambda n: n.vlan_no)


def vlan_net(lab, sw: str, tag: int):
    return next((n for n in vlans_of(lab, sw) if n.vlan_no == tag), None)


RPORT = "rport:"     # the router's setting: rport:<switch> = the port that switch's uplink is in
MIGRATED = "rports"  # set once a lab's router ports are kept by name


def _old_name(i: int) -> str:
    return f"GigabitEthernet0/{i}"


def cabled_ports(lab) -> dict[str, str]:
    """switch id -> the router interface its uplink cable is in. A port is
    kept in the lab file from the moment the cable goes in (pin_router_ports),
    so adding or removing another switch never renames it. A lab made before
    that (or written by hand with routed networks) gets its ports worked out
    in the order the old consoles had them."""
    own = lab.devices.get(ROUTER, {})
    out = {k[len(RPORT):]: v for k, v in own.items()
           if k.startswith(RPORT) and k[len(RPORT):] in lab.networks and v in ROUTER_IFS}
    used = set(out.values())
    old = not own.get(MIGRATED)
    if not old and lab.workbench:
        return out  # a workbench's cables are only the ones dragged in
    for i, sw in enumerate(switches(lab)):
        if sw in out or upstream(lab, sw):
            continue
        hit = any(n.routed for n in vlans_of(lab, sw))
        if old and not hit:
            hit = any(k.split(":", 1)[1].split(".")[0] == _old_name(i)
                      for k in own if k.startswith(("shut:", "was:", "sub:", "desc:")))
        free = [n for n in ROUTER_IFS if n not in used]
        if hit and free:
            out[sw] = free[0]
            used.add(free[0])
    return out


def pin_router_ports(lab) -> None:
    """Keep the router's ports by name in the lab file, and bring a lab's
    settings typed against the old port names (GigabitEthernet0/<n>, one per
    switch on the canvas) over to the ports their switches are in now. A new
    router's ports come shut down, as an ISR's do."""
    own = settings(lab, ROUTER)
    ports = cabled_ports(lab)
    if not own.get(MIGRATED):
        rename = {_old_name(i): ports[sw] for i, sw in enumerate(switches(lab)) if sw in ports}
        for k in [k for k in own if k.startswith(("shut:", "was:", "sub:", "desc:"))]:
            kind, name = k.split(":", 1)
            base, dot, sub = name.partition(".")
            if base in rename:
                own[f"{kind}:{rename[base]}{dot}{sub}"] = own.pop(k)
        if lab.workbench:
            for name in ROUTER_IFS:
                if name not in ports.values() and not any(k.split(":", 1)[1].split(".")[0] == name
                                                          for k in own if ":" in k):
                    own[f"shut:{name}"] = "yes"
        # The address each port has: what routed the switch's networks before.
        for sw, name in ports.items():
            subs = {v: k[4:] for k, v in own.items() if k.startswith("sub:") and k[4:].split(".")[0] == name}
            was = set(filter(None, own.pop(f"was:{name}", "").split(",")))
            for net in vlans_of(lab, sw):
                if net.routed or net.id in was:
                    ifname = name if net.vlan_no == 1 and net.id == sw else subs.get(net.id) or f"{name}.{net.vlan_no}"
                    if ifname != name:
                        own[f"sub:{ifname}"] = net.id
                    own[f"ip:{ifname}"] = net.id
        own[MIGRATED] = "2"
    for k in [k for k in own if k.startswith(RPORT)]:
        if k[len(RPORT):] not in ports:
            del own[k]
    for sw, name in ports.items():
        own[RPORT + sw] = name


def router_port_names(lab) -> list[str]:
    """The router's ports: the two onboard ones, and the NIM's eight when
    the canvas has more switches than that or one is cabled into it."""
    if len(switches(lab)) > len(ONBOARD) or any(v in NIM for v in cabled_ports(lab).values()):
        return list(ROUTER_IFS)
    return list(ONBOARD)


def router_ports(lab) -> list[tuple[str, str]]:
    """(interface name, switch id or "") per router port, the switch being
    the one whose uplink cable is in it."""
    by_name = {v: k for k, v in cabled_ports(lab).items()}
    return [(n, by_name.get(n, "")) for n in router_port_names(lab)]


def plug_router(lab, sw: str, port: str = "") -> str:
    """The cable from switch `sw`'s uplink goes into a router port (the one
    named, else the first free one): only the link. What the router does on
    it is what is typed at its console. Returns the port."""
    pin_router_ports(lab)
    own = settings(lab, ROUTER)
    ports = cabled_ports(lab)
    if ports.get(sw) and (not port or ports[sw] == port):
        return ports[sw]
    taken = {v for k, v in ports.items() if k != sw}
    if port:
        if port not in ROUTER_IFS:
            raise CliError(f"% The router has no port {port}")
        if port in taken:
            raise CliError(f"% {short_if(port)} already has a cable in it")
    else:
        free = [n for n in ROUTER_IFS if n not in taken]
        if not free:
            raise CliError(f"% Every router port has a cable in it ({len(ROUTER_IFS)} ports). Cable this "
                           f"switch to another switch that is already on the router (a trunk), carry it "
                           f"as a VLAN on one, or add a second router from the shelf")
        port = free[0]
    if ports.get(sw):
        unplug_router(lab, sw)
    own[RPORT + sw] = port
    refresh_routed(lab)
    return port


def unplug_router(lab, sw: str) -> str:
    """The uplink cable out of the router: the port loses its link, and with
    it the switch's networks; the port keeps its settings for the next cable."""
    pin_router_ports(lab)
    fixed = [n.id for n in vlans_of(lab, sw) if n.wan or n.site or n.gateway_node]
    if fixed:
        raise CliError(f"% {fixed[0]} carries the lab's sites or a firewall gateway: it stays on the router")
    port = settings(lab, ROUTER).pop(RPORT + sw, "")
    for n in vlans_of(lab, sw):
        n.routed = n.dhcp = False
    refresh_routed(lab)
    return port


def iface_net(lab, ifname: str):
    """The network an interface (a port, or a sub-interface on it) is in:
    the switch's own network behind a port, the VLAN a sub-interface's
    encapsulation names; None with no cable in the port."""
    own = lab.devices.get(ROUTER, {})
    base = ifname.split(".")[0]
    sw = {v: k for k, v in cabled_ports(lab).items()}.get(base, "")
    if not sw:
        return None
    if "." in ifname:
        net = lab.networks.get(own.get(f"sub:{ifname}", ""))
        if net is not None and net.home == sw:
            return net
        # encapsulation dot1Q typed before the switch had that VLAN: it is
        # the VLAN with that number once the switch makes it.
        tag = own.get(f"dot1q:{ifname}", "")
        return vlan_net(lab, sw, int(tag)) if tag.isdigit() else None
    return lab.networks.get(sw)


def router_shut(lab, ifname: str) -> bool:
    """Whether an interface is administratively down (a sub-interface also
    when its port is)."""
    own = lab.devices.get(ROUTER, {})
    return bool(own.get(f"shut:{ifname.split('.')[0]}") or own.get(f"shut:{ifname}"))


def refresh_routed(lab) -> None:
    """The one truth the running router follows is each network's `routed`
    (winlab/livenet.py): a network is routed while a router interface has an
    address in it, that interface is not shut down, and its port has a
    cable. The sites' and firewalls' networks always are."""
    own = lab.devices.get(ROUTER, {})
    want: set[str] = set()
    for k, nid in own.items():
        if k.startswith("ip:"):
            ifname = k[3:]
            net = iface_net(lab, ifname)
            if net is not None and net.id == nid and not router_shut(lab, ifname):
                want.add(nid)
    for net in lab.networks.values():
        if net.wan or net.site or net.gateway_node:
            continue
        on = net.id in want
        if on != net.routed:
            net.routed = on
        if not on:
            net.dhcp = False
        elif any(k.startswith("pool:") and v == net.id for k, v in own.items()):
            net.dhcp = True


def uplinked(lab, sw: str) -> bool:
    """Whether the switch's uplink cable is in a router port."""
    return sw in cabled_ports(lab)


def upstream(lab, sw: str) -> str:
    """The switch this one's uplink is cabled to ("" for the router or none)."""
    net = lab.networks.get(sw)
    return net.upstream if net else ""


def same_vlan_down_trunk(lab, a, b) -> bool:
    """Whether two networks are one VLAN number on two switches cabled one
    below the other: the floor switch's VLAN 1 is the hq switch's VLAN 1
    across their trunk, the same subnet by design, never an overlap."""
    if a.vlan_no != b.vlan_no or a.home == b.home:
        return False

    def chain(sw: str) -> list[str]:
        seen: list[str] = []
        while sw and sw not in seen:
            seen.append(sw)
            sw = upstream(lab, sw)
        return seen
    return b.home in chain(a.home) or a.home in chain(b.home)


def downlinks(lab, sw: str) -> list[tuple[str, str]]:
    """(port, switch) per switch cabled below this one: Gi0/2, Gi0/3..."""
    below = sorted(nid for nid in switches(lab) if lab.networks[nid].upstream == sw)
    return [(f"GigabitEthernet0/{i}", nid) for i, nid in enumerate(below, 2)]


def trunk_up(lab, sw: str) -> bool:
    """Whether anything is on the far end of the switch's uplink."""
    return bool(upstream(lab, sw)) or uplinked(lab, sw)


def gig_names() -> list[str]:
    return [f"GigabitEthernet0/{i}" for i in range(1, GIG_PORTS + 1)]


PIN = "port:"  # a switch's setting: the FastEthernet port a machine's cable went into


def pin_port(lab, sw: str, label: str, no: int | None) -> None:
    """Keep the cable `label` (pc01:nic0) in port Fa0/`no` of switch `sw`,
    where someone plugged it (the rack's back). None lets it float again;
    every other switch forgets it either way."""
    for dev, own in lab.devices.items():
        if dev.startswith("sw:"):
            own.pop(PIN + label, None)
    if no is not None:
        if not 1 <= no <= SWITCH_PORTS:
            raise ValueError(f"a switch has FastEthernet0/1 to FastEthernet0/{SWITCH_PORTS}")
        own = settings(lab, f"sw:{sw}")
        for k in [k for k, v in own.items() if k.startswith(PIN) and str(v) == str(no)]:
            del own[k]  # the cable that was in that port floats to a free one
        own[PIN + label] = str(no)


def switch_ports(lab, plan, layout: dict | None = None) -> dict[str, list]:
    """Per switch on the canvas, the machine ports plugged into it (in any
    of its VLANs), in port order: entry i is FastEthernet0/i+1, None where
    that port is empty. A cable plugged into a chosen port (pin_port) stays
    there; the rest fill the free ports by where the machines stand on the
    canvas, left to right, so cables do not cross (the canvas draws them so
    too)."""
    if layout is None:
        from .workbench import _auto_layout
        layout = _auto_layout(lab)
    order = {n.id: i for i, n in enumerate(lab.node_list())}
    nodes = sorted(lab.node_list(), key=lambda n: ((layout.get(n.id) or [0, 0])[0], order[n.id]))
    out: dict[str, list] = {nid: [] for nid in switches(lab)}
    for node in nodes:
        if node.vars.get("devvm") == "ap":
            continue  # an AP's own VM: its port is the AP's (ap_slots)
        radio = str(node.vars.get("wireless") or "").split()  # Wi-Fi cards reach the switch through an AP
        for link in plan.ports_for(node.id):
            if str(link.nic_index) in radio:
                continue
            net = lab.networks.get(link.network_id) if link.plugged else None
            if net is not None and net.home in out:
                out[net.home].append(link)
    for sw, links in out.items():
        own = lab.devices.get(f"sw:{sw}", {})
        slots: list = [None] * SWITCH_PORTS
        held = set(_ap_pins(lab, sw).values())
        loose = []
        for link in links:
            try:
                no = int(own.get(PIN + link.label) or 0)
            except ValueError:
                no = 0
            if 1 <= no <= SWITCH_PORTS and slots[no - 1] is None:
                slots[no - 1] = link
            else:
                loose.append(link)
        free = (i for i, s in enumerate(slots) if s is None and i + 1 not in held)
        for link in loose:
            i = next(free, None)
            if i is None:
                slots.append(link)  # more cables than ports: past the last, as before
            else:
                slots[i] = link
        while slots and slots[-1] is None:
            slots.pop()
        out[sw] = slots
    return out


def _ap_pins(lab, sw: str) -> dict[str, int]:
    """AP id -> the FastEthernet port its cable was plugged into (a site's
    patch), for the APs cabled into this switch."""
    from . import wifi
    own = lab.devices.get(f"sw:{sw}", {})
    out = {}
    for ap_id in wifi.on_switch(lab, sw):
        try:
            no = int(own.get(PIN + f"{ap_id}:nic0") or 0)
        except ValueError:
            no = 0
        if 1 <= no <= SWITCH_PORTS:
            out[ap_id] = no
    return out


def ap_slots(lab, plan, sw: str, ports: list | None = None) -> dict[int, str]:
    """FastEthernet port number -> the AP in it: an AP plugged into a chosen
    port keeps it; the others follow the machines' ports, as before."""
    from . import wifi
    ports = ports if ports is not None else switch_ports(lab, plan).get(sw, [])
    pins = _ap_pins(lab, sw)
    out: dict[int, str] = {}
    for ap_id, no in pins.items():
        if (no > len(ports) or ports[no - 1] is None) and no not in out:
            out[no] = ap_id
    nxt = len(ports) + 1
    for ap_id in wifi.on_switch(lab, sw):
        if ap_id in out.values():
            continue
        while nxt in out:
            nxt += 1
        out[nxt] = ap_id
        nxt += 1
    return out


def port_no(lab, plan, label: str) -> tuple[str, int] | None:
    """(switch, FastEthernet port number) a machine's cable is in."""
    for sw, links in switch_ports(lab, plan).items():
        for i, link in enumerate(links, 1):
            if link is not None and link.label == label:
                return sw, i
    return None


def short_if(name: str) -> str:
    return name.replace("GigabitEthernet", "Gi").replace("FastEthernet", "Fa")


def parse_if(text: str, names: list[str], sub: bool = False) -> str:
    """'g0/1', 'gi 0/1', 'GigabitEthernet0/1', 'fa0/3' -> the full name;
    'g0/1.10' a sub-interface of it, where `sub` allows one."""
    t = re.sub(r"\s+", "", text).lower()
    m = re.match(r"^([a-z]+)(\d+/\d+(?:/\d+)?)(\.\d+)?$", t)
    if not m:
        raise CliError("% Invalid input detected at '^' marker.")
    word, num, dot = m.groups()
    if dot and not sub:
        raise CliError("% Invalid input detected at '^' marker.")
    if dot and not 1 <= int(dot[1:]) <= 4094:
        raise CliError("% Invalid input detected at '^' marker.")
    for full in names:
        fm = re.match(r"^([A-Za-z]+)(\d+/\d+(?:/\d+)?)$", full)
        if fm and fm.group(2) == num and fm.group(1).lower().startswith(word):
            return full + (dot or "")
    raise CliError("% Invalid input detected at '^' marker.")


def mask_of(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def to_iface(addr: str, mask: str) -> ipaddress.IPv4Interface:
    try:
        if mask.startswith("/"):
            return ipaddress.IPv4Interface(f"{addr}{mask}")
        return ipaddress.IPv4Interface(f"{addr}/{mask}")
    except ValueError:
        raise CliError("% Invalid address or mask") from None


def dotted_mac(mac: str) -> str:
    h = mac.replace(":", "").lower()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


# ------------------------------------------------------------------ trunks
def vlan_set(text: str) -> set[int] | None:
    """'1,10,20-22' -> {1, 10, 20, 21, 22}; 'all' -> None; 'none' -> set()."""
    t = text.strip().lower()
    if t == "all":
        return None
    if t in ("none", ""):
        return set()
    out: set[int] = set()
    for part in t.split(","):
        lo, _, hi = part.strip().partition("-")
        a, b = int(lo), int(hi or lo)
        if not (1 <= a <= b <= 4094):
            raise ValueError(text)
        out.update(range(a, b + 1))
    return out


def vlan_text(tags: set[int]) -> str:
    """{1, 10, 20, 21, 22} -> '1,10,20-22'."""
    out, run = [], []
    for t in sorted(tags):
        if run and t == run[-1] + 1:
            run.append(t)
            continue
        if run:
            out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
        run = [t]
    if run:
        out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
    return ",".join(out)


def edit_vlans(have: set[int] | None, text: str) -> set[int] | None:
    """switchport trunk allowed vlan <list | add list | remove list | except
    list | all | none> on what a port allows now (None: all)."""
    w = text.strip().lower().split(None, 1)
    if not w:
        raise ValueError(text)
    every = set(range(1, 4095))
    if w[0] in ("add", "remove", "except") and len(w) == 2:
        tags = vlan_set(w[1]) or set()
        if w[0] == "except":
            return every - tags
        base = every if have is None else set(have)
        out = base | tags if w[0] == "add" else base - tags
        return None if out == every else out
    if w[0] == "all" and len(w) == 1:
        return None
    if w[0] == "none" and len(w) == 1:
        return set()
    return vlan_set(text)


def allowed_tags(lab, sw: str, key: str) -> set[int] | None:
    """The VLANs a switch port's trunk allows (None: every one)."""
    raw = lab.devices.get(f"sw:{sw}", {}).get(f"allowed:{key}")
    try:
        return vlan_set(raw) if raw else None
    except ValueError:
        return None


def trunk_tag(lab, sw: str, up: str, tag: int) -> int | None:
    """The VLAN that switch `sw`'s VLAN `tag` is part of on switch `up`,
    across the trunk from sw's uplink (Gi0/1) to up: None when either end
    does not allow it. Native VLANs that differ at the two ends join each
    other, untagged, as they do on real switches (a native VLAN mismatch)."""
    own_s, own_u = lab.devices.get(f"sw:{sw}", {}), lab.devices.get(f"sw:{up}", {})
    if not any(k.startswith(("allowed:Gi", "native:Gi")) for k in list(own_s) + list(own_u)):
        return tag
    port_u = dict((b, p) for p, b in downlinks(lab, up)).get(sw, "")
    try:
        ns = int(own_s.get("native:GigabitEthernet0/1", 1))
        nu = int(own_u.get(f"native:{port_u}", 1)) if port_u else 1
    except ValueError:
        ns = nu = 1
    far = nu if tag == ns else tag
    a = allowed_tags(lab, sw, "GigabitEthernet0/1")
    b = allowed_tags(lab, up, port_u) if port_u else None
    if (a is not None and tag not in a) or (b is not None and far not in b):
        return None
    return far


def refresh_trunks(lab, sw: str) -> list[int]:
    """A machine's port in trunk mode (switchport mode trunk) carries, tagged,
    every VLAN of the switch it allows besides its native one: the card's
    `trunk` in the lab file, which the router's switch port follows
    (winlab/netplan.py, winlab/livenet.py). A tagged VLAN goes out with its
    own number as the tag, so its network takes that number as its VLAN id
    on the router; a number another network already uses there cannot be
    carried. Returns the VLANs left out for that."""
    own = lab.devices.get(f"sw:{sw}", {})
    trunked = [(node, i, nic) for node in lab.node_list() for i, nic in enumerate(node.nics)
               if nic.plugged and nic.network in lab.networks and lab.networks[nic.network].home == sw
               and own.get(f"mode:{node.id}:nic{i}") == "trunk"]
    if not trunked:
        return []
    used: dict[int, str] = {}
    try:
        from .netplan import compile_topology
        for sid, seg in compile_topology(lab, check_ports=False).segments.items():
            used[seg.vid] = sid
    except Exception:  # noqa: BLE001 - a plan that does not compile: the lab file's own ids only
        pass
    for n in lab.networks.values():
        if n.vlan:
            used[n.vlan] = lab.segment_id(n.id)
    left: list[int] = []
    for node, i, nic in trunked:
        net = lab.networks[nic.network]
        allow = allowed_tags(lab, sw, f"{node.id}:nic{i}")
        carry = []
        for v in vlans_of(lab, sw):
            if v.id == net.id or (allow is not None and v.vlan_no not in allow):
                continue
            seg = lab.segment_id(v.id)
            if v.vlan != v.vlan_no and used.get(v.vlan_no, seg) != seg:
                left.append(v.vlan_no)
                continue
            if lab.networks[seg].vlan != v.vlan_no:
                lab.networks[seg].vlan = v.vlan_no
            used[v.vlan_no] = seg
            carry.append(v.id)
        nic.trunk = carry
    return sorted(set(left))


# ------------------------------------------------------------------ IOS manners
def split_pipe(text: str) -> tuple[str, str]:
    """'show run | include ip' -> ('show run', 'include ip')."""
    cmd, bar, rest = text.partition("|")
    return (cmd.strip(), rest.strip()) if bar else (text, "")


def apply_pipe(out: str, pipe: str) -> str:
    """An output filter as IOS has them: include, exclude, begin, section
    (each may be cut short), with a regular expression."""
    word, _, pattern = pipe.partition(" ")
    word = word.lower()
    try:
        rx = re.compile(pattern.strip())
    except re.error:
        raise CliError("% Invalid regular expression") from None
    lines = out.split("\n")
    for full in ("include", "exclude", "begin", "section", "count"):
        if word and full.startswith(word):
            break
    else:
        raise CliError("% Invalid input detected at '^' marker.")
    if not pattern.strip():
        raise CliError("% Incomplete command.")
    if full == "include":
        return "\n".join(l for l in lines if rx.search(l))
    if full == "exclude":
        return "\n".join(l for l in lines if not rx.search(l))
    if full == "count":
        return f"Number of lines which match regexp = {sum(1 for l in lines if rx.search(l))}"
    if full == "begin":
        for i, l in enumerate(lines):
            if rx.search(l):
                return "\n".join(lines[i:])
        return ""
    keep, inside = [], False
    for l in lines:
        if l and not l.startswith(" "):
            inside = bool(rx.search(l))
        if inside and l and l != "!":
            keep.append(l)
        elif l.startswith(" ") and rx.search(l) and not inside:
            keep.append(l)
    return "\n".join(keep)


# How ? names a blank to fill in, and what it is.
PLACE = {"<ip>": "A.B.C.D", "<mask>": "A.B.C.D", "<name>": "WORD", "<line>": "LINE", "<num>": "<1-4094>"}
PLACE_HELP = {"<ip>": "IP address", "<mask>": "IP subnet mask", "<name>": "Name", "<line>": "Arguments",
              "<num>": "Number"}
# What a word of a longer command does, as ? describes it: by the words
# before it, then by the word alone.
# A mode's prompt where it is not the mode's own name (winlab/routerpolicy.py fills it).
MODE_PROMPTS: dict[str, str] = {}
WORD_HELP = {
    ("show",): "Show running system information", ("show", "ip"): "IP information",
    ("show", "interfaces"): "Interface status and configuration",
    ("show", "running-config"): "Current operating configuration",
    ("show", "mac"): "MAC configuration", ("show", "mac", "address-table"): "MAC forwarding table",
    ("show", "ip", "dhcp"): "Show items in the DHCP database", ("show", "ip", "nat"): "IP NAT information",
    ("show", "ip", "interface"): "IP interface status and configuration",
    ("show", "cdp"): "CDP information", ("show", "spanning-tree"): "Spanning tree topology",
    ("show", "port-security"): "Show secure port information", ("show", "snmp"): "snmp statistics",
    ("show", "ntp"): "Network time protocol", ("show", "vlan"): "VTP VLAN status",
    ("show", "access-lists"): "List access lists", ("show", "ip", "access-lists"): "List IP access lists",
    ("ip",): "Global IP configuration subcommands", ("interface",): "Select an interface to configure",
    ("no",): "Negate a command or set its defaults", ("enable",): "Modify enable password parameters",
    ("line",): "Configure a terminal line", ("username",): "Establish User Name Authentication",
    ("service",): "Modify use of network based services", ("spanning-tree",): "Spanning Tree Subsystem",
    ("switchport",): "Set switching mode characteristics", ("logging",): "Modify message logging facilities",
    ("snmp-server",): "Modify SNMP engine parameters", ("ntp",): "Configure NTP",
    ("banner",): "Define a login banner", ("terminal",): "Set terminal line parameters",
    ("copy",): "Copy from one file to another", ("erase",): "Erase a filesystem",
    ("write",): "Write running configuration to memory, network, or terminal",
    ("clock",): "Manage the system clock", ("clear",): "Reset functions",
    ("access-list",): "Add an access list entry", ("vlan",): "Vlan commands",
    ("ip", "dhcp"): "Configure DHCP server and relay parameters", ("ip", "route"): "Establish static routes",
    ("ip", "nat"): "NAT configuration commands", ("ip", "access-list"): "Named access-list",
    ("ip", "access-group"): "Specify access control for packets", ("ip", "address"): "Set the IP address of an interface",
    ("ip", "default-gateway"): "Specify default gateway (if not routing IP)",
    ("ip", "helper-address"): "Specify a destination address for UDP broadcasts",
    ("switchport", "mode"): "Set trunking mode of the interface",
    ("switchport", "access"): "Set access mode characteristics of the interface",
    ("switchport", "trunk"): "Set trunking characteristics of the interface",
    ("switchport", "port-security"): "Security related command",
    ("line", "con"): "Primary terminal line", ("line", "console"): "Primary terminal line",
    ("line", "vty"): "Virtual terminal",
}


def word_help(before: list[str], word: str, router: bool) -> str:
    key = tuple(w for w in before if w != "no") + (word,)
    if key in WORD_HELP:
        return WORD_HELP[key]
    return WORD_HELP.get((word,), "")


# ------------------------------------------------------------------ console
class Console:
    """One device's command line. `dash` is the desktop's Dashboard (its lab,
    plan, reload(), the shared Live reader); `runner_factory` and `link`
    are seams for the tests."""

    def __init__(self, dash, device: str, runner_factory=None, link=None):
        from .routers import rid_of
        self.dash = dash
        # Another router than the lab router (winlab/routers.py): its console
        # is the router console on that router's view of the lab.
        self.rid = rid_of(device)
        self.device = ROUTER if self.rid else device
        self._views: tuple = (None, None, None, None)
        self.s = Session(device)
        self._runner_factory = runner_factory
        self._link = link
        self.specs = self._specs()

    # ---- state of the world
    @property
    def lab(self):
        if not self.rid:
            return self.dash.lab
        return self._view()[0]

    @property
    def plan(self):
        if not self.rid:
            return self.dash.plan
        return self._view()[1]

    @property
    def dev_key(self) -> str:
        """The device's own key in the lab file's devices table."""
        return f"router:{self.rid}" if self.rid else self.device

    def _view(self):
        """This router's view of the lab and plan, kept until the desktop
        reads the lab again (a view keeps what refresh_routed worked out)."""
        lab, plan = self.dash.lab, self.dash.plan
        if self._views[0] is not lab or self._views[1] is not plan:
            from . import routers
            v = routers.view(lab, self.rid)
            p = routers.plan_view(plan, self.rid, v) if plan is not None else None
            self._views = (lab, plan, v, p)
        return self._views[2], self._views[3]

    def _running(self) -> set[str]:
        from .workbench import _running
        return _running(self.lab.name)

    def powered(self) -> bool:
        if self.device != ROUTER and switch_off(self.lab, switch_id(self.device)):
            return False
        if self.rid:
            from .routers import powered
            if not powered(self.dash.lab, self.rid):
                return False
        return "fabric" in self._running()

    def _runner(self):
        if self._runner_factory is not None:
            run, why = self._runner_factory()
        else:
            from .cli import _fabric_runner
            run, why = _fabric_runner(self.lab.name)
        if run and self.rid:
            # Inside this router's own network stack (winlab/routers.py).
            from .routers import wrap
            inner, rid = run, self.rid

            def run(cmd, timeout=60):
                return inner(wrap(rid, cmd), timeout=timeout)
            if getattr(inner, "close", None):
                run.close = inner.close  # type: ignore[attr-defined]
        return run, why

    def _on_router(self, cmd: str, timeout: float = 30) -> str:
        run, why = self._runner()
        if not run:
            raise CliError(f"% {why}")
        try:
            return run(cmd, timeout=timeout)
        finally:
            close = getattr(run, "close", None)
            if close:
                close()

    def _save(self, live: bool = True) -> str:
        """Writes the lab file and, for a change the router must make, pushes
        it into the running network: a console line when that failed."""
        from .workbench import _save, _sync
        _save(self.dash)
        note = _sync(self.dash) if live else ""
        return "\n% " + note[2:] if note.startswith("; ") else ""

    def _boot_id(self) -> int:
        """Which start of the router this is (its process), so a session
        typed into before it restarted starts again."""
        st = state.load(self.lab.name)
        fab = st.nodes.get("fabric") if st else None
        return int(fab.pid or 0) if fab else 0

    def _fresh(self) -> None:
        boot = self._boot_id()
        if boot != self.s.boot:
            if self.s.boot:
                # The router started again since: the session is gone with it.
                self.s = Session(self.device, boot=boot, mode="idle")
            else:
                self.s.boot = boot

    def prompt(self) -> str:
        if self.s.ask:
            return self.s.ask["prompt"]
        from . import iosboot  # ROMMON and the switch's boot loader
        mon = iosboot.prompt(self)
        if mon is not None:
            return mon
        if self.s.mode == "idle":
            return ""
        host = ios_name(self.lab, self.device)
        if self.s.mode == "user":
            return f"{host}>"
        if self.s.mode == "enable":
            return f"{host}#"
        return f"{host}({MODE_PROMPTS.get(self.s.mode, self.s.mode)})#"

    def secret(self) -> bool:
        """Whether the device is asking for a password: what is typed does
        not echo."""
        return bool(self.s.ask and self.s.ask.get("secret"))

    def banner_text(self) -> str:
        motd = self.lab.devices.get(self.device, {}).get("banner", "")
        return (f"{motd}\n\n" if motd else "") + f"{ios_name(self.lab, self.device)} con0 is now available\n\n"

    def banner(self) -> str:
        """What the console prints as a session starts (RETURN pressed on
        a fresh line): the banner, then the login the line asks for."""
        if not self.powered():
            return ""
        self._fresh()
        from . import iosboot  # a boot monitor, or the setup dialog after a start without configuration
        said = iosboot.banner(self)
        if said is not None:
            return said
        if self.s.mode == "idle":
            self.s.mode = "user"
        from . import iosnv
        return self.banner_text() + iosnv.begin(self)

    # ---- the command tables
    def _specs(self) -> list[Spec]:
        E, U, C, I, D = ("enable",), ("user", "enable"), ("config",), ("config-if",), ("dhcp-config",)
        router = self.device == ROUTER
        sp: list[Spec] = []

        def add(words, fn, help_, modes):
            sp.append(Spec(words.split(), fn, help_, modes))

        R = ("config-if-range",)
        add("enable", self._enable, "Turn on privileged commands", ("user",))
        add("disable", self._disable, "Turn off privileged commands", E)
        add("exit", self._exit, "Exit from the EXEC", U)
        add("logout", self._exit, "Exit from the EXEC", U)
        add("quit", self._exit, "Exit from the EXEC", U)
        add("configure terminal", self._configure, "Configure from the terminal", E)
        add("configure", self._configure_ask, "Enter configuration mode", E)
        add("terminal length <num>", lambda a: "", "Set number of lines on a screen", U)
        add("terminal monitor", lambda a: "", "Copy debug output to the current terminal line", U)
        add("terminal no monitor", lambda a: "", "Negate a command or set its defaults", U)
        add("show version", self._show_version, "System hardware and software status", U)
        add("show running-config", self._show_run, "Current operating configuration", E)
        add("show running-config interface <line>", self._show_run_if, "Show interface configuration", E)
        add("show startup-config", self._show_startup, "Contents of startup configuration", E)
        add("show history", self._show_history, "Display the session command history", U)
        add("show clock", self._show_clock, "Display the system clock", U)
        add("show users", self._show_users, "Display information about terminal lines", U)
        add("show flash:", self._show_flash, "display information about flash: file system", U)
        add("show interfaces <line>", self._show_iface_one, "Interface status and configuration", U)
        add("clock set <line>", self._clock_set, "Set the time and date", E)
        add("write", self._write, "Write running configuration to memory, network, or terminal", E)
        add("write memory", self._write, "Write to NV memory", E)
        add("write erase", self._erase, "Erase NV memory", E)
        add("write terminal", self._show_run, "Write to terminal", E)
        add("copy running-config startup-config", self._copy, "Copy to startup configuration", E)
        add("erase startup-config", self._erase, "Erase contents of configuration memory", E)
        add("erase nvram:", self._erase, "Erase NV memory", E)
        add("reload", self._reload, "Halt and perform a cold restart", E)
        if router:
            add("show ip interface brief", self._show_ip_brief, "Brief summary of IP status and configuration", U)
            add("show ip interface", self._show_ip_iface, "IP interface status and configuration", U)
            add("show ip interface <line>", self._show_ip_iface, "IP interface status and configuration", U)
            add("show interfaces", self._show_interfaces, "Interface status and configuration", U)
            add("show ip route", self._show_route, "IP routing table", U)
            add("show ip protocols", self._show_protocols, "IP routing protocol process parameters and statistics", U)
            add("show arp", self._show_arp, "ARP table", U)
            add("show ip arp", self._show_arp, "IP ARP table", U)
            add("show ip dhcp binding", self._show_binding, "DHCP address bindings", U)
            add("show ip dhcp pool", self._show_pools, "DHCP pools information", U)
            add("ping <ip>", self._ping, "Send echo messages", U)
            add("traceroute <ip>", self._trace, "Trace route to destination", U)
            add("wake <line>", self._wake_on_lan, "Send a Wake-on-LAN magic packet to a MAC address", U)
        else:
            add("show vlan brief", self._show_vlan, "VTP all VLAN status in brief", U)
            add("show vlan", self._show_vlan, "VTP VLAN status", U)
            add("show mac address-table", self._show_mac, "MAC forwarding table", U)
            add("show mac address-table dynamic", lambda a: self._show_mac(a, dynamic=True), "dynamic entry type", U)
            add("show mac address-table interface <line>", lambda a: self._show_mac(a, port=a[0]), "interface keyword", U)
            add("show interfaces status", self._show_status, "Show interface line status", U)
            add("show interfaces trunk", self._show_trunk, "Show interface trunk information", U)
            add("show interfaces", lambda a: netauto.sw_interfaces(self), "Interface status and configuration", U)
            add("show ip interface brief", self._sw_ip_brief, "Brief summary of IP status and configuration", U)
            add("ping <ip>", self._sw_ping, "Send echo messages", U)
        # configuration
        SI, V = ("config-subif",), ("config-vlan",)
        L = ("config-line",)
        cfg = C + I + SI + D + V + L + R + ("config-std-nacl", "config-ext-nacl")
        add("hostname <name>", self._hostname, "Set system's network name", C)
        add("no hostname", self._no_hostname, "Negate a command or set its defaults", C)
        add("banner motd <line>", self._banner, "Set Message of the Day banner", C)
        add("no banner motd", self._no_banner, "Negate a command or set its defaults", C)
        add("interface <line>", self._interface, "Select an interface to configure", C + I + SI + V + R)
        add("interface range <line>", self._interface_range, "interface range command", C + I + SI + V + R)
        add("end", self._end, "Exit from configure mode", cfg)
        add("exit", self._cfg_exit, "Exit from configure mode", cfg)
        add("do <line>", self._do, "To run exec commands in config mode", cfg)
        add("description <line>", self._description, "Interface specific description", I + SI + R)
        add("no description", self._no_description, "Negate a command or set its defaults", I + SI + R)
        add("shutdown", lambda a: self._shutdown(True), "Shutdown the selected interface", I + SI + R)
        add("no shutdown", lambda a: self._shutdown(False), "Negate a command or set its defaults", I + SI + R)
        from . import iosnv  # passwords, the console line, local users
        add("enable secret <line>", lambda a: self._pw("enable-secret", a[0], True), "Assign the privileged level secret", C)
        add("enable password <line>", lambda a: self._pw("enable-password", a[0], False), "Assign the privileged level password", C)
        add("no enable secret", lambda a: self._no_key("enable-secret"), "Negate a command or set its defaults", C)
        add("no enable password", lambda a: self._no_key("enable-password"), "Negate a command or set its defaults", C)
        add("service password-encryption", lambda a: self._set_key("service-pwenc", "yes"), "Encrypt system passwords", C)
        add("no service password-encryption", lambda a: self._no_key("service-pwenc"), "Negate a command or set its defaults", C)
        add("username <name> <line>", self._username, "Establish User Name Authentication", C)
        add("no username <name>", lambda a: self._no_key(f"user:{a[0]}"), "Negate a command or set its defaults", C)
        add("line con 0", lambda a: self._line("con"), "Primary terminal line", C + L)
        add("line console 0", lambda a: self._line("con"), "Primary terminal line", C + L)
        add("line vty <num> <line>", lambda a: self._line("vty"), "Virtual terminal", C + L)
        add("password <line>", lambda a: self._pw(f"line-{self.s.ctx}:password", a[0], False), "Set a password", L)
        add("no password", lambda a: self._no_key(f"line-{self.s.ctx}:password"), "Negate a command or set its defaults", L)
        add("login", lambda a: self._login("yes"), "Enable password checking", L)
        add("login local", lambda a: self._login("local"), "Local password checking", L)
        add("no login", lambda a: self._login(""), "Negate a command or set its defaults", L)
        add("exec-timeout <line>", lambda a: self._line_opt("exec-timeout", a[0]), "Set the EXEC timeout", L)
        add("logging synchronous", lambda a: self._line_opt("logging-sync", "yes"), "Synchronized message output", L)
        add("transport input <line>", lambda a: self._line_opt("transport", a[0]), "Define which protocols to use when connecting to the terminal server", L)
        if router:
            add("ip address <ip> <mask>", self._ip_address, "Set the IP address of an interface", I + SI)
            add("no ip address", self._no_ip_address, "Negate a command or set its defaults", I + SI)
            add("no ip address <line>", self._no_ip_address, "Negate a command or set its defaults", I + SI)
            add("ip helper-address <ip>", self._helper, "Specify a destination address for UDP broadcasts", I + SI)
            add("no ip helper-address", lambda a: self._no_helper(""), "Negate a command or set its defaults", I + SI)
            add("no ip helper-address <ip>", lambda a: self._no_helper(a[0]), "Negate a command or set its defaults", I + SI)
            add("encapsulation dot1q <num>", self._encap, "IEEE 802.1Q Virtual LAN", SI)
            add("no interface <line>", self._no_interface, "Delete a subinterface", C)
            add("ip dhcp pool <name>", self._pool, "Configure DHCP address pools", C)
            add("no ip dhcp pool <name>", self._no_pool, "Negate a command or set its defaults", C)
            add("ip dhcp excluded-address <ip>", lambda a: self._excluded(a[0], a[0], True), "Prevent DHCP from assigning certain addresses", C)
            add("ip dhcp excluded-address <ip> <ip>", lambda a: self._excluded(a[0], a[1], True), "Prevent DHCP from assigning certain addresses", C)
            add("no ip dhcp excluded-address <ip>", lambda a: self._excluded(a[0], a[0], False), "Negate a command or set its defaults", C)
            add("no ip dhcp excluded-address <ip> <ip>", lambda a: self._excluded(a[0], a[1], False), "Negate a command or set its defaults", C)
            add("router <line>", self._no_protocols, "Enable a routing process", C)
            add("network <ip> <mask>", self._pool_network, "Network number and mask", D)
            add("default-router <line>", self._pool_gateway, "Default routers", D)
            add("no default-router", lambda a: self._pool_opt("poolgw", ""), "Negate a command or set its defaults", D)
            add("dns-server <line>", self._pool_dns, "DNS servers", D)
            add("no dns-server", lambda a: self._pool_opt("pooldns", ""), "Negate a command or set its defaults", D)
            add("domain-name <name>", lambda a: self._pool_opt("pooldom", a[0]), "Domain name", D)
            add("no domain-name", lambda a: self._pool_opt("pooldom", ""), "Negate a command or set its defaults", D)
            add("lease <line>", self._pool_lease, "Address lease time", D)
            add("no lease", lambda a: self._pool_opt("poollease", ""), "Negate a command or set its defaults", D)
            add("next-server <ip>", self._next_server, "Next server in boot process", D)
            add("bootfile <line>", self._bootfile, "Boot file name", D)
            add("no next-server", lambda a: self._boot_clear("next"), "Negate a command or set its defaults", D)
            add("no bootfile", lambda a: self._boot_clear("file"), "Negate a command or set its defaults", D)
            from . import iosl3  # static routes, access lists, NAT
            iosl3.add_specs(self, add, U, E, C, I + SI)
            from . import iosrouting  # OSPF, BGP, VRFs and VRRP (FRRouting on the router)
            iosrouting.add_specs(self, add, U, E, C, I + SI)
            from . import iosv6  # ipv6 unicast-routing, addresses, RAs, static routes, OSPFv3
            iosv6.add_specs(self, add, U, E, C, I + SI)
            from . import acl6  # ipv6 access-list, ipv6 traffic-filter (nftables' ip6 family)
            acl6.add_specs(self, add, U, E, C, I + SI)

            from . import routerpolicy  # zone firewall, Tunnel and IPsec, QoS
            routerpolicy.add_specs(self, add, U, E, C, I + SI)
            from . import iossla  # ip sla, track, and what follows an object
            iossla.add_specs(self, add, U, E, C, I + SI)
        else:
            add("vlan <num>", self._vlan, "VLAN commands", C + V)
            add("no vlan <num>", self._no_vlan, "Delete a VLAN", C)
            add("name <line>", self._vlan_name, "Ascii name of the VLAN", V)
            add("switchport mode <line>", self._switchport_mode, "Set trunking mode of the interface", I + R)
            add("switchport access vlan <num>", self._access_vlan, "Set VLAN when interface is in access mode", I + R)
            add("no switchport access vlan", self._no_access_vlan, "Negate a command or set its defaults", I + R)
            add("switchport trunk allowed vlan <line>", self._trunk_allowed, "Set allowed VLANs when interface is in trunking mode", I + R)
            add("no switchport trunk allowed vlan", lambda a: self._trunk_allowed(["all"]), "Negate a command or set its defaults", I + R)
            add("switchport trunk native vlan <num>", self._trunk_native, "Set native VLAN when interface is in trunking mode", I + R)
            add("no switchport trunk native vlan", lambda a: self._trunk_native(["1"]), "Negate a command or set its defaults", I + R)
            add("switchport nonegotiate", lambda a: self._port_key("noneg", "yes"), "Device will not engage in negotiation protocol on this interface", I + R)
            add("no switchport nonegotiate", lambda a: self._port_key("noneg", ""), "Negate a command or set its defaults", I + R)
            add("duplex <line>", lambda a: self._speed_duplex("duplex", a), "Configure duplex operation", I + R)
            add("speed <line>", lambda a: self._speed_duplex("speed", a), "Configure speed operation", I + R)
            add("ip address <ip> <mask>", self._sw_ip, "Set the IP address of an interface", I)
            add("no ip address", lambda a: self._sw_ip([]), "Negate a command or set its defaults", I)
            add("ip default-gateway <ip>", self._sw_gateway, "Specify default gateway (if not routing IP)", C)
            add("no ip default-gateway", lambda a: self._sw_gateway([]), "Negate a command or set its defaults", C)
            from . import stp  # spanning tree: show spanning-tree, spanning-tree vlan, portfast, bpduguard
            stp.add_specs(self, add, U, C, I)
            from . import portsec  # port security, err-disabled recovery, 802.1X (winlab/dot1x.py)
            portsec.add_specs(self, add, U, C, I)
            from . import etherchannel, span  # channel-group, port-channels; SPAN (monitor session)
            etherchannel.add_specs(self, add, U, C, I + R)
            span.add_specs(self, add, U, C, I)
            from . import iosv6  # the management interface's IPv6 address
            iosv6.add_switch_specs(self, add, U, C, I)
            from . import acl6, l2sec  # private VLANs, storm control, RA and DHCPv6 guard; IPv6 port ACLs
            l2sec.add_specs(self, add, U, C, I + R, V)
            acl6.add_specs(self, add, U, E, C, I + R, switch=True)
        from . import iosssh  # ip domain-name, crypto key generate rsa, ip ssh: SSH to the device's addresses
        iosssh.add_specs(self, add, U, C, I)
        from . import aaa  # aaa authentication login, tacacs server, login authentication, test aaa
        aaa.add_specs(self, add, U, E, C, L)
        from . import nms  # syslog, SNMP and NTP: logging host, snmp-server, ntp server, show logging
        nms.add_specs(self, add, U, C, I)
        from . import lldp, tftpcopy  # CDP and LLDP (lldpd), the voice VLAN; copy to and from a TFTP server
        lldp.add_specs(self, add, U, C, I)
        from . import poe  # Power over Ethernet: show power inline, power inline never / auto / static
        poe.add_specs(self, add, U, C, I)
        tftpcopy.add_specs(self, add, E)
        from . import ftpscp  # ip ftp username / password: the login copy ... ftp: uses (winlab/ftpscp.py)
        ftpscp.add_specs(self, add, C)
        from . import iosboot  # flash and images, boot system, config-register (winlab/iosimage.py)
        iosboot.add_specs(self, add, U, E, C)
        from . import netauto  # what Netmiko, NAPALM and Ansible send; RESTCONF (winlab/restconf.py)
        netauto.add_specs(self, add, U, C, I)
        return sp

    # ---- running a line
    def run(self, line: str) -> str:
        """What the device prints for a line typed at its prompt."""
        if not self.powered():
            return ""
        self._fresh()
        line = line.rstrip("\n")
        from . import iosboot  # the Break in the boot window, and lines typed at a boot monitor
        said = iosboot.intercept(self, line)
        if said is not None:
            return said
        if self.s.ask:
            from . import iosnv
            return iosnv.answer(self, line)
        if self.s.mode == "idle":
            return self.banner()
        if line.rstrip().endswith("?"):
            return self.help(line.rstrip()[:-1])
        text = line.strip()
        if not text or text.startswith("!"):
            return ""
        self.s.history = (self.s.history + [text])[-50:]
        if self.device == ROUTER:
            pin_router_ports(self.lab)
        text, pipe = split_pipe(text)
        try:
            try:
                spec, args = self._match(text, self.s.mode)
            except CliError:
                # As on IOS, a global command typed in a sub-mode (interface,
                # vlan, pool, line, list) leaves the sub-mode and runs.
                if self.s.mode in ("config", "user", "enable") or not self.s.mode.startswith(("config", "dhcp")):
                    raise
                spec, args = self._match(text, "config")
                if self.s.mode == "config-mst":
                    from . import mst  # leaving the MST submode applies the region typed in it
                    mst.apply(self)
                self.s.mode, self.s.ctx = "config", ""
            from . import aaa  # aaa authorization commands: the method list says yes or no first
            acct = aaa.gate(self, spec, args)
            from . import etherchannel  # interface port-channel: its own settings, the rest on its members
            po = etherchannel.on_po(self, spec, args)
            if po is not None:
                out = po
            elif self.s.mode == "config-if-range" and spec.run not in (
                    self._end, self._cfg_exit, self._do, self._interface, self._interface_range):
                out = self._each(spec, args)
            else:
                out = spec.run(args) or ""
            aaa.account(self, acct)   # aaa accounting commands: the command's stop record
        except CliError as exc:
            return str(exc)
        if pipe:
            out = apply_pipe(out, pipe)
        from . import nms  # what the device printed is its log: buffer, syslog server, traps
        nms.heard(self, text, out)
        return out

    def _each(self, spec, args) -> str:
        """A command typed under interface range: run on each port in it."""
        members = self.s.ctx.split(",")
        outs = []
        try:
            for name in members:
                self.s.mode, self.s.ctx = "config-if", name
                try:
                    outs.append(spec.run(args) or "")
                except CliError as exc:
                    outs.append(str(exc))
        finally:
            if self.s.mode == "config-if":
                self.s.mode, self.s.ctx = "config-if-range", ",".join(members)
        return "\n".join(o for o in outs if o)

    def _candidates(self, mode: str) -> list[Spec]:
        return [s for s in self.specs if mode in s.modes]

    def _match(self, text: str, mode: str):
        """The one command a line is, IOS style: each word may be cut short
        while it stays unambiguous among the commands of the mode."""
        tokens = text.split()
        alive = [(spec, [], 0, False) for spec in self._candidates(mode)]
        for i, tok in enumerate(tokens):
            nxt, lits = [], set()
            for spec, args, wi, done in alive:
                if done:
                    nxt.append((spec, args, wi, done))
                    continue
                if wi >= len(spec.words):
                    continue
                w = spec.words[wi]
                if w == "<line>":
                    nxt.append((spec, args + [" ".join(tokens[i:])], wi + 1, True))
                elif w == "<num>" and not tok.isdigit():
                    continue  # a number goes here
                elif w.startswith("<"):
                    nxt.append((spec, args + [tok], wi + 1, False))
                elif w.startswith(tok.lower()):
                    lits.add(w)
                    nxt.append((spec, args, wi + 1, False))
            if tok.lower() in lits:
                nxt = [e for e in nxt if e[3] or e[0].words[e[2] - 1].startswith("<")
                       or e[0].words[e[2] - 1] == tok.lower()]
            elif len(lits) > 1 and not any(e[3] or e[0].words[e[2] - 1].startswith("<") for e in nxt):
                raise CliError(f'% Ambiguous command:  "{text}"')
            elif len(lits) > 1:
                nxt = [e for e in nxt if e[3] or e[0].words[e[2] - 1].startswith("<")]
            if not nxt:
                col = len(self.prompt()) + sum(len(t) + 1 for t in tokens[:i])
                raise CliError(f"{' ' * col}^\n% Invalid input detected at '^' marker.")
            alive = nxt
        whole = [(spec, args) for spec, args, wi, done in alive if done or wi == len(spec.words)]
        if not whole:
            raise CliError("% Incomplete command.")
        if len({id(spec.run) for spec, _ in whole}) > 1:
            # A word the command names beats one that only fills a blank
            # (show interfaces status, not show interfaces <name>).
            def literal(spec):
                return sum(1 for w in spec.words[:len(tokens)] if not w.startswith("<"))
            most = max(literal(spec) for spec, _ in whole)
            whole = [w for w in whole if literal(w[0]) == most]
            fewest = min(len(spec.words) for spec, _ in whole)
            whole = [w for w in whole if len(w[0].words) == fewest]
            if len(whole) > 1 and len({id(spec.run) for spec, _ in whole}) > 1:
                raise CliError(f'% Ambiguous command:  "{text}"')
        return whole[0]

    def _next_words(self, tokens: list[str], partial: str) -> list[tuple[str, str]]:
        out: dict[str, str] = {}
        for spec in self._candidates(self.s.mode):
            ws = spec.words
            ok = True
            for i, t in enumerate(tokens):
                if i >= len(ws):
                    ok = False
                    break
                if ws[i] == "<line>":
                    break
                if not ws[i].startswith("<") and not ws[i].startswith(t.lower()):
                    ok = False
                    break
            if not ok:
                continue
            k = len(tokens)
            if k < len(ws):
                w = ws[k]
                if w.startswith("<") or w.startswith(partial.lower()):
                    words = [x for x in ws[:k] if not x.startswith("<")]
                    label = PLACE.get(w, w.strip("<>").upper()) if w.startswith("<") else w
                    hint = spec.help if k == len(ws) - 1 else word_help(words, w, self.device == ROUTER)
                    if w.startswith("<"):
                        hint = PLACE_HELP.get(w, hint) if k < len(ws) - 1 or w != "<line>" else hint
                    if not out.get(label):
                        out[label] = hint
            elif not partial:
                out.setdefault("<cr>", "")
        return sorted(out.items(), key=lambda kv: (kv[0] == "<cr>", kv[0]))

    def help(self, line: str) -> str:
        """'?' at the end of a line: the words that may come next, each with
        what it does, as IOS lists them."""
        tokens = line.split()
        partial = "" if (not line or line.endswith(" ")) else tokens.pop()
        words = self._next_words(tokens, partial)
        if not words:
            return "% Unrecognized command"
        if partial:
            return "  ".join(w for w, _ in words if w != "<cr>")
        width = max(len(w) for w, _ in words) + 2
        return "\n".join(f"  {w.ljust(width)}{h}".rstrip() for w, h in words)

    def complete(self, line: str) -> str:
        """Tab: the line with its last word finished, when only one fits."""
        if not line or line.endswith(" "):
            return line
        tokens = line.split()
        partial = tokens.pop()
        words = [w for w, _ in self._next_words(tokens, partial)
                 if not w.startswith("<") and w not in PLACE.values() and w != "LINE" and w != "WORD"]
        if len(words) == 1:
            return " ".join(tokens + [words[0]]) + " "
        return line

    # ---- modes
    def _enable(self, a):
        from . import iosnv  # the enable secret, when set, is asked for
        return iosnv.enable(self)

    def _disable(self, a):
        self.s.mode = "user"

    def _exit(self, a):
        self.s.mode, self.s.ctx, self.s.authed = "idle", "", False
        return f"\n{ios_name(self.lab, self.device)} con0 is now available\n\nPress RETURN to get started."

    def _configure(self, a):
        self.s.mode = "config"
        return "Enter configuration commands, one per line.  End with CNTL/Z."

    def _configure_ask(self, a):
        return self._configure(a)

    def _end(self, a):
        self.s.mode, self.s.ctx = "enable", ""
        return "%SYS-5-CONFIG_I: Configured from console by console"

    def _cfg_exit(self, a):
        if self.s.mode == "config":
            self.s.mode = "enable"
        else:
            self.s.mode, self.s.ctx = "config", ""
        return ""

    def _do(self, a):
        text, pipe = split_pipe(a[0])
        spec, args = self._match(text, "enable")
        out = spec.run(args) or ""
        return apply_pipe(out, pipe) if pipe else out

    # ---- NVRAM (winlab/iosnv.py)
    def _write(self, a):
        from . import iosnv
        return iosnv.write(self)

    def _copy(self, a):
        from . import iosnv
        iosnv.ask(self, "copy-dest", "Destination filename [startup-config]? ")
        return ""

    def _erase(self, a):
        from . import iosnv
        iosnv.ask(self, "erase", "Erasing the nvram filesystem will remove all configuration files! Continue? [confirm]")
        return ""

    def _reload(self, a):
        from . import iosnv
        if iosnv.unsaved(self):
            iosnv.ask(self, "reload-save", "System configuration has been modified. Save? [yes/no]: ")
        else:
            iosnv.ask(self, "reload", "Proceed with reload? [confirm]")
        return ""

    def _show_startup(self, a):
        from . import iosnv
        return iosnv.startup_text(self.lab, self.dev_key)

    # ---- passwords and lines (winlab/iosnv.py)
    def _set_key(self, key: str, value: str):
        settings(self.lab, self.device)[key] = value
        self._save(live=False)

    def _no_key(self, key: str):
        settings(self.lab, self.device).pop(key, None)
        self._save(live=False)

    def _pw(self, key: str, text: str, secret: bool):
        from . import iosnv
        try:
            kept = iosnv.keep(text.split(), secret)
        except ValueError as exc:
            raise CliError(str(exc)) from None
        own = settings(self.lab, self.device)
        if key == "enable-password" and own.get("enable-secret"):
            note = ("The enable password you have chosen is the same as your enable secret.\n"
                    "This is not recommended.  Re-enter the enable password."
                    if iosnv.matches(text, own["enable-secret"]) else "")
            if note:
                return note
        own[key] = kept
        self._save(live=False)

    def _username(self, a):
        from . import iosnv
        name, rest = a[0], a[1].split()
        priv = "1"
        if len(rest) >= 2 and rest[0] == "privilege":
            if not rest[1].isdigit() or not 0 <= int(rest[1]) <= 15:
                raise CliError("% Invalid input detected at '^' marker.")
            priv, rest = rest[1], rest[2:]
        if not rest or rest[0] not in ("secret", "password"):
            raise CliError("% Incomplete command.")
        try:
            kept = iosnv.keep(rest[1:], rest[0] == "secret")
        except ValueError as exc:
            raise CliError(str(exc)) from None
        settings(self.lab, self.device)[f"user:{name}"] = f"{priv} {kept}"
        from . import iosssh  # the crypt an SSH login (login local) is checked with
        note = iosssh.remember(self, name, rest[1:])
        self._save()   # live: the router's SSH server knows its users (winlab/iosssh.py)
        return note

    def _line(self, which: str):
        self.s.mode, self.s.ctx = "config-line", which

    def _login(self, how: str):
        own = settings(self.lab, self.device)
        key = f"line-{self.s.ctx}:login"
        if how:
            own[key] = how
        else:
            own.pop(key, None)
        self._save(live=self.s.ctx == "vty")   # the vty lines: what SSH logins meet (winlab/iosssh.py)
        if how == "yes" and not own.get(f"line-{self.s.ctx}:password"):
            return "% Login disabled on line 0, until 'password' is set"
        return ""

    def _line_opt(self, what: str, value: str):
        settings(self.lab, self.device)[f"line-{self.s.ctx}:{what}"] = value.strip()
        self._save(live=self.s.ctx == "vty")

    # ---- global configuration
    def _hostname(self, a):
        name = a[0]
        if not _HOST_RE.match(name):
            raise CliError("% Hostname contains one or more illegal characters.")
        settings(self.lab, self.device)["hostname"] = name
        self._save(live=False)

    def _no_hostname(self, a):
        settings(self.lab, self.device).pop("hostname", None)
        self._save(live=False)

    def _banner(self, a):
        text = a[0]
        if len(text) >= 2 and text[0] == text[-1] and not text[0].isalnum():
            text = text[1:-1]
        settings(self.lab, self.device)["banner"] = text.strip()
        self._save(live=False)

    def _no_banner(self, a):
        settings(self.lab, self.device).pop("banner", None)
        self._save(live=False)

    # ---- interfaces
    def _if_names(self) -> list[str]:
        if self.device == ROUTER:
            return router_port_names(self.lab)
        return [f"FastEthernet0/{i}" for i in range(1, SWITCH_PORTS + 1)] + gig_names()

    def _interface(self, a):
        router = self.device == ROUTER
        m = re.match(r"^\s*vl(?:a(?:n)?)?\s*(\d+)\s*$", a[0], re.I)
        if m and not router:
            tag = int(m.group(1))
            if not 1 <= tag <= 4094:
                raise CliError("% Invalid input detected at '^' marker.")
            self.s.ctx, self.s.mode = f"Vlan{tag}", "config-if"
            return
        from . import routerpolicy  # interface Tunnel<n> (winlab/vti.py)
        if router and routerpolicy.is_tunnel(a[0]):
            return routerpolicy.enter_tunnel(self, a[0])
        from . import iosmpls  # interface Loopback<n>
        if router and iosmpls.loopback_name(a[0]):
            return iosmpls.enter(self, a[0])

        from . import etherchannel  # interface port-channel <n>
        if not router and etherchannel.enter(self, a[0]):
            return
        self.s.ctx = parse_if(a[0], self._if_names(), sub=router)
        self.s.mode = "config-subif" if "." in self.s.ctx else "config-if"

    def _interface_range(self, a):
        """interface range fa0/1 - 4 , fa0/7: one command for several ports."""
        names = self._if_names()
        out: list[str] = []
        for part in a[0].split(","):
            m = re.match(r"^\s*([A-Za-z]+\s*\d+/(?:\d+/)?)(\d+)\s*(?:-\s*(\d+))?\s*$", part)
            if not m:
                raise CliError("% Invalid input detected at '^' marker.")
            stem, lo, hi = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
            if hi < lo:
                raise CliError("% Invalid input detected at '^' marker.")
            for n in range(lo, hi + 1):
                full = parse_if(f"{stem}{n}", names)
                if full not in out:
                    out.append(full)
        self.s.ctx, self.s.mode = ",".join(out), "config-if-range"

    # The router's interfaces: a port per switch on the canvas, and on it the
    # sub-interfaces typed in the console (interface g0/1.10, encapsulation
    # dot1Q 10), one per VLAN of that switch the router routes. A network
    # the router routes is one of these; `routed` in the lab file stays the
    # one truth the running router follows (winlab/livenet.py).
    def _port_switch(self, base: str) -> str:
        return dict(router_ports(self.lab)).get(base, "")

    def router_ifaces(self) -> list[tuple[str, object, bool]]:
        """(name, the network it routes or None, administratively up) per
        port, and per sub-interface typed on it."""
        lab = self.lab
        own = lab.devices.get(ROUTER, {})
        rows: list[tuple[str, object, bool]] = []
        for name, sw in router_ports(lab):
            net = iface_net(lab, name)
            rows.append((name, net if net is not None and own.get(f"ip:{name}") == net.id else None,
                         not router_shut(lab, name)))
            subs = sorted({k.split(":", 1)[1] for k in own if k.startswith(("sub:", "dot1q:"))
                           and k.split(":", 1)[1].split(".")[0] == name},
                          key=lambda x: int(x.split(".")[1]))
            for sub in subs:
                net = iface_net(lab, sub)
                rows.append((sub, net if net is not None and own.get(f"ip:{sub}") == net.id else None,
                             not router_shut(lab, sub)))
        return rows

    def iface_of(self, net) -> str:
        for name, n, _ in self.router_ifaces():
            if n is not None and n.id == net.id:
                return name
        return ""

    def _router_net(self):
        ctx = self.s.ctx
        own = settings(self.lab, ROUTER)
        if "." in ctx and not own.get(f"sub:{ctx}") and not own.get(f"dot1q:{ctx}"):
            raise CliError("% Configure encapsulation on the subinterface first")
        net = iface_net(self.lab, ctx)
        if "." in ctx and net is None and own.get(f"dot1q:{ctx}"):
            raise CliError(f"% VLAN {own[f'dot1q:{ctx}']} is not on the switch behind "
                           f"{short_if(ctx.split('.')[0])} yet: make it there first")
        if "." in ctx and net is not None:
            own[f"sub:{ctx}"] = net.id
        if net is None:
            raise CliError(f"% {short_if(ctx.split('.')[0])} has no cable in it: drag a switch's uplink "
                           f"onto this port on the canvas first")
        return net

    def _admin_up(self, ctx: str) -> bool:
        return not router_shut(self.lab, ctx)

    def _l3_done(self) -> str:
        refresh_routed(self.lab)
        return self._save().strip()

    def _encap(self, a):
        tag = self._tag(a[0])
        base = self.s.ctx.split(".")[0]
        sw = self._port_switch(base)
        if not sw:
            raise CliError(f"% {short_if(base)} has no cable in it: drag a switch's uplink onto this port first")
        if upstream(self.lab, sw):
            raise CliError(f"% {hostname(self.lab, 'sw:' + sw)}'s uplink is in another switch")
        net = vlan_net(self.lab, sw, tag)
        own = settings(self.lab, ROUTER)
        own[f"dot1q:{self.s.ctx}"] = str(tag)
        if net is None:
            # The router tags frames for any VLAN; the switch drops a VLAN it
            # does not have, so nothing answers until it is made there.
            own.pop(f"sub:{self.s.ctx}", None)
            own.pop(f"ip:{self.s.ctx}", None)
            return self._l3_done()
        for k in [k for k, v in own.items() if k.startswith("sub:") and v == net.id and k != f"sub:{self.s.ctx}"]:
            own.pop("ip:" + k[4:], None)
            del own[k]
        if own.get(f"sub:{self.s.ctx}") != net.id:
            own.pop(f"ip:{self.s.ctx}", None)
        own[f"sub:{self.s.ctx}"] = net.id
        return self._l3_done()

    def _no_interface(self, a):
        from . import routerpolicy  # no interface Tunnel<n> (winlab/vti.py)
        if routerpolicy.is_tunnel(a[0]):
            return routerpolicy.no_tunnel(self, a[0])
        from . import iosmpls  # no interface Loopback<n>
        if iosmpls.loopback_name(a[0]):
            return iosmpls.no_loopback(self, a[0])
        ctx = parse_if(a[0], self._if_names(), sub=True)
        if "." not in ctx:
            raise CliError("% Physical interfaces cannot be removed")
        own = settings(self.lab, ROUTER)
        for k in (f"sub:{ctx}", f"ip:{ctx}", f"shut:{ctx}", f"desc:{ctx}", f"dot1q:{ctx}"):
            own.pop(k, None)
        from . import iosl3  # what else was on it: ACLs, NAT
        iosl3.forget_iface(own, ctx)
        return self._l3_done()

    def _port_link(self):
        """The machine port plugged into the switch port being configured."""
        m = re.match(r"^FastEthernet0/(\d+)$", self.s.ctx)
        if not m:
            return None
        ports = switch_ports(self.lab, self.plan).get(switch_id(self.device), [])
        i = int(m.group(1)) - 1
        return ports[i] if i < len(ports) else None

    def _ap_here(self) -> str:
        """The AP plugged into the switch port being configured ("" if none)."""
        m = re.match(r"^FastEthernet0/(\d+)$", self.s.ctx)
        if not m:
            return ""
        return ap_slots(self.lab, self.plan, switch_id(self.device), self._ports()).get(int(m.group(1)), "")

    def _description(self, a):
        if self.device == ROUTER:
            settings(self.lab, ROUTER)[f"desc:{self.s.ctx}"] = a[0][:120]
            self._save(live=False)
            return
        link = self._port_link()
        key = f"desc:{link.label}" if link else f"desc:{self.s.ctx}"
        settings(self.lab, self.device)[key] = a[0][:120]
        self._save(live=False)

    def _no_description(self, a):
        if self.device == ROUTER:
            settings(self.lab, ROUTER).pop(f"desc:{self.s.ctx}", None)
        else:
            link = self._port_link()
            settings(self.lab, self.device).pop(f"desc:{link.label}" if link else f"desc:{self.s.ctx}", None)
        self._save(live=False)

    def _shutdown(self, down: bool):
        name = self.s.ctx
        if self.device == ROUTER:
            return self._router_shutdown(name, down)
        if name.startswith("Vlan"):
            return self._svi_shutdown(name, down)
        if name.startswith("GigabitEthernet"):
            from . import stp  # a switch-to-switch cable's link, and err-disabled ports coming back
            return stp.gi_shutdown(self, name, down)
        link = self._port_link()
        if link is None:
            raise CliError(f"% nothing is plugged into {name}")
        key = f"shut:{link.label}"
        if down:
            settings(self.lab, self.device)[key] = "yes"
        else:
            settings(self.lab, self.device).pop(key, None)
        self._save(live=False)
        self._set_link(link, not down)
        if down:
            return f"%LINK-5-CHANGED: Interface {name}, changed state to administratively down"
        from . import portsec  # no shutdown is what brings an err-disabled port back
        return (f"%LINK-5-CHANGED: Interface {name}, changed state to up\n"
                f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to up"
                + portsec.on_shutdown(self, link))

    def _router_shutdown(self, name: str, down: bool) -> str:
        own = settings(self.lab, ROUTER)
        if router_shut(self.lab, name) == down and bool(own.get(f"shut:{name}")) == down:
            return ""
        if down:
            own[f"shut:{name}"] = "yes"
        else:
            own.pop(f"shut:{name}", None)
        note = self._l3_done()
        note = f"\n{note}" if note else ""
        if down:
            return (f"%LINK-5-CHANGED: Interface {name}, changed state to administratively down\n"
                    f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to down{note}")
        if router_shut(self.lab, name):
            return note.strip()
        if iface_net(self.lab, name) is None or not self.powered():
            return f"%LINK-3-UPDOWN: Interface {name}, changed state to down{note}"
        return (f"%LINK-3-UPDOWN: Interface {name}, changed state to up\n"
                f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to up{note}")

    def _speed_duplex(self, what: str, a):
        """speed 10 | 100 | auto, duplex half | full | auto on a switch port
        (winlab/iosl2.py): a speed set is the port's rate on the router; a
        duplex set against a card that negotiates is a duplex mismatch, with
        the late collisions and errors one has. auto negotiates again, which
        also mends the duplex mismatch of a hidden fault (winlab/physfaults.py)."""
        from . import physfaults
        value = a[0].strip().lower()
        allowed = {"speed": ("10", "100", "auto"), "duplex": ("half", "full", "auto")}[what]
        if value not in allowed or (self.s.ctx.startswith("Vlan")):
            raise CliError("% Invalid input detected at '^' marker.")
        link = self._port_link()
        if link is None:
            if self.s.ctx.startswith("GigabitEthernet"):
                return "" if value == "auto" else f"% {what} {value} is not supported on a trunk to a switch here"
            raise CliError(f"% nothing is plugged into {self.s.ctx}")
        own = settings(self.lab, self.device)
        key = f"{what}:{link.label}"
        if value == "auto":
            own.pop(key, None)
        else:
            own[key] = value
        if value == "auto" and what == "duplex":
            physfaults.port_auto(self.lab, link)
        note = self._save().strip()
        return (f"%LINK-3-UPDOWN: Interface {self.s.ctx}, changed state to down\n"
                f"%LINK-3-UPDOWN: Interface {self.s.ctx}, changed state to up" + (f"\n{note}" if note else ""))

    def _svi_shutdown(self, name: str, down: bool) -> str:
        own = settings(self.lab, self.device)
        if down:
            own.pop(f"up:{name}", None)
        else:
            own[f"up:{name}"] = "yes"
        note = self._save().strip()
        if down:
            return (f"%LINK-5-CHANGED: Interface {name}, changed state to administratively down\n"
                    f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to down"
                    + (f"\n{note}" if note else ""))
        tag = int(name[4:])
        live = vlan_net(self.lab, switch_id(self.device), tag) is not None and self.powered()
        return (f"%LINK-3-UPDOWN: Interface {name}, changed state to up\n"
                f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to "
                f"{'up' if live else 'down'}" + (f"\n{note}" if note else ""))

    def _sw_ip(self, a):
        """ip address on a switch's VLAN interface: its management address,
        a real one (winlab/iosl2.py: a port of its own in that VLAN on the
        router, in a namespace of its own, so it answers ping and ARP)."""
        if not self.s.ctx.startswith("Vlan"):
            raise CliError("% IP addresses may not be configured on L2 links.")
        own = settings(self.lab, self.device)
        tag = int(self.s.ctx[4:])
        if not a:
            own.pop(f"svi:{tag}", None)
            return self._save().strip()
        iface = to_iface(a[0], a[1])
        if iface.ip in (iface.network.network_address, iface.network.broadcast_address) \
                or iface.network.prefixlen > 30:
            raise CliError(f"% Bad mask /{iface.network.prefixlen} for address {iface.ip}")
        for k in [k for k in own if k.startswith("svi:") and k != f"svi:{tag}"]:
            if own[k].split("/")[0] == str(iface.ip):
                raise CliError(f"% {iface.ip} overlaps with Vlan{k[4:]}")
        own[f"svi:{tag}"] = str(iface)
        return self._save().strip()

    def _sw_gateway(self, a):
        own = settings(self.lab, self.device)
        if a:
            own["default-gw"] = self._target(a[0])
        else:
            own.pop("default-gw", None)
        return self._save().strip()

    def svis(self) -> list[tuple[str, str, bool]]:
        """(Vlan<n>, address/len or "", administratively up) per VLAN
        interface the switch has: Vlan1 always, others once typed."""
        own = self.lab.devices.get(self.device, {})
        tags = {1} | {int(k[4:]) for k in own if k.startswith("svi:")} \
            | {int(k[7:]) for k in own if k.startswith("up:Vlan")}
        return [(f"Vlan{t}", own.get(f"svi:{t}", ""), bool(own.get(f"up:Vlan{t}"))) for t in sorted(tags)]

    def _set_link(self, link, up: bool) -> None:
        from . import physfaults
        if up and any(physfaults.card_side(r["kind"]) for r in physfaults.active(self.lab.name, link=link.label)):
            return  # a dead card stays dead, whatever the switch port does
        if self._link is not None:
            self._link(link, up)
            return
        st = state.load(self.lab.name)
        ns = st.nodes.get(link.node_id) if st else None
        if ns and ns.qmp_port and ns.pid and state.pid_alive(ns.pid):
            from . import livenet
            livenet.set_link(ns.qmp_port, link.nic_index, up)

    def _ip_address(self, a):
        net = self._router_net()
        iface = to_iface(a[0], a[1])
        if iface.network.prefixlen > 30 or iface.ip in (iface.network.network_address,
                                                        iface.network.broadcast_address):
            raise CliError("% Bad mask /%d for address %s" % (iface.network.prefixlen, iface.ip))
        own = settings(self.lab, ROUTER)
        for other in self.lab.networks.values():
            if other.id != net.id and other.net.overlaps(iface.network) \
                    and not same_vlan_down_trunk(self.lab, net, other):
                raise CliError(f"% {iface.network} overlaps with {self.iface_of(other) or other.id}")
        renumber = str(iface.network) != str(net.net)
        if renumber:
            for m in self.lab.nodes_on(net.id):
                if m.vars.get("devvm") == "ap":
                    continue  # an AP takes a new address with the subnet, as its DHCP lease would
                for n in m.nics:
                    if n.network == net.id and n.ip:
                        raise CliError(f"% {naming.display(self.lab, m.id)} has {n.ip} on this switch: "
                                       f"change it or unplug it first")
        net.cidr = str(iface.network)
        first = str(next(iface.network.hosts()))
        net.gateway = None if str(iface.ip) == first else str(iface.ip)
        own[f"ip:{self.s.ctx}"] = net.id
        if renumber:
            from . import wifi
            for ap_id, ap in wifi.aps(self.lab).items():
                if ap.get("network") == net.id:
                    wifi._address(self.lab, self.lab.devices[wifi.PREFIX + ap_id], net.id)
            wifi.vm_nodes(self.lab)
        return self._l3_done()

    def _no_ip_address(self, a):
        settings(self.lab, ROUTER).pop(f"ip:{self.s.ctx}", None)
        return self._l3_done()

    def _tag(self, text: str) -> int:
        try:
            tag = int(text)
        except ValueError:
            raise CliError("% Bad VLAN list") from None
        if not 1 <= tag <= 4094:
            raise CliError("% Bad VLAN list - character #1 is not in range 1-4094")
        return tag

    # ---- DHCP pools (winlab/netplan.py hands out what is typed here)
    def _pool_net(self, name: str):
        nid = settings(self.lab, ROUTER).get(f"pool:{name}", "")
        return self.lab.networks.get(nid)

    def _pool(self, a):
        own = settings(self.lab, ROUTER)
        if f"pool:{a[0]}" not in own and f"poolnet:{a[0]}" not in own:
            own[f"poolnet:{a[0]}"] = ""
            self._save(live=False)
        self.s.mode, self.s.ctx = "dhcp-config", a[0]

    def _no_pool(self, a):
        own = settings(self.lab, ROUTER)
        net = self._pool_net(a[0])
        if net is not None and not any(k.startswith("pool:") and v == net.id and k != f"pool:{a[0]}"
                                       for k, v in own.items()):
            net.dhcp = False
        found = False
        for k in [k for k in own if k.split(":", 1)[0] in POOL_KEYS and k.split(":", 1)[1] == a[0]]:
            del own[k]
            found = True
        if not found:
            raise CliError(f"%DHCP pool {a[0]} not found")
        return self._l3_done()

    def _pool_network(self, a):
        want = to_iface(a[0], a[1]).network
        own = settings(self.lab, ROUTER)
        for k, v in list(own.items()):
            if k.startswith("pool:") and k != f"pool:{self.s.ctx}" and v and v in self.lab.networks \
                    and self.lab.networks[v].net == want:
                raise CliError(f"% {want} is already in pool {k[5:]}")
        own.pop(f"pool:{self.s.ctx}", None)
        own[f"poolnet:{self.s.ctx}"] = str(want)
        # The pool serves the network of the router's interface in that
        # subnet; with none there, it waits (as on IOS) and hands out nothing.
        for net in self.lab.networks.values():
            if net.net == want:
                own[f"pool:{self.s.ctx}"] = net.id
                break
        return self._l3_done()

    def _pool_opt(self, key: str, value: str):
        own = settings(self.lab, ROUTER)
        if value:
            own[f"{key}:{self.s.ctx}"] = value
        else:
            own.pop(f"{key}:{self.s.ctx}", None)
        return self._save().strip()

    def _addrs(self, text: str, most: int = 8) -> list[str]:
        out = [self._target(t) for t in text.split()]
        if not out or len(out) > most:
            raise CliError("% Invalid input detected at '^' marker.")
        return out

    def _pool_gateway(self, a):
        return self._pool_opt("poolgw", " ".join(self._addrs(a[0])))

    def _pool_dns(self, a):
        return self._pool_opt("pooldns", " ".join(self._addrs(a[0])))

    def _pool_lease(self, a):
        w = a[0].split()
        if w == ["infinite"]:
            return self._pool_opt("poollease", "infinite")
        if not w or len(w) > 3 or not all(x.isdigit() for x in w):
            raise CliError("% Invalid input detected at '^' marker.")
        d, h, m = (list(map(int, w)) + [0, 0])[:3]
        if not (0 <= d <= 365 and 0 <= h <= 23 and 0 <= m <= 59) or d == h == m == 0:
            raise CliError("% Invalid input detected at '^' marker.")
        return self._pool_opt("poollease", f"{d} {h} {m}")

    def _excluded(self, lo: str, hi: str, on: bool):
        a, b = ipaddress.IPv4Address(self._target(lo)), ipaddress.IPv4Address(self._target(hi))
        if b < a:
            raise CliError("% Invalid input detected at '^' marker.")
        own = settings(self.lab, ROUTER)
        if on:
            own[f"dhcp-excl:{a}"] = str(b)
        elif own.pop(f"dhcp-excl:{a}", None) is None:
            raise CliError("% Range not found")
        return self._save().strip()

    # PXE: what the router's DHCP tells a machine booting from the network
    # (DHCP next-server/siaddr and options 66/67, file name and server)
    def _boot_net(self):
        net = self._pool_net(self.s.ctx)
        if net is None:
            raise CliError("% Give the pool its network first")
        return net

    def _next_server(self, a):
        net = self._boot_net()
        settings(self.lab, ROUTER)[f"next:{net.id}"] = self._target(a[0])
        return self._save().strip()

    def _bootfile(self, a):
        net = self._boot_net()
        name = a[0].strip()
        if not BOOTFILE_RE.match(name):
            raise CliError("% A boot file is a path such as boot\\x64\\wdsnbp.com or pxelinux.0")
        settings(self.lab, ROUTER)[f"file:{net.id}"] = name
        return self._save().strip()

    def _boot_clear(self, what: str):
        net = self._boot_net()
        settings(self.lab, ROUTER).pop(f"{what}:{net.id}", None)
        return self._save().strip()

    # ip helper-address: DHCP broadcasts arriving on this interface are relayed
    # to the address too, a WDS server for PXE (winlab/imaging.py)
    def _helper(self, a):
        net = self._router_net()
        imaging.set_helper(self.lab, net.id, self._target(a[0]))
        return self._save().strip()

    def _no_helper(self, addr: str):
        net = self._router_net()
        imaging.set_helper(self.lab, net.id, self._target(addr) if addr else "", on=False)
        return self._save().strip()

    # ---- a switch's VLANs
    def _make_vlan(self, tag: int):
        sw = switch_id(self.device)
        net = vlan_net(self.lab, sw, tag)
        if net is not None:
            return net, False
        nid, k = f"{sw}-v{tag}", 1
        while nid in self.lab.networks:
            k += 1
            nid = f"{sw}-v{tag}-{k}"
        net = editor.add_network(self.lab, nid, cidr=editor.next_free_subnet(self.lab, base="192.168.0.0/16"))
        net.routed, net.switch, net.tag = False, sw, tag
        refresh_trunks(self.lab, sw)  # a trunk that allows every VLAN carries the new one
        return net, True

    def _vlan(self, a):
        tag = self._tag(a[0])
        if tag != 1:
            _, made = self._make_vlan(tag)
            if made:
                self._save()
        self.s.mode, self.s.ctx = "config-vlan", str(tag)

    def _vlan_name(self, a):
        tag = int(self.s.ctx)
        if tag == 1:
            raise CliError("% Default VLAN 1 may not have its name changed.")
        net = vlan_net(self.lab, switch_id(self.device), tag)
        net.description = a[0][:32]
        self._save(live=False)

    def _no_vlan(self, a):
        tag = self._tag(a[0])
        if tag == 1:
            raise CliError("% Default VLAN 1 may not be deleted.")
        sw = switch_id(self.device)
        net = vlan_net(self.lab, sw, tag)
        if net is None:
            raise CliError(f"% VLAN {tag} does not exist")
        ports = switch_ports(self.lab, self.plan).get(sw, [])
        inside = [f"Fa0/{i}" for i, l in enumerate(ports, 1) if l is not None and l.network_id == net.id]
        if inside:
            raise CliError(f"% {', '.join(inside)} {'is' if len(inside) == 1 else 'are'} in VLAN {tag}: "
                           f"move {'it' if len(inside) == 1 else 'them'} first (switchport access vlan)")
        own = settings(self.lab, ROUTER)
        for k in [k for k, v in own.items() if k.startswith(("sub:", "pool:", "ip:")) and v == net.id]:
            del own[k]
        net.routed = net.dhcp = False
        for node in self.lab.node_list():
            for nic in node.nics:
                if net.id in nic.trunk:
                    nic.trunk.remove(net.id)
        editor.remove_network(self.lab, net.id)
        return self._save().strip()

    def _access_vlan(self, a):
        tag = self._tag(a[0]) if a else 1
        if self.s.ctx.startswith("GigabitEthernet"):
            raise CliError(f"% {short_if(self.s.ctx)} is a trunk to another switch or the router: "
                           f"it carries every VLAN")
        link = self._port_link()
        ap = self._ap_here() if link is None else ""
        if link is None and not ap:
            raise CliError(f"% nothing is plugged into {self.s.ctx}: cable a machine to it on the canvas first")
        note = ""
        if tag == 1:
            net = self.lab.networks[switch_id(self.device)]
        else:
            net, made = self._make_vlan(tag)
            if made:
                note = f"% Access VLAN does not exist. Creating vlan {tag}"
        if ap:
            if self._wifi().aps(self.lab)[ap]["network"] != net.id:
                self._wifi().set_ap(self.lab, ap, network=net.id)  # the AP's own cable, kept in its table
                note = (note + self._save()).strip()
            return note
        if link.network_id != net.id:
            from . import netbasics  # back where a ticket moved it from: its own address again
            editor.cable(self.lab, link.node_id, link.nic_index, net.id,
                         ip=netbasics.home_ip(self.lab, link.node_id, link.nic_index, net.id))
            note = (note + self._save()).strip()
        return note

    def _no_access_vlan(self, a):
        return self._access_vlan([])

    def _switchport_mode(self, a):
        mode = a[0].strip().lower().split()
        word = mode[0] if mode else ""
        uplink = self.s.ctx.startswith("GigabitEthernet")
        if not uplink and word and any(m.startswith(word) for m in ("access", "trunk", "dynamic")):
            from . import l2sec  # no longer a private-VLAN port
            l2sec.leave(self)
        if word and "trunk".startswith(word):
            if uplink:
                return ""
            link = self._port_link()
            if link is None:
                raise CliError(f"% nothing is plugged into {self.s.ctx}")
            settings(self.lab, self.device)[f"mode:{link.label}"] = "trunk"
            return self._trunk_note(refresh_trunks(self.lab, switch_id(self.device)))
        if word and ("access".startswith(word) or "dynamic".startswith(word)):
            if uplink:
                raise CliError("% A gigabit port here is a cable to a switch or the router: it stays a trunk")
            link = self._port_link()
            if link is None:
                return ""
            settings(self.lab, self.device).pop(f"mode:{link.label}", None)
            nic = self.lab.nodes[link.node_id].nics[link.nic_index]
            from . import lldp  # an access port keeps its voice VLAN tagged
            keep = lldp.voice_trunk(self.lab, switch_id(self.device), link.label)
            if nic.trunk != keep:
                nic.trunk = keep
                return self._save().strip()
            self._save(live=False)
            return ""
        raise CliError("% Invalid input detected at '^' marker.")

    def _trunk_note(self, left: list[int]) -> str:
        note = self._save().strip()
        if left:
            note = (f"% VLAN {vlan_text(set(left))} not carried: that number is another network's VLAN id "
                    f"on the router here" + (f"\n{note}" if note else ""))
        return note

    def _trunk_key(self) -> str:
        """The settings key of the port being configured: a gigabit port by
        its name, a machine's port by its cable."""
        if self.s.ctx.startswith("GigabitEthernet"):
            return self.s.ctx
        link = self._port_link()
        if link is None:
            raise CliError(f"% nothing is plugged into {self.s.ctx}")
        return link.label

    def _trunk_allowed(self, a):
        key = self._trunk_key()
        own = settings(self.lab, self.device)
        have = vlan_set(own.get(f"allowed:{key}", "all"))
        try:
            want = edit_vlans(have, a[0])
        except ValueError:
            raise CliError("% Invalid input detected at '^' marker.") from None
        if want is None:
            own.pop(f"allowed:{key}", None)
        else:
            own[f"allowed:{key}"] = vlan_text(want) or "none"
        return self._trunk_note(refresh_trunks(self.lab, switch_id(self.device)))

    def _trunk_native(self, a):
        tag = self._tag(a[0])
        key = self._trunk_key()
        own = settings(self.lab, self.device)
        if key.startswith("GigabitEthernet"):
            if tag == 1:
                own.pop(f"native:{key}", None)
            else:
                own[f"native:{key}"] = str(tag)
            from . import netbasics  # CDP's word on a trunk whose two ends disagree
            netbasics.native_log(self.lab)
            return self._save().strip()
        # A machine's trunk: its native VLAN is the one its untagged frames are in.
        net = vlan_net(self.lab, switch_id(self.device), tag)
        if net is None:
            net, _ = self._make_vlan(tag)
        link = self._port_link()
        if link.network_id != net.id:
            editor.cable(self.lab, link.node_id, link.nic_index, net.id)
        refresh_trunks(self.lab, switch_id(self.device))
        return self._save().strip()

    def _port_key(self, what: str, value: str):
        key = f"{what}:{self._trunk_key()}"
        own = settings(self.lab, self.device)
        if value:
            own[key] = value
        else:
            own.pop(key, None)
        self._save(live=False)

    # ---- show
    def _show_version(self, a):
        """A version block in IOS's shape, in winlab's own words (the hardware
        lines as IOS prints them: what Netmiko, NAPALM and Ansible read)."""
        from . import netauto
        kind = device_kind(self.device)
        host = ios_name(self.lab, self.device)
        if kind == ROUTER:
            nim = len(router_port_names(self.lab)) > len(ONBOARD)
            hw = [f"cisco {MODEL[ROUTER]} (1RU) processor with 1795999K/6147K bytes of memory.",
                  f"Processor board ID {netauto.serial(self.lab, self.device)}",
                  f"{len(router_port_names(self.lab))} Gigabit Ethernet interfaces"
                  + (" (2 on board, 8 on a NIM in subslot 0/1)" if nim else ""),
                  "32768K bytes of non-volatile configuration memory.",
                  "3207167K bytes of physical memory.", ""]
        else:
            from . import poe  # the switch's model: a PoE one when one was fitted
            model = poe.model_name(self.lab, switch_id(self.device))
            hw = [f"cisco {model} (PowerPC405) processor (revision B0) with 65536K bytes of memory.",
                  f"Processor board ID {netauto.serial(self.lab, self.device)}",
                  f"{SWITCH_PORTS} FastEthernet interfaces", f"{GIG_PORTS} Gigabit Ethernet interfaces",
                  "64K bytes of flash-simulated non-volatile configuration memory.",
                  f"Base ethernet MAC Address       : {self._sw_mac()}",
                  f"Model number                    : {model}", ""]
        from . import iosboot  # the image that runs and the configuration register
        boot = iosboot.version_lines(self)
        hw.append(boot["register"])
        image = boot["image"]
        return "\n".join([
            "winlab Internetwork Operating System Software",
            f"{MODEL[kind]} Software, Version {boot['version']}, RELEASE SOFTWARE",
            "This device is part of a winlab lab: its software is winlab's, running on the lab router",
            "(Alpine Linux, no disk, no way out to this PC or the internet).", "",
            f"ROM: Bootstrap program is {'IOS-XE ROMMON' if kind == ROUTER else 'C2960 boot loader'}", "",
            f"{host} uptime is {self._uptime()}",
            "System returned to ROM by reload",
            f'System image file is "{image}"', "",
            ] + hw)

    def _uptime(self) -> str:
        try:
            secs = int(float(self._on_router("cut -d' ' -f1 /proc/uptime", timeout=10).split()[0]))
        except (CliError, ValueError, IndexError):
            return "unknown"
        d, rest = divmod(secs, 86400)
        h, m = divmod(rest // 60, 60)
        return (f"{d} days, " if d else "") + f"{h} hours, {m} minutes"

    def _show_clock(self, a):
        from . import nms  # the router's own clock; '*' until NTP has it in sync
        return nms.show_clock(self)

    def _show_history(self, a):
        return "\n".join(f"  {h}" for h in self.s.history[-20:])

    def _show_run(self, a):
        from . import iosl3, iosnv, nms
        from . import iosrouting  # VRFs, OSPF, BGP, VRRP
        lab = self.lab
        own = lab.devices.get(self.device, {})
        enc = bool(own.get("service-pwenc"))
        out = ["!", "version 15.2"]
        out += [l for l in nms.run_lines(lab, self.device) if l.startswith(("service timestamps", "no service timestamps"))]
        out += ["service password-encryption"] if enc else ["no service password-encryption"]
        out += ["!", f"hostname {ios_name(lab, self.device)}", "!", "boot-start-marker"]
        from . import iosboot, iosimage
        out += iosimage.boot_lines(lab, self.device) + ["boot-end-marker", "!"]
        if own.get("enable-secret"):
            out.append(f"enable secret {iosnv.run_form(own['enable-secret'], enc)}")
        if own.get("enable-password"):
            out.append(f"enable password {iosnv.run_form(own['enable-password'], enc)}")
        out += ["!", "no aaa new-model"]
        if self.device == ROUTER:
            excl = sorted(((k[10:], v) for k, v in own.items() if k.startswith("dhcp-excl:")),
                          key=lambda r: int(ipaddress.IPv4Address(r[0])))
            if excl:
                out.append("!")
                out += [f"ip dhcp excluded-address {lo}" + (f" {hi}" if hi != lo else "") for lo, hi in excl]
            for name, net, subnet in self.pools():
                out += ["!", f"ip dhcp pool {name}"]
                if subnet:
                    sub = ipaddress.IPv4Network(subnet)
                    out.append(f" network {sub.network_address} {mask_of(sub.prefixlen)}")
                gw = own.get(f"poolgw:{name}") or ("" if lab.workbench or net is None else net.default_gateway)
                out += [f" default-router {gw}"] if gw else []
                dns = own.get(f"pooldns:{name}")
                out += [f" dns-server {dns}"] if dns else []
                dom = own.get(f"pooldom:{name}")
                out += [f" domain-name {dom}"] if dom else []
                lease = own.get(f"poollease:{name}")
                if lease:
                    d, h, m = (lease.split() + ["0", "0"])[:3] if lease != "infinite" else ("infinite", "", "")
                    out.append(" lease " + (" ".join(x for x in (d, h if (h != "0" or m != "0") else "",
                                                                 m if m != "0" else "") if x)))
                if net is not None:
                    out += [f" next-server {own[f'next:{net.id}']}"] if own.get(f"next:{net.id}") else []
                    out += [f" bootfile {own[f'file:{net.id}']}"] if own.get(f"file:{net.id}") else []
            out.append("!")
            users = sorted((k[5:], v) for k, v in own.items() if k.startswith("user:"))
            for name, kept in users:
                priv, _, pw = kept.partition(" ")
                word = "secret" if pw.startswith("9 ") else "password"
                out.append(f"username {name}" + (f" privilege {priv}" if priv != "1" else "")
                           + f" {word} {iosnv.run_form(pw, enc)}")
            out += ["!"] if users else []
            out += iosrouting.vrf_lines(own)

            from . import routerpolicy  # class-maps, policy-maps, zones, crypto (winlab/routerpolicy.py)
            out += routerpolicy.global_lines(own)
            from . import iosv6  # ipv6 unicast-routing, the interfaces' ipv6 lines, ipv6 route, ipv6 router ospf
            out += iosv6.global_lines(own)
            from . import iosmpls  # interface Loopback<n> prints first, as IOS orders interfaces
            out += iosmpls.loopback_blocks(own)
            for name, net, up in self.router_ifaces():
                out.append(f"interface {name}")
                if own.get(f"desc:{name}"):
                    out.append(f" description {own[f'desc:{name}']}")
                if "." in name:
                    bound = lab.networks.get(own.get(f"sub:{name}", ""))
                    tag = own.get(f"dot1q:{name}") or (str(bound.vlan_no) if bound is not None else "")
                    if tag:
                        out.append(f" encapsulation dot1Q {tag}")
                out += iosrouting.iface_pre(own, name)
                if net is not None:
                    out.append(f" ip address {net.router_ip} {mask_of(net.net.prefixlen)}")
                    out += [f" ip helper-address {h}" for h in imaging.helpers(lab, net.id)]
                else:
                    out.append(" no ip address")
                for way in ("in", "out"):
                    if own.get(f"acl-{way}:{name}"):
                        out.append(f" ip access-group {own[f'acl-{way}:{name}']} {way}")
                if own.get(f"nat:{name}"):
                    out.append(f" ip nat {own[f'nat:{name}']}")
                out += iosrouting.iface_lines(own, name)
                out += iosv6.iface_lines(own, name)
                from . import acl6  # ipv6 traffic-filter
                out += acl6.iface_lines(own, name)

                out += routerpolicy.iface_lines(own, name)
                if not up:
                    out.append(" shutdown")
                if "." not in name:
                    out.append(" negotiation auto")
                out.append("!")
            out += iosrouting.run_lines(self)

            out += routerpolicy.tunnel_blocks(own)
            out += iosl3.run_lines(own)
            from . import iossla  # track objects and ip sla operations
            out += iossla.run_lines(own)
            out += iosv6.run_lines(own)
            from . import acl6  # ipv6 access-list blocks
            out += acl6.run_lines(own)
        else:
            from . import stp  # spanning tree lines, and the spare cables' ports
            from . import portsec
            sid = switch_id(self.device)
            out += stp.run_lines(lab, sid)
            out += portsec.run_lines(lab, sid)
            for net in vlans_of(lab, sid)[1:]:
                out += [f"vlan {net.vlan_no}"] + ([f" name {net.description}"] if net.description else []) + ["!"]
            ports = switch_ports(lab, self.plan).get(sid, [])
            for i in range(1, SWITCH_PORTS + 1):
                link = ports[i - 1] if i <= len(ports) else None
                out.append(f"interface FastEthernet0/{i}")
                desc = own.get(f"desc:{link.label}") if link else own.get(f"desc:FastEthernet0/{i}")
                if desc:
                    out.append(f" description {desc}")
                nic = lab.nodes[link.node_id].nics[link.nic_index] if link else None
                tag = lab.networks[link.network_id].vlan_no if link else 1
                if nic is not None and nic.trunk and not own.get(f"voice:{link.label}"):
                    if tag != 1:
                        out.append(f" switchport trunk native vlan {tag}")
                    allow = allowed_tags(lab, sid, link.label)
                    if allow is not None:
                        out.append(f" switchport trunk allowed vlan {vlan_text(allow) or 'none'}")
                    out.append(" switchport mode trunk")
                elif tag != 1:
                    out += [f" switchport access vlan {tag}", " switchport mode access"]
                if link and own.get(f"shut:{link.label}"):
                    out.append(" shutdown")
                for what in ("speed", "duplex"):
                    if link and own.get(f"{what}:{link.label}"):
                        out.append(f" {what} {own[f'{what}:{link.label}']}")
                out += stp.iface_lines(lab, sid, link.label if link else f"FastEthernet0/{i}", False)
                out += portsec.iface_lines(lab, sid, portsec.conf_key(own, link.label, i) if link else f"FastEthernet0/{i}")
                out.append("!")
            up = upstream(lab, sid)
            for port in gig_names():
                out.append(f"interface {port}")
                if own.get(f"desc:{port}"):   # one typed under the port wins over winlab's own
                    out.append(f" description {own[f'desc:{port}']}")
                elif port == "GigabitEthernet0/1":
                    out += ([f" description uplink to {hostname(lab, f'sw:{up}')}"] if up else
                            [" description uplink to the router"] if uplinked(lab, sid) else [])
                else:
                    far = dict(downlinks(lab, sid) + sorted(stp.spare_ports(lab, sid).items())).get(port)
                    out += [f" description to {hostname(lab, f'sw:{far}')}"] if far else []
                if own.get(f"native:{port}"):
                    out.append(f" switchport trunk native vlan {own[f'native:{port}']}")
                allow = allowed_tags(lab, sid, port)
                if allow is not None:
                    out.append(f" switchport trunk allowed vlan {vlan_text(allow) or 'none'}")
                out.append(" switchport mode trunk")
                if own.get(f"noneg:{port}"):
                    out.append(" switchport nonegotiate")
                out += stp.iface_lines(lab, sid, port, True)
                out.append("!")
            for vname, addr, upv in self.svis():
                out.append(f"interface {vname}")
                if addr:
                    ip = ipaddress.IPv4Interface(addr)
                    out.append(f" ip address {ip.ip} {ip.netmask}")
                else:
                    out.append(" no ip address")
                from . import iosv6
                out += iosv6.sw_iface_lines(own, int(vname[4:]))
                if not upv:
                    out.append(" shutdown")
                out.append("!")
            if own.get("default-gw"):
                out += [f"ip default-gateway {own['default-gw']}", "!"]
        out += [l for l in nms.run_lines(lab, self.device)
                if not l.startswith(("service timestamps", "no service timestamps"))]
        from . import ftpscp
        ftp = ftpscp.run_lines(lab, self.device)
        out += ftp + (["!"] if ftp else [])
        if own.get("banner"):
            out += [f"banner motd ^C{own['banner']}^C", "!"]
        for line, label in (("con", "line con 0"), ("vty", "line vty 0 4")):
            out.append(label)
            if own.get(f"line-{line}:exec-timeout"):
                out.append(f" exec-timeout {own[f'line-{line}:exec-timeout']}")
            if own.get(f"line-{line}:password"):
                out.append(f" password {iosnv.run_form(own[f'line-{line}:password'], enc)}")
            if own.get(f"line-{line}:logging-sync"):
                out.append(" logging synchronous")
            how = own.get(f"line-{line}:login")
            if how:
                out.append(" login local" if how == "local" else " login")
            elif line == "vty":
                out.append(" login")
            if own.get(f"line-{line}:transport"):
                out.append(f" transport input {own[f'line-{line}:transport']}")
        out += ["!"] + iosboot.run_lines(lab, self.device) + ["end"]
        from . import iosssh, lldp  # domain name, SSH, local users; channel groups, port-channels, SPAN; CDP, LLDP
        out = iosssh.run_lines(self, lldp.run_lines(self, out))
        if self.device != ROUTER:
            from . import poe  # power inline under each interface
            out = poe.run_lines(self, out)
            from . import l2sec  # private VLANs, storm control, RA and DHCPv6 guard, IPv6 lists
            out = l2sec.run_lines(self, out)
        body = "\n".join(out)
        return f"Building configuration...\n\nCurrent configuration : {len(body)} bytes\n{body}"

    def _live(self) -> dict:
        reader = getattr(self.dash, "wb_live", None)
        if reader is None:
            return {"ips": {}, "seen": [], "ok": False}
        return reader.read(self.lab, self._runner_factory)

    def _show_ip_brief(self, a):
        rows = [f"{'Interface':<23}{'IP-Address':<16}{'OK?':<4}{'Method':<7}{'Status':<22}Protocol"]
        for name, net, up in self.router_ifaces():
            ip, how = (net.router_ip, "manual") if net is not None else ("unassigned", "unset")
            status, proto = self._router_status(name, up)
            rows.append(f"{name:<23}{ip:<16}{'YES':<4}{how:<7}{status:<22}{proto}")
        from . import routerpolicy  # interface Tunnel<n>
        rows += routerpolicy.brief_rows(self)
        from . import iosmpls  # interface Loopback<n>
        rows += iosmpls.brief_rows(self)
        return "\n".join(rows)

    def _show_interfaces(self, a):
        return "\n".join(self._router_block(name, net, up) for name, net, up in self.router_ifaces())

    def _show_route(self, a):
        """The routing table: connected networks of the interfaces that are
        up, and the static routes whose next hop is reachable."""
        from . import iosl3, iosrouting
        if iosrouting.active(self.lab):  # VRFs, and the routes OSPF and BGP learned
            return iosrouting.show_route(self, "")
        own = self.lab.devices.get(ROUTER, {})
        conn = []
        for name, net, up in self.router_ifaces():
            if net is not None and net.routed and self._router_status(name, up)[0] == "up":
                conn.append((net.net, name, net.router_ip))
        from . import routerpolicy  # interface Tunnel<n>
        conn += routerpolicy.connected(self)
        stat = []
        from . import iossla  # ip route ... track <n>: out of the table while the object is Down
        hidden = iossla.hidden_routes(self)
        for dest, target, dist in iosl3.routes(own):
            if f"{dest} {target}" in hidden:
                continue
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
                if any(ipaddress.IPv4Address(target) in n for n, _, _ in conn):
                    stat.append((dest, dist, f"[{dist}/0] via {target}"))
            elif any(nm == target for _, nm, _ in conn):
                stat.append((dest, dist, f"is directly connected, {target}"))
        stat = [(d, how) for d, _, how in iosl3.best(stat)]
        default = next((v for d, v in stat if d.prefixlen == 0), "")
        out = ["Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP",
               "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area",
               "       * - candidate default, U - per-user static route, o - ODR",
               "", ("Gateway of last resort is " + default.split("via ")[-1] + " to network 0.0.0.0"
                    if default and "via" in default else "Gateway of last resort is not set"), ""]
        rows = []
        for n, name, ip in conn:
            rows.append((n, f"C        {n} is directly connected, {name}"))
            rows.append((ipaddress.IPv4Network(f"{ip}/32"), f"L        {ip}/32 is directly connected, {name}"))
        for d, how in stat:
            rows.append((d, f"S{'*' if d.prefixlen == 0 else ' '}       {d} {how}"))
        rows.sort(key=lambda r: (int(r[0].network_address), r[0].prefixlen))
        return "\n".join(out + [r for _, r in rows])

    def _mac_owner(self) -> dict[str, object]:
        return {l.mac.lower(): l for l in self.plan.ports}

    def _show_arp(self, a):
        data = self._live()
        if not data.get("ok"):
            raise CliError(f"% cannot read the router's tables: {data.get('note') or 'not ready yet'}")
        names = {net.id: n for n, net, _ in self.router_ifaces() if net is not None}
        owners = self._mac_owner()
        out = [f"{'Protocol':<10}{'Address':<17}{'Age (min)':<11}{'Hardware Addr':<16}{'Type':<6}Interface"]
        for name, net, up in self.router_ifaces():
            if net is not None and up:
                out.append(f"{'Internet':<10}{net.router_ip:<17}{'-':<11}{'0001.6400.0001':<16}{'ARPA':<6}{name}")
        running = self._running()
        for mac, ips in sorted(data.get("ips", {}).items()):
            link = owners.get(mac)
            if link is None or link.node_id not in running:
                continue
            for ip in ips:
                out.append(f"{'Internet':<10}{ip:<17}{'0':<11}{dotted_mac(mac):<16}{'ARPA':<6}"
                           f"{names.get(link.network_id, '')}")
        return "\n".join(out)

    def _show_binding(self, a):
        text = self._on_router("cat /var/lib/misc/dnsmasq.leases 2>/dev/null", timeout=15)
        import time
        out = [f"{'IP address':<17}{'Client-ID/Hardware address':<28}{'Lease expiration':<26}Type"]
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3 or not parts[0].isdigit():
                continue
            when = time.strftime("%b %d %Y %I:%M %p", time.gmtime(int(parts[0]))) if parts[0] != "0" else "Infinite"
            out.append(f"{parts[2]:<17}{dotted_mac(parts[1]):<28}{when:<26}Automatic")
        return "\n".join(out)

    def _show_pools(self, a):
        from . import netplan
        own = self.lab.devices.get(ROUTER, {})
        out = []
        names = sorted({k.split(":", 1)[1] for k in own if k.split(":", 1)[0] in ("pool", "poolnet")})
        for name in names:
            net = self.lab.networks.get(own.get(f"pool:{name}", ""))
            subnet = own.get(f"poolnet:{name}") or (str(net.net) if net else "")
            out += [f"Pool {name} :", " Utilization mark (high/low)    : 100 / 0",
                    " Subnet size (first/next)       : 0 / 0"]
            if not subnet:
                out += [" Total addresses                : 0", " Leased addresses               : 0", ""]
                continue
            sub = ipaddress.IPv4Network(subnet)
            free = netplan.pool_ranges(self.lab, net) if net is not None else []
            total = sub.num_addresses - 2
            out += [f" Total addresses                : {total}",
                    f" Leased addresses               : {len(self._leases_in(sub))}",
                    f" Excluded addresses             : {total - sum(int(ipaddress.IPv4Address(h)) - int(ipaddress.IPv4Address(l)) + 1 for l, h in free)}",
                    " Pending event                  : none",
                    f" 1 subnet is currently in the pool :",
                    f" Current index        IP address range                    Leased/Excluded/Total",
                    f" {str(sub.network_address + 1):<20} {str(sub.network_address + 1)} - {str(sub.broadcast_address - 1):<18}"
                    f" {len(self._leases_in(sub))} / {total - sum(int(ipaddress.IPv4Address(h)) - int(ipaddress.IPv4Address(l)) + 1 for l, h in free)} / {total}"]
            out.append("")
        return "\n".join(out).rstrip()

    def _target(self, text: str) -> str:
        try:
            return str(ipaddress.IPv4Address(text))
        except ValueError:
            raise CliError(f"% Unrecognized host or address: {text}") from None

    def _ping(self, a):
        if ":" in a[0]:
            from . import iosv6  # ping <IPv6 address>
            return iosv6.ping(self, a[0])
        ip = self._target(a[0])
        text = self._on_router(f"ping -c 5 -W 2 {ip} 2>&1", timeout=20)
        return format_ping(ip, text)

    def _trace(self, a):
        if ":" in a[0]:
            from . import iosv6  # traceroute <IPv6 address>
            return iosv6.traceroute(self, a[0])
        ip = self._target(a[0])
        text = self._on_router(f"traceroute -n -q 1 -w 2 -m 10 {ip} 2>&1", timeout=40)
        out = ["Type escape sequence to abort.", f"Tracing the route to {ip}", ""]
        for line in text.splitlines():
            m = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if m:
                out.append(f"  {m.group(1):>2} {m.group(2).strip()}")
        return "\n".join(out)

    def _wake_on_lan(self, a):
        from .power import console_wake  # winlab/power.py: a magic packet out of every routed VLAN
        return console_wake(self, a[0])

    def _sw_ping(self, a):
        """ping from the switch: from its management address (winlab/iosl2.py)."""
        if ":" in a[0]:
            from . import iosv6
            return iosv6.sw_ping(self, a[0])
        ip = self._target(a[0])
        from . import iosl2
        ns = iosl2.netns(self.lab, switch_id(self.device))
        if not ns:
            return (f"Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to {ip}, timeout is 2 seconds:\n"
                    ".....\nSuccess rate is 0 percent (0/5)")
        text = self._on_router(f"ip netns exec {ns} ping -c 5 -W 2 {ip} 2>&1", timeout=20)
        return format_ping(ip, text)

    def _ports(self) -> list:
        return switch_ports(self.lab, self.plan).get(switch_id(self.device), [])

    def _sw_mac(self) -> str:
        h = hashlib.sha256(f"winlab-switch/{self.lab.name}/{self.device}".encode()).digest()
        return "%02x%02x.%02x%02x.%02x%02x" % (0x00, 0x1b, h[0], h[1], h[2], h[3] & 0xfe)

    def _show_users(self, a):
        return ("    Line       User       Host(s)              Idle       Location\n"
                "*  0 con 0                idle                 00:00:00")

    def _show_flash(self, a):
        from . import iosimage  # the images and files the device keeps
        return iosimage.show_flash(self)

    def _clock_set(self, a):
        """clock set hh:mm:ss day month year: the router's own clock (the
        switches keep theirs from it). NTP, when set, pulls it back."""
        import time as _t
        w = a[0].split()
        try:
            if len(w) != 4:
                raise ValueError
            when = _t.strptime(" ".join(w), "%H:%M:%S %d %B %Y") if not w[2].isdigit() else None
        except ValueError:
            try:
                when = _t.strptime(" ".join(w), "%H:%M:%S %d %b %Y")
            except ValueError:
                raise CliError("% Invalid input detected at '^' marker.") from None
        if when is None:
            raise CliError("% Invalid input detected at '^' marker.")
        stamp = _t.strftime("%Y-%m-%d %H:%M:%S", when)
        self._on_router(f"date -s '{stamp}' >/dev/null 2>&1; hwclock -w 2>/dev/null; true", timeout=10)
        return ""

    def _show_protocols(self, a):
        from . import iosrouting
        return iosrouting.show_protocols(self)

    def _no_protocols(self, a):
        from . import iosrouting
        return iosrouting.other_protocol(a[0])

    def _show_run_if(self, a):
        from .vti import tunnel_name  # interface Tunnel<n>
        try:
            name = (self.device == ROUTER and tunnel_name(a[0])) or parse_if(a[0], self._if_names(), sub=self.device == ROUTER)
        except CliError:
            m = re.match(r"^\s*vl(?:a(?:n)?)?\s*(\d+)\s*$", a[0], re.I)
            if not m or self.device == ROUTER:
                raise
            name = f"Vlan{m.group(1)}"
        lines = self._show_run([]).split("\n")
        block, inside = [], False
        for line in lines:
            if line == f"interface {name}":
                inside = True
            elif inside and not line.startswith(" "):
                break
            if inside:
                block.append(line)
        body = "\n".join(block + ["end"])
        return f"Building configuration...\n\nCurrent configuration : {len(body)} bytes\n!\n{body}"

    def _if_stats(self, dev: str) -> dict:
        """The counters of one of the router's Linux interfaces."""
        if not dev or not self.powered():
            return {}
        try:
            return parse_link_stats(self._on_router(f"ip -s -s link show dev {dev} 2>/dev/null", timeout=10))
        except CliError:
            return {}

    def _router_dev(self, name: str) -> str:
        net = iface_net(self.lab, name)
        if net is None or not net.routed:
            return ""
        try:
            return self.plan.segment_of(net.id).svi
        except KeyError:
            return ""

    def _router_status(self, name: str, up: bool) -> tuple[str, str]:
        if not up:
            return "administratively down", "down"
        net = iface_net(self.lab, name)
        if net is None or not self.powered() or switch_off(self.lab, net.home):
            return "down", "down"
        return "up", "up"

    def _show_ip_iface(self, a):
        want = parse_if(a[0], self._if_names(), sub=True) if a and a[0].strip() else ""
        if a and a[0].strip().lower().startswith("b"):
            return self._show_ip_brief(a)
        out = []
        own = self.lab.devices.get(ROUTER, {})
        for name, net, up in self.router_ifaces():
            if want and name != want:
                continue
            status, proto = self._router_status(name, up)
            out.append(f"{name} is {status}, line protocol is {proto}")
            if net is None:
                out.append("  Internet protocol processing disabled")
                continue
            out += [f"  Internet address is {net.router_ip}/{net.prefixlen}",
                    f"  Broadcast address is 255.255.255.255", "  MTU is 1500 bytes"]
            helpers = imaging.helpers(self.lab, net.id)
            out.append(f"  Helper address{'es are' if len(helpers) > 1 else ' is'} "
                       f"{', '.join(helpers)}" if helpers else "  Helper address is not set")
            out.append(f"  Outgoing Common access list is not set")
            out.append(f"  Outgoing access list is {own.get(f'acl-out:{name}') or 'not set'}")
            out.append(f"  Inbound  access list is {own.get(f'acl-in:{name}') or 'not set'}")
            out.append("  Proxy ARP is enabled")
            nat = own.get(f"nat:{name}")
            out.append(f"  Network address translation is {'enabled, interface in domain ' + nat if nat else 'disabled'}")
        return "\n".join(out) or "% Invalid input detected at '^' marker."

    def _router_block(self, name: str, net, up: bool) -> str:
        own = self.lab.devices.get(ROUTER, {})
        status, proto = self._router_status(name, up)
        st = self._if_stats(self._router_dev(name)) if status == "up" else {}
        mac = dotted_mac(st["mac"]) if st.get("mac") else "0000.0000.0000"
        out = [f"{name} is {status}, line protocol is {proto}",
               f"  Hardware is {'ISR4321-2x1GE' if name in ONBOARD else 'NIM-ES2-8'}, address is {mac} (bia {mac})"]
        if own.get(f"desc:{name}"):
            out.append(f"  Description: {own[f'desc:{name}']}")
        if net is not None:
            out.append(f"  Internet address is {net.router_ip}/{net.prefixlen}")
        out += ["  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,",
                "     reliability 255/255, txload 1/255, rxload 1/255"]
        if "." in name:
            vid = net.vlan_no if net is not None else own.get(f"sub:{name}", "")
            out.append(f"  Encapsulation 802.1Q Virtual LAN, Vlan ID  {vid}.")
        else:
            out += ["  Encapsulation ARPA, loopback not set", "  Keepalive not supported",
                    "  Full Duplex, 1000Mbps, link type is auto, media type is RJ45"]
        out += counter_lines(st)
        return "\n".join(out)

    def _show_iface_one(self, a):
        """show interfaces <name> [switchport | counters]."""
        w = a[0].split()
        tail = w[-1].lower() if len(w) > 1 and not re.match(r"^[\d/.]+$", w[-1]) else ""
        name_text = " ".join(w[:-1]) if tail else a[0]
        if self.device != ROUTER and name_text.lower() in ("status", "trunk"):
            return self._show_status(a) if name_text.lower() == "status" else self._show_trunk(a)
        from . import etherchannel  # show interfaces port-channel <n>
        if self.device != ROUTER and etherchannel.po_number(name_text):
            return etherchannel.show_iface(self, name_text)
        if self.device == ROUTER:
            name = parse_if(name_text, self._if_names(), sub=True)
            for n, net, up in self.router_ifaces():
                if n == name:
                    return self._router_block(n, net, up)
            raise CliError("% Invalid input detected at '^' marker.")
        m = re.match(r"^\s*vl(?:a(?:n)?)?\s*(\d+)\s*$", name_text, re.I)
        if m:
            for vname, addr, up in self.svis():
                if vname == f"Vlan{m.group(1)}":
                    st = ("up" if up and self.powered() else "administratively down" if not up else "down")
                    out = [f"{vname} is {st}, line protocol is {'up' if st == 'up' else 'down'}",
                           f"  Hardware is EtherSVI, address is {self._sw_mac()} (bia {self._sw_mac()})"]
                    out += [f"  Internet address is {addr}"] if addr else []
                    return "\n".join(out + ["  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,"])
            raise CliError("% Invalid input detected at '^' marker.")
        name = parse_if(name_text, self._if_names())
        if tail.startswith("sw"):
            return self._switchport_block(name)
        return self._switch_block(name)

    def _switch_block(self, name: str) -> str:
        own = self.lab.devices.get(self.device, {})
        short = short_if(name)
        rows = {r.split()[0]: r for r in self._show_status([]).splitlines()[1:]}
        row = rows.get(short, "")
        link = None
        m = re.match(r"^FastEthernet0/(\d+)$", name)
        if m:
            ports = self._ports()
            i = int(m.group(1))
            link = ports[i - 1] if i <= len(ports) else None
        status = "connected" in row and "up" or ("disabled" in row and "administratively down") \
            or ("err-disabled" in row and "down (err-disabled)") or "down"
        look = self._look(link)
        st = {}
        if link is not None and status == "up":
            st = self._if_stats(link.fabric_iface)
        hw = "Fast Ethernet" if name.startswith("Fast") else "Gigabit Ethernet"
        out = [f"{name} is {status}, line protocol is {'up' if status == 'up' else 'down'}"
               + (" (connected)" if status == "up" else " (notconnect)" if status == "down" else ""),
               f"  Hardware is {hw}, address is {self._sw_mac()} (bia {self._sw_mac()})"]
        desc = own.get(f"desc:{link.label}") if link else own.get(f"desc:{name}")
        if desc:
            out.append(f"  Description: {desc}")
        bw = {"10": 10000, "100": 100000}.get(look["speed"].replace("a-", ""), 100000)
        out += [f"  MTU 1500 bytes, BW {bw} Kbit/sec, DLY 100 usec,",
                "     reliability 255/255, txload 1/255, rxload 1/255", "  Encapsulation ARPA, loopback not set",
                f"  {'Full' if 'full' in look['duplex'] else 'Half'}-duplex, "
                f"{look['speed'].replace('a-', '')}Mb/s, media type is 10/100BaseTX"]
        late = st.get("tx_dropped", 0) if look.get("mismatch") else 0
        out += counter_lines(st, late=late)
        return "\n".join(out)

    def _switchport_block(self, name: str) -> str:
        from . import lldp  # the voice VLAN line
        own = self.lab.devices.get(self.device, {})
        sid = switch_id(self.device)
        if name.startswith("GigabitEthernet"):
            allow = allowed_tags(self.lab, sid, name)
            native = own.get(f"native:{name}", "1")
            return "\n".join([f"Name: {short_if(name)}", "Switchport: Enabled", "Administrative Mode: trunk",
                              "Operational Mode: trunk", "Administrative Trunking Encapsulation: dot1q",
                              "Operational Trunking Encapsulation: dot1q",
                              f"Negotiation of Trunking: {'Off' if own.get(f'noneg:{name}') else 'On'}",
                              "Access Mode VLAN: 1 (default)",
                              f"Trunking Native Mode VLAN: {native} ({'default' if native == '1' else 'VLAN%04d' % int(native)})",
                              f"Trunking VLANs Enabled: {'ALL' if allow is None else vlan_text(allow) or 'NONE'}"])
        link = None
        m = re.match(r"^FastEthernet0/(\d+)$", name)
        ports = self._ports()
        if m and int(m.group(1)) <= len(ports):
            link = ports[int(m.group(1)) - 1]
        net = self.lab.networks.get(link.network_id) if link else None
        tag = net.vlan_no if net else 1
        trunk = bool(link and self.lab.nodes[link.node_id].nics[link.nic_index].trunk
                     and not own.get(f"voice:{link.label}"))  # a voice VLAN is tagged on an access port
        mode = "trunk" if trunk else "static access"
        allow = allowed_tags(self.lab, sid, link.label) if link else None
        name_of = (net.description if net and net.description else f"VLAN{tag:04d}") if tag != 1 else "default"
        return "\n".join([f"Name: {short_if(name)}", "Switchport: Enabled", f"Administrative Mode: {mode}",
                          f"Operational Mode: {mode if link else 'down'}",
                          "Administrative Trunking Encapsulation: dot1q",
                          f"Negotiation of Trunking: {'On' if trunk else 'Off'}",
                          f"Access Mode VLAN: {tag} ({name_of})",
                          f"Trunking Native Mode VLAN: {tag if trunk else 1} ({name_of if trunk else 'default'})",
                          lldp.voice_line(self.lab, sid, link.label if link else name),
                          f"Trunking VLANs Enabled: {'ALL' if allow is None else vlan_text(allow) or 'NONE'}"])

    def _sw_ip_brief(self, a):
        rows = [f"{'Interface':<23}{'IP-Address':<16}{'OK?':<4}{'Method':<7}{'Status':<22}Protocol"]
        for vname, addr, up in self.svis():
            ip = addr.split("/")[0] if addr else "unassigned"
            status = "administratively down" if not up else "up" if self.powered() else "down"
            rows.append(f"{vname:<23}{ip:<16}{'YES':<4}{'manual' if addr else 'unset':<7}{status:<22}"
                        f"{'up' if status == 'up' else 'down'}")
        for line in self._show_status([]).splitlines()[1:]:
            port = line.split()[0]
            long = port.replace("Fa", "FastEthernet").replace("Gi", "GigabitEthernet")
            up = " connected " in line
            dis = " disabled " in line
            rows.append(f"{long:<23}{'unassigned':<16}{'YES':<4}{'unset':<7}"
                        f"{'administratively down' if dis else 'up' if up else 'down':<22}{'up' if up else 'down'}")
        return "\n".join(rows)

    def _leases_in(self, sub) -> list[str]:
        if not self.powered():
            return []
        try:
            text = self._on_router("cat /var/lib/misc/dnsmasq.leases 2>/dev/null", timeout=15)
        except CliError:
            return []
        out = []
        for line in (text or "").splitlines():
            parts = line.split()
            try:
                if len(parts) >= 3 and ipaddress.IPv4Address(parts[2]) in sub:
                    out.append(parts[2])
            except ValueError:
                continue
        return out

    def pools(self) -> list[tuple[str, object, str]]:
        """(name, network served or None, subnet) per DHCP pool: the pools
        typed at the console, and a lab file's own (dhcp = true)."""
        own = self.lab.devices.get(ROUTER, {})
        out, seen = [], set()
        for name in sorted({k.split(":", 1)[1] for k in own if k.split(":", 1)[0] in ("pool", "poolnet")}):
            net = self.lab.networks.get(own.get(f"pool:{name}", ""))
            subnet = own.get(f"poolnet:{name}") or (str(net.net) if net else "")
            out.append((name, net, subnet))
            if net is not None:
                seen.add(net.id)
        for nid, net in sorted(self.lab.networks.items()):
            if net.dhcp and net.routed and nid not in seen:
                out.append((nid.upper(), net, str(net.net)))
        return out

    def _show_vlan(self, a):
        sid = switch_id(self.device)
        ports = self._ports()
        out = [f"{'VLAN':<5}{'Name':<33}{'Status':<10}Ports", f"{'-' * 4} {'-' * 32} {'-' * 9} {'-' * 30}"]
        for net in vlans_of(self.lab, sid):
            tag = net.vlan_no
            members = [f"Fa0/{i}" for i, l in enumerate(ports, 1) if l is not None and l.network_id == net.id]
            if tag == 1:
                members = [f"Fa0/{i}" for i in range(1, SWITCH_PORTS + 1)
                           if i > len(ports) or ports[i - 1] is None or ports[i - 1].network_id == net.id]
            name = "default" if tag == 1 else (net.description or f"VLAN{tag:04d}")
            out.append(f"{tag:<5}{name[:32]:<33}{'active':<10}{_wrap(', '.join(members), 48)}".rstrip())
        return "\n".join(out)

    def _show_mac(self, a, dynamic: bool = False, port: str = ""):
        """The switch's MAC address table: the machines heard on its ports,
        Wi-Fi clients on their access point's port, and the router's own
        addresses on the uplink."""
        data = self._live()
        seen = set(data.get("seen", []))
        running = self._running()
        want = short_if(parse_if(port, self._if_names())) if port else ""
        rows = []
        for i, link in enumerate(self._ports(), 1):
            if link is not None and link.mac.lower() in seen and link.node_id in running:
                rows.append((self.lab.networks[link.network_id].vlan_no, dotted_mac(link.mac), f"Fa0/{i}"))
        # Wireless clients are learnt on the port their access point is in.
        for k, ap_id in sorted(ap_slots(self.lab, self.plan, switch_id(self.device), self._ports()).items()):
            for node_id in self._wifi().clients(self.lab, ap_id):
                node = self.lab.nodes[node_id]
                for link in self.plan.ports_for(node_id):
                    if link.nic_index in self._wifi().wireless(node) and link.plugged \
                            and link.mac.lower() in seen and node_id in running:
                        rows.append((self.lab.networks[link.network_id].vlan_no, dotted_mac(link.mac), f"Fa0/{k}"))
        sid = switch_id(self.device)
        # Machines on the other switches, learnt on the trunk that leads to
        # them, in this switch's VLAN that is one network with theirs across
        # it (Lab.segment_id: a VLAN a trunk does not carry, or a native VLAN
        # mismatch, changes that).
        mine = {self.plan.segment_of(n.id).network.id: n.vlan_no for n in vlans_of(self.lab, sid)}
        for link in self.plan.ports:
            net = self.lab.networks.get(link.network_id) if link.plugged else None
            if net is None or net.home == sid or link.mac.lower() not in seen or link.node_id not in running:
                continue
            tag = mine.get(self.plan.segment_of(net.id).network.id)
            port = self._toward(net.home)
            if tag is not None and port:
                rows.append((tag, dotted_mac(link.mac), short_if(port)))
        router_mac = data.get("router_mac", "")
        if router_mac and (uplinked(self.lab, sid) or upstream(self.lab, sid)) and self.powered():
            for net in vlans_of(self.lab, sid):
                if self.plan.segment_of(net.id).network.routed:
                    rows.append((net.vlan_no, dotted_mac(router_mac), "Gi0/1"))
        out = ["          Mac Address Table", "-------------------------------------------", "",
               f"{'Vlan':<8}{'Mac Address':<19}{'Type':<12}Ports", f"{'----':<8}{'-----------':<19}{'--------':<12}-----"]
        rows = [r for r in rows if not want or r[2] == want]
        out += [f"{t:<8}{m:<19}{'DYNAMIC':<12}{p}" for t, m, p in sorted(rows)]
        out.append(f"Total Mac Addresses for this criterion: {len(rows)}")
        return "\n".join(out)

    def _toward(self, other: str) -> str:
        """The gigabit port of this switch that leads to switch `other`: the
        downlink above it, else the uplink; "" when there is no way."""
        sid = switch_id(self.device)
        for port, below in downlinks(self.lab, sid):
            hop, been = other, set()
            while hop and hop not in been:
                if hop == below:
                    return port
                been.add(hop)
                hop = upstream(self.lab, hop)
        return "GigabitEthernet0/1" if upstream(self.lab, sid) else ""

    @staticmethod
    def _wifi():
        from . import wifi
        return wifi

    def _aps(self) -> list[str]:
        return self._wifi().on_switch(self.lab, switch_id(self.device))

    def _look(self, link) -> dict:
        """A port's duplex, speed and link: a fault on its cable
        (winlab/physfaults.py), then what was typed on it. A duplex hard-set
        to full against a card that negotiates is a mismatch: the card falls
        back to half."""
        if link is None:
            return {"duplex": "a-full", "speed": "a-100", "down": False}
        from . import physfaults
        out = dict(physfaults.port_look(self.lab, link))
        own = self.lab.devices.get(self.device, {})
        sp, dx = own.get(f"speed:{link.label}"), own.get(f"duplex:{link.label}")
        if sp:
            out["speed"] = sp
            if not dx:
                out["duplex"] = "a-half"
        if dx:
            out["duplex"] = dx
            out["mismatch"] = dx == "full"
        return out

    def _show_status(self, a):
        own = self.lab.devices.get(self.device, {})
        ports = self._ports()
        running = self._running()
        out = [f"{'Port':<10}{'Name':<19}{'Status':<13}{'Vlan':<11}{'Duplex':<7}{'Speed':<7}Type"]
        slots = ap_slots(self.lab, self.plan, switch_id(self.device), ports)
        every = self._wifi().aps(self.lab)
        for i in range(1, SWITCH_PORTS + 1):
            link = ports[i - 1] if i <= len(ports) else None
            name, status, tag = "", "notconnect", 1
            ap = every.get(slots.get(i, ""))
            if ap:
                name = own.get(f"desc:Fa0/{i}") or ap["name"]
                status = "connected" if self.powered() else "notconnect"
                tag = self.lab.networks[ap["network"]].vlan_no
            if link:
                name = own.get(f"desc:{link.label}") or naming.display(self.lab, link.node_id)
                status = ("disabled" if own.get(f"shut:{link.label}") else
                          "err-disabled" if own.get(f"psec-err:{link.label}") else
                          "connected" if link.node_id in running and self.powered()
                          and not own.get(f"nocable:{link.label}") else "notconnect")
                tag = self.lab.networks[link.network_id].vlan_no
            look = self._look(link)
            if link and look["down"] and status == "connected":
                status = "notconnect"
            out.append(f"{f'Fa0/{i}':<10}{name[:18]:<19}{status:<13}{tag:<11}"
                       f"{look['duplex']:<7}{look['speed']:<7}10/100BaseTX")
        for port, far, up in self._trunks():
            out.append(f"{short_if(port):<10}{far[:18]:<19}{'connected' if up else 'notconnect':<13}"
                       f"{'trunk':<11}{'a-full':<7}{'a-1000':<7}10/100/1000BaseTX")
        return "\n".join(out)

    def _trunks(self) -> list[tuple[str, str, bool]]:
        """(port, what is at the far end, whether it is cabled) per gigabit
        port: the uplink, then the switches cabled below this one."""
        lab, sid = self.lab, switch_id(self.device)
        up = upstream(lab, sid)
        out = [("GigabitEthernet0/1", hostname(lab, f"sw:{up}") if up else
                "uplink" if not uplinked(lab, sid) else hostname(lab, ROUTER), trunk_up(lab, sid))]
        below = dict(downlinks(lab, sid))
        from . import stp  # spare cables to other switches (a loop, if spanning tree lets it)
        below.update(stp.spare_ports(lab, sid))
        for port in gig_names()[1:]:
            out.append((port, hostname(lab, f"sw:{below[port]}") if port in below else "", port in below))
        return out

    def _show_trunk(self, a):
        sid = switch_id(self.device)
        own = self.lab.devices.get(self.device, {})
        vl = vlans_of(self.lab, sid)
        live = [(p, far) for p, far, up in self._trunks() if up]
        ports = self._ports()
        machine = [(f"Fa0/{i}", l) for i, l in enumerate(ports, 1)
                   if l is not None and self.lab.nodes[l.node_id].nics[l.nic_index].trunk
                   and not own.get(f"voice:{l.label}")]
        if not live and not machine:
            return ""
        rows = []   # (port, native, allowed set or None, active tags)
        for p, _ in live:
            allow = allowed_tags(self.lab, sid, p)
            native = int(own.get(f"native:{p}", 1))
            active = [n.vlan_no for n in vl if allow is None or n.vlan_no in allow]
            rows.append((short_if(p), native, allow, active))
        for p, link in machine:
            nic = self.lab.nodes[link.node_id].nics[link.nic_index]
            native = self.lab.networks[link.network_id].vlan_no
            tags = sorted({native} | {self.lab.networks[t].vlan_no for t in nic.trunk if t in self.lab.networks})
            rows.append((p, native, allowed_tags(self.lab, sid, link.label), tags))
        out = [f"{'Port':<12}{'Mode':<13}{'Encapsulation':<15}{'Status':<14}Native vlan"]
        out += [f"{p:<12}{'on':<13}{'802.1q':<15}{'trunking':<14}{n}" for p, n, _, _ in rows]
        out += ["", f"{'Port':<12}Vlans allowed on trunk"]
        out += [f"{p:<12}{'1-4094' if al is None else vlan_text(al) or 'none'}" for p, _, al, _ in rows]
        out += ["", f"{'Port':<12}Vlans allowed and active in management domain"]
        out += [f"{p:<12}{vlan_text(set(act)) or 'none'}" for p, _, _, act in rows]
        out += ["", f"{'Port':<12}Vlans in spanning tree forwarding state and not pruned"]
        out += [f"{p:<12}{vlan_text(set(act)) or 'none'}" for p, _, _, act in rows]
        return "\n".join(out)


def _wrap(text: str, indent: int, width: int = 30) -> str:
    out, line = [], ""
    for part in text.split(", "):
        if line and len(line) + len(part) + 2 > width:
            out.append(line + ",")
            line = part
        else:
            line = f"{line}, {part}" if line else part
    out.append(line)
    return ("\n" + " " * indent).join(out)


def format_ping(ip: str, text: str) -> str:
    """busybox/iputils ping output, told the way a router tells it."""
    seqs, times = set(), []
    for line in text.splitlines():
        m = re.search(r"(?:icmp_)?seq=(\d+)", line)
        if m and "bytes from" in line:
            seqs.add(int(m.group(1)))
            t = re.search(r"time=([\d.]+)", line)
            if t:
                times.append(float(t.group(1)))
    base = 0 if 0 in seqs or not seqs or min(seqs) == 0 else 1
    marks = "".join("!" if (base + i) in seqs else "." for i in range(5))
    ok = marks.count("!")
    out = ["Type escape sequence to abort.",
           f"Sending 5, 100-byte ICMP Echos to {ip}, timeout is 2 seconds:", marks]
    line = f"Success rate is {ok * 20} percent ({ok}/5)"
    if times:
        line += (f", round-trip min/avg/max = {round(min(times))}/{round(sum(times) / len(times))}/"
                 f"{round(max(times))} ms")
    out.append(line)
    return "\n".join(out)


def parse_link_stats(text: str) -> dict:
    """`ip -s -s link show dev X` -> its address and counters."""
    out: dict = {}
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        t = line.strip()
        if t.startswith("link/ether"):
            out["mac"] = t.split()[1]
        for head, pre in (("RX errors:", "rx_"), ("TX errors:", "tx_"), ("RX:", "rx_"), ("TX:", "tx_")):
            if t.startswith(head) and i + 1 < len(lines):
                names = t[len(head):].split()
                vals = lines[i + 1].split()
                for n, v in zip(names, vals):
                    if v.isdigit():
                        out[pre + n.lower()] = int(v)
                break
    return out


def counter_lines(st: dict, late: int = 0) -> list[str]:
    """The counters block of show interfaces, from parse_link_stats."""
    g = lambda k: int(st.get(k, 0))  # noqa: E731
    return ["  Last input never, output never, output hang never",
            "  Input queue: 0/375/0/0 (size/max/drops/flushes); Total output drops: "
            f"{g('tx_dropped')}",
            "  5 minute input rate 0 bits/sec, 0 packets/sec",
            "  5 minute output rate 0 bits/sec, 0 packets/sec",
            f"     {g('rx_packets')} packets input, {g('rx_bytes')} bytes, 0 no buffer",
            f"     Received {g('rx_mcast')} broadcasts (0 IP multicasts)",
            f"     {g('rx_errors') + g('rx_crc')} input errors, {g('rx_crc')} CRC, {g('rx_frame')} frame, "
            f"{g('rx_overrun') + g('rx_fifo')} overrun, 0 ignored",
            f"     {g('tx_packets')} packets output, {g('tx_bytes')} bytes, 0 underruns",
            f"     {g('tx_errors') + late} output errors, {g('tx_collsns') + late} collisions, 0 interface resets",
            f"     0 babbles, {late} late collision, 0 deferred"]


def switch_off(lab, sw: str) -> bool:
    """Whether a switch's power is off (its front panel's switch)."""
    return lab.devices.get(f"sw:{sw}", {}).get("power") == "off"


def held_down(lab, link) -> bool:
    """Whether a machine port is shut down on the switch it is plugged into,
    or that switch is off."""
    net = lab.networks.get(link.network_id) if link.plugged else None
    if net is not None and switch_off(lab, net.home):
        return True
    own = lab.devices.get(f"sw:{net.home}", {}) if net is not None else {}
    # err-disabled by port security holds it down too (winlab/portsec.py)
    # a cable not yet run and patched in the lab's building (winlab/buildlife.py) has no link
    return bool(own.get(f"shut:{link.label}") or own.get(f"psec-err:{link.label}") or own.get(f"nocable:{link.label}"))
