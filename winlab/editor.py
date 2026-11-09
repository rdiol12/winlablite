"""Live lab editing: add/remove machines and networks like a growing company.

Edits the TOML definition in place through a tomllib-read / hand-written-emit
round trip (tomllib cannot write), re-validating the whole lab before saving so
a bad edit is rejected rather than persisted. Running machines are untouched
until `winlab lab up` converges the lab.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
from pathlib import Path

from . import naming, schema
from .images import HAND_INSTALL, windows_images
from .netos import VENDORS as ROUTER_OS
from .model import DEVICE_KINDS, HARDWARE, HARDWARE_PC, KINDS, Device, Lab, Network, Nic, Node
from .schema import LabError


class EditError(Exception):
    pass


NODE_ID = re.compile(r"^[a-z][a-z0-9-]{1,14}$")


DEFAULT_IMAGE_FOR = {
    "windows-server": "ws2025",
    "windows-client": "win11",
    "linux": "alpine",
}


def load_for_edit(target: str) -> Lab:
    return schema.load(target)


# --------------------------------------------------------------------------
# Address allocation
# --------------------------------------------------------------------------


def _used_ips(lab: Lab, network_id: str) -> set[str]:
    used = set()
    net = lab.networks[network_id]
    used.add(net.router_ip)
    for node in lab.nodes.values():
        for nic in node.nics:
            if nic.network == network_id and nic.ip:
                used.add(nic.ip)
    return used


def next_free_ip(lab: Lab, network_id: str, start_offset: int = 10) -> str:
    net = lab.networks[network_id]
    used = _used_ips(lab, network_id)
    hosts = list(net.net.hosts())
    for host in hosts[start_offset:]:
        if str(host) not in used:
            return str(host)
    for host in hosts:
        if str(host) not in used:
            return str(host)
    raise EditError(f"network '{network_id}' has no free address")


def next_free_subnet(lab: Lab, base: str = "10.0.0.0/8", prefix: int = 24) -> str:
    taken = [n.net for n in lab.networks.values()]
    pool = ipaddress.ip_network(base)
    for candidate in pool.subnets(new_prefix=prefix):
        if not any(candidate.overlaps(t) for t in taken):
            return str(candidate)
    raise EditError(f"no free /{prefix} subnet under {base}")


# --------------------------------------------------------------------------
# Mutations (operate on the model; emit() serialises)
# --------------------------------------------------------------------------


def add_network(
    lab: Lab,
    net_id: str,
    cidr: str = "",
    vlan: int | None = None,
    dhcp: bool = False,
    wan: bool = False,
    description: str = "",
) -> Network:
    if net_id in lab.networks:
        raise EditError(f"network '{net_id}' already exists")
    cidr = cidr or next_free_subnet(lab)
    net = Network(id=net_id, cidr=cidr, vlan=vlan, dhcp=dhcp, wan=wan,
                  description=description)
    lab.networks[net_id] = net
    return net


def overlapping(lab: Lab, cidr: str, but: str = "") -> str:
    """The network whose subnet overlaps ``cidr`` (two switches on one
    subnet: the router cannot route both), or ''."""
    try:
        want = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return ""  # the lab's own check says what is wrong with it
    for other in lab.networks.values():
        if other.id == but or other.link:
            continue
        try:
            have = ipaddress.ip_network(other.cidr, strict=False)
        except ValueError:
            continue
        if have.version == want.version and have.overlaps(want):
            return other.id
    return ""


def check_new_switch(lab: Lab, net_id: str, cidr: str) -> None:
    """A switch the user adds: a name of its own, a subnet of its own."""
    if net_id in lab.nodes:
        raise EditError(f"{net_id} is already the name of a machine; give the switch another name")
    clash = overlapping(lab, cidr)
    if clash:
        raise EditError(f"{cidr} overlaps {clash}'s subnet ({lab.networks[clash].cidr}); give the new "
                        f"switch a subnet of its own, or leave it empty to take the next free one")


def remove_network(lab: Lab, net_id: str) -> None:
    if net_id not in lab.networks:
        raise EditError(f"no such network '{net_id}'")
    attached = [n.id for n in lab.nodes.values()
                if any(c.network == net_id for c in n.nics)]
    if attached:
        raise EditError(
            f"network '{net_id}' still has machines attached: {', '.join(attached)}"
        )
    users = [r.name for r in lab.firewall.rules if r.segment != net_id
             and net_id in (r.source.split(",") + r.destination.split(","))]
    if users:
        raise EditError(
            f"firewall rules still name network '{net_id}': {', '.join(users)}"
        )
    lab.firewall.rules = [r for r in lab.firewall.rules if r.segment != net_id]
    del lab.networks[net_id]


def add_node(
    lab: Lab,
    node_id: str,
    kind: str = "windows-server",
    network: str = "",
    ip: str = "",
    roles: list[str] | None = None,
    cpus: int = 0,
    memory_mb: int = 0,
    image: str = "",
    count: int = 1,
) -> list[Node]:
    if kind not in KINDS:
        raise EditError(f"unknown kind '{kind}'; use one of {sorted(KINDS)}")
    if lab.workbench:
        # On the workbench a machine arrives with its port empty: the
        # student plugs the cable in.
        if network and network not in lab.networks:
            raise EditError(f"no such network '{network}'")
    else:
        if not lab.networks:
            raise EditError("add a network first")
        network = network or next(iter(lab.networks))
        if network not in lab.networks:
            raise EditError(f"no such network '{network}'")

    from .images import templates

    tpl = templates().get(image) if image else None
    data_disks: list[int] = []
    if tpl is not None:
        # A template knows what it is: the machine takes the template's kind
        # and hardware, and only the roles need deciding.
        kind = tpl.kind
        cpus = cpus or tpl.cpus
        memory_mb = memory_mb or tpl.memory_mb
        data_disks = list(tpl.data_disks_gb)
    elif kind == "custom" and image in HAND_INSTALL:
        # Windows installed by hand from Microsoft's evaluation DVD.
        data_disks = []
    elif kind == "custom" and image in ROUTER_OS:
        # A vendor's router OS (winlab/netos.py): the vendor's own disk or ISO.
        data_disks = []
    elif kind == "custom":
        # Any OS from the user's own ISO: name which one, and default to the
        # first one added on this PC when there is exactly one.
        from .images import custom_images

        mine = custom_images()
        if not image and len(mine) == 1:
            image = next(iter(mine))
        if not image:
            raise EditError(
                "a custom machine needs --image (an ISO added with 'winlab images add')"
            )
        if image not in mine:
            raise EditError(f"no custom image '{image}'; add it with 'winlab images add'")
    elif image:
        from .images import CATALOG
        entry = CATALOG.get(image)
        if entry is None:
            raise EditError(
                f"no image '{image}': not a catalog image ({', '.join(windows_images())}), "
                f"not one of your templates, and --kind is not custom")
        if entry.kind != kind:
            raise EditError(f"image '{image}' is {entry.kind}, not {kind}")
    image = image or DEFAULT_IMAGE_FOR.get(kind, "ws2025")
    from .appliances import get as appliance
    app = appliance(image) if kind == "linux" else None
    if not cpus:
        cpus = app.cpus if app else (1 if kind == "linux" else 2)
    if not memory_mb:
        memory_mb = app.memory_mb if app else {
            "windows-server": 2048, "windows-client": 2048, "linux": 512}.get(kind, 2048)
    roles = [] if kind == "custom" else roles or (["domain-join"] if kind in ("windows-server", "windows-client")
                      and _has_domain(lab) else [])

    created: list[Node] = []
    # A name typed in the student's own spelling (HQ-Files) is the machine's
    # computer name; its id is the same in lower case.
    base = node_id.strip()
    for i in range(count):
        shown = base if count == 1 else f"{base}{i + 1:02d}"
        nid = shown.lower()
        if nid in lab.nodes:
            raise EditError(f"node '{nid}' already exists")
        nic_ip = ip if (ip and count == 1 and network) else ""
        if nic_ip and nic_ip in _used_ips(lab, network):
            raise EditError(f"address {nic_ip} is already in use on '{network}'")
        node = Node(
            id=nid,
            image=image,
            kind=kind,
            cpus=cpus,
            memory_mb=memory_mb,
            hostname=shown[:15] if shown != nid else nid.upper()[:15],
            nics=[Nic(network=network, ip=nic_ip or None)],
            roles=list(roles),
            data_disks_gb=list(data_disks),
            boot_order=_suggest_boot_order(kind, roles),
        )
        if tpl is not None and tpl.description:
            node.description = tpl.description
        lab.nodes[nid] = node
        created.append(node)
    return created


def clone_node(lab: Lab, src_id: str, new_id: str, ip: str = "") -> Node:
    """A second machine defined like the first: same image, kind, hardware,
    roles, disks and networks. Static addresses are allocated afresh, since
    two machines cannot share one; a DHCP machine stays DHCP."""
    src = lab.nodes.get(src_id)
    if not src:
        raise EditError(f"no such node '{src_id}'")
    if new_id in lab.nodes or new_id == "fabric":
        raise EditError(f"node '{new_id}' already exists")
    if not NODE_ID.match(new_id):
        raise EditError(
            f"'{new_id}': a machine name is 2-15 lower-case letters, digits and dashes"
        )
    if "ad-ds" in src.roles:
        raise EditError(
            f"'{src_id}' is a domain controller: Active Directory forbids copying one. "
            f"Add a machine with the ad-ds role and let it replicate instead"
        )
    nics: list[Nic] = []
    for i, nic in enumerate(src.nics):
        if nic.ip:
            want = ip if (i == 0 and ip) else next_free_ip(lab, nic.network)
            if i == 0 and ip and ip in _used_ips(lab, nic.network):
                raise EditError(f"address {ip} is already in use on '{nic.network}'")
            nics.append(Nic(network=nic.network, ip=want, dns=list(nic.dns),
                            trunk=list(nic.trunk)))
        else:
            nics.append(Nic(network=nic.network, dns=list(nic.dns), trunk=list(nic.trunk)))
    node = Node(
        id=new_id, image=src.image, kind=src.kind, cpus=src.cpus, memory_mb=src.memory_mb,
        hostname=new_id.upper()[:15], nics=nics, roles=list(src.roles),
        data_disks_gb=list(src.data_disks_gb),
        devices=[Device(kind=d.kind, name=f"{d.name}-{new_id}", shared=d.shared,
                        driver=d.driver, location=d.location, vars=dict(d.vars))
                 for d in src.devices],
        boot_order=src.boot_order,
        wait_ready=src.wait_ready,
        start_delay=src.start_delay,
        hardware=src.hardware,
        lean=src.lean,
        nested=src.nested,
        firmware=src.firmware,
        description=f"clone of {src_id}" + (f": {src.description}" if src.description else ""),
        vars={k: v for k, v in src.vars.items() if k not in ("forest_root", "dhcp_scope")},
    )
    lab.nodes[new_id] = node
    return node


def remove_node(lab: Lab, node_id: str) -> None:
    if node_id not in lab.nodes:
        raise EditError(f"no such node '{node_id}'")
    owners = [s.id for s in lab.sites.values() if s.gateway == node_id]
    if owners:
        raise EditError(f"'{node_id}' is the gateway of site {', '.join(owners)}; "
                        f"give the site another gateway first")
    named = [r.name for r in lab.firewall.rules if node_id in (r.source, r.destination)]
    if named:
        raise EditError(f"firewall rule(s) {', '.join(sorted(set(named)))} name '{node_id}'; "
                        f"remove them first (winlab fw {lab.name} rm <name>)")
    del lab.nodes[node_id]


def add_device(lab: Lab, node_id: str, kind: str, name: str,
               driver: str = "", location: str = "") -> Device:
    node = lab.nodes.get(node_id)
    if not node:
        raise EditError(f"no such node '{node_id}'")
    if kind not in DEVICE_KINDS:
        raise EditError(f"unknown device kind '{kind}'; use one of {sorted(DEVICE_KINDS)}")
    if any(d.name == name for d in node.devices):
        raise EditError(f"node '{node_id}' already has a device named '{name}'")
    dev = Device(kind=kind, name=name, driver=driver, location=location)
    node.devices.append(dev)
    return dev


def remove_device(lab: Lab, node_id: str, name: str) -> None:
    node = lab.nodes.get(node_id)
    if not node:
        raise EditError(f"no such node '{node_id}'")
    before = len(node.devices)
    node.devices = [d for d in node.devices if d.name != name]
    if len(node.devices) == before:
        raise EditError(f"node '{node_id}' has no device named '{name}'")


def set_node(lab: Lab, node_id: str, **changes) -> Node:
    node = lab.nodes.get(node_id)
    if not node:
        raise EditError(f"no such node '{node_id}'")
    if changes.get("hostname"):
        _rename(lab, node, str(changes["hostname"]).strip())
    if "cpus" in changes and changes["cpus"]:
        node.cpus = int(changes["cpus"])
    if "memory_mb" in changes and changes["memory_mb"]:
        node.memory_mb = int(changes["memory_mb"])
    if changes.get("add_role"):
        for r in changes["add_role"]:
            if r not in node.roles:
                node.roles.append(r)
    if changes.get("rm_role"):
        node.roles = [r for r in node.roles if r not in changes["rm_role"]]
    if changes.get("move_to"):
        target = changes["move_to"]
        if target not in lab.networks:
            raise EditError(f"no such network '{target}'")
        if node.nics:
            cable(lab, node_id, 0, target, ip=changes.get("ip") or None)
        else:
            node.nics = [Nic(network=target, ip=changes.get("ip") or None)]
    elif changes.get("ip"):
        if not node.nics:
            raise EditError(f"node '{node_id}' has no nic to address")
        node.nics[0].ip = changes["ip"]
    if changes.get("boot_order"):
        node.boot_order = int(changes["boot_order"])
    if "start_delay" in changes and changes["start_delay"] is not None:
        delay = int(changes["start_delay"])
        if not 0 <= delay <= 900:
            raise EditError("a start delay is 0 to 900 seconds")
        node.start_delay = delay
    if "wait_ready" in changes and changes["wait_ready"] is not None:
        if changes["wait_ready"] and not node.is_windows:
            raise EditError(f"node '{node_id}' runs no winlab agent, so nothing can wait "
                            f"for it to be ready; give it a start delay instead")
        node.wait_ready = bool(changes["wait_ready"])
    if "description" in changes and changes["description"] is not None:
        node.description = str(changes["description"])
    if changes.get("add_disk_gb"):
        size = int(changes["add_disk_gb"])
        if not 1 <= size <= 4096:
            raise EditError("a data disk is 1 to 4096 GB")
        node.data_disks_gb.append(size)
    if changes.get("rm_disk"):
        # Only the last disk: the files are numbered, and a gap would rename
        # every later disk on the machine.
        if not node.data_disks_gb:
            raise EditError(f"node '{node_id}' has no data disk to remove")
        node.data_disks_gb.pop()
        from . import disks, hardware
        hardware.forget(lab.name, node_id, len(node.data_disks_gb))
        disks.forget(lab.name, node_id, len(node.data_disks_gb))
    if changes.get("add_nic"):
        net, _, ip = str(changes["add_nic"]).partition(":")
        if net == "-" and lab.workbench:
            net, ip = "", ""  # a new card, no cable in it yet
        elif net not in lab.networks:
            raise EditError(f"no such network '{net}'")
        if len(node.nics) >= 8:
            raise EditError("a machine takes at most 8 nics")
        node.nics.append(Nic(network=net, ip=ip or None))
    if changes.get("rm_nic"):
        idx = int(changes["rm_nic"])
        if idx == 0 and not lab.workbench:
            raise EditError("nic0 is the machine's address in the lab; move it instead")
        if idx == 0 and len(node.nics) == 1:
            raise EditError(f"{node_id} would have no network card left")
        if not 0 <= idx < len(node.nics):
            raise EditError(f"node '{node_id}' has no nic{idx}")
        del node.nics[idx]
    if "iso" in changes and changes["iso"] is not None:
        _set_var(node, "iso", _check_iso(str(changes["iso"])))
    if "usb_storage_gb" in changes and changes["usb_storage_gb"] is not None:
        gb = int(changes["usb_storage_gb"] or 0)
        if not 0 <= gb <= 256:
            raise EditError("a usb stick is 0 (none) to 256 GB")
        _set_var(node, "usb_storage_gb", gb)
    if "gpu" in changes and changes["gpu"] is not None:
        _set_var(node, "gpu", bool(changes["gpu"]))
    if "hardware" in changes and changes["hardware"] is not None:
        hw = str(changes["hardware"] or "")
        if hw not in HARDWARE:
            raise EditError("hardware is 'pc' (a regular PC) or 'virtio' (Red Hat's paravirtual devices)")
        if hw and not node.is_windows:
            raise EditError(f"node '{node_id}' is not a Windows machine; hardware applies to those")
        node.hardware = "" if hw == HARDWARE_PC else hw
        node.vars.pop("virtio", None)
    if "lean" in changes and changes["lean"] is not None:
        if changes["lean"] and not node.is_windows:
            raise EditError(f"node '{node_id}' is not a Windows machine; the Low-memory profile applies to those")
        node.lean = bool(changes["lean"])
    return node


def _nic_of(lab: Lab, node_id: str, nic_index: int | str) -> tuple[Node, Nic]:
    node = lab.nodes.get(node_id)
    if not node:
        raise EditError(f"no such node '{node_id}'")
    try:
        idx = int(nic_index)
    except (TypeError, ValueError):
        raise EditError(f"'{nic_index}' is not a nic number") from None
    if not 0 <= idx < len(node.nics):
        raise EditError(f"node '{node_id}' has no nic{idx}")
    return node, node.nics[idx]


def cable(lab: Lab, node_id: str, nic_index: int | str, network: str, ip: str | None = None) -> Nic:
    """Plug nicN of a machine into another switch: what dragging a machine
    onto a switch in the Network map does. A static address is replaced by
    the first free one on the new subnet (or by `ip`), a DHCP address stays
    DHCP, and machines that used the old address as a DNS server follow it.
    A VLAN tagged on the port that is now its native VLAN leaves the trunk."""
    node, nic = _nic_of(lab, node_id, nic_index)
    if network not in lab.networks:
        raise EditError(f"no such network '{network}'")
    if nic.network == network and not ip:
        raise EditError(f"{node_id} nic{nic_index} is already cabled to {network}")
    if not nic.plugged:
        # A cable into an empty port. Equipment the lab sets up itself (a
        # provider's gateway, a printer's firmware) takes the first free
        # address; a machine the student sets up keeps whatever they type in
        # it, so the lab records nothing (DHCP, as a fresh install comes).
        from .provision import lab_addressed
        nic.network = network
        if ip:
            if ip in _used_ips(lab, network):
                raise EditError(f"{ip} is already used on {network}")
            nic.ip = ip
        elif lab_addressed(node) and not lab.networks[network].dhcp:
            nic.ip = next_free_ip(lab, network)
        return nic
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise EditError(f"'{ip}' is not an IPv4 address") from None
        if addr not in lab.networks[network].net:
            raise EditError(f"{ip} is not on {network} ({lab.networks[network].cidr})")
        if ip in _used_ips(lab, network) and ip != nic.ip:
            raise EditError(f"{ip} is already used on {network}")
    old_ip = nic.ip
    nic.network = network
    nic.trunk = [t for t in nic.trunk if t != network]
    if ip:
        nic.ip = ip
    elif old_ip:
        # The plan keeps a fixed address for it on the new subnet (what the
        # lessons, DNS and relays expect); the machine itself gets it only
        # when someone types it in.
        nic.ip = next_free_ip(lab, network)
    else:
        nic.ip = None
    if old_ip and nic.ip and nic.ip != old_ip:
        # The lab's other machines keep resolving against this one.
        for other in lab.nodes.values():
            for x in other.nics:
                if old_ip in x.dns:
                    x.dns = [nic.ip if d == old_ip else d for d in x.dns]
    return nic


def unplug(lab: Lab, node_id: str, nic_index: int | str) -> Nic:
    """Pull the cable out of nicN (the workbench): the card stays in the
    machine with nothing plugged in, its address forgotten."""
    if not lab.workbench:
        raise EditError("only a workbench network leaves a port without a cable; "
                        "re-cable the machine to another switch instead")
    node, nic = _nic_of(lab, node_id, nic_index)
    if not nic.plugged:
        raise EditError(f"{node_id} nic{nic_index} has no cable in it")
    nic.network, nic.ip, nic.trunk = "", None, []
    return nic


def set_routed(lab: Lab, net_id: str, routed: bool) -> Network:
    """Cable a switch to the lab router (it routes the segment, and can hand
    out addresses there) or take that cable out (the switch stands alone)."""
    net = lab.networks.get(net_id)
    if net is None:
        raise EditError(f"no such network '{net_id}'")
    if not routed and (net.wan or net.site or net.gateway_node):
        raise EditError(f"{net_id} carries the lab's sites or a firewall gateway; "
                        f"it stays on the router")
    if not routed and any(r.segment == net_id for r in lab.firewall.rules):
        raise EditError(f"{net_id} has zone firewall rules on the router; remove them first")
    net.routed = bool(routed)
    if not routed:
        net.dhcp = False
    return net


def set_layout(lab: Lab, positions: dict) -> None:
    """Where devices sit on the workbench canvas: {key: [x, y]} for machine
    ids, "router", "router:<id>" (winlab/routers.py) and "net:<id>"."""
    for key, pos in positions.items():
        key = str(key)
        known = (key == "router" or key in lab.nodes or (key.startswith(("ap:", "router:")) and key in lab.devices)
                 or (key.startswith("net:") and key[4:] in lab.networks))
        if not known:
            continue
        try:
            x, y = int(pos[0]), int(pos[1])
        except (TypeError, ValueError, IndexError):
            raise EditError(f"layout {key!r} must be [x, y]") from None
        lab.layout[key] = [max(0, min(x, 20000)), max(0, min(y, 20000))]
    # Devices that were removed leave the canvas too.
    for key in list(lab.layout):
        if key != "router" and key not in lab.nodes and not (
                key.startswith("net:") and key[4:] in lab.networks) and not (
                key.startswith(("ap:", "router:")) and key in lab.devices):
            del lab.layout[key]


def _tmp_for(dest: Path) -> Path:
    """A temporary of its own for each writer (this process and thread), so
    two saves at once never write into, or move away, each other's file."""
    import os
    import threading
    return dest.with_name(f"{dest.stem}.{os.getpid()}-{threading.get_ident()}.toml.tmp")


LAB_NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


def new_workbench(name: str, description: str = "") -> Path:
    """An empty network to build from nothing: no machines, no switches,
    only the lab router (switch and router in one) on the canvas."""
    from . import paths
    name = name.strip().lower()
    if not LAB_NAME.match(name):
        raise EditError("name the network with 2-31 lower-case letters, digits and dashes, "
                        "starting with a letter (for example my-office)")
    dest = paths.LABS / f"{name}.toml"
    if dest.exists():
        raise EditError(f"there is already a lab called {name}")
    lab = Lab(name=name, description=description or "A network built from nothing on the workbench.",
              workbench=True, sandbox=True, layout={"router": [440, 60]})
    lab.netbios = "CORP"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = _tmp_for(dest)
    tmp.write_text(emit(lab), encoding="utf-8")
    try:
        schema.load(tmp)
    except LabError as exc:
        tmp.unlink(missing_ok=True)
        raise EditError(str(exc)) from exc
    tmp.replace(dest)
    return dest


def tag(lab: Lab, node_id: str, nic_index: int | str, network: str) -> Nic:
    """Carry a second VLAN, tagged, on nicN's cable (a trunk port): what
    dragging a switch onto a machine in the Network map does."""
    node, nic = _nic_of(lab, node_id, nic_index)
    if network not in lab.networks:
        raise EditError(f"no such network '{network}'")
    if network == nic.network:
        raise EditError(f"{network} is already the native VLAN on {node_id} nic{nic_index}; "
                        f"a tag carries a second VLAN on the same cable")
    if not lab.networks[network].vlan:
        raise EditError(f"{network} has no explicit VLAN id in the lab, so its frames cannot be "
                        f"tagged; give it one (vlan = ...) first")
    if network in nic.trunk:
        raise EditError(f"{network} is already tagged on {node_id} nic{nic_index}")
    nic.trunk.append(network)
    return nic


def untag(lab: Lab, node_id: str, nic_index: int | str, network: str) -> Nic:
    """Take a tagged VLAN off nicN's cable."""
    node, nic = _nic_of(lab, node_id, nic_index)
    if network not in nic.trunk:
        raise EditError(f"{network} is not tagged on {node_id} nic{nic_index}")
    nic.trunk.remove(network)
    return nic


def _rename(lab: Lab, node: Node, name: str) -> None:
    """A new computer name. The id stays: disks, MAC addresses, checkpoints,
    firewall rules and lessons keep pointing at the same machine."""
    if name == naming.hostname_of(node):
        return
    err = naming.check_hostname(name)
    if err:
        raise EditError(err)
    why = naming.keeps_its_name(node)
    if why and name.upper() != naming.hostname_of(node).upper() \
            and naming.installed(lab.name, node.id):
        raise EditError(
            f"{naming.hostname_of(node)} is already installed and {why}. Rebuild it from "
            f"its image (winlab lab reset {lab.name} --only {node.id} --yes) and rename "
            f"it before it starts again")
    for other in lab.nodes.values():
        if other is not node and (naming.hostname_of(other).lower() == name.lower()
                                  or other.id.lower() == name.lower()):
            raise EditError(f"{name} is already the name of {other.id}")
    node.hostname = name


def set_lab_names(lab: Lab, *, domain: str | None = None, netbios: str | None = None,
                  share: str | None = None, sites: dict[str, str] | None = None,
                  scopes: dict[str, str] | None = None) -> list[str]:
    """What the student calls the services: the domain and its NetBIOS name,
    the file server's main share, the AD sites, the DHCP scopes. Blank puts
    winlab's default back. Returns what changed, for the caller's message."""
    changed: list[str] = []
    dcs = [n for n in lab.node_list() if "ad-ds" in n.roles]
    built = [n for n in dcs if naming.installed(lab.name, n.id)]

    def frozen(what: str) -> None:
        if built:
            raise EditError(
                f"the forest already exists on {', '.join(naming.hostname_of(n) for n in built)}, "
                f"and {what} is part of it. Rebuild the lab from its images "
                f"(winlab lab reset {lab.name} --yes), then rename it before the first start")

    if domain is not None:
        domain = domain.strip().lower() or naming.AUTHORED_DOMAIN
        if domain != lab.domain:
            err = naming.check_domain(domain)
            if err:
                raise EditError(err)
            frozen("its domain name")
            lab.domain = domain
            changed.append(f"domain {domain}")
            if netbios is None:
                # Windows proposes the first label; so does winlab.
                netbios = domain.split(".")[0].upper()[:15]
    if netbios is not None:
        netbios = netbios.strip().upper() or naming.AUTHORED_NETBIOS
        if netbios != lab.netbios:
            err = naming.check_netbios(netbios)
            if err:
                raise EditError(err)
            frozen("its NetBIOS name")
            lab.netbios = netbios
            changed.append(f"NetBIOS name {netbios}")
    if share is not None:
        share = share.strip()
        new = "" if share in ("", naming.AUTHORED_SHARE) else share
        if new != lab.names.share:
            err = naming.check_share(share) if share else ""
            if err:
                raise EditError(err)
            lab.names.share = new
            changed.append(f"file share {naming.share_name(lab)}")
    for key, name in (sites or {}).items():
        if key not in naming.site_keys(lab):
            raise EditError(f"no machine is in a site {key!r}")
        name = name.strip()
        new = "" if name in ("", key) else name
        if new != lab.names.sites.get(key, ""):
            err = naming.check_site(name) if name else ""
            if err:
                raise EditError(err)
            frozen("its sites")
            if new:
                lab.names.sites[key] = new
            else:
                lab.names.sites.pop(key, None)
            changed.append(f"site {naming.site_name(lab, key)}")
    for key, name in (scopes or {}).items():
        if key not in lab.networks:
            raise EditError(f"no network {key!r}")
        name = name.strip()
        new = "" if name in ("", f"{lab.name}-{key}") else name
        if new != lab.names.scopes.get(key, ""):
            err = naming.check_scope(name) if name else ""
            if err:
                raise EditError(err)
            if new:
                lab.names.scopes[key] = new
            else:
                lab.names.scopes.pop(key, None)
            changed.append(f"DHCP scope {naming.scope_name(lab, key)}")
    return changed


def set_lab_lean(lab: Lab, on: bool) -> None:
    """The Low-memory profile for the whole lab: every Windows machine
    follows the lab unless it says otherwise, so the per-machine values
    are reset to follow."""
    lab.lean = bool(on)
    for node in lab.nodes.values():
        if node.is_windows:
            node.lean = lab.lean


HARDWARE_CHANGES = ("cpus", "memory_mb", "add_disk_gb", "rm_disk", "add_nic", "rm_nic",
                    "iso", "usb_storage_gb", "gpu", "hardware")


def hardware_changes(changes: dict) -> list[str]:
    """Which of these set_node changes alter the virtual hardware: a machine
    that is suspended (hibernated) cannot wake into different hardware."""
    return [k for k in HARDWARE_CHANGES
            if k in changes and changes[k] not in (None, "", 0, False)]


def drop_unchanged(node: Node, changes: dict) -> dict:
    """The set_node changes that really change something: a form that sends
    every field (the Settings dialog's Apply) must not count the vCPUs it
    left alone as a hardware change."""
    cur = {"cpus": node.cpus, "memory_mb": node.memory_mb, "boot_order": node.boot_order,
           "start_delay": node.start_delay, "wait_ready": node.wait_ready, "lean": node.lean,
           "iso": str(node.vars.get("iso") or ""), "gpu": bool(node.vars.get("gpu")),
           "usb_storage_gb": int(node.vars.get("usb_storage_gb") or 0),
           "hardware": node.hardware or HARDWARE_PC, "description": node.description}
    norm = {"iso": lambda v: "" if str(v) in ("", "none") else str(v),
            "hardware": lambda v: str(v or "") or HARDWARE_PC}
    out = {}
    for key, value in changes.items():
        if value is None:
            continue
        if key in cur:
            have = norm[key](value) if key in norm else value
            if type(cur[key]) is int and not isinstance(have, bool):
                try:
                    have = int(have)
                except (TypeError, ValueError):
                    pass
            if have == cur[key]:
                continue
        out[key] = value
    return out


def _set_var(node: Node, key: str, value: object) -> None:
    if value in (None, "", 0, False):
        node.vars.pop(key, None)
    else:
        node.vars[key] = value


def _check_iso(image_id: str) -> str:
    """An ISO to keep in the machine's drive: one the user added, or an
    installer from the catalog. 'none' ejects it."""
    if image_id in ("", "none"):
        return ""
    from .images import CATALOG, custom_images

    if image_id in custom_images() or image_id in CATALOG:
        return image_id
    raise EditError(
        f"no ISO '{image_id}': use one from 'winlab images list' or add yours with "
        f"'winlab images add'"
    )


def _has_domain(lab: Lab) -> bool:
    return any("ad-ds" in n.roles for n in lab.nodes.values())


def _suggest_boot_order(kind: str, roles: list[str]) -> int:
    if "ad-ds" in roles:
        return 10
    if kind == "windows-client":
        return 80
    return 50


# --------------------------------------------------------------------------
# Serialisation (tomllib reads only; winlab writes its own TOML)
# --------------------------------------------------------------------------


def _q(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit(lab: Lab) -> str:
    out: list[str] = []
    out.append("[lab]")
    out.append(f"name = {_q(lab.name)}")
    out.append(f"description = {_q(lab.description)}")
    out.append(f"domain = {_q(lab.domain)}")
    out.append(f"netbios = {_q(lab.netbios)}")
    if lab.password_in_toml:
        out.append(f"admin_password = {_q(lab.admin_password)}")
    out.append(f"timezone = {_q(lab.timezone)}")
    out.append(f"locale = {_q(lab.locale)}")
    if lab.lean:
        out.append("lean = true")
    if lab.workbench:
        out.append("workbench = true")
    elif lab.sandbox:
        out.append("sandbox = true")
    if lab.bare:
        out.append("bare = true")
    if lab.inherited:
        out.append("inherited = true")
    if lab.server_room:
        out.append("server_room = true")
    if lab.exercises:
        items = ", ".join(_q(x) for x in lab.exercises)
        out.append(f"exercises = [{items}]")
    out.append("")

    for site in sorted(lab.sites.values(), key=lambda x: x.id):
        out.append("[[site]]")
        out.append(f"id = {_q(site.id)}")
        if site.description:
            out.append(f"description = {_q(site.description)}")
        if site.gateway:
            out.append(f"gateway = {_q(site.gateway)}")
        out.append("")

    for net in sorted(lab.networks.values(), key=lambda n: n.id):
        out.append("[[network]]")
        out.append(f"id = {_q(net.id)}")
        out.append(f"cidr = {_q(net.cidr)}")
        if net.vlan:
            out.append(f"vlan = {net.vlan}")
        if net.gateway:
            out.append(f"gateway = {_q(net.gateway)}")
        if net.dhcp:
            out.append("dhcp = true")
        if net.wan:
            out.append("wan = true")
        if net.gateway_node:
            out.append(f"gateway_node = {_q(net.gateway_node)}")
        if not net.routed:
            out.append("routed = false")
        if net.vswitch and net.vswitch != "private":
            out.append(f"vswitch = {_q(net.vswitch)}")
        if net.host_ports:
            out.append("host_ports = [" + ", ".join(_q(x) for x in net.host_ports) + "]")
        if net.switch:
            out.append(f"switch = {_q(net.switch)}")
            out.append(f"tag = {net.tag}")
        if net.upstream:
            out.append(f"upstream = {_q(net.upstream)}")
        if net.link:
            out.append("link = true")
        if net.site:
            out.append(f"site = {_q(net.site)}")
        if net.description:
            out.append(f"description = {_q(net.description)}")
        if net.impair.active:
            out.append("  [network.impair]")
            if net.impair.delay_ms:
                out.append(f"  delay_ms = {net.impair.delay_ms}")
            if net.impair.jitter_ms:
                out.append(f"  jitter_ms = {net.impair.jitter_ms}")
            if net.impair.loss_pct:
                out.append(f"  loss_pct = {net.impair.loss_pct}")
            if net.impair.rate_mbit:
                out.append(f"  rate_mbit = {net.impair.rate_mbit}")
        out.append("")

    if not lab.names.empty:
        out.append("[names]")
        if lab.names.share:
            out.append(f"share = {_q(lab.names.share)}")
        for key in ("sites", "scopes"):
            table = getattr(lab.names, key)
            if table:
                out.append(f"  [names.{key}]")
                for k, v in sorted(table.items()):
                    out.append(f"  {_q(k)} = {_q(v)}")
        out.append("")

    fw = lab.firewall
    if fw.enabled or fw.rules:
        out.append("[firewall]")
        out.append(f"enabled = {'true' if fw.enabled else 'false'}")
        for r in sorted(fw.rules, key=lambda x: (x.segment, x.direction, x.priority, x.name)):
            out.append("  [[firewall.rule]]")
            out.append(f"  name = {_q(r.name)}")
            out.append(f"  priority = {r.priority}")
            out.append(f"  direction = {_q(r.direction)}")
            out.append(f"  segment = {_q(r.segment)}")
            out.append(f"  source = {_q(r.source)}")
            out.append(f"  destination = {_q(r.destination)}")
            out.append(f"  ports = {_q(r.ports)}")
            out.append(f"  protocol = {_q(r.protocol)}")
            out.append(f"  action = {_q(r.action)}")
            if r.description:
                out.append(f"  description = {_q(r.description)}")
        out.append("")

    if lab.layout:
        out.append("[layout]")
        for key, (x, y) in sorted(lab.layout.items()):
            out.append(f"{_q(key)} = [{x}, {y}]")
        out.append("")

    for key, table in sorted(lab.devices.items()):
        if not table:
            continue
        out.append(f"[devices.{_q(key)}]")
        for k, v in sorted(table.items()):
            out.append(f"{_q(k)} = {_q(v)}")
        out.append("")

    from . import rack  # the [rack] table (winlab/rack.py)
    out += rack.emit_table(lab.rack)
    from . import campus  # the [campus] table (winlab/campus.py)
    out += campus.emit_table(lab.campus)

    for node in lab.node_list():
        if node.vars.get("devvm"):
            continue  # a device's own VM (an AP, the UPS card): made from the device at load (openwrt.py)
        out.append("[[node]]")
        out.append(f"id = {_q(node.id)}")
        out.append(f"image = {_q(node.image)}")
        out.append(f"kind = {_q(node.kind)}")
        out.append(f"cpus = {node.cpus}")
        out.append(f"memory_mb = {node.memory_mb}")
        if node.hostname and node.hostname.upper() != naming.default_hostname(node.id):
            out.append(f"hostname = {_q(node.hostname)}")
        if node.roles:
            out.append(f"roles = [{', '.join(_q(r) for r in node.roles)}]")
        if node.data_disks_gb:
            out.append(f"data_disks_gb = [{', '.join(str(d) for d in node.data_disks_gb)}]")
        out.append(f"boot_order = {node.boot_order}")
        if node.wait_ready:
            out.append("wait_ready = true")
        if node.start_delay:
            out.append(f"start_delay = {node.start_delay}")
        if node.hardware:
            out.append(f"hardware = {_q(node.hardware)}")
        if node.description:
            out.append(f"description = {_q(node.description)}")
        if node.is_windows and node.lean != lab.lean:
            out.append(f"lean = {'true' if node.lean else 'false'}")
        if node.nested:
            out.append("nested = true")
        if node.firmware:
            out.append(f"firmware = {_q(node.firmware)}")
        if node.vars:
            out.append("  [node.vars]")
            for k, v in node.vars.items():
                out.append(f"  {k} = {_toml_value(v)}")
        for nic in node.nics:
            out.append("  [[node.nic]]")
            out.append(f"  network = {_q(nic.network)}")
            if nic.ip:
                out.append(f"  ip = {_q(nic.ip)}")
            if nic.mac:
                out.append(f"  mac = {_q(nic.mac)}")
            if nic.dns:
                out.append(f"  dns = [{', '.join(_q(d) for d in nic.dns)}]")
            if nic.trunk:
                out.append(f"  trunk = [{', '.join(_q(t) for t in nic.trunk)}]")
        for dev in node.devices:
            out.append("  [[node.device]]")
            out.append(f"  kind = {_q(dev.kind)}")
            out.append(f"  name = {_q(dev.name)}")
            if not dev.shared:
                out.append("  shared = false")
            if dev.driver:
                out.append(f"  driver = {_q(dev.driver)}")
            if dev.location:
                out.append(f"  location = {_q(dev.location)}")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def _toml_value(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return _q(str(v))


def save(lab: Lab, path: str | Path | None = None) -> Path:
    dest = Path(path or lab.source_path)
    if not dest:
        raise EditError("lab has no source path to save to")
    text = emit(lab)

    # Validate the serialised form by round-tripping it, so a bad edit is
    # rejected before it replaces a working file.
    tmp = _tmp_for(dest)
    tmp.write_text(text, encoding="utf-8")
    try:
        reloaded = schema.load(tmp)
        schema.validate(reloaded)
    except LabError as exc:
        tmp.unlink(missing_ok=True)
        raise EditError(f"edit would make the lab invalid:\n{exc}") from exc

    if dest.exists():
        shutil.copy2(dest, dest.with_suffix(".toml.bak"))
    tmp.replace(dest)
    return dest
