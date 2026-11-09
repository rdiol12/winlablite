"""Lab-definition loader and validator. TOML because tomllib is stdlib."""

from __future__ import annotations

import ipaddress
import re
import tomllib
from pathlib import Path

from . import paths
from .model import (
    LINUX,
    HARDWARE,
    DEVICE_KINDS,
    KINDS,
    CUSTOM,
    WINDOWS_CLIENT,
    WINDOWS_SERVER,
    Device,
    Firewall,
    FirewallRule,
    Impairment,
    Lab,
    Names,
    Network,
    Nic,
    Node,
    Site,
)


class LabError(Exception):
    pass


class LabLocked(LabError):
    """The lab ships in the encrypted pack and this PC has no licence for it."""


_REQUIRED_LAB_KEYS = ("name",)


def load(path: str | Path) -> Lab:
    from . import content

    p = Path(path)
    if not content.exists(p):
        candidate = paths.LABS / f"{p.name}"
        if candidate.suffix != ".toml":
            candidate = paths.LABS / f"{p.name}.toml"
        if content.exists(candidate):
            p = candidate
        elif content.locked(candidate):
            raise LabLocked(f"The lab '{candidate.stem}' is part of the full version of winlab. "
                            f"{content.UNLOCK_HINT}")
        else:
            raise LabError(f"lab definition not found: {path}")

    try:
        raw = content.load_toml(p)
    except tomllib.TOMLDecodeError as exc:
        raise LabError(f"{p.name}: malformed TOML: {exc}") from exc

    lab = _build(raw, p)
    from . import openwrt
    openwrt.attach(lab)  # the VMs of the access points and the UPS card (winlab/openwrt.py)
    if not lab.admin_password:
        from . import secrets

        lab.admin_password = secrets.lab_admin_password(lab.name)
    validate(lab)
    return lab


def _build(raw: dict, path: Path) -> Lab:
    meta = raw.get("lab")
    if not isinstance(meta, dict):
        raise LabError(f"{path.name}: missing [lab] table")
    for key in _REQUIRED_LAB_KEYS:
        if not meta.get(key):
            raise LabError(f"{path.name}: [lab] is missing required key '{key}'")

    lab = Lab(
        name=str(meta["name"]),
        domain=str(meta.get("domain", "corp.lab")),
        netbios=str(meta.get("netbios", "")) or _netbios_from(str(meta.get("domain", "corp.lab"))),
        description=str(meta.get("description", "")),
        admin_password=str(meta.get("admin_password", "")),
        password_in_toml=bool(meta.get("admin_password")),
        timezone=str(meta.get("timezone", "UTC")),
        locale=str(meta.get("locale", "en-US")),
        exercises=[str(x) for x in meta.get("exercises", [])],
        source_path=str(path),
        lean=bool(meta.get("lean", False)),
        sandbox=bool(meta.get("sandbox", False)),
        bare=bool(meta.get("bare", False)),
        workbench=bool(meta.get("workbench", False)),
        inherited=bool(meta.get("inherited", False)),
        server_room=bool(meta.get("server_room", False)),
    )
    # A workbench network is free play: no lessons or grading attach to it.
    lab.sandbox = lab.sandbox or lab.workbench
    layout = raw.get("layout", {})
    if not isinstance(layout, dict):
        raise LabError(f"{path.name}: [layout] must be a table of device = [x, y]")
    for key, pos in layout.items():
        if (not isinstance(pos, list) or len(pos) != 2
                or not all(isinstance(v, (int, float)) for v in pos)):
            raise LabError(f"{path.name}: layout {key!r} must be [x, y]")
        lab.layout[str(key)] = [int(pos[0]), int(pos[1])]
    devices = raw.get("devices", {})
    if not isinstance(devices, dict) or not all(isinstance(v, dict) for v in devices.values()):
        raise LabError(f"{path.name}: [devices.<device>] must be tables of setting = \"value\"")
    for key, table in devices.items():
        lab.devices[str(key)] = {str(k): str(v) for k, v in table.items()}
    from . import rack  # the rack's [rack] table: positions, tags, cable labels
    lab.rack = rack.parse_table(raw.get("rack"), path.name)
    from . import campus  # a client job's site: cables, patches, devices (winlab/campus.py)
    lab.campus = campus.parse_table(raw.get("campus"), path.name)

    for entry in raw.get("site", []):
        if not isinstance(entry, dict) or not entry.get("id"):
            raise LabError(f"{path.name}: a [[site]] entry is missing 'id'")
        sid = str(entry["id"])
        if sid in lab.sites:
            raise LabError(f"{path.name}: duplicate site id '{sid}'")
        lab.sites[sid] = Site(id=sid, description=str(entry.get("description", "")),
                              gateway=str(entry.get("gateway", "")))

    for entry in raw.get("network", []):
        net = _build_network(entry, path)
        if net.id in lab.networks:
            raise LabError(f"{path.name}: duplicate network id '{net.id}'")
        lab.networks[net.id] = net

    for entry in raw.get("node", []):
        node = _build_node(entry, path, lean_default=lab.lean)
        if node.id in lab.nodes:
            raise LabError(f"{path.name}: duplicate node id '{node.id}'")
        lab.nodes[node.id] = node

    fw = raw.get("firewall")
    if fw is not None:
        if not isinstance(fw, dict):
            raise LabError(f"{path.name}: [firewall] must be a table")
        lab.firewall = _build_firewall(fw, path)

    names = raw.get("names")
    if names is not None:
        lab.names = _build_names(names, path)

    return lab


def _build_names(entry: dict, path: Path) -> Names:
    """[names]: what the student called the services winlab builds (see
    winlab/naming.py); sites and scopes are tables keyed by what winlab
    would otherwise call them."""
    if not isinstance(entry, dict):
        raise LabError(f"{path.name}: [names] must be a table")
    out = Names(share=str(entry.get("share", "") or ""))
    for key in ("sites", "scopes"):
        t = entry.get(key, {})
        if not isinstance(t, dict):
            raise LabError(f"{path.name}: [names.{key}] must be a table")
        setattr(out, key, {str(k): str(v) for k, v in t.items() if str(v)})
    return out


def _build_firewall(entry: dict, path: Path) -> Firewall:
    """[firewall] turns the zone firewall on (unless it says enabled = false);
    each [[firewall.rule]] joins one segment's table."""
    fw = Firewall(enabled=bool(entry.get("enabled", True)))
    for r in entry.get("rule", []):
        if not isinstance(r, dict) or not r.get("name"):
            raise LabError(f"{path.name}: a [[firewall.rule]] is missing 'name'")
        if r.get("priority") is None:
            raise LabError(f"{path.name}: firewall rule '{r['name']}' is missing 'priority'")
        fw.rules.append(FirewallRule(
            name=str(r["name"]),
            priority=int(r["priority"]),
            direction=str(r.get("direction", "inbound")),
            segment=str(r.get("segment", "")),
            source=str(r.get("source", "Any")),
            destination=str(r.get("destination", "Any")),
            ports=str(r.get("ports", "*")),
            protocol=str(r.get("protocol", "Any")),
            action=str(r.get("action", "Allow")),
            description=str(r.get("description", "")),
        ))
    return fw


def _netbios_from(domain: str) -> str:
    return domain.split(".")[0].upper()[:15]


def _build_network(entry: dict, path: Path) -> Network:
    if not entry.get("id"):
        raise LabError(f"{path.name}: a [[network]] entry is missing 'id'")
    if not entry.get("cidr"):
        raise LabError(f"{path.name}: network '{entry['id']}' is missing 'cidr'")
    imp = entry.get("impair", {})
    return Network(
        id=str(entry["id"]),
        cidr=str(entry["cidr"]),
        vlan=int(entry["vlan"]) if entry.get("vlan") is not None else None,
        gateway=str(entry["gateway"]) if entry.get("gateway") else None,
        dhcp=bool(entry.get("dhcp", False)),
        wan=bool(entry.get("wan", False)),
        description=str(entry.get("description", "")),
        site=str(entry.get("site", "")),
        gateway_node=str(entry.get("gateway_node", "")),
        routed=bool(entry.get("routed", True)),
        switch=str(entry.get("switch", "")),
        tag=int(entry.get("tag", 0) or 0),
        upstream=str(entry.get("upstream", "")),
        link=bool(entry.get("link", False)),
        vswitch=str(entry.get("vswitch", "private") or "private").lower(),
        host_ports=[str(x) for x in entry.get("host_ports", []) or []],
        impair=Impairment(
            delay_ms=int(imp.get("delay_ms", 0)),
            jitter_ms=int(imp.get("jitter_ms", 0)),
            loss_pct=float(imp.get("loss_pct", 0.0)),
            rate_mbit=int(imp.get("rate_mbit", 0)),
        ),
    )


def _build_node(entry: dict, path: Path, lean_default: bool = False) -> Node:
    if not entry.get("id"):
        raise LabError(f"{path.name}: a [[node]] entry is missing 'id'")
    nid = str(entry["id"])
    if not entry.get("image"):
        raise LabError(f"{path.name}: node '{nid}' is missing 'image'")

    nics: list[Nic] = []
    for spec in entry.get("nic", []):
        # `network = ""` is a port with no cable in it (the workbench);
        # leaving the key out is a mistake.
        if "network" not in spec:
            raise LabError(f"{path.name}: a nic on node '{nid}' is missing 'network'")
        nics.append(
            Nic(
                network=str(spec["network"]),
                ip=str(spec["ip"]) if spec.get("ip") else None,
                mac=str(spec.get("mac", "")).lower(),
                dns=[str(x) for x in spec.get("dns", [])],
                trunk=[str(x) for x in spec.get("trunk", [])],
            )
        )

    devices: list[Device] = []
    for spec in entry.get("device", []):
        if not spec.get("kind") or not spec.get("name"):
            raise LabError(f"{path.name}: a device on node '{nid}' needs 'kind' and 'name'")
        devices.append(
            Device(
                kind=str(spec["kind"]),
                name=str(spec["name"]),
                shared=bool(spec.get("shared", True)),
                driver=str(spec.get("driver", "")),
                location=str(spec.get("location", "")),
                vars=dict(spec.get("vars", {})),
            )
        )

    image = str(entry["image"])
    if entry.get("edition"):
        # `edition = "core"` (Server Core) or "desktop" picks the base of
        # that installation option for a Windows Server image.
        from .servercore import with_edition
        try:
            image = with_edition(image, entry["edition"])
        except ValueError as exc:
            raise LabError(f"{path.name}: node '{nid}': {exc}") from None

    return Node(
        id=nid,
        image=image,
        kind=str(entry.get("kind", WINDOWS_SERVER)),
        cpus=int(entry.get("cpus", 2)),
        memory_mb=int(entry.get("memory_mb", 2048)),
        hostname=str(entry.get("hostname", "")) or nid.upper()[:15],
        nics=nics,
        roles=[str(x) for x in entry.get("roles", [])],
        data_disks_gb=[int(x) for x in entry.get("data_disks_gb", [])],
        devices=devices,
        boot_order=int(entry.get("boot_order", 50)),
        wait_ready=bool(entry.get("wait_ready", False)),
        start_delay=int(entry.get("start_delay", 0)),
        hardware=str(entry.get("hardware", "")),
        description=str(entry.get("description", "")),
        vars=dict(entry.get("vars", {})),
        lean=bool(entry.get("lean", lean_default)),
        nested=bool(entry.get("nested", False)),
        firmware=str(entry.get("firmware", "")),
    )


MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_START_DELAY = 900


def _pacing_errors(lab: Lab) -> list[str]:
    errs = []
    for node in lab.nodes.values():
        if not 0 <= node.start_delay <= MAX_START_DELAY:
            errs.append(f"node '{node.id}': start_delay is 0 to {MAX_START_DELAY} seconds, "
                        f"got {node.start_delay}")
        if node.hardware not in HARDWARE:
            errs.append(f"node '{node.id}': hardware is 'pc' or 'virtio', not {node.hardware!r}")
        if node.hardware and not node.is_windows:
            errs.append(f"node '{node.id}': hardware applies to Windows machines only")
        # Windows 11 Enterprise needs the processor's virtualization for the
        # hypervisor that virtualization-based security (Credential Guard,
        # memory integrity) runs in, the same as Hyper-V on a server.
        if node.nested and node.kind not in (WINDOWS_SERVER, WINDOWS_CLIENT):
            from .nestedvirt import HAND_LINUX, is_linux
            if not is_linux(node):
                errs.append(f"node '{node.id}': nested virtualization (Hyper-V or KVM inside the machine) is "
                            f"for Windows machines, the Ubuntu appliance and Linux installed by hand "
                            f"({', '.join(HAND_LINUX)}) only")
        if node.firmware or node.vars.get("secure_boot_template"):
            from . import firmware, secureboot
            if node.firmware and node.firmware not in firmware.CHOICES:
                errs.append(f"node '{node.id}': firmware is one of {', '.join(firmware.CHOICES)}, "
                            f"not {node.firmware!r}")
            elif not firmware.fitted(node):
                errs.append(f"node '{node.id}': the firmware choice is for Windows machines only")
            tpl = node.vars.get("secure_boot_template")
            if tpl and tpl not in secureboot.TEMPLATES:
                errs.append(f"node '{node.id}': secure_boot_template is one of "
                            f"{', '.join(secureboot.TEMPLATES)}, not {tpl!r}")
        if node.wait_ready and not node.is_windows:
            errs.append(f"node '{node.id}': wait_ready needs the winlab agent, which only "
                        f"Windows machines run")
    return errs


def validate(lab: Lab) -> None:
    errs: list[str] = _pacing_errors(lab)

    if not lab.networks and not lab.workbench:
        errs.append("lab defines no [[network]] segments")
    if not lab.nodes and not lab.workbench:
        errs.append("lab defines no [[node]] machines")

    for net in lab.networks.values():
        try:
            parsed = net.net
        except ValueError as exc:
            errs.append(f"network '{net.id}': bad cidr {net.cidr!r}: {exc}")
            continue
        if parsed.prefixlen > 30:
            errs.append(f"network '{net.id}': prefix /{parsed.prefixlen} leaves no usable hosts")
        if net.gateway:
            try:
                gw = ipaddress.ip_address(net.gateway)
            except ValueError as exc:
                errs.append(f"network '{net.id}': bad gateway {net.gateway!r}: {exc}")
            else:
                if gw not in parsed:
                    errs.append(
                        f"network '{net.id}': gateway {net.gateway} is outside {net.cidr}"
                    )

    tags: dict[tuple[str, int], str] = {}
    for net in lab.networks.values():
        if not net.switch:
            continue
        parent = lab.networks.get(net.switch)
        if parent is None or parent.switch:
            errs.append(f"network '{net.id}': switch {net.switch!r} is not a switch of this lab")
        if not 2 <= net.tag <= 4094:
            errs.append(f"network '{net.id}': a switch's VLAN is numbered 2 to 4094 (1 is the switch's own)")
        elif (net.switch, net.tag) in tags:
            errs.append(f"network '{net.id}': VLAN {net.tag} is on switch {net.switch} twice "
                        f"({tags[(net.switch, net.tag)]})")
        tags[(net.switch, net.tag)] = net.id

    for net in lab.networks.values():
        if not net.upstream:
            continue
        up = lab.networks.get(net.upstream)
        if net.switch or up is None or up.switch or up.id == net.id:
            errs.append(f"network '{net.id}': upstream {net.upstream!r} is not another switch of this lab")
            continue
        if any(n.routed for n in lab.networks.values() if n.home == net.id):
            errs.append(f"network '{net.id}': its uplink goes to switch {net.upstream}, so the "
                        f"router cannot route it (routed = false)")
        hop, seen = up, {net.id}
        while hop is not None and hop.upstream:
            if hop.id in seen:
                errs.append(f"network '{net.id}': the switches' uplinks go round in a loop")
                break
            seen.add(hop.id)
            hop = lab.networks.get(hop.upstream)

    seen_ips: dict[tuple[str, str], str] = {}
    for node in lab.nodes.values():
        if node.kind not in KINDS:
            errs.append(
                f"node '{node.id}': unknown kind {node.kind!r} (expected one of {sorted(KINDS)})"
            )
        if node.cpus < 1:
            errs.append(f"node '{node.id}': cpus must be >= 1")
        if node.memory_mb < node.memory_floor_mb:
            what = {WINDOWS_SERVER: "Server Core" if node.is_server_core else "Windows Server",
                    WINDOWS_CLIENT: "Windows 11"}.get(node.kind, "a machine")
            errs.append(
                f"node '{node.id}': {what} needs >= {node.memory_floor_mb} MB "
                f"(got {node.memory_mb})"
            )
        if not node.nics and not lab.workbench:
            errs.append(f"node '{node.id}': has no [[node.nic]], so it cannot reach the lab")
        from .servercore import role_errors
        errs.extend(role_errors(node))
        if node.kind == CUSTOM and node.roles:
            errs.append(
                f"node '{node.id}': a custom machine runs no winlab agent, so it cannot "
                f"take roles ({', '.join(node.roles)}); configure it by hand in its window"
            )
        if node.kind == LINUX:
            from .images import LINUX_IMAGES, is_template
            if node.image not in LINUX_IMAGES and not is_template(node.image):
                errs.append(
                    f"node '{node.id}': a linux machine runs one of {', '.join(LINUX_IMAGES)} "
                    f"(or a template made from one), not '{node.image}'"
                )

        for dev in node.devices:
            if dev.kind not in DEVICE_KINDS:
                errs.append(
                    f"node '{node.id}': device '{dev.name}' has unknown kind "
                    f"{dev.kind!r} (expected {sorted(DEVICE_KINDS)})"
                )
            if node.kind not in (WINDOWS_SERVER, WINDOWS_CLIENT):
                errs.append(
                    f"node '{node.id}': only Windows nodes can host a {dev.kind} "
                    f"('{dev.name}')"
                )

        for idx, nic in enumerate(node.nics):
            if nic.mac and not MAC.match(nic.mac):
                errs.append(f"node '{node.id}' nic{idx}: bad mac {nic.mac!r} "
                            f"(expected six hex pairs like 52:54:00:12:34:56)")
            if not nic.plugged:
                # A lesson lab may leave a second port for the student to cable
                # (a storage array's port 2); a machine's first port is its address,
                # unless it is a laptop's radio card on the real air (winlab/vwifi.py).
                if not lab.workbench and idx == 0 and str(node.vars.get("air", "")) != "0":
                    errs.append(f"node '{node.id}' nic{idx}: has no network (only a "
                                f"workbench network leaves a port without a cable)")
                if nic.ip or nic.trunk:
                    errs.append(f"node '{node.id}' nic{idx}: an unplugged port carries no "
                                f"address and no tagged VLANs")
                continue
            if nic.network not in lab.networks:
                errs.append(
                    f"node '{node.id}' nic{idx}: references undefined network {nic.network!r}"
                )
                continue
            net = lab.networks[nic.network]

            for tagged in nic.trunk:
                if tagged not in lab.networks:
                    errs.append(
                        f"node '{node.id}' nic{idx}: trunk references undefined "
                        f"network {tagged!r}"
                    )
                elif tagged == nic.network:
                    errs.append(
                        f"node '{node.id}' nic{idx}: {tagged!r} is already the native vlan "
                        f"on this port and cannot also be trunked"
                    )
                elif not lab.networks[tagged].vlan:
                    errs.append(
                        f"node '{node.id}' nic{idx}: cannot trunk network {tagged!r} because "
                        f"it has no explicit 'vlan' id (tagged frames need a known tag)"
                    )

            if nic.ip:
                try:
                    addr = ipaddress.ip_address(nic.ip)
                except ValueError as exc:
                    errs.append(f"node '{node.id}' nic{idx}: bad ip {nic.ip!r}: {exc}")
                    continue
                if addr not in net.net:
                    errs.append(
                        f"node '{node.id}' nic{idx}: ip {nic.ip} is outside "
                        f"network '{net.id}' ({net.cidr})"
                    )
                # A switch the router is not cabled to has no router address to
                # collide with: its first host is free for a router machine the
                # student builds (winlab/routing.py).
                if net.routed and str(addr) == net.router_ip:
                    errs.append(
                        f"node '{node.id}' nic{idx}: ip {nic.ip} collides with the fabric "
                        f"router address for '{net.id}'"
                    )
                key = (net.id, str(addr))
                if key in seen_ips:
                    errs.append(
                        f"node '{node.id}' nic{idx}: ip {nic.ip} on '{net.id}' is already "
                        f"used by node '{seen_ips[key]}'"
                    )
                else:
                    seen_ips[key] = node.id
            # A card set to DHCP with no server anywhere is a PC fresh out of
            # the box on a LAN nobody has set up yet: the student builds the
            # DHCP server (or the router's pool), so it is no error.

    for net in lab.networks.values():
        if not net.gateway_node:
            continue
        gw = lab.nodes.get(net.gateway_node)
        nic = next((n for n in (gw.nics if gw else []) if n.network == net.id and n.ip), None)
        if gw is None:
            errs.append(f"network '{net.id}': gateway_node {net.gateway_node!r} is not a machine of the lab")
        elif nic is None:
            errs.append(f"network '{net.id}': gateway_node {net.gateway_node} has no static address on it")
        elif net.wan:
            errs.append(f"network '{net.id}': a wan segment has no gateway_node; the lab router is its way out")
        else:
            net.hosts_gateway = nic.ip or ""

    _validate_domain_shape(lab, errs)

    from . import firewall, naming, sites, vswitch
    errs.extend(vswitch.validate(lab))
    errs.extend(sites.validate(lab))
    errs.extend(firewall.validate(lab))
    errs.extend(naming.validate(lab))

    if errs:
        raise LabError("invalid lab definition:\n  - " + "\n  - ".join(errs))


def _validate_domain_shape(lab: Lab, errs: list[str]) -> None:
    dcs = [n for n in lab.nodes.values() if "ad-ds" in n.roles]
    joiners = [n for n in lab.nodes.values() if "domain-join" in n.roles]

    if joiners and not dcs:
        errs.append(
            "nodes request role 'domain-join' but no node has role 'ad-ds', "
            "so there is no domain to join"
        )

    for dc in dcs:
        nic = dc.primary_nic
        if nic and nic.dhcp:
            errs.append(
                f"node '{dc.id}': a domain controller must have a static ip on its first nic"
            )
        if dc.boot_order >= 50:
            errs.append(
                f"node '{dc.id}': domain controller should boot before members "
                f"(set boot_order below 50, got {dc.boot_order})"
            )

    roots = [n.id for n in dcs if n.vars.get("forest_root", False)]
    if len(roots) > 1:
        errs.append(
            f"nodes {', '.join(sorted(roots))} all set vars.forest_root = true; exactly one "
            f"node creates the forest and the rest join it as additional DCs"
        )
    elif len(dcs) > 1 and not roots:
        errs.append(
            f"lab has {len(dcs)} domain controllers but none sets vars.forest_root = true, "
            f"so no node would create the forest"
        )
