"""The network workbench: a network built from nothing, device by device.

The desktop's Workbench window is a canvas in the manner of a network
simulator, except every device on it is real: a Server is a QEMU machine
that boots Microsoft's evaluation DVD on an empty disk (or a ready-made
one), a Switch is a VLAN on the lab router's bridge, a cable is a port on
it. This module is the window's backend: what is on the canvas, what the
router sees on the wire (addresses, traffic), and the actions of the device
shelf, the cables and the inside of a machine (its parts).

Changes to a running network go through winlab/livenet.py, so a cable goes
in or out, or moves, while the machines run; parts (processors, memory,
disks, network cards) change with the machine off, as on a real PC.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from pathlib import Path

from . import appliance, devcli, editor, hardware, images, livenet, media, mediashelf, naming, netplan, paths, state, wan, wifi
from . import linuxiso
from . import adminui
from . import bsdfw
from .model import CUSTOM, LINUX, WINDOWS_CLIENT, WINDOWS_SERVER, Nic
from . import imaging
from . import firmware, nestedvirt

# What the device shelf offers. `make` is how the machine is made:
# "hand" boots the Setup DVD on an empty disk, "ready" clones a prepared
# base (installing it first when there is none), "appliance" a fetched
# image, "iso" the user's own disc.
SHELF = [
    {"id": "server", "title": "Server", "kind": WINDOWS_SERVER, "prefix": "srv",
     "images": ["ws2025", "ws2022", "ws2019"], "default": "ws2025",
     "text": "Windows Server you install yourself from the evaluation DVD, or a ready-made one"},
    {"id": "pc", "title": "PC", "kind": WINDOWS_CLIENT, "prefix": "pc",
     "images": ["win11", "win10"], "default": "win11",
     "text": "a Windows desktop you install yourself, or a ready-made one"},
    {"id": "laptop", "title": "Laptop", "kind": WINDOWS_CLIENT, "prefix": "lap",
     "images": ["win11", "win10"], "default": "win11",
     "text": "a Windows laptop with a wireless card: it joins the Wi-Fi of the access points in range"},
    {"id": "linux", "title": "Linux server", "kind": LINUX, "prefix": "lx",
     "images": ["ubuntu", "ubuntu24", "rocky9", "rhel9", "rhel10", "debian13", "alpine-std"], "default": "ubuntu",
     "text": "Linux you install yourself from the distribution's DVD, or Ubuntu Server ready-made"},
    {"id": "firewall", "title": "Firewall", "kind": LINUX, "prefix": "fw",
     "images": ["opnsense-dvd", "pfsense-ce", "opnsense"], "default": "opnsense-dvd",
     "text": "OPNsense or pfSense CE you install yourself from the project's installer, or OPNsense ready-made; two ports or more"},
    {"id": "iso", "title": "Your own disc", "kind": CUSTOM, "prefix": "box",
     "images": [], "default": "",
     "text": "any operating system from an ISO you add (another Linux, an older Windows)"},
    {"id": "printer", "title": "Printer", "kind": LINUX, "prefix": "prn",
     "images": ["alpine"], "default": "alpine",
     "text": "a network laser printer running CUPS: set up its queue in its web pages, Windows prints to it over IPP or TCP/IP, pages land in its tray"},
    {"id": "nas", "title": "NAS", "kind": LINUX, "prefix": "nas",
     "images": ["debian13-cloud"], "default": "debian13-cloud",
     "text": "network storage running OpenMediaVault: a data disk in its bay; file systems, shares, users "
             "and SMB/NFS set up in its web UI from a lab PC"},
    {"id": "san", "title": "SAN", "kind": LINUX, "prefix": "san",
     "images": ["alpine"], "default": "alpine",
     "text": "an iSCSI storage array: fill its bays with blank drives, cable both ports, build RAID groups, volumes and targets in its Webmin"},
    {"id": "phone", "title": "IP phone", "kind": LINUX, "prefix": "phone",
     "images": ["alpine"], "default": "alpine",
     "text": "a desk phone: a SIP softphone on its screen; you sign it in to the phone system yourself"},
    {"id": "camera", "title": "IP camera", "kind": LINUX, "prefix": "cam",
     "images": ["alpine"], "default": "alpine",
     "text": "an IP camera on the ceiling or an outside wall: it takes its address by DHCP; set its name, clock and admin password in its own web pages"},
    {"id": "pbx", "title": "Phone system", "kind": LINUX, "prefix": "pbx",
     "images": ["debian12"], "default": "debian12",
     "text": "the office PBX: FreePBX 17 on Asterisk, managed from a lab PC's browser; no extensions until you make them"},
    {"id": "ntp", "title": "NTP server", "kind": LINUX, "prefix": "ntp",
     "images": ["alpine"], "default": "alpine",
     "text": "a time server (chrony): serves lab time to the PDC emulator and the Linux machines, no upstream"},
    {"id": "doctools", "title": "Admin tools server", "kind": LINUX, "prefix": "tools",
     "images": ["debian12"], "default": "debian12",
     "text": "the IT department's own tools on Debian 12: an asset inventory (GLPI), a wiki (DokuWiki) and a "
             "password vault (Vaultwarden), each installed by you from its pack and used from a lab PC's browser"},
    {"id": "adminpc", "title": "Admin workstation", "kind": LINUX, "prefix": "admin",
     "images": ["alpine"], "default": "alpine",
     "text": "a small Linux desktop with Firefox ESR: a browser on the lab network to open the devices' own pages"},
    {"id": "ap", "title": "Access point", "kind": "ap", "prefix": "ap",
     "images": [], "default": "", "text": "a Wi-Fi access point (OpenWrt): cable it to a switch, set it up in its own web pages, laptops in range join its network"},
    {"id": "switch", "title": "Switch", "kind": "switch", "prefix": "sw",
     "images": [], "default": "", "text": "a VLAN-aware switch; cable it to the router to route it"},
]
SHELF_BY_ID = {s["id"]: s for s in SHELF}

MAX_PORTS = 8


class WorkbenchError(Exception):
    pass


def _free_id(taken, prefix: str) -> str:
    for i in range(1, 100):
        cand = f"{prefix}{i:02d}" if prefix != "sw" else f"sw{i}"
        if cand not in taken:
            return cand
    raise WorkbenchError(f"no free name left for another {prefix}")


_running = state.running   # a seam the tests replace


def _time_of(lab, node) -> dict:
    """Its clock's offset from lab time and, on an NTP server, its settings
    (winlab/timesync.py)."""
    from . import timesync
    out = {"skew": timesync.skew_of(lab.name, node.id)}
    if timesync.ROLE in node.roles:
        out["ntp"] = {"stratum": timesync.stratum(node), "allow": timesync.allow_list(lab, node),
                      "all": not node.vars.get("ntp_allow")}
    return out


def _how(node) -> str:
    if imaging.is_netboot(node):
        return "netboot"
    if images.is_hand_install(node):
        return "hand"
    if node.kind == CUSTOM:
        return "iso"
    if node.kind == LINUX:
        return "appliance" if node.image != "alpine" else "probe"
    return "ready"


def _shelf_of(node) -> str:
    dev = appliance.device_of(node)
    if dev:
        return dev
    if (node.kind == LINUX and node.image == "opnsense") or bsdfw.is_hand_firewall(node):
        return "firewall"
    if node.kind == LINUX or linuxiso.is_hand_linux(node):
        return "linux"
    if node.kind == CUSTOM and node.image not in images.HAND_INSTALL:
        return "iso"
    if node.vars.get("form") == "laptop":
        return "laptop"
    if node.kind == WINDOWS_CLIENT or (node.kind == CUSTOM and images.CATALOG[node.image].kind == WINDOWS_CLIENT):
        return "pc"
    return "server"


def _os_title(node) -> str:
    dev = appliance.device_of(node)
    if dev:
        return {"printer": "network printer", "nas": "network storage", "phone": "IP phone", "camera": "IP camera",
                "pbx": "phone system", "ntp": "NTP server", "san": "storage array (iSCSI)",
                "adminpc": "Linux desktop (Firefox ESR)", "doctools": "Debian 12 (admin tools server)"}[dev]
    if imaging.is_netboot(node):
        return "no operating system"
    if node.kind == CUSTOM and node.image in images.HAND_INSTALL:
        return images.CATALOG[node.image].short
    if node.kind == CUSTOM:
        mine = images.custom_images().get(node.image)
        return mine.title if mine else node.image
    root = images.catalog_root(node.image)
    return root.short if root else node.image


def _auto_layout(lab) -> dict[str, list[int]]:
    """Positions for devices the canvas has none for: switches in a row
    under the router, machines in a row under their switch."""
    out = {k: list(v) for k, v in lab.layout.items()}
    out.setdefault("router", [440, 60])
    rx, ry = out["router"]
    for i, nid in enumerate(devcli.switches(lab)):
        out.setdefault(f"net:{nid}", [120 + i * 260, ry + 180])
    for i, ap in enumerate(wifi.aps(lab).values()):
        net = lab.networks.get(ap["network"])
        sx, sy = out.get(f"net:{net.home}", [rx + 260, ry]) if net else [rx + 260, ry]
        out.setdefault(wifi.PREFIX + ap["id"], [sx + 260, sy + 20 + i * 90])
    count: dict[str, int] = {}
    for node in lab.node_list():
        if node.id in out:
            continue
        net = next((n.network for n in node.nics if n.plugged), "")
        net = lab.networks[net].home if net in lab.networks else net
        sx, sy = out.get(f"net:{net}", [60, ry + 180])
        k = count.get(net, 0)
        count[net] = k + 1
        out[node.id] = [sx - 80 + k * 130, sy + 170]
    return out


def _bay_lights(lab_name: str, node) -> dict:
    """What a machine's drive-bay LEDs show: failing drives (amber), the
    bays whose locate LED is on (blue; -1 the system disk) and a dead system
    disk."""
    from . import disks, sysdisk
    nd = paths.lab_dir(lab_name) / node.id
    return {"failing": sorted(disks.failing_in(nd, len(node.data_disks_gb))),
            "locate": sorted(disks.located(nd)), "sys_dead": sysdisk.dead(nd)}


def view(dash) -> dict:
    """Everything on the canvas, from the lab definition and the machines'
    run state (live addresses come from live())."""
    lab, plan = dash.lab, dash.plan
    from . import nms  # links that went up or down since the last look: logged, to syslog and SNMP
    nms.tick(dash)
    running = _running(lab.name)
    st = state.load(lab.name)
    layout = _auto_layout(lab)
    by_switch = devcli.switch_ports(lab, plan, layout)
    shelf = mediashelf.view(lab, running)
    slots = {l.label: i for ports in by_switch.values() for i, l in enumerate(ports) if l is not None}
    machines = []
    for node in lab.node_list():
        if node.vars.get("devvm"):
            continue  # an AP's or the UPS card's own VM: drawn as that device (winlab/openwrt.py)
        ns = st.nodes.get(node.id) if st else None
        ports = []
        for link in plan.ports_for(node.id):
            nic = node.nics[link.nic_index]
            ports.append({"index": link.nic_index, "network": link.network_id,
                          "ip": nic.ip or "", "mac": link.mac, "plugged": link.plugged,
                          "trunk": list(link.trunk_vlans), "slot": slots.get(link.label, -1),
                          "home": lab.networks[link.network_id].home if link.plugged else "",
                          "vlan": lab.networks[link.network_id].vlan_no if link.plugged else 0,
                          "segment": plan.segment_of(link.network_id).network.id if link.plugged else "",
                          "shut": devcli.held_down(lab, link),
                          # what the switch port was set to (speed, duplex): its front panel's MODE LEDs
                          **_port_speed(lab, link)})
        disk = paths.lab_dir(lab.name) / node.id / "system.qcow2"
        machines.append({
            "id": node.id, "name": naming.hostname_of(node), "shelf": _shelf_of(node),
            "how": _how(node), "kind": node.kind, "image": node.image, "os": _os_title(node),
            "cpus": node.cpus, "memory_mb": node.memory_mb,
            "disk_gb": int(node.vars.get("disk_gb") or (images.HAND_DISK_GB if images.is_hand_install(node) else 0)),
            "data_disks_gb": list(node.data_disks_gb),
            "pulled": sorted(hardware.pulled(lab.name, node.id, len(node.data_disks_gb))),
            **_bay_lights(lab.name, node),  # the front panel's drive LEDs (winlab/disks.py, sysdisk.py)
            "stick": media.stick_path(lab.name, node.id).exists(),
            "installed": disk.exists(),
            "iso": str(node.vars.get("iso") or ""),
            "distro": linuxiso.boot_hint(node.image) if linuxiso.is_hand_linux(node) else
                      bsdfw.boot_hint(node.image) if bsdfw.is_hand_firewall(node) else "",
            "media": shelf["machines"].get(node.id),
            "running": node.id in running, "phase": ns.phase if ns else "stopped",
            "ports": ports, "pos": layout.get(node.id),
            "agent": node.is_windows,
            "device": appliance.device_of(node),
            **_time_of(lab, node),
            "wireless": wifi.wireless(node),
            "pxe": imaging.pxe_view(lab, plan, node),
            "vtx": nestedvirt.view(lab, node, nestedvirt.accel_of(dash)),  # Hyper-V inside (nestedvirt.py)
            "fw": firmware.view(lab, node, nestedvirt.accel_of(dash)),  # boot mode, Secure Boot (firmware.py)
            **(_wifi_of(lab, layout, node) if wifi.wireless(node) else {}),
            **adminui.node_view(lab, node),  # its own management pages (winlab/adminui.py)
        })
    devcli.pin_router_ports(lab)
    rports = devcli.cabled_ports(lab)
    switches = []
    for nid, net in sorted(lab.networks.items()):
        seg = plan.segment_of(nid)
        snet = seg.network  # the network it is part of, over a trunk to another switch
        used = len(by_switch.get(nid, []))
        switches.append({"id": nid, "cidr": snet.cidr, "vlan": seg.vid, "routed": snet.routed,
                         "gateway": snet.router_ip if snet.routed else "", "dhcp": bool(snet.dhcp),
                         "dhcp_mode": netplan.dhcp_mode(plan, seg) if snet.routed else (
                             "server" if any("dhcp" in n.roles for n in lab.nodes_on(nid)) else "none"),
                         "segment": snet.id, "upstream": net.upstream,
                         "ports": used + (len(wifi.on_switch(lab, nid)) if net.home == nid else 0),
                         "pos": layout.get(f"net:{nid}"),
                         "description": net.description,
                         "name": devcli.hostname(lab, f"sw:{net.home}"),
                         "switch": net.switch, "tag": net.vlan_no,
                         "uplink": net.home in rports,
                         "off": devcli.switch_off(lab, net.home),
                         "rport": devcli.short_if(rports.get(net.home, "")),
                         "wan": _wan_of(lab, nid), "site": wan.site_of(lab, nid)})
    from . import consolecable  # the console cables (winlab/consolecable.py)
    return _power_of(lab, plan, running, by_switch, {
        "lab": lab.name, "workbench": lab.workbench,
        "console": consolecable.view(lab, running),
        "admin_targets": adminui.lab_view(lab),
        "router": {"running": "fabric" in running, "pos": layout["router"],
                   "name": devcli.hostname(lab, devcli.ROUTER),
                   "ports": [{"name": devcli.short_if(n), "network": nid,
                              "up": bool(nid) and not devcli.router_shut(lab, n)}
                             for n, nid in devcli.router_ports(lab)]},
        "machines": machines, "switches": switches,
        "aps": _aps_view(lab, layout, slots_after={nid: len(p) for nid, p in by_switch.items()}, running=running),
        "wan_presets": [{"id": k, "title": t, "text": l.text(), "delay_ms": l.delay_ms, "jitter_ms": l.jitter_ms,
                         "loss_pct": l.loss_pct, "rate_mbit": l.rate_mbit} for k, (t, l) in wan.PRESETS.items()],
        "shelf": _shelf_state(),
        "max_ports": MAX_PORTS,
        "faults": _faults_view(lab, plan),
        "stp": _stp_view(lab),
        "nms": nms.view(lab),
        "psec": _psec_view(lab, plan),
        "wpa": _wpa_view(lab, plan),
        "media_shelf": {**{k: shelf[k] for k in ("discs", "sticks", "blank_gb")}, "mail_client": _mail_ready(),
                        "wireshark": _wireshark_ready(), "toolkit": _toolkit_ready(),
                        "containers": _containers_ready(lab),
                        "db_clients": _db_ready(), "dsc_modules": _dsc_modules(lab), "ids_rules": _ids_ready(), "vpn_client": _vpn_ready(lab),
                        "docs": _docs_shelf(lab), "secops": _secops_shelf(lab)},
    })


def _switch_power(dash, sw: str, on: bool) -> dict:
    """A switch's power switch: off, every machine plugged into it loses its
    link (and its console goes dark); on, it starts with its startup
    configuration (winlab/iosnv.py), as a real switch does."""
    lab = dash.lab
    if sw not in devcli.switches(lab):
        raise WorkbenchError(f"no switch {sw!r} on the canvas")
    own = devcli.settings(lab, f"sw:{sw}")
    if on == (own.get("power") != "off"):
        return {"ok": True, "message": f"{sw} is already {'on' if on else 'off'}"}
    note = ""
    if on:
        own.pop("power", None)
        from . import iosnv
        data = iosnv.load(lab.name) or {}
        snap = (data.get("devices") or {}).get(f"sw:{sw}")
        if snap is not None or lab.workbench:
            iosnv.revert(lab, f"sw:{sw}", None if snap is None or snap.get("erased") else snap)
        dash.__dict__.get("dev_consoles", {}).pop(f"sw:{sw}", None)
    else:
        own["power"] = "off"
    _save(dash)
    con = devcli.Console(dash, f"sw:{sw}")
    for link in dash.plan.links:
        net = dash.lab.networks.get(link.network_id)
        if net is not None and net.home == sw:
            con._set_link(link, on and not devcli.held_down(dash.lab, link))
    note = _sync(dash)
    return {"ok": True, "message": f"{sw} powered {'on: it starts with its startup configuration' if on else 'off: its ports are dark'}{note}"}


def _port_speed(lab, link) -> dict:
    net = lab.networks.get(link.network_id) if link.plugged else None
    if net is None:
        return {}
    own = lab.devices.get(f"sw:{net.home}", {})
    return {"speed": own.get(f"speed:{link.label}", "auto"), "duplex": own.get(f"duplex:{link.label}", "auto")}


def _secops_shelf(lab):
    """The security-ops sticks this lab's machines name, each ready or not
    (None elsewhere): Greenbone, software, the Wazuh agent, the SCT."""
    from . import secops
    return secops.shelf_view(lab)


def _containers_ready(lab) -> dict:
    """Which container sticks can be written, for a lab with container hosts."""
    from . import containers
    if not any(containers.node_of(lab, r) for r in ("docker", "windows", "k3s-server")):
        return {}
    return {k: containers.ready(k) for k in containers.KINDS}


def _mail_ready() -> bool:
    from . import mail
    return mail.ready()


def _toolkit_ready() -> bool:
    from . import toolkit  # the admin toolkit stick (winlab/toolkit.py)
    return toolkit.ready()


def _wireshark_ready() -> bool:
    from . import wireshark
    return wireshark.ready()


def _vpn_ready(lab) -> bool | None:
    """Whether the VPN client stick can be written; None in a lab whose
    machines do not name it (the button stays hidden)."""
    from . import remoteaccess
    if not any(remoteaccess.DOWNLOAD_ID in (n.vars.get("downloads") or []) for n in lab.node_list()):
        return None
    return remoteaccess.ready()


def _dsc_modules(lab):
    """None for a lab without the automation admin box; else whether the
    DSC modules stick can be written (winlab/automation.py)."""
    from . import automation
    if not any(automation.DOWNLOAD_ID in (n.vars.get("downloads") or []) for n in lab.node_list()):
        return None
    return automation.modules_ready()


def _db_ready() -> bool:
    from . import databases
    return databases.ready()


def _docs_shelf(lab):
    """The GLPI Agent and staff directory sticks, for a lab with the Admin
    tools server or PCs that name the agent (None elsewhere)."""
    from . import doctools
    return doctools.shelf_view(lab)


def _ids_ready() -> bool:
    from . import ids
    return ids.ready()


def _power_of(lab, plan, running, by_switch, out: dict) -> dict:
    """Each server's management port (winlab/power.py): its panel, and its
    cable in the switch port after the machines' and the access points'."""
    from . import power
    slots = {sw: len(by_switch.get(sw, [])) + len(wifi.on_switch(lab, sw)) for sw in lab.networks}
    before = dict(slots)
    bmcs = power.view(lab, plan, running, slots)
    for m in out["machines"]:
        m["bmc"] = bmcs.get(m["id"])
    for s in out["switches"]:
        s["ports"] += slots.get(s["id"], 0) - before.get(s["id"], 0)
    from . import ups  # the UPS on the bench and the mains (winlab/ups.py)
    out["ups"] = ups.view(lab, running)
    return out


def _stp_view(lab) -> dict:
    from . import stp  # the switches' spanning tree, port roles, a storm (winlab/stp.py)
    return stp.view(lab)


def _psec_view(lab, plan) -> dict:
    from . import portsec  # port security, err-disabled ports, 802.1X (winlab/portsec.py)
    return portsec.view(lab, plan)


def _wpa_view(lab, plan) -> dict:
    from . import wpaent  # WPA2-Enterprise on the access points (winlab/wpaent.py)
    return wpaent.view(lab, plan)


def _faults_view(lab, plan) -> dict:
    from . import physfaults
    return physfaults.view(lab, plan)


def _wan_of(lab, sw: str) -> dict | None:
    line = wan.links(lab).get(sw)
    if line is None:
        return None
    return {"preset": wan.preset_of(lab, sw), "delay_ms": line.delay_ms, "jitter_ms": line.jitter_ms,
            "loss_pct": line.loss_pct, "rate_mbit": line.rate_mbit, "text": line.text()}


def _wifi_of(lab, layout, node) -> dict:
    ap_id = wifi.joined(lab, node)
    ap = wifi.aps(lab).get(ap_id)
    return {"wifi": {"ap": ap_id, "ssid": ap["ssid"] if ap else "",
                     "bars": wifi.bars(layout, ap, node.id) if ap else 0},
            "heard": wifi.heard(lab, layout, node), "profiles": sorted(wifi.profiles(node))}


def _aps_view(lab, layout, slots_after: dict[str, int], running=frozenset()) -> list[dict]:
    noisy = wifi.interference(lab, layout)
    st = state.load(lab.name)
    out, taken = [], dict(slots_after)
    for ap in wifi.aps(lab).values():
        net = lab.networks.get(ap["network"])
        slot = -1
        if net is not None:
            slot = taken.get(net.home, 0)  # after the machines' ports on that switch
            taken[net.home] = slot + 1
        out.append({**ap, "pos": layout.get(wifi.PREFIX + ap["id"]), "home": net.home if net else "",
                    "vlan": net.vlan_no if net else 0, "slot": slot, "band": wifi.band(ap["channel"]),
                    "vlans": [{"id": v.id, "vlan": v.vlan_no, "cidr": v.cidr}
                              for v in devcli.vlans_of(lab, net.home)] if net else [],
                    "clients": wifi.clients(lab, ap["id"]), "noisy": noisy.get(ap["id"], []),
                    "range": wifi.RANGE_5GHZ if ap["channel"] >= 36 else wifi.RANGE,
                    # its OpenWrt VM (winlab/openwrt.py): there while the cable is in
                    "vm": {"present": ap["id"] in lab.nodes, "running": ap["id"] in running,
                           "phase": (st.nodes[ap["id"]].phase if st and ap["id"] in st.nodes else "stopped")}})
    return out


def _shelf_state() -> list[dict]:
    """The shelf with, per image, whether it can be made on this PC now."""
    from . import appliances
    out = []
    for s in SHELF:
        imgs = []
        for i in s["images"]:
            e = images.CATALOG.get(i)
            if e is None:
                continue
            if e.kind in (linuxiso.KIND, bsdfw.KIND):  # an installer: installed by hand (linuxiso.py, bsdfw.py)
                imgs.append({"id": i, "title": e.short, "ready": False, "hand": True,
                             "dvd": images.installer_path(i).exists()})
            elif i == "alpine":  # the router's own Alpine, which the devices run too
                imgs.append({"id": i, "title": e.short, "ready": bool(images.status(i).get("base")), "dvd": False})
            elif e.kind == LINUX:
                imgs.append({"id": i, "title": e.short, "ready": appliances.ready(i), "dvd": False})
            else:
                st = images.status(i)
                imgs.append({"id": i, "title": e.short, "dvd": images.installer_path(i).exists(),
                             "ready": bool(st.get("base"))})
                if s["id"] == "server" and f"{i}-core" in images.CATALOG:  # Server Core: its own base
                    imgs[-1]["core_ready"] = bool(images.status(f"{i}-core").get("base"))
        if s["id"] == "iso":
            imgs = [{"id": c.id, "title": c.title, "ready": c.iso.exists(), "dvd": True}
                    for c in images.custom_images().values()]
        out.append({**{k: s[k] for k in ("id", "title", "text", "default")}, "images": imgs})
    return out


# ------------------------------------------------------------------ actions
def _trunk(dash, sw: str, to: str) -> dict:
    """Cable a switch's uplink into another switch: a trunk between them, so
    each VLAN of the one is the same network as the VLAN with that number on
    the other (the router reaches them through the switch at the top)."""
    lab = dash.lab
    for x in (sw, to):
        if x not in lab.networks or lab.networks[x].switch:
            raise WorkbenchError(f"no switch {x!r} on the canvas")
    if sw == to:
        raise WorkbenchError("a switch cannot be cabled to itself")
    hop, seen = to, set()
    while hop and hop not in seen:
        if hop == sw:
            raise WorkbenchError(f"{to} already hangs below {sw}: its uplink cannot go there too; for a "
                                 f"spare cable (a loop spanning tree blocks), drag a free Gi0/2-4 port instead")
        seen.add(hop)
        hop = lab.networks[hop].upstream
    if lab.networks[sw].upstream == to:
        return {"ok": True, "message": f"{sw} is already cabled to {to}"}
    from . import stp  # spare cables take gigabit ports too
    if stp.free_gig(lab, to) < 1:
        raise WorkbenchError(f"{to} has no free gigabit port (Gi0/2 to Gi0/{devcli.GIG_PORTS})")
    if devcli.uplinked(lab, sw):
        try:
            devcli.unplug_router(lab, sw)  # its uplink leaves the router
        except devcli.CliError as exc:
            raise WorkbenchError(str(exc).lstrip("% ")) from None
    lab.networks[sw].upstream = to
    wan.drop_switch(lab, sw)  # a trunk to another switch, not a line to the router
    _save(dash)
    port = dict((b, p) for p, b in devcli.downlinks(lab, to)).get(sw, "")
    shared = [str(v.vlan_no) for v in devcli.vlans_of(lab, sw) if lab.segment_id(v.id) != v.id]
    return {"ok": True, "message": f"{sw} Gi0/1 to {to} {devcli.short_if(port)} (trunk): VLAN "
                                   f"{', '.join(shared) or 'none'} shared{_sync(dash)}"}


def _sync(dash) -> str:
    """Pushes a change into the running network, if it runs."""
    try:
        res = livenet.sync(dash.lab)
    except livenet.LiveNetError as exc:
        return f"; the running network did not take it: {exc}"
    from . import nms  # a cable pulled or a port moved: what the switch logs about it
    nms.tick(dash)
    if res["live"] and res["done"]:
        return " (live)"
    return ""


def _save(dash) -> None:
    editor.save(dash.lab)
    dash.reload()


def _xy(params) -> list[int] | None:
    try:
        return [int(params["x"]), int(params["y"])]
    except (KeyError, TypeError, ValueError):
        return None


def act(dash, action: str, params: dict) -> dict:
    from . import history  # every change made on the bench goes in the lab's history
    if action in ("wb-history", "wb-undo", "wb-redo"):
        return history.act(dash, action, params)
    return history.recorded(dash, action, params, lambda: _act_safe(dash, action, params))


def _act_safe(dash, action: str, params: dict) -> dict:
    try:
        return _act(dash, action, params)
    except (WorkbenchError, editor.EditError, images.ImageError, devcli.CliError) as exc:
        dash.reload()
        return {"ok": False, "message": str(exc)}


def _act(dash, action: str, params: dict) -> dict:
    lab = dash.lab
    if action == "wb-new":
        dest = editor.new_workbench(params.get("name", ""), params.get("description", ""))
        return {"ok": True, "lab": dest.stem,
                "message": f"new network {dest.stem}: drag devices onto the canvas"}

    if action == "wb-add":
        shelf = SHELF_BY_ID.get(params.get("shelf", ""))
        if shelf is None:
            raise WorkbenchError(f"no device {params.get('shelf')!r} on the shelf")
        pos = _xy(params)
        if shelf["id"] == "ap":
            try:
                ap_id = wifi.add_ap(lab, pos, (params.get("id") or "").strip().lower())
            except wifi.WifiError as exc:
                raise WorkbenchError(str(exc)) from None
            _save(dash)
            return {"ok": True, "id": wifi.PREFIX + ap_id,
                    "message": f"{ap_id} added: cable it to a switch to power it, then set it up in its own pages (LuCI) from a browser on a lab PC"}
        if shelf["id"] == "switch":
            nid = (params.get("id") or "").strip().lower() or _free_id(lab.networks, "sw")
            cidr = params.get("cidr") or editor.next_free_subnet(lab, base="192.168.0.0/16")
            net = editor.add_network(lab, nid, cidr=cidr)
            net.routed = False
            if pos:
                lab.layout[f"net:{nid}"] = pos
            _save(dash)
            return {"ok": True, "id": nid,
                    "message": f"switch {nid} ({cidr}): cable it to the router to route it"}
        image = params.get("image") or shelf["default"]
        how = params.get("how", "hand")
        kind = shelf["kind"]
        if shelf["id"] in ("server", "pc", "laptop"):
            if image not in shelf["images"]:
                raise WorkbenchError(f"a {shelf['title']} runs one of {', '.join(shelf['images'])}")
            if how == "hand":
                images.hand_media(image)  # say now, not at power-on, that the DVD is missing
                kind = CUSTOM
            elif how == imaging.NETBOOT:
                kind = CUSTOM  # bare metal: an empty disk, no disc, network boot (winlab/imaging.py)
            elif shelf["id"] == "server" and params.get("edition"):
                from .servercore import with_edition
                try:
                    image = with_edition(image, params["edition"])
                except ValueError as exc:
                    raise WorkbenchError(str(exc)) from None
        elif shelf["id"] == "linux" and linuxiso.is_distro(image):
            images.hand_media(image)  # the installer DVD, fetched or imported in Setup
            kind = CUSTOM
        elif shelf["id"] == "firewall":
            if image not in shelf["images"]:
                raise WorkbenchError(f"a Firewall runs one of {', '.join(shelf['images'])}")
            if bsdfw.is_image(image):
                images.hand_media(image)  # OPNsense fetched, pfSense CE imported, in Setup
                kind = CUSTOM
        elif shelf["id"] == "iso" and not image:
            raise WorkbenchError("add your ISO first (Your own disc > Add an ISO)")
        taken = set(lab.nodes)
        nid = (params.get("id") or "").strip() or _free_id(taken, shelf["prefix"])
        dev = appliance.DEVICES.get(shelf["id"])
        created = editor.add_node(lab, nid, kind=kind, image=image, roles=[dev["role"]] if dev else [])
        node = created[0]
        if how == imaging.NETBOOT and kind == CUSTOM:
            node.vars[imaging.NETBOOT] = "1"
        if node.is_server_core:  # no desktop: it runs in less memory
            node.cpus, node.memory_mb = node.recommended_hardware
        if dev:
            # A device, not a computer: a small machine whose firmware (its
            # role) runs by itself at power-on.
            node.cpus, node.memory_mb = 1, dev["memory_mb"]
            node.data_disks_gb = list(dev["disks"])
            node.description = dev["text"]
        if shelf["id"] == "laptop":
            node.vars["form"] = "laptop"
            node.vars["wireless"] = "0"  # its one network card is the Wi-Fi card
            if node.nics and node.nics[0].plugged:
                editor.unplug(lab, node.id, 0)
        if shelf["id"] in ("firewall", "san") and len(node.nics) < 2 and lab.workbench:
            node.nics.append(Nic(network=""))  # inside and outside
        if bsdfw.is_hand_firewall(node):
            bsdfw.prepare_node(node)  # the memory its installer wants, a firewall-sized disk
        if linuxiso.is_hand_linux(node):
            node.memory_mb = linuxiso.DISTROS[image].memory_mb  # what its installer needs
        if pos:
            lab.layout[node.id] = pos
        _save(dash)
        what =("boots the Setup DVD on an empty disk: power it on and install Windows"
                if images.is_hand_install(node) else "power it on when it is cabled")
        if linuxiso.is_hand_linux(node):
            what = (f"boots the {images.CATALOG[image].short} installer DVD on an empty disk: power it on "
                    f"and install it on its screen; the lab has no internet, so it installs from the DVD alone")
        if bsdfw.is_hand_firewall(node):
            what = (f"boots the {images.CATALOG[image].short} installer on an empty disk: cable WAN and LAN "
                    f"(em0 is port 1), power it on and install it on its screen, then assign the interfaces "
                    f"and finish the setup from a lab PC's browser")
        if shelf["id"] == "server" and params.get("edition"):
            from .servercore import EDITIONS, CORE
            core = EDITIONS.get(str(params["edition"]).lower()) == CORE
            if images.is_hand_install(node):
                what += ("; for Server Core pick 'Standard Evaluation' (the entry without "
                         "'Desktop Experience') in Setup" if core else
                         "; pick a '(Desktop Experience)' edition in Setup")
            elif core:
                what = "Server Core, no desktop: its screen opens on sconfig; " + what
        if imaging.is_netboot(node):
            what = ("an empty disk and no disc: powered on, it boots from the network (PXE), "
                    "so a WDS server can deploy a golden image to it")
        if dev:
            what = "cable it to a switch and power it on; it takes its address from the router"
        if shelf["id"] == "san":
            what = ("its bays are empty: fit blank drives from its front panel's parts drawer, cable both "
                    "ports to a switch, power it on and build the storage in its Webmin (https port 10000) from "
                    "a PC on the storage network")
        if shelf["id"] == "phone":
            what += ("; it has no account: make its extension in the phone system's FreePBX, then sign it in "
                     "on its screen (Calls: menu > VoIP Accounts)" if appliance.pbx_of(dash.lab) else
                     "; it needs a phone system on the network to sign in to")
        if shelf["id"] == "pbx":
            what += ("; its first start installs FreePBX from the freepbx pack (winlab packs fetch freepbx), "
                     "then a lab PC's browser opens it on port 80 and you create its administrator")
        if shelf["id"] == "doctools":
            from . import doctools  # its three packs: Setup offers them, its Settings plugs them in
            node.vars["packs"] = list(doctools.PACKS)
            what += ("; it is a plain Debian 12 server: plug in the glpi, dokuwiki and vaultwarden package sticks "
                     "from its Settings (winlab docs fetch first) and install each one yourself")
        if shelf["id"] == "laptop" and not images.is_hand_install(node):
            what = "join the Wi-Fi of an access point in range from its panel, and power it on"
        elif shelf["id"] == "laptop":
            what += "; it joins the Wi-Fi of an access point in range from its panel"
        return {"ok": True, "id": node.id, "message": f"{node.id} added: {what}"}

    if action in ("wb-tray", "wb-job", "wb-tray-clear", "wb-printer", "wb-line"):
        return _device(dash, action, params)

    if action == "wb-move":
        positions = params.get("positions") or {}
        if not isinstance(positions, dict):
            raise WorkbenchError("positions must be {device: [x, y]}")
        editor.set_layout(lab, positions)
        said = wifi.settle(lab, _auto_layout(lab))
        _save(dash)
        return {"ok": True, "message": "; ".join(said) + (_sync(dash) if said else ""), "wifi": bool(said)}

    if action in ("wb-cable", "wb-unplug") and params.get("node") not in ("switch", "router") \
            and not str(params.get("node", "")).startswith(wifi.PREFIX):
        from . import physfaults  # a fault in the cable goes with it
        physfaults.recabled(lab, str(params.get("node", "")), int(params.get("nic", 0) or 0))

    if action in ("wb-fault", "wb-drill"):
        from . import physfaults
        return physfaults.act(dash, action, params)

    if action == "wb-cable":
        net = params.get("network", "")
        if params.get("node") == "switch":
            return _trunk(dash, net, params.get("to", ""))
        if str(params.get("node", "")).startswith(wifi.PREFIX):
            return _ap(dash, {"id": params["node"][len(wifi.PREFIX):], "network": net})
        node = naming.resolve(lab, params.get("node", ""))
        if node == "router":
            home = lab.networks[net].home if net in lab.networks else net
            if home not in lab.networks:
                raise WorkbenchError(f"no switch {home!r} on the canvas")
            want = str(params.get("port") or "")
            if want:
                try:
                    want = devcli.parse_if(want, devcli.ROUTER_IFS)
                except devcli.CliError as exc:
                    raise WorkbenchError(str(exc).lstrip("% ")) from None
            lab.networks[home].upstream = ""  # the uplink moves to the router
            try:
                port = devcli.plug_router(lab, home, want)
            except devcli.CliError as exc:
                raise WorkbenchError(str(exc).lstrip("% ")) from None
            if not lab.workbench:
                # A lesson lab's router is set up by its lab file: the cable
                # brings the switch's network back onto it.
                own = devcli.settings(lab, devcli.ROUTER)
                own.pop(f"shut:{port}", None)
                own[f"ip:{port}"] = home
                devcli.refresh_routed(lab)
            _save(dash)
            short = devcli.short_if(port)
            if lab.networks[home].routed:
                return {"ok": True, "message": f"{home} cabled to the router's {short}: "
                                               f"{lab.networks[home].router_ip} is its gateway{_sync(dash)}"}
            return {"ok": True, "message": f"{home}'s uplink cabled to the router's {short}: the port is "
                                           f"{'shut down and ' if devcli.router_shut(lab, port) else ''}has "
                                           f"no address yet; set it up on the router's console{_sync(dash)}"}
        idx = int(params.get("nic", 0) or 0)
        if node in lab.nodes and idx in wifi.wireless(lab.nodes[node]):
            raise WorkbenchError("that is the Wi-Fi card: it takes no cable; join a network from the laptop's panel")
        from . import san  # an array's port comes with an address from the factory
        want = int(params.get("port") or 0) or None
        if want and not 1 <= want <= devcli.SWITCH_PORTS:
            raise WorkbenchError(f"a switch has FastEthernet0/1 to FastEthernet0/{devcli.SWITCH_PORTS}")
        cur = lab.nodes[node].nics[idx] if node in lab.nodes and idx < len(lab.nodes[node].nics) else None
        if want and cur is not None and cur.plugged and cur.network == net:
            nic = cur  # the same switch, another port: only the port changes
        else:
            nic = editor.cable(lab, node, idx, net, san.cable_ip(lab, lab.nodes[node], idx, net) if node in lab.nodes else None)
        # Into the switch port it was plugged into (the rack's back names one),
        # else the first free one.
        devcli.pin_port(lab, lab.networks[net].home if net in lab.networks else net, f"{node}:nic{idx}", want)
        _save(dash)
        where = f" Fa0/{want}" if want else ""
        return {"ok": True, "message": f"{naming.display(lab, node)} port {idx + 1} -> {net}{where}"
                                       f"{' ' + nic.ip if nic.ip else ''}{_sync(dash)}"}

    if action == "wb-unplug":
        if params.get("node") == "switch":
            sw = params.get("network", "")
            if sw not in lab.networks or not lab.networks[sw].upstream:
                raise WorkbenchError(f"{sw}'s uplink is not in another switch")
            up = lab.networks[sw].upstream
            lab.networks[sw].upstream = ""
            _save(dash)
            return {"ok": True, "message": f"{sw} is off {up}: its machines reach only each "
                                           f"other{_sync(dash)}"}
        if str(params.get("node", "")).startswith(wifi.PREFIX):
            return _ap(dash, {"id": params["node"][len(wifi.PREFIX):], "network": ""})
        if params.get("node") == "router":
            net = params.get("network", "")
            home = lab.networks[net].home if net in lab.networks else net
            try:
                devcli.unplug_router(lab, home)
            except devcli.CliError as exc:
                raise WorkbenchError(str(exc).lstrip("% ")) from None
            net = home
            _save(dash)
            return {"ok": True, "message": f"{net} is off the router: its machines reach only each "
                                           f"other{_sync(dash)}"}
        node = naming.resolve(lab, params.get("node", ""))
        idx = int(params.get("nic", 0) or 0)
        if node in lab.nodes and idx in wifi.wireless(lab.nodes[node]):
            return _wifi(dash, {"node": node, "leave": "1"})
        editor.unplug(lab, node, idx)
        devcli.pin_port(lab, "", f"{node}:nic{idx}", None)
        _save(dash)
        return {"ok": True, "message": f"cable out of {naming.display(lab, node)} port {idx + 1}{_sync(dash)}"}

    if action == "wb-switch":
        net = lab.networks.get(params.get("network", ""))
        if net is None:
            raise WorkbenchError("no such switch")
        if "dhcp" in params:
            on = params.get("dhcp") in (True, "1", "true", "on")
            if on and not net.routed:
                raise WorkbenchError("only the router hands out addresses: give its port an address in "
                                     "this switch's network first (its console)")
            own = devcli.settings(lab, devcli.ROUTER)
            pools = [k for k, v in own.items() if k.startswith("pool:") and v == net.id]
            if on and not pools:
                # The same as typing ip dhcp pool / network on its console.
                own[f"pool:{net.id.upper()}"] = net.id
                own[f"poolnet:{net.id.upper()}"] = str(net.net)
                if lab.workbench:
                    own[f"poolgw:{net.id.upper()}"] = net.router_ip
            if not on:
                for k in pools:
                    name = k[5:]
                    for key in devcli.POOL_KEYS:
                        own.pop(f"{key}:{name}", None)
            net.dhcp = on
        if params.get("cidr") and params["cidr"] != net.cidr and lab.workbench:
            raise WorkbenchError("a switch's subnet is what the router's port in it has: set it with "
                                 "ip address on the router's console")
        if params.get("cidr") and params["cidr"] != net.cidr:
            try:
                ipaddress.ip_network(params["cidr"], strict=False)
            except ValueError:
                raise WorkbenchError(f"{params['cidr']!r} is not a subnet like 192.168.1.0/24") from None
            if lab.nodes_on(net.id) and any(n.ip for m in lab.nodes_on(net.id) for n in m.nics
                                            if n.network == net.id):
                raise WorkbenchError("machines on this switch have addresses from the old subnet; "
                                     "unplug them first")
            net.cidr = params["cidr"]
            net.gateway = None
        _save(dash)
        return {"ok": True, "message": f"{net.id} updated{_sync(dash)}"}

    if action == "wb-rm":
        what = params.get("id", "")
        running = _running(lab.name)
        if what.startswith(wifi.PREFIX):
            try:
                wifi.remove_ap(lab, what[len(wifi.PREFIX):])
            except wifi.WifiError as exc:
                raise WorkbenchError(str(exc)) from None
            said = wifi.settle(lab, _auto_layout(lab))
            _save(dash)
            return {"ok": True, "message": f"{what[len(wifi.PREFIX):]} removed"
                                           + "".join("; " + x for x in said) + _sync(dash)}
        if what.startswith("net:"):
            nid = what[4:]
            family = {vl.id for vl in devcli.vlans_of(lab, nid)}
            if wifi.on_switch(lab, nid):
                raise WorkbenchError(f"{', '.join(wifi.on_switch(lab, nid))} is still cabled to {nid}; unplug it first")
            for m in lab.nodes.values():
                for i, n in enumerate(m.nics):
                    if n.network in family:
                        raise WorkbenchError(f"{naming.display(lab, m.id)} is still cabled to {nid}; "
                                             f"unplug it first")
            for below in [b for _, b in devcli.downlinks(lab, nid)]:
                lab.networks[below].upstream = ""
            for vl in devcli.vlans_of(lab, nid)[1:]:
                editor.remove_network(lab, vl.id)
            editor.remove_network(lab, nid)
            lab.layout.pop(what, None)
            lab.devices.pop(f"sw:{nid}", None)
            from . import stp
            stp.forget(lab, nid)  # its spare cables to other switches
            wan.drop_switch(lab, nid)
            pools = lab.devices.get(devcli.ROUTER, {})
            for k in [k for k, v in pools.items() if (k.startswith("pool:") or k.startswith("sub:")) and v in family]:
                del pools[k]
            dash.__dict__.get("dev_consoles", {}).pop(f"sw:{nid}", None)
            _save(dash)
            return {"ok": True, "message": f"switch {nid} removed{_sync(dash)}"}
        node = naming.resolve(lab, what)
        if node in running:
            raise WorkbenchError(f"{naming.display(lab, node)} is running; shut it down first")
        editor.remove_node(lab, node)
        lab.layout.pop(node, None)
        lab.devices.pop("san:" + node, None)  # a storage array's saved configuration (winlab/san.py)
        _save(dash)
        return {"ok": True, "message": f"{node} removed (its disk stays until you delete the lab "
                                       f"folder; a machine added with the same name starts afresh)"}

    if action == "wb-parts":
        return _parts(dash, params)

    if action == "wb-ap":
        return _ap(dash, params)

    if action == "wb-ap-read":  # the AP's own configuration (LuCI's), into the air
        return _ap_read(dash, params)

    if action == "wb-ap-reset":  # the reset pinhole on the AP's underside
        return _ap_reset(dash, params)

    if action == "wb-wan":
        sw = str(params.get("network") or "")
        try:
            line = wan.set_link(lab, sw, str(params.get("preset") or ""), params.get("delay_ms"),
                                params.get("jitter_ms"), params.get("loss_pct"), params.get("rate_mbit"))
        except wan.WanError as exc:
            raise WorkbenchError(str(exc)) from None
        _save(dash)
        if line is None:
            return {"ok": True, "message": f"{sw} is back on a plain cable to the router{_sync(dash)}"}
        return {"ok": True, "message": f"{sw} is a branch office over a WAN line: {line.text()}{_sync(dash)}"}

    if action == "wb-wifi":
        return _wifi(dash, params)

    if action == "wb-burn":
        return _burn(dash, params)

    if action == "wb-media":
        # The media shelf: discs and sticks dragged onto machines (mediashelf.py).
        return mediashelf.act(dash, params)

    if action.startswith("wb-stp-"):  # spare cables between switches, spanning tree drills
        from . import stp
        return stp.act(dash, action, params)

    if action.startswith("wb-nms-"):  # syslog / SNMP / NTP drills (winlab/nms.py)
        from . import nms
        return nms.act(dash, action, params)
    if action.startswith("wb-psec-"):  # a visitor's laptop, the ports' live state, their drills
        from . import portsec
        return portsec.act(dash, action, params)
    if action.startswith("wb-wpa-"):  # WPA2-Enterprise: the laptops' sign-ins, the AP's drill
        from . import wpaent
        return wpaent.act(dash, action, params)
    if action.startswith("wb-ctr-"):  # the container sticks onto the shelf (winlab/containers.py)
        from . import containers
        return containers.act(dash, action, params)
    if action.startswith("wb-mail-"):  # the mail client stick onto the shelf (winlab/mail.py)
        from . import mail
        return mail.act(dash, action, params)
    if action.startswith("wb-wireshark-"):  # the Wireshark stick onto the shelf (winlab/wireshark.py)
        from . import wireshark
        return wireshark.act(dash, action, params)
    if action.startswith("wb-ra-"):  # the VPN client stick onto the shelf (winlab/remoteaccess.py)
        from . import remoteaccess
        return remoteaccess.act(dash, action, params)
    if action.startswith("wb-auto-"):  # the DSC modules stick onto the shelf (winlab/automation.py)
        from . import automation
        return automation.act(dash, action, params)
    if action.startswith("wb-db-"):  # the database clients stick onto the shelf (winlab/databases.py)
        from . import databases
        return databases.act(dash, action, params)
    if action.startswith("wb-docs-"):  # the GLPI Agent and staff directory sticks (winlab/doctools.py)
        from . import doctools
        return doctools.act(dash, action, params)
    if action.startswith("wb-ids-"):  # the Suricata rules stick onto the shelf (winlab/ids.py)
        from . import ids
        return ids.act(dash, action, params)
    if action.startswith("wb-secops-"):  # Greenbone, software, Wazuh agent, SCT sticks (winlab/secops.py)
        from . import secops
        return secops.act(dash, action, params)

    if action == "wb-firmware":  # boot mode and Secure Boot in the firmware setup (winlab/firmware.py)
        return firmware.act(dash, action, params)

    if action == "wb-vtx":  # the VT-x firmware setting, Hyper-V inside, its drill (winlab/nestedvirt.py)
        return nestedvirt.act(dash, action, params)

    if action == "wb-cli":
        return cli(dash, params.get("device", ""), params.get("line"), params.get("complete"))

    if action == "wb-swpower":
        return _switch_power(dash, str(params.get("network", "")), params.get("on") in (True, "1", "true", "on"))

    raise WorkbenchError(f"unknown workbench action {action!r}")


def _parts(dash, params: dict) -> dict:
    """The inside of a machine: processors, memory sticks, disks, network
    cards. Changed with the machine off, as on a real PC."""
    lab = dash.lab
    node_id = naming.resolve(lab, params.get("node", ""))
    node = lab.nodes.get(node_id)
    if node is None:
        raise WorkbenchError("no such machine")
    if node_id in _running(lab.name):
        raise WorkbenchError(f"shut {naming.display(lab, node_id)} down before you open the case")
    done = []
    if params.get("cpus"):
        cpus = int(params["cpus"])
        if not 1 <= cpus <= 16:
            raise WorkbenchError("a machine takes 1 to 16 processor cores")
        node.cpus = cpus
        done.append(f"{cpus} cores")
    if params.get("memory_mb"):
        mb = int(params["memory_mb"])
        if mb < node.memory_floor_mb and node.kind != CUSTOM:
            raise WorkbenchError(f"{_os_title(node)} needs at least {node.memory_floor_mb} MB")
        if not 256 <= mb <= 65536:
            raise WorkbenchError("memory is 256 MB to 64 GB")
        node.memory_mb = mb
        done.append(f"{mb} MB memory")
    if params.get("add_disk_gb"):
        if len(node.data_disks_gb) >= 4:
            raise WorkbenchError("the case has room for four more disks")
        from . import disks
        if not disks._virtio(node) and disks.asked_buses(node).count("sata") >= disks.MAX_SATA:
            raise WorkbenchError(f"the SATA controller has room for {disks.MAX_SATA} data disks: "
                                 "fit the next one as SAS or NVMe in Disks")
        editor.set_node(lab, node_id, add_disk_gb=int(params["add_disk_gb"]))
        done.append(f"a {params['add_disk_gb']} GB disk fitted")
    if params.get("rm_disk"):
        editor.set_node(lab, node_id, rm_disk=True)
        done.append("the last disk taken out")
    if params.get("add_nic"):
        if len(node.nics) >= MAX_PORTS:
            raise WorkbenchError(f"a machine takes at most {MAX_PORTS} network cards")
        editor.set_node(lab, node_id, add_nic="-" if lab.workbench else
                        (node.nics[0].network if node.nics else ""))
        done.append("a network card fitted")
    if params.get("rm_nic") not in (None, ""):
        idx = int(params["rm_nic"])
        cards = wifi.wireless(node)
        if idx in cards:
            raise WorkbenchError("the Wi-Fi card is built into the laptop")
        editor.set_node(lab, node_id, rm_nic=str(idx))
        if cards:
            node.vars["wireless"] = " ".join(str(c - 1 if c > idx else c) for c in cards)
        done.append(f"network card {int(params['rm_nic']) + 1} taken out")
    if params.get("dvd_drives"):
        n = int(params["dvd_drives"])
        if node.kind == LINUX or not 1 <= n <= mediashelf.MAX_DRIVES:
            raise WorkbenchError(f"a Windows machine takes 1 to {mediashelf.MAX_DRIVES} DVD drives")
        node.vars["dvd_drives"] = n
        done.append(f"{n} DVD drive{'s' if n > 1 else ''}")
    if params.get("system_disk_gb"):
        gb = int(params["system_disk_gb"])
        disk = paths.lab_dir(lab.name) / node_id / "system.qcow2"
        if disk.exists():
            raise WorkbenchError("the system disk is in use; its size is set before the first install")
        if not 20 <= gb <= 2048:
            raise WorkbenchError("a system disk is 20 to 2048 GB")
        node.vars["disk_gb"] = gb
        done.append(f"a {gb} GB system disk")
    if params.get("bmc") in ("fit", "remove"):
        from . import power  # the management port, the server's BMC (winlab/power.py)
        try:
            (power.fit if params["bmc"] == "fit" else power.remove)(lab, node_id)
        except power.PowerError as exc:
            raise WorkbenchError(str(exc)) from None
        done.append("a management port fitted (its user and password are on the toe tag)"
                    if params["bmc"] == "fit" else "the management port taken out")
    if not done:
        raise WorkbenchError("nothing to change")
    _save(dash)
    return {"ok": True, "message": f"{naming.display(lab, node_id)}: {', '.join(done)}"}


def _ap(dash, params: dict) -> dict:
    """An access point's cable (and VLAN), from its panel. Its Wi-Fi
    settings are set in its own web pages (LuCI) and read by _ap_read."""
    lab = dash.lab
    ap_id = str(params.get("id") or "")
    changes = {k: params[k] for k in wifi.SETTINGS + ("ip",) if params.get(k) not in (None, "")}
    if "network" in params:
        net = str(params.get("network") or "")
        if net and net in lab.networks and not params.get("vlan"):
            net = lab.networks[net].home  # a cable goes into the switch's own (first) VLAN
        changes["network"] = net
    if params.get("vlan"):
        changes["network"] = str(params["vlan"])
    try:
        before = wifi.aps(lab).get(ap_id, {}).get("network", "")
        if changes.get("network") and changes["network"] in lab.networks:
            home = lab.networks[changes["network"]].home
            if lab.networks.get(before) is None or lab.networks[before].home != home:
                used = sum(1 for l in devcli.switch_ports(lab, dash.plan).get(home, []) if l is not None) \
                    + len(wifi.on_switch(lab, home))
                if used >= devcli.SWITCH_PORTS:
                    raise WorkbenchError(f"{home} has no free port")
        ap = wifi.set_ap(lab, ap_id, **changes)
    except wifi.WifiError as exc:
        raise WorkbenchError(str(exc)) from None
    said = wifi.settle(lab, _auto_layout(lab))
    _save(dash)
    if ap["network"]:
        msg = (f"{ap['name']} cabled to {ap['network']}: it takes its power from the port; its pages "
               f"(LuCI) are at http://{ap['ip']}/ from a browser on a lab PC"
               + ("" if ap["radio"] == "on" else ", where you turn its radio on"))
    else:
        msg = f"cable out of {ap['name']}: it powers off"
    return {"ok": True, "message": msg + "".join("; " + x for x in said) + _sync(dash)}


def _ap_read(dash, params: dict, reader=None) -> dict:
    """What the AP's own configuration says now, read over its console
    (or handed in as `wireless`/`network` text by a model answer): into the
    air, the laptops settled to it, and the AP's RADIUS relay kept in step."""
    lab = dash.lab
    ap_id = str(params.get("id") or "")
    if ap_id not in wifi.aps(lab):
        raise WorkbenchError(f"no access point {ap_id!r}")
    from . import openwrt
    if params.get("wireless") is not None:
        wireless, network = str(params.get("wireless") or ""), str(params.get("network") or "")
    else:
        try:
            wireless, network = (reader or wifi.read_ap)(lab.name, ap_id)
        except openwrt.OpenWrtError as exc:
            return {"ok": False, "message": str(exc), "changed": False}
    said = wifi.apply_wireless(lab, ap_id, wireless, network, when=time.strftime("%H:%M:%S"))
    live = params.get("wireless") is None
    if said:
        said += wifi.settle(lab, _auto_layout(lab))
        _save(dash)
    ap = wifi.aps(dash.lab)[ap_id]
    if ap["security"] == "wpa2-ent" and ap["radio"] == "on":
        from . import wpaent
        relay = wpaent.relay_of(dash.plan, ap)
        if relay and live:  # again after a reboot of the AP, which forgets it
            try:
                openwrt.run(lab.name, ap_id, relay if said else
                            f"nft list table ip {openwrt.RADIUS_RELAY} >/dev/null 2>&1 || sh -s <<'WL_RELAY'\n"
                            f"{relay}WL_RELAY\n", timeout=20)
            except openwrt.OpenWrtError:
                pass
        if said:
            why = wpaent.issue(dash.plan, ap)
            src = wpaent.source(dash.plan, ap)[0]
            said.append(why if why else f"RADIUS to {ap['radius']}:{ap['radius_port']} from {src}, "
                                        f"the address the server must list as its RADIUS client")
    if not said:
        return {"ok": True, "message": "", "changed": False}
    return {"ok": True, "message": "; ".join(said) + _sync(dash), "changed": True}


def _wifi(dash, params: dict) -> dict:
    """A laptop joins or leaves a Wi-Fi network, from its panel."""
    lab = dash.lab
    node_id = naming.resolve(lab, params.get("node", ""))
    try:
        if params.get("leave") or params.get("forget"):
            msg = wifi.leave(lab, node_id, forget=bool(params.get("forget")))
        else:
            msg = wifi.join(lab, _auto_layout(lab), node_id, str(params.get("ssid") or ""), str(params.get("key") or ""))
    except (wifi.WifiError, editor.EditError) as exc:
        raise WorkbenchError(str(exc)) from None
    _save(dash)
    return {"ok": True, "message": msg + _sync(dash)}


def _ap_reset(dash, params: dict) -> dict:
    """The AP's reset pinhole: pressed briefly it restarts; held ten seconds
    it goes back to its factory settings (the radio's and LuCI's root
    sign-in, as it came out of the box) and restarts."""
    from . import openwrt
    lab = dash.lab
    ap_id = str(params.get("id") or "")
    if ap_id not in wifi.aps(lab):
        raise WorkbenchError("no such access point")
    factory = str(params.get("hold") or "") in ("1", "true")
    script = "(sleep 1; reboot) >/dev/null 2>&1 &"
    if factory:
        script = (f"cat > /etc/config/wireless <<'WINLAB_EOF'\n{openwrt.uci_wireless()}WINLAB_EOF\n"
                  "passwd -d root >/dev/null 2>&1; sync; " + script)
    try:
        openwrt.run(lab.name, ap_id, script, timeout=20)
    except openwrt.OpenWrtError as exc:
        raise WorkbenchError(str(exc)) from None
    name = wifi.aps(lab)[ap_id].get("name") or ap_id
    return {"ok": True, "message": (f"{name}: held ten seconds, its LEDs flash: factory settings (radio off, "
                                    f"no sign-in set), then it restarts" if factory else
                                    f"{name} restarts: its radio is back in about a minute")}


def _device(dash, action: str, params: dict) -> dict:
    """The printer's output tray and control panel, a desk phone's line,
    from their front panels."""
    lab = dash.lab
    node_id = naming.resolve(lab, params.get("node", ""))
    node = lab.nodes.get(node_id)
    if node is None or not appliance.device_of(node):
        raise WorkbenchError("no such device")
    try:
        if action == "wb-tray":
            return {"ok": True, "jobs": appliance.tray(lab.name, node_id)}
        if action == "wb-job":
            return {"ok": True, **appliance.job_text(lab.name, node_id, str(params.get("job") or ""))}
        if action == "wb-tray-clear":
            appliance.clear_tray(lab.name, node_id)
            return {"ok": True, "message": "the tray is empty"}
        if action == "wb-printer":
            op = str(params.get("op") or "")
            if not op:
                return {"ok": True, **appliance.printer_panel(lab.name, node_id)}
            return {"ok": True, **appliance.printer_op(lab.name, node_id, op)}
        if action == "wb-line":
            seen = {x for x in str(params.get("ips") or "").split(",") if re.fullmatch(r"[0-9.]{7,15}", x)}
            return appliance.phone_line(lab, node, seen)
    except appliance.ApplianceError as exc:
        raise WorkbenchError(str(exc)) from None
    raise WorkbenchError(f"unknown action {action}")


def _reapply(dash, node_id: str, role: str) -> str:
    """Runs a device's firmware role again now that its settings changed,
    if it is on; otherwise its next power-on does."""
    if node_id not in _running(dash.lab.name):
        return ""
    from . import roles
    try:
        ch = appliance._channel(dash.lab.name, node_id, wait=True)
        try:
            ch.run(f"rm -f /var/lib/winlab/done/{role}", shell="sh", timeout=30)  # run it again
            roles.apply_roles(dash.lab.nodes[node_id], ch, topology=dash.plan, lab=dash.lab)
        finally:
            ch.close()
        return " now"
    except Exception as exc:  # saved either way; the next power-on applies it
        return f" from its next start ({exc})"


BURN_MAX = 4 * 1024**3


def disc_path(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id / "burned.iso"


def _burn(dash, params: dict) -> dict:
    """A folder of the user's own installers (apps, scripts, drivers) burned
    to a disc and put in the machine's DVD drive: the only way files cross
    into the lab besides `winlab cp` and the USB stick."""
    from . import isowrite, media
    lab = dash.lab
    node_id = naming.resolve(lab, params.get("node", ""))
    node = lab.nodes.get(node_id)
    if node is None:
        raise WorkbenchError("no such machine")
    if node.kind == LINUX:
        raise WorkbenchError("this machine has no DVD drive; use a USB stick")
    folder = Path(str(params.get("folder", ""))).expanduser()
    if not folder.is_dir():
        raise WorkbenchError(f"no such folder: {folder}")
    label = re.sub(r"[^A-Za-z0-9_]", "_", params.get("label") or folder.name)[:32] or "APPS"
    w = isowrite.IsoWriter(label)
    try:
        count = w.add_tree(folder)
    except isowrite.IsoWriteError as exc:
        raise WorkbenchError(str(exc)) from exc
    if not count:
        raise WorkbenchError(f"{folder} holds no files")
    if w.total_bytes() > BURN_MAX:
        raise WorkbenchError("that folder is over 4 GB; a disc holds less")
    dest = disc_path(lab.name, node_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    try:
        w.write(tmp)
    except isowrite.IsoWriteError as exc:
        raise WorkbenchError(str(exc)) from exc
    tmp.replace(dest)
    live = False
    try:
        live = media.insert(lab.name, node_id, dest)
    except media.MediaError as exc:
        raise WorkbenchError(str(exc)) from exc
    return {"ok": True, "path": str(dest),
            "message": (f"{count} files burned to disc {label} and put in "
                        f"{naming.display(lab, node_id)}'s DVD drive"
                        if live else f"{count} files burned to {dest}; the machine is off, so the "
                        f"disc waits on the media shelf: drag it onto the machine")}


# ------------------------------------------------------------------ live view
class Live:
    """The router's view of the wire, read at most every few seconds and
    shared by every poll: addresses by MAC, and which cards sent frames."""

    MIN_AGE = 3.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._at = 0.0
        self._data: dict = {"ips": {}, "seen": [], "ok": False, "note": ""}

    @staticmethod
    def _factory(lab, runner_factory):
        if runner_factory is not None:
            return runner_factory
        from .cli import _fabric_runner
        return lambda: _fabric_runner(lab.name)

    def capture(self, lab, runner_factory=None) -> dict:
        """A couple of seconds of the network's traffic, as the router's
        switch saw it (livenet.parse_packets)."""
        with self._lock:
            run, why = self._factory(lab, runner_factory)()
            if not run:
                return {"ok": False, "packets": [], "note": why}
            try:
                out = run(livenet.capture_cmd(), timeout=livenet.CAPTURE_SECONDS + 15)
                plan = netplan.compile_topology(lab, check_ports=False)
                return {"ok": True, "packets": livenet.parse_packets(out, plan),
                        "seconds": livenet.CAPTURE_SECONDS, "note": ""}
            except Exception as exc:  # noqa: BLE001 - the canvas must keep drawing
                return {"ok": False, "packets": [], "note": str(exc)}
            finally:
                close = getattr(run, "close", None)
                if close:
                    close()

    def read(self, lab, runner_factory=None) -> dict:
        with self._lock:
            if time.monotonic() - self._at < self.MIN_AGE:
                return self._data
            self._at = time.monotonic()
            run, why = self._factory(lab, runner_factory)()
            if not run:
                self._data = {"ips": {}, "seen": [], "ok": False, "note": why}
                return self._data
            try:
                # The ports' counters too, for the meters (winlab/perfmon.py).
                from . import perfmon
                # Only reads the router's own tables: it never scans the LAN,
                # which a real router does not do and a student's capture
                # would show.
                cmd = livenet.LIVE_CMD + "; " + perfmon.COUNTERS_CMD
                out = run(cmd, timeout=20)
                self._data = {**livenet.parse_live(out), "counters": perfmon.parse_counters(out),
                              "ok": True, "note": ""}
            except Exception as exc:  # noqa: BLE001 - the map must keep drawing
                self._data = {"ips": {}, "seen": [], "ok": False, "note": str(exc)}
            finally:
                close = getattr(run, "close", None)
                if close:
                    close()
            return self._data


def live(dash, reader: Live) -> dict:
    """Per machine port: whether the link is up and the router's switch has
    frames from it, as a switch's port lights show. The addresses the router
    has seen go only with the equipment the lab sets up itself (a printer's,
    an access point's management address, provision.lab_addressed): what a
    student's own machine has, they read inside it (ipconfig, ip addr) or on
    the router's console (show ip arp), as at work."""
    from .provision import lab_addressed
    lab, plan = dash.lab, dash.plan
    running = _running(lab.name)
    if "fabric" not in running:
        return {"router": False, "ports": {}, "note": "the router is off"}
    data = reader.read(lab)
    seen = set(data.get("seen", []))
    ips = data.get("ips", {})
    ports = {}
    for link in plan.ports:
        mac = link.mac.lower()
        on = link.node_id in running
        # A machine that is off has no address, whatever the router's
        # tables still remember of it.
        node = lab.nodes.get(link.node_id)
        shown = on and node is not None and lab_addressed(node)
        ports[link.label] = {"ips": ips.get(mac, []) if shown else [], "traffic": on and mac in seen,
                             "up": link.plugged and on}
    return {"router": True, "ports": ports, "note": data.get("note", ""), "ok": data.get("ok", False)}


def packets(dash, reader: Live) -> dict:
    """What moved on the wire in the last seconds, for the canvas to play
    back on its cables."""
    if "fabric" not in _running(dash.lab.name):
        return {"ok": False, "packets": [], "note": "the router is off"}
    return reader.capture(dash.lab)


def console(dash, device: str) -> devcli.Console:
    """The device's console session, kept while the desktop runs."""
    if device != devcli.ROUTER and devcli.switch_id(device) not in devcli.switches(dash.lab):
        raise WorkbenchError(f"no device {device!r} with a console")
    consoles = dash.__dict__.setdefault("dev_consoles", {})
    con = consoles.get(device)
    if con is None:
        con = consoles[device] = devcli.Console(dash, device)
    return con


def cli(dash, device: str, line: str | None = None, complete: str | None = None) -> dict:
    con = console(dash, device)
    if not con.powered():
        return {"ok": True, "off": True, "out": "", "prompt": ""}
    if complete is not None:
        return {"ok": True, "line": con.complete(complete), "prompt": con.prompt()}
    if line is None:
        return {"ok": True, "out": con.banner(), "prompt": con.prompt(), "secret": con.secret()}
    try:
        out = con.run(line)
    except (WorkbenchError, editor.EditError) as exc:
        out = f"% {exc}"
    return {"ok": True, "out": out, "prompt": con.prompt(), "help": line.rstrip().endswith("?"),
            "secret": con.secret()}
