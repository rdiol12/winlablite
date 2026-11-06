"""Changing a network while it runs, the way one changes a real one.

A cable pulled out of a machine, a cable moved to another switch, a switch
cabled to the router or taken off it, a new machine (or a new card in one)
plugged into a running network: none of these needs the lab restarted.

The router's switch ports are fixed when it starts (one loopback socket per
network card, winlab/netplan.py), so what it was started with is recorded
here (`router-ports.json` beside the lab's machines) and every later plan
keeps those ports' numbers, interface names and VLAN ids. A change then
becomes a short script on the running router (re-tagging ports, adding or
removing its interface on a segment, rewriting DHCP) and, on the machines,
the link state of their cards over QMP, which Windows shows as "Network
cable unplugged" exactly as it would on a desk. A port the running router
does not have yet is added to it live: a socket backend and a network card
in one of its free PCIe slots (providers/qemu.py HOTPLUG_SLOTS).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from . import paths, state

PINS_FILE = "router-ports.json"


class LiveNetError(Exception):
    pass


def pins_path(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / PINS_FILE


def _router(lab_name: str) -> state.NodeState | None:
    st = state.load(lab_name)
    fab = st.nodes.get("fabric") if st else None
    if fab and fab.pid and state.pid_alive(fab.pid):
        return fab
    return None


def _load(lab_name: str) -> dict:
    """What the running router has, or {} when it is not running (a record
    left by a router that stopped or crashed belongs to no one)."""
    fab = _router(lab_name)
    if fab is None:
        return {}
    try:
        data = json.loads(pins_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if data.get("pid") == fab.pid else {}


def pinned_ports(lab_name: str) -> dict[str, dict]:
    return dict(_load(lab_name).get("ports", {}))


def pinned_vids(lab_name: str) -> dict[str, int]:
    return {k: int(v) for k, v in _load(lab_name).get("vids", {}).items()}


def _port_entry(plan, link) -> dict:
    return {"port": link.port, "iface": link.fabric_iface, "vid": plan.vid_of(link),
            "tagged": sorted(plan.segment_of(n).vid for n in link.trunk_vlans)
            if link.plugged else [],
            "plugged": link.plugged}


def _dhcp_text(plan) -> str:
    from .netplan import _render_dhcp
    return "\n".join(_render_dhcp(plan))


def _wan_hash(plan) -> str:
    from .wan import render
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


def _stp_hash(plan) -> str:
    from .stp import render_hash
    return render_hash(plan)


def _port_hash(plan) -> str:
    from .portsec import render_hash
    return render_hash(plan)


def _l3_hash(plan) -> str:
    from .iosl3 import render_hash
    return render_hash(plan)


def _pol_hash(plan) -> str:
    from .routerpolicy import render_hash
    return render_hash(plan)


def _l2_hash(plan) -> str:
    from .iosl2 import render_hash
    return render_hash(plan)


def _rt_hash(plan) -> str:
    from .iosrouting import render_hash
    return render_hash(plan)


def _wlan_hash(plan) -> str:
    from .wpaent import render_hash
    return render_hash(plan)


def snapshot(plan, pid: int, slots: int = 0) -> dict:
    return {
        "pid": pid,
        "ports": {l.label: _port_entry(plan, l) for l in plan.ports},
        "vids": {sid: seg.vid for sid, seg in plan.segments.items()},
        "routed": {sid: seg.network.routed for sid, seg in plan.segments.items()},
        "dhcp": hashlib.sha256(_dhcp_text(plan).encode()).hexdigest(),
        "wan": _wan_hash(plan),
        "stp": _stp_hash(plan),
        "psec": _port_hash(plan),
        "wlan": _wlan_hash(plan),
        "l3": _l3_hash(plan),
        "l2": _l2_hash(plan),
        "rt": _rt_hash(plan),

        "pol": _pol_hash(plan),
        "slots": slots,
    }


def record(plan, pid: int) -> None:
    """Called when the router starts: these are its ports."""
    _write(plan.lab.name, snapshot(plan, pid))


def forget(lab_name: str) -> None:
    pins_path(lab_name).unlink(missing_ok=True)


def _write(lab_name: str, data: dict) -> None:
    p = pins_path(lab_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(p)


def fabric_mac(port: int) -> str:
    """The router-side card of a port added live, findable by this address."""
    h = hashlib.sha256(f"winlab-port/{port}".encode()).digest()
    return "52:54:01:%02x:%02x:%02x" % (h[0], h[1], h[2])


# ------------------------------------------------------------------ planning
def port_script(link_label: str, iface: str, old: dict | None, vid: int,
                tagged: list[int]) -> list[str]:
    """Re-tag one switch port: what moving its cable to another switch (or
    pulling it out) does to the router."""
    from .netplan import BRIDGE
    out = [f"# {link_label}",
           f"ip link set {iface} up",
           f"ip link set {iface} master {BRIDGE} 2>/dev/null || true"]
    olds = ([old["vid"]] + list(old.get("tagged", []))) if old else [1]
    for v in olds:
        out.append(f"bridge vlan del dev {iface} vid {v} 2>/dev/null || true")
    out.append(f"bridge vlan add dev {iface} vid {vid} pvid untagged")
    for v in tagged:
        out.append(f"bridge vlan add dev {iface} vid {v}")
    return out


def svi_script(seg, was_routed: bool | None) -> list[str]:
    """The router's own interface on a segment, added or removed."""
    from .netplan import svi_lines
    net = seg.network
    if net.routed and was_routed is not True:
        return [f"{line} 2>/dev/null || true" if not line.startswith("#") else line
                for line in svi_lines(seg)]
    if not net.routed and was_routed:
        return [f"# {net.id} taken off the router",
                f"ip addr flush dev {seg.svi} 2>/dev/null || true",
                f"ip link del {seg.svi} 2>/dev/null || true"]
    return []


def changes(plan, pins: dict) -> dict:
    """What differs between the lab and the running router."""
    ports = pins.get("ports", {})
    new, moved = [], []
    for link in plan.ports:
        cur = ports.get(link.label)
        want = _port_entry(plan, link)
        if cur is None:
            new.append(link)
        elif (cur["vid"], sorted(cur.get("tagged", []))) != (want["vid"], want["tagged"]):
            moved.append(link)
    svis = []
    vids0 = pins.get("vids", {})
    for sid, seg in plan.segments.items():
        was = pins.get("routed", {}).get(sid)
        if svi_script(seg, was):
            svis.append(seg)
        elif was and seg.network.routed and sid in vids0 and int(vids0[sid]) != seg.vid:
            svis.append(seg)  # the same network on another VLAN id (a trunk tags it by its number now)
    # A routed segment that is gone (its switch was removed, or cabled to
    # another switch, where it is now part of that one's segment).
    vids = pins.get("vids", {})
    gone = [(sid, int(vids[sid])) for sid, was in pins.get("routed", {}).items()
            if was and sid not in plan.segments and sid in vids]
    dhcp = hashlib.sha256(_dhcp_text(plan).encode()).hexdigest() != pins.get("dhcp")
    # The WAN lines are set again whenever they or the gateways under them
    # change (a new SVI starts with no qdisc).
    wan = _wan_hash(plan) != pins.get("wan", _wan_hash(plan)) or bool(svis or gone)
    links = [l for l in plan.ports
             if l.label in ports and bool(ports[l.label].get("plugged", True)) != l.plugged]
    # The switch bridges and their spanning tree are built again when they change.
    stp = _stp_hash(plan) != pins.get("stp", _stp_hash(plan))
    # Port security and 802.1X on the access ports, likewise (winlab/portsec.py).
    psec = _port_hash(plan) != pins.get("psec", _port_hash(plan))
    # WPA2-Enterprise on the APs (winlab/wpaent.py): also when an SVI that
    # may carry an AP's own address was built again.
    wh = _wlan_hash(plan)
    wlan = wh != pins.get("wlan", wh) or bool((svis or gone) and wh != hashlib.sha256(b"").hexdigest())
    # The router's routes, access lists and NAT (winlab/iosl3.py): again too
    # when an SVI they name was built again or went.
    lh = _l3_hash(plan)
    l3 = lh != pins.get("l3", lh) or bool((svis or gone) and lh != hashlib.sha256(b"").hexdigest())
    # The switches' management addresses, port rates and uplink VLANs
    # (winlab/iosl2.py): again too when the SVIs, bridges or ports under them changed.
    l2h = _l2_hash(plan)
    l2 = l2h != pins.get("l2", l2h) or bool((svis or gone or stp or new or moved)
                                            and l2h != hashlib.sha256(b"").hexdigest())
    # OSPF, BGP, VRFs and VRRP (winlab/iosrouting.py): again too when an SVI under them was built again.
    rh = _rt_hash(plan)
    rt = rh != pins.get("rt", rh) or bool((svis or gone) and rh != hashlib.sha256(b"").hexdigest())
    # Tunnels, the zone firewall and QoS (winlab/routerpolicy.py): again too
    # when an interface under them was built again or the WAN lines reset its queues.
    ph = _pol_hash(plan)
    pol = ph != pins.get("pol", ph) or bool((svis or gone or wan) and ph != hashlib.sha256(b"").hexdigest())
    return {"new": new, "moved": moved, "svis": svis, "gone": gone, "dhcp": dhcp, "links": links, "wan": wan,
            "stp": stp, "psec": psec, "wlan": wlan, "l3": l3, "l2": l2, "rt": rt, "pol": pol}


# ------------------------------------------------------------------ applying
def _hot_add(qmp_port: int, link, slot: int, qmp=None) -> None:
    from .qmp import Qmp
    qmp = qmp or Qmp
    from .qmp import QmpError
    with qmp(qmp_port) as mon:
        # Either half may be there from an attempt that stopped short (the
        # router never named the new port): adding it again is a no-op.
        for cmd, args in (("netdev_add", dict(type="socket", id=f"hp{link.port}",
                                              listen=f"127.0.0.1:{link.port}")),
                          ("device_add", dict(driver="virtio-net-pci", id=f"hpd{link.port}",
                                              netdev=f"hp{link.port}", bus=f"hp{slot}",
                                              mac=fabric_mac(link.port)))):
            try:
                mon.call(cmd, **args)
            except QmpError as exc:
                if "uplicate" not in str(exc) and "in use" not in str(exc):
                    raise


def find_iface_cmd(mac: str) -> str:
    return (f"for i in /sys/class/net/*; do [ \"$(cat $i/address 2>/dev/null)\" = \"{mac}\" ] "
            f"&& echo ${{i##*/}}; done")


def set_link(qmp_port: int, nic_index: int, up: bool, qmp=None, tries: int = 1) -> bool:
    """A cable in (up) or out of a running machine's card."""
    from .qmp import Qmp, QmpError
    qmp = qmp or Qmp
    for attempt in range(tries):
        try:
            with qmp(qmp_port, timeout=5) as mon:
                mon.call("set_link", name=f"net{nic_index}", up=up)
            return True
        except (QmpError, OSError):
            if attempt + 1 < tries:
                time.sleep(0.5)
    return False


def apply_node_links(lab, plan, node_id: str, qmp_port: int, qmp=None) -> int:
    """At a machine's start: hold down the cards that have no cable in, or
    whose switch port is shut down."""
    from . import devcli
    n = 0
    for link in plan.ports_for(node_id):
        held = not link.plugged or devcli.held_down(lab, link)
        if held and set_link(qmp_port, link.nic_index, False, qmp=qmp, tries=20):
            n += 1
    return n


def sync(lab, emit=lambda _l: None, runner=None, qmp=None) -> dict:
    """Brings the running router and machines in line with the lab
    definition. Returns {"live": bool, "done": [...], "note": str}."""
    from . import netplan
    from .providers.qemu import HOTPLUG_SLOTS
    fab = _router(lab.name)
    pins = _load(lab.name)
    if fab is None or not pins:
        return {"live": False, "done": [],
                "note": "the network is off; the change is in place when it starts"}
    plan = netplan.compile_topology(lab, check_ports=False)
    ch = changes(plan, pins)
    if not any(ch.values()):
        return {"live": True, "done": [], "note": ""}
    if runner is None:
        from .cli import _fabric_runner
        runner, why = _fabric_runner(lab.name)
        if not runner:
            raise LiveNetError(f"cannot reach the router: {why}")
    done: list[str] = []
    slots = int(pins.get("slots", 0))
    try:
        for link in ch["new"]:
            if slots >= HOTPLUG_SLOTS:
                raise LiveNetError(
                    f"the router has no free slot for {link.label}'s port (it took "
                    f"{HOTPLUG_SLOTS} new ports since it started); stop and start the "
                    f"network to rebuild it with every port")
            pending = pins.setdefault("pending", {})
            slot = pending.get(link.label)
            if slot is None:
                slot = slots
                slots += 1
                pending[link.label] = slot
                _write(lab.name, {**pins, "slots": slots})
            _hot_add(fab.qmp_port, link, slot, qmp=qmp)
            iface = ""
            for _ in range(20):
                iface = (runner(find_iface_cmd(fabric_mac(link.port)), timeout=20) or "").strip()
                if iface:
                    break
                time.sleep(0.5)
            if not iface:
                raise LiveNetError(f"the router did not see its new port for {link.label}")
            link.fabric_iface = iface.split()[0]
            done.append(f"new switch port {link.fabric_iface} for {link.label}")
        script: list[str] = []
        for seg in ch["svis"]:
            old_vid = int(pins.get("vids", {}).get(seg.network.id, seg.vid))
            if old_vid != seg.vid:
                script += [f"ip link del {netplan.BRIDGE}.{old_vid} 2>/dev/null || true"]
                script += [f"{line} 2>/dev/null || true" for line in netplan.svi_lines(seg)]
                done.append(f"{seg.network.id} now VLAN {seg.vid} on the router")
                continue
            script += svi_script(seg, pins.get("routed", {}).get(seg.network.id))
            done.append(f"{seg.network.id} {'cabled to' if seg.network.routed else 'off'} the router")
        for sid, vid in ch["gone"]:
            svi = f"{netplan.BRIDGE}.{vid}"
            script += [f"# {sid} gone from the router", f"ip addr flush dev {svi} 2>/dev/null || true",
                       f"ip link del {svi} 2>/dev/null || true"]
            done.append(f"{sid} off the router")
        old_ports = pins.get("ports", {})
        for link in ch["new"] + ch["moved"]:
            e = _port_entry(plan, link)
            script += port_script(link.label, link.fabric_iface, old_ports.get(link.label),
                                  e["vid"], e["tagged"])
            if link in ch["moved"]:
                done.append(f"{link.label} -> {link.network_id or 'no cable'}")
        if ch["dhcp"]:
            text = _dhcp_text(plan)
            script += (text.splitlines() if text else [
                ": > /etc/dnsmasq.d/winlab.conf 2>/dev/null || true",
                "rc-service dnsmasq stop 2>/dev/null || pkill dnsmasq || true"])
            done.append("router DHCP updated")
        if ch["wan"]:
            from .wan import render
            had = pins.get("wan") not in (None, hashlib.sha256(b"").hexdigest())  # lines were set before
            wan_lines = render(plan, reset=had)
            if wan_lines:
                script += wan_lines
                done.append("WAN lines set")
        if ch["stp"]:
            from .stp import render
            script += render(plan, reset=True)
            done.append("switch bridges and spanning tree rebuilt")
        if ch["psec"]:
            from .portsec import render as port_render
            script += port_render(plan, reset=True)
            done.append("port security and 802.1X set")
        if ch["wlan"]:
            from .wpaent import render as wlan_render
            script += wlan_render(plan, reset=True)
            done.append("WPA2-Enterprise on the access points set")
        if ch["l3"]:
            from .iosl3 import render as l3_render
            script += l3_render(plan, reset=True)
            done.append("router routes, access lists and NAT set")
        if ch["l2"]:
            from .iosl2 import render as l2_render
            script += l2_render(plan, reset=True)
            done.append("switch management addresses and port settings set")
        if ch["rt"]:
            from .iosrouting import live_script  # reads FRRouting's running files first
            script += live_script(plan, runner)
            done.append("router OSPF, BGP, VRFs and VRRP set")

        if ch.get("pol"):
            from .routerpolicy import render as pol_render
            script += pol_render(plan, reset=True)
            done.append("router tunnels, zone firewall and QoS set")
        if script:
            runner("\n".join(script), timeout=60)
    finally:
        close = getattr(runner, "close", None)
        if close:
            close()
    # The machines' side of the cables.
    from . import devcli
    st = state.load(lab.name)
    for link in ch["links"] + [l for l in ch["new"] if not l.plugged]:
        ns = st.nodes.get(link.node_id) if st else None
        if ns and ns.pid and state.pid_alive(ns.pid):
            up = link.plugged and not devcli.held_down(lab, link)
            if set_link(ns.qmp_port, link.nic_index, up, qmp=qmp, tries=3):
                done.append(f"{link.label} cable {'in' if link.plugged else 'out'}")
    data = snapshot(plan, fab.pid, slots)
    data["pending"] = {k: v for k, v in pins.get("pending", {}).items() if k not in data["ports"]}
    _write(lab.name, data)
    for line in done:
        emit(line)
    return {"live": True, "done": done, "note": ""}


# ------------------------------------------------------------------ reading
LIVE_CMD = ("echo '#neigh'; ip -4 neigh show; echo '#leases'; "
            "cat /var/lib/misc/dnsmasq.leases 2>/dev/null; echo '#fdb'; "
            "bridge fdb show br lab0 2>/dev/null | grep -v permanent; echo '#mac'; "
            "cat /sys/class/net/lab0/address 2>/dev/null")


def parse_live(text: str) -> dict:
    """The router's view of who is on the network: address by MAC (ARP
    table, DHCP leases) and which MACs its switch has seen frames from."""
    section, ips, seen, router_mac = "", {}, set(), ""
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("#"):
            section = line[1:]
            continue
        parts = line.split()
        if section == "neigh" and "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1].lower()
            if "FAILED" not in parts and "INCOMPLETE" not in parts:
                ips.setdefault(mac, set()).add(parts[0])
        elif section == "leases" and len(parts) >= 3:
            ips.setdefault(parts[1].lower(), set()).add(parts[2])
        elif section == "fdb" and parts:
            seen.add(parts[0].lower())
        elif section == "mac" and parts:
            router_mac = parts[0].lower()
    return {"ips": {m: sorted(v) for m, v in ips.items()}, "seen": sorted(seen), "router_mac": router_mac}


# ------------------------------------------------------------------ packets
# The router's switch sees every frame of the lab, so a short capture on all
# its interfaces is the traffic of the whole network: a frame coming in on a
# machine's port (In) left that machine, one going out (Out) is delivered to
# it, and one on the router's own interface on a switch (an svi) is the
# router receiving or sending it. The workbench canvas plays these back on
# the cables, at the times they were captured.
CAPTURE_SECONDS = 2
CAPTURE_MAX = 160

_PORTS = {53: "DNS", 67: "DHCP", 68: "DHCP", 88: "Kerberos", 123: "NTP", 135: "RPC", 137: "NetBIOS",
          138: "NetBIOS", 139: "SMB", 389: "LDAP", 445: "SMB", 464: "Kerberos", 636: "LDAPS",
          3268: "LDAP", 3389: "RDP", 5353: "mDNS", 5355: "LLMNR", 1900: "SSDP", 80: "HTTP", 443: "HTTPS",
          22: "SSH", 5985: "WinRM", 5986: "WinRM", 3702: "WS-Discovery", 546: "DHCPv6", 547: "DHCPv6",
          161: "SNMP", 514: "Syslog", 1433: "SQL", 69: "TFTP", 4011: "PXE", 9100: "Printing", 631: "IPP", 500: "IKE",
          4500: "IKE"}


def capture_cmd(seconds: int = CAPTURE_SECONDS, count: int = CAPTURE_MAX) -> str:
    return (f"echo '#pkts'; timeout {seconds} tcpdump -i any -nn -tt -l -c {count} "
            f"not ether proto 0x88cc 2>/dev/null")


def classify(summary: str) -> str:
    """The protocol a tcpdump line is, in the words a sysadmin uses."""
    if summary.startswith("ARP"):
        return "ARP"
    if summary.startswith("IP6"):
        if "ICMP6" in summary:
            return "ICMPv6"
    if "ICMP" in summary:
        return "ICMP"
    ports = [int(p) for p in re.findall(r"\.(\d{1,5})[ :]", summary.split(":")[0] + ":")]
    for p in sorted(ports, key=lambda p: (p not in _PORTS, p)):
        if p in _PORTS:
            return _PORTS[p]
    if "Flags [" in summary or " tcp " in summary:
        return "TCP"
    if "UDP" in summary or " udp " in summary:
        return "UDP"
    return "IPv6" if summary.startswith("IP6") else "other"


def parse_packets(text: str, plan) -> list[dict]:
    """tcpdump -i any lines -> what moved where on the canvas: {t (ms from
    the first), at ("port" | "svi"), id (a machine port label, or the
    switch an svi serves), dir ("in" towards the switch or the router,
    "out" away from it), proto, text}."""
    ports = {l.fabric_iface: l.label for l in plan.ports if l.fabric_iface}
    svis = {seg.svi: sid for sid, seg in plan.segments.items() if seg.network.routed}
    out, t0, section = [], None, ""
    for line in (text or "").splitlines():
        if line.startswith("#"):
            section = line[1:].strip()
            continue
        if section != "pkts":
            continue
        m = _PKT_RE.match(line)
        if not m:
            continue
        ts, iface, way, summary = m.groups()
        if iface in ports:
            at, ident = "port", ports[iface]
            # "In" on a machine's port: the machine sent it into the switch.
            direction = "out" if way == "Out" else "in"
        elif iface in svis:
            at, ident = "svi", svis[iface]
            # "In" on the router's interface: the router received it.
            direction = "in" if way != "Out" else "out"
        else:
            continue
        t = float(ts)
        t0 = t if t0 is None else t0
        out.append({"t": int((t - t0) * 1000), "at": at, "id": ident, "dir": direction,
                    "proto": classify(summary), "text": summary[:200]})
    return out


_PKT_RE = re.compile(r"^(\d+\.\d+)\s+(\S+)\s+(In|Out|B|M|P)\s+(.*)$")
