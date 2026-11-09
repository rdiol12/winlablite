"""CCNA and Network+ basics on the lab's own consoles: the checks of their
exercises, and the troubleshooting tickets a first-line network technician
gets every week.

The lessons (content/lessons/vlans-access-trunks.toml, ipv4-static-routes,
ios-acls-standard-extended, ios-nat-pat) are typed at the switches' and the
router's consoles (winlab/devcli.py, iosl3.py), which already make VLANs,
trunks, routes, access lists and NAT real on the router. What is here:

* the exercises' checks graded from the lab file (``node = "winlab"``):
  which VLANs each switch has, what a trunk carries and its native VLAN, the
  router's sub-interfaces, and what an access list or a NAT rule decides
  for a given packet (iosl3.decide, the same decision nftables makes);
* the tickets broken from outside the machine (guestfaults.HOST_BREAKS):
  a native VLAN mismatch on the trunk between two switches, a VLAN missing
  from a trunk's allowed list, a PC's port in the wrong access VLAN, a port
  err-disabled by a port security violation, a port hard-set to 100/full
  (a duplex mismatch, with its losses), an extended list applied in the
  wrong direction, NAT's inside and outside swapped, and a PC given the
  address another machine has. Each break writes what it changed to the
  lab file as the console would have, pushes it into the running router
  (livenet.sync) and keeps what it was in the lab's folder
  (netbasics-fault.json), so Give up puts it back. It also leaves, inside
  the PC, the address and gateway the PC must have (PROBE): the verify reads
  that file, so a PC that came back on another subnet is not taken as fixed;
* two tickets broken inside the PC itself, from its netplan file: a wrong
  default gateway and a wrong subnet mask.

A native VLAN mismatch is also what CDP reports on both switches
(%CDP-4-NATIVE_VLAN_MISMATCH in show logging), as real switches do every
minute: native_log() writes it whenever a trunk's native VLAN is set.
"""

from __future__ import annotations

import ipaddress
import json
import time

from . import devcli, paths, state

QUICK = True   # the breaks take seconds (guestfaults.host_break_is_quick)
FAULT_FILE = "netbasics-fault.json"
PROBE = "/var/lib/winlab/netbasics-probe"      # "<address/len> <gateway>" the PC must have
ACL_PROBE = "/var/lib/winlab/netbasics-acl"     # the router address on the far side a guest must not reach
NAT_PROBE = "/var/lib/winlab/netbasics-nat"     # "<inside global> <web server on the outside>"
NETPLAN = "/etc/netplan/50-cloud-init.yaml"
NETPLAN_BAK = "/var/lib/winlab/netbasics-netplan.bak"


class NetBasicsError(Exception):
    pass


# ------------------------------------------------------------------ CDP's native VLAN check
def native_mismatches(lab) -> list[tuple[str, str, int, str, str, int]]:
    """(switch, its port, its native VLAN, the far switch, its port, its
    native VLAN) per trunk between two switches whose ends disagree."""
    out = []
    for sw in devcli.switches(lab):
        up = devcli.upstream(lab, sw)
        if not up:
            continue
        port_u = dict((b, p) for p, b in devcli.downlinks(lab, up)).get(sw, "")
        if not port_u:
            continue
        try:
            ns = int(lab.devices.get(f"sw:{sw}", {}).get("native:GigabitEthernet0/1", 1))
            nu = int(lab.devices.get(f"sw:{up}", {}).get(f"native:{port_u}", 1))
        except ValueError:
            continue
        if ns != nu:
            out.append((sw, "GigabitEthernet0/1", ns, up, port_u, nu))
    return out


def native_log(lab) -> None:
    """What CDP says on both ends of a trunk whose native VLANs differ,
    into each switch's log (show logging), once per change."""
    from . import lldp, portsec
    for sw, port, ns, up, port_u, nu in native_mismatches(lab):
        for dev, mine, mv, far, fport, fv in ((sw, port, ns, up, port_u, nu), (up, port_u, nu, sw, port, ns)):
            if not lldp.cdp_run(lab, f"sw:{dev}"):
                continue
            portsec.log(lab.name, f"sw:{dev}",
                        [f"%CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch discovered on {mine} ({mv}), "
                         f"with {devcli.hostname(lab, 'sw:' + far)} {fport} ({fv})."], lab=lab)


# ------------------------------------------------------------------ the fault record
def _path(lab_name: str):
    return paths.lab_dir(lab_name) / FAULT_FILE


def faults(lab_name: str) -> dict:
    try:
        d = json.loads(_path(lab_name).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _keep(lab_name: str, fid: str, rec: dict | None) -> None:
    d = faults(lab_name)
    if rec is None:
        d.pop(fid, None)
    else:
        d[fid] = rec
    state.save_json(_path(lab_name), d or None)


def home_ip(lab, node_id: str, nic_index: int, network: str) -> str | None:
    """The address a machine had on a network before a ticket moved its port
    out of it: moving the port back (switchport access vlan) gives it that
    address again in the lab file, not the first free one."""
    for rec in faults(lab.name).values():
        h = rec.get("home") or {}
        if h.get("node") == node_id and int(h.get("nic", -1)) == nic_index and h.get("network") == network:
            ip = h.get("ip")
            if ip and not any(n.ip == ip and nd.id != node_id for nd in lab.nodes.values() for n in nd.nics):
                return ip
    return None


def _put(lab, was: list, dev: str, key: str, val: str | None) -> None:
    own = lab.devices.setdefault(dev, {})
    was.append([dev, key, own.get(key)])
    if val is None:
        own.pop(key, None)
    else:
        own[key] = val


def _undo(lab, was: list) -> None:
    for dev, key, val in reversed(was):
        own = lab.devices.setdefault(dev, {})
        if val is None:
            own.pop(key, None)
        else:
            own[key] = val


# ------------------------------------------------------------------ the lab and the machines
def _load(lab_name: str):
    from . import netplan, schema
    lab = schema.load(lab_name)
    return lab, netplan.compile_topology(lab, check_ports=False)


def _push(lab) -> str:
    """The lab file written and the running router brought in line."""
    from . import editor, livenet
    editor.save(lab)
    try:
        res = livenet.sync(lab)
    except livenet.LiveNetError as exc:
        return f"; the running network did not take it: {exc}"
    return "" if res.get("live") else "; " + (res.get("note") or "the network is off")


def _guest(lab_name: str, node: str, cmd: str) -> tuple[bool, str]:
    """A command inside a machine, over its agent channel."""
    from .guestctl import GuestChannel, GuestError
    st = state.load(lab_name)
    ns = st.nodes.get(node) if st else None
    if not ns or not ns.pid or not state.pid_alive(ns.pid):
        return False, f"{node} is not running"
    try:
        ch = GuestChannel(ns.serial_port).connect(retries=8, delay=2)
    except (GuestError, OSError) as exc:
        return False, str(exc)
    try:
        r = ch.run(cmd, shell="sh", timeout=120)
        return r.ok, (r.out if r.ok else (r.err or r.out))
    finally:
        ch.close()


def _probe_cmd(ip: str, prefix: int, gw: str) -> str:
    return (f"mkdir -p /var/lib/winlab && echo '{ip}/{prefix} {gw}' > {PROBE}")


def _link(lab, plan, node: str):
    link = next((l for l in plan.ports_for(node) if l.nic_index == 0), None)
    if link is None or not link.plugged:
        raise NetBasicsError(f"{node} has no cable in its first network card")
    return link


def _where(lab, plan, node: str):
    """(switch id, its port number, the link, the machine's network) of a
    machine's first card."""
    link = _link(lab, plan, node)
    where = devcli.port_no(lab, plan, link.label)
    if not where:
        raise NetBasicsError(f"{node} is not cabled to a switch port")
    return where[0], where[1], link, lab.networks[link.network_id]


def _probe(lab, plan, node: str) -> tuple[str, int, str]:
    """(address, prefix, gateway) the machine has while its port is right."""
    nd = lab.nodes[node]
    nic = nd.nics[0]
    if not nic.ip:
        raise NetBasicsError(f"{node} takes its address from DHCP: these tickets need a machine with a fixed one")
    seg = plan.segment_of(nic.network).network
    return nic.ip, seg.prefixlen, seg.default_gateway


# ------------------------------------------------------------------ the switch tickets
def _sw_break(fid: str, lab_name: str, node: str, clear: bool, change) -> tuple[bool, str]:
    """The common shape: change(lab, plan, node, was) -> (message, home);
    clear puts `was` back."""
    try:
        lab, plan = _load(lab_name)
        if clear:
            rec = faults(lab_name).get(fid)
            if not rec:
                return True, "nothing of this ticket is left in the lab"
            _undo(lab, rec.get("was", []))
            h = rec.get("home") or {}
            if h:
                from . import editor
                nic = lab.nodes[h["node"]].nics[int(h["nic"])]
                if nic.network != h["network"]:
                    editor.cable(lab, h["node"], int(h["nic"]), h["network"], ip=h.get("ip"))
            note = _push(lab)
            _links(lab_name, node, up=True)
            _keep(lab_name, fid, None)
            return True, "put back as it was" + note
        ip, prefix, gw = _probe(lab, plan, node)
        was: list = []
        msg, home = change(lab, plan, node, was)
        ok, why = _guest(lab_name, node, _probe_cmd(ip, prefix, gw))
        if not ok:
            return False, f"{node} did not answer ({why}): start it and try again"
        _keep(lab_name, fid, {"was": was, "home": home, "node": node, "t": int(time.time())})
        return True, msg + _push(lab)
    except (NetBasicsError, KeyError, ValueError) as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 - a lab that does not load cannot be broken
        return False, str(exc)


def _links(lab_name: str, node: str, up: bool) -> None:
    """A machine's link up or down at its card (QEMU's set_link), as an
    err-disabled port drops the light and no shutdown brings it back."""
    try:
        from . import portsec
        lab, plan = _load(lab_name)
        link = _link(lab, plan, node)
        if up and devcli.held_down(lab, link):
            return
        portsec._set_link(lab, link, up)
    except Exception:  # noqa: BLE001 - a machine that is off has no link to set
        pass


def _native(lab, plan, node: str, was: list):
    sw, _, link, net = _where(lab, plan, node)
    up = devcli.upstream(lab, sw)
    if not up:
        raise NetBasicsError(f"{node}'s switch is cabled to the router, not to another switch: this ticket "
                             f"needs a PC on a switch below another (campus-vlans: pc-b on floor)")
    port_u = dict((b, p) for p, b in devcli.downlinks(lab, up)).get(sw, "")
    own_s = lab.devices.get(f"sw:{sw}", {})
    own_u = lab.devices.get(f"sw:{up}", {})
    ns = int(own_s.get("native:GigabitEthernet0/1", 1))
    nu = int(own_u.get(f"native:{port_u}", 1))
    tag = net.vlan_no
    if tag != ns:
        # The PC's VLAN becomes this end's native one: its frames cross untagged,
        # into whatever native VLAN the other end has.
        _put(lab, was, f"sw:{sw}", "native:GigabitEthernet0/1", str(tag))
        where = f"{devcli.hostname(lab, 'sw:' + sw)} Gi0/1"
    else:
        other = next((v.vlan_no for v in devcli.vlans_of(lab, up) if v.vlan_no not in (tag, nu)), 99)
        _put(lab, was, f"sw:{up}", f"native:{port_u}", str(other))
        where = f"{devcli.hostname(lab, 'sw:' + up)} {devcli.short_if(port_u)}"
    native_log(lab)
    return f"the native VLAN of one end of the trunk changed ({where})", None


def _allowed(lab, plan, node: str, was: list):
    sw, _, link, net = _where(lab, plan, node)
    up = devcli.upstream(lab, sw)
    if not up:
        raise NetBasicsError(f"{node}'s switch is cabled to the router, not to another switch: this ticket "
                             f"needs a PC on a switch below another (campus-vlans: pc-b on floor)")
    port_u = dict((b, p) for p, b in devcli.downlinks(lab, up)).get(sw, "")
    tag = devcli.trunk_tag(lab, sw, up, net.vlan_no)
    if tag is None:
        raise NetBasicsError(f"{node}'s VLAN does not cross the trunk now: fix that first")
    own_u = lab.devices.get(f"sw:{up}", {})
    have = devcli.allowed_tags(lab, up, port_u)
    if have is None:
        have = {v.vlan_no for v in devcli.vlans_of(lab, up)} | {int(own_u.get(f"native:{port_u}", 1))}
    keep = sorted(have - {tag})
    _put(lab, was, f"sw:{up}", f"allowed:{port_u}", devcli.vlan_text(set(keep)) or "none")
    devcli.refresh_trunks(lab, up)
    return f"VLAN {tag} is gone from a trunk's allowed list", None


def _access(lab, plan, node: str, was: list):
    sw, _, link, net = _where(lab, plan, node)
    others = [v for v in devcli.vlans_of(lab, sw) if v.id != net.id]
    routed = [v for v in others if plan.segment_of(v.id).network.routed]
    if not others:
        raise NetBasicsError(f"{node}'s switch has one VLAN: there is no wrong one to put it in")
    wrong = sorted(routed or others, key=lambda v: (v.vlan_no == 1, v.vlan_no))[0]
    from . import editor
    nic = lab.nodes[node].nics[link.nic_index]
    home = {"node": node, "nic": link.nic_index, "network": net.id, "ip": nic.ip}
    editor.cable(lab, node, link.nic_index, wrong.id)
    return f"{node}'s switch port is now in VLAN {wrong.vlan_no}", home


def _errdis(lab, plan, node: str, was: list):
    from . import portsec
    sw, no, link, net = _where(lab, plan, node)
    dev = f"sw:{sw}"
    label = link.label
    rogue = "0a:" + ":".join(link.mac.lower().split(":")[1:])   # a laptop's address, not the PC's
    _put(lab, was, dev, f"psec:{label}", "yes")
    _put(lab, was, dev, f"psec-sticky:{label}", "yes")
    _put(lab, was, dev, f"psec-stuck:{label}", link.mac.lower())
    now = time.time()
    _put(lab, was, dev, f"psec-err:{label}", f"{rogue} {int(now)}")
    p = portsec._port(lab, sw, no, link)
    rt = portsec.runtime(lab.name)
    rt.setdefault("count", {})[label] = int(rt.get("count", {}).get(label, 0)) + 1
    rt.setdefault("last", {})[label] = rogue
    lines = ["\n".join(portsec._violation_lines(p, rogue))]
    portsec.log(lab.name, dev, lines, rt=rt, now=now, lab=lab)
    portsec._rt_save(lab.name, rt)
    return (f"a laptop was plugged in at {node}'s desk for a minute: {devcli.hostname(lab, dev)} "
            f"err-disabled Fa0/{no}"), None


def _duplex(lab, plan, node: str, was: list):
    sw, no, link, net = _where(lab, plan, node)
    dev = f"sw:{sw}"
    _put(lab, was, dev, f"speed:{link.label}", "100")
    _put(lab, was, dev, f"duplex:{link.label}", "full")
    return f"Fa0/{no} on {devcli.hostname(lab, dev)} is hard-set to 100/full", None


def native_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    return _sw_break("trunk-native-mismatch", lab_name, node, clear, _native)


def allowed_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    return _sw_break("trunk-vlan-not-allowed", lab_name, node, clear, _allowed)


def access_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    return _sw_break("access-port-wrong-vlan", lab_name, node, clear, _access)


def errdis_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    ok, msg = _sw_break("port-err-disabled", lab_name, node, clear, _errdis)
    if ok and not clear:
        _links(lab_name, node, up=False)
    return ok, msg


def duplex_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    return _sw_break("speed-duplex-mismatch", lab_name, node, clear, _duplex)


# ------------------------------------------------------------------ the router tickets
def _private(net) -> bool:
    return any(net.net.subnet_of(ipaddress.ip_network(p)) for p in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _router_ifs(lab, plan) -> list[tuple[str, object]]:
    """(interface, network) per router interface with an address in a
    routed network."""
    devcli.pin_router_ports(lab)
    own = lab.devices.get(devcli.ROUTER, {})
    out = []
    for k, nid in sorted(own.items()):
        if k.startswith("ip:") and nid in lab.networks and lab.networks[nid].routed:
            out.append((k[3:], lab.networks[nid]))
    return out


def _my_if(lab, plan, node: str) -> tuple[str, object]:
    link = _link(lab, plan, node)
    seg = plan.segment_of(link.network_id).network
    for name, net in _router_ifs(lab, plan):
        if net.id == seg.id:
            return name, net
    raise NetBasicsError(f"the router has no interface in {node}'s network")


def _router_break(fid: str, lab_name: str, node: str, clear: bool, change) -> tuple[bool, str]:
    try:
        lab, plan = _load(lab_name)
        if clear:
            rec = faults(lab_name).get(fid)
            if not rec:
                return True, "nothing of this ticket is left in the lab"
            _undo(lab, rec.get("was", []))
            note = _push(lab)
            _keep(lab_name, fid, None)
            return True, "put back as it was" + note
        was: list = []
        msg, probe = change(lab, plan, node, was)
        ok, why = _guest(lab_name, node, probe)
        if not ok:
            return False, f"{node} did not answer ({why}): start it and try again"
        _keep(lab_name, fid, {"was": was, "node": node, "t": int(time.time())})
        return True, msg + _push(lab)
    except (NetBasicsError, KeyError, ValueError) as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _wild(net) -> str:
    return f"{net.net.network_address} {net.net.hostmask}"


def _acl(lab, plan, node: str, was: list):
    from . import iosl3
    mine, net = _my_if(lab, plan, node)
    far = [(n, x) for n, x in _router_ifs(lab, plan) if n != mine and _private(x)]
    if not far:
        raise NetBasicsError("the router has no other private network to keep this one out of")
    name = f"{net.id.upper().replace('-', '_')}-IN"
    own = lab.devices.setdefault(devcli.ROUTER, {})
    for k in (f"acltype:{name}", f"xacl:{name}", f"acl:{name}", f"acl-in:{mine}", f"acl-out:{mine}"):
        _put(lab, was, devcli.ROUTER, k, None)
    rows = [f"deny ip {_wild(net)} {_wild(x)}" for _, x in far] + [
        f"permit icmp {_wild(net)} any", f"permit tcp {_wild(net)} any eq www",
        f"permit tcp {_wild(net)} any eq 443", f"permit udp {_wild(net)} any eq domain"]
    own[f"acltype:{name}"] = "extended"
    for r in rows:
        iosl3.add_entry(own, name, "extended", r)
    own[f"acl-out:{mine}"] = name
    target = far[0][1].router_ip
    probe = f"mkdir -p /var/lib/winlab && echo '{target}' > {ACL_PROBE}"
    return f"the access list {name} is on {mine}, outbound", probe


def _nat(lab, plan, node: str, was: list):
    mine, net = _my_if(lab, plan, node)
    outside = [(n, x) for n, x in _router_ifs(lab, plan) if not _private(x)]
    if not outside:
        raise NetBasicsError("the router has no interface towards the ISP (an address outside 10/8, 172.16/12 "
                             "and 192.168/16)")
    out_if, out_net = outside[0]
    own = lab.devices.setdefault(devcli.ROUTER, {})
    for k in [k for k in own if k.startswith(("nat:", "natsrc:", "natstatic:"))]:
        _put(lab, was, devcli.ROUTER, k, None)
    name = "NAT-INSIDE"
    for k in (f"acltype:{name}", f"acl:{name}", f"xacl:{name}"):
        _put(lab, was, devcli.ROUTER, k, None)
    _put(lab, was, devcli.ROUTER, f"acltype:{name}", "standard")
    _put(lab, was, devcli.ROUTER, f"acl:{name}", f"10 permit {net.net}")
    _put(lab, was, devcli.ROUTER, f"natsrc:{name}", f"{out_if} overload")
    # swapped: the office's side is "outside", the ISP's "inside"
    _put(lab, was, devcli.ROUTER, f"nat:{mine}", "outside")
    _put(lab, was, devcli.ROUTER, f"nat:{out_if}", "inside")
    hop = next((h for h in (str(a) for a in out_net.net.hosts()) if h != out_net.router_ip), "")
    if not any(k.startswith("route:0.0.0.0/0 ") for k in own) and hop:
        _put(lab, was, devcli.ROUTER, f"route:0.0.0.0/0 {hop}", "1")
    web = next((nd.nics[0].ip for nd in lab.node_list() if "inet-host" in nd.roles and nd.nics and nd.nics[0].ip), "")
    if not web:
        raise NetBasicsError("no web server on the outside (a machine with the inet-host role) to test from")
    _isp_forwards(lab, hop)
    probe = f"mkdir -p /var/lib/winlab && echo '{out_net.router_ip} {web}' > {NAT_PROBE}"
    return "NAT on the router was set up again after a change", probe


def _isp_forwards(lab, hop: str) -> None:
    """The ISP's router forwards, as an ISP's does: best effort, inside the
    machine that has the next hop's address."""
    for nd in lab.node_list():
        if any(n.ip == hop for n in nd.nics) and nd.kind == "linux":
            _guest(lab.name, nd.id, "echo net.ipv4.ip_forward=1 > /etc/sysctl.d/90-isp-router.conf; "
                                    "sysctl -q -w net.ipv4.ip_forward=1; true")


def acl_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    return _router_break("acl-wrong-direction", lab_name, node, clear, _acl)


def nat_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    return _router_break("nat-inside-outside-swapped", lab_name, node, clear, _nat)


# ------------------------------------------------------------------ a machine with another's address
def dupip_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    """Gives the machine (in its netplan file) the address of another
    machine on the same network, as a hand-typed copy of a colleague's
    settings does."""
    try:
        lab, plan = _load(lab_name)
        if clear:
            ok, why = _guest(lab_name, node, f"[ -f {NETPLAN_BAK} ] && cp {NETPLAN_BAK} {NETPLAN} && "
                                             f"netplan apply; rm -f {NETPLAN_BAK}; true")
            _keep(lab_name, "pc-duplicate-ip", None)
            return ok, "its own address is back" if ok else why
        ip, prefix, gw = _probe(lab, plan, node)
        seg = plan.segment_of(lab.nodes[node].nics[0].network).network.id
        twin = next((n.ip for nd in lab.node_list() if nd.id != node for n in nd.nics
                     if n.ip and n.network in lab.networks and plan.segment_of(n.network).network.id == seg), "")
        if not twin:
            raise NetBasicsError(f"no other machine with a fixed address shares {node}'s network")
        cmd = (f"mkdir -p /var/lib/winlab; [ -f {NETPLAN_BAK} ] || cp {NETPLAN} {NETPLAN_BAK}; "
               f"sed -i 's#- {ip}/{prefix}#- {twin}/{prefix}#' {NETPLAN} && netplan apply && "
               f"{_probe_cmd(ip, prefix, gw)}")
        ok, why = _guest(lab_name, node, cmd)
        if not ok:
            return False, f"{node} did not take it ({why})"
        _keep(lab_name, "pc-duplicate-ip", {"node": node, "twin": twin, "t": int(time.time())})
        return True, f"{node} was given an address another machine has"
    except (NetBasicsError, KeyError, ValueError) as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


# ------------------------------------------------------------------ verify scripts (inside the PC)
VERIFY_LINK = (f"set -- $(cat {PROBE} 2>/dev/null); "
               "if [ -n \"$2\" ] && ip -o -4 addr show 2>/dev/null | grep -q \" $1 \" "
               "&& ping -c 2 -W 2 \"$2\" >/dev/null 2>&1; then echo True; else echo False; fi")
# A duplex mismatch loses about 3 frames in 100: 200 quick pings to the
# gateway, one lost at most.
VERIFY_DUPLEX = (f"set -- $(cat {PROBE} 2>/dev/null); "
                 "[ -n \"$2\" ] || { echo False; exit 0; }; "
                 "r=$(ping -c 200 -i 0.01 -W 1 -q \"$2\" 2>/dev/null | awk '/received/ {print $4}'); "
                 "if [ -n \"$r\" ] && [ \"$r\" -ge 199 ]; then echo True; else echo False; fi")
VERIFY_ACL = (f"far=$(cat {ACL_PROBE} 2>/dev/null); gw=$(ip route 2>/dev/null | awk '/^default/ {{print $3; exit}}'); "
              "if [ -n \"$far\" ] && [ -n \"$gw\" ] && ping -c 2 -W 2 \"$gw\" >/dev/null 2>&1 "
              "&& ! ping -c 2 -W 2 \"$far\" >/dev/null 2>&1; then echo True; else echo False; fi").replace("{{", "{").replace("}}", "}")
VERIFY_NAT = (f"set -- $(cat {NAT_PROBE} 2>/dev/null); [ -n \"$2\" ] || {{ echo False; exit 0; }}; "
              "out=$(curl -s -m 6 \"http://$2/\" 2>/dev/null || wget -qO- -T 6 \"http://$2/\" 2>/dev/null); "
              "case \"$out\" in *\"from $1\"*) echo True;; *) echo False;; esac").replace("{{", "{").replace("}}", "}")
# The address the netplan file had before the ticket, now on the card and in the file.
_ADDR_AWK = "awk '$1 == \"-\" && $2 ~ /^[0-9]/ && index($2, \"/\") {print $2; exit}'"
_WANT = f"want=$({_ADDR_AWK} {NETPLAN_BAK} 2>/dev/null); "
VERIFY_ADDR = (_WANT +
               "if [ -n \"$want\" ] && ip -o -4 addr show dev eth0 2>/dev/null | grep -q \" $want \" "
               "&& grep -rqs -- \"- $want\" /etc/netplan/; then echo True; else echo False; fi")
VERIFY_GW = (f"want=$(awk '/via:/ {{print $2; exit}}' {NETPLAN_BAK} 2>/dev/null); ".replace("{{", "{").replace("}}", "}") +
             "if [ -n \"$want\" ] && ip route show default 2>/dev/null | grep -q \"via $want \" "
             "&& grep -rqs \"via: $want\" /etc/netplan/ && ping -c 2 -W 2 \"$want\" >/dev/null 2>&1; "
             "then echo True; else echo False; fi")

# Inside an Ubuntu PC: its netplan file kept, then one value changed and applied.
_KEEP = f"mkdir -p /var/lib/winlab; [ -f {NETPLAN_BAK} ] || cp {NETPLAN} {NETPLAN_BAK}; "
APPLY_GW = (_KEEP + f"gw=$(awk '/via:/ {{print $2; exit}}' {NETPLAN_BAK}); "
            "[ -n \"$gw\" ] || { echo 'no default route in the netplan file' >&2; exit 1; }; "
            "bad=\"${gw%.*}.254\"; [ \"$bad\" = \"$gw\" ] && bad=\"${gw%.*}.253\"; "
            f"sed -i \"s#via: $gw\\$#via: $bad#\" {NETPLAN} && netplan apply").replace("{{", "{").replace("}}", "}")
APPLY_MASK = (_KEEP + f"a=$({_ADDR_AWK} {NETPLAN_BAK}); "
              "[ -n \"$a\" ] || { echo 'no fixed address in the netplan file' >&2; exit 1; }; "
              "p=${a#*/}; n=$((p - 8)); [ $n -lt 8 ] && n=8; "
              f"sed -i \"s#- $a#- ${{a%/*}}/$n#\" {NETPLAN} && netplan apply").replace("{{", "{").replace("}}", "}")
CLEAR_NETPLAN = (f"[ -f {NETPLAN_BAK} ] && cp {NETPLAN_BAK} {NETPLAN} && netplan apply; rm -f {NETPLAN_BAK}; true")


# ------------------------------------------------------------------ the problems
HOSTS = {"nb-native": "winlab.netbasics:native_break", "nb-allowed": "winlab.netbasics:allowed_break",
         "nb-access": "winlab.netbasics:access_break", "nb-errdis": "winlab.netbasics:errdis_break",
         "nb-duplex": "winlab.netbasics:duplex_break", "nb-acl": "winlab.netbasics:acl_break",
         "nb-nat": "winlab.netbasics:nat_break", "nb-dupip": "winlab.netbasics:dupip_break"}
FROM_OUTSIDE = "echo 'this ticket is set from outside the machine: winlab changes the switch or the router'"


def register_faults(reg) -> None:
    from .guestfaults import LINUX, GuestFault

    def host(fid, key, title, teaches, symptom, hints, verify=VERIFY_LINK, clear=""):
        reg(GuestFault(id=fid, host=key, title=title, os=LINUX, shell="sh", images=("ubuntu",),
                       teaches=teaches, symptom=symptom, apply=FROM_OUTSIDE,
                       clear=clear or "echo 'Give up puts the switch or the router back as it was'",
                       hints=hints, verify=verify))

    host("trunk-native-mismatch", "nb-native",
         "The two ends of the trunk between the switches disagree on the native VLAN",
         "the native VLAN of an 802.1Q trunk, how untagged frames cross into the other end's native VLAN, CDP's "
         "mismatch message, and show interfaces trunk read on both ends",
         "this PC on the floor switch lost its gateway and its colleagues on the core switch; its link light is "
         "on and nothing was unplugged",
         ("The PC has a link and its address, and cannot reach its gateway. Its VLAN reaches the router only "
          "across the trunk between the two switches: look at that trunk from both ends.",
          "show interfaces trunk on each switch: compare the Native vlan column at the two ends of the cable "
          "(floor's Gi0/1, core's Gi0/2). show logging on either switch has CDP's NATIVE_VLAN_MISMATCH line.",
          "Make the two ends agree: interface gi0/1 on floor (or gi0/2 on core), switchport trunk native vlan "
          "with the same number as the other end (no switchport trunk native vlan puts it back to 1)."))
    host("trunk-vlan-not-allowed", "nb-allowed",
         "A VLAN was left out of a trunk's allowed list",
         "switchport trunk allowed vlan, why add matters, and reading Vlans allowed on trunk in show interfaces trunk",
         "after a change on the core switch last night, the staff PC on the floor switch cannot reach its "
         "gateway or the server; the PCs on the core switch are fine",
         ("Only the PCs behind the trunk are cut off, and the ones in the same VLAN on the other switch are "
          "fine: the trunk is up, so look at what it carries.",
          "show interfaces trunk on core: the Vlans allowed on trunk line for Gi0/2 lacks the PC's VLAN. On "
          "floor, Vlans allowed and active lists it: one end drops it.",
          "interface gi0/2 on core, switchport trunk allowed vlan add <the VLAN>. Without add, the list you "
          "type replaces the whole list."))
    host("access-port-wrong-vlan", "nb-access",
         "A PC's switch port was put in the wrong access VLAN",
         "access ports and their VLAN, show vlan brief and show interfaces switchport, and how a PC in the wrong "
         "VLAN looks from the PC (address of one subnet, broadcast domain of another)",
         "this PC still has its usual address but reaches nothing, not even its gateway; the colleague at the next "
         "desk is fine",
         ("Its address and gateway look right, and ping to the gateway fails with Destination Host Unreachable: "
          "nothing answers its ARP. The PC is fine; what it is plugged into is not.",
          "show vlan brief on its switch: which VLAN is its port (show interfaces status names the PC) in, and "
          "which VLAN is its subnet's? show mac address-table interface <port> shows it learned in that VLAN.",
          "interface <its port>, switchport access vlan <the staff VLAN>. The PC answers its gateway again at once."))
    host("port-err-disabled", "nb-errdis",
         "A PC's port is err-disabled after a port security violation",
         "port security's shutdown violation mode, err-disabled ports, show port-security and show logging, and "
         "bringing a port back with shutdown and no shutdown",
         "this PC has had no network since someone plugged a laptop in at its desk this morning; the laptop is "
         "gone, the PC still shows no link",
         ("The PC reports no carrier at all: the switch dropped the link. show interfaces status on its switch "
          "says how the port is.",
          "The port is err-disabled. show port-security interface <port> and show logging tell why: a "
          "PSECURE_VIOLATION from an address that is not the PC's. The laptop is gone, but an err-disabled port "
          "stays down until someone brings it back.",
          "interface <the port>, shutdown, then no shutdown. Port security stays on with the PC's sticky "
          "address, so the PC is let in and a stranger would shut it again."))
    host("speed-duplex-mismatch", "nb-duplex",
         "A PC's port is hard-set to 100/full against a card that negotiates",
         "speed and duplex autonegotiation, a duplex mismatch and its symptoms (late collisions, CRC errors, "
         "slowness that grows with load), and reading show interfaces status and show interfaces counters",
         "this PC answers pings, but copies to and from it crawl and lose packets, worse the busier it gets",
         ("Small pings work, a long fast ping (sudo ping -c 200 -i 0.01 <gateway>) loses a few: that is a "
          "physical or link-layer problem, not routing. Look at the PC's switch port.",
          "show interfaces status: the port reads full and 100 without the a- the others have. It was hard-set; "
          "the PC's card, hearing no negotiation, fell back to half duplex. show interfaces <port> counts late "
          "collisions and output errors that rise while you ping.",
          "interface <the port>, speed auto, duplex auto (or set both ends by hand to the same thing, never one "
          "end only)."),
         verify=VERIFY_DUPLEX)
    host("acl-wrong-direction", "nb-acl",
         "The guest network's access list is applied in the wrong direction",
         "extended access lists, in versus out on an interface, where an extended list belongs (near the source), "
         "and reading show access-lists and show ip interface",
         "the access list meant to keep guests out of the office was put on the router yesterday, yet a guest "
         "laptop still gets answers from the router's office address, and the office PCs log connection attempts "
         "from guests",
         ("The list exists and its entries look right; what does it filter? Write down where the guests' "
          "packets enter the router and which way they go.",
          "show ip interface <the guest interface>: Outgoing access list is set, Inbound is not. The entries all "
          "match a guest source address, which packets leaving the router towards the guests never have: only "
          "the implicit deny at the end ever counts (show access-lists).",
          "interface <the guest interface>, no ip access-group <list> out, ip access-group <list> in."),
         verify=VERIFY_ACL)
    host("nat-inside-outside-swapped", "nb-nat",
         "NAT's inside and outside interfaces were swapped",
         "ip nat inside and ip nat outside, what overload translates and when, and reading show ip nat "
         "translations and show ip nat statistics",
         "since the router's NAT was set up again after a change, the office cannot reach the web server at the "
         "ISP; the router itself can",
         ("The router reaches the ISP, the office does not: the difference is the source address. What does the "
          "web server (or the ISP's router) see as the source of the office's packets?",
          "show ip nat translations is empty while the office tries; show ip nat statistics lists the "
          "interfaces: the office's interface is Outside and the ISP's Inside.",
          "interface <office>, ip nat inside; interface <ISP link>, ip nat outside. The ip nat inside source "
          "list ... overload line is right as it is."),
         verify=VERIFY_NAT)
    host("pc-duplicate-ip", "nb-dupip",
         "Two machines have the same IPv4 address",
         "duplicate address symptoms, ARP and the neighbour table, arping's duplicate address detection, and "
         "where a static address lives on Ubuntu (netplan)",
         "this PC and a colleague's keep dropping off the network, a few minutes each, in turns",
         ("Both PCs work some of the time: something else answers for one of them. Compare the MAC address the "
          "gateway has for the address (show ip arp on the router) with the PC's own (ip link).",
          "On the PC: ip -4 addr and ip link; the router's show ip arp has that address on the other PC's MAC "
          "now and then (where arping is installed, sudo arping -D -c 3 -I eth0 <its address> gets a reply). "
          "The address in /etc/netplan/50-cloud-init.yaml is not the one this PC was given.",
          "Put this PC's own address back in its netplan file (sudo nano /etc/netplan/50-cloud-init.yaml), then "
          "sudo netplan apply."),
         verify=VERIFY_ADDR, clear=CLEAR_NETPLAN)
    reg(GuestFault(
        id="pc-wrong-gateway",
        images=("ubuntu",),
        title="A PC has the wrong default gateway",
        os=LINUX,
        shell="sh",
        teaches="the default gateway, what a host does with a packet for another subnet, ip route and traceroute, "
                "and netplan on Ubuntu",
        symptom="this PC reaches the machines on its own subnet but nothing beyond it",
        apply=APPLY_GW,
        clear=CLEAR_NETPLAN,
        hints=(
            "Same subnet works, other subnets do not: the PC itself decides that difference. ip route shows "
            "where it sends a packet for another subnet.",
            "The default route points at an address nobody answers (ip neigh shows it FAILED or INCOMPLETE). "
            "The router's address on this subnet is in show ip interface brief on its console.",
            "sudo nano /etc/netplan/50-cloud-init.yaml: the via: under routes: is the gateway; put the router's "
            "address there, then sudo netplan apply.",
        ),
        verify=VERIFY_GW,
    ))
    reg(GuestFault(
        id="pc-wrong-mask",
        images=("ubuntu",),
        title="A PC has the wrong subnet mask",
        os=LINUX,
        shell="sh",
        teaches="the subnet mask and what a host thinks is on its own link, ARP for a host that is not there, "
                "and netplan on Ubuntu",
        symptom="this PC reaches its gateway and its own subnet, but not a server on another VLAN that everyone "
                "else reaches",
        apply=APPLY_MASK,
        clear=CLEAR_NETPLAN,
        hints=(
            "The gateway works, so the PC sends some traffic to it. Which destinations does it send to the "
            "gateway and which does it try to reach directly? ip route get <the server's address> tells you.",
            "ip route get says the server is on eth0 itself, with no via: the PC's mask is wider than the subnet "
            "(ip -4 addr), so it ARPs for the server on its own VLAN, and nobody answers (ip neigh).",
            "sudo nano /etc/netplan/50-cloud-init.yaml: the /prefix after the address must be the subnet's "
            "(the same as the router's interface, show ip interface brief); then sudo netplan apply.",
        ),
        verify=VERIFY_ADDR,
    ))


# ------------------------------------------------------------------ exercise checks
def _sw(lab, name: str) -> str:
    """A switch by its id or hostname."""
    for sw in devcli.switches(lab):
        if sw == name or devcli.hostname(lab, f"sw:{sw}").lower() == name.lower():
            return sw
    return name


def check_vlan30(lab) -> tuple[bool, str]:
    bad = []
    for sw in ("core", "floor"):
        net = devcli.vlan_net(lab, _sw(lab, sw), 30)
        if net is None:
            bad.append(f"{sw} has no VLAN 30")
        elif not net.description or net.description.startswith(("VLAN", "the ")):
            bad.append(f"VLAN 30 on {sw} has no name")
    return (not bad, "; ".join(bad) or "VLAN 30 is on both switches, named")


def check_pcc_vlan30(lab) -> tuple[bool, str]:
    nd = lab.nodes.get("pc-c")
    net = lab.networks.get(nd.nics[0].network) if nd and nd.nics else None
    if net is None or net.home != _sw(lab, "floor") or net.vlan_no != 30:
        return False, "pc-c's port on floor is not in VLAN 30 (switchport access vlan 30)"
    return True, "pc-c's port is an access port in VLAN 30"


def check_roas30(lab) -> tuple[bool, str]:
    devcli.pin_router_ports(lab)
    own = lab.devices.get(devcli.ROUTER, {})
    core = devcli.vlan_net(lab, _sw(lab, "core"), 30)
    if core is None:
        return False, "core has no VLAN 30"
    for k, nid in own.items():
        if k.startswith("ip:") and nid == core.id and "." in k:
            if core.net == ipaddress.ip_network("10.70.30.0/24"):
                return True, f"{k[3:]} routes VLAN 30 as 10.70.30.0/24"
            return False, f"{k[3:]} routes VLAN 30, but as {core.net}, not 10.70.30.0/24"
    return False, "the router has no sub-interface for VLAN 30 (interface g0/0/0.30, encapsulation dot1Q 30, ip address)"


def check_native99(lab) -> tuple[bool, str]:
    core, floor = _sw(lab, "core"), _sw(lab, "floor")
    port_u = dict((b, p) for p, b in devcli.downlinks(lab, core)).get(floor, "")
    a = lab.devices.get(f"sw:{floor}", {}).get("native:GigabitEthernet0/1", "1")
    b = lab.devices.get(f"sw:{core}", {}).get(f"native:{port_u}", "1") if port_u else "1"
    if a != "99" or b != "99":
        return False, f"native VLAN: floor Gi0/1 {a}, core {devcli.short_if(port_u) or 'Gi0/2'} {b}; both must be 99"
    return True, "both ends of the trunk use native VLAN 99"


def check_pruned(lab) -> tuple[bool, str]:
    core, floor = _sw(lab, "core"), _sw(lab, "floor")
    port_u = dict((b, p) for p, b in devcli.downlinks(lab, core)).get(floor, "")
    allow = devcli.allowed_tags(lab, core, port_u) if port_u else None
    if allow is None:
        return False, "core's trunk to floor still allows every VLAN"
    need = {10, 30, 99}
    if not need <= allow or 20 in allow:
        return False, (f"core's trunk to floor allows {devcli.vlan_text(allow) or 'none'}: it must carry 10, 30 "
                       f"and 99 and not 20")
    return True, f"core's trunk to floor allows {devcli.vlan_text(allow)}"


def _router_own(lab) -> dict:
    devcli.pin_router_ports(lab)
    return lab.devices.get(devcli.ROUTER, {})


def _if_of(lab, net_id: str, sub_ok: bool = False) -> str:
    own = _router_own(lab)
    return next((k[3:] for k, v in sorted(own.items()) if k.startswith("ip:") and v == net_id), "")


def check_acl_in(lab) -> tuple[bool, str]:
    from . import iosl3
    own = _router_own(lab)
    gi = _if_of(lab, "guest")
    name = own.get(f"acl-in:{gi}", "")
    if not name or iosl3.kind_of(own, name) != "extended":
        return False, f"no extended list is applied in on {gi or 'the guest interface'} (ip access-group <name> in)"
    tests = [("10.80.20.10", "10.80.0.10", "tcp", 445, "deny", "a guest to an office PC"),
             ("10.80.20.10", "10.80.0.2", "icmp", None, "deny", "a guest to the router's office address"),
             ("10.80.20.10", "203.0.113.80", "tcp", 80, "permit", "a guest to a web server on the Internet"),
             ("10.80.20.10", "10.80.20.1", "icmp", None, "permit", "a guest's ping to its gateway")]
    bad = [w for s, d, p, port, want, w in tests if iosl3.decide(own, name, s, d, p, None, port)[0] != want]
    if bad:
        return False, f"{name} does not do what it should for: " + "; ".join(bad)
    return True, f"{name} is in on {gi}: guests reach the web, not the office"


def check_acl_portal(lab) -> tuple[bool, str]:
    from . import iosl3
    own = _router_own(lab)
    gi = _if_of(lab, "guest")
    name = own.get(f"acl-in:{gi}", "")
    if not name:
        return False, "no list is in on the guest interface"
    if iosl3.decide(own, name, "10.80.20.10", "10.80.0.10", "tcp", None, 80)[0] != "permit":
        return False, f"{name} still drops a guest's web request to 10.80.0.10 (an entry before the deny, by sequence number)"
    if iosl3.decide(own, name, "10.80.20.10", "10.80.0.10", "tcp", None, 22)[0] != "deny":
        return False, f"{name} lets guests reach 10.80.0.10 on more than port 80"
    return True, f"{name} lets guests reach the portal on 10.80.0.10 port 80 and nothing else of the office"


def check_acl_std_gone(lab) -> tuple[bool, str]:
    own = _router_own(lab)
    oi = _if_of(lab, "office")
    if own.get(f"acl-out:{oi}"):
        return False, f"{own[f'acl-out:{oi}']} is still out on {oi}: the extended list near the source replaces it"
    return True, "no standard list left on the office interface"


def check_nat_pat(lab) -> tuple[bool, str]:
    from . import iosl3
    own = _router_own(lab)
    oi, gi, ii = _if_of(lab, "office"), _if_of(lab, "guest"), _if_of(lab, "isp-link")
    if own.get(f"nat:{oi}") != "inside" or own.get(f"nat:{gi}") != "inside" or own.get(f"nat:{ii}") != "outside":
        return False, (f"ip nat inside on {oi} and {gi}, ip nat outside on {ii} "
                       f"(now {own.get(f'nat:{oi}', '-')}, {own.get(f'nat:{gi}', '-')}, {own.get(f'nat:{ii}', '-')})")
    for k, v in own.items():
        if k.startswith("natsrc:") and v.split()[0] == ii:
            lst = k[7:]
            if all(iosl3.decide(own, lst, s)[0] == "permit" for s in ("10.80.0.10", "10.80.20.10")):
                return True, f"the office and the guests leave as {ii}'s address (list {lst}, overload)"
            return False, f"list {lst} does not permit both 10.80.0.0/24 and 10.80.20.0/24"
    return False, f"no ip nat inside source list <list> interface {ii} overload"


def check_nat_static(lab) -> tuple[bool, str]:
    own = _router_own(lab)
    glob = own.get("natstatic:10.80.0.10", "")
    if not glob:
        return False, "no ip nat inside source static 10.80.0.10 <global>"
    if ipaddress.ip_address(glob) not in ipaddress.ip_network("198.51.100.8/29"):
        return False, f"10.80.0.10 is published as {glob}, not an address of 198.51.100.8/29"
    return True, f"10.80.0.10 is published as {glob}"


def _register() -> None:
    from . import exercises
    for name, fn in (("netbasics-vlan30", check_vlan30), ("netbasics-pcc-vlan30", check_pcc_vlan30),
                     ("netbasics-roas30", check_roas30), ("netbasics-native99", check_native99),
                     ("netbasics-pruned", check_pruned), ("netbasics-acl-in", check_acl_in),
                     ("netbasics-acl-portal", check_acl_portal), ("netbasics-acl-std-gone", check_acl_std_gone),
                     ("netbasics-nat-pat", check_nat_pat), ("netbasics-nat-static", check_nat_static)):
        exercises.register_winlab_check(name, fn)


_register()
