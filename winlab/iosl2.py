"""What a switch's console sets that the router must make real, beyond its
VLANs and ports (winlab/devcli.py, winlab/netplan.py):

* the switch's management address (``interface vlan 1``, ``ip address``,
  ``no shutdown``, ``ip default-gateway``): the switch is a host of its own
  in that VLAN, so on the router it is a network namespace with one port in
  the VLAN (a veth pair into the router's bridge), its own MAC, address and
  default route. It answers ping and ARP from the lab's machines, and
  ``ping`` typed on the switch runs from it;
* ``speed 10 | 100`` on a machine's port: that port's rate on the router
  (tbf), and ``duplex full`` hard-set against a card that negotiates: the
  card falls back to half duplex, a duplex mismatch, with its losses (the
  same shaping winlab/physfaults.py uses for that fault);
* ``switchport trunk allowed vlan`` on the uplink of a switch cabled to the
  router: a VLAN the trunk does not carry does not reach the router (the
  router's own port in that VLAN leaves its bridge). Between switches the
  same setting decides which VLANs are one network (Lab.segment_id).

render() is shell for the router: at its start (netplan) and again whenever
it changes (livenet).
"""

from __future__ import annotations

import hashlib

STATE = "/run/winlab-ports"   # ports whose rate this module set, to undo
SIGS = "/run/winlab-swm"      # per management namespace, what it was made of (kept while unchanged)


def _ns(sw: str) -> str:
    return "swm" + hashlib.sha256(sw.encode()).hexdigest()[:6]


def mac_of(lab, sw: str, tag: int) -> str:
    h = hashlib.sha256(f"winlab-svi/{lab.name}/{sw}/{tag}".encode()).digest()
    return "52:54:02:%02x:%02x:%02x" % (h[0], h[1], h[2])


def svis(lab, sw: str) -> list[tuple[int, str]]:
    """(VLAN, address/len) per VLAN interface of a switch that has an
    address and is not shut down."""
    own = lab.devices.get(f"sw:{sw}", {})
    out = []
    for k, v in own.items():
        if k.startswith("svi:") and v and own.get(f"up:Vlan{k[4:]}"):
            try:
                out.append((int(k[4:]), v))
            except ValueError:
                continue
    return sorted(out)


def netns(lab, sw: str) -> str:
    """The namespace a switch's management address lives in, or "" when it
    has none up."""
    return _ns(sw) if svis(lab, sw) else ""


def _rate(lab, link) -> tuple[str, str]:
    """(egress qdisc, ingress police) for a machine's port from its speed
    and duplex, or ("", "")."""
    net = lab.networks.get(link.network_id) if link.plugged else None
    if net is None:
        return "", ""
    own = lab.devices.get(f"sw:{net.home}", {})
    sp, dx = own.get(f"speed:{link.label}"), own.get(f"duplex:{link.label}")
    if dx == "full":
        # A port hard-set to full duplex: the card, negotiating, falls back to
        # half; collisions the port does not expect lose frames both ways.
        return "netem rate 10mbit loss 3%", "police rate 10mbit burst 16k drop"
    if sp in ("10", "100"):
        return (f"tbf rate {sp}mbit burst 32kb latency 50ms", f"police rate {sp}mbit burst 32k drop")
    return "", ""


def render(plan, reset: bool = False) -> list[str]:
    from . import devcli, physfaults
    from .netplan import BRIDGE
    lab = plan.lab
    out: list[str] = []
    mgmt = [(sw, svis(lab, sw)) for sw in devcli.switches(lab)]
    mgmt = [(sw, v) for sw, v in mgmt if v]
    rates = []
    for link in plan.links:
        root, ingress = _rate(lab, link)
        if root and link.fabric_iface:
            try:
                faulty = bool(physfaults.active(lab.name, link=link.label))
            except Exception:  # noqa: BLE001 - no fault store: no fault
                faulty = False
            if not faulty:
                rates.append((link, root, ingress))
    cuts = []
    for sw in devcli.switches(lab):
        if not devcli.uplinked(lab, sw):
            continue
        allow = devcli.allowed_tags(lab, sw, "GigabitEthernet0/1")
        if allow is None:
            continue
        for net in devcli.vlans_of(lab, sw):
            if net.routed and net.vlan_no not in allow:
                cuts.append(plan.segment_of(net.id).vid)
    from . import iosssh, span  # SPAN's mirrors and the SSH servers follow the ports and addresses set here
    extra = span.render(plan, reset) + iosssh.render(plan, reset)
    if not (mgmt or rates or cuts or extra) and not reset:
        return []
    out.append("### the switches' own settings on the router (winlab/iosl2.py)")
    sigs = {_ns(sw): _sig(lab, plan, sw, addrs) for sw, addrs in mgmt}
    if reset:
        # A management namespace whose settings did not change is kept, with
        # the SSH sessions in it (winlab/iosssh.py); the others are made again.
        keep = "|".join(f'"{ns} {sig}"' for ns, sig in sorted(sigs.items())) or '"-"'
        names = "|".join(f"{ns}*" for ns in sorted(sigs)) or "-"
        out += ["for n in $(ip netns list 2>/dev/null | awk '{print $1}' | grep '^swm'); do "
                f"case \"$n $(cat {SIGS}.$n 2>/dev/null)\" in {keep}) ;; *) ip netns del $n; rm -f {SIGS}.$n;; "
                "esac; done; true",
                f"for n in {' '.join(sorted(sigs))}; do [ -e /var/run/netns/$n ] || rm -f {SIGS}.$n; done; true",
                "for i in $(ls /sys/class/net 2>/dev/null | grep '^swm'); do "
                f"case $i in {names}) [ -e /var/run/netns/${{i%[hn]*}} ] || ip link del $i 2>/dev/null;; "
                "*) ip link del $i 2>/dev/null;; esac; done; true",
                f"for i in $(cat {STATE} 2>/dev/null); do tc qdisc del dev $i root 2>/dev/null; "
                f"tc qdisc del dev $i ingress 2>/dev/null; done; : > {STATE}"]
        for seg in sorted(plan.segments.values(), key=lambda s: s.vid):
            if seg.network.routed:
                out.append(f"bridge vlan add dev {BRIDGE} vid {seg.vid} self 2>/dev/null || true")
    for sw, addrs in mgmt:
        ns = _ns(sw)
        own = lab.devices.get(f"sw:{sw}", {})
        out += [f"# {sw}'s management address", f"ip netns add {ns} 2>/dev/null || true",
                f"ip -n {ns} link set lo up", f"echo {sigs[ns]} > {SIGS}.{ns}"]
        for k, (tag, addr) in enumerate(addrs):
            net = devcli.vlan_net(lab, sw, tag)
            if net is None:
                continue
            vid = plan.segment_of(net.id).vid
            h, n = f"{ns}h{k}", f"{ns}n{k}"
            out += [f"ip link add {h} type veth peer name {n} 2>/dev/null || true",
                    f"ip link set {n} netns {ns} 2>/dev/null || true",
                    f"ip link set {h} master {BRIDGE}",
                    f"bridge vlan del dev {h} vid 1 2>/dev/null || true",
                    f"bridge vlan add dev {h} vid {vid} pvid untagged",
                    f"ip link set {h} up",
                    f"ip -n {ns} link set {n} address {mac_of(lab, sw, tag)}",
                    f"ip -n {ns} addr replace {addr} dev {n}",
                    f"ip -n {ns} link set {n} up"]
        if own.get("default-gw"):
            out.append(f"ip -n {ns} route replace default via {own['default-gw']} 2>/dev/null || true")
    for link, root, ingress in rates:
        i = link.fabric_iface
        out += [f"# {link.label}: speed/duplex set on its switch port",
                f"tc qdisc del dev {i} root 2>/dev/null; tc qdisc del dev {i} ingress 2>/dev/null; true",
                f"tc qdisc add dev {i} root {root}", f"tc qdisc add dev {i} handle ffff: ingress",
                f"tc filter add dev {i} parent ffff: protocol all prio 1 u32 match u32 0 0 {ingress}",
                f"echo {i} >> {STATE}"]
    for vid in sorted(set(cuts)):
        out.append(f"bridge vlan del dev {BRIDGE} vid {vid} self 2>/dev/null || true"
                   f"   # not allowed on the uplink trunk")
    out += extra
    out.append("")
    return out


def _sig(lab, plan, sw: str, addrs) -> str:
    """What a switch's management namespace is made of, as a short hash."""
    own = lab.devices.get(f"sw:{sw}", {})
    parts = [own.get("default-gw", "")]
    for tag, addr in addrs:
        net = devcli_vlan(lab, sw, tag)
        parts.append(f"{tag}={addr}@{plan.segment_of(net.id).vid if net is not None else 0}/{mac_of(lab, sw, tag)}")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:10]


def devcli_vlan(lab, sw: str, tag: int):
    from . import devcli
    return devcli.vlan_net(lab, sw, tag)


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()
