"""Virtual switches, as in Hyper-V's Virtual Switch Manager.

Each lab network is a virtual switch of one of three types, set in the lab
file (`[[network]] vswitch = "..."`) or in the Virtual Switch Manager window
of the Machines window, which writes the same key:

  private   the default: the lab's machines reach one another through the lab
            router and nothing else. A lab made only of private switches is
            sealed from this PC and from the internet.
  internal  the machines can also reach this PC (at 10.0.2.2 from inside the
            lab), and this PC can open the ports listed in host_ports on
            127.0.0.1. No internet.
  external  the machines reach the internet through this PC's own connection,
            and this PC as on internal. Nothing on the internet can reach in.

How: when a lab has any internal or external switch, the lab router (and only
the router: no lab machine ever gets a host-connected card) gets one more
network card, QEMU's user-mode network, which is NAT through this PC. The
router lets out exactly what each switch's type allows and drops the rest, so
a private switch next to an external one stays sealed. host_ports adds a
forward from 127.0.0.1 on this PC to the router, which passes it to the
machine's static address. The isolation guard (providers/qemu.check_isolation)
accepts that card on the router of such a lab and nothing else.
"""

from __future__ import annotations

import re

from .model import Lab, Network

KINDS = ("private", "internal", "external")
TITLES = {"private": "Private network", "internal": "Internal network", "external": "External network"}
TEXT = {
    "private": "The lab's machines on this switch reach one another and the lab's other networks through the lab router, nothing else.",
    "internal": "As private, and the machines can also reach this PC (10.0.2.2 from inside the lab); this PC opens the ports you list. No internet.",
    "external": "The machines reach the internet through this PC's own connection, and this PC as on internal. Nothing outside can reach in.",
}
NETDEV_ID = "uplink"
MAC = "52:54:00:fe:00:01"
SLIRP_NET, SLIRP_GW, SLIRP_DNS, SLIRP_ME = "10.0.2.0/24", "10.0.2.2", "10.0.2.3", "10.0.2.15"
_PORT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*):(\d{1,5})(?:@(\d{1,5}))?$")


class VSwitchError(Exception):
    pass


def kind_of(lab: Lab, network_id: str) -> str:
    net = lab.networks.get(network_id)
    return net.vswitch if net and net.vswitch in KINDS else "private"


def open_networks(lab: Lab) -> list[Network]:
    """The routed networks whose switch is internal or external."""
    return [n for n in sorted(lab.networks.values(), key=lambda n: n.id)
            if n.routed and n.vswitch in ("internal", "external")]


def active(lab: Lab) -> bool:
    return bool(open_networks(lab))


def parse_port(spec: str) -> tuple[str, int, int]:
    m = _PORT.match(spec.strip())
    if not m:
        raise VSwitchError(f"host port {spec!r}: write node:port or node:port@hostport")
    node, port = m.group(1), int(m.group(2))
    host = int(m.group(3)) if m.group(3) else (port + 10000 if port < 55536 else port)
    if not (0 < port < 65536 and 1024 <= host < 65536):
        raise VSwitchError(f"host port {spec!r}: ports are 1-65535, and this PC's side 1024 or above")
    return node, port, host


def forwards(lab: Lab) -> list[dict]:
    """Every host port: this PC's 127.0.0.1:host to node's address:port."""
    out = []
    for net in open_networks(lab):
        for spec in net.host_ports:
            node, port, host = parse_port(spec)
            n = lab.nodes.get(node)
            ip = next((c.ip for c in (n.nics if n else []) if c.network == net.id and c.ip), "")
            out.append({"network": net.id, "node": node, "port": port, "host": host, "ip": ip})
    return out


def validate(lab: Lab) -> list[str]:
    errs, hosts = [], {}
    for net in lab.networks.values():
        if net.vswitch not in KINDS:
            errs.append(f"network '{net.id}': vswitch is private, internal or external, not {net.vswitch!r}")
            continue
        if net.host_ports and net.vswitch == "private":
            errs.append(f"network '{net.id}': host_ports need an internal or external switch")
        for spec in net.host_ports:
            try:
                node, port, host = parse_port(spec)
            except VSwitchError as exc:
                errs.append(f"network '{net.id}': {exc}")
                continue
            n = lab.nodes.get(node)
            if n is None or not any(c.network == net.id and c.ip for c in n.nics):
                errs.append(f"network '{net.id}': host port {spec}: {node} has no static address on this network")
            if host in hosts:
                errs.append(f"network '{net.id}': this PC's port {host} is already forwarded ({hosts[host]})")
            hosts[host] = spec
    return errs


def netdev() -> str:
    return f"user,id={NETDEV_ID},ipv6=off,restrict=off"


def qemu_args(lab: Lab) -> list[str]:
    """The router's extra card. host forwards bind 127.0.0.1 only."""
    nd = netdev() + "".join(f",hostfwd=tcp:127.0.0.1:{f['host']}-{SLIRP_ME}:{f['host']}" for f in forwards(lab))
    return ["-netdev", nd, "-device", f"virtio-net-pci,netdev={NETDEV_ID},mac={MAC}"]


def netdev_ok(val: str) -> bool:
    """The isolation guard's test for the router's card: exactly ours."""
    parts = val.split(",")
    if parts[:4] != netdev().split(","):
        return False
    return all(re.fullmatch(r"hostfwd=tcp:127\.0\.0\.1:\d{4,5}-10\.0\.2\.15:\d{4,5}", p) for p in parts[4:])


def set_kind(lab: Lab, network_id: str, kind: str, host_ports: list[str] | None = None) -> Network:
    """The Switch Manager's change: written into the lab file."""
    from . import editor
    net = lab.networks.get(network_id)
    if net is None:
        raise VSwitchError(f"{lab.name} has no network {network_id!r}")
    if kind not in KINDS:
        raise VSwitchError(f"a switch is private, internal or external, not {kind!r}")
    old = (net.vswitch, list(net.host_ports))
    net.vswitch = kind
    if host_ports is not None:
        net.host_ports = [p.strip() for p in host_ports if p.strip()]
    if kind == "private":
        net.host_ports = []
    errs = [e for e in validate(lab) if f"'{net.id}'" in e]
    if errs:
        net.vswitch, net.host_ports = old
        raise VSwitchError("; ".join(errs))
    try:
        editor.save(lab)
    except Exception as exc:  # noqa: BLE001 - give the edit back on any failure
        net.vswitch, net.host_ports = old
        raise VSwitchError(str(exc)) from None
    return net


def render(plan) -> list[str]:
    """The router's side, appended to its setup script."""
    lab = plan.lab
    nets = open_networks(lab)
    if not nets:
        return [
            "### virtual switches: all private (no way out of the lab)",
            "nft delete table inet winlab_vswitch 2>/dev/null || true",
            '[ -f /run/winlab-vswitch-dns.pid ] && kill "$(cat /run/winlab-vswitch-dns.pid)" 2>/dev/null',
            f"ip route del default via {SLIRP_GW} 2>/dev/null || true",
            "",
        ]
    svi = {n.id: plan.segment_of(n.id).svi for n in nets}
    rules = []
    for n in nets:
        if n.vswitch == "external":
            rules.append(f'    iifname "{svi[n.id]}" oifname "$up" counter accept comment "{n.id}: external"')
        else:
            rules.append(f'    iifname "{svi[n.id]}" oifname "$up" ip daddr {SLIRP_GW} counter accept comment "{n.id}: internal, this PC only"')
    dnat = []
    for f in forwards(lab):
        if f["ip"]:
            dnat.append(f'    iifname "$up" tcp dport {f["host"]} dnat ip to {f["ip"]}:{f["port"]} comment "{f["node"]}:{f["port"]}"')
            rules.append(f'    iifname "$up" ip daddr {f["ip"]} tcp dport {f["port"]} ct status dnat accept')
    ext_gws = sorted({n.router_ip for n in nets if n.vswitch == "external"})
    out = [
        "### virtual switches (winlab/vswitch.py): " + ", ".join(f"{n.id} {n.vswitch}" for n in nets)
        + "; every other switch private",
        f"up=$(ip -o link | awk -F': ' 'tolower($0) ~ /{MAC}/ {{print $2; exit}}' | cut -d@ -f1)",
        'if [ -n "$up" ]; then',
        '  ip link set "$up" up',
        f'  udhcpc -q -n -i "$up" >/dev/null 2>&1 || ip addr replace {SLIRP_ME}/24 dev "$up"',
        f'  ip route replace default via {SLIRP_GW} dev "$up"',
        "  nft delete table inet winlab_vswitch 2>/dev/null || true",
        "  nft -f - <<NFT || true",
        "table inet winlab_vswitch {",
        "  chain prerouting {",
        "    type nat hook prerouting priority -100; policy accept;",
        *dnat,
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -5; policy accept;",
        '    iifname "$up" ct state established,related accept',
        '    oifname "$up" ct state established,related accept',
        *rules,
        '    iifname "$up" counter drop comment "nothing else comes in"',
        '    oifname "$up" counter drop comment "private switches stay sealed"',
        "  }",
        "  chain postrouting {",
        "    type nat hook postrouting priority 100; policy accept;",
        '    oifname "$up" masquerade',
        "  }",
        "}",
        "NFT",
    ]
    if ext_gws:
        # The machines' DNS server (the DC) forwards to its gateway for internet names.
        out += [
            '  [ -f /run/winlab-vswitch-dns.pid ] && kill "$(cat /run/winlab-vswitch-dns.pid)" 2>/dev/null',
            "  dnsmasq --port=53 --bind-interfaces --no-resolv --no-hosts "
            + " ".join(f"--listen-address={g}" for g in ext_gws)
            + f" --server={SLIRP_DNS} --pid-file=/run/winlab-vswitch-dns.pid || true",
        ]
    out += ["fi", ""]
    return out


def describe(lab: Lab) -> str:
    nets = open_networks(lab)
    if not nets:
        return "every virtual switch is private: no path to this PC or the internet"
    parts = [f"{n.id} {n.vswitch}" for n in nets]
    fw = [f"127.0.0.1:{f['host']} -> {f['node']}:{f['port']}" for f in forwards(lab)]
    return ("virtual switches: " + ", ".join(parts) + "; the rest private"
            + (f"; this PC opens {', '.join(fw)}" if fw else ""))


def view(lab: Lab) -> list[dict]:
    """The Switch Manager's list."""
    return [{"id": n.id, "cidr": n.cidr, "kind": n.vswitch if n.vswitch in KINDS else "private",
             "routed": n.routed, "host_ports": list(n.host_ports), "description": n.description,
             "machines": sorted({nd.id for nd in lab.node_list() for c in nd.nics if c.network == n.id})}
            for n in sorted(lab.networks.values(), key=lambda n: n.id) if not n.switch]
