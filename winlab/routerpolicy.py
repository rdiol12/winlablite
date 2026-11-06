"""The lab router's zone firewall, tunnels with IPsec, and QoS: where they
plug into its console (winlab/devcli.py), its start script
(winlab/netplan.py) and the live changes to a running router
(winlab/livenet.py).

The features themselves live in winlab/zbf.py (``zone security``,
``class-map type inspect``, ``zone-pair``), winlab/vti.py (``crypto
ikev2``, ``crypto ipsec``, ``interface Tunnel``) and winlab/qos.py
(``class-map``, ``policy-map``, ``service-policy``); winlab/mqc.py is how
a class-map matches, for both. This module only gathers them, so each hook
in the console, the start script and the live update is one line.
"""

from __future__ import annotations

import hashlib

from . import qos, vti, zbf

# A mode of these features as its prompt shows it (Router(config-if)#):
# IOS uses the same prompt for the firewall's and QoS's class-maps and
# policy-maps, and for a tunnel and a port; the console keeps them apart.
PROMPTS = {"config-cmap-insp": "config-cmap", "config-pmap-insp": "config-pmap",
           "config-pmap-c-insp": "config-pmap-c", "config-if-tunnel": "config-if",
           "config-crypto-trans": "cfg-crypto-trans", "config-ipsec-profile": "ipsec-profile"}
# exit from a mode inside another goes back to that one
PARENT = {"config-pmap-c": "config-pmap", "config-pmap-c-insp": "config-pmap-insp",
          "config-ikev2-keyring-peer": "config-ikev2-keyring"}
TUNNEL_MODE = ("config-if-tunnel",)
WORDS = {
    ("zone",): "FW with zoning", ("zone", "security"): "Security zone",
    ("zone-pair",): "Zone pair command", ("zone-member",): "Apply zone name",
    ("class-map",): "Configure CPL Class Map", ("class-map", "type"): "Configure CPL Class Map",
    ("class-map", "type", "inspect"): "Configure CPL Class Map for inspection",
    ("policy-map",): "Configure QoS Policy Map", ("policy-map", "type"): "type of the policy-map",
    ("policy-map", "type", "inspect"): "Configure CPL Policy Map for inspection",
    ("crypto",): "Encryption module", ("crypto", "ikev2"): "Configure IKEv2 Parameters",
    ("crypto", "ipsec"): "Configure IPSEC policy", ("tunnel",): "protocol-over-protocol tunneling",
    ("service-policy",): "Configure CPL Service Policy", ("match",): "classification criteria",
    ("show", "zone"): "Zone information", ("show", "zone-pair"): "Zone pair information",
    ("show", "policy-map"): "Show QoS Policy Map", ("show", "class-map"): "Show QoS Class Map",
    ("show", "crypto"): "Encryption module", ("show", "crypto", "ikev2"): "Shows ikev2 information",
    ("show", "crypto", "ipsec"): "Show IPSEC policy",
    # words only these features use (a word other commands share, such as
    # mode or priority, is left to them)
    ("shape",): "Traffic Shaping", ("police",): "Police", ("keyring",): "Specify keyring to use",
    ("pre-shared-key",): "Specify pre-shared key", ("encryption",): "Set encryption algorithm(s) for proposal",
    ("integrity",): "Set integrity hash algorithm(s) for proposal", ("proposal",): "Specify Proposal",
    ("peer",): "Configure a Peer and associated keys", ("dpd",): "Enable IKE liveness check for peers",
}


def _register_words() -> None:
    from . import devcli
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    for k, v in PROMPTS.items():
        devcli.MODE_PROMPTS.setdefault(k, v)


def add_specs(con, add, U, E, C, IF) -> None:
    """The router's commands for its firewall zones, tunnels and IPsec, and QoS."""
    _register_words()

    def sub(modes):
        cfg = tuple(m for m in modes)
        add("end", con._end, "Exit from configure mode", cfg)
        add("exit", lambda a: _exit(con), "Exit from this mode", cfg)
        add("do <line>", con._do, "To run exec commands in config mode", cfg)

    T = TUNNEL_MODE
    vti.add_specs(con, add, U, E, C, IF, sub)
    zbf.add_specs(con, add, U, E, C, IF + T, sub)
    qos.add_specs(con, add, U, E, C, IF + T, sub)
    # a tunnel's interface takes the access lists and NAT of winlab/iosl3.py too
    from . import iosl3
    add("ip access-group <name> <line>", lambda a: iosl3._group(con, a[0], a[1], True),
        "Specify access control for packets", T)
    add("no ip access-group <name> <line>", lambda a: iosl3._group(con, a[0], a[1], False),
        "Negate a command or set its defaults", T)


def _exit(con) -> str:
    up = PARENT.get(con.s.mode)
    if up:
        con.s.mode, con.s.ctx = up, con.s.ctx.split("|")[0]
    else:
        con.s.mode, con.s.ctx = "config", ""
    return ""


# ---- hooks
def is_tunnel(text: str) -> bool:
    return bool(vti.tunnel_name(text))


def enter_tunnel(con, text: str) -> str:
    return vti.enter_tunnel(con, text)


def no_tunnel(con, text: str) -> str:
    return vti.no_tunnel(con, text)


def global_lines(own: dict) -> list[str]:
    """What show running-config prints before the interfaces."""
    return qos.run_lines(own) + zbf.run_lines(own) + vti.run_lines(own)


def iface_lines(own: dict, ifname: str) -> list[str]:
    """What show running-config prints inside an interface's block."""
    return zbf.iface_lines(own, ifname) + qos.iface_lines(own, ifname)


def tunnel_blocks(own: dict) -> list[str]:
    def extra(name):
        out = [f" ip access-group {own[f'acl-{w}:{name}']} {w}" for w in ("in", "out") if own.get(f"acl-{w}:{name}")]
        return out + iface_lines(own, name)
    return vti.iface_blocks(own, extra)


def brief_rows(con) -> list[str]:
    return vti.brief_rows(con)


def connected(con) -> list[tuple]:
    """(network, interface, address) of the tunnels that are up, for show ip route."""
    return vti.connected(con)


def render(plan, reset: bool = False) -> list[str]:
    """The router's script for them: tunnels and IPsec first (the firewall
    and QoS name the tunnels' interfaces), then the zones, then QoS."""
    return vti.render(plan, reset) + zbf.render(plan, reset) + qos.render(plan, reset)


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()
