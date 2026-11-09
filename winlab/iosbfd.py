"""BFD typed at the lab router's console, made real by FRRouting's bfdd.

Bidirectional Forwarding Detection (RFC 5880, single hop RFC 5881) sends
small UDP packets (port 3784) between two routers many times a second, so a
dead neighbour is found in a fraction of a second instead of OSPF's dead
interval or BGP's hold time. On IOS the timers belong to the interface and
the routing protocols ask for a session:

* ``bfd interval <ms> min_rx <ms> multiplier <n>`` on an interface becomes a
  bfdd profile for that interface (``bfd`` / ``profile if-<device>`` with
  ``transmit-interval``, ``receive-interval``, ``detect-multiplier``). As on
  IOS, no session starts on an interface without it.
* ``ip ospf bfd`` on the interface, or ``bfd all-interfaces`` under
  ``router ospf``, is ospfd's ``ip ospf bfd`` with ``ip ospf bfd profile``;
  ``neighbor <ip> fall-over bfd`` under ``router bgp`` is bgpd's ``neighbor
  <ip> bfd`` with the profile of the interface the neighbour is on
  (winlab/iosbgpx.py).
* ``show bfd neighbors [details]`` reads bfdd's ``show bfd peers json``.

The routers the lab router meets run bfdd too (rtr-edge, rtr-isp: FRRouting
from the frr pack, ``bfdd=yes`` in /etc/frr/daemons).

Settings: ``bfd-if:<if>`` = ``<interval> <min_rx> <multiplier>``;
``ospf-bfd:<if>`` = yes; ``ospf-bfdall:<pid>`` = yes.
"""

from __future__ import annotations

import ipaddress
import json


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def profile(dev: str) -> str:
    return f"if-{dev}"


def timers(own: dict, ifname: str) -> tuple[int, int, int] | None:
    v = own.get(f"bfd-if:{ifname}", "").split()
    if len(v) != 3 or not all(x.isdigit() for x in v):
        return None
    return int(v[0]), int(v[1]), int(v[2])


def active(own: dict) -> bool:
    return any(k.startswith("bfd-if:") for k in own)


def ospf_wants(own: dict, ifname: str) -> bool:
    return bool(own.get(f"ospf-bfd:{ifname}") or any(k.startswith("ospf-bfdall:") for k in own))


# ------------------------------------------------------------------ frr.conf
def frr_lines(plan) -> list[str]:
    from .iosrouting import svi_map
    own = _own(plan.lab)
    svis = svi_map(plan.lab, plan)
    out = []
    for name, dev in sorted(svis.items(), key=lambda kv: kv[1]):
        t = timers(own, name)
        if t:
            out += [f" profile {profile(dev)}", f"  detect-multiplier {t[2]}", f"  receive-interval {t[1]}",
                    f"  transmit-interval {t[0]}"]
    return ["bfd"] + out + ["exit", "!"] if out else []


def frr_iface_lines(own: dict, ifname: str, dev: str) -> list[str]:
    if timers(own, ifname) and ospf_wants(own, ifname):
        return [" ip ospf bfd", f" ip ospf bfd profile {profile(dev)}"]
    return []


# ------------------------------------------------------------------ show running-config
def iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    t = timers(own, ifname)
    if t:
        out.append(f" bfd interval {t[0]} min_rx {t[1]} multiplier {t[2]}")
    if own.get(f"ospf-bfd:{ifname}"):
        out.append(" ip ospf bfd")
    return out


def ospf_run_lines(own: dict, pid: int) -> list[str]:
    return [" bfd all-interfaces"] if own.get(f"ospf-bfdall:{pid}") else []


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, IF, RM) -> None:
    from . import devcli
    for k, v in {("bfd",): "BFD interface configuration commands", ("show", "bfd"): "BFD protocol info",
                 ("ip", "ospf", "bfd"): "Enable BFD on this interface",
                 ("bfd", "all-interfaces"): "Enable BFD on all interfaces"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    add("bfd interval <num> min_rx <num> multiplier <num>", lambda a: interval(con, a[0], a[1], a[2]),
        "Maximum multiplier value", IF)
    add("no bfd interval", lambda a: interval(con, "", "", ""), "Negate a command or set its defaults", IF)
    add("no bfd interval <line>", lambda a: interval(con, "", "", ""), "Negate a command or set its defaults", IF)
    add("ip ospf bfd", lambda a: ospf_if(con, True), "Enable BFD on this interface", IF)
    add("no ip ospf bfd", lambda a: ospf_if(con, False), "Negate a command or set its defaults", IF)
    add("bfd all-interfaces", lambda a: all_ifs(con, True), "Enable BFD on all interfaces", RM)
    add("no bfd all-interfaces", lambda a: all_ifs(con, False), "Negate a command or set its defaults", RM)
    add("show bfd neighbors", lambda a: show_neighbors(con, False), "BFD neighbors", U)
    add("show bfd neighbors details", lambda a: show_neighbors(con, True), "Show detailed information", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def interval(con, tx: str, rx: str, mult: str) -> str:
    own = _own_c(con)
    key = f"bfd-if:{con.s.ctx}"
    if not tx:
        if own.pop(key, None) is None:
            return ""
        return _done(con)
    if not (50 <= int(tx) <= 9999 and 50 <= int(rx) <= 9999):
        raise _err("% Invalid input detected at '^' marker.\n% BFD intervals here are 50 to 9999 milliseconds")
    if not 3 <= int(mult) <= 50:
        raise _err("% Invalid input detected at '^' marker.\n% The multiplier is 3 to 50")
    own[key] = f"{int(tx)} {int(rx)} {int(mult)}"
    return _done(con)


def ospf_if(con, on: bool) -> str:
    own = _own_c(con)
    key = f"ospf-bfd:{con.s.ctx}"
    if on:
        own[key] = "yes"
    elif own.pop(key, None) is None:
        return ""
    note = "" if not on or timers(own, con.s.ctx) else \
        "% BFD: no bfd interval on this interface yet: the session starts once it has one"
    done = _done(con)
    return "\n".join(x for x in (note, done) if x)


def all_ifs(con, on: bool) -> str:
    kind, _, pid = con.s.ctx.partition(":")
    if kind != "ospf":
        raise _err("% Invalid input detected at '^' marker.")
    own = _own_c(con)
    key = f"ospf-bfdall:{pid}"
    if on:
        own[key] = "yes"
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def forget_pid(own: dict, pid: int) -> None:
    own.pop(f"ospf-bfdall:{pid}", None)


def has_interval_for(con, ip: str) -> bool:
    own = _own(con.lab)
    for name, net, _ in con.router_ifaces():
        if net is not None and ipaddress.IPv4Address(ip) in net.net:
            return bool(timers(own, name))
    return False


# ------------------------------------------------------------------ show bfd neighbors
def parse_peers(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = data.get("peers", [data])
    return [p for p in data if isinstance(p, dict) and p.get("peer")] if isinstance(data, list) else []


def show_neighbors(con, details: bool) -> str:
    from . import devcli
    from .iosrouting import _frr_note, _vtysh, svi_map
    own = _own(con.lab)
    if not active(own):
        return ""
    text = _vtysh(con, "show bfd peers json")
    if text.strip().startswith("%"):
        return _frr_note(text)
    rev = {dev: name for name, dev in svi_map(con.lab, con.plan).items()}
    out = ["", "IPv4 Sessions", f"{'NeighAddr':<39}{'LD/RD':<14}{'RH/RS':<10}{'State':<10}Int"]
    for p in parse_peers(text):
        st = str(p.get("status", "down")).capitalize()
        rh = "Up" if st == "Up" else ("Down" if p.get("remote-id") else "Unknown")
        name = devcli.short_if(rev.get(p.get("interface", ""), p.get("interface", "")))
        ldrd = f"{p.get('id', 0)}/{p.get('remote-id', 0)}"
        out.append(f"{p['peer']:<39}{ldrd:<14}{rh:<10}{st:<10}{name}")
        if details:
            mult = p.get("detect-multiplier", 3)
            out += [f"Session state is {st.upper()} and not using echo function.",
                    f"Local Diag: {p.get('diagnostic', 'ok')}, Demand mode: 0, Poll bit: 0",
                    f"MinTxInt: {int(p.get('transmit-interval', 300)) * 1000}, MinRxInt: "
                    f"{int(p.get('receive-interval', 300)) * 1000}, Multiplier: {mult}",
                    f"Received MinRxInt: {int(p.get('remote-receive-interval', 0)) * 1000}, Received Multiplier: "
                    f"{p.get('remote-detect-multiplier', 0)}",
                    f"Uptime: {_uptime(p.get('uptime', 0))}" if st == "Up" else f"Downtime: {_uptime(p.get('downtime', 0))}",
                    "Registered protocols: " + " ".join(_clients(own, con, p)), ""]
    return "\n".join(out)


def _uptime(sec) -> str:
    try:
        s = int(sec)
    except (TypeError, ValueError):
        return "00:00:00"
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def _clients(own: dict, con, p: dict) -> list[str]:
    out = []
    if any(k.startswith(("ospf-bfd:", "ospf-bfdall:")) for k in own):
        out.append("OSPF")
    if own.get(f"bgp-bfd:{p.get('peer')}"):
        out.append("BGP")
    return out or ["-"]
