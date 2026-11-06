"""SPAN on the workbench's switches: port mirroring, so a PC with Wireshark
can see another machine's traffic.

``monitor session 1 source interface fa0/1 both`` and ``monitor session 1
destination interface fa0/5`` copy every frame fa0/1 receives (rx) and
sends (tx) out of fa0/5, where a lab PC captures it. ``show monitor``
reads the sessions back.

How it is real. A switch's ports are the router's bridge ports (one per
machine's network card, winlab/netplan.py) and the cables between switches
are veths there (winlab/stp.py). A source port gets tc filters on those
ports: ``matchall action mirred egress mirror dev <destination>`` on its
ingress (rx: what the switch receives on the port) and on its egress (tx:
what the switch sends out of it), so the kernel copies each frame to the
destination port as a Catalyst's ASIC does. A source VLAN mirrors every
machine port of the switch in that VLAN. The destination port does what a
Catalyst's does by default: it leaves its VLAN (it is put in a VLAN of its
own, so only the copies come out of it) and frames coming in on it are
dropped (ingress is disabled), so the PC there is a listener and nothing
more. ``no monitor session`` puts the port back.

The PC on the destination port captures in promiscuous mode (Wireshark with
Npcap does by default), because the copies are addressed to other
machines. Its own network card has no network while it listens.

Settings live with the switch's others ([devices."sw:<id>"]):
``mon-src:<n>`` = "<port>=<rx|tx|both>;...", ``mon-vlan:<n>`` the same for
VLANs, ``mon-dst:<n>`` = the destination port, ``mon-enc:<n>``.
"""

from __future__ import annotations

import re

from . import devcli

SESSIONS = 66               # monitor session 1 to 66
DIRS = ("both", "rx", "tx")
STATE = "/run/winlab-span"  # what render() set on the router, to undo
PREF = 10                   # tc filter preference: PREF + session number


def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


def _pairs(text: str) -> list[tuple[str, str]]:
    out = []
    for part in (text or "").split(";"):
        k, _, v = part.partition("=")
        if k and v in DIRS:
            out.append((k, v))
    return out


def _text(pairs: list[tuple[str, str]]) -> str:
    return ";".join(f"{k}={v}" for k, v in pairs)


def sessions(lab, sw: str) -> list[int]:
    own = _own(lab, sw)
    return sorted({int(k.split(":")[1]) for k in own
                   if k.startswith(("mon-src:", "mon-vlan:", "mon-dst:")) and k.split(":")[1].isdigit()})


def session(lab, sw: str, n: int) -> dict:
    own = _own(lab, sw)
    return {"src": _pairs(own.get(f"mon-src:{n}", "")), "vlan": _pairs(own.get(f"mon-vlan:{n}", "")),
            "dst": own.get(f"mon-dst:{n}", ""), "enc": own.get(f"mon-enc:{n}", "")}


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    add("monitor session <num> source interface <line>", lambda a: set_source(con, int(a[0]), a[1], True),
        "SPAN source interface, VLAN", C)
    add("monitor session <num> source vlan <line>", lambda a: set_vlan(con, int(a[0]), a[1], True),
        "SPAN source VLAN", C)
    add("monitor session <num> destination interface <line>", lambda a: set_dest(con, int(a[0]), a[1], True),
        "SPAN destination interface", C)
    add("no monitor session <line>", lambda a: clear(con, a[0]), "Negate a command or set its defaults", C)
    add("no monitor session <num> source interface <line>", lambda a: set_source(con, int(a[0]), a[1], False),
        "Negate a command or set its defaults", C)
    add("no monitor session <num> source vlan <line>", lambda a: set_vlan(con, int(a[0]), a[1], False),
        "Negate a command or set its defaults", C)
    add("no monitor session <num> destination interface <line>", lambda a: set_dest(con, int(a[0]), a[1], False),
        "Negate a command or set its defaults", C)
    add("show monitor", lambda a: show(con, ""), "SPAN information and configuration", U)
    add("show monitor session <line>", lambda a: show(con, a[0]), "SPAN session", U)
    add("show monitor detail", lambda a: show(con, "", detail=True), "Show detailed output", U)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def _check_no(n: int) -> None:
    if not 1 <= n <= SESSIONS:
        raise devcli.CliError("% Invalid input detected at '^' marker.")


def _ports(con, text: str) -> tuple[list[str], str, list[str]]:
    """'fa0/1 , fa0/3 - 4 rx' -> (full port names, direction, words after)."""
    from . import etherchannel
    words = text.replace(",", " , ").replace("-", " - ").split()
    tail: list[str] = []
    direction = "both"
    while words and words[-1].lower() not in (",", "-") and not re.search(r"\d", words[-1]):
        tail.insert(0, words.pop())
    if tail and tail[0].lower() in DIRS:
        direction = tail.pop(0).lower()
    spec = " ".join(words)
    names = con._if_names()
    out: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        n = etherchannel.po_number(part)
        if n:
            out.append(etherchannel.po_name(n))
            continue
        m = re.match(r"^\s*([A-Za-z]+\s*\d+/)(\d+)\s*(?:-\s*(\d+))?\s*$", part)
        if not m:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        stem, lo, hi = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
        for i in range(lo, hi + 1):
            full = devcli.parse_if(f"{stem}{i}", names)
            if full not in out:
                out.append(full)
    return out, direction, tail


def _dests(lab, sw: str, but: int = 0) -> dict[str, int]:
    return {session(lab, sw, n)["dst"]: n for n in sessions(lab, sw) if n != but and session(lab, sw, n)["dst"]}


def _sources(lab, sw: str) -> dict[str, int]:
    return {p: n for n in sessions(lab, sw) for p, _ in session(lab, sw, n)["src"]}


def _done(con) -> str:
    note = con._save()
    return note.strip()


def set_source(con, n: int, text: str, on: bool) -> str:
    _check_no(n)
    lab, sw = con.lab, _sw(con)
    ports, direction, tail = _ports(con, text)
    if tail:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    s = session(lab, sw, n)
    own = devcli.settings(lab, con.device)
    pairs = [x for x in s["src"] if x[0] not in ports]
    if on:
        if s["vlan"]:
            raise devcli.CliError(f"% Session {n} has VLAN sources: a session mirrors interfaces or VLANs, "
                                  f"not both")
        dst = _dests(lab, sw)
        clash = [devcli.short_if(p) for p in ports if p in dst]
        if clash:
            raise devcli.CliError(f"% Interface(s) {', '.join(clash)} already configured as monitor destinations")
        pairs += [(p, direction) for p in ports]
    if pairs:
        own[f"mon-src:{n}"] = _text(pairs)
    else:
        own.pop(f"mon-src:{n}", None)
    return _done(con)


def set_vlan(con, n: int, text: str, on: bool) -> str:
    _check_no(n)
    lab, sw = con.lab, _sw(con)
    words = text.replace(",", " , ").split()
    direction = "both"
    if words and words[-1].lower() in DIRS:
        direction = words.pop().lower()
    tags = []
    for part in " ".join(words).replace(" ", "").split(","):
        m = re.match(r"^(\d+)(?:-(\d+))?$", part)
        if not m:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not 1 <= lo <= hi <= 4094:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        tags += [str(t) for t in range(lo, hi + 1)]
    s = session(lab, sw, n)
    own = devcli.settings(lab, con.device)
    pairs = [x for x in s["vlan"] if x[0] not in tags]
    if on:
        if s["src"]:
            raise devcli.CliError(f"% Session {n} has interface sources: a session mirrors interfaces or VLANs, "
                                  f"not both")
        pairs += [(t, direction) for t in tags]
    if pairs:
        own[f"mon-vlan:{n}"] = _text(pairs)
    else:
        own.pop(f"mon-vlan:{n}", None)
    return _done(con)


def set_dest(con, n: int, text: str, on: bool) -> str:
    _check_no(n)
    lab, sw = con.lab, _sw(con)
    ports, direction, tail = _ports(con, text)
    own = devcli.settings(lab, con.device)
    if not on:
        if own.get(f"mon-dst:{n}") in ports:
            own.pop(f"mon-dst:{n}", None)
            own.pop(f"mon-enc:{n}", None)
        return _done(con)
    if len(ports) != 1 or text.strip().lower().startswith(("both", "rx", "tx")):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    port = ports[0]
    if port.startswith("Port-channel"):
        raise devcli.CliError("% EtherChannel interface cannot be a SPAN destination")
    if port in _sources(lab, sw):
        raise devcli.CliError(f"% Interface(s) {devcli.short_if(port)} already configured as monitor sources")
    if port in _dests(lab, sw, but=n):
        raise devcli.CliError(f"% Interface(s) {devcli.short_if(port)} already configured as monitor destination "
                              f"in session {_dests(lab, sw, but=n)[port]}")
    enc = ""
    words = [w.lower() for w in tail]
    if words:
        if words[0] != "encapsulation"[:max(3, len(words[0]))] and not "encapsulation".startswith(words[0]):
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        if len(words) < 2 or not ("replicate".startswith(words[1]) or "dot1q".startswith(words[1])):
            raise devcli.CliError("% Incomplete command.")
        enc = "replicate" if "replicate".startswith(words[1]) else "dot1q"
    own[f"mon-dst:{n}"] = port
    if enc:
        own[f"mon-enc:{n}"] = enc
    else:
        own.pop(f"mon-enc:{n}", None)
    note = _done(con)
    gi = (f"% {devcli.short_if(port)} is a cable to another switch: the copies go to that switch, not to a PC"
          if port.startswith("Gigabit") else "")
    return "\n".join(x for x in (gi, note) if x)


def clear(con, text: str) -> str:
    lab, sw = con.lab, _sw(con)
    t = text.strip().lower()
    own = devcli.settings(lab, con.device)
    if t.isdigit():
        _check_no(int(t))
        which = [int(t)]
    elif t and ("all".startswith(t) or "local".startswith(t)):
        which = sessions(lab, sw)
    else:
        m = re.match(r"^(\d+)\s*-\s*(\d+)$", t)
        if not m:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        which = list(range(int(m.group(1)), int(m.group(2)) + 1))
    for n in which:
        for k in ("mon-src", "mon-vlan", "mon-dst", "mon-enc"):
            own.pop(f"{k}:{n}", None)
    return _done(con)


def _names(ports: list[str]) -> str:
    return ",".join(devcli.short_if(p).replace("Port-channel", "Po") for p in ports)


def show(con, which: str, detail: bool = False) -> str:
    lab, sw = con.lab, _sw(con)
    w = which.strip().lower()
    have = sessions(lab, sw)
    if w.isdigit():
        n = int(w)
        if n not in have:
            return f"Session {n} does not exist." if 1 <= n <= SESSIONS else "% Invalid input detected at '^' marker."
        have = [n]
    elif w and not ("all".startswith(w) or "local".startswith(w) or "detail".startswith(w)):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    if not have:
        return "No SPAN configured."
    out = []
    for n in have:
        s = session(lab, sw, n)
        out += [f"Session {n}", "---------", f"{'Type':<25}: Local Session"]
        for label, key in (("Source Ports", "src"), ("Source VLANs", "vlan")):
            pairs = s[key]
            if not pairs and not detail:
                continue
            out.append(f"{label:<25}:")
            for d, word in (("rx", "RX Only"), ("tx", "TX Only"), ("both", "Both")):
                items = [p for p, x in pairs if x == d]
                if items or detail:
                    shown = _names(items) if key == "src" else ",".join(items)
                    out.append(f"    {word:<21}: {shown or 'None'}")
        out.append(f"{'Destination Ports':<25}: {devcli.short_if(s['dst']) if s['dst'] else 'None'}")
        if s["dst"]:
            enc = {"replicate": "Replicate", "dot1q": "DOT1Q"}.get(s["enc"], "Native")
            out += [f"    {'Encapsulation':<21}: {enc}", f"{'          Ingress':<25}: Disabled"]
        if s["dst"] and not (s["src"] or s["vlan"]):
            out.append("% No source yet: the destination port listens, but nothing is copied to it")
        out.append("")
    return "\n".join(out).rstrip()


def run_lines(lab, sw: str) -> list[str]:
    out = []
    for n in sessions(lab, sw):
        s = session(lab, sw, n)
        for key, word in (("src", "interface"), ("vlan", "vlan")):
            for d in ("both", "rx", "tx"):
                items = [p for p, x in s[key] if x == d]
                if items:
                    shown = " , ".join(devcli.short_if(p).replace("Port-channel", "Po") for p in items) \
                        if key == "src" else ",".join(items)
                    out.append(f"monitor session {n} source {word} {shown}" + ("" if d == "both" else f" {d}"))
        if s["dst"]:
            out.append(f"monitor session {n} destination interface {devcli.short_if(s['dst'])}"
                       + (f" encapsulation {s['enc']}" if s["enc"] else ""))
    return out


# ------------------------------------------------------------------ the router
def _ifaces(lab, plan, sw: str, port: str, ports: list, gis: dict) -> list[str]:
    """The router's interfaces a switch port is: a machine's card, a veth, a channel's members."""
    from . import etherchannel
    if port.startswith("Port-channel"):
        n = int(port[len("Port-channel"):])
        out = []
        for p in etherchannel.groups(lab, sw).get(n, []):
            out += _ifaces(lab, plan, sw, p, ports, gis)
        return out
    m = re.match(r"^FastEthernet0/(\d+)$", port)
    if m:
        i = int(m.group(1)) - 1
        link = ports[i] if i < len(ports) else None
        return [link.fabric_iface] if link is not None and link.fabric_iface else []
    dev = gis.get(f"{sw} {port}")
    return [dev] if dev else []


def plan_lines(plan) -> tuple[list[str], list[str]]:
    """(lines, notes): the tc filters and VLAN moves every session needs."""
    from . import stp
    from .netplan import park_vid
    lab = plan.lab
    out, notes = [], []
    gis = stp.ifnames(lab)
    every = devcli.switch_ports(lab, plan)
    for sw in devcli.switches(lab):
        ports = every.get(sw, [])
        for n in sessions(lab, sw):
            s = session(lab, sw, n)
            dsts = _ifaces(lab, plan, sw, s["dst"], ports, gis) if s["dst"] else []
            if not dsts:
                if s["dst"]:
                    notes.append(f"# {sw} session {n}: nothing is plugged into {s['dst']}")
                continue
            d = dsts[0]
            pref = PREF + n
            srcs: list[tuple[str, str]] = []
            for p, way in s["src"]:
                srcs += [(i, way) for i in _ifaces(lab, plan, sw, p, ports, gis)]
            for tag, way in s["vlan"]:
                for i, link in enumerate(ports):
                    if link is None or not link.fabric_iface:
                        continue
                    net = lab.networks.get(link.network_id)
                    trunk = [lab.networks[t].vlan_no for t in link.trunk_vlans if t in lab.networks]
                    if net is not None and (net.vlan_no == int(tag) or int(tag) in trunk):
                        srcs.append((link.fabric_iface, way))
            out.append(f"# {sw} monitor session {n}: {len(srcs)} source port(s) copied to {d}")
            link = next((l for l in ports if l is not None and l.fabric_iface == d), None)
            if link is not None:
                vid = plan.vid_of(link)
                tagged = sorted(plan.segment_of(t).vid for t in link.trunk_vlans) if link.plugged else []
                park = park_vid(link.port)
                out += [f"bridge vlan del dev {d} vid {v} 2>/dev/null || true" for v in [vid] + tagged]
                out += [f"bridge vlan add dev {d} vid {park} pvid untagged   # out of its VLAN: only the copies",
                        f"echo 'dst {d} {pref}' >> {STATE}"]
            out += [f"tc qdisc add dev {d} clsact 2>/dev/null || true",
                    f"tc filter add dev {d} ingress pref {pref} matchall action drop   # ingress disabled",
                    f"echo 'src {d} {pref}' >> {STATE}"]
            for i, way in srcs:
                if i == d:
                    continue
                out.append(f"tc qdisc add dev {i} clsact 2>/dev/null || true")
                if way in ("rx", "both"):
                    out.append(f"tc filter add dev {i} ingress pref {pref} matchall action mirred egress mirror "
                               f"dev {d} || true")
                if way in ("tx", "both"):
                    out.append(f"tc filter add dev {i} egress pref {pref} matchall action mirred egress mirror "
                               f"dev {d} 2>/dev/null || echo 'span: {i} has a rate or fault qdisc: tx not mirrored'")
                out.append(f"echo 'src {i} {pref}' >> {STATE}")
    return out, notes


def render(plan, reset: bool = False) -> list[str]:
    """Shell for the router: the mirrors, after the switch bridges and the
    ports' own qdiscs (it runs at the end of winlab/iosl2.py's lines)."""
    lines, notes = plan_lines(plan)
    if not lines and not notes and not reset:
        return []
    out = ["# SPAN: monitor sessions as tc mirred (winlab/span.py)"]
    if reset:
        # Undo the last run: its filters, and each destination port back in its VLAN as the plan has it now.
        out.append(f"[ -f {STATE} ] && while read k i p; do [ $k = src ] && {{ tc filter del dev $i ingress pref $p "
                   f"2>/dev/null; tc filter del dev $i egress pref $p 2>/dev/null; }}; done < {STATE}; true")
        from .netplan import park_vid
        for link in plan.links:
            if not link.fabric_iface:
                continue
            i = link.fabric_iface
            back = [f"bridge vlan del dev {i} vid {park_vid(link.port)} 2>/dev/null",
                    f"bridge vlan add dev {i} vid {plan.vid_of(link)} pvid untagged"]
            back += [f"bridge vlan add dev {i} vid {plan.segment_of(t).vid}" for t in link.trunk_vlans]
            out.append(f"grep -q '^dst {i} ' {STATE} 2>/dev/null && {{ {'; '.join(back)}; }}; true")
        out.append(f": > {STATE}")
    return out + notes + lines
