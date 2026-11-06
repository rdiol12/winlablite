"""The lab router's zone-based policy firewall (ZBF), as typed at its console.

IOS's zone-based firewall puts interfaces into zones and says, for each
direction between two zones (a zone-pair), what may cross. What is typed is
kept with the router's settings in the lab file and becomes an nftables
table on the router (``table ip wlzbf``), beside the access lists and NAT of
winlab/iosl3.py, which it never touches:

* ``zone security <name>`` names a zone; ``zone-member security <zone>`` on
  an interface puts it in one. ``self`` is the router itself.
* ``class-map type inspect match-any|match-all <name>`` with ``match
  protocol <name>`` / ``match access-group <list>`` says which traffic
  (winlab/mqc.py turns it into rules);
* ``policy-map type inspect <name>`` with ``class type inspect <class>``
  and ``inspect``, ``pass`` or ``drop [log]`` says what to do;
  ``class class-default`` catches the rest and drops it unless told
  otherwise;
* ``zone-pair security <name> source <zone> destination <zone>`` with
  ``service-policy type inspect <policy>`` applies it in one direction.

The rules are IOS's: traffic inside one zone passes; traffic between two
zones is dropped unless a zone-pair's policy lets it; an interface in a
zone and one in none never talk; the router's own traffic (the self zone)
is free until a zone-pair names self. ``inspect`` is stateful: the
connection is marked in the kernel's connection tracking (conntrack) and
its return traffic, and what is related to it (ICMP errors), comes back
without a rule of its own. ``pass`` is one way only, as on IOS: the reply
needs a pass of its own in the other zone-pair.

Settings: ``zone:<name>`` = description; ``zone-member:<if>`` = zone;
``cmap-insp:<name>`` and ``pmap-insp:<name>`` (JSON); ``zpair:<name>`` =
JSON {src, dst, policy}.
"""

from __future__ import annotations

import hashlib
import json
import re

from . import iosl3, mqc

TABLE = "wlzbf"
SELF = "self"
MARK = 0x5A100000      # an inspected connection's conntrack mark: MARK | pair << 8 | class
MARK_MASK = 0xFFF00000
ACTIONS = ("inspect", "pass", "drop")


# ------------------------------------------------------------------ settings
def zones(own: dict) -> list[str]:
    return sorted(k[5:] for k in own if k.startswith("zone:"))


def members(own: dict, zone: str) -> list[str]:
    return sorted(k[12:] for k, v in own.items() if k.startswith("zone-member:") and v == zone)


def cmaps(own: dict) -> list[str]:
    return sorted(k[10:] for k in own if k.startswith("cmap-insp:"))


def pmaps(own: dict) -> list[str]:
    return sorted(k[10:] for k in own if k.startswith("pmap-insp:"))


def pmap(own: dict, name: str) -> list[list]:
    """[[class, action, log], ...] in the order typed; class-default last."""
    try:
        rows = json.loads(own.get(f"pmap-insp:{name}", "") or "[]")
    except ValueError:
        rows = []
    rows = [r for r in rows if isinstance(r, list) and len(r) == 3]
    return [r for r in rows if r[0] != "class-default"] + [r for r in rows if r[0] == "class-default"]


def store_pmap(own: dict, name: str, rows: list[list]) -> None:
    own[f"pmap-insp:{name}"] = json.dumps(rows, separators=(",", ":"))


def pairs(own: dict) -> dict[str, dict]:
    out = {}
    for k, v in own.items():
        if k.startswith("zpair:"):
            try:
                d = json.loads(v)
            except ValueError:
                continue
            out[k[6:]] = {"src": d.get("src", ""), "dst": d.get("dst", ""), "policy": d.get("policy", ""),
                          "desc": d.get("desc", "")}
    return dict(sorted(out.items()))


def pair_index(own: dict, name: str) -> int:
    return list(pairs(own)).index(name) + 1


# ------------------------------------------------------------------ nftables
def _dev(lab, plan, ifname: str) -> str:
    return iosl3.svi_for(lab, plan, ifname)


def _set(devs: list[str]) -> str:
    return "{ " + ", ".join(f'"{d}"' for d in devs) + " }"


def _action(pair: str, cls: str, action: str, log: bool, mark: int) -> str:
    c = f'comment "zbf {pair} {cls} {action}"'
    if action == "inspect":
        return f"counter ct mark set {mark:#x} accept {c}"
    lg = f'log prefix "%FW-6-{"DROP" if action == "drop" else "PASS"}_PKT: {pair} {cls}: " ' if log else ""
    return f"counter {lg}{'accept' if action == 'pass' else 'drop'} {c}"


def pair_chain(own: dict, name: str, pair: dict, chains: dict[str, list[str]]) -> str:
    """The chain of a zone-pair: its policy's classes in order, then
    class-default (drop unless typed otherwise)."""
    ch = mqc._chain_name("zp", name)
    body: list[str] = []
    idx = pair_index(own, name)
    rows = pmap(own, pair["policy"]) if pair["policy"] else []
    default = ["class-default", "drop", False]
    for k, (cls, action, log) in enumerate(rows, 1):
        if cls == "class-default":
            default = [cls, action, log]
            continue
        cm = mqc.load(own, f"cmap-insp:{cls}")
        if f"cmap-insp:{cls}" not in own:
            continue
        tail = _action(name, cls, action or "drop", bool(log), MARK | (idx << 8) | k)
        body += mqc.class_rules(own, cm, tail, mqc._chain_name("zc", name, cls), chains)
    _, action, log = default
    body.append(_action(name, "class-default", action or "drop", bool(log), MARK | (idx << 8) | 255))
    chains[ch] = body
    return ch


def render_nft(plan) -> list[str]:
    """The firewall's nftables table, or nothing when no interface is in a zone."""
    lab = plan.lab
    own = lab.devices.get("router", {})
    zdevs = {z: [d for d in (_dev(lab, plan, i) for i in members(own, z)) if d] for z in zones(own)}
    zdevs = {z: d for z, d in zdevs.items() if d}
    if not zdevs:
        return []
    allm = sorted({d for ds in zdevs.values() for d in ds})
    chains: dict[str, list[str]] = {}
    fwd, inp, outp = [], [], []
    ret = f"ct state established,related ct mark & {MARK_MASK:#x} == {MARK:#x} accept"
    byzones = {(p["src"], p["dst"]): (n, p) for n, p in pairs(own).items()}
    for zs in sorted(zdevs):
        for zd in sorted(zdevs):
            m = f"iifname {_set(zdevs[zs])} oifname {_set(zdevs[zd])} "
            if zs == zd:
                fwd.append(m + "accept")
            elif (zs, zd) in byzones:
                name, pair = byzones[(zs, zd)]
                fwd.append(m + f"jump {pair_chain(own, name, pair, chains)}")
            else:
                fwd.append(m + f'counter drop comment "zbf no-zone-pair {zs} {zd}"')
    fwd.append(f'iifname {_set(allm)} counter drop comment "zbf zone-to-nozone - -"')
    fwd.append(f'oifname {_set(allm)} counter drop comment "zbf nozone-to-zone - -"')
    for z in sorted(zdevs):
        if (z, SELF) in byzones:
            name, pair = byzones[(z, SELF)]
            inp.append(f"iifname {_set(zdevs[z])} jump {pair_chain(own, name, pair, chains)}")
        if (SELF, z) in byzones:
            name, pair = byzones[(SELF, z)]
            outp.append(f"oifname {_set(zdevs[z])} jump {pair_chain(own, name, pair, chains)}")
    out = ["nft -f - <<'EOF' || true", f"table ip {TABLE} {{"]
    for ch, body in sorted(chains.items()):
        out += [f"  chain {ch} {{"] + [f"    {r}" for r in body] + ["  }"]
    out += ["  chain forward {", "    type filter hook forward priority 5; policy accept;", f"    {ret}"]
    out += [f"    {r}" for r in fwd] + ["  }"]
    out += ["  chain input {", "    type filter hook input priority 5; policy accept;", f"    {ret}"]
    out += [f"    {r}" for r in inp] + ["  }"]
    out += ["  chain output {", "    type filter hook output priority 5; policy accept;", f"    {ret}"]
    out += [f"    {r}" for r in outp] + ["  }", "}", "EOF"]
    return out


def render(plan, reset: bool = False) -> list[str]:
    body = render_nft(plan)
    if not body and not reset:
        return []
    return (["### zone-based firewall typed at the router's console (winlab/zbf.py)",
             f"nft delete table ip {TABLE} 2>/dev/null || true"] + body + [""])


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


# ------------------------------------------------------------------ reading
LIVE_CMD = f"nft list table ip {TABLE} 2>/dev/null"
SESSIONS_CMD = "conntrack -L -o extended 2>/dev/null || conntrack -L 2>/dev/null"


def parse_sessions(text: str) -> list[dict]:
    """conntrack lines of inspected connections -> [{pair, cls, proto, src,
    sport, dst, dport, state}]."""
    out = []
    for line in text.splitlines():
        m = re.search(r"\bmark=(\d+)", line)
        if not m or (int(m.group(1)) & MARK_MASK) != MARK:
            continue
        mark = int(m.group(1))
        w = line.split()
        proto = next((x for x in w if x in ("tcp", "udp", "icmp")), "ip")
        kv = [tuple(x.split("=", 1)) for x in w if "=" in x]
        get = lambda key: [v for k, v in kv if k == key]  # noqa: E731
        src, dst, sp, dp = get("src"), get("dst"), get("sport"), get("dport")
        if not src or not dst:
            continue
        state = next((x for x in w if x in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "TIME_WAIT", "CLOSE",
                                             "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK")), "")
        out.append({"pair": (mark >> 8) & 0xFFF, "cls": mark & 0xFF, "proto": proto, "src": src[0],
                    "sport": sp[0] if sp else "", "dst": dst[0], "dport": dp[0] if dp else "", "state": state})
    return out


# ------------------------------------------------------------------ the console
def run_lines(own: dict) -> list[str]:
    """class-map type inspect, policy-map type inspect, zones and zone-pairs,
    as show running-config prints them."""
    out = []
    for name in cmaps(own):
        cm = mqc.load(own, f"cmap-insp:{name}")
        out.append(f"class-map type inspect {cm['how']} {name}")
        out += [f" description {cm['desc']}"] if cm["desc"] else []
        out += [f" match {mqc.run_match(m)}" for m in cm["m"]]
        out.append("!")
    for name in pmaps(own):
        out.append(f"policy-map type inspect {name}")
        for cls, action, log in pmap(own, name):
            out.append(f" class {'class-default' if cls == 'class-default' else 'type inspect ' + cls}")
            if action:
                out.append(f"  {action}" + (" log" if log else ""))
        out.append("!")
    for z in zones(own):
        out.append(f"zone security {z}")
        out += [f" description {own[f'zone:{z}']}"] if own.get(f"zone:{z}") else []
    for name, p in pairs(own).items():
        out.append(f"zone-pair security {name} source {p['src']} destination {p['dst']}")
        out += [f" description {p['desc']}"] if p["desc"] else []
        out += [f" service-policy type inspect {p['policy']}"] if p["policy"] else []
    out += ["!"] if zones(own) or pairs(own) else []
    return out


def iface_lines(own: dict, ifname: str) -> list[str]:
    z = own.get(f"zone-member:{ifname}")
    return [f" zone-member security {z}"] if z else []


def add_specs(con, add, U, E, C, IF, sub) -> None:
    """The firewall's commands (winlab/devcli.py, through winlab/routerpolicy.py).
    `sub` is how a mode of this module's own is registered with its end, exit and do."""
    Z, ZP, CM, PM, PC = ("config-sec-zone",), ("config-sec-zone-pair",), ("config-cmap-insp",), \
        ("config-pmap-insp",), ("config-pmap-c-insp",)
    sub(Z + ZP + CM + PM + PC)
    add("zone security <name>", lambda a: _zone(con, a[0]), "Security zone", C + Z + ZP)
    add("no zone security <name>", lambda a: _no_zone(con, a[0]), "Negate a command or set its defaults", C)
    add("description <line>", lambda a: _desc(con, a[0]), "Zone description", Z + ZP + CM)
    add("no description", lambda a: _desc(con, ""), "Negate a command or set its defaults", Z + ZP + CM)
    add("zone-pair security <name> source <name> destination <name>",
        lambda a: _pair(con, a[0], a[1], a[2]), "Zone pair command", C + Z + ZP)
    add("no zone-pair security <name>", lambda a: _no_pair(con, a[0]), "Negate a command or set its defaults", C)
    add("service-policy type inspect <name>", lambda a: _pair_policy(con, a[0]), "Configure CBAC Service Policy", ZP)
    add("no service-policy type inspect <name>", lambda a: _pair_policy(con, ""), "Negate a command or set its defaults", ZP)
    add("no service-policy type inspect", lambda a: _pair_policy(con, ""), "Negate a command or set its defaults", ZP)
    for how in ("match-any", "match-all"):
        add(f"class-map type inspect {how} <name>", lambda a, h=how: _cmap(con, a[0], h),
            "Logical-OR (any) / Logical-AND (all) of the match criteria", C + CM)
    add("class-map type inspect <name>", lambda a: _cmap(con, a[0], "match-all"), "Configure CPL Class Map", C + CM)
    add("no class-map type inspect <name>", lambda a: _no_key(con, f"cmap-insp:{a[0]}"),
        "Negate a command or set its defaults", C)
    add("match protocol <name>", lambda a: _match(con, ["protocol", a[0]], True), "Protocol", CM)
    add("match access-group <num>", lambda a: _match(con, ["access-group", a[0]], True), "Access group", CM)
    add("match access-group name <name>", lambda a: _match(con, ["access-group", "name", a[0]], True),
        "Named Access List", CM)
    add("no match <line>", lambda a: _match(con, a[0].split(), False), "Negate a command or set its defaults", CM)
    add("policy-map type inspect <name>", lambda a: _pmap(con, a[0]), "Configure CPL Policy Map", C + PM)
    add("no policy-map type inspect <name>", lambda a: _no_key(con, f"pmap-insp:{a[0]}"),
        "Negate a command or set its defaults", C)
    add("class type inspect <name>", lambda a: _class(con, a[0]), "The class-map type inspect to use", PM + PC)
    add("class class-default", lambda a: _class(con, "class-default"), "System default class matching otherwise unclassified packets", PM + PC)
    add("no class type inspect <name>", lambda a: _no_class(con, a[0]), "Negate a command or set its defaults", PM)
    add("no class class-default", lambda a: _no_class(con, "class-default"), "Negate a command or set its defaults", PM)
    add("inspect", lambda a: _act(con, "inspect", False), "Context-based Access Control Engine", PC)
    add("inspect <name>", lambda a: _act(con, "inspect", False), "Context-based Access Control Engine", PC)
    add("pass", lambda a: _act(con, "pass", False), "Pass the packet", PC)
    add("pass log", lambda a: _act(con, "pass", True), "Log the passed packet", PC)
    add("drop", lambda a: _act(con, "drop", False), "Drop the packet", PC)
    add("drop log", lambda a: _act(con, "drop", True), "Log the dropped packet", PC)
    for w in ("inspect", "pass", "drop"):
        add(f"no {w}", lambda a: _act(con, "", False), "Negate a command or set its defaults", PC)
    add("zone-member security <name>", lambda a: _member(con, a[0]), "Apply zone name", IF)
    add("no zone-member security", lambda a: _member(con, ""), "Negate a command or set its defaults", IF)
    add("no zone-member security <name>", lambda a: _member(con, ""), "Negate a command or set its defaults", IF)
    add("show zone security", lambda a: show_zones(con, ""), "Zone information", U)
    add("show zone security <name>", lambda a: show_zones(con, a[0]), "Zone information", U)
    add("show zone-pair security", lambda a: show_pairs(con), "Zone pair information", U)
    add("show class-map type inspect", lambda a: show_cmaps(con, ""), "Show class-maps of type inspect", U)
    add("show class-map type inspect <name>", lambda a: show_cmaps(con, a[0]), "Show class-maps of type inspect", U)
    add("show policy-map type inspect", lambda a: show_pmaps(con, ""), "Show policy-maps of type inspect", U)
    add("show policy-map type inspect <name>", lambda a: show_pmaps(con, a[0]), "Show policy-maps of type inspect", U)
    add("show policy-map type inspect zone-pair", lambda a: show_pair_policy(con, "", False), "Zone-pair", U)
    add("show policy-map type inspect zone-pair sessions", lambda a: show_pair_policy(con, "", True),
        "Inspect sessions", U)
    add("show policy-map type inspect zone-pair <name>", lambda a: show_pair_policy(con, a[0], False), "Zone-pair", U)
    add("show policy-map type inspect zone-pair <name> sessions", lambda a: show_pair_policy(con, a[0], True),
        "Inspect sessions", U)
    add("clear zone-pair inspect sessions", lambda a: _clear(con), "Clear inspect sessions", E)


def _own(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _err(text: str) -> Exception:
    from . import devcli
    return devcli.CliError(text)


def _done(con) -> str:
    return con._save().strip()


def _name_ok(name: str) -> str:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$", name):
        raise _err("% Invalid input detected at '^' marker.")
    return name


def _zone(con, name: str) -> str:
    _name_ok(name)
    if name.lower() == SELF:
        raise _err("% self is a system defined zone; it cannot be configured")
    own = _own(con)
    own.setdefault(f"zone:{name}", "")
    con.s.mode, con.s.ctx = "config-sec-zone", name
    return _done(con)


def _no_zone(con, name: str) -> str:
    own = _own(con)
    if f"zone:{name}" not in own:
        return f"% Zone {name} does not exist"
    if members(own, name):
        return f"% Zone {name} has member interfaces; remove them with no zone-member security first"
    if any(name in (p["src"], p["dst"]) for p in pairs(own).values()):
        return f"% Zone {name} is used by a zone-pair; remove the zone-pair first"
    own.pop(f"zone:{name}")
    return _done(con)


def _desc(con, text: str) -> str:
    own = _own(con)
    if con.s.mode == "config-sec-zone":
        own[f"zone:{con.s.ctx}"] = text
    elif con.s.mode == "config-sec-zone-pair":
        p = pairs(own).get(con.s.ctx)
        if p is not None:
            p["desc"] = text
            own[f"zpair:{con.s.ctx}"] = json.dumps(p, separators=(",", ":"))
    else:
        cm = mqc.load(own, f"cmap-insp:{con.s.ctx}")
        cm["desc"] = text
        mqc.store(own, f"cmap-insp:{con.s.ctx}", cm)
    return _done(con)


def _pair(con, name: str, src: str, dst: str) -> str:
    _name_ok(name)
    own = _own(con)
    for z in (src, dst):
        if z != SELF and f"zone:{z}" not in own:
            raise _err(f"% Zone {z} does not exist")
    if src == dst:
        raise _err("% Same zone cannot be both source and destination")
    for other, p in pairs(own).items():
        if other != name and (p["src"], p["dst"]) == (src, dst):
            raise _err(f"% Zone-pair {other} already exists for source {src} destination {dst}")
    p = pairs(own).get(name, {"policy": "", "desc": ""})
    p.update(src=src, dst=dst)
    own[f"zpair:{name}"] = json.dumps(p, separators=(",", ":"))
    con.s.mode, con.s.ctx = "config-sec-zone-pair", name
    return _done(con)


def _no_pair(con, name: str) -> str:
    if _own(con).pop(f"zpair:{name}", None) is None:
        return f"% Zone-pair {name} does not exist"
    return _done(con)


def _pair_policy(con, policy: str) -> str:
    own = _own(con)
    if policy and f"pmap-insp:{policy}" not in own:
        raise _err(f"% Policy map {policy} not configured")
    p = pairs(own)[con.s.ctx]
    p["policy"] = policy
    own[f"zpair:{con.s.ctx}"] = json.dumps(p, separators=(",", ":"))
    return _done(con)


def _cmap(con, name: str, how: str) -> str:
    _name_ok(name)
    own = _own(con)
    key = f"cmap-insp:{name}"
    cm = mqc.load(own, key)
    if key in own and cm["how"] != how:
        raise _err(f"% class-map {name} is already a {cm['how']} class-map; remove it to change that")
    cm["how"] = how
    mqc.store(own, key, cm)
    con.s.mode, con.s.ctx = "config-cmap-insp", name
    return _done(con)


def _match(con, words: list[str], on: bool) -> str:
    own = _own(con)
    key = f"cmap-insp:{con.s.ctx}"
    cm = mqc.load(own, key)
    try:
        line = mqc.match_line(words, qos=False)
    except mqc.MqcError as exc:
        raise _err(str(exc)) from None
    if on and line not in cm["m"]:
        cm["m"].append(line)
    elif not on:
        if line not in cm["m"]:
            return "% Match statement not found"
        cm["m"].remove(line)
    mqc.store(own, key, cm)
    return _done(con)


def _pmap(con, name: str) -> str:
    _name_ok(name)
    own = _own(con)
    if f"pmap-insp:{name}" not in own:
        store_pmap(own, name, [])
    con.s.mode, con.s.ctx = "config-pmap-insp", name
    return _done(con)


def _class(con, cls: str) -> str:
    own = _own(con)
    pm = con.s.ctx.split("|")[0]
    if cls != "class-default" and f"cmap-insp:{cls}" not in own:
        raise _err(f"%No such class-map {cls}, or it is not of type inspect")
    rows = pmap(own, pm)
    if not any(r[0] == cls for r in rows):
        rows.append([cls, "drop" if cls == "class-default" else "", False])
        store_pmap(own, pm, rows)
    con.s.mode, con.s.ctx = "config-pmap-c-insp", f"{pm}|{cls}"
    return _done(con)


def _no_class(con, cls: str) -> str:
    own = _own(con)
    pm = con.s.ctx
    store_pmap(own, pm, [r for r in pmap(own, pm) if r[0] != cls])
    return _done(con)


def _act(con, action: str, log: bool) -> str:
    own = _own(con)
    pm, cls = con.s.ctx.split("|", 1)
    if cls == "class-default" and action == "inspect":
        pass  # IOS allows it; return traffic of what class-default inspected comes back too
    rows = pmap(own, pm)
    for r in rows:
        if r[0] == cls:
            r[1], r[2] = action, log
    store_pmap(own, pm, rows)
    return _done(con)


def _member(con, zone: str) -> str:
    own = _own(con)
    key = f"zone-member:{con.s.ctx}"
    if zone:
        if zone == SELF:
            raise _err("% Cannot assign interface to self zone")
        if f"zone:{zone}" not in own:
            raise _err(f"% Zone {zone} does not exist")
        own[key] = zone
    else:
        own.pop(key, None)
    return _done(con)


def _no_key(con, key: str) -> str:
    own = _own(con)
    name = key.split(":", 1)[1]
    if key.startswith("pmap-insp:") and any(p["policy"] == name for p in pairs(own).values()):
        return f"% Policy map {name} is in use by a zone-pair; remove it there first"
    if own.pop(key, None) is None:
        return f"% {name} does not exist"
    return _done(con)


def show_zones(con, only: str) -> str:
    own = con.lab.devices.get("router", {})
    out = []
    if not only or only == SELF:
        out += ["zone self", "  Description: System defined zone", ""]
    for z in zones(own):
        if only and z != only:
            continue
        out.append(f"zone {z}")
        if own.get(f"zone:{z}"):
            out.append(f"  Description: {own[f'zone:{z}']}")
        ms = members(own, z)
        if ms:
            out += ["  Member Interfaces:"] + [f"    {m}" for m in ms]
        out.append("")
    if only and not out:
        return f"% Zone {only} does not exist"
    return "\n".join(out).rstrip()


def show_pairs(con) -> str:
    own = con.lab.devices.get("router", {})
    out = []
    for name, p in pairs(own).items():
        out += [f"Zone-pair name {name}", f"    Source-Zone {p['src']}  Destination-Zone {p['dst']} "]
        out += [f"    Description: {p['desc']}"] if p["desc"] else []
        out += [f"    service-policy {p['policy'] or 'not present'}", ""]
    return "\n".join(out).rstrip()


def show_cmaps(con, only: str) -> str:
    own = con.lab.devices.get("router", {})
    out = []
    for name in cmaps(own):
        if only and name != only:
            continue
        cm = mqc.load(own, f"cmap-insp:{name}")
        out.append(f" Class Map type inspect {cm['how']} {name} (id {cmaps(own).index(name) + 1})")
        out += [f"   Match {mqc.show_match(m)}" for m in cm["m"]] + [""]
    return "\n".join(out).rstrip()


def show_pmaps(con, only: str) -> str:
    own = con.lab.devices.get("router", {})
    out = []
    for name in pmaps(own):
        if only and name != only:
            continue
        out.append(f"  Policy Map type inspect {name}")
        for cls, action, log in pmap(own, name):
            out.append(f"    Class {cls}")
            out.append(f"      {(action or 'drop').capitalize()}" + (" log" if log else ""))
    return "\n".join(out)


def show_pair_policy(con, only: str, sessions: bool) -> str:
    own = con.lab.devices.get("router", {})
    counts, sess = {}, []
    if con.powered() and pairs(own):
        try:
            counts = mqc.counters(con._on_router(LIVE_CMD, timeout=10), "zbf")
            sess = parse_sessions(con._on_router(SESSIONS_CMD, timeout=15))
        except Exception:  # noqa: BLE001 - the policy still shows without the router's numbers
            counts, sess = {}, []
    out = []
    for name, p in pairs(own).items():
        if only and name != only:
            continue
        out += ["", "policy exists on zp " + name, f"  Zone-pair: {name}", ""]
        if not p["policy"]:
            out.append("  No service-policy: every packet from the source zone to the destination is dropped")
            continue
        out.append(f"  Service-policy inspect : {p['policy']}")
        idx = pair_index(own, name)
        rows = pmap(own, p["policy"])
        if not any(r[0] == "class-default" for r in rows):
            rows = rows + [["class-default", "drop", False]]
        for k, (cls, action, log) in enumerate(rows, 1):
            action = action or "drop"
            cm = mqc.load(own, f"cmap-insp:{cls}") if cls != "class-default" else {"how": "match-any", "m": ["any"]}
            out += ["", f"    Class-map: {cls} ({cm['how']})"]
            out += [f"      Match: {mqc.show_match(m)}" for m in cm["m"]]
            pk, by = counts.get(f"{name} {cls} {action}", (0, 0))
            if action == "inspect":
                mine = [s for s in sess if s["pair"] == idx and s["cls"] == (255 if cls == "class-default" else k)]
                out += ["      Inspect", f"        Packets matched: {pk}, bytes: {by}",
                        f"        Number of Established Sessions = {len(mine)}"]
                if sessions and mine:
                    out.append("        Established Sessions")
                    for j, s in enumerate(mine, 1):
                        sp = f":{s['sport']}" if s["sport"] else ""
                        dp = f":{s['dport']}" if s["dport"] else ""
                        out.append(f"         Session {j} ({s['src']}{sp})=>({s['dst']}{dp}) {s['proto']} "
                                   f"SIS_OPEN" + (f" ({s['state']})" if s["state"] else ""))
            else:
                out += [f"      {action.capitalize()}" + (" log" if log else ""), f"        {pk} packets, {by} bytes"]
    return "\n".join(out).strip("\n")


def _clear(con) -> str:
    con._on_router(f"conntrack -D -m {MARK:#x}/{MARK_MASK:#x} >/dev/null 2>&1; true", timeout=10)
    return ""
