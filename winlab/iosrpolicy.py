"""Routing policy typed at the lab router's console: prefix-lists, AS-path
access lists, community lists and route-maps, made real by FRRouting.

IOS chooses and changes routes with small named objects that refer to each
other, and FRRouting has the same objects under nearly the same words, so
winlab/iosrouting.py writes them into /etc/frr/frr.conf beside the routing
processes that use them (a BGP neighbour's ``route-map ... in|out``, a
``redistribute ... route-map``):

* ``ip prefix-list <name> [seq <n>] permit|deny <prefix>/<len> [ge <n>]
  [le <n>]`` is FRRouting's ``ip prefix-list`` line for line (a sequence
  number is always written, 5, 10, 15... as IOS numbers them);
  ``ip prefix-list <name> description <text>`` too.
* ``ip as-path access-list <name> permit|deny <regex>`` is FRRouting's
  ``bgp as-path access-list``: the same regular expressions (``_``, ``^``,
  ``$``).
* ``ip community-list standard <name> | <1-99> permit|deny <community>...``
  and ``expanded`` (or 100-500) are FRRouting's ``bgp community-list``.
* ``route-map <name> [permit|deny] [<seq>]`` enters config-route-map, where
  ``match ip address prefix-list``, ``match ip address <standard ACL>``,
  ``match as-path``, ``match community``, ``match tag``, ``match metric``
  and ``set metric``, ``set metric-type``, ``set local-preference``,
  ``set weight``, ``set tag``, ``set origin``, ``set as-path prepend``,
  ``set community``, ``set ip next-hop`` are FRRouting's route-map lines of
  the same names. A standard access list a route-map matches is written for
  FRRouting as its own ``access-list`` (the console's ACLs are otherwise
  nftables rules on the router, winlab/iosl3.py, which FRRouting does not
  read).

Where FRRouting and IOS differ the console says so instead of pretending:
one prefix-list, ACL or AS-path list per match line (FRRouting takes one
name; put a second in another sequence), no extended ACLs in a route-map.

Settings: ``pfx:<name>:<seq>`` = ``permit|deny <prefix> [ge n] [le n]``;
``pfx-desc:<name>``; ``aspath:<name>:<n>`` = ``permit|deny <regex>``;
``clist:<name>:<n>`` = ``standard|expanded permit|deny <values>``;
``rmap:<name>:<seq>`` = permit | deny; ``rmap-m:<name>:<seq>:<kind>`` and
``rmap-s:<name>:<seq>:<kind>`` = the match or set's value.
"""

from __future__ import annotations

import ipaddress
import re

MODE = "config-route-map"
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")
_COMM = re.compile(r"^(\d{1,5}:\d{1,5}|internet|no-export|no-advertise|local-as|\d{1,10})$", re.I)
# match kinds as IOS orders them in show running-config, and how each is typed
MATCH = ("ip address prefix-list", "ip address", "as-path", "community", "metric", "tag")
SET = ("metric", "metric-type", "local-preference", "weight", "tag", "origin", "as-path prepend", "community",
       "ip next-hop")


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


# ------------------------------------------------------------------ settings
def prefix_lists(own: dict) -> dict[str, list[tuple[int, str]]]:
    out: dict[str, list[tuple[int, str]]] = {}
    for k, v in own.items():
        if k.startswith("pfx:"):
            _, name, seq = k.split(":", 2)
            if seq.isdigit():
                out.setdefault(name, []).append((int(seq), v))
    for k in own:
        if k.startswith("pfx-desc:"):
            out.setdefault(k[9:], [])
    return {n: sorted(r) for n, r in sorted(out.items())}


def _indexed(own: dict, pre: str) -> dict[str, list[str]]:
    rows: dict[str, list[tuple[int, str]]] = {}
    for k, v in own.items():
        if k.startswith(pre):
            name, _, idx = k[len(pre):].rpartition(":")
            if idx.isdigit():
                rows.setdefault(name, []).append((int(idx), v))
    return {n: [v for _, v in sorted(r)] for n, r in sorted(rows.items(), key=lambda kv: _num_first(kv[0]))}


def _num_first(name: str):
    return (0, int(name), "") if name.isdigit() else (1, 0, name)


def aspath_lists(own: dict) -> dict[str, list[str]]:
    return _indexed(own, "aspath:")


def community_lists(own: dict) -> dict[str, list[str]]:
    return _indexed(own, "clist:")


def route_maps(own: dict) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for k in own:
        if k.startswith("rmap:"):
            _, name, seq = k.split(":", 2)
            if seq.isdigit():
                out.setdefault(name, []).append(int(seq))
    return {n: sorted(s) for n, s in sorted(out.items())}


def clauses(own: dict, name: str, seq: int, which: str) -> list[tuple[str, str]]:
    pre = f"rmap-{which}:{name}:{seq}:"
    have = {k[len(pre):]: v for k, v in own.items() if k.startswith(pre)}
    order = MATCH if which == "m" else SET
    return [(kind, have[kind]) for kind in order if kind in have]


def active(own: dict) -> bool:
    return any(k.startswith(("pfx:", "pfx-desc:", "aspath:", "clist:", "rmap:")) for k in own)


def acls_used(own: dict) -> list[str]:
    return sorted({v for k, v in own.items() if k.startswith("rmap-m:") and k.endswith(":ip address")},
                  key=_num_first)


# ------------------------------------------------------------------ frr.conf
def frr_lines(own: dict) -> list[str]:
    """access-lists a route-map matches, prefix-lists, AS-path and community
    lists, then the route-maps: FRRouting's own words."""
    from . import iosl3
    out = []
    for name in acls_used(own):
        if iosl3.kind_of(own, name) != "standard":
            continue
        for seq, entry in iosl3.entries(own, name):
            act, _, net = entry.partition(" ")
            out.append(f"access-list {name} seq {seq} {act} {'any' if net == '0.0.0.0/0' else net}")
    out += ["!"] if out else []
    for name, rows in prefix_lists(own).items():
        if own.get(f"pfx-desc:{name}"):
            out.append(f"ip prefix-list {name} description {own[f'pfx-desc:{name}']}")
        out += [f"ip prefix-list {name} seq {seq} {entry}" for seq, entry in rows]
    for name, rows in aspath_lists(own).items():
        out += [f"bgp as-path access-list {name} {entry}" for entry in rows]
    for name, rows in community_lists(own).items():
        for entry in rows:
            kind, _, rest = entry.partition(" ")
            word = "" if name.isdigit() else f"{kind} "
            out.append(f"bgp community-list {word}{name} {_frr_comm(rest)}")
    if out and out[-1] != "!":
        out.append("!")
    for name, seqs in route_maps(own).items():
        for seq in seqs:
            out.append(f"route-map {name} {own[f'rmap:{name}:{seq}']} {seq}")
            out += [f" {_frr_match(k, v)}" for k, v in clauses(own, name, seq, "m")]
            out += [f" {_frr_set(k, v)}" for k, v in clauses(own, name, seq, "s")]
            out += ["exit", "!"]
    return out


def _frr_comm(text: str) -> str:
    return re.sub(r"\blocal-as\b", "local-AS", text, flags=re.I)


def _frr_match(kind: str, value: str) -> str:
    return f"match {kind} {value}"


def _frr_set(kind: str, value: str) -> str:
    if kind == "community":
        return f"set community {_frr_comm(value)}"
    return f"set {kind} {value}"


# ------------------------------------------------------------------ show running-config
def run_lines(own: dict) -> list[str]:
    out = []
    for name, rows in aspath_lists(own).items():
        out += [f"ip as-path access-list {name} {entry}" for entry in rows]
    out += ["!"] if out else []
    n = len(out)
    for name, rows in community_lists(own).items():
        for entry in rows:
            kind, _, rest = entry.partition(" ")
            out.append(f"ip community-list {'' if name.isdigit() else kind + ' '}{name} {rest}")
    out += ["!"] if len(out) > n else []
    n = len(out)
    for name, rows in prefix_lists(own).items():
        if own.get(f"pfx-desc:{name}"):
            out.append(f"ip prefix-list {name} description {own[f'pfx-desc:{name}']}")
        out += [f"ip prefix-list {name} seq {seq} {entry}" for seq, entry in rows]
    out += ["!"] if len(out) > n else []
    for name, seqs in route_maps(own).items():
        for seq in seqs:
            out.append(f"route-map {name} {own[f'rmap:{name}:{seq}']} {seq}")
            out += [f" match {k} {v}" for k, v in clauses(own, name, seq, "m")]
            out += [f" set {k} {v}" for k, v in clauses(own, name, seq, "s")]
            out.append("!")
    return out


# ------------------------------------------------------------------ the console
WORDS = {("ip", "prefix-list"): "Build a prefix list", ("ip", "as-path"): "BGP autonomous system path filter",
         ("ip", "community-list"): "Add a community list entry", ("route-map",): "Create route-map or enter route-map command mode",
         ("match",): "Match values from routing table", ("set",): "Set values in destination routing protocol",
         ("show", "route-map"): "route-map information", ("show", "ip", "prefix-list"): "List IP prefix lists",
         ("show", "ip", "as-path-access-list"): "List AS path access lists",
         ("show", "ip", "community-list"): "List community-list"}


def add_specs(con, add, U, C) -> None:
    from . import devcli
    for k, v in WORDS.items():
        devcli.WORD_HELP.setdefault(k, v)
    M = (MODE,)
    add("end", con._end, "Exit from configure mode", M)
    add("exit", lambda a: _exit(con), "Exit from route-map configuration mode", M)
    add("do <line>", con._do, "To run exec commands in config mode", M)
    add("ip prefix-list <name> <line>", lambda a: prefix_cmd(con, a[0], a[1], True), "Build a prefix list", C + M)
    add("no ip prefix-list <name>", lambda a: prefix_cmd(con, a[0], "", False), "Negate a command or set its defaults", C + M)
    add("no ip prefix-list <name> <line>", lambda a: prefix_cmd(con, a[0], a[1], False), "Negate a command or set its defaults", C + M)
    add("ip as-path access-list <name> <line>", lambda a: aspath_cmd(con, a[0], a[1], True), "Specify an access list name", C + M)
    add("no ip as-path access-list <name>", lambda a: aspath_cmd(con, a[0], "", False), "Negate a command or set its defaults", C + M)
    add("no ip as-path access-list <name> <line>", lambda a: aspath_cmd(con, a[0], a[1], False), "Negate a command or set its defaults", C + M)
    add("ip community-list <line>", lambda a: clist_cmd(con, a[0], True), "Add a community list entry", C + M)
    add("no ip community-list <line>", lambda a: clist_cmd(con, a[0], False), "Negate a command or set its defaults", C + M)
    add("route-map <name>", lambda a: rmap_cmd(con, a[0], ""), "Route map tag", C + M)
    add("route-map <name> <line>", lambda a: rmap_cmd(con, a[0], a[1]), "Route map tag", C + M)
    add("no route-map <name>", lambda a: no_rmap(con, a[0], ""), "Negate a command or set its defaults", C + M)
    add("no route-map <name> <line>", lambda a: no_rmap(con, a[0], a[1]), "Negate a command or set its defaults", C + M)
    add("match <line>", lambda a: clause(con, "m", a[0], True), "Match values from routing table", M)
    add("no match <line>", lambda a: clause(con, "m", a[0], False), "Negate a command or set its defaults", M)
    add("set <line>", lambda a: clause(con, "s", a[0], True), "Set values in destination routing protocol", M)
    add("no set <line>", lambda a: clause(con, "s", a[0], False), "Negate a command or set its defaults", M)
    add("description <line>", lambda a: "", "Route-map comment", M)
    add("show route-map", lambda a: show_route_map(con, ""), "route-map information", U)
    add("show route-map <name>", lambda a: show_route_map(con, a[0]), "route-map name", U)
    add("show ip prefix-list", lambda a: show_prefix_list(con, ""), "List IP prefix lists", U)
    add("show ip prefix-list <name>", lambda a: show_prefix_list(con, a[0]), "Name of a prefix list", U)
    add("show ip as-path-access-list", lambda a: show_aspath(con, ""), "List AS path access lists", U)
    add("show ip as-path-access-list <name>", lambda a: show_aspath(con, a[0]), "AS path access list name", U)
    add("show ip community-list", lambda a: show_clist(con, ""), "List community-list", U)
    add("show ip community-list <name>", lambda a: show_clist(con, a[0]), "Community-list name", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _exit(con) -> str:
    con.s.mode, con.s.ctx = "config", ""
    return ""


def _name(text: str) -> str:
    if not _NAME.match(text):
        raise _err("% A name here is up to 63 letters, digits, '.', '-' or '_'")
    return text


def _net(text: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        raise _bad() from None


# ---- ip prefix-list
def parse_prefix_entry(words: list[str]) -> str:
    """['permit', '10.0.0.0/8', 'le', '24'] -> 'permit 10.0.0.0/8 le 24',
    checked as IOS checks it: len < ge <= le <= 32."""
    if len(words) < 2 or words[0] not in ("permit", "deny") or "/" not in words[1]:
        raise _bad()
    net = _net(words[1])
    ge = le = None
    i = 2
    while i < len(words):
        if words[i] in ("ge", "le") and i + 1 < len(words) and words[i + 1].isdigit():
            if words[i] == "ge":
                ge = int(words[i + 1])
            else:
                le = int(words[i + 1])
            i += 2
        else:
            raise _bad()
    lo = ge if ge is not None else net.prefixlen
    hi = le if le is not None else (32 if ge is not None else net.prefixlen)
    if (ge is not None and ge <= net.prefixlen) or (le is not None and le < net.prefixlen) or not lo <= hi <= 32:
        raise _err(f"% Invalid prefix range for {net}: the length must be below ge, ge no more than le, le at most 32")
    out = f"{words[0]} {net}"
    out += f" ge {ge}" if ge is not None else ""
    out += f" le {le}" if le is not None else ""
    return out


def prefix_cmd(con, name: str, rest: str, on: bool) -> str:
    _name(name)
    own = _own_c(con)
    w = rest.split()
    if w[:1] == ["description"]:
        text = rest.split(None, 1)[1] if on and len(w) > 1 else ""
        if on and (not text or len(text) > 80):
            raise _bad()
        if on:
            own[f"pfx-desc:{name}"] = text
        else:
            own.pop(f"pfx-desc:{name}", None)
        return _done(con)
    rows = prefix_lists(own).get(name, [])
    if not on and not w:
        keys = [k for k in own if k.startswith(f"pfx:{name}:") or k == f"pfx-desc:{name}"]
        for k in keys:
            del own[k]
        return _done(con) if keys else ""
    seq = None
    if w[:1] == ["seq"]:
        if len(w) < 2 or not w[1].isdigit() or not 1 <= int(w[1]) <= 4294967294:
            raise _bad()
        seq, w = int(w[1]), w[2:]
    if not on:
        if seq is not None and not w:
            if own.pop(f"pfx:{name}:{seq}", None) is None:
                return ""
            return _done(con)
        entry = parse_prefix_entry(w)
        hit = [s for s, e in rows if e == entry and (seq is None or s == seq)]
        for s in hit:
            del own[f"pfx:{name}:{s}"]
        return _done(con) if hit else ""
    entry = parse_prefix_entry(w)
    if any(e == entry for _, e in rows):
        return ""
    if seq is None:
        seq = (rows[-1][0] // 5 + 1) * 5 if rows else 5
    own[f"pfx:{name}:{seq}"] = entry
    return _done(con)


# ---- ip as-path access-list
def aspath_cmd(con, name: str, rest: str, on: bool) -> str:
    _name(name)
    own = _own_c(con)
    w = rest.split(None, 1)
    have = aspath_lists(own).get(name, [])
    if not on and not w:
        keys = [k for k in own if k.startswith(f"aspath:{name}:")]
        for k in keys:
            del own[k]
        return _done(con) if keys else ""
    if len(w) < 2 or w[0] not in ("permit", "deny"):
        raise _bad()
    regex = w[1].strip()
    if not re.fullmatch(r"[0-9_^$.*+?\[\]()| ,{}-]{1,200}", regex):
        raise _err("% An AS-path regular expression here is digits and _ ^ $ . * + ? [ ] ( ) |")
    try:
        re.compile(regex.replace("_", "(^|$|[ ,{}()])"))
    except re.error:
        raise _err("% Invalid regular expression") from None
    entry = f"{w[0]} {regex}"
    if on:
        if entry in have:
            return ""
        _store_indexed(own, f"aspath:{name}:", have + [entry])
    else:
        if entry not in have:
            return ""
        _store_indexed(own, f"aspath:{name}:", [e for e in have if e != entry])
    return _done(con)


def _store_indexed(own: dict, pre: str, rows: list[str]) -> None:
    for k in [k for k in own if k.startswith(pre)]:
        del own[k]
    for i, r in enumerate(rows, 1):
        own[f"{pre}{i}"] = r


# ---- ip community-list
def clist_cmd(con, rest: str, on: bool) -> str:
    own = _own_c(con)
    w = rest.split()
    if not w:
        raise _err("% Incomplete command.")
    if w[0].isdigit():
        n = int(w[0])
        if not 1 <= n <= 500:
            raise _bad()
        kind, name, w = ("standard" if n <= 99 else "expanded"), w[0], w[1:]
    elif w[0] in ("standard", "expanded") and len(w) >= 2:
        kind, name, w = w[0], _name(w[1]), w[2:]
    else:
        raise _bad()
    have = community_lists(own).get(name, [])
    if have and not have[0].startswith(kind + " "):
        raise _err(f"% Community list {name} is a {have[0].split()[0]} list")
    if not on and not w:
        keys = [k for k in own if k.startswith(f"clist:{name}:")]
        for k in keys:
            del own[k]
        return _done(con) if keys else ""
    if len(w) < 2 or w[0] not in ("permit", "deny"):
        raise _bad()
    if kind == "standard":
        vals = [v.lower() if not re.match(r"^local-as$", v, re.I) else "local-as" for v in w[1:]]
        if not all(_COMM.match(v) for v in vals):
            raise _err("% A community is AA:NN (each 0-65535), internet, no-export, no-advertise or local-as")
        entry = f"standard {w[0]} {' '.join(vals)}"
    else:
        entry = f"expanded {w[0]} {' '.join(w[1:])}"
    if on:
        if entry in have:
            return ""
        _store_indexed(own, f"clist:{name}:", have + [entry])
    else:
        if entry not in have:
            return ""
        _store_indexed(own, f"clist:{name}:", [e for e in have if e != entry])
    return _done(con)


# ---- route-map
def rmap_cmd(con, name: str, rest: str) -> str:
    _name(name)
    w = rest.split()
    act, seq = "permit", None
    if w and w[0] in ("permit", "deny"):
        act, w = w[0], w[1:]
    if w:
        if len(w) != 1 or not w[0].isdigit() or not 0 <= int(w[0]) <= 65535:
            raise _bad()
        seq = int(w[0])
    own = _own_c(con)
    seqs = route_maps(own).get(name, [])
    if seq is None:
        # IOS: with no sequence, the only entry is edited, a new map starts at 10
        if len(seqs) > 1:
            raise _err("% Please specify the entry to edit: this route-map has more than one (route-map "
                       f"{name} {act} <sequence>)")
        seq = seqs[0] if seqs else 10
    new = f"rmap:{name}:{seq}" not in own or own[f"rmap:{name}:{seq}"] != act
    own[f"rmap:{name}:{seq}"] = act
    con.s.mode, con.s.ctx = MODE, f"{name} {seq}"
    return _done(con) if new else (con._save(live=False) or "")


def no_rmap(con, name: str, rest: str) -> str:
    own = _own_c(con)
    w = rest.split()
    seq = next((x for x in w if x.isdigit()), "")
    if seq:
        keys = [k for k in own if k == f"rmap:{name}:{seq}"
                or k.startswith((f"rmap-m:{name}:{seq}:", f"rmap-s:{name}:{seq}:"))]
    else:
        keys = [k for k in own if k.startswith((f"rmap:{name}:", f"rmap-m:{name}:", f"rmap-s:{name}:"))]
    for k in keys:
        del own[k]
    return _done(con) if keys else ""


def _ctx(con) -> tuple[str, int]:
    name, _, seq = con.s.ctx.partition(" ")
    return name, int(seq)


def _parse_match(w: list[str], on: bool) -> tuple[str, str]:
    if w[:3] == ["ip", "address", "prefix-list"]:
        kind, vals = "ip address prefix-list", w[3:]
    elif w[:2] == ["ip", "address"]:
        kind, vals = "ip address", w[2:]
    elif w[:1] in (["as-path"], ["community"], ["tag"], ["metric"]):
        kind, vals = w[0], w[1:]
    else:
        raise _err("% This router's route-maps match ip address [prefix-list], as-path, community, tag and metric")
    if not on:
        return kind, ""
    if not vals:
        raise _err("% Incomplete command.")
    if kind == "community":
        if len(vals) > 2 or (len(vals) == 2 and vals[1] != "exact-match"):
            raise _err("% One community list per match line here (FRRouting takes one): another goes in its own "
                       "route-map entry")
        return kind, " ".join(vals)
    if len(vals) != 1:
        raise _err(f"% One name per match {kind} line on this router (FRRouting takes one): match the second in "
                   "another sequence of the route-map")
    if kind in ("tag", "metric") and not vals[0].isdigit():
        raise _bad()
    return kind, vals[0]


def _parse_set(w: list[str], on: bool) -> tuple[str, str]:
    if w[:3] == ["as-path", "prepend", "last-as"]:
        kind, vals = "as-path prepend", w[2:]
    elif w[:2] == ["as-path", "prepend"]:
        kind, vals = "as-path prepend", w[2:]
    elif w[:2] == ["ip", "next-hop"]:
        kind, vals = "ip next-hop", w[2:]
    elif w[:1] and w[0] in SET:
        kind, vals = w[0], w[1:]
    else:
        raise _err("% This router's route-maps set metric, metric-type, local-preference, weight, tag, origin, "
                   "as-path prepend, community and ip next-hop")
    if not on:
        return kind, ""
    if not vals:
        raise _err("% Incomplete command.")
    num = {"metric": 4294967295, "local-preference": 4294967295, "weight": 65535, "tag": 4294967295}
    if kind in num:
        if len(vals) != 1:
            raise _err("% One value here: EIGRP's five-part metric is not in this router's route-maps")
        if not vals[0].isdigit() or int(vals[0]) > num[kind]:
            raise _bad()
        return kind, str(int(vals[0]))
    if kind == "metric-type":
        if vals not in (["type-1"], ["type-2"]):
            raise _bad()
        return kind, vals[0]
    if kind == "origin":
        if vals not in (["igp"], ["incomplete"]):
            raise _err("% set origin igp | incomplete here")
        return kind, vals[0]
    if kind == "ip next-hop":
        if vals == ["peer-address"]:
            return kind, "peer-address"
        if len(vals) != 1:
            raise _bad()
        try:
            return kind, str(ipaddress.IPv4Address(vals[0]))
        except ValueError:
            raise _bad() from None
    if kind == "as-path prepend":
        if vals[0] == "last-as":
            if len(vals) != 2 or not vals[1].isdigit() or not 1 <= int(vals[1]) <= 10:
                raise _bad()
            return kind, f"last-as {vals[1]}"
        if not all(v.isdigit() and 1 <= int(v) <= 4294967295 for v in vals) or len(vals) > 10:
            raise _bad()
        return kind, " ".join(str(int(v)) for v in vals)
    # community
    if vals == ["none"]:
        return kind, "none"
    add = vals[-1] == "additive"
    body = vals[:-1] if add else vals
    norm = ["local-as" if v.lower() == "local-as" else v.lower() for v in body]
    if not norm or not all(_COMM.match(v) for v in norm):
        raise _err("% A community is AA:NN (each 0-65535), internet, no-export, no-advertise or local-as")
    return kind, " ".join(norm + (["additive"] if add else []))


def clause(con, which: str, rest: str, on: bool) -> str:
    name, seq = _ctx(con)
    w = rest.split()
    kind, value = (_parse_match if which == "m" else _parse_set)(w, on)
    own = _own_c(con)
    key = f"rmap-{which}:{name}:{seq}:{kind}"
    note = ""
    if on:
        if kind == "ip address":
            from . import iosl3
            have = iosl3.kind_of(own, value)
            if have == "extended":
                raise _err("% This router matches routes with a standard access list or a prefix-list: an "
                           "extended list filters packets here")
        if which == "m" and kind == "community" and value.split()[0] not in community_lists(own):
            note = f"% Community list {value.split()[0]} is not defined yet: the entry matches nothing until it is"
        own[key] = value
    elif own.pop(key, None) is None:
        return ""
    done = _done(con)
    return "\n".join(x for x in (note, done) if x)


# ------------------------------------------------------------------ show
def show_route_map(con, name: str) -> str:
    own = _own(con.lab)
    maps = route_maps(own)
    if name and name not in maps:
        return f"%route-map {name} not found"
    out = []
    for n, seqs in maps.items():
        if name and n != name:
            continue
        for seq in seqs:
            out.append(f"route-map {n}, {own[f'rmap:{n}:{seq}']}, sequence {seq}")
            out.append("  Match clauses:")
            for k, v in clauses(own, n, seq, "m"):
                label = {"ip address prefix-list": "ip address prefix-lists:", "ip address": "ip address (access-lists):",
                         "as-path": "as-path (as-path filter):", "community": "community (community-list filter):",
                         "tag": "tag", "metric": "metric"}[k]
                out.append(f"    {label} {v}")
            out.append("  Set clauses:")
            out += [f"    {k} {v}" for k, v in clauses(own, n, seq, "s")]
            out.append("  Policy routing matches: 0 packets, 0 bytes")
    return "\n".join(out)


def show_prefix_list(con, name: str) -> str:
    own = _own(con.lab)
    lists = prefix_lists(own)
    out = []
    for n, rows in lists.items():
        if name and n != name:
            continue
        out.append(f"ip prefix-list {n}: {len(rows)} entries")
        if own.get(f"pfx-desc:{n}"):
            out.append(f"   Description: {own[f'pfx-desc:{n}']}")
        out += [f"   seq {s} {e}" for s, e in rows]
    return "\n".join(out)


def show_aspath(con, name: str) -> str:
    own = _own(con.lab)
    out = []
    for n, rows in aspath_lists(own).items():
        if name and n != name:
            continue
        out.append(f"AS path access list {n}")
        out += [f"    {r}" for r in rows]
    return "\n".join(out)


def show_clist(con, name: str) -> str:
    own = _own(con.lab)
    out = []
    for n, rows in community_lists(own).items():
        if name and n != name:
            continue
        kind = rows[0].split()[0] if rows else "standard"
        out.append(f"Community {kind} list {n}" if not n.isdigit() else f"Community {kind} list {n}")
        out += [f"    {r.split(' ', 1)[1]}" for r in rows]
    return "\n".join(out)
