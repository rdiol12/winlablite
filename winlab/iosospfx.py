"""OSPF area types and summarisation at the lab router's console, made real by
FRRouting's ospfd (winlab/iosrouting.py writes the lines into its ``router
ospf`` block).

* ``area <id> stub [no-summary]``: a stub area takes no external (type 5)
  LSAs; its ABR gives it a default route instead, and with no-summary
  (totally stubby) no inter-area routes either. Every router of the area
  must agree, or they never become neighbours (the E bit in the hello).
* ``area <id> nssa [no-summary] [default-information-originate]``: a
  not-so-stubby area may hold an ASBR, whose externals travel as type 7
  LSAs (O N1 / O N2) that the ABR translates into type 5 for the rest of
  the domain.
* ``area <id> range <address> <mask> [not-advertise | cost <n>]`` on an ABR
  summarises an area's routes into one inter-area route;
  ``summary-address <address> <mask> [tag <n> | not-advertise]`` on an ASBR
  summarises externals; ``area <id> default-cost <n>`` is the cost of the
  default an ABR gives a stub area; ``area <id> virtual-link <router-id>``
  joins an area that does not touch area 0 to it through a transit area.

ospfd's commands carry the same words (a prefix instead of an address and
mask; IOS's ``not-advertise`` on summary-address is ospfd's
``no-advertise``). ``show ip ospf`` is ospfd's own; ``show ip route`` codes
inter-area routes O IA, externals O E1 / O E2 and NSSA externals O N1 / O
N2, read from ospfd's routing table and its type 7 LSAs; ``show ip
protocols`` counts the normal, stub and NSSA areas.

Settings: ``ospf-atype:<pid>:<area>`` = stub | nssa and its options;
``ospf-range:<pid>:<area>:<prefix>`` = "" | not-advertise | cost <n>;
``ospf-vlink:<pid>:<area>:<router-id>``; ``ospf-dcost:<pid>:<area>``;
``ospf-sumaddr:<pid>:<prefix>`` = "" | tag <n> | not-advertise.
"""

from __future__ import annotations

import ipaddress
import re


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def _area_key(area: str) -> str:
    """Areas sort and compare as numbers: 0.0.0.1 and 1 are the same."""
    return str(int(ipaddress.IPv4Address(area))) if "." in area else area


def area_types(own: dict, pid: int) -> dict[str, str]:
    pre = f"ospf-atype:{pid}:"
    return {k[len(pre):]: v for k, v in own.items() if k.startswith(pre)}


def _keyed(own: dict, pre: str) -> list[tuple[str, str, str]]:
    out = []
    for k, v in own.items():
        if k.startswith(pre):
            area, _, rest = k[len(pre):].partition(":")
            out.append((area, rest, v))
    return sorted(out, key=lambda r: (int(_area_key(r[0])), r[1]))


def ranges(own: dict, pid: int) -> list[tuple[str, str, str]]:
    return _keyed(own, f"ospf-range:{pid}:")


def vlinks(own: dict, pid: int) -> list[tuple[str, str, str]]:
    return _keyed(own, f"ospf-vlink:{pid}:")


def summaries(own: dict, pid: int) -> list[tuple[str, str]]:
    pre = f"ospf-sumaddr:{pid}:"
    return sorted(((k[len(pre):], v) for k, v in own.items() if k.startswith(pre)),
                  key=lambda r: int(ipaddress.IPv4Network(r[0]).network_address))


def _sorted_types(own: dict, pid: int) -> list[tuple[str, str]]:
    return sorted(area_types(own, pid).items(), key=lambda kv: int(_area_key(kv[0])))


# ------------------------------------------------------------------ frr.conf
def frr_lines(own: dict, pid: int) -> list[str]:
    out = [f" area {a} {t}" for a, t in _sorted_types(own, pid)]
    for k, v in sorted(own.items()):
        if k.startswith(f"ospf-dcost:{pid}:"):
            out.append(f" area {k.split(':', 2)[2]} default-cost {v}")
    out += [f" area {a} range {p}" + (f" {v}" if v else "") for a, p, v in ranges(own, pid)]
    out += [f" area {a} virtual-link {r}" for a, r, _ in vlinks(own, pid)]
    for p, v in summaries(own, pid):
        out.append(f" summary-address {p}" + (" no-advertise" if v == "not-advertise" else f" {v}" if v else ""))
    return out


# ------------------------------------------------------------------ show running-config
def run_lines(own: dict, pid: int) -> list[str]:
    out = []
    for k, v in sorted(own.items()):
        if k.startswith(f"ospf-dcost:{pid}:"):
            out.append(f" area {k.split(':', 2)[2]} default-cost {v}")
    out += [f" area {a} {t}" for a, t in _sorted_types(own, pid)]
    for a, p, v in ranges(own, pid):
        n = ipaddress.IPv4Network(p)
        out.append(f" area {a} range {n.network_address} {n.netmask}" + (f" {v}" if v else ""))
    out += [f" area {a} virtual-link {r}" for a, r, _ in vlinks(own, pid)]
    for p, v in summaries(own, pid):
        n = ipaddress.IPv4Network(p)
        out.append(f" summary-address {n.network_address} {n.netmask}" + (f" {v}" if v else ""))
    return out


def area_counts(own: dict, pid: int, areas: list[str]) -> tuple[int, int, int]:
    types = {_area_key(a): t.split()[0] for a, t in area_types(own, pid).items()}
    keys = {_area_key(a) for a in areas} | set(types)
    stub = sum(1 for a in keys if types.get(a) == "stub")
    nssa = sum(1 for a in keys if types.get(a) == "nssa")
    return len(keys) - stub - nssa, stub, nssa


def all_areas(own: dict, pid: int) -> list[str]:
    return [a for a, _ in _sorted_types(own, pid)]


# ------------------------------------------------------------------ the console
def add_specs(con, add, RM) -> None:
    from . import devcli
    for k, v in {("area", "stub"): "Specify a stub area", ("area", "nssa"): "Specify a NSSA area",
                 ("area", "range"): "Summarize routes matching address/mask (border routers only)",
                 ("area", "virtual-link"): "Define a virtual link and its parameters",
                 ("area", "default-cost"): "Set the summary-default cost of a NSSA/stub area",
                 ("summary-address",): "Configure IP address summaries"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    add("area <name> stub", lambda a: atype(con, a[0], "stub", ""), "Specify a stub area", RM)
    add("area <name> stub no-summary", lambda a: atype(con, a[0], "stub", "no-summary"), "Do not send summary LSA into stub area", RM)
    add("no area <name> stub", lambda a: no_atype(con, a[0], "stub", ""), "Negate a command or set its defaults", RM)
    add("no area <name> stub no-summary", lambda a: no_atype(con, a[0], "stub", "no-summary"), "Negate a command or set its defaults", RM)
    add("area <name> nssa", lambda a: atype(con, a[0], "nssa", ""), "Specify a NSSA area", RM)
    add("area <name> nssa <line>", lambda a: atype(con, a[0], "nssa", a[1]), "Specify a NSSA area", RM)
    add("no area <name> nssa", lambda a: no_atype(con, a[0], "nssa", ""), "Negate a command or set its defaults", RM)
    add("no area <name> nssa <line>", lambda a: no_atype(con, a[0], "nssa", a[1]), "Negate a command or set its defaults", RM)
    add("area <name> range <ip> <mask>", lambda a: area_range(con, a[0], a[1], a[2], "", True), "Summarize routes matching address/mask (border routers only)", RM)
    add("area <name> range <ip> <mask> <line>", lambda a: area_range(con, a[0], a[1], a[2], a[3], True), "Summarize routes matching address/mask (border routers only)", RM)
    add("no area <name> range <ip> <mask>", lambda a: area_range(con, a[0], a[1], a[2], "", False), "Negate a command or set its defaults", RM)
    add("no area <name> range <ip> <mask> <line>", lambda a: area_range(con, a[0], a[1], a[2], "", False), "Negate a command or set its defaults", RM)
    add("area <name> virtual-link <ip>", lambda a: vlink(con, a[0], a[1], True), "Define a virtual link and its parameters", RM)
    add("no area <name> virtual-link <ip>", lambda a: vlink(con, a[0], a[1], False), "Negate a command or set its defaults", RM)
    add("area <name> default-cost <num>", lambda a: dcost(con, a[0], a[1]), "Set the summary-default cost of a NSSA/stub area", RM)
    add("no area <name> default-cost", lambda a: dcost(con, a[0], ""), "Negate a command or set its defaults", RM)
    add("no area <name> default-cost <num>", lambda a: dcost(con, a[0], ""), "Negate a command or set its defaults", RM)
    add("no area <name>", lambda a: no_area(con, a[0]), "Negate a command or set its defaults", RM)
    add("no summary-address <line>", lambda a: summary_cmd(con, a[0], False), "Negate a command or set its defaults", RM)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _pid(con) -> int:
    kind, _, pid = con.s.ctx.partition(":")
    if kind != "ospf":
        raise _bad()
    return int(pid)


def _area(text: str) -> str:
    from .iosrouting import _area as norm
    return norm(text)


def _backbone(area: str) -> bool:
    return _area_key(area) == "0"


def _find(own: dict, pre: str, area: str) -> str:
    """The key an area already has under another spelling (1 / 0.0.0.1)."""
    for k in own:
        if k.startswith(pre) and _area_key(k[len(pre):].split(":")[0]) == _area_key(area):
            return k
    return ""


def atype(con, area_text: str, kind: str, rest: str) -> str:
    pid = _pid(con)
    area = _area(area_text)
    if _backbone(area):
        raise _err(f"% OSPF: Backbone can not be configured as {'stub' if kind == 'stub' else 'NSSA'} area")
    opts = rest.split()
    allowed = ("no-summary",) if kind == "stub" else ("no-summary", "default-information-originate", "no-redistribution")
    if any(o not in allowed for o in opts):
        raise _bad()
    own = _own_c(con)
    pre = f"ospf-atype:{pid}:"
    old = _find(own, pre, area)
    if old:
        have = own[old].split()
        if have[0] != kind:
            raise _err(f"% OSPF: area {area} is already a{'n NSSA' if have[0] == 'nssa' else ' stub'} area: "
                       f"no area {area} {have[0]} first")
        keep = set(have[1:]) | set(opts)
        del own[old]
    else:
        keep = set(opts)
    order = [o for o in ("no-redistribution", "default-information-originate", "no-summary") if o in keep]
    own[f"{pre}{area}"] = " ".join([kind] + order)
    return _done(con)


def no_atype(con, area_text: str, kind: str, rest: str) -> str:
    pid = _pid(con)
    area = _area(area_text)
    own = _own_c(con)
    old = _find(own, f"ospf-atype:{pid}:", area)
    if not old or own[old].split()[0] != kind:
        return ""
    drop = set(rest.split())
    if not drop:
        del own[old]
    else:
        have = own[old].split()
        own[old] = " ".join([have[0]] + [o for o in have[1:] if o not in drop])
    return _done(con)


def _prefix(addr: str, mask: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
    except ValueError:
        raise _bad() from None


def area_range(con, area_text: str, addr: str, mask: str, rest: str, on: bool) -> str:
    pid = _pid(con)
    area = _area(area_text)
    net = _prefix(addr, mask)
    w = rest.split()
    if w == ["advertise"] or not w:
        opt = ""
    elif w == ["not-advertise"]:
        opt = "not-advertise"
    elif len(w) == 2 and w[0] == "cost" and w[1].isdigit() and int(w[1]) <= 16777215:
        opt = f"cost {int(w[1])}"
    else:
        raise _bad()
    own = _own_c(con)
    key = f"ospf-range:{pid}:{area}:{net}"
    if on:
        own[key] = opt
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def vlink(con, area_text: str, rid: str, on: bool) -> str:
    pid = _pid(con)
    area = _area(area_text)
    if _backbone(area):
        raise _err("% OSPF: Area cannot be backbone for a virtual link")
    try:
        rid = str(ipaddress.IPv4Address(rid))
    except ValueError:
        raise _bad() from None
    own = _own_c(con)
    t = own.get(_find(own, f"ospf-atype:{pid}:", area), "")
    if on and t:
        raise _err(f"% OSPF: area {area} is a {t.split()[0]} area: a virtual link crosses a normal area only")
    key = f"ospf-vlink:{pid}:{area}:{rid}"
    if on:
        own[key] = "yes"
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def dcost(con, area_text: str, value: str) -> str:
    pid = _pid(con)
    area = _area(area_text)
    own = _own_c(con)
    key = f"ospf-dcost:{pid}:{area}"
    if value:
        if not value.isdigit() or int(value) > 16777215:
            raise _bad()
        own[key] = str(int(value))
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def no_area(con, area_text: str) -> str:
    pid = _pid(con)
    area = _area(area_text)
    own = _own_c(con)
    keys = [k for k in own if k.startswith((f"ospf-atype:{pid}:", f"ospf-range:{pid}:", f"ospf-vlink:{pid}:",
                                            f"ospf-dcost:{pid}:", f"ospf-areaauth:{pid}:"))
            and _area_key(k.split(":")[2]) == _area_key(area)]
    for k in keys:
        del own[k]
    return _done(con) if keys else ""


def summary_cmd(con, rest: str, on: bool) -> str:
    """summary-address <address> <mask> [tag <n> | not-advertise] under router ospf."""
    pid = _pid(con)
    w = rest.split()
    if len(w) < 2:
        raise _err("% Incomplete command.")
    net = _prefix(w[0], w[1])
    opt = w[2:]
    if not on or not opt:
        val = ""
    elif opt == ["not-advertise"]:
        val = "not-advertise"
    elif len(opt) == 2 and opt[0] == "tag" and opt[1].isdigit() and 1 <= int(opt[1]) <= 4294967295:
        val = f"tag {int(opt[1])}"
    else:
        raise _bad()
    own = _own_c(con)
    key = f"ospf-sumaddr:{pid}:{net}"
    if on:
        own[key] = val
    elif own.pop(key, None) is None:
        return ""
    return _done(con)


def forget_pid(own: dict, pid: int) -> None:
    for k in [k for k in own if k.startswith((f"ospf-atype:{pid}:", f"ospf-range:{pid}:", f"ospf-vlink:{pid}:",
                                              f"ospf-dcost:{pid}:", f"ospf-sumaddr:{pid}:"))]:
        del own[k]


# ------------------------------------------------------------------ route types for show ip route
_ROUTE = re.compile(r"^N\s+(IA|E1|E2)?\s*(\d+\.\d+\.\d+\.\d+/\d+)")
_LSID = re.compile(r"Link State ID:\s*(\d+\.\d+\.\d+\.\d+)")
_MASK = re.compile(r"Network Mask:\s*/(\d+)")


def parse_route_kinds(route_text: str, nssa_text: str = "") -> dict[str, str]:
    """ospfd's 'show ip ospf route' (N, N IA, N E1, N E2) and its type 7
    LSAs ('show ip ospf database nssa-external') -> IOS's IA, E1, E2, N1,
    N2 by prefix ("" for intra-area)."""
    nssa: set[str] = set()
    lsid = ""
    for line in (nssa_text or "").splitlines():
        m = _LSID.search(line)
        if m:
            lsid = m.group(1)
            continue
        m = _MASK.search(line)
        if m and lsid:
            nssa.add(str(ipaddress.IPv4Network(f"{lsid}/{m.group(1)}", strict=False)))
            lsid = ""
    out: dict[str, str] = {}
    for line in (route_text or "").splitlines():
        m = _ROUTE.match(line.strip())
        if not m:
            continue
        kind, prefix = m.group(1) or "", m.group(2)
        if kind in ("E1", "E2") and prefix in nssa:
            kind = "N" + kind[1]
        out.setdefault(prefix, kind)
    return out


def route_kinds(con) -> dict[str, str]:
    from .iosrouting import _vtysh
    text = _vtysh(con, "show ip ospf route", "show ip ospf database nssa-external")
    if text.strip().startswith("%"):
        return {}
    head, sep, tail = text.partition("NSSA-external Link States")
    return parse_route_kinds(head, tail if sep else "")
