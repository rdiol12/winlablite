"""IP SLA and object tracking typed at the lab router's console, run by
winlab-slad, winlab's own probe and tracking program (winlab/slad.py).

``ip sla <n>`` with ``icmp-echo <address> [source-interface <if>]``,
``frequency``, ``timeout`` and ``threshold``, started by ``ip sla schedule
<n> life forever start-time now``; ``track <n> ip sla <m> reachability |
state`` with ``delay down <s> up <s>``; and what follows an object: ``ip
route <net> <mask> <next hop> track <n>`` (a static route that is in the
table only while the object is Up, so a floating route behind it takes
over), ``standby <g> track <n> decrement <d>`` (HSRP, read by winlab-hsrpd)
and ``vrrp <g> track <n> decrement <d>`` (VRRP: FRRouting's vrrpd has no
tracking of its own, so winlab-slad lowers the group's priority in vrrpd
while the object is Down).

The console's lines are written to /etc/winlab-sla.conf on the router
under the Linux interfaces' names; winlab-slad, a stdlib Python program
written onto the router as winlab-hsrpd is (Python 3 from the lab's own
Alpine package volume), pings with the system's ping on schedule, keeps
IOS's return codes (OK, Timeout, Over threshold, No connection, Unknown
for an operation that never ran), moves the objects, installs and removes
the tracked routes in the kernel, and writes /run/winlab-sla.json, which
``show ip sla statistics``, ``show ip sla summary`` and ``show track``
read. An operation with no schedule (or ``start-time pending``) never
runs, and an object that follows it stays Down, as on IOS.

Only ``icmp-echo`` operations are here (no udp-jitter, http, dns, path
echo), started now or left pending (not at a clock time), and objects
follow one operation each (no boolean or threshold lists); the console
says so when they are typed.

Settings: ``sla:<n>`` = ``icmp-echo <ip> [source-interface <if> |
source-ip <ip>]``; ``sla-freq:<n>``; ``sla-timeout:<n>``; ``sla-thresh:<n>``;
``sla-sched:<n>`` = what followed ``ip sla schedule <n>``; ``track:<n>`` =
``ip sla <m> reachability | state``; ``track-delay:<n>`` = ``down <s> up
<s>``; ``route-track:<net>/<len> <target>`` = object (beside iosl3's
``route:`` key); ``vrrp-track:<if>:<g>:<object>`` = decrement.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import json
import re
from pathlib import Path

from . import slad

PROGRAM = "/usr/local/sbin/winlab-slad"
CONF = slad.CONF_FILE
STATE = slad.STATE_FILE
PIDFILE = "/run/winlab-slad.pid"
LOG = "/var/log/winlab-sla.log"
MODES = ("config-ip-sla", "config-ip-sla-echo", "config-track")


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def program_source() -> bytes:
    return Path(slad.__file__).read_bytes()


def program_hash() -> str:
    return hashlib.sha256(program_source()).hexdigest()


# ------------------------------------------------------------------ settings
def operations(own: dict) -> list[int]:
    return sorted(int(k[4:]) for k in own if k.startswith("sla:") and k[4:].isdigit())


def objects(own: dict) -> list[int]:
    return sorted(int(k[6:]) for k in own if k.startswith("track:") and k[6:].isdigit())


def scheduled(own: dict, n: int) -> bool:
    return "start-time now" in own.get(f"sla-sched:{n}", "")


def tracked_routes(own: dict) -> dict[str, int]:
    """'<net>/<len> <target>' -> object, for ip route ... track <n>."""
    return {k[12:]: int(v) for k, v in own.items() if k.startswith("route-track:") and str(v).isdigit()}


def vrrp_tracks(own: dict) -> list[tuple[str, int, int, int]]:
    """(interface, group, object, decrement)."""
    out = []
    for k, v in own.items():
        if k.startswith("vrrp-track:"):
            ifname, g, obj = k[11:].rsplit(":", 2)
            out.append((ifname, int(g), int(obj), int(v)))
    return sorted(out)


def active(own: dict) -> bool:
    return bool(operations(own) or objects(own))


# ------------------------------------------------------------------ the program's file
def conf_text(plan) -> str:
    from . import iosl3
    from .iosrouting import svi_map
    own = _own(plan.lab)
    if not active(own):
        return ""
    svis = svi_map(plan.lab, plan)
    out = []
    for n in operations(own):
        out.append(f"ip sla {n}")
        w = own[f"sla:{n}"].split()
        if len(w) >= 2:
            line = f" icmp-echo {w[1]}"
            if len(w) >= 4 and w[2] == "source-interface":
                # A source interface that routes nothing: the probe fails as No connection.
                line += f" source-interface {svis.get(w[3], 'down-' + w[3].replace('/', '_'))}"
            elif len(w) >= 4 and w[2] == "source-ip":
                line += f" source-ip {w[3]}"
            out.append(line)
        for key, word in (("freq", "frequency"), ("timeout", "timeout"), ("thresh", "threshold")):
            if own.get(f"sla-{key}:{n}"):
                out.append(f" {word} {own[f'sla-{key}:{n}']}")
        if scheduled(own, n):
            life = re.search(r"life (\S+)", own[f"sla-sched:{n}"])
            out.append(f"ip sla schedule {n} life {life.group(1) if life else 'forever'} start-time now")
    for n in objects(own):
        out.append(f"track {n} {own[f'track:{n}']}")
        if own.get(f"track-delay:{n}"):
            out.append(f" delay {own[f'track-delay:{n}']}")
    dists = {f"{net} {target}": dist for net, target, dist in iosl3.routes(own)}
    for key, obj in sorted(tracked_routes(own).items()):
        if key not in dists:
            continue
        net, _, target = key.partition(" ")
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            how = f"via {target}"
        elif svis.get(target):
            how = f"dev {svis[target]}"
        else:
            continue
        out.append(f"route {net} {how} metric {dists[key]} track {obj}")
    for ifname, g, obj, dec in vrrp_tracks(own):
        dev = svis.get(ifname)
        if dev and f"vrrp:{ifname}:{g}" in own:
            prio = own.get(f"vrrp-prio:{ifname}:{g}", "100")
            out.append(f"vrrp {dev} {g} priority {prio} track {obj} decrement {dec}")
    return "\n".join(out) + "\n"


def _program_lines() -> list[str]:
    blob = base64.b64encode(gzip.compress(program_source(), mtime=0)).decode()
    wrapped = "\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
    return [f"mkdir -p {PROGRAM.rsplit('/', 1)[0]}",
            f"base64 -d > {PROGRAM}.gz <<'WLSLAD'\n{wrapped}\nWLSLAD",
            f"gunzip -c {PROGRAM}.gz > {PROGRAM} && chmod 755 {PROGRAM}; rm -f {PROGRAM}.gz"]


def router_lines(plan, runner=None) -> list[str]:
    """Python 3 and the program installed, its file written, and the
    program started, told to read it again, or stopped."""
    from .ioshsrp import INSTALL
    conf = conf_text(plan)
    stop = (f"p=$(cat {PIDFILE} 2>/dev/null); [ -n \"$p\" ] && kill \"$p\" 2>/dev/null; "
            f"rm -f {PIDFILE} {CONF} {STATE}")
    if not conf:
        return ["# IP SLA: no operation and no track object", stop] if runner is not None else []
    send = True
    if runner is not None:
        try:
            have = runner(f"sha256sum {PROGRAM} 2>/dev/null", timeout=15) or ""
        except Exception:  # noqa: BLE001 - send it, then
            have = ""
        send = program_hash() not in have
    out = ["# IP SLA and tracking: winlab's own winlab-slad (winlab/slad.py), on the console's lines", INSTALL]
    if send:
        out += [f"if [ \"$(sha256sum {PROGRAM} 2>/dev/null | cut -c1-64)\" != {program_hash()} ]; then"]
        out += _program_lines() + ["fi"]
    out += [f"cat > {CONF} <<'WLSLA'\n{conf}WLSLA",
            f"p=$(cat {PIDFILE} 2>/dev/null)",
            f"if [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null; then kill -HUP \"$p\"; "
            f"else setsid python3 {PROGRAM} -c {CONF} </dev/null >>{LOG} 2>&1 & echo $! > {PIDFILE}; fi"]
    return out


# ------------------------------------------------------------------ show running-config
def run_lines(own: dict) -> list[str]:
    out = []
    for n in objects(own):
        out.append(f"track {n} {own[f'track:{n}']}")
        if own.get(f"track-delay:{n}"):
            out.append(f" delay {own[f'track-delay:{n}']}")
        out.append("!")
    for n in operations(own):
        out.append(f"ip sla {n}")
        out.append(f" {own[f'sla:{n}']}")
        for key, word in (("freq", "frequency"), ("timeout", "timeout"), ("thresh", "threshold")):
            if own.get(f"sla-{key}:{n}"):
                out.append(f" {word} {own[f'sla-{key}:{n}']}")
        if f"sla-sched:{n}" in own:
            out.append(f"ip sla schedule {n}" + (f" {own[f'sla-sched:{n}']}" if own[f"sla-sched:{n}"] else ""))
    return out + (["!"] if operations(own) else [])


def route_suffix(own: dict, net, target: str) -> str:
    obj = tracked_routes(own).get(f"{net} {target}")
    return f" track {obj}" if obj else ""


def vrrp_lines(own: dict, ifname: str, g: int) -> list[str]:
    return [f" vrrp {g} track {obj} decrement {dec}" for i, gg, obj, dec in vrrp_tracks(own)
            if i == ifname and gg == g]


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, E, C, IF) -> None:
    from . import devcli
    for k, v in {("ip", "sla"): "IP Service Level Agreement", ("track",): "Object tracking configuration commands",
                 ("show", "ip", "sla"): "IP Service Level Agreement", ("show", "track"): "Tracking information",
                 ("icmp-echo",): "ICMP Echo Operation", ("frequency",): "Frequency of an operation",
                 ("threshold",): "Operation threshold in milliseconds"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    S, SE, T = ("config-ip-sla",), ("config-ip-sla-echo",), ("config-track",)
    add("end", con._end, "Exit from configure mode", MODES)
    add("exit", lambda a: _exit(con), "Exit from this submode", MODES)
    add("do <line>", con._do, "To run exec commands in config mode", MODES)
    add("ip sla <num>", lambda a: sla(con, a[0]), "Entry Number", C + MODES)
    add("no ip sla <num>", lambda a: no_sla(con, a[0]), "Negate a command or set its defaults", C + MODES)
    add("ip sla schedule <num> <line>", lambda a: schedule(con, a[0], a[1]), "Schedule an IP SLAs operation", C + MODES)
    add("ip sla schedule <num>", lambda a: schedule(con, a[0], ""), "Schedule an IP SLAs operation", C + MODES)
    add("no ip sla schedule <num>", lambda a: no_schedule(con, a[0]), "Negate a command or set its defaults", C + MODES)
    add("icmp-echo <ip>", lambda a: echo(con, a[0], ""), "ICMP Echo Operation", S + SE)
    add("icmp-echo <ip> <line>", lambda a: echo(con, a[0], a[1]), "ICMP Echo Operation", S + SE)
    for op in ("udp-jitter", "http", "dns", "udp-echo", "tcp-connect", "path-echo", "path-jitter"):
        add(f"{op} <line>", lambda a, op=op: _not_here(op), "IP SLA operation", S)
    add("frequency <num>", lambda a: opt(con, "freq", a[0], 1, 604800), "Frequency of an operation", SE)
    add("no frequency", lambda a: opt(con, "freq", "", 0, 0), "Negate a command or set its defaults", SE)
    add("timeout <num>", lambda a: opt(con, "timeout", a[0], 0, 604800000), "Timeout of an operation", SE)
    add("no timeout", lambda a: opt(con, "timeout", "", 0, 0), "Negate a command or set its defaults", SE)
    add("threshold <num>", lambda a: opt(con, "thresh", a[0], 0, 2147483647), "Operation threshold in milliseconds", SE)
    add("no threshold", lambda a: opt(con, "thresh", "", 0, 0), "Negate a command or set its defaults", SE)
    add("track <num> ip sla <num>", lambda a: track(con, a[0], a[1], "state"), "IP SLA state", C + MODES)
    add("track <num> ip sla <num> <line>", lambda a: track(con, a[0], a[1], a[2]), "IP SLA state or reachability", C + MODES)
    add("track <num> interface <line>", lambda a: _track_iface(), "Select interface to track", C + MODES)
    add("track <num> list <line>", lambda a: _not_here("track list"), "Group objects in a list", C + MODES)
    add("no track <num>", lambda a: no_track(con, a[0]), "Negate a command or set its defaults", C + MODES)
    add("delay <line>", lambda a: delay(con, a[0]), "Tracking delay", T)
    add("no delay", lambda a: delay(con, ""), "Negate a command or set its defaults", T)
    add("show ip sla statistics", lambda a: show_stats(con, ""), "IP SLA statistics", U)
    add("show ip sla statistics <num>", lambda a: show_stats(con, a[0]), "IP SLA statistics", U)
    add("show ip sla summary", lambda a: show_summary(con), "IP SLA summary", U)
    add("show ip sla configuration", lambda a: show_config(con, ""), "IP SLA configuration", U)
    add("show ip sla configuration <num>", lambda a: show_config(con, a[0]), "IP SLA configuration", U)
    add("show track", lambda a: show_track(con, ""), "Tracking information", U)
    add("show track brief", lambda a: show_track(con, "", brief=True), "Brief tracking information", U)
    add("show track <num>", lambda a: show_track(con, a[0]), "Tracked object", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _num(text: str, lo: int, hi: int) -> int:
    if not text.isdigit() or not lo <= int(text) <= hi:
        raise _bad()
    return int(text)


def _not_here(what: str) -> str:
    return (f"% {what} is not in this router: winlab-slad runs icmp-echo operations only, and a track object "
            f"follows one of them (track <n> ip sla <m> reachability)")


def _track_iface() -> str:
    return ("% track <n> interface is not in this router: track the interface itself where it matters "
            "(standby <g> track <interface>), or an IP SLA operation (track <n> ip sla <m> reachability)")


def _exit(con) -> str:
    con.s.mode, con.s.ctx = "config", ""
    return ""


def sla(con, n_text: str) -> str:
    n = _num(n_text, 1, 2147483647)
    own = _own_c(con)
    con.s.ctx = str(n)
    if f"sla:{n}" in own:
        if scheduled(own, n):
            con.s.mode = "config"
            con.s.ctx = ""
            raise _err("%Entry already running and cannot be modified (only can delete (no) and start over)\n"
                       "%(check to see if the probe has finished exiting)")
        con.s.mode = "config-ip-sla-echo"
    else:
        con.s.mode = "config-ip-sla"
    return ""


def no_sla(con, n_text: str) -> str:
    n = _num(n_text, 1, 2147483647)
    own = _own_c(con)
    for k in [k for k in own if k in (f"sla:{n}", f"sla-freq:{n}", f"sla-timeout:{n}", f"sla-thresh:{n}",
                                      f"sla-sched:{n}")]:
        del own[k]
    return _done(con)


def echo(con, ip: str, rest: str) -> str:
    from . import devcli
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ValueError:
        raise _bad() from None
    own = _own_c(con)
    n = con.s.ctx
    w = rest.split()
    line = f"icmp-echo {ip}"
    if w:
        if len(w) != 2:
            raise _bad()
        word = w[0].lower()
        if word.startswith("source-in") and "source-interface".startswith(word):
            line += f" source-interface {devcli.parse_if(w[1], con._if_names(), sub=True)}"
        elif word == "source-ip":
            try:
                line += f" source-ip {ipaddress.IPv4Address(w[1])}"
            except ValueError:
                raise _bad() from None
        else:
            raise _bad()
    have = own.get(f"sla:{n}")
    if have and have.split()[:2] != line.split()[:2] and con.s.mode == "config-ip-sla-echo":
        raise _err("%Entry already has an operation type: no ip sla <n> to change it")
    own[f"sla:{n}"] = line
    con.s.mode = "config-ip-sla-echo"
    return _done(con)


def opt(con, key: str, value: str, lo: int, hi: int) -> str:
    own = _own_c(con)
    n = con.s.ctx
    if value:
        v = _num(value, lo, hi)
        own[f"sla-{key}:{n}"] = str(v)
    else:
        own.pop(f"sla-{key}:{n}", None)
    note = _done(con)
    t = int(own.get(f"sla-timeout:{n}", slad.TIMEOUT))
    f = int(own.get(f"sla-freq:{n}", slad.FREQUENCY))
    if t > f * 1000:
        note = "\n".join(x for x in ("%Timeout is greater than the frequency: the operation keeps the frequency",
                                     note) if x)
    return note


def schedule(con, n_text: str, rest: str) -> str:
    n = _num(n_text, 1, 2147483647)
    own = _own_c(con)
    if f"sla:{n}" not in own:
        raise _err(f"%No such operation: ip sla {n} first")
    w = rest.lower().split()
    life, start, i = "3600", "pending", 0
    while i < len(w):
        if w[i] == "life" and i + 1 < len(w):
            if w[i + 1] != "forever" and not w[i + 1].isdigit():
                raise _bad()
            life, i = w[i + 1], i + 2
        elif w[i] == "start-time" and i + 1 < len(w):
            if w[i + 1] in ("now", "pending"):
                start, i = w[i + 1], i + 2
            else:
                return ("% This router starts an operation now or leaves it pending (start-time now | pending); "
                        "a clock time or after <hh:mm:ss> is not here")
        elif w[i] in ("ageout", "recurring"):
            i += 2 if w[i] == "ageout" else 1
        else:
            raise _bad()
    if scheduled(own, n):
        raise _err(f"%Entry {n} is already scheduled: no ip sla schedule {n} first")
    words = []
    if life != "3600":
        words.append(f"life {life}")
    if start != "pending":
        words.append(f"start-time {start}")
    own[f"sla-sched:{n}"] = " ".join(words)
    note = _done(con)
    if start == "pending":
        note = "\n".join(x for x in (f"% Operation {n} is pending: it does not run until start-time now", note) if x)
    return note


def no_schedule(con, n_text: str) -> str:
    n = _num(n_text, 1, 2147483647)
    _own_c(con).pop(f"sla-sched:{n}", None)
    return _done(con)


def track(con, n_text: str, op_text: str, kind: str) -> str:
    n = _num(n_text, 1, 1000)
    op = _num(op_text, 1, 2147483647)
    kind = kind.strip().lower()
    hit = [k for k in ("state", "reachability") if k.startswith(kind)] if kind else ["state"]
    if len(hit) != 1:
        raise _bad()
    own = _own_c(con)
    have = own.get(f"track:{n}")
    if have and have != f"ip sla {op} {hit[0]}" and have.split()[:3] != ["ip", "sla", str(op)]:
        raise _err(f"%Track object {n} already tracks {have}: no track {n} first")
    own[f"track:{n}"] = f"ip sla {op} {hit[0]}"
    con.s.mode, con.s.ctx = "config-track", str(n)
    return _done(con)


def no_track(con, n_text: str) -> str:
    n = _num(n_text, 1, 1000)
    own = _own_c(con)
    own.pop(f"track:{n}", None)
    own.pop(f"track-delay:{n}", None)
    return _done(con)


def delay(con, text: str) -> str:
    own = _own_c(con)
    n = con.s.ctx
    if not text:
        own.pop(f"track-delay:{n}", None)
        return _done(con)
    w = text.lower().split()
    vals: dict[str, int] = {}
    i = 0
    while i < len(w):
        if w[i] in ("up", "down") and i + 1 < len(w) and w[i + 1].isdigit() and int(w[i + 1]) <= 180:
            vals[w[i]] = int(w[i + 1])
            i += 2
        else:
            raise _bad()
    if not vals:
        raise _err("% Incomplete command.")
    own[f"track-delay:{n}"] = " ".join(f"{k} {vals[k]}" for k in ("down", "up") if k in vals)
    return _done(con)


# ---- what other commands call
def route_track(own: dict, net, target: str, obj: int | None) -> None:
    """Called by ip route (winlab/iosl3.py): keeps or drops the object a
    static route follows."""
    key = f"route-track:{net} {target}"
    if obj:
        own[key] = str(obj)
    else:
        own.pop(key, None)


def hidden_routes(con) -> set[str]:
    """'<net>/<len> <target>' of the tracked routes that are out of the
    table now: their object is Down, or winlab-slad is not running."""
    own = _own(con.lab)
    want = tracked_routes(own)
    if not want:
        return set()
    st = read_state(con)
    objs = st.get("track", {})
    return {k for k, obj in want.items() if objs.get(str(obj), {}).get("state") != "Up"}


# ------------------------------------------------------------------ show
def read_state(con) -> dict:
    if not con.powered():
        return {}
    try:
        text = con._on_router(f"cat {STATE} 2>/dev/null", timeout=10) or ""
        return json.loads(text) if text.strip().startswith("{") else {}
    except Exception:  # noqa: BLE001 - nothing known: every object Down, every operation Unknown
        return {}


def _code(st: dict, n: int) -> dict:
    return st.get("sla", {}).get(str(n), {})


def show_stats(con, only: str) -> str:
    own = _own(con.lab)
    st = read_state(con)
    out = ["IPSLAs Latest Operation Statistics", ""]
    for n in operations(own):
        if only and str(n) != only:
            continue
        s = _code(st, n)
        ran = s.get("ok", 0) + s.get("fail", 0)
        out.append(f"IPSLA operation id: {n}")
        if not scheduled(own, n) or not ran:
            out += ["        Number of successes: Unknown", "        Number of failures: Unknown",
                    "        Operation time to live: 0" if not scheduled(own, n) else
                    "        Operation time to live: Forever", ""]
            continue
        out += [f"        Latest RTT: {int(s.get('rtt', 0)) if s.get('code') in ('OK', 'Over threshold') else 'NoConnection/Busy/Timeout'}"
                + (" milliseconds" if s.get("code") in ("OK", "Over threshold") else ""),
                f"Latest operation start time: {s.get('ago', 0):g} seconds ago",
                f"Latest operation return code: {s.get('code', 'Unknown')}",
                f"Number of successes: {s.get('ok', 0)}",
                f"Number of failures: {s.get('fail', 0)}",
                "Operation time to live: Forever" if "forever" in own.get(f"sla-sched:{n}", "")
                else "Operation time to live: (life in seconds from its start)", ""]
    return "\n".join(out).rstrip()


def show_summary(con) -> str:
    own = _own(con.lab)
    st = read_state(con)
    out = ["IPSLAs Latest Operation Summary", "Codes: * active, ^ inactive, ~ pending", "",
           f"{'ID':<11}{'Type':<12}{'Destination':<16}{'Stats':<9}{'Return':<15}Last",
           f"{'':<11}{'':<12}{'':<16}{'(ms)':<9}{'Code':<15}Run",
           "-" * 72]
    for n in operations(own):
        s = _code(st, n)
        w = own[f"sla:{n}"].split()
        mark = "*" if scheduled(own, n) else "~"
        rtt = str(int(s.get("rtt", 0))) if s.get("code") in ("OK", "Over threshold") else "-"
        last = f"{s.get('ago', 0):g} seconds ago" if s.get("ago", -1) >= 0 and scheduled(own, n) else "-"
        out.append(f"{mark}{n:<10}{w[0]:<12}{w[1] if len(w) > 1 else '-':<16}{rtt:<9}"
                   f"{(s.get('code') or 'Unknown') if scheduled(own, n) else 'Unknown':<15}{last}")
    return "\n".join(out)


def show_config(con, only: str) -> str:
    own = _own(con.lab)
    out = []
    for n in operations(own):
        if only and str(n) != only:
            continue
        w = own[f"sla:{n}"].split()
        src = w[3] if len(w) >= 4 else "0.0.0.0"
        sched = own.get(f"sla-sched:{n}")
        out += ["IP SLAs Infrastructure Engine-III", f"Entry number: {n}", "Type of operation to perform: icmp-echo",
                f"Target address/Source address: {w[1]}/{src}",
                f"Operation timeout (milliseconds): {own.get(f'sla-timeout:{n}', slad.TIMEOUT)}",
                "Schedule:",
                f"   Operation frequency (seconds): {own.get(f'sla-freq:{n}', slad.FREQUENCY)}",
                "   Next Scheduled Start Time: " + ("Start Time already passed" if scheduled(own, n)
                                                    else "Pending trigger"),
                "   Life (seconds): " + ("Forever" if sched and "forever" in sched
                                         else re.search(r"life (\d+)", sched).group(1)
                                         if sched and re.search(r"life (\d+)", sched) else "3600"),
                f"Threshold (milliseconds): {own.get(f'sla-thresh:{n}', slad.THRESHOLD)}", ""]
    return "\n".join(out).rstrip()


def show_track(con, only: str, brief: bool = False) -> str:
    from . import ioshsrp
    own = _own(con.lab)
    st = read_state(con)
    objs = st.get("track", {})
    if brief:
        out = [f"{'Track':<6}{'Type':<12}{'Instance':<18}{'Parameter':<16}{'State':<6}Last Change"]
        for n in objects(own):
            w = own[f"track:{n}"].split()
            o = objs.get(str(n), {})
            out.append(f"{n:<6}{'ip sla':<12}{w[2]:<18}{w[3]:<16}{o.get('state', 'Down'):<6}"
                       f"{_hms(o.get('since', 0))}")
        return "\n".join(out)
    out = []
    for n in objects(own):
        if only and str(n) != only:
            continue
        w = own[f"track:{n}"].split()
        o = objs.get(str(n), {})
        state = o.get("state", "Down")
        word = "Reachability" if w[3] == "reachability" else "State"
        out += [f"Track {n}", f"  IP SLA {w[2]} {w[3]}", f"  {word} is {state}",
                f"    {o.get('changes', 0)} change{'s' if o.get('changes', 0) != 1 else ''}, "
                f"last change {_hms(o.get('since', 0))}",
                f"  Latest operation return code: {o.get('code', 'Unknown')}"]
        s = _code(st, int(w[2]))
        if s.get("code") in ("OK", "Over threshold"):
            out.append(f"  Latest RTT (millisecs) {int(s.get('rtt', 0))}")
        if own.get(f"track-delay:{n}"):
            out.append(f"  Delay {own[f'track-delay:{n}']}")
        users = ["    STATIC-IP-ROUTING" for k, v in tracked_routes(own).items() if v == n][:1]
        for ifname, g, _ in ioshsrp.groups(own):
            if any(obj == n for obj, _ in ioshsrp.track_objs(own, ifname, g)):
                users.append(f"    HSRP {ifname} {g}")
        users += [f"    VRRP {i} {g}" for i, g, obj, _ in vrrp_tracks(own) if obj == n]
        if users:
            out += ["  Tracked by:"] + users
        if not st:
            out.append("  (winlab-slad is not running on the router: the object counts as Down)")
        out.append("")
    return "\n".join(out).rstrip()


def _hms(sec: float) -> str:
    s = int(sec or 0)
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"
