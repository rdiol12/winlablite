"""HSRP typed at the lab router's console (``standby``), spoken on the wire by
winlab-hsrpd, winlab's own HSRP speaker (winlab/hsrpd.py).

No open-source router speaks HSRP, so winlab wrote a small speaker of its own
from the published formats (RFC 2281 for version 1, Cisco's version 2 TLV
layout): real HSRP hellos, coups and resigns on UDP 1985 to 224.0.0.2 (v1) or
224.0.0.102 (v2), the six states, the virtual MAC 0000.0c07.acXX (v1) or
0000.0c9f.fXXX (v2) on a macvlan that holds the virtual address while this
router is Active (as FRRouting's vrrpd does for VRRP), gratuitous ARP when it
becomes Active. The console's ``standby`` lines are written to
/etc/winlab-hsrp.conf on the router in IOS's own words (under the Linux
interface's name) and the speaker reads them: started the first time a group
is configured, told to read the file again (SIGHUP) on every change, stopped
(it resigns first) when the last group goes. It runs on Python 3, which the
router installs from the lab's own Alpine package volume the first time
(alpineovl.APPLIANCE_PACKAGES), never from the Internet; the speaker itself
is winlab's code, written onto the router by the start script.

The other HSRP router in the lab is rtr-edge (Ubuntu): the same speaker, from
the frr pack's stick (winlab/debpacks.py puts it beside the packages), with a
configuration file the student writes in the same IOS lines. On real gear
both ends are Cisco IOS routers; here both ends run winlab's speaker, which
is the honest limit of a Linux lab: it interoperates with itself, and its
packets follow the published layout byte for byte (tests/test_winlab.py), but
it was not tried against a Cisco router.

Tracking: ``standby <g> track <interface> [decrement <n>]`` follows the
interface's link; ``standby <g> track <object> [decrement <n>]`` follows a
track object of IP SLA (``track <n> ip sla <m> reachability``,
winlab/iossla.py), which winlab-slad keeps and winlab-hsrpd reads.

What it does not do, and what the console says: MD5 authentication
(``standby <g> authentication md5`` is refused), ``timers msec``, ``use-bia``, ``follow``,
``mac-address``, ``redirect``, HSRP for IPv6. A group's virtual address may
not be the interface's own address nor another group's (VRRP's included).

``show standby`` and ``show standby brief`` read the speaker's state file
(/run/winlab-hsrp.json), so what they print is what the router is doing; when
the speaker is not running they print the configured groups in Init.

Settings (``<if>`` an IOS interface, ``<g>`` a group): ``hsrp-ver:<if>`` = 2
(absent: version 1); ``hsrp:<if>:<g>`` = virtual address ("" to learn it
from the Active router); ``hsrp-sec:<if>:<g>`` = secondary addresses;
``hsrp-prio:<if>:<g>``; ``hsrp-pre:<if>:<g>`` = preempt delay in seconds
("0": preempt with no delay); ``hsrp-timers:<if>:<g>`` = "hello hold";
``hsrp-auth:<if>:<g>`` = the text; ``hsrp-track:<if>:<g>:<tracked if>`` =
decrement; ``hsrp-trackobj:<if>:<g>:<object>`` = decrement; ``hsrp-name:<if>:<g>``.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import json
import re
from pathlib import Path

from . import hsrpd

SPEAKER = "/usr/local/sbin/winlab-hsrpd"
CONF = hsrpd.CONF_FILE
STATE = hsrpd.STATE_FILE
PIDFILE = "/run/winlab-hsrpd.pid"
LOG = "/var/log/winlab-hsrp.log"
INSTALL = ("command -v python3 >/dev/null 2>&1 || apk add --no-network python3 >/dev/null 2>&1 || "
           "echo 'winlab: Python 3 is not on the package volume (winlab images prepare fabric)' > /dev/kmsg")
NOT_HERE = "% standby {what} is not in this router (winlab-hsrpd): {why}"


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def speaker_source() -> bytes:
    return Path(hsrpd.__file__).read_bytes()


def speaker_hash() -> str:
    return hashlib.sha256(speaker_source()).hexdigest()


# ------------------------------------------------------------------ settings
def groups(own: dict, ifname: str = "") -> list[tuple[str, int, str]]:
    """(interface, group, virtual address or "")."""
    out = []
    for k, v in own.items():
        if k.startswith("hsrp:"):
            name, _, g = k[5:].rpartition(":")
            if (not ifname or name == ifname) and g.isdigit():
                out.append((name, int(g), v))
    return sorted(out)


def version(own: dict, ifname: str) -> int:
    return int(own.get(f"hsrp-ver:{ifname}", "1"))


def tracks(own: dict, ifname: str, g: int) -> list[tuple[str, int]]:
    pre = f"hsrp-track:{ifname}:{g}:"
    return sorted((k[len(pre):], int(v)) for k, v in own.items() if k.startswith(pre))


def track_objs(own: dict, ifname: str, g: int) -> list[tuple[int, int]]:
    pre = f"hsrp-trackobj:{ifname}:{g}:"
    return sorted((int(k[len(pre):]), int(v)) for k, v in own.items() if k.startswith(pre))


def active(own: dict) -> bool:
    return any(k.startswith("hsrp:") for k in own)


# ------------------------------------------------------------------ the speaker's file
def conf_text(plan) -> str:
    """/etc/winlab-hsrp.conf: the console's standby lines under the router's
    Linux interfaces; "" when no group is up."""
    from .iosrouting import svi_map
    own = _own(plan.lab)
    svis = svi_map(plan.lab, plan)
    out = []
    for ifname in sorted({i for i, _, _ in groups(own)}):
        dev = svis.get(ifname)
        if not dev:
            continue
        out += [f"! {ifname}", f"interface {dev}", f" standby version {version(own, ifname)}"]
        for _, g, vip in groups(own, ifname):
            key = f"{ifname}:{g}"
            out.append(f" standby {g} ip" + (f" {vip}" if vip else ""))
            out += [f" standby {g} ip {s} secondary" for s in own.get(f"hsrp-sec:{key}", "").split()]
            if own.get(f"hsrp-prio:{key}"):
                out.append(f" standby {g} priority {own[f'hsrp-prio:{key}']}")
            if f"hsrp-pre:{key}" in own:
                d = own[f"hsrp-pre:{key}"]
                out.append(f" standby {g} preempt" + (f" delay minimum {d}" if d not in ("", "0") else ""))
            if own.get(f"hsrp-timers:{key}"):
                out.append(f" standby {g} timers {own[f'hsrp-timers:{key}']}")
            if own.get(f"hsrp-auth:{key}"):
                out.append(f" standby {g} authentication {own[f'hsrp-auth:{key}']}")
            for t, dec in tracks(own, ifname, g):
                # A tracked interface that routes nothing has no device: it is down.
                out.append(f" standby {g} track {svis.get(t) or 'down:' + t.replace('/', '_')} decrement {dec}")
            for obj, dec in track_objs(own, ifname, g):
                out.append(f" standby {g} track object {obj} decrement {dec}")
            if own.get(f"hsrp-name:{key}"):
                out.append(f" standby {g} name {own[f'hsrp-name:{key}']}")
    return "\n".join(out) + "\n" if out else ""


def _speaker_lines() -> list[str]:
    blob = base64.b64encode(gzip.compress(speaker_source(), mtime=0)).decode()
    wrapped = "\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
    return [f"mkdir -p {SPEAKER.rsplit('/', 1)[0]}",
            f"base64 -d > {SPEAKER}.gz <<'WLHSRPD'\n{wrapped}\nWLHSRPD",
            f"gunzip -c {SPEAKER}.gz > {SPEAKER} && chmod 755 {SPEAKER}; rm -f {SPEAKER}.gz"]


def router_lines(plan, runner=None) -> list[str]:
    """The router's part: Python 3 and the speaker installed, its file
    written, and the speaker started, told to read it again, or stopped.
    With a runner (a running router), the speaker is sent only when the
    router's copy is not this one."""
    own = _own(plan.lab)
    conf = conf_text(plan)
    stop = (f"p=$(cat {PIDFILE} 2>/dev/null); [ -n \"$p\" ] && kill \"$p\" 2>/dev/null; "
            f"rm -f {PIDFILE} {CONF}")
    if not conf:
        return ["# HSRP: no standby group up", stop] if active(own) or runner is not None else []
    send = True
    if runner is not None:
        try:
            have = runner(f"sha256sum {SPEAKER} 2>/dev/null", timeout=15) or ""
        except Exception:  # noqa: BLE001 - send it, then
            have = ""
        send = speaker_hash() not in have
    out = ["# HSRP: winlab's own speaker, winlab-hsrpd (winlab/hsrpd.py), on the console's standby lines", INSTALL]
    if send:
        out += [f"if [ \"$(sha256sum {SPEAKER} 2>/dev/null | cut -c1-64)\" != {speaker_hash()} ]; then"]
        out += _speaker_lines() + ["fi"]
    out += [f"cat > {CONF} <<'WLHSRP'\n{conf}WLHSRP",
            f"p=$(cat {PIDFILE} 2>/dev/null)",
            f"if [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null; then kill -HUP \"$p\"; "
            f"else setsid python3 {SPEAKER} -c {CONF} -l {LOG} </dev/null >/dev/null 2>&1 & echo $! > {PIDFILE}; fi"]
    return out


# ------------------------------------------------------------------ show running-config
def iface_lines(own: dict, ifname: str) -> list[str]:
    gs = groups(own, ifname)
    if not gs:
        return []
    out = [" standby version 2"] if version(own, ifname) == 2 else []
    for _, g, vip in gs:
        key = f"{ifname}:{g}"
        lead = f" standby {g}" if g or version(own, ifname) == 2 else " standby"
        out.append(f"{lead} ip" + (f" {vip}" if vip else ""))
        out += [f"{lead} ip {s} secondary" for s in own.get(f"hsrp-sec:{key}", "").split()]
        if own.get(f"hsrp-timers:{key}"):
            out.append(f"{lead} timers {own[f'hsrp-timers:{key}']}")
        if own.get(f"hsrp-prio:{key}"):
            out.append(f"{lead} priority {own[f'hsrp-prio:{key}']}")
        if f"hsrp-pre:{key}" in own:
            d = own[f"hsrp-pre:{key}"]
            out.append(f"{lead} preempt" + (f" delay minimum {d}" if d not in ("", "0") else ""))
        if own.get(f"hsrp-auth:{key}"):
            out.append(f"{lead} authentication {own[f'hsrp-auth:{key}']}")
        if own.get(f"hsrp-name:{key}"):
            out.append(f"{lead} name {own[f'hsrp-name:{key}']}")
        for t, dec in tracks(own, ifname, g):
            out.append(f"{lead} track {t}" + (f" decrement {dec}" if dec != hsrpd.DECREMENT else ""))
        for obj, dec in track_objs(own, ifname, g):
            out.append(f"{lead} track {obj}" + (f" decrement {dec}" if dec != hsrpd.DECREMENT else ""))
    return out


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, IF) -> None:
    from . import devcli
    devcli.WORD_HELP.setdefault(("show", "standby"), "Hot standby protocol information")
    add("standby <line>", lambda a: standby(con, a[0], True), "HSRP interface configuration commands", IF)
    add("no standby <line>", lambda a: standby(con, a[0], False), "Negate a command or set its defaults", IF)
    add("show standby", lambda a: show(con, False), "Hot standby protocol information", U)
    add("show standby brief", lambda a: show(con, True), "Brief output", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def standby(con, rest: str, on: bool) -> str:
    from . import devcli
    own = _own_c(con)
    ifname = con.s.ctx
    w = rest.split()
    if not w:
        raise _err("% Incomplete command.")
    if w[0] == "version":
        if not on:
            return _set_version(con, own, ifname, 1)
        if len(w) != 2 or w[1] not in ("1", "2"):
            raise _bad()
        return _set_version(con, own, ifname, int(w[1]))
    ver = version(own, ifname)
    g = 0
    if w[0].isdigit():
        g = int(w[0])
        w = w[1:]
        if g > (4095 if ver == 2 else 255):
            raise _err(f"% Group number {g} is out of range for version {ver} (0-{4095 if ver == 2 else 255})"
                       + ("; standby version 2 takes up to 4095" if ver == 1 else ""))
    key = f"{ifname}:{g}"
    if not w:
        if on:
            raise _err("% Incomplete command.")
        for k in [k for k in own if k.startswith("hsrp") and (k.endswith(f":{key}") or k.startswith(
                (f"hsrp-track:{key}:", f"hsrp-trackobj:{key}:")))]:
            del own[k]
        return _done(con)
    word = w[0].lower()
    opts = ("ip", "priority", "preempt", "timers", "authentication", "track", "name", "use-bia", "follow",
            "mac-address", "redirect", "bfd", "delay")
    hit = [o for o in opts if o.startswith(word)]
    if len(hit) != 1:
        raise _bad()
    what, args = hit[0], w[1:]
    if what in ("use-bia", "follow", "mac-address", "redirect", "bfd", "delay"):
        return NOT_HERE.format(what=what, why="the speaker sends the protocol's own virtual MAC and plain "
                                              "hellos, nothing more")
    grp = f"hsrp:{key}"
    if what == "ip":
        if not on:
            if args[1:2] == ["secondary"]:
                sec = [s for s in own.get(f"hsrp-sec:{key}", "").split() if s != args[0]]
                _put(own, f"hsrp-sec:{key}", " ".join(sec))
            else:
                for k in [k for k in own if k.startswith("hsrp") and (k.endswith(f":{key}") or k.startswith(
                        (f"hsrp-track:{key}:", f"hsrp-trackobj:{key}:")))]:
                    del own[k]
            return _done(con)
        if not args:
            own[grp] = own.get(grp, "")
            return _done(con)
        vip = _vip(con, own, ifname, args[0], key)
        if args[1:2] == ["secondary"]:
            if not own.get(grp):
                raise _err(f"% Group {g} has no primary virtual address yet: standby {g} ip <address> first")
            sec = own.get(f"hsrp-sec:{key}", "").split()
            if vip not in sec:
                sec.append(vip)
            own[f"hsrp-sec:{key}"] = " ".join(sec)
        elif args[1:]:
            raise _bad()
        else:
            own[grp] = vip
    elif what == "priority":
        if on:
            if len(args) != 1 or not args[0].isdigit() or int(args[0]) > 255:
                raise _bad()
            _put(own, f"hsrp-prio:{key}", "" if int(args[0]) == hsrpd.PRIORITY else str(int(args[0])))
        else:
            own.pop(f"hsrp-prio:{key}", None)
    elif what == "preempt":
        if on:
            d = "0"
            if args:
                if len(args) == 3 and "delay".startswith(args[0]) and "minimum".startswith(args[1]) \
                        and args[2].isdigit() and int(args[2]) <= 3600:
                    d = str(int(args[2]))
                elif args and "delay".startswith(args[0]) and len(args) >= 2 and args[1] in ("reload", "sync"):
                    return NOT_HERE.format(what=f"preempt delay {args[1]}", why="only delay minimum is taken")
                else:
                    raise _bad()
            own[f"hsrp-pre:{key}"] = d
        else:
            own.pop(f"hsrp-pre:{key}", None)
    elif what == "timers":
        if on:
            if "msec" in args:
                return NOT_HERE.format(what="timers msec", why="hello and hold are whole seconds here")
            if len(args) != 2 or not all(a.isdigit() for a in args):
                raise _bad()
            hello, hold = int(args[0]), int(args[1])
            if not (1 <= hello <= 254 and 2 <= hold <= 255):
                raise _bad()
            if hold <= hello:
                raise _err("% Hold time must be greater than hello time")
            _put(own, f"hsrp-timers:{key}", "" if (hello, hold) == (hsrpd.HELLO, hsrpd.HOLD) else f"{hello} {hold}")
        else:
            own.pop(f"hsrp-timers:{key}", None)
    elif what == "authentication":
        if on:
            if args[:1] == ["md5"]:
                return NOT_HERE.format(what="authentication md5", why="the speaker takes plain-text "
                                                                       "authentication only")
            text = args[1] if args[:1] == ["text"] and len(args) == 2 else args[0] if len(args) == 1 else ""
            if not text or len(text) > 8 or not re.match(r"^[\x21-\x7e]+$", text):
                raise _err("% The authentication text is 1 to 8 characters, no spaces")
            own[f"hsrp-auth:{key}"] = text
        else:
            own.pop(f"hsrp-auth:{key}", None)
    elif what == "track":
        if not args:
            raise _err("% Incomplete command.")
        if args[0].isdigit():
            obj = int(args[0])
            if not 1 <= obj <= 1000:
                raise _bad()
            rest_t = args[1:]
            dec = hsrpd.DECREMENT
            if on and rest_t:
                if len(rest_t) != 2 or not "decrement".startswith(rest_t[0]) or not rest_t[1].isdigit() \
                        or not 1 <= int(rest_t[1]) <= 255:
                    raise _bad()
                dec = int(rest_t[1])
            if not on:
                own.pop(f"hsrp-trackobj:{key}:{obj}", None)
                return _done(con)
            own[f"hsrp-trackobj:{key}:{obj}"] = str(dec)
            own.setdefault(grp, "")
            done = _done(con)
            if f"track:{obj}" in own:
                return done
            return "\n".join(x for x in (f"% Track object {obj} does not exist yet: until track {obj} ... is "
                                         f"configured it counts as Down", done) if x)
        rest_t = args[1:]
        name = args[0]
        if rest_t and not rest_t[0].startswith(("d", "s")):
            name = f"{args[0]}{args[1]}"
            rest_t = args[2:]
        tracked = devcli.parse_if(name, con._if_names(), sub=True)
        if tracked == ifname:
            raise _err("% An interface cannot track itself: its own state already decides the group")
        if on:
            dec = hsrpd.DECREMENT
            if rest_t:
                if len(rest_t) != 2 or not "decrement".startswith(rest_t[0]) or not rest_t[1].isdigit() \
                        or not 1 <= int(rest_t[1]) <= 255:
                    raise _bad()
                dec = int(rest_t[1])
            own[f"hsrp-track:{key}:{tracked}"] = str(dec)
        else:
            own.pop(f"hsrp-track:{key}:{tracked}", None)
    elif what == "name":
        if on:
            if len(args) != 1 or not re.match(r"^[\w.-]{1,32}$", args[0]):
                raise _err("% A group name is up to 32 letters, digits, '.', '-' or '_'")
            own[f"hsrp-name:{key}"] = args[0]
        else:
            own.pop(f"hsrp-name:{key}", None)
    if on and grp not in own:
        own[grp] = ""   # IOS makes the group; its address is learned until one is given
    return _done(con)


def _put(own: dict, key: str, value: str) -> None:
    if value:
        own[key] = value
    else:
        own.pop(key, None)


def _set_version(con, own: dict, ifname: str, ver: int) -> str:
    if ver == 1 and any(g > 255 for _, g, _ in groups(own, ifname)):
        raise _err("% Group numbers above 255 need version 2: remove them first")
    _put(own, f"hsrp-ver:{ifname}", "2" if ver == 2 else "")
    return _done(con)


def _vip(con, own: dict, ifname: str, text: str, key: str) -> str:
    try:
        vip = str(ipaddress.IPv4Address(text))
    except ValueError:
        raise _bad() from None
    net = con.lab.networks.get(own.get(f"ip:{ifname}", ""))
    if net is None:
        raise _err(f"% {ifname} has no IP address: give it one first (ip address ...)")
    if ipaddress.IPv4Address(vip) not in net.net or vip in (str(net.net.network_address),
                                                            str(net.net.broadcast_address)):
        raise _err(f"% Address {vip} is not in {ifname}'s subnet {net.net}")
    if vip == net.router_ip:
        raise _err(f"% {vip} is this interface's own address: the virtual address is a third one, which "
                   f"both gateways share")
    for k, v in own.items():
        if k.startswith("vrrp:") and v == vip:
            raise _err(f"% Address {vip} is already the virtual address of VRRP group {k.rsplit(':', 1)[1]}")
        if k.startswith("glbp:") and v == vip:
            raise _err(f"% Address {vip} is already the virtual address of GLBP group {k.rsplit(':', 1)[1]}")
        if k.startswith("hsrp:") and v == vip and k != f"hsrp:{key}":
            raise _err(f"% Address {vip} in group {key.rsplit(':', 1)[1]} is already used by group "
                       f"{k.rsplit(':', 1)[1]}")
    return vip


# ------------------------------------------------------------------ show standby
def _names(con) -> dict[str, str]:
    from .iosrouting import svi_map
    out = {dev: name for name, dev in svi_map(con.lab, con.plan).items()}
    own = _own(con.lab)
    for k in own:
        if k.startswith("hsrp-track:"):
            t = k.split(":", 3)[3]
            out["down:" + t.replace("/", "_")] = t
    return out


def configured(con) -> list[dict]:
    """The groups as the console has them, in Init: what show standby says
    when the speaker is not running."""
    own = _own(con.lab)
    out = []
    for ifname, g, vip in groups(own):
        key = f"{ifname}:{g}"
        ver = version(own, ifname)
        hello, hold = (own.get(f"hsrp-timers:{key}") or f"{hsrpd.HELLO} {hsrpd.HOLD}").split()
        prio = int(own.get(f"hsrp-prio:{key}", hsrpd.PRIORITY))
        out.append({"iface": ifname, "group": g, "version": ver, "state": "Init", "prio": prio, "cfg_prio": prio,
                    "preempt": f"hsrp-pre:{key}" in own, "delay": int(own.get(f"hsrp-pre:{key}") or 0),
                    "hello": float(hello), "hold": float(hold), "vip": vip,
                    "secondary": own.get(f"hsrp-sec:{key}", "").split(), "vmac": hsrpd.vmac(ver, g), "my_ip": "",
                    "active": "", "active_prio": 0, "active_expires": 0, "standby": "", "standby_prio": 0,
                    "standby_expires": 0, "next_hello": 0, "changes": 0, "since": 0,
                    "tracks": [{"iface": t, "decrement": d, "up": True} for t, d in tracks(own, ifname, g)]
                    + [{"iface": f"object:{o}", "decrement": d, "up": True} for o, d in track_objs(own, ifname, g)],
                    "name": own.get(f"hsrp-name:{key}", ""), "auth_set": bool(own.get(f"hsrp-auth:{key}")),
                    "bad_auth": ""})
    return out


def read_state(con) -> list[dict]:
    if not con.powered():
        return configured(con)
    try:
        text = con._on_router(f"cat {STATE} 2>/dev/null; echo; p=$(cat {PIDFILE} 2>/dev/null); "
                              f"[ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null && echo '#running'", timeout=10) or ""
    except Exception:  # noqa: BLE001 - the configured groups, in Init
        return configured(con)
    if "#running" not in text:
        return configured(con)
    try:
        data = json.loads(text.split("#running")[0].strip() or "{}")
    except ValueError:
        return configured(con)
    names = _names(con)
    out = []
    for g in data.get("groups", []):
        g = dict(g)
        g["iface"] = names.get(g["iface"], g["iface"])
        g["tracks"] = [dict(t, iface=names.get(t["iface"], t["iface"])) for t in g.get("tracks", [])]
        out.append(g)
    return out


def show(con, brief: bool) -> str:
    from . import devcli
    if not groups(_own(con.lab)):
        return ""
    gs = read_state(con)
    if brief:
        return hsrpd.show_brief(gs, short=devcli.short_if)
    return hsrpd.show_detail(gs, short=devcli.short_if)


# ------------------------------------------------------------------ the drill (on rtr-edge)
def _faults():
    from .guestfaults import LINUX, GuestFault
    saved = "/var/lib/winlab/ts-hsrp-version"
    need = (f"[ -s {CONF} ] && grep -q '^ *standby .*ip ' {CONF} || {{ echo 'no HSRP group on this router: build it "
            "first (lesson router-console-hsrp)'; exit 1; }; ")
    reload = "systemctl reload winlab-hsrpd 2>/dev/null || pkill -HUP -f winlab-hsrpd"
    return [
        GuestFault(
            id="hsrp-version-mismatch",
            images=("ubuntu",),
            title="Both gateways say they are Active and the office's PCs lose their gateway now and then",
            os=LINUX,
            teaches="what two HSRP routers must share to hear each other (the version, which also changes the "
                    "multicast address and the virtual MAC; the group number; the authentication text), and why "
                    "two Active routers are a symptom of routers that cannot hear each other",
            symptom="show standby brief says Active on the lab router's console and winlab-hsrpd show brief says "
                    "Active on rtr-edge too; pc-office's ARP entry for the gateway changes MAC address, and pings "
                    "through it come and go",
            apply=(need + "mkdir -p /var/lib/winlab; "
                   f"if grep -q '^ *standby version 2' {CONF}; then echo 2 > {saved}; "
                   f"sed -i '/^ *standby version [12]$/d' {CONF}; "
                   f"else echo 1 > {saved}; sed -i '/^ *standby version [12]$/d' {CONF}; "
                   f"sed -i '/^interface /a\\ standby version 2' {CONF}; fi; {reload}; echo broken"),
            clear=(f"v=$(cat {saved} 2>/dev/null); [ -n \"$v\" ] || exit 0; sed -i '/^ *standby version [12]$/d' {CONF}; "
                   f"if [ \"$v\" = 2 ]; then sed -i '/^interface /a\\ standby version 2' {CONF}; fi; "
                   f"rm -f {saved}; {reload}; echo ok"),
            shell="sh",
            hints=(
                "Look at both ends: show standby brief on the lab router's console, sudo winlab-hsrpd show brief on "
                "rtr-edge. Two Active routers means each hears nobody: each thinks it is alone in the group.",
                "Watch what is on the wire: sudo tcpdump -ni eth1 udp port 1985 on rtr-edge. Version 1 hellos go to "
                "224.0.0.2, version 2 hellos to 224.0.0.102, and a router listens only to its own version. Compare "
                "standby version on the console (show running-config) with /etc/winlab-hsrp.conf here; then the "
                "group number and the authentication text.",
                "Make rtr-edge's file say what the lab router says (standby version 2 under the interface), then "
                "sudo systemctl reload winlab-hsrpd. Within a hold time one router goes Standby, and the PCs' ARP "
                "entry settles on the version's virtual MAC.",
            ),
            verify=(f"grep -q '\"state\": \"Standby\"' {STATE} 2>/dev/null && ! grep -q '\"state\": \"Active\"' {STATE} "
                    "&& echo True || echo False"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
