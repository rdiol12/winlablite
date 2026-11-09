"""GLBP typed at the lab router's console (``glbp``), spoken on the wire by
winlab-glbpd, winlab's own GLBP speaker (winlab/glbpd.py).

No open-source router speaks GLBP (Cisco's own Gateway Load Balancing
Protocol, with no published specification), so winlab wrote a small speaker
the way it wrote winlab-hsrpd for HSRP: GLBP hellos on UDP 3222 to
224.0.0.102 in the layout Wireshark's dissector decodes, the AVG and AVF
roles, the virtual MACs 0007.b400.XXYY on macvlans of the members that
forward for them, and the AVG answering each ARP request for the virtual
address with the next forwarder's MAC (round-robin, weighted or
host-dependent). The console's ``glbp`` lines go to /etc/winlab-glbp.conf
on the router in IOS's own words under the Linux interface's name; the
speaker is started the first time a group is configured, told to read the
file again (SIGHUP) on a change and stopped when the last group goes. It
runs on Python 3 from the lab's own Alpine package volume, as winlab-hsrpd
does. The other member in the lab is rtr-edge, running the same speaker
from the frr pack's stick. Both ends run winlab's code, which is the honest
limit: it interoperates with itself, it was not tried against a Cisco
router, and the forwarder assignment it carries in octets Wireshark calls
unknown is winlab's own reading.

Refused, with the reason: MD5 authentication, ``weighting track``,
``forwarder preempt``, ``client-cache``, ``timers msec``, ``ip <address>
secondary``.

``show glbp`` and ``show glbp brief`` read the speaker's state file
(/run/winlab-glbp.json); with the speaker not running they print the
configured groups in Init.

Settings (``<if>`` an IOS interface, ``<g>`` a group): ``glbp:<if>:<g>`` =
virtual address ("" to learn it); ``glbp-prio``, ``glbp-pre`` (delay, "0"
for none), ``glbp-timers`` ("hello hold"), ``glbp-redirect`` ("redirect
timeout"), ``glbp-lb``, ``glbp-weight``, ``glbp-auth``, ``glbp-name``, each
``:<if>:<g>``.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import json
import re
from pathlib import Path

from . import glbpd

SPEAKER = "/usr/local/sbin/winlab-glbpd"
CONF = glbpd.CONF_FILE
STATE = glbpd.STATE_FILE
PIDFILE = "/run/winlab-glbpd.pid"
LOG = "/var/log/winlab-glbp.log"
NOT_HERE = "% glbp {what} is not in this router (winlab-glbpd): {why}"


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _own(lab) -> dict:
    return lab.devices.get("router", {})


def speaker_source() -> bytes:
    return Path(glbpd.__file__).read_bytes()


def speaker_hash() -> str:
    return hashlib.sha256(speaker_source()).hexdigest()


def groups(own: dict, ifname: str = "") -> list[tuple[str, int, str]]:
    out = []
    for k, v in own.items():
        if k.startswith("glbp:"):
            name, _, g = k[5:].rpartition(":")
            if (not ifname or name == ifname) and g.isdigit():
                out.append((name, int(g), v))
    return sorted(out)


def active(own: dict) -> bool:
    return any(k.startswith("glbp:") for k in own)


# ------------------------------------------------------------------ the speaker's file
def _group_lines(own: dict, ifname: str, g: int, vip: str) -> list[str]:
    key = f"{ifname}:{g}"
    out = [f" glbp {g} ip" + (f" {vip}" if vip else "")]
    if own.get(f"glbp-timers:{key}"):
        out.append(f" glbp {g} timers {own[f'glbp-timers:{key}']}")
    if own.get(f"glbp-redirect:{key}"):
        out.append(f" glbp {g} timers redirect {own[f'glbp-redirect:{key}']}")
    if own.get(f"glbp-prio:{key}"):
        out.append(f" glbp {g} priority {own[f'glbp-prio:{key}']}")
    if f"glbp-pre:{key}" in own:
        d = own[f"glbp-pre:{key}"]
        out.append(f" glbp {g} preempt" + (f" delay minimum {d}" if d not in ("", "0") else ""))
    if own.get(f"glbp-weight:{key}"):
        out.append(f" glbp {g} weighting {own[f'glbp-weight:{key}']}")
    if own.get(f"glbp-lb:{key}"):
        out.append(f" glbp {g} load-balancing {own[f'glbp-lb:{key}']}")
    if own.get(f"glbp-auth:{key}"):
        out.append(f" glbp {g} authentication text {own[f'glbp-auth:{key}']}")
    if own.get(f"glbp-name:{key}"):
        out.append(f" glbp {g} name {own[f'glbp-name:{key}']}")
    return out


def conf_text(plan) -> str:
    from .iosrouting import svi_map
    own = _own(plan.lab)
    svis = svi_map(plan.lab, plan)
    out = []
    for ifname in sorted({i for i, _, _ in groups(own)}):
        dev = svis.get(ifname)
        if not dev:
            continue
        out += [f"! {ifname}", f"interface {dev}"]
        for _, g, vip in groups(own, ifname):
            out += _group_lines(own, ifname, g, vip)
    return "\n".join(out) + "\n" if out else ""


def router_lines(plan, runner=None) -> list[str]:
    from .ioshsrp import INSTALL
    own = _own(plan.lab)
    conf = conf_text(plan)
    stop = (f"p=$(cat {PIDFILE} 2>/dev/null); [ -n \"$p\" ] && kill \"$p\" 2>/dev/null; "
            f"rm -f {PIDFILE} {CONF}")
    if not conf:
        return ["# GLBP: no glbp group up", stop] if active(own) or runner is not None else []
    send = True
    if runner is not None:
        try:
            have = runner(f"sha256sum {SPEAKER} 2>/dev/null", timeout=15) or ""
        except Exception:  # noqa: BLE001 - send it, then
            have = ""
        send = speaker_hash() not in have
    out = ["# GLBP: winlab's own speaker, winlab-glbpd (winlab/glbpd.py), on the console's glbp lines", INSTALL]
    if send:
        blob = base64.b64encode(gzip.compress(speaker_source(), mtime=0)).decode()
        wrapped = "\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
        out += [f"if [ \"$(sha256sum {SPEAKER} 2>/dev/null | cut -c1-64)\" != {speaker_hash()} ]; then",
                f"mkdir -p {SPEAKER.rsplit('/', 1)[0]}",
                f"base64 -d > {SPEAKER}.gz <<'WLGLBPD'\n{wrapped}\nWLGLBPD",
                f"gunzip -c {SPEAKER}.gz > {SPEAKER} && chmod 755 {SPEAKER}; rm -f {SPEAKER}.gz", "fi"]
    out += [f"cat > {CONF} <<'WLGLBP'\n{conf}WLGLBP",
            f"p=$(cat {PIDFILE} 2>/dev/null)",
            f"if [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null; then kill -HUP \"$p\"; "
            f"else setsid python3 {SPEAKER} -c {CONF} -l {LOG} </dev/null >/dev/null 2>&1 & echo $! > {PIDFILE}; fi"]
    return out


# ------------------------------------------------------------------ show running-config
def iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    for _, g, vip in groups(own, ifname):
        out += _group_lines(own, ifname, g, vip)
    return out


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, IF) -> None:
    from . import devcli
    devcli.WORD_HELP.setdefault(("glbp",), "Gateway Load Balancing Protocol interface commands")
    devcli.WORD_HELP.setdefault(("show", "glbp"), "GLBP information")
    add("glbp <num> <line>", lambda a: glbp(con, a[0], a[1], True), "Gateway Load Balancing Protocol interface commands", IF)
    add("no glbp <num>", lambda a: glbp(con, a[0], "", False), "Negate a command or set its defaults", IF)
    add("no glbp <num> <line>", lambda a: glbp(con, a[0], a[1], False), "Negate a command or set its defaults", IF)
    add("show glbp", lambda a: show(con, False), "GLBP information", U)
    add("show glbp brief", lambda a: show(con, True), "Brief output", U)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _put(own: dict, key: str, value: str) -> None:
    if value:
        own[key] = value
    else:
        own.pop(key, None)


def glbp(con, g_text: str, rest: str, on: bool) -> str:
    g = int(g_text)
    if g > 1023:
        raise _bad()
    own = _own_c(con)
    ifname = con.s.ctx
    key = f"{ifname}:{g}"
    grp = f"glbp:{key}"
    w = rest.split()
    if not w:
        if on:
            raise _err("% Incomplete command.")
        for k in [k for k in own if k.startswith("glbp") and k.endswith(f":{key}")]:
            del own[k]
        return _done(con)
    opts = ("ip", "priority", "preempt", "timers", "load-balancing", "weighting", "authentication", "name",
            "forwarder", "client-cache")
    hit = [o for o in opts if o.startswith(w[0].lower())]
    if len(hit) != 1:
        raise _bad()
    what, args = hit[0], w[1:]
    if what in ("forwarder", "client-cache"):
        return NOT_HERE.format(what=what, why="forwarders are handed back to their member at once, and the AVG "
                                              "keeps no client cache")
    if what == "ip":
        if not on:
            for k in [k for k in own if k.startswith("glbp") and k.endswith(f":{key}")]:
                del own[k]
            return _done(con)
        if args[1:2] == ["secondary"]:
            return NOT_HERE.format(what="ip secondary", why="one virtual address per group")
        if args[1:]:
            raise _bad()
        own[grp] = _vip(con, own, ifname, args[0], key) if args else own.get(grp, "")
    elif what == "priority":
        if on:
            if len(args) != 1 or not args[0].isdigit() or not 1 <= int(args[0]) <= 255:
                raise _bad()
            _put(own, f"glbp-prio:{key}", "" if int(args[0]) == glbpd.PRIORITY else str(int(args[0])))
        else:
            own.pop(f"glbp-prio:{key}", None)
    elif what == "preempt":
        if on:
            d = "0"
            if args:
                if len(args) == 3 and "delay".startswith(args[0]) and "minimum".startswith(args[1]) \
                        and args[2].isdigit() and int(args[2]) <= 3600:
                    d = str(int(args[2]))
                else:
                    raise _bad()
            own[f"glbp-pre:{key}"] = d
        else:
            own.pop(f"glbp-pre:{key}", None)
    elif what == "timers":
        if args[:1] and "redirect".startswith(args[0]) and args[0][:1] == "r":
            if on:
                if len(args) != 3 or not all(a.isdigit() for a in args[1:]):
                    raise _bad()
                red, tmo = int(args[1]), int(args[2])
                if not (0 <= red <= 3600 and 610 <= tmo <= 64800 and tmo > red):
                    raise _err("% Redirect 0-3600 s, timeout 610-64800 s and more than the redirect")
                _put(own, f"glbp-redirect:{key}", "" if (red, tmo) == (glbpd.REDIRECT, glbpd.TIMEOUT) else f"{red} {tmo}")
            else:
                own.pop(f"glbp-redirect:{key}", None)
        elif on:
            if "msec" in args:
                return NOT_HERE.format(what="timers msec", why="hello and hold are whole seconds here")
            if len(args) != 2 or not all(a.isdigit() for a in args):
                raise _bad()
            hello, hold = int(args[0]), int(args[1])
            if not (1 <= hello <= 60 and 2 <= hold <= 180):
                raise _bad()
            if hold <= hello:
                raise _err("% Hold time must be greater than hello time")
            _put(own, f"glbp-timers:{key}", "" if (hello, hold) == (glbpd.HELLO, glbpd.HOLD) else f"{hello} {hold}")
        else:
            own.pop(f"glbp-timers:{key}", None)
    elif what == "load-balancing":
        if on:
            hit = [b for b in glbpd.BALANCE if args and b.startswith(args[0].lower())]
            if len(args) != 1 or len(hit) != 1:
                raise _bad()
            _put(own, f"glbp-lb:{key}", "" if hit[0] == "round-robin" else hit[0])
        else:
            own.pop(f"glbp-lb:{key}", None)
    elif what == "weighting":
        if on:
            if args[:1] and "track".startswith(args[0]) and args[0][:1] == "t":
                return NOT_HERE.format(what="weighting track", why="a member's weighting is what you set; track "
                                                                    "HSRP or VRRP groups instead (standby <g> track <n>)")
            if not args or not args[0].isdigit() or not 1 <= int(args[0]) <= 254:
                raise _bad()
            _put(own, f"glbp-weight:{key}", "" if int(args[0]) == glbpd.WEIGHT else str(int(args[0])))
        else:
            own.pop(f"glbp-weight:{key}", None)
    elif what == "authentication":
        if on:
            if args[:1] == ["md5"]:
                return NOT_HERE.format(what="authentication md5", why="the speaker takes plain-text authentication only")
            text = args[1] if args[:1] == ["text"] and len(args) == 2 else ""
            if not text or len(text) > 8 or not re.match(r"^[\x21-\x7e]+$", text):
                raise _err("% glbp <group> authentication text <1 to 8 characters, no spaces>")
            own[f"glbp-auth:{key}"] = text
        else:
            own.pop(f"glbp-auth:{key}", None)
    elif what == "name":
        if on:
            if len(args) != 1 or not re.match(r"^[\w.-]{1,32}$", args[0]):
                raise _err("% A group name is up to 32 letters, digits, '.', '-' or '_'")
            own[f"glbp-name:{key}"] = args[0]
        else:
            own.pop(f"glbp-name:{key}", None)
    if on and grp not in own:
        own[grp] = ""
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
        raise _err(f"% {vip} is this interface's own address: the virtual address is a third one")
    for k, v in own.items():
        if k.startswith(("vrrp:", "hsrp:")) and v == vip:
            raise _err(f"% Address {vip} is already the virtual address of {k.split(':')[0].upper()} group "
                       f"{k.rsplit(':', 1)[1]}")
        if k.startswith("glbp:") and v == vip and k != f"glbp:{key}":
            raise _err(f"% Address {vip} is already used by GLBP group {k.rsplit(':', 1)[1]}")
    return vip


# ------------------------------------------------------------------ show glbp
def configured(con) -> list[dict]:
    own = _own(con.lab)
    out = []
    for ifname, g, vip in groups(own):
        key = f"{ifname}:{g}"
        hello, hold = (own.get(f"glbp-timers:{key}") or f"{glbpd.HELLO} {glbpd.HOLD}").split()
        red, tmo = (own.get(f"glbp-redirect:{key}") or f"{glbpd.REDIRECT} {glbpd.TIMEOUT}").split()
        out.append({"iface": ifname, "group": g, "state": "Init", "vip": vip,
                    "prio": int(own.get(f"glbp-prio:{key}", glbpd.PRIORITY)), "preempt": f"glbp-pre:{key}" in own,
                    "delay": int(own.get(f"glbp-pre:{key}") or 0), "hello": float(hello), "hold": float(hold),
                    "redirect": int(red), "timeout": int(tmo), "balance": own.get(f"glbp-lb:{key}", "round-robin"),
                    "weight": int(own.get(f"glbp-weight:{key}", glbpd.WEIGHT)), "my_ip": "", "my_mac": "",
                    "active": "", "active_prio": 0, "active_expires": 0, "standby": "", "standby_prio": 0,
                    "next_hello": 0, "changes": 0, "since": 0, "members": [], "forwarders": [],
                    "name": own.get(f"glbp-name:{key}", ""), "auth_set": bool(own.get(f"glbp-auth:{key}")),
                    "bad_auth": ""})
    return out


def read_state(con) -> list[dict]:
    from .iosrouting import svi_map
    if not con.powered():
        return configured(con)
    try:
        text = con._on_router(f"cat {STATE} 2>/dev/null; echo; p=$(cat {PIDFILE} 2>/dev/null); "
                              f"[ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null && echo '#running'", timeout=10) or ""
    except Exception:  # noqa: BLE001
        return configured(con)
    if "#running" not in text:
        return configured(con)
    try:
        data = json.loads(text.split("#running")[0].strip() or "{}")
    except ValueError:
        return configured(con)
    names = {dev: name for name, dev in svi_map(con.lab, con.plan).items()}
    return [dict(g, iface=names.get(g["iface"], g["iface"])) for g in data.get("groups", [])]


def show(con, brief: bool) -> str:
    from . import devcli
    if not groups(_own(con.lab)):
        return ""
    gs = read_state(con)
    return glbpd.show_brief(gs, short=devcli.short_if) if brief else glbpd.show_detail(gs)
