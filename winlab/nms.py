"""Network management on the router and the switches: syslog, SNMP and NTP,
pointed at servers the student builds inside the lab.

A real network sends what its devices say to a syslog server, answers an
SNMP manager and sends it traps, and keeps its clocks on NTP so that the
log lines of ten devices can be read side by side. Here the consoles take
the IOS commands for all three (``logging host``, ``logging trap``,
``service timestamps``, ``snmp-server community / location / contact /
host / enable traps``, ``ntp server``, ``show logging / snmp / ntp``) and
the router makes them real:

- What a device logs (a link going up or down when a cable is pulled or a
  machine powers off, a port shut on the console, configuration changes,
  spanning tree changing its root or a port's state, privileged logins, and
  any %FAC-SEV-MNEMONIC line another part of winlab prints on a console) is
  numbered, kept in the device's buffer (show logging) and sent as a real
  syslog datagram over UDP from the router (RFC 3164, or RFC 5424 with
  ``logging host <ip> format rfc5424``), stamped by the router's own clock. The switches here are bridges
  inside the router and have no address of their own, so their messages
  leave from the router's address on their VLAN, with the switch's name as
  the host.
- SNMP: net-snmp's snmpd on the router answers on UDP 161 with the
  communities, location and contact typed in (a community bound to a
  standard access list answers only the addresses it permits), and link
  up / down (IF-MIB) and spanning tree (BRIDGE-MIB) traps go out with
  snmptrap to every ``snmp-server host`` once ``snmp-server enable traps``
  is on.
- NTP: chrony on the router follows the ``ntp server`` lines (the router's
  and its switches', since they share its clock). Until it is in sync the
  timestamps carry IOS's '*': the time is not to be trusted.

The packages (net-snmp, net-snmp-tools, chrony) are on the lab's package
volume (`winlab images prepare fabric` fetches them on this PC); the router
installs them offline the first time they are needed. The collectors are
the student's: rsyslog and snmptrapd on a Linux machine, or a syslog server
they bring to Windows. winlab only gets the datagrams onto the wire.

Four graded drills hide a fault in the student's own configuration: a
community that does not match, an access list that keeps the collector
out, a trap level that filters the link-down away, and a router clock that
is far off with its NTP server unreachable.
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
import shlex
import threading
import time

from . import devcli, paths, state

LEVELS = ("emergencies", "alerts", "critical", "errors", "warnings", "notifications",
          "informational", "debugging")
DEFAULT_TRAP = 6            # informational, as on IOS
STAMPS = ("datetime msec", "datetime", "uptime", "none")
DEFAULT_STAMP = "datetime msec"   # what a new router's configuration has
FACILITIES = tuple(f"local{i}" for i in range(8)) + ("syslog", "user", "daemon")
FACILITY_CODE = {**{f"local{i}": 16 + i for i in range(8)}, "syslog": 5, "user": 1, "daemon": 3}
LOG_FORMATS = ("rfc3164", "rfc5424")
BUFFER = 200                # lines kept per device (show logging)
NOWHERE = "192.0.2.123"     # TEST-NET-1: an NTP server nobody in the lab is
MSG_RE = re.compile(r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):")
# The OIDs the traps carry (numeric: no MIB files needed on the router).
LINK_DOWN, LINK_UP = "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.6.3.1.1.5.4"
NEW_ROOT, TOPO_CHANGE = "1.3.6.1.2.1.17.0.1", "1.3.6.1.2.1.17.0.2"
IF_TABLE = "1.3.6.1.2.1.2.2.1"


class NmsError(Exception):
    pass


# ------------------------------------------------------------------ settings
# What the consoles set lives with the device's other settings in the lab
# file ([devices."router"], [devices."sw:<id>"]):
#   log-host:<ip> = "<port> <rfc3164|rfc5424>"   log-trap = level number
#   log-stamp = one of STAMPS                     log-facility = local7...
#   snmp-comm:<name> = "ro|rw [acl]"             snmp-location / snmp-contact
#   snmp-host:<ip> = "<1|2c> <community>"        snmp-traps = "yes"
#   ntp:<ip> = "yes"                              acl:<n> = "permit host 10.0.0.5;deny any"
def _own(lab, device: str) -> dict:
    return lab.devices.get(device, {})


def devices(lab) -> list[str]:
    return [devcli.ROUTER] + [f"sw:{s}" for s in devcli.switches(lab)]


def log_hosts(lab, device: str) -> list[tuple[str, int, str]]:
    out = []
    for k, v in sorted(_own(lab, device).items()):
        if k.startswith("log-host:"):
            port, _, fmt = str(v).partition(" ")
            out.append((k[9:], int(port) if port.isdigit() else 514, fmt or "rfc3164"))
    return out


def trap_level(lab, device: str) -> int:
    v = str(_own(lab, device).get("log-trap", ""))
    return int(v) if v.isdigit() else DEFAULT_TRAP


def stamp(lab, device: str) -> str:
    return str(_own(lab, device).get("log-stamp") or DEFAULT_STAMP)


def facility(lab, device: str) -> str:
    return str(_own(lab, device).get("log-facility") or "local7")


def communities(lab, device: str) -> list[tuple[str, str, str]]:
    """(name, ro|rw, access list or "")."""
    out = []
    for k, v in sorted(_own(lab, device).items()):
        if k.startswith("snmp-comm:"):
            how, _, acl = str(v).partition(" ")
            out.append((k[10:], how, acl))
    return out


def trap_hosts(lab, device: str) -> list[tuple[str, str, str]]:
    """(address, version, community)."""
    out = []
    for k, v in sorted(_own(lab, device).items()):
        if k.startswith("snmp-host:"):
            ver, _, comm = str(v).partition(" ")
            out.append((k[10:], ver, comm))
    return out


def traps_on(lab, device: str) -> bool:
    return bool(_own(lab, device).get("snmp-traps"))


def ntp_servers(lab, device: str | None = None) -> list[str]:
    """One device's NTP servers, or (device None) every one the router's
    clock follows: its own and its switches'."""
    devs = [device] if device else devices(lab)
    return sorted({k[4:] for d in devs for k in _own(lab, d) if k.startswith("ntp:")},
                  key=lambda a: tuple(int(x) for x in a.split(".")))


def acl(lab, num: str) -> list[tuple[str, str]]:
    """A standard access list: (permit|deny, network as a CIDR). The lists
    are the router's (winlab/iosl3.py keeps them)."""
    from . import iosl3
    out = []
    for _, entry in iosl3.entries(_own(lab, devcli.ROUTER), num):
        how, _, net = entry.partition(" ")
        if how in ("permit", "deny") and "/" in net and " " not in net:
            out.append((how, net))
    return out


def acl_allows(lab, num: str, ip: str) -> bool:
    """What a standard list does with an address: the first entry that
    matches decides; nothing matching is the implicit deny."""
    if not num:
        return True
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    for how, net in acl(lab, num):
        if addr in ipaddress.IPv4Network(net):
            return how == "permit"
    return False


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    """The commands every device's console gets (winlab/devcli.py)."""
    E = ("enable",)
    add("show logging", lambda a: show_logging(con), "Show the contents of logging buffers", U)
    add("show ntp status", lambda a: show_ntp(con, False), "NTP status", U)
    add("show ntp associations", lambda a: show_ntp(con, True), "NTP associations", U)
    add("show snmp", lambda a: show_snmp(con), "snmp statistics", E)
    add("show snmp community", lambda a: show_community(con), "show snmp communities", E)
    add("show snmp host", lambda a: show_snmp_host(con), "show snmp notification hosts", E)
    add("clear logging", lambda a: _clear(con), "Clear logging buffer", E)
    add("logging host <ip>", lambda a: set_log_host(con, a[0], ""), "Set syslog server IP address and parameters", C)
    add("logging host <ip> <line>", lambda a: set_log_host(con, a[0], a[1]), "Set syslog server IP address and parameters", C)
    add("logging <ip>", lambda a: set_log_host(con, a[0], ""), "IP address of the logging host", C)
    add("no logging host <ip>", lambda a: no_log_host(con, a[0]), "Negate a command or set its defaults", C)
    add("no logging <ip>", lambda a: no_log_host(con, a[0]), "Negate a command or set its defaults", C)
    add("logging trap <line>", lambda a: set_trap(con, a[0]), "Set syslog server logging level", C)
    add("no logging trap", lambda a: set_trap(con, ""), "Negate a command or set its defaults", C)
    add("logging facility <line>", lambda a: set_facility(con, a[0]), "Facility parameter for syslog messages", C)
    add("service timestamps <line>", lambda a: set_stamp(con, a[0]), "Timestamp debug/log messages", C)
    add("no service timestamps", lambda a: set_stamp(con, "none"), "Negate a command or set its defaults", C)
    add("no service timestamps <line>", lambda a: set_stamp(con, "none"), "Negate a command or set its defaults", C)
    add("snmp-server community <name> <line>", lambda a: set_community(con, a[0], a[1]), "Enable SNMP; set community string and access privs", C)
    add("no snmp-server community <name>", lambda a: no_community(con, a[0]), "Negate a command or set its defaults", C)
    add("snmp-server location <line>", lambda a: set_text(con, "snmp-location", a[0]), "Text for mib object sysLocation", C)
    add("snmp-server contact <line>", lambda a: set_text(con, "snmp-contact", a[0]), "Text for mib object sysContact", C)
    add("no snmp-server location", lambda a: set_text(con, "snmp-location", ""), "Negate a command or set its defaults", C)
    add("no snmp-server contact", lambda a: set_text(con, "snmp-contact", ""), "Negate a command or set its defaults", C)
    add("snmp-server host <ip> <line>", lambda a: set_trap_host(con, a[0], a[1]), "Specify hosts to receive SNMP notifications", C)
    add("no snmp-server host <ip>", lambda a: no_trap_host(con, a[0]), "Negate a command or set its defaults", C)
    add("no snmp-server host <ip> <line>", lambda a: no_trap_host(con, a[0]), "Negate a command or set its defaults", C)
    add("snmp-server enable traps", lambda a: set_traps(con, True), "Enable SNMP Traps", C)
    add("snmp-server enable traps <line>", lambda a: set_traps(con, True), "Enable SNMP Traps", C)
    add("no snmp-server enable traps", lambda a: set_traps(con, False), "Negate a command or set its defaults", C)
    add("no snmp-server enable traps <line>", lambda a: set_traps(con, False), "Negate a command or set its defaults", C)
    add("ntp server <ip>", lambda a: set_ntp(con, a[0], True), "Configure NTP server", C)
    add("ntp server <ip> <line>", lambda a: set_ntp(con, a[0], True), "Configure NTP server", C)
    add("no ntp server <ip>", lambda a: set_ntp(con, a[0], False), "Negate a command or set its defaults", C)
    # access-list and show access-lists are the router's (winlab/iosl3.py).


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def _ip(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise devcli.CliError(f"% Invalid IP address: {text}") from None


def _saved(con, push: bool = False) -> str:
    """Saves a change; one the router's daemons follow (snmpd, chrony) goes
    into the running router too."""
    con._save(live=False)
    if push and con.powered():
        try:
            con._on_router(push_script(con.lab), timeout=60)
        except devcli.CliError as exc:
            return f"% the router did not take it now ({str(exc).lstrip('% ')}); it does at its next start"
        except Exception as exc:  # the serial channel: any failure is "not now"
            return f"% the router did not take it now ({exc}); it does at its next start"
    return ""


def set_log_host(con, ip: str, rest: str) -> str:
    ip = _ip(ip)
    port, fmt = 514, "rfc3164"
    w = rest.lower().split()
    i = 0
    while i < len(w):
        if w[i] == "transport" and i + 1 < len(w):
            if w[i + 1] != "udp":
                raise devcli.CliError("% This device sends syslog over UDP only: transport udp port <n>")
            i += 2
        elif w[i] == "port" and i + 1 < len(w) and w[i + 1].isdigit() and 0 < int(w[i + 1]) < 65536:
            port, i = int(w[i + 1]), i + 2
        elif w[i] == "format" and i + 1 < len(w) and w[i + 1] in LOG_FORMATS:
            fmt, i = w[i + 1], i + 2
        else:
            raise devcli.CliError("% logging host <ip> [transport udp port <n>] [format rfc3164 | rfc5424]")
    _mine(con)[f"log-host:{ip}"] = f"{port} {fmt}"
    return _saved(con)


def no_log_host(con, ip: str) -> str:
    if _mine(con).pop(f"log-host:{_ip(ip)}", None) is None:
        raise devcli.CliError(f"% {ip} is not a logging host here")
    return _saved(con)


def _level(text: str) -> int:
    t = text.strip().lower()
    if t.isdigit() and int(t) < 8:
        return int(t)
    hits = [i for i, n in enumerate(LEVELS) if t and n.startswith(t)]
    if len(hits) != 1:
        raise devcli.CliError("% Logging level: 0-7, or " + " | ".join(LEVELS))
    return hits[0]


def set_trap(con, text: str) -> str:
    if text:
        _mine(con)["log-trap"] = str(_level(text))
    else:
        _mine(con).pop("log-trap", None)
    return _saved(con)


def set_facility(con, text: str) -> str:
    t = text.strip().lower()
    if t not in FACILITIES:
        raise devcli.CliError("% Facility: " + " | ".join(FACILITIES))
    _mine(con)["log-facility"] = t
    return _saved(con)


def set_stamp(con, text: str) -> str:
    w = text.lower().split()
    if w and w[0] == "debug":
        return ""  # debug messages are not in this device
    if w and w[0] == "log":
        w = w[1:]
    if text == "none":
        how = "none"
    elif not w or w[0] == "uptime":
        how = "uptime"
    elif w[0] == "datetime":
        how = "datetime msec" if "msec" in w else "datetime"   # localtime, year, show-timezone: as kept
    else:
        raise devcli.CliError("% service timestamps log datetime [msec] | uptime")
    _mine(con)["log-stamp"] = how
    return _saved(con)


def set_community(con, name: str, rest: str) -> str:
    w = rest.lower().split()
    if not w or w[0] not in ("ro", "rw"):
        raise devcli.CliError("% snmp-server community <name> ro | rw [<access-list 1-99>]")
    how = w[0]
    num = w[1] if len(w) > 1 else ""
    if num and not (num.isdigit() and 1 <= int(num) <= 99):
        raise devcli.CliError("% Standard access lists are 1 to 99")
    if not re.match(r"^[A-Za-z0-9_.@#-]{1,32}$", name):
        raise devcli.CliError("% A community is 1 to 32 letters, digits or _.@#-")
    _mine(con)[f"snmp-comm:{name}"] = f"{how} {num}".strip()
    return _saved(con, push=con.device == devcli.ROUTER)


def no_community(con, name: str) -> str:
    if _mine(con).pop(f"snmp-comm:{name}", None) is None:
        raise devcli.CliError(f"% Community {name} does not exist")
    return _saved(con, push=con.device == devcli.ROUTER)


def set_text(con, key: str, text: str) -> str:
    if text:
        _mine(con)[key] = text.strip()[:120]
    else:
        _mine(con).pop(key, None)
    return _saved(con, push=con.device == devcli.ROUTER)


def set_trap_host(con, ip: str, rest: str) -> str:
    """snmp-server host <ip> [traps] [version 1 | 2c] <community>"""
    ip = _ip(ip)
    w = rest.split()
    ver = "1"
    i = 0
    while i < len(w) - 1:
        if w[i].lower() in ("traps", "informs"):
            i += 1
        elif w[i].lower() == "version" and w[i + 1].lower() in ("1", "2c"):
            ver, i = w[i + 1].lower(), i + 2
        elif w[i].lower() == "version":
            raise devcli.CliError("% SNMP version 1 or 2c (version 3 is not in this device)")
        else:
            break
    rest = w[i:]
    if len(rest) < 1 or rest[0].lower() in ("traps", "version"):
        raise devcli.CliError("% snmp-server host <ip> [traps] [version 1 | 2c] <community>")
    _mine(con)[f"snmp-host:{ip}"] = f"{ver} {rest[0]}"
    note = _saved(con, push=con.device == devcli.ROUTER)
    if not traps_on(con.lab, con.device):
        note = (note + "\n" if note else "") + "% No traps go to it until snmp-server enable traps"
    return note


def no_trap_host(con, ip: str) -> str:
    if _mine(con).pop(f"snmp-host:{_ip(ip)}", None) is None:
        raise devcli.CliError(f"% {ip} is not a notification host here")
    return _saved(con, push=con.device == devcli.ROUTER)


def set_traps(con, on: bool) -> str:
    if on:
        _mine(con)["snmp-traps"] = "yes"
    else:
        _mine(con).pop("snmp-traps", None)
    return _saved(con, push=con.device == devcli.ROUTER)


def set_ntp(con, ip: str, on: bool) -> str:
    ip = _ip(ip)
    if on:
        _mine(con)[f"ntp:{ip}"] = "yes"
    elif _mine(con).pop(f"ntp:{ip}", None) is None:
        raise devcli.CliError(f"% {ip} is not an NTP server here")
    note = _saved(con, push=True)
    if con.device != devcli.ROUTER and on:
        note = (note + "\n" if note else "") + ("% This switch keeps the router's clock (it is a bridge inside the "
                                                 "router): the router's chrony follows this server too")
    return note


def _clear(con) -> str:
    data = _buf_load(con.lab.name)
    data.pop(con.device, None)
    _buf_save(con.lab.name, data)
    return ""


def run_lines(lab, device: str) -> list[str]:
    """The device's lines in show running-config."""
    own = _own(lab, device)
    out = []
    st = stamp(lab, device)
    out += [f"service timestamps log {st}" if st != "none" else "no service timestamps log", "!"]
    for ip, port, fmt in log_hosts(lab, device):
        extra = (f" transport udp port {port}" if port != 514 else "") + (f" format {fmt}" if fmt != "rfc3164" else "")
        out.append(f"logging host {ip}{extra}")
    if own.get("log-trap"):
        out.append(f"logging trap {LEVELS[trap_level(lab, device)]}")
    if own.get("log-facility"):
        out.append(f"logging facility {facility(lab, device)}")
    for name, how, num in communities(lab, device):
        out.append(f"snmp-server community {name} {how.upper()}" + (f" {num}" if num else ""))
    for key, word in (("snmp-location", "location"), ("snmp-contact", "contact")):
        if own.get(key):
            out.append(f"snmp-server {word} {own[key]}")
    if traps_on(lab, device):
        out.append("snmp-server enable traps snmp linkdown linkup")
    for ip, ver, comm in trap_hosts(lab, device):
        out.append(f"snmp-server host {ip} " + (f"version {ver} " if ver != "1" else "") + comm)
    out += [f"ntp server {ip}" for ip in ntp_servers(lab, device)]
    return out + (["!"] if len(out) > 2 else [])


# ------------------------------------------------------------------ show
def _router_text(con, cmd: str) -> str:
    try:
        return con._on_router(cmd, timeout=20)
    except devcli.CliError:
        return ""


def show_clock(con) -> str:
    """The router's own clock (its switches share it): '*' until NTP has
    it in sync, as IOS marks a time it does not trust."""
    text = _router_text(con, "chronyc -n tracking 2>/dev/null | grep -q 'Leap status *: Normal' && echo SYNC; "
                             "date -u '+%H:%M:%S %a %b %d %Y'; date +%N 2>/dev/null | cut -c1-3")
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    sync = bool(lines) and lines[0] == "SYNC"
    rest = lines[1:] if sync else lines
    if not rest or not re.match(r"^\d\d:\d\d:\d\d ", rest[0]):
        from . import labclock
        return time.strftime("*%H:%M:%S.000 UTC %a %b %d %Y", time.gmtime(labclock.load(con.lab.name).now()))
    hms, _, day = rest[0].partition(" ")
    ms = rest[1] if len(rest) > 1 and rest[1].isdigit() else "000"
    return f"{'' if sync else '*'}{hms}.{ms} UTC {day}"


def show_logging(con) -> str:
    lab, dev = con.lab, con.device
    if dev.startswith("sw:") and con.powered():
        from . import portsec  # the kernel's port security counters first: a violation is a log line
        portsec._sync_live(con)
    lines = _buf_load(lab.name).get(dev, {}).get("lines", [])
    sent = _buf_load(lab.name).get(dev, {}).get("sent", {})
    lvl = LEVELS[trap_level(lab, dev)]
    out = ["Syslog logging: enabled (0 messages dropped, 0 messages rate-limited, 0 flushes, 0 overruns)",
           f"    Console logging: level debugging, {len(lines)} messages logged",
           f"    Buffer logging:  level debugging, {len(lines)} messages logged",
           f"    Trap logging: level {lvl}, {sum(sent.values())} message lines logged"]
    for ip, port, fmt in log_hosts(lab, dev):
        out.append(f"        Logging to {ip}  (udp port {port}, {fmt.upper()}), {sent.get(ip, 0)} message lines logged")
    if not log_hosts(lab, dev):
        out.append("        No syslog server: logging host <ip> in configure terminal")
    if dev != devcli.ROUTER:
        out.append("        (sent from the router's address on this switch's VLAN: the switch has none of its own)")
    out += ["", f"Log Buffer ({BUFFER} lines):"] + [x for _, x in lines[-60:]]
    return "\n".join(out)


def _tracking(con) -> dict:
    from . import timesync
    text = _router_text(con, "chronyc -n tracking 2>&1; echo '#src'; chronyc -n sources 2>&1")
    trk, _, src = text.partition("#src")
    return {"t": timesync.parse_tracking(trk), "s": timesync.parse_sources(src),
            "on": bool(text) and "Cannot talk" not in text and "not found" not in text,
            "raw": trk}


def show_ntp(con, assoc: bool) -> str:
    mine = ntp_servers(con.lab, con.device)
    if not ntp_servers(con.lab):
        return "%NTP is not enabled."
    d = _tracking(con)
    if assoc:
        out = ["  address         ref clock       st   when   poll reach  delay  offset   disp"]
        mark = {"*": "*", "+": "+", "-": "-", "x": "x", "?": " ", "~": " "}
        for s in d["s"]:
            out.append(f"{mark.get(s['state'], ' ')}~{s['name']:<16}{'.NTP.':<16}{s['stratum']:<5}{'-':>6}{64:>7}"
                       f"{s['reach']:>6}")
        known = {s["name"] for s in d["s"]}
        out += [f" ~{ip:<16}{'.INIT.':<16}{16:<5}{'-':>6}{64:>7}{0:>6}" for ip in ntp_servers(con.lab) if ip not in known]
        out.append(" * sys.peer, # selected, + candidate, - outlyer, x falseticker, ~ configured")
        if not mine:
            out.append("% (configured on another device sharing the router's clock)")
        return "\n".join(out)
    t = d["t"]
    if t.get("synced"):
        ref = t.get("reference", "").split("(")[-1].rstrip(")") or "?"
        return (f"Clock is synchronized, stratum {t.get('stratum', 0)}, reference is {ref}\n"
                f"clock offset: {t.get('system', '?')}\n"
                f"(chrony on the router: chronyc tracking)")
    return ("Clock is unsynchronized, stratum 16, no reference clock\n"
            + ("(chrony on the router has not reached a server yet: show ntp associations)" if d["on"] else
               "(chrony is not running on the router yet)"))


def show_snmp(con) -> str:
    lab, dev = con.lab, con.device
    own = _own(lab, dev)
    if not communities(lab, dev) and not trap_hosts(lab, dev):
        return "%SNMP agent not enabled"
    out = [f"Chassis: {devcli.hostname(lab, dev)}"]
    out += [f"Contact: {own['snmp-contact']}"] if own.get("snmp-contact") else []
    out += [f"Location: {own['snmp-location']}"] if own.get("snmp-location") else []
    if dev == devcli.ROUTER:
        live = _router_text(con, "pidof snmpd >/dev/null && echo running || echo stopped").strip()
        out.append(f"SNMP agent: net-snmp on the router, UDP 161, {live or 'state unknown'}")
    else:
        out.append("SNMP agent: none on this switch (it has no address); its traps leave from the router")
    out.append(f"SNMP logging: {'enabled' if traps_on(lab, dev) else 'disabled (snmp-server enable traps)'}")
    sent = _buf_load(lab.name).get(dev, {}).get("traps", {})
    for ip, ver, comm in trap_hosts(lab, dev):
        out.append(f"    Logging to {ip}.162, version {ver}, community {comm}, {sent.get(ip, 0)} sent")
    return "\n".join(out)


def show_community(con) -> str:
    rows = []
    for name, how, num in communities(con.lab, con.device):
        rows += [f"Community name: {name}", f"Community Index: {name}", f"Community SecurityName: {name}",
                 f"storage-type: nonvolatile\t active\t access: {how.upper()}"
                 + (f"\t access-list: {num}" if num else ""), ""]
    return "\n".join(rows) or "% No communities: snmp-server community <name> ro"


def show_snmp_host(con) -> str:
    rows = []
    for ip, ver, comm in trap_hosts(con.lab, con.device):
        rows += [f"Notification host: {ip}\tudp-port: 162\ttype: trap", f"user: {comm}\tsecurity model: v{ver}", ""]
    return "\n".join(rows) or "% No notification hosts: snmp-server host <ip> version 2c <community>"


# ------------------------------------------------------------------ the router
def snmpd_conf(lab) -> str:
    """net-snmp's configuration for the router's agent."""
    own = _own(lab, devcli.ROUTER)
    out = ["# generated by winlab from the router's console (snmp-server ...)", "agentAddress udp:161",
           f"sysName {devcli.hostname(lab, devcli.ROUTER)}"]
    out += [f"sysLocation {own['snmp-location']}"] if own.get("snmp-location") else []
    out += [f"sysContact {own['snmp-contact']}"] if own.get("snmp-contact") else []
    for name, how, num in communities(lab, devcli.ROUTER):
        word = "rocommunity" if how == "ro" else "rwcommunity"
        nets = [n for h, n in acl(lab, num) if h == "permit"] if num else ["default"]
        # A list that permits nothing answers no one: a source no packet has.
        out += [f"{word} {name} {n}" for n in (nets or ["127.255.255.254/32"])]
    if traps_on(lab, devcli.ROUTER):
        for ip, ver, comm in trap_hosts(lab, devcli.ROUTER):
            out.append(f"{'trap2sink' if ver == '2c' else 'trapsink'} {ip} {comm}")
    return "\n".join(out) + "\n"


def chrony_conf(lab) -> str:
    out = ["# generated by winlab from the consoles (ntp server ...)"]
    out += [f"server {ip} iburst" for ip in ntp_servers(lab)]
    out += ["makestep 1 3", "driftfile /var/lib/chrony/winlab.drift", "port 0"]
    return "\n".join(out) + "\n"


def push_script(lab) -> str:
    """Shell that brings the router's snmpd and chrony in line with the
    consoles (at boot, and when a command changes them)."""
    snmp = bool(communities(lab, devcli.ROUTER) or (traps_on(lab, devcli.ROUTER) and trap_hosts(lab, devcli.ROUTER)))
    ntp = bool(ntp_servers(lab))
    out = ["# network management: snmpd and chrony (winlab/nms.py)", "mkdir -p /etc/winlab /var/lib/chrony"]
    if snmp or any(trap_hosts(lab, d) for d in devices(lab)):
        out.append("command -v snmptrap >/dev/null 2>&1 || apk add --no-network net-snmp net-snmp-tools >/dev/null 2>&1 || true")
    out.append("pkill -x snmpd 2>/dev/null || true")
    if snmp:
        out += [f"cat > /etc/winlab/snmpd.conf <<'WLSNMP'\n{snmpd_conf(lab)}WLSNMP",
                "snmpd -C -c /etc/winlab/snmpd.conf -Lf /var/log/snmpd.log -p /run/snmpd.pid 2>/dev/null || true"]
    out.append("pkill -x chronyd 2>/dev/null || true")
    if ntp:
        out += ["command -v chronyd >/dev/null 2>&1 || apk add --no-network chrony >/dev/null 2>&1 || true",
                f"cat > /etc/winlab/chrony.conf <<'WLNTP'\n{chrony_conf(lab)}WLNTP",
                "sleep 1; chronyd -f /etc/winlab/chrony.conf 2>/dev/null || true"]
    return "\n".join(out)


def render(plan) -> list[str]:
    """The router's start script: the agents, and a drill's clock still off."""
    lab = plan.lab
    if not (any(communities(lab, d) or trap_hosts(lab, d) for d in devices(lab)) or ntp_servers(lab)):
        return []
    out = ["", "### network management (winlab/nms.py)"]
    d = drill_state(lab.name)
    if d and d.get("id") == "clock" and not d.get("done"):
        out.append(f"date -s @$(( $(date +%s) + {int(d.get('skew', 0))} )) >/dev/null 2>&1 || true")
    return out + push_script(lab).splitlines()


# ------------------------------------------------------------------ sending
_LOCK = threading.Lock()


def _buf_path(lab_name: str):
    return paths.lab_dir(lab_name) / "devlog.json"


def _buf_load(lab_name: str) -> dict:
    try:
        return json.loads(_buf_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _buf_save(lab_name: str, data: dict) -> None:
    p = _buf_path(lab_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=0), encoding="utf-8")


_STAMP_SH = {"datetime msec": '${Y}${D}.${M}: ', "datetime": '${Y}${D}: ', "uptime": '${U}: ', "none": ""}
_HEAD = ("Y='*'; chronyc -n tracking 2>/dev/null | grep -q 'Leap status *: Normal' && Y=''\n"
         "D=$(date '+%b %e %H:%M:%S'); M=$(date +%N 2>/dev/null | cut -c1-3)\n"
         "case \"$M\" in [0-9][0-9][0-9]) ;; *) M=000 ;; esac\n"
         "I=$(date -u '+%Y-%m-%dT%H:%M:%S').${M}Z\n"
         "U=$(awk '{t=int($1); d=int(t/86400); if (d) printf \"%dd%02dh\", d, int(t%86400/3600); "
         "else printf \"%02d:%02d:%02d\", int(t/3600), int(t%3600/60), t%60}' /proc/uptime)")


def severity(line: str) -> int:
    m = MSG_RE.search(line)
    return int(m.group(2)) if m else 6


def if_index(device: str, port: str) -> int:
    """IF-MIB ifIndex of a port: Fa0/n is n, a switch's Gi0/n 24+n, the
    router's Gi0/n n+1."""
    m = re.search(r"(\d+)$", port)
    n = int(m.group(1)) if m else 0
    if device == devcli.ROUTER:
        return n + 1
    return n + devcli.SWITCH_PORTS if port.startswith("Gigabit") else n


def build(lab, events: list[tuple[str, str, tuple | None]]) -> tuple[str, dict]:
    """The shell the router runs for a batch of (device, message, trap)
    events: each message numbered, stamped by the router's clock, echoed
    back (@@device text) for the buffer and sent to every logging host the
    device's trap level lets it reach; each trap (oid, ifindex, port) to
    every notification host. Returns (script, sequence numbers used)."""
    data = _buf_load(lab.name)
    seqs = {}
    out = [_HEAD]
    for dev, msg, trap in events:
        seq = int(data.get(dev, {}).get("seq", 0)) + seqs.get(dev, 0) + 1
        seqs[dev] = seqs.get(dev, 0) + 1
        host = shlex.quote(devcli.hostname(lab, dev))
        body = f'B="{seq}: {_STAMP_SH.get(stamp(lab, dev), "")}"{shlex.quote(msg)}'
        out += [body, f'echo "@@{dev} $B"']
        sev = severity(msg)
        pri = FACILITY_CODE.get(facility(lab, dev), 23) * 8 + sev
        if sev <= trap_level(lab, dev):
            for ip, port, fmt in log_hosts(lab, dev):
                head = f"'<{pri}>1 %s %s - - - - %s' \"$I\"" if fmt == "rfc5424" else f"'<{pri}>%s %s %s' \"$D\""
                out.append(f'(printf {head} {host} "$B" | nc -u -w1 {ip} {port}) >/dev/null 2>&1 &')
                out.append(f'echo "@@sent {dev} {ip}"; sleep 0.05 2>/dev/null')  # in order on the wire
        if trap and traps_on(lab, dev):
            oid, idx, port = trap
            for ip, ver, comm in trap_hosts(lab, dev):
                vb = (f"{IF_TABLE}.1.{idx} i {idx} {IF_TABLE}.2.{idx} s {shlex.quote(port)} "
                      f"{IF_TABLE}.7.{idx} i {1 if oid != LINK_DOWN or 'admin' not in msg else 2} "
                      f"{IF_TABLE}.8.{idx} i {2 if oid == LINK_DOWN else 1}") if idx else ""
                if ver == "2c":
                    cmd = f"snmptrap -v 2c -c {shlex.quote(comm)} {ip}:162 '' {oid} {vb}"
                else:
                    generic = {LINK_DOWN: 2, LINK_UP: 3}.get(oid, 6)
                    ent = "1.3.6.1.2.1.17" if oid in (NEW_ROOT, TOPO_CHANGE) else "1.3.6.1.4.1.8072.3.2.10"
                    spec = {NEW_ROOT: 1, TOPO_CHANGE: 2}.get(oid, 0)
                    cmd = f"snmptrap -v 1 -c {shlex.quote(comm)} {ip}:162 {ent} '' {generic} {spec} '' {vb}"
                out.append(f"({cmd}) >/dev/null 2>&1 &")
                out.append(f'echo "@@trap {dev} {ip}"')
    out.append("wait")
    return "\n".join(out), seqs


def record(lab_name: str, text: str, seqs: dict, fallback: list[tuple[str, str]] = ()) -> None:
    """Keeps what the router stamped (or, if it did not answer, the
    messages as they are) in the devices' buffers."""
    with _LOCK:
        data = _buf_load(lab_name)
        now = int(time.time())
        got = False
        for line in text.splitlines():
            if not line.startswith("@@"):
                continue
            head, _, rest = line[2:].partition(" ")
            if head in ("sent", "trap"):
                dev, _, ip = rest.partition(" ")
                d = data.setdefault(dev, {})
                key = "sent" if head == "sent" else "traps"
                d.setdefault(key, {})[ip] = d.get(key, {}).get(ip, 0) + 1
                continue
            got = True
            data.setdefault(head, {}).setdefault("lines", []).append([now, rest])
        if not got:
            for dev, msg in fallback:
                d = data.setdefault(dev, {})
                d.setdefault("lines", []).append([now, f"{int(d.get('seq', 0)) + 1}: {msg}"])
                d["seq"] = int(d.get("seq", 0)) + 1
        else:
            for dev, n in seqs.items():
                data.setdefault(dev, {})["seq"] = int(data[dev].get("seq", 0)) + n
        for d in data.values():
            if isinstance(d, dict) and "lines" in d:
                d["lines"] = d["lines"][-BUFFER:]
        _buf_save(lab_name, data)


def send(lab, events: list, runner=None, wait: bool = False) -> None:
    """Logs a batch of events: on the router (stamped, to the syslog servers
    and trap receivers) when it runs. In the background unless a runner is
    given or `wait` asks for it, so a console or the canvas never waits on
    the serial line."""
    if not events:
        return
    script, seqs = build(lab, events)
    fallback = [(d, m) for d, m, _ in events]

    def go():
        run, close = runner, None
        if run is None:
            from .cli import _fabric_runner
            run, _why = _fabric_runner(lab.name)
            close = getattr(run, "close", None)
        text = ""
        try:
            if run:
                text = run(script, timeout=30) or ""
        except Exception:  # the serial channel: a lost line still goes in the buffer
            text = ""
        finally:
            if close:
                close()
        record(lab.name, text, seqs, fallback)
    if runner is None and not _router_up(lab.name):
        record(lab.name, "", seqs, fallback)   # nothing to send it from: the buffer keeps it
    elif runner is not None or wait:
        go()
    else:
        threading.Thread(target=go, daemon=True).start()


def _router_up(lab_name: str) -> bool:
    from . import state
    st = state.load(lab_name)
    fab = st.nodes.get("fabric") if st else None
    return bool(fab and fab.serial_port and fab.pid and state.pid_alive(fab.pid))


def device_log(lab, device: str, line: str, runner=None) -> None:
    """For other parts of winlab (port security, DHCP snooping...): one
    %FAC-SEV-MNEMONIC line a device logs."""
    send(lab, [(device, line, None)], runner)


# ------------------------------------------------------------------ what happens
_SAID_RE = re.compile(r"^(?:[\w.-]+: )?(%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+:.*)$")


def _lines(out: str) -> list[str]:
    """The messages a command printed: a line that is one, or one a switch
    prefixed with its name (winlab/stp.py), never a buffer being shown."""
    return [m.group(1) for m in (_SAID_RE.match(raw.strip()) for raw in out.splitlines()) if m]


def heard(con, typed: str, out: str) -> None:
    """After a console line: the messages the device printed are its log;
    privileged logins and logouts are logged too. The link baseline then
    follows what the console did, so the canvas does not say it twice."""
    if not con.powered():
        return
    events = []
    word = typed.strip().split()[0].lower() if typed.strip() else ""
    if len(word) >= 2 and "enable".startswith(word) and con.s.mode == "enable":
        events.append((con.device, "%SYS-5-PRIV_AUTH_PASS: Privilege level set to 15 by console on console", None))
    if word in ("exit", "logout", "quit") and con.s.mode == "user":
        events.append((con.device, "%SYS-6-LOGOUT: User console has exited tty session 0(console)", None))
    shown = re.match(r"^(?:do\s+)?sh(?:ow?)?\s", typed.strip().lower() + " ")  # show, not shutdown
    for line in [] if shown else _lines(out):
        trap = None
        m = re.search(r"Interface (\S+), changed state to (administratively down|down|up)", line)
        if m and "%LINK-" in line:
            trap = (LINK_DOWN if "down" in m.group(2) else LINK_UP, if_index(con.device, m.group(1)), m.group(1))
        events.append((con.device, line, trap))
    if events:
        send(con.lab, events, con._runner_factory and (lambda *a, **k: _call(con, *a, **k)))
    try:
        _baseline(con.lab, con.plan)
    except Exception:  # never in the way of a console
        pass


def _call(con, script, timeout=30):
    run, _ = con._runner_factory()
    return run(script, timeout=timeout) if run else ""


_SEEN: dict[str, dict] = {}


def _ports_now(lab, plan) -> dict:
    """Every port a device logs about, and whether its link is up: the
    switches' machine ports (cable in, machine on, port not shut, card not
    dead), the router's ports (a switch cabled to it), and the switch
    cables' spanning tree state and root."""
    from . import physfaults, stp
    from .workbench import _running
    running = _running(lab.name)
    out: dict = {}
    if "fabric" not in running:
        return out
    for sid, links in devcli.switch_ports(lab, plan).items():
        own = _own(lab, f"sw:{sid}")
        for i, link in enumerate(links, 1):
            if link is None:
                continue
            up = (link.node_id in running and not own.get(f"shut:{link.label}")
                  and not physfaults.port_look(lab, link)["down"])
            out[f"link|{link.label}"] = (f"sw:{sid}", f"FastEthernet0/{i}", up)
    rown = _own(lab, devcli.ROUTER)
    for name, sw in devcli.router_ports(lab):
        if sw:
            up = devcli.uplinked(lab, sw) and not rown.get(f"shut:{name}")
            out[f"rport|{name}"] = (devcli.ROUTER, name, up)
    if stp.cables(lab):
        res = stp.compute(lab)
        for e, p in res.ports.items():
            out[f"stp|{e.sw}|{e.port}"] = (f"sw:{e.sw}", e.port, p.state)
        for s, b in res.bridges.items():
            if b.on:
                out[f"root|{s}"] = (f"sw:{s}", b.root_port, b.root)
    return out


def _baseline(lab, plan) -> None:
    with _LOCK:
        _SEEN[lab.name] = _ports_now(lab, plan)


def changes(lab, before: dict, now: dict) -> list[tuple[str, str, tuple | None]]:
    """What the devices log between two looks at their ports."""
    ev = []
    for key in sorted(set(before) | set(now)):
        kind = key.split("|")[0]
        old, new = before.get(key), now.get(key)
        if kind in ("link", "rport"):
            was = bool(old and old[2])
            up = bool(new and new[2])
            if was == up:
                continue
            dev, port = (new or old)[:2] if up else (old or new)[:2]
            word = "up" if up else "down"
            idx = if_index(dev, port)
            ev.append((dev, f"%LINK-3-UPDOWN: Interface {port}, changed state to {word}",
                       (LINK_UP if up else LINK_DOWN, idx, port)))
            ev.append((dev, f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {port}, changed state to {word}", None))
        elif kind == "stp" and old and new and old[2] != new[2]:
            names = {"FWD": "forwarding", "BLK": "blocking", "down": "disabled", "err": "err-disabled"}
            ev.append((new[0], f"%SPANTREE-6-PORT_STATE: Port {devcli.short_if(new[1])} instance 1 moving from "
                               f"{names.get(old[2], old[2])} to {names.get(new[2], new[2])}", None))
        elif kind == "root" and new and (not old or old[2] != new[2]):
            from . import stp
            mac = devcli.dotted_mac(stp.bridge_mac(lab, new[2])) if new[2] else "0000.0000.0000"
            via = f"New Root Port is {new[1]}" if new[1] else "This bridge is the new root"
            ev.append((new[0], f"%SPANTREE-5-ROOTCHANGE: Root Changed for vlan 1: {via}. New Root Mac Address is {mac}",
                       (NEW_ROOT if not new[1] else TOPO_CHANGE, 0, "")))
    return ev


def tick(dash, runner=None) -> list:
    """Looks at the ports again (the canvas asks every few seconds, and
    every change made on the bench): what changed is logged and sent."""
    lab = dash.lab
    try:
        now = _ports_now(lab, dash.plan)
    except Exception:  # a half-edited lab: look again next time
        return []
    with _LOCK:
        before = _SEEN.get(lab.name)
        _SEEN[lab.name] = now
    if before is None or not now:
        return []
    ev = changes(lab, before, now)
    send(lab, ev, runner)
    return ev


# ------------------------------------------------------------------ the canvas
def view(lab) -> dict:
    """What the router's panel shows (read only: it is set on the consoles)."""
    rows = []
    for dev in devices(lab):
        hosts = [f"{ip}:{p}" for ip, p, _ in log_hosts(lab, dev)]
        traps = [ip for ip, _, _ in trap_hosts(lab, dev)] if traps_on(lab, dev) else []
        ntp = ntp_servers(lab, dev)
        if hosts or traps or ntp or communities(lab, dev):
            rows.append({"device": dev, "name": devcli.hostname(lab, dev), "syslog": hosts,
                         "level": LEVELS[trap_level(lab, dev)], "traps": traps, "ntp": ntp,
                         "snmp": bool(communities(lab, dev)) and dev == devcli.ROUTER})
    return {"rows": rows, "drill": drill_view(lab), "drills": [{"id": k, "title": d.button} for k, d in DRILLS.items()]}


# ------------------------------------------------------------------ drills
class Drill:
    def __init__(self, id_, title, button, symptom, hints, fix):
        self.id, self.title, self.button, self.symptom, self.hints, self.fix = id_, title, button, symptom, hints, fix


DRILLS: dict[str, Drill] = {}


def _d(*a) -> None:
    DRILLS[a[0]] = Drill(*a)


_d("community", "The router's community no longer matches the collector's", "Hide an SNMP community fault",
   "the collector's snmpwalk of the router says Timeout: No Response, and its trap log stays quiet",
   ("SNMP v1/v2c has no error for a wrong community: the agent just does not answer. Compare what the "
    "collector asks with what the router has: show snmp community on the router.",
    "The community on the router is {bad}, one letter off what the collector uses ({good}); the trap host "
    "line sends {bad} too, so snmptrapd drops the traps (authCommunity names {good}).",
    "configure terminal, no snmp-server community {bad}, snmp-server community {good} ro, and "
    "snmp-server host {host} version 2c {good}."),
   "the community back as the collector knows it, on the agent and on the trap host line")
_d("acl", "An access list keeps the collector out of the router's SNMP agent", "Hide an SNMP access list fault",
   "snmpwalk from the collector times out; from another address it would answer",
   ("The agent answers some managers and not others: something filters by address. show snmp community "
    "on the router: is the community bound to an access list?",
    "Community {good} is bound to list {num}; show access-lists: it permits {wrong} only, not the "
    "collector {host}, and everything else meets the implicit deny.",
    "configure terminal, access-list {num} permit host {host} (or bind the community to no list: "
    "snmp-server community {good} ro)."),
   "the collector's address permitted by the community's access list")
_d("level", "The logging level filters the link-down away", "Hide a syslog level fault",
   "the collector gets configuration messages from {dev} but no word of a cable pulled or a port going down",
   ("The collector hears something from {dev}, so the path is fine: it is what the device chooses to send. "
    "show logging on {dev}: Trap logging: level ...",
    "%LINK-3-UPDOWN is severity 3 (errors); logging trap {lvl} sends only 0 to {lvln}.",
    "On {dev}: configure terminal, logging trap informational (6) or debugging (7)."),
   "logging trap informational, or at least errors, on the device")
_d("clock", "The router's clock is far off and its NTP server is unreachable", "Hide a clock fault",
   "the syslog lines carry a '*' and a time that is days away from the lab's; correlating them with the "
   "servers' logs is impossible",
   ("The messages arrive, but their time is wrong. show clock on the router, and show ntp status.",
    "show ntp associations: the router asks {nowhere}, which nobody in the lab is (reach 0), so its clock "
    "runs free and stays where it was set. The '*' before the time is IOS saying exactly that.",
    "configure terminal, no ntp server {nowhere}, ntp server {ntp} (the lab's time server). chrony steps the "
    "clock at its first answers; show ntp status says synchronized and the '*' is gone."),
   "the router's NTP pointed back at the lab's time server, and its clock in sync")


def _drill_path(lab_name: str):
    return paths.lab_dir(lab_name) / "nms-drill.json"


def drill_state(lab_name: str) -> dict | None:
    try:
        return json.loads(_drill_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _drill_save(lab_name: str, data: dict | None) -> None:
    state.save_json(_drill_path(lab_name), data)


def _words(lab, d: dict) -> dict:
    w = dict(d.get("w", {}))
    w.setdefault("nowhere", NOWHERE)
    if "dev" in w:
        w["dev"] = devcli.hostname(lab, w["dev"])
    return w


def drill_view(lab) -> dict | None:
    d = drill_state(lab.name)
    if not d:
        return None
    k = DRILLS[d["id"]]
    w = _words(lab, d)
    return {"id": k.id, "shown": int(d.get("hints", 0)), "of": len(k.hints),
            "hints": [h.format(**w) for h in k.hints[:int(d.get("hints", 0))]],
            "symptom": k.symptom.format(**w), "done": bool(d.get("done")),
            "title": k.title if d.get("done") else "", "fix": k.fix if d.get("done") else ""}


def act(dash, action: str, params: dict, runner=None) -> dict:
    try:
        if action == "wb-nms-drill":
            return drill(dash, str(params.get("op", "")), params, runner)
    except NmsError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown network management action {action!r}"}


def _collector(lab) -> str:
    for dev in devices(lab):
        for ip, _, _ in trap_hosts(lab, dev):
            return ip
    for dev in devices(lab):
        for ip, _, _ in log_hosts(lab, dev):
            return ip
    return ""


def _lab_ntp(lab) -> str:
    from . import timesync
    dev = timesync.ntp_device(lab)
    if dev is not None:
        return timesync.address(lab, dev)
    have = [ip for ip in ntp_servers(lab) if ip != NOWHERE]
    return have[0] if have else ""


def _router_run(lab, script: str, runner=None) -> str:
    run, close = runner, None
    if run is None:
        from .cli import _fabric_runner
        run, _ = _fabric_runner(lab.name)
        close = getattr(run, "close", None)
    if not run:
        return ""
    try:
        return run(script, timeout=60) or ""
    except Exception:  # the serial channel: the next start renders it anyway
        return ""
    finally:
        if close:
            close()


def drill(dash, op: str, params: dict, runner=None) -> dict:
    from .workbench import _running, _save
    lab = dash.lab
    d = drill_state(lab.name)
    if op == "start":
        if d and not d.get("done"):
            raise NmsError("a fault is already hidden in this network: find it, or give up")
        return _drill_start(dash, str(params.get("id") or "") or random.choice(sorted(DRILLS)), runner)
    if not d:
        raise NmsError("no network management fault in this network")
    k = DRILLS[d["id"]]
    if op == "hint":
        d["hints"] = min(len(k.hints), int(d.get("hints", 0)) + 1)
        _drill_save(lab.name, d)
        return {"ok": True, "message": k.hints[d["hints"] - 1].format(**_words(lab, d))}
    if op == "check":
        res = check(lab, d, runner)
        if res["passed"]:
            d["done"] = True
            _drill_save(lab.name, d)
        return res
    if op in ("undo", "close"):
        if op == "undo" and not d.get("done"):
            for key, v in d.get("was", {}).items():
                dev, k_ = key.split("|", 1)
                own = lab.devices.setdefault(dev, {})
                if v is None:
                    own.pop(k_, None)
                else:
                    own[k_] = v
            _save(dash)
            _drill_save(lab.name, None)
            if "fabric" in _running(lab.name):
                fix = f"date -s @$(( $(date +%s) - {int(d.get('skew', 0))} )) >/dev/null 2>&1; " if d["id"] == "clock" else ""
                _router_run(dash.lab, fix + push_script(dash.lab), runner)
            return {"ok": True, "message": f"put back: it was {k.title[0].lower() + k.title[1:]}"}
        _drill_save(lab.name, None)
        return {"ok": True, "message": ""}
    raise NmsError(f"unknown drill step {op!r}")


def _drill_start(dash, did: str, runner=None) -> dict:
    from .workbench import _running, _save
    lab = dash.lab
    if did not in DRILLS:
        raise NmsError(f"no drill {did!r}")
    was: dict = {}
    w: dict = {}
    skew = 0

    def put(dev, key, val):
        own = lab.devices.setdefault(dev, {})
        was.setdefault(f"{dev}|{key}", own.get(key))
        if val is None:
            own.pop(key, None)
        else:
            own[key] = val
    R = devcli.ROUTER
    if did in ("community", "acl"):
        comms = [c for c in communities(lab, R)]
        host = _collector(lab)
        if not comms or not host:
            raise NmsError("set up SNMP first: on the router, snmp-server community <name> ro and "
                           "snmp-server host <collector> version 2c <name>")
        name, how, num = comms[0]
        w.update(good=name, host=host)
        if did == "community":
            bad = _near(name)
            put(R, f"snmp-comm:{name}", None)
            put(R, f"snmp-comm:{bad}", f"{how} {num}".strip())
            for ip, ver, comm in trap_hosts(lab, R):
                if comm == name:
                    put(R, f"snmp-host:{ip}", f"{ver} {bad}")
            w["bad"] = bad
        else:
            num = next(str(n) for n in range(98, 0, -1) if not _own(lab, R).get(f"acl:{n}"))
            wrong = str(ipaddress.IPv4Address(host) + 7)
            put(R, f"acl:{num}", f"permit {wrong}/32")
            put(R, f"snmp-comm:{name}", f"{how} {num}")
            w.update(num=num, wrong=wrong)
    elif did == "level":
        devs = [x for x in devices(lab) if log_hosts(lab, x)]
        if not devs:
            raise NmsError("set up syslog first: logging host <collector> on a switch or the router")
        dev = next((x for x in devs if x != R), devs[0])
        put(dev, "log-trap", "2")
        w.update(dev=dev, lvl="critical", lvln="2 (critical)")
    else:
        ntp = _lab_ntp(lab)
        if not ntp:
            raise NmsError("this lab has no time server for the router to follow: add an NTP server from the "
                           "shelf first")
        for dev in devices(lab):
            for ip in ntp_servers(lab, dev):
                put(dev, f"ntp:{ip}", None)
        put(R, f"ntp:{NOWHERE}", "yes")
        skew = random.choice((3, -2, 5)) * 86400 + random.randint(600, 3000)
        w.update(ntp=ntp)
    _save(dash)
    _drill_save(lab.name, {"id": did, "w": w, "was": was, "hints": 0, "skew": skew, "at": int(time.time())})
    if "fabric" in _running(lab.name):
        fix = f"date -s @$(( $(date +%s) + {skew} )) >/dev/null 2>&1; " if skew else ""
        _router_run(dash.lab, fix + push_script(dash.lab), runner)
    return {"ok": True, "message": "something in the network's management is broken; find it from the "
                                   "collector and the consoles, then Check my fix"}


def _near(name: str) -> str:
    swap = {"l": "1", "i": "1", "o": "0", "e": "3", "a": "4", "s": "5"}
    for i, ch in enumerate(name):
        if ch.lower() in swap:
            return name[:i] + swap[ch.lower()] + name[i + 1:]
    return name + "1"


def check(lab, d: dict, runner=None) -> dict:
    """Check my fix: the consoles' settings, and while the router runs its
    own daemons (snmpd's configuration, chrony's tracking, its clock)."""
    from . import labclock
    from .workbench import _running
    w = d.get("w", {})
    R = devcli.ROUTER
    rows = []
    live = "fabric" in _running(lab.name)
    if d["id"] == "community":
        good = w.get("good", "")
        rows.append((f"the router's agent answers community {good}", any(c == good for c, _, _ in communities(lab, R))))
        rows.append(("the trap host line sends that community",
                     all(c == good for _, _, c in trap_hosts(lab, R)) and bool(trap_hosts(lab, R))))
    elif d["id"] == "acl":
        good, host = w.get("good", ""), w.get("host", "")
        comm = next(((h, n) for c, h, n in communities(lab, R) if c == good), None)
        rows.append((f"community {good} is there", comm is not None))
        rows.append((f"{host} may ask with it", comm is not None and acl_allows(lab, comm[1], host)))
    elif d["id"] == "level":
        dev = d.get("w", {}).get("dev", R)
        rows.append((f"{devcli.hostname(lab, dev)} sends errors (a link going down) to its syslog server",
                     trap_level(lab, dev) >= 3 and bool(log_hosts(lab, dev))))
    else:
        servers = ntp_servers(lab)
        rows.append(("the router follows a time server in the lab",
                     bool(servers) and NOWHERE not in servers))
        if live:
            text = _router_run(lab, "chronyc -n tracking 2>&1; echo \"#now $(date +%s)\"", runner)
            from . import timesync
            synced = timesync.parse_tracking(text.partition("#now")[0]).get("synced", False)
            m = re.search(r"#now (\d+)", text)
            off = abs(int(m.group(1)) - labclock.load(lab.name).now()) if m else 1e9
            rows.append(("chrony on the router is in sync", synced))
            rows.append(("the router's clock is on lab time (within a minute)", off < 60))
    passed = all(ok for _, ok in rows)
    k = DRILLS[d["id"]]
    msg = (f"fixed: it was {k.title[0].lower() + k.title[1:]}. The fix: {k.fix}." if passed else
           "not yet: " + "; ".join(t for t, ok in rows if not ok))
    return {"ok": True, "passed": passed, "message": msg,
            "results": [{"check": t, "passed": ok} for t, ok in rows]}
