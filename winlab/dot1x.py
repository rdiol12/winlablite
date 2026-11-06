"""802.1X on the workbench's switches: a port that lets a machine in only
once a RADIUS server says who it is.

The three parties are real. The supplicant is the machine: Windows' Wired
AutoConfig service (dot3svc), which the student starts and sets up on the
network card's Authentication tab. The authenticator is the switch port: on
the router, where every machine's cable is a port of its bridge
(winlab/netplan.py), hostapd's wired driver runs on that port, speaks EAPOL
with the machine and RADIUS with the server, one hostapd a port. The
authentication server is the student's own: NPS on a Windows Server, or
FreeRADIUS on a Linux machine, set up inside the lab by hand; the switch
only knows its address and the shared key.

Until the server says yes the port passes nothing but EAPOL: an nftables
rule on the router's bridge (the bridge family, the switch's own layer)
drops every frame from an address hostapd has not authorized, and
hostapd's action script adds the address once it has (portsec.TABLE,
dx_<port>). RADIUS leaves the router from its address on the server's
network: that is the address the server must know as its RADIUS client.

hostapd is one of the fabric's Alpine packages (alpineovl.FABRIC_PACKAGES),
fetched on the user's PC with ``winlab images prepare fabric``, never
bundled. The console's settings live with the switch's others in the lab
file ([devices."sw:<id>"]): aaa, aaa-dot1x, dot1x-sys, radius:<name> (the
address and ports), radius-key:<name>, and per port dx-ctl:<port> and
dx-pae:<port>.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

from . import devcli

CTRL = "/run/hostapd"
CONTROLS = ("auto", "force-authorized", "force-unauthorized")
AUTH_PORT, ACCT_PORT = 1812, 1813
KEY_RE = re.compile(r"^[!-~]{1,63}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
MISSING = ("hostapd is not on the router: run 'winlab images prepare fabric' on this PC to fetch the "
           "fabric's packages again, then start the network again")


def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


# ------------------------------------------------------------------ settings
def servers(lab, sw: str) -> list[dict]:
    """The switch's RADIUS servers, in the order they were typed in."""
    own, out = _own(lab, sw), []
    for k, v in own.items():
        if k.startswith("radius:"):
            name = k[7:]
            ip, auth, acct = (v.split() + ["", "", ""])[:3]
            out.append({"name": name, "ip": ip, "auth": int(auth or AUTH_PORT), "acct": int(acct or ACCT_PORT),
                        "key": own.get(f"radius-key:{name}", "")})
    return out


def enabled(lab, sw: str) -> bool:
    """aaa new-model, aaa authentication dot1x and dot1x system-auth-control:
    what a switch needs before any port asks a server."""
    own = _own(lab, sw)
    return bool(own.get("aaa") and own.get("aaa-dot1x") and own.get("dot1x-sys"))


def control(lab, sw: str, key: str) -> str:
    """A port's authentication port-control: "" when it has none (the
    port forwards as any port)."""
    return _own(lab, sw).get(f"dx-ctl:{key}", "")


def pae(lab, sw: str, key: str) -> bool:
    return bool(_own(lab, sw).get(f"dx-pae:{key}"))


def enforced(lab, sw: str, key: str) -> str:
    """What the port does: "auto" (only EAPOL until the server says yes),
    "closed" (force-unauthorized), or "" (it forwards)."""
    ctl = control(lab, sw, key)
    if not ctl or ctl == "force-authorized" or not _own(lab, sw).get("dot1x-sys"):
        return ""
    return "closed" if ctl == "force-unauthorized" else "auto"


def source_ip(plan, ip: str) -> str:
    """The router's address on the network a RADIUS server is on: where its
    requests come from, so what the server must list as its client."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return ""
    for seg in plan.segments.values():
        net = seg.network
        if net.routed and addr in net.net:
            return net.router_ip
    return ""


# ------------------------------------------------------------------ the router
def conf(plan, sw: str, iface: str) -> str:
    """hostapd's configuration for one port: the wired driver, 802.1X, the
    switch's RADIUS servers in order."""
    lab = plan.lab
    srv = [s for s in servers(lab, sw) if s["ip"] and s["key"]]
    src = next((source_ip(plan, s["ip"]) for s in srv if source_ip(plan, s["ip"])), "")
    out = [f"# {devcli.hostname(lab, 'sw:' + sw)}: 802.1X on {iface} (winlab/dot1x.py)",
           f"interface={iface}", "driver=wired", "ieee8021x=1", "eapol_version=2", "use_pae_group_addr=1",
           "eap_reauth_period=3600", f"ctrl_interface={CTRL}",
           f"nas_identifier={devcli.hostname(lab, 'sw:' + sw)}",
           "logger_syslog=-1", "logger_syslog_level=2", "logger_stdout=-1", "logger_stdout_level=2"]
    if src:
        out += [f"own_ip_addr={src}", f"radius_client_addr={src}"]
    for s in srv:
        out += [f"auth_server_addr={s['ip']}", f"auth_server_port={s['auth']}",
                f"auth_server_shared_secret={s['key']}"]
    return "\n".join(out) + "\n"


ACT_SH = """#!/bin/sh
# hostapd_cli -a calls this: <port> <event> <address>. An address the RADIUS
# server accepted is let through the port (winlab/dot1x.py).
echo "$(date +%s) $1 $2 $3" >> {run}/events
case "$2" in
AP-STA-CONNECTED) nft add element bridge {table} dx_$1 "{{ $3 }}" 2>/dev/null ;;
AP-STA-DISCONNECTED) nft delete element bridge {table} dx_$1 "{{ $3 }}" 2>/dev/null ;;
esac
"""


def render(plan, ports: list, run: str, table: str) -> tuple[list[str], list[str]]:
    """(lines before the port table is built, lines after) for the ports
    that run 802.1X: hostapd a port, started again only when its settings
    changed (otherwise the sessions and the addresses let through stay)."""
    want = [p for p in ports if p.iface and p.dx == "auto" and pae(plan.lab, p.sw, p.key) and enabled(plan.lab, p.sw)]
    confs = {p.iface: conf(plan, p.sw, p.iface) for p in want}
    if not confs:
        return ([f"for f in {run}/hapd-*.pid; do [ -e \"$f\" ] && kill $(cat \"$f\") 2>/dev/null; done; "
                 f"rm -f {run}/hapd-* {run}/hapd.sum; true"], [])
    total = hashlib.sha256("".join(confs[k] for k in sorted(confs)).encode()).hexdigest()[:16]
    pre = [f"# 802.1X: hostapd's wired driver on {', '.join(sorted(confs))}",
           # (kept only while every hostapd is still alive)
           f"if [ \"$(cat {run}/hapd.sum 2>/dev/null)\" = {total} ]"
           + "".join(f" && kill -0 $(cat {run}/hapd-{i}.pid 2>/dev/null) 2>/dev/null" for i in sorted(confs))
           + "; then keep=1; else keep=0; fi",
           # what hostapd let in, kept across the port table being built again
           f"if [ $keep = 1 ]; then for s in $(nft list sets bridge 2>/dev/null | grep -o 'dx_[A-Za-z0-9]*'); do "
           f"nft list set bridge {table} $s 2>/dev/null | tr -d '\\n\\t' | sed -n 's/.*elements = {{\\([^}}]*\\)}}.*/\\1/p' "
           f"> {run}/$s.keep; done; fi"]
    post = [f"cat > {run}/act.sh <<'WINLAB_EOF'", ACT_SH.format(run=run, table=table).rstrip("\n"), "WINLAB_EOF",
            f"chmod +x {run}/act.sh",
            f"if [ $keep = 1 ]; then for f in {run}/dx_*.keep; do [ -s \"$f\" ] && nft add element bridge {table} "
            f"$(basename $f .keep) \"{{ $(cat $f) }}\" 2>/dev/null; done; fi; rm -f {run}/dx_*.keep",
            "if [ $keep = 0 ]; then",
            f"  for f in {run}/hapd-*.pid; do [ -e \"$f\" ] && kill $(cat \"$f\") 2>/dev/null; done",
            # (hostapd and its hostapd_cli by their pid files: the router runs this
            # as sh -c, so a pkill -f pattern would match this very script)
            f"  mkdir -p {CTRL}",
            f"  command -v hostapd >/dev/null || echo \"$(date +%s) - hostapd-missing -\" >> {run}/events"]
    for p in want:
        i = p.iface
        post += [f"  cat > {run}/hapd-{i}.conf <<'WINLAB_EOF'", confs[i].rstrip("\n"), "WINLAB_EOF",
                 f"  hostapd -B -P {run}/hapd-{i}.pid {run}/hapd-{i}.conf >> {run}/hostapd.log 2>&1",
                 f"  hostapd_cli -p {CTRL} -i {i} -a {run}/act.sh -B -P {run}/hapd-{i}.cli.pid >/dev/null 2>&1"]
    post += ["  sleep 1"]
    # Ask the machines already on the ports who they are, as a switch does
    # when the port comes up (Wired AutoConfig answers an EAP request).
    for p in want:
        post.append(f"  hostapd_cli -p {CTRL} -i {p.iface} new_sta {p.link.mac.lower()} >/dev/null 2>&1   # {p.short}")
    post += [f"  echo {total} > {run}/hapd.sum", "fi; true"]
    return pre, post


def live_cmd(ifaces: list[str]) -> str:
    return "".join(f"echo '#sta {i}'; hostapd_cli -p {CTRL} -i {i} all_sta 2>/dev/null; "
                   f"echo '#mib {i}'; hostapd_cli -p {CTRL} -i {i} mib 2>/dev/null; " for i in ifaces)


_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def parse(text: str) -> dict:
    """hostapd_cli's all_sta and mib per port: {iface: {"sta": {mac: {k: v,
    "authorized": bool}}, "mib": {k: v}}}."""
    out: dict = {}
    cur, kind, mac = None, "", ""
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.match(r"^#(sta|mib) (\S+)$", line)
        if m:
            kind, cur, mac = m.group(1), out.setdefault(m.group(2), {"sta": {}, "mib": {}}), ""
            continue
        if line.startswith("#"):
            cur = None
            continue
        if cur is None or not line:
            continue
        if kind == "sta" and _MAC.match(line.lower()):
            mac = line.lower()
            cur["sta"][mac] = {"authorized": False}
        elif "=" in line:
            k, v = line.split("=", 1)
            if kind == "sta" and mac:
                cur["sta"][mac][k] = v
                if k == "flags":
                    cur["sta"][mac]["authorized"] = "[AUTHORIZED]" in v
            elif kind == "mib":
                cur["mib"][k] = v
    return out


def session_state(sta: dict) -> tuple[str, str]:
    """(Auth | Unauth | Running, what it means) for one hostapd station."""
    def n(k):
        try:
            return int(sta.get(k, "0"))
        except ValueError:
            return 0
    if sta.get("authorized"):
        return "Auth", "Authz Success"
    if n("dot1xAuthBackendAuthFails"):
        return "Unauth", "Authz Failed: the RADIUS server rejected it (user, password, or no network policy grants it)"
    if sta.get("dot1xAuthSessionUserName") and not n("dot1xAuthBackendAccessChallenges"):
        return "Running", ("no answer from the RADIUS server: a wrong shared key, the server not listing this "
                           "router as a RADIUS client, or the server off; the switch retries, the server drops "
                           "what it cannot verify")
    if not sta.get("dot1xAuthSessionUserName"):
        return "Unauth", "the machine never answered EAP: Wired AutoConfig is off, or 802.1X is not on its network card"
    return "Running", "authenticating"


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    R = ("config-radius-server",)
    add("aaa new-model", lambda a: _flag(con, "aaa", True), "Enable NEW access control commands and functions", C)
    add("no aaa new-model", lambda a: _flag(con, "aaa", False), "Negate a command or set its defaults", C)
    add("aaa authentication dot1x <line>", lambda a: _aaa_dot1x(con, a[0]), "Set authentication lists for IEEE 802.1x", C)
    add("no aaa authentication dot1x <line>", lambda a: _flag(con, "aaa-dot1x", False), "Negate a command or set its defaults", C)
    add("dot1x system-auth-control", lambda a: _flag(con, "dot1x-sys", True), "Enable or Disable SysAuthControl", C)
    add("no dot1x system-auth-control", lambda a: _flag(con, "dot1x-sys", False), "Negate a command or set its defaults", C)
    add("radius server <name>", lambda a: _server(con, a[0]), "Server configuration", C)
    add("no radius server <name>", lambda a: _no_server(con, a[0]), "Negate a command or set its defaults", C)
    add("address ipv4 <ip>", lambda a: _address(con, a[0], ""), "IPv4 address for the RADIUS server", R)
    add("address ipv4 <ip> <line>", lambda a: _address(con, a[0], a[1]), "IPv4 address for the RADIUS server", R)
    add("key <line>", lambda a: _key(con, a[0]), "Per-server encryption key", R)
    add("no key", lambda a: _key(con, ""), "Negate a command or set its defaults", R)
    add("exit", con._cfg_exit, "Exit from RADIUS server configuration mode", R)
    add("end", con._end, "Exit to privileged EXEC mode", R)
    add("do <line>", con._do, "To run exec commands in config mode", R)
    add("authentication port-control <line>", lambda a: _control(con, a[0]), "set the port-control value", I)
    add("no authentication port-control", lambda a: _control(con, ""), "Negate a command or set its defaults", I)
    add("dot1x port-control <line>", lambda a: _control(con, a[0]), "set the port-control value (older IOS)", I)
    add("dot1x pae authenticator", lambda a: _pae(con, True), "Set 802.1x interface pae type", I)
    add("no dot1x pae", lambda a: _pae(con, False), "Negate a command or set its defaults", I)
    add("no dot1x pae authenticator", lambda a: _pae(con, False), "Negate a command or set its defaults", I)
    add("show authentication sessions", lambda a: show_sessions(con, ""), "Shows Auth Manager sessions", U)
    add("show authentication sessions interface <line>", lambda a: show_sessions(con, a[0]),
        "Shows Auth Manager sessions on an interface", U)
    add("show dot1x all", lambda a: show_dot1x(con), "IEEE 802.1X status on every port", U)
    add("show radius server-group all", lambda a: show_servers(con), "RADIUS servers and their counters", U)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def _done(con) -> str:
    from . import portsec
    return portsec.done(con)


def _flag(con, key: str, on: bool) -> str:
    if on:
        _mine(con)[key] = "yes"
    else:
        _mine(con).pop(key, None)
    return _done(con)


def _aaa_dot1x(con, text: str) -> str:
    w = text.lower().split()
    if not _mine(con).get("aaa"):
        raise devcli.CliError("% AAA commands are not available: type aaa new-model first")
    if w[:3] != ["default", "group", "radius"]:
        raise devcli.CliError("% Invalid input: aaa authentication dot1x default group radius")
    return _flag(con, "aaa-dot1x", True)


def _server(con, name: str) -> str:
    if not NAME_RE.match(name):
        raise devcli.CliError("% A server name: letters, digits, - _ . (up to 32)")
    own = _mine(con)
    own.setdefault(f"radius:{name}", "")
    con.s.mode, con.s.ctx = "config-radius-server", name
    _done(con)
    return ""


def _no_server(con, name: str) -> str:
    own = _mine(con)
    if own.pop(f"radius:{name}", None) is None:
        raise devcli.CliError(f"% No RADIUS server {name}")
    own.pop(f"radius-key:{name}", None)
    return _done(con)


def _address(con, ip: str, rest: str) -> str:
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise devcli.CliError(f"% Invalid IPv4 address: {ip}") from None
    auth, acct = AUTH_PORT, ACCT_PORT
    w = rest.lower().split()
    while w:
        if len(w) < 2 or w[0] not in ("auth-port", "acct-port") or not w[1].isdigit() or not 0 < int(w[1]) < 65536:
            raise devcli.CliError("% Invalid input: address ipv4 <ip> [auth-port <port>] [acct-port <port>]")
        if w[0] == "auth-port":
            auth = int(w[1])
        else:
            acct = int(w[1])
        w = w[2:]
    _mine(con)[f"radius:{con.s.ctx}"] = f"{ip} {auth} {acct}"
    out = _done(con)
    src = source_ip(con.plan, ip)
    note = (f"% RADIUS requests to {ip} leave the router from {src}: on the server, the RADIUS client's "
            f"address is {src}" if src else
            f"% {ip} is on no network the router routes: the switch cannot reach it (cable that network to "
            f"the router)")
    return "\n".join(x for x in (out, note) if x)


def _key(con, text: str) -> str:
    own, name = _mine(con), con.s.ctx
    if not text:
        own.pop(f"radius-key:{name}", None)
        return _done(con)
    w = text.split()
    if len(w) == 2 and w[0] in ("0", "6", "7"):
        if w[0] != "0":
            raise devcli.CliError("% Only a clear-text key here (key <text>, or key 0 <text>)")
        w = w[1:]
    if len(w) != 1 or not KEY_RE.match(w[0]):
        raise devcli.CliError("% A shared key: 1 to 63 printable characters, no spaces")
    own[f"radius-key:{name}"] = w[0]
    return _done(con)


def _port(con) -> str:
    from . import portsec
    if not con.s.ctx.startswith("FastEthernet"):
        raise devcli.CliError("% 802.1X is for the ports machines are in (Fa0/1 to Fa0/24); the gigabit "
                              "ports are trunks to the router and other switches")
    return portsec.write_key(con)


def _control(con, how: str) -> str:
    key = _port(con)
    own = _mine(con)
    how = how.strip().lower()
    if not how:
        own.pop(f"dx-ctl:{key}", None)
        return _done(con)
    hit = [c for c in CONTROLS if c.startswith(how)]
    if len(hit) != 1:
        raise devcli.CliError("% Invalid input: authentication port-control auto | force-authorized | "
                              "force-unauthorized")
    own[f"dx-ctl:{key}"] = hit[0]
    out = _done(con)
    if hit[0] == "auto":
        lacks = [w for w, ok in (("aaa new-model", own.get("aaa")),
                                 ("aaa authentication dot1x default group radius", own.get("aaa-dot1x")),
                                 ("dot1x system-auth-control", own.get("dot1x-sys")),
                                 ("dot1x pae authenticator on this port", pae(con.lab, _sw(con), key)))
                 if not ok]
        if lacks:
            out = (out + "\n" if out else "") + "% Not yet asking a server: " + "; ".join(lacks)
    return out


def _pae(con, on: bool) -> str:
    key = _port(con)
    if on:
        _mine(con)[f"dx-pae:{key}"] = "yes"
    else:
        _mine(con).pop(f"dx-pae:{key}", None)
    return _done(con)


# ---- show
def _live(con) -> dict:
    from . import portsec
    return portsec.live_of(con).get("dot1x", {})


def show_sessions(con, text: str) -> str:
    from . import portsec
    lab, sw = con.lab, _sw(con)
    want = devcli.parse_if(text, con._if_names()) if text else ""
    live = _live(con)
    rows = []
    for p in portsec.ports_of(lab, con.plan, sw):
        if want and p.name != want:
            continue
        if not p.dx:
            continue
        stas = live.get(p.iface, {}).get("sta", {}) if p.iface else {}
        if not stas and p.dx == "auto":
            rows.append((p, p.link.mac.lower() if con.powered() else "", {}, "Unauth",
                         "no EAPOL from the machine yet" if con.powered() else "the network is off"))
        for mac, sta in sorted(stas.items()):
            st, why = session_state(sta)
            rows.append((p, mac, sta, st, why))
        if p.dx == "closed":
            rows.append((p, p.link.mac.lower(), {}, "Unauth", "authentication port-control force-unauthorized"))
    if want:
        if not rows:
            return f"No sessions match supplied criteria on {devcli.short_if(want)}."
        out = []
        for p, mac, sta, st, why in rows:
            user = sta.get("dot1xAuthSessionUserName", "")
            out += [f"{'Interface':>21}:  {p.name}", f"{'MAC Address':>21}:  {devcli.dotted_mac(mac) if mac else 'Unknown'}",
                    f"{'User-Name':>21}:  {user or 'Unknown'}",
                    f"{'Status':>21}:  {why if st != 'Auth' else 'Authz Success'}",
                    f"{'Domain':>21}:  {'DATA' if st == 'Auth' else 'UNKNOWN'}",
                    f"{'Oper host mode':>21}:  single-host", f"{'Oper control dir':>21}:  both",
                    f"{'Authorized By':>21}:  {'Authentication Server' if st == 'Auth' else 'n/a'}",
                    f"{'Common Session ID':>21}:  {sta.get('dot1xAuthSessionId', 'n/a')}",
                    "Runnable methods list:", "       Method   State",
                    f"       dot1x    {'Authc Success' if st == 'Auth' else 'Authc Failed' if st == 'Unauth' else 'Running'}",
                    ""]
        return "\n".join(out).rstrip()
    if not rows:
        return "No sessions currently exist"
    out = [f"{'Interface':<13}{'MAC Address':<16}{'Method':<8}{'Domain':<9}{'Status':<8}Session ID"]
    notes = []
    for p, mac, sta, st, why in rows:
        out.append(f"{p.short:<13}{devcli.dotted_mac(mac) if mac else 'Unknown':<16}{'dot1x':<8}"
                   f"{'DATA' if st == 'Auth' else 'UNKNOWN':<9}{st:<8}{sta.get('dot1xAuthSessionId', '')}")
        if st != "Auth":
            notes.append(f"% {p.short}: {why}")
    if not live and con.powered():
        notes.append("% (could not read hostapd on the router just now)")
    return "\n".join(out + notes)


def show_dot1x(con) -> str:
    from . import portsec
    lab, sw = con.lab, _sw(con)
    own = _own(lab, sw)
    out = [f"Sysauthcontrol              {'Enabled' if own.get('dot1x-sys') else 'Disabled'}",
           "Dot1x Protocol Version            2", ""]
    for p in portsec.ports_of(lab, con.plan, sw):
        ctl = control(lab, sw, p.key)
        if not ctl and not pae(lab, sw, p.key):
            continue
        out += [f"Dot1x Info for {p.name}", "-----------------------------------",
                f"PAE                       = {'AUTHENTICATOR' if pae(lab, sw, p.key) else 'NONE'}",
                f"PortControl               = {(ctl or 'force-authorized').upper().replace('-', '_')}",
                "ControlDirection          = Both", "HostMode                  = SINGLE_HOST",
                "QuietPeriod               = 60", "ServerTimeout             = 30", "ReAuthPeriod              = 3600", ""]
    return "\n".join(out).rstrip()


def show_servers(con) -> str:
    lab, sw = con.lab, _sw(con)
    srv = servers(lab, sw)
    if not srv:
        return "% No RADIUS server: radius server <name>, then address ipv4 <ip> auth-port 1812 and key <key>"
    live = _live(con)
    mib = next((v["mib"] for v in live.values() if v.get("mib")), {})
    out = ["Server group radius", f"    Sharecount: 1  sg_unconfigured: FALSE", f"    Type: standard  Memlocks: 1"]
    for s in srv:
        src = source_ip(con.plan, s["ip"]) if s["ip"] else ""
        out += [f"    Server({s['ip'] or 'no address'}:{s['auth']},{s['acct']}) name {s['name']}",
                f"      Key: {'set' if s['key'] else 'not set (key <text>)'}",
                f"      Requests leave from: {src or 'nowhere: the router routes no network with this address'}"]
    if mib:
        def g(k):
            return mib.get(k, "0")
        out += ["    Counters (the router's hostapd):",
                f"      Access-Requests {g('radiusAuthClientAccessRequests')}, retransmissions "
                f"{g('radiusAuthClientAccessRetransmissions')}, timeouts {g('radiusAuthClientTimeouts')}",
                f"      Access-Accepts {g('radiusAuthClientAccessAccepts')}, Access-Rejects "
                f"{g('radiusAuthClientAccessRejects')}, Access-Challenges {g('radiusAuthClientAccessChallenges')}",
                f"      bad authenticators {g('radiusAuthClientBadAuthenticators')}"]
        if g("radiusAuthClientTimeouts") != "0" and g("radiusAuthClientAccessChallenges") == "0":
            out.append("% Requests and no answer: the server drops what it cannot verify. Check the shared key "
                       "on both sides and the RADIUS client's address on the server.")
    return "\n".join(out)


def run_lines(lab, sw: str) -> list[str]:
    """Global lines for show running-config."""
    own, out = _own(lab, sw), []
    if own.get("aaa"):
        out += ["aaa new-model", "!"]
        if own.get("aaa-dot1x"):
            out += ["aaa authentication dot1x default group radius", "!"]
    if own.get("dot1x-sys"):
        out += ["dot1x system-auth-control", "!"]
    for s in servers(lab, sw):
        out.append(f"radius server {s['name']}")
        if s["ip"]:
            out.append(f" address ipv4 {s['ip']} auth-port {s['auth']} acct-port {s['acct']}")
        if s["key"]:
            out.append(f" key {s['key']}")
        out.append("!")
    return out


def iface_lines(lab, sw: str, key: str) -> list[str]:
    out = []
    ctl = control(lab, sw, key)
    if ctl:
        out.append(f" authentication port-control {ctl}")
    if pae(lab, sw, key):
        out.append(" dot1x pae authenticator")
    return out
