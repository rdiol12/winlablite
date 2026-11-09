"""AAA for logins to the router and the switches: RADIUS and TACACS+.

``aaa new-model`` turns the old line passwords off and method lists on.
``aaa authentication login default group radius local`` says how a login is
checked: ask the RADIUS servers first, and only when none of them answers
(not when one says no) the local user list. ``login authentication <list>``
under ``line vty 0 4`` or ``line con 0`` picks a named list instead of the
default. ``aaa authorization exec default group tacacs+ local`` asks, after
the login, which privilege level the user's session starts at; without it a
login lands at level 1 (user EXEC), even a local user of privilege 15, as on
IOS. ``tacacs server <name>`` with ``address ipv4`` and ``key``, and
``radius server <name>`` (the same command 802.1X uses, winlab/dot1x.py), say
where the servers are; ``test aaa group radius <user> <password> legacy``
asks one without logging in; ``show aaa servers`` and ``show tacacs`` count
what was asked and answered.

How it is real. The servers are the student's own, set up inside the lab by
hand: NPS or FreeRADIUS (the ``freeradius`` pack) for RADIUS; the router
knows only their address and the shared key. For TACACS+:
tac_plus-ng, built by the student from the source on the ``tacacs`` pack's
stick (winlab/tacacs.py: no distribution packages a TACACS+ server any more),
or any other TACACS+ server a lab machine runs. Each check is one real exchange with the server: the
request is built here (RADIUS: an Access-Request with the password hidden
as RFC 2865 says and a Message-Authenticator, RFC 3579; TACACS+: an ASCII
login START and its CONTINUE with the password, then for authorization an
AUTHOR REQUEST for service=shell, every body obfuscated with the key, RFC
8907) and sent from the router with nc, from the router's own address on the
server's network, or for a switch from inside its management namespace
(winlab/iosl2.py), so from the switch's own address; the answer comes back
the same way and is checked here (the Response Authenticator, the
Message-Authenticator, the TACACS+ body's lengths). An answer that does not
verify, the sign of a wrong shared key, counts as no answer at all, as on
IOS: the next method of the list is tried, so ``group radius local`` falls
back to the local users.

Command authorization and accounting (TACACS+). ``aaa authorization
commands 15 default group tacacs+ local`` asks the server about every level
15 command a vty session types before it runs (an AUTHOR REQUEST with
service=shell, cmd= and a cmd-arg for each word, the keywords spelled out
as IOS does); a no is "Command authorization failed.", no answer moves to
the next method (local: the user's own privilege). Commands typed at the #
prompt and in configuration mode are level 15, except the level 1 ones IOS
ships (show, ping, traceroute, terminal ...); ``no aaa authorization
config-commands`` leaves configuration mode out, and the console is asked
only after ``aaa authorization console``, as on IOS. ``aaa accounting exec
default start-stop group tacacs+`` sends a start record when a session
logs in and a stop record when it exits; ``aaa accounting commands 15
default stop-only group tacacs+`` (or start-stop) a stop record for each
command, with its task_id, priv-lvl and cmd. Lines replayed from a file
(copy tftp: running-config) are not authorized or accounted line by line.

What is not as on IOS, and why. A request is sent once with a 2-second wait,
not retransmitted. Server groups (``aaa group server``) are not here, and
RADIUS does neither command authorization nor accounting here (IOS's RADIUS
accounting is not modelled): those are TACACS+'s. The SSH server is Dropbear on the router
(winlab/iosssh.py), which lets in only names it has an account for; Alpine
has no PAM for it and musl no NSS to ask, so the router makes an account for
each local username and for each name a server has accepted (a console
login, or ``test aaa``): a name that has never been seen cannot open an SSH
session until one of those happened. The password itself is asked inside the session
(winlab/iosssh.py: Dropbear lets the account in with an empty password and
the console asks the method list), so an OpenSSH client logs in as on IOS,
but a paramiko-based tool (Netmiko, NAPALM, Ansible's network_cli), which
sends its password in the SSH handshake, is refused with "Authentication
failed" while the vty list starts with a server group; a list that starts
with ``local`` is checked by the SSH server and those tools work
(winlab/iosssh.ssh_checks). Tested by unit tests against RADIUS and
TACACS+ servers written in the tests themselves; not on a booted router.

Settings (the device's own, [devices."router"] or [devices."sw:<id>"]):
aaa, aaa-login:<list>, aaa-exec:<list>, line-con:login-list,
line-vty:login-list, radius:<name> and radius-key:<name> (shared with
802.1X), tacacs:<name> (address and port), tacacs-key:<name>, and aaa-names
(the names servers accepted: state, not configuration). Counters are runtime
state, in the lab's folder (aaa.json).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import shlex
import struct
import time

from . import devcli, paths, state

TACACS_PORT = 49
WAIT = 2
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
LIST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
KEY_RE = re.compile(r"^[!-~]{1,63}$")
LOGIN_METHODS = ("group radius", "group tacacs+", "local", "enable", "none")
EXEC_METHODS = ("group radius", "group tacacs+", "local", "if-authenticated", "none")
PASS, FAIL, ERROR = "pass", "fail", "error"


# ------------------------------------------------------------------ settings
def _own(lab, device: str) -> dict:
    return lab.devices.get(device, {})


def on(lab, device: str) -> bool:
    return bool(_own(lab, device).get("aaa"))


def radius_servers(lab, device: str) -> list[dict]:
    from . import dot1x
    own, out = _own(lab, device), []
    for k, v in own.items():
        if k.startswith("radius:"):
            name = k[7:]
            ip, auth, acct = (v.split() + ["", "", ""])[:3]
            out.append({"name": name, "ip": ip, "port": int(auth or dot1x.AUTH_PORT),
                        "acct": int(acct or dot1x.ACCT_PORT), "key": own.get(f"radius-key:{name}", ""),
                        "kind": "radius"})
    return out


def tacacs_servers(lab, device: str) -> list[dict]:
    own, out = _own(lab, device), []
    for k, v in own.items():
        if k.startswith("tacacs:"):
            name = k[7:]
            ip, port = (v.split() + ["", ""])[:2]
            out.append({"name": name, "ip": ip, "port": int(port or TACACS_PORT),
                        "key": own.get(f"tacacs-key:{name}", ""), "kind": "tacacs+"})
    return out


def methods_of(text: str) -> list[str]:
    """'group radius local' -> ['radius', 'local']."""
    w, out = text.split(), []
    while w:
        if w[0] == "group" and len(w) > 1:
            out.append(w[1])
            w = w[2:]
        else:
            out.append(w[0])
            w = w[1:]
    return out


def login_methods(lab, device: str, line: str) -> list[str] | None:
    """The methods a login on the line goes through: None when AAA is off
    (the line's own login), [] when nothing is asked (the console with no
    list at all, as on IOS)."""
    own = _own(lab, device)
    if not own.get("aaa"):
        return None
    name = own.get(f"line-{line}:login-list") or "default"
    text = own.get(f"aaa-login:{name}") or (own.get("aaa-login:default") if name != "default" else "")
    if text:
        return methods_of(text)
    return [] if line == "con" else ["local"]   # no list: the console asks nothing, a vty line the local users


def exec_methods(lab, device: str) -> list[str] | None:
    text = _own(lab, device).get("aaa-exec:default")
    return methods_of(text) if text and on(lab, device) else None


# ------------------------------------------------------------------ RADIUS (RFC 2865, 3579)
def _attr(t: int, v: bytes) -> bytes:
    return bytes([t, len(v) + 2]) + v


def hide_password(pw: bytes, secret: bytes, auth: bytes) -> bytes:
    p = pw + b"\0" * (-len(pw) % 16 or (16 if not pw else 0))
    out, last = b"", auth
    for i in range(0, len(p), 16):
        b = hashlib.md5(secret + last).digest()
        c = bytes(x ^ y for x, y in zip(p[i:i + 16], b))
        out += c
        last = c
    return out


def radius_request(user: str, pw: str, secret: str, nas: str, peer: str, nas_ip: str = "") -> tuple[bytes, bytes, int]:
    """An Access-Request: (packet, request authenticator, identifier)."""
    ident = secrets.randbelow(256)
    auth = secrets.token_bytes(16)
    s = secret.encode()
    attrs = (_attr(1, user.encode()) + _attr(2, hide_password(pw.encode(), s, auth))
             + _attr(6, struct.pack(">I", 1)) + _attr(61, struct.pack(">I", 5)) + _attr(32, nas.encode()[:64]))
    if nas_ip:
        attrs += _attr(4, ipaddress.IPv4Address(nas_ip).packed)
    if peer:
        attrs += _attr(31, peer.encode()[:64])
    attrs += _attr(80, b"\0" * 16)
    pkt = bytes([1, ident]) + struct.pack(">H", 20 + len(attrs)) + auth + attrs
    mac = hmac.new(s, pkt, hashlib.md5).digest()
    return pkt[:-16] + mac, auth, ident


def _attrs(body: bytes) -> list[tuple[int, bytes]] | None:
    out, i = [], 0
    while i < len(body):
        if i + 2 > len(body) or body[i + 1] < 2 or i + body[i + 1] > len(body):
            return None
        out.append((body[i], body[i + 2:i + body[i + 1]]))
        i += body[i + 1]
    return out


def radius_reply(pkt: bytes, secret: str, auth: bytes, ident: int) -> tuple[str, int, str]:
    """(PASS | FAIL | ERROR, privilege the server gave or 0, why)."""
    if len(pkt) < 20:
        return ERROR, 0, "no answer"
    code, rid, ln = pkt[0], pkt[1], struct.unpack(">H", pkt[2:4])[0]
    if rid != ident or ln > len(pkt) or ln < 20:
        return ERROR, 0, "an answer to another request"
    pkt = pkt[:ln]
    s = secret.encode()
    want = hashlib.md5(pkt[:4] + auth + pkt[20:] + s).digest()
    if not hmac.compare_digest(want, pkt[4:20]):
        return ERROR, 0, "an answer that does not verify (the shared key differs)"
    attrs = _attrs(pkt[20:])
    if attrs is None:
        return ERROR, 0, "a malformed answer"
    for t, v in attrs:
        if t == 80:
            i = pkt.index(bytes([80, 18]) + v, 20)
            z = pkt[:4] + auth + pkt[20:i + 2] + b"\0" * 16 + pkt[i + 18:]
            if not hmac.compare_digest(hmac.new(s, z, hashlib.md5).digest(), v):
                return ERROR, 0, "an answer whose Message-Authenticator does not verify"
    if code != 2:
        return FAIL, 0, "Access-Reject" if code == 3 else f"code {code}"
    priv = 0
    for t, v in attrs:
        if t == 6 and len(v) == 4 and struct.unpack(">I", v)[0] == 6:
            priv = max(priv, 15)   # Service-Type Administrative
        if t == 26 and len(v) > 6 and struct.unpack(">I", v[:4])[0] == 9:   # Cisco-AVPair
            m = re.search(rb"priv-lvl[=*](\d+)", v[6:])
            if m:
                priv = int(m.group(1))
    return PASS, priv, "Access-Accept"


# ------------------------------------------------------------------ TACACS+ (RFC 8907)
def _pad(session: bytes, key: bytes, version: int, seq: int, n: int) -> bytes:
    out, last = b"", b""
    while len(out) < n:
        last = hashlib.md5(session + key + bytes([version, seq]) + last).digest()
        out += last
    return out[:n]


def tac_packet(kind: int, seq: int, session: bytes, body: bytes, key: str, version: int = 0xC0) -> bytes:
    pad = _pad(session, key.encode(), version, seq, len(body))
    enc = bytes(a ^ b for a, b in zip(body, pad))
    return bytes([version, kind, seq, 0]) + session + struct.pack(">I", len(enc)) + enc


def tac_split(data: bytes, key: str) -> list[tuple[int, int, bytes]] | None:
    """The packets in a TACACS+ stream, bodies clear: [(type, seq, body)]."""
    out, i = [], 0
    while i + 12 <= len(data):
        version, kind, seq, flags = data[i:i + 4]
        session = data[i + 4:i + 8]
        n = struct.unpack(">I", data[i + 8:i + 12])[0]
        body = data[i + 12:i + 12 + n]
        if len(body) < n or version >> 4 != 0xC:
            return None
        if not flags & 1:
            body = bytes(a ^ b for a, b in zip(body, _pad(session, key.encode(), version, seq, n)))
        out.append((kind, seq, body))
        i += 12 + n
    return out


def tac_login(user: str, pw: str, port: str, peer: str, key: str) -> tuple[bytes, bytes]:
    """START (ASCII login with the user) and the CONTINUE that answers its
    GETPASS, sent together: (bytes, session id)."""
    session = secrets.token_bytes(4)
    u, p, r = user.encode(), port.encode(), peer.encode()
    start = bytes([1, 1, 1, 1, len(u), len(p), len(r), 0]) + u + p + r
    w = pw.encode()
    cont = struct.pack(">HHB", len(w), 0, 0) + w
    return tac_packet(1, 1, session, start, key) + tac_packet(1, 3, session, cont, key), session


def tac_login_reply(data: bytes, key: str) -> tuple[str, str]:
    pk = tac_split(data, key)
    if not pk:
        return ERROR, "no answer"
    status = None
    for kind, seq, body in pk:
        if kind != 1 or len(body) < 6:
            return ERROR, "a malformed answer"
        mlen, dlen = struct.unpack(">HH", body[2:6])
        if 6 + mlen + dlen != len(body):
            return ERROR, "an answer that does not decode (the shared key differs)"
        status = body[0]
    if status == 1:
        return PASS, "PASS"
    if status == 2:
        return FAIL, "FAIL"
    if status == 5:
        return ERROR, "GETPASS and then nothing"
    return ERROR, f"status {status}"


def tac_author(user: str, port: str, peer: str, key: str) -> bytes:
    session = secrets.token_bytes(4)
    u, p, r = user.encode(), port.encode(), peer.encode()
    args = [b"service=shell", b"cmd="]
    body = bytes([6, 1, 1, 1, len(u), len(p), len(r), len(args)]) + bytes(len(a) for a in args) + u + p + r + b"".join(args)
    return tac_packet(2, 1, session, body, key)


def tac_author_reply(data: bytes, key: str) -> tuple[str, int, str]:
    pk = tac_split(data, key)
    if not pk:
        return ERROR, 0, "no answer"
    kind, _, body = pk[-1]
    if kind != 2 or len(body) < 6:
        return ERROR, 0, "a malformed answer"
    status, n = body[0], body[1]
    mlen, dlen = struct.unpack(">HH", body[2:6])
    if 6 + n + mlen + dlen + sum(body[6:6 + n]) != len(body):
        return ERROR, 0, "an answer that does not decode (the shared key differs)"
    if status in (1, 2):
        i = 6 + n + mlen + dlen
        priv = 1
        for ln in body[6:6 + n]:
            m = re.match(rb"priv-lvl[=*](\d+)$", body[i:i + ln])
            if m:
                priv = int(m.group(1))
            i += ln
        return PASS, priv, "PASS"
    if status == 0x10:
        return FAIL, 0, "FAIL"
    return ERROR, 0, f"status {status}"


def tac_author_cmd(user: str, port: str, peer: str, key: str, words: list[str], level: int) -> bytes:
    """An AUTHOR REQUEST for one command, as IOS sends it under ``aaa
    authorization commands``: service=shell, cmd=<first word>, a cmd-arg for
    each word after it and cmd-arg=<cr> to close the line."""
    session = secrets.token_bytes(4)
    u, p, r = user.encode(), port.encode(), peer.encode()
    args = [b"service=shell", b"cmd=" + words[0].encode()] + [b"cmd-arg=" + w.encode() for w in words[1:]]
    args.append(b"cmd-arg=<cr>")
    args = [a[:255] for a in args][:255]
    body = (bytes([6, max(0, min(15, level)), 1, 1, len(u), len(p), len(r), len(args)])
            + bytes(len(a) for a in args) + u + p + r + b"".join(args))
    return tac_packet(2, 1, session, body, key)


ACCT_START, ACCT_STOP = 0x02, 0x04


def tac_acct(user: str, port: str, peer: str, key: str, flags: int, level: int, args: list[str]) -> bytes:
    """An ACCOUNTING REQUEST (RFC 8907 section 7.1): a start or stop record
    with its attribute-value pairs."""
    session = secrets.token_bytes(4)
    u, p, r = user.encode(), port.encode(), peer.encode()
    av = [a.encode()[:255] for a in args][:255]
    body = (bytes([flags, 6, max(0, min(15, level)), 1, 1, len(u), len(p), len(r), len(av)])
            + bytes(len(a) for a in av) + u + p + r + b"".join(av))
    return tac_packet(3, 1, session, body, key)


def tac_acct_reply(data: bytes, key: str) -> tuple[str, str]:
    pk = tac_split(data, key)
    if not pk:
        return ERROR, "no answer"
    kind, _, body = pk[-1]
    if kind != 3 or len(body) < 5:
        return ERROR, "a malformed answer"
    mlen, dlen = struct.unpack(">HH", body[:4])
    if 5 + mlen + dlen != len(body):
        return ERROR, "an answer that does not decode (the shared key differs)"
    return (PASS, "SUCCESS") if body[4] == 1 else (ERROR, f"status {body[4]}")


# ------------------------------------------------------------------ the wire: nc on the router
def source(con) -> tuple[str, str]:
    """(network namespace, address) a request leaves from: a switch's
    management namespace when it has one, else the router."""
    if con.device == devcli.ROUTER:
        return "", ""
    from . import iosl2
    sw = devcli.switch_id(con.device)
    ns = iosl2.netns(con.lab, sw)
    addrs = iosl2.svis(con.lab, sw)
    return ns, (addrs[0][1].split("/")[0] if addrs and ns else "")


def wire_cmd(ns: str, ip: str, port: int, payload: bytes, udp: bool) -> str:
    pre = f"ip netns exec {shlex.quote(ns)} " if ns else ""
    return (f"printf '%s' {shlex.quote(base64.b64encode(payload).decode())} | base64 -d | "
            f"{pre}nc {'-u ' if udp else ''}-w {WAIT} {ip} {port} 2>/dev/null | base64 | tr -d '\\n'; echo")


def _send(con, srv: dict, payload: bytes, udp: bool) -> bytes:
    ns, _ = source(con)
    try:
        ipaddress.IPv4Address(srv["ip"])
        text = con._on_router(wire_cmd(ns, srv["ip"], srv["port"], payload, udp), timeout=WAIT + 10)
    except (devcli.CliError, ValueError):
        return b""
    try:
        return base64.b64decode("".join(text.split()) or "", validate=False)
    except ValueError:
        return b""


# ------------------------------------------------------------------ counters
def _rt_path(lab_name: str):
    return paths.lab_dir(lab_name) / "aaa.json"


def runtime(lab_name: str) -> dict:
    try:
        d = json.loads(_rt_path(lab_name).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _count(con, srv: dict, what: str) -> None:
    d = runtime(con.lab.name)
    c = d.setdefault(con.device, {}).setdefault(f"{srv['kind']}:{srv['name']}", {})
    c[what] = int(c.get(what, 0)) + 1
    c["last"] = what
    c["at"] = int(time.time())
    state.save_json(_rt_path(con.lab.name), d)


# ------------------------------------------------------------------ asking
def ask_group(con, kind: str, user: str, pw: str, port: str, peer: str) -> tuple[str, int, str]:
    """One method: each server of the kind in turn, until one answers."""
    srvs = radius_servers(con.lab, con.device) if kind == "radius" else tacacs_servers(con.lab, con.device)
    srvs = [s for s in srvs if s["ip"] and s["key"]]
    if not srvs:
        return ERROR, 0, f"no {kind} server with an address and a key"
    why = ""
    for s in srvs:
        _count(con, s, "requests")
        if kind == "radius":
            _, src = source(con)
            pkt, auth, ident = radius_request(user, pw, s["key"], devcli.ios_name(con.lab, con.device), peer,
                                              src or _router_src(con, s["ip"]))
            res, priv, why = radius_reply(_send(con, s, pkt, True), s["key"], auth, ident)
        else:
            data, _ = tac_login(user, pw, port, peer, s["key"])
            res, why = tac_login_reply(_send(con, s, data, False), s["key"])
            priv = 0
        _count(con, s, {PASS: "accepts", FAIL: "rejects"}.get(res, "timeouts" if why == "no answer" else "errors"))
        if res != ERROR:
            return res, priv, f"{s['name']} ({s['ip']}): {why}"
        why = f"{s['name']} ({s['ip']}): {why}"
    return ERROR, 0, why


def _router_src(con, ip: str) -> str:
    from . import dot1x
    return dot1x.source_ip(con.plan, ip)


def authenticate(con, methods: list[str], user: str, pw: str, port: str, peer: str) -> tuple[str, int, str, str]:
    """(PASS | FAIL | ERROR, privilege a server gave, the method that
    decided, why) down a method list: the next method only when one errs."""
    from . import iosnv
    own = _own(con.lab, con.device)
    why = ""
    for m in methods:
        if m in ("radius", "tacacs+"):
            res, priv, why = ask_group(con, m, user, pw, port, peer)
            if res != ERROR:
                return res, priv, m, why
            continue
        if m in ("local", "local-case"):
            kept = own.get(f"user:{user}", "")
            if not kept:
                return FAIL, 0, "local", f"no local user {user}"
            priv, _, word = kept.partition(" ")
            return (PASS if word and iosnv.matches(pw, word) else FAIL), 0, "local", "local user list"
        if m == "enable":
            sec = own.get("enable-secret") or own.get("enable-password") or ""
            if not sec:
                why = "no enable secret"
                continue
            return (PASS if iosnv.matches(pw, sec) else FAIL), 0, "enable", "enable secret"
        if m == "none":
            return PASS, 0, "none", "method none"
    return ERROR, 0, "", why or "no method answered"


def authorize(con, user: str, method: str, server_priv: int, port: str, peer: str) -> tuple[bool, int, str]:
    """(allowed, privilege, why) for the exec session that starts."""
    methods = exec_methods(con.lab, con.device)
    if methods is None:
        return True, 1, "no exec authorization: level 1"
    own = _own(con.lab, con.device)
    for m in methods:
        if m == "radius":
            if method != "radius":
                continue   # RADIUS authorizes with the login's own answer
            return True, server_priv or 1, "the RADIUS server's answer"
        if m == "tacacs+":
            srvs = [s for s in tacacs_servers(con.lab, con.device) if s["ip"] and s["key"]]
            for s in srvs:
                _count(con, s, "requests")
                res, priv, why = tac_author_reply(_send(con, s, tac_author(user, port, peer, s["key"]), False), s["key"])
                _count(con, s, {PASS: "accepts", FAIL: "rejects"}.get(res, "errors"))
                if res == PASS:
                    return True, priv, f"TACACS+ {s['name']}"
                if res == FAIL:
                    return False, 0, f"TACACS+ {s['name']} refused"
            continue
        if m == "local":
            kept = own.get(f"user:{user}", "")
            if not kept:
                return False, 0, f"no local user {user}"
            try:
                return True, int(kept.split()[0]), "local user list"
            except ValueError:
                return True, 1, "local user list"
        if m in ("if-authenticated", "none"):
            return True, 1, m
    return False, 0, "no exec authorization method answered"


def _learn(con, user: str) -> None:
    """A name a server accepted gets an account on the router, for SSH."""
    own = devcli.settings(con.lab, con.device)
    names = own.get("aaa-names", "").split()
    if user in names or own.get(f"user:{user}") or not re.match(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$", user) \
            or user == "root":
        return
    own["aaa-names"] = " ".join((names + [user])[-32:])
    con._save()


def login(con, line: str, user: str, pw: str) -> tuple[bool, int, str, str]:
    """A whole login: (in, privilege, method, what to print on failure)."""
    methods = login_methods(con.lab, con.device, line) or []
    port = "tty0" if line == "con" else "vty0"
    peer = getattr(con, "peer", "") or ""
    res, spriv, method, why = authenticate(con, methods, user, pw, port, peer)
    if res != PASS:
        return False, 0, method, "% Authentication failed"
    if method in ("radius", "tacacs+"):
        _learn(con, user)
    ok, priv, why = authorize(con, user, method, spriv, port, peer)
    if not ok:
        return False, 0, method, "% Authorization failed."
    return True, priv, method, ""


# ------------------------------------------------------------------ command authorization and accounting
CMD_METHODS = ("group tacacs+", "local", "if-authenticated", "none")
ACCT_HOW = ("start-stop", "stop-only")
# Commands IOS ships at level 1 even when typed at the # prompt; everything
# else typed at # or in configuration mode is a level 15 command.
LEVEL1 = ("show", "ping", "traceroute", "terminal", "enable", "disable", "logout", "ssh", "telnet")
UNASKED = ("exit", "end", "logout", "quit", "do")


def cmd_methods(lab, device: str, level: int) -> list[str] | None:
    text = _own(lab, device).get(f"aaa-cmd:{level}:default")
    return methods_of(text) if text and on(lab, device) else None


def acct_list(lab, device: str, what: str) -> tuple[str, list[str]] | None:
    """('start-stop' | 'stop-only', methods) of the default accounting list
    for 'exec' or 'cmd:<level>'."""
    text = _own(lab, device).get(f"aaa-acct-{what}:default", "")
    if not text or not on(lab, device):
        return None
    how, _, rest = text.partition(" ")
    return how, methods_of(rest)


def command_level(mode: str, words: list[str]) -> int:
    if mode == "user" or (mode == "enable" and words and words[0] in LEVEL1):
        return 1
    return 15


def full_words(spec, args: list[str]) -> list[str]:
    """The command as IOS spells it out to the server: every keyword whole
    (conf t is configure terminal), the values as typed."""
    out, k = [], 0
    for w in spec.words:
        if w.startswith("<"):
            if k < len(args):
                out += str(args[k]).split() if w == "<line>" else [str(args[k])]
            k += 1
        else:
            out.append(w)
    return out


def _who(con) -> tuple[str, str, str] | None:
    """(user, port, remote address) of a session AAA logged in, or None."""
    vty = getattr(con, "logged", None) is not None
    user = getattr(con, "user", "") if vty else getattr(con, "aaa_user", "")
    if not user or not con.s.authed:
        return None
    return user, ("vty0" if vty else "tty0"), (getattr(con, "peer", "") or "")


def _tac_servers(con) -> list[dict]:
    return [s for s in tacacs_servers(con.lab, con.device) if s["ip"] and s["key"]]


def gate(con, spec, args) -> dict | None:
    """Before a command runs: under ``aaa authorization commands <level>``
    the method list says yes or no (a TACACS+ server is asked about the
    whole command). Raises the console's error when it says no; returns
    what accounting needs afterwards, or None."""
    lab, dev = con.lab, con.device
    if not on(lab, dev) or getattr(con, "_no_author", False):
        return None
    who = _who(con)
    if who is None:
        return None
    words = full_words(spec, args)
    if not words or words[0] in UNASKED:
        return None
    mode = con.s.mode
    level = command_level(mode, words)
    in_config = mode.startswith("config")
    vty = who[1] == "vty0"
    methods = cmd_methods(lab, dev, level)
    asked = (methods is not None and (vty or _own(lab, dev).get("aaa-console"))
             and not (in_config and _own(lab, dev).get("aaa-nocfgcmds")))
    if asked:
        ok, _why = _authorize_cmd(con, who, methods, words, level)
        if not ok:
            raise devcli.CliError("Command authorization failed.")
    return {"words": words, "level": level, "who": who}


def _authorize_cmd(con, who, methods: list[str], words: list[str], level: int) -> tuple[bool, str]:
    user, port, peer = who
    for m in methods:
        if m == "tacacs+":
            for s in _tac_servers(con):
                _count(con, s, "requests")
                pkt = tac_author_cmd(user, port, peer, s["key"], words, level)
                res, _, why = tac_author_reply(_send(con, s, pkt, False), s["key"])
                _count(con, s, {PASS: "accepts", FAIL: "rejects"}.get(res, "timeouts" if why == "no answer"
                                                                       else "errors"))
                if res == PASS:
                    return True, f"TACACS+ {s['name']}"
                if res == FAIL:
                    return False, f"TACACS+ {s['name']} refused"
            continue
        if m == "local":
            kept = _own(con.lab, con.device).get(f"user:{user}", "")
            priv = kept.split()[0] if kept else ""
            return (priv.isdigit() and int(priv) >= level), "local user list"
        if m in ("if-authenticated", "none"):
            return True, m
    return False, "no method answered"


def _task(con) -> int:
    d = runtime(con.lab.name)
    n = int(d.get("task", 0) or 0) % 100000 + 1
    d["task"] = n
    state.save_json(_rt_path(con.lab.name), d)
    return n


def _acct_send(con, who, methods: list[str], flags: int, level: int, args: list[str]) -> bool:
    if "tacacs+" not in methods:
        return False
    user, port, peer = who
    for s in _tac_servers(con):
        _count(con, s, "requests")
        res, why = tac_acct_reply(_send(con, s, tac_acct(user, port, peer, s["key"], flags, level, args), False),
                                  s["key"])
        _count(con, s, "accepts" if res == PASS else "timeouts" if why == "no answer" else "errors")
        if res == PASS:
            return True
    return False


def account(con, rec: dict | None) -> None:
    """After a command ran: its stop record under ``aaa accounting
    commands <level>`` (IOS sends one record per command)."""
    if not rec:
        return
    lst = acct_list(con.lab, con.device, f"cmd:{rec['level']}")
    if lst is None:
        return
    _acct_send(con, rec["who"], lst[1], ACCT_STOP, rec["level"],
               [f"task_id={_task(con)}", "timezone=UTC", "service=shell", f"priv-lvl={rec['level']}",
                "cmd=" + " ".join(rec["words"]) + " <cr>"])


def exec_start(con) -> None:
    """A session began: its start record under ``aaa accounting exec``."""
    who = _who(con)
    lst = acct_list(con.lab, con.device, "exec")
    if who is None or lst is None:
        return
    con.aaa_task, con.aaa_since = _task(con), int(time.time())
    if lst[0] == "start-stop":
        _acct_send(con, who, lst[1], ACCT_START, 1 if con.s.mode == "user" else 15,
                   [f"task_id={con.aaa_task}", "timezone=UTC", "service=shell", f"start_time={con.aaa_since}"])


def exec_stop(con) -> None:
    who = _who(con)
    lst = acct_list(con.lab, con.device, "exec")
    since = getattr(con, "aaa_since", 0)
    if who is None or lst is None or not since:
        return
    now = int(time.time())
    _acct_send(con, who, lst[1], ACCT_STOP, 1 if con.s.mode == "user" else 15,
               [f"task_id={getattr(con, 'aaa_task', 0)}", "timezone=UTC", "service=shell",
                f"start_time={since}", f"stop_time={now}", f"elapsed_time={now - since}"])
    con.aaa_since = 0


# ---- the login prompts (iosnv.begin for the console, iosssh.VtyConsole.open for SSH)
def begin(con, line: str) -> str | None:
    """The login a line asks for under AAA: None when AAA is off."""
    from . import iosnv
    methods = login_methods(con.lab, con.device, line)
    if methods is None:
        return None
    if not methods:
        con.s.authed = True
        return ""
    if line == "vty":
        iosnv.ask(con, "aaa-pass", "Password: ", secret=True, tries=_tries(con), on=_answer, user=con.user,
                  line="vty")
        return ""
    iosnv.ask(con, "aaa-user", "Username: ", tries=_tries(con), on=_answer, line="con")
    return "\nUser Access Verification\n"


def _tries(con) -> int:
    try:
        return int(_own(con.lab, con.device).get("ssh-retries") or 3) or 1
    except ValueError:
        return 3


def _answer(con, text: str, q: dict) -> str:
    from . import iosnv
    if q["kind"] == "aaa-user":
        iosnv.ask(con, "aaa-pass", "Password: ", secret=True, tries=q["tries"], on=_answer, user=text.strip(),
                  line=q["line"])
        return ""
    ok, priv, method, msg = login(con, q["line"], q["user"], text)
    if ok:
        con.s.authed = True
        con.s.mode = "enable" if priv >= 15 else "user"
        con.method = method
        if hasattr(con, "logged"):
            con.logged = True
        else:
            con.aaa_user = q["user"]
        exec_start(con)
        return ""
    left = q["tries"] - 1
    if left <= 0 or msg.startswith("% Authorization"):
        con.s.mode, con.s.authed = "idle", False
        return msg + ("" if q["line"] == "vty" else "\n\nPress RETURN to get started.")
    if q["line"] == "vty":
        iosnv.ask(con, "aaa-pass", "Password: ", secret=True, tries=left, on=_answer, user=q["user"], line="vty")
    else:
        iosnv.ask(con, "aaa-user", "Username: ", tries=left, on=_answer, line="con")
    return msg + "\n"


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, E, C, L) -> None:
    router = con.device == devcli.ROUTER
    T, R = ("config-server-tacacs",), ("config-radius-server",)
    if router:   # a switch has these from 802.1X (winlab/dot1x.py)
        add("aaa new-model", lambda a: _flag(con, True), "Enable NEW access control commands and functions", C)
        add("no aaa new-model", lambda a: _flag(con, False), "Negate a command or set its defaults", C)
        add("radius server <name>", lambda a: _server(con, "radius", a[0]), "Server configuration", C)
        add("no radius server <name>", lambda a: _no_server(con, "radius", a[0]), "Negate a command or set its defaults", C)
        add("address ipv4 <ip>", lambda a: _address(con, a[0], ""), "IPv4 address for the RADIUS server", R)
        add("address ipv4 <ip> <line>", lambda a: _address(con, a[0], a[1]), "IPv4 address for the RADIUS server", R)
        add("key <line>", lambda a: _key(con, a[0]), "Per-server encryption key", R)
        add("no key", lambda a: _key(con, ""), "Negate a command or set its defaults", R)
        add("exit", con._cfg_exit, "Exit from RADIUS server configuration mode", R)
        add("end", con._end, "Exit to privileged EXEC mode", R)
        add("do <line>", con._do, "To run exec commands in config mode", R)
    add("aaa authentication login <line>", lambda a: _list(con, "aaa-login", a[0], LOGIN_METHODS),
        "Set authentication lists for logins.", C)
    add("no aaa authentication login <line>", lambda a: _no_list(con, "aaa-login", a[0]), "Negate a command or set its defaults", C)
    add("aaa authorization exec <line>", lambda a: _list(con, "aaa-exec", a[0], EXEC_METHODS),
        "For starting an exec (shell).", C)
    add("no aaa authorization exec <line>", lambda a: _no_list(con, "aaa-exec", a[0]), "Negate a command or set its defaults", C)
    add("aaa authorization commands <num> <line>", lambda a: _cmd_list(con, a[0], a[1]),
        "For exec (shell) commands.", C)
    add("no aaa authorization commands <num> <line>", lambda a: _no_cmd_list(con, f"aaa-cmd:{a[0]}", a[1]),
        "Negate a command or set its defaults", C)
    add("aaa authorization config-commands", lambda a: _toggle(con, "aaa-nocfgcmds", False),
        "For configuration mode commands.", C)
    add("no aaa authorization config-commands", lambda a: _toggle(con, "aaa-nocfgcmds", True),
        "Negate a command or set its defaults", C)
    add("aaa authorization console", lambda a: _toggle(con, "aaa-console", True),
        "For enabling console authorization", C)
    add("no aaa authorization console", lambda a: _toggle(con, "aaa-console", False),
        "Negate a command or set its defaults", C)
    add("aaa accounting exec <line>", lambda a: _acct(con, "exec", a[0]), "For starting an exec (shell).", C)
    add("no aaa accounting exec <line>", lambda a: _no_cmd_list(con, "aaa-acct-exec", a[0]),
        "Negate a command or set its defaults", C)
    add("aaa accounting commands <num> <line>", lambda a: _acct(con, f"cmd:{a[0]}", a[1]),
        "For exec (shell) commands.", C)
    add("no aaa accounting commands <num> <line>", lambda a: _no_cmd_list(con, f"aaa-acct-cmd:{a[0]}", a[1]),
        "Negate a command or set its defaults", C)
    add("tacacs server <name>", lambda a: _server(con, "tacacs", a[0]), "Server configuration", C)
    add("no tacacs server <name>", lambda a: _no_server(con, "tacacs", a[0]), "Negate a command or set its defaults", C)
    add("address ipv4 <ip>", lambda a: _address(con, a[0], ""), "IPv4 address for the TACACS+ server", T)
    add("key <line>", lambda a: _key(con, a[0]), "Per-server encryption key", T)
    add("no key", lambda a: _key(con, ""), "Negate a command or set its defaults", T)
    add("port <num>", lambda a: _port(con, a[0]), "TCP port for TACACS+ server (default is 49)", T)
    add("exit", con._cfg_exit, "Exit from TACACS server configuration mode", T)
    add("end", con._end, "Exit to privileged EXEC mode", T)
    add("do <line>", con._do, "To run exec commands in config mode", T)
    add("login authentication <name>", lambda a: _line_list(con, a[0]), "Authentication parameters.", L)
    add("no login authentication", lambda a: _line_list(con, ""), "Negate a command or set its defaults", L)
    add("show tacacs", lambda a: show_tacacs(con), "Shows TACACS+ server statistics", U)
    add("show aaa servers", lambda a: show_servers(con), "Show AAA servers as seen by the AAA Server MIB", U)
    add("test aaa group <line>", lambda a: test(con, a[0]), "Test AAA server", E)


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def _flag(con, enable: bool) -> str:
    if enable:
        _mine(con)["aaa"] = "yes"
    else:
        _mine(con).pop("aaa", None)
    con._save(live=False)
    return ""


def _need_aaa(con) -> None:
    if not _mine(con).get("aaa"):
        raise devcli.CliError("% AAA commands are not available: type aaa new-model first")


def _list(con, key: str, text: str, allowed: tuple[str, ...]) -> str:
    _need_aaa(con)
    w = text.split()
    if len(w) < 2 or not (w[0] == "default" or LIST_RE.match(w[0])):
        raise devcli.CliError(f"% Incomplete command: {key.replace('aaa-', 'aaa ')} default|<list name> "
                              f"<method> [<method> ...]")
    name, rest = w[0], [x.lower() for x in w[1:]]
    methods: list[str] = []
    while rest:
        if rest[0] == "group" and len(rest) > 1:
            m = f"group {rest[1]}"
            rest = rest[2:]
        else:
            m = rest[0]
            rest = rest[1:]
        if m not in allowed:
            hint = ("% Server groups by name are not in this lab: group radius and group tacacs+ are"
                    if m.startswith("group ") else f"% Methods here: {', '.join(allowed)}")
            raise devcli.CliError(f"% Invalid input: {m}\n{hint}")
        if m in methods:
            raise devcli.CliError(f"% Method {m} is listed twice")
        methods.append(m)
    if len(methods) > 4:
        raise devcli.CliError("% At most four methods in a list")
    _mine(con)[f"{key}:{name}"] = " ".join(methods)
    con._save(live=False)
    if key == "aaa-exec" and name != "default":
        return "% Kept; logins here follow the default exec authorization list only"
    return ""


def _no_list(con, key: str, text: str) -> str:
    w = text.split()
    if not w:
        raise devcli.CliError("% Incomplete command.")
    _mine(con).pop(f"{key}:{w[0]}", None)
    con._save(live=False)
    return ""


def _level_of(text: str) -> int:
    if not text.isdigit() or not 0 <= int(text) <= 15:
        raise devcli.CliError("% Invalid input: a privilege level is 0 to 15")
    return int(text)


def _cmd_list(con, level: str, text: str) -> str:
    """aaa authorization commands <level> default|<list> <methods>."""
    _need_aaa(con)
    lvl = _level_of(level)
    w = text.split()
    if len(w) < 2 or not (w[0] == "default" or LIST_RE.match(w[0])):
        raise devcli.CliError(f"% Incomplete command: aaa authorization commands {lvl} default|<list name> "
                              "<method> [<method> ...]")
    methods = _methods(w[1:], CMD_METHODS)
    own = _mine(con)
    own[f"aaa-cmd:{lvl}:{w[0]}"] = " ".join(methods)
    con._save(live=False)
    notes = []
    if w[0] != "default":
        notes.append("% Kept; commands here follow the default list only")
    if lvl not in (1, 15):
        notes.append(f"% Commands here are level 1 or 15; nothing is a level {lvl} command")
    if "group tacacs+" in methods and not _tac_servers(con):
        notes.append("% No TACACS+ server with an address and a key yet: tacacs server <name>")
    if methods[-1] == "group tacacs+":
        notes.append("% With no method after group tacacs+, every command is refused while no TACACS+ server "
                     "answers: add local or if-authenticated as the last method")
    return "\n".join(notes)


def _methods(words: list[str], allowed: tuple[str, ...]) -> list[str]:
    rest, methods = [x.lower() for x in words], []
    while rest:
        if rest[0] == "group" and len(rest) > 1:
            m, rest = f"group {rest[1]}", rest[2:]
        else:
            m, rest = rest[0], rest[1:]
        if m not in allowed:
            hint = ("% Here: group tacacs+ (RADIUS does not authorize commands; a server group by name is not in "
                    "this lab)" if m.startswith("group ") else f"% Methods here: {', '.join(allowed)}")
            raise devcli.CliError(f"% Invalid input: {m}\n{hint}")
        if m in methods:
            raise devcli.CliError(f"% Method {m} is listed twice")
        methods.append(m)
    if not methods or len(methods) > 4:
        raise devcli.CliError("% One to four methods in a list")
    return methods


def _acct(con, what: str, text: str) -> str:
    """aaa accounting exec|commands <level> default|<list> start-stop|stop-only group tacacs+."""
    _need_aaa(con)
    if what.startswith("cmd:"):
        what = f"cmd:{_level_of(what[4:])}"
    w = text.split()
    if len(w) < 3 or not (w[0] == "default" or LIST_RE.match(w[0])) or w[1].lower() not in ACCT_HOW:
        raise devcli.CliError("% Incomplete command: aaa accounting exec|commands <level> default "
                              "start-stop|stop-only group tacacs+")
    methods = _methods(w[2:], ("group tacacs+",))
    _mine(con)[f"aaa-acct-{what}:{w[0]}"] = f"{w[1].lower()} " + " ".join(methods)
    con._save(live=False)
    return "% Kept; records here follow the default list only" if w[0] != "default" else ""


def _no_cmd_list(con, key: str, text: str) -> str:
    w = text.split()
    if not w:
        raise devcli.CliError("% Incomplete command.")
    if key.startswith("aaa-cmd:") or key.startswith("aaa-acct-cmd:"):
        k, _, lvl = key.rpartition(":")
        key = f"{k}:{_level_of(lvl)}"
    _mine(con).pop(f"{key}:{w[0]}", None)
    con._save(live=False)
    return ""


def _toggle(con, key: str, value: bool) -> str:
    _need_aaa(con)
    if value:
        _mine(con)[key] = "yes"
    else:
        _mine(con).pop(key, None)
    con._save(live=False)
    return ""


def _line_list(con, name: str) -> str:
    own = _mine(con)
    k = f"line-{con.s.ctx}:login-list"
    if not name:
        own.pop(k, None)
        con._save(live=False)
        return ""
    if not (name == "default" or LIST_RE.match(name)):
        raise devcli.CliError("% Invalid input: login authentication default|<list name>")
    own[k] = name
    con._save(live=False)
    if not own.get(f"aaa-login:{name}"):
        return f"AAA: Warning: authentication list {name} is not defined for LOGIN."
    return ""


def _server(con, kind: str, name: str) -> str:
    from . import dot1x
    if not NAME_RE.match(name):
        raise devcli.CliError("% A server name: letters, digits, - _ . (up to 32)")
    _mine(con).setdefault(f"{kind}:{name}", "")
    if kind == "radius" and con.device != devcli.ROUTER:
        return dot1x._server(con, name)
    con.s.mode, con.s.ctx = ("config-radius-server" if kind == "radius" else "config-server-tacacs"), name
    con._save(live=False)
    return ""


def _no_server(con, kind: str, name: str) -> str:
    own = _mine(con)
    if own.pop(f"{kind}:{name}", None) is None:
        raise devcli.CliError(f"% No {'RADIUS' if kind == 'radius' else 'TACACS+'} server {name}")
    own.pop(f"{kind}-key:{name}", None)
    con._save(live=False)
    return ""


def _kind(con) -> str:
    return "radius" if con.s.mode == "config-radius-server" else "tacacs"


def _address(con, ip: str, rest: str) -> str:
    from . import dot1x
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise devcli.CliError(f"% Invalid IPv4 address: {ip}") from None
    own, name = _mine(con), con.s.ctx
    if _kind(con) == "radius":
        auth, acct = dot1x.AUTH_PORT, dot1x.ACCT_PORT
        w = rest.lower().split()
        while w:
            if len(w) < 2 or w[0] not in ("auth-port", "acct-port") or not w[1].isdigit() or not 0 < int(w[1]) < 65536:
                raise devcli.CliError("% Invalid input: address ipv4 <ip> [auth-port <port>] [acct-port <port>]")
            if w[0] == "auth-port":
                auth = int(w[1])
            else:
                acct = int(w[1])
            w = w[2:]
        own[f"radius:{name}"] = f"{ip} {auth} {acct}"
    else:
        port = (own.get(f"tacacs:{name}", "").split() + ["", ""])[1] or str(TACACS_PORT)
        own[f"tacacs:{name}"] = f"{ip} {port}"
    con._save(live=False)
    ns, src = source(con)
    src = src or (_router_src(con, ip) if not ns else "")
    return (f"% Requests to {ip} leave from {src}: on the server, the client (NAS) address is {src}" if src else
            f"% {ip} is on no network this device reaches directly: give it an address on the server's network "
            f"(or a route to it)")


def _key(con, text: str) -> str:
    own, name, kind = _mine(con), con.s.ctx, _kind(con)
    if not text:
        own.pop(f"{kind}-key:{name}", None)
        con._save(live=False)
        return ""
    w = text.split()
    if len(w) == 2 and w[0] in ("0", "6", "7"):
        if w[0] != "0":
            raise devcli.CliError("% Only a clear-text key here (key <text>, or key 0 <text>)")
        w = w[1:]
    if len(w) != 1 or not KEY_RE.match(w[0]):
        raise devcli.CliError("% A shared key: 1 to 63 printable characters, no spaces")
    own[f"{kind}-key:{name}"] = w[0]
    con._save(live=False)
    return ""


def _port(con, n: str) -> str:
    v = int(n)
    if not 1 <= v <= 65535:
        raise devcli.CliError("% Invalid port")
    own, name = _mine(con), con.s.ctx
    ip = (own.get(f"tacacs:{name}", "").split() + [""])[0]
    own[f"tacacs:{name}"] = f"{ip} {v}"
    con._save(live=False)
    return ""


# ---- show and test
def test(con, text: str) -> str:
    """test aaa group radius|tacacs+ <user> <password> [legacy]."""
    w = text.split()
    if w and w[-1].lower() in ("legacy", "new-code"):
        w = w[:-1]
    if len(w) != 3 or w[0].lower() not in ("radius", "tacacs+"):
        raise devcli.CliError("% Invalid input: test aaa group radius|tacacs+ <user> <password> legacy")
    kind, user, pw = w[0].lower(), w[1], w[2]
    head = f"Attempting authentication test to server-group {kind} using {kind}"
    res, priv, why = ask_group(con, kind, user, pw, "vty0", "")
    if res == PASS:
        _learn(con, user)
        return head + "\nUser was successfully authenticated." + (f"\n% privilege level {priv} from the server"
                                                                   if priv else "")
    if res == FAIL:
        return head + "\nUser authentication request was rejected by server."
    return head + f"\nNo authoritative response from any server.\n% {why}"


def _counts(con, srv: dict) -> dict:
    return runtime(con.lab.name).get(con.device, {}).get(f"{srv['kind']}:{srv['name']}", {})


def show_servers(con) -> str:
    out = []
    for i, s in enumerate(radius_servers(con.lab, con.device) + tacacs_servers(con.lab, con.device), 1):
        c = _counts(con, s)
        up = "DEAD" if c.get("last") in ("timeouts", "errors") else "UP"
        kind = "RADIUS" if s["kind"] == "radius" else "TACACS+"
        ports = f"auth-port {s['port']}, acct-port {s['acct']}" if s["kind"] == "radius" else f"port {s['port']}"
        out += [f"{kind}: id {i}, priority 1, host {s['ip'] or 'unset'}, {ports}, hostname {s['name']}",
                f"     State: current {up}, duration {max(0, int(time.time()) - int(c.get('at', time.time())))}s",
                f"     Authen: request {c.get('requests', 0)}, timeouts {c.get('timeouts', 0)}, failover 0, "
                f"retransmission 0",
                f"             Response: accept {c.get('accepts', 0)}, reject {c.get('rejects', 0)}, challenge 0",
                f"             Response: unexpected 0, server error 0, incorrect {c.get('errors', 0)}, time 0ms",
                f"     Key: {'set' if s['key'] else 'not set'}"]
    if not out:
        return "% No AAA servers: radius server <name> or tacacs server <name>, then address ipv4 and key"
    if any(_counts(con, s).get("errors") for s in radius_servers(con.lab, con.device) + tacacs_servers(con.lab, con.device)):
        out.append("% incorrect: answers that did not verify. The shared key here and on the server differ.")
    return "\n".join(out)


def show_tacacs(con) -> str:
    srvs = tacacs_servers(con.lab, con.device)
    if not srvs:
        return ""
    out = []
    for s in srvs:
        c = _counts(con, s)
        out += ["", "Tacacs+ Server - public  :", f"               Server name: {s['name']}",
                f"            Server address: {s['ip'] or 'unset'}", f"               Server port: {s['port']}",
                f"              Socket opens: {c.get('requests', 0)}",
                f"             Socket closes: {c.get('requests', 0) - c.get('timeouts', 0)}",
                "             Socket aborts:          0",
                f"             Socket errors: {c.get('errors', 0)}",
                f"           Socket Timeouts: {c.get('timeouts', 0)}",
                f"   Failed Connect Attempts: {c.get('timeouts', 0)}",
                f"        Total Packets Sent: {c.get('requests', 0)}",
                f"        Total Packets Recv: {c.get('accepts', 0) + c.get('rejects', 0) + c.get('errors', 0)}"]
    return "\n".join(out)


def run_lines(con, out: list[str]) -> list[str]:
    """show running-config with AAA's lines where IOS prints them."""
    own = _own(con.lab, con.device)
    out = list(out)
    if own.get("aaa"):
        if "aaa new-model" in out:
            out = [x for x in out if x != "no aaa new-model"]
        elif "no aaa new-model" in out:
            out[out.index("no aaa new-model")] = "aaa new-model"
    if "aaa new-model" in out:
        k = out.index("aaa new-model") + 1
        add = ["!"]
        for key, word in (("aaa-login", "aaa authentication login"), ("aaa-exec", "aaa authorization exec")):
            for name in sorted((x[len(key) + 1:] for x in own if x.startswith(key + ":")),
                               key=lambda n: (n != "default", n)):
                add.append(f"{word} {name} {own[f'{key}:{name}']}")
        cmd = sorted((x for x in own if x.startswith("aaa-cmd:")),
                     key=lambda x: (int(x.split(":")[1]), x.split(":")[2] != "default", x))
        add += [f"aaa authorization commands {x.split(':')[1]} {x.split(':')[2]} {own[x]}" for x in cmd]
        if own.get("aaa-console"):
            add.append("aaa authorization console")
        if own.get("aaa-nocfgcmds"):
            add.append("no aaa authorization config-commands")
        acct = sorted((x for x in own if x.startswith("aaa-acct-")),
                      key=lambda x: (not x.startswith("aaa-acct-exec"), x))
        for x in acct:
            what, _, name = x[len("aaa-acct-"):].rpartition(":")
            word = "exec" if what == "exec" else f"commands {what.split(':')[1]}"
            add.append(f"aaa accounting {word} {name} {own[x]}")
        if len(add) > 1:
            out[k:k] = add
    blocks = []
    if con.device == devcli.ROUTER:
        for s in radius_servers(con.lab, con.device):
            blocks.append(f"radius server {s['name']}")
            if s["ip"]:
                blocks.append(f" address ipv4 {s['ip']} auth-port {s['port']} acct-port {s['acct']}")
            if s["key"]:
                blocks.append(f" key {s['key']}")
            blocks.append("!")
    for s in tacacs_servers(con.lab, con.device):
        blocks.append(f"tacacs server {s['name']}")
        if s["ip"]:
            blocks.append(f" address ipv4 {s['ip']}")
        if s["key"]:
            blocks.append(f" key {s['key']}")
        if s["port"] != TACACS_PORT:
            blocks.append(f" port {s['port']}")
        blocks.append("!")
    if blocks:
        j = next((i for i, x in enumerate(out) if x.startswith(("banner motd", "line con 0"))), len(out))
        out[j:j] = blocks
    for line, label in (("con", "line con 0"), ("vty", "line vty 0 4")):
        if label not in out:
            continue
        k = out.index(label) + 1
        end = k
        while end < len(out) and out[end].startswith(" "):
            end += 1
        body = [x for x in out[k:end] if not (own.get("aaa") and x == " login")]   # no plain login under AAA
        if own.get(f"line-{line}:login-list"):
            body.append(f" login authentication {own[f'line-{line}:login-list']}")
        out[k:end] = body
    return out


# ------------------------------------------------------------------ the troubleshooting fault
_CLIENTS = "/etc/freeradius/3.0/clients.conf"
_KEEP = "/var/lib/winlab/ts-radius-key"
_GW = "gw=$(ip -4 route show default | awk '{print $3; exit}'); "
# the shared key of clients.conf's client block for the router (its address is the machine's gateway)
_EXTRACT = ("awk -v ip=\"$gw\" '/^[ \\t]*client[ \\t]/ { inb = 1; hit = 0; v = \"\" } "
            "inb && $0 ~ (\"addr[ \\t]*=[ \\t]*\" ip \"([ \\t/]|$)\") { hit = 1 } "
            "inb && /^[ \\t]*secret[ \\t]*=/ { v = $0; sub(/^[^=]*=[ \\t]*/, \"\", v) } "
            "inb && /^[ \\t]*}/ { inb = 0; if (hit && v != \"\") { print v; exit } }' " + _CLIENTS)
_REWRITE = ("awk -v ip=\"$gw\" -v new=\"$new\" -v keep=" + _KEEP + " '{ line[NR] = $0 } "
            "/^[ \\t]*client[ \\t]/ { inb = 1; hit = 0; start = NR } "
            "inb && $0 ~ (\"addr[ \\t]*=[ \\t]*\" ip \"([ \\t/]|$)\") { hit = 1 } "
            "inb && /^[ \\t]*}/ { inb = 0; if (hit) for (k = start; k <= NR; k++) "
            "if (line[k] ~ /^[ \\t]*secret[ \\t]*=/) { v = line[k]; sub(/^[^=]*=[ \\t]*/, \"\", v); print v > keep; "
            "p = line[k]; sub(/=.*/, \"= \" new, p); line[k] = p; done = 1 } } "
            "END { for (k = 1; k <= NR; k++) print line[k]; if (!done) exit 3 }' " + _CLIENTS)


def _faults():
    from .guestfaults import LINUX, GuestFault
    return [GuestFault(
        id="radius-key-retyped",
        images=("ubuntu",),
        title="Logins to the router fall back to the local admin: the RADIUS server's key for it was retyped",
        os=LINUX,
        teaches="what a shared key mismatch looks like from the router (no answer, so the next method of "
                "the list) and from the server (packets dropped for a bad Message-Authenticator), why "
                "'group radius local' keeps a break-glass account working, and show aaa servers and "
                "test aaa as the first tools",
        symptom="staff accounts kept on the RADIUS server can no longer log in to the router over SSH "
                "(% Authentication failed); only the router's own local admin still gets in",
        apply=("[ -f " + _CLIENTS + " ] || { echo 'no FreeRADIUS on this machine: build the RADIUS login first "
               "(lesson aaa-radius-device-login)'; exit 1; }; " + _GW + "mkdir -p /var/lib/winlab; "
               "cp " + _CLIENTS + " /var/lib/winlab/ts-radius-clients.conf; "
               "new=$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \\n'); "
               "if " + _REWRITE + " > " + _CLIENTS + ".new; then cat " + _CLIENTS + ".new > " + _CLIENTS
               + "; rm -f " + _CLIENTS + ".new; systemctl restart freeradius; echo broken; else rm -f "
               + _CLIENTS + ".new; echo \"no client for the router ($gw) with a key in " + _CLIENTS
               + ": build the RADIUS login first\"; exit 1; fi"),
        clear=("[ -f /var/lib/winlab/ts-radius-clients.conf ] && cat /var/lib/winlab/ts-radius-clients.conf > "
               + _CLIENTS + " && systemctl restart freeradius; rm -f /var/lib/winlab/ts-radius-clients.conf "
               + _KEEP + "; echo ok"),
        shell="sh",
        hints=(
            "Start on the router's console: show aaa servers. Requests go out and the 'incorrect' or timeout "
            "count climbs while accept and reject stay where they were: the server is not answering anything "
            "the router can trust. test aaa group radius <a staff user> <their password> legacy says the same "
            "in one line. The local admin still works because the list is group radius local: no answer means "
            "the next method.",
            "Ask the server why: sudo systemctl stop freeradius, then sudo freeradius -X, and log in again. "
            "It drops the router's request: invalid Message-Authenticator, shared secret is incorrect. The "
            "router's own key is the one the network team keeps (show running-config, radius server).",
            "Someone retyped the router's client entry in /etc/freeradius/3.0/clients.conf. Put its key back "
            "to the router's (the client block whose ipaddr is the router's address), then sudo systemctl "
            "restart freeradius, and log in over SSH with a staff account again.",
        ),
        verify=(_GW + "cur=$(" + _EXTRACT + "); [ -n \"$cur\" ] && [ \"$cur\" = \"$(cat " + _KEEP
                + " 2>/dev/null)\" ] && systemctl is-active -q freeradius && echo True || echo False"),
    )]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
