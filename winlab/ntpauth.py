"""NTP authentication on the lab router's console, made real by chrony
(the router's NTP client, winlab/nms.py).

``ntp authentication-key <id> md5 | sha1 | hmac-sha2-256 <key>`` becomes a
line of chrony's key file (/etc/winlab/chrony.keys, ``<id> MD5 HEX:...``:
the key's own bytes, so a key typed with any characters reaches chrony
unchanged); ``ntp trusted-key <id>`` marks the keys the router may
authenticate a server with; ``ntp server <ip> key <id>`` names the key for
that server; ``ntp authenticate`` makes authentication required:

* with ``ntp authenticate`` on, a server whose key is defined and trusted
  is a chrony ``server <ip> key <id>`` source: every request carries a MAC
  made with the key and chrony drops a reply whose MAC does not check; and
  chrony's ``authselectmode require`` keeps every source that is not
  authenticated out of the selection, so a server with no trusted key, or a
  key the server does not have, never sets the clock: ``show ntp status``
  stays unsynchronized, as on IOS;
* without ``ntp authenticate`` the keys are kept but not used, and the
  servers are plain sources. IOS without it still signs its requests to a
  server with a key and takes the answers either way; chrony has no such
  middle mode, so here nothing is signed until ``ntp authenticate``.

The server end is the lab's NTP server (ntp01, chrony too): the same key ID
and key in a key file named by ``keyfile`` in its chrony.conf. ``show ntp
associations detail`` reads chronyc's authdata (the mode SK and the key ID
per source) and its sources, so "authenticated" is what chrony says.

Settings (on the router): ``ntp-auth`` = yes; ``ntp-key:<id>`` = ``<alg>
7 <scrambled key>``; ``ntp-trusted:<id>`` = yes; ``ntp:<ip>`` = ``yes`` or
``key <id>``.
"""

from __future__ import annotations

import re

KEYFILE = "/etc/winlab/chrony.keys"
ALGS = {"md5": "MD5", "sha1": "SHA1", "hmac-sha2-256": "SHA256"}


def _own(lab) -> dict:
    from . import devcli
    return lab.devices.get(devcli.ROUTER, {})


def keys(own: dict) -> dict[int, tuple[str, str]]:
    """id -> (algorithm, the key in clear)."""
    from . import iosnv
    out = {}
    for k, v in own.items():
        if k.startswith("ntp-key:") and k[8:].isdigit():
            alg, _, kept = str(v).partition(" ")
            kind, _, val = kept.partition(" ")
            try:
                out[int(k[8:])] = (alg, iosnv.untype7(val) if kind == "7" else val)
            except ValueError:
                continue
    return dict(sorted(out.items()))


def trusted(own: dict) -> list[int]:
    return sorted(int(k[12:]) for k in own if k.startswith("ntp-trusted:") and k[12:].isdigit())


def server_key(own: dict, ip: str) -> int | None:
    m = re.match(r"key (\d+)", str(own.get(f"ntp:{ip}", "")))
    return int(m.group(1)) if m else None


def required(own: dict) -> bool:
    return bool(own.get("ntp-auth"))


def usable_key(own: dict, ip: str) -> int | None:
    """The key a server line authenticates with: named on the line, defined,
    trusted, and ntp authenticate on."""
    kid = server_key(own, ip)
    if kid is None or not required(own) or kid not in keys(own) or kid not in trusted(own):
        return None
    return kid


# ------------------------------------------------------------------ chrony
def keyfile_text(lab) -> str:
    own = _own(lab)
    return "".join(f"{kid} {ALGS.get(alg, 'MD5')} HEX:{key.encode().hex().upper()}\n"
                   for kid, (alg, key) in keys(own).items())


def chrony_lines(lab, servers: list[str]) -> list[str]:
    """chrony.conf's server lines and what authentication adds."""
    own = _own(lab)
    out = []
    if keys(own):
        out.append(f"keyfile {KEYFILE}")
    if required(own):
        out.append("authselectmode require")
    for ip in servers:
        kid = usable_key(own, ip)
        out.append(f"server {ip} iburst" + (f" key {kid}" if kid is not None else ""))
    return out


def push_lines(lab) -> list[str]:
    text = keyfile_text(lab)
    if not text:
        return [f"rm -f {KEYFILE}"]
    return [f"cat > {KEYFILE} <<'WLNTPKEY'\n{text}WLNTPKEY", f"chmod 640 {KEYFILE}"]


# ------------------------------------------------------------------ show running-config
def run_lines(lab, device: str) -> list[str]:
    from . import devcli
    if device != devcli.ROUTER:
        return []
    own = _own(lab)
    out = ["ntp authenticate"] if required(own) else []
    for kid, (alg, _key) in keys(own).items():
        # IOS shows an NTP key scrambled (type 7) whatever service password-encryption says
        out.append(f"ntp authentication-key {kid} {alg} {own[f'ntp-key:{kid}'].split()[2]} 7")
    out += [f"ntp trusted-key {kid}" for kid in trusted(own)]
    return out


def server_suffix(lab, device: str, ip: str) -> str:
    from . import devcli
    if device != devcli.ROUTER:
        return ""
    kid = server_key(_own(lab), ip)
    return f" key {kid}" if kid is not None else ""


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C) -> None:
    from . import devcli
    if con.device != devcli.ROUTER:
        return
    for k, v in {("ntp", "authenticate"): "Authenticate time sources",
                 ("ntp", "authentication-key"): "Authentication key for trusted time sources",
                 ("ntp", "trusted-key"): "Key numbers for trusted time sources"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    add("ntp authenticate", lambda a: _flag(con, True), "Authenticate time sources", C)
    add("no ntp authenticate", lambda a: _flag(con, False), "Negate a command or set its defaults", C)
    add("ntp authentication-key <num> <name> <line>", lambda a: _key(con, a[0], a[1], a[2]),
        "Authentication key for trusted time sources", C)
    add("no ntp authentication-key <num>", lambda a: _no_key(con, a[0]), "Negate a command or set its defaults", C)
    add("no ntp authentication-key <num> <line>", lambda a: _no_key(con, a[0]), "Negate a command or set its defaults", C)
    add("ntp trusted-key <num>", lambda a: _trust(con, a[0], True), "Key numbers for trusted time sources", C)
    add("no ntp trusted-key <num>", lambda a: _trust(con, a[0], False), "Negate a command or set its defaults", C)
    add("show ntp associations detail", lambda a: show_detail(con), "Show detail", U)


def _mine(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _saved(con) -> str:
    from . import nms
    return nms._saved(con, push=True)


def _flag(con, on: bool) -> str:
    own = _mine(con)
    if on:
        own["ntp-auth"] = "yes"
    else:
        own.pop("ntp-auth", None)
    note = _saved(con)
    if on:
        from . import nms
        bare = [ip for ip in nms.ntp_servers(con.lab) if usable_key(own, ip) is None]
        if bare:
            note = "\n".join(x for x in (f"% {', '.join(bare)}: no trusted key on the server line, so it is not "
                                         f"used for time now that authentication is required", note) if x)
    return note


def _key(con, kid: str, alg: str, rest: str) -> str:
    from . import devcli, iosnv
    n = int(kid)
    if not 1 <= n <= 4294967295:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    alg = alg.lower()
    if alg not in ALGS:
        raise devcli.CliError(f"% {alg}: this router's NTP takes md5, sha1 or hmac-sha2-256 keys")
    w = rest.split()
    if len(w) == 2 and w[1] == "7":
        try:
            clear = iosnv.untype7(w[0])
        except ValueError:
            raise devcli.CliError("% Invalid encrypted key") from None
    elif len(w) == 1:
        clear = w[0]
    else:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    if not 1 <= len(clear) <= 32:
        raise devcli.CliError("% The key is 1 to 32 characters")
    _mine(con)[f"ntp-key:{n}"] = f"{alg} 7 {iosnv.type7(clear)}"
    return _saved(con)


def _no_key(con, kid: str) -> str:
    _mine(con).pop(f"ntp-key:{int(kid)}", None)
    return _saved(con)


def _trust(con, kid: str, on: bool) -> str:
    own = _mine(con)
    if on:
        own[f"ntp-trusted:{int(kid)}"] = "yes"
    else:
        own.pop(f"ntp-trusted:{int(kid)}", None)
    note = _saved(con)
    if on and int(kid) not in keys(own):
        note = "\n".join(x for x in (f"% Key {int(kid)} is not defined yet: ntp authentication-key {int(kid)} md5 <key>",
                                     note) if x)
    return note


def parse_authdata(text: str) -> dict[str, dict]:
    """chronyc -n authdata -> {address: {"mode": "SK" | "-" | "NTS", "key": n}}."""
    out = {}
    for line in text.splitlines():
        w = line.split()
        if len(w) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", w[0]):
            out[w[0]] = {"mode": w[1], "key": int(w[2]) if w[2].isdigit() else 0}
    return out


def show_detail(con) -> str:
    from . import nms, timesync
    own = _own(con.lab)
    servers = nms.ntp_servers(con.lab)
    if not servers:
        return "%NTP is not enabled."
    text = nms._router_text(con, "chronyc -n authdata 2>&1; echo '#src'; chronyc -n sources 2>&1")
    auth_t, _, src_t = text.partition("#src")
    auth = parse_authdata(auth_t)
    src = {s["name"]: s for s in timesync.parse_sources(src_t)}
    out = []
    for ip in servers:
        s = src.get(ip, {})
        a = auth.get(ip, {})
        signed = a.get("mode") == "SK"
        state = {"*": "our_master, sane, valid", "+": "candidate, sane, valid", "-": "outlyer",
                 "x": "falseticker", "?": "unreachable, insane, invalid"}.get(
            s.get("state", "?"), "insane, invalid")
        # chrony names the key (SK) whether or not the answers pass it: a
        # source that signs and has never answered usably is not authenticated
        heard = s.get("state", "?") != "?"
        words = ["configured", "ipv4", ("authenticated" if heard else "not authenticated") if signed else "insecure",
                 state]
        out.append(f"{ip} {', '.join(words)}, stratum {s.get('stratum', 16)}")
        out.append(f"ref ID .NTP., time is {'trusted' if s.get('state') == '*' else 'not trusted'}")
        kid = server_key(own, ip)
        if kid is None:
            why = ""
        elif usable_key(own, ip) is not None:
            why = " (in use)" if signed else " (in use, but chrony has had no authenticated answer yet)"
        elif not required(own):
            why = " (not used: ntp authenticate is off)"
        else:
            why = " (not used: the key is not defined or not trusted)"
        out.append(f"key id {kid if kid is not None else 'none'}{why}")
        out.append(f"reach {s.get('reach', 0)}, poll 64")
        out.append("")
    if required(own):
        out.append("Authentication required (ntp authenticate): sources that are not authenticated are not used")
    return "\n".join(out).rstrip()
