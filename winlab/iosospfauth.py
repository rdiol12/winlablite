"""OSPF authentication and key chains typed at the lab router's console,
made real by FRRouting's ospfd (winlab/iosrouting.py writes them into
/etc/frr/frr.conf).

* ``ip ospf authentication [message-digest | null | key-chain <name>]`` on
  an interface, ``ip ospf authentication-key <text>`` (plain text, type 1,
  up to 8 characters) and ``ip ospf message-digest-key <id> md5 <text>``
  (type 2, MD5 with a key ID, up to 16 characters) are ospfd's own interface
  commands of the same names;
* ``area <id> authentication [message-digest]`` under ``router ospf`` turns
  it on for every interface of the area (an interface's own ``ip ospf
  authentication`` wins), as on IOS and in ospfd;
* ``key chain <name>`` with ``key <id>``, ``key-string <text>`` and
  ``cryptographic-algorithm <alg>`` is FRRouting's key chain (its library's,
  shared by the daemons), and ``ip ospf authentication key-chain <name>``
  is ospfd's HMAC-SHA authentication from a key chain (RFC 5709), which
  FRRouting has had since 10.0; the lab router's Alpine FRRouting has it.
  rtr-edge's Ubuntu FRRouting (8.4) does not: between those two routers use
  message-digest keys, and keep key chains for the lab router's own links or
  another FRRouting 10 router.

A key is kept as IOS keeps a password typed in clear: a type 7 scramble
(winlab/iosnv.py) in the lab file, shown in clear in show running-config
unless ``service password-encryption`` is on. ospfd's file has it in clear,
as any FRRouting configuration does.

Settings: ``ospf-auth:<if>`` = text | md5 | null | kc:<chain>;
``ospf-authkey:<if>`` = the plain key (7 ...); ``ospf-md5:<if>:<id>`` =
the MD5 key (7 ...); ``ospf-areaauth:<pid>:<area>`` = text | md5;
``keychain:<name>`` = yes; ``keychain-key:<name>:<id>`` = the key string
(7 ...); ``keychain-alg:<name>:<id>`` = the algorithm.
"""

from __future__ import annotations

import re

ALGS = ("md5", "hmac-sha-1", "hmac-sha-256", "hmac-sha-384", "hmac-sha-512")
KC, KCK = "config-keychain", "config-keychain-key"


def _err(text: str):
    from . import devcli
    return devcli.CliError(text)


def _bad():
    return _err("% Invalid input detected at '^' marker.")


def _clear(kept: str) -> str:
    from . import iosnv
    kind, _, value = kept.partition(" ")
    if kind == "7":
        try:
            return iosnv.untype7(value)
        except ValueError:
            return ""
    return value


def _keep(text: str) -> str:
    from . import iosnv
    return f"7 {iosnv.type7(text)}"


def chains(own: dict) -> list[str]:
    return sorted(k[9:] for k in own if k.startswith("keychain:"))


def chain_keys(own: dict, name: str) -> list[int]:
    pre = f"keychain-key:{name}:"
    return sorted({int(k.rsplit(":", 1)[1]) for k in own if k.startswith((pre, f"keychain-alg:{name}:"))
                   and k.rsplit(":", 1)[1].isdigit()})


def md5_keys(own: dict, ifname: str) -> list[tuple[int, str]]:
    pre = f"ospf-md5:{ifname}:"
    return sorted((int(k[len(pre):]), v) for k, v in own.items() if k.startswith(pre) and k[len(pre):].isdigit())


def area_auth(own: dict, pid: int) -> list[tuple[str, str]]:
    pre = f"ospf-areaauth:{pid}:"
    return sorted((k[len(pre):], v) for k, v in own.items() if k.startswith(pre))


# ------------------------------------------------------------------ frr.conf
def frr_keychain_lines(own: dict) -> list[str]:
    out = []
    for name in chains(own):
        out.append(f"key chain {name}")
        for kid in chain_keys(own, name):
            out.append(f" key {kid}")
            if own.get(f"keychain-key:{name}:{kid}"):
                out.append(f"  key-string {_clear(own[f'keychain-key:{name}:{kid}'])}")
            if own.get(f"keychain-alg:{name}:{kid}"):
                out.append(f"  cryptographic-algorithm {own[f'keychain-alg:{name}:{kid}']}")
            out.append(" exit")
        out += ["exit", "!"]
    return out


def frr_iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    how = own.get(f"ospf-auth:{ifname}")
    if how == "text":
        out.append(" ip ospf authentication")
    elif how == "md5":
        out.append(" ip ospf authentication message-digest")
    elif how == "null":
        out.append(" ip ospf authentication null")
    elif how and how.startswith("kc:"):
        out.append(f" ip ospf authentication key-chain {how[3:]}")
    if own.get(f"ospf-authkey:{ifname}"):
        out.append(f" ip ospf authentication-key {_clear(own[f'ospf-authkey:{ifname}'])}")
    for kid, kept in md5_keys(own, ifname):
        out.append(f" ip ospf message-digest-key {kid} md5 {_clear(kept)}")
    return out


def frr_area_lines(own: dict, pid: int) -> list[str]:
    return [f" area {area} authentication" + (" message-digest" if how == "md5" else "")
            for area, how in area_auth(own, pid)]


# ------------------------------------------------------------------ show running-config
def iface_lines(own: dict, ifname: str) -> list[str]:
    from . import iosnv
    enc = bool(own.get("service-pwenc"))
    out = []
    how = own.get(f"ospf-auth:{ifname}")
    if how:
        out.append(" ip ospf authentication" + {"text": "", "md5": " message-digest", "null": " null"}.get(
            how, f" key-chain {how[3:]}"))
    if own.get(f"ospf-authkey:{ifname}"):
        k = own[f"ospf-authkey:{ifname}"]
        out.append(" ip ospf authentication-key " + (f"7 {k[2:]}" if enc else iosnv.run_form(k, False)))
    for kid, k in md5_keys(own, ifname):
        out.append(f" ip ospf message-digest-key {kid} md5 " + (f"7 {k[2:]}" if enc else iosnv.run_form(k, False)))
    return out


def area_run_lines(own: dict, pid: int) -> list[str]:
    return frr_area_lines(own, pid)


def keychain_run_lines(own: dict) -> list[str]:
    from . import iosnv
    enc = bool(own.get("service-pwenc"))
    out = []
    for name in chains(own):
        out.append(f"key chain {name}")
        for kid in chain_keys(own, name):
            out.append(f" key {kid}")
            k = own.get(f"keychain-key:{name}:{kid}")
            if k:
                out.append("  key-string " + (f"7 {k[2:]}" if enc else iosnv.run_form(k, False)))
            if own.get(f"keychain-alg:{name}:{kid}"):
                out.append(f"  cryptographic-algorithm {own[f'keychain-alg:{name}:{kid}']}")
        out.append("!")
    return out


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, IF, RM) -> None:
    from . import devcli
    for k, v in {("key",): "Key management", ("key", "chain"): "Key-chain management",
                 ("ip", "ospf", "authentication"): "Enable authentication",
                 ("ip", "ospf", "message-digest-key"): "Message digest authentication password (key)",
                 ("ip", "ospf", "authentication-key"): "Authentication password (key)",
                 ("area",): "OSPF area parameters"}.items():
        devcli.WORD_HELP.setdefault(k, v)
    M = (KC, KCK)
    add("end", con._end, "Exit from configure mode", M)
    add("exit", lambda a: _exit(con), "Exit from key-chain configuration mode", M)
    add("do <line>", con._do, "To run exec commands in config mode", M)
    add("key chain <name>", lambda a: chain(con, a[0]), "Key-chain management", C + M)
    add("no key chain <name>", lambda a: no_chain(con, a[0]), "Negate a command or set its defaults", C + M)
    add("key <num>", lambda a: key(con, a[0]), "Configure a key", M)
    add("no key <num>", lambda a: no_key(con, a[0]), "Negate a command or set its defaults", M)
    add("key-string <line>", lambda a: key_string(con, a[0]), "Set key string", (KCK,))
    add("no key-string", lambda a: key_string(con, ""), "Negate a command or set its defaults", (KCK,))
    add("cryptographic-algorithm <name>", lambda a: algorithm(con, a[0]), "Set cryptographic authentication algorithm", (KCK,))
    add("no cryptographic-algorithm", lambda a: algorithm(con, ""), "Negate a command or set its defaults", (KCK,))
    add("accept-lifetime <line>", lambda a: _lifetime(), "Set accept lifetime of key", (KCK,))
    add("send-lifetime <line>", lambda a: _lifetime(), "Set send lifetime of key", (KCK,))
    add("ip ospf authentication", lambda a: if_auth(con, "text"), "Enable authentication", IF)
    add("ip ospf authentication <line>", lambda a: if_auth(con, a[0]), "Enable authentication", IF)
    add("ip ospf authentication-key <line>", lambda a: if_text_key(con, a[0]), "Authentication password (key)", IF)
    add("ip ospf message-digest-key <num> md5 <line>", lambda a: if_md5(con, a[0], a[1], True),
        "Message digest authentication password (key)", IF)
    add("no ip ospf message-digest-key <num>", lambda a: if_md5(con, a[0], "", False), "Negate a command or set its defaults", IF)
    add("no ip ospf message-digest-key <num> <line>", lambda a: if_md5(con, a[0], "", False), "Negate a command or set its defaults", IF)
    add("no ip ospf authentication", lambda a: if_auth(con, ""), "Negate a command or set its defaults", IF)
    add("no ip ospf authentication <line>", lambda a: if_auth(con, ""), "Negate a command or set its defaults", IF)
    add("no ip ospf authentication-key", lambda a: if_text_key(con, ""), "Negate a command or set its defaults", IF)
    add("no ip ospf authentication-key <line>", lambda a: if_text_key(con, ""), "Negate a command or set its defaults", IF)
    add("area <name> authentication", lambda a: area(con, a[0], "text", True), "Enable authentication", RM)
    add("area <name> authentication message-digest", lambda a: area(con, a[0], "md5", True), "Use message-digest authentication", RM)
    add("no area <name> authentication", lambda a: area(con, a[0], "", False), "Negate a command or set its defaults", RM)
    add("no area <name> authentication <line>", lambda a: area(con, a[0], "", False), "Negate a command or set its defaults", RM)


def _own_c(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _done(con) -> str:
    return con._save().strip()


def _exit(con) -> str:
    if con.s.mode == KCK:
        con.s.mode, con.s.ctx = KC, con.s.ctx.split(":", 1)[0]
    else:
        con.s.mode, con.s.ctx = "config", ""
    return ""


def _lifetime() -> str:
    return ("% accept-lifetime and send-lifetime are not taken here: a key of this router's chains is always "
            "valid (add the new key, then take the old one away to roll it)")


def chain(con, name: str) -> str:
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", name):
        raise _err("% A key chain name is up to 32 letters, digits, '.', '-' or '_'")
    own = _own_c(con)
    new = f"keychain:{name}" not in own
    own[f"keychain:{name}"] = "yes"
    con.s.mode, con.s.ctx = KC, name
    return _done(con) if new else (con._save(live=False) or "")


def no_chain(con, name: str) -> str:
    own = _own_c(con)
    for k in [k for k in own if k == f"keychain:{name}" or k.startswith((f"keychain-key:{name}:",
                                                                         f"keychain-alg:{name}:"))]:
        del own[k]
    users = [k.split(":", 1)[1] for k, v in own.items() if k.startswith("ospf-auth:") and v == f"kc:{name}"]
    note = _done(con)
    if users:
        note = "\n".join(x for x in (f"% {', '.join(users)} still use key chain {name}: with no keys, OSPF "
                                     f"neighbours there go down", note) if x)
    return note


def key(con, kid: str) -> str:
    if not kid.isdigit() or int(kid) > 2147483647:
        raise _bad()
    name = con.s.ctx.split(":", 1)[0]
    own = _own_c(con)
    own.setdefault(f"keychain-key:{name}:{int(kid)}", "")
    con.s.mode, con.s.ctx = KCK, f"{name}:{int(kid)}"
    con._save(live=False)
    return ""


def no_key(con, kid: str) -> str:
    name = con.s.ctx.split(":", 1)[0]
    own = _own_c(con)
    own.pop(f"keychain-key:{name}:{kid}", None)
    own.pop(f"keychain-alg:{name}:{kid}", None)
    if con.s.mode == KCK:
        con.s.mode, con.s.ctx = KC, name
    return _done(con)


def key_string(con, text: str) -> str:
    name, kid = con.s.ctx.split(":", 1)
    own = _own_c(con)
    w = text.split()
    if w[:1] == ["7"] and len(w) == 2:
        from . import iosnv
        try:
            text = iosnv.untype7(w[1])
        except ValueError:
            raise _err("% Invalid encrypted keystring") from None
    elif w[:1] == ["0"] and len(w) == 2:
        text = w[1]
    if text and (len(text) > 80 or " " in text.strip()):
        raise _err("% The key string is up to 80 characters, no spaces")
    own[f"keychain-key:{name}:{kid}"] = _keep(text.strip()) if text else ""
    return _done(con)


def algorithm(con, alg: str) -> str:
    name, kid = con.s.ctx.split(":", 1)
    own = _own_c(con)
    if not alg:
        own.pop(f"keychain-alg:{name}:{kid}", None)
        own.setdefault(f"keychain-key:{name}:{kid}", "")
        return _done(con)
    hit = [a for a in ALGS if a.startswith(alg.lower())]
    if alg.lower() in ALGS:
        hit = [alg.lower()]
    if len(hit) != 1:
        raise _err(f"% {alg}: this router's key chains take {', '.join(ALGS)}")
    own[f"keychain-alg:{name}:{kid}"] = hit[0]
    return _done(con)


def if_auth(con, how: str) -> str:
    own = _own_c(con)
    ifname = con.s.ctx
    w = how.split()
    if not how:
        own.pop(f"ospf-auth:{ifname}", None)
        return _done(con)
    word = w[0].lower()
    if how == "text":
        val = "text"
    elif "message-digest".startswith(word) and word[:1] == "m" and len(w) == 1:
        val = "md5"
    elif word == "null" and len(w) == 1:
        val = "null"
    elif "key-chain".startswith(word) and word[:1] == "k" and len(w) == 2:
        val = f"kc:{w[1]}"
    else:
        raise _bad()
    own[f"ospf-auth:{ifname}"] = val
    note = _done(con)
    if val.startswith("kc:") and f"keychain:{val[3:]}" not in own:
        note = "\n".join(x for x in (f"% Key chain {val[3:]} does not exist yet: no key, no neighbour", note) if x)
    if val == "md5" and not md5_keys(own, ifname):
        note = "\n".join(x for x in ("% No message-digest key on this interface yet: ip ospf message-digest-key "
                                     "<id> md5 <key>", note) if x)
    return note


def if_text_key(con, text: str) -> str:
    own = _own_c(con)
    ifname = con.s.ctx
    if not text:
        own.pop(f"ospf-authkey:{ifname}", None)
        return _done(con)
    w = text.split()
    if w[0] == "7" and len(w) == 2:
        from . import iosnv
        try:
            text = iosnv.untype7(w[1])
        except ValueError:
            raise _err("% Invalid encrypted password") from None
    elif w[0] == "0" and len(w) == 2:
        text = w[1]
    elif len(w) != 1:
        raise _bad()
    note = ""
    if len(text) > 8:
        note = "% OSPF: Key is longer than 8 characters: only the first 8 are used"
        text = text[:8]
    own[f"ospf-authkey:{ifname}"] = _keep(text)
    return "\n".join(x for x in (note, _done(con)) if x)


def if_md5(con, kid: str, text: str, on: bool) -> str:
    if not kid.isdigit() or not 1 <= int(kid) <= 255:
        raise _bad()
    own = _own_c(con)
    ifname = con.s.ctx
    key_ = f"ospf-md5:{ifname}:{int(kid)}"
    if not on:
        own.pop(key_, None)
        return _done(con)
    w = text.split()
    if w and w[0] == "7" and len(w) == 2:
        from . import iosnv
        try:
            text = iosnv.untype7(w[1])
        except ValueError:
            raise _err("% Invalid encrypted password") from None
    elif w and w[0] == "0" and len(w) == 2:
        text = w[1]
    elif len(w) != 1:
        raise _bad()
    if len(text) > 16:
        raise _err("% OSPF: the MD5 key is 1 to 16 characters")
    if md5_keys(own, ifname) and key_ not in own:
        note = ("% A second key: this router sends with the newest key ID and accepts each, as IOS rolls a key over; "
                "take the old one away once the neighbours have the new one")
    else:
        note = ""
    own[key_] = _keep(text)
    return "\n".join(x for x in (note, _done(con)) if x)


def area(con, text: str, how: str, on: bool) -> str:
    from .iosrouting import _area, _cur
    kind, pid = _cur(con)
    if kind != "ospf":
        raise _bad()
    a = _area(text)
    own = _own_c(con)
    k = f"ospf-areaauth:{pid}:{a}"
    if on:
        own[k] = how
    else:
        own.pop(k, None)
    return _done(con)


def forget_pid(own: dict, pid: int) -> None:
    for k in [k for k in own if k.startswith(f"ospf-areaauth:{pid}:")]:
        del own[k]
