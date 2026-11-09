"""SSH to the lab router and the switches, from the lab's own machines.

On a real switch, SSH takes five things typed at the console: a hostname
other than the factory one, ``ip domain-name``, an RSA key pair
(``crypto key generate rsa modulus 2048``), a local user (``username ...
secret ...``) and the vty lines told to use them (``line vty 0 4``,
``login local``, ``transport input ssh``); ``ip ssh version 2`` turns the
old protocol off. Then ``ssh admin@<the switch's address>`` from a PC
reaches the same command line as the console cable.

How it is real.

* The key pair is generated here when ``crypto key generate rsa`` is typed
  (real RSA: two primes, Miller-Rabin, e = 65537), kept in ``sshkeys.json``
  beside the lab's machines, and named in the device's configuration, so it
  survives a reload only once written to NVRAM, as on IOS. ``show crypto key
  mypubkey rsa`` prints its public half as IOS does (DER, in hex) and ``show
  ip ssh`` the fingerprint an SSH client asks you to confirm.
* The SSH server is Dropbear on the router (the fabric VM), one per device
  with a key: the router's on its own addresses on the lab's VLANs, a
  switch's inside the network namespace its management address lives in
  (winlab/iosl2.py). It listens on those addresses only, never anywhere the
  host could reach, forwards no ports (-j -k) and refuses root (-w).
* Every login runs one program on the router (``winlab-vty <device>``,
  Dropbear's forced command) whose bytes travel over a serial line of the
  router's own (ttyS2, a loopback socket only the desktop connects to) to
  the device's console here (devcli.Console): the same command line, the
  same configuration.
* With ``login local`` the SSH client asks for the password, as against a
  real switch, and the session lands straight at ``SW1>`` (``SW1#`` for a
  ``privilege 15`` user): Dropbear checks it against a user list of that
  device alone. When ``username ... secret`` is typed, winlab keeps a
  SHA-512 crypt of it (``ssh-hash:<user>``, beside IOS's own type 9 hash,
  bound to it) and each device's Dropbear runs in its own mount namespace
  (``winlab-sshd``: unshare -m, then /etc/shadow bind-mounted from that
  device's list), so the router's users and each switch's are separate,
  and a user typed with an already-hashed secret (``secret 9 $9$...``),
  whose clear text winlab never saw, cannot log in over SSH (said in the
  console). This is what makes Netmiko's cisco_ios, NAPALM's ios and
  Ansible's cisco.ios network_cli work against the consoles (winlab/netauto.py).
* With ``login`` and a line password Dropbear lets the session open without
  one (-B) and the console asks inside the session ("Password:").
* Under ``aaa new-model`` (winlab/aaa.py) the vty lines' method list
  decides. A list that starts with ``local`` (or no list at all, which on a
  vty line means local) keeps the SSH server's own check above, and the
  exec authorization list then sets the level. A list that starts with a
  server group (``group radius local``, ``group tacacs+``) cannot be checked
  by Dropbear, which has no PAM to ask a server with: the device's local
  users and the names a server has accepted (``aaa-names``) get empty
  passwords in its shadow file, -B lets them in, and the console asks
  "Password:" inside the session and asks the server. An OpenSSH client
  gets in that way (it tries the "none" method first); Netmiko, NAPALM and
  Ansible do not: paramiko sends the password in the SSH handshake, which
  Dropbear refuses for an empty-password account, so the login fails with
  "Authentication failed" before the console is reached. Automating a device
  whose vty lines authenticate through RADIUS or TACACS+ therefore needs a
  vty list that starts with local.
* ``transport input`` decides at login: a line that does not take ssh closes
  the connection at once.

What a real 2960 does that this one does not: SSH version 1 (no modern
client speaks it either), telnet (``transport input telnet`` is kept and
shown, but no telnet server runs), and the old ciphers a Catalyst on old
IOS offers, which newer clients need ``-o KexAlgorithms=+...`` for.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import select
import socket
import struct
import threading
import time

from . import devcli, paths, state

STORE = "sshkeys.json"
MODULUS = (360, 4096)
SSH_V2_MIN = 768
DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$")
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
LINE = "/dev/ttyS2"
VTYD = "/usr/local/bin/winlab-vtyd"
VTY = "/usr/local/bin/winlab-vty"
SSHD = "/usr/local/bin/winlab-sshd"
LOG = "/var/log/winlab-vty.log"
KEYDIR = "/etc/winlab-ssh"
RUN = "/run/winlab-ssh"
CHUNK = 2400
_WATCH: dict[str, object] = {}
SESSIONS: dict[tuple[str, str], dict] = {}   # (lab, sid) -> device, user, peer, since: for show ssh


# ------------------------------------------------------------------ RSA
_SMALL = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def _probably_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in _SMALL:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = secrets.SystemRandom()
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, e: int) -> int:
    rng = secrets.SystemRandom()
    while True:
        n = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if (n - 1) % e and _probably_prime(n):
            return n


def generate(bits: int) -> dict:
    """An RSA key pair of exactly `bits` bits: {n, e, d, p, q, bits}."""
    e = 65537
    while True:
        p, q = _prime((bits + 1) // 2, e), _prime(bits // 2, e)
        n = p * q
        if p != q and n.bit_length() == bits:
            break
    d = pow(e, -1, (p - 1) * (q - 1))
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": bits}


def _sshstr(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _mpint(x: int) -> bytes:
    return _sshstr(x.to_bytes((x.bit_length() + 8) // 8, "big") if x else b"")


def public_blob(key: dict) -> bytes:
    """The key as SSH sends it: string "ssh-rsa", mpint e, mpint n."""
    return _sshstr(b"ssh-rsa") + _mpint(key["e"]) + _mpint(key["n"])


def dropbear_key(key: dict) -> bytes:
    """Dropbear's own private key file: the public blob, then d, p and q."""
    return public_blob(key) + _mpint(key["d"]) + _mpint(key["p"]) + _mpint(key["q"])


def fingerprint(key: dict) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(public_blob(key)).digest()).decode().rstrip("=")


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + ln + body


def _der_int(x: int) -> bytes:
    return _der(0x02, x.to_bytes((x.bit_length() + 8) // 8, "big"))


def spki(key: dict) -> bytes:
    """SubjectPublicKeyInfo: what show crypto key mypubkey rsa prints in hex."""
    algo = _der(0x30, _der(0x06, bytes.fromhex("2A864886F70D010101")) + b"\x05\x00")
    rsa = _der(0x30, _der_int(key["n"]) + _der_int(key["e"]))
    return _der(0x30, algo + _der(0x03, b"\x00" + rsa))


# ------------------------------------------------------------------ SSH logins (login local)
_CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_CRYPT_ORDER = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
                (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
                (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41)]
HASH = "ssh-hash:"   # a device's setting: ssh-hash:<user> = "<binding> $6$<salt>$<hash>"


def sha512_crypt(clear: str, salt: str = "") -> str:
    """'$6$<salt>$<hash>': SHA-512 crypt (Drepper's specification, 5000
    rounds), what Alpine's musl checks an /etc/shadow password with."""
    salt = (salt or "".join(secrets.choice(_CRYPT64) for _ in range(16)))[:16]
    p, s, sha = clear.encode(), salt.encode(), hashlib.sha512
    b = sha(p + s + p).digest()
    a = sha(p + s)
    n = len(p)
    while n > 64:
        a.update(b)
        n -= 64
    a.update(b[:n])
    n = len(p)
    while n:
        a.update(b if n & 1 else p)
        n >>= 1
    a = a.digest()
    pp = (sha(p * len(p)).digest() * (len(p) // 64 + 1))[:len(p)]
    ss = (sha(s * (16 + a[0])).digest() * (len(s) // 64 + 1))[:len(s)]
    c = a
    for i in range(5000):
        h = sha(pp if i & 1 else c)
        if i % 3:
            h.update(ss)
        if i % 7:
            h.update(pp)
        h.update(c if i & 1 else pp)
        c = h.digest()
    out = []
    for x, y, z in _CRYPT_ORDER + [(None, None, 63)]:
        v = (c[x] << 16 | c[y] << 8 | c[z]) if x is not None else c[z]
        for _ in range(4 if x is not None else 2):
            out.append(_CRYPT64[v & 63])
            v >>= 6
    return f"$6${salt}$" + "".join(out)


def _binding(kept: str) -> str:
    return hashlib.sha256(kept.encode()).hexdigest()[:12]


def remember(con, name: str, typed: list[str]) -> str:
    """After ``username <name> ... secret|password <typed>``: keep the crypt
    Dropbear checks an SSH login with, when the clear text is known (typed
    in clear, or a type 7 password); a note when it is not."""
    from . import iosnv
    own = _own(con)
    kept = own.get(f"user:{name}", "").partition(" ")[2]
    clear = None
    if typed and typed[0] == "7" and len(typed) > 1:
        try:
            clear = iosnv.untype7(" ".join(typed[1:]))
        except ValueError:
            clear = None
    elif typed and typed[0] == "0" and len(typed) > 1:
        clear = " ".join(typed[1:])
    elif typed and typed[0] not in ("5", "8", "9"):
        clear = " ".join(typed)
    if clear is None:
        own.pop(HASH + name, None)
        return "% SSH logins for this user need its secret typed in clear (winlab never saw this one)"
    own[HASH + name] = f"{_binding(kept)} {sha512_crypt(clear)}"
    return ""


def login_hash(lab, device: str, user: str) -> str:
    """The crypt an SSH login as `user` is checked against on the device, or
    '' (none: the user cannot log in over SSH)."""
    own = lab.devices.get(device, {})
    kept = own.get(f"user:{user}", "").partition(" ")[2]
    bind, _, h = own.get(HASH + user, "").partition(" ")
    return h if kept and h.startswith("$6$") and bind == _binding(kept) else ""


# ------------------------------------------------------------------ the key store
def _store_path(lab_name: str):
    return paths.lab_dir(lab_name) / STORE


def _load(lab_name: str) -> dict:
    try:
        data = json.loads(_store_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _keep(lab_name: str, kid: str, key: dict) -> None:
    data = _load(lab_name)
    data[kid] = {k: (format(v, "x") if k in ("n", "d", "p", "q") else v) for k, v in key.items()}
    p = _store_path(lab_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def key_of(lab, device: str) -> dict | None:
    """The device's key pair (with its name and when it was made), or None."""
    ref = lab.devices.get(device, {}).get("rsa-key", "")
    parts = ref.split()
    if len(parts) < 3:
        return None
    raw = _load(lab.name).get(parts[0])
    if not isinstance(raw, dict):
        return None
    try:
        key = {k: int(raw[k], 16) for k in ("n", "d", "p", "q")}
        key.update(e=int(raw["e"]), bits=int(raw["bits"]), at=float(raw.get("at", 0)))
    except (KeyError, TypeError, ValueError):
        return None
    key["label"] = parts[2]
    key["id"] = parts[0]
    return key


def version(lab, device: str) -> str:
    """'1.99' (both, the default), '2.0' or '1.5', as show ip ssh says it."""
    v = lab.devices.get(device, {}).get("ssh-ver", "")
    return {"2": "2.0", "1": "1.5"}.get(v, "1.99")


def serving(lab, device: str) -> bool:
    """Whether the device's SSH server runs: a key of SSH v2's size, and not version 1 only."""
    key = key_of(lab, device)
    return bool(key) and key["bits"] >= SSH_V2_MIN and version(lab, device) != "1.5"


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    add("ip domain-name <name>", lambda a: set_domain(con, a[0]), "Define the default domain name", C)
    add("ip domain name <name>", lambda a: set_domain(con, a[0]), "Define the default domain name", C)
    add("no ip domain-name", lambda a: set_domain(con, ""), "Negate a command or set its defaults", C)
    add("no ip domain-name <name>", lambda a: set_domain(con, ""), "Negate a command or set its defaults", C)
    add("no ip domain name", lambda a: set_domain(con, ""), "Negate a command or set its defaults", C)
    add("no ip domain name <name>", lambda a: set_domain(con, ""), "Negate a command or set its defaults", C)
    add("crypto key generate rsa", lambda a: generate_cmd(con, ""), "Generate RSA keys", C)
    add("crypto key generate rsa <line>", lambda a: generate_cmd(con, a[0]), "Generate RSA keys", C)
    add("crypto key zeroize rsa", lambda a: zeroize(con), "Remove RSA keys", C)
    add("crypto key zeroize rsa <line>", lambda a: zeroize(con), "Remove RSA keys", C)
    add("ip ssh version <num>", lambda a: set_ssh(con, "ssh-ver", a[0], (1, 2)), "Specify protocol version supported", C)
    add("no ip ssh version", lambda a: set_ssh(con, "ssh-ver", "", (1, 2)), "Negate a command or set its defaults", C)
    add("ip ssh time-out <num>", lambda a: set_ssh(con, "ssh-timeout", a[0], (1, 120)),
        "Specify SSH time-out interval", C)
    add("no ip ssh time-out", lambda a: set_ssh(con, "ssh-timeout", "", (1, 120)), "Negate a command or set its defaults", C)
    add("ip ssh authentication-retries <num>", lambda a: set_ssh(con, "ssh-retries", a[0], (0, 5)),
        "Specify number of authentication retries", C)
    add("no ip ssh authentication-retries", lambda a: set_ssh(con, "ssh-retries", "", (0, 5)),
        "Negate a command or set its defaults", C)
    add("show ip ssh", lambda a: show_ip_ssh(con), "Information on SSH", U)
    add("show ssh", lambda a: show_ssh(con), "Status of SSH server connections", U)
    add("show crypto key mypubkey rsa", lambda a: show_key(con), "Show public keys associated with this router", U)


def _own(con) -> dict:
    return devcli.settings(con.lab, con.device)


def set_domain(con, name: str) -> str:
    own = _own(con)
    if not name:
        own.pop("domain", None)
    else:
        if not DOMAIN_RE.match(name) or len(name) > 253:
            raise devcli.CliError("% Invalid domain name")
        own["domain"] = name.lower()
    con._save(live=False)
    return ""


def set_ssh(con, key: str, value: str, rng: tuple[int, int]) -> str:
    own = _own(con)
    if not value:
        own.pop(key, None)
    else:
        n = int(value)
        if not rng[0] <= n <= rng[1]:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
        own[key] = str(n)
    note = ""
    if key == "ssh-ver" and value == "2":
        k = key_of(con.lab, con.device)
        if not k or k["bits"] < SSH_V2_MIN:
            note = f"Please create RSA keys (of atleast {SSH_V2_MIN} bits size) to enable SSH v2."
    out = con._save()
    return "\n".join(x for x in (note, out.strip()) if x)


def _label(con) -> str:
    own = _own(con)
    return f"{devcli.ios_name(con.lab, con.device)}.{own.get('domain', '')}"


def generate_cmd(con, text: str) -> str:
    words = text.lower().split()
    bits = 0
    label = ""
    i = 0
    while i < len(words):
        w = words[i]
        if "modulus".startswith(w) and len(w) >= 2 and i + 1 < len(words) and words[i + 1].isdigit():
            bits = int(words[i + 1])
            i += 2
        elif "general-keys".startswith(w) and len(w) >= 2 or "exportable".startswith(w) and len(w) >= 2:
            i += 1
        elif "label".startswith(w) and len(w) >= 2 and i + 1 < len(words):
            label = text.split()[i + 1]
            i += 2
        else:
            raise devcli.CliError("% Invalid input detected at '^' marker.")
    if bits and not MODULUS[0] <= bits <= MODULUS[1]:
        raise devcli.CliError(f"% Invalid input detected at '^' marker.\n% The modulus is {MODULUS[0]} to {MODULUS[1]} bits")
    own = _own(con)
    if not label:
        if not own.get("hostname"):
            return f"% Please define a hostname other than {devcli.ios_name(con.lab, con.device)}."
        if not own.get("domain"):
            return "% Please define a domain-name first."
    label = label or _label(con)
    from . import iosnv
    old = key_of(con.lab, con.device)
    if old:
        iosnv.ask(con, "rsa-replace", "% Do you really want to replace them? [yes/no]: ",
                  on=_replace_answer, bits=bits, label=label)
        return f"% You already have RSA keys defined named {old['label']}."
    return _size_or_make(con, bits, label)


def _replace_answer(con, line: str, q: dict) -> str:
    if not line.strip().lower().startswith("y"):
        return ""
    return _size_or_make(con, q.get("bits") or 0, q.get("label") or _label(con))


def _size_or_make(con, bits: int, label: str) -> str:
    head = f"The name for the keys will be: {label}"
    if bits:
        return head + "\n\n" + make_key(con, bits, label)
    from . import iosnv
    iosnv.ask(con, "rsa-bits", "How many bits in the modulus [512]: ", on=_bits_answer, label=label)
    return (head + f"\nChoose the size of the key modulus in the range of {MODULUS[0]} to {MODULUS[1]} for your\n"
            "  General Purpose Keys. Choosing a key modulus greater than 512 may take\n  a few minutes.\n")


def _bits_answer(con, line: str, q: dict) -> str:
    t = line.strip() or "512"
    if not t.isdigit() or not MODULUS[0] <= int(t) <= MODULUS[1]:
        return f"% Key size must be in the range of {MODULUS[0]} to {MODULUS[1]}"
    return make_key(con, int(t), q.get("label") or _label(con), asked=True)


def make_key(con, bits: int, label: str, asked: bool = False) -> str:
    was = serving(con.lab, con.device)
    t0 = time.time()
    key = generate(bits)
    key["at"] = time.time()
    kid = hashlib.sha256(str(key["n"]).encode()).hexdigest()[:12]
    _keep(con.lab.name, kid, key)
    _own(con)["rsa-key"] = f"{kid} {bits} {label}"
    note = con._save()
    out = ([] if asked else [f"% The key modulus size is {bits} bits"]) + [
        f"% Generating {bits} bit RSA keys, keys will be non-exportable...",
        f"[OK] (elapsed time was {max(1, round(time.time() - t0))} seconds)"]
    if not was:
        out += ["", f"%SSH-5-ENABLED: SSH {version(con.lab, con.device)} has been enabled"]
    if bits < SSH_V2_MIN:
        out.append(f"% A {bits}-bit key is too small for SSH version 2 (at least {SSH_V2_MIN}); "
                   f"today's clients want 2048: crypto key generate rsa modulus 2048")
    return "\n".join(out + ([note.strip()] if note.strip() else []))


def zeroize(con) -> str:
    if not key_of(con.lab, con.device):
        return "% No Signature RSA Keys found in configuration."
    from . import iosnv
    iosnv.ask(con, "rsa-zero", "Do you really want to remove these keys? [yes/no]: ", on=_zero_answer)
    return "% All keys will be removed.\n% All router certs issued using these keys will also be removed."


def _zero_answer(con, line: str, q: dict) -> str:
    if not line.strip().lower().startswith("y"):
        return ""
    ver = version(con.lab, con.device)
    _own(con).pop("rsa-key", None)
    note = con._save()
    return "\n".join(x for x in (f"%SSH-5-DISABLED: SSH {ver} has been disabled", note.strip()) if x)


def show_ip_ssh(con) -> str:
    lab, own = con.lab, _own(con)
    key = key_of(lab, con.device)
    ver = version(lab, con.device)
    retries = own.get("ssh-retries", "3")
    tmo = own.get("ssh-timeout", "120")
    if not key:
        return (f"SSH Disabled - version {ver}\n%Please create RSA keys to enable SSH (and of atleast "
                f"{SSH_V2_MIN} bits for SSH v2).\nAuthentication timeout: {tmo} secs; Authentication retries: {retries}")
    pub = base64.b64encode(public_blob(key)).decode()
    out = [f"SSH Enabled - version {ver}",
           "Authentication methods:publickey,keyboard-interactive,password",
           "Hostkey Algorithms:rsa-sha2-512,rsa-sha2-256,ssh-rsa",
           f"Authentication timeout: {tmo} secs; Authentication retries: {retries}",
           "Minimum expected Diffie Hellman key size : 2048 bits",
           f"IOS Keys in SECSH format(ssh-rsa, base64 encoded): {key['label']}",
           f"ssh-rsa {pub}",
           f"! Host key fingerprint {fingerprint(key)}: what ssh asks you to confirm the first time"]
    if ver == "1.5":
        out.append("! SSH version 1 only: the lab's server (Dropbear) and every current client speak version 2 "
                   "alone, so nothing can connect")
    elif key["bits"] < SSH_V2_MIN:
        out.append(f"! A {key['bits']}-bit key: too small for SSH version 2, so nothing can connect")
    return "\n".join(out)


def show_key(con) -> str:
    key = key_of(con.lab, con.device)
    if not key:
        return "% No Signature RSA Keys found in configuration."
    hx = spki(key).hex().upper()
    words = [hx[i:i + 8] for i in range(0, len(hx), 8)]
    rows = ["  " + " ".join(words[i:i + 8]) for i in range(0, len(words), 8)]
    when = time.strftime("%H:%M:%S UTC %b %d %Y", time.gmtime(key.get("at") or time.time()))
    return "\n".join([f"% Key pair was generated at: {when}", f"Key name: {key['label']}", "Key type: RSA KEYS",
                      " Storage Device: not specified", " Usage: General Purpose Key", " Key is not exportable.",
                      " Key Data:"] + rows)


def show_ssh(con) -> str:
    rows = [(k, v) for k, v in SESSIONS.items() if k[0] == con.lab.name and v["device"] == con.device]
    if not rows:
        return "%No SSHv2 server connections running."
    out = ["Connection Version Mode Encryption  Hmac         State                 Username"]
    for i, (_, v) in enumerate(rows):
        for mode in ("IN", "OUT"):
            out.append(f"{i:<11}{'2.0':<8}{mode:<5}{'-':<12}{'-':<13}{'Session started':<22}{v['user']}")
    out.append("%No SSHv1 server connections running.")
    return "\n".join(out)


def _users_lines(own: dict, enc: bool) -> list[str]:
    from . import iosnv
    out = []
    for name, kept in sorted((k[5:], v) for k, v in own.items() if k.startswith("user:")):
        priv, _, pw = kept.partition(" ")
        word = "secret" if pw.startswith("9 ") else "password"
        out.append(f"username {name}" + (f" privilege {priv}" if priv != "1" else "")
                   + f" {word} {iosnv.run_form(pw, enc)}")
    return out


def run_lines(con, out: list[str]) -> list[str]:
    """show running-config with this module's lines and the switch features'
    (winlab/etherchannel.py, winlab/span.py) put where IOS prints them."""
    lab, own = con.lab, con.lab.devices.get(con.device, {})
    router = con.device == devcli.ROUTER
    from . import aaa  # aaa new-model, method lists, tacacs server, login authentication
    out = aaa.run_lines(con, out)
    glob: list[str] = []
    if not router:
        glob += _users_lines(own, bool(own.get("service-pwenc")))
    if own.get("domain"):
        glob += ([] if not glob else ["!"]) + [f"ip domain-name {own['domain']}"]
    anchor = next((a for a in ("no aaa new-model", "aaa new-model") if a in out), "")
    if glob and anchor:
        i = out.index(anchor) + 1
        out[i:i] = ["!"] + glob
    tail = []
    if not router:
        from . import span
        tail += span.run_lines(lab, devcli.switch_id(con.device))
    if own.get("ssh-ver"):
        tail.append(f"ip ssh version {own['ssh-ver']}")
    if own.get("ssh-timeout"):
        tail.append(f"ip ssh time-out {own['ssh-timeout']}")
    if own.get("ssh-retries"):
        tail.append(f"ip ssh authentication-retries {own['ssh-retries']}")
    if router:
        from . import restconf  # ip http ..., restconf (IOS-XE prints restconf last)
        http, rc = restconf.run_lines(lab, con.device)
        tail = http + (["!"] if http and tail else []) + tail
        if rc and "end" in out:
            k = len(out) - 1 - out[::-1].index("end")
            out[k:k] = rc + ["!"]
    if tail:
        j = next((k for k, line in enumerate(out) if line.startswith(("banner motd", "line con 0"))), len(out))
        out[j:j] = tail + ["!"]
    if not router:
        from . import etherchannel, snooping
        out = snooping.place(lab, devcli.switch_id(con.device), out)   # ip dhcp snooping trust on Gi0/1
        g, under, pos = etherchannel.run_lines(lab, devcli.switch_id(con.device))
        if g:
            k = next((k for k, line in enumerate(out) if line.startswith("spanning-tree mode")), None)
            k = (k + 1) if k is not None else next((k for k, line in enumerate(out) if line.startswith("interface ")), 0)
            out[k:k] = g
        for port, lines in under.items():
            if f"interface {port}" in out:
                k = out.index(f"interface {port}") + 1
                while k < len(out) and out[k].startswith(" "):
                    k += 1
                out[k:k] = lines
        if pos:
            k = next((k for k, line in enumerate(out) if line.startswith("interface ")), len(out))
            out[k:k] = pos
    return out


# ------------------------------------------------------------------ the router
VTYD_SCRIPT = r"""#!/bin/sh
# winlab: the SSH sessions' line to the consoles (winlab/iosssh.py), on ttyS2.
# From the desktop: "O <session> <base64>" what the console prints, "X <session>" it logged out,
# "L <session> <base64>" a login that passed.
P=/dev/ttyS2; D=/run/winlab-vty
mkdir -p $D; echo $$ > $D/vtyd.pid
stty -F $P 115200 raw -echo 2>/dev/null
exec 3<$P
while IFS=' ' read -r op sid data <&3; do
  case "$sid" in ''|*[!0-9]*) continue;; esac
  case "$op" in
    O) [ -p $D/$sid.out ] && kill -0 $sid 2>/dev/null && printf '%s' "$data" | base64 -d > $D/$sid.out 2>/dev/null ;;
    X) ( sleep 1; kill -TERM $sid 2>/dev/null ) </dev/null >/dev/null 2>&1 & ;;
    L) echo "$(date '+%F %T') login $(printf '%s' "$data" | base64 -d 2>/dev/null)" >> /var/log/winlab-vty.log ;;
  esac
done
"""

VTY_SCRIPT = r"""#!/bin/sh
# winlab: one SSH session on a device's console (winlab/iosssh.py). Dropbear runs it for every
# login (its forced command); the console itself is winlab's, reached over ttyS2.
P=/dev/ttyS2; D=/run/winlab-vty; sid=$$; dev="$1"
[ -c $P ] || { echo "% The console line is not wired: start the lab again"; exit 1; }
mkdir -p $D; rm -f $D/$sid.out; mkfifo -m 600 $D/$sid.out || exit 1
exec 4<>$D/$sid.out
exec 5<&0
send() { ( flock 9; printf '%s %s %s\n' "$1" "$sid" "$2" > $P ) 9>>$D/.lock; }
trap 'kill $rd $wr 2>/dev/null; rm -f $D/$sid.out; exit 0' HUP TERM INT
stty raw -echo 2>/dev/null
cat <&4 &
rd=$!
peer=${SSH_CLIENT%% *}; peer=${peer:-$TCPREMOTEIP}   # an SSH login, or a connection tcpsvd took (HTTPS)
echo "$(date '+%F %T') open $dev ${USER:-?} $peer" >> /var/log/winlab-vty.log
send N "$(printf '%s %s %s' "$dev" "${USER:-?}" "$peer" | base64 | tr -d '\n')"
( while :; do
    d=$(dd bs=512 count=1 2>/dev/null | base64 | tr -d '\n')
    [ -n "$d" ] || break
    send I "$d"
  done
  send C -
  kill -TERM $$ ) <&5 &
wr=$!
wait
"""


SSHD_SCRIPT = r"""#!/bin/sh
# winlab: one device's Dropbear (winlab/iosssh.py), in a mount namespace of its own where
# /etc/shadow is that device's user list. winlab-sshd <its shadow file> <dropbear's arguments>
s="$1"; shift
exec unshare -m --propagation private /bin/sh -c 'mount --bind "$0" /etc/shadow || exit 1; exec dropbear "$@"' "$s" "$@"
"""


def ssh_checks(lab, device: str) -> bool:
    """True when the SSH server itself checks the password a client sends
    (and the session opens at the prompt): login local with AAA off, or under
    aaa new-model a vty method list that starts with local (local never errs,
    so nothing after it is ever asked). Otherwise the password is asked inside
    the session: a line password, or an AAA list that starts with a server
    group (RADIUS, TACACS+), which Dropbear has no way to ask."""
    from . import aaa
    methods = aaa.login_methods(lab, device, "vty")
    if methods is None:
        return lab.devices.get(device, {}).get("line-vty:login") == "local"
    return bool(methods) and methods[0] in ("local", "local-case")


def shadow_line(lab, device: str, users: list[str], path: str) -> str:
    """Shell writing the device's /etc/shadow (from the router's own, every
    IOS user locked but this device's). When the SSH server checks passwords
    (ssh_checks), its local users' crypts (winlab/iosssh.remember); when the
    session asks instead (a line password, or AAA through a server group),
    empty ones for its local users and the names a server accepted
    (aaa-names), Dropbear's -B letting them in for the console to ask."""
    own = lab.devices.get(device, {})
    checks = ssh_checks(lab, device)
    names = set(own.get("aaa-names", "").split()) if own.get("aaa") and not checks else set()
    mine = []
    for u in users:
        if f"user:{u}" not in own and u not in names:
            continue
        h = login_hash(lab, device, u) if checks else ""
        if checks and not h:
            continue
        mine.append(f'h["{u}"]="{h}"')
    begin = "; ".join(mine)
    return (f"awk -F: -v OFS=: -v ios=' {' '.join(users)} ' 'BEGIN{{{begin}}} "
            f"index(ios, \" \" $1 \" \") {{ $2 = ($1 in h) ? h[$1] : \"!\" }} {{ print }}' /etc/shadow > {path}; "
            f"chmod 600 {path}")


def _file(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name)


def _exec_timeout(own: dict) -> int:
    v = own.get("line-vty:exec-timeout", "10 0").split()
    try:
        secs = int(v[0]) * 60 + (int(v[1]) if len(v) > 1 else 0)
    except (ValueError, IndexError):
        secs = 600
    return secs


def servers(plan) -> list[tuple[str, str, list[str]]]:
    """(device, network namespace or "", addresses) per SSH server to run."""
    from . import iosl2
    lab = plan.lab
    out = []
    if serving(lab, devcli.ROUTER):
        addrs = sorted({seg.network.router_ip for seg in plan.segments.values()
                        if seg.network.routed and not seg.network.wan and seg.network.router_ip})
        if addrs:
            out.append((devcli.ROUTER, "", addrs))
    from . import routers  # the other routers: their SSH server inside their own network stack
    for rid in routers.extra(lab):
        dev = routers.key(rid)
        if not serving(lab, dev) or not routers.powered(lab, rid):
            continue
        p = routers.plan_view(plan, rid)
        addrs = sorted({seg.network.router_ip for seg in p.segments.values() if seg.network.routed})
        if addrs:
            out.append((dev, routers.netns(rid), addrs))
    for sw in devcli.switches(lab):
        dev = f"sw:{sw}"
        if not serving(lab, dev):
            continue
        ns = iosl2.netns(lab, sw)
        addrs = [a.split("/")[0] for _, a in iosl2.svis(lab, sw)]
        if ns and addrs:
            out.append((dev, ns, addrs))
    return out


def render(plan, reset: bool = False) -> list[str]:
    """Shell for the router: the session line's two programs, the accounts
    Dropbear lets in, and one Dropbear per device with a key."""
    from . import restconf  # HTTPS (RESTCONF) on the router: its connections ride the same line
    lab = plan.lab
    run = servers(plan)
    https = restconf.render(plan, VTY)
    if not run and not https and not reset:
        return []
    out = ["# SSH to the consoles (winlab/iosssh.py): Dropbear on the lab addresses only, no forwarding;",
           "# each login is the device's own console, over ttyS2 to winlab",
           f"mkdir -p {KEYDIR} {RUN} /run/winlab-vty; chmod 700 {KEYDIR}",
           f"for f in {RUN}/*.pid; do [ -e $f ] && kill $(cat $f) 2>/dev/null; rm -f $f; done; rm -f {RUN}/*.line; true"]
    if not run and not https:
        return out
    out += [f"cat > {VTYD} <<'WINLAB_EOF'", VTYD_SCRIPT.rstrip("\n"), "WINLAB_EOF",
            f"cat > {VTY} <<'WINLAB_EOF'", VTY_SCRIPT.rstrip("\n"), "WINLAB_EOF",
            f"cat > {SSHD} <<'WINLAB_EOF'", SSHD_SCRIPT.rstrip("\n"), "WINLAB_EOF",
            f"chmod 755 {VTYD} {VTY} {SSHD}",
            # the sessions run as the IOS users: they may write the line, their fifo and the log
            f"chgrp dialout {LINE} 2>/dev/null; chmod 660 {LINE} 2>/dev/null; chmod 1777 /run/winlab-vty; "
            f"touch /run/winlab-vty/.lock {LOG}; chmod 666 /run/winlab-vty/.lock; chmod 622 {LOG}",
            f"[ -f /run/winlab-vty/vtyd.pid ] && kill -0 $(cat /run/winlab-vty/vtyd.pid) 2>/dev/null || "
            f"setsid {VTYD} </dev/null >/dev/null 2>&1 &"]
    users = sorted(u for u in ({k[5:] for dev, _, _ in run for k in lab.devices.get(dev, {}) if k.startswith("user:")}
                               | {n for dev, _, _ in run for n in lab.devices.get(dev, {}).get("aaa-names", "").split()})
                   if USER_RE.match(u) and u != "root")
    for u in users:
        out.append(f"id -u {u} >/dev/null 2>&1 || adduser -D -H -h /var/empty -s /bin/sh -g 'IOS user' {u} "
                   f"2>/dev/null; addgroup {u} dialout 2>/dev/null; passwd -l {u} >/dev/null 2>&1; true")
    for dev, ns, addrs in run:
        key = key_of(lab, dev)
        own = lab.devices.get(dev, {})
        f = f"{KEYDIR}/{_file(dev)}.rsa"
        b64 = base64.b64encode(dropbear_key(key)).decode()
        listen = " ".join(f"-p {a}:22" for a in addrs)
        idle = _exec_timeout(own)
        prefix = f"ip netns exec {ns} " if ns else ""
        line = (f"login={'local' if own.get('line-vty:login') == 'local' else 'line'} "
                f"transport={re.sub(r'[^a-z0-9,-]', '', (own.get('line-vty:transport') or 'all').lower().replace(' ', ','))} "
                f"version={version(lab, dev)} bits={key['bits']}")
        shadow = f"{KEYDIR}/{_file(dev)}.shadow"
        out += [f"# {devcli.hostname(lab, dev)}: key {key['label']} ({key['bits']} bits, {fingerprint(key)})",
                f"echo '{line}' > {RUN}/{_file(dev)}.line   # the vty lines as SSH logins meet them",
                f"printf '%s' '{b64}' | base64 -d > {f}; chmod 600 {f}",
                shadow_line(lab, dev, users, shadow),
                f"{prefix}{SSHD} {shadow} -r {f} {listen} -B -w -j -k "
                + (f"-I {idle} " if idle else "")
                + f"-c '{VTY} {dev}' -P {RUN}/{_file(dev)}.pid </dev/null >/dev/null 2>&1 || true"]
    return out + https


# ------------------------------------------------------------------ a session
class VtyConsole(devcli.Console):
    """A device's command line reached over SSH (line vty): the vty line's
    login, no console banner, and the session ends on exit."""

    def __init__(self, dash, device: str, user: str, peer: str, **kw):
        super().__init__(dash, device, **kw)
        self.user, self.peer = user, peer
        self.logged = False

    def banner_text(self) -> str:
        motd = self.lab.devices.get(self.device, {}).get("banner", "")
        return f"{motd}\n\n" if motd else ""

    def banner(self) -> str:
        return ""   # the session is over: Dropbear closes the connection

    def allowed(self) -> bool:
        words = self.lab.devices.get(self.device, {}).get("line-vty:transport", "").lower().split()
        return not words or "ssh" in words or "all" in words

    def open(self) -> str | None:
        """What the line prints as the session opens (None: the line refuses ssh)."""
        if not self.allowed():
            return None
        from . import iosnv
        self._fresh()
        self.s.mode, self.s.authed = "user", False
        own = self.lab.devices.get(self.device, {})
        how = own.get("line-vty:login") or "yes"
        tries = int(own.get("ssh-retries") or 3) or 1
        head = self.banner_text()
        from . import aaa  # aaa new-model: the vty lines' method list (winlab/aaa.py)
        if ssh_checks(self.lab, self.device):
            # The SSH client asked for the password and Dropbear checked it
            # against this device's users (shadow_line): straight to the prompt.
            if not login_hash(self.lab, self.device, self.user):
                return None
            if aaa.login_methods(self.lab, self.device, "vty") is None:
                priv = own.get(f"user:{self.user}", "").partition(" ")[0]
                level = 15 if priv == "15" else 1
            else:   # AAA, method local: the exec authorization still decides the level
                ok, level, _why = aaa.authorize(self, self.user, "local", 0, "vty0", self.peer)
                if not ok:
                    self.s.mode = "idle"
                    return head + "% Authorization failed.\n"
                self.method = "local"
            self.s.authed, self.logged = True, True
            self.s.mode = "enable" if level >= 15 else "user"
            aaa.exec_start(self)   # aaa accounting exec: the session's start record
            return head
        said = aaa.begin(self, "vty")
        if said is not None:
            return head + said
        if how == "local":
            return None   # login local without the SSH server's check: cannot happen (ssh_checks)
        elif own.get("line-vty:password"):
            iosnv.ask(self, "vty-line", "Password: ", secret=True, tries=tries, on=_vty_answer)
        else:
            self.s.mode = "idle"
            return head + "Password required, but none set\n"
        return head

    def _exit(self, a):
        from . import aaa
        aaa.exec_stop(self)   # aaa accounting exec: the session's stop record
        self.s.mode, self.s.ctx, self.s.authed = "idle", "", False
        return ""

    def _enable(self, a):
        own = self.lab.devices.get(self.device, {})
        if not (own.get("enable-secret") or own.get("enable-password")):
            return "% No password set"
        return super()._enable(a)


def _vty_answer(con, line: str, q: dict) -> str:
    from . import iosnv
    own = con.lab.devices.get(con.device, {})
    if q["kind"] == "vty-local":
        kept = own.get(f"user:{q['user']}", "")
        priv, _, pw = kept.partition(" ")
        ok = bool(pw) and iosnv.matches(line, pw)
    else:
        priv, ok = "1", iosnv.matches(line, own.get("line-vty:password", ""))
    if ok:
        con.s.authed, con.logged = True, True
        con.s.mode = "enable" if priv == "15" else "user"
        return ""
    left = q["tries"] - 1
    if left <= 0:
        con.s.mode = "idle"
        return "% Authentication failed"
    iosnv.ask(con, q["kind"], "Password: ", secret=True, tries=left, on=_vty_answer, user=q.get("user", ""))
    return "% Login invalid" if q["kind"] == "vty-local" else ""


def _terminal(con):
    from .consolecable import Terminal

    class VtyTerminal(Terminal):
        def wake(self) -> bytes:
            return b""
    t = VtyTerminal(con)
    t.started = t.powered = True
    return t


class Bridge:
    """The desktop's end of the router's ttyS2: one console per SSH session."""

    def __init__(self, dash_fn, console_factory=None):
        self.dash_fn = dash_fn
        self.factory = console_factory or (lambda dash, device, user, peer: VtyConsole(dash, device, user, peer))
        self.sock = None
        self.port = 0
        self.lab = ""
        self.buf = b""
        self.sessions: dict[str, tuple] = {}   # sid -> (console, terminal)

    def wanted(self) -> tuple[str, int]:
        lab = self.dash_fn().lab
        st = state.load(lab.name)
        fab = st.nodes.get("fabric") if st else None
        if fab and fab.com_port and fab.pid and state.pid_alive(fab.pid):
            return lab.name, int(fab.com_port)
        return lab.name, 0

    def _close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        for sid in list(self.sessions):
            self._drop(sid)
        self.buf = b""

    def _drop(self, sid: str) -> None:
        self.sessions.pop(sid, None)
        SESSIONS.pop((self.lab, sid), None)

    def send(self, line: str) -> None:
        if self.sock is None:
            return
        try:
            self.sock.sendall(line.encode("ascii") + b"\n")
        except OSError:
            self._close()

    def output(self, sid: str, data: bytes) -> None:
        for i in range(0, len(data), CHUNK):
            self.send(f"O {sid} {base64.b64encode(data[i:i + CHUNK]).decode()}")

    def handle(self, raw: bytes) -> None:
        parts = raw.decode("latin-1").strip().split(" ")
        if len(parts) < 2 or not parts[1].isdigit():
            return
        op, sid, data = parts[0], parts[1], parts[2] if len(parts) > 2 else ""
        try:
            blob = base64.b64decode(data, validate=False) if op in ("N", "I") else b""
        except ValueError:
            return
        if op == "N":
            self.open(sid, blob.decode("latin-1"))
        elif op == "I" and sid in self.sessions:
            con, term = self.sessions[sid]
            try:
                out = term.feed(blob)
            except Exception as exc:  # a device error is a console line, never a dead bridge
                out = f"% {exc}\r\n".encode()
            self.output(sid, out)
            self._after(sid, con)
        elif op == "C":
            self._drop(sid)

    def open(self, sid: str, head: str) -> None:
        words = head.split(" ")
        dev, user, peer = (words + ["", "", ""])[:3]
        dash = self.dash_fn()
        if dev.startswith("https:"):
            self._https(sid, dash, dev[6:], peer)
            return
        from . import routers
        known = (dev == devcli.ROUTER or devcli.switch_id(dev) in devcli.switches(dash.lab)
                 or (routers.rid_of(dev) and routers.key(routers.rid_of(dev)) in dash.lab.devices))
        if not known:
            self.send(f"X {sid}")
            return
        con = self.factory(dash, dev, user, peer)
        if not con.powered():
            self.send(f"X {sid}")
            return
        text = con.open()
        if text is None:
            self.send(f"X {sid}")
            return
        term = _terminal(con)
        self.sessions[sid] = (con, term)
        SESSIONS[(self.lab, sid)] = {"device": dev, "user": user, "peer": peer, "since": time.time()}
        self.output(sid, ("\r\n" + text.replace("\n", "\r\n") + con.prompt()).encode("latin-1", "replace"))
        self._after(sid, con)

    def _https(self, sid: str, dash, dev: str, peer: str) -> None:
        """A connection to the router's port 443: RESTCONF (winlab/restconf.py)."""
        from . import restconf
        if dev != devcli.ROUTER or not restconf.serving(dash.lab):
            self.send(f"X {sid}")
            return
        sess = self.https_factory(dash, dev, peer)
        self.sessions[sid] = (sess, sess)

    def https_factory(self, dash, dev: str, peer: str):
        from . import restconf
        return restconf.Session(dash, dev, peer)

    def _after(self, sid: str, con) -> None:
        if getattr(con, "logged", False):
            con.logged = False
            via = f" {con.method}" if getattr(con, "method", "") else ""   # radius, tacacs+, local (winlab/aaa.py)
            self.send(f"L {sid} " + base64.b64encode(f"{con.device} {con.user} {con.peer}{via}".encode()).decode())
        if con.s.mode == "idle" and not con.s.ask:
            self.send(f"X {sid}")
            self._drop(sid)

    def step(self, wait: float = 0.5) -> None:
        name, port = self.wanted()
        if (name, port) != (self.lab, self.port):
            self._close()
            self.lab, self.port = name, port
        if not port:
            time.sleep(wait)
            return
        if self.sock is None:
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                self.sock.setblocking(False)
            except OSError:
                self.sock = None
                time.sleep(wait)
                return
        ready, _, _ = select.select([self.sock], [], [], wait)
        if not ready:
            return
        try:
            data = self.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            self._close()
            return
        self.buf += data
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            self.handle(line)

    def run_forever(self) -> None:
        while True:
            try:
                self.step(1.0)
            except Exception:
                time.sleep(2)


def watch_desktop(dash_fn) -> None:
    """The desktop's bridge to the router's session line, on its own thread."""
    if "desktop" in _WATCH:
        return
    b = Bridge(dash_fn)
    _WATCH["desktop"] = b
    threading.Thread(target=b.run_forever, daemon=True, name="winlab-ssh-vty").start()
