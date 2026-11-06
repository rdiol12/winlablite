"""What a router or a switch keeps across a restart, and who may type into
it: the startup configuration in NVRAM, the enable secret, the console
line's password and the local user names.

The running configuration is the lab file ([devices."router"] and
[devices."sw:<id>"], and the networks the router has addresses in or the
switch's ports are in); it is what the running network follows. ``write
memory`` (``copy running-config startup-config``) keeps a copy of it here,
in ``nvram.json`` beside the lab's machines, and a device that starts
(the router powering on with the lab's network, or ``reload``) comes up
with that copy: what was typed and never written is gone, as on a real
device. ``erase startup-config`` leaves it to come up empty. A lab made
before this kept its devices' configuration as if it had been written, the
first time its network starts.

The VLANs a switch has are in its vlan.dat on a real switch, not in the
startup configuration, so they stay; which VLAN each port is in does not.

Passwords are kept the way IOS keeps them: an enable secret and a user's
secret as type 9 hashes (scrypt, hashlib.scrypt), a line or enable password
as type 7 (the reversible scramble ``service password-encryption`` shows),
never in clear in the lab file.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

from . import paths

STORE = "nvram.json"
NVRAM_BYTES = 33554432
# Settings that are the device's hardware or its state, not its
# configuration: where its cables are, what is err-disabled now.
PHYSICAL = ("rport:", "cable:", "rports", "console", "xcable:", "port:", "psec-err:", "psec-stuck:",
            "stp-err:", "errdis-cause:", "psec-viol:", "power", "ec-err:")
_SCRAMBLE = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_CISCO = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


# ------------------------------------------------------------------ secrets
def type7(clear: str, seed: int | None = None) -> str:
    """The reversible type 7 form of a password."""
    seed = secrets.randbelow(16) if seed is None else seed
    return f"{seed:02d}" + "".join(f"{ord(c) ^ ord(_SCRAMBLE[(seed + i) % len(_SCRAMBLE)]):02X}"
                                   for i, c in enumerate(clear))


def untype7(text: str) -> str:
    try:
        seed = int(text[:2])
        raw = bytes.fromhex(text[2:])
    except ValueError:
        raise ValueError("not a type 7 password") from None
    return "".join(chr(b ^ ord(_SCRAMBLE[(seed + i) % len(_SCRAMBLE)])) for i, b in enumerate(raw))


def type9(clear: str, salt: str = "") -> str:
    """'$9$<salt>$<hash>': scrypt (N 16384, r 1, p 1) as IOS's type 9."""
    salt = salt or "".join(secrets.choice(_CISCO) for _ in range(14))
    dk = hashlib.scrypt(clear.encode(), salt=salt.encode(), n=16384, r=1, p=1, dklen=32)
    enc = base64.b64encode(dk).decode().rstrip("=").translate(str.maketrans(_STD, _CISCO))
    return f"$9${salt}${enc}"


def check9(clear: str, hashed: str) -> bool:
    parts = hashed.split("$")
    return len(parts) == 4 and parts[1] == "9" and secrets.compare_digest(type9(clear, parts[2]), hashed)


def matches(clear: str, kept: str) -> bool:
    """Whether a typed password is the one kept ('9 $9$...' or '7 0822...')."""
    kind, _, value = kept.partition(" ")
    if kind == "9":
        return check9(clear, value)
    if kind == "7":
        try:
            return secrets.compare_digest(untype7(value), clear)
        except ValueError:
            return False
    return False


def keep(typed: list[str], secret: bool) -> str:
    """What `enable secret ...` / `password ...` typed becomes: '9 <hash>'
    for a secret, '7 <scrambled>' for a password ('0 x' and 'x' are clear
    text; '7 ...' and '9 $9$...' are taken as already done)."""
    if not typed:
        raise ValueError("% Incomplete command.")
    if typed[0] in ("0", "5", "7", "8", "9") and len(typed) >= 2:
        kind, value = typed[0], " ".join(typed[1:])
        if kind == "0":
            return keep([value], secret)
        if kind == "9" and secret and value.startswith("$9$") and len(value.split("$")) == 4:
            return f"9 {value}"
        if kind == "7" and not secret:
            try:
                untype7(value)
            except ValueError:
                raise ValueError("% Invalid encrypted password") from None
            return f"7 {value}"
        raise ValueError("% Invalid encrypted password")
    value = " ".join(typed)
    if len(value) > 25 and not secret:
        raise ValueError("% Password too long - must be at most 25 characters")
    return f"9 {type9(value)}" if secret else f"7 {type7(value)}"


def run_form(kept: str, encrypt: bool) -> str:
    """How show running-config prints a kept password."""
    kind, _, value = kept.partition(" ")
    if kind == "9":
        return f"9 {value}"
    if kind == "7" and not encrypt:
        try:
            return untype7(value)
        except ValueError:
            return f"7 {value}"
    return f"7 {value}"


# ------------------------------------------------------------------ login
def console_login(lab, device: str) -> str:
    """'' (no login), 'line' (the line's password) or 'local' (a user name
    and its password)."""
    own = lab.devices.get(device, {})
    how = own.get("line-con:login", "")
    if how == "local":
        return "local"
    if how == "yes" and own.get("line-con:password"):
        return "line"
    return ""


def ask(con, kind: str, prompt: str, secret: bool = False, tries: int = 3, **data) -> None:
    con.s.ask = {"kind": kind, "prompt": prompt, "secret": secret, "tries": tries, **data}


def begin(con) -> str:
    """A session starting on the console: the login the line asks for."""
    how = console_login(con.lab, con.device)
    if how and not con.s.authed:
        if how == "local":
            ask(con, "user", "Username: ")
        else:
            ask(con, "login", "Password: ", secret=True)
        return "\nUser Access Verification\n"
    con.s.authed = True
    return ""


def enable(con) -> str:
    own = con.lab.devices.get(con.device, {})
    if own.get("enable-secret") or own.get("enable-password"):
        ask(con, "enable", "Password: ", secret=True)
        return ""
    con.s.mode = "enable"
    return ""


def answer(con, line: str) -> str:
    """The line typed to a question the device asked."""
    q = con.s.ask
    con.s.ask = None
    own = con.lab.devices.get(con.device, {})
    kind = q["kind"]
    text = line.strip()
    if kind in ("login", "password-local"):
        if kind == "login":
            ok = matches(line, own.get("line-con:password", ""))
        else:
            kept = own.get(f"user:{q['user']}", "")
            ok = bool(kept) and matches(line, kept.split(" ", 1)[1] if " " in kept else "")
        if ok:
            con.s.authed = True
            con.s.mode = "user"
            return ""
        left = q["tries"] - 1
        if left <= 0:
            con.s.mode, con.s.authed = "idle", False
            return "% Bad passwords\n\nPress RETURN to get started." if kind == "login" else \
                "% Authentication failed\n\nPress RETURN to get started."
        if kind == "login":
            ask(con, "login", "Password: ", secret=True, tries=left)
            return ""
        ask(con, "user", "Username: ", tries=left)
        return "% Login invalid\n"
    if kind == "user":
        ask(con, "password-local", "Password: ", secret=True, tries=q["tries"], user=text)
        return ""
    if kind == "enable":
        ok = (own.get("enable-secret") and matches(line, own["enable-secret"])) or \
             (not own.get("enable-secret") and own.get("enable-password")
              and matches(line, own["enable-password"]))
        if ok:
            con.s.mode = "enable"
            return ""
        left = q["tries"] - 1
        if left <= 0:
            return "% Bad secrets\n"
        ask(con, "enable", "Password: ", secret=True, tries=left)
        return ""
    if kind == "copy-dest":
        if text and text != "startup-config":
            return "%Error opening flash:" + text + " (Permission denied)"
        return write(con)
    if kind == "erase":
        if text.lower() not in ("", "y", "yes", "confirm"):
            return ""
        erase(con.lab, con.device)
        return "[OK]\nErase of nvram: complete"
    if kind == "reload-save":
        w = text.lower()
        if w not in ("y", "yes", "n", "no"):
            ask(con, "reload-save", q["prompt"])
            return "% Please answer 'yes' or 'no'."
        out = write(con) + "\n" if w.startswith("y") else ""
        ask(con, "reload", "Proceed with reload? [confirm]")
        return out.rstrip("\n")
    if kind == "reload":
        if text.lower() not in ("", "y", "yes", "confirm"):
            return ""
        return reload(con)
    if q.get("on"):
        return q["on"](con, line, q)   # a question another module asked (winlab/iosssh.py: key size, a login)
    return ""


# ------------------------------------------------------------------ NVRAM
def _path(lab_name: str):
    return paths.lab_dir(lab_name) / STORE


def load(lab_name: str) -> dict | None:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _save_store(lab_name: str, data: dict) -> None:
    p = _path(lab_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def physical(key: str) -> bool:
    return key.startswith(PHYSICAL)


def snapshot(lab, device: str, plan=None) -> dict:
    """A device's configuration, as `write memory` keeps it."""
    own = {k: v for k, v in lab.devices.get(device, {}).items() if not physical(k)}
    snap: dict = {"own": own}
    if device == "router":
        ids = {v for k, v in own.items() if k.startswith("ip:")}
        snap["nets"] = {nid: {"cidr": n.cidr, "gateway": n.gateway or ""}
                        for nid, n in lab.networks.items() if nid in ids}
    else:
        from . import devcli
        sw = devcli.switch_id(device)
        access, trunks = {}, {}
        for node in lab.node_list():
            for i, nic in enumerate(node.nics):
                net = lab.networks.get(nic.network) if nic.plugged else None
                if net is not None and net.home == sw:
                    access[f"{node.id}:nic{i}"] = net.vlan_no
                    trunks[f"{node.id}:nic{i}"] = sorted(lab.networks[t].vlan_no for t in nic.trunk
                                                         if t in lab.networks)
        snap["access"], snap["trunk"] = access, trunks
    return snap


def has_config(lab, device: str) -> bool:
    snap = snapshot(lab, device)
    if snap["own"]:
        return True
    if device == "router":
        return any(n.routed for n in lab.networks.values() if not (n.wan or n.site or n.gateway_node))
    return any(v != 1 for v in snap["access"].values()) or any(snap["trunk"].values())


def write(con) -> str:
    """write memory: the running configuration becomes the startup one."""
    lab = con.lab
    data = load(lab.name) or {}
    snap = snapshot(lab, con.device)
    text = con._show_run([]).split("\n")
    body = "\n".join(text[2:]) if len(text) > 2 else "\n".join(text)
    body = body.replace("Current configuration", "", 1).lstrip(" :0123456789bytes\n")
    snap["text"] = body
    data.setdefault("devices", {})[con.device] = snap
    _save_store(lab.name, data)
    return "Building configuration...\n[OK]"


def erase(lab, device: str) -> None:
    data = load(lab.name) or {}
    data.setdefault("devices", {})[device] = {"erased": True}
    _save_store(lab.name, data)


def startup_text(lab, device: str) -> str:
    data = load(lab.name) or {}
    snap = (data.get("devices") or {}).get(device)
    if not snap or snap.get("erased") or "text" not in snap:
        return "startup-config is not present"
    body = snap["text"]
    return f"Using {len(body)} out of {NVRAM_BYTES} bytes\n{body}"


def unsaved(con) -> bool:
    """Whether the running configuration differs from the startup one."""
    data = load(con.lab.name) or {}
    snap = (data.get("devices") or {}).get(con.device)
    now = snapshot(con.lab, con.device)
    if not snap or snap.get("erased"):
        return has_config(con.lab, con.device)
    return {k: snap.get(k) for k in now} != now


def revert(lab, device: str, snap: dict | None) -> bool:
    """The device's configuration back to `snap` (None: as it leaves the
    factory). Returns whether anything changed."""
    from . import devcli, editor
    own = lab.devices.setdefault(device, {})
    before = json.dumps([own, {n: (v.cidr, v.gateway, v.routed, v.dhcp) for n, v in lab.networks.items()},
                         {n.id: [(c.network, list(c.trunk)) for c in n.nics] for n in lab.node_list()}],
                        sort_keys=True, default=str)
    keep_ = {k: v for k, v in own.items() if physical(k)}
    own.clear()
    own.update(keep_)
    own.update((snap or {}).get("own", {}))
    if device == "router":
        for nid, v in ((snap or {}).get("nets") or {}).items():
            net = lab.networks.get(nid)
            if net is not None and not any(c.ip for m in lab.nodes_on(nid) for c in m.nics
                                           if c.network == nid and v["cidr"] != net.cidr):
                net.cidr, net.gateway = v["cidr"], v["gateway"] or None
        devcli.refresh_routed(lab)
    else:
        sw = devcli.switch_id(device)
        access = (snap or {}).get("access") or {}
        trunks = (snap or {}).get("trunk") or {}
        for node in lab.node_list():
            for i, nic in enumerate(node.nics):
                net = lab.networks.get(nic.network) if nic.plugged else None
                if net is None or net.home != sw:
                    continue
                label = f"{node.id}:nic{i}"
                if snap is not None and label not in access:
                    continue
                want = devcli.vlan_net(lab, sw, int(access.get(label, 1))) or lab.networks[sw]
                if nic.network != want.id:
                    editor.cable(lab, node.id, i, want.id)
                tags = [devcli.vlan_net(lab, sw, t) for t in trunks.get(label, [])]
                nic.trunk = [t.id for t in tags if t is not None and t.id != want.id]
    after = json.dumps([own, {n: (v.cidr, v.gateway, v.routed, v.dhcp) for n, v in lab.networks.items()},
                        {n.id: [(c.network, list(c.trunk)) for c in n.nics] for n in lab.node_list()}],
                       sort_keys=True, default=str)
    return before != after


def _devices(lab) -> list[str]:
    from . import devcli
    return [devcli.ROUTER] + [f"sw:{s}" for s in devcli.switches(lab)]


def power_on(lab) -> bool:
    """The lab's network starting: every device comes up with its startup
    configuration. The first time (a lab from before startup
    configurations), what each device has is kept as written. Returns
    whether the lab file changed."""
    data = load(lab.name)
    if data is None:
        data = {"devices": {d: {**snapshot(lab, d), "text": ""} for d in _devices(lab) if has_config(lab, d)}}
        for snap in data["devices"].values():
            snap.pop("text")
        _save_store(lab.name, data)
        return False
    changed = False
    for dev in _devices(lab):
        snap = (data.get("devices") or {}).get(dev)
        if snap is None and not lab.workbench:
            continue  # a lesson lab's device as its lab file sets it up
        changed = revert(lab, dev, None if snap is None or snap.get("erased") else snap) or changed
    return changed


def reload(con) -> str:
    """reload: the device starts again with its startup configuration."""
    lab = con.lab
    data = load(lab.name) or {}
    snap = (data.get("devices") or {}).get(con.device)
    changed = False
    if snap is not None or lab.workbench:
        changed = revert(lab, con.device, None if snap is None or snap.get("erased") else snap)
    note = con._save() if changed else ""
    from .devcli import Session
    con.s = Session(con.device, boot=con.s.boot)
    con.s.mode = "idle"
    return ("\n%SYS-5-RELOAD: Reload requested by console. Reload Reason: Reload Command."
            + (f"\n{note.strip()}" if note.strip() else "")
            + f"\n\n{con.banner_text()}Press RETURN to get started.")
