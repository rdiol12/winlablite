"""Activities: a network to build, graded as the student builds it.

An instructor builds the finished network on the workbench and makes an
activity of it: instructions, the network the student starts from (an
empty canvas, some of the devices, or a saved version), what is graded and
for how many points, an optional time limit, and whether the student sees
which items are still wrong or only the score. The student opens the file,
builds, and the Activity window scores the network as it changes: devices
of the right kind, cables into the right switch and VLAN, the switches'
VLANs, trunks and DHCP, addresses, Wi-Fi, WAN lines, roles, and checks run
inside the machines over the serial agent ("dc01 is a domain controller").

The file (``.wlact``) is a network file (winlab/netfile.py) with three more
parts: ``activity.json`` (the instructions and rules), ``target.json`` (the
graded items) and ``seal``. The target holds no settings in clear: each item
is a label ("sw1: VLANs") and a salted hash of the right answer, so neither
the window nor the file shows the solution; the student's network is hashed
the same way and compared. The seal is a keyed hash over every part, so a
file whose points, rules or target were edited is refused, and like a
network file it carries no lab password. Opened in winlab's Open a network
file, it is just its starting network.

What the student's copy remembers (when it started, the in-guest results,
the score when the time ran out) is in ``var/activities/<lab>.json``.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import io
import json
import re
import secrets
import threading
import time
import zipfile
from pathlib import Path

from . import devcli, netfile, paths, state, wan, wifi

EXT = ".wlact"
FORMAT = 1
ACTIVITY = "activity.json"
TARGET = "target.json"
SEAL = "seal"
PARTS = {netfile.MANIFEST, netfile.NETWORK, ACTIVITY, TARGET, SEAL}
PART_MAX = 1024 * 1024
MAX_GUEST = 40
_SEAL = b"winlab activity file, format 1"

# What can be graded, in the order the check list shows it.
CATEGORIES = {
    "devices": "Devices of the right kind",
    "cables": "Cables to the right switch and VLAN",
    "switches": "Switch VLANs, uplinks and trunks",
    "dhcp": "Who hands out addresses",
    "ip": "Subnets and IP settings",
    "wifi": "Wi-Fi networks",
    "wan": "WAN lines",
    "roles": "Machine roles",
}
DEFAULT_POINTS = {"devices": 1, "cables": 1, "switches": 1, "dhcp": 1, "ip": 1, "wifi": 1, "wan": 1, "roles": 0}
FEEDBACK = ("items", "score")
STARTS = ("empty", "partial", "version")

# In-guest checks an instructor picks besides those of the exercises and
# the troubleshooting scenarios: (label, PowerShell, expected stdout).
TEMPLATES = {
    "dc": ("{node} is a domain controller", "(Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4", "True"),
    "joined": ("{node} joined to {arg}", "(Get-CimInstance Win32_ComputerSystem).Domain", "{arg}"),
    "feature": ("{node} has {arg} installed", "[bool](Get-WindowsFeature -Name '{arg}').Installed", "True"),
    "service": ("{node}: the {arg} service runs", "(Get-Service -Name '{arg}').Status", "Running"),
    "ping": ("{node} reaches {arg}", "Test-Connection -ComputerName '{arg}' -Count 1 -Quiet", "True"),
    "resolve": ("{node} resolves {arg}", "[bool](Resolve-DnsName -Name '{arg}' -ErrorAction SilentlyContinue)", "True"),
}
_SH = {"ping": "ping -c 1 -W 2 '{arg}' >/dev/null 2>&1 && echo True || echo False",
       "resolve": "nslookup '{arg}' >/dev/null 2>&1 && echo True || echo False"}
TEMPLATE_ARG = {"joined": "domain", "feature": "feature name", "service": "service name",
                "ping": "name or address", "resolve": "name"}
ARG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


class ActivityError(Exception):
    pass


# ------------------------------------------------------------------ facts
def _name(node) -> str:
    from . import naming
    return naming.hostname_of(node).lower()


def facts(lab) -> dict[str, tuple[str, str, object]]:
    """What the network is, item by item: {id: (category, label, value)}.
    Machines are known by their computer name and switches by their id, so
    a student's network that names them as the instructions say lines up
    with the instructor's however it was built."""
    from . import appliance, netplan, workbench
    out: dict[str, tuple[str, str, object]] = {}
    plan = netplan.compile_topology(lab, check_ports=False)

    def where(net_id: str):
        net = lab.networks.get(net_id)
        return [net.home, net.vlan_no] if net else None

    for node in lab.node_list():
        if node.vars.get("devvm"):
            continue  # an AP's or the UPS card's VM: graded as that device below
        nm = _name(node)
        out[f"dev:{nm}"] = ("devices", f"{nm}: on the network, the right kind of device", workbench._shelf_of(node))
        cards = wifi.wireless(node)
        for i, nic in enumerate(node.nics):
            if i in cards or not nic.plugged:
                continue
            out[f"cable:{nm}:{i}"] = ("cables", f"{nm} port {i + 1}: cable",
                                      (where(nic.network) or [nic.network, 0]) + [sorted(lab.networks[t].vlan_no for t in nic.trunk
                                                                   if t in lab.networks)])
            out[f"ip:{nm}:{i}"] = ("ip", f"{nm} port {i + 1}: IP settings",
                                   [nic.ip or "dhcp", sorted(nic.dns)])
        if cards:
            ap = wifi.aps(lab).get(wifi.joined(lab, node))
            out[f"wifi:{nm}"] = ("wifi", f"{nm}: Wi-Fi network it is on", ap["ssid"] if ap else "")
        own = appliance.DEVICES.get(appliance.device_of(node) or "", {}).get("role")
        roles = sorted(r for r in node.roles if r != own)
        if roles:
            out[f"roles:{nm}"] = ("roles", f"{nm}: roles", roles)
    lines = wan.links(lab)
    for sw in devcli.switches(lab):
        vlans = devcli.vlans_of(lab, sw)
        out[f"sw:{sw}:vlans"] = ("switches", f"{sw}: VLANs", sorted(v.vlan_no for v in vlans))
        up = "router" if devcli.uplinked(lab, sw) else (f"switch {devcli.upstream(lab, sw)}"
                                                        if devcli.upstream(lab, sw) else "")
        out[f"sw:{sw}:uplink"] = ("switches", f"{sw}: uplink (to the router or another switch)", up)
        for v in vlans:
            seg = plan.segment_of(v.id)
            mode = (netplan.dhcp_mode(plan, seg) if seg.network.routed else
                    "server" if any("dhcp" in n.roles for n in lab.nodes_on(v.id)) else "none")
            out[f"dhcp:{sw}:{v.vlan_no}"] = ("dhcp", f"{sw} VLAN {v.vlan_no}: who hands out addresses", mode)
            snet = seg.network
            out[f"net:{sw}:{v.vlan_no}"] = ("ip", f"{sw} VLAN {v.vlan_no}: subnet and gateway",
                                            [snet.cidr, snet.router_ip if snet.routed else ""])
        if sw in lines:
            ln = lines[sw]
            out[f"wan:{sw}"] = ("wan", f"{sw}: WAN line", [ln.delay_ms, ln.jitter_ms, ln.loss_pct, ln.rate_mbit])
    for ap in wifi.aps(lab).values():
        a = ap["id"]
        out[f"ap:{a}"] = ("wifi", f"{ap['name']}: network name and security", [ap["ssid"], ap["security"]])
        if ap["security"] == "wpa2":
            out[f"ap:{a}:key"] = ("wifi", f"{ap['name']}: network security key", ap["key"])
        if ap["security"] == "wpa2-ent":  # WPA2-Enterprise (winlab/wpaent.py)
            out[f"ap:{a}:radius"] = ("wifi", f"{ap['name']}: RADIUS server, shared secret and own address",
                                     [ap["radius"], ap["radius_port"], ap["radius_key"], ap["ip"]])
        out[f"ap:{a}:cable"] = ("wifi", f"{ap['name']}: cable", where(ap["network"]))
    return out


def _hash(salt: str, item: str, value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{salt}\0{item}\0{raw}".encode()).hexdigest()[:32]


# ------------------------------------------------------------------ in-guest checks
def guest_catalog(lab=None) -> list[dict]:
    """What an instructor can add as an in-guest check: the common ones,
    a troubleshooting scenario's "is it fixed" test, any exercise check."""
    from . import exercises, guestfaults
    out = [{"id": f"t:{k}", "group": "Common checks", "title": t.replace("{node} ", "").replace("{node}: ", "")
            .replace("{arg}", f"<{TEMPLATE_ARG[k]}>" if k in TEMPLATE_ARG else ""), "arg": TEMPLATE_ARG.get(k, "")}
           for k, (t, _, _) in TEMPLATES.items()]
    out += [{"id": f"f:{f.id}", "group": "A problem is fixed (Troubleshooting)", "title": f.title, "arg": ""}
            for f in guestfaults.catalog() if f.verify]
    for ex in exercises.list_available():
        for i, c in enumerate(ex.checks):
            if c.node == exercises.WINLAB:  # graded from winlab's records, not inside a machine
                continue
            out.append({"id": f"x:{ex.id}:{i}", "group": f"Exercise: {ex.title}", "title": c.name,
                        "node": c.node, "arg": ""})
    return out


def guest_check(lab, ref: str, node: str, arg: str = "", points: int = 2) -> dict:
    """One in-guest check, filled in for a machine of the network."""
    from . import exercises, guestfaults, naming
    nid = naming.resolve(lab, node)
    if nid not in lab.nodes:
        raise ActivityError(f"no machine {node!r} in {lab.name}")
    n = lab.nodes[nid]
    nm = _name(n)
    linux = n.kind == "linux"
    if not 0 <= int(points) <= 100:
        raise ActivityError("a check is worth 0 to 100 points")
    if ref.startswith("t:") and ref[2:] in TEMPLATES:
        k = ref[2:]
        label, script, expect = TEMPLATES[k]
        if k in TEMPLATE_ARG:
            arg = arg.strip() or (lab.domain if k == "joined" else "")
            if not ARG_RE.match(arg):
                raise ActivityError(f"give the check its {TEMPLATE_ARG[k]} (letters, digits, dots and dashes)")
        if linux:
            if k not in _SH:
                raise ActivityError(f"{nm} runs Linux: that check is for Windows")
            script = _SH[k]
        fill = lambda s: s.replace("{node}", nm).replace("{arg}", arg)  # noqa: E731
        return {"name": fill(label), "node": nm, "script": fill(script), "shell": "sh" if linux else "powershell",
                "expect": fill(expect), "match": "exact", "points": int(points)}
    if ref.startswith("f:") and ref[2:] in guestfaults.SCENARIOS:
        f = guestfaults.SCENARIOS[ref[2:]]
        if not guestfaults.applies_to(f, n.kind, n.image):
            raise ActivityError(f"{f.title!r} is not a check for {nm}")
        cmd, shell, expect = guestfaults.verify_command(f.id, guestfaults.lab_params(lab))
        return {"name": f"{nm}: fixed, {f.title.lower()}", "node": nm, "script": cmd, "shell": shell,
                "expect": expect, "match": "last", "points": int(points)}
    m = re.fullmatch(r"x:([a-z0-9-]+):(\d+)", ref)
    if m:
        try:
            ex = exercises.load(m.group(1))
            c = ex.checks[int(m.group(2))]
        except (exercises.ExerciseError, IndexError, OSError):
            raise ActivityError(f"no exercise check {ref!r}") from None
        return {"name": f"{nm}: {c.name}", "node": nm, "script": c.script, "shell": c.shell, "expect": c.expect,
                "match": c.match, "expect_rc": c.expect_rc, "points": int(points)}
    raise ActivityError(f"no in-guest check {ref!r} (see `winlab activity items`)")


def _guest_ok(g: dict, rc: int, out: str) -> bool:
    from . import exercises, guestfaults
    if rc != int(g.get("expect_rc", 0)):
        return False
    if g.get("match") == "last":
        return guestfaults.is_fixed(out, g.get("expect", "True"))
    c = exercises.Check(name=g["name"], node=g["node"], script=g["script"], expect=g.get("expect", ""),
                        match=g.get("match", "exact"))
    return exercises.output_matches(c, out)


# ------------------------------------------------------------------ making one
def _prune(lab, keep: set[str], cables: bool):
    """The instructor's network with only the devices in ``keep`` (machine
    ids or names, ``net:<switch>``, ``ap:<id>``), and without its cables
    unless ``cables``."""
    from . import naming
    lab = copy.deepcopy(lab)
    keep_ids = {naming.resolve(lab, k) for k in keep}
    gone_nodes = [nid for nid in lab.nodes if nid not in keep_ids]
    gone_sw = [sw for sw in devcli.switches(lab) if f"net:{sw}" not in keep]
    family = {v.id for sw in gone_sw for v in devcli.vlans_of(lab, sw)}
    for nid in gone_nodes:
        del lab.nodes[nid]
        lab.layout.pop(nid, None)
    for ap in list(wifi.aps(lab)):
        if wifi.PREFIX + ap not in keep:
            wifi.remove_ap(lab, ap)
        elif not cables or lab.devices[wifi.PREFIX + ap].get("network") in family:
            lab.devices[wifi.PREFIX + ap].pop("network", None)
    wifi.vm_nodes(lab)  # the APs' VMs follow their cables
    for node in lab.node_list():
        for nic in node.nics:
            nic.trunk = [t for t in nic.trunk if t not in family and cables]
            if nic.network in family or not cables:
                nic.network, nic.ip, nic.trunk = "", None, []
        if not cables or (node.vars.get("wifi_ap") and wifi.PREFIX + str(node.vars["wifi_ap"]) not in lab.devices):
            node.vars.pop("wifi_ap", None)
            for i in wifi.wireless(node):  # off the air: its card is on no network
                node.nics[i].network, node.nics[i].ip, node.nics[i].trunk = "", None, []
    for sw in devcli.switches(lab):
        if sw not in gone_sw and (not cables or lab.networks[sw].upstream in gone_sw):
            lab.networks[sw].upstream = ""
    for nid in family:
        lab.networks.pop(nid, None)
    for sw in gone_sw:
        lab.layout.pop(f"net:{sw}", None)
        lab.devices.pop(f"sw:{sw}", None)
        wan.drop_switch(lab, sw)
    if not cables:
        for net in lab.networks.values():
            net.routed = False
        for key in [k for k in lab.devices if k.startswith(wan.PREFIX)]:
            del lab.devices[key]
        for table in lab.devices.values():  # console cables too (consolecable.py)
            table.pop("console", None)
        router = lab.devices.get(devcli.ROUTER, {})
        for k in [k for k in router if k.startswith(devcli.RPORT)]:  # the switches' uplink cables
            del router[k]
    pools = lab.devices.get(devcli.ROUTER, {})
    for k in [k for k, v in pools.items() if (k.startswith("pool:") or k.startswith("sub:")) and v not in lab.networks]:
        del pools[k]
    lab.firewall.rules = [r for r in lab.firewall.rules if r.segment in lab.networks
                          and r.source not in gone_nodes and r.destination not in gone_nodes]
    return lab


def _empty(lab):
    from .model import Lab
    out = Lab(name=lab.name, description=lab.description, workbench=True, sandbox=True,
              layout={"router": list(lab.layout.get("router", [440, 60]))})
    out.domain, out.netbios = lab.domain, lab.netbios
    return out


def make(lab, title: str, instructions: str = "", start: str = "empty", keep: list[str] | None = None,
         cables: bool = False, version: str = "", time_limit: int = 0, feedback: str = "items",
         points: dict[str, int] | None = None, skip: list[str] | None = None,
         guest: list[dict] | None = None) -> bytes:
    """The activity file's bytes, with ``lab`` (the finished network) as the
    target. ``points``: per category, points per item (0 = not graded)."""
    if not lab.workbench:
        raise ActivityError("an activity is made from a network built on the workbench")
    title = " ".join(str(title).split())[:120]
    if not title:
        raise ActivityError("give the activity a title")
    instructions = str(instructions).strip()[:8000]
    if feedback not in FEEDBACK:
        raise ActivityError("the student sees which items are wrong (items) or only the score (score)")
    if not 0 <= int(time_limit) <= 24 * 60:
        raise ActivityError("a time limit is 0 (none) to 1440 minutes")
    pts = dict(DEFAULT_POINTS)
    for k, v in (points or {}).items():
        if k not in CATEGORIES:
            raise ActivityError(f"nothing called {k!r} to grade: one of {', '.join(CATEGORIES)}")
        if not 0 <= int(v) <= 100:
            raise ActivityError("an item is worth 0 to 100 points")
        pts[k] = int(v)
    if start == "empty":
        first = _empty(lab)
    elif start == "partial":
        first = _prune(lab, set(keep or []), cables)
    elif start == "version":
        f = netfile.points_dir(lab.name) / f"{version}{netfile.EXT}"
        if not netfile.POINT_ID.match(version or "") or not f.exists():
            raise ActivityError("no such saved version to start from")
        first = _from_raw(netfile.read(f.read_bytes())[1], lab.name)
    else:
        raise ActivityError(f"the student starts from {', '.join(STARTS)}")
    # The student's lab is called after the activity (netfile picks a free name).
    first.name = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:28] or lab.name
    salt = secrets.token_hex(12)
    skipped = set(skip or [])
    items = [{"id": k, "cat": cat, "label": label, "points": pts[cat], "want": _hash(salt, k, value)}
             for k, (cat, label, value) in sorted(facts(lab).items(), key=lambda kv: (list(CATEGORIES).index(kv[1][0]), kv[0]))
             if pts[cat] > 0 and k not in skipped]
    guest = list(guest or [])
    if len(guest) > MAX_GUEST:
        raise ActivityError(f"at most {MAX_GUEST} in-guest checks")
    if not items and not guest:
        raise ActivityError("nothing is graded: give a category some points, or add an in-guest check")
    rules = {"format": FORMAT, "title": title, "instructions": instructions, "time_limit_min": int(time_limit),
             "feedback": feedback, "start": start, "items": len(items), "guest": len(guest),
             "points": sum(i["points"] for i in items) + sum(int(g["points"]) for g in guest)}
    target = {"salt": salt, "items": items, "guest": guest}
    base = netfile.dumps(first, f"activity: {title}")
    with zipfile.ZipFile(io.BytesIO(base)) as z:
        parts = {n: z.read(n) for n in (netfile.MANIFEST, netfile.NETWORK)}
    manifest = json.loads(parts[netfile.MANIFEST])
    manifest["activity"] = title
    parts[netfile.MANIFEST] = (json.dumps(manifest, indent=1) + "\n").encode()
    parts[ACTIVITY] = (json.dumps(rules, indent=1) + "\n").encode()
    parts[TARGET] = json.dumps(target, separators=(",", ":")).encode()
    parts[SEAL] = _seal(parts).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n in (netfile.MANIFEST, netfile.NETWORK, ACTIVITY, TARGET, SEAL):
            z.writestr(n, parts[n])
    data = buf.getvalue()
    if len(data) > netfile.MAX_BYTES:
        raise ActivityError("that activity is far too big")
    return data


def _from_raw(raw: dict, name: str):
    from . import schema
    raw.setdefault("lab", {})["name"] = name
    try:
        return schema._build(raw, paths.LABS / f"{name}.toml")
    except (schema.LabError, KeyError, TypeError, ValueError) as exc:
        raise ActivityError(f"that version does not load: {exc}") from None


def _seal(parts: dict[str, bytes]) -> str:
    h = hmac.new(_SEAL, digestmod=hashlib.sha256)
    for n in sorted(p for p in parts if p != SEAL):
        h.update(n.encode() + b"\0" + hashlib.sha256(parts[n]).digest())
    return h.hexdigest()


def read(data: bytes) -> tuple[dict, dict, dict]:
    """(manifest, rules, target) of an activity file, checked whole: its
    size, its parts, its seal, and that its network loads as a network file."""
    if len(data) > netfile.MAX_BYTES:
        raise ActivityError("that is not an activity: it is far too big")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist())
            if names != PARTS:
                raise ActivityError("that is not a winlab activity file" if ACTIVITY not in names
                                    else "that activity file has been changed since it was made")
            if any(z.getinfo(n).file_size > (netfile.MAX_BYTES if n == netfile.NETWORK else PART_MAX) for n in names):
                raise ActivityError("that activity file is damaged")
            parts = {n: z.read(n) for n in names}
    except (zipfile.BadZipFile, KeyError, ValueError) as exc:
        raise ActivityError(f"that is not a winlab activity file ({exc})") from None
    if not hmac.compare_digest(parts[SEAL].decode("ascii", "replace").strip(), _seal(parts)):
        raise ActivityError("that activity file has been changed since it was made")
    try:
        manifest, _ = netfile.read(data)
        rules, target = json.loads(parts[ACTIVITY]), json.loads(parts[TARGET])
    except netfile.NetFileError as exc:
        raise ActivityError(str(exc)) from None
    except (ValueError, UnicodeDecodeError):
        raise ActivityError("that activity file is damaged") from None
    if int(rules.get("format", 0)) > FORMAT:
        raise ActivityError("this activity was made by a newer winlab; update winlab to open it")
    return manifest, rules, target


# ------------------------------------------------------------------ the student's copy
def _dir() -> Path:
    return paths.VAR / "activities"


def file_of(lab_name: str) -> Path:
    return _dir() / f"{lab_name}{EXT}"


def _state_file(lab_name: str) -> Path:
    return _dir() / f"{lab_name}.json"


def _load_state(lab_name: str) -> dict:
    try:
        return json.loads(_state_file(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


_lock = threading.Lock()


def _save_state(lab_name: str, st: dict) -> None:
    f = _state_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(st, indent=1), encoding="utf-8")
    tmp.replace(f)


def open_bytes(data: bytes, name: str = ""):
    """An activity brought in: its starting network as a new lab, and the
    activity kept beside it, its clock started."""
    _, rules, _ = read(data)
    try:
        lab = netfile.open_bytes(data, name)
    except netfile.NetFileError as exc:
        raise ActivityError(str(exc)) from None
    _dir().mkdir(parents=True, exist_ok=True)
    file_of(lab.name).write_bytes(data)
    _save_state(lab.name, {"started": time.time(), "title": rules["title"], "guest": {}})
    return lab


def is_activity(lab_name: str) -> bool:
    return file_of(lab_name).exists()


def grade(lab, rules: dict, target: dict, guest_results: dict | None = None) -> dict:
    """The score of ``lab`` against the target: every item, passed or not."""
    have = facts(lab)
    salt = target["salt"]
    items = []
    for it in target["items"]:
        got = have.get(it["id"])
        ok = got is not None and hmac.compare_digest(_hash(salt, it["id"], got[2]), it["want"])
        items.append({"id": it["id"], "cat": it["cat"], "label": it["label"], "points": int(it["points"]), "ok": ok})
    guests = []
    for i, g in enumerate(target.get("guest", [])):
        r = (guest_results or {}).get(str(i)) or {}
        guests.append({"n": i, "label": g["name"], "points": int(g["points"]), "ok": bool(r.get("ok")),
                       "checked": r.get("at", 0), "detail": r.get("detail", "")})
    total = sum(x["points"] for x in items + guests)
    earned = sum(x["points"] for x in items + guests if x["ok"])
    return {"items": items, "guest": guests, "earned": earned, "total": total,
            "percent": round(100 * earned / total) if total else 0,
            "done": sum(1 for x in items + guests if x["ok"]), "count": len(items) + len(guests)}


def status(lab, now: float | None = None) -> dict:
    """What the Activity window shows: the instructions, the clock, and the
    score, with the check list only when the instructor allowed it. Past
    the time limit (or once handed in) the score stays where it was."""
    if not is_activity(lab.name):
        return {"ok": True, "activity": False}
    try:
        _, rules, target = read(file_of(lab.name).read_bytes())
    except (OSError, ActivityError) as exc:
        return {"ok": False, "activity": True, "message": str(exc)}
    now = time.time() if now is None else now
    with _lock:
        st = _load_state(lab.name)
        started = float(st.get("started") or now)
        limit = int(rules.get("time_limit_min") or 0) * 60
        deadline = started + limit if limit else 0
        over = bool(deadline and now >= deadline)
        final = st.get("final")
        if final is None:
            g = grade(lab, rules, target, st.get("guest"))
            src = Path(lab.source_path) if lab.source_path else paths.LABS / f"{lab.name}.toml"
            try:
                changed = src.stat().st_mtime
            except OSError:
                changed = now
            if over and changed > deadline and st.get("last"):
                g = st["last"]  # changed after the time ran out: the score as it stood
            if over or st.get("handed_in"):
                st["final"] = final = g
            else:
                st["last"] = g
            _save_state(lab.name, st)
        g = final or st["last"]
    out = {"ok": True, "activity": True, "title": rules["title"], "instructions": rules.get("instructions", ""),
           "feedback": rules["feedback"], "started": started, "elapsed": int(now - started),
           "time_limit_min": int(rules.get("time_limit_min") or 0),
           "remaining": max(0, int(deadline - now)) if deadline else None,
           "over": over, "handed_in": bool(st.get("handed_in")), "final": final is not None,
           "percent": g["percent"], "earned": g["earned"], "total": g["total"],
           "checking": bool(st.get("checking")), "guest_count": len(target.get("guest", []))}
    from . import history  # who changed what on the bench since the activity started
    trail = history.since(lab.name, started)
    out["changes"], out["last_change"] = len(trail), trail[-1] if trail else None
    if rules["feedback"] == "items":
        out["items"] = [{k: x[k] for k in ("cat", "label", "points", "ok")} for x in g["items"]]
        out["guest"] = [{k: x[k] for k in ("label", "points", "ok", "checked", "detail")} for x in g["guest"]]
        out["categories"] = CATEGORIES
    return out


def hand_in(lab) -> dict:
    with _lock:
        st = _load_state(lab.name)
        if not is_activity(lab.name):
            raise ActivityError(f"{lab.name} is not an activity")
        st["handed_in"] = time.time()
        _save_state(lab.name, st)
    return status(lab)


def _run_in_guest(lab_name: str, node_id: str, script: str, shell: str) -> tuple[int, str]:
    from .guestctl import GuestChannel, GuestError
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not ns.serial_port or not state.pid_alive(ns.pid):
        raise ActivityError("the machine is off")
    try:
        ch = GuestChannel(ns.serial_port).connect(retries=3, delay=1)
    except GuestError as exc:
        raise ActivityError(f"its agent does not answer ({exc})") from None
    try:
        res = ch.run(script, shell=shell, timeout=120)
    except GuestError as exc:
        raise ActivityError(str(exc)) from None
    finally:
        ch.close()
    return res.rc, res.out


def check_guests(lab, runner=None) -> dict:
    """Runs the in-guest checks on the student's machines, one by one, and
    remembers the results. ``runner(lab, node_id, script, shell) -> (rc,
    stdout)`` stands in for the serial agent in tests."""
    from . import naming
    _, rules, target = read(file_of(lab.name).read_bytes())
    run = runner or (lambda lb, nid, script, shell: _run_in_guest(lb.name, nid, script, shell))
    if status(lab).get("final"):
        raise ActivityError("the activity is over: its score stands")
    results = {}
    for i, g in enumerate(target.get("guest", [])):
        nid = naming.resolve(lab, g["node"])
        try:
            if nid not in lab.nodes:
                raise ActivityError(f"there is no {g['node']} on the network")
            rc, out = run(lab, nid, g["script"], g.get("shell", "powershell"))
            ok = _guest_ok(g, rc, out)
            lines = (out or "").strip().splitlines()
            detail = "" if ok else (lines[-1][:120] if lines else f"exit code {rc}")
        except ActivityError as exc:
            ok, detail = False, str(exc)
        results[str(i)] = {"ok": ok, "at": time.time(), "detail": detail}
    with _lock:
        st = _load_state(lab.name)
        st["guest"], st["checking"] = results, False
        _save_state(lab.name, st)
    return results


def check_guests_soon(lab) -> None:
    """check_guests in the background, for the window (a check can take a
    minute while a machine's agent wakes up)."""
    with _lock:
        st = _load_state(lab.name)
        if st.get("checking") and time.time() - float(st.get("checking_at") or 0) < 600:
            return
        st["checking"], st["checking_at"] = True, time.time()
        _save_state(lab.name, st)

    def go() -> None:
        try:
            check_guests(lab)
        except Exception:  # noqa: BLE001 - the window shows the old results
            with _lock:
                s = _load_state(lab.name)
                s["checking"] = False
                _save_state(lab.name, s)
    threading.Thread(target=go, daemon=True, name=f"activity-{lab.name}").start()


# ------------------------------------------------------------------ the desktop
def items_view(lab) -> dict:
    """For the instructor's dialog: what this network would be graded on
    (labels, not values), the in-guest checks there are, its machines and
    saved versions."""
    from . import naming
    counts: dict[str, int] = {}
    rows = []
    for k, (cat, label, _) in sorted(facts(lab).items()):
        counts[cat] = counts.get(cat, 0) + 1
        rows.append({"id": k, "cat": cat, "label": label})
    return {"ok": True, "categories": [{"id": c, "title": t, "count": counts.get(c, 0), "points": DEFAULT_POINTS[c]}
                                       for c, t in CATEGORIES.items()],
            "items": rows, "catalog": guest_catalog(lab),
            "machines": [{"id": n.id, "name": naming.hostname_of(n), "linux": n.kind == "linux"} for n in lab.node_list()],
            "versions": netfile.savepoints(lab.name), "workbench": lab.workbench}


def make_from_params(lab, p: dict) -> bytes:
    guest = [guest_check(lab, str(g.get("ref", "")), str(g.get("node", "")), str(g.get("arg", "")),
                         int(g.get("points", 2) or 0)) for g in (p.get("guest") or [])]
    return make(lab, str(p.get("title", "")), str(p.get("instructions", "")), str(p.get("start", "empty")),
                [str(k) for k in p.get("keep") or []], bool(p.get("cables")), str(p.get("version", "")),
                int(p.get("time_limit") or 0), str(p.get("feedback", "items")),
                {k: int(v) for k, v in (p.get("points") or {}).items()}, [str(s) for s in p.get("skip") or []], guest)


def act(dash, action: str, params: dict) -> dict:
    try:
        if action == "activity-state":
            return status(dash.lab)
        if action == "activity-items":
            return items_view(dash.lab)
        if action == "activity-guest":
            if not is_activity(dash.lab.name):
                raise ActivityError("this network is not an activity")
            check_guests_soon(dash.lab)
            return {"ok": True, "message": "checking inside the machines…"}
        if action == "activity-handin":
            return {**hand_in(dash.lab), "message": "handed in: your score stands"}
    except (ActivityError, OSError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown activity action {action!r}"}


def http_post(handler, path: str, length: int) -> None:
    """POST /api/activity/make (the dialog's choices, JSON: the file comes
    back) and /api/activity/open (a file's bytes: a new lab, and the desktop
    moves to it)."""
    if length > netfile.MAX_BYTES:
        handler.close_connection = True
        handler._json({"ok": False, "message": "that is not an activity: it is far too big"}, 400)
        return
    body = handler.rfile.read(length)
    try:
        if path == "/api/activity/make":
            lab = handler.dash.lab
            data = make_from_params(lab, json.loads(body.decode() or "{}"))
            handler.send_response(200)
            handler.send_header("Content-Type", "application/octet-stream")
            handler.send_header("Content-Disposition", f'attachment; filename="{lab.name}{EXT}"')
            handler.send_header("Content-Length", str(len(data)))
            handler.send_header("Cache-Control", "no-store")
            handler.end_headers()
            handler.wfile.write(data)
            return
        if path == "/api/activity/open":
            lab = open_bytes(body)
            out = handler._switch_lab(lab.name)
            out["message"] = f"opened {lab.name}: the Activity window has your instructions"
            handler._json(out)
            return
        handler._json({"ok": False, "message": "not found"}, 404)
    except (ActivityError, ValueError, TypeError) as exc:
        handler._json({"ok": False, "message": str(exc)})


def render(st: dict) -> str:
    """The CLI's view of status()."""
    if not st.get("activity"):
        return "this lab is not an activity"
    lines = [st["title"], ""]
    if st["time_limit_min"]:
        left = st["remaining"] or 0
        lines.append("time is up" if st["over"] else f"time left: {left // 60}:{left % 60:02d}")
    lines.append(f"score: {st['earned']}/{st['total']} points ({st['percent']}%)"
                 + ("  [final]" if st["final"] else ""))
    if st.get("last_change"):
        c = st["last_change"]
        lines.append(f"changes: {st['changes']}, the last {c['t']} by {c['who']}: {c['what']}")
    if "items" in st:
        lines.append("")
        for x in st["items"] + st["guest"]:
            lines.append(f"  [{'x' if x['ok'] else ' '}] {x['label']}  ({x['points']})")
    return "\n".join(lines)
