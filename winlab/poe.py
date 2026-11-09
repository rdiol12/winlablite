"""Power over Ethernet on the workbench switches: a budget, per-port
settings, and the devices that stay dark when it runs out.

An access point, an IP phone and an IP camera take their power from the
switch port their cable is in (winlab/wifi.py, winlab/appliance.py). A
switch whose model is one of MODELS with a PoE budget powers them the way a
Catalyst does: each powered device (PD) is detected and classified by its
IEEE class, the switch allocates that class's maximum from its budget,
port by port, and a device the budget cannot cover gets no power at all. It
stays dark: its VM does not run (winlab stops it, as pulling its power
would, and refuses to start it), until a change frees the power, when it
boots by itself as a real one does.

How the switch allocates, as IOS does on a Catalyst 2960:
  * `power inline static [max N]` reserves the port's power first, whether
    a device is plugged in or not (the installer's "spare" for a future AP);
  * `power inline auto [max N]` (the default) powers what is detected,
    first come first served while the switch runs; when it starts (the lab
    starts, the switch is powered on) the ports are powered in port order;
    a device whose class is more than the port's max is denied;
  * `power inline never` turns the port's power off.
`show power inline` prints the budget (Available, Used, Remaining) and each
port's admin and oper state (on, off, power-deny), its watts, the device
and its class; the switch logs %ILPOWER-5-ILPOWER_POWER_DENY for a denied
port.

A switch with no model set is the classic workbench switch (WS-C2960-24TT-L,
no PoE): its powered devices take power from PoE injectors on the bench,
as before, so no lab changes behaviour until a PoE model is fitted (the
switch's panel on the canvas, or `model` in its [devices."sw:<id>"] table).
What is granted while the switch runs is kept beside the lab's machines
(poe.json), never in the lab file; the router (which runs every switch)
restarting starts the allocation over in port order.

The ts-poe-budget problem (``poe-budget``, register_faults) is set from
outside the phones: facilities fit four PoE+ access points over a weekend
and the switch restarted, so the APs, on the lower ports, took the budget.
"""

from __future__ import annotations

import json
import re

from . import devcli, paths, state

FILE = "poe.json"
LEGACY = "WS-C2960-24TT-L"
# The switch models a workbench switch can be: budget in watts, how many
# ports (Fa0/1 up) have PoE, and whether they are PoE+ (802.3at, 30 W).
MODELS: dict[str, dict] = {
    "WS-C2960-24TT-L": {"title": "Catalyst 2960-24TT-L: no PoE", "budget": 0.0, "ports": 0, "plus": False},
    "WS-C2960-24LT-L": {"title": "Catalyst 2960-24LT-L: PoE on Fa0/1-8, 123 W", "budget": 123.0, "ports": 8,
                        "plus": False},
    "WS-C2960-24PC-L": {"title": "Catalyst 2960-24PC-L: PoE on every port, 370 W", "budget": 370.0, "ports": 24,
                        "plus": False},
    "WS-C2960C-8PC-L": {"title": "Catalyst 2960C-8PC-L: PoE+ on Fa0/1-8, 124 W", "budget": 124.0, "ports": 8,
                        "plus": True},
}
# What the switch allocates per IEEE class (watts at the switch port).
CLASS_W = {0: 15.4, 1: 4.0, 2: 7.0, 3: 15.4, 4: 30.0}
# The class each kind of powered device presents.
PD_CLASS = {"ap": 4, "phone": 2, "camera": 3}
PD_NAME = {"ap": "Ieee PD", "phone": "Ieee PD", "camera": "Ieee PD"}
KEY = "poe:"        # a switch's setting: poe:<port no> = never | static | auto
MAX_KEY = "poemax:"  # poemax:<port no> = the port's max, milliwatts

# A seam for the tests: stop(lab_name, node_id, why) -> bool.
stop_fn = None


class PoeError(Exception):
    pass


# ------------------------------------------------------------------ the model
def model_of(lab, sw: str) -> str:
    """The switch's model number ('' for the classic switch fed by injectors)."""
    m = str(lab.devices.get(f"sw:{sw}", {}).get("model") or "")
    return m if m in MODELS else ""


def model_name(lab, sw: str) -> str:
    return model_of(lab, sw) or LEGACY


def has_poe(lab, sw: str) -> bool:
    m = model_of(lab, sw)
    return bool(m and MODELS[m]["budget"])


def set_model(lab, sw: str, model: str) -> str:
    if sw not in devcli.switches(lab):
        raise PoeError(f"no switch {sw!r}")
    if model and model not in MODELS:
        raise PoeError(f"no model {model!r} (one of {', '.join(MODELS)})")
    own = devcli.settings(lab, f"sw:{sw}")
    if model and model != LEGACY:
        own["model"] = model
    else:
        own.pop("model", None)
    _forget(lab.name, sw)  # a new switch starts its allocation over
    return MODELS[model or LEGACY]["title"]


def port_max(lab, sw: str) -> float:
    m = model_of(lab, sw)
    return 30.0 if m and MODELS[m]["plus"] else 15.4


# ------------------------------------------------------------------ what is on each port
def devices_on(lab, plan, sw: str) -> dict[int, dict]:
    """Port number -> the powered device in it: {kind, id (its VM's node
    id), name}. Machines that take no power (PCs, servers) are left out."""
    from . import appliance, naming, wifi
    out: dict[int, dict] = {}
    ports = devcli.switch_ports(lab, plan).get(sw, [])
    for i, link in enumerate(ports, 1):
        if link is None:
            continue
        node = lab.nodes.get(link.node_id)
        dev = appliance.device_of(node) if node is not None else ""
        if dev in PD_CLASS:
            out[i] = {"kind": dev, "id": node.id, "name": naming.display(lab, node.id), "label": link.label}
    every = wifi.aps(lab)
    for no, ap_id in devcli.ap_slots(lab, plan, sw, ports).items():
        ap = every.get(ap_id)
        if ap is not None:
            out[no] = {"kind": "ap", "id": ap_id, "name": ap["name"], "label": f"ap:{ap_id}"}
    return out


def port_conf(lab, sw: str, no: int) -> tuple[str, float]:
    """(admin mode, max watts) of a port: auto/static/never and its max."""
    own = lab.devices.get(f"sw:{sw}", {})
    mode = str(own.get(f"{KEY}{no}") or "auto")
    try:
        mx = int(own.get(f"{MAX_KEY}{no}") or 0) / 1000.0
    except ValueError:
        mx = 0.0
    return mode, (mx or port_max(lab, sw))


# ------------------------------------------------------------------ granted power
def _path(lab_name: str):
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
        if isinstance(data.get("granted"), dict):
            data.setdefault("dark", [])
            return data
    except (OSError, ValueError, AttributeError):
        pass
    return {"granted": {}, "dark": [], "boot": 0}


def _write(lab_name: str, data: dict) -> None:
    state.write_json(_path(lab_name), data)


def _boot(lab_name: str) -> int:
    st = state.load(lab_name)
    ns = st.nodes.get("fabric") if st else None
    return int(ns.pid or 0) if ns and ns.pid and state.pid_alive(ns.pid) else 0


def granted(lab_name: str) -> dict[str, list[int]]:
    """What each switch powers now; nothing (port order) when the router,
    which runs every switch, started since it was written."""
    data = load(lab_name)
    return data["granted"] if data.get("boot") == _boot(lab_name) else {}


def _forget(lab_name: str, sw: str) -> None:
    data = load(lab_name)
    if data["granted"].pop(sw, None) is not None:
        _write(lab_name, data)


def restarted(lab_name: str, sw: str = "") -> None:
    """The switch (or, with no switch, every switch) started again: it
    powers its ports in port order."""
    data = load(lab_name)
    if sw:
        data["granted"].pop(sw, None)
    else:
        data["granted"] = {}
    _write(lab_name, data)


def allocate(lab, plan, sw: str, granted: list[int] | None = None) -> dict:
    """The switch's power: {model, budget, used, remaining, ports: {no:
    {admin, oper, watts, max, device, class, why}}}. `granted` are the
    ports that had power before (they keep it first, as on a running
    switch); None powers in port order, as the switch does when it starts."""
    m = model_of(lab, sw)
    info = MODELS[m or LEGACY]
    budget = float(info["budget"])
    devs = devices_on(lab, plan, sw)
    own = lab.devices.get(f"sw:{sw}", {})
    conf_ports = {int(k[len(KEY):]) for k in own if k.startswith(KEY) and k[len(KEY):].isdigit()}
    numbers = sorted((set(devs) | conf_ports) & set(range(1, int(info["ports"]) + 1)))
    ports: dict[int, dict] = {}
    left = budget
    for no in numbers:
        mode, mx = port_conf(lab, sw, no)
        d = devs.get(no)
        cls = PD_CLASS[d["kind"]] if d else None
        ports[no] = {"admin": mode, "oper": "off", "watts": 0.0, "max": mx, "device": d, "class": cls, "why": ""}
    # Static first: its reservation stands whether a device draws it or not.
    for no in numbers:
        p = ports[no]
        if p["admin"] != "static":
            continue
        if p["max"] <= left + 1e-6:
            left -= p["max"]
            p["reserved"] = p["max"]
            if p["device"]:
                need = min(CLASS_W[p["class"]], port_max(lab, sw))
                if need > p["max"] + 1e-6:
                    p["oper"], p["why"] = "power-deny", "the device's class needs more than the port's max"
                else:
                    p["oper"], p["watts"] = "on", p["max"]
        else:
            p["oper"], p["why"] = ("power-deny" if p["device"] else "off"), "not enough power left to reserve"
    order = [n for n in numbers if granted and n in granted] + [n for n in numbers if not granted or n not in granted]
    for no in order:
        p = ports[no]
        if p["admin"] != "auto" or not p["device"]:
            continue
        need = min(CLASS_W[p["class"]], port_max(lab, sw))
        if need > p["max"] + 1e-6:
            p["oper"], p["why"] = "power-deny", f"its IEEE class {p['class']} needs {need:.1f} W, over the port's max"
        elif need <= left + 1e-6:
            left -= need
            p["oper"], p["watts"] = "on", need
        else:
            p["oper"], p["why"] = "power-deny", "insufficient power: the switch's budget is used up"
    for no, p in ports.items():
        if p["admin"] == "never":
            p["why"] = "power inline never"
    return {"switch": sw, "model": m or LEGACY, "poe": bool(budget), "budget": budget,
            "used": round(budget - left, 1), "remaining": round(left, 1), "ports": ports,
            "poe_ports": int(info["ports"]), "devices": devs}


def dark(lab, plan) -> dict[str, str]:
    """Node id -> why it has no power, for every powered device on a PoE
    switch that does not power it (a classic switch's devices take power
    from injectors: never dark)."""
    have = granted(lab.name)
    out: dict[str, str] = {}
    for sw in devcli.switches(lab):
        if not has_poe(lab, sw):
            continue
        name = devcli.hostname(lab, f"sw:{sw}")
        if devcli.switch_off(lab, sw):
            for d in devices_on(lab, plan, sw).values():
                out[d["id"]] = f"{name} is off"
            continue
        a = allocate(lab, plan, sw, have.get(sw))
        for no, d in a["devices"].items():
            p = a["ports"].get(no)
            if p is None:
                out[d["id"]] = f"{name} Fa0/{no} has no PoE (only Fa0/1-{a['poe_ports']} do)"
            elif p["oper"] != "on":
                out[d["id"]] = f"{name} Fa0/{no}: {p['why'] or p['oper']}"
    return out


def blocked(lab, plan, nodes: list[str]) -> dict[str, str]:
    """Of these node ids, the ones that cannot power on: no PoE for them."""
    try:
        d = dark(lab, plan)
    except Exception:  # noqa: BLE001 - a lab that does not compile powers as before
        return {}
    return {n: d[n] for n in nodes if n in d}


def settle(lab, plan, start=None) -> dict:
    """After a change (a port's setting, the model, a cable, a restart):
    keeps what each switch granted, stops the devices that lost their power
    and starts the ones that got it back (`start(node_ids)`, the desktop's
    start; without it they boot with the next start). Returns {"dark": {...},
    "stopped": [...], "lit": [...]}."""
    data = load(lab.name)
    boot = _boot(lab.name)
    if boot != data.get("boot"):
        data["granted"], data["boot"] = {}, boot   # the router (every switch) started again
    for sw in devcli.switches(lab):
        if not has_poe(lab, sw):
            data["granted"].pop(sw, None)
            continue
        a = allocate(lab, plan, sw, data["granted"].get(sw))
        data["granted"][sw] = [no for no, p in sorted(a["ports"].items()) if p["oper"] == "on" and p["device"]]
    _write(lab.name, data)
    now = dark(lab, plan)
    running = state.running(lab.name)
    stopped = []
    for node_id, why in now.items():
        if node_id in running:
            stop = stop_fn
            if stop is None:
                from .ups import hard_stop as stop
            if stop(lab.name, node_id, f"no PoE: {why}"):
                stopped.append(node_id)
    lit = [n for n in data.get("dark", []) if n not in now and n in lab.nodes and n not in running]
    data = load(lab.name)
    data["dark"] = sorted(now)
    _write(lab.name, data)
    if lit and start is not None:
        try:
            start(lit)
        except Exception:  # noqa: BLE001 - they boot with the next start then
            pass
    return {"dark": now, "stopped": stopped, "lit": lit}


def settle_dash(dash) -> str:
    """settle() from the desktop: the words for the console or a toast."""
    try:
        r = settle(dash.lab, dash.plan, start=getattr(dash, "start_up", None) and
                   (lambda ids: dash.start_up(ids)))
    except Exception:  # noqa: BLE001 - power is never what stops a command
        return ""
    words = []
    if r["stopped"]:
        words.append(f"{', '.join(r['stopped'])} lost power and went dark")
    if r["lit"]:
        words.append(f"{', '.join(r['lit'])} got power and boot{'s' if len(r['lit']) == 1 else ''}")
    return "; ".join(words)


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    if con.device == devcli.ROUTER:
        return
    IF = I + ("config-if-range",)
    add("show power inline", lambda a: show(con, ""), "Show inline power information", U)
    add("show power inline <line>", lambda a: show(con, a[0]), "Show inline power information", U)
    add("power inline auto", lambda a: set_port(con, "auto", ""), "Automatically detect and power inline devices", IF)
    add("power inline auto max <num>", lambda a: set_port(con, "auto", a[0]),
        "maximum power allowed on this interface", IF)
    add("power inline never", lambda a: set_port(con, "never", ""), "Never apply inline power", IF)
    add("power inline static", lambda a: set_port(con, "static", ""), "High priority inline power interface", IF)
    add("power inline static max <num>", lambda a: set_port(con, "static", a[0]),
        "maximum power allowed on this interface", IF)
    add("no power inline", lambda a: set_port(con, "auto", ""), "Negate a command or set its defaults", IF)


def _port_no(con) -> int:
    m = re.match(r"^FastEthernet0/(\d+)$", con.s.ctx or "")
    if not m:
        raise devcli.CliError("% Inline power is not supported on this interface")
    return int(m.group(1))


def set_port(con, mode: str, mx: str) -> str:
    lab, sw = con.lab, devcli.switch_id(con.device)
    no = _port_no(con)
    if not has_poe(lab, sw) or no > MODELS[model_of(lab, sw)]["ports"]:
        raise devcli.CliError(f"% Inline power is not supported on FastEthernet0/{no}")
    own = devcli.settings(lab, con.device)
    if mx:
        top = int(port_max(lab, sw) * 1000)
        if not mx.isdigit() or not 4000 <= int(mx) <= top:
            raise devcli.CliError(f"% Invalid input: max is 4000 to {top} milliwatts on this port")
    if mode == "auto":
        own.pop(f"{KEY}{no}", None)
    else:
        own[f"{KEY}{no}"] = mode
    if mx and mode != "never":
        own[f"{MAX_KEY}{no}"] = mx
    else:
        own.pop(f"{MAX_KEY}{no}", None)
    note = con._save(live=False).strip()
    said = settle_dash(con.dash)
    lines = [note] if note else []
    a = allocate(lab, con.plan, sw, granted(lab.name).get(sw))
    p = a["ports"].get(no)
    if p and p["device"] and p["oper"] != "on" and mode != "never":
        lines.append(f"%ILPOWER-5-ILPOWER_POWER_DENY: Interface Fa0/{no}: inline power denied. Reason: "
                     + ("insufficient power" if "budget" in p["why"] or "reserve" in p["why"] else
                        "admin off" if mode == "never" else "power class exceeds the port's max"))
    if said:
        lines.append(f"% {said}")
    return "\n".join(lines)


def show(con, which: str) -> str:
    lab, sw = con.lab, devcli.switch_id(con.device)
    if not has_poe(lab, sw):
        return (f"% Invalid input: this switch ({model_name(lab, sw)}) has no Power over Ethernet; its "
                f"powered devices take power from injectors")
    a = allocate(lab, con.plan, sw, granted(lab.name).get(sw))
    nos = list(range(1, a["poe_ports"] + 1))
    if which:
        try:
            name = devcli.parse_if(which, [f"FastEthernet0/{n}" for n in range(1, devcli.SWITCH_PORTS + 1)])
        except devcli.CliError:
            return "% Invalid input detected at '^' marker."
        n = int(name.rsplit("/", 1)[1])
        if n not in nos:
            return f"% Inline power is not supported on FastEthernet0/{n}"
        nos = [n]
    lines = []
    if not which:
        lines += [f"Available:{a['budget']:.1f}(w)  Used:{a['used']:.1f}(w)  Remaining:{a['remaining']:.1f}(w)", ""]
    lines += ["Interface Admin  Oper       Power   Device              Class Max",
              "                            (Watts)                            ",
              "--------- ------ ---------- ------- ------------------- ----- ----"]
    for n in nos:
        p = a["ports"].get(n)
        mode, mx = port_conf(lab, sw, n)
        if p is None:
            p = {"admin": mode, "oper": "off", "watts": 0.0, "max": mx, "device": None, "class": None}
        d = p["device"]
        lines.append(f"{'Fa0/' + str(n):<9} {p['admin']:<6} {p['oper']:<10} {p['watts']:>7.1f} "
                     f"{(PD_NAME[d['kind']] if d and p['oper'] == 'on' else 'n/a'):<19} "
                     f"{(str(p['class']) if d and p['oper'] == 'on' else 'n/a'):<5} {p['max']:.1f}")
    return "\n".join(lines)


def run_lines(con, out: list[str]) -> list[str]:
    """Under each interface, its power inline line (auto with no max is the
    default and not printed)."""
    own = devcli.settings(con.lab, con.device)
    out = list(out)
    for k in sorted((k for k in own if k.startswith(KEY) and k[len(KEY):].isdigit()), key=lambda k: int(k[len(KEY):])):
        no = int(k[len(KEY):])
        head = f"interface FastEthernet0/{no}"
        if head not in out:
            continue
        at = out.index(head) + 1
        while at < len(out) and out[at].startswith(" "):
            at += 1
        mx = own.get(f"{MAX_KEY}{no}")
        out[at:at] = [f" power inline {own[k]}" + (f" max {mx}" if mx and own[k] != "never" else "")]
    for k in sorted((k for k in own if k.startswith(MAX_KEY) and k[len(MAX_KEY):].isdigit()
                     and f"{KEY}{k[len(MAX_KEY):]}" not in own), key=lambda k: int(k[len(MAX_KEY):])):
        no = int(k[len(MAX_KEY):])
        head = f"interface FastEthernet0/{no}"
        if head in out:
            at = out.index(head) + 1
            while at < len(out) and out[at].startswith(" "):
                at += 1
            out[at:at] = [f" power inline auto max {own[k]}"]
    return out


# ------------------------------------------------------------------ the canvas
def view(lab, plan) -> dict:
    """Per switch: its model, the models it may be, and with PoE its budget
    and ports; and the devices that are dark."""
    have = granted(lab.name)
    out = {"models": [{"id": k, "title": v["title"]} for k, v in MODELS.items()], "switches": {}, "dark": {}}
    try:
        for sw in devcli.switches(lab):
            entry = {"model": model_name(lab, sw), "poe": has_poe(lab, sw)}
            if entry["poe"]:
                a = allocate(lab, plan, sw, have.get(sw))
                entry.update(budget=a["budget"], used=a["used"], remaining=a["remaining"],
                             ports=[{"port": f"Fa0/{n}", "admin": p["admin"], "oper": p["oper"],
                                     "watts": p["watts"], "device": (p["device"] or {}).get("name", ""),
                                     "cls": p["class"]} for n, p in sorted(a["ports"].items())])
            out["switches"][sw] = entry
        out["dark"] = dark(lab, plan)
    except Exception:  # noqa: BLE001 - the canvas draws without it
        pass
    return out


def any_poe(lab) -> bool:
    return any(has_poe(lab, sw) for sw in devcli.switches(lab))


def act(dash, params: dict) -> dict:
    """wb-poe: op=model (the switch's model)."""
    op = str(params.get("op") or "")
    try:
        if op == "model":
            sw = str(params.get("switch") or "")
            title = set_model(dash.lab, sw, str(params.get("model") or ""))
            from .workbench import _save
            _save(dash)
            said = settle_dash(dash)
            return {"ok": True, "message": f"{sw} is now a {title}" + (f"; {said}" if said else "")}
    except PoeError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"no such step {op!r}"}


# ------------------------------------------------------------------ the problem
QUICK = True
NEW_APS = ("ap-lobby", "ap-meeting", "ap-kitchen", "ap-store")


def host_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    """`winlab break <phone> poe-budget-exceeded` and the Break button: the
    phone's switch becomes a 2960C-8PC-L, four PoE+ APs are cabled into its
    lower ports over the weekend, and the switch restarted (so it powers in
    port order). Clearing takes the four APs and the ports' settings away."""
    from . import editor, netplan, schema, wifi
    try:
        lab = schema.load(lab_name)
    except Exception as exc:  # noqa: BLE001 - a lab that does not load cannot be broken
        return False, str(exc)
    phone = lab.nodes.get(node)
    if phone is None or not phone.nics or not phone.nics[0].network:
        return False, f"{node} is not cabled to a switch"
    sw = lab.networks[phone.nics[0].network].home
    own = devcli.settings(lab, f"sw:{sw}")
    if clear:
        for ap_id in NEW_APS:
            devcli.pin_port(lab, sw, f"{ap_id}:nic0", None)
            if wifi.PREFIX + ap_id in lab.devices:
                wifi.remove_ap(lab, ap_id)
        for k in [k for k in own if k.startswith((KEY, MAX_KEY))]:
            del own[k]
        for label, no in (load(lab_name).get("was") or {}).items():
            devcli.pin_port(lab, sw, label, int(no) if str(no).isdigit() else None)
        editor.save(lab)
        restarted(lab_name, sw)
        lab = schema.load(lab_name)
        settle(lab, netplan.compile_topology(lab, check_ports=False))
        msg = "the four new access points are gone and the phones are back in their ports"
        say(msg)
        return True, msg
    # Facilities' weekend: the switch becomes a PoE+ 2960C-8PC-L, the four
    # new APs go into its lowest free ports and the phones are moved up to
    # the last two PoE ports to make room; then the switch restarted.
    own["model"] = "WS-C2960C-8PC-L"
    net = phone.nics[0].network
    plan = netplan.compile_topology(lab, check_ports=False)
    phones = [l.label for l in devcli.switch_ports(lab, plan).get(sw, [])
              if l is not None and "ipphone" in (lab.nodes[l.node_id].roles or [])]
    was = {label: own.get(devcli.PIN + label, "") for label in phones}
    for label, no in zip(phones[-2:], (7, 8)):
        devcli.pin_port(lab, sw, label, no)
    taken = {int(v) for k, v in own.items() if k.startswith(devcli.PIN) and str(v).isdigit()}
    free = [n for n in range(1, 9) if n not in taken]
    for ap_id in NEW_APS:
        if wifi.PREFIX + ap_id in lab.devices:
            continue
        try:
            wifi.add_ap(lab, None, ap_id)
            lab.devices[wifi.PREFIX + ap_id]["hostname"] = ap_id
            wifi.set_ap(lab, ap_id, network=net)
        except wifi.WifiError as exc:
            return False, str(exc)
        if free:
            devcli.pin_port(lab, sw, f"{ap_id}:nic0", free.pop(0))
    editor.save(lab)
    data = load(lab_name)
    data["was"] = was
    _write(lab_name, data)
    restarted(lab_name, sw)
    lab = schema.load(lab_name)
    r = settle(lab, netplan.compile_topology(lab, check_ports=False))
    msg = (f"four PoE+ access points are cabled into {devcli.hostname(lab, 'sw:' + sw)} and it restarted; "
           f"dark now: {', '.join(sorted(r['dark'])) or 'nothing'}")
    say(msg)
    return True, msg


def register_faults(reg) -> None:
    from .guestfaults import LINUX, GuestFault
    reg(GuestFault(
        id="poe-budget-exceeded",
        images=("alpine",),
        roles=("ipphone",),
        host="poe-budget",
        title="New access points went in and the last desk phones stay dark",
        os=LINUX,
        shell="sh",
        teaches="the PoE budget of a switch, IEEE classes, show power inline, power inline never / auto max / "
                "static, and allocation in port order when a switch starts",
        symptom="after the weekend the two desk phones are dark (no screen, no link) while the new access points "
                "and the PCs work",
        apply="echo 'this problem is set from outside the phone: winlab break <phone> poe-budget-exceeded fits "
              "four access points on its switch'",
        clear="echo 'free power on the switch: power inline never on a port that does not need it'",
        hints=(
            "A dark phone with its cable in: no power. On the phone's switch, show power inline. Compare "
            "Available, Used and Remaining with what each port draws.",
            "The four new access points are PoE+ class 4: the switch gives each 30 W, 120 of its 124 W, before "
            "the phones (class 2, 7 W each) on the higher ports get anything. The phones are power-deny.",
            "Free power where it is not needed: one of the new APs is a spare for the storeroom. On its port, "
            "interface fa0/<n>, power inline never. Within a minute the phones are powered and boot.",
        ),
        verify="gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}'); "
               "[ -n \"$gw\" ] && ping -c 3 -W 2 \"$gw\" >/dev/null 2>&1 && echo True || echo False",
    ))


# ------------------------------------------------------------------ graded checks
# The PoE lesson's exercise is graded from the switch's settings and the
# allocation winlab computes from them, the same that keeps devices dark.
def _plan(lab):
    from . import netplan
    return netplan.compile_topology(lab, check_ports=False)


def _grade_phones(lab) -> tuple[bool, str]:
    plan = _plan(lab)
    phones = [n.id for n in lab.nodes.values() if "ipphone" in (n.roles or [])]
    dk = dark(lab, plan)
    off = [p for p in phones if p in dk]
    if off:
        return False, "dark: " + "; ".join(f"{p} ({dk[p]})" for p in off)
    return bool(phones), "every desk phone has power" if phones else "the lab has no desk phone"


def _grade_never(lab) -> tuple[bool, str]:
    for sw in lab.networks:
        if not has_poe(lab, sw):
            continue
        for no in range(1, devcli.SWITCH_PORTS + 1):
            if port_conf(lab, sw, no)[0] == "never":
                return True, f"{sw} Fa0/{no} is set to power inline never"
    return False, "no port is set to power inline never"


def _grade_no_stray_static(lab) -> tuple[bool, str]:
    plan = _plan(lab)
    for sw in lab.networks:
        if not has_poe(lab, sw):
            continue
        on = devices_on(lab, plan, sw)
        for no in range(1, devcli.SWITCH_PORTS + 1):
            if port_conf(lab, sw, no)[0] == "static" and no not in on:
                return False, f"{sw} Fa0/{no} reserves power with nothing plugged in (power inline static)"
    return True, "no power is reserved on an empty port"


def _register_grades() -> None:
    from . import exercises
    exercises.register_winlab_check("poe-phones-powered", _grade_phones)
    exercises.register_winlab_check("poe-port-never", _grade_never)
    exercises.register_winlab_check("poe-no-stray-static", _grade_no_stray_static)


_register_grades()
