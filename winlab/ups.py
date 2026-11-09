"""The UPS on the workbench shelf, the lab's mains, and power cuts.

A lab has mains power (on unless the user cuts it) and at most one UPS.
Every machine, the router and each switch draw from the wall, or from one
of the UPS's outlets. "Power cut" takes the mains away from the whole lab:
whatever hangs on the wall stops there and then, a real hard stop of its
QEMU (no ACPI, nothing flushed), so Windows finds at its next start what a
real power cut leaves: Kernel-Power 41, EventLog 6008 "the previous system
shutdown was unexpected", maybe a volume marked dirty for chkdsk. A switch
without power takes its ports down on the router's switch (the router runs
the switches); the router without power is the router's QEMU stopping,
with every switch in it.

What hangs on the UPS keeps running on its battery. The battery drains by
the load: a rough watt model of what runs on its outlets (a machine draws
by its processors and memory; the router and a switch a little), shown on
the UPS's front panel with the minutes left. Too much load on battery is
an overload: the UPS drops its outlets at once. An empty battery drops
them too. "Power back" brings the mains back; nothing restarts by itself
(machines whose firmware says "stay off after a power loss"); the battery
recharges, faster than a real one.

The UPS talks to one machine over a USB cable, the way a desk UPS does: a
USB HID Power Device (usage page 0x84, a UPS with its battery), so Windows
lists a battery of its own (Win32_Battery, the battery icon) and acts on
it with its power plan: the low and critical battery levels and actions
the student sets in Power Options or powercfg. QEMU has no such device, so
winlab is the device: a usb-redir port on the machine's USB controller,
behind a QEMU chardev socket on 127.0.0.1, and this module on the other
end speaks the usbredir protocol and answers as the UPS (its descriptors,
its reports). Nothing of this PC reaches the machine: no host USB device,
only the UPS winlab draws.

The UPS also has a network management card, as an office UPS does: its
own port, cabled to a switch, with its own address on that VLAN. The card
is a small OpenWrt VM (winlab/openwrt.py) running Network UPS Tools: upsd
answers NUT clients on port 3493, NUT's CGI pages show the UPS's status,
and LuCI's Services > Network UPS Tools is where the student sets up the
users, the monitor (upsmon: what shuts down and when) and its
notifications. The card's NUT driver (dummy-ups) reads the UPS from a file
winlab rewrites from this battery model every few seconds (card_push), so
upsc ups@<card> says what the front panel says. The card comes as NUT
ships: no users, no monitor; only the driver for its own UPS is defined.

Everything lives beside the lab's disks (var/labs/<lab>/ups.json): the
UPS, what is plugged into it, the mains, the battery, its log and the
power-cut drill, so it outlasts a restart of the desktop. The history of
each machine's power goes to the power history (winlab/power.py) too.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from pathlib import Path

from . import naming, paths, state

FILE = "ups.json"
USB_FILE = "ups-usb.json"   # in the machine's folder: the port of its UPS chardev
CHARDEV = "wlups"
ROUTER = "router"           # the router's plug (its QEMU, the fabric)
NET = "net:"                # a switch's plug: net:<switch>
TICK = 2.0
RECHARGE_MIN = 40.0         # empty to full; a real UPS takes hours
MAX_LOG = 120
MODELS = {
    "650": {"title": "UPS 650", "va": 650, "watts": 390, "wh": 36, "outlets": 4},
    "1500": {"title": "UPS 1500", "va": 1500, "watts": 900, "wh": 108, "outlets": 6},
}
DEFAULT_MODEL = "1500"


class UpsError(Exception):
    pass


# ------------------------------------------------------------------ records
def _path(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("mains", True)
    data.setdefault("plugs", [])
    data.setdefault("charge", 1.0)
    data.setdefault("log", [])
    return data


def _write(lab_name: str, data: dict) -> None:
    state.write_json(_path(lab_name), data, end="\n")


_LOCK = threading.RLock()


def _update(lab_name: str, fn):
    with _LOCK:
        data = load(lab_name)
        out = fn(data)
        _write(lab_name, data)
        return out


def _log(data: dict, what: str, when: float | None = None) -> None:
    data["log"].append({"t": round(when or time.time(), 1), "what": what})
    del data["log"][:-MAX_LOG]


def model(data: dict) -> dict:
    return MODELS.get(str(data.get("model") or DEFAULT_MODEL), MODELS[DEFAULT_MODEL])


# ------------------------------------------------------------------ the load
def node_watts(node) -> int:
    """A rough draw: a device (printer, NAS, phone) a little; a computer by
    its processors and memory."""
    from . import appliance
    if appliance.device_of(node):
        return 12
    return int(round(16 + 7 * node.cpus + 3 * node.memory_mb / 1024))


ROUTER_W, SWITCH_W = 18, 9


def switches(lab) -> list[str]:
    """The physical switches: a VLAN of a switch is not a box of its own."""
    return sorted(nid for nid, net in lab.networks.items() if net.home == nid)


def keys(lab) -> list[str]:
    # A device's own VM (an AP, this UPS's card) has no power cord of its own.
    return [n.id for n in lab.node_list() if not n.vars.get("devvm")] + [ROUTER] + [NET + s for s in switches(lab)]


def name_of(lab, key: str) -> str:
    if key == ROUTER:
        from . import devcli
        return devcli.hostname(lab, devcli.ROUTER)
    if key.startswith(NET):
        from . import devcli
        return devcli.hostname(lab, f"sw:{key[len(NET):]}")
    return naming.display(lab, key)


def draws(lab, key: str, running: set[str]) -> int:
    """What a plug draws now: nothing when it is off."""
    if key == ROUTER:
        return ROUTER_W if "fabric" in running else 0
    if key.startswith(NET):
        return SWITCH_W if "fabric" in running else 0
    node = lab.nodes.get(key)
    return node_watts(node) if node is not None and key in running else 0


def rated(lab, key: str) -> int:
    """What it draws when it runs, for the panel."""
    if key == ROUTER:
        return ROUTER_W
    if key.startswith(NET):
        return SWITCH_W
    node = lab.nodes.get(key)
    return node_watts(node) if node is not None else 0


def load_watts(lab, data: dict, running: set[str]) -> int:
    if not data.get("fitted") or data.get("dead"):
        return 0
    return sum(draws(lab, k, running) for k in data["plugs"])


def output_on(data: dict) -> bool:
    """The UPS's outlets have power: mains through it, or its battery; not
    when its ON/OFF button switched its output off."""
    return (bool(data.get("fitted")) and not data.get("dead") and not data.get("off")
            and (data["mains"] or data["charge"] > 0))


def powered(data: dict, key: str) -> bool:
    if key in data["plugs"] and data.get("fitted"):
        return output_on(data) and key not in data.get("outlets_off", [])
    return bool(data["mains"])


def on_battery(data: dict, now: float | None = None) -> bool:
    """It runs its outlets from the battery: a power cut, or its self-test."""
    return bool(data.get("fitted")) and not data.get("off") and (
        not data["mains"] or float((data.get("test") or {}).get("until") or 0) > (now or time.time()))


def minutes_left(data: dict, load_w: float) -> float | None:
    if load_w <= 0:
        return None
    return data["charge"] * model(data)["wh"] / load_w * 60


def advance(data: dict, load_w: float, dt: float) -> None:
    """The battery over dt seconds: it charges on mains, drains by the load
    on battery."""
    if dt <= 0 or not data.get("fitted"):
        return
    if data["mains"] and not on_battery(data):
        data["charge"] = min(1.0, data["charge"] + dt / (RECHARGE_MIN * 60))
    elif not data.get("dead"):
        data["charge"] = max(0.0, data["charge"] - load_w * dt / 3600 / model(data)["wh"])


# ------------------------------------------------------------------ its front panel
# The buttons of a UPS's front panel and what its network card can switch:
# the output on and off (everything on its outlets loses power at once, as
# with the real button), a self-test (it runs on its battery for a few
# seconds while the mains stay, and fails when the battery cannot carry the
# load), the alarm's mute, and one outlet off and on.
TEST_SECONDS = 10.0
TEST_MIN_CHARGE = 0.25


def switch(lab, on: bool, running: set[str] | None = None) -> str:
    running = state.running(lab.name) if running is None else running

    def go(d):
        if not d.get("fitted"):
            raise UpsError("there is no UPS on the bench")
        if bool(d.get("off")) == (not on):
            raise UpsError(f"the UPS is {'on' if on else 'off'} already")
        d["off"] = not on
        d.pop("test", None)
        if on and d["mains"]:
            d["dead"] = False
        _log(d, "the UPS's output switched " + ("on: its outlets have power" if on else "off with its ON/OFF button"))
    _update(lab.name, go)
    if not on:
        return "the UPS is off: whatever runs on its outlets loses power" + _settle(lab, running)
    return "the UPS is on: its outlets have power; machines stay off until you power them on" + _relight(lab)


def self_test(lab, now: float | None = None) -> str:
    now = time.time() if now is None else now

    def go(d):
        if not d.get("fitted") or d.get("off") or d.get("dead"):
            raise UpsError("the UPS must be on to test itself")
        if not d["mains"]:
            raise UpsError("it is on battery already: a self-test needs the mains")
        if on_battery(d, now):
            raise UpsError("a self-test is running")
        d["test"] = {"until": round(now + TEST_SECONDS, 1), "from": round(d["charge"], 3)}
        _log(d, "self-test: the UPS runs on its battery for a few seconds", now)
    _update(lab.name, go)
    return "self-test: on battery for a few seconds, then the UPS says whether its battery passed"


def mute(lab, on: bool) -> str:
    def go(d):
        if not d.get("fitted"):
            raise UpsError("there is no UPS on the bench")
        d["mute"] = bool(on)
        _log(d, "alarm muted" if on else "alarm on again")
    _update(lab.name, go)
    return "the UPS's alarm is muted" if on else "the UPS's alarm sounds again on battery"


def outlet(lab, key: str, on: bool, running: set[str] | None = None) -> str:
    key = _key(lab, key)
    running = state.running(lab.name) if running is None else running

    def go(d):
        if key not in d["plugs"]:
            raise UpsError(f"{name_of(lab, key)} is not on an outlet of the UPS")
        off = set(d.get("outlets_off", []))
        off = off - {key} if on else off | {key}
        d["outlets_off"] = sorted(off)
        _log(d, f"outlet of {name_of(lab, key)} switched {'on' if on else 'off'}")
    _update(lab.name, go)
    if not on:
        return f"{name_of(lab, key)}'s outlet is off" + _settle(lab, running)
    return f"{name_of(lab, key)}'s outlet has power again" + _relight(lab)


def _relight(lab) -> str:
    """Switches that went dark and have power again light up (the router
    runs)."""
    data = load(lab.name)
    if "fabric" not in state.running(lab.name):
        return ""
    lit = [s for s in data.get("dark", []) if powered(data, NET + s) and _switch_ports(lab, s, True)]
    if lit:
        def note(d):
            d["dark"] = [s for s in d.get("dark", []) if s not in lit]
        _update(lab.name, note)
        return f"; {', '.join(name_of(lab, NET + s) for s in lit)} light up again"
    return ""


def test_step(d: dict, now: float) -> str:
    """A running self-test, at a tick: it fails at once when the battery
    is too low to carry the load, and passes when its seconds are up."""
    t = d.get("test") or {}
    if not t.get("until") or t.get("result"):
        return ""
    if d["charge"] < TEST_MIN_CHARGE:
        d["test"] = {**t, "until": 0, "result": "failed"}
        _log(d, "self-test FAILED: the battery cannot carry the load; replace the battery", now)
        return "the UPS's self-test failed: replace its battery"
    if now >= float(t["until"]):
        d["test"] = {**t, "until": 0, "result": "passed"}
        _log(d, "self-test passed: back on the mains", now)
        return "the UPS's self-test passed"
    return ""


# ------------------------------------------------------------------ the UPS on the shelf
def add(lab_name: str, pos=None, kind: str = "") -> str:
    kind = kind or DEFAULT_MODEL
    if kind not in MODELS:
        raise UpsError(f"no UPS model {kind!r}: {', '.join(MODELS)}")

    def put(data):
        if data.get("fitted"):
            raise UpsError("the lab has its UPS already: one per lab")
        data.update(fitted=True, model=kind, plugs=[], usb="", charge=1.0, dead=False)
        if pos:
            data["pos"] = [int(pos[0]), int(pos[1])]
        _log(data, f"{MODELS[kind]['title']} put on the bench")
    _update(lab_name, put)
    return (f"{MODELS[kind]['title']} on the bench ({MODELS[kind]['outlets']} outlets, "
            f"{MODELS[kind]['watts']} W): drag a machine's power plug onto it, and its USB cable to one machine")


def remove(lab, running: set[str] | None = None) -> str:
    running = state.running(lab.name) if running is None else running

    def take(data):
        if not data.get("fitted"):
            raise UpsError("there is no UPS on the bench")
        if not data["mains"] and any(draws(lab, k, running) for k in data["plugs"]):
            raise UpsError("not during a power cut: what runs on it would lose power")
        old = data.get("usb", "")
        for k in ("fitted", "model", "usb", "dead", "drill", "card"):
            data.pop(k, None)
        data["plugs"], data["charge"] = [], 1.0
        return old
    old = _update(lab.name, take)
    if old:
        _usb_detach(lab.name, old)
    return "the UPS is off the bench; everything it fed is on the wall again"


def move(lab_name: str, pos) -> None:
    def put(data):
        data["pos"] = [max(0, min(int(pos[0]), 20000)), max(0, min(int(pos[1]), 20000))]
    _update(lab_name, put)


def set_model(lab_name: str, kind: str) -> str:
    if kind not in MODELS:
        raise UpsError(f"no UPS model {kind!r}: {', '.join(MODELS)}")

    def put(data):
        if not data.get("fitted"):
            raise UpsError("there is no UPS on the bench")
        if len(data["plugs"]) > MODELS[kind]["outlets"]:
            raise UpsError(f"the {MODELS[kind]['title']} has {MODELS[kind]['outlets']} outlets: unplug some first")
        data["model"] = kind
    _update(lab_name, put)
    return f"now a {MODELS[kind]['title']}"


def plug(lab, key: str, running: set[str] | None = None) -> str:
    """A power cord into an outlet of the UPS. During a power cut a running
    machine pulled off the wall loses power on the way."""
    key = _key(lab, key)
    running = state.running(lab.name) if running is None else running

    def put(data):
        if not data.get("fitted"):
            raise UpsError("there is no UPS on the bench: drag one from the shelf")
        if key in data["plugs"]:
            raise UpsError(f"{name_of(lab, key)} is plugged into the UPS already")
        if len(data["plugs"]) >= model(data)["outlets"]:
            raise UpsError(f"every outlet of the {model(data)['title']} is taken")
        data["plugs"].append(key)
        _log(data, f"{name_of(lab, key)} plugged into the UPS")
    _update(lab.name, put)
    msg = f"{name_of(lab, key)} draws from the UPS"
    if not load(lab.name)["mains"]:
        msg += _settle(lab, running)
    return msg


def unplug(lab, key: str, running: set[str] | None = None) -> str:
    """Its cord back into the wall."""
    key = _key(lab, key)
    running = state.running(lab.name) if running is None else running

    def take(data):
        if key not in data["plugs"]:
            raise UpsError(f"{name_of(lab, key)} is not plugged into the UPS")
        data["plugs"].remove(key)
        _log(data, f"{name_of(lab, key)} back on the wall")
    _update(lab.name, take)
    msg = f"{name_of(lab, key)} is on the wall socket again"
    if not load(lab.name)["mains"]:
        msg += _settle(lab, running)
    return msg


# ------------------------------------------------------------------ the network card
CARD_ID = "upscard"
CARD_HOST = "UPS-NMC"
CARD_EVERY = 6.0          # seconds between writes of the battery state to the card


def card(lab_name: str) -> dict:
    data = load(lab_name)
    return dict(data.get("card") or {}) if data.get("fitted") else {}


def card_cable(lab, network: str) -> str:
    """The card's cable into a switch (a VLAN of it): the card takes an
    address of that subnet, kept while it fits."""
    from . import openwrt
    net = lab.networks.get(network)
    if net is None:
        raise UpsError(f"no switch or VLAN {network!r}")

    def put(d):
        if not d.get("fitted"):
            raise UpsError("there is no UPS on the bench")
        c = dict(d.get("card") or {})
        ip = c.get("ip", "")
        if not ip or c.get("network") != network:
            node = lab.nodes.get(CARD_ID)
            taken = set()
            if node is not None:  # its own old address is free for it
                lab.nodes.pop(CARD_ID)
            try:
                ip = openwrt.free_ip(lab, network, taken)
            finally:
                if node is not None:
                    lab.nodes[CARD_ID] = node
        d["card"] = {"network": network, "ip": ip}
        return ip
    ip = _update(lab.name, put)
    card_vm(lab)
    return f"the UPS's network card -> {network}: {ip} (its pages: http://{ip}/ from a browser on a lab PC)"


def card_unplug(lab) -> str:
    def put(d):
        if not (d.get("card") or {}).get("network"):
            raise UpsError("the UPS's network card has no cable")
        d["card"] = {"network": "", "ip": d["card"].get("ip", "")}
    _update(lab.name, put)
    card_vm(lab)
    return "the cable is out of the UPS's network card"


def card_vm(lab) -> None:
    """The card's OpenWrt VM in lab.nodes while its cable is in."""
    from . import openwrt
    c = card(lab.name)
    old = lab.nodes.get(CARD_ID)
    if old is not None and openwrt.role_of(old) == "ups":
        del lab.nodes[CARD_ID]
    if c.get("network") in lab.networks and c.get("ip") and CARD_ID not in lab.nodes:
        lab.nodes[CARD_ID] = openwrt.device_vm(CARD_ID, "ups", c["network"], c["ip"], CARD_HOST)


card_push = None   # (lab_name, script) -> None: a seam for the tests


def _push_card(lab, data: dict, running: set[str]) -> bool:
    """The battery model into the card's NUT driver file."""
    from . import openwrt
    if CARD_ID not in running or not (data.get("card") or {}).get("network"):
        return False
    script = openwrt.write_ups_cmd(hid_state(lab, data, running))
    try:
        if card_push is not None:
            card_push(lab.name, script)
        else:
            openwrt.run(lab.name, CARD_ID, script, timeout=15)
    except openwrt.OpenWrtError:
        return False
    return True


def _key(lab, key: str) -> str:
    key = str(key or "").strip()
    if key in ("fabric", "router"):
        return ROUTER
    if key.startswith(NET):
        if key[len(NET):] not in switches(lab):
            raise UpsError(f"no switch {key[len(NET):]!r}")
        return key
    nid = naming.resolve(lab, key)
    if nid not in lab.nodes:
        raise UpsError(f"no machine {key!r}")
    return nid


# ------------------------------------------------------------------ the USB cable
def usb_cable(lab, node_id: str) -> str:
    """The UPS's USB cable into one machine: it sees a UPS battery."""
    from . import appliance
    node_id = naming.resolve(lab, node_id)
    node = lab.nodes.get(node_id)
    if node is None:
        raise UpsError(f"no machine {node_id!r}")
    if appliance.device_of(node):
        raise UpsError(f"{naming.display(lab, node_id)} is a device: it has no USB port for a UPS")
    if not has_usbredir():
        raise UpsError("this PC's QEMU has no usb-redir device, so a machine cannot take the UPS's USB cable; "
                       "the outlets still work")
    data = load(lab.name)
    if not data.get("fitted"):
        raise UpsError("there is no UPS on the bench")
    old = data.get("usb", "")
    if old == node_id:
        raise UpsError(f"the USB cable is in {naming.display(lab, node_id)} already")

    def put(d):
        d["usb"] = node_id
        _log(d, f"USB cable into {naming.display(lab, node_id)}")
    _update(lab.name, put)
    if old:
        _usb_detach(lab.name, old)
    live = _usb_attach(lab.name, node_id)
    return (f"the UPS's USB cable is in {naming.display(lab, node_id)}: "
            + ("Windows finds a UPS battery now (Device Manager, Batteries)" if live else
               "it finds the UPS battery when it starts"))


def usb_unplug(lab) -> str:
    data = load(lab.name)
    old = data.get("usb", "")
    if not old:
        raise UpsError("the UPS's USB cable is in no machine")

    def take(d):
        d["usb"] = ""
        _log(d, "USB cable out")
    _update(lab.name, take)
    _usb_detach(lab.name, old)
    return f"the USB cable is out of {naming.display(lab, old)}: it no longer sees the UPS"


def usb_args(lab_name: str, node_id: str, node_dir: Path, free_port) -> list[str]:
    """The machine's end of the USB cable, when it is cabled at power-on: a
    usb-redir port on its USB controller, its chardev a loopback socket
    winlab connects to."""
    data = load(lab_name)
    port_file = node_dir / USB_FILE
    if not data.get("fitted") or data.get("usb") != node_id or not has_usbredir():
        port_file.unlink(missing_ok=True)
        return []
    port = free_port()
    node_dir.mkdir(parents=True, exist_ok=True)
    port_file.write_text(json.dumps({"port": port}) + "\n", encoding="utf-8")
    return ["-chardev", f"socket,id={CHARDEV},host=127.0.0.1,port={port},server=on,wait=off",
            "-device", f"usb-redir,chardev={CHARDEV},id={CHARDEV},bus=xhci.0"]


def usb_port(lab_name: str, node_id: str) -> int:
    try:
        return int(json.loads((paths.lab_dir(lab_name) / node_id / USB_FILE).read_text(encoding="utf-8"))["port"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0


qmp_class = None   # a seam for the tests


def _usb_attach(lab_name: str, node_id: str) -> bool:
    """Plugged into a running machine: the port added over QMP."""
    qport = state.qmp_port(lab_name, node_id)
    if not qport:
        return False
    from .qmp import Qmp, QmpError
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    try:
        with (qmp_class or Qmp)(qport) as mon:
            mon.call("chardev-add", id=CHARDEV, backend={"type": "socket", "data": {
                "addr": {"type": "inet", "data": {"host": "127.0.0.1", "port": str(port)}},
                "server": True, "wait": False}})
            mon.call("device_add", driver="usb-redir", chardev=CHARDEV, id=CHARDEV, bus="xhci.0")
    except (QmpError, OSError) as exc:
        raise UpsError(f"{node_id}: the USB port did not take the cable: {exc}") from None
    d = paths.lab_dir(lab_name) / node_id
    d.mkdir(parents=True, exist_ok=True)
    (d / USB_FILE).write_text(json.dumps({"port": port}) + "\n", encoding="utf-8")
    return True


def _usb_detach(lab_name: str, node_id: str) -> None:
    (paths.lab_dir(lab_name) / node_id / USB_FILE).unlink(missing_ok=True)
    qport = state.qmp_port(lab_name, node_id)
    if not qport:
        return
    from .qmp import Qmp, QmpError
    try:
        with (qmp_class or Qmp)(qport) as mon:
            mon.call("device_del", id=CHARDEV)
            time.sleep(0.3)
            mon.call("chardev-remove", id=CHARDEV)
    except (QmpError, OSError):
        pass


_HAS: dict[str, bool] = {}


def has_usbredir() -> bool:
    """Whether this PC's QEMU was built with usb-redir (asked once)."""
    if "redir" not in _HAS:
        import subprocess
        try:
            out = subprocess.run([str(paths.qemu_exe()), "-device", "help"], capture_output=True,
                                 text=True, timeout=30).stdout
            _HAS["redir"] = '"usb-redir"' in out
        except (OSError, subprocess.SubprocessError):
            _HAS["redir"] = False
    return _HAS["redir"]


# ------------------------------------------------------------------ the mains
kill_fn = None     # seams for the tests: kill(pid), the router's runner
fabric_runner = None


def hard_stop(lab_name: str, node_id: str, why: str) -> bool:
    """Off at once, the way a machine without power stops: its QEMU ends,
    nothing in it is told."""
    from .orchestrator import _kill
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not ns.pid or not state.pid_alive(ns.pid):
        return False
    (kill_fn or _kill)(ns.pid)
    ns.pid, ns.phase = 0, "stopped"
    state.save(st)
    try:
        from . import power
        power.record(lab_name, node_id, f"lost power: {why}", "UPS" if "UPS" in why else "power cut")
    except Exception:  # noqa: BLE001 - the history is a record, not the cut
        pass
    return True


def _switch_ports(lab, sw: str, up: bool) -> str:
    """A switch losing (or getting back) its power while the router runs:
    every port of it goes down (or up) on the router's switch."""
    from . import devcli, netplan
    plan = netplan.compile_topology(lab, check_ports=False)
    lines = []
    for link in plan.links:
        net = lab.networks.get(link.network_id)
        if not link.plugged or net is None or net.home != sw or not link.fabric_iface:
            continue
        if up and devcli.held_down(lab, link):
            continue
        lines.append(f"ip link set {link.fabric_iface} {'up' if up else 'down'} 2>/dev/null || true")
    if not lines:
        return ""
    factory = fabric_runner
    if factory is None:
        from .cli import _fabric_runner as factory
    run, why = factory(lab.name)
    if not run:
        return ""
    try:
        run("\n".join(lines), timeout=40)
    except Exception:  # noqa: BLE001 - the router may just have gone
        return ""
    finally:
        close = getattr(run, "close", None)
        if close:
            close()
    return sw


def _settle(lab, running: set[str]) -> str:
    """Whatever has no power stops: machines and the router off at once,
    the switches' ports down. Returns what it says about it."""
    data = load(lab.name)
    stopped, dark = [], []
    for key in keys(lab):
        if powered(data, key):
            continue
        if key == ROUTER:
            if "fabric" in running and hard_stop(lab.name, "fabric", _why(data)):
                stopped.append(name_of(lab, key))
        elif key.startswith(NET):
            sw = key[len(NET):]
            if "fabric" in running and powered(data, ROUTER) and sw not in data.get("dark", []):
                if _switch_ports(lab, sw, False):
                    dark.append(sw)
        elif key in running and hard_stop(lab.name, key, _why(data)):
            stopped.append(name_of(lab, key))
    if dark or stopped:
        def note(d):
            d["dark"] = sorted(set(d.get("dark", [])) | set(dark))
            for k in stopped:
                _log(d, f"{k} lost power")
            if d.get("drill") and not d["drill"].get("back"):
                d["drill"].setdefault("dirty", [])
                d["drill"]["dirty"] += [k for k in _ids(lab, stopped) if k not in d["drill"]["dirty"]]
        _update(lab.name, note)
    out = ""
    if stopped:
        out += f"; {', '.join(stopped)} lost power and stopped dead"
    if dark:
        out += f"; {', '.join(name_of(lab, NET + s) for s in dark)} went dark"
    return out


def _ids(lab, names: list[str]) -> list[str]:
    by_name = {name_of(lab, k): k for k in keys(lab)}
    return [by_name.get(n, n) for n in names]


def _why(data: dict) -> str:
    if data.get("off"):
        return "the UPS was switched off"
    if data["mains"] and not data.get("dead"):
        return "its UPS outlet was switched off" if data.get("outlets_off") else "the UPS dropped its outlets"
    if data["mains"]:
        return "the UPS dropped its outlets"
    if data.get("dead") == "overload":
        return "the UPS overloaded on battery"
    if data.get("dead"):
        return "the UPS battery ran out"
    return "power cut"


def cut(lab, running: set[str] | None = None) -> str:
    """The mains go: the whole lab."""
    running = state.running(lab.name) if running is None else running
    from . import labclock

    def go(d):
        if not d["mains"]:
            raise UpsError("the power is off already: Power back brings it")
        d["mains"] = False
        d["t"] = time.time()
        d["cut"] = {"t": round(time.time(), 1), "lab_t": round(labclock.load(lab.name).now(time.time()), 1)}
        _log(d, "power cut: the mains are gone")
    _update(lab.name, go)
    data = load(lab.name)
    on_ups = [name_of(lab, k) for k in data["plugs"] if draws(lab, k, running)] if data.get("fitted") else []
    msg = "power cut" + _settle(lab, running)
    if on_ups:
        mins = minutes_left(data, load_watts(lab, data, running))
        msg += (f"; on the UPS's battery: {', '.join(on_ups)}"
                + (f", about {int(mins)} min left at {load_watts(lab, data, running)} W" if mins else ""))
    elif not any(lab.nodes) or not running:
        msg += "; nothing was running"
    return msg


def back(lab) -> str:
    """The mains come back: nothing restarts by itself; the switches the
    router still runs light up again; the battery recharges."""
    def go(d):
        if d["mains"]:
            raise UpsError("the mains are on")
        d["mains"], d["dead"] = True, False
        d["t"] = time.time()
        _log(d, "power back: mains on" + (", the UPS recharges" if d.get("fitted") else ""))
        if d.get("drill") and not d["drill"].get("back"):
            d["drill"]["back"] = round(time.time(), 1)
        dark, d["dark"] = d.get("dark", []), []
        return dark
    dark = _update(lab.name, go)
    lit = [s for s in dark if "fabric" in state.running(lab.name) and _switch_ports(lab, s, True)]
    return ("power back: machines stay off until you power them on (as a server set to "
            "'stay off after a power loss' does)" + (f"; {', '.join(lit)} light up again" if lit else ""))


def blocked(lab, nodes: list[str]) -> str:
    """Why these cannot power on now ('' when they can): no power at their plug."""
    data = load(lab.name)
    if data["mains"] and not data.get("off") and not data.get("outlets_off") and not data.get("dead"):
        return ""
    keys_ = list(nodes) + ([ROUTER] if "fabric" not in state.running(lab.name) else [])
    dead = [name_of(lab, ROUTER if k == "fabric" else k) for k in keys_ if not powered(data, ROUTER if k == "fabric" else k)]
    if not dead:
        return ""
    return (f"{'power cut' if not data['mains'] else 'no power at the UPS outlet'}: "
            f"{', '.join(dead)} {'has' if len(dead) == 1 else 'have'} no power"
            + (" (the router starts with any machine)" if ROUTER in keys_ and name_of(lab, ROUTER) in dead else "")
            + ". Power back first, or plug it into the UPS")


# ------------------------------------------------------------------ the watcher
class Watcher:
    """Every TICK: the battery drains or charges, an empty battery or an
    overload drops the outlets, whatever has no power stops, the machines
    that shut themselves down on battery are noted, and the USB cable's
    machine gets the UPS's state."""

    def __init__(self, lab_fn, connect=None) -> None:
        self.lab_fn = lab_fn
        self.connect = connect          # (port) -> socket; a seam for the tests
        self.seen: set[str] = set()
        self.lab_name = ""
        self.link: UsbLink | None = None
        self.card_at = 0.0
        self._stop = threading.Event()

    def run_forever(self) -> None:
        while not self._stop.wait(TICK):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - the watcher keeps watching
                pass

    def stop(self) -> None:
        self._stop.set()
        if self.link:
            self.link.close()

    def tick(self, now: float | None = None, running: set[str] | None = None) -> dict:
        from . import labclock
        lab = self.lab_fn()
        if lab.name != self.lab_name:
            self.lab_name, self.seen = lab.name, set()
            if self.link:
                self.link.close()
                self.link = None
        now = time.time() if now is None else now
        running = state.running(lab.name) if running is None else running
        paused = labclock.load(lab.name).paused
        said: list[str] = []

        def step(d):
            w = 0 if paused else load_watts(lab, d, running)
            dt = now - float(d.get("t") or now)
            d["t"] = now
            advance(d, w, min(dt, 600))
            m = model(d)
            said_t = test_step(d, now)
            if said_t:
                said.append(said_t)
            if d.get("fitted") and d["mains"] and on_battery(d, now) and w > m["watts"]:
                d["test"] = {**d["test"], "until": 0, "result": "failed"}
                _log(d, f"self-test FAILED: overload ({w} W on a {m['watts']} W UPS)", now)
                said.append("the UPS's self-test failed: overload")
            elif d.get("fitted") and on_battery(d, now) and not d.get("dead"):
                if w > m["watts"]:
                    d["dead"] = "overload"
                    _log(d, f"overload on battery ({w} W on a {m['watts']} W UPS): the outlets are off", now)
                elif d["charge"] <= 0:
                    d["dead"] = "empty"
                    _log(d, "the battery is empty: the outlets are off", now)
            # Plugged machines that stopped by themselves on battery: shut down.
            on_ups = {k for k in d["plugs"] if k in lab.nodes}
            for k in sorted((self.seen & on_ups) - running):
                if not d["mains"] and not d.get("dead"):
                    _log(d, f"{name_of(lab, k)} shut itself down on battery", now)
                    said.append(f"{k} shut down on battery")
                    if d.get("drill") and not d["drill"].get("back"):
                        d["drill"].setdefault("graceful", [])
                        if k not in d["drill"]["graceful"]:
                            d["drill"]["graceful"].append(k)
            self.seen = on_ups & running
        _update(lab.name, step)
        data = load(lab.name)
        if not data["mains"] or data.get("dead") or data.get("off") or data.get("outlets_off"):
            msg = _settle(lab, running)
            if msg:
                said.append(msg.lstrip("; "))
        self._usb(lab, data, running)
        if data.get("fitted") and now - self.card_at >= CARD_EVERY:
            self.card_at = now
            _push_card(lab, data, running)
        return {"said": said, "charge": data["charge"], "mains": data["mains"]}

    def _usb(self, lab, data: dict, running: set[str]) -> None:
        nid = data.get("usb", "") if data.get("fitted") else ""
        port = usb_port(lab.name, nid) if nid and nid in running else 0
        if self.link and (not port or self.link.port != port or not self.link.alive()):
            self.link.close()
            self.link = None
        if port and self.link is None:
            try:
                sock = (self.connect or _connect)(port)
            except OSError:
                return
            self.link = UsbLink(sock, port, UpsDevice())
            self.link.start()
        if self.link:
            self.link.device.update(hid_state(lab, data, running))


def _connect(port: int) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=3)


_WATCH: dict[str, Watcher] = {}


def watch_desktop(dash_fn) -> None:
    """The desktop's watcher, on its own thread, for whichever lab it shows."""
    if "desktop" in _WATCH:
        return
    w = Watcher(lambda: dash_fn().lab)
    _WATCH["desktop"] = w
    threading.Thread(target=w.run_forever, daemon=True, name="winlab-ups").start()


def usb_linked() -> bool:
    w = _WATCH.get("desktop")
    return bool(w and w.link and w.link.device.configured)


# ------------------------------------------------------------------ what the machine is told
def hid_state(lab, data: dict, running: set[str]) -> dict:
    w = load_watts(lab, data, running)
    m = model(data)
    pct = int(round(data["charge"] * 100))
    mins = minutes_left(data, w)
    on_batt = on_battery(data) and output_on(data)  # a power cut, or its self-test
    return {"percent": pct, "runtime": int(mins * 60) if mins is not None else 0xFFFF,
            "ac": bool(data["mains"]) and not on_batt, "charging": bool(data["mains"]) and not on_batt and pct < 100,
            "discharging": on_batt, "full": pct >= 100, "load": min(255, int(round(100 * w / m["watts"]))),
            "overload": w > m["watts"], "imminent": on_batt and (pct <= 3 or (mins is not None and mins < 1)),
            "model": m["title"], "volts": 13 if data["mains"] else 12}


# ------------------------------------------------------------------ the USB HID power device
# HID report descriptor items (HID 1.11, 6.2.2): prefix = tag | type | size.
def _short(prefix: int, value: int, signed: bool = False) -> bytes:
    if signed:
        size = 1 if -128 <= value <= 127 else 2 if -32768 <= value <= 32767 else 4
    else:
        size = 1 if 0 <= value <= 0xFF else 2 if value <= 0xFFFF else 4
    code = {1: 1, 2: 2, 4: 3}[size]
    return bytes([prefix | code]) + value.to_bytes(size, "little", signed=signed and value < 0)


def UP(page): return _short(0x04, page)                       # Usage Page
def U(usage): return _short(0x08, usage)                       # Usage (on the page in effect)
def UX(page, usage): return bytes([0x0B]) + struct.pack("<HH", usage, page)  # Usage, page and all
def COLL(kind): return bytes([0xA1, kind])                     # 0 physical, 1 application, 2 logical
def END(): return b"\xC0"
def LMIN(v): return _short(0x14, v, signed=True)
def LMAX(v): return _short(0x24, v, signed=True)
def RSIZE(v): return _short(0x74, v)
def RCOUNT(v): return _short(0x94, v)
def RID(v): return _short(0x84, v)
def UNIT(v): return _short(0x64, v) if v else b"\x65\x00"
def UEXP(v): return bytes([0x55, v & 0x0F])
def INPUT(f): return bytes([0x81, f])
def FEATURE(f): return bytes([0xB1, f])


CONST, DATA, VOLATILE = 0x03, 0x02, 0x82   # Cnst,Var,Abs / Data,Var,Abs / Data,Var,Abs,Vol
PD, BAT = 0x84, 0x85                        # the Power Device and Battery System pages
# Report ids
R_STRINGS, R_BATINFO, R_MODE, R_CAPS, R_LIMITS, R_GRAN, R_CHARGE, R_RUNTIME, R_STATUS, R_LOAD, R_VOLT, R_DELAY = range(1, 13)
STATUS_BITS = [(BAT, 0x44), (BAT, 0x45), (BAT, 0xD0), (BAT, 0xD1), (BAT, 0x42), (BAT, 0x43), (BAT, 0x4B), (BAT, 0x46),
               (PD, 0x69), (PD, 0x65), (PD, 0x68)]   # charging, discharging, AC present, battery present,
# below the remaining capacity limit, remaining time limit expired, need replacement, fully charged;
# shutdown imminent, overload, shutdown requested
VOLT_UNIT = 0x00F0D121      # SI linear: cm^2 g s^-3 A^-1, with exponent 7: volts
SECONDS = 0x1001


def report_descriptor() -> bytes:
    """A UPS (Power Device page, usage UPS) whose Power Summary carries its
    battery the way a desk UPS reports it to Windows' HID UPS battery
    driver: capacities in percent, the run time in seconds, the status
    bits, the strings."""
    status_usages = b"".join(UX(p, u) for p, u in STATUS_BITS)
    return b"".join([
        UP(PD), U(0x04), COLL(1),
        U(0x24), COLL(0),                                   # Power Summary
        RID(R_STRINGS), UP(PD), U(0xFE), U(0xFF), U(0xFD), LMIN(0), LMAX(255), RSIZE(8), RCOUNT(3), FEATURE(CONST),
        RID(R_BATINFO), UP(BAT), U(0x89), U(0x8F), U(0x8B), RCOUNT(3), FEATURE(CONST),
        RID(R_MODE), U(0x2C), RCOUNT(1), FEATURE(CONST),
        RID(R_CAPS), U(0x83), U(0x67), LMAX(100), RCOUNT(2), FEATURE(CONST),
        RID(R_LIMITS), U(0x8C), U(0x29), RCOUNT(2), FEATURE(DATA),
        RID(R_GRAN), U(0x8D), U(0x8E), RCOUNT(2), FEATURE(CONST),
        RID(R_CHARGE), U(0x66), RCOUNT(1), INPUT(DATA), U(0x66), FEATURE(VOLATILE),
        RID(R_RUNTIME), UNIT(SECONDS), UEXP(0), U(0x68), LMAX(65535), RSIZE(16), RCOUNT(1), INPUT(DATA),
        U(0x68), FEATURE(VOLATILE), UNIT(0),
        RID(R_STATUS), UP(PD), U(0x02), COLL(2), LMIN(0), LMAX(1), RSIZE(1), RCOUNT(len(STATUS_BITS)),
        status_usages, INPUT(DATA), status_usages, FEATURE(VOLATILE),
        RCOUNT(16 - len(STATUS_BITS)), INPUT(CONST), FEATURE(CONST), END(),
        RID(R_LOAD), UP(PD), U(0x35), LMIN(0), LMAX(255), RSIZE(8), RCOUNT(1), INPUT(DATA), U(0x35), FEATURE(VOLATILE),
        RID(R_VOLT), U(0x40), U(0x30), UNIT(VOLT_UNIT), UEXP(7), LMAX(255), RCOUNT(2), FEATURE(VOLATILE), UNIT(0), UEXP(0),
        RID(R_DELAY), U(0x57), LMIN(-1), LMAX(32767), RSIZE(16), RCOUNT(1), FEATURE(DATA),
        END(), END(),
    ])


VENDOR, PRODUCT = 0x1209, 0x0001     # the pid.codes test VID/PID: no real maker's id
STRINGS = {1: "winlab", 2: "winlab UPS", 3: "WLUPS0001", 4: "PbAc", 5: "winlab lab equipment"}
EP_IN = 0x81


def _string(i: int, text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return bytes([2 + len(raw), 3]) + raw


def descriptors(product: str = "") -> dict:
    rd = report_descriptor()
    device = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0110, 0, 0, 0, 64, VENDOR, PRODUCT, 0x0100, 1, 2, 3, 1)
    iface = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 1, 3, 0, 0, 0)
    hid = struct.pack("<BBHBBBH", 9, 0x21, 0x0111, 0, 1, 0x22, len(rd))
    ep = struct.pack("<BBBBHB", 7, 5, EP_IN, 3, 8, 32)
    body = iface + hid + ep
    config = struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), 1, 1, 0, 0xC0, 50) + body
    strings = dict(STRINGS)
    if product:
        strings[2] = product
    return {"device": device, "config": config, "hid": hid, "report": rd,
            "strings": {0: bytes([4, 3, 0x09, 0x04]), **{i: _string(i, s) for i, s in strings.items()}}}


class UpsDevice:
    """The UPS as its USB port shows it: its descriptors, its reports, and
    the two limits Windows may write."""

    def __init__(self) -> None:
        self.st = {"percent": 100, "runtime": 0xFFFF, "ac": True, "charging": False, "discharging": False,
                   "full": True, "load": 0, "overload": False, "imminent": False, "model": "", "volts": 13}
        self.warning, self.remaining, self.delay = 20, 5, -1
        self.config = 0
        self.configured = False
        self.changed = threading.Event()

    def update(self, st: dict) -> None:
        if any(self.st.get(k) != v for k, v in st.items()):
            self.st.update(st)
            self.changed.set()

    def report(self, rid: int) -> bytes:
        s = self.st
        if rid == R_STRINGS:
            v = [2, 3, 1]
        elif rid == R_BATINFO:
            v = [4, 5, 1]
        elif rid == R_MODE:
            v = [2]            # capacities in percent
        elif rid == R_CAPS:
            v = [100, 100]
        elif rid == R_LIMITS:
            v = [self.warning, self.remaining]
        elif rid == R_GRAN:
            v = [1, 1]
        elif rid == R_CHARGE:
            v = [s["percent"]]
        elif rid == R_RUNTIME:
            return bytes([rid]) + struct.pack("<H", min(0xFFFF, max(0, s["runtime"])))
        elif rid == R_STATUS:
            low = s["percent"] <= self.remaining
            bits = [s["charging"], s["discharging"], s["ac"], True, low, low and s["discharging"], False, s["full"],
                    s["imminent"], s["overload"], False]
            return bytes([rid]) + struct.pack("<H", sum(1 << i for i, b in enumerate(bits) if b))
        elif rid == R_LOAD:
            v = [s["load"]]
        elif rid == R_VOLT:
            v = [12, s["volts"]]
        elif rid == R_DELAY:
            return bytes([rid]) + struct.pack("<h", self.delay)
        else:
            return b""
        return bytes([rid] + [max(0, min(255, int(x))) for x in v])

    def set_report(self, rid: int, data: bytes) -> bool:
        if rid == R_LIMITS and len(data) >= 3:
            self.warning, self.remaining = data[1], data[2]
            return True
        if rid == R_DELAY and len(data) >= 3:
            self.delay = struct.unpack("<h", data[1:3])[0]
            return True
        return False

    def inputs(self) -> list[bytes]:
        return [self.report(r) for r in (R_STATUS, R_CHARGE, R_RUNTIME, R_LOAD)]

    def control(self, rtype: int, req: int, value: int, index: int, length: int, data: bytes) -> tuple[int, bytes]:
        """One control transfer: (status, data in). Status 0 is success, 4 a stall."""
        d = descriptors(self.st.get("model") and f"winlab {self.st['model']}" or "")
        if rtype in (0x80, 0x81) and req == 6:              # GET_DESCRIPTOR
            kind, i = value >> 8, value & 0xFF
            got = {1: d["device"], 2: d["config"], 0x21: d["hid"], 0x22: d["report"]}.get(kind)
            if kind == 3:
                got = d["strings"].get(i)
            return (0, got[:length]) if got is not None else (4, b"")
        if rtype == 0x80 and req == 0:                      # GET_STATUS: self powered
            return 0, b"\x01\x00"[:length]
        if rtype in (0x81, 0x82) and req == 0:
            return 0, b"\x00\x00"[:length]
        if rtype & 0x60 == 0 and req in (1, 3):              # CLEAR/SET_FEATURE
            return 0, b""
        if rtype == 0xA1 and req == 1:                      # GET_REPORT
            rep = self.report(value & 0xFF)
            return (0, rep[:length]) if rep else (4, b"")
        if rtype == 0x21 and req == 9:                      # SET_REPORT
            return (0, b"") if self.set_report(value & 0xFF, data) else (4, b"")
        if rtype == 0xA1 and req == 2:                      # GET_IDLE
            return 0, b"\x00"[:length]
        if rtype == 0x21 and req in (0x0A, 0x0B):           # SET_IDLE, SET_PROTOCOL
            return 0, b""
        if rtype == 0xA1 and req == 3:                      # GET_PROTOCOL: report
            return 0, b"\x01"[:length]
        return 4, b""


# usbredir (the SPICE USB redirection protocol, which QEMU's usb-redir
# device speaks): a header (type, length, id), then the packet.
HELLO, CONNECT, DISCONNECT, RESET, IFACE_INFO, EP_INFO = 0, 1, 2, 3, 4, 5
SET_CONFIG, GET_CONFIG, CONFIG_STATUS, SET_ALT, GET_ALT, ALT_STATUS = 6, 7, 8, 9, 10, 11
START_INT, STOP_INT, INT_STATUS, CANCEL = 15, 16, 17, 21
CONTROL, BULK, ISO, INTERRUPT = 100, 101, 102, 103
CAP_CONNECT_VERSION, CAP_EP_MAX_PACKET, CAP_64BIT_IDS, CAP_32BIT_BULK = 1, 4, 5, 6
OUR_CAPS = (1 << CAP_CONNECT_VERSION) | (1 << CAP_EP_MAX_PACKET) | (1 << CAP_64BIT_IDS) | (1 << CAP_32BIT_BULK)
VERSION = b"winlab ups 1"


def ep_index(ep: int) -> int:
    return ((ep & 0x80) >> 3) | (ep & 0x0F)


class UsbLink:
    """One usbredir connection to a machine's usb-redir port: the UPS
    plugged in for as long as it lasts."""

    def __init__(self, sock: socket.socket, port: int, device: UpsDevice) -> None:
        self.sock, self.port, self.device = sock, port, device
        self.wide = False          # 64-bit ids, once both hellos agree
        self.peer_caps = 0
        self.ids = 0
        self.int_on = False
        self.wlock = threading.Lock()
        self._closed = threading.Event()
        self.seen: list[tuple[int, int, int]] = []   # (request type, request, value): the tests read it

    def start(self) -> None:
        self.sock.settimeout(None)
        self.send(HELLO, VERSION.ljust(64, b"\0") + struct.pack("<I", OUR_CAPS), hello=True)
        threading.Thread(target=self._read, daemon=True, name="winlab-ups-usb").start()
        threading.Thread(target=self._feed, daemon=True, name="winlab-ups-feed").start()

    def alive(self) -> bool:
        return not self._closed.is_set()

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        try:
            self.send(DISCONNECT, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, kind: int, body: bytes, pid: int = 0, hello: bool = False) -> None:
        head = struct.pack("<IIQ" if self.wide and not hello else "<III", kind, len(body), pid)
        with self.wlock:
            self.sock.sendall(head + body)

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            got = self.sock.recv(n - len(buf))
            if not got:
                raise OSError("closed")
            buf += got
        return buf

    def _read(self) -> None:
        try:
            while not self._closed.is_set():
                if self.wide:
                    kind, length, pid = struct.unpack("<IIQ", self._recv(16))
                else:
                    kind, length, pid = struct.unpack("<III", self._recv(12))
                body = self._recv(length) if length else b""
                self.handle(kind, pid, body)
        except (OSError, struct.error):
            pass
        finally:
            self._closed.set()
            try:
                self.sock.close()
            except OSError:
                pass

    def _feed(self) -> None:
        """Input reports on the interrupt endpoint: at every change, and
        every few seconds the way a UPS keeps reporting."""
        while not self._closed.is_set():
            self.device.changed.wait(5)
            self.device.changed.clear()
            if self.int_on and not self._closed.is_set():
                try:
                    for rep in self.device.inputs():
                        self.ids += 1
                        self.send(INTERRUPT, struct.pack("<BBH", EP_IN, 0, len(rep)) + rep, self.ids)
                except OSError:
                    return

    def _connect_device(self) -> None:
        iface = struct.pack("<I", 1) + bytes([0] + [0] * 31) + bytes([3] + [0] * 31) + bytes(32) + bytes(32)
        types, interval, ifn, maxp = [255] * 32, [0] * 32, [0] * 32, [0] * 32
        for i in (0, 16):          # endpoint 0, both ways
            types[i], maxp[i] = 0, 64
        i = ep_index(EP_IN)
        types[i], interval[i], maxp[i] = 3, 32, 8
        ep = bytes(types) + bytes(interval) + bytes(ifn) + struct.pack("<32H", *maxp)
        self.send(IFACE_INFO, iface)
        self.send(EP_INFO, ep)
        self.send(CONNECT, struct.pack("<BBBBHHH", 1, 0, 0, 0, VENDOR, PRODUCT, 0x0100))

    def handle(self, kind: int, pid: int, body: bytes) -> None:
        if kind == HELLO:
            self.peer_caps = struct.unpack("<I", body[64:68])[0] if len(body) >= 68 else 0
            self.wide = bool(self.peer_caps & (1 << CAP_64BIT_IDS))
            self._connect_device()
        elif kind == CONTROL:
            ep, req, rtype, _st, value, index, length = struct.unpack("<BBBBHHH", body[:10])
            self.seen.append((rtype, req, value))
            status, data = self.device.control(rtype, req, value, index, length, body[10:])
            n = len(data) if rtype & 0x80 else (length if status == 0 else 0)
            self.send(CONTROL, struct.pack("<BBBBHHH", ep, req, rtype, status, value, index, n) + data, pid)
        elif kind == SET_CONFIG:
            self.device.config = body[0] if body else 0
            self.device.configured = self.device.config != 0
            self.send(CONFIG_STATUS, bytes([0, self.device.config]), pid)
        elif kind == GET_CONFIG:
            self.send(CONFIG_STATUS, bytes([0, self.device.config]), pid)
        elif kind == SET_ALT:
            self.send(ALT_STATUS, bytes([0, body[0], body[1]]), pid)
        elif kind == GET_ALT:
            self.send(ALT_STATUS, bytes([0, body[0], 0]), pid)
        elif kind == START_INT:
            self.int_on = True
            self.send(INT_STATUS, bytes([0, body[0] if body else EP_IN]), pid)
            self.device.changed.set()
        elif kind == STOP_INT:
            self.int_on = False
            self.send(INT_STATUS, bytes([0, body[0] if body else EP_IN]), pid)
        elif kind == RESET:
            self.device.config, self.device.configured, self.int_on = 0, False, False
        elif kind == INTERRUPT:
            ep = body[0] if body else 0
            self.send(INTERRUPT, struct.pack("<BBH", ep, 0, 0), pid)


# ------------------------------------------------------------------ the drill
DRILL_HINTS = (
    "Before the lights go out: is {server} plugged into the UPS, and is the UPS's USB cable in it? In "
    "{server}, Device Manager, Batteries lists 'HID UPS Battery' and the battery icon shows a charge; "
    "Get-CimInstance Win32_Battery says the same from PowerShell.",
    "Windows acts on a battery by its power plan: Control Panel, Power Options, Change plan settings, Change "
    "advanced power settings, Battery: Critical battery level (say 50%) and Critical battery action: Shut "
    "down. From the command line: powercfg /setdcvalueindex SCHEME_CURRENT SUB_BATTERY BATLEVELCRIT 50, "
    "powercfg /setdcvalueindex SCHEME_CURRENT SUB_BATTERY BATACTIONCRIT 3, powercfg /setactive SCHEME_CURRENT.",
    "When {server} has shut itself down (or the battery is empty), Power back, then power the machines on. "
    "On a machine that was on the wall: Event Viewer, Windows Logs, System, filter on 41 and 6008 "
    "(Kernel-Power: rebooted without cleanly shutting down; EventLog: the previous shutdown was unexpected). "
    "Save them: mkdir C:\\PowerCut; wevtutil epl System C:\\PowerCut\\system.evtx \"/q:*[System[(EventID=41 or "
    "EventID=6008)]]\". chkdsk C: /scan checks the volume the cut interrupted.",
)


def _pt(text: str) -> str:
    """A drill text in the desktop's language (content/i18n/content/<lang>/problems.json)."""
    from .content import problem_text
    return problem_text(text)


CLEAN_PS = (
    "$b = Get-WinEvent -FilterHashtable @{LogName='System'; Id=6005} -MaxEvents 1 -ErrorAction SilentlyContinue; "
    "$t = if ($b) { $b.TimeCreated.AddMinutes(-2) } else { (Get-Date).AddDays(-1) }; "
    "$d = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,6008; StartTime=$t} -ErrorAction SilentlyContinue).Count; "
    "$n = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue).Count; "
    "\"dirty=$d battery=$n\"")
EVIDENCE_PS = (
    "$f = 'C:\\PowerCut\\system.evtx'; if (-not (Test-Path $f)) { 'nofile'; return }; "
    "$b = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime; "
    "$n = @(Get-WinEvent -Path $f -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 41,6008 }).Count; "
    "\"after=$([int]((Get-Item $f).LastWriteTime -gt $b)) events=$n\"")

guest_channel = None   # (lab_name, node_id) -> channel with .run(cmd, shell, timeout) and .close()


def drill_start(lab, running: set[str] | None = None) -> dict:
    """The lights go out on purpose, with the server on the UPS ready to
    shut itself down; the record says what to grade."""
    running = state.running(lab.name) if running is None else running
    data = load(lab.name)
    if not data.get("fitted"):
        raise UpsError("put a UPS on the bench first (the shelf, UPS)")
    srv = data.get("usb", "")
    if not srv:
        raise UpsError("the drill needs the UPS's USB cable in a Windows server: plug it in on the UPS's panel")
    node = lab.nodes.get(srv)
    if node is None or not node.is_windows:
        raise UpsError(f"{name_of(lab, srv)} is not a Windows machine: the drill grades Windows' own shutdown")
    if srv not in data["plugs"]:
        raise UpsError(f"{name_of(lab, srv)} has the USB cable but draws from the wall: plug its power into the UPS")
    if srv not in running:
        raise UpsError(f"power {name_of(lab, srv)} on first")
    if not data["mains"]:
        raise UpsError("the power is off already: Power back first")

    def mark(d):
        d["drill"] = {"t": round(time.time(), 1), "server": srv, "dirty": [], "graceful": [], "hints": 0,
                      "wall": sorted(k for k in running if k in lab.nodes and k not in d["plugs"]
                                     and lab.nodes[k].is_windows)}
    _update(lab.name, mark)
    return {"ok": True, "message": "the lights go out: " + cut(lab, running)}


def drill_view(lab) -> dict:
    data = load(lab.name)
    dr = data.get("drill") or {}
    if not dr:
        return {}
    srv = dr["server"]
    wall = [k for k in dr.get("dirty", []) if k in lab.nodes and lab.nodes[k].is_windows and k != srv] or dr.get("wall", [])
    steps = [
        {"title": "The lights go out", "done": True},
        {"title": f"{name_of(lab, srv)} shuts itself down on the UPS battery",
         "done": srv in dr.get("graceful", []), "failed": srv in dr.get("dirty", [])},
        {"title": "Power back", "done": bool(dr.get("back"))},
        {"title": "Power on, read the logs" + (f" on {', '.join(name_of(lab, k) for k in wall)}" if wall else ""),
         "done": bool(dr.get("result", {}).get("ok"))},
    ]
    return {"server": srv, "wall": wall, "steps": steps, "hints": dr.get("hints", 0), "of": len(DRILL_HINTS),
            "result": dr.get("result") or {}, "shown": [_hint(lab, i, dr) for i in range(dr.get("hints", 0))]}


def _hint(lab, i: int, dr: dict) -> str:
    return _pt(DRILL_HINTS[i]).replace("{server}", name_of(lab, dr["server"]))


def drill_hint(lab) -> dict:
    def more(d):
        dr = d.get("drill")
        if not dr:
            raise UpsError("no power-cut drill runs")
        dr["hints"] = min(len(DRILL_HINTS), dr.get("hints", 0) + 1)
        return dr["hints"]
    n = _update(lab.name, more)
    return {"ok": True, "message": _hint(lab, n - 1, load(lab.name)["drill"])}


def _ask(lab_name: str, node_id: str, script: str) -> str:
    if guest_channel is not None:
        ch = guest_channel(lab_name, node_id)
    else:
        from .guestctl import GuestChannel
        st = state.load(lab_name)
        ns = st.nodes.get(node_id) if st else None
        if not ns or not ns.serial_port or not state.pid_alive(ns.pid):
            raise UpsError(f"{node_id} is not running: power it on, then check")
        ch = GuestChannel(ns.serial_port, timeout=20).connect(retries=3, delay=2)
    try:
        r = ch.run(script, shell="powershell", timeout=120)
        return (r.out if getattr(r, "ok", True) else "") or ""
    finally:
        ch.close()


def _kv(text: str) -> dict:
    return dict(p.split("=", 1) for p in (text or "").split() if "=" in p)


def drill_check(lab) -> dict:
    """Graded on the machines themselves: the server went down cleanly on
    battery (winlab saw it stop by itself, and its log has no 41 or 6008
    since it started again); a machine that was on the wall has the cut's
    41 and 6008 saved since it started again."""
    data = load(lab.name)
    dr = data.get("drill")
    if not dr:
        raise UpsError("no power-cut drill runs: Start the drill on the UPS's panel")
    if not data["mains"]:
        raise UpsError("the power is still off: Power back, power the machines on, then check")
    srv = dr["server"]
    rows = []
    try:
        got = _kv(_ask(lab.name, srv, CLEAN_PS))
    except Exception as exc:  # noqa: BLE001 - say why it could not look
        got, err = {}, str(exc)
    else:
        err = ""
    graceful = srv in dr.get("graceful", [])
    ok = graceful and got.get("dirty") == "0"
    rows.append({"name": f"{name_of(lab, srv)} shut itself down on battery", "ok": ok,
                 "detail": err or ("winlab saw it stop by itself; its System log has no 41 or 6008 since it started"
                                   if ok else "it lost power instead: the battery ran out (or the UPS overloaded) "
                                   "before Windows shut down" if srv in dr.get("dirty", []) else
                                   "it did not shut down on battery" if not graceful else
                                   f"its log has {got.get('dirty', '?')} unexpected-shutdown events since it started")})
    if got.get("battery") == "0":
        rows[-1]["detail"] += "; it does not list the UPS battery now (is the USB cable in?)"
    wall = [k for k in dr.get("dirty", []) if k in lab.nodes and lab.nodes[k].is_windows and k != srv]
    if wall:
        k = wall[0]
        try:
            ev = _kv(_ask(lab.name, k, EVIDENCE_PS))
            e = ""
        except Exception as exc:  # noqa: BLE001
            ev, e = {}, str(exc)
        ok2 = ev.get("after") == "1" and ev.get("events", "0") not in ("0", "")
        rows.append({"name": f"{name_of(lab, k)}'s unexpected shutdown, read and saved", "ok": ok2,
                     "detail": e or ("C:\\PowerCut\\system.evtx holds its 41 and 6008" if ok2 else
                                     "no C:\\PowerCut\\system.evtx yet" if not ev or "after" not in ev else
                                     "C:\\PowerCut\\system.evtx is older than the cut" if ev.get("after") != "1" else
                                     "the file has no event 41 or 6008: filter on those two")})
    res = {"ok": all(r["ok"] for r in rows), "rows": rows, "t": round(time.time(), 1)}

    def keep(d):
        if d.get("drill"):
            d["drill"]["result"] = res
    _update(lab.name, keep)
    return {"ok": True, "passed": res["ok"], "rows": rows,
            "message": "drill passed: a clean shutdown on battery, and the cut found in the logs" if res["ok"]
            else "not yet: " + "; ".join(r["name"] + ": " + r["detail"] for r in rows if not r["ok"])}


def drill_end(lab) -> str:
    def end(d):
        d.pop("drill", None)
    _update(lab.name, end)
    return "the drill is over" + ("" if load(lab.name)["mains"] else "; the power is still off: Power back brings it")


# ------------------------------------------------------------------ the panel
def view(lab, running: set[str] | None = None) -> dict:
    running = state.running(lab.name) if running is None else running
    data = load(lab.name)
    m = model(data)
    w = load_watts(lab, data, running)
    mins = minutes_left(data, w)
    fitted = bool(data.get("fitted"))
    status = ("off" if not fitted or data.get("off") else "overload" if data.get("dead") == "overload"
              else "empty" if data.get("dead") else "test" if on_battery(data) and data["mains"]
              else "online" if data["mains"] else "battery")
    return {"fitted": fitted, "model": str(data.get("model") or DEFAULT_MODEL), "title": m["title"],
            "watts": m["watts"], "va": m["va"], "wh": m["wh"], "outlets": m["outlets"],
            "pos": data.get("pos") or [40, 40], "mains": bool(data["mains"]), "status": status,
            "charge": int(round(data["charge"] * 100)), "load_w": w, "load_pct": int(round(100 * w / m["watts"])),
            "minutes": round(mins, 1) if mins is not None and fitted else None,
            "plugs": [{"key": k, "name": name_of(lab, k), "watts": rated(lab, k), "on": bool(draws(lab, k, running)),
                       "outlet": k not in data.get("outlets_off", [])}
                      for k in data["plugs"]] if fitted else [],
            "switched_off": bool(data.get("off")), "mute": bool(data.get("mute")),
            "test": (data.get("test") or {}).get("result", "running" if on_battery(data) and data["mains"] else ""),
            "usb": data.get("usb", "") if fitted else "", "usb_ok": usb_linked(),
            "powered": {k: powered(data, k) for k in keys(lab)},
            "candidates": [{"key": k, "name": name_of(lab, k), "watts": rated(lab, k)} for k in keys(lab)
                           if k not in data["plugs"]],
            "usb_candidates": [{"id": n.id, "name": naming.display(lab, n.id)} for n in lab.node_list()
                               if not _is_device(n) and not n.vars.get("devvm")],
            "card": {**card(lab.name), "running": CARD_ID in running,
                     "networks": [{"id": n.id, "home": n.home, "vlan": n.vlan_no, "cidr": n.cidr}
                                  for n in sorted(lab.networks.values(), key=lambda x: (x.home, x.vlan_no))]}
                    if fitted else {},
            "models": [{"id": k, **v} for k, v in MODELS.items()],
            "recharge_min": RECHARGE_MIN, "cut": data.get("cut") or {},
            # what the canvas draws as machines (a device's own VM is drawn as that device)
            "running": sorted(r for r in running if not (r in lab.nodes and lab.nodes[r].vars.get("devvm"))),
            "log": list(reversed(data["log"]))[:10], "drill": drill_view(lab)}


def _is_device(node) -> bool:
    from . import appliance
    return bool(appliance.device_of(node))


def act(dash, action: str, params: dict) -> dict:
    """The desktop's ups-* actions."""
    lab = dash.lab
    try:
        if action == "ups-status":
            return {"ok": True, "ups": view(lab)}
        if action == "ups-add":
            pos = None
            if "x" in params and "y" in params:
                pos = [int(params["x"]), int(params["y"])]
            msg = add(lab.name, pos, str(params.get("model") or ""))
        elif action == "ups-remove":
            msg = remove(lab)
        elif action == "ups-move":
            move(lab.name, [params.get("x", 0), params.get("y", 0)])
            return {"ok": True, "message": ""}
        elif action == "ups-model":
            msg = set_model(lab.name, str(params.get("model") or ""))
        elif action == "ups-plug":
            msg = plug(lab, str(params.get("key") or ""))
        elif action == "ups-unplug":
            msg = unplug(lab, str(params.get("key") or ""))
        elif action == "ups-usb":
            msg = usb_cable(lab, str(params.get("node") or "")) if params.get("node") else usb_unplug(lab)
        elif action == "ups-card":
            net = str(params.get("network") or "")
            msg = card_cable(lab, net) if net else card_unplug(lab)
            from .workbench import _sync
            msg += _sync(dash)
        elif action == "ups-power":
            msg = switch(lab, str(params.get("on", "")) in ("1", "true", "True"))
        elif action == "ups-test":
            msg = self_test(lab)
        elif action == "ups-mute":
            msg = mute(lab, str(params.get("on", "1")) in ("1", "true", "True"))
        elif action == "ups-outlet":
            msg = outlet(lab, str(params.get("key") or ""), str(params.get("on", "")) in ("1", "true", "True"))
        elif action == "ups-cut":
            msg = cut(lab)
        elif action == "ups-back":
            msg = back(lab)
        elif action == "ups-drill":
            return {**drill_start(lab), "ups": view(lab)}
        elif action == "ups-drill-hint":
            return drill_hint(lab)
        elif action == "ups-drill-check":
            return drill_check(lab)
        elif action == "ups-drill-end":
            msg = drill_end(lab)
        else:
            raise UpsError(f"unknown UPS action {action!r}")
    except UpsError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": True, "message": msg, "ups": view(lab)}


# ------------------------------------------------------------------ CLI
def add_cli(sub) -> None:
    p = sub.add_parser("ups", help="the lab's UPS and mains: power cut, power back, what draws from the UPS")
    p.add_argument("lab")
    p.add_argument("what", choices=["status", "add", "remove", "plug", "unplug", "usb", "cut", "back", "watch",
                                    "drill", "check", "hint", "end"])
    p.add_argument("target", nargs="?", default="", help="a machine, router or net:<switch>; for add, the model")


def run_cli(args) -> int:
    import sys
    from . import schema
    lab = schema.load(args.lab)
    try:
        if args.what == "status":
            v = view(lab)
            print(f"mains {'on' if v['mains'] else 'OFF (power cut)'}")
            if v["fitted"]:
                print(f"{v['title']}: {v['status']}, battery {v['charge']}%, load {v['load_w']} W "
                      f"({v['load_pct']}%)" + (f", {v['minutes']:.0f} min left" if v["minutes"] is not None else ""))
                for p in v["plugs"]:
                    print(f"  outlet: {p['name']} ({p['watts']} W{', running' if p['on'] else ''})")
                print(f"  USB cable: {v['usb'] or 'none'}")
            return 0
        if args.what == "watch":
            w = Watcher(lambda: schema.load(args.lab))
            print(f"watching {lab.name}'s UPS and mains; Ctrl-C to stop")
            try:
                while True:
                    for line in w.tick()["said"]:
                        print(line, flush=True)
                    time.sleep(TICK)
            except KeyboardInterrupt:
                return 0
        msg = {"add": lambda: add(lab.name, None, args.target), "remove": lambda: remove(lab),
               "plug": lambda: plug(lab, args.target), "unplug": lambda: unplug(lab, args.target),
               "usb": lambda: usb_cable(lab, args.target) if args.target else usb_unplug(lab),
               "cut": lambda: cut(lab), "back": lambda: back(lab),
               "drill": lambda: drill_start(lab)["message"], "check": lambda: drill_check(lab)["message"],
               "hint": lambda: drill_hint(lab)["message"], "end": lambda: drill_end(lab)}[args.what]()
    except UpsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(msg)
    return 0


# ------------------------------------------------------------------ its own pages
def _targets(lab) -> list:
    """The network card's LuCI and NUT pages, on its address (winlab/adminui.py)."""
    from . import adminui, openwrt
    c = card(lab.name)
    if not c.get("network") or not c.get("ip"):
        return []
    return [adminui.Target(key="ups", title="UPS network management card (OpenWrt, NUT)", host=c["ip"],
                           gui=openwrt.luci("ups"))]


def _register() -> None:
    from . import adminui
    adminui.register(targets=_targets)


_register()
