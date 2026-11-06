"""Remote power: a server's management port, and Wake-on-LAN.

A server can carry a management port (the "Management port" part, fitted
with the case open): the network port of its BMC, the small computer on
the board that keeps running while the server is off, the way iLO or iDRAC
do. It takes its own cable, usually into a switch of the management VLAN,
and its own address. The BMC itself runs on the lab's router, in a network
namespace of its own with the port's MAC and address, plugged into the
router's switch as an access port of that VLAN (render): so it answers only
inside the lab, to whatever reaches that VLAN, and never to this PC. Its web
pages are OpenBMC's own web UI (webui-vue, fetched at preparation from
winlab's release built from upstream source: winlab/openbmcui.py) on a
Redfish API that content/agent/bmc.sh answers under busybox tcpsvd: sign-in,
power state, power on / off / reset / graceful shutdown and restart, the
event log, the BMC's network port, behind the user and password on the toe
tag. Without the fetched UI the BMC serves winlab's own pages (overview,
power, a virtual console with a picture of the screen, the event log).

What the BMC asks of the server, winlab does on the machine: the BMC queues
the request in its folder on the router, the watcher here (Watcher, run by
the desktop or `winlab power <lab> watch`) collects it over the router's
serial agent and carries it out over QMP (system_reset, the power button,
a power cut, a start), then writes the outcome to the BMC's event log. The
watcher also writes back each server's power state and, when the virtual
console is open, a QMP screendump of its screen.

Wake-on-LAN: the router listens on its switch for magic packets (tcpdump,
UDP 7 and 9 and EtherType 0x0842). A packet that carries a machine's MAC and
reaches that machine's port, which means it was sent inside its VLAN (a
router does not forward broadcasts to another one), powers the machine on
when it is off. QEMU's network card cannot wake a machine by itself, nor
keep a Wake-on-LAN setting: winlab reads Windows' own setting for the card
(Get-NetAdapterPowerManagement: WakeOnMagicPacket) while the machine runs,
and a card whose setting is Disabled stays asleep, as on a real PC.

Everything winlab does here is kept in the power history (power.json in
the lab's folder) and, for grading, in /var/lib/winlab-power.log on the
router, beside the BMCs' own event logs.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets
import struct
import threading
import time
import zlib
from pathlib import Path

from . import naming, paths, state

PORT_VAR = "bmc"         # the network its management cable is in; "" fitted, no cable
IP_VAR = "bmc_ip"
TAG_VAR = "bmc_tag"      # the password printed on the toe tag
USER = "Administrator"
ROOT = "/var/lib/winlab-bmc"
POWER_LOG = "/var/lib/winlab-power.log"
WOL_LOG = "/run/winlab-wol.log"
WOL_PID = "/run/winlab-wol.pid"
FILE = "power.json"
SHELVES = ("server", "linux")
RESETS = ("On", "ForceOff", "GracefulShutdown", "ForceRestart", "PushPowerButton", "PowerCycle")
TICK = 4.0
WOL_EVERY = 45.0          # how often a running Windows machine's card setting is read
RESTART_WAIT = 600.0      # a graceful restart waits this long for the OS to shut down
WOKEN_HOLD = 90.0         # a machine just woken ignores more packets for this long
SCREEN_CHUNK = 36 * 1024
MAX_HISTORY = 300
_TAG_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_WOL_RE = re.compile(r"f{12}((?:[0-9a-f]{12}))\1{15}")


class PowerError(Exception):
    pass


# ------------------------------------------------------------------ the part
def fitted(node) -> bool:
    return PORT_VAR in node.vars


def takes_port(node) -> bool:
    """A server (Windows or Linux) has room for a management port; a PC, a
    laptop or a device does not."""
    from .workbench import _shelf_of
    return _shelf_of(node) in SHELVES


def tag(node, lab_name: str = "") -> str:
    """The password on the port's toe tag. A port fitted at the factory (a
    lab that comes with BMCs, such as the inherited company) has no tag in
    the lab file: its tag is made for this lab the first time it is read,
    and kept beside the lab's disks (var/labs/<lab>/bmc-tags.json)."""
    own = str(node.vars.get(TAG_VAR) or "")
    if own or not lab_name or not fitted(node):
        return own
    f = paths.lab_dir(lab_name) / "bmc-tags.json"
    try:
        tags = json.loads(f.read_text(encoding="utf-8"))
        tags = tags if isinstance(tags, dict) else {}
    except (OSError, ValueError):
        tags = {}
    if not tags.get(node.id):
        import os
        tags[node.id] = "".join(secrets.choice(_TAG_CHARS) for _ in range(8))
        f.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(tags, fh, indent=1)
    return str(tags[node.id])


def fit(lab, node_id: str) -> str:
    node = _node(lab, node_id)
    if not takes_port(node):
        raise PowerError(f"{naming.display(lab, node_id)} has no slot for a management port: servers have one")
    if fitted(node):
        raise PowerError(f"{naming.display(lab, node_id)} already has a management port")
    node.vars[PORT_VAR] = ""
    node.vars[TAG_VAR] = "".join(secrets.choice(_TAG_CHARS) for _ in range(8))
    return (f"a management port fitted in {naming.display(lab, node_id)}: cable it to a switch "
            f"(the management VLAN); its user and password are on the toe tag")


def remove(lab, node_id: str) -> str:
    node = _node(lab, node_id)
    if not fitted(node):
        raise PowerError(f"{naming.display(lab, node_id)} has no management port")
    for k in (PORT_VAR, IP_VAR, TAG_VAR):
        node.vars.pop(k, None)
    return f"the management port is out of {naming.display(lab, node_id)}"


def cable(lab, node_id: str, network: str, ip: str = "") -> str:
    """The management cable into a switch (a VLAN of it): the BMC takes an
    address of that subnet, from the top of it, or `ip`."""
    node = _node(lab, node_id)
    if not fitted(node):
        raise PowerError(f"{naming.display(lab, node_id)} has no management port: fit one with the case open")
    net = lab.networks.get(network)
    if net is None:
        raise PowerError(f"no switch or VLAN {network!r}")
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise PowerError(f"{ip!r} is not an IPv4 address") from None
        if addr not in net.net or ip in _used(lab, network, node_id):
            raise PowerError(f"{ip} is not a free address of {network} ({net.cidr})")
    elif node.vars.get(PORT_VAR) != network or not node.vars.get(IP_VAR):
        ip = _free_ip(lab, network, node_id)
    node.vars[PORT_VAR] = network
    if ip:
        node.vars[IP_VAR] = ip
    _fault_recabled(lab, node_id, network)
    return f"{naming.display(lab, node_id)}'s management port -> {network}: {node.vars[IP_VAR]}"


def unplug(lab, node_id: str) -> str:
    node = _node(lab, node_id)
    if not fitted(node) or not node.vars.get(PORT_VAR):
        raise PowerError(f"{naming.display(lab, node_id)}'s management port has no cable")
    node.vars[PORT_VAR] = ""
    return f"the cable is out of {naming.display(lab, node_id)}'s management port"


def _node(lab, node_id: str):
    node = lab.nodes.get(naming.resolve(lab, node_id))
    if node is None:
        raise PowerError(f"no machine {node_id!r}")
    return node


def _used(lab, network: str, but: str = "") -> set[str]:
    net = lab.networks[network]
    out = {net.router_ip}
    for n in lab.nodes.values():
        out |= {c.ip for c in n.nics if c.network == network and c.ip}
        if n.id != but and n.vars.get(PORT_VAR) == network and n.vars.get(IP_VAR):
            out.add(str(n.vars[IP_VAR]))
    out |= {str(o["ip"]) for o in lab.devices.values() if o.get("ip")}  # the access points' own (wifi.py)
    return out


def _free_ip(lab, network: str, node_id: str) -> str:
    """From .200 up (clear of the DHCP pool, .50 to .149, and of the low
    static addresses), then anywhere free."""
    hosts = [str(h) for h in lab.networks[network].net.hosts()]
    used = _used(lab, network, node_id)
    for h in hosts[199:] + hosts[150:199] + hosts[10:49]:
        if h not in used:
            return h
    raise PowerError(f"{network} has no free address for a management port")


def bmc_mac(lab_name: str, node_id: str) -> str:
    """Its own MAC, from another range than the machine's cards."""
    from .model import stable_mac
    return "02" + stable_mac(lab_name, f"{node_id}/bmc", 0)[2:]


def ports(lab, plan) -> list[dict]:
    """The BMCs with a cable, as the router builds them."""
    out = []
    for i, node in enumerate(n for n in lab.node_list() if fitted(n) and n.vars.get(PORT_VAR) in lab.networks):
        net_id = str(node.vars[PORT_VAR])
        seg = plan.segment_of(net_id)
        net = seg.network
        ip = str(node.vars.get(IP_VAR) or "")
        if not ip:
            continue
        name = naming.hostname_of(node)
        out.append({"node": node.id, "name": name, "dir": f"{ROOT}/{name.upper()}", "netns": f"bmc{i}", "veth": f"wlbmc{i}",
                    "network": net_id, "vid": seg.vid, "ip": ip, "prefix": net.prefixlen,
                    "gateway": net.router_ip if net.routed else "", "mac": bmc_mac(lab.name, node.id),
                    "mask": str(net.netmask), "cpus": int(node.cpus or 1), "memory": int(node.memory_mb or 0),
                    "auth": base64.b64encode(f"{USER}:{tag(node, lab.name)}".encode()).decode()})
    return out


# ------------------------------------------------------------------ the router
def handler_script() -> str:
    return (paths.CONTENT / "agent" / "bmc.sh").read_text(encoding="utf-8")


def render(plan) -> list[str]:
    """The router's part: the Wake-on-LAN listener on its switch, and one
    BMC per cabled management port (run at boot, and again live by push)."""
    from . import openbmcui
    bmcs = ports(plan.lab, plan)
    out = ["### remote power (winlab/power.py): Wake-on-LAN listener, server management ports",
           f"[ -f {WOL_PID} ] && kill $(cat {WOL_PID}) 2>/dev/null",
           f"tcpdump -i any -nn -tt -l -xx 'ether proto 0x0842 or udp port 9 or udp port 7' >> {WOL_LOG} 2>/dev/null &",
           f"echo $! > {WOL_PID}",
           f"for ns in $(ip netns list 2>/dev/null | awk '/^bmc[0-9]/ {{print $1}}'); do "
           f"ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $ns; done"]
    if not bmcs:
        return out + [""]
    out += ["command -v tcpsvd >/dev/null 2>&1 || apk add --no-network busybox-extras >/dev/null 2>&1 || true",
            f"mkdir -p {ROOT}",
            "cat > /usr/local/bin/winlab-bmc <<'WINLAB_BMC'", handler_script().rstrip("\n"), "WINLAB_BMC",
            "chmod 755 /usr/local/bin/winlab-bmc",
            "# OpenBMC's web UI for the BMCs, from the repository volume when it was fetched (winlab/openbmcui.py)",
            *openbmcui.router_lines()]
    for b in bmcs:
        ns, d = b["netns"], b["dir"]
        out += [f"# {b['node']}: management port {b['ip']}/{b['prefix']} on {b['network']} (VLAN {b['vid']})",
                f"mkdir -p {d}",
                f"printf '%s\\n' '{b['name']}' > {d}/name; printf '%s\\n' '{USER}' > {d}/user",
                f"printf '%s\\n' '{b['auth']}' > {d}/auth; printf '%s\\n' '{b['ip']}' > {d}/ip",
                f"printf '%s\\n' '{b['mac']}' > {d}/mac; printf '%s\\n' '{b['mask']}' > {d}/mask; "
                f"printf '%s\\n' '{b['gateway']}' > {d}/gateway",
                f"printf '%s\\n' '{b['cpus']}' > {d}/cpus; printf '%s\\n' '{b['memory']}' > {d}/memory",
                f"printf '%s\\n' {' '.join(repr(x) for x in accounts_of(plan.lab.name, b['node'])) or chr(39) * 2} "
                f"| grep . > {d}/accounts; true",
                f"ip netns add {ns}",
                f"ip link add {b['veth']} type veth peer name eth0 netns {ns}",
                f"ip link set {b['veth']} master lab0",
                f"bridge vlan del dev {b['veth']} vid 1 2>/dev/null || true",
                f"bridge vlan add dev {b['veth']} vid {b['vid']} pvid untagged",
                f"ip link set {b['veth']} up",
                f"ip -n {ns} link set lo up",
                f"ip -n {ns} link set eth0 address {b['mac']}",
                f"ip -n {ns} addr add {b['ip']}/{b['prefix']} dev eth0",
                f"ip -n {ns} link set eth0 up"]
        if b["gateway"]:
            out.append(f"ip -n {ns} route add default via {b['gateway']}")
        out.append(f"ip netns exec {ns} tcpsvd 0.0.0.0 80 /usr/local/bin/winlab-bmc {d} >/dev/null 2>&1 &")
    return out + [""]


def push(lab, runner=None) -> str:
    """The BMCs into the running router now: '' when it is off (its next
    start builds them), else a note for the user's message."""
    from . import netplan
    run, why = _runner(lab.name, runner)
    if not run:
        return ""
    try:
        run("\n".join(render(netplan.compile_topology(lab, check_ports=False))), timeout=60)
    except Exception as exc:  # noqa: BLE001 - saved either way; the next start builds it
        return f"; the router did not take it now ({exc})"
    finally:
        _close(run)
    return " (live)"


def _runner(lab_name: str, runner=None):
    if runner is not None:
        return runner()
    from .cli import _fabric_runner
    return _fabric_runner(lab_name)


def _close(run) -> None:
    close = getattr(run, "close", None)
    if close:
        close()


def _clean(text: str) -> str:
    return re.sub(r"[|\"\\<>'\n\r]", "", str(text))[:200]


def event_line(severity: str, text: str, when: float | None = None) -> str:
    return f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(when or time.time()))}|{severity}|{_clean(text)}"


# ------------------------------------------------------------------ records
def _path(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(lab_name: str, data: dict) -> None:
    state.write_json(_path(lab_name), data, end="\n")


_LOCK = threading.Lock()


def _update(lab_name: str, fn):
    with _LOCK:
        data = load(lab_name)
        out = fn(data)
        _write(lab_name, data)
        return out


def record(lab_name: str, node_id: str, what: str, by: str = "") -> dict:
    entry = {"t": round(time.time(), 1), "node": node_id, "what": what, "by": by}

    def add(data):
        data.setdefault("history", []).append(entry)
        del data["history"][:-MAX_HISTORY]
    _update(lab_name, add)
    return entry


def history(lab_name: str, node_id: str = "") -> list[dict]:
    """Newest first."""
    rows = load(lab_name).get("history", [])
    return [r for r in reversed(rows) if not node_id or r.get("node") == node_id]


def hung(lab_name: str) -> dict:
    return load(lab_name).get("hung", {})


def wol_settings(lab_name: str) -> dict:
    return load(lab_name).get("wol", {})


# ------------------------------------------------------------------ the machine
def _ns(lab_name: str, node_id: str):
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    return ns if ns and ns.pid and state.pid_alive(ns.pid) else None


def hang(lab, node_id: str, qmp=None) -> str:
    """A frozen operating system: the processors stop (QMP stop), so the
    screen, the network and the agent stop with them; only the power
    controller (a reset, a power cut) gets it back."""
    from .qmp import Qmp, QmpError
    node_id = naming.resolve(lab, node_id)
    ns = _ns(lab.name, node_id)
    if ns is None:
        raise PowerError(f"{naming.display(lab, node_id)} is off: power it on first")
    try:
        with (qmp or Qmp)(ns.qmp_port) as mon:
            mon.call("stop")
    except QmpError as exc:
        raise PowerError(str(exc)) from None

    def mark(data):
        data.setdefault("hung", {})[node_id] = time.time()
    _update(lab.name, mark)
    record(lab.name, node_id, "hung: the operating system stopped responding", "fault")
    return (f"{naming.display(lab, node_id)} hangs: its screen, its network and its agent stopped. "
            f"Reset it from its management port (or pull the plug)")


def _unhang(lab_name: str, node_id: str) -> None:
    def clear(data):
        data.get("hung", {}).pop(node_id, None)
    _update(lab_name, clear)


def carry_out(lab, node_id: str, reset: str, start, qmp=None, kill=None) -> tuple[str, str]:
    """A power request of the BMC on the machine: (severity, what happened)."""
    from .qmp import Qmp, QmpError
    from .orchestrator import _kill
    ns = _ns(lab.name, node_id)
    on = ns is not None
    try:
        if reset == "On" or (reset == "PushPowerButton" and not on):
            if on:
                return "Info", "Power on: the server is already on"
            err = start(node_id)
            return ("Critical", f"Power on failed: {err}") if err else ("Info", "Server power on: it starts")
        if not on:
            return "Info", f"{reset}: the server is off; nothing to do"
        if reset == "ForceRestart":
            with (qmp or Qmp)(ns.qmp_port) as mon:
                mon.call("system_reset")
                mon.call("cont")
            _unhang(lab.name, node_id)
            return "Info", "Server reset: it restarts now"
        if reset in ("GracefulShutdown", "PushPowerButton", "GracefulRestart"):
            with (qmp or Qmp)(ns.qmp_port) as mon:
                mon.call("system_powerdown")
            if node_id in hung(lab.name):
                return "Warning", "Power button pressed: the operating system does not respond, so it stays on"
            if reset == "GracefulRestart":
                return "Info", "Graceful restart: the operating system shuts down, then the server powers on again"
            return "Info", "Power button pressed: the operating system shuts down"
        if reset in ("ForceOff", "PowerCycle"):
            (kill or _kill)(ns.pid)
            st = state.load(lab.name)
            if st and node_id in st.nodes:
                st.nodes[node_id].pid, st.nodes[node_id].phase = 0, "stopped"
                state.save(st)
            _unhang(lab.name, node_id)
            if reset == "ForceOff":
                return "Info", "Server power off (press and hold): off at once"
            time.sleep(2)
            err = start(node_id)
            return ("Critical", f"Cold boot: off, but power on failed: {err}") if err else (
                "Info", "Cold boot: power removed, then on again")
    except QmpError as exc:
        return "Critical", f"{reset} failed: {exc}"
    return "Warning", f"{reset} is not a power action"


# ------------------------------------------------------------------ the BMC's services
# What a real BMC does beyond power, each carried out here on the machine the
# way a power request is: the BMC (bmc.sh) queues it, the watcher does it.
#   Virtual media: a disc of the lab's media shelf (never a path on this PC)
#     into the server's DVD drive, or out of it (mediashelf.insert, eject).
#   Boot override: the next boot (Once) or every boot (Continuous) from the
#     DVD, the disk or into the firmware's setup (mediashelf.set_boot; Esc
#     held through the power-on screen for BiosSetup).
#   Keystrokes from the virtual console (QMP send-key).
#   The management port's own static address.
#   Local BMC users, kept in power.json and written back at every BMC start.
# The chassis sensors are modelled from the server's load (its QEMU's CPU
# use), and say so.
BOOT_TARGETS = ("None", "Cd", "Hdd", "BiosSetup")
BOOT_ENABLED = ("Disabled", "Once", "Continuous")
BOOT_ARM_WAIT = 10.0      # a Once override is used up this long after the boot it applied to
ROLES = ("Administrator", "Operator", "ReadOnly")
_ACCOUNT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,15} (Administrator|Operator|ReadOnly) [A-Za-z0-9+/=]{4,200} (true|false)$")

# Characters to QEMU key codes: (qcode, with shift).
_QKEYS: dict[str, tuple[str, bool]] = {" ": ("spc", False), "\n": ("ret", False), "\t": ("tab", False)}
for _c in "abcdefghijklmnopqrstuvwxyz":
    _QKEYS[_c] = (_c, False)
    _QKEYS[_c.upper()] = (_c, True)
for _c in "0123456789":
    _QKEYS[_c] = (_c, False)
for _c, _k in zip(")!@#$%^&*(", "0123456789"):
    _QKEYS[_c] = (_k, True)
for _c, _k, _sh in (("-", "minus", False), ("_", "minus", True), ("=", "equal", False), ("+", "equal", True),
                    ("[", "bracket_left", False), ("{", "bracket_left", True), ("]", "bracket_right", False),
                    ("}", "bracket_right", True), (";", "semicolon", False), (":", "semicolon", True),
                    ("'", "apostrophe", False), ('"', "apostrophe", True), (",", "comma", False),
                    ("<", "comma", True), (".", "dot", False), (">", "dot", True), ("/", "slash", False),
                    ("?", "slash", True), ("\\", "backslash", False), ("|", "backslash", True),
                    ("`", "grave_accent", False), ("~", "grave_accent", True)):
    _QKEYS[_c] = (_k, _sh)
SPECIAL_KEYS = {"ctrl-alt-del": ["ctrl", "alt", "delete"], "enter": ["ret"], "esc": ["esc"], "tab": ["tab"],
                "backspace": ["backspace"], "up": ["up"], "down": ["down"], "left": ["left"], "right": ["right"],
                "f2": ["f2"], "f12": ["f12"], "delete": ["delete"]}


def qcodes(text: str) -> list[list[str]]:
    """Text as the key presses that type it on a US keyboard; a character
    with no key is left out."""
    out = []
    for ch in text:
        k = _QKEYS.get(ch)
        if k:
            out.append(["shift", k[0]] if k[1] else [k[0]])
    return out


def send_keys(lab_name: str, node_id: str, presses: list[list[str]], qmp=None) -> int:
    """Key presses on the machine's keyboard, one after another; how many."""
    from .qmp import Qmp, QmpError
    ns = _ns(lab_name, node_id)
    if ns is None:
        raise PowerError(f"{node_id} is off: its keyboard types nothing")
    try:
        with (qmp or Qmp)(ns.qmp_port) as mon:
            for keys in presses[:400]:
                mon.call("send-key", keys=[{"type": "qcode", "data": k} for k in keys])
    except (QmpError, OSError) as exc:
        raise PowerError(f"{node_id}: {exc}") from None
    return len(presses[:400])


def keys_from(arg: str) -> list[list[str]]:
    """A queued Keys request: 'k:<special>', 'u:<the text, form-encoded>'
    (the BMC's console page) or the text in hex."""
    if arg.startswith("k:"):
        k = SPECIAL_KEYS.get(arg[2:])
        return [k] if k else []
    if arg.startswith("u:"):
        from urllib.parse import unquote_plus
        return qcodes(unquote_plus(arg[2:]))
    try:
        return qcodes(bytes.fromhex(arg).decode("utf-8", "replace"))
    except ValueError:
        return []


def disc_ids(lab_name: str) -> list[dict]:
    """The media shelf's discs as the BMC's virtual media offers them: a
    short id each (what Image names), its title and its shelf reference."""
    from . import mediashelf
    out, seen = [], set()
    for d in mediashelf.discs(lab_name):
        base = re.sub(r"[^a-z0-9]+", "-", str(d["title"]).lower()).strip("-")[:32] or "disc"
        i, n = base, 2
        while i in seen:
            i, n = f"{base}-{n}", n + 1
        seen.add(i)
        out.append({"id": i, "title": _clean(d["title"])[:60], "ref": d["ref"]})
    return out


def media_image(lab_name: str, image: str) -> dict | None:
    """The shelf disc an InsertMedia names: its id, or a URL ending in it."""
    want = image.rstrip("/").rsplit("/", 1)[-1].lower()
    want = want[:-4] if want.endswith(".iso") else want
    return next((d for d in disc_ids(lab_name) if d["id"] == want), None)


def virtual_media(lab, node_id: str, image: str = "") -> tuple[str, str]:
    """InsertMedia (an image) or EjectMedia (none): (severity, what happened)."""
    from . import mediashelf
    who = naming.display(lab, node_id)
    try:
        if not image:
            r = mediashelf.eject(lab, node_id, 0)
            return "Info", (f"Virtual media: {r['title']} ejected from {who}'s DVD drive" if r
                            else "Virtual media: the DVD drive was empty")
        d = media_image(lab.name, image)
        if d is None:
            return "Warning", f"Virtual media: no disc {image} on the lab's media shelf"
        r = mediashelf.insert(lab, node_id, d["ref"], 0)
        return "Info", f"Virtual media: {r['title']} in {who}'s DVD drive"
    except mediashelf.ShelfError as exc:
        return "Warning", f"Virtual media: {exc}"


def boot_of(lab_name: str, node_id: str) -> dict:
    b = (load(lab_name).get("boot") or {}).get(node_id) or {}
    return {"target": b.get("target", "None"), "enabled": b.get("enabled", "Disabled"),
            "prev": b.get("prev", ""), "armed": float(b.get("armed") or 0)}


def set_boot_override(lab, node_id: str, target: str, enabled: str) -> tuple[str, str]:
    """BootSourceOverrideTarget and Enabled, from the BMC: the boot order
    changes now (it applies at the next power-on), BiosSetup waits for it."""
    from . import mediashelf
    node = _node(lab, node_id)
    if target not in BOOT_TARGETS or enabled not in BOOT_ENABLED:
        return "Warning", f"Boot override {target} {enabled}: not one this BMC takes"
    cur = boot_of(lab.name, node.id)
    nd = paths.lab_dir(lab.name) / node.id
    prev = cur["prev"] or mediashelf.boot_first(nd)
    try:
        if target == "None" or enabled == "Disabled":
            if cur["target"] in ("Cd", "Hdd") and cur["prev"]:
                mediashelf.set_boot(lab.name, node, cur["prev"])
            target, enabled = "None", "Disabled"
        elif target == "Cd":
            mediashelf.set_boot(lab.name, node, mediashelf.BOOT_DVD)
        elif target == "Hdd":
            mediashelf.set_boot(lab.name, node, mediashelf.BOOT_DISK)
    except mediashelf.ShelfError as exc:
        return "Warning", f"Boot override refused: {exc}"

    def keep(data):
        if target == "None":
            data.setdefault("boot", {}).pop(node.id, None)
        else:
            data.setdefault("boot", {})[node.id] = {"target": target, "enabled": enabled, "prev": prev}
    _update(lab.name, keep)
    if target == "None":
        return "Info", "Boot override cleared: the server boots as its firmware's boot order says"
    what = {"Cd": "from the DVD drive", "Hdd": "from its disk", "BiosSetup": "into the firmware's setup"}[target]
    return "Info", f"Boot override: {'the next boot' if enabled == 'Once' else 'every boot'} goes {what}"


def boot_armed(lab_name: str, node_id: str) -> None:
    """The server just started: a Once override is used up by this boot."""
    def arm(data):
        b = (data.get("boot") or {}).get(node_id)
        if b and b.get("enabled") == "Once" and not b.get("armed"):
            b["armed"] = round(time.time(), 1)
    _update(lab_name, arm)


def boot_used_up(lab, now: float | None = None) -> list[str]:
    """Once overrides whose boot has passed: the boot order goes back as it
    was. Returns the machines whose override ended."""
    from . import mediashelf
    now = time.time() if now is None else now
    done = [nid for nid, b in (load(lab.name).get("boot") or {}).items()
            if b.get("enabled") == "Once" and b.get("armed") and now - float(b["armed"]) >= BOOT_ARM_WAIT]
    for nid in done:
        b = boot_of(lab.name, nid)
        node = lab.nodes.get(nid)
        if node is not None and b["target"] in ("Cd", "Hdd") and b["prev"]:
            try:
                mediashelf.set_boot(lab.name, node, b["prev"])
            except mediashelf.ShelfError:
                pass

        def drop(data, nid=nid):
            (data.get("boot") or {}).pop(nid, None)
        _update(lab.name, drop)
    return done


def enter_setup(lab_name: str, node_id: str, reset: bool, wait: float = 30.0) -> None:
    """Esc held through the power-on screen (the firmware's setup), once the
    machine's QEMU answers; on a thread, the way a person waits at the
    screen."""
    from .orchestrator import firmware_setup

    def go():
        end = time.time() + wait
        while time.time() < end:
            ns = _ns(lab_name, node_id)
            if ns is not None and ns.qmp_port:
                if not firmware_setup(ns.qmp_port, reset=reset):
                    return
            time.sleep(1)
    threading.Thread(target=go, daemon=True).start()


def sensors(node, on: bool, cpu_pct: float) -> list[dict]:
    """The chassis sensors, modelled from the server's load: what its CPU
    temperature, inlet, fan and power draw would read at that load."""
    from . import ups
    c = max(0.0, min(100.0, float(cpu_pct or 0))) if on else 0.0
    w = ups.node_watts(node)
    return [{"id": "CPU_Temp", "name": "CPU Temp", "reading": round(36 + 0.42 * c, 1) if on else 24.0,
             "units": "Cel", "type": "Temperature"},
            {"id": "Inlet_Temp", "name": "Inlet Temp", "reading": round(22 + 0.02 * c, 1), "units": "Cel",
             "type": "Temperature"},
            {"id": "System_Fan_1", "name": "System Fan 1", "reading": round(3200 + 72 * c) if on else 0,
             "units": "RPM", "type": "Rotational"},
            {"id": "Total_Power", "name": "Total Power", "reading": round(w * (0.55 + 0.45 * c / 100)) if on else 6,
             "units": "W", "type": "Power"}]


def bmc_files(lab, b: dict, on: bool, cpu_pct: float) -> list[str]:
    """What the watcher writes into one BMC's folder every look: the
    sensors, the shelf's discs, what is in the drive, the boot override."""
    from . import mediashelf
    node = lab.nodes.get(b["node"])
    if node is None:
        return []
    d = b["dir"]

    def lines(rows: list[str]) -> str:
        return " ".join(f"'{r}'" for r in rows) or "''"
    sens = [f"{r['id']}|{_clean(r['name'])}|{r['reading']}|{r['units']}|{r['type']}" for r in sensors(node, on, cpu_pct)]
    discs = [f"{x['id']}|{x['title']}" for x in disc_ids(lab.name)]
    try:
        drive = (mediashelf.contents(lab.name, node)["drives"] or [{}])[0].get("disc")
    except Exception:  # noqa: BLE001 - a machine with no drive
        drive = None
    bo = boot_of(lab.name, node.id)
    return [f"printf '%s\\n' {lines(sens)} > {d}/sensors",
            f"printf '%s\\n' {lines(discs)} > {d}/media.list",
            f"printf '%s\\n' '{_clean(drive['title']) if drive else ''}' > {d}/vmedia",
            f"printf '%s\\n' '{bo['target']} {bo['enabled']}' > {d}/boot"]


def accounts_of(lab_name: str, node_id: str) -> list[str]:
    """The BMC's own users (beyond the toe tag's), as its accounts file
    holds them: user role auth enabled."""
    return [x for x in ((load(lab_name).get("accounts") or {}).get(node_id) or []) if _ACCOUNT_RE.match(x)]


def parse_accounts(out: str) -> dict[str, list[str]]:
    """The poll's #accounts section: per BMC folder, its accounts lines."""
    head, sep, rest = (out or "").partition("#accounts\n")
    if not sep:
        return {}
    body = rest.split("#queue\n", 1)[0]
    got: dict[str, list[str]] = {}
    for line in body.splitlines():
        name, _, acc = line.strip().partition(" ")
        if name == "-":
            continue
        if name and acc == "-":
            got.setdefault(name, [])
        elif name and _ACCOUNT_RE.match(acc):
            got.setdefault(name, []).append(acc)
    return got


# ------------------------------------------------------------------ the screen
def png(width: int, height: int, rgb: bytes) -> bytes:
    """An RGB picture as a PNG file (stdlib only)."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    stride = width * 3
    raw = b"".join(b"\x00" + rgb[y * stride:(y + 1) * stride] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def ppm_to_png(data: bytes, max_width: int = 1024) -> bytes:
    """QEMU's screendump (binary PPM, P6) as a PNG, halved until it fits."""
    m = re.match(rb"P6\s+(?:#[^\n]*\n\s*)*(\d+)\s+(\d+)\s+(\d+)\s", data)
    if not m:
        raise PowerError("the screen picture is not a PPM")
    w, h = int(m[1]), int(m[2])
    pix = data[m.end():m.end() + w * h * 3]
    step = 1
    while w // step > max_width:
        step *= 2
    if step > 1:
        rows = []
        for y in range(0, h, step):
            row = pix[y * w * 3:(y + 1) * w * 3]
            rows.append(b"".join(row[x:x + 3] for x in range(0, len(row) - 2, 3 * step)))
        pix, w, h = b"".join(rows), len(rows[0]) // 3, len(rows)
    return png(w, h, pix)


def screendump(lab_name: str, node_id: str, qmp=None) -> bytes:
    from .qmp import Qmp, QmpError
    ns = _ns(lab_name, node_id)
    if ns is None:
        raise PowerError("the server is off")
    dest = paths.lab_dir(lab_name) / node_id / "bmc-screen.ppm"
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with (qmp or Qmp)(ns.qmp_port) as mon:
            mon.call("screendump", filename=str(dest))
        data = dest.read_bytes()
    except (QmpError, OSError) as exc:
        raise PowerError(f"no picture of the screen: {exc}") from None
    finally:
        dest.unlink(missing_ok=True)
    return ppm_to_png(data)


def upload_cmds(folder: str, data: bytes) -> list[str]:
    """Commands that write a file into the router over its agent, in pieces
    each well under the length one command line can have."""
    part = f"{folder}/screen.png.part"
    cmds = [f": > {part}"]
    for i in range(0, len(data), SCREEN_CHUNK):
        cmds.append(f"printf '%s' '{base64.b64encode(data[i:i + SCREEN_CHUNK]).decode()}' | base64 -d >> {part}")
    cmds.append(f"mv {part} {folder}/screen.png && date +%s > {folder}/screen.at")
    return cmds


# ------------------------------------------------------------------ Wake-on-LAN
def parse_wol(text: str) -> tuple[list[dict], int]:
    """tcpdump -xx lines -> the magic packets in them ({ts, iface, way, mac})
    and how many characters are done with. The last packet is kept for the
    next read when its bytes are not all there yet."""
    from .livenet import _PKT_RE
    blocks: list[list] = []
    pos = 0
    for line in (text or "").splitlines(keepends=True):
        m = _PKT_RE.match(line.rstrip("\r\n"))
        if m:
            blocks.append([pos, m, ""])
        elif blocks and line.strip().startswith("0x"):
            blocks[-1][2] += re.sub(r"[^0-9a-f]", "", line.split(":", 1)[-1].lower())
        pos += len(line)
    hits, done = [], pos
    for i, (start, m, hx) in enumerate(blocks):
        found = _WOL_RE.search(hx)
        if not found and i == len(blocks) - 1:
            done = start
            break
        if found:
            mac = ":".join(found[1][k:k + 2] for k in range(0, 12, 2))
            hits.append({"ts": float(m[1]), "iface": m[2], "way": m[3], "mac": mac})
    return hits, done


def wake_targets(lab, plan, hits: list[dict]) -> list[dict]:
    """Which machine port each magic packet reached: the packet entered a
    VLAN from a machine's port ("In") or from the router ("Out" on its
    interface there), and wakes the card with that MAC in the same VLAN.
    {node, nic, mac, from, network}."""
    from . import devcli
    by_iface = {l.fabric_iface: l for l in plan.ports if l.fabric_iface}
    svis = {seg.svi: seg for seg in plan.segments.values() if seg.network.routed}
    out, seen = [], set()
    for h in hits:
        if h["iface"] in by_iface and h["way"] == "In":
            src = by_iface[h["iface"]]
            if not src.plugged:
                continue
            vid, sender = plan.segment_of(src.network_id).vid, src.node_id
        elif h["iface"] in svis and h["way"] == "Out":
            vid, sender = svis[h["iface"]].vid, "router"
        else:
            continue
        for link in plan.ports:
            if link.mac.lower() != h["mac"] or not link.plugged or link.node_id == sender:
                continue
            if plan.segment_of(link.network_id).vid != vid or devcli.held_down(lab, link):
                continue
            if (link.node_id, sender) in seen:
                continue
            seen.add((link.node_id, sender))
            out.append({"node": link.node_id, "nic": link.nic_index, "mac": h["mac"], "from": sender,
                        "network": link.network_id})
    return out


WOL_QUERY = ("Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object { "
             "$p = Get-NetAdapterPowerManagement -Name $_.Name -ErrorAction SilentlyContinue; "
             "'{0} {1}' -f $_.MacAddress, $(if ($p) { $p.WakeOnMagicPacket } else { 'Unsupported' }) }")


def parse_wol_query(text: str) -> dict[str, str]:
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(\S+)", line)
        if m:
            out[m[1].replace("-", ":").lower()] = m[2]
    return out


def wol_blocked(lab_name: str, mac: str) -> bool:
    """Windows said, the last time it ran, that this card does not wake on a
    magic packet."""
    return str(wol_settings(lab_name).get(mac.lower(), {}).get("v", "")).lower() == "disabled"


# ------------------------------------------------------------------ the watcher
class Watcher:
    """One look at the router every few seconds: the BMCs' requests and the
    magic packets, carried out on the machines; the BMCs told each server's
    power state. `start(node_id)` powers a machine on ('' or why not)."""

    def __init__(self, lab_fn, start, runner=None, channel=None, qmp=None, kill=None, running=None) -> None:
        self.lab_fn, self.start = lab_fn, start
        self._running = running
        self._runner, self._channel, self._qmp, self._kill = runner, channel, qmp, kill
        self.offset = -1  # -1: start at the end of the capture, not at packets sent before
        self.last: dict[str, bool] = {}
        self.woken: dict[str, float] = {}
        self.restart: dict[str, float] = {}  # graceful restarts waiting for the machine to be off
        self.sampled: dict[str, float] = {}
        self.lab_name = ""
        self._stop = threading.Event()
        self._sampler: threading.Thread | None = None

    def run_forever(self) -> None:
        while not self._stop.wait(TICK):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - the watcher keeps watching
                pass

    def stop(self) -> None:
        self._stop.set()

    def tick(self) -> dict:
        from . import netplan
        from .workbench import _running
        lab = self.lab_fn()
        if lab.name != self.lab_name:
            self.lab_name, self.offset, self.last = lab.name, -1, {}
        running = (self._running or _running)(lab.name)
        if "fabric" not in running:
            self.offset, self.last = -1, {}
            return {"router": False}
        plan = netplan.compile_topology(lab, check_ports=False)
        bmcs = {b["dir"].rsplit("/", 1)[1]: b for b in ports(lab, plan)}
        lines: list[str] = []
        stuck = hung(lab.name)
        for nid in [n for n in stuck if n not in running]:
            _unhang(lab.name, nid)
        changed = self._transitions(lab, running, bmcs, lines)
        self._restarts(lab, running, bmcs, lines)
        states = {name: ("On" if b["node"] in running else "Off",
                         "Critical" if b["node"] in running and b["node"] in stuck else "OK")
                  for name, b in bmcs.items()}
        for nid in boot_used_up(lab):
            if nid in {b["node"] for b in bmcs.values()}:
                lines.append(self._event(next(b for b in bmcs.values() if b["node"] == nid), "Info",
                                         "Boot override used: the boot order is back as it was"))
        for b in bmcs.values():
            lines += bmc_files(lab, b, b["node"] in running, self._cpu(lab.name, b["node"]))
        out = self._fabric(lab, self._poll_cmd(states, lines))
        if out is None:
            return {"router": False}
        self._keep_accounts(lab, bmcs, parse_accounts(out))
        queue, wol, size, start = _split(out)
        done: list[str] = []
        lines = []
        for name, reset, peer in queue:
            b = bmcs.get(name)
            if b is None:
                continue
            if reset == "Screenshot":
                self._screen(lab, b)
                continue
            if "=" in reset or reset == "EjectMedia":
                sev, what = self._service(lab, b, reset)
                lines.append(self._event(b, sev, what))
                record(lab.name, b["node"], what, f"management port, from {peer}")
                done.append(f"{b['node']}: {what}")
                continue
            bo = boot_of(lab.name, b["node"])
            if bo["target"] in ("Cd", "Hdd") and reset == "ForceRestart" and b["node"] in running:
                reset = "PowerCycle"  # the boot order is read at power-on: a cold boot applies the override
            sev, what = carry_out(lab, b["node"], reset, self.start, qmp=self._qmp, kill=self._kill)
            if sev == "Info" and bo["target"] != "None" and reset in ("On", "PowerCycle", "ForceRestart", "PushPowerButton"):
                if reset != "PushPowerButton" or b["node"] not in running:
                    boot_armed(lab.name, b["node"])
                    if bo["target"] == "BiosSetup":
                        enter_setup(lab.name, b["node"], reset=False)
                        what += "; Esc held at the power-on screen for the boot override (firmware setup)"
            if reset == "GracefulRestart" and sev == "Info" and "shuts down" in what:
                self.restart[b["node"]] = time.time()
            lines.append(self._event(b, sev, what))
            lines.append(self._log(lab, b["node"], f"{what} (BMC request from {peer})"))
            record(lab.name, b["node"], what, f"management port, from {peer}")
            done.append(f"{b['node']}: {what}")
        hits, used = parse_wol(wol)
        self.offset = start + used
        if size < self.offset:
            self.offset = 0
        for t in wake_targets(lab, plan, hits):
            what = self._wake(lab, t, running)
            if what:
                lines.append(self._log(lab, t["node"], what))
                done.append(f"{t['node']}: {what}")
        if lines:
            self._fabric(lab, "\n".join(lines))
        self._sample_soon(lab, running)
        return {"router": True, "done": done, "changed": changed}

    def _cpu(self, lab_name: str, node_id: str) -> float:
        """The server's CPU use now (its QEMU process), for the sensors."""
        ns = _ns(lab_name, node_id)
        if ns is None:
            return 0.0
        if getattr(self, "_meter", None) is None:
            from .procstats import Meter
            self._meter = Meter()
        try:
            u = self._meter.usage(ns.pid, 1)
        except Exception:  # noqa: BLE001 - a gap in the reading
            return 0.0
        return float(u.cpu_pct) if u else 0.0

    def _keep_accounts(self, lab, bmcs: dict, got: dict[str, list[str]]) -> None:
        """The BMCs' own users as their accounts files hold them now, kept so
        the next start of the BMC has them again."""
        if not got:
            return

        def keep(data):
            acc = data.setdefault("accounts", {})
            for name, rows in got.items():
                b = bmcs.get(name)
                if b is not None:
                    acc[b["node"]] = rows
        cur = load(lab.name).get("accounts") or {}
        if any(cur.get(bmcs[n]["node"]) != r for n, r in got.items() if n in bmcs):
            _update(lab.name, keep)

    def _service(self, lab, b: dict, req: str) -> tuple[str, str]:
        """A request of the BMC's other services: virtual media, the boot
        override, keystrokes, the port's address."""
        verb, _, arg = req.partition("=")
        nid = b["node"]
        try:
            if verb == "InsertMedia":
                return virtual_media(lab, nid, arg)
            if verb == "EjectMedia":
                return virtual_media(lab, nid, "")
            if verb == "Boot":
                target, _, enabled = arg.partition(":")
                return set_boot_override(lab, nid, target, enabled or "Once")
            if verb == "Keys":
                n = send_keys(lab.name, nid, keys_from(arg), qmp=self._qmp)
                return "Info", f"Virtual console: {n} key{'s' if n != 1 else ''} typed"
            if verb == "Address":
                from . import editor
                ip = arg.split("/", 1)[0]
                net = str(lab.nodes[nid].vars.get(PORT_VAR) or "")
                cable(lab, nid, net, ip)
                editor.save(lab)
                push(lab, self._runner)
                return "Info", f"Management port address set to {ip} (static)"
        except (PowerError, KeyError, ValueError) as exc:
            return "Warning", f"{verb} refused: {exc}"
        except Exception as exc:  # noqa: BLE001 - the BMC logs what went wrong
            return "Warning", f"{verb} failed: {exc}"
        return "Warning", f"{verb} is not a request this BMC makes"

    def _restarts(self, lab, running: set[str], bmcs: dict, lines: list[str]) -> None:
        """A graceful restart powers the server on again once its OS has shut
        it down; one that never goes off is given up after RESTART_WAIT."""
        by_node = {b["node"]: b for b in bmcs.values()}
        for nid, since in list(self.restart.items()):
            b = by_node.get(nid)
            if nid in running and time.time() - since < RESTART_WAIT:
                continue
            del self.restart[nid]
            if nid in running:
                what, sev = "Graceful restart: the operating system did not shut down; the server stays on", "Warning"
            else:
                err = self.start(nid)
                what, sev = ((f"Graceful restart: off, but power on failed: {err}", "Critical") if err else
                             ("Graceful restart: the server powers on again", "Info"))
                if not err and boot_of(lab.name, nid)["target"] == "BiosSetup":
                    enter_setup(lab.name, nid, reset=False)
            record(lab.name, nid, what, "management port")
            lines.append(self._log(lab, nid, what))
            if b is not None:
                lines.append(self._event(b, sev, what))

    @staticmethod
    def _poll_cmd(states: dict[str, tuple[str, str]], lines: list[str]) -> str:
        return "\n".join([f"R={ROOT}; now=$(date +%s)", *lines] + [
            'echo "#accounts"; for d in $R/*/; do d=${d%/}; [ -f "$d/auth" ] || continue; n=${d##*/}; '
            'if [ -s "$d/accounts" ]; then sed "s|^|$n |" "$d/accounts"; else echo "$n -"; fi; done'] + [
            f"[ -d $R/{d} ] && echo {p} > $R/{d}/power && echo {h} > $R/{d}/health && echo $now > $R/{d}/seen"
            for d, (p, h) in sorted(states.items())] + [
            'echo "#queue"; for q in $R/*/queue; do [ -s "$q" ] || continue; d=${q%/queue}; '
            'mv "$q" "$q.take"; sed "s|^|${d##*/} |" "$q.take"; rm -f "$q.take"; done',
            f's=$(wc -c < {WOL_LOG} 2>/dev/null | tr -d " "); s=${{s:-0}}; o=$WOL_OFFSET; [ "$s" -lt "$o" ] && o=0; '
            f'echo "#wol $s $o"; [ "$s" -gt "$o" ] && head -c "$s" {WOL_LOG} | tail -c +$((o + 1)); true'])

    def _fabric(self, lab, cmd: str) -> str | None:
        run, _why = _runner(lab.name, self._runner)
        if not run:
            return None
        try:
            return run(cmd.replace("$WOL_OFFSET", str(self.offset) if self.offset >= 0 else "$s"), timeout=60)
        except Exception:  # noqa: BLE001 - the next tick tries again
            return None
        finally:
            _close(run)

    @staticmethod
    def _event(b: dict, sev: str, what: str) -> str:
        return f"printf '%s\\n' '{event_line(sev, what)}' >> {b['dir']}/events"

    @staticmethod
    def _log(lab, node_id: str, what: str) -> str:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}|{naming.display(lab, node_id)}|{_clean(what)}"
        return f"printf '%s\\n' '{line}' >> {POWER_LOG}"

    def _transitions(self, lab, running: set[str], bmcs: dict, lines: list[str]) -> list[str]:
        """Machines that went on or off since the last look, for the history
        and their BMC's log; and a server that stopped responding."""
        out = []
        by_node = {b["node"]: b for b in bmcs.values()}
        stuck = hung(lab.name)
        for node in lab.node_list():
            on = node.id in running
            was = self.last.get(node.id)
            self.last[node.id] = on
            key = f"hung:{node.id}"
            if on and node.id in stuck and not self.last.get(key):
                self.last[key] = True
                if node.id in by_node:
                    lines.append(self._event(by_node[node.id], "Critical",
                                             "The operating system stopped responding (no heartbeat)"))
            elif node.id not in stuck:
                self.last[key] = False
            if was is None or was == on:
                continue
            what = "powered on" if on else "powered off"
            if on and boot_of(lab.name, node.id)["target"] != "None":
                if boot_of(lab.name, node.id)["target"] == "BiosSetup" and not boot_of(lab.name, node.id)["armed"]:
                    enter_setup(lab.name, node.id, reset=False)
                boot_armed(lab.name, node.id)
            out.append(f"{node.id} {what}")
            record(lab.name, node.id, what)
            lines.append(self._log(lab, node.id, what))
            if node.id in by_node:
                lines.append(self._event(by_node[node.id], "Info", f"Server {what}"))
        return out

    def _wake(self, lab, t: dict, running: set[str]) -> str:
        nid = t["node"]
        if nid in running or time.time() - self.woken.get(nid, 0) < WOKEN_HOLD:
            return ""
        sender = "the router" if t["from"] == "router" else naming.display(lab, t["from"])
        if wol_blocked(lab.name, t["mac"]):
            self.woken[nid] = time.time()
            what = (f"a magic packet from {sender} reached it; its network card has Wake on Magic Packet "
                    f"turned off in Windows, so it stays off")
            record(lab.name, nid, what, "Wake-on-LAN")
            return what
        self.woken[nid] = time.time()
        err = self.start(nid)
        what = (f"woke: a magic packet from {sender} on {t['network']}" if not err else
                f"a magic packet from {sender} reached it, but it could not start: {err}")
        record(lab.name, nid, what, "Wake-on-LAN")
        return what

    def _screen(self, lab, b: dict) -> None:
        try:
            data = screendump(lab.name, b["node"], qmp=self._qmp)
        except PowerError:
            return
        for cmd in upload_cmds(b["dir"], data):
            if self._fabric(lab, cmd) is None:
                return

    def _sample_soon(self, lab, running: set[str]) -> None:
        """The card settings are read on a thread of their own: a machine whose
        agent is slow to answer must not hold up a reset or a wake."""
        if self._sampler is not None and self._sampler.is_alive():
            return
        self._sampler = threading.Thread(target=self._sample, args=(lab, set(running)), daemon=True)
        self._sampler.start()

    def _sample(self, lab, running: set[str]) -> None:
        """Windows' own Wake-on-LAN setting of each card, read while it runs."""
        now = time.time()
        for node in lab.node_list():
            if node.id not in running or not node.is_windows or now - self.sampled.get(node.id, 0) < WOL_EVERY:
                continue
            self.sampled[node.id] = now
            text = self._ask(lab.name, node.id)
            if not text:
                continue
            seen = parse_wol_query(text)

            def keep(data, seen=seen):
                for mac, v in seen.items():
                    data.setdefault("wol", {})[mac] = {"v": v, "t": round(now), "node": node.id}
            if seen:
                _update(lab.name, keep)

    def _ask(self, lab_name: str, node_id: str) -> str:
        if self._channel is not None:
            return self._channel(lab_name, node_id, WOL_QUERY)
        from .guestctl import GuestChannel, GuestError
        ns = _ns(lab_name, node_id)
        if ns is None or not ns.serial_port:
            return ""
        try:
            ch = GuestChannel(ns.serial_port, timeout=10).connect(retries=1, delay=1)
        except (GuestError, OSError):
            return ""
        try:
            res = ch.run(WOL_QUERY, shell="powershell", timeout=40)
            return res.out if res.ok else ""
        except (GuestError, OSError):
            return ""
        finally:
            ch.close()


def _split(out: str) -> tuple[list[tuple[str, str, str]], str, int, int]:
    """The poll's answer: the BMCs' requests (server, action, from), the
    capture text, its size and where it starts."""
    queue, wol, size, start = [], "", 0, 0
    head, sep, rest = (out or "").partition("#queue\n")
    body, sep2, tail = (rest if sep else head).partition("#wol ")
    for line in body.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            queue.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
    if sep2:
        first, _, wol = tail.partition("\n")
        nums = first.split()
        if len(nums) == 2 and all(n.isdigit() for n in nums):
            size, start = int(nums[0]), int(nums[1])
    return queue, wol, size, start


_WATCH: dict[str, object] = {}


def watch_desktop(dash_fn) -> None:
    """The desktop's watcher, on its own thread, following whichever lab the
    desktop shows."""
    if "desktop" in _WATCH:
        return

    def start(node_id: str) -> str:
        r = dash_fn().start_up([node_id])
        return "" if r.get("ok") else str(r.get("message") or "it did not start")
    w = Watcher(lambda: dash_fn().lab, start)
    _WATCH["desktop"] = w
    threading.Thread(target=w.run_forever, daemon=True, name="winlab-power").start()


# ------------------------------------------------------------------ the fault
FAULT_HINTS = (
    "The server runs and answers on its own address, but its management address does not answer. "
    "Ping the management address from a machine on the management VLAN, then from the router's console.",
    "Follow the management cable on the workbench: which switch port, which VLAN is it in? The cable takes "
    "the colour of the VLAN it is really in.",
    "Re-patch it: plug {server}'s management cable into a port of {want} (the server's panel, Management "
    "port). Then reload its page from a machine on that VLAN.",
)


def misplug(lab, node_id: str, rng=None) -> str:
    """The management cable in a port of another VLAN: the BMC is on the
    wrong network, its address belongs to none it can reach."""
    import random
    node = _node(lab, node_id)
    want = str(node.vars.get(PORT_VAR) or "")
    if not want:
        raise PowerError(f"{naming.display(lab, node.id)}'s management port has no cable to misplug")
    home = lab.networks[want].home
    others = sorted(n for n in lab.networks if n != want)
    same = [n for n in others if lab.networks[n].home == home]
    pick = (same or others)
    if not pick:
        raise PowerError("there is no other VLAN or switch for the cable to end up in")
    wrong = (rng or random).choice(pick)
    ip = str(node.vars.get(IP_VAR) or "")
    node.vars[PORT_VAR] = wrong  # the address stays: set on the BMC, it now belongs to no subnet here

    def add(data):
        data.setdefault("faults", {})[node.id] = {"kind": "mgmt-vlan", "want": want, "wrong": wrong,
                                                   "ip": ip, "t": round(time.time()), "hints": 0}
    _update(lab.name, add)
    record(lab.name, node.id, "fault: management cable in a port of another VLAN", "fault")
    return f"{naming.display(lab, node.id)}'s management port is broken somewhere: find it"


def _fault_recabled(lab, node_id: str, network: str) -> None:
    f = load(lab.name).get("faults", {}).get(node_id)
    if f and network == f.get("want"):
        lab.nodes[node_id].vars[IP_VAR] = f.get("ip") or lab.nodes[node_id].vars.get(IP_VAR)

        def fixed(data):
            data.get("faults", {}).get(node_id, {})["fixed"] = round(time.time())
        _update(lab.name, fixed)


def fault_check(lab, node_id: str) -> dict:
    node = _node(lab, node_id)
    f = load(lab.name).get("faults", {}).get(node.id)
    if not f:
        return {"ok": True, "fault": False, "message": f"no management-port fault on {naming.display(lab, node.id)}"}
    fixed = node.vars.get(PORT_VAR) == f["want"]
    if fixed:
        def drop(data):
            data.get("faults", {}).pop(node.id, None)
        _update(lab.name, drop)
        record(lab.name, node.id, "fault fixed: the management cable is back in the management VLAN", "fault")
        return {"ok": True, "fault": True, "fixed": True,
                "message": f"fixed: the management cable was in a port of {f['wrong']}, it is back in {f['want']}"}
    return {"ok": True, "fault": True, "fixed": False,
            "message": "the management address still does not answer from its VLAN"}


def fault_hint(lab, node_id: str) -> str:
    node = _node(lab, node_id)
    f = load(lab.name).get("faults", {}).get(node.id)
    if not f:
        return "no management-port fault here"
    n = min(int(f.get("hints", 0)), len(FAULT_HINTS) - 1)

    def more(data):
        data["faults"][node.id]["hints"] = n + 1
    _update(lab.name, more)
    return FAULT_HINTS[n].format(server=naming.display(lab, node.id), want=f["want"])


# ------------------------------------------------------------------ the desktop
def view(lab, plan, running: set[str], slots: dict[str, int]) -> dict[str, dict]:
    """Per machine, what its panel and the canvas show: whether it is a
    server (room for a management port) and the port, whether it hangs,
    Windows' Wake-on-LAN setting of its cards as last read. `slots` is the
    next free port of each switch, taken here by the management cables."""
    out = {}
    data = load(lab.name)
    stuck, faults, wol = data.get("hung", {}), data.get("faults", {}), data.get("wol", {})
    nets = {b["node"]: b for b in ports(lab, plan)}
    for node in lab.node_list():
        macs = [str(n.mac or "").lower() for n in node.nics]
        cards = [{"mac": m, "wake": wol[m]["v"], "t": wol[m]["t"]} for m in macs if m in wol]
        row = {"server": takes_port(node), "fitted": fitted(node), "wol": cards,
               "hung": node.id in stuck and node.id in running}
        out[node.id] = row
        if not row["fitted"]:
            continue
        net = str(node.vars.get(PORT_VAR) or "")
        home = lab.networks[net].home if net in lab.networks else ""
        slot = -1
        if home:
            slot = slots.get(home, 0)
            slots[home] = slot + 1
        row.update({"network": net, "home": home, "slot": slot,
                    "ip": str(node.vars.get(IP_VAR) or ""), "user": USER, "tag": tag(node, lab.name),
                    "vlan": lab.networks[net].vlan_no if net in lab.networks else 0,
                    "mac": bmc_mac(lab.name, node.id), "vid": nets.get(node.id, {}).get("vid", 0),
                    "fault": node.id in faults})
    return out


def act(dash, action: str, params: dict) -> dict:
    """The desktop's power-* actions: the management port's cable, a hang,
    the history, keys on a machine's keyboard, the misplugged-cable fault."""
    from . import editor
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    try:
        if action == "power-history":
            return {"ok": True, "history": history(lab.name, node_id)[:40]}
        if action == "power-hang":
            return {"ok": True, "message": hang(lab, node_id)}
        if action == "power-keys":
            # Keys on the machine's own keyboard (a desk phone's keypad): QMP send-key.
            k = str(params.get("key") or "")
            presses = [SPECIAL_KEYS[k]] if k in SPECIAL_KEYS else qcodes(str(params.get("text") or "")[:64])
            return {"ok": True, "keys": send_keys(lab.name, node_id, presses)}
        if action == "power-fault":
            msg = misplug(lab, node_id)
        elif action == "power-fault-check":
            return fault_check(lab, node_id)
        elif action == "power-fault-hint":
            return {"ok": True, "message": fault_hint(lab, node_id)}
        elif action == "power-bmc":
            from .workbench import _running
            op = str(params.get("op") or "")
            if op in ("fit", "remove") and node_id in _running(lab.name):
                raise PowerError(f"shut {naming.display(lab, node_id)} down before you open the case")
            if op == "fit":
                msg = fit(lab, node_id)
            elif op == "remove":
                msg = remove(lab, node_id)
            elif op == "unplug":
                msg = unplug(lab, node_id)
            else:
                msg = cable(lab, node_id, str(params.get("network") or ""), str(params.get("ip") or ""))
        else:
            raise PowerError(f"unknown power action {action!r}")
    except (PowerError, editor.EditError) as exc:
        dash.reload()
        return {"ok": False, "message": str(exc)}
    editor.save(lab)
    dash.reload()
    return {"ok": True, "message": msg + push(dash.lab)}


# ------------------------------------------------------------------ CLI
def add_cli(sub) -> None:
    p = sub.add_parser("power", help="servers' management ports (BMC), Wake-on-LAN, the power history")
    p.add_argument("lab")
    p.add_argument("what", choices=["status", "fit", "remove", "cable", "unplug", "hang", "history",
                                    "watch", "fault", "check", "hint"])
    p.add_argument("node", nargs="?", default="")
    p.add_argument("network", nargs="?", default="")
    p.add_argument("--ip", default="")


def run_cli(args) -> int:
    import sys
    from . import editor, netplan, schema
    from .workbench import _running
    lab = schema.load(args.lab)
    try:
        if args.what in ("status", "history"):
            rows = history(lab.name, naming.resolve(lab, args.node) if args.node else "")
            if args.what == "status":
                plan = netplan.compile_topology(lab, check_ports=False)
                for b in ports(lab, plan):
                    print(f"{b['name']}: management port {b['ip']}/{b['prefix']} on {b['network']} "
                          f"(VLAN {b['vid']}), user {USER}, password {tag(lab.nodes[b['node']], lab.name)}")
                for n in lab.node_list():
                    if fitted(n) and not n.vars.get(PORT_VAR):
                        print(f"{naming.hostname_of(n)}: management port fitted, no cable")
                rows = rows[:10]
            for r in rows:
                print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['t']))}  {r['node']:<8} {r['what']}"
                      + (f"  ({r['by']})" if r.get("by") else ""))
            return 0
        if args.what == "watch":
            from .orchestrator import Orchestrator, OrchestratorError
            from . import hostprobe

            def start(node_id: str) -> str:
                try:
                    Orchestrator(schema.load(args.lab), accel=hostprobe.probe().accel).up(only=[node_id])
                    return ""
                except OrchestratorError as exc:
                    return str(exc)
            w = Watcher(lambda: schema.load(args.lab), start)
            print(f"watching {lab.name}'s router for management-port requests and magic packets; Ctrl-C to stop")
            try:
                while True:
                    for line in w.tick().get("done", []):
                        print(line, flush=True)
                    time.sleep(TICK)
            except KeyboardInterrupt:
                return 0
        if not args.node:
            raise PowerError(f"winlab power {args.lab} {args.what} needs a machine")
        nid = naming.resolve(lab, args.node)
        if args.what == "hang":
            print(hang(lab, nid))
            return 0
        if args.what == "check":
            print(fault_check(lab, nid)["message"])
            return 0
        if args.what == "hint":
            print(fault_hint(lab, nid))
            return 0
        if args.what in ("fit", "remove") and nid in _running(lab.name):
            raise PowerError(f"shut {nid} down before you open the case")
        msg = {"fit": lambda: fit(lab, nid), "remove": lambda: remove(lab, nid),
               "unplug": lambda: unplug(lab, nid), "fault": lambda: misplug(lab, nid),
               "cable": lambda: cable(lab, nid, args.network, args.ip)}[args.what]()
    except (PowerError, editor.EditError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    editor.save(lab)
    print(msg + push(lab))
    return 0


# ------------------------------------------------------------------ the router's console
def parse_mac(text: str) -> str:
    """52:54:00:12:34:56, 52-54-00-12-34-56 or 5254.0012.3456, as aa:bb:..."""
    hexes = re.sub(r"[^0-9a-fA-F]", "", text or "")
    if len(hexes) != 12 or not re.fullmatch(r"\s*[0-9a-fA-F:.\-]+\s*", text or ""):
        raise PowerError(f"% Invalid MAC address {text.strip()!r}: give it as 5254.0012.3456 or 52-54-00-12-34-56")
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).lower()


def wake_cmd(plan, mac: str) -> tuple[str, list[tuple[str, int]]]:
    """ether-wake out of each of the router's VLAN interfaces."""
    segs = sorted((s for s in plan.segments.values() if s.network.routed), key=lambda s: s.vid)
    return "; ".join(f"ether-wake -i {s.svi} {mac} 2>&1 || busybox ether-wake -i {s.svi} {mac} 2>&1"
                     for s in segs), [(s.network.id, s.vid) for s in segs]


def console_wake(con, text: str) -> str:
    """`wake <mac>` on the router: a magic packet out of every VLAN it routes
    (as the Wake-on-LAN tool of a router or firewall sends it)."""
    from .devcli import CliError, dotted_mac
    try:
        mac = parse_mac(text)
    except PowerError as exc:
        return str(exc)
    cmd, sent = wake_cmd(con.plan, mac)
    if not sent:
        return "% No routed interface to send it from"
    try:
        out = con._on_router(cmd, timeout=20)
    except CliError as exc:
        return str(exc)
    if "not found" in out or "applet not found" in out:
        return "% ether-wake is missing from the router (prepare the router again in Setup)"
    names = [con.iface_of(con.lab.networks[n]) or f"VLAN {v}" for n, v in sent]
    return f"Magic packet for {dotted_mac(mac)} sent out {', '.join(names)}"


# ------------------------------------------------------------------ its own pages
def _targets(lab) -> list:
    """Each cabled BMC's pages and Redfish API, on its address (winlab/adminui.py):
    OpenBMC's web UI when it was fetched (winlab/openbmcui.py), else winlab's
    own pages, and the box says which."""
    from . import adminui, openbmcui
    sign_in = f"{USER}, with the password on the server's toe tag"
    if openbmcui.ready():
        gui = adminui.AdminGui(software=f"OpenBMC web UI (webui-vue {openbmcui.SHORT}) on the BMC's Redfish API",
                               scheme="http", port=80, path="/", sign_in=sign_in, license=openbmcui.LICENSE,
                               note="Redfish at /redfish/v1. KVM and SOL are not available on this BMC: its virtual "
                                    "console keys are at /console and its virtual media at /media.")
    else:
        gui = adminui.AdminGui(software="winlab's own BMC pages and Redfish API (content/agent/bmc.sh)", scheme="http",
                               port=80, path="/", sign_in=sign_in, license="winlab's own",
                               note="Redfish at /redfish/v1. OpenBMC's web UI is not fetched: prepare the router again in "
                                    "Setup (winlab images prepare fabric) to get it.")
    out = []
    for node in lab.node_list():
        if fitted(node) and node.vars.get(PORT_VAR) in lab.networks and node.vars.get(IP_VAR):
            out.append(adminui.Target(key=node.id, title=f"{naming.hostname_of(node)}'s management processor",
                                      host=str(node.vars[IP_VAR]), gui=gui))
    return out


def _register() -> None:
    from . import adminui
    adminui.register(targets=_targets)


_register()
