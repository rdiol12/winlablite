"""The console cable: the blue rollover cable from a router's or a switch's
console port to a lab PC, its USB-serial adapter end in the PC.

A real router or switch comes out of the box with nothing set, so it is
first reached from a PC beside it: the rollover cable from its console port
to a USB-serial adapter in the PC, and a terminal program (PuTTY, or
Windows' own System.IO.Ports in PowerShell) on that serial line at 9600
baud, 8 data bits, no parity, 1 stop bit. Here the cable is a part on the
workbench shelf, plugged from the device to a Windows machine.

The adapter is the PC's second serial port, COM2 (COM1 carries the winlab
agent): a 16550 UART QEMU fits at power-on to a machine that has had the
adapter in, wired to a loopback socket like the agent's own. The desktop
bridges that socket to the device's command line (devcli.Console): what the
terminal program in Windows sends is a console line, typed and echoed byte
by byte, and what the device prints goes back down the cable. Nothing else
reaches the socket, so the lab stays as isolated as before: the bytes go
from the guest to the device's console and back, never to this PC's own
serial ports or network.

The desktop can also draw the terminal itself (con-term): a serial terminal
window "on" the PC, opened from Connect from... <PC> only when the cable runs
to that PC and the PC is on. It connects; the student types every command.
Its line settings matter: anything but 9600 8N1 on COM2 reads as garbage or
silence, as on a real console.
"""

from __future__ import annotations

import select
import socket
import threading
import time

from . import devcli, naming, state

VAR = "console"               # lab.devices[device][VAR]: the machine at the cable's far end
ADAPTER = "serial_adapter"    # node.vars: the USB-serial adapter is in it (its COM port fitted at power-on)
COM = "COM2"
LINE = {"speed": 9600, "data": 8, "parity": "none", "stop": 1}
SHELVES = ("pc", "laptop", "server")
CHARDEV = "com2"
TICK = 1.0
_WATCH: dict[str, object] = {}


class CableError(Exception):
    pass


# ------------------------------------------------------------------ the cable
def takes_adapter(node) -> bool:
    """A Windows machine (PC, laptop, server) takes the adapter's USB end."""
    from .workbench import _shelf_of
    return _shelf_of(node) in SHELVES


def fitted(node) -> bool:
    return bool(node.vars.get(ADAPTER))


def device_list(lab) -> list[str]:
    """The devices with a console port: the router and each switch."""
    return [devcli.ROUTER] + [f"sw:{s}" for s in devcli.switches(lab)]


def cables(lab) -> dict[str, str]:
    """{device: machine} for each console cable plugged in at both ends."""
    out = {}
    for dev in device_list(lab):
        node = lab.devices.get(dev, {}).get(VAR, "")
        if node and node in lab.nodes:
            out[dev] = node
    return out


def device_of(lab, node_id: str) -> str:
    """The device whose console cable runs to this machine ("" for none)."""
    return next((d for d, n in cables(lab).items() if n == node_id), "")


def _device(lab, device: str) -> str:
    device = str(device or "")
    if device.startswith("net:"):
        device = "sw:" + device[4:]
    if device not in device_list(lab):
        raise CableError(f"no router or switch {device!r} with a console port")
    return device


def plug(lab, device: str, node_id: str, running: set[str] | None = None, com_ready: bool = False) -> str:
    """The cable from the device's console port into the machine's adapter.
    `com_ready`: the machine runs with its COM port already fitted."""
    device = _device(lab, device)
    node_id = naming.resolve(lab, node_id)
    node = lab.nodes.get(node_id)
    if node is None:
        raise CableError(f"no machine {node_id!r}")
    who, there = naming.display(lab, node_id), devcli.hostname(lab, device)
    if not takes_adapter(node):
        raise CableError(f"{who} takes no USB-serial adapter here: plug the console cable into a Windows PC, laptop or server")
    other = device_of(lab, node_id)
    if other and other != device:
        raise CableError(f"{who}'s adapter already has the console cable from {devcli.hostname(lab, other)}: unplug that one first")
    devcli.settings(lab, device)[VAR] = node_id
    new = not fitted(node)
    node.vars[ADAPTER] = COM
    msg = (f"console cable: {there}'s console port to {who}'s USB-serial adapter ({COM}). "
           f"Open a terminal on {who} at 9600 8N1, or Connect from... {who}")
    if node_id in (running or set()) and (new or not com_ready):
        msg += f"; the adapter is new to {who}: Windows finds {COM} after it restarts"
    return msg


def unplug(lab, device: str) -> str:
    device = _device(lab, device)
    node = lab.devices.get(device, {}).pop(VAR, "")
    if not node:
        raise CableError(f"{devcli.hostname(lab, device)}'s console port has no cable")
    return (f"console cable out of {devcli.hostname(lab, device)}"
            + (f" and {naming.display(lab, node)}" if node in lab.nodes else "")
            + "; the adapter stays in the PC")


# ------------------------------------------------------------------ QEMU
def qemu_args(node, port: int) -> list[str]:
    """The adapter's serial port, after the agent's (COM1): a loopback socket
    only the desktop's bridge connects to."""
    if not port or not fitted(node):
        return []
    return ["-chardev", f"socket,id={CHARDEV},host=127.0.0.1,port={port},server=on,wait=off",
            "-serial", f"chardev:{CHARDEV}"]


def _com_ports(lab_name: str) -> dict[str, int]:
    """{machine: its adapter's socket} for the running machines that have one."""
    st = state.load(lab_name)
    if not st:
        return {}
    return {nid: ns.com_port for nid, ns in st.nodes.items()
            if getattr(ns, "com_port", 0) and ns.pid and state.pid_alive(ns.pid)}


def view(lab, running: set[str]) -> dict:
    """The cables, for the canvas and the device panels."""
    ports = _com_ports(lab.name)
    rows = []
    for dev, node in cables(lab).items():
        on = node in running
        rows.append({"device": dev, "key": "router" if dev == devcli.ROUTER else "net:" + devcli.switch_id(dev),
                     "name": devcli.hostname(lab, dev), "node": node, "com": COM, "running": on,
                     "live": on and node in ports, "restart": on and node not in ports})
    takers = [n.id for n in lab.node_list() if takes_adapter(n)]
    return {"cables": rows, "machines": takers, "com": COM, "line": dict(LINE)}


# ------------------------------------------------------------------ a console line
class Terminal:
    """A console port's side of the serial line: the bytes a terminal program
    sends in, what the device echoes and prints back. Like IOS: Enter to get
    started, echo, Backspace, '?' for help at once, Tab, Ctrl+Z to leave
    configuration, Ctrl+C and Ctrl+U to drop the line, the arrows for history."""

    def __init__(self, con):
        self.con = con
        self.buf = ""
        self.started = False
        self.powered = False
        self._esc = ""
        self._cr = False
        self._hist = -1

    def wake(self) -> bytes:
        """What the device prints when its line comes up (connected, or it
        powered on while the cable was in)."""
        on = self.con.powered()
        was, self.powered = self.powered, on
        if on and not was:
            self.started, self.buf = False, ""
            return b"\r\n\r\nPress RETURN to get started.\r\n"
        if not on:
            self.started, self.buf = False, ""
        return b""

    def _prompt(self) -> str:
        return self.con.prompt()

    def _redraw(self, line: str) -> str:
        self.buf = line
        return "\r\x1b[K" + self._prompt() + line

    def feed(self, data: bytes) -> bytes:
        out = [self.wake().decode("latin-1")]
        if not self.powered:
            return b""   # a dark console: nothing echoes
        for ch in data.decode("latin-1"):
            if self._esc:
                self._esc += ch
                if len(self._esc) == 2 and ch != "[":
                    self._esc = ""
                elif len(self._esc) >= 3 and (ch.isalpha() or ch == "~"):
                    out.append(self._arrow(self._esc[-1]))
                    self._esc = ""
                continue
            if ch == "\n" and self._cr:
                self._cr = False
                continue
            self._cr = ch == "\r"
            if not self.started:
                if ch in "\r\n":
                    self.started = True
                    out.append("\r\n" + self.con.banner().replace("\n", "\r\n") + self._prompt())
                continue
            if ch in "\r\n":
                out.append(self._enter())
            elif ch == "\x1b":
                self._esc = ch
            elif ch in "\x08\x7f":
                if self.buf:
                    self.buf = self.buf[:-1]
                    out.append("\b \b")
            elif ch == "?":
                text = self.con.help(self.buf)
                out.append("?\r\n" + text.replace("\n", "\r\n") + "\r\n" + self._prompt() + self.buf)
            elif ch == "\t":
                new = self.con.complete(self.buf)
                out.append(new[len(self.buf):] if new.startswith(self.buf) else self._redraw(new))
                self.buf = new
            elif ch == "\x1a":   # Ctrl+Z
                self.buf = ""
                if self.con.s.mode.startswith(("config", "dhcp")):
                    self.con.run("end")
                out.append("^Z\r\n" + self._prompt())
            elif ch in "\x03\x15":   # Ctrl+C, Ctrl+U
                self.buf = ""
                out.append(("^C\r\n" + self._prompt()) if ch == "\x03" else self._redraw(""))
            elif ch == "\x10":
                out.append(self._arrow("A"))
            elif ch == "\x0e":
                out.append(self._arrow("B"))
            elif " " <= ch <= "~":
                self.buf += ch
                if not self.con.secret():  # a password does not echo
                    out.append(ch)
        return "".join(out).encode("latin-1", "replace")

    def _enter(self) -> str:
        line, self.buf, self._hist = self.buf, "", -1
        try:
            text = self.con.run(line)
        except Exception as exc:   # a device error is a console line, never a dead bridge
            text = f"% {exc}"
        if "Press RETURN to get started" in text:
            self.started = False
            return "\r\n" + text.replace("\n", "\r\n") + "\r\n"
        return "\r\n" + (text.replace("\n", "\r\n") + "\r\n" if text else "") + self._prompt()

    def _arrow(self, key: str) -> str:
        hist = self.con.s.history
        if key not in "AB" or not hist:
            return ""
        i = len(hist) if self._hist < 0 else self._hist
        i = max(0, i - 1) if key == "A" else i + 1
        if i >= len(hist):
            self._hist = -1
            return self._redraw("")
        self._hist = i
        return self._redraw(hist[i])


def line_ok(settings: dict | None) -> bool:
    """Whether a terminal's line settings match the console port's."""
    s = {**LINE, **{k: v for k, v in (settings or {}).items() if k in LINE}}
    try:
        return (int(s["speed"]) == LINE["speed"] and int(s["data"]) == LINE["data"]
                and str(s["parity"]).lower() == LINE["parity"] and float(s["stop"]) == LINE["stop"])
    except (TypeError, ValueError):
        return False


def garble(text: str) -> str:
    """What a console prints when the terminal's speed or framing is wrong."""
    junk = "þæøÿàðüâ§x°~¬"
    return "".join(junk[(ord(c) * 7 + i) % len(junk)] if c not in "\r\n" else c for i, c in enumerate(text))


# ------------------------------------------------------------------ the bridge
class _Wire:
    def __init__(self, device: str, node: str, port: int, sock, term: Terminal):
        self.device, self.node, self.port, self.sock, self.term = device, node, port, sock, term


class Bridge:
    """Keeps each console cable's serial socket connected to its device's
    console while the PC at the far end runs, and pumps the bytes."""

    def __init__(self, dash_fn, console_factory=None):
        self.dash_fn = dash_fn
        self.factory = console_factory or (lambda dash, device: devcli.Console(dash, device))
        self.wires: dict[tuple[str, str], _Wire] = {}

    def wanted(self) -> dict[tuple[str, str], tuple[str, int]]:
        lab = self.dash_fn().lab
        ports = _com_ports(lab.name)
        return {(lab.name, dev): (node, ports[node]) for dev, node in cables(lab).items() if node in ports}

    def _drop(self, key) -> None:
        w = self.wires.pop(key, None)
        if w is not None:
            try:
                w.sock.close()
            except OSError:
                pass

    def _send(self, key, data: bytes) -> None:
        if data:
            try:
                self.wires[key].sock.sendall(data)
            except OSError:
                self._drop(key)

    def step(self, wait: float = 0.5) -> None:
        want = self.wanted()
        for key in list(self.wires):
            if want.get(key) != (self.wires[key].node, self.wires[key].port):
                self._drop(key)
        for key, (node, port) in want.items():
            if key in self.wires:
                continue
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            except OSError:
                continue
            sock.setblocking(False)
            self.wires[key] = _Wire(key[1], node, port, sock, Terminal(self.factory(self.dash_fn(), key[1])))
        for key in list(self.wires):
            self._send(key, self.wires[key].term.wake())
        socks = {w.sock: k for k, w in self.wires.items()}
        if not socks:
            time.sleep(wait)
            return
        ready, _, _ = select.select(list(socks), [], [], wait)
        for s in ready:
            key = socks[s]
            try:
                data = s.recv(4096)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                data = b""
            if not data:
                self._drop(key)
                continue
            self._send(key, self.wires[key].term.feed(data))

    def run_forever(self) -> None:
        while True:
            try:
                self.step(TICK)
            except Exception:
                time.sleep(2)


def watch_desktop(dash_fn) -> None:
    """The desktop's bridge, on its own thread."""
    if "desktop" in _WATCH:
        return
    b = Bridge(dash_fn)
    _WATCH["desktop"] = b
    threading.Thread(target=b.run_forever, daemon=True, name="winlab-console-cable").start()


# ------------------------------------------------------------------ the desktop
def term(dash, device: str, node_id: str, settings: dict | None = None,
         line: str | None = None, complete: str | None = None) -> dict:
    """The serial terminal drawn by the desktop, on the PC the cable runs to."""
    from .workbench import _running
    lab = dash.lab
    device = _device(lab, device)
    node_id = naming.resolve(lab, node_id)
    if cables(lab).get(device) != node_id:
        raise CableError(f"no console cable from {devcli.hostname(lab, device)} to {naming.display(lab, node_id)}: "
                         f"plug one from the shelf first")
    if node_id not in _running(lab.name):
        raise CableError(f"{naming.display(lab, node_id)} is off: the terminal runs on it")
    port = str((settings or {}).get("port") or COM).upper()
    if port != COM:
        return {"ok": True, "out": "", "prompt": "", "silent": True}   # nothing on that line
    cons = dash.__dict__.setdefault("cable_consoles", {})
    con = cons.get(device)
    if con is None:
        con = cons[device] = devcli.Console(dash, device)
    if not con.powered():
        return {"ok": True, "off": True, "out": "", "prompt": ""}
    if not line_ok(settings):
        text = (line or "") + "\n" + con.prompt()
        return {"ok": True, "out": garble(text), "prompt": "", "garbled": True}
    if complete is not None:
        return {"ok": True, "line": con.complete(complete), "prompt": con.prompt()}
    if line is None:
        return {"ok": True, "out": "Press RETURN to get started.\n", "prompt": "", "fresh": True}
    if line == "" and not dash.__dict__.setdefault("cable_started", {}).get(device):
        dash.__dict__["cable_started"][device] = True
        return {"ok": True, "out": con.banner(), "prompt": con.prompt()}
    try:
        out = con.run(line)
    except Exception as exc:
        out = f"% {exc}"
    if "Press RETURN to get started" in out:
        dash.__dict__.setdefault("cable_started", {})[device] = False
        return {"ok": True, "out": out, "prompt": ""}
    return {"ok": True, "out": out, "prompt": con.prompt(), "help": line.rstrip().endswith("?")}


def act(dash, action: str, params: dict) -> dict:
    """The desktop's con-* actions: plug, unplug, the serial terminal."""
    from . import editor
    from .workbench import _running
    lab = dash.lab
    try:
        if action == "con-term":
            return term(dash, params.get("device", ""), params.get("node", ""), params.get("settings") or {},
                        params.get("line"), params.get("complete"))
        if action == "con-plug":
            node_id = naming.resolve(lab, str(params.get("node") or ""))
            msg = plug(lab, params.get("device", ""), node_id, _running(lab.name), node_id in _com_ports(lab.name))
        elif action == "con-unplug":
            msg = unplug(lab, params.get("device", ""))
        else:
            raise CableError(f"unknown console cable action {action!r}")
    except (CableError, editor.EditError, devcli.CliError) as exc:
        return {"ok": False, "message": str(exc)}
    editor.save(lab)
    dash.reload()
    return {"ok": True, "message": msg}
