"""Command Prompt and Windows PowerShell windows for a Windows lab machine.

The machine's screen already has both, but a console window on the desktop
is what a sysadmin lives in: Windows' own pseudoconsole (ConPTY) with
cmd.exe or powershell.exe in it, so tab completion, colours, PSReadLine,
history, Ctrl+C, copy and paste and resizing all behave as they do on the
machine. It is reached the way Hyper-V's PowerShell Direct reaches a guest,
through the virtual machine rather than over its network: the labs have no
path to this PC, so the console travels over a serial line.

  * Every Windows machine gets a third serial port, COM3 (I/O 0x3e8, on IRQ 5
    of its own: COM3's usual IRQ 4 is COM1's, and Windows' serial driver does
    not share one), wired by QEMU to a loopback socket only the desktop
    connects to (`qemu_args`).
  * In the machine, content/agent/winlab-term.ps1 runs winlab-term.cs, the
    console host, as a startup task under SYSTEM (setup-term.ps1). It asks
    for a user name and password, signs the account in with Windows
    (LogonUser: a domain account on a member, a local one otherwise; a
    domain controller refuses non-administrators, as at its keyboard), and
    starts the shell as that account, elevated for "Run as administrator"
    when the account is an administrator.
  * A machine installed before the console host existed, or carrying an
    older one, gets the current one over the agent's channel (COM1) the
    first time a console window opens (`ensure`).

One `Line` per running machine multiplexes its console windows over COM3;
the line protocol is described at the top of winlab-term.cs. The desktop
bridges each window's WebSocket to one session (`serve_ws`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
import time

from . import paths

COM = "COM3"
INDEX = 2            # QEMU's third ISA serial port: 0x3e8, COM3 on a PC
IRQ = 5
CHARDEV = "wterm"
SHELLS = {"cmd": "Command Prompt", "powershell": "Windows PowerShell"}
AGENT_DIR = paths.CONTENT / "agent"
FILES = ("winlab-term.cs", "winlab-term.ps1", "setup-term.ps1")
GUEST_DIR = "C:\\winlab"
CHUNK = 3000         # input bytes per IN line
READY_TIMEOUT = 150.0  # compiling and starting a new console host in a slow guest


class TermError(Exception):
    pass


# ------------------------------------------------------------------ QEMU
def fitted(node) -> bool:
    """Every Windows machine has the console port."""
    return bool(node is not None and node.is_windows)


def qemu_args(port: int) -> list[str]:
    if not port:
        return []
    return ["-chardev", f"socket,id={CHARDEV},host=127.0.0.1,port={port},server=on,wait=off",
            "-device", f"isa-serial,chardev={CHARDEV},index={INDEX},irq={IRQ}"]


def build_id() -> str:
    """The console host build the desktop carries: the start of the SHA-256 of
    winlab-term.cs, which winlab-term.ps1 reports from the guest's copy."""
    return hashlib.sha256((AGENT_DIR / "winlab-term.cs").read_bytes()).hexdigest()[:16]


def _b64d(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return ""


# ------------------------------------------------------------------ the line
class Line:
    """The desktop's end of one machine's COM3: its console sessions, by id."""

    def __init__(self, port: int, connect_timeout: float = 3.0) -> None:
        self.port = port
        try:
            self.sock = socket.create_connection(("127.0.0.1", port), timeout=connect_timeout)
        except OSError as exc:
            raise TermError(f"the machine's console port does not answer: {exc}") from exc
        self.sock.settimeout(None)
        self.alive = True
        self.info: dict | None = None
        self._seen = 0                   # how many HELLO/READY answers so far
        self._cond = threading.Condition()
        self._wlock = threading.Lock()
        self._sessions: dict[int, tuple] = {}
        self._next = 1
        threading.Thread(target=self._reader, daemon=True, name=f"winterm-{port}").start()
        # Sessions a previous desktop left open in the machine end now.
        self.send("RESET")

    def send(self, text: str) -> None:
        data = (text + "\n").encode("ascii")
        with self._wlock:
            try:
                self.sock.sendall(data)
            except OSError:
                self.alive = False

    def close_line(self) -> None:
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _reader(self) -> None:
        buf = b""
        try:
            while True:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    self._handle(raw.decode("ascii", "replace").strip())
        except OSError:
            pass
        self.alive = False
        self._end_all(None, "the machine's console port closed")
        with self._cond:
            self._cond.notify_all()

    def _handle(self, msg: str) -> None:
        f = msg.split(" ")
        if not f or not f[0]:
            return
        if f[0] in ("READY", "HELLO") and len(f) >= 2:
            if f[0] == "READY":
                # The host in the machine (re)started, e.g. after a restart:
                # whatever sessions it had are gone.
                self._end_all(None, "the machine restarted its console service")
            with self._cond:
                self.info = {"build": f[1], "os": _b64d(f[2]) if len(f) > 2 else "",
                             "computer": _b64d(f[3]) if len(f) > 3 else ""}
                self._seen += 1
                self._cond.notify_all()
        elif f[0] == "OUT" and len(f) >= 3:
            s = self._sessions.get(_int(f[1]))
            if s:
                try:
                    s[0](base64.b64decode(f[2]))
                except (ValueError, TypeError):
                    pass
        elif f[0] == "EXIT" and len(f) >= 2:
            s = self._sessions.pop(_int(f[1]), None)
            if s:
                s[1](_int(f[2]) if len(f) > 2 else 0, "")

    def _end_all(self, code, why: str) -> None:
        gone, self._sessions = self._sessions, {}
        for on_out, on_exit in gone.values():
            on_exit(code, why)

    def hello(self, timeout: float = 4.0) -> dict | None:
        """Asks the host in the machine who it is; None when nothing answers."""
        with self._cond:
            seen = self._seen
        self.send("HELLO")
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._seen == seen and self.alive:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self._cond.wait(left)
            return self.info if self._seen != seen else None

    def open(self, shell: str, cols: int, rows: int, admin: bool, on_out, on_exit) -> int:
        if shell not in SHELLS:
            raise TermError(f"no shell called {shell!r}")
        sid = self._next
        self._next += 1
        self._sessions[sid] = (on_out, on_exit)
        self.send(f"OPEN {sid} {shell} {int(cols)} {int(rows)} {1 if admin else 0}")
        return sid

    def write(self, sid: int, data: bytes) -> None:
        for i in range(0, len(data), CHUNK):
            self.send(f"IN {sid} " + base64.b64encode(data[i:i + CHUNK]).decode("ascii"))

    def resize(self, sid: int, cols: int, rows: int) -> None:
        self.send(f"SIZE {sid} {max(20, min(500, int(cols)))} {max(5, min(300, int(rows)))}")

    def close(self, sid: int) -> None:
        if self._sessions.pop(sid, None) is not None:
            self.send(f"CLOSE {sid}")


def _int(s: str) -> int:
    try:
        return int(s)
    except (TypeError, ValueError):
        return 0


_lines: dict[int, Line] = {}
_reg = threading.Lock()


def line_for(port: int) -> Line:
    """The open line to a machine's COM3, opened on first use."""
    with _reg:
        ln = _lines.get(port)
        if ln is None or not ln.alive:
            ln = _lines[port] = Line(port)
        return ln


# ------------------------------------------------------------------ the host in the machine
def install(agent_port: int, connect=None) -> None:
    """Copies the console host into the machine and (re)starts its task, over
    the agent's channel."""
    from .guestctl import GuestChannel, GuestError
    try:
        ch = connect() if connect else GuestChannel(agent_port, timeout=90).connect(retries=5, delay=2)
    except (GuestError, OSError) as exc:
        raise TermError(f"the machine's agent does not answer: {exc}") from exc
    try:
        for name in FILES:
            ch.put_file(f"{GUEST_DIR}\\{name}", (AGENT_DIR / name).read_bytes())
        ch.run((AGENT_DIR / "setup-term.ps1").read_text(encoding="utf-8"),
               timeout=120).raise_for_status("starting the console service")
    except GuestError as exc:
        raise TermError(str(exc)) from exc
    finally:
        ch.close()


def ensure(ns, say=lambda _msg: None, connect=None, timeout: float = READY_TIMEOUT) -> dict:
    """The machine's console host, answering and current: installed or
    replaced over the agent first when it is missing or older."""
    if not getattr(ns, "wterm_port", 0):
        raise TermError("this machine has no console port yet: shut it down and start it "
                        "again once to fit one")
    line = line_for(ns.wterm_port)
    want = build_id()
    info = line.hello(4.0)
    if info and info.get("build") == want:
        return info
    if not ns.serial_port:
        raise TermError("no winlab agent in this machine to set the console service up")
    say("Setting up the console service in the machine (once)…" if not info
        else "Updating the console service in the machine…")
    install(ns.serial_port, connect)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = line_for(ns.wterm_port)
        info = line.hello(5.0)
        if info and info.get("build") == want:
            return info
        if not line.alive:
            time.sleep(1.0)
    raise TermError("the console service in the machine did not start; C:\\winlab\\term.log "
                    "inside it says why")


# ------------------------------------------------------------------ one window
def serve_ws(client: socket.socket, read, write, ns, shell: str, admin: bool,
             cols: int, rows: int, connect=None) -> None:
    """Runs one console window over a handshaken WebSocket until either side
    ends it. Binary messages are keystrokes; text messages are JSON
    ({"size": [cols, rows]}). The page gets the console's output as binary
    and JSON for {"status"}, {"open"}, {"exit"} and {"error"}."""
    from .wsbridge import (OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, OP_TEXT,
                           BridgeError, FrameReader, encode_frame)
    wl = threading.Lock()
    done = threading.Event()
    closed = threading.Event()

    def frame(payload: bytes, op: int) -> None:
        with wl:
            try:
                write(encode_frame(payload, op))
            except OSError:
                done.set()

    def ctl(obj: dict) -> None:
        frame(json.dumps(obj).encode(), OP_TEXT)

    def close_ws(code: int = 1000) -> None:
        if not closed.is_set():
            closed.set()
            frame(struct.pack("!H", code), OP_CLOSE)

    def on_exit(code, why: str) -> None:
        ctl({"exit": code, "why": why})
        done.set()
        close_ws()
        try:
            client.shutdown(socket.SHUT_RD)   # the reader below returns
        except OSError:
            pass

    try:
        info = ensure(ns, lambda m: ctl({"status": m}), connect)
        line = line_for(ns.wterm_port)
        sid = line.open(shell, cols, rows, admin, lambda b: frame(b, OP_BINARY), on_exit)
    except TermError as exc:
        ctl({"error": str(exc)})
        close_ws(1011)
        return
    ctl({"open": sid, "os": info.get("os", ""), "computer": info.get("computer", "")})
    reader = FrameReader(read)
    try:
        while not done.is_set():
            msg = reader.next_message()
            if msg is None:
                break
            op, payload = msg
            if op == OP_CLOSE:
                break
            if op == OP_PING:
                frame(payload, OP_PONG)
            elif op == OP_TEXT:
                try:
                    obj = json.loads(payload.decode("utf-8"))
                except ValueError:
                    continue
                size = obj.get("size") if isinstance(obj, dict) else None
                if isinstance(size, list) and len(size) == 2:
                    line.resize(sid, size[0], size[1])
            elif op == OP_BINARY:
                line.write(sid, payload)
    except (OSError, BridgeError):
        pass
    finally:
        if not done.is_set():
            line.close(sid)   # the window closed: the console goes, as a console window's does
        close_ws()
