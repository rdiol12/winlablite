"""The console agent: winlab's control channel for an appliance that has no
winlab agent inside, driven over its serial console from the host.

OPNsense's nano image puts a login prompt on its first serial port. This
module logs in there as root with the lab's password, opens the shell (menu
option 8), and from then on runs commands the way the in-guest agents do:
it listens on a loopback port and speaks the same JSON line protocol as
winlab-agent.ps1 and fabric-agent.sh ({"id","shell","b64"} in, {"id","rc",
"out","err","host"} out, a {"event":"ready"} banner first), so winlab shell,
cp, roles, exercises, problems and the lab guide all work on the appliance
unchanged. Nothing is installed in the appliance; the student's own
console (the VGA screen in the machine window) is a separate terminal.

A command travels as base64 in short lines (the tty's line buffer is small),
is decoded into a file, run with sh, and its output comes back base64 with
markers, so quoting and binary output are never a problem. On the first
shell, and whenever the generated configuration's fingerprint differs from
the one the appliance recorded, the configuration volume is mounted and
conf/config.xml copied into place, then the appliance reboots and the
driver logs in again.

Run as its own process by the orchestrator:
  python -m winlab.consoleagent --listen 34123 --console 34122 \
      --password-file var/labs/<lab>/admin-password --host fw01 \
      --fingerprint <sha> --log var/labs/<lab>/fw01/console.log
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import socket
import sys
import threading
import time
from pathlib import Path

PROMPT = "WLSH>>> "
CHUNK = 700
LOGIN_TIMEOUT = 900.0       # a first boot grows the filesystem and reboots once
REBOOT_TIMEOUT = 900.0
REBOOT_GRACE = 5.0          # seconds before looking for the console again after `reboot`

_RE_LOGIN = re.compile(r"login: ?$")
_RE_PASSWORD = re.compile(r"[Pp]assword: ?$")
_RE_MENU = re.compile(r"Enter an option: ?$")
_RE_OURS = re.compile(re.escape(PROMPT) + r"$")
_RE_SHELL = re.compile(r"(?:^|\n)[^\n]*[#$] $")
_RE_INCORRECT = re.compile(r"Login incorrect")
_RE_ACTIVATE = re.compile(r"Please press Enter to activate this console\.?\s*$")


class ConsoleError(Exception):
    pass


def _log_to(path: Path | None):
    fh = path.open("a", encoding="utf-8") if path else None

    def log(msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {msg}\n"
        if fh:
            fh.write(line)
            fh.flush()
        else:
            sys.stderr.write(line)
    return log


class Console:
    """One serial console, reached through QEMU's chardev socket."""

    OS = "OPNsense"
    SHELL_SETUP = f"exec /bin/sh\rstty -echo; PS1='{PROMPT}'; export PS1\r"

    def __init__(self, port: int, user: str, password: str, log=None, host: str = "127.0.0.1") -> None:
        self.port = port
        self.host = host
        self.user = user
        self.password = password
        self.log = log or (lambda m: None)
        self.sock: socket.socket | None = None
        self.buf = ""
        self.in_shell = False

    # ---------------------------------------------------------------- io
    def connect(self, retries: int = 30, delay: float = 2.0) -> None:
        last = None
        for attempt in range(retries):
            try:
                s = socket.create_connection((self.host, self.port), timeout=5)
                s.settimeout(1.0)
                self.sock = s
                self.buf = ""
                self.in_shell = False
                return
            except OSError as exc:
                last = exc
                if attempt + 1 < retries:  # no wait after the last try
                    time.sleep(delay)
        raise ConsoleError(f"no console on {self.host}:{self.port}: {last}")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self.in_shell = False

    def send(self, text: str) -> None:
        if not self.sock:
            raise ConsoleError("console not connected")
        try:
            self.sock.sendall(text.encode("utf-8", "replace"))
        except OSError as exc:
            self.close()
            raise ConsoleError(f"console write failed: {exc}") from exc

    def _fill(self) -> bool:
        if not self.sock:
            raise ConsoleError("console not connected")
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return False
        except OSError as exc:
            self.close()
            raise ConsoleError(f"console read failed: {exc}") from exc
        if not chunk:
            self.close()
            raise ConsoleError("console closed (machine stopped?)")
        self.buf += chunk.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
        return True

    def expect(self, patterns: list[re.Pattern], timeout: float) -> tuple[int, str]:
        """Waits until the tail of the console output matches one of the
        patterns; returns (index, everything before the match)."""
        deadline = time.monotonic() + timeout
        while True:
            tail = self.buf[-4000:]
            for i, p in enumerate(patterns):
                m = p.search(tail)
                if m:
                    cut = len(self.buf) - len(tail) + m.start()
                    before, self.buf = self.buf[:cut], self.buf[len(self.buf) - len(tail) + m.end():]
                    return i, before
            if time.monotonic() > deadline:
                raise ConsoleError(f"console: waited {timeout:.0f}s for {[p.pattern for p in patterns]}; "
                                   f"last seen: {self.buf[-200:]!r}")
            self._fill()
            if len(self.buf) > 200_000:
                self.buf = self.buf[-20_000:]

    # ----------------------------------------------------------- session
    def ensure_shell(self, timeout: float = LOGIN_TIMEOUT) -> None:
        """Gets to a root shell with our prompt, from whatever state the
        console is in: booting, a login prompt, the OPNsense menu, a shell
        someone left open, or our own shell from an earlier session."""
        if not self.sock:
            self.connect()
        if self.in_shell:
            return
        deadline = time.monotonic() + timeout
        self.send("\r")
        # "Login incorrect" comes with the next login prompt on its tail, so
        # it is looked for first; a password asked three times is a refusal
        # too, whatever the appliance prints.
        patterns = [_RE_INCORRECT, _RE_OURS, _RE_MENU, _RE_LOGIN, _RE_PASSWORD, _RE_SHELL, _RE_ACTIVATE]
        nudged = time.monotonic()
        passwords = 0
        while True:
            if time.monotonic() > deadline:
                raise ConsoleError(f"console: no shell within {timeout:.0f}s; last seen: {self.buf[-200:]!r}")
            try:
                which, _ = self.expect(patterns, timeout=min(30.0, max(1.0, deadline - time.monotonic())))
            except ConsoleError as exc:
                if "waited" not in str(exc):
                    raise
                if time.monotonic() > deadline:
                    raise
                if time.monotonic() - nudged > 20:
                    self.send("\r")
                    nudged = time.monotonic()
                continue
            if which == 0 or (which == 4 and passwords >= 3):
                raise ConsoleError("login refused: the appliance does not take the lab password "
                                   "(was its configuration applied?)")
            if which == 1:
                self.in_shell = True
                self.log("shell ready")
                return
            if which == 2:
                self.log("menu: opening the shell")
                self.send("8\r")
            elif which == 3:
                self.log(f"login prompt: logging in as {self.user}")
                self.send(self.user + "\r")
            elif which == 4:
                passwords += 1
                self.send(self.password + "\r")
            elif which == 5:
                # A shell, but not ours yet: make it sh, quiet, with our prompt.
                self.send(self.SHELL_SETUP)
            elif which == 6:
                self.send("\r")

    def run(self, command: str, timeout: float = 600.0) -> tuple[int, str, str]:
        """Runs a shell command and returns (rc, stdout, stderr)."""
        self.ensure_shell()
        b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
        self.send("rm -f /tmp/wl.in\r")
        for i in range(0, len(b64), CHUNK):
            self.send(f"printf '%s' '{b64[i:i + CHUNK]}' >> /tmp/wl.in\r")
        self.send("base64 -d /tmp/wl.in > /tmp/wl.cmd 2>/dev/null; "
                  "sh /tmp/wl.cmd > /tmp/wl.out 2> /tmp/wl.err < /dev/null; echo \"@@RC=$?@@\"; "
                  "base64 /tmp/wl.out; echo '@@OUT@@'; base64 /tmp/wl.err; echo '@@END@@'\r")
        _, text = self.expect([re.compile(r"@@END@@")], timeout)
        m = re.search(r"@@RC=(\d+)@@\n(.*?)@@OUT@@\n(.*)$", text, re.S)
        if not m:
            raise ConsoleError(f"console: reply not understood: {text[-300:]!r}")
        self.buf = ""   # the prompt after the marker is noise
        return int(m.group(1)), _unb64(m.group(2)), _unb64(m.group(3))

    def apply_config(self, fingerprint: str, reboot_timeout: float = REBOOT_TIMEOUT) -> bool:
        """Copies the generated configuration from the WLOPN volume when the
        appliance does not already run it, and reboots. True when applied."""
        rc, out, _ = self.run("cat /conf/winlab.sha 2>/dev/null || echo none")
        if out.strip() == fingerprint:
            return False
        self.log(f"applying configuration {fingerprint} (appliance has {out.strip()})")
        script = (
            "mkdir -p /mnt/winlab; ok=0; "
            "for d in /dev/vtbd1 /dev/vtbd2 /dev/vtbd3 /dev/vtbd1s1 /dev/da0 /dev/da0s1; do "
            "  mount -t msdosfs -o ro $d /mnt/winlab 2>/dev/null || continue; "
            "  if [ -f /mnt/winlab/conf/config.xml ]; then ok=1; break; fi; umount /mnt/winlab; done; "
            "[ $ok = 1 ] || { echo 'no configuration volume' >&2; exit 2; }; "
            "cp /mnt/winlab/conf/config.xml /conf/config.xml && "
            f"echo {fingerprint} > /conf/winlab.sha; rm -rf /conf/backup/*; umount /mnt/winlab; "
            "sync; echo applied"
        )
        rc, out, err = self.run(script)
        if rc != 0 or "applied" not in out:
            raise ConsoleError(f"configuration not applied: {err.strip() or out.strip()}")
        self.send("reboot\r")
        self.in_shell = False
        self.log("rebooting with the new configuration")
        time.sleep(REBOOT_GRACE)
        self.buf = ""
        self.ensure_shell(timeout=reboot_timeout)
        return True


class OpenWrtConsole(Console):
    """OpenWrt's console (winlab/openwrt.py): a root shell after Enter, no
    login while root has no console login set (OpenWrt's default), and a
    busybox without base64 or stty. So the tty keeps echoing: commands go
    in as octal escapes for printf, output comes back as hexdump, and every
    marker is typed in two halves so its echo never reads as the marker."""

    OS = "OpenWrt"
    SHELL_SETUP = "PS1='WLSH>''>> '; export PS1\r"
    LINE = 150   # bytes a printf line carries (4 characters each)

    def run(self, command: str, timeout: float = 600.0) -> tuple[int, str, str]:
        self.ensure_shell()
        data = command.encode("utf-8")
        self.send("rm -f /tmp/wl.cmd; : > /tmp/wl.cmd\r")
        for i in range(0, len(data), self.LINE):
            esc = "".join(f"\\{b:03o}" for b in data[i:i + self.LINE])
            self.send(f"printf '{esc}' >> /tmp/wl.cmd\r")
        hexd = "hexdump -v -e '1/1 \"%02x\"'"
        self.send("sh /tmp/wl.cmd > /tmp/wl.out 2> /tmp/wl.err < /dev/null; echo \"@@R\"\"C=$?@@\"; "
                  f"{hexd} /tmp/wl.out; echo; echo '@@O''UT@@'; {hexd} /tmp/wl.err; echo; echo '@@E''ND@@'\r")
        _, text = self.expect([re.compile(r"@@END@@")], timeout)
        m = re.search(r"@@RC=(\d+)@@\n(.*?)@@OUT@@\n(.*)$", text, re.S)
        if not m:
            raise ConsoleError(f"console: reply not understood: {text[-300:]!r}")
        self.buf = ""
        return int(m.group(1)), _unhex(m.group(2)), _unhex(m.group(3))

    def apply_config(self, fingerprint: str, reboot_timeout: float = REBOOT_TIMEOUT) -> bool:
        """Runs the volume's setup.sh when the device does not already run
        this fingerprint: no reboot, OpenWrt reloads what changed."""
        from .openwrt import APPLY, SHA_FILE
        rc, out, _ = self.run(f"cat {SHA_FILE} 2>/dev/null || echo none")
        if out.strip() == fingerprint:
            return False
        self.log(f"applying setup {fingerprint} (device has {out.strip()})")
        rc, out, err = self.run(APPLY.format(fp=fingerprint))
        if rc != 0 or "applied" not in out:
            raise ConsoleError(f"setup not applied: {err.strip() or out.strip()}")
        return True


def _unhex(text: str) -> str:
    digits = re.sub(r"[^0-9a-f]", "", text.lower())
    try:
        return bytes.fromhex(digits[:len(digits) // 2 * 2]).decode("utf-8", "replace")
    except ValueError:
        return ""


CONSOLES = {"opnsense": Console, "openwrt": OpenWrtConsole}


def _unb64(text: str) -> str:
    try:
        return base64.b64decode("".join(text.split())).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - a torn reply reads as empty, the rc still tells
        return ""


class Proxy:
    """The loopback server the rest of winlab talks to, in the agents' protocol."""

    def __init__(self, listen: int, console: Console, host: str, fingerprint: str = "",
                 log=None) -> None:
        self.listen = listen
        self.console = console
        self.hostname = host
        self.fingerprint = fingerprint
        self.log = log or (lambda m: None)
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.failed = ""
        self.stop = threading.Event()

    def prepare(self) -> None:
        """Reaches the shell (and applies the configuration) once, in the
        background, so clients get their ready banner as soon as it is true."""
        try:
            with self.lock:
                self.console.ensure_shell()
                if self.fingerprint:
                    self.console.apply_config(self.fingerprint)
            self.ready.set()
        except ConsoleError as exc:
            self.failed = str(exc)
            self.log(f"console failed: {exc}")

    def serve(self) -> None:
        threading.Thread(target=self.prepare, daemon=True).start()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.listen))
        srv.listen(8)
        srv.settimeout(1.0)
        self.log(f"listening on 127.0.0.1:{self.listen} for {self.hostname}")
        while not self.stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()
        srv.close()

    def _client(self, conn: socket.socket) -> None:
        conn.settimeout(1.0)
        buf = b""
        banner_sent = False
        try:
            while not self.stop.is_set():
                if not banner_sent and self.ready.is_set():
                    conn.sendall((json.dumps({"event": "ready", "host": self.hostname,
                                              "os": self.console.OS, "agent": 1}) + "\n").encode())
                    banner_sent = True
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    if not raw.strip():
                        continue
                    try:
                        req = json.loads(raw.decode("utf-8", "replace"))
                    except json.JSONDecodeError:
                        continue
                    conn.sendall((json.dumps(self._handle(req), separators=(",", ":")) + "\n").encode())
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle(self, req: dict) -> dict:
        rid = int(req.get("id") or 0)
        try:
            cmd = base64.b64decode(req.get("b64") or "").decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            cmd = ""
        if not self.ready.wait(timeout=600) or self.failed:
            err = self.failed or "console not ready"
            return {"id": rid, "rc": 255, "out": "", "err": _b64(err), "host": self.hostname}
        with self.lock:
            try:
                rc, out, err = self.console.run(cmd)
            except ConsoleError as exc:
                self.log(f"request {rid} failed: {exc}")
                try:
                    self.console.close()
                    self.console.connect(retries=3)
                    self.console.ensure_shell()
                    rc, out, err = self.console.run(cmd)
                except ConsoleError as exc2:
                    return {"id": rid, "rc": 255, "out": "", "err": _b64(str(exc2)), "host": self.hostname}
        return {"id": rid, "rc": rc, "out": _b64(out), "err": _b64(err), "host": self.hostname}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8", "replace")).decode("ascii")


def add_arguments(ap: argparse.ArgumentParser) -> None:
    """The agent's options, shared with `winlab console-agent`."""
    ap.add_argument("--listen", type=int, required=True, help="loopback port winlab connects to")
    ap.add_argument("--console", type=int, required=True, help="QEMU chardev port of the serial console")
    ap.add_argument("--password-file", required=True, help="file holding the lab password")
    ap.add_argument("--host", default="appliance")
    ap.add_argument("--user", default="root")
    ap.add_argument("--fingerprint", default="", help="the generated configuration's fingerprint")
    ap.add_argument("--log", default="")
    ap.add_argument("--flavor", default="opnsense", choices=sorted(CONSOLES),
                    help="opnsense (login, menu option 8) or openwrt (Enter, no base64)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="winlab console agent for an appliance")
    add_arguments(ap)
    return run(ap.parse_args(argv))


def run(args: argparse.Namespace) -> int:
    log = _log_to(Path(args.log) if args.log else None)
    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    console = CONSOLES[getattr(args, "flavor", "opnsense")](args.console, args.user, password, log=log)
    try:
        console.connect()
    except ConsoleError as exc:
        log(str(exc))
        return 1
    Proxy(args.listen, console, args.host, args.fingerprint, log=log).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
