"""Host side of the serial control channel.

Talks to the in-guest agent through the QEMU chardev on loopback. This is how
winlab runs commands inside a machine whose network reaches nothing but the
fabric.
"""

from __future__ import annotations

import base64
import json
import socket
import time
from dataclasses import dataclass


class GuestError(Exception):
    pass


class GuestRebooted(GuestError):
    """The agent re-announced itself while a request was outstanding: the
    guest rebooted before it could answer."""


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def raise_for_status(self, what: str = "command") -> Result:
        if not self.ok:
            detail = (self.err or self.out or "").strip()
            raise GuestError(f"{what} failed (rc={self.rc}): {detail[:600]}")
        return self


class GuestChannel:
    def __init__(self, port: int, host: str = "127.0.0.1", timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._seen = 0  # bytes of _buf already searched for a newline
        self._next_id = 1

    # ---------------------------------------------------------------- socket
    def connect(self, retries: int = 1, delay: float = 1.0,
                connect_timeout: float | None = None) -> GuestChannel:
        """Connects, trying ``retries`` times ``delay`` seconds apart (no
        wait after the last try). ``connect_timeout`` bounds each attempt
        (default: the channel's timeout)."""
        last: Exception | None = None
        tries = max(1, retries)
        for attempt in range(tries):
            try:
                s = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout if connect_timeout is None else connect_timeout)
                s.settimeout(self.timeout)
                self._sock = s
                return self
            except OSError as exc:
                last = exc
                if attempt + 1 < tries:
                    time.sleep(delay)
        raise GuestError(f"cannot reach the guest channel on {self.host}:{self.port}: {last}")

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> GuestChannel:
        # `with GuestChannel(p).connect(retries=20) as ch` is already
        # connected: a second connection would drop the first (QEMU's
        # chardev serves one client) and lose its retries.
        return self if self._sock else self.connect()

    def __exit__(self, *_exc) -> None:
        self.close()

    # ----------------------------------------------------------------- lines
    def _read_line(self, deadline: float) -> dict | None:
        # A reply is one line however long (get_file's is the whole file in
        # base64), so each chunk is searched once and appended in place:
        # rescanning and copying the buffer per chunk made a 40 MB line
        # take most of a minute.
        while True:
            nl = self._buf.find(b"\n", self._seen)
            if nl < 0:
                self._seen = len(self._buf)
            else:
                raw = bytes(self._buf[:nl])
                del self._buf[:nl + 1]
                self._seen = 0
                text = raw.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    continue  # boot-time console noise shares this port
            if time.monotonic() > deadline:
                return None
            if not self._sock:
                raise GuestError("channel is not connected")
            try:
                self._sock.settimeout(max(0.2, min(2.0, deadline - time.monotonic())))
                chunk = self._sock.recv(65536)
            except socket.timeout:
                continue
            except OSError as exc:
                raise GuestError(f"channel read failed: {exc}") from exc
            if not chunk:
                raise GuestError("guest closed the channel")
            self._buf += chunk

    def _send(self, payload: dict) -> None:
        if not self._sock:
            raise GuestError("channel is not connected")
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        try:
            self._sock.sendall(line.encode("utf-8"))
        except OSError as exc:
            raise GuestError(f"channel write failed: {exc}") from exc

    # ------------------------------------------------------------------- api
    def wait_ready(self, timeout: float = 2400.0) -> dict:
        """Block until the agent announces itself. Covers Windows Setup, which
        reboots several times before first logon."""
        deadline = time.monotonic() + timeout
        while True:
            msg = self._read_line(deadline)
            if msg is None:
                raise GuestError(
                    f"guest never announced readiness within {timeout:.0f}s"
                )
            if msg.get("event") == "ready":
                return msg

    def run(
        self,
        command: str,
        shell: str = "powershell",
        timeout: float = 1800.0,
        reboot_ok: bool = False,
    ) -> Result:
        """Runs one command. With reboot_ok, a ready banner arriving before the
        reply raises GuestRebooted instead of being skipped, so a caller that
        expects the command to reboot the guest does not wait out the timeout."""
        req_id = self._next_id
        self._next_id += 1
        self._send(
            {
                "id": req_id,
                "shell": shell,
                "b64": base64.b64encode(command.encode("utf-8")).decode("ascii"),
            }
        )
        deadline = time.monotonic() + timeout
        while True:
            msg = self._read_line(deadline)
            if msg is None:
                raise GuestError(f"no reply to request {req_id} within {timeout:.0f}s")
            if msg.get("event") == "ready":
                if reboot_ok:
                    raise GuestRebooted(f"guest rebooted during request {req_id}")
                continue  # agent restarted after a reboot
            if int(msg.get("id") or 0) != req_id:
                continue
            return Result(
                rc=int(msg.get("rc") or 0),
                out=_b64(msg.get("out")),
                err=_b64(msg.get("err")),
            )

    def run_script(
        self, script: str, timeout: float = 3600.0, reboot_ok: bool = False
    ) -> Result:
        return self.run(script, shell="powershell", timeout=timeout, reboot_ok=reboot_ok)

    def wait_responsive(self, shell: str = "powershell", timeout: float = 2400.0) -> None:
        """Waits until the agent answers a command. Unlike wait_ready this works
        on a guest that booted long ago: its one-off ready banner is gone, but
        it still answers requests."""
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                if self.run("echo ok", shell=shell, timeout=30).ok:
                    return
            except GuestError as exc:
                last = exc
            time.sleep(2)
        raise GuestError(f"agent did not answer within {timeout:.0f}s: {last}")

    def wait_for_reboot(self, timeout: float = 1800.0) -> dict:
        """After a reboot the agent re-announces itself on startup."""
        deadline = time.monotonic() + timeout
        while True:
            msg = self._read_line(deadline)
            if msg is None:
                raise GuestError(f"guest did not come back within {timeout:.0f}s")
            if msg.get("event") == "ready":
                return msg

    def put_file(self, remote_path: str, data: bytes, chunk: int = 24000) -> Result:
        """Writes in chunks: a single serial line carrying megabytes is a
        reliability problem, not a speed one."""
        esc = remote_path.replace("'", "''")
        first = (
            f"$d = Split-Path -Parent '{esc}'; "
            f"if ($d -and -not (Test-Path $d)) {{ New-Item -ItemType Directory -Path $d "
            f"-Force | Out-Null }}; "
            f"Set-Content -LiteralPath '{esc}' -Value '' -Encoding ascii; "
            # what an interrupted copy left behind must not prefix this one
            f"Remove-Item -LiteralPath '{esc}.b64' -Force -ErrorAction SilentlyContinue"
        )
        self.run(first).raise_for_status(f"create {remote_path}")

        b64 = base64.b64encode(data).decode("ascii")
        for i in range(0, len(b64), chunk):
            piece = b64[i : i + chunk]
            cmd = f"Add-Content -LiteralPath '{esc}.b64' -Value '{piece}' -Encoding ascii"
            self.run(cmd).raise_for_status(f"write chunk to {remote_path}")

        finish = (
            f"$b = [IO.File]::ReadAllText('{esc}.b64') -replace '\\s',''; "
            f"[IO.File]::WriteAllBytes('{esc}', [Convert]::FromBase64String($b)); "
            f"Remove-Item -LiteralPath '{esc}.b64' -Force"
        )
        return self.run(finish).raise_for_status(f"finalise {remote_path}")

    def get_file(self, remote_path: str) -> bytes:
        esc = remote_path.replace("'", "''")
        res = self.run(
            f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{esc}'))"
        ).raise_for_status(f"read {remote_path}")
        return base64.b64decode("".join(res.out.split()))


def _b64(value: object) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(str(value)).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return str(value)
