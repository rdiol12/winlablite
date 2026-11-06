"""A small QMP client for the loopback monitor every machine is started with.

QMP interleaves asynchronous events (STOP, RESUME, ...) with command replies,
so replies are matched by skipping event lines, and a reply carrying "error"
raises instead of being returned as data.
"""

from __future__ import annotations

import json
import socket


class QmpError(Exception):
    pass


class Qmp:
    def __init__(self, port: int, timeout: float = 30.0) -> None:
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._f = None

    def __enter__(self) -> Qmp:
        try:
            self._sock = socket.create_connection(("127.0.0.1", self.port),
                                                  timeout=self.timeout)
        except OSError as exc:
            raise QmpError(f"monitor on port {self.port} unreachable: {exc}") from exc
        self._sock.settimeout(self.timeout)
        self._f = self._sock.makefile("rwb")
        try:
            self._reply()  # greeting
            self.call("qmp_capabilities")
        except BaseException:
            self.__exit__()  # no with-block owns the socket yet
            raise
        return self

    def __exit__(self, *_exc) -> None:
        try:
            if self._f:
                self._f.close()
        finally:
            if self._sock:
                self._sock.close()

    def _reply(self) -> dict:
        assert self._f is not None
        while True:
            try:
                line = self._f.readline()
            except OSError as exc:
                raise QmpError(f"monitor on port {self.port}: {exc}") from exc
            if not line:
                raise QmpError(f"monitor on port {self.port} closed the connection")
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if "event" not in msg:
                return msg

    def call(self, command: str, **arguments) -> object:
        assert self._f is not None
        req: dict = {"execute": command}
        if arguments:
            req["arguments"] = arguments
        try:
            self._f.write((json.dumps(req) + "\n").encode("utf-8"))
            self._f.flush()
        except OSError as exc:
            raise QmpError(f"monitor on port {self.port}: {exc}") from exc
        msg = self._reply()
        if "error" in msg:
            err = msg["error"]
            raise QmpError(f"{command}: {err.get('desc') or err}")
        return msg.get("return")
