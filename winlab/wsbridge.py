"""A WebSocket-to-TCP bridge on the standard library, for the browser console.

noVNC speaks RFB over a WebSocket; QEMU speaks RFB over TCP on loopback. This
is the websockify in between, small enough to live inside the dashboard's
http.server: the handshake (RFC 6455 section 4), frame parsing with client
masking, fragmentation, ping/pong and close, and two threads that pump bytes
each way until either side hangs up.

Both ends are on 127.0.0.1, so there is no TLS and no authentication here;
the dashboard itself is bound to loopback (webui.serve).
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA

MAX_FRAME = 16 * 1024 * 1024


class BridgeError(Exception):
    pass


def accept_key(client_key: str) -> str:
    digest = hashlib.sha1((client_key.strip() + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def encode_frame(payload: bytes, opcode: int = OP_BINARY, fin: bool = True,
                 mask: bool = False) -> bytes:
    """One frame. Servers send unmasked; a client (the tests) masks."""
    head = bytearray([(0x80 if fin else 0) | (opcode & 0x0F)])
    n = len(payload)
    mbit = 0x80 if mask else 0
    if n < 126:
        head.append(mbit | n)
    elif n < 65536:
        head.append(mbit | 126)
        head += struct.pack("!H", n)
    else:
        head.append(mbit | 127)
        head += struct.pack("!Q", n)
    if mask:
        key = os.urandom(4)
        head += key
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return bytes(head) + payload


def decode_frame(buf: bytes) -> tuple[bool, int, bytes, int] | None:
    """(fin, opcode, payload, bytes consumed), or None while buf is short."""
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    n = b1 & 0x7F
    pos = 2
    if n == 126:
        if len(buf) < 4:
            return None
        n = struct.unpack("!H", buf[2:4])[0]
        pos = 4
    elif n == 127:
        if len(buf) < 10:
            return None
        n = struct.unpack("!Q", buf[2:10])[0]
        pos = 10
    if n > MAX_FRAME:
        raise BridgeError(f"frame of {n} bytes refused")
    key = b""
    if masked:
        if len(buf) < pos + 4:
            return None
        key = buf[pos:pos + 4]
        pos += 4
    if len(buf) < pos + n:
        return None
    payload = buf[pos:pos + n]
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload, pos + n


class FrameReader:
    """Reassembles frames (and fragmented messages) from a byte stream."""

    def __init__(self, read) -> None:
        self._read = read  # callable(n) -> up to n bytes, b"" on EOF
        self._buf = b""
        self._frag_op = 0
        self._frag = b""

    def next_message(self) -> tuple[int, bytes] | None:
        """(opcode, payload) for the next complete data or control message;
        None at end of stream."""
        while True:
            parsed = decode_frame(self._buf)
            if parsed is None:
                chunk = self._read(65536)
                if not chunk:
                    return None
                self._buf += chunk
                continue
            fin, opcode, payload, used = parsed
            self._buf = self._buf[used:]
            if opcode in (OP_CLOSE, OP_PING, OP_PONG):
                return opcode, payload
            if opcode == OP_CONT:
                self._frag += payload
                if fin:
                    msg = (self._frag_op, self._frag)
                    self._frag_op, self._frag = 0, b""
                    return msg
                continue
            if fin:
                return opcode, payload
            self._frag_op, self._frag = opcode, payload


def handshake_response(headers, path: str = "") -> tuple[int, str, list[tuple[str, str]]]:
    """(status, reason, response headers) for an upgrade request. 101 when
    the request is a valid WebSocket opening handshake."""
    upgrade = (headers.get("Upgrade") or "").lower()
    conn = (headers.get("Connection") or "").lower()
    key = headers.get("Sec-WebSocket-Key") or ""
    version = headers.get("Sec-WebSocket-Version") or ""
    if upgrade != "websocket" or "upgrade" not in conn or not key:
        return 400, "Bad Request", [("Content-Type", "text/plain")]
    if version != "13":
        return 426, "Upgrade Required", [("Sec-WebSocket-Version", "13")]
    out = [("Upgrade", "websocket"), ("Connection", "Upgrade"),
           ("Sec-WebSocket-Accept", accept_key(key))]
    offered = [p.strip() for p in (headers.get("Sec-WebSocket-Protocol") or "").split(",")]
    if "binary" in offered:
        out.append(("Sec-WebSocket-Protocol", "binary"))
    return 101, "Switching Protocols", out


def bridge(client: socket.socket, read, write, host: str, port: int,
           connect_timeout: float = 5.0, tap=None) -> None:
    """Pumps a handshaken WebSocket (read/write on the client, which is also
    `client` for shutdown) to TCP host:port until either side closes.

    tap, when given, is called with every chunk on its way from the target
    to the browser (a Terminal window's recording, recordings.py); nothing
    the browser sends is passed to it, and a tap that fails is dropped."""
    try:
        target = socket.create_connection((host, port), timeout=connect_timeout)
    except OSError as exc:
        write(encode_frame(struct.pack("!H", 1011) + b"target unreachable", OP_CLOSE))
        raise BridgeError(f"cannot connect to {host}:{port}: {exc}") from exc
    target.settimeout(None)
    lock = threading.Lock()
    done = threading.Event()
    closed = threading.Event()

    def send(frame: bytes) -> None:
        with lock:
            try:
                write(frame)
            except OSError:
                done.set()

    def send_close(payload: bytes) -> None:
        # One close frame per connection: the browser rejects a second one,
        # and both pumps reach their shutdown path when either side closes.
        if not closed.is_set():
            closed.set()
            send(encode_frame(payload, OP_CLOSE))

    def to_browser() -> None:
        try:
            while not done.is_set():
                data = target.recv(65536)
                if not data:
                    break
                send(encode_frame(data, OP_BINARY))
                if tap is not None:
                    try:
                        tap(data)
                    except Exception:  # noqa: BLE001 - a recording never breaks the session
                        pass
        except OSError:
            pass
        finally:
            done.set()
            send_close(struct.pack("!H", 1000))
            # Unblock the browser-side reader so the handler thread returns
            # even when the browser never answers the close.
            try:
                client.shutdown(socket.SHUT_RD)
            except OSError:
                pass

    def to_target() -> None:
        reader = FrameReader(read)
        try:
            while not done.is_set():
                msg = reader.next_message()
                if msg is None:
                    break
                opcode, payload = msg
                if opcode == OP_CLOSE:
                    send_close(payload[:2])
                    break
                if opcode == OP_PING:
                    send(encode_frame(payload, OP_PONG))
                    continue
                if opcode == OP_PONG:
                    continue
                target.sendall(payload)
        except (OSError, BridgeError):
            pass
        finally:
            done.set()
            try:
                target.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    t = threading.Thread(target=to_browser, daemon=True)
    t.start()
    to_target()
    done.wait()
    t.join(timeout=2)
    target.close()
