#!/usr/bin/env python3
"""winlab-hsrpd: a small HSRP speaker, winlab's own code (MIT, like the rest
of winlab), so a Linux router can stand in an HSRP group with IOS routers or
with another copy of itself.

No open-source HSRP daemon exists, so this is one, written from the published
packet formats: HSRP version 1 as RFC 2281 gives it (UDP 1985 to 224.0.0.2,
virtual MAC 0000.0c07.acXX) and version 2 as Cisco documents it and Wireshark
decodes it (UDP 1985 to 224.0.0.102, a group state TLV and a text
authentication TLV, virtual MAC 0000.0c9f.fXXX, groups 0-4095). The states
are RFC 2281's: Init, Learn, Listen, Speak, Standby, Active; hello 3 s and
hold 10 s by default; priority (100 by default) and then the higher address
decide; preemption (off by default, with ``delay minimum``); Coup and Resign;
plain-text authentication (the protocol's default string when none is set,
as on IOS); interface tracking that lowers the priority while a tracked
interface is down. The Active router puts the virtual address on a macvlan
that carries the virtual MAC (as FRRouting's vrrpd does for VRRP), sends its
hellos from the virtual MAC and announces it with gratuitous ARP; a router
that leaves Active takes the address away again.

Tracking: an interface (``track <iface>``) or a track object of winlab-slad's
(``track object <n>``, read from its state file /run/winlab-sla.json:
IOS's ``standby <g> track <n>`` on an IP SLA object).

What it does not do: MD5 authentication, HSRP for IPv6, BFD, ``standby use-bia``, ``follow`` groups, and the
interface state TLV some IOS releases add to version 2 (it is read and
ignored when it arrives). It needs root (raw sockets, ``ip``) and Python 3
with nothing beyond the standard library.

Usage, on a Linux router (the lab router runs it the same way, written from
its console's ``standby`` lines by winlab/ioshsrp.py)::

    winlab-hsrpd -c /etc/winlab-hsrp.conf      # run (SIGHUP reloads, SIGTERM resigns)
    winlab-hsrpd show [brief]                   # IOS's show standby, from the state file
    winlab-hsrpd check -c /etc/winlab-hsrp.conf # read the file, say what is wrong

The configuration file is IOS's own lines, under the Linux interface's name::

    interface eth1
     standby version 2
     standby 1 ip 10.80.0.1
     standby 1 priority 90
     standby 1 preempt

How it is tested (tests/test_winlab.py): the packets byte for byte against
RFC 2281's layout and the version 2 TLV layout, the state machine with two
speakers in one process over a fake wire, and two real speakers in two Linux
network namespaces on a veth pair (failover, preemption, tracking).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time

PORT = 1985
V1_GROUP = "224.0.0.2"
V2_GROUP = "224.0.0.102"
STATE_FILE = "/run/winlab-hsrp.json"
CONF_FILE = "/etc/winlab-hsrp.conf"
HELLO, HOLD, PRIORITY, DECREMENT = 3, 10, 100, 10
OP_HELLO, OP_COUP, OP_RESIGN = 0, 1, 2
OPS = {0: "Hello", 1: "Coup", 2: "Resign"}
STATES = ("Init", "Learn", "Listen", "Speak", "Standby", "Active")
# RFC 2281, section 5.2: the state octet of version 1.
V1_CODE = {"Init": 0, "Learn": 1, "Listen": 2, "Speak": 4, "Standby": 8, "Active": 16}
# Version 2's group state TLV numbers them 1 to 6 (0 is Disabled).
V2_CODE = {"Init": 1, "Learn": 2, "Listen": 3, "Speak": 4, "Standby": 5, "Active": 6}
TLV_GROUP, TLV_IFSTATE, TLV_TEXT_AUTH, TLV_MD5_AUTH = 1, 2, 3, 4


def default_auth() -> bytes:
    """The text both versions send when no authentication is configured:
    the protocol's default string (RFC 2281, section 5.1)."""
    return bytes((0x63, 0x69, 0x73, 0x63, 0x6F))


def auth_bytes(text: str | None) -> bytes:
    raw = default_auth() if text is None else text.encode()[:8]
    return raw.ljust(8, b"\0")


def vmac(version: int, group: int) -> str:
    """0000.0c07.acXX (v1) or 0000.0c9f.fXXX (v2), as aa:bb:.. for ip."""
    if version == 2:
        return "00:00:0c:9f:%s" % ":".join("%02x" % b for b in (0xF000 | group).to_bytes(2, "big"))
    return "00:00:0c:07:ac:%02x" % group


def cisco_mac(mac: str) -> str:
    h = mac.replace(":", "").lower()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


# ------------------------------------------------------------------ packets
def encode_v1(op: int, state: str, hello: int, hold: int, prio: int, group: int, auth: bytes, vip: str) -> bytes:
    """RFC 2281 section 5.1: version 0, op code, state, hellotime, holdtime,
    priority, group, reserved, 8 octets of authentication, virtual IP."""
    return struct.pack("!BBBBBBBB8s4s", 0, op, V1_CODE[state], hello & 0xFF, hold & 0xFF, prio & 0xFF,
                       group & 0xFF, 0, auth, socket.inet_aton(vip or "0.0.0.0"))


def decode_v1(data: bytes) -> dict | None:
    if len(data) < 20 or data[0] != 0:
        return None
    _, op, st, hello, hold, prio, group, _, auth, vip = struct.unpack("!BBBBBBBB8s4s", data[:20])
    state = next((k for k, v in V1_CODE.items() if v == st), None)
    if state is None or op not in OPS:
        return None
    return {"version": 1, "op": op, "state": state, "hello": float(hello), "hold": float(hold), "prio": prio,
            "group": group, "auth": auth, "vip": socket.inet_ntoa(vip), "ident": b""}


def encode_v2(op: int, state: str, group: int, ident: bytes, prio: int, hello: float, hold: float, vip: str,
              auth: bytes) -> bytes:
    """Version 2: the group state TLV (type 1, length 40: version 2, op code,
    state, IP version 4, group (2 octets), identifier (the sender's MAC,
    6 octets), priority (4), hello and hold time in milliseconds (4 each),
    the virtual address in 16 octets), then the text authentication TLV
    (type 3, length 8)."""
    body = struct.pack("!BBBBH6sIII16s", 2, op, V2_CODE[state], 4, group & 0xFFFF, ident[:6].ljust(6, b"\0"),
                       prio, int(round(hello * 1000)), int(round(hold * 1000)),
                       socket.inet_aton(vip or "0.0.0.0").ljust(16, b"\0"))
    return bytes((TLV_GROUP, len(body))) + body + bytes((TLV_TEXT_AUTH, 8)) + auth[:8].ljust(8, b"\0")


def decode_v2(data: bytes) -> dict | None:
    out: dict | None = None
    auth = None
    i = 0
    while i + 2 <= len(data):
        t, ln = data[i], data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if len(val) < ln:
            break
        if t == TLV_GROUP and ln >= 40:
            ver, op, st, ipver, group, ident, prio, hello, hold, vip = struct.unpack("!BBBBH6sIII16s", val[:40])
            state = next((k for k, v in V2_CODE.items() if v == st), None)
            if ver != 2 or ipver != 4 or state is None or op not in OPS:
                return None
            out = {"version": 2, "op": op, "state": state, "group": group, "ident": ident, "prio": prio,
                   "hello": hello / 1000, "hold": hold / 1000, "vip": socket.inet_ntoa(vip[:4])}
        elif t == TLV_TEXT_AUTH:
            auth = val[:8].ljust(8, b"\0")
        elif t == TLV_MD5_AUTH:
            auth = b"md5"
        i += 2 + ln
    if out is not None:
        out["auth"] = auth if auth is not None else b"\0" * 8
    return out


def decode(data: bytes) -> dict | None:
    return decode_v1(data) if data[:1] == b"\0" else decode_v2(data)


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _mac(text: str) -> bytes:
    return bytes(int(x, 16) for x in text.split(":"))


def mcast_mac(ip: str) -> str:
    a = socket.inet_aton(ip)
    return "01:00:5e:%02x:%02x:%02x" % (a[1] & 0x7F, a[2], a[3])


def udp_frame(src_mac: str, src_ip: str, dst_ip: str, payload: bytes, ident: int = 0) -> bytes:
    """Ethernet + IPv4 (TTL 1, as HSRP sends) + UDP 1985 -> 1985, with both
    checksums: what the speaker puts on the wire through a packet socket."""
    udp_len = 8 + len(payload)
    src, dst = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    pseudo = src + dst + struct.pack("!BBH", 0, 17, udp_len)
    udp = struct.pack("!HHHH", PORT, PORT, udp_len, 0) + payload
    c = _csum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", c) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0xC0, 20 + udp_len, ident & 0xFFFF, 0, 1, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return _mac(mcast_mac(dst_ip)) + _mac(src_mac) + b"\x08\x00" + ip + udp


def garp_frame(mac: str, ip: str) -> bytes:
    """A gratuitous ARP request: who has <vip>, tell <vip>, from the virtual
    MAC to everyone, so the switches and the PCs learn where it is now."""
    m, a = _mac(mac), socket.inet_aton(ip)
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, m, a, b"\0" * 6, a)
    return b"\xff" * 6 + m + b"\x08\x06" + arp + b"\0" * 18


# ------------------------------------------------------------------ configuration
class ConfError(Exception):
    pass


def new_group(iface: str, group: int, version: int) -> dict:
    return {"iface": iface, "group": group, "version": version, "vip": "", "secondary": [], "prio": PRIORITY,
            "preempt": False, "delay": 0, "hello": float(HELLO), "hold": float(HOLD), "timers_set": False,
            "auth": None, "tracks": [], "name": ""}


def parse_conf(text: str) -> list[dict]:
    """IOS's interface and standby lines -> one dict per group. Raises
    ConfError naming the line for anything it does not take."""
    groups: dict[tuple[str, int], dict] = {}
    versions: dict[str, int] = {}
    iface = ""
    lines: list[tuple[int, str, list[str]]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("!")[0].split("#")[0].strip()
        if not line:
            continue
        w = line.split()
        if w[0] == "interface" and len(w) == 2:
            iface = w[1]
            continue
        if w[0] != "standby":
            raise ConfError(f"line {n}: only 'interface <name>' and 'standby ...' lines: {line}")
        if not iface:
            raise ConfError(f"line {n}: a standby line before any 'interface <name>'")
        if len(w) == 3 and w[1] == "version":
            if w[2] not in ("1", "2"):
                raise ConfError(f"line {n}: standby version 1 or 2")
            versions[iface] = int(w[2])
            continue
        lines.append((n, iface, w[1:]))
    for n, iface, w in lines:
        ver = versions.get(iface, 1)
        top = 4095 if ver == 2 else 255
        g = 0
        if w and w[0].isdigit():
            g = int(w[0])
            w = w[1:]
            if g > top:
                raise ConfError(f"line {n}: group {g}: version {ver} takes 0 to {top}")
        if not w:
            raise ConfError(f"line {n}: incomplete")
        cfg = groups.setdefault((iface, g), new_group(iface, g, ver))
        word, rest = w[0], w[1:]
        try:
            if word == "ip":
                if rest and rest[-1] == "secondary":
                    cfg["secondary"].append(str(ipaddress.IPv4Address(rest[0])))
                elif rest:
                    cfg["vip"] = str(ipaddress.IPv4Address(rest[0]))
            elif word == "priority":
                p = int(rest[0])
                if not 0 <= p <= 255:
                    raise ValueError
                cfg["prio"] = p
            elif word == "preempt":
                cfg["preempt"] = True
                if rest[:2] == ["delay", "minimum"]:
                    cfg["delay"] = int(rest[2])
                elif rest:
                    raise ValueError
            elif word == "timers":
                hello, hold = int(rest[0]), int(rest[1])
                if not (1 <= hello <= 254 and 2 <= hold <= 255 and hold > hello):
                    raise ConfError(f"line {n}: timers <hello 1-254> <hold 2-255>, hold more than hello")
                cfg["hello"], cfg["hold"], cfg["timers_set"] = float(hello), float(hold), True
            elif word == "authentication":
                if rest[:1] == ["md5"]:
                    raise ConfError(f"line {n}: MD5 authentication is not in winlab-hsrpd (text only)")
                text = rest[1] if rest[:1] == ["text"] else rest[0]
                if len(text) > 8:
                    raise ConfError(f"line {n}: the authentication text is up to 8 characters")
                cfg["auth"] = text
            elif word == "track":
                dec = DECREMENT
                if rest[0] == "object":   # a track object of winlab-slad's (IOS: standby <g> track <n>)
                    rest = [f"object:{int(rest[1])}"] + rest[2:]
                if len(rest) >= 3 and rest[1] == "decrement":
                    dec = int(rest[2])
                cfg["tracks"].append({"iface": rest[0], "decrement": dec})
            elif word == "name":
                cfg["name"] = rest[0]
            else:
                raise ConfError(f"line {n}: standby {word} is not in winlab-hsrpd")
        except (IndexError, ValueError):
            raise ConfError(f"line {n}: standby {' '.join(w)}: incomplete or not a valid value") from None
    for (iface, g), cfg in groups.items():
        cfg["version"] = versions.get(iface, 1)
    return sorted(groups.values(), key=lambda c: (c["iface"], c["group"]))


# ------------------------------------------------------------------ the state machine
def _key(prio: int, ip: str) -> tuple[int, int]:
    """Who wins: the higher priority, then the higher address (RFC 2281)."""
    try:
        return prio, int(ipaddress.IPv4Address(ip))
    except ValueError:
        return prio, 0


class Group:
    """One HSRP group on one interface. It never touches the network
    itself: send(op) puts a packet out, on_active()/on_inactive() move the
    virtual address, log(text) says what changed. tick(now) runs the
    timers; receive(msg, src_ip, now) takes what arrived."""

    def __init__(self, cfg: dict, send, on_active=None, on_inactive=None, log=None):
        self.cfg = cfg
        self.send, self.log = send, log or (lambda _t: None)
        self.on_active, self.on_inactive = on_active or (lambda: None), on_inactive or (lambda: None)
        self.state = "Init"
        self.my_ip = ""
        self.vip = cfg["vip"]
        self.hello, self.hold = cfg["hello"], cfg["hold"]
        self.active: dict | None = None    # {"ip", "prio", "expires"}
        self.standby: dict | None = None
        self.active_timer = self.standby_timer = 0.0
        self.next_hello = 0.0
        self.started = 0.0
        self.changes = 0
        self.last_change = 0.0
        self.track_down: set[str] = set()
        self.bad_auth = ""

    # -- what it is
    def prio(self) -> int:
        p = self.cfg["prio"] - sum(t["decrement"] for t in self.cfg["tracks"] if t["iface"] in self.track_down)
        return max(0, p)

    def mine(self) -> tuple[int, int]:
        return _key(self.prio(), self.my_ip)

    def _to(self, state: str, now: float) -> None:
        if state == self.state:
            return
        old = self.state
        self.state = state
        self.changes += 1
        self.last_change = now
        self.log(f"%HSRP-5-STATECHANGE: {self.cfg['iface']} Grp {self.cfg['group']} state {old} -> {state}")
        if state == "Active":
            self.active = {"ip": self.my_ip, "prio": self.prio(), "expires": 0.0}
            self.on_active()
            self._hello(now)
        elif old == "Active":
            self.on_inactive()
        if state in ("Speak", "Standby") and old not in ("Speak", "Standby", "Active"):
            self._hello(now)

    def _hello(self, now: float, op: int = OP_HELLO) -> None:
        self.send(op)
        if op == OP_HELLO:
            self.next_hello = now + self.hello

    # -- events
    def start(self, my_ip: str, now: float) -> None:
        """Event a: the group configured on an interface that is up."""
        self.my_ip = my_ip
        self.started = now
        self.active_timer = self.standby_timer = now + self.hold
        self._to("Listen" if self.vip else "Learn", now)

    def stop(self, now: float) -> None:
        """Event b: the group taken away, or its interface went down."""
        if self.state == "Active":
            self.send(OP_RESIGN)
        self.active = self.standby = None
        self._to("Init", now)

    def tick(self, now: float) -> None:
        st = self.state
        if st == "Init":
            return
        if self.active and self.active["ip"] != self.my_ip and now >= self.active_timer:
            self.active = None
        if self.standby and now >= self.standby_timer:
            self.standby = None
        if st == "Listen" and (now >= self.active_timer or now >= self.standby_timer):
            # Event c or d: nobody better is there; speak up.
            if now >= self.active_timer:
                self.active_timer = now + self.hold
            if now >= self.standby_timer:
                self.standby_timer = now + self.hold
            self._to("Speak", now)
        elif st == "Speak" and now >= self.standby_timer:
            self._to("Standby", now)
        if self.state == "Standby" and now >= self.active_timer and not self.active:
            self._to("Active", now)
        if self.state in ("Speak", "Standby", "Active") and now >= self.next_hello:
            self._hello(now)
        if self.state in ("Listen", "Speak", "Standby") and self.active and self._may_preempt(now) \
                and self.mine() > _key(self.active["prio"], self.active["ip"]):
            self._coup(now)

    def _may_preempt(self, now: float) -> bool:
        return self.cfg["preempt"] and now - self.started >= self.cfg["delay"] and bool(self.vip)

    def _coup(self, now: float) -> None:
        self.send(OP_COUP)
        self._to("Active", now)

    def receive(self, msg: dict, src_ip: str, now: float) -> None:
        if msg["group"] != self.cfg["group"] or self.state == "Init" or src_ip == self.my_ip:
            return
        if msg["auth"] != auth_bytes(self.cfg["auth"]):
            if self.bad_auth != src_ip:
                self.log(f"%HSRP-4-BADAUTH: Bad authentication from {src_ip}, group {self.cfg['group']}, "
                         f"remote state {msg['state']}")
            self.bad_auth = src_ip
            return
        self.bad_auth = ""
        theirs = _key(msg["prio"], src_ip)
        if msg["state"] == "Active" and msg["op"] == OP_HELLO:
            if not self.cfg["timers_set"]:
                self.hello, self.hold = msg["hello"] or self.hello, msg["hold"] or self.hold
            if not self.vip and msg["vip"] != "0.0.0.0":
                self.vip = msg["vip"]
                if self.state == "Learn":
                    self._to("Listen", now)
        op, st = msg["op"], msg["state"]
        if op == OP_RESIGN:
            if self.active and self.active["ip"] == src_ip:
                self.active = None
                self.active_timer = now
                if self.state == "Standby":
                    self._to("Active", now)
            return
        if op == OP_COUP:
            if self.state == "Active" and theirs > self.mine():
                self.active = {"ip": src_ip, "prio": msg["prio"], "expires": now + self.hold}
                self.active_timer = now + self.hold
                self._to("Speak", now)
            elif self.state != "Active":
                self.active = {"ip": src_ip, "prio": msg["prio"], "expires": now + self.hold}
                self.active_timer = now + self.hold
            return
        if st == "Active":
            if self.state == "Active":
                if theirs > self.mine():
                    self.active = {"ip": src_ip, "prio": msg["prio"], "expires": now + self.hold}
                    self.active_timer = now + self.hold
                    self._to("Speak", now)
                else:
                    self.send(OP_COUP)
                return
            self.active = {"ip": src_ip, "prio": msg["prio"], "expires": now + self.hold}
            self.active_timer = now + self.hold
            if self.standby and self.standby["ip"] == src_ip:
                self.standby = None
            if self.state in ("Listen", "Speak", "Standby") and self._may_preempt(now) and self.mine() > theirs:
                self._coup(now)
        elif st == "Standby":
            self.standby = {"ip": src_ip, "prio": msg["prio"]}
            self.standby_timer = now + self.hold
            if self.active and self.active["ip"] == src_ip:
                self.active = None
            if self.state == "Standby" and theirs > self.mine():
                self._to("Listen", now)
            elif self.state == "Speak":
                self._to("Listen" if theirs > self.mine() else "Standby", now)
        elif st == "Speak":
            if self.state in ("Speak", "Standby") and theirs > self.mine():
                self.standby_timer = now + self.hold
                self._to("Listen", now)

    def payload(self, op: int, ident: bytes = b"") -> bytes:
        auth = auth_bytes(self.cfg["auth"])
        state = self.state if self.state != "Init" else "Init"
        if self.cfg["version"] == 2:
            return encode_v2(op, state, self.cfg["group"], ident, self.prio(), self.hello, self.hold, self.vip, auth)
        return encode_v1(op, state, int(self.hello), int(self.hold), self.prio(), self.cfg["group"], auth, self.vip)

    def status(self, now: float) -> dict:
        def left(t):
            return round(max(0.0, t - now), 3)
        return {"iface": self.cfg["iface"], "group": self.cfg["group"], "version": self.cfg["version"],
                "state": self.state, "prio": self.prio(), "cfg_prio": self.cfg["prio"], "preempt": self.cfg["preempt"],
                "delay": self.cfg["delay"], "hello": self.hello, "hold": self.hold, "vip": self.vip,
                "secondary": list(self.cfg["secondary"]), "vmac": vmac(self.cfg["version"], self.cfg["group"]),
                "my_ip": self.my_ip,
                "active": ("local" if self.state == "Active" else self.active["ip"]) if self.active else "",
                "active_prio": self.active["prio"] if self.active else 0,
                "active_expires": left(self.active_timer) if self.active and self.state != "Active" else 0,
                "standby": self.standby["ip"] if self.standby else ("local" if self.state == "Standby" else ""),
                "standby_prio": self.standby["prio"] if self.standby else 0,
                "standby_expires": left(self.standby_timer) if self.standby else 0,
                "next_hello": left(self.next_hello) if self.state in ("Speak", "Standby", "Active") else 0,
                "changes": self.changes, "since": round(now - self.last_change, 1) if self.changes else 0,
                "tracks": [{"iface": t["iface"], "decrement": t["decrement"], "up": t["iface"] not in self.track_down}
                           for t in self.cfg["tracks"]],
                "name": self.cfg["name"], "auth_set": self.cfg["auth"] is not None, "bad_auth": self.bad_auth}


# ------------------------------------------------------------------ show standby
def _hms(sec: float) -> str:
    s = int(sec)
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def show_brief(groups: list[dict], names: dict | None = None, short=None) -> str:
    names = names or {}
    short = short or (lambda n: n)
    out = ["                     P indicates configured to preempt.", "                     |",
           f"{'Interface':<12}{'Grp':<5}{'Pri':<4}{'P':<2}{'State':<8}{'Active':<16}{'Standby':<16}Virtual IP"]
    for g in groups:
        name = short(names.get(g["iface"], g["iface"]))
        act = g["active"] or "unknown"
        sby = g["standby"] or "unknown"
        out.append(f"{name:<12}{g['group']:<5}{g['prio']:<4}{'P' if g['preempt'] else ' ':<2}{g['state']:<8}"
                   f"{act:<16}{sby:<16}{g['vip'] or 'unknown'}")
    return "\n".join(out)


def show_detail(groups: list[dict], names: dict | None = None, short=None) -> str:
    names = names or {}
    out = []
    for g in groups:
        name = names.get(g["iface"], g["iface"])
        mac = cisco_mac(g["vmac"])
        out += [f"{name} - Group {g['group']}" + (" (version 2)" if g["version"] == 2 else ""),
                f"  State is {g['state']}"]
        if g["changes"]:
            out.append(f"    {g['changes']} state change{'s' if g['changes'] != 1 else ''}, "
                       f"last state change {_hms(g['since'])}")
        out.append(f"  Virtual IP address is {g['vip'] or 'unknown'}")
        out += [f"    Secondary virtual IP address {s}" for s in g["secondary"]]
        out.append(f"  Active virtual MAC address is {mac if g['active'] else 'unknown'}"
                   + (" (MAC In Use)" if g["state"] == "Active" else " (MAC Not In Use)" if g["active"] else ""))
        out.append(f"    Local virtual MAC address is {mac} (v{g['version']} default)")
        out.append(f"  Hello time {g['hello']:g} sec, hold time {g['hold']:g} sec")
        if g["next_hello"]:
            out.append(f"    Next hello sent in {g['next_hello']:.3f} secs")
        out.append("  Preemption " + ("enabled" + (f", delay min {g['delay']} secs" if g["delay"] else "")
                                      if g["preempt"] else "disabled"))
        if g["active"] == "local":
            out.append("  Active router is local")
        elif g["active"]:
            out.append(f"  Active router is {g['active']}, priority {g['active_prio']} "
                       f"(expires in {g['active_expires']:.3f} sec)")
        else:
            out.append("  Active router is unknown")
        if g["standby"] == "local":
            out.append("  Standby router is local")
        elif g["standby"]:
            out.append(f"  Standby router is {g['standby']}, priority {g['standby_prio']} "
                       f"(expires in {g['standby_expires']:.3f} sec)")
        else:
            out.append("  Standby router is unknown")
        out.append(f"  Priority {g['prio']} (configured {g['cfg_prio']})")
        for t in g["tracks"]:
            what = (f"object {t['iface'][7:]}" if t["iface"].startswith("object:")
                    else f"interface {names.get(t['iface'], t['iface'])}")
            out.append(f"    Track {what} state {'Up' if t['up'] else 'Down'} decrement {t['decrement']}")
        if g.get("bad_auth"):
            out.append(f"  Authentication mismatch with {g['bad_auth']}: its hellos are ignored")
        out.append(f"  Group name is \"{g['name'] or 'hsrp-' + (short or str)(name) + '-' + str(g['group'])}\""
                   + ("" if g["name"] else " (default)"))
    return "\n".join(out)


# ------------------------------------------------------------------ the running speaker
def _run(*args: str) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def iface_info(name: str) -> tuple[str, int, str, bool]:
    """(address, prefix length, MAC, up) of a Linux interface."""
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", _run("ip", "-o", "-4", "addr", "show", "dev", name))
    try:
        with open(f"/sys/class/net/{name}/address") as f:
            mac = f.read().strip()
        with open(f"/sys/class/net/{name}/operstate") as f:
            oper = f.read().strip()
        with open(f"/sys/class/net/{name}/flags") as f:
            up = int(f.read().strip(), 16) & 1 == 1
    except OSError:
        return "", 0, "", False
    up = up and oper in ("up", "unknown")
    return (m.group(1), int(m.group(2)), mac, up) if m else ("", 0, mac, up)


SLA_STATE = "/run/winlab-sla.json"


def link_up(name: str) -> bool:
    """An interface's link, or (object:<n>) a track object of winlab-slad's:
    Down when the program is not running or has no such object."""
    if name.startswith("object:"):
        try:
            with open(SLA_STATE) as f:
                return json.load(f)["track"][name[7:]]["state"] == "Up"
        except (OSError, ValueError, KeyError, TypeError):
            return False
    try:
        with open(f"/sys/class/net/{name}/operstate") as f:
            return f.read().strip() in ("up", "unknown")
    except OSError:
        return False


class Speaker:
    def __init__(self, conf: str, state_file: str = STATE_FILE, log_file: str = ""):
        self.conf, self.state_file, self.log_file = conf, state_file, log_file
        self.groups: dict[tuple[str, int], Group] = {}
        self.tx: dict[str, socket.socket] = {}
        self.joined: set[tuple[str, str]] = set()
        self.reload_wanted = False
        self.stop_wanted = False
        self.rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rx.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_PKTINFO", 8), 1)
        self.rx.bind(("", PORT))
        self.ident = 0

    def log(self, text: str) -> None:
        line = time.strftime("%b %d %H:%M:%S ") + text
        print(line, flush=True)
        if self.log_file:
            try:
                with open(self.log_file, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def _macvlan(self, g: Group) -> str:
        return f"hs{socket.if_nametoindex(g.cfg['iface'])}g{g.cfg['group']}"[:15]

    def _send(self, g: Group, op: int) -> None:
        iface = g.cfg["iface"]
        ip, _, mac, up = iface_info(iface)
        if not ip or not up:
            return
        src_mac = g.status(0)["vmac"] if g.state == "Active" else mac
        dst = V2_GROUP if g.cfg["version"] == 2 else V1_GROUP
        self.ident = (self.ident + 1) & 0xFFFF
        frame = udp_frame(src_mac, ip, dst, g.payload(op, _mac(mac)), self.ident)
        try:
            s = self.tx.get(iface)
            if s is None:
                s = self.tx[iface] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                s.bind((iface, 0))
            s.send(frame)
        except OSError as e:
            self.tx.pop(iface, None)
            self.log(f"%HSRP-3-SEND: {iface}: {e}")

    def _active(self, g: Group) -> None:
        iface = g.cfg["iface"]
        _, plen, _, _ = iface_info(iface)
        mv = self._macvlan(g)
        if not os.path.exists(f"/sys/class/net/{mv}"):
            self._prepare(g)
        _run("ip", "link", "set", "dev", mv, "up")
        for a in [g.vip] + g.cfg["secondary"]:
            if a:
                _run("ip", "addr", "replace", f"{a}/{plen or 32}", "dev", mv)
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((iface, 0))
            for a in [g.vip] + g.cfg["secondary"]:
                if a:
                    for _ in range(2):
                        s.send(garp_frame(vmac(g.cfg["version"], g.cfg["group"]), a))
            s.close()
        except OSError as e:
            self.log(f"%HSRP-3-ARP: {iface}: {e}")

    def _inactive(self, g: Group) -> None:
        mv = self._macvlan(g)
        _run("ip", "addr", "flush", "dev", mv)
        _run("ip", "link", "set", "dev", mv, "down")

    def _prepare(self, g: Group) -> None:
        iface = g.cfg["iface"]
        mv = self._macvlan(g)
        _run("ip", "link", "add", mv, "link", iface, "type", "macvlan", "mode", "bridge")
        _run("ip", "link", "set", "dev", mv, "down")
        _run("ip", "link", "set", "dev", mv, "address", vmac(g.cfg["version"], g.cfg["group"]))
        # Only the virtual MAC answers ARP for the virtual address, from the
        # Active router, and the real interface asks with its own address, so
        # no PC ever learns the virtual address at the real MAC.
        for path, val in ((f"/proc/sys/net/ipv4/conf/{iface}/arp_ignore", "1"),
                          (f"/proc/sys/net/ipv4/conf/{iface}/arp_announce", "2"),
                          (f"/proc/sys/net/ipv4/conf/{mv}/rp_filter", "0")):
            try:
                with open(path, "w") as f:
                    f.write(val)
            except OSError:
                pass

    def _join(self, iface: str, ip: str) -> None:
        for grp in (V1_GROUP, V2_GROUP):
            if (iface, grp) in self.joined:
                continue
            try:
                mreq = struct.pack("!4s4s", socket.inet_aton(grp), socket.inet_aton(ip))
                self.rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                self.joined.add((iface, grp))
            except OSError:
                pass

    def load(self) -> None:
        try:
            with open(self.conf) as f:
                cfgs = parse_conf(f.read())
        except (OSError, ConfError) as e:
            self.log(f"%HSRP-3-CONFIG: {self.conf}: {e}; keeping what runs")
            return
        now = time.monotonic()
        want = {(c["iface"], c["group"]): c for c in cfgs}
        for key in [k for k in self.groups if k not in want or want[k]["version"] != self.groups[k].cfg["version"]]:
            g = self.groups.pop(key)
            g.stop(now)
            _run("ip", "link", "del", self._macvlan(g))
        for key, cfg in want.items():
            g = self.groups.get(key)
            if g is None:
                g = Group(cfg, None, log=self.log)
                g.send = (lambda op, g=g: self._send(g, op))
                g.on_active = (lambda g=g: self._active(g))
                g.on_inactive = (lambda g=g: self._inactive(g))
                try:
                    self._prepare(g)
                except OSError:
                    self.log(f"%HSRP-3-CONFIG: no interface {cfg['iface']}")
                    continue
                self.groups[key] = g
            else:
                old_vips = [g.vip] + g.cfg["secondary"]
                g.cfg = cfg
                if cfg["vip"]:
                    g.vip = cfg["vip"]
                if cfg["timers_set"] or not g.cfg["timers_set"]:
                    g.hello, g.hold = cfg["hello"], cfg["hold"]
                if g.state == "Active" and old_vips != [g.vip] + cfg["secondary"]:
                    self._inactive(g)
                    self._active(g)
        self.log(f"%HSRP-6-CONFIG: {len(self.groups)} group(s) from {self.conf}")

    def _poll_links(self, now: float) -> None:
        for g in self.groups.values():
            ip, _, _, up = iface_info(g.cfg["iface"])
            if g.state == "Init" and ip and up:
                self._join(g.cfg["iface"], ip)
                g.start(ip, now)
            elif g.state != "Init" and (not ip or not up):
                g.stop(now)
            down = {t["iface"] for t in g.cfg["tracks"] if not link_up(t["iface"])}
            if down != g.track_down:
                for t in g.cfg["tracks"]:
                    if (t["iface"] in down) != (t["iface"] in g.track_down):
                        self.log(f"%TRACK-6-STATE: {g.cfg['iface']} Grp {g.cfg['group']}: interface {t['iface']} "
                                 f"{'Up -> Down' if t['iface'] in down else 'Down -> Up'}, priority now "
                                 f"{g.cfg['prio'] - sum(x['decrement'] for x in g.cfg['tracks'] if x['iface'] in down)}")
                g.track_down = down

    def _write_state(self, now: float) -> None:
        data = {"pid": os.getpid(), "updated": time.time(), "conf": self.conf,
                "groups": [g.status(now) for _, g in sorted(self.groups.items())]}
        tmp = self.state_file + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.state_file)
        except OSError:
            pass

    def run(self) -> None:
        signal.signal(signal.SIGHUP, lambda *_: setattr(self, "reload_wanted", True))
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "stop_wanted", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "stop_wanted", True))
        self.load()
        ifindex = {}
        last_poll = last_write = 0.0
        while not self.stop_wanted:
            now = time.monotonic()
            if self.reload_wanted:
                self.reload_wanted = False
                self.load()
                last_poll = 0.0
            if now - last_poll >= 1.0:
                self._poll_links(now)
                ifindex = {}
                for g in self.groups.values():
                    try:
                        ifindex[socket.if_nametoindex(g.cfg["iface"])] = g.cfg["iface"]
                    except OSError:
                        pass
                last_poll = now
            r, _, _ = select.select([self.rx], [], [], 0.1)
            if r:
                try:
                    data, anc, _, (src, _) = self.rx.recvmsg(1500, 256)
                except OSError:
                    data, anc, src = b"", [], ""
                idx = next((struct.unpack("i", d[:4])[0] for lvl, typ, d in anc
                            if lvl == socket.IPPROTO_IP and typ == getattr(socket, "IP_PKTINFO", 8)), 0)
                iface = ifindex.get(idx)
                msg = decode(data) if iface else None
                if msg:
                    for g in self.groups.values():
                        if g.cfg["iface"] == iface and g.cfg["version"] == msg["version"]:
                            g.receive(msg, src, time.monotonic())
            now = time.monotonic()
            for g in self.groups.values():
                g.tick(now)
            if now - last_write >= 0.5:
                self._write_state(now)
                last_write = now
        now = time.monotonic()
        for g in self.groups.values():
            g.stop(now)
            _run("ip", "link", "del", self._macvlan(g))
        self.groups.clear()
        self._write_state(now)
        self.log("%HSRP-6-STOP: winlab-hsrpd stopped")


def main(argv: list[str]) -> int:
    conf, state_file, log_file = CONF_FILE, STATE_FILE, ""
    cmd = "run"
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-c", "--conf") and i + 1 < len(argv):
            conf, i = argv[i + 1], i + 2
        elif a in ("-s", "--state") and i + 1 < len(argv):
            state_file, i = argv[i + 1], i + 2
        elif a in ("-l", "--log") and i + 1 < len(argv):
            log_file, i = argv[i + 1], i + 2
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            rest.append(a)
            i += 1
    if rest:
        cmd = rest[0]
    if cmd == "check":
        try:
            with open(conf) as f:
                groups = parse_conf(f.read())
        except (OSError, ConfError) as e:
            print(f"{conf}: {e}")
            return 1
        for g in groups:
            print(f"{g['iface']} group {g['group']} version {g['version']}: virtual {g['vip'] or '(learned)'}, "
                  f"priority {g['prio']}, preempt {'yes' if g['preempt'] else 'no'}, "
                  f"timers {g['hello']:g}/{g['hold']:g}")
        return 0
    if cmd == "show":
        try:
            with open(state_file) as f:
                data = json.load(f)
        except (OSError, ValueError):
            print("winlab-hsrpd is not running (no state file)")
            return 1
        print(show_brief(data["groups"]) if rest[1:2] == ["brief"] else show_detail(data["groups"]))
        return 0
    if cmd != "run":
        print("usage: winlab-hsrpd [-c conf] [-s state] [-l log] [run | show [brief] | check]")
        return 2
    Speaker(conf, state_file, log_file).run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
