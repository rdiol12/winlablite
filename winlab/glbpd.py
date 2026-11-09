#!/usr/bin/env python3
"""winlab-glbpd: a small GLBP speaker, winlab's own code (MIT, like the rest
of winlab), so a Linux router can stand in a GLBP group with another copy
of itself.

GLBP (Gateway Load Balancing Protocol) is Cisco's own: no open-source router
speaks it and Linux has nothing like it, so this is one, written the way
winlab-hsrpd is (winlab/hsrpd.py). Its packets follow the layout Wireshark's
GLBP dissector decodes (UDP 3222 to 224.0.0.102, a 12-octet header with
version 1, the group and the sender's MAC, then TLVs: Hello (type 1),
Request/Response (type 2), Authentication (type 3)); Cisco has published no
specification. Wireshark names seven octets of the Request/Response TLV
"unknown": winlab-glbpd sends a reserved octet and the forwarder owner's MAC
there, which is how its AVG says which router it gave a forwarder to. Two
copies of winlab-glbpd interoperate; it has not been tried against a Cisco
router, and nothing says a Cisco router would take its forwarder
assignments.

What it does, as IOS does:

* one virtual gateway (VG) per group, elected like HSRP's Active router:
  the highest priority (100 by default), then the highest address; the
  Active VG (AVG) and a Standby VG; hello 3 s, hold 10 s by default; AVG
  preemption off by default (``glbp <g> preempt``);
* virtual forwarders (AVF): the AVG gives each member, itself first, one of
  up to four virtual MACs 0007.b400.XXYY (XX the group, YY the forwarder);
  a member forwards frames sent to its virtual MAC on a macvlan that carries
  it (as winlab-hsrpd and FRRouting's vrrpd do);
* load balancing: the AVG answers every ARP request for the virtual address
  itself, each time with a virtual MAC of the next forwarder
  (``round-robin``, the default), in proportion to the members' weighting
  (``weighted``), or always the same one for the same host
  (``host-dependent``); so the PCs of one subnet share the routers while all
  of them use one gateway address;
* a member that goes silent: its forwarder is taken over by the AVG, which
  stops handing that virtual MAC out (IOS waits the redirect time, 600 s,
  first; here it is at once), and gives it back when the member returns.

Not here: MD5 authentication (plain text only), ``weighting track``,
``forwarder preempt`` settings, ``client-cache``, IPv6, millisecond
timers. Usage::

    winlab-glbpd -c /etc/winlab-glbp.conf      # run (SIGHUP reloads, SIGTERM leaves the group)
    winlab-glbpd show [brief]                   # IOS's show glbp, from the state file
    winlab-glbpd check -c /etc/winlab-glbp.conf

The configuration file is IOS's own lines under the Linux interface::

    interface eth1
     glbp 1 ip 10.80.0.1
     glbp 1 priority 110
     glbp 1 preempt
     glbp 1 load-balancing round-robin
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
import zlib

PORT = 3222
GROUP_ADDR = "224.0.0.102"
STATE_FILE = "/run/winlab-glbp.json"
CONF_FILE = "/etc/winlab-glbp.conf"
HELLO, HOLD, PRIORITY, WEIGHT = 3, 10, 100, 100
REDIRECT, TIMEOUT = 600, 14400
MAX_FWD = 4
TLV_HELLO, TLV_REQRESP, TLV_AUTH = 1, 2, 3
# Wireshark's value strings for the VG and VF states.
STATE_CODE = {"Disabled": 0x01, "Init": 0x02, "Listen": 0x04, "Speak": 0x08, "Standby": 0x10, "Active": 0x20}
CODE_STATE = {v: k for k, v in STATE_CODE.items()}
BALANCE = ("round-robin", "weighted", "host-dependent")


def vmac(group: int, fwd: int) -> str:
    """0007.b400.XXYY as aa:bb:..: XX the group (10 bits across two octets
    for groups above 255), YY the forwarder."""
    return "00:07:b4:%02x:%02x:%02x" % ((group >> 8) & 0x03, group & 0xFF, fwd & 0xFF)


def cisco_mac(mac: str) -> str:
    h = mac.replace(":", "").lower()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


def _mac(text: str) -> bytes:
    return bytes(int(x, 16) for x in text.split(":"))


def _mac_text(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


# ------------------------------------------------------------------ packets
def encode(group: int, owner: str, hello: dict, fwds: list[dict], auth: str | None = None) -> bytes:
    """The header, a Hello TLV, one Request/Response TLV per forwarder, and
    (with a key) a plain-text Authentication TLV."""
    out = struct.pack("!BBHH6s", 1, 0, group & 0xFFFF, 0, _mac(owner))
    body = struct.pack("!BBBBHIIHHHBB4s", 0, STATE_CODE[hello["state"]], 0, hello["prio"] & 0xFF, 0,
                       int(hello["hello"] * 1000), int(hello["hold"] * 1000), hello.get("redirect", REDIRECT),
                       hello.get("timeout", TIMEOUT), 0, 1, 4, socket.inet_aton(hello["vip"] or "0.0.0.0"))
    out += bytes((TLV_HELLO, 2 + len(body))) + body
    for f in fwds:
        body = struct.pack("!BBBBBB6s6s", f["fwd"] & 0xFF, STATE_CODE[f["state"]], 0, f.get("prio", 167) & 0xFF,
                           f.get("weight", WEIGHT) & 0xFF, 0, _mac(f["owner"]) if f.get("owner") else b"\0" * 6,
                           _mac(f["vmac"]))
        # Wireshark's layout: forwarder, state, unknown, priority, weight, seven unknown octets, virtual MAC;
        # the seven here are a reserved octet and the owner's MAC (see above).
        out += bytes((TLV_REQRESP, 2 + len(body))) + body
    if auth:
        raw = auth.encode()[:8]
        out += bytes((TLV_AUTH, 4 + len(raw), 1, len(raw))) + raw
    return out


def decode(data: bytes) -> dict | None:
    if len(data) < 12 or data[0] != 1:
        return None
    _, _, group, _, owner = struct.unpack("!BBHH6s", data[:12])
    msg = {"group": group, "owner": _mac_text(owner), "hello": None, "fwds": [], "auth": None}
    i = 12
    while i + 2 <= len(data):
        t, ln = data[i], data[i + 1]
        if ln < 2 or i + ln > len(data):
            break
        val = data[i + 2:i + ln]
        if t == TLV_HELLO and len(val) >= 26:
            _, st, _, prio, _, hello, hold, red, tmo, _, atype, alen, vip = struct.unpack("!BBBBHIIHHHBB4s", val[:26])
            if st not in CODE_STATE or atype != 1:
                return None
            msg["hello"] = {"state": CODE_STATE[st], "prio": prio, "hello": hello / 1000, "hold": hold / 1000,
                            "redirect": red, "timeout": tmo, "vip": socket.inet_ntoa(vip)}
        elif t == TLV_REQRESP and len(val) >= 18:
            fwd, st, _, prio, weight, _, own, mac = struct.unpack("!BBBBBB6s6s", val[:18])
            msg["fwds"].append({"fwd": fwd, "state": CODE_STATE.get(st, "Init"), "prio": prio, "weight": weight,
                                "owner": _mac_text(own) if any(own) else "", "vmac": _mac_text(mac)})
        elif t == TLV_AUTH and len(val) >= 2:
            msg["auth"] = val[2:2 + val[1]].decode(errors="replace") if val[0] == 1 else ("md5" if val[0] else None)
        i += ln
    return msg if msg["hello"] else None


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def udp_frame(src_mac: str, src_ip: str, payload: bytes, ident: int = 0) -> bytes:
    """Ethernet + IPv4 (TTL 1) + UDP 3222 -> 3222 to 224.0.0.102."""
    udp_len = 8 + len(payload)
    src, dst = socket.inet_aton(src_ip), socket.inet_aton(GROUP_ADDR)
    udp = struct.pack("!HHHH", PORT, PORT, udp_len, 0) + payload
    c = _csum(src + dst + struct.pack("!BBH", 0, 17, udp_len) + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", c) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0xC0, 20 + udp_len, ident & 0xFFFF, 0, 1, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    a = socket.inet_aton(GROUP_ADDR)
    dst_mac = bytes((0x01, 0x00, 0x5E, a[1] & 0x7F, a[2], a[3]))
    return dst_mac + _mac(src_mac) + b"\x08\x00" + ip + udp


def arp_reply(vmac_: str, vip: str, to_mac: str, to_ip: str) -> bytes:
    """The AVG's answer for the virtual address: this forwarder's MAC."""
    m, t = _mac(vmac_), _mac(to_mac)
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, m, socket.inet_aton(vip), t, socket.inet_aton(to_ip))
    return t + m + b"\x08\x06" + arp + b"\0" * 18


def parse_arp(frame: bytes) -> dict | None:
    """An ARP request in an Ethernet frame -> sender MAC and IP, target IP."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    htype, ptype, hl, pl, op, sha, spa, _tha, tpa = struct.unpack("!HHBBH6s4s6s4s", frame[14:42])
    if htype != 1 or ptype != 0x0800 or op != 1:
        return None
    return {"mac": _mac_text(sha), "ip": socket.inet_ntoa(spa), "target": socket.inet_ntoa(tpa)}


# ------------------------------------------------------------------ configuration
class ConfError(Exception):
    pass


def new_group(iface: str, group: int) -> dict:
    return {"iface": iface, "group": group, "vip": "", "prio": PRIORITY, "preempt": False, "delay": 0,
            "hello": float(HELLO), "hold": float(HOLD), "balance": "round-robin", "weight": WEIGHT,
            "auth": None, "name": "", "redirect": REDIRECT, "timeout": TIMEOUT}


def parse_conf(text: str) -> list[dict]:
    groups: dict[tuple[str, int], dict] = {}
    iface = ""
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("!")[0].split("#")[0].strip()
        if not line:
            continue
        w = line.split()
        if w[0] == "interface" and len(w) == 2:
            iface = w[1]
            continue
        if w[0] != "glbp" or len(w) < 3 or not w[1].isdigit():
            raise ConfError(f"line {n}: only 'interface <name>' and 'glbp <group> ...' lines: {line}")
        if not iface:
            raise ConfError(f"line {n}: a glbp line before any 'interface <name>'")
        g = int(w[1])
        if g > 1023:
            raise ConfError(f"line {n}: group {g}: 0 to 1023")
        cfg = groups.setdefault((iface, g), new_group(iface, g))
        word, rest = w[2], w[3:]
        try:
            if word == "ip":
                if rest:
                    cfg["vip"] = str(ipaddress.IPv4Address(rest[0]))
            elif word == "priority":
                p = int(rest[0])
                if not 1 <= p <= 255:
                    raise ValueError
                cfg["prio"] = p
            elif word == "preempt":
                cfg["preempt"] = True
                if rest[:2] == ["delay", "minimum"]:
                    cfg["delay"] = int(rest[2])
                elif rest:
                    raise ValueError
            elif word == "timers":
                if rest[:1] == ["redirect"]:
                    cfg["redirect"], cfg["timeout"] = int(rest[1]), int(rest[2])
                else:
                    hello, hold = int(rest[0]), int(rest[1])
                    if not (1 <= hello <= 60 and hello < hold <= 180):
                        raise ConfError(f"line {n}: timers <hello 1-60> <hold>, hold more than hello")
                    cfg["hello"], cfg["hold"] = float(hello), float(hold)
            elif word == "load-balancing":
                if rest[0] not in BALANCE:
                    raise ValueError
                cfg["balance"] = rest[0]
            elif word == "weighting":
                cfg["weight"] = int(rest[0])
                if not 1 <= cfg["weight"] <= 254:
                    raise ValueError
            elif word == "authentication":
                if rest[:1] == ["md5"]:
                    raise ConfError(f"line {n}: MD5 authentication is not in winlab-glbpd (text only)")
                text = rest[1] if rest[:1] == ["text"] else rest[0]
                if len(text) > 8:
                    raise ConfError(f"line {n}: the authentication text is up to 8 characters")
                cfg["auth"] = text
            elif word == "name":
                cfg["name"] = rest[0]
            else:
                raise ConfError(f"line {n}: glbp {word} is not in winlab-glbpd")
        except (IndexError, ValueError):
            raise ConfError(f"line {n}: glbp {' '.join(w[1:])}: incomplete or not a valid value") from None
    return sorted(groups.values(), key=lambda c: (c["iface"], c["group"]))


# ------------------------------------------------------------------ the protocol
def _key(prio: int, ip: str) -> tuple[int, int]:
    try:
        return prio, int(ipaddress.IPv4Address(ip))
    except ValueError:
        return prio, 0


class Group:
    """One GLBP group on one interface, without touching the network:
    send() puts a hello out; forward(vmac, on) starts or stops forwarding
    for a virtual MAC; avg(on) holds or drops the virtual address; log(text)
    says what changed. tick(now) runs the timers, receive(msg, src_ip, now)
    takes a packet, arp(mac) picks the virtual MAC a host is answered with."""

    def __init__(self, cfg: dict, my_mac: str, send=None, forward=None, avg=None, log=None):
        self.cfg = cfg
        self.my_mac = my_mac
        self.my_ip = ""
        self.send = send or (lambda _p: None)
        self.forward = forward or (lambda _m, _on: None)
        self.avg = avg or (lambda _on: None)
        self.log = log or (lambda _t: None)
        self.state = "Init"
        self.vip = cfg["vip"]
        self.peers: dict[str, dict] = {}       # ip -> {"prio", "state", "mac", "expires", "weight"}
        self.fwds: dict[int, dict] = {}        # number -> {"owner", "primary", "vmac", "state_changes", "since"}
        self.mine: set[int] = set()            # forwarders this router forwards for
        self.started = 0.0
        self.next_hello = 0.0
        self.changes = 0
        self.last_change = 0.0
        self.rr = 0
        self.bad_auth = ""

    # -- who wins
    def my_key(self) -> tuple[int, int]:
        return _key(self.cfg["prio"], self.my_ip)

    def _alive(self, now: float) -> dict[str, dict]:
        return {ip: p for ip, p in self.peers.items() if p["expires"] > now}

    def _to(self, state: str, now: float) -> None:
        if state == self.state:
            return
        old, self.state = self.state, state
        self.changes += 1
        self.last_change = now
        self.log(f"%GLBP-6-STATECHANGE: {self.cfg['iface']} Grp {self.cfg['group']} state {old} -> {state}")
        if state == "Active":
            self.avg(True)
        elif old == "Active":
            self.avg(False)

    # -- events
    def start(self, my_ip: str, now: float) -> None:
        self.my_ip = my_ip
        self.started = now
        self.next_hello = now
        self._to("Listen", now)

    def stop(self, now: float) -> None:
        for n in sorted(self.mine):
            self.forward(self.fwds[n]["vmac"], False)
        self.mine.clear()
        self.peers.clear()
        self._to("Init", now)

    def tick(self, now: float) -> None:
        if self.state == "Init":
            return
        alive = self._alive(now)
        actives = [(_key(p["prio"], ip), ip) for ip, p in alive.items() if p["state"] == "Active"]
        best_active = max(actives) if actives else None
        speakers = [_key(p["prio"], ip) for ip, p in alive.items() if p["state"] in ("Speak", "Standby", "Listen")]
        learning = now - self.started < self.cfg["hold"]
        if self.state == "Active":
            if best_active and best_active[0] > self.my_key():
                self._to("Standby", now)
        elif best_active:
            if self.cfg["preempt"] and now - self.started >= self.cfg["delay"] and self.vip \
                    and self.my_key() > best_active[0]:
                self._to("Active", now)
            elif all(self.my_key() > k for k in speakers):
                self._to("Standby", now)
            else:
                self._to("Listen", now)
        elif learning:
            self._to("Speak", now)
        elif self.vip and all(self.my_key() > k for k in speakers if k):
            self._to("Active", now)
        else:
            self._to("Standby" if all(self.my_key() > k for k in speakers) else "Listen", now)
        if self.state == "Active":
            self._assign(now, alive)
        self._follow()
        if now >= self.next_hello:
            self.send(self.packet())
            self.next_hello = now + self.cfg["hello"]

    def _assign(self, now: float, alive: dict) -> None:
        """The AVG's job: a forwarder for every member (itself first), the
        forwarder of a silent member taken over, given back on its return."""
        macs = {p["mac"]: ip for ip, p in alive.items()}
        members = [self.my_mac] + sorted(macs, key=lambda m: _key(alive[macs[m]]["prio"], macs[m]), reverse=True)
        for n, f in self.fwds.items():
            if f["primary"] != self.my_mac and f["primary"] not in macs and f["owner"] != self.my_mac:
                self.log(f"%GLBP-6-FWDSTATECHANGE: {self.cfg['iface']} Grp {self.cfg['group']} Fwd {n}: "
                         f"owner {f['primary']} silent, taken over")
                f["owner"] = self.my_mac
            elif f["primary"] in macs and f["owner"] != f["primary"]:
                f["owner"] = f["primary"]   # forwarder preemption: back to its own member
        have = {f["primary"] for f in self.fwds.values()}
        for m in members:
            if m in have:
                continue
            free = next((n for n in range(1, MAX_FWD + 1) if n not in self.fwds), None)
            if free is None:
                break
            self.fwds[free] = {"owner": m, "primary": m, "vmac": vmac(self.cfg["group"], free)}
            self.log(f"%GLBP-6-FWDSTATECHANGE: {self.cfg['iface']} Grp {self.cfg['group']} Fwd {free} "
                     f"given to {m}")
        for n in [n for n, f in self.fwds.items() if f["primary"] not in macs and f["primary"] != self.my_mac
                  and now - self.last_change > self.cfg["timeout"]]:
            del self.fwds[n]

    def _follow(self) -> None:
        want = {n for n, f in self.fwds.items() if f["owner"] == self.my_mac}
        old, self.mine = self.mine, want
        for n in sorted(old - want):
            if n in self.fwds:
                self.forward(self.fwds[n]["vmac"], False)
            self.log(f"%GLBP-6-FWDSTATECHANGE: {self.cfg['iface']} Grp {self.cfg['group']} Fwd {n} Active -> Listen")
        for n in sorted(want - old):
            self.forward(self.fwds[n]["vmac"], True)
            self.log(f"%GLBP-6-FWDSTATECHANGE: {self.cfg['iface']} Grp {self.cfg['group']} Fwd {n} Listen -> Active")

    def receive(self, msg: dict, src_ip: str, now: float) -> None:
        if msg["group"] != self.cfg["group"] or self.state == "Init" or src_ip == self.my_ip:
            return
        if (msg["auth"] or None) != (self.cfg["auth"] or None):
            if self.bad_auth != src_ip:
                self.log(f"%GLBP-4-BADAUTH: Bad authentication received from {src_ip}, group {self.cfg['group']}")
            self.bad_auth = src_ip
            return
        self.bad_auth = ""
        h = msg["hello"]
        self.peers[src_ip] = {"prio": h["prio"], "state": h["state"], "mac": msg["owner"],
                              "expires": now + (h["hold"] or self.cfg["hold"]),
                              "weight": max([f["weight"] for f in msg["fwds"]] or [WEIGHT])}
        if not self.vip and h["vip"] != "0.0.0.0":
            self.vip = h["vip"]
        if h["state"] == "Active" and self.state != "Active":
            # The AVG says who forwards what.
            self.fwds = {f["fwd"]: {"owner": f["owner"], "primary": self.fwds.get(f["fwd"], {}).get("primary")
                                    or f["owner"], "vmac": f["vmac"]}
                         for f in msg["fwds"] if 1 <= f["fwd"] <= MAX_FWD and f["owner"]}
            self._follow()

    # -- what it sends and answers
    def packet(self) -> bytes:
        fwds = [{"fwd": n, "state": "Active" if f["owner"] == self.my_mac else "Listen", "owner": f["owner"],
                 "vmac": f["vmac"], "weight": self.cfg["weight"]}
                for n, f in sorted(self.fwds.items()) if self.state == "Active" or f["owner"] == self.my_mac]
        hello = {"state": self.state if self.state != "Init" else "Listen", "prio": self.cfg["prio"],
                 "hello": self.cfg["hello"], "hold": self.cfg["hold"], "vip": self.vip,
                 "redirect": self.cfg["redirect"], "timeout": self.cfg["timeout"]}
        return encode(self.cfg["group"], self.my_mac, hello, fwds, self.cfg["auth"])

    def arp(self, host_mac: str, now: float) -> str:
        """The virtual MAC the AVG answers a host's ARP request with; ""
        when this router is not the AVG."""
        if self.state != "Active":
            return ""
        alive = {p["mac"]: p for p in self._alive(now).values()}
        live = [(n, f) for n, f in sorted(self.fwds.items())
                if f["owner"] == f["primary"] and (f["owner"] == self.my_mac or f["owner"] in alive)]
        if not live:
            return ""
        bal = self.cfg["balance"]
        if bal == "host-dependent":
            return live[zlib.crc32(host_mac.encode()) % len(live)][1]["vmac"]
        if bal == "weighted":
            seq = []
            for _, f in live:
                w = self.cfg["weight"] if f["owner"] == self.my_mac else alive[f["owner"]]["weight"]
                seq += [f["vmac"]] * max(1, w // 10)
            self.rr = (self.rr + 1) % len(seq)
            return seq[self.rr]
        self.rr = (self.rr + 1) % len(live)
        return live[self.rr][1]["vmac"]

    def status(self, now: float) -> dict:
        alive = self._alive(now)
        act = next((ip for ip, p in alive.items() if p["state"] == "Active"), "")
        sby = next((ip for ip, p in alive.items() if p["state"] == "Standby"), "")
        names = {p["mac"]: ip for ip, p in alive.items()}
        names[self.my_mac] = "local"
        return {"iface": self.cfg["iface"], "group": self.cfg["group"], "state": self.state, "vip": self.vip,
                "prio": self.cfg["prio"], "preempt": self.cfg["preempt"], "delay": self.cfg["delay"],
                "hello": self.cfg["hello"], "hold": self.cfg["hold"], "redirect": self.cfg["redirect"],
                "timeout": self.cfg["timeout"], "balance": self.cfg["balance"], "weight": self.cfg["weight"],
                "my_ip": self.my_ip, "my_mac": self.my_mac,
                "active": "local" if self.state == "Active" else act,
                "active_prio": alive[act]["prio"] if act in alive else 0,
                "active_expires": round(alive[act]["expires"] - now, 3) if act in alive else 0,
                "standby": "local" if self.state == "Standby" else sby,
                "standby_prio": alive[sby]["prio"] if sby in alive else 0,
                "next_hello": round(max(0.0, self.next_hello - now), 3) if self.state != "Init" else 0,
                "changes": self.changes, "since": round(now - self.last_change, 1) if self.changes else 0,
                "members": [{"mac": self.my_mac, "ip": self.my_ip or "-", "local": True}]
                + [{"mac": p["mac"], "ip": ip, "local": False} for ip, p in sorted(alive.items())],
                "forwarders": [{"fwd": n, "vmac": f["vmac"], "owner": f["primary"],
                                "state": "Active" if n in self.mine else "Listen",
                                "active": names.get(f["owner"], f["owner"]),
                                "primary": f["owner"] == f["primary"]} for n, f in sorted(self.fwds.items())],
                "name": self.cfg["name"], "auth_set": self.cfg["auth"] is not None, "bad_auth": self.bad_auth}


# ------------------------------------------------------------------ show glbp
def _hms(sec: float) -> str:
    s = int(sec)
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def show_brief(groups: list[dict], names: dict | None = None, short=None) -> str:
    names = names or {}
    short = short or (lambda n: n)
    out = [f"{'Interface':<12}{'Grp':<6}{'Fwd':<4}{'Pri':<5}{'State':<9}{'Address':<16}{'Active router':<16}"
           "Standby router"]
    for g in groups:
        name = short(names.get(g["iface"], g["iface"]))
        out.append(f"{name:<12}{g['group']:<6}{'-':<4}{g['prio']:<5}{g['state']:<9}{g['vip'] or 'unknown':<16}"
                   f"{g['active'] or 'unknown':<16}{g['standby'] or 'unknown'}")
        for f in g["forwarders"]:
            out.append(f"{name:<12}{g['group']:<6}{f['fwd']:<4}{'-':<5}{f['state']:<9}{cisco_mac(f['vmac']):<16}"
                       f"{f['active'] or '-':<16}-")
    return "\n".join(out)


def show_detail(groups: list[dict], names: dict | None = None) -> str:
    names = names or {}
    out = []
    for g in groups:
        out += [f"{names.get(g['iface'], g['iface'])} - Group {g['group']}", f"  State is {g['state']}"]
        if g["changes"]:
            out.append(f"    {g['changes']} state change{'s' if g['changes'] != 1 else ''}, "
                       f"last state change {_hms(g['since'])}")
        out += [f"  Virtual IP address is {g['vip'] or 'unknown'}",
                f"  Hello time {g['hello']:g} sec, hold time {g['hold']:g} sec"]
        if g["next_hello"]:
            out.append(f"    Next hello sent in {g['next_hello']:.3f} secs")
        out.append(f"  Redirect time {g['redirect']} sec, forwarder time-out {g['timeout']} sec")
        out.append("  Preemption " + (f"enabled, min delay {g['delay']} sec" if g["preempt"] else "disabled"))
        out.append("  Active is local" if g["active"] == "local" else
                   f"  Active is {g['active']}, priority {g['active_prio']} (expires in {g['active_expires']:.3f} sec)"
                   if g["active"] else "  Active is unknown")
        out.append("  Standby is local" if g["standby"] == "local" else
                   f"  Standby is {g['standby']}, priority {g['standby_prio']}" if g["standby"]
                   else "  Standby is unknown")
        out += [f"  Priority {g['prio']}" + (" (default)" if g["prio"] == PRIORITY else " (configured)"),
                f"  Weighting {g['weight']} (configured {g['weight']}), thresholds: lower 1, upper {g['weight']}",
                f"  Load balancing: {g['balance']}"]
        if g.get("bad_auth"):
            out.append(f"  Authentication mismatch with {g['bad_auth']}: its hellos are ignored")
        out.append("  Group members:")
        for m in g["members"]:
            out.append(f"    {cisco_mac(m['mac'])} ({m['ip']})" + (" local" if m["local"] else ""))
        act = sum(1 for f in g["forwarders"] if f["state"] == "Active")
        out.append(f"  There {'is' if len(g['forwarders']) == 1 else 'are'} {len(g['forwarders'])} "
                   f"forwarder{'s' if len(g['forwarders']) != 1 else ''} ({act} active)")
        for f in g["forwarders"]:
            out += [f"  Forwarder {f['fwd']}", f"    State is {f['state']}",
                    f"    MAC address is {cisco_mac(f['vmac'])} ({'default' if f['state'] == 'Active' else 'learnt'})",
                    f"    Owner ID is {cisco_mac(f['owner'])}",
                    "    Active is local" if f["active"] == "local" else f"    Active is {f['active']}"
                    + (" (primary)" if f["primary"] else " (secondary: its own member is silent)")]
    return "\n".join(out)


# ------------------------------------------------------------------ the running speaker
def _run(*args: str) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def iface_info(name: str) -> tuple[str, int, str, bool]:
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


def _sysctl(path: str, val: str) -> None:
    try:
        with open(path, "w") as f:
            f.write(val)
    except OSError:
        pass


class Speaker:
    def __init__(self, conf: str, state_file: str = STATE_FILE, log_file: str = ""):
        self.conf, self.state_file, self.log_file = conf, state_file, log_file
        self.groups: dict[tuple[str, int], Group] = {}
        self.tx: dict[str, socket.socket] = {}
        self.arp_rx: dict[str, socket.socket] = {}
        self.joined: set[str] = set()
        self.reload_wanted = self.stop_wanted = False
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

    def _dev(self, g: Group, mac: str) -> str:
        return f"gl{socket.if_nametoindex(g.cfg['iface'])}m{mac.replace(':', '')[-4:]}"[:15]

    def _send(self, g: Group, payload: bytes) -> None:
        iface = g.cfg["iface"]
        ip, _, mac, up = iface_info(iface)
        if not ip or not up:
            return
        self.ident = (self.ident + 1) & 0xFFFF
        try:
            s = self.tx.get(iface)
            if s is None:
                s = self.tx[iface] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                s.bind((iface, 0))
            s.send(udp_frame(mac, ip, payload, self.ident))
        except OSError as e:
            self.tx.pop(iface, None)
            self.log(f"%GLBP-3-SEND: {iface}: {e}")

    def _forward(self, g: Group, mac: str, on: bool) -> None:
        """A macvlan with the virtual MAC: frames sent to it are this
        router's to route. It answers no ARP itself (the AVG does)."""
        iface = g.cfg["iface"]
        dev = self._dev(g, mac)
        if on:
            _run("ip", "link", "add", dev, "link", iface, "type", "macvlan", "mode", "bridge")
            _run("ip", "link", "set", "dev", dev, "address", mac)
            for path, val in ((f"/proc/sys/net/ipv4/conf/{dev}/arp_ignore", "8"),
                              (f"/proc/sys/net/ipv4/conf/{dev}/rp_filter", "2"),
                              (f"/proc/sys/net/ipv4/conf/{iface}/arp_ignore", "1"),
                              (f"/proc/sys/net/ipv4/conf/{iface}/arp_announce", "2")):
                _sysctl(path, val)
            _run("ip", "link", "set", "dev", dev, "up")
        else:
            _run("ip", "link", "del", dev)
        if g.state == "Active":
            self._avg(g, True)

    def _avg(self, g: Group, on: bool) -> None:
        """The AVG holds the virtual address (on its first forwarder's
        macvlan, with ARP off there), so it answers ping to it."""
        _, plen, _, _ = iface_info(g.cfg["iface"])
        devs = [self._dev(g, g.fwds[n]["vmac"]) for n in sorted(g.mine) if n in g.fwds]
        for i, dev in enumerate(devs):
            if on and g.vip and i == 0:
                _run("ip", "addr", "replace", f"{g.vip}/32", "dev", dev)
            else:
                _run("ip", "addr", "flush", "dev", dev)

    def _arp_socket(self, iface: str) -> socket.socket | None:
        s = self.arp_rx.get(iface)
        if s is None:
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                s.bind((iface, 0))
                self.arp_rx[iface] = s
            except OSError as e:
                self.log(f"%GLBP-3-ARP: {iface}: {e}")
                return None
        return s

    def _answer_arp(self, iface: str, frame: bytes, now: float) -> None:
        req = parse_arp(frame)
        if not req:
            return
        for g in self.groups.values():
            if g.cfg["iface"] == iface and g.vip and req["target"] == g.vip:
                m = g.arp(req["mac"], now)
                if m:
                    try:
                        self.arp_rx[iface].send(arp_reply(m, g.vip, req["mac"], req["ip"]))
                    except OSError as e:
                        self.log(f"%GLBP-3-ARP: {iface}: {e}")

    def load(self) -> None:
        try:
            with open(self.conf) as f:
                cfgs = parse_conf(f.read())
        except (OSError, ConfError) as e:
            self.log(f"%GLBP-3-CONFIG: {self.conf}: {e}; keeping what runs")
            return
        now = time.monotonic()
        want = {(c["iface"], c["group"]): c for c in cfgs}
        for key in [k for k in self.groups if k not in want]:
            self.groups.pop(key).stop(now)
        for key, cfg in want.items():
            g = self.groups.get(key)
            if g is None:
                _, _, mac, _ = iface_info(cfg["iface"])
                if not mac:
                    self.log(f"%GLBP-3-CONFIG: no interface {cfg['iface']}")
                    continue
                g = Group(cfg, mac, log=self.log)
                g.send = (lambda p, g=g: self._send(g, p))
                g.forward = (lambda m, on, g=g: self._forward(g, m, on))
                g.avg = (lambda on, g=g: self._avg(g, on))
                self.groups[key] = g
            else:
                g.cfg = cfg
                if cfg["vip"]:
                    g.vip = cfg["vip"]
        self.log(f"%GLBP-6-CONFIG: {len(self.groups)} group(s) from {self.conf}")

    def _poll(self, now: float) -> None:
        for g in self.groups.values():
            ip, _, _, up = iface_info(g.cfg["iface"])
            if g.state == "Init" and ip and up:
                if g.cfg["iface"] not in self.joined:
                    try:
                        mreq = struct.pack("!4s4s", socket.inet_aton(GROUP_ADDR), socket.inet_aton(ip))
                        self.rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                        self.joined.add(g.cfg["iface"])
                    except OSError:
                        pass
                self._arp_socket(g.cfg["iface"])
                g.start(ip, now)
            elif g.state != "Init" and (not ip or not up):
                g.stop(now)

    def _write_state(self, now: float) -> None:
        data = {"pid": os.getpid(), "updated": time.time(),
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
        ifindex: dict[int, str] = {}
        last_poll = last_write = 0.0
        while not self.stop_wanted:
            now = time.monotonic()
            if self.reload_wanted:
                self.reload_wanted = False
                self.load()
                last_poll = 0.0
            if now - last_poll >= 1.0:
                self._poll(now)
                ifindex = {}
                for g in self.groups.values():
                    try:
                        ifindex[socket.if_nametoindex(g.cfg["iface"])] = g.cfg["iface"]
                    except OSError:
                        pass
                last_poll = now
            socks = [self.rx] + list(self.arp_rx.values())
            r, _, _ = select.select(socks, [], [], 0.1)
            for s in r:
                if s is self.rx:
                    try:
                        data, anc, _, (src, _) = self.rx.recvmsg(1500, 256)
                    except OSError:
                        continue
                    idx = next((struct.unpack("i", d[:4])[0] for lvl, typ, d in anc
                                if lvl == socket.IPPROTO_IP and typ == getattr(socket, "IP_PKTINFO", 8)), 0)
                    iface = ifindex.get(idx)
                    msg = decode(data) if iface else None
                    if msg:
                        for g in self.groups.values():
                            if g.cfg["iface"] == iface:
                                g.receive(msg, src, time.monotonic())
                else:
                    iface = next((i for i, x in self.arp_rx.items() if x is s), "")
                    try:
                        frame = s.recv(2048)
                    except OSError:
                        continue
                    self._answer_arp(iface, frame, time.monotonic())
            now = time.monotonic()
            for g in self.groups.values():
                g.tick(now)
            if now - last_write >= 0.5:
                self._write_state(now)
                last_write = now
        now = time.monotonic()
        for g in self.groups.values():
            g.stop(now)
        self.groups.clear()
        self._write_state(now)
        self.log("%GLBP-6-STOP: winlab-glbpd stopped")


def main(argv: list[str]) -> int:
    conf, state_file, log_file = CONF_FILE, STATE_FILE, ""
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
    cmd = rest[0] if rest else "run"
    if cmd == "check":
        try:
            with open(conf) as f:
                groups = parse_conf(f.read())
        except (OSError, ConfError) as e:
            print(f"{conf}: {e}")
            return 1
        for g in groups:
            print(f"{g['iface']} group {g['group']}: virtual {g['vip'] or '(learned)'}, priority {g['prio']}, "
                  f"preempt {'yes' if g['preempt'] else 'no'}, load balancing {g['balance']}")
        return 0
    if cmd == "show":
        try:
            with open(state_file) as f:
                data = json.load(f)
        except (OSError, ValueError):
            print("winlab-glbpd is not running (no state file)")
            return 1
        print(show_brief(data["groups"]) if rest[1:2] == ["brief"] else show_detail(data["groups"]))
        return 0
    if cmd != "run":
        print("usage: winlab-glbpd [-c conf] [-s state] [-l log] [run | show [brief] | check]")
        return 2
    Speaker(conf, state_file, log_file).run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
