#!/usr/bin/env python3
"""winlab-pagpd: a small PAgP speaker, winlab's own code (MIT, like the rest
of winlab), so the lab router's switch cables can negotiate an EtherChannel
with Cisco's Port Aggregation Protocol the way two Catalysts do.

PAgP is Cisco's own protocol. Linux bonding speaks LACP (802.3ad) and
nothing else, and no open-source PAgP daemon exists, so this is one, written
from the frame layout Cisco's switches send and Wireshark's PAgP dissector
decodes (epan/dissectors/packet-pagp.c): an 802.3 frame to 01:00:0c:cc:cc:cc
with LLC AA-AA-03 and SNAP (OUI 00-00-0C, protocol 0x0104), then the PDU.
The Info PDU (version 1): flags (0x01 slow hello, 0x02 auto mode, 0x04
consistent state), the sender's device id (a MAC), learn capability, port
priority, sent-port ifindex, group capability and group ifindex, then the
same five fields as it last heard them from its partner, a partner count, and
TLVs (type and length, 2 octets each, the length counting the 4-octet
header): 1 device name, 2 port name, 3 the aggregate port's MAC. The Flush
PDU (version 2) is decoded and never sent.

How a channel forms. A ``desirable`` port sends an Info PDU every second; an
``auto`` port only answers, once it has heard a neighbour (the auto-mode flag
says which it is). A port is ready to bundle when its neighbour's PDU echoes
this port back as the partner (both ends hear each other) and at least one end
is desirable: desirable with desirable or auto forms, auto with auto never
does, and a port facing a switch that does not speak PAgP stays stand-alone.
The ready ports of one channel group that face the same neighbour device and
group capability bundle (the consistent-state flag goes up and hellos slow to
every 30 s); a ready port facing another device is suspended. A neighbour is
lost after three and a half of its hello intervals, or as soon as the link
goes down (two link polls in a row, so a port that is being moved into or out
of the bond does not count as a cable pulled).

How it bundles. On the lab router every switch-to-switch cable is a veth
pair between the switches' kernel bridges (winlab/stp.py). A PAgP port starts
as an ordinary port of its switch's bridge, so spanning tree blocks the spare
cables, exactly as an IOS port that has not bundled stands alone (I). When
PAgP agrees, the speaker moves the veth into the channel's Linux bond, a
non-LACP bond (balance-xor, the hash from ``port-channel load-balance``)
that is one port of the bridge; when it no longer agrees (neighbour lost,
link down, a mode changed), it moves the veth back into the bridge with its
VLANs, cost and priority. PAgP frames are sent and read on each veth with a
raw packet socket, which sees them before the bridge or the bond does; the
fabric's nftables drops them at the bridge (winlab/etherchannel.py) so a PDU
is never flooded onto another cable.

What it does not do: PAgP's physical-port versus aggregate-port learning
(``pagp learn-method``; the learn capability is sent as 1 and ignored),
hot-standby port priority (``pagp port-priority`` is sent as 128 and never
used to keep ports in standby), Flush PDUs (decoded, never sent), the
``non-silent`` / silent distinction (a desirable or auto port facing a silent
device simply stands alone), and the group-capability and ifindex values a
Catalyst derives from its hardware: winlab sends the channel group number as
the group capability, 24 + the port number as the port ifindex (spanning
tree's port number) and 0x1000 + the group as the group ifindex while
bundled. It was tested against itself only: two copies on the two ends of
veth pairs (tests/test_winlab.py), never against a Cisco switch; its frames
follow the published layout byte for byte. It needs root (raw sockets,
``ip``) and Python 3 with nothing beyond the standard library.

Usage, on the lab router (winlab/etherchannel.py writes the file and starts
it)::

    winlab-pagpd -c /etc/winlab-pagp.json   # run (SIGHUP reloads, SIGTERM stops)
    winlab-pagpd show                        # the ports' state, from the state file

The configuration is JSON: {"ports": [{"dev": the veth, "mode": "desirable"
or "auto", "group": n, "device_id": the switch's MAC, "device_name",
"port_name", "ifindex", "bond", "bridge", "native": the untagged VLAN,
"vids": [...], "cost", "priority"}, ...]}.
"""

from __future__ import annotations

import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import time

DST = bytes.fromhex("01000ccccccc")
SNAP = bytes.fromhex("aaaa0300000c0104")    # LLC AA-AA-03, OUI 00-00-0C, PID 0x0104
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
INFO, FLUSH = 1, 2
F_SLOW, F_AUTO, F_CONSISTENT = 0x01, 0x02, 0x04
TLV_DEVICE_NAME, TLV_PORT_NAME, TLV_AGPORT_MAC = 1, 2, 3
FAST, SLOW = 1.0, 30.0           # hello intervals: negotiating, bundled
HOLD_FACTOR = 3.5                # a neighbour is lost after 3.5 of its hellos
LEARN_CAP, PORT_PRIORITY = 1, 128
CONF_FILE = "/etc/winlab-pagp.json"
STATE_FILE = "/run/winlab-pagp.json"


def _mac(text: str) -> bytes:
    h = text.replace(":", "").replace(".", "").replace("-", "")
    return bytes.fromhex(h) if len(h) == 12 else b"\0" * 6


def _mac_text(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


# ------------------------------------------------------------------ packets
def encode_info(flags: int, local: dict, partner: dict | None, tlvs: list[tuple[int, bytes]]) -> bytes:
    """An Info PDU. `local` and `partner` carry device_id (aa:bb:..),
    learn_cap, priority, ifindex, group_cap and group_ifindex; no partner is
    all zeros and a partner count of 0."""
    def five(d: dict | None) -> bytes:
        d = d or {}
        return struct.pack("!6sBBIII", _mac(d.get("device_id", "")), d.get("learn_cap", 0) & 0xFF,
                           d.get("priority", 0) & 0xFF, d.get("ifindex", 0) & 0xFFFFFFFF,
                           d.get("group_cap", 0) & 0xFFFFFFFF, d.get("group_ifindex", 0) & 0xFFFFFFFF)
    body = b"".join(struct.pack("!HH", t, len(v) + 4) + v for t, v in tlvs)
    return (struct.pack("!BB", INFO, flags & 0xFF) + five(local) + five(partner)
            + struct.pack("!HH", 1 if partner else 0, len(tlvs)) + body)


def encode_flush(local_id: str, partner_id: str, transaction: int) -> bytes:
    return struct.pack("!BB6s6sI", FLUSH, 0, _mac(local_id), _mac(partner_id), transaction & 0xFFFFFFFF)


def decode(pdu: bytes) -> dict | None:
    """An Info or Flush PDU as a dict, or None for anything else."""
    if len(pdu) >= 18 and pdu[0] == FLUSH:
        _, _, a, b, t = struct.unpack("!BB6s6sI", pdu[:18])
        return {"version": FLUSH, "device_id": _mac_text(a), "partner_id": _mac_text(b), "transaction": t}
    if len(pdu) < 46 or pdu[0] != INFO:
        return None

    def five(off: int) -> dict:
        dev, lc, pri, ifx, cap, gif = struct.unpack("!6sBBIII", pdu[off:off + 20])
        return {"device_id": _mac_text(dev), "learn_cap": lc, "priority": pri, "ifindex": ifx,
                "group_cap": cap, "group_ifindex": gif}
    out = {"version": INFO, "flags": pdu[1], "local": five(2), "partner": five(22)}
    out["partner_count"], n = struct.unpack("!HH", pdu[42:46])
    off, tlvs = 46, {}
    for _ in range(n):
        if off + 4 > len(pdu):
            break
        t, ln = struct.unpack("!HH", pdu[off:off + 4])
        if ln < 4 or off + ln > len(pdu):
            break
        v = pdu[off + 4:off + ln]
        if t in (TLV_DEVICE_NAME, TLV_PORT_NAME):
            tlvs[t] = v.split(b"\0")[0].decode("ascii", "replace")
        elif t == TLV_AGPORT_MAC and len(v) >= 6:
            tlvs[t] = _mac_text(v[:6])
        off += ln
    out["device_name"] = tlvs.get(TLV_DEVICE_NAME, "")
    out["port_name"] = tlvs.get(TLV_PORT_NAME, "")
    out["agport_mac"] = tlvs.get(TLV_AGPORT_MAC, "")
    return out


def frame(src_mac: str, pdu: bytes) -> bytes:
    """The 802.3 frame: Cisco's multicast, the length, LLC/SNAP, the PDU,
    padded to Ethernet's 60-octet minimum."""
    body = SNAP + pdu
    out = DST + _mac(src_mac) + struct.pack("!H", len(body)) + body
    return out.ljust(60, b"\0")


def unframe(data: bytes) -> bytes | None:
    """The PDU in a received frame, or None when the frame is not PAgP."""
    if len(data) < 22 or data[:6] != DST:
        return None
    ln = struct.unpack("!H", data[12:14])[0]
    if ln > 1500 or data[14:22] != SNAP:
        return None
    return data[22:14 + ln]


# ------------------------------------------------------------------ the protocol
class Port:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.nb: dict | None = None      # the neighbour's last Info PDU
        self.heard = 0.0
        self.next_send = 0.0
        self.up = False
        self.down_polls = 0
        self.state = "D"                 # P bundled, I stand-alone, s suspended, D down
        self.ready = False
        self.sent = self.received = 0
        self.flaps = 0

    @property
    def dev(self) -> str:
        return self.cfg["dev"]

    def local(self) -> dict:
        c = self.cfg
        return {"device_id": c["device_id"], "learn_cap": LEARN_CAP, "priority": PORT_PRIORITY,
                "ifindex": int(c.get("ifindex", 0)), "group_cap": int(c.get("group", 0)),
                "group_ifindex": 0x1000 + int(c.get("group", 0)) if self.state == "P" else 0}

    def alive(self, now: float) -> bool:
        if self.nb is None:
            return False
        hello = SLOW if self.nb["flags"] & F_SLOW else FAST
        return now - self.heard <= HOLD_FACTOR * hello

    def two_way(self) -> bool:
        nb = self.nb
        return bool(nb) and nb["partner"]["device_id"] == self.cfg["device_id"].lower() \
            and nb["partner"]["ifindex"] == int(self.cfg.get("ifindex", 0))

    def willing(self) -> bool:
        return self.cfg["mode"] == "desirable" or not (self.nb and self.nb["flags"] & F_AUTO)

    def flags(self) -> int:
        f = F_AUTO if self.cfg["mode"] == "auto" else 0
        if self.state == "P":
            f |= F_CONSISTENT | F_SLOW
        return f

    def pdu(self) -> bytes:
        partner = self.nb["local"] if self.nb else None
        tlvs = [(TLV_DEVICE_NAME, self.cfg.get("device_name", "").encode()[:64]),
                (TLV_PORT_NAME, self.cfg.get("port_name", "").encode()[:64])]
        if self.state == "P" and self.cfg.get("agport_mac"):
            tlvs.append((TLV_AGPORT_MAC, _mac(self.cfg["agport_mac"])))
        return encode_info(self.flags(), self.local(), partner, tlvs)


class Engine:
    """PAgP's decisions for a set of ports, with no sockets: tell it what
    arrives and when links change, ask it what to send and which ports
    bundle. The running speaker and the tests drive it alike."""

    def __init__(self, cfgs: list[dict], log=print):
        self.ports = {c["dev"]: Port(c) for c in cfgs}
        self.log = log

    def link(self, dev: str, up: bool, now: float) -> None:
        p = self.ports[dev]
        if up:
            p.down_polls = 0
            if not p.up:
                p.up = True
                p.next_send = now
            return
        p.down_polls += 1
        if p.up and p.down_polls >= 2:
            p.up = False
            if p.nb:
                self.log(f"%PAGP-5-NEIGHBOR: {p.cfg.get('port_name', dev)} lost its neighbour (link down)")
            p.nb = None

    def receive(self, dev: str, pdu: bytes, now: float) -> None:
        p = self.ports.get(dev)
        msg = decode(pdu)
        if p is None or msg is None or msg["version"] != INFO or not p.up:
            return
        p.received += 1
        old = p.nb
        p.nb, p.heard = msg, now
        if old is None or old["local"] != msg["local"] or old["partner"] != msg["partner"] \
                or old["flags"] != msg["flags"]:
            p.next_send = now            # answer a change at once, so both ends agree within a hello

    def tick(self, now: float) -> list[tuple[str, bytes]]:
        """Ages neighbours out, decides the bundles, and returns the PDUs due."""
        for p in self.ports.values():
            if p.nb is not None and not p.alive(now):
                self.log(f"%PAGP-5-NEIGHBOR: {p.cfg.get('port_name', p.dev)} lost its neighbour "
                         f"(nothing heard for {HOLD_FACTOR:g} hellos)")
                p.nb = None
        self._decide()
        out = []
        for p in self.ports.values():
            if not p.up:
                continue
            if p.cfg["mode"] == "auto" and p.nb is None:
                continue                 # auto only answers
            if now >= p.next_send:
                out.append((p.dev, p.pdu()))
                p.sent += 1
                p.next_send = now + (SLOW if p.state == "P" else FAST)
        return out

    def _decide(self) -> None:
        groups: dict = {}
        for p in self.ports.values():
            p.ready = p.up and p.nb is not None and p.two_way() and p.willing()
            groups.setdefault(p.cfg.get("bond") or p.cfg.get("group"), []).append(p)
        for ports in groups.values():
            by: dict = {}
            for p in ports:
                if p.ready:
                    by.setdefault((p.nb["local"]["device_id"], p.nb["local"]["group_cap"]), []).append(p)
            keep = max(sorted(by), key=lambda k: len(by[k])) if by else None
            for p in ports:
                was = p.state
                if not p.up:
                    p.state = "D"
                elif p.ready and by.get(keep) and p in by[keep]:
                    p.state = "P"
                elif p.ready:
                    p.state = "s"
                else:
                    p.state = "I"
                if was != p.state:
                    p.next_send = 0.0     # tell the neighbour now
                    name = p.cfg.get("port_name", p.dev)
                    if p.state == "P":
                        self.log(f"%EC-5-BUNDLE: Interface {name} joined port-channel Po{p.cfg.get('group')}")
                    elif was == "P":
                        self.log(f"%EC-5-UNBUNDLE: Interface {name} left the port-channel Po{p.cfg.get('group')}")

    def status(self, now: float) -> list[dict]:
        out = []
        for p in self.ports.values():
            nb = p.nb
            out.append({"dev": p.dev, "switch": p.cfg.get("switch", ""), "port": p.cfg.get("port", ""),
                        "group": p.cfg.get("group"), "mode": p.cfg["mode"], "state": p.state,
                        "flags": p.flags(), "ready": p.ready, "sent": p.sent, "received": p.received,
                        "neighbor": None if nb is None else {
                            "device_id": nb["local"]["device_id"], "name": nb["device_name"],
                            "port": nb["port_name"], "ifindex": nb["local"]["ifindex"],
                            "group_cap": nb["local"]["group_cap"], "flags": nb["flags"],
                            "age": round(now - p.heard, 1)}})
        return out


# ------------------------------------------------------------------ the running speaker
def _run(*args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return r.returncode, (r.stderr or r.stdout).strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def master_of(dev: str) -> str:
    try:
        return os.path.basename(os.readlink(f"/sys/class/net/{dev}/master"))
    except OSError:
        return ""


def bundle(cfg: dict) -> tuple[bool, str]:
    """The veth into the channel's bond (out of its switch's bridge)."""
    dev, bond = cfg["dev"], cfg["bond"]
    if not os.path.exists(f"/sys/class/net/{bond}"):
        return False, f"no bond {bond} (Linux bonding missing from this kernel?)"
    _run("ip", "link", "set", "dev", dev, "nomaster")
    rc, err = _run("ip", "link", "set", "dev", dev, "master", bond)
    if rc != 0:     # an older kernel enslaves only a port that is down
        _run("ip", "link", "set", "dev", dev, "down")
        rc, err = _run("ip", "link", "set", "dev", dev, "master", bond)
    _run("ip", "link", "set", "dev", dev, "up")
    if rc != 0:
        unbundle(cfg)
        return False, err
    return True, ""


def unbundle(cfg: dict) -> None:
    """The veth back into its switch's bridge as a port of its own, as the
    start script made it."""
    dev, br = cfg["dev"], cfg["bridge"]
    if master_of(dev) != br:
        _run("ip", "link", "set", "dev", dev, "nomaster")
        _run("ip", "link", "set", "dev", dev, "master", br)
        _run("bridge", "vlan", "add", "dev", dev, "vid", str(cfg["native"]), "pvid", "untagged")
        for v in cfg.get("vids", []):
            _run("bridge", "vlan", "add", "dev", dev, "vid", str(v))
        _run("bridge", "link", "set", "dev", dev, "cost", str(cfg.get("cost", 4)),
             "priority", str(cfg.get("priority", 32)))
    _run("ip", "link", "set", "dev", dev, "up")


class Speaker:
    def __init__(self, conf: str, state_file: str = STATE_FILE, log_file: str = ""):
        self.conf, self.state_file, self.log_file = conf, state_file, log_file
        self.engine = Engine([], self.log)
        self.socks: dict[str, socket.socket] = {}
        self.applied: dict[str, str] = {}       # dev -> "P" when it sits in the bond
        self.errors: dict[str, str] = {}
        self.tried: dict[str, float] = {}       # dev -> when a failed move into the bond was last tried
        self.reload_wanted = self.stop_wanted = False

    def log(self, text: str) -> None:
        line = time.strftime("%b %d %H:%M:%S ") + text
        print(line, flush=True)
        if self.log_file:
            try:
                with open(self.log_file, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def load(self) -> None:
        try:
            with open(self.conf) as f:
                cfgs = json.load(f).get("ports", [])
        except (OSError, ValueError) as e:
            self.log(f"%PAGP-3-CONFIG: {self.conf}: {e}; keeping what runs")
            return
        for s in self.socks.values():
            s.close()
        self.socks.clear()
        # The start script (re)built the bridges: every port starts stand-alone.
        self.engine = Engine(cfgs, self.log)
        self.applied, self.errors, self.tried = {}, {}, {}
        self.log(f"%PAGP-6-CONFIG: {len(cfgs)} port(s) from {self.conf}")

    def _sock(self, dev: str) -> socket.socket | None:
        s = self.socks.get(dev)
        if s is None:
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                s.bind((dev, 0))
                s.setblocking(False)
            except OSError:
                return None
            self.socks[dev] = s
        return s

    def _apply(self) -> None:
        for p in self.engine.ports.values():
            want = p.state == "P"
            if want and self.applied.get(p.dev) != "P":
                if time.monotonic() - self.tried.get(p.dev, -60.0) < 5.0:
                    continue
                ok, err = bundle(p.cfg)
                if ok:
                    self.applied[p.dev] = "P"
                    self.errors.pop(p.dev, None)
                    p.cfg["agport_mac"] = _read(f"/sys/class/net/{p.cfg['bond']}/address")
                else:
                    self.tried[p.dev] = time.monotonic()
                if not ok and self.errors.get(p.dev) != err:
                    self.errors[p.dev] = err
                    self.log(f"%PAGP-3-BUNDLE: {p.dev} into {p.cfg['bond']}: {err}")
                # Moving the veth blinks its link: not a cable pulled.
                p.down_polls = -2
            elif not want and self.applied.get(p.dev) == "P":
                unbundle(p.cfg)
                self.applied.pop(p.dev, None)
                p.down_polls = -2

    def _write_state(self, now: float) -> None:
        ports = self.engine.status(now)
        for st in ports:
            st["master"] = master_of(st["dev"])
            st["bundled"] = self.applied.get(st["dev"]) == "P"
            if st["dev"] in self.errors:
                st["error"] = self.errors[st["dev"]]
        data = {"pid": os.getpid(), "updated": time.time(), "conf": self.conf, "ports": ports}
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
        last_poll = last_write = 0.0
        while not self.stop_wanted:
            now = time.monotonic()
            if self.reload_wanted:
                self.reload_wanted = False
                self.load()
                last_poll = 0.0
            if now - last_poll >= 1.0:
                for dev, p in self.engine.ports.items():
                    oper = _read(f"/sys/class/net/{dev}/operstate")
                    up = oper in ("up", "unknown")
                    if p.down_polls < 0 and not up:
                        p.down_polls += 1        # a move in progress
                        continue
                    self.engine.link(dev, up, now)
                    if up and self._sock(dev) is None:
                        self.engine.link(dev, False, now)
                last_poll = now
            socks = {s: d for d, s in self.socks.items()}
            r = select.select(list(socks), [], [], 0.1)[0] if socks else (time.sleep(0.1) or [])
            for s in r:
                for _ in range(64):
                    try:
                        data, addr = s.recvfrom(2048)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        self.socks.pop(socks[s], None)
                        break
                    if addr[2] == PACKET_OUTGOING:
                        continue
                    pdu = unframe(data)
                    if pdu is not None:
                        self.engine.receive(socks[s], pdu, time.monotonic())
            now = time.monotonic()
            for dev, pdu in self.engine.tick(now):
                s = self._sock(dev)
                mac = _read(f"/sys/class/net/{dev}/address")
                try:
                    if s is not None:
                        s.send(frame(mac, pdu))
                except OSError as e:
                    self.socks.pop(dev, None)
                    self.log(f"%PAGP-3-SEND: {dev}: {e}")
            self._apply()
            if now - last_write >= 0.5:
                self._write_state(now)
                last_write = now
        for p in self.engine.ports.values():
            if self.applied.get(p.dev) == "P":
                unbundle(p.cfg)
        self.applied.clear()
        self.engine = Engine([], self.log)
        self._write_state(time.monotonic())
        self.log("%PAGP-6-STOP: winlab-pagpd stopped")


def show(data: dict) -> str:
    rows = ["Port            Mode       State  Neighbour                          Sent  Rcvd"]
    for p in data.get("ports", []):
        nb = p.get("neighbor") or {}
        who = f"{nb.get('name', '')} {nb.get('port', '')} ({nb.get('device_id', '')})" if nb else "-"
        rows.append(f"{p['dev']:<16}{p['mode']:<11}{p['state']:<7}{who[:34]:<35}{p['sent']:<6}{p['received']}")
    return "\n".join(rows)


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
    if cmd == "show":
        try:
            with open(state_file) as f:
                print(show(json.load(f)))
        except (OSError, ValueError):
            print("winlab-pagpd is not running (no state file)")
            return 1
        return 0
    if cmd != "run":
        print("usage: winlab-pagpd [-c conf] [-s state] [-l log] [run | show]")
        return 2
    Speaker(conf, state_file, log_file).run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
