#!/usr/bin/env python3
"""winlab-slad: IP SLA probes and object tracking for a Linux router,
winlab's own code (MIT, like the rest of winlab), behind the lab router's
``ip sla``, ``track`` and ``ip route ... track`` console lines.

IOS's IP SLA sends a probe on a schedule and keeps its result; a track
object follows one operation's result; a static route, an HSRP group or a
VRRP group follows the track. Linux has the pieces (ping, the kernel's
routing table, FRRouting's vrrpd) but nothing that ties them together the
IOS way, so this small program does: it is configured with the console's
own lines (under the router's Linux interface names) and it

* runs each scheduled ``icmp-echo`` operation every ``frequency`` seconds
  with the system's ping (one echo, ``timeout`` milliseconds to answer),
  keeping the return code IOS shows: OK, Timeout, Over threshold (an answer
  slower than ``threshold``) or No connection (no route, an unknown source);
* keeps each track object's state: ``reachability`` is Up while the return
  code is OK or Over threshold, ``state`` only while it is OK; ``delay down
  <s> up <s>`` holds a change back that long, as IOS does. An operation that
  was never scheduled (no ``ip sla schedule``) never runs: its return code
  stays Unknown and the object stays Down, as on IOS, so whatever follows it
  stays withdrawn;
* installs a tracked static route in the kernel (protocol 120, the console's
  static routes, winlab/iosl3.py) while its object is Up and takes it away
  while it is Down, so a floating route behind it takes over;
* lowers a VRRP group's priority by its decrement while its object is Down,
  by telling FRRouting's vrrpd (``vtysh``: vrrpd has no tracking of its
  own); HSRP's tracking of an object is winlab-hsrpd's own, which reads
  this program's state file.

State is written to /run/winlab-sla.json for the console's ``show ip sla
statistics``, ``show ip sla configuration`` and ``show track``. Usage::

    winlab-slad -c /etc/winlab-sla.conf     # run (SIGHUP reloads, SIGTERM stops)
    winlab-slad check -c /etc/winlab-sla.conf

The file::

    ip sla 1
     icmp-echo 198.51.100.2 source-interface eth3
     frequency 5
    ip sla schedule 1 life forever start-time now
    track 1 ip sla 1 reachability
     delay down 10 up 5
    route 203.0.113.0/24 via 198.51.100.2 metric 1 track 1
    vrrp eth1 1 priority 120 track 1 decrement 30

What it does not do: operations other than icmp-echo (udp-jitter, http,
dns...), ``start-time`` other than now, a ``life`` of so many seconds that
ends (it is taken; the operation then stops after it), boolean track lists.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time

CONF_FILE = "/etc/winlab-sla.conf"
STATE_FILE = "/run/winlab-sla.json"
ROUTE_PROTO = 120
FREQUENCY, TIMEOUT, THRESHOLD = 60, 5000, 5000
CODES = ("Unknown", "OK", "Timeout", "Over threshold", "No connection")


class ConfError(Exception):
    pass


# ------------------------------------------------------------------ configuration
def parse_conf(text: str) -> dict:
    """The file -> {"sla": {n: {...}}, "track": {n: {...}}, "routes": [...],
    "vrrp": [...]}. Raises ConfError naming the line."""
    sla: dict[int, dict] = {}
    track: dict[int, dict] = {}
    routes: list[dict] = []
    vrrp: list[dict] = []
    cur: tuple[str, int] | None = None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("!")[0].split("#")[0].rstrip()
        if not line.strip():
            continue
        w = line.split()
        sub = line.startswith(" ")
        try:
            if not sub and w[:2] == ["ip", "sla"] and len(w) == 3 and w[2].isdigit():
                cur = ("sla", int(w[2]))
                sla.setdefault(int(w[2]), {"type": "", "target": "", "source": "", "frequency": FREQUENCY,
                                           "timeout": TIMEOUT, "threshold": THRESHOLD, "scheduled": False,
                                           "life": 0})
            elif not sub and w[:3] == ["ip", "sla", "schedule"]:
                op = int(w[3])
                if op not in sla:
                    raise ConfError(f"line {n}: ip sla schedule {op}: no ip sla {op}")
                sla[op]["scheduled"] = True
                if "life" in w:
                    life = w[w.index("life") + 1]
                    sla[op]["life"] = 0 if life == "forever" else int(life)
                cur = None
            elif not sub and w[0] == "track" and len(w) >= 5 and w[2:4] == ["ip", "sla"]:
                kind = w[5] if len(w) > 5 else "state"
                if kind not in ("state", "reachability"):
                    raise ConfError(f"line {n}: track <n> ip sla <n> state | reachability")
                cur = ("track", int(w[1]))
                track[int(w[1])] = {"sla": int(w[4]), "kind": kind, "down": 0, "up": 0}
            elif not sub and w[0] == "route":
                # route <prefix> via <ip> | dev <dev> metric <n> track <n>
                rt = {"prefix": str(ipaddress.IPv4Network(w[1])), "how": f"{w[2]} {w[3]}",
                      "metric": int(w[w.index("metric") + 1]) if "metric" in w else 1,
                      "track": int(w[w.index("track") + 1])}
                routes.append(rt)
                cur = None
            elif not sub and w[0] == "vrrp":
                vrrp.append({"iface": w[1], "group": int(w[2]), "priority": int(w[w.index("priority") + 1]),
                             "track": int(w[w.index("track") + 1]), "decrement": int(w[w.index("decrement") + 1])})
                cur = None
            elif sub and cur and cur[0] == "sla":
                op = sla[cur[1]]
                if w[0] == "icmp-echo":
                    op["type"], op["target"] = "icmp-echo", str(ipaddress.IPv4Address(w[1]))
                    if len(w) >= 4 and w[2] in ("source-interface", "source-ip"):
                        op["source"] = w[3]
                elif w[0] in ("frequency", "timeout", "threshold"):
                    op[w[0]] = int(w[1])
                else:
                    raise ConfError(f"line {n}: {w[0]} is not taken here (icmp-echo, frequency, timeout, threshold)")
            elif sub and cur and cur[0] == "track" and w[0] == "delay":
                t = track[cur[1]]
                for i in range(1, len(w) - 1, 2):
                    if w[i] in ("down", "up"):
                        t[w[i]] = int(w[i + 1])
            else:
                raise ConfError(f"line {n}: not understood: {line.strip()}")
        except (IndexError, ValueError):
            raise ConfError(f"line {n}: incomplete or not a valid value: {line.strip()}") from None
    for k, op in sla.items():
        if op["scheduled"] and not op["type"]:
            raise ConfError(f"ip sla {k}: scheduled with no operation (icmp-echo <address>)")
    return {"sla": sla, "track": track, "routes": routes, "vrrp": vrrp}


# ------------------------------------------------------------------ results
def parse_ping(rc: int, out: str) -> tuple[bool, float]:
    """The system's ping, one echo -> (answered, round trip in ms)."""
    m = re.search(r"time[=<]([\d.]+) ?ms", out)
    if rc == 0 and m:
        return True, float(m.group(1))
    return False, 0.0


def code_for(answered: bool, rtt: float, threshold: int, failed_to_send: bool = False) -> str:
    if failed_to_send:
        return "No connection"
    if not answered:
        return "Timeout"
    return "Over threshold" if rtt > threshold else "OK"


def object_up(kind: str, code: str) -> bool:
    if kind == "reachability":
        return code in ("OK", "Over threshold")
    return code == "OK"


class Tracker:
    """The operations and objects, without touching the network: probe(op)
    returns (code, rtt); apply(changes) acts on what changed. tick(now)
    runs what is due."""

    def __init__(self, cfg: dict, probe, log=None):
        self.cfg = cfg
        self.probe = probe
        self.log = log or (lambda _t: None)
        self.ops: dict[int, dict] = {}
        self.objs: dict[int, dict] = {}
        self.reconfigure(cfg, 0.0)

    def reconfigure(self, cfg: dict, now: float) -> None:
        self.cfg = cfg
        for k in [k for k in self.ops if k not in cfg["sla"]]:
            del self.ops[k]
        for k, op in cfg["sla"].items():
            st = self.ops.setdefault(k, {"code": "Unknown", "rtt": 0.0, "ok": 0, "fail": 0, "last": 0.0,
                                         "next": now, "started": 0.0})
            if op["scheduled"] and not st["started"]:
                st["started"], st["next"] = now or 1e-9, now
            if not op["scheduled"]:
                st.update(code="Unknown", started=0.0)
        for k in [k for k in self.objs if k not in cfg["track"]]:
            del self.objs[k]
        for k in cfg["track"]:
            # An object starts Down, as IOS's does until its operation says otherwise.
            self.objs.setdefault(k, {"up": False, "changes": 0, "since": now, "pending": None})

    def tick(self, now: float) -> list[int]:
        """Runs due operations, then updates objects; returns the objects
        whose state changed."""
        for k, op in self.cfg["sla"].items():
            st = self.ops[k]
            if not op["scheduled"] or now < st["next"]:
                continue
            if op["life"] and now - st["started"] > op["life"]:
                continue
            code, rtt = self.probe(op)
            st["code"], st["rtt"], st["last"] = code, rtt, now
            st["ok" if code == "OK" else "fail"] += 1
            st["next"] = now + max(1, op["frequency"])
        changed = []
        for k, t in self.cfg["track"].items():
            obj = self.objs[k]
            code = self.ops.get(t["sla"], {}).get("code", "Unknown")
            want = object_up(t["kind"], code)
            if want == obj["up"]:
                obj["pending"] = None
                continue
            delay = t["up"] if want else t["down"]
            if obj["pending"] is None:
                obj["pending"] = now + delay
            if now >= obj["pending"]:
                obj.update(up=want, changes=obj["changes"] + 1, since=now, pending=None)
                self.log(f"%TRACK-6-STATE: {k} ip sla {t['sla']} {t['kind']} {'Down -> Up' if want else 'Up -> Down'}")
                changed.append(k)
        return changed

    def up(self, obj: int) -> bool:
        return bool(self.objs.get(obj, {}).get("up"))

    def status(self, now: float) -> dict:
        ops = {}
        for k, op in self.cfg["sla"].items():
            st = self.ops[k]
            ops[str(k)] = dict(op, code=st["code"], rtt=st["rtt"], ok=st["ok"], fail=st["fail"],
                               ago=round(now - st["last"], 1) if st["last"] else -1,
                               running=bool(op["scheduled"]))
        objs = {}
        for k, t in self.cfg["track"].items():
            o = self.objs[k]
            objs[str(k)] = dict(t, state="Up" if o["up"] else "Down", changes=o["changes"],
                                since=round(now - o["since"], 1),
                                pending=round(o["pending"] - now, 1) if o["pending"] else 0,
                                code=self.ops.get(t["sla"], {}).get("code", "Unknown"))
        return {"sla": ops, "track": objs}


# ------------------------------------------------------------------ the running program
def _run(*args: str, timeout: float = 10) -> tuple[int, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def ping_probe(op: dict) -> tuple[str, float]:
    wait = max(1, -(-op["timeout"] // 1000))
    args = ["ping", "-c", "1", "-W", str(wait)]
    if op["source"]:
        args += ["-I", op["source"]]
    rc, out = _run(*args, op["target"], timeout=wait + 5)
    answered, rtt = parse_ping(rc, out)
    failed = (not answered) and bool(re.search(r"unreachable|bad address|No such device|Cannot assign|"
                                               r"Network is unreachable|sendto", out, re.I))
    return code_for(answered, rtt, op["threshold"], failed), rtt


class Daemon:
    def __init__(self, conf: str, state_file: str = STATE_FILE):
        self.conf, self.state_file = conf, state_file
        self.reload_wanted = self.stop_wanted = False
        self.tracker = Tracker({"sla": {}, "track": {}, "routes": [], "vrrp": []}, ping_probe, self.log)
        self.vrrp_applied: dict[tuple[str, int], int] = {}

    def log(self, text: str) -> None:
        print(time.strftime("%b %d %H:%M:%S ") + text, flush=True)

    def load(self) -> None:
        try:
            with open(self.conf) as f:
                cfg = parse_conf(f.read())
        except (OSError, ConfError) as e:
            self.log(f"%SLA-3-CONFIG: {self.conf}: {e}; keeping what runs")
            return
        self.tracker.reconfigure(cfg, time.monotonic())
        self.vrrp_applied.clear()
        self.log(f"%SLA-6-CONFIG: {len(cfg['sla'])} operation(s), {len(cfg['track'])} object(s)")

    def routes(self) -> None:
        """Tracked routes in the kernel while their object is Up; again on
        every pass, as the console's own static routes are flushed and
        written again on a change (winlab/iosl3.py)."""
        for rt in self.tracker.cfg["routes"]:
            args = [rt["prefix"], *rt["how"].split(), "proto", str(ROUTE_PROTO), "metric", str(rt["metric"])]
            if self.tracker.up(rt["track"]):
                _run("ip", "route", "replace", *args)
            else:
                _run("ip", "route", "del", *args)

    def vrrp(self, force: bool = False) -> None:
        for v in self.tracker.cfg["vrrp"]:
            prio = v["priority"] - (0 if self.tracker.up(v["track"]) else v["decrement"])
            prio = max(1, min(254, prio))
            key = (v["iface"], v["group"])
            if force or self.vrrp_applied.get(key) != prio:
                _run("vtysh", "-c", "configure terminal", "-c", f"interface {v['iface']}",
                     "-c", f"vrrp {v['group']} priority {prio}", "-c", "end")
                self.vrrp_applied[key] = prio

    def write_state(self, now: float) -> None:
        data = dict(self.tracker.status(now), pid=os.getpid(), updated=time.time())
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
        last_force = 0.0
        while not self.stop_wanted:
            now = time.monotonic()
            if self.reload_wanted:
                self.reload_wanted = False
                self.load()
            self.tracker.tick(now)
            self.routes()
            force = now - last_force >= 30   # vrrpd's file is read again on a console change
            self.vrrp(force)
            if force:
                last_force = now
            self.write_state(now)
            time.sleep(1)
        self.log("%SLA-6-STOP: winlab-slad stopped")


def main(argv: list[str]) -> int:
    conf, state = CONF_FILE, STATE_FILE
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] in ("-c", "--conf") and i + 1 < len(argv):
            conf, i = argv[i + 1], i + 2
        elif argv[i] in ("-s", "--state") and i + 1 < len(argv):
            state, i = argv[i + 1], i + 2
        elif argv[i] in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            rest.append(argv[i])
            i += 1
    if rest[:1] == ["check"]:
        try:
            with open(conf) as f:
                cfg = parse_conf(f.read())
        except (OSError, ConfError) as e:
            print(f"{conf}: {e}")
            return 1
        for k, op in cfg["sla"].items():
            print(f"ip sla {k}: {op['type'] or '(no operation)'} {op['target']}, every {op['frequency']} s, "
                  f"{'scheduled' if op['scheduled'] else 'NOT scheduled'}")
        for k, t in cfg["track"].items():
            print(f"track {k}: ip sla {t['sla']} {t['kind']}")
        return 0
    if rest and rest[0] != "run":
        print("usage: winlab-slad [-c conf] [-s state] [run | check]")
        return 2
    Daemon(conf, state).run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
