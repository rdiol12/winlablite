"""Live meters and alerts for the running machines, watched from the host.

Nothing runs inside a guest. A machine's CPU is its QEMU process's
(winlab/procstats.py); its memory is what the guest itself reports through
the virtio balloon's statistics (QMP guest-stats: total and available, as
Task Manager counts them), and "n/a" when the guest's balloon driver does
not report (the QEMU process's size says nothing about the guest: Windows
touches all of its memory at boot). Its disk I/O is QEMU's own block
statistics (QMP query-blockstats: bytes, operations and the time they took,
so latency too), and its network is the router's switch port its cable is
in (the port's byte, error and drop counters, and the drops of the qdiscs a
bad cable of winlab/physfaults.py puts on it). The router's counters ride on
the workbench's live read (workbench.Live), so watching costs no extra trip
to the router.

A sampler thread reads everything every few seconds while the desktop polls
(slower while nobody looks), keeps a few minutes of history for the
sparklines, and checks each machine's alert rules: CPU or memory high for a
while, disk latency high, a link down, errors on a cable, a machine that
went off without winlab stopping it. The rules a user changes, and the
alerts with their history, are kept beside the lab's machines (alerts.json),
never in the lab file.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from . import paths, state

FILE = "alerts.json"
EVERY, IDLE_EVERY = 4.0, 20.0   # seconds between samples: watched, nobody looking
WATCHED_FOR = 15.0              # a poll keeps the fast pace this long
KEEP = 90                       # samples of history per machine (6 minutes at 4 s)
HISTORY_MAX = 200
GRACE = 8.0                     # a machine gone this long, not stopped by winlab: unexpected

# Seams for the tests: QMP, and a pid -> procstats.Usage reader.
qmp_class = None
usage_reader = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    unit: str        # what the limit is in ("" for a rule with none)
    limit: float     # default threshold
    seconds: int     # default time the condition must hold
    on: bool         # on unless the user turns it off
    level: str       # "warning" or "error"
    text: str


RULES: dict[str, Rule] = {r.id: r for r in (
    Rule("cpu", "CPU high", "%", 90, 120, True, "warning", "CPU above {limit}% for {for}"),
    Rule("mem", "Memory high", "%", 95, 300, False, "warning",
         "the QEMU process holds over {limit}% of the memory given to the machine for {for}"),
    Rule("disk", "Disk latency high", "ms", 100, 60, True, "warning",
         "disk operations take over {limit} ms on average for {for}"),
    Rule("link", "Link down", "", 0, 10, True, "error",
         "a cabled port has no link while the machine runs, for {for}"),
    Rule("errors", "Cable errors", "/min", 10, 0, True, "warning",
         "more than {limit} errors or drops a minute on a cable"),
    Rule("stopped", "Stopped unexpectedly", "", 0, 0, True, "error",
         "the machine went off without being stopped from winlab (shut down inside, or crashed)"),
)}


def _for(s: float) -> str:
    s = int(s)
    return f"{s // 60} min" if s >= 60 and s % 60 == 0 else f"{s} s"


# ------------------------------------------------------------------ the router's counters
COUNTERS_CMD = ("echo '#ifstat'; for i in /sys/class/net/*; do s=$i/statistics; "
                "echo \"${i##*/} $(cat $s/rx_bytes $s/tx_bytes $s/rx_errors $s/tx_errors "
                "$s/rx_dropped $s/tx_dropped $i/operstate 2>/dev/null | tr '\\n' ' ')\"; done; "
                "echo '#qdisc'; tc -s qdisc show 2>/dev/null")


def parse_counters(text: str) -> dict[str, dict]:
    """The router's interfaces: {iface: {rx, tx, errors, drops, up}}. rx is
    what came in on the port (what the machine sent), tx what went out to
    it; drops add the qdiscs' (a bad cable's netem, a policer)."""
    out: dict[str, dict] = {}
    section, dev = "", ""
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("#") and " " not in s:
            section = s[1:]
            continue
        parts = s.split()
        if section == "ifstat" and len(parts) >= 7:
            try:
                rx, tx, re_, te, rd, td = (int(p) for p in parts[1:7])
            except ValueError:
                continue
            out[parts[0]] = {"rx": rx, "tx": tx, "errors": re_ + te, "drops": rd + td,
                             "up": len(parts) < 8 or parts[7] in ("up", "unknown")}
        elif section == "qdisc":
            if parts[:1] == ["qdisc"] and "dev" in parts:
                dev = parts[parts.index("dev") + 1]
            elif "(dropped" in parts and dev in out:
                try:
                    out[dev]["drops"] += int(parts[parts.index("(dropped") + 1].rstrip(","))
                except (ValueError, IndexError):
                    pass
    return out


# ------------------------------------------------------------------ QEMU's block statistics
def _blockstats(qmp_port: int) -> dict | None:
    """The machine's disks together: bytes, operations and nanoseconds."""
    if not qmp_port:
        return None
    cls = qmp_class
    if cls is None:
        from .qmp import Qmp as cls
    try:
        with cls(qmp_port, timeout=3) as mon:
            devs = mon.call("query-blockstats") or []
    except Exception:  # noqa: BLE001 - a busy monitor is a gap in the graph
        return None
    tot = {"rd": 0, "wr": 0, "ops": 0, "ns": 0}
    for d in devs:
        st = d.get("stats") or {}
        tot["rd"] += int(st.get("rd_bytes", 0))
        tot["wr"] += int(st.get("wr_bytes", 0))
        tot["ops"] += int(st.get("rd_operations", 0)) + int(st.get("wr_operations", 0))
        tot["ns"] += int(st.get("rd_total_time_ns", 0)) + int(st.get("wr_total_time_ns", 0))
    return tot


# The balloon device's QOM path per monitor port, once found.
_BALLOON: dict[int, str] = {}
STATS_EVERY = 2   # seconds between the guest driver's memory reports


def _balloon_path(mon, port: int) -> str:
    """Finds the virtio balloon among the machine's devices (it is added
    without an id) and asks its guest driver to report every few seconds."""
    if port in _BALLOON:
        return _BALLOON[port]
    path = ""
    for parent in ("/machine/peripheral-anon", "/machine/peripheral"):
        for child in mon.call("qom-list", path=parent) or []:
            if "virtio-balloon" in str(child.get("type", "")):
                path = f"{parent}/{child['name']}"
                break
        if path:
            break
    if path:
        mon.call("qom-set", path=path, property="guest-stats-polling-interval", value=STATS_EVERY)
    _BALLOON[port] = path
    return path


def guest_memory(stats: dict) -> tuple[int, int] | None:
    """(used MB, total MB) from the balloon's guest-stats, or None when the
    driver has not reported (QEMU gives -1 for a value it does not have)."""
    s = (stats or {}).get("stats") or {}
    total = int(s.get("stat-total-memory", -1))
    free = int(s.get("stat-available-memory", -1))
    if free < 0:
        free = int(s.get("stat-free-memory", -1))
    if total <= 0 or free < 0 or not (stats or {}).get("last-update"):
        return None
    return (max(0, total - free) // (1024 * 1024), total // (1024 * 1024))


def _guest_mem(qmp_port: int) -> tuple[int, int] | None:
    if not qmp_port:
        return None
    cls = qmp_class
    if cls is None:
        from .qmp import Qmp as cls
    try:
        with cls(qmp_port, timeout=3) as mon:
            path = _balloon_path(mon, qmp_port)
            if not path:
                return None
            return guest_memory(mon.call("qom-get", path=path, property="guest-stats"))
    except Exception:  # noqa: BLE001 - no balloon, a busy monitor: memory shows n/a
        return None


def _alive(pid: int) -> bool:
    """state.pid_alive, and on Linux not a zombie: a QEMU that crashed
    under a parent that has not reaped it yet is gone all the same."""
    if not state.pid_alive(pid):
        return False
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return stat[stat.rindex(")") + 2:][:1] != "Z"
    except (OSError, ValueError):
        return True


def _delta(cur: int, prev: int | None) -> int:
    """A counter's growth; a counter that went back (a port re-made, a
    router restarted) starts over."""
    return 0 if prev is None or cur < prev else cur - prev


# ------------------------------------------------------------------ rules and alerts on disk
def _path(lab_name: str):
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
        if isinstance(data.get("history"), list):
            data.setdefault("rules", {})
            data.setdefault("seq", 0)
            return data
    except (OSError, ValueError, AttributeError):
        pass
    return {"rules": {}, "history": [], "seq": 0}


def _write(lab_name: str, data: dict) -> None:
    state.write_json(_path(lab_name), data)


def rules_of(data: dict, node_id: str) -> dict[str, dict]:
    """A machine's rules: the defaults with what the user changed on top."""
    mine = data["rules"].get(node_id, {})
    return {r.id: {"on": bool(mine.get(r.id, {}).get("on", r.on)),
                   "limit": float(mine.get(r.id, {}).get("limit", r.limit)),
                   "for": int(mine.get(r.id, {}).get("for", r.seconds))} for r in RULES.values()}


def _hidden_errors(lab_name: str) -> bool:
    """While "Break something for me" runs, the cables' error counts stay
    hidden: the drill is finding them with the lab's own tools."""
    from . import physfaults
    dr = physfaults.load(lab_name).get("drill")
    return bool(dr and not dr.get("done") and not dr.get("gave_up"))


# ------------------------------------------------------------------ the sampler
class Monitor:
    def __init__(self, lab_name: str) -> None:
        self.lab_name = lab_name
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._watched = 0.0
        self._prev: dict[str, dict] = {}         # per machine: last disk totals and time
        self._ports: dict[str, dict] = {}        # per router iface: last counters
        self._errs: dict[str, deque] = {}        # per cable: (t, accumulated errors+drops)
        self._hist: dict[str, deque] = {}
        self._since: dict[tuple[str, str], float] = {}
        self._muted: set[tuple[str, str]] = set()
        self._seen_on: dict[str, float] = {}     # machines running at the last sample
        self._gone: dict[str, float] = {}
        self._meter = None
        self.machines: dict[str, dict] = {}
        self.cables: dict[str, dict] = {}
        self.uplinks: dict[str, dict] = {}
        self.router = False
        self.at = 0.0

    # ---- the thread: samples while the desktop runs this lab
    def watch(self, dash) -> None:
        self._watched = time.monotonic()
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._loop, args=(dash,), daemon=True)
            self._thread.start()

    def _loop(self, dash) -> None:
        while dash.lab.name == self.lab_name:
            try:
                self.sample(dash)
            except Exception:  # noqa: BLE001 - the meters must keep going
                pass
            fast = time.monotonic() - self._watched < WATCHED_FOR
            time.sleep(EVERY if fast else IDLE_EVERY)

    # ---- one sample of everything, and the rules checked against it
    def sample(self, dash, now: float | None = None) -> None:
        from . import physfaults
        lab, plan = dash.lab, dash.plan
        now = time.monotonic() if now is None else now
        st = state.load(lab.name)
        nss = st.nodes if st else {}
        running = {nid for nid, ns in nss.items() if ns.pid and _alive(ns.pid)}
        self.router = "fabric" in running
        counters: dict[str, dict] = {}
        if self.router:
            live = dash.__dict__.get("wb_live")
            if live is not None:
                counters = live.read(lab).get("counters") or {}
        hide = _hidden_errors(lab.name)
        rates = self._port_rates(counters, now)
        cables = {}
        for link in plan.ports:
            if not link.plugged:
                continue
            r = rates.get(link.fabric_iface)
            on = link.node_id in running and self.router
            cables[link.label] = {"rx_bps": r["rx_bps"] if r and on else 0,
                                  "tx_bps": r["tx_bps"] if r and on else 0,
                                  "errors_min": None if hide else (self._err_rate(link.label, r, now) if r else 0),
                                  "up": bool(on and r and r["up"]) if counters else on}
        uplinks: dict[str, dict] = {}
        for seg in plan.segments.values():
            r = rates.get(seg.svi) if seg.network.routed else None
            if not r:
                continue
            u = uplinks.setdefault(getattr(seg.network, "home", "") or seg.network.id, {"rx_bps": 0, "tx_bps": 0})
            u["rx_bps"] += r["tx_bps"]  # out of the router's interface: down the uplink to the switch
            u["tx_bps"] += r["rx_bps"]
        nic_down = {(f["node"], f["nic"]) for f in physfaults.load(lab.name)["faults"]
                    if f["state"] == "on" and f["kind"] == "nic"}
        machines = {}
        for node in lab.node_list():
            ns = nss.get(node.id)
            alive = node.id in running
            m = {"running": alive, "cpu_pct": 0, "rss_mb": 0, "mem_pct": 0, "memory_mb": node.memory_mb,
                 "mem_used_mb": None, "mem_total_mb": None,
                 "disk": {"rd_bps": 0, "wr_bps": 0, "iops": 0, "lat_ms": 0.0},
                 "net": {"rx_bps": 0, "tx_bps": 0}, "links_down": []}
            if alive:
                u = self._usage(ns.pid, node.cpus)
                if u:
                    m["cpu_pct"], m["rss_mb"] = u.cpu_pct, u.rss_mb
                # Memory in use as the guest counts it; None (n/a) without
                # the balloon driver's report, never the QEMU process's size.
                gm = _guest_mem(ns.qmp_port)
                if gm:
                    m["mem_used_mb"], m["mem_total_mb"] = gm
                    m["mem_pct"] = min(100, round(gm[0] * 100 / max(1, gm[1])))
                else:
                    m["mem_pct"] = None
                m["disk"] = self._disk(node.id, ns.qmp_port, now)
                for link in plan.ports_for(node.id):
                    c = cables.get(link.label)
                    if not c:
                        continue
                    m["net"]["rx_bps"] += c["tx_bps"]  # the port sends what the machine receives
                    m["net"]["tx_bps"] += c["rx_bps"]
                    from .devcli import held_down
                    if self.router and (not c["up"] or held_down(lab, link)
                                        or (node.id, link.nic_index) in nic_down):
                        m["links_down"].append(link.nic_index)
            else:
                self._prev.pop(node.id, None)
                if ns:  # a new QEMU on that port is asked for its reports again
                    _BALLOON.pop(ns.qmp_port, None)
            h = self._hist.setdefault(node.id, deque(maxlen=KEEP))
            h.append((m["cpu_pct"], m["mem_pct"] or 0, m["disk"]["rd_bps"] + m["disk"]["wr_bps"],
                      m["net"]["rx_bps"] + m["net"]["tx_bps"]) if alive else (0, 0, 0, 0))
            machines[node.id] = m
        with self._lock:
            self.machines, self.cables, self.uplinks, self.at = machines, cables, uplinks, time.time()
        self._check(lab, nss, running, machines, cables, plan, now)

    def _usage(self, pid: int, vcpus: int):
        if usage_reader is not None:
            return usage_reader(pid, vcpus)
        if self._meter is None:
            from .procstats import Meter
            self._meter = Meter()
        return self._meter.usage(pid, vcpus)

    def _disk(self, node_id: str, qmp_port: int, now: float) -> dict:
        cur = _blockstats(qmp_port)
        out = {"rd_bps": 0, "wr_bps": 0, "iops": 0, "lat_ms": 0.0}
        if cur is None:
            return out
        prev = self._prev.get(node_id)
        self._prev[node_id] = {**cur, "t": now}
        if prev and now > prev["t"]:
            dt = now - prev["t"]
            ops = _delta(cur["ops"], prev["ops"])
            out = {"rd_bps": int(_delta(cur["rd"], prev["rd"]) / dt), "wr_bps": int(_delta(cur["wr"], prev["wr"]) / dt),
                   "iops": int(ops / dt), "lat_ms": round(_delta(cur["ns"], prev["ns"]) / ops / 1e6, 1) if ops else 0.0}
        return out

    def _port_rates(self, counters: dict[str, dict], now: float) -> dict[str, dict]:
        out = {}
        for iface, c in counters.items():
            prev = self._ports.get(iface)
            self._ports[iface] = {**c, "t": now}
            dt = now - prev["t"] if prev else 0
            out[iface] = {"rx_bps": int(_delta(c["rx"], prev["rx"]) / dt) if dt > 0 else 0,
                          "tx_bps": int(_delta(c["tx"], prev["tx"]) / dt) if dt > 0 else 0,
                          "bad": (_delta(c["errors"], prev["errors"]) + _delta(c["drops"], prev["drops"])) if prev else 0,
                          "up": c["up"]}
        return out

    def _err_rate(self, label: str, r: dict, now: float) -> int:
        """Errors and drops on a cable in the last minute."""
        q = self._errs.setdefault(label, deque())
        acc = (q[-1][1] if q else 0) + r["bad"]
        q.append((now, acc))
        while len(q) > 1 and now - q[0][0] > 60:
            q.popleft()
        return acc - q[0][1] if len(q) > 1 else 0

    # ---- the rules
    def _check(self, lab, nss, running, machines, cables, plan, now) -> None:
        data = load(lab.name)
        active = {(a["node"], a["rule"]): a for a in data["history"] if not a.get("ended")}
        changed = False
        for node in lab.node_list():
            m, rules = machines[node.id], rules_of(data, node.id)
            errs = [cables[l.label]["errors_min"] for l in plan.ports_for(node.id)
                    if l.label in cables and cables[l.label]["errors_min"] is not None]
            ns = nss.get(node.id)
            gone = False
            if node.id in running:
                self._seen_on[node.id] = now
                self._gone.pop(node.id, None)
            elif node.id in self._seen_on and ns and ns.phase not in ("stopped", state.SUSPENDED):
                t = self._gone.setdefault(node.id, now)
                gone = now - t >= GRACE
                if gone:
                    self._seen_on.pop(node.id, None)
            else:
                self._seen_on.pop(node.id, None)
                self._gone.pop(node.id, None)
            alive = m["running"]
            cond = {
                "cpu": (alive and m["cpu_pct"] > rules["cpu"]["limit"], f"{m['cpu_pct']}%"),
                "mem": (alive and m["mem_pct"] is not None and m["mem_pct"] > rules["mem"]["limit"],
                        f"{m['mem_pct']}%"),
                "disk": (alive and m["disk"]["lat_ms"] > rules["disk"]["limit"], f"{m['disk']['lat_ms']} ms"),
                "link": (alive and bool(m["links_down"]),
                         ", ".join(f"port {i + 1}" for i in m["links_down"])),
                "errors": (alive and bool(errs) and max(errs) > rules["errors"]["limit"],
                           f"{max(errs) if errs else 0} a minute"),
            }
            for rid, (bad, value) in cond.items():
                key, cfg = (node.id, rid), rules[rid]
                if not bad or not cfg["on"]:
                    self._since.pop(key, None)
                    self._muted.discard(key)
                    if key in active:
                        active.pop(key).update(ended=time.time(), how="cleared")
                        changed = True
                    continue
                t = self._since.setdefault(key, now)
                if key not in active and key not in self._muted and now - t >= cfg["for"]:
                    active[key] = self._fire(data, node.id, rid, cfg, value)
                    changed = True
                elif key in active:
                    active[key]["value"] = value
            key = (node.id, "stopped")
            if gone and rules["stopped"]["on"] and key not in active:
                active[key] = self._fire(data, node.id, "stopped", rules["stopped"], "off")
                changed = True
            elif node.id in running and key in active:
                active.pop(key).update(ended=time.time(), how="started again")
                changed = True
        if changed:
            data["history"] = data["history"][-HISTORY_MAX:]
            _write(lab.name, data)

    @staticmethod
    def _fire(data: dict, node_id: str, rid: str, cfg: dict, value: str) -> dict:
        r = RULES[rid]
        data["seq"] += 1
        rec = {"id": data["seq"], "node": node_id, "rule": rid, "title": r.title, "level": r.level,
               "text": r.text.format(limit=_num(cfg["limit"]), **{"for": _for(cfg["for"])}),
               "value": value, "at": time.time(), "ended": 0, "how": ""}
        data["history"].append(rec)
        return rec

    def acknowledge(self, lab_name: str, alert_id: int, note: str = "", who: str = "admin") -> dict:
        """Acknowledges an alert with a comment, as on the Pager: someone is
        on it. It stays active until the condition clears."""
        data = load(lab_name)
        for a in data["history"]:
            if a["id"] == alert_id and not a.get("ended"):
                a.update(acked=time.time(), acked_by=who, ack_note=str(note or "")[:500])
                _write(lab_name, data)
                return a
        raise ValueError(f"no open alert {alert_id}")

    def dismiss(self, lab_name: str, alert_id: int) -> dict:
        """Ends an alert by hand; it comes back only once the condition
        cleared and returned."""
        data = load(lab_name)
        for a in data["history"]:
            if a["id"] == alert_id and not a.get("ended"):
                a.update(ended=time.time(), how="dismissed")
                self._muted.add((a["node"], a["rule"]))
                _write(lab_name, data)
                return a
        raise ValueError(f"no open alert {alert_id}")

    def view(self, lab) -> dict:
        data = load(lab.name)
        with self._lock:
            machines = {k: {**v, "hist": [list(x) for x in zip(*self._hist.get(k, ()))] or [[], [], [], []]}
                        for k, v in self.machines.items()}
            out = {"ok": True, "at": self.at, "every": EVERY, "router": self.router,
                   "errors_hidden": _hidden_errors(lab.name),
                   "machines": machines, "cables": dict(self.cables), "uplinks": dict(self.uplinks)}
        act = [a for a in data["history"] if not a.get("ended")]
        for a in data["history"]:
            a["sev"] = severity(lab, a)
        for nid, m in out["machines"].items():
            m["alerts"] = sum(a["node"] == nid for a in act)
        out["alerts"] = {"active": act[::-1], "history": [a for a in data["history"] if a.get("ended")][::-1][:60],
                         "seq": data["seq"]}
        return out


def severity(lab, a: dict) -> str:
    """P1 to P4, the one severity model the Pager and the helpdesk use
    (alerts.PERF_SEVERITY: a server's alert is a step higher than a PC's)."""
    from . import alerts
    pair = alerts.PERF_SEVERITY.get(a.get("rule", ""), ("P3", "P4"))
    return pair[0] if alerts._server(lab.nodes.get(a.get("node", ""))) else pair[1]


def _num(x: float) -> str:
    return str(int(x)) if float(x).is_integer() else str(x)


def monitor(dash) -> Monitor:
    mons = dash.__dict__.setdefault("perf_monitors", {})
    mon = mons.get(dash.lab.name)
    if mon is None:
        mon = mons[dash.lab.name] = Monitor(dash.lab.name)
    return mon


def view(dash) -> dict:
    """GET /api/perf: one batched answer for every meter, cable and alert."""
    mon = monitor(dash)
    mon.watch(dash)
    return mon.view(dash.lab)


def rules_view(lab) -> dict:
    data = load(lab.name)
    return {"ok": True,
            "kinds": [{"id": r.id, "title": r.title, "unit": r.unit, "limit": r.limit, "for": r.seconds,
                       "on": r.on, "level": r.level, "tpl": r.text,
                       "text": r.text.format(limit=_num(r.limit), **{"for": _for(r.seconds)})} for r in RULES.values()],
            "machines": {n.id: rules_of(data, n.id) for n in lab.node_list()}}


def set_rule(lab, node_id: str, rule: str, on=None, limit=None, seconds=None) -> dict:
    """One machine's rule (node "*": every machine's)."""
    if rule not in RULES:
        raise ValueError(f"no alert rule {rule!r}")
    ids = [n.id for n in lab.node_list()] if node_id == "*" else [node_id]
    if node_id != "*" and node_id not in lab.nodes:
        raise ValueError(f"no machine {node_id!r}")
    data = load(lab.name)
    for nid in ids:
        cur = data["rules"].setdefault(nid, {}).setdefault(rule, {})
        if on is not None:
            cur["on"] = bool(on)
        if limit is not None:
            v = float(limit)
            if not math.isfinite(v) or v < 0:
                raise ValueError("the limit must be a number, 0 or more")
            cur["limit"] = v
        if seconds is not None:
            cur["for"] = max(0, min(3600, int(seconds)))
    _write(lab.name, data)
    return rules_of(data, ids[0]) if ids else {}


def act(dash, action: str, params: dict) -> dict:
    """The desktop's perf-* actions."""
    from . import naming
    lab = dash.lab
    try:
        if action == "perf-rules":
            return rules_view(lab)
        if action == "perf-rule":
            node = str(params.get("node") or "")
            node = node if node == "*" else naming.resolve(lab, node)
            on = params.get("on")
            set_rule(lab, node, str(params.get("rule") or ""),
                     on=None if on is None else on in (True, "1", "true", 1),
                     limit=params.get("limit"), seconds=params.get("for"))
            who = "every machine" if node == "*" else naming.display(lab, node)
            return {"ok": True, "message": f"{RULES[params['rule']].title}: saved for {who}", **rules_view(lab)}
        if action == "perf-ack":
            a = monitor(dash).acknowledge(lab.name, int(params.get("id") or 0), str(params.get("note") or ""))
            return {"ok": True, "message": f"{a['title']} on {naming.display(lab, a['node'])} acknowledged"}
        if action == "perf-dismiss":
            a = monitor(dash).dismiss(lab.name, int(params.get("id") or 0))
            return {"ok": True, "message": f"{a['title']} on {naming.display(lab, a['node'])} dismissed"}
        if action == "perf-clear":
            data = load(lab.name)
            data["history"] = [a for a in data["history"] if not a.get("ended")]
            _write(lab.name, data)
            return {"ok": True, "message": "alert history cleared"}
        return {"ok": False, "message": f"no such action {action!r}"}
    except (ValueError, KeyError) as exc:
        return {"ok": False, "message": str(exc)}
