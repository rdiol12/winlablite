"""Start of shift: the morning routine of a sysadmin, on the lab clock.

Every working morning starts the same way before the first call comes in:
what went off in the night, did last night's backups run, what is in the
queue and how close it is to breaching, what wore out, how long the
evaluation licences have left, how full every server's volumes are, and is
every clock still right. Then a checklist, worked top to bottom, and a line in
the handover notes.

`build` makes that report for a lab at lab time `now`:

- overnight alerts: what monitoring raised since the last shift started
  (or since yesterday's close of business, 17:00) (winlab/alerts.py);
- last night's backups: read inside each machine with Windows Server Backup
  (Get-WBSummary and Get-WBPolicy), so it is what the server itself says,
  not what winlab thinks happened;
- the ticket queue with each ticket's SLA (winlab/helpdesk.py);
- what wore out since then (winlab/wear.py);
- evaluation licence days left, as the Software Licensing service reports
  them (the same read as winlab/evaluation.py and slmgr /dlv);
- free space on every volume of every running server, and each clock's
  distance from lab time.

Reading inside a machine is one read-only command per running machine over
the serial guest agent; nothing is changed by looking.

The student's report shows only what the morning hands an admin (the
night's alerts, the queue, what wore out). Backups, disk space, licences and
clocks are blank rows the student fills in from the machines themselves
(Windows Server Backup, Explorer, slmgr /dlv, the clock); winlab's own read
stays hidden and grades those rows ("report") and the checklist.

The checklist is graded where a machine can say: every backup succeeded
within a day, every volume has 15% free, no evaluation under two weeks, every
clock within five minutes, every overnight alert acknowledged, every P1 and
P2 ticket taken and nothing past its respond target, every wear event's
ticket taken, and today's date in the lab notes (the handover). The student
ticks what they did; `check` reads the machines again and says which hold.
The shifts are kept per lab in var/labs/<lab>/shift.json.

The command line: `winlab shift start <lab>` (read and show the report),
`winlab shift check <lab>`, `winlab shift tick <lab> <item>`, `winlab shift
show <lab>`.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Callable

from . import labclock, paths

Runner = Callable[[str, str, str], tuple[bool, str]]

FILE = "shift.json"
CLOSE_HOUR = 17           # yesterday's close of business: where "overnight" starts
MORNING_HOUR = 6          # from this hour the day's shift is due
BACKUP_HOURS = 26         # a nightly backup older than this missed a night
FREE_PCT = 15             # the checklist's floor for free space
CLOCK_LIMIT = 300         # Kerberos' five minutes
LICENCE_DAYS = 14
KEEP_DAYS = 90

CHECKLIST: tuple[tuple[str, str], ...] = (
    ("alerts", "Read the night's alerts and acknowledge each one (or see it recovered)"),
    ("backups", "Check last night's backup on every server that has one; fix and rerun a failed one"),
    ("queue", "Work the queue: every P1 and P2 taken, nothing past its respond target"),
    ("wear", "Every wear event since yesterday has its ticket taken"),
    ("disks", f"Every server volume has at least {FREE_PCT}% free"),
    ("licence", f"No Windows evaluation within {LICENCE_DAYS} days of its end (rearm or plan the rebuild)"),
    ("clocks", "Every machine's clock within five minutes of lab time"),
    ("handover", "Write today's handover in the lab notes: a line starting with today's date"),
    ("report", "Fill in the backups, disk space, licences and clocks from the machines themselves"),
)
# The rows the student fills in, and how close a figure must be to winlab's read.
FILL_SECTIONS = ("backups", "disks", "licences", "clocks")
DISK_TOLERANCE = 3        # percentage points of free space
CLOCK_TOLERANCE = 2       # minutes
LICENCE_TOLERANCE = 1     # days
ITEMS = tuple(i for i, _t in CHECKLIST)

_lock = threading.RLock()

_LICENCE_APP = "55c92734-d682-4d71-983e-d6ec3f16059f"


# ------------------------------------------------------------------ storage
def shift_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        raw = json.loads(shift_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("days"), dict):
            return raw
    except (OSError, ValueError):
        pass
    return {"days": {}}


def save(lab_name: str, data: dict) -> None:
    keys = sorted(data["days"])
    for k in keys[:-KEEP_DAYS]:
        data["days"].pop(k, None)
    f = shift_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(f)


def day_key(t: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(t))


def overnight_since(data: dict, now: float) -> float:
    """Where the report starts: the last shift's start, when there was one
    in the last four days (a Monday reads back to Friday); otherwise
    yesterday's close of business."""
    lt = time.localtime(now)
    close = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday - 1, CLOSE_HOUR, 0, 0, 0, 0, -1))
    starts = [float(d.get("started") or 0) for k, d in data["days"].items()
              if k != day_key(now) and now - 4 * 86400 < float(d.get("started") or 0) < now]
    return max(starts) if starts else close


# ------------------------------------------------------------------ reading a machine
def probe_command(node) -> tuple[str, str]:
    """The read-only morning read of one machine: its clock, its volumes,
    and on Windows the licence and Windows Server Backup's own summary."""
    if node.kind == "linux":
        return ("echo \"time|$(date +%s)\"; df -P -k 2>/dev/null | awk 'NR>1 && $1 ~ /^\\/dev\\// "
                "{print \"vol|\" $6 \"|\" $2*1024 \"|\" $4*1024}'"), "sh"
    return ("; ".join((
        "$o = @()",
        "$o += 'time|' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()",
        "Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | "
        "ForEach-Object { $o += \"vol|$($_.DeviceID)|$($_.Size)|$($_.FreeSpace)\" }",
        "$p = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter \"ApplicationID='" + _LICENCE_APP
        + "' AND PartialProductKey IS NOT NULL\" -ErrorAction SilentlyContinue | Select-Object -First 1",
        "if ($p) { $l = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction SilentlyContinue; "
        "$o += ('lic|{0}|{1}|{2}|{3}' -f $p.LicenseStatus, $p.GracePeriodRemaining, $l.RemainingWindowsReArmCount, "
        "$p.Description) }",
        "$u = { param($d) if ($d -and ([datetime]$d).Year -gt 2000) { ([DateTimeOffset][datetime]$d).ToUnixTimeSeconds() } else { 0 } }",
        "if (Get-Module -ListAvailable -Name WindowsServerBackup) { Import-Module WindowsServerBackup -ErrorAction "
        "SilentlyContinue; $pol = Get-WBPolicy -ErrorAction SilentlyContinue; $s = Get-WBSummary -ErrorAction "
        "SilentlyContinue; if ($s) { $o += ('wb|{0}|{1}|{2}|{3}|{4}|{5}' -f ([int][bool]$pol), "
        "(& $u $s.LastSuccessfulBackupTime), (& $u $s.LastBackupTime), $s.LastBackupResultHR, "
        "(& $u $s.NextBackupTime), $s.NumberOfVersions) } }",
        "$o -join \"`n\"",
    ))), "powershell"


def parse_probe(node_id: str, text: str, now: float) -> dict:
    from . import evaluation
    out: dict = {"time": None, "vols": [], "lic": None, "wb": None}
    for line in (text or "").splitlines():
        f = line.strip().split("|")
        try:
            if f[0] == "time" and len(f) >= 2:
                out["time"] = int(float(f[1]))
            elif f[0] == "vol" and len(f) >= 4 and f[2] and f[3]:
                out["vols"].append((f[1], int(float(f[2])), int(float(f[3]))))
            elif f[0] == "lic" and len(f) >= 5:
                c = evaluation.parse(node_id, "|".join(f[1:]), now)
                out["lic"] = {"evaluation": c.evaluation, "days": c.days_left, "rearms": c.rearms_left,
                              "status": c.status}
            elif f[0] == "wb" and len(f) >= 7:
                out["wb"] = {"policy": f[1] == "1", "last_ok": int(float(f[2] or 0)), "last": int(float(f[3] or 0)),
                             "result": int(float(f[4] or 0)), "next": int(float(f[5] or 0)),
                             "versions": int(float(f[6] or 0))}
        except (ValueError, IndexError, evaluation.EvaluationError):
            continue
    return out


def read_all(lab, runner: Runner, running: list[str], now: float) -> dict[str, dict]:
    """Every running machine read once; one that does not answer is left out."""
    from .appliances import console_driven
    out: dict[str, dict] = {}
    for nid in running:
        node = lab.nodes.get(nid)
        if node is None or (node.kind == "linux" and console_driven(node.image)):
            continue
        if node.kind not in ("linux",) and not node.is_windows:
            continue
        cmd, shell = probe_command(node)
        try:
            ok, text = runner(nid, cmd, shell)
        except Exception:  # noqa: BLE001 - one machine must not stop the rest
            ok, text = False, ""
        if ok:
            out[nid] = parse_probe(nid, text, now)
    return out


# ------------------------------------------------------------------ the report
def backup_row(name: str, wb: dict, now: float) -> dict:
    """What Windows Server Backup says about last night, in words."""
    if not wb["policy"] and not wb["last"]:
        return {"ok": None, "text": "the backup feature is installed, no backup is scheduled"}
    if not wb["last"]:
        return {"ok": False, "text": "scheduled, but no backup has run yet"}
    if wb["result"] != 0:
        return {"ok": False, "text": f"the last backup failed (result 0x{wb['result'] & 0xFFFFFFFF:08X})"}
    if wb["last_ok"] < now - BACKUP_HOURS * 3600:
        return {"ok": False, "text": f"no successful backup since {labclock.stamp(wb['last_ok'])}"}
    return {"ok": True, "text": f"succeeded {labclock.stamp(wb['last_ok'])}, {wb['versions']} versions kept"}


def _server(node) -> bool:
    from . import alerts
    return alerts._server(node)


def build(lab, reads: dict[str, dict], now: float, since: float) -> dict:
    """The morning report from what the machines said and what winlab keeps."""
    from . import alerts, helpdesk, naming, notes, wear
    name = lambda nid: naming.display(lab, nid)  # noqa: E731 - a short local helper
    data = alerts.load(lab.name)
    night = [a for a in data["alerts"] if float(a["opened"]) >= since]
    rows_alerts = [{"id": a["id"], "severity": a["severity"], "title": a["title"], "node": alerts._where(lab, a["node"]),
                    "opened": a["opened"], "acked": bool(a.get("acked")), "cleared": bool(a.get("cleared")),
                    "ticket": a.get("ticket", "")} for a in sorted(night, key=lambda a: a["opened"])]
    backups, licences, disks, clocks = [], [], [], []
    for nid, r in sorted(reads.items()):
        node = lab.nodes.get(nid)
        if r.get("wb"):
            backups.append({"node": nid, "name": name(nid), **backup_row(name(nid), r["wb"], now),
                            "last": r["wb"]["last"], "last_ok": r["wb"]["last_ok"], "next": r["wb"]["next"]})
        if r.get("lic"):
            lic = r["lic"]
            licences.append({"node": nid, "name": name(nid), "evaluation": lic["evaluation"], "days": lic["days"],
                             "rearms": lic["rearms"], "warn": lic["evaluation"] and lic["days"] <= LICENCE_DAYS})
        if node is not None and _server(node) and r["vols"]:
            vols = [{"dev": d, "size": s, "free": f, "pct": round(f * 100 / s, 1) if s else 0.0,
                     "low": bool(s) and f * 100 / s < FREE_PCT} for d, s, f in r["vols"]]
            disks.append({"node": nid, "name": name(nid), "vols": vols})
        if r.get("time") is not None:
            clocks.append({"node": nid, "name": name(nid), "off": int(r["time"] - now)})
    hv = helpdesk.view(lab, now)
    tickets = [{"id": t["id"], "priority": t["priority"], "summary": t["summary"], "state": t["state"],
                "caller": t["caller"], "assignee": t["assignee"], "due": t["due"], "breached": t["breached"],
                "respond_breached": t["sla"]["respond"]["state"] == "breached", "node": t["node"]}
               for t in hv["tickets"] if t["state"] in helpdesk.OPEN_STATES]
    ws = wear.load(lab.name)
    wear_rows = [{"id": e["id"], "title": wear.describe(lab, e), "at": e["at"], "state": e["state"],
                  "ticket": e.get("ticket", "")} for e in wear.since(ws, since)]
    rep = {"lab": lab.name, "at": now, "since": since, "day": day_key(now), "alerts": rows_alerts,
           "backups": backups, "tickets": tickets, "wear": wear_rows, "licences": licences, "disks": disks,
           "clocks": clocks, "read": sorted(reads), "notes_today": day_key(now) in notes.load(lab.name)["text"]}
    rep["grades"] = grade(rep, hv)
    return rep


# ------------------------------------------------------------------ the rows the student fills
def fill_rows(rep: dict) -> dict[str, list[dict]]:
    """The blank rows of the report: which machine (and volume) to look at,
    never what winlab read there."""
    reads = rep.get("read") or []
    names = {x["node"]: x["name"] for sec in ("backups", "licences", "clocks", "disks") for x in rep.get(sec, [])}
    windows = sorted({x["node"] for x in rep.get("licences", [])} | {x["node"] for x in rep.get("backups", [])})
    return {
        "backups": [{"key": n, "name": names.get(n, n)} for n in windows],
        "disks": [{"key": f"{d['node']}|{v['dev']}", "name": f"{d['name']} {v['dev']}"}
                  for d in rep.get("disks", []) for v in d["vols"]],
        "licences": [{"key": n, "name": names.get(n, n)} for n in windows],
        "clocks": [{"key": n, "name": names.get(n, n)} for n in reads if n in names],
    }


def truth(rep: dict) -> dict[str, dict[str, object]]:
    """winlab's hidden read, keyed like the rows."""
    bk = {b["node"]: ("ok" if b["ok"] else "failed" if b["ok"] is False else "none") for b in rep.get("backups", [])}
    return {
        "backups": {r["key"]: bk.get(r["key"], "none") for r in fill_rows(rep)["backups"]},
        "disks": {f"{d['node']}|{v['dev']}": v["pct"] for d in rep.get("disks", []) for v in d["vols"]},
        "licences": {x["node"]: (max(0, x["days"]) if x["evaluation"] else "licensed") for x in rep.get("licences", [])},
        "clocks": {c["node"]: round(c["off"] / 60) for c in rep.get("clocks", [])},
    }


def matches(section: str, want, got) -> bool:
    g = str(got if got is not None else "").strip().lower()
    if not g:
        return False
    try:
        if section == "backups":
            return g == str(want)
        if section == "licences":
            return g == "licensed" if want == "licensed" else abs(int(float(g)) - int(want)) <= LICENCE_TOLERANCE
        if section == "disks":
            return abs(float(g.rstrip("%")) - float(want)) <= DISK_TOLERANCE
        if section == "clocks":
            return abs(float(g) - float(want)) <= CLOCK_TOLERANCE
    except (TypeError, ValueError):
        return False
    return False


def grade_filled(rep: dict, filled: dict) -> dict:
    """The "report" item: every row filled, every figure close to the read."""
    tr = truth(rep)
    total = sum(len(v) for v in tr.values())
    ok = sum(1 for sec, rows in tr.items() for k, want in rows.items()
             if matches(sec, want, ((filled or {}).get(sec) or {}).get(k)))
    blank = sum(1 for sec, rows in tr.items() for k in rows if not str(((filled or {}).get(sec) or {}).get(k) or "").strip())
    if not total:
        return {"ok": None, "detail": "no machine was read"}
    return {"ok": ok == total, "detail": f"{ok} of {total} rows match what the machines say"
            + (f", {blank} still blank" if blank else "")}


def fill(lab_name: str, section: str, key: str, value: str, now: float | None = None) -> dict:
    """The student writes one row of the report."""
    if section not in FILL_SECTIONS:
        raise ValueError(f"report sections: {', '.join(FILL_SECTIONS)}")
    at = labclock.load(lab_name).now() if now is None else now
    with _lock:
        data = load(lab_name)
        day = data["days"].setdefault(day_key(at), {"started": at, "ticked": []})
        day.setdefault("filled", {}).setdefault(section, {})[str(key)[:80]] = str(value or "")[:40]
        save(lab_name, data)
        return day["filled"]


# Checklist items whose detail would read the machines for the student: the
# view says only how many hold, never which machine or what figure.
_HIDDEN_DETAIL = {"backups": "backups", "disks": "volumes", "licence": "machines", "clocks": "clocks"}


def _student_grade(item: str, g: dict) -> dict:
    if item not in _HIDDEN_DETAIL or g.get("ok") is None:
        return g
    return {"ok": g["ok"], "detail": "holds on every machine read" if g["ok"]
            else f"not on every machine yet: check the {_HIDDEN_DETAIL[item]} yourself"}


def grade(rep: dict, hv: dict | None = None) -> dict[str, dict]:
    """Each checklist item: ok True/False, or None when there is nothing to
    say (no backup scheduled anywhere, no machine read)."""
    g: dict[str, dict] = {}

    def put(item: str, ok, detail: str) -> None:
        g[item] = {"ok": ok, "detail": detail}
    al = rep["alerts"]
    left = [a for a in al if not a["acked"] and not a["cleared"]]
    put("alerts", not left, f"{len(left)} of {len(al)} not acknowledged" if left else
        (f"all {len(al)} acknowledged or recovered" if al else "a quiet night: no alerts"))
    bk = [b for b in rep["backups"] if b["ok"] is not None]
    bad = [b for b in bk if not b["ok"]]
    put("backups", (not bad) if bk else None,
        ", ".join(f"{b['name']}: {b['text']}" for b in bad) if bad else
        (f"{len(bk)} server{'s' if len(bk) != 1 else ''} backed up last night" if bk else
         "no server has a scheduled backup: that is a finding for the plan"))
    tk = rep["tickets"]
    untaken = [t for t in tk if t["priority"] in ("P1", "P2") and t["state"] == "new"]
    late = [t for t in tk if t["respond_breached"] and t["state"] == "new"]
    put("queue", not untaken and not late,
        f"{len(untaken)} P1/P2 not taken, {len(late)} past their respond target" if untaken or late
        else f"{len(tk)} open, all high ones taken")
    wr = [w for w in rep["wear"] if w["state"] == "open"]
    tickets = {t["id"]: t for t in tk}
    idle = [w for w in wr if w["ticket"] in tickets and tickets[w["ticket"]]["state"] == "new"]
    put("wear", not idle, f"{len(idle)} wear ticket{'s' if len(idle) != 1 else ''} not taken" if idle else
        (f"{len(wr)} open, all taken" if wr else "nothing wore out"))
    vols = [(d["name"], v) for d in rep["disks"] for v in d["vols"]]
    low = [f"{n} {v['dev']} {v['pct']}%" for n, v in vols if v["low"]]
    put("disks", (not low) if vols else None, "low: " + ", ".join(low) if low else
        (f"{len(vols)} volumes, all above {FREE_PCT}%" if vols else "no server was read"))
    ev = [x for x in rep["licences"] if x["evaluation"]]
    near = [f"{x['name']} {max(0, x['days'])} days" for x in ev if x["warn"]]
    put("licence", (not near) if rep["licences"] else None, "running out: " + ", ".join(near) if near else
        (f"{len(ev)} evaluation{'s' if len(ev) != 1 else ''}, the nearest {min(x['days'] for x in ev)} days away" if ev
         else ("all licensed" if rep["licences"] else "no Windows machine was read")))
    off = [f"{c['name']} {round(c['off'] / 60)} min" for c in rep["clocks"] if abs(c["off"]) > CLOCK_LIMIT]
    put("clocks", (not off) if rep["clocks"] else None, "off: " + ", ".join(off) if off else
        (f"{len(rep['clocks'])} clocks within five minutes" if rep["clocks"] else "no machine was read"))
    put("handover", bool(rep.get("notes_today")), "today's date is in the lab notes" if rep.get("notes_today")
        else f"no line with {rep['day']} in the lab notes yet")
    return g


def score(grades: dict) -> tuple[int, int]:
    graded = [v for v in grades.values() if v["ok"] is not None]
    return sum(1 for v in graded if v["ok"]), len(graded)


# ------------------------------------------------------------------ a shift
def _running(lab) -> list[str]:
    from . import oncall
    return oncall.running_nodes(lab)


def start(lab, runner: Runner, now: float | None = None, running: list[str] | None = None) -> dict:
    """The morning: read the machines, build the report, keep it as today's shift."""
    at = labclock.load(lab.name).now() if now is None else now
    run = _running(lab) if running is None else running
    reads = read_all(lab, runner, run, at)
    with _lock:
        data = load(lab.name)
        since = overnight_since(data, at)
        rep = build(lab, reads, at, since)
        day = data["days"].setdefault(rep["day"], {"started": at, "ticked": []})
        day.setdefault("started", at)
        day["report"], day["checked"] = rep, at
        save(lab.name, data)
    return rep


def check(lab, runner: Runner, now: float | None = None, running: list[str] | None = None) -> dict:
    """Read the machines again and grade today's checklist."""
    at = labclock.load(lab.name).now() if now is None else now
    data = load(lab.name)
    day = data["days"].get(day_key(at))
    if not day or not day.get("report"):
        return start(lab, runner, at, running)
    run = _running(lab) if running is None else running
    reads = read_all(lab, runner, run, at)
    with _lock:
        data = load(lab.name)
        day = data["days"][day_key(at)]
        rep = build(lab, reads, at, float(day["report"]["since"]))
        day["report"], day["checked"] = rep, at
        save(lab.name, data)
    return rep


def tick(lab_name: str, item: str, done: bool = True, now: float | None = None) -> list[str]:
    """The student ticks (or unticks) a checklist item."""
    if item not in ITEMS:
        raise ValueError(f"checklist items: {', '.join(ITEMS)}")
    at = labclock.load(lab_name).now() if now is None else now
    with _lock:
        data = load(lab_name)
        day = data["days"].setdefault(day_key(at), {"started": at, "ticked": []})
        ticked = set(day.get("ticked") or [])
        (ticked.add if done else ticked.discard)(item)
        day["ticked"] = [i for i in ITEMS if i in ticked]
        save(lab_name, data)
        return day["ticked"]


def today(lab_name: str, now: float | None = None) -> dict | None:
    at = labclock.load(lab_name).now() if now is None else now
    return load(lab_name)["days"].get(day_key(at))


def result(day: dict | None) -> dict:
    """A day's shift in numbers, for the company journal."""
    if not day or not day.get("report"):
        return {"done": False, "passed": 0, "graded": 0, "ticked": 0}
    p, n = score(day["report"]["grades"])
    return {"done": True, "passed": p, "graded": n, "ticked": len(day.get("ticked") or [])}


def due(lab_name: str, now: float | None = None) -> bool:
    """Today's shift has not started and it is morning or later."""
    at = labclock.load(lab_name).now() if now is None else now
    return time.localtime(at).tm_hour >= MORNING_HOUR and not (today(lab_name, at) or {}).get("report")


def view(lab, now: float | None = None) -> dict:
    """What the student sees: the report without winlab's read of backups,
    disks, licences and clocks (blank rows to fill instead, with what was
    written), and the checklist without the figures."""
    at = labclock.load(lab.name).now() if now is None else now
    day = today(lab.name, at) or {}
    full = day.get("report")
    grades = dict((full or {}).get("grades") or {})
    if full:
        grades["report"] = grade_filled(full, day.get("filled") or {})
    items = [{"id": i, "text": t, "ticked": i in (day.get("ticked") or []),
              **_student_grade(i, grades.get(i) or {"ok": None, "detail": ""})} for i, t in CHECKLIST]
    p, n = score(grades) if full else (0, 0)
    rep = None
    if full:
        rep = {k: v for k, v in full.items() if k not in FILL_SECTIONS + ("grades",)}
        rep["fill"] = fill_rows(full)
        rep["filled"] = day.get("filled") or {}
    return {"lab": lab.name, "now": at, "day": day_key(at), "report": rep, "checklist": items,
            "due": due(lab.name, at), "passed": p, "graded": n, "checked": day.get("checked")}


# ------------------------------------------------------------------ text
def _ago(secs: float) -> str:
    s = int(abs(secs))
    return f"{s // 3600}h {s % 3600 // 60:02d}m" if s >= 3600 else f"{s // 60}m"


def render(v: dict) -> str:
    rep = v["report"]
    if not rep:
        return f"no shift yet on {v['day']}: winlab shift start {v['lab']}"
    out = [f"Start of shift, {v['lab']}, {labclock.stamp(rep['at'])} (lab time)",
           f"overnight since {labclock.stamp(rep['since'])}", ""]
    out.append(f"Alerts overnight ({len(rep['alerts'])})")
    for a in rep["alerts"]:
        out.append(f"  #{a['id']} {a['severity']} {labclock.stamp(a['opened'])[5:16]}  {a['title']} on {a['node']}"
                   f"  {'recovered' if a['cleared'] else 'acknowledged' if a['acked'] else 'NOT ACKNOWLEDGED'}"
                   + (f"  {a['ticket']}" if a["ticket"] else ""))
    filled = rep.get("filled") or {}

    def blanks(section: str, hint: str) -> None:
        for r in rep["fill"][section]:
            got = (filled.get(section) or {}).get(r["key"], "")
            out.append(f"  {r['name']:<16} {got or '____'}" + ("" if got else f"   ({hint})"))
    out.append(f"Last night's backups ({len(rep['fill']['backups'])})")
    blanks("backups", "ok, failed or none: read Windows Server Backup on the server")
    out.append(f"Ticket queue ({len(rep['tickets'])} open)")
    for t in rep["tickets"]:
        d = t["due"]
        sla = ("BREACHED " + _ago(d["left"])) if d["left"] < 0 else f"{_ago(d['left'])} left"
        out.append(f"  {t['id']} {t['priority']} {t['state']:<11} {sla:<16} {t['summary']}")
    out.append(f"Wear since yesterday ({len(rep['wear'])})")
    for w in rep["wear"]:
        out.append(f"  {w['id']} {labclock.stamp(w['at'])[5:16]} {w['state']:<6} {w['title']}"
                   + (f"  {w['ticket']}" if w["ticket"] else ""))
    out.append("Evaluation licences")
    blanks("licences", "days left, or licensed: slmgr /dlv")
    out.append("Disk space")
    blanks("disks", "% free")
    out.append("Clocks")
    blanks("clocks", "minutes off lab time, + ahead, - behind")
    out.append("")
    out.append(f"Checklist ({v['passed']} of {v['graded']} hold)")
    for it in v["checklist"]:
        mark = "[x]" if it["ticked"] else "[ ]"
        verdict = "holds" if it["ok"] else "--" if it["ok"] is None else "NOT YET"
        out.append(f"  {mark} {it['id']:<9} {verdict:<8} {it['text']}")
        if it.get("detail"):
            out.append(f"      {it['detail']}")
    return "\n".join(out)


# ------------------------------------------------------------------ the command line
def add_cli(sub) -> None:
    sp = sub.add_parser("shift", help="start of shift: the night's alerts, backups, queue, wear, licences, disks and a checklist")
    ss = sp.add_subparsers(dest="shiftcmd", metavar="<op>")
    for name, what in (("start", "read the machines and show this morning's report"),
                       ("check", "read the machines again and grade the checklist"),
                       ("show", "today's report as last read, without reading the machines")):
        ss.add_parser(name, help=what).add_argument("lab", nargs="?", default="")
    sf = ss.add_parser("fill", help="write one row of the report: backups, disks, licences or clocks")
    sf.add_argument("lab")
    sf.add_argument("section", choices=list(FILL_SECTIONS))
    sf.add_argument("key", help="the machine (for disks: machine|volume, like fs01|C:)")
    sf.add_argument("value")
    st = ss.add_parser("tick", help="tick (or --undo) a checklist item")
    st.add_argument("lab")
    st.add_argument("item", choices=list(ITEMS))
    st.add_argument("--undo", action="store_true")


def run_cli(args) -> int:
    import sys

    from . import oncall, schema
    from .cli import _resolve_lab
    try:
        lab = schema.load(_resolve_lab(getattr(args, "lab", "")))
    except Exception as exc:  # noqa: BLE001 - the CLI reports it
        print(f"{exc}", file=sys.stderr)
        return 2
    op = args.shiftcmd or "show"
    if op in ("start", "check"):
        run = oncall.guest_runner(lab.name)
        (start if op == "start" else check)(lab, run)
    elif op == "tick":
        tick(lab.name, args.item, not args.undo)
    elif op == "fill":
        fill(lab.name, args.section, args.key, args.value)
    print(render(view(lab)))
    return 0
