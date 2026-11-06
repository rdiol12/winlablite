"""The company run: one lab that lasts weeks of lab time, like a real job.

A lesson is an afternoon; a job is months of the same servers. A company run
turns a lab into the company the student looks after: its disks are kept
(they always were: a lab's machines live in var/labs/<lab>/ until `lab reset`),
the lab clock moves on a working day at a time, and everything the student
built on day one is still there on day twenty, now with logs that grew,
licences that ran down and users who need things.

What a run does, all from modules that already exist:

- the lab clock (winlab/labclock.py) goes from one working morning to the
  next (Monday to Friday, 07:30) with `next day`: the night in between passes
  in one move, and the machines' clocks follow over their agents;
- wear (winlab/wear.py) is on at the run's level, so things wear out
  overnight and during the day;
- the helpdesk (winlab/helpdesk.py) takes calls in business hours, and the
  office's staff (winlab/workday.py) come in, sign in, save and print;
- every morning starts with the start-of-shift report and checklist
  (winlab/shift.py);
- each week has a plan of work: projects (lessons for this lab the student
  has not done yet, graded the way the lesson grades them), a problem to work
  (a troubleshooting lesson of this lab), and maintenance with a date
  (volumes above 20% free, no evaluation under 30 days, no ticket older than
  three days, last night's backups good), checked on the machines;
- a journal keeps each day (from one evening's close to the next, so the
  night belongs to the day it lands on): tickets in and resolved, the SLA met, incidents
  (P1 and P2 alerts), wear, service uptime (servers' time without a P1 or P2
  outage alert), the morning checklist, plan work done, and any machine that
  was rebuilt from its image (its earlier work gone);
- the run's totals (days run, tickets, the SLA met, incidents, uptime) go
  into the student's progress at the close of every day and when the run
  ends, and from there onto the skills transcript (winlab/transcript.py);
- `save` stops for the day: the lab clock pauses, the helpdesk stops taking
  calls (nothing is undone: what is broken stays broken), and with a
  checkpoint every machine's disks are kept as company-day<N> (winlab/
  snapshots.py). `resume` picks up where it stopped.

The run never builds anything for the student: it moves time, breaks what
wears out, and grades. Its record is var/labs/<lab>/company.json.
"""

from __future__ import annotations

import json
import random
import threading
import time
from pathlib import Path
from typing import Callable

from . import labclock, paths

Runner = Callable[[str, str, str], tuple[bool, str]]

FILE = "company.json"
DAY_START = (7, 30)       # each working morning
WEEK_DAYS = 5
DEFAULT_WEEKS = 4
DEFAULT_LEVEL = "realistic"
DEFAULT_PACE = "quiet"
PROJECTS_A_WEEK = 2
OUTAGE_SOURCES = ("power", "service")
MAINTENANCE: tuple[tuple[str, str], ...] = (
    ("disk20", "Every server volume above 20% free"),
    ("licence30", "No Windows evaluation under 30 days (rearm and restart, or plan the rebuild)"),
    ("backlog", "No ticket left open for more than three lab days"),
    ("backups", "Every scheduled server backup succeeded last night"),
)

_lock = threading.RLock()


class CompanyError(Exception):
    pass


# ------------------------------------------------------------------ storage
def company_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        raw = json.loads(company_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return raw
    except (OSError, ValueError):
        pass
    return {}


def save(lab_name: str, run: dict) -> None:
    f = company_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(run, indent=1), encoding="utf-8")
    tmp.replace(f)


def active(run: dict) -> bool:
    return bool(run) and not run.get("finished")


# ------------------------------------------------------------------ time
def next_morning(t: float) -> float:
    """The next working morning after `t`: tomorrow 07:30, Monday after a Friday."""
    lt = time.localtime(t)
    for add in range(1, 8):
        cand = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + add, DAY_START[0], DAY_START[1], 0, 0, 0, -1))
        if time.localtime(cand).tm_wday < 5:
            return cand
    raise ValueError("no working day ahead")


def week_of(day: int) -> int:
    return (max(1, day) - 1) // WEEK_DAYS + 1


# ------------------------------------------------------------------ the disks are kept
def disk_marks(lab) -> dict[str, str]:
    """One mark per machine's system disk: the same file keeps its mark, a
    machine rebuilt from its image (lab reset) gets a new one."""
    out = {}
    for nid in lab.nodes:
        f = paths.lab_dir(lab.name) / nid / "system.qcow2"
        try:
            st = f.stat()
        except OSError:
            continue
        out[nid] = f"{st.st_ino}:{st.st_dev}"
    return out


def rebuilt(old: dict[str, str], new: dict[str, str]) -> list[str]:
    return sorted(n for n, m in new.items() if n in old and old[n] != m)


# ------------------------------------------------------------------ the week's plan
def _done_lessons() -> dict[str, dict]:
    from . import progress
    return progress.load()["lessons"]


def lesson_pool(lab) -> tuple[list, list]:
    """This lab's lessons in course order: (projects, problems)."""
    from . import lessons
    mods = {m: i for i, m in enumerate(("start", "identity", "network", "workloads", "endpoint", "operations",
                                        "security", "cloud", "troubleshoot", "capstone"))}
    ls = sorted((l for l in lessons.list_available() if l.lab == lab.name and not l.browser),
                key=lambda l: (mods.get(l.module, 99), l.order, l.id))
    return [l for l in ls if l.module != "troubleshoot"], [l for l in ls if l.module == "troubleshoot" and l.problem]


def plan_week(lab, week: int, first_day: int, rng: random.Random, done: dict[str, dict] | None = None,
              taken: set[str] | None = None) -> dict:
    """The week's work: the next projects in course order the student has
    not done, one problem to work, and two maintenance items with a date."""
    done = _done_lessons() if done is None else done
    taken = taken or set()
    projects, problems = lesson_pool(lab)
    todo = [l for l in projects if (done.get(l.id) or {}).get("status") != "done" and l.id not in taken]
    items = []
    for k, l in enumerate(todo[:PROJECTS_A_WEEK]):
        items.append({"id": f"w{week}-p{k + 1}", "kind": "lesson", "ref": l.id, "title": l.title,
                      "due": first_day + (2 if k == 0 else 4), "done": False, "done_day": 0})
    open_problems = [l for l in problems if (done.get(l.id) or {}).get("status") != "done" and l.id not in taken]
    if open_problems:
        l = rng.choice(open_problems[:6])
        items.append({"id": f"w{week}-t1", "kind": "lesson", "ref": l.id, "title": f"Problem: {l.title}",
                      "due": first_day + 3, "done": False, "done_day": 0})
    for k, (mid, text) in enumerate(rng.sample(MAINTENANCE, 2)):
        items.append({"id": f"w{week}-m{k + 1}", "kind": "check", "ref": mid, "title": text,
                      "due": first_day + 4, "done": False, "done_day": 0})
    return {"week": week, "first_day": first_day, "items": items}


def check_item(item: dict, lab, report: dict | None, now: float, done: dict[str, dict]) -> bool | None:
    """Whether a plan item is done: a lesson by the student's progress, a
    check from this morning's reading of the machines and the queue."""
    if item["kind"] == "lesson":
        return (done.get(item["ref"]) or {}).get("status") == "done"
    ref = item["ref"]
    if ref == "backlog":
        from . import helpdesk
        old = [t for t in helpdesk.open_tickets(lab.name) if now - float(t["opened"]) > 3 * 86400]
        return not old
    if not report:
        return None
    if ref == "disk20":
        vols = [v for d in report["disks"] for v in d["vols"]]
        return bool(vols) and all(v["pct"] >= 20 for v in vols)
    if ref == "licence30":
        lic = report["licences"]
        return bool(lic) and all(not x["evaluation"] or x["days"] >= 30 for x in lic)
    if ref == "backups":
        b = [x for x in report["backups"] if x["ok"] is not None]
        return bool(b) and all(x["ok"] for x in b)
    return None


def update_plan(run: dict, lab, report: dict | None, now: float, done: dict[str, dict] | None = None) -> list[dict]:
    """Ticks off what is done; returns the items done just now."""
    done = _done_lessons() if done is None else done
    out = []
    for it in (run.get("plan") or {}).get("items", []):
        if it["done"]:
            continue
        if check_item(it, lab, report, now, done):
            it["done"], it["done_day"] = True, run["day"]
            out.append(it)
    return out


# ------------------------------------------------------------------ the journal
def uptime(lab, alerts_list: list[dict], t0: float, t1: float) -> dict:
    """Service uptime over [t0, t1]: each server's time with no P1/P2 outage
    alert (a machine down, a role's service stopped) open. A night of a
    stopped DNS counts."""
    from . import alerts
    span = max(1.0, t1 - t0)
    servers = [n for n in lab.node_list() if alerts._server(n)]
    per = {}
    for n in servers:
        spans = sorted((max(t0, float(a["opened"])), min(t1, float(a.get("cleared") or t1)))
                       for a in alerts_list if a["node"] == n.id and a["severity"] in ("P1", "P2")
                       and a["source"] in OUTAGE_SOURCES and float(a["opened"]) < t1
                       and (not a.get("cleared") or float(a["cleared"]) > t0))
        down, end = 0.0, t0
        for a, b in spans:
            a = max(a, end)
            if b > a:
                down += b - a
                end = b
        per[n.id] = round(100 * (1 - down / span), 2)
    overall = round(sum(per.values()) / len(per), 2) if per else 100.0
    return {"overall": overall, "servers": per}


def day_entry(lab, run: dict, t0: float, t1: float) -> dict:
    """One day in the journal."""
    from . import alerts, helpdesk, shift, wear
    q = helpdesk.load(lab.name)
    rep = helpdesk.report(q, t1, since=t0)
    data = alerts.load(lab.name)
    incidents = [a for a in data["alerts"] if t0 <= float(a["opened"]) < t1 and a["severity"] in ("P1", "P2")]
    ws = wear.load(lab.name)
    worn = wear.since(ws, t0, t1)
    fixed = [e for e in ws["events"] if e.get("fixed") and t0 <= float(e["fixed"]) < t1 and e["state"] == "fixed"]
    today = shift.day_key(float(run.get("day_start") or t0))
    sh = shift.result(shift.load(lab.name)["days"].get(today))
    plan_done = [it["id"] for it in (run.get("plan") or {}).get("items", []) if it.get("done_day") == run["day"]]
    return {"day": run["day"], "week": week_of(run["day"]), "date": today, "from": t0, "to": t1,
            "tickets_in": rep["tickets"], "resolved": rep["handled"], "sla_met_pct": rep["sla_met_pct"],
            "breaches": rep["breaches"], "first_fix_pct": rep["first_fix_pct"],
            "incidents": [{"severity": a["severity"], "title": a["title"], "node": a["node"]} for a in incidents],
            "wear": len(worn), "wear_fixed": len(fixed), "uptime": uptime(lab, data["alerts"], t0, t1),
            "shift": sh, "plan_done": plan_done, "rebuilt": []}


def totals(run: dict) -> dict:
    j = run.get("journal") or []
    handled = sum(d["resolved"] for d in j)
    met = sum(round(d["resolved"] * d["sla_met_pct"] / 100) for d in j)
    weeks = list(run.get("weeks_done", []))
    if run.get("plan") and run["plan"]["week"] not in {w["week"] for w in weeks}:
        weeks.append(run["plan"])
    plan = [it for w in weeks for it in w.get("items", [])]
    return {"days": len(j), "tickets": sum(d["tickets_in"] for d in j), "resolved": handled,
            "sla_met_pct": round(100 * met / handled) if handled else 0,
            "incidents": sum(len(d["incidents"]) for d in j), "wear": sum(d["wear"] for d in j),
            "uptime": round(sum(d["uptime"]["overall"] for d in j) / len(j), 2) if j else 100.0,
            "shifts": sum(1 for d in j if d["shift"]["done"]),
            "plan_done": sum(1 for it in plan if it["done"]), "plan_items": len(plan)}


# ------------------------------------------------------------------ the run
def record(run: dict) -> dict:
    """The run's totals as the student's progress keeps them (and the
    transcript shows them): one entry per run, kept up to date."""
    from . import progress
    t = totals(run)
    entry = {"lab": run["lab"], "name": run["name"], "started": run["started"], "weeks": run["weeks"],
             "level": run["level"], "days": t["days"], "tickets": t["tickets"], "resolved": t["resolved"],
             "sla_met_pct": t["sla_met_pct"], "incidents": t["incidents"], "uptime": t["uptime"],
             "wear": t["wear"], "plan_done": t["plan_done"], "plan_items": t["plan_items"],
             "finished": run.get("finished", 0.0), "updated": time.time()}
    try:
        progress.record_company(entry)
    except OSError:
        pass   # a progress file that cannot be written loses the line, not the run
    return entry


def start(lab, now: float | None = None, weeks: int = DEFAULT_WEEKS, level: str = DEFAULT_LEVEL,
          pace: str = DEFAULT_PACE, staff: bool = True, name: str = "") -> dict:
    """The company opens: wear on, the helpdesk on in business hours, the
    staff coming in, the first week planned, day one starts now."""
    from . import helpdesk, wear
    if level not in wear.LEVELS or level == "off":
        raise CompanyError(f"a company run wears its servers: level is one of {', '.join(l for l in wear.LEVELS if l != 'off')}")
    if pace not in helpdesk.PACES:
        raise CompanyError(f"pace is one of {', '.join(helpdesk.PACES)}")
    if not 1 <= int(weeks) <= 52:
        raise CompanyError("a run lasts 1 to 52 weeks")
    at = labclock.load(lab.name).now() if now is None else now
    with _lock:
        if active(load(lab.name)):
            raise CompanyError("a company run is already going on this lab: winlab company status")
        rng = random.Random(f"company:{lab.name}:{int(at)}")
        run = {"lab": lab.name, "name": name or company_name(lab), "started": at, "weeks": int(weeks),
               "level": level, "pace": pace, "staff": bool(staff), "day": 1, "day_start": at,
               "saved": False, "checkpoints": [], "disks": disk_marks(lab), "journal": [], "weeks_done": [],
               "finished": 0.0, "events": [{"at": at, "text": "The company opened."}]}
        run["plan"] = plan_week(lab, 1, 1, rng)
        save(lab.name, run)
    wear.set_level(lab.name, level, at)
    helpdesk.start(lab.name, at, pace)
    helpdesk.set_settings(lab.name, business_hours=True)
    if staff:
        try:
            from . import workday
            workday.start(lab)
        except Exception:  # noqa: BLE001 - a lab without an office still runs
            pass
    return run


def company_name(lab) -> str:
    dom = (lab.domain or lab.name).split(".")[0]
    return f"{dom.replace('-', ' ').title()} Ltd"


def _need(lab) -> dict:
    run = load(lab.name)
    if not active(run):
        raise CompanyError("no company run on this lab: winlab company start <lab>")
    return run


def next_day(lab, runner: Runner, clock_runner: Runner | None = None, now: float | None = None,
             running: list[str] | None = None, emit=lambda _l: None) -> dict:
    """Close today (its journal entry) and move to the next working morning:
    the clock moves, the night's wear happens, a new week gets its plan, and
    after the last day the run is finished."""
    from . import shift, wear
    at = labclock.load(lab.name).now() if now is None else now
    run = _need(lab)
    if run.get("saved"):
        raise CompanyError("the run is saved for the day: resume it first")
    rep = (shift.today(lab.name, at) or {}).get("report")
    update_plan(run, lab, rep, at)
    entry = day_entry(lab, run, float(run.get("last_close") or run["started"]), at)
    run["last_close"] = at
    marks = disk_marks(lab)
    entry["rebuilt"] = rebuilt(run.get("disks") or {}, marks)
    run["disks"] = {**(run.get("disks") or {}), **marks}
    run["journal"].append(entry)
    if entry["rebuilt"]:
        run["events"].append({"at": at, "text": f"Rebuilt from the image: {', '.join(entry['rebuilt'])}: "
                                                "what was built on them is gone."})
    total_days = int(run["weeks"]) * WEEK_DAYS
    if run["day"] >= total_days:
        run["weeks_done"].append(run["plan"])
        run["finished"] = at
        run["events"].append({"at": at, "text": "The run is over."})
        save(lab.name, run)
        record(run)
        return run
    to = next_morning(at)
    emit(f"day {run['day']} closed: moving the lab clock to {labclock.stamp(to)}")
    labclock.change(lab, "set", labclock.stamp(to), runner=clock_runner, emit=emit)
    run["day"] += 1
    run["day_start"] = to
    if week_of(run["day"]) != run["plan"]["week"]:
        run["weeks_done"].append(run["plan"])
        taken = {it["ref"] for w in run["weeks_done"] for it in w["items"] if it["kind"] == "lesson"}
        rng = random.Random(f"company:{lab.name}:week{week_of(run['day'])}")
        run["plan"] = plan_week(lab, week_of(run["day"]), run["day"], rng, taken=taken)
    save(lab.name, run)
    record(run)
    r = wear.tick(lab, runner, now=to, running=running)
    for e in r["fired"]:
        emit(f"overnight: {wear.describe(lab, e)}")
    return run


def check_plan(lab, now: float | None = None) -> list[dict]:
    """Tick off plan work now, from today's shift report and progress."""
    from . import shift
    at = labclock.load(lab.name).now() if now is None else now
    with _lock:
        run = _need(lab)
        got = update_plan(run, lab, (shift.today(lab.name, at) or {}).get("report"), at)
        save(lab.name, run)
    return got


def save_day(lab, checkpoint: bool = False, now: float | None = None, clock: bool = True) -> dict:
    """Stop for the day: the clock pauses, the helpdesk stops taking calls
    (what is broken stays broken), and with `checkpoint` the disks are kept."""
    from . import helpdesk
    at = labclock.load(lab.name).now() if now is None else now
    run = _need(lab)
    if checkpoint:
        from . import snapshots
        tag = f"company-day{run['day']}"
        snapshots.save(lab.name, tag)
        labclock.note_checkpoint(lab.name, tag)
        run["checkpoints"].append({"tag": tag, "day": run["day"], "at": at})
    with helpdesk._lock:
        q = helpdesk.load(lab.name)
        s = helpdesk.settings(q)
        s["on"] = False
        q["settings"] = s
        helpdesk.save(lab.name, q)
    if clock and not labclock.load(lab.name).paused:
        labclock.change(lab, "pause")
    run["saved"] = True
    run["events"].append({"at": at, "text": f"Saved on day {run['day']}" + (" with a checkpoint" if checkpoint else "")})
    save(lab.name, run)
    return run


def resume(lab, now: float | None = None, clock: bool = True) -> dict:
    """Back to work where the run stopped."""
    from . import helpdesk
    run = _need(lab)
    if clock and labclock.load(lab.name).paused:
        labclock.change(lab, "resume")
    at = labclock.load(lab.name).now() if now is None else now
    helpdesk.start(lab.name, at, run.get("pace", DEFAULT_PACE))
    run["saved"] = False
    run["events"].append({"at": at, "text": f"Resumed on day {run['day']}"})
    save(lab.name, run)
    return run


def stop(lab, runner: Runner, now: float | None = None) -> dict:
    """End the run early: wear off, the queue closed, the record kept."""
    from . import helpdesk, wear
    at = labclock.load(lab.name).now() if now is None else now
    run = _need(lab)
    run["journal"].append(day_entry(lab, run, float(run.get("last_close") or run["started"]), at))
    run["weeks_done"].append(run["plan"])
    run["finished"] = at
    run["events"].append({"at": at, "text": "The run was ended."})
    save(lab.name, run)
    record(run)
    wear.set_level(lab.name, "off", at)
    helpdesk.stop(lab, runner, at)
    return run


# ------------------------------------------------------------------ the view
def view(lab, now: float | None = None) -> dict:
    from . import shift, wear
    at = labclock.load(lab.name).now() if now is None else now
    run = load(lab.name)
    ws = wear.load(lab.name)
    out = {"lab": lab.name, "now": at, "stamp": labclock.stamp(at), "active": active(run),
           "wear": {"level": ws["level"], "open": len(wear.open_events(ws)),
                    "levels": {k: v[2] for k, v in wear.LEVELS.items()}},
           "shift_due": shift.due(lab.name, at), "paused": labclock.load(lab.name).paused}
    if not run:
        return {**out, "run": None}
    days = int(run["weeks"]) * WEEK_DAYS
    out["run"] = {"name": run["name"], "day": run["day"], "days": days, "week": week_of(run["day"]),
                  "weeks": run["weeks"], "level": run["level"], "pace": run["pace"], "saved": run.get("saved", False),
                  "finished": run.get("finished", 0.0), "started": run["started"], "day_start": run["day_start"],
                  "plan": run.get("plan"), "journal": list(reversed(run.get("journal") or []))[:40],
                  "events": list(reversed(run.get("events") or []))[:20], "totals": totals(run),
                  "checkpoints": run.get("checkpoints", []),
                  "next_morning": next_morning(at) if active(run) else None}
    return out


def render(v: dict) -> str:
    r = v["run"]
    if not r:
        return (f"no company run on {v['lab']} (wear {v['wear']['level']}): "
                f"winlab company start {v['lab']} [--weeks 4] [--wear realistic]")
    t = r["totals"]
    lines = [f"{r['name']} on {v['lab']}: day {r['day']} of {r['days']} (week {r['week']} of {r['weeks']})"
             + (", finished" if r["finished"] else ", saved for the day" if r["saved"] else ""),
             f"lab time {v['stamp']}; wear {r['level']}, helpdesk {r['pace']}",
             f"so far: {t['tickets']} tickets, {t['resolved']} resolved, SLA met {t['sla_met_pct']}%, "
             f"{t['incidents']} incidents, {t['wear']} things wore out, uptime {t['uptime']}%, "
             f"{t['shifts']} morning shifts, plan {t['plan_done']} of {t['plan_items']}", ""]
    if r["plan"]:
        lines.append(f"Week {r['plan']['week']} plan")
        for it in r["plan"]["items"]:
            lines.append(f"  [{'x' if it['done'] else ' '}] day {it['due']:<3} {it['title']}"
                         + (f"  ({it['ref']})" if it["kind"] == "lesson" else ""))
    if r["journal"]:
        lines.append("")
        lines.append("Journal")
        for d in r["journal"][:10]:
            lines.append(f"  day {d['day']:<3} {d['date']}  tickets {d['tickets_in']} in, {d['resolved']} resolved, "
                         f"SLA {d['sla_met_pct']}%, incidents {len(d['incidents'])}, wear {d['wear']}, "
                         f"uptime {d['uptime']['overall']}%, shift {d['shift']['passed']}/{d['shift']['graded']}"
                         + (f", REBUILT {', '.join(d['rebuilt'])}" if d["rebuilt"] else ""))
    return "\n".join(lines)


# ------------------------------------------------------------------ the desktop
def view_all(dash) -> dict:
    """GET /api/ops: the company, today's shift and wear, in one poll; wear
    moves on in a thread."""
    from . import shift, wear
    wear.background(dash)
    lab = dash.lab
    st = dash.__dict__.get("wear_state") or {}
    return {"company": view(lab), "shift": shift.view(lab), "wear": wear.view(lab),
            "wear_busy": bool(st.get("busy")), "wear_error": st.get("error", "")}


def act(dash, action: str, params: dict) -> dict:
    """The desktop's ops-* actions: the company run, the shift, wear."""
    from . import oncall, shift, wear
    lab = dash.lab
    op = action.removeprefix("ops-")
    try:
        if op == "wear-level":
            wear.set_level(lab.name, str(params.get("level", "")))
            return {"ok": True, "message": f"wear is {params.get('level')}"}
        if op == "shift-fill":
            shift.fill(lab.name, str(params.get("section", "")), str(params.get("key", "")), str(params.get("value", "")))
            return {"ok": True, "message": "written", "silent": True}
        if op == "shift-tick":
            shift.tick(lab.name, str(params.get("item", "")), bool(params.get("done", True)))
            return {"ok": True, "message": "ticked", "silent": True}
        if op == "company-start":
            r = start(lab, weeks=int(params.get("weeks") or DEFAULT_WEEKS),
                      level=str(params.get("level") or DEFAULT_LEVEL), pace=str(params.get("pace") or DEFAULT_PACE),
                      staff=bool(params.get("staff", True)))
            return {"ok": True, "message": f"{r['name']} is open: day 1 of {r['weeks'] * WEEK_DAYS}"}
        if op == "company-save":
            r = save_day(lab, checkpoint=bool(params.get("checkpoint")))
            return {"ok": True, "message": f"saved on day {r['day']}: the clock is paused"}
        if op == "company-resume":
            r = resume(lab)
            return {"ok": True, "message": f"back at work: day {r['day']}"}
        if op == "company-plan":
            got = check_plan(lab)
            return {"ok": True, "message": f"{len(got)} plan item{'s' if len(got) != 1 else ''} done" if got
                    else "nothing new done on the plan"}
        if op in ("shift-start", "shift-check", "company-next", "company-stop", "wear-tick"):
            def job(emit):
                run = oncall.guest_runner(lab.name)
                if op == "shift-start":
                    emit("reading the machines for the morning report")
                    r = shift.start(lab, run)
                    emit(f"report ready: {len(r['alerts'])} alerts overnight, {len(r['tickets'])} tickets open")
                elif op == "shift-check":
                    emit("checking the checklist on the machines")
                    shift.check(lab, run)
                    v = shift.view(lab)
                    emit(f"{v['passed']} of {v['graded']} hold")
                elif op == "company-next":
                    r = next_day(lab, run, emit=emit)
                    emit("the run is over" if r.get("finished") else f"day {r['day']} starts")
                elif op == "company-stop":
                    stop(lab, run)
                    emit("the run is ended; the record is kept")
                else:
                    r = wear.tick(lab, run, force=bool(params.get("force")))
                    emit(f"{len(r['fired'])} worn out, {len(r['fixed'])} fixed")
            jid = dash.jobs.start(f"ops-{op}", job)
            return {"ok": True, "job": jid, "message": "working…"}
    except (CompanyError, ValueError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown action {action}"}


# ------------------------------------------------------------------ the command line
def add_cli(sub) -> None:
    cp = sub.add_parser("company", help="a company run: one lab for weeks of lab time, day by day")
    cs = cp.add_subparsers(dest="compcmd", metavar="<op>")
    st = cs.add_parser("start", help="open the company: wear on, the helpdesk in business hours, week one planned")
    st.add_argument("lab", nargs="?", default="")
    st.add_argument("--weeks", type=int, default=DEFAULT_WEEKS)
    st.add_argument("--wear", default=DEFAULT_LEVEL, choices=["gentle", "realistic", "harsh"])
    st.add_argument("--pace", default=DEFAULT_PACE, choices=["quiet", "normal", "busy"])
    st.add_argument("--no-staff", action="store_true", help="leave the office's staff out")
    for name, what in (("status", "the day, the week's plan, the journal"),
                       ("next", "close today and move to the next working morning"),
                       ("plan", "tick off plan work that is done"),
                       ("resume", "back to work after a save"),
                       ("stop", "end the run early; the record is kept")):
        cs.add_parser(name, help=what).add_argument("lab", nargs="?", default="")
    sv = cs.add_parser("save", help="stop for the day: the clock pauses, calls stop; --checkpoint keeps the disks")
    sv.add_argument("lab", nargs="?", default="")
    sv.add_argument("--checkpoint", action="store_true")


def run_cli(args) -> int:
    import sys

    from . import oncall, schema
    from .cli import _resolve_lab
    try:
        lab = schema.load(_resolve_lab(getattr(args, "lab", "")))
    except Exception as exc:  # noqa: BLE001 - the CLI reports it
        print(f"{exc}", file=sys.stderr)
        return 2
    op = args.compcmd or "status"
    try:
        if op == "start":
            r = start(lab, weeks=args.weeks, level=args.wear, pace=args.pace, staff=not args.no_staff)
            print(f"{r['name']} is open on {lab.name}: {r['weeks']} weeks, wear {r['level']}, helpdesk {r['pace']}")
        elif op == "next":
            next_day(lab, oncall.guest_runner(lab.name), emit=print)
        elif op == "plan":
            for it in check_plan(lab):
                print(f"done: {it['title']}")
        elif op == "save":
            save_day(lab, checkpoint=args.checkpoint)
        elif op == "resume":
            resume(lab)
        elif op == "stop":
            stop(lab, oncall.guest_runner(lab.name))
    except CompanyError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print(render(view(lab)))
    return 0
