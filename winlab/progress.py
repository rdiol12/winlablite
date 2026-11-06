"""What the student has done: one JSON file under var/, no account, no cloud.

A lesson is done when its graded exercise passed, or, for a lesson that has
no exercise, when every step is ticked. A problem (guest fault) records how
often it was solved and how many hints that took. A company run (weeks of
one lab as a job, winlab/company.py) keeps its totals here as it goes: days
run, tickets, the SLA met, incidents. Nothing here leaves the
machine: the file is the student's own record, and `winlab progress reset`
starts over.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import paths

VERSION = 1

STATUS_NEW = "new"
STATUS_STARTED = "started"
STATUS_DONE = "done"


def progress_file() -> Path:
    return paths.VAR / "progress.json"


def _empty() -> dict:
    return {"version": VERSION, "lessons": {}, "problems": {}, "shifts": [], "updated": 0.0}


def load() -> dict:
    f = progress_file()
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty()
    if not isinstance(raw, dict):
        return _empty()
    out = _empty()
    out["lessons"] = {k: v for k, v in (raw.get("lessons") or {}).items() if isinstance(v, dict)}
    out["problems"] = {k: v for k, v in (raw.get("problems") or {}).items() if isinstance(v, dict)}
    if isinstance(raw.get("student"), str):
        out["student"] = raw["student"]
    out["shifts"] = [x for x in (raw.get("shifts") or []) if isinstance(x, dict)]
    if isinstance(raw.get("helpdesk"), list):
        out["helpdesk"] = [x for x in raw["helpdesk"] if isinstance(x, dict)]
    if isinstance(raw.get("companies"), list):
        out["companies"] = [x for x in raw["companies"] if isinstance(x, dict)]
    out["updated"] = float(raw.get("updated") or 0.0)
    return out


def save(data: dict) -> Path:
    f = progress_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    data["updated"] = time.time()
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(f)
    return f


def lesson_entry(data: dict, lesson_id: str) -> dict:
    e = data["lessons"].setdefault(lesson_id, {})
    e.setdefault("status", STATUS_NEW)
    e.setdefault("steps", [])
    e.setdefault("best", 0)
    e.setdefault("last", 0)
    e.setdefault("attempts", 0)
    e.setdefault("updated", 0.0)
    e.setdefault("passed_at", 0.0)
    return e


def set_step(lesson_id: str, index: int, done: bool, total_steps: int = 0) -> dict:
    """Ticks or unticks one hands-on step. With total_steps, ticking the last
    open step completes a lesson that has no graded exercise."""
    data = load()
    e = lesson_entry(data, lesson_id)
    steps = set(int(i) for i in e["steps"])
    if done:
        steps.add(int(index))
    else:
        steps.discard(int(index))
    e["steps"] = sorted(steps)
    if e["status"] != STATUS_DONE:
        e["status"] = STATUS_STARTED if steps else STATUS_NEW
    if total_steps and len(steps) >= total_steps and e["status"] != STATUS_DONE:
        e["status"] = STATUS_DONE
        e["passed_at"] = time.time()
    e["updated"] = time.time()
    save(data)
    return e


def record_grade(lesson_id: str, percent: int, passed: bool) -> dict:
    data = load()
    e = lesson_entry(data, lesson_id)
    e["attempts"] = int(e["attempts"]) + 1
    e["last"] = int(percent)
    e["best"] = max(int(e["best"]), int(percent))
    if passed:
        e["status"] = STATUS_DONE
        e["passed_at"] = time.time()
    else:
        e["failed"] = int(e.get("failed") or 0) + 1
        if e["status"] != STATUS_DONE:
            e["status"] = STATUS_STARTED
    e["updated"] = time.time()
    save(data)
    return e


# A failed check shows its hint only after this many failed gradings of the
# lesson (or exercise): the first tries are the student's own.
CHECK_HINT_AFTER = 2


def check_hints_open(lesson_id: str) -> bool:
    e = load()["lessons"].get(lesson_id) or {}
    return e.get("status") == STATUS_DONE or int(e.get("failed") or 0) >= CHECK_HINT_AFTER


def record_quiz(lesson_id: str, right: int, total: int) -> dict:
    """The lesson's recall questions: last and best score. A quiz never
    completes or blocks a lesson; it shows what stuck."""
    data = load()
    e = lesson_entry(data, lesson_id)
    e["quiz_total"] = int(total)
    e["quiz_last"] = int(right)
    e["quiz_best"] = max(int(e.get("quiz_best") or 0), int(right))
    e["quiz_tries"] = int(e.get("quiz_tries") or 0) + 1
    if e["status"] == STATUS_NEW:
        e["status"] = STATUS_STARTED
    e["updated"] = time.time()
    save(data)
    return e


def mark(lesson_id: str, status: str) -> dict:
    if status not in (STATUS_NEW, STATUS_STARTED, STATUS_DONE):
        raise ValueError(status)
    data = load()
    e = lesson_entry(data, lesson_id)
    e["status"] = status
    if status == STATUS_NEW:
        e["steps"] = []
    if status == STATUS_DONE and not e["passed_at"]:
        e["passed_at"] = time.time()
    e["updated"] = time.time()
    save(data)
    return e


def record_problem(scenario_id: str, node: str, solved: bool, hints_used: int = 0) -> dict:
    data = load()
    e = data["problems"].setdefault(scenario_id, {})
    e.setdefault("solved", 0)
    e.setdefault("attempts", 0)
    e.setdefault("hints", 0)
    e["attempts"] = int(e["attempts"]) + 1
    if solved:
        e["solved"] = int(e["solved"]) + 1
        e["last_node"] = node
        e["solved_at"] = time.time()
    e["hints"] = max(int(e["hints"]), int(hints_used))
    e["updated"] = time.time()
    save(data)
    return e


def hint_used(scenario_id: str, n: int) -> dict:
    data = load()
    e = data["problems"].setdefault(scenario_id, {})
    e["hints_open"] = max(int(e.get("hints_open") or 0), int(n))
    e["updated"] = time.time()
    save(data)
    return e


def problem_broken(scenario_id: str, node: str, broken: bool) -> dict:
    """A problem was broken on a machine (or put back). The tries counted
    since the break open the hint ladder, one hint per failed verify, and a
    verify only counts as solved while the break is in place."""
    data = load()
    e = data["problems"].setdefault(scenario_id, {})
    if broken:
        e["broken_on"] = node
        e["broken_at"] = time.time()
        e["tries"] = 0
    else:
        e.pop("broken_on", None)
    e["updated"] = time.time()
    save(data)
    return e


def problem_try(scenario_id: str) -> dict:
    """One failed verify (or failed grading) since the break."""
    data = load()
    e = data["problems"].setdefault(scenario_id, {})
    e["tries"] = int(e.get("tries") or 0) + 1
    e["updated"] = time.time()
    save(data)
    return e


def next_hint(scenario_id: str, total: int, min_tries: bool = True) -> tuple[int, str]:
    """The number of the next hint the ladder may open, or 0 and why not:
    hints open in order, each after one more failed try than the last."""
    e = load()["problems"].get(scenario_id) or {}
    n = int(e.get("hints_open") or 0) + 1
    if n > total:
        return 0, "every hint is already open"
    if min_tries and int(e.get("tries") or 0) < n:
        return 0, ("try it first: press Verify (or Check my work) once more, then the next hint opens"
                   if n > 1 else "try it first: diagnose, then press Verify (or Check my work); "
                   "the first hint opens after one try")
    return n, ""


def lesson_fault(lesson_id: str, broken: bool) -> dict:
    """A network-fault lesson's break (True) or its Restore (False). Restore
    before the lesson is passed gives it up: the try scores 0 and Check my work
    refuses until the network is broken again."""
    data = load()
    e = lesson_entry(data, lesson_id)
    if broken:
        e["fault_broken"] = time.time()
        e["fault_restored"] = False
    else:
        e["fault_restored"] = True
        if e["status"] != STATUS_DONE:
            e["attempts"] = int(e["attempts"]) + 1
            e["last"] = 0
            e["gave_up"] = int(e.get("gave_up") or 0) + 1
            e["status"] = STATUS_STARTED
    e["updated"] = time.time()
    save(data)
    return e


def answer_viewed(lesson_id: str) -> dict:
    """The worked answer was opened: kept on the record and the transcript."""
    data = load()
    e = lesson_entry(data, lesson_id)
    e["answer_viewed"] = e.get("answer_viewed") or time.time()
    e["updated"] = time.time()
    save(data)
    return e


def record_shift(result: dict) -> dict:
    """Keeps an on-call shift's result (winlab/oncall.py): the newest 50."""
    data = load()
    data["shifts"] = (data["shifts"] + [dict(result)])[-50:]
    save(data)
    return result


def record_helpdesk(result: dict) -> dict:
    """Keeps a helpdesk queue session's report (winlab/helpdesk.py): the newest 50."""
    data = load()
    data["helpdesk"] = (data.get("helpdesk", []) + [dict(result)])[-50:]
    save(data)
    return result


def record_company(result: dict) -> dict:
    """Keeps a company run's totals (winlab/company.py), one entry per run
    (its lab and start), brought up to date each day: the newest 50."""
    data = load()
    key = (str(result.get("lab", "")), float(result.get("started") or 0))
    runs = [r for r in data.get("companies", [])
            if (str(r.get("lab", "")), float(r.get("started") or 0)) != key]
    data["companies"] = (runs + [dict(result)])[-50:]
    save(data)
    return result


def student() -> str:
    return str(load().get("student") or "")


def set_student(name: str) -> None:
    data = load()
    data["student"] = name.strip()[:80]
    save(data)


def reset(lesson_id: str = "") -> None:
    if not lesson_id:
        save(_empty())
        return
    data = load()
    data["lessons"].pop(lesson_id, None)
    data["problems"].pop(lesson_id, None)
    save(data)


def summary(lessons: list, data: dict | None = None) -> dict:
    """Totals plus the next lesson to take: the first, in path order, that is
    not done. `lessons` is the ordered list from lessons.list_available()."""
    data = data or load()
    done = started = 0
    nxt = None
    for lesson in lessons:
        e = data["lessons"].get(lesson.id) or {}
        st = e.get("status", STATUS_NEW)
        if st == STATUS_DONE:
            done += 1
        elif st == STATUS_STARTED:
            started += 1
        if nxt is None and st != STATUS_DONE:
            nxt = lesson
    total = len(lessons)
    solved = sum(1 for p in data["problems"].values() if int(p.get("solved") or 0) > 0)
    return {
        "total": total, "done": done, "started": started,
        "percent": round(100 * done / total) if total else 0,
        "next": nxt.id if nxt else "", "next_title": nxt.title if nxt else "",
        "problems_solved": solved,
    }


def render(lessons: list) -> str:
    data = load()
    s = summary(lessons, data)
    lines = [f"progress: {s['done']}/{s['total']} lessons done ({s['percent']}%), "
             f"{s['started']} started, {s['problems_solved']} problems solved"]
    if s["next"]:
        lines.append(f"next: {s['next']}  {s['next_title']}")
    lines.append("")
    for lesson in lessons:
        e = data["lessons"].get(lesson.id) or {}
        st = e.get("status", STATUS_NEW)
        mark_ = {"done": "[x]", "started": "[~]"}.get(st, "[ ]")
        score = f"  best {e['best']}%" if e.get("attempts") else ""
        lines.append(f"  {mark_} {lesson.id:<32} {lesson.title}{score}")
    return "\n".join(lines)
