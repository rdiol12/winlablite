"""The Progress window's facts: one read of var/progress.json turned into
what a student wants to see at a glance. Totals, a day-by-day activity
calendar and streak, every track with its next lesson and certificate,
exam readiness, recent work and the lessons worth another look. Nothing
here is stored: it is all worked out from the progress file each time.
"""

from __future__ import annotations

import time

from . import lessons as lmod, progress, tracks

WEEKS = 26


def _day(t: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(t))


def activity(data: dict, titles: dict, now: float | None = None) -> tuple[list[dict], dict]:
    """Every dated thing the student did, newest first, and a count per day."""
    events: list[dict] = []
    days: dict[str, int] = {}

    def add(t: float, kind: str, text: str, ref: str = "", weight: int = 1) -> None:
        if not t:
            return
        events.append({"t": t, "kind": kind, "text": text, "ref": ref})
        d = _day(t)
        days[d] = days.get(d, 0) + weight

    for lid, e in data["lessons"].items():
        title = titles.get(lid, lid)
        passed = float(e.get("passed_at") or 0)
        if e.get("status") == progress.STATUS_DONE and passed:
            add(passed, "passed", title, lid)
        upd = float(e.get("updated") or 0)
        # work on a lesson on another day (a failed check, a quiz, a step)
        if upd and (not passed or _day(upd) != _day(passed)):
            d = _day(upd)
            days[d] = days.get(d, 0) + 1
    for sid, e in data["problems"].items():
        if int(e.get("solved") or 0) > 0:
            from . import guestfaults
            f = guestfaults.SCENARIOS.get(sid)
            add(float(e.get("solved_at") or 0), "fixed", f.title if f else titles.get(sid, sid), sid)
    for s in data.get("shifts", []):
        add(float(s.get("started") or 0), "shift",
            f"On-call shift: {int(s.get('fixed') or 0)} of {int(s.get('tickets') or 0)} tickets fixed")
    for h in data.get("helpdesk", []):
        add(float(h.get("ended") or h.get("started") or 0), "helpdesk",
            f"Helpdesk queue: {int(h.get('handled') or 0)} of {int(h.get('tickets') or 0)} tickets handled")
    for c in data.get("companies", []):
        if int(c.get("days") or 0) > 0:
            add(float(c.get("started") or 0), "company",
                f"Company run {c.get('name') or c.get('lab') or ''}: {int(c.get('days') or 0)} days")
    for tid, c in (data.get("certificates") or {}).items():
        add(float(c.get("issued") or 0), "certificate", f"Certificate: {c.get('title') or tid}", tid, 0)
    events.sort(key=lambda e: e["t"], reverse=True)
    return events, days


def streaks(days: dict, now: float | None = None) -> tuple[int, int]:
    """(current, longest) run of days with work in them. Today without work
    yet does not break the current run."""
    if not days:
        return 0, 0
    now = now or time.time()
    have = set(days)
    longest = run = 0
    prev = None
    for d in sorted(have):
        t = time.mktime(time.strptime(d, "%Y-%m-%d"))
        run = run + 1 if prev is not None and round((t - prev) / 86400) == 1 else 1
        longest = max(longest, run)
        prev = t
    cur = 0
    t = now if _day(now) in have else now - 86400
    while _day(t) in have:
        cur += 1
        t -= 86400
    return cur, longest


def calendar(days: dict, now: float | None = None, weeks: int = WEEKS) -> list[list[dict]]:
    """Weeks (Monday first) of {date, n} cells, the last week holding today;
    days after today are left out."""
    now = now or time.time()
    lt = time.localtime(now)
    today = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 12, 0, 0, 0, 0, -1))
    start = today - (lt.tm_wday + 7 * (weeks - 1)) * 86400
    out = []
    for w in range(weeks):
        col = []
        for d in range(7):
            t = start + (w * 7 + d) * 86400
            if t > today + 3600:
                break
            key = _day(t)
            col.append({"date": key, "n": days.get(key, 0)})
        out.append(col)
    return out


def collect(data: dict | None = None, now: float | None = None) -> dict:
    from . import exams
    data = data or progress.load()
    now = now or time.time()
    all_lessons = lmod.list_available()
    titles = {l.id: l.title for l in all_lessons}
    by_id = {l.id: l for l in all_lessons}
    s = progress.summary(all_lessons, data)
    graded = sum(1 for l in all_lessons if l.check_kind == "exercise"
                 and (data["lessons"].get(l.id) or {}).get("status") == progress.STATUS_DONE)
    minutes = sum(l.minutes for l in all_lessons
                  if (data["lessons"].get(l.id) or {}).get("status") == progress.STATUS_DONE)
    quiz_r = sum(int(e.get("quiz_best") or 0) for e in data["lessons"].values() if e.get("quiz_total"))
    quiz_t = sum(int(e.get("quiz_total") or 0) for e in data["lessons"].values() if e.get("quiz_total"))
    events, days = activity(data, titles, now)
    cur, longest = streaks(days, now)
    week_ago = now - 7 * 86400
    trk = tracks.all_status(data)
    # worth another look: checks failed more than once and not passed yet,
    # and recall quizzes under half right
    review = []
    for lid, e in data["lessons"].items():
        l = by_id.get(lid)
        if not l:
            continue
        why = ""
        if e.get("status") != progress.STATUS_DONE and int(e.get("failed") or 0) >= 2:
            why = f"Check my work failed {int(e['failed'])} times"
        elif e.get("quiz_total") and int(e.get("quiz_best") or 0) * 2 < int(e["quiz_total"]):
            why = f"recall quiz {int(e.get('quiz_best') or 0)} of {int(e['quiz_total'])}"
        if why:
            review.append({"id": lid, "title": l.title, "why": why, "t": float(e.get("updated") or 0)})
    review.sort(key=lambda r: r["t"], reverse=True)
    readiness = []
    for ex in exams.list_available():
        r = exams.readiness(ex, data, titles)
        readiness.append({"id": r["id"], "title": r["title"], "overall": r["overall"], "ready": r["ready"]})
    return {
        "student": str(data.get("student") or ""),
        "summary": {**s, "graded": graded, "hours": round(minutes / 60, 1),
                    "this_week": sum(1 for e in events if e["t"] >= week_ago and e["kind"] in ("passed", "fixed")),
                    "streak": cur, "longest": longest, "active_days": len(days),
                    "quiz_percent": round(100 * quiz_r / quiz_t) if quiz_t else None,
                    "certificates": sum(1 for t in trk if t["certificate"].get("code"))},
        "tracks": trk,
        "calendar": calendar(days, now),
        "recent": [{**e, "date": time.strftime("%d %b %Y", time.localtime(e["t"]))} for e in events[:12]],
        "review": review[:8],
        "exams": readiness,
    }
