"""Spaced review: the recall questions of finished lessons come back.

A lesson's quiz is answered once, right after the lesson; without a second
look most of it is gone a month later. Review brings every question of every
finished lesson back on a widening schedule (Leitner boxes):

- a question enters review the day after its lesson was finished (box 0);
- a right answer moves it up one box, and it comes back after that box's
  interval: 1, 3, 7, 14, 30, then every 60 days;
- a wrong answer puts it back in box 0, due tomorrow;
- a skipped question keeps its place and stays due.

The daily set is the questions due today, the longest-waiting first, at most
DAILY of them a day (answered ones count toward it), so finishing twenty
lessons in a week does not bury the student in a hundred questions.

Days are the real calendar date on this PC (not the lab clock). The state is
var/review.json, next to var/progress.json; it travels in the .wlprogress
file (winlab/progressfile.py) and merges by the newer answer per question.

    winlab learn review            today's set, one question at a time
    winlab learn review --status   how many are due, per box

The desktop shows the same set in the Learn window ("Review (N due)").
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import random
import time
from pathlib import Path

from . import paths

VERSION = 1
INTERVALS = (1, 3, 7, 14, 30, 60)   # days until the next review after a right answer, by box 1..6
TOP = len(INTERVALS)
DAILY = 20                          # questions in one day's review
LOG_DAYS = 120                      # days of answer counts kept


def review_file() -> Path:
    return paths.VAR / "review.json"


def today() -> _dt.date:
    return _dt.date.today()


def _day(d) -> _dt.date:
    if d is None:
        return today()
    if isinstance(d, _dt.date):
        return d
    return _dt.date.fromisoformat(str(d)[:10])


def _iso(d: _dt.date) -> str:
    return d.isoformat()


def card_key(lesson_id: str, n: int) -> str:
    return f"{lesson_id}#{int(n)}"


def split_key(key: str) -> tuple[str, int]:
    lid, _, n = str(key).rpartition("#")
    if not lid or not n.isdigit():
        raise ValueError(f"not a review question: {key!r}")
    return lid, int(n)


# ------------------------------------------------------------------ the file
def _empty() -> dict:
    return {"version": VERSION, "cards": {}, "log": {}}


def _clean_card(c) -> dict | None:
    if not isinstance(c, dict):
        return None
    try:
        due = _iso(_day(c.get("due")))
    except (TypeError, ValueError):
        return None
    out = {"box": max(0, min(TOP, int(c.get("box") or 0))), "due": due,
           "right": max(0, int(c.get("right") or 0)), "wrong": max(0, int(c.get("wrong") or 0)),
           "updated": float(c.get("updated") or 0.0)}
    if c.get("last"):
        out["last"] = str(c["last"])[:10]
    return out


def load() -> dict:
    try:
        raw = json.loads(review_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty()
    return clean(raw)


def clean(raw) -> dict:
    """A review state with only well-formed cards and day counts."""
    out = _empty()
    if not isinstance(raw, dict):
        return out
    for k, c in (raw.get("cards") or {}).items():
        try:
            split_key(k)
            cc = _clean_card(c)
        except (TypeError, ValueError):
            continue
        if cc:
            out["cards"][str(k)] = cc
    for d, row in (raw.get("log") or {}).items():
        try:
            d = _iso(_day(d))
        except (TypeError, ValueError):
            continue
        if isinstance(row, dict):
            out["log"][d] = {"answered": max(0, int(row.get("answered") or 0)),
                             "right": max(0, int(row.get("right") or 0))}
    return out


def save(data: dict) -> Path:
    f = review_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    keep = sorted(data.get("log") or {})[-LOG_DAYS:]
    data["log"] = {d: data["log"][d] for d in keep}
    tmp = f.with_name(f.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(f)
    return f


# ------------------------------------------------------------------ the schedule
def schedule(card: dict, ok: bool, day=None) -> dict:
    """The card after one answer on `day`: right moves it up a box and out
    by that box's interval; wrong puts it in box 0, due tomorrow."""
    d = _day(day)
    c = dict(card)
    if ok:
        c["box"] = min(TOP, int(c.get("box") or 0) + 1)
        c["due"] = _iso(d + _dt.timedelta(days=INTERVALS[c["box"] - 1]))
        c["right"] = int(c.get("right") or 0) + 1
    else:
        c["box"] = 0
        c["due"] = _iso(d + _dt.timedelta(days=1))
        c["wrong"] = int(c.get("wrong") or 0) + 1
    c["last"] = _iso(d)
    c["updated"] = time.time()
    return c


def new_card(passed_at: float, day=None) -> dict:
    """A question not reviewed yet: due the day after its lesson was finished."""
    if passed_at:
        due = _dt.date.fromtimestamp(float(passed_at)) + _dt.timedelta(days=1)
    else:
        due = _day(day)
    return {"box": 0, "due": _iso(due), "right": 0, "wrong": 0, "updated": 0.0}


def _done_lessons(prog: dict) -> dict[str, float]:
    from . import progress
    return {lid: float(e.get("passed_at") or 0.0) for lid, e in (prog.get("lessons") or {}).items()
            if isinstance(e, dict) and e.get("status") == progress.STATUS_DONE}


def _quiz_sizes(lesson_ids, loader=None) -> dict[str, int]:
    from . import lessons as ls
    load_one = loader or ls.load
    out = {}
    for lid in lesson_ids:
        try:
            out[lid] = len(load_one(lid).quiz)
        except Exception:   # a lesson removed or locked since: its questions leave review
            continue
    return out


def cards(state: dict | None = None, prog: dict | None = None, day=None, sizes=None) -> dict[str, dict]:
    """Every question in review: the finished lessons' questions, each with
    its stored card or a new one."""
    from . import progress
    state = state if state is not None else load()
    prog = prog if prog is not None else progress.load()
    done = _done_lessons(prog)
    sizes = sizes if sizes is not None else _quiz_sizes(sorted(done))
    out = {}
    for lid, passed in done.items():
        for n in range(int(sizes.get(lid) or 0)):
            k = card_key(lid, n)
            out[k] = state["cards"].get(k) or new_card(passed, day)
    return out


def _order(key: str, d: _dt.date) -> str:
    # the same day gives the same order; the next day mixes the lessons again
    return hashlib.sha1(f"{d}:{key}".encode()).hexdigest()


def due_keys(all_cards: dict, day=None) -> list[str]:
    """Questions due on `day`, the longest-waiting first, lower boxes first."""
    d = _day(day)
    iso = _iso(d)
    due = [k for k, c in all_cards.items() if c["due"] <= iso]
    return sorted(due, key=lambda k: (all_cards[k]["due"], all_cards[k]["box"], _order(k, d)))


def answered_on(state: dict, day=None) -> dict:
    return dict(state["log"].get(_iso(_day(day))) or {"answered": 0, "right": 0})


def todays_keys(state: dict | None = None, prog: dict | None = None, day=None, sizes=None) -> tuple[list[str], dict]:
    state = state if state is not None else load()
    allc = cards(state, prog, day, sizes)
    left = max(0, DAILY - answered_on(state, day)["answered"])
    return due_keys(allc, day)[:left], allc


def status(day=None, state: dict | None = None, prog: dict | None = None, sizes=None) -> dict:
    """What the Learn window's Review button and `--status` show."""
    d = _day(day)
    state = state if state is not None else load()
    allc = cards(state, prog, d, sizes)
    due = due_keys(allc, d)
    log = answered_on(state, d)
    left = max(0, DAILY - log["answered"])
    later = sorted(c["due"] for c in allc.values() if c["due"] > _iso(d))
    boxes = [0] * (TOP + 1)
    for c in allc.values():
        boxes[c["box"]] += 1
    return {"day": _iso(d), "questions": len(allc), "due": len(due), "today": min(len(due), left),
            "answered_today": log["answered"], "right_today": log["right"], "daily": DAILY,
            "next": later[0] if later else "", "boxes": boxes,
            "intervals": list(INTERVALS)}


# ------------------------------------------------------------------ a day's set
def _question(key: str):
    from . import lessons as ls
    lid, n = split_key(key)
    lesson = ls.load(lid)
    if n >= len(lesson.quiz):
        raise ValueError(f"{lid} has no question {n + 1}")
    return lesson, lesson.quiz[n]


def todays_set(day=None) -> dict:
    """Today's questions with their choices shuffled (the same order all day),
    in the desktop's language, answers left out."""
    d = _day(day)
    keys, allc = todays_keys(day=d)
    items = []
    for k in keys:
        try:
            lesson, q = _question(k)
        except Exception:
            continue
        choices = q.choices
        random.Random(_order(k, d)).shuffle(choices)
        items.append({"key": k, "lesson": lesson.id, "lesson_title": lesson.title,
                      "q": q.q, "choices": choices, "box": allc[k]["box"]})
    return {**status(d), "items": items}


def _english_answer(lesson_id: str, n: int) -> str:
    """The answer as written in English: a set shown before the desktop's
    language changed is still graded right."""
    from . import content, lessons as ls
    try:
        return str(content.load_toml(ls.lesson_path(lesson_id))["quiz"][n]["answer"]).strip()
    except Exception:
        return ""


def answer(picked: dict | list, day=None) -> dict:
    """Grades answers to review questions ({key: choice text} or a list of
    {key, picked}) and moves each answered card on its schedule. A skipped
    question (empty pick) is not graded and stays due."""
    from . import progress
    d = _day(day)
    if isinstance(picked, list):
        picked = {str(x.get("key", "")): x.get("picked") for x in picked if isinstance(x, dict)}
    if not isinstance(picked, dict):
        raise ValueError("picked must be {key: choice}")
    state = load()
    done = _done_lessons(progress.load())
    log = state["log"].setdefault(_iso(d), {"answered": 0, "right": 0})
    results = []
    for key, got in picked.items():
        got = str(got or "").strip()
        try:
            lid, n = split_key(key)
            if lid not in done:
                raise ValueError(f"{lid} is not finished yet")
            lesson, q = _question(key)
        except Exception as exc:
            results.append({"key": key, "ok": False, "error": str(exc)})
            continue
        row = {"key": key, "lesson": lid, "lesson_title": lesson.title, "q": q.q, "picked": got,
               "answer": q.answer, "why": q.why}
        if not got:
            row.update(ok=False, skipped=True)
            results.append(row)
            continue
        ok = got == q.answer or got == _english_answer(lid, n)
        card = state["cards"].get(key) or new_card(done[lid], d)
        card = schedule(card, ok, d)
        state["cards"][key] = card
        log["answered"] += 1
        log["right"] += int(ok)
        row.update(ok=ok, box=card["box"], due=card["due"])
        results.append(row)
    save(state)
    graded = [r for r in results if "box" in r]
    right = sum(1 for r in graded if r["ok"])
    return {"right": right, "total": len(graded), "results": results, "status": status(d)}


# ------------------------------------------------------------------ carrying it to another PC
def merge(local: dict, other: dict) -> tuple[dict, int]:
    """Two PCs' review states as one: per question the card answered last
    wins; per day the larger counts. Merging the same twice changes nothing."""
    a, b = clean(local), clean(other)
    changed = 0
    for k, c in b["cards"].items():
        cur = a["cards"].get(k)
        if cur is None or c["updated"] > cur["updated"]:
            if cur != c:
                a["cards"][k] = c
                changed += 1
    for dd, row in b["log"].items():
        cur = a["log"].get(dd) or {"answered": 0, "right": 0}
        a["log"][dd] = {"answered": max(cur["answered"], row["answered"]), "right": max(cur["right"], row["right"])}
    return a, changed
