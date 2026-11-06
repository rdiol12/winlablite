"""Timed practice exams over a track's question bank.

A track (content/exams/<id>.toml, winlab/exams.py) has a question bank beside
it, content/exams/<id>-questions.toml. A question is one of three kinds:

  single   one right option among several
  multi    several right options ("Choose two."), all of them needed
  lab      a task the student does on the running lab, graded live inside the
           guests by an exercise's own checks (all of them, or the ones named)

Every question names the lesson to revisit, and says why the answer is right.

A practice exam draws N questions weighted by the track's areas, shuffles
each question's options, and runs against a clock. Everything that decides a
score stays here, on the PC's own server: the page gets the question text and
the options in a shuffled order, never which is right, until the exam is
submitted. The deadline is the server's: an answer after it is refused and
the exam is submitted as it stands. Results are kept per student in
var/exams/history.json. Nothing here changes a machine: lab questions only read.
"""

from __future__ import annotations

import json
import random
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import exams, paths

KINDS = ("single", "multi", "lab")
LETTERS = "ABCDEFGHIJ"
MIN_MINUTES, MAX_MINUTES = 5, 240
MAX_HISTORY = 200


class PracticeError(Exception):
    pass


@dataclass
class Question:
    id: str
    area: str
    kind: str
    text: str
    lesson: str
    why: str
    options: list[str] = field(default_factory=list)
    answer: list[str] = field(default_factory=list)   # the right options' text
    exercise: str = ""                                  # lab: the exercise whose checks grade it
    checks: list[str] = field(default_factory=list)     # lab: which of its checks (all when empty)


@dataclass
class Bank:
    exam: str
    questions: list[Question] = field(default_factory=list)

    def by_id(self) -> dict[str, Question]:
        return {q.id: q for q in self.questions}


def bank_path(track: str) -> Path:
    return exams.EXAMS / f"{track}-questions.toml"


def load_bank(track: str) -> Bank:
    path = bank_path(track)
    try:
        from . import content
        raw = content.load_toml(path)
    except OSError as exc:
        raise PracticeError(f"no question bank for {track}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PracticeError(f"{path.name}: {exc}") from exc
    meta = raw.get("bank") or {}
    out = Bank(exam=str(meta.get("exam", track)))
    for i, q in enumerate(raw.get("question", [])):
        ans = q.get("answer", [])
        out.questions.append(Question(
            id=str(q.get("id", f"#{i + 1}")), area=str(q.get("area", "")), kind=str(q.get("type", "single")),
            text=str(q.get("q", "")).strip(), lesson=str(q.get("lesson", "")), why=str(q.get("why", "")).strip(),
            options=[str(x) for x in q.get("options", [])],
            answer=[str(ans)] if isinstance(ans, str) else [str(x) for x in ans],
            exercise=str(q.get("exercise", "")), checks=[str(x) for x in q.get("checks", [])]))
    return out


def validate_bank(exam: exams.Exam, bank: Bank, lesson_ids: set[str],
                  exercise_checks: dict[str, list[str]] | None = None) -> list[str]:
    """What an author must fix: duplicate ids, answers that are not options,
    unknown areas, lessons or exercises, a covered area without questions."""
    from . import exercises as exs

    if exercise_checks is None:
        exercise_checks = {e.id: [c.name for c in e.checks] for e in exs.list_available()}
    tag = exam.id
    problems: list[str] = []
    if bank.exam != exam.id:
        problems.append(f"{tag}: the bank says it is for {bank.exam}")
    areas = {a.id: a for a in exam.areas}
    seen: set[str] = set()
    for q in bank.questions:
        where = f"{tag}/{q.id}"
        if q.id in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(q.id)
        if q.kind not in KINDS:
            problems.append(f"{where}: type must be one of {', '.join(KINDS)}")
            continue
        if q.area not in areas:
            problems.append(f"{where}: unknown area {q.area!r}")
        elif not areas[q.area].covered:
            problems.append(f"{where}: area {q.area} is not covered in winlab, so it has no lesson to revisit")
        if not q.text:
            problems.append(f"{where}: no question text")
        if not q.why:
            problems.append(f"{where}: no explanation (why)")
        if q.lesson not in lesson_ids:
            problems.append(f"{where}: unknown lesson {q.lesson!r}")
        elif q.area in areas and q.lesson not in areas[q.area].lessons:
            problems.append(f"{where}: lesson {q.lesson} is not mapped to area {q.area}")
        if q.kind == "lab":
            if q.options or q.answer:
                problems.append(f"{where}: a lab question has no options or answer; its exercise grades it")
            if q.exercise not in exercise_checks:
                problems.append(f"{where}: unknown exercise {q.exercise!r}")
            else:
                for c in q.checks:
                    if c not in exercise_checks[q.exercise]:
                        problems.append(f"{where}: exercise {q.exercise} has no check {c!r}")
            continue
        if len(q.options) < 3 or len(q.options) > len(LETTERS):
            problems.append(f"{where}: needs 3 to {len(LETTERS)} options")
        if len(set(q.options)) != len(q.options):
            problems.append(f"{where}: two options are the same")
        missing = [a for a in q.answer if a not in q.options]
        if missing:
            problems.append(f"{where}: answer not among the options: {missing}")
        if len(set(q.answer)) != len(q.answer):
            problems.append(f"{where}: an answer is listed twice")
        if q.kind == "single" and len(q.answer) != 1:
            problems.append(f"{where}: a single-answer question needs exactly one answer")
        if q.kind == "multi" and not 2 <= len(q.answer) < len(q.options):
            problems.append(f"{where}: a multiple-select question needs at least two answers and a wrong option")
    for a in exam.areas:
        if a.covered and not any(q.area == a.id for q in bank.questions):
            problems.append(f"{tag}/{a.id}: a covered area with no questions")
    return problems


def validate_all() -> tuple[int, int, list[str]]:
    """(tracks, questions, problems) over every track and bank. A bank's ids
    are unique across banks too: history refers to them."""
    from . import lessons as ls

    lesson_ids = {l.id for l in ls.list_available()}
    problems: list[str] = []
    n_tracks = n_q = 0
    all_ids: dict[str, str] = {}
    from . import content
    for f in content.glob(exams.EXAMS, "*-questions.toml"):
        track = f.stem[: -len("-questions")]
        if not content.exists(exams.EXAMS / f"{track}.toml"):
            problems.append(f"{f.name}: no track {track}.toml beside it")
    for ex in exams.list_available():
        n_tracks += 1
        problems += [p for p in exams.validate(ex, lesson_ids)]
        if not content.exists(bank_path(ex.id)):
            continue
        try:
            bank = load_bank(ex.id)
        except PracticeError as exc:
            problems.append(str(exc))
            continue
        n_q += len(bank.questions)
        problems += validate_bank(ex, bank, lesson_ids)
        for q in bank.questions:
            if q.id in all_ids and all_ids[q.id] != ex.id:
                problems.append(f"{ex.id}/{q.id}: id also used in {all_ids[q.id]}")
            all_ids.setdefault(q.id, ex.id)
    return n_tracks, n_q, problems


# ------------------------------------------------------------------ the draw
def allocate(weights: dict[str, float], available: dict[str, int], n: int) -> dict[str, int]:
    """How many questions each area gets: in proportion to its exam weight
    (largest remainder), never more than it has; what an area cannot fill
    goes to the others by weight."""
    n = max(0, min(n, sum(available.values())))
    out = {a: 0 for a in weights}
    left = n
    open_ = [a for a in weights if available.get(a, 0) > 0 and weights[a] > 0]
    while left > 0 and open_:
        wsum = sum(weights[a] for a in open_)
        share = {a: left * weights[a] / wsum for a in open_}
        give = {a: int(share[a]) for a in open_}
        rest = left - sum(give.values())
        for a in sorted(open_, key=lambda a: (-(share[a] - give[a]), -weights[a], a))[:rest]:
            give[a] += 1
        for a in open_:
            take = min(give[a], available[a] - out[a])
            out[a] += take
            left -= take
        open_ = [a for a in open_ if out[a] < available[a]]
    return out


def draw(exam: exams.Exam, bank: Bank, n: int, rng: random.Random,
         lab_ok: Callable[[Question], bool] | None = None) -> list[Question]:
    """N questions weighted by area. Lab questions take part only when lab_ok
    says this lab can grade them now (its machines are running)."""
    pool: dict[str, list[Question]] = {}
    for q in bank.questions:
        if q.kind == "lab" and not (lab_ok and lab_ok(q)):
            continue
        pool.setdefault(q.area, []).append(q)
    weights = {a.id: a.mid_weight for a in exam.areas if a.covered}
    counts = allocate(weights, {a: len(pool.get(a, [])) for a in weights}, n)
    picked: list[Question] = []
    for a in weights:
        picked += rng.sample(pool.get(a, []), counts[a])
    rng.shuffle(picked)
    return picked


# ------------------------------------------------------------------ the session
def exam_dir() -> Path:
    return paths.VAR / "exams"


def session_file() -> Path:
    return exam_dir() / "session.json"


def history_file() -> Path:
    return exam_dir() / "history.json"


def _now() -> float:
    return time.time()


def _student() -> str:
    from . import progress
    return progress.student()


def load_session() -> dict | None:
    try:
        raw = json.loads(session_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return raw if isinstance(raw, dict) and raw.get("items") else None


def save_session(s: dict | None) -> None:
    f = session_file()
    if s is None:
        f.unlink(missing_ok=True)
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(s, indent=1), encoding="utf-8")
    tmp.replace(f)


def start(track: str, n: int | None = None, minutes: int | None = None, *,
          rng: random.Random | None = None, now: float | None = None,
          lab_ok: Callable[[Question], bool] | None = None, lab: str = "") -> dict:
    """A new exam. One at a time: an open one must be submitted or abandoned."""
    cur = load_session()
    if cur and not cur.get("done"):
        raise PracticeError("a practice exam is already open: finish it, or abandon it first")
    exam = exams.load(track)
    bank = load_bank(track)
    rng = rng or random.Random()
    n = int(n or exam.questions)
    minutes = int(minutes or exam.minutes)
    if n < 1:
        raise PracticeError("an exam needs at least one question")
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise PracticeError(f"the clock runs {MIN_MINUTES} to {MAX_MINUTES} minutes")
    qs = draw(exam, bank, n, rng, lab_ok)
    if not qs:
        raise PracticeError(f"{track} has no questions that can be asked here")
    t0 = _now() if now is None else now
    items = []
    for q in qs:
        order = list(range(len(q.options)))
        rng.shuffle(order)
        items.append({"qid": q.id, "kind": q.kind, "order": order, "picked": [], "flagged": False})
    s = {"id": f"{track}-{int(t0)}", "track": track, "title": exam.title, "student": _student(),
         "lab": lab, "started": t0, "minutes": minutes, "deadline": t0 + minutes * 60,
         "pass_mark": exam.pass_mark, "items": items, "done": False, "result": None}
    save_session(s)
    return s


def _left(s: dict, now: float) -> int:
    return max(0, int(round(s["deadline"] - now)))


def answer(s: dict, n: int, picked: list[int] | None = None, flagged: bool | None = None,
           *, now: float | None = None, grader: "Grader | None" = None) -> tuple[bool, str]:
    """Record an answer (displayed option numbers) or a flag for question n
    (from 1). After the deadline nothing is recorded: the exam is submitted."""
    now = _now() if now is None else now
    if s.get("done"):
        return False, "this exam is already submitted"
    if now >= s["deadline"]:
        submit(s, grader, now=now, auto=True)
        return False, "time is up: the exam was submitted as it stood"
    if not 1 <= n <= len(s["items"]):
        return False, f"there is no question {n}"
    it = s["items"][n - 1]
    if picked is not None:
        width = max(1, len(it["order"]))
        got = sorted({int(p) for p in picked if 0 <= int(p) < width})
        if it.get("kind") == "single" and len(got) > 1:
            return False, "this question has one answer"
        it["picked"] = got
    if flagged is not None:
        it["flagged"] = bool(flagged)
    save_session(s)
    return True, "saved"


def expire(s: dict | None, grader: "Grader | None" = None, now: float | None = None) -> bool:
    """Submit an open exam whose time has run out. True when it did."""
    now = _now() if now is None else now
    if s and not s.get("done") and now >= s["deadline"]:
        submit(s, grader, now=now, auto=True)
        return True
    return False


# A grader runs a lab question's checks on the running machines and returns
# exercises.Grade; the GUI and the CLI pass exercises.grade on the lab.
Grader = Callable[["object"], "object"]


def lab_exercise(q: Question):
    """The exercise a lab question is graded by, cut down to its named checks."""
    from . import exercises as exs
    ex = exs.load(q.exercise)
    if q.checks:
        ex.checks = [c for c in ex.checks if c.name in q.checks]
    return ex


def lab_nodes(q: Question) -> list[str]:
    try:
        return sorted({c.node for c in lab_exercise(q).checks})
    except Exception:  # noqa: BLE001
        return []


def default_grader(lab_name: str) -> Grader:
    from . import exercises as exs
    return lambda ex: exs.grade(ex, lab_name)


def submit(s: dict, grader: Grader | None = None, *, now: float | None = None, auto: bool = False) -> dict:
    """Grade every question (lab ones live), keep the result in the session
    and the student's history."""
    if s.get("done"):
        return s["result"]
    now = _now() if now is None else now
    exam = exams.load(s["track"])
    qs = load_bank(s["track"]).by_id()
    titles = _lesson_titles()
    rows = []
    for i, it in enumerate(s["items"], 1):
        q = qs.get(it["qid"])
        if q is None:
            rows.append({"n": i, "qid": it["qid"], "area": "", "score": 0.0, "missing": True})
            continue
        row = {"n": i, "qid": q.id, "area": q.area, "kind": q.kind, "lesson": q.lesson,
               "lesson_title": titles.get(q.lesson, q.lesson), "why": q.why}
        if q.kind == "lab":
            row.update(_grade_lab(q, grader))
        else:
            chosen = {q.options[it["order"][p]] for p in it["picked"] if p < len(it["order"])}
            right = set(q.answer)
            row["score"] = 1.0 if chosen == right else 0.0
            row["correct"] = sorted(p for p, o in enumerate(it["order"]) if q.options[o] in right)
            row["picked"] = list(it["picked"])
        rows.append(row)
    areas = []
    for a in exam.areas:
        mine = [r for r in rows if r["area"] == a.id]
        if not mine:
            continue
        got = sum(r["score"] for r in mine)
        areas.append({"id": a.id, "title": a.title, "questions": len(mine), "score": round(got, 2),
                      "percent": round(100 * got / len(mine))})
    total = sum(r["score"] for r in rows)
    pct = round(100 * total / len(rows)) if rows else 0
    result = {"percent": pct, "score": round(total, 2), "questions": len(rows), "pass_mark": s["pass_mark"],
              "passed": pct >= s["pass_mark"], "areas": areas, "items": rows, "auto": auto,
              "finished": now, "used_seconds": int(min(now, s["deadline"]) - s["started"])}
    s["done"], s["result"] = True, result
    save_session(s)
    _record(s, result)
    return result


def _grade_lab(q: Question, grader: Grader | None) -> dict:
    if grader is None:
        return {"score": 0.0, "checks": [], "note": "no running lab to grade this task on"}
    try:
        g = grader(lab_exercise(q))
    except Exception as exc:  # noqa: BLE001
        return {"score": 0.0, "checks": [], "note": f"could not grade on the lab: {exc}"}
    checks = [{"name": r.check.name, "passed": r.passed, "detail": r.detail} for r in g.results]
    return {"score": round(g.earned / g.total, 2) if g.results else 0.0, "checks": checks}


def _lesson_titles() -> dict[str, str]:
    from . import lessons as ls
    return {l.id: l.title for l in ls.list_available()}


def abandon() -> bool:
    s = load_session()
    save_session(None)
    return bool(s)


# ------------------------------------------------------------------ history
def load_history() -> list[dict]:
    try:
        raw = json.loads(history_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []


def _record(s: dict, r: dict) -> None:
    entry = {"id": s["id"], "track": s["track"], "title": s["title"], "student": s.get("student", ""),
             "date": r["finished"], "percent": r["percent"], "pass_mark": r["pass_mark"],
             "passed": r["passed"], "questions": r["questions"], "minutes": s["minutes"],
             "used_seconds": r["used_seconds"], "auto": r["auto"],
             "areas": [{"id": a["id"], "title": a["title"], "percent": a["percent"]} for a in r["areas"]]}
    hist = [h for h in load_history() if h.get("id") != entry["id"]] + [entry]
    f = history_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(hist[-MAX_HISTORY:], indent=1), encoding="utf-8")
    tmp.replace(f)


def history(track: str = "", student: str | None = None) -> list[dict]:
    """This student's results, newest first (another student's stay theirs)."""
    who = _student() if student is None else student
    return [h for h in reversed(load_history())
            if h.get("student", "") == who and (not track or h.get("track") == track)]


# ------------------------------------------------------------------ what the page sees
def client_view(s: dict | None, now: float | None = None) -> dict:
    """The exam as the page may see it. While it runs: the questions and the
    options in their shuffled order, what was picked and flagged, the time
    left. Never the answers, the explanations or the checks. Once submitted:
    the result, with what was right and why."""
    if not s:
        return {"active": False}
    now = _now() if now is None else now
    qs = load_bank(s["track"]).by_id()
    titles = _lesson_titles() if s.get("done") else {}
    items = []
    for i, it in enumerate(s["items"], 1):
        q = qs.get(it["qid"])
        if q is None:
            items.append({"n": i, "kind": "single", "text": "(this question was removed)", "options": [],
                          "picked": [], "flagged": False, "choose": 1})
            continue
        v = {"n": i, "kind": q.kind, "text": q.text, "options": [q.options[o] for o in it["order"]],
             "picked": list(it["picked"]), "flagged": bool(it["flagged"]),
             "choose": len(q.answer) if q.kind == "multi" else 1}
        if q.kind == "lab":
            v["nodes"] = lab_nodes(q)
        items.append(v)
    out = {"active": True, "done": bool(s.get("done")), "track": s["track"], "title": s["title"],
           "minutes": s["minutes"], "left": 0 if s.get("done") else _left(s, now), "pass_mark": s["pass_mark"],
           "items": items, "answered": sum(1 for it in s["items"] if it["picked"]),
           "flagged": sum(1 for it in s["items"] if it["flagged"])}
    if s.get("done") and s.get("result"):
        r = s["result"]
        out["result"] = {k: r[k] for k in ("percent", "score", "questions", "pass_mark", "passed", "areas",
                                           "auto", "used_seconds")}
        for v, row in zip(items, r["items"]):
            v["score"] = row.get("score", 0.0)
            v["right"] = row.get("score", 0.0) >= 1.0
            for k in ("correct", "why", "lesson", "checks", "note"):
                if k in row:
                    v[k] = row[k]
            if row.get("lesson"):
                v["lesson_title"] = titles.get(row["lesson"], row.get("lesson_title", row["lesson"]))
    return out


def tracks_view(lab_name: str = "", running: list[str] | None = None) -> dict:
    """Every track for the Exam prep page: readiness per area, the question
    bank's size, this student's last results, and the open exam if any."""
    out = []
    titles = _lesson_titles()
    for ex in exams.list_available():
        r = exams.readiness(ex, titles=titles)
        try:
            bank = load_bank(ex.id)
        except PracticeError:
            bank = None
        r["bank"] = {"questions": len(bank.questions) if bank else 0,
                     "lab": sum(1 for q in bank.questions if q.kind == "lab") if bank else 0,
                     "lab_here": sum(1 for q in bank.questions if q.kind == "lab"
                                     and lab_ready(q, lab_name, running or [])) if bank else 0}
        r["history"] = history(ex.id)[:5]
        out.append(r)
    s = load_session()
    return {"tracks": out, "open": bool(s and not s.get("done")),
            "open_track": s["track"] if s and not s.get("done") else ""}


def lab_ready(q: Question, lab_name: str, running: list[str]) -> bool:
    """A lab question can be asked when it is for this lab and the machines
    its checks read are running (the router counts when anything runs)."""
    if q.kind != "lab" or not lab_name:
        return False
    try:
        ex = lab_exercise(q)
    except Exception:  # noqa: BLE001
        return False
    if ex.lab != lab_name:
        return False
    need = {c.node for c in ex.checks}
    return bool(running) and all(n == "fabric" or n in running for n in need)


# ------------------------------------------------------------------ terminal mode
def render_question(v: dict, it: dict, total: int) -> str:
    lines = [f"Question {it['n']} of {total}" + ("   [flagged]" if it["flagged"] else ""), "", it["text"], ""]
    if it["kind"] == "lab":
        lines.append(f"  A task on the running lab, graded inside {', '.join(it.get('nodes') or ['the machines'])} "
                     "when you submit. Do it in the machine, then move on.")
    else:
        for i, o in enumerate(it["options"]):
            mark = "*" if i in it["picked"] else " "
            lines.append(f"  {mark}{LETTERS[i]}) {o}")
        if it["kind"] == "multi":
            lines += ["", f"  Choose {choose_words(it['choose'])}."]
    return "\n".join(lines)


def choose_words(n: int) -> str:
    return {2: "two", 3: "three", 4: "four"}.get(n, str(n))


def render_review(v: dict) -> str:
    lines = ["Review", ""]
    for it in v["items"]:
        state = "answered" if it["picked"] else ("lab task" if it["kind"] == "lab" else "not answered")
        lines.append(f"  {it['n']:>3}  {state:<13}{'  flagged' if it['flagged'] else ''}")
    lines += ["", f"{v['answered']} answered, {v['flagged']} flagged, {len(v['items']) - v['answered']} not answered"]
    return "\n".join(lines)


def render_result(v: dict) -> str:
    r = v["result"]
    lines = [v["title"], "",
             f"score {r['percent']}%   practice target {r['pass_mark']}%   "
             + ("target met" if r["passed"] else "below the target")
             + ("   (time ran out: submitted automatically)" if r["auto"] else ""), ""]
    for a in r["areas"]:
        bar = "#" * (a["percent"] // 5) + "." * (20 - a["percent"] // 5)
        lines.append(f"  [{bar}] {a['percent']:>3}%  {a['score']:g}/{a['questions']}  {a['title']}")
    lines.append("")
    for it in v["items"]:
        if it.get("right"):
            continue
        lines.append(f"  {it['n']:>3}. {it['text'][:110]}")
        if it["kind"] != "lab":
            right = ", ".join(f"{LETTERS[i]}) {it['options'][i]}" for i in it.get("correct", []))
            lines.append(f"       right: {right}")
        else:
            for c in it.get("checks", []):
                lines.append(f"       [{'PASS' if c['passed'] else 'FAIL'}] {c['name']}")
            if it.get("note"):
                lines.append(f"       {it['note']}")
        lines.append(f"       why: {it.get('why', '')}")
        lines.append(f"       revisit: {it.get('lesson_title', '')}  (winlab learn show {it.get('lesson', '')})")
    lines += ["", "The practice target is winlab's, not the real exam's scaled pass score."]
    return "\n".join(lines)


def parse_letters(text: str, width: int) -> list[int] | None:
    out = []
    for ch in text.replace(",", " ").split():
        for c in ch.upper():
            i = LETTERS.find(c)
            if i < 0 or i >= width:
                return None
            out.append(i)
    return sorted(set(out))


def run_terminal(s: dict, ask: Callable[[str], str], say: Callable[[str], None],
                 grader: Grader | None = None, now: Callable[[], float] = _now) -> dict:
    """The exam in a terminal: letters answer, n next, p previous, f flag,
    g N go to, r review, s submit, q leave it open for later."""
    pos = 1
    total = len(s["items"])
    help_ = "letters answer (A or A,C), n next, p previous, f flag, g N go to, r review, s submit, q quit for now"
    while not s.get("done"):
        if expire(s, grader, now()):
            say("Time is up: the exam was submitted as it stood.")
            break
        v = client_view(s, now())
        it = v["items"][pos - 1]
        m, sec = divmod(v["left"], 60)
        say(f"\n[{m}:{sec:02d} left]  {render_question(v, it, total)}")
        try:
            cmd = ask(f"> ({help_})\n> ").strip()
        except EOFError:
            cmd = "q"
        low = cmd.lower()
        if expire(s, grader, now()):
            say("Time is up: the exam was submitted as it stood; that last answer came too late.")
            break
        if low in ("n", ""):
            pos = min(total, pos + 1)
        elif low == "p":
            pos = max(1, pos - 1)
        elif low == "f":
            answer(s, pos, flagged=not it["flagged"], now=now(), grader=grader)
        elif low.startswith("g"):
            try:
                pos = max(1, min(total, int(low[1:].strip())))
            except ValueError:
                say("g and a question number, for example g 7")
        elif low == "r":
            say(render_review(v))
        elif low == "s":
            left = total - v["answered"]
            if left and ask(f"{left} not answered. Submit anyway? (y/n) ").strip().lower() != "y":
                continue
            submit(s, grader, now=now())
        elif low == "q":
            say("The exam stays open and its clock keeps running: winlab exam resume")
            return client_view(s, now())
        elif it["kind"] == "lab":
            answer(s, pos, picked=[0], now=now(), grader=grader)
            pos = min(total, pos + 1)
        else:
            got = parse_letters(cmd, len(it["options"]))
            if got is None:
                say("not an option here: " + help_)
                continue
            ok, msg = answer(s, pos, picked=got, now=now(), grader=grader)
            if not ok:
                say(msg)
                continue
            if pos < total:
                pos += 1
    v = client_view(s, now())
    say(render_result(v))
    return v


def render_history(rows: list[dict]) -> str:
    if not rows:
        return "no practice exams yet: winlab exam start <track>"
    out = []
    for h in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(h.get("date") or 0)))
        out.append(f"  {when}  {h.get('track', ''):<22} {h.get('percent', 0):>3}%  "
                   f"(target {h.get('pass_mark', 0)}%, {h.get('questions', 0)} questions"
                   + (", timed out" if h.get("auto") else "") + ")")
    return "\n".join(out)
