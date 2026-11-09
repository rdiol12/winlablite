"""The student's progress as one file, to carry it to another PC.

winlab keeps no account and no cloud copy: what the student has done lives
under var/ on the PC they worked on. A progress file (``.wlprogress``) holds
all of it, so the next PC (the school's, home, a new laptop) picks up where
the last one stopped:

- lessons: done or started, ticked steps, best grade, recall-quiz scores
- problems fixed, on-call shifts, helpdesk and break-and-fix runs, company
  runs, interviews, incident drills, the ticket game's career
- practice exam results (var/exams/history.json), subnetting drills,
  scenario runs
- track certificates (code, name, verification link) and the name on them
- the Notes window's notebook of every lab
- the spaced review schedule of the recall questions (var/review.json)

It is a JSON document, readable in any editor; nothing about the labs'
machines, disks or licence is in it. Opening one *merges*: nothing on this PC
is lost, a lesson done on either PC is done, the best score of the two wins,
results from both are kept, and notes that differ are kept one after the
other. Importing the same file twice changes nothing the second time.

    winlab progress export [file]      the file to take along
    winlab progress import <file>      merge it into this PC's progress

The desktop does the same from the Progress window (Export, Import).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from . import notes, paths, progress, review

FORMAT = "winlab-progress"
VERSION = 1
EXT = ".wlprogress"
MAX_BYTES = 32 * 1024 * 1024
LIST_KEEP = 50  # the newest results progress.py keeps per kind
_LISTS = ("shifts", "helpdesk", "breakfix", "interviews", "incidents")
_RANK = {progress.STATUS_NEW: 0, progress.STATUS_STARTED: 1, progress.STATUS_DONE: 2}


class ProgressFileError(ValueError):
    pass


# ------------------------------------------------------------------ the other files under var/
def _exam_file() -> Path:
    from . import practice_exam
    return practice_exam.history_file()


def _drill_file() -> Path:
    return paths.VAR / "drills" / "subnet.json"


def _scenario_file() -> Path:
    return paths.VAR / "scenario-history.json"


def _read_list(f: Path) -> list[dict]:
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):  # TypeError: a part the trial leaves out
        return []
    return [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []


def _write_json(f: Path, data) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(f)


def _notes_all() -> dict[str, dict]:
    out = {}
    d = paths.VAR / "notes"
    if d.is_dir():
        for f in sorted(d.glob("*.txt")):
            try:
                text = f.read_text(encoding="utf-8")
            except OSError:
                continue
            if text.strip():
                out[f.stem] = {"text": text, "saved": f.stat().st_mtime}
    return out


# ------------------------------------------------------------------ export
def bundle() -> dict:
    """Everything the student has done on this PC, as one document."""
    data = progress.load()
    return {
        "format": FORMAT, "version": VERSION, "exported": time.time(),
        "student": data.get("student", ""),
        "progress": data,
        "exams": _read_list(_exam_file()),
        "drills": {"subnet": _read_list(_drill_file())},
        "scenarios": _read_list(_scenario_file()),
        "notes": _notes_all(),
        "review": review.load(),
    }


def dumps(b: dict | None = None) -> bytes:
    return (json.dumps(b or bundle(), indent=1, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def file_name(b: dict | None = None) -> str:
    """winlab-progress-<name>-<date>.wlprogress: says whose and when."""
    who = re.sub(r"[^A-Za-z0-9]+", "-", str((b or {}).get("student") or progress.student())).strip("-")[:40]
    day = time.strftime("%Y-%m-%d")
    return f"winlab-progress-{who + '-' if who else ''}{day}{EXT}"


def export(dest: str | Path = "") -> Path:
    b = bundle()
    out = Path(dest) if dest else Path(file_name(b))
    if out.is_dir():
        out = out / file_name(b)
    out.write_bytes(dumps(b))
    return out


def counts(b: dict) -> dict:
    p = b.get("progress") or {}
    lessons = p.get("lessons") or {}
    return {"lessons_done": sum(1 for e in lessons.values() if isinstance(e, dict) and e.get("status") == progress.STATUS_DONE),
            "lessons_started": sum(1 for e in lessons.values() if isinstance(e, dict) and e.get("status") == progress.STATUS_STARTED),
            "problems": sum(1 for e in (p.get("problems") or {}).values() if isinstance(e, dict) and int(e.get("solved") or 0) > 0),
            "exams": len(b.get("exams") or []), "certificates": len(p.get("certificates") or {}),
            "notes": len(b.get("notes") or {})}


# ------------------------------------------------------------------ reading a file
def read(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise ProgressFileError("that is not a progress file: it is far too big")
    try:
        b = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise ProgressFileError("that is not a winlab progress file (.wlprogress)") from None
    if not isinstance(b, dict) or b.get("format") != FORMAT:
        raise ProgressFileError("that is not a winlab progress file (.wlprogress)")
    if int(b.get("version") or 0) > VERSION:
        raise ProgressFileError("this progress file comes from a newer winlab: update winlab on this PC first")
    if not isinstance(b.get("progress"), dict):
        raise ProgressFileError("the progress file is damaged: it has no progress in it")
    return b


# ------------------------------------------------------------------ merging
def _num(v) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _first(a, b):
    """The earlier of two times, ignoring 0 (never)."""
    xs = [x for x in (_num(a), _num(b)) if x > 0]
    return min(xs) if xs else 0.0


def merge_lesson(a: dict, b: dict) -> dict:
    newer, older = (a, b) if _num(a.get("updated")) >= _num(b.get("updated")) else (b, a)
    out = {**older, **newer}
    out["status"] = max((a.get("status"), b.get("status")), key=lambda s: _RANK.get(s, 0)) or progress.STATUS_NEW
    out["steps"] = sorted({int(i) for i in (a.get("steps") or []) + (b.get("steps") or []) if str(i).lstrip("-").isdigit()})
    for k in ("best", "attempts", "failed", "gave_up", "quiz_best", "quiz_tries", "quiz_total"):
        if k in a or k in b:
            out[k] = int(max(_num(a.get(k)), _num(b.get(k))))
    for k in ("passed_at", "answer_viewed"):
        if k in a or k in b:
            out[k] = _first(a.get(k), b.get(k))
    out["updated"] = max(_num(a.get("updated")), _num(b.get("updated")))
    return out


def merge_problem(a: dict, b: dict) -> dict:
    newer, older = (a, b) if _num(a.get("updated")) >= _num(b.get("updated")) else (b, a)
    out = {**older, **newer}
    for k in ("solved", "attempts", "hints", "hints_open"):
        if k in a or k in b:
            out[k] = int(max(_num(a.get(k)), _num(b.get(k))))
    for k in ("solved_at", "updated"):
        if k in a or k in b:
            out[k] = max(_num(a.get(k)), _num(b.get(k)))
    return out


def _when(row: dict) -> float:
    for k in ("finished", "ended", "date", "at", "started", "t", "time"):
        if _num(row.get(k)):
            return _num(row.get(k))
    return 0.0


def merge_rows(a: list, b: list, keep: int, key=None) -> list:
    """Both lists' rows, each once, oldest first, the newest `keep`."""
    key = key or (lambda r: json.dumps(r, sort_keys=True))
    seen, out = set(), []
    for r in list(a) + list(b):
        if not isinstance(r, dict):
            continue
        k = key(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    out.sort(key=_when)
    return out[-keep:]


def merge_max(a, b):
    """A tally both PCs added to (the ticket game's career): the larger
    number, both lists' items, keys from both. Merging the same thing twice
    gives the same result."""
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: (merge_max(a[k], b[k]) if k in a and k in b else a.get(k, b.get(k))) for k in {**b, **a}}
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) or bool(b)
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return max(a, b)
    if isinstance(a, list) and isinstance(b, list):
        out = list(a)
        for x in b:
            if x not in out:
                out.append(x)
        return out
    return a if a not in (None, "") else b


def merge_progress(local: dict, other: dict) -> tuple[dict, dict]:
    """local's progress with other's merged in, and what changed."""
    out = json.loads(json.dumps(local))
    got = {"lessons_new": 0, "lessons_updated": 0, "problems": 0, "results": 0, "certificates": 0}
    for lid, e in (other.get("lessons") or {}).items():
        if not isinstance(e, dict):
            continue
        cur = out["lessons"].get(lid)
        if cur is None:
            out["lessons"][lid] = e
            got["lessons_new"] += 1
        else:
            m = merge_lesson(cur, e)
            if m != cur:
                out["lessons"][lid] = m
                got["lessons_updated"] += 1
    for pid, e in (other.get("problems") or {}).items():
        if not isinstance(e, dict):
            continue
        cur = out["problems"].get(pid)
        m = e if cur is None else merge_problem(cur, e)
        if m != cur:
            out["problems"][pid] = m
            got["problems"] += 1
    for k in _LISTS:
        mine = out.get(k) or []
        m = merge_rows(mine, other.get(k) or [], LIST_KEEP)
        got["results"] += max(0, len(m) - len(mine))
        if m:
            out[k] = m
    runs = {(str(r.get("lab", "")), _num(r.get("started"))): r for r in out.get("companies") or [] if isinstance(r, dict)}
    for r in other.get("companies") or []:
        if not isinstance(r, dict):
            continue
        k = (str(r.get("lab", "")), _num(r.get("started")))
        if k not in runs:
            got["results"] += 1
            runs[k] = r
        elif _num(r.get("updated") or r.get("day") or r.get("days")) > _num(runs[k].get("updated") or runs[k].get("day") or runs[k].get("days")):
            runs[k] = r
    if runs:
        out["companies"] = sorted(runs.values(), key=lambda r: _num(r.get("started")))[-LIST_KEEP:]
    if isinstance(other.get("ticketgame"), dict):
        out["ticketgame"] = merge_max(out.get("ticketgame") or {}, other["ticketgame"])
    certs = out.setdefault("certificates", {})
    for tid, c in (other.get("certificates") or {}).items():
        if not isinstance(c, dict):
            continue
        if tid not in certs:
            certs[tid] = c
            got["certificates"] += 1
        else:
            certs[tid] = {**c, **{k: v for k, v in certs[tid].items() if v not in (None, "")}}
    if not certs:
        out.pop("certificates", None)
    if not out.get("student") and other.get("student"):
        out["student"] = str(other["student"])[:80]
    return out, got


def merge_notes(mine: str, theirs: str, when: float = 0.0) -> str:
    """One notebook from two: the same or one inside the other is kept once;
    otherwise this PC's notes, then the other PC's under a line saying so."""
    a, b = mine.rstrip(), theirs.rstrip()
    if not b or b in a:
        return mine
    if not a or a in b:
        return theirs
    day = time.strftime("%Y-%m-%d %H:%M", time.localtime(when)) if when else "another PC"
    return f"{a}\n\n----- notes from another PC ({day}) -----\n{b}\n"


# ------------------------------------------------------------------ import
def import_bundle(b: dict) -> dict:
    """Merges a read progress file into this PC's progress. Returns what it added."""
    merged, got = merge_progress(progress.load(), b["progress"])
    progress.save(merged)
    rep = dict(got)
    # practice exams: one row per exam sitting (its id)
    mine = _read_list(_exam_file())
    ex = merge_rows(mine, b.get("exams") or [], 200, key=lambda r: str(r.get("id") or json.dumps(r, sort_keys=True)))
    rep["exams"] = max(0, len(ex) - len(mine))
    if rep["exams"]:
        _write_json(_exam_file(), ex)
    mine = _read_list(_drill_file())
    dr = merge_rows(mine, (b.get("drills") or {}).get("subnet") or [], 100)
    rep["drills"] = max(0, len(dr) - len(mine))
    if rep["drills"]:
        _write_json(_drill_file(), dr)
    mine = _read_list(_scenario_file())
    sc = merge_rows(mine, b.get("scenarios") or [], 200)
    rep["scenarios"] = max(0, len(sc) - len(mine))
    if rep["scenarios"]:
        _write_json(_scenario_file(), sc)
    rep["notes"] = 0
    rep["notes_skipped"] = []
    for lab, n in (b.get("notes") or {}).items():
        if not isinstance(n, dict) or not isinstance(n.get("text"), str):
            continue
        lab = re.sub(r"[^A-Za-z0-9._-]", "_", str(lab)) or "lab"
        cur = notes.load(lab)["text"]
        text = merge_notes(cur, n["text"], _num(n.get("saved")))
        if text == cur:
            continue
        try:
            notes.save(lab, text)
            rep["notes"] += 1
        except ValueError:
            rep["notes_skipped"].append(lab)
    rev, rep["review"] = review.merge(review.load(), b.get("review") or {})
    if rep["review"] or (b.get("review") or {}).get("log"):
        review.save(rev)
    rep["student"] = merged.get("student", "")
    rep["message"] = describe(rep)
    return rep


def import_bytes(data: bytes) -> dict:
    return import_bundle(read(data))


def import_file(src: str | Path) -> dict:
    f = Path(src)
    try:
        if f.stat().st_size > MAX_BYTES:
            raise ProgressFileError("that is not a progress file: it is far too big")
        data = f.read_bytes()
    except OSError as exc:
        raise ProgressFileError(f"cannot read {f}: {exc.strerror or exc}") from None
    return import_bytes(data)


def describe(rep: dict) -> str:
    parts = []
    if rep.get("lessons_new"):
        parts.append(f"{rep['lessons_new']} new lesson{'s' if rep['lessons_new'] != 1 else ''}")
    if rep.get("lessons_updated"):
        parts.append(f"{rep['lessons_updated']} lesson{'s' if rep['lessons_updated'] != 1 else ''} brought up to date")
    if rep.get("problems"):
        parts.append(f"{rep['problems']} problem{'s' if rep['problems'] != 1 else ''}")
    results = sum(int(rep.get(k) or 0) for k in ("results", "exams", "drills", "scenarios"))
    if results:
        parts.append(f"{results} result{'s' if results != 1 else ''}")
    if rep.get("certificates"):
        parts.append(f"{rep['certificates']} certificate{'s' if rep['certificates'] != 1 else ''}")
    if rep.get("review"):
        parts.append(f"the review schedule of {rep['review']} question{'s' if rep['review'] != 1 else ''}")
    if rep.get("notes"):
        parts.append(f"notes of {rep['notes']} lab{'s' if rep['notes'] != 1 else ''}")
    msg = ("merged: " + ", ".join(parts)) if parts else "nothing new: this PC already has everything in that file"
    if rep.get("notes_skipped"):
        msg += f"; notes too long to merge for {', '.join(rep['notes_skipped'])}"
    return msg
