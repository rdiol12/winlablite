"""Classes: the teacher's class loop, with no server and no internet.

A teacher makes a class (its name and the roster of students: a name each
and, if the school uses them, a student id), assigns work to it (activities,
``.wlact`` files from the workbench, and lessons or exercises of the Lab
guide) with due dates, and exports a class file (``.wlclass``). The class
file goes to the students' PCs however the school moves files: a USB stick,
the school's learning platform, e-mail. Each lab PC is isolated, so nothing
here ever talks to a network.

On the student's PC the class file opens the Classwork window. The student
picks their name, does the work (an activity opens its starting network and
its own Activity window; a lesson opens in the Lab guide; an exercise is
graded with Check my work) and presses Hand in. That writes a result file
(``.wlresult``): who, which class, every assignment's score with its graded
items one by one, the time spent, when each score was handed in, the winlab
version, a hash of the PC (never the raw machine id), and evidence: the
outputs the in-guest checks read inside the student's machines, how many
changes the student made to an activity's network, and the activity
network itself as the student left it.

The teacher imports the result files (many at once, or a whole folder) into
the Class results window, which keeps them under ``var/classes/<class>/``
and shows the gradebook: students by assignments, late hand-ins flagged,
each score's items on a click, and a CSV for the school's own gradebook.
A file that was edited, or that belongs to another class or to a student
who is not on the roster, is refused with the reason.

What the seals can and cannot do, honestly:

* The class file and the result file are zip files with a ``seal`` part: a
  keyed hash (HMAC-SHA256) over every other part. The class file's key is
  winlab's own; the result file's key is derived from a random key made for
  that class, which travels inside the class file. Editing a score, a time
  or an item in a result file (in a text editor, or by unzipping and zipping
  it again) breaks the seal, and the teacher's import refuses the file. A
  result made for another class does not verify against this class's key.
* A local seal cannot stop a determined student. The key a student's PC
  seals with is on the student's PC (in the class file), and winlab's own
  code is there too; someone who takes winlab apart can seal any file they
  like. Only a server could prevent that, and lab PCs have none.
* So the result also carries evidence the teacher can look at, and the
  import cross-checks what it can: an activity's network is graded again on
  the teacher's PC against the activity's own target (a score that does not
  match the network handed in is flagged), the in-guest checks' outputs are
  shown as the student's machines printed them, clocks that look wrong are
  flagged (a hand-in dated before the class file was made, or after the
  file reached the teacher), and two students handing in from the same PC
  is shown.
* Times come from the student's PC clock. A student who sets their clock
  back can make a late hand-in look on time; the import time on the
  teacher's PC is kept as the latest the work can have been done.

Whether teacher mode is part of a given edition is decided by the
distribution builder (see ``teacher_mode_allowed``); nothing here checks a
licence.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import threading
import time
import zipfile
from pathlib import Path

from . import __version__, paths

CLASS_EXT = ".wlclass"
RESULT_EXT = ".wlresult"
FORMAT = 1
CLASS = "class.json"
RESULT = "result.json"
SEAL = "seal"
ACT_DIR = "activities/"
NET_DIR = "networks/"
MAX_FILE = 16 * 1024 * 1024
PART_MAX = 4 * 1024 * 1024
MAX_STUDENTS = 200
MAX_ASSIGNMENTS = 60
KINDS = {"activity": "Activity", "lesson": "Lesson", "exercise": "Exercise"}
_CLASS_SEAL = b"winlab class file, format 1"
_RESULT_SEAL = b"winlab class result, format 1"
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
CLASS_ID = re.compile(r"^[0-9a-f]{16}$")
DUE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?$")
CLOCK_SLACK = 10 * 60  # a student's clock may run this far ahead of the teacher's


class ClassError(Exception):
    pass


def teacher_mode_allowed() -> bool:
    """Whether this copy of winlab may make classes and read results.

    A school key's signed licence carries the "teacher" feature; a
    development checkout (no content packs) allows it too. The student
    side (opening a class file, handing in) never depends on it."""
    from . import content
    from .licensing import client
    return content.mode() == "dev" or client.has_feature("teacher")


def _need_teacher() -> None:
    if not teacher_mode_allowed():
        raise ClassError("making classes and reading results needs a school license key; students can open a class file and hand in without one")


# ------------------------------------------------------------------ sealing
def _digest(key: bytes, parts: dict[str, bytes]) -> str:
    h = hmac.new(key, digestmod=hashlib.sha256)
    for n in sorted(p for p in parts if p != SEAL):
        h.update(n.encode() + b"\0" + hashlib.sha256(parts[n]).digest())
    return h.hexdigest()


def _result_key(class_key: str) -> bytes:
    return hmac.new(_RESULT_SEAL, bytes.fromhex(class_key), hashlib.sha256).digest()


def _zip(parts: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n in sorted(parts, key=lambda n: (n == SEAL, n)):
            z.writestr(n, parts[n])
    return buf.getvalue()


def _unzip(data: bytes, main: str, sub: str, what: str) -> dict[str, bytes]:
    """The parts of a sealed file: ``main``, ``seal`` and any under ``sub``,
    nothing else, each of a sane size."""
    if len(data) > MAX_FILE:
        raise ClassError(f"that is not a {what}: it is far too big")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            if main not in names:
                raise ClassError(f"that is not a {what}")
            if SEAL not in names or len(set(names)) != len(names) or any(
                    n not in (main, SEAL) and not (n.startswith(sub) and "/" not in n[len(sub):] and n[len(sub):])
                    for n in names):
                raise ClassError(f"that {what} has been changed since it was made (its parts are not as written)")
            if any(z.getinfo(n).file_size > PART_MAX for n in names) or len(names) > 2 + MAX_ASSIGNMENTS:
                raise ClassError(f"that {what} is damaged")
            return {n: z.read(n) for n in names}
    except (zipfile.BadZipFile, KeyError, ValueError, OSError) as exc:
        raise ClassError(f"that is not a {what} ({exc})") from None


def _json(raw: bytes, what: str) -> dict:
    try:
        out = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ClassError(f"that {what} is damaged") from None
    if not isinstance(out, dict):
        raise ClassError(f"that {what} is damaged")
    return out


# ------------------------------------------------------------------ small helpers
def slug_of(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "class"


def _clean(text: object, n: int = 80) -> str:
    return " ".join(str(text or "").split())[:n]


def parse_due(text: str) -> float:
    """``YYYY-MM-DD`` (the end of that day) or ``YYYY-MM-DD HH:MM``, local
    time, as a timestamp; empty means no due date (0)."""
    text = (text or "").strip()
    if not text:
        return 0.0
    m = DUE.match(text)
    if not m:
        raise ClassError("a due date is YYYY-MM-DD, or YYYY-MM-DD HH:MM")
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hh, mm = (int(m.group(4)), int(m.group(5))) if m.group(4) else (23, 59)
    try:
        t = time.mktime((y, mo, d, hh, mm, 59 if not m.group(4) else 0, 0, 0, -1))
        if time.localtime(t)[:3] != (y, mo, d) or hh > 23 or mm > 59:
            raise ValueError
    except (ValueError, OverflowError):
        raise ClassError(f"{text} is not a date") from None
    return t


def _when(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else ""


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _write_json(path: Path, obj: dict) -> None:
    _write(path, (json.dumps(obj, indent=1) + "\n").encode())


def _read_json(path: Path) -> dict:
    try:
        out = json.loads(path.read_text(encoding="utf-8"))
        return out if isinstance(out, dict) else {}
    except (OSError, ValueError):
        return {}


_lock = threading.RLock()


# ================================================================== the teacher
def classes_dir() -> Path:
    return paths.VAR / "classes"


def class_dir(slug: str) -> Path:
    if not SLUG.match(slug or ""):
        raise ClassError(f"no class {slug!r}")
    return classes_dir() / slug


def list_classes() -> list[dict]:
    out = []
    d = classes_dir()
    for f in sorted(d.glob("*/class.json")) if d.exists() else []:
        c = _read_json(f)
        if c.get("id"):
            out.append({"slug": f.parent.name, "name": c.get("name", ""), "students": len(c.get("students", [])),
                        "assignments": len(c.get("assignments", [])), "created": c.get("created", 0)})
    return out


def load_class(slug: str) -> dict:
    _need_teacher()
    c = _read_json(class_dir(slug) / "class.json")
    if not c.get("id"):
        raise ClassError(f"no class {slug!r} (see `winlab class new`)")
    c["slug"] = slug
    return c


def _save_class(c: dict) -> None:
    _write_json(class_dir(c["slug"]) / "class.json", c)


def new_class(name: str, students: list[tuple[str, str]] | None = None) -> dict:
    """A new class, kept in ``var/classes/<slug>/``."""
    _need_teacher()
    name = _clean(name)
    if not name:
        raise ClassError("give the class a name, e.g. Networking 2B")
    base = slug_of(name)
    slug, n = base, 2
    while (classes_dir() / slug / "class.json").exists():
        slug, n = f"{base[:36]}-{n}", n + 1
    c = {"format": FORMAT, "id": secrets.token_hex(8), "key": secrets.token_hex(32), "name": name, "slug": slug,
         "created": time.time(), "students": [], "assignments": []}
    with _lock:
        _save_class(c)
        for s_name, sid in students or []:
            add_student(slug, s_name, sid)
    return load_class(slug)


def add_student(slug: str, name: str, sid: str = "") -> dict:
    with _lock:
        c = load_class(slug)
        name, sid = _clean(name), _clean(sid, 40)
        if not name:
            raise ClassError("give the student's name")
        if any(s["name"].lower() == name.lower() for s in c["students"]):
            raise ClassError(f"{name} is already on the roster: add a second initial to tell them apart")
        if len(c["students"]) >= MAX_STUDENTS:
            raise ClassError(f"a class holds at most {MAX_STUDENTS} students")
        key = secrets.token_hex(4)
        while any(s["key"] == key for s in c["students"]):
            key = secrets.token_hex(4)
        st = {"key": key, "name": name, "sid": sid}
        c["students"].append(st)
        _save_class(c)
        return st


def remove_student(slug: str, who: str) -> None:
    with _lock:
        c = load_class(slug)
        s = _student(c, who)
        c["students"] = [x for x in c["students"] if x["key"] != s["key"]]
        _save_class(c)


def _student(c: dict, who: str) -> dict:
    who = (who or "").strip()
    for s in c["students"]:
        if who in (s["key"], s["sid"]) and who or s["name"].lower() == who.lower():
            return s
    raise ClassError(f"no student {who!r} in {c['name']}")


def assign(slug: str, kind: str, ref: str, title: str = "", due: str = "", weight: int = 1,
           data: bytes | None = None) -> dict:
    """Assigns work: ``activity`` (``data`` is the .wlact file's bytes and
    ``ref`` its file name), ``lesson`` or ``exercise`` (``ref`` is its id)."""
    from . import activity
    with _lock:
        c = load_class(slug)
        if kind not in KINDS:
            raise ClassError(f"an assignment is an {', a '.join(KINDS)}")
        if len(c["assignments"]) >= MAX_ASSIGNMENTS:
            raise ClassError(f"a class has at most {MAX_ASSIGNMENTS} assignments")
        parse_due(due)
        if not 0 <= int(weight) <= 100:
            raise ClassError("an assignment's weight is 0 to 100")
        ref = (ref or "").strip()
        if kind == "activity":
            if not data:
                raise ClassError("give the activity file (.wlact)")
            try:
                _, rules, _ = activity.read(data)
            except activity.ActivityError as exc:
                raise ClassError(str(exc)) from None
            name = title or rules["title"]
            ref = Path(ref).name or f"{slug_of(rules['title'])}{activity.EXT}"
        elif kind == "lesson":
            from . import lessons
            try:
                name = title or lessons.load(ref).title
            except (lessons.LessonError, OSError, ValueError):
                raise ClassError(f"no lesson {ref!r} (see `winlab learn list`)") from None
        else:
            from . import exercises
            try:
                name = title or exercises.load(ref).title
            except (exercises.ExerciseError, OSError, ValueError):
                raise ClassError(f"no exercise {ref!r} (see `winlab exercise list`)") from None
        n = 1 + max([int(a["id"][1:]) for a in c["assignments"]] or [0])
        a = {"id": f"a{n}", "kind": kind, "ref": ref, "title": _clean(name, 120), "due": (due or "").strip(),
             "weight": int(weight)}
        if kind == "activity":
            _write(class_dir(slug) / "activities" / f"{a['id']}{activity.EXT}", data)
        c["assignments"].append(a)
        _save_class(c)
        return a


def rename_class(slug: str, name: str) -> dict:
    """A new name for the class (its folder and the students' files keep
    their id, so results already handed in still import)."""
    name = _clean(name)
    if not name:
        raise ClassError("give the class a name")
    with _lock:
        c = load_class(slug)
        c["name"] = name
        _save_class(c)
        return c


def delete_class(slug: str) -> None:
    """Deletes the class, its roster and every result imported into it."""
    import shutil
    with _lock:
        load_class(slug)
        shutil.rmtree(class_dir(slug), ignore_errors=True)


def edit_assignment(slug: str, aid: str, due: str | None = None, weight: int | None = None,
                    title: str | None = None) -> dict:
    """Moves an assignment's due date, changes its weight or its title."""
    with _lock:
        c = load_class(slug)
        a = next((x for x in c["assignments"] if x["id"] == aid), None)
        if a is None:
            raise ClassError(f"no assignment {aid!r}")
        if due is not None:
            parse_due(due)
            a["due"] = due.strip()
        if weight is not None:
            if not 0 <= int(weight) <= 100:
                raise ClassError("an assignment's weight is 0 to 100")
            a["weight"] = int(weight)
        if title is not None and _clean(title, 120):
            a["title"] = _clean(title, 120)
        _save_class(c)
        return a


def override(slug: str, who: str, aid: str, percent: object = None, feedback: str = "") -> dict:
    """The teacher's own grade for one cell (percent, or empty to go back to
    the graded score) and feedback for the student; both go in the CSV."""
    with _lock:
        c = load_class(slug)
        s = _student(c, who)
        if not any(a["id"] == aid for a in c["assignments"]):
            raise ClassError(f"no assignment {aid!r}")
        pct = None
        if percent not in (None, ""):
            pct = int(float(str(percent).rstrip("%")))
            if not 0 <= pct <= 100:
                raise ClassError("a grade is 0 to 100")
        cell = {"percent": pct, "feedback": _clean(feedback, 1000), "at": time.time()}
        book = c.setdefault("overrides", {}).setdefault(s["key"], {})
        if pct is None and not cell["feedback"]:
            book.pop(aid, None)
        else:
            book[aid] = cell
        _save_class(c)
        return cell


def unassign(slug: str, aid: str) -> None:
    with _lock:
        c = load_class(slug)
        if not any(a["id"] == aid for a in c["assignments"]):
            raise ClassError(f"no assignment {aid!r}")
        c["assignments"] = [a for a in c["assignments"] if a["id"] != aid]
        _save_class(c)


def export_class(slug: str) -> bytes:
    """The class file's bytes: the class, its roster (names only: student
    ids stay on the teacher's PC), its assignments and their activity
    files, and the key results are sealed with."""
    from . import activity
    c = load_class(slug)
    if not c["students"]:
        raise ClassError("add the students first: each picks their name when they open the class file")
    if not c["assignments"]:
        raise ClassError("assign some work first")
    info = {"format": FORMAT, "kind": "winlab-class", "id": c["id"], "name": c["name"], "key": c["key"],
            "issued": time.time(), "winlab": __version__,
            "students": [{"key": s["key"], "name": s["name"]} for s in c["students"]],
            "assignments": [{k: a[k] for k in ("id", "kind", "ref", "title", "due", "weight")}
                            for a in c["assignments"]]}
    parts = {CLASS: (json.dumps(info, indent=1) + "\n").encode()}
    for a in c["assignments"]:
        if a["kind"] == "activity":
            try:
                parts[f"{ACT_DIR}{a['id']}{activity.EXT}"] = (
                    class_dir(slug) / "activities" / f"{a['id']}{activity.EXT}").read_bytes()
            except OSError:
                raise ClassError(f"the activity file of {a['title']!r} is missing: assign it again") from None
    parts[SEAL] = _digest(_CLASS_SEAL, parts).encode()
    data = _zip(parts)
    if len(data) > MAX_FILE:
        raise ClassError("that class file would be far too big")
    c["exported"] = info["issued"]
    _save_class(c)
    return data


def read_class(data: bytes) -> tuple[dict, dict[str, bytes]]:
    """(the class, {assignment id: activity file bytes}) of a class file,
    checked whole."""
    parts = _unzip(data, CLASS, ACT_DIR, "winlab class file")
    if not hmac.compare_digest(parts[SEAL].decode("ascii", "replace").strip(), _digest(_CLASS_SEAL, parts)):
        raise ClassError("that class file has been changed since the teacher made it")
    info = _json(parts[CLASS], "class file")
    if info.get("kind") != "winlab-class":
        raise ClassError("that is not a winlab class file")
    if int(info.get("format", 0)) > FORMAT:
        raise ClassError("this class file was made by a newer winlab; update winlab to open it")
    if not CLASS_ID.match(str(info.get("id", ""))) or not re.fullmatch(r"[0-9a-f]{64}", str(info.get("key", ""))):
        raise ClassError("that class file is damaged")
    acts = {n[len(ACT_DIR):].split(".")[0]: b for n, b in parts.items() if n.startswith(ACT_DIR)}
    return info, acts


# ------------------------------------------------------------------ importing results
def _results_dir(slug: str) -> Path:
    return class_dir(slug) / "results"


def verify_result(c: dict, data: bytes) -> tuple[dict, dict[str, bytes]]:
    """(the result, its networks) of a result file for class ``c``, or
    ClassError with the reason it is refused."""
    parts = _unzip(data, RESULT, NET_DIR, "winlab result file")
    res = _json(parts[RESULT], "result file")
    if res.get("kind") != "winlab-result":
        raise ClassError("that is not a winlab result file")
    if res.get("class_id") != c["id"]:
        raise ClassError(f"it is for another class ({_clean(res.get('class_name')) or 'unknown'}), "
                         f"not {c['name']}")
    if not hmac.compare_digest(parts[SEAL].decode("ascii", "replace").strip(),
                               _digest(_result_key(c["key"]), parts)):
        raise ClassError("it has been changed since the student handed it in (its seal does not match)")
    if int(res.get("format", 0)) > FORMAT:
        raise ClassError("it was made by a newer winlab; update winlab to read it")
    who = res.get("student") or {}
    if not any(s["key"] == who.get("key") for s in c["students"]):
        raise ClassError(f"{_clean(who.get('name')) or 'the student'} is not on the roster of {c['name']}")
    if not isinstance(res.get("assignments"), list):
        raise ClassError("that result file is damaged")
    return res, {n[len(NET_DIR):].split(".")[0]: b for n, b in parts.items() if n.startswith(NET_DIR)}


def _regrade(slug: str, aid: str, net: bytes, claimed: dict) -> str:
    """Grades the activity network a student handed in against the
    activity's target, on the teacher's PC. '' when it agrees with the
    items the result claims, else what does not."""
    from . import activity, netfile
    try:
        _, rules, target = activity.read((class_dir(slug) / "activities" / f"{aid}{activity.EXT}").read_bytes())
        _, raw = netfile.read(net)
        lab = activity._from_raw(raw, "regrade-" + aid)
        g = activity.grade(lab, rules, target, {})
    except Exception as exc:  # noqa: BLE001 - a network that does not load is itself the finding
        return f"the network handed in could not be graded again ({exc})"
    said = {x.get("id"): bool(x.get("ok")) for x in claimed.get("items", []) if x.get("kind") == "network"}
    have = {x["id"]: x["ok"] for x in g["items"]}
    wrong = [k for k in have if said.get(k, False) != have[k]]
    if wrong:
        return (f"the network handed in scores {sum(1 for v in have.values() if v)} of {len(have)} network items "
                f"on this PC; the result claims {sum(1 for v in said.values() if v)}")
    return ""


def import_results(slug: str, files: list[tuple[str, bytes]], now: float | None = None) -> list[dict]:
    """Imports result files: one line per file, imported or refused (and
    why). Imported files are kept in ``var/classes/<class>/results/``."""
    c = load_class(slug)
    now = time.time() if now is None else now
    out = []
    for name, data in files:
        try:
            res, nets = verify_result(c, data)
        except ClassError as exc:
            out.append({"file": name, "ok": False, "reason": str(exc)})
            continue
        who = res["student"]["key"]
        sha = hashlib.sha256(data).hexdigest()[:10]
        dest = _results_dir(slug) / who / f"{int(float(res.get('handed_in') or 0))}-{sha}{RESULT_EXT}"
        again = dest.exists()
        flags = []
        for a in res["assignments"]:
            if a.get("id") in nets and isinstance(a, dict):
                why = _regrade(slug, a["id"], nets[a["id"]], a)
                if why:
                    flags.append(f"{_clean(a.get('title'), 120)}: {why}")
        handed = float(res.get("handed_in") or 0)
        if handed > now + CLOCK_SLACK:
            flags.append("its hand-in time is later than this PC's clock: the student's clock is ahead")
        if handed and handed < float(res.get("class_issued") or 0) - CLOCK_SLACK:
            flags.append("its hand-in time is before the class file was made: the student's clock is wrong")
        with _lock:
            if not again:
                _write(dest, data)
            meta = _read_json(class_dir(slug) / "imports.json")
            meta.setdefault(dest.name, {"imported": now, "flags": flags, "file": name})
            _write_json(class_dir(slug) / "imports.json", meta)
        out.append({"file": name, "ok": True, "student": _student(c, who)["name"], "again": again,
                    "handed_in": handed, "flags": flags,
                    "reason": "already imported" if again else ""})
    return out


def import_paths(slug: str, items: list[str | Path]) -> list[dict]:
    """import_results for files and folders on disk (a folder: every
    .wlresult in it and below)."""
    files: list[tuple[str, bytes]] = []
    for p in items:
        p = Path(p).expanduser()
        found = sorted(p.rglob(f"*{RESULT_EXT}")) if p.is_dir() else [p]
        for f in found:
            try:
                files.append((f.name, f.read_bytes()))
            except OSError as exc:
                files.append((f"{f.name} ({exc.strerror or exc})", b""))
    return import_results(slug, files)


def _latest(slug: str, c: dict) -> dict[str, tuple[dict, dict]]:
    """Each student's newest result: {student key: (result, import note)}."""
    out: dict[str, tuple[dict, dict]] = {}
    meta = _read_json(class_dir(slug) / "imports.json")
    base = _results_dir(slug)
    for s in c["students"]:
        best = None
        for f in sorted((base / s["key"]).glob(f"*{RESULT_EXT}")) if (base / s["key"]).exists() else []:
            try:
                res, _ = verify_result(c, f.read_bytes())
            except (ClassError, OSError):
                continue
            if best is None or float(res.get("handed_in") or 0) >= float(best[0].get("handed_in") or 0):
                best = (res, meta.get(f.name, {}))
        if best:
            out[s["key"]] = best
    return out


def gradebook(slug: str, now: float | None = None) -> dict:
    """Students by assignments: each cell the score handed in (the newest
    result of each student), late or missing; each student's weighted
    total; and the flags the import raised."""
    c = load_class(slug)
    now = time.time() if now is None else now
    latest = _latest(slug, c)
    machines: dict[str, list[str]] = {}
    for key, (res, _) in latest.items():
        machines.setdefault(str(res.get("machine", "")), []).append(key)
    rows = []
    overrides = c.get("overrides") or {}
    for s in c["students"]:
        res, note = latest.get(s["key"], ({}, {}))
        got = {a.get("id"): a for a in res.get("assignments", []) if isinstance(a, dict)}
        cells, wsum, wtot = {}, 0.0, 0
        mine = overrides.get(s["key"]) or {}
        teacher = False   # a grade the teacher gave without a hand-in still makes a total
        for a in c["assignments"]:
            due = parse_due(a["due"])
            r = got.get(a["id"])
            w = int(a.get("weight", 1))
            wtot += w
            ov = mine.get(a["id"]) or {}
            if not r or r.get("status") == "not started":
                cells[a["id"]] = {"status": "not started" if r else "none", "percent": ov.get("percent"),
                                  "missing": bool(due and now > due) and ov.get("percent") is None, "late": False,
                                  "override": ov.get("percent") is not None, "feedback": ov.get("feedback", "")}
                if ov.get("percent") is not None:
                    wsum += w * int(ov["percent"])
                    teacher = True
                continue
            pct = int(r.get("percent") or 0)
            auto = pct
            if ov.get("percent") is not None:
                pct = int(ov["percent"])
            wsum += w * pct
            sub = float(r.get("submitted") or res.get("handed_in") or 0)
            cells[a["id"]] = {"status": r.get("status", ""), "percent": pct, "earned": r.get("earned", 0),
                              "total": r.get("total", 0), "submitted": sub, "late": bool(due and sub > due),
                              "missing": False, "seconds": int(r.get("seconds") or 0),
                              "override": ov.get("percent") is not None, "auto": auto, "feedback": ov.get("feedback", "")}
        same = [k for k in machines.get(str(res.get("machine", "")), []) if k != s["key"]] if res else []
        flags = list(note.get("flags", []))
        if same:
            flags.append("handed in from the same PC as " + ", ".join(_student(c, k)["name"] for k in same))
        rows.append({"key": s["key"], "name": s["name"], "sid": s.get("sid", ""), "cells": cells,
                     "handed_in": float(res.get("handed_in") or 0) if res else 0.0,
                     "imported": float(note.get("imported") or 0), "flags": flags,
                     "total": round(wsum / wtot) if (res or teacher) and wtot else None})
    return {"ok": True, "slug": slug, "id": c["id"], "name": c["name"], "students": rows,
            "assignments": [{**a, "due_at": parse_due(a["due"])} for a in c["assignments"]],
            "exported": c.get("exported", 0)}


def breakdown(slug: str, who: str, aid: str) -> dict:
    """One student's assignment item by item, with the evidence."""
    c = load_class(slug)
    s = _student(c, who)
    res = _latest(slug, c).get(s["key"], ({}, {}))[0]
    a = next((x for x in res.get("assignments", []) if isinstance(x, dict) and x.get("id") == aid), None)
    meta = next((x for x in c["assignments"] if x["id"] == aid), None)
    if meta is None:
        raise ClassError(f"no assignment {aid!r}")
    return {"ok": True, "student": s["name"], "assignment": meta, "handed": bool(a), "result": a or {},
            "handed_in": res.get("handed_in", 0), "winlab": res.get("winlab", ""), "machine": res.get("machine", "")}


def to_csv(slug: str, now: float | None = None) -> str:
    """The gradebook as CSV: one row per student, a score column per
    assignment (empty when nothing was handed in) and its status, then the
    weighted total."""
    g = gradebook(slug, now)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    head = ["Student", "Student ID"]
    for a in g["assignments"]:
        head += [f"{a['title']} (%)", f"{a['title']} status", f"{a['title']} feedback"]
    w.writerow(head + ["Total (%)", "Handed in", "Notes"])
    for r in g["students"]:
        row = [r["name"], r["sid"]]
        for a in g["assignments"]:
            cell = r["cells"][a["id"]]
            st = ("late" if cell["late"] else "missing" if cell["missing"] else
                  "not handed in" if cell["percent"] is None else "on time")
            if cell.get("override"):
                st += ", grade set by the teacher"
            row += ["" if cell["percent"] is None else cell["percent"], st, cell.get("feedback", "")]
        row += ["" if r["total"] is None else r["total"], _when(r["handed_in"]), "; ".join(r["flags"])]
        w.writerow(row)
    return buf.getvalue()


# ================================================================== the student
def classwork_dir() -> Path:
    return paths.VAR / "classwork"


def _cw(cid: str) -> Path:
    if not CLASS_ID.match(cid or ""):
        raise ClassError("no such class here")
    return classwork_dir() / cid


def _st(cid: str) -> dict:
    return _read_json(_cw(cid) / "state.json")


def _save_st(cid: str, st: dict) -> None:
    _write_json(_cw(cid) / "state.json", st)


def joined_classes() -> list[dict]:
    out = []
    d = classwork_dir()
    for f in sorted(d.glob(f"*/class{CLASS_EXT}")) if d.exists() else []:
        try:
            info, _ = read_class(f.read_bytes())
        except (ClassError, OSError):
            continue
        out.append({"id": info["id"], "name": info["name"], "student": _st(info["id"]).get("student", "")})
    return out


def current() -> str:
    cid = _read_json(classwork_dir() / "current.json").get("id", "")
    return cid if CLASS_ID.match(cid) and (classwork_dir() / cid / f"class{CLASS_EXT}").exists() else ""


def set_current(cid: str) -> None:
    _cw(cid)
    _write_json(classwork_dir() / "current.json", {"id": cid})


def open_class(data: bytes) -> dict:
    """A class file the student opened: kept in ``var/classwork/<id>/``
    and made the current class. Opening a newer copy of the same class
    (the teacher added work) keeps what the student did."""
    info, _ = read_class(data)
    with _lock:
        _write(_cw(info["id"]) / f"class{CLASS_EXT}", data)
        st = _st(info["id"])
        if st.get("student") and not any(s["key"] == st["student"] for s in info["students"]):
            st.pop("student")
        st.setdefault("opened", time.time())
        _save_st(info["id"], st)
        set_current(info["id"])
    return info


def _info(cid: str) -> tuple[dict, dict[str, bytes]]:
    try:
        return read_class((_cw(cid) / f"class{CLASS_EXT}").read_bytes())
    except OSError:
        raise ClassError("open your class file first (the teacher hands it out)") from None


def pick_student(cid: str, key: str) -> dict:
    info, _ = _info(cid)
    s = next((s for s in info["students"] if s["key"] == key or s["name"].lower() == (key or "").lower()), None)
    if not s:
        raise ClassError(f"{key!r} is not on the roster of {info['name']}: ask your teacher")
    with _lock:
        st = _st(cid)
        st["student"] = s["key"]
        _save_st(cid, st)
    return s


# grades of exercises, as Check my work ran them (any lab, any class)
def _grades_file() -> Path:
    return classwork_dir() / "grades.json"


def note_grade(exercise_id: str, g, lab_name: str = "") -> None:
    """Remembers an exercise's grading with each check's result and the
    output it read inside the machine: the newest and the best run. Called
    by the desktop whenever Check my work runs."""
    run = {"at": time.time(), "percent": int(g.percent), "earned": int(g.earned), "total": int(g.total),
           "passed": bool(g.passed), "lab": lab_name,
           "results": [{"name": r.check.name, "node": r.check.node, "passed": bool(r.passed),
                        "detail": str(r.detail)[:300], "weight": int(r.check.weight)} for r in g.results]}
    with _lock:
        log = _read_json(_grades_file())
        e = log.setdefault(exercise_id, {})
        e["last"] = run
        if not e.get("best") or run["percent"] >= int(e["best"].get("percent") or 0):
            e["best"] = run
        _write_json(_grades_file(), log)


def _exercise_items(run: dict) -> list[dict]:
    return [{"id": f"check:{i}", "kind": "inside", "label": r["name"], "points": r["weight"], "ok": r["passed"],
             "detail": r["detail"], "node": r["node"]} for i, r in enumerate(run.get("results", []))]


def assess(cid: str, a: dict, st: dict, acts: dict[str, bytes], now: float | None = None,
           with_network: bool = False) -> tuple[dict, bytes | None]:
    """One assignment as the student stands now: status, score, the items
    one by one with the evidence, the time spent. With ``with_network``,
    an activity's network as it is, for the result file."""
    from . import progress
    now = time.time() if now is None else now
    mine = (st.get("work") or {}).get(a["id"], {})
    out = {"id": a["id"], "kind": a["kind"], "ref": a["ref"], "title": a["title"], "due": a["due"],
           "status": "not started", "percent": 0, "earned": 0, "total": 0, "items": [], "evidence": [],
           "started": float(mine.get("started") or 0), "finished": 0.0, "seconds": 0}
    net = None
    if a["kind"] == "activity":
        from . import activity, history, netfile, schema
        lab_name = mine.get("lab", "")
        if not lab_name:
            return out, None
        try:
            lab = schema.load(lab_name)
            s = activity.status(lab, now)
        except Exception as exc:  # noqa: BLE001 - the lab was deleted or does not load
            out["status"] = "started"
            out["evidence"].append(f"the activity's network {lab_name} could not be read: {exc}")
            return out, None
        ast = activity._load_state(lab.name)
        g = ast.get("final") or ast.get("last") or {}
        out["percent"], out["earned"], out["total"] = s.get("percent", 0), s.get("earned", 0), s.get("total", 0)
        out["items"] = ([{"id": x["id"], "kind": "network", "label": x["label"], "points": x["points"], "ok": x["ok"]}
                         for x in g.get("items", [])]
                        + [{"id": f"guest:{x['n']}", "kind": "inside", "label": x["label"], "points": x["points"],
                            "ok": x["ok"], "detail": x.get("detail", ""), "checked": x.get("checked", 0)}
                           for x in g.get("guest", [])])
        out["started"] = float(s.get("started") or out["started"])
        if s.get("final") or (out["total"] and out["earned"] == out["total"]):
            out["status"] = "done"
            limit = int(s.get("time_limit_min") or 0) * 60
            out["finished"] = float(ast.get("handed_in") or (out["started"] + limit if limit and s.get("over") else now))
        else:
            out["status"] = "started"
        out["seconds"] = int((out["finished"] or now) - out["started"])
        trail = history.since(lab.name, out["started"])
        out["evidence"].append(f"{len(trail)} changes to the network since the activity was opened"
                               + (f", the last at {trail[-1]['t']}" if trail else ""))
        for x in g.get("guest", []):
            if x.get("checked"):
                out["evidence"].append(f"inside the machines, {_when(x['checked'])}: {x['label']}: "
                                       + ("passed" if x["ok"] else f"not yet ({x.get('detail', '')})"))
        if with_network:
            net = netfile.dumps(lab, f"handed in for {a['title']}")
        return out, net
    grades = _read_json(_grades_file())
    prog = progress.load()
    if a["kind"] == "lesson":
        from . import lessons
        try:
            lesson = lessons.load(a["ref"])
        except (lessons.LessonError, OSError, ValueError):
            out["evidence"].append(f"this winlab has no lesson {a['ref']}: update winlab")
            return out, None
        e = prog["lessons"].get(lesson.id) or {}
        ex = lesson.exercise
        run = (grades.get(ex) or {}).get("best") if ex else None
        if ex:
            out["items"] = _exercise_items(run or {})
            out["percent"] = max(int(e.get("best") or 0), int((run or {}).get("percent") or 0))
            out["earned"], out["total"] = (run or {}).get("earned", 0), (run or {}).get("total", 0)
        else:
            ticked = set(int(i) for i in e.get("steps") or [])
            out["items"] = [{"id": f"step:{i}", "kind": "step", "label": f"Step {i + 1}: {_clean(t, 90)}",
                             "points": 1, "ok": i in ticked} for i, t in enumerate(lesson.steps)]
            out["earned"], out["total"] = len(ticked & set(range(len(lesson.steps)))), len(lesson.steps)
            out["percent"] = 100 if e.get("status") == progress.STATUS_DONE else (
                round(100 * out["earned"] / out["total"]) if out["total"] else 0)
        if lesson.quiz:
            tot = int(e.get("quiz_total") or len(lesson.quiz))
            out["items"].append({"id": "quiz", "kind": "quiz", "points": 0, "ok": int(e.get("quiz_best") or 0) >= tot,
                                 "label": f"Recall questions: best {int(e.get('quiz_best') or 0)} of {tot}"
                                          + (f" in {e['quiz_tries']} tries" if e.get("quiz_tries") else "")})
        status = e.get("status", progress.STATUS_NEW)
        out["status"] = ("done" if status == progress.STATUS_DONE else
                         "started" if status == progress.STATUS_STARTED or run or out["started"] else "not started")
        out["finished"] = float(e.get("passed_at") or 0) if out["status"] == "done" else 0.0
        if not out["started"]:
            out["started"] = float((run or {}).get("at") or e.get("updated") or 0) if out["status"] != "not started" else 0
    else:
        e = grades.get(a["ref"]) or {}
        run = e.get("best")
        if run:
            out["items"] = _exercise_items(run)
            out["percent"], out["earned"], out["total"] = run["percent"], run["earned"], run["total"]
            out["status"] = "done" if run.get("passed") else "started"
            out["finished"] = float(run["at"]) if run.get("passed") else 0.0
            out["started"] = out["started"] or float(run["at"])
        elif out["started"]:
            out["status"] = "started"
    if a["kind"] in ("lesson", "exercise") and run:
        out["evidence"].append(f"graded {_when(run['at'])} on lab {run.get('lab') or '?'}: {run['percent']}%"
                               + (f" (the newest run: {_when(e['last']['at'])}, {e['last']['percent']}%)"
                                  if a["kind"] == "exercise" and e.get("last") and e["last"]["at"] != run["at"] else ""))
        for r in run.get("results", []):
            out["evidence"].append(f"{r['node']}: {r['name']}: {'passed' if r['passed'] else 'not passed'}"
                                   + (f", the machine said: {r['detail']}" if r.get("detail") else ""))
    if out["started"]:
        out["seconds"] = max(0, int((out["finished"] or now) - out["started"]))
    return out, None


def classwork(cid: str = "", now: float | None = None) -> dict:
    """What the Classwork window shows."""
    cid = cid or current()
    if not cid:
        return {"ok": True, "class": False, "joined": joined_classes()}
    info, acts = _info(cid)
    st = _st(cid)
    me = next((s for s in info["students"] if s["key"] == st.get("student")), None)
    now = time.time() if now is None else now
    rows = []
    handed = st.get("handed") or {}
    for a in info["assignments"]:
        if me:
            r, _ = assess(cid, a, st, acts, now)
        else:
            r = {"status": "not started", "percent": 0, "items": [], "evidence": [], "seconds": 0}
        due = parse_due(a["due"])
        h = handed.get(a["id"])
        rows.append({**{k: a[k] for k in ("id", "kind", "ref", "title", "due", "weight")}, "due_at": due,
                     "overdue": bool(due and now > due), "status": r["status"], "percent": r["percent"],
                     "items": r["items"], "seconds": r["seconds"], "lab": (st.get("work") or {}).get(a["id"], {}).get("lab", ""),
                     "handed": h or None})
    return {"ok": True, "class": True, "id": cid, "name": info["name"], "issued": info.get("issued", 0),
            "students": [{"key": s["key"], "name": s["name"]} for s in info["students"]],
            "me": me, "assignments": rows, "handins": st.get("handins", [])[-5:], "joined": joined_classes()}


def start(cid: str, aid: str) -> dict:
    """The student starts (or goes back to) an assignment. An activity's
    starting network becomes a lab the first time; a lesson or exercise
    only has its start time noted. Returns what to open."""
    from . import activity, schema
    info, acts = _info(cid)
    a = next((x for x in info["assignments"] if x["id"] == aid), None)
    if a is None:
        raise ClassError(f"no assignment {aid!r} in {info['name']}")
    with _lock:
        st = _st(cid)
        if not st.get("student"):
            raise ClassError("pick your name first")
        mine = st.setdefault("work", {}).setdefault(aid, {})
        if a["kind"] == "activity":
            lab_name = mine.get("lab", "")
            exists = False
            if lab_name:
                try:
                    schema.load(lab_name)
                    exists = activity.is_activity(lab_name)
                except Exception:  # noqa: BLE001 - deleted since: open it again
                    exists = False
            if not exists:
                if aid not in acts:
                    raise ClassError("the class file is missing that activity: ask your teacher for a new copy")
                try:
                    lab = activity.open_bytes(acts[aid])
                except activity.ActivityError as exc:
                    raise ClassError(str(exc)) from None
                mine["lab"], mine["started"] = lab.name, time.time()
            _save_st(cid, st)
            return {"ok": True, "kind": "activity", "lab": mine["lab"], "title": a["title"]}
        mine.setdefault("started", time.time())
        _save_st(cid, st)
    lesson = a["ref"] if a["kind"] == "lesson" else ""
    lab = ""
    if a["kind"] == "exercise":
        from . import exercises, lessons
        lesson = next((l.id for l in lessons.list_available() if l.exercise == a["ref"]), "")
        try:
            lab = exercises.load(a["ref"]).lab
        except (exercises.ExerciseError, OSError):
            lab = ""
    elif lesson:
        from . import lessons
        try:
            lab = lessons.load(lesson).lab
        except (lessons.LessonError, OSError):
            lab = ""
    return {"ok": True, "kind": a["kind"], "lesson": lesson, "exercise": a["ref"] if a["kind"] == "exercise" else "",
            "lab": lab, "title": a["title"]}


def hand_in(cid: str = "", now: float | None = None) -> tuple[str, bytes, dict]:
    """The result file of everything done so far: (file name, bytes,
    summary). A score that changed since the last hand-in is stamped with
    this hand-in's time; one that did not keeps its earlier time, so work
    finished before the due date stays on time if handed in again later."""
    from . import licensing
    cid = cid or current()
    info, acts = _info(cid)
    now = time.time() if now is None else now
    with _lock:
        st = _st(cid)
        me = next((s for s in info["students"] if s["key"] == st.get("student")), None)
        if not me:
            raise ClassError("pick your name first")
        handed = st.setdefault("handed", {})
        rows, nets = [], {}
        for a in info["assignments"]:
            r, net = assess(cid, a, st, acts, now, with_network=True)
            prev = handed.get(a["id"])
            same = prev and prev.get("percent") == r["percent"] and prev.get("status") == r["status"]
            r["submitted"] = float(prev["submitted"]) if same else (now if r["status"] != "not started" else 0.0)
            if r["status"] != "not started":
                handed[a["id"]] = {"percent": r["percent"], "status": r["status"], "submitted": r["submitted"]}
            r["evidence"] = r["evidence"][:60]
            rows.append(r)
            if net:
                nets[a["id"]] = net
        try:
            fp = licensing.fingerprint()
        except Exception:  # noqa: BLE001 - no machine id: the hash says so
            fp = "unknown"
        res = {"format": FORMAT, "kind": "winlab-result", "class_id": info["id"], "class_name": info["name"],
               "class_issued": info.get("issued", 0), "student": {"key": me["key"], "name": me["name"]},
               "handed_in": now, "handed_in_text": _when(now), "tz_offset_min": int(-time.timezone / 60),
               "winlab": __version__, "machine": hashlib.sha256(f"winlab class|{info['id']}|{fp}".encode()).hexdigest()[:24],
               "handins_before": len(st.get("handins", [])), "assignments": rows}
        parts = {RESULT: (json.dumps(res, indent=1) + "\n").encode()}
        for aid, net in nets.items():
            parts[f"{NET_DIR}{aid}.wlnet"] = net
        parts[SEAL] = _digest(_result_key(info["key"]), parts).encode()
        data = _zip(parts)
        if len(data) > MAX_FILE:
            raise ClassError("the result would be far too big")
        name = f"{slug_of(info['name'])}-{slug_of(me['name'])}-{time.strftime('%Y%m%d-%H%M', time.localtime(now))}{RESULT_EXT}"
        _write(_cw(cid) / "handins" / name, data)
        st.setdefault("handins", []).append({"at": now, "file": name})
        _save_st(cid, st)
    done = sum(1 for r in rows if r["status"] == "done")
    summary = {"file": name, "path": str(_cw(cid) / "handins" / name), "student": me["name"], "class": info["name"],
               "at": now, "done": done, "count": len(rows),
               "rows": [{"title": r["title"], "status": r["status"], "percent": r["percent"],
                         "late": bool(parse_due(r["due"]) and r["submitted"] > parse_due(r["due"]))} for r in rows]}
    return name, data, summary


def check_work(dash, cid: str, aid: str) -> dict:
    """Check my work, from the Classwork window, for a lesson's or an
    exercise's graded checks (the desktop's own grading, which notes the
    result here)."""
    from . import exercises, lessons
    info, _ = _info(cid)
    a = next((x for x in info["assignments"] if x["id"] == aid), None)
    if a is None or a["kind"] == "activity":
        raise ClassError("an activity is scored in its own Activity window as you build")
    if a["kind"] == "lesson":
        lesson = lessons.load(a["ref"])
        if not lesson.exercise:
            raise ClassError("this lesson has no graded checks: tick its steps in the Lab guide as you do them")
        ex_id, les_id = lesson.exercise, lesson.id
    else:
        ex_id, les_id = a["ref"], ""
    ex = exercises.load(ex_id)
    if ex.lab and ex.lab != dash.lab.name:
        raise ClassError(f"this is graded on the lab {ex.lab}: switch the desktop to it (Start > Labs) first")
    with _lock:
        st = _st(cid)
        st.setdefault("work", {}).setdefault(aid, {}).setdefault("started", time.time())
        _save_st(cid, st)
    return dash._grade(ex_id, lesson_id=les_id)


# ================================================================== the desktop
def act(dash, action: str, params: dict) -> dict:
    """class-* actions of the desktop's two windows."""
    try:
        p = params
        if action == "class-work":
            return classwork(str(p.get("id") or ""))
        if action == "class-pick":
            s = pick_student(str(p.get("id") or current()), str(p.get("student", "")))
            return {"ok": True, "message": f"signed in to the class as {s['name']}"}
        if action == "class-switch":
            set_current(str(p.get("id", "")))
            return {"ok": True, "message": "switched class"}
        if action == "class-start":
            return start(str(p.get("id") or current()), str(p.get("aid", "")))
        if action == "class-check":
            return check_work(dash, str(p.get("id") or current()), str(p.get("aid", "")))
        # the teacher's
        _need_teacher()
        if action == "class-list":
            from . import exercises, lessons
            return {"ok": True, "classes": list_classes(),
                    "lessons": [{"id": l.id, "title": l.title} for l in lessons.list_available()],
                    "exercises": [{"id": e.id, "title": e.title} for e in exercises.list_available()]}
        if action == "class-new":
            c = new_class(str(p.get("name", "")))
            return {"ok": True, "slug": c["slug"], "message": f"made the class {c['name']}"}
        slug = str(p.get("slug", ""))
        if action == "class-book":
            return gradebook(slug)
        if action == "class-detail":
            return breakdown(slug, str(p.get("student", "")), str(p.get("aid", "")))
        if action == "class-roster":
            c = load_class(slug)
            return {"ok": True, "students": c["students"], "assignments": c["assignments"], "name": c["name"]}
        if action == "class-add-student":
            names = [x for x in re.split(r"[\r\n]+", str(p.get("name", ""))) if x.strip()]
            for line in names:
                bits = [b.strip() for b in line.split(",", 1)] if "," in line else [line, ""]
                add_student(slug, bits[0], str(p.get("sid", "")) if len(names) == 1 and p.get("sid") else bits[1])
            return {"ok": True, "message": f"added {len(names)} student{'s' if len(names) != 1 else ''}"}
        if action == "class-remove-student":
            remove_student(slug, str(p.get("student", "")))
            return {"ok": True, "message": "removed from the roster"}
        if action == "class-assign":
            a = assign(slug, str(p.get("kind", "")), str(p.get("ref", "")), str(p.get("title", "")),
                       str(p.get("due", "")), int(p.get("weight") or 1))
            return {"ok": True, "message": f"assigned {a['title']}"}
        if action == "class-rename":
            c = rename_class(slug, str(p.get("name", "")))
            return {"ok": True, "message": f"the class is now {c['name']}"}
        if action == "class-delete":
            delete_class(slug)
            return {"ok": True, "message": "class deleted"}
        if action == "class-edit-assignment":
            a = edit_assignment(slug, str(p.get("aid", "")),
                                due=None if p.get("due") is None else str(p.get("due")),
                                weight=None if p.get("weight") in (None, "") else int(p.get("weight")),
                                title=None if p.get("title") is None else str(p.get("title")))
            return {"ok": True, "message": f"{a['title']}: saved"}
        if action == "class-override":
            override(slug, str(p.get("student", "")), str(p.get("aid", "")), p.get("percent"), str(p.get("feedback", "")))
            return {"ok": True, "message": "grade saved"}
        if action == "class-unassign":
            unassign(slug, str(p.get("aid", "")))
            return {"ok": True, "message": "assignment removed"}
    except (ClassError, OSError, ValueError, KeyError) as exc:
        return {"ok": False, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - lessons/exercises errors surface as messages
        if type(exc).__name__ in ("LessonError", "ExerciseError", "ActivityError"):
            return {"ok": False, "message": str(exc)}
        raise
    return {"ok": False, "message": f"unknown class action {action!r}"}


def _send_file(handler, data: bytes, name: str, ctype: str, extra: dict | None = None) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Disposition", f'attachment; filename="{name}"')
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    for k, v in (extra or {}).items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(data)


def http_post(handler, path: str, q: dict, length: int) -> None:
    """POST /api/class/open (a class file's bytes), /handin (the result
    file comes back), /import?slug=&name= (one result file's bytes), and
    /assign-activity?slug=&name=&title=&due=&weight= (a .wlact's bytes);
    /export?slug= and /csv?slug= send the class file and the CSV."""
    if length > MAX_FILE:
        handler.close_connection = True
        handler._json({"ok": False, "message": "that file is far too big"}, 400)
        return
    body = handler.rfile.read(length) if length else b""
    arg = lambda k: (q.get(k) or [""])[0]  # noqa: E731
    try:
        if path == "/api/class/open":
            info = open_class(body)
            handler._json({"ok": True, "message": f"opened the class {info['name']}: pick your name"})
            return
        if path == "/api/class/handin":
            name, data, summary = hand_in(arg("id"))
            _send_file(handler, data, name, "application/octet-stream",
                       {"X-Winlab-Summary": json.dumps(summary, ensure_ascii=True)})
            return
        _need_teacher()
        slug = arg("slug")
        if path == "/api/class/import":
            handler._json({"ok": True, "results": import_results(slug, [(arg("name") or "result", body)])})
            return
        if path == "/api/class/assign-activity":
            a = assign(slug, "activity", arg("name"), arg("title"), arg("due"), int(arg("weight") or 1), body)
            handler._json({"ok": True, "message": f"assigned {a['title']}"})
            return
        if path == "/api/class/export":
            data = export_class(slug)
            _send_file(handler, data, f"{slug}{CLASS_EXT}", "application/octet-stream")
            return
        if path == "/api/class/csv":
            data = to_csv(slug).encode("utf-8-sig")
            _send_file(handler, data, f"{slug}-grades.csv", "text/csv; charset=utf-8")
            return
        handler._json({"ok": False, "message": "not found"}, 404)
    except (ClassError, ValueError, OSError) as exc:
        handler._json({"ok": False, "message": str(exc)})


# ================================================================== the CLI
def add_cli(sub) -> None:
    p = sub.add_parser("class", help="classes: a roster, assigned work, hand-ins and the gradebook (no server)")
    cs = p.add_subparsers(dest="classcmd", metavar="<op>")
    n = cs.add_parser("new", help="make a class (teacher)")
    n.add_argument("name")
    n.add_argument("--students", default="", help="names to add, comma-separated")
    s = cs.add_parser("add-student", help="add a student to a class's roster (teacher)")
    s.add_argument("klass", metavar="class")
    s.add_argument("name")
    s.add_argument("--id", dest="sid", default="", help="the school's student id (stays on this PC)")
    a = cs.add_parser("assign", help="assign an activity file, a lesson or an exercise (teacher)")
    a.add_argument("klass", metavar="class")
    a.add_argument("kind", choices=list(KINDS))
    a.add_argument("ref", help="the .wlact file, or the lesson or exercise id")
    a.add_argument("--title", default="")
    a.add_argument("--due", default="", help="YYYY-MM-DD (the end of that day) or YYYY-MM-DD HH:MM")
    a.add_argument("--weight", type=int, default=1, help="its weight in the total (default 1)")
    e = cs.add_parser("export", help="write the class file (.wlclass) to hand out (teacher)")
    e.add_argument("klass", metavar="class")
    e.add_argument("dest", nargs="?", default=".")
    o = cs.add_parser("open", help="open a class file on a student's PC")
    o.add_argument("file")
    o.add_argument("--student", default="", help="your name as on the roster")
    st = cs.add_parser("start", help="start an assignment (student)")
    st.add_argument("assignment", help="its id (a1, a2...) as `winlab class open` lists them")
    st.add_argument("--class", dest="cid", default="")
    h = cs.add_parser("handin", help="hand in: write the result file (.wlresult) for the teacher (student)")
    h.add_argument("dest", nargs="?", default=".")
    h.add_argument("--class", dest="cid", default="")
    i = cs.add_parser("import", help="import result files or folders of them (teacher)")
    i.add_argument("klass", metavar="class")
    i.add_argument("files", nargs="+")
    g = cs.add_parser("grades", help="the gradebook; with --student, that student's items (teacher)")
    g.add_argument("klass", metavar="class")
    g.add_argument("--student", default="")
    c = cs.add_parser("csv", help="the gradebook as CSV for the school's gradebook (teacher)")
    c.add_argument("klass", metavar="class")
    c.add_argument("dest", nargs="?", default="-", help="a file (default: print it)")
    cs.add_parser("list", help="the classes on this PC: made here, and opened here")


def _render_work(v: dict) -> str:
    if not v.get("class"):
        return "no class opened on this PC: winlab class open <file.wlclass>"
    lines = [f"{v['name']}" + (f"  (you are {v['me']['name']})" if v.get("me") else "  (pick your name: --student)"), ""]
    for a in v["assignments"]:
        due = f"due {a['due']}" if a["due"] else "no due date"
        lines.append(f"  {a['id']:<4} {KINDS[a['kind']]:<9} {a['title'][:44]:<44} {due:<20} "
                     f"{a['status']:<12} {a['percent']}%")
    return "\n".join(lines)


def _render_book(g: dict) -> str:
    cols = g["assignments"]
    lines = [f"{g['name']}: {len(g['students'])} students, {len(cols)} assignments", ""]
    lines.append(f"{'student':<24}" + "".join(f"{a['id']:>9}" for a in cols) + f"{'total':>8}")
    for r in g["students"]:
        cells = ""
        for a in cols:
            c = r["cells"][a["id"]]
            t = "-" if c["percent"] is None else f"{c['percent']}%"
            t += " L" if c["late"] else " M" if c["missing"] else "  "
            cells += f"{t:>9}"
        lines.append(f"{r['name'][:23]:<24}{cells}{('-' if r['total'] is None else str(r['total']) + '%'):>8}")
        for f in r["flags"]:
            lines.append(f"    note: {f}")
    lines += ["", "L: handed in after the due date   M: missing, past the due date", ""]
    lines += [f"{a['id']}: {a['title']}" + (f" (due {a['due']})" if a["due"] else "") for a in cols]
    return "\n".join(lines)


def run_cli(args) -> int:
    import sys
    cmd = getattr(args, "classcmd", None)
    try:
        if cmd == "new":
            c = new_class(args.name, [(x.strip(), "") for x in args.students.split(",") if x.strip()])
            print(f"made the class {c['name']} as '{c['slug']}' ({len(c['students'])} students), "
                  f"kept in {class_dir(c['slug'])}")
        elif cmd == "add-student":
            s = add_student(args.klass, args.name, args.sid)
            print(f"added {s['name']}" + (f" ({s['sid']})" if s["sid"] else ""))
        elif cmd == "assign":
            data = None
            if args.kind == "activity":
                data = Path(args.ref).expanduser().read_bytes()
            a = assign(args.klass, args.kind, args.ref, args.title, args.due, args.weight, data)
            print(f"assigned {a['id']}: {a['title']}" + (f", due {a['due']}" if a["due"] else ""))
        elif cmd == "export":
            data = export_class(args.klass)
            dest = Path(args.dest).expanduser()
            if dest.is_dir() or not dest.suffix:
                dest = dest / f"{args.klass}{CLASS_EXT}"
            _write(dest, data)
            print(f"saved {dest}: hand it to the students (USB stick, the school's platform, e-mail)")
        elif cmd == "open":
            info = open_class(Path(args.file).expanduser().read_bytes())
            if args.student:
                pick_student(info["id"], args.student)
            print(_render_work(classwork(info["id"])))
        elif cmd == "start":
            r = start(args.cid or current(), args.assignment)
            if r["kind"] == "activity":
                print(f"the activity is the lab '{r['lab']}': winlab gui {r['lab']} (its Activity window scores it)")
            else:
                print(f"started {r['title']}: winlab learn show {r['lesson']}" if r.get("lesson")
                      else f"started {r['title']}: winlab exercise show {r['exercise']}")
        elif cmd == "handin":
            name, data, summary = hand_in(args.cid)
            dest = Path(args.dest).expanduser()
            if dest.is_dir() or not dest.suffix:
                dest = dest / name
            _write(dest, data)
            print(f"handed in for {summary['student']}: {summary['done']} of {summary['count']} assignments done")
            for r in summary["rows"]:
                print(f"  {r['title'][:50]:<50} {r['status']:<12} {r['percent']}%" + ("  late" if r["late"] else ""))
            print(f"saved {dest}: give this file to your teacher")
        elif cmd == "import":
            rows = import_paths(args.klass, args.files)
            bad = 0
            for r in rows:
                if r["ok"]:
                    print(f"  ok       {r['file']}: {r['student']}" + (" (already imported)" if r["again"] else ""))
                    for f in r["flags"]:
                        print(f"           note: {f}")
                else:
                    bad += 1
                    print(f"  refused  {r['file']}: {r['reason']}")
            print(f"{len(rows) - bad} imported, {bad} refused")
            return 1 if bad else 0
        elif cmd == "grades":
            if args.student:
                c = load_class(args.klass)
                s = _student(c, args.student)
                for a in c["assignments"]:
                    b = breakdown(args.klass, s["key"], a["id"])
                    r = b["result"]
                    print(f"{a['id']} {a['title']}: " + (f"{r.get('status')} {r.get('percent')}%" if r else "not handed in"))
                    for x in r.get("items", []):
                        print(f"    [{'x' if x.get('ok') else ' '}] {x.get('label')}  ({x.get('points')})"
                              + (f"  {x['detail']}" if x.get("detail") and not x.get("ok") else ""))
                    for ev in r.get("evidence", []):
                        print(f"    evidence: {ev}")
            else:
                print(_render_book(gradebook(args.klass)))
        elif cmd == "csv":
            text = to_csv(args.klass)
            if args.dest == "-":
                sys.stdout.write(text)
            else:
                _write(Path(args.dest).expanduser(), text.encode("utf-8-sig"))
                print(f"saved {args.dest}")
        elif cmd == "list":
            mine = list_classes() if teacher_mode_allowed() else []
            for c in mine:
                print(f"teacher  {c['slug']:<24} {c['name']}  ({c['students']} students, {c['assignments']} assignments)")
            for c in joined_classes():
                print(f"student  {c['id']:<24} {c['name']}" + ("  (current)" if c["id"] == current() else ""))
            if not mine and not joined_classes():
                print("no classes on this PC yet: winlab class new <name>, or winlab class open <file.wlclass>")
        else:
            print("usage: winlab class {new,add-student,assign,export,open,start,handin,import,grades,csv,list}",
                  file=sys.stderr)
            return 2
        return 0
    except (ClassError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
