"""Scenario days: a working day told as a story, on a lab the student built.

A scenario (content/scenarios/<id>.toml) is a timed sequence of beats on one
lab. A beat is a message from a person in the story (the manager, a user),
delivered to the Scenarios inbox at its moment: so many minutes after the
day starts, or after a task is done (`after`), or at the latest by a given
minute (`latest`) so a slow student still meets the story. A beat may inject
a problem into a machine at that moment (`inject`: a guest fault, or one of
the scenario's own in winlab/scenariofaults.py) and may open tasks. A task is
graded by a check run inside the machine over the serial agent, exactly as an
exercise check is; a task can also be "the problem this beat injected is
fixed", graded by that fault's own verify.

A real day branches on what the student does, so a beat can also wait for
several tasks (`after` as a list), for the problem another beat injected to
be fixed (`after_fixed`, judged by that fault's own verify), or come only if
something is still not done by its minute (`unless`: the rollback order that
a quick fix never sees; its tasks then do not count). A beat may break the
same thing on several machines at once (`nodes`), and a beat can `repair`
another beat's injection when someone in the story fixes it (the vendor
brings the hardware back). A task may be graded on several machines
(`nodes`): it is done when it passes on every one. Tasks with a `due` are the
day's service levels: the debrief says how many were met, and how long each
injected problem kept the business waiting.

The hands-on rule holds throughout: the scenario injects problems and
grades, and the student does every fix inside the machines. Whatever the
day needs as its starting state is either built by the student in earlier
lessons (the scenario names them in `prerequisites` and checks the result
with `[[requires]]` before it starts) or created by an injection. A scenario
never applies a role.

When the clock runs out or the student ends the day, problems still open are
undone (beats with undo = false, such as files users dropped, are left), and
the debrief lists every task: done and when, or missed and what it was for.

The engine decides and records; commands run through a
`runner(node, command, shell) -> (ok, stdout)` the caller passes in (the
desktop and the command line use oncall.guest_runner), so tests run it
without a machine.
"""

from __future__ import annotations

import json
import re
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import paths

Runner = Callable[[str, str, str], tuple[bool, str]]

POINTS = 10                  # per unit of a task's weight
LATE_FACTOR = 0.5            # a task done after its `due` keeps half
MATCH_MODES = ("exact", "contains", "regex")
KINDS = ("incident", "planned", "audit", "project")
# Task states that never count towards the score: the injection failed
# (void) or the story took the other branch (not needed).
UNCOUNTED = ("void", "not needed")
# Windows PowerShell 5.1 does not parse these; every check must.
_PS7_ONLY = (re.compile(r"\?\?"), re.compile(r"\?\.\w"), re.compile(r"-Parallel\b"),
             re.compile(r"\$\w+\s*\?\s*[^\s:]+\s*:\s"))
# Words that would mean the scenario configures a machine itself.
_SETUP_WORDS = re.compile(r"(?i)\b(Install-ADDS\w*|Start-DscConfiguration|Install-WindowsFeature|"
                          r"Add-DhcpServerv4Scope|New-SmbShare|New-GPO|New-ADReplication\w+)\b")


class ScenarioError(Exception):
    pass


@dataclass
class Task:
    id: str
    title: str
    node: str = ""
    script: str = ""
    expect: str = "True"
    match: str = "exact"
    shell: str = "powershell"
    weight: int = 1
    due: int = 0              # minutes after it opens; 0 = no deadline
    fault_beat: str = ""      # graded by that beat's injected fault's verify
    missed: str = ""          # what the debrief says when it was not done
    nodes: list[str] = field(default_factory=list)   # more machines it must pass on

    @property
    def targets(self) -> list[str]:
        return list(dict.fromkeys(n for n in [self.node, *self.nodes] if n))


@dataclass
class Beat:
    id: str
    sender: str
    subject: str
    body: str
    at: int = 0               # minutes after start, or after `after` is done
    after: str = ""           # a task id
    latest: int = 0           # minutes after start: deliver by then whatever `after` says
    inject: str = ""          # a fault id
    node: str = ""            # where the fault is injected
    params: dict = field(default_factory=dict)
    undo: bool = True         # undo the injection at the end if its tasks are not done
    opens: list[str] = field(default_factory=list)
    afters: list[str] = field(default_factory=list)   # `after` as a list: every one done
    after_fixed: str = ""     # a beat id: comes once that beat's injected problem is fixed
    unless: list[str] = field(default_factory=list)   # skipped if all of these are done by its time
    nodes: list[str] = field(default_factory=list)    # more machines the injection hits
    repairs: str = ""         # a beat id: someone in the story undoes that beat's injection

    @property
    def targets(self) -> list[str]:
        return list(dict.fromkeys(n for n in [self.node, *self.nodes] if n))

    @property
    def waits(self) -> list[str]:
        return self.afters or ([self.after] if self.after else [])


@dataclass
class Require:
    name: str
    node: str
    script: str
    expect: str = "True"
    match: str = "exact"
    shell: str = "powershell"
    lesson: str = ""


@dataclass
class Scenario:
    id: str
    title: str
    lab: str
    minutes: int
    summary: str = ""
    story: str = ""
    sender: str = ""
    prerequisites: list[str] = field(default_factory=list)
    nodes: list[str] = field(default_factory=list)
    student_nodes: list[str] = field(default_factory=list)   # machines the student adds during the day
    requires: list[Require] = field(default_factory=list)
    beats: list[Beat] = field(default_factory=list)
    tasks: list[Task] = field(default_factory=list)
    debrief: str = ""
    kind: str = "incident"    # how the picker groups it: one of KINDS
    path: Path | None = None

    def task(self, tid: str) -> Task | None:
        return next((t for t in self.tasks if t.id == tid), None)

    def beat(self, bid: str) -> Beat | None:
        return next((b for b in self.beats if b.id == bid), None)

    def graders(self, bid: str) -> list[Task]:
        """The tasks graded by that beat's injected fault."""
        return [t for t in self.tasks if t.fault_beat == bid]

    @property
    def max_points(self) -> int:
        return sum(t.weight for t in self.tasks) * POINTS


# ------------------------------------------------------------------ content
def scenarios_dir() -> Path:
    return paths.CONTENT / "scenarios"


def _as_list(v) -> list:
    return v if isinstance(v, list) else ([v] if v else [])


def _parse(raw: dict, path: Path | None = None) -> Scenario:
    s = raw.get("scenario", {})
    sender = str(s.get("sender", ""))
    beats = []
    for b in raw.get("beat", []):
        after = b.get("after", "")
        afters = [str(x) for x in after] if isinstance(after, list) else []
        nodes = [str(x) for x in b.get("nodes", [])]
        node = str(b.get("node", "")) or (nodes[0] if nodes else "")
        beats.append(Beat(id=str(b.get("id", "")), sender=str(b.get("from", sender)),
                          subject=str(b.get("subject", "")), body=str(b.get("body", "")).strip(),
                          at=int(b.get("at", 0)), after=(afters[0] if afters else str(after)),
                          latest=int(b.get("latest", 0)), inject=str(b.get("inject", "")), node=node,
                          params={str(k): str(v) for k, v in (b.get("params") or {}).items()},
                          undo=bool(b.get("undo", True)), opens=[str(x) for x in b.get("opens", [])],
                          afters=afters if len(afters) > 1 else [], after_fixed=str(b.get("after_fixed", "")),
                          unless=[str(x) for x in _as_list(b.get("unless", []))],
                          nodes=[n for n in nodes if n != node], repairs=str(b.get("repairs", ""))))
    tasks = []
    for t in raw.get("task", []):
        nodes = [str(x) for x in t.get("nodes", [])]
        node = str(t.get("node", "")) or (nodes[0] if nodes else "")
        tasks.append(Task(id=str(t.get("id", "")), title=str(t.get("title", "")), node=node,
                          script=str(t.get("script", "")).strip(), expect=str(t.get("expect", "True")),
                          match=str(t.get("match", "exact")), shell=str(t.get("shell", "powershell")),
                          weight=int(t.get("weight", 1)), due=int(t.get("due", 0)),
                          fault_beat=str(t.get("fault_beat", "")), missed=str(t.get("missed", "")).strip(),
                          nodes=[n for n in nodes if n != node]))
    reqs = [Require(name=str(r.get("name", "")), node=str(r.get("node", "")), script=str(r.get("script", "")).strip(),
                    expect=str(r.get("expect", "True")), match=str(r.get("match", "exact")),
                    shell=str(r.get("shell", "powershell")), lesson=str(r.get("lesson", "")))
            for r in raw.get("requires", [])]
    return Scenario(id=str(s.get("id", path.stem if path else "")), title=str(s.get("title", "")),
                    lab=str(s.get("lab", "")), minutes=int(s.get("minutes", 60)),
                    summary=str(s.get("summary", "")).strip(), story=str(s.get("story", "")).strip(),
                    sender=sender, prerequisites=[str(x) for x in s.get("prerequisites", [])],
                    nodes=[str(x) for x in s.get("nodes", [])],
                    student_nodes=[str(x) for x in s.get("student_nodes", [])],
                    requires=reqs, beats=beats, tasks=tasks,
                    debrief=str(s.get("debrief", "")).strip(), kind=str(s.get("kind", "incident")), path=path)


def load(id_or_path: str) -> Scenario:
    from . import content
    p = Path(id_or_path)
    if not (p.suffix == ".toml" and content.exists(p)):
        p = scenarios_dir() / f"{id_or_path}.toml"
    if content.locked(p):
        raise ScenarioError(f"the scenario '{p.stem}' is part of the full version of winlab. {content.UNLOCK_HINT}")
    if not content.exists(p):
        raise ScenarioError(f"no scenario '{id_or_path}' (winlab scenario list)")
    try:
        return _parse(content.load_toml(p), p)
    except (tomllib.TOMLDecodeError, ValueError, TypeError) as exc:
        raise ScenarioError(f"{p.name}: {exc}") from exc


def list_available() -> list[Scenario]:
    from . import content
    out = []
    for f in content.glob(scenarios_dir(), "*.toml"):
        try:
            out.append(load(str(f)))
        except ScenarioError:
            continue
    return out


def fault(fid: str):
    """A scenario's own injection, else a guest fault."""
    from . import guestfaults, scenariofaults
    return scenariofaults.FAULTS.get(fid) or guestfaults.SCENARIOS.get(fid)


def task_nodes(scn: Scenario, task: Task) -> list[str]:
    """Where a task is graded: its own machines, or every machine its beat
    broke."""
    if task.fault_beat:
        b = scn.beat(task.fault_beat)
        return b.targets if b else []
    return task.targets


def task_script(scn: Scenario, task: Task, params: dict | None = None) -> tuple[str, str, str, str]:
    """(script, shell, expect, match) that grades a task."""
    if task.fault_beat:
        from . import guestfaults as gf
        b = scn.beat(task.fault_beat)
        f = fault(b.inject) if b else None
        if f is None:
            raise ScenarioError(f"task {task.id}: beat {task.fault_beat} injects nothing")
        p = dict(params or {})
        p.update(b.params)
        return gf._fill(f.verify, p), f.shell, f.expect, "exact"
    return task.script, task.shell, task.expect, task.match


def _ps_problems(where: str, script: str) -> list[str]:
    out = []
    for rx in _PS7_ONLY:
        if rx.search(script):
            out.append(f"{where}: uses syntax Windows PowerShell 5.1 cannot parse ({rx.pattern})")
    if re.search(r"(?m)^\s*(return|exit)\b|;\s*(return|exit)\b", script):
        out.append(f"{where}: return or exit would end the agent's request; leave the result as the last value")
    if script.count("{") != script.count("}") or script.count("(") != script.count(")"):
        out.append(f"{where}: unbalanced braces or brackets")
    return out


def validate(scn: Scenario) -> list[str]:
    """What a content author must fix before a scenario can run."""
    from . import guestfaults, lessons, schema
    w = f"scenario {scn.id}"
    out: list[str] = []
    if scn.path and scn.path.stem != scn.id:
        out.append(f"{w}: the file is {scn.path.name}, the id is {scn.id}")
    for name in ("title", "lab", "summary"):
        if not getattr(scn, name):
            out.append(f"{w}: no {name}")
    if scn.minutes < 10:
        out.append(f"{w}: a day shorter than 10 minutes")
    if scn.kind not in KINDS:
        out.append(f"{w}: kind must be one of {', '.join(KINDS)}")
    try:
        lab = schema.load(scn.lab)
    except Exception as exc:  # noqa: BLE001 a bad lab is reported, not raised
        return out + [f"{w}: lab '{scn.lab}' does not load: {exc}"]
    nodes = set(lab.nodes) | set(scn.student_nodes)
    for n in scn.nodes:
        if n not in lab.nodes:
            out.append(f"{w}: needs machine '{n}', which is not in {scn.lab}")
    if not scn.prerequisites:
        out.append(f"{w}: names no prerequisite lessons")
    for lid in scn.prerequisites:
        try:
            les = lessons.load(lid)
        except Exception:  # noqa: BLE001
            out.append(f"{w}: prerequisite lesson '{lid}' does not exist")
            continue
        if les.lab and les.lab != scn.lab:
            out.append(f"{w}: prerequisite '{lid}' is a lesson of {les.lab}, not {scn.lab}")
    task_ids = [t.id for t in scn.tasks]
    beat_ids = [b.id for b in scn.beats]
    for kind, ids in (("task", task_ids), ("beat", beat_ids)):
        dup = {i for i in ids if ids.count(i) > 1}
        if dup or "" in ids:
            out.append(f"{w}: {kind} ids must be set and unique ({', '.join(sorted(dup)) or 'empty id'})")
    opened: list[str] = []
    if not any(b.at == 0 and not b.waits and not b.after_fixed and not b.unless for b in scn.beats):
        out.append(f"{w}: no beat at minute 0 opens the day")
    for b in scn.beats:
        bw = f"{w} beat {b.id}"
        if not (b.sender and b.subject and b.body):
            out.append(f"{bw}: needs from, subject and body")
        for a in b.waits:
            if a not in task_ids:
                out.append(f"{bw}: after '{a}', which is no task")
        if b.after_fixed:
            fb = scn.beat(b.after_fixed)
            if fb is None or not fb.inject or fb.id == b.id:
                out.append(f"{bw}: after_fixed '{b.after_fixed}', which is no other beat that injects")
            if b.waits:
                out.append(f"{bw}: waits on a task and on a fix; pick one")
        for u in b.unless:
            if u not in task_ids:
                out.append(f"{bw}: unless '{u}', which is no task")
        if b.unless and (b.waits or b.after_fixed):
            out.append(f"{bw}: unless is a check at a minute of the day; it cannot also wait on a task or a fix")
        if b.unless and not (b.at or b.latest):
            out.append(f"{bw}: unless needs the minute it is decided at (at or latest)")
        if b.repairs:
            rb = scn.beat(b.repairs)
            if rb is None or not rb.inject or rb.id == b.id:
                out.append(f"{bw}: repairs '{b.repairs}', which is no other beat that injects")
            elif scn.graders(rb.id):
                out.append(f"{bw}: repairs '{b.repairs}', whose fix is the student's task")
        if b.at < 0 or b.latest < 0 or (b.latest and b.latest > scn.minutes):
            out.append(f"{bw}: its time is outside the day")
        if b.nodes and not b.inject:
            out.append(f"{bw}: names machines but injects nothing")
        if b.inject:
            f = fault(b.inject)
            if f is None:
                out.append(f"{bw}: injects '{b.inject}', which is no fault")
            for n in b.targets if f is not None else []:
                if n not in nodes:
                    out.append(f"{bw}: injects on '{n}', which is not in {scn.lab}")
                elif n in lab.nodes and not guestfaults.applies_to(f, lab.nodes[n].kind, lab.nodes[n].image):
                    out.append(f"{bw}: '{b.inject}' cannot run on {n}")
            if not b.targets:
                out.append(f"{bw}: injects on no machine")
            if f is not None and f.shell == "powershell":
                from . import guestfaults as gf
                for part, text in (("apply", f.apply), ("clear", f.clear), ("verify", f.verify)):
                    out += _ps_problems(f"{bw} {b.inject} {part}", gf._fill(text, {}))
        for t in b.opens:
            if t not in task_ids:
                out.append(f"{bw}: opens '{t}', which is no task")
            opened.append(t)
    for t in scn.tasks:
        tw = f"{w} task {t.id}"
        if not t.title:
            out.append(f"{tw}: no title")
        if opened.count(t.id) != 1:
            out.append(f"{tw}: must be opened by exactly one beat")
        if not t.missed:
            out.append(f"{tw}: no 'missed' text for the debrief")
        if t.weight < 1:
            out.append(f"{tw}: weight below 1")
        if t.due < 0:
            out.append(f"{tw}: due below 0")
        if t.fault_beat:
            b = scn.beat(t.fault_beat)
            if b is None or not b.inject:
                out.append(f"{tw}: fault_beat '{t.fault_beat}' is no beat that injects")
            continue
        if not t.targets:
            out.append(f"{tw}: runs on no machine")
        for n in t.targets:
            if n not in nodes:
                out.append(f"{tw}: runs on '{n}', which is not in {scn.lab}")
        if not t.script:
            out.append(f"{tw}: no script")
        if t.match not in MATCH_MODES:
            out.append(f"{tw}: match must be one of {', '.join(MATCH_MODES)}")
        if t.shell == "powershell":
            out += _ps_problems(tw, t.script)
        if _SETUP_WORDS.search(t.script):
            out.append(f"{tw}: a check must only read; it names {_SETUP_WORDS.search(t.script).group(0)}")
    for r in scn.requires:
        rw = f"{w} requires '{r.name}'"
        if r.node not in lab.nodes:
            out.append(f"{rw}: runs on '{r.node}', which is not in {scn.lab}")
        if r.lesson and r.lesson not in scn.prerequisites:
            out.append(f"{rw}: points at lesson '{r.lesson}', which is not a prerequisite")
        if r.shell == "powershell":
            out += _ps_problems(rw, r.script)
        if _SETUP_WORDS.search(r.script):
            out.append(f"{rw}: a check must only read")
    for text in [scn.title, scn.summary, scn.story, scn.debrief] + [b.body for b in scn.beats] + \
            [b.subject for b in scn.beats] + [t.title for t in scn.tasks] + [t.missed for t in scn.tasks]:
        if "—" in text:
            out.append(f"{w}: uses an em-dash; write two sentences instead")
            break
    return out


def validate_all() -> list[str]:
    from . import content
    out = []
    for f in content.glob(scenarios_dir(), "*.toml"):
        try:
            out += validate(load(str(f)))
        except ScenarioError as exc:
            out.append(str(exc))
    return out


# ------------------------------------------------------------------ state
def state_file() -> Path:
    return paths.VAR / "scenario.json"


def history_file() -> Path:
    return paths.VAR / "scenario-history.json"


def load_state() -> dict | None:
    try:
        raw = json.loads(state_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return raw if isinstance(raw, dict) and raw.get("id") else None


def save_state(st: dict | None) -> None:
    f = state_file()
    if st is None:
        f.unlink(missing_ok=True)
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    tmp.replace(f)


def _now() -> float:
    return time.time()


def _matches(out: str, expect: str, match: str) -> bool:
    from .exercises import Check, output_matches
    return output_matches(Check(name="", node="", script="", expect=expect, match=match), out)


def _params(lab, scn: Scenario, beat: Beat, node: str = "") -> dict:
    from . import guestfaults as gf, naming
    p = gf.lab_params(lab) if lab is not None else {}
    nid = node or beat.node
    n = lab.nodes.get(nid) if lab is not None else None
    p["node"] = naming.hostname_of(n) if n is not None else nid
    p.update(beat.params)
    return p


def _refused(ok: bool, out: str) -> str:
    """Why an injection did not take, or '' when it did. A fault whose
    starting state is missing says 'nothing to break: ...' and changes
    nothing, so its tasks must not count."""
    last = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    if not ok:
        return (last[-1] if last else "no answer")[:200]
    if last and (last[-1].lower() == "false" or last[-1].lower().startswith("nothing to break")):
        return last[-1][:200]
    return ""


def preflight(scn: Scenario, running: list[str], runner: Runner) -> list[str]:
    """Why the day cannot start yet, in words: machines off, or the lab not in
    the state the prerequisite lessons leave it."""
    out = []
    off = [n for n in scn.nodes if n not in running]
    if off:
        out.append(f"start {', '.join(off)} first")
        return out
    for r in scn.requires:
        ok, got = runner(r.node, r.script, r.shell)
        if not (ok and _matches(got, r.expect, r.match)):
            les = f" (lesson: {r.lesson})" if r.lesson else ""
            out.append(f"{r.name}{les}")
    return out


def start(scn: Scenario, lab, running: list[str], runner: Runner, now: float | None = None) -> dict:
    cur = load_state()
    if cur and not cur.get("done"):
        raise ScenarioError(f"'{cur['id']}' is running: end it first (winlab scenario stop)")
    if lab is not None and lab.name != scn.lab:
        raise ScenarioError(f"{scn.title} runs on the {scn.lab} lab; this is {lab.name}")
    missing = preflight(scn, running, runner)
    if missing:
        raise ScenarioError("not ready yet: " + "; ".join(missing))
    t = _now() if now is None else now
    st = {"id": scn.id, "lab": scn.lab, "title": scn.title, "started": t, "ends": t + 60 * scn.minutes,
          "minutes": scn.minutes, "done": False, "finished": 0.0,
          "beats": {b.id: {"status": "pending", "at": 0.0, "note": "", "applied": [], "fixed_at": 0.0}
                    for b in scn.beats},
          "tasks": {k.id: {"status": "locked", "opened": 0.0, "done_at": 0.0, "tries": 0, "last": ""}
                    for k in scn.tasks},
          "inbox": []}
    tick(st, scn, lab, runner, t)
    save_state(st)
    return st


def _done(st: dict, tid: str) -> bool:
    return st["tasks"].get(tid, {}).get("status") == "done"


def _due(st: dict, b: Beat, now: float) -> bool:
    started = st["started"]
    if b.latest and now >= started + 60 * b.latest:
        return True
    if b.waits:
        if not all(_done(st, a) for a in b.waits):
            return False
        return now >= max(st["tasks"][a]["done_at"] for a in b.waits) + 60 * b.at
    if b.after_fixed:
        fixed = st["beats"].get(b.after_fixed, {}).get("fixed_at") or 0.0
        return bool(fixed) and now >= fixed + 60 * b.at
    return now >= started + 60 * b.at


def _applied(rec: dict, b: Beat) -> list[str]:
    # A state file from before `applied` was kept: a delivered beat hit its node.
    if "applied" in rec:
        return list(rec["applied"])
    return b.targets if rec.get("status") == "delivered" else []


def _undo(st: dict, scn: Scenario, lab, b: Beat, runner: Runner) -> None:
    from . import guestfaults as gf
    f = fault(b.inject)
    if f is None:
        return
    for n in _applied(st["beats"][b.id], b):
        runner(n, gf._fill(f.clear, _params(lab, scn, b, n)), f.shell)


def _deliver(st: dict, scn: Scenario, lab, b: Beat, runner: Runner, now: float) -> None:
    from . import guestfaults as gf
    rec = st["beats"][b.id]
    rec["at"] = now
    status = "delivered"
    if b.repairs:
        rb = scn.beat(b.repairs)
        rrec = st["beats"].get(b.repairs, {})
        if rb is not None and rrec.get("status") in ("delivered", "failed") and not rrec.get("fixed_at"):
            _undo(st, scn, lab, rb, runner)
            rrec["fixed_at"], rrec["repaired"], rrec["note"] = now, True, "repaired in the story"
    if b.inject:
        f = fault(b.inject)
        rec["applied"] = []
        why = []
        for n in b.targets:
            if f is None:
                why.append(f"{n}: unknown fault")
                continue
            ok, out = runner(n, gf._fill(f.apply, _params(lab, scn, b, n)), f.shell)
            refused = _refused(ok, out)
            if refused:
                why.append(f"{n}: {refused}" if len(b.targets) > 1 else refused)
            else:
                rec["applied"].append(n)
        if why:
            status = "failed"
            rec["note"] = "; ".join(why)[:200]
    rec["status"] = status
    st["inbox"].append({"beat": b.id, "from": b.sender, "subject": b.subject, "body": b.body,
                        "at": now, "read": False})
    for tid in b.opens:
        tk = st["tasks"][tid]
        if tk["status"] == "locked":
            tk["status"], tk["opened"] = ("void" if status == "failed" else "open"), now
    if status == "failed":
        where = ", ".join(n for n in b.targets if n not in rec["applied"]) or b.node
        st["inbox"].append({"beat": b.id, "from": "winlab", "subject": f"Part of the day could not start: {b.subject}",
                            "body": (f"{where} did not take the change this message is about "
                                     f"({rec['note']}). Its tasks do not count towards your score. "
                                     f"Is the machine running, its agent answering, and the lesson it builds on done?"),
                            "at": now, "read": False, "system": True})


def _skip(st: dict, b: Beat, now: float) -> None:
    """The story took the other branch: this beat never comes, and what it
    would have asked for does not count."""
    rec = st["beats"][b.id]
    rec["status"], rec["at"], rec["note"] = "skipped", now, "not needed: " + ", ".join(b.unless) + " done in time"
    for tid in b.opens:
        if st["tasks"][tid]["status"] == "locked":
            st["tasks"][tid]["status"] = "not needed"


def tick(st: dict, scn: Scenario, lab, runner: Runner, now: float | None = None) -> bool:
    """Delivers every beat that is due; ends the day when the clock runs out.
    True when something changed."""
    t = _now() if now is None else now
    if st.get("done"):
        return False
    changed = False
    moved = True
    while moved:
        moved = False
        for b in scn.beats:
            if st["beats"][b.id]["status"] == "pending" and _due(st, b, t):
                if b.unless and all(_done(st, u) for u in b.unless):
                    _skip(st, b, t)
                else:
                    _deliver(st, scn, lab, b, runner, t)
                changed = moved = True
    if t >= st["ends"]:
        finish(st, scn, lab, runner, t, reason="time")
        changed = True
    return changed


def _grade(scn: Scenario, lab, task: Task, runner: Runner) -> tuple[bool, str]:
    """Runs a task's check on every machine it names: (passed, what the
    first machine that failed said)."""
    b = scn.beat(task.fault_beat) if task.fault_beat else None
    targets = task_nodes(scn, task)
    for n in targets:
        params = _params(lab, scn, b, n) if b else {}
        script, shell, expect, match = task_script(scn, task, params)
        ok, out = runner(n, script, shell)
        if ok and _matches(out, expect, match):
            continue
        lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        detail = lines[-1] if lines else ("no answer" if not ok else "not done yet")
        if detail.lower() in ("true", "false") or (ok and not lines):
            detail = "not done yet"
        return False, (f"{n}: {detail}" if len(targets) > 1 else detail)
    return bool(targets), "done"


def _watch_fixes(st: dict, scn: Scenario, lab, runner: Runner, t: float) -> None:
    """A beat waiting for a fix that no task grades: ask the fault's own
    verify, on every machine it was injected on."""
    from . import guestfaults as gf
    for b in scn.beats:
        if not b.after_fixed or st["beats"][b.id]["status"] != "pending":
            continue
        w = scn.beat(b.after_fixed)
        wrec = st["beats"].get(b.after_fixed, {})
        if w is None or wrec.get("status") != "delivered" or wrec.get("fixed_at") or scn.graders(w.id):
            continue
        f = fault(w.inject)
        if f is None or not f.verify:
            continue
        good = True
        for n in _applied(wrec, w):
            ok, out = runner(n, gf._fill(f.verify, _params(lab, scn, w, n)), f.shell)
            if not (ok and _matches(out, f.expect, "exact")):
                good = False
                break
        if good:
            wrec["fixed_at"] = t


def check(st: dict, scn: Scenario, lab, runner: Runner, now: float | None = None) -> list[dict]:
    """Check my work: grades every open task, then lets the story move on."""
    t = _now() if now is None else now
    tick(st, scn, lab, runner, t)
    results = []
    if st.get("done"):
        save_state(st)
        return results
    for task in scn.tasks:
        rec = st["tasks"][task.id]
        if rec["status"] != "open":
            continue
        passed, detail = _grade(scn, lab, task, runner)
        rec["tries"] += 1
        rec["last"] = detail[:200]
        if passed:
            rec["status"], rec["done_at"] = "done", t
            if task.fault_beat and all(_done(st, k.id) for k in scn.graders(task.fault_beat)):
                fb = st["beats"].get(task.fault_beat)
                if fb is not None and not fb.get("fixed_at"):
                    fb["fixed_at"] = t
        results.append({"id": task.id, "title": task.title, "passed": passed})
    _watch_fixes(st, scn, lab, runner, t)
    tick(st, scn, lab, runner, t)
    save_state(st)
    return results


def points(task: Task, rec: dict) -> int:
    if rec.get("status") != "done":
        return 0
    full = task.weight * POINTS
    if task.due and rec["done_at"] - rec["opened"] > 60 * task.due:
        return int(full * LATE_FACTOR)
    return full


def finish(st: dict, scn: Scenario, lab, runner: Runner, now: float | None = None, reason: str = "ended") -> dict:
    """Ends the day: problems whose tasks are not done are undone, then the
    debrief is kept with the student's history."""
    t = _now() if now is None else now
    if st.get("done"):
        return debrief(st, scn)
    for b in scn.beats:
        rec = st["beats"][b.id]
        if not (b.inject and b.undo and rec["status"] in ("delivered", "failed") and _applied(rec, b)):
            continue
        if rec.get("repaired"):
            continue
        graded_by = [k for k in scn.tasks if k.fault_beat == b.id or k.id in b.opens]
        if graded_by and all(st["tasks"][k.id]["status"] == "done" for k in graded_by):
            continue
        _undo(st, scn, lab, b, runner)
        rec["note"] = "undone at the end of the day"
    for rec in st["tasks"].values():
        if rec["status"] in ("open", "locked"):
            rec["status"] = "missed" if rec["status"] == "open" else "not reached"
    st["done"], st["finished"], st["reason"] = True, t, reason
    d = debrief(st, scn)
    _record(d)
    save_state(st)
    return d


def _record(d: dict) -> None:
    f = history_file()
    try:
        hist = json.loads(f.read_text(encoding="utf-8"))
        if not isinstance(hist, list):
            hist = []
    except (OSError, json.JSONDecodeError):
        hist = []
    row = {k: d[k] for k in ("id", "title", "lab", "score", "max", "percent", "started", "finished")}
    row["sla"] = f"{d['sla']['met']}/{d['sla']['total']}"
    row["downtime"] = d["downtime"]
    hist.append(row)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(hist[-200:], indent=2), encoding="utf-8")


def _outages(st: dict, scn: Scenario) -> list[dict]:
    """How long each injected problem the student had to fix stayed broken:
    from the moment it hit to the fix, or to the end of the day."""
    end = st.get("finished") or st["ends"]
    out = []
    for b in scn.beats:
        rec = st["beats"][b.id]
        if not b.inject or rec["status"] != "delivered" or not scn.graders(b.id):
            continue
        fixed = rec.get("fixed_at") or 0.0
        out.append({"beat": b.id, "subject": b.subject, "fixed": bool(fixed),
                    "minutes": round(max(0.0, (fixed or end) - rec["at"]) / 60, 1)})
    return out


def debrief(st: dict, scn: Scenario) -> dict:
    rows = []
    counted = [k for k in scn.tasks if st["tasks"][k.id]["status"] not in UNCOUNTED]
    for k in scn.tasks:
        rec = st["tasks"][k.id]
        mins = round((rec["done_at"] - rec["opened"]) / 60, 1) if rec["status"] == "done" else None
        late = bool(k.due and rec["status"] == "done" and mins is not None and mins > k.due)
        rows.append({"id": k.id, "title": k.title, "status": rec["status"], "minutes": mins, "late": late,
                     "due": k.due, "points": points(k, rec), "max": k.weight * POINTS,
                     "missed": k.missed if rec["status"] in ("missed", "not reached", "open", "locked") else ""})
    score = sum(r["points"] for r in rows)
    mx = sum(k.weight for k in counted) * POINTS
    pct = round(100 * score / mx) if mx else 0
    slas = [r for r in rows if r["due"] and r["status"] not in UNCOUNTED]
    met = sum(1 for r in slas if r["status"] == "done" and not r["late"])
    outages = _outages(st, scn)
    branches = [{"subject": b.subject, "taken": st["beats"][b.id]["status"] != "skipped"}
                for b in scn.beats if b.unless and st["beats"][b.id]["status"] in ("delivered", "failed", "skipped")]
    return {"id": scn.id, "title": scn.title, "lab": scn.lab, "score": score, "max": mx, "percent": pct,
            "started": st["started"], "finished": st.get("finished") or 0.0, "reason": st.get("reason", ""),
            "verdict": _verdict(pct), "tasks": rows, "debrief": scn.debrief,
            "sla": {"met": met, "total": len(slas)}, "outages": outages,
            "downtime": round(sum(o["minutes"] for o in outages), 1), "branches": branches}


def _verdict(pct: int) -> str:
    if pct >= 90:
        return "An excellent day: the business barely noticed."
    if pct >= 70:
        return "A good day, with a few loose ends to tie up tomorrow."
    if pct >= 40:
        return "A hard day. Read what was missed, then run it again."
    return "The day got away from you. Do the prerequisite lessons again, then try once more."


def view(st: dict | None, scn: Scenario | None, now: float | None = None) -> dict:
    """What the Scenarios window shows. A task's check and an injected
    fault's name never reach the page; a task is shown once its beat came."""
    if not st or scn is None:
        return {"active": False}
    t = _now() if now is None else now
    tasks = []
    for k in scn.tasks:
        rec = st["tasks"][k.id]
        if rec["status"] in ("locked", "not reached", "not needed") and not st.get("done"):
            continue
        where = task_nodes(scn, k)
        row = {"id": k.id, "title": k.title, "status": rec["status"], "tries": rec["tries"],
               "node": where[0] if where else k.node, "nodes": where,
               # While the story runs, a failed check says only that it is not
               # done yet and how often it was tried: its raw output can name
               # the fix. The debrief (the story over) shows what it said.
               "last": ("" if rec["status"] == "done" else rec["last"] if st.get("done")
                        else f"still not done ({rec['tries']} tr{'y' if rec['tries'] == 1 else 'ies'})"
                        if rec["tries"] else "")}
        if k.due and rec["status"] == "open":
            row["due_left"] = int(rec["opened"] + 60 * k.due - t)
        tasks.append(row)
    score = sum(points(k, st["tasks"][k.id]) for k in scn.tasks)
    out = {"active": not st.get("done"), "done": bool(st.get("done")), "id": scn.id, "title": scn.title,
           "lab": scn.lab, "kind": scn.kind, "left": max(0, int(st["ends"] - t)), "minutes": st["minutes"],
           "started": st["started"], "inbox": list(reversed(st["inbox"])), "tasks": tasks,
           "score": score, "max": scn.max_points}
    if st.get("done"):
        out["debrief"] = debrief(st, scn)
    return out


def catalog(lab_name: str = "") -> list[dict]:
    """Every scenario for the picker: its lab, length, story and the lessons
    to do first, with whether each is done."""
    from . import lessons, progress
    try:
        prog = progress.load()
    except Exception:  # noqa: BLE001 progress is a nicety here
        prog = {}
    done = set()
    for lid, rec in ((prog.get("lessons") or {}) if isinstance(prog, dict) else {}).items():
        if isinstance(rec, dict) and rec.get("status") == "done":
            done.add(lid)
    out = []
    for s in list_available():
        pre = []
        for lid in s.prerequisites:
            try:
                title = lessons.load(lid).title
            except Exception:  # noqa: BLE001
                title = lid
            pre.append({"id": lid, "title": title, "done": lid in done})
        out.append({"id": s.id, "title": s.title, "lab": s.lab, "minutes": s.minutes, "summary": s.summary,
                    "story": s.story, "sender": s.sender, "prerequisites": pre, "here": s.lab == lab_name,
                    "nodes": s.nodes, "tasks": len(s.tasks), "max": s.max_points, "kind": s.kind,
                    "slas": sum(1 for t in s.tasks if t.due)})
    return out


def _mmss(sec: int) -> str:
    return f"{'-' if sec < 0 else ''}{abs(sec) // 60}:{abs(sec) % 60:02d}"


def render(v: dict) -> str:
    if not v.get("active") and not v.get("done"):
        return "no scenario running: winlab scenario list, then winlab scenario start <id>"
    clock = "over" if v["done"] else f"{v['left'] // 60} min left"
    lines = [f"{v['title']} on {v['lab']}: {clock}, {v['score']} of {v['max']} points", "", "inbox (newest first):"]
    for m in v["inbox"]:
        when = time.strftime("%H:%M", time.localtime(m["at"]))
        lines.append(f"  {when}  {m['from']}: {m['subject']}")
    lines += ["", "tasks:"]
    mark = {"done": "[x]", "open": "[ ]", "missed": "[-]", "void": "[~]", "not reached": "[ ]", "not needed": "[.]"}
    for k in v["tasks"]:
        extra = f"  ({k['last']})" if k.get("last") and k["status"] == "open" and k["tries"] else ""
        if "due_left" in k:
            extra += f"  [due in {_mmss(k['due_left'])}]" if k["due_left"] >= 0 else "  [past due]"
        lines.append(f"  {mark.get(k['status'], '[ ]')} {k['title']} ({', '.join(k.get('nodes') or [k['node']])}){extra}")
    if v.get("debrief"):
        d = v["debrief"]
        lines += ["", f"debrief: {d['score']} of {d['max']} points ({d['percent']}%). {d['verdict']}"]
        if d["sla"]["total"]:
            lines.append(f"  service levels met: {d['sla']['met']} of {d['sla']['total']}")
        for o in d["outages"]:
            lines.append(f"  {o['subject']}: {'fixed after' if o['fixed'] else 'still broken after'} {o['minutes']} min")
        for b in d["branches"]:
            lines.append(f"  {'came' if b['taken'] else 'not needed'}: {b['subject']}")
        for r in d["tasks"]:
            if r["missed"]:
                lines.append(f"  missed: {r['title']}: {r['missed']}")
        if d.get("debrief"):
            lines += ["", d["debrief"]]
    return "\n".join(lines)


def render_list(items: list[dict]) -> str:
    lines = []
    for s in items:
        lines.append(f"{s['id']:<22} {s['title']}  ({s['lab']}, {s['minutes']} min, {s['tasks']} tasks, {s.get('kind', 'incident')})")
        lines.append(f"{'':<22} {s['summary']}")
        lines.append(f"{'':<22} first: " + ", ".join(p['id'] + (' (done)' if p['done'] else '') for p in s['prerequisites']))
    return "\n".join(lines) if lines else "no scenarios"
