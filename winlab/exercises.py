"""Exercise and grading engine.

An exercise is a TOML file describing a task the student performs, plus checks
the engine runs inside the guests to grade it. Checks are PowerShell snippets
whose success is decided by exit code and expected stdout, run over the same
serial channel the role runner uses. qcow2 snapshots give each exercise a
pristine start and a one-command reset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import paths, state
from .guestctl import GuestChannel, GuestError


class ExerciseError(Exception):
    pass


MATCH_MODES = ("exact", "contains", "regex")

# A check whose node is "winlab" is answered by winlab itself, from what it
# keeps of the lab outside the machines (the rack, its documentation, the
# UPS's plugs): its script is the name of a registered check, which returns
# (passed, what it found). Nothing runs in a guest for it.
WINLAB = "winlab"
WINLAB_MODULES = ("rack", "serverroom")   # the modules that register such checks
_WINLAB_CHECKS: dict = {}


def register_winlab_check(name: str, fn) -> None:
    """fn(lab) -> (bool, str): a check graded from winlab's records."""
    _WINLAB_CHECKS[name] = fn


def winlab_check(name: str, lab_name: str) -> tuple[bool, str]:
    import importlib
    for mod in WINLAB_MODULES:
        importlib.import_module(f"winlab.{mod}")
    fn = _WINLAB_CHECKS.get(name.strip())
    if fn is None:
        raise ExerciseError(f"no winlab check {name.strip()!r}")
    from . import schema
    try:
        return fn(schema.load(lab_name))
    except Exception as exc:  # noqa: BLE001 - a lab that does not load fails the check, not the grading
        raise ExerciseError(str(exc)) from exc


def output_matches(check: "Check", out: str) -> bool:
    """Compares stdout only: stderr carries errors, and an error message that
    happens to contain the expected word must not pass a check. Exact is the
    default because a substring lets 10.10.10.10 match 10.10.10.100."""
    if not check.expect:
        return True
    got = out.strip()
    if check.match == "contains":
        return check.expect.lower() in got.lower()
    if check.match == "regex":
        return re.search(check.expect, got, re.IGNORECASE | re.MULTILINE) is not None
    return got.lower() == check.expect.strip().lower()


@dataclass
class Check:
    name: str
    node: str
    script: str
    expect: str = ""          # what stdout must be (see match)
    match: str = "exact"      # exact | contains | regex, all case-insensitive
    expect_rc: int = 0
    weight: int = 1
    hint: str = ""
    shell: str = "powershell"


@dataclass
class Exercise:
    id: str
    title: str
    lab: str = ""
    brief: str = ""
    tasks: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    reset_nodes: list[str] = field(default_factory=list)
    nodes: list[str] = field(default_factory=list)  # machines it needs running

    def needed_nodes(self) -> list[str]:
        """The machines `exercise start` boots: the declared list, or else
        every machine the exercise resets or checks. The domain controller
        they depend on is added at boot time (membudget.with_dependencies)."""
        if self.nodes:
            return list(self.nodes)
        out: list[str] = []
        for n in self.reset_nodes + [c.node for c in self.checks]:
            if n not in out and n not in ("fabric", WINLAB):   # the router is always up
                out.append(n)
        return out

    @property
    def total_weight(self) -> int:
        return sum(c.weight for c in self.checks) or 1


@dataclass
class CheckResult:
    check: Check
    passed: bool
    detail: str


@dataclass
class Grade:
    exercise: str
    results: list[CheckResult]

    @property
    def earned(self) -> int:
        return sum(r.check.weight for r in self.results if r.passed)

    @property
    def total(self) -> int:
        return sum(r.check.weight for r in self.results) or 1

    @property
    def percent(self) -> int:
        return round(100 * self.earned / self.total)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)


def exercise_path(ident: str) -> Path:
    from . import content
    p = Path(ident)
    if content.exists(p):
        return p
    cand = paths.EXERCISES / f"{ident}.toml"
    if content.exists(cand):
        return cand
    if content.locked(cand):
        raise ExerciseError(f"the exercise {ident} is part of the full version. {content.UNLOCK_HINT}")
    raise ExerciseError(f"exercise not found: {ident}")


def load(ident: str) -> Exercise:
    from . import content
    path = exercise_path(ident)
    raw = content.load_toml(path)
    meta = raw.get("exercise", {})
    if not meta.get("id"):
        raise ExerciseError(f"{path.name}: [exercise] missing 'id'")

    checks = []
    for c in raw.get("check", []):
        if not c.get("node") or not c.get("script"):
            raise ExerciseError(f"{path.name}: a [[check]] needs 'node' and 'script'")
        if c.get("match", "exact") not in MATCH_MODES:
            raise ExerciseError(
                f"{path.name}: check '{c.get('name', '')}' has unknown match "
                f"'{c['match']}' (use {', '.join(MATCH_MODES)})")
        checks.append(
            Check(
                name=c.get("name", c["node"]),
                node=str(c["node"]),
                script=str(c["script"]),
                expect=str(c.get("expect", "")),
                match=str(c.get("match", "exact")),
                expect_rc=int(c.get("expect_rc", 0)),
                weight=int(c.get("weight", 1)),
                hint=str(c.get("hint", "")),
                shell=str(c.get("shell", "powershell")),
            )
        )

    ex = Exercise(
        id=str(meta["id"]),
        title=str(meta.get("title", meta["id"])),
        lab=str(meta.get("lab", "")),
        brief=str(meta.get("brief", "")),
        tasks=[str(t) for t in meta.get("tasks", [])],
        checks=checks,
        reset_nodes=[str(n) for n in meta.get("reset_nodes", [])],
        nodes=[str(n) for n in meta.get("nodes", [])],
    )
    # Checks are written against winlab's names; grade in the student's.
    from . import naming
    return naming.for_lab(ex.lab).exercise(ex) if ex.lab else ex


def footprint(ex: Exercise) -> tuple[list[str], int, int] | None:
    """(machines, MB as defined, MB trimmed to the floor) that `exercise
    start` boots for this exercise, fabric included; None when its lab cannot
    be loaded."""
    from . import membudget, netplan, schema

    try:
        lab = schema.load(ex.lab)
        ids, _ = membudget.with_dependencies(lab, ex.needed_nodes())
    except (schema.LabError, membudget.BudgetError):
        return None
    fabric = netplan.compile_topology(lab, check_ports=False).fabric_memory_mb
    return ids, membudget.plan(lab, ids, fabric, 0).need_mb, membudget.floor_mb(lab, ids, fabric)


def list_available() -> list[Exercise]:
    out = []
    if not paths.EXERCISES.exists():
        return out
    from . import content
    for f in content.glob(paths.EXERCISES, "*.toml"):
        try:
            out.append(load(f))
        except ExerciseError:
            continue
    return out


def _channel_for(lab_name: str, node_id: str) -> GuestChannel:
    st = state.load(lab_name)
    if not st:
        raise ExerciseError(f"lab '{lab_name}' is not running")
    ns = st.nodes.get(node_id)
    if not ns or not ns.serial_port or not state.pid_alive(ns.pid):
        raise ExerciseError(f"node '{node_id}' is not running")
    return GuestChannel(ns.serial_port).connect(retries=20, delay=2)


# Values the host keeps out of the guests and hands to a check only while it
# runs: {{winlab:planted}} is what the inherited company's handover planted
# (winlab/inherited.py), so the answer key never sits on a machine the student
# administers.
_HOST_VALUES = ("{{winlab:planted}}",)


def host_value(token: str, lab_name: str) -> str:
    if token == "{{winlab:planted}}":
        from . import inherited
        return inherited.planted_for_grading(lab_name)
    return ""


def with_host_values(script: str, lab_name: str) -> str:
    for token in _HOST_VALUES:
        if token in script:
            script = script.replace(token, host_value(token, lab_name))
    return script


def grade(ex: Exercise, lab_name: str) -> Grade:
    """Runs every check, reusing one channel per node."""
    channels: dict[str, GuestChannel] = {}
    results: list[CheckResult] = []
    try:
        for check in ex.checks:
            try:
                if check.node == WINLAB:
                    passed, found = winlab_check(check.script, lab_name)
                    ok = output_matches(check, "True" if passed else "False")
                    summary = found if ok or not check.hint else f"{found}  |  hint: {check.hint}"
                    results.append(CheckResult(check, ok, summary[:300]))
                    continue
                if check.node not in channels:
                    channels[check.node] = _channel_for(lab_name, check.node)
                ch = channels[check.node]
                res = ch.run(with_host_values(check.script, lab_name), shell=check.shell, timeout=120)
                ok = res.rc == check.expect_rc and output_matches(check, res.out)
                detail = (res.out or res.err).strip().splitlines()
                summary = detail[-1] if detail else f"rc={res.rc}"
                if not ok and check.hint:
                    summary = f"{summary}  |  hint: {check.hint}"
                results.append(CheckResult(check, ok, summary[:300]))
            except (ExerciseError, GuestError) as exc:
                results.append(CheckResult(check, False, f"check could not run: {exc}"))
    finally:
        for ch in channels.values():
            ch.close()
    return Grade(ex.id, results)


def render_grade(g: Grade, ex: Exercise) -> str:
    lines = [f"{ex.title}  [{ex.id}]", ""]
    for r in g.results:
        mark = "PASS" if r.passed else "FAIL"
        lines.append(f"  [{mark}] {r.check.name}  (weight {r.check.weight})")
        lines.append(f"         {r.detail}")
    lines.append("")
    verdict = "PASSED" if g.passed else "incomplete"
    lines.append(f"score: {g.earned}/{g.total}  ({g.percent}%)  -> {verdict}")
    return "\n".join(lines)


def render_brief(ex: Exercise) -> str:
    lines = [f"{ex.title}  [{ex.id}]"]
    if ex.lab:
        lines.append(f"lab: {ex.lab}")
    if ex.brief:
        lines.append("")
        lines.append(ex.brief.strip())
    if ex.tasks:
        lines.append("")
        lines.append("tasks:")
        for i, t in enumerate(ex.tasks, 1):
            lines.append(f"  {i}. {t}")
    lines.append("")
    lines.append(f"{len(ex.checks)} graded checks. Run 'winlab exercise grade {ex.id}' "
                 f"when done.")
    return "\n".join(lines)
