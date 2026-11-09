"""The self-test: proves on a real PC that every lesson can be passed.

`winlab selftest` works through the lessons the way a student would, on the
student's own machines, and writes down what happened:

- An exercise: its machines are brought up with winlab's own mechanisms (the
  lab starts empty, `lab up` boots what the exercise needs), it is graded on
  the fresh lab (which must NOT pass yet), its worked solution
  (content/solutions/<exercise>.toml, winlab/solutions.py) is typed in, and
  it is graded again (which must pass).
- A troubleshooting problem (winlab/guestfaults.py, `winlab break`): broken,
  verified (must fail), put back with the CLI's "fix it for me" path, and
  verified again (must pass). A problem lesson with an exercise then breaks
  the machine again and runs the exercise with its solution.
- A network fault (winlab/faults.py, `winlab net <lab> fault`): broken, the
  lesson's exercise graded (must fail), the solution, graded (must pass), the
  fault cleared, graded again (must pass).

Lessons run lab by lab in path order (module, then order), so a later lesson
finds what the earlier ones built, as it does for a student: every lab starts
empty and its foundation lesson comes first. After each lesson the lab's
machines are checkpointed (`selftest`), so a run that stops (a crash, the PC
restarting) resumes with `--resume` from the last lesson that finished.

The run lives in var/selftest/<time>/: state.json (the plan and every
result, written after each step), report.json and report.txt. It is a
command-line tool only: nothing of it, and no solution, is in the desktop.
"""
from __future__ import annotations

import contextlib
import io
import json
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import paths, solutions

CHECKPOINT = "selftest"
BOOT_TIMEOUT = 3600     # a machine's agent must answer within this after it starts
REBOOT_TIMEOUT = 1800   # a step that restarts its machine: back within this

# What a lesson's result is, worst first (the summary counts them).
OK = "ok"
CHECK_FAILED = "check failed"
STEP_FAILED = "solution step failed"
PASSES_BEFORE = "passes before work"
PROBLEM_FAILED = "problem failed"
NOT_STARTED = "machines did not start"
NO_SOLUTION = "no solution"
SKIPPED = "skipped"
STATUSES = (CHECK_FAILED, STEP_FAILED, PASSES_BEFORE, PROBLEM_FAILED, NOT_STARTED, NO_SOLUTION, OK, SKIPPED)
GOOD = (OK, SKIPPED)

# What the console prints for a line it did not take.
CONSOLE_ERRORS = ("% Invalid input", "% Incomplete command", "% Ambiguous command")


class SelftestError(Exception):
    pass


# --------------------------------------------------------------------------
# The plan
# --------------------------------------------------------------------------

@dataclass
class Item:
    """One thing the run proves: a lesson (or an exercise no lesson uses)."""
    key: str                  # lesson id, or exercise:<id>
    lab: str
    kind: str                 # exercise | problem | fault | setup | skip
    lesson: str = ""
    exercise: str = ""
    problem: str = ""         # guest fault (problem lessons)
    fault: str = ""           # network fault (find-the-fault lessons)
    fault_on: str = ""
    node: str = ""            # the machine a problem is broken on
    reason: str = ""          # why skipped
    status: str = "pending"   # pending | running | done
    result: dict = field(default_factory=dict)


def _lesson_items(lesson, seen: dict[str, str]) -> Item:
    key = lesson.id
    if lesson.browser:
        return Item(key, lesson.lab, "skip", lesson=lesson.id,
                    reason="done in the student's own browser, on their own cloud tenant")
    if not lesson.lab:
        return Item(key, "", "skip", lesson=lesson.id, reason="the lesson names no lab")
    if lesson.exercise and lesson.exercise in seen and not (lesson.problem or lesson.fault):
        return Item(key, lesson.lab, "skip", lesson=lesson.id, exercise=lesson.exercise,
                    reason=f"same exercise as lesson {seen[lesson.exercise]}")
    if lesson.fault:
        return Item(key, lesson.lab, "fault", lesson=lesson.id, exercise=lesson.exercise,
                    fault=lesson.fault, fault_on=lesson.fault_on)
    if lesson.problem:
        return Item(key, lesson.lab, "problem", lesson=lesson.id, exercise=lesson.exercise,
                    problem=lesson.problem, node=lesson.node)
    if lesson.exercise:
        return Item(key, lesson.lab, "exercise", lesson=lesson.id, exercise=lesson.exercise)
    return Item(key, lesson.lab, "skip", lesson=lesson.id,
                reason="checked by ticking its steps: nothing to grade")


def full_plan() -> dict[str, list[Item]]:
    """Every lab's items in path order, then the lab's exercises no lesson uses."""
    from . import exercises, lessons
    by_lab: dict[str, list[Item]] = {}
    seen: dict[str, str] = {}
    for lesson in lessons.list_available():
        it = _lesson_items(lesson, seen)
        if it.exercise and it.kind != "skip":
            seen.setdefault(it.exercise, lesson.id)
        by_lab.setdefault(it.lab, []).append(it)
    order: dict[str, list[str]] = {}

    def rank(ex) -> tuple:
        # In the order the lab lists them (later practice builds on earlier), then by id.
        if ex.lab not in order:
            try:
                from . import schema
                order[ex.lab] = list(schema.load(ex.lab).exercises)
            except Exception:  # noqa: BLE001
                order[ex.lab] = []
        ids = order[ex.lab]
        return (ids.index(ex.id) if ex.id in ids else len(ids), ex.id)

    for ex in sorted(exercises.list_available(), key=lambda e: (e.lab or "", *rank(e)) if e.lab else ("", 0, e.id)):
        if ex.id in seen or not ex.lab:
            continue
        seen[ex.id] = ""
        by_lab.setdefault(ex.lab, []).append(Item(f"exercise:{ex.id}", ex.lab, "exercise", exercise=ex.id))
    return by_lab


def select(by_lab: dict[str, list[Item]], lab: str = "", lesson: str = "", exercise: str = "",
           everything: bool = False, only: str = "", setup: bool = True) -> list[Item]:
    """The items one run works through. One lesson or exercise brings the
    lab's earlier lessons along as setup (their solutions only, no
    grading), so it finds the lab the way a student would."""
    if lesson or exercise:
        for lab_name, items in by_lab.items():
            for i, it in enumerate(items):
                if (lesson and it.lesson == lesson) or (exercise and it.exercise == exercise and it.kind != "skip"):
                    before = [_as_setup(x) for x in items[:i] if x.kind != "skip"] if setup and lab_name else []
                    return _only([x for x in before if x.kind == "setup"] + [it], only)
        raise SelftestError(f"no lesson or exercise {lesson or exercise!r}")
    if everything:
        out = [it for name in sorted(by_lab) for it in by_lab[name]]
    elif lab:
        if lab not in by_lab:
            raise SelftestError(f"no lessons or exercises on lab {lab!r}")
        out = list(by_lab[lab])
    else:
        raise SelftestError("name a lab, or --lesson, --exercise or --all")
    return _only(out, only)


def _as_setup(it: Item) -> Item:
    if it.kind in ("exercise", "problem", "fault") and it.exercise:
        return Item(f"setup:{it.key}", it.lab, "setup", lesson=it.lesson, exercise=it.exercise)
    return Item(it.key, it.lab, "skip", lesson=it.lesson, reason="nothing to set up")


def _only(items: list[Item], only: str) -> list[Item]:
    if only == "problems":
        out = []
        for it in items:
            if it.kind in ("problem", "fault", "skip", "setup"):
                out.append(it)
            elif it.kind == "exercise":
                out.append(_as_setup(it))   # still built: a later problem may need it
        return [it for it in out if it.kind != "skip" or it.lesson]
    if only == "exercises":
        return [it for it in items if it.kind != "problem" or it.exercise]
    return items


# --------------------------------------------------------------------------
# The machines: one seam, so the tests run the flow without a VM
# --------------------------------------------------------------------------

class Env:
    """What the run does to the machines, through winlab's own mechanisms.
    The tests replace the methods that would touch QEMU."""

    def __init__(self, accel: str = "", display: str = "none", say=print, checkpoints: bool = True,
                 workdir: Path | None = None) -> None:
        import tempfile
        self.workdir = workdir or Path(tempfile.gettempdir()) / "winlab-selftest"
        self.accel = accel
        self.display = display
        self.say = say
        self.checkpoints = checkpoints

    # ---- time
    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    # ---- the lab
    def _lab(self, lab_name: str):
        from . import schema
        return schema.load(lab_name)

    def secret(self, lab_name: str) -> str:
        """The lab's generated admin secret: what `winlab lab password` prints."""
        return self._lab(lab_name).admin_password

    def _quiet(self, fn, *a, **k):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = fn(*a, **k)
        for line in buf.getvalue().splitlines():
            if line.strip():
                self.say(f"      {line}")
        return rc

    def empty_lab(self, lab_name: str) -> str:
        """Every lab starts empty: its machines stopped and rebuilt from
        their image at the next boot (`winlab lab down`, `lab reset`)."""
        from . import cli
        from .orchestrator import Orchestrator, OrchestratorError
        self._quiet(cli.cmd_lab_down, lab_name)
        try:
            lab = self._lab(lab_name)
            done = Orchestrator(lab, accel="tcg", display="none").reset([n.id for n in lab.node_list()])
        except (OrchestratorError, Exception) as exc:  # noqa: BLE001 - said in the report
            return f"could not reset {lab_name}: {exc}"
        if done:
            self.say(f"    fresh: {', '.join(done)}")
        return ""

    def running(self, lab_name: str) -> set[str]:
        from . import state
        st = state.load(lab_name)
        return set(st.running()) if st else set()

    def up(self, lab_name: str, nodes: list[str]) -> str:
        """`winlab lab up --only` the item's machines; machines it does not
        need are suspended when the PC has no memory for both."""
        from . import cli
        rc = self._quiet(cli.cmd_lab_up, lab_name, False, self.accel, self.display, only=nodes or None)
        if rc == 0:
            return ""
        others = sorted(self.running(lab_name) - set(nodes) - {"fabric"})
        if others:
            self.say(f"    suspending {', '.join(others)} to make room")
            self._quiet(cli.cmd_lab_suspend, lab_name, others)
            rc = self._quiet(cli.cmd_lab_up, lab_name, False, self.accel, self.display, only=nodes or None)
            if rc == 0:
                return ""
        rc = self._quiet(cli.cmd_lab_up, lab_name, False, self.accel, self.display, only=nodes or None, force=True)
        return "" if rc == 0 else f"`winlab lab up {lab_name}` failed (rc={rc})"

    def down(self, lab_name: str) -> None:
        from . import cli
        self._quiet(cli.cmd_lab_down, lab_name)

    def wait_agent(self, lab_name: str, node: str, timeout: float = BOOT_TIMEOUT) -> str:
        from .guestctl import GuestError
        try:
            ch = self.channel(lab_name, node)
        except Exception as exc:  # noqa: BLE001
            return f"{node}: {exc}"
        try:
            ch.wait_responsive(shell=self.shell_of(lab_name, node), timeout=timeout)
            return ""
        except GuestError as exc:
            return f"{node} did not answer: {exc}"
        finally:
            ch.close()

    def shell_of(self, lab_name: str, node: str) -> str:
        if node == "fabric":
            return "sh"
        try:
            n = self._lab(lab_name).nodes.get(node)
        except Exception:  # noqa: BLE001
            n = None
        return "sh" if n is not None and n.kind == "linux" else "powershell"

    def checkpoint(self, lab_name: str, tag: str = CHECKPOINT) -> bool:
        if not self.checkpoints:
            return False
        from . import snapshots
        from .images import ImageError
        try:
            snapshots.save(lab_name, tag)
            return True
        except (ImageError, OSError, Exception) as exc:  # noqa: BLE001 - the run goes on without one
            self.say(f"    checkpoint not taken: {exc}")
            return False

    def restore(self, lab_name: str, tag: str = CHECKPOINT) -> str:
        from . import snapshots
        try:
            done = snapshots.restore(lab_name, tag)
        except Exception as exc:  # noqa: BLE001
            return f"could not restore checkpoint {tag!r}: {exc}"
        self.say(f"    restored checkpoint {tag!r} on {', '.join(done)}")
        return ""

    def clean(self, lab_name: str) -> None:
        """A lab whose lessons all passed: down, and its disks given back."""
        from .orchestrator import Orchestrator
        self.down(lab_name)
        try:
            lab = self._lab(lab_name)
            Orchestrator(lab, accel="tcg", display="none").reset([n.id for n in lab.node_list()])
        except Exception:  # noqa: BLE001 - only disk space
            pass

    # ---- the guests
    def channel(self, lab_name: str, node: str):
        """The serial channel exercises.grade uses (a connected GuestChannel)."""
        from . import exercises
        return exercises._channel_for(lab_name, node)

    def console(self, lab_name: str, device: str):
        """The device's console as the desktop's cable gives it (devcli.Console)."""
        from . import devcli
        return devcli.Console(_Dash(lab_name), device)

    def winlab(self, argv: list[str], stdin: str = "") -> tuple[int, str]:
        """One `winlab` command, in this process. A command that reads a
        secret from standard input (--stdin) gets the lab's."""
        from . import cli
        if argv[:2] in (["lab", "up"], ["lab", "resume"]) and "--display" not in argv:
            argv = [*argv, "--display", self.display]   # the self-test's screens, not a window each
        buf = io.StringIO()
        saved = sys.stdin
        sys.stdin = io.StringIO(stdin + "\n")
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                rc = cli.main(argv)
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 2
            finally:
                sys.stdin = saved
        return int(rc or 0), buf.getvalue()

    # ---- grading and problems
    def grade(self, ex, lab_name: str):
        from . import exercises
        return exercises.grade(ex, lab_name)

    def problem_params(self, lab_name: str, node: str) -> dict:
        from . import guestfaults
        lab = self._lab(lab_name)
        out = guestfaults.lab_params(lab)
        nd = lab.nodes.get(node)
        if nd is not None:
            out.setdefault("node", nd.hostname or nd.id)
        return out

    def problem(self, action: str, lab_name: str, scenario: str, node: str):
        """break | verify | clear a guest problem: problemengine, as `winlab break` does."""
        from . import guestfaults as gf
        from . import problemengine as pe
        params = self.problem_params(lab_name, node)
        f = gf.SCENARIOS[scenario]
        if f.host and action != "verify":
            ok, msg = gf.host_break(scenario, lab_name, node, action == "clear", say=lambda s: None)
            return pe.Outcome(ok, pe.BROKEN if action == "break" else pe.RESTORED, msg, broken=action == "break")
        run = pe.guest_runner(lab_name)
        if action == "break":
            return pe.apply_break(run, lab_name, scenario, node, params)
        if action == "clear":
            return pe.restore(run, lab_name, scenario, node, params)
        return pe.verify_fix(run, lab_name, scenario, node, params)

    def fault(self, lab_name: str, scenario: str, on: str, clear: bool) -> tuple[int, str]:
        argv = ["net", lab_name, "fault", scenario] + (["--on", on] if on else []) + (["--clear"] if clear else [])
        return self.winlab(argv)


class _Dash:
    """What devcli.Console reads of the desktop: the lab, its plan, reload."""

    def __init__(self, lab_name: str) -> None:
        from . import workbench
        self.name = lab_name
        self.wb_live = workbench.Live()
        self.reload()

    def reload(self) -> None:
        from . import netplan, schema
        self.lab = schema.load(self.name)
        self.plan = netplan.compile_topology(self.lab, check_ports=False)


# --------------------------------------------------------------------------
# Running a solution
# --------------------------------------------------------------------------

def fill(script: str, lab_name: str, secret: str, workdir: str = "") -> str:
    """The placeholders a solution uses, filled the way a check's are: the
    student's names, the host's values, and the lab's generated secret."""
    from . import exercises, naming
    script = naming.for_lab(lab_name).code(script)
    script = exercises.with_host_values(script, lab_name)
    script = script.replace("{{winlab:lab-secret}}", secret).replace("{{winlab:workdir}}", workdir)
    if "{{winlab:bmc-tag:" in script:
        import re
        from . import power, schema
        lab = schema.load(lab_name)
        nodes = lab.nodes

        def _tag(m):
            node = nodes.get(m.group(1))
            return power.tag(node, lab_name) if node is not None else m.group(0)
        script = re.sub(r"\{\{winlab:bmc-tag:([A-Za-z0-9_-]+)\}\}", _tag, script)
    return script


def _typed(ln: str) -> str:
    """`<enter>` is an empty line (a prompt's default), `<break>` the
    console's Break (Ctrl+C while a device starts: its boot monitor)."""
    from . import iosboot
    low = ln.lower()
    if low in ("<enter>", "<return>"):
        return ""
    if low == "<break>":
        return iosboot.BREAK
    return ln


def console_lines(con, lines: list[str]) -> tuple[bool, str]:
    """Types each line at the device's console; (False, why) at the first
    one it does not take. A device that starts without a configuration
    offers its setup dialog first: answered no, as an admin does."""
    out = con.banner() or ""
    if "initial configuration dialog" in (con.prompt() or ""):
        out += (con.run("no") or "") + (con.run("") or "")
    for ln in lines:
        typed = _typed(ln)
        try:
            said = con.run(typed) or ""
        except Exception as exc:  # noqa: BLE001 - the line failed, said in the report
            return False, f"{ln!r}: {exc}"
        out += said
        bad = next((m for m in CONSOLE_ERRORS if m in said), "")
        if bad:
            return False, f"{ln!r}: {said.strip()[:300]}"
    return True, out[-300:]


def run_step(env: Env, lab_name: str, step: "solutions.Step", secret: str) -> tuple[bool, str]:
    """One solution step on the lab: (done, what happened)."""
    from .guestctl import GuestError, GuestRebooted
    env.workdir.mkdir(parents=True, exist_ok=True)
    script = fill(step.script, lab_name, secret, str(env.workdir))
    lines = [ln.strip() for ln in script.splitlines() if ln.strip()]
    if step.shell == "console":
        try:
            con = env.console(lab_name, step.node)
        except Exception as exc:  # noqa: BLE001
            return False, f"console {step.node}: {exc}"
        ok, detail = console_lines(con, lines)
    elif step.shell == "winlab":
        ok, detail = True, ""
        for ln in lines:
            rc, out = env.winlab(shlex.split(ln), stdin=secret)
            detail = out.strip()[-300:]
            if rc != 0:
                ok, detail = False, f"winlab {ln}: rc={rc} {detail}"
                break
    else:
        try:
            ch = env.channel(lab_name, step.node)
        except Exception as exc:  # noqa: BLE001
            return False, f"{step.node}: {exc}"
        rebooted = False
        try:
            try:
                res = ch.run(script, shell=step.shell, timeout=step.timeout, reboot_ok=step.reboot)
                ok = res.rc == 0
                detail = ((res.err if not ok and res.err.strip() else res.out) or f"rc={res.rc}").strip()[-300:]
                if not ok:
                    detail = f"rc={res.rc}: {detail}"
            except GuestRebooted:
                ok, detail, rebooted = True, "restarted", True
            if ok and step.reboot and not rebooted:
                ch.wait_for_reboot(timeout=REBOOT_TIMEOUT)
        except GuestError as exc:
            return False, f"{step.node}: {exc}"
        finally:
            ch.close()
        if ok and step.reboot:
            why = env.wait_agent(lab_name, step.node, timeout=REBOOT_TIMEOUT)
            if why:
                return False, why
    if ok and step.wait:
        env.sleep(step.wait)
    return ok, detail


def write_files(env: Env, lab_name: str, sol, secret: str) -> None:
    """A solution's [files], placeholders filled, into the work folder."""
    for rel, text in (getattr(sol, "files", None) or {}).items():
        dest = env.workdir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(fill(text, lab_name, secret, str(env.workdir)), encoding="utf-8", newline="\n")


def run_solution(env: Env, lab_name: str, sol, secret: str) -> dict:
    for i, st in enumerate(sol.steps, 1):
        env.say(f"    step {i}/{len(sol.steps)} on {st.node} ({st.shell})")
        ok, detail = run_step(env, lab_name, st, secret)
        if not ok:
            return {"ok": False, "step": i, "node": st.node, "shell": st.shell, "detail": detail}
    return {"ok": True}


# --------------------------------------------------------------------------
# One item
# --------------------------------------------------------------------------

def _grade_dict(g) -> list[dict]:
    return [{"check": r.check.name, "passed": bool(r.passed), "detail": r.detail} for r in g.results]


def _machines_for(ex, sol) -> list[str]:
    from . import exercises
    nodes = list(ex.needed_nodes()) if ex is not None else []
    for st in (sol.steps if sol else []):
        if st.shell in ("powershell", "sh") and st.node not in nodes and st.node not in ("fabric", exercises.WINLAB):
            nodes.append(st.node)
    return nodes


def _agents_for(ex, sol) -> list[str]:
    """The machines whose agent the item talks to: those a check or a step runs on."""
    from . import exercises
    out: list[str] = []
    for c in (ex.checks if ex is not None else []):
        if c.node not in out and c.node not in (exercises.WINLAB,):
            out.append(c.node)
    for st in (sol.steps if sol else []):
        if st.shell in ("powershell", "sh") and st.node not in out:
            out.append(st.node)
    return out


def _bring_up(env: Env, lab_name: str, nodes: list[str], agents: list[str]) -> str:
    why = env.up(lab_name, nodes)
    if why:
        return why
    for n in agents:
        why = env.wait_agent(lab_name, n)
        if why:
            return why
    return ""


def run_item(env: Env, it: Item) -> dict:
    """Proves one item; the result dict for the report."""
    from . import exercises
    if it.kind == "skip":
        return {"status": SKIPPED, "why": it.reason}
    ex = sol = None
    notes: list[str] = []
    if it.exercise:
        try:
            ex = exercises.load(it.exercise)
        except exercises.ExerciseError as exc:
            return {"status": SKIPPED, "why": f"exercise {it.exercise}: {exc}"}
        try:
            sol = solutions.load(it.exercise)
        except solutions.SolutionError as exc:
            if it.kind in ("exercise", "setup"):
                return {"status": NO_SOLUTION if it.kind == "exercise" else SKIPPED,
                        "why": f"no worked solution: {exc}"}
            notes.append(f"the exercise is not run: {exc}")
            ex = None
    nodes = _machines_for(ex, sol)
    if it.node and it.node not in nodes:
        nodes.append(it.node)
    agents = _agents_for(ex, sol) + ([it.node] if it.node and it.node not in _agents_for(ex, sol) else [])
    agents = [n for n in agents if n != "fabric"]
    cold = set(sol.cold) if sol is not None else set()
    nodes = [n for n in nodes if n not in cold]
    agents = [n for n in agents if n not in cold]
    why = _bring_up(env, it.lab, nodes, agents)
    if why:
        return {"status": NOT_STARTED, "why": why}
    secret = env.secret(it.lab)
    if sol is not None:
        write_files(env, it.lab, sol, secret)

    if it.kind == "setup":
        if sol.restore_after:
            return {"status": SKIPPED, "why": "its lab is put back after it: nothing it does stays for later lessons"}
        r = run_solution(env, it.lab, solutions.Solution(sol.exercise, sol.setup + sol.steps + sol.cleanup), secret)
        return {"status": OK if r["ok"] else STEP_FAILED, "solution": r}

    out: dict = {"notes": notes}
    if it.kind == "problem":
        # The problem mechanism: break, it shows; put back, it is gone.
        p = _problem_cycle(env, it)
        out["problem"] = p
        if not p["ok"]:
            out["status"] = PROBLEM_FAILED
            return out
        if ex is None:
            out["status"] = NO_SOLUTION if notes else OK
            if notes:
                out["why"] = notes[0]
            return out
        # The exercise is graded on the broken machine, as the student meets it.
        b = env.problem("break", it.lab, it.problem, it.node)
        out["problem"]["break_again"] = b.message
        if not b.ok:
            out["status"] = PROBLEM_FAILED
            out["why"] = f"the second break failed: {b.message}"
            return out
        if b.status == "restarting":
            env.wait_agent(it.lab, it.node, timeout=REBOOT_TIMEOUT)
    if it.kind == "fault":
        if ex is None:
            return {**out, "status": NO_SOLUTION if notes else SKIPPED,
                    "why": notes[0] if notes else "a network fault lesson with no exercise to grade"}
        rc, said = env.fault(it.lab, it.fault, it.fault_on, clear=False)
        out["fault_break"] = said.strip()[-300:]
        if rc != 0:
            out["status"] = PROBLEM_FAILED
            out["why"] = f"the network fault {it.fault} did not break: {said.strip()[-200:]}"
            return out
    if ex is None:
        out["status"] = OK
        return out

    before_tag = f"{CHECKPOINT}-before"
    kept = sol.restore_after and env.checkpoint(it.lab, before_tag)
    out.update(_exercise_cycle(env, it, ex, sol, secret))
    if sol.cleanup:
        r = run_solution(env, it.lab, solutions.Solution(sol.exercise, sol.cleanup), secret)
        if not r["ok"]:
            out.setdefault("notes", []).append(f"cleanup step {r['step']} failed: {r['detail']}")
    if sol.restore_after:
        why = env.restore(it.lab, before_tag) if kept else "no checkpoint was taken before it"
        if why:
            out.setdefault("notes", []).append(f"the lab could not be put back after it: {why}")
    if it.kind == "fault":
        rc, said = env.fault(it.lab, it.fault, it.fault_on, clear=True)
        g = env.grade(ex, it.lab)
        out["after_clear"] = _grade_dict(g)
        if out["status"] == OK and (rc != 0 or not g.passed):
            out["status"] = PROBLEM_FAILED
            out["why"] = ("clearing the fault failed: " + said.strip()[-200:]) if rc != 0 else \
                "after the fault is cleared the exercise no longer passes"
    return out


def _problem_cycle(env: Env, it: Item) -> dict:
    from . import problemengine as pe
    out: dict = {"ok": False}
    b = env.problem("break", it.lab, it.problem, it.node)
    out["break"] = f"{b.status}: {b.message}"
    if not b.ok:
        out["why"] = f"break: {b.message}"
        return out
    if b.status == pe.RESTARTING:
        env.wait_agent(it.lab, it.node, timeout=REBOOT_TIMEOUT)
    v = env.problem("verify", it.lab, it.problem, it.node)
    out["verify_broken"] = f"{v.status}: {v.message}"
    if v.status != pe.NOT_FIXED:
        out["why"] = f"after the break the problem's check says {v.status}, not not-fixed"
        env.problem("clear", it.lab, it.problem, it.node)
        return out
    c = env.problem("clear", it.lab, it.problem, it.node)
    out["clear"] = f"{c.status}: {c.message}"
    if not c.ok:
        out["why"] = f"fix it for me: {c.message}"
        return out
    if pe.restarts(it.problem):
        env.wait_agent(it.lab, it.node, timeout=REBOOT_TIMEOUT)
    v = env.problem("verify", it.lab, it.problem, it.node)
    out["verify_fixed"] = f"{v.status}: {v.message}"
    if v.status != pe.FIXED:
        out["why"] = f"after fix it for me the problem's check says {v.status}, not fixed"
        return out
    out["ok"] = True
    return out


def _exercise_cycle(env: Env, it: Item, ex, sol, secret: str) -> dict:
    out: dict = {}
    if sol.setup:
        r = run_solution(env, it.lab, solutions.Solution(sol.exercise, sol.setup), secret)
        if not r["ok"]:
            return {"status": STEP_FAILED, "solution": r,
                    "why": f"setup step {r['step']} on {r['node']}: {r['detail']}"}
    before = env.grade(ex, it.lab)
    out["before"] = _grade_dict(before)
    early = [r.check.name for r in before.results if r.passed]
    if early:
        out["passes_before_work"] = early
    r = run_solution(env, it.lab, sol, secret)
    out["solution"] = r
    after = env.grade(ex, it.lab)
    out["after"] = _grade_dict(after)
    failed = [x for x in out["after"] if not x["passed"]]
    if not r["ok"]:
        out["status"] = STEP_FAILED
        out["why"] = f"step {r['step']} on {r['node']}: {r['detail']}"
    elif failed:
        out["status"] = CHECK_FAILED
        out["why"] = "; ".join(f"{x['check']}: {x['detail']}" for x in failed)[:1000]
    elif before.passed:
        out["status"] = PASSES_BEFORE
        out["why"] = "every check passed on the fresh lab, before the solution ran"
    else:
        out["status"] = OK
    return out


# --------------------------------------------------------------------------
# The run: state on disk, resumable
# --------------------------------------------------------------------------

def runs_dir() -> Path:
    return paths.VAR / "selftest"


def _write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


class Run:
    def __init__(self, folder: Path, items: list[Item], meta: dict) -> None:
        self.folder = folder
        self.items = items
        self.meta = meta

    @classmethod
    def new(cls, items: list[Item], meta: dict, when: float | None = None) -> "Run":
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(when or time.time()))
        folder = runs_dir() / stamp
        n = 1
        while folder.exists():
            n += 1
            folder = runs_dir() / f"{stamp}-{n}"
        folder.mkdir(parents=True)
        run = cls(folder, items, {**meta, "started": time.time(), "finished": 0, "labs": {}})
        run.save()
        return run

    @classmethod
    def load(cls, folder: Path) -> "Run":
        raw = json.loads((folder / "state.json").read_text(encoding="utf-8"))
        items = [Item(**it) for it in raw["items"]]
        return cls(folder, items, raw["meta"])

    @staticmethod
    def latest_unfinished() -> Path | None:
        if not runs_dir().is_dir():
            return None
        for d in sorted(runs_dir().iterdir(), reverse=True):
            try:
                raw = json.loads((d / "state.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not raw.get("meta", {}).get("finished"):
                return d
        return None

    def lab_meta(self, lab: str) -> dict:
        return self.meta.setdefault("labs", {}).setdefault(lab, {"started": False, "checkpoint": False})

    def save(self) -> None:
        _write(self.folder / "state.json",
               json.dumps({"meta": self.meta, "items": [asdict(i) for i in self.items]}, indent=1))
        _write(self.folder / "report.json", json.dumps(report(self), indent=1))
        _write(self.folder / "report.txt", render_report(self))


def report(run: Run) -> dict:
    counts: dict[str, int] = {}
    for it in run.items:
        if it.status == "done":
            s = it.result.get("status", "")
            counts[s] = counts.get(s, 0) + 1
    return {"started": run.meta.get("started"), "finished": run.meta.get("finished"),
            "selection": run.meta.get("selection", ""), "counts": counts,
            "pending": sum(1 for it in run.items if it.status != "done"),
            "lessons": [{"key": it.key, "lesson": it.lesson, "exercise": it.exercise, "lab": it.lab,
                         "kind": it.kind, "problem": it.problem or it.fault, "state": it.status,
                         **it.result} for it in run.items]}


def _line(it: Item) -> str:
    r = it.result
    what = it.lesson or it.exercise
    if it.status != "done":
        return f"  {what:<44} {it.status}"
    s = r.get("status", "")
    line = f"  {what:<44} {s}"
    if s in (CHECK_FAILED,):
        failed = [x for x in r.get("after", []) if not x["passed"]]
        line += "".join(f"\n      check '{x['check']}': {x['detail']}" for x in failed)
    elif s == STEP_FAILED:
        sol = r.get("solution", {})
        line += f"\n      step {sol.get('step')} on {sol.get('node')} ({sol.get('shell')}): {sol.get('detail', '')}"
    elif r.get("why"):
        line += f": {r['why']}"
    early = r.get("passes_before_work")
    if early and s != PASSES_BEFORE:
        line += f"\n      passes before any work: {', '.join(early)}"
    return line


def render_report(run: Run) -> str:
    rep = report(run)
    out = [f"winlab self-test, started {time.strftime('%Y-%m-%d %H:%M', time.localtime(run.meta.get('started') or 0))}"
           + (f", finished {time.strftime('%Y-%m-%d %H:%M', time.localtime(run.meta['finished']))}"
              if run.meta.get("finished") else ", not finished"),
           f"selection: {run.meta.get('selection', '')}", ""]
    lab = None
    for it in run.items:
        if it.lab != lab:
            lab = it.lab
            out.append(f"lab {lab or '(none)'}")
        out.append(_line(it))
    out.append("")
    out.append(summary_line(rep))
    return "\n".join(out) + "\n"


def summary_line(rep: dict) -> str:
    parts = [f"{rep['counts'][s]} {s}" for s in STATUSES if rep["counts"].get(s)]
    if rep.get("pending"):
        parts.append(f"{rep['pending']} not run yet")
    return "summary: " + (", ".join(parts) or "nothing ran")


def execute(env: Env, run: Run) -> int:
    """Works through the run's items, saving after each; returns 0 when
    every item is ok or skipped."""
    labs_done: dict[str, bool] = {}
    for idx, it in enumerate(run.items):
        if it.status == "done":
            continue
        lm = run.lab_meta(it.lab) if it.lab else {}
        if it.lab and it.kind != "skip":
            if not lm.get("started"):
                env.say(f"lab {it.lab}: starting empty")
                why = env.empty_lab(it.lab)
                lm.update(started=True, checkpoint=False)
                run.save()
                if why:
                    env.say(f"    {why}")
            elif it.status == "running" or not env.running(it.lab):
                # Back after a stop: the lab as the last finished item left it.
                env.say(f"lab {it.lab}: resuming")
                if lm.get("checkpoint"):
                    why = env.restore(it.lab)
                    if why:
                        env.say(f"    {why}")
                else:
                    _replay(env, run, idx)
        label = it.lesson or it.exercise
        env.say(f"  {label} [{it.kind}]")
        it.status = "running"
        run.save()
        try:
            it.result = run_item(env, it)
        except Exception as exc:  # noqa: BLE001 - one lesson's crash is its result, the run goes on
            it.result = {"status": NOT_STARTED, "why": f"{type(exc).__name__}: {exc}"}
        it.status = "done"
        s = it.result.get("status", "")
        env.say(f"    -> {s}" + (f": {it.result['why']}" if it.result.get("why") and s not in GOOD else ""))
        if it.lab and it.kind != "skip" and s != NOT_STARTED:
            lm["checkpoint"] = env.checkpoint(it.lab) or lm.get("checkpoint", False)
        labs_done[it.lab] = labs_done.get(it.lab, True) and s in GOOD
        run.save()
        nxt = run.items[idx + 1].lab if idx + 1 < len(run.items) else None
        if it.lab and nxt != it.lab and not any(x.lab == it.lab and x.status != "done" for x in run.items):
            # The lab's last item: free the PC for the next lab.
            if all(x.result.get("status") in GOOD for x in run.items if x.lab == it.lab) and run.meta.get("clean", True):
                env.say(f"lab {it.lab}: every lesson passed, its disks are given back")
                env.clean(it.lab)
            else:
                env.say(f"lab {it.lab}: kept as it is, for a look at what failed (`winlab lab up {it.lab}`)")
                env.down(it.lab)
    run.meta["finished"] = time.time()
    run.save()
    rep = report(run)
    env.say("")
    env.say(summary_line(rep))
    env.say(f"report: {run.folder / 'report.txt'}")
    bad = sum(n for s, n in rep["counts"].items() if s not in GOOD)
    return 0 if not bad else 1


def _replay(env: Env, run: Run, upto: int) -> None:
    """No checkpoint to go back to: the lab is built again from empty by
    the solutions of what already ran on it."""
    lab = run.items[upto].lab
    done = [x for x in run.items[:upto] if x.lab == lab and x.status == "done" and x.exercise
            and x.kind != "skip"]
    env.say(f"    no checkpoint: building {lab} again from empty ({len(done)} solution(s))")
    env.empty_lab(lab)
    for x in done:
        r = run_item(env, Item(f"setup:{x.key}", lab, "setup", lesson=x.lesson, exercise=x.exercise))
        if r.get("status") != OK:
            env.say(f"    setup {x.key}: {r.get('status')}: {r.get('why', '')}")


# --------------------------------------------------------------------------
# Dry run
# --------------------------------------------------------------------------

def render_plan(items: list[Item]) -> str:
    """What a run would do, read from the content alone: no machine starts."""
    from . import exercises
    out: list[str] = []
    lab = None
    counts = {"exercise": 0, "problem": 0, "fault": 0, "setup": 0, "skip": 0, "missing": 0}
    for it in items:
        if it.lab != lab:
            lab = it.lab
            out.append(f"lab {lab or '(none)'}: starts empty")
        what = it.lesson or it.exercise
        counts[it.kind] = counts.get(it.kind, 0) + 1
        if it.kind == "skip":
            out.append(f"  {what:<44} skip: {it.reason}")
            continue
        steps = ""
        nodes: list[str] = []
        if it.exercise:
            try:
                ex = exercises.load(it.exercise)
                nodes = ex.needed_nodes()
            except exercises.ExerciseError as exc:
                steps = f"exercise does not load: {exc}"
            if not steps:
                if solutions.exists(it.exercise):
                    try:
                        steps = f"{len(solutions.load(it.exercise).steps)} solution step(s)"
                    except solutions.SolutionError as exc:
                        steps = f"solution does not load: {exc}"
                else:
                    steps = "NO SOLUTION"
                    counts["missing"] += 1
        flow = {"exercise": "grade (must fail), solution, grade (must pass)",
                "setup": "solution only (setup for what follows)",
                "problem": f"break {it.problem} on {it.node}, verify, clear, verify"
                           + (", break, grade, solution, grade" if it.exercise else ""),
                "fault": f"break network fault {it.fault} on {it.fault_on or 'the first segment'}, grade, "
                         "solution, grade, clear, grade"}[it.kind]
        out.append(f"  {what:<44} {flow}")
        if it.exercise:
            out.append(f"  {'':<44} exercise {it.exercise}: {steps}; machines {', '.join(nodes) or '-'}")
    out.append("")
    out.append(f"{counts['exercise']} exercise(s), {counts['problem']} problem lesson(s), {counts['fault']} "
               f"network fault lesson(s), {counts['setup']} setup step(s), {counts['skip']} skipped, "
               f"{counts['missing']} without a worked solution")
    out.append("dry run: nothing was started.")
    return "\n".join(out)


# --------------------------------------------------------------------------
# The command line
# --------------------------------------------------------------------------

def add_cli(sub) -> None:
    p = sub.add_parser("selftest", help="prove every lesson on this PC: fresh lab, solution, grade (overnight)")
    p.add_argument("lab", nargs="?", default="", help="every lesson of this lab")
    p.add_argument("--lesson", default="", help="one lesson (the lab's earlier lessons run first as setup)")
    p.add_argument("--exercise", default="", help="one exercise (the same)")
    p.add_argument("--all", action="store_true", help="every lab, every lesson")
    p.add_argument("--only", choices=("problems", "exercises"), default="", help="only one kind")
    p.add_argument("--resume", nargs="?", const="latest", default="",
                   help="carry on the last unfinished run (or the run folder given)")
    p.add_argument("--dry-run", action="store_true", help="print the plan; nothing starts")
    p.add_argument("--no-setup", action="store_true", help="with --lesson/--exercise: do not run the earlier lessons first")
    p.add_argument("--keep", action="store_true", help="keep every lab's disks when its lessons pass")
    p.add_argument("--no-checkpoint", action="store_true", help="no checkpoint after each lesson (resume rebuilds)")
    p.add_argument("--accel", default="", help="override the accelerator (whpx, kvm, tcg)")
    p.add_argument("--display", choices=("window", "none"), default="none")


def run_cli(args, env: Env | None = None) -> int:
    env = env or Env(accel=args.accel, display=args.display, checkpoints=not args.no_checkpoint)
    try:
        if args.resume:
            folder = Run.latest_unfinished() if args.resume == "latest" else Path(args.resume)
            if folder is None or not (folder / "state.json").is_file():
                print("no unfinished self-test run to resume", file=sys.stderr)
                return 2
            run = Run.load(folder)
            left = sum(1 for it in run.items if it.status != "done")
            print(f"resuming {folder}: {left} of {len(run.items)} left")
            return execute(env, run)
        items = select(full_plan(), lab=args.lab, lesson=args.lesson, exercise=args.exercise,
                       everything=args.all, only=args.only, setup=not args.no_setup)
    except SelftestError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(render_plan(items))
        return 0
    selection = ("all" if args.all else args.lab or f"lesson {args.lesson}" if args.lesson
                 else f"exercise {args.exercise}") + (f", only {args.only}" if args.only else "")
    run = Run.new(items, {"selection": selection, "clean": not args.keep})
    print(f"self-test of {selection}: {len(items)} item(s); state and report in {run.folder}")
    print("stop it any time; `winlab selftest --resume` carries on from the last lesson that finished")
    return execute(env, run)


# --------------------------------------------------------------------------
# Offline checks of a solution (solutions.problems uses these)
# --------------------------------------------------------------------------

def console_replay(lab_name: str, device: str, lines: list[str]) -> list[str]:
    """Every console line typed at an offline copy of the device (the lab
    file only, nothing running): the lines it does not take."""
    import copy
    from . import devcli, netplan, schema
    from .tftpcopy import _Shadow
    lab = copy.deepcopy(schema.load(lab_name))
    try:
        plan = netplan.compile_topology(lab, check_ports=False)
    except Exception:  # noqa: BLE001
        plan = None
    con = devcli.Console(_Shadow(lab, plan), device,
                         runner_factory=lambda: ((lambda cmd, timeout=60: ""), ""), link=lambda l, up: None)
    con._save = lambda live=True: ""
    con.powered = lambda: True
    con._fresh = lambda: None
    con._running = lambda: {"fabric", *lab.nodes}
    bad: list[str] = []
    try:
        con.banner()
    except Exception:  # noqa: BLE001 - the banner reads the running router; offline it says nothing
        con.s.mode = "user"
    if con.s.mode == "idle":
        con.s.mode = "user"
    for ln in lines:
        if ln.lower() == "<break>":
            break   # what follows goes to a boot monitor, which only a starting device has
        typed = _typed(ln)
        try:
            said = con.run(typed) or ""
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{ln!r}: {type(exc).__name__}: {exc}")
            continue
        m = next((m for m in CONSOLE_ERRORS if m in said), "")
        if m:
            bad.append(f"{ln!r}: {said.strip().splitlines()[-1] if said.strip() else m}")
    return bad


def sh_syntax(script: str) -> str:
    """'' when /bin/sh parses the script (sh -n), else what it said; '' too
    on a PC without /bin/sh."""
    sh = shutil.which("sh") or ("/bin/sh" if Path("/bin/sh").exists() else "")
    if not sh:
        return ""
    try:
        r = subprocess.run([sh, "-n"], input=script, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return ""
    return "" if r.returncode == 0 else (r.stderr.strip() or f"sh -n rc={r.returncode}")[:300]
