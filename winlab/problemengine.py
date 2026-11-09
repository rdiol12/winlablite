"""The problems engine: breaks a guest problem, puts it back and checks a
fix, the same careful way for the Problems window, problem lessons and
`winlab break`.

guestfaults.py is the catalog (what each problem breaks, how to undo it,
the check that prints True once the machine is healthy). This module is
how winlab uses it, so that a student never chases a problem that is not
there, and a machine is never left half broken:

- Nothing runs with a hole in it. Every {name} a command uses must have a
  value from the lab; a lab without a mail server cannot break the mail
  server, and says so, instead of sending a command with an empty address.
- Health first. Before a break the problem's own check runs. A machine
  that does not answer is not touched. A machine that already fails the
  check is broken anyway (many checks ask for more than a fresh machine
  has: the fix is part of the lesson), but then winlab cannot tell
  whether the break took, so it does not judge that.
- Idempotent. A problem already broken on the machine is not broken a
  second time (the second apply could stash the stash); putting back a
  machine that is already healthy is a no-op that succeeds.
- The break must take. When the machine was healthy before, the check
  runs again after the apply (a few times, as a hog needs seconds to show);
  a machine that still checks out healthy is put back and the student is
  told, instead of hunting a problem that was never there. A break that
  restarts the machine is trusted (the check would race the restart).
- A failed break is rolled back. When the apply fails part way, the undo
  runs at once so nothing is left half broken; when that fails too the
  student is told to press Give up.
- A check that cannot run is not a failed try. A machine that does not
  answer, or a check that times out, says so and counts nothing.
- One action per problem and machine at a time: a second Break pressed
  while the first still runs is told to wait.
- Every action is logged with the raw output to var/labs/<lab>/problems.log
  (JSON lines) for support; the student's messages never carry that raw
  output (it often names the cause).

The messages are plain English; the desktop's translator turns them into
Hebrew, Arabic or Spanish from content/i18n/<lang>.json, which holds each
message as a {} pattern.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from . import guestfaults as gf

# {name} tokens in the catalog that are not parameters: awk and curl
# formats, bcdedit's {current}, a PowerShell format item. Everything else
# in braces must be a parameter with a value.
LITERAL_TOKENS = frozenset({"n", "end", "http_code", "print", "mb", "current"})
# Parameters that are not in guestfaults.DEFAULTS because the caller fills
# them: the lab's clock now (timesync.fault_params), the broken machine.
RUNTIME_PARAMS = frozenset({"labtime", "node"})

_TOKEN = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_RESTART = re.compile(r"shutdown(\.exe)?\s+[/-]r\b|Restart-Computer|\breboot\b|Stop-Computer|shutdown -h", re.I)
# Seconds between the checks after a break that still checks out healthy:
# some problems need a moment to show (a hog's CPU time, a service stopping).
SETTLE: tuple[float, ...] = (3, 10, 20)

# Outcome statuses.
BROKEN = "broken"
ALREADY_BROKEN = "already-broken"
RESTARTING = "restarting"
DID_NOT_TAKE = "did-not-take"
REFUSED = "refused"
UNREACHABLE = "unreachable"
MISSING_VALUES = "missing-values"
BUSY = "busy"
RESTORED = "restored"
RESTORE_INCOMPLETE = "restore-incomplete"
FIXED = "fixed"
NOT_FIXED = "not-fixed"
CHECK_ERROR = "check-error"


@dataclass
class Ran:
    """One command on a guest: reached says whether the machine answered at
    all (a timeout or a dead channel is not an answer)."""
    reached: bool
    ok: bool = False
    out: str = ""
    err: str = ""


Runner = Callable[[str, str, str], Ran]


@dataclass
class Outcome:
    ok: bool                # the action did what was asked
    status: str
    message: str            # for the student: never the raw output of a check
    broken: bool = False    # the problem is (still) in place on the machine afterwards
    detail: str = ""        # raw output, for the log only
    steps: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "status": self.status, "message": self.message, "broken": self.broken}


# --- what a scenario needs ------------------------------------------------

def tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(text or ""))


def scenario_tokens(scenario_id: str) -> set[str]:
    """Every {name} the scenario's commands, words and hints use."""
    f = gf.SCENARIOS[scenario_id]
    out = set()
    for t in (f.apply, f.clear, f.verify, f.title, f.symptom, f.teaches, *f.hints):
        out |= tokens(t)
    return out - LITERAL_TOKENS


def unknown_tokens(scenario_id: str) -> list[str]:
    """Names the scenario uses that no lab could ever fill: a typo such as
    {subzon} would otherwise reach the student or the guest as raw text."""
    return sorted(scenario_tokens(scenario_id) - set(gf.DEFAULTS) - RUNTIME_PARAMS)


def missing_values(scenario_id: str, params: dict[str, str], fields=("apply", "clear", "verify")) -> list[str]:
    """The parameters the scenario's commands need that have no value here
    (absent, or empty because this lab has no such machine)."""
    f = gf.SCENARIOS[scenario_id]
    values = {**gf.DEFAULTS, **(params or {})}
    need = set()
    for name in fields:
        need |= tokens(getattr(f, name))
    need -= LITERAL_TOKENS
    return sorted(k for k in need if not str(values.get(k, "")).strip())


def restarts(scenario_id: str) -> bool:
    """Whether the break restarts the machine to show the problem."""
    return bool(_RESTART.search(gf.SCENARIOS[scenario_id].apply))


# --- running on a guest ---------------------------------------------------

def guest_runner(lab_name: str, timeout: float = 120) -> Runner:
    """A Runner over the serial agent of a running lab's machines. It never
    raises: an unreachable machine or a timeout is Ran(reached=False)."""
    from . import state
    from .guestctl import GuestChannel, GuestError, GuestRebooted

    def run(node: str, cmd: str, shell: str) -> Ran:
        st = state.load(lab_name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return Ran(False, err=f"{node} is not running")
        try:
            ch = GuestChannel(ns.serial_port).connect(retries=8, delay=2)
        except (GuestError, OSError) as exc:
            return Ran(False, err=str(exc))
        try:
            res = ch.run(cmd, shell=shell, timeout=timeout)
        except GuestRebooted as exc:
            # The command restarted the machine before it could answer.
            return Ran(True, True, "", str(exc))
        except (GuestError, OSError) as exc:
            return Ran(False, err=str(exc))
        finally:
            try:
                ch.close()
            except Exception:  # noqa: BLE001 - closing a dead channel
                pass
        return Ran(True, res.ok, res.out, res.err)
    return run


def _last_line(r: Ran) -> str:
    lines = [ln.strip() for ln in (r.err or r.out or "").strip().splitlines() if ln.strip()]
    return lines[-1][:200] if lines else "no output"


# --- one action at a time per problem and machine -------------------------

_busy: set[tuple[str, str, str]] = set()
_busy_lock = threading.Lock()


def _claim(key: tuple[str, str, str]) -> bool:
    with _busy_lock:
        if key in _busy:
            return False
        _busy.add(key)
        return True


def _release(key: tuple[str, str, str]) -> None:
    with _busy_lock:
        _busy.discard(key)


def _guarded(lab_name: str, scenario_id: str, node: str, action: str, fn) -> Outcome:
    if scenario_id not in gf.SCENARIOS:
        return Outcome(False, REFUSED, f"unknown problem {scenario_id}")
    key = (lab_name, scenario_id, node)
    if not _claim(key):
        return Outcome(False, BUSY, f"winlab is still working on {node}: wait for it to finish, then try again")
    try:
        try:
            out = fn()
        except Exception as exc:  # noqa: BLE001 - a bug must not leave the student guessing
            out = Outcome(False, REFUSED, f"something went wrong on {node}; nothing more was changed: {exc}",
                          detail=repr(exc))
        log(lab_name, action, scenario_id, node, out)
        return out
    finally:
        _release(key)


def log(lab_name: str, action: str, scenario_id: str, node: str, out: Outcome) -> None:
    """Appends one action to var/labs/<lab>/problems.log; never fails."""
    try:
        from . import paths
        p = paths.lab_dir(lab_name) / "problems.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        rec = {"at": round(time.time(), 3), "action": action, "problem": scenario_id, "node": node,
               "status": out.status, "ok": out.ok, "message": out.message, "steps": out.steps,
               "detail": out.detail[-2000:]}
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:  # noqa: BLE001 - the log is for support, never in the way
        pass


# --- the check -----------------------------------------------------------

def check(run: Runner, scenario_id: str, node: str, params: dict[str, str]) -> tuple[str, Ran]:
    """("healthy" | "unhealthy" | "error", what ran). error: the check never
    got an answer (the machine is off, the channel timed out)."""
    cmd, shell, expect = gf.verify_command(scenario_id, params)
    r = run(node, cmd, shell)
    if not r.reached:
        return "error", r
    return ("healthy" if gf.is_fixed(r.out, expect) else "unhealthy"), r


def _undo(run: Runner, scenario_id: str, node: str, params: dict[str, str], steps: list[str]) -> bool:
    """Runs the undo and tells whether the machine checks out healthy after."""
    cmd, shell = gf.build_command(scenario_id, params, clear=True)
    r = run(node, cmd, shell)
    steps.append(f"undo: reached={r.reached} ok={r.ok} {_last_line(r)}")
    if not r.reached:
        return False
    if restarts(scenario_id) or not gf.SCENARIOS[scenario_id].verify:
        return r.ok
    health, c = check(run, scenario_id, node, params)
    steps.append(f"check after undo: {health}")
    return health == "healthy"


# --- break, put back, verify ---------------------------------------------

def apply_break(run: Runner, lab_name: str, scenario_id: str, node: str, params: dict[str, str],
                known_broken: bool = False) -> Outcome:
    """Breaks the problem on node, carefully (see the module doc).
    known_broken: winlab's progress says it is broken there already."""
    def go() -> Outcome:
        steps: list[str] = []
        miss = missing_values(scenario_id, params)
        if miss:
            return Outcome(False, MISSING_VALUES,
                           f"this problem needs {', '.join(miss)}, which this lab does not have: "
                           f"it cannot be broken here")
        symptom = gf.words(scenario_id, params)["symptom"]
        f = gf.SCENARIOS[scenario_id]
        healthy_before = False
        if f.verify:
            health, r = check(run, scenario_id, node, params)
            steps.append(f"check before: {health}")
            if health == "error":
                return Outcome(False, UNREACHABLE, f"could not reach {node}: is it running and signed in? "
                                                   "Nothing was broken", detail=r.err, steps=steps)
            if health == "unhealthy" and known_broken:
                # Broken already: a second apply could stash the stash.
                return Outcome(True, ALREADY_BROKEN,
                               f"{node} already has this problem: find and fix it, or press Give up",
                               broken=True, steps=steps)
            healthy_before = health == "healthy"
        cmd, shell = gf.build_command(scenario_id, params, clear=False)
        r = run(node, cmd, shell)
        steps.append(f"apply: reached={r.reached} ok={r.ok} {_last_line(r)}")
        if not r.reached or not r.ok:
            # Part of it may have run: undo at once so nothing is left half broken.
            back = _undo(run, scenario_id, node, params, steps)
            if not r.reached:
                why = f"lost contact with {node} while breaking it"
            else:
                why = f"{node} refused the break: {_last_line(r)}"
            if back:
                return Outcome(False, UNREACHABLE if not r.reached else REFUSED,
                               f"{why}. winlab put it back as it was", detail=r.out + r.err, steps=steps)
            return Outcome(False, UNREACHABLE if not r.reached else REFUSED,
                           f"{why}, and putting it back did not finish either: press Give up to try again",
                           broken=True, detail=r.out + r.err, steps=steps)
        if restarts(scenario_id):
            return Outcome(True, RESTARTING, f"broke {node}; it restarts to show the problem — symptom: {symptom}",
                           broken=True, steps=steps)
        if healthy_before:
            health, c = check(run, scenario_id, node, params)
            for wait in SETTLE:
                if health != "healthy":
                    break
                time.sleep(wait)   # a CPU hog, a service on its way down
                health, c = check(run, scenario_id, node, params)
            steps.append(f"check after: {health}")
            if health == "healthy":
                back = _undo(run, scenario_id, node, params, steps)
                return Outcome(False, DID_NOT_TAKE,
                               f"the break did not take on {node}: it still checks out healthy"
                               + (", so winlab put it back. There is nothing to fix" if back
                                  else ", and putting it back did not finish: press Give up"),
                               broken=not back, detail=c.out, steps=steps)
        return Outcome(True, BROKEN, f"broke {node} — symptom: {symptom}", broken=True, steps=steps)
    return _guarded(lab_name, scenario_id, node, "break", go)


def restore(run: Runner, lab_name: str, scenario_id: str, node: str, params: dict[str, str]) -> Outcome:
    """Puts the machine back. Safe to repeat: an undo that errors on a
    machine that is already healthy still counts as put back."""
    def go() -> Outcome:
        steps: list[str] = []
        miss = missing_values(scenario_id, params, fields=("clear",))
        if miss:
            return Outcome(False, MISSING_VALUES,
                           f"this problem needs {', '.join(miss)}, which this lab does not have: "
                           f"winlab cannot put it back here", broken=True)
        f = gf.SCENARIOS[scenario_id]
        cmd, shell = gf.build_command(scenario_id, params, clear=True)
        r = run(node, cmd, shell)
        steps.append(f"undo: reached={r.reached} ok={r.ok} {_last_line(r)}")
        if not r.reached:
            return Outcome(False, UNREACHABLE, f"could not reach {node} to put it back: is it running?",
                           broken=True, detail=r.err, steps=steps)
        if restarts(scenario_id) or not f.verify:
            if r.ok:
                return Outcome(True, RESTORED, f"put {node} back as it was", steps=steps)
            return Outcome(False, RESTORE_INCOMPLETE, f"putting {node} back did not finish: {_last_line(r)}",
                           broken=True, detail=r.out + r.err, steps=steps)
        health, c = check(run, scenario_id, node, params)
        steps.append(f"check after undo: {health}")
        if health == "healthy":
            return Outcome(True, RESTORED, f"put {node} back as it was", steps=steps)
        if health == "error":
            return Outcome(r.ok, RESTORED if r.ok else RESTORE_INCOMPLETE,
                           f"put {node} back; the check could not run to confirm it" if r.ok
                           else f"putting {node} back did not finish: {_last_line(r)}",
                           broken=not r.ok, detail=r.out + r.err, steps=steps)
        return Outcome(False, RESTORE_INCOMPLETE,
                       f"winlab ran the undo on {node}, but it still fails the problem's check: "
                       "fix the rest by hand, or press Give up again", broken=True,
                       detail=r.out + r.err + c.out + c.err, steps=steps)
    return _guarded(lab_name, scenario_id, node, "restore", go)


def verify_fix(run: Runner, lab_name: str, scenario_id: str, node: str, params: dict[str, str]) -> Outcome:
    """The student's fix: FIXED, NOT_FIXED, or CHECK_ERROR when the check
    could not run (which must not count as a try)."""
    def go() -> Outcome:
        miss = missing_values(scenario_id, params, fields=("verify",))
        if miss:
            return Outcome(False, MISSING_VALUES,
                           f"this problem needs {', '.join(miss)}, which this lab does not have: "
                           f"its check cannot run here", broken=True)
        health, r = check(run, scenario_id, node, params)
        if health == "error":
            return Outcome(False, CHECK_ERROR,
                           f"could not check {node}: it did not answer. Nothing was counted; try again in a moment",
                           broken=True, detail=r.err, steps=["check: error"])
        if health == "healthy":
            return Outcome(True, FIXED, f"{node} checks out healthy", steps=["check: healthy"])
        return Outcome(False, NOT_FIXED, f"{node} still shows the problem", broken=True,
                       detail=r.out + r.err, steps=["check: unhealthy"])
    return _guarded(lab_name, scenario_id, node, "verify", go)


def host_break_in_background(lab_name: str, scenario_id: str, node: str,
                             on_done: Callable[[bool, str], None] | None = None) -> threading.Thread:
    """A slow break from outside the machine (a checkpoint reverted), run
    beside the request. Its result, good or bad, reaches on_done and the
    log instead of dying with the thread."""
    def work() -> None:
        try:
            ok, msg = gf.host_break(scenario_id, lab_name, node)
        except Exception as exc:  # noqa: BLE001 - reported, not lost
            ok, msg = False, f"the break from outside {node} failed: {exc}"
        log(lab_name, "host-break", scenario_id, node,
            Outcome(ok, BROKEN if ok else REFUSED, msg, broken=ok))
        if on_done is not None:
            try:
                on_done(ok, msg)
            except Exception:  # noqa: BLE001
                pass
    t = threading.Thread(target=work, daemon=True)
    t.start()
    return t
