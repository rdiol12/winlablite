"""Worked solutions: what a correct student does, written so a script can do it.

Every exercise has a solution file, content/solutions/<exercise-id>.toml. The
self-test (`winlab selftest`, winlab/selftest.py) runs it on a real lab to
prove the exercise's checks are fair: on a fresh lab the checks fail, after
the solution they pass. Nothing in the desktop shows a solution to the
student; the hint ladder and the lesson steps stay the student's help.

    [solution]
    exercise = "promote-first-dc"
    notes = "optional: anything a person running it should know"
    cold = ["pc05"]            # optional: machines that cannot start until the
                               # solution has built them (an empty case): not
                               # powered on or waited for before the solution
    restore_after = false      # the exercise wrecks the lab for the lessons after it
                               # (a DC killed on purpose): the self-test checkpoints
                               # the lab before it and goes back to that afterwards

    [[step]]
    node = "dc01"              # a machine of the exercise's lab, "fabric" (the
                               # lab router's shell), a console device
                               # ("router", "router:<rid>", "sw:<id>") or "winlab"
    shell = "powershell"       # powershell | sh | console | winlab
    script = '''
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    '''
    reboot = false             # the step restarts the machine: wait for it
    wait = 0                   # seconds to wait after the step (replication, a service)
    timeout = 600              # seconds the step may take

[[setup]] steps (same keys as [[step]]) arrange the scenario the lesson
starts from before the first grading, the way a problem lesson's Break
does (the lab clock jumped ahead, a machine switched off); they are not
the student's work.
[[cleanup]] steps (same keys as [[step]]) run after the last grading and
are not graded: they undo what only the exercise needed (a disk mended)
before a restore_after checkpoint is put back.

shell = "console": every non-blank line of script is typed into the device's
console (winlab/devcli.py), from its user-mode prompt; start with "enable"
as a student would. shell = "winlab": every non-blank line is the argument
list of one `winlab` command (`rack label ...`), run on this PC against the
lab. Steps run in order. Placeholders the checks use (naming, host values)
are applied to solutions the same way, plus {{winlab:lab-secret}}: the lab's
generated admin secret (`winlab lab password <lab>`), filled in at run time
so no secret is ever written in a solution file, and {{winlab:workdir}}: a
folder on this PC for files carried between machines (winlab cp).

[files] maps a path under that folder to a file's text, written there
(placeholders filled) before the first step: an answer file a winlab
`media ... burn` step puts on a disc, say.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

SHELLS = ("powershell", "sh", "console", "winlab")
CONSOLE_NODES = ("router",)   # plus "router:<rid>" and "sw:<id>"


class SolutionError(Exception):
    pass


@dataclass
class Step:
    node: str
    shell: str
    script: str
    reboot: bool = False
    wait: int = 0
    timeout: int = 600

    def lines(self) -> list[str]:
        return [ln.strip() for ln in self.script.splitlines() if ln.strip()]


@dataclass
class Solution:
    exercise: str
    steps: list[Step] = field(default_factory=list)
    notes: str = ""
    path: Path | None = None
    cleanup: list[Step] = field(default_factory=list)
    restore_after: bool = False
    setup: list[Step] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    cold: list[str] = field(default_factory=list)   # machines that cannot start before the solution (an empty case)


def solutions_dir() -> Path:
    return paths.CONTENT / "solutions"


def solution_path(exercise_id: str) -> Path:
    return solutions_dir() / f"{exercise_id}.toml"


def exists(exercise_id: str) -> bool:
    from . import content
    return content.exists(solution_path(exercise_id))   # plain, or in an open content pack


def load(exercise_id: str) -> Solution:
    from . import content
    path = solution_path(exercise_id)
    if not content.exists(path):
        raise SolutionError(f"no solution for {exercise_id} ({path.name})")
    raw = content.load_toml(path)
    meta = raw.get("solution", {})
    if meta.get("exercise") != exercise_id:
        raise SolutionError(f"{path.name}: [solution] exercise must be {exercise_id!r}")
    steps = _steps(raw.get("step", []), path, "step")
    if not steps:
        raise SolutionError(f"{path.name}: no [[step]]")
    return Solution(exercise=exercise_id, steps=steps, notes=str(meta.get("notes", "")), path=path,
                    cleanup=_steps(raw.get("cleanup", []), path, "cleanup"),
                    setup=_steps(raw.get("setup", []), path, "setup"),
                    restore_after=bool(meta.get("restore_after", False)),
                    files=_files(raw.get("files", {}), path),
                    cold=[str(n) for n in meta.get("cold", [])])


def _files(table, path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel, text in dict(table).items():
        parts = Path(rel).parts
        if not parts or Path(rel).is_absolute() or ".." in parts or not isinstance(text, str):
            raise SolutionError(f"{path.name}: [files] {rel!r} must be a relative path to a text")
        out[rel] = text
    return out


def _steps(rows, path: Path, what: str) -> list[Step]:
    steps = []
    for i, s in enumerate(rows, 1):
        if not s.get("node") or not str(s.get("script", "")).strip():
            raise SolutionError(f"{path.name}: {what} {i} needs 'node' and 'script'")
        shell = str(s.get("shell", "powershell"))
        if shell not in SHELLS:
            raise SolutionError(f"{path.name}: {what} {i} shell {shell!r} (use {', '.join(SHELLS)})")
        steps.append(Step(node=str(s["node"]), shell=shell, script=str(s["script"]),
                          reboot=bool(s.get("reboot", False)), wait=int(s.get("wait", 0)),
                          timeout=int(s.get("timeout", 600))))
    return steps


def is_console_node(node: str) -> bool:
    return node in CONSOLE_NODES or node.startswith(("router:", "sw:"))


def problems(exercise_id: str) -> list[str]:
    """What is wrong with one solution file, without a lab running: the
    exercise exists, every step names a machine of its lab with a shell that
    fits it, sh scripts parse (sh -n, where /bin/sh exists), winlab lines
    parse as arguments, and every console line is one the device's console
    takes (typed at an offline copy of it: no % Invalid input, Incomplete
    or Ambiguous)."""
    from . import exercises, schema, selftest
    out: list[str] = []
    try:
        sol = load(exercise_id)
    except SolutionError as exc:
        return [str(exc)]
    try:
        ex = exercises.load(exercise_id)
    except Exception as exc:  # noqa: BLE001
        return [f"{exercise_id}: exercise does not load: {exc}"]
    try:
        lab = schema.load(ex.lab)
        nodes = set(lab.nodes)
    except Exception as exc:  # noqa: BLE001
        return [f"{exercise_id}: lab {ex.lab!r} does not load: {exc}"]
    named = ([(f"step {i}", st) for i, st in enumerate(sol.steps, 1)]
             + [(f"setup {i}", st) for i, st in enumerate(sol.setup, 1)]
             + [(f"cleanup {i}", st) for i, st in enumerate(sol.cleanup, 1)])
    reshaped = False   # an earlier step changed the lab on the Workbench: the offline copy no longer matches
    for label, st in named:
        where = f"{exercise_id} {label}"
        if st.shell == "winlab" and any(ln.split()[:1] == ["workbench"] for ln in st.lines()):
            reshaped = True
        if st.shell == "console":
            if not is_console_node(st.node):
                out.append(f"{where}: console steps go to router, router:<rid> or sw:<id>, not {st.node}")
            elif not reshaped:
                # Typed at an offline copy of the device: every line must be one it takes.
                for bad in selftest.console_replay(ex.lab, st.node, st.lines()):
                    out.append(f"{where}: the console does not take {bad}")
        elif st.shell == "winlab":
            if st.node != "winlab":
                out.append(f"{where}: winlab steps use node = \"winlab\"")
            for ln in st.lines():
                try:
                    shlex.split(ln)
                except ValueError as exc:
                    out.append(f"{where}: {ln!r}: {exc}")
        else:
            if st.node != "fabric" and st.node not in nodes:
                out.append(f"{where}: {st.node} is not a machine of {ex.lab}")
            if st.node == "fabric" and st.shell != "sh":
                out.append(f"{where}: the lab router runs sh")
            if st.shell == "sh":
                why = selftest.sh_syntax(st.script)
                if why:
                    out.append(f"{where}: sh -n: {why}")
    return out
