"""The user's own labs: delete one, give one a new name.

winlab ships its labs in the content pack; the user makes more (a new network
on the Workbench, `winlab lab new`, a network file opened, a lab imported, a
client job's site). Only those can be deleted or renamed: a shipped lab has
lessons, exercises and progress that point at it by name, and the next
update would put it back anyway.

A lab is more than its definition. Everything winlab keeps by the lab's name
goes with it: the machines' folder (disks, checkpoints, sticks, the
password), the run state, the save points and the notes. Both refuse while a
machine of the lab runs or is suspended, because its disks are in use.
"""

from __future__ import annotations

import functools
import shutil
import subprocess
from pathlib import Path

from . import paths, state


class MyLabError(Exception):
    pass


def _source_labs() -> Path:
    """The labs winlab itself ships: the bundle's when frozen, else the source tree's."""
    if paths.BUNDLE is not None:
        return paths.BUNDLE / "content" / "labs"
    return Path(__file__).resolve().parent.parent / "content" / "labs"


@functools.lru_cache(maxsize=1)
def _git_tracked(labs: str) -> frozenset[str] | None:
    try:
        out = subprocess.run(["git", "ls-files", "--", "*.toml"], cwd=labs, capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return frozenset(Path(l).stem for l in out.stdout.splitlines() if l.strip())


def shipped(name: str) -> bool:
    """A lab winlab ships (its file came with the content pack)."""
    seeded = paths._read_manifest(paths.CONTENT / paths.SEED_MANIFEST)
    if f"labs/{name}.toml" in seeded:
        return True
    src = _source_labs()
    if (src / f"{name}.toml").exists() or (src.parent / "packs").is_dir() and any(
            p.stem == name for p in (src.parent / "packs").glob("**/*.toml")):
        try:
            same = src.resolve() == paths.LABS.resolve()
        except OSError:
            same = False
        if not same:
            return True
        # Running from the source tree: the labs in it are both shipped and
        # the user's; git knows which ones the repository has.
        tracked = _git_tracked(str(src))
        return True if tracked is None else name in tracked
    return False


def lab_file(name: str) -> Path:
    return paths.LABS / f"{name}.toml"


def _places(name: str) -> list[Path]:
    """Everything kept by the lab's name, besides its definition."""
    from . import netfile, notes
    return [paths.lab_dir(name), state.state_file(name), netfile.points_dir(name), notes.notes_file(name)]


def _check_mine(name: str) -> None:
    if shipped(name):
        raise MyLabError(f"{name} comes with winlab, so it stays; only labs you made can be "
                         f"deleted or renamed (save it as a network file to keep a copy of your own)")
    if not lab_file(name).exists():
        raise MyLabError(f"there is no lab called {name}")


def _check_off(name: str) -> None:
    st = state.load(name)
    if st is None:
        return
    on = sorted(st.running())
    if on:
        raise MyLabError(f"{name} has machines running ({', '.join(on)}): shut the lab down first")
    held = sorted(st.suspended())
    if held:
        raise MyLabError(f"{name} has suspended machines ({', '.join(held)}): start them and shut "
                         f"them down, or shut the lab down, first")


def delete(name: str) -> list[str]:
    """Delete one of the user's labs and everything kept by its name.
    Returns what went, for the message."""
    _check_mine(name)
    _check_off(name)
    gone = []
    f = lab_file(name)
    for p in (f, f.with_suffix(".toml.bak")):
        if p.exists():
            p.unlink()
            gone.append(p.name)
    for p in _places(name):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            gone.append(f"{p.name}/")
        elif p.exists():
            p.unlink(missing_ok=True)
            gone.append(p.name)
    _forget_last(name, "")
    return gone


def rename(old: str, new: str) -> Path:
    """Give one of the user's labs a new name: its definition, machines,
    save points and notes move with it."""
    from . import editor, schema
    new = (new or "").strip().lower()
    _check_mine(old)
    if not editor.LAB_NAME.match(new):
        raise MyLabError("name the lab with 2-31 lower-case letters, digits and dashes, "
                         "starting with a letter (for example my-office)")
    if new == old:
        return lab_file(old)
    if lab_file(new).exists() or shipped(new):
        raise MyLabError(f"there is already a lab called {new}")
    _check_off(old)
    lab = schema.load(lab_file(old))
    olddir, newdir = paths.lab_dir(old), paths.lab_dir(new)
    if newdir.exists() and any(newdir.iterdir()):
        raise MyLabError(f"a folder for {new} is left from an older lab ({newdir}); "
                         f"move it away first")
    # The machines' folder first: if it cannot move (a disk still open by a
    # program), nothing has changed yet.
    if olddir.exists():
        newdir.parent.mkdir(parents=True, exist_ok=True)
        if newdir.exists():
            newdir.rmdir()
        try:
            olddir.rename(newdir)
        except OSError as exc:
            raise MyLabError(f"the machines of {old} could not be moved ({exc}); close any program "
                             f"that has one of its disks open and try again") from exc
        _repoint(newdir, olddir, newdir)
    lab.name = new
    dest = lab_file(new)
    lab.source_path = dest
    editor.save(lab, dest)
    lab_file(old).unlink(missing_ok=True)
    lab_file(old).with_suffix(".toml.bak").unlink(missing_ok=True)
    state.state_file(old).unlink(missing_ok=True)  # it was off: the state held nothing running
    for p_old, p_new in zip(_places(old)[2:], _places(new)[2:]):
        if p_old.exists():
            p_new.parent.mkdir(parents=True, exist_ok=True)
            p_old.rename(p_new)
    _forget_last(old, new)
    return dest


def _repoint(root: Path, old: Path, new: Path) -> None:
    """Side files that wrote the machines' folder out in full follow the move."""
    a, b = str(old), str(new)
    for f in root.rglob("*.json"):
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if a in text or a.replace("\\", "\\\\") in text:
            f.write_text(text.replace(a.replace("\\", "\\\\"), b.replace("\\", "\\\\")).replace(a, b),
                         encoding="utf-8")


def _forget_last(old: str, new: str) -> None:
    """The desktop opens the last lab next time: a renamed one by its new name."""
    last = paths.VAR / "last-lab"
    try:
        if last.read_text(encoding="utf-8").strip() == old:
            if new:
                last.write_text(new, encoding="utf-8")
            else:
                last.unlink()
    except OSError:
        pass


# ------------------------------------------------- a machine taken off the bench
PARKED = ".removed"


def park_machine(lab_name: str, node_id: str) -> bool:
    """A machine removed from a lab: its folder (disks, checkpoints) moves
    aside, so a new machine given the same name really starts afresh, and an
    Undo of the removal puts it back (unpark). Only the newest removal of a
    name is kept; deleting the lab removes it with the rest."""
    src = paths.lab_dir(lab_name) / node_id
    if not src.is_dir():
        return False
    dest = paths.lab_dir(lab_name) / PARKED / node_id
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        src.rename(dest)
    except OSError:
        return False
    return True


def unpark_machine(lab_name: str, node_id: str) -> bool:
    """The machine came back (Undo): its folder comes back with it."""
    src = paths.lab_dir(lab_name) / PARKED / node_id
    dest = paths.lab_dir(lab_name) / node_id
    if not src.is_dir() or dest.exists():
        return False
    try:
        src.rename(dest)
    except OSError:
        return False
    return True
