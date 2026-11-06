"""Editions: the full app, or winlab core, the cut-down first release.

Core is the same program with most of it switched off: one lab (ad-ds-basics:
a domain controller with DNS and DHCP, a file server and a Windows 11 PC),
the lessons and drills that need nothing but those three machines, and the
windows and commands that serve them. Nothing is deleted from the code;
the release build of core ships only core's content and says "core" in a
file inside the exe (packaging/build-exe.ps1 -Edition core).

Which edition runs:
    frozen exe   edition.txt in the bundle ("core"), else full
    checkout     WINLAB_EDITION=core or full, else edition.txt at the top of
                 the checkout (an export made by tools/export_lite.py), else full

Every reader of content/ goes through winlab/content.py, which asks
visible() here, so a core checkout behaves like the core exe even with the
whole content tree on disk.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path, PurePosixPath

from . import paths

FULL = "full"
CORE = "core"
EDITION_FILE = "edition.txt"

CORE_LAB = "ad-ds-basics"
# The trial's labs: the domain, a firewall installed by hand, routers.
CORE_LABS = (CORE_LAB, "firewall-by-hand", "router-protocols")
CORE_IMAGES = ("ws2025", "win11", "alpine", "ubuntu", "opnsense-dvd")

# Lessons of the trial's labs that it leaves out: each needs hardware the
# trial's workbench does not offer (Wi-Fi, the drive bays, the UPS, a BMC,
# Wake-on-LAN through the router, a driver stick). The switch and router
# consoles and the firewall are in.
CORE_OUT_LESSONS = frozenset({
    "drivers-and-devices", "mirrored-volume",
    "remote-power-bmc", "storage-spaces-repair",
    "ts-wol-off", "ups-power-cut",
    "wake-on-lan", "wpa2-enterprise",
})

# The lab's own exercise list, less the ones those lessons grade.
CORE_OUT_EXERCISES = frozenset({
    "power-cycle-hung-server", "rebuild-a-mirror",
    "repair-a-storage-pool",
    "ups-graceful-shutdown", "wake-a-pc", "wpa2-enterprise",
})

# Content folders core filters; everything else under content/ (roles, the
# guest agent, help, the command reference) ships whole.
_FILTERED = ("labs", "lessons", "exercises", "guides", "scenarios", "exams")

# Top-level commands of the core CLI. The rest are hidden from -h and refused.
CORE_COMMANDS = frozenset({
    "doctor", "setup", "gui", "bootstrap", "lab", "images", "exercise", "snap",
    "console", "console-agent", "exec", "shell", "cp", "break", "fault",
    "helpdesk", "learn", "commands", "progress", "transcript", "virtio",
    "viewer", "window", "icon", "fw", "routing", "net", "media",
})

# Desktop windows core hides (the page reads this list from /api/state).
CORE_HIDDEN_WINDOWS = (
    "Guide", "Build", "Activation", "Scenario", "Pager", "Office",
    "Rack", "Inherited", "Classwork", "ClassResults", "Alerts", "Activity",
    "Company", "Shift",
)

_cache: str | None = None


def current() -> str:
    global _cache
    if _cache is None:
        _cache = _detect()
    return _cache


def _detect() -> str:
    if paths.BUNDLE is not None:
        try:
            text = (paths.BUNDLE / EDITION_FILE).read_text(encoding="utf-8").strip().lower()
        except OSError:
            text = ""
        return CORE if text == CORE else FULL
    env = os.environ.get("WINLAB_EDITION", "").strip().lower()
    if env:
        return CORE if env == CORE else FULL
    # A checkout exported as winlab core (tools/export_lite.py) says so in a file.
    try:
        text = (paths.APP_DIR / EDITION_FILE).read_text(encoding="utf-8").strip().lower()
    except OSError:
        text = ""
    return CORE if text == CORE else FULL


def set_for_tests(name: str | None) -> None:
    """Force an edition (None: detect again)."""
    global _cache
    _cache = name


def is_core() -> bool:
    return current() == CORE


def label() -> str:
    return "winlab trial" if is_core() else "winlab"


def keeps(rel: str) -> bool:
    """Whether core ships the content file at rel (POSIX, relative to content/)."""
    parts = PurePosixPath(rel).parts
    if len(parts) != 2 or parts[0] not in _FILTERED:
        return True
    folder, stem = parts[0], PurePosixPath(parts[1]).stem
    if not parts[1].endswith(".toml"):
        return folder not in ("labs", "lessons", "exercises")
    if folder == "labs":
        return stem in CORE_LABS
    if folder == "lessons":
        return stem in core_lessons()
    if folder == "exercises":
        return stem in core_exercises()
    return False   # guides, scenarios, exams: none in core


def visible(rel: str | None) -> bool:
    """content.py's filter: everything in the full edition, keeps() in core."""
    return rel is None or not is_core() or keeps(rel)


def keeps_command(cmd: str | None) -> bool:
    return cmd is None or not is_core() or cmd in CORE_COMMANDS


# The core lesson and exercise sets come from the shipped content, read
# once: ad-ds-basics' lessons less CORE_OUT_LESSONS, and the exercises those
# lessons and the lab name less CORE_OUT_EXERCISES.
_sets: dict[str, tuple[frozenset, frozenset]] = {}


def _toml(p: Path) -> dict:
    import tomllib
    try:
        with p.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return {}


def _core_sets(content_dir: Path | None = None) -> tuple[frozenset, frozenset]:
    root = Path(content_dir or paths.CONTENT)
    key = str(root)
    if key not in _sets:
        lessons, exercises = set(), set()
        for p in sorted((root / "lessons").glob("*.toml")):
            meta = _toml(p).get("lesson") or {}
            if str(meta.get("lab", "")) in CORE_LABS and p.stem not in CORE_OUT_LESSONS:
                lessons.add(p.stem)
                if meta.get("exercise"):
                    exercises.add(str(meta["exercise"]))
        for name in CORE_LABS:
            lab = _toml(root / "labs" / f"{name}.toml").get("lab") or {}
            exercises |= {str(x) for x in lab.get("exercises", [])}
        _sets[key] = (frozenset(lessons), frozenset(exercises - CORE_OUT_EXERCISES))
    return _sets[key]


def core_lessons(content_dir: Path | None = None) -> frozenset:
    return _core_sets(content_dir)[0]


def core_exercises(content_dir: Path | None = None) -> frozenset:
    return _core_sets(content_dir)[1]


def lab_exercises(names: list[str]) -> list[str]:
    """A lab's exercise list as this edition shows it."""
    if not is_core():
        return list(names)
    return [n for n in names if n not in CORE_OUT_EXERCISES]


def stage(src: Path, dest: Path) -> dict:
    """Copy the content tree to dest the way core ships it (the build passes
    dest to PyInstaller instead of content/). Returns counts for the log."""
    src, dest = Path(src), Path(dest)
    lessons, exercises = core_lessons(src), core_exercises(src)
    if dest.exists():
        shutil.rmtree(dest)
    kept = dropped = 0
    for f in sorted(src.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(src).as_posix()
        parts = PurePosixPath(rel).parts
        if parts[0] == "packs" or parts[-1] == paths.SEED_MANIFEST:
            dropped += 1   # core has no paid packs, and a seed manifest is per PC
            continue
        if len(parts) == 2 and parts[0] in _FILTERED and parts[1].endswith(".toml"):
            stem, folder = PurePosixPath(parts[1]).stem, parts[0]
            ok = ((folder == "labs" and stem in CORE_LABS) or (folder == "lessons" and stem in lessons)
                  or (folder == "exercises" and stem in exercises))
            if not ok:
                dropped += 1
                continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)
        kept += 1
    return {"kept": kept, "dropped": dropped, "lessons": len(lessons), "exercises": len(exercises)}
