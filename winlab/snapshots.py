"""Checkpoints: save and restore machines' disks to a named point.

A checkpoint is a qcow2 internal snapshot on every disk of a machine, plus a
copy of its UEFI NVRAM. Stopped machines are snapshotted with qemu-img.
Running machines are snapshotted through their QMP monitor
(blockdev-snapshot-internal-sync), which needs no migration support and so
works on WHPX as well as KVM: every running machine is paused for the moment
it takes, so all disks of the lab are captured at the same instant.

Memory is not saved. A checkpoint of a running machine is what its disks held
at that instant, like pulling the power cord, and reverting a running machine
restarts it from there (Hyper-V calls the equivalent a production checkpoint).
A machine's TPM (its swtpm state, winlab/bitlocker.py) is kept with the
checkpoint too, so keys sealed to it match the disks after a revert.

A checkpoint has a name the student types (spaces allowed, as in Hyper-V)
and a tag qcow2 keeps: the name itself when it is a plain word, otherwise
a safe spelling of it. Each machine's checkpoints.json keeps the names,
when each was taken, the one it was taken from (the tree) and the one the
machine is at now.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import paths, state
from .images import ImageError
from .qmp import Qmp, QmpError

TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")


def _qemu_img() -> Path:
    exe = paths.qemu_img()
    if not exe.exists():
        raise ImageError("qemu-img missing; run 'winlab bootstrap'")
    return exe


NAME_MAX = 100
META = "checkpoints.json"
DATE = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")


def _check_name(name: str) -> str:
    """A name as the student typed it: up to 100 characters, no control
    characters, quotes or slashes. Returns it trimmed."""
    name = (name or "").strip()
    if not name or len(name) > NAME_MAX or any(c in name for c in '"\\/') \
            or any(ord(c) < 32 for c in name):
        raise ImageError(f"checkpoint name {name!r}: use up to {NAME_MAX} characters, "
                         f"without quotes or slashes")
    return name


def tag_for(name: str) -> str:
    """The qcow2 tag for a typed name: the name when it is already a tag,
    else its letters and digits with the rest folded into underscores."""
    if TAG.match(name):
        return name
    t = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")[:40].strip("._-")
    return t if t and TAG.match(t) else "checkpoint"


def _meta_path(node_dir: Path) -> Path:
    return node_dir / META


def _meta(node_dir: Path) -> dict:
    try:
        d = json.loads(_meta_path(node_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    for k in ("names", "created", "parent"):
        if not isinstance(d.get(k), dict):
            d[k] = {}
    d.setdefault("current", "")
    return d


def _save_meta(node_dir: Path, d: dict) -> None:
    _meta_path(node_dir).write_text(json.dumps(d, indent=1, sort_keys=True), encoding="utf-8")


def _resolve(node_dir: Path, disk: Path, wanted: str) -> str:
    """The tag on this machine for a tag or a typed name, or ''."""
    tags = _tags(disk)
    if wanted in tags:
        return wanted
    names = _meta(node_dir)["names"]
    for tag in tags:
        if names.get(tag) == wanted:
            return tag
    t = tag_for(wanted)
    return t if t in tags and names.get(t, t) == wanted else ""


def _check_tag(tag: str) -> None:
    if not TAG.match(tag):
        raise ImageError(
            f"checkpoint name {tag!r}: use up to 40 letters, digits, dots, dashes "
            f"or underscores"
        )


def _drive_id(disk: Path) -> str:
    """The -drive id the QEMU provider gives each disk file."""
    return "sys" if disk.name == "system.qcow2" else disk.stem


def _node_disks(lab_name: str) -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    base = paths.lab_dir(lab_name)
    if not base.exists():
        return out
    for node_dir in sorted(base.iterdir()):
        if not node_dir.is_dir() or node_dir.name == "fabric":
            continue
        disks = [node_dir / "system.qcow2"]
        disks += sorted(node_dir.glob("data*.qcow2"))
        found = [d for d in disks if d.exists()]
        if found:
            out[node_dir.name] = found
    return out


def _img(args: list[str]) -> str:
    res = subprocess.run([str(_qemu_img())] + args, capture_output=True, timeout=600)
    out = (res.stdout or b"").decode("utf-8", "replace")
    if res.returncode != 0:
        err = (res.stderr or b"").decode("utf-8", "replace")
        raise ImageError(f"qemu-img {args[0]} failed: {(err or out).strip()[:300]}")
    return out


def _tags(disk: Path) -> list[str]:
    # -U reads the snapshot table even while QEMU holds the image open.
    info = _img(["snapshot", "-l", "-U", str(disk)])
    tags = []
    for line in info.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit() and len(parts) > 1:
            tags.append(parts[1])
    return tags


def _running(lab_name: str) -> dict[str, state.NodeState]:
    st = state.load(lab_name)
    return st.running() if st else {}


def _vars(disk: Path) -> Path:
    return disk.parent / "uefi-vars.fd"


def _vars_copy(disk: Path, tag: str) -> Path:
    return disk.parent / f"uefi-vars.{tag}.fd"


def _tpm_copy(disk: Path, tag: str) -> Path:
    return disk.parent / f"tpm.{tag}"


def _tpm_save(disk: Path, tag: str) -> None:
    """The chip's state files (not its socket, pid or log) beside the tag."""
    src, dst = disk.parent / "tpm", _tpm_copy(disk, tag)
    shutil.rmtree(dst, ignore_errors=True)
    files = sorted(src.glob("*.permall")) if src.is_dir() else []
    if files:
        dst.mkdir(parents=True)
        for f in files:
            shutil.copyfile(f, dst / f.name)


def _tpm_restore(disk: Path, tag: str) -> None:
    saved, live = _tpm_copy(disk, tag), disk.parent / "tpm"
    if not saved.is_dir():
        return
    live.mkdir(parents=True, exist_ok=True)
    for f in live.glob("*.permall"):
        f.unlink()
    for f in saved.glob("*.permall"):
        shutil.copyfile(f, live / f.name)


def _targets(lab_name: str, only: list[str] | None) -> dict[str, list[Path]]:
    disks = _node_disks(lab_name)
    if only:
        missing = [n for n in only if n not in disks]
        if missing:
            raise ImageError(
                f"{', '.join(missing)}: no disks yet in lab '{lab_name}' (boot it once first)"
            )
        disks = {n: d for n, d in disks.items() if n in only}
    if not disks:
        raise ImageError(f"no disks found for lab '{lab_name}' (has it been booted?)")
    return disks


def save(lab_name: str, tag: str, only: list[str] | None = None) -> list[str]:
    """Checkpoint machines, running or not. Saving an existing name replaces it.
    `tag` is the name the student typed; spaces are fine."""
    name = _check_name(tag)
    tag = tag_for(name)
    targets = _targets(lab_name, only)
    for node_id, disks in targets.items():
        other = _meta(disks[0].parent)["names"].get(tag)
        if other and other != name:
            raise ImageError(f"{node_id} already has a checkpoint named {other!r} "
                             f"under that spelling; choose another name")
    running = _running(lab_name)
    live = {n: running[n] for n in targets if n in running}

    for node_id, disks in targets.items():
        if node_id not in live:
            for disk in disks:
                if tag in _tags(disk):
                    _img(["snapshot", "-d", tag, str(disk)])
                _img(["snapshot", "-c", tag, str(disk)])

    if live:
        _save_live(live, targets, tag)

    now = time.time()
    for disks in targets.values():
        nv = _vars(disks[0])
        if nv.exists():
            shutil.copyfile(nv, _vars_copy(disks[0], tag))
        _tpm_save(disks[0], tag)
        m = _meta(disks[0].parent)
        if m["current"] != tag:
            m["parent"][tag] = m["current"]
        m["names"][tag], m["created"][tag], m["current"] = name, now, tag
        _save_meta(disks[0].parent, m)
    from . import labclock
    labclock.note_checkpoint(lab_name, tag)
    return list(targets)


def _save_live(live: dict[str, state.NodeState], targets: dict[str, list[Path]],
               tag: str) -> None:
    monitors: dict[str, Qmp] = {}
    paused: list[str] = []
    try:
        for node_id, ns in live.items():
            monitors[node_id] = Qmp(ns.qmp_port).__enter__()
        for node_id, mon in monitors.items():
            # One the paused lab clock holds stays paused (winlab/labclock.py).
            if not (mon.call("query-status") or {}).get("running", True):
                continue
            mon.call("stop")
            paused.append(node_id)
        for node_id, mon in monitors.items():
            for disk in targets[node_id]:
                dev = _drive_id(disk)
                if tag in _tags(disk):
                    mon.call("blockdev-snapshot-delete-internal-sync", device=dev, name=tag)
                mon.call("blockdev-snapshot-internal-sync", device=dev, name=tag)
    except QmpError as exc:
        raise ImageError(f"checkpoint '{tag}' failed: {exc}") from exc
    finally:
        for node_id in paused:
            try:
                monitors[node_id].call("cont")
            except QmpError:
                pass
        for mon in monitors.values():
            mon.__exit__(None, None, None)


def restore(lab_name: str, tag: str, only: list[str] | None = None) -> list[str]:
    """Revert machines to a checkpoint. Running machines are powered off,
    reverted and started again; the rest of the lab keeps running. The lab
    clock is not rewound: they start again at the current lab time."""
    wanted = (tag or "").strip()
    targets = _targets(lab_name, only)
    tags = {n: _resolve(disks[0].parent, disks[0], wanted) for n, disks in targets.items()}
    lacking = [n for n in targets if not tags[n]]
    if lacking and only:
        raise ImageError(f"no checkpoint '{wanted}' on {', '.join(lacking)}")
    targets = {n: d for n, d in targets.items() if n not in lacking}
    if not targets:
        raise ImageError(f"no checkpoint '{wanted}' in lab '{lab_name}'")

    running = [n for n in targets if n in _running(lab_name)]
    orch = _orchestrator(lab_name) if running else None
    if orch:
        orch.stop_nodes(running)

    for node_id, disks in targets.items():
        tag = tags[node_id]
        for disk in disks:
            if tag in _tags(disk):
                _img(["snapshot", "-a", tag, str(disk)])
        saved = _vars_copy(disks[0], tag)
        if saved.exists():
            shutil.copyfile(saved, _vars(disks[0]))
        _tpm_restore(disks[0], tag)
        m = _meta(disks[0].parent)
        m["current"] = tag
        _save_meta(disks[0].parent, m)

    st = state.load(lab_name)
    if st:
        for node_id in targets:
            ns = st.nodes.get(node_id)
            if ns and ns.phase == state.SUSPENDED:
                ns.phase = "stopped"  # the disk is another one now; it may or may not wake
        state.save(st)
    if orch:
        orch.up(only=running)
    return list(targets)


def _orchestrator(lab_name: str):
    from .orchestrator import open_lab

    st = state.load(lab_name)
    assert st is not None
    return open_lab(st.source_path or lab_name, accel=st.accel or "tcg",
                    display=st.display or "window")


def delete(lab_name: str, tag: str, only: list[str] | None = None) -> list[str]:
    """Delete a checkpoint (a tag or its typed name) from the machines in
    `only`, or from every machine that has it. The checkpoints taken from
    it hang from its parent afterwards, as in Hyper-V's tree."""
    wanted = (tag or "").strip()
    running = _running(lab_name)
    done = []
    for node_id, disks in _node_disks(lab_name).items():
        if only and node_id not in only:
            continue
        tag = _resolve(disks[0].parent, disks[0], wanted)
        if not tag:
            continue
        for disk in disks:
            if tag not in _tags(disk):
                continue
            if node_id in running:
                with Qmp(running[node_id].qmp_port) as mon:
                    mon.call("blockdev-snapshot-delete-internal-sync",
                             device=_drive_id(disk), name=tag)
            else:
                _img(["snapshot", "-d", tag, str(disk)])
        _vars_copy(disks[0], tag).unlink(missing_ok=True)
        shutil.rmtree(_tpm_copy(disks[0], tag), ignore_errors=True)
        m = _meta(disks[0].parent)
        up = m["parent"].pop(tag, "")
        for child, parent in list(m["parent"].items()):
            if parent == tag:
                m["parent"][child] = up
        m["names"].pop(tag, None)
        m["created"].pop(tag, None)
        if m["current"] == tag:
            m["current"] = up
        _save_meta(disks[0].parent, m)
        done.append(node_id)
    return done


def rename(lab_name: str, node_id: str, tag: str, new_name: str) -> str:
    """A new name for one machine's checkpoint; the tag in qcow2 stays."""
    disks = _targets(lab_name, [node_id])[node_id]
    found = _resolve(disks[0].parent, disks[0], (tag or "").strip())
    if not found:
        raise ImageError(f"no checkpoint '{tag}' on {node_id}")
    name = _check_name(new_name)
    m = _meta(disks[0].parent)
    for other, other_name in m["names"].items():
        if other != found and other_name == name:
            raise ImageError(f"{node_id} already has a checkpoint named {name!r}")
    m["names"][found] = name
    _save_meta(disks[0].parent, m)
    return name


def _dates(disk: Path) -> dict[str, float]:
    """When each tag was taken, from qemu-img's own table."""
    out: dict[str, float] = {}
    for line in _img(["snapshot", "-l", "-U", str(disk)]).splitlines():
        parts = line.split()
        hit = DATE.search(line)
        if parts and parts[0].isdigit() and len(parts) > 1 and hit:
            try:
                out[parts[1]] = time.mktime(time.strptime(" ".join(hit.groups()), "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                pass
    return out


def details(lab_name: str) -> dict[str, dict]:
    """Each machine's checkpoints for the desktop: name, tag, when, parent,
    in the order they were taken, and the one the machine is at."""
    out: dict[str, dict] = {}
    for node_id, disks in _node_disks(lab_name).items():
        m = _meta(disks[0].parent)
        dates = _dates(disks[0])
        tags = _tags(disks[0])
        items = [{"tag": t, "name": m["names"].get(t, t),
                  "created": m["created"].get(t) or dates.get(t, 0),
                  "parent": m["parent"].get(t, "") if m["parent"].get(t, "") in tags else ""}
                 for t in tags]
        items.sort(key=lambda x: x["created"])
        out[node_id] = {"checkpoints": items,
                        "current": m["current"] if m["current"] in tags else ""}
    return out


def listing(lab_name: str) -> dict[str, list[str]]:
    return {node_id: _tags(disks[0]) for node_id, disks in _node_disks(lab_name).items()}


def render_listing(lab_name: str) -> str:
    data = listing(lab_name)
    if not data:
        return f"no checkpoints for lab '{lab_name}'"
    lines = [f"checkpoints for '{lab_name}':"]
    for node_id, tags in data.items():
        lines.append(f"  {node_id:<12} {', '.join(tags) if tags else '(none)'}")
    return "\n".join(lines)
