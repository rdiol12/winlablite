"""Running-lab state. One JSON file per lab under var/state."""

from __future__ import annotations

import ctypes
import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import paths

STILL_ACTIVE = 259
SUSPENDED = "suspended"
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


@dataclass
class NodeState:
    node_id: str
    pid: int = 0
    qmp_port: int = 0
    serial_port: int = 0
    vnc_port: int = 0
    disk: str = ""
    phase: str = "created"  # created | installing | booting | provisioning | ready | stopped | suspended
    # An appliance winlab drives over its serial console (OPNsense): the
    # console agent process that speaks the agent protocol on serial_port,
    # and the QEMU chardev port of the console itself.
    helper_pid: int = 0
    console_port: int = 0
    # A Linux machine's login console (ttyS0) as a loopback socket: the
    # desktop's Terminal window (termview.py).
    term_port: int = 0
    # The USB-serial adapter's COM port, wired to a router's or a switch's
    # console by the console cable (consolecable.py).
    com_port: int = 0
    # A Windows machine's COM3: the console host behind the desktop's
    # Command Prompt and PowerShell windows (winterm.py).
    wterm_port: int = 0


@dataclass
class LabState:
    name: str
    accel: str = ""
    display: str = ""
    started_at: float = 0.0
    source_path: str = ""
    nodes: dict[str, NodeState] = field(default_factory=dict)

    def running(self) -> dict[str, NodeState]:
        return {k: v for k, v in self.nodes.items() if v.pid and pid_alive(v.pid)}

    def suspended(self) -> dict[str, NodeState]:
        """Machines that hibernated: not running, and their next start is a resume."""
        return {k: v for k, v in self.nodes.items()
                if v.phase == SUSPENDED and not (v.pid and pid_alive(v.pid))}


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        # os.kill(pid, 0) on Windows calls TerminateProcess, which would kill
        # the very machine we are probing. Query the handle instead.
        k = ctypes.windll.kernel32
        handle = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = k.GetExitCodeProcess(handle, ctypes.byref(code))
        k.CloseHandle(handle)
        return bool(ok) and code.value == STILL_ACTIVE
    # A child of this process that exited stays a zombie until it is reaped,
    # and kill(pid, 0) answers for a zombie: a QEMU that died under the
    # desktop would show as running until the desktop closed. Reap it here.
    try:
        done, _status = os.waitpid(pid, os.WNOHANG)
        if done == pid:
            return False
    except ChildProcessError:
        pass  # not our child: the kill probe below answers
    except OSError:
        pass
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    try:  # someone else's child, exited and not reaped yet
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return True


class Busy(Exception):
    """Another start of the same lab did not finish in time."""


_start_locks: dict[str, threading.Lock] = {}
_start_guard = threading.Lock()


@contextmanager
def start_lock(lab_name: str, wait: float = 1800.0, on_wait=None):
    """One start of a lab at a time, in this process (two quick Power on
    clicks are two jobs) and across processes (the desktop and `winlab lab
    up`): the second waits for the first, then finds its machines running
    instead of starting the router a second time. A lock file left by a
    process that died is taken over."""
    with _start_guard:
        lk = _start_locks.setdefault(lab_name, threading.Lock())
    deadline = time.monotonic() + wait
    said = False
    if not lk.acquire(blocking=False):
        if on_wait:
            on_wait()
            said = True
        if not lk.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise Busy(f"{lab_name} is still being started by an earlier start")
    f = paths.lab_dir(lab_name) / "starting.lock"
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                fd = os.open(f, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    owner = int(f.read_text(encoding="utf-8").strip() or 0)
                except (OSError, ValueError):
                    owner = 0
                if not owner:  # another winlab is writing its number into it now
                    try:
                        young = time.time() - f.stat().st_mtime < 5
                    except OSError:
                        young = False
                    if young:
                        time.sleep(0.2)
                        continue
                if owner == os.getpid() or not owner or not pid_alive(owner):
                    f.unlink(missing_ok=True)  # left by a process that is gone
                    continue
                if time.monotonic() > deadline:
                    raise Busy(f"{lab_name} is still being started by another winlab (process {owner})")
                if on_wait and not said:
                    on_wait()
                    said = True
                time.sleep(0.5)
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(str(os.getpid()))
            break
        try:
            yield
        finally:
            f.unlink(missing_ok=True)
    finally:
        lk.release()


def state_file(lab_name: str) -> Path:
    return paths.STATE / f"{lab_name}.json"


def save(st: LabState) -> Path:
    paths.STATE.mkdir(parents=True, exist_ok=True)
    dest = state_file(st.name)
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(asdict(st), indent=2), encoding="utf-8")
    tmp.replace(dest)
    return dest


def load(lab_name: str) -> LabState | None:
    f = state_file(lab_name)
    if not f.exists():
        return None
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    # Fields this version does not know (a state file from a newer winlab)
    # are dropped instead of making every command fail on the lab.
    known = set(NodeState.__dataclass_fields__)
    nodes = {k: NodeState(**{f: x for f, x in v.items() if f in known})
             for k, v in (raw.get("nodes") or {}).items()}
    return LabState(
        name=raw.get("name", lab_name),
        accel=raw.get("accel", ""),
        display=raw.get("display", ""),
        started_at=float(raw.get("started_at") or 0.0),
        source_path=raw.get("source_path", ""),
        nodes=nodes,
    )


def suspended(lab_name: str) -> set[str]:
    st = load(lab_name)
    return set(st.suspended()) if st else set()


def running(lab_name: str) -> set[str]:
    """The ids of the lab's machines whose QEMU is alive."""
    st = load(lab_name)
    return set(st.running()) if st else set()


def is_running(lab_name: str, node_id: str) -> bool:
    st = load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    return bool(ns and ns.pid and pid_alive(ns.pid))


def qmp_port(lab_name: str, node_id: str) -> int:
    """A running machine's monitor port, 0 when it is not running."""
    st = load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    return ns.qmp_port if ns and ns.qmp_port and ns.pid and pid_alive(ns.pid) else 0


def write_json(p: Path, data: dict, end: str = "") -> None:
    """A lab's side file, through a temporary so a reader never sees half of it."""
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1) + end, encoding="utf-8")
    tmp.replace(p)


def save_json(p: Path, data: dict | None) -> None:
    """A lab's side file written in place; None removes it."""
    if data is None:
        p.unlink(missing_ok=True)
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=1), encoding="utf-8")


def clear(lab_name: str) -> None:
    state_file(lab_name).unlink(missing_ok=True)


def known_labs() -> list[str]:
    paths.STATE.mkdir(parents=True, exist_ok=True)
    return sorted(p.stem for p in paths.STATE.glob("*.json"))


def new(lab_name: str, accel: str, display: str, source_path: str = "") -> LabState:
    return LabState(
        name=lab_name,
        accel=accel,
        display=display,
        started_at=time.time(),
        source_path=source_path,
    )
