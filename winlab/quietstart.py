"""Start the desktop without a console window, and keep its output.

winlab.exe is a console program, so the command line (``winlab lab up``,
``winlab doctor``) prints where it was typed. Started from the Start menu or
the desktop icon, that console is only an empty black window beside the app.
The installer's shortcuts therefore start ``winlab-start.exe`` (a tiny
launcher of winlab's own, packaging/launcher) which runs winlab.exe with no
console window at all. When winlab.exe itself is double-clicked, the console
it got belongs to it alone: it starts a copy of itself with no window
(``CREATE_NO_WINDOW``, so the programs it starts in turn have none either)
and the visible one goes away.

The quiet copy writes what it would have printed to
``var/appwindow/desktop.log`` (the previous run kept as desktop.log.1), so
support still has it. Started from a terminal, nothing changes.
"""

from __future__ import annotations

import os
import subprocess
import sys

from . import paths

ENV = "WINLAB_QUIET"
CREATE_NO_WINDOW = 0x08000000


def log_path():
    return paths.VAR / "appwindow" / "desktop.log"


def console_processes() -> list[int]:
    """The processes attached to this console (Windows), [] when unknown."""
    import ctypes

    try:
        arr = (ctypes.c_uint32 * 64)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(arr, 64)
    except (AttributeError, OSError):
        return []
    return list(arr[:min(n, 64)])


def owns_console_alone(pids: list[int], pid: int, ppid: int) -> bool:
    """Only winlab itself is on the console (PyInstaller's one-file exe is two
    processes, the unpacker and its child): it was double-clicked, not typed
    in a terminal, whose shell would be on the list too."""
    return bool(pids) and set(pids) <= {pid, ppid}


def keep_output() -> None:
    """In the quiet copy: print into desktop.log instead of nowhere."""
    log = log_path()
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        if log.exists():
            os.replace(log, log.with_name(log.name + ".1"))
        out = open(log, "a", encoding="utf-8", buffering=1)  # noqa: SIM115 - lives as long as the process
    except OSError:
        return
    sys.stdout = sys.stderr = out


def command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "winlab"]


def relaunch_hidden(env: dict | None = None, platform: str | None = None,
                    pids=None, popen=subprocess.Popen) -> bool:
    """True when a console-less copy now runs the desktop and this process
    should simply end."""
    env = os.environ if env is None else env
    platform = platform or sys.platform
    if platform != "win32":
        return False
    if env.get(ENV):
        keep_output()
        return False
    pids = console_processes() if pids is None else pids
    if not owns_console_alone(pids, os.getpid(), os.getppid()):
        return False
    try:
        popen(command(), env={**env, ENV: "1"}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW, close_fds=True)
    except OSError:
        return False
    return True
