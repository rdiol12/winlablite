"""The desktop's own error log: var/logs/desktop.log.

The desktop runs without a console window, so an error it hits (a request
that failed, a job that ended in an error, an action that broke) would
otherwise go nowhere. Each one is written here with its time and, for a
crash, the end of its traceback. The support file (winlab/support.py) takes
everything under var/logs, through its redactor, so support sees what went
wrong in the app as well as in QEMU.

The log is capped: past MAX_BYTES it moves to desktop.old.log (the one before
is dropped), so it never grows without end.
"""

from __future__ import annotations

import threading
import time
import traceback
from pathlib import Path

from . import paths

NAME = "desktop.log"
OLD = "desktop.old.log"
MAX_BYTES = 1024 * 1024
_lock = threading.Lock()


def path() -> Path:
    return paths.LOGS / NAME


def write(kind: str, message: str, exc: BaseException | None = None) -> None:
    """One entry. Never raises: a log that cannot be written must not turn
    an error the user can recover from into a crash."""
    try:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {kind}: {' '.join(str(message).split())[:2000]}\n"
        if exc is not None and exc.__traceback__ is not None:
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            line += "".join(f"    {l}\n" for l in tb.rstrip().splitlines()[-30:])
        p = path()
        with _lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            try:
                if p.stat().st_size > MAX_BYTES:
                    p.replace(p.with_name(OLD))
            except OSError:
                pass
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception:  # noqa: BLE001 - see the docstring
        pass


def tail(lines: int = 50) -> list[str]:
    try:
        return path().read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return []
