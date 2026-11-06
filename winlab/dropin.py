"""Files dropped onto a machine's window, and text typed into it.

A file dropped on a Windows machine's screen goes to the Public desktop
(every user sees it) over the machine's serial agent, the same channel
`winlab cp` uses: no shared folder, no network path, nothing that would let
the lab reach the PC. Typing text is done in the browser, as keystrokes over
the screen connection, exactly what the student could type by hand.
"""
from __future__ import annotations

import re

MAX_BYTES = 64 * 1024 * 1024
FOLDER = "C:\\Users\\Public\\Desktop\\From this PC"
# Characters Windows refuses in a file name, and the names it reserves.
_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class DropError(Exception):
    pass


def safe_name(name: str) -> str:
    """The dropped file's own name, made a valid Windows file name: only the
    last path part, forbidden characters replaced, trailing dots and spaces
    dropped (Windows strips them), reserved device names prefixed."""
    base = re.split(r"[\\/]", name or "")[-1]
    base = _BAD.sub("_", base).strip().rstrip(". ")[:120]
    if not base:
        raise DropError("the file has no name")
    if base.split(".")[0].lower() in _RESERVED:
        base = "_" + base
    return base


def folder(core: bool = False) -> str:
    """Server Core has no desktop to show the file on: it goes to a short
    folder that is quick to reach from the prompt instead."""
    from .servercore import DROP_FOLDER
    return DROP_FOLDER if core else FOLDER


def dest_path(name: str, core: bool = False) -> str:
    return f"{folder(core)}\\{safe_name(name)}"


def check(node, size: int) -> None:
    if not node.is_windows:
        raise DropError(f"{node.id} is not a Windows machine; copy files to it with winlab cp")
    from .vmctl import service_on
    if not service_on(node, "files"):
        raise DropError(f"Guest services is off in {node.id}'s settings (Integration Services): "
                        f"turn it on to copy files into the machine")
    if size <= 0:
        raise DropError("the file is empty")
    if size > MAX_BYTES:
        raise DropError(f"the file is {size >> 20} MB; dropping takes files up to {MAX_BYTES >> 20} MB "
                        f"(the serial agent is slow): use an ISO with winlab media, or a USB folder image")


def running(lab_name: str, node_id: str):
    """The running machine's state record, or DropError."""
    from . import state
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not state.pid_alive(ns.pid):
        raise DropError(f"{node_id} is not running: start it, then drop the file again")
    return ns


def send(lab_name: str, node_id: str, name: str, data: bytes, emit, connect=None,
         core: bool = False) -> str:
    """Writes the file into the running machine; returns where it landed."""
    from .guestctl import GuestChannel, GuestError
    path = dest_path(name, core)
    if connect is None:
        ns = running(lab_name, node_id)

        def connect():
            return GuestChannel(ns.serial_port).connect(retries=8, delay=2)
    emit(f"copying {safe_name(name)} ({max(1, len(data) >> 10)} KB) to {node_id} over the agent…")
    try:
        ch = connect()
    except GuestError as exc:
        raise DropError(f"{node_id}'s agent does not answer yet: {exc}") from exc
    try:
        ch.put_file(path, data)
    except GuestError as exc:
        raise DropError(str(exc)) from exc
    finally:
        ch.close()
    emit(f"done: {path} (at its prompt: cd {folder(True)})" if core else
         f"done: {path} (on every user's desktop, folder 'From this PC')")
    return path
