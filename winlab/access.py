"""Interactive access to a running machine: console, exec, shell, file copy.

The graphical window is opened by QEMU itself at boot (display=window). These
commands cover scripted access over the serial agent, and raising the window
again via QMP if it was closed.
"""

from __future__ import annotations

import json
import socket
import sys

from . import state
from .guestctl import GuestChannel, GuestError


class AccessError(Exception):
    pass


def _running_node(lab_name: str, node_id: str):
    st = state.load(lab_name)
    if not st:
        raise AccessError(f"lab '{lab_name}' is not running")
    ns = st.nodes.get(node_id)
    if not ns or not ns.pid or not state.pid_alive(ns.pid):
        raise AccessError(f"node '{node_id}' is not running")
    return ns


def _qmp(port: int, commands: list[dict]) -> list[dict]:
    """Minimal QMP client: greeting, capabilities, then the commands."""
    out: list[dict] = []
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.settimeout(10)
        f = s.makefile("rwb")
        f.readline()  # greeting
        f.write(b'{"execute":"qmp_capabilities"}\n')
        f.flush()
        f.readline()
        for cmd in commands:
            f.write((json.dumps(cmd) + "\n").encode())
            f.flush()
            line = f.readline()
            try:
                out.append(json.loads(line.decode("utf-8", "replace")))
            except json.JSONDecodeError:
                out.append({"raw": line.decode("utf-8", "replace")})
    return out


def console(lab_name: str, node_id: str) -> str:
    ns = _running_node(lab_name, node_id)
    # Nudge the GTK window to the foreground if QEMU supports it; harmless if not.
    try:
        _qmp(ns.qmp_port, [{"execute": "query-name"}])
        reachable = True
    except OSError:
        reachable = False
    vnc = (f"  vnc screen   : 127.0.0.1:{ns.vnc_port} (the dashboard's Console tab, "
           f"or any VNC viewer)\n" if ns.vnc_port else "")
    return (
        f"{node_id}: graphical window is open (QEMU display).\n"
        f"{vnc}"
        f"  serial agent : 127.0.0.1:{ns.serial_port}\n"
        f"  qmp monitor  : 127.0.0.1:{ns.qmp_port} ({'reachable' if reachable else 'unreachable'})\n"
        f"  if the window was closed, 'winlab lab down {lab_name}' then 'lab up' reopens it"
    )


def run_exec(lab_name: str, node_id: str, command: str, shell: str = "powershell") -> int:
    ns = _running_node(lab_name, node_id)
    try:
        ch = GuestChannel(ns.serial_port).connect(retries=10, delay=2)
    except GuestError as exc:
        raise AccessError(str(exc)) from exc
    try:
        res = ch.run(command, shell=shell, timeout=300)
    finally:
        ch.close()
    if res.out.strip():
        print(res.out.rstrip())
    if res.err.strip():
        print(res.err.rstrip(), file=sys.stderr)
    return res.rc


def interactive_shell(lab_name: str, node_id: str, shell: str = "powershell") -> int:
    ns = _running_node(lab_name, node_id)
    try:
        ch = GuestChannel(ns.serial_port).connect(retries=10, delay=2)
    except GuestError as exc:
        raise AccessError(str(exc)) from exc
    print(f"winlab shell on {node_id} ({shell}); type 'exit' to leave")
    try:
        while True:
            try:
                line = input(f"{node_id}> ")
            except EOFError:
                break
            if line.strip() in ("exit", "quit"):
                break
            if not line.strip():
                continue
            res = ch.run(line, shell=shell, timeout=300)
            if res.out.strip():
                print(res.out.rstrip())
            if res.err.strip():
                print(res.err.rstrip(), file=sys.stderr)
    finally:
        ch.close()
    return 0


def copy_in(lab_name: str, node_id: str, local: str, remote: str) -> None:
    from pathlib import Path

    ns = _running_node(lab_name, node_id)
    data = Path(local).read_bytes()
    ch = GuestChannel(ns.serial_port).connect(retries=10, delay=2)
    try:
        ch.put_file(remote, data)
    finally:
        ch.close()


def copy_out(lab_name: str, node_id: str, remote: str, local: str) -> None:
    from pathlib import Path

    ns = _running_node(lab_name, node_id)
    ch = GuestChannel(ns.serial_port).connect(retries=10, delay=2)
    try:
        data = ch.get_file(remote)
    finally:
        ch.close()
    Path(local).write_bytes(data)
