"""The server room: servers you run from your desk, not from their screens.

In a real company the servers are in a locked room down the corridor. Their
monitors are not on your desk: you run them from your admin PC, over Remote
Desktop, PowerShell remoting (WinRM), Server Manager, Windows Admin Center
and SSH, and when a server will not answer any of those, over its BMC's
virtual console or, last of all, by walking to the room. An opt-in lab
setting (`server_room = true` in the lab, or the switch in the Machines
window) makes the lab work like that:

- A server's screen (and a Linux server's serial terminal) does not open
  from the desk. The desktop shows the locked door instead.
- "Walk to the server room" costs lab time, not real time: the lab clock
  (winlab/labclock.py) moves on WALK_MINUTES and you are there, with no
  wait at the desk. The walk is written in the server room's access log
  with the lab-clock time and the reason given, as a real access log asks.
  While you are in the room the servers' screens open and your desk's
  screens do not; walking back moves the clock on the same again.
- What exists inside the lab is untouched: a BMC's virtual console (on the
  management network, winlab/power.py) and the console cable to a switch or
  router (winlab/consolecable.py) are lab equipment reached from a lab PC,
  so they work as they would in the building.

Nothing here touches a machine but the clock. The state is a small file
beside the lab's disks (var/labs/<lab>/serverroom.json). A state saved while
walking took real time (older winlab) still settles when its arrival time
has passed.
The inherited company lab (winlab/inherited.py) turns the setting on; every
other lab has it off until the student turns it on.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import paths
from .model import LINUX, WINDOWS_SERVER

WALK_MINUTES = 5           # lab minutes one way, desk to server room: the clock moves on, nobody waits
LOG_KEEP = 200             # access log entries kept
DESK, ROOM = "desk", "room"
TO_ROOM, TO_DESK = "walking-to-room", "walking-to-desk"
# Linux machines that sit on a desk or a shelf in the office, not in the room.
_DESK_PREFIXES = ("pc", "ws", "lap", "desk", "prn", "printer", "phone", "ap", "cam")


class RoomError(Exception):
    pass


def room_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / "serverroom.json"


def load(lab_name: str) -> dict:
    try:
        raw = json.loads(room_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw.setdefault("where", DESK)
            raw.setdefault("log", [])
            return raw
    except (OSError, ValueError):
        pass
    return {"where": DESK, "since": 0.0, "arrive": 0.0, "log": []}


def save(lab_name: str, st: dict) -> None:
    f = room_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    st["log"] = st.get("log", [])[-LOG_KEEP:]
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    tmp.replace(f)


# ------------------------------------------------------------- pure logic
def in_room(lab, node_id: str) -> bool:
    """Whether a machine lives in the server room: every Windows server and
    every Linux server; desk PCs, laptops, printers and phones stay in the
    office, and the lab's router is reached over its own console."""
    node = lab.nodes.get(node_id)
    if node is None:
        return False
    if node.kind == WINDOWS_SERVER:
        return True
    return node.kind == LINUX and not node_id.startswith(_DESK_PREFIXES) and not node.vars.get("devvm")


def where(st: dict, now: float) -> str:
    """Where the student is at `now`: a walk that has arrived is over."""
    w = st.get("where", DESK)
    if w in (TO_ROOM, TO_DESK) and now >= float(st.get("arrive") or 0):
        return ROOM if w == TO_ROOM else DESK
    return w


def settle(st: dict, now: float) -> bool:
    """Writes an arrival into the state and its log; True when it changed."""
    w = st.get("where", DESK)
    got = where(st, now)
    if got == w:
        return False
    st["where"], st["since"] = got, float(st.get("arrive") or now)
    st.setdefault("log", []).append({"real": st["since"], "lab": _lab_stamp(st, st["since"]),
                                     "event": "in the server room" if got == ROOM else "back at the desk"})
    return True


def screen_allowed(lab, node_id: str, st: dict, now: float) -> tuple[bool, str]:
    """Whether the desktop may open this machine's screen or terminal now,
    and why not. Off, the setting changes nothing."""
    if not getattr(lab, "server_room", False) or node_id == "fabric" or node_id not in lab.nodes:
        return True, ""
    w = where(st, now)
    if in_room(lab, node_id):
        if w == ROOM:
            return True, ""
        if w == TO_ROOM:
            return False, f"{node_id} is in the server room: you are on your way there"
        return False, (f"{node_id} is in the locked server room. Manage it from your desk (Remote Desktop, "
                       f"PowerShell remoting, Server Manager, Windows Admin Center, SSH, its BMC), "
                       f"or walk to the server room")
    if w == DESK:
        return True, ""
    return False, f"you are {'in' if w == ROOM else 'on the way to'} the server room: {node_id} is on a desk in the office"


def walk(st: dict, now: float, to: str, reason: str = "", lab_now: float | None = None,
         minutes: int = WALK_MINUTES) -> str:
    """A walk to the room or back to the desk, logged at lab time: you are
    there at once, and the walk's minutes are lab minutes (the caller moves
    the lab clock on by them). The message."""
    w = where(st, now)
    settle(st, now)
    if to not in (ROOM, DESK):
        raise RoomError("walk to the room or to the desk")
    if w == to or (w == TO_ROOM and to == ROOM) or (w == TO_DESK and to == DESK):
        return "you are already " + ("there" if w == to else "on your way")
    if w in (TO_ROOM, TO_DESK):
        raise RoomError("you are walking; wait until you get there")
    reason = " ".join(str(reason or "").split())[:200]
    if to == ROOM and not reason:
        raise RoomError("the server room's access log asks why you are going in: give a reason")
    st["lab_offset"] = (lab_now - now) if lab_now is not None else st.get("lab_offset", 0.0)
    left = now + float(st["lab_offset"] or 0.0)
    there = left + minutes * 60
    st["where"], st["since"], st["arrive"] = to, now, now
    st.setdefault("log", []).extend([
        {"real": now, "lab": _stamp(left), "lab_at": left,
         "event": "walked to the server room" if to == ROOM else "walked back to the desk",
         "reason": reason, "minutes": minutes},
        {"real": now, "lab": _stamp(there), "lab_at": there,
         "event": "in the server room" if to == ROOM else "back at the desk"}])
    return (f"walked to the server room: the lab clock moves on {minutes} minutes; logged: {reason}" if to == ROOM
            else f"walked back to your desk: the lab clock moves on {minutes} minutes")


def visits(st: dict) -> list[dict]:
    return [e for e in st.get("log", []) if e.get("event") == "walked to the server room"]


def minutes_away(st: dict, now: float, lab_now: float | None = None) -> float:
    """Lab minutes spent away from the desk (walking or in the room), all told."""
    total, left = 0.0, None
    for e in st.get("log", []):
        at = float(e.get("lab_at") or e.get("real") or 0)
        if e.get("event") == "walked to the server room":
            left = at
        elif e.get("event") == "back at the desk" and left is not None:
            total += at - left
            left = None
    if left is not None:
        total += max(0.0, (now if lab_now is None else lab_now) - left)
    return round(total / 60.0, 1)


def _stamp(lab: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(lab))


def _lab_stamp(st: dict, real: float) -> str:
    return _stamp(real + float(st.get("lab_offset") or 0.0))


# ------------------------------------------------------------------- I/O
def _lab_now(lab_name: str, now: float) -> float:
    from . import labclock
    try:
        return labclock.load(lab_name).now(now)
    except Exception:  # noqa: BLE001 - the log falls back to real time
        return now


def current(lab_name: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    st = load(lab_name)
    if settle(st, now):
        save(lab_name, st)
    return st


def allowed(lab, node_id: str, now: float | None = None) -> tuple[bool, str]:
    """screen_allowed against the saved state (the console's WebSocket asks)."""
    now = time.time() if now is None else now
    if not getattr(lab, "server_room", False):
        return True, ""
    return screen_allowed(lab, node_id, current(lab.name, now), now)


def view(lab, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    st = current(lab.name, now)
    w = where(st, now)
    return {
        "on": bool(getattr(lab, "server_room", False)),
        "where": w, "arrive": float(st.get("arrive") or 0), "left": max(0, int(float(st.get("arrive") or 0) - now))
        if w in (TO_ROOM, TO_DESK) else 0,
        "walk_minutes": WALK_MINUTES,
        "servers": [n.id for n in lab.node_list() if in_room(lab, n.id)],
        "visits": len(visits(st)), "minutes_away": minutes_away(st, now, _lab_now(lab.name, now)),
        "log": list(reversed(st.get("log", [])[-30:])),
    }


def set_on(lab, on: bool) -> str:
    from . import editor
    lab.server_room = bool(on)
    editor.save(lab)
    return ("the servers are in the locked server room: manage them from your desk" if on
            else "the server room is open: every machine's screen opens from the desk")


def move_clock(lab, minutes: int = WALK_MINUTES) -> None:
    """The walk's lab minutes: the lab clock moves on (labclock.change, which
    sets the running machines' clocks too). With machines running that
    takes a while, so it runs in the background and the desktop answers at once."""
    import threading
    from . import labclock

    def go():
        try:
            labclock.change(lab, "jump", f"{int(minutes)}min")
        except Exception:  # noqa: BLE001 - a clock that did not move still leaves the walk logged
            pass
    if labclock._running(lab.name):
        threading.Thread(target=go, name=f"room-walk-{lab.name}", daemon=True).start()
    else:
        go()


def act(lab, action: str, params: dict, now: float | None = None, move=None) -> dict:
    """room-walk (reason), room-back, room-set (on). A walk moves the lab
    clock on (`move`, move_clock unless a test passes its own)."""
    now = time.time() if now is None else now
    try:
        if action == "room-set":
            return {"ok": True, "message": set_on(lab, params.get("on") in ("1", "true", True, 1))}
        if not getattr(lab, "server_room", False):
            return {"ok": False, "message": "this lab has no locked server room: every screen opens from the desk"}
        st = current(lab.name, now)
        if action == "room-walk":
            msg = walk(st, now, ROOM, params.get("reason", ""), _lab_now(lab.name, now))
        elif action == "room-back":
            msg = walk(st, now, DESK, "", _lab_now(lab.name, now))
        else:
            return {"ok": False, "message": f"unknown action {action}"}
        save(lab.name, st)
        if not msg.startswith("you are already"):
            (move or move_clock)(lab, WALK_MINUTES)
        return {"ok": True, "message": msg, "room": view(lab, now)}
    except RoomError as exc:
        return {"ok": False, "message": str(exc)}


def render(lab, now: float | None = None) -> str:
    v = view(lab, now)
    if not v["on"]:
        return f"{lab.name}: no locked server room (winlab room {lab.name} on)"
    where_txt = {DESK: "at your desk", ROOM: "in the server room",
                 TO_ROOM: f"walking to the server room ({v['left']} s)",
                 TO_DESK: f"walking back to your desk ({v['left']} s)"}[v["where"]]
    lines = [f"{lab.name}: servers in the locked server room: {', '.join(v['servers']) or 'none'}",
             f"you are {where_txt}; {v['visits']} visit(s), {v['minutes_away']} min away from the desk"]
    for e in reversed(v["log"][:10]):
        lines.append(f"  {e.get('lab', '')}  {e.get('event', '')}" + (f": {e['reason']}" if e.get("reason") else ""))
    return "\n".join(lines)


# ------------------------------------------------- grading from the log
def _check_logged(lab) -> tuple[bool, str]:
    """Every walk to the server room has its reason in the access log, and
    there were at most two of them: the servers are run from the desk."""
    st = load(lab.name)
    v = visits(st)
    if not lab.server_room:
        return False, "the server room is open: turn the locked server room on (Machines window)"
    if any(not e.get("reason") for e in v):
        return False, "a walk to the server room has no reason in the access log"
    if len(v) > 2:
        return False, f"{len(v)} walks to the server room: run the servers from your desk"
    return True, f"{len(v)} walk(s) to the server room, each with its reason"


def _register() -> None:
    from . import exercises
    exercises.register_winlab_check("server-room-remote-only", _check_logged)


_register()


# -------------------------------------------------------------------- CLI
def add_cli(sub) -> None:
    p = sub.add_parser("room", help="the locked server room: run the servers from your desk; walking there takes "
                                    "lab time (the clock moves on) and is logged")
    p.add_argument("lab")
    p.add_argument("op", nargs="?", default="status", choices=("status", "walk", "back", "on", "off"),
                   help="status (default), walk to the room, back to the desk, or turn the setting on or off")
    p.add_argument("reason", nargs="*", help="walk: why you are going in (the access log asks)")


def run_cli(args) -> int:
    import sys
    from . import schema
    lab = schema.load(args.lab)
    if args.op == "status":
        print(render(lab))
        return 0
    action = {"walk": "room-walk", "back": "room-back", "on": "room-set", "off": "room-set"}[args.op]
    r = act(lab, action, {"reason": " ".join(args.reason), "on": args.op == "on"})
    print(r["message"], file=sys.stdout if r["ok"] else sys.stderr)
    return 0 if r["ok"] else 1
