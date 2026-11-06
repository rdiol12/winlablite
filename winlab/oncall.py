"""On call: a helpdesk shift of blind tickets against the running lab.

A shift is a queue of tickets. Each ticket is one guest fault, broken for
real on a running machine that can take it, and shown only as a user would
report it: who called and what they see. No fault name, no hint ladder. The
student finds and fixes it, then says so; winlab runs the fault's verify on
the machine. A ticket fixed quickly scores most, a wrong "it's fixed" costs,
and an escalated ticket scores nothing (winlab undoes the fault and the
next ticket comes in). When the clock runs out the shift ends, open work is
undone, and the result is kept with the student's progress.

The module decides and records; the caller runs the commands, through a
`runner(node, command, shell) -> (ok, stdout)` it passes in, so the desktop
and the command line share one shift.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Callable

from . import guestfaults as gf
from . import paths

Runner = Callable[[str, str, str], tuple[bool, str]]

BASE_POINTS = 100
TARGET_MINUTES = 15       # a ticket closed within this keeps every point
LATE_PER_MINUTE = 2       # then this many points a minute
FLOOR_POINTS = 30         # a slow fix still beats an escalation
WRONG_CLAIM = 10          # "it's fixed" when it is not
LENGTHS = (30, 45, 60, 90)

# What the caller says. {node} is the machine's name, the rest the fault's
# parameters. Faults with preconditions a shift cannot arrange (a profile
# that must exist first) have no ticket and never come up.
TICKETS: dict[str, tuple[str, str]] = {
    "service-stopped": ("Operations", "Something on {node} stopped answering an hour ago. The server pings and you can sign in to it, but the service people use on it is dead."),
    "disk-full": ("Facilities team", "{node} is crawling and an app on it says it cannot save. It was fine yesterday."),
    "password-expired": ("Alice in Sales", "I typed my password right, I'm sure, and it won't let me in anywhere. It worked on Friday. (my user is {user})"),
    "account-locked": ("Alice in Sales", "It says my account is locked. I haven't even tried today! (user {user})"),
    "time-skew": ("Team lead, 2nd floor", "{node} throws errors whenever it talks to the domain: something about a clock or a ticket. Shares on it fail too."),
    "dns-wrong": ("Branch office", "{node} can't find the domain any more. Group Policy fails and shares only open by IP address."),
    "share-removed": ("Finance", "Our {share} drive is gone. The server is there, the files must be there, but \\\\{node}\\{share} says not found."),
    "firewall-blocks-rdp": ("Second-line support", "I can't Remote Desktop into {node}. It answers ping, it's up, someone says nothing changed."),
    "high-cpu": ("Monitoring alert", "{node}: CPU above 95% for twenty minutes. Users say everything on it is slow."),
    "driver-missing": ("Desk-side visit", "{node} has no network at all. The cable is in, the switch light is on."),
    "sql-tcp-disabled": ("App team", "Our app can't reach the database on {node}: 'server was not found or was not accessible'. The DBA says the database is fine."),
    "exporter-stopped": ("Monitoring", "The dashboard shows {node} as down with every panel empty, but people are using it right now."),
    "secure-channel-broken": ("Helpdesk", "Nobody can sign in to {node} with a domain account: 'the trust relationship between this workstation and the primary domain failed'."),
    "replication-disabled": ("Branch IT", "We reset a password at HQ an hour ago and the user still can't sign in at the branch. Changes don't seem to arrive on {node}."),
    "gpo-filtered-out": ("Everyone, it seems", "The company drive disappeared for all of us this morning. Logging off and on doesn't bring it back."),
    "srv-records-missing": ("Desktop team", "New PCs fail to join the domain and new users can't sign in: 'an Active Directory domain controller could not be contacted'. {node} is up and answers ping."),
    "https-cert-expired": ("Intranet users", "The website on {node} shows a big red security warning in every browser since this morning."),
    "dhcp-scope-full": ("New starter", "My new laptop has no network. It has an address starting 169.254. Everyone else is fine."),
    "print-queue-stuck": ("Reception", "I printed the visitor badges twenty minutes ago and nothing came out. Others say the same about {printer}."),
    "wsus-client-cannot-reach": ("Patch report", "{node} hasn't reported to WSUS in days and Windows Update on it fails with a timeout."),
    "linux-service-stopped": ("Operations", "A service on {node} stopped answering."),
    "systemd-service-stopped": ("Security team", "No logs have arrived from anywhere since this morning; the collector is {node}."),
    "linux-disk-full": ("Operations", "{node} says 'No space left on device' and its logs stopped."),
    "linux-dns-wrong": ("Operations", "{node} can't resolve any names: 'Temporary failure in name resolution'."),
    "pf-disabled": ("Whole office", "The office has no Internet since lunch and the web server is gone from outside. The firewall {node} looks fine in its GUI."),
    "attack-in-the-logs": ("Security team", "Our monitoring trial flagged a wave of failed sign-ins on {node} overnight, and someone swears a new admin account showed up. Find out what happened and clean it up. Write what you found in C:\\winlab\\incident.txt."),
}

# service-stopped needs a service the machine really runs.
_SERVICE_BY_ROLE = (("dns", "DNS"), ("ad-ds", "DNS"), ("dhcp", "DHCPServer"), ("iis", "W3SVC"),
                    ("file", "LanmanServer"), ("printer", "Spooler"))


def guest_runner(lab_name: str) -> Runner:
    """A Runner over the serial agent of a running lab's machines."""
    from . import state
    from .guestctl import GuestChannel, GuestError

    def run(node: str, cmd: str, shell: str) -> tuple[bool, str]:
        st = state.load(lab_name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return False, f"{node} is not running"
        try:
            ch = GuestChannel(ns.serial_port).connect(retries=8, delay=2)
        except GuestError as exc:
            return False, str(exc)
        try:
            res = ch.run(cmd, shell=shell, timeout=180)
        finally:
            ch.close()
        return res.ok, res.out
    return run


def running_nodes(lab) -> list[str]:
    from . import state
    st = state.load(lab.name)
    return [n for n, ns in (st.nodes.items() if st else [])
            if n in lab.nodes and state.pid_alive(ns.pid)]


def shift_file() -> Path:
    return paths.VAR / "oncall.json"


def load() -> dict | None:
    try:
        raw = json.loads(shift_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return raw if isinstance(raw, dict) and raw.get("tickets") else None


def save(shift: dict | None) -> None:
    f = shift_file()
    if shift is None:
        f.unlink(missing_ok=True)
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(shift, indent=2), encoding="utf-8")
    tmp.replace(f)


def candidates(lab, running: list[str]) -> list[tuple[str, str, dict]]:
    """(scenario, node, parameters) for every ticket that can be raised on a
    running machine of this lab."""
    from . import naming, roles

    base = gf.lab_params(lab)
    out = []
    for node_id in running:
        n = lab.nodes.get(node_id)
        if n is None:
            continue
        have = roles.effective_roles(n)
        for sid in TICKETS:
            f = gf.SCENARIOS.get(sid)
            if f is None or not gf.applies_to(f, n.kind, n.image, have):
                continue
            p = dict(base)
            p["node"] = naming.hostname_of(n)
            if sid == "service-stopped":
                svc = next((s for r, s in _SERVICE_BY_ROLE if r in have), "")
                if not svc:
                    continue
                p["service"] = svc
            if sid in ("dns-wrong", "time-skew", "secure-channel-broken") and "ad-ds" in have:
                continue        # a DC pointing at itself is another lesson
            if sid == "wsus-client-cannot-reach" and "wsus" in have:
                continue        # the update server is not its own client
            out.append((sid, node_id, p))
    return out


def plan(lab, running: list[str], count: int, rng: random.Random | None = None) -> list[dict]:
    """Up to `count` tickets, no machine twice in a row and no fault twice,
    so a shift moves around the network like a real queue."""
    rng = rng or random.Random()
    pool = candidates(lab, running)
    rng.shuffle(pool)
    out: list[dict] = []
    used: set[str] = set()
    last = ""
    for _ in range(count):
        pick = next((c for c in pool if c[0] not in used and c[1] != last), None) \
            or next((c for c in pool if c[0] not in used), None)
        if pick is None:
            break
        sid, node, p = pick
        caller, text = TICKETS[sid]
        out.append({"scenario": sid, "node": node, "params": p, "caller": caller,
                    "text": gf._fill(text, p), "status": "queued", "opened": 0.0, "closed": 0.0,
                    "wrong": 0, "points": 0})
        used.add(sid)
        last = node
    return out


def _now() -> float:
    return time.time()


def start(lab, running: list[str], minutes: int, count: int, runner: Runner,
          rng: random.Random | None = None, now: float | None = None) -> dict:
    if load():
        raise RuntimeError("a shift is already running: end it first")
    tickets = plan(lab, running, count, rng)
    if not tickets:
        raise RuntimeError("no ticket fits the machines that are running: start a few first")
    t = _now() if now is None else now
    shift = {"lab": lab.name, "started": t, "ends": t + 60 * int(minutes), "minutes": int(minutes),
             "tickets": tickets, "done": False}
    _open_next(shift, runner, t)
    save(shift)
    return shift


def current(shift: dict) -> dict | None:
    return next((t for t in shift["tickets"] if t["status"] == "open"), None)


def _open_next(shift: dict, runner: Runner, now: float) -> None:
    for t in shift["tickets"]:
        if t["status"] != "queued":
            continue
        cmd, shell = gf.build_command(t["scenario"], t["params"], clear=False)
        ok, _ = runner(t["node"], cmd, shell)
        if ok:
            t["status"], t["opened"] = "open", now
            return
        t["status"] = "skipped"    # the machine refused the fault; the caller never rang
    _finish(shift, now)


def points(ticket: dict) -> int:
    minutes = max(0.0, (ticket["closed"] - ticket["opened"]) / 60)
    late = max(0.0, minutes - TARGET_MINUTES)
    p = BASE_POINTS - int(late * LATE_PER_MINUTE)
    return max(FLOOR_POINTS, p) - WRONG_CLAIM * int(ticket.get("wrong", 0))


def resolve(shift: dict, runner: Runner, now: float | None = None) -> tuple[bool, str]:
    """The student says the open ticket is fixed: verify it on the machine."""
    t = _now() if now is None else now
    if expire(shift, runner, t):
        return False, "the shift is over"
    tk = current(shift)
    if tk is None:
        return False, "no open ticket"
    cmd, shell, expect = gf.verify_command(tk["scenario"], tk["params"])
    ok, out = runner(tk["node"], cmd, shell)
    if not (ok and gf.is_fixed(out, expect)):
        tk["wrong"] += 1
        save(shift)
        return False, f"the caller rings back: still broken (-{WRONG_CLAIM} points)"
    tk["status"], tk["closed"] = "fixed", t
    tk["points"] = points(tk)
    _open_next(shift, runner, t)
    save(shift)
    return True, f"closed: {tk['points']} points"


def escalate(shift: dict, runner: Runner, now: float | None = None) -> str:
    """Hand the open ticket to second line: winlab undoes the fault, no points."""
    t = _now() if now is None else now
    tk = current(shift)
    if tk is None:
        return "no open ticket"
    _undo(tk, runner)
    tk["status"], tk["closed"], tk["points"] = "escalated", t, 0
    if not expire(shift, runner, t):
        _open_next(shift, runner, t)
    save(shift)
    return "escalated: second line fixed it, no points"


def _undo(tk: dict, runner: Runner) -> None:
    cmd, shell = gf.build_command(tk["scenario"], tk["params"], clear=True)
    runner(tk["node"], cmd, shell)


def expire(shift: dict, runner: Runner, now: float) -> bool:
    """End the shift when its time is up; open work is undone and missed."""
    if shift.get("done"):
        return True
    if now < shift["ends"]:
        return False
    end(shift, runner, now)
    return True


def end(shift: dict, runner: Runner, now: float | None = None) -> dict:
    t = _now() if now is None else now
    tk = current(shift)
    if tk is not None:
        _undo(tk, runner)
        tk["status"], tk["closed"], tk["points"] = "missed", t, 0
    for q in shift["tickets"]:
        if q["status"] == "queued":
            q["status"] = "not reached"
    _finish(shift, t)
    save(shift)
    return summary(shift)


def _finish(shift: dict, now: float) -> None:
    if shift.get("done"):
        return
    shift["done"] = True
    shift["finished"] = now
    from . import progress
    progress.record_shift(summary(shift))


def summary(shift: dict) -> dict:
    tk = shift["tickets"]
    fixed = [t for t in tk if t["status"] == "fixed"]
    mins = [(t["closed"] - t["opened"]) / 60 for t in fixed]
    return {"lab": shift["lab"], "started": shift["started"], "minutes": shift["minutes"],
            "tickets": len([t for t in tk if t["status"] != "skipped"]), "fixed": len(fixed),
            "escalated": sum(1 for t in tk if t["status"] == "escalated"),
            "score": sum(t["points"] for t in tk),
            "max": BASE_POINTS * len([t for t in tk if t["status"] != "skipped"]),
            "avg_minutes": round(sum(mins) / len(mins), 1) if mins else 0.0,
            "solved": [t["scenario"] for t in fixed]}


def view(shift: dict | None, now: float | None = None) -> dict:
    """What the On call window shows: the open ticket in the caller's words,
    the queue, the clock and the score so far. Never the fault's name until
    the ticket is closed."""
    if not shift:
        return {"active": False, "lengths": list(LENGTHS)}
    t = _now() if now is None else now
    rows = []
    for i, tk in enumerate(shift["tickets"], 1):
        row = {"n": i, "status": tk["status"], "caller": tk["caller"], "id": tk["node"],
               "node": tk["params"].get("node", tk["node"]),
               "points": tk["points"], "wrong": tk["wrong"]}
        if tk["status"] != "queued":
            row["text"] = tk["text"]
            row["opened"] = tk["opened"]
        if tk["status"] in ("fixed", "escalated", "missed"):
            f = gf.SCENARIOS.get(tk["scenario"])
            row["was"] = f.title if f else tk["scenario"]
        rows.append(row)
    return {"active": not shift.get("done"), "done": bool(shift.get("done")), "lab": shift["lab"],
            "left": max(0, int(shift["ends"] - t)), "minutes": shift["minutes"], "tickets": rows,
            "summary": summary(shift), "lengths": list(LENGTHS)}
