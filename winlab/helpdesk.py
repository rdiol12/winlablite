"""The helpdesk queue: tickets from the lab's staff, on the lab clock.

On-call (winlab/oncall.py) is a timed drill, one blind ticket at a time. The
queue is the job itself: tickets pile up while the lab runs, from the people
in the lab's directory (winlab/people.py), from the monitoring that pages
the admin (winlab/alerts.py) and from the simulated workday
(winlab/workday.py) when a member of staff hits something broken. Each
ticket has a priority, response and resolve targets measured on the lab
clock (winlab/labclock.py), a work log, and, when it is backed by a real
fault, the fault's own verify decides whether "resolved" is true.

This module is the store and the shared API; everything that raises a
ticket goes through `open_ticket`. The queue is kept per lab in
var/labs/<lab>/helpdesk.json.

Tickets coming in. With the queue switched on, `tick` (called by the
desktop's poll and by `winlab helpdesk tick`) raises a ticket now and then,
at the pace chosen in the queue's settings (a quiet, normal or busy day).
Each one is a real fault, broken on a running machine that can take it,
from the catalogues the rest of winlab already has: the guest faults on-call
uses (winlab/guestfaults.py, with on-call's own choice of what fits which
machine) and, on a workbench network, a dead card or a bad cable
(winlab/physfaults.py). The caller is a person from the directory: whoever
sits at the PC that broke, or someone who uses the server that did. They
say what they see and never what it is. Priority follows impact: a server
everyone uses going down is P1 or P2, one person's problem P3 or P4.

The SLA. A ticket must be answered (taken, or a note written on it) by its
respond-by time and resolved by its resolve-by time, both on the lab clock.
While it waits on the user, its resolve clock stands still. With business
hours on, P3 and P4 only count working time (a P3 rung in at 17:00 on a
Friday is not due over the weekend); P1 and P2 run round the clock.
Overnight, the clocks start when someone could act: a P3 or P4 opened
outside business hours starts its SLA at the next opening (08:00), and a P1
or P2 opened at night pages on-call (winlab/alerts.py) and counts from the
page. A night ticket nobody may be paged for (wear on its gentle level)
waits for the morning like a P3.

Ticket life: new, in progress (taken), waiting on user, resolved, closed.
Resolving a fault-backed ticket runs the fault's verify on the machine,
through a runner the caller passes in; a fault still there reopens the
ticket with the caller saying so, and that ticket is no longer a first-time
fix. A ticket with no fault (one raised by the workday or monitoring with
fault=None) resolves on the student's word and a resolution note, unless the
module that raised it registered a check for its kind of fault
(`register_check`). Stopping the queue undoes the faults it broke that are
still open, and keeps the shift's report with the student's progress.

Nothing here configures a machine for the student: the queue breaks things
and checks them; the fixing is the student's.
"""

from __future__ import annotations

import json
import random
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import labclock, paths

Runner = Callable[[str, str, str], tuple[bool, str]]

# priority -> (label, respond within, resolve within), seconds of lab time
PRIORITIES: dict[str, tuple[str, int, int]] = {
    "P1": ("Critical", 15 * 60, 4 * 3600),
    "P2": ("High", 30 * 60, 8 * 3600),
    "P3": ("Normal", 4 * 3600, 3 * 86400),
    "P4": ("Low", 86400, 10 * 86400),
}
STATES = ("new", "in-progress", "waiting", "resolved", "closed")
OPEN_STATES = ("new", "in-progress", "waiting")
SOURCES = ("phone", "mail", "walk-up", "portal", "monitoring", "workday")

# pace -> (lab seconds between tickets on average, most queue tickets open at once)
PACES: dict[str, tuple[int, int]] = {
    "quiet": (120 * 60, 2),
    "normal": (45 * 60, 4),
    "busy": (15 * 60, 6),
}
DEFAULT_SETTINGS = {"on": False, "pace": "normal", "business_hours": False,
                    "open_hour": 8, "close_hour": 17}
BUSINESS_PRIORITIES = ("P3", "P4")   # the ones business hours apply to
FIRST_AFTER = 60                      # the first ticket rings this long after the queue opens
REPLY_AFTER = 20 * 60                 # a caller asked something answers after this long
CLOSE_AFTER = 86400                   # a resolved ticket closes itself after a lab day

_lock = threading.RLock()             # the desktop's poll and its buttons run in threads


# ------------------------------------------------------------------ storage
def queue_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / "helpdesk.json"


def load(lab_name: str) -> dict:
    """{"next": int, "tickets": [ticket, ...]}; an empty queue when there is none.
    The queue's settings ride along under "settings" once they are set."""
    try:
        raw = json.loads(queue_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("tickets"), list):
            raw.setdefault("next", len(raw["tickets"]) + 1)
            return raw
    except (OSError, ValueError):
        pass
    return {"next": 1, "tickets": []}


def save(lab_name: str, q: dict) -> None:
    f = queue_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(q, indent=2), encoding="utf-8")
    tmp.replace(f)


def lab_now(lab_name: str, real: float | None = None) -> float:
    return labclock.load(lab_name).now(real)


def settings(q: dict) -> dict:
    """The queue's settings, with the defaults for anything not set."""
    out = dict(DEFAULT_SETTINGS)
    out.update({k: v for k, v in (q.get("settings") or {}).items() if k in DEFAULT_SETTINGS})
    if out["pace"] not in PACES:
        out["pace"] = "normal"
    return out


def _add(q: dict, *, at: float, caller: str, summary: str, body: str, priority: str, source: str,
         category: str, node: str, fault: dict | None, dedupe: str) -> dict:
    """The ticket put into `q` (not saved): a new one, or the open one with
    the same dedupe key, noted again."""
    if priority not in PRIORITIES:
        raise ValueError(f"priority must be one of {', '.join(PRIORITIES)}")
    if dedupe:
        for t in q["tickets"]:
            if t.get("dedupe") == dedupe and t["state"] in OPEN_STATES:
                t["log"].append({"at": at, "who": caller, "text": f"Again: {summary}"})
                return t
    _, respond, resolve = PRIORITIES[priority]
    t = {
        "id": f"INC{q['next']:05d}",
        "opened": at, "caller": caller, "summary": summary, "body": body,
        "priority": priority, "source": source if source in SOURCES else "phone",
        "category": category, "node": node, "fault": fault or None, "dedupe": dedupe,
        "state": "new", "respond_by": at + respond, "resolve_by": at + resolve,
        "responded": None, "resolved": None, "log": [],
    }
    s = settings(q)
    if not in_hours(at, s):
        # Out of hours: a P3/P4 waits for the morning; a P1/P2 waits for its page.
        t["morning"] = add_business(at, 0, s["open_hour"], s["close_hour"])
    q["next"] += 1
    q["tickets"].append(t)
    return t


def open_ticket(lab_name: str, *, caller: str, summary: str, body: str = "",
                priority: str = "P3", source: str = "phone", category: str = "",
                node: str = "", fault: dict | None = None, dedupe: str = "",
                now: float | None = None) -> dict:
    """Raise a ticket and keep it. `caller` is a people.py id ("admin" for
    monitoring), `fault` the backing fault when there is one
    ({"kind": "guest"|"phys"|..., "id": ..., "node": ..., "params": {...}}),
    and `dedupe` a key: while an open ticket carries the same key, no second
    one is raised and the open one is returned with a note added instead
    (monitoring repeating itself, a user calling twice)."""
    if priority not in PRIORITIES:
        raise ValueError(f"priority must be one of {', '.join(PRIORITIES)}")
    at = lab_now(lab_name) if now is None else now
    with _lock:
        q = load(lab_name)
        t = _add(q, at=at, caller=caller, summary=summary, body=body, priority=priority, source=source,
                 category=category, node=node, fault=fault, dedupe=dedupe)
        save(lab_name, q)
    return t


def open_tickets(lab_name: str) -> list[dict]:
    return [t for t in load(lab_name)["tickets"] if t["state"] in OPEN_STATES]


def find(q: dict, ticket_id: str) -> dict | None:
    """A ticket by id: INC00012, inc12 or 12."""
    k = ticket_id.strip().upper().removeprefix("INC")
    if not k.isdigit():
        return None
    return next((t for t in q["tickets"] if t["id"] == f"INC{int(k):05d}"), None)


# ------------------------------------------------------------------ checks other modules plug in
# kind -> check(lab, fault, runner) -> (fixed, detail), or None when it cannot
# be told right now (the machine is off); and kind -> undo(lab, fault, runner).
Check = Callable[[Any, dict, Runner], "tuple[bool, str] | None"]
Undo = Callable[[Any, dict, Runner], None]
_CHECKS: dict[str, Check] = {}
_UNDOS: dict[str, Undo] = {}


def register_check(kind: str, fn: Check, undo: Undo | None = None) -> None:
    """Let a module's own kind of fault decide its tickets: `fn(lab, fault,
    runner)` returns (fixed, what it saw), or None when it cannot check now.
    `undo`, when given, is what stopping the queue runs for a fault of that
    kind still open on a ticket the queue raised."""
    _CHECKS[kind] = fn
    if undo is not None:
        _UNDOS[kind] = undo


# Fault kinds whose check lives in another module, imported on first use so
# a ticket can be checked before anything else loaded that module.
_CHECK_MODULES = {"workday": "workday", "rack": "rack", "wear": "wear", "alert": "alerts", "campus": "campus"}


def has_check(fault: dict | None) -> bool:
    if not fault:
        return False
    kind = fault.get("kind")
    if kind not in _CHECKS and kind in _CHECK_MODULES:
        import importlib
        importlib.import_module(f"{__package__}.{_CHECK_MODULES[kind]}")
    return kind in _CHECKS


def _guest_fault(fid: str):
    from . import guestfaults as gf
    from . import scenariofaults
    return gf.SCENARIOS.get(fid) or scenariofaults.FAULTS.get(fid)


def _guest_run(fault: dict, runner: Runner, what: str) -> tuple[bool, str]:
    from . import guestfaults as gf
    f = _guest_fault(fault["id"])
    if f is None:
        return False, f"no fault {fault['id']}"
    return runner(fault["node"], gf._fill(getattr(f, what), fault.get("params") or {}), f.shell)


def _guest_check(lab, fault: dict, runner: Runner) -> tuple[bool, str] | None:
    from . import guestfaults as gf
    f = _guest_fault(fault["id"])
    if f is None:
        return None
    ok, out = _guest_run(fault, runner, "verify")
    if not ok:
        return None      # the machine did not answer: nothing can be said either way
    last = [ln.strip() for ln in out.strip().splitlines() if ln.strip()][-1:] or [""]
    return gf.is_fixed(out, f.expect), last[0]


def _guest_undo(lab, fault: dict, runner: Runner) -> None:
    _guest_run(fault, runner, "clear")


def _phys_rec(lab, fault: dict):
    from . import physfaults as pf
    return next((r for r in pf.refresh(lab.name)["faults"] if r["id"] == fault["id"]), None)


def _phys_check(lab, fault: dict, runner: Runner) -> tuple[bool, str] | None:
    from . import physfaults as pf
    rec = _phys_rec(lab, fault)
    if rec is None or rec["state"] != "on":
        return True, "gone"
    if pf.KINDS[rec["kind"]].side == "router":
        try:
            seen = pf.parse_probe(pf._on_router(lab.name, [pf.probe_cmd([rec])]))
        except pf.FaultError:
            return None
        if rec["id"] in seen and not pf.still_there(rec, seen[rec["id"]]):
            return True, "gone from the switch port"
    return False, "still there"


def _phys_undo(lab, fault: dict, runner: Runner) -> None:
    from . import physfaults as pf
    rec = _phys_rec(lab, fault)
    if rec is not None and rec["state"] == "on":
        pf.clear(lab, rec["id"], how="undone")


register_check("guest", _guest_check, _guest_undo)
register_check("phys", _phys_check, _phys_undo)


# ------------------------------------------------------------------ what people say
# Subject lines, in the caller's words. {node} and the rest are the fault's parameters.
SUMMARY: dict[str, str] = {
    "service-stopped": "{node} not working",
    "disk-full": "{node} very slow, cannot save",
    "password-expired": "Cannot sign in",
    "account-locked": "My account is locked",
    "time-skew": "Errors talking to the domain on {node}",
    "dns-wrong": "{node} cannot find the domain",
    "share-removed": "{share} drive has gone",
    "firewall-blocks-rdp": "Cannot Remote Desktop to {node}",
    "high-cpu": "{node}: CPU high for 20 minutes",
    "driver-missing": "{node} has no network",
    "sql-tcp-disabled": "Our app cannot reach the database",
    "exporter-stopped": "Dashboard shows {node} as down",
    "secure-channel-broken": "Nobody can sign in to {node}",
    "replication-disabled": "Password reset not working at the branch",
    "gpo-filtered-out": "Company drive missing for everyone",
    "srv-records-missing": "New PCs cannot join the domain",
    "https-cert-expired": "Security warning on the intranet site",
    "dhcp-scope-full": "New laptop has no network",
    "print-queue-stuck": "Nothing comes out of the printer",
    "wsus-client-cannot-reach": "{node} not reporting to WSUS",
    "linux-service-stopped": "Service on {node} not answering",
    "systemd-service-stopped": "No logs arriving at {node}",
    "linux-disk-full": "{node}: no space left",
    "linux-dns-wrong": "{node} cannot resolve names",
    "pf-disabled": "No Internet in the office",
    "attack-in-the-logs": "Suspicious sign-ins on {node}",
}

# What someone sitting at the PC that broke says about it. Only these faults
# are raised on a desk PC; the rest happen to servers.
DESK_TEXT: dict[str, tuple[str, str]] = {
    "dns-wrong": ("My PC cannot find anything", "Since this morning my PC cannot open the shared drives "
                  "and it says it cannot reach the domain. Websites inside the company do not load either."),
    "time-skew": ("Errors about the time on my PC", "Whenever I open the shared drive I get an error about "
                  "the time or a ticket, and it keeps asking me to sign in again."),
    "firewall-blocks-rdp": ("IT cannot connect to my PC", "Someone from IT wanted to connect to my PC remotely "
                            "to look at something, but they say it will not let them in. It is switched on."),
    "high-cpu": ("My computer is really slow", "My computer is incredibly slow today. The fan is loud and "
                 "everything takes ages to open, even the Start menu."),
    "driver-missing": ("No network on my PC", "My PC has no network at all. The cable is plugged in, I "
                       "checked it twice, and the light on the wall socket is on."),
    "secure-channel-broken": ("Cannot log on to my PC", "I cannot log on to my PC. It says something about "
                              "the trust relationship between this workstation and the domain."),
    "disk-full": ("PC says it is full", "My PC says it is running out of space and Excel will not save "
                  "my file. I have not put anything big on it."),
}
PHYS_DESK: dict[str, tuple[str, str, str]] = {
    # physfaults kind -> (summary, what they say, priority)
    "nic": ("No network on my PC", "My PC has no network at all since a few minutes ago. Nothing opens, "
            "not even the intranet. I did not touch anything.", "P3"),
    "bad": ("Network keeps dropping", "The network on my PC is terrible today: files take forever to open "
            "and the calls I am on keep cutting out. Everyone else seems fine.", "P3"),
    "slow": ("Copying files takes forever", "Copying anything to or from the shared drive takes ages on my "
             "PC. My colleague next to me does the same in seconds.", "P4"),
}
REOPEN_TEXT = ("I just tried again and it still does not work.",
               "Sorry, it is still not working here.",
               "Still the same for me, nothing has changed.")
REPLY_TEXT = "I am back at my desk now, what did you need from me?"
# What a caller answers a question with, by the fault behind the ticket: the
# exact message they see, and that they did try the obvious. {pc} is the
# machine, {user} their account. Used by caller_reply; REPLY_TEXT is the
# fallback for a ticket with no fault behind it.
CALLER_REPLIES: dict[str, str] = {
    "password-expired": "It says \"Your password has expired and must be changed.\" but then the change does not go through. My account is {user}.",
    "account-locked": "It says \"The referenced account is currently locked out and may not be logged on to.\" I only tried a few times. Account {user}.",
    "dns-wrong": "Websites and the shared drive say \"server not found\", but some things still work. My PC is {pc}. Yes, I restarted it.",
    "linux-dns-wrong": "Anything by name fails with \"Temporary failure in name resolution\". It is {pc}.",
    "share-removed": "The S: drive shows a red cross and says \"The network path was not found.\" Yesterday it was fine. I am on {pc}.",
    "disk-full": "It keeps saying it is low on disk space and Outlook will not save anything. The server is {pc}, someone said.",
    "linux-disk-full": "Saving fails with \"No space left on device\". That is on {pc}.",
    "print-queue-stuck": "My document just sits in the queue with \"Error - Printing\" and nothing comes out. Restarting my PC did not help.",
    "time-skew": "It says \"The time and date on this computer differ from the domain\" or something like that, and I cannot sign in. {pc}.",
    "secure-channel-broken": "Sign-in says \"The trust relationship between this workstation and the primary domain failed.\" Machine {pc}.",
    "firewall-blocks-rdp": "Remote Desktop just times out on {pc}: \"Remote Desktop can't connect to the remote computer\". It pings fine, IT told me to check that.",
    "high-cpu": "Everything on {pc} is crawling, the fan is loud. I closed all my programs and restarted, same thing.",
    "https-cert-expired": "The intranet shows \"Your connection isn't private\" with NET::ERR_CERT_DATE_INVALID. On every PC here.",
    "sql-tcp-disabled": "The finance app says it cannot connect to the database server. It worked on Friday. I restarted twice.",
    "gpo-filtered-out": "My mapped drives and the printer did not come back after the restart. My colleagues have theirs. PC {pc}.",
    "dhcp-scope-full": "My laptop says \"No Internet, secured\" and has a 169.254 address. Others who came in early are fine.",
    "srv-records-missing": "Nobody here can sign in; it says \"There are currently no logon servers available\".",
    "driver-missing": "There is no network at all on {pc}: the icon has a red cross. I checked the cable, it is plugged in.",
}


def caller_reply(t: dict, staff: list[dict] | None = None) -> str:
    """What the caller says back when asked: keyed by the fault behind the
    ticket, filled with their PC and account."""
    f = t.get("fault") or {}
    fid = f.get("id") or (f.get("params") or {}).get("fault", "")
    text = CALLER_REPLIES.get(fid, "")
    if not text:
        return REPLY_TEXT if not t.get("node") else (
            f"I am back at my desk. It is {t['node'].upper()}, and yes, I restarted it this morning: same thing.")
    user = ((f.get("params") or {}).get("user") or t.get("caller") or "").strip()
    return text.format(pc=(t.get("node") or "my PC").upper(), user=user or "the usual one")


# ServiceNow-like fields: priority comes from impact and urgency (1 high .. 3 low).
CATEGORIES = ("Accounts", "Network", "Files", "Printing", "Email", "Hardware", "Applications", "Web",
              "Security", "Updates", "Monitoring", "Other")
GROUPS = ("Service Desk", "Server team", "Network team", "Desktop support", "Security")


def priority_of(impact: int, urgency: int) -> str:
    """The impact x urgency matrix: 1/1 P1; 1/2 or 2/1 P2; 1/3, 2/2, 3/1 P3; the rest P4."""
    s = int(impact) + int(urgency)
    return "P1" if s <= 2 else "P2" if s == 3 else "P3" if s == 4 else "P4"


def impact_urgency(priority: str) -> tuple[int, int]:
    return {"P1": (1, 1), "P2": (1, 2), "P3": (2, 2), "P4": (3, 3)}.get(priority, (2, 2))

# Priority for a server fault: who it stops. One person's problem is P3/P4.
SERVER_PRIORITY: dict[str, str] = {
    "disk-full": "P2", "password-expired": "P3", "account-locked": "P3", "time-skew": "P2",
    "dns-wrong": "P2", "share-removed": "P2", "firewall-blocks-rdp": "P3", "high-cpu": "P2",
    "driver-missing": "P1", "sql-tcp-disabled": "P2", "exporter-stopped": "P4",
    "secure-channel-broken": "P2", "replication-disabled": "P3", "gpo-filtered-out": "P2",
    "srv-records-missing": "P1", "https-cert-expired": "P2", "dhcp-scope-full": "P3",
    "print-queue-stuck": "P3", "wsus-client-cannot-reach": "P4", "linux-service-stopped": "P2",
    "systemd-service-stopped": "P2", "linux-disk-full": "P2", "linux-dns-wrong": "P2",
    "pf-disabled": "P1", "attack-in-the-logs": "P1",
}
SERVICE_PRIORITY = {"DNS": "P1", "LanmanServer": "P2", "DHCPServer": "P2", "W3SVC": "P2", "Spooler": "P3"}
DESK_PRIORITY = {"firewall-blocks-rdp": "P4"}
CATEGORY: dict[str, str] = {
    "password-expired": "Accounts", "account-locked": "Accounts", "secure-channel-broken": "Accounts",
    "replication-disabled": "Accounts", "dns-wrong": "Network", "dhcp-scope-full": "Network",
    "driver-missing": "Network", "linux-dns-wrong": "Network", "pf-disabled": "Network",
    "srv-records-missing": "Network", "share-removed": "Files", "gpo-filtered-out": "Files",
    "print-queue-stuck": "Printing", "attack-in-the-logs": "Security", "https-cert-expired": "Web",
    "sql-tcp-disabled": "Applications", "wsus-client-cannot-reach": "Updates",
}
# Who rings about it, when it is one department's problem.
DEPARTMENT: dict[str, str] = {"share-removed": "Finance", "print-queue-stuck": "Front desk",
                              "sql-tcp-disabled": "Finance", "gpo-filtered-out": "Operations",
                              "replication-disabled": "HR", "pf-disabled": "Sales"}
# On-call's callers that are not people: the queue raises these from monitoring.
MONITORING = ("Monitoring alert", "Monitoring", "Patch report")


def candidates(lab, running: list[str]) -> list[dict]:
    """Every ticket the queue could raise now: a fault on a running machine,
    what it would be called and how urgent it is. The caller is chosen when
    one is raised (`pick`). Desk PCs only take the faults their user would
    notice, and only when somebody sits at them."""
    from . import guestfaults as gf
    from . import oncall, people
    staff = people.load(lab)
    desks = set(people.desk_pcs(lab))
    out: list[dict] = []
    for sid, node, p in oncall.candidates(lab, running):
        fault = {"kind": "guest", "id": sid, "node": node, "params": p, "by": "queue"}
        if node in desks:
            who = people.at_pc(staff, node)
            if sid not in DESK_TEXT or who is None:
                continue
            summary, body = DESK_TEXT[sid]
            out.append({"fault": fault, "node": node, "caller": who["id"], "source": "phone",
                        "summary": summary, "body": body, "priority": DESK_PRIORITY.get(sid, "P3"),
                        "category": CATEGORY.get(sid, "Desktop")})
            continue
        caller_label, text = oncall.TICKETS[sid]
        pri = SERVICE_PRIORITY.get(p.get("service", ""), "P2") if sid == "service-stopped" \
            else SERVER_PRIORITY.get(sid, "P2")
        out.append({"fault": fault, "node": node, "caller": "", "source": "monitoring" if caller_label in MONITORING
                    else "phone", "summary": gf._fill(SUMMARY.get(sid, "{node} has a problem"), p),
                    "text": text, "priority": pri, "category": CATEGORY.get(sid, "Server"),
                    "department": DEPARTMENT.get(sid, "")})
    if getattr(lab, "workbench", False):
        for node in running:
            who = people.at_pc(staff, node) if node in desks else None
            if who is None:
                continue
            for kind, (summary, body, pri) in PHYS_DESK.items():
                out.append({"fault": {"kind": "phys", "id": "", "node": node, "params": {"fault": kind}, "by": "queue"},
                            "node": node, "caller": who["id"], "source": "phone", "summary": summary,
                            "body": body, "priority": pri, "category": "Hardware"})
    if getattr(lab, "campus", None) and lab.campus.get("job"):
        from . import campus  # a client site: patch cords and cables in the walls (winlab/campus.py)
        out += campus.ticket_candidates(lab, running)
    return out


def pick_caller(spec: dict, staff: list[dict], rng: random.Random) -> dict:
    """The spec with its caller and words filled in: the desk PC's user
    already is; a server's comes from the department it hurts, or anyone."""
    from . import guestfaults as gf
    spec = dict(spec)
    if spec.get("caller"):
        return spec
    if spec["source"] == "monitoring":
        spec["caller"] = "admin"
    else:
        dept = spec.get("department", "")
        pool = [p for p in staff if not p.get("admin") and p.get("department") == dept] \
            or [p for p in staff if not p.get("admin")] or staff
        who = rng.choice(pool)
        spec["caller"] = who["id"]
        if spec["fault"]["id"] in ("password-expired", "account-locked") and who.get("account"):
            # It is their own account that is stuck.
            spec["fault"] = dict(spec["fault"], params=dict(spec["fault"]["params"], user=who["account"]))
    spec["body"] = gf._fill(spec.pop("text", spec.get("body", "")), spec["fault"]["params"])
    return spec


def _break(lab, fault: dict, runner: Runner) -> tuple[bool, str]:
    """Breaks it for real. A phys fault gets its record id here."""
    if fault["kind"] == "campus":
        from . import campus
        return campus.break_fault(lab, fault, runner)
    if fault["kind"] == "phys":
        from . import physfaults as pf
        try:
            rec = pf.add(lab, fault["params"]["fault"], fault["node"], hidden=True)
        except pf.FaultError as exc:
            return False, str(exc)
        fault["id"] = rec["id"]
        return True, ""
    return _guest_run(fault, runner, "apply")


# ------------------------------------------------------------------ the SLA
def add_business(start: float, secs: float, open_hour: int = 8, close_hour: int = 17) -> float:
    """The lab time `secs` of working time after `start`: Monday to Friday,
    open_hour to close_hour on the lab's wall clock."""
    t, left = float(start), float(secs)
    for _ in range(4000):
        lt = time.localtime(t)
        y, m, d = lt.tm_year, lt.tm_mon, lt.tm_mday
        day_open = time.mktime((y, m, d, open_hour, 0, 0, 0, 0, -1))
        day_close = time.mktime((y, m, d, close_hour, 0, 0, 0, 0, -1))
        if lt.tm_wday >= 5 or t >= day_close:
            t = time.mktime((y, m, d + 1, open_hour, 0, 0, 0, 0, -1))
            continue
        t = max(t, day_open)
        if left <= day_close - t:
            return t + left
        left -= day_close - t
        t = time.mktime((y, m, d + 1, open_hour, 0, 0, 0, 0, -1))
    return t + left


def in_hours(at: float, s: dict) -> bool:
    lt = time.localtime(at)
    return lt.tm_wday < 5 and s["open_hour"] <= lt.tm_hour < s["close_hour"]


def paused_for(t: dict, now: float) -> float:
    """How long the ticket has waited on its user, which the resolve clock does not count."""
    extra = now - t["waiting_since"] if t["state"] == "waiting" and t.get("waiting_since") else 0.0
    return float(t.get("paused") or 0.0) + max(0.0, extra)


def sla_start(t: dict) -> float:
    """When a ticket's SLA clocks start: when it was opened; for one opened
    out of hours, at the morning's opening (a P3/P4, or any ticket marked
    quiet, that nobody is paged for), or at the on-call page (a P1/P2)."""
    opened = float(t["opened"])
    if t["priority"] in BUSINESS_PRIORITIES or t.get("quiet"):
        return max(opened, float(t.get("morning") or opened))
    return max(opened, float(t.get("paged") or opened))


def paged(lab_name: str, ticket_id: str, at: float) -> bool:
    """On-call was paged for this ticket at `at`: a P1/P2 opened out of
    hours counts its SLA from the first page. True when that was recorded."""
    with _lock:
        q = load(lab_name)
        t = find(q, ticket_id)
        if t is None or t.get("paged") or t["state"] not in OPEN_STATES or not t.get("morning") \
                or t["priority"] in BUSINESS_PRIORITIES or t.get("quiet"):
            return False
        t["paged"] = max(float(t["opened"]), float(at))
        _log(t, at, "monitoring", f"On-call paged at {time.strftime('%H:%M', time.localtime(at))}: "
                                  "the SLA counts from the page.", "state")
        save(lab_name, q)
    return True


def hold_for_morning(lab_name: str, ticket_id: str, at: float, why: str) -> bool:
    """A ticket nobody is paged for at night: its SLA starts at the morning's
    opening, whatever its priority, and its log says why."""
    with _lock:
        q = load(lab_name)
        t = find(q, ticket_id)
        if t is None or t["state"] not in OPEN_STATES or t.get("quiet"):
            return False
        s = settings(q)
        t["quiet"] = True
        t["morning"] = float(t.get("morning") or add_business(at, 0, s["open_hour"], s["close_hour"]))
        _log(t, at, "monitoring", why, "state")
        save(lab_name, q)
    return True


def due(t: dict, s: dict, now: float) -> tuple[float, float]:
    """(respond by, resolve by) for a ticket under these settings. With
    business hours, a P3/P4 target counts working time only: hours as
    working hours, days as working days. The clocks start at sla_start."""
    _, respond, resolve = PRIORITIES.get(t["priority"], PRIORITIES["P3"])
    opened = sla_start(t)
    if s.get("business_hours") and t["priority"] in BUSINESS_PRIORITIES:
        day = (s["close_hour"] - s["open_hour"]) * 3600

        def work(secs: int) -> float:
            return secs / 86400 * day if secs >= 86400 else secs
        r = add_business(opened, work(respond), s["open_hour"], s["close_hour"])
        z = add_business(opened, work(resolve) + paused_for(t, now), s["open_hour"], s["close_hour"])
        return r, z
    return opened + respond, opened + resolve + paused_for(t, now)


def sla(t: dict, s: dict, now: float) -> dict:
    """The ticket's two targets: when, how long left, and met, breached or running."""
    rb, zb = due(t, s, now)
    _, respond, resolve = PRIORITIES.get(t["priority"], PRIORITIES["P3"])

    def one(target: float, done: float | None, span: float) -> dict:
        if done is not None:
            return {"by": target, "left": int(target - done), "state": "met" if done <= target else "breached",
                    "used": 1.0, "done": True}
        left = target - now
        if t["state"] not in OPEN_STATES:
            return {"by": target, "left": int(left), "state": "n/a", "used": 0.0, "done": False}
        start = sla_start(t)
        whole = max(1.0, target - start)
        return {"by": target, "left": int(left), "state": "breached" if left < 0 else "running",
                "used": round(max(0.0, min(1.5, (now - start) / whole)), 3), "done": False}
    out = {"respond": one(rb, t.get("responded"), respond), "resolve": one(zb, t.get("resolved"), resolve)}
    out["breached"] = "breached" in (out["respond"]["state"], out["resolve"]["state"])
    out["paused"] = t["state"] == "waiting"
    return out


# ------------------------------------------------------------------ working a ticket
def _log(t: dict, at: float, who: str, text: str, kind: str = "note") -> None:
    t["log"].append({"at": at, "who": who, "text": text, "kind": kind})


def _respond(t: dict, at: float) -> None:
    if t.get("responded") is None:
        t["responded"] = at


def _leave_waiting(t: dict, at: float) -> None:
    if t["state"] == "waiting" and t.get("waiting_since"):
        t["paused"] = float(t.get("paused") or 0.0) + max(0.0, at - t["waiting_since"])
    t.pop("waiting_since", None)


def _ticket(q: dict, ticket_id: str) -> dict:
    t = find(q, ticket_id)
    if t is None:
        raise ValueError(f"no ticket {ticket_id}")
    return t


def _open(t: dict) -> None:
    if t["state"] not in OPEN_STATES:
        raise ValueError(f"{t['id']} is {t['state']}")


def take(q: dict, ticket_id: str, now: float, who: str = "admin") -> dict:
    """The student takes the ticket: it is theirs and in progress (and
    answered, for the respond target)."""
    t = _ticket(q, ticket_id)
    _open(t)
    _leave_waiting(t, now)
    t["state"], t["assignee"] = "in-progress", who
    _respond(t, now)
    _log(t, now, who, "Taken and in progress.", "state")
    return t


def note(q: dict, ticket_id: str, text: str, now: float, who: str = "admin", comment: bool = False) -> dict:
    """A work note (inside IT), or with comment a comment to the caller
    (they see it). Either answers the ticket the first time."""
    t = _ticket(q, ticket_id)
    text = text.strip()
    if not text:
        raise ValueError("write something in the note")
    _respond(t, now)
    _log(t, now, who, text, "comment" if comment else "note")
    return t


def set_fields(q: dict, ticket_id: str, now: float, who: str = "admin", impact=None, urgency=None,
               category=None, group=None) -> dict:
    """Impact, urgency (they set the priority), category and assignment
    group. A new priority moves its SLA targets, counted from when it opened."""
    t = _ticket(q, ticket_id)
    changes = []
    imp, urg = impact_urgency(t["priority"])
    imp, urg = int(t.get("impact") or imp), int(t.get("urgency") or urg)
    if impact not in (None, ""):
        if int(impact) not in (1, 2, 3):
            raise ValueError("impact is 1 (high), 2 (medium) or 3 (low)")
        imp = int(impact)
    if urgency not in (None, ""):
        if int(urgency) not in (1, 2, 3):
            raise ValueError("urgency is 1 (high), 2 (medium) or 3 (low)")
        urg = int(urgency)
    t["impact"], t["urgency"] = imp, urg
    pri = priority_of(imp, urg)
    if pri != t["priority"]:
        _, respond, resolve_s = PRIORITIES[pri]
        start = float(t["opened"])
        changes.append(f"priority {t['priority']} to {pri}")
        t["priority"], t["respond_by"], t["resolve_by"] = pri, start + respond, start + resolve_s
    if category not in (None, "") and category != t.get("category"):
        if category not in CATEGORIES:
            raise ValueError(f"category: one of {', '.join(CATEGORIES)}")
        changes.append(f"category {category}")
        t["category"] = category
    if group not in (None, "") and group != t.get("group"):
        if group not in GROUPS:
            raise ValueError(f"assignment group: one of {', '.join(GROUPS)}")
        changes.append(f"assignment group {group}")
        t["group"] = group
    if changes:
        _log(t, now, who, "Changed " + ", ".join(changes) + ".", "state")
    return t


def close(q: dict, ticket_id: str, now: float, who: str = "admin") -> dict:
    """Closes a resolved ticket (the caller confirmed)."""
    t = _ticket(q, ticket_id)
    if t["state"] != "resolved":
        raise ValueError(f"{t['id']} is {t['state']}: only a resolved ticket closes")
    t["state"] = "closed"
    _log(t, now, who, "Closed: the caller confirmed it works.", "state")
    return t


def cancel(q: dict, ticket_id: str, text: str, now: float, who: str = "admin") -> dict:
    """Cancels an open ticket (a duplicate, raised in error). One with a
    fault behind it counts as not fixed in the report."""
    t = _ticket(q, ticket_id)
    _open(t)
    text = text.strip()
    if not text:
        raise ValueError("say why it is canceled")
    _leave_waiting(t, now)
    t["state"], t["canceled"] = "closed", True
    _log(t, now, who, f"Canceled: {text}", "state")
    return t


def reopen(q: dict, ticket_id: str, text: str, now: float, who: str = "admin") -> dict:
    """Reopens a resolved or closed ticket: back in progress."""
    t = _ticket(q, ticket_id)
    if t["state"] in OPEN_STATES:
        raise ValueError(f"{t['id']} is still open")
    t["state"], t["resolved"] = "in-progress", None
    t["reopened"] = int(t.get("reopened") or 0) + 1
    t.pop("canceled", None)
    _log(t, now, who, f"Reopened: {text.strip() or 'not fixed after all'}", "state")
    return t


def wait(q: dict, ticket_id: str, text: str, now: float, who: str = "admin") -> dict:
    """Waiting on the user: a question for them; the resolve clock stops
    until they answer (they do, after a while, on `tick`)."""
    t = _ticket(q, ticket_id)
    _open(t)
    _respond(t, now)
    if t["state"] != "waiting":
        t["waiting_since"] = now
    t["state"] = "waiting"
    t.setdefault("assignee", who)
    _log(t, now, who, text.strip() or "Waiting on the user.", "state")
    return t


def resolve(lab, q: dict, ticket_id: str, text: str, runner: Runner, now: float,
            who: str = "admin") -> tuple[bool, str]:
    """The student says it is fixed. A ticket with a check runs it on the
    machine; one still broken reopens with the caller saying so. Without a
    check the student's word and the resolution note are enough."""
    t = _ticket(q, ticket_id)
    _open(t)
    text = text.strip()
    if not text:
        return False, "write what you did in the resolution note first"
    fault = t.get("fault")
    if has_check(fault):
        try:
            got = _CHECKS[fault["kind"]](lab, fault, runner)
        except Exception as exc:  # noqa: BLE001 - another module's check: report it, keep the ticket
            got = None
            text_err = str(exc)
        else:
            text_err = ""
        if got is None:
            return False, (f"could not check {fault.get('node') or 'the machine'}"
                           f"{': ' + text_err if text_err else ''}: is it running? The ticket stays open.")
        fixed, seen = got
        if not fixed:
            _respond(t, now)
            _leave_waiting(t, now)
            t["reopened"] = int(t.get("reopened") or 0) + 1
            t["state"] = "in-progress"
            t.setdefault("assignee", who)
            _log(t, now, who, f"Resolved: {text}", "resolve")
            caller = t["caller"] if t.get("source") != "monitoring" else "monitoring"
            _log(t, now, caller, REOPEN_TEXT[(t["reopened"] - 1) % len(REOPEN_TEXT)], "reopen")
            return False, f"{t['id']} reopened: the caller says it still does not work"
    _respond(t, now)
    _leave_waiting(t, now)
    t["state"], t["resolved"], t["resolution"] = "resolved", now, text
    t.setdefault("assignee", who)
    t["first_fix"] = not int(t.get("reopened") or 0)
    _log(t, now, who, f"Resolved: {text}", "resolve")
    return True, f"{t['id']} resolved" + (" first time" if t["first_fix"] else "")


def housekeeping(q: dict, now: float) -> bool:
    """What happens on its own: a caller asked something answers after a
    while, and a resolved ticket nobody reopened closes after a lab day."""
    changed = False
    for t in q["tickets"]:
        if t["state"] == "waiting" and t.get("waiting_since") and now - t["waiting_since"] >= REPLY_AFTER:
            caller = t["caller"] if t.get("source") != "monitoring" else "monitoring"
            reply_at = t["waiting_since"] + REPLY_AFTER
            _leave_waiting(t, reply_at)
            t["state"] = "in-progress"
            _log(t, reply_at, caller, caller_reply(t), "reply")
            changed = True
        elif t["state"] == "resolved" and t.get("resolved") and now - t["resolved"] >= CLOSE_AFTER:
            t["state"] = "closed"
            _log(t, t["resolved"] + CLOSE_AFTER, "admin", "Closed: no word back from the caller.", "state")
            changed = True
    return changed


# ------------------------------------------------------------------ the queue switched on
def _queue_open(q: dict) -> list[dict]:
    return [t for t in q["tickets"] if t["state"] in OPEN_STATES and (t.get("fault") or {}).get("by") == "queue"]


def _gap(pace: str, rng: random.Random) -> float:
    return PACES[pace][0] * rng.uniform(0.5, 1.5)


def start(lab_name: str, now: float, pace: str = "") -> dict:
    """Tickets start coming in: the first one in a minute."""
    with _lock:
        q = load(lab_name)
        s = settings(q)
        if pace:
            if pace not in PACES:
                raise ValueError(f"pace must be one of {', '.join(PACES)}")
            s["pace"] = pace
        if not s["on"]:
            q["session"] = {"started": now, "pace": s["pace"]}
        s["on"] = True
        q["settings"] = s
        q["next_at"] = now + FIRST_AFTER
        save(lab_name, q)
        return q


def set_settings(lab_name: str, **changes) -> dict:
    with _lock:
        q = load(lab_name)
        s = settings(q)
        if "pace" in changes and changes["pace"] not in PACES:
            raise ValueError(f"pace must be one of {', '.join(PACES)}")
        for k in ("open_hour", "close_hour"):
            if k in changes:
                changes[k] = int(changes[k])
                if not 0 <= changes[k] <= 24:
                    raise ValueError("hours run from 0 to 24")
        s.update({k: v for k, v in changes.items() if k in DEFAULT_SETTINGS and k != "on"})
        if s["open_hour"] >= s["close_hour"]:
            raise ValueError("the day must open before it closes")
        q["settings"] = s
        save(lab_name, q)
        return s


def tick(lab, runner: Runner, now: float | None = None, rng: random.Random | None = None,
         running: list[str] | None = None, force: bool = False) -> list[dict]:
    """One beat of the queue: callers waiting answer, resolved tickets close,
    and while the queue is on and a ticket is due (or `force`), one comes
    in: a real fault broken on a running machine, raised by the person it
    hurts. Returns the tickets raised."""
    from . import oncall, people
    rng = rng or random.Random()
    at = lab_now(lab.name) if now is None else now
    with _lock:
        q = load(lab.name)
        changed = housekeeping(q, at)
        s = settings(q)
        raised: list[dict] = []
        due_now = force or (s["on"] and at >= float(q.get("next_at") or 0)
                            and (not s["business_hours"] or in_hours(at, s)))
        if due_now and (force or len(_queue_open(q)) < PACES[s["pace"]][1]):
            busy = {t["fault"]["node"] for t in _queue_open(q)}
            run = oncall.running_nodes(lab) if running is None else running
            pool = [c for c in candidates(lab, run) if c["node"] not in busy]
            rng.shuffle(pool)
            staff = people.load(lab)
            tried: set[tuple[str, str]] = set()
            for spec in pool:
                key = (spec["fault"]["kind"], spec["fault"]["id"] or spec["fault"]["params"].get("fault", ""))
                if (key, spec["node"]) in tried:
                    continue
                tried.add((key, spec["node"]))
                spec = pick_caller(spec, staff, rng)
                ok, _ = _break(lab, spec["fault"], runner)
                if not ok:
                    continue        # the machine would not take it: someone else rings instead
                t = _add(q, at=at, caller=spec["caller"], summary=spec["summary"], body=spec["body"],
                         priority=spec["priority"], source=spec["source"], category=spec["category"],
                         node=spec["node"], fault=spec["fault"], dedupe="")
                raised.append(t)
                # One ticket a beat: a lab clock moved a week ahead does not flood the queue.
                break
        if due_now and s["on"]:
            q["next_at"] = at + _gap(s["pace"], rng)
            changed = True
        if changed or raised:
            save(lab.name, q)
        return raised


def stop(lab, runner: Runner, now: float | None = None) -> dict:
    """The queue closes: no more tickets, the faults it broke that are still
    open are undone (those tickets are withdrawn), and the report is kept
    with the student's progress."""
    at = lab_now(lab.name) if now is None else now
    with _lock:
        q = load(lab.name)
        for t in _queue_open(q):
            undo = _UNDOS.get(t["fault"]["kind"])
            if undo is not None:
                try:
                    undo(lab, t["fault"], runner)
                except Exception:  # noqa: BLE001 - a machine that is off keeps nothing to undo
                    pass
            _leave_waiting(t, at)
            t["state"], t["withdrawn"] = "closed", True
            _log(t, at, "admin", "Withdrawn: the queue was stopped and the problem undone.", "state")
        s = settings(q)
        s["on"] = False
        q["settings"] = s
        sess = q.get("session") or {}
        rep = report(q, at, since=float(sess.get("started") or 0))
        rep.update(lab=lab.name, started=float(sess.get("started") or 0), ended=at, pace=sess.get("pace", s["pace"]))
        q["session"] = None
        save(lab.name, q)
    if rep["tickets"]:
        from . import progress
        progress.record_helpdesk(rep)
    return rep


def report(q: dict, now: float, since: float = 0.0) -> dict:
    """Tickets handled, the SLA met, first-time fixes, mean time to resolve, breaches."""
    s = settings(q)
    ts = [t for t in q["tickets"] if float(t["opened"]) >= since and not t.get("withdrawn")]
    done = [t for t in ts if t.get("resolved") is not None]
    slas = {t["id"]: sla(t, s, now) for t in ts}
    met = [t for t in done if not slas[t["id"]]["breached"]]
    ftf = [t for t in done if t.get("first_fix", not t.get("reopened"))]
    mins = [(t["resolved"] - t["opened"]) / 60 for t in done]
    return {"tickets": len(ts), "handled": len(done),
            "open": sum(1 for t in ts if t["state"] in OPEN_STATES),
            "sla_met_pct": round(100 * len(met) / len(done)) if done else 0,
            "first_fix_pct": round(100 * len(ftf) / len(done)) if done else 0,
            "mttr_minutes": round(sum(mins) / len(mins), 1) if mins else 0.0,
            "breaches": sum(1 for t in ts if slas[t["id"]]["breached"]),
            "reopened": sum(int(t.get("reopened") or 0) for t in ts),
            "withdrawn": sum(1 for t in q["tickets"] if float(t["opened"]) >= since and t.get("withdrawn")),
            "by_priority": {p: sum(1 for t in ts if t["priority"] == p) for p in PRIORITIES}}


# ------------------------------------------------------------------ what the window shows
def _who(staff: list[dict], pid: str) -> dict:
    from . import people
    p = people.find(staff, pid) if pid else None
    return p or {}


def _card(lab, staff: list[dict], t: dict) -> dict:
    from . import naming
    if t.get("source") == "monitoring" or t.get("caller") in ("", "monitoring"):
        return {"name": "Monitoring", "department": "Automatic alert", "title": "", "ext": "", "mail": "",
                "pc": "", "pc_name": "", "monitoring": True}
    p = _who(staff, t["caller"])
    pc = p.get("pc", "")
    return {"name": p.get("name", t["caller"]), "department": p.get("department", ""), "title": p.get("title", ""),
            "ext": p.get("ext", ""), "mail": p.get("mail", ""), "pc": pc,
            "pc_name": naming.display(lab, pc) if pc and pc in lab.nodes else pc}


def row(lab, staff: list[dict], t: dict, s: dict, now: float, full: bool = False) -> dict:
    """One ticket for the window. Never the fault's name while it is open."""
    sl = sla(t, s, now)
    who = _card(lab, staff, t)
    active = sl["respond"] if t.get("responded") is None and t["state"] in OPEN_STATES else sl["resolve"]
    out = {"id": t["id"], "priority": t["priority"], "plabel": PRIORITIES.get(t["priority"], ("",))[0],
           "summary": t["summary"], "state": t["state"], "source": t.get("source", ""),
           "category": t.get("category", ""), "opened": t["opened"], "caller": who["name"],
           "caller_id": t["caller"], "assignee": t.get("assignee", ""), "node": t.get("node", ""),
           "sla": sl, "due": active, "breached": sl["breached"], "reopened": int(t.get("reopened") or 0),
           "checked": has_check(t.get("fault")), "group": t.get("group", "Service Desk"),
           "impact": int(t.get("impact") or impact_urgency(t["priority"])[0]),
           "urgency": int(t.get("urgency") or impact_urgency(t["priority"])[1]),
           "canceled": bool(t.get("canceled"))}
    if full:
        staff_name = {p["id"]: p["name"] for p in staff}
        out.update(body=t.get("body", ""), card=who, resolution=t.get("resolution", ""),
                   log=[{"at": e["at"], "who": "You" if e["who"] == "admin" else
                         "Monitoring" if e["who"] == "monitoring" else staff_name.get(e["who"], e["who"]),
                         "mine": e["who"] == "admin", "text": e["text"], "kind": e.get("kind", "note")}
                        for e in t["log"]])
        f = t.get("fault") or {}
        if t["state"] not in OPEN_STATES and f.get("kind") == "guest":
            g = _guest_fault(f.get("id", ""))
            out["was"] = g.title if g else ""
    return out


def view(lab, now: float | None = None) -> dict:
    from . import people
    at = lab_now(lab.name) if now is None else now
    q = load(lab.name)
    s = settings(q)
    staff = people.load(lab)
    rows = [row(lab, staff, t, s, at, full=True) for t in reversed(q["tickets"])]
    opened = [r for r in rows if r["state"] in OPEN_STATES]
    sess = q.get("session") or {}
    return {"lab": lab.name, "now": at, "stamp": labclock.stamp(at), "settings": s, "paces": list(PACES),
            "paused": labclock.load(lab.name).paused,
            "next_at": q.get("next_at") if s["on"] else None, "tickets": rows,
            "counts": {"open": len(opened), "mine": sum(1 for r in opened if r["assignee"] == "admin"),
                       "breached": sum(1 for r in opened if r["breached"]),
                       "new": sum(1 for r in opened if r["state"] == "new")},
            "report": report(q, at, since=float(sess.get("started") or 0)),
            "priorities": {p: {"label": v[0], "respond": v[1], "resolve": v[2]} for p, v in PRIORITIES.items()},
            "business": list(BUSINESS_PRIORITIES), "categories": list(CATEGORIES), "groups": list(GROUPS)}


def act(lab, action: str, params: dict, runner: Runner) -> dict:
    """The window's buttons (helpdesk-* actions)."""
    at = lab_now(lab.name)
    op = action.removeprefix("helpdesk-")
    try:
        if op == "start":
            start(lab.name, at, str(params.get("pace") or ""))
            return {"ok": True, "message": "the queue is open: tickets will start coming in"}
        if op == "stop":
            r = stop(lab, runner, at)
            return {"ok": True, "message": f"the queue is closed: {r['handled']} handled, "
                                           f"{r['sla_met_pct']}% within SLA", "report": r}
        if op == "settings":
            ch = {k: params[k] for k in ("pace", "open_hour", "close_hour") if k in params}
            if "business_hours" in params:
                ch["business_hours"] = bool(params["business_hours"])
            set_settings(lab.name, **ch)
            return {"ok": True, "message": "settings saved"}
        if op == "tick":
            got = tick(lab, runner, at, force=bool(params.get("force")))
            return {"ok": True, "message": f"{got[0]['id']} came in" if got else "no ticket came in", "silent": not got}
        tid = str(params.get("id", ""))
        with _lock:
            q = load(lab.name)
            if op == "take":
                take(q, tid, at)
                msg = f"{tid} is yours"
            elif op == "note":
                comment = params.get("visibility") == "comment"
                note(q, tid, str(params.get("text", "")), at, comment=comment)
                msg = "comment sent to the caller" if comment else "work note added"
            elif op == "set":
                set_fields(q, tid, at, impact=params.get("impact"), urgency=params.get("urgency"),
                           category=params.get("category"), group=params.get("group"))
                msg = f"{tid} updated"
            elif op == "close":
                close(q, tid, at)
                msg = f"{tid} closed"
            elif op == "cancel":
                cancel(q, tid, str(params.get("text", "")), at)
                msg = f"{tid} canceled"
            elif op == "reopen":
                reopen(q, tid, str(params.get("text", "")), at)
                msg = f"{tid} reopened"
            elif op == "wait":
                wait(q, tid, str(params.get("text", "")), at)
                msg = f"{tid} is waiting on the user"
            elif op == "resolve":
                fixed, msg = resolve(lab, q, tid, str(params.get("text", "")), runner, at)
                save(lab.name, q)
                return {"ok": True, "fixed": fixed, "message": msg}
            else:
                return {"ok": False, "message": f"unknown action {action}"}
            save(lab.name, q)
        return {"ok": True, "message": msg}
    except ValueError as exc:
        return {"ok": False, "message": str(exc)}


# ------------------------------------------------------------------ the command line
def _left(secs: int) -> str:
    s = abs(int(secs))
    text = f"{s // 86400}d {s % 86400 // 3600}h" if s >= 86400 else f"{s // 3600}h {s % 3600 // 60:02d}m" \
        if s >= 3600 else f"{s // 60}m"
    return text if secs >= 0 else f"-{text}"


def render_list(v: dict, everything: bool = False) -> str:
    s = v["settings"]
    head = (f"helpdesk on {v['lab']}  lab time {v['stamp']}  queue {'on, ' + s['pace'] if s['on'] else 'off'}"
            f"{', business hours ' + str(s['open_hour']) + '-' + str(s['close_hour']) if s['business_hours'] else ''}")
    lines = [head, f"{v['counts']['open']} open, {v['counts']['mine']} yours, {v['counts']['breached']} breached", ""]
    rows = [r for r in v["tickets"] if everything or r["state"] in OPEN_STATES]
    for r in rows:
        d = r["due"]
        sla_txt = d["state"] if d["state"] in ("met", "n/a") else ("BREACHED " + _left(-d["left"]) if d["left"] < 0 else _left(d["left"]))
        lines.append(f"  {r['id']}  {r['priority']}  {r['state']:<11} {sla_txt:<14} {r['caller'][:18]:<18} {r['summary']}")
    if not rows:
        lines.append("  nothing open" + ("" if s["on"] else ": winlab helpdesk start"))
    return "\n".join(lines)


def render_ticket(r: dict) -> str:
    c = r["card"]
    lines = [f"{r['id']}  {r['priority']} ({r['plabel']})  {r['state']}  {r['summary']}",
             f"caller: {c['name']}" + (f", {c['title']}, {c['department']}" if c.get("department") and c.get("title") else "")
             + (f", ext {c['ext']}" if c.get("ext") else "") + (f", desk PC {c['pc_name']}" if c.get("pc") else ""),
             f"respond: {r['sla']['respond']['state']} (by {labclock.stamp(r['sla']['respond']['by'])})",
             f"resolve: {r['sla']['resolve']['state']} (by {labclock.stamp(r['sla']['resolve']['by'])})"
             + (", paused while waiting on the user" if r["sla"]["paused"] else ""), "", f"  \"{r['body']}\"", ""]
    for e in r["log"]:
        lines.append(f"  {labclock.stamp(e['at'])}  {e['who']}: {e['text']}")
    if r.get("was"):
        lines.append(f"it was: {r['was']}")
    return "\n".join(lines)


def render_report(r: dict) -> str:
    return (f"tickets {r['tickets']}, handled {r['handled']}, open {r['open']}, withdrawn {r['withdrawn']}\n"
            f"SLA met {r['sla_met_pct']}%, first-time fix {r['first_fix_pct']}%, "
            f"mean time to resolve {r['mttr_minutes']} min, breaches {r['breaches']}, reopened {r['reopened']}")


def add_cli(sub) -> None:
    """The `winlab helpdesk` parser."""
    hp = sub.add_parser("helpdesk", help="the helpdesk queue: tickets from the lab's staff, SLAs on the lab clock")
    hp.add_argument("--lab", default="")
    hs = hp.add_subparsers(dest="hdcmd", metavar="<op>")
    hl = hs.add_parser("list", help="the open tickets, their SLA and caller")
    hl.add_argument("--all", action="store_true", help="resolved and closed ones too")
    for name, what in (("show", "one ticket: the caller, the SLA, the work log"),
                       ("take", "take a ticket: it is yours and in progress")):
        hs.add_parser(name, help=what).add_argument("id")
    hn = hs.add_parser("note", help="add a work-log note")
    hn.add_argument("id")
    hn.add_argument("text", nargs="+")
    hw = hs.add_parser("wait", help="ask the user something: waiting on user, the resolve clock stops")
    hw.add_argument("id")
    hw.add_argument("text", nargs="*")
    hr = hs.add_parser("resolve", help="resolve with a note; a fault-backed ticket is checked on the machine")
    hr.add_argument("id")
    hr.add_argument("text", nargs="+")
    hst = hs.add_parser("start", help="tickets start coming in")
    hst.add_argument("--pace", choices=list(PACES), default="")
    hs.add_parser("stop", help="no more tickets; open faults the queue broke are undone; the report is kept")
    ht = hs.add_parser("tick", help="let the queue move on now (callers answer, a ticket may come in)")
    ht.add_argument("--force", action="store_true", help="a ticket comes in now, whatever the pace")
    hs.add_parser("report", help="handled, SLA met, first-time fix, mean time to resolve, breaches")
    hse = hs.add_parser("settings", help="pace and business hours")
    hse.add_argument("--pace", choices=list(PACES))
    hse.add_argument("--business-hours", choices=("on", "off"))
    hse.add_argument("--hours", default="", help="the working day, like 8-17")


def run_cli(args) -> int:
    import sys

    from . import oncall, schema
    from .cli import _resolve_lab
    try:
        lab = schema.load(_resolve_lab(args.lab))
    except Exception as exc:  # noqa: BLE001 - the CLI reports it
        print(f"{exc}", file=sys.stderr)
        return 2
    run = oncall.guest_runner(lab.name)
    op = args.hdcmd or "list"
    at = lab_now(lab.name)
    try:
        if op == "start":
            start(lab.name, at, args.pace)
            print("the queue is open: tickets come in on the lab clock (winlab helpdesk tick moves it on)")
        elif op == "stop":
            print(render_report(stop(lab, run, at)))
            return 0
        elif op == "tick":
            for t in tick(lab, run, at, force=args.force):
                print(f"{t['id']} came in: {t['summary']}")
        elif op == "report":
            q = load(lab.name)
            print(render_report(report(q, at, since=float((q.get("session") or {}).get("started") or 0))))
            return 0
        elif op == "settings":
            ch: dict = {}
            if args.pace:
                ch["pace"] = args.pace
            if args.business_hours:
                ch["business_hours"] = args.business_hours == "on"
            if args.hours:
                a, _, b = args.hours.partition("-")
                ch["open_hour"], ch["close_hour"] = int(a), int(b)
            s = set_settings(lab.name, **ch)
            print(f"pace {s['pace']}, business hours {'on' if s['business_hours'] else 'off'} "
                  f"({s['open_hour']}-{s['close_hour']}, P3 and P4)")
            return 0
        elif op in ("show", "take", "note", "wait", "resolve"):
            text = " ".join(getattr(args, "text", []) or [])
            with _lock:
                q = load(lab.name)
                ok = True
                if op == "take":
                    take(q, args.id, at)
                elif op == "note":
                    note(q, args.id, text, at)
                elif op == "wait":
                    wait(q, args.id, text, at)
                elif op == "resolve":
                    ok, msg = resolve(lab, q, args.id, text, run, at)
                    print(msg)
                save(lab.name, q)
            v = view(lab, at)
            r = next((x for x in v["tickets"] if x["id"] == _ticket(load(lab.name), args.id)["id"]), None)
            print(render_ticket(r))
            return 0 if ok else 1
    except ValueError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print(render_list(view(lab), everything=getattr(args, "all", False)))
    return 0
