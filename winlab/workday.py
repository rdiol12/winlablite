"""The working day: the lab's staff come in, sign in, save, print and mail.

A lab feels like a job when other people use it. The staff in the lab's
directory (winlab/people.py) keep office hours on the lab clock
(winlab/labclock.py): each arrives around half past eight, goes to lunch,
and leaves around half past five, a few minutes earlier or later every day,
and now and then someone is off sick. Nobody works at night or at the weekend
unless the student turns on shift work, which puts people on early, late and
night shifts, every day of the week.

While someone is in, they really work inside the lab, at their own desk PC
(or a hot desk, one of the lab's Windows PCs, when the directory gave them
none), as their own domain account:
- they sign in: the domain controller checks who they are (its Security log
  gets a 4624 for them, or a 4625 when the account is missing, disabled,
  locked or the password is wrong), and a new account that must change its
  password at first sign-in gets a new one the person chooses themselves;
- they open their department's share on the file server, create and edit
  documents there and save them, and keep notes in their home folder;
- they print a page, when the lab has a print server or a network printer;
- they mail a colleague through the lab's mail server, when it has one;
- they open the intranet, when a machine serves one.
Each action is picked only when the lab has what it needs and that machine
is running. How hard they work is the load level: quiet, normal or busy.

The load engine (winlab/traffic.py) adds the rest of a real office's day on
top: more things people do (look a colleague up in the directory, open and
save Word-sized documents, copy big files, run a report on the lab's SQL
Server, browse the lab's other web sites, reach the Remote Desktop session
host, dial the VPN from home), what a sign-in really does (a Group Policy
refresh, the logon script, the mapped drives), the shape of the day (the
Monday-morning storm, the lunch dip, the end-of-day saves, month-end in
Finance), the servers' own night work, and the rules that keep it from
swamping a slow guest.

Acting as a user without anyone at the screen is done the way Windows itself
does it for a job that runs as somebody: winlab's agent (running as the
machine) registers a one-off scheduled task with the person's credentials,
Task Scheduler signs them in (a batch logon, their profile is made like at a
first sign-in) and runs their part as them, and the task is removed when it
is done. Nothing is installed and nothing stays behind but what the person
made: their profile, their files, their printouts and mail.

The accounts are the student's job. On day one HR's new-starter sheet (a CSV
of names, departments, account names and job titles) arrives on a USB stick
on the media shelf; the student creates the accounts, groups, shares and home
folders, and then types each person's initial password into the staff list
(the Office window, or `winlab staff password <account>`). The passwords are
kept only in this lab's folder under var/, never in the repo and never in a
log. Someone with no account, or whose sign-in or work fails, calls the
helpdesk (winlab/helpdesk.py) in their own words, one ticket per broken
thing that grows notes as more people call about it.

The pure parts (the timetable, what someone does next, the commands sent,
what an answer means, the ticket wording) take everything they need as
arguments, so the suite runs them with a fake runner and no machine.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import random
import re
import secrets as _rand
import threading
import time
import zlib
from pathlib import Path
from typing import Callable

from . import helpdesk, labclock, paths
from . import people as directory

Runner = Callable[[str, str, str], tuple[bool, str]]

# Load: a person's mean lab minutes between two things they do, and the most
# guest actions one tick may run (a jump of the clock must not start fifty).
LEVELS: dict[str, tuple[int, int]] = {"quiet": (60, 2), "normal": (20, 4), "busy": (6, 8)}
DEFAULT_LEVEL = "normal"
# Office hours, in minutes after midnight, and how far a day may stray.
ARRIVE, LEAVE, LUNCH = 8 * 60 + 30, 17 * 60 + 30, 12 * 60
JITTER = 20
# Shift work: early, late and night, every day of the week.
SHIFTS: dict[str, tuple[int, int]] = {"early": (6 * 60, 14 * 60), "late": (14 * 60, 22 * 60),
                                      "night": (22 * 60, 30 * 60)}
ABSENT = 0.04             # the chance someone is off on a given day
RETRY_MINUTES = 90        # after a failed sign-in, the next try
FEED_MAX = 200
TICK_EVERY = 15.0         # real seconds between the desktop's ticks
TASK_WAIT = 150           # seconds the agent waits for a person's task (a sign-in runs Group Policy)
PRINT_WAIT = 25           # seconds a print job may sit in the queue
SHEET_STICK = "new-starters"
SHEET_TITLE = "HR: new-starter sheet"
SHEET_LABEL = "NEWSTARTERS"
SHEET_FILE = "New starters.csv"
ACTIONS = ("signin", "share", "home", "print", "mail", "intranet",
           "lookup", "document", "bigcopy", "browse", "sql", "rdp")
WEIGHTS = {"share": 5, "home": 2, "print": 2, "mail": 3, "intranet": 2,
           "lookup": 2, "document": 3, "bigcopy": 1, "browse": 1, "sql": 3, "rdp": 2}
SLOW_MBPS = 0.5           # a big copy slower than this: "the network is slow today"

_lock = threading.RLock()
_running: set[str] = set()
_last_kick: dict[str, float] = {}


class WorkdayError(Exception):
    pass


# =================================================================== storage
def state_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / "workday.json"


def secrets_file(lab_name: str) -> Path:
    """The staff's passwords, as the student typed them (or as a person chose
    at first sign-in): only here, in this lab's own folder under var/."""
    return paths.lab_dir(lab_name) / "staff-secrets.json"


def fresh_state() -> dict:
    return {"on": False, "level": DEFAULT_LEVEL, "shifts": False, "people": {}, "feed": [],
            "sheet": "", "last_tick": 0.0}


def load(lab_name: str) -> dict:
    try:
        raw = json.loads(state_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {**fresh_state(), **raw}
    except (OSError, ValueError):
        pass
    return fresh_state()


def save(lab_name: str, st: dict) -> None:
    f = state_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    st["feed"] = st.get("feed", [])[-FEED_MAX:]
    with _lock:
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=1), encoding="utf-8")
        tmp.replace(f)


def load_secrets(lab_name: str) -> dict[str, str]:
    try:
        raw = json.loads(secrets_file(lab_name).read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in raw.items() if v} if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_secrets(lab_name: str, store: dict[str, str]) -> None:
    f = secrets_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(store, indent=1), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(f)


def set_secret(lab_name: str, account: str, value: str) -> None:
    """Keeps what the student typed for `account` (an empty value forgets it)."""
    store = load_secrets(lab_name)
    if value:
        store[account.lower()] = value
    else:
        store.pop(account.lower(), None)
    _save_secrets(lab_name, store)


# ================================================================ the lab
def everyone(lab) -> list[dict]:
    """The people of the working day: those Start-OfficeLoad found in the
    student's own directory (winlab/freeload.py), else the lab's directory."""
    from . import freeload
    found = freeload.discovered_staff(lab.name)
    return found if found is not None else directory.load(lab)


def lab_facts(lab) -> dict:
    """What the lab offers its staff: the domain, the DC to sign in against,
    the file server, a printer, the mail server, the intranet and the PCs.
    An empty value means the lab has none. When the student started the load
    from inside the lab (Start-OfficeLoad), what winlab discovered there wins
    over the lab's plan (winlab/freeload.py)."""
    from . import freeload
    found = freeload.discovered_facts(lab.name)
    return found if found is not None else plan_facts(lab)


def plan_facts(lab) -> dict:
    """lab_facts from the lab's plan: the machines' roles."""
    from . import mail, naming
    from .model import WINDOWS_CLIENT

    def first(pred):
        return next((n for n in lab.node_list() if pred(n)), None)

    def host(n):
        return naming.hostname_of(n).lower() if n is not None else ""

    dc = first(lambda n: n.is_windows and "ad-ds" in n.roles and n.vars.get("forest_root")) or \
        first(lambda n: n.is_windows and "ad-ds" in n.roles)
    fs = first(lambda n: n.is_windows and "file" in n.roles)
    ps = first(lambda n: n.is_windows and "printer" in n.roles)
    np_ = first(lambda n: "netprinter" in n.roles)
    mn = mail.mail_node(lab)
    web = first(lambda n: n.is_windows and "iis" in n.roles)
    sql = first(lambda n: n.is_windows and "sql" in n.roles)
    rds = first(lambda n: n.is_windows and "rds" in n.roles)
    wsus = first(lambda n: n.is_windows and "wsus" in n.roles)
    domain = (lab.domain or "").lower()

    def fqdn(n):
        return f"{host(n)}.{domain}" if n is not None and domain else host(n)
    # A PC on the same network as the home worker's broadband router is at
    # home: it reaches the office only through the VPN.
    home_nets = {c.network for n in lab.node_list() if "home-router" in n.roles for c in n.nics if c.network}
    return {
        "domain": domain, "netbios": (lab.netbios or domain.split(".")[0]).upper(),
        "dc": host(dc), "dc_node": dc.id if dc else "",
        # The DC by name, found through the PC's own DNS as a real sign-in
        # finds it: the lab plan's address is not what the student set.
        "dc_addr": (f"{host(dc)}.{domain}" if dc is not None and domain else host(dc)),
        "files": host(fs), "files_node": fs.id if fs else "", "company": naming.share_name(lab),
        "printserver": host(ps), "printserver_node": ps.id if ps else "",
        "printer": host(np_), "printer_node": np_.id if np_ else "",
        "mail": mail.fault_params(lab)["mailhost"] if mn is not None else "",
        "mail_node": mn.id if mn is not None else "",
        "intranet": f"{host(web)}.{domain}" if web is not None and domain else host(web),
        "intranet_node": web.id if web else "",
        "pcs": [n.id for n in lab.node_list() if n.kind == WINDOWS_CLIENT],
        # What the load engine (winlab/traffic.py) uses besides.
        "dc_nodes": [n.id for n in lab.node_list() if n.is_windows and "ad-ds" in n.roles],
        "file_nodes": [n.id for n in lab.node_list() if n.is_windows and "file" in n.roles],
        "sql": fqdn(sql), "sql_node": sql.id if sql else "",
        "rds": fqdn(rds), "rds_node": rds.id if rds else "",
        "wsus": host(wsus), "wsus_node": wsus.id if wsus else "",
        "sites": [{"node": n.id, "url": f"http://{fqdn(n)}/"} for n in lab.node_list()
                  if n.is_windows and "iis" in n.roles and n is not web],
        "remote_pcs": [n.id for n in lab.node_list() if n.kind == WINDOWS_CLIENT
                       and any(c.network in home_nets for c in n.nics)],
        "windows": [n.id for n in lab.node_list() if n.is_windows],
    }


def share_name(department: str) -> str:
    """A department's share: its name without spaces (Front desk: FrontDesk)."""
    return re.sub(r"[^A-Za-z0-9]", "", department) or "Staff"


def staff_of(everyone: list[dict]) -> list[dict]:
    """The people who come to work: everyone but the admin (the student)."""
    return [p for p in everyone if not p.get("admin")]


def desk_of(person: dict, staff: list[dict], pcs: list[str]) -> tuple[str, bool]:
    """(machine, hot desk?) where `person` works: their own Windows PC, or
    the lab's Windows PCs in turn for those who have none."""
    if person.get("pc") in pcs:
        return person["pc"], False
    if not pcs:
        return "", False
    without = [p["id"] for p in staff if p.get("pc") not in pcs]
    i = without.index(person["id"]) if person["id"] in without else 0
    return pcs[i % len(pcs)], True


def available(facts: dict, running: set[str]) -> dict[str, int]:
    """The things to do the lab has, each with its weight: only what has its
    server, and only while that server runs."""
    out: dict[str, int] = {}
    if facts["files_node"] in running:
        out["share"], out["home"] = WEIGHTS["share"], WEIGHTS["home"]
    if (facts["printserver_node"] in running) or (facts["printer_node"] in running):
        out["print"] = WEIGHTS["print"]
    if facts["mail_node"] and facts["mail_node"] in running:
        out["mail"] = WEIGHTS["mail"]
    if facts["intranet_node"] and facts["intranet_node"] in running:
        out["intranet"] = WEIGHTS["intranet"]
    return out


def available_more(facts: dict, running: set[str]) -> dict[str, int]:
    """The load engine's further things to do, on the same rule: only what
    the lab has, and only while it runs. Nothing here is made for the
    student: a lab without SQL Server simply has nobody running reports."""
    out: dict[str, int] = {}
    if facts.get("dc_node") in running:
        out["lookup"] = WEIGHTS["lookup"]
    if facts.get("files_node") in running:
        out["document"], out["bigcopy"] = WEIGHTS["document"], WEIGHTS["bigcopy"]
    if any(s["node"] in running for s in facts.get("sites", ())):
        out["browse"] = WEIGHTS["browse"]
    if facts.get("sql_node") and facts["sql_node"] in running:
        out["sql"] = WEIGHTS["sql"]
    if facts.get("rds_node") and facts["rds_node"] in running:
        out["rdp"] = WEIGHTS["rdp"]
    return out


# ============================================================ the timetable
def _midnight(ts: float) -> float:
    t = time.localtime(ts)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1))


def day_key(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def shift_of(person: dict) -> str:
    """With shift work on, the shift a person works (always the same one)."""
    names = tuple(SHIFTS)
    return names[zlib.crc32(person["id"].encode("utf-8")) % len(names)]


def day_plan(lab_name: str, person: dict, midnight: float, shifts: bool) -> dict:
    """One person's day starting at `midnight` (lab time): arrive, lunch and
    leave as timestamps, or why they are not in ("weekend", "off sick",
    "on leave"). The same lab, person and day always give the same plan."""
    day = time.strftime("%Y-%m-%d", time.localtime(midnight + 3600))
    rng = random.Random(zlib.crc32(f"{lab_name}|{day}|{person['id']}".encode("utf-8")))
    weekday = time.localtime(midnight + 3600).tm_wday
    if not shifts and weekday >= 5:
        return {"day": day, "off": "weekend"}
    if rng.random() < ABSENT:
        return {"day": day, "off": rng.choice(("off sick", "on leave"))}
    if shifts:
        name = shift_of(person)
        start, end = SHIFTS[name]
        start += rng.randint(-10, 10)
        end += rng.randint(-5, 15)
        brk = start + (end - start) // 2 + rng.randint(-30, 30)
    else:
        name = "day"
        start = ARRIVE + rng.randint(-JITTER, JITTER + 5)
        end = LEAVE + rng.randint(-JITTER - 5, JITTER + 10)
        brk = LUNCH + rng.randint(-30, 60)
    blen = rng.choice((30, 30, 45, 60))
    return {"day": day, "shift": name, "arrive": midnight + start * 60, "leave": midnight + end * 60,
            "lunch": midnight + brk * 60, "back": midnight + (brk + blen) * 60}


def presence(lab_name: str, person: dict, now: float, shifts: bool) -> tuple[str, dict]:
    """(where they are, the plan that says so): "in", "lunch", "not in yet",
    "gone home", or the plan's reason for a day off. A night shift that
    began yesterday still counts."""
    today = day_plan(lab_name, person, _midnight(now), shifts)
    if shifts:
        yesterday = day_plan(lab_name, person, _midnight(_midnight(now) - 3600), shifts)
        if "arrive" in yesterday and yesterday["arrive"] <= now < yesterday["leave"]:
            today = yesterday
    if "off" in today:
        return today["off"], today
    if now < today["arrive"]:
        return "not in yet", today
    if now >= today["leave"]:
        return "gone home", today
    if today["lunch"] <= now < today["back"]:
        return "lunch", today
    return "in", today


def hhmm(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


# ============================================================ what to do next
DOCS = {
    "Finance": ("Budget {year}.txt", "Invoices {month}.txt", "Expenses {month}.txt"),
    "Sales": ("Leads.txt", "Quotes {month}.txt", "Customer visits.txt"),
    "HR": ("Holiday rota {year}.txt", "Training plan.txt", "Interview notes.txt"),
    "Operations": ("Supplier list.txt", "Stock count {month}.txt", "Office moves.txt"),
    "Front desk": ("Visitors {month}.txt", "Meeting rooms.txt", "Deliveries.txt"),
    "IT": ("Changes.txt",),
}
LINES = ("Updated the figures after the call.", "Added this week's entries.", "Checked and corrected two rows.",
         "Notes from this morning's meeting.", "Draft for the manager to look at.", "Follow up on Monday.")
SUBJECTS = ("Quick question", "Meeting tomorrow", "Figures for {month}", "Re: {doc}", "Lunch?", "Can you check this?")


def _doc(person: dict, rng: random.Random, now: float) -> str:
    t = time.localtime(now)
    names = DOCS.get(person.get("department", ""), ("Notes.txt",))
    return rng.choice(names).format(year=t.tm_year, month=time.strftime("%B", t))


DOC_KB = (24, 60, 150, 400, 900, 2048)   # a memo to a report full of tables
COPY_MB = (4, 8, 12)                     # a scan, photos, a recorded meeting: small lab disks never fill


def pick(person: dict, can: dict[str, int], colleagues: list[dict], rng: random.Random, now: float,
         facts: dict | None = None) -> dict | None:
    """What `person` does next, from the things the lab has (`available`,
    `available_more`): {"action": ..., and its details}, or None when there
    is nothing to do."""
    if not can:
        return None
    acts = sorted(can)
    act = rng.choices(acts, weights=[can[a] for a in acts])[0]
    job = {"action": act}
    others = [c for c in colleagues if c["id"] != person["id"]]
    if act in ("share", "home"):
        job["doc"] = _doc(person, rng, now) if act == "share" else "Notes.txt"
        job["line"] = rng.choice(LINES)
    elif act == "mail":
        others = [c for c in others if c.get("mail")]
        if not others:
            return None
        to = rng.choice(others)
        job["to"], job["to_name"], job["line"] = to["mail"], to["name"], rng.choice(LINES)
        job["subject"] = rng.choice(SUBJECTS).format(month=time.strftime("%B", time.localtime(now)),
                                                     doc=_doc(person, rng, now))
    elif act == "document":
        job["doc"] = _doc(person, rng, now).rsplit(".", 1)[0] + ".rtf"
        job["kb"], job["line"] = rng.choice(DOC_KB), rng.choice(LINES)
    elif act == "bigcopy":
        job["file"] = f"Scans - {person['name']}.dat"   # one name each: it never fills the server
        job["mb"] = rng.choice(COPY_MB)
    elif act == "lookup":
        job["who"] = rng.choice(others)["name"] if others else person["name"]
    elif act == "browse":
        sites = [s["url"] for s in (facts or {}).get("sites", ())]
        if not sites:
            return None
        job["sites"] = rng.sample(sites, min(len(sites), rng.randint(1, 3)))
    elif act == "sql":
        job["n"] = rng.randint(0, 9)
    return job


def gap(level: str, rng: random.Random, factor: float = 1.0) -> float:
    """Seconds until a person's next action at this load level; `factor`
    is the load engine's pace now (2 is twice as busy)."""
    mean = LEVELS.get(level, LEVELS[DEFAULT_LEVEL])[0] / max(0.05, factor)
    return 60 * max(2.0, min(3.0 * mean, rng.expovariate(1.0 / mean)))


def plan(st: dict, lab_name: str, staff: list[dict], facts: dict, now: float, running: set[str],
         keys: set[str], rng: random.Random, pace: dict | None = None) -> list[dict]:
    """One tick's decisions. Updates each person's record in `st` (where
    they are, a new day, going home) and returns the jobs due now, at most
    the level's limit, soonest first: [{"id", "pc", "action", ...}]. Pure:
    the caller runs the jobs.

    `pace` is the load engine's word for this moment (traffic.pace): how
    busy the office is overall and per department, which things people
    favour now, the most jobs this tick, and the PCs to leave alone while
    they are slow to answer. Without it, the plain office of old."""
    level = st.get("level", DEFAULT_LEVEL)
    can = available(facts, running)
    if pace is not None:
        can.update(available_more(facts, running))
    pace = pace or {}
    held = set(pace.get("held", ()))
    due: list[tuple[float, dict]] = []
    recs = st.setdefault("people", {})
    for p in staff:
        where, today = presence(lab_name, p, now, bool(st.get("shifts")))
        pc, hot = desk_of(p, staff, facts["pcs"])
        r = recs.setdefault(p["id"], {})
        if r.get("day") != today["day"]:
            r.update({"day": today["day"], "signed": False, "next": today.get("arrive", 0), "doing": ""})
            if pace.get("spread") and r["next"] < now:
                # The clock jumped into the day: they trickle in, not all at once.
                r["next"] = now + rng.uniform(0, pace["spread"])
        r.update({"where": where, "pc": pc, "hot": hot,
                  "arrive": today.get("arrive"), "leave": today.get("leave"), "shift": today.get("shift", "")})
        if where != "in":
            if where == "gone home" and r.get("signed"):
                r["signed"] = False
                _feed(st, now, p, pc, f"signed out of {pc} and went home", True)
            r["doing"] = {"lunch": "at lunch", "not in yet": "", "gone home": "gone home"}.get(where, where)
            continue
        if not pc:
            r["doing"] = "in, no PC to work at"
            continue
        if not facts["dc_node"]:
            r["doing"] = f"working at {pc}: the lab has no domain to sign in to"
            continue
        if pc not in running or (facts["dc_node"] and facts["dc_node"] not in running):
            r["doing"] = f"waiting for {pc} to be switched on" if pc not in running else \
                "waiting: the domain controller is off"
            continue
        if now < float(r.get("next") or 0):
            continue
        if pc in held:
            r["doing"] = f"waiting: {pc} is slow to respond"
            continue
        dept = p.get("department", "")
        factor = float(pace.get("factor", 1.0)) * float(pace.get("dept", {}).get(dept, 1.0))
        if not r.get("signed"):
            job = {"action": "signin", "keyed": p["account"].lower() in keys}
        else:
            favour = {**pace.get("favour", {})}
            for a, m in pace.get("dept_favour", {}).get(dept, {}).items():
                favour[a] = favour.get(a, 1.0) * m
            mine = {a: w * favour.get(a, 1.0) for a, w in can.items()}
            job = pick(p, mine, staff, rng, now, facts)
            if job is None:
                r["doing"] = f"working at {pc}"
                r["next"] = now + gap(level, rng, factor)
                continue
        job.update({"id": p["id"], "pc": pc})
        due.append((float(r.get("next") or 0), job))
    due.sort(key=lambda x: x[0])
    cap = int(pace.get("cap") or LEVELS.get(level, LEVELS[DEFAULT_LEVEL])[1])
    per_pc, used, out = int(pace.get("per_pc") or cap), {}, []
    for _, j in due:
        if len(out) >= cap:
            break
        if used.get(j["pc"], 0) < per_pc:
            used[j["pc"]] = used.get(j["pc"], 0) + 1
            out.append(j)
    return out


def _feed(st: dict, now: float, person: dict, pc: str, text: str, ok: bool) -> dict:
    e = {"at": now, "who": person["id"], "name": person["name"], "pc": pc, "text": text, "ok": ok}
    st.setdefault("feed", []).append(e)
    return e


# ========================================================== the commands
def ps_quote(s: str) -> str:
    """A PowerShell single-quoted string."""
    return "'" + str(s).replace("'", "''") + "'"


def encode_ps(script: str) -> str:
    """powershell.exe -EncodedCommand takes UTF-16LE, base64."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def new_secret(rng: random.Random | None = None) -> str:
    """What a person picks when Windows makes them change the initial one:
    two words, four digits and a sign (meets the domain's complexity rule)."""
    words = ("Maple", "River", "Copper", "Harbor", "Willow", "Falcon", "Meadow", "Cedar", "Amber", "Summit")
    r = rng or random.SystemRandom()
    return f"{r.choice(words)}{r.choice(words).lower()}{r.randint(1000, 9999)}{r.choice('!#%+')}"


def ps_dq(text: str) -> str:
    """Text safe inside a PowerShell double-quoted string (the directory is
    the student's to edit: a name must never become code)."""
    return str(text).replace("`", "``").replace('"', '`"').replace("$", "`$")


def ldap_escape(value: str) -> str:
    """A value inside an LDAP filter (RFC 4515)."""
    return "".join({"*": r"\2a", "(": r"\28", ")": r"\29", "\\": r"\5c", "\0": r"\00"}.get(c, c) for c in value)


def rtf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")


# A TCP knock from the person's PC: open, refused (nothing listens, or a
# firewall rejects), blocked (a firewall drops it: the knock times out) or
# dns (the name does not resolve). It tells a broken server from a rule.
PORT_FN = (r"function Port($h, $p) { $c = New-Object Net.Sockets.TcpClient; try { $a = $c.BeginConnect($h, $p, $null, $null); "
           r"if (-not $a.AsyncWaitHandle.WaitOne(4000)) { return 'blocked' }; $c.EndConnect($a); return 'open' } "
           r"catch { $m = $_.Exception.Message; if ($m -match 'refused') { return 'refused' } "
           r"elseif ($m -match 'host is known|No such host|resolve') { return 'dns' } else { return 'blocked' } } finally { $c.Close() } }")


def _find_share(body: list[str], person: dict, facts: dict) -> str:
    """The lines that find the person's department folder ($hit): its own
    share, or the company share's folder for it. When neither opens, a knock
    on the file server's SMB port tells a missing share from a server that
    cannot be reached (switched off, or a firewall rule in the way)."""
    dept = share_name(person.get("department", ""))
    first = f"\\\\{facts['files']}\\{dept}"
    alt = f"\\\\{facts['files']}\\{facts['company']}\\{dept}"
    body += [f"$paths = @({ps_quote(first)}, {ps_quote(alt)}); $hit = $null; $why = 'missing'",
             "foreach ($p in $paths) { try { $null = Get-ChildItem -LiteralPath $p -ErrorAction Stop; $hit = $p; break }",
             "  catch { if ($_.CategoryInfo.Category -eq 'PermissionDenied' -or $_.Exception.Message -match 'denied') { $why = 'denied' } } }",
             f"if (-not $hit -and $why -eq 'missing') {{ $pt = Port {ps_quote(facts['files'])} 445; "
             f"if ($pt -ne 'open') {{ Say \"fail share-unreachable {facts['files']} ($pt)\"; return }} }}",
             f"if (-not $hit) {{ Say \"fail share-$why {first}\"; return }}"]
    return first


def _signin_extras(netlogon: str) -> list[str]:
    """What Windows does at a sign-in after the password is checked: the
    user's Group Policy (a refresh, as at logon), the logon script the
    account names (scriptPath, from NETLOGON), and the drives it or a
    Group Policy drive map connects. Each that fails is a step that fails."""
    return [
        # A native command's stderr under ErrorActionPreference Stop would throw
        # in Windows PowerShell 5.1: these two run with Continue.
        "$gp = & { $ErrorActionPreference = 'Continue'; gpupdate.exe /target:user /wait:60 2>&1 | Out-String }",
        "if ($gp -notmatch 'completed successfully') { $l = @($gp -split \"`r?`n\" | Where-Object { $_ -match 'fail|error|could not|cannot' })",
        "  Say \"fail gpo $(if ($l.Count) { $l[0].Trim() } else { 'Group Policy did not finish' })\" }",
        "$me = ([adsisearcher]\"(sAMAccountName=$env:USERNAME)\").FindOne()",
        "$sp = if ($me) { @($me.Properties['scriptpath'])[0] } else { $null }",
        f"if ($sp) {{ $sf = Join-Path {ps_quote(netlogon)} $sp",
        "  if (-not (Test-Path -LiteralPath $sf)) { Say \"fail logonscript-missing $sf\" }",
        "  else { $ext = [IO.Path]::GetExtension($sf).ToLower()",
        "    if ($ext -eq '.ps1') { $p = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', \"`\"$sf`\"\") -PassThru -WindowStyle Hidden }",
        "    elseif ($ext -eq '.vbs') { $p = Start-Process cscript.exe -ArgumentList @('//nologo', \"`\"$sf`\"\") -PassThru -WindowStyle Hidden }",
        "    else { $p = Start-Process cmd.exe -ArgumentList @('/c', \"`\"$sf`\"\") -PassThru -WindowStyle Hidden }",
        "    $null = $p.Handle",
        "    if (-not $p.WaitForExit(60000)) { try { $p.Kill() } catch { }; Say \"fail logonscript-hung $sf\" }",
        "    elseif ($p.ExitCode -ne 0) { Say \"fail logonscript-fail $sf (exit $($p.ExitCode))\" } } }",
        "$bad = @()",
        "$nu = & { $ErrorActionPreference = 'Continue'; net.exe use 2>$null }",
        "foreach ($l in @($nu)) { if ($l -match '([A-Z]:)\\s+(\\\\\\\\\\S+)') { $d = $matches[1]; $u = $matches[2]",
        "  if ($l -match '^\\s*(Unavailable|Disconnected)' -or -not (Test-Path -LiteralPath ($d + '\\'))) { $bad += \"$d $u\" } } }",
        "if ($bad.Count) { Say \"fail drive-broken $(@($bad | Select-Object -Unique) -join ', ')\" }",
    ]


def _part_lookup(body: list[str], job: dict, person: dict, facts: dict, stamp: str) -> None:
    """DNS and the directory, as Outlook's address book and every program
    that opens a server by name use them: the lab's servers looked up, a
    colleague found by name, and the person's own groups read."""
    names = [facts.get(k, "") for k in ("dc_addr", "files", "printserver", "mail", "intranet", "sql", "rds")]
    names = list(dict.fromkeys(n for n in names if n))
    who = job.get("who") or person["name"]
    filt = f"(&(objectCategory=person)(displayName={ldap_escape(who)}))"
    body += [f"$bad = @(); foreach ($n in @({', '.join(ps_quote(n) for n in names) or chr(39) * 2})) "
             "{ if ($n) { try { $null = Resolve-DnsName -Name $n -QuickTimeout -ErrorAction Stop } catch { $bad += $n } } }",
             "if ($bad.Count) { Say \"fail dns $($bad -join ', ')\"; return }",
             f"try {{ $s = New-Object DirectoryServices.DirectorySearcher; $s.Filter = {ps_quote(filt)}; $hit = $s.FindOne()",
             "  $me = ([adsisearcher]\"(sAMAccountName=$env:USERNAME)\").FindOne(); $g = @($me.Properties['memberof']).Count }",
             "catch { Say \"fail directory $($_.Exception.Message)\"; return }",
             f"if ($hit) {{ Say \"ok lookup {ps_dq(who)} (ext $(@($hit.Properties['telephonenumber'])[0]); I am in $g groups)\" }}",
             f"else {{ Say \"ok lookup {ps_dq(who)}: not in the directory yet ($g groups)\" }}"]


def _save_errors(var: str) -> str:
    """The catch of a save: a full disk or quota, a refusal, or anything else."""
    return (f"$m = $_.Exception.Message; if ($m -match 'not enough space|disk is full|quota') {{ Say \"fail disk-full $hit\" }} "
            f"elseif ($m -match 'denied') {{ Say \"fail save-denied $hit\" }} else {{ Say \"fail {var} $m\" }}")


def _part_document(body: list[str], job: dict, person: dict, facts: dict, stamp: str) -> None:
    """A Word-sized document: opened from the department folder when it is
    there, then saved back at the size the job says (a memo to a report of
    a couple of megabytes), as Rich Text that Word and WordPad open."""
    _find_share(body, person, facts)
    line = rtf_escape(stamp or person["name"]) + r" \par "
    body += [f"$kb = {int(job.get('kb', 60))}; $sb = New-Object Text.StringBuilder",
             r"[void]$sb.Append('{\rtf1\ansi\deff0{\fonttbl{\f0 Calibri;}}\f0\fs22 ')",
             f"$ln = {ps_quote(line)}; while ($sb.Length -lt $kb * 1024) {{ [void]$sb.Append($ln) }}; [void]$sb.Append('}}')",
             f"$f = Join-Path $hit {ps_quote(job['doc'])}; $t = [Diagnostics.Stopwatch]::StartNew()",
             "try { if (Test-Path -LiteralPath $f) { $null = [IO.File]::ReadAllBytes($f) }",
             "  [IO.File]::WriteAllText($f, $sb.ToString()); $n = ([IO.File]::ReadAllBytes($f)).Length }",
             f"catch {{ {_save_errors('document')}; return }}",
             "Say \"bytes $($n * 2)\"",
             "Say \"ok document $f ($([math]::Round($n / 1KB)) KB, $([math]::Round($t.Elapsed.TotalSeconds, 1)) s)\""]


def _part_bigcopy(body: list[str], job: dict, person: dict, facts: dict, stamp: str) -> None:
    """A big file to the department folder and on into the home folder: a
    scan or a recording, the same name each time so it never fills the
    server. A copy slower than SLOW_MBPS is what users call slow."""
    _find_share(body, person, facts)
    name = ps_quote(job.get("file") or f"Scans - {person['name']}.dat")
    body += [f"$mb = {int(job.get('mb', 8))}; $tmp = Join-Path $env:TEMP 'winlab-bigcopy.dat'",
             "$buf = New-Object byte[] 1048576; (New-Object Random).NextBytes($buf)",
             "$fs = [IO.File]::Create($tmp); try { for ($i = 0; $i -lt $mb; $i++) { $fs.Write($buf, 0, $buf.Length) } } finally { $fs.Close() }",
             f"$dst = Join-Path $hit {name}; $t = [Diagnostics.Stopwatch]::StartNew()",
             "try { Copy-Item -LiteralPath $tmp -Destination $dst -Force -ErrorAction Stop }",
             f"catch {{ Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; {_save_errors('bigcopy')}; return }}",
             "$up = [math]::Max(0.1, $t.Elapsed.TotalSeconds); Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue",
             "$moved = $mb; $back = ''",
             "$r = ([adsisearcher]\"(sAMAccountName=$env:USERNAME)\").FindOne(); $h = if ($r) { @($r.Properties['homedirectory'])[0] } else { $null }",
             f"if ($h) {{ $t.Restart(); try {{ Copy-Item -LiteralPath $dst -Destination (Join-Path $h {name}) -Force -ErrorAction Stop; $moved += $mb",
             "  $back = \", $([math]::Round($t.Elapsed.TotalSeconds, 1)) s on into the home folder\" } catch { } }",
             "Say \"bytes $($moved * 1MB)\"",
             f"if ($mb / $up -lt {SLOW_MBPS}) {{ Say \"fail slow $dst ($mb MB took $([math]::Round($up)) s)\"; return }}",
             "Say \"ok bigcopy $dst ($mb MB in $([math]::Round($up, 1)) s$back)\""]


def _part_browse(body: list[str], job: dict, person: dict, facts: dict, stamp: str) -> None:
    """The lab's other web sites, a page each, signed in as the person."""
    urls = job.get("sites") or [s["url"] for s in facts.get("sites", ())][:1]
    body += [f"$bytes = 0; $seen = @(); foreach ($u in @({', '.join(ps_quote(u) for u in urls)})) {{",
             "  try { $w = Invoke-WebRequest -Uri $u -UseBasicParsing -UseDefaultCredentials -TimeoutSec 20 -ErrorAction Stop",
             "    $bytes += $w.RawContent.Length; $seen += $u }",
             "  catch { Say \"bytes $bytes\"; Say \"fail website $u $($_.Exception.Message)\"; return } }",
             "Say \"bytes $bytes\"; Say \"ok browse $($seen -join ' ')\""]


def _part_sql(body: list[str], job: dict, person: dict, facts: dict, stamp: str) -> None:
    """A report from the lab's SQL Server, as the person (Windows
    authentication): the company's databases listed, one opened, a table
    read. Whatever databases there are, the student made."""
    app = f"{person.get('department', 'Staff')} reports".replace(";", "")
    cs = f"Server={facts['sql']};Database=master;Integrated Security=SSPI;Connect Timeout=15;Application Name={app}"
    body += [f"$c = New-Object Data.SqlClient.SqlConnection {ps_quote(cs)}",
             "try { $c.Open() } catch { $m = $_.Exception.Message -replace '\\s+', ' '",
             "  if ($m -match 'Login failed') { Say \"fail sql-login $m\" } else { Say \"fail sql-down $m\" }; return }",
             "try { $q = $c.CreateCommand(); $q.CommandTimeout = 30",
             "  $q.CommandText = 'SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0 ORDER BY name'",
             "  $dbs = @(); $r = $q.ExecuteReader(); while ($r.Read()) { $dbs += $r.GetString(0) }; $r.Close()",
             "  if (-not $dbs.Count) { Say 'ok sql master (the company has no database of its own yet)'; return }",
             f"  $db = $dbs[{int(job.get('n', 0))} % $dbs.Count]; $c.ChangeDatabase($db)",
             "  $q.CommandText = 'SELECT TOP 1 s.name, t.name FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id ORDER BY NEWID()'",
             "  $r = $q.ExecuteReader(); $tb = $null",
             "  if ($r.Read()) { $tb = '[' + $r.GetString(0).Replace(']', ']]') + '].[' + $r.GetString(1).Replace(']', ']]') + ']' }; $r.Close()",
             "  $rows = 0; if ($tb) { $q.CommandText = \"SELECT TOP 500 * FROM $tb\"; $r = $q.ExecuteReader(); while ($r.Read()) { $rows++ }; $r.Close() }",
             "  Say \"bytes $($rows * 200)\"; Say \"ok sql $db ($rows rows$(if ($tb) { ' from ' + $tb }))\" }",
             "catch { $m = $_.Exception.Message -replace '\\s+', ' '",
             "  if ($m -match 'permission|denied') { Say \"fail sql-denied $m\" } elseif ($m -match 'Login failed|Cannot open database') { Say \"fail sql-login $m\" }",
             "  else { Say \"fail sql $m\" } }",
             "finally { $c.Close() }"]


# The first message of a Remote Desktop connection: a TPKT header and an
# X.224 Connection Request carrying RDP's negotiation request (TLS or
# CredSSP). The session host answers with a Connection Confirm (0xD0).
RDP_HELLO = (3, 0, 0, 19, 14, 0xE0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0)


def _part_rdp(body: list[str], job: dict, person: dict, facts: dict, stamp: str) -> None:
    """The person opens the remote desktop: their PC reaches the session
    host's Remote Desktop listener and the listener answers the connection
    request. (A full session needs a screen; this is the network half.)"""
    h = ps_quote(facts["rds"])
    hello = ", ".join(f"0x{b:02X}" for b in RDP_HELLO)
    body += [f"$pt = Port {h} 3389; if ($pt -ne 'open') {{ Say \"fail rdp-$pt {facts['rds']}\"; return }}",
             f"$tc = New-Object Net.Sockets.TcpClient; try {{ $tc.Connect({h}, 3389); $s = $tc.GetStream(); $s.ReadTimeout = 8000",
             f"  $req = [byte[]]@({hello}); $s.Write($req, 0, $req.Length)",
             "  $buf = New-Object byte[] 64; $n = $s.Read($buf, 0, 64)",
             f"  if ($n -ge 11 -and $buf[5] -eq 0xD0) {{ Say \"bytes $($n + 19)\"; Say \"ok rdp {facts['rds']}\" }} else {{ Say \"fail rdp-refused {facts['rds']}\" }} }}",
             f"catch {{ Say \"fail rdp-refused {facts['rds']} $($_.Exception.Message)\" }} finally {{ $tc.Close() }}"]


MORE_PARTS = {"lookup": _part_lookup, "document": _part_document, "bigcopy": _part_bigcopy,
              "browse": _part_browse, "sql": _part_sql, "rdp": _part_rdp}


def user_part(job: dict, person: dict, facts: dict, outfile: str, today: str = "") -> str:
    """The script the person runs as themselves (inside their scheduled
    task): one action, its result written line by line to `outfile` as
    "ok <action> <detail>" or "fail <what broke> <detail>", then "end"."""
    act = job["action"]
    stamp = f"{today} {person['name']}: {job.get('line', '')}".strip()
    body: list[str] = []
    if act == "signin":
        # What a logon does next: the logon scripts' share on the domain, the
        # user's Group Policy, their logon script and the drives it maps.
        netlogon = chr(92) * 2 + facts["domain"] + chr(92) + "NETLOGON"
        body += [f"$null = Test-Path {ps_quote(netlogon)}", *_signin_extras(netlogon)]
        body +=["Say \"ok signin $env:USERDOMAIN\\$env:USERNAME on $env:COMPUTERNAME\""]
    elif act == "share":
        _find_share(body, person, facts)
        body += ["$null = New-PSDrive -Name S -PSProvider FileSystem -Root $hit",
                 f"$f = 'S:\\' + {ps_quote(job['doc'])}",
                 f"try {{ Add-Content -LiteralPath $f -Value {ps_quote(stamp)} -ErrorAction Stop; $null = Get-Content -LiteralPath $f -Tail 1 -ErrorAction Stop",
                 f"  Say \"ok share $hit\\{job['doc']}\" }} catch {{ Say \"fail save-denied $hit\" }}"]
    elif act == "home":
        body += ["$r = ([adsisearcher]\"(sAMAccountName=$env:USERNAME)\").FindOne()",
                 "$h = if ($r) { @($r.Properties['homedirectory'])[0] } else { $null }",
                 "if (-not $h) { Say 'fail home-unset none'; return }",
                 f"try {{ Add-Content -LiteralPath (Join-Path $h 'Notes.txt') -Value {ps_quote(stamp)} -ErrorAction Stop; Say \"ok home $h\\Notes.txt\" }}",
                 "catch { if ($_.Exception.Message -match 'denied') { Say \"fail home-denied $h\" } else { Say \"fail home-missing $h\" } }"]
    elif act == "print":
        srv = facts["printserver"]
        body += ["$p = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'PDF|XPS|OneNote|Fax' } | Select-Object -First 1"]
        if srv:
            body += [f"if (-not $p) {{ try {{ $s = Get-Printer -ComputerName {ps_quote(srv)} -ErrorAction Stop | Where-Object Shared | Select-Object -First 1",
                     f"  if ($s) {{ $c = '\\\\{srv}\\' + $s.ShareName; Add-Printer -ConnectionName $c -ErrorAction Stop; $p = Get-Printer -Name $c }} }} catch {{ }} }}"]
        body += ["if (-not $p) { Say 'fail print-none none'; return }",
                 f"try {{ {ps_quote(stamp or person['name'])} | Out-Printer -Name $p.Name }}",
                 "catch { Say \"fail print-stuck $($p.Name) ($($_.Exception.Message))\"; return }",
                 f"$until = (Get-Date).AddSeconds({PRINT_WAIT})",
                 "do { Start-Sleep -Seconds 3; $left = @(Get-PrintJob -PrinterName $p.Name -ErrorAction SilentlyContinue | Where-Object { $_.UserName -eq $env:USERNAME }) }",
                 "while ($left.Count -and (Get-Date) -lt $until)",
                 "if ($left.Count) { Say \"fail print-stuck $($p.Name) ($($left[0].JobStatus))\" } else { Say \"ok print $($p.Name)\" }"]
    elif act == "mail":
        body += [f"try {{ Send-MailMessage -SmtpServer {ps_quote(facts['mail'])} -From {ps_quote(person['mail'])} "
                 f"-To {ps_quote(job['to'])} -Subject {ps_quote(job['subject'])} -Body {ps_quote(stamp or job['subject'])} "
                 "-WarningAction SilentlyContinue -ErrorAction Stop",
                 f"  Say {ps_quote('ok mail ' + job['to'])} }} catch {{ Say \"fail mail $($_.Exception.Message)\" }}"]
    elif act == "intranet":
        url = f"http://{facts['intranet']}/"
        body += [f"try {{ $w = Invoke-WebRequest -Uri {ps_quote(url)} -UseBasicParsing -UseDefaultCredentials -TimeoutSec 20 -ErrorAction Stop",
                 f"  Say \"ok intranet {url} $($w.StatusCode)\" }} catch {{ Say \"fail intranet $($_.Exception.Message)\" }}"]
    elif act in MORE_PARTS:
        MORE_PARTS[act](body, job, person, facts, stamp)
    else:
        raise WorkdayError(f"unknown action {act!r}")
    return "\n".join([
        f"$o = {ps_quote(outfile)}",
        "function Say($t) { Add-Content -LiteralPath $o -Value $t -Encoding UTF8 }",
        PORT_FN,
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'",
        "try { & {", *body, "} } catch { Say \"fail error $($_.Exception.Message)\" }",
        "Say 'end'"])


def _vpn_first() -> list[str]:
    """A PC at home reaches the office only through the VPN the student
    built: when the domain controller does not answer, the PC's all-user VPN
    connection is dialled (rasdial, as Windows does for a connection set to
    connect automatically), and the person works only once the DC answers."""
    return [
        "function Reach { $c = New-Object Net.Sockets.TcpClient; try { $a = $c.BeginConnect($dc, 389, $null, $null)",
        "  ($a.AsyncWaitHandle.WaitOne(3000) -and $c.Connected) } catch { $false } finally { $c.Close() } }",
        "if (-not (Reach)) { $v = @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue)",
        "  if (-not $v.Count) { Say 'vpn none'; return }",
        "  $why = & { $ErrorActionPreference = 'Continue'; rasdial.exe $v[0].Name 2>&1 | Out-String }",
        "  Start-Sleep -Seconds 2",
        "  if (Reach) { Say \"vpn up $($v[0].Name)\" }",
        "  else { Say \"vpn fail $($v[0].Name) $((($why -split \"`r?`n\") | Where-Object { $_ -match '\\d{3}' } | Select-Object -First 1))\"; return } }",
    ]


def command_for(job: dict, person: dict, facts: dict, secret: str = "", fresh: str = "",
                tag: str = "", today: str = "") -> str:
    """The command winlab's agent runs on the person's PC (as the machine):
    look the account up in the directory; with a password, sign in against
    the domain controller, change an initial password that must be changed
    (to `fresh`), then run the person's part as them in a one-off scheduled
    task and pass its lines back. Every line it prints starts with "WD "."""
    tag = tag or _rand.token_hex(4)
    acct = person["account"]
    outfile = f"C:\\Windows\\Temp\\wd-{tag}.txt"
    head = [
        f"# {person['name']} starts work at this PC. The directory is asked whether the account exists; then",
        "# Windows checks the credentials with the domain controller, as at a sign-in, and the person's own",
        "# work runs under their account in a scheduled task that is removed when it is done.",
        "& {",
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'",
        "function Say($t) { Write-Output \"WD $t\" }",
        f"$acct = {ps_quote(acct)}; $dom = {ps_quote(facts['netbios'])}; $dns = {ps_quote(facts['domain'])}; "
        f"$dc = {ps_quote(facts['dc_addr'])}",
        *(_vpn_first() if job.get("pc") in facts.get("remote_pcs", ()) else []),
        "$asked = $true",
        "try { $r = ([adsisearcher]\"(&(objectCategory=person)(objectClass=user)(sAMAccountName=$acct))\").FindOne() }",
        "catch { $r = $null; $asked = $false; Say \"account unknown $($_.Exception.Message)\" }",
        "if ($r) { $uac = [int]@($r.Properties['useraccountcontrol'])[0]; $pls = [int64]@($r.Properties['pwdlastset'])[0]",
        "  $lt = if ($r.Properties['lockouttime'].Count) { [int64]$r.Properties['lockouttime'][0] } else { 0 }",
        "  Say \"account exists disabled=$([bool]($uac -band 2)) locked=$($lt -gt 0) mustchange=$($pls -eq 0)\" }",
        "elseif ($asked) { Say 'account none' }",
    ]
    if not secret:
        return "\n".join(head + ["}"])
    job_script = user_part(job, person, facts, outfile, today)
    body = [
        f"$given = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String({ps_quote(_b64(secret))}))",
        f"$fresh = {ps_quote(_b64(fresh)) if fresh else chr(39) * 2}",
        "function Logon($s) {",
        "  $c = New-Object System.Management.Automation.PSCredential(\"$dom\\$acct\", (ConvertTo-SecureString $s -AsPlainText -Force))",
        "  try { $null = New-PSDrive -Name WDLOGON -PSProvider FileSystem -Root \"\\\\$dc\\NETLOGON\" -Credential $c",
        "    Remove-PSDrive -Name WDLOGON -Force; return 'ok' } catch { return $_.Exception.Message } }",
        "$res = Logon $given",
        "if ($res -match 'must be changed' -and $fresh) {",
        "  $new = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($fresh))",
        "  if (-not ('Office.NetApi' -as [type])) { Add-Type -Namespace Office -Name NetApi -MemberDefinition '[DllImport(\"netapi32.dll\", CharSet = CharSet.Unicode)] public static extern int NetUserChangePassword(string d, string u, string o, string n);' }",
        "  $rc = [Office.NetApi]::NetUserChangePassword($dns, $acct, $given, $new)",
        "  if ($rc -eq 0) { Say 'newsecret ok'; $given = $new; $res = Logon $given } else { Say \"newsecret fail $rc\" } }",
        "if ($res -ne 'ok') { Say \"signin-fail $res\"; return }",
        "Say 'signin ok'",
        f"$outf = {ps_quote(outfile)}; Remove-Item -LiteralPath $outf -Force -ErrorAction SilentlyContinue",
        f"$name = {ps_quote('Workday ' + acct)}",
        "$svc = New-Object -ComObject Schedule.Service; $svc.Connect(); $root = $svc.GetFolder('\\')",
        "$def = $svc.NewTask(0); $def.Settings.ExecutionTimeLimit = 'PT5M'",
        "$def.Settings.DisallowStartIfOnBatteries = $false; $def.Settings.StopIfGoingOnBatteries = $false",
        "$def.Principal.LogonType = 1; $def.Principal.RunLevel = 0",
        "$a = $def.Actions.Create(0); $a.Path = 'powershell.exe'",
        f"$a.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encode_ps(job_script)}'",
        "try { $t = $root.RegisterTaskDefinition($name, $def, 6, \"$dom\\$acct\", $given, 1) }",
        "catch { Say \"task-fail $($_.Exception.Message)\"; return }",
        "try { $null = $t.Run($null)",
        f"  $until = (Get-Date).AddSeconds({TASK_WAIT})",
        "  do { Start-Sleep -Seconds 2; $done = (Test-Path -LiteralPath $outf) -and ((Get-Content -LiteralPath $outf -Tail 1) -eq 'end') }",
        "  while (-not $done -and (Get-Date) -lt $until)",
        "  if (Test-Path -LiteralPath $outf) { Get-Content -LiteralPath $outf | ForEach-Object { Say \"task $_\" } }",
        "  else { Say \"task-noresult $('0x{0:X}' -f $t.LastTaskResult)\" }",
        "} finally { try { $root.DeleteTask($name, 0) } catch { }; Remove-Item -LiteralPath $outf -Force -ErrorAction SilentlyContinue }",
        "}",
    ]
    return "\n".join(head + body)


# ============================================================ the answers
_SIGNIN = (
    (r"locked", "locked"),
    (r"disabled", "disabled"),
    (r"must be changed", "mustchange"),
    (r"expired", "expired"),
    (r"logon servers|network path|network name|RPC server|not reachable|unreachable|no longer available", "unreachable"),
    (r"restriction|not allowed|not been granted|logon type", "restricted"),
    (r"user name or password|password is incorrect|unknown user|bad password", "badpassword"),
)


def classify_signin(msg: str) -> str:
    for rx, kind in _SIGNIN:
        if re.search(rx, msg or "", re.IGNORECASE):
            return kind
    return "signin"


def parse(ok: bool, out: str) -> dict:
    """What the agent's answer says: {"account": "exists"|"none"|"unknown",
    "flags": {...}, "signin": "ok"|<failure kind>|"", "fresh": True when the
    person set their own password, "steps": [(ok, what, detail)], "error"}."""
    res: dict = {"account": "", "flags": {}, "signin": "", "fresh": False, "steps": [], "error": "",
                 "bytes": 0, "vpn": ""}
    if not ok and "WD " not in (out or ""):
        res["error"] = (out or "no answer from the agent").strip()[:200]
        return res
    for raw in (out or "").splitlines():
        line = raw.strip()
        if not line.startswith("WD "):
            continue
        word, _, rest = line[3:].partition(" ")
        if word == "account":
            kind, _, more = rest.partition(" ")
            res["account"] = kind
            res["flags"] = dict(x.split("=", 1) for x in more.split() if "=" in x)
        elif word == "signin":
            res["signin"] = "ok"
        elif word == "signin-fail":
            res["signin"] = "noaccount" if res["account"] == "none" else classify_signin(rest)
            res["detail"] = rest[:200]
        elif word == "newsecret":
            res["fresh"] = rest.startswith("ok")
            if not res["fresh"]:
                res["signin"] = "mustchange"
        elif word in ("task-fail", "task-noresult"):
            res["steps"].append((False, "pc", rest[:200]))
        elif word == "vpn":
            kind, _, detail = rest.partition(" ")
            res["vpn"], res["vpn_detail"] = kind, detail.strip()[:200]
        elif word == "task":
            verdict, _, more = rest.partition(" ")
            what, _, detail = more.partition(" ")
            if verdict in ("ok", "fail"):
                res["steps"].append((verdict == "ok", what, detail.strip()[:200]))
            elif verdict == "bytes" and what.isdigit():
                res["bytes"] += int(what)
    return res


# ========================================================== who calls whom
TICKETS: dict[str, tuple[str, str, str, str]] = {
    # kind: (priority, category, what they say, more)
    "noaccount": ("P2", "accounts", "I can't sign in: I'm new and it says my user name or password is wrong",
                  "Hi, I'm {name}, the new {title} in {department}. I'm at {pc} and Windows won't take my user name. "
                  "HR said IT would set me up as {account}."),
    "nopassword": ("P2", "accounts", "Nobody has given me my password",
                   "Hi, I'm {name} in {department}. I'm at {pc} and I have a user name ({account}) but nobody gave me a "
                   "password, so I can't start work."),
    "badpassword": ("P2", "accounts", "My password doesn't work",
                    "I'm typing the password I was given and {pc} says the user name or password is incorrect. "
                    "My user name is {account}."),
    "disabled": ("P2", "accounts", "It says my account is disabled",
                 "I can't sign in at {pc}: 'your account has been disabled'. I haven't done anything! ({account})"),
    "locked": ("P2", "accounts", "It says my account is locked",
               "I can't sign in at {pc}, it says my account is locked. Can you unlock it? ({account})"),
    "expired": ("P2", "accounts", "It says my password has expired",
                "{pc} says my password has expired and I can't get in. ({account})"),
    "mustchange": ("P2", "accounts", "It makes me change my password and won't take the new one",
                   "Windows asks me for a new password but every one I try is refused. ({account} at {pc})"),
    "restricted": ("P2", "accounts", "It says I'm not allowed to sign in at this PC",
                   "I get 'the sign-in method you're trying to use isn't allowed' at {pc}. ({account})"),
    "unreachable": ("P1", "network", "I can't sign in: it says no logon servers are available",
                    "At {pc} I get 'there are currently no logon servers available'. Is the network down?"),
    "signin": ("P2", "accounts", "I can't sign in to my PC",
               "I can't sign in at {pc}. The message says: {detail}"),
    "share-missing": ("P2", "file share", "I can't open the {department} share",
                      "{detail} says it can't be found. We need it for today's work."),
    "share-denied": ("P2", "file share", "I can't open the {department} share",
                     "I get 'access denied' on {detail}. I'm in {department}, I should be able to open it."),
    "save-denied": ("P2", "file share", "I can open the {department} share but I can't save anything",
                    "I can see the files on {detail} but saving says access denied."),
    "home-unset": ("P3", "file share", "I have no home folder",
                   "Other people have a home drive for their own files; I don't. ({account})"),
    "home-missing": ("P3", "file share", "My home folder won't open",
                     "My home folder {detail} says it can't be found. ({account})"),
    "home-denied": ("P3", "file share", "I can't save in my home folder",
                    "Saving into my home folder {detail} says access denied. ({account})"),
    "print-none": ("P3", "printing", "I can't find a printer",
                   "I want to print and there's no printer on {pc}, only 'Print to PDF'."),
    "print-stuck": ("P3", "printing", "My print job never came out",
                    "I printed on {detail} a few minutes ago and nothing came out. It's still sitting in the queue."),
    "mail": ("P2", "mail", "My emails aren't going out",
             "I tried to send a message to a colleague and it failed: {detail}"),
    "intranet": ("P3", "web", "The intranet won't open",
                 "The intranet page doesn't load on {pc}: {detail}"),
    "pc": ("P3", "desktop", "My PC isn't working properly",
           "At {pc} nothing I start seems to run. ({detail})"),
    "error": ("P3", "desktop", "Something went wrong on my PC",
              "I got an error at {pc}: {detail}"),
    # The load engine's things (winlab/traffic.py), in the same staff words.
    "share-unreachable": ("P2", "file share", "Nothing on the file server opens",
                          "Every folder on the file server says it can't be found, not just ours. ({detail}, from {pc}) "
                          "It was fine before. Has something been changed?"),
    "disk-full": ("P2", "file share", "The file server says it's full",
                  "I tried to save on {detail} and it says there is not enough space."),
    "bigcopy": ("P3", "file share", "Copying a big file to the server fails",
                "I'm copying a large file to our folder and it stops with: {detail}"),
    "slow": ("P3", "network", "Everything is really slow today",
             "Copying anything to the server takes forever at {pc}: {detail}."),
    "document": ("P3", "file share", "Word can't save my document",
                 "I'm trying to save a document and get: {detail}"),
    "dns": ("P2", "network", "My PC says it can't find the servers",
            "At {pc} programs say they can't find {detail}. It worked yesterday."),
    "directory": ("P3", "accounts", "The address book won't open",
                  "I tried to look up a colleague's extension and the address book says: {detail}"),
    "website": ("P3", "web", "A web site I use for work won't open",
                "This page doesn't load at {pc}: {detail}"),
    "sql-login": ("P2", "apps", "The {department} database app says login failed",
                  "When I open our reports at {pc} the database says: {detail}"),
    "sql-denied": ("P3", "apps", "The database app says I don't have permission",
                   "Running my usual report at {pc} I get: {detail}"),
    "sql-down": ("P2", "apps", "The database app won't connect",
                 "Our reports don't open at all at {pc}: {detail}"),
    "sql": ("P3", "apps", "My report fails in the database app",
            "The report I run every day fails at {pc}: {detail}"),
    "rdp-blocked": ("P2", "remote desktop", "I can't connect to the remote desktop",
                    "Connecting to the remote desktop ({detail}) from {pc} just times out."),
    "rdp-refused": ("P2", "remote desktop", "I can't connect to the remote desktop",
                    "The remote desktop ({detail}) says it can't connect, from {pc}."),
    "rdp-dns": ("P2", "remote desktop", "I can't connect to the remote desktop",
                "{pc} says the remote computer ({detail}) can't be found."),
    "gpo": ("P3", "desktop", "Windows says it couldn't apply group policy",
            "When I signed in at {pc} a message said: {detail}. Some of my settings are missing."),
    "logonscript-missing": ("P3", "desktop", "My drives didn't map when I signed in",
                            "My usual drives aren't there at {pc}. Someone said the sign-in script {detail} is missing."),
    "logonscript-fail": ("P3", "desktop", "My drives didn't map when I signed in",
                         "A black window flashed when I signed in at {pc} and my drives aren't there. ({detail})"),
    "logonscript-hung": ("P3", "desktop", "Signing in takes forever",
                         "Signing in at {pc} hangs on a black window for a minute. ({detail})"),
    "drive-broken": ("P3", "file share", "One of my drives has a red cross on it",
                     "At {pc} this drive shows a red cross and won't open: {detail}"),
    "vpn-none": ("P2", "network", "I'm working from home and can't reach anything",
                 "I'm at home on {pc} and nothing from the office opens. There's no VPN on this laptop that I can see."),
    "vpn-fail": ("P2", "network", "The VPN won't connect",
                 "I'm working from home on {pc} and the VPN won't connect: {detail}"),
}


def dedupe_key(kind: str, person: dict, pc: str, detail: str = "") -> str:
    """One broken thing, one ticket: a share is broken once for everyone in
    the department, a printer once for everyone, an account once per person."""
    if kind == "share-unreachable":
        return f"workday:server:{detail.split(' ')[0].lower()}"
    if kind.startswith(("share", "save")):
        return f"workday:share:{share_name(person.get('department', ''))}"
    if kind == "disk-full":
        return f"workday:disk-full:{detail.split(' ')[0].lower()}"
    if kind in ("sql-login", "sql-denied"):
        return f"workday:{kind}:{share_name(person.get('department', ''))}"
    if kind in ("dns", "directory", "sql-down", "sql", "gpo", "vpn-fail"):
        return f"workday:{kind}"
    if kind.startswith("rdp"):
        return "workday:rdp"
    if kind == "website":
        return f"workday:website:{detail.split(' ')[0].lower()}"
    if kind.startswith("logonscript"):
        return f"workday:logonscript:{detail.split(' (')[0].lower()}"
    if kind == "drive-broken":
        return f"workday:drive:{detail.split(',')[0].split(' ')[-1].lower()}"
    if kind in ("slow", "bigcopy", "document"):
        return f"workday:{kind}:{pc}"
    if kind == "print-stuck":
        return f"workday:print:{detail.split(' (')[0].lower()}"
    if kind == "print-none":
        return f"workday:print-none:{pc}"
    if kind in ("mail", "intranet"):
        return f"workday:{kind}"
    if kind in ("unreachable",):
        return "workday:logon-servers"
    if kind in ("pc", "error"):
        return f"workday:pc:{pc}"
    return f"workday:{kind}:{person['account'].lower()}"


def scope_of(key: str, person: dict, pc: str) -> dict:
    """Who a broken thing's ticket is about, from its dedupe key: one
    department, one account, one PC, or everyone ({}). The load engine uses
    it to tell when calls about it have stopped (someone it touched did the
    same thing again without trouble)."""
    kind = key.split(":")[1] if key.count(":") else ""
    if kind in ("share", "sql-login", "sql-denied"):
        return {"department": person.get("department", "")}
    if kind in ("pc", "print-none", "slow", "bigcopy", "document"):
        return {"pc": pc}
    if key.count(":") == 2 and key.endswith(":" + person["account"].lower()):
        return {"account": person["account"].lower()}
    return {}


def ticket_for(kind: str, person: dict, pc: str, detail: str = "") -> dict:
    """The ticket a person raises: open_ticket's keyword arguments."""
    pri, cat, summary, body = TICKETS.get(kind, TICKETS["error"])
    fill = {**{k: person.get(k, "") for k in ("name", "title", "department", "account")}, "pc": pc or "my PC",
            "detail": (detail or "").strip() or "no message"}
    key = dedupe_key(kind, person, pc, detail)
    return {"caller": person["id"], "summary": summary.format(**fill), "body": body.format(**fill),
            "priority": pri, "source": "workday", "category": cat, "node": pc, "dedupe": key,
            # Resolving it has the caller try again (check_ticket, registered below).
            "fault": {"kind": "workday", "node": pc, "caller": person["id"], "dedupe": key}}


DOING = {"signin": "signing in", "share": "editing {doc} on the {department} share", "home": "keeping notes in the home folder",
         "print": "printing", "mail": "writing to {to_name}", "intranet": "reading the intranet",
         "lookup": "looking {who} up in the address book", "document": "working on {doc}",
         "bigcopy": "copying a big file to the {department} folder", "browse": "on the lab's web sites",
         "sql": "running a report in the database", "rdp": "working on the remote desktop"}


def outcome(job: dict, person: dict, res: dict) -> dict:
    """What happened, in the feed's words: {"ok", "text", "doing", "signed",
    "status", "ticket": (kind, detail) or None}."""
    act, pc = job["action"], job["pc"]
    doing = DOING.get(act, act).format(**{**person, **job})
    if res.get("error"):
        return {"ok": False, "text": f"could not start at {pc}: the PC's agent did not answer", "doing": "waiting for the PC",
                "signed": False, "status": "", "ticket": None, "retry": True}
    if res.get("vpn") in ("none", "fail"):
        why = "has no VPN to reach the office" if res["vpn"] == "none" else "could not connect the VPN from home"
        return {"ok": False, "text": f"{why} ({pc})", "doing": "at home, cut off from the office",
                "signed": False, "status": "failing", "ticket": (f"vpn-{res['vpn']}", res.get("vpn_detail", ""))}
    acct = res.get("account")
    if act == "signin" and not job.get("keyed"):
        if acct == "none":
            return {"ok": False, "text": f"arrived at {pc}: there is no account {person['account']} yet",
                    "doing": "waiting for an account", "signed": False, "status": "no account",
                    "ticket": ("noaccount", "")}
        if acct == "exists":
            return {"ok": False, "text": f"arrived at {pc}: has an account but no password from IT",
                    "doing": "waiting for a password", "signed": False, "status": "no password",
                    "ticket": ("nopassword", "")}
        return {"ok": False, "text": f"arrived at {pc}: the PC cannot reach the directory", "doing": "waiting",
                "signed": False, "status": "failing", "ticket": None, "retry": True}
    if res.get("signin") != "ok":
        kind = res.get("signin") or ("noaccount" if acct == "none" else "signin")
        why = {"noaccount": "there is no such account", "badpassword": "the password is wrong",
               "disabled": "the account is disabled", "locked": "the account is locked out",
               "expired": "the password has expired", "mustchange": "the new password was refused",
               "unreachable": "no logon server answered", "restricted": "not allowed to sign in there"}.get(kind, "sign-in failed")
        return {"ok": False, "text": f"could not sign in at {pc}: {why}", "doing": "on the phone to the helpdesk",
                "signed": False, "status": "no account" if kind == "noaccount" else "failing",
                "ticket": (kind, res.get("detail", ""))}
    steps = res.get("steps") or []
    fresh = " (chose a new password)" if res.get("fresh") else ""
    if not steps:
        return {"ok": False, "text": f"signed in at {pc}{fresh}, but nothing ran", "doing": f"working at {pc}",
                "signed": True, "status": "signed in", "ticket": ("pc", "the task gave no answer")}
    # The first thing that failed is what they call about (a sign-in can
    # succeed and its Group Policy or logon script fail); else the last word.
    good, what, detail = next((s for s in steps if not s[0]), steps[-1])
    if good:
        text = {"signin": f"signed in at {pc}{fresh}", "share": f"saved {detail}", "home": f"saved {detail}",
                "print": f"printed a page on {detail}", "mail": f"sent mail to {detail}",
                "intranet": f"opened {detail.split(' ')[0]}", "lookup": f"looked up {detail}",
                "document": f"saved {detail}", "bigcopy": f"copied {detail}", "browse": f"browsed {detail}",
                "sql": f"ran a report on {detail}", "rdp": f"reached the remote desktop on {detail}"}.get(what, f"{what} {detail}")
        return {"ok": True, "text": text, "doing": doing, "signed": True, "status": "signed in", "ticket": None}
    say = {"share-missing": "could not find the {department} share", "share-denied": "was refused on the {department} share",
           "save-denied": "could not save on the {department} share", "home-unset": "has no home folder",
           "home-missing": "could not open their home folder", "home-denied": "could not save in their home folder",
           "print-none": "found no printer", "print-stuck": "printed, and nothing came out",
           "mail": "could not send mail", "intranet": "could not open the intranet", "pc": "nothing ran on the PC",
           "share-unreachable": "could not reach the file server", "disk-full": "found the file server full",
           "bigcopy": "could not copy a big file", "slow": "copied a big file, and it crawled",
           "document": "could not save a document", "dns": "could not find the servers by name",
           "directory": "could not open the address book", "website": "could not open a web site",
           "sql-login": "was refused by the database", "sql-denied": "has no permission in the database",
           "sql-down": "could not reach the database", "sql": "had a report fail",
           "rdp-blocked": "could not reach the remote desktop", "rdp-refused": "was turned away by the remote desktop",
           "rdp-dns": "could not find the remote desktop", "gpo": "signed in, but Group Policy failed",
           "logonscript-missing": "signed in, but the logon script is missing",
           "logonscript-fail": "signed in, but the logon script failed",
           "logonscript-hung": "signed in, and the logon script hung", "drive-broken": "has a drive that won't open"}
    text = say.get(what, f"{what} failed").format(**person)
    if detail and detail != "none":
        text += f" ({detail})"
    return {"ok": False, "text": text,
            "doing": "on the phone to the helpdesk", "signed": True, "status": "signed in",
            "ticket": (what if what in TICKETS else "error", detail if detail != "none" else "")}


# ================================================================ the tick
def _apply(lab_name: str, st: dict, job: dict, person: dict, res: dict, now: float, rng: random.Random,
           fresh: str = "", open_ticket=helpdesk.open_ticket) -> dict:
    o = outcome(job, person, res)
    r = st.setdefault("people", {}).setdefault(person["id"], {})
    r["doing"], r["signed"] = o["doing"], o["signed"]
    if o["status"]:
        r["status"] = o["status"]
        r["reason"] = "" if o["ok"] else o["text"]
    if res.get("fresh") and fresh:
        set_secret(lab_name, person["account"], fresh)
        r["own"] = True
    level = st.get("level", DEFAULT_LEVEL)
    factor = float(job.get("factor") or 1.0)
    if o["ok"]:
        r["next"] = now + gap(level, rng, factor)
    else:
        r["next"] = now + (5 * 60 if o.get("retry") else RETRY_MINUTES * 60 if not o["signed"] else gap(level, rng, factor))
    e = _feed(st, now, person, job["pc"], o["text"], o["ok"])
    if o["ticket"]:
        from . import traffic
        kind, detail = o["ticket"]
        spec = ticket_for(kind, person, job["pc"], detail)
        # Each person affected calls; nobody calls about the same thing
        # twice within the hour (they are still waiting on the ticket).
        again, tid = traffic.may_call(lab_name, spec["dedupe"], person["id"], now)
        if again:
            t = open_ticket(lab_name, now=now, **spec)
            e["ticket"] = t.get("id", "")
            e["text"] += f": called the helpdesk ({e['ticket']})" if e["ticket"] else ": called the helpdesk"
            traffic.called(lab_name, spec["dedupe"], job["action"], scope_of(spec["dedupe"], person, job["pc"]),
                           person, t, now)
        else:
            e["ticket"] = tid
            e["text"] += f": still waiting on the helpdesk ({tid})" if tid else ""
    elif o["ok"]:
        from . import traffic
        traffic.works_again(lab_name, job["action"], person, job["pc"], o["text"], now)
    return o


def run_job(lab_name: str, st: dict, job: dict, person: dict, facts: dict, runner: Runner, now: float,
            rng: random.Random, open_ticket=helpdesk.open_ticket) -> dict:
    """Runs one job on the person's PC and records what came of it, and
    what it cost: the time the guest took, the bytes it moved (the load
    engine's counters and its back-off for a slow guest)."""
    from . import traffic
    store = load_secrets(lab_name)
    secret = store.get(person["account"].lower(), "")
    fresh = new_secret() if secret and job["action"] == "signin" else ""
    cmd = command_for(job, person, facts, secret, fresh, today=time.strftime("%Y-%m-%d %H:%M", time.localtime(now)))
    t0, raised = time.monotonic(), False
    try:
        ok, out = runner(job["pc"], cmd, "powershell")
    except Exception as exc:  # noqa: BLE001 - one PC must not stop the office
        ok, out, raised = False, str(exc), True
    res = parse(ok, out)
    o = _apply(lab_name, st, job, person, res, now, rng, fresh, open_ticket)
    traffic.after_job(lab_name, job, person, facts, res, o, time.monotonic() - t0, now, raised)
    return o


def tick(lab, runner: Runner | None = None, now: float | None = None, running: set[str] | None = None,
         rng: random.Random | None = None, open_ticket=helpdesk.open_ticket) -> list[dict]:
    """One step of the working day: who is in, and the things that are due
    now done for real inside the lab. Returns the new feed entries. With
    the workday off only the servers' own work runs; nothing runs while the
    lab clock is paused."""
    with _lock:
        st = load(lab.name)
        clock = labclock.load(lab.name)
        if clock.paused and now is None:
            return []
        now = clock.now() if now is None else now
        if not st.get("on"):
            # Real servers do not wait for the staff: the nightly backup, the
            # scans and replication run whenever the lab runs (winlab/traffic.py).
            from . import traffic
            traffic.servers_only(lab, runner, now, running)
            return []
        if running is None:
            from . import oncall
            running = set(oncall.running_nodes(lab))
        staff = staff_of(everyone(lab))
        facts = lab_facts(lab)
        rng = rng or random.Random()
        n_feed = len(st.setdefault("feed", []))
        # The load engine: a clock that jumped is caught up gently, and the
        # pace of this moment of the day (winlab/traffic.py).
        from . import traffic
        pace = traffic.begin(lab.name, st, now, rng)
        jobs = plan(st, lab.name, staff, facts, now, running, set(load_secrets(lab.name)), rng, pace)
        made: list[dict] = list(st["feed"][n_feed:])
        st["last_tick"] = now
        for j in jobs:
            p = next(p for p in staff if p["id"] == j["id"])
            j["factor"] = pace["factor"] * pace["dept"].get(p.get("department", ""), 1.0)
            st["people"][j["id"]]["doing"] = DOING.get(j["action"], j["action"]).format(
                **{**p, "doc": "", "to_name": "", "who": "", **j})
        save(lab.name, st)
    if runner is None:
        from . import oncall
        runner = oncall.guest_runner(lab.name)
    started = time.monotonic()
    for j in jobs:
        if time.monotonic() - started > traffic.TICK_BUDGET:
            break   # the rest are still due: the next tick takes them
        if j["pc"] in traffic.held_now(lab.name):
            continue   # the PC stopped answering earlier in this tick: leave it be
        person = next(p for p in staff if p["id"] == j["id"])
        with _lock:
            st2 = load(lab.name)
        n0 = len(st2.get("feed", []))
        run_job(lab.name, st2, j, person, facts, runner, now, rng, open_ticket)
        with _lock:
            cur = load(lab.name)
            cur.setdefault("people", {})[j["id"]] = st2["people"][j["id"]]
            cur["feed"] = cur.get("feed", []) + st2["feed"][n0:]
            save(lab.name, cur)
            made.extend(st2["feed"][n0:])
    # The servers' own work (backups, scans, replication) on what is left of
    # the tick's time, and notes on tickets whose calls have stopped.
    traffic.background(lab, facts, now, running, runner, used={j["pc"] for j in jobs},
                       budget=max(0.0, traffic.TICK_BUDGET - (time.monotonic() - started)))
    traffic.housekeep(lab.name, now)
    return made


def traffic_on(lab_name: str) -> bool:
    """Whether the servers' own work runs with the workday off."""
    from . import traffic
    return bool(traffic.load(lab_name).get("background", True))


def kick(lab, runner_factory=None) -> bool:
    """The desktop's poll: a tick in the background at most every
    TICK_EVERY seconds, never two at once. True if one started."""
    name = lab.name
    with _lock:
        if name in _running or time.time() - _last_kick.get(name, 0.0) < TICK_EVERY:
            return False
        if not load(name).get("on") and not traffic_on(name):
            return False
        _running.add(name)
        _last_kick[name] = time.time()

    def go():
        try:
            tick(lab, runner_factory() if runner_factory else None)
        except Exception:  # noqa: BLE001 - the next poll tries again
            pass
        finally:
            with _lock:
                _running.discard(name)
    threading.Thread(target=go, name=f"workday-{name}", daemon=True).start()
    return True


# ========================================================== the HR sheet
SHEET_COLUMNS = ("FirstName", "LastName", "DisplayName", "Department", "Title", "SamAccountName",
                 "EmailAddress", "Extension", "DeskPC", "Manager", "StartDate")


def sheet_csv(everyone: list[dict], start: str) -> str:
    """HR's new-starter sheet: everyone who works here but the admin, as a
    CSV that Import-Csv reads. It never holds anyone's password (that is IT's job)."""
    managers = {p["department"]: p["name"] for p in everyone if p.get("manager")}
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(SHEET_COLUMNS)
    for p in staff_of(everyone):
        boss = managers.get(p["department"], "")
        w.writerow([p["first"], p["last"], p["name"], p["department"], p["title"], p["account"], p["mail"],
                    p["ext"], p.get("pc", ""), "" if boss == p["name"] else boss, start])
    return buf.getvalue()


def sheet_readme(lab) -> str:
    return "\r\n".join([
        "From: HR", "To: IT", "",
        "Hi, the people on New starters.csv start this week. Please set them up before they arrive:",
        "an account each (the user name we agreed is in SamAccountName), in the right department,",
        "with their job title, e-mail, phone extension and manager filled in, a home folder,",
        f"and access to their department's folder on the file server. The domain is {lab.domain}.",
        "", "Their first passwords are up to you: give them to each person (and type them into", "the staff list in winlab's Office window so they can start).", "",
        "Thanks!", ""])


def deliver_sheet(lab, now: float | None = None) -> dict:
    """HR's stick with the sheet onto the lab's media shelf."""
    from . import media, mediashelf
    everyone = directory.load(lab)
    start = day_key(labclock.load(lab.name).now() if now is None else now)
    files = {SHEET_FILE: sheet_csv(everyone, start).encode("utf-8"), "README.txt": sheet_readme(lab).encode("utf-8")}
    sid = mediashelf._new_id(lab.name, SHEET_STICK)
    d = mediashelf.shelf_dir(lab.name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", SHEET_LABEL)
    except media.MediaError as exc:
        raise WorkdayError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": SHEET_TITLE}) + "\n", encoding="utf-8")
    return {"id": sid, "title": SHEET_TITLE, "people": len(staff_of(everyone))}


# ============================================================ the controls
def start(lab) -> str:
    """The workday on. Day one, HR's sheet arrives on the media shelf."""
    with _lock:
        st = load(lab.name)
        msg = "the workday is on"
        if not st.get("sheet"):
            r = deliver_sheet(lab)
            st["sheet"] = r["id"]
            msg += f"; HR's new-starter sheet ({r['people']} people) is on the media shelf: plug it into a machine"
        st["on"] = True
        save(lab.name, st)
    return msg


def stop(lab) -> str:
    with _lock:
        st = load(lab.name)
        st["on"] = False
        save(lab.name, st)
    return "the workday is off: nobody comes in until it is on again"


def set_level(lab, level: str) -> str:
    if level not in LEVELS:
        raise WorkdayError(f"load level is one of {', '.join(LEVELS)}")
    with _lock:
        st = load(lab.name)
        st["level"] = level
        save(lab.name, st)
    return f"load level {level}: each person acts about every {LEVELS[level][0]} minutes"


def set_shifts(lab, on: bool) -> str:
    with _lock:
        st = load(lab.name)
        st["shifts"] = bool(on)
        save(lab.name, st)
    return ("shift work on: early, late and night shifts, every day" if on
            else "shift work off: office hours on weekdays")


def type_secret(lab, account: str, value: str) -> str:
    """The student gives a person their initial password (the staff list).
    The person tries it at their next chance."""
    p = directory.find(everyone(lab), account)
    if p is None or p.get("admin"):
        raise WorkdayError(f"no member of staff {account!r}")
    set_secret(lab.name, p["account"], value)
    with _lock:
        st = load(lab.name)
        r = st.setdefault("people", {}).setdefault(p["id"], {})
        r["next"], r["own"] = 0, False
        if r.get("status") in ("failing", "no password", "no account"):
            r["status"], r["reason"] = "not tried", ""
        save(lab.name, st)
    return f"{p['name']} has a password now" if value else f"{p['name']}'s password is forgotten"


def staff_rows(lab, st: dict | None = None) -> list[dict]:
    """The staff list: who they are, where they sit, and whether they can
    sign in (never the password, only whether one was typed)."""
    st = st or load(lab.name)
    keys = load_secrets(lab.name)
    staff = staff_of(everyone(lab))
    facts = lab_facts(lab)
    out = []
    for p in staff:
        r = st.get("people", {}).get(p["id"], {})
        pc, hot = desk_of(p, staff, facts["pcs"])
        status = r.get("status") or ("not tried" if p["account"].lower() in keys else "no password")
        out.append({"id": p["id"], "name": p["name"], "department": p["department"], "title": p["title"],
                    "account": p["account"], "mail": p["mail"], "ext": p["ext"], "pc": pc, "hot": hot,
                    "manager": bool(p.get("manager")), "keyed": p["account"].lower() in keys,
                    "own": bool(r.get("own")), "status": status, "reason": r.get("reason", ""),
                    "where": r.get("where", ""), "doing": r.get("doing", ""),
                    "arrive": hhmm(r["arrive"]) if r.get("arrive") else "", "leave": hhmm(r["leave"]) if r.get("leave") else "",
                    "shift": r.get("shift", "")})
    return out


def view(lab, real: float | None = None) -> dict:
    """The Office window: the controls, today's people, the feed."""
    st = load(lab.name)
    c = labclock.load(lab.name)
    now = c.now(real)
    facts = lab_facts(lab)
    rows = staff_rows(lab, st)
    # Before the first tick of a day, where people are comes from the plan.
    for row in rows:
        where, today = presence(lab.name, {"id": row["id"]}, now, bool(st.get("shifts")))
        row["where"] = where
        if not row["arrive"] and today.get("arrive"):
            row["arrive"], row["leave"] = hhmm(today["arrive"]), hhmm(today["leave"])
    offers = {"files": facts["files"], "print": facts["printserver"] or facts["printer"],
              "mail": facts["mail"], "intranet": facts["intranet"]}
    try:
        open_ = [t for t in helpdesk.open_tickets(lab.name) if t.get("source") == "workday"]
    except Exception:  # noqa: BLE001
        open_ = []
    return {"on": bool(st.get("on")), "level": st.get("level", DEFAULT_LEVEL), "levels": list(LEVELS),
            "shifts": bool(st.get("shifts")), "now": now, "paused": c.paused,
            "day": time.strftime("%A %d %B", time.localtime(now)),
            "weekend": time.localtime(now).tm_wday >= 5,
            "people": rows, "in": sum(1 for r in rows if r["where"] == "in"),
            "feed": list(reversed(st.get("feed", [])[-80:])), "offers": offers, "pcs": facts["pcs"],
            "dc": facts["dc"], "busy": lab.name in _running, "sheet": st.get("sheet", ""),
            "tickets": len(open_)}


def act(dash, action: str, params: dict) -> dict:
    """The Office window's actions: workday-on, workday-off, workday-level,
    workday-shifts, workday-sheet, workday-tick, staff-password."""
    lab = dash.lab
    try:
        if action == "workday-on":
            return {"ok": True, "message": start(lab)}
        if action == "workday-off":
            return {"ok": True, "message": stop(lab)}
        if action == "workday-level":
            return {"ok": True, "message": set_level(lab, str(params.get("level", "")))}
        if action == "workday-shifts":
            return {"ok": True, "message": set_shifts(lab, params.get("on") in (True, "1", "true", 1))}
        if action == "workday-sheet":
            r = deliver_sheet(lab)
            with _lock:
                st = load(lab.name)
                st["sheet"] = r["id"]
                save(lab.name, st)
            return {"ok": True, "message": f"HR left another copy of the sheet on the media shelf ({r['id']})"}
        if action == "workday-tick":
            _last_kick.pop(lab.name, None)
            return {"ok": True, "message": "the office moves on" if kick(lab) else "the office is busy already",
                    "silent": True}
        if action == "staff-password":
            return {"ok": True, "message": type_secret(lab, str(params.get("account", "")), str(params.get("value", "")))}
    except WorkdayError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown action {action}"}


# ============================================================ the helpdesk
def check_ticket(lab, ticket: dict, runner: Runner | None = None) -> tuple[bool, str]:
    """Whether what a workday ticket reported works now: its caller tries
    the same thing again on their PC. (helpdesk.register_check)"""
    pid = ticket.get("caller", "")
    people_ = everyone(lab)
    person = directory.find(people_, pid)
    if person is None:
        return False, f"{pid} is not in the staff directory"
    staff = staff_of(people_)
    facts = lab_facts(lab)
    pc = ticket.get("node") or desk_of(person, staff, facts["pcs"])[0]
    key = str(ticket.get("dedupe", ""))
    kind = key.split(":")[1] if key.count(":") >= 1 else ""
    action = {"share": "share", "home-unset": "home", "home-missing": "home", "home-denied": "home",
              "print": "print", "print-none": "print", "mail": "mail", "intranet": "intranet",
              "server": "share", "disk-full": "bigcopy", "bigcopy": "bigcopy", "slow": "bigcopy",
              "document": "document", "dns": "lookup", "directory": "lookup", "website": "browse",
              "sql-login": "sql", "sql-denied": "sql", "sql-down": "sql", "sql": "sql", "rdp": "rdp"}.get(kind, "signin")
    rng = random.Random(0)
    job = pick(person, {action: 1}, staff, rng, time.time(), facts) if action != "signin" else {"action": "signin"}
    if job is None:
        return False, "nobody to mail"
    job.update({"id": person["id"], "pc": pc, "keyed": person["account"].lower() in load_secrets(lab.name)})
    if runner is None:
        from . import oncall
        runner = oncall.guest_runner(lab.name)
    secret = load_secrets(lab.name).get(person["account"].lower(), "")
    ok, out = runner(pc, command_for(job, person, facts, secret), "powershell")
    o = outcome(job, person, parse(ok, out))
    return o["ok"], o["text"]


# The helpdesk hands a check the ticket's fault, which carries the caller,
# their PC and what broke: all check_ticket reads.
helpdesk.register_check("workday", check_ticket)


# ================================================================ the CLI
def add_cli(sub) -> None:
    w = sub.add_parser("workday", help="the lab's staff at work: office hours on the lab clock, real sign-ins, "
                                       "files, printing and mail, tickets when something is broken")
    w.add_argument("what", choices=["start", "stop", "status", "tick", "level", "shifts"])
    w.add_argument("arg", nargs="?", default="", help="for level: quiet, normal or busy; for shifts: on or off")
    w.add_argument("--lab", default="")
    s = sub.add_parser("staff", help="the lab's staff list: who works here, their accounts, and their first "
                                     "passwords (typed at a prompt, never on the command line)")
    s.add_argument("what", choices=["list", "password"])
    s.add_argument("account", nargs="?", default="")
    s.add_argument("--lab", default="")


def render(v: dict) -> str:
    lines = [f"workday {'on' if v['on'] else 'off'} · load {v['level']} · shift work {'on' if v['shifts'] else 'off'}"
             + ("   (the lab clock is paused)" if v["paused"] else ""),
             f"{v['day']}, {hhmm(v['now'])} lab time · {v['in']} in · {v['tickets']} open workday ticket(s)", ""]
    for r in v["people"]:
        lines.append(f"  {r['name']:<20} {r['department']:<11} {r['pc'] + (' (hot desk)' if r['hot'] else ''):<18} "
                     f"{r['where']:<11} {r['status']:<12} {r['doing']}")
    if v["feed"]:
        lines += ["", "latest:"]
        for e in v["feed"][:12]:
            lines.append(f"  {hhmm(e['at'])}  {e['name']:<20} {e['text']}")
    return "\n".join(lines)


def run_cli(args) -> int:
    import getpass
    import sys
    from . import schema
    from .cli import _resolve_lab
    try:
        lab = schema.load(_resolve_lab(args.lab))
    except Exception as exc:  # noqa: BLE001
        print(f"{exc}", file=sys.stderr)
        return 2
    try:
        if args.cmd == "staff":
            if args.what == "list":
                for r in staff_rows(lab):
                    print(f"{r['account']:<14} {r['name']:<20} {r['department']:<11} {r['title']:<20} "
                          f"{r['pc'] + (' (hot)' if r['hot'] else ''):<12} "
                          f"{'password typed' if r['keyed'] else 'no password':<15} {r['status']}")
                return 0
            if not args.account:
                print("winlab staff password <account>", file=sys.stderr)
                return 2
            value = getpass.getpass(f"First password for {args.account} (empty forgets it): ")
            print(type_secret(lab, args.account, value))
            return 0
        if args.what == "start":
            print(start(lab))
        elif args.what == "stop":
            print(stop(lab))
        elif args.what == "level":
            print(set_level(lab, args.arg))
        elif args.what == "shifts":
            print(set_shifts(lab, args.arg.lower() in ("on", "1", "yes", "true")))
        elif args.what == "tick":
            for e in tick(lab):
                print(f"{hhmm(e['at'])}  {e['name']}: {e['text']}")
        print(render(view(lab)))
        return 0
    except WorkdayError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
