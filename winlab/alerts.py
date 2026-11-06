"""On-call alerting: the monitoring that pages the admin.

winlab/oncall.py is a drill: a shift of blind tickets. This is the other
half of being on call: the lab watches itself and, when something breaks,
tells the person whose job it is. It is the monitoring a small company buys
or builds (Nagios, Zabbix, PRTG): checks, a severity, a ticket, a mail, and
at night a phone that rings until someone answers.

What is watched (each source can be turned off):

- the meters and alert rules of the Performance window (winlab/perfmon.py):
  CPU, memory, disk latency, a link down, errors on a cable;
- power (winlab/power.py): a machine that went off without being shut down
  from winlab, a machine that hangs;
- the UPS (winlab/ups.py): mains lost, running on battery;
- disks (winlab/disks.py, winlab/sysdisk.py): a failing data disk, a dead
  system disk, and, read inside the machine, a volume nearly full;
- certificates (labs with a CA, winlab/pki.py): machine certificates that
  expire within two weeks, read inside the machine;
- the clock (winlab/timesync.py): a machine more than five minutes off lab
  time, which is where Kerberos gives up;
- Windows services the machine's roles need (DNS, NTDS, Netlogon, DHCP
  Server, Spooler, W3SVC and the like), read inside the machine.

Reading inside a machine goes over the serial guest agent (the guest runner
the clock uses), one short read-only command per running machine. Nothing
is changed on a machine by watching it.

An alert has a severity (P1 to P4, the helpdesk's priorities), a dedupe key
(source, machine and what), the lab time it opened and the lab time it
cleared. It opens a helpdesk ticket through helpdesk.open_ticket with that
key, so a condition that comes back while its ticket is still open lands on
the same ticket; when the condition clears, the ticket gets a note
("recovered at ...") and stays open: someone still has to say what happened.

How it reaches the admin:

1. Mail. When the lab has a mail server (winlab/mail.py: mail_node) and the
   admin's mailbox exists on it, the alert is delivered as a real mail by
   running the server's own sendmail (Postfix's pickup) on the mail server
   over the guest agent. The student reads it in Thunderbird or Roundcube on
   a lab PC. Nothing is sent by SMTP from this PC: the lab stays sealed.
2. The phone, out of hours. An on-call rota says who is on call, in which
   order, and which hours of the lab clock are out of hours. Out of hours a
   P1 or P2 rings the on-call person's IP phone: winlab drops an Asterisk
   call file into the phone system's spool (winlab/voip.py, the pbx role),
   which calls the extension and plays a pager tone made here, in Python, at
   run time (no recorded sound is bundled). The caller name on the phone's
   screen says what broke. Answering the call acknowledges the alert (the
   spool reports the call Completed). No answer within the rota's minutes of
   lab time: the next person on the rota is called.
3. The desktop: a pager toast in the tray with a sound, and the Alerts
   window: the active alerts, the history, the rota and the sources.

A P1 or P2 helpdesk ticket that comes in out of hours by another way (a
caller, the office's own staff) pages on-call the same way: monitoring keeps
an alert on it ("helpdesk" source) until the ticket closes. Such a ticket's
SLA counts from the first page, not from the call (winlab/helpdesk.py). An
alert marked quiet (wear on its gentle level, at night) never rings the
phone: it waits for the morning report.

Acknowledging (in the window, `winlab alerts ack`, or by answering the
phone) stops the escalation. It does not fix anything: the ticket stays
open until the student resolves it.

The Night shift drill moves the lab clock to 02:00 (labclock.change),
breaks something real on a running machine (a guest fault) and waits: the
pager goes off, the student acknowledges, fixes it, and writes the incident
note on the ticket.

Everything that decides is pure: rule evaluation, dedupe, the rota, the
escalation timing and the text of every command run in a guest are plain
functions over plain data, and the runners are passed in, so the test suite
runs it all without a machine. The state is kept per lab in
var/labs/<lab>/pager.json (perfmon's alerts.json is the meters' own).
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import math
import re
import struct
import threading
import time
import wave
from pathlib import Path
from typing import Callable

from . import paths

Runner = Callable[[str, str, str], tuple[bool, str]]

FILE = "pager.json"
SEVERITY = {"P1": "critical", "P2": "high", "P3": "warning", "P4": "info"}
SOURCES: tuple[tuple[str, str, str], ...] = (
    ("perf", "Meters", "CPU, memory, disk latency, a link down and cable errors: the Performance window's rules"),
    ("power", "Power", "a machine that went off without being shut down from winlab, or hangs"),
    ("ups", "UPS", "mains power lost, the UPS on battery"),
    ("disk", "Disks", "a failing data disk, a dead system disk, a volume nearly full"),
    ("cert", "Certificates", "machine certificates that expire within two weeks (labs with a CA)"),
    ("clock", "Clock", "a machine's clock more than five minutes off lab time"),
    ("service", "Services", "Windows services the machine's roles need: DNS, Netlogon, DHCP Server, Spooler, W3SVC"),
)
SOURCE_IDS = tuple(s[0] for s in SOURCES)
SKEW_LIMIT = 300          # seconds: Kerberos' default tolerance
CERT_DAYS = 14
LOW_FREE_PCT = 10
PROBE_EVERY = 60.0        # real seconds between reads inside the machines (the desktop)
TICK_EVERY = 20.0         # real seconds between the desktop's ticks
ROUNDS = 2                # times round the rota before the phone gives up
MAX_HISTORY = 200
MAX_EVENTS = 80
WAIT_SECONDS = 30         # how long a page rings
CALL_DIR = "/var/spool/asterisk"
SOUND = "/var/lib/winlab/pager"           # Playback adds .wav
SENDER = "monitoring"

# A role's Windows services, the severity when one is down, and the name an
# admin knows it by. Only services that exist on the machine are watched: a
# role still installing is not an outage.
ROLE_SERVICES: tuple[tuple[str, str, str, str], ...] = (
    ("ad-ds", "NTDS", "P1", "Active Directory Domain Services"),
    ("ad-ds", "Netlogon", "P1", "Netlogon"),
    ("ad-ds", "Kdc", "P1", "Kerberos Key Distribution Center"),
    ("ad-ds", "DNS", "P1", "DNS Server"),
    ("ad-ds", "W32Time", "P2", "Windows Time"),
    ("dns", "DNS", "P1", "DNS Server"),
    ("dhcp", "DHCPServer", "P2", "DHCP Server"),
    ("iis", "W3SVC", "P2", "World Wide Web Publishing Service"),
    ("file", "LanmanServer", "P2", "Server (file sharing)"),
    ("dfs", "DFSR", "P2", "DFS Replication"),
    ("printer", "Spooler", "P3", "Print Spooler"),
    ("wsus", "WsusService", "P3", "WSUS Service"),
    ("adcs", "CertSvc", "P2", "Active Directory Certificate Services"),
    ("sql", "MSSQLSERVER", "P2", "SQL Server"),
    ("nps", "IAS", "P2", "Network Policy Server"),
    ("rds", "TermService", "P2", "Remote Desktop Services"),
    ("wds", "WDSServer", "P3", "Windows Deployment Services"),
    ("adfs", "adfssrv", "P2", "AD FS"),
)
# perfmon's rules -> (severity on a server, severity on a PC)
PERF_SEVERITY = {"cpu": ("P3", "P4"), "mem": ("P3", "P4"), "disk": ("P3", "P4"), "link": ("P2", "P3"),
                 "errors": ("P3", "P4"), "stopped": ("P1", "P3")}

_LOCK = threading.RLock()


# ===================================================================== storage
def _path(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    """{"seq", "alerts", "events", "ev", "rota", "sources", "drill", "tests"}."""
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("alerts", [])
    data.setdefault("events", [])
    data.setdefault("ev", 0)
    data.setdefault("rota", {})
    data.setdefault("sources", {})
    data.setdefault("tests", 0)
    data.setdefault("drill", None)
    data.setdefault("silenced", {})   # machine -> lab time its maintenance window ends
    return data


def save(lab_name: str, data: dict) -> None:
    f = _path(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    data["alerts"] = [a for a in data["alerts"] if not a.get("cleared")][-MAX_HISTORY:] + \
        [a for a in data["alerts"] if a.get("cleared")][-MAX_HISTORY:]
    data["alerts"].sort(key=lambda a: a["id"])
    data["events"] = data["events"][-MAX_EVENTS:]
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(f)


def stamp(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def source_on(data: dict, source: str) -> bool:
    return bool(data["sources"].get(source, True))


# ================================================================ the rota
def _hhmm(text: str) -> tuple[int, int]:
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*", str(text))
    if not m or int(m[1]) > 23 or int(m[2]) > 59:
        raise ValueError(f"{text!r}: give a time as HH:MM")
    return int(m[1]), int(m[2])


def escalation_contact(staff: list[dict]) -> dict | None:
    """Who is called when the admin does not answer: the IT manager, else a
    department's manager (people.py marks one per department), else any
    manager. The generated directory's IT is the admin alone, so a student
    who wants a second admin adds one (add_colleague)."""
    for test in (lambda p: p.get("department") == "IT" and p.get("manager"),
                 lambda p: "it manager" in str(p.get("title", "")).lower(),
                 lambda p: p.get("manager") and "manager" in str(p.get("title", "")).lower(),
                 lambda p: p.get("department") == "Operations" and p.get("manager"),
                 lambda p: p.get("manager") and not p.get("admin")):
        hit = next((p for p in staff if test(p)), None)
        if hit:
            return hit
    return None


def default_rota(staff: list[dict]) -> dict:
    """Out of hours 18:00 to 08:00 and all weekend, the admin first, then
    the escalation contact; ten minutes of lab time to answer; the phone
    rings for P1 and P2."""
    order = []
    if staff:
        adm = next((p for p in staff if p.get("admin")), staff[0])
        order.append({"who": adm["id"], "phone": str(adm.get("ext", ""))})
        boss = escalation_contact(staff)
        if boss and boss["id"] != adm["id"]:
            order.append({"who": boss["id"], "phone": str(boss.get("ext", ""))})
    return {"start": "18:00", "end": "08:00", "weekends": True, "ack_minutes": 10,
            "levels": ["P1", "P2"], "order": order}


def rota_of(data: dict, staff: list[dict]) -> dict:
    r = default_rota(staff)
    r.update({k: v for k, v in (data.get("rota") or {}).items() if k in r})
    return r


def out_of_hours(rota: dict, t: float) -> bool:
    """Whether lab time `t` is out of hours: a weekend (when the rota says
    so), or between the end of the day and the start of the next. start
    18:00, end 08:00 is the night; start == end means always."""
    lt = time.localtime(t)
    if rota.get("weekends", True) and lt.tm_wday >= 5:
        return True
    sh, sm = _hhmm(rota.get("start", "18:00"))
    eh, em = _hhmm(rota.get("end", "08:00"))
    now, start, end = lt.tm_hour * 60 + lt.tm_min, sh * 60 + sm, eh * 60 + em
    if start == end:
        return True
    if start > end:
        return now >= start or now < end
    return start <= now < end


def on_call(rota: dict, staff: list[dict]) -> list[dict]:
    """The rota in order, each entry with the person: [{who, phone, person}]."""
    from . import people
    out = []
    for e in rota.get("order") or []:
        p = people.find(staff, e.get("who", ""))
        if p is not None:
            out.append({"who": p["id"], "phone": str(e.get("phone") or p.get("ext", "")), "person": p})
    return out


def set_rota(data: dict, staff: list[dict], **kw) -> dict:
    """Changes the rota: start, end (HH:MM), weekends, ack_minutes, levels
    (P1..P4), order ([{who, phone}] or "id,id"), and phone=(who, extension)."""
    from . import people
    r = rota_of(data, staff)
    for k in ("start", "end"):
        if kw.get(k) is not None:
            h, m = _hhmm(kw[k])
            r[k] = f"{h:02d}:{m:02d}"
    if kw.get("weekends") is not None:
        r["weekends"] = kw["weekends"] in (True, 1, "1", "true", "on", "yes")
    if kw.get("ack_minutes") is not None:
        n = int(kw["ack_minutes"])
        if not 1 <= n <= 240:
            raise ValueError("the time to answer is 1 to 240 minutes")
        r["ack_minutes"] = n
    if kw.get("levels") is not None:
        lv = kw["levels"] if isinstance(kw["levels"], list) else str(kw["levels"]).replace(" ", "").split(",")
        lv = [x.upper() for x in lv if x]
        if any(x not in SEVERITY for x in lv):
            raise ValueError("levels are P1, P2, P3 or P4")
        r["levels"] = sorted(set(lv))
    if kw.get("order") is not None:
        raw = kw["order"]
        if isinstance(raw, str):
            raw = [{"who": w} for w in raw.replace(" ", "").split(",") if w]
        order = []
        old = {e["who"]: e.get("phone", "") for e in r["order"]}
        for e in raw:
            p = people.find(staff, str(e.get("who", "")))
            if p is None:
                raise ValueError(f"nobody called {e.get('who')!r} in the staff directory")
            if any(x["who"] == p["id"] for x in order):
                continue
            phone = str(e.get("phone") or old.get(p["id"]) or p.get("ext", ""))
            order.append({"who": p["id"], "phone": _ext(phone)})
        if not order:
            raise ValueError("the rota needs at least one person")
        r["order"] = order
    if kw.get("phone") is not None:
        who, ext = kw["phone"]
        p = people.find(staff, who)
        hit = next((e for e in r["order"] if p is not None and e["who"] == p["id"]), None)
        if hit is None:
            raise ValueError(f"{who} is not on the rota")
        hit["phone"] = _ext(ext)
    data["rota"] = r
    return r


def _ext(text: str) -> str:
    s = str(text).strip()
    if s and not re.fullmatch(r"[0-9*#]{2,10}", s):
        raise ValueError(f"{text!r}: an extension is 2 to 10 digits")
    return s


def add_colleague(lab, staff: list[dict], name: str, ext: str) -> dict:
    """A second admin in IT, added to the staff directory (people.py) so the
    rota can call them."""
    from . import people
    parts = name.split()
    if len(parts) < 2:
        raise ValueError("give a first and a last name")
    first, last = parts[0], " ".join(parts[1:])
    account = re.sub(r"[^a-z0-9]", "", (first[0] + last).lower())
    base, n = account, 2
    while people.find(staff, account) is not None:
        account, n = f"{base}{n}", n + 1
    p = {"id": account, "first": first, "last": last, "name": f"{first} {last}", "department": "IT",
         "title": "Systems administrator", "account": account,
         "mail": f"{account}@{(lab.domain or 'corp.lab').lower()}", "ext": int(_ext(ext) or 0) or "",
         "pc": "", "manager": False, "admin": False}
    staff.append(p)
    people.save(lab.name, staff)
    return p


# ========================================================== the conditions
def cond(source: str, node: str, what: str, severity: str, title: str, detail: str) -> dict:
    """One thing that is wrong now. Its key is what dedupes it."""
    return {"key": f"{source}:{node}:{what}", "source": source, "node": node, "severity": severity,
            "title": title, "detail": detail}


def _server(node) -> bool:
    return node is not None and (node.kind == "windows-server" or bool(node.roles) and node.kind != "windows-client")


def perf_conditions(lab, perf: dict) -> tuple[list[dict], set]:
    """perfmon's open alerts (its own rules decide) as conditions; the stopped
    rule is power's."""
    out, scopes = [], set()
    for n in lab.node_list():
        scopes.add(("perf", n.id))
    for a in perf.get("history") or []:
        if a.get("ended") or a.get("node") not in lab.nodes:
            continue
        rule = str(a.get("rule", ""))
        srv, pc = PERF_SEVERITY.get(rule, ("P3", "P4"))
        sev = srv if _server(lab.nodes[a["node"]]) else pc
        src = "power" if rule == "stopped" else "perf"
        what = "off" if rule == "stopped" else rule
        title = "Machine went off unexpectedly" if rule == "stopped" else str(a.get("title", rule))
        out.append(cond(src, a["node"], what, sev, title, f"{a.get('text', '')} ({a.get('value', '')})".strip()))
    return out, scopes


def power_conditions(lab, phases: dict[str, tuple[str, bool]], hung: dict) -> tuple[list[dict], set]:
    """phases: {node: (phase, process alive)}. A machine winlab did not stop
    whose process is gone went off by itself; a hung one is frozen."""
    out, scopes = [], set()
    for n in lab.node_list():
        scopes.add(("power", n.id))
        phase, alive = phases.get(n.id, ("", False))
        sev = "P1" if _server(n) else "P3"
        if n.id in hung and alive:
            out.append(cond("power", n.id, "hung", sev, "Machine not responding",
                            "the machine hangs: no screen, no network, no agent; reset it from its management port"))
        elif phase in ("booting", "provisioning", "ready", "installing") and not alive:
            out.append(cond("power", n.id, "off", sev, "Machine went off unexpectedly",
                            "the machine went off without being shut down from winlab (shut down inside, or crashed)"))
    return out, scopes


def ups_conditions(ups: dict) -> tuple[list[dict], set]:
    out, scopes = [], {("ups", "ups")}
    if ups.get("mains", True):
        return out, scopes
    if ups.get("fitted") and not ups.get("dead") and float(ups.get("charge", 0)) > 0:
        pct = round(100 * float(ups.get("charge", 0)))
        sev = "P1" if pct < 30 else "P2"
        out.append(cond("ups", "ups", "battery", sev, "UPS on battery",
                        f"mains power is lost: the UPS runs the lab on its battery, {pct}% left"))
    else:
        out.append(cond("ups", "ups", "mains", "P1", "Mains power lost",
                        "mains power is lost and nothing holds the machines up"))
    return out, scopes


def disk_conditions(lab, failing: dict[str, set[int]], dead: set[str]) -> tuple[list[dict], set]:
    out, scopes = [], set()
    for n in lab.node_list():
        scopes.add(("disk", n.id))
        for i in sorted(failing.get(n.id, ())):
            out.append(cond("disk", n.id, f"bay{i + 1}", "P2", "Disk failing",
                            f"the disk in bay {i + 1} reports errors and answers slowly: replace it before it dies"))
        if n.id in dead:
            out.append(cond("disk", n.id, "system", "P1", "System disk failed",
                            "the system disk is dead: the machine cannot start"))
    return out, scopes


# ------------------------------------------------- reading inside a machine
def watched_services(node) -> list[tuple[str, str, str]]:
    """(service, severity, display name) for the roles this machine has."""
    from . import roles as rl
    have = set(rl.effective_roles(node))
    out, seen = [], set()
    for role, svc, sev, title in ROLE_SERVICES:
        if role in have and svc not in seen:
            seen.add(svc)
            out.append((svc, sev, title))
    return out


def probe_command(node, certs: bool) -> tuple[str, str]:
    """The read-only command that reads one machine: its role services, its
    clock (Unix seconds), its volumes and, with certs, the machine
    certificates' expiry. Windows PowerShell 5.1, or sh on Linux."""
    if node.kind == "linux":
        return ("echo \"time|$(date +%s)\"; df -P -k / 2>/dev/null | "
                "awk 'NR==2 {print \"vol|/|\" $2*1024 \"|\" $4*1024}'"), "sh"
    names = ",".join(f"'{s}'" for s, _sev, _t in watched_services(node))
    parts = ["$o = @()"]
    if names:
        parts.append(f"foreach ($n in @({names})) {{ $s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
                     "if ($s) { $o += \"svc|$n|$($s.Status)|$($s.StartType)\" } else { $o += \"svc|$n|missing|\" } }")
    parts.append("$o += 'time|' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()")
    parts.append("Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | "
                 "ForEach-Object { $o += \"vol|$($_.DeviceID)|$($_.Size)|$($_.FreeSpace)\" }")
    if certs:
        parts.append("Get-ChildItem -Path Cert:\\LocalMachine\\My -ErrorAction SilentlyContinue | ForEach-Object { "
                     "$o += \"cert|$($_.Thumbprint)|$(([DateTimeOffset]$_.NotAfter).ToUnixTimeSeconds())|$($_.Subject)\" }")
    parts.append("$o -join \"`n\"")
    return "; ".join(parts), "powershell"


def parse_probe(text: str) -> dict:
    out: dict = {"services": {}, "time": None, "vols": [], "certs": []}
    for line in (text or "").splitlines():
        f = line.strip().split("|")
        try:
            if f[0] == "svc" and len(f) >= 3:
                out["services"][f[1]] = (f[2], f[3] if len(f) > 3 else "")
            elif f[0] == "time" and len(f) >= 2:
                out["time"] = int(float(f[1]))
            elif f[0] == "vol" and len(f) >= 4 and f[2] and f[3]:
                out["vols"].append((f[1], int(float(f[2])), int(float(f[3]))))
            elif f[0] == "cert" and len(f) >= 3:
                out["certs"].append((f[1], int(float(f[2])), "|".join(f[3:])))
        except (ValueError, IndexError):
            continue
    return out


def probe_conditions(node, got: dict, lab_now: float, certs: bool) -> tuple[list[dict], set]:
    """What one machine's read says is wrong. Only what was read is in
    scope: a machine that did not answer keeps its alerts as they were."""
    nid = node.id
    out, scopes = [], {("service", nid), ("disk-vol", nid)}
    for svc, sev, title in watched_services(node):
        status, start = got["services"].get(svc, ("missing", ""))
        if status not in ("missing", "Running"):
            out.append(cond("service", nid, svc, sev, f"{title} stopped",
                            f"the {svc} service is {status.lower()} (start type {start or 'unknown'})"))
    if got["time"] is not None:
        scopes.add(("clock", nid))
        off = got["time"] - lab_now
        if abs(off) > SKEW_LIMIT:
            out.append(cond("clock", nid, "skew", "P2", "Clock off",
                            f"the machine's clock is {round(abs(off) / 60)} minutes "
                            f"{'ahead of' if off > 0 else 'behind'} lab time: Kerberos fails past 5 minutes"))
    for dev, size, free in got["vols"]:
        if size > 0 and free * 100 / size < LOW_FREE_PCT:
            pct = round(free * 100 / size, 1)
            out.append(cond("disk", nid, f"vol{dev.rstrip(':').replace('/', 'root')}", "P2", "Low disk space",
                            f"{dev} has {pct}% free ({free >> 20} MB of {size >> 30} GB)"))
    if certs:
        scopes.add(("cert", nid))
        for thumb, until, subject in got["certs"]:
            days = (until - lab_now) / 86400
            if days < CERT_DAYS:
                sev = "P2" if days < 0 else "P3"
                what = "expired" if days < 0 else f"expires in {max(0, int(days))} days"
                out.append(cond("cert", nid, thumb[:12], sev, "Certificate expiring" if days >= 0 else "Certificate expired",
                                f"{subject or thumb}: {what} ({stamp(until)})"))
    return out, scopes


# ================================================================ reconcile
def _event(data: dict, kind: str, alert: dict | None, text: str, now: float, real: float | None = None) -> dict:
    data["ev"] += 1
    e = {"n": data["ev"], "at": now, "real": time.time() if real is None else real, "kind": kind,
         "alert": alert["id"] if alert else 0, "severity": alert["severity"] if alert else "",
         "node": alert["node"] if alert else "", "text": text}
    data["events"].append(e)
    return e


def active(data: dict) -> list[dict]:
    return [a for a in data["alerts"] if not a.get("cleared")]


def reconcile(data: dict, conds: list[dict], scopes: set, now: float) -> tuple[list[dict], list[dict]]:
    """Opens an alert for each new condition (one per key), updates the
    ones still true, and clears the ones whose source and machine were
    checked and are fine now. Returns (opened, cleared)."""
    live = {a["key"]: a for a in active(data)}
    seen: set[str] = set()
    opened, cleared = [], []
    for c in conds:
        if c["key"] in seen or not source_on(data, c["source"]):
            continue
        if silenced(data, c["node"], now) and c["key"] not in live:
            continue        # a maintenance window: nothing new opens for that machine
        a = live.get(c["key"])
        if a is not None and a.get("snoozed_until") and a["snoozed_until"] <= now:
            # The snooze ran out with the problem still there: it pages again.
            a.update(acked=0.0, acked_by="", ack_how="", snoozed_until=0.0)
            _event(data, "unsnooze", a, f"{a['title']} on {a['node']}: snooze over, still failing", now)
        seen.add(c["key"])
        a = live.get(c["key"])
        if a is None:
            data["seq"] += 1
            a = {"id": data["seq"], **c, "opened": now, "updated": now, "cleared": 0.0, "acked": 0.0,
                 "acked_by": "", "ack_how": "", "ticket": "", "deliveries": [], "notes": []}
            data["alerts"].append(a)
            opened.append(a)
            _event(data, "open", a, f"{c['severity']} {c['title']} on {c['node']}", now)
        else:
            a["updated"] = now
            a["detail"] = c["detail"]
            if c["severity"] < a["severity"]:      # "P1" < "P2": it got worse
                a["severity"] = c["severity"]
    for a in active(data):
        if a["key"] in seen or a["source"] == "test":
            continue
        scope = (a["source"], a["node"])
        vol = a["source"] == "disk" and a["key"].split(":")[-1].startswith("vol")
        if (vol and ("disk-vol", a["node"]) in scopes) or (not vol and scope in scopes) \
                or not source_on(data, a["source"]):
            a["cleared"] = now
            cleared.append(a)
            _event(data, "clear", a, f"{a['title']} on {a['node']}: recovered", now)
    return opened, cleared


# ========================================================== the escalation
def phone_pages(a: dict) -> list[dict]:
    return [d for d in a.get("deliveries", []) if d["via"] == "phone"]


def next_page(a: dict, rota: dict, now: float) -> int | None:
    """Which rota entry to ring now for this alert, or None: only out of
    hours (the caller decides that), only for the rota's levels, never for
    an acknowledged or cleared alert; the first person at once, the next one
    each time ack_minutes of lab time pass without an answer, round the
    rota ROUNDS times."""
    n = len(rota.get("order") or [])
    if not n or a.get("cleared") or a.get("acked") or a.get("quiet") or a["severity"] not in rota.get("levels", []):
        return None
    pages = phone_pages(a)
    skip = int(a.get("skip") or 0)       # reassigned: start further down the rota
    if not pages:
        return skip % n
    if a.get("page_now"):
        return (len(pages) + skip) % n
    if now - pages[-1]["at"] < 60 * int(rota.get("ack_minutes", 10)):
        return None
    if len(pages) >= n * ROUNDS:
        return None
    return (len(pages) + skip) % n


def silenced(data: dict, node: str, now: float) -> bool:
    return float((data.get("silenced") or {}).get(node) or 0) > now


def _alert(data: dict, alert_id: int) -> dict:
    a = next((x for x in data["alerts"] if x["id"] == int(alert_id)), None)
    if a is None:
        raise ValueError(f"no alert {alert_id}")
    return a


def resolve(lab_name: str, alert_id: int, note: str = "", who: str = "admin", now: float | None = None) -> dict:
    """Resolved by hand, as on a pager: it leaves the active list. If the
    check still fails on the next round, a new alert opens."""
    from . import helpdesk
    with _LOCK:
        data = load(lab_name)
        a = _alert(data, alert_id)
        if a.get("cleared"):
            return a
        t = helpdesk.lab_now(lab_name) if now is None else now
        a.update(cleared=t, resolved_by=who, resolved_note=str(note or "")[:500])
        if not a.get("acked"):
            a.update(acked=t, acked_by=who, ack_how="resolved")
        _event(data, "resolve", a, f"{a['title']} on {a['node']}: resolved by {who}" + (f": {note}" if note else ""), t)
        save(lab_name, data)
    if a.get("ticket"):
        ticket_note(lab_name, a["ticket"], who, f"Alert resolved at {stamp(t)}" + (f": {note}" if note else "."), t)
    return a


def snooze(lab_name: str, alert_id: int, minutes: int, who: str = "admin", now: float | None = None) -> dict:
    """Snoozed for n minutes of lab time: quiet until then; still failing
    after it, it is unacknowledged and pages again."""
    from . import helpdesk
    minutes = int(minutes)
    if not 5 <= minutes <= 24 * 60:
        raise ValueError("snooze for 5 minutes to 24 hours")
    with _LOCK:
        data = load(lab_name)
        a = _alert(data, alert_id)
        if a.get("cleared"):
            raise ValueError(f"#{alert_id} has already cleared")
        t = helpdesk.lab_now(lab_name) if now is None else now
        a.update(acked=t, acked_by=who, ack_how=f"snoozed {minutes} min", snoozed_until=t + 60 * minutes)
        _event(data, "snooze", a, f"{a['title']} on {a['node']}: snoozed {minutes} min by {who}", t)
        save(lab_name, data)
    return a


def reassign(lab, alert_id: int, who: str = "admin", now: float | None = None) -> dict:
    """Hands the alert to the next person on the rota: unacknowledged
    again, and out of hours their phone rings at once."""
    from . import helpdesk, people
    staff = people.load(lab)
    with _LOCK:
        data = load(lab.name)
        a = _alert(data, alert_id)
        if a.get("cleared"):
            raise ValueError(f"#{alert_id} has already cleared")
        entries = on_call(rota_of(data, staff), staff)
        if len(entries) < 2:
            raise ValueError("nobody else is on the rota: add someone on the Rota tab first")
        t = helpdesk.lab_now(lab.name) if now is None else now
        n, pages = len(entries), len(phone_pages(a))
        who_list = [e["who"] for e in entries]
        # Who holds it now: the one it was handed to, else the last one paged
        # (the first on the rota before any page).
        i = who_list.index(a["assigned"]) if a.get("assigned") in who_list \
            else (max(pages - 1, 0) + int(a.get("skip") or 0)) % n
        k = (i + 1) % n
        nxt = entries[k]
        # next_page rings (pages + skip) % n: point it at the new holder.
        a.update(assigned=nxt["who"], acked=0.0, acked_by="", ack_how="", snoozed_until=0.0, page_now=True,
                 skip=(k - pages) % n)
        _event(data, "reassign", a, f"{a['title']} on {a['node']}: reassigned to {nxt['person']['name']} by {who}", t)
        save(lab.name, data)
    if a.get("ticket"):
        ticket_note(lab.name, a["ticket"], who, f"Alert reassigned to {nxt['person']['name']} at {stamp(t)}.", t)
    return {**a, "assigned_name": nxt["person"]["name"]}


def silence(lab, node: str, hours: float, who: str = "admin", now: float | None = None) -> dict:
    """A maintenance window: no new alert opens for the machine for n hours
    of lab time (0 ends it). What is already open stays open."""
    from . import helpdesk
    if node not in lab.nodes:
        raise ValueError(f"no machine {node!r} in {lab.name}")
    hours = float(hours)
    if not 0 <= hours <= 72:
        raise ValueError("silence for up to 72 hours")
    with _LOCK:
        data = load(lab.name)
        t = helpdesk.lab_now(lab.name) if now is None else now
        if hours:
            data["silenced"][node] = t + hours * 3600
            _event(data, "silence", None, f"{node}: maintenance, alerts silenced until {stamp(t + hours * 3600)} by {who}", t)
        else:
            data["silenced"].pop(node, None)
            _event(data, "silence", None, f"{node}: maintenance ended by {who}", t)
        save(lab.name, data)
    return data["silenced"]


def ack(lab_name: str, alert_id: int, who: str = "admin", how: str = "app", now: float | None = None) -> dict:
    """Acknowledged: the escalation stops; the ticket stays open."""
    from . import helpdesk
    with _LOCK:
        data = load(lab_name)
        a = next((x for x in data["alerts"] if x["id"] == int(alert_id)), None)
        if a is None:
            raise ValueError(f"no alert {alert_id}")
        if a.get("acked"):
            return a
        t = helpdesk.lab_now(lab_name) if now is None else now
        a.update(acked=t, acked_by=who, ack_how=how)
        _event(data, "ack", a, f"{a['title']} on {a['node']}: acknowledged by {who} ({how})", t)
        save(lab_name, data)
    if a.get("ticket"):
        ticket_note(lab_name, a["ticket"], who, f"Alert acknowledged ({how}) at {stamp(t)}.", t)
    return a


# =============================================================== the ticket
def ticket_note(lab_name: str, ticket_id: str, who: str, text: str, now: float, kind: str = "") -> bool:
    """A line in a ticket's work log (the helpdesk store's own list)."""
    from . import helpdesk
    with _LOCK:
        q = helpdesk.load(lab_name)
        t = helpdesk.find(q, ticket_id)
        if t is None:
            return False
        entry = {"at": now, "who": who, "text": text}
        if kind:
            entry["kind"] = kind
        t["log"].append(entry)
        helpdesk.save(lab_name, q)
    return True


def _where(lab, node: str) -> str:
    """A machine's name as the student knows it; the UPS and the like as themselves."""
    from . import naming
    if node in lab.nodes:
        return naming.display(lab, node)
    return {"ups": "UPS", "monitoring": "Monitoring"}.get(node, node)


def open_ticket_for(lab, a: dict, now: float, fault: dict | None = None) -> str:
    from . import helpdesk
    name = _where(lab, a["node"])
    # Without a fault of its own (a drill's), the ticket is backed by the
    # alert's own check: resolving it re-runs that probe (alert_check).
    fault = fault or {"kind": "alert", "key": a["key"], "source": a["source"], "node": a["node"]}
    t = helpdesk.open_ticket(lab.name, caller="admin", summary=f"{a['title']} on {name}",
                             body=f"Monitoring: {a['detail']}. Opened {stamp(a['opened'])} (lab time), "
                                  f"severity {a['severity']} ({SEVERITY[a['severity']]}).",
                             priority=a["severity"], source="monitoring", category="monitoring",
                             node=a["node"], fault=fault, dedupe=a["key"], now=now)
    if fault["kind"] != "alert" and (t.get("fault") or {}).get("kind") in (None, "alert"):
        # the key's ticket was already open: the drill's fault backs it from now on
        with _LOCK:
            q = helpdesk.load(lab.name)
            hit = helpdesk.find(q, t["id"])
            if hit is not None:
                hit["fault"] = fault
                helpdesk.save(lab.name, q)
    return t["id"]


def alert_check(lab, fault: dict, runner: Runner | None) -> tuple[bool, str] | None:
    """A monitoring ticket's check: the alert's own source read again
    (inside the machine for services, clock, volumes and certificates).
    None when the machine cannot be read now."""
    from . import helpdesk, pki
    now = helpdesk.lab_now(lab.name)
    data = load(lab.name)
    key, src, node_id = fault.get("key", ""), fault.get("source", ""), fault.get("node", "")
    conds, _ = collect(lab, None, now, data, probe=False)
    if src in ("service", "clock", "disk", "cert") and node_id in lab.nodes:
        if runner is None:
            return None
        cmd, sh = probe_command(lab.nodes[node_id], pki.lab_ca(lab)[0] is not None)
        try:
            ok, out = runner(node_id, cmd, sh)
        except Exception:  # noqa: BLE001 - the machine did not answer
            ok, out = False, ""
        if not ok:
            return None
        conds += probe_conditions(lab.nodes[node_id], parse_probe(out), now, True)[0]
    still = next((c for c in conds if c["key"] == key), None)
    return (still is None, still["detail"] if still else "the check that raised it passes now")


def _register_alert_check() -> None:
    from . import helpdesk
    helpdesk.register_check("alert", alert_check)


def note(lab_name: str, alert_id: int, text: str, who: str = "admin", now: float | None = None) -> str:
    """The incident note: what happened and what was done, on the alert's
    ticket."""
    from . import helpdesk
    text = " ".join(str(text).split())
    if len(text) < 10:
        raise ValueError("write what happened and what you did (a sentence or two)")
    data = load(lab_name)
    a = next((x for x in data["alerts"] if x["id"] == int(alert_id)), None)
    if a is None:
        raise ValueError(f"no alert {alert_id}")
    if not a.get("ticket"):
        raise ValueError("this alert has no ticket")
    t = helpdesk.lab_now(lab_name) if now is None else now
    ticket_note(lab_name, a["ticket"], who, text, t, kind="incident")
    with _LOCK:
        data = load(lab_name)
        a = next(x for x in data["alerts"] if x["id"] == int(alert_id))
        a["notes"].append({"at": t, "text": text})
        save(lab_name, data)
    return a["ticket"]


# ===================================================== delivery: the sound
def pager_wav(rate: int = 8000) -> bytes:
    """The pager tone, made here: three short beeps at 1 kHz and a pause,
    four times (about 5 seconds), 8 kHz 16-bit mono, the format Asterisk
    plays as it is."""
    def tone(freq: int, ms: int) -> bytes:
        n = rate * ms // 1000
        return b"".join(struct.pack("<h", int(9000 * math.sin(2 * math.pi * freq * i / rate))) for i in range(n))
    gap = b"\0\0" * (rate * 70 // 1000)
    beep = tone(1000, 140) + gap
    pcm = ((beep * 3) + b"\0\0" * (rate // 2)) * 4
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    return buf.getvalue()


# ===================================================== delivery: the phone
def pbx_node(lab):
    from .voip import ROLE_PBX
    return next((n for n in lab.node_list() if ROLE_PBX in n.roles), None)


def _clean(text: str, n: int = 40) -> str:
    return re.sub(r"[^A-Za-z0-9 ._:/-]", "", str(text))[:n].strip()


def call_id(a: dict, n: int) -> str:
    return f"monitoring-{'test' if a['source'] == 'test' else 'a'}{a['id']}-{n}"


def call_file(channel: str, caller: str, wait: int = WAIT_SECONDS) -> str:
    """An Asterisk call file: ring `channel`, and when it answers play the
    pager tone three times. Archive keeps it in outgoing_done with the
    outcome (Status: Completed means answered)."""
    return "\n".join([f"Channel: {channel}", f"CallerID: \"{_clean(caller)}\" <999>",
                      f"WaitTime: {int(wait)}", "MaxRetries: 0", "RetryTime: 60",
                      "Application: Playback", f"Data: {SOUND}&{SOUND}&{SOUND}", "Archive: yes", ""])


def call_command(cid: str, ext: str, caller: str, wait: int = WAIT_SECONDS) -> str:
    """The sh run on the phone system: write the pager tone (once), then the
    call file, moved into the spool in one step as Asterisk wants."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", cid):
        raise ValueError("bad call id")
    ext = _ext(ext)
    if not ext:
        raise ValueError("no extension to ring")
    wav = base64.b64encode(gzip.compress(pager_wav(), 9, mtime=0)).decode("ascii")
    cf = base64.b64encode(call_file(f"PJSIP/{ext}", caller, wait).encode()).decode("ascii")
    return ("command -v asterisk >/dev/null 2>&1 || { echo 'no Asterisk on this machine'; exit 3; }; "
            f"[ -d {CALL_DIR}/outgoing ] || {{ echo 'no call spool ({CALL_DIR}/outgoing)'; exit 3; }}; "
            f"mkdir -p {SOUND.rsplit('/', 1)[0]} && chmod 755 {SOUND.rsplit('/', 1)[0]}; "
            f"[ -s {SOUND}.wav ] || {{ printf '%s' '{wav}' | base64 -d | gzip -dc > {SOUND}.wav.tmp && "
            f"mv {SOUND}.wav.tmp {SOUND}.wav; }}; chmod 644 {SOUND}.wav; "
            f"t=$(mktemp {CALL_DIR}/tmp-{cid}.XXXXXX) || exit 1; "
            f"printf '%s' '{cf}' | base64 -d > \"$t\"; chown asterisk:asterisk \"$t\" 2>/dev/null; "
            f"mv \"$t\" {CALL_DIR}/outgoing/{cid}.call && echo queued")


def call_status_command(cid: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", cid):
        raise ValueError("bad call id")
    return (f"f={CALL_DIR}/outgoing_done/{cid}.call; if [ -f $f ]; then sed -n 's/^Status: *//p' $f | tail -n 1; "
            f"elif [ -f {CALL_DIR}/outgoing/{cid}.call ]; then echo Ringing; else echo Gone; fi")


def parse_call_status(text: str) -> str:
    """answered | no answer | failed | ringing | gone"""
    s = ((text or "").strip().splitlines() or [""])[-1].strip().lower()
    return {"completed": "answered", "expired": "no answer", "failed": "failed",
            "ringing": "ringing"}.get(s, "gone" if s == "gone" else "ringing" if not s else s)


# ====================================================== delivery: the mail
def mail_message(lab, a: dict, person: dict, kind: str, now: float) -> bytes:
    from email.message import EmailMessage
    from email.utils import formatdate
    domain = (lab.domain or "corp.lab").lower()
    name = _where(lab, a["node"])
    m = EmailMessage()
    m["From"] = f"Lab monitoring <{SENDER}@{domain}>"
    m["To"] = f"{person.get('name', '')} <{person['mail']}>"
    tag = {"problem": f"{a['severity']} PROBLEM", "recovery": "RECOVERED", "test": "TEST"}[kind]
    m["Subject"] = f"[{tag}] {a['title']} on {name}"
    m["Date"] = formatdate(now, localtime=True)
    m["Message-ID"] = f"<alert-{a['id']}-{kind}-{int(now)}@{SENDER}.{domain}>"
    if kind == "problem" and a["severity"] in ("P1", "P2"):
        m["X-Priority"] = "1"
    lines = [f"{a['title']} on {name}", "",
             f"Severity:  {a['severity']} ({SEVERITY[a['severity']]})",
             f"Machine:   {name}", f"What:      {a['detail']}",
             f"Since:     {stamp(a['opened'])}"]
    if kind == "recovery":
        lines.append(f"Recovered: {stamp(a['cleared'] or now)}")
    if a.get("ticket"):
        lines.append(f"Ticket:    {a['ticket']}")
    lines += ["", "Acknowledge it in the Alerts window, or: winlab alerts ack " + str(a["id"]) if kind == "problem"
              else "The ticket stays open: write what happened on it." if kind == "recovery"
              else "A test page from the lab's monitoring: nothing is wrong.", "", "-- ", "Lab monitoring"]
    m.set_content("\n".join(lines) + "\n")
    return bytes(m)


def mail_command(person: dict, sender: str, message: bytes) -> str:
    """The sh run on the mail server: the mailbox must exist (a local user
    or one Dovecot knows), then the server's own sendmail delivers it."""
    acct = re.sub(r"[^a-z0-9._-]", "", str(person.get("account", "")).lower())
    addr = str(person.get("mail", ""))
    if not acct or not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+", addr) \
            or not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+", sender):
        raise ValueError("no mail address")
    b64 = base64.b64encode(message).decode("ascii")
    return ("[ -x /usr/sbin/sendmail ] || { echo 'no sendmail: the mail server is not built yet'; exit 3; }; "
            f"id -u '{acct}' >/dev/null 2>&1 || doveadm user '{addr}' >/dev/null 2>&1 || "
            f"doveadm user '{acct}' >/dev/null 2>&1 || {{ echo 'no mailbox for {acct}'; exit 4; }}; "
            f"printf '%s' '{b64}' | base64 -d | /usr/sbin/sendmail -i -f '{sender}' '{addr}' && echo sent")


# ============================================================= the tick
def _running(lab_name: str) -> dict[str, tuple[str, bool]]:
    from . import state
    st = state.load(lab_name)
    return {nid: (ns.phase, bool(ns.pid and state.pid_alive(ns.pid))) for nid, ns in (st.nodes.items() if st else [])}


def collect(lab, runner: Runner | None, now: float, data: dict, probe: bool = True,
            phases: dict | None = None) -> tuple[list[dict], set]:
    """Reads every source that is on. Cheap ones from winlab's own records,
    the rest (services, clock, volumes, certificates) inside each running
    machine when `probe`."""
    from . import disks, perfmon, power, sysdisk, ups
    phases = _running(lab.name) if phases is None else phases
    conds, scopes = [], set()

    def take(pair):
        conds.extend(pair[0])
        scopes.update(pair[1])
    if source_on(data, "perf"):
        take(perf_conditions(lab, perfmon.load(lab.name)))
    if source_on(data, "power"):
        take(power_conditions(lab, phases, power.hung(lab.name)))
    if source_on(data, "ups"):
        take(ups_conditions(ups.load(lab.name)))
    if source_on(data, "disk"):
        failing = {n.id: disks.failing_in(disks._dir(lab.name, n.id), len(n.data_disks_gb))
                   for n in lab.node_list() if n.data_disks_gb}
        dead = {n.id for n in lab.node_list() if sysdisk.dead(sysdisk._dir(lab.name, n.id))}
        take(disk_conditions(lab, failing, dead))
    if probe and runner is not None and any(source_on(data, s) for s in ("service", "clock", "disk", "cert")):
        take(probe_all(lab, runner, now, data, phases))
    return conds, scopes


def probe_all(lab, runner: Runner, now: float, data: dict, phases: dict) -> tuple[list[dict], set]:
    from . import labclock, pki
    certs = pki.lab_ca(lab)[0] is not None and source_on(data, "cert")
    running = {n: ph for n, (ph, alive) in phases.items() if alive and n in lab.nodes}
    conds, scopes = [], set()
    t0 = time.time()
    for nid, shell in labclock.apply_order(lab, running):
        if not shell or nid == "fabric" or nid in lab.nodes and running.get(nid) == "installing":
            continue
        node = lab.nodes[nid]
        cmd, sh = probe_command(node, certs)
        try:
            ok, out = runner(nid, cmd, sh)
        except Exception:  # noqa: BLE001 - one machine must not stop the rest
            ok, out = False, ""
        if not ok:
            continue
        got = parse_probe(out)
        c, s = probe_conditions(node, got, now + (time.time() - t0), certs)
        conds += [x for x in c if source_on(data, x["source"])]
        scopes |= s
    return conds, scopes


def ticket_conditions(data: dict, tickets: list[dict], rota: dict) -> tuple[list[dict], set]:
    """Open P1/P2 helpdesk tickets that came in out of hours with no alert
    of their own (a caller, the staff): each pages on-call like monitoring
    would, and its alert stays until the ticket closes. Pure."""
    linked = {a.get("ticket") for a in data["alerts"] if a.get("ticket") and a["source"] != "helpdesk"}
    paging = {a["key"] for a in active(data) if a["source"] == "helpdesk"}
    conds = []
    for t in tickets:
        if t["priority"] not in ("P1", "P2") or t["id"] in linked or t.get("quiet") or t.get("withdrawn"):
            continue
        c = cond("helpdesk", t.get("node") or "helpdesk", t["id"], t["priority"], t["summary"],
                 f"a {t['priority']} ticket ({t['id']}) came in out of hours: {t['summary']}")
        if c["key"] in paging or (t.get("morning") and out_of_hours(rota, float(t["opened"]))):
            conds.append(c)
    return conds, {("helpdesk", a["node"]) for a in active(data) if a["source"] == "helpdesk"}


def tick(lab, runner: Runner | None, now: float | None = None, probe: bool = True,
         phases: dict | None = None, deliver: bool = True) -> dict:
    """One round: read, open and clear alerts and their tickets, mail, ring
    and escalate. Returns what happened: {opened, cleared, sent: [...]}."""
    from . import helpdesk, people
    t = helpdesk.lab_now(lab.name) if now is None else now
    data = load(lab.name)
    conds, scopes = collect(lab, runner, t, data, probe, phases)
    staff = people.load(lab)
    with _LOCK:
        data = load(lab.name)
        tc, ts = ticket_conditions(data, helpdesk.open_tickets(lab.name), rota_of(data, staff))
        opened, cleared = reconcile(data, conds + tc, scopes | ts, t)
        dr = data.get("drill") or {}
        for a in opened:
            if a["source"] == "helpdesk":
                a["ticket"] = a["key"].rsplit(":", 1)[1]    # the ticket it pages for is its own
                continue
            fault = None
            if dr and not dr.get("done") and not dr.get("alert") and a["node"] == dr.get("node") \
                    and a["source"] == dr.get("source"):
                fault, dr["alert"] = dr["fault"], a["id"]
            a["ticket"] = open_ticket_for(lab, a, t, fault)
        jobs = plan_deliveries(lab, data, staff, opened, cleared, t) if deliver else []
        save(lab.name, data)
    for a in cleared:
        if a.get("ticket") and a["source"] != "helpdesk":
            ticket_note(lab.name, a["ticket"], "monitoring", f"Recovered at {stamp(t)} (lab time): {a['title']} cleared.", t)
    phases = _running(lab.name) if phases is None else phases
    sent = run_deliveries(lab, runner, jobs, t, phases) if jobs and runner is not None else []
    if runner is not None and deliver:
        sent += check_calls(lab, runner, t, phases)
    return {"opened": [a["id"] for a in opened], "cleared": [a["id"] for a in cleared], "sent": sent, "at": t}


def plan_deliveries(lab, data: dict, staff: list[dict], opened: list[dict], cleared: list[dict],
                    now: float) -> list[dict]:
    """What to send this round, recorded on the alerts at once (so a slow
    delivery is never repeated): a mail to the admin for every new alert and
    every recovery, and out of hours a call to whoever the rota says."""
    from . import mail as mailmod, people
    rota = rota_of(data, staff)
    adm = people.admin(staff) if staff else None
    if mailmod.mail_node(lab) is None:
        adm = None          # no mail server in this lab: the app (and the phone) only
    jobs = []
    for a in opened:
        if adm:
            jobs.append(_job(a, "mail", adm["id"], now, kind="problem"))
    for a in cleared:
        if adm and any(d["via"] == "mail" for d in a["deliveries"]):
            jobs.append(_job(a, "mail", adm["id"], now, kind="recovery"))
    if out_of_hours(rota, now):
        entries = on_call(rota, staff)
        for a in active(data):
            k = next_page(a, {**rota, "order": entries}, now)
            if k is None:
                continue
            e = entries[k]
            if phone_pages(a):
                _event(data, "escalate", a, f"no answer: calling {e['person']['name']} next", now)
            elif a.get("ticket"):
                from . import helpdesk
                helpdesk.paged(lab.name, a["ticket"], now)   # its SLA counts from this first page
            jobs.append(_job(a, "phone", e["who"], now, phone=e["phone"]))
            if adm and e["who"] != adm["id"] and e["person"].get("mail"):
                jobs.append(_job(a, "mail", e["who"], now, kind="problem"))
    return jobs


def _job(a: dict, via: str, who: str, now: float, **kw) -> dict:
    if via == "phone":
        a.pop("page_now", None)
    d = {"via": via, "to": who, "at": now, "ok": None, "note": "sending…", **kw}
    a["deliveries"].append(d)
    if via == "phone":
        d["call"] = call_id(a, len(phone_pages(a)))
        d["state"] = "calling"
    return {"alert": a["id"], "i": len(a["deliveries"]) - 1, **d}


def run_deliveries(lab, runner: Runner, jobs: list[dict], now: float, phases: dict | None = None) -> list[dict]:
    """Runs the planned deliveries inside the lab and records how each went."""
    from . import mail as mailmod, people
    staff = people.load(lab)
    data = load(lab.name)
    by_id = {a["id"]: a for a in data["alerts"]}
    mnode, pnode = mailmod.mail_node(lab), pbx_node(lab)
    run = _running(lab.name) if phases is None else phases
    results = []
    for j in jobs:
        a = by_id.get(j["alert"])
        p = people.find(staff, j["to"])
        ok, note = False, ""
        if a is None or p is None:
            ok, note = False, "nobody to send it to"
        elif j["via"] == "mail":
            if mnode is None:
                note = "no mail server in this lab: shown in the app only"
            elif not run.get(mnode.id, ("", False))[1]:
                note = f"the mail server {mnode.id} is off"
            else:
                try:
                    msg = mail_message(lab, a, p, j.get("kind", "problem"), now)
                    good, out = runner(mnode.id, mail_command(p, f"{SENDER}@{(lab.domain or 'corp.lab').lower()}", msg), "sh")
                    ok = good and "sent" in (out or "")
                    note = f"delivered to {p['mail']}" if ok else _last(out) or "the mail server did not take it"
                except ValueError as exc:
                    note = str(exc)
        else:
            if pnode is None:
                note = "no phone system in this lab"
            elif not run.get(pnode.id, ("", False))[1]:
                note = f"the phone system {pnode.id} is off"
            elif not j.get("phone"):
                note = f"{p['name']} has no phone on the rota"
            else:
                try:
                    good, out = runner(pnode.id, call_command(j["call"], j["phone"],
                                                              f"{a['severity']} {a['node']} {a['title']}"), "sh")
                    ok = good and "queued" in (out or "")
                    note = f"extension {j['phone']}" if ok else _last(out) or "the phone system did not take it"
                except ValueError as exc:
                    note = str(exc)
        results.append({"alert": j["alert"], "via": j["via"], "to": j["to"], "ok": ok, "note": note})
        with _LOCK:
            fresh = load(lab.name)
            fa = next((x for x in fresh["alerts"] if x["id"] == j["alert"]), None)
            if fa is not None and j["i"] < len(fa["deliveries"]):
                d = fa["deliveries"][j["i"]]
                d.update(ok=ok, note=note)
                if j["via"] == "phone":
                    d["state"] = "ringing" if ok else "failed"
                    _event(fresh, "page", fa, f"{fa['severity']} {fa['title']} on {fa['node']}: {note}", now)
                save(lab.name, fresh)
    return results


def check_calls(lab, runner: Runner, now: float, phases: dict | None = None) -> list[dict]:
    """Asks the phone system how ringing pages went; an answered call
    acknowledges the alert for the person who answered."""
    pnode = pbx_node(lab)
    run = _running(lab.name) if phases is None else phases
    if pnode is None or not run.get(pnode.id, ("", False))[1]:
        return []
    data = load(lab.name)
    out = []
    for a in data["alerts"]:
        for i, d in enumerate(a.get("deliveries", [])):
            if d["via"] != "phone" or d.get("state") != "ringing":
                continue
            ok, text = runner(pnode.id, call_status_command(d["call"]), "sh")
            if not ok:
                continue
            st = parse_call_status(text)
            if st == "ringing":
                continue
            with _LOCK:
                fresh = load(lab.name)
                fa = next(x for x in fresh["alerts"] if x["id"] == a["id"])
                fa["deliveries"][i]["state"] = st
                save(lab.name, fresh)
            out.append({"alert": a["id"], "call": d["call"], "state": st})
            if st == "answered" and a["source"] != "test" and not a.get("cleared"):
                ack(lab.name, a["id"], who=d["to"], how="phone", now=now)
    return out


def _last(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:160] if lines else ""


# ============================================================== test page
def test(lab, runner: Runner, now: float | None = None, phases: dict | None = None) -> list[dict]:
    """A test page through every delivery the lab has: the desktop's toast,
    a mail to the admin when there is a mail server, and the first person on
    the rota's phone when there is a phone system (whatever the hour)."""
    from . import helpdesk, mail as mailmod, people
    t = helpdesk.lab_now(lab.name) if now is None else now
    staff = people.load(lab)
    with _LOCK:
        data = load(lab.name)
        data["tests"] += 1
        data["seq"] += 1
        a = {"id": data["seq"], "key": f"test::{data['tests']}", "source": "test", "node": "monitoring",
             "severity": "P4", "title": "Test page", "detail": "a test of every way the monitoring reaches you",
             "opened": t, "updated": t, "cleared": t, "acked": t, "acked_by": "", "ack_how": "test",
             "ticket": "", "deliveries": [], "notes": []}
        data["alerts"].append(a)
        _event(data, "test", a, "Test page: if you see this, the desktop's pager works", t)
        jobs = []
        adm = people.admin(staff) if staff else None
        if adm and mailmod.mail_node(lab) is not None:
            jobs.append(_job(a, "mail", adm["id"], t, kind="test"))
        entries = on_call(rota_of(data, staff), staff)
        if entries and pbx_node(lab) is not None:
            jobs.append(_job(a, "phone", entries[0]["who"], t, phone=entries[0]["phone"]))
        save(lab.name, data)
    out = [{"via": "app", "ok": True, "note": "a pager toast on the desktop"}]
    out += run_deliveries(lab, runner, jobs, t, phases) if jobs else []
    if not any(r["via"] == "mail" for r in out):
        out.append({"via": "mail", "ok": False, "note": "no mail server in this lab: alerts show in the app"})
    if not any(r["via"] == "phone" for r in out):
        out.append({"via": "phone", "ok": False, "note": "no phone system in this lab (the voice-office lab has one)"})
    return out


# ============================================================ the drill
DRILL_FAULTS = ("service-stopped", "disk-full", "time-skew")
DRILL_SOURCE = {"service-stopped": "service", "disk-full": "disk", "time-skew": "clock"}


def drill_candidates(lab, running: list[str]) -> list[tuple[str, str, dict]]:
    """Faults the monitoring sees, on machines that are running: a role's
    service stopped (best: it is a P1 on a DC), a volume filled, a clock
    pushed off."""
    from . import oncall
    pool = [c for c in oncall.candidates(lab, running) if c[0] in DRILL_FAULTS]
    return sorted(pool, key=lambda c: (DRILL_FAULTS.index(c[0]), "ad-ds" not in lab.nodes[c[1]].roles, c[1]))


def drill_start(lab, runner: Runner, clock_runner: Runner | None = None, running: list[str] | None = None,
                rng=None, emit=lambda _l: None) -> dict:
    """Night shift: the lab clock goes to 02:00, something real breaks, and
    the pager is left to do its job."""
    import random
    from . import guestfaults as gf, labclock, oncall
    data = load(lab.name)
    if data.get("drill") and not data["drill"].get("done"):
        raise RuntimeError("a night shift is already running: end it first")
    running = oncall.running_nodes(lab) if running is None else running
    pool = drill_candidates(lab, running)
    if not pool:
        raise RuntimeError("no running Windows machine can take a night-shift problem: start a server first")
    rng = rng or random.Random()
    best = [c for c in pool if c[0] == pool[0][0]]
    sid, node, params = best[rng.randrange(len(best))]
    emit("moving the lab clock to 02:00 tonight")
    msg = labclock.change(lab, "jump", "tonight", runner=clock_runner, emit=emit)
    cmd, shell = gf.build_command(sid, params, clear=False)
    ok, out = runner(node, cmd, shell)
    if not ok:
        raise RuntimeError(f"{node} did not take the problem: {_last(out) or 'no answer'}")
    t = labclock.load(lab.name).now()
    with _LOCK:
        data = load(lab.name)
        data["drill"] = {"started": t, "fault": {"kind": "guest", "id": sid, "node": node, "params": params},
                         "node": node, "source": DRILL_SOURCE[sid], "alert": 0, "done": False, "fixed": 0.0,
                         "clock": msg, "ooh": out_of_hours(rota_of(data, []), t)}
        save(lab.name, data)
    emit(f"something broke on {node}: wait for the pager")
    return data["drill"]


def drill_view(lab_name: str, data: dict | None = None) -> dict | None:
    from . import helpdesk
    data = data or load(lab_name)
    dr = data.get("drill")
    if not dr:
        return None
    a = next((x for x in data["alerts"] if x["id"] == dr.get("alert")), None)
    steps = {"paged": bool(a), "acked": bool(a and a.get("acked")), "fixed": bool(dr.get("fixed")),
             "recovered": bool(a and a.get("cleared")), "noted": False}
    if a and a.get("ticket"):
        t = helpdesk.find(helpdesk.load(lab_name), a["ticket"])
        steps["noted"] = bool(t and any(e.get("kind") == "incident" for e in t.get("log", [])))
    out = {"started": dr["started"], "node": dr["node"], "done": dr.get("done", False), "steps": steps,
           "alert": dr.get("alert", 0), "ticket": a.get("ticket", "") if a else "",
           "ack_minutes": round((a["acked"] - a["opened"]) / 60, 1) if a and a.get("acked") else None,
           "result": dr.get("result")}
    if dr.get("done"):
        out["was"] = dr["fault"]["id"]
    return out


def drill_check(lab, runner: Runner) -> dict:
    """Is it fixed? Runs the fault's own verify on the machine; the drill is
    over when it is fixed, the alert recovered and the incident note is on
    the ticket."""
    from . import guestfaults as gf, helpdesk
    data = load(lab.name)
    dr = data.get("drill")
    if not dr or dr.get("done"):
        raise RuntimeError("no night shift running")
    f = dr["fault"]
    cmd, shell, expect = gf.verify_command(f["id"], f["params"])
    ok, out = runner(f["node"], cmd, shell)
    fixed = ok and gf.is_fixed(out, expect)
    with _LOCK:
        data = load(lab.name)
        dr = data["drill"]
        if fixed and not dr.get("fixed"):
            dr["fixed"] = helpdesk.lab_now(lab.name)
        save(lab.name, data)
    v = drill_view(lab.name, data)
    if all(v["steps"].values()):
        with _LOCK:
            data = load(lab.name)
            data["drill"]["done"] = True
            data["drill"]["result"] = "passed"
            save(lab.name, data)
        v = drill_view(lab.name)
    return v


def drill_stop(lab, runner: Runner) -> dict:
    """Ends the night shift; a problem still there is undone."""
    from . import guestfaults as gf
    data = load(lab.name)
    dr = data.get("drill")
    if not dr:
        raise RuntimeError("no night shift running")
    if not dr.get("done") and not dr.get("fixed"):
        f = dr["fault"]
        cmd, shell = gf.build_command(f["id"], f["params"], clear=True)
        runner(f["node"], cmd, shell)
    v = drill_view(lab.name, data)
    with _LOCK:
        data = load(lab.name)
        if data["drill"].get("done"):
            data["drill"] = None
        else:
            data["drill"]["done"] = True
            data["drill"]["result"] = data["drill"].get("result") or "ended"
        save(lab.name, data)
    return v


# ================================================================ the view
def view(lab, now: float | None = None) -> dict:
    """What the Alerts window and the tray show."""
    from . import helpdesk, mail as mailmod, people
    t = helpdesk.lab_now(lab.name) if now is None else now
    data = load(lab.name)
    staff = people.load(lab)
    rota = rota_of(data, staff)
    entries = on_call(rota, staff)
    names = {p["id"]: p["name"] for p in staff}
    run = _running(lab.name)

    def row(a):
        return {"id": a["id"], "key": a["key"], "source": a["source"], "node": a["node"],
                "name": _where(lab, a["node"]),
                "severity": a["severity"], "level": SEVERITY[a["severity"]], "title": a["title"],
                "detail": a["detail"], "opened": a["opened"], "cleared": a["cleared"], "acked": a["acked"],
                "acked_by": names.get(a["acked_by"], a["acked_by"]), "ack_how": a["ack_how"], "ticket": a["ticket"],
                "deliveries": [{"via": d["via"], "to": names.get(d["to"], d["to"]), "at": d["at"], "ok": d["ok"],
                                "note": d["note"], "state": d.get("state", "")} for d in a["deliveries"]],
                "notes": a.get("notes", []), "snoozed_until": float(a.get("snoozed_until") or 0),
                "assigned": names.get(a.get("assigned", ""), a.get("assigned", "")),
                "resolved_by": names.get(a.get("resolved_by", ""), a.get("resolved_by", "")),
                "resolved_note": a.get("resolved_note", "")}
    act_ = sorted((row(a) for a in active(data)), key=lambda r: (r["severity"], -r["opened"]))
    hist = [row(a) for a in reversed(data["alerts"]) if a.get("cleared")][:80]
    mnode, pnode = mailmod.mail_node(lab), pbx_node(lab)
    adm = people.admin(staff) if staff else {}
    return {"ok": True, "now": t, "ooh": out_of_hours(rota, t), "active": act_, "history": hist,
            "events": data["events"][-20:], "ev": data["ev"],
            "unacked": sum(1 for r in act_ if not r["acked"]),
            "rota": {**rota, "order": [{"who": e["who"], "phone": e["phone"], "name": e["person"]["name"],
                                        "title": e["person"].get("title", ""),
                                        "department": e["person"].get("department", "")} for e in entries]},
            "oncall": {"who": entries[0]["who"], "name": entries[0]["person"]["name"], "phone": entries[0]["phone"]}
            if entries else None,
            "people": [{"id": p["id"], "name": p["name"], "ext": p.get("ext", ""), "title": p.get("title", ""),
                        "department": p.get("department", "")} for p in staff],
            "sources": [{"id": s, "title": ti, "text": tx, "on": source_on(data, s)} for s, ti, tx in SOURCES],
            "delivery": {"mail": {"node": mnode.id if mnode else "", "running": bool(mnode and run.get(mnode.id, ("", 0))[1]),
                                  "to": adm.get("mail", "")},
                         "phone": {"node": pnode.id if pnode else "", "running": bool(pnode and run.get(pnode.id, ("", 0))[1])}},
            "drill": drill_view(lab.name, data),
            "machines": [{"id": n.id, "name": _where(lab, n.id)} for n in lab.node_list() if n.id != "fabric"],
            "silenced": {k: v for k, v in data["silenced"].items() if float(v) > t}}


def render(v: dict, history: bool = False) -> str:
    lines = [f"lab time {stamp(v['now'])} ({'out of hours' if v['ooh'] else 'office hours'}); "
             f"on call: {v['oncall']['name'] + ' on ' + (v['oncall']['phone'] or 'no phone') if v['oncall'] else 'nobody'}"]
    rows = v["history"] if history else v["active"]
    if not rows:
        lines.append("no alerts in the history" if history else "no active alerts")
    for r in rows:
        state = f"acked by {r['acked_by']} ({r['ack_how']})" if r["acked"] else "NOT ACKNOWLEDGED"
        if history:
            state = f"cleared {stamp(r['cleared'])}"
        lines.append(f"  #{r['id']:<4} {r['severity']} {r['name']:<12} {r['title']}  since {stamp(r['opened'])}  "
                     f"{state}  {r['ticket']}")
        lines.append(f"        {r['detail']}")
    return "\n".join(lines)


def render_rota(v: dict) -> str:
    r = v["rota"]
    lines = [f"out of hours: {r['start']} to {r['end']}{', and all weekend' if r['weekends'] else ''} (lab clock)",
             f"the phone rings for: {', '.join(r['levels']) or 'nothing'}; "
             f"{r['ack_minutes']} minutes to answer, then the next person", "on call, in order:"]
    for i, e in enumerate(r["order"], 1):
        lines.append(f"  {i}. {e['name']} ({e['who']}, {e['title']}) phone {e['phone'] or 'none'}")
    return "\n".join(lines)


# ========================================================== the desktop
def _dash_state(dash) -> dict:
    return dash.__dict__.setdefault("alerts_state", {"lock": threading.Lock(), "last": 0.0, "probe": 0.0,
                                                     "busy": False, "error": ""})


def background(dash, force: bool = False) -> bool:
    """Starts a tick in a thread when one is due (and none is running), so
    the desktop's poll answers at once. Reads inside the machines at most
    every PROBE_EVERY seconds."""
    st = _dash_state(dash)
    lab = dash.lab
    now = time.monotonic()
    with st["lock"]:
        if st["busy"] or (not force and now - st["last"] < TICK_EVERY):
            return False
        st["busy"], st["last"] = True, now
        probe = force or now - st["probe"] >= PROBE_EVERY
        if probe:
            st["probe"] = now
    _keep_meters(dash)

    def go():
        from . import labclock
        try:
            tick(lab, labclock.guest_runner(lab.name, timeout=30), probe=probe)
            st["error"] = ""
        except Exception as exc:  # noqa: BLE001 - the pager keeps going
            st["error"] = str(exc)[:200]
        finally:
            st["busy"] = False
    threading.Thread(target=go, daemon=True).start()
    return True


def _keep_meters(dash) -> None:
    """The meters' sampler (perfmon) runs at its idle pace while the pager
    watches, so its rules fire with the Performance window closed."""
    try:
        from . import perfmon
        mon = perfmon.monitor(dash)
        th = mon._thread
        if th is None or not th.is_alive():
            mon.watch(dash)
            mon._watched = time.monotonic() - perfmon.WATCHED_FOR
    except Exception:  # noqa: BLE001 - the meters are one source of several
        pass


def poll(dash) -> dict:
    """GET /api/alerts."""
    background(dash)
    v = view(dash.lab)
    st = _dash_state(dash)
    v["busy"], v["error"] = st["busy"], st["error"]
    return v


def act(dash, action: str, params: dict) -> dict:
    """The desktop's alerts-* actions."""
    from . import labclock, people
    lab = dash.lab
    run = labclock.guest_runner(lab.name, timeout=30)
    try:
        if action == "alerts-ack":
            a = ack(lab.name, int(params.get("id") or 0), who="admin", how="app")
            return {"ok": True, "message": f"#{a['id']} acknowledged: the escalation stops; fix it, then close "
                                           f"{a['ticket'] or 'the ticket'}"}
        if action == "alerts-resolve":
            a = resolve(lab.name, int(params.get("id") or 0), str(params.get("note") or ""))
            return {"ok": True, "message": f"#{a['id']} resolved" + (f"; {a['ticket']} stays open until you close it"
                                                                      if a.get("ticket") else "")}
        if action == "alerts-snooze":
            a = snooze(lab.name, int(params.get("id") or 0), int(params.get("minutes") or 0))
            return {"ok": True, "message": f"#{a['id']} snoozed until {stamp(a['snoozed_until'])} (lab time)"}
        if action == "alerts-reassign":
            a = reassign(lab, int(params.get("id") or 0))
            return {"ok": True, "message": f"#{a['id']} reassigned to {a['assigned_name']}"}
        if action == "alerts-silence":
            node = str(params.get("node") or "")
            silence(lab, node, float(params.get("hours") or 0))
            h = float(params.get("hours") or 0)
            return {"ok": True, "message": f"{node}: alerts silenced for {h:g} h of lab time" if h
                    else f"{node}: maintenance window ended"}
        if action == "alerts-note":
            tid = note(lab.name, int(params.get("id") or 0), str(params.get("text") or ""))
            return {"ok": True, "message": f"incident note written on {tid}"}
        if action == "alerts-source":
            sid = str(params.get("source") or "")
            if sid not in SOURCE_IDS:
                return {"ok": False, "message": f"no source {sid!r}"}
            with _LOCK:
                data = load(lab.name)
                data["sources"][sid] = params.get("on") in (True, 1, "1", "true")
                save(lab.name, data)
            return {"ok": True, "message": f"{dict((s, t) for s, t, _ in SOURCES)[sid]}: "
                                           f"{'watched' if data['sources'][sid] else 'not watched'}"}
        if action == "alerts-rota":
            staff = people.load(lab)
            raw = params.get("rota") or {}
            if isinstance(raw, str):
                raw = json.loads(raw)
            with _LOCK:
                data = load(lab.name)
                set_rota(data, staff, start=raw.get("start"), end=raw.get("end"), weekends=raw.get("weekends"),
                         ack_minutes=raw.get("ack_minutes"), levels=raw.get("levels"), order=raw.get("order"))
                save(lab.name, data)
            return {"ok": True, "message": "rota saved"}
        if action == "alerts-add-person":
            p = add_colleague(lab, people.load(lab), str(params.get("name") or ""), str(params.get("ext") or ""))
            return {"ok": True, "message": f"{p['name']} joined IT ({p['account']}): put them on the rota", "id": p["id"]}
        if action == "alerts-check":
            background(dash, force=True)
            return {"ok": True, "message": "checking every machine now…"}
        if action == "alerts-test":
            jid = dash.jobs.start("alerts-test", lambda emit: [emit(f"{r['via']}: {r['note']}")
                                                                for r in test(lab, run)])
            return {"ok": True, "job": jid, "message": "sending a test page…"}
        if action == "alerts-drill-start":
            def go(emit):
                drill_start(lab, run, emit=emit)
                background(dash, force=True)
            jid = dash.jobs.start("night-shift", go)
            return {"ok": True, "job": jid, "message": "night shift: the clock goes to 02:00…"}
        if action == "alerts-drill-check":
            v = drill_check(lab, run)
            s = v["steps"]
            left = [k for k in ("paged", "acked", "fixed", "recovered", "noted") if not s[k]]
            return {"ok": True, "message": "night shift done: well handled" if v["done"] else
                    f"still to do: {', '.join(left)}", "drill": v}
        if action == "alerts-drill-stop":
            drill_stop(lab, run)
            return {"ok": True, "message": "night shift ended"}
    except (ValueError, RuntimeError, KeyError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"no such action {action!r}"}


# ================================================================ the CLI
def add_cli(sub) -> None:
    p = sub.add_parser("alerts", help="on-call alerting: the lab's monitoring, its pager, the rota and the night-shift drill")
    p.add_argument("--lab", default="")
    s = p.add_subparsers(dest="alcmd", metavar="<op>")
    ls = s.add_parser("list", help="the active alerts (--history: the cleared ones)")
    ls.add_argument("--history", action="store_true")
    a = s.add_parser("ack", help="acknowledge an alert: the escalation stops, the ticket stays open")
    a.add_argument("id", type=int)
    n = s.add_parser("note", help="write the incident note on an alert's ticket")
    n.add_argument("id", type=int)
    n.add_argument("text", nargs="+")
    s.add_parser("tick", help="check every source now: open and clear alerts, mail, ring, escalate")
    r = s.add_parser("rota", help="who is on call: show, or set hours HH:MM-HH:MM | weekends on|off | ack <min> | "
                                  "levels P1,P2 | order id,id | phone <id> <ext> | add \"First Last\" <ext>")
    r.add_argument("what", nargs="*", default=["show"])
    so = s.add_parser("source", help="turn a source on or off: " + ", ".join(SOURCE_IDS))
    so.add_argument("source", choices=SOURCE_IDS)
    so.add_argument("on", choices=["on", "off"])
    s.add_parser("test", help="send a test page through every delivery this lab has")
    d = s.add_parser("drill", help="the Night shift drill: start | check | stop | status")
    d.add_argument("op", choices=["start", "check", "stop", "status"], nargs="?", default="status")


def run_cli(args) -> int:
    import sys
    from . import labclock, people, schema
    from .cli import _resolve_lab
    from .schema import LabError
    try:
        lab = schema.load(_resolve_lab(args.lab))
    except LabError as exc:
        print(exc, file=sys.stderr)
        return 2
    run = labclock.guest_runner(lab.name, timeout=30)
    op = args.alcmd or "list"
    try:
        if op == "list":
            print(render(view(lab), history=args.history))
        elif op == "ack":
            a = ack(lab.name, args.id, how="cli")
            print(f"#{a['id']} acknowledged: the escalation stops. Fix it, then resolve {a['ticket'] or 'its ticket'}.")
        elif op == "note":
            print(f"incident note written on {note(lab.name, args.id, ' '.join(args.text))}")
        elif op == "tick":
            r = tick(lab, run)
            print(f"opened {len(r['opened'])}, cleared {len(r['cleared'])}")
            for x in r["sent"]:
                print(f"  #{x['alert']} {x.get('via', 'call')}: {x.get('note') or x.get('state')}")
            print(render(view(lab)))
        elif op == "test":
            for x in test(lab, run):
                print(f"  {x['via']:<6} {'ok  ' if x['ok'] else 'no  '} {x['note']}")
        elif op == "source":
            with _LOCK:
                data = load(lab.name)
                data["sources"][args.source] = args.on == "on"
                save(lab.name, data)
            print(f"{args.source}: {'watched' if args.on == 'on' else 'not watched'}")
        elif op == "rota":
            w = list(args.what)
            if w and w[0] == "set":
                w = w[1:]
            if w and w[0] != "show":
                staff = people.load(lab)
                k, rest = w[0], w[1:]
                if k == "add":
                    if len(rest) < 2:
                        raise ValueError("rota add \"First Last\" <extension>")
                    p = add_colleague(lab, staff, " ".join(rest[:-1]), rest[-1])
                    print(f"{p['name']} ({p['id']}) joined IT")
                    staff = people.load(lab)
                    with _LOCK:
                        data = load(lab.name)
                        cur = rota_of(data, staff)["order"]
                        set_rota(data, staff, order=cur + [{"who": p["id"], "phone": rest[-1]}])
                        save(lab.name, data)
                else:
                    kw = {}
                    if k == "hours" and rest and "-" in rest[0]:
                        kw["start"], kw["end"] = rest[0].split("-", 1)
                    elif k == "weekends" and rest:
                        kw["weekends"] = rest[0]
                    elif k == "ack" and rest:
                        kw["ack_minutes"] = rest[0]
                    elif k == "levels" and rest:
                        kw["levels"] = rest[0]
                    elif k == "order" and rest:
                        kw["order"] = ",".join(rest)
                    elif k == "phone" and len(rest) == 2:
                        kw["phone"] = (rest[0], rest[1])
                    else:
                        raise ValueError("rota set hours 18:00-08:00 | weekends on|off | ack 10 | levels P1,P2 | "
                                         "order admin,<id> | phone <id> <extension> | add \"First Last\" <extension>")
                    with _LOCK:
                        data = load(lab.name)
                        set_rota(data, staff, **kw)
                        save(lab.name, data)
            print(render_rota(view(lab)))
        elif op == "drill":
            if args.op == "start":
                dr = drill_start(lab, run, emit=print)
                tick(lab, run)
                print(f"night shift on {dr['node']}: the pager goes off when the monitoring sees it "
                      f"(winlab alerts list). Acknowledge, fix, then write the incident note.")
            elif args.op == "check":
                v = drill_check(lab, run)
                print(" ".join(f"[{'x' if ok else ' '}] {k}" for k, ok in v["steps"].items()))
                print("night shift done: well handled" if v["done"] else "not done yet")
            elif args.op == "stop":
                drill_stop(lab, run)
                print("night shift ended")
            else:
                v = drill_view(lab.name)
                print("no night shift running: winlab alerts drill start" if not v else
                      " ".join(f"[{'x' if ok else ' '}] {k}" for k, ok in v["steps"].items()))
    except (ValueError, RuntimeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


_register_alert_check()
