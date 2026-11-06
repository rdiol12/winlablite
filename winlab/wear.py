"""Wear: servers that wear out on their own, on the lab clock.

A real server room is never still. Volumes fill, logs grow, a certificate
reaches its date, last night's backup did not fit on the NAS, a domain
controller's clock wanders off, a service crashes after the night's patching
and stays down, the print queue jams, a data disk starts throwing errors, and
the evaluation licence counts down to the day the machine shuts itself down
every hour. Nobody does any of it; it happens.

This module is that, for a lab left running for days or weeks (the company
run, winlab/company.py). On the lab clock (winlab/labclock.py) it picks the
next thing to wear out at a rate set by the wear level, and breaks it for
real inside the machine:

- off: nothing wears (the default: lessons and drills stay exactly as set);
- gentle: about one thing every three lab days, and it never pages at
  night: what wears out out of hours waits for the morning report;
- realistic: about one thing a lab day;
- harsh: two or three a day, more open at once.

What breaks comes from the catalogues winlab already has: a volume filled
(guestfaults disk-full, linux-disk-full), the web server's certificate
expired (https-cert-expired), the backup NAS full (wsbackup nas-backups-full),
a DC off the time hierarchy and drifting (timesync member-clock-nosync and
pdc-source-unreachable, plus a clock that keeps wandering while it stays
broken), the print queue paused (print-queue-stuck), a failing data disk
(winlab/disks.py), and two that only time makes, in winlab/wearfaults.py: a
service that crashed after the updates with no recovery options, and IIS logs
nobody ever deleted. The evaluation licence is not broken by winlab at all:
it is read every morning (as winlab/evaluation.py reads it) and reported
when it really runs low.

Only what the student has built can wear out. Before anything breaks, a
read-only command asks the machine whether the thing is there: a role
feature installed, the service running, an HTTPS binding, a shared printer,
backups on the NAS, a data disk with a volume on it. A server nobody built
has nothing to wear. A machine that is off wears nothing either.

When something wears out it shows the way a real event does: monitoring
raises an alert (winlab/alerts.py: mail to the admin, the phone out of hours)
under the key its own probe would use, so the two never double up, and the
alert opens a helpdesk ticket (winlab/helpdesk.py); what users notice first
(a jammed printer, a browser warning) comes in as a call from the person it
hurts. The ticket is backed by the wear event: resolving it runs the fault's
own verify on the machine.

Each lab has its own seed, so two runs of the same lab wear the same way
until the student's own actions make them differ. Everything is recorded in
var/labs/<lab>/wear.json: the level, the seed, the next event, and every
event with its time, machine, ticket and alert, and when it was fixed.

The deciding parts (the schedule, which kind fits which machine, the
commands, the alert, the record) are plain functions over plain data with the
runner passed in, so the suite runs them without a machine.
"""

from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import labclock, paths

Runner = Callable[[str, str, str], tuple[bool, str]]

FILE = "wear.json"
# level -> (mean lab days between two events, most wear events open at once, what it is like)
LEVELS: dict[str, tuple[float, int, str]] = {
    "off": (0.0, 0, "nothing wears out: lessons and drills stay as they were set"),
    "gentle": (3.0, 2, "about one thing every three lab days, and nothing pages at night: it waits for the morning"),
    "realistic": (1.0, 4, "about one thing a lab day, like a small company's server room"),
    "harsh": (0.4, 7, "two or three things a day and more open at once: an old building and no budget"),
}
DEFAULT_LEVEL = "off"
CATCH_UP = 3              # most events one tick fires when the clock jumped far ahead
CHECK_EVERY = 15 * 60     # lab seconds between checks of the open events
LICENCE_HOUR = 6          # the licence is read once a lab day, from 06:00
LICENCE_WARN = 14         # days left at which it is reported (evaluation.WARN_DAYS)
DRIFT_START = 6 * 60      # a drifting clock starts this far off (past Kerberos' five minutes)
DRIFT_PER_DAY = 3 * 60    # and wanders this much further each lab day it stays broken
DRIFT_MAX = 30 * 60
MAX_EVENTS = 400
NIGHT = (1, 5)            # night events land between 01:00 and 05:00
EVENING = (19, 21)        # the backup target fills before the 21:00 backup
DAY = (9, 16)             # what users notice happens in office hours

_lock = threading.RLock()


@dataclass(frozen=True)
class Kind:
    """One way something wears out."""
    id: str
    title: str             # what the journal calls it
    fault: str             # the guest fault it breaks with ("" for a disk or the licence)
    os: str                # "windows" | "linux"
    when: str              # "night" | "evening" | "day" | "any"
    weight: int
    notice: str            # "monitoring" (an alert) or "user" (someone rings)
    severity: str
    roles: tuple[str, ...] = ()   # the machine must carry one of these; () = any server
    param: str = ""        # the fault parameter the present check's answer fills
    alert: str = ""        # the alert key, as monitoring's own probe names it
    alert_title: str = ""
    detail: str = ""       # what monitoring says, or what the caller says
    department: str = ""   # who rings, for a user-noticed one
    summary: str = ""      # the ticket's subject for a user-noticed one


WIN_SERVER_BUILT = ("$f = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed -and "
                    "$_.FeatureType -eq 'Role' }); if ($f.Count) { 'yes|' + $f[0].Name } else { 'no|' }")

KINDS: dict[str, Kind] = {k.id: k for k in (
    Kind("disk-filling", "A volume filled up", "disk-full", "windows", "any", 3, "monitoring", "P2",
         alert="disk:{node}:volC", alert_title="Low disk space",
         detail="C: has under 10% free and is still filling"),
    Kind("logs-grew", "The web server's logs ate the disk", "iis-logs-grew", "windows", "any", 2, "monitoring",
         "P2", roles=("iis",), alert="disk:{node}:volC", alert_title="Low disk space",
         detail="C: has about 5% free: something on it grew"),
    Kind("service-crash", "A service crashed after the night's updates", "service-crashed-after-update",
         "windows", "night", 3, "monitoring", "P2", param="service", alert="service:{node}:{service}",
         alert_title="{service_title} stopped",
         detail="the {service} service terminated unexpectedly after the night's updates and is not running"),
    Kind("cert-expired", "The web certificate expired", "https-cert-expired", "windows", "day", 2, "user", "P2",
         roles=("iis",), department="Sales", summary="Security warning on the intranet site",
         detail="Since this morning every browser shows a big red warning when I open our site on {node}. "
                "Customers on the phone say the same."),
    Kind("backup-failed", "The backup target filled up", "nas-backups-full", "linux", "evening", 2,
         "monitoring", "P3", roles=("nas",), alert="wear:{node}:backup", alert_title="Backup target almost full",
         detail="the Backups share on the NAS has under 200 MB free: tonight's server backup will not fit"),
    Kind("dc-drift", "A domain controller's clock drifted", "", "windows", "any", 2, "monitoring", "P2",
         roles=("ad-ds",), alert="clock:{node}:skew", alert_title="Clock off",
         detail="the domain controller's clock is more than five minutes off lab time and drifting"),
    Kind("printer-jam", "The print queue jammed", "print-queue-stuck", "windows", "day", 2, "user", "P3",
         roles=("printer",), param="printer", department="Front desk", summary="Nothing comes out of the printer",
         detail="I sent the visitor badges to {printer} twenty minutes ago and nothing has come out. "
                "The others at the front desk say the same."),
    Kind("linux-disk-filling", "A Linux volume filled up", "linux-disk-full", "linux", "any", 2, "monitoring",
         "P2", alert="disk:{node}:volroot", alert_title="Low disk space",
         detail="/ has under 10% free and is still filling"),
    Kind("disk-failing", "A data disk started failing", "", "windows", "any", 1, "monitoring", "P2",
         alert="disk:{node}:bay{bay}", alert_title="Disk failing",
         detail="the disk in bay {bay} reports errors and answers slowly: replace it before it dies"),
    Kind("licence", "The evaluation licence is running out", "", "windows", "any", 0, "monitoring", "P3",
         alert="wear:{node}:licence", alert_title="Windows licence running out",
         detail="the Windows evaluation has {days} days left ({rearms} rearms left): after that it shuts "
                "itself down every hour"),
)}
RANDOM_KINDS = tuple(k for k, v in KINDS.items() if v.weight > 0)

# The services a crash may hit: a role's service the alerts already watch,
# never the directory's core (a dead NTDS is another story).
CRASH_SERVICES = ("DNS", "DHCPServer", "W3SVC", "Spooler", "WsusService", "MSSQLSERVER", "IAS", "CertSvc",
                  "DFSR", "LanmanServer", "TermService")
_NTDS_RUNNING = "if ((Get-Service -Name NTDS -ErrorAction SilentlyContinue).Status -eq 'Running') { 'yes|' } else { 'no|' }"
_W32_TYPE = "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters').Type"


# ------------------------------------------------------------------ storage
def wear_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def lab_seed(lab_name: str) -> int:
    """The lab's own seed: the same lab wears the same way."""
    import zlib
    return zlib.crc32(f"winlab-wear:{lab_name}".encode("utf-8"))


def fresh(lab_name: str) -> dict:
    return {"level": DEFAULT_LEVEL, "seed": lab_seed(lab_name), "n": 0, "next": None, "events": [],
            "last_check": 0.0, "licence_day": "", "readings": {}, "seq": 0}


def load(lab_name: str) -> dict:
    out = fresh(lab_name)
    try:
        raw = json.loads(wear_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            out.update({k: v for k, v in raw.items() if k in out})
    except (OSError, ValueError):
        pass
    if out["level"] not in LEVELS:
        out["level"] = DEFAULT_LEVEL
    return out


def save(lab_name: str, st: dict) -> None:
    f = wear_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    st["events"] = st["events"][-MAX_EVENTS:]
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=1), encoding="utf-8")
    tmp.replace(f)


def open_events(st: dict) -> list[dict]:
    return [e for e in st["events"] if e["state"] == "open"]


def find(st: dict, event_id: str) -> dict | None:
    return next((e for e in st["events"] if e["id"] == event_id), None)


# ------------------------------------------------------------------ the schedule
def rng_for(st: dict, salt: str = "") -> random.Random:
    """The n-th draw of this lab's wear: seeded, so it repeats."""
    return random.Random(f"{st['seed']}:{st['n']}:{salt}")


def _window(at: float, span: tuple[int, int], rng: random.Random) -> float:
    """The first moment in the hours `span` on or after `at`, with minutes drawn."""
    lt = time.localtime(at)
    for add in range(0, 3):
        start = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + add, span[0], 0, 0, 0, 0, -1))
        end = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + add, span[1], 0, 0, 0, 0, -1))
        if end <= at:
            continue
        lo = max(start, at)
        return lo + rng.random() * (end - lo)
    return at


def place(at: float, when: str, rng: random.Random) -> float:
    """When a kind of wear happens: the night, the evening, office hours, or any time."""
    if when == "night":
        return _window(at, NIGHT, rng)
    if when == "evening":
        return _window(at, EVENING, rng)
    if when == "day":
        t = _window(at, DAY, rng)
        for _ in range(3):                           # nobody prints badges on a Sunday
            lt = time.localtime(t)
            if lt.tm_wday < 5:
                break
            t = _window(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + 1, 0, 0, 0, 0, 0, -1)), DAY, rng)
        return t
    return at


def schedule(st: dict, after: float) -> dict | None:
    """The next event: a kind drawn by weight, at a gap drawn from the level's
    mean, placed in that kind's hours. None when wear is off."""
    mean_days = LEVELS[st["level"]][0]
    if not mean_days:
        return None
    rng = rng_for(st, "next")
    kind = rng.choices(RANDOM_KINDS, weights=[KINDS[k].weight for k in RANDOM_KINDS])[0]
    gap = rng.expovariate(1.0 / (mean_days * 86400))
    gap = min(max(gap, 2 * 3600), mean_days * 86400 * 4)
    return {"at": place(after + gap, KINDS[kind].when, rng), "kind": kind}


def set_level(lab_name: str, level: str, now: float | None = None) -> dict:
    """Wear on, off or harder. Turning it on schedules the first event; off
    keeps what is already broken (it is the student's to fix)."""
    if level not in LEVELS:
        raise ValueError(f"wear level must be one of {', '.join(LEVELS)}")
    at = labclock.load(lab_name).now() if now is None else now
    with _lock:
        st = load(lab_name)
        st["level"] = level
        st["next"] = schedule(st, at)
        if not st["last_check"]:
            st["last_check"] = at
        save(lab_name, st)
    return st


def set_seed(lab_name: str, seed: int) -> dict:
    with _lock:
        st = load(lab_name)
        st["seed"] = int(seed)
        save(lab_name, st)
    return st


# ------------------------------------------------------------------ what fits which machine
def _is_server(node) -> bool:
    return node is not None and node.kind != "windows-client" and (node.kind == "windows-server" or bool(node.roles))


def _forest_root(lab):
    from . import timesync
    return timesync.first_dc(lab)


def fits(kind: Kind, lab, node, have: list[str]) -> bool:
    """Whether a kind can happen to this machine at all, from the lab alone
    (the machine is then asked whether the thing is really built)."""
    if not _is_server(node):
        return False
    os = "linux" if node.kind == "linux" else "windows"
    if kind.os != os:
        return False
    if kind.roles and not any(r in have for r in kind.roles):
        return False
    if kind.id == "disk-failing":
        return bool(getattr(node, "data_disks_gb", None))
    if kind.id == "linux-disk-filling":
        return bool(node.roles) and node.image in ("alpine", "ubuntu")
    if kind.id == "backup-failed":
        from . import omv
        return node.image == omv.IMAGE
    if kind.id == "dc-drift":
        root = _forest_root(lab)
        if root is not None and root.id == node.id:
            from . import timesync
            return timesync.ntp_device(lab) is not None    # the PDC drifts only with a source to fix it with
    if kind.id == "service-crash":
        return bool(crash_services(node))
    return True


def crash_services(node) -> list[str]:
    from . import alerts
    return [s for s, _sev, _t in alerts.watched_services(node) if s in CRASH_SERVICES]


def fault_for(kind: Kind, lab, node) -> str:
    """The guest fault a kind breaks with on this machine."""
    if kind.id == "dc-drift":
        root = _forest_root(lab)
        return "pdc-source-unreachable" if root is not None and root.id == node.id else "member-clock-nosync"
    return kind.fault


def present_command(kind: Kind, lab, node) -> tuple[str, str]:
    """The read-only question 'is the thing built here?'. It answers
    yes|<value> or no|; the value fills the fault's parameter (the printer's
    name, the services that run)."""
    if kind.id in ("disk-filling",):
        return WIN_SERVER_BUILT, "powershell"
    if kind.id == "logs-grew":
        return ("$s = Get-Service -Name W3SVC -ErrorAction SilentlyContinue; "
                "$c = Get-PSDrive -Name C; if ($s -and $s.Status -eq 'Running' -and (Test-Path -Path 'C:\\inetpub') -and "
                "($c.Free / ($c.Used + $c.Free)) -gt 0.2) { 'yes|' } else { 'no|' }"), "powershell"
    if kind.id == "service-crash":
        names = ",".join(f"'{s}'" for s in crash_services(node))
        return (f"$r = @(foreach ($n in @({names})) {{ $s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
                "if ($s -and $s.Status -eq 'Running' -and [string]$s.StartType -eq 'Automatic') { $n } }); "
                "if ($r.Count) { 'yes|' + ($r -join ',') } else { 'no|' }"), "powershell"
    if kind.id == "cert-expired":
        return ("Import-Module WebAdministration -ErrorAction SilentlyContinue; "
                "if (Test-Path -Path 'IIS:\\SslBindings\\0.0.0.0!443') { 'yes|' } else { 'no|' }"), "powershell"
    if kind.id == "backup-failed":
        from . import wsbackup
        return (f"d={wsbackup.SHARE_DIR}; if [ -n \"$d\" ] && ls -d \"$d\"/WindowsImageBackup/*/Backup* "
                ">/dev/null 2>&1; then echo 'yes|'; else echo 'no|'; fi"), "sh"
    if kind.id == "dc-drift":
        if fault_for(kind, lab, node) == "pdc-source-unreachable":
            return (f"if ((Get-Service -Name NTDS -ErrorAction SilentlyContinue).Status -eq 'Running' -and "
                    f"{_W32_TYPE} -eq 'NTP') {{ 'yes|' }} else {{ 'no|' }}"), "powershell"
        return _NTDS_RUNNING, "powershell"
    if kind.id == "printer-jam":
        return ("$p = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared } | Select-Object -First 1; "
                "if ($p) { 'yes|' + $p.Name } else { 'no|' }"), "powershell"
    if kind.id == "linux-disk-filling":
        return "if [ -d /var/log ]; then echo 'yes|'; else echo 'no|'; fi", "sh"
    if kind.id == "disk-failing":
        return ("$d = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { -not $_.IsBoot -and -not $_.IsSystem "
                "-and [string]$_.PartitionStyle -ne 'RAW' }); if ($d.Count) { 'yes|' + $d.Count } else { 'no|' }"), "powershell"
    return "'yes|'", "powershell"


def parse_present(out: str) -> tuple[bool, list[str]]:
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    last = lines[-1] if lines else ""
    yes, _, rest = last.partition("|")
    return yes == "yes", [v for v in rest.split(",") if v]


def candidates(lab, running: list[str], st: dict, prefer: str = "") -> list[tuple[Kind, object]]:
    """(kind, machine) for every kind of wear that fits a running machine
    and is not already open on it; the preferred kind first."""
    from . import roles
    busy = {(e["kind"], e["node"]) for e in open_events(st)}
    out = []
    for nid in running:
        node = lab.nodes.get(nid)
        if node is None:
            continue
        have = roles.effective_roles(node)
        for kid in RANDOM_KINDS:
            k = KINDS[kid]
            if (kid, nid) not in busy and fits(k, lab, node, have):
                out.append((k, node))
    out.sort(key=lambda kn: (kn[0].id != prefer, kn[0].id, kn[1].id))
    return out


# ------------------------------------------------------------------ an event
def _params(lab, node, kind: Kind, value: list[str], rng: random.Random) -> dict:
    from . import guestfaults as gf, naming
    p = dict(gf.lab_params(lab))
    p["node"] = naming.hostname_of(node)
    if kind.param and value:
        p[kind.param] = rng.choice(value)
    return p


def fault_commands(fid: str, params: dict) -> dict:
    """apply/clear/verify of a guest fault with its parameters filled."""
    from . import guestfaults as gf
    f = gf.SCENARIOS[fid]
    return {"apply": gf._fill(f.apply, params), "clear": gf._fill(f.clear, params),
            "verify": gf._fill(f.verify, params), "shell": f.shell, "expect": f.expect}


def _fresh_params(lab, params: dict) -> dict:
    """A fault's parameters as they are now: its verify compares with lab time."""
    p = dict(params)
    p["labtime"] = str(int(labclock.load(lab.name).now()))
    return p


def _fill(text: str, values: dict) -> str:
    for k, v in values.items():
        text = text.replace("{" + k + "}", str(v))
    return text


def drift_for(e: dict, now: float) -> float:
    """How far a drifting clock is off now: it starts past five minutes and
    wanders further every day nobody fixes it."""
    days = max(0.0, (now - float(e["at"])) / 86400)
    return min(DRIFT_MAX, DRIFT_START + DRIFT_PER_DAY * days)


def _drift(lab, e: dict, now: float, runner: Runner) -> None:
    from . import timesync
    off = drift_for(e, now)
    runner(e["node"], timesync.skew_command("powershell", now + off), "powershell")
    e["drift"] = off


def _record(st: dict, **kw) -> dict:
    st["seq"] = int(st.get("seq") or 0) + 1
    e = {"id": f"W{st['seq']:04d}", "state": "open", "fixed": 0.0, "ticket": "", "alert": 0, **kw}
    st["events"].append(e)
    return e


def fire(lab, st: dict, kind_pref: str, at: float, runner: Runner, running: list[str],
         rng: random.Random) -> dict | None:
    """Something wears out at `at`: the preferred kind if a running machine
    has it built, otherwise another. Returns the event, or None when nothing
    built can wear right now."""
    from . import disks
    pool = candidates(lab, running, st, kind_pref)
    pref = [c for c in pool if c[0].id == kind_pref]
    rest = [c for c in pool if c[0].id != kind_pref]
    rng.shuffle(pref)
    rng.shuffle(rest)
    for kind, node in (pref + rest)[:8]:
        cmd, shell = present_command(kind, lab, node)
        try:
            ok, out = runner(node.id, cmd, shell)
        except Exception:  # noqa: BLE001 - a machine that cannot answer has nothing to wear
            ok, out = False, ""
        built, value = parse_present(out) if ok else (False, [])
        if not built:
            continue
        if kind.id == "disk-failing":
            bad = disks.failing_in(disks._dir(lab.name, node.id), len(node.data_disks_gb))
            free = [i for i in range(len(node.data_disks_gb)) if i not in bad]
            if not free:
                continue
            bay = free[0]
            try:
                disks.fail(lab.name, node, bay)
            except Exception:  # noqa: BLE001 - the disk would not fail: another kind instead
                continue
            return _record(st, kind=kind.id, node=node.id, at=at, fault="", params={"bay": str(bay + 1)},
                           index=bay)
        fid = fault_for(kind, lab, node)
        params = _params(lab, node, kind, value, rng)
        extra = {}
        if kind.id == "service-crash":
            from . import alerts
            sev, title = next(((sv, tt) for s, sv, tt in alerts.watched_services(node) if s == params.get("service")),
                              (kind.severity, params.get("service", "")))
            params["service_title"], extra["severity"] = title, sev
        cmds = fault_commands(fid, params)
        try:
            ok, _ = runner(node.id, cmds["apply"], cmds["shell"])
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            continue
        e = _record(st, kind=kind.id, node=node.id, at=at, fault=fid, params=params, **extra)
        if kind.id == "dc-drift":
            _drift(lab, e, at, runner)
        return e
    return None


def alert_of(kind: Kind, e: dict) -> dict:
    """The alert condition a wear event raises, keyed the way the monitoring's
    own probe keys it."""
    from . import alerts
    values = {**{k: str(v) for k, v in (e.get("params") or {}).items()}, "node": e["node"]}
    key = _fill(kind.alert or "wear:{node}:" + kind.id, values)
    source, _, rest = key.partition(":")
    _node, _, what = rest.partition(":")
    return {**alerts.cond(source, e["node"], what, e.get("severity") or kind.severity,
                          _fill(kind.alert_title or kind.title, values), _fill(kind.detail, values)), "key": key}


def announce(lab, e: dict, now: float, runner: Runner | None, rng: random.Random) -> None:
    """The event shows: an alert and its ticket, or a call from the person it hurts."""
    from . import alerts, helpdesk, people
    kind = KINDS[e["kind"]]
    fault = {"kind": "wear", "id": e["id"], "node": e["node"], "params": {}, "by": "wear"}
    staff = people.load(lab)
    # Gentle wear never pages at night: it is left for the morning report.
    quiet = load(lab.name)["level"] == "gentle" and alerts.out_of_hours(
        alerts.rota_of(alerts.load(lab.name), staff), now)
    why = "Gentle wear pages nobody at night: left for the morning report, its SLA starts at opening."
    if kind.notice == "user":
        values = {"node": alerts._where(lab, e["node"]), **(e.get("params") or {})}
        spec = {"fault": {**fault, "params": dict(e.get("params") or {})}, "source": "phone", "caller": "",
                "department": kind.department, "text": _fill(kind.detail, values)}
        spec = helpdesk.pick_caller(spec, staff, rng)
        t = helpdesk.open_ticket(lab.name, caller=spec["caller"], summary=_fill(kind.summary, values),
                                 body=spec["body"], priority=kind.severity, source="phone",
                                 category="Wear", node=e["node"], fault=fault,
                                 dedupe=f"wear:{e['node']}:{kind.id}", now=now)
        e["ticket"] = t["id"]
        if quiet:
            helpdesk.hold_for_morning(lab.name, t["id"], now, why)
        return
    c = alert_of(kind, e)
    jobs: list[dict] = []
    with alerts._LOCK:
        data = alerts.load(lab.name)
        opened, _ = alerts.reconcile(data, [c], set(), float(e["at"]))
        a = opened[0] if opened else next((x for x in alerts.active(data) if x["key"] == c["key"]), None)
        if a is not None:
            a["ticket"] = alerts.open_ticket_for(lab, a, now, fault)
            e["alert"], e["ticket"] = a["id"], a["ticket"]
            if quiet:
                a["quiet"] = True
                helpdesk.hold_for_morning(lab.name, a["ticket"], now, why)
            jobs = alerts.plan_deliveries(lab, data, staff, opened, [], now)
        alerts.save(lab.name, data)
    if a is None:
        # The source is switched off in the Alerts window: the ticket still comes in.
        t = helpdesk.open_ticket(lab.name, caller="admin", summary=f"{c['title']} on {alerts._where(lab, e['node'])}",
                                 body=f"Monitoring: {c['detail']}.", priority=c["severity"], source="monitoring",
                                 category="monitoring", node=e["node"], fault=fault, dedupe=c["key"], now=now)
        e["ticket"] = t["id"]
        if quiet:
            helpdesk.hold_for_morning(lab.name, t["id"], now, why)
    elif jobs and runner is not None:
        try:
            alerts.run_deliveries(lab, runner, jobs, now)
        except Exception:  # noqa: BLE001 - a mail that did not go is not a reason to lose the event
            pass


# ------------------------------------------------------------------ is it fixed
def check_event(lab, e: dict, runner: Runner) -> bool | None:
    """True when the wear is gone, False while it is there, None when the
    machine cannot be asked."""
    from . import disks
    if e["kind"] == "disk-failing":
        node = lab.nodes.get(e["node"])
        if node is None:
            return True
        return int(e.get("index", 0)) not in disks.failing_in(disks._dir(lab.name, node.id))
    if e["kind"] == "licence":
        from . import evaluation
        try:
            ok, out = runner(e["node"], evaluation._QUERY, "powershell")
        except Exception:  # noqa: BLE001
            return None
        if not ok:
            return None
        try:
            c = evaluation.parse(e["node"], out)
        except evaluation.EvaluationError:
            return None
        return not c.evaluation or c.days_left > LICENCE_WARN
    if not e.get("fault"):
        return None
    cmds = fault_commands(e["fault"], _fresh_params(lab, e.get("params") or {}))
    try:
        ok, out = runner(e["node"], cmds["verify"], cmds["shell"])
    except Exception:  # noqa: BLE001
        return None
    if not ok:
        return None
    from . import guestfaults as gf
    return gf.is_fixed(out, cmds["expect"])


def _mark_fixed(lab, e: dict, now: float) -> None:
    from . import alerts
    e["state"], e["fixed"] = "fixed", now
    if e.get("alert"):
        with alerts._LOCK:
            data = alerts.load(lab.name)
            a = next((x for x in data["alerts"] if x["id"] == e["alert"]), None)
            if a is not None and not a.get("cleared") and a["source"] == "wear":
                a["cleared"] = now
                alerts._event(data, "clear", a, f"{a['title']} on {a['node']}: recovered", now)
            alerts.save(lab.name, data)
        if e.get("ticket"):
            alerts.ticket_note(lab.name, e["ticket"], "monitoring",
                               f"Recovered at {alerts.stamp(now)} (lab time).", now)


def _ticket_check(lab, fault: dict, runner: Runner) -> tuple[bool, str] | None:
    """The helpdesk's check for a wear-backed ticket."""
    with _lock:
        st = load(lab.name)
        e = find(st, fault.get("id", ""))
        if e is None:
            return True, "gone"
        if e["state"] != "open":
            return True, e["state"]
        got = check_event(lab, e, runner)
        if got is None:
            return None
        if got:
            _mark_fixed(lab, e, labclock.load(lab.name).now())
            save(lab.name, st)
        return got, "fixed" if got else "still there"


def undo_event(lab, e: dict, runner: Runner) -> None:
    """Winlab puts it back (an instructor's reset): the fault's clear, the disk mended."""
    from . import disks
    if e["kind"] == "disk-failing":
        node = lab.nodes.get(e["node"])
        if node is not None:
            try:
                disks.heal(lab.name, node, int(e.get("index", 0)))
            except Exception:  # noqa: BLE001 - replaced or already mended
                pass
    elif e.get("fault"):
        cmds = fault_commands(e["fault"], _fresh_params(lab, e.get("params") or {}))
        try:
            runner(e["node"], cmds["clear"], cmds["shell"])
        except Exception:  # noqa: BLE001
            pass
        if e["kind"] == "dc-drift":
            from . import timesync
            now = labclock.load(lab.name).now()
            try:
                runner(e["node"], timesync.skew_command("powershell", now), "powershell")
            except Exception:  # noqa: BLE001
                pass
    e["state"], e["fixed"] = "undone", labclock.load(lab.name).now()


def _ticket_undo(lab, fault: dict, runner: Runner) -> None:
    # Stopping the helpdesk queue leaves wear alone: it is not the queue's.
    return None


def register() -> None:
    from . import helpdesk
    helpdesk.register_check("wear", _ticket_check, _ticket_undo)


register()


# ------------------------------------------------------------------ the licence, read every morning
def licence_due(st: dict, now: float) -> bool:
    lt = time.localtime(now)
    return lt.tm_hour >= LICENCE_HOUR and st.get("licence_day") != time.strftime("%Y-%m-%d", lt)


def licence_severity(days: int) -> str:
    return "P1" if days <= 0 else "P2" if days <= 3 else "P3"


def read_licences(lab, st: dict, now: float, runner: Runner, running: list[str]) -> list[dict]:
    """Reads each running Windows machine's licence; one that is an
    evaluation within LICENCE_WARN days of its end becomes an event."""
    from . import evaluation
    raised = []
    st["licence_day"] = time.strftime("%Y-%m-%d", time.localtime(now))
    busy = {e["node"] for e in open_events(st) if e["kind"] == "licence"}
    for nid in running:
        node = lab.nodes.get(nid)
        if node is None or not node.is_windows:
            continue
        try:
            ok, out = runner(nid, evaluation._QUERY, "powershell")
            c = evaluation.parse(nid, out, now) if ok else None
        except Exception:  # noqa: BLE001 - an answer that does not parse is no reading
            c = None
        if c is None:
            continue
        st["readings"][nid] = {"at": now, "evaluation": c.evaluation, "days": c.days_left, "rearms": c.rearms_left}
        if c.evaluation and c.days_left <= LICENCE_WARN and nid not in busy:
            raised.append(_record(st, kind="licence", node=nid, at=now, fault="",
                                  params={"days": str(max(0, c.days_left)), "rearms": str(c.rearms_left)},
                                  severity=licence_severity(c.days_left)))
    return raised


# ------------------------------------------------------------------ one beat
def tick(lab, runner: Runner, now: float | None = None, running: list[str] | None = None,
         force: bool = False) -> dict:
    """What has worn out since the last beat: due events fire (at their own
    time, so a night that passed in a jump still has its 03:00 crash), the
    morning licence reading, the open events checked, a drifting clock
    pushed further. Returns {"fired": [...], "fixed": [...]}."""
    from . import oncall
    at = labclock.load(lab.name).now() if now is None else now
    with _lock:
        st = load(lab.name)
        level = st["level"]
        fired: list[dict] = []
        fixed: list[dict] = []
        if level == "off" and not force:
            return {"fired": [], "fixed": [], "level": level}
        run = oncall.running_nodes(lab) if running is None else running
        mean_days, cap, _ = LEVELS[level]
        if st["next"] is None and mean_days:
            st["next"] = schedule(st, at)
        n = 0
        while mean_days and st["next"] and (float(st["next"]["at"]) <= at or force) and n < CATCH_UP:
            due = st["next"]
            when = min(float(due["at"]), at)
            if sum(1 for e in open_events(st) if e["kind"] != "licence") < cap or force:
                rng = rng_for(st, "fire")
                e = fire(lab, st, due["kind"], when, runner, run, rng)
                if e is not None:
                    announce(lab, e, at, runner, rng)
                    fired.append(e)
            st["n"] += 1
            st["next"] = schedule(st, when)
            n += 1
            force = False
        if st["next"] and float(st["next"]["at"]) <= at:
            st["next"] = schedule(st, at)       # the clock jumped further than a beat catches up
        if licence_due(st, at) and run:
            for e in read_licences(lab, st, at, runner, run):
                announce(lab, e, at, runner, rng_for(st, e["id"]))
                fired.append(e)
        if at - float(st.get("last_check") or 0) >= CHECK_EVERY or force:
            st["last_check"] = at
            for e in open_events(st):
                if e["node"] not in run and e["kind"] != "disk-failing":
                    continue
                got = check_event(lab, e, runner)
                if got:
                    _mark_fixed(lab, e, at)
                    fixed.append(e)
                elif got is False and e["kind"] == "dc-drift":
                    _drift(lab, e, at, runner)
        save(lab.name, st)
    return {"fired": fired, "fixed": fixed, "level": level}


def clear(lab, runner: Runner) -> list[dict]:
    """Undo every open wear event (an instructor's reset, not a fix)."""
    with _lock:
        st = load(lab.name)
        done = []
        for e in open_events(st):
            undo_event(lab, e, runner)
            done.append(e)
        save(lab.name, st)
    return done


# ------------------------------------------------------------------ what is shown
def describe(lab, e: dict) -> str:
    from . import alerts
    k = KINDS.get(e["kind"])
    title = k.title if k else e["kind"]
    return f"{title} on {alerts._where(lab, e['node'])}"


def since(st: dict, t0: float, t1: float | None = None) -> list[dict]:
    return [e for e in st["events"] if float(e["at"]) >= t0 and (t1 is None or float(e["at"]) < t1)]


def view(lab, now: float | None = None) -> dict:
    at = labclock.load(lab.name).now() if now is None else now
    st = load(lab.name)
    rows = []
    for e in reversed(st["events"][-60:]):
        rows.append({"id": e["id"], "kind": e["kind"], "title": describe(lab, e), "node": e["node"],
                     "at": e["at"], "state": e["state"], "fixed": e.get("fixed") or 0.0,
                     "ticket": e.get("ticket", ""), "alert": e.get("alert", 0)})
    return {"lab": lab.name, "now": at, "level": st["level"], "seed": st["seed"],
            "levels": {k: {"days": v[0], "open": v[1], "text": v[2]} for k, v in LEVELS.items()},
            "next": st["next"]["at"] if st["next"] else None, "events": rows,
            "open": len(open_events(st)), "readings": st.get("readings", {})}


def render(v: dict) -> str:
    lines = [f"wear on {v['lab']}: {v['level']} ({v['levels'][v['level']]['text']}), seed {v['seed']}",
             f"lab time {labclock.stamp(v['now'])}; {v['open']} open"
             + (f"; something wears out by {labclock.stamp(v['next'])}" if v["next"] else ""), ""]
    for r in v["events"][:20]:
        lines.append(f"  {r['id']}  {labclock.stamp(r['at'])}  {r['state']:<6} {r['title']}"
                     + (f"  ({r['ticket']})" if r["ticket"] else ""))
    if not v["events"]:
        lines.append("  nothing has worn out yet")
    return "\n".join(lines)


# ------------------------------------------------------------------ the desktop, in a thread
def background(dash, every: float = 30.0) -> bool:
    """A beat in a thread when one is due, so the desktop's poll answers at once."""
    st = dash.__dict__.setdefault("wear_state", {"lock": threading.Lock(), "last": 0.0, "busy": False, "error": ""})
    if load(dash.lab.name)["level"] == "off":
        return False
    now = time.monotonic()
    with st["lock"]:
        if st["busy"] or now - st["last"] < every:
            return False
        st["busy"], st["last"] = True, now
    lab = dash.lab

    def go():
        from . import oncall
        try:
            tick(lab, oncall.guest_runner(lab.name))
            st["error"] = ""
        except Exception as exc:  # noqa: BLE001 - wear keeps going
            st["error"] = str(exc)[:200]
        finally:
            st["busy"] = False
    threading.Thread(target=go, daemon=True).start()
    return True


# ------------------------------------------------------------------ the command line
def add_cli(sub) -> None:
    wp = sub.add_parser("wear", help="servers that wear out on their own on the lab clock: off, gentle, realistic, harsh")
    wp.add_argument("lab", nargs="?", default="")
    ws = wp.add_subparsers(dest="wearcmd", metavar="<op>")
    ws.add_parser("status", help="the level, the next event and what has worn out")
    wl = ws.add_parser("level", help="set the wear level")
    wl.add_argument("level", choices=list(LEVELS))
    wt = ws.add_parser("tick", help="let wear move on now (due events fire, open ones are checked)")
    wt.add_argument("--force", action="store_true", help="something wears out now, whatever the schedule")
    wse = ws.add_parser("seed", help="this lab's wear seed (the same seed wears the same way)")
    wse.add_argument("seed", type=int)
    ws.add_parser("clear", help="undo every open wear event (a reset, not a fix)")


def run_cli(args) -> int:
    import sys

    from . import oncall, schema
    from .cli import _resolve_lab
    try:
        lab = schema.load(_resolve_lab(args.lab))
    except Exception as exc:  # noqa: BLE001 - the CLI reports it
        print(f"{exc}", file=sys.stderr)
        return 2
    op = args.wearcmd or "status"
    try:
        if op == "level":
            set_level(lab.name, args.level)
        elif op == "seed":
            set_seed(lab.name, args.seed)
        elif op == "tick":
            r = tick(lab, oncall.guest_runner(lab.name), force=args.force)
            for e in r["fired"]:
                print(f"{e['id']} worn out: {describe(lab, e)}" + (f" ({e['ticket']})" if e.get("ticket") else ""))
            for e in r["fixed"]:
                print(f"{e['id']} fixed: {describe(lab, e)}")
            if not r["fired"] and not r["fixed"]:
                print("nothing new" + ("; wear is off: winlab wear <lab> level realistic" if r["level"] == "off" else ""))
            return 0
        elif op == "clear":
            for e in clear(lab, oncall.guest_runner(lab.name)):
                print(f"{e['id']} undone: {describe(lab, e)}")
            return 0
    except ValueError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print(render(view(lab)))
    return 0
