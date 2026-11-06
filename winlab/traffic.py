"""The load engine: a real office's day of traffic on the lab's servers.

The working day (winlab/workday.py) has the lab's staff sign in and work as
themselves inside the guests. This module gives that day its shape and its
weight, and keeps it honest:

The shape. A profile says how busy the office is at each moment on the lab
clock. The office day starts slowly with the early starters, peaks as
everyone opens their mail, dips at lunch, swells again with the end-of-day
saves, and goes quiet at the weekend; on a Monday morning everyone signs in
and opens everything at once, and on the last two working days of a month
Finance closes the books (more documents, more reports, more printing). A
"busy day" doubles everything for one lab day (an audit, a product launch).
The student can turn each period up or down, or pick a flat or a
round-the-clock profile. The pace changes how often each person does
something and which things they favour, never what they do it with.

The servers' own work. Real servers are busy when nobody is in: the nightly
backup window reads every file on the shares, Microsoft Defender runs its
quick scan (servers at night, PCs at lunch), the search indexer crawls the
shares for changed files, each machine asks its update server what it is
missing when the lab has WSUS and the student pointed it there, and the
domain controllers push every partition to each other when there are two of
them. They run whenever the lab's machines run, with the workday on or off:
real servers do not wait for the staff to arrive. Each runs inside the guest, through its agent, detached so a long scan
never holds the agent, with a lock file so a second never starts while the
first runs; the next run reports how the last one went. A replication or
update scan that fails raises a monitoring ticket.

The rules that keep it robust. Each tick runs at most so many jobs, at most a
few on any one PC, and stops when its time is used up (the rest stay due). A
guest that does not answer or takes too long is left alone for a while, the
pause doubling each time (back-off), and its people wait at their desks. A
clock that jumps (the student moves the lab clock forward a day, or back)
does not make everyone act at once: their next actions are spread over the
next minutes. Every action is counted per server, per person and per PC, so
the Office window can show where the load goes, beside the live meters of
winlab/perfmon.py for each cable.

The consequences. A failure is turned into a helpdesk ticket in the
person's own words (workday.TICKETS). Everyone it touches calls, each once
an hour at most, and their calls go onto the one ticket for that broken
thing: when enough people have called it is raised (three people: P2, six:
P1). When someone it touched does the same thing again without trouble, or
nobody has called for a while, a note on the ticket says the calls have
stopped, so the student knows the fix took before resolving.

Hands-on: nothing here creates a share, an account, a policy or a service.
The load only uses what the student built, and what is not there is simply
not used.
"""

from __future__ import annotations

import json
import math
import threading
import time
import zlib
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import paths

Runner = Callable[[str, str, str], tuple[bool, str]]

FILE = "traffic.json"
TICK_BUDGET = 150.0          # real seconds one tick may spend inside the guests
PER_PC = 3                   # the most staff jobs one PC runs in a tick
MAX_PER_TICK = 12            # the most staff jobs in a tick, however busy
BG_PER_TICK = 2              # the most server jobs started in a tick
SLOW_CALL = 120.0            # real seconds: a guest slower than this is slow
BACKOFF_BASE, BACKOFF_MAX = 30.0, 900.0
JUMP_AHEAD = 2 * 3600        # lab seconds: a step forward bigger than this is a jump
JUMP_BACK = 300              # lab seconds: a step back bigger than this is a jump
SPREAD = 20 * 60             # lab seconds over which a jump's backlog is spread
CALL_AGAIN = 60 * 60         # lab seconds before a person calls again about one thing
QUIET_AFTER = 90 * 60        # lab seconds without a call: "the calls have stopped"
ESCALATE = ((6, "P1"), (3, "P2"))
BUSY_FACTOR = 2.0
LOG_MAX, EVENTS_MAX = 800, 120

_lock = threading.RLock()
_links: dict[str, dict[str, deque]] = {}     # lab -> cable -> recent bytes/s (the sparklines)
_links_at: dict[str, float] = {}


# =================================================================== profiles
@dataclass(frozen=True)
class Period:
    id: str
    title: str
    days: str            # "weekdays", "monday", "friday", "weekend", "month-end", "every day"
    start: int           # minutes after midnight, lab time
    end: int
    factor: float        # 2.0: twice as busy as a plain hour
    favour: tuple = ()   # (action, weight multiplier): what people do more of now
    department: str = ""  # only this department's pace and favours


@dataclass(frozen=True)
class Profile:
    id: str
    title: str
    text: str
    periods: tuple


def _hm(h: int, m: int = 0) -> int:
    return h * 60 + m


PROFILES: dict[str, Profile] = {p.id: p for p in (
    Profile("office", "Office day", "office hours with a morning peak, a lunch dip, end-of-day saves, "
            "a Monday-morning storm and month-end in Finance", (
                Period("weekend", "Weekend", "weekend", 0, 1440, 0.2),
                Period("early", "Early starters", "weekdays", _hm(6, 30), _hm(8, 30), 0.6),
                Period("morning", "Morning mail", "weekdays", _hm(8, 30), _hm(10), 1.4,
                       (("mail", 2.0), ("intranet", 1.5), ("lookup", 1.5))),
                Period("lunch", "Lunch dip", "weekdays", _hm(12), _hm(13, 30), 0.35),
                Period("friday", "Friday afternoon", "friday", _hm(14), _hm(16, 30), 0.7),
                Period("eod", "End-of-day saves", "weekdays", _hm(16, 30), _hm(17, 45), 1.8,
                       (("share", 2.0), ("home", 2.0), ("document", 2.0), ("bigcopy", 1.5))),
                Period("monday", "Monday-morning storm", "monday", _hm(8, 15), _hm(9, 45), 2.5,
                       (("mail", 2.0), ("intranet", 2.0), ("lookup", 2.0), ("document", 1.5))),
                Period("month-end", "Month-end close", "month-end", _hm(8), _hm(19), 3.0,
                       (("share", 2.0), ("document", 2.0), ("sql", 3.0), ("print", 2.0)), "Finance"),
            )),
    Profile("flat", "Flat", "the same pace all day: the plain office of the load level alone", ()),
    Profile("round", "Round the clock", "a 24/7 operation for shift work: a quieter night and weekend", (
        Period("weekend", "Weekend", "weekend", 0, 1440, 0.7),
        Period("night", "Night", "every day", 0, _hm(6), 0.4),
        Period("late", "Late evening", "every day", _hm(22), 1440, 0.5),
        Period("handover", "Shift handover", "every day", _hm(6), _hm(7), 1.6, (("mail", 2.0), ("lookup", 1.5))),
    )),
)}
DEFAULT_PROFILE = "office"


def _midnight(ts: float) -> float:
    t = time.localtime(ts)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1))


def day_key(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def hhmm(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def month_end(ts: float) -> bool:
    """One of the month's last two working days (Monday to Friday)."""
    t = time.localtime(ts)
    if t.tm_wday >= 5:
        return False
    left, day = 0, _midnight(ts) + 36 * 3600
    while time.localtime(day).tm_mon == t.tm_mon:
        if time.localtime(day).tm_wday < 5:
            left += 1
        day += 86400
    return left < 2


def _on(days: str, ts: float) -> bool:
    wd = time.localtime(ts).tm_wday
    return {"weekdays": wd < 5, "monday": wd == 0, "friday": wd == 4, "weekend": wd >= 5,
            "month-end": month_end(ts), "every day": True}.get(days, False)


def factor_of(cfg: dict, period: Period) -> float:
    """A period's pace, as the student set it or the profile's own."""
    try:
        return max(0.0, min(5.0, float(cfg.get("factors", {}).get(period.id, period.factor))))
    except (TypeError, ValueError):
        return period.factor


def profile_of(cfg: dict) -> Profile:
    return PROFILES.get(cfg.get("profile", DEFAULT_PROFILE), PROFILES[DEFAULT_PROFILE])


def active(cfg: dict, ts: float) -> list[Period]:
    lt = time.localtime(ts)
    mins = lt.tm_hour * 60 + lt.tm_min
    return [p for p in profile_of(cfg).periods if p.start <= mins < p.end and _on(p.days, ts)]


def busy_today(cfg: dict, ts: float) -> str:
    """The busy day's name when today (lab time) is one, else ""."""
    b = cfg.get("busy") or {}
    return str(b.get("label") or "busy day") if b.get("day") == day_key(ts) else ""


def pace(cfg: dict, now: float, held: set[str] | None = None, base_cap: int = 4) -> dict:
    """How busy the office is at `now`: the overall factor (the last of the
    profile's periods that applies wins: the more specific ones come last),
    each department's own factor, what people favour, the most jobs this
    tick and on one PC, and the PCs to leave alone. Pure."""
    factor, favour, reasons = 1.0, {}, []
    dept: dict[str, float] = {}
    dept_favour: dict[str, dict[str, float]] = {}
    glob = None
    for p in active(cfg, now):
        if p.department:
            dept[p.department] = dept.get(p.department, 1.0) * factor_of(cfg, p)
            dept_favour[p.department] = dict(p.favour)
            reasons.append(f"{p.title} ({p.department})")
        else:
            glob = p
    if glob is not None:
        factor, favour = factor_of(cfg, glob), dict(glob.favour)
        reasons.insert(0, glob.title)
    busy = busy_today(cfg, now)
    if busy:
        factor *= BUSY_FACTOR
        reasons.append(f"busy day: {busy}")
    cap = max(1, min(MAX_PER_TICK, round(base_cap * min(2.0, max(0.5, factor)))))
    return {"factor": round(factor, 3), "dept": dept, "favour": favour, "dept_favour": dept_favour,
            "cap": cap, "per_pc": PER_PC, "held": sorted(held or ()), "reasons": reasons}


def curve(cfg: dict, midnight: float) -> dict:
    """The day's pace in half hours, for the Office window's graph: the
    overall line, and each department's own when one has a period today."""
    out: dict = {"all": [], "dept": {}}
    for i in range(48):
        p = pace(cfg, midnight + i * 1800 + 60)
        out["all"].append(p["factor"])
        for d, f in p["dept"].items():
            out["dept"].setdefault(d, [0.0] * 48)[i] = round(p["factor"] * f, 3)
    for d in out["dept"]:
        out["dept"][d] = [v or out["all"][i] for i, v in enumerate(out["dept"][d])]
    return out


# ======================================================== the servers' own work
@dataclass(frozen=True)
class Background:
    id: str
    title: str
    text: str
    start: int           # the window, minutes after midnight, lab time
    end: int
    every: int           # minutes between runs inside the window
    targets: str         # which machines: see targets()
    needs: str = ""      # a lab fact whose machine must be running
    ticket: tuple = ()   # (priority, category, summary) of the monitoring ticket a failure raises


BACKGROUND: dict[str, Background] = {b.id: b for b in (
    Background("backup", "Nightly backup window", "the backup reads every file on the file server's shares "
               "(and reports Windows Server Backup's last result when it is set up)", _hm(1), _hm(4), 60, "files"),
    Background("av-servers", "Antivirus scan, servers", "Microsoft Defender's quick scan", _hm(2), _hm(5), 1440, "servers"),
    Background("av-pcs", "Antivirus scan, PCs", "Microsoft Defender's quick scan over lunch", _hm(12, 15), _hm(13, 45),
               1440, "pcs"),
    Background("index", "Search indexing", "the indexer crawls the shares and reads the files changed since its last pass",
               _hm(9), _hm(18), 120, "files"),
    Background("wsus", "Windows Update scan", "each machine asks its update server (the WSUS the student pointed "
               "it at) what it is missing", _hm(6), _hm(11), 1440, "updaters", "wsus_node",
               ("P3", "updates", "Machines can't scan for updates against WSUS")),
    Background("repl", "Domain controller replication", "repadmin /syncall: every partition pushed to every DC",
               0, 1440, 60, "repl", "", ("P2", "directory", "Replication between the domain controllers is failing")),
)}


def targets(bg: Background, facts: dict, running: set[str]) -> list[str]:
    pcs = set(facts.get("pcs", ()))
    if bg.targets == "files":
        return list(facts.get("file_nodes", ()))
    if bg.targets == "servers":
        return [n for n in facts.get("windows", ()) if n not in pcs]
    if bg.targets == "pcs":
        return [n for n in facts.get("windows", ()) if n in pcs]
    if bg.targets == "updaters":
        return [n for n in facts.get("windows", ()) if n != facts.get("wsus_node")]
    if bg.targets == "repl":
        up = [n for n in facts.get("dc_nodes", ()) if n in running]
        return [facts["dc_node"] if facts.get("dc_node") in up else up[0]] if len(up) >= 2 else []
    return []


def due_background(cfg: dict, facts: dict, now: float, running: set[str], avoid: set[str]) -> list[tuple]:
    """The server jobs due now, most overdue first: [(Background, node)].
    A job runs inside its window, spread a little per machine so the PCs do
    not all scan at the same minute, once a window or every `every` minutes.
    A run recorded in the future (the clock went back) counts as none. Pure."""
    lt = time.localtime(now)
    midnight, wd = _midnight(now), lt.tm_wday
    out = []
    for bg in BACKGROUND.values():
        if bg.needs and facts.get(bg.needs) not in running:
            continue
        if bg.id in ("index", "av-pcs") and wd >= 5:
            continue
        for node in targets(bg, facts, running):
            if node not in running or node in avoid:
                continue
            key = f"{bg.id}@{node}"
            off = zlib.crc32(key.encode("utf-8")) % max(1, min(30, (bg.end - bg.start) // 2))
            start, end = midnight + (bg.start + off) * 60, midnight + bg.end * 60
            if not start <= now < end:
                continue
            last = float(cfg.get("bg", {}).get(key, {}).get("last") or 0)
            if last > now:
                last = 0.0
            if last < start or now - last >= bg.every * 60:
                out.append((now - max(last, start), bg, node))
    out.sort(key=lambda x: -x[0])
    return [(bg, node) for _, bg, node in out]


TEMP = "C:\\Windows\\Temp\\winlab-load-"
SHARES = ("$roots = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.Path "
          "-and $_.Name -notmatch '^(NETLOGON|SYSVOL|print\\$)$' } | ForEach-Object { $_.Path })")


def _worker(bg: Background) -> list[str]:
    """What runs detached inside the guest, as the machine."""
    if bg.id == "backup":
        return [SHARES,
                "if (-not $roots.Count) { Done 'ok no shares to back up yet'; return }",
                "$max = 512MB; $n = 0; $bytes = 0; $buf = New-Object byte[] 1048576; $t0 = Get-Date",
                ":all foreach ($r in $roots) { foreach ($f in @(Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue)) {",
                "  if ($bytes -ge $max) { break all }",
                "  try { $s = [IO.File]::OpenRead($f.FullName); try { while (($k = $s.Read($buf, 0, $buf.Length)) -gt 0) { $bytes += $k } } finally { $s.Close() }; $n++ } catch { } } }",
                "$wb = ''; try { $sum = Get-WBSummary -ErrorAction Stop",
                "  $wb = '; Windows Server Backup last succeeded ' + $sum.LastSuccessfulBackupTime + ', last result 0x' + ('{0:X}' -f $sum.LastBackupResultHR) } catch { }",
                "Done \"ok read $n files ($([math]::Round($bytes / 1MB)) MB) on $($roots.Count) shares in $([int]((Get-Date) - $t0).TotalSeconds) s$wb\""]
    if bg.id.startswith("av-"):
        return ["$mp = Join-Path $env:ProgramFiles 'Windows Defender\\MpCmdRun.exe'; $t0 = Get-Date",
                "$null = & { $ErrorActionPreference = 'Continue'; & $mp -Scan -ScanType 1 2>&1 | Out-String }",
                "if ($LASTEXITCODE -eq 0) { Done \"ok quick scan done in $([int]((Get-Date) - $t0).TotalSeconds) s\" }",
                "else { Done \"fail the quick scan ended with exit code $LASTEXITCODE\" }"]
    if bg.id == "index":
        return [SHARES,
                "$since = (Get-Date).AddHours(-2); $n = 0; $ch = 0; $buf = New-Object byte[] 4096",
                "foreach ($r in $roots) { foreach ($f in @(Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue)) { $n++",
                "  if ($f.LastWriteTime -gt $since -and $ch -lt 2000) { try { $s = [IO.File]::OpenRead($f.FullName); $null = $s.Read($buf, 0, 4096); $s.Close(); $ch++ } catch { } } } }",
                "$ws = Get-Service WSearch -ErrorAction SilentlyContinue",
                "Done \"ok crawled $n files on $($roots.Count) shares, read $ch changed ones$(if ($ws) { '; Windows Search is ' + $ws.Status })\""]
    if bg.id == "wsus":
        return ["$wu = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -ErrorAction SilentlyContinue).WUServer",
                "try { $s = New-Object -ComObject Microsoft.Update.Session; $r = $s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')",
                "  Done \"ok $($r.Updates.Count) updates needed, from $wu\" }",
                "catch { Done \"fail the scan against $wu failed ($($_.Exception.Message))\" }"]
    if bg.id == "repl":
        return ["$o = & { $ErrorActionPreference = 'Continue'; repadmin.exe /syncall /AdeP 2>&1 | Out-String }",
                "if ($o -match 'terminated with no errors') { Done 'ok every partition pushed to every DC, no errors' }",
                "else { $l = @($o -split \"`r?`n\" | Where-Object { $_ -match 'error|fail' -and $_.Trim() })",
                "  Done \"fail $(if ($l.Count) { $l[0].Trim() } else { 'repadmin did not finish' })\" }"]
    raise ValueError(f"no server job {bg.id!r}")


def _precheck(bg: Background) -> list[str]:
    """Lines the launcher runs first: what the machine must already have."""
    if bg.id.startswith("av-"):
        return ["if (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Windows Defender\\MpCmdRun.exe'))) "
                "{ Say 'skip no Microsoft Defender on this machine'; return }"]
    if bg.id in ("backup", "index"):
        return ["if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { Say 'skip no SMB shares here'; return }"]
    if bg.id == "wsus":
        return ["if (-not (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -ErrorAction SilentlyContinue).WUServer) "
                "{ Say 'skip not pointed at an update server (no WUServer policy yet)'; return }"]
    if bg.id == "repl":
        return ["if (-not (Get-Command repadmin.exe -ErrorAction SilentlyContinue)) { Say 'skip no repadmin here'; return }"]
    return []


def background_command(bg: Background) -> str:
    """The launcher winlab's agent runs (as the machine): report the last
    run's result, say "busy" while a run still holds its lock, check what
    the job needs, then start the worker detached and keep its process id
    in the lock. Every line it prints starts with "LD "."""
    from .workday import encode_ps, ps_quote
    lock, res = f"{TEMP}{bg.id}.lock", f"{TEMP}{bg.id}.txt"
    worker = "\n".join([
        f"$res = {ps_quote(res)}; $lock = {ps_quote(lock)}",
        "function Done($t) { Set-Content -LiteralPath $res -Value $t -Encoding UTF8 }",
        "$ProgressPreference = 'SilentlyContinue'",
        "try { & {", *_worker(bg), "} } catch { Done \"fail $($_.Exception.Message)\" }",
        "finally { Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue }"])
    return "\n".join([
        f"# The lab's own background work: {bg.title.lower()} ({bg.text}).",
        "& {",
        "$ProgressPreference = 'SilentlyContinue'",
        "function Say($t) { Write-Output \"LD $t\" }",
        f"$lock = {ps_quote(lock)}; $res = {ps_quote(res)}",
        "if (Test-Path -LiteralPath $res) { Say \"last $((Get-Content -LiteralPath $res -Raw).Trim())\"; Remove-Item -LiteralPath $res -Force -ErrorAction SilentlyContinue }",
        "if (Test-Path -LiteralPath $lock) { $old = Get-Content -LiteralPath $lock -ErrorAction SilentlyContinue | Select-Object -First 1",
        "  if ($old -and (Get-Process -Id ([int]$old) -ErrorAction SilentlyContinue)) { Say 'busy'; return } }",
        *_precheck(bg),
        "$p = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList "
        f"'-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encode_ps(worker)}'",
        "Set-Content -LiteralPath $lock -Value $p.Id",
        "Say 'started'",
        "}"])


def parse_background(ok: bool, out: str) -> dict:
    """{"state": started|busy|skipped|no answer, "result": the last run's
    words or "", "skip": why}."""
    res = {"state": "", "result": "", "skip": ""}
    for raw in (out or "").splitlines():
        line = raw.strip()
        if not line.startswith("LD "):
            continue
        word, _, rest = line[3:].partition(" ")
        if word == "last":
            res["result"] = rest.strip()[:300]
        elif word == "busy":
            res["state"] = "busy"
        elif word == "skip":
            res["state"], res["skip"] = "skipped", rest.strip()[:200]
        elif word == "started":
            res["state"] = "started"
    if not res["state"]:
        res["state"] = "no answer" if not ok else "started" if res["result"] else "no answer"
        res["skip"] = (out or "").strip()[:200] if not ok else ""
    return res


# ===================================================================== storage
def state_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def fresh() -> dict:
    return {"profile": DEFAULT_PROFILE, "factors": {}, "busy": {}, "background": True, "guests": {}, "bg": {},
            "streams": {}, "log": [], "events": [], "last_lab": 0.0}


def load(lab_name: str) -> dict:
    try:
        raw = json.loads(state_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {**fresh(), **raw}
    except (OSError, ValueError):
        pass
    return fresh()


def save(lab_name: str, ts: dict) -> None:
    f = state_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    ts["log"] = ts.get("log", [])[-LOG_MAX:]
    ts["events"] = ts.get("events", [])[-EVENTS_MAX:]
    with _lock:
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(ts, indent=1), encoding="utf-8")
        tmp.replace(f)


def _event(ts: dict, now: float, text: str, node: str = "", ok: bool = True, job: str = "") -> None:
    ts.setdefault("events", []).append({"at": now, "node": node, "job": job, "text": text, "ok": ok})


# ================================================================ guest health
def health(ts: dict, node: str, answered: bool, seconds: float, real: float) -> dict:
    """A guest's answer recorded: a fast answer clears its back-off; no
    answer, or a slow one, sets it, twice as long each time. Pure on `ts`."""
    g = ts.setdefault("guests", {}).setdefault(node, {"fails": 0, "until": 0.0, "s": 0.0, "why": ""})
    g["s"], g["at"] = round(seconds, 1), real
    if answered and seconds <= SLOW_CALL:
        g.update(fails=0, until=0.0, why="")
    else:
        g["fails"] = int(g.get("fails", 0)) + 1
        g["until"] = real + min(BACKOFF_MAX, BACKOFF_BASE * 2 ** (g["fails"] - 1))
        g["why"] = "no answer" if not answered else f"slow ({int(seconds)} s)"
    return g


def held(ts: dict, real: float) -> set[str]:
    return {n for n, g in ts.get("guests", {}).items() if float(g.get("until") or 0) > real}


def held_now(lab_name: str) -> set[str]:
    """The guests being left alone right now."""
    with _lock:
        return held(load(lab_name), time.time())


# ===================================================== the tick, as workday calls it
def settle(st: dict, now: float, rng, spread: float = SPREAD) -> int:
    """After a jump of the clock: everyone's next action that is now long
    past (or far ahead) moves to a moment in the next few minutes, so the
    backlog trickles in instead of landing at once. Returns how many moved."""
    moved = 0
    for r in st.get("people", {}).values():
        nxt = float(r.get("next") or 0)
        if nxt < now - 60 or nxt > now + 3 * 3600:
            r["next"] = now + rng.uniform(0, spread)
            moved += 1
    return moved


def begin(lab_name: str, st: dict, now: float, rng) -> dict:
    """The start of a workday tick: catch up after a jump of the lab clock,
    and the pace of this moment (pace())."""
    from . import workday
    with _lock:
        ts = load(lab_name)
        last = float(ts.get("last_lab") or 0)
        jumped = bool(last) and (now - last > JUMP_AHEAD or now < last - JUMP_BACK)
        if jumped:
            n = settle(st, now, rng)
            for rec in ts.get("bg", {}).values():
                if float(rec.get("last") or 0) > now:
                    rec["last"] = 0.0
            step = now - last
            _event(ts, now, f"the lab clock {'jumped ahead' if step > 0 else 'went back'} "
                            f"{_span(abs(step))}: {n} people's next steps spread over {SPREAD // 60} minutes")
        ts["last_lab"] = now
        level_cap = workday.LEVELS.get(st.get("level", workday.DEFAULT_LEVEL), workday.LEVELS[workday.DEFAULT_LEVEL])[1]
        p = pace(ts, now, held(ts, time.time()), level_cap)
        p["spread"] = SPREAD if jumped else 0
        save(lab_name, ts)
    return p


def _span(s: float) -> str:
    if s >= 86400:
        return f"{s / 86400:.1f} days"
    if s >= 3600:
        return f"{s / 3600:.1f} hours"
    return f"{int(s // 60)} minutes"


def server_of(job: dict, facts: dict) -> str:
    """The machine a staff action loads, beside the PC it runs on."""
    act = job.get("action", "")
    if act in ("signin", "lookup"):
        return facts.get("dc_node", "")
    if act in ("share", "home", "document", "bigcopy"):
        return facts.get("files_node", "")
    if act == "print":
        return facts.get("printserver_node") or facts.get("printer_node", "")
    if act == "browse":
        urls = job.get("sites") or []
        return next((s["node"] for s in facts.get("sites", ()) if urls and s["url"] == urls[0]), "")
    return facts.get({"mail": "mail_node", "intranet": "intranet_node", "sql": "sql_node",
                      "rdp": "rds_node"}.get(act, ""), "")


def after_job(lab_name: str, job: dict, person: dict, facts: dict, res: dict, o: dict, seconds: float,
              now: float, raised: bool = False) -> None:
    """A staff job done: the guest's health, and one line of the activity
    log (who, from which PC, to which server, what, how it went, bytes).
    A runner that raised is winlab's own fault, not the guest's: no back-off."""
    with _lock:
        ts = load(lab_name)
        if not raised:
            health(ts, job["pc"], not res.get("error"), seconds, time.time())
        ts.setdefault("log", []).append({
            "at": now, "who": person["id"], "name": person["name"], "dept": person.get("department", ""),
            "pc": job["pc"], "server": server_of(job, facts), "action": job["action"], "ok": bool(o.get("ok")),
            "bytes": int(res.get("bytes") or 0), "s": round(seconds, 1)})
        save(lab_name, ts)


# ===================================================== the calls, and when they stop
FAMILY = {"document": "share", "bigcopy": "share"}   # one broken folder, whichever way it was hit


def _open_ids(lab_name: str) -> set[str]:
    from . import helpdesk
    try:
        return {t["id"] for t in helpdesk.open_tickets(lab_name)}
    except Exception:  # noqa: BLE001 - a queue that cannot be read takes no notes
        return set()


def may_call(lab_name: str, key: str, pid: str, now: float) -> tuple[bool, str]:
    """(whether `pid` calls the helpdesk now about the broken thing `key`,
    the open ticket about it). Nobody calls twice within CALL_AGAIN."""
    with _lock:
        s = load(lab_name).get("streams", {}).get(key)
    if not s or s.get("ticket") not in _open_ids(lab_name):
        return True, ""
    last = s.get("people", {}).get(pid)
    if last is not None and 0 <= now - float(last) < CALL_AGAIN:
        return False, s["ticket"]
    return True, s["ticket"]


PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def escalation(n: int, priority: str) -> str:
    """The priority a ticket rises to when `n` people have called, or ""."""
    for need, pri in ESCALATE:
        if n >= need and PRIORITY_RANK.get(pri, 9) < PRIORITY_RANK.get(priority, 9):
            return pri
    return ""


def called(lab_name: str, key: str, action: str, scope: dict, person: dict, ticket: dict, now: float) -> None:
    """A person called about `key`: kept with the others who did, and the
    ticket raised when enough people are affected."""
    from . import helpdesk
    tid = ticket.get("id", "")
    if not tid:
        return
    with _lock:
        ts = load(lab_name)
        s = ts.setdefault("streams", {}).get(key)
        if not s or s.get("ticket") != tid:
            s = ts["streams"][key] = {"ticket": tid, "action": FAMILY.get(action, action), "scope": scope,
                                      "people": {}, "first": now, "last": now, "quiet": "",
                                      "summary": ticket.get("summary", "")}
        s["people"][person["id"]] = now
        s["last"], s["quiet"] = now, ""
        n = len(s["people"])
        save(lab_name, ts)
    with helpdesk._lock:
        q = helpdesk.load(lab_name)
        t = helpdesk.find(q, tid)
        if t is None or t["state"] not in helpdesk.OPEN_STATES:
            return
        t["affected"] = n
        pri = escalation(n, t["priority"])
        if pri:
            _, respond, resolve = helpdesk.PRIORITIES[pri]
            t["priority"], t["respond_by"], t["resolve_by"] = pri, t["opened"] + respond, t["opened"] + resolve
            t["log"].append({"at": now, "who": "workday", "kind": "state",
                             "text": f"{n} people have called about this now: raised to {pri} "
                                     f"({helpdesk.PRIORITIES[pri][0]})."})
        helpdesk.save(lab_name, q)


def _touches(scope: dict, person: dict, pc: str) -> bool:
    return all({"department": person.get("department", ""), "account": person["account"].lower(),
                "pc": pc}.get(k) == v for k, v in (scope or {}).items())


def _note(lab_name: str, notes: list[tuple[str, str]], now: float) -> None:
    from . import helpdesk
    if not notes:
        return
    with helpdesk._lock:
        q = helpdesk.load(lab_name)
        for tid, text in notes:
            t = helpdesk.find(q, tid)
            if t is not None and t["state"] in helpdesk.OPEN_STATES:
                t["log"].append({"at": now, "who": "workday", "text": text, "kind": "note"})
        helpdesk.save(lab_name, q)


def works_again(lab_name: str, action: str, person: dict, pc: str, text: str, now: float) -> None:
    """Someone did without trouble what a ticket's callers could not: the
    calls have stopped, said once on the ticket."""
    fam = FAMILY.get(action, action)
    notes = []
    with _lock:
        ts = load(lab_name)
        streams = ts.get("streams", {})
        hits = [s for s in streams.values() if s.get("action") == fam and not s.get("quiet")
                and _touches(s.get("scope", {}), person, pc)]
        if not hits:
            return
        open_ = _open_ids(lab_name)
        for s in hits:
            if s["ticket"] in open_:
                s["quiet"] = "works"
                notes.append((s["ticket"], f"The calls have stopped: at {hhmm(now)} {person['name']} {text} "
                                           "without trouble. Worth a word with the callers before resolving."))
        save(lab_name, ts)
    _note(lab_name, notes, now)


def housekeep(lab_name: str, now: float) -> None:
    """Forget the calls about tickets that are closed; note a ticket nobody
    has called about for QUIET_AFTER."""
    notes = []
    with _lock:
        ts = load(lab_name)
        streams = ts.get("streams", {})
        if not streams:
            return
        open_ = _open_ids(lab_name)
        for key in list(streams):
            s = streams[key]
            if s.get("ticket") not in open_:
                del streams[key]
            elif not s.get("quiet") and now - float(s.get("last") or now) >= QUIET_AFTER:
                s["quiet"] = "time"
                n = len(s.get("people", {}))
                notes.append((s["ticket"], f"No new calls about this since {hhmm(s['last'])} "
                                           f"({n} {'person' if n == 1 else 'people'} called in all)."))
        save(lab_name, ts)
    _note(lab_name, notes, now)


# ===================================================== the servers' work, run
def servers_only(lab, runner: Runner | None, now: float, running: set[str] | None = None) -> list[dict]:
    """The servers' own work with the workday off: real servers do not wait
    for the staff, so the nightly backup, the scans and replication run
    whenever the lab's machines run. Returns the events added."""
    with _lock:
        if not load(lab.name).get("background", True):
            return []
    from . import oncall, workday
    if running is None:
        running = set(oncall.running_nodes(lab))
    if not running:
        return []
    if runner is None:
        runner = oncall.guest_runner(lab.name)
    return background(lab, workday.lab_facts(lab), now, running, runner)


def background(lab, facts: dict, now: float, running: set[str], runner: Runner, used: set[str] | None = None,
               budget: float = TICK_BUDGET) -> list[dict]:
    """Starts the server jobs due now (at most BG_PER_TICK, none on a guest
    the staff used this tick or one backed off) and records what each said.
    Returns the events added."""
    with _lock:
        ts = load(lab.name)
        if not ts.get("background", True):
            return []
        due = due_background(ts, facts, now, running, set(used or ()) | held(ts, time.time()))[:BG_PER_TICK]
    made = []
    started = time.monotonic()
    for bg, node in due:
        # no time left is no time, even before Windows' coarse clock has moved
        if budget <= 0 or time.monotonic() - started > budget:
            break
        t0, raised = time.monotonic(), False
        try:
            ok, out = runner(node, background_command(bg), "powershell")
        except Exception as exc:  # noqa: BLE001 - one machine must not stop the rest
            ok, out, raised = False, f"{type(exc).__name__}: {exc}", True
        made.append(record_background(lab.name, bg, node, parse_background(ok, out), time.monotonic() - t0, now,
                                      raised))
    return made


def record_background(lab_name: str, bg: Background, node: str, r: dict, seconds: float, now: float,
                      raised: bool = False) -> dict:
    from . import helpdesk
    with _lock:
        ts = load(lab_name)
        if not raised:
            health(ts, node, r["state"] != "no answer", seconds, time.time())
        key = f"{bg.id}@{node}"
        rec = ts.setdefault("bg", {}).setdefault(key, {"last": 0.0, "state": "", "result": "", "ok": True})
        rec.update(last=now, state=r["state"], why=r.get("skip", ""))
        if r["result"]:
            rec.update(result=r["result"], ok=r["result"].startswith("ok"), result_at=now)
        text = {"started": f"{bg.title} started", "busy": f"{bg.title}: the last run is still going",
                "skipped": f"{bg.title} skipped: {r.get('skip', '')}",
                "no answer": f"{bg.title}: the machine did not answer"}[r["state"]]
        if raised:
            text = f"{bg.title}: winlab could not send it ({r.get('skip', '')[:120]})"
        if r["result"]:
            text += f"; last run: {r['result']}"
        ev = {"at": now, "node": node, "job": bg.id, "text": text, "ok": r["state"] != "no answer" and rec.get("ok", True)}
        ts.setdefault("events", []).append(ev)
        save(lab_name, ts)
    if r["result"] and not r["result"].startswith("ok") and bg.ticket:
        pri, cat, summary = bg.ticket
        helpdesk.open_ticket(lab_name, caller="admin", summary=summary, priority=pri, source="monitoring",
                             category=cat, node=node, dedupe=f"load:{bg.id}", now=now,
                             body=f"The monitoring saw {bg.title.lower()} fail on {node}: {r['result'][4:]}")
    return ev


# ======================================================================= controls
def set_profile(lab_name: str, profile: str) -> str:
    if profile not in PROFILES:
        raise ValueError(f"the profile is one of {', '.join(PROFILES)}")
    with _lock:
        ts = load(lab_name)
        ts["profile"] = profile
        save(lab_name, ts)
    return f"load profile: {PROFILES[profile].title} ({PROFILES[profile].text})"


def set_factor(lab_name: str, period: str, value) -> str:
    with _lock:
        ts = load(lab_name)
        prof = profile_of(ts)
        p = next((x for x in prof.periods if x.id == period), None)
        if p is None:
            raise ValueError(f"{prof.title} has no period {period!r}: {', '.join(x.id for x in prof.periods) or 'none'}")
        if value in (None, "", "reset"):
            ts.setdefault("factors", {}).pop(period, None)
            v = p.factor
        else:
            try:
                v = float(value)
            except (TypeError, ValueError):
                raise ValueError("the pace is a number from 0 to 5") from None
            if not math.isfinite(v) or not 0 <= v <= 5:
                raise ValueError("the pace is a number from 0 to 5")
            ts.setdefault("factors", {})[period] = round(v, 2)
        save(lab_name, ts)
    return f"{p.title}: pace x{_num(v)}"


def set_busy(lab_name: str, on: bool, label: str = "", now: float | None = None) -> str:
    from . import labclock
    with _lock:
        ts = load(lab_name)
        day = day_key(labclock.load(lab_name).now() if now is None else now)
        if on:
            ts["busy"] = {"day": day, "label": (label or "busy day").strip()[:60]}
        else:
            ts["busy"] = {}
        save(lab_name, ts)
    return (f"busy day on {day}: everyone works twice as hard until midnight" if on
            else "no busy day: the profile's own pace")


def set_background(lab_name: str, on: bool) -> str:
    with _lock:
        ts = load(lab_name)
        ts["background"] = bool(on)
        save(lab_name, ts)
    return ("the servers' own work on: backups at night, antivirus scans, indexing, update scans, replication"
            if on else "the servers' own work off: only the staff load the machines")


def _num(x: float) -> str:
    return str(int(x)) if float(x).is_integer() else str(round(x, 2))


# ========================================================================= view
def _window(bg: Background) -> str:
    return "all day" if bg.start == 0 and bg.end == 1440 else f"{bg.start // 60:02d}:{bg.start % 60:02d}–{bg.end // 60:02d}:{bg.end % 60:02d}"


def summary(lab, ts: dict, facts: dict, now: float) -> dict:
    """The activity per server, per person and per PC over the last lab
    hour and today, from the log. Pure on its arguments."""
    from . import naming
    hour, today = now - 3600, _midnight(now)
    servers: dict[str, dict] = {}
    people: dict[str, dict] = {}
    pcs: dict[str, dict] = {}
    for e in ts.get("log", []):
        at = float(e.get("at") or 0)
        if at < today or at > now + 60:
            continue
        for bucket, key in ((servers, e.get("server")), (pcs, e.get("pc"))):
            if not key:
                continue
            b = bucket.setdefault(key, {"hour": 0, "today": 0, "failed": 0, "bytes": 0, "actions": {}})
            b["today"] += 1
            if at >= hour:
                b["hour"] += 1
                b["bytes"] += int(e.get("bytes") or 0)
                b["actions"][e["action"]] = b["actions"].get(e["action"], 0) + 1
            if not e.get("ok"):
                b["failed"] += 1
        p = people.setdefault(e["who"], {"id": e["who"], "name": e.get("name", e["who"]), "dept": e.get("dept", ""),
                                         "today": 0, "failed": 0, "bytes": 0, "last": "", "last_at": 0.0})
        p["today"] += 1
        p["failed"] += 0 if e.get("ok") else 1
        p["bytes"] += int(e.get("bytes") or 0)
        if at >= p["last_at"]:
            p["last"], p["last_at"] = e["action"], at
    real = time.time()
    rows = []
    for n in lab.node_list():
        if n.id not in servers and n.id not in facts.get("windows", ()):
            continue
        g = ts.get("guests", {}).get(n.id, {})
        s = servers.get(n.id) or pcs.get(n.id) or {"hour": 0, "today": 0, "failed": 0, "bytes": 0, "actions": {}}
        rows.append({"node": n.id, "name": naming.display(lab, n.id), "pc": n.id in facts.get("pcs", ()),
                     **s, "held": float(g.get("until") or 0) > real,
                     "held_for": max(0, int(float(g.get("until") or 0) - real)), "why": g.get("why", ""),
                     "answer_s": g.get("s", 0)})
    return {"machines": rows, "people": sorted(people.values(), key=lambda p: -p["today"])}


def links(dash) -> dict:
    """Each cable's load from the live meters (winlab/perfmon.py), with a
    short history for its sparkline, and the load the staff put on it in
    the last ten lab minutes by the engine's own count."""
    from . import naming, perfmon
    lab = dash.lab
    try:
        mon = perfmon.monitor(dash)
        mon.watch(dash)
        cables, uplinks, at, machines = dict(mon.cables), dict(mon.uplinks), mon.at, dict(mon.machines)
    except Exception:  # noqa: BLE001 - no meters, no graph
        cables, uplinks, at, machines = {}, {}, 0.0, {}
    meters = {nid: {"running": m.get("running", False), "cpu": m.get("cpu_pct", 0),
                    "disk": m.get("disk", {}).get("rd_bps", 0) + m.get("disk", {}).get("wr_bps", 0),
                    "net": m.get("net", {}).get("rx_bps", 0) + m.get("net", {}).get("tx_bps", 0)}
              for nid, m in machines.items()}
    hist = _links.setdefault(lab.name, {})
    fresh_sample = at and at != _links_at.get(lab.name)
    _links_at[lab.name] = at
    out = []
    plan = getattr(dash, "plan", None)
    for link in (plan.ports if plan is not None else []):
        if not link.plugged:
            continue
        c = cables.get(link.label, {})
        bps = int(c.get("rx_bps", 0)) + int(c.get("tx_bps", 0))
        h = hist.setdefault(link.label, deque(maxlen=60))
        if fresh_sample:
            h.append(bps)
        out.append({"label": link.label, "node": link.node_id, "name": naming.display(lab, link.node_id),
                    "nic": link.nic_index, "network": link.network_id, "rx_bps": int(c.get("tx_bps", 0)),
                    "tx_bps": int(c.get("rx_bps", 0)), "up": bool(c.get("up", False)),
                    "errors_min": c.get("errors_min"), "hist": list(h)})
    return {"links": out, "uplinks": [{"network": k, **v} for k, v in uplinks.items()], "metered": bool(at),
            "meters": meters}


def view(lab, dash=None, real: float | None = None) -> dict:
    """GET /api/load: the profile and its curve, the pace now, the servers'
    jobs, the activity per machine and person, the cables, the calls."""
    from . import labclock, workday
    ts = load(lab.name)
    now = labclock.load(lab.name).now(real)
    facts = workday.lab_facts(lab)
    prof = profile_of(ts)
    p = pace(ts, now, held(ts, time.time()))
    running: set[str] = set()
    try:
        from . import oncall
        running = set(oncall.running_nodes(lab))
    except Exception:  # noqa: BLE001
        pass
    bgs = []
    for bg in BACKGROUND.values():
        for node in targets(bg, facts, set(facts.get("dc_nodes", ()))):
            rec = ts.get("bg", {}).get(f"{bg.id}@{node}", {})
            bgs.append({"id": bg.id, "title": bg.title, "text": bg.text, "node": node, "window": _window(bg),
                        "every": bg.every, "last": rec.get("last", 0), "state": rec.get("state", ""),
                        "result": rec.get("result", ""), "ok": rec.get("ok", True), "why": rec.get("why", ""),
                        "running": node in running,
                        "needs": bool(bg.needs) and not facts.get(bg.needs)})
    streams = [{"key": k, "ticket": s["ticket"], "summary": s.get("summary", ""), "people": len(s.get("people", {})),
                "last": s.get("last", 0), "quiet": s.get("quiet", "")} for k, s in ts.get("streams", {}).items()]
    out = {"ok": True, "now": now, "profile": prof.id, "factors": ts.get("factors", {}),
           "profiles": [{"id": x.id, "title": x.title, "text": x.text} for x in PROFILES.values()],
           "periods": [{"id": x.id, "title": x.title, "days": x.days, "from": x.start, "to": x.end,
                        "factor": factor_of(ts, x), "default": x.factor, "department": x.department,
                        "on": x in active(ts, now)} for x in prof.periods],
           "busy": busy_today(ts, now), "background": bool(ts.get("background", True)),
           "pace": {"factor": p["factor"], "reasons": p["reasons"], "dept": p["dept"], "cap": p["cap"]},
           "curve": curve(ts, _midnight(now)), "jobs": bgs, "streams": streams,
           "events": list(reversed(ts.get("events", [])[-40:])),
           **summary(lab, ts, facts, now)}
    out.update(links(dash) if dash is not None else {"links": [], "uplinks": [], "metered": False, "meters": {}})
    from . import freeload
    out["free"] = freeload.view(lab)   # started from inside the lab: from where, by whom, what was found
    return out


def act(dash, action: str, params: dict) -> dict:
    """The Office window's load-* actions."""
    lab = dash.lab
    if action.startswith("load-free-"):
        from . import freeload  # the load started from inside the lab (Start-OfficeLoad)
        return freeload.act(dash, action, params)
    try:
        if action == "load-profile":
            return {"ok": True, "message": set_profile(lab.name, str(params.get("profile", "")))}
        if action == "load-period":
            return {"ok": True, "message": set_factor(lab.name, str(params.get("period", "")), params.get("factor"))}
        if action == "load-busy":
            on = params.get("on") in (True, "1", "true", 1)
            return {"ok": True, "message": set_busy(lab.name, on, str(params.get("label", "")))}
        if action == "load-background":
            return {"ok": True, "message": set_background(lab.name, params.get("on") in (True, "1", "true", 1))}
    except ValueError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown action {action}"}


# ========================================================================== CLI
def add_cli(sub) -> None:
    p = sub.add_parser("load", help="the load engine: the office's pace over the day, busy days, the servers' "
                                    "own night work, and where the traffic goes")
    p.add_argument("what", choices=["status", "profile", "period", "busy", "background", "links",
                                    "discover", "free", "stick", "poll", "forget"])
    p.add_argument("arg", nargs="?", default="", help="profile: office, flat or round; period: its name; "
                                                       "busy and background: on or off; discover, free, stick, "
                                                       "poll and forget: the lab")
    p.add_argument("value", nargs="?", default="", help="period: its pace (0 to 5, or reset); busy: a name for the day")
    p.add_argument("--lab", default="")
    p.add_argument("--from", dest="origin", default="", help="discover: the machine to look around from "
                                                             "(default: where Start-OfficeLoad last ran)")


def _rate(bps: float) -> str:
    for unit, div in (("MB/s", 1e6), ("KB/s", 1e3)):
        if bps >= div:
            return f"{bps / div:.1f} {unit}"
    return f"{int(bps)} B/s"


def render(v: dict) -> str:
    prof = next(p for p in v["profiles"] if p["id"] == v["profile"])
    lines = [f"profile {prof['title']} · pace now x{_num(v['pace']['factor'])}"
             + (f" ({', '.join(v['pace']['reasons'])})" if v["pace"]["reasons"] else "")
             + f" · servers' own work {'on' if v['background'] else 'off'}", ""]
    if v["periods"]:
        lines.append("periods:")
        for x in v["periods"]:
            lines.append(f"  {'*' if x['on'] else ' '} {x['id']:<10} {x['title']:<22} {x['days']:<10} "
                         f"{x['from'] // 60:02d}:{x['from'] % 60:02d}-{x['to'] // 60:02d}:{x['to'] % 60:02d}  x{_num(x['factor'])}"
                         + (f" ({x['department']})" if x["department"] else ""))
        lines.append("")
    lines.append("machines (last lab hour):")
    for m in v["machines"]:
        lines.append(f"  {m['name']:<12} {m['hour']:>4} actions  {m['failed']:>3} failed today  {_rate(m['bytes'] / 3600):>10}"
                     + (f"  backing off: {m['why']}" if m["held"] else ""))
    lines += ["", "server jobs:"]
    for j in v["jobs"]:
        lines.append(f"  {j['title']:<30} {j['node']:<8} {j['window']:<12} "
                     f"{(hhmm(j['last']) + ' ' + j['state']) if j['last'] else 'not yet':<16} {j['result'][:60]}")
    if v["streams"]:
        lines += ["", "calls:"]
        for s in v["streams"]:
            lines.append(f"  {s['ticket']}  {s['people']} caller(s)  {s['summary']}" + ("  (calls stopped)" if s["quiet"] else ""))
    return "\n".join(lines)


def render_links(v: dict) -> str:
    if not v.get("metered"):
        return "no live meters yet: the cables' load shows while the desktop runs this lab (winlab gui)"
    lines = []
    for link in v["links"]:
        lines.append(f"  {link['name']:<12} nic{link['nic']} on {link['network']:<10} "
                     f"in {_rate(link['rx_bps']):>10}  out {_rate(link['tx_bps']):>10}  {'up' if link['up'] else 'down'}")
    return "\n".join(lines)


def run_cli(args) -> int:
    import sys
    from . import schema
    from .cli import _resolve_lab
    if args.what in ("discover", "free", "stick", "poll", "forget"):
        from . import freeload  # the load started from inside the lab
        return freeload.run_cli(args)
    try:
        lab = schema.load(_resolve_lab(args.lab))
    except Exception as exc:  # noqa: BLE001
        print(f"{exc}", file=sys.stderr)
        return 2
    try:
        if args.what == "profile":
            if args.arg:
                print(set_profile(lab.name, args.arg))
        elif args.what == "period":
            print(set_factor(lab.name, args.arg, args.value or "reset"))
        elif args.what == "busy":
            print(set_busy(lab.name, args.arg.lower() in ("on", "1", "yes", "true"), args.value))
        elif args.what == "background":
            print(set_background(lab.name, args.arg.lower() in ("on", "1", "yes", "true")))
        elif args.what == "links":
            print(render_links({"metered": False}))
            return 0
        print(render(view(lab)))
        return 0
    except ValueError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
