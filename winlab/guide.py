"""The guided first build: a step-by-step guide beside the Workbench.

A guide walks a new user through building a real network on the canvas
(a switch, the router's DHCP, a server installed by hand, a domain, a PC
that joins it) one step at a time. Each step says what to do and why in
plain words, names the place on the canvas or the machine to use (the page
points at it), and ticks itself by looking at the real thing:

  canvas steps   the lab definition (switch, cable, DHCP, machines)
  power steps    the machine's run state
  Windows steps  a PowerShell check run inside the machine over the serial
                 agent, judged the way exercise checks are

A machine installed by hand has no winlab agent, so the guide offers a
small check disc (burned with isowrite and put in its DVD drive) that
installs the same agent the ready-made machines run; until it is run the
Windows steps say so instead of guessing.

Guides are TOML in content/guides/; progress (the step the user is on, what
was skipped, what passed inside the machines and what was learnt there,
like the domain name) is per lab in var/guide.json, so the guide resumes
where it was after a restart.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import naming, paths, state

GUIDES = paths.CONTENT / "guides"
DEFAULT = "first-network"
VERSION = 1

# What ticks a step: the lab definition, the run state, or a check inside.
CANVAS = ("workbench", "switch", "routed", "dhcp", "machine", "cabled")
CHECKS = CANVAS + ("running", "guest")
STICKY = ("running", "guest")   # once seen, done: a server turned off later keeps its step
MATCH = ("exact", "contains", "regex", "in-subnet")
RECHECK_SECONDS = 15.0          # the pane's own re-checks inside a machine, at most this often
GUEST_TIMEOUT = 25.0            # a machine with no agent never answers: give up soon

_lock = threading.Lock()


class GuideError(Exception):
    pass


@dataclass
class Step:
    id: str
    title: str
    check: str
    text: str = ""
    why: str = ""
    point: str = ""          # where the page points: shelf:<id>, router, switch, machine:<on>, port:<on>, screen:<on>, button:<id>
    on: str = ""             # the machine the step is about, by shelf: server, pc
    show: list[str] = field(default_factory=list)   # "Show me": how, click by click
    commands: list[str] = field(default_factory=list)  # PowerShell the user may type instead (draggable onto the screen)
    script: str = ""         # guest: the check, run inside the machine
    expect: str = ""
    match: str = "exact"
    shell: str = "powershell"
    remember: str = ""       # guest: keep what the check printed as this fact
    else_expect: str = ""    # used when expect names a fact not learnt yet
    else_match: str = ""
    hint: str = ""
    disc: bool = False       # offers the check disc


@dataclass
class Guide:
    id: str
    title: str
    summary: str = ""
    lab: str = ""            # the name the new workbench gets
    done_text: str = ""
    steps: list[Step] = field(default_factory=list)

    def index(self, step_id: str) -> int:
        for i, s in enumerate(self.steps):
            if s.id == step_id:
                return i
        return -1


def guide_path(ident: str) -> Path:
    from . import content
    p = Path(ident)
    if p.suffix == ".toml" and content.exists(p):
        return p
    cand = GUIDES / f"{ident}.toml"
    if content.exists(cand):
        return cand
    if content.locked(cand):
        raise GuideError(f"the guide {ident} is part of the full version. {content.UNLOCK_HINT}")
    raise GuideError(f"guide not found: {ident}")


def load(ident: str = DEFAULT) -> Guide:
    from . import content
    path = guide_path(ident)
    raw = content.load_toml(path)
    meta = raw.get("guide")
    if not isinstance(meta, dict) or not meta.get("id"):
        raise GuideError(f"{path.name}: [guide] missing 'id'")
    steps, seen = [], set()
    for i, s in enumerate(raw.get("step", []), 1):
        sid, check = str(s.get("id", "")), str(s.get("check", ""))
        if not sid or sid in seen:
            raise GuideError(f"{path.name}: step {i} needs a unique 'id'")
        seen.add(sid)
        if check not in CHECKS:
            raise GuideError(f"{path.name}: step {sid}: unknown check {check!r} (use {', '.join(CHECKS)})")
        if check in ("machine", "cabled", "running", "guest") and not s.get("on"):
            raise GuideError(f"{path.name}: step {sid}: a {check} check needs 'on' (the machine)")
        if check == "guest" and not s.get("script"):
            raise GuideError(f"{path.name}: step {sid}: a guest check needs 'script'")
        if s.get("match", "exact") not in MATCH:
            raise GuideError(f"{path.name}: step {sid}: unknown match {s['match']!r}")
        strs = lambda k: [str(x).strip() for x in s.get(k, []) if str(x).strip()]  # noqa: E731
        steps.append(Step(
            id=sid, title=str(s.get("title", sid)), check=check, text=str(s.get("text", "")).strip(),
            why=str(s.get("why", "")).strip(), point=str(s.get("point", "")), on=str(s.get("on", "")),
            show=strs("show"), commands=strs("commands"), script=str(s.get("script", "")),
            expect=str(s.get("expect", "")), match=str(s.get("match", "exact")),
            shell=str(s.get("shell", "powershell")), remember=str(s.get("remember", "")),
            else_expect=str(s.get("else_expect", "")), else_match=str(s.get("else_match", "")),
            hint=str(s.get("hint", "")).strip(), disc=bool(s.get("disc", False))))
    if not steps:
        raise GuideError(f"{path.name}: no [[step]]")
    return Guide(id=str(meta["id"]), title=str(meta.get("title", meta["id"])),
                 summary=str(meta.get("summary", "")).strip(), lab=str(meta.get("lab", "")),
                 done_text=str(meta.get("done", "")).strip(), steps=steps)


# ------------------------------------------------------------------ progress
def progress_file() -> Path:
    return paths.VAR / "guide.json"


def _load_all() -> dict:
    try:
        raw = json.loads(progress_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = {}
    labs = raw.get("labs") if isinstance(raw, dict) else None
    return {"version": VERSION, "labs": {k: v for k, v in (labs or {}).items() if isinstance(v, dict)}}


def _save_all(data: dict) -> None:
    f = progress_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(f)


def _fresh(guide_id: str) -> dict:
    return {"guide": guide_id, "pos": 0, "held": "", "skipped": [], "done": {}, "checked": {},
            "bind": {}, "facts": {}, "open": True, "started": time.time()}


def entry_for(lab_name: str) -> dict | None:
    e = _load_all()["labs"].get(lab_name)
    if not e:
        return None
    base = _fresh(str(e.get("guide") or DEFAULT))
    base.update({k: v for k, v in e.items() if k in base})
    return base


def put_entry(lab_name: str, entry: dict) -> None:
    data = _load_all()
    data["labs"][lab_name] = entry
    _save_all(data)


# ------------------------------------------------------------------ binding
def _shelf_of(node) -> str:
    from . import workbench
    return workbench._shelf_of(node)


def bind(lab, entry: dict) -> dict:
    """Which switch and which machines the guide's steps mean: the ones it
    chose before while they are still on the canvas, else the first that
    fits (a routed switch first, a hand-installed machine first)."""
    from . import devcli, images
    b = dict(entry.get("bind") or {})
    top = devcli.switches(lab)
    if b.get("switch") not in top:
        b.pop("switch", None)
        ranked = sorted(top, key=lambda n: (not lab.networks[n].routed, n))
        if ranked:
            b["switch"] = ranked[0]
    for shelf in ("server", "pc"):
        cur = lab.nodes.get(b.get(shelf, ""))
        if cur is None or _shelf_of(cur) != shelf:
            b.pop(shelf, None)
            fits = sorted((n for n in lab.node_list() if _shelf_of(n) == shelf),
                          key=lambda n: (not images.is_hand_install(n), n.id))
            if fits:
                b[shelf] = fits[0].id
    entry["bind"] = b
    return b


def facts(lab, entry: dict) -> dict[str, str]:
    """What the steps' words and checks may name: {switch}, {server}, {pc},
    the switch's subnet and a free address for the server, and what was
    learnt inside the machines ({domain}, {server_ip})."""
    from . import netplan
    b = entry.get("bind") or {}
    out = {"switch": b.get("switch", "the switch"), "server": "the server", "pc": "the PC",
           "cidr": "", "gateway": "", "mask": "", "prefix": "", "suggest_ip": "", "pool": "", "reserved": ""}
    for shelf in ("server", "pc"):
        if b.get(shelf):
            out[shelf] = naming.display(lab, b[shelf])
    net = lab.networks.get(b.get("switch", ""))
    if net is not None:
        hosts = list(net.net.hosts())
        lo, hi = netplan.dhcp_range(net)
        out.update(cidr=net.cidr, gateway=net.router_ip, mask=net.netmask, prefix=str(net.prefixlen),
                   suggest_ip=str(hosts[min(9, len(hosts) - 1)]) if hosts else "", pool=f"{lo} to {hi}",
                   # The low addresses kept for servers: the student excludes
                   # them from the router's pool (ip dhcp excluded-address).
                   reserved=f"{hosts[1]} to {hosts[min(9, len(hosts) - 1)]}" if len(hosts) > 2 else "")
    learnt = {k: str(v) for k, v in (entry.get("facts") or {}).items()}
    out["server_ip"] = learnt.get("server_ip") or out["suggest_ip"]
    out["domain"] = learnt.get("domain") or "corp.lab"
    out["learnt"] = ",".join(sorted(learnt))
    out.update({f"learnt_{k}": v for k, v in learnt.items()})
    return out


def fill(text: str, f: dict[str, str]) -> str:
    return re.sub(r"\{([a-z_]+)\}", lambda m: f.get(m.group(1), m.group(0)), text)


# ------------------------------------------------------------------ checks
def _plugged_on(lab, node, sw: str) -> bool:
    for nic in node.nics:
        if nic.plugged and nic.network in lab.networks and (not sw or lab.networks[nic.network].home == sw):
            return True
    return False


def canvas_check(step: Step, lab, b: dict, running: set[str]) -> tuple[bool, str]:
    """A step the lab definition or the run state answers: (done, why not)."""
    sw = b.get("switch", "")
    net = lab.networks.get(sw)
    node = lab.nodes.get(b.get(step.on, "")) if step.on else None
    what = {"server": "a server", "pc": "a PC"}.get(step.on, step.on)
    if step.check == "workbench":
        return bool(lab.workbench), "this network is a lesson lab, not one built on the workbench"
    if step.check == "switch":
        return net is not None, "no switch on the canvas yet"
    if step.check == "routed":
        if net is None:
            return False, "add a switch first"
        return bool(net.routed and not net.upstream), f"{sw}'s uplink is not in the router"
    if step.check == "dhcp":
        if net is None or not net.routed:
            return False, f"cable {sw or 'the switch'} to the router first"
        return bool(net.dhcp), f"the router does not hand out addresses on {sw} yet"
    if node is None:
        return False, f"no {what} on the canvas yet"
    if step.check == "machine":
        return True, ""
    if step.check == "cabled":
        return _plugged_on(lab, node, sw), f"{naming.display(lab, node.id)} has no cable into {sw or 'a switch'}"
    if step.check == "running":
        return node.id in running, f"{naming.display(lab, node.id)} is off"
    return False, ""


def expectation(step: Step, f: dict[str, str]) -> tuple[str, str]:
    """What a guest check's output must be, with facts filled in; the
    fallback when it names a fact the guide has not learnt yet."""
    names = re.findall(r"\{([a-z_]+)\}", step.expect)
    learnt = set(filter(None, f.get("learnt", "").split(",")))
    if step.else_expect and any(n in ("domain", "server_ip") and n not in learnt for n in names):
        return fill(step.else_expect, f), step.else_match or step.match
    return fill(step.expect, f), step.match


def judge(step: Step, out: str, f: dict[str, str], rc: int = 0) -> tuple[bool, str]:
    """Whether a guest check passed, and the value it found (what a
    `remember` step keeps). Matching is the exercises' own; in-subnet wants
    an address in the switch's subnet that is not the router's."""
    from .exercises import Check, output_matches
    lines = [ln.strip() for ln in (out or "").strip().splitlines() if ln.strip()]
    if rc != 0:
        return False, lines[-1] if lines else f"rc={rc}"
    expect, match = expectation(step, f)
    if match == "in-subnet":
        try:
            net = ipaddress.ip_network(f.get("cidr") or "", strict=False)
        except ValueError:
            return False, "no switch to compare with"
        for ln in lines:
            try:
                ip = ipaddress.ip_address(ln)
            except ValueError:
                continue
            if ip in net and str(ip) != f.get("gateway"):
                return True, str(ip)
        return False, ", ".join(lines) or "no fixed address"
    ok = output_matches(Check(name=step.id, node="", script="", expect=expect, match=match), out)
    return ok, lines[-1] if lines else ""


def guest_runner(lab_name: str):
    """run(node, script, shell) -> (reached, rc, out) over the serial agent.
    A machine with no agent accepts the connection and never answers, so
    the wait is short and `reached` False says so."""
    from .guestctl import GuestChannel, GuestError

    def run(node_id: str, script: str, shell: str) -> tuple[bool, int, str]:
        st = state.load(lab_name)
        ns = st.nodes.get(node_id) if st else None
        if not ns or not ns.serial_port or not state.pid_alive(ns.pid):
            return False, 1, "not running"
        try:
            ch = GuestChannel(ns.serial_port, timeout=10).connect(retries=1)
        except GuestError as exc:
            return False, 1, str(exc)
        try:
            res = ch.run(script, shell=shell, timeout=GUEST_TIMEOUT)
        except GuestError as exc:
            return False, 1, str(exc)
        finally:
            ch.close()
        return True, res.rc, res.out if res.out.strip() or res.rc == 0 else res.err
    return run


def _running(lab_name: str) -> set[str]:
    st = state.load(lab_name)
    return {n for n, ns in (st.nodes.items() if st else []) if ns.pid and state.pid_alive(ns.pid)}


def evaluate(guide: Guide, lab, entry: dict, running: set[str]) -> list[dict]:
    """Every step's state from the lab and the record: done, skipped or to
    do, and why not. Canvas steps are read live; power and Windows steps
    stay done once seen (entry['done']); the record is updated in place."""
    b = bind(lab, entry)
    done = entry.setdefault("done", {})
    out = []
    for s in guide.steps:
        rec = done.get(s.id)
        if s.check in CANVAS or s.check == "running":
            ok, why = canvas_check(s, lab, b, running)
            if s.check == "running" and ok and not rec:
                rec = done[s.id] = {"at": time.time(), "detail": f"{naming.display(lab, b[s.on])} was on"}
            ok = ok or (s.check in STICKY and bool(rec))
        else:
            node = b.get(s.on, "")
            ok = bool(rec)
            last = (entry.get("checked") or {}).get(s.id) or {}
            if ok:
                why = ""
            elif not node:
                why = f"no {'server' if s.on == 'server' else 'PC'} on the canvas yet"
            elif node not in running:
                why = f"{naming.display(lab, node)} is off: power it on"
            else:
                why = last.get("detail") or "not checked yet"
        state_ = "done" if ok else ("skipped" if s.id in (entry.get("skipped") or []) else "todo")
        out.append({"id": s.id, "state": state_, "why": "" if ok else why,
                    "detail": (rec or {}).get("detail", "") if ok else ""})
    return out


def first_open(states: list[dict], start: int = 0) -> int:
    """The first step from `start` that is neither done nor skipped; the end
    when there is none."""
    for i in range(max(0, start), len(states)):
        if states[i]["state"] == "todo":
            return i
    return len(states)


def advance(entry: dict, states: list[dict]) -> int:
    """Moves past the step the user is on once it is done (to the next one
    still to do), and back to an earlier step that came undone (a cable
    pulled out); a skipped step stays behind. A done step the user went
    back to look at (entry['held']) stays on screen until Next."""
    pos = int(entry.get("pos") or 0)
    pos = max(0, min(pos, len(states)))
    earlier = first_open(states)
    held = pos < len(states) and entry.get("held") == states[pos]["id"]
    if earlier < pos:
        pos = earlier
    elif pos < len(states) and states[pos]["state"] == "done" and not held:
        pos = first_open(states, pos)
    if pos >= len(states) or entry.get("held") != states[pos]["id"]:
        entry["held"] = ""
    entry["pos"] = pos
    return pos


def _go(entry: dict, states: list[dict], to: int) -> None:
    """The user moved to a step (Back, Next or a click in the list)."""
    to = max(0, min(len(states), to))
    entry["pos"] = to
    entry["held"] = states[to]["id"] if to < len(states) and states[to]["state"] == "done" else ""


def check_step(guide: Guide, lab, entry: dict, step: Step, run, running: set[str]) -> dict:
    """Runs a Windows step's check inside its machine and records it."""
    b = bind(lab, entry)
    node = b.get(step.on, "")
    f = facts(lab, entry)
    checked = entry.setdefault("checked", {})
    if step.check != "guest":
        return {"ok": False, "message": f"{step.title} is checked on the canvas, not inside a machine"}
    if not node:
        return {"ok": False, "message": f"there is no {step.on} on the canvas yet"}
    if node not in running:
        return {"ok": False, "message": f"{naming.display(lab, node)} is off: power it on first"}
    reached, rc, out = run(node, fill(step.script, f), step.shell)
    if not reached:
        detail = (f"winlab cannot see inside {naming.display(lab, node)} yet: when Windows is at its desktop, "
                  f"put in the check disc and run it (Show me)")
        checked[step.id] = {"at": time.time(), "ok": False, "detail": detail}
        return {"ok": False, "passed": False, "reached": False, "message": detail}
    ok, found = judge(step, out, f, rc)
    if ok:
        entry.setdefault("done", {})[step.id] = {"at": time.time(), "detail": found}
        if step.remember and found:
            entry.setdefault("facts", {})[step.remember] = found
        checked[step.id] = {"at": time.time(), "ok": True, "detail": found}
        return {"ok": True, "passed": True, "reached": True, "message": f"{step.title}: done ({found})" if found else f"{step.title}: done"}
    detail = f"not yet (it says {found})" if found else "not yet"
    if step.hint:
        detail += f"; hint: {fill(step.hint, f)}"
    checked[step.id] = {"at": time.time(), "ok": False, "detail": detail}
    return {"ok": True, "passed": False, "reached": True, "message": detail}


# ------------------------------------------------------------------ the check disc
def disc_files() -> dict[str, str]:
    """What the check disc holds: the winlab agent and the script that
    installs it as a startup task (the one setup-agent.ps1 registers on a
    ready-made machine, without its other settings). No facts.json, so
    apply-network leaves the addresses the user set alone."""
    agent = paths.CONTENT / "agent"
    files = {n: (agent / n).read_text(encoding="utf-8") for n in ("winlab-agent.ps1", "apply-network.ps1")}
    files["install-checks.ps1"] = INSTALL_PS1
    files["RUN-ME.cmd"] = RUN_ME_CMD
    files["README.txt"] = README_TXT
    return files


INSTALL_PS1 = r"""# Lets winlab's guide check this machine: copies the winlab agent to
# C:\winlab and starts it at every boot. It talks only over COM1, the
# machine's serial port, never the network.
$ErrorActionPreference = 'Stop'
$Root = 'C:\winlab'
New-Item -ItemType Directory -Path $Root -Force | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'winlab-agent.ps1'), (Join-Path $PSScriptRoot 'apply-network.ps1') -Destination $Root -Force
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Root\winlab-agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'winlab-agent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'winlab-agent'
Write-Output 'winlab can check this machine now. You can take the disc out.'
"""

RUN_ME_CMD = """@echo off
rem Right-click, Run as administrator.
net session >nul 2>&1 || (echo Right-click RUN-ME and choose Run as administrator. & pause & exit /b 1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-checks.ps1"
pause
"""

README_TXT = """winlab check disc

The guide beside the Workbench checks your work inside this machine. To let
it, right-click RUN-ME on this disc and choose Run as administrator. It
installs winlab's agent, which answers the guide over this machine's serial
port (never the network) and starts with Windows.
"""


def burn_disc(lab_name: str, node_id: str) -> Path:
    from . import isowrite
    dest = paths.lab_dir(lab_name) / node_id / "guide-checks.iso"
    src = dest.parent / "guide-checks"
    src.mkdir(parents=True, exist_ok=True)
    for name, text in disc_files().items():
        (src / name).write_text(text.replace("\r\n", "\n").replace("\n", "\r\n"), encoding="utf-8", newline="")
    w = isowrite.IsoWriter("WINLAB_CHECKS")
    w.add_tree(src)
    tmp = dest.with_suffix(".tmp")
    w.write(tmp)
    tmp.replace(dest)
    return dest


# ------------------------------------------------------------------ the pane
def _step_view(s: Step, st: dict, f: dict[str, str], last: dict) -> dict:
    # "Show me" and the commands to type are the step's answer: they open
    # once the step was skipped or a check of it failed (or it is done).
    shown = st["state"] in ("done", "skipped") or last.get("ok") is False
    return {"id": s.id, "title": fill(s.title, f), "text": fill(s.text, f), "why": fill(s.why, f),
            "point": s.point, "on": s.on, "show": [fill(x, f) for x in s.show] if shown else [],
            "commands": [fill(x, f) for x in s.commands] if shown else [], "check": s.check,
            "show_open": shown,
            "inside": s.check == "guest", "disc": s.disc, "state": st["state"], "why_not": st["why"],
            "detail": st["detail"], "checked_at": float(last.get("at") or 0)}


def view(dash, guide_id: str = "") -> dict:
    """The pane: the guide's steps with their state, the step the user is
    on, and the machines the steps mean."""
    lab = dash.lab
    with _lock:
        entry = entry_for(lab.name)
        started = entry is not None
        entry = entry or _fresh(guide_id or DEFAULT)
        guide = load(entry["guide"])
        running = _running(lab.name)
        before = json.dumps(entry, sort_keys=True)
        states = evaluate(guide, lab, entry, running)
        pos = advance(entry, states)
        if started and json.dumps(entry, sort_keys=True) != before:
            put_entry(lab.name, entry)
    f = facts(lab, entry)
    b = entry.get("bind") or {}
    return {"guide": guide.id, "title": guide.title, "summary": guide.summary, "lab": lab.name,
            "started": started, "open": bool(entry.get("open")) and started,
            "workbench": lab.workbench, "pos": pos, "finished": pos >= len(guide.steps),
            "done": sum(1 for s in states if s["state"] == "done"), "total": len(guide.steps),
            "done_text": fill(guide.done_text, f), "bind": b,
            "running": sorted(n for n in running if n in b.values()),
            "steps": [_step_view(s, st, f, (entry.get("checked") or {}).get(s.id) or {})
                      for s, st in zip(guide.steps, states)]}


def act(dash, action: str, params: dict, runner=None) -> dict:
    try:
        return _act(dash, action, params, runner)
    except (GuideError, OSError, ValueError) as exc:
        return {"ok": False, "message": str(exc)}


def _act(dash, action: str, params: dict, runner) -> dict:
    lab = dash.lab
    if action == "guide-start":
        guide = load(params.get("guide") or DEFAULT)
        with _lock:
            entry = entry_for(lab.name)
            if entry is None or params.get("restart"):
                entry = _fresh(guide.id)
            entry["open"] = True
            put_entry(lab.name, entry)
        return {"ok": True, "message": f"{guide.title}: {guide.summary}" if guide.summary else guide.title}
    if action == "guide-check":
        return _check(dash, params, runner)
    with _lock:
        entry = entry_for(lab.name)
        if entry is None:
            return {"ok": False, "message": "no guide started on this network"}
        guide = load(entry["guide"])
        running = _running(lab.name)
        states = evaluate(guide, lab, entry, running)
        pos = advance(entry, states)
        n = len(guide.steps)
        msg = ""
        if action == "guide-back":
            _go(entry, states, pos - 1)
        elif action == "guide-next":
            _go(entry, states, pos + 1)
        elif action == "guide-goto":
            _go(entry, states, int(params.get("step", pos)))
        elif action == "guide-skip":
            if pos < n:
                sk = entry.setdefault("skipped", [])
                if guide.steps[pos].id not in sk:
                    sk.append(guide.steps[pos].id)
                if states[pos]["state"] != "done":
                    states[pos]["state"] = "skipped"
                entry["pos"], entry["held"] = first_open(states, pos + 1), ""
                msg = f"skipped: {guide.steps[pos].title}"
        elif action in ("guide-open", "guide-close"):
            entry["open"] = action == "guide-open"
        elif action == "guide-disc":
            i = int(params.get("step", pos))
            step = guide.steps[max(0, min(n - 1, i))]
            node = bind(lab, entry).get(step.on or str(params.get("on") or ""), "")
            if not node:
                return {"ok": False, "message": "no machine for the check disc yet"}
            put_entry(lab.name, entry)
            return _disc(dash, node)
        elif action == "guide-reset":
            entry = _fresh(guide.id)
        else:
            return {"ok": False, "message": f"unknown guide action {action!r}"}
        put_entry(lab.name, entry)
    return {"ok": True, "message": msg}


def _check(dash, params: dict, runner) -> dict:
    """A Windows step's check, run outside the lock: a machine with no agent
    takes GUEST_TIMEOUT to say nothing, and the pane keeps polling meanwhile."""
    lab = dash.lab
    with _lock:
        entry = entry_for(lab.name)
        if entry is None:
            return {"ok": False, "message": "no guide started on this network"}
        guide = load(entry["guide"])
        running = _running(lab.name)
        pos = advance(entry, evaluate(guide, lab, entry, running))
        i = int(params.get("step", pos))
        if not 0 <= i < len(guide.steps):
            return {"ok": False, "message": "no such step"}
        step = guide.steps[i]
        last = (entry.get("checked") or {}).get(step.id) or {}
        if params.get("auto") and time.time() - float(last.get("at") or 0) < RECHECK_SECONDS:
            return {"ok": True, "passed": False, "message": last.get("detail", ""), "waited": True}
        node, f = bind(lab, entry).get(step.on, ""), facts(lab, entry)
    got = None
    if step.check == "guest" and node in running:
        got = (runner or guest_runner(lab.name))(node, fill(step.script, f), step.shell)
    with _lock:
        entry = entry_for(lab.name) or entry
        res = check_step(guide, lab, entry, step, lambda *_a: got, running)
        advance(entry, evaluate(guide, lab, entry, running))
        put_entry(lab.name, entry)
    return res


def _disc(dash, node_id: str) -> dict:
    from . import media
    lab = dash.lab
    iso = burn_disc(lab.name, node_id)
    try:
        live = media.insert(lab.name, node_id, iso)
    except media.MediaError as exc:
        return {"ok": False, "message": str(exc)}
    who = naming.display(lab, node_id)
    if not live:
        return {"ok": False, "message": f"{who} is off: power it on, then put the check disc in"}
    return {"ok": True, "message": f"the check disc is in {who}'s DVD drive: open it in File Explorer, "
                                   f"right-click RUN-ME and choose Run as administrator"}
