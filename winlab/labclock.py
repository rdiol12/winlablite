"""The lab's own clock: follows real time until the student moves it.

The lab clock can be paused, jumped ahead (an hour, to 02:00 tonight, a day, a
week, to a date) or set, and put back on real time. Whatever happens inside
the machines at a time (scheduled tasks, backups, certificates and passwords
expiring, Kerberos tickets running out, the evaluation licence) then happens
when the lab clock gets there.

How a machine gets lab time:
- At power-on, from its RTC. QEMU starts the RTC at lab time (`-rtc
  base=<lab time>,clock=vm`) and it runs while the machine runs: paused with
  the lab clock, it stands still too, so a restart inside the same QEMU
  (which rereads the RTC) still lands on lab time. Windows reads the RTC as
  local time (base=localtime is what winlab always gave it); Linux machines
  and the router read it as UTC. A machine resuming from hibernation reads
  it too.
- While it runs, from inside. A running guest reads its RTC only at boot and
  resume, and QMP has no setter for it, so winlab sets the time over the
  serial agent: Set-Date on Windows, date on Linux and the router. The
  domain's time authority goes first (the forest root DC, then the other
  DCs), then the members, which resync from their DC (w32tm /resync) so
  w32time agrees instead of pulling them back. A machine whose agent does not
  answer (still installing, an appliance driven over its console, an OS
  installed by hand) keeps its own time until its next power-on.
- Pause: a running PC's clock cannot stop, so pausing the lab clock pauses the
  lab's running machines too (QMP stop, like Hyper-V's Pause). Resume
  continues them and sets their clocks to lab time again. Starting, restarting
  or suspending a machine resumes a paused clock first: a lab that was off
  starts at the time it was paused at.

Nothing syncs with this PC or the internet: the PDC's upstream
(time.windows.com) is outside the lab, so it serves its own clock; members
follow the domain hierarchy; the router runs no NTP client. A lab with an
NTP server (winlab/timesync.py) has its time set first: it serves its own
clock, lab time, and the PDC syncs from it. One machine can run off lab time
on purpose (its skew), at power-on and when the clock moves.

Checkpoints hold disks, not time: reverting one restarts machines at the
current lab time, so the clock never runs backwards on its own. The lab time
each checkpoint was taken at is kept, for going back to it on purpose.

The clock lives beside the lab's disks (var/labs/<lab>/clock.json), so it
outlasts `lab down` like they do.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

from . import paths

Runner = Callable[[str, str, str], tuple[bool, str]]

TONIGHT = (2, 0)          # "tonight" is the next 02:00, when nightly jobs run
IN_STEP = 1.0             # seconds of offset still counted as real time

_UNITS = {"s": 1, "sec": 1, "m": 60, "min": 60, "mins": 60, "h": 3600, "hr": 3600,
          "hour": 3600, "hours": 3600, "d": 86400, "day": 86400, "days": 86400,
          "w": 604800, "week": 604800, "weeks": 604800}
_AMOUNT = re.compile(r"^\+?\s*(\d+(?:\.\d+)?)\s*([a-z]+)$")
_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M", "%Y-%m-%d")
_REAL = ("real", "normal", "now")


@dataclass
class Clock:
    anchor_real: float = 0.0   # lab time = anchor_lab + (real - anchor_real)
    anchor_lab: float = 0.0
    paused: bool = False
    held: list[str] = field(default_factory=list)          # machines paused with the clock
    checkpoints: dict[str, float] = field(default_factory=dict)  # tag -> lab time
    machines: dict[str, str] = field(default_factory=dict)  # what the last change did

    def now(self, real: float | None = None) -> float:
        real = time.time() if real is None else real
        return self.anchor_lab if self.paused else self.anchor_lab + (real - self.anchor_real)

    def offset(self, real: float | None = None) -> float:
        real = time.time() if real is None else real
        return self.now(real) - real

    def following(self, real: float | None = None) -> bool:
        return not self.paused and abs(self.offset(real)) < IN_STEP


# ------------------------------------------------------------------ storage
def clock_file(lab_name: str):
    return paths.lab_dir(lab_name) / "clock.json"


def load(lab_name: str) -> Clock:
    try:
        raw = json.loads(clock_file(lab_name).read_text(encoding="utf-8"))
        known = set(Clock.__dataclass_fields__)
        return Clock(**{k: v for k, v in raw.items() if k in known})
    except (OSError, ValueError, TypeError):
        return Clock()


def save(lab_name: str, c: Clock) -> None:
    f = clock_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(c), indent=2), encoding="utf-8")
    tmp.replace(f)


# --------------------------------------------------------------- time math
def pause(c: Clock, real: float) -> None:
    c.anchor_lab, c.anchor_real, c.paused = c.now(real), real, True


def resume(c: Clock, real: float) -> None:
    c.anchor_lab, c.anchor_real, c.paused = c.now(real), real, False


def move_to(c: Clock, lab: float, real: float) -> None:
    """Lab time becomes `lab` now; a paused clock stays paused there."""
    c.anchor_lab, c.anchor_real = float(lab), real


def follow_real(c: Clock) -> None:
    c.anchor_lab = c.anchor_real = 0.0
    c.paused = False


def parse_amount(text: str) -> float | None:
    """'1h', '90 min', '2d', '+1 week' -> seconds; None if it is not an amount."""
    m = _AMOUNT.match(text.strip().lower())
    if not m or m.group(2) not in _UNITS:
        return None
    return float(m.group(1)) * _UNITS[m.group(2)]


def next_at(lab: float, hour: int, minute: int = 0) -> float:
    """The next hour:minute on the lab's wall clock, strictly after `lab`."""
    t = time.localtime(lab)
    day = (t.tm_year, t.tm_mon, t.tm_mday)
    for add in range(0, 3):
        cand = time.mktime((day[0], day[1], day[2] + add, hour, minute, 0, 0, 0, -1))
        if cand > lab:
            return cand
    raise ValueError("no such time")


def parse_when(text: str, lab: float) -> float:
    """A wall-clock time on the lab's clock: '2026-12-24 09:00', '2026-12-24',
    'HH:MM' (the next one), or 'tonight'."""
    s = text.strip()
    if s.lower() == "tonight":
        return next_at(lab, *TONIGHT)
    m = re.match(r"^(\d{1,2}):(\d{2})$", s)
    if m and int(m.group(1)) < 24 and int(m.group(2)) < 60:
        return next_at(lab, int(m.group(1)), int(m.group(2)))
    for fmt in _FORMATS:
        try:
            return time.mktime(time.strptime(s, fmt))
        except ValueError:
            continue
    raise ValueError(f"{text!r}: give an amount (1h, 2d, 1w), 'tonight', HH:MM "
                     f"or a date like 2026-12-24 09:00")


def target(spec: str, c: Clock, real: float, ahead_only: bool = False) -> float:
    """Where `jump`/`set` puts the lab clock. A jump only goes ahead."""
    now = c.now(real)
    amount = parse_amount(spec)
    if amount is not None:
        return now + amount
    if spec.strip().lower() in _REAL:
        return real
    when = parse_when(spec, now)
    if ahead_only and when <= now:
        raise ValueError(f"{spec}: that is not ahead of lab time "
                         f"({stamp(now)}); use 'winlab clock set' to go back")
    return when


def stamp(lab: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lab))


def describe_offset(seconds: float) -> str:
    if abs(seconds) < IN_STEP:
        return "in step with real time"
    s, left = abs(int(round(seconds))), []
    for name, size in (("w", 604800), ("d", 86400), ("h", 3600), ("min", 60)):
        if s >= size:
            left.append(f"{s // size} {name}")
            s %= size
    text = " ".join(left[:2]) or f"{s} s"
    return f"{text} {'ahead of' if seconds > 0 else 'behind'} real time"


def rtc_arg(c: Clock, utc: bool, real: float | None = None) -> str:
    """QEMU's -rtc value: the RTC starts at lab time and runs while the
    machine runs (clock=vm), so it stands still while the lab clock is paused,
    as the lab clock does. On real time the base is QEMU's own utc/localtime."""
    real = time.time() if real is None else real
    if c.following(real):
        return f"base={'utc' if utc else 'localtime'},clock=vm"
    lab = c.now(real)
    when = time.gmtime(lab) if utc else time.localtime(lab)
    return f"base={time.strftime('%Y-%m-%dT%H:%M:%S', when)},clock=vm"


# ----------------------------------------------------------- machines
def set_command(shell: str, lab: float) -> str:
    """The command that puts a running machine's clock at `lab`."""
    if shell == "sh":
        return (f"date -u -s '{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(lab))}' "
                f">/dev/null && echo ok")
    wall = stamp(lab)
    return (f"$t = [datetime]::ParseExact('{wall}', 'yyyy-MM-dd HH:mm:ss', "
            f"[Globalization.CultureInfo]::InvariantCulture); Set-Date -Date $t | Out-Null; "
            f"w32tm /resync /nowait 2>&1 | Out-Null; 'ok'")


def apply_order(lab, running: dict[str, str]) -> list[tuple[str, str]]:
    """(machine, shell) in the order their clocks are set: the time authority
    first, members after their DCs, the router last. Shell '' means the
    machine has no agent to ask and takes lab time at its next power-on."""
    from .appliances import console_driven
    from .model import LINUX

    out: list[tuple[int, str, str]] = []
    for nid, phase in running.items():
        node = lab.nodes.get(nid)
        if nid == "fabric":
            out.append((4, nid, "sh"))
        elif node is not None and "ntp-server" in node.roles and phase != "installing":
            out.append((-1, nid, "sh"))   # the lab's NTP server: the PDC syncs from it
        elif node is None or phase == "installing":
            out.append((5, nid, ""))
        elif node.is_windows:
            rank = (0 if node.vars.get("forest_root") else 1) if "ad-ds" in node.roles else 2
            out.append((rank, nid, "powershell"))
        elif node.kind == LINUX and not console_driven(node.image):
            out.append((3, nid, "sh"))
        else:
            out.append((5, nid, ""))
    return [(nid, sh) for _r, nid, sh in sorted(out, key=lambda x: (x[0], x[1]))]


NEXT_ON = "takes lab time at its next power-on"


def _skew(lab_name: str, node_id: str) -> float:
    from .timesync import skew_of
    return skew_of(lab_name, node_id)


def apply(lab, c: Clock, running: dict[str, str], runner: Runner,
          real: Callable[[], float] = time.time, emit=lambda _l: None) -> dict[str, str]:
    """Sets every running machine to lab time; returns what happened on each."""
    done: dict[str, str] = {}
    from .vmctl import service_on
    for nid, shell in apply_order(lab, running):
        if not shell:
            done[nid] = NEXT_ON
            continue
        node = lab.nodes.get(nid)
        if node is not None and not service_on(node, "time"):
            # Time synchronization is off in its settings (Integration
            # Services): its clock is left to the machine.
            done[nid] = "time synchronization is off in its settings: its clock is left alone"
            emit(f"{nid}: {done[nid]}")
            continue
        # each one at the moment it is asked, plus its own skew (timesync)
        when = c.now(real()) + _skew(lab.name, nid)
        try:
            ok, out = runner(nid, set_command(shell, when), shell)
        except Exception as exc:  # noqa: BLE001 - one machine must not stop the rest
            ok, out = False, str(exc)
        done[nid] = f"set to {stamp(when)}" if ok else \
            f"{NEXT_ON} (agent: {(out or 'no answer').strip()[:80]})"
        emit(f"{nid}: {done[nid]}")
    return done


def guest_runner(lab_name: str, timeout: float = 45.0) -> Runner:
    """Setting a clock is quick: a machine that has not answered within
    `timeout` is not going to, and takes lab time at its next power-on."""
    from . import state
    from .guestctl import GuestChannel, GuestError

    def run(node: str, cmd: str, shell: str) -> tuple[bool, str]:
        st = state.load(lab_name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return False, f"{node} is not running"
        try:
            with GuestChannel(ns.serial_port, timeout=10).connect(retries=2, delay=1) as ch:
                res = ch.run(cmd, shell=shell, timeout=timeout)
        except GuestError as exc:
            return False, str(exc)
        return res.ok, res.out
    return run


def _running(lab_name: str) -> dict[str, "object"]:
    from . import state
    st = state.load(lab_name)
    return {n: ns for n, ns in (st.nodes.items() if st else []) if state.pid_alive(ns.pid)}


def _qmp_all(lab_name: str, nodes: list[str], command: str) -> list[str]:
    from .qmp import Qmp, QmpError
    ok, running = [], _running(lab_name)
    for nid in nodes:
        ns = running.get(nid)
        if not ns or not ns.qmp_port:
            continue
        try:
            with Qmp(ns.qmp_port, timeout=10) as mon:
                mon.call(command)
            ok.append(nid)
        except QmpError:
            pass
    return ok


def wake(lab_name: str, real: float | None = None) -> bool:
    """A paused clock runs again, its held machines with it (called before
    machines start or suspend). True if it was paused."""
    c = load(lab_name)
    if not c.paused:
        return False
    _qmp_all(lab_name, c.held, "cont")
    resume(c, time.time() if real is None else real)
    c.held, c.machines = [], {}
    save(lab_name, c)
    return True


def note_checkpoint(lab_name: str, tag: str, real: float | None = None) -> None:
    c = load(lab_name)
    c.checkpoints[tag] = c.now(real)
    save(lab_name, c)


# ------------------------------------------------------------------ verbs
VERBS = ("pause", "resume", "jump", "set")


def change(lab, verb: str, arg: str = "", runner: Runner | None = None,
           emit=lambda _l: None, real: Callable[[], float] = time.time) -> str:
    """pause | resume | jump <amount|when> | set <when|real>: the one place the
    desktop and the command line move the clock."""
    if verb not in VERBS:
        raise ValueError(f"unknown clock command {verb!r}")
    c, now = load(lab.name), real()
    running = {n: ns.phase for n, ns in _running(lab.name).items()}
    if verb == "pause":
        if c.paused:
            return f"the lab clock is already paused at {stamp(c.now(now))}"
        pause(c, now)
        c.held = _qmp_all(lab.name, list(running), "stop")
        c.machines = {n: "paused with the clock" for n in c.held}
        save(lab.name, c)
        return f"lab clock paused at {stamp(c.now(now))}" + \
            (f"; paused {', '.join(c.held)}" if c.held else "")
    if verb == "resume":
        if not c.paused:
            return "the lab clock is already running"
        _qmp_all(lab.name, c.held, "cont")
        resume(c, now)
        c.held = []
        msg = f"lab clock running from {stamp(c.now(now))}"
    else:
        if not arg:
            raise ValueError(f"clock {verb}: say how far or to when")
        if verb == "set" and arg.strip().lower() in _REAL:
            was = c.offset(now)
            follow_real(c)
            msg = "lab clock back on real time" + (
                " (that moves it back: Kerberos and replication may complain until "
                "machines restart)" if was > 60 and running else "")
        else:
            to = target(arg, c, now, ahead_only=verb == "jump")
            back = to < c.now(now) - 60
            move_to(c, to, now)
            msg = f"lab clock {'paused ' if c.paused else ''}at {stamp(to)}" + (
                " (back in time: best done with the machines off)" if back and running else "")
    if running and not c.paused:
        c.machines = {n: "setting its clock…" for n in running}
    save(lab.name, c)
    if c.paused or not running:
        if c.paused and running:
            msg += "; paused machines take the time when the clock resumes"
        return msg
    if runner is None:
        runner = guest_runner(lab.name)
    c.machines = apply(lab, c, running, runner, real, emit)
    fresh = load(lab.name)
    fresh.machines = c.machines
    save(lab.name, fresh)
    later = [n for n, how in c.machines.items() if how.startswith(NEXT_ON)]
    return msg + (f"; {', '.join(later)} {NEXT_ON}" if later else "")


# -------------------------------------------------------------------- views
def view(lab_name: str, real: float | None = None) -> dict:
    real = time.time() if real is None else real
    c = load(lab_name)
    lab = c.now(real)
    return {"lab": lab, "real": real, "offset": c.offset(real), "paused": c.paused,
            "following": c.following(real), "text": describe_offset(c.offset(real)),
            "hour": time.localtime(lab).tm_hour + time.localtime(lab).tm_min / 60,
            "tonight": next_at(lab, *TONIGHT), "machines": c.machines,
            "checkpoints": c.checkpoints}


def render(lab_name: str, real: float | None = None) -> str:
    v = view(lab_name, real)
    lines = [f"lab time   {stamp(v['lab'])}" + ("   (paused)" if v["paused"] else ""),
             f"real time  {stamp(v['real'])}",
             f"           {'paused, ' if v['paused'] else ''}{v['text']}"]
    for nid, how in sorted(v["machines"].items()):
        lines.append(f"  {nid:<12} {how}")
    for tag, at in sorted(v["checkpoints"].items(), key=lambda x: x[1]):
        lines.append(f"  checkpoint {tag} taken at lab time {stamp(at)}")
    return "\n".join(lines)
