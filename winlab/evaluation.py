"""Evaluation licence clock of Windows machines.

Windows Server evaluation runs 180 days and Windows 11 Enterprise evaluation
90 days from installation; after that the machine shuts itself down every
hour. A home lab lives longer than that, so winlab asks each machine how long
it has left (over the serial agent, nothing leaves the lab), remembers the
answer, and warns before it runs out. `slmgr /rearm` restarts the clock a
limited number of times; the machine needs a restart afterwards.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass

from . import paths, state
from .guestctl import GuestChannel, GuestError

WARN_DAYS = 14

# The Windows application id in the Software Licensing service: only the
# operating system's own licence, not Office or other products.
_QUERY = r"""
$p = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" | Select-Object -First 1
$s = Get-CimInstance SoftwareLicensingService
'{0}|{1}|{2}|{3}' -f $p.LicenseStatus, $p.GracePeriodRemaining, $s.RemainingWindowsReArmCount, $p.Description
"""

_REARM = r"""
$s = Get-CimInstance SoftwareLicensingService
Invoke-CimMethod -InputObject $s -MethodName ReArmWindows | Out-Null
'rearmed'
"""


class EvaluationError(Exception):
    pass


@dataclass
class Clock:
    node: str
    days_left: int        # -1: not an evaluation (licensed or unknown)
    rearms_left: int
    evaluation: bool
    checked_at: float
    status: int = 0

    @property
    def warn(self) -> bool:
        return self.evaluation and 0 <= self.days_left <= WARN_DAYS


def _cache_file(lab_name: str):
    return paths.STATE / f"{lab_name}.evaluation.json"


def cached(lab_name: str) -> dict[str, Clock]:
    f = _cache_file(lab_name)
    if not f.exists():
        return {}
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
        return {k: Clock(**v) for k, v in raw.items()}
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def _remember(lab_name: str, clock: Clock) -> None:
    data = cached(lab_name)
    data[clock.node] = clock
    paths.STATE.mkdir(parents=True, exist_ok=True)
    f = _cache_file(lab_name)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({k: asdict(v) for k, v in data.items()}, indent=2),
                   encoding="utf-8")
    tmp.replace(f)


def parse(node_id: str, line: str, now: float | None = None) -> Clock:
    """Turns the agent's 'status|minutes|rearms|description' line into a Clock."""
    parts = (line.strip().splitlines() or [""])[-1].split("|")
    if len(parts) < 4:
        raise EvaluationError(f"{node_id}: unexpected licence answer {line.strip()[:120]!r}")
    status = int(parts[0] or 0)
    minutes = int(parts[1] or 0)
    rearms = int(parts[2] or 0)
    evaluation = "EVAL" in parts[3].upper()
    return Clock(node=node_id, days_left=minutes // 1440 if evaluation else -1,
                 rearms_left=rearms, evaluation=evaluation,
                 checked_at=now if now is not None else time.time(), status=status)


def _channel(lab_name: str, node_id: str) -> GuestChannel:
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not ns.serial_port or not state.pid_alive(ns.pid):
        raise EvaluationError(f"{node_id} is not running")
    try:
        return GuestChannel(ns.serial_port).connect(retries=5, delay=2)
    except GuestError as exc:
        raise EvaluationError(f"{node_id}: {exc}") from exc


def check(lab_name: str, node_id: str) -> Clock:
    ch = _channel(lab_name, node_id)
    try:
        res = ch.run(_QUERY, timeout=120)
    except GuestError as exc:
        raise EvaluationError(f"{node_id}: {exc}") from exc
    finally:
        ch.close()
    if not res.ok:
        raise EvaluationError(f"{node_id}: {res.err.strip()[:200] or 'query failed'}")
    clock = parse(node_id, res.out)
    _remember(lab_name, clock)
    return clock


def rearm(lab_name: str, node_id: str) -> str:
    ch = _channel(lab_name, node_id)
    try:
        res = ch.run(_REARM, timeout=180)
    except GuestError as exc:
        raise EvaluationError(f"{node_id}: {exc}") from exc
    finally:
        ch.close()
    if not res.ok:
        raise EvaluationError(
            f"{node_id}: rearm refused ({res.err.strip()[:200] or 'no rearms left?'})"
        )
    return f"{node_id}: evaluation clock reset; restart the machine to apply it"


def describe(clock: Clock) -> str:
    if not clock.evaluation:
        return "not an evaluation"
    left = f"{clock.days_left} days left" if clock.days_left > 0 else "expired"
    return f"{left}, {clock.rearms_left} rearms left"
