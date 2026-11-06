"""Time inside the lab: an NTP server the student adds, the domain's time
hierarchy pointed at it, Linux machines on chrony, and the ways time breaks.

The lab clock (winlab/labclock.py) is the only time there is. Nothing in a
lab ever asks this PC or the internet for the time: QEMU starts every RTC at
lab time, the NTP server's own clock is that RTC, and it serves it with no
upstream (chrony's `local stratum`). So the NTP server here is what a GPS
clock on the office rack is: the reference everything else follows.

- NTP server: a small Alpine device on the workbench shelf (the ``ntp-server``
  role, chrony: its firmware, run at every power-on with factory settings,
  stratum 3 and every lab network; a lab may set ntp_stratum / ntp_allow).
  The student reads and changes it on its own console, as on a real one; its
  workbench panel only shows what it serves and who asked.
- The PDC emulator syncs from it (w32tm /config /manualpeerlist:<it>
  /syncfromflags:manual /reliable:yes); members follow the domain hierarchy
  (NT5DS). The student does that inside the machines; the ``ntp`` role (CLI,
  CI) is the model answer and points at the NTP server when there is one.
- Linux machines run chrony against the NTP server, or the domain controller
  when there is none (``ntp-client``: the model answer; in a lab it only
  brings the chrony package onto an Alpine machine).
- One machine's clock can be put off on purpose: its hardware clock runs that
  far from lab time (the -rtc base at power-on) and a running one is set over
  its agent at once. Whether the OS pulls it back is the lesson.

Seven graded faults register with guestfaults, each with a hint ladder.
Their verify commands compare the machine with lab time ({labtime}, the lab
clock when the check is built), so a fix that only hides the symptom fails.
"""

from __future__ import annotations

import json
import re
import shlex
import time

from . import paths

ROLE = "ntp-server"
CLIENT_ROLE = "ntp-client"
DEFAULT_STRATUM = 3
CONF = "/etc/chrony/chrony.conf"
# A network address nobody in the lab has (TEST-NET-1): where faults point.
NOWHERE = "192.0.2.123"


class TimeError(ValueError):
    pass


# ----------------------------------------------------------------- sources
def ntp_device(lab):
    """The lab's NTP server, if it has one (the first, by boot order)."""
    return next((n for n in lab.node_list() if ROLE in n.roles), None)


def address(lab, node) -> str:
    """How others reach a machine: its fixed address, else its name (the
    router's DNS answers for the names DHCP clients give)."""
    nic = node.nics[0] if node.nics else None
    if nic is not None and getattr(nic, "plugged", True) and nic.ip:
        return nic.ip
    from . import naming
    return naming.hostname_of(node).lower()


def first_dc(lab):
    dcs = [n for n in lab.node_list() if "ad-ds" in n.roles]
    return next((n for n in dcs if n.vars.get("forest_root")), dcs[0] if dcs else None)


def pdc_peers(lab, node=None) -> str:
    """The PDC emulator's manual peer list: the node's `ntp_source`, else the
    lab's NTP server, else time.windows.com (outside the sealed lab: the PDC
    then serves its own clock, which is lab time)."""
    src = str((node.vars.get("ntp_source") if node is not None else "") or "")
    if not src:
        dev = ntp_device(lab)
        src = address(lab, dev) if dev is not None else "time.windows.com"
    return " ".join(p if "," in p else p + ",0x8" for p in src.split())


def client_source(lab, node=None) -> str:
    """Where a Linux machine's chrony asks: its `ntp_source`, else the NTP
    server, else the forest root DC."""
    src = str((node.vars.get("ntp_source") if node is not None else "") or "")
    if src:
        return src
    dev = ntp_device(lab)
    if dev is not None:
        return address(lab, dev)
    dc = first_dc(lab)
    return address(lab, dc) if dc is not None else ""


def allow_list(lab, node) -> list[str]:
    """The networks the NTP server answers: its `ntp_allow` (CIDRs), or every
    network of the lab."""
    raw = str(node.vars.get("ntp_allow") or "").split()
    if raw and raw != ["all"]:
        return raw
    out = []
    for net in lab.networks.values():
        if getattr(net, "cidr", "") and net.cidr not in out:
            out.append(net.cidr)
    return out


def stratum(node) -> int:
    try:
        return max(1, min(15, int(node.vars.get("ntp_stratum") or DEFAULT_STRATUM)))
    except (TypeError, ValueError):
        return DEFAULT_STRATUM


def sh_env_lines(lab, node) -> list[str]:
    """What the ntp-server and ntp-client roles read (roles.sh_env)."""
    out = []
    if ROLE in node.roles:
        out.append(f"WINLAB_NTP_STRATUM={stratum(node)}")
        out.append(f"WINLAB_NTP_ALLOW={shlex.quote(' '.join(allow_list(lab, node)))}")
    if CLIENT_ROLE in node.roles:
        out.append(f"WINLAB_NTP_SOURCE={shlex.quote(client_source(lab, node))}")
    return out


# --------------------------------------------------------- chrony's answers
def parse_tracking(text: str) -> dict:
    """chronyc tracking: the reference, stratum, how far off, leap status."""
    out = {}
    for line in text.splitlines():
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "reference id":
            out["reference"] = val
        elif key == "stratum":
            out["stratum"] = int(val) if val.isdigit() else 0
        elif key == "system time":
            out["system"] = val
        elif key == "leap status":
            out["leap"] = val
    out["synced"] = out.get("leap", "") == "Normal"
    return out


def parse_clients(text: str) -> list[dict]:
    """chronyc -n clients: who asked for the time, how often, how long ago."""
    out, body = [], False
    for line in text.splitlines():
        if line.startswith("===="):
            body = True
            continue
        f = line.split()
        if body and len(f) >= 6 and f[1].isdigit():
            out.append({"host": f[0], "requests": int(f[1]), "dropped": int(f[2]) if f[2].isdigit() else 0,
                        "last": f[5]})
    return out


def parse_sources(text: str) -> list[dict]:
    """chronyc -n sources: each source, whether it is selected (*), usable
    (+), unreachable (?), and its reach register."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^([\^=#])([*+\-?x~])\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)", line)
        if m:
            out.append({"mode": m[1], "state": m[2], "name": m[3], "stratum": int(m[4]),
                        "reach": m[6], "selected": m[2] == "*"})
    return out


def _run(lab_name: str, node_id: str, cmd: str, factory=None) -> str:
    from . import appliance
    from .guestctl import GuestChannel, GuestError
    try:
        ch = appliance._channel(lab_name, node_id, factory or GuestChannel)
    except appliance.ApplianceError as exc:
        raise TimeError(str(exc)) from None
    try:
        r = ch.run(cmd, shell="sh", timeout=30)
    except GuestError as exc:
        raise TimeError(f"{node_id}: {exc}") from None
    finally:
        ch.close()
    return r.out


def server_state(lab_name: str, node_id: str, factory=None) -> dict:
    """The NTP server's panel: its own time, tracking, and its clients."""
    out = _run(lab_name, node_id, "date -u '+%Y-%m-%d %H:%M:%S'; echo '#tracking'; chronyc -n tracking 2>&1; "
                                  "echo '#clients'; chronyc -n clients 2>&1", factory)
    now, _, rest = out.partition("#tracking")
    trk, _, cli = rest.partition("#clients")
    return {"utc": now.strip(), "tracking": parse_tracking(trk), "clients": parse_clients(cli),
            "running": "Cannot talk to daemon" not in out and "506" not in trk}


# --------------------------------------------------- one machine's clock off
def skew_file(lab_name: str):
    return paths.lab_dir(lab_name) / "clockskew.json"


def skews(lab_name: str) -> dict[str, float]:
    try:
        raw = json.loads(skew_file(lab_name).read_text(encoding="utf-8"))
        return {str(k): float(v) for k, v in raw.items() if float(v)}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def skew_of(lab_name: str, node_id: str) -> float:
    return skews(lab_name).get(node_id, 0.0)


def _save_skews(lab_name: str, data: dict[str, float]) -> None:
    f = skew_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps({k: v for k, v in data.items() if v}, indent=2), encoding="utf-8")
    tmp.replace(f)


def parse_skew(text: str) -> float:
    """'+10min', '-6min', '1w', '0', 'off' -> seconds (signed)."""
    from .labclock import parse_amount
    s = str(text).strip().lower()
    if s in ("0", "off", "none", "lab", "clear", "reset"):
        return 0.0
    sign = -1.0 if s.startswith("-") else 1.0
    amount = parse_amount(s.lstrip("+-").strip())
    if amount is None:
        raise TimeError(f"{text!r}: give how far off, like +10min, -6min, +1w, or 0 for lab time")
    if amount > 400 * 86400:
        raise TimeError("a year off is as far as a lab clock goes here")
    return sign * amount


def describe_skew(seconds: float) -> str:
    if not seconds:
        return "on lab time"
    left, parts = int(round(abs(seconds))), []
    for name, size in (("week", 604800), ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)):
        if left >= size:
            n, left = divmod(left, size)
            parts.append(f"{n} {name}{'' if n == 1 else 's'}")
    return f"{' '.join(parts[:2])} {'ahead of' if seconds > 0 else 'behind'} lab time"


def rtc_arg(lab_name: str, node_id: str, utc: bool, real: float | None = None) -> str:
    """QEMU's -rtc for one machine: lab time, plus that machine's skew."""
    from . import labclock
    c = labclock.load(lab_name)
    off = skew_of(lab_name, node_id)
    if not off:
        return labclock.rtc_arg(c, utc, real)
    lab = c.now(time.time() if real is None else real) + off
    when = time.gmtime(lab) if utc else time.localtime(lab)
    return f"base={time.strftime('%Y-%m-%dT%H:%M:%S', when)},clock=vm"


def skew_command(shell: str, when: float) -> str:
    """Puts a running machine's clock at `when` and nothing else: no resync,
    so whatever the time service does next is the machine's own doing."""
    if shell == "sh":
        return f"date -u -s '{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(when))}' >/dev/null && echo ok"
    return (f"$t = [DateTimeOffset]::FromUnixTimeSeconds({int(when)}).LocalDateTime; "
            f"Set-Date -Date $t | Out-Null; 'ok'")


def set_skew(lab, node_id: str, spec: str, runner=None) -> str:
    """One machine's hardware clock (its RTC) off by `spec` (0 puts it back
    on lab time), as a flat CMOS battery or a date typed into the firmware
    leaves it: it starts there at its next power-on. A running machine's
    clock is left to its own time service, as on a real PC: nothing is set
    inside it. (`runner` is kept for callers; nothing runs in the guest.)"""
    from . import labclock, naming
    node = lab.nodes.get(node_id)
    if node is None:
        raise TimeError(f"no machine {node_id} in {lab.name}")
    seconds = parse_skew(spec)
    data = skews(lab.name)
    data[node_id] = seconds
    _save_skews(lab.name, data)
    who = naming.display(lab, node_id)
    what = (f"{who}: its hardware clock runs {describe_skew(seconds)}" if seconds
            else f"{who}: its hardware clock is back on lab time")
    if node_id not in labclock._running(lab.name):
        return what + "; it takes that time at its next power-on"
    return what + ("; it takes that time at its next power-on. While it runs, its clock is its own time "
                   "service's (Windows Time, chrony)")


# ------------------------------------------------------------- desktop actions
def act(dash, action: str, params: dict) -> dict:
    try:
        return _act(dash, action, params)
    except TimeError as exc:
        return {"ok": False, "message": str(exc)}


def _act(dash, action: str, params: dict) -> dict:
    from . import naming
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node", "")))
    node = lab.nodes.get(node_id)
    if node is None:
        raise TimeError(f"no machine {params.get('node') or ''} in {lab.name}".strip())
    if action == "time-skew":
        return {"ok": True, "message": set_skew(lab, node_id, str(params.get("skew", "0"))),
                "skew": skew_of(lab.name, node_id)}
    if ROLE not in node.roles:
        raise TimeError(f"{naming.display(lab, node_id)} is not an NTP server")
    if action == "time-ntp":
        return {"ok": True, **server_state(lab.name, node_id)}
    raise TimeError(f"unknown action {action}")


def render(lab) -> str:
    """`winlab clock skew` with no machine: the time map of the lab."""
    from . import naming
    lines = []
    dev = ntp_device(lab)
    lines.append(f"NTP server   {naming.display(lab, dev.id) + ' (' + address(lab, dev) + ')' if dev else 'none'}")
    dc = first_dc(lab)
    if dc is not None:
        lines.append(f"PDC emulator {naming.display(lab, dc.id)} syncs from {pdc_peers(lab, dc)}")
    for n in lab.node_list():
        if n.kind == "linux" and CLIENT_ROLE in n.roles:
            lines.append(f"  {n.id:<12} chrony asks {client_source(lab, n)}")
    for nid, off in sorted(skews(lab.name).items()):
        lines.append(f"  {nid:<12} clock runs {describe_skew(off)}")
    return "\n".join(lines)


# ------------------------------------------------------------- guest faults
_W32 = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time"
_PARAMS = f"'{_W32}\\Parameters'"
_NTPC = f"'{_W32}\\TimeProviders\\NtpClient'"
_VMIC = f"'{_W32}\\TimeProviders\\VMICTimeProvider'"
# The machine against lab time, in seconds: what every verify ends on.
_OFF_WIN = "$d = [math]::Abs([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - {labtime}); "
_OFF_SH = "d=$(( $(date +%s) - {labtime} )); [ ${d#-} -lt 120 ]"
_KEEP = "New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "


def _faults():
    from .guestfaults import LINUX, WINDOWS, GuestFault
    return [
        GuestFault(
            id="member-clock-nosync",
            roles=("domain-join",),
            title="A member's clock is 10 minutes off and nothing corrects it",
            os=WINDOWS,
            teaches="Kerberos' five-minute tolerance, reading KRB_AP_ERR_SKEW, klist, and a member taken off the domain "
                    "time hierarchy (Type NoSync) so it can never come back on its own",
            symptom="domain sign-ins on this machine fail ('the time on this computer is different from the domain'), "
                    "shares on it ask for credentials, klist get krbtgt fails; a local account still signs in",
            apply=("w32tm /config /syncfromflags:NO /update | Out-Null; Restart-Service w32time; "
                   "Set-Date -Date (Get-Date).AddMinutes(10) | Out-Null; klist -li 0x3e7 purge | Out-Null"),
            clear=("w32tm /config /syncfromflags:domhier /update | Out-Null; Restart-Service w32time; "
                   "w32tm /resync /rediscover | Out-Null"),
            hints=(
                "Separate the account from the clock: a local account signs in, a domain one does not. Ask Kerberos: "
                "klist get krbtgt fails with 0xc000133 / KRB_AP_ERR_SKEW (clock skew too great), and on the DC the "
                "Security log has event 4771 with failure code 0x25 for this machine. Then compare clocks: "
                "w32tm /stripchart /computer:{dns} /samples:3 /dataonly shows about +600 s.",
                "Why does it not correct itself? w32tm /query /status says Source: Local CMOS Clock, and "
                "w32tm /query /configuration shows Type: NoSync: someone took it off the time hierarchy. The System "
                "log's Time-Service events (Get-WinEvent -FilterHashtable @{LogName='System'; "
                "ProviderName='Microsoft-Windows-Time-Service'} -MaxEvents 10) stop after that change.",
                "Put it back on the domain hierarchy and resync: w32tm /config /syncfromflags:domhier /update; "
                "Restart-Service w32time; w32tm /resync /rediscover. w32tm /query /source names a DC, the stripchart "
                "is near zero, klist purge, and a domain sign-in works again.",
            ),
            verify=(f"$t = (Get-ItemProperty -Path {_PARAMS}).Type; $s = Get-Service -Name w32time; " + _OFF_WIN +
                    "($t -eq 'NT5DS' -and $s.Status -eq 'Running' -and $d -lt 120)"),
        ),
        GuestFault(
            id="pdc-source-unreachable",
            roles=("ad-ds",),
            title="The PDC emulator syncs from a source nobody can reach",
            os=WINDOWS,
            teaches="the top of the domain time hierarchy, w32tm /query /status and /source, the Time-Service warnings "
                    "24, 29 and 47 (and 12, its domain-hierarchy twin), and pointing the PDC at a source inside the lab",
            symptom="nothing fails yet: w32tm /query /status on the domain controller says Source: Local CMOS Clock "
                    "(or Free-running System Clock) and the System log fills with Time-Service warnings; the "
                    "domain's time is no longer traceable to anything, and it drifts with nobody correcting it",
            apply=(_KEEP + f"if (-not (Test-Path 'C:\\winlab\\w32time-before.txt')) {{ $p = Get-ItemProperty -Path {_PARAMS}; "
                   "Set-Content -Path 'C:\\winlab\\w32time-before.txt' -Value @([string]$p.Type, [string]$p.NtpServer) }; "
                   "w32tm /config /manualpeerlist:'time.windows.com,0x8 ntp.isp.example,0x8' /syncfromflags:manual "
                   "/reliable:yes /update | Out-Null; Restart-Service w32time; w32tm /resync /nowait | Out-Null"),
            clear=("$b = @(Get-Content -Path 'C:\\winlab\\w32time-before.txt' -ErrorAction SilentlyContinue); "
                   "$to = '{ntp}'; if (-not $to -and $b.Count -gt 1 -and $b[0] -eq 'NTP') { $to = $b[1] }; "
                   "if ($to) { if ($to -notmatch ',') { $to = $to + ',0x8' }; "
                   "w32tm /config /manualpeerlist:$to /syncfromflags:manual /reliable:yes /update | Out-Null } "
                   "else { w32tm /config /syncfromflags:domhier /update | Out-Null }; Restart-Service w32time; "
                   "Remove-Item -Path 'C:\\winlab\\w32time-before.txt' -ErrorAction SilentlyContinue; "
                   "w32tm /resync /nowait | Out-Null"),
            hints=(
                "Start at the top of the tree. On the DC: w32tm /query /source answers Local CMOS Clock or "
                "Free-running System Clock, not a server. w32tm /query /status shows when it last synced. "
                "Then the System log: Time-Service events 24 and 47 (no valid response from a manually configured "
                "peer) and 29 (none of the sources are accessible). Event 12 is the same story for a PDC left on "
                "the domain hierarchy, with nobody above it.",
                "w32tm /query /peers lists time.windows.com and ntp.isp.example in state Pending: neither exists for "
                "this sealed lab. Test a candidate before you configure it: w32tm /stripchart /computer:{ntp} "
                "/samples:3 /dataonly answers with offsets from the lab's NTP server (add one from the shelf if the "
                "lab has none).",
                "w32tm /config /manualpeerlist:\"{ntp},0x8\" /syncfromflags:manual /reliable:yes /update; "
                "Restart-Service w32time; w32tm /resync /rediscover. /query /source now names it and /query /status "
                "shows its stratum plus one. Every source in the list must answer.",
            ),
            verify=(f"$p = Get-ItemProperty -Path {_PARAMS}; $src = (w32tm /query /source | Out-String).Trim(); "
                    "$peers = @(([string]$p.NtpServer).Trim() -split '\\s+' | Where-Object { $_ } | "
                    "ForEach-Object { $_ -replace ',0x[0-9a-fA-F]+$', '' }); $ok = ($p.Type -eq 'NTP' -and $peers.Count -gt 0 "
                    "-and $src -notmatch 'Local CMOS|Free-running'); foreach ($h in $peers) { "
                    "if (-not (w32tm /stripchart /computer:$h /samples:1 /dataonly 2>&1 | Select-String -Pattern "
                    "'[+-][0-9.]+s')) { $ok = $false } }; $ok"),
        ),
        GuestFault(
            id="w32time-off-host-sync",
            title="Time sync was left to a hypervisor that does not do it",
            os=WINDOWS,
            teaches="time providers (NtpClient, VMICTimeProvider), why a VM must have exactly one thing setting its "
                    "clock, and the Windows Time service's start type",
            symptom="the clock is a few minutes off and creeping; after a while Kerberos refuses it. w32tm commands "
                    "say 'The service has not been started' and Services shows Windows Time disabled",
            apply=(_KEEP + "if (-not (Test-Path 'C:\\winlab\\vmic-before.txt')) { "
                   f"$v = (Get-ItemProperty -Path {_VMIC} -ErrorAction SilentlyContinue).Enabled; "
                   "Set-Content -Path 'C:\\winlab\\vmic-before.txt' -Value ([string]$v) }; "
                   f"if (Test-Path {_VMIC}) {{ Set-ItemProperty -Path {_VMIC} -Name Enabled -Value 1 }}; "
                   f"Set-ItemProperty -Path {_NTPC} -Name Enabled -Value 0; Stop-Service -Name w32time -Force; "
                   "Set-Service -Name w32time -StartupType Disabled; Set-Date -Date (Get-Date).AddMinutes(7) | Out-Null"),
            clear=("$v = Get-Content -Path 'C:\\winlab\\vmic-before.txt' -ErrorAction SilentlyContinue | Select-Object -First 1; "
                   f"if ((Test-Path {_VMIC}) -and \"$v\" -match '^[01]$') {{ Set-ItemProperty -Path {_VMIC} -Name Enabled -Value ([int]$v) }}; "
                   f"Set-ItemProperty -Path {_NTPC} -Name Enabled -Value 1; Set-Service -Name w32time -StartupType Automatic; "
                   "Start-Service -Name w32time; w32tm /resync /rediscover | Out-Null; "
                   "Remove-Item -Path 'C:\\winlab\\vmic-before.txt' -ErrorAction SilentlyContinue"),
            hints=(
                "w32tm /query /status answers 'The following error occurred: The service has not been started.' "
                "Get-Service w32time | Select-Object Status, StartType: Stopped and Disabled. Nothing is keeping "
                "this clock: compare it, w32tm /stripchart /computer:{dns} /samples:3 /dataonly.",
                "Whoever did this meant the hypervisor to set the time (Hyper-V's time synchronization integration "
                "service, the VMICTimeProvider). Read the providers: Get-ItemProperty "
                "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient shows Enabled 0. On this "
                "hypervisor no host sets the guest clock, and in a domain the hierarchy must win anyway.",
                "Set-ItemProperty that NtpClient key -Name Enabled -Value 1; Set-Service w32time -StartupType "
                "Automatic; Start-Service w32time; w32tm /resync /rediscover. /query /status shows a source again "
                "and the stripchart is near zero. On a Hyper-V DC you would also turn the host's time sync off "
                "(VMICTimeProvider Enabled 0).",
            ),
            verify=(f"$s = Get-Service -Name w32time; $n = (Get-ItemProperty -Path {_NTPC}).Enabled; " + _OFF_WIN +
                    "($s.Status -eq 'Running' -and [string]$s.StartType -eq 'Automatic' -and $n -eq 1 -and $d -lt 120)"),
        ),
        GuestFault(
            id="wrong-time-zone",
            title="The clock shows the wrong hour, but nothing fails",
            os=WINDOWS,
            teaches="wrong time zone versus wrong time: Kerberos, NTP and the event logs run on UTC, the zone is only "
                    "how the hour is shown, and 'fixing' the hour by hand breaks what was working",
            symptom="the taskbar clock, file times and Task Scheduler are hours off from everyone else's, yet "
                    "domain sign-ins work and the time service reports no error",
            apply=(_KEEP + "$t = Get-TimeZone; if (-not (Test-Path 'C:\\winlab\\tz-before.txt')) { "
                   "Set-Content -Path 'C:\\winlab\\tz-before.txt' -Value $t.Id }; "
                   "$new = if ($t.BaseUtcOffset.TotalHours -gt -3) { 'Pacific Standard Time' } else { 'Tokyo Standard Time' }; "
                   "Set-TimeZone -Id $new"),
            clear=("$id = Get-Content -Path 'C:\\winlab\\tz-before.txt' -ErrorAction SilentlyContinue | Select-Object -First 1; "
                   "if ($id) { Set-TimeZone -Id $id }; Remove-Item -Path 'C:\\winlab\\tz-before.txt' -ErrorAction SilentlyContinue"),
            hints=(
                "Compare the instant, not the hour: [DateTime]::UtcNow here and on the DC agree, and "
                "w32tm /stripchart /computer:{dns} /samples:3 /dataonly is near zero. So the time is right. Kerberos, "
                "NTP and the event logs keep UTC, which is why nothing fails.",
                "What differs is how the hour is shown: Get-TimeZone (or tzutil /g) here says Pacific or Tokyo "
                "Standard Time; on the DC it says the lab's zone. A wrong zone shifts the wall clock by whole hours; "
                "a wrong time is off by any amount and breaks authentication.",
                "Set-TimeZone -Id '<the DC's zone>' (or tzutil /s, or Settings > Time & language). Do not Set-Date: "
                "moving the clock to 'fix' the hour makes the UTC time wrong, and then Kerberos fails. In a company "
                "the zone comes from the image or a Group Policy preference.",
            ),
            verify=("$want = Get-Content -Path 'C:\\winlab\\tz-before.txt' -ErrorAction SilentlyContinue | Select-Object -First 1; "
                    "if (-not $want) { $want = (Get-TimeZone).Id }; " + _OFF_WIN + "((Get-TimeZone).Id -eq $want -and $d -lt 120)"),
        ),
        GuestFault(
            id="dc-week-ahead",
            roles=("ad-ds",),
            title="A domain controller's clock jumped a week ahead",
            os=WINDOWS,
            teaches="MaxPosPhaseCorrection (a DC will not step more than 48 hours by itself), event 52, and why a "
                    "DC with a wrong clock drags its members along",
            symptom="the DC's clock says next week; members that sync from it follow at their next poll, others "
                    "get clock-skew errors against it; Task Scheduler fires next week's jobs; nothing corrects it",
            apply="Set-Date -Date (Get-Date).AddDays(7) | Out-Null; w32tm /resync /nowait | Out-Null",
            clear="Set-Date -Date (Get-Date).AddDays(-7) | Out-Null; w32tm /resync /nowait | Out-Null",
            hints=(
                "Get-Date on the DC is a week ahead. Ask what it is ahead of: w32tm /stripchart "
                "/computer:{ntp} /samples:3 /dataonly (or another DC, or the NTP server's panel) shows about "
                "-604800 s. The System log's Time-Service event 52 says it will not change the time by more than "
                "172800 seconds.",
                "That limit is MaxPosPhaseCorrection / MaxNegPhaseCorrection under "
                "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config: 48 hours on a DC, so a big jump is never "
                "fixed by the time service and must be fixed by a person. Members have no limit, which is how one "
                "wrong DC moves the whole domain.",
                "Set the clock back by hand, near the source: Set-Date (Get-Date).AddDays(-7), or the exact offset the "
                "stripchart shows. Then w32tm /resync /force here and w32tm /resync /rediscover on the members. "
                "Keep the 48-hour limits: they are what stopped this from being worse.",
            ),
            verify=_OFF_WIN + "($d -lt 120)",
        ),
        GuestFault(
            id="ntp-allow-wrong",
            roles=(ROLE,),
            images=("alpine",),
            title="The NTP server ignores the office",
            os=LINUX,
            teaches="an NTP server's access list (chrony's allow), telling 'no answer' from 'refused', and reading a "
                    "time server's own counters",
            symptom="the PDC emulator logs Time-Service warnings 24 and 47 against the NTP server, its stripchart "
                    "times out (0x800705B4), Linux machines show it as ^? in chronyc sources; the NTP server pings",
            apply=(f"cp -n {CONF} {CONF}.winlab 2>/dev/null; sed -i '/^allow/d' {CONF} && "
                   f"echo 'allow {NOWHERE.rsplit('.', 1)[0]}.0/24' >> {CONF} && "
                   "(rc-service chronyd restart >/dev/null 2>&1 || (pkill -x chronyd; sleep 1; "
                   f"chronyd -f {CONF})) && echo broken"),
            clear=(f"[ -f {CONF}.winlab ] && mv {CONF}.winlab {CONF}; "
                   f"rc-service chronyd restart >/dev/null 2>&1 || (pkill -x chronyd; sleep 1; chronyd -f {CONF}); echo ok"),
            shell="sh",
            hints=(
                "From the PDC: w32tm /stripchart /computer:{ntp} /samples:3 /dataonly times out, yet ping {ntp} "
                "answers. So the machine is there and its NTP service (UDP 123) says nothing back. On a Linux "
                "machine, chronyc -n sources shows it as ^? with Reach 0.",
                "On the NTP server (its screen, or Terminal): chronyc -n clients lists nobody, and chronyc serverstats "
                "shows 'NTP packets dropped' climbing with every request. chrony answers only the networks its allow "
                f"lines name: grep allow {CONF}.",
                f"The allow line names 192.0.2.0/24, which is no network of this lab. Put the lab's networks back "
                f"(allow 10.20.0.0/24, one line per network, or a bare allow for everyone), then rc-service chronyd "
                "restart. chronyc -n clients shows the PDC within a minute and its stripchart answers.",
            ),
            verify=("ok=True; [ -f /etc/winlab-ntp/allow ] || ok=False; "
                    f"if ! grep -qx 'allow' {CONF}; then while read -r l; do [ -z \"$l\" ] || grep -qxF \"$l\" {CONF} || ok=False; "
                    "done < /etc/winlab-ntp/allow; fi; pgrep -x chronyd >/dev/null || ok=False; echo $ok"),
        ),
        GuestFault(
            id="chrony-source-unreachable",
            roles=(CLIENT_ROLE,),
            images=("alpine",),
            title="A Linux server's clock has no source",
            os=LINUX,
            teaches="chronyc sources and tracking, the reach register, and pointing chrony at the domain's time",
            symptom="kinit and SSSD logons on this Linux machine start failing with 'Clock skew too great' as it "
                    "drifts; chronyc tracking says 'Not synchronised'",
            apply=(f"cp -n {CONF} {CONF}.winlab 2>/dev/null; sed -i '/^server/d;/^pool/d' {CONF} && "
                   f"echo 'server {NOWHERE} iburst' >> {CONF} && (rc-service chronyd restart >/dev/null 2>&1 || "
                   f"(pkill -x chronyd; sleep 1; chronyd -f {CONF})); "
                   "date -u -s \"@$(( $(date +%s) + 420 ))\" >/dev/null; echo broken"),
            clear=(f"[ -f {CONF}.winlab ] && mv {CONF}.winlab {CONF}; "
                   f"rc-service chronyd restart >/dev/null 2>&1 || (pkill -x chronyd; sleep 1; chronyd -f {CONF}); "
                   "chronyc makestep >/dev/null 2>&1; echo ok"),
            shell="sh",
            hints=(
                "chronyc tracking: Leap status 'Not synchronised', Reference ID 00000000. chronyc -n sources: one "
                "line, ^? with Reach 0, so nothing has ever answered. Compare: date -u here against the NTP server's "
                "panel or the DC.",
                f"grep server {CONF}: it asks 192.0.2.123, an address nobody in the lab has (TEST-NET-1, kept for "
                "documentation). The lab's time comes from {timesrc}.",
                f"Point it there: replace the server line with 'server {{timesrc}} iburst' in {CONF}, rc-service "
                "chronyd restart, then chronyc makestep to step the seven minutes at once (chrony otherwise slews "
                "slowly). chronyc -n sources shows ^* on it.",
            ),
            verify=("chronyc -n sources 2>/dev/null | grep -q '^\\^\\*' && chronyc tracking 2>/dev/null | "
                    "grep -q 'Leap status *: Normal' && " + _OFF_SH + " && echo True || echo False"),
        ),
    ]


FAULT_IDS = ("member-clock-nosync", "pdc-source-unreachable", "w32time-off-host-sync", "wrong-time-zone",
             "dc-week-ahead", "ntp-allow-wrong", "chrony-source-unreachable")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)


def fault_params(lab) -> dict[str, str]:
    """The faults' parameters from a lab (guestfaults.lab_params): the NTP
    server, the source Linux machines should use, and lab time now."""
    from . import labclock
    dev = ntp_device(lab)
    return {"ntp": address(lab, dev) if dev is not None else "",
            "timesrc": client_source(lab) or "the domain controller",
            "labtime": str(int(labclock.load(lab.name).now()))}
