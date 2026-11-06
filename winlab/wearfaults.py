"""Wear: the faults that come from time, not from a person.

winlab/wear.py breaks things on its own while a lab runs for weeks, mostly
from the catalogues the rest of winlab already has (a full volume, a stopped
service, an expired certificate, a NAS full of junk, a paused print queue).
Two kinds of wear had no fault yet, and live here:

- A service that crashed after the night's patching and did not come back,
  because nobody ever set its recovery options: the System log has the
  Service Control Manager's 7034 ("terminated unexpectedly") and the service
  stays stopped. The fix is the service and the recovery options, so the next
  crash restarts it by itself.
- The web server's logs, never cleaned: three months of daily IIS log files
  under C:\\inetpub\\logs\\LogFiles have eaten the system volume. The fix is
  deleting the old ones (and keeping it from coming back).

Both are GuestFaults with a hint ladder and a verify like every other, and
each has its ts-* lesson, so a student can practise them on purpose too.
"""

from __future__ import annotations

KEEP = "New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "
IIS_LOGS = "C:\\inetpub\\logs\\LogFiles"
LOG_LIST = "C:\\winlab\\wear-iislogs.txt"
LOG_DAYS = 90             # how many days of logs nobody deleted
LEAVE_PCT = 0.05          # the share of C: left free once they have grown

# The service and its recovery options. Start-Process passes the argument
# string to sc.exe as written, which an empty actions= needs.
_NO_RECOVERY = ("Start-Process -FilePath sc.exe -ArgumentList 'failure {service} reset= 0 actions= \"\"' "
                "-Wait -NoNewWindow | Out-Null; ")
CRASH_APPLY = (
    _NO_RECOVERY
    + "Stop-Service -Name {service} -Force -ErrorAction SilentlyContinue; "
    "Write-EventLog -LogName System -Source 'Service Control Manager' -EventId 7034 -EntryType Error "
    "-Message 'The {service} service terminated unexpectedly. It has done this 1 time(s).'"
)
CRASH_CLEAR = (
    "sc.exe failure {service} reset= 86400 actions= restart/60000/restart/60000// | Out-Null; "
    "Set-Service -Name {service} -StartupType Automatic; Start-Service -Name {service}"
)
CRASH_VERIFY = (
    "$s = Get-Service -Name {service} -ErrorAction SilentlyContinue; "
    "$f = (sc.exe qfailure {service} 2>&1 | Out-String); "
    "[bool]($s -and $s.Status -eq 'Running' -and $f -match 'RESTART')"
)

LOGS_APPLY = (
    KEEP + f"$d = '{IIS_LOGS}\\W3SVC1'; New-Item -ItemType Directory -Path $d -Force | Out-Null; "
    "$c = Get-PSDrive -Name C; $eat = [long]($c.Free - ($c.Used + $c.Free) * " + str(LEAVE_PCT) + "); "
    f"$made = @(); if ($eat -gt 0) {{ $each = [long]($eat / {LOG_DAYS}); "
    f"for ($i = 1; $i -le {LOG_DAYS}; $i++) {{ $day = (Get-Date).AddDays(-$i); "
    "$f = Join-Path $d ('u_ex' + $day.ToString('yyMMdd') + '.log'); "
    "if (Test-Path -Path $f) { continue }; "
    "$fs = New-Object IO.FileStream($f, 'CreateNew'); $fs.SetLength($each); $fs.Close(); "
    "(Get-Item -Path $f).LastWriteTime = $day; $made += $f } }; "
    f"Set-Content -Path '{LOG_LIST}' -Value $made"
)
LOGS_CLEAR = (
    f"Get-Content -Path '{LOG_LIST}' -ErrorAction SilentlyContinue | "
    "ForEach-Object { Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue }; "
    f"Remove-Item -Path '{LOG_LIST}' -ErrorAction SilentlyContinue"
)
LOGS_VERIFY = (
    "$c = Get-PSDrive -Name C; "
    f"$old = @(Get-ChildItem -Path '{IIS_LOGS}' -Recurse -Filter 'u_ex*.log' -ErrorAction SilentlyContinue | "
    "Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-31) }); "
    "[bool](($c.Free / ($c.Used + $c.Free)) -gt 0.10 -and $old.Count -eq 0)"
)

FAULT_IDS = ("service-crashed-after-update", "iis-logs-grew")


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [
        GuestFault(
            id="service-crashed-after-update",
            title="A service crashed after last night's updates and stayed down",
            os=WINDOWS,
            teaches="reading a crash from the System log (7031, 7034), a service's recovery options (sc.exe "
                    "qfailure and failure), and why a crash at 03:00 should restart itself instead of waiting for you",
            symptom="since the night's patching a service on the server is stopped; nobody stopped it, its start "
                    "type is still Automatic, and it did not come back on its own",
            apply=CRASH_APPLY,
            clear=CRASH_CLEAR,
            hints=(
                "Find out what is down and how it went down. Get-Service | Where-Object { $_.StartType -eq "
                "'Automatic' -and $_.Status -ne 'Running' } lists the automatic services that are not running. "
                "Then the System log: Get-WinEvent -FilterHashtable @{LogName='System'; "
                "ProviderName='Service Control Manager'; Id=7031,7034} -MaxEvents 5 | Format-List TimeCreated, Message.",
                "7034 is 'terminated unexpectedly' with no recovery action taken. A service can say what the "
                "Service Control Manager does when it dies: sc.exe qfailure {service} shows its recovery options. "
                "Here there are none, so a crash leaves it down until someone notices.",
                "Start it (Start-Service {service}) and give it recovery options so the next crash heals itself: "
                "sc.exe failure {service} reset= 86400 actions= restart/60000/restart/60000// (restart after a "
                "minute, twice, counters reset daily). sc.exe qfailure {service} now lists RESTART. Note the time "
                "of the crash against the update history (Get-HotFix, the Setup log) for the change record.",
            ),
            verify=CRASH_VERIFY,
        ),
        GuestFault(
            id="iis-logs-grew",
            roles=("iis",),
            title="The web server's logs have filled the system volume",
            os=WINDOWS,
            teaches="finding what grew on a volume, IIS's daily log files and their folder, a retention rule for "
                    "logs, and keeping it from coming back with a scheduled clean-up",
            symptom="C: on the web server is nearly full; Windows Update and the site's own writes start failing, "
                    "and monitoring raises low disk space; nothing was installed",
            apply=LOGS_APPLY,
            clear=LOGS_CLEAR,
            hints=(
                "Get-PSDrive C shows how little is left. Find the folders that grew, not single files: "
                f"Get-ChildItem C:\\inetpub -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum, "
                "then the same for C:\\Windows\\Temp and C:\\Users. The inetpub tree is far bigger than a web site.",
                f"{IIS_LOGS}\\W3SVC1 holds one u_exYYMMDD.log a day, months of them. IIS writes logs and never "
                "deletes them; nobody set a retention rule. List them by age: Get-ChildItem "
                f"{IIS_LOGS} -Recurse -Filter u_ex*.log | Sort-Object LastWriteTime | Select-Object -First 5 Name, "
                "LastWriteTime, Length.",
                "Keep a month and delete the rest: Get-ChildItem " + IIS_LOGS + " -Recurse -Filter u_ex*.log | "
                "Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) | Remove-Item. Then make it a job: a "
                "scheduled task running that line every night (Register-ScheduledTask), or move the logs to a data "
                "volume in the site's logging settings. Get-PSDrive C again.",
            ),
            verify=LOGS_VERIFY,
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
