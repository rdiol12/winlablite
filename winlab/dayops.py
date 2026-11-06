"""Day-two operations: the scenes a working directory admin walks into.

Each one is a guest fault (winlab/guestfaults.py) that sets a scene on a
domain controller or a server, never the answer: a leaver whose account is
still live, computer accounts nobody has seen for months, a prestaged account
for a machine that changed jobs, extra members in Domain Admins, scheduled
tasks an intruder left behind. The student does the work; the lesson's
exercise grades the end state, and each fault's verify says True once the job
is done, so `winlab break --verify` and on-call agree with the exercise.

Every scene records what it planted under HKLM:\\SOFTWARE\\winlab\\scenario
(a baseline the checks compare against), and every account it makes gets a
random password generated inside the guest.
"""

from __future__ import annotations

# A random password made inside the guest; nothing secret is in the repo.
SECRET = ("(ConvertTo-SecureString -AsPlainText -Force "
          "([guid]::NewGuid().ToString('N').ToUpper() + '-' + [guid]::NewGuid().ToString('N')))")

SCENE_KEY = "HKLM:\\SOFTWARE\\winlab\\scenario"
# Made once and kept: New-Item -Force on a registry key that exists would
# wipe the values other scenes recorded in it.
_KEY = f"if (-not (Test-Path -Path '{SCENE_KEY}')) {{ New-Item -Path '{SCENE_KEY}' -Force | Out-Null }}; "

# Where a scene puts things: the lesson OUs when the student built them,
# the default containers otherwise.
_WHERE = (
    "$dom = Get-ADDomain; $base = $dom.DistinguishedName; "
    "function Find-Ou($dn, $fallback) { if (Get-ADOrganizationalUnit -Filter \"DistinguishedName -eq '$dn'\" "
    "-ErrorAction SilentlyContinue) { $dn } else { $fallback } }; "
    "$usersOu = Find-Ou ('OU=Users,OU=Corp,' + $base) $dom.UsersContainer; "
    "$groupsOu = Find-Ou ('OU=Groups,OU=Corp,' + $base) $dom.UsersContainer; "
    "$wksOu = Find-Ou ('OU=Workstations,OU=Corp,' + $base) $dom.ComputersContainer; "
    + _KEY
)


def _remember(name: str, value_ps: str) -> str:
    return f"Set-ItemProperty -Path '{SCENE_KEY}' -Name '{name}' -Value ([string]({value_ps})); "


def _recall(name: str) -> str:
    return f"(Get-ItemProperty -Path '{SCENE_KEY}' -ErrorAction SilentlyContinue).'{name}'"


# --------------------------------------------------------------- the leaver
LEAVER = "kmorgan"
LEAVER_HOME = "C:\\Shares\\Home"

LEAVER_APPLY = (
    _WHERE
    + f"$hd = '{LEAVER_HOME}\\{LEAVER}'; New-Item -ItemType Directory -Path $hd -Force | Out-Null; "
    "Set-Content -Path (Join-Path $hd 'Q3 pipeline.txt') -Value 'Open deals for the Q3 review.'; "
    "Set-Content -Path (Join-Path $hd 'Customer contacts.txt') -Value 'Who to call at each account.'; "
    f"if (-not (Get-SmbShare -Name 'Home$' -ErrorAction SilentlyContinue)) {{ New-SmbShare -Name 'Home$' -Path '{LEAVER_HOME}' "
    "-FullAccess 'Administrators' -ChangeAccess 'Authenticated Users' | Out-Null }; "
    f"if (-not (Get-ADUser -Filter \"SamAccountName -eq '{LEAVER}'\")) {{ "
    f"New-ADUser -Name 'Kim Morgan' -SamAccountName {LEAVER} -GivenName Kim -Surname Morgan -DisplayName 'Kim Morgan' "
    f"-UserPrincipalName ('{LEAVER}@' + $dom.DNSRoot) -EmailAddress ('kim.morgan@' + $dom.DNSRoot) "
    "-Department Sales -Title 'Account manager' -Description 'Account manager, Sales' "
    f"-HomeDirectory ('\\\\' + $env:COMPUTERNAME + '\\Home$\\{LEAVER}') -HomeDrive 'H:' -Path $usersOu "
    f"-AccountPassword {SECRET} -Enabled $true }}; "
    "foreach ($g in 'G-Sales', 'DL-Sales-Share', 'U-AllStaff', 'Remote Desktop Users') { "
    f"Add-ADGroupMember -Identity $g -Members {LEAVER} -ErrorAction SilentlyContinue }}; "
    f"icacls $hd /grant ('{LEAVER}' + ':(OI)(CI)M') | Out-Null; "
    + _remember("leaver-pwdlastset", f"(Get-ADUser {LEAVER} -Properties pwdLastSet).pwdLastSet")
    + _remember("leaver-planted", "(Get-Date).ToUniversalTime().ToString('o')")
    + f"'Kim Morgan ({LEAVER}) works here until today'"
)

LEAVER_CLEAR = (
    f"Get-ADUser -Filter \"SamAccountName -eq '{LEAVER}'\" | Remove-ADUser -Confirm:$false; "
    f"Remove-Item -Path '{LEAVER_HOME}\\{LEAVER}' -Recurse -Force -ErrorAction SilentlyContinue; "
    f"if (-not (Get-ChildItem -Path '{LEAVER_HOME}' -ErrorAction SilentlyContinue)) {{ "
    "Remove-SmbShare -Name 'Home$' -Force -ErrorAction SilentlyContinue }; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'leaver-pwdlastset', 'leaver-planted' -ErrorAction SilentlyContinue; 'cleared'"
)

# A reset is either a newer pwdLastSet than the one planted, or a 4724
# (password reset) event for the account since the scene was set.
LEAVER_RESET = (
    f"$ur = Get-ADUser -Filter \"SamAccountName -eq '{LEAVER}'\" -Properties pwdLastSet; "
    f"$was = [int64]{_recall('leaver-pwdlastset')}; "
    f"$since = {_recall('leaver-planted')}; "
    "$after = if ($since) { [datetime]::Parse($since).ToLocalTime() } else { (Get-Date).AddDays(-7) }; "
    "$ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4724; StartTime = $after } -ErrorAction SilentlyContinue | "
    f"Where-Object {{ $_.Properties[0].Value -eq '{LEAVER}' }}); "
    "$reset = ($ur -and [int64]$ur.pwdLastSet -gt $was) -or ($ev.Count -gt 0); "
)

LEAVER_VERIFY = (
    f"$u = Get-ADUser -Filter \"SamAccountName -eq '{LEAVER}'\" -Properties MemberOf, HomeDirectory, EmailAddress; "
    + LEAVER_RESET
    + f"[bool]($u -and -not $u.Enabled -and $u.DistinguishedName -match '^CN=[^,]+,OU=Disabled,' "
    "-and @($u.MemberOf).Count -eq 0 -and $u.HomeDirectory -and $u.EmailAddress -and $reset "
    f"-and (Test-Path -Path '{LEAVER_HOME}\\{LEAVER}\\*'))"
)


# ------------------------------------------------------- stale computers
STALE = (("WKS-0142", 212), ("WKS-0157", 145), ("LAP-0203", 388))
RECENT = ("WKS-0311", 3)
STALE_NAMES = ", ".join(f"'{n}'" for n, _ in STALE)

STALE_APPLY = (
    _WHERE
    + "$now = Get-Date; "
    "foreach ($p in @(" + ", ".join(f"@('{n}', {d})" for n, d in STALE + (RECENT,)) + ")) { "
    "$n = $p[0]; "
    "if (-not (Get-ADComputer -Filter \"Name -eq '$n'\")) { New-ADComputer -Name $n -SamAccountName ($n + '$') -Path $wksOu "
    "-OperatingSystem 'Windows 11 Pro' -Description 'Sales floor' -Enabled $true }; "
    "Set-ADComputer -Identity ($n + '$') -Replace @{ lastLogonTimestamp = $now.AddDays(0 - [int]$p[1]).ToFileTime() } }; "
    "Get-ADComputer -Filter \"Name -like 'WKS-0*' -or Name -like 'LAP-0*'\" -Properties LastLogonDate | "
    "ForEach-Object { '{0} last seen {1:yyyy-MM-dd}' -f $_.Name, $_.LastLogonDate }"
)

STALE_CLEAR = (
    "foreach ($n in @(" + STALE_NAMES + f", '{RECENT[0]}')) {{ "
    "Get-ADComputer -Filter \"Name -eq '$n'\" | Remove-ADObject -Recursive -Confirm:$false }; "
    "Remove-Item -Path 'C:\\winlab\\stale-computers.csv' -ErrorAction SilentlyContinue; 'cleared'"
)

STALE_VERIFY = (
    "$ok = $true; foreach ($n in @(" + STALE_NAMES + ")) { "
    "$c = Get-ADComputer -Filter \"Name -eq '$n'\"; "
    "if (-not $c -or $c.Enabled -or $c.DistinguishedName -notmatch ',OU=Stale,') { $ok = $false } }; "
    f"$r = Get-ADComputer -Filter \"Name -eq '{RECENT[0]}'\"; "
    "[bool]($ok -and $r -and $r.Enabled -and $r.DistinguishedName -notmatch ',OU=Stale,')"
)


# --------------------------------------------------- the prestaged kiosk
KIOSK, NEWNAME = "KIOSK-07", "FIN-PC07"

KIOSK_APPLY = (
    _WHERE
    + "foreach ($g in 'G-Kiosks', 'G-Finance-PCs') { if (-not (Get-ADGroup -Filter \"Name -eq '$g'\")) { "
    "New-ADGroup -Name $g -GroupScope Global -GroupCategory Security -Path $groupsOu } }; "
    f"if (-not (Get-ADComputer -Filter \"Name -eq '{KIOSK}'\")) {{ New-ADComputer -Name '{KIOSK}' -SamAccountName '{KIOSK}$' "
    f"-DNSHostName ('{KIOSK.lower()}.' + $dom.DNSRoot) -Path $dom.ComputersContainer -Description 'Lobby kiosk' -Enabled $true }}; "
    f"Add-ADGroupMember -Identity 'G-Kiosks' -Members '{KIOSK}$'; "
    + _remember("kiosk-guid", f"(Get-ADComputer -Identity '{KIOSK}$').ObjectGUID")
    + f"'{KIOSK} is prestaged in ' + $dom.ComputersContainer"
)

KIOSK_FIND = f"$id = {_recall('kiosk-guid')}; $c = if ($id) {{ try {{ Get-ADComputer -Identity $id -Properties DNSHostName, MemberOf }} catch {{ $null }} }}; "

KIOSK_CLEAR = (
    KIOSK_FIND
    + "if ($c) { Remove-ADObject -Identity $c.DistinguishedName -Recursive -Confirm:$false }; "
    "foreach ($g in 'G-Kiosks', 'G-Finance-PCs') { Get-ADGroup -Filter \"Name -eq '$g'\" | Remove-ADGroup -Confirm:$false }; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'kiosk-guid' -ErrorAction SilentlyContinue; 'cleared'"
)

KIOSK_VERIFY = (
    KIOSK_FIND
    + "$fin = (Get-ADGroup -Filter \"Name -eq 'G-Finance-PCs'\").DistinguishedName; "
    "$kio = (Get-ADGroup -Filter \"Name -eq 'G-Kiosks'\").DistinguishedName; "
    f"[bool]($c -and $c.Name -eq '{NEWNAME}' -and $c.SamAccountName -eq '{NEWNAME}$' -and $c.DNSHostName -like '{NEWNAME.lower()}.*' "
    f"-and $c.DistinguishedName -match '^CN={NEWNAME},OU=Workstations,' -and @($c.MemberOf) -contains $fin "
    "-and @($c.MemberOf) -notcontains $kio)"
)


# --------------------------------------------- extra Domain Admins members
CONTRACTOR, PROJECT_GROUP = "jcontractor", "G-Project-Ops"
_DA = "$daSid = (Get-ADDomain).DomainSID.Value + '-512'; "

ADMINS_APPLY = (
    _WHERE + _DA
    + f"if (-not (Get-ADUser -Filter \"SamAccountName -eq '{CONTRACTOR}'\")) {{ New-ADUser -Name 'Jo Contractor' "
    f"-SamAccountName {CONTRACTOR} -Description 'Contractor, server migration (project closed)' -Path $usersOu "
    f"-AccountPassword {SECRET} -Enabled $true }}; "
    f"if (-not (Get-ADGroup -Filter \"Name -eq '{PROJECT_GROUP}'\")) {{ New-ADGroup -Name '{PROJECT_GROUP}' -GroupScope Global "
    "-GroupCategory Security -Description 'Project operations team' -Path $groupsOu }; "
    f"Add-ADGroupMember -Identity '{PROJECT_GROUP}' -Members dlee -ErrorAction SilentlyContinue; "
    f"Add-ADGroupMember -Identity $daSid -Members {CONTRACTOR}, '{PROJECT_GROUP}'; "
    "Get-ADGroupMember -Identity $daSid | ForEach-Object { $_.SamAccountName }"
)

ADMINS_CLEAR = (
    _DA
    + f"Remove-ADGroupMember -Identity $daSid -Members '{PROJECT_GROUP}' -Confirm:$false -ErrorAction SilentlyContinue; "
    f"Get-ADUser -Filter \"SamAccountName -eq '{CONTRACTOR}'\" | Remove-ADUser -Confirm:$false; "
    f"Get-ADGroup -Filter \"Name -eq '{PROJECT_GROUP}'\" | Remove-ADGroup -Confirm:$false; "
    "Remove-Item -Path 'C:\\winlab\\domain-admins-review.txt' -ErrorAction SilentlyContinue; 'cleared'"
)

ADMINS_VERIFY = (
    _DA
    + "$all = @(Get-ADGroupMember -Identity $daSid -Recursive | ForEach-Object { $_.SamAccountName }); "
    "$direct = @(Get-ADGroupMember -Identity $daSid | ForEach-Object { $_.SamAccountName }); "
    "$admin = (Get-ADUser -Identity ((Get-ADDomain).DomainSID.Value + '-500')).SamAccountName; "
    "$t = [string](Get-Content -Path 'C:\\winlab\\domain-admins-review.txt' -Raw -ErrorAction SilentlyContinue); "
    f"[bool](($all -notcontains '{CONTRACTOR}') -and ($direct -notcontains '{PROJECT_GROUP}') -and ($all -notcontains 'dlee') "
    f"-and ($all -contains $admin) -and $t -match '{CONTRACTOR}' -and $t -match '{PROJECT_GROUP}')"
)


# ------------------------------------------- scheduled-task persistence
TASK_DIR = "C:\\ProgramData\\WinSvc"
TASKS = (("\\Microsoft\\Windows\\Maintenance\\", "WinSvcHealth"), ("\\", "UserTask-Sync"))
EVIDENCE = "C:\\winlab\\evidence"

TASK_APPLY = (
    f"$d = '{TASK_DIR}'; New-Item -ItemType Directory -Path $d -Force | Out-Null; "
    f"Set-Content -Path \"$d\\health.ps1\" -Value \"Add-Content -Path '{TASK_DIR}\\beacon.log' -Value (Get-Date -Format o)\"; "
    "(Get-Item -Path $d).Attributes = 'Hidden, Directory'; "
    "$base = @(Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\*' -ErrorAction SilentlyContinue).Count; "
    f"$a1 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File {TASK_DIR}\\health.ps1'; "
    "$t1 = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) "
    "-RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 365))); "
    "$sys = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; "
    f"Register-ScheduledTask -TaskPath '{TASKS[0][0]}' -TaskName '{TASKS[0][1]}' -Action $a1 -Trigger $t1 -Principal $sys "
    "-Description 'Keeps Windows services healthy.' -Force | Out-Null; "
    f"$a2 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c start /min powershell.exe -NoProfile -WindowStyle Hidden -File {TASK_DIR}\\health.ps1'; "
    f"Register-ScheduledTask -TaskPath '{TASKS[1][0]}' -TaskName '{TASKS[1][1]}' -Action $a2 -Trigger (New-ScheduledTaskTrigger -AtLogOn) "
    "-Principal $sys -Force | Out-Null; "
    f"Start-ScheduledTask -TaskPath '{TASKS[0][0]}' -TaskName '{TASKS[0][1]}'; "
    + _KEY
    + _remember("tasks-baseline", "$base")
    + "'two tasks planted'"
)

TASK_CLEAR = (
    "".join(f"Unregister-ScheduledTask -TaskPath '{p}' -TaskName '{n}' -Confirm:$false -ErrorAction SilentlyContinue; "
            for p, n in TASKS)
    + f"Remove-Item -Path '{TASK_DIR}' -Recurse -Force -ErrorAction SilentlyContinue; 'cleared'"
)

# Every task whose action mentions the payload folder, wherever it hides.
TASK_LEFT = ("$left = @(Get-ScheduledTask | Where-Object { (@($_.Actions) | ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) "
             "-match 'WinSvc' }); ")
TASK_EVIDENCE = (f"$ev = @(Get-ChildItem -Path '{EVIDENCE}' -Filter *.xml -ErrorAction SilentlyContinue | "
                 "Where-Object { [string](Get-Content -Path $_.FullName -Raw) -match 'WinSvc' }); ")

TASK_VERIFY = (
    TASK_LEFT + TASK_EVIDENCE
    + f"[bool](($left.Count -eq 0) -and -not (Test-Path -Path '{TASK_DIR}') -and ($ev.Count -ge 2))"
)


def register_faults(reg) -> None:
    from .guestfaults import WINDOWS, GuestFault
    reg(GuestFault(
        id="leaver-to-offboard",
        roles=("ad-ds",),
        title="A leaver's account is still live",
        os=WINDOWS,
        teaches="offboarding: disable rather than delete, move to a holding OU, strip group memberships, reset the "
                "password, and keep the person's home folder and mail address for the handover",
        symptom="HR says Kim Morgan in Sales left today; her account still signs in, sits in Sales and Remote "
                "Desktop groups, and her manager needs her files and mail address kept",
        apply=LEAVER_APPLY,
        clear=LEAVER_CLEAR,
        hints=(
            f"Read the account before you change it: Get-ADUser {LEAVER} -Properties MemberOf, HomeDirectory, "
            "EmailAddress. Note the groups and the home folder; those are what the checklist works through.",
            "Offboarding is disable, move, strip, reset, keep. A holding OU called Disabled under Corp keeps leavers "
            "out of the policies and delegations aimed at live users. Deleting the account loses its SID and the "
            "audit trail.",
            "Disable-ADAccount, Move-ADObject into OU=Disabled,OU=Corp, Remove-ADGroupMember for each group in "
            "MemberOf (Domain Users stays: it is the primary group), Set-ADAccountPassword -Reset with a random "
            "password. Leave HomeDirectory, EmailAddress and the folder alone.",
        ),
        verify=LEAVER_VERIFY,
    ))
    reg(GuestFault(
        id="stale-computers",
        roles=("ad-ds",),
        title="Computer accounts nobody has seen for months",
        os=WINDOWS,
        teaches="lastLogonTimestamp and why it lags by up to two weeks, Search-ADAccount -AccountInactive, and the "
                "disable, move, wait, delete cycle for stale computer accounts",
        symptom="the asset list says the office has fewer PCs than Active Directory does; some accounts in the "
                "Workstations OU belong to machines that were scrapped months ago",
        apply=STALE_APPLY,
        clear=STALE_CLEAR,
        hints=(
            "Ask the directory when each computer last authenticated: Get-ADComputer -Filter * -Properties "
            "LastLogonDate | Sort-Object LastLogonDate. LastLogonDate is lastLogonTimestamp made readable; it "
            "replicates, but only updates every 9 to 14 days.",
            "Search-ADAccount -AccountInactive -ComputersOnly -TimeSpan 90.00:00:00 lists the candidates. Check each "
            "against reality before acting: a machine seen three days ago is not stale.",
            "For each stale one: Disable-ADAccount, then Move-ADObject into an OU called Stale under Corp, and keep a "
            "list (Export-Csv) of what you did. Deleting comes later, after the waiting period.",
        ),
        verify=STALE_VERIFY,
    ))
    reg(GuestFault(
        id="prestaged-kiosk",
        roles=("ad-ds",),
        title="A prestaged computer account changes jobs",
        os=WINDOWS,
        teaches="what a computer account's names are (CN, sAMAccountName with its $, dNSHostName), renaming and "
                "moving an account without recreating it, and group-based targeting of computers",
        symptom=f"the lobby kiosk {KIOSK} was never built; the hardware goes to Finance as {NEWNAME} instead, and "
                "it must get the Finance PCs' policies and none of the kiosk lockdown",
        apply=KIOSK_APPLY,
        clear=KIOSK_CLEAR,
        hints=(
            f"Look at the account first: Get-ADComputer {KIOSK} -Properties DNSHostName, MemberOf. Note where it "
            "sits and which group targets it.",
            "A computer account has three names: the CN (Rename-ADObject), the sAMAccountName that ends in $ and "
            "the dNSHostName (both Set-ADComputer). Renaming keeps the SID and the GUID; delete and recreate does "
            "not.",
            f"Rename the object to {NEWNAME}, set -SamAccountName and -DNSHostName to match, Move-ADObject it into "
            "the Workstations OU, then swap G-Kiosks for G-Finance-PCs with Remove-ADGroupMember and "
            "Add-ADGroupMember.",
        ),
        verify=KIOSK_VERIFY,
    ))
    reg(GuestFault(
        id="extra-domain-admins",
        roles=("ad-ds",),
        title="Domain Admins has members nobody can explain",
        os=WINDOWS,
        teaches="reviewing privileged groups, nested membership (Get-ADGroupMember -Recursive), removing access "
                "without deleting the team's own group, and writing the review down",
        symptom="the auditor's question is who can administer the domain; the answer is longer than the IT team "
                "and includes a contractor whose project closed",
        apply=ADMINS_APPLY,
        clear=ADMINS_CLEAR,
        hints=(
            "Get-ADGroupMember 'Domain Admins' shows direct members only. Add -Recursive and compare the two "
            "lists: a group inside the group makes all its members domain admins.",
            "Read each unexpected entry's Description and its own members before acting. A contractor whose project "
            "closed should not be there; a project team's group should not be nested in a tier 0 group.",
            "Remove-ADGroupMember 'Domain Admins' for the extra user and the nested group (keep the group itself: "
            "the team still uses it), and write C:\\winlab\\domain-admins-review.txt naming both and why.",
        ),
        verify=ADMINS_VERIFY,
    ))
    reg(GuestFault(
        id="task-persistence",
        title="Something runs a hidden script every half hour",
        os=WINDOWS,
        teaches="persistence through scheduled tasks: finding a task by what it runs rather than by its name, "
                "keeping its definition as evidence (Export-ScheduledTask), and removing task and payload",
        symptom="the endpoint team saw a hidden PowerShell window start on this server at boot and every half "
                "hour, as SYSTEM; nobody admits to scheduling anything",
        apply=TASK_APPLY,
        clear=TASK_CLEAR,
        hints=(
            "A task hides behind its name and its folder, never behind what it runs. List every task with its "
            "actions: Get-ScheduledTask | ForEach-Object { $_.TaskPath + $_.TaskName + ' ' + $_.Actions.Execute + "
            "' ' + $_.Actions.Arguments }.",
            "Look for powershell or cmd with -WindowStyle Hidden, -ExecutionPolicy Bypass or a script under "
            "ProgramData. There is more than one task, and one of them sits in a folder Windows uses for its own.",
            f"Export-ScheduledTask each one into {EVIDENCE} as XML first, then Unregister-ScheduledTask it, then "
            "delete the folder the script lives in. Leave Windows' own tasks alone.",
        ),
        verify=TASK_VERIFY,
    ))
