"""Injections only a scenario day uses (winlab/scenarios.py).

They have the shape of a guest fault (apply, clear, verify, run over the
serial agent) but they are not problems on their own, so they are kept out
of the Troubleshooting window and the helpdesk shift: a scenario names them
by id and the scenario engine looks here before the guest fault catalog.

Ransomware morning uses two:

  finance-files-arrive   Finance's users drop their quarter-end files on the
                         file server (C:\\Shares\\Finance). Data, not
                         configuration: no share, no permission, no service
                         is set up. A manifest of the files' hashes is kept
                         under C:\\winlab\\scenario so a restore can be proved.
  ransomware-drill       A harmless stand-in for ransomware. Every Finance
                         file is renamed to .wlcry and its bytes reversed
                         (scrambled, not encrypted, nothing leaves the lab),
                         a note appears beside them, and the way in is left
                         as evidence to find: a local admin account nobody
                         recognises and a scheduled task it created, whose
                         script stands in for the attacker's tool and does
                         nothing. Clear puts every file back byte for byte
                         and removes the account, the task and the note.

Every script here parses under Windows PowerShell 5.1 and never uses
`return` or `exit`: the agent runs it with Invoke-Expression inside its own
function, where either would end the agent's request instead.
"""

from __future__ import annotations

_FIN = "C:\\Shares\\Finance"
_DIR = "C:\\winlab\\scenario"
_MANIFEST = _DIR + "\\finance-files.json"
_SEEDED = _DIR + "\\finance-seeded.txt"
_TASK = "SyncHelper"
_USER = "scan-svc"
_TOOL = "C:\\ProgramData\\SyncHelper"
_NOTE = "HOW-TO-RECOVER-FILES.txt"
_EXT = ".wlcry"

FINANCE_FILES = ("Q3-revenue.csv", "Q3-expenses.csv", "payroll-summary.txt", "supplier-list.csv",
                 "budget-2027-draft.txt", "board-minutes-september.txt", "invoice-run-0931.csv",
                 "audit-checklist.txt")

_SEED = (
    f"$d = '{_FIN}'; New-Item -ItemType Directory -Path $d -Force | Out-Null; "
    f"New-Item -ItemType Directory -Path '{_DIR}' -Force | Out-Null; "
    "$rows = @(); $i = 0; "
    "foreach ($n in @(" + ", ".join(f"'{n}'" for n in FINANCE_FILES) + ")) { "
    "$i++; $lines = @(('winlab practice file ' + $n), 'Department: Finance', 'Made for the Ransomware morning scenario day.'); "
    "foreach ($r in 1..40) { $lines += ('{0},{1},{2}' -f $n, $r, ($r * 137 + $i * 11)) }; "
    "$p = Join-Path $d $n; Set-Content -Path $p -Value $lines -Encoding UTF8; "
    "$rows += New-Object PSObject -Property @{ name = $n; sha256 = (Get-FileHash -Path $p -Algorithm SHA256).Hash } }; "
    f"ConvertTo-Json -InputObject $rows | Set-Content -Path '{_MANIFEST}' -Encoding UTF8; "
    f"(Get-Date).ToUniversalTime().ToString('o') | Set-Content -Path '{_SEEDED}' -Encoding ASCII; "
    f"(@(Get-ChildItem -Path $d -File).Count -ge {len(FINANCE_FILES)})"
)

# Undo of the seed is deliberately empty of deletes: once the student has
# shared and backed the files up they are the student's data.
_SEED_CLEAR = "'True'"

_SEED_VERIFY = f"(Test-Path '{_MANIFEST}') -and (@(Get-ChildItem -Path '{_FIN}' -File -ErrorAction SilentlyContinue).Count -ge 1)"

_DRILL = (
    f"$d = '{_FIN}'; $ok = $false; "
    f"if (Test-Path '{_MANIFEST}') {{ "
    # the way in: an account nobody recognises, in the local Administrators group
    f"if (-not (Get-LocalUser -Name '{_USER}' -ErrorAction SilentlyContinue)) {{ "
    f"New-LocalUser -Name '{_USER}' -NoPassword -Description 'Scanner upload account (old MFP)' | Out-Null }}; "
    f"Enable-LocalUser -Name '{_USER}'; "
    f"Add-LocalGroupMember -Group 'Administrators' -Member '{_USER}' -ErrorAction SilentlyContinue; "
    # the tool and the task it registered (both harmless)
    f"New-Item -ItemType Directory -Path '{_TOOL}' -Force | Out-Null; "
    f"Set-Content -Path '{_TOOL}\\sync.ps1' -Encoding UTF8 -Value @("
    "'# winlab drill: this file stands in for the attacker''s tool. It does nothing.', "
    f"'Get-ChildItem -Path ''{_FIN}'' | Out-Null'); "
    "$a = New-ScheduledTaskAction -Execute 'powershell.exe' "
    f"-Argument '-NoProfile -WindowStyle Hidden -File {_TOOL}\\sync.ps1'; "
    "$tr = New-ScheduledTaskTrigger -AtStartup; "
    "$pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest; "
    "$t = New-ScheduledTask -Action $a -Trigger $tr -Principal $pr -Description 'Keeps scanned documents in sync'; "
    f"$t.Author = $env:COMPUTERNAME + '\\{_USER}'; "
    f"Register-ScheduledTask -TaskName '{_TASK}' -InputObject $t -Force | Out-Null; "
    f"if (-not [Diagnostics.EventLog]::SourceExists('{_TASK}')) {{ New-EventLog -LogName Application -Source '{_TASK}' }}; "
    f"Write-EventLog -LogName Application -Source '{_TASK}' -EventId 4100 -EntryType Information "
    f"-Message ('{_TASK} started by {_USER}: processing ' + $d); "
    # scramble every file: reversed bytes under a new name
    f"$m = Get-Content -Path '{_MANIFEST}' -Raw | ConvertFrom-Json; "
    "foreach ($f in @($m)) { $p = Join-Path $d $f.name; if (Test-Path $p) { "
    "$b = [IO.File]::ReadAllBytes($p); [Array]::Reverse($b); "
    f"[IO.File]::WriteAllBytes($p + '{_EXT}', $b); Remove-Item -Path $p -Force }} }}; "
    f"Set-Content -Path (Join-Path $d '{_NOTE}') -Encoding UTF8 -Value @("
    "'Your files have been encrypted. To get them back, contact us.', '', "
    "'(This is a winlab drill. Nothing was stolen and nothing left the lab: the files were scrambled. "
    "Restore them from your backup.)'); "
    f"$ok = (@(Get-ChildItem -Path $d -Filter '*{_EXT}').Count -ge 1) }}; $ok"
)

_DRILL_CLEAR = (
    f"$d = '{_FIN}'; "
    f"foreach ($x in @(Get-ChildItem -Path $d -Filter '*{_EXT}' -ErrorAction SilentlyContinue)) {{ "
    f"$orig = $x.FullName.Substring(0, $x.FullName.Length - {len(_EXT)}); "
    "if (-not (Test-Path $orig)) { $b = [IO.File]::ReadAllBytes($x.FullName); [Array]::Reverse($b); "
    "[IO.File]::WriteAllBytes($orig, $b) }; Remove-Item -Path $x.FullName -Force }; "
    f"Remove-Item -Path (Join-Path $d '{_NOTE}') -Force -ErrorAction SilentlyContinue; "
    f"Unregister-ScheduledTask -TaskName '{_TASK}' -Confirm:$false -ErrorAction SilentlyContinue; "
    f"Remove-Item -Path '{_TOOL}' -Recurse -Force -ErrorAction SilentlyContinue; "
    f"Remove-LocalUser -Name '{_USER}' -ErrorAction SilentlyContinue; "
    f"if ([Diagnostics.EventLog]::SourceExists('{_TASK}')) {{ Remove-EventLog -Source '{_TASK}' }}; 'True'"
)

# Fixed means the files are back and the way in is shut; the scenario
# grades each half as its own task (content/scenarios/ransomware-morning.toml).
_DRILL_VERIFY = (
    f"$m = Get-Content -Path '{_MANIFEST}' -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json; $ok = [bool]$m; "
    f"foreach ($f in @($m)) {{ $p = Join-Path '{_FIN}' $f.name; "
    "if (-not (Test-Path $p)) { $ok = $false } elseif ((Get-FileHash -Path $p -Algorithm SHA256).Hash -ne $f.sha256) { $ok = $false } }; "
    f"$t = Get-ScheduledTask -TaskName '{_TASK}' -ErrorAction SilentlyContinue; "
    f"$u = Get-LocalUser -Name '{_USER}' -ErrorAction SilentlyContinue; "
    "$ok -and ((-not $t) -or ([string]$t.State -eq 'Disabled')) -and ((-not $u) -or (-not $u.Enabled))"
)


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [
        GuestFault(
            id="finance-files-arrive",
            roles=("file",),
            title="Finance's quarter-end files arrive on the file server",
            os=WINDOWS,
            teaches="(scenario starting state) the files a later restore must bring back",
            symptom="new files in C:\\Shares\\Finance",
            apply=_SEED, clear=_SEED_CLEAR, verify=_SEED_VERIFY,
        ),
        GuestFault(
            id="ransomware-drill",
            roles=("file",),
            title="Ransomware drill: the Finance files are scrambled",
            os=WINDOWS,
            teaches="containing an incident, restoring from backup, and finding the way in",
            symptom="every file in the Finance share ends in .wlcry and will not open, and a note demands contact",
            apply=_DRILL, clear=_DRILL_CLEAR, verify=_DRILL_VERIFY,
        ),
    ] + _day_faults()


# ===================================================================
# The working-day scenarios: a DC that dies, Monday's lockouts, a full disk
# at month-end, an expired VPN certificate, an access review, a botched GPO,
# a new office, a phished account, a maintenance window and a storage
# migration. Each injection either drops data a later check compares against
# (a manifest, a CSV, a recorded time) or breaks something the student
# built; none of them sets anything up.
# ===================================================================
_SCN = "C:\\winlab\\scenario"
_MK = f"New-Item -ItemType Directory -Path '{_SCN}' -Force | Out-Null; "
_NOW_UTC = "(Get-Date).ToUniversalTime().ToString('o')"
# Parses a time written with _NOW_UTC back, in UTC.
_PARSE_UTC = "[datetime]::Parse(([string]{0}).Trim(), $null, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()"


def _when(ps: str) -> str:
    return _PARSE_UTC.replace("{0}", ps)


# --------------------------------------------------- a DC dies at seven
# dc01's directory stops and is set not to start: the server answers on the
# network, but it is no longer a domain controller for anyone. The story
# forbids starting it (the database is suspect), so the student moves the
# roles to dc02. A later beat "repairs" it the way the vendor would.
DC_DOWN_SERVICES = ("Netlogon", "Kdc", "DNS", "NTDS")

_DC_DOWN = (
    _MK + f"{_NOW_UTC} | Set-Content -Path '{_SCN}\\dc-down.txt' -Encoding ASCII; "
    "foreach ($s in @(" + ", ".join(f"'{s}'" for s in DC_DOWN_SERVICES) + ")) { "
    "Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue }; "
    "foreach ($s in @(" + ", ".join(f"'{s}'" for s in DC_DOWN_SERVICES) + ")) { "
    "Stop-Service -Name $s -Force -ErrorAction SilentlyContinue }; "
    "[string](Get-Service -Name 'NTDS').Status -eq 'Stopped'"
)
_DC_DOWN_CLEAR = (
    "foreach ($s in @('NTDS', 'DNS', 'Kdc', 'Netlogon')) { "
    "Set-Service -Name $s -StartupType Automatic -ErrorAction SilentlyContinue; "
    "Start-Service -Name $s -ErrorAction SilentlyContinue }; 'True'"
)
_DC_DOWN_VERIFY = (
    "$ok = $true; foreach ($s in @('NTDS', 'DNS', 'Kdc', 'Netlogon')) { "
    "if ([string](Get-Service -Name $s -ErrorAction SilentlyContinue).Status -ne 'Running') { $ok = $false } }; $ok"
)


# --------------------------------------------------- Monday morning lockouts
# Six people come back from a long weekend. Three passwords expired over it,
# two people typed old ones until they locked, and Diego is fine until a
# forgotten job on fs01 starts trying his old password every minute.
MONDAY_EXPIRED = ("hito", "lnovak", "jmensah")
MONDAY_LOCKED = ("mrossi", "zweber")
MONDAY_PEOPLE = (("hito", "Hannah", "Ito", "Sales"), ("lnovak", "Lena", "Novak", "Finance"),
                 ("jmensah", "Jamal", "Mensah", "Sales"), ("mrossi", "Marco", "Rossi", "Operations"),
                 ("zweber", "Zara", "Weber", "Finance"), ("dcosta", "Diego", "Costa", "Operations"))


def _ps_rows(rows) -> str:
    return "@(" + ", ".join("@(" + ", ".join(f"'{c}'" for c in r) + ")" for r in rows) + ")"


def _ps_names(names) -> str:
    return "@(" + ", ".join(f"'{n}'" for n in names) + ")"


def _bad_binds(names_ps: str, tries_ps: str) -> str:
    # A sign-in with a password nobody knows, made fresh each time: it fails
    # and counts as a bad attempt, exactly as a user typing the old one.
    return (f"foreach ($sam in {names_ps}) {{ foreach ($i in 1..({tries_ps})) {{ "
            "$bad = [guid]::NewGuid().ToString(); "
            "try { $e = New-Object DirectoryServices.DirectoryEntry(('LDAP://' + $env:COMPUTERNAME), "
            "($dom.NetBIOSName + '\\' + $sam), $bad); $e.RefreshCache() } catch { } } }; ")


def _people(rows_ps: str, extra: str = "") -> str:
    """Makes each person who is not there yet, with a password generated in
    the guest, and remembers who was made so clear removes only them."""
    from .dayops import SECRET
    return (f"$made = @(); foreach ($p in {rows_ps}) {{ $sam = $p[0]; "
            "if (-not (Get-ADUser -Filter \"SamAccountName -eq '$sam'\")) { "
            "New-ADUser -Name ($p[1] + ' ' + $p[2]) -SamAccountName $sam -GivenName $p[1] -Surname $p[2] "
            "-DisplayName ($p[1] + ' ' + $p[2]) -Department $p[3] -UserPrincipalName ($sam + '@' + $dom.DNSRoot) "
            f"-Path $usersOu -AccountPassword {SECRET} -Enabled $true{extra}; $made += $sam }} }}; ")


def _monday():
    from .dayops import _WHERE, _recall, _remember
    apply = (
        _WHERE + _people(_ps_rows(MONDAY_PEOPLE), " -Description 'Back from the long weekend'")
        + _remember("monday-made", "$made -join ','")
        + _remember("monday-planted", _NOW_UTC)
        + f"foreach ($sam in {_ps_names(MONDAY_EXPIRED)}) {{ Set-ADUser -Identity $sam -ChangePasswordAtLogon $true }}; "
        + "$th = [int](Get-ADDefaultDomainPasswordPolicy).LockoutThreshold; "
        + _bad_binds(_ps_names(MONDAY_LOCKED), "[Math]::Max(1, $th) + 2")
        + f"$locked = @({_ps_names(MONDAY_LOCKED)} | Where-Object {{ [int64](Get-ADUser -Identity $_ -Properties lockoutTime).lockoutTime -gt 0 }}); "
        + f"$exp = @({_ps_names(MONDAY_EXPIRED)} | Where-Object {{ (Get-ADUser -Identity $_ -Properties PasswordExpired).PasswordExpired }}); "
        + f"($th -gt 0) -and ($locked.Count -eq {len(MONDAY_LOCKED)}) -and ($exp.Count -eq {len(MONDAY_EXPIRED)})"
    )
    clear = (
        f"$made = @(([string]{_recall('monday-made')}) -split ',' | Where-Object {{ $_ }}); "
        f"foreach ($p in {_ps_rows(MONDAY_PEOPLE)}) {{ $sam = $p[0]; "
        "$u = Get-ADUser -Filter \"SamAccountName -eq '$sam'\"; if ($u) { "
        "if ($made -contains $sam) { $u | Remove-ADUser -Confirm:$false } else { "
        "Set-ADUser -Identity $sam -ChangePasswordAtLogon $false; Unlock-ADAccount -Identity $sam } } }; 'True'"
    )
    verify = (
        f"$ok = $true; foreach ($sam in {_ps_names(MONDAY_EXPIRED + MONDAY_LOCKED)}) {{ "
        "$u = Get-ADUser -Identity $sam -Properties PasswordExpired, lockoutTime -ErrorAction SilentlyContinue; "
        "if (-not $u -or $u.PasswordExpired -or [int64]$u.lockoutTime -gt 0) { $ok = $false } }; $ok"
    )
    return apply, clear, verify


LOCKOUT_TASK = "ScanToFolder Upload"
_SCANDIR = "C:\\ProgramData\\ScanToFolder"

_STALE_CRED = (
    f"$d = '{_SCANDIR}'; New-Item -ItemType Directory -Path $d -Force | Out-Null; "
    "Set-Content -Path (Join-Path $d 'upload.ps1') -Encoding UTF8 -Value @("
    "'# Scan to folder: signs in as dcosta to upload the scanner''s documents. Set up by Diego in 2024.', "
    "'# winlab: the password below stands in for the one Diego changed on Friday; it is made new each run and never works.', "
    "'$u = ''dcosta@{domain}''', "
    "'$p = [guid]::NewGuid().ToString()', "
    "'try { $e = New-Object DirectoryServices.DirectoryEntry(''LDAP://{domain}'', $u, $p); $e.RefreshCache() } catch { }'); "
    "$a = New-ScheduledTaskAction -Execute 'powershell.exe' "
    f"-Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File {_SCANDIR}\\upload.ps1'; "
    "$tr = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) "
    "-RepetitionDuration (New-TimeSpan -Days 1); "
    "$pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; "
    f"Register-ScheduledTask -TaskName '{LOCKOUT_TASK}' -Action $a -Trigger $tr -Principal $pr "
    "-Description 'Uploads the scanner documents as dcosta' -Force | Out-Null; "
    f"Start-ScheduledTask -TaskName '{LOCKOUT_TASK}'; "
    f"[bool](Get-ScheduledTask -TaskName '{LOCKOUT_TASK}' -ErrorAction SilentlyContinue)"
)
_STALE_CRED_CLEAR = (
    f"Unregister-ScheduledTask -TaskName '{LOCKOUT_TASK}' -Confirm:$false -ErrorAction SilentlyContinue; "
    f"Remove-Item -Path '{_SCANDIR}' -Recurse -Force -ErrorAction SilentlyContinue; 'True'"
)
_STALE_CRED_VERIFY = (
    f"$t = Get-ScheduledTask -TaskName '{LOCKOUT_TASK}' -ErrorAction SilentlyContinue; "
    "(-not $t) -or ([string]$t.State -eq 'Disabled')"
)


# --------------------------------------------------- month-end, and the disk fills
MONTH_END_FILES = ("ledger-october.csv", "accruals-october.csv", "bank-reconciliation.csv",
                   "vat-return-draft.txt", "payroll-october.csv", "fixed-assets.csv",
                   "close-checklist.txt", "management-pack-draft.txt")
_COMPANY = "$s = Get-SmbShare -Name '{share}' -ErrorAction SilentlyContinue; "
_NOSHARE = "'nothing to break: share the company folder on this server first (lesson quotas-and-file-screens)'"


def _seed_files(folder_ps: str, names, manifest: str, seeded: str, label: str) -> str:
    """Writes practice files and keeps a manifest of their hashes, so a later
    check can prove every one is back unchanged."""
    return (
        f"$d = {folder_ps}; New-Item -ItemType Directory -Path $d -Force | Out-Null; " + _MK
        + "$rows = @(); $i = 0; "
        f"foreach ($n in {_ps_names(names)}) {{ "
        f"$i++; $lines = @(('winlab practice file ' + $n), 'Made for the {label} scenario day.'); "
        "foreach ($r in 1..40) { $lines += ('{0},{1},{2}' -f $n, $r, ($r * 211 + $i * 7)) }; "
        "$p = Join-Path $d $n; Set-Content -Path $p -Value $lines -Encoding UTF8; "
        "$rows += New-Object PSObject -Property @{ name = $n; sha256 = (Get-FileHash -Path $p -Algorithm SHA256).Hash } }; "
        f"ConvertTo-Json -InputObject $rows | Set-Content -Path '{manifest}' -Encoding UTF8; "
        f"{_NOW_UTC} | Set-Content -Path '{seeded}' -Encoding ASCII; "
        f"(@(Get-ChildItem -Path $d -File).Count -ge {len(names)})"
    )


_MONTH_END = (
    _COMPANY + f"if (-not $s) {{ {_NOSHARE} }} else {{ "
    + _seed_files("(Join-Path $s.Path 'Finance\\Month-End')", MONTH_END_FILES, f"{_SCN}\\month-end.json",
                  f"{_SCN}\\month-end-seeded.txt", "Month-end")
    + " }"
)
_MONTH_END_VERIFY = f"Test-Path -Path '{_SCN}\\month-end.json'"

_DUMP = "ScanStation-batch-0917.tmp"
_DISK_FULL = (
    _COMPANY + f"if (-not $s) {{ {_NOSHARE} }} else {{ " + _MK
    + "$scans = Join-Path $s.Path 'Scans'; New-Item -ItemType Directory -Path $scans -Force | Out-Null; "
    f"$f = Join-Path $scans '{_DUMP}'; Set-Content -Path '{_SCN}\\scan-dump.txt' -Value $f; "
    "foreach ($i in 1..6) { Set-Content -Path (Join-Path $scans ('scan-{0:D4}.pdf' -f $i)) -Value 'winlab practice scan' }; "
    "Set-Content -Path (Join-Path $scans 'ScanStation.log') -Value @('ScanStation 4.2: batch 0917 started', "
    "'ScanStation 4.2: upload failed, keeping the temporary batch file and retrying', 'ScanStation 4.2: batch 0917 retry 312'); "
    "$drv = New-Object IO.DriveInfo((Split-Path -Path $s.Path -Qualifier)); "
    "try { $fs = New-Object IO.FileStream($f, 'Create'); $fs.SetLength([Math]::Max(1MB, $drv.AvailableFreeSpace - 150MB)); "
    "$fs.Close() } catch { }; "
    "$drv = New-Object IO.DriveInfo((Split-Path -Path $s.Path -Qualifier)); ($drv.AvailableFreeSpace -lt 400MB) }"
)
_DISK_FULL_CLEAR = (
    f"$f = Get-Content -Path '{_SCN}\\scan-dump.txt' -ErrorAction SilentlyContinue; "
    "if ($f) { Remove-Item -Path ([string]$f).Trim() -Force -ErrorAction SilentlyContinue }; 'True'"
)
_DISK_FULL_VERIFY = (
    f"$f = Get-Content -Path '{_SCN}\\scan-dump.txt' -ErrorAction SilentlyContinue; "
    "if ($f) { $drv = New-Object IO.DriveInfo((Split-Path -Path ([string]$f).Trim() -Qualifier)); "
    "$drv.AvailableFreeSpace -gt 2GB } else { $false }"
)


# --------------------------------------------------- the VPN certificate expired
_SSTP_SAVED = "C:\\Windows\\Temp\\winlab-sstp-expired.txt"
_SSTP_EXPIRED = (
    "if (-not (Get-Command Get-RemoteAccess -ErrorAction SilentlyContinue)) { "
    "'nothing to break: build the VPN edge first (lesson remote-access-sstp)' } else { "
    "$ra = Get-RemoteAccess -ErrorAction SilentlyContinue; "
    "if (-not $ra -or -not $ra.SslCertificate) { 'nothing to break: give SSTP its certificate first (lesson remote-access-sstp)' } else { "
    f"if (-not (Test-Path '{_SSTP_SAVED}')) {{ $ra.SslCertificate.Thumbprint | Set-Content '{_SSTP_SAVED}' }}; "
    "$c = New-SelfSignedCertificate -DnsName '{vpnname}' -CertStoreLocation 'Cert:\\LocalMachine\\My' "
    "-NotBefore (Get-Date).AddDays(-400) -NotAfter (Get-Date).AddDays(-1) -FriendlyName 'winlab {vpnname} last year'; "
    "$ok = $true; try { Set-RemoteAccess -SslCertificate $c -ErrorAction Stop } catch { $ok = $false }; "
    "Restart-Service -Name RemoteAccess -Force -ErrorAction SilentlyContinue; "
    "if ($ok) { 'broken' } else { 'nothing to break: RRAS would not take the expired certificate on this build' } } }"
)
_SSTP_EXPIRED_CLEAR = (
    f"$f = '{_SSTP_SAVED}'; if (Test-Path $f) {{ $t = (Get-Content $f | Select-Object -First 1).Trim(); "
    "$c = Get-Item ('Cert:\\LocalMachine\\My\\' + $t) -ErrorAction SilentlyContinue; "
    "if ($c) { Set-RemoteAccess -SslCertificate $c; Restart-Service -Name RemoteAccess -Force }; Remove-Item $f }; "
    "Get-ChildItem -Path 'Cert:\\LocalMachine\\My' | Where-Object { $_.FriendlyName -like 'winlab * last year' } | "
    "Remove-Item -ErrorAction SilentlyContinue; 'True'"
)
_SSTP_EXPIRED_VERIFY = (
    "$c = (Get-RemoteAccess -ErrorAction SilentlyContinue).SslCertificate; "
    "[bool]($c -and $c.NotAfter -gt (Get-Date).AddDays(7) -and $c.NotBefore -lt (Get-Date) "
    "-and (@($c.DnsNameList | ForEach-Object { $_.Unicode }) -contains '{vpnname}') "
    "-and (Test-Certificate -Cert $c -Policy SSL -DNSName '{vpnname}' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue))"
)


# --------------------------------------------------- the auditor finds Everyone
_EVERYONE = "S-1-1-0"
_WIDE = (
    _COMPANY + f"if (-not $s) {{ {_NOSHARE} }} else {{ " + _MK
    + "$was = @(Get-SmbShareAccess -Name '{share}' | Where-Object { $_.AccountName -match 'Everyone' -and "
    "[string]$_.AccessControlType -eq 'Allow' } | ForEach-Object { [string]$_.AccessRight }); "
    f"Set-Content -Path '{_SCN}\\share-everyone.txt' -Value ($(if ($was) {{ $was[0] }} else {{ 'none' }})); "
    "Grant-SmbShareAccess -Name '{share}' -AccountName 'Everyone' -AccessRight Full -Force | Out-Null; "
    "$hr = Join-Path $s.Path 'HR'; New-Item -ItemType Directory -Path $hr -Force | Out-Null; "
    "Set-Content -Path (Join-Path $hr 'salaries-2026.csv') -Value @('name,band', 'winlab practice row,0'); "
    "Set-Content -Path (Join-Path $hr 'disciplinary-notes.txt') -Value 'winlab practice file: HR only.'; "
    f"icacls $hr /grant '*{_EVERYONE}:(OI)(CI)F' | Out-Null; 'broken' }}"
)
_WIDE_CLEAR = (
    _COMPANY + "if ($s) { "
    f"$was = ([string](Get-Content -Path '{_SCN}\\share-everyone.txt' -ErrorAction SilentlyContinue)).Trim(); "
    "if ($was -and $was -ne 'none') { Grant-SmbShareAccess -Name '{share}' -AccountName 'Everyone' -AccessRight $was -Force | Out-Null } "
    "else { Revoke-SmbShareAccess -Name '{share}' -AccountName 'Everyone' -Force | Out-Null }; "
    f"icacls (Join-Path $s.Path 'HR') /remove:g '*{_EVERYONE}' | Out-Null }}; 'True'"
)
_WIDE_VERIFY = (
    _COMPANY + "if ($s) { "
    "$sh = @(Get-SmbShareAccess -Name '{share}' | Where-Object { $_.AccountName -match 'Everyone' -and "
    "[string]$_.AccessControlType -eq 'Allow' -and @('Full', 'Change') -contains [string]$_.AccessRight }); "
    "$hr = Join-Path $s.Path 'HR'; $fs = @(); if (Test-Path $hr) { $fs = @((Get-Acl -Path $hr).Access | Where-Object { "
    f"$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq '{_EVERYONE}' -and "
    "[string]$_.AccessControlType -eq 'Allow' -and ([string]$_.FileSystemRights -match 'FullControl|Modify|Write') }) }; "
    "($sh.Count -eq 0) -and ($fs.Count -eq 0) } else { $false }"
)


# --------------------------------------------------- the botched GPO change
_GPO_STATUS = (
    "Import-Module GroupPolicy; $g = Get-GPO -Name '{gpo}' -ErrorAction SilentlyContinue; "
    "if (-not $g) { 'nothing to break: create the drive-mapping policy first (lesson gpo-drive-mapping)' } else { " + _MK
    + f"Set-Content -Path '{_SCN}\\gpo-status.txt' -Value ([string]$g.GpoStatus); "
    "$g.GpoStatus = 'UserSettingsDisabled'; 'broken' }"
)
_GPO_STATUS_CLEAR = (
    "Import-Module GroupPolicy; $g = Get-GPO -Name '{gpo}' -ErrorAction SilentlyContinue; "
    f"$was = ([string](Get-Content -Path '{_SCN}\\gpo-status.txt' -ErrorAction SilentlyContinue)).Trim(); "
    "if ($g) { if ($was) { $g.GpoStatus = $was } else { $g.GpoStatus = 'AllSettingsEnabled' } }; 'True'"
)
_GPO_STATUS_VERIFY = (
    "Import-Module GroupPolicy; $g = Get-GPO -Name '{gpo}' -ErrorAction SilentlyContinue; "
    "[bool]($g -and (@('AllSettingsEnabled', 'ComputerSettingsDisabled') -contains [string]$g.GpoStatus))"
)


# --------------------------------------------------- a new office opens tomorrow
NEW_OFFICE = (
    ("Amara", "Okafor", "aokafor", "Sales", "Sales rep", "LDS-PC01"),
    ("Ben", "Jensen", "bjensen", "Sales", "Sales rep", "LDS-PC02"),
    ("Chloe", "Dubois", "cdubois", "Sales", "Account manager", "LDS-PC03"),
    ("Farid", "Haddad", "fhaddad", "Finance", "Accountant", "LDS-PC04"),
    ("Elif", "Yilmaz", "eyilmaz", "Finance", "Payroll officer", "LDS-PC05"),
    ("Jonas", "Berg", "jberg", "Operations", "Office manager", "LDS-PC06"),
    ("Mei", "Tanaka", "mtanaka", "Operations", "Buyer", "LDS-PC07"),
    ("Noah", "Lindqvist", "nlindqvist", "Sales", "Sales manager", "LDS-PC08"),
    ("Rosa", "Silva", "rsilva", "HR", "HR officer", "LDS-PC09"),
    ("Ravi", "Kumar", "rkumar", "Sales", "Sales rep", "LDS-PC10"),
)
NEW_OFFICE_CSV = "C:\\winlab\\scenario\\leeds-starters.csv"
_NEW_OFFICE = (
    _MK + f"Set-Content -Path '{NEW_OFFICE_CSV}' -Encoding UTF8 -Value @("
    "'GivenName,Surname,SamAccountName,Department,Title,Desk', "
    + ", ".join("'" + ",".join(r) + "'" for r in NEW_OFFICE)
    + f"); @(Import-Csv -Path '{NEW_OFFICE_CSV}').Count -eq {len(NEW_OFFICE)}"
)


# --------------------------------------------------- a phished account
PHISH_HR_MOBILE = "+44 7700 900418"       # Ofcom's drama range: no real phone
PHISH_ATTACKER_MOBILE = "+44 7700 900731"
PHISH_PEOPLE = (("mbrooks", "Mia", "Brooks", "Finance"), ("tquinn", "Tomas", "Quinn", "Sales"),
                ("lsilva", "Leila", "Silva", "Sales"), ("nvarga", "Nadia", "Varga", "Operations"))
PHISH_IN = ("mbrooks", "tquinn")          # their passwords worked for the phisher


def _phish():
    from .dayops import _WHERE, _recall, _remember
    apply = (
        _WHERE + _people(_ps_rows(PHISH_PEOPLE), f" -MobilePhone '{PHISH_HR_MOBILE}'")
        + _remember("phish-made", "$made -join ','")
        # Each password the phisher "captured" is made here, inside the guest,
        # set on the account and used once: nothing secret is in the repo.
        + "$keys = @{}; "
        + f"foreach ($sam in {_ps_names(PHISH_IN)}) {{ $k = [guid]::NewGuid().ToString('N').ToUpper() + '-' + "
        "[guid]::NewGuid().ToString('N'); Set-ADAccountPassword -Identity $sam -Reset "
        "-NewPassword (ConvertTo-SecureString -AsPlainText -Force $k); $keys[$sam] = $k }; "
        + f"Set-ADUser -Identity mbrooks -MobilePhone '{PHISH_HR_MOBILE}'; Start-Sleep -Seconds 2; "
        + _remember("phish-planted", _NOW_UTC)
        + _bad_binds(_ps_names([p[0] for p in PHISH_PEOPLE]), "2")
        + f"foreach ($sam in {_ps_names(PHISH_IN)}) {{ foreach ($i in 1..3) {{ try {{ "
        "$e = New-Object DirectoryServices.DirectoryEntry(('LDAP://' + $env:COMPUTERNAME), "
        "($dom.NetBIOSName + '\\' + $sam), $keys[$sam]); $e.RefreshCache() } catch { } } }; "
        "try { $u = Get-ADUser -Identity mbrooks; $e = New-Object DirectoryServices.DirectoryEntry("
        "('LDAP://' + $env:COMPUTERNAME + '/' + $u.DistinguishedName), ($dom.NetBIOSName + '\\mbrooks'), $keys['mbrooks']); "
        f"$e.Properties['mobile'].Value = '{PHISH_ATTACKER_MOBILE}'; $e.CommitChanges() }} catch {{ "
        f"Set-ADUser -Identity mbrooks -MobilePhone '{PHISH_ATTACKER_MOBILE}' }}; $keys = $null; "
        f"(Get-ADUser -Identity mbrooks -Properties mobile).mobile -eq '{PHISH_ATTACKER_MOBILE}'"
    )
    clear = (
        f"$made = @(([string]{_recall('phish-made')}) -split ',' | Where-Object {{ $_ }}); "
        f"foreach ($sam in {_ps_names([p[0] for p in PHISH_PEOPLE])}) {{ "
        "$u = Get-ADUser -Filter \"SamAccountName -eq '$sam'\"; if ($u) { "
        "if ($made -contains $sam) { $u | Remove-ADUser -Confirm:$false } "
        f"elseif ($sam -eq 'mbrooks') {{ Set-ADUser -Identity $sam -MobilePhone '{PHISH_HR_MOBILE}' }} }} }}; 'True'"
    )
    verify = (
        f"$since = {_when(_recall('phish-planted'))}; $ok = $true; "
        f"foreach ($sam in {_ps_names(PHISH_IN)}) {{ $u = Get-ADUser -Identity $sam -Properties pwdLastSet; "
        "if ([datetime]::FromFileTimeUtc([int64]$u.pwdLastSet) -le $since) { $ok = $false } }; "
        f"$ok -and ((Get-ADUser -Identity mbrooks -Properties mobile).mobile -eq '{PHISH_HR_MOBILE}')"
    )
    return apply, clear, verify


# --------------------------------------------------- a maintenance window opens
CHANGE_ID = "CHG-1042"
_WINDOW = (
    "New-Item -ItemType Directory -Path 'C:\\winlab\\change' -Force | Out-Null; " + _MK
    + "$o = New-Object PSObject -Property @{ opened = " + _NOW_UTC + "; "
    "hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue).Count; "
    "boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }; "
    f"ConvertTo-Json -InputObject $o | Set-Content -Path '{_SCN}\\change-window.json' -Encoding UTF8; "
    f"Set-Content -Path 'C:\\winlab\\change\\{CHANGE_ID}.txt' -Encoding UTF8 -Value @("
    f"'{CHANGE_ID} Monthly patching: srv01, then dc01', 'Window: tonight, 90 minutes', "
    "'Plan: 1 record the state, 2 patch srv01, 3 restart srv01, 4 verify, 5 restart dc01, 6 close the change', "
    "'Rollback: uninstall the update or return to the checkpoint taken before the window', 'Status: Approved'); "
    f"Test-Path -Path '{_SCN}\\change-window.json'"
)


# --------------------------------------------------- the storage migration weekend
PROJECTS_DIR = "C:\\Data\\Projects"
PROJECTS_GROUP = "Projects-RW"
_PROJECTS = (
    f"$d = '{PROJECTS_DIR}'; New-Item -ItemType Directory -Path $d -Force | Out-Null; " + _MK
    + f"if (-not (Get-LocalGroup -Name '{PROJECTS_GROUP}' -ErrorAction SilentlyContinue)) {{ "
    f"New-LocalGroup -Name '{PROJECTS_GROUP}' -Description 'Project staff: change access to the project files' | Out-Null }}; "
    "$rows = @(); foreach ($sub in @('Alpha', 'Bravo', 'Charlie')) { $p = Join-Path $d $sub; "
    "New-Item -ItemType Directory -Path $p -Force | Out-Null; foreach ($n in 1..4) { "
    "$name = ('{0}-{1:D2}.txt' -f $sub.ToLower(), $n); $f = Join-Path $p $name; "
    "$lines = @(('winlab practice file ' + $sub + ' ' + $n), 'Made for the Storage migration weekend scenario day.'); "
    "foreach ($r in 1..60) { $lines += ('{0},{1},{2}' -f $sub, $r, ($r * 97 + $n)) }; "
    "Set-Content -Path $f -Value $lines -Encoding UTF8; "
    "$rows += New-Object PSObject -Property @{ name = ($sub + '\\' + $name); sha256 = (Get-FileHash -Path $f -Algorithm SHA256).Hash } } }; "
    f"icacls $d /grant '{PROJECTS_GROUP}:(OI)(CI)M' | Out-Null; "
    f"ConvertTo-Json -InputObject $rows | Set-Content -Path '{_SCN}\\projects.json' -Encoding UTF8; "
    f"{_NOW_UTC} | Set-Content -Path '{_SCN}\\projects-seeded.txt' -Encoding ASCII; "
    "(@(Get-ChildItem -Path $d -Recurse -File).Count -ge 12)"
)

# Data the users made stays when the day ends: once the student has copied,
# shared and backed it up, it is theirs.
_KEEP = "'True'"


def _day_faults():
    from .guestfaults import WINDOWS, GuestFault
    mon_apply, mon_clear, mon_verify = _monday()
    ph_apply, ph_clear, ph_verify = _phish()
    return [
        GuestFault(id="dc-directory-down", roles=("ad-ds",), os=WINDOWS,
                   title="A domain controller's directory will not start",
                   teaches="(scenario) losing a DC: moving its roles, pointing clients elsewhere",
                   symptom="NTDS, DNS, Kerberos and Netlogon are stopped and disabled on the DC",
                   apply=_DC_DOWN, clear=_DC_DOWN_CLEAR, verify=_DC_DOWN_VERIFY),
        GuestFault(id="monday-wave", roles=("ad-ds",), os=WINDOWS,
                   title="Monday morning: expired passwords and lockouts",
                   teaches="(scenario) the helpdesk's Monday: unlock, reset, and find what keeps locking",
                   symptom="three users' passwords expired, two are locked out",
                   apply=mon_apply, clear=mon_clear, verify=mon_verify),
        GuestFault(id="stale-cred-lockout", roles=("domain-join", "file"), os=WINDOWS,
                   title="A forgotten job signs in with an old password every minute",
                   teaches="(scenario) finding a lockout's source from event 4740's caller computer",
                   symptom="dcosta locks out again minutes after every unlock",
                   apply=_STALE_CRED, clear=_STALE_CRED_CLEAR, verify=_STALE_CRED_VERIFY),
        GuestFault(id="month-end-files", roles=("file",), os=WINDOWS,
                   title="Finance's month-end files arrive on the file server",
                   teaches="(scenario starting state) the files a clean-up must not touch",
                   symptom="new files in the company share's Finance\\Month-End folder",
                   apply=_MONTH_END, clear=_KEEP, verify=_MONTH_END_VERIFY),
        GuestFault(id="scan-dump-fills-disk", roles=("file",), os=WINDOWS,
                   title="A scanner's retry loop fills the file server's data volume",
                   teaches="(scenario) finding what filled a disk and stopping it happening again",
                   symptom="the volume with the company share has almost no free space",
                   apply=_DISK_FULL, clear=_DISK_FULL_CLEAR, verify=_DISK_FULL_VERIFY),
        GuestFault(id="sstp-cert-expired", roles=("domain-join",), os=WINDOWS,
                   title="The VPN's certificate has expired",
                   teaches="(scenario) renewing a service certificate from the company CA and binding it",
                   symptom="home workers' SSTP connections fail on the server's certificate",
                   apply=_SSTP_EXPIRED, clear=_SSTP_EXPIRED_CLEAR, verify=_SSTP_EXPIRED_VERIFY),
        GuestFault(id="share-everyone-full", roles=("file",), os=WINDOWS,
                   title="Everyone has full control of the company share and the HR folder",
                   teaches="(scenario) share and NTFS permissions an auditor will flag",
                   symptom="Get-SmbShareAccess lists Everyone with Full, and HR's folder grants Everyone full control",
                   apply=_WIDE, clear=_WIDE_CLEAR, verify=_WIDE_VERIFY),
        GuestFault(id="gpo-user-side-off", roles=("ad-ds", "gpo"), os=WINDOWS,
                   title="A policy's user settings were switched off",
                   teaches="(scenario) GPO status: a policy can be linked and still apply nothing",
                   symptom="Get-GPO shows GpoStatus UserSettingsDisabled",
                   apply=_GPO_STATUS, clear=_GPO_STATUS_CLEAR, verify=_GPO_STATUS_VERIFY),
        GuestFault(id="new-office-sheet", roles=("ad-ds",), os=WINDOWS,
                   title="HR's new-starter sheet for the Leeds office",
                   teaches="(scenario starting state) the CSV the onboarding is built from",
                   symptom=f"a CSV in {NEW_OFFICE_CSV}",
                   apply=_NEW_OFFICE, clear=_KEEP, verify=f"Test-Path -Path '{NEW_OFFICE_CSV}'"),
        GuestFault(id="phish-signins", roles=("ad-ds",), os=WINDOWS,
                   title="Two accounts were signed in to with phished passwords",
                   teaches="(scenario) containing a compromised account and reading the sign-in logs",
                   symptom="successful sign-ins nobody made, and a changed mobile number on one account",
                   apply=ph_apply, clear=ph_clear, verify=ph_verify),
        GuestFault(id="change-window-opens", os=WINDOWS,
                   title="The maintenance window opens",
                   teaches="(scenario starting state) the change ticket and what the server looked like before",
                   symptom=f"C:\\winlab\\change\\{CHANGE_ID}.txt",
                   apply=_WINDOW, clear=_KEEP, verify=f"Test-Path -Path '{_SCN}\\change-window.json'"),
        GuestFault(id="projects-data", os=WINDOWS,
                   title="The project files that must move to the SAN",
                   teaches="(scenario starting state) data, a group and its permissions a migration must keep",
                   symptom=f"files in {PROJECTS_DIR}",
                   apply=_PROJECTS, clear=_KEEP, verify=f"Test-Path -Path '{_SCN}\\projects.json'"),
    ]


FAULTS = {f.id: f for f in _faults()}
