"""File and print operations: the faults a file server team meets after the
build is done.

The lessons beside this module cover the jobs that come after a file server
is up: moving it to a newer Windows Server with Storage Migration Service and
moving its other roles by hand (DHCP export and import, print queues with
printbrm), auditing share and NTFS permissions, deploying printers by Group
Policy, DFS Replication's backlog and conflicts, roaming profiles and folder
redirection, disk housekeeping (Data Deduplication, FSRM, a full C: drive),
restore drills that prove a backup works, and runbooks in the lab wiki.

Each fault here is a guest fault (winlab/guestfaults.py) that breaks what the
student built, never builds it for them: a DHCP server that stopped listening
on its network card, a folder whose inheritance was removed, Everyone given
Full Control, a print queue whose share name changed, a DFS Replication
staging quota far too small, a user's registry hive damaged, a system drive
filled by a dump, old logs and unbounded shadow storage, and the Volume
Shadow Copy service disabled under a backup. Every fault records what it
changed under HKLM:\\SOFTWARE\\winlab\\scenario, so its verify compares the
machine with that record and its undo puts things back.

The pure helpers at the end read a DokuWiki runbook page and a restore-drill
record the same way the graded checks do, so the suite can test the rules
without a machine.
"""

from __future__ import annotations

import json
import re

from .dayops import SCENE_KEY, _KEY, _recall, _remember

FAULT_IDS = ("dhcp-not-listening", "inheritance-broken", "everyone-full-control", "printer-share-renamed",
             "dfsr-staging-quota", "profile-hive-corrupt", "system-drive-clutter", "vss-disabled")

# The share a fault works on: the lab's main share by name, or else the first
# ordinary folder share on the server (not an admin share, not SYSVOL).
_SHARE = (
    "$s = Get-SmbShare -Name '{share}' -ErrorAction SilentlyContinue; "
    "if (-not $s) { $s = Get-SmbShare | Where-Object { $_.Name -notlike '*$' -and $_.Name -notin @('NETLOGON', 'SYSVOL') "
    "-and [string]$_.ShareType -eq 'FileSystemDirectory' } | Select-Object -First 1 }; "
    "if (-not $s) { throw 'there is no file share on this server yet: build the share in the file server lesson first' }; "
    "$root = $s.Path; "
)


# ------------------------------------------------- DHCP not listening
DHCP_APPLY = (
    "$b = @(Get-DhcpServerv4Binding | Where-Object { $_.BindingState }); "
    "if (-not $b) { throw 'no DHCP server binding is on here: install DHCP and create a scope first' }; "
    + _KEY
    + _remember("dhcp-unbound", "($b | ForEach-Object { $_.InterfaceAlias }) -join '|'")
    + "foreach ($x in $b) { Set-DhcpServerv4Binding -InterfaceAlias $x.InterfaceAlias -BindingState $false }; "
    "Restart-Service -Name DHCPServer; 'the DHCP server no longer listens on ' + (($b | ForEach-Object { $_.InterfaceAlias }) -join ', ')"
)

DHCP_CLEAR = (
    f"foreach ($a in @(([string]{_recall('dhcp-unbound')}) -split '\\|' | Where-Object {{ $_ }})) {{ "
    "Set-DhcpServerv4Binding -InterfaceAlias $a -BindingState $true }; "
    "Restart-Service -Name DHCPServer; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'dhcp-unbound' -ErrorAction SilentlyContinue; 'cleared'"
)

# Fixed when the server runs and listens on an adapter inside an active scope.
DHCP_VERIFY = (
    "$on = @(Get-DhcpServerv4Binding | Where-Object { $_.BindingState } | ForEach-Object { [string]$_.IPAddress }); "
    "$hit = $false; "
    "foreach ($sc in @(Get-DhcpServerv4Scope | Where-Object { [string]$_.State -eq 'Active' })) { "
    "$m = ([ipaddress][string]$sc.SubnetMask).GetAddressBytes(); $n = ([ipaddress][string]$sc.ScopeId).GetAddressBytes(); "
    "foreach ($ip in $on) { $a = ([ipaddress]$ip).GetAddressBytes(); $same = $true; "
    "foreach ($i in 0..3) { if (($a[$i] -band $m[$i]) -ne $n[$i]) { $same = $false } }; if ($same) { $hit = $true } } }; "
    "[bool]($hit -and (Get-Service -Name DHCPServer).Status -eq 'Running')"
)


# ---------------------------------------------- inheritance removed
INHERIT_APPLY = (
    _SHARE + _KEY
    + "$t = Get-ChildItem -LiteralPath $root -Directory | Where-Object { -not (Get-Acl -LiteralPath $_.FullName).AreAccessRulesProtected } "
    "| Sort-Object Name | Select-Object -First 1; "
    "if ($t) { $t = $t.FullName } else { $t = Join-Path $root 'Projects'; New-Item -ItemType Directory -Path $t -Force | Out-Null; "
    "Set-Content -Path (Join-Path $t 'Project plan.txt') -Value 'Milestones for the next quarter.' }; "
    + _remember("inherit-path", "$t")
    + _remember("inherit-sddl", "(Get-Acl -LiteralPath $t).Sddl")
    + "icacls $t /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null; "
    "icacls $t /inheritance:r | Out-Null; 'inheritance removed on ' + $t"
)

INHERIT_CLEAR = (
    f"$t = {_recall('inherit-path')}; $sd = {_recall('inherit-sddl')}; "
    "if ($t -and $sd -and (Test-Path -LiteralPath $t)) { $a = Get-Acl -LiteralPath $t; $a.SetSecurityDescriptorSddlForm($sd); "
    "Set-Acl -LiteralPath $t -AclObject $a }; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'inherit-path', 'inherit-sddl' -ErrorAction SilentlyContinue; 'cleared'"
)

INHERIT_VERIFY = (
    f"$t = {_recall('inherit-path')}; "
    "$a = if ($t -and (Test-Path -LiteralPath $t)) { Get-Acl -LiteralPath $t } else { $null }; "
    "$from = if ($a) { @($a.Access | Where-Object { $_.IsInherited -and [string]$_.AccessControlType -eq 'Allow' "
    "-and \"$($_.IdentityReference)\" -notmatch '(Administrators|SYSTEM|CREATOR OWNER)$' }) } else { @() }; "
    "[bool]($a -and -not $a.AreAccessRulesProtected -and $from.Count -gt 0)"
)


# ------------------------------------------- Everyone: Full Control
EVERYONE_APPLY = (
    _SHARE + _KEY
    + "$sub = Get-ChildItem -LiteralPath $root -Directory | Sort-Object Name | Select-Object -First 1; "
    "$where = @($root) + @($sub | ForEach-Object { $_.FullName }); "
    + _remember("everyone-paths", "$where -join '|'")
    + "foreach ($p in $where) { icacls $p /grant '*S-1-1-0:(OI)(CI)F' | Out-Null }; "
    "'Everyone: Full Control on ' + ($where -join ', ')"
)

EVERYONE_CLEAR = (
    f"foreach ($p in @(([string]{_recall('everyone-paths')}) -split '\\|' | Where-Object {{ $_ }})) {{ "
    "if (Test-Path -LiteralPath $p) { icacls $p /remove:g '*S-1-1-0' | Out-Null } }; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'everyone-paths' -ErrorAction SilentlyContinue; 'cleared'"
)

# Any right that writes, deletes or changes permissions, including the generic
# bits an inherit-only entry carries.
WRITE_MASK = "0x500D0116"

EVERYONE_VERIFY = (
    f"$ps = @(([string]{_recall('everyone-paths')}) -split '\\|' | Where-Object {{ $_ }}); "
    "$bad = @(foreach ($p in $ps) { if (Test-Path -LiteralPath $p) { "
    "(Get-Acl -LiteralPath $p).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | "
    "Where-Object { [string]$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq 'S-1-1-0' "
    f"-and ([int]$_.FileSystemRights -band {WRITE_MASK}) }} | ForEach-Object {{ $p }} }} }}); "
    "$others = if ($ps.Count -gt 0 -and (Test-Path -LiteralPath $ps[0])) { "
    "@((Get-Acl -LiteralPath $ps[0]).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | "
    "Where-Object { [string]$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ne 'S-1-1-0' }) } else { @() }; "
    "[bool]($ps.Count -gt 0 -and $bad.Count -eq 0 -and $others.Count -gt 0)"
)


# ---------------------------------------------- print share renamed
PRINT_APPLY = (
    "$p = Get-Printer -Name '{printer}' -ErrorAction SilentlyContinue; "
    "if (-not $p -or -not $p.Shared) { $p = Get-Printer | Where-Object { $_.Shared } | Sort-Object Name | Select-Object -First 1 }; "
    "if (-not $p) { throw 'no shared print queue on this server yet: build one in the print server lesson first' }; "
    + _KEY
    + _remember("printer-name", "$p.Name")
    + _remember("printer-share", "$p.ShareName")
    + _remember("printer-published", "[int][bool]$p.Published")
    + "Set-Printer -Name $p.Name -ShareName ($p.ShareName + '-2F'); "
    "if ($p.Published) { Set-Printer -Name $p.Name -Published $false }; "
    "$p.Name + ' is now shared as ' + $p.ShareName + '-2F'"
)

PRINT_CLEAR = (
    f"$n = {_recall('printer-name')}; $sn = {_recall('printer-share')}; "
    "if ($n -and $sn) { Set-Printer -Name $n -Shared $true -ShareName $sn; "
    f"if ([int]{_recall('printer-published')} -eq 1) {{ Set-Printer -Name $n -Published $true }} }}; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'printer-name', 'printer-share', 'printer-published' -ErrorAction SilentlyContinue; "
    "'cleared'"
)

PRINT_VERIFY = (
    f"$n = {_recall('printer-name')}; $sn = {_recall('printer-share')}; $pub = [int]{_recall('printer-published')}; "
    "$p = if ($n) { Get-Printer -Name $n -ErrorAction SilentlyContinue } else { $null }; "
    "[bool]($p -and $p.Shared -and $p.ShareName -eq $sn -and ($pub -eq 0 -or $p.Published))"
)


# ------------------------------------------ DFS-R staging quota tiny
DFSR_APPLY = (
    "$m = @(Get-DfsrMembership -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue | "
    "Where-Object { $_.Enabled -and $_.ContentPath })[0]; "
    "if (-not $m) { throw 'this server is not in a DFS replication group yet: build the replication in the DFS lesson first' }; "
    "$all = @(Get-DfsrMember -GroupName $m.GroupName | ForEach-Object { $_.ComputerName }); "
    + _KEY
    + _remember("dfsr-group", "$m.GroupName")
    + _remember("dfsr-folder", "$m.FolderName")
    + _remember("dfsr-quota", "$m.StagingPathQuotaInMB")
    + _remember("dfsr-renders", "Join-Path $m.ContentPath 'Design\\Renders'")
    + "Set-DfsrMembership -GroupName $m.GroupName -FolderName $m.FolderName -ComputerName $all -StagingPathQuotaInMB 16 -Force | Out-Null; "
    # Random bytes: staging compresses what it can, and zeros would fit anywhere.
    "$d = Join-Path $m.ContentPath 'Design\\Renders'; New-Item -ItemType Directory -Path $d -Force | Out-Null; "
    "$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $buf = New-Object byte[] 1048576; "
    "foreach ($i in 1..4) { $fs = [System.IO.File]::Create((Join-Path $d ('render-0' + $i + '.bin'))); "
    "foreach ($k in 1..48) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }; $fs.Close() }; "
    "Update-DfsrConfigurationFromAD -ComputerName $all -ErrorAction SilentlyContinue; "
    "'staging quota 16 MB on ' + ($all -join ', ')"
)

DFSR_CLEAR = (
    f"$g = {_recall('dfsr-group')}; $f = {_recall('dfsr-folder')}; $q = [int]{_recall('dfsr-quota')}; "
    "if ($q -lt 4096) { $q = 4096 }; "
    "if ($g) { $all = @(Get-DfsrMember -GroupName $g | ForEach-Object { $_.ComputerName }); "
    "Set-DfsrMembership -GroupName $g -FolderName $f -ComputerName $all -StagingPathQuotaInMB $q -Force | Out-Null; "
    "Update-DfsrConfigurationFromAD -ComputerName $all -ErrorAction SilentlyContinue }; "
    f"$r = {_recall('dfsr-renders')}; if ($r -and (Test-Path -LiteralPath $r)) {{ Remove-Item -LiteralPath $r -Recurse -Force }}; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'dfsr-group', 'dfsr-folder', 'dfsr-quota', 'dfsr-renders' -ErrorAction SilentlyContinue; "
    "'cleared'"
)

# Microsoft's rule of thumb: staging at least as large as the 32 largest
# files of the replicated folder together, and never below 1 GB here.
DFSR_VERIFY = (
    f"$g = {_recall('dfsr-group')}; $f = {_recall('dfsr-folder')}; "
    "$ms = @(if ($g) { Get-DfsrMembership -GroupName $g -ErrorAction SilentlyContinue | Where-Object { $_.FolderName -eq $f } }); "
    "$local = $ms | Where-Object { $_.ComputerName -eq $env:COMPUTERNAME } | Select-Object -First 1; "
    "$big = 0; if ($local) { $big = [double](Get-ChildItem -LiteralPath $local.ContentPath -Recurse -File -Force -ErrorAction SilentlyContinue | "
    "Where-Object { $_.FullName -notmatch '\\\\DfsrPrivate\\\\' } | Sort-Object Length -Descending | Select-Object -First 32 | "
    "Measure-Object -Property Length -Sum).Sum / 1MB }; "
    "$need = [math]::Max(1024, [math]::Ceiling($big)); "
    "[bool]($ms.Count -ge 2 -and -not ($ms | Where-Object { $_.StagingPathQuotaInMB -lt $need }))"
)


# ------------------------------------------- a user's hive damaged
_PROFILES = "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'"
_THEIRS = "Where-Object { [string](Get-ItemProperty -Path $_.PSPath).ProfileImagePath -match '\\\\{user}(\\.[^\\\\]+)?$' }"
MARKER = "Quarterly figures.txt"
HIVE_COPY = "C:\\winlab\\faults\\ntuser-{user}.dat"

HIVE_APPLY = (
    "$k = Get-ChildItem -Path " + _PROFILES + " | " + _THEIRS + " | Where-Object { $_.PSChildName -notlike '*.bak' } | Select-Object -First 1; "
    "if (-not $k) { throw '{user} has never signed in to this machine: sign in as {user} once, sign out, then break it' }; "
    "$dir = [string](Get-ItemProperty -Path $k.PSPath).ProfileImagePath; "
    "$up = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -eq $dir }; "
    "if ($up -and $up.Loaded) { throw '{user} is signed in: sign {user} out first, then break it' }; "
    + _KEY
    + _remember("hive-dir", "$dir")
    + "New-Item -ItemType Directory -Path 'C:\\winlab\\faults' -Force | Out-Null; "
    f"$h = Join-Path $dir 'NTUSER.DAT'; Copy-Item -LiteralPath $h -Destination '{HIVE_COPY}' -Force; "
    "New-Item -ItemType Directory -Path (Join-Path $dir 'Desktop') -Force | Out-Null; "
    f"Set-Content -Path (Join-Path $dir 'Desktop\\{MARKER}') -Value 'Q3 numbers for the board pack. Do not lose this.'; "
    # A hidden file cannot be recreated by File.Create; open it and overwrite.
    "$junk = New-Object byte[] 262144; (New-Object System.Random 7).NextBytes($junk); "
    "$fs = [System.IO.File]::Open($h, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write); "
    "$fs.SetLength(0); $fs.Write($junk, 0, $junk.Length); $fs.Close(); "
    "'the registry hive of {user} in ' + $dir + ' is damaged'"
)

HIVE_CLEAR = (
    f"$dir = {_recall('hive-dir')}; "
    f"if ($dir -and (Test-Path -LiteralPath '{HIVE_COPY}') -and (Test-Path -LiteralPath $dir)) {{ "
    "$h = Join-Path $dir 'NTUSER.DAT'; if (Test-Path -LiteralPath $h) { (Get-Item -LiteralPath $h -Force).Attributes = 'Archive' }; "
    f"Copy-Item -LiteralPath '{HIVE_COPY}' -Destination $h -Force; (Get-Item -LiteralPath $h -Force).Attributes = 'Hidden, System' }}; "
    "$pl = " + _PROFILES + "; "
    "foreach ($b in @(Get-ChildItem -Path $pl | Where-Object { $_.PSChildName -like '*.bak' } | " + _THEIRS + ")) { "
    "$sid = $b.PSChildName -replace '\\.bak$', ''; "
    "if (Test-Path -Path \"$pl\\$sid\") { Remove-Item -Path \"$pl\\$sid\" -Recurse -Force }; "
    "Rename-Item -Path $b.PSPath -NewName $sid; Set-ItemProperty -Path \"$pl\\$sid\" -Name State -Value 0 }; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'hive-dir' -ErrorAction SilentlyContinue; 'cleared'"
)

# Fixed when the profile Windows maps the user to has a real hive (it starts
# with 'regf', or Windows holds it open because it is loaded) and the file
# that was on the old desktop is in it, on the Desktop or in Documents.
HIVE_VERIFY = (
    "$k = @(Get-ChildItem -Path " + _PROFILES + " | " + _THEIRS + " | Where-Object { $_.PSChildName -notlike '*.bak' }); "
    "$good = @(foreach ($x in $k) { $d = [string](Get-ItemProperty -Path $x.PSPath).ProfileImagePath; $h = Join-Path $d 'NTUSER.DAT'; "
    "$head = ''; if (Test-Path -LiteralPath $h) { try { $b = New-Object byte[] 4; "
    "$fs = [System.IO.File]::Open($h, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite); "
    "[void]$fs.Read($b, 0, 4); $fs.Close(); $head = [System.Text.Encoding]::ASCII.GetString($b) } catch { $head = 'regf' } }; "
    f"$kept = @(Get-ChildItem -LiteralPath (Join-Path $d 'Desktop'), (Join-Path $d 'Documents') -Recurse -Filter '{MARKER}' "
    "-File -Force -ErrorAction SilentlyContinue); "
    "if ($head -eq 'regf' -and $kept.Count -gt 0 -and -not ([int](Get-ItemProperty -Path $x.PSPath).State -band 0x800)) { $d } }); "
    "[bool]($good.Count -ge 1)"
)


# -------------------------------------------------- C: drive full
LOGS = "C:\\ProgramData\\LabApp\\Logs"
DUMP = "$env:SystemRoot\\MEMORY.DMP"

CLUTTER_APPLY = (
    _KEY
    + "$free = (Get-PSDrive -Name C).Free; $spend = $free - 300MB; "
    "if ($spend -lt 1GB) { throw 'C: has less than 1.3 GB free already: free some space before breaking it' }; "
    + _remember("clutter-free", "$free")
    + f"$logs = '{LOGS}'; New-Item -ItemType Directory -Path $logs -Force | Out-Null; "
    "$dump = [int64]($spend * 0.4); $each = [int64](($spend - $dump) / 24); "
    f"$f = [System.IO.File]::Create(\"{DUMP}\"); $f.SetLength($dump); $f.Close(); "
    f"(Get-Item -LiteralPath \"{DUMP}\").LastWriteTime = (Get-Date).AddDays(-41); "
    "foreach ($i in 1..24) { $d = (Get-Date).AddDays(-30 - 3 * $i); $p = Join-Path $logs ('labapp-' + $d.ToString('yyyyMMdd') + '.log'); "
    "$f = [System.IO.File]::Create($p); $f.SetLength($each); $f.Close(); (Get-Item -LiteralPath $p).LastWriteTime = $d }; "
    "$recent = @(foreach ($i in 0..2) { $d = (Get-Date).AddDays(0 - $i); $n = 'labapp-' + $d.ToString('yyyyMMdd') + '.log'; "
    "Set-Content -Path (Join-Path $logs $n) -Value ('LabApp started ' + $d.ToString('s')); (Get-Item -LiteralPath (Join-Path $logs $n)).LastWriteTime = $d; $n }); "
    + _remember("clutter-recent", "$recent -join '|'")
    + "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=UNBOUNDED 2>&1 | Out-Null; "
    "if ($LASTEXITCODE -ne 0) { vssadmin add shadowstorage /for=C: /on=C: /maxsize=UNBOUNDED 2>&1 | Out-Null }; "
    "'C: has ' + [math]::Round((Get-PSDrive -Name C).Free / 1MB) + ' MB free'"
)

CLUTTER_CLEAR = (
    f"Remove-Item -LiteralPath \"{DUMP}\" -Force -ErrorAction SilentlyContinue; "
    f"Get-ChildItem -LiteralPath '{LOGS}' -Filter 'labapp-*.log' -File -ErrorAction SilentlyContinue | "
    "Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force; "
    "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10% 2>&1 | Out-Null; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'clutter-free', 'clutter-recent' -ErrorAction SilentlyContinue; 'cleared'"
)

# Fixed when the space is back, the dump is gone, no log older than the
# 30-day retention is left, the recent logs were kept, and shadow copies of
# C: have a ceiling.
CLUTTER_VERIFY = (
    f"$old = @(Get-ChildItem -LiteralPath '{LOGS}' -Filter 'labapp-*.log' -File -ErrorAction SilentlyContinue | "
    "Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }); "
    f"$lost = @(([string]{_recall('clutter-recent')}) -split '\\|' | Where-Object {{ $_ -and -not (Test-Path -LiteralPath (Join-Path '{LOGS}' $_)) }}); "
    f"$was = [double]{_recall('clutter-free')}; $want = [math]::Min(2GB, $was * 0.8); "
    "$vs = (vssadmin list shadowstorage /for=C: 2>&1 | Out-String); "
    f"[bool](((Get-PSDrive -Name C).Free -ge $want) -and $old.Count -eq 0 -and $lost.Count -eq 0 -and -not (Test-Path -LiteralPath \"{DUMP}\") "
    "-and $vs -notmatch 'UNBOUNDED')"
)


# --------------------------------------- VSS disabled under a backup
VSS_APPLY = (
    "if (-not (Get-Command -Name Get-WBSummary -ErrorAction SilentlyContinue)) { "
    "throw 'Windows Server Backup is not installed here yet: set up the backup first' }; "
    + _KEY
    + _remember("vss-broken", "(Get-Date).ToUniversalTime().ToString('o')")
    + "Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue; Set-Service -Name VSS -StartupType Disabled; "
    "'the Volume Shadow Copy service is disabled'"
)

VSS_CLEAR = (
    "Set-Service -Name VSS -StartupType Manual; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'vss-broken' -ErrorAction SilentlyContinue; 'cleared'"
)

# Fixed when VSS can start again and a backup has succeeded since the break.
VSS_VERIFY = (
    f"$since = {_recall('vss-broken')}; "
    "$after = if ($since) { [datetime]::Parse($since).ToLocalTime() } else { (Get-Date).AddDays(-1) }; "
    "$sum = Get-WBSummary -ErrorAction SilentlyContinue; "
    "[bool](([string](Get-Service -Name VSS).StartType -ne 'Disabled') -and $sum -and $sum.LastSuccessfulBackupTime -gt $after)"
)


def register_faults(reg) -> None:
    from .guestfaults import WINDOWS, GuestFault
    reg(GuestFault(
        id="dhcp-not-listening",
        roles=("dhcp",),
        title="The DHCP server runs and hands out nothing",
        os=WINDOWS,
        teaches="the three things a Windows DHCP server needs to answer (running, authorized in AD, bound to the network "
                "card on the scope's subnet), the server's bindings, and the events that name the gap",
        symptom="after the DHCP role moved to this server, PCs that renew get a 169.254 address; the DHCP Server "
                "service is running, the server is authorized and the scope is active",
        apply=DHCP_APPLY,
        clear=DHCP_CLEAR,
        hints=(
            "Rule out the usual suspects in order. From a PC, ipconfig /renew times out. On the server: "
            "Get-Service DHCPServer is Running, Get-DhcpServerInDC lists this server (it is authorized), and "
            "Get-DhcpServerv4Scope shows the scope Active with free addresses. So the server never hears the requests.",
            "A DHCP server answers only on the adapters it is bound to. Get-DhcpServerv4Binding shows BindingState "
            "False on the server's network card; the DHCP Server log and the System log say no interface is serviced. "
            "Bindings are per adapter, which is why they go wrong after a move, a new card or a renamed one.",
            "Set-DhcpServerv4Binding -InterfaceAlias <the adapter> -BindingState $true, then Restart-Service DHCPServer. "
            "ipconfig /renew on the PC gets an address from the scope, and Get-DhcpServerv4Lease -ScopeId <scope> lists it.",
        ),
        verify=DHCP_VERIFY,
    ))
    reg(GuestFault(
        id="inheritance-broken",
        roles=("file",),
        title="One folder in the share says access denied to everyone",
        os=WINDOWS,
        teaches="NTFS inheritance, the (I) marks icacls prints, what 'Disable inheritance, remove all inherited "
                "permissions' leaves behind, and turning inheritance back on without losing explicit entries",
        symptom="staff open the share and every folder in it except one, which says 'Access is denied' to everyone "
                "but the administrators; nothing changed in the groups",
        apply=INHERIT_APPLY,
        clear=INHERIT_CLEAR,
        hints=(
            "When a folder refuses and the folder above opens, the gate is on that folder. Compare the two: "
            "icacls <share folder> and icacls <the folder that refuses>. Entries passed down from above carry (I).",
            "The folder has no (I) entries at all, only Administrators and SYSTEM: inheritance was disabled with "
            "'remove all inherited permissions'. (Get-Acl <folder>).AreAccessRulesProtected says True. The users' "
            "group still has its rights on the folder above; they just no longer flow down.",
            "Turn inheritance back on: icacls <folder> /inheritance:e (the Security tab: Advanced, Enable inheritance). "
            "Explicit entries stay; the group's rights flow in again. Test from a PC as a user, then run your "
            "permission report to see whether any other folder is an island.",
        ),
        verify=INHERIT_VERIFY,
    ))
    reg(GuestFault(
        id="everyone-full-control",
        roles=("file",),
        title="Everyone has Full Control on the file share",
        os=WINDOWS,
        teaches="reading an NTFS ACL for over-broad entries, Everyone versus Authenticated Users, explicit entries that "
                "survive a fix at the top, and removing an entry without locking the real users out",
        symptom="the auditor's report says any account, a contractor's or a guest's, can change, delete and take "
                "ownership of files in the main share; users notice nothing",
        apply=EVERYONE_APPLY,
        clear=EVERYONE_CLEAR,
        hints=(
            "Start with the share's folder, not the share: icacls <share folder> lists Everyone:(OI)(CI)(F). Share "
            "permissions (Get-SmbShareAccess) are the outer gate; Everyone there is common and harmless when NTFS is "
            "right. Here NTFS is not.",
            "Fixing the top is not enough. Search below for explicit entries, which do not carry (I): Get-ChildItem "
            "<share folder> -Directory -Recurse | ForEach-Object { icacls $_.FullName } and look for Everyone without "
            "(I). One folder has its own copy.",
            "icacls <folder> /remove:g *S-1-1-0 on the share folder and on each folder with its own entry (*S-1-1-0 is "
            "Everyone's SID). Check the real users still get in through their group, then run your permission report "
            "again and keep it as the evidence.",
        ),
        verify=EVERYONE_VERIFY,
    ))
    reg(GuestFault(
        id="printer-share-renamed",
        roles=("printer",),
        title="A deployed printer says it cannot be found",
        os=WINDOWS,
        teaches="what a client's printer connection points at (\\\\server\\sharename, not the queue's name), share "
                "names versus queue names, and publishing a queue in AD",
        symptom="users' printers deployed by Group Policy show as offline or 'printer not found'; the queue is on the "
                "server, it is shared and it prints locally; searching the directory no longer finds it",
        apply=PRINT_APPLY,
        clear=PRINT_CLEAR,
        hints=(
            "A connection is \\\\server\\sharename. On a PC: Get-Printer shows the connection's name; on the server: "
            "Get-Printer | Format-Table Name, ShareName, Shared, Published. Compare what the PC asks for with what "
            "the server offers.",
            "The queue kept its name and its share name changed (someone tidied names during a move), so every "
            "connection, every GPO that deploys it and every script that maps it now points at a share that is not "
            "there. Published is also off, so a search in the directory misses it.",
            "Put the share name back: Set-Printer -Name <queue> -ShareName <the old share name>, and "
            "Set-Printer -Name <queue> -Published $true. On a PC, gpupdate /force and the deployed printer reconnects. "
            "If a rename is really wanted, change the GPO and the share name in the same change window.",
        ),
        verify=PRINT_VERIFY,
    ))
    reg(GuestFault(
        id="dfsr-staging-quota",
        roles=("dfs", "ad-ds"),
        title="DFS Replication crawls and the backlog keeps growing",
        os=WINDOWS,
        teaches="DFS Replication's staging folder and its quota, the high and low watermarks (events 4202 and 4204), "
                "measuring a backlog, and sizing staging from the largest files",
        symptom="large files written at one site take hours to appear at the other, the backlog between the members "
                "grows all day, and the DFS Replication log fills with warnings",
        apply=DFSR_APPLY,
        clear=DFSR_CLEAR,
        hints=(
            "Measure first: Get-DfsrBacklog -GroupName <group> -FolderName <folder> -SourceComputerName <this server> "
            "-DestinationComputerName <partner> (or dfsrdiag backlog /rgname: /rfname: /smem: /rmem:). Then read the "
            "DFS Replication log: Get-WinEvent -LogName 'DFS Replication' -MaxEvents 20. Events 4202 and 4204 repeat.",
            "4202 says the staging folder went over its high watermark, 4204 that it cleaned up to the low one: staging "
            "is far too small. Get-DfsrMembership | Format-Table ComputerName, StagingPath, StagingPathQuotaInMB shows "
            "16 MB, while the largest files are 48 MB each. Staging should hold at least the 32 largest files together: "
            "Get-ChildItem <content path> -Recurse -File | Sort-Object Length -Descending | Select-Object -First 32 | "
            "Measure-Object Length -Sum.",
            "Set-DfsrMembership -GroupName <group> -FolderName <folder> -ComputerName <both members> "
            "-StagingPathQuotaInMB 4096 -Force, then Update-DfsrConfigurationFromAD on both. The 4202 events stop and "
            "Get-DfsrBacklog falls to zero.",
        ),
        verify=DFSR_VERIFY,
    ))
    reg(GuestFault(
        id="profile-hive-corrupt",
        title="A user's profile is corrupt",
        os=WINDOWS,
        teaches="NTUSER.DAT as the user's registry, the User Profile Service events (1500 to 1530), and rebuilding a "
                "profile without losing the user's files",
        symptom="{user} signs in to a temporary profile every time; the ProfileList entry looks normal; their desktop "
                "files are still on the disk, and their settings are gone",
        apply=HIVE_APPLY,
        clear=HIVE_CLEAR,
        hints=(
            "Read the Application log first: Get-WinEvent -FilterHashtable @{LogName='Application'; "
            "ProviderName='Microsoft-Windows-User Profiles Service'} -MaxEvents 10. Before the 1511 (temporary "
            "profile) comes an error that the registry file of the user could not be loaded.",
            "The user's settings live in C:\\Users\\{user}\\NTUSER.DAT, a registry hive. A healthy hive starts with the "
            "four letters regf: Format-Hex C:\\Users\\{user}\\NTUSER.DAT | Select-Object -First 2. This one does not. The "
            "files on the Desktop and in Documents are ordinary files and are fine.",
            "With {user} signed out: rename C:\\Users\\{user} to {user}.old, delete the ProfileList key of the user's "
            "SID, let {user} sign in to a fresh profile and sign out, then copy Desktop and Documents back from {user}.old "
            "(robocopy C:\\Users\\{user}.old\\Desktop C:\\Users\\{user}\\Desktop /E). Keep {user}.old until the user "
            "confirms nothing is missing. A hive from last night's backup is the other way.",
        ),
        verify=HIVE_VERIFY,
    ))
    reg(GuestFault(
        id="system-drive-clutter",
        title="The server's C: drive is full",
        os=WINDOWS,
        teaches="finding what filled a system drive, what is safe to delete (a memory dump, logs past retention) and "
                "what is not (WinSxS by hand, recent logs), component store cleanup, and a ceiling on shadow storage",
        symptom="the server warns about low disk space on C:, updates fail to install and services cannot write their "
                "logs; nobody copied anything big onto it",
        apply=CLUTTER_APPLY,
        clear=CLUTTER_CLEAR,
        hints=(
            "Get-PSDrive C says how little is left. Find the big files, not the big folders: Get-ChildItem C:\\ "
            "-Recurse -File -Force -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object "
            "-First 15 FullName, Length, LastWriteTime. There is more than one cause.",
            "A memory dump in C:\\Windows (copy it off if the crash still needs analysing, then delete it), and an "
            "application's log folder that keeps everything forever. Logs past the 30-day retention can go; the last "
            "few days stay. vssadmin list shadowstorage shows shadow copies of C: allowed to grow without limit. "
            "Never delete in C:\\Windows\\WinSxS by hand.",
            "Remove-Item C:\\Windows\\MEMORY.DMP; Get-ChildItem <log folder> -Filter *.log | Where-Object LastWriteTime "
            "-lt (Get-Date).AddDays(-30) | Remove-Item; vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%; "
            "Dism /Online /Cleanup-Image /StartComponentCleanup for the component store. Then a scheduled task that "
            "keeps the logs at 30 days, and an alert on free space.",
        ),
        verify=CLUTTER_VERIFY,
    ))
    reg(GuestFault(
        id="vss-disabled",
        roles=("server-backup", "backup", "backup-nas"),
        title="Backups fail every night and the restore drill finds nothing new",
        os=WINDOWS,
        teaches="how Windows Server Backup depends on the Volume Shadow Copy service, reading Get-WBSummary and the "
                "Backup log, and proving a backup after a fix rather than assuming it",
        symptom="this morning's restore drill restored yesterday's file: the latest backup is days old, and the "
                "scheduled backup has failed every night since",
        apply=VSS_APPLY,
        clear=VSS_CLEAR,
        hints=(
            "Ask the backup what it did: Get-WBSummary (LastSuccessfulBackupTime, LastBackupResultHR), wbadmin get "
            "versions, and the log: Get-WinEvent -LogName Microsoft-Windows-Backup -MaxEvents 10. The runs start and "
            "fail at the snapshot.",
            "A backup is taken from a shadow copy. Get-Service VSS shows the Volume Shadow Copy service Stopped with "
            "StartType Disabled, so no snapshot can be made (vssadmin list writers fails too).",
            "Set-Service VSS -StartupType Manual (its default: it starts when asked), then run a backup now "
            "(Start-WBBackup -Policy (Get-WBPolicy), or wbadmin start backup with the schedule's settings) and check "
            "Get-WBSummary says it succeeded just now. Then run the restore drill again.",
        ),
        verify=VSS_VERIFY,
    ))


# ------------------------------------------------------------ pure helpers
RUNBOOK_SECTIONS = ("Symptom", "Diagnosis", "Fix", "Verify", "Escalation")
_HEADING = re.compile(r"^\s*(={2,6})\s*(.*?)\s*\1\s*$")


def headings(page: str) -> list[str]:
    """The headings of a DokuWiki page, in order: lines like '==== Fix ===='."""
    out = []
    for line in page.splitlines():
        m = _HEADING.match(line)
        if m and m.group(2):
            out.append(m.group(2))
    return out


def missing_sections(page: str, sections: tuple[str, ...] = RUNBOOK_SECTIONS) -> list[str]:
    """The runbook sections a page lacks. A heading counts when it starts with
    the section's word (Symptoms, Fix it, Verify the fix)."""
    have = [h.lower() for h in headings(page)]
    return [s for s in sections if not any(h.startswith(s.lower()) for h in have)]


DRILL_FIELDS = ("when", "backupVersion", "source", "restored", "sourceHash", "restoredHash", "passed")


def drill_problems(record_text: str) -> list[str]:
    """What is wrong with a restore-drill record (the JSON the drill script
    writes), as the graded check sees it: missing fields, hashes that differ,
    or a drill that says it passed when its hashes say otherwise."""
    try:
        rec = json.loads(record_text)
    except ValueError as exc:
        return [f"not JSON: {exc}"]
    if not isinstance(rec, dict):
        return ["not a JSON object"]
    out = [f"no {k}" for k in DRILL_FIELDS if k not in rec]
    sh, rh = str(rec.get("sourceHash", "")), str(rec.get("restoredHash", ""))
    if sh and rh and sh.lower() != rh.lower():
        out.append("the restored file's hash differs from the original's")
    if sh and not re.fullmatch(r"[0-9A-Fa-f]{64}", sh):
        out.append("sourceHash is not a SHA256")
    if rec.get("passed") is True and sh.lower() != rh.lower():
        out.append("passed is true while the hashes differ")
    return out
