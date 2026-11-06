"""Identity operations: the directory jobs and drills of a working AD admin
that winlab/dayops.py does not already set.

Each is a guest fault (winlab/guestfaults.py) with a three-hint ladder and a
verify that prints True once the job is done; the lessons' exercises grade
the same end state check by check. Like the day-two scenes they set a scene
and never the answer, record what they planted under
HKLM:\\SOFTWARE\\winlab\\scenario, and give every account they make a
random password generated inside the guest.

The user lifecycle
  hr-joiners-drop        HR drops this week's joiners as a CSV in C:\\HR\\Joiners
                         (one row for a department with no group, one person
                         twice); the student automates joiners with a script
                         and a scheduled task.
  mover-to-finance       Dan Price moves from Sales to Finance: attributes,
                         groups, a direct permission someone once gave him on
                         a Sales folder, and his home folder to Finance's share.
  leaver-after-handover  Bob Hughes left 35 days ago: archive his home folder
                         (and, on lnx01, his mailbox), delete the account,
                         take his laptop back as a spare.

Recovery and health
  ou-deleted             The Contractors OU is deleted with its people and a
                         group in it; the AD Recycle Bin brings them back.
  sysvol-replication-disabled  this DC's SYSVOL subscription is switched off
                         (msDFSR-Enabled), so new GPOs never reach its SYSVOL.
  usn-rollback           a DC reverted to a checkpoint of its disk; broken from
                         outside the machine by winlab/dcrollback.py.

Privileged access and Kerberos
  tier0-hygiene          tier 0 accounts that break the rules: a service
                         account with an SPN in Domain Admins, an admin outside
                         Protected Users, a server trusted for unconstrained
                         delegation.
  kerberos-spn-duplicate the intranet's SPN on a second account (an old pool
                         account from before the uniqueness check).
  stale-credential-lockout  a script on a PC maps a drive every two minutes
                         with a user's old password, so she is locked out again
                         and again; the trail runs from 4740 on the PDC to the
                         machine.

Every script parses under Windows PowerShell 5.1 and uses no top-level
`return` or `exit` (see winlab/scenariofaults.py).
"""

from __future__ import annotations

from .dayops import SCENE_KEY, SECRET, _WHERE, _recall, _remember

# ============================================================ the joiners
DROP = "C:\\HR\\Joiners"
JOINER_SCRIPT = "New-Starters.ps1"
# (first, last, department, title, account, extension): one department with
# no group (Marketing), and Tom Becker twice because HR sent him twice.
JOINERS = (
    ("Nadia", "Okafor", "Finance", "Accounts assistant", "nokafor", "4211"),
    ("Tom", "Becker", "Sales", "Sales executive", "tbecker", "4307"),
    ("Lucia", "Ferreira", "Operations", "Facilities coordinator", "lferreira", "4412"),
    ("Arjun", "Mehta", "Finance", "Payroll officer", "amehta", "4215"),
    ("Grace", "Lin", "Marketing", "Designer", "glin", "4502"),
    ("Tom", "Becker", "Sales", "Sales executive", "tbecker", "4307"),
)
REJECTED = "glin"
JOINER_DEPTS = ("Finance", "Sales", "Operations")


def _ps_rows(rows) -> str:
    return "@(" + ", ".join("@(" + ", ".join(f"'{v}'" for v in r) + ")" for r in rows) + ")"


JOINERS_APPLY = (
    _WHERE
    + "$staff = Find-Ou ('OU=Staff,' + $base) $groupsOu; "
    "foreach ($d in @(" + ", ".join(f"'{d}'" for d in JOINER_DEPTS) + ")) { $g = 'G-' + $d; "
    "if (-not (Get-ADGroup -Filter \"Name -eq '$g'\")) { "
    "New-ADGroup -Name $g -GroupScope Global -GroupCategory Security -Path $staff } }; "
    f"New-Item -ItemType Directory -Path '{DROP}' -Force | Out-Null; "
    "$start = (Get-Date).AddDays(7).ToString('yyyy-MM-dd'); "
    "$lines = @('FirstName,LastName,DisplayName,Department,Title,SamAccountName,EmailAddress,Extension,Manager,StartDate'); "
    f"foreach ($r in {_ps_rows(JOINERS)}) {{ "
    "$lines += ('{0},{1},{0} {1},{2},{3},{4},{5}@{6},{7},,{8}' -f $r[0], $r[1], $r[2], $r[3], $r[4], "
    "($r[0] + '.' + $r[1]).ToLower(), $dom.DNSRoot, $r[5], $start) }; "
    f"$file = Join-Path '{DROP}' ('joiners-' + (Get-Date -Format 'yyyy-MM-dd') + '.csv'); "
    "Set-Content -Path $file -Value $lines -Encoding UTF8; "
    + _remember("joiners-planted", "(Get-Date).ToUniversalTime().ToString('o')")
    + "'HR dropped ' + ($lines.Count - 1) + ' rows in ' + $file"
)

JOINERS_CLEAR = (
    "foreach ($n in @(" + ", ".join(f"'{r[4]}'" for r in JOINERS[:5]) + ")) { "
    "Get-ADUser -Filter \"SamAccountName -eq '$n'\" | Remove-ADUser -Confirm:$false }; "
    f"Remove-Item -Path '{DROP}' -Recurse -Force -ErrorAction SilentlyContinue; "
    "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { "
    f"(@($_.Actions | ForEach-Object {{ [string]$_.Arguments }}) -join ' ') -match '{JOINER_SCRIPT.replace('.', '[.]')}' }} | "
    "Unregister-ScheduledTask -Confirm:$false; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'joiners-planted' -ErrorAction SilentlyContinue; 'cleared'"
)

_WANT = "@{ " + "; ".join(f"{r[4]} = '{r[2]}'" for r in JOINERS[:4]) + " }"

JOINERS_VERIFY = (
    f"$want = {_WANT}; $bad = @(); "
    "foreach ($k in $want.Keys) { "
    "$u = Get-ADUser -Filter \"SamAccountName -eq '$k'\" -Properties Department, Title, MemberOf, pwdLastSet, LastLogonDate; "
    "if (-not $u) { $bad += ($k + ' was not created') } "
    "elseif (-not $u.Enabled) { $bad += ($k + ' is disabled') } "
    "elseif ($u.Department -ne $want[$k]) { $bad += ($k + ' has the wrong department') } "
    "elseif (-not (@($u.MemberOf) -match ('^CN=G-' + $want[$k] + ','))) { $bad += ($k + ' is not in G-' + $want[$k]) } "
    "elseif ($u.DistinguishedName -match ',CN=Users,DC=') { $bad += ($k + ' sits in the default Users container') } "
    "elseif (([int64]$u.pwdLastSet -ne 0) -and -not $u.LastLogonDate) { $bad += ($k + ' does not have to change the first password') } }; "
    f"if (Get-ADUser -Filter \"SamAccountName -eq '{REJECTED}'\") {{ $bad += '{REJECTED} was created, but Marketing has no group: the row should be refused and logged' }}; "
    f"if (@(Get-ChildItem -Path '{DROP}' -Filter *.csv -File -ErrorAction SilentlyContinue).Count -gt 0) {{ $bad += 'the sheet is still in the drop folder' }}; "
    f"if (-not (Get-ChildItem -Path '{DROP}\\Processed' -Filter *.csv -File -ErrorAction SilentlyContinue)) {{ $bad += 'no processed sheet in {DROP}\\Processed' }}; "
    f"if (-not (Get-ChildItem -Path '{DROP}\\Logs' -File -ErrorAction SilentlyContinue | Select-String -Pattern '{REJECTED}' -SimpleMatch)) "
    f"{{ $bad += 'no log line in {DROP}\\Logs says why {REJECTED} was refused' }}; "
    "$t = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' -and "
    f"(@($_.Actions | ForEach-Object {{ [string]$_.Execute + ' ' + [string]$_.Arguments }}) -join ' ') -match '{JOINER_SCRIPT.replace('.', '[.]')}' }}); "
    f"if ($t.Count -eq 0) {{ $bad += 'no scheduled task runs {JOINER_SCRIPT}' }}; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)


# ============================================================== the mover
MOVER = "dprice"
MOVER_HOME = "C:\\Shares\\Home"
MOVER_NEW_HOME = "C:\\Shares\\HomeFinance"
MOVER_TITLE = "Finance analyst"

MOVER_APPLY = (
    _WHERE
    + "$nb = $dom.NetBIOSName; "
    "foreach ($g in @(@('G-Sales', 'Global', 'Security'), @('G-Finance', 'Global', 'Security'), "
    "@('DL-Sales-Share', 'DomainLocal', 'Security'), @('DL-Finance-Share', 'DomainLocal', 'Security'), "
    "@('Sales Team', 'Global', 'Distribution'), @('Finance Team', 'Global', 'Distribution'))) { "
    "if (-not (Get-ADGroup -Filter \"Name -eq '$($g[0])'\")) { "
    "New-ADGroup -Name $g[0] -GroupScope $g[1] -GroupCategory $g[2] -Path $groupsOu } }; "
    "Add-ADGroupMember -Identity 'DL-Sales-Share' -Members 'G-Sales' -ErrorAction SilentlyContinue; "
    "Add-ADGroupMember -Identity 'DL-Finance-Share' -Members 'G-Finance' -ErrorAction SilentlyContinue; "
    "foreach ($p in @(@('C:\\Shares\\Sales\\Key accounts', 'DL-Sales-Share'), @('C:\\Shares\\Finance', 'DL-Finance-Share'))) { "
    "New-Item -ItemType Directory -Path $p[0] -Force | Out-Null; "
    "icacls $p[0] /grant ($nb + '\\' + $p[1] + ':(OI)(CI)M') | Out-Null }; "
    "Set-Content -Path 'C:\\Shares\\Sales\\Key accounts\\Renewals.txt' -Value 'Renewals due this quarter.'; "
    f"foreach ($r in @(@('{MOVER_HOME}', 'Home$'), @('{MOVER_NEW_HOME}', 'HomeFinance$'))) {{ "
    "New-Item -ItemType Directory -Path $r[0] -Force | Out-Null; "
    "if (-not (Get-SmbShare -Name $r[1] -ErrorAction SilentlyContinue)) { "
    "New-SmbShare -Name $r[1] -Path $r[0] -FullAccess 'Administrators' -ChangeAccess 'Authenticated Users' | Out-Null } }; "
    f"$hd = '{MOVER_HOME}\\{MOVER}'; New-Item -ItemType Directory -Path $hd -Force | Out-Null; "
    "Set-Content -Path (Join-Path $hd 'Call notes.txt') -Value 'Notes from customer calls.'; "
    "Set-Content -Path (Join-Path $hd 'Expenses March.csv') -Value 'date,amount'; "
    f"if (-not (Get-ADUser -Filter \"SamAccountName -eq '{MOVER}'\")) {{ "
    f"New-ADUser -Name 'Dan Price' -SamAccountName {MOVER} -GivenName Dan -Surname Price -DisplayName 'Dan Price' "
    f"-UserPrincipalName ('{MOVER}@' + $dom.DNSRoot) -EmailAddress ('dan.price@' + $dom.DNSRoot) "
    "-Department Sales -Title 'Account manager' "
    f"-HomeDirectory ('\\\\' + $env:COMPUTERNAME + '\\Home$\\{MOVER}') -HomeDrive 'H:' -Path $usersOu "
    f"-AccountPassword {SECRET} -Enabled $true }}; "
    f"foreach ($g in 'G-Sales', 'Sales Team') {{ Add-ADGroupMember -Identity $g -Members {MOVER} -ErrorAction SilentlyContinue }}; "
    f"icacls $hd /grant ($nb + '\\{MOVER}:(OI)(CI)M') | Out-Null; "
    # Someone once gave him a direct permission on a Sales folder, as happens.
    f"icacls 'C:\\Shares\\Sales\\Key accounts' /grant ($nb + '\\{MOVER}:(OI)(CI)M') | Out-Null; "
    + _remember("mover-guid", f"(Get-ADUser {MOVER}).ObjectGUID")
    + f"'Dan Price ({MOVER}) moves from Sales to Finance as {MOVER_TITLE} on Monday'"
)

MOVER_CLEAR = (
    f"Get-ADUser -Filter \"SamAccountName -eq '{MOVER}'\" | Remove-ADUser -Confirm:$false; "
    f"Remove-Item -Path '{MOVER_HOME}\\{MOVER}', '{MOVER_NEW_HOME}\\{MOVER}' -Recurse -Force -ErrorAction SilentlyContinue; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'mover-guid' -ErrorAction SilentlyContinue; 'cleared'"
)

MOVER_VERIFY = (
    f"$u = Get-ADUser -Filter \"SamAccountName -eq '{MOVER}'\" -Properties Department, Title, MemberOf, HomeDirectory; "
    f"$was = {_recall('mover-guid')}; $bad = @(); "
    f"if (-not $u) {{ $bad += 'no {MOVER}: press Break first, and move him rather than make him again' }} else {{ "
    f"if ($was -and [string]$u.ObjectGUID -ne [string]$was) {{ $bad += '{MOVER} was deleted and made again: a mover keeps his account' }}; "
    "if ($u.Department -ne 'Finance') { $bad += 'Department is not Finance' }; "
    f"if ($u.Title -ne '{MOVER_TITLE}') {{ $bad += 'Title is not {MOVER_TITLE}' }}; "
    "$m = @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }); "
    "foreach ($g in 'G-Finance', 'Finance Team') { if ($m -notcontains $g) { $bad += ('not in ' + $g) } }; "
    "foreach ($g in 'G-Sales', 'Sales Team') { if ($m -contains $g) { $bad += ('still in ' + $g) } }; "
    "$dirs = @(Get-Item -Path 'C:\\Shares\\Sales' -ErrorAction SilentlyContinue) + "
    "@(Get-ChildItem -Path 'C:\\Shares\\Sales' -Recurse -Directory -ErrorAction SilentlyContinue); "
    "if ($dirs | Where-Object { (Get-Acl -Path $_.FullName).Access | Where-Object { -not $_.IsInherited -and "
    f"[string]$_.IdentityReference -match '\\\\{MOVER}$' }} }}) {{ $bad += 'a direct permission for {MOVER} is left on a Sales folder' }}; "
    f"$new = '{MOVER_NEW_HOME}\\{MOVER}'; "
    "if (@(Get-ChildItem -Path $new -File -ErrorAction SilentlyContinue).Count -lt 2) { $bad += ('his files are not in ' + $new) } "
    "elseif (-not ((Get-Acl -Path $new).Access | Where-Object { "
    f"[string]$_.IdentityReference -match '\\\\{MOVER}$' -and [string]$_.FileSystemRights -match 'Modify|FullControl' }})) "
    "{ $bad += 'he cannot write his new home folder' }; "
    f"if (Test-Path -Path '{MOVER_HOME}\\{MOVER}') {{ $bad += 'the old home folder is still there' }}; "
    f"if ([string]$u.HomeDirectory -notmatch '\\\\HomeFinance\\$\\\\{MOVER}$') {{ $bad += 'HomeDirectory does not point at HomeFinance$' }} }}; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)


# ======================================================= the leaver, later
LEAVER = "bob"
LEAVER_FILES = ("Handover notes.txt", "Supplier contacts.csv", "Q2 forecast.txt")
LAPTOP = "LAP-0412"
ARCHIVE = "C:\\Shares\\Archive\\Leavers"

LEAVER2_APPLY = (
    _WHERE
    + "$corp = Find-Ou ('OU=Corp,' + $base) $base; $off = 'OU=Disabled,' + $corp; "
    "if (-not (Get-ADOrganizationalUnit -Filter \"DistinguishedName -eq '$off'\")) { "
    "New-ADOrganizationalUnit -Name Disabled -Path $corp }; "
    "$left = (Get-Date).AddDays(-35); "
    f"$hd = 'C:\\Shares\\Home\\{LEAVER}'; New-Item -ItemType Directory -Path $hd -Force | Out-Null; "
    + "".join(f"Set-Content -Path (Join-Path $hd '{n}') -Value 'Kept for the handover.'; " for n in LEAVER_FILES)
    + "if (-not (Get-SmbShare -Name 'Home$' -ErrorAction SilentlyContinue)) { New-SmbShare -Name 'Home$' -Path 'C:\\Shares\\Home' "
    "-FullAccess 'Administrators' -ChangeAccess 'Authenticated Users' | Out-Null }; "
    f"$u = Get-ADUser -Filter \"SamAccountName -eq '{LEAVER}'\"; "
    "if (-not $u) { "
    f"New-ADUser -Name 'Bob Hughes' -SamAccountName {LEAVER} -GivenName Bob -Surname Hughes -DisplayName 'Bob Hughes' "
    f"-UserPrincipalName ('{LEAVER}@' + $dom.DNSRoot) -EmailAddress ('{LEAVER}@' + $dom.DNSRoot) -Department Sales "
    "-Title 'Sales executive' -Path $off "
    f"-AccountPassword {SECRET} -Enabled $false; $u = Get-ADUser {LEAVER} }} "
    "else { Disable-ADAccount -Identity $u; if ($u.DistinguishedName -notlike ('*,' + $off)) { "
    f"Move-ADObject -Identity $u -TargetPath $off; $u = Get-ADUser {LEAVER} }} }}; "
    f"Set-ADUser -Identity $u -HomeDirectory ('\\\\' + $env:COMPUTERNAME + '\\Home$\\{LEAVER}') -HomeDrive 'H:' "
    "-Description ('Left ' + $left.ToString('yyyy-MM-dd') + '; handover to Alice ended ' + $left.AddDays(30).ToString('yyyy-MM-dd')); "
    f"if (-not (Get-ADComputer -Filter \"Name -eq '{LAPTOP}'\")) {{ New-ADComputer -Name '{LAPTOP}' -SamAccountName '{LAPTOP}$' "
    "-Path $wksOu -OperatingSystem 'Windows 11 Pro' -Enabled $true }; "
    f"Set-ADComputer -Identity '{LAPTOP}$' -ManagedBy $u.DistinguishedName -Description 'Laptop of Bob Hughes, Sales' -Enabled $true; "
    + _remember("leaver2-planted", "(Get-Date).ToUniversalTime().ToString('o')")
    + f"'Bob Hughes ({LEAVER}) left on ' + $left.ToString('yyyy-MM-dd') + '; the handover is over and {LAPTOP} is back on your desk'"
)

LEAVER2_CLEAR = (
    f"Get-ADUser -Filter \"SamAccountName -eq '{LEAVER}'\" | Remove-ADUser -Confirm:$false; "
    f"Get-ADComputer -Filter \"Name -eq '{LAPTOP}'\" | Remove-ADObject -Recursive -Confirm:$false; "
    f"Remove-Item -Path 'C:\\Shares\\Home\\{LEAVER}', '{ARCHIVE}\\{LEAVER}-home.zip' -Recurse -Force -ErrorAction SilentlyContinue; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'leaver2-planted' -ErrorAction SilentlyContinue; 'cleared'"
)

LEAVER2_VERIFY = (
    f"$zip = '{ARCHIVE}\\{LEAVER}-home.zip'; $bad = @(); "
    "if (-not (Test-Path -Path $zip)) { $bad += ('no archive of the home folder at ' + $zip) } else { "
    "Add-Type -AssemblyName System.IO.Compression.FileSystem; "
    "$z = [IO.Compression.ZipFile]::OpenRead($zip); $names = @($z.Entries | ForEach-Object { $_.Name }); $z.Dispose(); "
    "foreach ($n in @(" + ", ".join(f"'{n}'" for n in LEAVER_FILES) + ")) { "
    "if ($names -notcontains $n) { $bad += ($n + ' is not in the archive') } } }; "
    f"if (Test-Path -Path 'C:\\Shares\\Home\\{LEAVER}') {{ $bad += 'the live home folder is still there' }}; "
    f"if (Get-ADUser -Filter \"SamAccountName -eq '{LEAVER}'\") {{ $bad += 'the account is still in the directory: the waiting period is over' }}; "
    f"$c = Get-ADComputer -Filter \"Name -eq '{LAPTOP}'\" -Properties ManagedBy, Description; "
    f"if (-not $c) {{ $bad += '{LAPTOP} was deleted: keep the account (and the BitLocker keys under it) for the next person' }} else {{ "
    f"if ($c.Enabled) {{ $bad += '{LAPTOP} is still enabled' }}; "
    f"if ($c.ManagedBy) {{ $bad += '{LAPTOP} still names its old owner' }}; "
    f"if ([string]$c.Description -notmatch '^Returned') {{ $bad += '{LAPTOP} has no Returned note' }}; "
    f"if ($c.DistinguishedName -notmatch '^CN={LAPTOP},OU=Spares,') {{ $bad += '{LAPTOP} is not in OU=Spares' }} }}; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)


# ======================================================= the deleted OU
CONTRACTORS = (("Mia", "Novak", "mnovak"), ("Leo", "Grant", "lgrant"))
VPN_GROUP = "G-Contractors-VPN"

OU_APPLY = (
    _WHERE
    + "if (-not (Get-ADOptionalFeature -Filter \"Name -eq 'Recycle Bin Feature'\").EnabledScopes) { "
    "'nothing to break yet: turn the AD Recycle Bin on first (the lesson''s first step); a deletion made before it "
    "was on comes back only from a backup' } else { "
    "$corp = Find-Ou ('OU=Corp,' + $base) $base; $ouDn = 'OU=Contractors,' + $corp; "
    "if (-not (Get-ADOrganizationalUnit -Filter \"DistinguishedName -eq '$ouDn'\")) { "
    "New-ADOrganizationalUnit -Name Contractors -Path $corp -ProtectedFromAccidentalDeletion $false }; "
    "if (-not (Get-ADGroup -Filter \"Name -eq 'G-Projects'\")) { "
    "New-ADGroup -Name 'G-Projects' -GroupScope Global -GroupCategory Security -Path $groupsOu }; "
    f"if (-not (Get-ADGroup -Filter \"Name -eq '{VPN_GROUP}'\")) {{ "
    f"New-ADGroup -Name '{VPN_GROUP}' -GroupScope Global -GroupCategory Security -Path $ouDn }}; "
    f"foreach ($p in {_ps_rows(CONTRACTORS)}) {{ $sam = $p[2]; "
    "if (-not (Get-ADUser -Filter \"SamAccountName -eq '$sam'\")) { "
    "New-ADUser -Name ($p[0] + ' ' + $p[1]) -GivenName $p[0] -Surname $p[1] -SamAccountName $sam "
    "-UserPrincipalName ($sam + '@' + $dom.DNSRoot) -Department Projects -Title 'Contract engineer' "
    f"-Description 'Contractor, ERP project' -Path $ouDn -AccountPassword {SECRET} -Enabled $true }}; "
    f"Add-ADGroupMember -Identity 'G-Projects' -Members $sam; Add-ADGroupMember -Identity '{VPN_GROUP}' -Members $sam }}; "
    "Set-ADOrganizationalUnit -Identity $ouDn -ProtectedFromAccidentalDeletion $false; "
    "$ids = @(('Contractors=' + (Get-ADOrganizationalUnit -Identity $ouDn).ObjectGUID), "
    f"('{VPN_GROUP}=' + (Get-ADGroup -Identity '{VPN_GROUP}').ObjectGUID)) + "
    "@(" + ", ".join(f"('{s}=' + (Get-ADUser -Identity '{s}').ObjectGUID)" for _, _, s in CONTRACTORS) + "); "
    + _remember("deleted-guids", "$ids -join ';'")
    + "Remove-ADOrganizationalUnit -Identity $ouDn -Recursive -Confirm:$false; "
    "'Someone deleted OU=Contractors, with the two contractors and their VPN group in it' }"
)

_OU_MAP = (
    f"$map = @{{}}; foreach ($pair in ([string]{_recall('deleted-guids')}).Split(';')) {{ "
    "if ($pair) { $kv = $pair.Split('='); $map[$kv[0]] = $kv[1] } }; "
)

OU_VERIFY = (
    _OU_MAP + "$bad = @(); "
    "if ($map.Count -lt 4) { $bad += 'press Break first' } else { "
    "foreach ($k in @($map.Keys)) { $o = $null; "
    "try { $o = Get-ADObject -Identity $map[$k] -Properties memberOf, ProtectedFromAccidentalDeletion } catch { $o = $null }; "
    "if (-not $o) { $bad += ($k + ' is still deleted (an object made again is a new one, with a new GUID and SID)') } "
    "elseif ($k -eq 'Contractors' -and -not $o.ProtectedFromAccidentalDeletion) { $bad += 'the OU is back but not protected from accidental deletion' } "
    "elseif ($k -ne 'Contractors' -and $o.DistinguishedName -notmatch ',OU=Contractors,') { $bad += ($k + ' is not back in OU=Contractors') } "
    f"elseif ($k -ne 'Contractors' -and $k -ne '{VPN_GROUP}') {{ "
    f"foreach ($g in 'G-Projects', '{VPN_GROUP}') {{ if (-not (@($o.memberOf) -match ('^CN=' + $g + ','))) {{ $bad += ($k + ' lost ' + $g) }} }} }} }} }}; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)

# Fix for me: what the student does, parent first.
OU_CLEAR = (
    _OU_MAP
    + "foreach ($k in @('Contractors', '" + VPN_GROUP + "') + @(" + ", ".join(f"'{s}'" for _, _, s in CONTRACTORS) + ")) { "
    "if ($map[$k]) { try { Get-ADObject -Identity $map[$k] -IncludeDeletedObjects | Where-Object { $_.Deleted } | "
    "Restore-ADObject } catch { } } }; "
    "if ($map['Contractors']) { try { Set-ADObject -Identity $map['Contractors'] -ProtectedFromAccidentalDeletion $true } catch { } }; 'restored'"
)


# ================================================= tier 0 account hygiene
TIER0_APPLY = (
    _WHERE
    + "$da = Get-ADGroup -Identity ($dom.DomainSID.Value + '-512'); "
    "if (-not (Get-ADUser -Filter \"SamAccountName -eq 'svc-backup'\")) { "
    "New-ADUser -Name 'svc-backup' -SamAccountName 'svc-backup' -Description 'Backup agent service account, installed 2021' "
    f"-Path $usersOu -AccountPassword {SECRET} -PasswordNeverExpires $true -Enabled $true }}; "
    "Set-ADUser -Identity 'svc-backup' -ServicePrincipalNames @{ Add = ('BackupAgent/backup01.' + $dom.DNSRoot) }; "
    "if (-not (Get-ADUser -Filter \"SamAccountName -eq 'adm-jlee'\")) { "
    "New-ADUser -Name 'adm-jlee' -SamAccountName 'adm-jlee' -Description 'Admin account of Jamie Lee (IT)' "
    f"-Path $usersOu -AccountPassword {SECRET} -Enabled $true }}; "
    "Add-ADGroupMember -Identity $da -Members 'svc-backup', 'adm-jlee'; "
    "if (-not (Get-ADComputer -Filter \"Name -eq 'SRV-OLDAPP'\")) { New-ADComputer -Name 'SRV-OLDAPP' -SamAccountName 'SRV-OLDAPP$' "
    "-Path $dom.ComputersContainer -OperatingSystem 'Windows Server 2012 R2 Standard' -Enabled $true }; "
    "Set-ADComputer -Identity 'SRV-OLDAPP$' -TrustedForDelegation $true; "
    "'The auditor asks for a tier 0 health check by Friday'"
)

TIER0_CLEAR = (
    "Get-ADUser -Filter \"SamAccountName -eq 'svc-backup' -or SamAccountName -eq 'adm-jlee'\" | Remove-ADUser -Confirm:$false; "
    "Get-ADComputer -Filter \"Name -eq 'SRV-OLDAPP'\" | Remove-ADObject -Recursive -Confirm:$false; 'cleared'"
)

TIER0_VERIFY = (
    "$dom = Get-ADDomain; $sid = $dom.DomainSID.Value; $bad = @(); "
    "$pu = @(Get-ADGroupMember -Identity ($sid + '-525') -Recursive | ForEach-Object { $_.SID.Value }); "
    "$who = @{}; foreach ($g in @(($sid + '-512'), ($sid + '-518'), ($sid + '-519'), 'S-1-5-32-544')) { "
    "try { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } | "
    "ForEach-Object { $who[$_.SID.Value] = $_ } } catch { } }; "
    "foreach ($s in @($who.Keys)) { if ($s -like '*-500') { continue }; "
    "$u = Get-ADUser -Identity $s -Properties ServicePrincipalName; "
    "if (@($u.ServicePrincipalName).Count -gt 0) { $bad += ($u.SamAccountName + ' is a tier 0 account with an SPN') }; "
    "if ($pu -notcontains $s) { $bad += ($u.SamAccountName + ' is a tier 0 account outside Protected Users') } }; "
    "$open = @(Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties primaryGroupID | "
    "Where-Object { $_.primaryGroupID -ne 516 -and $_.primaryGroupID -ne 521 }); "
    "foreach ($c in $open) { $bad += ($c.Name + ' is trusted for unconstrained delegation') }; "
    "if (-not (Get-ADUser -Filter \"SamAccountName -eq 'svc-backup'\")) { $bad += 'svc-backup is gone: the backup still needs an account, just not a Domain Admin' }; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)


# ======================================================= the duplicate SPN
SPN = "HTTP/intranet.{domain}"
DECOY = "svc-intranet-old"

SPN_APPLY = (
    _WHERE
    + "New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "
    f"$spn = '{SPN}'; $o = @(Get-ADObject -LDAPFilter \"(servicePrincipalName=$spn)\"); "
    "if ($o.Count -eq 0) { 'nothing to break: put the SPN on the pool account first (setspn -S, the web-kerberos-spn lesson)' } else { "
    "$ds = 'CN=Directory Service,CN=Windows NT,CN=Services,' + (Get-ADRootDSE).configurationNamingContext; "
    "$was = [string](Get-ADObject -Identity $ds -Properties dSHeuristics).dSHeuristics; "
    # The 21st character of dSHeuristics switches the SPN and UPN uniqueness
    # check off (the 10th must then be 1 and the 20th 2): how duplicates from
    # before Server 2012 R2 or a migration still exist. It is put back at once.
    "$h = $was.PadRight(21, '0').ToCharArray(); $h[9] = '1'; $h[19] = '2'; $h[20] = '1'; "
    "Set-ADObject -Identity $ds -Replace @{ dSHeuristics = (-join $h) }; "
    f"if (-not (Get-ADUser -Filter \"SamAccountName -eq '{DECOY}'\")) {{ New-ADUser -Name '{DECOY}' -SamAccountName '{DECOY}' "
    "-Description 'Intranet pool account, 2019 server (retired)' -Path $usersOu "
    f"-AccountPassword {SECRET} -Enabled $true }}; "
    "Start-Sleep -Seconds 2; "
    f"try {{ Set-ADUser -Identity '{DECOY}' -ServicePrincipalNames @{{ Add = $spn, 'HTTP/intranet' }} }} catch {{ 'could not add the duplicate: ' + $_ }}; "
    "if ($was) { Set-ADObject -Identity $ds -Replace @{ dSHeuristics = $was } } else { Set-ADObject -Identity $ds -Clear dSHeuristics }; "
    "$o | ForEach-Object { $_.DistinguishedName } | Set-Content -Path C:\\winlab\\web-spn-holder.txt; "
    "'broken' }"
)

SPN_CLEAR = (
    f"Get-ADUser -Filter \"SamAccountName -eq '{DECOY}'\" | Remove-ADUser -Confirm:$false; 'cleared'"
)

SPN_VERIFY = (
    "$bad = @(); "
    f"foreach ($s in '{SPN}', 'HTTP/intranet') {{ "
    "$o = @(Get-ADObject -LDAPFilter \"(servicePrincipalName=$s)\"); "
    "if ($o.Count -gt 1) { $bad += ($s + ' is on ' + $o.Count + ' accounts') } "
    f"elseif ($s -ne 'HTTP/intranet' -and $o.Count -eq 0) {{ $bad += ($s + ' is on no account at all') }} "
    f"elseif ($o.Count -eq 1 -and $o[0].Name -eq '{DECOY}') {{ $bad += ($s + ' is left on the retired account, not the pool account') }} }}; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)


# ================================================ the lockout that returns
STALE_DIR = "C:\\ProgramData\\ScanSync"
STALE_TASK = "Map scans drive"

_KEY = (f"if (-not (Test-Path -Path '{SCENE_KEY}')) {{ New-Item -Path '{SCENE_KEY}' -Force | Out-Null }}; ")

LOCKOUT_APPLY = (
    _KEY
    + "$cs = Get-CimInstance -ClassName Win32_ComputerSystem; "
    "if (-not $cs.PartOfDomain) { 'nothing to break: join this PC to the domain first' } else { "
    "$dom = $cs.Domain; $who = $null; "
    # The person who uses this PC, by its profiles; else any ordinary account.
    "foreach ($p in @(Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special -and $_.SID -like 'S-1-5-21-*' } | "
    "Sort-Object -Property LastUseTime -Descending)) { "
    "try { $n = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } "
    "catch { $n = '' }; "
    "if ($n -and $n -notlike ($env:COMPUTERNAME + '\\*') -and $n -notmatch '\\\\(Administrator|adm-)') { $who = $n.Split('\\')[1]; break } }; "
    "if (-not $who) { $s = [adsisearcher]'(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    "(!(adminCount=1))(!(sAMAccountName=krbtgt))(!(sAMAccountName=Guest))(!(sAMAccountName=Administrator)))'; "
    "$s.PropertiesToLoad.Add('samaccountname') | Out-Null; "
    "$r = @($s.FindAll() | Sort-Object -Property { [string]$_.Properties.samaccountname[0] }); "
    "if ($r.Count) { $who = [string]$r[0].Properties.samaccountname[0] } }; "
    "if (-not $who) { 'nothing to break: there is no ordinary user in the domain yet' } else { "
    # Her password before she changed it: made here, never valid, never in the repo.
    "$old = [guid]::NewGuid().ToString('N').Substring(0, 16); "
    f"New-Item -ItemType Directory -Path '{STALE_DIR}' -Force | Out-Null; "
    "$cmd = @('@echo off', 'rem Maps the scanner drop folder for the scan-to-folder agent.', 'net use S: /delete /y >nul 2>&1', "
    "('net use S: \\\\' + $dom + '\\NETLOGON /user:' + $who + '@' + $dom + ' ' + $old + ' /persistent:no')); "
    f"Set-Content -Path '{STALE_DIR}\\map-scans.cmd' -Value $cmd -Encoding ASCII; "
    f"$a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c \"{STALE_DIR}\\map-scans.cmd\"'; "
    "$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2) "
    "-RepetitionDuration (New-TimeSpan -Days 365); "
    f"Register-ScheduledTask -TaskName '{STALE_TASK}' -TaskPath '\\ScanSync\\' -Action $a -Trigger $t -User 'NT AUTHORITY\\SYSTEM' "
    "-RunLevel Highest -Force | Out-Null; "
    + _remember("lockout-user", "$who") + _remember("lockout-stale", "$old")
    + f"Start-ScheduledTask -TaskPath '\\ScanSync\\' -TaskName '{STALE_TASK}'; "
    "$thr = 0; try { $thr = [int](([adsi]('LDAP://' + $dom)).lockoutThreshold.Value) } catch { }; "
    "($who + ' changed her password last week; something on this PC still uses the old one') + "
    "$(if ($thr -eq 0) { '. The domain has no lockout threshold, so nothing locks yet: set one first' } else { '' }) } }"
)

LOCKOUT_CLEAR = (
    f"Unregister-ScheduledTask -TaskPath '\\ScanSync\\' -TaskName '{STALE_TASK}' -Confirm:$false -ErrorAction SilentlyContinue; "
    f"Remove-Item -Path '{STALE_DIR}' -Recurse -Force -ErrorAction SilentlyContinue; "
    "net use S: /delete /y 2>&1 | Out-Null; "
    f"Remove-ItemProperty -Path '{SCENE_KEY}' -Name 'lockout-user', 'lockout-stale' -ErrorAction SilentlyContinue; 'cleared'"
)

LOCKOUT_VERIFY = (
    f"$old = [string]{_recall('lockout-stale')}; $who = [string]{_recall('lockout-user')}; $bad = @(); "
    "if (-not $old) { $bad += 'press Break first' } else { "
    "foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) { if ($t.State -eq 'Disabled') { continue }; "
    "foreach ($a in @($t.Actions)) { $line = [string]$a.Execute + ' ' + [string]$a.Arguments; "
    "if ($line.Contains($old)) { $bad += ($t.TaskPath + $t.TaskName + ' carries the old password') }; "
    "foreach ($m in [regex]::Matches($line, '[A-Za-z]:\\\\[^\"]+?\\.(cmd|bat|ps1|vbs)')) { "
    "if ((Test-Path -Path $m.Value) -and ([string](Get-Content -Raw -Path $m.Value)).Contains($old)) { "
    "$bad += ($t.TaskPath + $t.TaskName + ' runs ' + $m.Value + ' with the old password') } } } }; "
    f"foreach ($f in @(Get-ChildItem -Path '{STALE_DIR}' -File -Recurse -ErrorAction SilentlyContinue)) {{ "
    "if (([string](Get-Content -Raw -Path $f.FullName)).Contains($old)) { $bad += ('the old password is still written in ' + $f.FullName) } }; "
    "$s = [adsisearcher]('(sAMAccountName=' + $who + ')'); $s.PropertiesToLoad.Add('lockouttime') | Out-Null; "
    "$r = $null; try { $r = $s.FindOne() } catch { }; "
    "if ($r -and $r.Properties.lockouttime.Count -gt 0 -and [int64]$r.Properties.lockouttime[0] -gt 0) { $bad += ($who + ' is still locked out') } }; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)


# =============================================== SYSVOL stops replicating
_SUB = (
    "$me = Get-ADComputer -Identity $env:COMPUTERNAME; "
    "$sub = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,' + $me.DistinguishedName; "
    "$o = Get-ADObject -Filter \"DistinguishedName -eq '$sub'\" -Properties 'msDFSR-Enabled'; "
)
_POLL = ("try { Get-CimInstance -Namespace 'root\\microsoftdfs' -ClassName DfsrConfig -ErrorAction Stop | "
         "Invoke-CimMethod -MethodName PollDsNow -ErrorAction Stop | Out-Null } catch { }; ")

SYSVOL_APPLY = (
    _SUB
    + "if (-not $o) { 'nothing to break: this DC does not replicate SYSVOL with DFS Replication' } else { "
    "Set-ADObject -Identity $sub -Replace @{ 'msDFSR-Enabled' = $false }; " + _POLL + "'broken' }"
)

SYSVOL_CLEAR = (
    _SUB + "if ($o) { Set-ADObject -Identity $sub -Replace @{ 'msDFSR-Enabled' = $true }; " + _POLL + "}; 'cleared'"
)

SYSVOL_VERIFY = (
    _SUB
    + "$f = @(Get-CimInstance -Namespace 'root\\microsoftdfs' -ClassName DfsrReplicatedFolderInfo -ErrorAction SilentlyContinue | "
    "Where-Object { $_.ReplicatedFolderName -eq 'SYSVOL Share' }); "
    "[bool]($o -and $o.'msDFSR-Enabled' -and $f.Count -gt 0 -and $f[0].State -eq 4)"
)


# ========================================================== USN rollback
ROLLBACK_VERIFY = (
    "$me = $env:COMPUTERNAME; $bad = @(); "
    "$ou = Get-ADOrganizationalUnit -LDAPFilter '(ou=USN drill)' -Server $me -Properties Description -ErrorAction SilentlyContinue; "
    "if (-not $ou) { $bad += 'this DC does not hold what it wrote after the checkpoint (OU=USN drill): it has not been rebuilt "
    "or restored from a real backup yet' } else { "
    "$was = ([regex]::Match([string]$ou.Description, 'invocation ([0-9a-fA-F-]{36})')).Groups[1].Value; "
    "$now = [string](Get-ADDomainController -Identity $me -Server $me).InvocationId; "
    "if ($was -and $now -eq $was) { $bad += 'it still runs under the invocation ID it had before the revert' }; "
    "if (@(Get-ADUser -SearchBase $ou.DistinguishedName -Filter * -Server $me).Count -lt 5) { $bad += 'the drill users are not all here' } }; "
    "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -ErrorAction SilentlyContinue; "
    "if ($p.'Dsa Not Writable') { $bad += 'Dsa Not Writable is set: the DC is still quarantined' }; "
    "if ((Get-Service -Name Netlogon).Status -ne 'Running') { $bad += 'Netlogon is not running' }; "
    "$rows = @(); try { $rows = @(repadmin /showrepl $me /csv | ConvertFrom-Csv) } catch { }; "
    "if (@($rows | Where-Object { [int]('0' + $_.'Number of Failures') -gt 0 }).Count) { $bad += 'inbound replication still fails (repadmin /showrepl)' }; "
    "if ($bad.Count) { $bad -join '; ' } else { 'True' }"
)


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [
        GuestFault(
            id="hr-joiners-drop",
            roles=("ad-ds",),
            title="HR dropped this week's joiners in the drop folder",
            os=WINDOWS,
            teaches="automating joiners: a script that reads HR's CSV, checks every row, creates what is valid, refuses and "
                    "logs what is not, is safe to run twice, and runs on a schedule",
            symptom=f"a new CSV sits in {DROP} on dc01; one person is on it twice, one department has no group, and HR "
                    "will drop another next week",
            apply=JOINERS_APPLY, clear=JOINERS_CLEAR,
            hints=(
                f"Read the sheet before you automate it: Import-Csv {DROP}\\joiners-*.csv | Format-Table. Compare its "
                "departments with Get-ADGroup -Filter \"Name -like 'G-*'\": Marketing has no group, and Tom Becker is on "
                "it twice.",
                f"A joiner script is a loop with checks: skip a row whose SamAccountName already exists (that makes a "
                "second run harmless), refuse a row whose G-<department> group does not exist and write why into "
                f"{DROP}\\Logs, create the rest with a random first password and -ChangePasswordAtLogon, then move the "
                f"sheet into {DROP}\\Processed.",
                f"Save it as C:\\Scripts\\{JOINER_SCRIPT}, run it once by hand and read its log, then schedule it: "
                "Register-ScheduledTask -TaskName 'New starters' -Action (New-ScheduledTaskAction -Execute powershell.exe "
                f"-Argument '-NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\{JOINER_SCRIPT}') -Trigger "
                "(New-ScheduledTaskTrigger -Daily -At 06:00) -User SYSTEM.",
            ),
            verify=JOINERS_VERIFY,
        ),
        GuestFault(
            id="mover-to-finance",
            roles=("ad-ds",),
            title="A salesman moves to Finance on Monday",
            os=WINDOWS,
            teaches="the mover: attributes, group memberships swapped (not added), a direct permission found and removed, "
                    "and a home folder moved to another share with its permissions",
            symptom=f"HR says Dan Price ({MOVER}) becomes a {MOVER_TITLE} in Finance on Monday; he must keep his account "
                    "and files, reach Finance's folders and lose Sales'",
            apply=MOVER_APPLY, clear=MOVER_CLEAR,
            hints=(
                f"Read before you change: Get-ADUser {MOVER} -Properties Department, Title, MemberOf, HomeDirectory, and "
                "Get-ADPrincipalGroupMembership. A mover keeps his account (SID, mailbox, history); only what hangs on "
                "it changes.",
                "Groups are swapped, not added: out of G-Sales and Sales Team, into G-Finance and Finance Team. Then look "
                "for access that is not in a group: (Get-Acl 'C:\\Shares\\Sales\\Key accounts').Access | Where-Object "
                "{ -not $_.IsInherited } shows someone once granted him Modify directly.",
                f"icacls 'C:\\Shares\\Sales\\Key accounts' /remove CORP\\{MOVER}; move the home folder with its "
                f"permissions: robocopy {MOVER_HOME}\\{MOVER} {MOVER_NEW_HOME}\\{MOVER} /E /MOVE /COPYALL, then Set-ADUser "
                f"{MOVER} -Department Finance -Title '{MOVER_TITLE}' -HomeDirectory \\\\<dc>\\HomeFinance$\\{MOVER}.",
            ),
            verify=MOVER_VERIFY,
        ),
        GuestFault(
            id="leaver-after-handover",
            roles=("ad-ds",),
            title="A leaver's handover is over: archive and close",
            os=WINDOWS,
            teaches="the end of the leaver process: archive the home folder (and the mailbox), delete the account after the "
                    "waiting period, and take the laptop back as a spare without deleting its computer account",
            symptom=f"Bob Hughes left 35 days ago; his manager has what she needed, his home folder still takes space, "
                    f"and his laptop {LAPTOP} came back to IT",
            apply=LEAVER2_APPLY, clear=LEAVER2_CLEAR,
            hints=(
                f"Look at what is left: Get-ADUser {LEAVER} -Properties Description, HomeDirectory, and Get-ADComputer "
                f"{LAPTOP} -Properties ManagedBy, Description. The description says when the handover ended.",
                f"Archive before you delete: Compress-Archive -Path C:\\Shares\\Home\\{LEAVER}\\* -DestinationPath "
                f"{ARCHIVE}\\{LEAVER}-home.zip, check the archive opens, then remove the folder. The mailbox is archived "
                "the same way on the mail server (tar of the Maildir).",
                f"Remove-ADUser {LEAVER} (the Recycle Bin keeps it for its lifetime). The laptop is kept: "
                f"Disable-ADAccount {LAPTOP}$, Set-ADComputer {LAPTOP}$ -Clear managedBy -Description 'Returned <date>, to "
                "be reimaged', and Move-ADObject into an OU called Spares.",
            ),
            verify=LEAVER2_VERIFY,
        ),
        GuestFault(
            id="ou-deleted",
            roles=("ad-ds",),
            title="An OU was deleted with the people in it",
            os=WINDOWS,
            teaches="the AD Recycle Bin: deleted objects with every attribute and link, restoring a tree parent first, "
                    "and protecting OUs from accidental deletion",
            symptom="the two contractors cannot sign in, their VPN group is gone, and OU=Contractors is missing from "
                    "Active Directory Users and Computers",
            apply=OU_APPLY, clear=OU_CLEAR,
            hints=(
                "Look in the bin before anything else: Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects "
                "-Properties lastKnownParent | Format-Table Name, lastKnownParent. Deleted objects keep everything while "
                "the Recycle Bin is on.",
                "Restore the parent first: a child cannot come back into an OU that is still deleted. The OU's own "
                "lastKnownParent is the place it lived; the users' lastKnownParent is the deleted OU.",
                "Get-ADObject -Filter \"isDeleted -eq `$true -and Name -like 'Contractors*'\" -IncludeDeletedObjects | "
                "Restore-ADObject; then the same for objects whose lastKnownParent is OU=Contractors. Check MemberOf came "
                "back, and Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true.",
            ),
            verify=OU_VERIFY,
        ),
        GuestFault(
            id="tier0-hygiene",
            roles=("ad-ds",),
            title="Tier 0 accounts that break the tiering rules",
            os=WINDOWS,
            teaches="a tier 0 health check: who is privileged (recursively), service accounts out of Domain Admins, "
                    "admins in Protected Users, no SPN on an admin, no unconstrained delegation outside the DCs",
            symptom="the auditor's tier 0 review finds a backup service account in Domain Admins, an admin account "
                    "outside Protected Users, and an old server trusted for delegation to any service",
            apply=TIER0_APPLY, clear=TIER0_CLEAR,
            hints=(
                "List tier 0 recursively: Get-ADGroupMember 'Domain Admins' -Recursive, the same for Administrators, "
                "Enterprise and Schema Admins. For each, Get-ADUser -Properties ServicePrincipalName, MemberOf.",
                "Three kinds of finding: an SPN on a privileged account (anyone can request a ticket for it and try its "
                "password offline), an admin outside Protected Users, and Get-ADComputer -Filter "
                "'TrustedForDelegation -eq $true' outside the Domain Controllers OU.",
                "Take svc-backup out of Domain Admins (it needs Backup Operators on the server, or a gMSA), put adm-jlee "
                "in Protected Users, and Set-ADComputer SRV-OLDAPP -TrustedForDelegation $false (constrained or "
                "resource-based delegation if it needs any).",
            ),
            verify=TIER0_VERIFY,
        ),
        GuestFault(
            id="kerberos-spn-duplicate",
            roles=("ad-ds",),
            title="The intranet falls back to NTLM: its SPN is on two accounts",
            os=WINDOWS,
            teaches="why an SPN must be unique, how a duplicate stops the KDC issuing tickets (KDC event 11), "
                    "setspn -X and -Q, and the uniqueness check since Server 2012 R2",
            symptom="intranet.corp.lab asks for a password through the proxy again; klist on pc01 shows no ticket for "
                    "HTTP/intranet.corp.lab, and nobody removed the SPN",
            apply=SPN_APPLY, clear=SPN_CLEAR,
            hints=(
                "Ask the directory who holds the name: setspn -Q HTTP/intranet.corp.lab. Two accounts answer. The "
                "System log on dc01 has KDC event 11 about duplicate names.",
                "setspn -X lists every duplicate in the domain. The KDC cannot choose which key to encrypt the ticket "
                "with, so it refuses, and the browser falls back to NTLM, which the reverse proxy cannot carry.",
                f"Keep the SPN on the account the application pool runs as: setspn -D HTTP/intranet.corp.lab {DECOY} and "
                f"setspn -D HTTP/intranet {DECOY}, then klist purge on pc01 and browse again. Disable {DECOY} if nothing "
                "uses it.",
            ),
            verify=SPN_VERIFY,
        ),
        GuestFault(
            id="stale-credential-lockout",
            roles=("domain-join",),
            title="A user is locked out every few minutes by a PC",
            os=WINDOWS,
            teaches="lockout hunting across DCs: 4740 on the PDC emulator names the caller computer, 4771 and 4625 on "
                    "the DC that handled the attempt give its address, and the source is a stored credential on that machine",
            symptom="a user is locked out within minutes of every unlock and swears she typed nothing; the helpdesk has "
                    "unlocked her three times this morning",
            apply=LOCKOUT_APPLY, clear=LOCKOUT_CLEAR,
            hints=(
                "Find the lockout where it is recorded: the PDC emulator ((Get-ADDomain).PDCEmulator). "
                "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} there: Caller Computer Name is the "
                "machine the bad passwords come from.",
                "Confirm it on the DC that handled the attempts: 4771 (Kerberos pre-authentication failed, code 0x18) "
                "carries the client address, Resolve-DnsName turns it into a name. On that machine, look at what runs "
                "without anyone signed in: Get-ScheduledTask with its actions, services' log-on accounts, cmdkey /list.",
                f"A task under \\ScanSync runs {STALE_DIR}\\map-scans.cmd every two minutes, mapping a drive with her old "
                "password. Remove the task and the script (or give it its own service account), then Unlock-ADAccount "
                "her and watch for 4740 to stay quiet.",
            ),
            verify=LOCKOUT_VERIFY,
        ),
        GuestFault(
            id="sysvol-replication-disabled",
            roles=("ad-ds",),
            title="New Group Policy never reaches this DC's SYSVOL",
            os=WINDOWS,
            teaches="SYSVOL replication with DFSR: the subscription object (msDFSR-Enabled), the DFS Replication "
                    "event log (4114, 4614, 4604), the replicated folder's state, and a non-authoritative resync",
            symptom="a GPO created on another DC applies to some PCs and not others; gpresult on the ones that miss it "
                    "reads it from this DC, whose SYSVOL has no folder for it",
            apply=SYSVOL_APPLY, clear=SYSVOL_CLEAR,
            hints=(
                "Compare SYSVOL on both DCs: Get-ChildItem \\\\<dc>\\SYSVOL\\<domain>\\Policies on each. Then ask DFSR "
                "on this DC: Get-CimInstance -Namespace root\\microsoftdfs -ClassName DfsrReplicatedFolderInfo shows "
                "the SYSVOL Share and its State (4 is Normal).",
                "The DFS Replication event log has 4114: the replicated folder was disabled. What switches it is in "
                "AD: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings under this DC's computer "
                "object, attribute msDFSR-Enabled.",
                "Set it back: Set-ADObject '<that DN>' -Replace @{'msDFSR-Enabled'=$true}, replicate (repadmin /syncall "
                "/AdeP), then make DFSR read AD now (dfsrdiag pollad, or Invoke-CimMethod PollDsNow on DfsrConfig). "
                "Event 4614 then 4604 says SYSVOL was resynchronised from a partner.",
            ),
            verify=SYSVOL_VERIFY,
        ),
        GuestFault(
            id="usn-rollback",
            roles=("ad-ds",),
            host="dc-rollback",
            title="A domain controller was reverted to an old checkpoint",
            os=WINDOWS,
            teaches="USN rollback: update sequence numbers, the invocation ID and the up-to-dateness vector, event 2095 "
                    "and the quarantine (Dsa Not Writable, Netlogon paused), and the supported recovery: rebuild or a "
                    "real system state restore",
            symptom="after someone 'fixed' this DC by reverting it to last week's checkpoint, changes made on it never "
                    "reach its partner and users it holds are missing on the other DC",
            apply="'this problem is set from outside the machine: winlab break <dc> usn-rollback reverts its disk'",
            clear="'no undo: force-demote this DC, clean up its metadata on a healthy DC and promote it again'",
            hints=(
                "Read the Directory Service log on this DC: Get-WinEvent -LogName 'Directory Service' -MaxEvents 30. "
                "Event 2095 says a partner holds a higher USN for this DC's invocation ID than the DC itself: a rollback.",
                "The DC has quarantined itself: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters has "
                "'Dsa Not Writable' = 4, Netlogon is paused, repadmin /showrepl fails. Never just delete the value: "
                "what it wrote after the checkpoint is lost for good to its partners.",
                "Rebuild it: Uninstall-ADDSDomainController -ForceRemoval -DemoteOperationMasterRole on it, metadata "
                "cleanup on the healthy DC (ntdsutil, or delete its server object in Sites and Services), then "
                "Install-ADDSDomainController again. It comes back under a new invocation ID and pulls everything.",
            ),
            verify=ROLLBACK_VERIFY,
        ),
    ]


FAULT_IDS = ("hr-joiners-drop", "mover-to-finance", "leaver-after-handover", "ou-deleted", "tier0-hygiene",
             "kerberos-spn-duplicate", "stale-credential-lockout", "sysvol-replication-disabled", "usn-rollback")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
