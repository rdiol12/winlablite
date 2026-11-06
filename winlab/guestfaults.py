"""Guest-side fault injection: break things INSIDE a machine, the way they
actually break in production, so a student diagnoses a real symptom.

Where netplan/faults break the network on the fabric, these run inside a guest
over the serial agent and misconfigure the OS itself: a stopped service, a full
disk, an expired password, a skewed clock, wrong DNS. Each is reversible.

Every scenario carries a hint ladder (three hints, from "where to look" to
"the command") and a verify command that prints True once the machine is
healthy again, so the dashboard can grade the student's fix rather than
simply undo the fault for them.

Scenarios are grouped by the OS they apply to. Windows uses PowerShell; Linux
uses sh. The agent already selects the shell per node kind.
"""

from __future__ import annotations

from dataclasses import dataclass

WINDOWS = "windows"
LINUX = "linux"
BOTH = "both"


@dataclass
class GuestFault:
    id: str
    title: str
    os: str
    teaches: str
    symptom: str
    apply: str
    clear: str
    shell: str = "powershell"
    hints: tuple[str, ...] = ()
    verify: str = ""        # prints True when the problem is fixed
    expect: str = "True"
    images: tuple[str, ...] = ()  # Linux flavours it runs on (image ids); () = any of its OS
    roles: tuple[str, ...] = ()   # the machine must carry one of these roles; () = any machine
    host: str = ""          # broken from outside the machine (HOST_BREAKS); apply only explains


def applies_to(fault: "GuestFault", kind: str, image: str = "",
               roles: list[str] | tuple[str, ...] | None = None) -> bool:
    """Whether a scenario can run on a machine of this kind and image: a
    systemd problem needs Ubuntu, an OpenRC one Alpine, the packet-filter
    one the OPNsense appliance. A Windows scenario fits any Windows kind,
    unless it breaks a role (replication needs a domain controller, a full
    scope a DHCP server): then the machine must carry that role. roles=None
    skips that test, for callers that do not know the machine's roles."""
    os = LINUX if kind == "linux" else WINDOWS
    if fault.os not in (os, BOTH):
        return False
    if fault.images and image not in fault.images:
        return False
    return not fault.roles or roles is None or any(r in fault.roles for r in roles)


def for_machine(kind: str, image: str = "", roles: list[str] | None = None) -> list["GuestFault"]:
    return [f for f in SCENARIOS.values() if applies_to(f, kind, image, roles)]


SCENARIOS: dict[str, GuestFault] = {}


def _reg(f: GuestFault) -> None:
    SCENARIOS[f.id] = f


# --- Windows -------------------------------------------------------------

_SQL_TCP = ("$id = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL').MSSQLSERVER; "
            "$tcp = 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\' + $id + '\\MSSQLServer\\SuperSocketNetLib\\Tcp'; ")

_reg(GuestFault(
    id="sql-tcp-disabled",
    roles=("sql",),
    title="SQL Server answers locally but not over the network",
    os=WINDOWS,
    teaches="the protocols a database engine listens on, its error log, and the difference between a service that is up and one that is reachable",
    symptom="applications and sqlcmd on other machines get 'server not found or not accessible' while sqlcmd on the server itself works",
    apply=_SQL_TCP + "Set-ItemProperty -Path $tcp -Name Enabled -Value 0; Restart-Service -Name MSSQLSERVER -Force",
    clear=_SQL_TCP + "Set-ItemProperty -Path $tcp -Name Enabled -Value 1; Restart-Service -Name MSSQLSERVER -Force",
    hints=(
        "Separate 'up' from 'reachable'. On the server, sqlcmd -S . -E -Q \"SELECT @@SERVERNAME\" answers (that is shared memory, "
        "no network). From dc01, Test-NetConnection sql01 -Port 1433 fails. So the engine runs and nothing listens on the port: "
        "Get-NetTCPConnection -LocalPort 1433 -State Listen shows nothing.",
        "An engine logs every protocol it listens on at start-up. Read the error log: Get-Content "
        "\"$env:ProgramFiles\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG\" | Select-String 'listening'. "
        "A healthy server has a line 'Server is listening on [ any <ipv4> 1433 ]'; this one only lists the local shared-memory and named-pipe entries, "
        "so TCP/IP is disabled in the instance's protocols (SQL Server Configuration Manager, SQL Server Network Configuration, Protocols for MSSQLSERVER).",
        "Enable TCP/IP and restart the engine: the setting lives at HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQLServer"
        "\\SuperSocketNetLib\\Tcp, value Enabled = 1 (Set-ItemProperty, or Configuration Manager), then Restart-Service MSSQLSERVER -Force "
        "(the Agent restarts with it). Confirm with Get-NetTCPConnection -LocalPort 1433 -State Listen and the error log's 'listening' line.",
    ),
    verify=_SQL_TCP + "$on = (Get-ItemProperty -Path $tcp).Enabled; $l = Get-NetTCPConnection -LocalPort 1433 -State Listen -ErrorAction SilentlyContinue; ($on -eq 1 -and [bool]$l)",
))

_reg(GuestFault(
    id="exporter-stopped",
    roles=("metrics",),
    title="The dashboard shows 'No data' for one machine",
    os=WINDOWS,
    teaches="reading a monitoring gap from the monitor's side (the target is down) and the machine's side (the exporter service), and why a stopped exporter is not a stopped server",
    symptom="Grafana's lab overview shows this machine as down and every panel for it goes blank, while the machine itself works and answers ping",
    apply="Set-Service -Name 'windows_exporter' -StartupType Disabled; Stop-Service -Name 'windows_exporter' -Force",
    clear="Set-Service -Name 'windows_exporter' -StartupType Automatic; Start-Service -Name 'windows_exporter'",
    hints=(
        "Start from the monitor. On the Grafana machine, open Prometheus at http://<grafana machine>:9090/targets: the "
        "machine's target shows State DOWN with the error (connection refused). 'Refused' means the machine answered "
        "and nothing listens on the port, which is not the same as 'timeout' (a firewall, or the machine is off).",
        "Now the machine's side. Get-Service windows_exporter shows the exporter service Stopped, and "
        "(Get-Service windows_exporter).StartType says Disabled, so a restart would not bring it back either. "
        "Get-NetTCPConnection -LocalPort 9182 -State Listen confirms nothing listens. The server's own services "
        "(DNS, AD) are fine; only the view of it is gone.",
        "Set-Service windows_exporter -StartupType Automatic; Start-Service windows_exporter, then "
        "Invoke-WebRequest http://localhost:9182/metrics -UseBasicParsing answers with the metrics text. Within one "
        "scrape interval the target is UP again and the panels fill. Then write the alert that would have told you: "
        "up == 0 for 2 minutes (the starter rule MachineDown in /etc/prometheus/rules/winlab.yml does this).",
    ),
    verify="$s = Get-Service -Name 'windows_exporter' -ErrorAction SilentlyContinue; $l = Get-NetTCPConnection -LocalPort 9182 -State Listen -ErrorAction SilentlyContinue; ([bool]$s -and $s.Status -eq 'Running' -and $s.StartType -eq 'Automatic' -and [bool]$l)",
))

_reg(GuestFault(
    id="service-stopped",
    title="A critical service is stopped",
    os=WINDOWS,
    teaches="reading service state, dependencies, and the System event log",
    symptom="a role silently stops working; 'the server is up but X doesn't respond'",
    apply="Stop-Service -Name {service} -Force; Set-Service -Name {service} -StartupType Disabled",
    clear="Set-Service -Name {service} -StartupType Automatic; Start-Service -Name {service}",
    hints=(
        "The machine answers ping and RDP, so the OS is up. Something that used to answer on a port does not. "
        "List the services and look for one that should be running: Get-Service | Where-Object Status -ne Running.",
        "Found it stopped? Starting it is half the fix. Check its startup type (Get-Service {service} | Select-Object StartType): "
        "Disabled means it will not survive a reboot, and Start-Service refuses a disabled service.",
        "Set-Service {service} -StartupType Automatic, then Start-Service {service}. Confirm with Get-Service {service}, "
        "and read the System log (Get-WinEvent -LogName System -MaxEvents 20) to see who stopped it.",
    ),
    verify="$s = Get-Service -Name {service}; ($s.Status -eq 'Running' -and $s.StartType -eq 'Automatic')",
))

_reg(GuestFault(
    id="disk-full",
    title="A volume is nearly full",
    os=WINDOWS,
    teaches="finding what ate the disk, cleanup, why services fail to write",
    symptom="logons slow, services fail, 'low disk space'; apps can't write temp files",
    # A forgotten full backup, as a real full disk usually is. The old name is
    # still removed by clear, for a lab broken by an older winlab.
    apply=("New-Item -ItemType Directory -Path 'C:\\ProgramData\\Backup' -Force | Out-Null; "
           "$f='C:\\ProgramData\\Backup\\FULL_nightly_0300.bak'; $fs=New-Object IO.FileStream($f,'Create');"
           "$fs.SetLength((Get-PSDrive C).Free - 200MB); $fs.Close()"),
    clear=("Remove-Item 'C:\\ProgramData\\Backup\\FULL_nightly_0300.bak' -Force -EA SilentlyContinue; "
           "Remove-Item 'C:\\winlab\\balloon.bin' -Force -EA SilentlyContinue"),
    hints=(
        "Get-PSDrive C shows how much is free. When it is a few hundred MB, Windows cannot write its own logs, "
        "profiles or temp files, which is why everything looks broken at once.",
        "Find the big files, not the big folders: Get-ChildItem C:\\ -Recurse -File -EA SilentlyContinue | "
        "Sort-Object Length -Descending | Select-Object -First 10 FullName, Length.",
        "A multi-GB backup file appeared recently under C:\\ProgramData. Delete it (Remove-Item) and check Get-PSDrive C again. "
        "In production, ask what wrote it before you delete it.",
    ),
    verify="((Get-PSDrive C).Free -gt 1GB)",
))

_reg(GuestFault(
    id="password-expired",
    roles=("ad-ds",),
    title="A user's password has expired",
    os=WINDOWS,
    teaches="AD account states, pwdLastSet, why a user can authenticate yesterday but not today",
    symptom="'{user}' cannot log in; 'you must change your password'",
    apply="Set-ADUser -Identity {user} -ChangePasswordAtLogon $true",
    clear="Set-ADUser -Identity {user} -ChangePasswordAtLogon $false",
    hints=(
        "A logon that worked yesterday and fails today with the right password is an account state, not a typo. "
        "Look at the account: Get-ADUser {user} -Properties PasswordExpired, PasswordLastSet, LockedOut, Enabled.",
        "PasswordLastSet is empty (pwdLastSet = 0): the account is flagged 'must change password at next logon'. "
        "A domain-joined PC lets the user change it; a service or a kiosk cannot.",
        "Clear the flag with Set-ADUser {user} -ChangePasswordAtLogon $false, or set a new password and let the user "
        "change it at logon if that is the policy.",
    ),
    verify="-not (Get-ADUser -Identity {user} -Properties PasswordExpired).PasswordExpired",
))

_reg(GuestFault(
    id="account-locked",
    roles=("ad-ds",),
    title="An account is locked out",
    os=WINDOWS,
    teaches="lockout policy, finding the source of bad logons (event 4740)",
    symptom="'{user}' is locked out after failed attempts",
    apply=("1..10 | ForEach-Object { "
           "try{ New-Object DirectoryServices.DirectoryEntry("
           "'LDAP://rootDSE','{user}','wrongpass') | Out-Null }catch{} }"),
    clear="Unlock-ADAccount -Identity {user}",
    hints=(
        "Search-ADAccount -LockedOut lists every locked account. Lockouts come from repeated bad passwords, "
        "often from a device or a service still using an old one, not from the user at the desk.",
        "Unlock-ADAccount {user} fixes the symptom. The cause is in the Security log on the domain controller: "
        "event 4740 names the caller computer.",
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 5 | Format-List. "
        "Unlock the account, then find and fix the source of the bad attempts.",
    ),
    verify="-not (Get-ADUser -Identity {user} -Properties LockedOut).LockedOut",
))

_reg(GuestFault(
    id="time-skew",
    title="The clock is wrong (breaks Kerberos)",
    os=WINDOWS,
    teaches="why a >5-minute skew kills domain auth; w32time troubleshooting",
    symptom="domain logons and replication fail with 'clock skew too great'",
    apply="Set-Date (Get-Date).AddMinutes(20)",
    clear="w32tm /resync /force; Set-Service w32time -StartupType Automatic; Start-Service w32time",
    hints=(
        "Kerberos tickets carry timestamps; more than five minutes of skew between a machine and the DC and every "
        "domain operation fails. Compare clocks: w32tm /stripchart /computer:<dc> /samples:3 /dataonly.",
        "w32tm /query /status shows the source and the last sync. A machine that drifts has a stopped Windows Time "
        "service, a wrong source, or a VM clock nobody disciplines.",
        "Start-Service w32time, then w32tm /resync /force. A domain member should sync from the domain hierarchy "
        "(w32tm /config /syncfromflags:domhier /update). Check w32tm /query /status again.",
    ),
    verify="$o = w32tm /stripchart /computer:{dns} /samples:1 /dataonly 2>&1 | Select-String -Pattern '([+-][0-9.]+)s' | Select-Object -Last 1; "
           "if ($o) { [math]::Abs([double]$o.Matches[0].Groups[1].Value) -lt 120 } else { (Get-Service w32time).Status -eq 'Running' }",
))

_reg(GuestFault(
    id="dns-wrong",
    title="Client DNS points at the wrong server",
    os=WINDOWS,
    teaches="the #1 broken-AD cause: a member that can't resolve SRV records",
    symptom="'domain not found', GPOs don't apply, can't find a DC",
    apply=("Get-NetAdapter | Where-Object Status -eq 'Up' | "
           "Set-DnsClientServerAddress -ServerAddresses 1.2.3.4"),
    clear=("Get-NetAdapter | Where-Object Status -eq 'Up' | "
           "Set-DnsClientServerAddress -ServerAddresses {dns}"),
    hints=(
        "A domain member finds its DC through DNS SRV records. Test exactly that: nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>. "
        "If it fails, the problem is name resolution, whatever the symptom looked like.",
        "Get-DnsClientServerAddress -AddressFamily IPv4 shows which server each adapter asks. A member must ask a "
        "domain DNS server (the DC), never a public resolver and never an address that does not answer.",
        "Set-DnsClientServerAddress -InterfaceIndex <n> -ServerAddresses {dns}, then ipconfig /flushdns and "
        "nltest /dsgetdc:<domain> to prove the DC is found again.",
    ),
    verify="@(Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { "
           "(Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses }) -contains '{dns}'",
))

_reg(GuestFault(
    id="share-removed",
    roles=("file",),
    title="A file share disappeared",
    os=WINDOWS,
    teaches="share vs NTFS permissions, re-creating shares, mapped-drive failures",
    symptom="users' mapped drives are gone; '\\\\server\\{share} not found'",
    # The share's folder is remembered so Fix-for-me puts it back where the
    # file role created it (D:\Shares\Company on a server with a data disk).
    apply=("$s = Get-SmbShare -Name {share} -EA SilentlyContinue; if ($s) { New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "
           "Set-Content -Path 'C:\\winlab\\share-{share}.path' -Value $s.Path }; "
           "Remove-SmbShare -Name {share} -Force -EA SilentlyContinue"),
    clear=("$p = Get-Content -Path 'C:\\winlab\\share-{share}.path' -EA SilentlyContinue; "
           "if (-not $p) { $p = 'C:\\Shares\\{share}' }; New-Item -ItemType Directory -Path $p -Force | Out-Null; "
           "New-SmbShare -Name {share} -Path $p -ChangeAccess 'Authenticated Users' -EA SilentlyContinue"),
    hints=(
        "'Network path not found' with the server reachable means the share name is gone, not the files. "
        "Get-SmbShare on the server lists what is published; the folder is still on disk.",
        "A share has two permission layers: the share ACL (Get-SmbShareAccess) and the NTFS ACL (Get-Acl). "
        "Re-creating the share restores the first; the second was never lost.",
        "New-SmbShare -Name {share} -Path <folder> -ChangeAccess 'Authenticated Users' (or the group that should "
        "have it), then test from a client with Test-Path \\\\<server>\\{share}.",
    ),
    verify="[bool](Get-SmbShare -Name {share} -ErrorAction SilentlyContinue)",
))

_reg(GuestFault(
    id="firewall-blocks-rdp",
    title="RDP is blocked by the firewall",
    os=WINDOWS,
    teaches="distinguishing 'service down' from 'port filtered'; firewall rule triage",
    symptom="can't RDP in, but ping works and the server is up",
    # Named like a hardening rule someone left behind; clear also removes the
    # rule an older winlab named.
    apply=("New-NetFirewallRule -DisplayName 'Remote Desktop - Restrict (TCP-In)' -Group 'Security Baseline' "
           "-Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Any"),
    clear=("Remove-NetFirewallRule -DisplayName 'Remote Desktop - Restrict (TCP-In)' -EA SilentlyContinue; "
           "Remove-NetFirewallRule -DisplayName 'winlab-break-rdp' -EA SilentlyContinue"),
    hints=(
        "Ping works, so the host is up. Test the port itself from another machine: Test-NetConnection <server> -Port 3389. "
        "A timeout with the service running means something filters the port.",
        "Is the service listening? Get-NetTCPConnection -LocalPort 3389 -State Listen. If yes, the firewall is the "
        "suspect: Get-NetFirewallRule -Direction Inbound -Enabled True -Action Block | Get-NetFirewallPortFilter ... .",
        "Find the block rule for TCP 3389 (Get-NetFirewallPortFilter | Where-Object LocalPort -eq 3389 | Get-NetFirewallRule) "
        "and remove or disable it. Block rules win over allow rules, so an extra allow rule changes nothing.",
    ),
    verify="-not (Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -EA SilentlyContinue | "
           "Get-NetFirewallPortFilter | Where-Object { $_.Protocol -eq 'TCP' -and \"$($_.LocalPort)\" -match '(^|,)3389($|,)' })",
))

_reg(GuestFault(
    id="high-cpu",
    title="A runaway process pins the CPU",
    os=WINDOWS,
    teaches="finding the offending process, Task Manager / Get-Process, why the box is sluggish",
    symptom="everything is slow; CPU at 100%",
    apply=("Start-Process powershell -ArgumentList "
           "'-WindowStyle Hidden -Command while($true){1}' -WindowStyle Hidden"),
    clear="Get-Process powershell | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -EA SilentlyContinue",
    hints=(
        "Measure before you guess: Get-Counter '\\Processor(_Total)\\% Processor Time'. Then rank processes by CPU "
        "time: Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, CPU.",
        "A process with a huge and climbing CPU value and no window is the one. Find out what started it before "
        "killing it: Get-CimInstance Win32_Process -Filter \"ProcessId=<id>\" | Select-Object CommandLine, ParentProcessId.",
        "Stop-Process -Id <id> -Force. Watch Get-Counter again to confirm the CPU settles. In production, the parent "
        "and the command line tell you whether it will come back.",
    ),
    verify="-not (Get-Process powershell -EA SilentlyContinue | Where-Object { $_.Id -ne $PID -and $_.CPU -gt 10 -and $_.MainWindowHandle -eq 0 })",
))

_reg(GuestFault(
    id="driver-missing",
    title="The network card has no working driver",
    os=WINDOWS,
    teaches="Device Manager, Get-PnpDevice, hardware ids, the driver store and pnputil, enabling a device",
    symptom="the machine cannot reach anything; the adapter shows an error or is gone from ipconfig",
    # The Intel 82574L (or the virtio card on a machine built with it) is
    # disabled the way an administrator would do it by mistake: Plug and
    # Play keeps the device, the driver, and the disabled state across reboots.
    apply=("Get-PnpDevice -Class Net -PresentOnly | Where-Object { $_.InstanceId -like 'PCI\\*' } | "
           "Disable-PnpDevice -Confirm:$false"),
    clear=("Get-PnpDevice -Class Net | Where-Object { $_.InstanceId -like 'PCI\\*' } | "
           "Enable-PnpDevice -Confirm:$false"),
    hints=(
        "ipconfig shows no adapter with an address, and ping fails before DNS gets a chance. Look at the hardware, "
        "not the network: Get-PnpDevice -Class Net (or Device Manager, Network adapters). Status OK is what you want.",
        "The PCI network card (the Intel 82574L, hardware id PCI\\VEN_8086&DEV_10D3) has a status of Error, and in "
        "Device Manager a down arrow: it is disabled, with its driver in place. Get-PnpDevice -Class Net -Status Error.",
        "Enable it: Get-PnpDevice -Class Net -Status Error | Enable-PnpDevice -Confirm:$false, or right-click, Enable "
        "device. Had the driver been gone instead (problem code 28), pnputil /add-driver <inf> from the DRIVERS stick "
        "would put one in the store and Plug and Play would bind it.",
    ),
    verify=("$pci = Get-PnpDevice -Class Net -PresentOnly | Where-Object { $_.InstanceId -like 'PCI\\*' }; "
            "($pci | Where-Object Status -eq 'OK' | Measure-Object).Count -ge 1 -and "
            "-not ($pci | Where-Object Status -ne 'OK')"),
))


# --- Windows: identity, name resolution and policy -------------------------

# The lab credential, rebuilt from the facts file every Windows machine
# carries (the DSC builders do the same); the domain side of a fault needs it.
_LAB_CRED = ("$f = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json; "
             "$cred = New-Object System.Management.Automation.PSCredential("
             "('{0}\\Administrator' -f $f.lab.netbios), "
             "(ConvertTo-SecureString -String $f.lab.admin_password -AsPlainText -Force)); ")

_reg(GuestFault(
    id="secure-channel-broken",
    roles=("domain-join",),
    title="The trust relationship with the domain failed",
    os=WINDOWS,
    teaches="the machine account and its password, the secure channel a member keeps with a DC, and repairing it without leaving the domain",
    symptom="domain users cannot sign in to this machine ('the trust relationship between this workstation and the primary domain failed') while local accounts still can, and the machine reaches the DC fine",
    # The computer object's password is reset on the domain side only, the way a
    # restored checkpoint or an old clone leaves a member that the DC no longer knows.
    apply=(_LAB_CRED
           + "$dn = ([adsisearcher]\"(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)`$))\").FindOne().Properties.distinguishedname[0]; "
           "$e = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$dn\", $cred.UserName, $cred.GetNetworkCredential().Password); "
           "$e.Invoke('SetPassword', ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N').ToUpper())); "
           "klist -li 0x3e7 purge | Out-Null"),
    clear=_LAB_CRED + "Test-ComputerSecureChannel -Repair -Credential $cred | Out-Null",
    hints=(
        "A domain logon fails and a local one works, so the machine and the network are fine and the domain no longer "
        "accepts this computer. Ask it: Test-ComputerSecureChannel -Verbose (or nltest /sc_verify:{domain}). False means "
        "the secure channel, the authenticated link a member keeps with a DC, is broken.",
        "Every member has a computer account with a password it changes itself every 30 days; the member and the DC each "
        "keep a copy. Restore an old checkpoint, revert a VM, or reset the account on the DC and the copies differ. The DC's "
        "System log has NETLOGON event 5722 or 3210 naming this machine.",
        "Repair it in place, no unjoin, no reboot: Test-ComputerSecureChannel -Repair -Credential (Get-Credential CORP\\Administrator) "
        "while signed in with a local admin (or Reset-ComputerMachinePassword -Credential ...). Then Test-ComputerSecureChannel "
        "says True and domain logons work again. Unjoining and rejoining also works, but loses the computer's group memberships.",
    ),
    verify="[bool](Test-ComputerSecureChannel)",
))

_reg(GuestFault(
    id="replication-disabled",
    roles=("ad-ds",),
    title="This domain controller stopped taking changes from its partners",
    os=WINDOWS,
    teaches="AD replication health with repadmin and dcdiag, DSA options, and how a DC can be up and serving stale data",
    symptom="a user created or a password changed on another DC never shows up on this one; logons that hit this DC use old passwords while the other DC is current",
    apply="repadmin /options $env:COMPUTERNAME +DISABLE_INBOUND_REPL | Out-Null",
    clear="repadmin /options $env:COMPUTERNAME -DISABLE_INBOUND_REPL | Out-Null",
    hints=(
        "Measure replication before guessing: repadmin /replsummary shows every DC's failures and the largest delta, and "
        "repadmin /showrepl on this DC lists each inbound partner and the last attempt. Create a test user on the other DC and "
        "look for it here with Get-ADUser -Server $env:COMPUTERNAME.",
        "repadmin /showrepl starts with the DSA options, and this DC reports DISABLE_INBOUND_REPL: someone turned inbound "
        "replication off (it is done before maintenance, and forgotten). dcdiag /test:replications says the same in its own words.",
        "repadmin /options $env:COMPUTERNAME -DISABLE_INBOUND_REPL, then repadmin /syncall /AdeP to pull the changes now, "
        "and repadmin /replsummary again: zero failures and a delta of minutes.",
    ),
    verify="$o = (repadmin /options $env:COMPUTERNAME) -join ' '; -not ($o -match 'DISABLE_(INBOUND|OUTBOUND)_REPL')",
))

_reg(GuestFault(
    id="gpo-filtered-out",
    roles=("gpo",),
    title="A Group Policy object no longer applies to anyone",
    os=WINDOWS,
    teaches="GPO security filtering, why every GPO must be readable by the computer (MS16-072), and reading gpresult",
    symptom="the mapped company drive is gone for every user at sign-in, nobody changed the GPO's settings, and gpupdate reports success",
    apply=("Import-Module GroupPolicy; "
           "Set-GPPermission -Name '{gpo}' -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel None "
           "-Replace -WarningAction SilentlyContinue | Out-Null"),
    clear=("Import-Module GroupPolicy; "
           "Set-GPPermission -Name '{gpo}' -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoApply "
           "-Replace -WarningAction SilentlyContinue | Out-Null"),
    hints=(
        "Ask the client which policies it got and which it skipped: on a workstation, gpresult /r /scope:user lists applied "
        "GPOs and, below them, the ones 'filtered out' with the reason. The drive map GPO is there with 'Denied (Security)'.",
        "Security filtering decides who applies a GPO, and since the 2016 hardening (MS16-072) user policy is read with the "
        "computer's account, so the computer must be able to read it too. On the DC: Get-GPPermission -Name '{gpo}' -All. "
        "Authenticated Users is gone from the list.",
        "Give it back: Set-GPPermission -Name '{gpo}' -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoApply. "
        "To narrow a GPO to a group instead, give that group GpoApply and leave Domain Computers with GpoRead. Then gpupdate /force "
        "on the client and gpresult /r again.",
    ),
    verify=("Import-Module GroupPolicy; $ok = $false; "
            "foreach ($t in 'Authenticated Users', 'Domain Computers') { "
            "$p = Get-GPPermission -Name '{gpo}' -TargetName $t -TargetType Group -ErrorAction SilentlyContinue; "
            "if ($p -and @('GpoRead', 'GpoApply', 'GpoEdit', 'GpoEditDeleteModifySecurity') -contains [string]$p.Permission) { $ok = $true } }; $ok"),
))

_NETLOGON = "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters'"

_reg(GuestFault(
    id="srv-records-missing",
    roles=("ad-ds",),
    title="The domain controller's SRV records are gone from DNS",
    os=WINDOWS,
    teaches="how members find a DC (the DC locator and SRV records), who registers them (Netlogon), and dcdiag's DNS tests",
    symptom="new sign-ins and domain joins fail with 'an Active Directory domain controller could not be contacted' although the DC is up, answers ping and its DNS server answers other names",
    apply=("Set-ItemProperty -Path " + _NETLOGON + " -Name UseDynamicDns -Value 0 -Type DWord; "
           "foreach ($z in '{domain}', '_msdcs.{domain}') { "
           "Get-DnsServerResourceRecord -ZoneName $z -RRType Srv -ErrorAction SilentlyContinue | "
           "Where-Object { $_.RecordData.DomainName -like \"$($env:COMPUTERNAME).*\" } | "
           "Remove-DnsServerResourceRecord -ZoneName $z -Force }"),
    clear=("Remove-ItemProperty -Path " + _NETLOGON + " -Name UseDynamicDns -ErrorAction SilentlyContinue; "
           "Restart-Service -Name Netlogon -Force; nltest /dsregdns | Out-Null"),
    hints=(
        "Ask DNS the question a member asks: nslookup -type=SRV _ldap._tcp.dc._msdcs.{domain}. The server answers, with no record "
        "for this DC. nltest /dsgetdc:{domain} from a member fails the same way. The name of the DC still resolves; only the "
        "service records are missing.",
        "A DC registers its SRV records itself: Netlogon writes the list in %SystemRoot%\\System32\\config\\netlogon.dns and "
        "registers it at start and every 24 hours. dcdiag /test:dns /DnsRecordRegistration says they are missing. Look at why "
        "Netlogon does not put them back: Get-ItemProperty " + _NETLOGON.strip("'") + " shows UseDynamicDns = 0.",
        "Remove-ItemProperty -Path " + _NETLOGON.strip("'") + " -Name UseDynamicDns, then Restart-Service Netlogon (or "
        "nltest /dsregdns) to register now. nslookup -type=SRV again, and dcdiag /test:dns passes.",
    ),
    verify=("$r = Get-DnsServerResourceRecord -ZoneName '_msdcs.{domain}' -Name '_ldap._tcp.dc' -RRType Srv -ErrorAction SilentlyContinue | "
            "Where-Object { $_.RecordData.DomainName -like \"$($env:COMPUTERNAME).*\" }; "
            "$v = (Get-ItemProperty -Path " + _NETLOGON + ").UseDynamicDns; "
            "[bool]$r -and ($v -ne 0)"),
))

_HTTPS = "'IIS:\\SslBindings\\0.0.0.0!443'"

_reg(GuestFault(
    id="https-cert-expired",
    roles=("iis",),
    title="The web server's certificate has expired",
    os=WINDOWS,
    teaches="certificate validity, what a binding points at, renewing from the enterprise CA, and watching expiry before users do",
    symptom="every browser shows a certificate error for the HTTPS site (expired); plain HTTP and the server itself are fine",
    apply=("Import-Module WebAdministration; New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "
           "$b = Get-Item " + _HTTPS + " -ErrorAction SilentlyContinue; if ($b) { Set-Content -Path 'C:\\winlab\\https-thumb.txt' -Value $b.Thumbprint }; "
           "$fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName; "
           "$c = New-SelfSignedCertificate -DnsName $fqdn -CertStoreLocation 'Cert:\\LocalMachine\\My' "
           "-NotBefore (Get-Date).AddDays(-400) -NotAfter (Get-Date).AddDays(-2) -FriendlyName 'web (last year)'; "
           "if ($b) { Remove-Item " + _HTTPS + " }; New-Item " + _HTTPS + " -Value $c | Out-Null"),
    clear=("Import-Module WebAdministration; $t = Get-Content -Path 'C:\\winlab\\https-thumb.txt' -ErrorAction SilentlyContinue; "
           "$c = $null; if ($t) { $c = Get-Item -Path \"Cert:\\LocalMachine\\My\\$t\" -ErrorAction SilentlyContinue }; "
           "if (-not $c) { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName; "
           "$c = New-SelfSignedCertificate -DnsName $fqdn -CertStoreLocation 'Cert:\\LocalMachine\\My' }; "
           "Remove-Item " + _HTTPS + " -ErrorAction SilentlyContinue; New-Item " + _HTTPS + " -Value $c | Out-Null"),
    hints=(
        "Read the certificate the site really presents, not the one you think it has: Get-Item IIS:\\SslBindings\\0.0.0.0!443 gives "
        "the thumbprint, and Get-Item Cert:\\LocalMachine\\My\\<thumbprint> | Format-List Subject, NotBefore, NotAfter its dates.",
        "NotAfter is in the past. The store may still hold a valid certificate (Get-ChildItem Cert:\\LocalMachine\\My | "
        "Where-Object NotAfter -gt (Get-Date)): renewing a certificate never moves the binding, so a site keeps serving the old one.",
        "Bind a valid certificate: Remove-Item IIS:\\SslBindings\\0.0.0.0!443, then Get-Item Cert:\\LocalMachine\\My\\<good thumbprint> | "
        "New-Item IIS:\\SslBindings\\0.0.0.0!443. With the enterprise CA, request a fresh one first: Get-Certificate -Template WebServer "
        "-DnsName <fqdn> -CertStoreLocation Cert:\\LocalMachine\\My. Then find the next one before it bites: Get-ChildItem "
        "Cert:\\LocalMachine\\My | Where-Object NotAfter -lt (Get-Date).AddDays(30).",
    ),
    verify=("Import-Module WebAdministration; $t = (Get-Item " + _HTTPS + " -ErrorAction SilentlyContinue).Thumbprint; "
            "$c = $null; if ($t) { $c = Get-Item -Path \"Cert:\\LocalMachine\\My\\$t\" -ErrorAction SilentlyContinue }; "
            "[bool]($c -and $c.NotAfter -gt (Get-Date).AddDays(7) -and $c.NotBefore -lt (Get-Date))"),
))

_reg(GuestFault(
    id="dhcp-scope-full",
    roles=("dhcp",),
    title="The DHCP scope has run out of addresses",
    os=WINDOWS,
    teaches="scope statistics, lease duration, finding who holds the leases, and the difference between renewing and getting a new lease",
    symptom="machines already on the network keep working, but a new or rebuilt PC gets a 169.254 address and no network",
    # Every free address is taken by a burst of guest devices on long leases.
    apply=("$free = @(Get-DhcpServerv4FreeIPAddress -ScopeId {scope} -NumAddress 1024 -WarningAction SilentlyContinue); "
           "$i = 0; foreach ($ip in $free) { $i++; "
           "$mac = '02-BD-00-00-{0:X2}-{1:X2}' -f [math]::Floor($i / 256), ($i % 256); "
           "Add-DhcpServerv4Lease -ScopeId {scope} -IPAddress $ip -ClientId $mac -HostName ('byod-{0:D3}' -f $i) "
           "-LeaseExpiryTime (Get-Date).AddDays(8) }"),
    clear=("Get-DhcpServerv4Lease -ScopeId {scope} | Where-Object { $_.HostName -like 'byod-*' } | "
           "Remove-DhcpServerv4Lease"),
    hints=(
        "A 169.254 address means no DHCP answer at all. Ask the server how full it is: Get-DhcpServerv4ScopeStatistics "
        "-ScopeId {scope} shows PercentageInUse 100 and Free 0, and the DHCP-Server Operational log on the server says the scope is full.",
        "Who holds the leases? Get-DhcpServerv4Lease -ScopeId {scope} | Sort-Object HostName | Format-Table IPAddress, ClientId, "
        "HostName, LeaseExpiryTime. Dozens of byod-NNN devices with leases of eight days: guests' phones that came once and left. "
        "The lease duration (Get-DhcpServerv4Scope -ScopeId {scope}) keeps their addresses long after they have gone.",
        "Free the stale leases: Get-DhcpServerv4Lease -ScopeId {scope} | Where-Object HostName -like 'byod-*' | Remove-DhcpServerv4Lease. "
        "Then stop it coming back: a shorter lease (Set-DhcpServerv4Scope -ScopeId {scope} -LeaseDuration 1.00:00:00), a bigger "
        "range, or guests on their own segment. ipconfig /renew on the PC that failed.",
    ),
    verify="[bool]((Get-DhcpServerv4ScopeStatistics -ScopeId {scope}).Free -ge 10)",
))

_reg(GuestFault(
    id="print-queue-stuck",
    roles=("printer",),
    title="Print jobs pile up and nothing prints",
    os=WINDOWS,
    teaches="print queues and jobs, the paused state, clearing a queue, and when (and when not) to restart the spooler",
    symptom="users' documents go into the {printer} queue and never come out; the print spooler is running and the printer is shared as before",
    apply=("$p = Get-CimInstance -ClassName Win32_Printer -Filter \"Name='{printer}'\"; "
           "Invoke-CimMethod -InputObject $p -MethodName Pause | Out-Null; "
           "1..5 | ForEach-Object { \"winlab test page $_\" | Out-Printer -Name '{printer}' }"),
    clear=("Get-PrintJob -PrinterName '{printer}' -ErrorAction SilentlyContinue | Remove-PrintJob; "
           "$p = Get-CimInstance -ClassName Win32_Printer -Filter \"Name='{printer}'\"; "
           "Invoke-CimMethod -InputObject $p -MethodName Resume | Out-Null"),
    hints=(
        "Start from the queue, not the spooler: Get-PrintJob -PrinterName {printer} lists jobs waiting, and "
        "Get-Printer -Name {printer} | Format-List PrinterStatus, JobCount says what the queue itself is doing.",
        "PrinterStatus is Paused: someone paused the queue (Print Management, or right-click > Pause Printing), so the spooler "
        "accepts jobs and holds them. Restarting the spooler would not resume it; it only drops jobs on every queue of the server.",
        "Resume it: Get-CimInstance Win32_Printer -Filter \"Name='{printer}'\" | Invoke-CimMethod -MethodName Resume, and clear what "
        "will never print: Get-PrintJob -PrinterName {printer} | Remove-PrintJob. The heavy fix for a hung spooler is Stop-Service "
        "Spooler, delete C:\\Windows\\System32\\spool\\PRINTERS\\*, Start-Service Spooler: keep it for when a job will not delete.",
    ),
    verify=("$p = Get-Printer -Name '{printer}' -ErrorAction SilentlyContinue; "
            "$j = @(Get-PrintJob -PrinterName '{printer}' -ErrorAction SilentlyContinue); "
            "[bool]($p -and ([string]$p.PrinterStatus -notmatch 'Paused') -and $j.Count -eq 0)"),
))

_PROFILES = "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'"
_THEIRS = "Where-Object { [string](Get-ItemProperty -Path $_.PSPath).ProfileImagePath -match '\\\\{user}(\\.[^\\\\]+)?$' }"

_reg(GuestFault(
    id="temp-profile",
    title="A user signs in to a temporary profile",
    os=WINDOWS,
    teaches="the user profile, the ProfileList registry key that maps a SID to its folder, and repairing a profile without losing the user's files",
    symptom="{user} signs in and gets 'You've been signed in with a temporary profile': an empty desktop, no files, settings gone at sign-out",
    # Windows renames a profile's key to <SID>.bak when it judges it damaged; then
    # it cannot find the profile and builds a throwaway one at every sign-in.
    apply=("$k = Get-ChildItem -Path " + _PROFILES + " | " + _THEIRS + " | Select-Object -First 1; "
           "if (-not $k) { throw '{user} has never signed in to this machine: sign in as {user} once, sign out, then break it' }; "
           "Rename-Item -Path $k.PSPath -NewName ($k.PSChildName + '.bak')"),
    clear=("$pl = " + _PROFILES + "; "
           "foreach ($b in @(Get-ChildItem -Path $pl | Where-Object { $_.PSChildName -like '*.bak' } | " + _THEIRS + ")) { "
           "$sid = $b.PSChildName -replace '\\.bak$', ''; "
           "if (Test-Path -Path \"$pl\\$sid\") { Remove-Item -Path \"$pl\\$sid\" -Recurse -Force }; "
           "Rename-Item -Path $b.PSPath -NewName $sid; "
           "Set-ItemProperty -Path \"$pl\\$sid\" -Name State -Value 0; "
           "Set-ItemProperty -Path \"$pl\\$sid\" -Name RefCount -Value 0 -ErrorAction SilentlyContinue }"),
    hints=(
        "The account is fine (it signs in); its profile is not. The Application log has User Profile Service events 1511 or 1515, "
        "and Get-CimInstance Win32_UserProfile | Select-Object LocalPath, Status shows the temporary one. C:\\Users\\{user} is "
        "still on disk with every file in it: do not delete it.",
        "Windows maps each SID to its profile folder under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList. "
        "Find the user's SID ((New-Object System.Security.Principal.NTAccount('{user}')).Translate([System.Security.Principal.SecurityIdentifier]).Value): "
        "its key ends in .bak, so Windows does not find the profile and builds a temporary one at every sign-in.",
        "With {user} signed out: delete a key for the same SID without .bak if one exists, rename <SID>.bak to <SID>, and set its "
        "State and RefCount values to 0. Sign in again and the old desktop is back.",
    ),
    verify=("$k = @(Get-ChildItem -Path " + _PROFILES + " | " + _THEIRS + "); "
            "($k.Count -ge 1) -and -not ($k | Where-Object { $_.PSChildName -like '*.bak' }) -and "
            "-not ($k | Where-Object { ([int](Get-ItemProperty -Path $_.PSPath).State -band 0x800) })"),
))

_HOSTS = "\"$env:SystemRoot\\System32\\drivers\\etc\\hosts\""

_reg(GuestFault(
    id="wsus-client-cannot-reach",
    roles=("domain-join",),
    title="Windows Update cannot reach the update server",
    os=WINDOWS,
    teaches="how a client finds its WSUS server (policy, then name resolution), the hosts file that overrides DNS, and the Windows Update log",
    symptom="Settings > Windows Update fails with 0x8024401c or 0x80072ee2 and the machine stops reporting to WSUS; other machines update fine and this one browses the network normally",
    # A forgotten hosts-file line from a server move pins the WSUS name to an old address.
    apply=("Add-Content -Path " + _HOSTS + " -Value \"`r`n10.255.255.1  {wsus} {wsus}.{domain}  # old update server\" -Encoding ASCII; "
           "ipconfig /flushdns | Out-Null"),
    clear=("$h = " + _HOSTS + "; Set-Content -Path $h -Value (Get-Content -Path $h | Where-Object { $_ -notmatch '# old update server' }) "
           "-Encoding ASCII; ipconfig /flushdns | Out-Null"),
    hints=(
        "The policy tells the client where to go: (Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate).WUServer. "
        "Test exactly that address and port: Test-NetConnection {wsus} -Port 8530. It fails here and works from another machine.",
        "Compare the two resolvers: Resolve-DnsName {wsus} asks DNS and gets the right address; Test-NetConnection and the update "
        "client use the full resolver, where the hosts file wins over DNS. Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts. "
        "(Get-WindowsUpdateLog writes the client's log to the desktop: the failing URL is in it.)",
        "Remove the stale {wsus} line from C:\\Windows\\System32\\drivers\\etc\\hosts (an elevated editor), ipconfig /flushdns, "
        "then UsoClient StartScan: the machine reports to WSUS again.",
    ),
    verify=("$h = @(Get-Content -Path " + _HOSTS + " | Where-Object { $_ -match '^\\s*[^#\\s].*\\b{wsus}\\b' }); "
            "$c = New-Object System.Net.Sockets.TcpClient; "
            "try { $ok = $c.ConnectAsync('{wsus}', 8530).Wait(5000) } catch { $ok = $false }; $c.Close(); "
            "($h.Count -eq 0) -and $ok"),
))

# The secrets the simulated intruder uses are made up on the guest at run time.
_RANDOM_SECRET = ("ConvertTo-SecureString -AsPlainText -Force "
                  "([guid]::NewGuid().ToString('N').ToUpper() + [guid]::NewGuid().ToString('N'))")

_reg(GuestFault(
    id="attack-in-the-logs",
    roles=("ad-ds",),
    title="Someone got in overnight: find what they did in the event logs",
    os=WINDOWS,
    teaches="reading the Security and System logs as evidence: a password spray, a new account, a privileged group change and a new service, then cleaning up",
    symptom="the security team saw a burst of failed sign-ins on this domain controller overnight, and someone thinks a new admin account appeared; nothing is broken, which is the problem",
    # A password spray against the real users, then persistence: an account
    # added to Domain Admins and a service that would start a program.
    apply=("$base = (Get-ADDomain).DistinguishedName; "
           "Get-ADUser -Filter 'Enabled -eq $true' -SearchBase ('OU=Corp,' + $base) | Select-Object -First 8 | ForEach-Object { "
           "$bad = [guid]::NewGuid().ToString(); "
           "$de = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$env:COMPUTERNAME\", \"$env:USERDOMAIN\\$($_.SamAccountName)\", $bad); "
           "try { $de.RefreshCache() } catch { } }; "
           "New-ADUser -Name 'svc-sync' -SamAccountName 'svc-sync' -Description 'sync service' -Enabled $true "
           "-AccountPassword (" + _RANDOM_SECRET + "); "
           "Add-ADGroupMember -Identity 'Domain Admins' -Members 'svc-sync'; "
           "New-Service -Name 'WinTelemetryHelper' -DisplayName 'Windows Telemetry Helper' "
           "-BinaryPathName 'C:\\ProgramData\\Microsoft\\Crypto\\wth.exe -k netsvcs' -StartupType Manual | Out-Null"),
    clear=("Get-ADUser -Filter \"SamAccountName -eq 'svc-sync'\" | Remove-ADUser -Confirm:$false; "
           "if (Get-Service -Name 'WinTelemetryHelper' -ErrorAction SilentlyContinue) { sc.exe delete WinTelemetryHelper | Out-Null }; "
           "Remove-Item -Path 'C:\\winlab\\incident.txt' -ErrorAction SilentlyContinue"),
    hints=(
        "Work from the evidence, newest first. On the domain controller: Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 4728, 4732, 4756 } "
        "lists accounts created and members added to security groups; Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } "
        "lists services installed.",
        "Read the messages, not just the ids: Get-WinEvent ... | Format-List TimeCreated, Message. One account was created and put in "
        "Domain Admins minutes after a burst of failed sign-ins (4625, 4771 or 4776 for many different users from one place: a spray). "
        "A service with an odd path under C:\\ProgramData was installed at the same time.",
        "Contain and record: Remove-ADGroupMember 'Domain Admins' svc-sync and Disable-ADAccount svc-sync (or delete it), "
        "sc.exe delete WinTelemetryHelper, and write C:\\winlab\\incident.txt naming the account and the service. In real life: "
        "reset the sprayed users' passwords and krbtgt's twice, and find how the intruder got the rights to do this.",
    ),
    verify=("$u = Get-ADUser -Filter \"SamAccountName -eq 'svc-sync'\" -Properties MemberOf -ErrorAction SilentlyContinue; "
            "$da = (Get-ADGroup 'Domain Admins').DistinguishedName; "
            "$okU = (-not $u) -or ((-not $u.Enabled) -and ($u.MemberOf -notcontains $da)); "
            "$okS = -not (Get-Service -Name 'WinTelemetryHelper' -ErrorAction SilentlyContinue); "
            "$t = [string](Get-Content -Path 'C:\\winlab\\incident.txt' -Raw -ErrorAction SilentlyContinue); "
            "[bool]($okU -and $okS -and $t -match 'svc-sync' -and $t -match 'WinTelemetryHelper')"),
))


# --- Linux ---------------------------------------------------------------

_reg(GuestFault(
    id="linux-service-stopped",
    images=("alpine",),
    title="A daemon is stopped",
    os=LINUX,
    teaches="rc-service/systemctl status, reading logs, restarting daemons",
    symptom="a service stops answering",
    apply="rc-service {service} stop",
    clear="rc-service {service} start",
    shell="sh",
    hints=(
        "rc-status shows every service and its state; the one that stopped answering is 'stopped' or 'crashed'.",
        "rc-service <name> status, then its log under /var/log, tells you whether it crashed or was stopped.",
        "rc-service <name> start, and rc-update add <name> if it must come back at boot.",
    ),
    verify="rc-service {service} status >/dev/null 2>&1 && echo True || echo False",
))

_reg(GuestFault(
    id="systemd-service-stopped",
    images=("ubuntu",),
    title="A systemd service is stopped ({unit})",
    os=LINUX,
    teaches="systemctl status and is-active, journalctl -u, restarting and re-enabling a unit",
    symptom="the service stops answering: nothing arrives on the syslog server, or a daemon's port is closed",
    apply="systemctl stop {unit}",
    clear="systemctl start {unit}",
    shell="sh",
    hints=(
        "systemctl --failed and systemctl list-units --type=service show every service and its state; the one that stopped answering is 'inactive' or 'failed'.",
        "systemctl status {unit} and journalctl -u {unit} -n 50 tell you whether it crashed, was stopped, or refuses its configuration.",
        "systemctl start {unit}; systemctl enable {unit} if it must come back at boot; a listener shows in ss -lntup.",
    ),
    verify="systemctl is-active {unit} >/dev/null 2>&1 && echo True || echo False",
))

_reg(GuestFault(
    id="linux-disk-full",
    images=("alpine", "ubuntu"),
    title="Root filesystem is full",
    os=LINUX,
    teaches="df/du, finding the big files, why writes fail",
    symptom="'No space left on device'",
    apply="mkdir -p /var/backups && dd if=/dev/zero of=/var/backups/rootfs-full.img bs=1M count=100000 2>/dev/null || true",
    clear="rm -f /var/backups/rootfs-full.img /winlab-balloon",
    shell="sh",
    hints=(
        "df -h / shows the root filesystem at 100%. Writes fail, logs stop, package installs break.",
        "du -xh / --max-depth=1 2>/dev/null | sort -h finds the directory; find / -xdev -size +500M finds the file.",
        "Remove the file (rm) and check df -h again. Ask what created it before deleting it in production.",
    ),
    verify="[ \"$(df -P / | awk 'NR==2{print $4}')\" -gt 500000 ] && echo True || echo False",
))

_reg(GuestFault(
    id="linux-dns-wrong",
    images=("alpine", "ubuntu"),
    title="resolv.conf points nowhere",
    os=LINUX,
    teaches="name resolution, resolv.conf, nsswitch",
    symptom="hostnames don't resolve; 'Temporary failure in name resolution'",
    apply="cp /etc/resolv.conf /etc/resolv.conf.bak; echo 'nameserver 1.2.3.4' > /etc/resolv.conf",
    clear="mv /etc/resolv.conf.bak /etc/resolv.conf 2>/dev/null || true",
    shell="sh",
    hints=(
        "ping an IP address first. If that works and a name does not, the problem is resolution, not the network.",
        "cat /etc/resolv.conf: the nameserver line must point at a server that answers. nslookup <name> <server> tests one directly.",
        "Put the domain's DNS server back in /etc/resolv.conf (nameserver {dns}) and test again.",
    ),
    verify="grep -q 'nameserver {dns}' /etc/resolv.conf && echo True || echo False",
))


_reg(GuestFault(
    id="pf-disabled",
    images=("opnsense",),
    title="The firewall's packet filter is off",
    os=LINUX,
    teaches="what a firewall does when its filter engine stops: it becomes a router that forwards "
            "everything, NAT and port forwards included, and the GUI still looks fine",
    symptom="the office cannot reach the Internet any more (nothing is translated, so the replies "
            "never come back), the published DMZ web server is gone from the Internet (the WAN "
            "address answers with the firewall's own web interface instead), and rules that blocked "
            "DMZ traffic no longer block it; the firewall pings, its GUI opens and its rules and "
            "interfaces all look unchanged",
    apply="pfctl -d >/dev/null 2>&1; echo disabled",
    clear="pfctl -e >/dev/null 2>&1; echo enabled",
    shell="sh",
    hints=(
        "Nothing in the rules changed. Ask the engine itself: on the firewall, pfctl -si shows "
        "'Status: Enabled' or 'Status: Disabled' on its first line.",
        "pfctl -sn (NAT rules) and pfctl -sr (filter rules) still list everything: the rules are "
        "loaded, the filter just is not running them.",
        "pfctl -e turns the packet filter back on; OPNsense also re-enables it when you apply a "
        "firewall change in the GUI or reboot.",
    ),
    verify="pfctl -si 2>/dev/null | head -1 | grep -c 'Status: Enabled'",
    expect="1",
))


# Wake-on-LAN (winlab/power.py): QEMU's card keeps no such setting, so winlab
# reads Windows' own one while the machine runs and a card set to Disabled
# stays asleep when its magic packet arrives, as on a real PC.
_reg(GuestFault(
    id="wol-off",
    title="The PC does not wake on LAN",
    os=WINDOWS,
    teaches="what lets a powered-off PC wake on a magic packet: the network card's own Wake on Magic Packet "
            "setting (Device Manager, Get-NetAdapterPowerManagement), and that the packet must arrive in its VLAN",
    symptom="every other PC wakes when its magic packet is sent; this one stays off, although the packet goes "
            "to the right MAC address from a machine on its own network",
    apply=("Get-NetAdapter -Physical | ForEach-Object { Set-NetAdapterPowerManagement -Name $_.Name "
           "-WakeOnMagicPacket Disabled -ErrorAction SilentlyContinue }; 'disabled'"),
    clear=("Get-NetAdapter -Physical | ForEach-Object { Set-NetAdapterPowerManagement -Name $_.Name "
           "-WakeOnMagicPacket Enabled -ErrorAction SilentlyContinue }; 'enabled'"),
    hints=(
        "The packet is fine if another PC wakes from the same command. Look at the PC that does not: what does its "
        "network card do while the PC is off? Get-NetAdapterPowerManagement shows it.",
        "Get-NetAdapterPowerManagement | Format-List Name, WakeOnMagicPacket: Disabled. In Device Manager it is the "
        "card's Advanced tab, 'Wake on Magic Packet', and its Power Management tab.",
        "Turn it back on: Set-NetAdapterPowerManagement -Name Ethernet -WakeOnMagicPacket Enabled (or Device "
        "Manager > the card > Advanced > Wake on Magic Packet: Enabled). Shut the PC down and wake it again.",
    ),
    verify=("[bool](Get-NetAdapter -Physical | Get-NetAdapterPowerManagement -ErrorAction SilentlyContinue | "
            "Where-Object { [string]$_.WakeOnMagicPacket -eq 'Enabled' })"),
))


# App Control for Business (the lesson app-control-for-business): someone
# tidied the PC's policies and took the line-of-business app's supplemental
# policy away with the leftovers. The base stays enforced, so the app it never
# allowed is blocked. The removed binary is kept in winlab's own folder so
# Fix it for me can put it back; the student redeploys it from their XML.
_CI_LIST = "$j = (CiTool.exe --list-policies -json | Out-String) | ConvertFrom-Json; "
_CI_STASH = "C:\\winlab\\faults\\app-control"
_TIMESHEET = "C:\\Program Files\\Contoso\\Timesheet\\Timesheet.exe"

_reg(GuestFault(
    id="app-control-supplemental-removed",
    title="An App Control policy blocks the timesheet app",
    os=WINDOWS,
    teaches="reading a code integrity block (event 3077) back to the policy that caused it, base and supplemental "
            "App Control policies, and redeploying a policy with CiTool instead of switching enforcement off",
    symptom="after a restart the Contoso Timesheet app will not start: 'Your organization used App Control for "
            "Business to block this app'; Windows and Office still run",
    apply=(_CI_LIST
           + "$s = @($j.Policies | Where-Object { -not $_.IsSystemPolicy -and $_.IsEnforced -and "
             "\"$($_.PolicyID)\".Trim('{}') -ne \"$($_.BasePolicyID)\".Trim('{}') }); "
             "if (-not $s.Count) { throw 'no supplemental App Control policy is active on this PC: do the lesson "
             "app-control-for-business first' }; "
             "New-Item -ItemType Directory -Path '" + _CI_STASH + "' -Force | Out-Null; "
             "foreach ($p in $s) { $id = \"$($p.PolicyID)\".Trim('{}'); "
             "$src = Join-Path $env:SystemRoot ('System32\\CodeIntegrity\\CiPolicies\\Active\\{' + $id + '}.cip'); "
             "if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination '" + _CI_STASH + "' -Force }; "
             "CiTool.exe --remove-policy ('{' + $id + '}') -json | Out-Null }; "
             "shutdown.exe /r /t 15 /c 'winlab'; 'restarting'"),
    clear=("foreach ($f in @(Get-ChildItem -Path '" + _CI_STASH + "' -Filter *.cip -ErrorAction SilentlyContinue)) { "
           "CiTool.exe --update-policy $f.FullName -json | Out-Null }; 'supplemental policies back'"),
    hints=(
        "Read the message first: 'Your organization used App Control for Business to block this app' is code "
        "integrity, not AppLocker (AppLocker says 'This app has been blocked by your system administrator'). As "
        "Administrator: Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational -MaxEvents 20 | "
        "Where-Object Id -eq 3077 | Format-List Message. The 3077 names Timesheet.exe and the policy that blocked it.",
        "The policy that blocked it is the base, Corp Base, which never allowed the app: a supplemental policy did. "
        "CiTool --list-policies lists Corp Base, enforced, and no Contoso Timesheet any more. Someone removed it.",
        "Put the supplemental policy back from its source: your C:\\AppControl\\Timesheet.xml still names Corp Base. "
        "$supp = ([xml](Get-Content C:\\AppControl\\Timesheet.xml)).SiPolicy.PolicyID; ConvertFrom-CIPolicy "
        "-XmlFilePath C:\\AppControl\\Timesheet.xml -BinaryFilePath \"C:\\AppControl\\$supp.cip\"; CiTool "
        "--update-policy \"C:\\AppControl\\$supp.cip\". Run the app. Do not put Corp Base back into audit mode or "
        "remove it to make the call go away.",
    ),
    verify=("$dg = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard; "
            "$o = ''; try { $o = & '" + _TIMESHEET + "' 2>&1 | Out-String } catch { $o = $_.Exception.Message }; "
            "[bool]([int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2 -and $o -match 'Contoso Timesheet')"),
))


def catalog() -> list[GuestFault]:
    return list(SCENARIOS.values())


def render_catalog() -> str:
    lines = ["guest-side problems (break the OS, diagnose the symptom)", ""]
    for osname in (WINDOWS, LINUX):
        items = [f for f in SCENARIOS.values() if f.os in (osname, BOTH)]
        lines.append(f"{osname}:")
        for f in items:
            where = f" [{', '.join(f.images)}]" if f.images else ""
            lines.append(f"  {f.id:<22} {f.title}{where}")
            lines.append(f"  {'':<22} symptom: {f.symptom}")
        lines.append("")
    lines.append("inject:  winlab break <node> <id> [--param k=v ...]")
    lines.append("hint:    winlab break <node> <id> --hint 1   (1, 2 or 3)")
    lines.append("verify:  winlab break <node> <id> --verify   (True when your fix holds)")
    lines.append("fix:     winlab break <node> <id> --clear    (winlab undoes it for you)")
    return "\n".join(lines)


DEFAULTS = {"service": "DNS", "user": "asmith", "share": "Company", "dns": "10.10.10.10",
            "unit": "rsyslog", "domain": "corp.lab", "scope": "10.10.10.0",
            "gpo": "Map Company Share", "printer": "Lab-PDF", "wsus": "app01", "ntp": "",
            "timesrc": "the domain controller", "mailhost": "mail.corp.lab", "mailip": "",
            "mailserver": "the mail server", "registry": "the lab registry", "k3sserver": "the k3s server",
            "pgprimary": "db01.corp.lab", "pgprimaryip": "",
            "pgstandby": "db03.corp.lab", "mariahost": "db02.corp.lab", "dbnet": "10.88.0.0/24",
            "dbhosts": "10.88.0.%",
            "proxyhost": "px01.corp.lab", "proxyip": "",
            "proxyport": "3128", "corpnet": "", "inetip": "203.0.113.80",
            "v6host": "lnx01", "v6hostip": "fd12:3456:789a:2::25", "v6prefix": "fd12:3456:789a:1::",
            "sensor": "rt01", "corpgw": "", "dmzgw": "", "dmznet": "", "srvip": "",
            "vpnname": "vpn.corp.example", "crlname": "pki.corp.example", "vpnhost": "vpn01",
            "vpnpublic": "203.0.113.10", "officenet": "10.96.0.0/24", "fsip": "10.96.0.20",
            "fshost": "fs01.corp.lab", "poolnet": "10.96.8.0/24", "caname": "CORP Root CA",
            "vpnconn": "Corp VPN", "rapolicy": "Remote-Workers VPN", "ragroup": "Remote-Workers",
            "anscontrol": "ctl01.corp.lab", "anstarget": "lnx02", "anstargetfqdn": "lnx02.corp.lab",
            "anstargetip": "", "dscnode": "srv01"}


def lab_params(lab) -> dict[str, str]:
    """Scenario parameters read from a lab: its domain, the first DC's
    address as the right DNS server, the DHCP server's scope, the company
    share and the GPO that maps it, the WSUS server. The Problems window and
    `winlab break` both fill scenarios from here, so a fault on the
    every-role lab breaks 10.40.10.0, not ad-ds-basics' scope."""
    import ipaddress

    from . import naming
    share = naming.share_name(lab)
    out: dict[str, str] = {"share": share, "gpo": f"Map {share} Share"}
    if lab.domain:
        out["domain"] = lab.domain
    for n in lab.node_list():
        nic = n.primary_nic
        if "ad-ds" in n.roles and nic and nic.ip and "dns" not in out:
            out["dns"] = nic.ip
        if "dhcp" in n.roles and nic and "scope" not in out:
            net = lab.networks.get(nic.network)
            if net is not None and net.cidr:
                out["scope"] = str(ipaddress.ip_network(net.cidr, strict=False).network_address)
        if "wsus" in n.roles and "wsus" not in out:
            out["wsus"] = n.hostname or n.id
    from .timesync import fault_params  # the NTP server, lab time now
    out.update(fault_params(lab))
    from .mail import fault_params as mail_params  # the mail server's name and address
    out.update(mail_params(lab))
    from .containers import fault_params as ctr_params  # the lab registry, the k3s server
    out.update(ctr_params(lab))
    from .databases import fault_params as db_params  # the database servers and the lab subnet
    out.update(db_params(lab))
    from .webproxy import fault_params as proxy_params  # the proxy, its segment, the lab Internet
    out.update(proxy_params(lab))
    from .ipv6 import fault_params as v6_params  # the IPv6 host's name and address, the DHCPv6 prefix
    out.update(v6_params(lab))
    from .ids import fault_params as ids_params  # the sensor's legs, the inside segments, the DMZ server
    out.update(ids_params(lab))
    from .remoteaccess import fault_params as ra_params  # the VPN edge, its public names, the office
    out.update(ra_params(lab))
    from .automation import fault_params as auto_params  # the control node, the managed servers
    out.update(auto_params(lab))
    from .doctools import fault_params as docs_params  # the Admin tools server's name and address
    out.update(docs_params(lab))
    return out


def _fill(tmpl: str, params: dict[str, str]) -> str:
    # Targeted token replacement, NOT str.format: scenario commands contain
    # literal PowerShell/sh braces (script blocks, hashtables) that format()
    # would misparse as fields.
    values = dict(DEFAULTS)
    values.update(params)
    for key, val in values.items():
        tmpl = tmpl.replace("{" + key + "}", str(val))
    return tmpl


def build_command(scenario_id: str, params: dict[str, str], clear: bool) -> tuple[str, str]:
    f = SCENARIOS.get(scenario_id)
    if not f:
        raise KeyError(scenario_id)
    return _fill(f.clear if clear else f.apply, params), f.shell


def verify_command(scenario_id: str, params: dict[str, str]) -> tuple[str, str, str]:
    """(command, shell, expected stdout) that proves the fault is fixed."""
    f = SCENARIOS.get(scenario_id)
    if not f:
        raise KeyError(scenario_id)
    return _fill(f.verify, params), f.shell, f.expect


def hint(scenario_id: str, n: int, params: dict[str, str] | None = None) -> str:
    """Hint n (1-based); the ladder goes from where to look to the command."""
    f = SCENARIOS.get(scenario_id)
    if not f:
        raise KeyError(scenario_id)
    if n < 1 or n > len(f.hints):
        raise IndexError(n)
    return _fill(f.hints[n - 1], params or {})


def is_fixed(stdout: str, expect: str = "True") -> bool:
    lines = [ln.strip() for ln in stdout.strip().splitlines() if ln.strip()]
    return bool(lines) and lines[-1].lower() == expect.lower()


# Remote administration between lab machines: WinRM, the RDP rules, who may
# sign in over RDP (winlab/remoteadmin.py).
from . import remoteadmin as _remoteadmin  # noqa: E402
_remoteadmin.register_faults(_reg)

# The lab's CA in use: the CDP, the root's trust, the RDP and LDAPS
# certificates (winlab/pki.py).
from . import pki as _pki  # noqa: E402
_pki.register_faults(_reg)

# Time: the NTP server, the domain hierarchy, skew and time zones
# (winlab/timesync.py).
from . import timesync as _timesync  # noqa: E402
_timesync.register_faults(_reg)

# Windows Server Backup to the NAS: the target full, the share read-only
# (winlab/wsbackup.py).
from . import wsbackup as _wsbackup  # noqa: E402
_wsbackup.register_faults(_reg)

# Imaging: a WDS server that stops answering PXE clients (winlab/imaging.py).
from . import imaging as _imaging  # noqa: E402
_imaging.register_faults(_reg)

# Windows updates in an isolated lab: the Windows Update service, the WSUS
# client's server, the servicing stack (winlab/updates.py).
from . import updates as _updates  # noqa: E402
_updates.register_faults(_reg)

# Microsoft Edge by Group Policy: the central store's msedge.adml gone
# (winlab/edge.py).
from . import edge as _edge  # noqa: E402
_edge.register_faults(_reg)

# BitLocker: escrow policy switched off, a forced recovery (winlab/bitlocker.py).
from . import bitlocker as _bitlocker  # noqa: E402
_bitlocker.register_faults(_reg)

# The storage array: an initiator's IQN off its target's list, a CHAP secret
# changed on one side (winlab/san.py).
from . import san as _san  # noqa: E402
_san.register_faults(_reg)

# Web servers: a binding clash, the SPN gone, a certificate for the wrong
# name, a stale A record (winlab/webfarm.py).
from . import webfarm as _webfarm  # noqa: E402
_webfarm.register_faults(_reg)
# Mail: the MX in AD DNS, Postfix's own domains, Dovecot's certificate
# (winlab/mail.py).
from . import mail as _mail  # noqa: E402
_mail.register_faults(_reg)

# Containers: a wrong port mapping, an image the lab does not have, a k3s
# agent pointed at the wrong port (winlab/containers.py).
from . import containers as _containers  # noqa: E402
_containers.register_faults(_reg)

# Dynamic routing: OSPF timers that disagree, an MTU that stalls the database
# exchange, an eBGP neighbour with the wrong AS (winlab/routing.py).
from . import routing as _routing  # noqa: E402
_routing.register_faults(_reg)

# IPv6: router advertisements switched off, a DHCPv6 scope on the wrong
# prefix, a missing AAAA and PTR, ICMPv6 blocked (winlab/ipv6.py).
from . import ipv6 as _ipv6  # noqa: E402
_ipv6.register_faults(_reg)

# Web filtering: the router that lets the PCs out directly, an allow line
# above the block list, the proxy's port in the GPO (winlab/webproxy.py).
from . import webproxy as _webproxy  # noqa: E402
_webproxy.register_faults(_reg)

# Intrusion detection: the sensor on the wrong leg, HOME_NET that leaves the
# office out, a rule written and never loaded (winlab/ids.py).
from . import ids as _ids  # noqa: E402
_ids.register_faults(_reg)

# Remote access: the CRL blocked at the edge, the SSTP certificate for the
# wrong name, NPS's default deny above the group's policy, a split tunnel
# with no route to the office (winlab/remoteaccess.py).
from . import remoteaccess as _remoteaccess  # noqa: E402
_remoteaccess.register_faults(_reg)

# Day-two directory work: a leaver, stale computers, a prestaged account
# changing jobs, extra Domain Admins, scheduled-task persistence
# (winlab/dayops.py).
from . import dayops as _dayops  # noqa: E402
_dayops.register_faults(_reg)

# Databases: pg_hba.conf, listen_addresses from ALTER SYSTEM, the standby's
# primary_conninfo, MariaDB's bind-address (winlab/databases.py).
from . import databases as _databases  # noqa: E402
_databases.register_faults(_reg)

# Automation at scale: a WinRM listener gone, a changed SSH host key, an
# inventory group typo, the DSC LCM in ApplyOnly (winlab/automation.py).
from . import automation as _automation  # noqa: E402
_automation.register_faults(_reg)

# The admin's documentation tools: a PC's GLPI Agent stopped, the wiki's data
# folder not writable, GLPI's database switched off (winlab/doctools.py).
from . import doctools as _doctools  # noqa: E402
_doctools.register_faults(_reg)

# Wear: a service that crashed after the night's updates with no recovery
# options, a web server's logs never cleaned (winlab/wearfaults.py).
from . import wearfaults as _wearfaults  # noqa: E402
_wearfaults.register_faults(_reg)
# File and print operations: a DHCP server unbound after a move, inheritance
# removed, Everyone with Full Control, a print share renamed, a DFS-R staging
# quota too small, a damaged profile hive, a full C:, VSS disabled under the
# backup (winlab/fileops.py).
from . import fileops as _fileops  # noqa: E402
_fileops.register_faults(_reg)
# Identity operations: joiners from HR's CSV, a mover, a leaver closed out, a
# deleted OU, tier 0 hygiene, a duplicate SPN, a lockout from a stale
# credential, SYSVOL switched off, and a DC rolled back (winlab/identityops.py).
from . import identityops as _identityops  # noqa: E402
_identityops.register_faults(_reg)

# Faults winlab breaks from outside the machine: a DC's disk reverted to a
# checkpoint (winlab/dcrollback.py). host_break runs them for `winlab break`
# and the Break button; the verify still runs inside the machine.
HOST_BREAKS = {"dc-rollback": "winlab.dcrollback"}


def host_break(scenario_id: str, lab_name: str, node: str, clear: bool = False,
               say=lambda line: None) -> tuple[bool, str]:
    import importlib
    f = SCENARIOS[scenario_id]
    mod = importlib.import_module(HOST_BREAKS[f.host])
    return mod.host_break(lab_name, node, clear, say=say)
# Security operations: a WEF source that cannot read its Security log, a Wazuh
# agent pointed at a server that is gone, a scan target that stopped answering
# ping, legacy audit policy overriding the baseline, the software share closed
# to computers, Chocolatey sent to the internet, a certificate nothing will
# renew, the daily report's log folder locked (winlab/secops.py).
from . import secops as _secops  # noqa: E402
_secops.register_faults(_reg)
