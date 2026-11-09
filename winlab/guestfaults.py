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

_reg(GuestFault(
    id="printer-unshared",
    roles=("printer",),
    title="A shared printer is no longer shared",
    os=WINDOWS,
    teaches="printer sharing on a print server, share names clients map, and testing from a client",
    symptom="clients' {printer} printer shows offline or 'Windows cannot connect to the printer'; the queue on the server looks fine",
    apply=("$p = Get-Printer -Name '{printer}' -ErrorAction Stop; if (-not $p.Shared) { throw 'the printer is not shared' }; "
           "New-Item -ItemType Directory -Path C:\\winlab\\faults -Force | Out-Null; "
           "Set-Content -Path 'C:\\winlab\\faults\\printer-share-{printer}.txt' -Value $p.ShareName; "
           "Set-Printer -Name '{printer}' -Shared $false"),
    clear=("$n = Get-Content -Path 'C:\\winlab\\faults\\printer-share-{printer}.txt' -ErrorAction SilentlyContinue | Select-Object -First 1; "
           "if (-not $n) { $n = '{printer}' }; Set-Printer -Name '{printer}' -Shared $true -ShareName $n.Trim()"),
    hints=(
        "The server's queue is fine, so look at what clients connect to: a print queue is published under a share name. "
        "Get-Printer -Name '{printer}' | Format-List Name, Shared, ShareName on the print server.",
        "Shared is False: the queue still prints locally on the server, but no client can reach \\\\<server>\\<share name>. "
        "Clients keep the old connection and show it offline.",
        "Share it again under the name clients already use: Set-Printer -Name '{printer}' -Shared $true -ShareName <the old name> "
        "(Print Management > Printers > Properties > Sharing does the same). Then print a test page from a client.",
    ),
    verify=("$n = Get-Content -Path 'C:\\winlab\\faults\\printer-share-{printer}.txt' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "$p = Get-Printer -Name '{printer}' -ErrorAction SilentlyContinue; "
            "[bool]($p -and $p.Shared -and (-not $n -or $p.ShareName -eq $n.Trim()))"),
))

_reg(GuestFault(
    id="dns-record-typo",
    roles=("ad-ds", "dns"),
    title="A server's DNS record has a typo",
    os=WINDOWS,
    teaches="host (A) records, reading what DNS really answers, stale client caches, and why a ping by number works",
    symptom="\\\\{typohost} and anything by its name fail for everyone, while the server answers by its address",
    # Somebody retyped the record by hand and swapped two digits: the right
    # address is kept on the DNS server so Fix-for-me and the check know it.
    apply=("$z = '{domain}'; $h = '{typohost}'; "
           "$r = @(Get-DnsServerResourceRecord -ZoneName $z -Name $h -RRType A -ErrorAction Stop); "
           "if (-not $r) { throw \"no host record for $h\" }; "
           "$ip = $r[0].RecordData.IPv4Address.IPAddressToString; $o = $ip.Split('.'); $l = $o[3]; $b = ''; "
           "if ($l.Length -ge 2 -and $l[-1] -ne $l[-2]) { $b = $l.Substring(0, $l.Length - 2) + $l[-1] + $l[-2] }; "
           "if (-not $b -or [int]$b -lt 1 -or [int]$b -gt 254 -or [int]$b -eq [int]$l) { $b = [string](([int]$l % 253) + 1) }; "
           "$bad = ($o[0..2] -join '.') + '.' + [int]$b; "
           "New-Item -ItemType Directory -Path C:\\winlab\\faults -Force | Out-Null; "
           "Set-Content -Path \"C:\\winlab\\faults\\dns-typo-$h.txt\" -Value $ip; "
           "$r | Remove-DnsServerResourceRecord -ZoneName $z -Force; "
           "Add-DnsServerResourceRecordA -ZoneName $z -Name $h -IPv4Address $bad; "
           "Clear-DnsServerCache -Force -ErrorAction SilentlyContinue"),
    clear=("$z = '{domain}'; $h = '{typohost}'; "
           "$ip = Get-Content -Path \"C:\\winlab\\faults\\dns-typo-$h.txt\" -ErrorAction SilentlyContinue | Select-Object -First 1; "
           "if ($ip) { Get-DnsServerResourceRecord -ZoneName $z -Name $h -RRType A -ErrorAction SilentlyContinue | "
           "Remove-DnsServerResourceRecord -ZoneName $z -Force; "
           "Add-DnsServerResourceRecordA -ZoneName $z -Name $h -IPv4Address $ip.Trim(); "
           "Clear-DnsServerCache -Force -ErrorAction SilentlyContinue }"),
    hints=(
        "Works by address, fails by name: that is name resolution. Ask DNS what it answers: "
        "Resolve-DnsName {typohost}.{domain} (or nslookup {typohost}), and compare with the address the server really has (ipconfig on it).",
        "The answer is wrong for everyone, so it is not one PC's cache: the host (A) record in the {domain} zone on the DNS server "
        "has the wrong address. Get-DnsServerResourceRecord -ZoneName {domain} -Name {typohost} -RRType A shows it.",
        "Fix the record: remove the wrong one and add the right address (DNS Manager, or Remove-DnsServerResourceRecord and "
        "Add-DnsServerResourceRecordA -ZoneName {domain} -Name {typohost} -IPv4Address <its real address>). "
        "Then Clear-DnsServerCache on the server and ipconfig /flushdns on the clients that cached the wrong answer.",
    ),
    verify=("$ip = Get-Content -Path 'C:\\winlab\\faults\\dns-typo-{typohost}.txt' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "$a = @(Get-DnsServerResourceRecord -ZoneName '{domain}' -Name '{typohost}' -RRType A -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString }); "
            "[bool]($ip -and $a.Count -ge 1 -and @($a | Where-Object { $_ -ne $ip.Trim() }).Count -eq 0)"),
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
           "if (Get-Service -Name 'WinTelemetryHelper' -ErrorAction SilentlyContinue) { sc.exe delete WinTelemetryHelper | Out-Null }"),
    hints=(
        "Work from the evidence, newest first. On the domain controller: Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 4728, 4732, 4756 } "
        "lists accounts created and members added to security groups; Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } "
        "lists services installed.",
        "Read the messages, not just the ids: Get-WinEvent ... | Format-List TimeCreated, Message. One account was created and put in "
        "Domain Admins minutes after a burst of failed sign-ins (4625, 4771 or 4776 for many different users from one place: a spray). "
        "A service with an odd path under C:\\ProgramData was installed at the same time.",
        "Contain and record: Remove-ADGroupMember 'Domain Admins' svc-sync and Disable-ADAccount svc-sync (or delete it), "
        "sc.exe delete WinTelemetryHelper, and record the incident where the team keeps them (the wiki's incidents "
        "namespace, or the helpdesk ticket) naming the account and the service. In real life: "
        "reset the sprayed users' passwords and krbtgt's twice, and find how the intruder got the rights to do this.",
    ),
    verify=("$u = Get-ADUser -Filter \"SamAccountName -eq 'svc-sync'\" -Properties MemberOf -ErrorAction SilentlyContinue; "
            "$da = (Get-ADGroup 'Domain Admins').DistinguishedName; "
            "$okU = (-not $u) -or ((-not $u.Enabled) -and ($u.MemberOf -notcontains $da)); "
            "$okS = -not (Get-Service -Name 'WinTelemetryHelper' -ErrorAction SilentlyContinue); "
            "[bool]($okU -and $okS)"),
))


# The incident-response drill on a member PC: a stand-in intruder's foothold.
# Everything planted is harmless (the "payload" only writes the date to a
# file); it exists to be found from the logs and the SIEM, contained,
# preserved as evidence, removed, and written up in the lifecycle's terms.
_IR_DIR = "C:\\ProgramData\\EdgeUpdateHelper"
_IR_RUN = "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'"

_reg(GuestFault(
    id="compromised-workstation",
    roles=("domain-join",),
    title="A PC has a foothold on it: respond to the incident from detection to lessons learned",
    os=WINDOWS,
    teaches="the incident response lifecycle on one PC: detect from the SIEM and the logs, scope, contain, keep the evidence with its hash, eradicate every persistence, recover and write the report",
    symptom="the SIEM shows a new local administrator and a new scheduled task on this PC overnight, and nobody in IT made them; the user noticed nothing",
    apply=("$d = '" + _IR_DIR + "'; New-Item -ItemType Directory -Path $d -Force | Out-Null; "
           "Set-Content -Path ($d + '\\helper.ps1') -Encoding ASCII -Value @("
           "'# winlab incident drill: a harmless stand-in for an intruder''s script', "
           "'Get-Date | Out-File -FilePath " + _IR_DIR + "\\last.txt'); "
           "New-LocalUser -Name 'support_tmp' -Description 'Remote support' -AccountPassword (" + _RANDOM_SECRET + ") | Out-Null; "
           "Add-LocalGroupMember -SID 'S-1-5-32-544' -Member 'support_tmp'; "
           "$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ' + $d + '\\helper.ps1'); "
           "$t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15); "
           "Register-ScheduledTask -TaskName 'EdgeUpdateHelper' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null; "
           "Set-ItemProperty -Path " + _IR_RUN + " -Name 'EdgeUpdateHelper' "
           "-Value ('powershell.exe -NoProfile -WindowStyle Hidden -File ' + $d + '\\helper.ps1'); "
           "New-NetFirewallRule -Name 'winlab-ir-remote-support' -DisplayName 'Remote Support' -Direction Inbound "
           "-Protocol TCP -LocalPort 4444 -Action Allow -Profile Any | Out-Null"),
    clear=("Unregister-ScheduledTask -TaskName 'EdgeUpdateHelper' -Confirm:$false -ErrorAction SilentlyContinue; "
           "Remove-ItemProperty -Path " + _IR_RUN + " -Name 'EdgeUpdateHelper' -ErrorAction SilentlyContinue; "
           "Remove-NetFirewallRule -Name 'winlab-ir-remote-support' -ErrorAction SilentlyContinue; "
           "Remove-LocalUser -Name 'support_tmp' -ErrorAction SilentlyContinue; "
           "Remove-Item -Path '" + _IR_DIR + "' -Recurse -Force -ErrorAction SilentlyContinue; "
           "Remove-Item -Path 'C:\\winlab\\incident-report.txt', 'C:\\winlab\\evidence' -Recurse -Force -ErrorAction SilentlyContinue"),
    hints=(
        "Start where the alert came from, then widen: in the Wazuh dashboard filter agent.name for this PC and the last day. On the PC: "
        "Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 4732, 4698, 4688 } -MaxEvents 50 | Format-List TimeCreated, Id, Message "
        "(4698 and the command lines in 4688 appear only if the endpoint logging lesson is done). Scope it: an account, a task, and what else ran at the same minute?",
        "Look for every way it comes back, not just the first: Get-LocalGroupMember Administrators, Get-ScheduledTask | Where-Object TaskPath -eq '\\', "
        "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, and Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True "
        "| Get-NetFirewallPortFilter for a port nothing in the company uses. The task and the Run key start the same script.",
        "Contain first (Disable-LocalUser support_tmp, Disable-ScheduledTask, Disable-NetFirewallRule), then keep the evidence: copy the script to "
        "C:\\winlab\\evidence and record Get-FileHash -Algorithm SHA256 of the copy. Then eradicate: remove the account, the task, the Run value, the rule "
        "and C:\\ProgramData\\EdgeUpdateHelper. Write C:\\winlab\\incident-report.txt with what you found (names, port, hash) under the headings "
        "Containment, Eradication, Recovery and Lessons learned.",
    ),
    verify=("$u = Get-LocalUser -Name 'support_tmp' -ErrorAction SilentlyContinue; "
            "$adm = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\\\\support_tmp$' }); "
            "$okU = ((-not $u) -or (-not $u.Enabled)) -and ($adm.Count -eq 0); "
            "$okT = -not (Get-ScheduledTask -TaskName 'EdgeUpdateHelper' -ErrorAction SilentlyContinue); "
            "$okR = -not (Get-ItemProperty -Path " + _IR_RUN + " -Name 'EdgeUpdateHelper' -ErrorAction SilentlyContinue); "
            "$okF = -not (Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue "
            "| Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -contains '4444' }); "
            "$okP = -not (Test-Path -Path '" + _IR_DIR + "\\helper.ps1'); "
            "$ev = Get-ChildItem -Path 'C:\\winlab\\evidence' -Filter 'helper.ps1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "$h = if ($ev) { (Get-FileHash -Path $ev.FullName -Algorithm SHA256).Hash } else { 'none' }; "
            "$okE = [bool]$ev -and ([string](Get-Content -Path $ev.FullName -Raw) -match 'winlab incident drill'); "
            "$t = [string](Get-Content -Path 'C:\\winlab\\incident-report.txt' -Raw -ErrorAction SilentlyContinue); "
            "$okW = ($t -match 'support_tmp') -and ($t -match 'EdgeUpdateHelper') -and ($t -match '4444') -and ($t -match $h) "
            "-and ($t -match 'containment') -and ($t -match 'eradication') -and ($t -match 'recovery') -and ($t -match 'lessons learned'); "
            "[bool]($okU -and $okT -and $okR -and $okF -and $okP -and $okE -and $okW)"),
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


# The edge-firewall lab's drills (content/labs/edge-firewall.toml): both break
# a part of OPNsense the student built, at run time, so the configuration (and
# the GUI's pages) still look right; OPNsense puts both back when the part is
# applied again in the GUI or the firewall reboots.
_reg(GuestFault(
    id="opn-wg-down",
    images=("opnsense",),
    title="The home workers' VPN stopped answering",
    os=LINUX,
    teaches="reading a WireGuard tunnel from both ends: the handshake time, the interface's own "
            "state and the rules, before touching keys or peers",
    symptom="the home worker's laptop says the tunnel is active and nothing in the office answers; "
            "on the firewall the instance and the peer are still configured and enabled, the WAN "
            "rule for UDP 51820 is there, and the last handshake grows older by the minute",
    apply="for i in $(ifconfig -g wg 2>/dev/null); do ifconfig \"$i\" down; done; echo down",
    clear="for i in $(ifconfig -g wg 2>/dev/null); do ifconfig \"$i\" up; done; echo up",
    shell="sh",
    hints=(
        "Start at the firewall end: wg show prints the instance and its peer with the latest "
        "handshake. Minutes old while the laptop keeps trying means the firewall is not answering.",
        "The configuration is fine, so ask the interface: ifconfig -g wg lists the WireGuard "
        "interfaces, and ifconfig wg0 shows its flags. A tunnel interface without UP on its first "
        "line takes no packets in or out.",
        "ifconfig wg0 up brings it back at once; VPN, WireGuard, Apply (or a restart of the "
        "service on the dashboard) does the same through OPNsense. Then read the system log for "
        "who or what took it down.",
    ),
    verify="n=0; for i in $(ifconfig -g wg 2>/dev/null); do ifconfig \"$i\" | head -1 | grep -q '<UP' "
           "|| n=$((n+1)); done; echo $n",
    expect="0",
))


_reg(GuestFault(
    id="opn-ids-stopped",
    images=("opnsense",),
    title="The intrusion detection went quiet",
    os=LINUX,
    teaches="telling a quiet network from a blind sensor: the service's state, its log and a "
            "known test alert, before you trust an empty alert list",
    symptom="no new alerts since this morning; the test page that always raises 2100498 raises "
            "nothing; Intrusion Detection is still ticked Enabled in Settings and its rule sets "
            "are all there",
    apply="configctl ids stop >/dev/null 2>&1; pkill -x suricata 2>/dev/null; echo stopped",
    clear="configctl ids start >/dev/null 2>&1; echo started",
    shell="sh",
    hints=(
        "An empty alert list proves nothing on its own. Make the test alert happen (the test page "
        "from pc01) and see whether it arrives.",
        "Ask for the engine, not the setting: the dashboard's Services widget, or on the shell "
        "configctl ids status and pgrep -lf suricata. The last lines of /var/log/suricata/suricata.log "
        "say when it stopped.",
        "Start it: Services, Intrusion Detection, Administration, Apply restarts it with the saved "
        "settings, or configctl ids start on the shell. Then raise the test alert again.",
    ),
    verify="pgrep -x suricata >/dev/null && echo True || echo False",
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
            lines.append(f"  {f.id:<22} {_fill(f.title, {})}{where}")
            lines.append(f"  {'':<22} symptom: {_fill(f.symptom, {})}")
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
            "mailserver": "the mail server", "registry": "the lab registry", "k3sserver": "the k3s server", "k8scp": "the control plane",
            "pgprimary": "db01.corp.lab", "pgprimaryip": "",
            "pgstandby": "db03.corp.lab", "mariahost": "db02.corp.lab", "dbnet": "10.88.0.0/24",
            "dbhosts": "10.88.0.%", "typohost": "fs01",
            "proxyhost": "px01.corp.lab", "proxyip": "",
            "proxyport": "3128", "corpnet": "", "inetip": "203.0.113.80",
            "v6host": "lnx01", "v6hostip": "fd12:3456:789a:2::25", "v6prefix": "fd12:3456:789a:1::",
            "sensor": "rt01", "corpgw": "", "dmzgw": "", "dmznet": "", "srvip": "",
            "mcserver": "ops01.corp.lab", "mcip": "", "mcwrong": "192.0.2.250",
            "vpnname": "vpn.corp.example", "crlname": "pki.corp.example", "vpnhost": "vpn01",
            "vpnpublic": "203.0.113.10", "officenet": "10.96.0.0/24", "fsip": "10.96.0.20",
            "fshost": "fs01.corp.lab", "poolnet": "10.96.8.0/24", "caname": "CORP Root CA",
            "vpnconn": "Corp VPN", "rapolicy": "Remote-Workers VPN", "ragroup": "Remote-Workers",
            "anscontrol": "ctl01.corp.lab", "anstarget": "lnx02", "anstargetfqdn": "lnx02.corp.lab",
            "anstargetip": "", "dscnode": "srv01",
            "netbios": "CORP", "smbhost": "fs01.corp.lab", "smbserver": "fs01", "smbip": "",
            "smbshare": "projects", "nshost": "ns01.corp.lab", "nsip": "", "subzone": "dev.corp.lab",
            "fsshare": "Departments", "fsserver": "fs01", "dfsroot": "\\\\corp.lab\\Files",
            "dfsfolder": "Departments",
            "attackerip": "10.94.0.66", "toolsserver": "the tools server", "toolsip": "",
            "opsserver": "the network operations server", "opsip": "",
            "inetdns": "203.0.113.53", "inetmx": "203.0.113.25", "inetspam": "203.0.113.66",
            "mailpublic": "203.0.113.10",
            "forgejoip": "10.83.0.20", "forgejourl": "http://10.83.0.20:3000", "forgejoreg": "10.83.0.20:3000",
            "cihost": "ci01", "apphost": "app01", "appip": "10.83.0.31"}


from .printing import DEFAULTS as _PRINT_DEFAULTS  # noqa: E402
DEFAULTS.update(_PRINT_DEFAULTS)


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
        if "typohost" not in out and n.kind != "linux" and "ad-ds" not in n.roles \
                and any(r in n.roles for r in ("file", "printer", "iis", "web")):
            out["typohost"] = naming.hostname_of(n).lower()   # a server staff reach by name
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
    from .remotesupport import fault_params as rs_params  # MeshCentral's name and address, a dead one
    out.update(rs_params(lab))
    from .remoteaccess import fault_params as ra_params  # the VPN edge, its public names, the office
    out.update(ra_params(lab))
    from .automation import fault_params as auto_params  # the control node, the managed servers
    out.update(auto_params(lab))
    from .doctools import fault_params as docs_params  # the Admin tools server's name and address
    out.update(docs_params(lab))
    from .netops import fault_params as ops_params  # the Network operations server's name and address
    out.update(ops_params(lab))
    from .linuxdomain import fault_params as lx_params  # the Linux track's file server, BIND server, subdomain
    out.update(lx_params(lab))
    from .filesharing import fault_params as fs_params  # the file-sharing lab's share and namespace
    out.update(fs_params(lab))
    from .incidents import fault_params as ir_params  # the incident drills' attacker address nobody owns
    out.update(ir_params(lab))
    from .printing import fault_params as print_params  # the print queues, the print servers, the printers
    out.update(print_params(lab))
    from .devops import fault_params as devops_params  # Forgejo's address and URL, the runner, the deploy target
    out.update(devops_params(lab))
    from .hwfaults import fault_params as hw_params  # what is in the PC's case: supply, cooling, sticks, cards, drives
    out.update(hw_params(lab))
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


def words(scenario_id: str, params: dict[str, str] | None = None,
          lang: str | None = None) -> dict[str, str]:
    """The scenario's title, symptom and teaches in the desktop's language
    (content/i18n/content/<lang>/problems.json) with the lab's names filled
    in ({subzone}, {domain}, {nshost}...): what a student reads must never
    show a raw placeholder."""
    from .content import problem_text
    f = SCENARIOS.get(scenario_id)
    if not f:
        raise KeyError(scenario_id)
    return {k: _fill(problem_text(getattr(f, k) or "", lang), params or {})
            for k in ("title", "symptom", "teaches")}


def hint(scenario_id: str, n: int, params: dict[str, str] | None = None,
         lang: str | None = None) -> str:
    """Hint n (1-based), translated; the ladder goes from where to look to the command."""
    from .content import problem_text
    f = SCENARIOS.get(scenario_id)
    if not f:
        raise KeyError(scenario_id)
    if n < 1 or n > len(f.hints):
        raise IndexError(n)
    return _fill(problem_text(f.hints[n - 1], lang), params or {})


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

# The certificate-authority lab: a template taken off the issuing CA, the
# ACME renewal timer stopped on the step-ca server (winlab/calab.py).
from . import calab as _calab  # noqa: E402
_calab.register_faults(_reg)

# Time: the NTP server, the domain hierarchy, skew and time zones
# (winlab/timesync.py).
from . import timesync as _timesync  # noqa: E402
_timesync.register_faults(_reg)

# Windows Server Backup to the NAS: the target full, the share read-only
# (winlab/wsbackup.py).
from . import wsbackup as _wsbackup  # noqa: E402
_wsbackup.register_faults(_reg)

# VM-level backup on the Hyper-V host: a deleted VM, a checkpoint a backup
# left behind (winlab/vmbackup.py).
from . import vmbackup as _vmbackup  # noqa: E402
_vmbackup.register_faults(_reg)
# Bareos on the disaster-recovery lab's backup server and clients: the
# storage daemon's disk full, a client's Director password changed
# (winlab/bareos.py).
from . import bareos as _bareos  # noqa: E402
_bareos.register_faults(_reg)

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
# Kubernetes administration: a kubelet that will not start, the API server
# pointed at etcd's peer port, a leftover taint, a lockdown NetworkPolicy, a
# stopped storage provisioner, a RoleBinding with the wrong subject
# (winlab/kubeadm.py).
from . import kubeadm as _kubeadm  # noqa: E402
_kubeadm.register_faults(_reg)

# Dynamic routing: OSPF timers that disagree, an MTU that stalls the database
# exchange, an eBGP neighbour with the wrong AS (winlab/routing.py).
from . import routing as _routing  # noqa: E402
_routing.register_faults(_reg)

# Advanced networking on open source: a leaf that stopped advertising its
# VXLAN VNI in EVPN, a keepalived pair split by a VRID that differs, a flow
# exporter sending to the wrong port (winlab/advnet.py).
from . import advnet as _advnet  # noqa: E402
_advnet.register_faults(_reg)

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

# Monitoring dashboards: rule files Prometheus no longer finds, Grafana's
# data source on the wrong port, a silence that swallows every alert
# (winlab/dashlab.py).
from . import dashlab as _dashlab  # noqa: E402
_dashlab.register_faults(_reg)
# The AI data center: a drained node, GPU counts that drift, a MUNGE key and
# a clock that lock a node out, an NFS export on the wrong network, a full
# checkpoint volume, a model moved under the server, a context too big for
# memory (winlab/aidc.py).
from . import aidc as _aidc  # noqa: E402
_aidc.register_faults(_reg)
# The aws-cloud lab: a login script that overrides the CLI's region, a
# pipeline policy that names the bucket instead of its objects, the lab's
# root gone from ops01's trust store (winlab/aws.py).
from . import aws as _aws  # noqa: E402
_aws.register_faults(_reg)
# The azure-admin lab: a ReadOnly lock left from an audit, an allowed-locations
# assignment with the wrong values, a stored access policy that expired, a
# slot swap that moved the database setting (winlab/azure.py).
from . import azure as _azure  # noqa: E402
_azure.register_faults(_reg)
# Remote support: the Mesh Agent stopped, a hosts entry that sends it to the
# wrong server, MeshCentral unable to bind port 443 (winlab/remotesupport.py).
from . import remotesupport as _remotesupport  # noqa: E402
_remotesupport.register_faults(_reg)

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

# Network automation: the inventory's network_cli gone (winlab/netauto.py).
from . import netauto as _netauto  # noqa: E402
_netauto.register_faults(_reg)

# The admin's documentation tools: a PC's GLPI Agent stopped, the wiki's data
# folder not writable, GLPI's database switched off (winlab/doctools.py).
from . import doctools as _doctools  # noqa: E402
_doctools.register_faults(_reg)

# Network operations: LibreNMS's poller container stopped with no restart
# policy (winlab/netops.py).
from . import netops as _netops  # noqa: E402
_netops.register_faults(_reg)

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

# Switch security and device logins: a rogue DHCP server someone plugged into the
# office LAN, the RADIUS server's key for the router retyped wrong
# (winlab/snooping.py, winlab/aaa.py).
from . import aaa as _aaa  # noqa: E402
from . import snooping as _snooping  # noqa: E402
_snooping.register_faults(_reg)
_aaa.register_faults(_reg)

# Faults winlab breaks from outside the machine: a DC's disk reverted to a
# checkpoint (winlab/dcrollback.py). host_break runs them for `winlab break`
# and the Break button; the verify still runs inside the machine.
# HR's joiner and leaver requests (winlab/lifecycle.py) set a scene on the DC
# and the mail server and mail the helpdesk: "module:function" names which.
HOST_BREAKS = {"dc-rollback": "winlab.dcrollback", "voice-vlan": "winlab.lldp",
               "hr-joiner": "winlab.lifecycle:joiner_break", "hr-leaver": "winlab.lifecycle:leaver_break",
               "ios-confreg": "winlab.iosboot:confreg_break", "ios-lockout": "winlab.iosboot:lockout_break",
               "poe-budget": "winlab.poe", "phys-split": "winlab.cabletest:split_break",
               "phys-wrong-port": "winlab.cabletest:wrong_port_break"}


def _host_module(scenario_id: str):
    import importlib
    modname, _, fn = HOST_BREAKS[SCENARIOS[scenario_id].host].partition(":")
    mod = importlib.import_module(modname)
    return mod, getattr(mod, fn or "host_break")


def host_break(scenario_id: str, lab_name: str, node: str, clear: bool = False,
               say=lambda line: None) -> tuple[bool, str]:
    return _host_module(scenario_id)[1](lab_name, node, clear, say=say)


def host_break_is_quick(scenario_id: str) -> bool:
    """Whether a break from outside takes seconds (the desktop waits for it
    and says what happened) rather than minutes and a restart."""
    return bool(getattr(_host_module(scenario_id)[0], "QUICK", False))
# Security operations: a WEF source that cannot read its Security log, a Wazuh
# agent pointed at a server that is gone, a scan target that stopped answering
# ping, legacy audit policy overriding the baseline, the software share closed
# to computers, Chocolatey sent to the internet, a certificate nothing will
# renew, the daily report's log folder locked (winlab/secops.py).
from . import secops as _secops  # noqa: E402
_secops.register_faults(_reg)
# A phone's switch port advertising the wrong voice VLAN over LLDP-MED, set
# from outside the phone (winlab/lldp.py).
from . import lldp as _lldp  # noqa: E402
_lldp.register_faults(_reg)
# The Linux track: an idmap range too small, a file server's lost trust, a
# share folder's Linux permissions reset, SMB1 only, a zone file BIND will not
# load, and Windows DNS refusing the transfer to BIND (winlab/linuxdomain.py).
from . import linuxdomain as _linuxdomain  # noqa: E402
_linuxdomain.register_faults(_reg)
# File sharing: share permissions cut to Read, access-based enumeration off, a
# namespace folder's targets offline, the DFS Replication firewall rules closed,
# a Samba share limited to the wrong network (winlab/filesharing.py).
from . import filesharing as _filesharing  # noqa: E402
_filesharing.register_faults(_reg)
# EIGRP and HSRP on the router-protocols lab: rtr-edge put in another EIGRP AS,
# rtr-edge's HSRP speaker on the other version (winlab/ioseigrp.py, winlab/ioshsrp.py).
from . import ioseigrp as _ioseigrp  # noqa: E402
from . import ioshsrp as _ioshsrp  # noqa: E402
_ioseigrp.register_faults(_reg)
_ioshsrp.register_faults(_reg)
# The router console's layer 3 services on the router-protocols lab: a NAT
# pool exhausted and an IP SLA never scheduled (broken on the lab router's
# console settings), and on rtr-edge an OSPF key, a PIM RP and an IS-IS area
# and level that no longer match the lab router's (winlab/consolel3.py).
from . import consolel3 as _consolel3  # noqa: E402
_consolel3.register_faults(_reg)
HOST_BREAKS.update(_consolel3.HOSTS)
# The router console's CCNP routing on the router-protocols lab: a BGP
# prefix-list and an iBGP next hop broken on the lab router's console
# settings, and on rtr-edge an OSPF stub flag and the LDP loopback taken
# out of OSPF (winlab/ccnpfaults.py).
from . import ccnpfaults as _ccnpfaults  # noqa: E402
_ccnpfaults.register_faults(_reg)
HOST_BREAKS.update(_ccnpfaults.HOSTS)
# HR's requests for a joiner and a leaver, worked from osTicket through AD,
# the mail server and GLPI (winlab/lifecycle.py).
from . import lifecycle as _lifecycle  # noqa: E402
_lifecycle.register_faults(_reg)

# Security incident drills: an SSH brute force and a backdoor account on the
# Ubuntu servers, staged for Wazuh to alert on (winlab/incidents.py).
from . import incidents as _incidents  # noqa: E402
_incidents.register_faults(_reg)

# Printer support: the spooler's dependencies, a queue's driver and port on
# the Windows print server; CUPS's queue switches, device URI, driver filter
# and sharing (winlab/printing.py).
from . import printing as _printing  # noqa: E402
_printing.register_faults(_reg)

# Linux administration basics on linux-by-hand's practice server: a line in
# fstab for a disk that is not there, cron given a user that does not exist,
# a deleted log still held open, a timer systemd cannot parse
# (winlab/linuxadmin.py).
from . import linuxadmin as _linuxadmin  # noqa: E402
_linuxadmin.register_faults(_reg)

# Linux administration, part two, on linux-by-hand's lx01 and lx02: a job
# started at a raised priority, a rootless container's user without
# lingering, a mirror without a member or a spare, and a Kea configuration
# whose pool lies outside its subnet (winlab/linuxplus.py).
from . import linuxplus as _linuxplus  # noqa: E402
_linuxplus.register_faults(_reg)

# Linux identity and single sign-on on linux-in-the-domain: sssd.conf made
# world-readable on the FreeIPA client, sss gone from nsswitch's sudoers
# line, and Grafana holding a client secret Keycloak does not know
# (winlab/linuxidentity.py).
from . import linuxidentity as _linuxidentity  # noqa: E402
_linuxidentity.register_faults(_reg)

# The analyst's desk (CySA+ style, defensive only): a quiet foothold to hunt
# on a server, a reported phishing mail to triage, Sysmon's channel switched
# off, and a Wazuh suppression rule with no condition (winlab/blueteam.py).
from . import blueteam as _blueteam  # noqa: E402
_blueteam.register_faults(_reg)

# Incident response in depth (defensive only, harmless plants): a task to hunt
# across the fleet, a share to sweep with YARA, a beaconing task worked as an
# incident, a Velociraptor client lost, a Zeek script that does not parse, a
# Sigma-converted Wazuh rule with the wrong field names (winlab/irtools.py).
from . import irtools as _irtools  # noqa: E402
_irtools.register_faults(_reg)

# Desktop support on Windows 11: a deleted boot entry, a PC stuck in Safe Mode,
# a hosts-file redirect, a home router's fixed address, a slow start, a memory
# leak and a "PC booster" nuisance (winlab/desksupport.py).
from . import desksupport as _desksupport  # noqa: E402
_desksupport.register_faults(_reg)
# A blue screen at every start after a "driver update" switched the disk
# controller's driver off (winlab/bluescreen.py), and the printer's own
# faults as its sensors report them: a jam, toner empty, an empty tray
# (winlab/printerfaults.py).
from . import bluescreen as _bluescreen  # noqa: E402
from . import printerfaults as _printerfaults  # noqa: E402
_bluescreen.register_faults(_reg)
_printerfaults.register_faults(_reg)

# Windows Server availability and trust: DHCP failover's port closed, an
# RODC's branch group moved to the Denied list, a selective trust's Allowed
# to Authenticate grants removed (winlab/serverha.py).
from . import serverha as _serverha  # noqa: E402
_serverha.register_faults(_reg)
# Windows Server hybrid: a SET team down to one card, a cluster's file share
# witness closed to the cluster, SMB over QUIC's UDP 443 blocked, BranchCache
# switched off on the content server's shares (winlab/wshybrid.py).
from . import wshybrid as _wshybrid  # noqa: E402
_wshybrid.register_faults(_reg)

# The router's and the switches' start-up: a configuration register left at
# 0x2142 after a password recovery, and a switch nobody can log in to with a
# PC's port shut (winlab/iosboot.py; both end with the lab's power cut).
from . import iosboot as _iosboot  # noqa: E402
_iosboot.register_faults(_reg)

# DevOps: a runner pointed at a Forgejo that is not there, the deploy target's
# Docker no longer trusting the lab registry over HTTP, the deploy account's
# .ssh opened up so sshd's StrictModes ignores its key (winlab/devops.py).
from . import devops as _devops  # noqa: E402
_devops.register_faults(_reg)

# Desk-side support, second batch: the troubleshooting method on a ticket
# mailed to the lab's osTicket (an outbound rule blocking SMB), a PC on the
# DHCP server's deny filter (APIPA), a broken Winsock catalog, one user's
# proxy left on, and a metered office network (winlab/deskops.py).
from . import deskops as _deskops  # noqa: E402
_deskops.register_faults(_reg)
HOST_BREAKS.update(_deskops.HOST_BREAKS)
# The physical layer on the workbench switches: a desk with link lights and
# no network (a split pair the cable tester finds), a cable in a port of
# another VLAN traced with the toner (winlab/cabletest.py), and a PoE budget
# used up by new access points (winlab/poe.py).
from . import cabletest as _cabletest  # noqa: E402
from . import poe as _poe  # noqa: E402
_cabletest.register_faults(_reg)
_poe.register_faults(_reg)
# CCNA and Network+ basics, broken on the switches and the router from outside
# the PC (a native VLAN mismatch, a VLAN missing from a trunk, a port in the
# wrong VLAN, err-disabled, a duplex mismatch, an access list the wrong way
# round, NAT's sides swapped, another machine's address) and inside it (a
# wrong gateway, a wrong mask) (winlab/netbasics.py).
from . import netbasics as _netbasics  # noqa: E402
_netbasics.register_faults(_reg)
HOST_BREAKS.update(_netbasics.HOSTS)
# Rapid spanning tree: core's port to the floor switch given PortFast and BPDU
# guard as if a desk were there, so the floor switch's BPDUs err-disable it
# (winlab/stp.py; mstpd enforces it on the router when it was fetched).
from . import stp as _stp  # noqa: E402
_stp.register_faults(_reg)
HOST_BREAKS.update(_stp.HOSTS)
# Storm control err-disabling a server's port, a private-VLAN host in the
# wrong community, an IPv6 list that blocks neighbour discovery and RA guard
# on the uplink to the router, set from outside the machines (winlab/l2checks.py).
from . import l2checks as _l2checks  # noqa: E402
_l2checks.register_faults(_reg)
HOST_BREAKS.update(_l2checks.HOSTS)
# FTP backups of the devices' configurations: the backup account's folder
# given to root, so vsftpd refuses the upload after a good login
# (winlab/ftpscp.py).
from . import ftpscp as _ftpscp  # noqa: E402
_ftpscp.register_faults(_reg)
# Wi-Fi on a Linux laptop over the real air (vwifi): the access point's key
# rotated under a saved profile, a profile pinned to the other band
# (winlab/vwifi.py).
from . import vwifi as _vwifi  # noqa: E402
_vwifi.register_faults(_reg)
HOST_BREAKS[_vwifi.HOST_KEY] = "winlab.vwifi:key_rotated_break"
# Vendor Wi-Fi gear: a WLAN out of the 9800-style controller's policy tag, a
# lightweight AP sent by DNS to a retired controller, an EWC's guest WLAN lost
# on reload without write memory, an Aruba change never committed, an AP's
# RADIUS secret that no longer matches NPS's (winlab/wifivendors.py).
from . import wifivendors as _wifivendors  # noqa: E402
_wifivendors.register_faults(_reg)
HOST_BREAKS.update(_wifivendors.HOSTS)
# The company phone's MDM: Headwind MDM's panel moved off the port the phones
# were enrolled with, a pushed app's stored URL naming the server's old name
# (winlab/hmdm.py).
from . import hmdm as _hmdm  # noqa: E402
_hmdm.register_faults(_reg)
# Server hardware and storage (Server+ style): a member kicked out of the
# student's md RAID array on lx01, a data disk taken offline under an
# OfflineAll SAN policy on fs01 (winlab/serverhw.py).
from . import serverhw as _serverhw  # noqa: E402
_serverhw.register_faults(_reg)

# PC technician calls on Windows 11 (CompTIA A+ Core 2 software troubleshooting):
# USB storage disabled, no sound, a custom display scale, an Edge policy
# hijack, an app missing its runtime, a broken .log association, a mapped
# drive to a retired server, search off, a runaway log, a tiny page file, UAC
# denying standard users, a user's keyboard and region (winlab/pcsupport.py).
from . import pcsupport as _pcsupport  # noqa: E402
_pcsupport.register_faults(_reg)


# Hardware faults of a PC, set from outside it and found at the bench and in
# Windows: a dead or overloaded power supply, a stick that stops POST or is
# not detected, a dead CPU fan, a flat CMOS battery, a loose network card or
# SATA cable, no video after a processor swap, a drive failing SMART
# (winlab/hwfaults.py, winlab/pcbuild.py).
from . import hwfaults as _hwfaults  # noqa: E402
_hwfaults.register_faults(_reg)
HOST_BREAKS.update(_hwfaults.HOSTS)
# What a lab with no PC fills them with: a verify that cannot pass.
DEFAULTS.update(_hwfaults.DEFAULTS)
