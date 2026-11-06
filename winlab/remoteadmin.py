"""Remote administration between lab machines.

Remote Desktop, PowerShell remoting over WinRM, and the admin tools (RSAT)
are how an administrator runs servers from a desk instead of from each
server's console. In the lab all of it happens from one lab machine to
another, never from this PC: the lab has no path to it.

Three per-machine switches, each a role (desired state, applied and tested
like every other) and each a pair of PowerShell scripts, test and set, so the
Machines window can also turn one on at once over the agent:

  remote-desktop  RDP allowed, Network Level Authentication on, the Remote
                  Desktop firewall group enabled
  winrm           WinRM running at boot with its HTTP listener and firewall
                  rule (servers have it; Windows 11 does not)
  rsat            the admin tools: Windows features on a server; on Windows
                  11, Features on Demand from Microsoft's Languages and
                  Optional Features ISO, which the user imports (fod-win11),
                  as with the SQL Server ISO. Never shipped with winlab.

"Connect from..." types the command (mstsc, Enter-PSSession, compmgmt.msc)
on the source machine's own screen; the student presses Enter there. Three
graded troubleshooting scenarios register with guestfaults.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .model import WINDOWS_CLIENT

if TYPE_CHECKING:
    from .dsc import NodeConfig

FOD_MEDIA = "fod-win11"
# The Remote Desktop firewall group by its resource string, which is the
# same on every display language. Double-quoted in the scripts: a quote then
# an @ would end the here-string a Script body travels in.
RDP_GROUP = "@FirewallAPI.dll,-28752"
_TS = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
_RDP_TCP = _TS + "\\WinStations\\RDP-Tcp"
# Remote Desktop Users, by its well-known SID.
RDU_SID = "S-1-5-32-555"

RDP_TEST = (
    f"$deny = (Get-ItemProperty -Path '{_TS}').fDenyTSConnections\n"
    f"$nla = (Get-ItemProperty -Path '{_RDP_TCP}').UserAuthentication\n"
    f"$off = @(Get-NetFirewallRule -Group \"{RDP_GROUP}\" -ErrorAction SilentlyContinue | "
    "Where-Object { $_.Direction -eq 'Inbound' -and [string]$_.Enabled -ne 'True' })\n"
    "[bool]($deny -eq 0 -and $nla -eq 1 -and $off.Count -eq 0)"
)
RDP_SET = (
    f"Set-ItemProperty -Path '{_TS}' -Name fDenyTSConnections -Value 0\n"
    f"Set-ItemProperty -Path '{_RDP_TCP}' -Name UserAuthentication -Value 1\n"
    f"Enable-NetFirewallRule -Group \"{RDP_GROUP}\""
)

WINRM_TEST = (
    "$s = Get-Service -Name WinRM -ErrorAction SilentlyContinue\n"
    "$l = @(Get-ChildItem -Path WSMan:\\localhost\\Listener -ErrorAction SilentlyContinue | "
    "Where-Object { $_.Keys -contains 'Transport=HTTP' })\n"
    "$r = Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP' -ErrorAction SilentlyContinue\n"
    "[bool]($s -and $s.Status -eq 'Running' -and [string]$s.StartType -eq 'Automatic' -and "
    "$l.Count -gt 0 -and $r -and [string]$r.Enabled -eq 'True')"
)
WINRM_SET = (
    # SkipNetworkProfileCheck: a lab network can be Public until the domain
    # profile is found; the Public rule stays limited to the local subnet.
    "Set-Service -Name WinRM -StartupType Automatic\n"
    "Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null\n"
    "Enable-NetFirewallRule -Name 'WINRM-HTTP-In-TCP'"
)

# The tools a lab's roles call for, as Windows 11 capabilities.
RSAT_CAPABILITIES = (
    "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0",
    "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0",
    "Rsat.Dns.Tools~~~~0.0.1.0",
    "Rsat.DHCP.Tools~~~~0.0.1.0",
    "Rsat.FileServices.Tools~~~~0.0.1.0",
    "Rsat.ServerManager.Tools~~~~0.0.1.0",
)
# The same on a server: Windows features, installable offline from the
# component store. Server Core takes the PowerShell modules only.
RSAT_FEATURES = ("RSAT-AD-Tools", "GPMC", "RSAT-DNS-Server", "RSAT-DHCP", "RSAT-File-Services")
RSAT_FEATURES_CORE = ("RSAT-AD-PowerShell", "RSAT-DNS-Server", "RSAT-DHCP")

_CAPS = "$caps = @(" + ", ".join(f"'{c}'" for c in RSAT_CAPABILITIES) + ")\n"
RSAT_CLIENT_TEST = (
    _CAPS
    + "$missing = @($caps | Where-Object { (Get-WindowsCapability -Online -Name $_).State -ne 'Installed' })\n"
    "$missing.Count -eq 0"
)
RSAT_CLIENT_SET = (
    _CAPS
    # The ISO's payload is under LanguagesAndOptionalFeatures (Windows 11) or
    # at its root (older discs): whichever holds a metadata folder.
    + "$src = ''\n"
    "foreach ($v in @(Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter })) {\n"
    "    foreach ($p in @(('{0}:\\LanguagesAndOptionalFeatures' -f $v.DriveLetter), ('{0}:\\' -f $v.DriveLetter))) {\n"
    "        if (-not $src -and (Test-Path (Join-Path $p 'metadata'))) { $src = $p }\n"
    "    }\n"
    "}\n"
    "$failed = @()\n"
    "foreach ($c in $caps) {\n"
    "    if ((Get-WindowsCapability -Online -Name $c).State -eq 'Installed') { continue }\n"
    "    try {\n"
    "        if ($src) { Add-WindowsCapability -Online -Name $c -Source $src -LimitAccess -ErrorAction Stop | Out-Null }\n"
    "        else { Add-WindowsCapability -Online -Name $c -LimitAccess -ErrorAction Stop | Out-Null }\n"
    "    } catch { $failed += $c }\n"
    "}\n"
    "if ($failed.Count) {\n"
    "    if ($src) { throw ('RSAT: {0} would not install from {1}: is it the Languages and Optional Features ISO "
    "of this Windows build?' -f ($failed -join ', '), $src) }\n"
    "    throw ('RSAT: {0} need the Features on Demand media, and the lab has no internet: import Microsoft''s "
    f"Languages and Optional Features ISO (winlab images import {FOD_MEDIA} <file.iso>) and apply again' "
    "-f ($failed -join ', '))\n"
    "}"
)


def _feature_test(names) -> str:
    arr = ", ".join(f"'{n}'" for n in names)
    return f"@(Get-WindowsFeature -Name @({arr}) | Where-Object {{ -not $_.Installed }}).Count -eq 0"


def _feature_set(names) -> str:
    arr = ", ".join(f"'{n}'" for n in names)
    return f"Install-WindowsFeature -Name @({arr}) -IncludeAllSubFeature | Out-Null"


def scripts(feature: str, kind: str, core: bool = False) -> tuple[str, str]:
    """(test, set) for one switch on a machine of this kind."""
    if feature == "remote-desktop":
        return RDP_TEST, RDP_SET
    if feature == "winrm":
        return WINRM_TEST, WINRM_SET
    if feature == "rsat":
        if kind == WINDOWS_CLIENT:
            return RSAT_CLIENT_TEST, RSAT_CLIENT_SET
        names = RSAT_FEATURES_CORE if core else RSAT_FEATURES
        return _feature_test(names), _feature_set(names)
    raise KeyError(feature)


FEATURES = {
    "remote-desktop": "Remote Desktop (with NLA and the firewall rule)",
    "winrm": "PowerShell remoting (WinRM and its firewall rule)",
    "rsat": "Admin tools (RSAT: AD, Group Policy, DNS, DHCP, file services, Server Manager)",
}


# ----------------------------------------------------------------- roles
def build_remote_desktop(cfg: NodeConfig) -> None:
    test, set_ = scripts("remote-desktop", cfg.node.kind)
    cfg.script("RemoteDesktopOn", test, set_)
    cfg.notes.append("remote-desktop: RDP on, NLA required, the Remote Desktop firewall group enabled; "
                     "who may sign in is the Remote Desktop Users group, left to you")


def build_winrm(cfg: NodeConfig) -> None:
    test, set_ = scripts("winrm", cfg.node.kind)
    cfg.script("PowerShellRemoting", test, set_)


def build_rsat(cfg: NodeConfig) -> None:
    if cfg.node.kind == WINDOWS_CLIENT:
        test, set_ = scripts("rsat", cfg.node.kind)
        cfg.script("RsatCapabilities", test, set_)
        cfg.notes.append(f"rsat: Features on Demand from the {FOD_MEDIA} ISO in the DVD drive")
        return
    for name in (RSAT_FEATURES_CORE if cfg.node.is_server_core else RSAT_FEATURES):
        cfg.feature(name, subfeatures=name == "RSAT-AD-Tools")


BUILDERS = {"remote-desktop": build_remote_desktop, "winrm": build_winrm, "rsat": build_rsat}


# ----------------------------------------------------------------- connect from
# (id, menu label, what it opens)
METHODS = (
    ("rdp", "Remote Desktop", "mstsc"),
    ("ps", "PowerShell session", "Enter-PSSession"),
    ("mmc", "Computer Management", "compmgmt.msc"),
)


class RemoteError(Exception):
    pass


def _in_domain(node) -> bool:
    return bool({"ad-ds", "domain-join"} & set(node.roles))


def connect_command(lab, source_id: str, target_id: str, how: str) -> dict:
    """What to type on source to reach target: {text, run, note}. run: open
    the Run box first (Win+R); a Server Core source has no desktop, so the
    text goes into its console as it stands."""
    from . import naming
    src, dst = lab.nodes.get(source_id), lab.nodes.get(target_id)
    if src is None or dst is None:
        raise RemoteError(f"no machine {source_id if src is None else target_id} in {lab.name}")
    if source_id == target_id:
        raise RemoteError("pick another machine to connect from")
    if not src.is_windows or not dst.is_windows:
        raise RemoteError("Connect from works between Windows machines; use ssh from a Linux one")
    host = naming.hostname_of(dst)
    shown = naming.display(lab, source_id)
    if how in ("rdp", "mmc") and src.is_server_core:
        raise RemoteError(f"{shown} is Server Core: no Remote Desktop client and no MMC there. "
                          "Use a PowerShell session from it, or connect from a machine with a desktop")
    note = (f"{host} is Server Core: Computer Management works against it once its firewall "
            "allows Remote Event Log Management and Remote Service Management"
            if how == "mmc" and dst.is_server_core else "")
    domain = _in_domain(src) and _in_domain(dst) and bool(lab.domain)
    if how == "rdp":
        text = f"mstsc /v:{host}"
        note = note or ("Sign in as a domain admin, or a user in Remote Desktop Users on " + host
                        if domain else f"Sign in as {host}\\Administrator")
    elif how == "ps":
        cred = "" if domain else f" -Credential {host}\\Administrator"
        text = f"powershell -NoExit -Command Enter-PSSession -ComputerName {host}{cred}"
        note = note or ("Kerberos inside the domain: no password asked" if domain else
                        f"Outside a domain, {shown} must list {host} in TrustedHosts first: "
                        f"Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value {host}")
    elif how == "mmc":
        text = f"compmgmt.msc /computer:{host}"
        note = note or f"Runs as you on {shown}: a domain admin, or the same local account on both"
    else:
        raise RemoteError(f"unknown way to connect {how!r} (one of {', '.join(m[0] for m in METHODS)})")
    return {"ok": True, "text": text, "run": not src.is_server_core, "note": note,
            "message": f"{shown}: {text}"}


# ----------------------------------------------------------------- desktop actions
def act(dash, action: str, params: dict) -> dict:
    try:
        return _act(dash, action, params)
    except (RemoteError, KeyError) as exc:
        return {"ok": False, "message": str(exc).strip("'")}


def _act(dash, action: str, params: dict) -> dict:
    # Only Connect from…: turning RDP, WinRM or RSAT on is the student's work
    # inside the machine (the roles are for `winlab roles apply`, CI and the game).
    lab = dash.lab
    node_id = params.get("node", "")
    if action == "remote-connect":
        return connect_command(lab, params.get("source", ""), node_id, params.get("how", ""))
    raise RemoteError(f"unknown action {action}")


# ----------------------------------------------------------------- guest faults
def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [
        GuestFault(
            id="winrm-stopped",
            title="PowerShell remoting to a server fails",
            os=WINDOWS,
            teaches="WinRM as a service with a listener, Test-WSMan, and telling a refused port from a filtered one",
            symptom="Enter-PSSession and Invoke-Command to this machine fail with 'WinRM cannot complete the operation', "
                    "Server Manager shows it as 'Online - cannot get data'; it answers ping and RDP",
            apply="Set-Service -Name WinRM -StartupType Disabled; Stop-Service -Name WinRM -Force",
            clear="Set-Service -Name WinRM -StartupType Automatic; Start-Service -Name WinRM",
            hints=(
                "From another lab machine, ask WinRM itself: Test-WSMan <this machine>. Then the port: "
                "Test-NetConnection <this machine> -Port 5985. 'Refused' (TcpTestSucceeded False at once) means the "
                "machine answered and nothing listens; a long wait would point at a firewall instead.",
                "On the machine: Get-Service WinRM shows it Stopped, and its StartType is Disabled, so it would not "
                "come back after a reboot either. Get-NetTCPConnection -LocalPort 5985 -State Listen shows nothing.",
                "Set-Service WinRM -StartupType Automatic; Start-Service WinRM (or Enable-PSRemoting -Force, which also "
                "checks the listener and the firewall rule). Then Test-WSMan from the other machine answers, and "
                "Enter-PSSession works again.",
            ),
            verify="$s = Get-Service -Name WinRM; $l = Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue; "
                   "($s.Status -eq 'Running' -and [string]$s.StartType -eq 'Automatic' -and [bool]$l)",
        ),
        GuestFault(
            id="rdp-rule-disabled",
            title="Remote Desktop's firewall rules are switched off",
            os=WINDOWS,
            teaches="allow rules versus the default inbound block, firewall rule groups, and checking that a rule is "
                    "enabled rather than present",
            symptom="mstsc to this machine waits and then says it cannot connect; ping works, RDP is allowed in "
                    "System Properties, and nobody added a block rule",
            apply=f"Disable-NetFirewallRule -Group \"{RDP_GROUP}\"",
            clear=f"Enable-NetFirewallRule -Group \"{RDP_GROUP}\"",
            hints=(
                "Separate the service from the path. On the machine, Get-NetTCPConnection -LocalPort 3389 -State Listen "
                "shows Remote Desktop listening; from another machine Test-NetConnection <it> -Port 3389 times out. "
                "So the firewall drops it.",
                "Look for a block rule first: there is none. Inbound traffic with no allow rule is blocked by default, "
                "so read the allow rules: Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Select-Object "
                "DisplayName, Enabled, Profile. They are all there, and Enabled is False.",
                "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' (or wf.msc, Inbound Rules, the Remote Desktop "
                "group, Enable Rule). Test-NetConnection -Port 3389 succeeds and mstsc connects. A rule that exists "
                "but is disabled does nothing.",
            ),
            verify=f"@(Get-NetFirewallRule -Group \"{RDP_GROUP}\" | Where-Object {{ $_.Direction -eq 'Inbound' -and "
                   "$_.Name -like 'RemoteDesktop-UserMode-In-TCP*' -and [string]$_.Enabled -eq 'True' }).Count -gt 0",
        ),
        GuestFault(
            id="rdp-user-not-allowed",
            roles=("domain-join",),
            title="The IT group can no longer Remote Desktop in",
            os=WINDOWS,
            teaches="the Remote Desktop Users group, the 'Allow log on through Remote Desktop Services' right, and "
                    "granting a group rather than people",
            symptom="an IT user (cwright) gets 'The connection was denied because the user account is not authorized "
                    "for remote login'; administrators still connect",
            # Whoever was allowed is written down, so the fix can be checked;
            # a machine nobody was allowed on expects the IT group.
            apply=("$f = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json; "
                   f"$m = @(Get-LocalGroupMember -SID '{RDU_SID}' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Name }}); "
                   "if ($m.Count -eq 0) { $m = @(('{0}\\G-IT' -f $f.lab.netbios)) }; "
                   "New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "
                   "Set-Content -Path 'C:\\winlab\\rdp-users.txt' -Value $m; "
                   f"Get-LocalGroupMember -SID '{RDU_SID}' -ErrorAction SilentlyContinue | ForEach-Object {{ "
                   f"Remove-LocalGroupMember -SID '{RDU_SID}' -Member $_.Name -ErrorAction SilentlyContinue }}"),
            clear=("Get-Content -Path 'C:\\winlab\\rdp-users.txt' -ErrorAction SilentlyContinue | ForEach-Object { "
                   f"Add-LocalGroupMember -SID '{RDU_SID}' -Member $_ -ErrorAction SilentlyContinue }}"),
            hints=(
                "The message names the cause: the connection reached the machine and the sign-in was refused, so the "
                "network and the firewall are fine. Who may sign in over RDP? Administrators, and the members of the "
                "local Remote Desktop Users group.",
                "On the machine: Get-LocalGroupMember -Group 'Remote Desktop Users' is empty. (lusrmgr.msc, or "
                "Computer Management from another machine, shows the same.) The IT group used to be in it.",
                "Add-LocalGroupMember -Group 'Remote Desktop Users' -Member 'CORP\\G-IT' (the group, not cwright), "
                "or System Properties > Remote > Select Users. cwright connects with mstsc at once; in a real company "
                "a GPO with Restricted Groups keeps it that way.",
            ),
            verify=("$want = @(Get-Content -Path 'C:\\winlab\\rdp-users.txt' -ErrorAction SilentlyContinue); "
                    f"$have = @(Get-LocalGroupMember -SID '{RDU_SID}' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Name }}); "
                    "$want.Count -gt 0 -and @($want | Where-Object { $have -notcontains $_ }).Count -eq 0"),
        ),
    ]


FAULT_IDS = ("winrm-stopped", "rdp-rule-disabled", "rdp-user-not-allowed")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
