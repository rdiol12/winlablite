"""The role library: every Windows role as DSC resources.

Each builder turns one role into resources on a NodeConfig (dsc.py). Where a
DSC Community module has a resource for the job it is used; where none exists
(Group Policy objects, w32tm, print queues, PerfMon) a Script resource with a
real TestScript does the same thing, so every role has one definition of
"configured" that `roles apply` enforces and `roles test` checks.

Roles read their inputs from the node's facts (vars, nics, devices, the lab's
other machines), all known at plan time, so the PowerShell emitted here is
specific to one machine and carries no decisions of its own beyond what the
guest can only know at run time (which disk is raw, whether an OU exists).

PowerShell inside Block(...) is Windows PowerShell 5.1: no ternary, no ??.
"""

from __future__ import annotations

import ipaddress
import re

from typing import Callable

from . import naming
from .dsc import DscError, NodeConfig, Raw, Resource, ident, ps_quote
from .model import WINDOWS_CLIENT

# ----------------------------------------------------------------- helpers
def _ps_array(items) -> str:
    return "@(" + ", ".join(ps_quote(str(i)) for i in items) + ")"


def _ou_dn(path: str, base: str) -> str:
    """'Corp/Users' -> 'OU=Users,OU=Corp,DC=corp,DC=lab'."""
    parts = [p for p in path.split("/") if p]
    return ",".join(f"OU={p}" for p in reversed(parts)) + "," + base


DEFAULT_OUS = ["Corp", "Corp/Users", "Corp/Admins", "Corp/Servers",
               "Corp/Workstations", "Corp/Groups", "Corp/ServiceAccounts"]

DEFAULT_USERS = [
    {"sam": "asmith", "name": "Alice Smith", "dept": "Sales"},
    {"sam": "bjones", "name": "Bob Jones", "dept": "Sales"},
    {"sam": "cwright", "name": "Carol Wright", "dept": "IT"},
    {"sam": "dlee", "name": "David Lee", "dept": "Finance"},
]

# AGDLP worked example: accounts -> global -> domain-local -> permission.
DEFAULT_GROUPS = [
    {"name": "G-Sales", "scope": "Global", "category": "Security", "members": ["asmith", "bjones"]},
    {"name": "G-IT", "scope": "Global", "category": "Security", "members": ["cwright"]},
    {"name": "DL-Sales-Share", "scope": "DomainLocal", "category": "Security", "members": ["G-Sales"]},
    {"name": "U-AllStaff", "scope": "Universal", "category": "Security", "members": ["G-Sales", "G-IT"]},
    {"name": "DL-Announce", "scope": "DomainLocal", "category": "Distribution", "members": []},
]


def _ad_tools(cfg: NodeConfig) -> list[str]:
    """RSAT so AD and GPO cmdlets exist on a member server too."""
    return [cfg.feature("RSAT-AD-PowerShell"), cfg.feature("GPMC")]


def _domain(cfg: NodeConfig) -> str:
    return cfg.domain_ready or cfg.ensure_domain_ready()


def gpo(cfg: NodeConfig, name: str, values: list[tuple[str, str, str, object]],
        links: list[str], depends: list[str] | None = None) -> str:
    """A Group Policy object with registry policy values, linked to the given
    DNs (a link target that does not exist is skipped, so a GPO can be
    declared before the OU tree is built). values: (key, value name, DWord|String, value)."""
    want = ",\n".join(
        f"    @{{ Key = {ps_quote(k)}; Name = {ps_quote(v)}; Type = {ps_quote(t)}; "
        f"Value = {ps_quote(str(val)) if t == 'String' else int(val)} }}"
        for k, v, t, val in values)
    common = (
        "Import-Module GroupPolicy\n"
        "Import-Module ActiveDirectory\n"
        f"$name = {ps_quote(name)}\n"
        f"$want = @(\n{want}\n)\n"
        f"$targets = {_ps_array(links)}\n"
        "function Test-Dn($dn) { try { [bool](Get-ADObject -Identity $dn -ErrorAction Stop) } catch { $false } }\n"
    )
    test = common + (
        "$g = Get-GPO -Name $name -ErrorAction SilentlyContinue\n"
        "if (-not $g) { return $false }\n"
        "foreach ($w in $want) {\n"
        "    $cur = Get-GPRegistryValue -Name $name -Key $w.Key -ValueName $w.Name -ErrorAction SilentlyContinue\n"
        "    if (-not $cur) { return $false }\n"
        "    if ([string]$cur.Value -ne [string]$w.Value) { return $false }\n"
        "}\n"
        "foreach ($t in $targets) {\n"
        "    if (-not (Test-Dn $t)) { continue }\n"
        "    $linked = @((Get-GPInheritance -Target $t).GpoLinks | ForEach-Object { $_.DisplayName })\n"
        "    if ($linked -notcontains $name) { return $false }\n"
        "}\n"
        "$true"
    )
    set_ = common + (
        "$g = Get-GPO -Name $name -ErrorAction SilentlyContinue\n"
        "if (-not $g) { $g = New-GPO -Name $name }\n"
        "foreach ($w in $want) {\n"
        "    Set-GPRegistryValue -Name $name -Key $w.Key -ValueName $w.Name -Type $w.Type -Value $w.Value | Out-Null\n"
        "}\n"
        "foreach ($t in $targets) {\n"
        "    if (-not (Test-Dn $t)) { continue }\n"
        "    $linked = @((Get-GPInheritance -Target $t).GpoLinks | ForEach-Object { $_.DisplayName })\n"
        "    if ($linked -notcontains $name) { New-GPLink -Guid $g.Id -Target $t | Out-Null }\n"
        "}"
    )
    deps = _ad_tools(cfg) + [_domain(cfg)] + list(depends or [])
    return cfg.script(f"GPO_{ident(name)}", test, set_, depends=deps, run_as=True)


def ensure_data_volume(cfg: NodeConfig) -> str:
    """The node's first data disk, NTFS, labelled Data, always at D:. Whatever
    held D: (the winlab payload volume, a CD) moves out of the way; the payload
    is only read once at first logon. A node without a data disk gets nothing
    here and its roles use C:."""
    if not cfg.node.data_disks_gb:
        return ""
    rid = "[Script]DataVolume"
    if cfg.has(rid):
        return rid
    test = (
        "$v = Get-Volume -DriveLetter D -ErrorAction SilentlyContinue\n"
        "[bool]($v -and $v.FileSystemLabel -eq 'Data')"
    )
    set_ = (
        "$occupant = Get-Volume -DriveLetter D -ErrorAction SilentlyContinue\n"
        "if ($occupant -and $occupant.FileSystemLabel -ne 'Data') {\n"
        "    $free = @([char[]](90..84) | ForEach-Object { [string]$_ } |\n"
        "        Where-Object { -not (Get-Volume -DriveLetter $_ -ErrorAction SilentlyContinue) })[0]\n"
        "    $part = Get-Partition -DriveLetter D -ErrorAction SilentlyContinue\n"
        "    if ($part) { $part | Set-Partition -NewDriveLetter $free }\n"
        "    else { Get-CimInstance Win32_Volume -Filter \"DriveLetter='D:'\" | Set-CimInstance -Property @{ DriveLetter = \"${free}:\" } }\n"
        "}\n"
        "$data = Get-Volume -FileSystemLabel 'Data' -ErrorAction SilentlyContinue | Select-Object -First 1\n"
        "if ($data) {\n"
        "    Get-Partition -Volume $data | Set-Partition -NewDriveLetter D\n"
        "    return\n"
        "}\n"
        "$disk = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Sort-Object Number | Select-Object -First 1\n"
        "if (-not $disk) { throw 'no raw data disk to initialise and no Data volume to attach' }\n"
        "Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru |\n"
        "    New-Partition -DriveLetter D -UseMaximumSize |\n"
        "    Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Data' -Confirm:$false | Out-Null"
    )
    return cfg.script("DataVolume", test, set_)


def _data_deps(cfg: NodeConfig) -> list[str]:
    v = ensure_data_volume(cfg)
    return [v] if v else []


def _printer_script(cfg: NodeConfig, name: str, driver: str, shared: bool,
                    location: str = "", depends: list[str] | None = None) -> str:
    """A print queue on a software-only port, shared and published to AD when
    asked. Add-PrinterDriver needs the in-box driver by name."""
    port = f"winlab-{name}"
    test = (
        "Import-Module PrintManagement\n"
        f"$p = Get-Printer -Name {ps_quote(name)} -ErrorAction SilentlyContinue\n"
        f"[bool]($p -and $p.Shared -eq ${'true' if shared else 'false'})"
    )
    set_ = (
        "Import-Module PrintManagement\n"
        f"$driver = {ps_quote(driver)}\n"
        f"$port = {ps_quote(port)}\n"
        f"$name = {ps_quote(name)}\n"
        "if (-not (Get-PrinterDriver -Name $driver -ErrorAction SilentlyContinue)) { Add-PrinterDriver -Name $driver }\n"
        "if (-not (Get-PrinterPort -Name $port -ErrorAction SilentlyContinue)) {\n"
        "    Add-PrinterPort -Name $port -PrinterHostAddress '127.0.0.1'\n"
        "}\n"
        "$p = Get-Printer -Name $name -ErrorAction SilentlyContinue\n"
        "if (-not $p) {\n"
        "    Add-Printer -Name $name -DriverName $driver -PortName $port"
        + (f" -Location {ps_quote(location)}" if location else "") + "\n"
        "}\n"
        + ("Set-Printer -Name $name -Shared $true -ShareName $name -Published $true\n" if shared
           else "Set-Printer -Name $name -Shared $false -Published $false\n")
    )
    return cfg.script(f"Printer_{ident(name)}", test, set_, depends=depends)


def _iscsi_target_script(cfg: NodeConfig, target: str, size_gb: int,
                         depends: list[str] | None = None) -> str:
    lun = f"C:\\iSCSI\\{target}.vhdx"
    test = (
        f"[bool](Get-IscsiServerTarget -TargetName {ps_quote(target)} -ErrorAction SilentlyContinue)"
    )
    set_ = (
        "New-Item -ItemType Directory -Path 'C:\\iSCSI' -Force | Out-Null\n"
        f"$lun = {ps_quote(lun)}\n"
        f"if (-not (Test-Path $lun)) {{ New-IscsiVirtualDisk -Path $lun -Size ({size_gb} * 1GB) | Out-Null }}\n"
        f"New-IscsiServerTarget -TargetName {ps_quote(target)} -InitiatorIds 'IQN:*' | Out-Null\n"
        f"Add-IscsiVirtualDiskTargetMapping -TargetName {ps_quote(target)} -Path $lun | Out-Null"
    )
    return cfg.script(f"IscsiTarget_{ident(target)}", test, set_, depends=depends)


# ----------------------------------------------------------------- identity
def build_ou_structure(cfg: NodeConfig) -> None:
    ous = [str(o) for o in (cfg.vars.get("ous") or DEFAULT_OUS)]
    created: dict[str, str] = {}   # OU DN -> resource id
    last = _domain(cfg)
    for path in ous:
        parts = [p for p in path.split("/") if p]
        for i in range(1, len(parts) + 1):
            dn = _ou_dn("/".join(parts[:i]), cfg.base_dn)
            if dn in created:
                continue
            parent = _ou_dn("/".join(parts[:i - 1]), cfg.base_dn) if i > 1 else cfg.base_dn
            deps = [created[parent]] if parent in created else [_domain(cfg)]
            res = cfg.add(Resource("ADOrganizationalUnit", f"OU_{ident('_'.join(parts[:i]))}", {
                "Name": parts[i - 1],
                "Path": parent,
                "Ensure": "Present",
                "ProtectedFromAccidentalDeletion": False,
                "Credential": Raw("$DomainCred"),
            }, depends_on=deps, module="ActiveDirectoryDsc"))
            created[dn] = res.id
            cfg.ous.append(dn)
            last = res.id
    cfg.ou_ready = last


def build_users_groups(cfg: NodeConfig) -> None:
    users_ou = _ou_dn("Corp/Users", cfg.base_dn)
    groups_ou = _ou_dn("Corp/Groups", cfg.base_dn)
    if users_ou not in cfg.ous:
        users_ou = f"CN=Users,{cfg.base_dn}"
    if groups_ou not in cfg.ous:
        groups_ou = f"CN=Users,{cfg.base_dn}"
    after = [cfg.ou_ready or _domain(cfg)]

    users = cfg.vars.get("users") or DEFAULT_USERS
    user_ids: dict[str, str] = {}
    for u in users:
        sam = str(u.get("sam") or "").strip()
        if not sam:
            continue
        display = str(u.get("name") or sam)
        first, _, last = display.partition(" ")
        props = {
            "DomainName": cfg.domain,
            "UserName": sam,
            "Password": Raw("$UserPwCred"),
            "PasswordNeverResets": True,
            "Ensure": "Present",
            "CommonName": display,
            "DisplayName": display,
            "GivenName": first,
            "UserPrincipalName": f"{sam}@{cfg.domain}",
            "Path": users_ou,
            "Enabled": True,
            "ChangePasswordAtLogon": False,
            "Credential": Raw("$DomainCred"),
        }
        if last:
            props["Surname"] = last
        if u.get("dept"):
            props["Department"] = str(u["dept"])
        res = cfg.add(Resource("ADUser", f"User_{ident(sam)}", props,
                               depends_on=after, module="ActiveDirectoryDsc"))
        user_ids[sam] = res.id

    groups = cfg.vars.get("groups") or DEFAULT_GROUPS
    group_ids: dict[str, str] = {}
    for g in groups:
        name = str(g.get("name") or "").strip()
        if not name:
            continue
        members = [str(m) for m in (g.get("members") or [])]
        deps = list(after)
        for m in members:
            if m in user_ids:
                deps.append(user_ids[m])
            elif m in group_ids:
                deps.append(group_ids[m])
        props = {
            "GroupName": name,
            "GroupScope": str(g.get("scope") or "Global"),
            "Category": str(g.get("category") or "Security"),
            "Path": groups_ou,
            "Ensure": "Present",
            "Credential": Raw("$DomainCred"),
        }
        if members:
            props["MembersToInclude"] = members
        res = cfg.add(Resource("ADGroup", f"Group_{ident(name)}", props,
                               depends_on=deps, module="ActiveDirectoryDsc"))
        group_ids[name] = res.id


# Group Policy Preferences drive maps live in Drives.xml under SYSVOL, not in
# registry policy; this writes what the GPMC editor writes.
_DRIVES_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">\n'
    '  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="LETTER:" status="LETTER:" '
    'image="2" changed="CHANGED" uid="UID" bypassErrors="1">\n'
    '    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" '
    'path="SHARE" label="LABEL" persistent="1" useLetter="1" letter="LETTER"/>\n'
    '  </Drive>\n'
    '</Drives>'
)


def build_gpo(cfg: NodeConfig) -> None:
    corp = _ou_dn("Corp", cfg.base_dn)
    workstations = _ou_dn("Corp/Workstations", cfg.base_dn)
    dom = _domain(cfg)

    # 1. Domain password policy (Default Domain Policy). MaxPasswordAge in minutes.
    cfg.add(Resource("ADDomainDefaultPasswordPolicy", "PasswordPolicy", {
        "DomainName": cfg.domain,
        "ComplexityEnabled": True,
        "MinPasswordLength": 12,
        "MaxPasswordAge": 60 * 24 * 60,
        "LockoutThreshold": 5,
        "Credential": Raw("$DomainCred"),
    }, depends_on=[dom], module="ActiveDirectoryDsc"))

    # 2. Drive map GPO at Corp.
    m = cfg.vars.get("drive_map") or {}
    letter = str(m.get("letter") or "S").rstrip(":").upper()
    company = naming.share_name(cfg.lab)
    label = str(m.get("label") or company)
    share = str(m.get("path") or "")
    if not share:
        servers = cfg.facts.get("file_servers") or []
        if servers:
            share = f"\\\\{servers[0]}\\{company}"
    if share:
        gname = f"Map {company} Share"
        xml = (_DRIVES_XML.replace("LETTER", letter).replace("SHARE", share)
               .replace("LABEL", label))
        common = (
            "Import-Module GroupPolicy\n"
            "Import-Module ActiveDirectory\n"
            f"$name = {ps_quote(gname)}\n"
            f"$domain = {ps_quote(cfg.domain)}\n"
            f"$target = {ps_quote(corp)}\n"
            f"$share = {ps_quote(share)}\n"
            f"$letter = {ps_quote(letter)}\n"
        )
        test = common + (
            "$g = Get-GPO -Name $name -ErrorAction SilentlyContinue\n"
            "if (-not $g) { return $false }\n"
            "$gpoId = '{' + $g.Id.ToString().ToUpper() + '}'\n"
            "$xmlPath = \"\\\\$domain\\SYSVOL\\$domain\\Policies\\$gpoId\\User\\Preferences\\Drives\\Drives.xml\"\n"
            "if (-not (Test-Path $xmlPath)) { return $false }\n"
            "$x = Get-Content -Path $xmlPath -Raw\n"
            "if ($x -notmatch [regex]::Escape(\"path=`\"$share`\"\") -or $x -notmatch \"letter=`\"$letter`\"\") { return $false }\n"
            "$linked = @((Get-GPInheritance -Target $target).GpoLinks | ForEach-Object { $_.DisplayName })\n"
            "$linked -contains $name"
        )
        xml_ps = xml.replace("'", "''")
        set_ = common + (
            "$g = Get-GPO -Name $name -ErrorAction SilentlyContinue\n"
            "if (-not $g) { $g = New-GPO -Name $name }\n"
            "$gpoId = '{' + $g.Id.ToString().ToUpper() + '}'\n"
            "$gpoRoot = \"\\\\$domain\\SYSVOL\\$domain\\Policies\\$gpoId\"\n"
            "$dir = \"$gpoRoot\\User\\Preferences\\Drives\"\n"
            "New-Item -ItemType Directory -Path $dir -Force | Out-Null\n"
            "$changed = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')\n"
            "$uid = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'\n"
            f"$xml = '{xml_ps}'\n"
            "$xml = $xml.Replace('CHANGED', $changed).Replace('UID', $uid)\n"
            "Set-Content -Path \"$dir\\Drives.xml\" -Value $xml -Encoding UTF8\n"
            "# Register the Drive Maps client-side extension and bump the user version so clients notice.\n"
            f"$gpoDn = \"CN=$gpoId,CN=Policies,CN=System,{cfg.base_dn}\"\n"
            "$cse = '[{00000000-0000-0000-0000-000000000000}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]' +\n"
            "       '[{5794DAFD-BE60-433F-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]'\n"
            "$ver = [int](Get-ADObject $gpoDn -Properties versionNumber).versionNumber + 65536\n"
            "Set-ADObject $gpoDn -Replace @{ gPCUserExtensionNames = $cse; versionNumber = $ver }\n"
            "Set-Content -Path \"$gpoRoot\\GPT.INI\" -Value \"[General]`r`nVersion=$ver\" -Encoding ASCII\n"
            "$linked = @((Get-GPInheritance -Target $target).GpoLinks | ForEach-Object { $_.DisplayName })\n"
            "if ($linked -notcontains $name) { New-GPLink -Guid $g.Id -Target $target | Out-Null }"
        )
        cfg.script("GPO_Map_Company_Share", test, set_,
                   depends=_ad_tools(cfg) + [dom, cfg.ou_ready or dom], run_as=True)
    else:
        cfg.notes.append("gpo: no file server in the lab and no vars.drive_map; no drive map GPO")

    # 3. Workstation lockdown: a user setting on a computer OU needs loopback.
    gpo(cfg, "Workstation Lockdown", [
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoRun", "DWord", 1),
        ("HKLM\\Software\\Policies\\Microsoft\\Windows\\System", "UserPolicyMode", "DWord", 1),
    ], [workstations], depends=[cfg.ou_ready] if cfg.ou_ready else None)


def build_laps(cfg: NodeConfig) -> None:
    dom = _domain(cfg)
    tools = _ad_tools(cfg)
    schema = cfg.script(
        "LapsSchema",
        "Import-Module ActiveDirectory\n"
        "$schemaNc = (Get-ADRootDSE).schemaNamingContext\n"
        "[bool](Get-ADObject -SearchBase $schemaNc -LDAPFilter '(name=ms-LAPS-Password)' -ErrorAction SilentlyContinue)",
        "Import-Module LAPS\n"
        "Update-LapsADSchema -Confirm:$false",
        depends=tools + [dom], run_as=True)
    ou = _ou_dn("Corp/Workstations", cfg.base_dn)
    cfg.script(
        "LapsSelfPermission",
        "Import-Module ActiveDirectory\n"
        f"$ou = {ps_quote(ou)}\n"
        "try { Get-ADObject -Identity $ou -ErrorAction Stop | Out-Null } catch { return $true }\n"
        "$acl = Get-Acl -Path \"AD:\\$ou\"\n"
        "[bool]($acl.Access | Where-Object { $_.IdentityReference -eq 'NT AUTHORITY\\SELF' -and "
        "$_.ActiveDirectoryRights -match 'WriteProperty' -and $_.InheritanceType -ne 'None' })",
        "Import-Module ActiveDirectory\n"
        "Import-Module LAPS\n"
        f"$ou = {ps_quote(ou)}\n"
        "try { Get-ADObject -Identity $ou -ErrorAction Stop | Out-Null } catch { return }\n"
        "Set-LapsADComputerSelfPermission -Identity $ou | Out-Null",
        depends=[schema], run_as=True)
    gpo(cfg, "Windows LAPS", [
        ("HKLM\\Software\\Microsoft\\Policies\\LAPS", "BackupDirectory", "DWord", 2),
        ("HKLM\\Software\\Microsoft\\Policies\\LAPS", "PasswordAgeDays", "DWord", 30),
        ("HKLM\\Software\\Microsoft\\Policies\\LAPS", "PasswordComplexity", "DWord", 4),
    ], [ou], depends=[schema])


def build_ntp(cfg: NodeConfig) -> None:
    """The PDC emulator is the domain's time authority; everyone else follows
    the domain hierarchy. The forest root holds that FSMO role unless moved.
    Its source is the lab's NTP server when there is one (winlab/timesync.py)."""
    from . import timesync
    if cfg.vars.get("forest_root"):
        cfg.script(
            "TimeAuthority",
            "$p = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters'\n"
            "$c = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config'\n"
            "($p.Type -eq 'NTP') -and ([int]$c.AnnounceFlags -eq 5) -and ((Get-Service w32time).Status -eq 'Running')",
            f"w32tm /config /manualpeerlist:'{timesync.pdc_peers(cfg.lab, cfg.node)}' /syncfromflags:manual "
            "/reliable:yes /update | Out-Null\n"
            "Set-Service w32time -StartupType Automatic\n"
            "Restart-Service w32time\n"
            "w32tm /resync /nowait 2>&1 | Out-Null",
            depends=[_domain(cfg)])
    else:
        cfg.script(
            "TimeFromDomain",
            "$p = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters'\n"
            "($p.Type -eq 'NT5DS') -and ((Get-Service w32time).Status -eq 'Running')",
            "w32tm /config /syncfromflags:domhier /update | Out-Null\n"
            "Set-Service w32time -StartupType Automatic\n"
            "Restart-Service w32time\n"
            "w32tm /resync /nowait 2>&1 | Out-Null",
            depends=[_domain(cfg)])


# ---------------------------------------------------------------- storage
def build_file(cfg: NodeConfig) -> None:
    feat = cfg.feature("FS-FileServer")
    deps = [feat] + _data_deps(cfg)
    company = naming.share_name(cfg.lab)
    path = f"{cfg.data_root}\\Shares\\{company}"
    share = cfg.smb_share(company, path, full=["Administrators"],
                          change=["Authenticated Users"], abe=True, depends=deps)
    # NTFS: the sales resource group gets Modify, to contrast with the share
    # ACL. The group lives on the DC (users-groups role); until it exists the
    # grant waits without failing the file server.
    group = f"{cfg.netbios}\\DL-Sales-Share"
    cfg.script(
        "NtfsSalesModify",
        f"$path = {ps_quote(path)}\n"
        f"$group = {ps_quote(group)}\n"
        "try { (New-Object System.Security.Principal.NTAccount($group)).Translate([System.Security.Principal.SecurityIdentifier]) | Out-Null }\n"
        "catch { return $true }\n"
        "$acl = Get-Acl -Path $path\n"
        "[bool]($acl.Access | Where-Object { $_.IdentityReference -eq $group -and $_.FileSystemRights -match 'Modify' })",
        f"$path = {ps_quote(path)}\n"
        f"$group = {ps_quote(group)}\n"
        "$acl = Get-Acl -Path $path\n"
        "$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(\n"
        "    $group, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')\n"
        "$acl.AddAccessRule($rule)\n"
        "Set-Acl -Path $path -AclObject $acl",
        depends=[share])


def build_dfs(cfg: NodeConfig) -> None:
    feat = cfg.feature("FS-DFS-Namespace")
    tools = cfg.feature("RSAT-DFS-Mgmt-Con")
    dom = _domain(cfg)
    company = naming.share_name(cfg.lab)
    ns_share = cfg.smb_share(f"{company}-NS", f"C:\\DFSRoots\\{company}", full=["Everyone"],
                             depends=[feat])
    root_path = f"\\\\{cfg.domain}\\{company}"
    root = cfg.add(Resource("DFSNamespaceRoot", "Root_Company", {
        "Path": root_path,
        "TargetPath": f"\\\\{cfg.hostname}\\{company}-NS",
        "Type": "DomainV2",
        "Ensure": "Present",
        "Description": f"{cfg.lab.name} company namespace",
    }, depends_on=[feat, tools, dom, ns_share], module="DFSDsc", run_as=True))
    deps = [root.id]
    if company in cfg.share_ids:
        deps.append(cfg.share_ids[company])
    cfg.add(Resource("DFSNamespaceFolder", "Folder_Shared", {
        "Path": f"{root_path}\\Shared",
        "TargetPath": f"\\\\{cfg.hostname}\\{company}",
        "Ensure": "Present",
    }, depends_on=deps, module="DFSDsc", run_as=True))


def build_fsrm(cfg: NodeConfig) -> None:
    feat = cfg.feature("FS-Resource-Manager")
    tools = cfg.feature("RSAT-FSRM-Mgmt")
    company = naming.share_name(cfg.lab)
    path = cfg.share_paths.get(company) or f"{cfg.data_root}\\Shares\\{company}"
    deps = [feat, tools, cfg.directory(path, _data_deps(cfg))]
    grp = cfg.add(Resource("FSRMFileGroup", "ExecutableFiles", {
        "Name": "Executable Files",
        "IncludePattern": ["*.exe", "*.bat", "*.cmd", "*.scr", "*.ps1", "*.vbs"],
        "Ensure": "Present",
    }, depends_on=deps, module="FSRMDsc"))
    cfg.add(Resource("FSRMFileScreen", "Screen_Company", {
        "Path": path,
        "IncludeGroup": ["Executable Files"],
        "Active": True,
        "Description": f"no executables or scripts in the {company} share",
        "Ensure": "Present",
    }, depends_on=[grp.id], module="FSRMDsc"))
    cfg.add(Resource("FSRMQuota", "Quota_Company", {
        "Path": path,
        "Size": 5 * 1024 ** 3,
        "SoftLimit": False,
        "ThresholdPercentages": [85, 95],
        "Description": f"{company} share quota",
        "Ensure": "Present",
    }, depends_on=deps, module="FSRMDsc"))


def build_storage(cfg: NodeConfig) -> None:
    # After the file role's data volume, so the pool takes the spare disks only.
    cfg.script(
        "StoragePool",
        "$canPool = @(Get-PhysicalDisk -CanPool $true -ErrorAction SilentlyContinue)\n"
        "if ($canPool.Count -eq 0) { return $true }\n"
        "[bool](Get-StoragePool -FriendlyName 'LabPool' -ErrorAction SilentlyContinue)",
        "$canPool = @(Get-PhysicalDisk -CanPool $true)\n"
        "$sub = (Get-StorageSubSystem)[0]\n"
        "New-StoragePool -FriendlyName 'LabPool' -StorageSubSystemFriendlyName $sub.FriendlyName -PhysicalDisks $canPool | Out-Null\n"
        "$resiliency = 'Simple'\n"
        "if ($canPool.Count -ge 2) { $resiliency = 'Mirror' }\n"
        "$vd = New-VirtualDisk -StoragePoolFriendlyName 'LabPool' -FriendlyName 'LabVD' -ResiliencySettingName $resiliency -UseMaximumSize\n"
        "$vd | Get-Disk | Initialize-Disk -PassThru |\n"
        "    New-Partition -AssignDriveLetter -UseMaximumSize |\n"
        "    Format-Volume -FileSystem ReFS -NewFileSystemLabel 'Pool' -Confirm:$false | Out-Null",
        get="$pool = Get-StoragePool -FriendlyName 'LabPool' -ErrorAction SilentlyContinue\n"
            "@{ Result = $(if ($pool) { 'LabPool ' + $pool.HealthStatus } else { 'no pool' }) }",
        depends=_data_deps(cfg))
    feat = cfg.feature("FS-iSCSITarget-Server")
    _iscsi_target_script(cfg, "lab-target", 8, depends=[feat])


def build_backup(cfg: NodeConfig) -> None:
    if not cfg.node.data_disks_gb:
        raise DscError(
            f"{cfg.node.id}: the backup role needs a data disk to back up to "
            f"(add data_disks_gb = [20] to the node); Windows Server Backup refuses the system volume")
    feat = cfg.feature("Windows-Server-Backup")
    vol = ensure_data_volume(cfg)
    target = f"{cfg.data_root}\\Backups"
    d = cfg.directory(target, [vol])
    cfg.script(
        "BackupPolicy",
        "Import-Module WindowsServerBackup\n"
        "$p = Get-WBPolicy -ErrorAction SilentlyContinue\n"
        "[bool]($p -and $p.SystemState -and $p.Schedule)",
        "Import-Module WindowsServerBackup\n"
        "$policy = New-WBPolicy\n"
        "Add-WBSystemState -Policy $policy\n"
        "Add-WBVolume -Policy $policy -Volume (Get-WBVolume -VolumePath 'C:') | Out-Null\n"
        f"$tgt = New-WBBackupTarget -VolumePath '{cfg.data_root}'\n"
        "Add-WBBackupTarget -Policy $policy -Target $tgt | Out-Null\n"
        "Set-WBSchedule -Policy $policy -Schedule ([datetime]'02:00') | Out-Null\n"
        "Set-WBPolicy -Policy $policy -Force",
        depends=[feat, d])
    cfg.text_file("RestoreDrill", f"{target}\\RESTORE-DRILL.txt", (
        "AD / system-state recovery drill (do NOT run casually):\r\n"
        "  1. Reboot into Directory Services Restore Mode (DSRM): bcdedit /set safeboot dsrepair\r\n"
        "  2. wbadmin get versions\r\n"
        "  3. wbadmin start systemstaterecovery -version:<id> -authsysvol\r\n"
        "  4. For an authoritative object restore: ntdsutil 'authoritative restore'\r\n"
        "  5. bcdedit /deletevalue safeboot ; reboot\r\n"), depends=[d])


# ------------------------------------------------------------ infrastructure
def build_adcs(cfg: NodeConfig) -> None:
    ca = cfg.feature("ADCS-Cert-Authority")
    web = cfg.feature("ADCS-Web-Enrollment")
    tools = cfg.feature("RSAT-ADCS", subfeatures=True)
    dom = _domain(cfg)
    cn = str(cfg.vars.get("ca_common_name") or f"{cfg.netbios} Issuing CA")
    if cfg.vars.get("parent_ca"):
        # An issuing CA under an offline root (the certificate-authority lab):
        # installed with its request written out; the offline root signs it
        # by hand (winlab/calab.py).
        from . import calab
        calab.build_subordinate(cfg, cn, [ca, tools, dom])
        return
    root = cfg.add(Resource("AdcsCertificationAuthority", "EnterpriseRootCA", {
        "IsSingleInstance": "Yes",
        "CAType": "EnterpriseRootCA",
        "Credential": Raw("$DomainCred"),
        "CACommonName": cn,
        "KeyLength": 2048,
        "HashAlgorithmName": "SHA256",
        "ValidityPeriod": "Years",
        "ValidityPeriodUnits": 10,
        "Ensure": "Present",
    }, depends_on=[ca, tools, dom], module="ActiveDirectoryCSDsc"))
    enrol = cfg.add(Resource("AdcsWebEnrollment", "WebEnrollment", {
        "IsSingleInstance": "Yes",
        "Credential": Raw("$DomainCred"),
        "Ensure": "Present",
    }, depends_on=[web, root.id], module="ActiveDirectoryCSDsc"))
    # The CA in use: templates, autoenrolment, CRL schedule (winlab/pki.py).
    from . import pki
    pki.build_ca(cfg, root.id, enrol.id)


def build_adcs_root(cfg: NodeConfig) -> None:
    """The offline standalone root (winlab/calab.py): a workgroup server."""
    from . import calab
    calab.build_root(cfg)


def build_iis(cfg: NodeConfig) -> None:
    web = cfg.feature("Web-Server")
    tools = cfg.feature("Web-Mgmt-Tools")
    page = cfg.text_file("LandingPage", "C:\\inetpub\\wwwroot\\index.html",
                         f"<h1>winlab</h1><p>{cfg.hostname} serving from {cfg.lab.name}</p>\r\n",
                         depends=[web])
    binding = cfg.script(
        "HttpsBinding",
        "Import-Module WebAdministration\n"
        "$b = Get-WebBinding -Name 'Default Web Site' -Protocol https -ErrorAction SilentlyContinue\n"
        "[bool]($b -and (Test-Path 'IIS:\\SslBindings\\0.0.0.0!443'))",
        "Import-Module WebAdministration\n"
        f"$dns = {ps_quote(cfg.fqdn)}\n"
        "$cert = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.Subject -eq \"CN=$dns\" } | Select-Object -First 1\n"
        "if (-not $cert) { $cert = New-SelfSignedCertificate -DnsName $dns -CertStoreLocation 'Cert:\\LocalMachine\\My' }\n"
        "if (-not (Get-WebBinding -Name 'Default Web Site' -Protocol https -ErrorAction SilentlyContinue)) {\n"
        "    New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443\n"
        "}\n"
        "if (-not (Test-Path 'IIS:\\SslBindings\\0.0.0.0!443')) {\n"
        "    New-Item 'IIS:\\SslBindings\\0.0.0.0!443' -Value $cert | Out-Null\n"
        "}",
        depends=[web, tools, page])
    for port in (80, 443):
        cfg.firewall(f"winlab-iis-{port}", local_port=[str(port)], depends=[web])
    from . import pki
    pki.build_iis(cfg, binding)


def build_firewall(cfg: NodeConfig) -> None:
    for prof in ("Domain", "Private", "Public"):
        cfg.add(Resource("FirewallProfile", f"Profile_{prof}", {
            "Name": prof, "Enabled": "True",
        }, module="NetworkingDsc"))
    for p in cfg.vars.get("open_ports") or []:
        if not p.get("port"):
            continue
        proto = str(p.get("proto") or "TCP").upper()
        name = str(p.get("name") or f"winlab-open-{proto}-{p['port']}")
        cfg.firewall(name, protocol=proto, local_port=[str(p["port"])])
    for p in cfg.vars.get("block_ports") or []:
        if not p.get("port"):
            continue
        proto = str(p.get("proto") or "TCP").upper()
        name = str(p.get("name") or f"winlab-block-{proto}-{p['port']}")
        cfg.firewall(name, protocol=proto, local_port=[str(p["port"])], action="Block")
    # ICMP echo stays open so reachability can be ping-tested.
    cfg.firewall("winlab-icmp", protocol="ICMPv4", icmp_type=["8"])


def build_wsus(cfg: NodeConfig) -> None:
    svc = cfg.feature("UpdateServices")
    db = cfg.feature("UpdateServices-WidDB")
    tools = cfg.feature("UpdateServices-RSAT", subfeatures=True)
    content = f"{cfg.data_root}\\WSUS"
    d = cfg.directory(content, _data_deps(cfg))
    post = cfg.script(
        "WsusPostInstall",
        "$k = 'HKLM:\\SOFTWARE\\Microsoft\\Update Services\\Server\\Setup'\n"
        "$v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).ContentDir\n"
        f"[string]$v -eq {ps_quote(content)}",
        "$tool = Join-Path $env:ProgramFiles 'Update Services\\Tools\\wsusutil.exe'\n"
        f"& $tool postinstall CONTENT_DIR={content} 2>&1 | Out-Null\n"
        "if ($LASTEXITCODE -ne 0) { throw \"wsusutil postinstall failed with $LASTEXITCODE\" }",
        depends=[svc, db, tools, d])
    me = f"http://{cfg.hostname}:8530"
    key = "HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
    gpo(cfg, "WSUS Client", [
        (key, "WUServer", "String", me),
        (key, "WUStatusServer", "String", me),
        (key + "\\AU", "UseWUServer", "DWord", 1),
    ], [cfg.base_dn], depends=[post])


def build_rds(cfg: NodeConfig) -> None:
    host = cfg.feature("RDS-RD-Server")
    lic = cfg.feature("RDS-Licensing")
    cfg.add(Resource("RemoteDesktopAdmin", "AllowRdp", {
        "IsSingleInstance": "Yes", "Ensure": "Present", "UserAuthentication": "Secure",
    }, depends_on=[host], module="ComputerManagementDsc"))
    for rule in ("RemoteDesktop-UserMode-In-TCP", "RemoteDesktop-UserMode-In-UDP",
                 "RemoteDesktop-Shadow-In-TCP"):
        cfg.enable_rule(rule, depends=[host])
    cfg.notes.append("rds: single session host with RD Licensing in its grace period; "
                     "a farm adds RDS-Connection-Broker and RDS-Web-Access on another node")
    _ = lic


def build_rras(cfg: NodeConfig) -> None:
    ra = cfg.feature("RemoteAccess")
    routing = cfg.feature("Routing")
    tools = cfg.feature("RSAT-RemoteAccess", subfeatures=True)
    inst = cfg.script(
        "RrasRouting",
        "Import-Module RemoteAccess\n"
        "$s = Get-RemoteAccess -ErrorAction SilentlyContinue\n"
        "[bool]($s -and $s.RoutingStatus -eq 'Installed')",
        "Import-Module RemoteAccess\n"
        "Install-RemoteAccess -VpnType RoutingOnly | Out-Null",
        depends=[ra, routing, tools])
    cfg.add(Resource("Service", "RemoteAccessService", {
        "Name": "RemoteAccess", "StartupType": "Automatic", "State": "Running",
    }, depends_on=[inst]))
    cfg.script(
        "IpForwarding",
        "@(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.Forwarding -eq 'Disabled' }).Count -eq 0",
        "Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled",
        depends=[inst])


def build_vpn_s2s(cfg: NodeConfig) -> None:
    """Site-to-site IKEv2 VPN (RRAS) to the other site's gateway, with routes
    for the far site's prefixes. The peer, the prefixes and the pre-shared
    key (the lab password) all come from the lab's [[site]] entries, so the
    role has nothing to be told."""
    from . import sites
    t = sites.tunnel_for(cfg.lab, cfg.node.id)
    if not t:
        cfg.notes.append("vpn-s2s: this machine is no site's gateway, or no other site has one; "
                         "nothing to connect to (set [[site]] gateway = this machine)")
        return
    ra = cfg.feature("RemoteAccess")
    vpn = cfg.feature("DirectAccess-VPN")
    routing = cfg.feature("Routing")
    tools = cfg.feature("RSAT-RemoteAccess", subfeatures=True)
    inst = cfg.script(
        "RrasSiteToSite",
        "Import-Module RemoteAccess\n"
        "$s = Get-RemoteAccess -ErrorAction SilentlyContinue\n"
        "[bool]($s -and $s.VpnS2SStatus -eq 'Installed')",
        "Import-Module RemoteAccess\n"
        "Install-RemoteAccess -VpnType VpnS2S | Out-Null",
        depends=[ra, vpn, routing, tools])
    # Shared with the rras role when both are on one machine.
    svc_id = "[Service]RemoteAccessService"
    if not cfg.has(svc_id):
        cfg.add(Resource("Service", "RemoteAccessService", {
            "Name": "RemoteAccess", "StartupType": "Automatic", "State": "Running",
        }, depends_on=[inst]))
    name = f"to-{t.peer_site}"
    subnets = _ps_array(f"{p}:100" for p in t.remote_prefixes)
    cfg.script(
        f"S2SInterface_{ident(name)}",
        "Import-Module RemoteAccess\n"
        f"$i = Get-VpnS2SInterface -Name {ps_quote(name)} -ErrorAction SilentlyContinue\n"
        f"[bool]($i -and ($i.Destination -contains {ps_quote(t.peer_outside_ip)}))",
        "Import-Module RemoteAccess\n"
        "$f = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json\n"
        f"Add-VpnS2SInterface -Name {ps_quote(name)} -Destination {ps_quote(t.peer_outside_ip)} "
        f"-Protocol IKEv2 -AuthenticationMethod PSKOnly -SharedSecret $f.lab.admin_password "
        f"-IPv4Subnet {subnets} -Persistent -PassThru | Out-Null\n"
        f"Connect-VpnS2SInterface -Name {ps_quote(name)} -ErrorAction SilentlyContinue | Out-Null",
        depends=[svc_id, inst])
    if not cfg.has("[Script]IpForwarding"):
        cfg.script(
            "IpForwarding",
            "@(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.Forwarding -eq 'Disabled' }).Count -eq 0",
            "Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled",
            depends=[inst])
    # Two adapters, one default route: the outside adapter wins (lower
    # interface metric) and the rest of the site is reached through the
    # inside router, so nothing of the site's traffic leaks out of the WAN.
    inside_ip, outside_ip = t.local_inside_ip, t.local_outside_ip
    inside_net = next((n for n in cfg.lab.networks.values()
                       if ipaddress.ip_address(inside_ip) in n.net), None)
    inside_gw = inside_net.router_ip if inside_net else ""
    routes = [p for p in t.local_prefixes if inside_net and p != inside_net.cidr]
    want_routes = "\n".join(
        f"if (-not (Get-NetRoute -DestinationPrefix {ps_quote(p)} -ErrorAction SilentlyContinue | "
        f"Where-Object NextHop -eq {ps_quote(inside_gw)})) {{ $ok = $false }}" for p in routes)
    add_routes = "\n".join(
        f"New-NetRoute -DestinationPrefix {ps_quote(p)} -InterfaceIndex $in.ifIndex -NextHop "
        f"{ps_quote(inside_gw)} -ErrorAction SilentlyContinue | Out-Null" for p in routes)
    cfg.script(
        "GatewayRoutes",
        f"$in = Get-NetIPAddress -IPAddress {ps_quote(inside_ip)} -ErrorAction SilentlyContinue\n"
        f"$out = Get-NetIPAddress -IPAddress {ps_quote(outside_ip)} -ErrorAction SilentlyContinue\n"
        "if (-not $in -or -not $out) { return $false }\n"
        "$ok = (Get-NetIPInterface -InterfaceIndex $in.ifIndex -AddressFamily IPv4).InterfaceMetric -ge 50 -and "
        "(Get-NetIPInterface -InterfaceIndex $out.ifIndex -AddressFamily IPv4).InterfaceMetric -le 10\n"
        f"{want_routes}\n"
        "$ok",
        f"$in = Get-NetIPAddress -IPAddress {ps_quote(inside_ip)}\n"
        f"$out = Get-NetIPAddress -IPAddress {ps_quote(outside_ip)}\n"
        "Set-NetIPInterface -InterfaceIndex $out.ifIndex -AddressFamily IPv4 -InterfaceMetric 10\n"
        "Set-NetIPInterface -InterfaceIndex $in.ifIndex -AddressFamily IPv4 -InterfaceMetric 50\n"
        f"{add_routes}",
        depends=[inst])
    cfg.notes.append(f"vpn-s2s: IKEv2 interface '{name}' to {t.peer_node} at {t.peer_outside_ip} "
                     f"for {', '.join(t.remote_prefixes)}; pre-shared key = the lab password")


def build_nps(cfg: NodeConfig) -> None:
    feat = cfg.feature("NPAS")
    tools = cfg.feature("RSAT-NPAS")
    ad = cfg.feature("RSAT-AD-PowerShell")
    dom = _domain(cfg)
    reg = cfg.script(
        "NpsRegisteredInAD",
        "Import-Module ActiveDirectory\n"
        "$members = @(Get-ADGroupMember -Identity 'RAS and IAS Servers' -ErrorAction SilentlyContinue | ForEach-Object { $_.name })\n"
        "$members -contains $env:COMPUTERNAME",
        "netsh nps add registeredserver | Out-Null",
        depends=[feat, tools, ad, dom], run_as=True)
    client_ip = str(cfg.vars.get("radius_client_ip") or "")
    if client_ip:
        # The shared secret is the lab password, which both ends already know.
        cfg.script(
            "RadiusClient_lab_vpn",
            "Import-Module NPS\n"
            "[bool](Get-NpsRadiusClient -Name 'lab-vpn' -ErrorAction SilentlyContinue)",
            "Import-Module NPS\n"
            "$f = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json\n"
            f"New-NpsRadiusClient -Name 'lab-vpn' -Address {ps_quote(client_ip)} -SharedSecret $f.lab.admin_password | Out-Null",
            depends=[reg])
    else:
        cfg.notes.append("nps: set vars.radius_client_ip to register the VPN/RRAS box as a RADIUS client")


def build_printer(cfg: NodeConfig) -> None:
    feat = cfg.feature("Print-Services")
    tools = cfg.feature("RSAT-Print-Services")
    _printer_script(cfg, "Lab-PDF", "Microsoft Print To PDF", shared=True, depends=[feat, tools])


# --------------------------------------------------------------- operations
def build_monitoring(cfg: NodeConfig) -> None:
    name = "winlab-baseline"
    xml = (
        "<DataCollectorSet>"
        f"<Name>{name}</Name><Duration>0</Duration><SegmentMaxDuration>86400</SegmentMaxDuration>"
        "<PerformanceCounterDataCollector><Name>counters</Name><SampleInterval>15</SampleInterval>"
        "<LogFileFormat>3</LogFileFormat>"
        "<Counter>\\Processor(_Total)\\% Processor Time</Counter>"
        "<Counter>\\Memory\\Available MBytes</Counter>"
        "<Counter>\\PhysicalDisk(_Total)\\Avg. Disk sec/Transfer</Counter>"
        "<Counter>\\Network Interface(*)\\Bytes Total/sec</Counter>"
        "<Counter>\\System\\Processor Queue Length</Counter>"
        "</PerformanceCounterDataCollector></DataCollectorSet>"
    )
    cfg.script(
        "PerfMonBaseline",
        f"$dcs = New-Object -ComObject Pla.DataCollectorSet\n"
        f"try {{ $dcs.Query({ps_quote(name)}, $null); $dcs.Status -eq 1 }} catch {{ $false }}",
        f"$dcs = New-Object -ComObject Pla.DataCollectorSet\n"
        f"$dcs.SetXml({ps_quote(xml)})\n"
        f"$dcs.Commit({ps_quote(name)}, $null, 0x0003) | Out-Null\n"
        "$dcs.Start($false)")
    cfg.add(Resource("WindowsEventLog", "SecurityLog", {
        "LogName": "Security", "IsEnabled": True, "MaximumSizeInBytes": 128 * 1024 ** 2,
    }, module="ComputerManagementDsc"))
    cfg.script(
        "EventCollector",
        "$s = Get-Service -Name Wecsvc -ErrorAction SilentlyContinue\n"
        "[bool]($s -and $s.StartType -eq 'Automatic' -and $s.Status -eq 'Running')",
        "wecutil qc /q | Out-Null\n"
        "Set-Service -Name Wecsvc -StartupType Automatic\n"
        "Start-Service -Name Wecsvc")


_AUDIT = ["Logon", "Logoff", "Account Lockout", "User Account Management",
          "Security Group Management", "Directory Service Changes", "Process Creation",
          "Credential Validation", "Kerberos Authentication Service"]


def build_hardening(cfg: NodeConfig) -> None:
    cats = _ps_array(_AUDIT)
    cfg.script(
        "AuditPolicy",
        f"foreach ($c in {cats}) {{\n"
        "    $row = auditpol /get /subcategory:\"$c\" /r | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv | Select-Object -First 1\n"
        "    if (-not $row -or $row.'Inclusion Setting' -ne 'Success and Failure') { return $false }\n"
        "}\n"
        "$true",
        f"foreach ($c in {cats}) {{\n"
        "    auditpol /set /subcategory:\"$c\" /success:enable /failure:enable | Out-Null\n"
        "}")
    for name, key, value, data in (
        ("AuditCmdLine", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
         "ProcessCreationIncludeCmdLine_Enabled", "1"),
        ("LsaRunAsPPL", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL", "1"),
        ("NtlmMinServerSec", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
         "NtlmMinServerSec", "537395200"),
    ):
        cfg.add(Resource("Registry", name, {
            "Key": key, "ValueName": value, "ValueType": "Dword", "ValueData": [data],
            "Ensure": "Present", "Force": True,
        }))
    cfg.add(Resource("SmbServerConfiguration", "SmbHardening", {
        "IsSingleInstance": "Yes", "RequireSecuritySignature": True, "EnableSMB1Protocol": False,
    }, module="ComputerManagementDsc"))
    cfg.feature("FS-SMB1", ensure="Absent")
    cfg.script(
        "DefenderRealtime",
        "try { -not (Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring } catch { $true }",
        "Set-MpPreference -DisableRealtimeMonitoring $false")
    cfg.text_file("HardeningRecord", "C:\\winlab\\hardening-applied.txt", (
        "audit policy: logon/account-mgmt/ds-changes/process-creation (success+failure)\r\n"
        "smb: signing required, SMBv1 off\r\n"
        "lsa: RunAsPPL=1, NTLM min server sec raised\r\n"
        "defender: realtime on\r\n"))


def build_dsc(cfg: NodeConfig) -> None:
    """The configuration-as-code lesson: this machine's LCM corrects drift on
    its own, and a few plainly visible resources show it happening."""
    cfg.lcm_mode = "ApplyAndAutoCorrect"
    cfg.text_file("ManagedMarker", "C:\\winlab\\dsc\\managed.txt", "managed by winlab DSC\r\n")
    cfg.add(Resource("Service", "TimeService", {
        "Name": "W32Time", "State": "Running", "StartupType": "Automatic",
    }))
    cfg.feature("Telnet-Client", ensure="Absent")


def build_drivers(cfg: NodeConfig) -> None:
    staging = "C:\\winlab\\drivers"
    cfg.script(
        "VendorDrivers",
        f"$infs = @(Get-ChildItem -Path {ps_quote(staging)} -Recurse -Filter *.inf -ErrorAction SilentlyContinue)\n"
        "if ($infs.Count -eq 0) { return $true }\n"
        "$store = (pnputil /enum-drivers) -join \"`n\"\n"
        "foreach ($inf in $infs) { if ($store -notmatch [regex]::Escape($inf.Name)) { return $false } }\n"
        "$true",
        f"$infs = @(Get-ChildItem -Path {ps_quote(staging)} -Recurse -Filter *.inf -ErrorAction SilentlyContinue)\n"
        "foreach ($inf in $infs) { pnputil /add-driver \"$($inf.FullName)\" /install | Out-Null }\n"
        "pnputil /scan-devices | Out-Null\n"
        "$third = pnputil /enum-drivers | Select-String -Pattern 'Original Name|Provider' | Select-Object -First 40\n"
        "Set-Content -Path 'C:\\winlab\\drivers-installed.txt' -Value ($third -join \"`n\") -Encoding utf8",
        get=f"$n = @(Get-ChildItem -Path {ps_quote(staging)} -Recurse -Filter *.inf -ErrorAction SilentlyContinue).Count\n"
            "@{ Result = \"$n staged inf(s)\" }")


# ----------------------------------------------------------------- devices
def build_devices(cfg: NodeConfig) -> None:
    devices = cfg.facts.get("devices") or []
    if not devices:
        cfg.notes.append("devices: no devices on this node")
        return
    root = f"{cfg.data_root}\\Devices"
    for d in devices:
        kind, name = str(d.get("kind")), str(d.get("name"))
        shared = bool(d.get("shared", True))
        dvars = d.get("vars") or {}
        if kind in ("printer", "label-printer"):
            feat = cfg.feature("Print-Services")
            default = "Microsoft Print To PDF" if kind == "printer" else "Generic / Text Only"
            _printer_script(cfg, name, str(d.get("driver") or default), shared,
                            str(d.get("location") or ""), depends=[feat])
        elif kind == "scanner":
            cfg.smb_share(f"scan-{name}", f"{root}\\scan-{name}", full=["Administrators"],
                          change=["Authenticated Users"], depends=_data_deps(cfg))
        elif kind == "fileshare":
            cfg.smb_share(name, f"{root}\\{name}", full=["Administrators"],
                          change=["Authenticated Users"], depends=_data_deps(cfg))
        elif kind == "nas":
            feat = cfg.feature("FS-iSCSITarget-Server")
            _iscsi_target_script(cfg, name, int(dvars.get("size_gb") or 10), depends=[feat])
        elif kind == "voip":
            server = str(dvars.get("provisioning_server") or (cfg.facts.get("nics") or [{}])[0].get("ip") or "")
            if cfg.dhcp_scopes and server:
                for subnet in cfg.dhcp_scopes:
                    tag = subnet.replace(".", "_")
                    cfg.add(Resource("DhcpScopeOptionValue", f"Opt66_{tag}", {
                        "OptionId": 66, "Value": [server], "ScopeId": subnet,
                        "VendorClass": "", "UserClass": "", "AddressFamily": "IPv4",
                        "Ensure": "Present",
                    }, depends_on=[f"[xDhcpServerScope]Scope_{tag}"], module="DhcpServerDsc"))
            else:
                cfg.notes.append(f"voip '{name}': option 66 (provisioning server) is set by the dhcp role; "
                                 "put the device on the DHCP server node or set it there")
        elif kind == "camera":
            cfg.firewall(f"winlab-camera-{name}", local_port=["554", "80"])
        elif kind == "ups":
            cfg.firewall(f"winlab-ups-{name}", direction="Outbound", protocol="UDP",
                         remote_port=["161", "3493"])
        else:
            raise DscError(f"{cfg.node.id}: unknown device kind {kind!r}")


def build_connect_devices(cfg: NodeConfig) -> None:
    """The client side: this machine's user reaches every shared device in the
    lab. Mappings are made as the lab administrator (PsDscRunAsCredential),
    the account a student uses on the workstation."""
    targets = list(cfg.vars.get("connect") or [])
    if not targets:
        targets = [t for t in (cfg.facts.get("lab_devices") or [])
                   if str(t.get("host")).upper() != cfg.hostname.upper()]
    if not targets:
        cfg.notes.append("connect-devices: no shared devices elsewhere in the lab")
        return
    dom = _domain(cfg)
    for t in targets:
        kind, host, name = str(t.get("kind")), str(t.get("host")), str(t.get("name"))
        unc = f"\\\\{host}\\{name}"
        tag = ident(f"{host}_{name}")
        if kind in ("printer", "label-printer"):
            cfg.script(
                f"Connect_Printer_{tag}",
                f"[bool](Get-Printer -Name {ps_quote(unc)} -ErrorAction SilentlyContinue)",
                f"Add-Printer -ConnectionName {ps_quote(unc)}",
                depends=[dom], run_as=True)
        elif kind in ("scanner", "fileshare"):
            letter = str(t.get("drive") or ("S" if kind == "scanner" else "N")).rstrip(":").upper()
            remote = f"\\\\{host}\\scan-{name}" if kind == "scanner" else unc
            cfg.script(
                f"Map_{letter}_{tag}",
                f"$m = Get-SmbMapping -LocalPath '{letter}:' -ErrorAction SilentlyContinue\n"
                f"[bool]($m -and $m.RemotePath -eq {ps_quote(remote)})",
                f"New-SmbMapping -LocalPath '{letter}:' -RemotePath {ps_quote(remote)} -Persistent $true | Out-Null",
                depends=[dom], run_as=True)
        elif kind == "nas":
            portal = str(t.get("portal") or host)
            svc = cfg.add(Resource("Service", "IscsiInitiator", {
                "Name": "MSiSCSI", "StartupType": "Automatic", "State": "Running",
            }))
            cfg.script(
                f"Connect_Nas_{tag}",
                f"[bool](Get-IscsiSession -ErrorAction SilentlyContinue | Where-Object {{ $_.TargetNodeAddress -like '*{name.lower()}*' }})",
                f"New-IscsiTargetPortal -TargetPortalAddress {ps_quote(portal)} | Out-Null\n"
                f"Get-IscsiTarget | Where-Object {{ $_.NodeAddress -like '*{name.lower()}*' }} |\n"
                "    Connect-IscsiTarget -IsPersistent $true | Out-Null",
                depends=[svc.id, dom])
        else:
            cfg.notes.append(f"connect-devices: nothing to connect for a {kind} ('{name}' on {host})")


# ----------------------------------------------------------------- lean
# Services an isolated lab machine gets nothing from and pays memory or CPU
# for at idle. Ones an edition lacks (the indexer and Xbox on Server) are
# skipped, not errors.
_LEAN_SERVICES = [
    "DiagTrack",          # telemetry upload
    "dmwappushservice",   # WAP push routing, telemetry's companion
    "WerSvc",             # error reporting upload
    "MapsBroker",         # offline maps
    "RetailDemo",
    "lfsvc",              # geolocation
    "WSearch",            # the indexer: the largest idle consumer on a client
    "SysMain",            # prefetch: pointless with 2 GB and a thin disk
    "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc",
]
# Scheduled tasks that wake an idle machine for what an isolated lab never
# needs (compatibility telemetry, CEIP, error reporting, WinSAT) or that grow
# a thin disk for nothing (the weekly defrag of a virtual disk). Written as
# "path|name" because Windows PowerShell flattens a one-element nested array.
_LEAN_TASKS = [
    "\\Microsoft\\Windows\\Application Experience\\|Microsoft Compatibility Appraiser",
    "\\Microsoft\\Windows\\Application Experience\\|ProgramDataUpdater",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\|Consolidator",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\|UsbCeip",
    "\\Microsoft\\Windows\\Windows Error Reporting\\|QueueReporting",
    "\\Microsoft\\Windows\\Maintenance\\|WinSAT",
    "\\Microsoft\\Windows\\Defrag\\|ScheduledDefrag",
    "\\Microsoft\\Windows\\DiskDiagnostic\\|Microsoft-Windows-DiskDiagnosticDataCollector",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\|DmClient",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\|DmClientOnScenarioDownload",
]
_POL = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\"
# Documented Group Policy settings written as local policy, so a domain GPO
# (the wsus role's Windows Update settings, say) still wins where it sets the
# same value, and gpedit shows a student exactly what is in force.
_LEAN_RECORD = "C:\\winlab\\lean-applied.txt"
_LEAN_SERVICES_RECORD = "C:\\winlab\\lean-services.json"
_LEAN_POLICIES = [
    ("WuNoAutoUpdate", _POL + "Windows\\WindowsUpdate\\AU", "NoAutoUpdate", "1"),
    ("TelemetryOff", _POL + "Windows\\DataCollection", "AllowTelemetry", "0"),
    ("DoNoPeering", _POL + "Windows\\DeliveryOptimization", "DODownloadMode", "0"),
    ("EdgeNoStartupBoost", _POL + "Edge", "StartupBoostEnabled", "0"),
    ("EdgeNoBackground", _POL + "Edge", "BackgroundModeEnabled", "0"),
    ("NoCloudContent", _POL + "Windows\\CloudContent", "DisableCloudOptimizedContent", "1"),
]
_LEAN_POLICIES_CLIENT = [
    ("NoWidgets", _POL + "Dsh", "AllowNewsAndInterests", "0"),
    ("NoChatIcon", _POL + "Windows\\Windows Chat", "ChatIcon", "3"),
    ("NoOneDrive", _POL + "Windows\\OneDrive", "DisableFileSyncNGSC", "1"),
    ("NoCopilot", _POL + "Windows\\WindowsCopilot", "TurnOffWindowsCopilot", "1"),
    ("NoConsumerFeatures", _POL + "Windows\\CloudContent", "DisableWindowsConsumerFeatures", "1"),
    ("NoCortana", _POL + "Windows\\Windows Search", "AllowCortana", "0"),
    ("NoSearchHighlights", _POL + "Windows\\Windows Search", "EnableDynamicContentInWSB", "0"),
    ("NoCloudSearch", _POL + "Windows\\Windows Search", "AllowCloudSearch", "0"),
    ("NoSearchSuggestions", _POL + "Windows\\Explorer", "DisableSearchBoxSuggestions", "1"),
]


def build_lean(cfg: NodeConfig) -> None:
    """The Low-memory profile, off by default (machines run stock Windows;
    `lean = true` in [lab] or on a node, or the switch in the Machines
    window, turns it on): what an isolated lab machine does not need and pays
    memory for at idle, so a server serves its roles at 1.5 GB and Windows 11
    stays usable at 2 GB. Every piece is a documented setting a lesson can
    turn back on; the Defender feature goes only from a server that no role
    wants it on (the hardening role keeps it, and clients keep it: Windows 11
    has no supported way to remove it). The services' start types are
    recorded first, so switching the profile off (build_lean_restore) puts
    stock Windows back."""
    client = cfg.node.kind == WINDOWS_CLIENT
    services = _ps_array(_LEAN_SERVICES)
    cfg.script(
        "LeanServices",
        f"$bad = Get-Service -Name {services} -ErrorAction SilentlyContinue |\n"
        "    Where-Object { $_.StartType -ne 'Disabled' -or $_.Status -ne 'Stopped' }\n"
        "-not $bad",
        f"if (-not (Test-Path {ps_quote(_LEAN_SERVICES_RECORD)})) {{\n"
        f"    Get-Service -Name {services} -ErrorAction SilentlyContinue |\n"
        "        Select-Object Name, StartType | ConvertTo-Json |\n"
        f"        Set-Content -Path {ps_quote(_LEAN_SERVICES_RECORD)} -Encoding ASCII\n"
        "}\n"
        f"foreach ($n in {services}) {{\n"
        "    if (Get-Service -Name $n -ErrorAction SilentlyContinue) {\n"
        "        Set-Service -Name $n -StartupType Disabled -ErrorAction SilentlyContinue\n"
        "        Stop-Service -Name $n -Force -ErrorAction SilentlyContinue\n"
        "    }\n"
        "}")
    tasks = _ps_array(_LEAN_TASKS)
    cfg.script(
        "LeanTasks",
        f"foreach ($t in {tasks}) {{\n"
        "    $p, $n = $t.Split('|')\n"
        "    $x = Get-ScheduledTask -TaskPath $p -TaskName $n -ErrorAction SilentlyContinue\n"
        "    if ($x -and $x.State -ne 'Disabled') { return $false }\n"
        "}\n"
        "$true",
        f"foreach ($t in {tasks}) {{\n"
        "    $p, $n = $t.Split('|')\n"
        "    Get-ScheduledTask -TaskPath $p -TaskName $n -ErrorAction SilentlyContinue |\n"
        "        Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null\n"
        "}")
    for name, key, value, data in _LEAN_POLICIES + (_LEAN_POLICIES_CLIENT if client else []):
        cfg.add(Resource("Registry", f"Lean_{name}", {
            "Key": key, "ValueName": value, "ValueType": "Dword", "ValueData": [data],
            "Ensure": "Present", "Force": True,
        }))
    defender = "kept: Windows 11 keeps Defender"
    if not client:
        if cfg.has("[Script]DefenderRealtime"):
            defender = "kept: the hardening role wants real-time protection on"
            cfg.notes.append("lean: Defender stays, the hardening role teaches it")
        else:
            cfg.feature("Windows-Defender", ensure="Absent")
            defender = "removed (Install-WindowsFeature Windows-Defender brings it back)"
    cfg.text_file("LeanRecord", _LEAN_RECORD, (
        "winlab Low-memory profile. Undo any line with the setting it names, or\r\n"
        "switch the profile off (lean = false on this machine in the lab file, or\r\n"
        "the Machines window) and apply roles again: stock Windows comes back.\r\n"
        f"services disabled: {', '.join(_LEAN_SERVICES)}\r\n"
        f"scheduled tasks disabled: {', '.join(t.split('|')[1] for t in _LEAN_TASKS)}\r\n"
        "local policy: no automatic updates, telemetry off, Delivery Optimization\r\n"
        "  HTTP only, Edge startup boost and background mode off, cloud content off\r\n"
        + ("local policy (client): Widgets, Chat, OneDrive, Copilot, consumer apps,\r\n"
           "  Cortana, search highlights, cloud search and search suggestions off\r\n"
           if client else "")
        + f"defender: {defender}\r\n"))


def build_lean_restore(cfg: NodeConfig) -> None:
    """Stock Windows on a machine that once had the Low-memory profile: the
    services get their recorded start types back, the tasks are enabled, the
    policies removed and Defender reinstalled on a server. A machine the
    profile never touched has no record file and nothing runs. dsc.compile_node
    adds this to every Windows machine whose profile is off."""
    client = cfg.node.kind == WINDOWS_CLIENT
    tasks = _ps_array(_LEAN_TASKS)
    pols = _ps_array([f"{key}|{value}" for _n, key, value, _d in _LEAN_POLICIES + _LEAN_POLICIES_CLIENT])
    cfg.script(
        "LeanRestore",
        f"-not (Test-Path {ps_quote(_LEAN_RECORD)})",
        f"$rec = {ps_quote(_LEAN_SERVICES_RECORD)}\n"
        "if (Test-Path $rec) {\n"
        "    foreach ($s in (Get-Content -Path $rec -Raw | ConvertFrom-Json)) {\n"
        "        $t = if ($s.StartType -eq 'AutomaticDelayedStart') { 'Automatic' } else { [string]$s.StartType }\n"
        "        Set-Service -Name $s.Name -StartupType $t -ErrorAction SilentlyContinue\n"
        "        if ($t -eq 'Automatic') { Start-Service -Name $s.Name -ErrorAction SilentlyContinue }\n"
        "    }\n"
        "    Remove-Item -Path $rec -Force\n"
        "}\n"
        f"foreach ($t in {tasks}) {{\n"
        "    $p, $n = $t.Split('|')\n"
        "    Get-ScheduledTask -TaskPath $p -TaskName $n -ErrorAction SilentlyContinue |\n"
        "        Enable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null\n"
        "}\n"
        f"foreach ($pv in {pols}) {{\n"
        "    $k, $v = $pv.Split('|')\n"
        "    Remove-ItemProperty -Path ('Registry::' + $k) -Name $v -ErrorAction SilentlyContinue\n"
        "}\n"
        + ("" if client else
           "if ((Get-WindowsFeature -Name Windows-Defender).InstallState -ne 'Installed') {\n"
           "    Install-WindowsFeature -Name Windows-Defender | Out-Null\n"
           "}\n")
        + f"Remove-Item -Path {ps_quote(_LEAN_RECORD)} -Force -ErrorAction SilentlyContinue")


# ------------------------------------------------------------ SQL Server
# sqlcmd.exe comes with the Database Engine; the LCM's PATH predates the
# install, so the scripts find it under Program Files.
_SQLCMD = (
    "$sqlcmd = Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Microsoft SQL Server') -Recurse "
    "-Filter 'SQLCMD.EXE' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName\n"
    "if (-not $sqlcmd) { throw 'sqlcmd.exe not found: the SQL Server Database Engine is not installed' }\n"
)

LABINVENTORY_SQL = """IF DB_ID('LabInventory') IS NULL CREATE DATABASE [LabInventory];
GO
USE [LabInventory];
GO
IF OBJECT_ID('dbo.Assets') IS NULL
BEGIN
    CREATE TABLE dbo.Assets (
        AssetId   int IDENTITY(1,1) PRIMARY KEY,
        Tag       nvarchar(20)  NOT NULL UNIQUE,
        Kind      nvarchar(30)  NOT NULL,
        Owner     nvarchar(60)  NULL,
        Site      nvarchar(20)  NOT NULL,
        Purchased date          NOT NULL
    );
    INSERT INTO dbo.Assets (Tag, Kind, Owner, Site, Purchased) VALUES
        ('LT-0001', 'laptop',      'Dana Reyes',    'HQ',     '2024-03-11'),
        ('LT-0002', 'laptop',      'Sam Okafor',    'HQ',     '2024-03-11'),
        ('LT-0003', 'laptop',      'Priya Nair',    'Branch', '2024-06-02'),
        ('DT-0001', 'desktop',     'Front desk',    'HQ',     '2023-09-19'),
        ('PR-0001', 'printer',     NULL,            'HQ',     '2022-01-30'),
        ('PR-0002', 'printer',     NULL,            'Branch', '2022-01-30'),
        ('SW-0001', 'switch',      NULL,            'HQ',     '2021-11-05'),
        ('SV-0001', 'server',      NULL,            'HQ',     '2025-02-14');
END
GO
IF OBJECT_ID('dbo.AssetsBySite') IS NULL
    EXEC('CREATE VIEW dbo.AssetsBySite AS SELECT Site, Kind, COUNT(*) AS Assets FROM dbo.Assets GROUP BY Site, Kind');
GO
"""


def build_sql(cfg: NodeConfig) -> None:
    """SQL Server 2022 Developer (or Evaluation) from the user's own ISO,
    which the role runner puts in the DVD drive: the Database Engine installed
    unattended by the media's own setup.exe (the supported command line, the
    same one deployment tooling uses), listening on TCP 1433 with the firewall
    open, the Agent running, Windows authentication only, Domain Admins as
    sysadmin on a domain member, the engine capped at 1 GB so the machine
    stays usable, data and backups on the data disk when there is one, and a
    small LabInventory database the lessons work on."""
    joined = bool({"ad-ds", "domain-join"} & set(cfg.node.roles))
    sites = _mecm_sites_of(cfg) if joined else []
    data = ensure_data_volume(cfg)
    root = f"{cfg.data_root}\\SQL" if data else "C:\\SQL"
    backup_dir = f"{root}\\Backup"
    admins = ["BUILTIN\\Administrators"] + ([f"{cfg.netbios}\\Domain Admins"] if joined else [])
    sysadmins = " ".join(f'"{a}"' for a in admins)
    dirs = [f'/SQLBACKUPDIR="{backup_dir}"']
    if data:
        dirs += [f'/SQLUSERDBDIR="{root}\\Data"', f'/SQLUSERDBLOGDIR="{root}\\Log"',
                 f'/SQLTEMPDBDIR="{root}\\TempDB"']
    setup_args = [
        "/Q", "/ACTION=Install", "/IACCEPTSQLSERVERLICENSETERMS", "/SUPPRESSPRIVACYSTATEMENTNOTICE",
        "/FEATURES=SQLENGINE,CONN", "/INSTANCENAME=MSSQLSERVER", "/UPDATEENABLED=False",
        "/TCPENABLED=1", "/NPENABLED=0", "/SQLSVCSTARTUPTYPE=Automatic", "/AGTSVCSTARTUPTYPE=Automatic",
        "/BROWSERSVCSTARTUPTYPE=Disabled", "/SQLMAXMEMORY=1024",
        # A feature install earlier in the same configuration can leave a
        # reboot pending that setup would otherwise refuse to start under.
        "/SKIPRULES=RebootRequiredCheck",
        f"/SQLSYSADMINACCOUNTS={sysadmins}", *dirs,
    ]
    if sites:
        # Configuration Manager accepts its site database on this collation only.
        setup_args.append(f"/SQLCOLLATION={MECM_COLLATION}")
    ps_args = ", ".join("'" + a.replace("'", "''") + "'" for a in setup_args)
    deps = [data] if data else []
    engine = cfg.script(
        "SqlServerEngine",
        "[bool](Get-Service -Name 'MSSQLSERVER' -ErrorAction SilentlyContinue)",
        "$media = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and "
        "(Test-Path ('{0}:\\setup.exe' -f $_.DriveLetter)) -and (Test-Path ('{0}:\\x64' -f $_.DriveLetter)) } | "
        "Select-Object -First 1\n"
        "if (-not $media) { throw 'the SQL Server installation media is not in the DVD drive: import the "
        "sql2022 ISO (winlab images import sql2022 <file.iso>) and apply the role again' }\n"
        "$setup = '{0}:\\setup.exe' -f $media.DriveLetter\n"
        f"$setupArgs = @({ps_args})\n"
        "$p = Start-Process -FilePath $setup -ArgumentList $setupArgs -Wait -PassThru -NoNewWindow\n"
        "if ($p.ExitCode -eq 3010) {\n"
        "    $global:DSCMachineStatus = 1\n"
        "} elseif ($p.ExitCode -ne 0) {\n"
        "    $log = Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Microsoft SQL Server\\*\\Setup Bootstrap\\Log\\Summary.txt') "
        "-ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1\n"
        "    $tail = if ($log) { (Get-Content -Path $log.FullName -Tail 15) -join ' | ' } else { 'no summary log' }\n"
        "    throw ('SQL Server setup exited {0}: {1}' -f $p.ExitCode, $tail)\n"
        "}",
        get="@{ Result = (Get-Service -Name 'MSSQLSERVER' -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Status.ToString() }) }",
        depends=deps)
    agent = cfg.add(Resource("Service", "SqlAgent", {
        "Name": "SQLSERVERAGENT", "State": "Running", "StartupType": "Automatic",
    }, depends_on=[engine]))
    cfg.firewall("winlab-sql-1433", local_port=["1433"], depends=[engine])
    bdir = cfg.directory(backup_dir, deps)
    script_path = "C:\\winlab\\sql\\labinventory.sql"
    sqlfile = cfg.text_file("LabInventoryScript", script_path, LABINVENTORY_SQL.replace("\n", "\r\n"))
    if joined:
        login = f"{cfg.netbios}\\Domain Admins"
        cfg.script(
            "SqlDomainAdmins",
            _SQLCMD
            + f"$r = & $sqlcmd -S . -E -h -1 -W -b -Q \"SET NOCOUNT ON; SELECT CASE WHEN IS_SRVROLEMEMBER('sysadmin', '{login}') = 1 THEN 'yes' ELSE 'no' END\"\n"
            "(($r | Out-String).Trim() -eq 'yes')",
            _SQLCMD
            + f"& $sqlcmd -S . -E -b -Q \"IF SUSER_ID('{login}') IS NULL CREATE LOGIN [{login}] FROM WINDOWS; ALTER SERVER ROLE sysadmin ADD MEMBER [{login}];\" | Out-Null\n"
            f"if ($LASTEXITCODE -ne 0) {{ throw 'creating the {login} login failed (is the machine joined and the DC reachable?)' }}",
            depends=[engine])
    if sites:
        _sql_for_mecm_site(cfg, engine)
    cfg.script(
        "LabInventoryDatabase",
        _SQLCMD
        + "$r = & $sqlcmd -S . -E -h -1 -W -b -Q \"SET NOCOUNT ON; SELECT CASE WHEN DB_ID('LabInventory') IS NULL THEN 'no' ELSE 'yes' END\"\n"
        "(($r | Out-String).Trim() -eq 'yes')",
        _SQLCMD
        + f"& $sqlcmd -S . -E -b -i '{script_path}' | Out-Null\n"
        "if ($LASTEXITCODE -ne 0) { throw 'creating the LabInventory database failed' }",
        depends=[engine, sqlfile])
    cfg.text_file("SqlReadme", "C:\\winlab\\sql\\README.txt", (
        "SQL Server 2022 (winlab role sql)\r\n"
        "  instance: MSSQLSERVER (default), Windows authentication only\r\n"
        "  connect here:      sqlcmd -S . -E\r\n"
        f"  connect remotely:  sqlcmd -S {cfg.hostname} -E   (TCP 1433, firewall rule winlab-sql-1433)\r\n"
        f"  backups:           {backup_dir}\r\n"
        + (f"  data and logs:     {root}\\Data, {root}\\Log (the Data volume)\r\n" if data else "")
        + f"  sysadmin:          {', '.join(admins)}\r\n"
        "  sample database:   LabInventory (dbo.Assets, dbo.AssetsBySite); script in this folder\r\n"
        "  engine memory cap: 1024 MB (sp_configure 'max server memory')\r\n"
        + "".join(f"  Configuration Manager: site server {cfg.netbios}\\{h}$ is sysadmin and a local\r\n"
                  f"                     administrator here; Service Broker on TCP {MECM_SSB_PORT}\r\n" for h in sites)),
        depends=[engine, agent.id, bdir])


MECM_COLLATION = "SQL_Latin1_General_CP1_CI_AS"
MECM_SSB_PORT = 4022


def _mecm_sql_node(cfg: NodeConfig, site) -> object | None:
    """The lab node holding a Configuration Manager site's database: the
    site's var sql_server (a node id), else the lab's first sql node."""
    want = str(site.vars.get("sql_server") or "")
    for n in cfg.lab.node_list():
        if "sql" in n.roles and (n.id == want or not want):
            return n
    return None


def _mecm_sites_of(cfg: NodeConfig) -> list[str]:
    """Hostnames of the Configuration Manager site servers whose database
    lives on this SQL Server."""
    from .naming import hostname_of
    out = []
    for n in cfg.lab.node_list():
        if "mecm" in n.roles:
            sql = _mecm_sql_node(cfg, n)
            if sql is not None and sql.id == cfg.node.id:
                out.append(hostname_of(n).upper())
    return out


def _sql_for_mecm_site(cfg: NodeConfig, engine: str) -> None:
    """The SQL Server side of a remote site database: Service Broker's port
    open for the site's replication endpoint. The site server's own rights
    here (a sysadmin login and local Administrators for its computer
    account) are granted by the mecm role, because that account exists only
    once the site server has joined the domain."""
    cfg.firewall(f"winlab-sql-ssb-{MECM_SSB_PORT}", local_port=[str(MECM_SSB_PORT)], depends=[engine])


def build_metrics(cfg: NodeConfig) -> None:
    """The Prometheus Windows exporter (windows_exporter, MIT) as a service
    on port 9182 with the collectors this machine's roles call for, so the
    lab's Grafana (role grafana on an Ubuntu appliance) can draw it. The MSI
    is fetched onto the PC by `winlab exporter fetch` and reaches the machine
    on its provisioning volume (C:\\winlab after first logon) or over the agent
    channel; nothing is downloaded inside the lab."""
    from . import exporters, metrics
    collectors = ",".join(metrics.collectors_for(cfg.node))
    msi = exporters.MSI_NAME
    port = metrics.WINDOWS_PORT
    install = cfg.script(
        "WindowsExporter",
        "[bool](Get-Service -Name 'windows_exporter' -ErrorAction SilentlyContinue)",
        f"$msi = 'C:\\winlab\\{msi}'\n"
        "if (-not (Test-Path $msi)) {\n"
        "    $vol = Get-Volume -FileSystemLabel 'WLDATA' -ErrorAction SilentlyContinue | "
        "Where-Object DriveLetter | Select-Object -First 1\n"
        f"    if ($vol) {{ $msi = ('{{0}}:\\{msi}' -f $vol.DriveLetter) }}\n"
        "}\n"
        "if (-not (Test-Path $msi)) { throw 'the Windows exporter installer is not on this machine: run "
        "winlab exporter fetch on the PC and apply the role again' }\n"
        f"$msiArgs = @('/i', $msi, 'ENABLED_COLLECTORS={collectors}', 'LISTEN_PORT={port}', "
        "'/qn', '/norestart', '/L*v', 'C:\\winlab\\windows_exporter-install.log')\n"
        "$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow\n"
        "if ($p.ExitCode -eq 3010) {\n"
        "    $global:DSCMachineStatus = 1\n"
        "} elseif ($p.ExitCode -ne 0) {\n"
        "    throw ('windows_exporter setup exited {0}; see C:\\winlab\\windows_exporter-install.log' -f $p.ExitCode)\n"
        "}",
        get="@{ Result = (Get-Service -Name 'windows_exporter' -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Status.ToString() }) }")
    svc = cfg.add(Resource("Service", "WindowsExporterService", {
        "Name": "windows_exporter", "State": "Running", "StartupType": "Automatic",
    }, depends_on=[install]))
    cfg.firewall(f"winlab-metrics-{port}", local_port=[str(port)], depends=[install])
    cfg.text_file("MetricsReadme", "C:\\winlab\\metrics-README.txt", (
        "Prometheus Windows exporter (winlab role metrics)\r\n"
        f"  service:     windows_exporter, listening on http://{cfg.hostname}:{port}/metrics\r\n"
        f"  collectors:  {collectors}\r\n"
        f"  firewall:    rule winlab-metrics-{port} (TCP {port}, any profile)\r\n"
        "  scraped by:  the lab's monitoring appliance (role grafana), Grafana on port 3000\r\n"
        "  change collectors: reinstall with msiexec /i windows_exporter.msi ENABLED_COLLECTORS=... or edit\r\n"
        "    the service's ImagePath (HKLM\\SYSTEM\\CurrentControlSet\\Services\\windows_exporter) and restart it\r\n"),
        depends=[svc.id])


def build_wac(cfg: NodeConfig) -> None:
    """Windows Admin Center as a gateway on https 443, so the lab's servers
    (the Server Core file server above all) can be run from a browser inside
    the lab. The installer is Microsoft's: fetched onto the PC by `winlab wac
    fetch`, never shipped with winlab, and run only when its Authenticode
    signature is valid and Microsoft's."""
    from . import wac
    exe = wac.EXE_NAME
    port = wac.PORT
    have = ("[bool](Get-Service -Name 'WindowsAdminCenter','ServerManagementGateway' "
            "-ErrorAction SilentlyContinue)")
    install = cfg.script(
        "WindowsAdminCenter", have,
        f"$exe = 'C:\\winlab\\{exe}'\n"
        "if (-not (Test-Path $exe)) {\n"
        "    $vol = Get-Volume -FileSystemLabel 'WLDATA' -ErrorAction SilentlyContinue | "
        "Where-Object DriveLetter | Select-Object -First 1\n"
        f"    if ($vol) {{ $exe = ('{{0}}:\\{exe}' -f $vol.DriveLetter) }}\n"
        "}\n"
        "if (-not (Test-Path $exe)) { throw 'the Windows Admin Center installer is not on this machine: run "
        "winlab wac fetch on the PC and apply the role again' }\n"
        "$sig = Get-AuthenticodeSignature -FilePath $exe\n"
        "if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {\n"
        "    throw ('the Windows Admin Center installer is not signed by Microsoft ({0}); fetch it again' "
        "-f $sig.Status)\n"
        "}\n"
        "$wacArgs = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/LOG=C:\\winlab\\wac-install.log')\n"
        "$p = Start-Process -FilePath $exe -ArgumentList $wacArgs -Wait -PassThru\n"
        "if ($p.ExitCode -eq 3010) {\n"
        "    $global:DSCMachineStatus = 1\n"
        "} elseif ($p.ExitCode -ne 0) {\n"
        "    throw ('Windows Admin Center setup exited {0}; see C:\\winlab\\wac-install.log' -f $p.ExitCode)\n"
        "}",
        get="@{ Result = (Get-Service -Name 'WindowsAdminCenter','ServerManagementGateway' "
            "-ErrorAction SilentlyContinue | ForEach-Object { $_.Status.ToString() }) -join ',' }")
    cfg.firewall(f"winlab-wac-{port}", local_port=[str(port)], depends=[install])
    cfg.text_file("WacReadme", "C:\\winlab\\wac-README.txt", (
        "Windows Admin Center (winlab role wac)\r\n"
        f"  open:        https://{cfg.hostname}/ from a machine in the lab (Edge on the Windows 11 PC)\r\n"
        "  sign in:     a domain admin; the certificate is self-signed, so the browser warns once\r\n"
        "  add servers: Add > Servers > the server's name; it talks to them over WinRM (5985)\r\n"
        f"  firewall:    rule winlab-wac-{port} (TCP {port}, any profile)\r\n"
        "  installer:   Microsoft's, downloaded onto the PC by winlab wac fetch; log C:\\winlab\\wac-install.log\r\n"),
        depends=[install])


def _cluster_nodes(cfg: NodeConfig) -> list:
    return [n for n in cfg.lab.node_list() if "cluster-node" in n.roles]


def build_cluster_storage(cfg: NodeConfig) -> None:
    """Shared disks for a failover cluster: an iSCSI target 'cluster' with a
    1 GB witness LUN and two 20 GB LUNs (a clustered file server's disk, and
    one for virtual machines as a Cluster Shared Volume), offered only to the machines that
    carry the cluster-node role (by DNS name), the way a SAN zones its LUNs."""
    from .naming import hostname_of
    feat = cfg.feature("FS-iSCSITarget-Server")
    root = f"{cfg.data_root}\\iSCSI"
    who = ", ".join(ps_quote(f"DNSName:{hostname_of(n).lower()}.{cfg.domain}") for n in _cluster_nodes(cfg))
    if not who:
        raise DscError(f"{cfg.node.id}: cluster-storage serves the machines with the cluster-node role, "
                       f"and this lab has none")
    cfg.script(
        "IscsiTarget_cluster",
        "[bool](Get-IscsiServerTarget -TargetName 'cluster' -ErrorAction SilentlyContinue | "
        "Where-Object { @($_.LunMappings).Count -ge 3 })",
        f"New-Item -ItemType Directory -Path '{root}' -Force | Out-Null\n"
        f"$witness = '{root}\\cluster-witness.vhdx'\n"
        f"$data = '{root}\\cluster-data.vhdx'\n"
        f"$vms = '{root}\\cluster-vms.vhdx'\n"
        "if (-not (Test-Path $witness)) { New-IscsiVirtualDisk -Path $witness -SizeBytes 1GB | Out-Null }\n"
        "if (-not (Test-Path $data)) { New-IscsiVirtualDisk -Path $data -SizeBytes 20GB | Out-Null }\n"
        "if (-not (Test-Path $vms)) { New-IscsiVirtualDisk -Path $vms -SizeBytes 20GB | Out-Null }\n"
        "if (-not (Get-IscsiServerTarget -TargetName 'cluster' -ErrorAction SilentlyContinue)) {\n"
        f"    New-IscsiServerTarget -TargetName 'cluster' -InitiatorIds @({who}) | Out-Null\n"
        "}\n"
        "Add-IscsiVirtualDiskTargetMapping -TargetName 'cluster' -Path $witness -ErrorAction SilentlyContinue\n"
        "Add-IscsiVirtualDiskTargetMapping -TargetName 'cluster' -Path $data -ErrorAction SilentlyContinue\n"
        "Add-IscsiVirtualDiskTargetMapping -TargetName 'cluster' -Path $vms -ErrorAction SilentlyContinue",
        get="@{ Result = (Get-IscsiServerTarget -TargetName 'cluster' -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Status.ToString() }) }",
        depends=[feat] + _data_deps(cfg))
    cfg.firewall("winlab-iscsi-target-3260", local_port=["3260"], depends=[feat])


def build_cluster_node(cfg: NodeConfig) -> None:
    """A machine ready to be clustered: the Failover Clustering feature and
    its tools, and the shared disks of the lab's cluster-storage machine
    connected over iSCSI and kept across restarts. Creating the cluster is
    the student's job (the failover-cluster lesson)."""
    store = [n for n in cfg.lab.node_list() if "cluster-storage" in n.roles]
    portal = next((nic.ip for n in store for nic in n.nics if nic.ip), "")
    if not portal:
        raise DscError(f"{cfg.node.id}: cluster-node needs a machine with the cluster-storage role and a static "
                       f"address in the lab, to connect its disks")
    feat = cfg.feature("Failover-Clustering")
    tools = cfg.feature("RSAT-Clustering-PowerShell", depends=[feat])
    if not cfg.node.is_server_core:
        cfg.feature("RSAT-Clustering-Mgmt", depends=[feat])
    svc = cfg.add(Resource("Service", "MSiSCSI", {
        "Name": "MSiSCSI", "State": "Running", "StartupType": "Automatic",
    }))
    cfg.script(
        "IscsiClusterDisks",
        "[bool](Get-IscsiSession -ErrorAction SilentlyContinue | Where-Object { $_.TargetNodeAddress -like '*:cluster' -and $_.IsPersistent })",
        f"if (-not (Get-IscsiTargetPortal -ErrorAction SilentlyContinue | Where-Object TargetPortalAddress -eq '{portal}')) {{\n"
        f"    New-IscsiTargetPortal -TargetPortalAddress '{portal}' | Out-Null\n"
        "}\n"
        "Update-IscsiTarget -ErrorAction SilentlyContinue | Out-Null\n"
        "$t = Get-IscsiTarget | Where-Object NodeAddress -like '*:cluster' | Select-Object -First 1\n"
        f"if (-not $t) {{ throw 'the cluster target on {portal} is not offered to this machine yet: apply the "
        "cluster-storage role first, then this one again' }\n"
        "if (-not $t.IsConnected) { Connect-IscsiTarget -NodeAddress $t.NodeAddress -IsPersistent $true | Out-Null }",
        get="@{ Result = (@(Get-IscsiSession -ErrorAction SilentlyContinue).Count).ToString() }",
        depends=[svc.id, tools])


# ------------------------------------------------------------------ AD FS
def _ca_config(cfg: NodeConfig) -> str:
    """'<ca host fqdn>\\<CA name>' of the lab's enterprise CA (role adcs), or
    '' when the lab has none and a role must make do with self-signed."""
    from .naming import hostname_of
    for n in cfg.lab.node_list():
        if "adcs" in n.roles and n.id != cfg.node.id:
            cn = str(n.vars.get("ca_common_name") or f"{cfg.netbios} Issuing CA")
            return f"{hostname_of(n).lower()}.{cfg.domain}\\{cn}"
    return ""


def build_adfs(cfg: NodeConfig) -> None:
    """Active Directory Federation Services: a one-server farm on the
    Windows Internal Database, its service account a group managed service
    account (so nobody knows a password), its TLS certificate from the lab's
    enterprise CA when there is one (self-signed otherwise), and the
    federation service name in DNS. Relying parties are the student's work."""
    from .dsc import _LAB_CRED
    feat = cfg.feature("ADFS-Federation")
    tools = _ad_tools(cfg) + [cfg.feature("RSAT-DNS-Server")]
    dom = _domain(cfg)
    fs = str(cfg.vars.get("federation_name") or f"sts.{cfg.domain}").lower()
    gmsa = str(cfg.vars.get("adfs_account") or "gmsaADFS")[:15]
    ip = next((n.get("ip") for n in cfg.facts.get("nics") or [] if n.get("ip")), "")
    ca = _ca_config(cfg)
    kds = cfg.script(
        "KdsRootKey",
        "[bool](Get-KdsRootKey)",
        # A lab may backdate the key so it is usable now; production waits
        # ten hours for it to replicate to every DC.
        "Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null",
        depends=tools + [dom], run_as=True)
    acct = cfg.script(
        "AdfsServiceAccount",
        "Import-Module ActiveDirectory\n"
        f"$a = Get-ADServiceAccount -Filter \"Name -eq '{gmsa}'\" -Properties PrincipalsAllowedToRetrieveManagedPassword\n"
        "if (-not $a) { return $false }\n"
        f"$me = (Get-ADComputer -Identity {ps_quote(cfg.hostname)}).DistinguishedName\n"
        "[bool]($a.PrincipalsAllowedToRetrieveManagedPassword -contains $me)",
        "Import-Module ActiveDirectory\n"
        f"$me = Get-ADComputer -Identity {ps_quote(cfg.hostname)}\n"
        f"$a = Get-ADServiceAccount -Filter \"Name -eq '{gmsa}'\"\n"
        "if ($a) {\n"
        f"    Set-ADServiceAccount -Identity {ps_quote(gmsa)} -PrincipalsAllowedToRetrieveManagedPassword $me\n"
        "} else {\n"
        f"    New-ADServiceAccount -Name {ps_quote(gmsa)} -DNSHostName {ps_quote(fs)} "
        f"-ServicePrincipalNames {ps_quote('host/' + fs)} -PrincipalsAllowedToRetrieveManagedPassword $me "
        "-KerberosEncryptionType AES128,AES256\n"
        "}",
        depends=[kds], run_as=True)
    dns = cfg.script(
        "FederationNameInDns",
        f"[bool](Resolve-DnsName -Name {ps_quote(fs)} -Type A -DnsOnly -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.IPAddress -eq {ps_quote(ip)} }})",
        "Import-Module DnsServer\n"
        "$dc = (Get-ADDomainController -Discover).HostName | Select-Object -First 1\n"
        f"$name = {ps_quote(fs.split('.', 1)[0])}\n"
        f"$zone = {ps_quote(cfg.domain)}\n"
        "Get-DnsServerResourceRecord -ComputerName $dc -ZoneName $zone -Name $name -RRType A -ErrorAction SilentlyContinue | "
        "Remove-DnsServerResourceRecord -ComputerName $dc -ZoneName $zone -Force -ErrorAction SilentlyContinue\n"
        f"Add-DnsServerResourceRecordA -ComputerName $dc -ZoneName $zone -Name $name -IPv4Address {ps_quote(ip)}\n"
        "Clear-DnsClientCache",
        depends=tools + [dom], run_as=True)
    find_cert = (f"$fs = {ps_quote(fs)}\n"
                 "$cert = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.Subject -eq \"CN=$fs\" -and "
                 "$_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } | Sort-Object NotAfter -Descending | Select-Object -First 1\n")
    if ca:
        enrol = (find_cert + "if (-not $cert) {\n"
                 "    $r = Get-Certificate -Template 'WebServer' -SubjectName \"CN=$fs\" "
                 f"-DnsName $fs, {ps_quote(cfg.fqdn.lower())} -CertStoreLocation 'Cert:\\LocalMachine\\My' -Url 'ldap:'\n"
                 "    if ($r.Status -ne 'Issued') { throw ('the enterprise CA did not issue the AD FS certificate: {0}' -f $r.Status) }\n"
                 "}")
        cfg.notes.append(f"adfs: TLS certificate CN={fs} from the enterprise CA {ca} (template WebServer)")
    else:
        enrol = (find_cert + "if (-not $cert) {\n"
                 f"    New-SelfSignedCertificate -DnsName $fs, {ps_quote(cfg.fqdn.lower())} "
                 "-CertStoreLocation 'Cert:\\LocalMachine\\My' -NotAfter (Get-Date).AddYears(2) | Out-Null\n"
                 "}")
        cfg.notes.append(f"adfs: no enterprise CA in the lab, so CN={fs} is self-signed; browsers will warn")
    cert = cfg.script("AdfsCertificate", find_cert + "[bool]$cert", enrol,
                      depends=[feat, dom], run_as=bool(ca))
    farm = cfg.script(
        "AdfsFarm",
        "try { [bool](Get-AdfsProperties -ErrorAction Stop) } catch { $false }",
        _LAB_CRED + find_cert
        + "if (-not $cert) { throw \"no certificate CN=$fs with a private key in LocalMachine\\My\" }\n"
        "Import-Module ADFS\n"
        "$r = Install-AdfsFarm -CertificateThumbprint $cert.Thumbprint -FederationServiceName $fs "
        f"-FederationServiceDisplayName {ps_quote(cfg.netbios + ' sign-in')} "
        f"-GroupServiceAccountIdentifier {ps_quote(cfg.netbios + chr(92) + gmsa + '$')} "
        "-Credential $cred -OverwriteConfiguration -ErrorAction Stop\n"
        "if ($r.Status -ne 'Success') { throw ('Install-AdfsFarm: {0} {1}' -f $r.Status, $r.Message) }\n"
        "if ($r.Context -match 'Restart') { $global:DSCMachineStatus = 1 }",
        get="@{ Result = (Get-Service -Name 'adfssrv' -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Status.ToString() }) }",
        depends=[feat, acct, dns, cert])
    svc = cfg.add(Resource("Service", "AdfsService", {
        "Name": "adfssrv", "State": "Running", "StartupType": "Automatic",
    }, depends_on=[farm]))
    cfg.text_file("AdfsReadme", "C:\\winlab\\adfs-README.txt", (
        "Active Directory Federation Services (winlab role adfs)\r\n"
        f"  federation service:  https://{fs}/  (A record in {cfg.domain} -> {ip})\r\n"
        f"  metadata:            https://{fs}/FederationMetadata/2007-06/FederationMetadata.xml\r\n"
        f"  test sign-in page:   https://{fs}/adfs/ls/idpinitiatedsignon.aspx (off until\r\n"
        "                       Set-AdfsProperties -EnableIdPInitiatedSignonPage $true)\r\n"
        f"  service account:     {cfg.netbios}\\{gmsa}$ (group managed; this server may retrieve its password)\r\n"
        f"  TLS certificate:     CN={fs}, " + (f"issued by {ca}" if ca else "self-signed") + "\r\n"
        "  configuration store: Windows Internal Database on this server (a one-server farm)\r\n"
        "  console:             Server Manager > Tools > AD FS Management, or the ADFS PowerShell module\r\n"),
        depends=[svc.id])


# ------------------------------------------------------- Configuration Manager
_MECM_DVD = (
    "$dvd = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and "
    "(Test-Path ('{0}:\\CM\\SMSSETUP\\BIN\\X64\\setup.exe' -f $_.DriveLetter)) } | Select-Object -First 1\n"
    "if (-not $dvd) { throw 'the Configuration Manager disc is not in the DVD drive: prepare it with "
    "winlab mecm prepare (or Setup in the app) and apply the role again' }\n"
    "$dvd = '{0}:' -f $dvd.DriveLetter\n"
)

_MECM_FEATURES = (
    # Site server and SMS Provider
    "NET-Framework-45-Core", "RDC",
    # Management point and distribution point over HTTP
    "Web-Server", "Web-ISAPI-Ext", "Web-Windows-Auth", "Web-Metabase", "Web-WMI",
    "BITS", "BITS-IIS-Ext",
)


def build_mecm(cfg: NodeConfig) -> None:
    """Microsoft Configuration Manager (current branch, evaluation): a
    standalone primary site with its management point and distribution
    point on this server over HTTP, the site database on the lab's SQL
    Server (role sql on another machine, from the user's own SQL Server
    ISO), the AD schema extended and the System Management container
    delegated to this server. Everything installs from the winlab-built
    mecm disc (`winlab mecm prepare`), so the lab never reaches the
    Internet. Discovery, boundaries, clients and collections are the
    student's work."""
    from .naming import hostname_of
    site = str(cfg.vars.get("site_code") or "LAB").upper()[:3]
    if not re.fullmatch(r"[A-Z0-9]{3}", site):
        raise DscError(f"{cfg.node.id}: site_code must be three letters or digits, not {site!r}")
    sql_node = _mecm_sql_node(cfg, cfg.node)
    if sql_node is None:
        raise DscError(f"{cfg.node.id}: the mecm role needs a machine with the sql role in the lab "
                       "for its site database (SQL Server 2022 from your own ISO)")
    sql = f"{hostname_of(sql_node).lower()}.{cfg.domain}"
    db = f"CM_{site}"
    fqdn = cfg.fqdn.lower()
    install_dir = f"{cfg.data_root}\\ConfigMgr"
    dom = _domain(cfg)
    tools = _ad_tools(cfg)
    data = _data_deps(cfg)
    feats = [cfg.feature(f) for f in _MECM_FEATURES]
    cfg.notes.append(f"mecm: primary site {site}, database {db} on {sql} (needs the sql2022 ISO there), "
                     "media from winlab mecm prepare")

    adk = cfg.script(
        "WindowsAdk",
        "[bool](Get-ItemProperty 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows Kits\\Installed Roots' "
        "-ErrorAction SilentlyContinue).KitsRoot10 -and "
        "(Test-Path (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\\10\\Assessment and Deployment Kit\\Deployment Tools'))",
        _MECM_DVD
        + "$p = Start-Process -FilePath \"$dvd\\ADK\\adksetup.exe\" -ArgumentList '/quiet', '/norestart', '/ceip', 'off', "
        "'/features', 'OptionId.DeploymentTools', 'OptionId.UserStateMigrationTool', "
        "'/log', 'C:\\winlab\\adk-install.log' -Wait -PassThru -NoNewWindow\n"
        "if ($p.ExitCode -notin 0, 3010) { throw ('the Windows ADK setup exited {0}; see C:\\winlab\\adk-install.log' -f $p.ExitCode) }",
        depends=feats)
    winpe = cfg.script(
        "WindowsPeAddOn",
        "Test-Path (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\\10\\Assessment and Deployment Kit\\Windows Preinstallation Environment')",
        _MECM_DVD
        + "$p = Start-Process -FilePath \"$dvd\\WINPE\\adkwinpesetup.exe\" -ArgumentList '/quiet', '/norestart', '/ceip', 'off', "
        "'/features', 'OptionId.WindowsPreinstallationEnvironment', "
        "'/log', 'C:\\winlab\\winpe-install.log' -Wait -PassThru -NoNewWindow\n"
        "if ($p.ExitCode -notin 0, 3010) { throw ('the Windows PE add-on setup exited {0}; see C:\\winlab\\winpe-install.log' -f $p.ExitCode) }",
        depends=[adk])
    odbc = cfg.script(
        "OdbcDriver18",
        "[bool](Get-OdbcDriver -Name 'ODBC Driver 18 for SQL Server' -Platform '64-bit' -ErrorAction SilentlyContinue)",
        _MECM_DVD
        + "$msi = Get-ChildItem -Path \"$dvd\\ODBC\" -Filter 'msodbcsql*.msi' | Select-Object -First 1\n"
        "$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i', $msi.FullName, '/qn', '/norestart', "
        "'IACCEPTMSODBCSQLLICENSETERMS=YES', '/L*v', 'C:\\winlab\\odbc-install.log' -Wait -PassThru -NoNewWindow\n"
        "if ($p.ExitCode -notin 0, 3010) { throw ('the ODBC driver setup exited {0}; see C:\\winlab\\odbc-install.log' -f $p.ExitCode) }",
        depends=feats)
    schema = cfg.script(
        "ConfigMgrSchema",
        "Import-Module ActiveDirectory\n"
        "[bool](Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext "
        "-Filter \"lDAPDisplayName -eq 'mSSMSSiteCode'\")",
        _MECM_DVD
        + "$p = Start-Process -FilePath \"$dvd\\CM\\SMSSETUP\\BIN\\X64\\extadsch.exe\" -Wait -PassThru -NoNewWindow\n"
        "if ($p.ExitCode -ne 0) { throw ('extadsch exited {0}; see C:\\ExtADSch.log' -f $p.ExitCode) }",
        depends=tools + [dom], run_as=True)
    me = ps_quote(cfg.hostname)
    container = cfg.script(
        "SystemManagementContainer",
        "Import-Module ActiveDirectory\n"
        f"$dn = 'CN=System Management,CN=System,{cfg.base_dn}'\n"
        "if (-not (Get-ADObject -Filter \"distinguishedName -eq '$dn'\")) { return $false }\n"
        f"$sid = (Get-ADComputer -Identity {me}).SID\n"
        "[bool]((Get-Acl -Path \"AD:$dn\").Access | Where-Object { $_.IdentityReference.Translate("
        "[System.Security.Principal.SecurityIdentifier]) -eq $sid -and "
        "$_.ActiveDirectoryRights -match 'GenericAll' -and $_.InheritanceType -eq 'All' })",
        "Import-Module ActiveDirectory\n"
        f"$dn = 'CN=System Management,CN=System,{cfg.base_dn}'\n"
        "if (-not (Get-ADObject -Filter \"distinguishedName -eq '$dn'\")) {\n"
        f"    New-ADObject -Name 'System Management' -Type 'container' -Path 'CN=System,{cfg.base_dn}'\n"
        "}\n"
        f"$sid = (Get-ADComputer -Identity {me}).SID\n"
        "$acl = Get-Acl -Path \"AD:$dn\"\n"
        "$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule("
        "$sid, 'GenericAll', 'Allow', 'All')))\n"
        "Set-Acl -Path \"AD:$dn\" -AclObject $acl",
        depends=tools + [dom], run_as=True)
    content_drive = []
    if data:
        # Content library and package shares stay off the system drive.
        content_drive = [cfg.text_file("MecmNotOnC", "C:\\NO_SMS_ON_DRIVE.SMS", "", depends=data)]
    ini = ",\n".join("    " + ps_quote(line) for line in [
        "[Identification]", "Action=InstallPrimarySite", "",
        "[Options]", "ProductID=EVAL", f"SiteCode={site}", f"SiteName={cfg.netbios} lab primary site",
        f"SMSInstallDir={install_dir}", f"SDKServer={fqdn}", "PrerequisiteComp=1",
        "PrerequisitePath=__DVD__\\PREREQS", "AdminConsole=1", "JoinCEIP=0", "CurrentBranch=1",
        "MobileDeviceLanguage=0", "RoleCommunicationProtocol=HTTPorHTTPS", "ClientsUsePKICertificate=0",
        f"ManagementPoint={fqdn}", "ManagementPointProtocol=HTTP",
        f"DistributionPoint={fqdn}", "DistributionPointProtocol=HTTP", "DistributionPointInstallIIS=0", "",
        "[SQLConfigOptions]", f"SQLServerName={sql}", f"DatabaseName={db}", f"SQLSSBPort={MECM_SSB_PORT}", "",
        "[CloudConnectorOptions]", "CloudConnector=0", f"CloudConnectorServer={fqdn}", "UseProxy=0", "",
        "[SystemCenterOptions]", "", "[HierarchyExpansionOption]", ""])
    ini = f"$ini = @(\n{ini}\n) -join \"`r`n\"\n"
    reach = cfg.script(
        "SiteDatabaseServer",
        f"[bool](Test-NetConnection -ComputerName {ps_quote(sql)} -Port 1433 -InformationLevel Quiet -WarningAction SilentlyContinue)",
        "$until = (Get-Date).AddMinutes(30)\n"
        f"while (-not (Test-NetConnection -ComputerName {ps_quote(sql)} -Port 1433 -InformationLevel Quiet -WarningAction SilentlyContinue)) {{\n"
        f"    if ((Get-Date) -gt $until) {{ throw 'SQL Server on {sql} does not answer on TCP 1433: start {sql_node.id}, "
        "apply its sql role (it needs the sql2022 ISO), then this role again' }\n"
        "    Start-Sleep -Seconds 30\n"
        "}",
        depends=[dom])
    acct = f"{cfg.netbios}\\{cfg.hostname.upper()}$"
    sql_q = (f"$c = New-Object System.Data.SqlClient.SqlConnection('Server={sql};Database=master;"
             "Integrated Security=SSPI;Connect Timeout=30')\n$c.Open()\n"
             "$cmd = $c.CreateCommand()\n")
    rights = cfg.script(
        "SiteServerRightsOnSql",
        sql_q
        + f"$cmd.CommandText = \"SELECT IS_SRVROLEMEMBER('sysadmin', '{acct}')\"\n"
        "$login = $cmd.ExecuteScalar()\n$c.Close()\n"
        f"$admin = Invoke-Command -ComputerName {ps_quote(sql)} -ScriptBlock {{ [bool](Get-LocalGroupMember -Group 'Administrators' | "
        f"Where-Object Name -eq {ps_quote(acct)}) }}\n"
        "[bool]($login -eq 1 -and $admin)",
        sql_q
        + f"$cmd.CommandText = \"IF SUSER_ID('{acct}') IS NULL CREATE LOGIN [{acct}] FROM WINDOWS; "
        f"ALTER SERVER ROLE sysadmin ADD MEMBER [{acct}];\"\n"
        "$cmd.ExecuteNonQuery() | Out-Null\n$c.Close()\n"
        f"Invoke-Command -ComputerName {ps_quote(sql)} -ScriptBlock {{\n"
        f"    if (-not (Get-LocalGroupMember -Group 'Administrators' | Where-Object Name -eq {ps_quote(acct)})) {{\n"
        f"        Add-LocalGroupMember -Group 'Administrators' -Member {ps_quote(acct)}\n"
        "    }\n"
        "}",
        depends=[reach], run_as=True)
    setup = cfg.script(
        "ConfigMgrPrimarySite",
        "[bool](Get-Service -Name 'SMS_EXECUTIVE' -ErrorAction SilentlyContinue)",
        _MECM_DVD
        + ini + "$ini = $ini.Replace('__DVD__', $dvd)\n"
        "New-Item -ItemType Directory -Path 'C:\\winlab\\mecm' -Force | Out-Null\n"
        "Set-Content -Path 'C:\\winlab\\mecm\\setup.ini' -Value $ini -Encoding ASCII\n"
        "$p = Start-Process -FilePath \"$dvd\\CM\\SMSSETUP\\BIN\\X64\\setup.exe\" "
        "-ArgumentList '/SCRIPT', 'C:\\winlab\\mecm\\setup.ini', '/NOUSERINPUT' -Wait -PassThru -NoNewWindow\n"
        "# setup can hand over to its own service and return before the site is up.\n"
        "$until = (Get-Date).AddMinutes(60)\n"
        "while (-not (Get-Service -Name 'SMS_EXECUTIVE' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $until) {\n"
        "    if (Select-String -Path 'C:\\ConfigMgrSetup.log' -Pattern 'Setup failed|ERROR:' -Quiet -ErrorAction SilentlyContinue) { break }\n"
        "    Start-Sleep -Seconds 30\n"
        "}\n"
        "if (-not (Get-Service -Name 'SMS_EXECUTIVE' -ErrorAction SilentlyContinue)) {\n"
        "    $tail = if (Test-Path 'C:\\ConfigMgrSetup.log') { (Get-Content -Path 'C:\\ConfigMgrSetup.log' -Tail 12) -join ' | ' } "
        "else { 'no C:\\ConfigMgrSetup.log' }\n"
        "    throw ('Configuration Manager setup exited {0} without a site: {1} (prerequisite results are in C:\\ConfigMgrPrereq.log)' -f $p.ExitCode, $tail)\n"
        "}",
        get="@{ Result = (Get-Service -Name 'SMS_EXECUTIVE' -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Status.ToString() }) }",
        depends=[adk, winpe, odbc, schema, container, rights] + content_drive + data, run_as=True)
    svc = cfg.add(Resource("Service", "SmsExecutive", {
        "Name": "SMS_EXECUTIVE", "State": "Running", "StartupType": "Automatic",
    }, depends_on=[setup]))
    cfg.text_file("MecmReadme", "C:\\winlab\\mecm-README.txt", (
        "Microsoft Configuration Manager (winlab role mecm)\r\n"
        f"  site:               {site}, a standalone primary site (evaluation, 180 days)\r\n"
        f"  site server:        {fqdn}, installed in {install_dir}\r\n"
        f"  site database:      {db} on {sql} (the lab's SQL Server)\r\n"
        f"  roles here:         management point and distribution point, HTTP\r\n"
        f"  client files:       \\\\{cfg.hostname}\\SMS_{site}\\Client\\ccmsetup.exe\r\n"
        "  console:            Start > Microsoft Endpoint Manager > Configuration Manager Console\r\n"
        "  PowerShell:         from the console's menu, Connect via Windows PowerShell\r\n"
        "  setup logs:         C:\\ConfigMgrSetup.log, C:\\ConfigMgrPrereq.log\r\n"
        f"  site logs:          {install_dir}\\Logs (CMTrace in {install_dir}\\tools)\r\n"),
        depends=[svc.id])


BUILDERS: dict[str, Callable[[NodeConfig], None]] = {
    "adfs": build_adfs,
    "mecm": build_mecm,
    "ou-structure": build_ou_structure,
    "users-groups": build_users_groups,
    "gpo": build_gpo,
    "file": build_file,
    "dfs": build_dfs,
    "adcs": build_adcs,
    "adcs-root": build_adcs_root,
    "iis": build_iis,
    "sql": build_sql,
    "metrics": build_metrics,
    "wac": build_wac,
    "cluster-storage": build_cluster_storage,
    "cluster-node": build_cluster_node,
    "firewall": build_firewall,
    "ntp": build_ntp,
    "fsrm": build_fsrm,
    "wsus": build_wsus,
    "backup": build_backup,
    "rds": build_rds,
    "storage": build_storage,
    "monitoring": build_monitoring,
    "rras": build_rras,
    "vpn-s2s": build_vpn_s2s,
    "nps": build_nps,
    "laps": build_laps,
    "printer": build_printer,
    "hardening": build_hardening,
    "dsc": build_dsc,
    "devices": build_devices,
    "connect-devices": build_connect_devices,
    "drivers": build_drivers,
    "lean": build_lean,
}
