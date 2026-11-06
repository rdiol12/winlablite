"""Free play under load: the student starts the load engine from inside the lab.

In a normal lab the load engine (winlab/workday.py, winlab/traffic.py)
knows from the lab's plan which machine is the domain controller, which the
file server, and who works there. In free play (the sandbox, and networks
built in the Build window) nothing has a role: the student built a domain,
shares, printers and mail by hand, under names they chose, and the plan
knows none of it. So the engine is started from where the student works,
inside the network, and it looks around first.

The command. The "Load engine" stick on the media shelf carries a small
PowerShell module, OfficeLoad. The student copies it onto a machine of
theirs and types Start-OfficeLoad (with -StaffGroup, -Level, -Profile and
the rest), Stop-OfficeLoad or Get-OfficeLoad. Start-OfficeLoad asks once
for the first password the student gave the staff accounts (Read-Host
-AsSecureString; Enter skips it) and leaves a request file in
C:\\ProgramData\\winlab\\load, a folder only SYSTEM and the administrators
can open.

The channel. Nothing in the lab reaches the host. winlab looks for the
request the way it reaches every guest: through the machine's serial agent,
on the desktop's normal poll. The same call writes winlab's latest status
into that folder (status.json), which Get-OfficeLoad reads, and takes the
request away (it is deleted as it is read; the secret in it goes only into
this lab's staff-secrets file under var/, the one `winlab staff password`
fills).

The discovery, read-only. From the machine the request came from: the
domain it is joined to and its domain controllers (the .NET domain object,
nltest and the _ldap._tcp SRV records), the NetBIOS name, the computer
objects, the staff (the members of -StaffGroup, the users in -StaffOU, or
every enabled ordinary user), the printers published in the directory,
SQL Server's service names, the MX record, the DNS names an office uses
(intranet, www, portal, mail) and the WSUS server Group Policy points at.
Then from each running Windows machine of the lab: its own computer name
and domain, whether it is a workstation, a domain controller or a server,
its shares, its shared printers, its web bindings, its SQL Server
instances, whether it is a Remote Desktop session host or a WSUS server.
The computer names map back to the lab's machines (the name the student
gave it inside Windows first, then the plan's), and the result is the facts
dict the engine already uses, marked source "discovered" and kept in this
lab's folder (load-discovered.json). workday.lab_facts and the staff list
prefer it while it is there; a lab that never ran Start-OfficeLoad keeps
its plan's facts.

Then the engine starts on what was found: the working day at the asked
level, the traffic profile, the servers' own work only where a server for
it was found. Tickets and calls flow as usual. When the domain, a domain
controller, a PC or the staff are missing, nothing starts and the reason is
written back to the guest. Start-OfficeLoad -Rediscover looks again, and so
does winlab by itself when a Windows machine it has not seen starts.

Hands-on: discovery only reads. Every share, account, printer and site the
load uses is one the student made. The pure parts (the commands, what the
answers mean, the facts, the staff, the request) take everything as
arguments, so the suite runs them with a fake runner and no machine.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import threading
import time
from pathlib import Path
from typing import Callable

from . import paths

Runner = Callable[[str, str, str], tuple[bool, str]]

FILE = "freeload.json"                 # the free-play state: the stick, who started it, the last status
FOUND_FILE = "load-discovered.json"    # the discovered facts and staff
GUEST_DIR = "C:\\ProgramData\\winlab\\load"
STICK_ID = "load-engine"
STICK_TITLE = "Load engine (OfficeLoad module)"
STICK_LABEL = "OFFICELOAD"
MODULE_FILES = ("OfficeLoad.psm1", "OfficeLoad.psd1")
POLL_EVERY = 30.0              # real seconds between two looks for requests
REDISCOVER_AFTER = 120.0       # real seconds: a new machine is looked at no sooner
MAX_STAFF = 40                 # the most people one discovery puts to work
LEVELS = ("quiet", "normal", "busy")
PROFILES = ("office", "flat", "round")
PACES = ("normal", "busyday")
ACTIONS = ("start", "stop")
# Shares every Windows machine or every domain controller has: not a file server's.
SYSTEM_SHARES = {"ADMIN$", "IPC$", "PRINT$", "NETLOGON", "SYSVOL", "CERTENROLL", "WSUSCONTENT",
                 "UPDATESERVICESPACKAGES", "WSUSTEMP", "REMINST"}
COMPANY_FIRST = ("company", "shared", "share", "public", "data", "files", "office", "common", "departments")
WEB_NAMES = ("intranet", "www", "portal", "mail", "webmail")
REQ_MARK, HOST_MARK = "@@WL-LOAD-REQ", "@@WL-LOAD-HOST"
BEGIN, END = "@@WL-DISCOVERY-BEGIN", "@@WL-DISCOVERY-END"
# ProductType from Win32_OperatingSystem.
WORKSTATION, DOMAIN_CONTROLLER, SERVER = 1, 2, 3

_lock = threading.RLock()
_last_poll: dict[str, float] = {}


class FreeloadError(Exception):
    pass


# =================================================================== storage
def state_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def found_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FOUND_FILE


def _read(f: Path) -> dict:
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(f: Path, data: dict) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        tmp.replace(f)


def load(lab_name: str) -> dict:
    return {"stick": "", "origin": "", "by": "", "started": 0.0, "settings": {}, "status": {},
            "seen": [], "discovered_at": 0.0, **_read(state_file(lab_name))}


def save(lab_name: str, st: dict) -> None:
    _write(state_file(lab_name), st)


def discovered(lab_name: str) -> dict:
    """{"facts", "staff", "found", "missing", ...} from the last discovery, or {}."""
    d = _read(found_file(lab_name))
    return d if isinstance(d.get("facts"), dict) else {}


def discovered_facts(lab_name: str) -> dict | None:
    """The facts dict workday.lab_facts uses, when Start-OfficeLoad found them."""
    d = discovered(lab_name)
    return dict(d["facts"]) if d else None


def discovered_staff(lab_name: str) -> list[dict] | None:
    """The staff discovery found (the people of the group or OU), or None."""
    d = discovered(lab_name)
    return list(d.get("staff") or []) if d else None


def forget(lab_name: str) -> str:
    """Back to the lab plan's facts and directory."""
    found_file(lab_name).unlink(missing_ok=True)
    with _lock:
        st = load(lab_name)
        st.update({"origin": "", "by": "", "started": 0.0, "seen": [], "discovered_at": 0.0,
                   "status": {"state": "stopped", "message": "winlab forgot what it discovered"}})
        save(lab_name, st)
    return "winlab forgot the discovered network: the load engine uses the lab plan's facts again"


# =============================================================== the request
def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _name_ok(value: str) -> str:
    """A group or OU name from the guest: plain text, no control characters."""
    v = str(value or "").strip()
    if len(v) > 128 or any(ord(c) < 32 for c in v):
        raise FreeloadError("the group or OU name is too long or holds control characters")
    return v


def parse_request(text: str) -> dict:
    """What Start-OfficeLoad or Stop-OfficeLoad left in the guest, checked.
    The guest is the student's machine: every field is validated, and the
    secret (base64 of what was typed) is kept apart under "secret"."""
    try:
        raw = json.loads(text.lstrip("\ufeff"))
    except ValueError as exc:
        raise FreeloadError(f"the request is not JSON: {exc}") from None
    if not isinstance(raw, dict):
        raise FreeloadError("the request is not a JSON object")
    action = str(raw.get("action", "")).lower()
    if action not in ACTIONS:
        raise FreeloadError(f"the request's action is one of {', '.join(ACTIONS)}")
    level = str(raw.get("level") or "normal").lower()
    profile = str(raw.get("profile") or "office").lower()
    pace = str(raw.get("pace") or "normal").lower()
    if level not in LEVELS or profile not in PROFILES or pace not in PACES:
        raise FreeloadError("the level, profile or pace is not one Start-OfficeLoad knows")
    secret = ""
    if raw.get("signin"):
        try:
            secret = base64.b64decode(str(raw["signin"]), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            raise FreeloadError("the staff password in the request could not be read") from None
    return {"action": action, "id": re.sub(r"[^A-Za-z0-9-]", "", str(raw.get("id", "")))[:40],
            "level": level, "profile": profile, "pace": pace,
            "group": _name_ok(raw.get("group", "")), "ou": _name_ok(raw.get("ou", "")),
            "shifts": bool(raw.get("shifts")), "server_jobs": raw.get("server_jobs", True) is not False,
            "rediscover": bool(raw.get("rediscover")),
            "computer": re.sub(r"[^A-Za-z0-9_.-]", "", str(raw.get("computer", "")))[:63],
            "user": re.sub(r"[^\w .@\\-]", "", str(raw.get("user", "")))[:100], "secret": secret}


def poll_command(status: dict) -> str:
    """The look into one guest: when the load folder is there (the module
    made it), write winlab's status, then hand back any request and delete
    it. Nothing is created on a machine that never ran the module."""
    from .workday import ps_quote
    blob = _b64(json.dumps(status))
    d = ps_quote(GUEST_DIR)
    return "\n".join([
        "$ErrorActionPreference = 'SilentlyContinue'",
        f"$d = {d}",
        "if (Test-Path -LiteralPath $d) {",
        f"  '{HOST_MARK} ' + $env:COMPUTERNAME",
        f"  $s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}'))",
        "  [IO.File]::WriteAllText((Join-Path $d 'status.json'), $s)",
        "  $r = Join-Path $d 'request.json'",
        "  if (Test-Path -LiteralPath $r) {",
        "    $t = [IO.File]::ReadAllText($r)",
        "    Remove-Item -LiteralPath $r -Force",
        f"    '{REQ_MARK} ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t)) }}",
        "}"])


def parse_poll(ok: bool, out: str) -> tuple[str, str | None]:
    """(the guest's computer name, the request's text or None)."""
    host, req = "", None
    if not ok:
        return host, req
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith(HOST_MARK):
            host = line[len(HOST_MARK):].strip()
        elif line.startswith(REQ_MARK):
            try:
                req = base64.b64decode(line[len(REQ_MARK):].strip()).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                req = None
    return host, req


# ============================================================ the discovery
_Q = ("function Q($base, $filter, $props) {",
      "  $s = New-Object DirectoryServices.DirectorySearcher",
      "  $s.SearchRoot = New-Object DirectoryServices.DirectoryEntry ('LDAP://' + $base)",
      "  $s.Filter = $filter; $s.PageSize = 500",
      "  foreach ($p in $props) { $null = $s.PropertiesToLoad.Add($p) }",
      "  try { @($s.FindAll()) } catch { $script:o.errors += ('ldap ' + $_.Exception.Message); @() } }",
      "function V($r, $n) { $v = $r.Properties[$n]; if ($v -and $v.Count) { [string]$v[0] } else { '' } }",
      "function Esc($t) { $t -replace '\\\\', '\\5c' -replace '\\(', '\\28' -replace '\\)', '\\29' -replace '\\*', '\\2a' }")

ENABLED = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
STAFF_PROPS = ("sAMAccountName", "givenName", "sn", "displayName", "department", "title", "mail",
               "telephoneNumber", "homeDirectory")


def discover_command(group: str = "", ou: str = "") -> str:
    """Read-only discovery from the machine the request came from, as its
    agent (the machine's own account in the domain). One JSON object between
    markers. Windows PowerShell 5.1, no return or exit at top level."""
    from .workday import ldap_escape, ps_quote
    staff_props = "@(" + ", ".join(ps_quote(p) for p in STAFF_PROPS) + ")"
    return "\n".join([
        "$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'",
        "$o = @{ computer = $env:COMPUTERNAME; domain = ''; netbios = ''; dcs = @(); pdc = ''; nltest = ''; srv = @(); "
        "errors = @(); computers = @(); staff = @(); staff_from = ''; printers = @(); mx = @(); names = @(); "
        "sqlspn = @(); wsus = '' }",
        "$script:o = $o",
        *_Q,
        f"$group = {ps_quote(ldap_escape(group))}; $ou = {ps_quote(ldap_escape(ou))}",
        "try { $dom = [DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain(); $o.domain = $dom.Name.ToLower() }",
        "catch { $o.errors += ('domain ' + $_.Exception.Message) }",
        "if ($o.domain) {",
        "  try { $o.dcs = @($dom.DomainControllers | ForEach-Object { $_.Name.ToLower() }) } catch { $o.errors += ('dcs ' + $_.Exception.Message) }",
        "  try { $o.pdc = $dom.PdcRoleOwner.Name.ToLower() } catch { }",
        "  $nl = & { $ErrorActionPreference = 'Continue'; nltest.exe ('/dsgetdc:' + $o.domain) 2>$null }",
        "  foreach ($l in @($nl)) { if ($l -match '^\\s*DC: \\\\\\\\(\\S+)') { $o.nltest = $matches[1].ToLower() } }",
        "  try { $o.srv = @(Resolve-DnsName -Type SRV -Name ('_ldap._tcp.dc._msdcs.' + $o.domain) -ErrorAction Stop | "
        "Where-Object { $_.Type -eq 'SRV' } | ForEach-Object { $_.NameTarget.ToLower() }) } catch { $o.errors += ('srv ' + $_.Exception.Message) }",
        "  $dn = 'DC=' + ($o.domain -replace '\\.', ',DC=')",
        "  foreach ($r in (Q ('CN=Partitions,CN=Configuration,' + $dn) ('(&(objectClass=crossRef)(nCName=' + $dn + '))') @('nETBIOSName'))) "
        "{ $o.netbios = V $r 'netbiosname' }",
        "  $o.computers = @(Q $dn '(objectCategory=computer)' @('name', 'dNSHostName', 'operatingSystem', 'userAccountControl') | "
        "Select-Object -First 80 | ForEach-Object { $h = (V $_ 'dnshostname').ToLower(); $ips = @()",
        "    if ($h) { try { $ips = @(Resolve-DnsName -Type A -Name $h -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) } catch { } }",
        "    @{ name = (V $_ 'name').ToLower(); dns = $h; os = (V $_ 'operatingsystem'); uac = [int](V $_ 'useraccountcontrol'); ips = $ips } })",
        "  $base = $dn",
        f"  $filter = '(&(objectCategory=person)(objectClass=user){ENABLED}(!(isCriticalSystemObject=TRUE))(!(adminCount=1)))'",
        "  if ($group) { $g = @(Q $dn ('(&(objectCategory=group)(|(sAMAccountName=' + $group + ')(cn=' + $group + ')))') @('distinguishedName'))",
        "    if ($g.Count) { $gdn = V $g[0] 'distinguishedname'; $o.staff_from = 'group ' + $gdn",
        f"      $filter = '(&(objectCategory=person)(objectClass=user){ENABLED}(memberOf:1.2.840.113556.1.4.1941:=' + (Esc $gdn) + '))' }}",
        "    else { $o.errors += ('nogroup ' + $group); $filter = '' } }",
        "  elseif ($ou) { $u = @(Q $dn ('(&(objectCategory=organizationalUnit)(|(ou=' + $ou + ')(distinguishedName=' + $ou + ')))') @('distinguishedName'))",
        "    if ($u.Count) { $base = V $u[0] 'distinguishedname'; $o.staff_from = 'OU ' + $base",
        f"      $filter = '(&(objectCategory=person)(objectClass=user){ENABLED}(!(adminCount=1)))' }}",
        "    else { $o.errors += ('noou ' + $ou); $filter = '' } }",
        "  else { $o.staff_from = 'every enabled user' }",
        f"  if ($filter) {{ $o.staff = @(Q $base $filter {staff_props} | Select-Object -First 80 | ForEach-Object {{",
        "    @{ account = (V $_ 'samaccountname'); first = (V $_ 'givenname'); last = (V $_ 'sn'); name = (V $_ 'displayname'); "
        "department = (V $_ 'department'); title = (V $_ 'title'); mail = (V $_ 'mail'); phone = (V $_ 'telephonenumber'); "
        "home = (V $_ 'homedirectory') } }) }",
        "  $o.printers = @(Q $dn '(objectCategory=printQueue)' @('printerName', 'serverName', 'shortServerName', 'uNCName') | "
        "ForEach-Object { @{ name = (V $_ 'printername'); server = (V $_ 'servername').ToLower(); unc = (V $_ 'uncname') } })",
        "  foreach ($r in (Q $dn '(servicePrincipalName=MSSQLSvc*)' @('servicePrincipalName'))) "
        "{ foreach ($s in @($r.Properties['serviceprincipalname'])) { if ($s -like 'MSSQLSvc/*') { $o.sqlspn += ([string]$s).ToLower() } } }",
        "  try { $o.mx = @(Resolve-DnsName -Type MX -Name $o.domain -ErrorAction Stop | Where-Object { $_.Type -eq 'MX' } | "
        "ForEach-Object { $_.NameExchange.ToLower() }) } catch { }",
        "  foreach ($n in @(" + ", ".join(ps_quote(n) for n in WEB_NAMES) + ")) {",
        "    try { $a = @(Resolve-DnsName -Name ($n + '.' + $o.domain) -ErrorAction Stop)",
        "      $o.names += @{ name = $n; cname = @($a | Where-Object { $_.Type -eq 'CNAME' } | ForEach-Object { $_.NameHost.ToLower() }); "
        "ips = @($a | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) } } catch { } }",
        "  $wu = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -ErrorAction SilentlyContinue",
        "  if ($wu -and $wu.WUServer) { $o.wsus = [string]$wu.WUServer }",
        "}",
        f"'{BEGIN}'",
        "$o | ConvertTo-Json -Depth 6 -Compress",
        f"'{END}'"])


def inventory_command() -> str:
    """What one Windows machine is, read-only, as its agent sees it: name,
    domain, workstation/DC/server, addresses, shares, shared printers, web
    bindings, SQL Server instances, session host, WSUS, a mail service."""
    return "\n".join([
        "$ErrorActionPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'",
        "$o = @{ computer = $env:COMPUTERNAME; domain = ''; member = $false; type = 0; ips = @(); shares = @(); "
        "printers = @(); web = @(); sql = @(); rds = $false; wsus = $false; smtp = $false }",
        "$cs = Get-WmiObject Win32_ComputerSystem",
        "if ($cs) { $o.domain = ([string]$cs.Domain).ToLower(); $o.member = [bool]$cs.PartOfDomain }",
        "$os = Get-WmiObject Win32_OperatingSystem; if ($os) { $o.type = [int]$os.ProductType }",
        "$o.ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | "
        "ForEach-Object { $_.IPAddress })",
        "$o.shares = @(Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { $_.Name })",
        "$o.printers = @(Get-Printer | Where-Object { $_.Shared } | ForEach-Object { $_.ShareName })",
        "if (Get-Service W3SVC | Where-Object { $_.Status -eq 'Running' }) {",
        "  if (Import-Module WebAdministration -PassThru) { $o.web = @(Get-WebBinding | ForEach-Object { $_.protocol + ' ' + $_.bindingInformation }) }",
        "  if (-not $o.web.Count) { $o.web = @('http *:80:') } }",
        "$o.sql = @(Get-Service -Name 'MSSQLSERVER', 'MSSQL$*' | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })",
        "if ($o.type -gt 1 -and (Get-Command Get-WindowsFeature)) { $f = Get-WindowsFeature RDS-RD-Server; $o.rds = [bool]($f -and $f.Installed) }",
        "$o.wsus = [bool](Get-Service WsusService | Where-Object { $_.Status -eq 'Running' })",
        "$o.smtp = [bool](Get-Service SMTPSVC, MSExchangeTransport, hMailServer | Where-Object { $_.Status -eq 'Running' })",
        f"'{BEGIN}'",
        "$o | ConvertTo-Json -Depth 4 -Compress",
        f"'{END}'"])


def parse_marked(ok: bool, out: str) -> dict | None:
    """The JSON object between the markers, or None."""
    text = out or ""
    if BEGIN not in text or END not in text:
        return None
    body = text.split(BEGIN, 1)[1].split(END, 1)[0].strip()
    try:
        raw = json.loads(body)
    except ValueError:
        return None
    return raw if isinstance(raw, dict) else None


def _list(v) -> list:
    """ConvertTo-Json in 5.1 writes a one-item array as the item and an empty one as null."""
    if v is None or v == "":
        return []
    return v if isinstance(v, list) else [v]


def _short(name: str) -> str:
    return str(name or "").strip().rstrip(".").split(".")[0].lower()


# ================================================================ the facts
def host_map(lab, invs: dict[str, dict]) -> dict[str, str]:
    """Computer name (short, lower case) -> lab machine. The name a machine
    gave itself inside Windows wins over the lab plan's (the student may
    have renamed it)."""
    from . import naming
    out: dict[str, str] = {}
    for n in lab.node_list():
        out.setdefault(n.id.lower(), n.id)
        out[naming.hostname_of(n).lower()] = n.id
    for node, inv in invs.items():
        if inv.get("computer"):
            out[_short(inv["computer"])] = node
    return out


def visible_shares(inv: dict) -> list[str]:
    return [s for s in (str(x) for x in _list(inv.get("shares"))) if s.upper() not in SYSTEM_SHARES
            and not s.endswith("$")]


def company_share(shares: list[str]) -> str:
    low = {s.lower(): s for s in shares}
    return next((low[c] for c in COMPANY_FIRST if c in low), shares[0] if shares else "")


def build_facts(lab, disc: dict, invs: dict[str, dict]) -> dict:
    """The facts dict workday and traffic use, from what discovery saw.
    Pure on its arguments: `disc` is the origin machine's discovery, `invs`
    each running Windows machine's inventory by lab machine id."""
    from .model import WINDOWS_CLIENT
    domain = str(disc.get("domain") or "").lower()
    hosts = host_map(lab, invs)

    def node_of(name: str) -> str:
        return hosts.get(_short(name), "")

    members = {n: inv for n, inv in invs.items()
               if inv.get("member") and str(inv.get("domain", "")).lower() == domain and n in lab.nodes}
    order = [n.id for n in lab.node_list()]
    ranked = sorted(members, key=order.index)

    def host(node: str) -> str:
        inv = members.get(node) or invs.get(node) or {}
        if inv.get("computer"):
            return str(inv["computer"]).lower()
        from . import naming
        return naming.hostname_of(lab.nodes[node]).lower() if node in lab.nodes else ""

    def fqdn(node: str) -> str:
        return f"{host(node)}.{domain}" if node and domain else host(node)

    def kind(node: str) -> int:
        return int(members.get(node, {}).get("type") or 0)

    def servers_first(nodes: list[str]) -> list[str]:
        nodes = [n for n in nodes if kind(n) != WORKSTATION]
        return sorted(nodes, key=lambda n: (0 if kind(n) == SERVER else 1, order.index(n)))

    # The domain controllers: what the domain says, then what says it is one.
    dc_names = [_short(x) for x in [disc.get("pdc"), disc.get("nltest"), *_list(disc.get("dcs")), *_list(disc.get("srv"))] if x]
    dc_nodes = list(dict.fromkeys([node_of(x) for x in dc_names if node_of(x) in members]
                                  + [n for n in ranked if kind(n) == DOMAIN_CONTROLLER]))
    dc_node = dc_nodes[0] if dc_nodes else ""
    dc = host(dc_node) if dc_node else (dc_names[0] if dc_names else "")
    # File servers: a share of the student's own, not only the system's.
    file_nodes = servers_first([n for n in ranked if visible_shares(members[n])])
    files_node = file_nodes[0] if file_nodes else ""
    shares = visible_shares(members[files_node]) if files_node else []
    # Printing: a machine sharing a printer, or the server a published printer names.
    print_nodes = servers_first([n for n in ranked if _list(members[n].get("printers"))])
    if not print_nodes:
        print_nodes = servers_first([node_of(p.get("server", "")) for p in _list(disc.get("printers"))
                                     if isinstance(p, dict) and node_of(p.get("server", "")) in members])
    ps_node = print_nodes[0] if print_nodes else ""
    # Mail: the domain's MX record, else a machine called mail.
    mail, mail_node = "", ""
    names = {str(x.get("name")): x for x in _list(disc.get("names")) if isinstance(x, dict)}
    for mx in _list(disc.get("mx")):
        mail, mail_node = str(mx).lower().rstrip("."), node_of(str(mx))
        break
    if not mail and "mail" in names:
        mail = f"mail.{domain}"
        mail_node = _named_node(names["mail"], node_of, members)
    if not mail:
        smtp = servers_first([n for n in ranked if members[n].get("smtp")])
        if smtp:
            mail, mail_node = fqdn(smtp[0]), smtp[0]
    # Web: the intranet's own DNS name when the student made one, else the first web server.
    web_nodes = servers_first([n for n in ranked if _list(members[n].get("web"))])
    intranet, intranet_node = "", ""
    for nm in ("intranet", "www", "portal"):
        if nm in names:
            node = _named_node(names[nm], node_of, members)
            if node:
                intranet, intranet_node = f"{nm}.{domain}", node
                break
    if not intranet_node and web_nodes:
        intranet, intranet_node = fqdn(web_nodes[0]), web_nodes[0]
    sites = [{"node": n, "url": f"http://{fqdn(n)}/"} for n in web_nodes if n != intranet_node]
    # SQL Server: a running instance, else a host its service names point at.
    sql_nodes = servers_first([n for n in ranked if _list(members[n].get("sql"))])
    if not sql_nodes:
        spn_hosts = [node_of(s.split("/", 1)[1].split(":")[0]) for s in _list(disc.get("sqlspn")) if "/" in str(s)]
        sql_nodes = [n for n in dict.fromkeys(spn_hosts) if n in members]
    sql_node = sql_nodes[0] if sql_nodes else ""
    rds_nodes = servers_first([n for n in ranked if members[n].get("rds")])
    rds_node = rds_nodes[0] if rds_nodes else ""
    # WSUS: the server Group Policy points the machines at, else one running it.
    wsus_node = ""
    m = re.match(r"^\w+://([^/:]+)", str(disc.get("wsus") or ""))
    if m and node_of(m.group(1)) in members:
        wsus_node = node_of(m.group(1))
    if not wsus_node:
        w = servers_first([n for n in ranked if members[n].get("wsus")])
        wsus_node = w[0] if w else ""
    pcs = [n for n in ranked if kind(n) == WORKSTATION]
    home_nets = {c.network for n in lab.node_list() if "home-router" in n.roles for c in n.nics if c.network}
    netbios = str(disc.get("netbios") or (domain.split(".")[0] if domain else "")).upper()
    return {
        "source": "discovered",
        "domain": domain, "netbios": netbios,
        "dc": dc, "dc_node": dc_node, "dc_addr": f"{dc}.{domain}" if dc and domain else dc,
        "files": host(files_node) if files_node else "", "files_node": files_node,
        "company": company_share(shares) or "Company", "shares": shares,
        "printserver": host(ps_node) if ps_node else "", "printserver_node": ps_node,
        "printer": "", "printer_node": "",
        "mail": mail, "mail_node": mail_node,
        "intranet": intranet, "intranet_node": intranet_node,
        "pcs": pcs,
        "dc_nodes": dc_nodes, "file_nodes": file_nodes,
        "sql": fqdn(sql_node) if sql_node else "", "sql_node": sql_node,
        "rds": fqdn(rds_node) if rds_node else "", "rds_node": rds_node,
        "wsus": host(wsus_node) if wsus_node else "", "wsus_node": wsus_node,
        "sites": sites,
        "remote_pcs": [n for n in pcs if lab.nodes[n].kind == WINDOWS_CLIENT
                       and any(c.network in home_nets for c in lab.nodes[n].nics)],
        "windows": ranked,
        "hosts": {n: host(n) for n in ranked},   # each machine's name inside Windows
        "unmatched": sorted({_short(c.get("name", "")) for c in _list(disc.get("computers"))
                             if isinstance(c, dict) and c.get("name") and not node_of(c["name"])}),
    }


def _named_node(entry: dict, node_of, members: dict) -> str:
    """The machine a DNS name (intranet.corp.lab) lands on: its CNAME's
    target, or the machine with its address."""
    for c in _list(entry.get("cname")):
        if node_of(str(c)) in members:
            return node_of(str(c))
    ips = {str(i) for i in _list(entry.get("ips"))}
    for n, inv in members.items():
        if ips & {str(i) for i in _list(inv.get("ips"))}:
            return n
    return ""


def build_staff(disc: dict, facts: dict, exclude: str = "") -> list[dict]:
    """The people discovery found, as the staff directory's entries. The
    person who typed the command is the admin, not staff. Someone without a
    department works in the company share."""
    out: list[dict] = []
    seen: set[str] = set()
    ex = exclude.split("\\")[-1].lower()
    for i, s in enumerate(x for x in _list(disc.get("staff")) if isinstance(x, dict)):
        account = str(s.get("account") or "").strip()
        if not account or account.endswith("$") or account.lower() in seen or account.lower() == ex:
            continue
        seen.add(account.lower())
        first, last = str(s.get("first") or "").strip(), str(s.get("last") or "").strip()
        name = str(s.get("name") or "").strip() or f"{first} {last}".strip() or account
        if not first:
            first = name.split()[0] if name.split() else account
        if not last:
            last = name.split()[-1] if len(name.split()) > 1 else ""
        digits = re.sub(r"\D", "", str(s.get("phone") or ""))[-4:]
        out.append({"id": account.lower(), "first": first, "last": last, "name": name,
                    "department": str(s.get("department") or "").strip() or facts.get("company") or "Staff",
                    "title": str(s.get("title") or "").strip() or "Staff",
                    "account": account, "mail": str(s.get("mail") or "").strip() or f"{account.lower()}@{facts.get('domain', '')}",
                    "ext": int(digits) if digits else 300 + i, "pc": "", "manager": False, "admin": False,
                    "source": "discovered"})
        if len(out) >= MAX_STAFF:
            break
    return out


def problem(facts: dict, staff: list[dict], disc: dict, origin_name: str) -> str:
    """Why nothing can start, in words for the student, or ""."""
    errs = " ".join(str(e) for e in _list(disc.get("errors")))
    if disc.get("silent"):
        return f"Nothing to load: {origin_name} did not answer winlab's look around. Try again in a minute."
    if not disc.get("domain"):
        return f"Nothing to load: {origin_name} is not in a domain. Join it to the domain you built and try again."
    if not facts["dc"]:
        return "Nothing to load: no domain controller answered for " + facts["domain"] + "."
    if not facts["dc_node"]:
        return f"Nothing to load: the domain controller {facts['dc'].upper()} is not a running machine of this lab."
    if "nogroup" in errs:
        return "Nothing to load: there is no group of that name in " + facts["domain"] + "."
    if "noou" in errs:
        return "Nothing to load: there is no OU of that name in " + facts["domain"] + "."
    if not staff:
        return ("Nothing to load: no staff found (no enabled ordinary user accounts"
                + (f" in {disc.get('staff_from')}" if disc.get("staff_from") else "") + ").")
    if not facts["pcs"]:
        return "Nothing to load: no running Windows PC is joined to " + facts["domain"] + " for the staff to work at."
    return ""


def found_lines(lab, facts: dict, staff: list[dict], disc: dict) -> tuple[list[str], list[str]]:
    """What was found and what was not, as short lines for the guest, the
    Office window and the command line."""
    from . import naming

    def at(name: str, node: str) -> str:
        return name.upper() + (f" ({node})" if node and node.lower() != name.lower() else "")

    def nm(node: str) -> str:
        return at(facts.get("hosts", {}).get(node) or naming.display(lab, node), node) if node else ""

    found, missing = [], []
    found.append(f"domain {facts['domain']} ({facts['netbios']}), domain controller "
                 + ", ".join(at(_dc_name(facts, n, lab), n) for n in facts["dc_nodes"] or [facts["dc_node"]]))
    for key, label in (("files_node", "file server"), ("printserver_node", "print server"), ("mail_node", "mail"),
                       ("intranet_node", "intranet"), ("sql_node", "SQL Server"), ("rds_node", "Remote Desktop session host"),
                       ("wsus_node", "WSUS")):
        node = facts.get(key, "")
        if key == "mail_node" and facts.get("mail") and not node:
            found.append(f"mail: {facts['mail']} (not a machine of this lab: nobody mails)")
            continue
        if not node:
            missing.append(label)
            continue
        if key == "files_node":
            found.append(f"file server {nm(node)}: shares {', '.join(facts['shares'])}")
        elif key == "mail_node":
            found.append(f"mail: {facts['mail']} on {nm(node)}")
        elif key == "intranet_node":
            found.append(f"intranet: http://{facts['intranet']}/ on {nm(node)}"
                         + (f", {len(facts['sites'])} more web site(s)" if facts["sites"] else ""))
        else:
            found.append(f"{label}: {nm(node)}")
    found.append(f"PCs: {', '.join(nm(n) for n in facts['pcs']) or 'none'}")
    found.append(f"staff: {len(staff)} from {disc.get('staff_from') or 'the directory'}")
    if facts.get("unmatched"):
        found.append("in the directory but not a machine of this lab: " + ", ".join(x.upper() for x in facts["unmatched"][:8]))
    return found, missing


def _dc_name(facts: dict, node: str, lab) -> str:
    from . import naming
    if node and node == facts["dc_node"]:
        return facts["dc"]
    return naming.display(lab, node) if node else facts["dc"]


def discover(lab, origin: str, req: dict, runner: Runner, running: set[str]) -> dict:
    """Looks around from `origin`, then at each running Windows machine.
    Returns {"facts", "staff", "found", "missing", "problem", "disc", "seen"}."""
    ok, out = runner(origin, discover_command(req.get("group", ""), req.get("ou", "")), "powershell")
    disc = parse_marked(ok, out) or {"errors": [f"no answer from {origin}: {(out or '').strip()[:200]}"], "silent": True}
    invs: dict[str, dict] = {}
    for n in lab.node_list():
        if not n.is_windows or n.id not in running:
            continue
        try:
            ok, out = runner(n.id, inventory_command(), "powershell")
        except Exception:  # noqa: BLE001 - one silent machine must not stop the look around
            continue
        inv = parse_marked(ok, out)
        if inv:
            invs[n.id] = inv
    facts = build_facts(lab, disc, invs)
    staff = build_staff(disc, facts, req.get("user", ""))
    found, missing = found_lines(lab, facts, staff, disc) if disc.get("domain") else ([], [])
    origin_name = str((invs.get(origin) or {}).get("computer") or origin).upper()
    return {"facts": facts, "staff": staff, "found": found, "missing": missing,
            "problem": problem(facts, staff, disc, origin_name), "disc": disc,
            "seen": sorted(invs), "origin_name": origin_name}


# ============================================================== the engine
def _lab_now(lab_name: str) -> float:
    from . import labclock
    return labclock.load(lab_name).now()


def _stamp(ts: float) -> str:
    return time.strftime("%a %d %b %H:%M", time.localtime(ts)) if ts else ""


def status_for(lab, st: dict | None = None) -> dict:
    """What Get-OfficeLoad shows: every key always there."""
    from . import helpdesk, workday
    st = st or load(lab.name)
    s = dict(st.get("status") or {})
    wd = workday.load(lab.name)
    found = discovered(lab.name)
    try:
        tickets = len([t for t in helpdesk.open_tickets(lab.name) if t.get("source") == "workday"])
    except Exception:  # noqa: BLE001
        tickets = 0
    running = bool(wd.get("on")) and bool(found)
    state = s.get("state") or ("running" if running else "stopped")
    if state == "running" and not wd.get("on"):
        state = "stopped"
    return {"ack": s.get("ack", ""), "state": state,
            "message": s.get("message") or ("The office is at work." if state == "running" else "The load engine is off."),
            "from": st.get("origin_name", "") or st.get("origin", ""), "by": st.get("by", ""),
            "started": _stamp(st.get("started", 0.0)),
            "level": wd.get("level", "normal"), "profile": (st.get("settings") or {}).get("profile", "office"),
            "staff": len(found.get("staff") or []),
            "in_now": sum(1 for r in (wd.get("people") or {}).values() if r.get("where") == "in" and r.get("day")),
            "tickets": tickets, "found": list(found.get("found") or []), "missing": list(found.get("missing") or []),
            "updated": _stamp(_lab_now(lab.name))}


def _set_status(lab_name: str, **kw) -> dict:
    with _lock:
        st = load(lab_name)
        st["status"] = {**{"ack": "", "state": "", "message": ""}, **kw}
        save(lab_name, st)
    return st


def start_engine(lab, req: dict, result: dict, origin: str) -> str:
    """The engine on with what was found: workday, traffic profile, busy
    day, the servers' own work. Nothing in the lab is touched."""
    from . import traffic, workday
    _write(found_file(lab.name), {"facts": result["facts"], "staff": result["staff"], "found": result["found"],
                                  "missing": result["missing"], "origin": origin, "at": time.time()})
    # The first password the student typed, for each person who has none yet.
    if req.get("secret"):
        have = workday.load_secrets(lab.name)
        for p in result["staff"]:
            if p["account"].lower() not in have:
                workday.set_secret(lab.name, p["account"], req["secret"])
    with workday._lock:
        wd = workday.load(lab.name)
        wd["on"], wd["level"], wd["shifts"] = True, req.get("level", "normal"), bool(req.get("shifts"))
        wd["sheet"] = wd.get("sheet") or "free play"   # the staff exist already: no HR sheet
        workday.save(lab.name, wd)
    traffic.set_profile(lab.name, req.get("profile", "office"))
    traffic.set_busy(lab.name, req.get("pace") == "busyday", "busy day (Start-OfficeLoad)")
    traffic.set_background(lab.name, bool(req.get("server_jobs", True)))
    return f"The office is at work: {len(result['staff'])} staff, load {req.get('level', 'normal')}."


def handle(lab, node: str, req: dict, runner: Runner, running: set[str], now: float | None = None) -> dict:
    """One request from `node`: discover and start, or stop. Writes the
    answer back into the guest. Returns the status written."""
    from . import workday
    now = _lab_now(lab.name) if now is None else now
    if req["action"] == "stop":
        workday.stop(lab)
        with _lock:
            st = load(lab.name)
            st["status"] = {"ack": req["id"], "state": "stopped",
                            "message": "The staff went home: the load engine is off until Start-OfficeLoad runs again."}
            save(lab.name, st)
        status = status_for(lab, st)
        runner(node, poll_command(status), "powershell")
        return status
    with _lock:
        st = load(lab.name)
        st.update({"origin": node, "by": req.get("user", ""), "started": now,
                   "settings": {k: req.get(k) for k in ("level", "profile", "pace", "group", "ou", "shifts", "server_jobs")}})
        st["status"] = {"ack": req["id"], "state": "discovering", "message": "winlab is looking around your network..."}
        save(lab.name, st)
    runner(node, poll_command(status_for(lab, st)), "powershell")
    result = discover(lab, node, req, runner, running)
    with _lock:
        st = load(lab.name)
        st["origin_name"] = result["origin_name"]
        st["seen"], st["discovered_at"] = result["seen"], time.time()
        if result["problem"]:
            st["status"] = {"ack": req["id"], "state": "error", "message": result["problem"]}
            save(lab.name, st)
        else:
            save(lab.name, st)
    if not result["problem"]:
        msg = start_engine(lab, req, result, node)
        st = _set_status(lab.name, ack=req["id"], state="running", message=msg)
    status = status_for(lab, st)
    if result["problem"]:
        status["found"], status["missing"] = result["found"], result["missing"]
    runner(node, poll_command(status), "powershell")
    return status


def poll(lab, runner: Runner, running: set[str]) -> list[dict]:
    """The look for requests: each running Windows machine once, its status
    refreshed; a request found is handled there and then. Also looks again
    when a Windows machine it has not seen is running."""
    from . import workday
    st = load(lab.name)
    status = status_for(lab, st)
    done: list[dict] = []
    for n in lab.node_list():
        if not n.is_windows or n.id not in running:
            continue
        try:
            host, text = parse_poll(*runner(n.id, poll_command(status), "powershell"))
        except Exception:  # noqa: BLE001 - the next poll tries again
            continue
        if text is None:
            continue
        try:
            req = parse_request(text)
        except FreeloadError as exc:
            _set_status(lab.name, ack="", state="error", message=f"winlab could not read the request: {exc}")
            runner(n.id, poll_command(status_for(lab)), "powershell")
            continue
        done.append(handle(lab, n.id, req, runner, running))
        status = status_for(lab)
    # A Windows machine the last look did not see has started: look again.
    st = load(lab.name)
    if (not done and st.get("origin") in running and workday.load(lab.name).get("on") and discovered(lab.name)
            and time.time() - float(st.get("discovered_at") or 0) > REDISCOVER_AFTER):
        new = {n.id for n in lab.node_list() if n.is_windows and n.id in running} - set(st.get("seen") or [])
        if new:
            req = {"action": "start", "id": "", "user": st.get("by", ""), "secret": "",
                   **{k: v for k, v in (st.get("settings") or {}).items()}}
            done.append(handle(lab, st["origin"], req, runner, running))
    return done


def wants_poll(lab) -> bool:
    """Only labs where the module may be: its stick was made, or the
    engine was started from inside before."""
    st = load(lab.name)
    return bool(st.get("stick") or st.get("origin"))


_offered: set[str] = set()


def offer_stick(lab) -> str:
    """The first time a free-play lab (the sandbox, a Build-window network)
    opens, the Load engine stick is put on its media shelf, plugged into
    nothing: the student decides where it goes. Once only: a stick the
    student throws away is not made again (the Load tab has a button).
    Returns the new stick's id, or ""."""
    name = lab.name
    if not getattr(lab, "sandbox", False) or name in _offered:
        return ""
    _offered.add(name)
    st = load(name)
    if st.get("stick") or st.get("origin"):
        return ""
    try:
        return to_stick(name)["id"]
    except Exception:  # noqa: BLE001 - the Load tab's button makes one by hand
        return ""


def kick(lab, runner_factory=None) -> bool:
    """The desktop's poll: a look into the guests in the background at most
    every POLL_EVERY seconds, never while the working day's tick talks to
    the same guests (both use workday's busy set). True if one started.
    A free-play lab gets its Load engine stick here the first time it opens."""
    from . import workday
    name = lab.name
    offer_stick(lab)
    if not wants_poll(lab):
        return False
    with workday._lock:
        if name in workday._running or time.time() - _last_poll.get(name, 0.0) < POLL_EVERY:
            return False
        workday._running.add(name)
        _last_poll[name] = time.time()

    def go():
        try:
            from . import oncall
            runner = runner_factory() if runner_factory else oncall.guest_runner(name)
            poll(lab, runner, set(oncall.running_nodes(lab)))
        except Exception:  # noqa: BLE001 - the next poll tries again
            pass
        finally:
            with workday._lock:
                workday._running.discard(name)
    threading.Thread(target=go, name=f"freeload-{name}", daemon=True).start()
    return True


# ================================================================ the stick
def module_files() -> dict[str, bytes]:
    d = paths.CONTENT / "officeload"
    out = {f"OfficeLoad/{f}": (d / f).read_bytes() for f in MODULE_FILES}
    out["Install.ps1"] = install_script().encode("utf-8")
    out["README.txt"] = readme().encode("utf-8")
    return out


def install_script() -> str:
    return "\r\n".join([
        "# Copies the OfficeLoad module where Windows PowerShell finds it for every user.",
        "$src = Join-Path $PSScriptRoot 'OfficeLoad'",
        "$dst = Join-Path $env:ProgramFiles 'WindowsPowerShell\\Modules\\OfficeLoad'",
        "$null = New-Item -ItemType Directory -Path $dst -Force",
        "Copy-Item -Path (Join-Path $src '*') -Destination $dst -Force",
        "Import-Module OfficeLoad -Force",
        "'OfficeLoad is installed: Start-OfficeLoad, Stop-OfficeLoad, Get-OfficeLoad'", ""])


def readme() -> str:
    return "\r\n".join([
        "Load engine: put the network you built under an office's load", "",
        "1. On a domain-joined machine of yours, open Windows PowerShell as administrator.",
        "2. Allow scripts for this window only: Set-ExecutionPolicy -Scope Process Bypass",
        "3. Install the module from this stick (E: here; use your stick's letter): E:\\Install.ps1",
        "   (or just for now: Import-Module E:\\OfficeLoad)",
        "4. Start-OfficeLoad -StaffGroup <the group your staff are in> -Level normal",
        "   It asks once for the first password you gave the staff accounts (Enter skips it).",
        "", "winlab then looks around your network (read-only: the domain, its domain controllers,",
        "the file, print, web, SQL, Remote Desktop and WSUS servers, mail, the PCs, the staff)",
        "and starts the working day on what it found. Get-OfficeLoad shows what it found and",
        "who is in; Stop-OfficeLoad sends everyone home; Start-OfficeLoad -Rediscover looks again.",
        "", "Other switches: -Profile office|flat|round, -Pace busyday, -StaffOU <OU>, -Shifts,",
        "-NoServerJobs, -NoWait. Get-Help Start-OfficeLoad -Full has the rest.",
        "", "winlab answers only while its desktop runs this lab: it looks for requests about",
        "every half minute, through the machine's own agent (nothing in the lab reaches your PC).", ""])


def to_stick(lab_name: str, node: str = "") -> dict:
    """A "Load engine" stick on the lab's media shelf; with `node`, plugged
    straight into that machine."""
    from . import media, mediashelf
    files = module_files()
    sid = mediashelf._new_id(lab_name, STICK_ID)
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise FreeloadError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": STICK_TITLE}) + "\n", encoding="utf-8")
    with _lock:
        st = load(lab_name)
        st["stick"] = sid
        save(lab_name, st)
    out = {"id": sid, "title": STICK_TITLE, "plugged": None}
    if node:
        from . import schema
        try:
            out["plugged"] = mediashelf.plug(schema.load(lab_name), node, sid)
        except mediashelf.ShelfError as exc:
            raise FreeloadError(f"the stick is on the shelf, but: {exc}") from exc
    return out


# ============================================================== the window
def view(lab) -> dict:
    """The Office window's free-play banner: who started the load, from
    where, when, and what was found."""
    st = load(lab.name)
    found = discovered(lab.name)
    s = st.get("status") or {}
    return {"sandbox": bool(getattr(lab, "sandbox", False)), "stick": st.get("stick", ""),
            "discovered": bool(found), "origin": st.get("origin", ""),
            "origin_name": st.get("origin_name", "") or st.get("origin", ""), "by": st.get("by", ""),
            "started": st.get("started", 0.0), "state": s.get("state", ""), "message": s.get("message", ""),
            "found": list(found.get("found") or []), "missing": list(found.get("missing") or []),
            "staff": len(found.get("staff") or []), "settings": st.get("settings") or {}}


def act(dash, action: str, params: dict) -> dict:
    """load-free-stick, load-free-rediscover, load-free-forget."""
    lab = dash.lab
    try:
        if action == "load-free-stick":
            r = to_stick(lab.name, str(params.get("node", "")))
            return {"ok": True, "message": f"{r['title']} is on the media shelf ({r['id']}): plug it into a machine of yours"}
        if action == "load-free-forget":
            return {"ok": True, "message": forget(lab.name)}
        if action == "load-free-rediscover":
            if not load(lab.name).get("origin"):
                raise FreeloadError("the load was never started from inside: run Start-OfficeLoad on a machine first")
            threading.Thread(target=_rediscover_bg, args=(lab,), name=f"freeload-look-{lab.name}", daemon=True).start()
            return {"ok": True, "message": "winlab is looking around your network again: the Load tab shows what it finds"}
    except FreeloadError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown action {action}"}


def _rediscover_bg(lab) -> None:
    """The window's "Look again", off the request thread, never while the
    working day's tick or a poll talks to the guests."""
    from . import workday
    for _ in range(300):
        with workday._lock:
            if lab.name not in workday._running:
                workday._running.add(lab.name)
                break
        time.sleep(1)
    else:
        return
    try:
        rediscover(lab)
    except Exception as exc:  # noqa: BLE001 - shown in the window instead
        _set_status(lab.name, ack="", state="error", message=str(exc))
    finally:
        with workday._lock:
            workday._running.discard(lab.name)


def rediscover(lab, origin: str = "", runner: Runner | None = None, running: set[str] | None = None) -> str:
    """Looks again from `origin` (default: where it was started), with the
    last settings, and starts or keeps the engine on what is found."""
    from . import oncall
    st = load(lab.name)
    origin = origin or st.get("origin", "")
    if not origin:
        raise FreeloadError("the load was never started from inside: run Start-OfficeLoad on a machine, "
                            "or name one (winlab load discover <lab> --from <machine>)")
    if origin not in lab.nodes:
        from . import naming
        origin = naming.resolve(lab, origin)
        if origin not in lab.nodes:
            raise FreeloadError(f"no machine {origin!r} in {lab.name}")
    running = set(oncall.running_nodes(lab)) if running is None else running
    if origin not in running:
        raise FreeloadError(f"{origin} is not running")
    runner = runner or oncall.guest_runner(lab.name)
    req = {"action": "start", "id": "", "user": st.get("by", ""), "secret": "", "level": "normal", "profile": "office",
           "pace": "normal", "group": "", "ou": "", "shifts": False, "server_jobs": True,
           **(st.get("settings") or {})}
    status = handle(lab, origin, req, runner, running)
    return status["message"] + ("\n  " + "\n  ".join(status["found"]) if status["found"] else "")


# ================================================================== the CLI
def render(v: dict) -> str:
    if not v["origin"]:
        lines = ["The load engine was never started from inside this lab."]
        lines.append(f"Load engine stick: {v['stick']} on the media shelf" if v["stick"]
                     else "Put the Load engine stick on the media shelf: winlab load stick")
        return "\n".join(lines)
    lines = [f"Started from {v['origin_name']} by {v['by'] or 'someone'} at {_stamp(v['started'])} (lab time): {v['message']}"]
    lines += [f"  found: {x}" for x in v["found"]]
    lines += [f"  none:  {x}" for x in v["missing"]]
    return "\n".join(lines)


def run_cli(args) -> int:
    """winlab load discover|free|stick|poll|forget [<lab>] [--from <machine>]."""
    import sys
    from . import oncall, schema
    from .cli import _resolve_lab
    try:
        lab = schema.load(_resolve_lab(args.arg or args.lab))
    except Exception as exc:  # noqa: BLE001
        print(f"{exc}", file=sys.stderr)
        return 2
    try:
        if args.what == "stick":
            r = to_stick(lab.name, args.origin)
            print(f"{r['title']} is on {lab.name}'s media shelf ({r['id']})"
                  + (f", plugged into {args.origin}" if r["plugged"] else "")
                  + ". Inside the lab: E:\\Install.ps1, then Start-OfficeLoad.")
        elif args.what == "discover":
            print(rediscover(lab, args.origin))
        elif args.what == "poll":
            with _lock:
                st = load(lab.name)
                st["stick"] = st.get("stick") or "by hand"
                save(lab.name, st)
            done = poll(lab, oncall.guest_runner(lab.name), set(oncall.running_nodes(lab)))
            print(f"{len(done)} request(s) handled" + "".join(f"\n  {d['message']}" for d in done))
        elif args.what == "forget":
            print(forget(lab.name))
        print(render(view(lab)))
        return 0
    except FreeloadError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
