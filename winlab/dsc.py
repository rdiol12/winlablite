"""Compile a node's desired state into a PowerShell DSC configuration.

A lab TOML says what a machine *is* (a forest root DC serving DHCP for these
subnets). This module turns that into DSC resources from the DSC Community
modules (see psmodules.py) plus the in-box PSDesiredStateConfiguration, and the
guest's Local Configuration Manager does the rest: test every resource, set
only what differs, reboot where a resource asks, and report drift afterwards.

Each DSC-backed role is a builder that appends resources to a NodeConfig. The
same resources back `roles apply` (set), `roles test` (drift) and, over time,
exercise grading, so there is one definition of "correct" per role.

Only Windows PowerShell 5.1 syntax is emitted: the guest agent runs
powershell.exe.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable

from . import naming, psmodules
from .model import Lab, Node
from .netplan import TopologyPlan


class DscError(Exception):
    pass


# ----------------------------------------------------------------- rendering
class Raw(str):
    """A PowerShell expression emitted verbatim ($DomainCred, $true)."""


class Block(str):
    """A script body emitted as a single-quoted here-string."""


def ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def ps_value(v) -> str:
    if isinstance(v, Raw):
        return str(v)
    if isinstance(v, Block):
        body = str(v).strip("\n")
        return "@'\n" + body + "\n'@"
    if isinstance(v, bool):
        return "$true" if v else "$false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return ps_quote(v)
    if isinstance(v, (list, tuple)):
        return "@(" + ", ".join(ps_value(x) for x in v) + ")"
    raise DscError(f"cannot render {type(v).__name__} into PowerShell")


@dataclass
class Resource:
    type: str
    name: str
    props: dict = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    module: str = ""   # "" = in-box PSDesiredStateConfiguration
    run_as: bool = False  # PsDscRunAsCredential = the lab's domain admin

    @property
    def id(self) -> str:
        return f"[{self.type}]{self.name}"

    def render(self, indent: str = "        ") -> str:
        lines = [f"{indent}{self.type} {ps_quote(self.name)}", f"{indent}{{"]
        extra = (["DependsOn"] if self.depends_on else []) + (["PsDscRunAsCredential"] if self.run_as else [])
        width = max(len(k) for k in list(self.props) + extra)
        for k, v in self.props.items():
            lines.append(f"{indent}    {k:<{width}} = {ps_value(v)}")
        if self.depends_on:
            lines.append(f"{indent}    {'DependsOn':<{width}} = {ps_value(list(self.depends_on))}")
        if self.run_as:
            lines.append(f"{indent}    {'PsDscRunAsCredential':<{width}} = $DomainCred")
        lines.append(f"{indent}}}")
        return "\n".join(lines)


def ident(s: str) -> str:
    """A DSC resource instance name: letters, digits and underscores."""
    return re.sub(r"[^A-Za-z0-9_]", "_", str(s))


def base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


_MODULE_VERSIONS = {m.name: m.version for m in psmodules.MODULES}


class NodeConfig:
    """Accumulates resources for one node, with cross-role handles so a later
    role can depend on an earlier one (DHCP authorization needs the domain)."""

    def __init__(self, node: Node, lab: Lab, facts: dict) -> None:
        self.node = node
        self.lab = lab
        self.facts = facts
        self.resources: list[Resource] = []
        self.domain_ready: str = ""   # resource id after which the domain is usable
        self.dns_client_set: str = "" # resource id after which DNS points at a DC
        # Handles later roles build on (see dscroles.py).
        self.lcm_mode = "ApplyAndMonitor"   # the dsc role switches to ApplyAndAutoCorrect
        self.ous: list[str] = []            # OU distinguished names ou-structure creates
        self.ou_ready: str = ""             # resource id after which the OU tree exists
        self.share_paths: dict[str, str] = {}   # share name -> local path (file, devices)
        self.share_ids: dict[str, str] = {}     # share name -> resource id
        self.dhcp_scopes: list[str] = []        # subnet ids this node serves
        self.notes: list[str] = []              # plan-time remarks shown by describe()

    def add(self, res: Resource) -> Resource:
        if res.module and res.module not in _MODULE_VERSIONS:
            raise DscError(f"{res.id} needs module {res.module}, not in psmodules.MODULES")
        if any(r.id == res.id for r in self.resources):
            raise DscError(f"duplicate resource {res.id} on {self.node.id}")
        self.resources.append(res)
        return res

    def has(self, rid: str) -> bool:
        return any(r.id == rid for r in self.resources)

    # ------------------------------------------------- reusable resources
    @property
    def hostname(self) -> str:
        return str(self.facts["hostname"])

    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.domain}"

    @property
    def base_dn(self) -> str:
        return base_dn(self.domain)

    @property
    def data_root(self) -> str:
        """Where bulk data lives: the first data disk, always lettered D: by
        the file role, or C: on a machine without one. Fixed at plan time so
        every role can name paths; see dscroles.ensure_data_volume."""
        return "D:" if self.node.data_disks_gb else "C:"

    @property
    def vars(self) -> dict:
        return self.facts.get("vars") or {}

    def feature(self, name: str, depends: list[str] | None = None,
                subfeatures: bool = False, ensure: str = "Present") -> str:
        """WindowsFeature, shared between roles that need the same one."""
        rid = f"[WindowsFeature]Feature_{ident(name)}"
        if not self.has(rid):
            self.add(Resource("WindowsFeature", f"Feature_{ident(name)}", {
                "Name": name, "Ensure": ensure, "IncludeAllSubFeature": subfeatures,
            }, depends_on=list(depends or [])))
        return rid

    def directory(self, path: str, depends: list[str] | None = None) -> str:
        rid = f"[File]Dir_{ident(path)}"
        if not self.has(rid):
            self.add(Resource("File", f"Dir_{ident(path)}", {
                "DestinationPath": path, "Type": "Directory", "Ensure": "Present",
            }, depends_on=list(depends or [])))
        return rid

    def text_file(self, name: str, path: str, contents: str,
                  depends: list[str] | None = None) -> str:
        res = self.add(Resource("File", name, {
            "DestinationPath": path, "Type": "File", "Contents": contents,
            "Ensure": "Present", "Force": True,
        }, depends_on=list(depends or [])))
        return res.id

    def script(self, name: str, test: str, set_: str, get: str = "",
               depends: list[str] | None = None, run_as: bool = False) -> str:
        """A Script resource with a real TestScript: the engine's escape hatch
        for what no community module covers (GPOs, w32tm, print queues)."""
        res = self.add(Resource("Script", name, {
            "GetScript": Block(get or f"@{{ Result = {ps_quote(name)} }}"),
            "TestScript": Block(test),
            "SetScript": Block(set_),
        }, depends_on=list(depends or []), run_as=run_as))
        return res.id

    def firewall(self, name: str, *, direction: str = "Inbound", action: str = "Allow",
                 protocol: str = "TCP", local_port: list[str] | None = None,
                 remote_port: list[str] | None = None, icmp_type: list[str] | None = None,
                 depends: list[str] | None = None) -> str:
        rid = f"[Firewall]FW_{ident(name)}"
        if self.has(rid):
            return rid
        props: dict = {
            "Name": name, "DisplayName": name, "Ensure": "Present", "Enabled": "True",
            "Direction": direction, "Action": action, "Protocol": protocol, "Profile": ["Any"],
        }
        if local_port:
            props["LocalPort"] = [str(p) for p in local_port]
        if remote_port:
            props["RemotePort"] = [str(p) for p in remote_port]
        if icmp_type:
            props["IcmpType"] = [str(t) for t in icmp_type]
        self.add(Resource("Firewall", f"FW_{ident(name)}", props,
                          depends_on=list(depends or []), module="NetworkingDsc"))
        return rid

    def enable_rule(self, rule_name: str, depends: list[str] | None = None) -> str:
        """Turns on an in-box firewall rule by its (non-localised) name."""
        rid = f"[Firewall]Enable_{ident(rule_name)}"
        if not self.has(rid):
            self.add(Resource("Firewall", f"Enable_{ident(rule_name)}", {
                "Name": rule_name, "Ensure": "Present", "Enabled": "True",
            }, depends_on=list(depends or []), module="NetworkingDsc"))
        return rid

    def smb_share(self, name: str, path: str, *, full: list[str] | None = None,
                  change: list[str] | None = None, abe: bool = False,
                  depends: list[str] | None = None) -> str:
        if name in self.share_ids:
            return self.share_ids[name]
        d = self.directory(path, depends)
        props: dict = {"Name": name, "Path": path, "Ensure": "Present",
                       "FullAccess": full or ["Administrators"]}
        if change:
            props["ChangeAccess"] = change
        if abe:
            props["FolderEnumerationMode"] = "AccessBased"
        res = self.add(Resource("SmbShare", f"Share_{ident(name)}", props,
                                depends_on=[d] + list(depends or []),
                                module="ComputerManagementDsc"))
        self.share_paths[name] = path
        self.share_ids[name] = res.id
        return res.id

    def modules(self) -> list[str]:
        seen: list[str] = []
        for r in self.resources:
            if r.module and r.module not in seen:
                seen.append(r.module)
        return seen

    # ------------------------------------------------------------ helpers
    @property
    def domain(self) -> str:
        return self.lab.domain

    @property
    def netbios(self) -> str:
        return self.lab.netbios

    @property
    def dc_addresses(self) -> list[str]:
        """Domain controllers other than this machine: before it is promoted
        a replica must resolve through a DC that already exists."""
        mine = {n.get("ip") for n in self.facts.get("nics") or []}
        return [d for d in self.facts.get("dns_servers") or [] if d not in mine]

    def ensure_dns_client(self) -> str:
        """Point the client resolver at a DC. Everything that talks to the
        domain before it is itself a DC depends on this. A Script resource,
        because the adapter alias differs between virtio and e1000 guests and
        NetworkingDsc wants it by name."""
        if self.dns_client_set:
            return self.dns_client_set
        dcs = self.dc_addresses
        if not dcs:
            raise DscError(f"{self.node.id}: no domain controller address in the lab")
        servers = ", ".join(ps_quote(d) for d in dcs)
        res = self.add(Resource(
            "Script", "DnsClientPointsAtDC",
            {
                "GetScript": Block(
                    "$cur = @(Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {\n"
                    "    (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses })\n"
                    "@{ Result = ($cur | Select-Object -Unique) -join ',' }"),
                "TestScript": Block(
                    f"$want = @({servers})\n"
                    "$ok = $true\n"
                    "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {\n"
                    "    $cur = @((Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses)\n"
                    "    if (($cur -join ',') -ne ($want -join ',')) { $ok = $false }\n"
                    "}\n"
                    "$ok"),
                "SetScript": Block(
                    f"$want = @({servers})\n"
                    "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {\n"
                    "    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $want\n"
                    "}"),
            }))
        self.dns_client_set = res.id
        return res.id

    def ensure_domain_ready(self) -> str:
        """A resource id after which the domain answers. On a DC that is the
        promotion itself; elsewhere a WaitForADDomain."""
        if self.domain_ready:
            return self.domain_ready
        dns = self.ensure_dns_client()
        res = self.add(Resource(
            "WaitForADDomain", "DomainUp",
            {
                "DomainName": self.domain,
                "Credential": Raw("$DomainCred"),
                "WaitTimeout": 1800,
                "RestartCount": 2,
            },
            depends_on=[dns], module="ActiveDirectoryDsc"))
        self.domain_ready = res.id
        return res.id


# ------------------------------------------------------------------ builders
# Script resources run in their own scope and cannot see $DomainCred, so they
# rebuild the lab credential from facts.json.
_LAB_CRED = (
    "$f = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json\n"
    "$cred = New-Object System.Management.Automation.PSCredential(\n"
    "    ('{0}\\Administrator' -f $f.lab.netbios),\n"
    "    (ConvertTo-SecureString -String $f.lab.admin_password -AsPlainText -Force))\n"
)

def build_ad_ds(cfg: NodeConfig) -> None:
    facts = cfg.facts
    is_root = bool((facts.get("vars") or {}).get("forest_root"))
    feat = cfg.add(Resource("WindowsFeature", "ADDS", {
        "Name": "AD-Domain-Services", "Ensure": "Present",
        "IncludeAllSubFeature": False}))
    tools = cfg.add(Resource("WindowsFeature", "ADDSTools", {
        "Name": "RSAT-AD-Tools", "Ensure": "Present", "IncludeAllSubFeature": True},
        depends_on=[feat.id]))

    # Machines carry a site key (`site = "HQ"`); the AD site is called what
    # the student named it ([names.sites]), or the key itself.
    site_key = str((facts.get("vars") or {}).get("site") or "")
    site = naming.site_name(cfg.lab, site_key) if site_key else ""
    if is_root:
        dom = cfg.add(Resource("ADDomain", "Forest", {
            "DomainName": cfg.domain,
            "DomainNetBiosName": cfg.netbios,
            "Credential": Raw("$DomainCred"),
            "SafeModeAdministratorPassword": Raw("$SafeModeCred"),
            "ForestMode": "WinThreshold",
            "DomainMode": "WinThreshold",
        }, depends_on=[tools.id], module="ActiveDirectoryDsc"))
        up = cfg.add(Resource("WaitForADDomain", "ForestUp", {
            "DomainName": cfg.domain,
            "Credential": Raw("$DomainCred"),
            "WaitTimeout": 1800,
            "RestartCount": 2,
        }, depends_on=[dom.id], module="ActiveDirectoryDsc"))
        cfg.domain_ready = up.id
        cfg.dns_client_set = up.id  # a DC resolves through itself

        # Sites: the root renames Default-First-Site-Name to its own site and
        # creates the others, so a replica can promote straight into its site.
        # Subnets and site links are left for the sites-and-services exercise.
        sites = [naming.site_name(cfg.lab, k) for k in naming.site_keys(cfg.lab)]
        if site and site in sites:
            sites.remove(site)
            sites.insert(0, site)
        for s in sites:
            cfg.add(Resource("ADReplicationSite", f"Site_{ident(s)}", {
                "Name": s, "Ensure": "Present",
                "RenameDefaultFirstSiteName": s == site,
            }, depends_on=[up.id], module="ActiveDirectoryDsc"))
    else:
        up = cfg.ensure_domain_ready()
        deps = [tools.id, up]
        if site:
            # Install-ADDSDomainController refuses a site that does not exist.
            wait_site = cfg.add(Resource("Script", f"WaitForSite_{ident(site)}", {
                "GetScript": Block("@{ Result = 'site check' }"),
                "TestScript": Block(
                    _LAB_CRED
                    + f"$dc = @({', '.join(ps_quote(d) for d in cfg.dc_addresses)})[0]\n"
                    "try {\n"
                    f"    [bool](Get-ADReplicationSite -Filter \"Name -eq '{site}'\" -Server $dc -Credential $cred)\n"
                    "} catch { $false }"),
                "SetScript": Block(
                    _LAB_CRED
                    + f"$dc = @({', '.join(ps_quote(d) for d in cfg.dc_addresses)})[0]\n"
                    "for ($i = 0; $i -lt 90; $i++) {\n"
                    "    try {\n"
                    f"        if (Get-ADReplicationSite -Filter \"Name -eq '{site}'\" -Server $dc -Credential $cred) {{ return }}\n"
                    "    } catch {}\n"
                    "    Start-Sleep -Seconds 20\n"
                    "}\n"
                    f"throw 'site {site} never appeared on the forest root DC'"),
            }, depends_on=deps))
            deps = [wait_site.id]
        props = {
            "DomainName": cfg.domain,
            "Credential": Raw("$DomainCred"),
            "SafeModeAdministratorPassword": Raw("$SafeModeCred"),
            "InstallDns": True,
        }
        if site:
            props["SiteName"] = site
        rep = cfg.add(Resource("ADDomainController", "Replica", props,
                               depends_on=deps, module="ActiveDirectoryDsc"))
        cfg.domain_ready = rep.id
        cfg.dns_client_set = rep.id


def build_dns(cfg: NodeConfig) -> None:
    v = cfg.facts.get("vars") or {}
    feat = cfg.add(Resource("WindowsFeature", "DNSServer", {
        "Name": "DNS", "Ensure": "Present"}))
    cfg.add(Resource("WindowsFeature", "DNSTools", {
        "Name": "RSAT-DNS-Server", "Ensure": "Present"}, depends_on=[feat.id]))
    deps = [feat.id] + ([cfg.domain_ready] if cfg.domain_ready else [])

    fwd = [str(x) for x in (v.get("dns_forwarders") or [])]
    if fwd:
        cfg.add(Resource("DnsServerForwarder", "Forwarders", {
            "IsSingleInstance": "Yes",
            "IPAddresses": fwd,
            "UseRootHint": False,
        }, depends_on=deps, module="DnsServerDsc"))
    for cf in v.get("dns_conditional") or []:
        zone, servers = cf.get("zone"), cf.get("servers")
        if zone and servers:
            cfg.add(Resource("DnsServerConditionalForwarder", f"CF_{zone}", {
                "Name": str(zone),
                "MasterServers": [str(s) for s in servers],
                "ReplicationScope": "None",
                "Ensure": "Present",
            }, depends_on=deps, module="DnsServerDsc"))
    cfg.add(Resource("DnsServerScavenging", "Scavenging", {
        "DnsServer": "localhost",
        "ScavengingState": True,
        "ScavengingInterval": "7.00:00:00",
        "RefreshInterval": "7.00:00:00",
        "NoRefreshInterval": "7.00:00:00",
    }, depends_on=deps, module="DnsServerDsc"))


def _scope_range(subnet: str, prefix: int, explicit: str = "") -> tuple[str, str]:
    net = ipaddress.ip_network(f"{subnet}/{prefix}", strict=False)
    if explicit:
        lo, _, hi = explicit.partition("-")
        lo, hi = lo.strip(), hi.strip()
        for a in (lo, hi):
            if ipaddress.ip_address(a) not in net:
                raise DscError(f"dhcp_scope {explicit} is outside {net}")
        return lo, hi
    hosts = list(net.hosts())
    if len(hosts) < 160:
        return str(hosts[len(hosts) // 4]), str(hosts[-2])
    return str(net.network_address + 50), str(net.network_address + 150)


def build_dhcp(cfg: NodeConfig) -> None:
    facts = cfg.facts
    v = facts.get("vars") or {}
    nic = (facts.get("nics") or [None])[0]
    if not nic or not nic.get("ip"):
        raise DscError(f"{cfg.node.id}: the dhcp role needs a static address")

    feat = cfg.add(Resource("WindowsFeature", "DHCPServer", {
        "Name": "DHCP", "Ensure": "Present"}))
    tools = cfg.add(Resource("WindowsFeature", "DHCPTools", {
        "Name": "RSAT-DHCP", "Ensure": "Present"}, depends_on=[feat.id]))

    own = ipaddress.ip_network(f"{nic['ip']}/{nic['prefix']}", strict=False)
    scopes = [{
        "network": nic["network"], "subnet": str(own.network_address),
        "prefix": int(nic["prefix"]), "gateway": nic["gateway"],
        "explicit": str(v.get("dhcp_scope") or ""),
    }]
    for rel in facts.get("dhcp_relayed") or []:
        scopes.append({**rel, "explicit": ""})

    dns = list(dict.fromkeys(cfg.dc_addresses + [nic["ip"]]))
    scope_ids: list[str] = []
    for s in scopes:
        net = ipaddress.ip_network(f"{s['subnet']}/{s['prefix']}", strict=False)
        lo, hi = _scope_range(s["subnet"], int(s["prefix"]), s["explicit"])
        tag = s["subnet"].replace(".", "_")
        sc = cfg.add(Resource("xDhcpServerScope", f"Scope_{tag}", {
            "ScopeId": s["subnet"],
            "Name": naming.scope_name(cfg.lab, s["network"]),
            "IPStartRange": lo,
            "IPEndRange": hi,
            "SubnetMask": str(net.netmask),
            "LeaseDuration": "08:00:00",
            "State": "Active",
            "AddressFamily": "IPv4",
            "Ensure": "Present",
        }, depends_on=[tools.id], module="DhcpServerDsc"))
        scope_ids.append(sc.id)
        cfg.dhcp_scopes.append(s["subnet"])
        for opt, val, label in ((3, [s["gateway"]], "Router"),
                                (6, dns, "DnsServers"),
                                (15, [cfg.domain], "DnsDomain")):
            cfg.add(Resource("DhcpScopeOptionValue", f"Opt{opt}_{tag}", {
                "OptionId": opt,
                "Value": val,
                "ScopeId": s["subnet"],
                "VendorClass": "",
                "UserClass": "",
                "AddressFamily": "IPv4",
                "Ensure": "Present",
            }, depends_on=[sc.id], module="DhcpServerDsc"))

    for res in v.get("dhcp_reserve") or []:
        if not (res.get("mac") and res.get("ip")):
            continue
        ip = ipaddress.ip_address(res["ip"])
        home = next((s for s in scopes if ip in ipaddress.ip_network(
            f"{s['subnet']}/{s['prefix']}", strict=False)), None)
        if home is None:
            raise DscError(f"dhcp_reserve {res['ip']} is outside every scope on {cfg.node.id}")
        cfg.add(Resource("xDhcpServerReservation", f"Reserve_{str(ip).replace('.', '_')}", {
            "ScopeId": home["subnet"],
            "IPAddress": str(ip),
            "ClientMACAddress": str(res["mac"]).replace(":", "-"),
            "Name": str(res.get("name") or ip),
            "AddressFamily": "IPv4",
            "Ensure": "Present",
        }, depends_on=[f"[xDhcpServerScope]Scope_{home['subnet'].replace('.', '_')}"],
            module="DhcpServerDsc"))

    # A DHCP server in a domain must be authorized in AD or it refuses to lease.
    cfg.add(Resource("xDhcpServerAuthorization", "Authorized", {
        "IsSingleInstance": "Yes",
        "Ensure": "Present",
        "DnsName": f"{facts['hostname']}.{cfg.domain}",
        "IPAddress": nic["ip"],
    }, depends_on=[cfg.ensure_domain_ready()] + scope_ids, module="DhcpServerDsc"))


def build_domain_join(cfg: NodeConfig) -> None:
    up = cfg.ensure_domain_ready()
    cfg.add(Resource("Computer", "JoinDomain", {
        "Name": str(cfg.facts["hostname"]),
        "DomainName": cfg.domain,
        "Credential": Raw("$DomainCred"),
    }, depends_on=[up], module="ComputerManagementDsc"))


BUILDERS: dict[str, Callable[[NodeConfig], None]] = {
    "ad-ds": build_ad_ds,
    "dns": build_dns,
    "dhcp": build_dhcp,
    "domain-join": build_domain_join,
}
# The rest of the role library lives in dscroles.py and registers itself here.
from . import dscroles as _dscroles  # noqa: E402
BUILDERS.update(_dscroles.BUILDERS)
# Remote administration between lab machines (remote-desktop, winrm, rsat).
from . import remoteadmin as _remoteadmin  # noqa: E402
BUILDERS.update(_remoteadmin.BUILDERS)
# Windows Server Backup: the feature, and the nightly backup to the NAS.
from . import wsbackup as _wsbackup  # noqa: E402
BUILDERS.update(_wsbackup.BUILDERS)
# Windows Deployment Services: golden images over PXE (wds).
from . import imaging as _imaging  # noqa: E402
BUILDERS.update(_imaging.BUILDERS)
# VM-level backup: a Hyper-V host and Veeam Backup & Replication (vmbackup).
from . import vmbackup as _vmbackup  # noqa: E402
BUILDERS.update(_vmbackup.BUILDERS)


# ----------------------------------------------------------------- compile
def compile_node(node: Node, lab: Lab, plan: TopologyPlan, roles: list[str]) -> NodeConfig:
    """Builds the resources for the DSC-backed roles, in the order given (the
    role runner passes them already topologically sorted)."""
    from .provision import node_facts

    cfg = NodeConfig(node, lab, node_facts(node, lab, plan))
    for r in roles:
        b = BUILDERS.get(r)
        if b is None:
            raise DscError(f"role '{r}' has no DSC builder")
        b(cfg)
    if node.is_windows and not ({"ad-ds", "domain-join"} & set(node.roles)):
        # The computer name the student gave it: Windows took it at install,
        # and this renames a workgroup machine they renamed since. A member
        # is renamed by its domain join, a domain controller never.
        cfg.add(Resource("Computer", "ComputerName", {
            "Name": str(cfg.facts["hostname"]),
        }, module="ComputerManagementDsc"))
    if node.is_windows and "lean" not in roles:
        # Stock Windows: undo the Low-memory profile if this machine had it.
        _dscroles.build_lean_restore(cfg)
    return cfg


MOF_DIR = r"C:\winlab\dsc\mof"
LCM_DIR = r"C:\winlab\dsc\lcm"


def render(cfg: NodeConfig) -> str:
    """The .ps1 the guest runs to compile its MOFs. It reads the lab password
    from facts.json at compile time rather than carrying it in this file."""
    imports = ["    Import-DscResource -ModuleName PSDesiredStateConfiguration"]
    for m in cfg.modules():
        imports.append(
            f"    Import-DscResource -ModuleName {m} -ModuleVersion {_MODULE_VERSIONS[m]}")
    body = "\n\n".join(r.render() for r in cfg.resources)
    return f"""# Generated by winlab (winlab/dsc.py) for node {cfg.node.id} in lab {cfg.lab.name}.
# Do not edit: 'winlab dsc render {cfg.lab.name} {cfg.node.id}' regenerates it.
# Windows PowerShell 5.1 / DSC v1.1. Compiles MOFs; apply-dsc.ps1 applies them.

$ErrorActionPreference = 'Stop'
$facts = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json
$pw = ConvertTo-SecureString -String $facts.lab.admin_password -AsPlainText -Force
$DomainCred = New-Object System.Management.Automation.PSCredential(
    ('{{0}}\\Administrator' -f $facts.lab.netbios), $pw)
$SafeModeCred = New-Object System.Management.Automation.PSCredential('Administrator', $pw)
# Seeded lab users get the lab password too; ADUser takes it as a credential.
$UserPwCred = New-Object System.Management.Automation.PSCredential('labuser', $pw)

[DSCLocalConfigurationManager()]
Configuration WinlabLcm
{{
    Node 'localhost'
    {{
        Settings
        {{
            RefreshMode                    = 'Push'
            ConfigurationMode              = '{cfg.lcm_mode}'
            ConfigurationModeFrequencyMins = 15
            RebootNodeIfNeeded             = $true
            ActionAfterReboot              = 'ContinueConfiguration'
            AllowModuleOverwrite           = $true
        }}
    }}
}}

Configuration WinlabNode
{{
    param(
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential] $DomainCred,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential] $SafeModeCred,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential] $UserPwCred
    )
{chr(10).join(imports)}

    Node 'localhost'
    {{
{body}
    }}
}}

# Plain-text credentials in the MOF: the lab password is already in facts.json
# on this disk, and the lab has no network path to anything.
$configData = @{{
    AllNodes = @(
        @{{
            NodeName                    = 'localhost'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
        }}
    )
}}

New-Item -ItemType Directory -Path '{MOF_DIR}', '{LCM_DIR}' -Force | Out-Null
WinlabLcm -OutputPath '{LCM_DIR}' | Out-Null
WinlabNode -ConfigurationData $configData -DomainCred $DomainCred `
    -SafeModeCred $SafeModeCred -UserPwCred $UserPwCred -OutputPath '{MOF_DIR}' | Out-Null
Write-Output ('compiled {{0}} resources for {cfg.node.id}' -f {len(cfg.resources)})
"""


def describe(cfg: NodeConfig) -> str:
    lines = []
    for r in cfg.resources:
        key = next((k for k in ("Name", "DomainName", "ScopeId", "OptionId", "Path", "GroupName",
                                "UserName", "DestinationPath", "LogName") if k in r.props), None)
        detail = f" {r.props[key]}" if key else ""
        lines.append(f"       {r.type} {r.name}{detail}")
    for n in cfg.notes:
        lines.append(f"       note: {n}")
    return "\n".join(lines)


def script_blocks(cfg: NodeConfig) -> dict[str, str]:
    """The PowerShell embedded in Script resources, keyed by file name, so CI
    can parse it: the MOF compiler only sees those bodies as strings."""
    out: dict[str, str] = {}
    for r in cfg.resources:
        if r.type != "Script":
            continue
        for k in ("GetScript", "TestScript", "SetScript"):
            out[f"{cfg.lab.name}-{cfg.node.id}-{ident(r.name)}-{k}.ps1"] = str(r.props[k]).strip("\n") + "\n"
    return out
