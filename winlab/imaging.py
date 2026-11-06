"""Imaging: a golden image captured from a reference PC, deployed over PXE.

What admins do with Windows Deployment Services, done inside the lab:

  1. A WDS server (role ``wds``): the WDS feature, the server initialised
     with its RemoteInstall folder, answering PXE clients, a Setup boot image
     and a capture boot image made from it, an image group for the captures,
     and a domain-join answer file ready to attach to a captured image.
  2. A reference PC built by hand, generalised with
     ``sysprep /generalize /oobe /shutdown``, then network-booted into the
     capture image, which writes its disk to a WIM in the image group.
  3. Bare PCs (the workbench's "No operating system" PC: an empty disk, no
     disc, network boot after the disk as on any PC) PXE-boot, pick the
     golden image and install it, joining the domain from the answer file.
  4. Across VLANs a PXE client's DHCP broadcast stops at the router, as any
     broadcast does: the router forwards it to the WDS server
     (``ip helper-address`` on the clients' interface), or the router's own
     pool names the server and the boot file (``next-server``/``bootfile``,
     options 66 and 67).

The boot image comes from the Windows Server 2022 DVD: WDS refuses to boot
Windows 11's own boot.wim (Microsoft blocked it), while the 2022 one still
runs Setup in WDS mode and deploys any Windows 11 install image. Nothing is
shipped: the DVD is the user's own evaluation download, imported in Setup.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .dsc import NodeConfig

ROLE = "wds"
NETBOOT = "netboot"            # node var: a PC with no operating system that boots from the network
BOOT_MEDIA = "ws2022"          # whose sources\boot.wim becomes the WDS boot image
BOOT_UEFI = "boot\\x64\\wdsmgfw.efi"
BOOT_BIOS = "boot\\x64\\wdsnbp.com"
SETUP_IMAGE = "Microsoft Windows Setup (x64)"
CAPTURE_IMAGE = "Capture (x64)"
IMAGE_GROUP = "Golden images"
JOIN_FILE = "C:\\winlab\\wds\\join-domain.xml"
_MARK = "%%JOIN%%"             # where the lab's admin secret goes, at apply time in the guest


def is_netboot(node) -> bool:
    return str(node.vars.get(NETBOOT) or "").lower() in ("1", "true", "yes")


# ------------------------------------------------------------- the router
# `ip helper-address` on a router interface: DHCP broadcasts arriving there
# are relayed, as unicast with the interface's address as giaddr, to each
# address (a WDS server, a DHCP server). Kept in the lab file with the rest
# of the router's console settings ([devices."router"], helper:<network>).
def helpers(lab, net_id: str) -> list[str]:
    raw = lab.devices.get("router", {}).get(f"helper:{net_id}", "")
    return [a for a in str(raw).split(",") if a]


def set_helper(lab, net_id: str, addr: str, on: bool = True) -> list[str]:
    """Adds (or removes) one helper address on a network's interface; an
    empty addr with on=False removes them all."""
    have = helpers(lab, net_id)
    if on:
        addr = str(ipaddress.IPv4Address(addr))
        if addr not in have:
            have.append(addr)
    else:
        have = [a for a in have if addr and a != addr]
    own = lab.devices.setdefault("router", {})
    if have:
        own[f"helper:{net_id}"] = ",".join(have)
    else:
        own.pop(f"helper:{net_id}", None)
    return have


# A Configuration Manager site server (role mecm) carries the distribution
# point, whose PXE responder the student turns on in the OSD lessons: it
# answers PXE clients like a WDS server does.
PXE_ROLES = (ROLE, "mecm")


def wds_servers(lab) -> list[tuple[str, str, str]]:
    """(node id, address, network) of every machine that can answer PXE:
    the wds role, or a ConfigMgr site server's distribution point."""
    out = []
    for n in lab.node_list():
        if any(r in n.roles for r in PXE_ROLES):
            for nic in n.nics:
                if nic.ip:
                    out.append((n.id, nic.ip, nic.network))
    return out


def pxe_path(lab, plan, net_id: str) -> tuple[bool, str]:
    """Whether a machine booting from the network on this network finds a
    boot server, and how (or what is missing), in the router's terms. The
    WDS servers a lab names (role wds) are checked by address; on a network
    built on the workbench, where the student set the server up by hand,
    only the router's side can be read."""
    from . import netplan
    seg = plan.segment_of(net_id)
    sid = seg.network.id
    servers = wds_servers(lab)
    for node_id, ip, net in servers:
        if plan.joined.get(net, net) == sid:
            return True, f"{node_id} ({ip}) is on this network and answers the broadcast itself"
    target = servers[0][1] if servers else "<the WDS server>"
    own = lab.devices.get("router", {})
    if seg.serves_dhcp:
        nxt, f = own.get(f"next:{sid}", ""), own.get(f"file:{sid}", "")
        if nxt and f:
            return True, f"the router's pool sends PXE clients to {nxt} for {f} (options 66 and 67)"
        return False, ("the router's pool hands out addresses but no boot server: in ip dhcp pool, "
                       f"next-server {target} and bootfile {BOOT_UEFI}")
    ips = {ip for _, ip, _ in servers}
    hit = [a for a in helpers(lab, sid) if a in ips or not ips]
    if hit:
        return True, f"the router relays PXE broadcasts to {', '.join(hit)} (ip helper-address)"
    mode = netplan.dhcp_mode(plan, seg)
    where = "the router relays DHCP to the Windows DHCP server only" if mode == "relay" else \
        "nothing forwards the broadcast off this network"
    return False, (f"{where}: ip helper-address {target} on the router's interface here "
                   "(or options 66 and 67 in the Windows DHCP scope)")


def pxe_view(lab, plan, node) -> dict | None:
    """For a bare PC on the workbench: whether booting it from the network
    reaches a boot server, said in the router's terms."""
    if not is_netboot(node):
        return None
    nets = [n.network for n in node.nics if n.network and n.network in lab.networks]
    if not nets:
        return {"ok": False, "text": "no cable: plug it into a switch"}
    ok, text = pxe_path(lab, plan, nets[0])
    return {"ok": ok, "text": text}


# ------------------------------------------------------- the answer file
def join_unattend(domain: str, netbios: str, timezone: str = "UTC") -> str:
    """The image unattend a deployed PC runs: join the domain in the
    specialize pass, skip the OOBE pages, keep a local administrator. The
    secret is the marker _MARK, filled in by the role inside the guest."""
    comp = ('processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" '
            'language="neutral" versionScope="nonSxS"')
    secret = "<" + "Password>" + _MARK + "</" + "Password>"
    value = "<Value>" + _MARK + "</Value><PlainText>true</PlainText>"
    return "\r\n".join([
        '<?xml version="1.0" encoding="utf-8"?>',
        '<unattend xmlns="urn:schemas-microsoft-com:unattend">',
        '  <settings pass="specialize">',
        f'    <component name="Microsoft-Windows-UnattendedJoin" {comp}>',
        "      <Identification>",
        f"        <Credentials><Domain>{netbios}</Domain><Username>Administrator</Username>{secret}</Credentials>",
        f"        <JoinDomain>{domain}</JoinDomain>",
        "      </Identification>",
        "    </component>",
        f'    <component name="Microsoft-Windows-Shell-Setup" {comp}>',
        "      <ComputerName>*</ComputerName>",
        f"      <TimeZone>{timezone}</TimeZone>",
        "    </component>",
        "  </settings>",
        '  <settings pass="oobeSystem">',
        f'    <component name="Microsoft-Windows-International-Core" {comp}>',
        "      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale>"
        "<UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>",
        "    </component>",
        f'    <component name="Microsoft-Windows-Shell-Setup" {comp}>',
        "      <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens>"
        "<HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>",
        "      <UserAccounts><LocalAccounts><LocalAccount>"
        "<" + "Password>" + value + "</" + "Password>"
        "<Group>Administrators</Group><Name>labadmin</Name></LocalAccount></LocalAccounts></UserAccounts>",
        "    </component>",
        "  </settings>",
        "</unattend>",
        ""])


# ------------------------------------------------------------- the role
_DVD = (
    "$dvd = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and "
    "(Test-Path ('{0}:\\sources\\boot.wim' -f $_.DriveLetter)) } | Select-Object -First 1\n"
    "if (-not $dvd) { throw 'no Windows DVD with sources\\boot.wim in a DVD drive: put the Windows Server 2022 "
    "DVD in (Setup > Get Windows imports it) and apply the role again' }\n"
    "$dvd = '{0}:' -f $dvd.DriveLetter\n"
)
_CONFIG = "$c = (wdsutil /get-server /show:config) -join \"`n\"\n"
ANSWERS_TEST = _CONFIG + "[bool]($c -match 'Answer clients:\\s*Yes' -and $c -notmatch 'Answer only known clients:\\s*Yes')"


def build_wds(cfg: NodeConfig) -> None:
    """Windows Deployment Services, integrated with Active Directory (or
    standalone on a workgroup server), RemoteInstall on the data disk."""
    from .dsc import Resource, ps_quote
    from .dscroles import _data_deps
    member = bool({"domain-join", "ad-ds"} & set(cfg.node.roles))
    data = _data_deps(cfg)
    ri = f"{cfg.data_root}\\RemoteInstall"
    src = f"{cfg.data_root}\\WdsSource"
    feat = cfg.feature("WDS", subfeatures=True, depends=data)
    tools = cfg.feature("WDS-AdminPack")
    deps = [feat, tools] + ([cfg.ensure_domain_ready()] if member else [])
    init = cfg.script(
        "WdsInitialized",
        f"[bool](Test-Path {ps_quote(ri + chr(92) + 'Boot')}) -and [bool](Get-Service -Name WDSServer -ErrorAction SilentlyContinue)",
        f"$out = wdsutil /Verbose /initialize-server /reminst:{ps_quote(ri)}{'' if member else ' /Standalone'} 2>&1\n"
        f"if (-not (Test-Path {ps_quote(ri + chr(92) + 'Boot')})) {{ throw ('WDS did not initialise: ' + ($out -join ' ')) }}",
        depends=deps, run_as=member)
    after = [init]
    if "dhcp" in cfg.node.roles:
        # DHCP on the same server owns UDP 67: WDS listens on 4011 and the
        # DHCP replies carry option 60 (PXEClient) to send clients there.
        after = [cfg.script(
            "WdsBesideDhcp",
            _CONFIG + "[bool]($c -match 'Use DHCP ports:\\s*No')",
            "wdsutil /set-server /UseDhcpPorts:No /DhcpOption60:Yes | Out-Null",
            depends=[init])]
    answer = cfg.script("WdsAnswersClients", ANSWERS_TEST,
                        "wdsutil /set-server /answerclients:All | Out-Null", depends=after)
    svc = cfg.add(Resource("Service", "WdsServer", {
        "Name": "WDSServer", "State": "Running", "StartupType": "Automatic",
    }, depends_on=[answer])).id
    setup = cfg.script(
        "WdsSetupBootImage",
        f"[bool](Get-WdsBootImage -Architecture X64 -ImageName {ps_quote(SETUP_IMAGE)} -ErrorAction SilentlyContinue)",
        _DVD + f"Import-WdsBootImage -Path \"$dvd\\sources\\boot.wim\" -NewImageName {ps_quote(SETUP_IMAGE)} "
        "-SkipVerify | Out-Null",
        depends=[svc], run_as=member)
    cap = f"{src}\\capture-x64.wim"
    d = cfg.directory(src, data)
    capture = cfg.script(
        "WdsCaptureBootImage",
        f"[bool](Get-WdsBootImage -Architecture X64 -ImageName {ps_quote(CAPTURE_IMAGE)} -ErrorAction SilentlyContinue)",
        f"wdsutil /Verbose /new-captureimage /Image:{ps_quote(SETUP_IMAGE)} /Architecture:x64 /DestinationImage "
        f"/FilePath:{ps_quote(cap)} /Name:{ps_quote(CAPTURE_IMAGE)} "
        "/Description:'Writes a sysprepped PC to a WIM' /Overwrite:Yes | Out-Null\n"
        f"Import-WdsBootImage -Path {ps_quote(cap)} -NewImageName {ps_quote(CAPTURE_IMAGE)} -SkipVerify | Out-Null",
        depends=[setup, d], run_as=member)
    group = cfg.script(
        "WdsImageGroup",
        f"[bool](Get-WdsInstallImageGroup -Name {ps_quote(IMAGE_GROUP)} -ErrorAction SilentlyContinue)",
        f"New-WdsInstallImageGroup -Name {ps_quote(IMAGE_GROUP)} | Out-Null",
        depends=[svc], run_as=member)
    xml = join_unattend(cfg.domain or "lab.local", cfg.netbios or "LAB", cfg.lab.timezone or "UTC")
    lines = ",\n".join("    " + ps_quote(x) for x in xml.split("\r\n"))
    unattend = cfg.script(
        "WdsJoinDomainUnattend",
        f"Test-Path {ps_quote(JOIN_FILE)}",
        "$f = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json\n"
        f"$xml = @(\n{lines}\n) -join \"`r`n\"\n"
        f"$xml = $xml.Replace({ps_quote(_MARK)}, [Security.SecurityElement]::Escape([string]$f.lab.admin_password))\n"
        "New-Item -ItemType Directory -Path 'C:\\winlab\\wds' -Force | Out-Null\n"
        f"Set-Content -Path {ps_quote(JOIN_FILE)} -Value $xml -Encoding UTF8",
        depends=[group]) if member else ""
    cfg.notes.append(f"wds: RemoteInstall at {ri}, boot images from the {BOOT_MEDIA} DVD's boot.wim; "
                     f"PXE clients on other VLANs need ip helper-address or options 66/67")
    cfg.text_file("WdsReadme", "C:\\winlab\\wds-README.txt", (
        "Windows Deployment Services (winlab role wds)\r\n"
        f"  RemoteInstall:   {ri}\r\n"
        f"  boot images:     {SETUP_IMAGE}, {CAPTURE_IMAGE} (from the Windows Server 2022 DVD's boot.wim)\r\n"
        f"  image group:     {IMAGE_GROUP} (captures land here)\r\n"
        f"  boot files:      {BOOT_UEFI} (UEFI), {BOOT_BIOS} (BIOS)\r\n"
        + (f"  domain join:     {JOIN_FILE}, attach it to a captured image:\r\n"
           f"                   Set-WdsInstallImage -ImageName <name> -ImageGroup '{IMAGE_GROUP}' "
           f"-UnattendFile {JOIN_FILE} -OverwriteUnattend\r\n" if member else "")
        + "  console:         Start > Windows Deployment Services (wdsmgmt.msc)\r\n"
        "  capture a PC:    sysprep /generalize /oobe /shutdown on it, network-boot it, pick Capture (x64)\r\n"
        "  other VLANs:     on the router, ip helper-address <this server> on the clients' interface\r\n"),
        depends=[capture, group] + ([unattend] if unattend else []))


BUILDERS = {ROLE: build_wds}


# ----------------------------------------------------------- guest faults
def _faults():
    from .guestfaults import WINDOWS, GuestFault
    return [GuestFault(
        id="wds-not-answering",
        roles=(ROLE,),
        title="Machines booting from the network get no boot server",
        os=WINDOWS,
        teaches="the PXE conversation (DHCP offer, then a boot server offer, then TFTP), telling a missing relay "
                "from a server that will not answer, and where WDS keeps its PXE response policy",
        symptom="a bare PC on the clients network shows 'Start PXE over IPv4', gets an address and then falls "
                "back to the boot menu ('PXE-E16: No valid offer received' on a BIOS PC); WDS is installed, its "
                "service runs and the boot images are there",
        apply="wdsutil /set-server /answerclients:None | Out-Null",
        clear="wdsutil /set-server /answerclients:All | Out-Null",
        hints=(
            "Split the boot in two: did the PC get an address? On the DHCP server, Get-DhcpServerv4Lease for the "
            "clients' scope shows a lease for its MAC, so DHCP and the relay work. What is missing is the second "
            "offer, the one from the boot server. On the router, show running-config: the clients' interface "
            "has its ip helper-address to this server, so the broadcast reaches it.",
            "The broadcast arrives and nothing answers. On this server Get-Service WDSServer runs, so look at what "
            "it is told to answer: wdsutil /get-server /show:config, under Answer Policy, or in the Windows "
            "Deployment Services console the server's Properties, PXE Response tab. The Deployment-Services-"
            "Diagnostics event log shows requests arriving and being ignored.",
            "wdsutil /set-server /answerclients:All (or 'Respond to all client computers' on the PXE Response "
            "tab). Restart the PC from its firmware's network entry: it now gets the boot server's offer and "
            "loads the Windows Boot Manager over TFTP.",
        ),
        verify=ANSWERS_TEST.replace("\n", "; ") + " -and ((Get-Service -Name WDSServer).Status -eq 'Running')",
    )]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
