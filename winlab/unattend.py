"""autounattend.xml generation for unattended Windows installs."""

from __future__ import annotations

import html

from .model import WINDOWS_CLIENT, Lab, Node

UEFI = "uefi"
BIOS = "bios"

# The install.wim image Setup is told to install, by catalog image, when the
# media's own image list could not be read (images.edition_name reads it at
# import; these are the names retail media uses). Not documented by Microsoft
# and different on evaluation and volume media, which is why the media is
# read first.
DEFAULT_IMAGE = {
    "ws2025": "Windows Server 2025 SERVERSTANDARD",
    "ws2025-core": "Windows Server 2025 SERVERSTANDARDCORE",
    "ws2022": "Windows Server 2022 SERVERSTANDARD",
    "ws2022-core": "Windows Server 2022 SERVERSTANDARDCORE",
    "ws2019": "Windows Server 2019 SERVERSTANDARD",
    "ws2019-core": "Windows Server 2019 SERVERSTANDARDCORE",
    "win11": "Windows 11 Enterprise",
    "win10": "Windows 10 Enterprise",
}

# Windows 11 refuses to install without TPM 2.0, Secure Boot and 4 GB RAM
# (Windows 10 ignores these keys).
# swtpm is not part of the MSYS2 qemu package, so setup is told to skip the
# checks instead. Server 2025 has no such requirement.
BYPASS_KEYS = [
    "BypassTPMCheck",
    "BypassSecureBootCheck",
    "BypassRAMCheck",
    "BypassCPUCheck",
    "BypassStorageCheck",
]


def _esc(value: str) -> str:
    return html.escape(str(value), quote=True)


def _media_image_name(image_id: str) -> str:
    """The edition's name as the imported ISO's install.wim lists it, when
    `images import` could read it; blank otherwise."""
    try:
        from . import images
        return images.edition_name(image_id)
    except Exception:  # never let a metadata problem stop an answer file
        return ""


def _disk_config(firmware: str) -> str:
    if firmware == UEFI:
        parts = """
                <CreatePartitions>
                  <CreatePartition wcm:action="add">
                    <Order>1</Order><Type>EFI</Type><Size>500</Size>
                  </CreatePartition>
                  <CreatePartition wcm:action="add">
                    <Order>2</Order><Type>MSR</Type><Size>16</Size>
                  </CreatePartition>
                  <CreatePartition wcm:action="add">
                    <Order>3</Order><Type>Primary</Type><Extend>true</Extend>
                  </CreatePartition>
                </CreatePartitions>
                <ModifyPartitions>
                  <ModifyPartition wcm:action="add">
                    <Order>1</Order><PartitionID>1</PartitionID>
                    <Label>System</Label><Format>FAT32</Format>
                  </ModifyPartition>
                  <ModifyPartition wcm:action="add">
                    <Order>2</Order><PartitionID>2</PartitionID>
                  </ModifyPartition>
                  <ModifyPartition wcm:action="add">
                    <Order>3</Order><PartitionID>3</PartitionID>
                    <Label>Windows</Label><Format>NTFS</Format><Letter>C</Letter>
                  </ModifyPartition>
                </ModifyPartitions>"""
        target = 3
    else:
        parts = """
                <CreatePartitions>
                  <CreatePartition wcm:action="add">
                    <Order>1</Order><Type>Primary</Type><Size>500</Size>
                  </CreatePartition>
                  <CreatePartition wcm:action="add">
                    <Order>2</Order><Type>Primary</Type><Extend>true</Extend>
                  </CreatePartition>
                </CreatePartitions>
                <ModifyPartitions>
                  <ModifyPartition wcm:action="add">
                    <Order>1</Order><PartitionID>1</PartitionID>
                    <Label>System</Label><Format>NTFS</Format><Active>true</Active>
                  </ModifyPartition>
                  <ModifyPartition wcm:action="add">
                    <Order>2</Order><PartitionID>2</PartitionID>
                    <Label>Windows</Label><Format>NTFS</Format><Letter>C</Letter>
                  </ModifyPartition>
                </ModifyPartitions>"""
        target = 2
    return parts, target


def _prep_logon(prep: bool, cmd: str, virtio: bool = False) -> str:
    if not prep:
        return ""
    from . import basetrim
    drivers = ""
    if virtio:
        from . import virtio as vio
        drivers = f"""
        <SynchronousCommand wcm:action="add">
          <Order>97</Order>
          <CommandLine>{_esc(vio.command())}</CommandLine>
          <Description>winlab virtio drivers (network, disk, balloon) before sysprep</Description>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>"""
    return drivers + f"""
        <SynchronousCommand wcm:action="add">
          <Order>98</Order>
          <CommandLine>{_esc(basetrim.command())}</CommandLine>
          <Description>winlab base trim (hibernation, pagefile, component store, Compact OS, retrim)</Description>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>99</Order>
          <CommandLine>{_esc(cmd)}</CommandLine>
          <Description>winlab base seal (sysprep + shutdown)</Description>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>"""


def _bypass_block(node: Node) -> str:
    if node.kind != WINDOWS_CLIENT:
        return ""
    rows = []
    for i, key in enumerate(BYPASS_KEYS, start=1):
        rows.append(
            f"""
          <RunSynchronousCommand wcm:action="add">
            <Order>{i}</Order>
            <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v {key} /t REG_DWORD /d 1 /f</Path>
          </RunSynchronousCommand>"""
        )
    return f"""
        <RunSynchronous>{''.join(rows)}
        </RunSynchronous>"""


def render(
    node: Node,
    lab: Lab,
    firmware: str = UEFI,
    image_name: str = "",
    disk_id: int = 0,
    prep: bool = False,
    virtio: bool = False,
) -> str:
    parts, target = _disk_config(firmware)
    image = (image_name or str(node.vars.get("image_name") or "")
             or _media_image_name(node.image)
             or DEFAULT_IMAGE.get(node.image, DEFAULT_IMAGE["ws2025"]))
    password = _esc(lab.admin_password)
    hostname = _esc(node.hostname or node.id.upper()[:15])

    # Stage 0 runs from whichever drive letter the data volume lands on.
    stage0 = (
        "cmd /c for %i in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do "
        "@if exist %i:\\winlab-stage0.cmd call %i:\\winlab-stage0.cmd"
    )
    # In base-prep mode, after staging the agent the machine generalises itself
    # and powers off. This removes the fragile OOBE->serial-agent handoff from
    # base preparation: prepare just waits for the VM to power off, then seals.
    prep_cmd = (
        "cmd /c %WINDIR%\\System32\\Sysprep\\sysprep.exe "
        "/generalize /oobe /shutdown /quiet"
    )

    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">

  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS">
      <SetupUILanguage><UILanguage>{_esc(lab.locale)}</UILanguage></SetupUILanguage>
      <InputLocale>{_esc(lab.locale)}</InputLocale>
      <SystemLocale>{_esc(lab.locale)}</SystemLocale>
      <UILanguage>{_esc(lab.locale)}</UILanguage>
      <UserLocale>{_esc(lab.locale)}</UserLocale>
    </component>

    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS">{_bypass_block(node)}
      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add">
          <DiskID>{disk_id}</DiskID>
          <WillWipeDisk>true</WillWipeDisk>{parts}
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/NAME</Key>
              <Value>{_esc(image)}</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo><DiskID>{disk_id}</DiskID><PartitionID>{target}</PartitionID></InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>winlab</FullName>
        <Organization>winlab</Organization>
      </UserData>
    </component>
  </settings>

  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS">
      <ComputerName>{hostname}</ComputerName>
      <TimeZone>{_esc(lab.timezone)}</TimeZone>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
    <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS">
      <FirewallGroups>
        <FirewallGroup wcm:action="add" keyValue="rdp">
          <Active>true</Active><Group>@FirewallAPI.dll,-28752</Group>
          <Profile>all</Profile>
        </FirewallGroup>
      </FirewallGroups>
    </component>
  </settings>

  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS">
      <InputLocale>{_esc(lab.locale)}</InputLocale>
      <SystemLocale>{_esc(lab.locale)}</SystemLocale>
      <UILanguage>{_esc(lab.locale)}</UILanguage>
      <UserLocale>{_esc(lab.locale)}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral"
               versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
          <Value>{password}</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <LogonCount>999</LogonCount>
        <Username>Administrator</Username>
        <Password><Value>{password}</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <NetworkLocation>Work</NetworkLocation>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>{_esc(stage0)}</CommandLine>
          <Description>winlab stage 0</Description>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>{_prep_logon(prep, prep_cmd, virtio)}
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""


def setup_helper(arch: str = "amd64") -> str:
    """The whole answer file of a Windows 11 machine the student installs by
    hand: it only tells Setup to skip the TPM, Secure Boot and RAM checks
    this virtual PC cannot pass (what Rufus offers for real PCs). Every page
    of Setup still asks: nothing else is answered."""
    rows = "".join(
        f"""
          <RunSynchronousCommand wcm:action="add">
            <Order>{i}</Order>
            <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v {key} /t REG_DWORD /d 1 /f</Path>
          </RunSynchronousCommand>"""
        for i, key in enumerate(BYPASS_KEYS, start=1))
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="{arch}"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>{rows}
      </RunSynchronous>
    </component>
  </settings>
</unattend>
"""

