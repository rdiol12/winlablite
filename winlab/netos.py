"""Vendor routers: the router makers' own operating systems, in a lab VM.

A network engineer at work does not meet "a router": they meet a MikroTik
with its WebFig pages and its /ip address print, a Juniper with its
candidate configuration and commit, an Arista with its EOS shell. Those
differences are the job, and an imitation teaches only the imitation. So
the shelf's Vendor router is a lab machine that boots the vendor's real
router OS, unmodified, the way the vendors themselves hand it out for labs
(a "virtual router" image for a hypervisor): the web UI and the CLI the
student meets are the vendor's own, nothing of ours is drawn over them.

What each vendor allows decides how the image gets onto this PC; winlab
never bundles, mirrors or re-hosts any of them (LICENSING.md):

* MikroTik RouterOS CHR (Cloud Hosted Router): MikroTik publishes the image
  for anyone to download, so winlab fetches it from download.mikrotik.com.
  Without a paid licence it runs at the free level: no time limit, every
  feature, but each interface's upload is held to 1 Mbit/s. MikroTik
  publishes no checksum file a program can read (the SHA-256 is on its
  download page), so winlab checks the archive's own CRCs and records the
  SHA-256 it computed, to compare with that page.
* VyOS: the project builds a rolling release every night from its free
  sources and publishes it on GitHub (vyos/vyos-nightly-build) for anyone;
  GitHub's release API carries each file's SHA-256, which the download is
  checked against. The long-term-support releases (1.4, 1.5) are images
  for subscribers only, so winlab does not offer them. VyOS is installed by
  hand from its live ISO (`install image`), like winlab's Linux DVDs.
* Juniper vJunos-router, vJunos-switch and vSRX: free for labs, but behind a
  Juniper account and an EULA accepted on the download page, so they are
  imported only: the user downloads the file, winlab imports it.
  vJunos runs Junos inside a small VM of its own, so it needs nested
  virtualization (KVM with VT-x passed on) and refuses to start where this
  PC cannot give it (winlab/nestedvirt.py says why in words).
* Arista vEOS-lab: free with an Arista account, imported only (the vEOS-lab
  disk, and Arista's Aboot boot-loader ISO for the releases that need it).
* Fortinet FortiGate-VM and Palo Alto Networks PA-VM (VM-Series): the
  firewall makers' own KVM images, behind a FortiCare or a Palo Alto
  Networks support account, so imported only like Juniper's. They are
  firewalls, not routers: the shelf offers them as "Other vendors", and only
  once one is on this PC (winlab/workbench.py). Their licences are the
  vendors' own: FortiGate-VM's permanent trial and an unlicensed PA-VM both
  run with small limits, said in `limits`.

Cisco publishes no free image, so the lab's Cisco-style routers stay the
IOS-style console (winlab/devcli.py); no vendor's web UI is imitated.

Each one is a lab machine (kind "custom") with several network cards cabled
into workbench switch ports, the cards and disk the vendor's OS documents
(virtio for RouterOS, VyOS and Junos, Intel e1000 and SATA for EOS), legacy
BIOS, a VGA screen and its serial console on the Terminal window. Its web
UI, where it has one, is opened from a lab PC's browser (winlab/adminui.py);
the lab stays isolated from this PC and the internet like every machine.
"""

from __future__ import annotations

import json
import re
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import BootstrapError, _download_to, _get, _sha256

# The catalog kind of a vendor router OS (images.CATALOG).
KIND = "router-os"
# `winlab images import router <file>`: which vendor is read off the file.
AUTO = "router"
DISK = "disk"            # the vendor ships a ready disk image: the machine is a thin clone of it
INSTALLER = "installer"  # the vendor ships an installer ISO: an empty disk, installed by hand
VIRTIO = "virtio"
SATA = "sata"
FILE_TYPES = (".img", ".zip", ".qcow2", ".vmdk", ".vdi", ".vhdx", ".iso")


class NetOsError(Exception):
    pass


@dataclass(frozen=True)
class Vendor:
    id: str
    title: str
    short: str
    publisher: str
    page: str            # where a person gets it
    license: str
    form: str            # DISK or INSTALLER
    nic: str             # QEMU's network card model
    disk_bus: str        # VIRTIO or SATA
    memory_mb: int       # the vendor's documented floor for a lab
    cpus: int
    ports: tuple[str, ...]    # the first cards' names, in port order
    port_fmt: str        # the cards after them: "{n}" counts on from port_start
    port_start: int
    login: str           # the first sign-in, in words (never a password literal)
    cli: str             # where its CLI is
    names: tuple[str, ...]    # file names (regexes) the vendor gives its downloads
    labels: tuple[str, ...] = ()   # ISO volume labels (regexes), for an installer
    fetch: bool = False  # winlab may download it for the user
    get: str = ""        # how a person gets it when winlab cannot
    limits: str = ""     # what the free use leaves out, said plainly
    size_gb: float = 0.5
    disk_gb: int = 0     # an installer's empty disk
    nics: int = 4        # cards a new one gets on the workbench
    nested: bool = False # runs a VM of its own inside: needs VT-x passed on
    smbios: str = ""     # what the vendor's image reads in SMBIOS type 1
    web: tuple = ()      # (software, scheme, port, path, note) of its web UI; () for none
    defaults: str = ""   # what a fresh one does, for the panel
    role: str = "router" # "router" (the shelf's Vendor router) or "firewall" (Other vendors)


VENDORS: dict[str, Vendor] = {v.id: v for v in (
    Vendor(
        id="chr", title="MikroTik RouterOS CHR (Cloud Hosted Router)", short="MikroTik CHR",
        publisher="MikroTik", page="https://mikrotik.com/download",
        license=("MikroTik's RouterOS licence: the CHR image is free to download and run; without a paid "
                 "licence it runs at the free level (no time limit, every feature, upload limited to 1 Mbit/s "
                 "per interface). \"MikroTik\", \"RouterOS\" and \"WinBox\" are MikroTik's trademarks"),
        form=DISK, nic="virtio-net-pci", disk_bus=VIRTIO, memory_mb=1024, cpus=1,
        ports=(), port_fmt="ether{n}", port_start=1,
        login=("the admin user with an empty password, as CHR ships; RouterOS 7 asks you to choose a new "
               "password at that first sign-in"),
        cli="its screen and serial console, SSH (port 22) and WebFig's Terminal",
        names=(r"(?i)^chr-\d[\w.]*\.(?:img(?:\.zip)?|vmdk|vdi|vhdx|qcow2)$",),
        fetch=True, size_gb=0.1,
        limits=("the free licence level: every feature, no time limit, but each interface sends at most "
                "1 Mbit/s; a paid level (P1 and up, or a 60-day trial) needs a MikroTik account and internet, "
                "which the lab does not have"),
        nics=4,
        web=("WebFig (RouterOS's web UI)", "http", 80, "/",
             "Interfaces, IP addresses, routing, firewall and DHCP, the same menus as WinBox and the CLI. "
             "WinBox (MikroTik's own Windows program, which you download from MikroTik yourself) "
             "connects on TCP 8291."),
        defaults="out of the box ether1 runs a DHCP client; nothing else is configured"),
    Vendor(
        id="vyos", title="VyOS rolling release (live and installer ISO)", short="VyOS",
        publisher="the VyOS project (VyOS Networks)", page="https://vyos.net/get/nightly-builds/",
        license=("GPL-2.0 and the other free licences of the software it is built from; the rolling-release "
                 "ISOs are published for anyone to download. The long-term-support images (1.4, 1.5) are for "
                 "subscribers only, and winlab does not offer them. \"VyOS\" is VyOS Networks' trademark"),
        form=INSTALLER, nic="virtio-net-pci", disk_bus=VIRTIO, memory_mb=2048, cpus=2,
        ports=(), port_fmt="eth{n}", port_start=0,
        login=("the vyos user, whose password is the user's own name, on the live system and on the "
               "installed one until you change it"),
        cli="its screen and serial console, and SSH once you turn it on (set service ssh)",
        names=(r"(?i)^vyos-[\w.-]*amd64\.iso$",), labels=(r"(?i)^vyos",),
        fetch=True, size_gb=0.7, disk_gb=10, nics=3,
        limits=("a rolling release, built every night: newest features, no long-term support; the LTS "
                "releases need a VyOS subscription"),
        defaults=("the live system boots first: sign in and run install image to put it on the disk, then "
                  "reboot: the installed disk boots before the DVD from then on")),
    Vendor(
        id="vjunos-router", title="Juniper vJunos-router (your download)", short="vJunos-router",
        publisher="Juniper Networks", page="https://www.juniper.net/us/en/dm/vjunos-labs.html",
        license=("Juniper's end user licence agreement, accepted on its download page: free for labs and "
                 "training, not for production, no support. \"Juniper\" and \"Junos\" are Juniper Networks' "
                 "trademarks"),
        form=DISK, nic="virtio-net-pci", disk_bus=VIRTIO, memory_mb=5120, cpus=4,
        ports=("fxp0",), port_fmt="ge-0/0/{n}", port_start=0,
        login=("root with no password at the first boot; Junos will not commit a configuration until root "
               "has one (set system root-authentication plain-text-password)"),
        cli="its serial console (the Terminal window), and SSH once you turn it on (set system services ssh)",
        names=(r"(?i)^vjunos-router-[\w.-]+\.qcow2$",), size_gb=4.0, nics=4, nested=True,
        smbios="product=VM-VMX,family=lab",
        get=("Juniper hands vJunos-router out from its vJunos labs page behind a free Juniper account and its "
             "licence agreement; winlab cannot fetch it. Download the .qcow2 yourself and import it here"),
        limits="a lab edition: one routing engine, a few Gbit/s at most, no support, never production",
        defaults="the first card is the management port fxp0, the next ones ge-0/0/0, ge-0/0/1 …"),
    Vendor(
        id="vjunos-switch", title="Juniper vJunos-switch (your download)", short="vJunos-switch",
        publisher="Juniper Networks", page="https://www.juniper.net/us/en/dm/vjunos-labs.html",
        license=("Juniper's end user licence agreement, accepted on its download page: free for labs and "
                 "training, not for production, no support. \"Juniper\" and \"Junos\" are Juniper Networks' "
                 "trademarks"),
        form=DISK, nic="virtio-net-pci", disk_bus=VIRTIO, memory_mb=5120, cpus=4,
        ports=("fxp0",), port_fmt="ge-0/0/{n}", port_start=0,
        login=("root with no password at the first boot; Junos will not commit a configuration until root "
               "has one (set system root-authentication plain-text-password)"),
        cli="its serial console (the Terminal window), and SSH once you turn it on (set system services ssh)",
        names=(r"(?i)^vjunos-switch-[\w.-]+\.qcow2$",), size_gb=4.0, nics=4, nested=True,
        smbios="product=VM-VEX,family=lab",
        get=("Juniper hands vJunos-switch out from its vJunos labs page behind a free Juniper account and its "
             "licence agreement; winlab cannot fetch it. Download the .qcow2 yourself and import it here"),
        limits="a lab edition: a few Gbit/s at most, no support, never production",
        defaults="the first card is the management port fxp0, the next ones ge-0/0/0, ge-0/0/1 …"),
    Vendor(
        id="vsrx", title="Juniper vSRX Virtual Firewall (your download)", short="vSRX",
        publisher="Juniper Networks", page="https://support.juniper.net/support/downloads/?p=vsrx",
        license=("Juniper's end user licence agreement: the image needs a Juniper account to download; its "
                 "evaluation licence unlocks the licensed features for a trial period. \"Juniper\", \"Junos\" "
                 "and \"vSRX\" are Juniper Networks' trademarks"),
        form=DISK, nic="virtio-net-pci", disk_bus=VIRTIO, memory_mb=4096, cpus=2,
        ports=("fxp0",), port_fmt="ge-0/0/{n}", port_start=0,
        login=("root with no password at the first boot; Junos will not commit a configuration until root "
               "has one (set system root-authentication plain-text-password)"),
        cli="its screen and serial console, and SSH once you turn it on (set system services ssh)",
        names=(r"(?i)^junos-vsrx3?-x86-64-[\w.-]+\.qcow2$", r"(?i)^vsrx[\w.-]*\.qcow2$"),
        size_gb=2.0, nics=3,
        get=("Juniper hands vSRX out from its download site behind a Juniper account (an evaluation is "
             "offered); winlab cannot fetch it. Download the KVM .qcow2 yourself and import it here"),
        limits="the evaluation licence's features for its trial period; the base firewall runs without it",
        web=("J-Web (Junos's web UI)", "https", 443, "/",
             "Off until you turn it on (set system services web-management https system-generated-certificate); "
             "it signs its pages with its own certificate: accept the browser's warning once."),
        defaults="the first card is fxp0 (management), ge-0/0/0 is untrust and ge-0/0/1 trust, as it ships"),
    Vendor(
        id="veos-lab", title="Arista vEOS-lab (your download)", short="Arista vEOS-lab",
        publisher="Arista Networks", page="https://www.arista.com/en/support/software-download",
        license=("Arista's end user licence agreement: vEOS-lab is free for labs with an Arista account, not "
                 "for production, no support. \"Arista\" and \"EOS\" are Arista Networks' trademarks"),
        form=DISK, nic="e1000", disk_bus=SATA, memory_mb=4096, cpus=2,
        ports=("Management1",), port_fmt="Ethernet{n}", port_start=1,
        login=("admin with no password; at the first boot Zero Touch Provisioning waits for a server the lab "
               "does not have: type zerotouch cancel, and it restarts without it"),
        cli="its serial console (the Terminal window) and its screen, SSH (on by default once it has an address)",
        names=(r"(?i)^veos(?:64)?-lab-[\w.-]+\.(?:vmdk|qcow2)$", r"(?i)^aboot-veos[\w.-]*\.iso$"),
        labels=(r"(?i)aboot",), size_gb=0.6, nics=4,
        get=("Arista hands vEOS-lab out from its software download page behind a free Arista account; winlab "
             "cannot fetch it. Download the vEOS-lab .vmdk (or .qcow2) yourself and import it here; for the "
             "releases that boot through it, import Arista's Aboot ISO (Aboot-veos-serial-…iso) too"),
        limits="a lab edition: a few hundred Mbit/s through the data plane, no support, never production",
        web=("EOS Command API explorer (eAPI)", "https", 443, "/explorer.html",
             "EOS has no configuration web GUI: its Command API answers on https once you turn it on "
             "(management api http-commands, then no shutdown), with an explorer page to try commands; "
             "it signs its pages with its own certificate."),
        defaults="the first card is Management1, the next ones Ethernet1, Ethernet2 …"),
    Vendor(
        id="fortigate-vm", title="Fortinet FortiGate-VM (your download)", short="FortiGate-VM",
        publisher="Fortinet", page="https://support.fortinet.com/",
        license=("Fortinet's end user licence agreement: the KVM image is downloaded from Fortinet's support site "
                 "with a FortiCare account; its permanent trial licence (FortiOS 7.2 and later) is free and tied to "
                 "that account, with small limits. \"Fortinet\", \"FortiGate\" and \"FortiOS\" are Fortinet's "
                 "trademarks"),
        form=DISK, nic="virtio-net-pci", disk_bus=VIRTIO, memory_mb=2048, cpus=1,
        ports=(), port_fmt="port{n}", port_start=1,
        login=("admin with an empty password at the first boot; FortiOS makes you choose a new password at that "
               "first sign-in"),
        cli="its serial console (the Terminal window) and its screen, SSH once an interface allows it (set allowaccess)",
        names=(r"(?i)^FGT_VM64_KVM-v[\w.-]+\.out\.kvm\.(?:zip|qcow2)$", r"(?i)^fortios\.qcow2$"),
        size_gb=0.1, nics=3, role="firewall",
        get=("Fortinet hands FortiGate-VM out from its support site (Support > VM Images, platform KVM) behind a "
             "FortiCare account; winlab cannot fetch it. Download the KVM .zip (FGT_VM64_KVM-…out.kvm.zip) yourself "
             "and import it here"),
        limits=("the permanent trial licence: one processor, 2 GB of memory, a few interfaces, policies and routes, "
                "weak encryption only; it is activated against your FortiCare account, which the isolated lab cannot "
                "reach, so follow Fortinet's current instructions for activating it before you rely on it"),
        web=("FortiOS web UI", "https", 443, "/",
             "On an interface once you allow it there (config system interface, edit port2, set allowaccess ping "
             "https ssh); it signs its pages with its own certificate: accept the browser's warning once."),
        defaults="port1 asks for an address by DHCP out of the box; port2, port3 … are unconfigured"),
    Vendor(
        id="pa-vm", title="Palo Alto Networks PA-VM (VM-Series, your download)", short="PA-VM",
        publisher="Palo Alto Networks", page="https://support.paloaltonetworks.com/",
        license=("Palo Alto Networks' end user licence agreement: the KVM image needs a Palo Alto Networks support "
                 "account (or an evaluation from them) to download and an authorization code to licence; unlicensed "
                 "it runs with a minimal session limit. \"Palo Alto Networks\", \"PAN-OS\" and \"VM-Series\" are "
                 "trademarks of Palo Alto Networks"),
        form=DISK, nic="virtio-net-pci", disk_bus=VIRTIO, memory_mb=6656, cpus=2,
        ports=("management",), port_fmt="ethernet1/{n}", port_start=1,
        login=("admin, whose first password is the user's own name; PAN-OS makes you choose a new one at that "
               "first sign-in. It takes several minutes after boot before the prompt accepts it"),
        cli="its serial console (the Terminal window), and SSH on the management port",
        names=(r"(?i)^PA-VM-KVM-[\d.]+(?:-h\d+)?\.qcow2$",),
        size_gb=3.0, nics=3, role="firewall",
        get=("Palo Alto Networks hands the VM-Series KVM image out from its support portal (Updates > Software "
             "Updates, PA-VM-KVM) behind a support account or an evaluation; winlab cannot fetch it. Download the "
             ".qcow2 yourself and import it here"),
        limits=("without an authorization code it runs unlicensed: no serial number, a minimal number of sessions, "
                "no threat or URL subscriptions; an evaluation licence comes from Palo Alto Networks"),
        web=("PAN-OS web interface", "https", 443, "/",
             "On the management port out of the box; on a data port only with an interface management profile that "
             "allows HTTPS. It signs its pages with its own certificate: accept the browser's warning once."),
        defaults=("the first card is the management port (DHCP out of the box), the next ones ethernet1/1, "
                  "ethernet1/2 …; a data port belongs to no zone until you put it in one")),
)}

# The router makers' OS (the shelf's Vendor router) and the firewall makers'
# (the shelf's Other vendors, shown once one is imported).
ROUTERS = [i for i, v in VENDORS.items() if v.role == "router"]
FIREWALLS = [i for i, v in VENDORS.items() if v.role == "firewall"]


def is_image(image_id: str) -> bool:
    return image_id in VENDORS


def is_router(node) -> bool:
    """A lab machine that boots a vendor's router or firewall OS."""
    return getattr(node, "kind", "") == "custom" and getattr(node, "image", "") in VENDORS


def is_disk_router(node) -> bool:
    """One that runs the vendor's ready disk image (a thin clone of it)."""
    return is_router(node) and VENDORS[node.image].form == DISK


def is_hand_router(node) -> bool:
    """One installed by hand from the vendor's ISO (VyOS)."""
    return is_router(node) and VENDORS[node.image].form == INSTALLER


def vendor_of(node) -> Vendor | None:
    return VENDORS.get(node.image) if is_router(node) else None


def port_name(image_id: str, index: int) -> str:
    """The name the vendor's OS gives the card in that port: ether1 on a
    MikroTik, eth0 on VyOS, fxp0 then ge-0/0/0 on Junos, Management1 then
    Ethernet1 on EOS."""
    v = VENDORS[image_id]
    if index < len(v.ports):
        return v.ports[index]
    return v.port_fmt.format(n=v.port_start + index - len(v.ports))


def port_names(image_id: str, count: int) -> list[str]:
    return [port_name(image_id, i) for i in range(count)]


def uses_virtio(node) -> bool:
    return VENDORS[node.image].disk_bus == VIRTIO


def nic_model(node) -> str:
    return VENDORS[node.image].nic


def needs_nested(node) -> bool:
    v = vendor_of(node)
    return bool(v and v.nested)


def can_run(node, accel: str) -> tuple[bool, str]:
    """Whether this PC can run it, and in plain words why not: vJunos runs
    Junos in a VM of its own, which needs VT-x passed on to the machine."""
    v = vendor_of(node)
    if v is None or not v.nested:
        return True, ""
    from .nestedvirt import host_support
    ok, why = host_support(accel)
    if ok:
        return True, ""
    return False, (f"{v.short} runs Junos inside a VM of its own, so it needs nested virtualization (VT-x "
                   f"passed on to the machine), and {why}. Juniper documents it for KVM on Linux only")


def smbios_args(argv: list[str], node) -> list[str]:
    """The machine's SMBIOS system entry with what the vendor's image looks
    for (vJunos reads product VM-VMX or VM-VEX, family lab, to know it runs
    as a lab VM); the rest of the entry stays the machine's own."""
    v = vendor_of(node)
    if v is None or not v.smbios:
        return argv
    want = dict(kv.split("=", 1) for kv in v.smbios.split(","))
    out = list(argv)
    for i, a in enumerate(out[:-1]):
        if a == "-smbios" and out[i + 1].startswith("type=1"):
            fields = [f for f in out[i + 1].split(",") if f.split("=", 1)[0] not in want]
            out[i + 1] = ",".join(fields + [f"{k}={x}" for k, x in want.items()])
            return out
    return out + ["-smbios", "type=1," + v.smbios]


# ------------------------------------------------------------ fetching
CHR_NEWEST = "https://upgrade.mikrotik.com/routeros/NEWESTa7.stable"
CHR_URL = "https://download.mikrotik.com/routeros/{v}/chr-{v}.img.zip"
VYOS_API = "https://api.github.com/repos/vyos/vyos-nightly-build/releases/latest"
VYOS_ISO = re.compile(r"^vyos-[\w.-]+-generic-amd64\.iso$")


def resolve(image_id: str, get=_get) -> tuple[str, str, str, str]:
    """(url, file, sha256 or '', version) of the newest image the vendor
    publishes: RouterOS's stable channel, or VyOS's latest rolling release
    with the SHA-256 GitHub records for the file."""
    v = VENDORS[image_id]
    if not v.fetch:
        raise NetOsError(f"winlab cannot fetch {v.short}. {v.get}: {v.page}, then: winlab images import "
                         f"{image_id} <file>")
    try:
        if image_id == "chr":
            text = get(CHR_NEWEST).decode("utf-8", "replace").split()
            if not text or not re.fullmatch(r"7\.\d+(?:\.\d+)?", text[0]):
                raise NetOsError(f"{CHR_NEWEST} did not name a RouterOS 7 release")
            ver = text[0]
            return CHR_URL.format(v=ver), f"chr-{ver}.img.zip", "", ver
        rel = json.loads(get(VYOS_API).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise NetOsError(str(exc)) from exc
    except ValueError as exc:
        raise NetOsError(f"GitHub's answer about VyOS's releases did not read ({exc})") from exc
    for a in rel.get("assets") or []:
        if VYOS_ISO.match(str(a.get("name", ""))):
            digest = str(a.get("digest") or "")
            if not digest.startswith("sha256:"):
                raise NetOsError(f"GitHub records no SHA-256 for {a['name']}: download it yourself from "
                                 f"{v.page} and import it: winlab images import vyos <file>")
            return a["browser_download_url"], a["name"], digest.split(":", 1)[1].lower(), str(rel.get("tag_name", ""))
    raise NetOsError(f"VyOS's latest rolling release ({rel.get('tag_name', '?')}) has no generic amd64 ISO")


def _convert(src: Path, dest: Path, fmt: str = "") -> Path:
    """The vendor's disk, whatever its format (raw, VMDK, VDI, VHDX,
    qcow2), as a qcow2 the machines are thin clones of; through dest.part,
    so a failed run never looks like an image."""
    from . import images
    part = dest.with_name(dest.name + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)
    part.unlink(missing_ok=True)
    images._run_img(["convert", "-p"] + (["-f", fmt] if fmt else []) + ["-O", "qcow2", str(src), str(part)])
    part.replace(dest)
    return dest


def _unzip(src: Path, workdir: Path) -> Path:
    """The disk image inside a vendor's .zip (MikroTik ships chr-<v>.img.zip),
    its CRCs checked on the way."""
    try:
        with zipfile.ZipFile(src) as z:
            bad = z.testzip()
            if bad:
                raise NetOsError(f"{src.name} is damaged ({bad} fails its CRC): download it again")
            disks = [n for n in z.namelist() if n.lower().endswith((".img", ".vmdk", ".vdi", ".vhdx", ".qcow2"))]
            if len(disks) != 1:
                raise NetOsError(f"{src.name} holds {len(disks)} disk images; expected one")
            name = Path(disks[0]).name
            workdir.mkdir(parents=True, exist_ok=True)
            out = workdir / name
            with z.open(disks[0]) as fi, out.open("wb") as fo:
                while True:
                    buf = fi.read(8 << 20)
                    if not buf:
                        break
                    fo.write(buf)
            return out
    except zipfile.BadZipFile as exc:
        raise NetOsError(f"{src.name} is not a zip archive ({exc}): is the download complete?") from exc


def _record(image_id: str, **fields) -> None:
    from . import images
    p = images.base_meta_path(image_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"kind": KIND, **fields}, indent=2), encoding="utf-8")


def meta(image_id: str) -> dict:
    from . import images
    return images.base_meta(image_id)


def fetch(image_id: str, progress=None, get=_get, download=_download_to, convert=_convert) -> Path:
    """The vendor's image onto this PC: RouterOS CHR unzipped and turned
    into the base its machines clone; the VyOS ISO verified against the
    SHA-256 GitHub records and kept where its machines boot it."""
    from . import images, paths
    v = VENDORS[image_id]
    say = progress or (lambda m: print(f"  {m}", file=sys.stderr))
    if v.fetch:
        say(f"asking {v.publisher} for the newest {v.short}")
    url, name, sha, version = resolve(image_id, get)
    if v.form == INSTALLER:
        dest = images.installer_path(image_id)
        say(f"fetching {v.short} {version}: {name}, about {v.size_gb:g} GB (verified against {sha[:12]}…)")
        try:
            download(url, dest, expect_sha=sha, label=f"{v.short} {version}")
        except BootstrapError as exc:
            raise NetOsError(str(exc)) from exc
        images._write_installer_meta(image_id, name=name, version=version, sha256=sha, source=url,
                                     size=dest.stat().st_size, fetched=time.strftime("%Y-%m-%d"),
                                     holds=f"{v.short} {version}")
        say(f"{v.short} {version} ready: {dest}")
        return dest
    arch = paths.downloads_dir() / name
    say(f"fetching {v.short} {version}: {name} from {url.split('/')[2]}")
    try:
        download(url, arch, expect_sha="", label=f"{v.short} {version}")
    except BootstrapError as exc:
        raise NetOsError(str(exc)) from exc
    got_sha = _sha256(arch)
    work = paths.downloads_dir() / f"{image_id}.unpack"
    try:
        disk = _unzip(arch, work)
        say(f"converting {disk.name} into the base its machines clone")
        dest = convert(disk, images.base_path(image_id), "raw" if disk.suffix.lower() == ".img" else "")
    finally:
        for f in work.glob("*"):
            f.unlink(missing_ok=True)
        if work.exists():
            work.rmdir()
        arch.unlink(missing_ok=True)
    _record(image_id, name=name, version=version, source=url, sha256=got_sha, fetched=time.strftime("%Y-%m-%d"),
            holds=f"{v.short} {version}",
            note=(f"MikroTik publishes no checksum file: the archive's CRCs were checked, and its SHA-256 is "
                  f"{got_sha}; compare it with the one on MikroTik's download page" if image_id == "chr" else ""))
    say(f"{v.short} {version} ready (SHA-256 of the download {got_sha[:16]}…)")
    return dest


# ------------------------------------------------------------ recognition
def label_of(path: str | Path) -> str:
    from . import iso9660
    try:
        with iso9660.Iso(path) as iso:
            return iso.volume_id().strip()
    except (iso9660.IsoError, OSError):
        return ""


def is_aboot(path: str | Path) -> bool:
    """Arista's Aboot boot-loader ISO, which some vEOS-lab releases boot through."""
    p = Path(path)
    return p.suffix.lower() == ".iso" and bool(re.match(r"(?i)^aboot", p.name) or re.search(r"(?i)aboot", label_of(p)))


def detect(path: str | Path) -> str:
    """Which vendor's image this is, by the file name the vendor gives it
    (an ISO also by its volume label); '' when neither says."""
    p = Path(path)
    for v in VENDORS.values():
        if any(re.match(r, p.name) for r in v.names):
            return v.id
    if p.suffix.lower() == ".iso":
        label = label_of(p)
        for v in VENDORS.values():
            if label and any(re.search(r, label) for r in v.labels):
                return v.id
    return ""


def which(src: Path) -> str:
    found = detect(src)
    if not found:
        raise NetOsError(f"{src.name} is not a router image winlab recognises; import it by name: winlab "
                         f"images import {'|'.join(VENDORS)} <file>")
    return found


def import_file(image_id: str, src: Path, progress=None, convert=_convert) -> Path:
    """An image the user downloaded from the vendor: the VyOS ISO or
    Arista's Aboot ISO copied to where the machine boots it, a disk image
    (zipped or not, any format qemu-img reads) turned into the base the
    machines clone. The other vendor's file is refused, naming it."""
    from . import images
    v = VENDORS[image_id]
    say = progress or (lambda m: print(f"  {m}", file=sys.stderr))
    found = detect(src)
    if found and found != image_id:
        raise NetOsError(f"{src.name} is {VENDORS[found].short}, not {v.short}: import it as {found} "
                         f"(or as {AUTO}, which reads the name)")
    low = src.name.lower()
    if not low.endswith(FILE_TYPES):
        raise NetOsError(f"{src.name}: expected one of {', '.join(FILE_TYPES)} for {v.short}")
    if src.suffix.lower() == ".iso":
        if v.form == INSTALLER or (image_id == "veos-lab" and is_aboot(src)):
            dest = images.installer_path(image_id)
            if not (dest.exists() and dest.samefile(src)):
                images.copy_with_progress(src, dest, progress, f"copying {src.name}")
            images._write_installer_meta(image_id, name=src.name, size=dest.stat().st_size, imported=True,
                                         fingerprint=images.fingerprint(dest),
                                         holds=label_of(dest) or src.name)
            return dest
        raise NetOsError(f"{src.name} is an ISO, and {v.short} comes as a disk image: download the disk "
                         f"image from {v.page}")
    if v.form == INSTALLER:
        raise NetOsError(f"{v.short} installs from its ISO: import the .iso")
    work = None
    disk = src
    if low.endswith(".zip"):
        from . import paths
        work = paths.downloads_dir() / f"{image_id}.unpack"
        disk = _unzip(src, work)
    try:
        say(f"converting {disk.name} into the base its machines clone")
        dest = convert(disk, images.base_path(image_id), "raw" if disk.suffix.lower() == ".img" else "")
    finally:
        if work is not None:
            for f in work.glob("*"):
                f.unlink(missing_ok=True)
            if work.exists():
                work.rmdir()
    _record(image_id, name=src.name, imported=True, holds=src.name, size=src.stat().st_size,
            fetched=time.strftime("%Y-%m-%d"))
    return dest


def ready(image_id: str) -> bool:
    """Its machines can be made: the base (a disk router) or the ISO (VyOS)."""
    from . import images
    v = VENDORS[image_id]
    return (images.installer_path(image_id) if v.form == INSTALLER else images.base_path(image_id)).exists()


def boot_disc(image_id: str) -> Path | None:
    """The disc a disk router boots first: Arista's Aboot ISO, when imported."""
    from . import images
    if image_id != "veos-lab":
        return None
    p = images.installer_path(image_id)
    return p if p.exists() else None


# ------------------------------------------------------------ the machine
def missing_text(image_id: str) -> str:
    v = VENDORS[image_id]
    if v.fetch:
        return (f"{v.short} is not on this PC; fetch it in Setup > Vendor routers and firewalls (from {v.publisher}, about "
                f"{v.size_gb:g} GB) or import one you have. Or: winlab images fetch {image_id}")
    return (f"{v.short} is not on this PC. {v.get}. Then import it in Setup > Vendor routers and firewalls, or: winlab "
            f"images import {image_id} <file>")


def check_media(image_id: str) -> None:
    if not ready(image_id):
        raise NetOsError(missing_text(image_id))


def boot_hint(image_id: str) -> str:
    """What the student sees at power-on, for the machine's panel."""
    v = VENDORS[image_id]
    ports = ", ".join(port_names(image_id, 3))
    start = ("It boots the live system from the DVD on its empty disk. " if v.form == INSTALLER
             else f"It boots {v.short} from its own disk. ")
    web = f" Its web UI, {v.web[0]}, opens from a lab PC's browser on its address." if v.web else (
        " It has no web UI: everything is on its CLI.")
    return (f"{start}Its cards are {ports} … in port order. Sign in on the Terminal window or its screen as "
            f"{v.login}. {v.defaults[0].upper() + v.defaults[1:]}.{web} Free use: {v.limits}.")


def prepare_node(node, lab_workbench: bool = True) -> None:
    """A new vendor router's hardware: the memory and processors the
    vendor documents, the cards it is cabled with, an installer's disk."""
    from .model import Nic
    v = VENDORS[node.image]
    node.memory_mb = v.memory_mb
    node.cpus = v.cpus
    if v.form == INSTALLER:
        node.vars.setdefault("disk_gb", v.disk_gb)
    while lab_workbench and len(node.nics) < v.nics:
        node.nics.append(Nic(network=""))


def os_title(node) -> str:
    return VENDORS[node.image].short


def is_vendor_firewall(node) -> bool:
    """A firewall maker's own OS (FortiGate-VM, PA-VM): the shelf's Other vendors."""
    return is_router(node) and VENDORS[node.image].role == "firewall"


def imported_firewalls() -> list[str]:
    """The firewall makers' images on this PC: Other vendors appears on
    the shelf only when there is one."""
    return [i for i in FIREWALLS if ready(i)]


# --------------------------------------------------------------- setup
def setup_rows(lab) -> list[dict]:
    """Setup's vendor routers: on this PC or not, fetched or import only,
    and which of this lab's machines run each."""
    rows = []
    for v in VENDORS.values():
        m = meta(v.id)
        who = [n.id for n in lab.node_list() if is_router(n) and n.image == v.id]
        have = ready(v.id)
        aboot = boot_disc(v.id) is not None
        rows.append({"image": v.id, "title": v.title, "short": v.short, "publisher": v.publisher,
                     "page": v.page, "fetch": v.fetch, "get": v.get, "size_gb": v.size_gb, "license": v.license,
                     "limits": v.limits, "nested": v.nested, "memory_mb": v.memory_mb,
                     "ready": have, "aboot": aboot, "holds": str(m.get("holds") or ""),
                     "note": str(m.get("note") or ""), "who": who, "needed": bool(who) and not have})
    return rows


def setup_steps(lab) -> list[dict]:
    """Get-ready steps for the vendor images this lab's routers run:
    CHR and VyOS fetched, the rest imported from the user's own download."""
    out = []
    for r in setup_rows(lab):
        if not r["who"]:
            continue
        who = f"{', '.join(r['who'])} run{'s' if len(r['who']) == 1 else ''} it"
        if r["fetch"]:
            out.append({"id": f"netos-{r['image']}", "label": f"Fetch {r['short']} ({r['publisher']})",
                        "done": r["ready"], "blocked": False, "image": r["image"], "link": r["page"],
                        "job": "netos-fetch", "hint": f"{who}: the vendor's own image, about {r['size_gb']:g} GB once"})
        else:
            out.append({"id": f"netos-{r['image']}", "label": f"Import the {r['short']} image you downloaded",
                        "done": r["ready"], "blocked": not r["ready"], "image": r["image"], "link": r["page"],
                        "job": "import", "hint": f"{who}. {r['get']}"})
    return out


def find_downloads(dirs: list[Path] | None = None) -> list[dict]:
    """Vendor router files in the folders a download lands in, by the name
    each vendor gives them, newest first."""
    from . import readiness
    seen: list[Path] = []
    for d in (readiness.search_dirs() if dirs is None else dirs):
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_file() and e not in seen and any(re.match(r, e.name) for v in VENDORS.values() for r in v.names):
                seen.append(e)
    seen.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [{"path": str(p), "name": p.name, "folder": str(p.parent), "fits": [detect(p)],
             "size_gb": round(p.stat().st_size / 1024 ** 3, 2)} for p in seen[:20]]


# ---- each one's web UI, opened from a lab PC's browser (winlab/adminui.py)
def _admin_gui(lab, node):
    v = vendor_of(node)
    if v is None or not v.web:
        return None
    from .adminui import AdminGui
    software, scheme, port, path, note = v.web
    return AdminGui(software=software, scheme=scheme, port=port, path=path, sign_in=v.login,
                    license=v.license.split(";")[0], note=note)


def _register() -> None:
    from . import adminui
    adminui.register(node_gui=_admin_gui)


_register()
