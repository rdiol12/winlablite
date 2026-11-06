"""A firewall installed by hand: OPNsense or pfSense CE from the project's
own installer image, on a regular PC the student cables WAN and LAN.

The shelf's Firewall can be the ready-made OPNsense appliance
(winlab/opnsense.py, configured from the lab file) or, like a Windows or
Linux machine installed by hand (winlab/linuxiso.py), an empty disk with
the firewall's installer in the drive: the student boots it, runs the
installer, assigns the interfaces on the console and finishes the setup in
the web GUI from a lab PC's browser. winlab runs nothing inside it.

The installer is the project's, never ours. OPNsense publishes its DVD
image on its own mirror with a SHA-256 checksum file per release, so winlab
fetches the newest one onto this PC, verifies it and unpacks it (bzip2).
pfSense CE is only handed out by Netgate behind a store account (a $0
checkout), and its current download is the online Netgate Installer, so
winlab cannot fetch it: the user downloads it and imports it (an ISO, or
its .iso.gz as Netgate ships it). The Netgate Installer downloads pfSense
from Netgate during the install, which the isolated lab cannot reach: the
import says so, and an offline CE image (pfSense-CE-<version>-RELEASE-amd64.iso)
is what installs here.

The machine is a regular PC both BSDs drive out of the box: Intel e1000
network cards (em0, em1 ...), a SATA (AHCI) disk and DVD drive, a VGA
screen and a serial port (COM1, FreeBSD's ttyu0) on the Terminal window;
UEFI for OPNsense, legacy BIOS for pfSense CE, as each installer boots.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import BootstrapError, _download_to, _get

# The catalog kind of a firewall installer (images.CATALOG).
KIND = "firewall-installer"
# `winlab images import firewall <file>`: which firewall is read off the disc.
AUTO = "firewall"
DISK_GB = 16
NIC_MODEL = "e1000"


class BsdFwError(Exception):
    pass


@dataclass(frozen=True)
class Firewall:
    id: str
    title: str
    short: str
    publisher: str
    page: str            # where a person gets it
    license: str
    size_gb: float       # about what the download is
    firmware: str        # "uefi" or "bios": how its installer boots on this PC
    memory_mb: int
    labels: tuple[str, ...]   # volume labels (regexes) the project's images carry
    names: tuple[str, ...]    # file names (regexes) the project gives them
    folder: str = ""     # the mirror directory, when winlab can fetch it
    pattern: str = ""    # the archive's name in the listing, one group: the version
    sums: str = ""       # the release's checksum file ("{version}")
    get: str = ""        # how a person gets it when winlab cannot
    defaults: str = ""   # what a fresh install does, for the lesson and the panel


FIREWALLS: dict[str, Firewall] = {f.id: f for f in (
    Firewall(
        id="opnsense-dvd", title="OPNsense installer (DVD image)", short="OPNsense",
        publisher="the OPNsense project (Deciso B.V.)", page="https://opnsense.org/download/",
        license=("BSD 2-Clause (OPNsense), the FreeBSD base and packages under their own free licences; "
                 "the project publishes the image for anyone to download. \"OPNsense\" is a registered "
                 "trademark of Deciso B.V."),
        size_gb=0.5, firmware="uefi", memory_mb=2048,
        labels=(r"(?i)^opnsense",), names=(r"(?i)^OPNsense-[\d.]+-dvd-amd64\.iso(?:\.bz2)?$",),
        folder="https://pkg.opnsense.org/releases/mirror/",
        pattern=r"OPNsense-(\d+\.\d+(?:\.\d+)?)-dvd-amd64\.iso\.bz2",
        sums="OPNsense-{version}-checksums-amd64.sha256",
        defaults=("the live system boots first: log in as installer (the password is the product's name in lower case) to install; "
                  "LAN 192.168.1.1/24 with DHCP, WAN by DHCP, the GUI at https://192.168.1.1")),
    Firewall(
        id="pfsense-ce", title="pfSense CE installer (your download from Netgate)", short="pfSense CE",
        publisher="Netgate", page="https://www.pfsense.org/download/",
        license=("Apache License 2.0 (pfSense CE), the FreeBSD base and packages under their own free "
                 "licences. \"pfSense\" is a registered trademark of Electric Sheep Fencing LLC (Netgate)"),
        size_gb=0.8, firmware="bios", memory_mb=1024,
        labels=(r"(?i)^pfsense", r"(?i)netgate"),
        names=(r"(?i)^pfSense-CE-.*amd64.*\.iso(?:\.gz)?$", r"(?i)^netgate-installer.*\.iso(?:\.gz)?$"),
        get=("Netgate hands pfSense CE out only through its store (an account and a $0 checkout); winlab "
             "cannot fetch it. Download the AMD64 ISO yourself and import it here. The current download is "
             "the online Netgate Installer, which fetches pfSense from Netgate during the install: the lab "
             "has no internet, so use an offline CE image (pfSense-CE-<version>-RELEASE-amd64.iso) if you "
             "have one"),
        defaults=("the installer asks for the interfaces at the first boot: WAN em0 by DHCP, LAN em1 "
                  "192.168.1.1/24 with DHCP, the GUI at https://192.168.1.1 (admin; the password is the product's name in lower case)")),
)}


def is_image(image_id: str) -> bool:
    return image_id in FIREWALLS


def is_hand_firewall(node) -> bool:
    """A machine that boots a firewall installer on an empty disk."""
    return node.kind == "custom" and node.image in FIREWALLS


def uefi(node) -> bool:
    return FIREWALLS[node.image].firmware == "uefi"


# ------------------------------------------------------------ fetching
def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def resolve(fw_id: str, get=_get) -> tuple[str, str, str, str]:
    """(url, file, sha256, version) of the newest installer on the project's
    mirror, the SHA-256 read off that release's own checksum file."""
    from .linuxiso import parse_sums
    f = FIREWALLS[fw_id]
    if not f.folder:
        raise BsdFwError(f"winlab cannot fetch {f.short}. {f.get}: {f.page}, then "
                         f"winlab images import {fw_id} <file>")
    try:
        listing = get(f.folder).decode("utf-8", "replace")
        found = {m.group(1): m.group(0) for m in re.finditer(f.pattern, listing)}
        if not found:
            raise BsdFwError(f"{f.folder} lists no {f.short} installer image")
        version = max(found, key=_vkey)
        name = found[version]
        sums = parse_sums(get(f.folder + f.sums.format(version=version)).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise BsdFwError(str(exc)) from exc
    if name not in sums:
        raise BsdFwError(f"{f.sums.format(version=version)} does not list {name}: download it yourself "
                         f"from {f.page} and import it: winlab images import {AUTO} <file>")
    return f.folder + name, name, sums[name], version


def unpack(src: Path, dest: Path, progress=None) -> Path:
    """The installer as a plain image at dest: a .bz2 or .gz unpacked (the
    way the projects ship them), anything else copied; through dest.part,
    so a failed run never looks like an installer."""
    import bz2
    import gzip
    say = progress or (lambda _m: None)
    opener = {".bz2": bz2.open, ".gz": gzip.open}.get(src.suffix.lower())
    dest.parent.mkdir(parents=True, exist_ok=True)
    if opener is None:
        from .images import copy_with_progress
        return copy_with_progress(src, dest, progress, f"copying {src.name}")
    part = dest.with_name(dest.name + ".part")
    done = 0
    try:
        with opener(src, "rb") as fi, part.open("wb") as fo:
            while True:
                buf = fi.read(8 << 20)
                if not buf:
                    break
                fo.write(buf)
                done += len(buf)
                if done % (256 << 20) < (8 << 20):
                    say(f"unpacking {src.name}: {done >> 20} MB")
    except (OSError, EOFError) as exc:
        part.unlink(missing_ok=True)
        raise BsdFwError(f"{src.name} does not unpack ({exc}): is the download complete?") from exc
    part.replace(dest)
    say(f"unpacked {src.name}: {done >> 20} MB")
    return dest


def fetch(fw_id: str, progress=None, get=_get, download=_download_to) -> Path:
    """The installer onto this PC: downloaded from the project's mirror,
    verified against its SHA-256, unpacked, and recorded beside it."""
    from . import images, paths
    f = FIREWALLS[fw_id]
    say = progress or (lambda m: print(f"  {m}", file=sys.stderr))
    if f.folder:
        say(f"reading {f.publisher}'s mirror ({f.folder})")
    url, name, sha, version = resolve(fw_id, get)
    arch = paths.downloads_dir() / name
    say(f"fetching {f.short} {version}: {name}, about {f.size_gb:g} GB (verified against {sha[:12]}…)")
    try:
        download(url, arch, expect_sha=sha, label=f"{f.short} {version}")
    except BootstrapError as exc:
        raise BsdFwError(str(exc)) from exc
    dest = images.installer_path(fw_id)
    unpack(arch, dest, say)
    arch.unlink(missing_ok=True)
    images._write_installer_meta(fw_id, name=name, version=version, sha256=sha, source=url,
                                 size=dest.stat().st_size, fetched=time.strftime("%Y-%m-%d"),
                                 holds=f"{f.short} {version}")
    say(f"{f.short} {version} installer ready: {dest}")
    return dest


# ------------------------------------------------------------ recognition
def label_of(path: str | Path) -> str:
    """The ISO 9660 volume label ('' for a compressed or unreadable file)."""
    from . import iso9660
    try:
        with iso9660.Iso(path) as iso:
            return iso.volume_id().strip()
    except (iso9660.IsoError, OSError):
        return ""


def detect(path: str | Path) -> str:
    """Which firewall's installer this is, by its volume label, then by the
    file name the project gives it; '' when neither says."""
    p = Path(path)
    label = label_of(p) if p.suffix.lower() == ".iso" else ""
    for f in FIREWALLS.values():
        if label and any(re.search(r, label) for r in f.labels):
            return f.id
    for f in FIREWALLS.values():
        if any(re.match(r, p.name) for r in f.names):
            return f.id
    return ""


def online_installer(path: str | Path) -> bool:
    """Netgate's online installer, which needs Netgate's servers to install."""
    p = Path(path)
    return bool(re.match(r"(?i)^netgate-installer", p.name) or re.search(r"(?i)netgate", label_of(p)))


def check_import(fw_id: str, src: Path) -> str:
    """Refuses the other firewall's installer and a Linux DVD; returns a
    warning for an image the lab cannot install from, else ''."""
    from . import linuxiso
    f = FIREWALLS[fw_id]
    found = detect(src)
    if found and found != fw_id:
        raise BsdFwError(f"{src.name} is the {FIREWALLS[found].short} installer, not {f.short}: "
                         f"import it as {found} (or as {AUTO}, which reads the disc)")
    if linuxiso.detect(src):
        raise BsdFwError(f"{src.name} is a Linux DVD ({linuxiso.DISTROS[linuxiso.detect(src)].short}): "
                         f"import it as linux")
    if src.suffix.lower() == ".img" or src.name.lower().endswith((".img.gz", ".img.bz2")):
        raise BsdFwError(f"{src.name} is a memstick (USB) image; the machine boots the ISO: download "
                         f"the DVD/ISO image of {f.short} instead")
    if fw_id == "pfsense-ce" and online_installer(src):
        return ("this is Netgate's online installer: it downloads pfSense from Netgate during the "
                "install, and the lab has no internet, so it stops there; an offline CE image "
                "(pfSense-CE-<version>-RELEASE-amd64.iso) installs")
    if not found:
        return (f"winlab cannot tell from its label or name that {src.name} is {f.short}; it is "
                "imported as you asked")
    return ""


def which(src: Path) -> str:
    found = detect(src)
    if not found:
        raise BsdFwError(f"{src.name} is not an installer winlab recognises ({label_of(src) or 'no label'}); "
                         f"import it by name: winlab images import opnsense-dvd|pfsense-ce <file>")
    return found


def import_file(fw_id: str, src: Path, progress=None) -> Path:
    """An installer the user downloaded: checked, unpacked if it came
    compressed, and recorded like a fetched one."""
    from . import images
    warn = check_import(fw_id, src)
    if warn:
        print(f"  note: {warn}", file=sys.stderr)
        if progress:
            progress(f"note: {warn}")
    dest = images.installer_path(fw_id)
    if not (dest.exists() and dest.samefile(src)):
        unpack(src, dest, progress)
    images._write_installer_meta(fw_id, name=src.name, size=dest.stat().st_size, imported=True,
                                 fingerprint=images.fingerprint(dest), note=warn,
                                 holds=label_of(dest) or src.name)
    return dest


# ------------------------------------------------------------ the machine
def missing_text(fw_id: str) -> str:
    f = FIREWALLS[fw_id]
    if f.folder:
        return (f"the {f.short} installer is not on this PC; fetch it in Setup (from {f.publisher}'s "
                f"mirror, about {f.size_gb:g} GB) or import one you have. Or: winlab images fetch {fw_id}")
    return (f"the {f.short} installer is not on this PC. {f.get}. Then import it in Setup > Firewall "
            f"installers, or: winlab images import {fw_id} <file>")


def boot_hint(fw_id: str) -> str:
    """What the student sees at power-on, for the machine's panel."""
    f = FIREWALLS[fw_id]
    boot = "UEFI" if f.firmware == "uefi" else "the BIOS"
    return (f"Power it on and open its screen: {boot} finds nothing on the empty disk and boots the "
            f"installer. Its cards are em0, em1 ... in port order; cable WAN and LAN, then assign them "
            f"on the console. {f.defaults[0].upper() + f.defaults[1:]}. The serial console (COM1) is "
            f"on its Terminal window too.")


def prepare_node(node) -> None:
    """A new hand-installed firewall's hardware: the memory its installer
    wants and a disk the size a firewall needs."""
    node.memory_mb = FIREWALLS[node.image].memory_mb
    node.cpus = max(1, min(node.cpus or 1, 2))
    node.vars.setdefault("disk_gb", DISK_GB)


# --------------------------------------------------------------- setup
def setup_rows(lab) -> list[dict]:
    """Setup's firewall installers: on this PC or not, fetchable or import
    only, and which of this lab's machines boot each."""
    from . import images
    rows = []
    for f in FIREWALLS.values():
        iso = images.installer_path(f.id)
        meta = images.installer_meta(f.id)
        who = [n.id for n in lab.node_list() if is_hand_firewall(n) and n.image == f.id]
        rows.append({"image": f.id, "title": f.title, "short": f.short, "publisher": f.publisher,
                     "page": f.page, "mirror": f.folder.split("/")[2] if f.folder else "",
                     "fetch": bool(f.folder), "get": f.get, "size_gb": f.size_gb, "license": f.license,
                     "iso": iso.exists(), "holds": str(meta.get("holds") or meta.get("name") or ""),
                     "note": str(meta.get("note") or ""), "who": who, "needed": bool(who) and not iso.exists()})
    return rows


def setup_steps(lab) -> list[dict]:
    """Get-ready steps for the installers this lab's firewalls boot: OPNsense
    fetched like a Linux DVD, pfSense CE imported like a Windows ISO."""
    out = []
    for r in setup_rows(lab):
        if not r["who"]:
            continue
        who = f"{', '.join(r['who'])} boot{'s' if len(r['who']) == 1 else ''} it and you install by hand"
        if r["fetch"]:
            out.append({"id": f"fwiso-{r['image']}", "label": f"Fetch the {r['short']} installer ({r['publisher']})",
                        "done": r["iso"], "blocked": False, "image": r["image"], "link": r["page"],
                        "job": "fwiso-fetch",
                        "hint": f"{who}: the project's own image, verified against its checksum file, "
                                f"about {r['size_gb']:g} GB once"})
        else:
            out.append({"id": f"fwiso-{r['image']}", "label": f"Import the {r['short']} installer you downloaded",
                        "done": r["iso"], "blocked": not r["iso"], "image": r["image"], "link": r["page"],
                        "job": "import", "hint": f"{who}. {r['get']}"})
    return out
