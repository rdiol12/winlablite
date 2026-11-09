"""An Android phone or tablet for the lab: Android-x86, installed by hand.

CompTIA A+ asks about phones and tablets (Settings, accounts, screen locks,
app installs, mobile device management, remote wipe) and MD-102 about
enrolling them in an MDM. winlab's machines are QEMU PCs, so the device is
the Android Open Source Project built for PCs by the Android-x86 project:
the student boots its installer on an empty disk, installs it, and then
works on Android's own screen (Settings, the launcher, Developer options),
and from a lab Linux machine with adb over the lab network. winlab runs
nothing inside it and shows nothing it does not do.

Which build, and why. Android-x86 9.0-r2 (Android 9, kernel 4.19, 2020) is
the project's last stable release. It is the AOSP with no Google apps or
services in it, so every part is under a free licence (Apache-2.0 for AOSP
and Android-x86's own code, GPL-2.0 for the kernel, MIT for Mesa) apart
from the redistributable binary firmware files of linux-firmware. ARM
translation (Intel's libhoudini) is not in the image: its "native bridge"
option downloads it from the internet, which the lab does not have, and
winlab never fetches it. BlissOS (Android 11 to 13 for PCs) was weighed:
its FOSS builds carry extra app stores and microG, and its GApps builds
Google's proprietary apps; its Vanilla folders on SourceForge are empty,
and the FOSS set's licences could not be listed one by one here, so it is
not the lab's phone. Android 9 gets no security updates any more: the lab
is isolated (no internet, no host forwards), and the lessons say so.

How it is fetched. The project publishes its ISO on SourceForge; the
listing there gives each file's SHA-256 (the release note gives SHA-1s).
winlab pins that SHA-256, checked against a full download on 2026-11-07,
and fetches the ISO onto this PC; nothing is bundled.

The machine is a regular PC that Android-x86's kernel drives out of the
box: legacy BIOS (its installer's GRUB on an MBR disk, the best-trodden
path), an Intel e1000 network card (eth0, DHCP from the lab), a SATA disk
and DVD drive, a standard VGA screen (Mesa's software renderer draws it),
the USB tablet as its pointer. Its adb daemon answers on the lab network
(TCP 5555 once USB debugging is on), so only machines in the lab reach it.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import BootstrapError, _download_to

# The catalog kind of an Android installer (images.CATALOG).
KIND = "android-installer"
# `winlab images import android <iso>`: which build is read off the disc.
AUTO = "android"
NIC_MODEL = "e1000"
DISK_GB = 16
ADB_PORT = 5555
# The Headwind MDM launcher's device-owner receiver (winlab/hmdm.py).
LAUNCHER = "com.hmdm.launcher"


class AndroidError(Exception):
    pass


@dataclass(frozen=True)
class Build:
    id: str
    title: str
    short: str
    publisher: str
    page: str
    license: str
    url: str
    file: str
    sha256: str
    size: int
    checksum: str        # where the pinned SHA-256 comes from
    labels: tuple[str, ...]
    names: tuple[str, ...]
    android: str         # the Android release it is
    memory_mb: int = 2048
    firmware: str = "bios"


BUILDS: dict[str, Build] = {b.id: b for b in (
    Build(
        id="android-x86-9", title="Android-x86 9.0-r2 (64-bit installer ISO)", short="Android-x86 9.0-r2",
        publisher="the Android-x86 project",
        page="https://www.android-x86.org/releases/releasenote-9-0-r2.html",
        license=("Apache-2.0 for the Android Open Source Project and Android-x86's own code, GPL-2.0 for the "
                 "Linux kernel, MIT for Mesa, each other part under its own free licence; the linux-firmware "
                 "files are redistributable binary firmware under their makers' terms. No Google apps or "
                 "services are in it, and ARM translation (libhoudini) is not: winlab never fetches it. "
                 "Android is a trademark of Google LLC; Android-x86 is an independent project"),
        url="https://sourceforge.net/projects/android-x86/files/Release%209.0/android-x86_64-9.0-r2.iso/download",
        file="android-x86_64-9.0-r2.iso",
        sha256="f7eb8fc56f29ad5432335dc054183acf086c539f3990f0b6e9ff58bd6df4604e",
        size=965738496,
        checksum="the SHA-256 SourceForge's file listing for the project gives (the release note gives SHA-1)",
        labels=(r"^Android-x86 9\.0-r2 \(x86_64\)$",),
        names=(r"^android-x86_64-9\.0-r2\.iso$",),
        android="Android 9 (API 28)"),
)}


def is_image(image_id: str) -> bool:
    return image_id in BUILDS


def is_hand_android(node) -> bool:
    """A machine that boots an Android-x86 installer on an empty disk."""
    return getattr(node, "kind", "") == "custom" and getattr(node, "image", "") in BUILDS


def uefi(node) -> bool:
    return BUILDS[node.image].firmware == "uefi"


# ------------------------------------------------------------ fetching
def fetch(build_id: str, progress=None, download=_download_to) -> Path:
    """The installer ISO onto this PC from the project's SourceForge files,
    verified against the pinned SHA-256, recorded beside it."""
    from . import images
    b = BUILDS[build_id]
    say = progress or (lambda m: print(f"  {m}", file=sys.stderr))
    dest = images.installer_path(build_id)
    say(f"fetching {b.short} from {b.publisher}'s SourceForge files: {b.file}, about "
        f"{b.size / 1024 ** 3:.1f} GB (verified against {b.sha256[:12]}…)")
    try:
        download(b.url, dest, expect_sha=b.sha256, label=b.short)
    except BootstrapError as exc:
        raise AndroidError(str(exc)) from exc
    images._write_installer_meta(build_id, name=b.file, size=dest.stat().st_size, sha256=b.sha256,
                                 source=b.url, fetched=time.strftime("%Y-%m-%d"), holds=b.short,
                                 checksum=b.checksum)
    say(f"{b.short} installer ready: {dest}")
    return dest


# ------------------------------------------------------------ recognition
def label_of(path: str | Path) -> str:
    from . import iso9660
    try:
        with iso9660.Iso(path) as iso:
            return iso.volume_id().strip()
    except (iso9660.IsoError, OSError):
        return ""


def detect(path: str | Path) -> str:
    """Which build this disc is, by its volume label, then by the file name
    the project gives it; '' when neither says."""
    p = Path(path)
    label = label_of(p) if p.suffix.lower() == ".iso" else ""
    for b in BUILDS.values():
        if label and any(re.search(r, label) for r in b.labels):
            return b.id
    for b in BUILDS.values():
        if any(re.match(r, p.name) for r in b.names):
            return b.id
    return ""


def check_import(build_id: str, src: Path) -> str:
    """Refuses another build's disc and a 32-bit one; a warning when the disc
    cannot be told apart, else ''."""
    b = BUILDS[build_id]
    label = label_of(src)
    if re.search(r"Android-x86 .*\(x86\)$", label) or re.match(r"(?i)^android-x86-\d", src.name):
        raise AndroidError(f"{src.name} is the 32-bit Android-x86 ({label or src.name}); the lab's device is "
                           f"the 64-bit build, {b.file}")
    found = detect(src)
    if found and found != build_id:
        raise AndroidError(f"{src.name} is {BUILDS[found].short}, not {b.short}")
    if not found:
        return (f"winlab cannot tell from its label ({label or 'none'}) or name that {src.name} is "
                f"{b.short}; it is imported as you asked")
    return ""


def which(src: Path) -> str:
    found = detect(src)
    if not found:
        raise AndroidError(f"{src.name} is not an Android installer winlab knows ({label_of(src) or 'no label'}); "
                           f"the lab's device is {', '.join(b.file for b in BUILDS.values())}")
    return found


def import_file(build_id: str, src: Path, progress=None) -> Path:
    """An ISO the user already has: checked, copied in, recorded."""
    from . import images
    warn = check_import(build_id, src)
    if warn:
        print(f"  note: {warn}", file=sys.stderr)
        if progress:
            progress(f"note: {warn}")
    dest = images.installer_path(build_id)
    if not (dest.exists() and dest.samefile(src)):
        images.copy_with_progress(src, dest, progress, f"copying {src.name}")
    images._write_installer_meta(build_id, name=src.name, size=dest.stat().st_size, imported=True,
                                 fingerprint=images.fingerprint(dest), note=warn,
                                 holds=label_of(dest) or src.name)
    return dest


# ------------------------------------------------------------ the machine
def missing_text(build_id: str) -> str:
    b = BUILDS[build_id]
    return (f"the {b.short} installer is not on this PC; fetch it in Setup (from {b.publisher}'s "
            f"SourceForge files, about {b.size / 1024 ** 3:.1f} GB) or: winlab images fetch {build_id}")


def boot_hint(build_id: str) -> str:
    """What the student sees at power-on, for the machine's panel."""
    b = BUILDS[build_id]
    return (f"Power it on and open its screen: the BIOS finds nothing on the empty disk and boots the "
            f"{b.short} disc, whose menu offers Live CD and Installation. Install it to the disk "
            f"(a new MBR partition, ext4, GRUB), then it starts {b.android}. Its network card is eth0, "
            f"addressed by DHCP; the lab has no internet and no Google services. With USB debugging on, "
            f"adb reaches it from a lab Linux machine on TCP {ADB_PORT}.")


def prepare_node(node) -> None:
    """A new device's hardware: the memory Android 9 wants and a phone-sized disk."""
    node.memory_mb = BUILDS[node.image].memory_mb
    node.cpus = max(1, min(node.cpus or 2, 2))
    node.vars.setdefault("disk_gb", DISK_GB)


# --------------------------------------------------------------- setup
def setup_steps(lab) -> list[dict]:
    """Get-ready steps for the installers this lab's devices boot: fetched
    like an appliance image (the job images.fetch runs)."""
    from . import images
    out = []
    for b in BUILDS.values():
        who = [n.id for n in lab.node_list() if is_hand_android(n) and n.image == b.id]
        if not who:
            continue
        out.append({"id": f"androidiso-{b.id}", "label": f"Fetch the {b.short} installer ({b.publisher})",
                    "done": images.installer_path(b.id).exists(), "blocked": False, "image": b.id,
                    "link": b.page, "job": "appliance-fetch",
                    "hint": f"{', '.join(who)} boot{'s' if len(who) == 1 else ''} it and you install by hand: "
                            f"the project's own ISO, checked against the pinned SHA-256, about "
                            f"{b.size / 1024 ** 3:.1f} GB once"})
    return out
