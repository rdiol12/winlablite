"""Linux installed by hand from the distribution's own installer DVD.

The shelf's Linux server can be a ready-made appliance (winlab/appliances.py)
or, like a Windows machine installed by hand, an empty disk with the
distribution's installer DVD in the drive: the student boots it and does the
whole install on the machine's screen (language, disks, users, packages).
winlab runs nothing inside it.

The ISO is the publisher's, never ours: winlab fetches it onto this PC from
the distribution's own mirror (a pinned release; the point release and its
SHA-256 come from the checksum file published beside it), or imports one the
user already has, recognised by its volume label, .disk/info or .treeinfo.
The lab has no internet, so every install here is a DVD-only install: the
full DVDs (Rocky, Debian DVD-1) carry a package repository, the Ubuntu
Server and Alpine discs install their own base system.

The machine is a regular PC: UEFI, Intel e1000e network card, SATA disk and
DVD drive; `hardware = "virtio"` gives it virtio devices instead, which
every one of these kernels drives out of the box.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import BootstrapError, _download_to, _get

# The catalog kind of an installer DVD (images.CATALOG): not a machine's own
# image and not a role's media; a hand-installed machine boots it.
KIND = "linux-installer"
# `winlab images import linux <iso>`: the distribution is read off the disc.
AUTO = "linux"


class LinuxIsoError(Exception):
    pass


@dataclass(frozen=True)
class Distro:
    id: str
    title: str
    short: str
    publisher: str
    folder: str          # the mirror directory the ISO and its checksum file are in
    sums: str            # the checksum file there; "{file}" in it: one per ISO
    pattern: str         # the ISO's file name (a regex); the newest match is fetched
    labels: tuple[str, ...]   # volume labels (regexes) the publisher's discs carry
    license: str
    page: str
    size_gb: float       # about what the download is
    memory_mb: int = 2048
    offline: str = ""    # what an install with no network gets
    repo: bool = False   # the disc carries a package repository
    get: str = ""        # how a person gets it when winlab cannot fetch it (no folder)
    virt: str = ""       # what the disc carries to make the machine a KVM host and make ISOs


# The Red Hat family's DVDs, 9: everything a KVM host needs is in AppStream.
RHEL9_VIRT = ("AppStream has qemu-kvm, libvirt, virt-install, virt-viewer, virt-manager (deprecated, kept "
              "for a desktop install), cockpit-machines and xorriso; genisoimage is gone since 9, "
              "xorriso -as mkisofs makes ISOs")

DISTROS: dict[str, Distro] = {d.id: d for d in (
    Distro(
        id="ubuntu24", title="Ubuntu Server 24.04 LTS (installer DVD)", short="Ubuntu Server 24.04",
        publisher="Canonical", folder="https://releases.ubuntu.com/24.04/", sums="SHA256SUMS",
        pattern=r"ubuntu-24\.04(?:\.\d+)?-live-server-amd64\.iso",
        labels=(r"^Ubuntu-Server 24\.04",),
        license=("free software under each package's own licence (Ubuntu's licence policy); Canonical "
                 "publishes the ISO for anyone to download. \"Ubuntu\" is Canonical's trademark"),
        page="https://ubuntu.com/download/server", size_gb=3.1,
        offline=("the installer says the mirror is unreachable and installs the base system from the "
                 "disc; packages beyond it (sssd, realmd) are not on it"),
        virt=("nothing for it: the live-server disc carries no QEMU or libvirt; xorriso is not on it either. "
              "A VM host on Ubuntu is the ready-made Ubuntu appliance with the kvm pack")),
    Distro(
        id="rocky9", title="Rocky Linux 9 (DVD)", short="Rocky Linux 9",
        publisher="the Rocky Enterprise Software Foundation",
        folder="https://download.rockylinux.org/pub/rocky/9/isos/x86_64/", sums="CHECKSUM",
        pattern=r"Rocky-9\.\d+-x86_64-dvd\.iso",
        labels=(r"^Rocky-9-\d+-x86_64-dvd",),
        license=("BSD-3-Clause for Rocky's own work, GPL and other free licences for the packages; "
                 "freely redistributable. \"Rocky Linux\" is the RESF's trademark"),
        page="https://rockylinux.org/download", size_gb=10.5,
        offline=("the DVD is a full repository (BaseOS and AppStream): Server with GUI, realmd, sssd, "
                 "adcli and the rest install from it with no network"), repo=True,
        virt=RHEL9_VIRT),
    Distro(
        id="rhel9", title="Red Hat Enterprise Linux 9 (DVD, your download)", short="RHEL 9",
        publisher="Red Hat", folder="", sums="",
        pattern=r"rhel-9\.\d+-x86_64-dvd\.iso",
        labels=(r"^RHEL-9-\d+-\d+-BaseOS-x86_64",),
        license=("GPL and other free licences for the packages; using it is governed by your own Red Hat "
                 "subscription (the no-cost Developer Subscription for Individuals covers personal and "
                 "development use). \"Red Hat\" and \"Red Hat Enterprise Linux\" are Red Hat, Inc.'s trademarks"),
        page="https://developers.redhat.com/products/rhel/download",
        size_gb=11.0,
        get=("Red Hat hands RHEL out only through its own site, behind a free Red Hat account (the no-cost "
             "Developer Subscription for Individuals); winlab cannot fetch it. Sign in there, download the "
             "x86_64 DVD ISO (the Binary DVD, not the Boot ISO, which needs a network the lab does not have) "
             "and import it here"),
        offline=("the DVD is a full repository (BaseOS and AppStream): Server with GUI, Cockpit, realmd, sssd "
                 "and the rest install from it with no network. With no internet the system cannot register "
                 "with Red Hat: it runs, only Red Hat's online update repositories stay out of reach"), repo=True,
        virt=RHEL9_VIRT),
    Distro(
        id="rhel10", title="Red Hat Enterprise Linux 10 (DVD, your download)", short="RHEL 10",
        publisher="Red Hat", folder="", sums="",
        pattern=r"rhel-10\.\d+-x86_64-dvd\.iso",
        labels=(r"^RHEL-10-\d+-\d+-BaseOS-x86_64",),
        license=("GPL and other free licences for the packages; using it is governed by your own Red Hat "
                 "subscription (the no-cost Developer Subscription for Individuals covers personal and "
                 "development use). \"Red Hat\" and \"Red Hat Enterprise Linux\" are Red Hat, Inc.'s trademarks"),
        page="https://developers.redhat.com/products/rhel/download",
        size_gb=8.5,
        get=("Red Hat hands RHEL out only through its own site, behind a free Red Hat account (the no-cost "
             "Developer Subscription for Individuals); winlab cannot fetch it. Sign in there, download the "
             "x86_64 DVD ISO (the Binary DVD, not the Boot ISO, which needs a network the lab does not have) "
             "and import it here"),
        offline=("the DVD is a full repository (BaseOS and AppStream): Server with GUI, Cockpit, realmd, sssd "
                 "and the rest install from it with no network. With no internet the system cannot register "
                 "with Red Hat: it runs, only Red Hat's online update repositories stay out of reach"), repo=True,
        virt=("AppStream has qemu-kvm, libvirt, virt-install, virt-viewer, cockpit-machines and xorriso; "
              "virt-manager is deprecated in RHEL 10 (Cockpit's Virtual machines page is its replacement) and "
              "genisoimage is gone, xorriso -as mkisofs makes ISOs")),
    Distro(
        id="debian13", title="Debian 13 (DVD-1)", short="Debian 13",
        publisher="the Debian project",
        folder="https://cdimage.debian.org/debian-cd/current/amd64/iso-dvd/", sums="SHA256SUMS",
        pattern=r"debian-13\.\d+\.\d+-amd64-DVD-1\.iso",
        labels=(r"^Debian 13\.\S+ (?:amd64|M-A)",),
        license="the Debian Free Software Guidelines: every package under its own free licence",
        page="https://www.debian.org/CD/http-ftp/", size_gb=3.9,
        offline=("DVD-1 is a repository of the most used packages; the netinst disc needs a mirror "
                 "the lab does not have, so it installs only a bare base system"), repo=True,
        virt=("DVD-1 holds the most used packages: qemu-system-x86, libvirt-daemon-system, virtinst, "
              "virt-manager (with a desktop) and xorriso should be on it; apt-cdrom add and apt install say "
              "what is not, and DVD-2 and later carry the rest")),
    Distro(
        id="alpine-std", title="Alpine Linux 3.22 standard", short="Alpine Linux 3.22",
        publisher="the Alpine Linux project",
        folder="https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/", sums="{file}.sha256",
        pattern=r"alpine-standard-3\.22\.\d+-x86_64\.iso",
        labels=(r"^alpine-(?:std|ext) 3\.22",),
        license="MIT for Alpine's own work, GPL and other free licences for the packages",
        page="https://alpinelinux.org/downloads/", size_gb=0.3, memory_mb=512,
        offline="setup-alpine installs a sys-mode disk from the packages on the disc", repo=True),
    # Proxmox: a Debian-based virtualization platform and its backup server,
    # both AGPL-3.0, both published for anyone to download at Proxmox's own
    # ISO folder with one SHA256SUMS file. Without a subscription they run
    # in full (the web UI only says so once per sign-in); the lab has no
    # internet, so their package repositories simply stay unreachable.
    Distro(
        id="proxmox-ve9", title="Proxmox Virtual Environment 9 (installer ISO)", short="Proxmox VE 9",
        publisher="Proxmox Server Solutions", folder="https://enterprise.proxmox.com/iso/", sums="SHA256SUMS",
        pattern=r"proxmox-ve_9\.\d+-\d+\.iso",
        labels=(r"^PVE$",),
        license=("AGPL-3.0 for Proxmox's own software, Debian's free licences for the base system; "
                 "Proxmox publishes the ISO for anyone to download and the software runs in full without a "
                 "subscription. \"Proxmox\" is Proxmox Server Solutions GmbH's trademark"),
        page="https://www.proxmox.com/en/downloads/proxmox-virtual-environment", size_gb=1.6,
        memory_mb=4096,
        offline=("the graphical installer needs no network: it writes the whole system from the disc, asks "
                 "for a fixed address, and the web UI answers on https port 8006 afterwards; only the package "
                 "repositories stay out of reach"),
        virt=("it is a KVM host out of the box: QEMU/KVM, LXC, the web UI on port 8006, vzdump backups and "
              "a Proxmox Backup Server client")),
    Distro(
        id="proxmox-bs4", title="Proxmox Backup Server 4 (installer ISO)", short="Proxmox Backup Server 4",
        publisher="Proxmox Server Solutions", folder="https://enterprise.proxmox.com/iso/", sums="SHA256SUMS",
        pattern=r"proxmox-backup-server_4\.\d+-\d+\.iso",
        labels=(r"^PBS$",),
        license=("AGPL-3.0 for Proxmox's own software, Debian's free licences for the base system; "
                 "Proxmox publishes the ISO for anyone to download and the software runs in full without a "
                 "subscription. \"Proxmox\" is Proxmox Server Solutions GmbH's trademark"),
        page="https://www.proxmox.com/en/downloads/proxmox-backup-server", size_gb=1.3,
        memory_mb=2048,
        offline=("the graphical installer needs no network: it writes the whole system from the disc, asks "
                 "for a fixed address, and the web UI answers on https port 8007 afterwards; only the package "
                 "repositories stay out of reach")),
    # Ubuntu Desktop: Linux as a PC's operating system, for the desktop
    # support lessons (CompTIA A+ Core 2's Linux items: Settings, Files,
    # software, users, the terminal). The same checksum file as the server
    # disc; the desktop installer installs the whole desktop from the disc,
    # and the disc's own small package pool (dists/noble, pool/main) is an
    # apt source with no network.
    Distro(
        id="ubuntu24-desktop", title="Ubuntu Desktop 24.04 LTS (installer DVD)", short="Ubuntu Desktop 24.04",
        publisher="Canonical", folder="https://releases.ubuntu.com/24.04/", sums="SHA256SUMS",
        pattern=r"ubuntu-24\.04(?:\.\d+)*-desktop-amd64\.iso",
        labels=(r"^Ubuntu 24\.04",),
        license=("free software under each package's own licence (Ubuntu's licence policy); Canonical "
                 "publishes the ISO for anyone to download. \"Ubuntu\" is Canonical's trademark"),
        page="https://ubuntu.com/download/desktop", size_gb=6.2, memory_mb=4096,
        offline=("the installer installs the desktop from the disc (Default or Extended selection) and skips "
                 "updates and third-party drivers; the disc's small package pool is an apt source after "
                 "sudo apt-cdrom add, and the App Center's snaps need the internet the lab does not have"),
        repo=True),
)}


def is_distro(image_id: str) -> bool:
    return image_id in DISTROS


def is_hand_linux(node) -> bool:
    """A machine that boots a Linux installer DVD on an empty disk."""
    return node.kind == "custom" and node.image in DISTROS


def _vkey(name: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", name))


def parse_sums(text: str) -> dict[str, str]:
    """{file: sha256} out of GNU ("<hash> *<file>") or BSD ("SHA256 (<file>)
    = <hash>") checksum lines; other lines (signatures, comments) are skipped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"SHA256\s*\((.+?)\)\s*=\s*([0-9a-fA-F]{64})$", line)
        if m:
            out[m.group(1)] = m.group(2).lower()
            continue
        m = re.match(r"([0-9a-fA-F]{64})\s+\*?(\S+)$", line)
        if m:
            out[m.group(2)] = m.group(1).lower()
    return out


def resolve(distro_id: str, get=_get) -> tuple[str, str, str]:
    """(url, file, sha256) of the newest ISO of the pinned release, read off
    the publisher's own checksum file (and, where each ISO has its own, the
    mirror's listing)."""
    d = DISTROS[distro_id]
    if not d.folder:
        raise LinuxIsoError(f"winlab cannot fetch {d.short}: {d.get}. Then: winlab images import {distro_id} <path>")
    try:
        if "{file}" in d.sums:
            listing = get(d.folder).decode("utf-8", "replace")
            names = set(re.findall(rf'href="({d.pattern})"', listing))
            if not names:
                raise LinuxIsoError(f"{d.folder} lists no {d.short} ISO")
            name = max(names, key=_vkey)
            sums = parse_sums(get(d.folder + d.sums.format(file=name)).decode("utf-8", "replace"))
        else:
            sums = parse_sums(get(d.folder + d.sums).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise LinuxIsoError(str(exc)) from exc
    files = [f for f in sums if re.fullmatch(d.pattern, f)]
    if not files:
        raise LinuxIsoError(
            f"{d.publisher}'s checksum file ({d.folder}{d.sums.replace('{file}', '<iso>')}) lists no "
            f"{d.short} ISO: the release may have moved to the archive. Download it yourself from "
            f"{d.page} and import it: winlab images import {AUTO} <path>")
    name = max(files, key=_vkey)
    return d.folder + name, name, sums[name]


def fetch(distro_id: str, progress=None, get=_get, download=_download_to) -> Path:
    """The installer DVD onto this PC, verified against the publisher's
    SHA-256; recorded beside it (file, version, checksum, where from)."""
    from . import images
    d = DISTROS[distro_id]
    say = progress or (lambda m: print(f"  {m}", file=sys.stderr))
    say(f"reading {d.publisher}'s checksum file ({d.folder})")
    url, name, sha = resolve(distro_id, get)
    dest = images.installer_path(distro_id)
    say(f"fetching {d.short}: {name}, about {d.size_gb:g} GB (verified against {sha[:12]}…)")
    try:
        download(url, dest, expect_sha=sha, label=d.short)
    except BootstrapError as exc:
        raise LinuxIsoError(str(exc)) from exc
    images._write_installer_meta(distro_id, name=name, size=dest.stat().st_size, sha256=sha,
                                 source=url, fetched=time.strftime("%Y-%m-%d"),
                                 holds=describe(dest) or d.short)
    say(f"{d.short} DVD ready: {dest}")
    return dest


# ------------------------------------------------------------ recognition
def read_disc(path: str | Path) -> dict[str, str]:
    """The volume label and the release files a Linux disc carries, as far
    as they can be read (empty when it is not an ISO 9660 image)."""
    from . import iso9660
    out: dict[str, str] = {}
    try:
        with iso9660.Iso(path) as iso:
            out["label"] = iso.volume_id()
            for f in (".disk/info", ".treeinfo", ".alpine-release"):
                try:
                    if iso.exists(f):
                        out[f] = iso.read(f)[:4096].decode("utf-8", "replace")
                except iso9660.IsoError:
                    pass
    except (iso9660.IsoError, OSError):
        return {}
    return out


def detect(path: str | Path) -> str:
    """The distro id a disc is, from its volume label first, then from what
    .disk/info, .treeinfo or .alpine-release say; '' when it is none of them."""
    disc = read_disc(path)
    label = disc.get("label", "")
    for d in DISTROS.values():
        if any(re.match(p, label) for p in d.labels):
            return d.id
    info, tree = disc.get(".disk/info", ""), disc.get(".treeinfo", "")
    if re.match(r"Ubuntu-Server 24\.04", info):
        return "ubuntu24"
    if re.match(r"Ubuntu 24\.04", info):
        return "ubuntu24-desktop"
    if re.match(r"Debian GNU/Linux 13\.", info):
        return "debian13"
    rhel = re.search(r"(?m)^version\s*=\s*(9|10)\b", tree)
    if re.search(r"(?m)^family\s*=\s*Red Hat Enterprise Linux", tree) and rhel:
        return f"rhel{rhel.group(1)}"
    if re.search(r"(?m)^family\s*=\s*Rocky Linux", tree) and re.search(r"(?m)^version\s*=\s*9\b", tree):
        return "rocky9"
    if re.match(r"alpine-(?:standard|extended)-3\.22", disc.get(".alpine-release", "")):
        return "alpine-std"
    return ""


def netinst(path: str | Path) -> bool:
    """A Debian network-install disc (label ends ' n', .disk/info NETINST)."""
    disc = read_disc(path)
    return disc.get("label", "").endswith(" n") or "NETINST" in disc.get(".disk/info", "").upper()


def describe(path: str | Path) -> str:
    """What the disc says it is, for a person: its .disk/info line or label."""
    disc = read_disc(path)
    info = disc.get(".disk/info", "").strip().splitlines()
    return (info[0] if info else disc.get("label", "")).strip()[:120]


def check_import(distro_id: str, src: Path) -> str:
    """Refuses a disc that is another distribution (naming the one it is);
    returns a warning for a disc the lab cannot fully use, else ''."""
    found = detect(src)
    d = DISTROS[distro_id]
    if found and found != distro_id:
        raise LinuxIsoError(f"{src.name} is {DISTROS[found].short}, not {d.short}: "
                            f"import it as {found} (or as {AUTO}, which reads the disc)")
    if not found and read_disc(src):
        raise LinuxIsoError(f"{src.name} ({describe(src) or 'no label'}) is not a {d.short} installer; "
                            f"winlab installs {', '.join(x.short for x in DISTROS.values())} by hand. "
                            "Any other disc goes in as your own: winlab images add <name> <path>")
    if distro_id == "debian13" and netinst(src):
        return ("this is the netinst disc: with no mirror in the lab it installs only a bare base "
                "system; the DVD-1 ISO has the packages")
    return ""


def which(src: Path) -> str:
    found = detect(src)
    if not found:
        raise LinuxIsoError(f"{src.name} is not a disc winlab recognises "
                            f"({describe(src) or 'no ISO 9660 label'}); it installs "
                            f"{', '.join(x.short for x in DISTROS.values())} by hand")
    return found


def missing_text(distro_id: str) -> str:
    d = DISTROS[distro_id]
    if not d.folder:
        return f"the {d.short} DVD is not on this PC. {d.get}: winlab images import {distro_id} <path>"
    return (f"the {d.short} installer DVD is not on this PC; fetch it in Setup (from {d.publisher}'s "
            f"mirror, about {d.size_gb:g} GB) or import one you have. Or: winlab images fetch "
            f"{distro_id}, or: winlab images import {AUTO} <path>")


def boot_hint(distro_id: str) -> str:
    """What the student sees at power-on, for the machine's panel."""
    d = DISTROS[distro_id]
    return (f"Power it on and open its screen: the firmware finds nothing on the empty disk and boots "
            f"the DVD (no key to press), and the {d.short} installer starts. The lab has no internet: "
            f"{d.offline}.")


# --------------------------------------------------------------- setup
def setup_rows(lab) -> list[dict]:
    """Setup's optional Linux downloads: each installer DVD, whether it is on
    this PC, and which of this lab's machines boot it."""
    from . import images
    rows = []
    for d in DISTROS.values():
        iso = images.installer_path(d.id)
        meta = images.installer_meta(d.id)
        who = [n.id for n in lab.node_list() if is_hand_linux(n) and n.image == d.id]
        rows.append({"image": d.id, "title": d.title, "short": d.short, "publisher": d.publisher,
                     "page": d.page, "mirror": d.folder.split("/")[2] if d.folder else "",
                     "fetch": bool(d.folder), "get": d.get,
                     "size_gb": d.size_gb, "license": d.license, "offline": d.offline,
                     "iso": iso.exists(), "holds": str(meta.get("holds") or meta.get("name") or ""),
                     "who": who, "needed": bool(who) and not iso.exists()})
    return rows


def setup_steps(lab) -> list[dict]:
    """Get-ready steps for the DVDs this lab's machines boot: fetched from
    the publisher's mirror like an appliance image, or (Red Hat) imported
    from the user's own download."""
    out = []
    for r in setup_rows(lab):
        if not r["who"]:
            continue
        who = f"{', '.join(r['who'])} boot{'s' if len(r['who']) == 1 else ''} it and you install by hand"
        if r["fetch"]:
            out.append({"id": f"linuxiso-{r['image']}",
                        "label": f"Fetch the {r['short']} installer DVD ({r['publisher']})",
                        "done": r["iso"], "blocked": False, "image": r["image"], "link": r["page"],
                        "job": "linuxiso-fetch",
                        "hint": f"{who}: the publisher's own ISO, verified against their checksum file, "
                                f"about {r['size_gb']:g} GB once"})
        else:
            out.append({"id": f"linuxiso-{r['image']}", "label": f"Import the {r['short']} DVD you downloaded",
                        "done": r["iso"], "blocked": not r["iso"], "image": r["image"], "link": r["page"],
                        "job": "import", "hint": f"{who}. {r['get']}"})
    return out


# ---- the web console of the Red Hat family: Cockpit, on the machine itself.
COCKPIT_PORT = 9090
COCKPIT_IMAGES = ("rocky9", "rhel9", "rhel10")


def _admin_gui(lab, node):
    """Cockpit, the web console RHEL and Rocky install with the Server
    environment: off until the student turns it on, on the machine's own
    address, port 9090, over https with its own certificate. Its Virtual
    machines page comes with cockpit-machines, from the same DVD. The Ubuntu
    appliance has it too once the student installs it from the kvm pack."""
    from .adminui import AdminGui
    if getattr(node, "kind", "") == "custom" and getattr(node, "image", "") in COCKPIT_IMAGES:
        return AdminGui(software="Cockpit (the web console)", scheme="https", port=COCKPIT_PORT, path="/",
                        sign_in="the administrator you made during the install",
                        license="LGPL-2.1-or-later",
                        note="Off until you turn it on, on the machine's screen: sudo systemctl enable --now "
                             "cockpit.socket, then sudo firewall-cmd --permanent --add-service=cockpit and "
                             "sudo firewall-cmd --reload. It signs its pages with its own certificate: accept "
                             "the browser's warning once. Its Virtual machines page appears once you install "
                             "cockpit-machines from the DVD (sudo dnf install cockpit-machines), with libvirt.")
    packs = (getattr(node, "vars", None) or {}).get("packs") or []
    if getattr(node, "kind", "") == "linux" and getattr(node, "image", "") == "ubuntu" and "kvm" in packs:
        from .webmin import ubuntu_sign_in
        return AdminGui(software="Cockpit (the web console)", scheme="https", port=COCKPIT_PORT, path="/",
                        sign_in=ubuntu_sign_in(), license="LGPL-2.1-or-later",
                        note="Once you install it from the kvm pack (sudo apt install cockpit cockpit-machines "
                             "from the stick): its Virtual machines page runs the VMs libvirt holds. It signs "
                             "its pages with its own certificate: accept the browser's warning once.")
    return None


def _register() -> None:
    from . import adminui
    adminui.register(node_gui=_admin_gui)


_register()
