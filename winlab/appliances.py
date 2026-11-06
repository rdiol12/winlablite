"""Appliances: ready-made Linux machines a lab boots from a publisher's own
cloud image.

An appliance is fetched from its publisher onto this PC (never bundled, the
same rule as QEMU and the virtio drivers), verified against the publisher's
checksum file, and kept as a base image the lab's machines are thin-cloned
from. At first boot cloud-init (winlab/cloudinit.py) gives the machine its
name, address, DNS, the lab password and the winlab serial agent, so
`winlab shell`, `winlab cp`, roles and problems work on it like on any other
machine. The lab has no internet, so packages come as packs
(winlab/debpacks.py) fetched on this PC and plugged in as a stick.

The image's package manifest is kept beside it: the pack fetcher resolves
dependencies against what the image already has.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import BootstrapError, _download_to, _get


class ApplianceError(Exception):
    pass


@dataclass(frozen=True)
class Appliance:
    id: str
    title: str
    short: str
    publisher: str
    page: str                 # the publisher's directory the files come from
    file: str                 # the image, a qcow2 the lab clones
    sums: str                 # the publisher's checksum file in that directory
    manifest: str             # the package manifest in that directory
    license: str
    user: str                 # the administrator account cloud-init creates
    series: str               # the apt suite the packs are fetched for
    archive: str              # the distribution's package archive
    security: str             # its security archive
    components: tuple[str, ...]
    disk_gb: int = 20
    memory_mb: int = 1024
    cpus: int = 1
    note: str = ""
    # How the image is fetched and driven. flavor "cloud-init": a qcow2 cloud
    # image, SHA256SUMS lines, cloud-init first boot, the winlab agent on
    # ttyS1. flavor "opnsense": the current release found in the mirror's
    # listing ({version} in file and sums), BSD-style checksum lines, a raw
    # disk image compressed with bzip2 that is unpacked and converted to qcow2
    # here, and winlab drives the machine over its serial console
    # (winlab/consoleagent.py) because nothing of winlab's runs inside it.
    flavor: str = "cloud-init"
    console: str = "agent"        # "agent": ttyS1 agent; "serial": the console is the channel
    pattern: str = ""             # regex with one group, the release version, over the listing


UBUNTU = Appliance(
    id="ubuntu",
    title="Ubuntu Server 24.04 LTS (Canonical's cloud image)",
    short="Ubuntu Server 24.04",
    publisher="Canonical",
    page="https://cloud-images.ubuntu.com/noble/current/",
    file="noble-server-cloudimg-amd64.img",
    sums="SHA256SUMS",
    manifest="noble-server-cloudimg-amd64.manifest",
    license=("free software under each package's own licence (GPL, LGPL, BSD, MIT and "
             "others); Canonical publishes the image for anyone to download"),
    user="ubuntu",
    series="noble",
    archive="https://archive.ubuntu.com/ubuntu",
    security="https://security.ubuntu.com/ubuntu",
    components=("main", "universe"),
    disk_gb=20,
    memory_mb=1024,
    cpus=1,
    note=("a plain Ubuntu server with SSH and systemd; the lab has no internet, so "
          "packages come from winlab's packs; the linux-member role joins it to the domain"),
)

OPNSENSE = Appliance(
    id="opnsense",
    title="OPNsense firewall (the project's nano image)",
    short="OPNsense",
    publisher="the OPNsense project (Deciso B.V.)",
    page="https://pkg.opnsense.org/releases/mirror/",
    file="OPNsense-{version}-nano-amd64.img.bz2",
    sums="OPNsense-{version}-checksums-amd64.sha256",
    manifest="",
    license=("BSD 2-Clause (the OPNsense project's licence; FreeBSD base and packages under "
             "their own free licences); the project publishes the image for anyone to download. "
             "\"OPNsense\" is a registered trademark of Deciso B.V.: winlab names it, never claims it"),
    user="root",
    series="",
    archive="",
    security="",
    components=(),
    disk_gb=8,
    memory_mb=1024,
    cpus=1,
    note=("a real OPNsense firewall between the lab's zones: winlab writes its config.xml from the "
          "lab file (interfaces, addresses, the lab password for root, SSH and the web GUI) and "
          "drives it over the serial console, so shell, lessons and problems work on it"),
    flavor="opnsense",
    console="serial",
    pattern=r"OPNsense-(\d+\.\d+(?:\.\d+)?)-nano-amd64\.img\.bz2",
)

def _debian(version: int, codename: str, image_id: str, note: str) -> Appliance:
    """Debian's own genericcloud image from the Debian cloud team: a qcow2
    with cloud-init, its SHA-512 from the SHA512SUMS beside it, and the
    build's JSON manifest (its package list) for the pack resolver."""
    return Appliance(
        id=image_id,
        title=f"Debian {version} {codename} (the Debian cloud team's genericcloud image)",
        short=f"Debian {version} cloud",
        publisher="the Debian project",
        page=f"https://cloud.debian.org/images/cloud/{codename}/latest/",
        file=f"debian-{version}-genericcloud-amd64.qcow2",
        sums="SHA512SUMS",
        manifest=f"debian-{version}-genericcloud-amd64.json",
        license=("free software under each package's own licence (DFSG: GPL, LGPL, BSD, MIT and "
                 "others); the Debian project publishes the image for anyone to download"),
        user="debian",
        series=codename,
        archive="https://deb.debian.org/debian",
        security="https://security.debian.org/debian-security",
        components=("main",),
        disk_gb=20,
        memory_mb=1024,
        cpus=1,
        note=note,
    )


# Debian 13 trixie: what OpenMediaVault 8 (Synchrony), the current stable
# release, is built on; the NAS on the shelf runs it (role nas, pack omv).
# "debian13" is the Debian DVD a student installs by hand (linuxiso.py), so
# the cloud image is its own id.
DEBIAN13 = _debian(13, "trixie", "debian13-cloud",
                   "a plain Debian 13 server with cloud-init and SSH; the NAS on the workbench shelf runs "
                   "OpenMediaVault on it, installed from the omv pack at its first start")
# Debian 12 bookworm, for software that is built for it.
DEBIAN12 = _debian(12, "bookworm", "debian12",
                   "a plain Debian 12 server with cloud-init and SSH; the lab has no internet, so "
                   "packages come from winlab's packs")

OPENWRT = Appliance(
    id="openwrt",
    title="OpenWrt (the project's x86-64 image): the access points and the UPS's network card",
    short="OpenWrt",
    publisher="the OpenWrt project",
    page="https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/",
    file="openwrt-24.10.4-x86-64-generic-ext4-combined.img.gz",
    sums="sha256sums",
    manifest="openwrt-24.10.4-x86-64.manifest",
    license=("GPL-2.0 (OpenWrt; its packages under their own free licences); the project publishes the "
             "image and its package feeds for anyone to download"),
    user="root",
    series="",
    archive="",
    security="",
    components=(),
    disk_gb=1,
    memory_mb=128,
    cpus=1,
    note=("the firmware of the workbench's access points and of the UPS's network card: LuCI, OpenWrt's "
          "web interface, served on the lab network; the software radio, hostapd and NUT come from the "
          "release's own package feeds, fetched with the image (winlab/openwrt.py)"),
    flavor="openwrt",
    console="serial",
)

APPLIANCES: dict[str, Appliance] = {UBUNTU.id: UBUNTU, OPNSENSE.id: OPNSENSE, OPENWRT.id: OPENWRT,
                                    DEBIAN13.id: DEBIAN13, DEBIAN12.id: DEBIAN12}


def console_driven(image_id: str) -> bool:
    """True for an appliance winlab reaches over its serial console (no agent inside)."""
    app = APPLIANCES.get(image_id)
    return bool(app and app.console == "serial")


def parse_bsd_sums(text: str, filename: str) -> str:
    """The SHA-256 of one file out of BSD-style lines ("SHA256 (<file>) = <hash>")."""
    import re
    for line in text.splitlines():
        m = re.match(r"SHA256\s*\((.+?)\)\s*=\s*([0-9a-fA-F]{64})\s*$", line.strip())
        if m and m.group(1) == filename:
            return m.group(2).lower()
    return parse_sums(text, filename)


def discover_version(listing: str, pattern: str) -> str:
    """The newest release the mirror's listing names (26.7.1 over 26.7 over 26.1)."""
    import re
    found = set(re.findall(pattern, listing))
    if not found:
        raise ApplianceError("the mirror's listing names no image of that kind")
    return max(found, key=lambda v: tuple(int(x) for x in v.split(".")))


def unpack_bz2(src: Path, dest: Path, progress=None) -> Path:
    """Decompresses a bzip2 disk image to a raw file, writing it sparse (a
    nano image is mostly empty), so the raw copy costs little disk."""
    import bz2
    say = progress or (lambda _m: None)
    dec = bz2.BZ2Decompressor()
    dest.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    zero = bytes(1 << 20)
    with src.open("rb") as fin, dest.open("wb") as fout:
        while True:
            chunk = fin.read(1 << 20)
            if not chunk:
                break
            data = dec.decompress(chunk)
            while data:
                piece, data = data[:1 << 20], data[1 << 20:]
                if piece == zero[:len(piece)]:
                    fout.seek(len(piece), 1)
                else:
                    fout.write(piece)
                written += len(piece)
        fout.truncate(written)
    say(f"unpacked {written >> 20} MB")
    return dest


def raw_to_qcow2(raw: Path, dest: Path) -> Path:
    from .images import _run_img
    dest.parent.mkdir(parents=True, exist_ok=True)
    _run_img(["convert", "-f", "raw", "-O", "qcow2", str(raw), str(dest)])
    return dest


def get(image_id: str) -> Appliance | None:
    return APPLIANCES.get(image_id)


def is_appliance(image_id: str) -> bool:
    return image_id in APPLIANCES


def image_path(image_id: str) -> Path:
    from .images import base_path
    return base_path(image_id)


def manifest_path(image_id: str) -> Path:
    return image_path(image_id).with_suffix(".manifest")


def ready(image_id: str) -> bool:
    return image_path(image_id).exists()


def parse_sums(text: str, filename: str) -> str:
    """The digest of one file out of a SHA256SUMS or SHA512SUMS listing
    ("<hash> *<file>" or "<hash>  <file>"): 64 hex digits or 128."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == filename:
            digest = parts[0].lower()
            if len(digest) in (64, 128) and all(c in "0123456789abcdef" for c in digest):
                return digest
    raise ApplianceError(f"{filename} is not listed in the publisher's checksum file")


def fetch(image_id: str, progress=None, get=_get, download=_download_to, convert=None) -> Path:
    """Fetches the image (checksum from the publisher's own listing) and its
    package manifest onto this PC, and records both in the base's metadata."""
    app = get_or_raise(image_id)
    say = progress or (lambda _m: None)
    if app.flavor == "opnsense":
        return _fetch_opnsense(app, say, get, download, convert)
    if app.flavor == "openwrt":
        from . import openwrt
        try:
            return openwrt.fetch(app, say, get, download, convert)
        except openwrt.OpenWrtError as exc:
            raise ApplianceError(str(exc)) from exc
    say(f"reading {app.publisher}'s checksum file ({app.page}{app.sums})")
    try:
        sha = parse_sums(get(app.page + app.sums).decode("utf-8", "replace"), app.file)
        dest = image_path(image_id)
        dest.parent.mkdir(parents=True, exist_ok=True)
        say(f"fetching {app.short}: {app.file} (verified against {sha[:12]}…)")
        download(app.page + app.file, dest, expect_sha=sha, label=f"{app.short} image")
        count = 0
        if app.manifest:
            say("fetching the image's package manifest")
            try:
                text = get(app.page + app.manifest).decode("utf-8", "replace")
            except BootstrapError:
                if app.sums != "SHA512SUMS":
                    raise
                text = ""  # Debian's build manifest is a help, not a must (see below)
            manifest_path(image_id).write_text(text, encoding="utf-8")
            count = len(_manifest_names(text))
            if not count:
                # A manifest that names no packages: the pack resolver then
                # counts only the archive's Priority: required packages as
                # present (debpacks.fetch) and fetches the rest.
                say("the manifest lists no packages; packs will carry everything above Debian's base")
    except BootstrapError as exc:
        raise ApplianceError(str(exc)) from exc
    from .images import write_base_meta
    digest = {"sha256": sha} if len(sha) == 64 else {"sha512": sha}
    write_base_meta(image_id, appliance=True, **digest, source=app.page + app.file,
                    fetched=time.strftime("%Y-%m-%d"), packages=count, user=app.user)
    say(f"{app.short} ready: {dest} ({dest.stat().st_size >> 20} MB, {count} packages in the image)")
    return dest


def _fetch_opnsense(app: Appliance, say, get, download, convert) -> Path:
    """The current nano image from the OPNsense mirror: version from the
    listing, SHA-256 from the release's checksum file, the bzip2 image
    downloaded and verified, unpacked sparse and converted to the qcow2
    base the lab's firewalls are cloned from; the archives are removed."""
    from .images import write_base_meta
    from . import paths
    say(f"reading the OPNsense mirror's listing ({app.page})")
    try:
        version = discover_version(get(app.page).decode("utf-8", "replace"), app.pattern)
        fname = app.file.format(version=version)
        sums = app.sums.format(version=version)
        say(f"release {version}: reading its checksum file ({sums})")
        sha = parse_bsd_sums(get(app.page + sums).decode("utf-8", "replace"), fname)
        down = paths.downloads_dir() / fname
        say(f"fetching {app.short} {version}: {fname} (verified against {sha[:12]}…)")
        download(app.page + fname, down, expect_sha=sha, label=f"{app.short} {version}")
    except BootstrapError as exc:
        raise ApplianceError(str(exc)) from exc
    raw = down.with_suffix("")     # .img.bz2 -> .img
    say("unpacking the image (bzip2, written sparse)")
    unpack_bz2(down, raw, say)
    dest = image_path(app.id)
    say(f"converting to qcow2: {dest}")
    (convert or raw_to_qcow2)(raw, dest)
    raw.unlink(missing_ok=True)
    down.unlink(missing_ok=True)
    write_base_meta(app.id, appliance=True, sha256=sha, source=app.page + fname, version=version,
                    fetched=time.strftime("%Y-%m-%d"), packages=0, user=app.user, console="serial")
    say(f"{app.short} {version} ready: {dest} ({dest.stat().st_size >> 20} MB)")
    return dest


def get_or_raise(image_id: str) -> Appliance:
    app = get(image_id)
    if app is None:
        raise ApplianceError(f"no appliance '{image_id}'; known: {', '.join(APPLIANCES)}")
    return app


def _json_packages(data) -> set[str]:
    """Package names out of a build manifest in JSON (Debian's cloud images):
    any list under a "packages" key, of names or of {"name": ...} objects."""
    out: set[str] = set()
    if isinstance(data, dict):
        for k, v in data.items():
            if k == "packages" and isinstance(v, list):
                for p in v:
                    name = p.get("name") or p.get("package") if isinstance(p, dict) else p
                    if isinstance(name, str) and name:
                        out.add(name.split(":")[0])
            else:
                out |= _json_packages(v)
    elif isinstance(data, list):
        for v in data:
            out |= _json_packages(v)
    return out


def _manifest_names(text: str) -> set[str]:
    if text.lstrip()[:1] in ("{", "["):
        import json
        try:
            return _json_packages(json.loads(text))
        except ValueError:
            return set()
    out: set[str] = set()
    for line in text.splitlines():
        name = line.split("\t")[0].split()[0] if line.strip() else ""
        if not name or name.startswith("snap:"):
            continue
        out.add(name.split(":")[0])
    return out


def installed_packages(image_id: str) -> set[str]:
    """The packages the fetched image already carries (its publisher's
    manifest), so a pack fetches only what is missing."""
    p = manifest_path(image_id)
    if not p.exists():
        return set()
    return _manifest_names(p.read_text(encoding="utf-8", errors="replace"))


def summary(image_id: str) -> dict:
    app = get_or_raise(image_id)
    from .images import base_meta
    meta = base_meta(image_id)
    return {
        "id": app.id, "title": app.title, "short": app.short, "publisher": app.publisher,
        "ready": ready(image_id), "fetched": meta.get("fetched", ""),
        "sha256": meta.get("sha256", ""), "sha512": meta.get("sha512", ""), "packages": len(installed_packages(image_id)),
        "license": app.license, "page": app.page, "user": app.user, "note": app.note,
        "disk_gb": app.disk_gb, "memory_mb": app.memory_mb, "cpus": app.cpus,
    }
