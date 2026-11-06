"""Image catalog: acquisition, base preparation and thin clones.

Microsoft media is never downloaded automatically or redistributed. The
Evaluation Center requires registration, and the media is not ours to mirror,
so Windows images are IMPORTED from a file the user fetched themselves.
Freely redistributable images (Alpine) are fetched directly; the virtio-win
guest drivers are fetched by virtio.py and recorded in each base's metadata.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import paths
from .appliances import APPLIANCES, is_appliance
from .linuxiso import DISTROS
from .bsdfw import FIREWALLS
from .bootstrap import BootstrapError, _download_to, _get

FETCH = "fetch"
IMPORT = "import"

ALPINE_DIR = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/"


class ImageError(Exception):
    pass


@dataclass
class Entry:
    id: str
    title: str
    mode: str
    kind: str
    license: str
    note: str = ""
    url: str = ""
    page: str = ""
    accepts: tuple[str, ...] = field(default_factory=tuple)
    min_gb: float = 0.0
    # The name the desktop shows for a machine on this image.
    short: str = ""
    # How a student gets installation media that is not one ISO to import.
    get: str = ""


# Catalog kinds besides the machine kinds: installation media for a role.
MEDIA = "media"

SERVER_EVAL = "Microsoft Evaluation EULA, 180 days, non-production"
CLIENT_EVAL = "Microsoft Evaluation EULA, 90 days, non-production"
EVALCENTER = "https://www.microsoft.com/en-us/evalcenter/"


def _server(version: str, core: bool = False) -> Entry:
    """A Windows Server evaluation: the Desktop Experience base, or the
    Server Core base that installs from the same ISO."""
    image_id = f"ws{version}" + ("-core" if core else "")
    return Entry(
        id=image_id,
        title=f"Windows Server {version}{' Server Core' if core else ''} (evaluation)",
        short=f"Windows Server {version}{' Core' if core else ''}",
        mode=IMPORT,
        kind="windows-server",
        license=SERVER_EVAL,
        note=(f"no desktop, about half the memory; installs from the ws{version} ISO" if core
              else "download the 64-bit ISO or VHD yourself, then import it"),
        page=f"{EVALCENTER}evaluate-windows-server-{version}",
        accepts=(".iso", ".vhd", ".vhdx"),
        min_gb=20.0,
    )


CATALOG: dict[str, Entry] = {
    "ws2025": _server("2025"),
    "ws2025-core": _server("2025", core=True),
    "ws2022": _server("2022"),
    "ws2022-core": _server("2022", core=True),
    "ws2019": _server("2019"),
    "ws2019-core": _server("2019", core=True),
    "win11": Entry(
        id="win11",
        title="Windows 11 Enterprise (evaluation)",
        short="Windows 11",
        mode=IMPORT,
        kind="windows-client",
        license=CLIENT_EVAL,
        note="download the 64-bit ISO yourself, then import it",
        page=f"{EVALCENTER}evaluate-windows-11-enterprise",
        accepts=(".iso", ".vhd", ".vhdx"),
        min_gb=20.0,
    ),
    "win10": Entry(
        id="win10",
        title="Windows 10 Enterprise (evaluation)",
        short="Windows 10",
        mode=IMPORT,
        kind="windows-client",
        license=CLIENT_EVAL,
        note=("Windows 10 left support in October 2025 and Microsoft has been taking its "
              "evaluation download off the Evaluation Center; import a 64-bit Windows 10 "
              "Enterprise ISO you already hold (evaluation, LTSC 2021 evaluation, or a "
              "Visual Studio or volume-licence download)"),
        page=f"{EVALCENTER}evaluate-windows-10-enterprise",
        accepts=(".iso", ".vhd", ".vhdx"),
        min_gb=20.0,
    ),
    # Installation media a role installs from inside a Windows machine: not
    # an operating system, so it never makes a base; the user downloads it,
    # imports it, and the role finds it in the DVD drive.
    "sql2022": Entry(
        id="sql2022",
        title="SQL Server 2022 Developer (installation media)",
        short="SQL Server 2022",
        mode=IMPORT,
        kind=MEDIA,
        license=("Microsoft SQL Server Developer edition licence: free, full-featured, for "
                 "development and testing only, never production"),
        note=("download the free Developer edition from Microsoft, run its small installer, "
              "choose Download Media and the ISO (about 1.2 GB), then import that ISO; the "
              "180-day Evaluation ISO works the same way. The sql role installs the Database "
              "Engine from it, unattended, inside the machine"),
        page="https://www.microsoft.com/en-us/sql-server/sql-server-downloads",
        accepts=(".iso",),
        min_gb=1.0,
    ),
    "mecm": Entry(
        id="mecm",
        title="Microsoft Configuration Manager (evaluation), prepared media",
        short="Configuration Manager",
        mode=IMPORT,
        kind=MEDIA,
        license=("Microsoft Evaluation EULA, 180 days, non-production; the Windows ADK, Windows PE "
                 "add-on and ODBC Driver 18 under their own Microsoft terms"),
        note=("download the Configuration Manager evaluation (it extracts itself to a folder), the "
              "Windows ADK and its Windows PE add-on installers, and the ODBC Driver 18 for SQL Server "
              "MSI, all from Microsoft, into Downloads; winlab then builds one disc from them (about "
              "6 GB, an hour or two the first time, because the ADK installers fetch their offline "
              "copies). The mecm role installs a primary site from it inside the machine"),
        page="https://www.microsoft.com/en-us/evalcenter/evaluate-microsoft-endpoint-configuration-manager",
        accepts=(".iso",),
        min_gb=2.0,
        get="winlab mecm prepare",
    ),
    # RSAT on Windows 11 is a set of Features on Demand: with no internet in
    # the lab they install from Microsoft's own disc, which the user imports.
    "fod-win11": Entry(
        id="fod-win11",
        title="Windows 11 Languages and Optional Features (Features on Demand) ISO",
        short="Windows 11 Features on Demand",
        mode=IMPORT,
        kind=MEDIA,
        license="part of your Windows 11 licence (evaluation included), under Microsoft's terms",
        note=("Microsoft publishes a Languages and Optional Features ISO for each Windows 11 "
              "release (with the Enterprise evaluation, or in your Visual Studio or volume-licensing "
              "downloads; Microsoft Learn's Features on Demand page explains it); take the one for the "
              "same release as the Windows 11 ISO you imported, then import it. The rsat role installs "
              "the admin tools from it on the Windows 11 PC; servers need no disc"),
        page=f"{EVALCENTER}evaluate-windows-11-enterprise",
        accepts=(".iso",),
        min_gb=1.0,
    ),
    "alpine": Entry(
        id="alpine",
        title="Alpine Linux virt (fabric and probe nodes)",
        short="Alpine Linux",
        mode=FETCH,
        kind="linux",
        license="MIT and assorted free licenses",
        accepts=(".iso",),
        min_gb=0.3,
    ),
}

# Appliances: ready-made Linux machines fetched from their publisher's own
# cloud image (winlab/appliances.py); first boot is cloud-init's.
for _app in APPLIANCES.values():
    CATALOG[_app.id] = Entry(
        id=_app.id, title=_app.title, short=_app.short, mode=FETCH, kind="linux",
        license=_app.license, note=_app.note,
        url=_app.page if "{" in _app.file else _app.page + _app.file, page=_app.page,
        accepts=(".img", ".qcow2"),
        min_gb={"cloud-init": 0.7, "openwrt": 0.2}.get(_app.flavor, 3.5),
    )

# Linux installer DVDs (winlab/linuxiso.py): fetched from the distribution's
# own mirror or imported, booted by a machine the student installs by hand.
for _d in DISTROS.values():
    CATALOG[_d.id] = Entry(
        id=_d.id, title=_d.title, short=_d.short, mode=FETCH if _d.folder else IMPORT,
        kind="linux-installer", license=_d.license, note=_d.get or _d.offline, url=_d.folder, page=_d.page,
        accepts=(".iso",), min_gb=min(1.0, _d.size_gb / 2),
    )

# Firewall installers (winlab/bsdfw.py): OPNsense fetched from its mirror,
# pfSense CE imported from the user's own download; installed by hand.
for _f in FIREWALLS.values():
    CATALOG[_f.id] = Entry(
        id=_f.id, title=_f.title, short=_f.short, mode=FETCH if _f.folder else IMPORT,
        kind="firewall-installer", license=_f.license, note=_f.get or _f.defaults,
        url=_f.folder, page=_f.page, accepts=(".iso", ".gz", ".bz2"), min_gb=0.2,
    )

# The Windows images in the order the desktop lists them.
WINDOWS_IMAGES = [i for i, e in CATALOG.items() if e.kind.startswith("windows-")]
# What a Linux machine can run: the Alpine probe, or an appliance.
LINUX_IMAGES = [i for i, e in CATALOG.items() if e.kind == "linux"]
# Installation media roles install from (never a machine's own image).
MEDIA_IMAGES = [i for i, e in CATALOG.items() if e.kind == MEDIA]


def is_media(image_id: str) -> bool:
    e = CATALOG.get(image_id)
    return bool(e and e.kind == MEDIA)


def windows_images(kind: str = "") -> list[str]:
    return [i for i in WINDOWS_IMAGES if not kind or CATALOG[i].kind == kind]


def _qemu_img() -> Path:
    exe = paths.qemu_img()
    if not exe.exists():
        raise ImageError(f"{exe.name} missing -- run 'winlab bootstrap' first")
    return exe


def _run_img(args: list[str], timeout: int = 7200) -> str:
    cmd = [str(_qemu_img())] + args
    res = subprocess.run(cmd, capture_output=True, timeout=timeout)
    out = (res.stdout or b"").decode("utf-8", "replace")
    err = (res.stderr or b"").decode("utf-8", "replace")
    if res.returncode != 0:
        raise ImageError(f"qemu-img {args[0]} failed: {(err or out).strip()[:500]}")
    return out


def base_path(image_id: str, suffix: str = ".qcow2") -> Path:
    return paths.bases_dir() / f"{image_id}{suffix}"


# Images installed from another image's media (a different edition on the
# same ISO), so the user imports one ISO, not two copies of it.
SHARES_INSTALLER = {i: i[:-5] for i in CATALOG if i.endswith("-core")}


def installer_path(image_id: str) -> Path:
    return paths.downloads_dir() / f"{SHARES_INSTALLER.get(image_id, image_id)}.iso"


def installer_meta_path(image_id: str) -> Path:
    return installer_path(image_id).with_suffix(".iso.json")


def installer_meta(image_id: str) -> dict:
    """What `images import` and `retire_installer` recorded about the ISO:
    the images its install.wim lists, and, once removed, what it was."""
    p = installer_meta_path(image_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_installer_meta(image_id: str, **fields) -> dict:
    meta = installer_meta(image_id)
    meta.update(fields)
    p = installer_meta_path(image_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


# The Windows build each catalog image installs (Server 2025 and Windows 11
# 24H2 are both 26100: the installation type tells them apart) and, for the
# clients, the editions in order of preference. Servers take Standard, then
# Datacenter; Desktop Experience or Server Core by the installation type.
BUILDS = {"ws2025": (26100, 26100), "ws2022": (20348, 20348), "ws2019": (17763, 17763),
          "win11": (22000, 99999), "win10": (10240, 19045)}
SERVER_EDITIONS = ("serverstandard", "serverdatacenter")
CLIENT_EDITIONS = ("enterprise", "enterprises", "professional", "education", "core")


def _edition_key(edition: str) -> str:
    """'ServerStandardEvalCore' -> 'serverstandard'; 'EnterpriseEval' -> 'enterprise'."""
    e = edition.lower()
    for suffix in ("core", "eval", "core"):
        if e.endswith(suffix) and len(e) > len(suffix):
            e = e[: -len(suffix)]
    return e


def pick_edition(image_id: str, found: list[dict]) -> dict | None:
    """The install.wim image a catalog image installs, out of what the media
    lists; None when the media is another Windows."""
    entry = CATALOG.get(image_id)
    if entry is None or not entry.kind.startswith("windows-"):
        return None
    core = image_id.endswith("-core")
    base = image_id[:-5] if core else image_id
    lo, hi = BUILDS.get(base, (0, 0))
    server = entry.kind == "windows-server"
    fit = []
    for im in found:
        build = int(im.get("build") or 0)
        if build and not lo <= build <= hi:
            continue
        itype = str(im.get("type", "")).lower()
        name = str(im.get("name", "")).upper()
        is_server = itype.startswith("server") if itype else "SERVER" in name
        if is_server != server:
            continue
        if server:
            is_core = itype == "server core" if itype else name.endswith("CORE")
            if is_core != core:
                continue
        fit.append(im)
    if not fit:
        return None
    order = SERVER_EDITIONS if server else CLIENT_EDITIONS
    keyed = [(_edition_key(str(im.get("edition", ""))), im) for im in fit]
    for want in order:
        for key, im in keyed:
            if key == want:
                return im
    return fit[0]


def installer_images(image_id: str) -> list[dict]:
    return list(installer_meta(image_id).get("images") or [])


def edition(image_id: str) -> dict | None:
    """The media image this catalog image installs, from what import read."""
    return pick_edition(image_id, installer_images(image_id))


def edition_name(image_id: str) -> str:
    """The /IMAGE/NAME for the answer file, blank when the media was not
    read (a VHD import, an ISO without install.wim)."""
    ed = edition(image_id)
    return str(ed.get("name") or "") if ed else ""


def edition_text(image_id: str) -> str:
    from . import wim
    ed = edition(image_id)
    return wim.describe(ed) if ed else ""


def media_fits(found: list[dict]) -> list[str]:
    """The catalog images this media can install."""
    return [i for i in WINDOWS_IMAGES if pick_edition(i, found)]


def base_meta_path(image_id: str) -> Path:
    return base_path(image_id, ".json")


def base_meta(image_id: str) -> dict:
    """What `images prepare` recorded about a base: whether the virtio
    drivers are in it (the QEMU provider reads this to pick virtio or
    emulated devices), when, compressed or not."""
    p = base_meta_path(image_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def write_base_meta(image_id: str, **fields) -> dict:
    meta = base_meta(image_id)
    meta.update(fields)
    p = base_meta_path(image_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    tmp.replace(p)
    return meta


def catalog_root(image_id: str) -> Entry | None:
    """The catalog image behind an image id: itself, or for a template the
    base its source machine (or that one's template) was made from."""
    seen: set[str] = set()
    while image_id and image_id not in seen:
        seen.add(image_id)
        if image_id in CATALOG:
            return CATALOG[image_id]
        tpl = templates().get(image_id)
        if tpl is None:
            return None
        image_id = tpl.image
    return None


def base_virtio(image_id: str) -> bool:
    """True when this base was prepared with the virtio-win drivers, so a
    clone boots from a virtio disk and drives a virtio NIC. A template is a
    machine's disk, drivers included, so it answers for the base (or the
    template) its source machine was made from."""
    seen: set[str] = set()
    while image_id and image_id not in seen:
        seen.add(image_id)
        tpl = templates().get(image_id)
        if tpl is None:
            return bool(base_meta(image_id).get("virtio"))
        image_id = tpl.image
    return False


def fingerprint(path: Path) -> str:
    """Identifies a multi-gigabyte ISO in well under a second: its size plus
    a hash of its first and last mebibyte. Enough to recognise the same
    download again; not a proof of integrity."""
    import hashlib
    size = path.stat().st_size
    h = hashlib.sha256(str(size).encode())
    chunk = 1024 * 1024
    with path.open("rb") as f:
        h.update(f.read(chunk))
        if size > chunk:
            f.seek(max(0, size - chunk))
            h.update(f.read(chunk))
    return f"{size}:{h.hexdigest()[:32]}"


def retire_installer(image_id: str) -> dict | None:
    """After a base is prepared the ISO copy only costs disk: remove it and
    keep a note of what it was, so importing the same download again is a
    no-op and a rebuild says what it needs."""
    import time
    iso = installer_path(image_id)
    if not iso.exists():
        return None
    meta = _write_installer_meta(
        image_id, name=iso.name, size=iso.stat().st_size, fingerprint=fingerprint(iso),
        retired=time.time(), prepared=image_id)
    iso.unlink()
    return meta


def retired_installer(image_id: str) -> dict | None:
    if installer_path(image_id).exists():
        return None
    meta = installer_meta(image_id)
    return meta if meta.get("retired") else None


def status(image_id: str) -> dict[str, object]:
    entry = CATALOG.get(image_id)
    if entry is None:
        raise ImageError(f"unknown image {image_id!r}; known: {', '.join(sorted(CATALOG))}")
    base = base_path(image_id)
    iso = installer_path(image_id)
    return {
        "entry": entry,
        "base": base if base.exists() else None,
        "base_gb": base.stat().st_size / (1024**3) if base.exists() else 0.0,
        "installer": iso if iso.exists() else None,
        "installer_gb": iso.stat().st_size / (1024**3) if iso.exists() else 0.0,
        "installer_retired": retired_installer(image_id) is not None,
        "virtio": base.exists() and base_virtio(image_id),
        "edition": edition_text(image_id),
        "appliance": is_appliance(image_id),
        "fetched": str(base_meta(image_id).get("fetched", "")) if is_appliance(image_id) else "",
    }


def _alpine_url() -> tuple[str, str]:
    html = _get(ALPINE_DIR).decode("utf-8", "replace")
    found = re.findall(r'href="(alpine-virt-([\d.]+)-x86_64\.iso)"', html)
    if not found:
        raise ImageError(f"no alpine-virt iso listed at {ALPINE_DIR}")
    name, version = sorted(found, key=lambda t: [int(x) for x in t[1].split(".")])[-1]
    return ALPINE_DIR + name, version


def fetch(image_id: str, progress=None) -> Path:
    entry = CATALOG.get(image_id)
    if entry is None:
        raise ImageError(f"unknown image {image_id!r}")
    if image_id in FIREWALLS:
        from . import bsdfw
        try:
            return bsdfw.fetch(image_id, progress=progress)
        except bsdfw.BsdFwError as exc:
            raise ImageError(str(exc)) from exc
    if image_id in DISTROS:
        from . import linuxiso
        try:
            return linuxiso.fetch(image_id, progress=progress)
        except linuxiso.LinuxIsoError as exc:
            raise ImageError(str(exc)) from exc
    if is_appliance(image_id):
        from . import appliances
        say = progress or (lambda m: print(f"  {m}", file=sys.stderr))
        try:
            return appliances.fetch(image_id, progress=say)
        except appliances.ApplianceError as exc:
            raise ImageError(str(exc)) from exc
    if entry.mode != FETCH:
        raise ImageError(
            f"{image_id} cannot be fetched automatically.\n"
            f"  {entry.license}\n"
            f"  download it from: {entry.page}\n"
            f"  then: winlab images import {image_id} <path>"
        )

    url = entry.url
    label = image_id
    if image_id == "alpine":
        url, version = _alpine_url()
        label = f"alpine {version}"

    dest = installer_path(image_id)
    print(f"  fetching {label}", file=sys.stderr)
    try:
        _download_to(url, dest, label=label)
    except BootstrapError as exc:
        raise ImageError(str(exc)) from exc
    return dest


def copy_with_progress(src: Path, dest: Path, progress=None, label: str = "") -> Path:
    """Copies into dest.part and renames, so a cancelled or failed copy never
    looks like imported media; reports whole percents through progress."""
    total = src.stat().st_size or 1
    part = dest.with_name(dest.name + ".part")
    done = shown = 0
    with src.open("rb") as fi, part.open("wb") as fo:
        while True:
            buf = fi.read(8 * 1024 * 1024)
            if not buf:
                break
            fo.write(buf)
            done += len(buf)
            pct = done * 100 // total
            if progress and pct >= shown + 2:
                shown = pct
                progress(f"{label or 'copying ' + src.name}: {pct}%")
    shutil.copystat(src, part)
    os.replace(part, dest)
    return dest


def import_media(image_id: str, source: str | Path, progress=None) -> Path:
    src = Path(source).expanduser()
    if image_id == "linux" and src.is_file():
        from . import linuxiso  # a Linux installer DVD: which one is read off the disc
        try:
            image_id = linuxiso.which(src)
        except linuxiso.LinuxIsoError as exc:
            raise ImageError(str(exc)) from exc
        print(f"  {src.name}: {DISTROS[image_id].short}", file=sys.stderr)
    if image_id == "firewall" and src.is_file():
        from . import bsdfw  # a firewall installer: which one is read off the disc or its name
        try:
            image_id = bsdfw.which(src)
        except bsdfw.BsdFwError as exc:
            raise ImageError(str(exc)) from exc
        print(f"  {src.name}: {FIREWALLS[image_id].short}", file=sys.stderr)
    entry = CATALOG.get(image_id)
    if entry is None:
        raise ImageError(f"unknown image {image_id!r}")

    if not src.exists():
        raise ImageError(f"not found: {src}")
    if image_id == "mecm":
        return _import_mecm(src, progress)
    if image_id in FIREWALLS:  # unpacked from .gz/.bz2 as the projects ship them
        from . import bsdfw
        try:
            return bsdfw.import_file(image_id, src, progress)
        except bsdfw.BsdFwError as exc:
            raise ImageError(str(exc)) from exc
    if entry.accepts and src.suffix.lower() not in entry.accepts:
        raise ImageError(
            f"{src.name}: expected one of {', '.join(entry.accepts)} for {image_id}"
        )

    size_gb = src.stat().st_size / (1024**3)
    if entry.min_gb and size_gb < entry.min_gb * 0.5:
        raise ImageError(
            f"{src.name} is only {size_gb:.1f} GiB; {image_id} media is normally "
            f"around {entry.min_gb:.0f} GiB -- is this a full image?"
        )

    paths.bases_dir().mkdir(parents=True, exist_ok=True)
    paths.downloads_dir().mkdir(parents=True, exist_ok=True)

    if src.suffix.lower() == ".iso" and image_id in DISTROS:
        return _import_linux(image_id, src, size_gb, progress)
    if src.suffix.lower() == ".iso":
        dest = installer_path(image_id)
        if dest.exists() and dest.samefile(src):
            return dest
        was = retired_installer(image_id)
        if was and base_path(image_id).exists() and was.get("fingerprint") == fingerprint(src):
            print(f"  {src.name} is the ISO {image_id} was prepared from and the base is "
                  f"ready; nothing to copy", file=sys.stderr)
            return base_path(image_id)
        wim_path, found = _read_media(image_id, src)
        print(f"  copying {src.name} -> {dest} ({size_gb:.1f} GiB)", file=sys.stderr)
        copy_with_progress(src, dest, progress, f"copying {src.name} ({size_gb:.1f} GiB)")
        _write_installer_meta(image_id, name=src.name, size=src.stat().st_size,
                              fingerprint=fingerprint(src), wim=wim_path, images=found)
        return dest

    dest = base_path(image_id)
    print(
        f"  converting {src.name} -> {dest.name} (qcow2, {size_gb:.1f} GiB source)",
        file=sys.stderr,
    )
    _run_img(["convert", "-p", "-O", "qcow2", str(src), str(dest)])
    return dest


def _import_linux(image_id: str, src: Path, size_gb: float, progress=None) -> Path:
    """A Linux installer DVD the user already has: checked against what the
    disc says it is, copied in, and recorded like a fetched one."""
    from . import linuxiso
    try:
        warn = linuxiso.check_import(image_id, src)
    except linuxiso.LinuxIsoError as exc:
        raise ImageError(str(exc)) from exc
    if warn:
        print(f"  note: {warn}", file=sys.stderr)
        if progress:
            progress(f"note: {warn}")
    dest = installer_path(image_id)
    if not (dest.exists() and dest.samefile(src)):
        copy_with_progress(src, dest, progress, f"copying {src.name} ({size_gb:.1f} GiB)")
    _write_installer_meta(image_id, name=src.name, size=src.stat().st_size, fingerprint=fingerprint(src),
                          holds=linuxiso.describe(src), imported=True, note=warn)
    return dest


def _import_mecm(src: Path, progress=None) -> Path:
    """Configuration Manager media is a disc winlab builds from the pieces
    (mecm.prepare); a folder holding them is prepared, a disc that already
    holds them is copied."""
    from . import mecm
    if src.is_dir():
        parts = mecm.find_parts([src])
        try:
            mecm.prepare(parts, progress=progress)
        except mecm.MecmError as exc:
            raise ImageError(str(exc)) from exc
        return installer_path("mecm")
    problems = mecm.check_iso(src)
    if problems:
        raise ImageError(f"{src.name} is not a disc winlab prepared ({'; '.join(problems)}); point "
                         "winlab at the folder with the downloads instead: winlab mecm prepare")
    dest = installer_path("mecm")
    if not (dest.exists() and dest.samefile(src)):
        copy_with_progress(src, dest, progress, f"copying {src.name}")
    _write_installer_meta("mecm", name=src.name, size=src.stat().st_size)
    return dest


def _read_media(image_id: str, src: Path) -> tuple[str, list[dict]]:
    """The images on a Windows ISO, checked against the catalog image they
    are imported as. Media that cannot be read goes through (the answer
    file then uses the stock image name); media that is readable and holds
    another Windows is refused, naming the image id that fits it."""
    entry = CATALOG[image_id]
    if not entry.kind.startswith("windows-"):
        return "", []
    from . import wim
    try:
        wim_path, found = wim.images_in_iso(src)
    except wim.WimError as exc:
        print(f"  could not read the image list ({exc}); the install will use the "
              f"stock image name", file=sys.stderr)
        return "", []
    if not found:
        return wim_path, []
    chosen = pick_edition(image_id, found)
    if chosen is None:
        fits = media_fits(found)
        held = "; ".join(wim.describe(im) for im in found[:6])
        raise ImageError(
            f"{src.name} does not hold {entry.title}: it lists {held}"
            + (f". Import it as: winlab images import {fits[0]} {src}" if fits
               else ". winlab installs Windows Server 2019, 2022 and 2025 and Windows 10 "
                    "and 11 (64-bit); for anything else, use 'winlab images add' and a "
                    "custom machine"))
    print(f"  {src.name}: {len(found)} image(s); {image_id} installs "
          f"{wim.describe(chosen)}", file=sys.stderr)
    return wim_path, found


def create_base(image_id: str, size_gb: int = 64) -> Path:
    """Blank qcow2 that an unattended install writes into."""
    dest = base_path(image_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return dest
    _run_img(["create", "-f", "qcow2", str(dest), f"{size_gb}G"])
    return dest


def clone(image_id: str, dest: Path) -> Path:
    """Copy-on-write clone of a prepared base or a template. Per-node cost is
    the delta, not a full copy."""
    src = disk_source(image_id)
    if src is None:
        if image_id not in CATALOG:
            raise ImageError(
                f"no image {image_id!r} on this PC: not a catalog image and not one of "
                f"your templates (removed?). See: winlab template list"
            )
        raise ImageError(
            f"no prepared base for {image_id!r} at {base_path(image_id)}\n"
            f"  run: winlab images prepare {image_id}"
        )
    return clone_disk(src, dest)


def resize_disk(dest: Path, size_gb: int) -> Path:
    """Grows a clone's virtual size (a cloud image ships small and grows its
    root filesystem on first boot). Never shrinks."""
    if size_gb > 0:
        _run_img(["resize", str(dest), f"{size_gb}G"])
    return dest


def clone_disk(src: Path, dest: Path) -> Path:
    """A fresh qcow2 whose backing file is src; src is never written again."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    _run_img(["create", "-f", "qcow2", "-b", str(src), "-F", "qcow2", str(dest)])
    return dest


def disk_source(image_id: str) -> Path | None:
    """The disk `lab up` clones for this image id: a template the user made,
    else the prepared base of a catalog image. None when neither exists."""
    tpl = templates().get(image_id)
    if tpl is not None:
        return tpl.disk if tpl.disk.exists() else None
    base = base_path(image_id)
    return base if base.exists() else None


def nvram_source(image_id: str) -> Path | None:
    """The UEFI variable store a new machine of this image starts from: it
    holds the Windows Boot Manager entry the install wrote."""
    tpl = templates().get(image_id)
    if tpl is not None:
        return tpl.nvram if tpl.nvram.exists() else None
    vars_fd = base_path(image_id).with_suffix(".vars.fd")
    return vars_fd if vars_fd.exists() else None


def create_data_disk(dest: Path, size_gb: int) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return dest
    _run_img(["create", "-f", "qcow2", str(dest), f"{size_gb}G"])
    return dest


# ------------------------------------------------------------ custom media
# An ISO the user brings for an operating system winlab does not install for
# them: another Linux, a firewall appliance, TrueNAS, an older Windows. The
# registry lives beside the media in the image store, never in the repo, and
# the ISO is only ever copied from the user's own disk (nothing is fetched).

CUSTOM_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
FIRMWARES = ("bios", "uefi")


@dataclass
class CustomImage:
    id: str
    title: str
    firmware: str = "bios"
    disk_gb: int = 32
    source: str = ""  # the file name the user imported, for display

    @property
    def iso(self) -> Path:
        return paths.downloads_dir() / f"{self.id}.iso"


def _custom_file() -> Path:
    return paths.images_dir() / "custom.json"


def custom_images() -> dict[str, CustomImage]:
    f = _custom_file()
    if not f.exists():
        return {}
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: CustomImage(**v) for k, v in raw.items()}


def _save_custom(entries: dict[str, CustomImage]) -> None:
    f = _custom_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({k: v.__dict__ for k, v in sorted(entries.items())},
                              indent=2), encoding="utf-8")
    tmp.replace(f)


def custom_image(image_id: str) -> CustomImage:
    found = custom_images().get(image_id)
    if found is None:
        raise ImageError(
            f"no custom image {image_id!r} on this PC\n"
            f"  add it with: winlab images add {image_id} <path-to.iso>"
        )
    return found


def add_custom(image_id: str, source: str | Path, title: str = "",
               firmware: str = "bios", disk_gb: int = 32) -> CustomImage:
    if not CUSTOM_ID.match(image_id):
        raise ImageError(
            f"{image_id!r}: use 2-32 lower-case letters, digits and dashes, starting "
            f"with a letter (for example ubuntu-24 or opnsense)"
        )
    if image_id in CATALOG:
        raise ImageError(f"{image_id!r} is a built-in image; pick another name")
    if firmware not in FIRMWARES:
        raise ImageError(f"firmware must be one of {', '.join(FIRMWARES)}")
    if not 4 <= disk_gb <= 2048:
        raise ImageError("disk_gb must be between 4 and 2048")
    src = Path(source).expanduser()
    if not src.is_file():
        raise ImageError(f"not found: {src}")
    if src.suffix.lower() != ".iso":
        raise ImageError(f"{src.name}: expected an .iso file")

    entry = CustomImage(id=image_id, title=title or src.stem, firmware=firmware,
                        disk_gb=disk_gb, source=src.name)
    paths.downloads_dir().mkdir(parents=True, exist_ok=True)
    dest = entry.iso
    if not (dest.exists() and dest.samefile(src)):
        size_gb = src.stat().st_size / (1024**3)
        print(f"  copying {src.name} -> {dest} ({size_gb:.1f} GiB)", file=sys.stderr)
        copy_with_progress(src, dest, None, f"copying {src.name} ({size_gb:.1f} GiB)")
    entries = custom_images()
    entries[image_id] = entry
    _save_custom(entries)
    return entry


def remove_custom(image_id: str) -> None:
    entries = custom_images()
    entry = entries.pop(image_id, None)
    if entry is None:
        raise ImageError(f"no custom image {image_id!r}")
    entry.iso.unlink(missing_ok=True)
    _save_custom(entries)


# ------------------------------------------------------------ hand installs
# A machine that boots Microsoft's own evaluation DVD on an empty disk: the
# student presses a key to boot from it and runs Windows Setup themselves
# (edition, Desktop Experience or Core, partitions, the Administrator
# password), then configures the server by hand. winlab runs nothing inside
# it. One per Windows release; Server Core is a choice Setup offers. The
# Linux installer DVDs (winlab/linuxiso.py) are hand installs the same way,
# and so are the firewall installers (winlab/bsdfw.py).
HAND_INSTALL = [i for i in WINDOWS_IMAGES if not i.endswith("-core")] + list(DISTROS) + list(FIREWALLS)
HAND_DISK_GB = 64


def is_hand_install(node) -> bool:
    return node.kind == "custom" and node.image in HAND_INSTALL


def hand_media(image_id: str) -> Path:
    """The Setup DVD a hand-installed machine boots: the ISO imported in
    Setup, which preparing a ready-made base removes again."""
    iso = installer_path(image_id)
    if iso.exists():
        return iso
    if image_id in DISTROS:
        from .linuxiso import missing_text
        raise ImageError(missing_text(image_id))
    if image_id in FIREWALLS:
        from .bsdfw import missing_text as fw_missing
        raise ImageError(fw_missing(image_id))
    entry = CATALOG[image_id]
    gone = retired_installer(image_id)
    raise ImageError(
        f"the {entry.short} Setup DVD is not on this PC"
        + (" (it was put away after the ready-made machine was built from it)" if gone else "")
        + f"; import the ISO again in Setup > Get Windows, or: winlab images import {image_id} <path>")


def create_blank(dest: Path, size_gb: int) -> Path:
    """An empty system disk for a machine the user installs by hand."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return dest
    _run_img(["create", "-f", "qcow2", str(dest), f"{size_gb}G"])
    return dest


# --------------------------------------------------------------- templates
# A template is a machine the user set up once and turned into an image:
# `lab up` thin-clones it the way it clones a prepared base, so a lab can
# grow from a gold file server or a tuned workstation instead of a bare
# install every time. Windows templates are generalised (sysprep), so every
# clone is a new computer; see templates.py for how they are made.

TEMPLATES_DIR = "templates"


@dataclass
class Template:
    id: str
    title: str
    kind: str                 # windows-server | windows-client | linux | custom
    image: str = ""           # the image the source machine was made from
    firmware: str = "bios"    # what the source machine booted with
    disk_gb: int = 0          # virtual size of the system disk
    cpus: int = 2
    memory_mb: int = 2048
    data_disks_gb: list[int] = field(default_factory=list)
    generalized: bool = False  # sysprep ran: clones get their own identity
    source: str = ""          # "lab/machine" it was made from
    created: float = 0.0
    description: str = ""

    @property
    def disk(self) -> Path:
        return templates_dir() / f"{self.id}.qcow2"

    @property
    def nvram(self) -> Path:
        return templates_dir() / f"{self.id}.vars.fd"

    @property
    def size_gb(self) -> float:
        """What it costs on disk (a thin template is only its delta)."""
        try:
            return self.disk.stat().st_size / (1024**3)
        except OSError:
            return 0.0

    @property
    def size_text(self) -> str:
        if not self.disk.exists():
            return "disk missing"
        gb = self.size_gb
        return f"{gb:.1f} GiB" if gb >= 1 else f"{int(gb * 1024)} MiB"


def templates_dir() -> Path:
    return paths.images_dir() / TEMPLATES_DIR


def _templates_file() -> Path:
    return paths.images_dir() / "templates.json"


def templates() -> dict[str, Template]:
    f = _templates_file()
    if not f.exists():
        return {}
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, Template] = {}
    for k, v in raw.items():
        try:
            out[k] = Template(**v)
        except TypeError:
            continue
    return out


def save_templates(entries: dict[str, Template]) -> None:
    f = _templates_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({k: v.__dict__ for k, v in sorted(entries.items())},
                              indent=2), encoding="utf-8")
    tmp.replace(f)


def template(image_id: str) -> Template:
    found = templates().get(image_id)
    if found is None:
        raise ImageError(
            f"no template {image_id!r} on this PC\n"
            f"  make one with: winlab template create <lab> <machine> {image_id}"
        )
    return found


def is_template(image_id: str) -> bool:
    return image_id in templates()


def check_template_id(image_id: str) -> None:
    if not CUSTOM_ID.match(image_id):
        raise ImageError(
            f"{image_id!r}: use 2-32 lower-case letters, digits and dashes, starting "
            f"with a letter (for example fileserver-gold or win11-tuned)"
        )
    if image_id in CATALOG:
        raise ImageError(f"{image_id!r} is a built-in image; pick another name")
    if image_id in custom_images():
        raise ImageError(f"{image_id!r} is one of your ISOs; pick another name")


def remove_template(image_id: str) -> None:
    entries = templates()
    entry = entries.pop(image_id, None)
    if entry is None:
        raise ImageError(f"no template {image_id!r}")
    for f in (entry.disk, entry.nvram, entry.disk.with_suffix(".log")):
        f.unlink(missing_ok=True)
    save_templates(entries)


def render_status() -> str:
    lines = [f"image store: {paths.images_dir()}", ""]
    for image_id in CATALOG:
        st = status(image_id)
        entry: Entry = st["entry"]  # type: ignore[assignment]
        if st["base"] and st["appliance"]:
            state = f"image fetched ({st['base_gb']:.1f} GiB, {st['fetched'] or 'date unknown'})"
        elif st["base"]:
            state = f"base ready ({st['base_gb']:.1f} GiB)"
            if st["virtio"]:
                state += ", virtio drivers"
            if st["installer_retired"]:
                state += ", ISO copy removed after preparation"
        elif st["installer"] and entry.kind in ("linux-installer", "firewall-installer"):
            state = f"installer DVD present ({st['installer_gb']:.1f} GiB): machines boot it, you install by hand"
        elif st["installer"]:
            state = f"installer present ({st['installer_gb']:.1f} GiB), not prepared"
            if st["edition"]:
                state += f"; installs {st['edition']}"
        else:
            state = "missing"
        lines.append(f"  {image_id:<12} {state}")
        lines.append(f"  {'':<12} {entry.title}")
        lines.append(f"  {'':<12} license: {entry.license}")
        if entry.mode == IMPORT and not st["base"] and not st["installer"]:
            lines.append(f"  {'':<12} get it:  {entry.page}")
            lines.append(f"  {'':<12} then:    winlab images import {image_id} <path>")
        elif entry.mode == FETCH and not st["installer"] and not st["base"]:
            lines.append(f"  {'':<12} then:    winlab images fetch {image_id}")
            if entry.kind == "linux-installer":
                lines.append(f"  {'':<12} or:      winlab images import linux <your.iso>")
            elif entry.kind == "firewall-installer":
                lines.append(f"  {'':<12} or:      winlab images import firewall <your.iso>")
        lines.append("")
    custom = custom_images()
    if custom:
        lines.append("your own media (machines with kind = \"custom\"):")
        for entry in custom.values():
            have = "present" if entry.iso.exists() else "ISO missing"
            lines.append(f"  {entry.id:<12} {entry.title}  ({entry.firmware}, "
                         f"{entry.disk_gb} GB disk, {have})")
        lines.append("")
    tpls = templates()
    if tpls:
        lines.append("your templates (machines you turned into images):")
        for t in tpls.values():
            ident = "new identity per clone" if t.generalized else "identical clones"
            lines.append(f"  {t.id:<12} {t.title}  ({t.kind}, from {t.source or '?'}, "
                         f"{t.size_text}, {ident})")
        lines.append("")
    lines.append(
        "winlab never downloads or redistributes Microsoft media; see LICENSING.md"
    )
    return "\n".join(lines)
