r"""virtio-win guest drivers: fetched from Red Hat onto the customer's PC.

A Windows machine on QEMU can talk to its network card and disk through the
emulated Intel e1000e and AHCI devices, which cost the host CPU on every
packet and every block, or through virtio, which hands the work to the host
in bulk. Windows has no virtio drivers of its own; Red Hat publishes signed
ones (the virtio-win project). Like QEMU, the DSC modules and noVNC they are
never bundled: `winlab virtio fetch` downloads the stable ISO on this PC,
keeps the three drivers winlab uses, for each Windows version the catalog
has, under runtime/virtio-win with the project's licence file, and removes
the ISO.

`images prepare` then stages the drivers on the preparation data disk,
boots the installer with a virtio NIC, a virtio disk and a balloon device
present, and installs the drivers right before sysprep, so the sealed base
boots from a virtio disk and the base's metadata says so. The QEMU provider
reads that flag: a machine whose base has the drivers gets virtio devices,
any other keeps the emulated ones.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import paths
from .iso9660 import Iso, IsoError

URL = ("https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/"
       "stable-virtio/virtio-win.iso")
PROJECT = "https://github.com/virtio-win/virtio-win-pkg-scripts"
USER_AGENT = "winlab/0.2"
# Package directory on the ISO -> the device it drives. These three go into
# every prepared base; the rest of the ISO's packages are kept too, for the
# driver stick a machine can plug in (viogpudo, qxldod, vioinput, viorng,
# vioscsi, pvpanic, qemufwcfg...), as is Red Hat's installer.
PACKAGES = {"NetKVM": "network", "viostor": "system disk", "Balloon": "memory balloon"}
# Red Hat's own driver installer, from the ISO's root.
ROOT_FILES = ("virtio-win-guest-tools.exe", "virtio-win-gt-x64.msi")
# The ISO's per-Windows directories each base takes its drivers from, newest
# first. A driver built for an older Windows installs on a newer one (its INF
# names the lowest build it accepts), never the other way round, so each
# image takes the first of its own directories that the ISO carries; a Server
# Core image takes its Desktop sibling's.
IMAGE_DIRS = {
    "ws2025": ("2k25", "2k22", "2k19"),
    "ws2022": ("2k22", "2k19"),
    "ws2019": ("2k19", "2k16"),
    "win11": ("w11", "w10"),
    "win10": ("w10",),
}
# Every directory extract keeps, in that order.
ALL_DIRS = tuple(dict.fromkeys(d for dirs in IMAGE_DIRS.values() for d in dirs))
ARCH = "amd64"
KEEP = (".inf", ".sys", ".cat", ".dll", ".exe")   # not the .pdb debug symbols
LICENSE_FILES = ("virtio-win_license.txt",)

# The guest-side installer, staged on the preparation data disk next to the
# drivers and run as the logon step before the base trim and sysprep.
FILE = "winlab-virtio.ps1"
LOG = r"C:\winlab\virtio.log"
SCRIPT = r"""# winlab: install the virtio drivers staged on the data volume, before sysprep.
$ErrorActionPreference = 'Continue'
$log = 'C:\winlab\virtio.log'
New-Item -ItemType Directory -Path 'C:\winlab' -Force | Out-Null
"$(Get-Date -Format s) virtio driver install" | Add-Content $log
$vol = Get-Volume -FileSystemLabel 'WLDATA' -ErrorAction SilentlyContinue |
    Where-Object DriveLetter | Select-Object -First 1
if (-not $vol) { 'no WLDATA volume found' | Add-Content $log; exit 0 }
$src = "$($vol.DriveLetter):\"
foreach ($inf in Get-ChildItem -Path $src -Filter *.inf -ErrorAction SilentlyContinue) {
    "adding $($inf.Name)" | Add-Content $log
    & pnputil.exe /add-driver $inf.FullName /install 2>&1 | Out-String | Add-Content $log
}
& pnputil.exe /enum-drivers 2>&1 | Out-String | Add-Content $log
"$(Get-Date -Format s) done" | Add-Content $log
"""


class VirtioError(Exception):
    pass


def command() -> str:
    return (f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
            f"C:\\winlab\\{FILE}")


def virtio_dir() -> Path:
    return paths.RUNTIME / "virtio-win"


def manifest_path() -> Path:
    return virtio_dir() / "manifest.json"


def manifest() -> dict:
    p = manifest_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def dirs_for(image_id: str) -> tuple[str, ...]:
    base = image_id[:-5] if image_id.endswith("-core") else image_id
    return IMAGE_DIRS.get(base, ())


def _complete(d: str, pkg: str, info: dict) -> bool:
    files = info.get("files", [])
    return (bool(files) and any(f.lower().endswith(".inf") for f in files)
            and all((virtio_dir() / d / pkg / f).exists() for f in files))


def chosen_dirs(image_id: str) -> dict[str, str]:
    """Package -> the ISO directory this image's driver for it came from:
    the newest of the image's directories that is complete on disk. A
    package with none is missing from the result."""
    dirs = manifest().get("dirs") or {}
    out: dict[str, str] = {}
    for pkg in PACKAGES:
        for d in dirs_for(image_id):
            info = (dirs.get(d) or {}).get(pkg)
            if info and _complete(d, pkg, info):
                out[pkg] = d
                break
    return out


def ready(image_id: str) -> bool:
    """Whether every driver winlab uses is on disk for this image."""
    return set(chosen_dirs(image_id)) == set(PACKAGES)


def files_for(image_id: str) -> dict[str, bytes]:
    """The driver files for one image, flat, as the FAT data disk carries
    them (its root holds everything; the names do not collide)."""
    dirs = manifest().get("dirs") or {}
    out: dict[str, bytes] = {}
    for pkg, d in chosen_dirs(image_id).items():
        for f in dirs[d][pkg].get("files", []):
            if f in out:
                raise VirtioError(f"driver file name {f} appears twice")
            out[f] = (virtio_dir() / d / pkg / f).read_bytes()
    return out


def stick_tree(image_id: str) -> dict[str, bytes]:
    """Everything a driver stick for this Windows carries, laid out like the
    ISO (package/version/amd64/files) so vendor instructions and
    `pnputil /add-driver *.inf /subdirs /install` apply as written: every
    package the ISO had for the version, Red Hat's installer, the licence."""
    m = manifest()
    dirs = m.get("dirs") or {}
    out: dict[str, bytes] = {}
    done: set[str] = set()
    for d in dirs_for(image_id):
        for pkg, info in (dirs.get(d) or {}).items():
            if pkg in done:
                continue   # the newest directory of each package, only
            done.add(pkg)
            for f in info.get("files", []):
                src = virtio_dir() / d / pkg / f
                if src.exists():
                    out[f"{pkg}/{d}/{ARCH}/{f}"] = src.read_bytes()
    for name in list(m.get("tools") or []) + list(m.get("licence_files") or []):
        src = virtio_dir() / name
        if src.exists():
            out[name] = src.read_bytes()
    return out


def summary(image_id: str) -> dict:
    return {"version": manifest().get("version", ""), "dirs": chosen_dirs(image_id)}


# ------------------------------------------------------------------ extract
def extract(iso_path: str | Path, dest: Path | None = None, progress=None,
            source: str = "", version: str = "") -> dict:
    """Copies the drivers winlab uses out of a virtio-win ISO into
    runtime/virtio-win and writes the manifest. Returns the manifest."""
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    dest = dest or virtio_dir()
    try:
        iso = Iso(iso_path)
    except (OSError, IsoError) as exc:
        raise VirtioError(f"cannot read {iso_path}: {exc}") from exc
    with iso:
        dirs: dict[str, dict] = {}
        packages = sorted({e.name for e in iso.listdir("") if e.is_dir
                           and any(iso.exists(f"{e.name}/{d}/{ARCH}") for d in ALL_DIRS)},
                          key=lambda n: (n not in PACKAGES, n.lower()))
        for d in ALL_DIRS:
            for pkg in packages:
                if not iso.exists(f"{pkg}/{d}/{ARCH}"):
                    continue
                names = [e.name for e in iso.listdir(f"{pkg}/{d}/{ARCH}")
                         if not e.is_dir and e.name.lower().endswith(KEEP)]
                if not any(n.lower().endswith(".inf") for n in names):
                    if pkg in PACKAGES:
                        raise VirtioError(f"{pkg}/{d}/{ARCH} on the ISO has no .inf")
                    continue
                target = dest / d / pkg
                target.mkdir(parents=True, exist_ok=True)
                for n in names:
                    (target / n).write_bytes(iso.read(f"{pkg}/{d}/{ARCH}/{n}"))
                dirs.setdefault(d, {})[pkg] = {"files": sorted(names)}
                say(f"{d}: {pkg} from {pkg}/{d}/{ARCH} ({len(names)} files)")
        for image_id, candidates in IMAGE_DIRS.items():
            for pkg in PACKAGES:
                if not any(pkg in dirs.get(d, {}) for d in candidates):
                    raise VirtioError(
                        f"{Path(iso_path).name} has no {pkg} driver for {image_id} (none of "
                        f"{', '.join(candidates)}); is it a virtio-win ISO?")
        licences = []
        for name in LICENSE_FILES:
            if iso.exists(name):
                (dest / name).write_bytes(iso.read(name))
                licences.append(name)
        tools = []
        for name in ROOT_FILES:
            if iso.exists(name):
                (dest / name).write_bytes(iso.read(name))
                tools.append(name)
                say(f"kept {name} (Red Hat's driver installer)")
        if not version:
            m = re.search(r"virtio-win-(\d+\.\d+\.\d+(?:-\d+)?)", str(iso_path) + " " + source)
            version = m.group(1) if m else iso.volume_id()
    man = {
        "version": version,
        "source": source or str(iso_path),
        "project": PROJECT,
        "fetched": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "licence_files": licences,
        "tools": tools,
        "dirs": dirs,
    }
    dest.mkdir(parents=True, exist_ok=True)
    tmp = (dest / "manifest.json").with_suffix(".json.tmp")
    tmp.write_text(json.dumps(man, indent=2), encoding="utf-8")
    tmp.replace(dest / "manifest.json")
    say(f"virtio-win {version}: drivers ready in {dest}")
    return man


# -------------------------------------------------------------------- fetch
def _download(url: str, dest: Path, progress) -> tuple[Path, str]:
    """Streams the ISO with a percentage line every few percent (the desktop's
    job bar reads it); returns the file and the URL it finally came from."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last = -5
    try:
        with urllib.request.urlopen(req, timeout=180) as resp, tmp.open("wb") as fh:
            final = resp.geturl()
            expect = int(resp.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if expect:
                    pct = int(100 * done / expect)
                    if pct >= last + 5:
                        last = pct
                        progress(f"downloading virtio-win.iso {pct}% ({done >> 20} of {expect >> 20} MiB)")
    except (urllib.error.URLError, OSError) as exc:
        tmp.unlink(missing_ok=True)
        raise VirtioError(f"cannot fetch {url}: {exc}") from exc
    if expect and done != expect:
        tmp.unlink(missing_ok=True)
        raise VirtioError(f"short download: {done} of {expect} bytes")
    tmp.replace(dest)
    return dest, final


def fetch(refresh: bool = False, keep_iso: bool = False, progress=None) -> dict:
    """Downloads the stable virtio-win ISO, extracts the drivers, and removes
    the ISO (about 600 MB) unless asked to keep it. Nothing to do when the
    drivers are already there."""
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    if not refresh and all(ready(i) for i in IMAGE_DIRS):
        m = manifest()
        say(f"virtio-win {m.get('version', '')} already fetched")
        return m
    iso = paths.downloads_dir() / "virtio-win.iso"
    if iso.exists() and not refresh:
        say(f"using the virtio-win ISO already in {iso.parent}")
        final = str(iso)
    else:
        say(f"fetching {URL}")
        iso, final = _download(URL, iso, say)
    m = re.search(r"virtio-win-(\d+\.\d+\.\d+(?:-\d+)?)", final)
    man = extract(iso, progress=say, source=final, version=m.group(1) if m else "")
    if not keep_iso:
        iso.unlink(missing_ok=True)
        say("ISO removed; the drivers winlab needs are kept")
    return man


def import_iso(path: str | Path, progress=None) -> dict:
    """The same from a virtio-win ISO the user downloaded themselves."""
    p = Path(path)
    if not p.exists():
        raise VirtioError(f"no such file: {p}")
    return extract(p, progress=progress, source=str(p))


def render_status() -> str:
    m = manifest()
    if not m:
        return ("virtio-win drivers: not fetched\n"
                "  winlab virtio fetch        (about 600 MB once; the ISO is removed after)\n"
                f"  or: winlab virtio import <virtio-win.iso>\n"
                f"  source: {URL}")
    lines = [f"virtio-win {m.get('version', '?')} in {virtio_dir()}  (fetched {m.get('fetched', '?')})"]
    for image_id in IMAGE_DIRS:
        got = chosen_dirs(image_id)
        ok = "ready" if ready(image_id) else "incomplete: fetch again"
        parts = ", ".join(f"{pkg} ({got[pkg]})" for pkg in PACKAGES if pkg in got) or "nothing"
        lines.append(f"  {image_id:<8} {ok}: {parts}")
    if m.get("licence_files"):
        lines.append(f"  licence: {', '.join(m['licence_files'])} alongside the drivers")
    return "\n".join(lines)
