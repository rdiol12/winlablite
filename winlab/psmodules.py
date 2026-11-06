"""Fetch the PowerShell DSC resource modules the role engine compiles against.

Same posture as QEMU in bootstrap.py: winlab never bundles third-party code.
The modules are MIT-licensed, but they are still fetched from the PowerShell
Gallery onto the end user's machine at bootstrap, unpacked into ./runtime, and
zipped once so every lab machine can install them offline (lab guests have no
network path anywhere).

A .nupkg is a zip; the module is everything in it except NuGet's own metadata.
The guest expands dsc-modules.zip straight into
C:\\Program Files\\WindowsPowerShell\\Modules, which expects <Name>/<Version>/.
"""

from __future__ import annotations

import hashlib
import io
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import paths

GALLERY = "https://www.powershellgallery.com/api/v2/package/"


@dataclass(frozen=True)
class Module:
    name: str
    version: str
    purpose: str

    @property
    def url(self) -> str:
        return f"{GALLERY}{self.name}/{self.version}"

    @property
    def nupkg(self) -> str:
        return f"{self.name.lower()}.{self.version}.nupkg"


# Pinned: a role compiles against a resource schema, and schemas change between
# majors. Bump deliberately, with the configs in dsc.py.
MODULES: tuple[Module, ...] = (
    Module("ActiveDirectoryDsc", "6.4.0", "forest, domain controllers, sites, OUs, users, groups"),
    Module("DnsServerDsc", "3.0.0", "zones, forwarders, scavenging"),
    Module("DhcpServerDsc", "4.0.0", "scopes, options, reservations, authorization"),
    Module("NetworkingDsc", "9.0.0", "firewall rules, DNS client, IP addressing"),
    Module("ComputerManagementDsc", "9.0.0", "domain join, SMB shares and server settings, event logs, RDP"),
    Module("ActiveDirectoryCSDsc", "5.0.0", "enterprise certificate authority, web enrolment"),
    Module("DFSDsc", "5.2.0", "DFS namespace roots and folders"),
    Module("FSRMDsc", "2.5.0", "quotas, file screens, file groups"),
)

# NuGet packaging metadata that is not part of the module.
_NUGET_NOISE = ("_rels/", "package/", "[Content_Types].xml")

ZIP_NAME = "dsc-modules.zip"


class ModuleError(Exception):
    pass


def modules_dir() -> Path:
    return paths.RUNTIME / "psmodules"


def zip_path() -> Path:
    return modules_dir() / ZIP_NAME


def is_module_file(member: str) -> bool:
    if member.endswith("/"):
        return False
    if member.startswith(_NUGET_NOISE) or member in _NUGET_NOISE:
        return False
    if member.endswith(".nuspec") and "/" not in member:
        return False
    return True


def unpack_nupkg(data: bytes, module: Module, dest_root: Path) -> Path:
    """Lays a .nupkg out as <dest_root>/<Name>/<Version>/..., the shape the
    PowerShell module loader needs. Returns the version directory."""
    dest = dest_root / module.name / module.version
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ModuleError(f"{module.nupkg} is not a zip: {exc}") from exc
    with zf:
        names = [n for n in zf.namelist() if is_module_file(n)]
        if not any(n.lower() == f"{module.name.lower()}.psd1" for n in names):
            raise ModuleError(f"{module.nupkg} has no {module.name}.psd1 at its root")
        for n in names:
            # No zip-slip: every member lands under dest.
            target = (dest / n).resolve()
            if dest.resolve() not in target.parents:
                raise ModuleError(f"{module.nupkg}: refusing path {n!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(n))
    # The loader matches Import-DscResource -ModuleVersion against the
    # manifest, not the folder name, so a mismatch is caught here.
    got = manifest_version(dest / f"{module.name}.psd1")
    if got and got != module.version:
        raise ModuleError(
            f"{module.nupkg}: manifest says ModuleVersion {got}, expected {module.version}")
    return dest


def manifest_version(psd1: Path) -> str:
    """ModuleVersion from a .psd1. New-ModuleManifest on Windows PowerShell
    writes UTF-16 LE, so the BOM decides the decoding."""
    try:
        raw = psd1.read_bytes()
    except OSError:
        return ""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    m = re.search(r"^\s*ModuleVersion\s*=\s*['\"]([^'\"]+)['\"]", text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def build_zip(root: Path, out: Path, modules: tuple[Module, ...] = MODULES) -> Path:
    """One zip of every module, rooted at <Name>/<Version>/, for Expand-Archive
    into the guest's module path."""
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for m in modules:
            vdir = root / m.name / m.version
            if not vdir.is_dir():
                raise ModuleError(f"{m.name} {m.version} is not unpacked under {root}")
            for f in sorted(vdir.rglob("*")):
                if f.is_file():
                    zf.write(f, f"{m.name}/{m.version}/{f.relative_to(vdir).as_posix()}")
    return out


def installed() -> list[Module]:
    return [m for m in MODULES if (modules_dir() / m.name / m.version).is_dir()]


def missing() -> list[Module]:
    have = set(installed())
    return [m for m in MODULES if m not in have]


def ready() -> bool:
    return not missing() and zip_path().exists()


def fetch(refresh: bool = False) -> Path:
    """Download, unpack and zip. Idempotent; refresh re-downloads."""
    from .bootstrap import _download_to  # same retry/short-read handling

    root = modules_dir()
    cache = root / "cache"
    root.mkdir(parents=True, exist_ok=True)
    lock: list[str] = []
    for i, m in enumerate(MODULES, 1):
        vdir = root / m.name / m.version
        pkg = cache / m.nupkg
        if refresh or not vdir.is_dir():
            if refresh and pkg.exists():
                pkg.unlink()
            _download_to(m.url, pkg, label=f"[{i}/{len(MODULES)}] {m.name} {m.version}")
            data = pkg.read_bytes()
            unpack_nupkg(data, m, root)
            lock.append(f"{m.name}\t{m.version}\t{hashlib.sha256(data).hexdigest()}")
        else:
            print(f"    {m.name} {m.version}: present", file=sys.stderr)
    out = build_zip(root, zip_path())
    if lock:
        with (root / "manifest.txt").open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lock) + "\n")
    size = out.stat().st_size / (1024 ** 2)
    print(f"  dsc modules ready: {out} ({size:.1f} MiB)", file=sys.stderr)
    return out


def render_status() -> str:
    lines = ["DSC resource modules (fetched from the PowerShell Gallery, MIT-licensed):"]
    for m in MODULES:
        state = "present" if m in installed() else "missing"
        lines.append(f"  {m.name:<24} {m.version:<8} {state:<8} {m.purpose}")
    z = zip_path()
    lines.append(f"  guest bundle {ZIP_NAME}: {'present' if z.exists() else 'missing'}")
    if not ready():
        lines.append("  run 'winlab bootstrap' (or 'winlab dsc fetch') to fetch them")
    return "\n".join(lines)
