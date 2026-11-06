"""Filesystem layout. Everything lives under ROOT: no AppData, no registry.

ROOT is the winlab folder: the repository when running from source, the folder
that holds winlab.exe when frozen with PyInstaller. A one-file exe unpacks
itself into a temporary directory that vanishes when it exits, so nothing
writable may derive from __file__ there; only the read-only bundle (the seed
content pack, the dashboard page) is read from it, see BUNDLE.

WINLAB_HOME overrides ROOT for an install whose data lives elsewhere. The
Windows installer puts winlab.exe in a program folder winlab never writes to
and leaves winlab-home.txt beside it: one line naming the data folder the
customer chose (environment variables such as %LOCALAPPDATA% are expanded, so
an all-users install still gives each user their own). The portable zip has
no such file and keeps everything next to the exe.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
# PyInstaller's extraction directory (one-file) or the app folder (one-dir).
BUNDLE: Path | None = Path(sys._MEIPASS) if FROZEN and hasattr(sys, "_MEIPASS") else None


# Written by the installer next to winlab.exe; see the module docstring.
HOME_POINTER = "winlab-home.txt"


def read_home_pointer(exe_dir: Path, env: dict | None = None) -> Path | None:
    """The data folder an installed winlab.exe was given, or None (portable)."""
    f = exe_dir / HOME_POINTER
    try:
        text = f.read_text(encoding="utf-8-sig")
    except OSError:
        return None
    e = os.environ if env is None else env
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # %VAR% the way Windows spells it, whatever OS the tests run on.
        line = re.sub(r"%([^%]+)%", lambda m: e.get(m.group(1), e.get(m.group(1).upper(), m.group(0))), line)
        return Path(line).expanduser().resolve()
    return None


def compute_root(env: dict | None = None, exe_dir: Path | None = None,
                 frozen: bool | None = None) -> Path:
    e = os.environ if env is None else env
    override = e.get("WINLAB_HOME", "")
    if override:
        return Path(override).expanduser().resolve()
    if FROZEN if frozen is None else frozen:
        here = exe_dir or Path(sys.executable).resolve().parent
        return read_home_pointer(here, e) or here
    return Path(__file__).resolve().parent.parent


ROOT = compute_root()
# The folder holding winlab.exe (read-only when installed): the documents
# the installer put beside it live here. The checkout when run from source.
APP_DIR = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent.parent

RUNTIME = ROOT / "runtime"
CONTENT = ROOT / "content"
LABS = CONTENT / "labs"
ROLES = CONTENT / "roles"
EXERCISES = CONTENT / "exercises"
VAR = ROOT / "var"
LOGS = VAR / "logs"
STATE = VAR / "state"


def images_dir() -> Path:
    """Overridable: images are tens of GB and C: is often the smallest drive."""
    env = os.environ.get("WINLAB_IMAGES")
    if env:
        return Path(env).expanduser().resolve()
    cfg = ROOT / "winlab.local.toml"
    if cfg.exists():
        import tomllib

        with cfg.open("rb") as fh:
            data = tomllib.load(fh)
        p = data.get("store", {}).get("images")
        if p:
            return Path(p).expanduser().resolve()
    return ROOT / "images"


def bases_dir() -> Path:
    return images_dir() / "bases"


def downloads_dir() -> Path:
    return images_dir() / "downloads"


def lab_dir(lab_name: str) -> Path:
    return VAR / "labs" / lab_name


def qemu_dir() -> Path:
    # QEMU finds its BIOS/keymaps at ../share/qemu, so keep the tree layout.
    return RUNTIME / "qemu"


def uefi_firmware() -> tuple[Path, Path] | None:
    """The UEFI firmware QEMU ships (code, empty variable store), or None
    when either is missing and machines boot with the BIOS. Everything that
    decides a machine's firmware asks here, so Setup's answer file, the
    installer's boot and every later boot agree."""
    share = qemu_dir() / "share" / "qemu"
    code, varstore = share / "edk2-x86_64-code.fd", share / "edk2-i386-vars.fd"
    return (code, varstore) if code.exists() and varstore.exists() else None


def uefi_secure_firmware() -> Path | None:
    """QEMU's edk2 build with Secure Boot and System Management Mode, which
    a machine set to UEFI with Secure Boot boots (winlab/firmware.py); it
    shares the variable store layout of uefi_firmware()'s."""
    code = qemu_dir() / "share" / "qemu" / "edk2-x86_64-secure-code.fd"
    return code if code.exists() and uefi_firmware() else None


def qemu_bin() -> Path:
    return qemu_dir() / "bin"


def _exe(stem: str) -> Path:
    return qemu_bin() / (f"{stem}.exe" if os.name == "nt" else stem)


def qemu_exe() -> Path:
    return _exe("qemu-system-x86_64")


def qemu_img() -> Path:
    return _exe("qemu-img")


def writable(d: Path) -> bool:
    """Whether winlab can create files under d (Program Files is not)."""
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / f".winlab-write-{os.getpid()}"
        probe.write_text("", encoding="ascii")
        probe.unlink()
        return True
    except OSError:
        return False


def ensure_dirs() -> None:
    for d in (RUNTIME, CONTENT, LABS, ROLES, EXERCISES, VAR, LOGS, STATE):
        d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------- seed content
#
# The exe carries the content pack (labs, roles, exercises, agent) inside it,
# but the customer edits labs in place and the roles are read as files, so
# the pack is laid out next to the exe on first run. A manifest of what was
# seeded makes upgrades safe: a newer exe replaces files the customer never
# touched and leaves edited ones alone.

SEED_MANIFEST = ".seeded"


@dataclass
class SeedReport:
    added: list[Path] = field(default_factory=list)
    updated: list[Path] = field(default_factory=list)
    kept: list[Path] = field(default_factory=list)  # edited by the user, left alone
    removed: list[Path] = field(default_factory=list)  # no longer shipped, never edited

    @property
    def changed(self) -> int:
        return len(self.added) + len(self.updated)


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _read_manifest(p: Path) -> dict[str, str]:
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        digest, _, rel = line.partition("  ")
        if digest and rel:
            out[rel] = digest
    return out


def seed_content(src: Path | None = None, dest: Path | None = None) -> SeedReport:
    """Copies the bundled content pack into dest, file by file. A missing file
    is added; a file identical to the last seeded version is upgraded; a file
    the user changed is kept; a file seeded before that the bundle no longer
    has is removed when the user never changed it. Running from source there is no bundle and this
    does nothing."""
    rep = SeedReport()
    if src is None:
        if BUNDLE is None:
            return rep
        src = BUNDLE / "content"
    dest = CONTENT if dest is None else dest
    if not src.is_dir():
        return rep
    manifest_path = dest / SEED_MANIFEST
    seeded = _read_manifest(manifest_path)
    manifest: dict[str, str] = {}
    for f in sorted(src.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(src).as_posix()
        digest = _sha(f)
        manifest[rel] = digest
        target = dest / rel
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, target)
            rep.added.append(target)
            continue
        current = _sha(target)
        if current == digest:
            continue
        if seeded.get(rel) == current:
            shutil.copy2(f, target)
            rep.updated.append(target)
        else:
            rep.kept.append(target)
    # A file an older exe seeded that this one no longer ships plain (the
    # paid labs moved into content/packs/) goes, unless the user edited it.
    for rel, digest in seeded.items():
        if rel in manifest:
            continue
        target = dest / rel
        try:
            if target.is_file() and _sha(target) == digest:
                target.unlink()
                rep.removed.append(target)
        except OSError:
            pass
    dest.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        "".join(f"{d}  {r}\n" for r, d in sorted(manifest.items())), encoding="utf-8")
    return rep
