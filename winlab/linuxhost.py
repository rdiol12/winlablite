"""winlab on a Linux PC: the system's own QEMU, KVM access, file pickers.

On Windows `winlab bootstrap` unpacks a portable QEMU into ./runtime/qemu.
On Linux the distribution already packages QEMU, the edk2 UEFI firmware
and swtpm, and they are installed with the package manager (winlab never
ships them; see LICENSING.md). `link_runtime` then lays the installed
QEMU out in ./runtime/qemu the way the rest of winlab expects it, as
symbolic links:

    runtime/qemu/bin/qemu-system-x86_64   -> /usr/bin/qemu-system-x86_64
    runtime/qemu/bin/qemu-img             -> /usr/bin/qemu-img
    runtime/qemu/share/qemu/edk2-x86_64-code.fd         -> the distro's OVMF code
    runtime/qemu/share/qemu/edk2-x86_64-secure-code.fd  -> its Secure Boot build
    runtime/qemu/share/qemu/edk2-i386-vars.fd           -> its empty variable store

QEMU resolves its own data folder from the real path of the binary, so the
BIOS, option ROMs and keymaps still come from /usr/share/qemu. A distro
update of QEMU keeps the links valid; removing QEMU leaves them dangling,
and Setup then offers the step again.

The firmware is found through QEMU's firmware descriptors
(/usr/share/qemu/firmware/*.json, the interop spec every distro ships),
then through the well-known paths. winlab's NVRAM handling (secureboot.py)
needs the 4 MB OVMF layout, so only firmware whose variable store is
0x84000 bytes is taken.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import paths

VARS_SIZE = 0x84000  # the 4 MB OVMF layout; see secureboot.blank_store
DESCRIPTOR_DIRS = (Path("/etc/qemu/firmware"), Path("/usr/share/qemu/firmware"))
MANIFEST = "system-qemu.json"

# What each package manager calls QEMU (x86-64 system emulator with audio
# and VNC), qemu-img, the edk2 UEFI firmware and swtpm.
PACKAGES = {
    "debian": ("apt-get", ["install", "-y"], ["qemu-system-x86", "qemu-utils", "ovmf", "swtpm"]),
    "fedora": ("dnf", ["install", "-y"], ["qemu-system-x86-core", "qemu-img", "qemu-audio-pa",
                                          "qemu-ui-opengl", "edk2-ovmf", "swtpm"]),
    "arch": ("pacman", ["-S", "--needed", "--noconfirm"], ["qemu-desktop", "edk2-ovmf", "swtpm"]),
    "suse": ("zypper", ["--non-interactive", "install"], ["qemu-x86", "qemu-tools", "qemu-ovmf-x86_64",
                                                          "swtpm"]),
}
FAMILY_NAMES = {"debian": "Debian, Ubuntu or Mint", "fedora": "Fedora", "arch": "Arch",
                "suse": "openSUSE"}

# (code, vars, secure code) by distro layout, tried after the descriptors.
FALLBACK_FIRMWARE = (
    ("/usr/share/qemu/edk2-x86_64-code.fd", "/usr/share/qemu/edk2-i386-vars.fd",
     "/usr/share/qemu/edk2-x86_64-secure-code.fd"),
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd",
     "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
     "/usr/share/edk2/x64/OVMF_CODE.secure.4m.fd"),
    ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd",
     "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd"),
    ("/usr/share/qemu/ovmf-x86_64-4m-code.bin", "/usr/share/qemu/ovmf-x86_64-4m-vars.bin",
     "/usr/share/qemu/ovmf-x86_64-smm-4m-code.bin"),
)


class LinuxHostError(Exception):
    pass


# ------------------------------------------------------------------ distro
def os_release(text: str | None = None) -> dict[str, str]:
    if text is None:
        for p in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                text = Path(p).read_text(encoding="utf-8", errors="replace")
                break
            except OSError:
                continue
        else:
            return {}
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip():
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def family(rel: dict[str, str] | None = None) -> str:
    """debian | fedora | arch | suse | '' (unknown)."""
    rel = os_release() if rel is None else rel
    ids = [rel.get("ID", "").lower(), *rel.get("ID_LIKE", "").lower().split()]
    for i in ids:
        if i in ("debian", "ubuntu", "linuxmint", "pop", "elementary", "kali", "raspbian", "zorin"):
            return "debian"
        if i in ("fedora", "rhel", "centos", "rocky", "almalinux", "nobara"):
            return "fedora"
        if i in ("arch", "manjaro", "endeavouros", "cachyos", "garuda"):
            return "arch"
        if i.startswith("opensuse") or i in ("suse", "sles"):
            return "suse"
    return ""


def install_argv(fam: str | None = None) -> list[str]:
    """The package manager command that installs what winlab needs, without sudo."""
    fam = family() if fam is None else fam
    if fam not in PACKAGES:
        return []
    tool, verb, pkgs = PACKAGES[fam]
    return [tool, *verb, *pkgs]


def install_hint(fam: str | None = None) -> str:
    """One sentence a student can act on."""
    argv = install_argv(fam)
    if not argv:
        return ("install QEMU (the x86-64 system emulator and qemu-img), the OVMF/edk2 UEFI firmware "
                "and swtpm with your distribution's package manager, then run winlab setup again")
    return "in a terminal run: sudo " + " ".join(argv)


# ------------------------------------------------------------------ QEMU
def find_qemu(which=shutil.which) -> Path | None:
    w = which("qemu-system-x86_64")
    if w:
        return Path(w)
    # RHEL and its rebuilds ship only qemu-kvm, outside PATH.
    p = Path("/usr/libexec/qemu-kvm")
    return p if p.exists() else None


def find_img(which=shutil.which) -> Path | None:
    w = which("qemu-img")
    return Path(w) if w else None


def qemu_version(exe: Path, run=subprocess.run) -> str:
    try:
        cp = run([str(exe), "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    first = (cp.stdout or "").strip().splitlines()
    return first[0] if first else ""


@dataclass
class Firmware:
    code: Path
    vars: Path
    secure: Path | None = None


def _raw_file(m: dict, key: str) -> Path | None:
    part = m.get(key) or {}
    if (part.get("format") or "raw") != "raw" or not part.get("filename"):
        return None
    p = Path(part["filename"])
    return p if p.is_file() else None


def _vars_ok(p: Path | None) -> bool:
    try:
        return p is not None and p.stat().st_size == VARS_SIZE
    except OSError:
        return False


def _descriptors(dirs=DESCRIPTOR_DIRS) -> list[dict]:
    """Descriptors by file name, /etc overriding /usr/share, in the spec's order."""
    by_name: dict[str, Path] = {}
    for d in reversed(dirs):
        try:
            for f in d.glob("*.json"):
                by_name[f.name] = f
        except OSError:
            continue
    out = []
    for name in sorted(by_name):
        try:
            out.append(json.loads(by_name[name].read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out


def find_firmware(dirs=DESCRIPTOR_DIRS, fallbacks=FALLBACK_FIRMWARE) -> Firmware | None:
    plain: tuple[Path, Path] | None = None
    secure: Path | None = None
    for d in _descriptors(dirs):
        if "uefi" not in (d.get("interface-types") or []):
            continue
        m = d.get("mapping") or {}
        if m.get("device") != "flash":
            continue
        if not any(t.get("architecture") == "x86_64"
                   and any("q35" in mm for mm in t.get("machines") or []) for t in d.get("targets") or []):
            continue
        feats = set(d.get("features") or [])
        # Confidential-computing builds (SEV-ES/SNP, TDX) and stateless ones are not for labs.
        if feats & {"amd-sev-es", "amd-sev-snp", "intel-tdx"} or m.get("mode", "split") != "split":
            continue
        code, nv = _raw_file(m, "executable"), _raw_file(m, "nvram-template")
        if code is None or not _vars_ok(nv):
            continue
        # The keys winlab enrolls itself (secureboot.py), so an empty store.
        if "enrolled-keys" in feats:
            continue
        if "secure-boot" in feats:
            secure = secure or code
        elif plain is None:
            plain = (code, nv)
    if plain is None:
        for c, v, s in fallbacks:
            cp, vp = Path(c), Path(v)
            if cp.is_file() and _vars_ok(vp):
                plain = (cp, vp)
                if secure is None and Path(s).is_file():
                    secure = Path(s)
                break
    if plain is None:
        return None
    return Firmware(plain[0], plain[1], secure)


def _link(dest: Path, src: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink() or dest.exists():
        dest.unlink()
    dest.symlink_to(src)


def missing_parts(which=shutil.which) -> list[str]:
    out = []
    if find_qemu(which) is None:
        out.append("QEMU (qemu-system-x86_64)")
    if find_img(which) is None:
        out.append("qemu-img")
    if find_firmware() is None:
        out.append("the UEFI firmware (OVMF/edk2, 4 MB build)")
    return out


def link_runtime(target: Path | None = None, say=lambda _m: None) -> Path:
    """Lays the installed QEMU out in runtime/qemu; returns the emulator's link.
    Raises LinuxHostError naming what to install when something is missing."""
    qemu, img = find_qemu(), find_img()
    if qemu is None or img is None:
        gone = [n for n, p in (("QEMU", qemu), ("qemu-img", img)) if p is None]
        raise LinuxHostError(f"{' and '.join(gone)} not installed on this PC: {install_hint()}")
    fw = find_firmware()
    target = target or paths.qemu_dir()
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.exists():
        shutil.rmtree(target, ignore_errors=True)
    bin_dir, share = target / "bin", target / "share" / "qemu"
    _link(bin_dir / "qemu-system-x86_64", qemu)
    _link(bin_dir / "qemu-img", img)
    say(f"QEMU: {qemu}")
    if fw:
        _link(share / "edk2-x86_64-code.fd", fw.code)
        _link(share / "edk2-i386-vars.fd", fw.vars)
        say(f"UEFI firmware: {fw.code}")
        if fw.secure:
            _link(share / "edk2-x86_64-secure-code.fd", fw.secure)
            say(f"Secure Boot firmware: {fw.secure}")
    else:
        share.mkdir(parents=True, exist_ok=True)
        say("no 4 MB UEFI firmware found: machines start with the BIOS until it is installed "
            f"({install_hint()})")
    (target / MANIFEST).write_text(json.dumps({
        "qemu": str(qemu), "qemu_img": str(img), "version": qemu_version(qemu),
        "firmware": {"code": str(fw.code), "vars": str(fw.vars),
                     "secure": str(fw.secure) if fw.secure else ""} if fw else {},
    }, indent=2), encoding="utf-8")
    return bin_dir / "qemu-system-x86_64"


def linked_info(target: Path | None = None) -> dict:
    try:
        return json.loads(((target or paths.qemu_dir()) / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# ------------------------------------------------------------------ privileges
def has_desktop(env: dict | None = None) -> bool:
    env = os.environ if env is None else env
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def pkexec(argv: list[str], run=subprocess.run, timeout: int = 1800) -> tuple[bool, str]:
    """Runs argv as root after the desktop's own password prompt (polkit),
    the Linux counterpart of Windows asking for permission."""
    exe = shutil.which("pkexec")
    if not exe:
        return False, "pkexec is not installed"
    try:
        cp = run([exe, *argv], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if cp.returncode == 0:
        return True, ""
    if cp.returncode in (126, 127):
        return False, "permission was not given"
    tail = ((cp.stdout or "") + (cp.stderr or "")).strip().splitlines()
    return False, tail[-1][:300] if tail else f"exit {cp.returncode}"


def install_packages(say=print, run=subprocess.run) -> bool:
    argv = install_argv()
    if not argv:
        say(f"winlab does not know this distribution's package manager: {install_hint('')}")
        return False
    if not has_desktop() or not shutil.which("pkexec"):
        say(f"winlab needs QEMU installed first: {install_hint()}")
        return False
    say("asking for your password to install QEMU, the UEFI firmware and swtpm: " + " ".join(argv))
    if argv[0] == "apt-get":
        pkexec(["apt-get", "update"], run=run, timeout=600)
    ok, why = pkexec(argv, run=run)
    if not ok:
        say(f"installing did not finish ({why}); {install_hint()}")
    return ok


# ------------------------------------------------------------------ KVM
def kvm_state(dev: Path = Path("/dev/kvm")) -> str:
    """'ok', 'no-access' (the device is there, this user cannot open it) or 'missing'."""
    if not dev.exists():
        return "missing"
    return "ok" if os.access(str(dev), os.R_OK | os.W_OK) else "no-access"


def user_name() -> str:
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, AttributeError):
        return os.environ.get("USER", "")


def grant_kvm(say=print, run=subprocess.run) -> bool:
    """Adds this user to the kvm group (polkit asks for the password). It
    takes effect at the next sign-in."""
    user = user_name()
    if not user:
        say("could not tell this user's name")
        return False
    ok, why = pkexec(["usermod", "-aG", "kvm", user], run=run, timeout=300)
    if ok:
        (paths.VAR / KVM_MARKER).parent.mkdir(parents=True, exist_ok=True)
        (paths.VAR / KVM_MARKER).write_text(user, encoding="utf-8")
        say(f"{user} is now in the kvm group: sign out and back in (or restart), then open winlab again")
    else:
        say(f"could not add {user} to the kvm group ({why}); in a terminal run: sudo usermod -aG kvm {user}")
    return ok


KVM_MARKER = "kvm-group-requested"


def kvm_pending() -> bool:
    return (paths.VAR / KVM_MARKER).exists()


# ------------------------------------------------------------------ file pickers
def _picker_argv(kind: str, title: str, start: str, which=shutil.which) -> list[str]:
    start_dir = start.rstrip("/") + "/" if start else ""
    if which("zenity"):
        argv = ["zenity", "--file-selection", f"--title={title}"]
        if kind == "folder":
            argv.append("--directory")
        else:
            argv += ["--file-filter=Disk images (*.iso) | *.iso *.ISO", "--file-filter=All files | *"]
        if start_dir:
            argv.append(f"--filename={start_dir}")
        return argv
    if which("kdialog"):
        if kind == "folder":
            return ["kdialog", "--title", title, "--getexistingdirectory", start or str(Path.home())]
        return ["kdialog", "--title", title, "--getopenfilename", start or str(Path.home()),
                "Disk images (*.iso *.ISO)\nAll files (*)"]
    if which("yad"):
        argv = ["yad", "--file", f"--title={title}"]
        if kind == "folder":
            argv.append("--directory")
        if start_dir:
            argv.append(f"--filename={start_dir}")
        return argv
    return []


def pick(kind: str, title: str, start: str = "", run=subprocess.run, which=shutil.which) -> str:
    """The desktop's own Open dialog (GNOME's through zenity, KDE's through
    kdialog); '' when cancelled, RuntimeError when none can open."""
    argv = _picker_argv(kind, title, start, which)
    if not argv:
        raise RuntimeError("no file dialog on this PC (install zenity or kdialog); type the path instead")
    try:
        cp = run(argv, capture_output=True, timeout=3600)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"the file dialog did not open ({exc}); type the path instead") from exc
    out = (cp.stdout or b"").decode("utf-8", "replace").strip().splitlines()
    if cp.returncode == 0 and out:
        return out[0].strip()
    if cp.returncode in (0, 1):
        return ""  # cancelled
    err = (cp.stderr or b"").decode("utf-8", "replace").strip().splitlines()
    raise RuntimeError("the file dialog did not open" + (f" ({err[0][:200]})" if err else "")
                       + "; type the path instead")
