"""First run, for a student rather than an engineer.

`winlab doctor` reports what an engineer needs; this module turns the same
probe into a short checklist a student can act on (each item says what it
means and, where winlab can do it, offers the fix), finds the Windows ISO the
student downloaded, and opens the native file picker. The one-click download
and preparation of everything else is Dashboard.stream_get_ready (webui.py),
which `winlab setup` runs in the console too.

Nothing here changes the PC without the student pressing a button: turning
on Windows Hypervisor Platform asks Windows for permission (UAC), and a
restart is always the student's own click.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from . import hostprobe, paths

# The first Windows build winlab supports: tar with zstd (bsdtar) and WHPX
# both arrived by Windows 10 1809. The installer refuses anything older.
MIN_WINDOWS_BUILD = 17763
# A Windows evaluation ISO is 4.5-6 GiB; anything far smaller is not one.
ISO_MIN_BYTES = 2 * 1024 ** 3
# Downloads, in the Explorer "User Shell Folders" key (it may be moved off C:).
DOWNLOADS_GUID = "{374DE290-123F-4565-9164-39C4925E467B}"
# Marker: the student turned Windows Hypervisor Platform on and still owes a restart.
WHP_MARKER = "hypervisor-platform-requested"
# What the one-time downloads reach first (the QEMU runtime's package mirror).
INTERNET_PROBE = "https://repo.msys2.org/"


def _check(cid: str, title: str, status: str, detail: str, fix: str = "", fix_label: str = "") -> dict:
    return {"id": cid, "title": title, "status": status, "detail": detail,
            "fix": fix, "fix_label": fix_label}


def internet_ok(url: str = INTERNET_PROBE, timeout: float = 5.0) -> bool:
    import urllib.request
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "winlab"})
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:  # noqa: BLE001 any failure means "not now"
        return False


def _whp_pending() -> bool:
    return (paths.VAR / WHP_MARKER).exists()


def checks(report: hostprobe.HostReport | None = None, online: bool | None = None,
           windows: bool | None = None, linux: bool | None = None) -> list[dict]:
    """The PC checklist: one entry per thing a student may have to act on,
    status ok | warn | fail, in plain words, with the fix winlab can run."""
    r = report or hostprobe.probe()
    on_windows = (os.name == "nt") if windows is None else windows
    on_linux = (sys.platform.startswith("linux") and not on_windows) if linux is None else linux
    out: list[dict] = []

    if on_windows:
        b = r.windows_build
        if b and b < MIN_WINDOWS_BUILD:
            out.append(_check("windows", "Windows 10 or 11, 64-bit", "fail",
                              f"This PC runs Windows build {b}; winlab needs Windows 10 version 1809 "
                              f"(build {MIN_WINDOWS_BUILD}) or later. Update Windows, then open winlab again."))
        else:
            out.append(_check("windows", "Windows 10 or 11, 64-bit", "ok",
                              "Any edition works, Home included."))

        if r.virt_firmware is False:
            out.append(_check(
                "virtualization", "Virtualization is on in the BIOS/UEFI", "fail",
                "It is off, so the machines cannot run. Press the button to restart into the PC's "
                "BIOS/UEFI settings. There, turn on the option called Intel Virtualization Technology "
                "(VT-x), SVM Mode or AMD-V, save and exit, then open winlab again.",
                "firmware", "Restart into BIOS/UEFI settings"))
        else:
            out.append(_check("virtualization", "Virtualization is on in the BIOS/UEFI", "ok",
                              "The processor's virtualization support is on."
                              if r.virt_firmware else "Windows did not say; the next check decides."))

        if r.hypervisor_platform:
            if _whp_pending():
                try:
                    (paths.VAR / WHP_MARKER).unlink()
                except OSError:
                    pass
            out.append(_check("hypervisor-platform", "Windows Hypervisor Platform is on", "ok",
                              "Machines run at near full speed."))
        elif _whp_pending():
            out.append(_check("hypervisor-platform", "Windows Hypervisor Platform is on", "warn",
                              "Turned on: restart the PC to finish, then open winlab again. "
                              "Until then machines would run very slowly.",
                              "restart", "Restart now"))
        else:
            out.append(_check(
                "hypervisor-platform", "Windows Hypervisor Platform is on", "warn",
                "It is off, so machines would run very slowly. Press the button and winlab turns "
                "it on: Windows asks for permission, then restart the PC.",
                "enable-whp", "Turn it on"))
    elif on_linux:
        out += linux_checks(r)
    else:
        accel = r.accel in (hostprobe.ACCEL_KVM, hostprobe.ACCEL_HVF)
        out.append(_check("acceleration", "Fast machines (hardware virtualization)", "ok" if accel else "warn",
                          f"On ({r.accel}): machines run at near full speed." if accel else
                          "Off, so machines run very slowly. Turn on virtualization (Intel VT-x or "
                          "AMD-V) in the PC's BIOS/UEFI settings."))

    gb = r.ram_gb
    if gb >= hostprobe.COMFORT_RAM_GB - 0.6:  # a "16 GB" PC reports a little under
        out.append(_check("memory", "Memory", "ok", f"{gb:.0f} GB: enough to run any lab whole."))
    elif gb >= hostprobe.MIN_RAM_GB - 0.6:
        out.append(_check("memory", "Memory", "warn",
                          f"{gb:.0f} GB: enough for one lesson's machines at a time (the Lab guide "
                          f"starts only those). The Low-memory switch in the Start menu helps further."))
    else:
        out.append(_check("memory", "Memory", "fail",
                          f"{gb:.1f} GB: winlab needs 8 GB to run a domain controller and one more "
                          f"machine. A single machine may still start."))

    if r.cores >= hostprobe.MIN_CORES:
        out.append(_check("cpu", "Processor", "ok", f"{r.cores} processor cores."))
    else:
        out.append(_check("cpu", "Processor", "warn",
                          f"{r.cores} processor cores; 4 or more keep two machines running smoothly."))

    store = paths.images_dir()
    free = r.free_gb
    if not r.root_writable:
        out.append(_check("disk", "Room for the machines", "fail",
                          f"winlab cannot write to {paths.ROOT}. Run the installer again and pick "
                          f"a data folder you own."))
    elif free >= hostprobe.MIN_FREE_GB:
        out.append(_check("disk", "Room for the machines", "ok",
                          f"{free:.0f} GB free for the machines ({store})."))
    elif free >= hostprobe.SERVER_ONLY_FREE_GB:
        out.append(_check("disk", "Room for the machines", "warn",
                          f"{free:.0f} GB free: enough for labs with server machines only. Labs with a "
                          f"Windows 11 PC need about {hostprobe.MIN_FREE_GB:.0f} GB, so free some space before those."))
    else:
        out.append(_check("disk", "Room for the machines", "fail",
                          f"{free:.0f} GB free in {store}; winlab needs at least "
                          f"{hostprobe.SERVER_ONLY_FREE_GB:.0f} GB. Free some space, or run the "
                          f"installer again and pick a data folder on a bigger drive."))

    if online is None:
        online = internet_ok()
    out.append(_check("internet", "Internet, for the one-time downloads",
                      "ok" if online else "warn",
                      "Reachable. After setup the labs run with no internet at all." if online else
                      "Not connected right now. Setup needs it once, to download about 1 GB plus Windows; "
                      "after that the labs work with no internet."))
    return out


def linux_checks(r: hostprobe.HostReport, kvm: str | None = None, missing: list[str] | None = None) -> list[dict]:
    """A Linux PC's part of the checklist: KVM, and QEMU from the distribution."""
    from . import linuxhost
    out: list[dict] = []
    kvm = linuxhost.kvm_state() if kvm is None else kvm
    title = "Fast machines (KVM)"
    if kvm == "ok":
        out.append(_check("kvm", title, "ok", "KVM is on and yours to use: machines run at near full speed."))
    elif kvm == "no-access":
        if linuxhost.kvm_pending():
            out.append(_check("kvm", title, "warn",
                              "You were added to the kvm group: sign out and back in (or restart the PC), "
                              "then open winlab again. Until then machines would run very slowly."))
        else:
            out.append(_check("kvm", title, "warn",
                              "KVM is on, but your user may not use it yet, so machines would run very slowly. "
                              "Press the button and winlab adds you to the kvm group (it asks for your "
                              "password), then sign out and back in.", "kvm-access", "Give me access"))
    else:
        out.append(_check("kvm", title, "fail",
                          "There is no /dev/kvm, so machines would run very slowly. Turn on Intel "
                          "Virtualization Technology (VT-x), SVM Mode or AMD-V in the PC's BIOS/UEFI "
                          "settings. If it is on already, load the module: sudo modprobe kvm_intel "
                          "(kvm_amd on AMD). Inside another virtual machine, turn on nested virtualization."))
    missing = linuxhost.missing_parts() if missing is None else missing
    if not missing:
        out.append(_check("qemu", "QEMU from your distribution", "ok",
                          "Installed. winlab uses it as it is and installs nothing of its own system-wide."))
    else:
        argv = linuxhost.install_argv()
        can = bool(argv) and linuxhost.has_desktop()
        parts = ", ".join(missing)
        # one sentence each, so the desktop's translation finds it whole
        if can:
            detail = (f"Not installed yet: {parts}. Press the button and winlab installs it with your package "
                      f"manager (it asks for your password), or let Get everything ready do it.")
        elif argv:
            detail = f"Not installed yet: {parts}. In a terminal run: sudo {' '.join(argv)}."
        else:
            detail = (f"Not installed yet: {parts}. Install QEMU (the x86-64 system emulator and qemu-img), the "
                      f"OVMF/edk2 UEFI firmware and swtpm with your distribution's package manager, then run "
                      f"winlab setup again.")
        out.append(_check("qemu", "QEMU from your distribution", "warn", detail,
                          "install-qemu" if can else "", "Install QEMU" if can else ""))
    return out


def summary(items: list[dict]) -> str:
    """ok | warn | fail: the worst status in the checklist."""
    st = {i["status"] for i in items}
    return "fail" if "fail" in st else "warn" if "warn" in st else "ok"


# ------------------------------------------------------------------ the fixes

def _powershell(script: str, timeout: int = 600) -> subprocess.CompletedProcess:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=timeout, creationflags=flags)


def _encode(script: str) -> str:
    """For powershell -EncodedCommand: no quoting survives two shells intact."""
    import base64
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _elevated(command: str, args: list[str], timeout: int = 900) -> tuple[bool, str]:
    """Runs a program as administrator: Windows shows its own permission
    prompt (UAC). Declining it is an ordinary 'no', not an error."""
    quoted = ",".join("'" + a.replace("'", "''") + "'" for a in args)
    script = (f"try {{ $p = Start-Process -FilePath '{command}' -ArgumentList {quoted} -Verb RunAs "
              f"-WindowStyle Hidden -Wait -PassThru -ErrorAction Stop; exit $p.ExitCode }} "
              f"catch {{ Write-Output $_.Exception.Message; exit 1223 }}")
    try:
        cp = _powershell(script, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if cp.returncode == 1223:
        return False, "Windows did not get permission (the prompt was declined or closed)."
    # 3010: done, restart required.
    return cp.returncode in (0, 3010), (cp.stdout + cp.stderr).strip()[-300:]


def enable_hypervisor_platform(emit=print) -> bool:
    """Turns on the Windows Hypervisor Platform optional feature (what QEMU's
    WHPX accelerator runs on). Needs administrator rights, so Windows asks;
    takes a minute; the PC must restart afterwards."""
    if os.name != "nt":
        raise RuntimeError("Windows Hypervisor Platform is a Windows feature")
    emit("asking Windows for permission to turn on Windows Hypervisor Platform…")
    ok, detail = _elevated("powershell.exe", [
        "-NoProfile", "-EncodedCommand", _encode(
            "$ErrorActionPreference = 'Stop'; "
            "Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart | Out-Null; "
            "exit 3010")])
    if not ok:
        raise RuntimeError(detail or "turning the feature on failed")
    paths.VAR.mkdir(parents=True, exist_ok=True)
    (paths.VAR / WHP_MARKER).write_text(time.strftime("%Y-%m-%d %H:%M:%S"), encoding="ascii")
    emit("Windows Hypervisor Platform is on; restart the PC to finish")
    return True


def restart(firmware: bool = False) -> tuple[bool, str]:
    """Restarts the PC in 15 seconds; into its UEFI settings when firmware is
    set (Windows needs administrator rights for that, so it asks)."""
    if os.name != "nt":
        return False, "restart the computer yourself"
    if firmware:
        ok, detail = _elevated("shutdown.exe", ["/r", "/fw", "/t", "15"], timeout=120)
        return ok, ("restarting into the firmware settings in 15 seconds" if ok else
                    detail or "this PC cannot restart into its firmware settings from Windows; "
                    "restart it and press the setup key (often F2, F10, F12 or Del)")
    cp = subprocess.run(["shutdown.exe", "/r", "/t", "15", "/c",
                         "winlab: restarting to finish turning on Windows Hypervisor Platform"],
                        capture_output=True, text=True)
    return cp.returncode == 0, ("restarting in 15 seconds" if cp.returncode == 0
                                else (cp.stdout + cp.stderr).strip())


# ----------------------------------------------------------- finding the ISO

def downloads_dir() -> Path:
    """The Downloads folder, wherever the student moved it."""
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
                val, _ = winreg.QueryValueEx(k, DOWNLOADS_GUID)
            p = Path(os.path.expandvars(val))
            if p.is_dir():
                return p
        except OSError:
            pass
    else:
        xdg = _xdg_download_dir()
        if xdg is not None:
            return xdg
    return Path.home() / "Downloads"


def _xdg_download_dir(home: Path | None = None) -> Path | None:
    """XDG_DOWNLOAD_DIR from ~/.config/user-dirs.dirs (a Linux desktop's
    Downloads, localised or moved)."""
    home = home or Path.home()
    cfg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") / "user-dirs.dirs"
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() == "XDG_DOWNLOAD_DIR":
            p = Path(v.strip().strip('"').replace("$HOME", str(home)))
            return p if p.is_dir() else None
    return None


def search_dirs() -> list[Path]:
    home = Path.home()
    cands = [downloads_dir(), home / "Desktop", home / "Documents"]
    one = os.environ.get("OneDrive", "")
    if one:
        cands += [Path(one) / "Desktop", Path(one) / "Documents"]
    out: list[Path] = []
    for c in cands:
        if c.is_dir() and c not in out:
            out.append(c)
    return out


_SCAN_CACHE: dict[tuple[str, int, float], dict] = {}


def _describe_iso(f: Path) -> dict:
    from . import images, wim
    st = f.stat()
    key = (str(f), st.st_size, st.st_mtime)
    if key in _SCAN_CACHE:
        return _SCAN_CACHE[key]
    fits: list[str] = []
    holds = ""
    try:
        _, found = wim.images_in_iso(f)
        fits = images.media_fits(found)
        holds = wim.describe(images.pick_edition(fits[0], found)) if fits else (
            wim.describe(found[0]) if found else "")
    except wim.WimError:
        pass
    if not fits:
        from . import linuxiso  # a Linux installer DVD: told by its label
        found_id = linuxiso.detect(f)
        if found_id:
            fits, holds = [found_id], linuxiso.describe(f)
    if not fits:
        from . import bsdfw  # a firewall installer: told by its label or name
        found_id = bsdfw.detect(f)
        if found_id:
            fits, holds = [found_id], bsdfw.label_of(f) or bsdfw.FIREWALLS[found_id].short
    if not fits:
        from . import android  # Android-x86's installer: told by its label or name
        found_id = android.detect(f)
        if found_id:
            fits, holds = [found_id], android.label_of(f) or android.BUILDS[found_id].short
    if not fits:
        from . import netos  # VyOS's ISO, or Arista's Aboot disc for vEOS-lab
        found_id = netos.detect(f)
        if found_id:
            fits, holds = [found_id], netos.label_of(f) or netos.VENDORS[found_id].short
    row = {"path": str(f), "name": f.name, "folder": str(f.parent),
           "size_gb": round(st.st_size / 1024 ** 3, 1), "fits": fits, "holds": holds}
    _SCAN_CACHE[key] = row
    return row


def find_isos(dirs: list[Path] | None = None, min_bytes: int = ISO_MIN_BYTES) -> list[dict]:
    """Windows ISOs in the folders a download lands in (and one level of
    subfolders), each with the catalog images it can install, newest first."""
    seen: list[Path] = []
    for d in (search_dirs() if dirs is None else dirs):
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        subs = [e for e in entries if e.is_dir() and not e.name.startswith(".")][:50]
        for e in entries + [x for s in subs for x in _safe_iter(s)]:
            if e.suffix.lower() == ".iso" and e.is_file() and e not in seen:
                try:
                    if e.stat().st_size >= min_bytes:
                        seen.append(e)
                except OSError:
                    pass
    seen.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [_describe_iso(p) for p in seen[:20]]


def _safe_iter(d: Path) -> list[Path]:
    try:
        return list(d.iterdir())
    except OSError:
        return []


def _ps_quote(text: str) -> str:
    return "'" + str(text).replace("'", "''") + "'"


# The dialog's owner. winlab's server is not the program the user is looking
# at (that is the app window, another process), and Windows will not let a
# background program bring a window to the front. A Form that is never shown
# makes TopMost meaningless, so the Open dialog used to open hidden behind the
# app window with no taskbar button: Browse... looked dead. The owner is now a
# real, shown, see-through, topmost window with a taskbar button; the dialog
# it owns sits above it, so above every normal window, and the owner is
# activated (forced through to the front) before the dialog opens.
_OWNER = (
    "Add-Type -AssemblyName System.Windows.Forms; "
    "Add-Type -AssemblyName System.Drawing; "
    "[System.Windows.Forms.Application]::EnableVisualStyles(); "
    "$owner = New-Object System.Windows.Forms.Form; "
    "$owner.Text = {title}; $owner.TopMost = $true; $owner.ShowInTaskbar = $true; "
    "$owner.FormBorderStyle = 'None'; $owner.Opacity = 0; "
    "$owner.StartPosition = 'CenterScreen'; $owner.Size = New-Object System.Drawing.Size(1, 1); "
    "$owner.Show(); $owner.Activate(); [System.Windows.Forms.Application]::DoEvents(); "
)


def dialog_script(kind: str, title: str, filter_: str = "", start: str = "") -> str:
    """The PowerShell that shows the Windows Open (kind 'file') or folder
    (kind 'folder') dialog in front of everything and prints the choice."""
    if kind == "file":
        make = ("$d = New-Object System.Windows.Forms.OpenFileDialog; "
                f"$d.Title = {_ps_quote(title)}; $d.Filter = {_ps_quote(filter_)}; "
                f"$d.InitialDirectory = {_ps_quote(start)}; ")
        pick = "$d.FileName"
    else:
        make = ("$d = New-Object System.Windows.Forms.FolderBrowserDialog; "
                f"$d.Description = {_ps_quote(title)}; ")
        pick = "$d.SelectedPath"
    return (_OWNER.format(title=_ps_quote(title)) + make
            + "try { if ($d.ShowDialog($owner) -eq 'OK') { [Console]::OutputEncoding = [Text.Encoding]::UTF8; "
            + f"Write-Output {pick} }} }} finally {{ $owner.Close() }}")


def powershell_exe(env: dict | None = None) -> str:
    """Windows PowerShell by its full path: a PATH trimmed by an installer or
    a shortcut must not cost the user their Browse... button."""
    env = os.environ if env is None else env
    root = env.get("SystemRoot") or env.get("WINDIR") or r"C:\Windows"
    full = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(full) if full.exists() else "powershell.exe"


def _run_dialog(script: str, run=subprocess.run) -> str:
    """The chosen path, '' when the user cancelled; RuntimeError when the
    dialog could not open at all, so the page asks for the path instead of
    doing nothing."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    cp = run([powershell_exe(), "-NoProfile", "-NonInteractive", "-STA", "-ExecutionPolicy", "Bypass",
              "-Command", script], capture_output=True, timeout=3600, creationflags=flags)
    out = (cp.stdout or b"").decode("utf-8", "replace").strip()
    if cp.returncode != 0 and not out:
        err = (cp.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError("the Windows file dialog did not open"
                           + (f" ({err[0][:200]})" if err else "") + "; type the path instead")
    return out


def pick_file(title: str = "Choose the ISO you downloaded",
              filter_: str = "Disk images (*.iso)|*.iso|All files (*.*)|*.*",
              run=subprocess.run, windows: bool | None = None) -> str:
    """The Windows Open dialog, in front of the app window; '' when cancelled.
    winlab's desktop runs in a browser, which never hands a page a file's
    real path, so the engine asks Windows directly."""
    if not (os.name == "nt" if windows is None else windows):
        return _other_dialog("file", title, run)
    return _run_dialog(dialog_script("file", title, filter_, str(downloads_dir())), run)


def pick_folder(title: str = "Choose the folder to put on the disc",
                run=subprocess.run, windows: bool | None = None) -> str:
    """The Windows folder dialog, for the same reason as pick_file."""
    if not (os.name == "nt" if windows is None else windows):
        return _other_dialog("folder", title, run)
    return _run_dialog(dialog_script("folder", title), run)


def _other_dialog(kind: str, title: str, run=subprocess.run) -> str:
    if not sys.platform.startswith("linux"):
        raise RuntimeError(f"the {kind} picker is a Windows or Linux dialog; type the path instead")
    from . import linuxhost
    return linuxhost.pick(kind, title, str(downloads_dir()) if kind == "file" else str(Path.home()), run)


def render(items: list[dict]) -> str:
    mark = {"ok": "ok  ", "warn": "note", "fail": "FIX "}
    lines = []
    for i in items:
        lines.append(f"  [{mark[i['status']]}] {i['title']}")
        if i["status"] != "ok" or i["detail"]:
            lines.append(f"         {i['detail']}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    print(render(checks()), file=sys.stdout)
