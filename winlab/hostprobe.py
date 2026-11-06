"""Host capability probe. Answers one question: accelerated, or software-only?"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, paths

ACCEL_KVM = "kvm"
ACCEL_WHPX = "whpx"
ACCEL_HVF = "hvf"
ACCEL_TCG = "tcg"

# Floors for running a lab at all. 8 GiB runs every one- and two-machine
# exercise (a DC plus a member at 2 GiB each, and the fabric); `lab up` boots
# only what an exercise needs and checks what fits before it starts anything.
MIN_RAM_GB = 8.0
COMFORT_RAM_GB = 16.0
MIN_CORES = 4
# Bases are sealed compressed and the ISO copy goes once a base exists, so a
# Server base is ~8 GiB and the Windows 11 base ~9 GiB; 40 GiB leaves room
# for the pair, the ISO while it is being prepared, and a lab of clones.
MIN_FREE_GB = 40.0
SERVER_ONLY_FREE_GB = 25.0


@dataclass
class Finding:
    key: str
    value: str
    status: str = "info"  # info | ok | warn | fail
    note: str = ""


@dataclass
class HostReport:
    findings: list[Finding] = field(default_factory=list)
    accel: str = ACCEL_TCG
    accel_confirmed: bool = False
    ram_gb: float = 0.0
    cores: int = 0
    free_gb: float = 0.0
    qemu_present: bool = False
    # Raw facts the first-run checklist (winlab/readiness.py) words for a
    # student: None where this host does not say.
    windows_build: int = 0
    virt_firmware: bool | None = None
    hypervisor_platform: bool | None = None
    root_writable: bool = True
    nested: bool | None = None   # VT-x for Hyper-V inside a machine (nestedvirt.host_support)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, key: str, value: str, status: str = "info", note: str = "") -> None:
        self.findings.append(Finding(key, value, status, note))


def _ps(script: str, timeout: int = 25) -> str:
    """Returns '' on failure. Decoded as UTF-8: non-English hosts emit bidi
    marks that are undecodable in legacy codepages such as cp1255."""
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return ""
    wrapped = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script
    try:
        res = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", wrapped],
            capture_output=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    raw = res.stdout or b""
    text = raw.decode("utf-8", errors="replace")
    # Strip bidi/zero-width controls so values render predictably in a report.
    return "".join(ch for ch in text if ch.isprintable() or ch in "\r\n\t").strip()


def _memstatus() -> tuple[float, float]:
    """(total, available) physical memory in bytes; (0, 0) when unknown."""
    if os.name == "nt":

        class MemStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = MemStatus()
        st.dwLength = ctypes.sizeof(MemStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return float(st.ullTotalPhys), float(st.ullAvailPhys)
        return 0.0, 0.0
    total = avail = 0.0
    try:
        total = float(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    except (ValueError, OSError, AttributeError):
        pass
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                avail = float(line.split()[1]) * 1024
                break
    except OSError:
        pass
    return total, avail


def _ram_gb() -> float:
    return _memstatus()[0] / (1024**3)


def available_ram_mb() -> int:
    """Physical memory free for new machines right now; 0 when unknown."""
    return int(_memstatus()[1] / (1024**2))


def probe() -> HostReport:
    r = HostReport()

    r.add("winlab", f"{__version__} ({'winlab.exe' if paths.FROZEN else 'source'}) in {paths.ROOT}")
    r.root_writable = paths.writable(paths.ROOT)
    if not r.root_writable:
        r.add("folder", "read-only", "fail",
              "move winlab to a folder you own (not Program Files), or set WINLAB_HOME")
        r.blockers.append(f"{paths.ROOT} is not writable")
    r.add("platform", f"{platform.system()} {platform.release()} ({platform.machine()})")
    r.cores = os.cpu_count() or 1
    r.ram_gb = _ram_gb()

    r.add(
        "cpu cores",
        str(r.cores),
        "ok" if r.cores >= MIN_CORES else "warn",
        "" if r.cores >= MIN_CORES else f"below the {MIN_CORES}-core floor for a multi-vm lab",
    )
    r.add(
        "memory",
        f"{r.ram_gb:.1f} GiB",
        "ok" if r.ram_gb >= MIN_RAM_GB else "warn",
        "" if r.ram_gb >= MIN_RAM_GB
        else f"below the {MIN_RAM_GB:.0f} GiB floor: one machine at a time at most",
    )

    store = paths.images_dir()
    probe_dir = store if store.exists() else store.anchor or Path.cwd().anchor
    try:
        usage = shutil.disk_usage(str(probe_dir))
        r.free_gb = usage.free / (1024**3)
        r.add(
            "image store",
            f"{store}  ({r.free_gb:.1f} GiB free)",
            "ok" if r.free_gb >= MIN_FREE_GB else "warn",
            ""
            if r.free_gb >= MIN_FREE_GB
            else f"a Server + client base pair needs ~{MIN_FREE_GB:.0f} GiB "
            f"(~{SERVER_ONLY_FREE_GB:.0f} GiB with the Server base alone); "
            f"point WINLAB_IMAGES at a roomier drive",
        )
    except OSError as exc:
        r.add("image store", str(store), "warn", f"could not stat: {exc}")

    if os.name == "nt":
        _probe_windows(r)
    elif platform.system() == "Linux":
        _probe_linux(r)
    elif platform.system() == "Darwin":
        r.accel = ACCEL_HVF
        r.add("acceleration", "hvf (Hypervisor.framework)", "ok")

    _probe_qemu(r)
    _probe_nested(r)
    _probe_dsc_modules(r)
    _verdict(r)
    return r


def _probe_nested(r: HostReport) -> None:
    """Whether a lab server can run Hyper-V inside it (winlab/nestedvirt.py)."""
    from . import nestedvirt
    ok, why = nestedvirt.host_support(r.accel)
    r.nested = ok
    r.add("nested virtualization", "yes" if ok else "no", "ok" if ok else "info",
          why or "a Windows Server machine can be given VT-x for Hyper-V inside it")


def _probe_windows(r: HostReport) -> None:
    edition = _ps("(Get-CimInstance Win32_OperatingSystem).Caption") or "unknown"
    build = _ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber") or "?"
    edition = edition.strip()
    r.windows_build = int(build) if build.strip().isdigit() else 0
    is_home = "home" in edition.lower()
    r.add("windows edition", f"{edition} (build {build})", "warn" if is_home else "ok",
          "Home has no Hyper-V role; the portable runtime does not need it" if is_home else "")

    hv_present = _ps("(Get-CimInstance Win32_ComputerSystem).HypervisorPresent").strip().lower()
    r.add(
        "hypervisor running",
        "yes" if hv_present == "true" else "no",
        "info",
        "a root hypervisor (WSL2/Docker/VBS) is already active; "
        "nested accelerators must go through WHPX" if hv_present == "true" else "",
    )

    virt = _ps(
        "$p=Get-CimInstance Win32_Processor | Select-Object -First 1; "
        "'{0}|{1}' -f $p.VirtualizationFirmwareEnabled, "
        "$p.SecondLevelAddressTranslationExtensions"
    )
    if "|" in virt:
        fw, slat = (x.strip().lower() == "true" for x in virt.split("|", 1))
        # With a hypervisor already running (Hyper-V, WSL2, memory integrity)
        # Windows reports VirtualizationFirmwareEnabled as False: the CPU's
        # virtualization is in the hypervisor's hands, so it is on.
        fw = fw or hv_present == "true"
        r.virt_firmware = fw
        r.add(
            "vt-x/amd-v in firmware",
            "enabled" if fw else "disabled",
            "ok" if fw else "fail",
            "" if fw else "enable SVM/VT-x in UEFI; without it no accelerator can work",
        )
        if not fw:
            r.blockers.append("hardware virtualization is disabled in firmware")
        # This WMI property only reports Intel EPT, so it reads false on AMD
        # hosts that do have NPT. Report it, but never treat it as a signal.
        if slat:
            r.add("slat (intel ept)", "present", "ok")
        else:
            r.add(
                "slat (intel ept)",
                "not reported",
                "info",
                "WMI only reports Intel EPT here; on AMD this is expected and says "
                "nothing about NPT support -- the accel smoke test is the real check",
            )

    whp_dll = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WinHvPlatform.dll"
    hv_role = _ps("(Get-Service vmms -ErrorAction SilentlyContinue).Status").strip()
    r.add("hyper-v role (vmms)", hv_role or "not installed", "info")

    r.hypervisor_platform = whp_dll.exists()
    if whp_dll.exists():
        r.accel = ACCEL_WHPX
        r.add(
            "WinHvPlatform.dll",
            "present",
            "ok",
            "necessary condition for -accel whpx; confirmed by the smoke test below",
        )
    else:
        r.add(
            "WinHvPlatform.dll",
            "missing",
            "warn",
            "no WHPX; portable runtime falls back to software emulation (tcg)",
        )


def _probe_linux(r: HostReport) -> None:
    kvm = Path("/dev/kvm")
    if kvm.exists():
        writable = os.access(str(kvm), os.R_OK | os.W_OK)
        r.accel = ACCEL_KVM
        r.add(
            "/dev/kvm",
            "present" + ("" if writable else " (no access)"),
            "ok" if writable else "warn",
            "" if writable else "add your user to the kvm group",
        )
    else:
        r.add("/dev/kvm", "missing", "warn", "software emulation only")


def _probe_dsc_modules(r: HostReport) -> None:
    from . import psmodules, viewer

    if psmodules.ready():
        r.add("dsc modules", f"{len(psmodules.MODULES)} fetched", "ok")
    else:
        r.add(
            "dsc modules",
            "not fetched",
            "warn",
            "every Windows role compiles against them; "
            "'winlab bootstrap' or 'winlab dsc fetch' downloads them from the PowerShell Gallery",
        )
    if viewer.ready():
        r.add("console viewer", f"noVNC {viewer.VERSION} fetched", "ok")
    else:
        r.add(
            "console viewer",
            "not fetched",
            "warn",
            "the dashboard's Console tab needs it; 'winlab bootstrap' or 'winlab viewer fetch' "
            "downloads it (the QEMU window works without it)",
        )


def _probe_qemu(r: HostReport) -> None:
    exe = paths.qemu_exe()
    r.qemu_present = exe.exists()
    if not r.qemu_present:
        r.add(
            "portable qemu",
            "not installed",
            "warn",
            "run 'winlab bootstrap' to fetch it into ./runtime (nothing is installed "
            "system-wide)",
        )
        r.accel_confirmed = False
        return

    r.add("portable qemu", str(exe), "ok")
    try:
        res = subprocess.run([str(exe), "-accel", "help"], capture_output=True, timeout=30)
        blob = (res.stdout or b"").decode("utf-8", "replace") + (res.stderr or b"").decode(
            "utf-8", "replace"
        )
        offered = [
            line.strip()
            for line in blob.splitlines()
            if line.strip() and "accel" not in line.lower()
        ]
    except (subprocess.SubprocessError, OSError) as exc:
        r.add("accel list", f"probe failed: {exc}", "warn")
        return

    r.add("accelerators offered", ", ".join(offered) or "none reported", "info")

    forced = os.environ.get("WINLAB_ACCEL")
    if forced and forced in offered:
        r.accel = forced
        r.accel_confirmed = True
        r.add("acceleration", f"{forced} (forced via WINLAB_ACCEL)", "ok")
        return

    for want in (ACCEL_KVM, ACCEL_WHPX, ACCEL_HVF):
        if want in offered and _smoke_test_accel(exe, want):
            r.accel = want
            r.accel_confirmed = True
            r.add("acceleration", f"{want} CONFIRMED by smoke test", "ok")
            return

    r.accel = ACCEL_TCG
    r.accel_confirmed = True
    r.add(
        "acceleration",
        "tcg (software emulation)",
        "warn",
        "a Windows Server install will take 10-25 minutes instead of 1-2; "
        "the bootable appliance runtime avoids this",
    )


def _smoke_test_accel(exe: Path, accel: str) -> bool:
    """QEMU initialises the accelerator during machine setup, before the QMP
    monitor comes up, so seeing the QMP greeting proves the accelerator works.

    Deliberately does not rely on a QMP `quit` round-trip: QEMU's stdio monitor
    mangles piped input on Windows, which made an earlier version of this probe
    report a working WHPX as broken.
    """
    cmd = [
        str(exe),
        "-accel", accel,
        "-machine", "q35",
        "-m", "128",
        "-display", "none",
        "-nodefaults",
        "-no-user-config",
        "-S",
        "-qmp", "stdio",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError:
        return False

    buf = bytearray()

    def drain() -> None:
        try:
            assert proc.stdout is not None
            for byte in iter(lambda: proc.stdout.read(1), b""):
                buf.extend(byte)
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()

    bad = (b"failed to initialize", b"not supported", b"no accelerator",
           b"invalid accelerator", b"could not", b"error")
    deadline = time.monotonic() + 30
    verdict = False
    while time.monotonic() < deadline:
        blob = bytes(buf)
        low = blob.lower()
        if b'"qmp"' in low:
            verdict = not any(b in low for b in bad[:4])
            break
        if any(b in low for b in bad):
            verdict = False
            break
        if proc.poll() is not None:
            break
        time.sleep(0.15)

    try:
        proc.kill()
        proc.wait(timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass
    return verdict


def _verdict(r: HostReport) -> None:
    if r.ram_gb and r.ram_gb < COMFORT_RAM_GB:
        # ~3 GiB for the host OS, 2 GiB per Windows machine, 0.5 for the fabric.
        machines = max(1, int((r.ram_gb - 3.5) // 2))
        r.warnings.append(
            f"{r.ram_gb:.1f} GiB RAM runs about {machines} Windows machine"
            f"{'s' if machines != 1 else ''} at once: enough for exercises that "
            f"use {'that many' if machines > 1 else 'one'}, which `winlab exercise start` "
            f"boots on their own"
        )
    if r.free_gb and r.free_gb < MIN_FREE_GB:
        r.warnings.append(
            f"{r.free_gb:.1f} GiB free is tight; the compressed bases take ~8 GiB each, "
            f"an ISO ~6 GiB while it is being prepared, and each booted machine 2-6 GiB"
        )
    if r.accel == ACCEL_TCG and r.accel_confirmed:
        r.warnings.append(
            "no hardware acceleration: prefer the bootable appliance runtime for real work"
        )


def render(r: HostReport) -> str:
    glyph = {"ok": "ok  ", "warn": "warn", "fail": "FAIL", "info": "    "}
    width = max(len(f.key) for f in r.findings) if r.findings else 10
    lines = ["winlab doctor", ""]
    for f in r.findings:
        lines.append(f"  [{glyph.get(f.status, '    ')}] {f.key:<{width}}  {f.value}")
        if f.note:
            lines.append(f"  {'':<{width + 9}}{f.note}")
    lines.append("")

    if r.blockers:
        lines.append("blockers")
        for b in r.blockers:
            lines.append(f"  - {b}")
        lines.append("")
    if r.warnings:
        lines.append("notes")
        for w in r.warnings:
            lines.append(f"  - {w}")
        lines.append("")

    conf = "confirmed" if r.accel_confirmed else "unconfirmed (run bootstrap, then doctor again)"
    lines.append(f"verdict    acceleration = {r.accel} ({conf})")
    if r.accel in (ACCEL_KVM, ACCEL_WHPX, ACCEL_HVF):
        lines.append("           portable runtime is viable at near-native speed")
    elif r.accel_confirmed:
        lines.append("           portable runtime works but is slow; appliance runtime recommended")
    return "\n".join(lines)
