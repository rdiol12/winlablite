"""Nested virtualization: Hyper-V or KVM inside a lab machine, and the
hypervisor Windows 11's virtualization-based security runs in.

A Windows machine carries one firmware setting for it, "Intel
Virtualization Technology (VT-x)", flipped with the case open and the
machine off like any BIOS setting (`nested = true` in the lab file). On, the
machine's processor shows VT-x (AMD-V on an AMD host) and the student can
install the Hyper-V role inside a server, build a virtual switch and run a VM
of their own from an ISO they bring. Winlab does none of that for them.

A Windows 11 PC carries the same setting: Windows starts its own hypervisor
for virtualization-based security (Credential Guard, memory integrity) only
when the processor shows VT-x with second-level address translation, and the
Hyper-V feature needs it too. VT-x is one requirement of several: Credential
Guard also wants Secure Boot, the machine's other firmware setting
(winlab/firmware.py: UEFI with Secure Boot, which needs System Management
Mode, so KVM and not WHPX), and the PC's own answer (Win32_DeviceGuard,
msinfo32) says what is missing; the lessons say so too.

Linux servers carry the same setting: the ones the student installs by hand
from their own DVD (Rocky Linux 9, RHEL 9 and 10, Debian 13, Ubuntu Server
24.04; winlab/linuxiso.py) and the ready-made Ubuntu appliance. On, /dev/kvm
appears inside once the kvm_intel (kvm_amd) module loads, and the student
installs QEMU/KVM, libvirt and Cockpit's Virtual machines page from the
distribution's DVD (or the `kvm` pack on the appliance, winlab/debpacks.py)
and runs a VM of their own. Off, the processor shows no VT-x at all: on KVM
a fitted machine gets `-vmx,-svm`, so the setting means what it says (with
plain `-cpu host` a nesting KVM would pass VT-x on regardless).

What the host can give decides whether the setting can be turned on:

* KVM (Linux, the winlab appliance): yes, when the kvm_intel or kvm_amd
  module allows nesting (/sys/module/kvm_*/parameters/nested; on by default
  on current kernels). The CPU is the host's with +vmx (+svm on AMD) and the
  Hyper-V enlightenments the machines always get (relaxed, vapic, time).
  hv-evmcs is left out: it is KVM- and Intel-only, needs kernel support
  (QEMU refuses to start without it) and turns posted interrupts off; it is a
  speed-up for Hyper-V on KVM, never a requirement.
* WHPX (QEMU on Windows): before QEMU 11.0 no; WHPX never asked Windows for
  nested virtualization. QEMU 11.0 and later ask for it when Windows offers
  it (the in-kernel APIC on, a processor and build that support it), so the
  setting can be turned on there, with the plain warning that Windows may
  still say no.
* HVF (macOS): no. QEMU's HVF CPUID filter leaves VMX out of leaf 1.
* TCG (software emulation): no; a hypervisor inside an emulated CPU is far
  too slow to be useful.

`WINLAB_NESTED=1` (or 0) forces the host's answer, and `host_override` does
the same from the tests.

The drill "Hyper-V will not start" turns the setting off behind the
student's back, the way a firmware reset or a replaced board does: Hyper-V
inside then cannot start a VM. The student finds why from inside Windows
(systeminfo, the Hyper-V-Hypervisor log, the error on Start-VM), turns the
setting back on with the machine off, and "Check my fix" proves a VM runs
again. Three hints on the way, in the pattern of winlab/guestfaults.py.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

from . import naming, paths, state
from .model import LINUX, WINDOWS_CLIENT, WINDOWS_SERVER

FILE = "nested.json"     # the drill, beside the lab's machines (never in the lab file)
MIN_MB = 4096            # what Hyper-V itself asks of a host; turning VT-x on fits at least this
WARN_MB = 8192           # under this a host and a VM inside it are tight
LINUX_MIN_MB = 4096      # a KVM host and a small VM inside it (1 GB for the VM, the rest for the host)
LINUX_WARN_MB = 4096
CLIENT_MIN_MB = 4096     # Windows 11's own minimum; its hypervisor and VBS fit in it
CLIENT_WARN_MB = 4096
# The Linux machines the setting is fitted to: the hand installs whose DVD
# (or whose archive) carries QEMU/KVM and libvirt (not the Alpine standard
# disc), and the ready-made Ubuntu appliance (the kvm pack).
HAND_LINUX = ("rocky9", "rhel9", "rhel10", "debian13", "ubuntu24")
APPLIANCES = ("ubuntu",)
SETTING = "Intel Virtualization Technology (VT-x)"
# What the setting means on a Windows 11 PC, said plainly: VT-x is one of the
# things virtualization-based security needs, not all of them.
CLIENT_NOTE_ON = ("The processor shows VT-x to Windows: the hypervisor that virtualization-based security "
                  "(Credential Guard, memory integrity) runs in can start, and the Hyper-V feature can run VMs. "
                  "Credential Guard also needs Secure Boot, set below (Security, Secure Boot) where this PC "
                  "can run it: msinfo32 and Win32_DeviceGuard inside say what Windows found.")
CLIENT_NOTE_OFF = ("Virtualization-based security (Credential Guard, memory integrity) and the Hyper-V "
                   "feature inside this PC need it Enabled: without it Windows sees no VT-x.")
CHECK = "Check my fix"
ENV = "WINLAB_NESTED"

# Seams for the tests: the host's answer (ok, why), a machine's agent channel.
host_override = None
guest_channel = None     # (lab_name, node_id) -> channel with .run(cmd, shell, timeout) and .close()

# A VM can only be Running if the hypervisor inside started, which needs VT-x.
VM_RUNNING = ("[bool](@(Get-VM -ErrorAction SilentlyContinue | "
              "Where-Object State -eq 'Running').Count -ge 1)")

HINTS = (
    "Start inside {machine}: try to start a VM in Hyper-V Manager or with Start-VM, and read "
    "exactly what it says. Then look at the end of systeminfo and in Event Viewer under "
    "Applications and Services Logs, Microsoft, Windows, Hyper-V-Hypervisor.",
    "Hyper-V says the hypervisor is not running, and systeminfo on {machine} lists the "
    "Hyper-V Requirements with 'VM Monitor Mode Extensions: No': the processor no longer "
    "shows VT-x to Windows. Nothing inside Windows turns that on; it is a firmware setting.",
    "Shut {machine} down, open its case (Open the case, Firmware setup) and set " + SETTING
    + " to Enabled. Start it again, then start your VM (Start-VM) and press " + CHECK + ".",
)


LINUX_HINTS = (
    "Start inside {machine}: try to start your VM (virsh start <name>, or Run in Cockpit's Virtual "
    "machines page) and read exactly what it says. Then ask the machine itself: virt-host-validate qemu, "
    "and ls -l /dev/kvm.",
    "libvirt says KVM is not available, virt-host-validate says 'Checking for hardware virtualization: "
    "FAIL', and grep -c -E 'vmx|svm' /proc/cpuinfo prints 0 on {machine}: the processor no longer shows "
    "VT-x to Linux. No package or module turns that on; it is a firmware setting.",
    "Shut {machine} down, open its case (Open the case, Firmware setup) and set " + SETTING
    + " to Enabled. Start it again: grep -c vmx /proc/cpuinfo counts the processors, /dev/kvm is back; "
    "start your VM and press " + CHECK + ".",
)


class NestedError(Exception):
    pass


# ------------------------------------------------------------------ the host
def kvm_nested(root: str = "/sys/module") -> str | None:
    """The kvm module's nested parameter ('Y', 'N', '1', '0'), or None when
    neither kvm_intel nor kvm_amd is loaded."""
    for mod in ("kvm_intel", "kvm_amd"):
        p = Path(root) / mod / "parameters" / "nested"
        try:
            return p.read_text(encoding="ascii").strip()
        except OSError:
            continue
    return None


def amd_host(cpuinfo: str = "/proc/cpuinfo") -> bool:
    try:
        with open(cpuinfo, encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("vendor_id"):
                    return "AuthenticAMD" in line
    except OSError:
        pass
    return False


_qemu_ver: tuple[int, int] | None = None


def qemu_version() -> tuple[int, int]:
    """The portable QEMU's (major, minor); (0, 0) when it does not say."""
    global _qemu_ver
    if _qemu_ver is None:
        _qemu_ver = (0, 0)
        try:
            res = subprocess.run([str(paths.qemu_exe()), "-version"], capture_output=True, timeout=20)
            m = re.search(rb"version (\d+)\.(\d+)", res.stdout or b"")
            if m:
                _qemu_ver = (int(m.group(1)), int(m.group(2)))
        except (OSError, subprocess.SubprocessError):
            pass
    return _qemu_ver


def host_support(accel: str, nested_param: str | None = "", qemu: tuple[int, int] | None = None) -> tuple[bool, str]:
    """Whether this PC can show VT-x to a machine, and in plain words why
    not (or what to know). nested_param and qemu are for the tests; by
    default they are read from the host."""
    if host_override is not None:
        return host_override
    forced = os.environ.get(ENV, "")
    if forced in ("1", "0"):
        return (forced == "1", "" if forced == "1" else f"turned off on this PC ({ENV}=0)")
    if accel == "kvm":
        param = kvm_nested() if nested_param == "" else nested_param
        if param is not None and param.upper() in ("N", "0"):
            return False, ("this PC's KVM has nesting turned off: on the host, "
                           "modprobe -r kvm_intel; modprobe kvm_intel nested=1 (kvm_amd on AMD)")
        return True, ""
    if accel == "whpx":
        ver = qemu_version() if qemu is None else qemu
        if ver >= (11, 0):
            return True, ("QEMU asks the Windows Hypervisor Platform for nested virtualization; Windows "
                          "gives it only on processors and builds that support it. If Hyper-V inside "
                          "says the hypervisor is not running, this PC cannot")
        return False, ("this PC runs machines through the Windows Hypervisor Platform, and this QEMU "
                       f"{f' ({ver[0]}.{ver[1]})' if ver > (0, 0) else ''} does not pass VT-x on to them (QEMU 11 and later can ask "
                       "Windows for it); Hyper-V inside a machine needs the winlab appliance (KVM)")
    if accel == "hvf":
        return False, "QEMU on macOS (Hypervisor.framework) does not pass VT-x on to a machine"
    return False, ("this PC has no hardware acceleration (software emulation): a hypervisor inside "
                   "an emulated processor is far too slow to run; use the winlab appliance (KVM)")


def cpu(accel: str, amd: bool | None = None, linux: bool = False) -> str:
    """The -cpu value of a machine with VT-x on, where the host can give it.
    Linux gets the plain host CPU with VT-x: the Hyper-V enlightenments are
    for Windows."""
    if accel == "kvm":
        ext = "+svm" if (amd_host() if amd is None else amd) else "+vmx"
        return f"host,{ext}" if linux else f"host,{ext},hv-relaxed,hv-vapic,hv-time"
    return ""   # WHPX on QEMU 11+: Windows itself handles the processor's features


def cpu_off(accel: str, base: str) -> str:
    """The -cpu value of a fitted machine with the setting off. On KVM,
    `-cpu host` passes VT-x on whenever the host's module nests, so the
    setting is honoured by taking VMX (and SVM) away; WHPX, HVF and TCG
    machines never see it anyway."""
    if accel == "kvm" and base.split(",")[0] == "host":
        return base + ",-vmx,-svm"
    return base


# ------------------------------------------------------------------ the setting
def is_linux(node) -> bool:
    """A Linux machine the setting is fitted to (KVM inside it)."""
    kind, image = getattr(node, "kind", ""), getattr(node, "image", "")
    if kind == LINUX:
        return image in APPLIANCES
    return kind == "custom" and image in HAND_LINUX


def fitted(node) -> bool:
    """The setting exists on Windows machines (Hyper-V on a server; the
    hypervisor of virtualization-based security and the Hyper-V feature on a
    Windows 11 PC) and on the Linux servers that can be KVM hosts (is_linux)."""
    return getattr(node, "kind", "") in (WINDOWS_SERVER, WINDOWS_CLIENT) or is_linux(node)


def is_client(node) -> bool:
    """A Windows PC (Windows 11): VT-x is for virtualization-based security
    there, and for the Hyper-V feature."""
    return getattr(node, "kind", "") == WINDOWS_CLIENT


def hand_installed(node) -> bool:
    """winlab runs nothing inside it, so its drill cannot ask the guest."""
    return getattr(node, "kind", "") == "custom"


def floor(node) -> tuple[int, int, str]:
    """(memory turning VT-x on fits, under what it warns, what for)."""
    if is_linux(node):
        return LINUX_MIN_MB, LINUX_WARN_MB, "what a KVM host and a small VM inside it want"
    if is_client(node):
        return CLIENT_MIN_MB, CLIENT_WARN_MB, "what Windows 11 with its hypervisor running wants"
    return MIN_MB, WARN_MB, "what Hyper-V asks of a host"


def hints(node) -> tuple[str, ...]:
    return LINUX_HINTS if is_linux(node) else HINTS


def drill_name(node) -> str:
    return "Drill: the VM will not start" if is_linux(node) else "Drill: Hyper-V will not start"


def view(lab, node, accel: str) -> dict | None:
    if not fitted(node):
        return None
    ok, why = host_support(accel)
    linux = is_linux(node)
    warn_mb = floor(node)[1]
    client = is_client(node)
    what = ("KVM and a VM inside" if linux else
            "Windows 11 with virtualization-based security" if client else "Hyper-V and a VM inside")
    warn = (f"{naming.display(lab, node.id)} has {node.memory_mb // 1024} GB: {what} want "
            f"{warn_mb // 1024} GB or more" if node.nested and node.memory_mb < warn_mb else "")
    if linux and why:
        why = why.replace("Hyper-V inside a machine", "KVM inside a machine").replace(
            "If Hyper-V inside says the hypervisor is not running", "If /dev/kvm does not appear inside")
    elif client and why:
        why = why.replace("Hyper-V inside a machine", "Credential Guard or Hyper-V inside a PC").replace(
            "If Hyper-V inside says the hypervisor is not running",
            "If Win32_DeviceGuard inside does not list hypervisor support (1) in AvailableSecurityProperties")
    dr = load(lab.name)["drill"]
    out = {"on": bool(node.nested), "can": ok, "why": why, "warn": warn, "drill": None,
           "os": "linux" if linux else "windows", "drill_name": drill_name(node),
           "note_on": ("The processor shows VT-x to Linux: /dev/kvm appears, and QEMU/KVM, libvirt and "
                       "Cockpit's Virtual machines page (cockpit-machines) run VMs from your own ISO."
                       if linux else CLIENT_NOTE_ON if client else "The processor shows VT-x to Windows: "
                       "install the Hyper-V role inside, build a virtual switch and a VM from your own ISO."),
           "note_off": ("KVM inside this server needs it Enabled: without it the processor shows no VT-x "
                        "(grep -c vmx /proc/cpuinfo prints 0)." if linux
                        else CLIENT_NOTE_OFF if client else "Hyper-V inside this server needs it Enabled.")}
    if dr and dr["node"] == node.id:
        out["drill"] = {k: dr[k] for k in ("hints", "checks", "done", "gave_up")}
    return out


def set_vtx(lab, node_id: str, on: bool, accel: str, running: set[str]) -> str:
    """Flips the firmware setting; the machine must be off. Turning it on
    fits at least MIN_MB of memory and says so under WARN_MB."""
    node = lab.nodes.get(node_id)
    if node is None:
        raise NestedError("no such machine")
    name = naming.display(lab, node_id)
    if not fitted(node):
        raise NestedError(f"{name} has no such firmware setting here: it is fitted to Windows machines "
                          f"(Hyper-V on a server, virtualization-based security on a Windows 11 PC) and to "
                          f"the Linux servers that can host KVM ({', '.join(HAND_LINUX)} installed by hand, "
                          f"the Ubuntu appliance)")
    if node_id in running:
        raise NestedError(f"shut {name} down first: firmware settings change with the machine off")
    if not on:
        node.nested = False
        return f"{name}: {SETTING} disabled"
    ok, why = host_support(accel)
    if not ok:
        raise NestedError(f"{SETTING} cannot be enabled: {why}")
    node.nested = True
    msg = f"{name}: {SETTING} enabled"
    min_mb, warn_mb, what = floor(node)
    if node.memory_mb < min_mb:
        node.memory_mb = min_mb
        msg += f"; memory raised to {min_mb // 1024} GB, {what}"
    if node.memory_mb < warn_mb:
        msg += f" (it has {node.memory_mb // 1024} GB: {warn_mb // 1024} GB or more leaves room for a VM inside)"
    return msg


# ------------------------------------------------------------------ the drill
def _path(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
        if isinstance(data, dict) and "drill" in data:
            return data
    except (OSError, ValueError):
        pass
    return {"drill": None}


def _write(lab_name: str, data: dict) -> None:
    state.write_json(_path(lab_name), data)


def drill_start(lab, node_id: str, accel: str) -> dict:
    node = lab.nodes.get(node_id)
    if node is None or not fitted(node):
        raise NestedError("the drill needs a Windows machine or a Linux server with the VT-x setting")
    ok, why = host_support(accel)
    if not ok:
        raise NestedError(f"this drill needs a PC that can pass VT-x on: {why}")
    if not node.nested:
        raise NestedError(f"turn {SETTING} on for {naming.display(lab, node_id)} first, and build "
                          f"{'KVM and a VM' if is_linux(node) else 'Hyper-V'} inside it: the drill "
                          f"breaks what you built")
    if load(lab.name)["drill"]:
        raise NestedError("a drill is already running: check it or give up first")
    node.nested = False
    _write(lab.name, {"drill": {"node": node_id, "started": int(time.time()), "hints": 0,
                                "checks": 0, "done": False, "gave_up": False}})
    name = naming.display(lab, node_id)
    if is_linux(node):
        return {"message": f"Something changed on {name}: from its next start, your VM inside cannot start. "
                           f"Restart {name}, find out why from inside Linux and put it right."}
    return {"message": f"Something changed on {name}: from its next start, Hyper-V inside cannot start "
                       f"a VM. Restart {name}, find out why from inside Windows and put it right."}


def _guest_ok(lab_name: str, node_id: str) -> bool | None:
    """VM_RUNNING inside the machine: True, False, or None when its agent
    does not answer."""
    if guest_channel is not None:
        ch = guest_channel(lab_name, node_id)
    else:
        from .guestctl import GuestChannel, GuestError
        st = state.load(lab_name)
        ns = st.nodes.get(node_id) if st else None
        try:
            ch = GuestChannel(ns.serial_port).connect(retries=3, delay=2)
        except (GuestError, OSError, AttributeError):
            return None
    from .guestctl import GuestError
    try:
        # A machine still in its firmware or Setup has no agent: say so in seconds.
        if not ch.run("echo ok", shell="powershell", timeout=15).ok:
            return None
        res = ch.run(VM_RUNNING, shell="powershell", timeout=60)
    except GuestError:
        return None
    finally:
        ch.close()
    return res.ok and (res.out or "").strip().splitlines()[-1:] == ["True"]


def drill_check(lab, running: set[str]) -> dict:
    data = load(lab.name)
    dr = data["drill"]
    if not dr:
        raise NestedError("no drill is running")
    node_id = dr["node"]
    name = naming.display(lab, node_id)
    node = lab.nodes.get(node_id)
    dr["checks"] += 1
    fixed = False
    linux = node is not None and is_linux(node)
    if node is None or not node.nested:
        msg = f"Not yet: {'KVM' if linux else 'Hyper-V'} on {name} still cannot start a VM. Ask for a hint."
    elif node_id not in running:
        msg = f"Start {name}, start a VM inside it ({'virsh start' if linux else 'Start-VM'}), then check again."
    elif linux:
        # winlab runs nothing inside a Linux server here (a hand install has
        # no agent at all): the firmware setting is what it can see, the
        # proof inside is the student's.
        fixed = True
        msg = (f"Fixed: {SETTING} is back on in {name}'s firmware and {name} runs. winlab does not look "
               f"inside it: grep -c vmx /proc/cpuinfo counts the processors again, virt-host-validate "
               f"passes its hardware virtualization line, /dev/kvm is back and your VM starts.")
    else:
        seen = _guest_ok(lab.name, node_id)
        if seen is None:
            msg = f"{name}'s agent does not answer yet: let Windows finish starting, then check again."
        elif not seen:
            msg = (f"{SETTING} is back on, but no VM runs on {name}: if {name} was running when you "
                   f"changed it, restart it; then Start-VM and check again.")
        else:
            fixed = True
            msg = (f"Fixed: a VM runs on {name} again. {SETTING} had been turned off in its firmware, "
                   f"so Windows saw no VT-x and the hypervisor could not start.")
    dr["done"] = fixed
    _write(lab.name, data)
    return {"fixed": fixed, "message": msg}


def drill_hint(lab) -> dict:
    data = load(lab.name)
    dr = data["drill"]
    if not dr:
        raise NestedError("no drill is running")
    node = lab.nodes.get(dr["node"])
    ladder = hints(node) if node is not None else HINTS
    n = min(dr["hints"] + 1, len(ladder))
    dr["hints"] = n
    _write(lab.name, data)
    return {"n": n, "of": len(ladder), "text": ladder[n - 1].format(machine=naming.display(lab, dr["node"])),
            "message": f"hint {n} of {len(ladder)}"}


def drill_end(lab, give_up: bool = False) -> dict:
    """Puts the drill away; giving up says what it was. The setting stays as
    the student left it: flipping it is theirs to do."""
    data = load(lab.name)
    dr = data["drill"]
    if not dr:
        raise NestedError("no drill is running")
    _write(lab.name, {"drill": None})
    if give_up and not dr["done"]:
        return {"message": f"It was {SETTING}, turned off in {naming.display(lab, dr['node'])}'s firmware: "
                           f"shut it down, open its case and enable it again."}
    return {"message": "drill finished"}


# ------------------------------------------------------------------ the workbench
def accel_of(dash) -> str:
    return getattr(dash, "accel", "") or "tcg"


def act(dash, action: str, params: dict) -> dict:
    """wb-vtx (op: set, or the drill's start, hint, check, give-up, end)."""
    from .workbench import _running, _save
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    op = str(params.get("op") or "set")
    try:
        if op == "set":
            msg = set_vtx(lab, node_id, str(params.get("on")) in ("1", "true", "True"),
                          accel_of(dash), _running(lab.name))
            _save(dash)
            return {"ok": True, "message": msg}
        if op == "start":
            r = drill_start(lab, node_id, accel_of(dash))
            _save(dash)
            return {"ok": True, **r}
        if op == "hint":
            return {"ok": True, **drill_hint(lab)}
        if op == "check":
            return {"ok": True, **drill_check(lab, _running(lab.name))}
        if op in ("give-up", "end"):
            return {"ok": True, **drill_end(lab, give_up=op == "give-up")}
        raise NestedError(f"no such step {op!r}")
    except (NestedError, ValueError) as exc:
        return {"ok": False, "message": str(exc)}
