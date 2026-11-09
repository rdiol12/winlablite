"""A Windows machine's firmware, chosen per machine: UEFI (what winlab has
always given a Windows machine), UEFI with Secure Boot, or a legacy BIOS.

Set it in the lab file (`firmware = "uefi" | "uefi-secure" | "bios"` on a
node; `secure_boot_template` in its vars picks the Secure Boot template, as
Hyper-V's Set-VMFirmware does), on the Settings dialog's Security and
Firmware pages, or in the machine's own firmware setup on the Workbench (Open
the case). It changes with the machine off, like any firmware setting, and
takes effect at its next start. Left unset, nothing changes: UEFI when this
PC's QEMU has the UEFI firmware, else the BIOS.

What each one is on this PC:

* uefi: QEMU's edk2 build without Secure Boot (edk2-x86_64-code.fd), the
  machine's own NVRAM (uefi-vars.fd), the pflash not locked to SMM.
* uefi-secure: QEMU's edk2 build with Secure Boot and SMM
  (edk2-x86_64-secure-code.fd), the machine type with System Management Mode
  on (q35,smm=on), the pflash writable only from SMM (secure=on) and S3
  sleep off (edk2's SMM build does not support it). The keys are written
  into the machine's NVRAM by winlab/secureboot.py before its first start
  with Secure Boot: winlab's own platform key, Microsoft's KEK, db and dbx.
* bios: SeaBIOS, QEMU's default when no pflash is given.

Where Secure Boot can run, which is a question of System Management Mode:
edk2 keeps its Secure Boot variables safe from the operating system only in
SMM, and the one Secure Boot build QEMU ships requires it.

* KVM (Linux, the winlab appliance): yes.
* TCG (software emulation): yes, slowly, as everything is there.
* WHPX (QEMU on Windows): no. QEMU's WHPX accelerator has no System
  Management Mode: QEMU stops with "System Management Mode not supported by
  this hypervisor" when asked for smm=on. A machine set to uefi-secure then
  starts with UEFI without Secure Boot, and the settings say why.
* HVF (macOS): no, for the same reason.

`WINLAB_SECUREBOOT=1` (or 0) forces the answer, and `host_override` does the
same from the tests.

Switching a machine that is already installed behaves like a real PC, on
purpose: a disk installed under UEFI (GPT, an EFI system partition, Windows
Boot Manager in NVRAM) does not start under the BIOS, and one installed under
the BIOS (MBR, an active partition) does not start under UEFI, until the
student converts it (MBR2GPT) or reinstalls. winlab never repairs it. A new
install partitions to match the firmware it was started with: Windows Setup
does that by itself, and the answer file winlab writes asks for GPT under
UEFI and MBR under the BIOS (unattend._disk_config).
"""

from __future__ import annotations

import os
from pathlib import Path

from . import naming, paths
from .model import CUSTOM, WINDOWS_CLIENT, WINDOWS_SERVER

UEFI, SECURE, BIOS = "uefi", "uefi-secure", "bios"
CHOICES = (UEFI, SECURE, BIOS)
TITLES = {UEFI: "UEFI", SECURE: "UEFI with Secure Boot", BIOS: "Legacy BIOS"}
TEMPLATE_VAR = "secure_boot_template"
ENV = "WINLAB_SECUREBOOT"

host_override = None     # the tests: (ok, why)


class FirmwareError(Exception):
    pass


def fitted(node) -> bool:
    """The choice is offered on Windows machines: the ones winlab installs
    and Windows installed by hand from its own media."""
    kind = getattr(node, "kind", "")
    if kind in (WINDOWS_SERVER, WINDOWS_CLIENT):
        return True
    if kind == CUSTOM:
        from .images import WINDOWS_IMAGES
        return getattr(node, "image", "") in WINDOWS_IMAGES
    return False


def host_support(accel: str) -> tuple[bool, str]:
    """Whether this PC can run a machine with Secure Boot, and in plain
    words why not."""
    if host_override is not None:
        return host_override
    forced = os.environ.get(ENV, "")
    if forced in ("1", "0"):
        return (forced == "1", "" if forced == "1" else f"turned off on this PC ({ENV}=0)")
    if paths.uefi_firmware() and not paths.uefi_secure_firmware():
        return False, ("this PC's QEMU has no Secure Boot firmware (share/qemu/edk2-x86_64-secure-code.fd "
                       "is missing): reinstall QEMU with winlab setup")
    if accel == "kvm":
        return True, ""
    if accel == "tcg":
        return True, "software emulation runs System Management Mode too, slowly"
    if accel == "whpx":
        return False, ("this PC runs machines through the Windows Hypervisor Platform (WHPX), which gives QEMU "
                       "no System Management Mode, and QEMU's only Secure Boot firmware needs it to keep its keys "
                       "safe (QEMU refuses smm=on there). Secure Boot needs the winlab appliance (KVM)")
    if accel == "hvf":
        return False, ("QEMU on macOS (Hypervisor.framework) has no System Management Mode, which QEMU's Secure "
                       "Boot firmware needs")
    return False, f"this PC's accelerator ({accel or 'none'}) cannot run System Management Mode"


def template(node) -> str:
    from .secureboot import DEFAULT_TEMPLATE
    return str((getattr(node, "vars", None) or {}).get(TEMPLATE_VAR) or DEFAULT_TEMPLATE)


def default(node, uefi_default: bool) -> str:
    return UEFI if uefi_default else BIOS


def wanted(node, uefi_default: bool) -> str:
    """What the machine is set to (its lab file), or what it gets by default."""
    fw = getattr(node, "firmware", "") or ""
    return fw if fw in CHOICES else default(node, uefi_default)


def effective(node, accel: str, uefi_default: bool) -> tuple[str, str]:
    """(what the machine really boots with, why it is not what it was set
    to, or ''). A machine never fails to start because of Secure Boot: where
    it cannot run, the machine starts with plain UEFI and the reason is said."""
    want = wanted(node, uefi_default)
    if want == BIOS:
        return BIOS, ""
    if not paths.uefi_firmware():
        return BIOS, "this PC's QEMU has no UEFI firmware (edk2-x86_64-code.fd): the machine starts with the BIOS"
    if want == UEFI:
        return UEFI, ""
    ok, why = host_support(accel)
    if not ok:
        return UEFI, f"Secure Boot cannot run on this PC: {why}"
    from . import secureboot
    gone = secureboot.missing(template(node))
    if gone:
        return UEFI, ("Microsoft's Secure Boot certificates are not on this PC yet ("
                      + ", ".join(c.name for c in gone) + "): run winlab secureboot fetch")
    return SECURE, ""


def qemu_args(mode: str, code: Path, vars_fd: Path) -> tuple[str, list[str]]:
    """(the -machine value, the firmware's arguments) for one mode."""
    if mode == SECURE:
        return "q35,smm=on", [
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_fd}",
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-global", "ICH9-LPC.disable_s3=1",
        ]
    if mode == UEFI:
        return "q35", [
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_fd}",
            "-global", "driver=cfi.pflash01,property=secure,value=off",
        ]
    return "q35", []


# ------------------------------------------------------------------ the settings
def nvram_state(lab_name: str, node_id: str) -> dict:
    """What the machine's NVRAM holds now (secureboot.describe), or {}."""
    p = paths.lab_dir(lab_name) / node_id / "uefi-vars.fd"
    try:
        data = p.read_bytes()
    except OSError:
        return {}
    from .secureboot import describe
    return describe(data)


def view(lab, node, accel: str) -> dict | None:
    """The Security page, the Firmware page's boot mode and the firmware
    setup screen, for one machine."""
    if not fitted(node):
        return None
    from . import secureboot
    uefi_default = _uefi_default(node)
    want = wanted(node, uefi_default)
    mode, why = effective(node, accel, uefi_default)
    can, host_why = host_support(accel)
    tpl = template(node)
    from . import bitlocker
    nd = paths.lab_dir(lab.name) / node.id
    return {
        "tpm": bitlocker.tpm_fitted(nd, node) if getattr(node, "is_windows", False) else False,
        "tpm_available": bitlocker.tpm_available(),
        "set": want, "runs": mode, "why": why, "title": TITLES[want],
        "secure_can": can and bool(paths.uefi_firmware()), "secure_why": host_why,
        "certs_ready": secureboot.ready(tpl),
        "template": tpl, "templates": dict(secureboot.TEMPLATES),
        "nvram": nvram_state(lab.name, node.id),
        "installed_as": installed_as(lab.name, node),
        "uefi_available": bool(paths.uefi_firmware()),
    }


def _uefi_default(node) -> bool:
    """What winlab gives this machine when nothing is set (the provider's
    own rule, without a plan)."""
    if not paths.uefi_firmware():
        return False
    if getattr(node, "kind", "") == CUSTOM:
        from .images import HAND_INSTALL, ImageError, custom_image, templates
        from .netos import is_router
        if is_router(node):
            return False  # the vendors' virtual routers boot with the legacy BIOS (winlab/netos.py)
        from . import android
        if android.is_hand_android(node):
            return android.uefi(node)  # Android-x86 installs its GRUB on an MBR disk (winlab/android.py)
        if node.image in HAND_INSTALL:
            return True
        tpl = templates().get(node.image)
        if tpl is not None:
            return tpl.firmware == "uefi"
        try:
            return custom_image(node.image).firmware == "uefi"
        except ImageError:
            return False
    return True


def installed_as(lab_name: str, node) -> str:
    """The firmware the machine's disk was installed under, as winlab knows
    it ('uefi', 'bios' or '' for not installed or unknown): kept beside the
    machine the first time it starts, from the base it was cloned from or
    the firmware its own Setup ran under."""
    p = paths.lab_dir(lab_name) / node.id / "installed-firmware"
    try:
        return p.read_text(encoding="ascii").strip()
    except OSError:
        return ""


def note_install(lab_name: str, node, mode: str) -> None:
    """Remembers the firmware a machine's disk was first started under."""
    d = paths.lab_dir(lab_name) / node.id
    p = d / "installed-firmware"
    if not p.exists() and (d / "system.qcow2").exists():
        try:
            p.write_text(BIOS if mode == BIOS else UEFI, encoding="ascii")
        except OSError:
            pass


def mismatch(lab_name: str, node, mode: str) -> str:
    """A sentence when the firmware no longer matches the disk's layout."""
    was = installed_as(lab_name, node)
    now = BIOS if mode == BIOS else UEFI
    if not was or was == now:
        return ""
    if now == BIOS:
        return ("its disk was installed under UEFI (GPT, an EFI system partition): the BIOS finds no boot code "
                "on it and Windows does not start. Set it back to UEFI, or reinstall")
    return ("its disk was installed under the BIOS (MBR, an active partition): UEFI finds no EFI system "
            "partition on it and Windows does not start. Convert it inside Windows first (MBR2GPT /convert "
            "/allowFullOS), or set it back to Legacy BIOS")


def set_firmware(lab, node_id: str, want: str, accel: str, running: set[str], template_name: str = "") -> str:
    """Changes one machine's firmware (and its Secure Boot template); the
    machine must be off. Secure Boot is refused, with the reason, where this
    PC cannot run it."""
    from . import secureboot
    node = lab.nodes.get(node_id)
    if node is None:
        raise FirmwareError("no such machine")
    name = naming.display(lab, node_id)
    if not fitted(node):
        raise FirmwareError(f"{name} has no firmware choice here: it is offered on Windows machines")
    if want not in CHOICES:
        raise FirmwareError(f"the firmware is one of {', '.join(CHOICES)}, not {want!r}")
    tpl = template_name or template(node)
    if tpl not in secureboot.TEMPLATES:
        raise FirmwareError(f"no Secure Boot template {tpl!r}: {', '.join(secureboot.TEMPLATES)}")
    cur_tpl = template(node)
    cur = wanted(node, _uefi_default(node))
    if want == cur and tpl == cur_tpl:
        return f"{name}: firmware unchanged ({TITLES[want]})"
    if node_id in running:
        raise FirmwareError(f"shut {name} down first: firmware settings change with the machine off")
    if want == SECURE:
        ok, why = host_support(accel)
        if not ok:
            raise FirmwareError(f"Secure Boot cannot be enabled: {why}")
        if not paths.uefi_firmware():
            raise FirmwareError("Secure Boot cannot be enabled: this PC's QEMU has no UEFI firmware")
    if want in (UEFI, SECURE) and not paths.uefi_firmware():
        raise FirmwareError("UEFI cannot be chosen: this PC's QEMU has no UEFI firmware (edk2-x86_64-code.fd)")
    node.firmware = "" if want == default(node, _uefi_default(node)) and want != SECURE else want
    if tpl == secureboot.DEFAULT_TEMPLATE:
        node.vars.pop(TEMPLATE_VAR, None)
    else:
        node.vars[TEMPLATE_VAR] = tpl
    msg = f"{name}: firmware {TITLES[want]}"
    if want == SECURE:
        msg += f", template {secureboot.TEMPLATES[tpl]}"
        if not secureboot.ready(tpl):
            msg += " (Microsoft's certificates are not on this PC yet: winlab secureboot fetch; until then it starts without Secure Boot)"
    warn = mismatch(lab.name, node, want)
    if warn:
        msg += f". Note: {warn}"
    return msg


def act(dash, action: str, params: dict) -> dict:
    """wb-firmware: op set (firmware, template)."""
    from .workbench import _running, _save
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    try:
        msg = set_firmware(lab, node_id, str(params.get("firmware") or ""),
                           getattr(dash, "accel", "") or "tcg", _running(lab.name),
                           str(params.get("template") or ""))
        _save(dash)
        return {"ok": True, "message": msg}
    except FirmwareError as exc:
        return {"ok": False, "message": str(exc)}
