"""Templates and clones: a machine turned into an image, and new machines
made from a machine.

A template is a system disk in the image store that `lab up` thin-clones
the way it clones a prepared base, plus the hardware the machine had. It
is made from a *stopped* machine without touching it: the disk is copied,
and for Windows the copy is booted once, alone and with no network, so the
agent can run `sysprep /generalize` on it and power it off. Every machine
made from such a template is a new computer: own name, own SID, the lab's
answer file and roles on first boot, like a machine made from the base.

A clone is the same copy made straight into a new machine of the same lab:
its definition is copied (new name, fresh static addresses), its data disks
go with it, and a Windows clone is generalised the same way unless asked
not to be. Linux and custom machines run no agent, so their copies are
identical twins inside (same hostname), which is what Hyper-V's export and
import give as well.

Nothing here reaches outside the lab: the generalising boot has no network
device at all and talks to the host over the same loopback serial channel
as every other machine.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

from . import editor, images, paths, state
from .guestctl import GuestChannel, GuestError
from .images import ImageError, Template
from .model import Lab, Node
from .providers.qemu import assert_isolated, cpu_model

Emit = Callable[[str], None]

BOOT_TIMEOUT = 900.0         # the copy must answer on its agent within this
GENERALIZE_TIMEOUT = 2400.0  # sysprep normally takes 5-15 min; Win11 longer
MIN_MEMORY_MB = 2048         # sysprep on less than this is a coin toss

# The answer file sysprep reads while generalising. SkipRearm keeps the
# evaluation clock as it is instead of spending one of the licence's few
# rearms on every template (a clone can rearm itself with `lab eval --rearm`);
# PersistAllDeviceInstalls keeps the drivers the machine already has, since
# every clone runs on exactly the same virtual hardware.
SYSPREP_UNATTEND = """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="generalize">
    <component name="Microsoft-Windows-Security-SPP" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SkipRearm>1</SkipRearm>
    </component>
    <component name="Microsoft-Windows-PnpSysprep" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
    </component>
  </settings>
</unattend>
"""
SYSPREP_XML = r"C:\winlab\sysprep-template.xml"
SYSPREP_LOG = r"C:\Windows\System32\Sysprep\Panther\setuperr.log"

_SYSPREP_START = (
    "Start-Process -FilePath \"$env:WINDIR\\System32\\Sysprep\\sysprep.exe\" "
    "-ArgumentList '/generalize','/oobe','/shutdown','/quiet',"
    f"'/unattend:{SYSPREP_XML}'; 'started'"
)
_SYSPREP_ALIVE = (
    "if (Get-Process -Name sysprep -ErrorAction SilentlyContinue) {'running'} else {'gone'}"
)
_SYSPREP_TAIL = (
    f"if (Test-Path '{SYSPREP_LOG}') {{ Get-Content '{SYSPREP_LOG}' | "
    "Select-Object -Last 12 }"
)


class TemplateError(Exception):
    pass


def _say(line: str) -> None:
    print(f"  {line}")


def node_dir(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id


# ----------------------------------------------------------------- disks
def disk_info(disk: Path) -> dict:
    out = images._run_img(["info", "--output=json", "-U", str(disk)])
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise TemplateError(f"cannot read {disk}: {exc}") from exc


def backing_of(disk: Path) -> Path | None:
    info = disk_info(disk)
    full = info.get("full-backing-filename") or info.get("backing-filename")
    return Path(full) if full else None


def virtual_gb(disk: Path) -> int:
    return int(round(int(disk_info(disk).get("virtual-size") or 0) / (1024**3)))


def _relative_backing(backing: Path, dest: Path) -> str:
    """Inside the image store a backing path is relative, so the store can
    move as a whole (WINLAB_IMAGES); anywhere else it is absolute."""
    store = paths.images_dir().resolve()
    b = backing.resolve()
    d = dest.resolve().parent
    try:
        b.relative_to(store)
        d.relative_to(store)
    except ValueError:
        return str(b)
    return os.path.relpath(b, d).replace(os.sep, "/")


def copy_disk(src: Path, dest: Path, full: bool = False) -> Path:
    """A copy of a machine's disk. Thin (the default) keeps the backing file
    the machine had and holds only what the machine wrote onto it, so a
    template of a 60 GB Windows machine is typically a few GB; full writes
    everything into one standalone image. Checkpoints are not copied."""
    if not src.exists():
        raise TemplateError(f"no disk at {src}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["convert", "-O", "qcow2"]
    backing = None if full else backing_of(src)
    if backing is not None:
        args += ["-B", _relative_backing(backing, dest), "-F", "qcow2"]
    try:
        images._run_img(args + [str(src), str(dest)])
    except ImageError as exc:
        raise TemplateError(str(exc)) from exc
    return dest


# ------------------------------------------------------------ generalise
def generalize_argv(disk: Path, nvram: Path | None, cpus: int, memory_mb: int,
                    accel: str, serial: int, qmp: int) -> list[str]:
    """QEMU for the one boot that generalises a Windows copy: the same
    machine type and disk controller the lab uses, no network device of any
    kind, the serial agent and QMP on loopback, no window."""
    args = [
        str(paths.qemu_exe()),
        "-name", "winlab:template",
        "-machine", "q35",
        "-accel", accel,
        "-cpu", cpu_model(accel),
        "-smp", str(max(1, cpus)),
        "-m", str(max(MIN_MEMORY_MB, memory_mb)),
        "-rtc", "base=localtime,clock=host",
        "-no-user-config",
        "-nodefaults",
    ]
    if nvram is not None:
        code = paths.qemu_dir() / "share" / "qemu" / "edk2-x86_64-code.fd"
        args += [
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={nvram}",
            "-global", "driver=cfi.pflash01,property=secure,value=off",
        ]
    args += [
        "-device", "ich9-ahci,id=ahci",
        "-drive", f"id=sys,file={disk},if=none,format=qcow2,cache=writeback,discard=unmap",
        "-device", "ide-hd,bus=ahci.0,drive=sys,bootindex=0",
        "-device", "qemu-xhci,id=xhci",
        "-device", "usb-tablet,bus=xhci.0",
        "-qmp", f"tcp:127.0.0.1:{qmp},server=on,wait=off",
        "-chardev", f"socket,id=ser0,host=127.0.0.1,port={serial},server=on,wait=off",
        "-serial", "chardev:ser0",
        "-display", "none",
        "-device", "VGA",
    ]
    assert_isolated(args)
    return args


def _sysprep_failure(ch: GuestChannel) -> str:
    try:
        res = ch.run(_SYSPREP_TAIL, timeout=30)
        return res.out.strip()[-1500:]
    except GuestError:
        return ""


def generalize(disk: Path, nvram: Path | None, cpus: int, memory_mb: int, accel: str,
               log: Path, emit: Emit = _say, timeout: float = GENERALIZE_TIMEOUT) -> None:
    """Boots the copy once and has its agent run sysprep /generalize; returns
    when the machine has powered itself off. Raises with sysprep's own log
    tail when it refuses (a Windows 11 machine with per-user store apps is
    the usual reason)."""
    from .prepare import _free_port

    serial = _free_port()
    qmp = _free_port(serial + 1)
    argv = generalize_argv(disk, nvram, cpus, memory_mb, accel, serial, qmp)
    log.parent.mkdir(parents=True, exist_ok=True)
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    with log.open("ab") as fh:
        proc = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, creationflags=flags)
    ch: GuestChannel | None = None
    try:
        emit("booting the copy alone, with no network, and waiting for its agent…")
        ch = GuestChannel(serial, timeout=30).connect(retries=90, delay=2)
        ch.wait_responsive(timeout=BOOT_TIMEOUT)
        emit("agent answered; starting sysprep /generalize (it powers the copy off when done)")
        ch.put_file(SYSPREP_XML, SYSPREP_UNATTEND.encode("utf-8"))
        res = ch.run(_SYSPREP_START, timeout=120)
        if not res.ok:
            raise TemplateError(f"could not start sysprep: {(res.err or res.out).strip()[:400]}")

        deadline = time.monotonic() + timeout
        gone_since = 0.0
        while proc.poll() is None:
            if time.monotonic() > deadline:
                raise TemplateError(
                    f"sysprep did not finish within {timeout / 60:.0f} min\n"
                    f"{_sysprep_failure(ch) or f'see {log}'}"
                )
            time.sleep(10)
            if proc.poll() is not None:
                break
            try:
                alive = ch.run(_SYSPREP_ALIVE, timeout=20)
            except GuestError:
                continue  # the guest is on its way down
            if alive.ok and "gone" in alive.out:
                # sysprep exits a few seconds before the power-off it asked
                # for; still here after that, it failed and left a dialog.
                gone_since = gone_since or time.monotonic()
                if time.monotonic() - gone_since > 45:
                    raise TemplateError(
                        "sysprep stopped without powering the machine off; its log says:\n"
                        + (_sysprep_failure(ch) or f"nothing (see {log})")
                    )
            else:
                gone_since = 0.0
        emit("the copy powered off: generalised")
    except GuestError as exc:
        raise TemplateError(f"the copy's agent did not cooperate: {exc}") from exc
    finally:
        if ch is not None:
            ch.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


# ---------------------------------------------------------------- checks
def _source(lab: Lab, node_id: str) -> tuple[Node, Path]:
    node = lab.nodes.get(node_id)
    if node is None or node_id == "fabric":
        raise TemplateError(f"no machine '{node_id}' in lab '{lab.name}'")
    if "ad-ds" in node.roles:
        raise TemplateError(
            f"{node_id} is a domain controller: Active Directory forbids copying one "
            f"(sysprep refuses, and a copied DC corrupts replication). Promote another "
            f"machine with the ad-ds role instead"
        )
    st = state.load(lab.name)
    if st and node_id in st.running():
        raise TemplateError(f"stop {node_id} first: a copy of a running disk is not consistent")
    if st and node_id in st.suspended():
        raise TemplateError(
            f"{node_id} is suspended (hibernated): a copy would wake up as the original "
            f"instead of generalising. Resume it and shut it down first"
        )
    disk = node_dir(lab.name, node_id) / "system.qcow2"
    if not disk.exists():
        raise TemplateError(f"{node_id} has never been started, so there is nothing to copy")
    return node, disk


def _accel(accel: str) -> str:
    if accel:
        return accel
    from .prepare import _detect_accel

    return _detect_accel()


# ---------------------------------------------------------------- create
def create(lab: Lab, node_id: str, template_id: str, title: str = "",
           generalize_: bool | None = None, full: bool = False, accel: str = "",
           emit: Emit = _say) -> Template:
    """Turns a stopped machine into a template, leaving the machine as it is."""
    try:
        images.check_template_id(template_id)
    except ImageError as exc:
        raise TemplateError(str(exc)) from exc
    if template_id in images.templates():
        raise TemplateError(f"template '{template_id}' exists; remove it first")
    node, disk = _source(lab, node_id)
    if generalize_ is None:
        generalize_ = node.is_windows
    if generalize_ and not node.is_windows:
        raise TemplateError(f"{node_id} runs no winlab agent, so it cannot be generalised")

    nvram_src = node_dir(lab.name, node_id) / "uefi-vars.fd"
    tpl = Template(
        id=template_id, title=title or f"{node_id} from {lab.name}", kind=node.kind,
        image=node.image, firmware="uefi" if nvram_src.exists() else "bios",
        disk_gb=virtual_gb(disk), cpus=node.cpus, memory_mb=node.memory_mb,
        data_disks_gb=list(node.data_disks_gb), generalized=False,
        source=f"{lab.name}/{node_id}", created=time.time(), description=node.description,
    )
    work = tpl.disk.with_name(f"{template_id}.building.qcow2")
    emit(f"copying {node_id}'s disk ({'everything' if full else 'only what it wrote'})…")
    copy_disk(disk, work, full=full)
    try:
        if nvram_src.exists():
            shutil.copy2(nvram_src, tpl.nvram)
        if generalize_:
            generalize(work, tpl.nvram if nvram_src.exists() else None, node.cpus,
                       node.memory_mb, _accel(accel), tpl.disk.with_suffix(".log"), emit)
            tpl.generalized = True
        work.replace(tpl.disk)
    except Exception:
        work.unlink(missing_ok=True)
        tpl.nvram.unlink(missing_ok=True)
        raise
    entries = images.templates()
    entries[template_id] = tpl
    images.save_templates(entries)
    emit(f"template {template_id} ready ({tpl.size_text}): "
         f"winlab node {lab.name} add <name> --image {template_id}")
    return tpl


# ----------------------------------------------------------------- clone
def clone_machine(lab: Lab, src_id: str, new_id: str, ip: str = "",
                  generalize_: bool | None = None, accel: str = "",
                  emit: Emit = _say) -> Node:
    """A second machine made from the first: definition, system disk, data
    disks, USB stick and firmware variables. Saves the lab when the copy
    succeeded, and leaves nothing behind when it did not."""
    src, disk = _source(lab, src_id)
    if generalize_ is None:
        generalize_ = src.is_windows
    if generalize_ and not src.is_windows:
        raise TemplateError(f"{src_id} runs no winlab agent, so its clone cannot be generalised")
    try:
        node = editor.clone_node(lab, src_id, new_id, ip=ip)
    except editor.EditError as exc:
        raise TemplateError(str(exc)) from exc

    src_dir, dst_dir = node_dir(lab.name, src_id), node_dir(lab.name, new_id)
    if dst_dir.exists() and any(dst_dir.iterdir()):
        # Disks of a machine removed from the lab earlier: the name is free
        # again in the definition, so the files are leftovers.
        emit(f"replacing leftover disks of a machine once called {new_id}")
        shutil.rmtree(dst_dir)
    try:
        emit(f"copying {src_id}'s disks to {new_id}…")
        copy_disk(disk, dst_dir / "system.qcow2")
        for name in ("data*.qcow2", "usb0.qcow2"):
            for f in sorted(src_dir.glob(name)):
                copy_disk(f, dst_dir / f.name, full=True)
        nvram = src_dir / "uefi-vars.fd"
        if nvram.exists():
            shutil.copy2(nvram, dst_dir / "uefi-vars.fd")
        if generalize_:
            generalize(dst_dir / "system.qcow2",
                       dst_dir / "uefi-vars.fd" if nvram.exists() else None,
                       src.cpus, src.memory_mb, _accel(accel), dst_dir / "qemu.log", emit)
        editor.save(lab)
    except Exception:
        lab.nodes.pop(new_id, None)
        shutil.rmtree(dst_dir, ignore_errors=True)
        raise
    nic = node.primary_nic
    emit(f"{new_id} added: {nic.network if nic else '-'} "
         f"{nic.ip if nic and nic.ip else 'dhcp'}, "
         + ("a new computer on first boot" if generalize_ else "an identical copy inside"))
    return node


def describe(tpl: Template) -> str:
    ident = "new identity per machine" if tpl.generalized else "identical copies"
    return f"{tpl.kind}, from {tpl.source or '?'}, {tpl.size_text}, {ident}"
