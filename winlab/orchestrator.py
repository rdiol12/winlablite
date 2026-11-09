"""Boot, track, suspend and stop a lab.

Order matters: the fabric listens on the loopback links, every node connects to
them, so the fabric must be up before the first node. Within the nodes, boot
order is honoured so a domain controller is serving DNS before a member tries
to find the domain; a machine marked wait_ready holds the ones after it until
its agent answers, and start_delay adds a fixed pause.

Save (suspend): where QEMU can save a machine's memory (KVM, TCG), it is
Hyper-V's Save: the machine is paused, its memory and device state are
written to saved.vmstate beside its disks, and the next start reads them
back (-incoming file:), so it carries on where it was, whatever runs in it.
QEMU cannot save a machine's memory with the WHPX accelerator on Windows
hosts (it registers a migration blocker, so savevm and migrate both refuse);
there winlab saves the way a laptop does. Windows machines hibernate through
the agent: the memory image goes into hiberfil.sys on the machine's own disk,
the process exits, and the next start is Windows' own resume, sessions and
open windows included. Machines without an agent get an ACPI power-button
press and shut down cleanly. The fabric is rebuilt on every start anyway.
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import alpineovl, appliances, cloudinit, images, membudget, openwrt, opnsense, paths, provision, secrets, state
from .state import SUSPENDED
from .model import CUSTOM, LINUX, Lab
from .netplan import TopologyPlan, compile_topology
from .providers.qemu import QemuProvider
from .schema import load as load_lab
from . import imaging


class OrchestratorError(Exception):
    pass


@dataclass
class BootReport:
    lab: str
    started: list[str]
    skipped: list[str]
    accel: str
    display: str
    resumed: list[str] = field(default_factory=list)  # started from hibernation
    # Machines whose QEMU exited right after it was started: id -> why (the
    # last error lines of its qemu.log). The others started anyway.
    failed: dict[str, str] = field(default_factory=dict)


@dataclass
class SuspendReport:
    lab: str
    saved: list[str] = field(default_factory=list)        # memory written to saved.vmstate
    hibernated: list[str] = field(default_factory=list)   # Windows, resume on next start
    shut_down: list[str] = field(default_factory=list)    # no agent: clean ACPI shutdown
    powered_off: list[str] = field(default_factory=list)  # did not finish in time; killed
    skipped: list[str] = field(default_factory=list)      # were not running
    failed: dict[str, str] = field(default_factory=dict)  # still running, with the reason


READY_TIMEOUT = 600.0     # wait_ready: how long the next machines wait for an agent
SUSPEND_TIMEOUT = 300.0   # hibernation / clean shutdown must finish within this
HIBERNATE = (
    "powercfg /hibernate on | Out-Null; powercfg /hibernate /type full | Out-Null; "
    "shutdown /h; exit $LASTEXITCODE"
)


def exit_reason(log: Path, lines: int = 3, since: int = 0) -> str:
    """The last error QEMU wrote to a machine's qemu.log (from byte `since`:
    this start's own lines), for a machine that stopped by itself: '' when
    there is none."""
    try:
        with open(log, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(since, fh.tell() - 8192))
            tail = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return ""
    errs = [l.strip() for l in tail if l.strip() and ("qemu" in l.lower() or "error" in l.lower()
                                                      or "could not" in l.lower() or "failed" in l.lower())]
    keep = list(dict.fromkeys(errs))[-lines:] or [l.strip() for l in tail if l.strip()][-1:]
    return " / ".join(l[:300] for l in keep)


def _noop(_line: str) -> None:
    pass


def _mmss(seconds: float) -> str:
    return f"{int(seconds) // 60}:{int(seconds) % 60:02d}"


# The three guest-facing steps below are module functions so tests can stand
# them in without a running machine.
_sleep = time.sleep

FABRIC_LISTEN_TIMEOUT = 60.0  # how long the router's switch may take to open its ports


def _wait_fabric(qmp_port: int, proc, netdevs: list[str], timeout: float = FABRIC_LISTEN_TIMEOUT) -> str:
    """Waits until the router's switch has every port open, as one waits
    for a switch's port lights before plugging PCs in: its QEMU answers on
    its monitor and lists each port's backend (each one is listening on its
    loopback port by then). Returns "" when ready, else why not."""
    from .qmp import Qmp, QmpError

    deadline = time.monotonic() + timeout
    missing, answered = list(netdevs), False
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return "its QEMU exited before opening its ports"
        try:
            with Qmp(qmp_port, timeout=5) as mon:
                text = str(mon.call("human-monitor-command", **{"command-line": "info network"}) or "")
            missing, answered = [n for n in netdevs if f"{n}:" not in text], True
            if not missing:
                return ""
        except QmpError:
            pass
        _sleep(0.2)
    return (f"its switch did not open {len(missing)} of its {len(netdevs)} ports within {timeout:.0f} s"
            if answered else f"its monitor did not answer within {timeout:.0f} s")


FABRIC_BOOT_TIMEOUT = 300.0   # a restarted router's boot, before the machines' links come back


def _wait_router_ready(serial_port: int, timeout: float) -> bool:
    """True once the router has run its setup script (the line it logs at
    the end of it, winlab/netplan.py render_fabric_setup)."""
    from .guestctl import GuestChannel, GuestError

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with GuestChannel(serial_port, timeout=20).connect(retries=1) as ch:
                res = ch.run("dmesg | grep -c 'winlab fabric ready' || true", shell="sh", timeout=20)
                if (res.out or "").strip() not in ("", "0"):
                    return True
        except GuestError:
            pass
        _sleep(3.0)
    return False


def _log_tail(log: Path) -> str:
    """The last thing QEMU wrote, which says why it stopped."""
    try:
        lines = [l.strip() for l in log.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    except OSError:
        return ""
    return lines[-1][:300] if lines else ""


def _wait_agent(serial_port: int, timeout: float) -> bool:
    """True once the machine's winlab agent answers a command."""
    from .guestctl import GuestChannel, GuestError

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with GuestChannel(serial_port, timeout=20).connect(retries=1) as ch:
                ch.wait_responsive(timeout=max(5.0, deadline - time.monotonic()))
                return True
        except GuestError:
            _sleep(5.0)
    return False


def _hibernate(serial_port: int) -> str:
    """Ask a Windows machine to hibernate. Returns "" or the reason it refused."""
    from .guestctl import GuestChannel, GuestError

    try:
        with GuestChannel(serial_port, timeout=60).connect(retries=3, delay=2) as ch:
            res = ch.run(HIBERNATE, shell="powershell", timeout=90)
    except GuestError as exc:
        return f"the agent did not answer ({exc}); is Windows still booting?"
    if not res.ok:
        return (res.err or res.out).strip()[:300] or f"shutdown /h exited {res.rc}"
    return ""


SAVED_STATE = "saved.vmstate"
SAVE_TIMEOUT = 600.0


def _save_state(qmp_port: int, path: Path, timeout: float = SAVE_TIMEOUT) -> str:
    """Hyper-V's Save: pause the machine, write its memory and device state
    to `path` and quit. Returns "" or why it could not (WHPX refuses; the
    machine then runs on as it was)."""
    from .qmp import Qmp, QmpError

    try:
        with Qmp(qmp_port, timeout=30) as mon:
            was_running = (mon.call("query-status") or {}).get("running", True)
            mon.call("stop")
            try:
                mon.call("migrate", uri=f"file:{path}")
                deadline = time.monotonic() + timeout
                while True:
                    status = (mon.call("query-migrate") or {}).get("status", "")
                    if status == "completed":
                        break
                    if status in ("failed", "cancelled") or time.monotonic() > deadline:
                        if status not in ("failed", "cancelled"):
                            mon.call("migrate_cancel")
                        raise QmpError(f"writing the saved state {status or 'timed out'}")
                    _sleep(0.2)
            except QmpError:
                path.unlink(missing_ok=True)
                if was_running:
                    mon.call("cont")
                raise
            try:
                mon.call("quit")
            except QmpError:
                pass  # the monitor goes with the process
    except QmpError as exc:
        return str(exc)
    except OSError as exc:
        return str(exc)
    return ""


def _wait_restored(qmp_port: int, proc, timeout: float = SAVE_TIMEOUT) -> bool:
    """True once a machine started from its saved state runs; False if
    QEMU could not read it back (it exits)."""
    from .qmp import Qmp, QmpError

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with Qmp(qmp_port, timeout=5) as mon:
                status = (mon.call("query-status") or {}).get("status", "")
                if status not in ("inmigrate", "prelaunch", "restore-vm"):
                    if status in ("paused", "postmigrate"):
                        mon.call("cont")
                    return True
        except QmpError:
            pass
        _sleep(0.3)
    return proc.poll() is None


def _acpi_powerdown(qmp_port: int) -> str:
    """Press a machine's virtual power button."""
    from .qmp import Qmp, QmpError

    try:
        with Qmp(qmp_port) as mon:
            mon.call("system_powerdown")
    except QmpError as exc:
        return str(exc)
    return ""


def firmware_setup(qmp_port: int, seconds: float = 10.0, pause: float = 0.25,
                   reset: bool = True) -> str:
    """Restart a machine and hold Esc through its power-on screen, as a
    person does to get into a PC's firmware: the UEFI setup (boot order,
    boot manager, network boot) or the BIOS boot menu. The key goes on in
    the background; returns "" or why the machine could not be reached."""
    import threading
    from .qmp import Qmp, QmpError

    try:
        mon = Qmp(qmp_port).__enter__()
        if reset:
            mon.call("system_reset")
    except QmpError as exc:
        return str(exc)

    def press() -> None:
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                mon.call("send-key", keys=[{"type": "qcode", "data": "esc"}])
                time.sleep(pause)
        except QmpError:
            pass
        finally:
            mon.__exit__()

    threading.Thread(target=press, daemon=True).start()
    return ""


FIRMWARE_UEFI = "uefi"
FIRMWARE_BIOS = "bios"


class Orchestrator:
    def __init__(self, lab: Lab, accel: str, display: str = "window") -> None:
        self.lab = lab
        self.accel = accel
        self.display = display
        # While the fabric is up it is listening on the link ports, so they are
        # busy by design: a machine started now must dial those same stable
        # ports, not hunt for free ones the fabric is not listening on.
        self.plan: TopologyPlan = compile_topology(
            lab, check_ports=not _fabric_running(lab.name))
        self.provider = QemuProvider(self.plan, accel=accel, display=display)
        self.workdir = paths.lab_dir(lab.name)

    # ------------------------------------------------------------- firmware
    def _firmware(self) -> str:
        return FIRMWARE_UEFI if paths.uefi_firmware() else FIRMWARE_BIOS

    # -------------------------------------------------------------- staging
    def _stage_disks(self, node_id: str) -> None:
        node = self.lab.nodes.get(node_id)
        ndir = self.provider.node_dir(node_id)
        ndir.mkdir(parents=True, exist_ok=True)

        if node_id == "fabric":
            # Fabric runs the Alpine ISO diskless with the winlab overlay; the
            # cloned qcow2 is just writable scratch for apk cache and state.
            images.clone("alpine", self.provider.disk_path("fabric"))
            provision.build_fabric_config(self.plan, ndir / "config.img")
            # The overlay rides on its own FAT volume: Alpine's init restores
            # the first *.apkovl.tar.gz it finds on a volume it can mount.
            alpineovl.overlay_disk(ndir / "overlay.img", "fabric")
            return

        assert node is not None
        # A machine keeps its disks between `lab down` and `lab up`, like a VM
        # on any hypervisor; `lab reset` (or an exercise's reset_nodes) is the
        # only thing that puts it back to the image it was made from.
        disk = self.provider.disk_path(node_id)
        fresh = not disk.exists()
        from . import netos
        ok, why = netos.can_run(node, self.provider.accel)
        if not ok:
            raise OrchestratorError(f"node '{node_id}': {why}")
        if not disk.exists():
            if netos.is_disk_router(node):
                # A vendor router: a thin clone of the vendor's own disk (winlab/netos.py).
                if not netos.ready(node.image):
                    raise OrchestratorError(f"node '{node_id}': {netos.missing_text(node.image)}")
                images.clone(node.image, disk)
            elif images.is_template(node.image):
                images.clone(node.image, disk)
            elif images.is_hand_install(node):
                try:
                    if not imaging.is_netboot(node):  # a bare PC has no disc: it boots from the network
                        images.hand_media(node.image)
                except images.ImageError as exc:
                    raise OrchestratorError(f"node '{node_id}': {exc}") from exc
                images.create_blank(disk, int(node.vars.get("disk_gb") or images.HAND_DISK_GB))
            elif node.kind == CUSTOM:
                entry = images.custom_image(node.image)
                if not entry.iso.exists():
                    raise OrchestratorError(
                        f"node '{node_id}': the ISO for custom image '{node.image}' is "
                        f"missing; add it again with: winlab images add {node.image} <path>"
                    )
                images.create_blank(disk, int(node.vars.get("disk_gb") or entry.disk_gb))
            elif node.kind == LINUX and appliances.is_appliance(node.image):
                app = appliances.get_or_raise(node.image)
                if not appliances.ready(node.image):
                    raise OrchestratorError(
                        f"node '{node_id}': the {app.short} image is not on this PC yet; "
                        f"fetch it from {app.publisher} with: winlab images fetch {node.image}"
                    )
                images.clone(node.image, disk)
                images.resize_disk(disk, int(node.vars.get("disk_gb") or app.disk_gb))
            else:
                image_id = "alpine" if node.kind == LINUX else node.image
                images.clone(image_id, disk)
        if node.kind == CUSTOM and node.image == "win11":
            from . import fatfs, unattend
            img = fatfs.floppy("SETUP")
            img.add_file("autounattend.xml", unattend.setup_helper())
            img.write(ndir / "setup-helper.img")
        if fresh:
            self._record_install(node)
        self._stage_uefi_vars(node)

        if node.kind == LINUX:
            if appliances.console_driven(node.image):
                # The firewall's configuration volume: rewritten at every
                # start; the console agent applies it when its fingerprint
                # changed (and reboots the appliance), else leaves it alone.
                if openwrt.is_openwrt(node):  # an access point or the UPS card (winlab/openwrt.py)
                    openwrt.config_disk(node, self.lab, self.plan, ndir / "config.img")
                else:
                    opnsense.config_disk(node, self.lab, self.plan, ndir / "config.img")
            elif appliances.is_appliance(node.image):
                # The first-boot seed: rewritten at every start, so an address
                # or name change reaches the machine (cloud-init sees a new
                # instance id) while an unchanged one is a no-op in the guest.
                cloudinit.write_seed(node, self.lab, self.plan,
                                     appliances.get_or_raise(node.image), ndir / cloudinit.SEED_FILE)
            else:
                # The Alpine probe boots the fabric's ISO diskless and restores
                # an overlay named after itself (its hostname, the agent).
                from . import roles
                extra = roles.apk_packages(node)
                alpineovl.overlay_disk(ndir / "overlay.img", node.id,
                                       alpineovl.FABRIC_PACKAGES + extra if extra else None)

        for i, size in enumerate(node.data_disks_gb):
            images.create_data_disk(self.provider.data_disk_path(node_id, i), size)

        usb_gb = int(node.vars.get("usb_storage_gb") or 0)
        if usb_gb:
            images.create_data_disk(ndir / "usb0.qcow2", usb_gb)

        if node.is_windows:
            provision.build_answer_floppy(
                node, self.lab, ndir / "answer.img",
                firmware=FIRMWARE_UEFI if self.provider._uses_uefi(node) else FIRMWARE_BIOS,
            )
            provision.build_data_disk(node, self.lab, self.plan, ndir / "payload.img")

    def _record_install(self, node) -> None:
        """Which firmware the machine's new disk is laid out for, kept beside
        it (winlab/firmware.py): a clone's is its base's (GPT when the base
        was installed under UEFI, which left a variable store beside it), a
        blank disk's is the firmware its Setup is about to run under."""
        from . import firmware
        if not firmware.fitted(node):
            return
        if images.is_template(node.image) or node.is_windows:
            family = firmware.UEFI if images.nvram_source(node.image) is not None else firmware.BIOS
        else:
            family = firmware.UEFI if self.provider._uses_uefi(node) else firmware.BIOS
        try:
            (self.provider.node_dir(node.id) / "installed-firmware").write_text(family, encoding="ascii")
        except OSError:
            pass

    def firmware_notes(self, node) -> list[str]:
        """What to say at start about the machine's firmware: why it is not
        what it was set to, and a disk laid out for the other firmware."""
        from . import firmware
        if not firmware.fitted(node):
            return []
        mode, why = self.provider.firmware_mode(node)
        out = [why] if why else []
        clash = firmware.mismatch(self.lab.name, node, mode)
        if clash:
            out.append(f"starts with {firmware.TITLES[mode]}, but {clash}")
        return out

    def _stage_uefi_vars(self, node) -> None:
        """A UEFI machine needs its own writable NVRAM. A clone starts from the
        NVRAM its base was installed with (it holds the Windows Boot Manager
        entry); anything else starts from the firmware's empty template. A
        machine set to Secure Boot gets its keys written in before its first
        start with it (winlab/secureboot.py), and its db follows the template
        it is set to."""
        if not self.provider._uses_uefi(node):
            return
        dest = self.provider.uefi_vars_path(node.id)
        if not dest.exists():
            src = images.nvram_source(node.image)
            if src is None:
                src = paths.uefi_firmware()[1]
            dest.write_bytes(src.read_bytes())
        if not self.provider.secure_boot(node):
            return
        from . import firmware, secureboot
        tpl = firmware.template(node)
        data = dest.read_bytes()
        try:
            store = secureboot.VarStore(data)
            if not secureboot.enrolled(store):
                data = secureboot.enroll(data, tpl)
            elif secureboot.template_of(store) != tpl:
                data = secureboot.set_template(data, tpl)
            else:
                return
        except secureboot.SecureBootError as exc:
            raise OrchestratorError(f"node '{node.id}': Secure Boot keys: {exc}") from exc
        dest.write_bytes(data)

    def reset(self, node_ids: list[str]) -> list[str]:
        """Throw away machines' disks so the next boot rebuilds them from their
        image. Their checkpoints go with them. Machines must be stopped."""
        running = self.running()
        busy = [n for n in node_ids if n in running]
        if busy:
            raise OrchestratorError(
                f"stop {', '.join(busy)} first: a running machine cannot be reset"
            )
        done: list[str] = []
        for node_id in node_ids:
            if node_id not in self.lab.nodes:
                raise OrchestratorError(f"no machine '{node_id}' in lab '{self.lab.name}'")
            ndir = self.provider.node_dir(node_id)
            removed = False
            for pattern in ("system.qcow2", "data*.qcow2", "usb0.qcow2", "uefi-vars*.fd", "installed-firmware"):
                for f in ndir.glob(pattern):
                    f.unlink()
                    removed = True
            if removed:
                done.append(node_id)
        st = state.load(self.lab.name)
        if st:
            for node_id in done:
                ns = st.nodes.get(node_id)
                if ns and ns.phase == SUSPENDED:
                    ns.phase = "stopped"
            state.save(st)
        return done

    def stop_nodes(self, node_ids: list[str]) -> list[str]:
        """Power off some machines and leave the rest of the lab running."""
        st = state.load(self.lab.name)
        if not st:
            return []
        stopped: list[str] = []
        for node_id in node_ids:
            ns = st.nodes.get(node_id)
            if ns and ns.pid and state.pid_alive(ns.pid):
                _kill(ns.pid)
                _wait_gone(ns.pid)
                _kill_helper(ns)
                ns.pid = 0
                ns.phase = "stopped"
                stopped.append(node_id)
        state.save(st)
        if stopped:
            # The memory a stopped machine held is free: let the others have
            # theirs back where the balloon had taken it.
            from . import balloon
            balloon.relax(self.lab, st.running())
        return stopped

    # -------------------------------------------------------------- media
    def _attach_media(self, node_id: str, argv: list[str]) -> list[str]:
        node = self.lab.nodes.get(node_id)
        ndir = self.provider.node_dir(node_id)

        if node_id == "fabric":
            return argv + alpine_media_argv(ndir / "overlay.img", config=ndir / "config.img")

        assert node is not None
        extra: list[str] = []
        if node.kind == LINUX:
            seed = ndir / cloudinit.SEED_FILE
            cfg = ndir / "config.img"
            if appliances.console_driven(node.image):
                if cfg.exists():
                    extra += [
                        "-drive", f"id=cfg,file={cfg},if=none,format=raw,readonly=on",
                        "-device", "virtio-blk-pci,drive=cfg",
                    ]
            elif appliances.is_appliance(node.image):
                if seed.exists():
                    extra += [
                        "-drive", f"id=seed,file={seed},if=none,format=raw,readonly=on",
                        "-device", "virtio-blk-pci,drive=seed",
                    ]
            else:
                extra += alpine_media_argv(ndir / "overlay.img")
            return argv + extra
        helper = ndir / "setup-helper.img"
        if node.kind == CUSTOM and node.image == "win11" and helper.exists():
            extra += ["-drive", f"id=ans,file={helper},if=floppy,format=raw,readonly=on"]
        answer = ndir / "answer.img"
        payload = ndir / "payload.img"
        if node.is_windows and answer.exists():
            extra += [
                "-drive", f"id=ans,file={answer},if=floppy,format=raw",
            ]
        if node.is_windows and payload.exists():
            extra += [
                "-drive", f"id=pl,file={payload},if=none,format=raw",
                "-device", "ich9-ahci,id=ahci2",
                "-device", "ide-hd,bus=ahci2.0,drive=pl",
            ]
        return argv + extra

    # ----------------------------------------------------------------- boot
    def _needs_install_iso(self, node_id: str) -> Path | None:
        node = self.lab.nodes.get(node_id)
        if not node or not node.is_windows:
            return None
        if self.provider.disk_path(node_id).exists():
            return None  # already installed (built here, or imported standalone)
        if images.disk_source(node.image) is not None:
            return None  # prepared base or template; thin clone already installed
        if node.image not in images.CATALOG:
            raise OrchestratorError(
                f"node '{node_id}': its image '{node.image}' is not on this PC (a template "
                f"that was removed?). Give it another image with: winlab node "
                f"{self.lab.name} set {node_id} ... or see: winlab template list"
            )
        iso = images.installer_path(node.image)
        if iso.exists():
            return iso
        raise OrchestratorError(
            f"node '{node_id}': no prepared base and no installer for image "
            f"'{node.image}'. Run: winlab images import {node.image} <path>"
        )

    def _check_attached_iso(self, node_id: str) -> None:
        node = self.lab.nodes.get(node_id)
        iso = str(node.vars.get("iso") or "") if node else ""
        if iso and not self.provider.iso_path(iso).exists():
            raise OrchestratorError(
                f"node '{node_id}': the attached ISO '{iso}' is not in the image store; "
                f"eject it (winlab node {self.lab.name} set {node_id} --iso none) or add it"
            )

    def _media_problem(self, node_id: str) -> str:
        """What this machine still needs on this PC before it can start
        (its base, installer or ISO), or ''. Read-only: it runs for every
        machine before the first one starts, so a lab does not power the
        router on and then stop at the third machine."""
        if node_id == "fabric":
            if images.disk_source("alpine") is None:
                return ("the router and switches need their base (Alpine Linux), which is not on this PC "
                        "yet: open Setup and press Get everything ready (or: winlab images prepare alpine)")
            return ""
        node = self.lab.nodes.get(node_id)
        if node is None or self.provider.disk_path(node_id).exists():
            return ""
        try:
            self._needs_install_iso(node_id)
            self._check_attached_iso(node_id)
        except OrchestratorError as exc:
            return str(exc)
        from . import netos
        ok, why = netos.can_run(node, self.provider.accel)
        if not ok:
            return f"node '{node_id}': {why}"
        if node.is_windows and node.kind != CUSTOM:
            return ""
        if netos.is_disk_router(node):
            return "" if netos.ready(node.image) else f"node '{node_id}': {netos.missing_text(node.image)}"
        if images.is_template(node.image):
            return "" if images.disk_source(node.image) else (
                f"node '{node_id}': its template '{node.image}' has no disk on this PC any more")
        if images.is_hand_install(node):
            if imaging.is_netboot(node):
                return ""
            try:
                images.hand_media(node.image)
            except images.ImageError as exc:
                return f"node '{node_id}': {exc}"
            return ""
        if node.kind == CUSTOM:
            try:
                entry = images.custom_image(node.image)
            except (images.ImageError, KeyError) as exc:
                return f"node '{node_id}': {exc}"
            return "" if entry.iso.exists() else (
                f"node '{node_id}': the ISO for your image '{node.image}' is missing; add it again in "
                f"Setup > Use any ISO (or: winlab images add {node.image} <path>)")
        if node.kind == LINUX and appliances.is_appliance(node.image):
            if appliances.ready(node.image):
                return ""
            app = appliances.get_or_raise(node.image)
            return (f"node '{node_id}': the {app.short} image is not on this PC yet; fetch it in Setup "
                    f"(or: winlab images fetch {node.image})")
        image_id = "alpine" if node.kind == LINUX else node.image
        if images.disk_source(image_id) is None:
            return (f"node '{node_id}': the {image_id} base is not on this PC yet: open Setup and press "
                    f"Get everything ready (or: winlab images prepare {image_id})")
        return ""

    def preflight(self, order: list[str], st) -> None:
        """Every machine about to start has what it needs, or nothing starts."""
        problems = []
        if not paths.qemu_exe().exists():
            problems.append("QEMU is not on this PC yet: open Setup and press Get everything ready "
                            "(or: winlab bootstrap)")
        for node_id in order:
            ns = st.nodes.get(node_id)
            if ns and ns.pid and state.pid_alive(ns.pid):
                continue
            try:
                why = self._media_problem(node_id)
            except Exception:  # noqa: BLE001 - the start itself says it, with its own words
                why = ""
            if why:
                problems.append(why)
        if problems:
            raise OrchestratorError("nothing was started: " + "; ".join(problems))

    @staticmethod
    def _died_at_start(proc: subprocess.Popen, log: Path, wait: float = 1.5, since: int = 0) -> str:
        """'' while QEMU is still running after `wait` seconds; else why it
        stopped: the error lines it wrote last (a corrupt disk, a port taken,
        a setting this QEMU does not have)."""
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        if proc.poll() is None:
            return ""
        return exit_reason(log, since=since) or f"QEMU stopped at once (exit code {proc.returncode})"

    def _launch(self, node_id: str, argv: list[str]) -> subprocess.Popen:
        log = self.provider.node_dir(node_id) / "qemu.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        fh = log.open("ab")
        flags = 0
        if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            flags = subprocess.CREATE_NEW_PROCESS_GROUP
        # A machine with a TPM fitted: its chip (swtpm) is up before QEMU connects.
        from . import bitlocker
        try:
            bitlocker.start_tpm(self.provider.node_dir(node_id), argv)
        except bitlocker.BitLockerError as exc:
            raise OrchestratorError(f"node '{node_id}': {exc}") from exc
        return subprocess.Popen(argv, stdout=fh, stderr=fh, stdin=subprocess.DEVNULL,
                                creationflags=flags)

    def up(self, only: list[str] | None = None, emit=_noop) -> BootReport:
        """Start the lab (or `only` those machines). One start of a lab runs at
        a time: a second one (another Power on click, `winlab lab up` while
        the desktop starts it) waits, then starts only what is still off."""
        try:
            with state.start_lock(self.lab.name, on_wait=lambda: emit(
                    "waiting for the start already under way to finish")):
                return self._up(only, emit)
        except state.Busy as exc:
            raise OrchestratorError(str(exc)) from exc

    def _up(self, only: list[str] | None = None, emit=_noop) -> BootReport:
        self.workdir.mkdir(parents=True, exist_ok=True)
        st = state.load(self.lab.name) or state.new(
            self.lab.name, self.accel, self.display, self.lab.source_path
        )
        st.accel, st.display = self.accel, self.display

        if not _fabric_running(self.lab.name):
            # The router and its switches power on with what their NVRAM
            # holds: what was typed and never written is gone (winlab/iosnv.py).
            from . import iosnv
            try:
                changed = iosnv.power_on(self.lab)
            except Exception as exc:  # noqa: BLE001 - a bad NVRAM file never stops a lab starting
                emit(f"router and switch configuration kept as it is: {exc}")
                changed = False
            if changed:
                from . import editor
                editor.save(self.lab)
                self.plan = compile_topology(self.lab, check_ports=True)
                self.provider = QemuProvider(self.plan, accel=self.accel, display=self.display)
                emit("router and switches started with their startup configuration")
        if _fabric_running(self.lab.name):
            # Machines joining a running network: the router grows the ports
            # it does not have yet, then the plan is made again around them.
            from . import livenet
            try:
                livenet.sync(self.lab, emit)
            except livenet.LiveNetError as exc:
                raise OrchestratorError(str(exc)) from exc
            self.plan = compile_topology(self.lab, check_ports=False)
            self.provider = QemuProvider(self.plan, accel=self.accel, display=self.display)

        # A paused lab clock runs again when machines start: they power on at
        # the time it was paused at (winlab/labclock.py).
        from . import labclock
        if labclock.wake(self.lab.name):
            emit("lab clock resumed")
        if not _fabric_running(self.lab.name) and any(
                n != "fabric" and ns.pid and state.pid_alive(ns.pid) for n, ns in st.nodes.items()):
            # The router stopped (or crashed) under running machines: it comes
            # back on the ports they keep dialling (winlab/providers/qemu.py).
            from . import livenet
            livenet.keep_ports(self.plan, livenet.last_ports(self.lab.name))
        runtimes = self.provider.build_all()
        order = ["fabric"] + [n.id for n in self.lab.node_list()]
        if only:
            order = [n for n in order if n in only or n == "fabric"]

        self.preflight(order, st)

        started: list[str] = []
        skipped: list[str] = []
        resumed: list[str] = []
        failed: dict[str, str] = {}
        # A head office lost in a disaster drill has no building to start in
        # (winlab/drsite.py): its machines stay off until it is rebuilt.
        from . import drsite
        gone = drsite.lost_nodes(self.lab)

        for idx, node_id in enumerate(order):
            if node_id in gone:
                emit(f"{node_id}: lost with the head office; it does not start until the site is rebuilt "
                     f"(winlab dr {self.lab.name} rebuild)")
                continue
            existing = st.nodes.get(node_id)
            if existing and existing.pid and state.pid_alive(existing.pid):
                skipped.append(node_id)
                continue
            if existing and existing.phase == SUSPENDED:
                resumed.append(node_id)

            # The power button: a PC with no power supply, no processor or no
            # memory it can use does not start at all (winlab/pcbuild.py).
            post = None
            hwnode = self.lab.nodes.get(node_id)
            if hwnode is not None and node_id not in resumed:
                from . import pcbuild
                if pcbuild.form_of(hwnode):
                    post = pcbuild.post(self.lab.name, hwnode)
                    if post["halt"]:
                        pcbuild.record(self.lab.name, node_id, post)
                        emit(f"{node_id}: {pcbuild.verdict(post)}")
                        continue

            self._stage_disks(node_id)
            if node_id in self.lab.nodes:
                for line in self.firmware_notes(self.lab.nodes[node_id]):
                    emit(f"{node_id}: {line}")
            rt = runtimes[node_id]
            argv = self._attach_media(node_id, list(rt.argv))

            iso = self._needs_install_iso(node_id)
            if iso:
                slot = self.provider.next_ahci_slot(argv)
                argv += [
                    "-drive", f"id=inst,file={iso},if=none,media=cdrom,readonly=on",
                    "-device", f"ide-cd,bus=ahci.{slot},drive=inst,bootindex=1",
                ]
            self._check_attached_iso(node_id)

            # Saved (Hyper-V's Save): read the memory back and carry on. A
            # file left from a machine that has been off since is stale.
            saved = self.provider.node_dir(node_id) / SAVED_STATE
            restoring = saved.exists() and node_id in resumed and not iso
            if saved.exists() and not restoring:
                saved.unlink(missing_ok=True)
            qlog = self.provider.node_dir(node_id) / "qemu.log"
            log_at = qlog.stat().st_size if qlog.exists() else 0
            if restoring and "-S" in argv:
                argv.remove("-S")   # woken from a save: no POST to wait at
            proc = self._launch(node_id, argv + (["-incoming", f"file:{saved}"] if restoring else []))
            if restoring:
                if _wait_restored(rt.qmp_port, proc):
                    emit(f"{node_id}: back where it was saved")
                else:
                    emit(f"{node_id}: its saved state could not be read back (its settings "
                         f"changed?); starting it fresh, as after a power cut")
                    proc = self._launch(node_id, argv)
                saved.unlink(missing_ok=True)
            if post is not None:
                from . import pcbuild
                pcbuild.record(self.lab.name, node_id, post, pid=proc.pid)
                if post.get("errors"):
                    emit(f"{node_id}: POST: {post['errors'][0]}")
                if post.get("heat"):
                    # No cooler, a dead fan: it switches itself off after a while.
                    pcbuild.arm_thermal(self.lab.name, node_id, proc.pid, rt.qmp_port, post["heat"])
            agent_port, helper_pid, console_port = rt.serial_port, 0, 0
            node = self.lab.nodes.get(node_id)
            if node is not None and appliances.console_driven(node.image):
                # No agent inside the appliance: a console agent on this PC
                # logs in over the serial console and answers on its own
                # port in the agents' protocol, so the rest of winlab is none
                # the wiser (winlab/consoleagent.py).
                helper_pid, agent_port = self._launch_console_agent(node_id, rt.serial_port)
                console_port = rt.serial_port
            st.nodes[node_id] = state.NodeState(
                node_id=node_id,
                pid=proc.pid,
                qmp_port=rt.qmp_port,
                serial_port=agent_port,
                vnc_port=rt.vnc_port,
                disk=str(rt.disk or ""),
                phase="installing" if iso else "booting",
                helper_pid=helper_pid,
                console_port=console_port,
                term_port=rt.term_port,
                com_port=rt.com_port,
                wterm_port=rt.wterm_port,
            )
            state.save(st)
            if node_id != "fabric":
                # A machine whose QEMU stops at once (a damaged disk, a port
                # taken, a setting this QEMU lacks) is not "started": say why.
                why = self._died_at_start(proc, qlog, since=log_at)
                if why:
                    _kill_helper(st.nodes[node_id])
                    st.nodes[node_id].pid = 0
                    st.nodes[node_id].phase = "stopped"
                    state.save(st)
                    failed[node_id] = why
                    emit(f"{node_id} did not start: {why}")
                    continue
            started.append(node_id)
            emit(f"{'resumed' if node_id in resumed else 'started'} {node_id}"
                 + (" (installing)" if iso else ""))

            if node_id == "fabric":
                # The machines dial into the router's switch ports: wait until
                # they are open, rather than guess how long that takes.
                from . import livenet
                livenet.record(self.plan, proc.pid)
                self._fabric_listening(rt.qmp_port, proc, emit)
                continue
            from . import devcli
            if any(not l.plugged or devcli.held_down(self.lab, l) for l in self.plan.ports_for(node_id)):
                from . import livenet
                livenet.apply_node_links(self.lab, self.plan, node_id, rt.qmp_port)
            later = [n for n in order[idx + 1:]
                     if not (st.nodes.get(n) and st.nodes[n].pid
                             and state.pid_alive(st.nodes[n].pid))]
            if later and not iso:
                self._pace(node_id, agent_port, later, emit)

        return BootReport(self.lab.name, started, skipped, self.accel, self.display, resumed, failed)

    def _launch_console_agent(self, node_id: str, console_port: int) -> tuple[int, int]:
        """Starts the console agent for an appliance winlab drives over its
        serial console. Returns (pid, the port it answers on)."""
        from .providers.qemu import MGMT_BASE, _free_port
        node = self.lab.nodes[node_id]
        ndir = self.provider.node_dir(node_id)
        taken = {console_port}
        st = state.load(self.lab.name)
        for other in (st.nodes.values() if st else []):
            taken.update(x for x in (other.qmp_port, other.serial_port, other.vnc_port, other.console_port,
                                     other.term_port, other.com_port,
                                     other.wterm_port) if x)
        listen = _free_port(MGMT_BASE, taken)
        if openwrt.is_openwrt(node):
            fp, user, flavor = openwrt.fingerprint(node, self.lab, self.plan), openwrt.CONSOLE_USER, "openwrt"
        else:
            fp = opnsense.fingerprint(opnsense.render_config(node, self.lab, self.plan))
            user, flavor = opnsense.CONSOLE_USER, "opnsense"
        pw_file = secrets.password_path(self.lab.name)
        if not pw_file.exists():
            secrets.lab_admin_password(self.lab.name)
        argv = [sys.executable] + ([] if paths.FROZEN else ["-m", "winlab"]) + [
            "console-agent", "--listen", str(listen), "--console", str(console_port),
            "--password-file", str(pw_file), "--host", node_id, "--user", user,
            "--fingerprint", fp, "--log", str(ndir / "console.log"), "--flavor", flavor,
        ]
        flags = 0
        if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            flags = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL, creationflags=flags)
        return proc.pid, listen

    def _pace(self, node_id: str, serial_port: int, later: list[str], emit) -> None:
        """Hold the machines after this one in boot order, as the lab asks."""
        node = self.lab.nodes[node_id]
        if node.wait_ready:
            emit(f"waiting for {node_id} to be ready before {', '.join(later)} start "
                 f"(up to {READY_TIMEOUT / 60:.0f} min)…")
            t0 = time.monotonic()
            if _wait_agent(serial_port, READY_TIMEOUT):
                emit(f"{node_id} is ready after {_mmss(time.monotonic() - t0)}")
            else:
                emit(f"{node_id} did not answer within {READY_TIMEOUT / 60:.0f} min; "
                     f"starting the rest anyway")
        if node.start_delay:
            emit(f"pausing {node.start_delay} s after {node_id}…")
            _sleep(node.start_delay)

    def running(self) -> set[str]:
        st = state.load(self.lab.name)
        if not st:
            return set()
        return {n for n, ns in st.nodes.items() if ns.pid and state.pid_alive(ns.pid)}

    # ------------------------------------------------------- the router alone
    def _fabric_listening(self, qmp_port: int, proc, emit) -> None:
        """After the router starts: its switch ports are open, or a clear
        error (a router that will not start is no network at all)."""
        from .providers.qemu import fabric_netdev_id, redials
        why = _wait_fabric(qmp_port, proc, [fabric_netdev_id(l) for l in self.plan.ports])
        if not why:
            return
        log = self.provider.node_dir("fabric") / "qemu.log"
        tail = _log_tail(log)
        msg = (f"the lab's router did not come up: {why}" + (f" ({tail})" if tail else "")
               + f"; its QEMU log is {log}")
        if proc is not None and proc.poll() is None and redials():
            # The machines' cards redial: they connect whenever it is ready.
            emit(msg + "; the machines start anyway and plug in when it is ready")
            return
        raise OrchestratorError(msg)

    def restart_fabric(self, emit=_noop) -> dict:
        """Restarts the lab's router and its switches (one machine, the
        fabric) while the lab's machines keep running, as when the switch
        rack is power-cycled or the router reloads: every machine's link goes
        down, the router boots with its startup configuration, and the links
        come back by themselves. Also what brings a crashed router back.
        Returns {"machines": [...], "relinked": n, "redial": bool}."""
        from . import devcli, iosnv, livenet
        from .providers.qemu import redials
        st = state.load(self.lab.name)
        if st is None:
            raise OrchestratorError(f"{self.lab.name} is not running")
        machines = sorted(n for n, ns in st.nodes.items()
                          if n != "fabric" and ns.pid and state.pid_alive(ns.pid))
        if not machines and not _fabric_running(self.lab.name):
            raise OrchestratorError(f"{self.lab.name} is not running; `winlab lab up` starts it")
        # The machines keep dialling the ports they were started with.
        keep = livenet.last_ports(self.lab.name)
        old = livenet.pinned_ports(self.lab.name)
        fab = st.nodes.get("fabric")
        if fab and fab.pid and state.pid_alive(fab.pid):
            # The switch goes dark: every machine's link light goes out.
            for nid in machines:
                for link in self.plan.ports_for(nid):
                    if old.get(link.label, {}).get("plugged", link.plugged):
                        livenet.set_link(st.nodes[nid].qmp_port, link.nic_index, False, tries=2)
            emit("router and switches going down; the machines' links are down")
            _kill(fab.pid)
            _wait_gone(fab.pid)
            fab.pid, fab.phase = 0, "stopped"
            state.save(st)
        # It starts with what its NVRAM holds, as on any power-up (winlab/iosnv.py).
        try:
            if iosnv.power_on(self.lab):
                from . import editor
                editor.save(self.lab)
                emit("router and switches start with their startup configuration")
        except Exception as exc:  # noqa: BLE001 - a bad NVRAM file never stops the router starting
            emit(f"router and switch configuration kept as it is: {exc}")
        self.plan = compile_topology(self.lab, check_ports=False)
        livenet.keep_ports(self.plan, keep)
        self.provider = QemuProvider(self.plan, accel=self.accel, display=self.display)
        rt = self.provider.build_fabric()
        self._stage_disks("fabric")
        proc = self._launch("fabric", self._attach_media("fabric", list(rt.argv)))
        st = state.load(self.lab.name) or st
        st.nodes["fabric"] = state.NodeState(
            node_id="fabric", pid=proc.pid, qmp_port=rt.qmp_port, serial_port=rt.serial_port,
            vnc_port=rt.vnc_port, disk=str(rt.disk or ""), phase="booting", com_port=rt.com_port)
        state.save(st)
        livenet.record(self.plan, proc.pid)
        self._fabric_listening(rt.qmp_port, proc, emit)
        emit("router started; waiting for it to finish booting…")
        if not _wait_router_ready(rt.serial_port, FABRIC_BOOT_TIMEOUT):
            emit(f"the router did not say it was ready within {FABRIC_BOOT_TIMEOUT / 60:.0f} min; "
                 f"plugging the machines back in anyway")
        # The cables come back as they were: a port shut down, an empty
        # port or a switch that is off keeps its machine's link down.
        relinked = 0
        for nid in machines:
            ns = st.nodes.get(nid)
            for link in self.plan.ports_for(nid):
                up = link.plugged and not devcli.held_down(self.lab, link)
                if livenet.set_link(ns.qmp_port, link.nic_index, up, tries=3) and up:
                    relinked += 1
        redial = redials()
        if machines and not redial:
            emit("this PC's QEMU cannot redial a cable (QEMU 8.0 or later can): restart the machines "
                 "to plug them back into the router")
        elif machines:
            emit(f"{relinked} machine link{'s' if relinked != 1 else ''} back up")
        return {"machines": machines, "relinked": relinked, "redial": redial}

    def budget(self, only: list[str] | None = None,
               avail_mb: int | None = None) -> membudget.Budget:
        """What starting these machines (all of them when `only` is empty)
        would cost the host, trimmed to fit where their floors allow."""
        from .hostprobe import available_ram_mb

        wanted = list(only) if only else [n.id for n in self.lab.node_list()]
        ids, added = membudget.with_dependencies(self.lab, wanted)
        running = self.running()
        start = [n for n in ids if n not in running]
        fabric_mb = 0 if "fabric" in running else self.plan.fabric_memory_mb
        avail = available_ram_mb() if avail_mb is None else avail_mb
        b = membudget.plan(self.lab, start, fabric_mb, avail)
        b.nodes, b.added = ids, [n for n in added if n not in running]
        return b

    def budgeted_up(self, only: list[str] | None = None, force: bool = False,
                    avail_mb: int | None = None, emit=_noop) -> tuple[BootReport, membudget.Budget]:
        """`up`, but only after checking the host has the memory for it. When
        it is short, the machines already running are asked for memory first
        (the balloon; see balloon.py for where that can work)."""
        b = self.checked_budget(only, force, avail_mb)
        membudget.apply(self.lab, b)
        return self.up(only=b.nodes, emit=emit), b

    def checked_budget(self, only: list[str] | None = None, force: bool = False,
                       avail_mb: int | None = None) -> membudget.Budget:
        """The budget for starting these machines, after asking the running
        ones for memory when the host is short. Raises when it still does not
        fit, unless forced. The desktop answers from this before it starts the
        boot as a job."""
        from . import balloon

        b = self.budget(only, avail_mb)
        if not b.fits and not force and avail_mb is None:
            deficit = b.need_mb + membudget.HOST_MARGIN_MB - b.avail_mb
            freed, notes = balloon.reclaim(self.lab, self.running_states(), deficit)
            if freed:
                b = self.budget(only, None)
            b.notes = notes
        if not b.fits and not force:
            raise OrchestratorError("\n".join(membudget.explain(self.lab, b)))
        return b

    # -------------------------------------------------------------- suspend
    def suspend(self, only: list[str] | None = None, emit=_noop,
                timeout: float = SUSPEND_TIMEOUT) -> SuspendReport:
        """Hibernate Windows machines, shut the others down cleanly, and keep
        the lab's state so the next `up` reports a resume."""
        from . import labclock
        labclock.wake(self.lab.name)  # a machine held by a paused clock cannot hibernate
        st = state.load(self.lab.name)
        rep = SuspendReport(self.lab.name)
        if not st:
            raise OrchestratorError(f"lab '{self.lab.name}' is not running")
        ids = [n.id for n in self.lab.node_list()]
        wanted = [n for n in (only or ids) if n != "fabric"]
        unknown = [n for n in wanted if n not in self.lab.nodes]
        if unknown:
            raise OrchestratorError(f"no machine {', '.join(unknown)} in lab '{self.lab.name}'")
        running = st.running()
        targets = [n for n in wanted if n in running]
        rep.skipped = [n for n in wanted if n not in running]
        installing = [n for n in targets if st.nodes[n].phase == "installing"]
        if installing:
            raise OrchestratorError(
                f"{', '.join(installing)} still installing: let it finish, or stop it"
            )
        if not targets:
            raise OrchestratorError(
                f"nothing to suspend: {', '.join(wanted) or 'the lab'} is not running"
            )

        hib: list[str] = []
        acpi: list[str] = []
        saved: list[str] = []
        for node_id in targets:
            node, ns = self.lab.nodes[node_id], st.nodes[node_id]
            if self.accel != "whpx":
                emit(f"{node_id}: saving its memory and state…")
                err = _save_state(ns.qmp_port, self.provider.node_dir(node_id) / SAVED_STATE)
                if not err:
                    saved.append(node_id)
                    continue
                emit(f"{node_id}: its memory cannot be saved here ({err}); "
                     + ("hibernating instead" if node.is_windows else "shutting it down instead"))
            if node.is_windows:
                emit(f"{node_id}: hibernating…")
                err = _hibernate(ns.serial_port)
                (hib.append(node_id) if not err else rep.failed.__setitem__(node_id, err))
            else:
                emit(f"{node_id}: shutting down (no agent, so nothing to hibernate)…")
                err = _acpi_powerdown(ns.qmp_port)
                (acpi.append(node_id) if not err else rep.failed.__setitem__(node_id, err))
            if err:
                emit(f"{node_id}: {err}")

        pending = saved + hib + acpi
        deadline = time.monotonic() + timeout
        while pending and time.monotonic() < deadline:
            _sleep(1.0)
            pending = [n for n in pending if state.pid_alive(st.nodes[n].pid)]
        for node_id in saved + hib + acpi:
            ns = st.nodes[node_id]
            if state.pid_alive(ns.pid):
                emit(f"{node_id}: did not finish within {_mmss(timeout)}; powering it off")
                _kill(ns.pid)
                _wait_gone(ns.pid)
                rep.powered_off.append(node_id)
                ns.phase = "stopped"
            else:
                ns.phase = SUSPENDED if node_id in hib or node_id in saved else "stopped"
                (rep.saved if node_id in saved else rep.hibernated if node_id in hib
                 else rep.shut_down).append(node_id)
            _kill_helper(ns)
            ns.pid = 0

        whole_lab = set(wanted) >= set(ids)
        others = [n for n, x in st.nodes.items()
                  if n != "fabric" and x.pid and state.pid_alive(x.pid)]
        fab = st.nodes.get("fabric")
        if whole_lab and not others and fab and fab.pid and state.pid_alive(fab.pid):
            _kill(fab.pid)
            _wait_gone(fab.pid)
            fab.pid, fab.phase = 0, "stopped"
        state.save(st)
        return rep

    def running_states(self) -> dict:
        st = state.load(self.lab.name)
        return st.running() if st else {}

    def down(self, keep_state: bool = False) -> list[str]:
        st = state.load(self.lab.name)
        if not st:
            return []
        stopped: list[str] = []
        # Nodes first, fabric last, so links tear down cleanly.
        order = [n.id for n in self.lab.node_list()][::-1] + ["fabric"]
        for node_id in order:
            ns = st.nodes.get(node_id)
            if ns and ns.pid and state.pid_alive(ns.pid):
                _kill(ns.pid)
                _kill_helper(ns)
                ns.pid = 0
                ns.phase = "stopped"
                stopped.append(node_id)
        # A suspended machine resumes at its next start whatever happens to the
        # state file; keep the file so the desktop keeps saying so.
        if keep_state or st.suspended():
            state.save(st)
        else:
            state.clear(self.lab.name)
        from . import livenet
        livenet.forget(self.lab.name)
        return stopped


def _kill_helper(ns: "state.NodeState") -> None:
    """The console agent that served an appliance stops with the machine."""
    if ns.helper_pid and state.pid_alive(ns.helper_pid):
        _kill(ns.helper_pid)
    ns.helper_pid = 0


def _kill(pid: int) -> None:
    try:
        if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=30)
        else:
            import os
            import signal

            os.kill(pid, signal.SIGTERM)
    except (OSError, subprocess.SubprocessError):
        pass


def alpine_media_argv(overlay: Path | None, repo: Path | None = None,
                      config: Path | None = None) -> list[str]:
    """QEMU arguments for a machine that boots the Alpine ISO diskless (the
    fabric, the probe, the Alpine gateway): the ISO as the boot CD, the
    machine's overlay volume, the repository volume with the packages
    (bases/alpine-repo.img unless another is named; left out when it was
    never built) and, for the fabric, its config disk. The volumes are
    virtio-blk drives Alpine's init mounts and scans; all but the config
    disk read-only, since several machines share the repository image."""
    from . import apkrepo

    out: list[str] = []
    iso = images.installer_path("alpine")
    if iso.exists():
        out += ["-cdrom", str(iso), "-boot", "order=d"]
    if overlay and overlay.exists():
        out += [
            "-drive", f"id=ovl,file={overlay},if=none,format=raw,readonly=on",
            "-device", "virtio-blk-pci,drive=ovl",
        ]
    repo = repo or apkrepo.image_path()
    if repo.exists():
        out += [
            "-drive", f"id=apk,file={repo},if=none,format=raw,readonly=on",
            "-device", "virtio-blk-pci,drive=apk",
        ]
    if config and config.exists():
        out += [
            "-drive", f"id=cfg,file={config},if=none,format=raw",
            "-device", "virtio-blk-pci,drive=cfg",
        ]
    return out


def _fabric_running(lab_name: str) -> bool:
    st = state.load(lab_name)
    ns = st.nodes.get("fabric") if st else None
    return bool(ns and ns.pid and state.pid_alive(ns.pid))


def _wait_gone(pid: int, timeout: float = 20.0) -> None:
    """QEMU holds its disk images locked until the process has exited."""
    deadline = time.monotonic() + timeout
    while state.pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.2)


def open_lab(target: str, accel: str, display: str = "window") -> Orchestrator:
    lab = load_lab(target)
    return Orchestrator(lab, accel=accel, display=display)
