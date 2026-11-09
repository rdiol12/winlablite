"""Portable QEMU provider: TopologyPlan -> QEMU command lines and processes.

Device choices favour booting without a driver-injection pipeline:
Windows nodes get e1000e NICs and an AHCI disk, both of which Windows has
in-box drivers for. Linux nodes get virtio.

Each node also gets two loopback management channels, QMP and a serial port.
These are host-side control channels equivalent to a KVM/iLO, not network
interfaces: the guest's IP stack still reaches nothing but the fabric.
"""

from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .. import bitlocker, disks, hardware, mediashelf, paths, sysdisk
from ..images import is_template
from ..appliances import console_driven
from ..model import CUSTOM, LINUX, Node
from .. import imaging
from ..netplan import TopologyPlan

MGMT_BASE = 31000
# Every machine's screen is also served over VNC on loopback (display number
# N is port 5900+N) so the dashboard can show it in the browser; the GTK
# window stays the desktop view. The fabric is headless.
VNC_BASE = 5900

DISPLAY_WINDOW = "window"
DISPLAY_NONE = "none"


def _free_port(start: int, taken: set[int]) -> int:
    port = start
    while port < start + 3000:
        if port not in taken:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", port))
                except OSError:
                    port += 1
                    continue
            taken.add(port)
            return port
        port += 1
    raise RuntimeError("no free management port")


# ----------------------------------------------------------------- isolation
# The lab must never have a path to the host PC or the internet. Every
# machine is wired only to the fabric over loopback socket links; the only
# host-side channels are the serial agent, QMP and the VNC display, all
# bound to 127.0.0.1 and all initiated by winlab. These checks run on every
# command line before QEMU starts, so a future lab option cannot quietly
# add a user-mode NIC, a tap, a shared folder or a public listener.
_FORBIDDEN_FLAGS = {
    "-nic", "-net", "-virtfs", "-fsdev", "-spice", "-smb", "-redir", "-tftp", "-bootp",
    "-netdev-user",
}
_FORBIDDEN_NETDEV = ("user", "tap", "bridge", "vde", "hubport", "l2tpv3", "vhost-user",
                     "vhost-vdpa", "stream", "dgram", "af-xdp")
_FORBIDDEN_DEVICE = ("virtio-9p", "vhost-user-fs", "virtserialport", "virtio-serial",
                     "usb-host", "pci-assign", "vfio-pci", "e1000-passthrough")
_LOOPBACK_FLAGS = ("-vnc", "-qmp", "-monitor")


# Free slots on the lab router for ports added while it runs.
HOTPLUG_SLOTS = 16
# Where the router's cards sit on its PCI bus (q35: slots 0x01-0x1e are
# free; 0x1f is the chipset). Its management port (eth0) first, then the
# switch ports from LINK_SLOT0, eight to a slot; the spare slots for live
# ports after them; the way out (a virtual switch's uplink) last. The other
# devices take the low slots by themselves.
MGMT_SLOT = 0x07
LINK_SLOT0 = 0x08
LINK_SLOTS = 16
HOTPLUG_SLOT0 = LINK_SLOT0 + LINK_SLOTS
UPLINK_SLOT = HOTPLUG_SLOT0 + (HOTPLUG_SLOTS + 7) // 8


def _pci_addr(slot: int, fn: int) -> str:
    return f"addr=0x{slot:02x}.{fn}" + (",multifunction=on" if fn == 0 else "")


def fabric_netdev_id(link) -> str:
    """The router's end of a machine's cable."""
    return f"p{link.nic_index}_{link.node_id}"


# ------------------------------------------------------------------ cables
# Each machine's network card is cabled to the router's switch over one
# loopback TCP connection, the router's end listening and the machine's end
# dialling in. QEMU 8.0 and later can redial a dropped connection on its own
# (-netdev stream with reconnect), which is what a PC does when the switch
# it is plugged into reboots: the link comes back by itself. Older QEMU only
# has -netdev socket, which never redials; those labs keep working, and a
# router restarted under them needs the machines restarted too. The option
# is `reconnect` (seconds) from QEMU 8.0 and `reconnect-ms` from 9.2;
# `reconnect` is gone in 10.2 (QEMU's docs/about/removed-features).
LINK_STREAM_MS = "stream-ms"   # QEMU 9.2 and later
LINK_STREAM = "stream"         # QEMU 8.0 - 9.1
LINK_SOCKET = "socket"         # older, or a QEMU that does not say its version
RECONNECT_MS = 1000            # how soon a machine redials its switch port

link_override: str | None = None   # tests set the style here
_link_ver: tuple[int, int] | None = None


def qemu_link_version() -> tuple[int, int]:
    """The (major, minor) of the QEMU winlab runs; (0, 0) when it cannot tell."""
    global _link_ver
    if _link_ver is None:
        _link_ver = (0, 0)
        try:
            res = subprocess.run([str(paths.qemu_exe()), "-version"], capture_output=True, timeout=20)
            m = re.search(rb"version (\d+)\.(\d+)", res.stdout or b"")
            if m:
                _link_ver = (int(m.group(1)), int(m.group(2)))
        except (OSError, subprocess.SubprocessError):
            pass
    return _link_ver


def link_style(ver: tuple[int, int] | None = None) -> str:
    """Which kind of cable this QEMU can make (see above)."""
    if ver is None and link_override:
        return link_override
    ver = qemu_link_version() if ver is None else ver
    if ver >= (9, 2):
        return LINK_STREAM_MS
    if ver >= (8, 0):
        return LINK_STREAM
    return LINK_SOCKET


def redials(style: str | None = None) -> bool:
    """Whether the machines' cables come back by themselves after the
    router restarts."""
    return (style or link_style()) != LINK_SOCKET


def link_netdev(nid: str, port: int, listen: bool, style: str | None = None) -> str:
    """The -netdev for one end of a cable: the router's switch port
    (`listen`) or the machine's card, which redials where QEMU can."""
    style = style or link_style()
    if style == LINK_SOCKET:
        return f"socket,id={nid},{'listen' if listen else 'connect'}=127.0.0.1:{port}"
    out = (f"stream,id={nid},server={'on' if listen else 'off'},"
           f"addr.type=inet,addr.host=127.0.0.1,addr.port={port}")
    if not listen:
        out += (f",reconnect-ms={RECONNECT_MS}" if style == LINK_STREAM_MS
                else f",reconnect={max(1, RECONNECT_MS // 1000)}")
    return out


def link_qmp_args(nid: str, port: int, style: str | None = None) -> dict:
    """netdev_add's arguments for a switch port added to the running
    router (winlab/livenet.py): the same kind of cable as the others."""
    style = style or link_style()
    if style == LINK_SOCKET:
        return dict(type="socket", id=nid, listen=f"127.0.0.1:{port}")
    return dict(type="stream", id=nid, server=True,
                addr={"type": "inet", "host": "127.0.0.1", "port": str(port)})


# Exactly the cables link_netdev makes and nothing else: loopback only, and
# no option QEMU would read as another address, a file or a forward.
_LINK_RE = re.compile(
    r"socket,id=[\w.-]+,(?:listen|connect)=127\.0\.0\.1:\d{1,5}"
    r"|stream,id=[\w.-]+,server=on,addr\.type=inet,addr\.host=127\.0\.0\.1,addr\.port=\d{1,5}"
    r"|stream,id=[\w.-]+,server=off,addr\.type=inet,addr\.host=127\.0\.0\.1,addr\.port=\d{1,5}"
    r"(?:,reconnect=\d{1,4}|,reconnect-ms=\d{1,7})?")


def link_ok(val: str) -> bool:
    """The isolation guard's test for a cable: one link_netdev makes."""
    return bool(_LINK_RE.fullmatch(val))


def check_isolation(argv: list[str], uplink: bool = False) -> list[str]:
    """Returns every way this QEMU command line would reach outside the lab
    (empty means isolated). `uplink` is the lab router of a lab with an
    internal or external virtual switch (winlab/vswitch.py): it may carry
    exactly that one user-mode card, with no share or boot server and
    forwards from 127.0.0.1 only."""
    from ..vswitch import netdev_ok
    bad: list[str] = []
    uplinks = 0
    it = iter(range(len(argv)))
    for i in it:
        flag = argv[i]
        val = argv[i + 1] if i + 1 < len(argv) else ""
        if flag in _FORBIDDEN_FLAGS:
            bad.append(f"{flag} {val}".strip())
        elif flag == "-netdev":
            kind = val.split(",", 1)[0]
            if uplink and netdev_ok(val) and not uplinks:
                uplinks += 1
            elif link_ok(val):
                pass
            elif kind in ("socket", "stream"):
                bad.append(f"-netdev {val}: socket link not on 127.0.0.1")
            elif kind in _FORBIDDEN_NETDEV:
                bad.append(f"-netdev {val}: host-connected network backend")
            else:
                bad.append(f"-netdev {val}: only loopback socket links are allowed")
        elif flag == "-device":
            kind = val.split(",", 1)[0]
            if any(kind.startswith(k) for k in _FORBIDDEN_DEVICE):
                bad.append(f"-device {val}: host-sharing or passthrough device")
        elif flag == "-chardev":
            kind = val.split(",", 1)[0]
            if kind == "socket" and ("host=127.0.0.1" not in val and "path=" not in val):
                bad.append(f"-chardev {val}: socket not on 127.0.0.1")
            elif kind in ("udp", "tcp", "parallel", "serial", "pipe", "spicevmc", "spiceport"):
                bad.append(f"-chardev {val}: host device or network channel")
        elif flag == "-drive":
            if "file=fat:" in val or "file=http" in val or "file=nbd" in val or "file=ssh" in val \
                    or "file=iscsi" in val or "file=nfs" in val:
                bad.append(f"-drive {val}: host directory or network disk")
        elif flag == "-incoming":
            # A saved state comes back from its file in the lab; never over a socket.
            if not (val.startswith("file:") or val == "defer"):
                bad.append(f"-incoming {val}: a saved state is read from a file only")
        elif flag in _LOOPBACK_FLAGS:
            if "127.0.0.1" not in val and not val.startswith("none") and not val.startswith("stdio"):
                bad.append(f"{flag} {val}: not bound to 127.0.0.1")
    return bad


SAN_BAY = "SANBAY"  # a storage array's drives report their bay as their serial (content/roles/san.sh)


def uses_virtio(node: Node) -> bool:
    """Whether the machine gets Red Hat's paravirtual devices (see
    QemuProvider._virtio)."""
    if node.kind == LINUX:
        return True
    from ..linuxiso import is_hand_linux
    if is_hand_linux(node):
        return node.wants_virtio
    from .. import netos
    if netos.is_router(node):
        return netos.uses_virtio(node)  # the disk and cards the vendor's OS documents (winlab/netos.py)  # a regular PC unless asked; the installer's kernel drives virtio
    if not node.is_windows or not node.wants_virtio:
        return False
    from ..images import base_virtio
    return base_virtio(node.image)


def hardware_of(node: Node) -> str:
    """'virtio' or 'pc', as the machine will really be built: a machine that
    asks for virtio but whose base has no drivers stays a pc."""
    return "virtio" if uses_virtio(node) else "pc"


# The Hyper-V enlightenments a Windows guest on KVM is given, the set
# libvirt and Proxmox use for Windows 10+/Server 2016+: a reference clock and
# synthetic timers in place of the emulated HPET/PIT ticks, paravirtual
# EOI, TLB flush and IPIs, and a spin-lock hint. Without them an idle Windows
# machine keeps a host core noticeably busy servicing timer exits. Linux
# guests have kvm-clock and need none of this.
HV_KVM = ("hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,hv-runtime,hv-time,"
          "hv-synic,hv-stimer,hv-frequencies,hv-tlbflush,hv-ipi")


def cpu_model(accel: str, windows: bool = False) -> str:
    # WHPX (Windows' Hyper-V platform) crashes with `-cpu host` on some
    # hosts -- passing through the physical CPU's xsave/AVX state produces
    # "failed to get xsave state" + "Unexpected VP exit code 4" and freezes
    # the guest. A named model exposes a stable, complete-enough feature set
    # (POPCNT/SSE4.2/AES that Server 2025 and Win11 require) without the
    # passthrough that trips WHPX. KVM and TCG are unaffected.
    if accel == "tcg":
        return "max"
    if accel == "whpx":
        return "Skylake-Client-v4,-xsave,-xsaveopt,hv-relaxed,hv-vapic,hv-time"
    return f"host,{HV_KVM}" if windows else "host"


def quiet_timers(node) -> bool:
    """Whether a Windows machine runs without the emulated HPET. Windows
    polls an HPET it is given far more than any other clock, and each read is
    an exit to QEMU, so an idle machine with one burns host CPU for nothing;
    every mainstream Windows VM setup (Hyper-V, libvirt, Proxmox) leaves it
    out. `hpet = true` on a node puts it back."""
    return bool(node is not None and node.is_windows and not node.vars.get("hpet"))


def balloon_device() -> str:
    """The balloon, reporting the guest's free memory back where the host can
    take it (Linux, the appliance: madvise). A Linux machine or the router
    then gives back what it frees instead of holding its high-water mark for
    the rest of the session. QEMU on Windows cannot discard a page, so there
    the plain device."""
    from ..balloon import host_can_reclaim
    return "virtio-balloon-pci,free-page-reporting=on" if host_can_reclaim() else "virtio-balloon-pci"


def nested_supported(accel: str) -> bool:
    """Whether a machine can be shown VT-x so Hyper-V runs inside it: KVM
    with nesting allowed, or WHPX on QEMU 11 and later; never HVF or TCG
    (winlab/nestedvirt.py says why, in words)."""
    from ..nestedvirt import host_support
    return host_support(accel)[0]


def nested_cpu(accel: str, linux: bool = False) -> str:
    """The CPU for a machine marked `nested = true`: the host's with VT-x
    where the accelerator can give it; elsewhere the usual model, and the
    machine runs as any other (Hyper-V inside it will say it cannot start,
    a Linux one has no /dev/kvm)."""
    if nested_supported(accel):
        from ..nestedvirt import cpu
        return cpu(accel, linux=linux) or cpu_model(accel)
    return cpu_model(accel)


def assert_isolated(argv: list[str], uplink: bool = False) -> None:
    bad = check_isolation(argv, uplink)
    if bad:
        raise RuntimeError("refusing to start a machine with a path outside the lab:\n  "
                           + "\n  ".join(bad))


# Network cards come after every disk and disc in the boot order.
NIC_BOOTINDEX = 20


@dataclass
class NodeRuntime:
    node_id: str
    qmp_port: int = 0
    serial_port: int = 0
    vnc_port: int = 0
    term_port: int = 0          # a Linux machine's ttyS0 console, for its Terminal window
    com_port: int = 0           # the console cable's USB-serial adapter, COM2 (consolecable.py)
    wterm_port: int = 0         # a Windows machine's COM3, its console host's line (winterm.py)
    disk: Path | None = None
    data_disks: list[Path] = field(default_factory=list)
    install_iso: Path | None = None
    provision_iso: Path | None = None
    attach_iso: Path | None = None   # an ISO kept in the drive, not booted from
    extra_discs: list[Path | None] = field(default_factory=list)  # DVD drives 2.. (mediashelf)
    dvd_first: bool = False          # the firmware tries the DVD drive before the disk
    uefi_vars: Path | None = None
    argv: list[str] = field(default_factory=list)


class QemuProvider:
    def __init__(
        self,
        plan: TopologyPlan,
        accel: str = "whpx",
        display: str = DISPLAY_WINDOW,
    ) -> None:
        self.plan = plan
        self.accel = accel
        self.display = display
        self.lab = plan.lab
        self.workdir = paths.lab_dir(self.lab.name)
        self._taken: set[int] = set()
        self._hw: dict[str, dict] = {}   # each machine's build at this power-on (winlab/pcbuild.py)

    # ---------------------------------------------------------------- paths
    def node_dir(self, node_id: str) -> Path:
        return self.workdir / node_id

    def disk_path(self, node_id: str) -> Path:
        return self.node_dir(node_id) / "system.qcow2"

    def data_disk_path(self, node_id: str, index: int) -> Path:
        return self.node_dir(node_id) / f"data{index}.qcow2"

    def uefi_vars_path(self, node_id: str) -> Path:
        return self.node_dir(node_id) / "uefi-vars.fd"

    # ------------------------------------------------------------- firmware
    def _firmware(self) -> tuple[Path, Path] | None:
        return paths.uefi_firmware()

    def _cpu_model(self, name: str = "") -> str:
        node = self.lab.nodes.get(name)
        return cpu_model(self.accel, windows=bool(node is not None and node.is_windows))

    # ----------------------------------------------------------------- args
    def _base_args(self, name: str, cpus: int, memory_mb: int) -> list[str]:
        return [
            str(paths.qemu_exe()),
            "-name", f"winlab:{self.lab.name}:{name}",
            "-machine", "q35",
            "-accel", self.accel,
            "-cpu", self._cpu_model(name),
            "-smp", str(cpus),
            "-m", str(memory_mb),
            "-rtc", self._rtc(name),
            "-no-user-config",
            "-nodefaults",
            # A boot menu so a student can press ESC in the machine's window to
            # enter UEFI/BIOS setup -- boot order, Secure Boot, the real thing.
            "-boot", "menu=on,splash-time=2000",
        ]

    def _rtc(self, name: str) -> str:
        """The machine's RTC starts at lab time and stops while the lab clock
        is paused (winlab/labclock.py): local time for Windows, UTC for Linux
        and the router, as each OS reads it. With its CMOS battery flat or
        out it starts at the firmware's default date (winlab/pcbuild.py)."""
        from .. import timesync
        node = self.lab.nodes.get(name)
        cmos = self._hw.get(name, {}).get("rtc")
        if cmos:
            return f"base={cmos},clock=vm"
        from ..linuxiso import is_hand_linux  # Linux installed by hand keeps its RTC in UTC too
        from ..bsdfw import is_hand_firewall  # and so does a BSD firewall
        from ..netos import is_router         # and a vendor's router OS
        from ..android import is_hand_android  # and Android, a Linux kernel underneath
        utc = name == "fabric" or (node is not None and (node.kind == LINUX or is_hand_linux(node)
                                                        or is_hand_firewall(node) or is_router(node)
                                                        or is_hand_android(node)))
        return timesync.rtc_arg(self.lab.name, name, utc)  # plus its own skew, if it has one

    def _display_args(self, node: Node, rt: NodeRuntime | None = None, video: str = "") -> list[str]:
        # A node can request the paravirtual display adapter (virtio-vga:
        # more resolutions, a driver to install) for teaching display and
        # driver management. It is 2D: the GL variant needs gl=on on a
        # display that has none here, and QEMU refuses to start with it.
        # Real GPU passthrough is deliberately not offered: it is
        # host-specific and would break both portability and the
        # host-isolation guarantee.
        gpu = bool(node.vars.get("gpu")) if not video else video == "gpu"
        adapter = "virtio-vga" if gpu else "VGA,vgamem_mb=32"
        # No graphics card and a processor without graphics: no display
        # device at all (winlab/pcbuild.py). Windows boots headless.
        dev = [] if video == "none" else ["-device", adapter if gpu or self.display != DISPLAY_NONE else "VGA"]
        if self.display == DISPLAY_NONE:
            out = ["-display", "none"] + dev
        else:
            out = ["-display", "gtk,show-tabs=on"] + dev
        if rt and rt.vnc_port:
            # -vnc adds a server beside the window; loopback only, so the
            # screen is reachable by the dashboard and nothing else.
            out += ["-vnc", f"127.0.0.1:{rt.vnc_port - VNC_BASE}"]
        return out

    def _usb_args(self, node: Node) -> list[str]:
        # Emulated USB controller + an optional virtual USB mass-storage device
        # (a "USB stick") so removable-media policy, BitLocker To Go and driver
        # binding are all teachable without touching a real host USB device.
        out: list[str] = ["-device", "qemu-xhci,id=xhci"]
        gb = int(node.vars.get("usb_storage_gb") or 0)
        if gb:
            path = self.node_dir(node.id) / "usb0.qcow2"
            out += [
                "-drive", f"id=usb0,file={path},if=none,format=qcow2",
                "-device", "usb-storage,bus=xhci.0,drive=usb0,removable=on",
            ]
        if node.vars.get("usb_tablet", True):
            out += ["-device", "usb-tablet,bus=xhci.0"]  # smooth mouse in the GUI
        stick = self.node_dir(node.id) / "stick.img"
        if stick.exists():
            # A stick winlab wrote and plugged in (media.plug) stays plugged
            # across a restart, until it is unplugged.
            out += [
                "-drive", f"id=wlstick,file={stick},if=none,format=raw",
                "-device", "usb-storage,bus=xhci.0,drive=wlstick,removable=on,id=wlstick",
            ]
        # The other USB ports: sticks from the media shelf (mediashelf.py).
        for i in range(1, mediashelf.ports(node)):
            f = mediashelf.port_file(self.node_dir(node.id), i)
            if f.exists():
                sid = mediashelf.port_id(i)
                out += ["-drive", f"id={sid},file={f},if=none,format=raw",
                        "-device", f"usb-storage,bus=xhci.0,drive={sid},removable=on,id={sid}"]
        # The UPS's USB cable (winlab/ups.py): a usb-redir port whose far end
        # is winlab's UPS, over a loopback socket; no host USB device.
        from .. import ups
        out += ups.usb_args(self.lab.name, node.id, self.node_dir(node.id),
                            lambda: _free_port(MGMT_BASE, self._taken))
        return out

    def _mgmt_args(self, rt: NodeRuntime, node: Node | None = None) -> list[str]:
        out = [
            "-qmp", f"tcp:127.0.0.1:{rt.qmp_port},server=on,wait=off",
            "-chardev", f"socket,id=ser0,host=127.0.0.1,port={rt.serial_port},"
                        f"server=on,wait=off",
        ]
        from ..bsdfw import is_hand_firewall
        from ..netos import is_router
        if node is not None and (is_hand_firewall(node) or is_router(node)) and rt.term_port:
            # A firewall installed by hand: its COM1 (FreeBSD's ttyu0, the
            # serial console) is the Terminal window's; COM2 is idle. So is
            # a vendor router's: RouterOS, VyOS, Junos and EOS all sign in
            # on their first serial port.
            out += ["-chardev", f"socket,id=term0,host=127.0.0.1,port={rt.term_port},"
                                "server=on,wait=off", "-serial", "chardev:term0"]
        elif node is not None and node.kind == LINUX and not console_driven(node.image):
            # Like the fabric: ttyS0 is the kernel console, the agent (the
            # fabric agent in the Alpine overlay, or the one cloud-init
            # installs on an appliance) speaks on ttyS1. An appliance winlab
            # drives over its console (OPNsense) gets the chardev on its first
            # serial port instead: that console is the channel. ttyS0 is the
            # machine's login console, on a loopback socket of its own for
            # the Terminal window when it has a port.
            if rt.term_port:
                out += ["-chardev", f"socket,id=term0,host=127.0.0.1,port={rt.term_port},"
                                    "server=on,wait=off", "-serial", "chardev:term0"]
            else:
                out += ["-serial", "null"]
        return out + ["-serial", "chardev:ser0"]

    def _virtio(self, node: Node) -> bool:
        """Red Hat's paravirtual devices: for Linux always, and for a
        Windows machine that asks (`hardware = "virtio"`) whose base was
        prepared with the virtio-win drivers (images.base_virtio). Every
        other Windows machine is a regular PC: Intel 82574L network card,
        ICH9 SATA, the devices Windows drives out of the box."""
        return uses_virtio(node)

    def hardware_of(self, node: Node) -> str:
        """'virtio' or 'pc', as the machine will really be built."""
        return hardware_of(node)

    def _audio_args(self, node: Node) -> list[str]:
        """Intel HD Audio, the sound card a regular PC has (Windows has the
        driver); no host backend, so nothing leaves the machine."""
        if not node.is_windows:
            return []
        return ["-audiodev", "none,id=snd0",
                "-device", "intel-hda,id=hda",
                "-device", "hda-duplex,bus=hda.0,audiodev=snd0"]

    def _nic_args(self, node: Node, skip: set[int] | None = None) -> list[str]:
        from ..bsdfw import NIC_MODEL, is_hand_firewall  # em(4) cards a BSD firewall installs on
        from .. import netos  # the card each vendor's router OS documents (virtio, or e1000 for EOS)
        from .. import android  # Android-x86's eth0: an Intel e1000 (winlab/android.py)
        model = (netos.nic_model(node) if netos.is_router(node) else "virtio-net-pci" if self._virtio(node)
                 else NIC_MODEL if is_hand_firewall(node)
                 else android.NIC_MODEL if android.is_hand_android(node) else "e1000e")
        out: list[str] = []
        # Every card, cable or not: an empty port is still a card in the
        # machine, its link held down (winlab/livenet.py) until one goes in.
        # Each card is in the boot order after the disks and discs, as on a
        # PC: a machine with nothing else to boot tries the network (PXE),
        # and the firmware's boot menu (Esc at power-on) can pick it.
        for link in self.plan.ports_for(node.id):
            if skip and link.nic_index in skip:
                continue   # its card is out of the case or not seated (winlab/pcbuild.py)
            nid = f"net{link.nic_index}"
            out += [
                "-netdev", link_netdev(nid, link.port, listen=False),
                "-device", f"{model},netdev={nid},mac={link.mac},bootindex={NIC_BOOTINDEX + link.nic_index}",
            ]
        return out

    def _disk_args(self, rt: NodeRuntime, node: Node) -> list[str]:
        out = ["-device", "ich9-ahci,id=ahci"]
        slot = 0
        boot = 1 if rt.dvd_first else 0
        first = ",bootindex=0" if rt.dvd_first else ""
        virtio = self._virtio(node)

        # A dead system disk answers nothing at power-on; a new one fitted in
        # its place has its own serial number (winlab/sysdisk.py).
        ndir = self.node_dir(node.id)
        hw = self._hw.get(node.id, {})
        if rt.disk and sysdisk.present(ndir) and hw.get("sys", True):
            out += [
                "-drive", f"id=sys,file={rt.disk},if=none,format=qcow2,"
                          f"cache=writeback,discard=unmap,detect-zeroes=unmap" + sysdisk.drive_opts(),
            ]
            sn = sysdisk.device_opts(ndir, node.id)
            if virtio:
                out += ["-device", f"virtio-blk-pci,drive=sys,bootindex={boot}{sn}"]
            else:
                out += ["-device", f"ide-hd,bus=ahci.{slot},drive=sys,bootindex={boot}{sn}"]
                slot += 1
            boot += 1
        elif rt.disk and not virtio:
            slot += 1   # the dead drive's port stays where it was

        # Data disks sit in hot-swap bays (winlab/hardware.py): the named
        # nodes are what a pull swaps, and a pulled disk leaves its port empty.
        out_of_bay = hardware.pulled_in(self.node_dir(node.id), len(rt.data_disks))
        out_of_bay |= set(hw.get("absent", ()))   # a cable unplugged or loose, an adapter not seated (pcbuild.py)
        if not virtio:
            # A regular PC's bays are SATA, SAS or NVMe, failing or not (winlab/disks.py).
            out += disks.controller_args(node) if hw.get("hba", True) else []
            bus = disks.asked_buses(node)
        for i, path in enumerate(rt.data_disks):
            if i in out_of_bay:
                slot += 0 if virtio or bus[i] != "sata" else 1
                continue
            if not virtio:
                out += disks.drive_args(self.node_dir(node.id), node, i, path, slot)
                slot += 1 if bus[i] == "sata" else 0
                continue
            out += [
                "-drive", f"id=data{i},file={path},if=none,format=qcow2,cache=writeback,"
                          f"discard=unmap,detect-zeroes=unmap,node-name={hardware.fmt_node(i)},file.node-name={hardware.file_node(i)}",
                "-device", f"virtio-blk-pci,drive=data{i}"
                           + (f",serial={SAN_BAY}{i + 1}" if "san" in node.roles else ""),  # a SAN knows its bays
            ]

        if rt.install_iso:
            out += [
                "-drive", f"id=cdinst,file={rt.install_iso},if=none,media=cdrom,readonly=on",
                "-device", f"ide-cd,bus=ahci.{slot},drive=cdinst,bootindex={boot}",
            ]
            slot += 1
            boot += 1

        if rt.provision_iso:
            out += [
                "-drive", f"id=cdprov,file={rt.provision_iso},if=none,media=cdrom,readonly=on",
                "-device", f"ide-cd,bus=ahci.{slot},drive=cdprov",
            ]
            slot += 1

        if rt.attach_iso:
            out += [
                "-drive", f"id=cdattach,file={rt.attach_iso},if=none,media=cdrom,readonly=on",
                "-device", f"ide-cd,bus=ahci.{slot},id=cdattach,drive=cdattach{first}",
            ]
            slot += 1
        elif node.kind != LINUX:
            # An empty DVD drive, like a PC's: a disc goes in and out while
            # the machine runs (media.insert / eject, QMP on this drive; the
            # device's own id is what blockdev-change-medium's `id` names).
            out += [
                "-drive", "id=cdattach,if=none,media=cdrom",
                "-device", f"ide-cd,bus=ahci.{slot},id=cdattach,drive=cdattach{first}",
            ]
            slot += 1
        # A second DVD drive fitted in the case (mediashelf.drives), while
        # the SATA controller has a port for it.
        for i, disc in enumerate(rt.extra_discs, start=1):
            if slot >= mediashelf.AHCI_PORTS:
                break
            did = mediashelf.drive_id(i)
            out += ["-drive", f"id={did},if=none,media=cdrom" + (f",file={disc},readonly=on" if disc else ""),
                    "-device", f"ide-cd,bus=ahci.{slot},id={did},drive={did}"]
            slot += 1

        if virtio:
            out += ["-device", balloon_device()]
        return out

    @staticmethod
    def next_ahci_slot(argv: list[str]) -> int:
        """The first free port on the machine's AHCI controller, for a caller
        that adds a drive after the command line was built."""
        return sum(1 for a in argv if a.startswith("ide-") and "bus=ahci." in a)

    @staticmethod
    def iso_path(image_id: str) -> Path:
        """Where an ISO named in node.vars['iso'] lives: the user's own media
        or a catalog installer."""
        from ..images import CATALOG, CustomImage, installer_path

        if image_id in CATALOG:
            return installer_path(image_id)
        return CustomImage(id=image_id, title="").iso

    def _default_uefi(self, node: Node) -> bool:
        """What winlab gives a machine whose firmware is not set."""
        if not self._firmware() or node.kind == LINUX:
            return False
        if node.kind == CUSTOM:
            from ..images import HAND_INSTALL, ImageError, custom_image, templates

            from ..bsdfw import is_hand_firewall, uefi
            if is_hand_firewall(node):
                return uefi(node)  # each firewall's installer boots the way it was built to
            from .. import android
            if android.is_hand_android(node):
                return android.uefi(node)  # Android-x86: the BIOS and its installer's GRUB on MBR
            from ..netos import is_router
            if is_router(node):
                return False  # the vendors' virtual routers boot with the legacy BIOS
            if node.image in HAND_INSTALL:
                return True  # Windows Setup on a modern PC: UEFI, GPT

            tpl = templates().get(node.image)
            if tpl is not None:
                return tpl.firmware == "uefi"
            try:
                return custom_image(node.image).firmware == "uefi"
            except ImageError:
                return False
        return True

    def firmware_mode(self, node: Node) -> tuple[str, str]:
        """(uefi, uefi-secure or bios, why it is not what the machine is set
        to): the machine's own choice (winlab/firmware.py) where it has one."""
        from .. import firmware
        if not firmware.fitted(node):
            return (firmware.UEFI if self._default_uefi(node) else firmware.BIOS), ""
        return firmware.effective(node, self.accel, self._default_uefi(node))

    def _uses_uefi(self, node: Node) -> bool:
        return self.firmware_mode(node)[0] != "bios"

    def secure_boot(self, node: Node) -> bool:
        return self.firmware_mode(node)[0] == "uefi-secure"

    def _firmware_args(self, rt: NodeRuntime, node: Node) -> list[str]:
        fw = self._firmware()
        if not fw or not rt.uefi_vars:
            return []
        from .. import firmware
        mode = self.firmware_mode(node)[0]
        code = paths.uefi_secure_firmware() if mode == firmware.SECURE else fw[0]
        return firmware.qemu_args(mode, code, rt.uefi_vars)[1]

    # --------------------------------------------------------------- builder
    def build_node(self, node: Node) -> NodeRuntime:
        rt = NodeRuntime(node_id=node.id)
        rt.qmp_port = _free_port(MGMT_BASE, self._taken)
        rt.serial_port = _free_port(MGMT_BASE, self._taken)
        rt.vnc_port = _free_port(VNC_BASE, self._taken)
        from ..bsdfw import is_hand_firewall
        from .. import netos
        if (node.kind == LINUX and not console_driven(node.image)) or is_hand_firewall(node) or netos.is_router(node):
            rt.term_port = _free_port(MGMT_BASE, self._taken)
        from .. import consolecable
        if consolecable.fitted(node) and consolecable.takes_adapter(node):
            rt.com_port = _free_port(MGMT_BASE, self._taken)
        from .. import winterm
        if winterm.fitted(node):
            rt.wterm_port = _free_port(MGMT_BASE, self._taken)
        rt.disk = self.disk_path(node.id)
        rt.data_disks = [
            self.data_disk_path(node.id, i) for i in range(len(node.data_disks_gb))
        ]
        if self._uses_uefi(node):
            rt.uefi_vars = self.uefi_vars_path(node.id)
        if netos.is_disk_router(node):
            pass  # the vendor's own disk; no installer in the drive (vEOS's Aboot disc is below)
        elif node.kind == CUSTOM and not is_template(node.image) and not imaging.is_netboot(node):
            # The user's installer stays in the drive, after the disk in boot
            # order: an empty disk falls through to it, an installed one boots.
            # A machine cloned from a template is already installed.
            rt.install_iso = self.iso_path(node.image)
        iso = str(node.vars.get("iso") or "")
        if iso and iso != node.image:
            rt.attach_iso = self.iso_path(iso)
        # What the media shelf put in the drives, and the boot order the
        # machine's firmware keeps (mediashelf.py).
        discs = mediashelf.provider_discs(self.lab.name, node, rt.attach_iso)
        rt.attach_iso, rt.extra_discs = discs[0], discs[1:]
        rt.dvd_first = (mediashelf.boot_first(self.node_dir(node.id)) == mediashelf.BOOT_DVD
                        and mediashelf.drives(node) > 0)
        aboot = netos.boot_disc(node.image) if netos.is_disk_router(node) else None
        if aboot is not None and not rt.attach_iso:
            # Arista's Aboot ISO: the boot loader older vEOS-lab releases
            # start from, which then loads EOS from the disk.
            rt.attach_iso, rt.dvd_first = aboot, True

        # The parts around the processor and the memory (winlab/pcbuild.py):
        # the sticks the board reads, the display, cards and cables seated.
        from .. import pcbuild
        hw = pcbuild.effects(self.lab.name, node)
        self._hw[node.id] = hw
        base = self._base_args(node.id, node.cpus, hw.get("memory_mb") or node.memory_mb)
        from .. import nestedvirt
        if node.nested or netos.needs_nested(node):
            # vJunos runs Junos in a VM of its own: the host's CPU with VT-x.
            base[base.index("-cpu") + 1] = nested_cpu(self.accel, linux=nestedvirt.is_linux(node)
                                                      or netos.needs_nested(node))
        elif nestedvirt.fitted(node):
            # The firmware's VT-x setting is off: the processor shows none.
            at = base.index("-cpu") + 1
            base[at] = nestedvirt.cpu_off(self.accel, base[at])
        if rt.uefi_vars and self.secure_boot(node):
            # System Management Mode, which the Secure Boot firmware needs.
            base[base.index("-machine") + 1] = "q35,smm=on"
        if quiet_timers(node):
            base[base.index("-machine") + 1] += ",hpet=off"
            if self.accel == "kvm":
                # Ticks missed while the host was busy are delivered late, not
                # all at once (what Windows' clock expects).
                base += ["-global", "kvm-pit.lost_tick_policy=delay"]
        from .. import bmcfw, identity
        rt.argv = (
            base
            + netos.smbios_args(identity.qemu_args(self.lab.name, node), node)   # its serial, asset tag and UUID (SMBIOS)
            + bmcfw.smbios_args(self.lab.name, node)      # a server's BIOS version, as its BMC last wrote it
            + (pcbuild.smbios_args(self.lab.name, node, hw.get("sticks")) if hw else [])  # each stick (type 17)
            + self._firmware_args(rt, node)
            + bitlocker.tpm_args(self.node_dir(node.id), node)   # a TPM 2.0 chip, when one is fitted
            + self._disk_args(rt, node)
            + self._nic_args(node, hw.get("skip_nics"))
            + self._usb_args(node)
            + self._audio_args(node)
            + self._mgmt_args(rt, node)
            + consolecable.qemu_args(node, rt.com_port)   # COM2, after the agent's COM1
            + winterm.qemu_args(rt.wterm_port)            # COM3, the Command Prompt and PowerShell windows' line
            + self._display_args(node, rt, hw.get("video", ""))
            + (["-S"] if hw.get("hold") else [])   # POST waits for F1: the machine starts paused
        )
        assert_isolated(rt.argv)
        return rt

    def build_fabric(self) -> NodeRuntime:
        rt = NodeRuntime(node_id="fabric")
        rt.qmp_port = _free_port(MGMT_BASE, self._taken)
        rt.serial_port = _free_port(MGMT_BASE, self._taken)
        rt.disk = self.disk_path("fabric")

        args = self._base_args("fabric", self.plan.fabric_cpus, self.plan.fabric_memory_mb)
        args += [
            "-device", balloon_device(),
            "-device", "ich9-ahci,id=ahci",
            "-drive", f"id=sys,file={rt.disk},if=none,format=qcow2,cache=writeback",
            "-device", "ide-hd,bus=ahci.0,drive=sys,bootindex=0",
        ]
        # The fabric listens; node links connect (and redial, where QEMU can,
        # when the fabric restarts under them).
        # The switch ports are line cards of eight ports each (functions of one
        # PCI slot), in the order the router names them, so a big lab's ports
        # and the spare slots below all fit on the machine's one PCI bus
        # (31 slots; one card per slot ran out at about ten ports).
        if len(self.plan.ports) > LINK_SLOTS * 8:
            raise RuntimeError(f"the lab router has room for {LINK_SLOTS * 8} network ports; "
                               f"this lab has {len(self.plan.ports)}")
        # eth0 is the router's own management port, with no cable: the
        # router names its cards in bus order, and the switch ports are
        # eth1, eth2... (netplan.compile_topology). Without it the first
        # machine's cable would be eth0 and every port one name off.
        args += ["-device", f"virtio-net-pci,id=mgmt0,{_pci_addr(MGMT_SLOT, 0)}"]
        for i, link in enumerate(self.plan.ports):
            nid = fabric_netdev_id(link)
            args += [
                "-netdev", link_netdev(nid, link.port, listen=True),
                "-device", f"virtio-net-pci,netdev={nid},{_pci_addr(LINK_SLOT0 + i // 8, i % 8)}",
            ]
        # Empty slots for switch ports added while the router runs: a machine
        # or a network card put into a running network gets its port here
        # (winlab/livenet.py), the way a module goes into a modular switch.
        for i in range(HOTPLUG_SLOTS):
            args += ["-device", f"pcie-root-port,id=hp{i},chassis={i + 1},slot={i + 1},"
                                f"{_pci_addr(HOTPLUG_SLOT0 + i // 8, i % 8)}"]
        # ttyS0 is the Alpine boot console (kept on stdio-less null so it does
        # not pollute the control channel); the agent speaks on ttyS1, which is
        # rt.serial_port. Two -serial args map to ttyS0 then ttyS1 in order.
        args += [
            "-qmp", f"tcp:127.0.0.1:{rt.qmp_port},server=on,wait=off",
            "-serial", "null",
            "-chardev",
            f"socket,id=ctl,host=127.0.0.1,port={rt.serial_port},server=on,wait=off",
            "-serial", "chardev:ctl",
        ]
        # ttyS2: the SSH sessions' line to the devices' consoles (winlab/iosssh.py),
        # a loopback socket only the desktop connects to.
        rt.com_port = _free_port(MGMT_BASE, self._taken)
        args += ["-chardev", f"socket,id=vty,host=127.0.0.1,port={rt.com_port},server=on,wait=off",
                 "-serial", "chardev:vty"]
        args += ["-display", "none", "-device", "VGA"]
        # The way out for internal and external virtual switches
        # (winlab/vswitch.py): none while every switch is private.
        from .. import vswitch
        out = vswitch.active(self.lab)
        if out:
            # after the switch ports on the bus, so it does not take a port's name
            args += [a + f",{_pci_addr(UPLINK_SLOT, 0)}" if a.startswith("virtio-net-pci,") else a
                     for a in vswitch.qemu_args(self.lab)]
        rt.argv = args
        assert_isolated(rt.argv, uplink=out)
        return rt

    def build_all(self) -> dict[str, NodeRuntime]:
        out: dict[str, NodeRuntime] = {"fabric": self.build_fabric()}
        for node in self.lab.node_list():
            out[node.id] = self.build_node(node)
        return out


def render_commands(runtimes: dict[str, NodeRuntime]) -> str:
    lines: list[str] = []
    for node_id, rt in runtimes.items():
        vnc = f"  vnc tcp/{rt.vnc_port}" if rt.vnc_port else ""
        lines.append(f"### {node_id}   qmp tcp/{rt.qmp_port}  serial tcp/{rt.serial_port}{vnc}")
        argv = rt.argv
        out: list[str] = [f"  {argv[0]}"]
        i = 1
        while i < len(argv):
            if argv[i].startswith("-") and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                out.append(f"    {argv[i]} {argv[i + 1]}")
                i += 2
            else:
                out.append(f"    {argv[i]}")
                i += 1
        lines.extend(out)
        lines.append("")
    return "\n".join(lines)
