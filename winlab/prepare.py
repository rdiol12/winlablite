"""One-time base-image preparation.

A base is a qcow2 that `winlab lab up` thin-clones per machine. Preparing one
means installing the OS once, embedding the winlab agent, generalising, and
shutting down clean.

Windows: boot the Microsoft ISO + the unattended answer floppy headless, wait
for the agent's 'ready' banner over serial, sysprep /generalize, power off.
Linux (Alpine fabric): a lighter path, since Alpine runs from the ISO and the
agent + networking tools are installed into a persistent qcow2 overlay.

The Windows path depends on a real Microsoft ISO, which is import-only.
"""

from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
from pathlib import Path

from . import images, paths, provision, unattend
from .model import Lab, Nic, Node
from .images import ImageError


class PrepareError(Exception):
    pass


def _firmware_mode() -> str:
    return "uefi" if paths.uefi_firmware() else "bios"


def _free_port(base: int = 34000) -> int:
    import socket

    for port in range(base, base + 500):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise PrepareError("no free port for preparation")


def _write_prep_answer(node, lab, dest: Path, virtio: bool = False) -> Path:
    from . import fatfs
    img = fatfs.floppy("WLPROV")
    img.add_file("autounattend.xml",
                 unattend.render(node, lab, firmware=_firmware_mode(), prep=True, virtio=virtio))
    return img.write(dest)


def _agent_payload_disk(image_id: str, kind: str,
                        drivers: dict[str, bytes] | None = None) -> Path:
    """A FAT disk with the agent + a synthetic facts.json, so the prepared base
    already has the agent installed and self-starting; with the virtio-win
    drivers and their installer script when the base is to carry them."""
    out = paths.downloads_dir() / f"prep-{image_id}.img"
    fake = Node(id="base", image=image_id, kind=kind, nics=[Nic(network="prep")])
    lab = Lab(name="prep", domain="prep.local")
    # Reuse the provisioning data-disk builder; facts are placeholder, replaced
    # per-node at real boot time.
    from .netplan import compile_topology

    lab.networks["prep"] = __import__("winlab.model", fromlist=["Network"]).Network(
        id="prep", cidr="10.255.255.0/24"
    )
    lab.nodes["base"] = fake
    plan = compile_topology(lab, check_ports=False)
    from . import basetrim
    extra = {basetrim.FILE: basetrim.SCRIPT.encode("utf-8")}
    if drivers:
        from . import virtio as vio
        extra[vio.FILE] = vio.SCRIPT.encode("utf-8")
        extra.update(drivers)
    provision.build_data_disk(fake, lab, plan, out, extra=extra)
    return out


def _virtio_drivers(image_id: str, want: bool, say=print) -> dict[str, bytes]:
    """The virtio-win drivers to stage for this Windows version: fetched now
    when they are not on this PC yet. Without them (network down, asked not
    to) the base is prepared with the emulated devices, and says so."""
    from . import virtio as vio

    if not want:
        return {}
    if not vio.ready(image_id):
        say("  fetching the virtio-win drivers (Red Hat, about 600 MB once; the ISO is removed after)")
        try:
            vio.fetch(progress=lambda line: say(f"  {line}"))
        except vio.VirtioError as exc:
            say(f"  virtio drivers not fetched ({exc}); preparing with emulated devices. "
                f"Later: winlab virtio fetch, then rebuild the base")
            return {}
    return vio.files_for(image_id)


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------


def prepare_windows(image_id: str, size_gb: int = 64, timeout: float = 5400.0,
                    headless: bool = True, compress: bool = True,
                    keep_iso: bool = False, virtio: bool = True) -> Path:
    iso = images.installer_path(image_id)
    if not iso.exists():
        was = images.retired_installer(image_id)
        if was:
            raise PrepareError(
                f"the ISO copy ({was.get('name')}) was removed after '{was.get('prepared')}' "
                f"was prepared, to save disk. Import your download again:\n"
                f"  winlab images import {images.SHARES_INSTALLER.get(image_id, image_id)} <path-to-iso>"
            )
        raise PrepareError(
            f"no installer for '{image_id}'. Download the Microsoft media and import it:\n"
            f"  winlab images import {image_id} <path-to-iso>"
        )

    base = images.base_path(image_id)
    if base.exists():
        raise PrepareError(f"base already prepared at {base}; delete it to rebuild")

    work = base.with_suffix(".building.qcow2")
    images._run_img(["create", "-f", "qcow2", str(work), f"{size_gb}G"])

    kind = images.CATALOG[image_id].kind
    node = Node(id="base", image=image_id, kind=kind, memory_mb=4096, cpus=2,
                nics=[Nic(network="prep")])
    lab = Lab(name="prep", domain="prep.local")
    answer = paths.downloads_dir() / f"prep-{image_id}-answer.img"
    drivers = _virtio_drivers(image_id, virtio)
    # Prep mode: the guest syspreps and powers off on its own after first logon,
    # so base preparation never depends on the OOBE->serial-agent handoff.
    _write_prep_answer(node, lab, answer, virtio=bool(drivers))
    data = _agent_payload_disk(image_id, kind, drivers)

    serial = _free_port()
    qmp = _free_port(serial + 1)
    accel = _detect_accel()
    # With the drivers staged, a virtio NIC, disk and balloon are present
    # during preparation so the drivers bind (the disk driver must, to be
    # boot-start after sysprep); the scratch disk is thrown away after.
    dummy = work.with_suffix(".virtio-scratch.qcow2") if drivers else None
    if dummy:
        images._run_img(["create", "-f", "qcow2", str(dummy), "64M"])
    argv = _windows_install_argv(work, iso, answer, data, serial, qmp, accel, headless,
                                 virtio_disk=dummy, virtio_port=_free_port(qmp + 1) if drivers else 0)
    if drivers:
        from . import virtio as vio
        where = ", ".join(sorted(set(vio.chosen_dirs(image_id).values())))
        print(f"  staged {len(drivers)} virtio-win driver files (network, disk, balloon; "
              f"the ISO's {where} build)")
    edition = images.edition_name(image_id)
    if edition:
        print(f"  installing the media's image {edition!r}")

    print(f"  preparing {image_id}: booting installer (accel={accel}, "
          f"{'headless' if headless else 'windowed'})")
    log = paths.downloads_dir() / f"prep-{image_id}.log"
    proc = subprocess.Popen(argv, stdout=log.open("ab"), stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL)

    # Clear the 'press any key to boot from CD' prompt so setup actually starts.
    stop_keys = threading.Event()
    keythread = threading.Thread(target=_qmp_sendkeys, args=(qmp, stop_keys), daemon=True)
    keythread.start()

    print("  nudging past the boot prompt; the guest installs, syspreps and "
          "powers off on its own (no agent handoff). This can take 20-40 min…")

    # The guest powers off when it is done (sysprep /shutdown in the answer
    # file). A clean exit of the QEMU process is the signal that the base is
    # ready — far more robust than waiting on a serial agent through OOBE.
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(15)
    stop_keys.set()

    if proc.poll() is None:
        proc.kill()
        raise PrepareError(
            f"the guest did not power off within {timeout/60:.0f} min; it may be "
            f"stuck in OOBE. See {log}."
        )

    if not work.exists() or work.stat().st_size < 3 * 1024**3:
        raise PrepareError(
            f"the guest powered off but the disk looks unwritten ({work}); "
            f"the install likely failed. See {log}."
        )
    _seal_base(work, base, compress=compress)
    if dummy:
        dummy.unlink(missing_ok=True)
    from . import virtio as vio
    images.write_base_meta(
        image_id, virtio=bool(drivers), compressed=compress,
        prepared=time.strftime("%Y-%m-%dT%H:%M:%S"),
        drivers=vio.summary(image_id) if drivers else {})
    print(f"  base ready: {base} ({base.stat().st_size / 1024**3:.1f} GiB)"
          f"{', virtio drivers in' if drivers else ', emulated devices only'}")
    if not keep_iso:
        meta = images.retire_installer(image_id)
        if meta:
            print(f"  removed the ISO copy {meta['name']} ({meta['size'] / 1024**3:.1f} GiB); "
                  f"your download is untouched, import it again only to rebuild")
    return base


def _seal_base(work: Path, base: Path, compress: bool = True) -> Path:
    """The installed disk becomes the base. Compressed by default: clones only
    ever read the base (writes go to their own overlay), so qcow2's read-only
    compression costs nothing but a little CPU and halves the file. The
    conversion also drops every cluster the guest retrimmed or never wrote."""
    if not compress:
        work.replace(base)
        return base
    tmp = base.with_suffix(".sealing.qcow2")
    for ctype in ("zstd", "zlib"):
        try:
            print(f"  compressing the base ({ctype}); a few minutes…")
            images._run_img(["convert", "-p", "-O", "qcow2", "-c",
                             "-o", f"compression_type={ctype}", str(work), str(tmp)])
            break
        except ImageError as exc:
            tmp.unlink(missing_ok=True)
            if ctype == "zlib":
                raise PrepareError(f"could not compress the base: {exc}") from exc
            print(f"  this qemu-img has no zstd support ({str(exc)[:80]}); using zlib")
    tmp.replace(base)
    work.unlink(missing_ok=True)
    return base


def _windows_install_argv(disk, iso, answer, data, serial, qmp, accel, headless,
                          virtio_disk=None, virtio_port: int = 0):
    qemu = str(paths.qemu_exe())
    # WHPX faults with `-cpu host` (xsave passthrough -> "Unexpected VP exit
    # code 4"); use a stable named model with the features Server 2025 needs.
    if accel == "tcg":
        cpu = "max"
    elif accel == "whpx":
        cpu = "Skylake-Client-v4,-xsave,-xsaveopt,hv-relaxed,hv-vapic,hv-time"
    else:
        cpu = "host"
    args = [
        qemu, "-name", "winlab-prepare",
        "-machine", "q35", "-accel", accel,
        "-cpu", cpu,
        "-smp", "2", "-m", "4096",
        "-rtc", "base=localtime", "-no-user-config", "-nodefaults",
        "-device", "ich9-ahci,id=ahci",
        # discard=unmap: the retrim at the end of the install hands the free
        # space back, so the sealed base holds only what Windows kept.
        "-drive", f"id=sys,file={disk},if=none,format=qcow2,cache=writeback,"
                  f"discard=unmap,detect-zeroes=unmap",
        "-device", "ide-hd,bus=ahci.0,drive=sys,bootindex=0",
        "-drive", f"id=inst,file={iso},if=none,media=cdrom,readonly=on",
        "-device", "ide-cd,bus=ahci.1,drive=inst,bootindex=1",
        "-drive", f"id=ans,file={answer},if=floppy,format=raw",
        "-drive", f"id=pl,file={data},if=none,format=raw",
        "-device", "ide-hd,bus=ahci.2,drive=pl",
        "-chardev", f"socket,id=ser0,host=127.0.0.1,port={serial},server=on,wait=off",
        "-serial", "chardev:ser0",
        "-qmp", f"tcp:127.0.0.1:{qmp},server=on,wait=off",
    ]
    uefi = paths.uefi_firmware()
    if uefi:
        fw, src = uefi
        varstore = disk.with_suffix(".vars.fd")
        if not varstore.exists():
            varstore.write_bytes(src.read_bytes())
        args += [
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={fw}",
            "-drive", f"if=pflash,format=raw,unit=1,file={varstore}",
        ]
    if virtio_disk:
        # A virtio disk, NIC (on a loopback socket nobody connects to) and
        # balloon, so the drivers staged on the data disk bind during the
        # install and the sealed base boots from virtio afterwards.
        args += [
            "-drive", f"id=vio,file={virtio_disk},if=none,format=qcow2",
            "-device", "virtio-blk-pci,drive=vio",
            "-netdev", f"socket,id=vnet,listen=127.0.0.1:{virtio_port}",
            "-device", "virtio-net-pci,netdev=vnet",
            "-device", "virtio-balloon-pci",
        ]
    args += ["-display", "none" if headless else "gtk", "-device", "VGA"]
    return args


def _detect_accel() -> str:
    from .hostprobe import probe

    return probe().accel


def _qmp_sendkeys(port: int, stop: threading.Event) -> None:
    """Windows UEFI/BIOS install media prints 'Press any key to boot from CD'
    and waits; headless, nobody presses one, so firmware falls through to the
    UEFI shell and nothing installs. This clears the prompt by sending Enter
    over QMP through the early-boot window, then goes quiet so it does not
    disturb the installer.
    """
    deadline = time.monotonic() + 75
    sock = None
    for _ in range(40):
        if stop.is_set():
            return
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            break
        except OSError:
            time.sleep(1)
    if not sock:
        return
    try:
        f = sock.makefile("rwb")
        f.readline()
        f.write(b'{"execute":"qmp_capabilities"}\n')
        f.flush()
        f.readline()
        while time.monotonic() < deadline and not stop.is_set():
            for key in ("ret", "spc"):
                f.write(
                    json.dumps(
                        {"execute": "send-key",
                         "arguments": {"keys": [{"type": "qcode", "data": key}]}}
                    ).encode() + b"\n"
                )
                f.flush()
                try:
                    f.readline()
                except OSError:
                    return
            time.sleep(1.5)
    except OSError:
        return
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Alpine fabric base
# --------------------------------------------------------------------------


def prepare_fabric(fetch_packages: bool = True) -> Path:
    """Build what the fabric and the Alpine nodes boot with.

    Rather than a full disk install, the fabric runs the stock Alpine ISO in
    diskless (run-from-RAM) mode: Alpine's init restores a winlab apkovl
    overlay (hostname, the serial agent, the package list) from a FAT volume
    and installs that list from the "boot repositories" it finds on the
    attached media. The ISO's own repository holds the base system only and
    the lab has no internet, so the packages are fetched here, from the
    Alpine mirror for the ISO's own release, into a second repository volume.

    Produces:
      - bases/alpine.qcow2         : a small writable scratch disk (cache + state)
      - bases/fabric.apkovl.tar.gz : the overlay (each start wraps it in its own
                                     FAT volume, alpineovl.overlay_disk)
      - bases/alpine-repo.img      : the repository volume (apkrepo)
    The orchestrator attaches the ISO (-cdrom), the overlay volume, the
    repository volume and the config disk (orchestrator.alpine_media_argv).
    """
    from . import alpineovl, apkrepo

    iso = images.installer_path("alpine")
    if not iso.exists():
        raise PrepareError("alpine iso missing; run 'winlab images fetch alpine'")

    ovl = alpineovl.build_apkovl()
    info = alpineovl.verify(ovl)
    if not (info["has_agent"] and info["has_service"]):
        raise PrepareError("overlay build is incomplete (missing agent or service)")

    # A small scratch qcow2 gives Alpine somewhere to cache apks and persist the
    # overlay across reboots within a lab session.
    scratch = images.base_path("alpine")
    if not scratch.exists():
        images._run_img(["create", "-f", "qcow2", str(scratch), "4G"])

    print(f"  overlay:  {ovl}  ({ovl.stat().st_size} bytes, "
          f"{info['packages']} packages, agent+service embedded)")
    print(f"  scratch:  {scratch}")

    cache = None
    if fetch_packages:
        try:
            cache = apkrepo.fetch(iso=iso, say=print).dir
        except Exception as exc:  # noqa: BLE001 - a failed fetch is reported, not hidden
            cache = apkrepo.cached(apkrepo.branch_of(apkrepo.iso_release(iso)))
            if cache is None:
                raise PrepareError(
                    f"could not fetch the fabric's Alpine packages from {apkrepo.MIRROR} "
                    f"({exc}); the fabric needs them to serve the lab. Check the "
                    f"connection and run 'winlab images prepare fabric' again"
                ) from exc
            print(f"  warning: package fetch failed ({exc}); using the set fetched earlier")
        # The storage array's and the NTP server's management pages: Webmin's
        # pinned release from its GitHub release, onto the same volume.
        from . import webmin
        try:
            webmin.fetch(progress=lambda m: print(f"  {m}"))
        except webmin.WebminError as exc:
            print(f"  warning: Webmin fetch failed ({exc}); the storage array and the NTP "
                  f"server come up without their management pages until it is fetched")
        # The servers' BMCs: OpenBMC's web UI, winlab's release built from its
        # source, onto the same volume for the router.
        from . import openbmcui
        try:
            openbmcui.fetch(progress=lambda m: print(f"  {m}"))
        except openbmcui.OpenBmcUiError as exc:
            print(f"  warning: OpenBMC web UI fetch failed ({exc}); the servers' management "
                  f"ports serve winlab's own BMC pages until it is fetched")
    else:
        cache = apkrepo.cached()
    if cache is not None:
        img = apkrepo.build_image(cache)
        print(f"  packages: {img}  ({img.stat().st_size // (1024 * 1024)} MB, "
              f"from {cache})")
    print("  fabric base ready (Alpine diskless + winlab overlay + repository volume)")
    return scratch


def repo_image_path() -> Path:
    from . import apkrepo
    return apkrepo.image_path()
