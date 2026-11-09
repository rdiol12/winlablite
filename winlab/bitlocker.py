"""BitLocker's physical side: the security chip, the startup-key stick, a
disk carried to another machine, and drills that make a PC ask for its
recovery key.

Encrypting, protectors, Group Policy and escrow are the student's, inside
Windows (the lessons bitlocker-*). What winlab adds is the hardware a real
desk has around them:

  TPM          A machine has no TPM until one is fitted (machine off). It is
               a TPM 2.0 chip emulated by swtpm, a separate program winlab
               starts beside QEMU, never bundles: on Linux and the appliance
               the distribution's package (apt install swtpm), elsewhere in
               ./runtime/swtpm. Without swtpm a machine stays TPM-less and
               BitLocker runs with a password or a startup key. The chip's
               state lives in the machine's folder (tpm/), so it keeps its
               keys across restarts; Clear the TPM throws them away, the way
               the firmware's "Clear TPM" does, and BitLocker asks for the
               recovery key at the next power-on.
  Startup key  BitLocker writes <protector id>.BEK on a FAT stick. The
               sticks are the media shelf's (winlab/mediashelf.py): one left
               in a USB port at power-on is there for the boot manager. winlab
               reads the stick's root folder from this PC to say which sticks
               carry a key, the way a label would.
  Disk move    A data disk out of one machine and into a free bay of another,
               with its data (both machines off). Auto-unlock does not travel:
               the other machine sees a locked drive and asks for its password
               or recovery key.
  Drills       The startup-key stick left out of the PC, the stick lost for
               good, the TPM cleared, the encrypted disk carried to another
               machine. Each comes with a hint ladder and a Check my fix that
               reads the machine (winlab/guestfaults.py's pattern); two more
               problems inside Windows (escrow policy switched off, a forced
               recovery) register as guest faults.

What is fitted and which drill runs are kept in the machine's folder
(bitlocker.json), never in the lab file: a network saved or shared carries
no chip state and no drill.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import mediashelf, paths, state
from .hardware import HardwareError

STATE_FILE = "bitlocker.json"
TPM_DIR = "tpm"
TPM_ID = "wltpm"
SOCK_MAX = 100          # a Unix socket path is at most 108 bytes
KEY_RE = re.compile(r"^([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\.BEK$", re.I)
FAT_TYPES = (0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E)
LOST = "lost"           # the lab shelf's folder for a stick that is gone (a drill)


class BitLockerError(HardwareError):
    pass


# ------------------------------------------------------------------ records
def _dir(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id


def _load(node_dir: Path) -> dict:
    try:
        data = json.loads((node_dir / STATE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(node_dir: Path, data: dict) -> None:
    data = {k: v for k, v in data.items() if v not in (None, {}, "")}
    p = node_dir / STATE_FILE
    if not data:
        p.unlink(missing_ok=True)
        return
    node_dir.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def _off(lab_name: str, node, what: str) -> None:
    if state.is_running(lab_name, node.id):
        raise BitLockerError(f"shut {node.id} down before you {what}")
    if node.id in state.suspended(lab_name):
        raise BitLockerError(f"{node.id} is suspended: resume it and shut it down before you {what}")


# ---------------------------------------------------------------------- TPM
def swtpm_exe() -> Path | None:
    """swtpm, where this PC has it: ./runtime/swtpm, then the PATH."""
    name = "swtpm.exe" if os.name == "nt" else "swtpm"
    p = paths.RUNTIME / "swtpm" / "bin" / name
    if p.exists():
        return p
    w = shutil.which("swtpm")
    return Path(w) if w else None


def tpm_available(on_windows: bool | None = None) -> bool:
    # QEMU reaches swtpm over a Unix socket; the Windows build of QEMU has no
    # such character device, so a TPM is a Linux host's (and the appliance's).
    win = (os.name == "nt") if on_windows is None else on_windows
    return not win and swtpm_exe() is not None


def tpm_fitted(node_dir: Path, node) -> bool:
    """A chip in the machine: fitted by hand, or `tpm = true` in the lab file."""
    if not node.is_windows:
        return False
    rec = _load(node_dir)
    return bool(rec["tpm"]) if "tpm" in rec else bool(node.vars.get("tpm"))


def tpm_dir(node_dir: Path) -> Path:
    return node_dir / TPM_DIR


def tpm_socket(node_dir: Path) -> Path:
    s = tpm_dir(node_dir) / "swtpm.sock"
    if len(str(s)) <= SOCK_MAX:
        return s
    tag = hashlib.sha1(str(node_dir.resolve()).encode()).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / f"winlab-tpm-{tag}.sock"


def tpm_args(node_dir: Path, node) -> list[str]:
    """The chip on QEMU's command line (a CRB interface, what q35 PCs
    have), or nothing when the machine has none or this PC has no swtpm."""
    if not tpm_fitted(node_dir, node) or not tpm_available():
        return []
    return ["-chardev", f"socket,id=chr{TPM_ID},path={tpm_socket(node_dir)}",
            "-tpmdev", f"emulator,id={TPM_ID},chardev=chr{TPM_ID}",
            "-device", f"tpm-crb,tpmdev={TPM_ID}"]


def start_tpm(node_dir: Path, argv: list[str]) -> bool:
    """Starts the machine's chip before QEMU connects to it; True when the
    command line has one. swtpm leaves when QEMU closes the socket."""
    if "-tpmdev" not in argv:
        return False
    exe = swtpm_exe()
    if exe is None:
        raise BitLockerError("this machine has a TPM fitted but swtpm is not on this PC: "
                             "install it (apt install swtpm) or take the chip out")
    d = tpm_dir(node_dir)
    d.mkdir(parents=True, exist_ok=True)
    sock = tpm_socket(node_dir)
    pidf = d / "swtpm.pid"
    try:
        old = int(pidf.read_text().strip())
        if state.pid_alive(old):
            os.kill(old, 15)
    except (OSError, ValueError):
        pass
    sock.unlink(missing_ok=True)
    cmd = [str(exe), "socket", "--tpm2", "--tpmstate", f"dir={d}",
           "--ctrl", f"type=unixio,path={sock}", "--terminate", "--daemon",
           "--pid", f"file={pidf}", "--log", f"file={d / 'swtpm.log'}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BitLockerError(f"the TPM did not start: {exc}") from exc
    if r.returncode != 0:
        raise BitLockerError(f"the TPM did not start: {(r.stderr or r.stdout).strip()[:200]}")
    return True


def fit_tpm(lab_name: str, node, on: bool) -> None:
    """The chip in or out of the machine (off). Taken out it keeps its keys:
    the same chip back in, BitLocker unlocks as before."""
    if not node.is_windows:
        raise BitLockerError(f"{node.id}: the security chip is for the Windows machines")
    _off(lab_name, node, "open the case" if on else "take the chip out")
    if on and not tpm_available():
        raise BitLockerError("this PC cannot emulate a TPM: swtpm is not installed "
                             "(apt install swtpm on Linux and the appliance; QEMU on Windows has no TPM link)")
    nd = _dir(lab_name, node.id)
    rec = _load(nd)
    rec["tpm"] = bool(on)
    _save(nd, rec)


def clear_tpm(lab_name: str, node) -> bool:
    """Clear the TPM (machine off): its owner, its keys and every key sealed
    to it (BitLocker's) are gone. True when the chip had anything in it."""
    nd = _dir(lab_name, node.id)
    if not tpm_fitted(nd, node):
        raise BitLockerError(f"{node.id} has no TPM to clear")
    _off(lab_name, node, "clear its TPM")
    d = tpm_dir(nd)
    had = any(d.glob("tpm2-*")) if d.exists() else False
    for f in d.glob("tpm2-*") if d.exists() else []:
        f.unlink()
    return had


# ------------------------------------------------------ the startup-key stick
def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _is_bpb(s: bytes) -> bool:
    return s[0] in (0xEB, 0xE9) and _u16(s, 11) in (512, 1024, 2048, 4096) and s[13] > 0


def _volume_start(fh) -> int | None:
    """Where the FAT volume starts: the whole stick, or its first FAT
    partition (MBR, or GPT as Windows writes on larger sticks)."""
    s = fh.read(512)
    if len(s) < 512:
        return None
    if _is_bpb(s):
        return 0
    if s[510:512] != b"\x55\xaa":
        return None
    for k in range(4):
        e = s[446 + 16 * k:462 + 16 * k]
        if e[4] in FAT_TYPES:
            return _u32(e, 8) * 512
        if e[4] == 0xEE:
            fh.seek(512)
            h = fh.read(92)
            if h[:8] != b"EFI PART":
                return None
            fh.seek(struct.unpack_from("<Q", h, 72)[0] * 512)
            ent = fh.read(128)
            first = struct.unpack_from("<Q", ent, 32)[0]
            return first * 512 if first else None
    return None


def _names(raw: bytes) -> list[str]:
    """The long (or short) names in a FAT directory's entries."""
    out, lfn = [], []
    for o in range(0, len(raw) - 31, 32):
        e = raw[o:o + 32]
        if e[0] == 0:
            break
        if e[0] == 0xE5:
            lfn = []
            continue
        if e[11] == 0x0F:
            part = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "replace")
            lfn.insert(0, part.split("\x00")[0])
            continue
        if e[11] & 0x08:
            lfn = []
            continue
        base, ext = e[0:8].decode("latin-1").rstrip(), e[8:11].decode("latin-1").rstrip()
        base, ext = (base.lower() if e[12] & 0x08 else base), (ext.lower() if e[12] & 0x10 else ext)
        short = base + ("." + ext if ext else "")   # case bits: how Windows keeps "readme.txt"
        out.append("".join(lfn) or short)
        lfn = []
    return out


def stick_files(img: Path) -> list[str]:
    """The names in a stick's root folder (FAT12, FAT16 or FAT32), read
    from this PC; [] for a blank stick or another file system."""
    try:
        with open(img, "rb") as fh:
            base = _volume_start(fh)
            if base is None:
                return []
            fh.seek(base)
            bs = fh.read(512)
            if not _is_bpb(bs):
                return []
            bps, spc, rsv, nfats = _u16(bs, 11), bs[13], _u16(bs, 14), bs[16]
            rootent, spf = _u16(bs, 17), _u16(bs, 22) or _u32(bs, 36)
            fat = base + rsv * bps
            root = fat + nfats * spf * bps
            if rootent:
                fh.seek(root)
                return _names(fh.read(rootent * 32))
            data, clus, raw = root, _u32(bs, 44), b""   # FAT32: the root is a cluster chain
            for _ in range(64):
                if not 2 <= clus < 0x0FFFFFF7:
                    break
                fh.seek(data + (clus - 2) * spc * bps)
                raw += fh.read(spc * bps)
                fh.seek(fat + clus * 4)
                clus = _u32(fh.read(4), 0) & 0x0FFFFFFF
            return _names(raw)
    except (OSError, struct.error, IndexError):
        return []


def startup_keys(img: Path) -> list[str]:
    """The BitLocker startup keys on a stick: each .BEK is named after the
    key protector it unlocks."""
    out = []
    for n in stick_files(img):
        m = KEY_RE.match(n)
        if m:
            out.append(m.group(1).upper())
    return out


def key_sticks(lab_name: str, node=None) -> list[dict]:
    """Every stick that carries a startup key: on the shelf, or in a port
    (of this machine, when one is named)."""
    out = []
    if node is None:
        for s in mediashelf.sticks(lab_name):
            keys = startup_keys(mediashelf.shelf_dir(lab_name, "sticks") / f"{s['id']}.img")
            if keys:
                out.append({**s, "where": "shelf", "keys": keys})
    nodes = [node] if node is not None else []
    if node is None:
        from . import schema
        try:
            nodes = schema.load(lab_name).node_list()
        except Exception:  # noqa: BLE001 - a lab being edited elsewhere
            nodes = []
    for n in nodes:
        c = mediashelf.contents(lab_name, n)
        for p in c["ports"]:
            if p["stick"]:
                keys = startup_keys(mediashelf.port_file(_dir(lab_name, n.id), p["index"]))
                if keys:
                    out.append({**p["stick"], "where": n.id, "port": p["index"], "keys": keys})
    return out


# -------------------------------------------------------------- disk move
def move_disk(lab, src, index: int, dst) -> int:
    """A data disk out of src's bay and into the next free bay of dst, with
    its data (both off). Returns its bay index in dst. The caller saves the
    lab."""
    from . import disks
    if src.id == dst.id:
        raise BitLockerError("pick another machine to carry the disk to")
    if not 0 <= index < len(src.data_disks_gb):
        raise BitLockerError(f"{src.id} has no data disk in bay {index + 1}")
    for n, what in ((src, "take a disk out"), (dst, "fit a disk")):
        _off(lab.name, n, what)
    f = _dir(lab.name, src.id) / f"data{index}.qcow2"
    if not f.exists():
        raise BitLockerError(f"the disk in bay {index + 1} of {src.id} was never written: "
                             "fit a new one on the other machine instead")
    gb, bus = src.data_disks_gb[index], disks.asked_buses(src)[index]
    try:
        j = disks.add(lab, dst, gb, bus)
    except disks.DiskError:
        if bus == "sata":
            j = disks.add(lab, dst, gb, "sas")   # SATA ports all taken: the next bay on the SAS card
        else:
            raise
    dest = _dir(lab.name, dst.id) / f"data{j}.qcow2"
    dest.parent.mkdir(parents=True, exist_ok=True)
    f.replace(dest)
    disks.remove(lab, src, index)
    return j


# ----------------------------------------------------------------- drills
def _pt(text: str) -> str:
    """A drill text in the desktop's language (content/i18n/content/<lang>/problems.json)."""
    from .content import problem_text
    return problem_text(text)


@dataclass(frozen=True)
class Drill:
    id: str
    title: str
    menu: str
    symptom: str
    needs: str          # "key": a startup-key stick in a port; "tpm": a chip; "disk": a data disk
    hints: tuple[str, ...]
    check: str          # PowerShell on the machine that answers (check_on): True once mended
    check_on: str = "machine"   # or "target": the machine the disk went to


_OS = "$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; "
DRILLS: dict[str, Drill] = {}


def _d(d: Drill) -> None:
    DRILLS[d.id] = d


_d(Drill("key-out", "The startup key stick is not in the PC", "Take the startup key stick out",
         "at power-on the PC stops at a blue BitLocker screen: 'Plug in the USB drive that has the BitLocker key'",
         "key",
         ("Power {machine} on and read its screen: BitLocker's pre-boot screen names what it wants. "
          "It is not Windows that is broken; nothing has loaded yet.",
          "The screen asks for the USB drive that has the BitLocker key. That is {stick}, the stick that holds "
          "the startup key {key}.BEK. Look at the media shelf: it is not in {machine}'s ports.",
          "Plug {stick} into a USB port of {machine} from the media shelf and power it on again (or press the "
          "key the screen names to retry). It boots. Then Check my fix."),
         _OS + "$k = @($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'ExternalKey' }); "
         "[bool]([string]$v.ProtectionStatus -eq 'On' -and $k.Count -gt 0)"))
_d(Drill("key-lost", "The user lost the startup key stick", "Lose the startup key stick",
         "at power-on the PC asks for the USB drive with the BitLocker key, and the stick is nowhere: "
         "not in a port, not on the shelf",
         "key",
         ("Power {machine} on and read the screen: it wants the startup key stick, which is gone. Press Esc "
          "for BitLocker recovery: the screen shows a Recovery key ID. Write down its first eight characters.",
          "The 48-digit recovery password is in Active Directory, on {machine}'s computer object. On the DC: "
          "Active Directory Users and Computers, {machine}, BitLocker Recovery tab (the BitLocker Recovery "
          "Password Viewer, RSAT-Feature-Tools-BitLocker-BdeAducExt), or Get-ADObject -SearchBase <pc DN> "
          "-Filter \"objectClass -eq 'msFVE-RecoveryInformation'\" -Properties msFVE-RecoveryPassword; match "
          "the key ID.",
          "Type the recovery password on {machine}'s screen. In Windows, the lost key must stop working: "
          "manage-bde -protectors -get C: lists it ({{{key}}}); manage-bde -protectors -delete C: -id "
          "{{{key}}}, then a new key on a new stick from the shelf: manage-bde -protectors -add C: "
          "-startupkey E: (format it FAT32 first). Then Check my fix."),
         _OS + "$ids = @($v.KeyProtector | ForEach-Object { ([string]$_.KeyProtectorId).Trim('{}').ToUpper() }); "
         "$k = @($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -in 'ExternalKey','Password','TpmPin','Tpm','TpmPinStartupKey','TpmStartupKey' }); "
         "[bool]([string]$v.ProtectionStatus -eq 'On' -and $ids -notcontains '{key}' -and $k.Count -gt 0)"))
_d(Drill("tpm-cleared", "The TPM was cleared", "Clear the TPM",
         "at power-on BitLocker recovery asks for the 48-digit recovery key: the TPM no longer releases the key",
         "tpm",
         ("Power {machine} on: the BitLocker recovery screen. Something changed in what the TPM measured or "
          "holds. Note the Recovery key ID it shows.",
          "The chip was cleared: its owner and the key BitLocker sealed to it are gone, so the TPM protector "
          "cannot unlock. The recovery password for that key ID is on {machine}'s object in AD (the BitLocker "
          "Recovery tab, or Get-ADObject ... msFVE-RecoveryInformation).",
          "Type the recovery password. In Windows, Get-Tpm shows the chip again (Windows takes ownership "
          "after a restart; tpm.msc), and BitLocker needs a new TPM protector: Suspend-BitLocker -MountPoint "
          "C: -RebootCount 1 and restart, or manage-bde -protectors -delete C: -type tpm then "
          "manage-bde -protectors -add C: -tpm. Then Check my fix."),
         "$t = Get-Tpm -ErrorAction SilentlyContinue; " + _OS
         + "$k = @($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -like 'Tpm*' }); "
         "[bool]($t -and $t.TpmReady -and [string]$v.ProtectionStatus -eq 'On' -and $k.Count -gt 0)"))
_d(Drill("disk-moved", "The encrypted disk was moved to another machine", "Move the encrypted disk to another machine",
         "{target} has a new drive that File Explorer shows with a padlock; opening it asks for a password",
         "disk",
         ("On {target}, Disk Management and manage-bde -status show a new drive: BitLocker, Locked. On "
          "{machine} it unlocked itself (auto-unlock), on another machine it cannot.",
          "Auto-unlock keeps the drive's key in {machine}'s own encrypted system drive, so it stays behind. "
          "On {target}, manage-bde -protectors -get <drive>: shows the Numerical Password's ID; that is the key "
          "ID to look up on the computer object of {machine} in AD (the BitLocker Recovery tab finds it by "
          "its first eight characters: Action, Find BitLocker recovery password).",
          "On {target}: manage-bde -unlock <drive>: -RecoveryPassword <the 48 digits> (Unlock-BitLocker "
          "-RecoveryPassword); a server needs the BitLocker feature first (Install-WindowsFeature BitLocker, "
          "restart). Then Check my fix."),
         "[bool](Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { [string]$_.VolumeType -eq 'Data' "
         "-and [string]$_.LockStatus -eq 'Unlocked' -and [string]$_.VolumeStatus -ne 'FullyDecrypted' })",
         check_on="target"))


def drill(lab_name: str, node_id: str) -> dict:
    return _load(_dir(lab_name, node_id)).get("drill") or {}


def _set_drill(lab_name: str, node_id: str, rec: dict | None) -> None:
    nd = _dir(lab_name, node_id)
    data = _load(nd)
    data["drill"] = rec or {}
    _save(nd, data)


def _lost_dir(lab_name: str) -> Path:
    return mediashelf.shelf_dir(lab_name, LOST)


def start_drill(lab, node, kind: str, target=None, disk: int | None = None) -> dict:
    """Break it the way it breaks on a desk; the record says what was done."""
    d = DRILLS.get(kind)
    if d is None:
        raise BitLockerError(f"no drill {kind!r}: {', '.join(DRILLS)}")
    if not node.is_windows:
        raise BitLockerError(f"{node.id} is not a Windows machine")
    if drill(lab.name, node.id):
        raise BitLockerError(f"{node.id} has a drill running: check it or end it first")
    rec: dict = {"kind": kind, "hints": 0}
    if d.needs == "key":
        ks = key_sticks(lab.name, node)
        if not ks:
            raise BitLockerError(f"no stick in {node.id}'s ports carries a startup key: encrypt C: with a "
                                 "startup key on a stick first (lesson bitlocker-os-without-tpm)")
        k = ks[0]
        r = mediashelf.unplug(lab, node.id, k["port"])
        rec.update(stick=r["id"] if r else k["id"], title=k["title"], key=k["keys"][0])
        if kind == "key-lost" and r:
            src = mediashelf.shelf_dir(lab.name, "sticks") / f"{r['id']}.img"
            ld = _lost_dir(lab.name)
            ld.mkdir(parents=True, exist_ok=True)
            for ext in (".img", ".json"):
                if src.with_suffix(ext).exists():
                    src.with_suffix(ext).replace(ld / f"{r['id']}{ext}")
    elif d.needs == "tpm":
        clear_tpm(lab.name, node)
    elif d.needs == "disk":
        if target is None:
            raise BitLockerError("name the machine the disk goes to")
        i = 0 if disk is None else int(disk)
        j = move_disk(lab, node, i, target)
        rec.update(target=target.id, bay=j, from_bay=i)
    _set_drill(lab.name, node.id, rec)
    return {**rec, "title": _pt(d.title), "symptom": _fill(_pt(d.symptom), lab, node.id, rec)}


def _fill(text: str, lab, node_id: str, rec: dict) -> str:
    from . import naming
    words = {"machine": naming.display(lab, node_id), "stick": rec.get("title") or "the key stick",
             "key": rec.get("key") or "", "target": naming.display(lab, rec["target"]) if rec.get("target") else ""}
    for k, v in words.items():
        text = text.replace("{" + k + "}", v)
    return text.replace("{{", "{").replace("}}", "}")


def drill_hint(lab, node_id: str) -> dict:
    rec = drill(lab.name, node_id)
    if not rec:
        raise BitLockerError(f"no drill on {node_id}")
    d = DRILLS[rec["kind"]]
    n = min(len(d.hints), int(rec.get("hints") or 0) + 1)
    rec["hints"] = n
    _set_drill(lab.name, node_id, rec)
    return {"hint": n, "of": len(d.hints), "text": _fill(_pt(d.hints[n - 1]), lab, node_id, rec)}


def check_script(lab, node_id: str) -> tuple[str, str]:
    """(machine, PowerShell) that proves the drill mended."""
    rec = drill(lab.name, node_id)
    if not rec:
        raise BitLockerError(f"no drill on {node_id}")
    d = DRILLS[rec["kind"]]
    on = rec.get("target") if d.check_on == "target" else node_id
    return on, d.check.replace("{key}", rec.get("key") or "")


def drill_check(lab, node_id: str, runner=None) -> dict:
    """Check my fix: the machine itself is read, never the answer. runner
    (machine, script) -> stdout is the tests' seam."""
    on, script = check_script(lab, node_id)
    rec = drill(lab.name, node_id)
    d = DRILLS[rec["kind"]]
    if d.needs == "key" and rec["kind"] == "key-out":
        nd = _dir(lab.name, node_id)
        back = any(rec.get("key") in startup_keys(mediashelf.port_file(nd, i)) for i in range(mediashelf.PORTS))
        if not back:
            return {"ok": True, "fixed": False, "message": f"{rec.get('title')} is not in a port of {node_id}"}
    if runner is None:
        if not state.is_running(lab.name, on):
            return {"ok": True, "fixed": False, "message": f"{on} is not running: power it on and get it to Windows"}
        runner = _guest_run(lab.name)
    try:
        out = runner(on, script)
    except Exception as exc:  # noqa: BLE001 - a machine at the recovery screen has no agent
        return {"ok": True, "fixed": False, "message": f"{on} does not answer yet ({exc}): is it past BitLocker's screen?"}
    from .guestfaults import is_fixed
    fixed = is_fixed(out or "")
    if fixed:
        rec["fixed"] = True
        _set_drill(lab.name, node_id, rec)
    return {"ok": True, "fixed": fixed, "message": f"fixed: {_pt(d.title).lower()}, and {on} is protected again" if fixed
            else f"not yet: {on} answers, but the check is not met ({_last(out)})"}


def _last(out: str | None) -> str:
    lines = (out or "").strip().splitlines()
    return lines[-1][:120] if lines else "no output"


def _guest_run(lab_name: str):
    def run(node_id: str, script: str) -> str:
        from .exercises import _channel_for
        ch = _channel_for(lab_name, node_id)
        try:
            res = ch.run(script, shell="powershell", timeout=120)
        finally:
            ch.close()
        return res.out if res.ok else (res.out or res.err)
    return run


def end_drill(lab, node_id: str) -> dict:
    """Ends the drill and says what it was. A lost stick turns up again (on
    the shelf); a cleared chip and a moved disk stay as they are now."""
    rec = drill(lab.name, node_id)
    if not rec:
        return {"ended": False}
    if rec["kind"] == "key-lost":
        ld, sd = _lost_dir(lab.name), mediashelf.shelf_dir(lab.name, "sticks")
        sid = rec.get("stick", "")
        if (ld / f"{sid}.img").exists():
            sd.mkdir(parents=True, exist_ok=True)
            for ext in (".img", ".json"):
                if (ld / f"{sid}{ext}").exists():
                    (ld / f"{sid}{ext}").replace(sd / f"{sid}{ext}")
    _set_drill(lab.name, node_id, None)
    return {"ended": True, "kind": rec["kind"], "title": _pt(DRILLS[rec["kind"]].title), "fixed": bool(rec.get("fixed"))}


# ----------------------------------------------------------------- the view
def summary(lab, node) -> dict:
    """The machine's BitLocker hardware, for the desktop's BitLocker window."""
    from . import disks, naming
    nd = _dir(lab.name, node.id)
    rec = drill(lab.name, node.id)
    d = DRILLS.get(rec.get("kind", "")) if rec else None
    others = [{"id": n.id, "name": naming.display(lab, n.id)} for n in lab.node_list()
              if n.id != node.id and n.is_windows]
    tdir = tpm_dir(nd)
    return {
        "node": node.id, "windows": node.is_windows, "running": state.is_running(lab.name, node.id),
        "tpm": {"fitted": tpm_fitted(nd, node), "available": tpm_available(),
                "owned": bool(tdir.exists() and any(tdir.glob("tpm2-*")))},
        "keys": key_sticks(lab.name, node), "shelf_keys": [k for k in key_sticks(lab.name) if k["where"] == "shelf"],
        "disks": [{"index": r["index"], "bay": r["bay"], "gb": r["gb"], "health": r["health"]}
                  for r in disks.status(lab.name, node)],
        "others": others,
        "drills": [{"id": x.id, "title": _pt(x.title), "menu": x.menu, "needs": x.needs} for x in DRILLS.values()],
        "drill": ({"kind": rec["kind"], "title": _pt(d.title), "symptom": _fill(_pt(d.symptom), lab, node.id, rec),
                   "hints": int(rec.get("hints") or 0), "of": len(d.hints), "fixed": bool(rec.get("fixed")),
                   "shown": [_fill(_pt(h), lab, node.id, rec) for h in d.hints[:int(rec.get("hints") or 0)]]}
                  if d else None),
    }


def act(dash, action: str, params: dict) -> dict:
    """The BitLocker window: bl-state, bl-tpm (on=1/0), bl-tpm-clear,
    bl-move (disk, to), bl-drill (kind[, to, disk]), bl-hint, bl-check, bl-end."""
    from . import editor, naming
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    node = lab.nodes.get(node_id)
    if node is None:
        return {"ok": False, "message": "no such machine"}
    name = naming.display(lab, node_id)

    def other():
        t = naming.resolve(lab, str(params.get("to") or ""))
        if t not in lab.nodes:
            raise BitLockerError("pick the machine the disk goes to")
        return lab.nodes[t]
    try:
        if action == "bl-state":
            return {"ok": True, **summary(lab, node)}
        if action == "bl-tpm":
            on = str(params.get("on") or "") in ("1", "true", "on")
            fit_tpm(lab.name, node, on)
            return {"ok": True, "message": f"a TPM 2.0 chip is fitted in {name}: Windows finds it at the next start (tpm.msc)"
                    if on else f"the TPM is out of {name}, with its keys: BitLocker on a TPM asks for recovery without it"}
        if action == "bl-tpm-clear":
            clear_tpm(lab.name, node)
            return {"ok": True, "message": f"{name}'s TPM is cleared: its keys are gone; a drive sealed to it asks "
                                           "for the recovery key at the next start"}
        if action == "bl-move":
            dst = other()
            i = int(params.get("disk", -1))
            j = move_disk(lab, node, i, dst)
            editor.save(lab); dash.reload()
            return {"ok": True, "message": f"the disk from bay {i + 1} of {name} is in bay {j + 1} of "
                                           f"{naming.display(lab, dst.id)}, with its data"}
        if action == "bl-drill":
            kind = str(params.get("kind") or "")
            dst = other() if DRILLS.get(kind) and DRILLS[kind].needs == "disk" else None
            r = start_drill(lab, node, kind, dst, int(params["disk"]) if params.get("disk") not in (None, "") else None)
            if dst is not None:
                editor.save(lab); dash.reload()
            return {"ok": True, "message": f"drill on {name}: {r['symptom']}"}
        if action == "bl-hint":
            r = drill_hint(lab, node_id)
            return {"ok": True, **r, "message": f"hint {r['hint']} of {r['of']}: {r['text']}"}
        if action == "bl-check":
            return drill_check(lab, node_id)
        if action == "bl-end":
            r = end_drill(lab, node_id)
            return {"ok": True, "message": (f"drill ended: it was '{r['title']}'" + (", and you fixed it" if r["fixed"] else ""))
                    if r["ended"] else "no drill was running"}
    except (ValueError, HardwareError, mediashelf.ShelfError) as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown BitLocker action {action!r}"}


# ---------------------------------------------------- problems inside Windows
_FVE = "HKLM\\Software\\Policies\\Microsoft\\FVE"
_ESCROW_GPOS = ("@(Get-GPO -All | Where-Object { $g = $_; @('OSRequireActiveDirectoryBackup','FDVRequireActiveDirectoryBackup',"
                "'OSActiveDirectoryBackup','FDVActiveDirectoryBackup') | Where-Object { (Get-GPRegistryValue -Guid $g.Id "
                f"-Key '{_FVE}' -ValueName $_ -ErrorAction SilentlyContinue).Value -eq 1 }} }})")


def register_faults(reg) -> None:
    from .guestfaults import WINDOWS, GuestFault
    reg(GuestFault(
        id="bitlocker-escrow-off",
        roles=("ad-ds",),
        title="New BitLocker keys stop reaching Active Directory",
        os=WINDOWS,
        teaches="how BitLocker escrow depends on a GPO reaching the PC, gpresult's 'Denied (Disabled GPO)', and why the "
                "'do not enable until stored' setting is the safety net",
        symptom="a PC encrypted a new drive (or got a new recovery password) and the computer object in AD has no "
                "recovery key for it; Enable-BitLocker no longer waits for AD",
        apply="$g = " + _ESCROW_GPOS + "; if (-not $g.Count) { throw 'no GPO stores BitLocker recovery in AD DS yet: "
              "do the bitlocker lessons first' }; $g | ForEach-Object { $_.GpoStatus = 'ComputerSettingsDisabled'; "
              "$_.DisplayName }",
        clear="$g = " + _ESCROW_GPOS + "; $g | ForEach-Object { $_.GpoStatus = 'AllSettingsEnabled'; $_.DisplayName }",
        hints=(
            "Start on the PC: gpresult /r /scope computer lists the GPOs applied and those filtered out. "
            "The BitLocker policy is not among the applied ones. HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE on the "
            "PC has lost its ActiveDirectoryBackup values.",
            "gpresult names the reason: Disabled (GPO). On the DC, Group Policy Management, the BitLocker GPO, "
            "Details tab: GPO Status is 'Computer configuration settings disabled' (Get-GPO -All | Select "
            "DisplayName, GpoStatus). All its settings are computer settings, so it does nothing now.",
            "Set it back: (Get-GPO -Name '<the GPO>').GpoStatus = 'AllSettingsEnabled' (or GPO Status, Enabled), "
            "gpupdate /force on the PC, then escrow what was made meanwhile: Backup-BitLockerKeyProtector "
            "-MountPoint <drive> -KeyProtectorId <the RecoveryPassword protector's id>.",
        ),
        verify="$g = @(" + _ESCROW_GPOS + " | Where-Object { [string]$_.GpoStatus -in 'AllSettingsEnabled','UserSettingsDisabled' "
               "-and @(([xml](Get-GPOReport -Guid $_.Id -ReportType Xml)).GPO.LinksTo | Where-Object { $_.Enabled -eq 'true' }).Count }); "
               "[bool]$g.Count",
    ))
    reg(GuestFault(
        id="bitlocker-forced-recovery",
        title="The PC restarts into BitLocker recovery",
        os=WINDOWS,
        teaches="the recovery screen's key ID, finding the 48-digit password in AD, and putting the TPM protector "
                "back so the next boot does not ask again",
        symptom="the PC restarted on its own and stops at the blue BitLocker recovery screen, asking for the "
                "recovery key",
        apply=_OS + "if ([string]$v.ProtectionStatus -ne 'On' -or -not @($v.KeyProtector | Where-Object { "
              "[string]$_.KeyProtectorType -like 'Tpm*' }).Count) { throw 'C: is not protected by a TPM yet: do the "
              "lesson bitlocker-tpm-and-pin first' }; if (-not @($v.KeyProtector | Where-Object { "
              "[string]$_.KeyProtectorType -eq 'RecoveryPassword' }).Count) { throw 'C: has no recovery password' }; "
              "manage-bde -forcerecovery $env:SystemDrive | Out-Null; shutdown.exe /r /t 15 /c 'winlab'; 'restarting'",
        clear=_OS + "if (-not @($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -like 'Tpm*' }).Count) { "
              "Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector | Out-Null }; 'TPM protector back'",
        hints=(
            "The recovery screen shows a Recovery key ID. Its first eight characters are what the helpdesk asks for. "
            "Nothing is wrong with the disk: BitLocker was told not to trust the TPM's answer.",
            "On the DC, Active Directory Users and Computers: right-click the domain, Find BitLocker recovery password, "
            "type those eight characters (the BitLocker Recovery Password Viewer; Install-WindowsFeature "
            "RSAT-Feature-Tools-BitLocker-BdeAducExt if the tab is missing). Or Get-ADObject -Filter "
            "\"objectClass -eq 'msFVE-RecoveryInformation'\" -Properties msFVE-RecoveryPassword.",
            "Type the 48 digits on the PC's screen. In Windows, manage-bde -protectors -get C: has no TPM protector "
            "any more (forced recovery removes it): manage-bde -protectors -add C: -tpm (or -tpmandpin), then restart "
            "once to prove it boots without asking.",
        ),
        verify=_OS + "[bool]([string]$v.ProtectionStatus -eq 'On' -and @($v.KeyProtector | Where-Object { "
               "[string]$_.KeyProtectorType -like 'Tpm*' }).Count -gt 0)",
    ))


# ---------------------------------------------------------------- the CLI
def add_cli(sub) -> None:
    p = sub.add_parser("bitlocker", help="BitLocker's hardware: the TPM, startup-key sticks, moving a disk, drills")
    p.add_argument("lab")
    p.add_argument("node")
    p.add_argument("op", choices=("show", "tpm-in", "tpm-out", "tpm-clear", "move", "drill", "hint", "check", "end"),
                   nargs="?", default="show")
    p.add_argument("--to", default="", help="move / disk-moved drill: the machine the disk goes to")
    p.add_argument("--bay", type=int, default=1, help="move: the data disk's bay (1 is the first)")
    p.add_argument("--kind", default="", help=f"drill: {', '.join(DRILLS)}")


def run_cli(args) -> int:
    import sys
    from . import editor
    try:
        lab = editor.load_for_edit(args.lab)
        node = lab.nodes.get(args.node)
        if node is None:
            print(f"no such node '{args.node}' in {lab.name}", file=sys.stderr)
            return 2
        op = args.op
        if op == "show":
            s = summary(lab, node)
            t = s["tpm"]
            print(f"{node.id}: TPM {'fitted' + (' (keys in it)' if t['owned'] else ' (empty)') if t['fitted'] else 'none'}"
                  + ("" if t["available"] else " · this PC has no swtpm: no TPM can be fitted"))
            for k in s["keys"]:
                print(f"  USB port {k['port'] + 1}: {k['title']} holds startup key {', '.join(k['keys'])}")
            if s["drill"]:
                print(f"  drill: {s['drill']['title']} (hints {s['drill']['hints']}/{s['drill']['of']})")
        elif op in ("tpm-in", "tpm-out"):
            fit_tpm(lab.name, node, op == "tpm-in")
            print(f"TPM {'fitted in' if op == 'tpm-in' else 'taken out of'} {node.id}")
        elif op == "tpm-clear":
            clear_tpm(lab.name, node)
            print(f"{node.id}'s TPM cleared")
        elif op == "move":
            dst = lab.nodes.get(args.to)
            if dst is None:
                raise BitLockerError("--to names the machine the disk goes to")
            j = move_disk(lab, node, args.bay - 1, dst)
            editor.save(lab)
            print(f"bay {args.bay} of {node.id} is now bay {j + 1} of {dst.id}")
        elif op == "drill":
            r = start_drill(lab, node, args.kind, lab.nodes.get(args.to), args.bay - 1)
            if r.get("target"):
                editor.save(lab)
            print(f"{r['title']}: {r['symptom']}")
        elif op == "hint":
            r = drill_hint(lab, node.id)
            print(f"hint {r['hint']}/{r['of']}: {r['text']}")
        elif op == "check":
            r = drill_check(lab, node.id)
            print(r["message"])
            return 0 if r.get("fixed") else 1
        elif op == "end":
            r = end_drill(lab, node.id)
            print(f"ended: {r['title']}" if r["ended"] else "no drill")
        return 0
    except (editor.EditError, editor.LabError, HardwareError, mediashelf.ShelfError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
