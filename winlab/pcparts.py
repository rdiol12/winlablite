"""The inside of a machine, part by part: its hardware view.

A PC, a server or a laptop is drawn open, from above: the board with its
processor socket, memory slots, PCIe slots and M.2 sockets, the drive cage
(a server's hot-swap bays at the front), the optical bays, the TPM header
and a server's management module. Beside it lies a tray of parts. The user
drags a part from the tray onto a free slot to fit it, drags a fitted part
out of the machine to take it out, or drops a part on a full slot of its
kind to swap it (a processor, a memory stick).

Every part is a real part of the QEMU machine at its next start, and only
what QEMU really gives is offered:

* processor: the cores of -smp;
* memory sticks: their sum is -m (the sticks per slot are kept in the lab
  file as ``dimms``, so the board shows what was fitted where);
* network card: an Intel Gigabit CT (82574L, e1000e), which Windows drives
  with its own driver; on a virtio machine, a virtio network card;
* graphics card: virtio-vga in the x16 slot (Windows uses its Basic
  Display driver until the virtio display driver is installed from a driver
  stick); without one, the board's own VGA;
* SAS host bus adapter: the LSI SAS1068 (lsi_sas, in Windows), which SAS
  drives need;
* drives: SATA in the cage or a server's bays, SAS on the HBA, NVMe in an
  M.2 socket (winlab/disks.py);
* DVD drives (winlab/mediashelf.py), the TPM 2.0 module (winlab/bitlocker.py)
  and a server's management module (its BMC, winlab/power.py).

Which PCIe slot holds which card is kept in the lab file (``pcie``, one
word a slot: gpu, hba, nic<N> or -).

The machine must be off, as on a real PC, except for what is made to be
changed while it runs: a drive in a server's hot-swap bay comes out live
(it stops answering at once, winlab/hardware.py) and the same drive goes
back in live. A drive taken out lies on the bench with its data until it
goes back in or is thrown away.
"""

from __future__ import annotations

from . import disks, hardware, mediashelf, naming, paths
from .hardware import HardwareError
from .model import CUSTOM, LINUX
from .qmp import Qmp

_qmp = Qmp  # a seam the tests replace

CORES = (1, 2, 4, 6, 8, 12, 16)
STICKS_MB = (1024, 2048, 4096, 8192, 16384, 32768)
DRIVE_GB = (20, 40, 64, 128, 256)
MAX_MEMORY_MB = 65536
MAX_NICS = 8

# Each form's board: how many of each slot it has.
FORMS = {
    "tower": {"dimm": 4, "pcie": ("x16", "x1", "x16", "x1", "x1", "x4"), "m2": 2, "bay35": 4, "bay25": 2,
              "hs": 0, "odd": 2, "tpm": True, "bmc": False, "cpu_fixed": False},
    "server": {"dimm": 8, "pcie": ("x16", "x8", "x8", "x8", "x4", "x4"), "m2": 2, "bay35": 0, "bay25": 0,
               "hs": 10, "odd": 1, "tpm": True, "bmc": True, "cpu_fixed": False},
    "laptop": {"dimm": 2, "pcie": (), "m2": 1, "bay35": 0, "bay25": 1,
               "hs": 0, "odd": 0, "tpm": True, "bmc": False, "cpu_fixed": True},
}
SHELF_FORM = {"pc": "tower", "iso": "tower", "server": "server", "linux": "server", "laptop": "laptop"}


class PartsError(HardwareError):
    pass


# ------------------------------------------------------------------ the host
_HOST_CACHE: dict = {}


def host() -> dict:
    """What this PC has to give: logical processors, physical memory and the
    free space where the machines' disks live (kept for a few seconds)."""
    import os
    import shutil
    import time
    from . import hostprobe
    now = time.monotonic()
    if _HOST_CACHE and now - _HOST_CACHE["t"] < 5:
        return _HOST_CACHE["v"]
    free = 0
    try:
        where = paths.VAR if paths.VAR.exists() else paths.VAR.parent
        free = int(shutil.disk_usage(str(where)).free / (1 << 30))
    except OSError:
        pass
    v = {"cores": os.cpu_count() or 0, "ram_mb": int(hostprobe._memstatus()[0] / (1 << 20)), "free_gb": free}
    _HOST_CACHE.update(t=now, v=v)
    return v


def _host() -> dict:
    return host()   # a seam the tests replace


def warnings(node, h: dict | None = None) -> list[dict]:
    """Where the machine as built asks more than this PC has: its cores, its
    memory, the space its drives can grow to."""
    from . import membudget
    h = h or _host()
    out = []
    if h.get("cores") and node.cpus > h["cores"]:
        out.append({"part": "cpu", "text": f"{node.cpus} cores on a PC with {h['cores']}: the machine shares this "
                    "PC's processors, so it runs slower, and so does everything else on this PC"})
    room = h.get("ram_mb", 0) - membudget.HOST_MARGIN_MB - membudget.QEMU_OVERHEAD_MB
    if h.get("ram_mb") and node.memory_mb > room:
        floor = node.trim_floor_mb
        out.append({"part": "dimm", "text": f"{_mb(node.memory_mb)} of memory on a PC with {_mb(h['ram_mb'])}: it will not "
                    "start at this size. At power-on winlab cuts it toward " + _mb(floor)
                    + (" or refuses to start it" if floor > room else "") + "; take sticks out to fit this PC"})
    grow = int(node.vars.get("disk_gb") or 0) + sum(node.data_disks_gb)
    if h.get("free_gb") and grow > h["free_gb"]:
        out.append({"part": "disk", "text": f"its drives can grow to {grow} GB and this PC has {h['free_gb']} GB free: "
                    "they only take space as Windows writes to them, but filled up they would fill this PC's disk"})
    return out


# ------------------------------------------------------------------ helpers
def form_of(node) -> str:
    """'tower', 'server' or 'laptop'; '' for a device with no case to open
    (a printer, a phone, an appliance)."""
    from .workbench import _shelf_of
    return SHELF_FORM.get(_shelf_of(node), "")


def _running(lab_name: str, node_id: str) -> bool:
    from .media import _qmp_port
    return bool(_qmp_port(lab_name, node_id))


def _virtio(node) -> bool:
    return disks._virtio(node)


def nic_title(node) -> str:
    return "virtio network card" if _virtio(node) else "Intel Gigabit CT network card (82574L)"


def sticks(node, slots: int) -> list[int]:
    """The memory stick in each slot (0 = empty). Kept as fitted; when the
    lab file has none (or they no longer add up), the fewest sticks that make
    the memory, from the first slot."""
    try:
        got = [int(x) for x in str(node.vars.get("dimms") or "").split()]
    except ValueError:
        got = []
    if len(got) == slots and all(x >= 0 for x in got) and (sum(got) == node.memory_mb and any(got) or not any(got)):
        return got   # as fitted (every slot empty: the sticks are out, pcbuild.py)
    out, left = [], node.memory_mb
    for s in sorted(STICKS_MB, reverse=True):
        while left >= s and len(out) < slots:
            out.append(s)
            left -= s
    if left > 0:
        if len(out) < slots:
            out.append(left)
        elif out:
            out[-1] += left
    return out + [0] * (slots - len(out))


def _store_sticks(node, got: list[int]) -> None:
    if sum(got):
        node.memory_mb = sum(got)   # with every stick out the machine keeps its last size (it cannot POST)
    node.vars["dimms"] = " ".join(str(x) for x in got)


def has_hba(node) -> bool:
    return "hba" in str(node.vars.get("pcie") or "").split() or "sas" in disks.asked_buses(node)


def cards(node, form: str) -> list[str]:
    """What is in each PCIe slot: 'gpu', 'hba', 'nic<N>' or '' (empty). A
    card the lab file has but no slot names goes in the first free slot (a
    slot past the board's when it is full: older labs)."""
    n = len(FORMS[form]["pcie"])
    words = str(node.vars.get("pcie") or "").split()
    from . import pcbuild
    out_of_case = pcbuild.build(node).nics_out if form == "tower" else set()
    nics = [i for i in range(len(node.nics)) if i not in _builtin_nics(node, form) and i not in out_of_case]
    want = (["gpu"] if node.vars.get("gpu") else []) + (["hba"] if has_hba(node) else []) + [f"nic{i}" for i in nics]
    out = [""] * max(n, len(words))
    seen = set()
    for k, w in enumerate(words):
        if w in want and w not in seen:
            out[k] = w
            seen.add(w)
    for w in want:
        if w in seen:
            continue
        lanes = lambda k: FORMS[form]["pcie"][k] if k < n else "x1"  # noqa: E731
        free = [k for k, v in enumerate(out) if not v and (lanes(k) == "x16") == (w == "gpu")]
        if not free:
            free = [k for k, v in enumerate(out) if not v]
        if free:
            out[free[0]] = w
        else:
            out.append(w)
        seen.add(w)
    while len(out) > n and not out[-1]:
        out.pop()
    return out


def _store_cards(node, out: list[str]) -> None:
    words = [w or "-" for w in out]
    while words and words[-1] == "-":
        words.pop()
    if words:
        node.vars["pcie"] = " ".join(words)
    else:
        node.vars.pop("pcie", None)


def _builtin_nics(node, form: str) -> set[int]:
    """A laptop's network adapters are built in (its Wi-Fi card and its
    wired port): no slot to pull them from."""
    if form == "laptop":
        return set(range(len(node.nics)))
    from . import wifi
    return set(wifi.wireless(node))


# ------------------------------------------------------------------ the board
def _drive_slots(node, form: str, pulled: set[int]) -> dict[str, dict]:
    """Where each drive sits: the system disk first, then each data disk by
    its bus, in bay order."""
    f = FORMS[form]
    bs = disks.asked_buses(node)
    real = disks.buses(node)
    slots: dict[str, dict] = {}
    for k in range(f["m2"]):
        slots[f"m2-{k}"] = {"type": "m2", "part": None}
    for k in range(f["bay35"]):
        slots[f"bay35-{k}"] = {"type": "bay35", "part": None}
    for k in range(f["bay25"]):
        slots[f"bay25-{k}"] = {"type": "bay25", "part": None}
    for k in range(f["hs"]):
        slots[f"hs-{k}"] = {"type": "hs", "part": None, "hot": True}
    sys_slot = "hs-0" if f["hs"] else "bay35-0" if f["bay35"] else "bay25-0"
    want = str(node.vars.get("sys_bay") or "")
    if want in slots and slots[want]["type"] in ("bay35", "bay25"):
        sys_slot = want
    gb = int(node.vars.get("disk_gb") or 0)
    from . import pcbuild
    if pcbuild.build(node).sys_in:   # an empty case's system drive lies on the tray until it is fitted
        slots[sys_slot]["part"] = {"kind": "disk", "system": True, "gb": gb, "bus": "virtio" if _virtio(node) else "sata",
                                   "title": f"system disk{' · ' + str(gb) + ' GB' if gb else ''}"}
    for i, gb in enumerate(node.data_disks_gb):
        key = _next_slot(slots, form, bs[i])
        slots[key]["part"] = {"kind": "disk", "index": i, "gb": gb, "bus": real[i], "pulled": i in pulled,
                              "title": f"{gb} GB {disks.TITLE[real[i]]} drive"}
    return slots


def _order(form: str, bus: str) -> list[str]:
    if bus == "nvme":
        return ["m2"]
    if FORMS[form]["hs"]:
        return ["hs"]
    return ["bay35", "bay25"] if bus == "sata" else ["bay25"]


def _next_slot(slots: dict, form: str, bus: str) -> str:
    """The first free bay a drive on this bus goes in (one past the board's
    when it is full, so an older lab with more drives still draws)."""
    kinds = _order(form, bus)
    for kind in kinds:
        for key, s in slots.items():
            if s["type"] == kind and s["part"] is None:
                return key
    kind = kinds[-1]
    k = sum(1 for s in slots.values() if s["type"] == kind)
    key = f"{kind}-{k}"
    slots[key] = {"type": kind, "part": None, "extra": True, "hot": kind == "hs"}
    return key


def board(lab, node) -> dict:
    """The machine open on the bench: every slot and what is in it, the
    tray of parts that fit it, and whether it is running."""
    form = form_of(node)
    if not form:
        return {"form": ""}
    f = FORMS[form]
    from . import bitlocker, power
    nd = paths.lab_dir(lab.name) / node.id
    running = _running(lab.name, node.id)
    pulled = hardware.pulled_in(nd, len(node.data_disks_gb))
    slots: dict[str, dict] = {"cpu": {"type": "cpu", "fixed": f["cpu_fixed"],
                                      "part": {"kind": "cpu", "cores": node.cpus, "title": _cpu_title(node.cpus)}}}
    from . import pcbuild
    ram = pcbuild.ram_type(node)
    for k, mb in enumerate(sticks(node, f["dimm"])):
        slots[f"dimm-{k}"] = {"type": "dimm", "part": {"kind": "dimm", "mb": mb, "title": _stick_title(mb, form, ram)} if mb else None}
    for k, w in enumerate(cards(node, form)):
        lanes = f["pcie"][k] if k < len(f["pcie"]) else "x1"
        part = None
        if w == "gpu":
            part = {"kind": "gpu", "title": "graphics card (virtio-vga)"}
        elif w == "hba":
            part = {"kind": "hba", "title": "SAS host bus adapter (LSI SAS1068)"}
        elif w.startswith("nic"):
            i = int(w[3:])
            nic = node.nics[i]
            part = {"kind": "nic", "nic": i, "network": nic.network or "", "title": f"{nic_title(node)} · port {i + 1}"}
        slots[f"pcie-{k}"] = {"type": "pcie", "lanes": lanes, "part": part, "extra": k >= len(f["pcie"])}
    slots.update(_drive_slots(node, form, pulled))
    for s in slots.values():  # the serial on a drive's label, as Windows and an inventory read it
        d = s.get("part") or {}
        if d.get("kind") == "disk" and "index" in d:
            sn = drive_serial(nd, node, d["index"])
            if sn:
                d["serial"] = sn
    if form != "laptop" and node.kind != LINUX:
        for k in range(f["odd"]):
            slots[f"odd-{k}"] = {"type": "odd", "part": {"kind": "dvd", "title": "DVD-RW drive (SATA)"}
                                 if k < mediashelf.drives(node) else None}
    if f["tpm"] and node.is_windows:
        slots["tpm"] = {"type": "tpm", "part": {"kind": "tpm", "title": "TPM 2.0 module"}
                        if bitlocker.tpm_fitted(nd, node) else None}
    if f["bmc"] and power.takes_port(node):
        slots["bmc"] = {"type": "bmc", "part": {"kind": "bmc", "title": "management module (BMC)"}
                        if power.fitted(node) else None}
    _build_slots(lab, node, form, slots)
    bench = [{"index": i, "gb": node.data_disks_gb[i], "bus": disks.buses(node)[i],
              "title": f"{node.data_disks_gb[i]} GB {disks.TITLE[disks.buses(node)[i]]} drive from bay {i + 1}"}
             for i in sorted(pulled)]
    from . import identity
    return {"form": form, "running": running, "virtio": _virtio(node), "slots": slots,
            "identity": identity.of(lab.name, node),
            "host": _host(), "warnings": warnings(node),
            "tray": tray(node, form, slots), "bench": bench,
            "lands": {bus: _lands(node, form, slots, bus) for bus in disks.BUSES},
            **_build_view(lab, node, form, slots)}


def drive_serial(nd, node, index: int) -> str:
    """The serial number winlab gives a data drive ('' for a drive winlab
    made before drives had their own, which keeps QEMU's)."""
    if _virtio(node):
        return ""
    gen = disks.generation(nd, index)
    if gen or disks.buses(node)[index] == "nvme":
        return disks.serial(node.id, index, gen)
    return ""


def _lands(node, form: str, slots: dict, bus: str) -> str:
    """The bay a new drive on this bus goes in, or '' when none takes it."""
    if form == "laptop" and bus != "nvme":
        return ""
    if bus == "sas" and form == "tower" and not FORMS[form]["bay25"]:
        return ""
    copy = {k: dict(v) for k, v in slots.items()}
    key = _next_slot(copy, form, bus)
    return "" if copy[key].get("extra") else key


def tray(node, form: str, slots: dict | None = None) -> list[dict]:
    """The parts on the tray beside the machine, each with the slot type it
    fits and what it is."""
    from . import bitlocker, power
    slots = slots or {}
    out = []
    if not FORMS[form]["cpu_fixed"]:
        for c in CORES:
            out.append({"id": f"cpu:{c}", "kind": "cpu", "fits": "cpu", "cores": c, "group": "Processors",
                        "title": _cpu_title(c),
                        "text": f"{c} core{'s' if c > 1 else ''} for the machine (QEMU -smp {c}). Drop it on the "
                                "socket: the processor in it comes out."})
    from . import pcbuild
    ram = pcbuild.ram_type(node)
    for mb in STICKS_MB:
        out.append({"id": f"dimm:{mb}", "kind": "dimm", "fits": "dimm", "mb": mb, "group": "Memory",
                    "title": _stick_title(mb, form, ram),
                    "text": "A memory stick for a free slot. The sticks add up to the machine's memory."})
    for bus in disks.BUSES:
        if form == "laptop" and bus != "nvme":
            continue
        what = {"sata": "3.5-inch SATA hard drive" if form == "tower" else "2.5-inch SATA drive",
                "sas": "2.5-inch SAS drive (needs the SAS host bus adapter)",
                "nvme": "M.2 NVMe SSD"}[bus]
        for gb in DRIVE_GB:
            out.append({"id": f"disk:{bus}:{gb}", "kind": "disk", "bus": bus, "gb": gb, "group": "Drives",
                        "fits": {"nvme": "m2", "sata": "drive", "sas": "drive"}[bus],
                        "title": f"{gb} GB {disks.TITLE[bus]}",
                        "text": f"A new blank {what}. Windows finds it offline and not initialised: bring it "
                                "online in Disk Management."})
    if FORMS[form]["pcie"]:
        out.append({"id": "nic", "kind": "nic", "fits": "pcie", "group": "Expansion cards", "title": nic_title(node),
                    "text": "One gigabit Ethernet port on a PCIe card. Windows has its driver; cable its port to "
                            "a switch from the back of the machine."})
        out.append({"id": "gpu", "kind": "gpu", "fits": "pcie-x16", "group": "Expansion cards",
                    "fitted": bool(node.vars.get("gpu")),
                    "title": "graphics card (virtio-vga)",
                    "text": "A display card for the x16 slot: more screen resolutions. Windows shows it as Microsoft "
                            "Basic Display Adapter until you install its driver (Red Hat VirtIO GPU DOD) from a "
                            "driver stick. Without it the board's own VGA drives the screen."})
        out.append({"id": "hba", "kind": "hba", "fits": "pcie", "group": "Expansion cards", "fitted": has_hba(node),
                    "title": "SAS host bus adapter (LSI SAS1068)",
                    "text": "The controller SAS drives hang on. Windows drives it with its own lsi_sas driver."})
    if form != "laptop" and node.kind != LINUX:
        out.append({"id": "dvd", "kind": "dvd", "fits": "odd", "group": "Other", "title": "DVD-RW drive (SATA)",
                    "text": "An optical drive for a 5.25-inch bay. Discs from the media shelf go in it."})
    if node.is_windows:
        ok = bitlocker.tpm_available()
        out.append({"id": "tpm", "kind": "tpm", "fits": "tpm", "group": "Other", "title": "TPM 2.0 module",
                    "text": "The security chip on the board's TPM header: BitLocker keeps its keys in it, Windows 11 "
                            "needs one." + ("" if ok else " This PC cannot emulate one (swtpm is missing)."),
                    "unavailable": not ok, "fitted": bool((slots.get("tpm") or {}).get("part"))})
    if FORMS[form]["bmc"] and power.takes_port(node):
        out.append({"id": "bmc", "kind": "bmc", "fits": "bmc", "group": "Other", "title": "management module (BMC)",
                    "fitted": power.fitted(node),
                    "text": "The server's baseboard management controller (iLO, iDRAC): its own network port, to "
                            "power the server on, off or reset it from another machine. Its user and password "
                            "are on the toe tag."})
    return out + _build_tray(node, form, slots)


# ------------------------------------------------------------------ the parts around them (pcbuild.py)
# The board, the power supply and its cables, the cooler and the fans, the
# CMOS battery; a laptop's battery, charger and Wi-Fi card.
BOARD_SLOTS = ("cpu", "dimm-", "pcie-", "m2-", "tpm", "cmos", "cooler")


def _build_slots(lab, node, form: str, slots: dict) -> None:
    from . import pcbuild
    b = pcbuild.build(node)
    info = b.board_info()
    if form == "tower":
        if not b.board:
            for k in [k for k in slots if k.startswith(BOARD_SLOTS)]:
                del slots[k]
            slots["board"] = {"type": "board", "part": None}
        else:
            slots["board"] = {"type": "board", "part": {"kind": "board", "board": b.board, "title": info.get("title", "")}}
            if not b.cpu:
                slots["cpu"]["part"] = None
            else:
                slots["cpu"]["part"]["socket"] = b.socket
                slots["cpu"]["part"]["igpu"] = b.igpu
                slots["cpu"]["part"]["title"] = _cpu_title(node.cpus, b.cpu)
            slots["cooler"] = {"type": "cooler", "part": {"kind": "cooler", "title": "tower cooler (heatsink and 120 mm fan)"}
                               if b.cooler else None}
            slots["cmos"] = {"type": "cmos", "part": {"kind": "cmos", "title": "CMOS battery (CR2032 coin cell)"}
                             if b.cmos else None}
        slots["psu"] = {"type": "psu", "part": {"kind": "psu", "watts": b.psu, "title": f"{b.psu} W ATX power supply"}
                        if b.psu else None}
        for k, f in enumerate(b.fans):
            slots[f"fan-{k}"] = {"type": "fan", "part": {"kind": "fan", "title": "120 mm case fan"} if f else None,
                                 "where": "front"}
    elif form == "server":
        slots["cmos"] = {"type": "cmos", "part": {"kind": "cmos", "title": "CMOS battery (CR2032 coin cell)"}
                         if b.cmos else None}
    else:
        slots["wifi"] = {"type": "wifi", "part": {"kind": "wifi", "title": "Wi-Fi card (M.2 2230)"} if b.wifi else None}
        slots["battery"] = {"type": "battery", "part": {"kind": "battery", "title": "battery (4 cells, 56 Wh)"}
                            if b.battery else None}
        slots["cmos"] = {"type": "cmos", "part": {"kind": "cmos", "title": "CMOS battery (coin cell on a lead)"}
                         if b.cmos else None}


def cables(node, form: str, slots: dict) -> list[dict]:
    """The cables inside a tower, each plugged in or not: the board's 24-pin
    and the processor's 8-pin from the supply, the graphics card's power,
    and each SATA drive's power and data."""
    from . import pcbuild
    if form == "laptop":
        b = pcbuild.build(node)
        return [{"id": "ac", "title": "charger (65 W, USB-C)", "plugged": b.ac, "kind": "ac"}]
    if form != "tower":
        return []
    b = pcbuild.build(node)
    out = []
    if b.psu and b.board:
        out.append({"id": "atx24", "title": "24-pin main power (supply to board)", "kind": "power",
                    "plugged": "atx24" not in b.unplugged})
        out.append({"id": "eps", "title": "8-pin CPU power (supply to board)", "kind": "power",
                    "plugged": "eps" not in b.unplugged})
    gpu = any(((s.get("part") or {}).get("kind") == "gpu") for s in slots.values())
    if gpu and b.psu:
        out.append({"id": "gpu", "title": "PCIe 8-pin power (supply to graphics card)", "kind": "power",
                    "plugged": "gpu" not in b.unplugged})
    for key, s in slots.items():
        p = s.get("part") or {}
        if p.get("kind") != "disk" or p.get("pulled") or s["type"] not in ("bay35", "bay25"):
            continue
        if not p.get("system") and p.get("bus") != "sata":
            continue
        d = "sys" if p.get("system") else str(p["index"])
        name = "the system disk" if p.get("system") else f"the {p['gb']} GB drive"
        if b.psu:
            out.append({"id": f"sata-pwr:{d}", "title": f"SATA power to {name}", "kind": "power", "slot": key,
                        "plugged": f"sata-pwr:{d}" not in b.unplugged})
        if b.board:
            out.append({"id": f"sata-data:{d}", "title": f"SATA data from the board to {name}", "kind": "data", "slot": key,
                        "plugged": f"sata-data:{d}" not in b.unplugged})
    return out


def _build_view(lab, node, form: str, slots: dict) -> dict:
    from . import pcbuild
    b = pcbuild.build(node)
    w = pcbuild.draw(node, b)
    rec = pcbuild.last(lab.name, node.id) or {}
    info = b.board_info()
    return {"cables": cables(node, form, slots),
            "build": {"kit": b.kit, "board": b.board, "socket": info.get("socket", ""), "ram": info.get("ram", ""),
                      "cpu": b.cpu, "igpu": b.igpu, "psu": b.psu, "draw": w, "advice": pcbuild.advice(w) if w else 0,
                      "over": bool(form == "tower" and b.psu and w > b.psu)},
            "stuck": bool(rec.get("stuck")),
            # A dead fan is seen standing still while the machine runs.
            "fan_stopped": bool(_running(lab.name, node.id) and pcbuild.faults(lab.name, node.id).get("fan")),
            "post": ({**{k: rec.get(k) for k in ("stage", "led", "power", "at", "tripped", "halt")},
                      "beeps": pcbuild._pt(rec["beeps"]) if rec.get("beeps") else ""} if rec else None)}


def _cpu_title(cores: int, kind: str = "") -> str:
    if not kind or kind == "bga":
        return f"{cores}-core processor"
    sock, _, f = kind.partition("-")
    return f"{cores}-core processor · {sock.upper()}" + (" · no graphics" if f else "")


def _stick_title(mb: int, form: str, ram: str = "ddr4") -> str:
    size = f"{mb // 1024} GB" if mb % 1024 == 0 else f"{mb} MB"
    r = ram.upper()
    return {"server": f"{size} {r} registered ECC", "laptop": f"{size} {r} SO-DIMM"}.get(form, f"{size} {r}")


def _build_tray(node, form: str, slots: dict) -> list[dict]:
    from . import pcbuild
    b = pcbuild.build(node)
    info = b.board_info()
    out = []
    if form == "tower":
        sock = info.get("socket", "lga") if b.board else "lga"
        other = "pga" if sock == "lga" else "lga"
        for c in (6, 8, 12):
            out.append({"id": f"cpu:{c}:{sock}-f", "kind": "cpu", "fits": "cpu", "cores": c, "group": "Processors without graphics",
                        "title": _cpu_title(c, f"{sock}-f"),
                        "text": f"{c} cores for the {sock.upper()} socket, with no graphics built in: the board's own "
                                "video outputs stay dark, so the PC needs a graphics card."})
        for c in (6, 8):
            out.append({"id": f"cpu:{c}:{other}", "kind": "cpu", "fits": "cpu", "cores": c, "group": "Processors for another socket",
                        "title": _cpu_title(c, other), "wrong": True,
                        "text": f"Made for the {pcbuild.SOCKET_TITLE[other]}. It does not fit this board's "
                                f"{pcbuild.SOCKET_TITLE[sock]}."})
        ram = info.get("ram", "ddr4")
        wrong = "ddr5" if ram == "ddr4" else "ddr4"
        for mb in (8192, 16384):
            out.append({"id": f"dimm:{mb}:{wrong}", "kind": "dimm", "fits": "dimm", "mb": mb, "group": "Memory of another type",
                        "title": _stick_title(mb, form, wrong), "wrong": True,
                        "text": f"{wrong.upper()}: its notch is in another place, so it does not go into this board's "
                                f"{ram.upper()} slots."})
        for bid, bi in pcbuild.BOARDS.items():
            out.append({"id": f"board:{bid}", "kind": "board", "fits": "board", "group": "Boards", "title": bi["title"],
                        "fitted": b.board == bid, "wrong": bi["size"] != "atx",
                        "text": ("An ATX board for this mid-tower case: its standoffs line up. " if bi["size"] == "atx" else
                                 "An E-ATX board is wider than this mid-tower case takes: its holes miss the standoffs. ")
                                + f"Socket {bi['socket'].upper()}, {bi['ram'].upper()} memory, its own video outputs (they need a "
                                  "processor with graphics), an M.2 socket, SATA ports and a CMOS battery. Its manual: two "
                                  "sticks go in DIMM2 and DIMM4 (dual channel)."})
        for w in pcbuild.PSU_W:
            out.append({"id": f"psu:{w}", "kind": "psu", "fits": "psu", "watts": w, "group": "Power supplies",
                        "title": f"{w} W ATX power supply",
                        "text": f"Gives the parts up to {w} W. Add up what they draw and leave about a quarter spare. "
                                "It comes with its cables unplugged: plug the 24-pin, the CPU's 8-pin and the drives' "
                                "SATA power in yourself."})
        out.append({"id": "cooler", "kind": "cooler", "fits": "cooler", "group": "Cooling", "fitted": b.cooler,
                    "title": "tower cooler (heatsink and 120 mm fan)",
                    "text": "Thermal paste on the processor, the heatsink on top, its fan's lead on the board's CPU_FAN "
                            "header. Without it the processor overheats within a minute and the PC switches off."})
        out.append({"id": "fan", "kind": "fan", "fits": "fan", "group": "Cooling", "title": "120 mm case fan",
                    "text": "The front fans pull cool air in over the drives and the cards; the supply's own fan and the "
                            "open back let the warm air out. Each plugs into a SYS_FAN header."})
        out.append({"id": "cmos", "kind": "cmos", "fits": "cmos", "group": "Other",
                    "title": "CMOS battery (CR2032 coin cell)", "fitted": b.cmos,
                    "text": "Keeps the board's clock running and its settings while the PC is unplugged. Flat, the "
                            "clock starts at the firmware's default date at every power-on."})
        if not b.sys_in:
            gb = int(node.vars.get("disk_gb") or 0)
            out.append({"id": "sysdisk", "kind": "disk", "bus": "sata", "fits": "sysdisk", "group": "Drives",
                        "title": "the system drive (2.5-inch SATA SSD" + (f", {gb} GB" if gb else "") + ", Windows on it)",
                        "text": "The drive this PC boots from. It goes in a drive bay and needs a SATA power and a SATA "
                                "data cable."})
        for i in sorted(b.nics_out):
            if i < len(node.nics):
                out.append({"id": f"nic:{i}", "kind": "nic", "fits": "pcie", "group": "Expansion cards",
                            "title": f"{nic_title(node)} · port {i + 1} (this PC's)", "nic": i,
                            "text": "This PC's own network card, out of the case: fit it in a PCIe slot and its port "
                                    "keeps its cable and its address."})
    elif form == "laptop":
        out.append({"id": "dimm:8192:dimm", "kind": "dimm", "fits": "dimm", "mb": 8192, "group": "Memory of another type",
                    "title": "8 GB DDR4 (desktop DIMM)", "wrong": True,
                    "text": "A desktop stick (DIMM) is longer than a laptop's SO-DIMM slot."})
        out.append({"id": "battery", "kind": "battery", "fits": "battery", "group": "Other", "fitted": b.battery,
                    "title": "battery (4 cells, 56 Wh)",
                    "text": "Unplug the charger and disconnect the old battery's lead before you lift it out. With "
                            "no battery the laptop runs only on its charger."})
        out.append({"id": "wifi", "kind": "wifi", "fits": "wifi", "group": "Other", "fitted": b.wifi,
                    "title": "Wi-Fi card (M.2 2230)",
                    "text": "The laptop's wireless card: an M.2 2230 card with two antenna leads (main and aux) that "
                            "snap onto it. Without it Windows has no Wi-Fi adapter."})
        out.append({"id": "cmos", "kind": "cmos", "fits": "cmos", "group": "Other", "fitted": b.cmos,
                    "title": "CMOS battery (coin cell on a lead)",
                    "text": "Keeps the clock and the firmware settings. Flat, the clock resets at every power-on."})
    else:
        out.append({"id": "cmos", "kind": "cmos", "fits": "cmos", "group": "Other", "fitted": b.cmos,
                    "title": "CMOS battery (CR2032 coin cell)",
                    "text": "Keeps the clock and the firmware settings. Flat, the clock resets at every power-on."})
    return out


def _fit_build(lab, node, form: str, kind: str, rest: str, slot: str, s: dict, name: str) -> str | None:
    """Fits a part around the processor and the memory; None when the part
    is not one of these."""
    from . import pcbuild
    b = pcbuild.build(node)
    if kind == "board":
        if s["type"] != "board":
            raise PartsError("a board goes on the case's standoffs")
        bi = pcbuild.BOARDS.get(rest)
        if bi is None:
            raise PartsError(f"no board {rest!r} on the tray")
        if b.board:
            raise PartsError("the case has a board: take it out first")
        if bi["size"] != "atx":
            raise PartsError("an E-ATX board is too wide for this mid-tower case: its holes do not meet the standoffs")
        b.board = rest
        b.cpu = ""
        b.cmos = True
        pcbuild.save(node, b)
        node.vars["dimms"] = " ".join("0" for _ in range(FORMS[form]["dimm"]))
        return f"the {bi['title']} is screwed to the standoffs of {name}, its I/O shield in the back"
    if kind == "psu":
        if s["type"] != "psu":
            raise PartsError("the power supply goes in its bay at the bottom of the case")
        if b.psu:
            raise PartsError("a power supply is fitted: take it out first")
        b.psu = int(rest)
        if b.psu not in pcbuild.PSU_W:
            raise PartsError(f"no {rest} W supply on the tray")
        b.unplugged |= {c["id"] for c in _power_cables(node, form)}
        pcbuild.save(node, b)
        pcbuild.clear_fault(lab.name, node.id, "psu")
        need = pcbuild.draw(node, b)
        return (f"a {b.psu} W power supply in {name}, its cables unplugged: plug them in. The parts draw about "
                f"{need} W" + (f": more than it gives, so the PC will not start" if need > b.psu else ""))
    if kind == "cooler":
        if s["type"] != "cooler":
            raise PartsError("the cooler goes on the processor")
        if not b.cpu:
            raise PartsError("fit the processor first: the cooler sits on it")
        b.cooler = True
        pcbuild.save(node, b)
        pcbuild.clear_fault(lab.name, node.id, "fan")
        return f"thermal paste on the processor, the cooler on top and its fan on CPU_FAN: {name} is cooled"
    if kind == "fan":
        if s["type"] != "fan":
            raise PartsError("a case fan goes in a fan mount")
        if s.get("part"):
            raise PartsError("that fan mount has a fan")
        k = int(slot.split("-")[1])
        b.fans[k] = True
        pcbuild.save(node, b)
        return f"a 120 mm fan at the {s.get('where', 'front')} of {name}, on its SYS_FAN header"
    if kind == "cmos":
        if s["type"] != "cmos":
            raise PartsError("the coin cell goes in the battery holder on the board")
        b.cmos = True
        pcbuild.save(node, b)
        pcbuild.clear_fault(lab.name, node.id, "cmos")
        return f"a new CMOS battery in {name}: set the date and time (the firmware starts from its default once)"
    if kind == "sysdisk":
        if s["type"] not in ("bay35", "bay25"):
            raise PartsError("the system drive goes in a drive bay")
        if s.get("part"):
            raise PartsError("that bay is taken")
        if b.sys_in:
            raise PartsError("the system drive is in already")
        b.sys_in = True
        if b.kit:
            b.unplugged |= {"sata-pwr:sys", "sata-data:sys"}
        pcbuild.save(node, b)
        node.vars["sys_bay"] = slot
        return f"the system drive in {_slot_title(slot)} of {name}" + (": plug in its SATA power and data" if b.kit else "")
    if kind == "battery":
        if s["type"] != "battery":
            raise PartsError("the battery goes in its bay under the palm rest")
        b.battery = True
        pcbuild.save(node, b)
        return f"a new battery in {name}, its lead on the board"
    if kind == "wifi":
        if s["type"] != "wifi":
            raise PartsError("the Wi-Fi card goes in its M.2 2230 slot")
        b.wifi = True
        pcbuild.save(node, b)
        return f"the Wi-Fi card in {name}: snap the two antenna leads onto it (main on 1, aux on 2)"
    return None


def _power_cables(node, form: str) -> list[dict]:
    """Every power cable the supply has in this machine (out with it)."""
    from . import pcbuild
    b = pcbuild.build(node)
    out = [{"id": "atx24"}, {"id": "eps"}, {"id": "gpu"}]
    for d in pcbuild._drive_cables(node, b):
        out.append({"id": f"sata-pwr:{d}"})
    return out


def _out_build(lab, node, form: str, slot: str, s: dict, p: dict, name: str) -> str | None:
    from . import pcbuild
    b = pcbuild.build(node)
    kind = p["kind"]
    if kind == "board":
        busy = [k for k, v in (board(lab, node)["slots"]).items()
                if k.startswith(("cpu", "dimm-", "pcie-", "m2-")) and v.get("part")]
        if busy:
            raise PartsError("take what is on the board out first: " + ", ".join(sorted({k.split('-')[0] for k in busy})))
        b.board = ""
        b.cpu = ""
        b.cooler = False
        b.unplugged |= {"atx24", "eps"} | {f"sata-data:{d}" for d in pcbuild._drive_cables(node, b)}
        pcbuild.save(node, b)
        return f"the board is out of {name}"
    if kind == "psu":
        b.psu = 0
        b.unplugged |= {c["id"] for c in _power_cables(node, form)}
        pcbuild.save(node, b)
        pcbuild.clear_fault(lab.name, node.id, "psu")
        return f"the power supply is out of {name}, every power cable unplugged from the parts"
    if kind == "cooler":
        b.cooler = False
        pcbuild.save(node, b)
        pcbuild.clear_fault(lab.name, node.id, "fan")
        return f"the cooler is off {name}'s processor (clean the old paste off before a cooler goes back on)"
    if kind == "fan":
        k = int(slot.split("-")[1])
        b.fans[k] = False
        pcbuild.save(node, b)
        return f"the {s.get('where', 'front')} fan is out of {name}"
    if kind == "cmos":
        b.cmos = False
        pcbuild.save(node, b)
        pcbuild.clear_fault(lab.name, node.id, "cmos")
        return f"the CMOS battery is out of {name}: the clock and the firmware settings are lost"
    if kind == "cpu":
        if form != "tower":
            raise PartsError("a machine needs its processor: drop another one on the socket to swap it")
        if b.cooler:
            raise PartsError("take the cooler off first: it sits on the processor")
        b.cpu = ""
        pcbuild.save(node, b)
        return f"the processor is out of {name}'s socket (lift it straight up by its edges)"
    if kind == "battery":
        b.battery = False
        pcbuild.save(node, b)
        return f"the battery is out of {name}" + (": it runs only on its charger now" if b.ac else "")
    if kind == "wifi":
        b.wifi = False
        pcbuild.save(node, b)
        return f"the Wi-Fi card is out of {name} (unclip the antenna leads first)"
    if kind == "disk" and p.get("system"):
        if form != "tower":
            raise PartsError("the system disk stays in: replace it from the drive's menu (a dead system disk)")
        b.sys_in = False
        b.unplugged |= {"sata-pwr:sys", "sata-data:sys"}
        pcbuild.save(node, b)
        node.vars.pop("sys_bay", None)
        return f"the system drive is out of {name}, its data on it"
    return None


def reseat(lab, node, slot: str) -> str:
    """Press a part back into its slot: what was loose holds again."""
    from . import pcbuild
    b = board(lab, node)
    s = _slot(b, slot)
    p = s.get("part")
    name = naming.display(lab, node.id)
    if not p:
        raise PartsError("that slot is empty")
    _need_off(lab, node, "reseat a part")
    fx = pcbuild.faults(lab.name, node.id)
    what = p.get("title", "part")
    if p["kind"] == "dimm":
        k = int(slot.split("-")[1])
        loose = [x for x in str(fx.get("ram-loose", "")).split() if x != str(k)]
        if loose:
            pcbuild.set_fault(lab.name, node.id, "ram-loose", " ".join(loose))
        else:
            pcbuild.clear_fault(lab.name, node.id, "ram-loose")
        return f"the {what} stick in slot {k + 1} of {name} is out and back in, both latches clicked shut"
    if p["kind"] in ("nic", "gpu", "hba"):
        card = "gpu" if p["kind"] == "gpu" else "hba" if p["kind"] == "hba" else f"nic{p['nic']}"
        if fx.get("card") == card:
            pcbuild.clear_fault(lab.name, node.id, "card")
        return f"the {what} is pressed firmly back into its slot and screwed to the bracket"
    return f"the {what} is out and back in"


def plug(lab, node, cable: str, on: bool) -> str:
    """Plug a cable in, or pull it out. Pulling a loose cable and plugging it
    back in seats it."""
    from . import pcbuild
    form = form_of(node)
    name = naming.display(lab, node.id)
    b = pcbuild.build(node)
    if form == "laptop" and cable == "ac":
        b.ac = bool(on)
        pcbuild.save(node, b)
        if not on and not b.battery and _running(lab.name, node.id):
            _power_cut(lab.name, node.id)   # no battery to carry it: it goes dark at once
            return f"the charger is unplugged from {name}: with no battery it went dark at once"
        return f"the charger is {'plugged into' if on else 'unplugged from'} {name}"
    _need_off(lab, node, "plug or unplug a cable inside it")
    bd = board(lab, node)
    known = {c["id"]: c for c in bd.get("cables", [])}
    if cable not in known:
        raise PartsError(f"there is no cable {cable!r} in {name}")
    if on:
        b.unplugged.discard(cable)
    else:
        b.unplugged.add(cable)
        if pcbuild.faults(lab.name, node.id).get("cable") == cable:
            pcbuild.clear_fault(lab.name, node.id, "cable")
    pcbuild.save(node, b)
    return f"the {known[cable]['title']} is {'plugged in' if on else 'unplugged'}"


def _power_cut(lab_name: str, node_id: str) -> None:
    """The machine loses its power at once (QMP quit): no shutdown."""
    from .media import _qmp_port
    from .qmp import QmpError
    port = _qmp_port(lab_name, node_id)
    if not port:
        return
    try:
        with _qmp(port) as mon:
            mon.call("quit")
    except (QmpError, OSError):
        pass


# ------------------------------------------------------------------ changes
def _need_off(lab, node, what: str) -> None:
    if _running(lab.name, node.id):
        raise PartsError(f"shut {naming.display(lab, node.id)} down before you {what}")
    from . import pcbuild
    if pcbuild.stuck(lab.name, node.id):
        raise PartsError(f"{naming.display(lab, node.id)} is still switched on (its fans spin): hold its power "
                         f"button to switch it off before you {what}")


def _slot(b: dict, slot: str) -> dict:
    s = b["slots"].get(slot)
    if s is None:
        raise PartsError(f"there is no slot {slot!r} in this machine")
    return s


def fit(lab, node, part: str, slot: str) -> str:
    """Fit a part from the tray into a slot (swapping what is in it, for a
    processor or a memory stick). The machine is off. A part that takes the
    machine past what this PC has is fitted, with a warning."""
    msg = _fit(lab, node, part, slot)
    kind = part.partition(":")[0]
    new = [w["text"] for w in warnings(node) if w["part"] == kind]
    return msg + (". Note: " + new[0] if new else "")


def _fit(lab, node, part: str, slot: str) -> str:
    from . import editor
    b = board(lab, node)
    if not b["form"]:
        raise PartsError("this device has no case to open")
    form = b["form"]
    s = _slot(b, slot)
    kind, _, rest = part.partition(":")
    name = naming.display(lab, node.id)
    _need_off(lab, node, "fit a part")
    if s.get("fixed"):
        raise PartsError("that part is soldered to the board")
    done = _fit_build(lab, node, form, kind, rest, slot, s, name)
    if done is not None:
        return done
    if kind == "cpu":
        if s["type"] != "cpu":
            raise PartsError("a processor goes in the socket")
        from . import pcbuild
        cores_s, _, variant = rest.partition(":")
        cores = int(cores_s)
        if cores not in CORES:
            raise PartsError(f"no {cores}-core processor on the tray")
        bld = pcbuild.build(node)
        if form == "tower":
            sock = bld.board_info().get("socket", "lga")
            variant = variant or sock
            if variant.split("-")[0] != sock:
                raise PartsError(f"that processor is made for the {pcbuild.SOCKET_TITLE[variant.split('-')[0]]}: it "
                                 f"does not fit this board's {pcbuild.SOCKET_TITLE[sock]}")
            was = bld.cpu
            bld.cpu = variant
            pcbuild.save(node, bld)
            node.cpus = cores
            return (f"a {_cpu_title(cores, variant)} in {name}'s socket"
                    + (" (the cooler came off and went back on with fresh paste)" if was and bld.cooler else "")
                    + ("" if bld.cooler else ": it needs its cooler before the PC starts"))
        node.cpus = cores
        return f"a {cores}-core processor in {name}'s socket"
    if kind == "dimm":
        if s["type"] != "dimm":
            raise PartsError("a memory stick goes in a memory slot")
        mb_s, _, typ = rest.partition(":")
        from . import pcbuild
        ram = pcbuild.ram_type(node)
        if typ == "dimm":
            raise PartsError("a desktop DIMM is longer than the laptop's SO-DIMM slot: it does not go in")
        if typ and typ != ram:
            raise PartsError(f"a {typ.upper()} stick does not go into a {ram.upper()} slot: the notch is in another place")
        mb = int(mb_s)
        got = sticks(node, FORMS[form]["dimm"])
        k = int(slot.split("-")[1])
        new = list(got)
        new[k] = mb
        _check_memory(node, sum(new))
        old = got[k]
        _store_sticks(node, new)
        _stick_gone(lab, node, k)
        return (f"a {_stick_title(mb, form)} stick in slot {k + 1} of {name}" + (f" (the {_stick_title(old, form)} came out)" if old else "")
                + f": {_mb(node.memory_mb)} in all")
    if s["part"] is not None:
        raise PartsError("that slot is taken: take the part in it out first")
    if kind == "disk":
        bus, _, gb = rest.partition(":")
        if bus not in disks.BUSES:
            raise PartsError(f"no {bus} drive on the tray")
        want = b["lands"].get(bus, "")
        if not want:
            raise PartsError({"nvme": "every M.2 socket is taken", "sas": "this machine has no bay for a SAS drive"}
                             .get(bus, "every bay for that drive is taken"))
        if bus == "sas" and not has_hba(node):
            raise PartsError("a SAS drive needs the SAS host bus adapter: fit one in a PCIe slot first")
        if slot != want:
            where = {"m2": "M.2 socket", "hs": "bay", "bay35": "bay", "bay25": "bay"}[s["type"]]
            raise PartsError(f"that drive goes in the next free {where} ({_slot_title(want)})")
        i = disks.add(lab, node, int(gb), bus)
        return (f"a new blank {gb} GB {disks.TITLE[disks.buses(node)[i]]} drive in {_slot_title(slot)} of {name}"
                + (": Windows finds it offline and not initialised" if node.is_windows else ", blank"))
    if kind in ("nic", "gpu", "hba"):
        if s["type"] != "pcie":
            raise PartsError("an expansion card goes in a PCIe slot")
        if kind == "gpu" and s.get("lanes") != "x16":
            raise PartsError("the graphics card needs an x16 slot")
        cs = cards(node, form)
        k = int(slot.split("-")[1])
        if kind == "gpu":
            if node.vars.get("gpu"):
                raise PartsError(f"{name} already has a graphics card")
            node.vars["gpu"] = True
            cs[k] = "gpu"
        elif kind == "hba":
            if has_hba(node):
                raise PartsError(f"{name} already has a SAS host bus adapter")
            cs[k] = "hba"
        elif rest:
            from . import pcbuild
            bld = pcbuild.build(node)
            i = int(rest)
            if i not in bld.nics_out:
                raise PartsError("that network card is in the machine already")
            bld.nics_out.discard(i)
            pcbuild.save(node, bld)
            cs[k] = f"nic{i}"
        else:
            if len(node.nics) >= MAX_NICS:
                raise PartsError(f"a machine takes at most {MAX_NICS} network cards")
            editor.set_node(lab, node.id, add_nic="-" if lab.workbench else
                            (node.nics[0].network if node.nics else ""))
            cs[k] = f"nic{len(node.nics) - 1}"
        _store_cards(node, cs)
        return f"{_part_title(kind, node)} in PCIe slot {k + 1} ({s.get('lanes')}) of {name}"
    if kind == "dvd":
        if s["type"] != "odd":
            raise PartsError("a DVD drive goes in a 5.25-inch bay")
        node.vars["dvd_drives"] = mediashelf.drives(node) + 1
        return f"a DVD drive in {name}: {node.vars['dvd_drives']} in all"
    if kind == "tpm":
        if s["type"] != "tpm":
            raise PartsError("the TPM module goes on its header")
        from . import bitlocker
        try:
            bitlocker.fit_tpm(lab.name, node, True)
        except bitlocker.BitLockerError as exc:
            raise PartsError(str(exc)) from None
        return f"a TPM 2.0 module on {name}'s board: Windows finds it in tpm.msc"
    if kind == "bmc":
        if s["type"] != "bmc":
            raise PartsError("the management module goes in its own slot")
        from . import power
        try:
            return power.fit(lab, node.id)
        except power.PowerError as exc:
            raise PartsError(str(exc)) from None
    raise PartsError(f"no {part!r} on the tray")


def take_out(lab, node, slot: str) -> str:
    """Take the part in a slot out. A drive comes out onto the bench, with
    its data (live from a hot-swap bay); every other part with the machine
    off."""
    from . import editor
    b = board(lab, node)
    if not b["form"]:
        raise PartsError("this device has no case to open")
    form = b["form"]
    s = _slot(b, slot)
    p = s["part"]
    name = naming.display(lab, node.id)
    if p is None:
        raise PartsError("that slot is empty")
    if s.get("fixed"):
        raise PartsError("that part is soldered to the board")
    if p["kind"] == "disk":
        if p.get("system"):
            _need_off(lab, node, "take the system drive out")
            done = _out_build(lab, node, form, slot, s, p, name)
            if done is not None:
                return done
        if p.get("pulled"):
            raise PartsError("that bay is already empty")
        if not s.get("hot"):
            _need_off(lab, node, "take a drive out (only a hot-swap bay's drive comes out while it runs)")
        live = hardware.pull(lab.name, node, p["index"], qmp=_qmp)
        return (f"the {p['title']} is out of {_slot_title(slot)} of {name}"
                + (": it stops answering at once" if live else "") + "; it lies on the bench with its data")
    _need_off(lab, node, "take a part out")
    done = _out_build(lab, node, form, slot, s, p, name)
    if done is not None:
        return done
    if p["kind"] == "dimm":
        got = sticks(node, FORMS[form]["dimm"])
        k = int(slot.split("-")[1])
        if sum(1 for x in got if x) <= 1 and form != "tower":
            raise PartsError("a machine needs at least one memory stick")
        new = list(got)
        new[k] = 0
        if any(new):
            _check_memory(node, sum(new))
        _store_sticks(node, new)
        _stick_gone(lab, node, k)
        return (f"the {p['title']} stick is out of slot {k + 1} of {name}: "
                + (f"{_mb(node.memory_mb)} left" if any(new) else "no memory left: it will not POST"))
    if p["kind"] in ("nic", "gpu", "hba"):
        cs = cards(node, form)
        k = int(slot.split("-")[1])
        if p["kind"] == "gpu":
            node.vars.pop("gpu", None)
        elif p["kind"] == "hba":
            if "sas" in disks.asked_buses(node):
                raise PartsError("SAS drives hang on the adapter: take them out first")
        else:
            i = p["nic"]
            editor.set_node(lab, node.id, rm_nic=str(i))
            from . import wifi
            ws = wifi.wireless(node)
            if ws:
                node.vars["wireless"] = " ".join(str(c - 1 if c > i else c) for c in ws)
            cs = [(f"nic{int(w[3:]) - 1}" if w.startswith("nic") and int(w[3:]) > i else w) for w in cs]
        cs[k] = ""
        _store_cards(node, cs)
        from . import pcbuild
        card = p["kind"] if p["kind"] != "nic" else f"nic{p['nic']}"
        if pcbuild.faults(lab.name, node.id).get("card") == card:
            pcbuild.clear_fault(lab.name, node.id, "card")
        return f"the {p['title']} is out of PCIe slot {k + 1} of {name}"
    if p["kind"] == "dvd":
        n = mediashelf.drives(node)
        if n <= 1:
            raise PartsError("a Windows machine keeps one DVD drive (its installer and the media shelf's discs go in it)")
        node.vars["dvd_drives"] = n - 1
        return f"a DVD drive out of {name}: {n - 1} left"
    if p["kind"] == "tpm":
        from . import bitlocker
        try:
            bitlocker.fit_tpm(lab.name, node, False)
        except bitlocker.BitLockerError as exc:
            raise PartsError(str(exc)) from None
        return f"the TPM module is off {name}'s board (it keeps its keys: the same chip back in, BitLocker unlocks as before)"
    if p["kind"] == "bmc":
        from . import power
        try:
            return power.remove(lab, node.id)
        except power.PowerError as exc:
            raise PartsError(str(exc)) from None
    raise PartsError("that part does not come out")


def put_back(lab, node, index: int) -> str:
    """A drive from the bench back in its bay, with its data: live in a
    server's hot-swap bay, otherwise with the machine off."""
    name = naming.display(lab, node.id)
    if index not in hardware.pulled(lab.name, node.id, len(node.data_disks_gb)):
        raise PartsError(f"no drive from bay {index + 1} on the bench")
    if _running(lab.name, node.id):
        if form_of(node) != "server":
            raise PartsError(f"shut {name} down before you fit a drive (only a hot-swap bay takes one while it runs)")
        hardware.reseat(lab.name, node, index, qmp=_qmp)
        return f"the drive is back in bay {index + 1} of {name}: it answers again (Windows may need a rescan)"
    hardware.put_back(lab.name, node, index)
    return f"the drive is back in bay {index + 1} of {name}, with its data"


def throw_away(lab, node, index: int) -> str:
    """A drive on the bench into the bin: it and its data are gone, and the
    bays after it move up one."""
    if index not in hardware.pulled(lab.name, node.id, len(node.data_disks_gb)):
        raise PartsError(f"no drive from bay {index + 1} on the bench")
    disks.remove(lab, node, index)
    return f"the drive from bay {index + 1} is thrown away with everything on it"


def _stick_gone(lab, node, k: int) -> None:
    """The stick that was in slot k is out of the machine: a fault it had
    goes with it (pcbuild.py)."""
    from . import pcbuild
    fx = pcbuild.faults(lab.name, node.id)
    for key in ("ram-bad", "ram-dead"):
        if str(fx.get(key, "")) == str(k):
            pcbuild.clear_fault(lab.name, node.id, key)
    loose = [x for x in str(fx.get("ram-loose", "")).split() if x != str(k)]
    if str(k) in str(fx.get("ram-loose", "")).split():
        if loose:
            pcbuild.set_fault(lab.name, node.id, "ram-loose", " ".join(loose))
        else:
            pcbuild.clear_fault(lab.name, node.id, "ram-loose")


def _check_memory(node, mb: int) -> None:
    if mb < node.memory_floor_mb and node.kind != CUSTOM:
        raise PartsError(f"this OS needs at least {_mb(node.memory_floor_mb)}")
    if not 256 <= mb <= MAX_MEMORY_MB:
        raise PartsError(f"memory is 256 MB to {MAX_MEMORY_MB // 1024} GB")


def _mb(mb: int) -> str:
    if mb % 1024 == 0:
        return f"{mb // 1024} GB"
    return f"{mb / 1024:.1f} GB" if mb >= 1024 else f"{mb} MB"


def _slot_title(slot: str) -> str:
    kind, _, k = slot.partition("-")
    n = int(k) + 1 if k.isdigit() else 0
    return {"m2": f"M.2 socket {n}", "hs": f"bay {n}", "bay35": f"3.5-inch bay {n}",
            "bay25": f"2.5-inch bay {n}"}.get(kind, slot)


def _part_title(kind: str, node) -> str:
    return {"nic": nic_title(node), "gpu": "graphics card", "hba": "SAS host bus adapter"}[kind]


# ------------------------------------------------------------------ the desktop
def act(dash, params: dict) -> dict:
    """wb-hw: op board | fit (part, slot) | out (slot) | back (disk) | trash (disk) | reseat (slot) |
    plug (cable, on) | f1 | setup (the POST screen's keys) | off (a PC halted in POST)."""
    from . import editor
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    node = lab.nodes.get(node_id)
    if node is None:
        return {"ok": False, "message": "no such machine"}
    op = str(params.get("op") or "board")
    try:
        if op == "board":
            return {"ok": True, "board": board(lab, node)}
        if op == "fit":
            msg = fit(lab, node, str(params.get("part") or ""), str(params.get("slot") or ""))
        elif op == "out":
            msg = take_out(lab, node, str(params.get("slot") or ""))
        elif op == "back":
            msg = put_back(lab, node, int(params.get("disk", -1)))
        elif op == "trash":
            msg = throw_away(lab, node, int(params.get("disk", -1)))
        elif op == "reseat":
            msg = reseat(lab, node, str(params.get("slot") or ""))
        elif op == "plug":
            msg = plug(lab, node, str(params.get("cable") or ""), str(params.get("on", "1")) in ("1", "true", "True"))
        elif op in ("f1", "setup"):
            from . import pcbuild
            try:
                return {"ok": True, "message": pcbuild.continue_post(lab.name, node.id, setup=op == "setup")}
            except pcbuild.BuildError as exc:
                return {"ok": False, "message": str(exc)}
        elif op == "off":
            from . import pcbuild
            try:
                return {"ok": True, "message": pcbuild.switch_off(lab.name, node.id)}
            except pcbuild.BuildError as exc:
                return {"ok": False, "message": str(exc)}
        else:
            return {"ok": False, "message": f"unknown hardware action {op!r}"}
    except (ValueError, HardwareError, editor.EditError) as exc:
        return {"ok": False, "message": str(exc)}
    editor.save(lab)
    dash.reload()
    return {"ok": True, "message": msg[:1].upper() + msg[1:]}
