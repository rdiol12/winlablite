"""What makes a PC start before its operating system does: the board, the
power supply and its cables, the cooler and the fans, the CMOS battery, and
the power-on self-test (POST) that checks them.

The hardware view (winlab/pcparts.py) fits and takes out the parts a QEMU
machine really has (processor, memory, drives, cards). This module adds the
parts a PC needs around them, and every one of them has a real effect on the
QEMU machine at its next power-on, or on whether it powers on at all:

* the board: its socket (LGA or PGA) and memory type (DDR4 or DDR5) decide
  which processors and sticks fit (generic parts, no makers' names);
* the processor's integrated graphics: the board's own video outputs work
  only with a processor that has graphics. With no graphics card and a
  processor without graphics, QEMU starts with NO display device: Windows
  boots headless (Win32_VideoController is empty) and the screen shows the
  monitor's "No signal";
* the power supply and its wattage: the parts' draw is added up; no supply,
  a dead one, the 24-pin cable unplugged, or a draw over its rating and the
  machine does not start (QEMU is never launched);
* the CPU power cable (8-pin): unplugged, the fans spin and nothing POSTs;
* memory: the sticks per slot are -m, and each stick is an SMBIOS type 17
  record (-smbios file=, one per slot) so Windows lists them in
  Win32_PhysicalMemory and Task Manager's "Slots used". A stick the board
  cannot read is left out of both; a stick that shorts the bus stops POST
  with the memory beep code;
* SATA power and data cables: a drive with either unplugged is absent from
  the QEMU command line, so Windows does not see it (a system disk unplugged:
  the firmware finds nothing to boot);
* the cooler and the fans: no cooler, or a dead CPU fan, and the machine
  powers itself off after a while, as a thermal trip does (a helper watches
  the running machine and sends QMP quit; Windows logs Kernel-Power 41 at the
  next start);
* the CMOS battery: flat or missing, the RTC (QEMU's -rtc base) starts at the
  firmware's default date at every power-on, and POST says so;
* a card or a cable that is loose is absent from the command line until it
  is reseated.

The POST result of each power-on (what the screen shows, the beep code, the
board's debug LEDs, whether it waits for F1) is kept in the machine's folder
(post.json) for the screen window and the hardware view. A POST message
that asks for F1 starts QEMU paused (-S): the machine really waits until the
student presses F1 in its screen window (QMP cont).

The build is in the lab file (node.vars: board, cpu, psu, cooler, fans, cmos,
unplugged, sys_out, nics_out, battery, ac, wifi_out, kit). Faults that the
troubleshooting drills hide (a dead power supply, a bad stick, a dead fan, a
flat CMOS battery, a loose card or cable) are kept beside the machine's
disks (hwfaults.json), never in the lab file, so a lab saved or shared does
not carry them.

A second monitor is not offered: the lab's PCs use the standard VGA adapter
(one head) or virtio-vga, and the Windows drivers for both drive a single
output (see the hardware lessons' notes).
"""

from __future__ import annotations

import json
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from . import paths

FAULTS_FILE = "hwfaults.json"
POST_FILE = "post.json"
SMBIOS_DIR = "smbios"
CMOS_DEFAULT = "2020-01-01T00:00:00"   # the date the firmware starts from with no CMOS battery

# ------------------------------------------------------------------ the parts
BOARDS = {
    "lga-ddr4": {"title": "ATX board · LGA socket · DDR4", "socket": "lga", "ram": "ddr4", "size": "atx"},
    "pga-ddr5": {"title": "ATX board · PGA socket · DDR5", "socket": "pga", "ram": "ddr5", "size": "atx"},
    "eatx": {"title": "E-ATX workstation board · LGA socket · DDR5", "socket": "lga", "ram": "ddr5", "size": "eatx"},
}
FORM_BOARD = {"tower": "lga-ddr4", "server": "server", "laptop": "laptop"}
FIXED_BOARDS = {"server": {"title": "server board · 1 socket · DDR4 registered ECC", "socket": "lga", "ram": "ddr4"},
                "laptop": {"title": "laptop board · processor soldered · DDR4 SO-DIMM", "socket": "bga", "ram": "ddr4"}}
SOCKET_TITLE = {"lga": "LGA socket (pins on the board)", "pga": "PGA socket (pins on the processor)"}
RAM_TITLE = {"ddr4": "DDR4", "ddr5": "DDR5"}
PSU_W = (300, 450, 550, 750, 1000)
DEFAULT_PSU = 550
CASE_FANS = 2                         # a tower: two intake fans at the front
LAPTOP_ADAPTER_W = 65
HEAT_NO_COOLER = 40                   # seconds of running before a processor with no cooler trips
HEAT_FAN_DEAD = 150                   # a heatsink with a dead fan lasts longer
HEAT_NO_CASE_FANS = 600               # a hot graphics card in a case with no airflow
CABLES = ("atx24", "eps", "gpu")      # plus sata-pwr:<d> and sata-data:<d> per drive (d = sys or a bay index)

# What each part draws, in watts (round figures a technician adds up).
CPU_W = {1: 35, 2: 45, 4: 65, 6: 65, 8: 105, 12: 125, 16: 170}
DRAW = {"board": 40, "server-board": 80, "dimm": 4, "sata": 8, "ssd": 4, "nvme": 6, "sas": 10, "dvd": 15,
        "gpu": 220, "nic": 5, "hba": 12, "fan": 3, "cooler": 4, "tpm": 1}

# Beep codes: this board's own (every maker has its own list in the board's manual).
BEEPS = {
    "ok": ("one short beep", [[120, 0]]),
    "dram": ("three long beeps, repeating", [[600, 300], [600, 300], [600, 900]] * 3),
    "vga": ("one long beep, three short", [[700, 250], [150, 150], [150, 150], [150, 600]]),
    "cmos": ("two short beeps", [[150, 150], [150, 0]]),
    "fan": ("high-low siren", [[250, 30], [250, 30]] * 4),
}


class BuildError(Exception):
    pass


def _pt(text: str) -> str:
    """A drill text in the desktop's language (content/i18n/content/<lang>/problems.json)."""
    from .content import problem_text
    return problem_text(text)


def form_of(node) -> str:
    from .pcparts import form_of as f
    return f(node)


# ------------------------------------------------------------------ the build
@dataclass
class Build:
    form: str
    kit: bool
    board: str          # a BOARDS key, or the form's fixed board, or "" (no board)
    cpu: str            # "lga", "lga-f", "pga", "pga-f", "bga" (soldered) or "" (empty socket)
    cooler: bool
    fans: list[bool]
    psu: int            # watts; 0 = no power supply
    cmos: bool
    unplugged: set[str]
    sys_in: bool
    nics_out: set[int]
    battery: bool
    ac: bool
    wifi: bool

    @property
    def socket(self) -> str:
        return self.cpu.split("-")[0] if self.cpu else ""

    @property
    def igpu(self) -> bool:
        return bool(self.cpu) and not self.cpu.endswith("-f")

    def board_info(self) -> dict:
        if self.form in FIXED_BOARDS:
            return FIXED_BOARDS[self.form]
        return BOARDS.get(self.board, {})


def _words(v) -> set[str]:
    return {w for w in str(v or "").split() if w}


def _flag(v, default: bool) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() not in ("0", "false", "no", "off", "none")


def build(node) -> Build:
    """The machine's build as the lab file has it (defaults: a complete,
    working PC of its form)."""
    form = form_of(node)
    v = node.vars
    kit = _flag(v.get("kit"), False)
    if form == "tower":
        board = str(v.get("board", "lga-ddr4") if "board" in v else "lga-ddr4")
    else:
        board = form
    sock = BOARDS.get(board, {}).get("socket", "lga") if form == "tower" else ("bga" if form == "laptop" else "lga")
    cpu = str(v["cpu"]) if "cpu" in v else sock
    if form == "laptop":
        cpu = "bga"
    nfans = CASE_FANS if form == "tower" else 1
    fans = [c == "1" for c in str(v.get("fans", "1" * nfans)).replace(" ", "")[:nfans].ljust(nfans, "0")]
    if form != "tower":
        fans = [True] * nfans
    psu = int(v.get("psu", DEFAULT_PSU) or 0) if form == "tower" else (LAPTOP_ADAPTER_W if form == "laptop" else 1600)
    nouts = set()
    for w in _words(v.get("nics_out")):
        if w.isdigit():
            nouts.add(int(w))
    return Build(form=form, kit=kit, board=board if form == "tower" else form,
                 cpu="" if cpu == "none" else cpu,
                 cooler=_flag(v.get("cooler"), True) if form != "laptop" else True,
                 fans=fans, psu=psu, cmos=_flag(v.get("cmos"), True),
                 unplugged=_words(v.get("unplugged")) if form == "tower" else set(),
                 sys_in=not _flag(v.get("sys_out"), False),
                 nics_out=nouts,
                 battery=_flag(v.get("battery"), True) if form == "laptop" else False,
                 ac=_flag(v.get("ac"), True) if form == "laptop" else True,
                 wifi=not _flag(v.get("wifi_out"), False) if form == "laptop" else True)


def save(node, b: Build) -> None:
    """Writes the build back into node.vars, leaving out what is default."""
    v = node.vars
    if b.form == "tower":
        _set(v, "board", b.board, "lga-ddr4")
        dflt = BOARDS.get(b.board, {}).get("socket", "lga")
        _set(v, "cpu", b.cpu or "none", dflt)
        _set(v, "fans", "".join("1" if f else "0" for f in b.fans), "1" * CASE_FANS)
        _set(v, "psu", int(b.psu), DEFAULT_PSU)
        _set(v, "cooler", bool(b.cooler), True)
        _set(v, "unplugged", " ".join(sorted(b.unplugged)), "")
    if b.form == "server":
        _set(v, "cooler", bool(b.cooler), True)
    _set(v, "cmos", bool(b.cmos), True)
    _set(v, "sys_out", not b.sys_in, False)
    _set(v, "nics_out", " ".join(str(i) for i in sorted(b.nics_out)), "")
    if b.form == "laptop":
        _set(v, "battery", bool(b.battery), True)
        _set(v, "ac", bool(b.ac), True)
        _set(v, "wifi_out", not b.wifi, False)


def _set(v: dict, key: str, value, default) -> None:
    if value == default:
        v.pop(key, None)
    else:
        v[key] = value


def make_kit(node) -> None:
    """An empty case: the student fits the board, the processor, its cooler,
    the memory, the power supply, the fans and the system drive, and plugs
    in every cable, before the PC starts."""
    if form_of(node) != "tower":
        raise BuildError("only a PC (a tower) comes as an empty case")
    v = node.vars
    v["kit"] = True
    v["board"] = ""
    v["cpu"] = "none"
    v["cooler"] = False
    v["fans"] = "0" * CASE_FANS
    v["psu"] = 0
    v["sys_out"] = True
    v["unplugged"] = "atx24 eps sata-pwr:sys sata-data:sys"
    from .pcparts import FORMS
    v["dimms"] = " ".join("0" for _ in range(FORMS["tower"]["dimm"]))
    if node.nics:
        v["nics_out"] = " ".join(str(i) for i in range(len(node.nics)))
    v.pop("gpu", None)
    v.pop("pcie", None)


# ------------------------------------------------------------------ memory
def raw_sticks(node, slots: int) -> list[int] | None:
    """The sticks per slot as the lab file has them, or None when it has
    none that make sense."""
    try:
        got = [int(x) for x in str(node.vars.get("dimms") or "").split()]
    except ValueError:
        return None
    if len(got) != slots or any(x < 0 for x in got):
        return None
    return got


def ram_type(node, b: Build | None = None) -> str:
    b = b or build(node)
    return b.board_info().get("ram", "ddr4")


# ------------------------------------------------------------------ faults
def _dir(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id


def faults_in(node_dir: Path) -> dict:
    try:
        data = json.loads((node_dir / FAULTS_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def faults(lab_name: str, node_id: str) -> dict:
    return faults_in(_dir(lab_name, node_id))


def _save_faults(lab_name: str, node_id: str, data: dict) -> None:
    p = _dir(lab_name, node_id) / FAULTS_FILE
    data = {k: v for k, v in data.items() if v not in (None, False, "")}
    if not data:
        p.unlink(missing_ok=True)
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")


def set_fault(lab_name: str, node_id: str, key: str, value) -> None:
    data = faults(lab_name, node_id)
    data[key] = value
    _save_faults(lab_name, node_id, data)


def clear_fault(lab_name: str, node_id: str, key: str) -> bool:
    data = faults(lab_name, node_id)
    had = key in data
    data.pop(key, None)
    _save_faults(lab_name, node_id, data)
    return had


# ------------------------------------------------------------------ power
def draw(node, b: Build | None = None) -> int:
    """What the machine as built draws at full load, in watts."""
    from . import disks, mediashelf
    from .pcparts import FORMS, cards
    b = b or build(node)
    if b.form != "tower":
        return 0
    w = DRAW["board"] if b.board else 0
    if b.cpu:
        w += CPU_W.get(node.cpus, 65 + node.cpus * 5)
    if b.cooler:
        w += DRAW["cooler"]
    w += DRAW["fan"] * sum(b.fans)
    sticks = raw_sticks(node, FORMS["tower"]["dimm"])
    w += DRAW["dimm"] * (sum(1 for s in sticks if s) if sticks is not None else 2)
    if b.sys_in:
        w += DRAW["ssd"]
    for bus in disks.asked_buses(node):
        w += DRAW.get(bus, 8)
    w += DRAW["dvd"] * mediashelf.drives(node)
    for c in cards(node, "tower"):
        w += DRAW["gpu"] if c == "gpu" else DRAW["hba"] if c == "hba" else DRAW["nic"] if c else 0
    return w


def advice(watts: int) -> int:
    """The supply a technician picks for this draw: about a quarter of
    headroom, rounded up to a supply that is sold."""
    need = watts * 1.25
    return next((p for p in PSU_W if p >= need), PSU_W[-1])


# ------------------------------------------------------------------ POST
def _drive_cables(node, b: Build) -> list[str]:
    """The drives that hang on SATA cables in a tower: the system disk and
    the SATA data disks."""
    from . import disks
    out = ["sys"] if b.sys_in else []
    for i, bus in enumerate(disks.asked_buses(node)):
        if bus == "sata":
            out.append(str(i))
    return out


def cabled(b: Build, drive: str) -> bool:
    return b.form != "tower" or not ({f"sata-pwr:{drive}", f"sata-data:{drive}"} & b.unplugged)


def absent_drives(node, b: Build, fx: dict) -> set[int]:
    """Data disks the machine will not see at its next start: a SATA cable
    unplugged or loose, or on a SAS adapter that is loose."""
    from . import disks
    out: set[int] = set()
    loose = str(fx.get("cable") or "")
    for i, bus in enumerate(disks.asked_buses(node)):
        if bus == "sata" and b.form == "tower":
            if not cabled(b, str(i)) or loose in (f"sata-data:{i}", f"sata-pwr:{i}"):
                out.add(i)
        if bus == "sas" and fx.get("card") == "hba":
            out.add(i)
    return out


def video(node, b: Build, fx: dict) -> str:
    """'gpu', 'onboard' or 'none': where the screen's picture comes from."""
    gpu = bool(node.vars.get("gpu")) and fx.get("card") != "gpu" and "gpu" not in b.unplugged
    if gpu:
        return "gpu"
    if b.form != "tower" or b.igpu:
        return "onboard"
    return "none"


def post(lab_name: str, node, now: float | None = None) -> dict:
    """What happens when the power button is pressed: whether it powers on,
    where POST stops, what the screen and the speaker say, and how the QEMU
    machine is built from it."""
    from . import disks
    from .pcparts import FORMS
    b = build(node)
    fx = faults(lab_name, node.id)
    nd = _dir(lab_name, node.id)
    out = {"form": b.form, "power": "ok", "stage": "ok", "halt": False, "beeps": "", "beep": [],
           "lines": [], "errors": [], "hold": False, "heat": 0, "video": "onboard", "memory_mb": node.memory_mb,
           "led": "", "draw": 0, "psu": b.psu, "no_display": False}
    if not b.form:
        return out
    info = b.board_info()
    # Power first: nothing at all happens without it.
    if b.form == "tower":
        out["draw"] = draw(node, b)
        if not b.board:
            out["power"] = "board"
        elif not b.psu:
            out["power"] = "none"
        elif fx.get("psu"):
            out["power"] = "dead"
        elif "atx24" in b.unplugged or fx.get("cable") == "atx24":
            out["power"] = "atx24"
        elif out["draw"] > b.psu:
            out["power"] = "over"
    elif b.form == "laptop" and not b.ac and not b.battery:
        out["power"] = "battery"
    if out["power"] != "ok":
        out["halt"] = True
        out["stage"] = "power"
        return out
    # The processor and its power.
    if not b.cpu or ("eps" in b.unplugged or fx.get("cable") == "eps"):
        out.update(halt=True, stage="cpu", led="cpu")
        return out
    # Memory: the sticks the board reads, and one that stops it dead.
    slots = FORMS[b.form]["dimm"]
    sticks = raw_sticks(node, slots)
    if sticks is None:
        from .pcparts import sticks as made
        sticks = made(node, slots)
    bad = {int(fx["ram-bad"])} if str(fx.get("ram-bad", "")).isdigit() else set()
    dead = {int(fx["ram-dead"])} if str(fx.get("ram-dead", "")).isdigit() else set()
    loose = {int(x) for x in str(fx.get("ram-loose", "")).split() if x.isdigit()}
    good = [mb if mb and k not in bad | dead | loose else 0 for k, mb in enumerate(sticks)]
    if not any(sticks) or not any(good) or any(sticks[k] for k in dead if k < len(sticks)):
        out.update(halt=True, stage="dram", led="dram")
        out["beeps"], out["beep"] = BEEPS["dram"]
        return out
    mem = sum(good)
    if node.memory_mb < sum(sticks):   # cut to fit this PC at power-on (winlab/membudget.py)
        mem = min(mem, node.memory_mb)
    out["memory_mb"] = mem
    out["sticks"] = good
    out["fitted"] = sticks
    # Video.
    out["video"] = video(node, b, fx)
    if out["video"] == "none":
        out["led"] = "vga"
        out["no_display"] = True
        out["beeps"], out["beep"] = BEEPS["vga"]
    # The screen's lines, as this board's firmware prints them.
    lines = [f"winlab PC firmware 2.4 · {info.get('title', 'board')}",
             f"Processor: {node.cpus}-core processor ({'graphics built in' if b.igpu or b.form != 'tower' else 'no graphics'})"]
    ram = RAM_TITLE.get(info.get("ram", "ddr4"), "DDR4")
    lines.append(f"Memory test: {mem} MB OK")
    lines.append("  " + "   ".join(f"DIMM{k + 1}: " + (f"{g} MB {ram}" if g else "not detected" if sticks[k] else "empty")
                                  for k, g in enumerate(good)))
    drives = []
    if b.sys_in and cabled(b, "sys") and fx.get("cable") not in ("sata-data:sys", "sata-pwr:sys"):
        drives.append("SATA0: system disk")
    elif b.form == "tower":
        drives.append("SATA0: none")
    gone = absent_drives(node, b, fx)
    for i, bus in enumerate(disks.asked_buses(node)):
        if i in gone:
            continue
        drives.append(f"{disks.TITLE[bus]} {node.data_disks_gb[i]} GB")
    lines.append("Drives: " + ", ".join(drives))
    errors: list[str] = []
    beep = ""
    if b.form == "tower":
        rpm = ", ".join(f"SYS_FAN{k + 1} {'980 RPM' if f else 'not detected'}" for k, f in enumerate(b.fans))
        cpu_fan = "CPU_FAN not detected" if not b.cooler or fx.get("fan") else "CPU_FAN 1450 RPM"
        lines.append(f"Fans: {cpu_fan}, {rpm}")
    elif fx.get("fan"):
        lines.append("Fans: CPU_FAN not detected")
    # Heat.
    gpu = bool(node.vars.get("gpu"))
    if not b.cooler:
        out["heat"] = HEAT_NO_COOLER
    elif fx.get("fan"):
        out["heat"] = HEAT_FAN_DEAD
        errors.append("CPU fan error! Press F1 to resume")
        beep = "fan"
    elif b.form == "tower" and not any(b.fans) and gpu:
        out["heat"] = HEAT_NO_CASE_FANS
        errors.append("Chassis fan not detected")
    elif b.form == "tower" and not any(b.fans):
        errors.append("Chassis fan not detected")
    if not b.cmos or fx.get("cmos"):
        errors.append("CMOS battery has failed. CMOS checksum error - Defaults loaded")
        errors.append("System date and time are not set. Press F1 to continue, DEL to enter SETUP")
        beep = beep or "cmos"
    if any(sticks[k] and not good[k] for k in range(len(sticks))):
        errors.append("Memory size has decreased: a DIMM was not detected")
    sick = disks.failing_in(nd, len(node.data_disks_gb))
    for i in sorted(sick):
        if i in gone:
            continue
        if disks.buses(node)[i] == "nvme":
            errors.append(f"S.M.A.R.T. status BAD on the NVMe drive in M.2 socket ({node.data_disks_gb[i]} GB): "
                          "back it up and replace it. Press F1 to resume")
    out["lines"] = lines
    out["errors"] = errors
    out["hold"] = any("F1" in e for e in errors)
    if beep and not out["beeps"]:
        out["beeps"], out["beep"] = BEEPS[beep]
    elif not out["beeps"]:
        out["beeps"], out["beep"] = BEEPS["ok"]
    return out


POWER_WHY = {
    "board": "nothing happens: there is no board in the case for the power button to talk to",
    "none": "nothing happens: no power supply is fitted",
    "dead": "nothing happens: no fans, no lights, not even the light on the board",
    "atx24": "nothing happens: no fans, no lights (the board gets no power)",
    "over": "it clicks, the fans twitch for a moment and it switches itself off again: the power supply shut down",
    "battery": "nothing happens: no charger plugged in and no battery",
}
STAGE_WHY = {
    "cpu": "the fans spin, but nothing appears on the screen and there is no beep",
    "dram": "the fans spin, nothing appears on the screen, and it beeps: {beeps}",
}


def verdict(p: dict) -> str:
    """One sentence: what the student sees and hears when it does not start."""
    if p["stage"] == "power":
        return _pt(POWER_WHY.get(p["power"], "it does not power on"))
    return _pt(STAGE_WHY.get(p["stage"], "it does not start")).replace("{beeps}", p.get("beeps", ""))


# ------------------------------------------------------------------ the record of a power-on
def record(lab_name: str, node_id: str, p: dict, pid: int = 0) -> None:
    rec = dict(p)
    rec["at"] = time.time()
    rec["pid"] = pid
    rec["stuck"] = bool(p.get("halt")) and p.get("stage") != "power"
    path = _dir(lab_name, node_id) / POST_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec) + "\n", encoding="utf-8")


def last(lab_name: str, node_id: str) -> dict | None:
    try:
        rec = json.loads((_dir(lab_name, node_id) / POST_FILE).read_text(encoding="utf-8"))
        return rec if isinstance(rec, dict) else None
    except (OSError, ValueError):
        return None


def forget(lab_name: str, node_id: str) -> None:
    (_dir(lab_name, node_id) / POST_FILE).unlink(missing_ok=True)


def stuck(lab_name: str, node_id: str) -> dict | None:
    """A PC that is switched on but halted in POST (no processor, no
    memory): its fans spin and a debug LED is lit until it is switched off."""
    rec = last(lab_name, node_id)
    return rec if rec and rec.get("stuck") else None


def screen(lab_name: str, node_id: str, alive: bool, pid: int = 0) -> dict | None:
    """What the machine's screen window shows before (or instead of) the
    operating system: the record of its last power-on, while it applies."""
    rec = last(lab_name, node_id)
    if not rec:
        return None
    if alive:
        if rec.get("pid") and pid and rec["pid"] != pid:
            return None
        if not rec.get("hold") and not rec.get("no_display") and time.time() - float(rec.get("at", 0)) > 20:
            return None
    else:
        if not rec.get("halt"):
            return None
        if not rec.get("stuck") and time.time() - float(rec.get("at", 0)) > 120:
            return None
    keep = ("form", "power", "stage", "beeps", "beep", "lines", "errors", "hold", "video", "led", "no_display",
            "at", "stuck", "halt")
    out = {k: rec.get(k) for k in keep}
    out["why"] = verdict(rec) if rec.get("halt") else ""
    out["beeps"] = _pt(out["beeps"]) if out.get("beeps") else ""
    out["running"] = alive
    return out


# ------------------------------------------------------------------ the QEMU machine
def effects(lab_name: str, node) -> dict:
    """How the build changes the QEMU command line at this power-on."""
    b = build(node)
    if not b.form:
        return {}
    fx = faults(lab_name, node.id)
    p = post(lab_name, node)
    from . import wifi
    skip = set(b.nics_out)
    if fx.get("card", "").startswith("nic") and fx["card"][3:].isdigit():
        skip.add(int(fx["card"][3:]))
    if b.form == "laptop" and not b.wifi:
        skip.update(wifi.wireless(node) or [0])
    sys_ok = b.sys_in and cabled(b, "sys") and fx.get("cable") not in ("sata-data:sys", "sata-pwr:sys")
    return {"memory_mb": p.get("memory_mb", node.memory_mb), "video": p["video"], "skip_nics": skip,
            "sys": sys_ok, "absent": absent_drives(node, b, fx),
            "hba": fx.get("card") != "hba",
            "rtc": None if (b.cmos and not fx.get("cmos")) else CMOS_DEFAULT,
            "hold": bool(p.get("hold")), "heat": int(p.get("heat") or 0),
            "sticks": p.get("sticks"), "ram": ram_type(node, b)}


def smbios_args(lab_name: str, node, sticks: list[int] | None) -> list[str]:
    """One SMBIOS type 17 (memory device) record per slot, written to the
    machine's folder and handed to QEMU as -smbios file=: Windows lists each
    stick (Win32_PhysicalMemory: DeviceLocator, Capacity, Speed,
    SMBIOSMemoryType) and counts the slots used."""
    b = build(node)
    if not b.form or sticks is None:
        return []
    d = _dir(lab_name, node.id) / SMBIOS_DIR
    d.mkdir(parents=True, exist_ok=True)
    out = []
    ram = ram_type(node, b)
    for k, mb in enumerate(sticks):
        f = d / f"dimm{k}.bin"
        f.write_bytes(type17(k, mb, ram, b.form))
        out += ["-smbios", f"file={f}"]
    return out


MEM_TYPE = {"ddr4": 0x1A, "ddr5": 0x22}
SPEED = {"ddr4": 3200, "ddr5": 4800}


def type17(slot: int, mb: int, ram: str = "ddr4", form: str = "tower") -> bytes:
    """An SMBIOS 2.8 Memory Device structure (type 17, 40 bytes and its
    strings) for one slot: its locator, size, type and speed, or an empty
    slot (size 0). The handle follows QEMU's own numbering for type 17
    (0x1100 + slot), under its Physical Memory Array (0x1000)."""
    ecc = form == "server"
    sodimm = form == "laptop"
    names = [f"DIMM {slot + 1}", f"CHANNEL {'AB'[slot % 2]}"]
    if mb:
        names += ["Generic", f"WL{slot + 1:02d}{mb:06d}", f"ASSET-DIMM{slot + 1}",
                  f"{'SO-' if sodimm else ''}{ram.upper()}-{SPEED.get(ram, 3200)} {mb // 1024 or mb} {'GB' if mb >= 1024 else 'MB'}"]
    else:
        names += ["NO DIMM", "NO DIMM", "NO DIMM", "NO DIMM"]
    size = mb if mb < 0x7FFF else 0x7FFF
    ext = mb if mb >= 0x7FFF else 0
    speed = SPEED.get(ram, 3200) if mb else 0
    body = struct.pack(
        "<BBHHHHHHBBBBBHHBBBBBIHHHH",
        17, 0x28, 0x1100 + slot, 0x1000, 0xFFFE,
        72 if ecc else 64, 64, size,
        0x0D if sodimm else 0x09, 0, 1, 2, MEM_TYPE.get(ram, 0x1A) if mb else 0x02, 0x0080 if mb else 0x0004,
        speed, 3, 4, 5, 6, 1 if mb else 0, ext, speed, 1200 if mb else 0, 1200 if mb else 0, 1200 if mb else 0)
    strings = b"".join(s.encode("ascii", "replace") + b"\0" for s in names) + b"\0"
    return body + strings


# ------------------------------------------------------------------ overheating
def thermal_argv(lab_name: str, node_id: str, pid: int, qmp_port: int, seconds: int) -> list[str]:
    import sys
    return [sys.executable] + ([] if paths.FROZEN else ["-m", "winlab"]) + [
        "hw-thermal", lab_name, node_id, str(pid), str(qmp_port), str(seconds)]


def arm_thermal(lab_name: str, node_id: str, pid: int, qmp_port: int, seconds: int) -> None:
    """A helper that watches the running machine and switches it off after
    `seconds` of running, as a processor's thermal trip does."""
    import subprocess
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        subprocess.Popen(thermal_argv(lab_name, node_id, pid, qmp_port, seconds), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
                         start_new_session=not flags)
    except OSError:
        pass


def thermal_watch(lab_name: str, node_id: str, pid: int, qmp_port: int, seconds: int,
                  qmp=None, sleep=time.sleep, alive=None) -> bool:
    """Counts the seconds the machine really runs (not while it waits at
    POST or is paused) and, at `seconds`, powers it off with QMP quit.
    True when it tripped."""
    from . import state
    from .qmp import Qmp, QmpError
    qmp = qmp or Qmp
    alive = alive or state.pid_alive
    ran = 0.0
    while alive(pid):
        try:
            with qmp(qmp_port, timeout=5) as mon:
                st = mon.call("query-status") or {}
                if st.get("running"):
                    ran += 2
                if ran >= seconds:
                    mon.call("quit")
                    rec = last(lab_name, node_id) or {}
                    rec["tripped"] = time.time()
                    try:
                        (_dir(lab_name, node_id) / POST_FILE).write_text(json.dumps(rec) + "\n", encoding="utf-8")
                    except OSError:
                        pass
                    return True
        except (QmpError, OSError):
            pass
        sleep(2)
    return False


def run_thermal_cli(args) -> int:
    thermal_watch(args.lab, args.node, int(args.pid), int(args.port), int(args.seconds))
    return 0


def add_cli(sub) -> None:
    import argparse
    p = sub.add_parser("hw-thermal", help=argparse.SUPPRESS)
    for a in ("lab", "node", "pid", "port", "seconds"):
        p.add_argument(a)


# ------------------------------------------------------------------ powering on
def blocked(lab, node_ids: list[str]) -> dict[str, str]:
    """The machines that do not start when their power button is pressed,
    and what the student sees: the record is written for each."""
    out = {}
    for nid in node_ids:
        node = lab.nodes.get(nid)
        if node is None or not form_of(node):
            continue
        p = post(lab.name, node)
        if p["halt"]:
            record(lab.name, nid, p)
            out[nid] = verdict(p)
    return out


def continue_post(lab_name: str, node_id: str, setup: bool = False, qmp=None) -> str:
    """F1 (or DEL) on a POST screen that waits: the machine carries on."""
    from .media import _qmp_port
    from .qmp import Qmp, QmpError
    qmp = qmp or Qmp
    port = _qmp_port(lab_name, node_id)
    if not port:
        raise BuildError(f"{node_id} is not running")
    try:
        with qmp(port) as mon:
            mon.call("cont")
    except (QmpError, OSError) as exc:
        raise BuildError(f"{node_id}: {exc}") from exc
    rec = last(lab_name, node_id) or {}
    rec["hold"] = False
    rec["continued"] = time.time()
    (_dir(lab_name, node_id) / POST_FILE).write_text(json.dumps(rec) + "\n", encoding="utf-8")
    if setup:
        from .orchestrator import firmware_setup
        try:
            firmware_setup(port)
        except Exception:  # noqa: BLE001 - the machine runs either way
            pass
    return "continuing" + (": into the firmware setup" if setup else "")


def switch_off(lab_name: str, node_id: str) -> str:
    """Holding the power button of a PC halted in POST: it goes dark."""
    rec = last(lab_name, node_id)
    if not rec or not rec.get("stuck"):
        raise BuildError(f"{node_id} is not on")
    rec["stuck"] = False
    rec["halt"] = False
    (_dir(lab_name, node_id) / POST_FILE).write_text(json.dumps(rec) + "\n", encoding="utf-8")
    return f"{node_id} is off"


# ------------------------------------------------------------------ graded from the build
# The exercises of the PC building lessons (content/exercises/hw-*.toml) check
# the case itself here, and what Windows sees inside the machine.
def _node_or(lab, node_id: str):
    node = lab.nodes.get(node_id)
    if node is None:
        return None, f"the lab has no {node_id}"
    return node, ""


def check_built(lab, node_id: str = "pc05") -> tuple[bool, str]:
    """Every part of a working PC in the case, every cable in, and a POST
    with nothing to say."""
    node, why = _node_or(lab, node_id)
    if node is None:
        return False, why
    b = build(node)
    missing = [what for ok, what in ((b.board, "a board"), (b.cpu, "a processor"), (b.cooler, "the cooler"),
                                     (b.psu, "a power supply"), (b.sys_in, "the system drive"),
                                     (all(b.fans), "both front fans"), (b.cmos, "the CMOS battery")) if not ok]
    if missing:
        return False, f"{node_id} still needs " + ", ".join(missing)
    # The supply's PCIe lead hangs free when there is no graphics card for it.
    loose = b.unplugged - (set() if node.vars.get("gpu") else {"gpu"})
    if loose:
        return False, f"{node_id}: unplugged: " + ", ".join(sorted(loose))
    p = post(lab.name, node)
    if p["halt"]:
        return False, f"{node_id} does not POST: {verdict(p)}"
    if p["errors"]:
        return False, f"{node_id} POSTs with: {p['errors'][0]}"
    return True, f"{node_id} is built and POSTs cleanly"


def check_psu(lab, node_id: str = "pc05") -> tuple[bool, str]:
    """A graphics card, its power plugged in, and a supply with headroom."""
    node, why = _node_or(lab, node_id)
    if node is None:
        return False, why
    b = build(node)
    if not node.vars.get("gpu"):
        return False, f"{node_id} has no graphics card"
    if "gpu" in b.unplugged:
        return False, f"the graphics card's PCIe power is not plugged in"
    w = draw(node, b)
    if not b.psu:
        return False, f"{node_id} has no power supply"
    if b.psu < advice(w):
        return False, f"the parts draw about {w} W: a {b.psu} W supply leaves too little headroom ({advice(w)} W or more)"
    return True, f"{w} W on a {b.psu} W supply"


def check_cpu_card(lab, node_id: str = "pc05") -> tuple[bool, str]:
    """A processor without graphics, and the picture from a graphics card."""
    node, why = _node_or(lab, node_id)
    if node is None:
        return False, why
    b = build(node)
    if not b.cpu:
        return False, f"{node_id} has no processor"
    if b.igpu:
        return False, f"{node_id}'s processor has graphics built in: fit one without graphics"
    if not b.cooler:
        return False, f"{node_id}'s processor has no cooler on it"
    if not node.vars.get("gpu"):
        return False, f"{node_id} has no graphics card: its monitor has no signal"
    if "gpu" in b.unplugged:
        return False, "the graphics card's PCIe power is not plugged in"
    return True, "a processor without graphics, and a graphics card for the monitor"


def check_dual_channel(lab, node_id: str = "pc05") -> tuple[bool, str]:
    """Two matched sticks in DIMM2 and DIMM4, the slots the board's manual
    names for two sticks (dual channel), 8 GB or more in all."""
    node, why = _node_or(lab, node_id)
    if node is None:
        return False, why
    from .pcparts import FORMS
    sticks = raw_sticks(node, FORMS["tower"]["dimm"]) or []
    fitted = [k for k, mb in enumerate(sticks) if mb]
    if len(fitted) < 2:
        return False, f"{node_id} has {len(fitted)} stick(s): dual channel takes a matched pair"
    if len(fitted) == 2 and fitted != [1, 3]:
        return False, (f"the two sticks are in DIMM{fitted[0] + 1} and DIMM{fitted[1] + 1}: the board's manual puts "
                       "a pair in DIMM2 and DIMM4")
    if len({sticks[k] for k in fitted}) > 1 and len(fitted) == 2:
        return False, "the two sticks are not the same size"
    if sum(sticks) < 8192:
        return False, f"{sum(sticks)} MB in all: 8 GB or more wanted"
    return True, f"{sum(sticks) // 1024} GB in matched sticks"


def check_cooling(lab, node_id: str = "pc05") -> tuple[bool, str]:
    node, why = _node_or(lab, node_id)
    if node is None:
        return False, why
    b = build(node)
    if not b.cooler:
        return False, f"{node_id}'s processor has no cooler"
    if faults(lab.name, node_id).get("fan"):
        return False, f"{node_id}'s CPU fan does not turn"
    if not all(b.fans):
        return False, f"{node_id} has {sum(b.fans)} of {len(b.fans)} front fans"
    return True, "the processor and the case are cooled"


def check_cmos(lab, node_id: str = "pc05") -> tuple[bool, str]:
    node, why = _node_or(lab, node_id)
    if node is None:
        return False, why
    if not build(node).cmos:
        return False, f"{node_id} has no CMOS battery"
    if faults(lab.name, node_id).get("cmos"):
        return False, f"{node_id}'s CMOS battery is flat"
    return True, "the CMOS battery holds the clock"


def check_laptop(lab, node_id: str = "lap01") -> tuple[bool, str]:
    node, why = _node_or(lab, node_id)
    if node is None:
        return False, why
    from . import disks
    from .pcparts import FORMS
    b = build(node)
    sticks = raw_sticks(node, FORMS["laptop"]["dimm"]) or []
    missing = [what for ok, what in ((len([s for s in sticks if s]) >= 2, "a second SO-DIMM"),
                                     ("nvme" in disks.asked_buses(node), "an M.2 NVMe SSD"),
                                     (b.battery, "the battery"), (b.wifi, "the Wi-Fi card")) if not ok]
    if missing:
        return False, f"{node_id} still needs " + ", ".join(missing)
    return True, f"{node_id} is upgraded"


def check_breakfix(lab) -> tuple[bool, str]:
    """A round of Break-fix on the Hardware topic, a fault fixed and its
    cause named."""
    from . import breakfix
    run = breakfix.load()
    if not run or run.get("lab") != lab.name or run.get("topic") != "hardware":
        return False, "no Break-fix round on the Hardware topic in this lab"
    done = [fx for fx in run.get("faults", []) if fx.get("fixed_at")]
    if not done:
        return False, "the hardware fault is not fixed yet: Verify my fix in Break-fix"
    if not any(breakfix._right(fx) for fx in done):
        return False, "the fault is fixed, but its cause is not answered right yet"
    return True, "a hardware fault found, fixed and named"


def _register() -> None:
    from . import exercises
    for name, fn in (("hw-pc05-built", check_built), ("hw-pc05-psu", check_psu), ("hw-pc05-cpu-card", check_cpu_card),
                     ("hw-pc05-dual-channel", check_dual_channel), ("hw-pc05-cooled", check_cooling),
                     ("hw-pc05-cmos", check_cmos), ("hw-lap01-upgraded", check_laptop),
                     ("hw-breakfix-hardware", check_breakfix)):
        exercises.register_winlab_check(name, lambda lab, fn=fn: fn(lab))


_register()
