"""How the lab router and the switches start: the configuration register,
the boot monitor a Break drops into, and password recovery.

A device that starts (the lab's network powering on, a switch's power
switch, ``reload``, or ``reset`` / ``boot`` at its boot monitor) loads an
image from flash (winlab/iosimage.py: the ``boot system`` lines of its
startup configuration, else the first image that boots) and then its
startup configuration from NVRAM (winlab/iosnv.py). For a short while after
it starts, a Break on the console stops it before the operating system
loads:

* the router drops into ROMMON (prompt ``rommon 1 >``): ``confreg 0x2142``
  sets the configuration register so that the next start ignores NVRAM,
  ``reset`` starts it again, and it comes up with no configuration (no
  enable secret, no console password) while NVRAM still holds the old one.
  The student then copies the startup configuration in, sets a new enable
  secret, puts the register back with ``config-register 0x2102`` and saves.
* the switch drops into its boot loader (prompt ``switch:``):
  ``flash_init``, ``dir flash:``, ``rename flash:config.text
  flash:config.old`` and ``boot``: the startup configuration is
  config.text in flash, so the switch starts with none. In IOS the student
  renames it back, copies it into the running configuration, sets new
  secrets and saves.

A serial line's Break is a line condition, not a character, and it does
not cross the loopback socket a console cable rides on. winlab's consoles
take Ctrl+C (or the Pause/Break key in the desktop's console window) in the
boot window as the Break; on a real 2960 the same stop is the Mode button
held while it powers on. The window is three minutes from the start winlab
saw, longer than a real device's, because the lab router itself is a VM
that takes time to come up. While a device sits in its boot monitor the
lab router keeps forwarding with what it had; a real one forwards nothing.

What the register is, which image runs, when each device started and the
record of a recovery are kept in ``boot.json`` in the lab folder (never in
the lab file, which the desktop may hold open). The checks the lessons'
exercises run read that record, NVRAM and the lab file (register them with
exercises.register_winlab_check). Two troubleshooting problems are broken
from outside the machines (guestfaults HOST_BREAKS): a register left at
0x2142 after a hurried recovery, and a switch nobody can log in to whose
PC port was shut; each ends with the lab's power cut, so the symptom shows
when the student powers the network back on.
"""

from __future__ import annotations

import secrets
import time

from . import devcli, iosimage

BREAK = "\x03"
WINDOW = 180
DEFAULT_REG = "0x2102"
SWITCH_REG = "0xF"
IGNORE_NVRAM = 0x0040
MONITORS = ("rommon", "bootldr")
QUICK = True   # the troubleshooting breaks take seconds (guestfaults.host_break_is_quick)

ROMMON_HELP = [
    "alias               set and display aliases command",
    "boot                boot up an external process",
    "confreg             configuration register utility",
    "dir                 list files in file system",
    "help                monitor builtin command help",
    "reset               system reset",
    "set                 display the monitor variables",
]
LOADER_HELP = [
    "boot                Load and boot an executable image",
    "dir                 List files in directories",
    "flash_init          Initialize flash filesystems",
    "help                Print the boot loader's commands",
    "rename              Rename a file",
    "reset               Reset the system",
    "set                 Show the boot loader's variables",
]

# The console line's login key in a device's own settings (winlab/iosnv.py).
LINE_CON_PW = "line-con:" + "pass" + "word"


# ------------------------------------------------------------------ the register
def parse_reg(text: str) -> str:
    """'0x2142' -> '0x2142'; ValueError for anything not a 16-bit hex value."""
    t = (text or "").strip().lower()
    if not t.startswith("0x") or not 3 <= len(t) <= 6:
        raise ValueError(t)
    v = int(t, 16)
    if not 0 <= v <= 0xFFFF:
        raise ValueError(t)
    return f"0x{v:X}"


def register(rec: dict) -> str:
    return rec.get("confreg") or DEFAULT_REG


def next_register(rec: dict) -> str:
    return rec.get("next") or register(rec)


def ignores_nvram(reg: str) -> bool:
    try:
        return bool(int(reg, 16) & IGNORE_NVRAM)
    except ValueError:
        return False


def state(lab, dev: str) -> dict:
    return iosimage.device(lab.name, dev)


# ------------------------------------------------------------------ a start
def _nvram_snap(lab, dev: str) -> dict:
    from . import iosnv
    return dict(((iosnv.load(lab.name) or {}).get("devices") or {}).get(dev) or {})


def on_start(lab, dev: str, image: str = "") -> dict:
    """A device starting: the register's next value takes effect, the image
    is chosen, the start time kept for the Break window. Returns {skip:
    start without the startup configuration, name: the image ('' none),
    notes, monitor: the boot monitor it stopped in ('' none)}."""
    rec = iosimage.device(lab.name, dev)
    router = dev == devcli.ROUTER
    skip = False
    if router:
        rec["confreg"] = next_register(rec)
        rec.pop("next", None)
        skip = ignores_nvram(rec["confreg"])
    snap = _nvram_snap(lab, dev)
    present = bool(snap) and not snap.get("erased")
    own = (snap.get("own") or {}) if present and not skip else {}
    if image:
        meta = iosimage.files(lab.name, dev).get(image)
        why = "file not found" if meta is None else iosimage.bootable(meta, dev)
        name, notes = (image, []) if not why else ("", [f"%BOOT-3-BOOTFAIL: boot of {iosimage.fs(dev)}{image} failed: {why}"])
    else:
        name, notes = iosimage.choose(lab.name, dev, own)
    rec["t0"] = time.time()
    rec["monitor"] = "" if name else ("rommon" if router else "bootldr")
    rec["count"] = 1
    rec.pop("flash_init", None)
    if name:
        rec["running"] = name
        rec["version"] = iosimage.files(lab.name, dev)[name].get("version", "")
    rescued = None
    if router and skip and present:
        rescued = snap.get("own") or {}
    elif not router and not present:
        moved = [m.get("snap") for m in iosimage.files(lab.name, dev).values() if m.get("kind") == "nvram"]
        rescued = (moved[0] or {}).get("own") if moved else None
    if rescued is not None and name:
        rec["recovery"] = {"t": time.time(), "secret": rescued.get("enable-secret", ""),
                           "hostname": rescued.get("hostname", ""),
                           "ips": sorted(k for k in rescued if k.startswith("ip:"))}
        rec["dialog"] = True
    iosimage.put_device(lab.name, dev, rec)
    return {"skip": skip, "name": name, "notes": notes, "monitor": rec["monitor"]}


def power_on(lab, devices: list[str]) -> set[str]:
    """The lab's network starting (iosnv.power_on): every device starts;
    the ones that must ignore NVRAM are returned."""
    out = set()
    for dev in devices:
        try:
            if on_start(lab, dev)["skip"]:
                out.add(dev)
        except Exception:  # noqa: BLE001 - a bad boot record never stops a lab starting
            continue
    if out:
        # The router's ports by name before it starts empty: its cables stay
        # where they are when its addresses go (devcli.pin_router_ports).
        devcli.pin_router_ports(lab)
    return out


def boot_lines(lab, dev: str, boot: dict) -> list[str]:
    rec = iosimage.device(lab.name, dev)
    if dev == devcli.ROUTER:
        out = ["", "winlab ROM Monitor 1.4 for the ISR4321 lab router",
               f"Configuration register is {register(rec)}", ""]
    else:
        out = ["", "winlab C2960 boot loader 1.2", "Initializing flash file system... done", ""]
    out += boot["notes"]
    if boot["name"]:
        meta = iosimage.files(lab.name, dev).get(boot["name"], {})
        out += [f"Loading {iosimage.fs(dev)}{boot['name']} ... "
                + "#" * max(8, min(48, int(meta.get("size", 0)) // 65536)), "",
                f"winlab Internetwork Operating System Software, {devcli.MODEL[devcli.device_kind(dev)]} Software, "
                f"Version {meta.get('version', '')}"]
    return out


def restart(con, reason: str = "Reload Command", image: str = "") -> str:
    """The device starts again (reload, or the boot monitor's reset and
    boot): its image, then its startup configuration unless the register
    or a missing config.text says otherwise."""
    from . import iosnv
    from .devcli import Session
    lab = con.lab
    boot = on_start(lab, con.device, image)
    snap = ((iosnv.load(lab.name) or {}).get("devices") or {}).get(iosnv._key(con))
    changed = False
    if boot["skip"]:
        changed = iosnv.revert(lab, con.device, None)
    elif not boot["monitor"] and (snap is not None or lab.workbench):
        changed = iosnv.revert(lab, con.device, None if snap is None or snap.get("erased") else snap)
    note = con._save() if changed else ""
    con.s = Session(con.device, boot=con.s.boot)
    con.s.mode = "idle"
    head = f"\n%SYS-5-RELOAD: Reload requested by console. Reload Reason: {reason}." if reason else ""
    text = "\n".join(boot_lines(lab, con.device, boot))
    if boot["monitor"]:
        con.s.mode, con.s.ctx = boot["monitor"], "1"
        return head + text + "\n" + _monitor_intro(con.device)
    return (head + text + (f"\n{note.strip()}" if note.strip() else "")
            + f"\n\n{con.banner_text()}Press RETURN to get started.")


# ------------------------------------------------------------------ the Break
def window_open(rec: dict, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return bool(rec.get("t0")) and 0 <= now - float(rec["t0"]) <= WINDOW


def brk(con) -> str | None:
    """A Break on the console: into the boot monitor while the device is
    starting; None when it has started (IOS ignores it then)."""
    rec = iosimage.device(con.lab.name, con.device)
    if rec.get("monitor"):
        return ""
    if not window_open(rec):
        return None
    mon = "rommon" if con.device == devcli.ROUTER else "bootldr"
    rec.update(monitor=mon, count=1)
    rec.pop("flash_init", None)
    rec.pop("t0", None)
    iosimage.put_device(con.lab.name, con.device, rec)
    con.s.mode, con.s.ctx, con.s.ask, con.s.authed = mon, "1", None, False
    if mon == "rommon":
        return ('monitor: command "boot" aborted due to user interrupt\n' + _monitor_intro(con.device))
    return _monitor_intro(con.device)


def _monitor_intro(dev: str) -> str:
    if dev == devcli.ROUTER:
        return "The router is in ROMMON: no operating system is loaded. Type help for its commands."
    return ("The switch stopped before its operating system loaded. Its flash is not read yet: flash_init reads "
            "it, boot carries on starting.")


def prompt(con) -> str | None:
    """The boot monitor's prompt; None when the device runs IOS."""
    if con.s.mode not in MONITORS:
        return None
    if con.s.mode == "rommon":
        return f"rommon {con.s.ctx if con.s.ctx.isdigit() else '1'} > "
    return "switch: "


def sync(con) -> dict:
    """The session follows the device: into its boot monitor when it is in
    one (a Break from the other console), out when it started."""
    rec = iosimage.device(con.lab.name, con.device)
    mon = rec.get("monitor", "")
    if mon and con.s.mode != mon:
        con.s.mode, con.s.ctx, con.s.ask = mon, str(rec.get("count", 1)), None
    elif not mon and con.s.mode in MONITORS:
        con.s.mode, con.s.ctx = "idle", ""
    return rec


def intercept(con, line: str) -> str | None:
    """Console.run's first look at a line: the Break, and every line typed
    at a boot monitor. None: IOS takes the line."""
    if line.strip("\r\n") == BREAK:
        out = brk(con)
        return "" if out is None else out
    rec = sync(con)
    if con.s.mode in MONITORS:
        return monitor(con, line, rec)
    return None


def banner(con) -> str | None:
    """Console.banner's first look: nothing in a boot monitor, and after a
    start without a configuration IOS's offer of its setup dialog."""
    from . import iosnv
    rec = sync(con)
    if con.s.mode in MONITORS:
        return ""
    if rec.get("dialog"):
        rec.pop("dialog")
        iosimage.put_device(con.lab.name, con.device, rec)
        iosnv.ask(con, "setup-dialog", "Would you like to enter the initial configuration dialog? [yes/no]: ",
                  on=_dialog)
        return "\n         --- System Configuration Dialog ---\n\n"
    return None


def _dialog(con, line: str, q: dict) -> str:
    from . import iosnv
    w = line.strip().lower()
    if w not in ("y", "yes", "n", "no"):
        iosnv.ask(con, "setup-dialog", q["prompt"], on=_dialog)
        return "% Please answer 'yes' or 'no'."
    con.s.mode, con.s.authed = "idle", False
    said = "" if w.startswith("n") else ("winlab's devices have no setup dialog: everything is typed at the "
                                          "command line.\n")
    return f"{said}\nPress RETURN to get started!"


# ------------------------------------------------------------------ the boot monitors
def _count(con, rec: dict) -> None:
    n = int(rec.get("count", 1)) + 1
    rec["count"] = n
    con.s.ctx = str(n)
    iosimage.put_device(con.lab.name, con.device, rec)


def monitor(con, line: str, rec: dict) -> str:
    text = line.strip()
    if not text:
        return ""
    words = text.split()
    cmd = words[0].lower()
    if con.s.mode == "rommon":
        out = _rommon(con, cmd, words[1:], rec)
    else:
        out = _loader(con, cmd, words[1:], rec)
    if con.s.mode in MONITORS:
        rec2 = iosimage.device(con.lab.name, con.device)
        if rec2.get("monitor"):
            _count(con, rec2)
    return out


def _vars(con, rec: dict) -> str:
    from . import iosnv
    own = ((((iosnv.load(con.lab.name) or {}).get("devices") or {}).get(con.device) or {}).get("own") or {})
    boot = ",".join(iosimage.boot_entries(own)) or "(not set)"
    lines = [f"BOOT={boot}"]
    if con.device == devcli.ROUTER:
        lines.append(f"CONFREG={next_register(rec)}")
    lines.append(f"MODEL={devcli.MODEL[devcli.device_kind(con.device)]}")
    return "\n".join(lines)


def _dir(con, rec: dict, arg: str) -> str:
    if con.device != devcli.ROUTER and not rec.get("flash_init"):
        return "The flash file system is not initialized: flash_init first"
    if arg and iosimage.flash_name(con.device, arg) is None:
        return f"unable to open {arg}: no such device"
    rows = iosimage.listing(con)
    out = [f"Directory of {iosimage.fs(con.device)}/", ""]
    out += [f"{i:>4}  {p}  {n:>10}  {name}" for i, (p, n, name) in enumerate(rows, 1)]
    return "\n".join(out)


def _rommon(con, cmd: str, args: list[str], rec: dict) -> str:
    if cmd in ("?", "help"):
        return "\n".join(ROMMON_HELP)
    if cmd == "confreg":
        if not args:
            return (f"Configuration register is {register(rec)}"
                    + (f" (the next start uses {next_register(rec)})" if next_register(rec) != register(rec) else "")
                    + "\nGive the new value as confreg 0x<hex>.")
        try:
            v = parse_reg(args[0])
        except ValueError:
            return f"confreg: bad value {args[0]}: give it as hex, 0x2102 for example"
        rec["next"] = v
        iosimage.put_device(con.lab.name, con.device, rec)
        return "\nYou must reset or power cycle for the new value to take effect"
    if cmd in ("reset", "i"):
        return restart(con, reason="")
    if cmd == "boot":
        image = ""
        if args:
            image = iosimage.flash_name(con.device, args[0]) or ""
            if not image:
                return f"boot: cannot open {args[0]}: give it as bootflash:<file>"
        return restart(con, reason="", image=image)
    if cmd == "dir":
        return _dir(con, rec, args[0] if args else "")
    if cmd == "set":
        return _vars(con, rec)
    if cmd == "alias":
        return "boot=boot\nr=repeat\ni=reset\n?=help"
    return f'monitor: command "{cmd}" not found'


def _loader(con, cmd: str, args: list[str], rec: dict) -> str:
    if cmd in ("?", "help"):
        return "\n".join(LOADER_HELP)
    if cmd == "flash_init":
        rec["flash_init"] = True
        iosimage.put_device(con.lab.name, con.device, rec)
        n = len(iosimage.listing(con))
        return (f"Initializing Flash...\nflashfs[0]: {n} files, 1 directories\n"
                f"flashfs[0]: {iosimage.FLASH_TOTAL['switch']} bytes total\n...done Initializing Flash.")
    if cmd == "dir":
        return _dir(con, rec, args[0] if args else "")
    if cmd == "rename":
        if not rec.get("flash_init"):
            return "The flash file system is not initialized: flash_init first"
        if len(args) != 2:
            return "usage: rename <source file> <destination file>"
        src, dst = (iosimage.flash_name(con.device, a) for a in args)
        if not src or not dst:
            return "rename: give both files as flash:<name>"
        return iosimage.move(con, src, dst)
    if cmd == "boot":
        image = iosimage.flash_name(con.device, args[0]) if args else ""
        if args and not image:
            return f"boot: cannot load {args[0]}: give it as flash:<file>"
        return restart(con, reason="", image=image or "")
    if cmd == "reset":
        return restart(con, reason="")
    if cmd == "set":
        return _vars(con, rec)
    return f"{cmd}: no such command (help lists them)"


# ------------------------------------------------------------------ IOS commands
def config_register(con, a) -> str:
    try:
        v = parse_reg(a[0] if a else "")
    except ValueError:
        raise devcli.CliError("% Invalid input detected at '^' marker.") from None
    rec = iosimage.device(con.lab.name, con.device)
    rec["next"] = v
    iosimage.put_device(con.lab.name, con.device, rec)
    return ""


def run_lines(lab, dev: str) -> list[str]:
    """show running-config: config-register when the next start is not the default."""
    if dev != devcli.ROUTER:
        return []
    nxt = next_register(iosimage.device(lab.name, dev))
    return [f"config-register {nxt}"] if nxt != DEFAULT_REG else []


def version_lines(con) -> dict:
    """What show version says about the image and the register."""
    rec = iosimage.device(con.lab.name, con.device)
    name, ver = iosimage.running_image(con.lab.name, con.device)
    if con.device == devcli.ROUTER:
        cur, nxt = register(rec), next_register(rec)
        reg = f"Configuration register is {cur}" + (f" (will be {nxt} at next reload)" if nxt != cur else "")
    else:
        reg = f"Configuration register is {SWITCH_REG}"
    return {"image": f"{iosimage.fs(con.device)}{name}", "version": ver, "register": reg}


def show_boot(con, a=None) -> str:
    from . import iosnv
    own = devcli.settings(con.lab, con.device)
    snap = ((iosnv.load(con.lab.name) or {}).get("devices") or {}).get(con.device) or {}
    rec = iosimage.device(con.lab.name, con.device)
    name, _ = iosimage.running_image(con.lab.name, con.device)
    lines = [f"BOOT variable = {';'.join(iosimage.boot_entries(own)) or '(not set)'}",
             f"BOOT in the startup configuration = {';'.join(iosimage.boot_entries(snap.get('own') or {})) or '(not set)'}",
             f"Running image = {iosimage.fs(con.device)}{name}"]
    if con.device == devcli.ROUTER:
        lines.append(f"Configuration register is {register(rec)}"
                     + (f" (will be {next_register(rec)} at next reload)" if next_register(rec) != register(rec) else ""))
    return "\n".join(lines)


def add_specs(con, add, U, E, C) -> None:
    iosimage.add_specs(con, add, U, E, C)
    add("show boot", lambda a: show_boot(con), "Boot and related environment variables", U)
    if con.device == devcli.ROUTER:
        add("config-register <line>", lambda a: config_register(con, a), "Define the configuration register", C)


# ------------------------------------------------------------------ graded checks
def _ips_back(lab, rec_ips: list[str]) -> list[str]:
    own = lab.devices.get(devcli.ROUTER, {})
    return [k[3:] for k in rec_ips if k not in own]


def check_router_recovered(lab) -> tuple[bool, str]:
    rec = iosimage.device(lab.name, devcli.ROUTER)
    r = rec.get("recovery")
    if not r:
        return False, ("the router has not started with NVRAM bypassed: Break in its boot window, "
                       "confreg 0x2142 at rommon, then reset")
    own = lab.devices.get(devcli.ROUTER, {})
    if r.get("hostname") and own.get("hostname") != r["hostname"]:
        return False, f"its configuration is not back: hostname is {own.get('hostname') or 'Router'}, was {r['hostname']}"
    missing = _ips_back(lab, r.get("ips") or [])
    if missing:
        return False, f"its configuration is not back: no address on {', '.join(missing)} (copy startup-config running-config)"
    return True, "the router started without its configuration and has it back"


def _secret_check(lab, dev: str, old: str) -> tuple[bool, str]:
    from . import iosnv
    own = lab.devices.get(dev, {})
    new = own.get("enable-secret", "")
    if not new:
        return False, f"{devcli.hostname(lab, dev)} has no enable secret: set a new one"
    if new == old:
        return False, f"{devcli.hostname(lab, dev)} still has the enable secret nobody knows"
    snap = ((iosnv.load(lab.name) or {}).get("devices") or {}).get(dev) or {}
    if (snap.get("own") or {}).get("enable-secret") != new:
        return False, f"the new enable secret is not saved: copy running-config startup-config on {devcli.hostname(lab, dev)}"
    return True, f"{devcli.hostname(lab, dev)} has a new enable secret, saved in NVRAM"


def check_router_secret(lab) -> tuple[bool, str]:
    r = iosimage.device(lab.name, devcli.ROUTER).get("recovery")
    if not r:
        return False, "no password recovery on the router yet"
    return _secret_check(lab, devcli.ROUTER, r.get("secret", ""))


def check_router_register(lab) -> tuple[bool, str]:
    rec = iosimage.device(lab.name, devcli.ROUTER)
    if not rec.get("recovery"):
        return False, "no password recovery on the router yet"
    nxt = next_register(rec)
    if nxt != DEFAULT_REG:
        return False, f"the register the next start uses is {nxt}: the router would come up empty again (config-register 0x2102)"
    return True, "the configuration register is back to 0x2102 for the next start"


def _office_switch(lab) -> str:
    sws = devcli.switches(lab)
    return "sw:office" if "office" in sws else (f"sw:{sws[0]}" if sws else "")


def check_switch_recovered(lab) -> tuple[bool, str]:
    from . import iosnv
    dev = _office_switch(lab)
    rec = iosimage.device(lab.name, dev) if dev else {}
    r = rec.get("recovery")
    if not r:
        return False, ("the switch has not started without config.text: Break in its boot window, flash_init, "
                       "rename flash:config.text flash:config.old, boot")
    snap = ((iosnv.load(lab.name) or {}).get("devices") or {}).get(dev) or {}
    if not snap or snap.get("erased"):
        return False, "config.text is still missing: the switch would start empty (rename it back and save)"
    own = lab.devices.get(dev, {})
    if r.get("hostname") and own.get("hostname") != r["hostname"]:
        return False, f"its configuration is not back: hostname is {own.get('hostname') or 'Switch'}, was {r['hostname']}"
    return True, "the switch started without its configuration, has it back and a config.text to start with"


def check_switch_secret(lab) -> tuple[bool, str]:
    dev = _office_switch(lab)
    r = iosimage.device(lab.name, dev).get("recovery") if dev else None
    if not r:
        return False, "no password recovery on the switch yet"
    return _secret_check(lab, dev, r.get("secret", ""))


def check_image_router(lab) -> tuple[bool, str]:
    img = iosimage.UPGRADE[devcli.ROUTER]
    meta = iosimage.files(lab.name, devcli.ROUTER).get(img.name)
    if meta is None:
        return False, f"{img.name} is not in bootflash: (copy tftp: bootflash:)"
    if not meta.get("valid") or meta.get("md5") != iosimage.published_md5(img):
        return False, f"the {img.name} in bootflash: does not verify: copy it again"
    return True, f"{img.name} is in bootflash: and verifies"


def check_image_boot(lab) -> tuple[bool, str]:
    from . import iosnv
    img = iosimage.UPGRADE[devcli.ROUTER]
    entry = f"bootflash:{img.name}"
    snap = ((iosnv.load(lab.name) or {}).get("devices") or {}).get(devcli.ROUTER) or {}
    saved = iosimage.boot_entries(snap.get("own") or {})
    if not saved or saved[0] != entry:
        return False, f"the startup configuration's first boot system line is not {entry} (boot system, then write memory)"
    name, ver = iosimage.running_image(lab.name, devcli.ROUTER)
    if name != img.name or ver != img.version:
        return False, f"the router runs {name} ({ver}): reload it to start the new image"
    return True, f"the router runs {img.version} and will again at its next start"


def check_image_archive(lab) -> tuple[bool, str]:
    cfgs = [n for n, m in iosimage.files(lab.name, devcli.ROUTER).items() if m.get("kind") == "config"]
    if not cfgs:
        return False, "no configuration file in bootflash: (copy running-config bootflash:<name> before the upgrade)"
    return True, f"a configuration archive in bootflash: ({', '.join(cfgs)})"


def check_image_switch(lab) -> tuple[bool, str]:
    dev = _office_switch(lab)
    img = iosimage.UPGRADE["switch"]
    name, ver = iosimage.running_image(lab.name, dev) if dev else ("", "")
    if name != img.name or ver != img.version:
        return False, f"the office switch runs {name or 'nothing known'} ({ver}), not {img.name}"
    return True, f"the office switch runs {img.version}"


def check_ts_register(lab) -> tuple[bool, str]:
    rec = iosimage.device(lab.name, devcli.ROUTER)
    if (rec.get("fault") or {}).get("id") != "confreg-left":
        return False, "the problem is not broken on this lab: press Break first"
    nxt = next_register(rec)
    if nxt != DEFAULT_REG:
        return False, f"the next start still uses {nxt}: the router would come up empty again"
    own = lab.devices.get(devcli.ROUTER, {})
    if not any(k.startswith("ip:") for k in own):
        return False, "the router has no interface addresses: its configuration is not back"
    from . import iosnv
    snap = ((iosnv.load(lab.name) or {}).get("devices") or {}).get(devcli.ROUTER) or {}
    if not any(k.startswith("ip:") for k in (snap.get("own") or {})):
        return False, "NVRAM holds no interface addresses: save the configuration"
    return True, "the register is 0x2102 again and the configuration is running and saved"


def check_ts_lockout(lab) -> tuple[bool, str]:
    from . import iosnv
    for dev in [f"sw:{s}" for s in devcli.switches(lab)]:
        f = iosimage.device(lab.name, dev).get("fault") or {}
        if f.get("id") != "switch-lockout":
            continue
        ok, why = _secret_check(lab, dev, f.get("secret", ""))
        if not ok:
            return ok, why
        own = lab.devices.get(dev, {})
        if own.get(f"shut:{f.get('label', '')}"):
            return False, "the PC's switch port is still shut down"
        snap = ((iosnv.load(lab.name) or {}).get("devices") or {}).get(dev) or {}
        if not snap or snap.get("erased") or (snap.get("own") or {}).get(f"shut:{f.get('label', '')}"):
            return False, "the switch's startup configuration still has the PC's port shut, or is missing"
        return True, f"{devcli.hostname(lab, dev)}: new enable secret saved, the PC's port up"
    return False, "the problem is not broken on this lab: press Break first"


def _register() -> None:
    from . import exercises
    for name, fn in (("iosboot-router-recovered", check_router_recovered),
                     ("iosboot-router-secret", check_router_secret),
                     ("iosboot-router-register", check_router_register),
                     ("iosboot-switch-recovered", check_switch_recovered),
                     ("iosboot-switch-secret", check_switch_secret),
                     ("iosimage-router-flash", check_image_router),
                     ("iosimage-router-boot", check_image_boot),
                     ("iosimage-config-archive", check_image_archive),
                     ("iosimage-switch-running", check_image_switch),
                     ("iosboot-ts-register", check_ts_register),
                     ("iosboot-ts-lockout", check_ts_lockout)):
        exercises.register_winlab_check(name, fn)


_register()


# ------------------------------------------------------------------ troubleshooting breaks
FAULT_IDS = ("router-confreg-left", "switch-locked-out")
VERIFY = ("gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}'); "
          "[ -n \"$gw\" ] && ping -c 2 -W 2 \"$gw\" >/dev/null 2>&1 && echo True || echo False")


def register_faults(reg) -> None:
    from .guestfaults import LINUX, GuestFault
    reg(GuestFault(
        id="router-confreg-left",
        host="ios-confreg",
        title="The router's configuration register was left at 0x2142 after a password recovery",
        os=LINUX,
        shell="sh",
        images=("ubuntu",),
        teaches="the configuration register's bit that skips NVRAM, show version's register line, and finishing "
                "a password recovery properly",
        symptom="after a short power cut the router came back with no configuration at all: no addresses, the PCs "
                "cannot reach their gateway, yet show startup-config still has everything",
        apply="echo 'this problem is set from outside the machine: winlab changes the router and cuts the power'",
        clear="echo 'config-register 0x2102 on the router, then copy startup-config running-config'",
        hints=(
            "On the router's console: show running-config is a factory one, show startup-config is the office's. "
            "The router did not lose its configuration; it did not load it. What decides that at start-up?",
            "show version, last line: the configuration register. A value with the 0x0040 bit set (0x2142) tells "
            "the router to ignore NVRAM when it starts: the setting a password recovery uses, left behind.",
            "enable (no secret now), copy startup-config running-config, then configure terminal, "
            "config-register 0x2102, end, copy running-config startup-config. show version says it will be "
            "0x2102 at the next reload; the PCs reach their gateway again at once.",
        ),
        verify=VERIFY,
    ))
    reg(GuestFault(
        id="switch-locked-out",
        host="ios-lockout",
        title="Nobody knows the switch's passwords, and this PC's port on it is shut down",
        os=LINUX,
        shell="sh",
        images=("ubuntu",),
        teaches="switch password recovery from the boot loader (flash_init, config.text renamed), keeping the "
                "configuration, and saving new secrets",
        symptom="this PC has no network since the power cut; its port on the switch is down, and the console asks "
                "for a password nobody has",
        apply="echo 'this problem is set from outside the machine: winlab changes the switch and cuts the power'",
        clear="echo 'recover the switch from its boot loader and bring the PC port up'",
        hints=(
            "The console line asks for a password, and enable would too. Nobody has them: the only way in is "
            "the switch's own recovery, which needs its boot loader. When does a switch listen for that?",
            "Power the switch off and on (its power switch, or the network's power), and press Ctrl+C on its "
            "console while it starts: the switch: prompt. flash_init, dir flash:, then rename "
            "flash:config.text flash:config.old and boot. It starts with no configuration and no passwords.",
            "enable, rename flash:config.old flash:config.text, copy flash:config.text running-config, then "
            "configure terminal: enable secret <new>, line con 0 / password <new>, interface <the PC's port> / "
            "no shutdown, end, copy running-config startup-config. The PC gets its link back.",
        ),
        verify=VERIFY,
    ))


def _power_cut(lab_name: str) -> bool:
    """The lab's network loses power: the lab router (and the switches on
    it) stop at once, as the power-cut action does."""
    from . import state as st_mod
    from .orchestrator import _kill
    st = st_mod.load(lab_name)
    ns = st.nodes.get("fabric") if st else None
    if not ns or not ns.pid or not st_mod.pid_alive(ns.pid):
        return False
    _kill(ns.pid)
    ns.pid, ns.phase = 0, "stopped"
    st_mod.save(st)
    return True


def _shadow_write(lab, dev: str, edit=None) -> None:
    """NVRAM written for a device from outside its console, as if its
    running configuration had been saved with `edit` applied: the snapshot
    and the text show startup-config prints."""
    import copy
    from . import iosnv, netplan, tftpcopy
    cp = copy.deepcopy(lab)
    devcli.pin_router_ports(cp)   # the router's addresses by port name, as its console keeps them
    if edit:
        edit(cp.devices.setdefault(dev, {}))
    plan = netplan.compile_topology(cp, check_ports=False)
    sh = devcli.Console(tftpcopy._Shadow(cp, plan), dev, runner_factory=lambda: (None, "the device is off"),
                        link=lambda l, up: None)
    sh._save = lambda live=True: ""
    sh.powered = lambda: True
    sh._fresh = lambda: None
    sh.s.mode, sh.s.authed = "enable", True
    iosnv.write(sh)


def _load(lab_name: str):
    from . import schema
    return schema.load(lab_name)


CUT = ("the power went off in the comms room for a moment: the router and its switches are off. Power the "
       "router on again (the lab's network) and see what comes back")
NOT_RUNNING = "the router was off: power it on (the lab's network) and see what comes back"


def confreg_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    try:
        lab = _load(lab_name)
        rec = iosimage.device(lab_name, devcli.ROUTER)
        if clear:
            rec["next"] = DEFAULT_REG
            rec.pop("fault", None)
            iosimage.put_device(lab_name, devcli.ROUTER, rec)
            return True, ("the register is 0x2102 again for the next start: copy startup-config running-config "
                          "on the router, or power it off and on")
        _shadow_write(lab, devcli.ROUTER)
        rec = iosimage.device(lab_name, devcli.ROUTER)
        rec["next"] = "0x2142"
        rec["fault"] = {"id": "confreg-left", "t": time.time()}
        iosimage.put_device(lab_name, devcli.ROUTER, rec)
    except Exception as exc:  # noqa: BLE001 - a lab that does not load cannot be broken
        return False, str(exc)
    return True, CUT if _power_cut(lab_name) else NOT_RUNNING


def _random_word() -> str:
    return secrets.token_urlsafe(12)


def lockout_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    from . import iosnv, netplan
    try:
        lab = _load(lab_name)
        plan = netplan.compile_topology(lab, check_ports=False)
        where = devcli.port_no(lab, plan, f"{node}:nic0")
        if not where:
            return False, f"{node} is not cabled to a switch port"
        dev, label = f"sw:{where[0]}", f"{node}:nic0"
        rec = iosimage.device(lab_name, dev)
        if clear:
            planted = (rec.get("fault") or {})

            def undo(own: dict) -> None:
                if own.get("enable-secret") == planted.get("secret"):
                    own.pop("enable-secret", None)
                if planted:
                    for k in (LINE_CON_PW, "line-con:login", f"shut:{label}"):
                        own.pop(k, None)
            _shadow_write(lab, dev, undo)
            rec.pop("fault", None)
            iosimage.put_device(lab_name, dev, rec)
            return True, "the switch's startup configuration is back as it was: power the network off and on"
        secret = "9 " + iosnv.type9(_random_word())
        line_pw = "7 " + iosnv.type7(_random_word()[:20])

        def plant(own: dict) -> None:
            own.update({"enable-secret": secret, "line-con:login": "yes", f"shut:{label}": "yes"})
            own[LINE_CON_PW] = line_pw
        _shadow_write(lab, dev, plant)
        rec = iosimage.device(lab_name, dev)
        rec["fault"] = {"id": "switch-lockout", "secret": secret, "label": label, "t": time.time()}
        iosimage.put_device(lab_name, dev, rec)
    except Exception as exc:  # noqa: BLE001 - a lab that does not load cannot be broken
        return False, str(exc)
    return True, CUT if _power_cut(lab_name) else NOT_RUNNING
