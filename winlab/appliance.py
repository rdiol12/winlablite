"""Office devices on the network: a network printer, a NAS, a phone system
and IP phones.

Each is a small Alpine machine on the lab's network, with its own network
card and MAC address, that gets its address the way the real device does
(DHCP from the router, or the one the lab gives it) and runs its "firmware"
at every power-on: the ``netprinter`` role (content/roles), say. Windows
reaches them as it reaches the real ones: the printer's CUPS over IPP on 631
(its web pages there too, where the student sets up its queue) or a Standard
TCP/IP port on 9100. The NAS is the exception in what it runs: a Debian
machine whose firmware is OpenMediaVault (winlab/omv.py), managed from its
own web UI. The Admin workstation (``admin-desktop``) is a small Linux
desktop with Firefox, to open those pages from inside the lab.

The phone system (``pbx``) is FreePBX 17 on a Debian 12 machine and each IP
phone (``ipphone``) a softphone on its own screen (winlab/voip.py): the
student makes the extensions in FreePBX's web pages and signs each phone in
on the phone, so nothing about them is kept or shown here.

This module is the host side: what the workbench shows on their panels
(the printer's output tray, which is its paper: CUPS is managed in its own
pages) and the changes made there.
"""

from __future__ import annotations

import re
import shlex

from . import state
from .guestctl import GuestChannel, GuestError

TRAY = "/var/spool/tray"
MAX_JOB = 256 * 1024
# Shelf entries: what each device is when it is added to a network.
DEVICES = {
    "printer": {"title": "Printer", "prefix": "prn", "role": "netprinter", "memory_mb": 768, "disks": [1],
                "text": "a network laser printer running CUPS: its queues are set up in its web pages, "
                        "Windows prints to it over IPP or TCP/IP, pages land in its tray"},
    # OpenMediaVault on Debian (winlab/omv.py): it wants a gigabyte.
    "nas": {"title": "NAS", "prefix": "nas", "role": "nas", "memory_mb": 1024, "disks": [64],
            "image": "debian13-cloud",
            "text": "network storage (OpenMediaVault): a data disk in its bay; file systems, shares, "
                    "users and SMB/NFS set up in its web UI"},
    # A softphone on its screen (GNOME Calls) and a 1 GB flash disk for its settings.
    "phone": {"title": "IP phone", "prefix": "phone", "role": "ipphone", "memory_mb": 1024, "disks": [1],
              "text": "a desk phone: a SIP softphone on its screen; you sign it in to the phone system yourself"},
    # FreePBX 17 on Debian 12 (winlab/voip.py): Apache, MariaDB, PHP and Asterisk want 2 GB.
    "pbx": {"title": "Phone system", "prefix": "pbx", "role": "pbx", "memory_mb": 2048, "disks": [],
            "image": "debian12",
            "text": "the office PBX: FreePBX 17 on Asterisk, managed from a lab PC's browser; no extensions until you make them"},
    # An IP camera (content/roles/ipcam.sh): its web pages and a snapshot on
    # port 80, set up from a lab PC's browser; PoE-powered on a site job.
    "camera": {"title": "IP camera", "prefix": "cam", "role": "ipcam", "memory_mb": 512, "disks": [],
               "text": "an IP camera: takes its address by DHCP, its own web pages set its name, time and "
                       "admin password; its live view on its home page"},
    "ntp": {"title": "NTP server", "prefix": "ntp", "role": "ntp-server", "memory_mb": 512, "disks": [],
            "text": "a time server (chrony): serves lab time to the PDC emulator and the Linux machines, no upstream"},
    "san": {"title": "SAN", "prefix": "san", "role": "san", "memory_mb": 768, "disks": [],
            "text": "an iSCSI storage array (winlab/san.py): empty drive bays and two ports; RAID groups, volumes and targets built in its Webmin"},
    # The admin's documentation tools (winlab/doctools.py): a plain Debian 12
    # server on which the student installs GLPI, DokuWiki and Vaultwarden.
    "doctools": {"title": "Admin tools server", "prefix": "tools", "role": "doc-tools", "memory_mb": 2048,
                 "disks": [], "image": "debian12",
                 "text": "a plain Debian 12 server for the IT department's own tools: GLPI, DokuWiki and "
                         "Vaultwarden, installed by you from their packs and managed from a lab PC's browser"},
    # Network operations (winlab/netops.py): a plain Debian 12 server on which
    # the student runs LibreNMS (with MariaDB), Oxidized and Uptime Kuma; 3 GB
    # for the four of them and Docker.
    "netops": {"title": "Network operations server", "prefix": "nms", "role": "net-ops", "memory_mb": 3072,
               "disks": [], "image": "debian12",
               "text": "a plain Debian 12 server for the network team's tools: LibreNMS, Oxidized and Uptime "
                       "Kuma, installed by you from their packs and managed from a lab PC's browser"},
    "adminpc": {"title": "Admin workstation", "prefix": "admin", "role": "admin-desktop", "memory_mb": 1536,
                "disks": [],
                "text": "a small Linux desktop with Firefox ESR on its screen: a browser on the lab network "
                        "to open the devices' own pages"},
}


class ApplianceError(Exception):
    pass


# ---- the printer's management pages: CUPS, served on the lab network.
CUPS_PORT = 631


def _admin_gui(lab, node):
    from .adminui import AdminGui
    if device_of(node) == "camera":
        return AdminGui(software="camera firmware (BusyBox httpd)", scheme="http", port=80, path="/",
                        sign_in="admin, with the password you set on its first page", license="GPL-2.0",
                        note="Out of the box it asks for a new admin password: there is no default one.")
    if device_of(node) == "printer":
        return AdminGui(software="CUPS 2.4", scheme="https", port=CUPS_PORT, path="/",
                        sign_in="root, with the lab's password (Start > Lab password), when CUPS asks",
                        license="Apache-2.0",
                        note="CUPS signs its pages with its own self-signed certificate: accept the browser's "
                             "warning once.")
    return None


def device_of(node) -> str:
    """The device a machine is ('printer', 'nas', 'adminpc', ...: a key of
    DEVICES), or '' for any other machine: a device is its role on the image
    it is built on (Alpine, or Debian for the NAS)."""
    for dev, d in DEVICES.items():
        if d["role"] in node.roles and node.image == d.get("image", "alpine"):
            return dev
    return ""


QUICK_CONNECT = 2.0  # seconds: a panel's look at a device does not wait for it to boot


def _channel(lab_name: str, node_id: str, factory=GuestChannel, wait: bool = False):
    """The device's agent channel. A panel's view (``wait`` False) tries
    once and says "still starting" at once rather than hold the request
    for a device that is booting; a change the user asked for (``wait``)
    gives it a few seconds."""
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not state.pid_alive(ns.pid) or not ns.serial_port:
        raise ApplianceError(f"{node_id} is off: power it on first")
    try:
        ch = factory(ns.serial_port)
        if wait:
            return ch.connect(retries=4, delay=2)
        return ch.connect(retries=1, connect_timeout=QUICK_CONNECT)
    except (GuestError, OSError) as exc:
        raise ApplianceError(f"{node_id} is still starting ({exc})") from None


def tray(lab_name: str, node_id: str, factory=GuestChannel) -> list[dict]:
    """The jobs in the printer's output tray, newest first."""
    ch = _channel(lab_name, node_id, factory)
    try:
        r = ch.run(f"cd {TRAY} 2>/dev/null && ls -1 *.prn 2>/dev/null | while read f; do "
                   "echo \"$f $(wc -c < \"$f\")\"; done", shell="sh", timeout=30)
    except GuestError as exc:
        raise ApplianceError(f"{node_id}: {exc}") from None
    finally:
        ch.close()
    out = []
    for line in r.out.splitlines():
        name, _, size = line.strip().partition(" ")
        if name.endswith(".prn") and size.isdigit():
            out.append({"job": name, "bytes": int(size), "when": _when(name)})
    return sorted(out, key=lambda j: j["job"], reverse=True)


def _when(name: str) -> str:
    m = re.match(r"(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)", name)
    return f"{m[1]}-{m[2]}-{m[3]} {m[4]}:{m[5]}:{m[6]}" if m else ""


def job_text(lab_name: str, node_id: str, job: str, factory=GuestChannel) -> dict:
    """One job, as far as it reads as a page: the text a Generic / Text Only
    driver sends, or what can be read out of PCL; the kind it is."""
    if not re.fullmatch(r"[0-9-]+\.prn", job):
        raise ApplianceError("no such job")
    ch = _channel(lab_name, node_id, factory)
    try:
        r = ch.run(f"head -c {MAX_JOB} {shlex.quote(TRAY + '/' + job)} | base64", shell="sh", timeout=60)
    except GuestError as exc:
        raise ApplianceError(f"{node_id}: {exc}") from None
    finally:
        ch.close()
    import base64
    try:
        data = base64.b64decode("".join(r.out.split()))
    except ValueError:
        raise ApplianceError("the job could not be read") from None
    return {"job": job, **readable(data)}


def readable(data: bytes) -> dict:
    """What a print job holds, for the tray: its kind and its text."""
    head = data[:4096]
    if head.startswith(b"%PDF"):
        kind = "PDF"
    elif head.startswith(b"%!"):
        kind = "PostScript"
    elif b"PCLXL" in head.upper() or b"HP-PCL XL" in head:
        kind = "PCL XL"
    elif b"\x1b%-12345X" in head or b"@PJL" in head:
        kind = "PCL"
    elif b"\x1bE" in head[:16] or b"\x1b&" in head:
        kind = "PCL"
    else:
        kind = "text"
    if kind == "PCL XL" or kind == "PDF":
        return {"kind": kind, "text": "", "pages": data.count(b"\x0c") or 1}
    text = data.decode("latin-1")
    text = re.sub(r"\x1b%-12345X(@PJL[^\n]*\n)*", "", text)       # PJL job header
    text = re.sub(r"@PJL[^\n]*\n", "", text)
    text = re.sub(r"\x1b[&*(][a-zA-Z0-9.,+-]*?[A-Z@]", "", text)  # PCL parameterised escapes
    text = re.sub(r"\x1b.", "", text)
    text = "".join(ch for ch in text.replace("\r\n", "\n").replace("\r", "\n")
                   if ch in "\n\t\x0c" or 32 <= ord(ch) < 127 or ord(ch) >= 160)
    text = text.strip("\x0c\n")
    return {"kind": kind, "text": text, "pages": text.count("\x0c") + 1}


def clear_tray(lab_name: str, node_id: str, factory=GuestChannel) -> None:
    ch = _channel(lab_name, node_id, factory, wait=True)
    try:
        ch.run(f"rm -f {TRAY}/*.prn", shell="sh", timeout=30)
    except GuestError as exc:
        raise ApplianceError(f"{node_id}: {exc}") from None
    finally:
        ch.close()


# ---- the printer's front panel: its engine's sensors (content/roles/netprinter.sh)
PANEL = "/var/lib/printer-panel"
# What each button or physical move does to the flags: (touch, remove).
PRINTER_OPS = {
    "paper-out": ({"nopaper"}, set()),            # the tray runs out of paper
    "load-paper": (set(), {"nopaper"}),
    "jam": ({"jam"}, set()),                      # a sheet jams in the engine
    "door-open": ({"door-open"}, {"jam"}),        # opening the door is where a jam is cleared
    "door-close": (set(), {"door-open"}),
    "online": (set(), {"offline"}),               # the Online button
    "offline": ({"offline"}, set()),
    "toner-low": ({"toner-low"}, set()),
    "toner-empty": ({"toner-low", "toner-empty"}, set()),   # the cartridge runs out: the engine stops
    "toner-new": (set(), {"toner-low", "toner-empty"}),     # a new cartridge, with the door open
    "cancel": ({"cancel"}, set()),                # the Cancel button: the job waiting in the engine
}
_FLAGS = ("nopaper", "jam", "door-open", "offline", "toner-low", "toner-empty", "busy")


def printer_panel(lab_name: str, node_id: str, factory=GuestChannel) -> dict:
    """What the printer's control panel shows: its engine's state, the
    toner, a job waiting in the engine, the jobs CUPS has not finished,
    the pages in the tray."""
    ch = _channel(lab_name, node_id, factory)
    try:
        r = ch.run(f"cd {PANEL} 2>/dev/null && for f in {' '.join(_FLAGS)}; do [ -e $f ] && echo flag $f; done; "
                   "echo jobs $(lpstat -o 2>/dev/null | wc -l); echo tray $(ls -1 " + TRAY + "/*.prn 2>/dev/null | wc -l)",
                   shell="sh", timeout=20)
    except GuestError as exc:
        raise ApplianceError(f"{node_id}: {exc}") from None
    finally:
        ch.close()
    return panel_state(r.out)


def panel_state(text: str) -> dict:
    flags, jobs, pages = set(), 0, 0
    for line in text.splitlines():
        k, _, v = line.strip().partition(" ")
        if k == "flag" and v in _FLAGS:
            flags.add(v)
        elif k == "jobs" and v.strip().isdigit():
            jobs = int(v)
        elif k == "tray" and v.strip().isdigit():
            pages = int(v)
    state_ = ("door-open" if "door-open" in flags else "jam" if "jam" in flags else
              "paper-out" if "nopaper" in flags else "toner-empty" if "toner-empty" in flags else
              "offline" if "offline" in flags else
              "printing" if "busy" in flags or jobs else "ready")
    return {"state": state_, "door": "door-open" in flags, "paper": "nopaper" not in flags,
            "toner_low": "toner-low" in flags, "toner_empty": "toner-empty" in flags,
            "online": "offline" not in flags,
            "waiting": "busy" in flags, "jobs": jobs, "pages": pages}


def printer_op(lab_name: str, node_id: str, op: str, factory=GuestChannel) -> dict:
    """A button on the printer's panel, or a hand on it (paper, the door,
    the cartridge)."""
    if op not in PRINTER_OPS:
        raise ApplianceError(f"the printer has no {op!r}")
    if op == "toner-new":
        now = printer_panel(lab_name, node_id, factory)
        if not now["door"]:
            raise ApplianceError("open the front door to change the toner cartridge")
    add, drop = PRINTER_OPS[op]
    cmd = f"mkdir -p {PANEL}; cd {PANEL}" + "".join(f"; touch {f}" for f in sorted(add)) + \
          "".join(f"; rm -f {f}" for f in sorted(drop))
    ch = _channel(lab_name, node_id, factory, wait=True)
    try:
        ch.run(cmd, shell="sh", timeout=20)
    except GuestError as exc:
        raise ApplianceError(f"{node_id}: {exc}") from None
    finally:
        ch.close()
    return printer_panel(lab_name, node_id, factory)


# ---- a desk phone's display: its line, as the phone system sees it
def phone_line(lab, node, seen: set[str] | None = None, factory=GuestChannel) -> dict:
    """Whether a phone is signed in to the phone system, and as which
    extension: Asterisk's own registrations (pjsip show contacts on the
    PBX), matched by the phone's addresses (its own, and `seen`, those the
    router saw it use). Nothing is read from or written to the phone."""
    from . import naming
    pbx = pbx_of(lab)
    if pbx is None:
        return {"ok": True, "pbx": "", "ext": "", "registered": False, "why": "no phone system"}
    ips = {n.ip for n in node.nics if n.ip} | set(seen or ())
    try:
        ch = _channel(lab.name, pbx.id, factory)
    except ApplianceError as exc:
        return {"ok": True, "pbx": naming.display(lab, pbx.id), "ext": "", "registered": False, "why": str(exc)}
    try:
        r = ch.run("asterisk -rx 'pjsip show contacts' 2>/dev/null", shell="sh", timeout=20)
    except GuestError as exc:
        return {"ok": True, "pbx": naming.display(lab, pbx.id), "ext": "", "registered": False, "why": str(exc)}
    finally:
        ch.close()
    return {"ok": True, "pbx": naming.display(lab, pbx.id), **contacts_for(r.out, ips)}


def contacts_for(text: str, ips: set[str]) -> dict:
    """The extension registered from one of these addresses, from
    `pjsip show contacts`: 'Contact:  101/sip:101@10.40.0.60:5060;ob ...'."""
    for m in re.finditer(r"Contact:\s+(\S+?)/sip:[^@\s]*@\[?([0-9a-fA-F.:]+?)\]?(?::\d+)?[;\s]\S*\s+\S+\s+(\w+)", text):
        ext, ip, status = m.group(1), m.group(2), m.group(3)
        if ip in ips:
            return {"ext": ext, "registered": status.lower() in ("avail", "nonqual", "reachable"), "why": status}
    return {"ext": "", "registered": False, "why": "not registered"}


def pbx_of(lab):
    """The lab's phone system, if it has one."""
    return next((n for n in lab.node_list() if "pbx" in n.roles), None)


def _register() -> None:
    from . import adminui
    adminui.register(node_gui=_admin_gui)


_register()
