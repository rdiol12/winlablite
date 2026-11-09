"""A server's firmware versions, updated through its BMC the way a real one is.

A server with a management port (winlab/power.py) has two firmware images
its BMC keeps an inventory of: the BMC's own (an active image and the one
before it, the backup, as OpenBMC keeps two) and the server's BIOS (UEFI).
The BMC lists them in Redfish (UpdateService/FirmwareInventory, the
Manager's FirmwareVersion, the system's BiosVersion) and takes a new image
the way bmcweb does: the package POSTed to UpdateService's HttpPushUri as
the request body, which OpenBMC's web UI does from its Firmware page.

What the BMC checks before it takes an image (content/agent/bmc.sh) is what
a real one checks, minus the vendor's signature: the package is a tar with
an OpenBMC style MANIFEST (purpose, version, MachineName), the machine name
is this server's model, and the image's SHA-256 is the one its MANIFEST
names. A real vendor signs its packages and the BMC checks that signature
against a key in its own firmware; winlab's packages carry no signature and
the lessons say so. The student checks the package against the vendor's
published SHA256SUMS before uploading, which is the habit that matters.

What changes, and when, is what changes on a real server:

* A BMC image is activated at once and the BMC restarts on it; the image it
  replaced becomes the backup, and switching back is a PATCH of the
  Manager's Links.ActiveSoftwareImage (webui-vue's "Switch to backup image").
* A BIOS image is staged. It is written while the server is off: at its next
  power-on from off (a power cycle, or off then on), never at a warm reset.
  From then on the server's SMBIOS type 0 (BIOS vendor, version and release
  date) says the new version, which Windows reads in Win32_BIOS and Linux in
  dmidecode. That is the honest limit of a lab: the UEFI code that runs is
  still QEMU's edk2 build; the version the firmware reports is the one the
  BMC wrote.

The packages themselves are winlab's own (a header that says what they are
and filler bytes), made on this PC and burned to the "SRV_FIRMWARE" disc on
the lab's media shelf with the vendor's release notes and SHA256SUMS, and one
package for another model that the BMC must refuse. Versions are kept in the
lab's power.json (firmware) so a rebuilt router gives the BMC the same ones.
"""

from __future__ import annotations

import hashlib
import io
import re
import tarfile
import tempfile
from pathlib import Path

VENDOR = "winlab"
MACHINE = "WL-R200"          # the server's model (identity.MODELS["server"]), the packages' MachineName
DEFAULTS = {"bmc": "2.14.0", "bmc_backup": "2.13.1", "bios": "1.2.0", "bios_date": "03/14/2025"}
PURPOSE = {"bmc": "xyz.openbmc_project.Software.Version.VersionPurpose.BMC",
           "bios": "xyz.openbmc_project.Software.Version.VersionPurpose.Host"}
IMAGE_FILE = {"bmc": "image-bmc", "bios": "image-bios"}
IMAGE_KB = 192
# The vendor's support disc: (kind, version, machine, release date, what it fixes)
RELEASES = (
    ("bmc", "2.15.0", MACHINE, "08/18/2026",
     "BMC 2.15.0: fixes the web session timeout ignoring its setting; adds TLS 1.3 to the Redfish service."),
    ("bios", "1.4.0", MACHINE, "09/02/2026",
     "BIOS 1.4.0: processor microcode update; fixes NVMe drives not shown in the boot menu after a hot swap."),
    ("bios", "2.0.1", "WL-R300", "07/30/2026",
     "BIOS 2.0.1 for the R300 only (a different board): not for the R200."),
)
DISC_LABEL = "SRV_FIRMWARE"
_VER = re.compile(r"^[0-9A-Za-z._-]{1,32}$")
_DATE = re.compile(r"^[0-9]{2}/[0-9]{2}/[0-9]{4}$")


def package_name(kind: str, version: str, machine: str = MACHINE) -> str:
    model = machine.split("-")[-1].lower()
    return f"{model}-{kind}-{version}.tar"


def image_bytes(kind: str, version: str, machine: str = MACHINE) -> bytes:
    """The image: a header saying what it is, then filler that depends on
    the version (so two versions have different hashes)."""
    head = (f"{VENDOR.upper()} {machine} {kind.upper()} FIRMWARE IMAGE {version}\n"
            "A winlab lab image: carried, checked and recorded like a real one; it holds no code.\n").encode()
    out = bytearray(head)
    seed = hashlib.sha256(f"{machine}/{kind}/{version}".encode()).digest()
    while len(out) < IMAGE_KB * 1024:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return bytes(out[:IMAGE_KB * 1024])


def manifest(kind: str, version: str, machine: str, date: str, image: bytes) -> str:
    return (f"purpose={PURPOSE[kind]}\nversion={version}\nMachineName={machine}\n"
            f"ReleaseDate={date}\nImageFile={IMAGE_FILE[kind]}\nHashType=SHA256\n"
            f"ImageSHA256={hashlib.sha256(image).hexdigest()}\n")


def package(kind: str, version: str, machine: str = MACHINE, date: str = "01/01/2026",
            image: bytes | None = None) -> bytes:
    """The update package as the BMC takes it: a tar of MANIFEST and the
    image, made the same byte for byte every time."""
    img = image_bytes(kind, version, machine) if image is None else image
    good = image_bytes(kind, version, machine)
    files = [("MANIFEST", manifest(kind, version, machine, date, good).encode()), (IMAGE_FILE[kind], img)]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in files:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode, ti.uname, ti.gname = len(data), 1767225600, 0o644, "root", "root"
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def write_disc(folder: Path) -> list[str]:
    """The vendor's support disc's files into a folder: the packages, their
    SHA256SUMS and the release notes."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    sums, notes = [], [f"{VENDOR} server firmware support disc", "",
                       "Check each package against SHA256SUMS.txt before you upload it to the BMC",
                       "(Get-FileHash <file> -Algorithm SHA256, or sha256sum <file>).",
                       "Read the model: each package is for one server model only.", ""]
    names = []
    for kind, ver, machine, date, what in RELEASES:
        name = package_name(kind, ver, machine)
        data = package(kind, ver, machine, date)
        (folder / name).write_bytes(data)
        sums.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
        notes += [f"{name}  (model {machine}, released {date})", f"  {what}", ""]
        names.append(name)
    notes += ["A BMC image is activated at once and the BMC restarts on it; the old image is kept as the backup.",
              "A BIOS image is staged by the BMC and written while the server is off: power-cycle the server",
              "(or shut it down and power it on) in a maintenance window. A warm restart does not apply it."]
    (folder / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8", newline="\r\n")
    (folder / "RELEASE-NOTES.txt").write_text("\n".join(notes) + "\n", encoding="utf-8", newline="\r\n")
    return names


def ensure_disc(lab_name: str) -> str:
    """The support disc on the lab's media shelf (burned once); its title,
    or '' when it could not be made."""
    from . import mediashelf
    try:
        if any(d["title"] == DISC_LABEL for d in mediashelf.discs(lab_name)):
            return DISC_LABEL
        with tempfile.TemporaryDirectory() as td:
            write_disc(Path(td) / "fw")
            return mediashelf.burn(lab_name, Path(td) / "fw", DISC_LABEL)["title"]
    except Exception:  # noqa: BLE001 - the port is fitted either way
        return ""


# ------------------------------------------------------------------ the versions
def state(lab_name: str, node_id: str) -> dict:
    """The server's firmware now: bmc, bmc_backup, bios, bios_date and, when
    a BIOS image waits to be written, pending and pending_date."""
    from . import power
    rec = (power.load(lab_name).get("firmware") or {}).get(node_id) or {}
    out = dict(DEFAULTS)
    for k in ("bmc", "bmc_backup", "bios", "bios_date", "pending", "pending_date"):
        v = str(rec.get(k) or "")
        if v and (_DATE if k.endswith("date") else _VER).match(v):
            out[k] = v
    return out


def _save(lab_name: str, node_id: str, fn) -> dict:
    from . import power

    def change(data):
        fw = data.setdefault("firmware", {})
        cur = dict(state(lab_name, node_id))
        cur.update((fw.get(node_id) or {}))
        fn(cur)
        fw[node_id] = {k: v for k, v in cur.items() if v}
        return fw[node_id]
    return power._update(lab_name, change)


def keep(lab_name: str, node_id: str, arg: str) -> tuple[str, str]:
    """A firmware request the BMC queued (Firmware=<arg>), kept for good:
    bmc:<version>, bmc-switch, or bios:<version>:<date>."""
    kind, _, rest = arg.partition(":")
    if kind == "bmc-switch":
        def swap(c):
            c["bmc"], c["bmc_backup"] = c["bmc_backup"], c["bmc"]
        s = _save(lab_name, node_id, swap)
        return "Info", f"BMC firmware: switched to image {s['bmc']} (backup {s['bmc_backup']})"
    if kind == "bmc" and _VER.match(rest):
        def act(c):
            if c["bmc"] != rest:
                c["bmc_backup"], c["bmc"] = c["bmc"], rest
        s = _save(lab_name, node_id, act)
        return "Info", f"BMC firmware {s['bmc']} active (backup {s['bmc_backup']})"
    ver, _, date = rest.partition(":")
    if kind == "bios" and _VER.match(ver) and _DATE.match(date):
        def stage(c):
            c["pending"], c["pending_date"] = ver, date
        _save(lab_name, node_id, stage)
        return "Info", f"BIOS firmware {ver} staged: written at the server's next power-on from off"
    return "Warning", f"Firmware request {arg!r} not understood"


def power_on(lab_name: str, node_id: str) -> str:
    """The server powered on from off: a staged BIOS image is written now.
    What the BMC's log says, or '' when nothing was staged."""
    s = state(lab_name, node_id)
    if not s.get("pending"):
        return ""

    def write(c):
        c["bios"], c["bios_date"] = c.pop("pending", c["bios"]), c.pop("pending_date", c["bios_date"])
    old = s["bios"]
    s = _save(lab_name, node_id, write)
    return f"BIOS firmware updated from {old} to {s['bios']} at power-on"


def router_lines(lab_name: str, node_id: str, d: str) -> list[str]:
    """The BMC's firmware files on the router (power.render, and after a
    BIOS image was written)."""
    s = state(lab_name, node_id)
    pend = f"{s['pending']} {s['pending_date']}" if s.get("pending") else ""
    return [f"printf '%s\\n' '{MACHINE}' > {d}/machine; printf '%s\\n' '{s['bmc']}' > {d}/fw_bmc; "
            f"printf '%s\\n' '{s['bmc_backup']}' > {d}/fw_bmc_backup",
            f"printf '%s\\n' '{s['bios']} {s['bios_date']}' > {d}/fw_bios; "
            + (f"printf '%s\\n' '{pend}' > {d}/fw_bios_pending" if pend else f"rm -f {d}/fw_bios_pending")]


def smbios_args(lab_name: str, node) -> list[str]:
    """SMBIOS type 0 for a server with a management port: its BIOS vendor,
    version and release date. A staged image counts: QEMU reads these only
    when the machine starts from off, which is when the BMC writes it."""
    from . import power
    if not power.fitted(node):
        return []
    s = state(lab_name, node.id)
    ver, date = (s["pending"], s["pending_date"]) if s.get("pending") else (s["bios"], s["bios_date"])
    return ["-smbios", f"type=0,vendor={VENDOR},version={ver},date={date}"]
