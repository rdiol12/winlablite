"""Each machine's own identity in its firmware: maker, model, serial
number, asset tag and UUID, as the sticker on a real PC's case shows them.

A real PC has a serial number and a system UUID in its SMBIOS tables, and
an asset tag that the company's IT puts on it. Windows reads them
(``Get-CimInstance Win32_BIOS``, ``Win32_SystemEnclosure``,
``Win32_ComputerSystemProduct``), and so does every inventory tool: the GLPI
Agent sends them to GLPI, which tells one computer from another by them.
Without them every lab machine would have the same blank serial and the same
all-zero UUID, which no inventory can tell apart.

The values are made from the lab's and the machine's names, so a machine
keeps them from start to start and a copy of it under another name gets its
own, as a new PC does. ``asset_tag`` in a machine's vars sets the tag.
The maker is winlab itself: no real vendor's name.
"""

from __future__ import annotations

import hashlib
import uuid

MAKER = "winlab"
# The model each form of machine is sold as (pcparts.FORMS).
MODELS = {
    "tower": ("T100 Tower PC", "WL-T100", "T100 Desktop"),
    "server": ("R200 Rack Server", "WL-R200", "R200 Server"),
    "laptop": ("L14 Laptop", "WL-L14", "L14 Notebook"),
}
BOARDS = {"tower": "WLB-Z1", "server": "WLB-S2", "laptop": "WLB-N1"}
_NS = uuid.UUID("6f1d3c52-8a4e-4f7b-9d2a-5b1e0c7a9e31")  # winlab's own namespace


def _h(*parts: str) -> str:
    return hashlib.sha1("/".join(parts).encode()).hexdigest().upper()


def _clean(text: str) -> str:
    """A value QEMU's -smbios takes: no comma (its separator), printable."""
    return "".join(c for c in str(text) if c.isprintable() and c != ",").strip()[:64]


def of(lab_name: str, node) -> dict:
    """The machine's identity, or {} for one with no case (the fabric)."""
    from . import pcparts
    form = pcparts.form_of(node)
    if not form:
        return {}
    model, sku, family = MODELS[form]
    h = _h(lab_name, node.id)
    tag = _clean(node.vars.get("asset_tag") or "") or f"IT-{int(h[:8], 16) % 100000:05d}"
    return {"maker": MAKER, "model": model, "sku": sku, "family": family,
            "serial": "WL" + h[8:18], "board": BOARDS[form], "board_serial": "WLB" + h[18:28],
            "asset": tag, "uuid": str(uuid.uuid5(_NS, f"{lab_name}/{node.id}"))}


def qemu_args(lab_name: str, node) -> list[str]:
    """-uuid and -smbios: types 1 (system), 2 (board) and 3 (case)."""
    i = of(lab_name, node)
    if not i:
        return []
    return ["-uuid", i["uuid"],
            "-smbios", f"type=1,manufacturer={MAKER},product={i['model']},version=1,serial={i['serial']},"
                       f"sku={i['sku']},family={i['family']}",
            "-smbios", f"type=2,manufacturer={MAKER},product={i['board']},version=1,serial={i['board_serial']}",
            "-smbios", f"type=3,manufacturer={MAKER},version=1,serial={i['serial']},asset={i['asset']},sku={i['sku']}"]
