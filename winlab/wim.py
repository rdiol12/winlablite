"""The image list of a Windows install.wim (or install.esd), read out of the
installer ISO without mounting it.

Windows Setup installs the image an answer file names, and the names are
not documented: "Windows Server 2022 SERVERSTANDARD" on one medium is not
what the evaluation or volume-licence medium of the same version calls its
Standard edition. Every WIM carries an XML block that lists its images with
their name, edition and build, at the end of the file. `images import` reads
it (the header is 208 bytes, the XML a few dozen kilobytes) and records it,
so the answer file names what the ISO really holds and a wrong ISO is
refused at import instead of failing twenty minutes into an install.
"""

from __future__ import annotations

import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

from .iso9660 import Iso, IsoError

MAGIC = b"MSWIM\x00\x00\x00"
HEADER = 208
# Where the installer media keeps its images.
WIM_PATHS = ("sources/install.wim", "sources/install.esd")


class WimError(Exception):
    pass


def _reshdr(raw: bytes) -> tuple[int, int, int]:
    """A resource header: 7 bytes of size, a flag byte, then the offset."""
    size = int.from_bytes(raw[:7], "little")
    flags = raw[7]
    offset = struct.unpack_from("<q", raw, 8)[0]
    return size, flags, offset


def xml_location(header: bytes) -> tuple[int, int]:
    """(offset, size) of the XML data block, from a WIM header."""
    if len(header) < HEADER or header[:8] != MAGIC:
        raise WimError("not a WIM file (no MSWIM signature)")
    size, flags, offset = _reshdr(header[0x48:0x60])
    if not size or not offset:
        raise WimError("the WIM has no XML data")
    if flags & 0x04:
        raise WimError("the WIM's XML data is compressed")
    return offset, size


def _text(el, tag: str) -> str:
    x = el.find(tag) if el is not None else None
    return (x.text or "").strip() if x is not None else ""


def parse_xml(data: bytes) -> list[dict]:
    """The images in a WIM's XML block, each with index, name, display name,
    edition id, installation type and build."""
    text = data.decode("utf-16", "replace") if data[:2] in (b"\xff\xfe", b"\xfe\xff") \
        else data.decode("utf-16-le", "replace")
    text = re.sub(r"^﻿?\s*<\?xml[^>]*\?>", "", text.strip())
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise WimError(f"cannot parse the WIM's image list: {exc}") from exc
    out = []
    for im in root.findall("IMAGE"):
        win = im.find("WINDOWS")
        ver = win.find("VERSION") if win is not None else None
        try:
            build = int(_text(ver, "BUILD") or 0)
        except ValueError:
            build = 0
        out.append({
            "index": int(im.get("INDEX") or 0),
            "name": _text(im, "NAME"),
            "display": _text(im, "DISPLAYNAME"),
            "edition": _text(win, "EDITIONID"),
            "type": _text(win, "INSTALLATIONTYPE"),
            "build": build,
        })
    return out


def images_in_iso(iso_path: str | Path) -> tuple[str, list[dict]]:
    """(path of the WIM on the ISO, its images). Raises WimError when the
    ISO has no install.wim or the file is not readable as one."""
    try:
        iso = Iso(iso_path)
    except (OSError, IsoError) as exc:
        raise WimError(f"cannot read {iso_path}: {exc}") from exc
    with iso:
        for cand in WIM_PATHS:
            if not iso.exists(cand):
                continue
            try:
                offset, size = xml_location(iso.read_at(cand, 0, HEADER))
                return cand, parse_xml(iso.read_at(cand, offset, size))
            except IsoError as exc:
                raise WimError(f"{cand}: {exc}") from exc
    raise WimError(f"{Path(iso_path).name} has no sources/install.wim or install.esd")


def describe(image: dict) -> str:
    """One line for a listing: display name, build, evaluation or not."""
    name = image.get("display") or image.get("name") or "?"
    bits = [name]
    if image.get("build"):
        bits.append(f"build {image['build']}")
    if "eval" in str(image.get("edition", "")).lower():
        bits.append("evaluation")
    return ", ".join(bits)
