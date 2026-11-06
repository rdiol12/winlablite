"""winlab's own application icon, drawn from primitives with the standard
library only: a blue tile with a monitor showing a three-node network.

Nothing here is traced from anyone else's artwork. The same drawing serves
three places: ``winlab.exe`` (PyInstaller takes the .ico that ``winlab icon``
writes), the browser tab of the desktop (``/favicon.ico``) and the Start menu
tile. A .png of any size can be written for a store listing or a shortcut.

The rasteriser is a signed-distance-field renderer: every shape is a distance
function, pixel coverage is how far inside the pixel centre lies, so edges are
anti-aliased without supersampling and 256 px renders in about a second.
"""

from __future__ import annotations

import math
import struct
import threading
import zlib
from pathlib import Path

# The tile colour is the desktop's accent (see webui_page.html) and the glyph
# is white, so the icon matches the taskbar tiles of the app it opens.
TILE_TOP = (0x1E, 0x84, 0xDC)
TILE_BOTTOM = (0x00, 0x56, 0xA8)
GLYPH = (0xFF, 0xFF, 0xFF)

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
_PNG_IN_ICO_FROM = 64  # Vista+ reads PNG entries; the small ones stay BMP for XP-era shell code


# --------------------------------------------------------------------------
# distance functions (coordinates in pixels, origin top-left)
# --------------------------------------------------------------------------


def _d_round_rect(px: float, py: float, cx: float, cy: float, hw: float, hh: float, r: float) -> float:
    qx = abs(px - cx) - hw + r
    qy = abs(py - cy) - hh + r
    outside = math.hypot(max(qx, 0.0), max(qy, 0.0))
    inside = min(max(qx, qy), 0.0)
    return outside + inside - r


def _d_circle(px: float, py: float, cx: float, cy: float, r: float) -> float:
    return math.hypot(px - cx, py - cy) - r


def _d_segment(px: float, py: float, ax: float, ay: float, bx: float, by: float, hw: float) -> float:
    abx, aby = bx - ax, by - ay
    apx, apy = px - ax, py - ay
    ab2 = abx * abx + aby * aby
    t = 0.0 if ab2 == 0 else max(0.0, min(1.0, (apx * abx + apy * aby) / ab2))
    return math.hypot(apx - t * abx, apy - t * aby) - hw


def _cov(d: float) -> float:
    """Coverage of a pixel whose centre lies at signed distance d."""
    if d <= -0.5:
        return 1.0
    if d >= 0.5:
        return 0.0
    return 0.5 - d


# --------------------------------------------------------------------------
# the drawing
# --------------------------------------------------------------------------


def _shapes(size: int) -> list:
    """The glyph as (kind, params) in pixel units for a size x size tile.

    Two levels of detail: at 40 px and below the screen shows a single dot,
    because a three-node network at 16 px is a smudge.
    """
    s = float(size)
    u = s / 48.0  # the design is laid out on a 48-unit grid
    stroke = max(1.1, 3.2 * u)
    shapes: list = []
    # monitor frame: an outlined rounded rectangle (the fill is the tile)
    mon_cx, mon_cy, mon_hw, mon_hh = 24 * u, 20.5 * u, 15 * u, 10.5 * u
    shapes.append(("ring", (mon_cx, mon_cy, mon_hw, mon_hh, 2.6 * u, stroke / 2)))
    # stand: a short neck and a base
    shapes.append(("seg", (24 * u, 31 * u, 24 * u, 36.5 * u, stroke / 2)))
    shapes.append(("seg", (16 * u, 37.5 * u, 32 * u, 37.5 * u, stroke / 2)))
    if size <= 40:
        shapes.append(("disc", (24 * u, 20.5 * u, 3.4 * u)))
        return shapes
    # on the screen: one node at the top, two below, cabled together
    top = (24 * u, 15 * u)
    left = (17.5 * u, 26 * u)
    right = (30.5 * u, 26 * u)
    thin = max(0.9, 1.7 * u) / 2
    shapes.append(("seg", (top[0], top[1], left[0], left[1], thin)))
    shapes.append(("seg", (top[0], top[1], right[0], right[1], thin)))
    shapes.append(("seg", (left[0], left[1], right[0], right[1], thin)))
    for cx, cy in (top, left, right):
        shapes.append(("disc", (cx, cy, 2.6 * u)))
    return shapes


def render(size: int) -> bytes:
    """RGBA pixels, row-major, top row first (size * size * 4 bytes)."""
    s = float(size)
    tile_r = 0.22 * s
    shapes = _shapes(size)
    out = bytearray(size * size * 4)
    i = 0
    for y in range(size):
        py = y + 0.5
        t = py / s
        tr = TILE_TOP[0] + (TILE_BOTTOM[0] - TILE_TOP[0]) * t
        tg = TILE_TOP[1] + (TILE_BOTTOM[1] - TILE_TOP[1]) * t
        tb = TILE_TOP[2] + (TILE_BOTTOM[2] - TILE_TOP[2]) * t
        for x in range(size):
            px = x + 0.5
            a = _cov(_d_round_rect(px, py, s / 2, s / 2, s / 2, s / 2, tile_r))
            if a <= 0.0:
                i += 4
                continue
            g = 0.0
            for kind, p in shapes:
                if kind == "ring":
                    cx, cy, hw, hh, r, hs = p
                    d = abs(_d_round_rect(px, py, cx, cy, hw, hh, r)) - hs
                elif kind == "seg":
                    d = _d_segment(px, py, *p)
                else:
                    d = _d_circle(px, py, *p)
                c = _cov(d)
                if c > g:
                    g = c
                    if g >= 1.0:
                        break
            r = tr + (GLYPH[0] - tr) * g
            gg = tg + (GLYPH[1] - tg) * g
            b = tb + (GLYPH[2] - tb) * g
            out[i] = int(r + 0.5)
            out[i + 1] = int(gg + 0.5)
            out[i + 2] = int(b + 0.5)
            out[i + 3] = int(a * 255 + 0.5)
            i += 4
    return bytes(out)


# --------------------------------------------------------------------------
# encoders
# --------------------------------------------------------------------------


def png(size: int, pixels: bytes | None = None) -> bytes:
    pixels = pixels if pixels is not None else render(size)
    stride = size * 4
    raw = b"".join(b"\x00" + pixels[y * stride:(y + 1) * stride] for y in range(size))

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _bmp_entry(size: int, pixels: bytes) -> bytes:
    """A classic 32-bit ICO image: BITMAPINFOHEADER, bottom-up BGRA rows and a
    1-bit AND mask (set where the pixel is fully transparent)."""
    stride = size * 4
    rows = []
    mask_rows = []
    mask_stride = ((size + 31) // 32) * 4
    for y in range(size - 1, -1, -1):
        row = pixels[y * stride:(y + 1) * stride]
        bgra = bytearray(stride)
        bits = bytearray(mask_stride)
        for x in range(size):
            r, g, b, a = row[x * 4:x * 4 + 4]
            bgra[x * 4:x * 4 + 4] = bytes((b, g, r, a))
            if a == 0:
                bits[x // 8] |= 0x80 >> (x % 8)
        rows.append(bytes(bgra))
        mask_rows.append(bytes(bits))
    pix = b"".join(rows)
    mask = b"".join(mask_rows)
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, len(pix) + len(mask), 0, 0, 0, 0)
    return header + pix + mask


def ico(sizes: tuple[int, ...] = ICO_SIZES) -> bytes:
    """A multi-size .ico: BMP entries up to 48 px, PNG entries above."""
    entries = []
    for size in sizes:
        pixels = render(size)
        data = png(size, pixels) if size >= _PNG_IN_ICO_FROM else _bmp_entry(size, pixels)
        entries.append((size, data))
    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = 6 + 16 * len(entries)
    directory = b""
    blobs = b""
    for size, data in entries:
        dim = 0 if size >= 256 else size
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return header + directory + blobs


_cache: dict[str, bytes] = {}
_lock = threading.Lock()


def ico_bytes() -> bytes:
    """The full icon, rendered once per process (about a second of CPU)."""
    with _lock:
        if "ico" not in _cache:
            _cache["ico"] = ico()
        return _cache["ico"]


def write(path: str | Path, size: int = 0) -> Path:
    """Write the icon: a .ico with every size, or a .png of `size` pixels."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.suffix.lower() == ".png":
        dest.write_bytes(png(size or 256))
    else:
        dest.write_bytes(ico_bytes())
    return dest
