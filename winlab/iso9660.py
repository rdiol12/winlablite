"""A read-only ISO 9660 reader, Joliet first, in the standard library.

winlab pulls a handful of driver files out of the virtio-win ISO on the
customer's PC. Mounting the image needs rights and a platform-specific
tool, and the third-party readers are not in the standard library, so this
walks the directory tree itself. Joliet (the UCS-2 supplementary volume
descriptor every Windows-oriented ISO carries) gives the real mixed-case
names; the primary descriptor is the fallback for images without it.

Only what reading needs: volume descriptors, directory records, extents,
and the multi-extent records a file over 4 GiB (a Windows install.wim) is
split into. No path tables, no Rock Ridge, no interleaving.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

SECTOR = 2048
_PVD, _SVD, _TERMINATOR = 1, 2, 255
_JOLIET_ESCAPES = (b"%/@", b"%/C", b"%/E")
_FLAG_DIR = 0x02
_FLAG_MORE = 0x80   # this record is not the file's last extent


class IsoError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    name: str
    is_dir: bool
    lba: int
    size: int
    # Every (lba, size) piece of the file, in order; one for most files.
    extents: tuple[tuple[int, int], ...] = ()

    @property
    def pieces(self) -> tuple[tuple[int, int], ...]:
        return self.extents or ((self.lba, self.size),)


class Iso:
    """Opens an .iso and lists or reads files by a slash-separated path.
    Paths are matched without regard to case, which is what a Windows user
    expects and what Joliet's own matching does."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh = self.path.open("rb")
        self.joliet = False
        self._root = self._find_root()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> Iso:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ------------------------------------------------------------ descriptors
    def _sector(self, lba: int, count: int = 1) -> bytes:
        self._fh.seek(lba * SECTOR)
        data = self._fh.read(count * SECTOR)
        if len(data) < count * SECTOR:
            raise IsoError(f"{self.path.name}: truncated at sector {lba}")
        return data

    def _find_root(self) -> Entry:
        primary: Entry | None = None
        for lba in range(16, 16 + 64):
            try:
                vd = self._sector(lba)
            except IsoError:
                break
            if vd[1:6] != b"CD001":
                break
            kind = vd[0]
            if kind == _TERMINATOR:
                break
            if kind == _PVD and primary is None:
                primary = self._root_record(vd)
            elif kind == _SVD and vd[88:91] in _JOLIET_ESCAPES:
                self.joliet = True
                return self._root_record(vd)
        if primary is None:
            raise IsoError(f"{self.path.name}: no ISO 9660 volume descriptor")
        return primary

    def _root_record(self, vd: bytes) -> Entry:
        rec = vd[156:190]
        lba = struct.unpack_from("<I", rec, 2)[0]
        size = struct.unpack_from("<I", rec, 10)[0]
        return Entry(name="", is_dir=True, lba=lba, size=size)

    # ------------------------------------------------------------- directory
    def _decode(self, raw: bytes) -> str:
        if self.joliet:
            name = raw.decode("utf-16-be", "replace")
        else:
            name = raw.decode("ascii", "replace")
        if ";" in name:
            name = name.split(";", 1)[0]
        return name.rstrip(".")

    def _entries(self, d: Entry) -> list[Entry]:
        sectors = (d.size + SECTOR - 1) // SECTOR
        data = self._sector(d.lba, sectors)[: d.size]
        out: list[Entry] = []
        pos = 0
        more = False
        while pos < len(data):
            length = data[pos]
            if length == 0:
                # Records never straddle a sector: skip the padding.
                pos = (pos // SECTOR + 1) * SECTOR
                continue
            rec = data[pos:pos + length]
            pos += length
            name_len = rec[32]
            raw = rec[33:33 + name_len]
            if raw in (b"\x00", b"\x01"):
                continue  # . and ..
            lba = struct.unpack_from("<I", rec, 2)[0]
            size = struct.unpack_from("<I", rec, 10)[0]
            flags = rec[25]
            name = self._decode(raw)
            if out and more and out[-1].name == name:
                # The next piece of a file split over several records.
                prev = out[-1]
                ext = prev.pieces + ((lba, size),)
                out[-1] = Entry(name=name, is_dir=False, lba=prev.lba,
                                size=prev.size + size, extents=ext)
            else:
                out.append(Entry(name=name, is_dir=bool(flags & _FLAG_DIR), lba=lba, size=size,
                                 extents=((lba, size),) if flags & _FLAG_MORE else ()))
            more = bool(flags & _FLAG_MORE)
        return out

    def _lookup(self, path: str) -> Entry | None:
        cur = self._root
        for part in [p for p in path.replace("\\", "/").split("/") if p]:
            if not cur.is_dir:
                return None
            nxt = next((e for e in self._entries(cur) if e.name.lower() == part.lower()), None)
            if nxt is None:
                return None
            cur = nxt
        return cur

    # ---------------------------------------------------------------- public
    def exists(self, path: str) -> bool:
        return self._lookup(path) is not None

    def listdir(self, path: str = "") -> list[Entry]:
        e = self._lookup(path)
        if e is None or not e.is_dir:
            raise IsoError(f"{self.path.name}: no directory {path!r}")
        return sorted(self._entries(e), key=lambda x: x.name.lower())

    def entry(self, path: str) -> Entry:
        e = self._lookup(path)
        if e is None or e.is_dir:
            raise IsoError(f"{self.path.name}: no file {path!r}")
        return e

    def read(self, path: str) -> bytes:
        e = self.entry(path)
        return self.read_at(path, 0, e.size)

    def read_at(self, path: str, offset: int, size: int) -> bytes:
        """`size` bytes of the file from `offset`, across extents; what a
        multi-gigabyte file's header or tail needs without reading it all."""
        e = self.entry(path)
        if offset < 0 or size < 0 or offset + size > e.size:
            raise IsoError(f"{self.path.name}: {path} is {e.size} bytes; "
                           f"cannot read {size} at {offset}")
        out = bytearray()
        start = 0
        for lba, length in e.pieces:
            end = start + length
            if end > offset and start < offset + size and size:
                lo = max(offset, start)
                hi = min(offset + size, end)
                self._fh.seek(lba * SECTOR + (lo - start))
                chunk = self._fh.read(hi - lo)
                if len(chunk) != hi - lo:
                    raise IsoError(f"{self.path.name}: {path} is truncated")
                out += chunk
            start = end
        return bytes(out)

    def volume_id(self) -> str:
        vd = self._sector(16)
        return vd[40:72].decode("ascii", "replace").strip("\x00 ")
