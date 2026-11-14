"""A read-only ISO 9660 and UDF reader, in the standard library.

winlab pulls a handful of driver files out of the virtio-win ISO on the
customer's PC. Mounting the image needs rights and a platform-specific
tool, and the third-party readers are not in the standard library, so this
walks the directory tree itself. Joliet (the UCS-2 supplementary volume
descriptor every Windows-oriented ISO carries) gives the real mixed-case
names; the primary descriptor is the fallback for images without it.

Only what reading needs: volume descriptors, directory records, extents,
and the multi-extent records a file over 4 GiB (a Windows install.wim) is
split into. No path tables, no Rock Ridge, no interleaving.

UDF. Microsoft's newer Windows ISOs are "UDF bridge" discs whose ISO 9660
side holds one README.TXT ("this disc contains a UDF file system") and
nothing else; the files are in the UDF side. When the ISO 9660 tree has no
folder and the image carries UDF, the tree is read from UDF instead: the
anchor at sector 256, the partition and logical volume descriptors, the
file set, then file entries and file identifiers (ECMA-167, as UDF 1.02 to
2.01 write them on a plain disc). Not the metadata partition of UDF 2.50
(Blu-ray) and no virtual or sparable partitions: such a disc keeps its
ISO 9660 side.
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
        self.udf = False
        self._part = 0                      # UDF: the partition's first sector
        self._inline: dict[int, bytes] = {}  # UDF: files kept inside their file entry
        self._root = self._find_root()
        if not any(e.is_dir for e in self._entries(self._root)):
            try:
                root = self._udf_root()
            except (IsoError, struct.error, IndexError):
                root = None
            if root is not None:
                self.udf, self._root = True, root

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

    # ------------------------------------------------------------------- UDF
    def _tag(self, lba: int, want: int) -> bytes:
        blk = self._sector(lba)
        if struct.unpack_from("<H", blk, 0)[0] != want:
            raise IsoError(f"{self.path.name}: no UDF descriptor {want} at sector {lba}")
        return blk

    def _udf_root(self) -> Entry | None:
        """The root directory of the UDF side, or None when there is none."""
        recognised = False
        for lba in range(16, 16 + 64):
            ident = self._sector(lba)[1:6]
            if ident in (b"NSR02", b"NSR03"):
                recognised = True
            if ident in (b"TEA01", b"\0\0\0\0\0"):
                break
        if not recognised:
            return None
        anchor = self._tag(256, 2)
        length, start = struct.unpack_from("<II", anchor, 16)
        part = fileset = None
        for lba in range(start, start + length // SECTOR):
            blk = self._sector(lba)
            tag = struct.unpack_from("<H", blk, 0)[0]
            if tag == 5 and part is None:           # partition descriptor
                part = struct.unpack_from("<I", blk, 188)[0]
            elif tag == 6:                          # logical volume descriptor
                if struct.unpack_from("<I", blk, 212)[0] != SECTOR:
                    raise IsoError(f"{self.path.name}: UDF blocks are not {SECTOR} bytes")
                maps, pos = struct.unpack_from("<I", blk, 268)[0], 440
                for _ in range(maps):
                    if blk[pos] != 1:               # a metadata, virtual or sparable partition
                        raise IsoError(f"{self.path.name}: a UDF partition map this reader does not follow")
                    pos += blk[pos + 1]
                fileset = struct.unpack_from("<I", blk, 252)[0]
            elif tag == 8:                          # terminating descriptor
                break
        if part is None or fileset is None:
            raise IsoError(f"{self.path.name}: the UDF volume has no partition or file set")
        self._part = part
        fsd = self._tag(part + fileset, 256)
        root = struct.unpack_from("<I", fsd, 404)[0]
        return self._udf_entry("", part + root)

    def _udf_ads(self, blk: bytes, kind: int, pos: int, length: int) -> list[tuple[int, int]]:
        """The (sector, bytes) pieces an allocation descriptor list names; a
        sector of -1 is a hole (allocated or not, never written: zeros)."""
        out: list[tuple[int, int]] = []
        step = {0: 8, 1: 16}.get(kind)
        if step is None:
            raise IsoError(f"{self.path.name}: UDF allocation descriptors of type {kind}")
        end = pos + length
        while pos + step <= end:
            raw, lbn = struct.unpack_from("<II", blk, pos)
            pos += step
            size, what = raw & 0x3FFFFFFF, raw >> 30
            if size == 0:
                break
            if what == 3:                           # the list goes on in another block
                blk = self._tag(self._part + lbn, 258)
                pos, end = 24, 24 + struct.unpack_from("<I", blk, 20)[0]
                continue
            out.append((self._part + lbn if what == 0 else -1, size))
        return out

    def _udf_entry(self, name: str, lba: int) -> Entry:
        blk = self._sector(lba)
        tag = struct.unpack_from("<H", blk, 0)[0]
        if tag == 261:                              # file entry
            (l_ea, l_ad), data = struct.unpack_from("<II", blk, 168), 176
        elif tag == 266:                            # extended file entry
            (l_ea, l_ad), data = struct.unpack_from("<II", blk, 208), 216
        else:
            raise IsoError(f"{self.path.name}: no UDF file entry at sector {lba}")
        is_dir = blk[16 + 11] == 4
        kind = struct.unpack_from("<H", blk, 16 + 18)[0] & 7
        size = struct.unpack_from("<Q", blk, 56)[0]
        data += l_ea
        if kind == 3:                               # the file is inside its own entry
            self._inline[lba] = blk[data:data + l_ad][:size]
            return Entry(name=name, is_dir=is_dir, lba=lba, size=size)
        pieces, left = [], size
        for sector, length in self._udf_ads(blk, kind, data, l_ad):
            length = min(length, left)
            if length:
                pieces.append((sector, length))
            left -= length
        if left:
            raise IsoError(f"{self.path.name}: {name or 'the root'} is {size} bytes, {left} of them not on the disc")
        return Entry(name=name, is_dir=is_dir, lba=lba, size=size, extents=tuple(pieces))

    def _udf_bytes(self, e: Entry) -> bytes:
        if e.lba in self._inline:
            return self._inline[e.lba]
        out = bytearray()
        for sector, length in e.pieces:
            if sector < 0:
                out += bytes(length)
            else:
                self._fh.seek(sector * SECTOR)
                out += self._fh.read(length)
        return bytes(out)

    def _udf_entries(self, d: Entry) -> list[Entry]:
        data = self._udf_bytes(d)
        out: list[Entry] = []
        pos = 0
        while pos + 38 <= len(data):
            if struct.unpack_from("<H", data, pos)[0] != 257:   # file identifier descriptor
                break
            flags, l_fi = data[pos + 18], data[pos + 19]
            lbn = struct.unpack_from("<I", data, pos + 24)[0]
            l_iu = struct.unpack_from("<H", data, pos + 36)[0]
            raw = data[pos + 38 + l_iu:pos + 38 + l_iu + l_fi]
            pos += (38 + l_iu + l_fi + 3) & ~3
            if flags & 0x0C or not raw:             # deleted, or the parent
                continue
            name = raw[1:].decode("utf-16-be" if raw[0] == 16 else "latin-1", "replace")
            out.append(self._udf_entry(name, self._part + lbn))
        return out

    def _entries(self, d: Entry) -> list[Entry]:
        if self.udf:
            return self._udf_entries(d)
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
        if self.udf and e.lba in self._inline:
            return self._inline[e.lba][offset:offset + size]
        out = bytearray()
        start = 0
        for lba, length in e.pieces:
            end = start + length
            if end > offset and start < offset + size and size:
                lo = max(offset, start)
                hi = min(offset + size, end)
                if lba < 0:                         # a hole in a UDF file
                    out += bytes(hi - lo)
                    start = end
                    continue
                self._fh.seek(lba * SECTOR + (lo - start))
                chunk = self._fh.read(hi - lo)
                if len(chunk) != hi - lo:
                    raise IsoError(f"{self.path.name}: {path} is truncated")
                out += chunk
            start = end
        return bytes(out)

    def volume_id(self) -> str:
        # The ISO 9660 label; a UDF bridge disc carries the same one there.
        vd = self._sector(16)
        return vd[40:72].decode("ascii", "replace").strip("\x00 ")
