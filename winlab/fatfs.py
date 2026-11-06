"""Minimal FAT12/FAT16 image writer, pure stdlib.

Needed because Windows Setup only reads an answer file named literally
`autounattend.xml`, which is 12.3 and therefore not an 8.3 name, so the
directory entries must carry VFAT long-filename records. Subdirectories
(a file added as "NetKVM/w11/amd64/netkvm.inf") make a USB stick that
looks like a vendor's: folders, long names, up to 2 GB on FAT16.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field
from pathlib import Path

SECTOR = 512
ATTR_LFN = 0x0F
ATTR_ARCHIVE = 0x20
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10

FAT12 = 12
FAT16 = 16

_INVALID_SHORT = set('+,;=[]" *?<>|/\\:')


@dataclass
class _Entry:
    name: str
    data: bytes
    first_cluster: int = 0
    is_dir: bool = False
    children: list = field(default_factory=list)   # _Entry, for a directory
    shorts: set = field(default_factory=set)       # 8.3 names taken in this directory
    parent: object = None


@dataclass
class FatImage:
    total_bytes: int
    label: str = "WINLAB"
    fat_type: int = FAT16
    sectors_per_cluster: int = 0
    root_entries: int = 0
    media: int = 0xF8
    entries: list[_Entry] = field(default_factory=list)   # the root's children
    _shorts: set[str] = field(default_factory=set)       # 8.3 names taken in the root

    def __post_init__(self) -> None:
        if self.fat_type == FAT12:
            self.sectors_per_cluster = self.sectors_per_cluster or 1
            self.root_entries = self.root_entries or 224
            self.media = 0xF0
        else:
            self.sectors_per_cluster = self.sectors_per_cluster or 4
            self.root_entries = self.root_entries or 512
            self.media = 0xF8

    # ------------------------------------------------------------- geometry
    @property
    def total_sectors(self) -> int:
        return self.total_bytes // SECTOR

    @property
    def root_dir_sectors(self) -> int:
        return (self.root_entries * 32 + SECTOR - 1) // SECTOR

    @property
    def cluster_bytes(self) -> int:
        return self.sectors_per_cluster * SECTOR

    def _sectors_per_fat(self) -> int:
        reserved = 1
        bits = self.fat_type
        # Each FAT must describe the clusters that remain once the FATs
        # themselves are subtracted, so solve for it iteratively.
        spf = 1
        for _ in range(64):
            data_sectors = (
                self.total_sectors - reserved - self.root_dir_sectors - 2 * spf
            )
            if data_sectors <= 0:
                raise ValueError("image too small for the requested geometry")
            clusters = data_sectors // self.sectors_per_cluster
            need_bytes = ((clusters + 2) * bits + 7) // 8
            new_spf = max(1, (need_bytes + SECTOR - 1) // SECTOR)
            if new_spf == spf:
                return spf
            spf = new_spf
        return spf

    def _cluster_count(self) -> int:
        spf = self._sectors_per_fat()
        data_sectors = self.total_sectors - 1 - self.root_dir_sectors - 2 * spf
        return data_sectors // self.sectors_per_cluster

    # ---------------------------------------------------------------- files
    def add_file(self, name: str, data: bytes | str) -> None:
        """A file at the root, or under directories made on the way when
        the name has slashes ("drivers/NetKVM/netkvm.inf")."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        parts = [p for p in name.replace("\\", "/").split("/") if p and p != "."]
        if not parts:
            raise ValueError(f"bad file name {name!r}")
        children = self.entries
        parent: _Entry | None = None
        for part in parts[:-1]:
            d = next((e for e in children if e.is_dir and e.name.lower() == part.lower()), None)
            if d is None:
                d = _Entry(name=part, data=b"", is_dir=True, parent=parent)
                children.append(d)
            children = d.children
            parent = d
        children.append(_Entry(name=parts[-1], data=data, parent=parent))

    def add_path(self, name: str, src: Path) -> None:
        self.add_file(name, src.read_bytes())

    def add_tree(self, src: Path, prefix: str = "") -> int:
        """Every file under a folder on disk, keeping its layout. Returns
        how many files were added."""
        n = 0
        for f in sorted(src.rglob("*")):
            if f.is_file():
                rel = f.relative_to(src).as_posix()
                self.add_file(f"{prefix}/{rel}" if prefix else rel, f.read_bytes())
                n += 1
        return n

    def _walk(self) -> list[_Entry]:
        """Every entry, directories before their contents."""
        out: list[_Entry] = []

        def rec(children):
            for e in children:
                out.append(e)
                if e.is_dir:
                    rec(e.children)
        rec(self.entries)
        return out

    # ------------------------------------------------------------ 8.3 names
    def _short_name(self, long_name: str, taken: set[str] | None = None) -> tuple[bytes, bool]:
        taken = self._shorts if taken is None else taken
        stem, _, ext = long_name.rpartition(".")
        if not stem:
            stem, ext = long_name, ""

        def clean(s: str) -> str:
            return "".join(
                ch for ch in s.upper() if ch not in _INVALID_SHORT and ch != "."
            )

        cstem, cext = clean(stem), clean(ext)[:3]
        lossless = (
            cstem == stem.upper()
            and cext == ext.upper()
            and len(cstem) <= 8
            and len(cext) <= 3
        )
        if lossless and cstem:
            short = f"{cstem:<8}{cext:<3}"
            if short not in taken:
                taken.add(short)
                return short.encode("ascii"), False

        base = (cstem or "FILE")[:6]
        for n in range(1, 1000):
            tail = f"~{n}"
            candidate = f"{(base[: 8 - len(tail)] + tail):<8}{cext:<3}"
            if candidate not in taken:
                taken.add(candidate)
                return candidate.encode("ascii"), True
        raise ValueError(f"cannot generate a short name for {long_name!r}")

    def _lfn_records(self, name: str, short11: bytes) -> bytes:
        checksum = self._lfn_checksum(short11)
        chars = name.encode("utf-16-le")
        units = [chars[i : i + 2] for i in range(0, len(chars), 2)]
        units.append(b"\x00\x00")
        while len(units) % 13:
            units.append(b"\xff\xff")
        groups = [units[i : i + 13] for i in range(0, len(units), 13)]
        out = bytearray()
        # LFN records are stored highest-sequence-first, immediately
        # before the 8.3 record they describe.
        for idx in range(len(groups) - 1, -1, -1):
            seq = idx + 1
            if idx == len(groups) - 1:
                seq |= 0x40
            g = groups[idx]
            rec = bytearray(32)
            rec[0] = seq
            rec[11] = ATTR_LFN
            rec[12] = 0
            rec[13] = checksum
            rec[26:28] = b"\x00\x00"
            for i in range(5):
                rec[1 + i * 2 : 3 + i * 2] = g[i]
            for i in range(6):
                rec[14 + i * 2 : 16 + i * 2] = g[5 + i]
            for i in range(2):
                rec[28 + i * 2 : 30 + i * 2] = g[11 + i]
            out += bytes(rec)
        return bytes(out)

    @staticmethod
    def _lfn_checksum(short11: bytes) -> int:
        total = 0
        for byte in short11:
            total = (((total & 1) << 7) | (total >> 1)) + byte
            total &= 0xFF
        return total

    def _dir_records(self, entry: _Entry, taken: set[str] | None = None) -> bytes:
        short11, needs_lfn = self._short_name(entry.name, taken)
        out = bytearray()

        if needs_lfn:
            out += self._lfn_records(entry.name, short11)

        out += self._short_record(short11, entry.first_cluster,
                                  0 if entry.is_dir else len(entry.data),
                                  ATTR_DIRECTORY if entry.is_dir else ATTR_ARCHIVE,
                                  0 if needs_lfn else self._case_bits(entry.name))
        return bytes(out)

    def _dir_records_named(self, entry: _Entry) -> bytes:
        """Like _dir_records, with the 8.3 name _dir_size already chose."""
        short11 = entry._short  # type: ignore[attr-defined]
        needs_lfn = entry._lfn  # type: ignore[attr-defined]
        out = bytearray()
        if needs_lfn:
            out += self._lfn_records(entry.name, short11)
        out += self._short_record(short11, entry.first_cluster,
                                  0 if entry.is_dir else len(entry.data),
                                  ATTR_DIRECTORY if entry.is_dir else ATTR_ARCHIVE,
                                  0 if needs_lfn else self._case_bits(entry.name))
        return bytes(out)

    @staticmethod
    def _case_bits(name: str) -> int:
        """The NT flags Windows sets on an 8.3 name typed in lower case, so
        'netkvm.inf' lists as netkvm.inf rather than NETKVM.INF."""
        stem, _, ext = name.rpartition(".")
        if not stem:
            stem, ext = name, ""
        bits = 0
        if stem and stem == stem.lower() and stem != stem.upper():
            bits |= 0x08
        if ext and ext == ext.lower() and ext != ext.upper():
            bits |= 0x10
        return bits

    @staticmethod
    def _short_record(short11: bytes, first_cluster: int, size: int, attr: int,
                      case: int = 0) -> bytes:
        rec = bytearray(32)
        rec[0:11] = short11
        rec[11] = attr
        rec[12] = case
        rec[22:24] = struct.pack("<H", 0x6000)  # 12:00:00
        rec[24:26] = struct.pack("<H", ((2025 - 1980) << 9) | (1 << 5) | 1)
        rec[26:28] = struct.pack("<H", first_cluster)
        rec[28:32] = struct.pack("<I", size)
        return bytes(rec)

    @staticmethod
    def _record_count(name: str, lossless: bool) -> int:
        """How many 32-byte records an entry takes: its 8.3 record plus one
        LFN record per 13 UTF-16 units of a long name."""
        if lossless:
            return 1
        units = len(name.encode("utf-16-le")) // 2 + 1
        return 1 + (units + 12) // 13

    def _dir_size(self, d: _Entry) -> int:
        """Bytes a subdirectory's records take, '.' and '..' included; the
        8.3 names are assigned here, once, in the directory's own namespace."""
        d.shorts = set()
        total = 64
        for child in d.children:
            short11, needs_lfn = self._short_name(child.name, d.shorts)
            child._short = short11  # type: ignore[attr-defined]
            child._lfn = needs_lfn  # type: ignore[attr-defined]
            total += 32 * self._record_count(child.name, not needs_lfn)
        return total

    # ---------------------------------------------------------------- build
    def build(self) -> bytes:
        """The whole image in memory."""
        buf = io.BytesIO()
        self._emit(buf)
        return buf.getvalue() + b"\x00" * (self.total_bytes - buf.tell())

    def _emit(self, out) -> None:
        """Writes the image up to the end of the last file's cluster; the
        rest of the volume is free space, all zeros, which the caller adds
        (a file extended by truncate reads back as zeros and costs no time)."""
        spf = self._sectors_per_fat()
        clusters_total = self._cluster_count()

        if self.fat_type == FAT12 and clusters_total >= 4085:
            raise ValueError("too many clusters for FAT12; use FAT16")
        if self.fat_type == FAT16 and not (4085 <= clusters_total < 65525):
            raise ValueError(
                f"cluster count {clusters_total} is outside the FAT16 range; "
                f"adjust size or sectors_per_cluster"
            )

        everything = self._walk()
        # Subdirectories are stored like files: their size is their records'.
        sizes = {id(e): (self._dir_size(e) if e.is_dir else len(e.data)) for e in everything}
        next_cluster = 2
        chains: list[list[int]] = []
        for entry in everything:
            n = max(1, (sizes[id(entry)] + self.cluster_bytes - 1) // self.cluster_bytes)
            chain = list(range(next_cluster, next_cluster + n))
            next_cluster += n
            if chain[-1] - 2 >= clusters_total:
                raise ValueError("image too small for the files added")
            entry.first_cluster = chain[0]
            chains.append(chain)

        # the root directory
        dir_bytes = bytearray()
        if self.label:
            vol = bytearray(32)
            vol[0:11] = f"{self.label.upper()[:11]:<11}".encode("ascii")
            vol[11] = ATTR_VOLUME_ID
            dir_bytes += bytes(vol)
        for entry in self.entries:
            dir_bytes += self._dir_records(entry)
        if len(dir_bytes) > self.root_entries * 32:
            raise ValueError("root directory full; raise root_entries")
        dir_bytes += b"\x00" * (self.root_dir_sectors * SECTOR - len(dir_bytes))

        # subdirectories: '.', '..', then the children, 8.3 names as assigned
        for d in everything:
            if not d.is_dir:
                continue
            body = bytearray()
            body += self._short_record(b".          ", d.first_cluster, 0, ATTR_DIRECTORY)
            up = d.parent.first_cluster if d.parent is not None else 0
            body += self._short_record(b"..         ", up, 0, ATTR_DIRECTORY)
            for child in d.children:
                body += self._dir_records_named(child)
            d.data = bytes(body)

        # FAT
        end = 0xFFF if self.fat_type == FAT12 else 0xFFFF
        table = [0] * (clusters_total + 2)
        table[0] = (0xF00 | self.media) if self.fat_type == FAT12 else (0xFF00 | self.media)
        table[1] = end
        for chain in chains:
            for i, cl in enumerate(chain):
                table[cl] = chain[i + 1] if i + 1 < len(chain) else end
        fat_bytes = self._pack_fat(table, spf)

        # Boot sector, both FATs, the root directory, then the clusters in
        # chain order: each file padded to whole clusters, an empty one
        # still owning its cluster. Written straight out, so a 2 GB stick
        # never sits in memory twice.
        out.write(self._boot_sector(spf))
        out.write(fat_bytes)
        out.write(fat_bytes)
        out.write(dir_bytes)
        for entry in everything:
            out.write(entry.data)
            pad = -len(entry.data) % self.cluster_bytes if entry.data else self.cluster_bytes
            out.write(b"\x00" * pad)

    def _pack_fat(self, table: list[int], spf: int) -> bytes:
        size = spf * SECTOR
        if self.fat_type == FAT16:
            raw = struct.pack(f"<{len(table)}H", *(v & 0xFFFF for v in table))
        else:
            raw = bytearray((len(table) * 3 + 1) // 2 + 2)
            for i, v in enumerate(table):
                v &= 0xFFF
                pos = (i * 3) // 2
                if i % 2 == 0:
                    raw[pos] = v & 0xFF
                    raw[pos + 1] = (raw[pos + 1] & 0xF0) | ((v >> 8) & 0x0F)
                else:
                    raw[pos] = (raw[pos] & 0x0F) | ((v << 4) & 0xF0)
                    raw[pos + 1] = (v >> 4) & 0xFF
            raw = bytes(raw)
        if len(raw) > size:
            raise ValueError("FAT does not fit in the reserved sectors")
        return raw + b"\x00" * (size - len(raw))

    def _boot_sector(self, spf: int) -> bytes:
        bs = bytearray(SECTOR)
        bs[0:3] = b"\xeb\x3c\x90"
        bs[3:11] = b"MSWIN4.1"
        struct.pack_into("<H", bs, 11, SECTOR)
        bs[13] = self.sectors_per_cluster
        struct.pack_into("<H", bs, 14, 1)
        bs[16] = 2
        struct.pack_into("<H", bs, 17, self.root_entries)
        small = self.total_sectors if self.total_sectors < 0x10000 else 0
        struct.pack_into("<H", bs, 19, small)
        bs[21] = self.media
        struct.pack_into("<H", bs, 22, spf)
        struct.pack_into("<H", bs, 24, 63)
        struct.pack_into("<H", bs, 26, 255)
        struct.pack_into("<I", bs, 28, 0)
        struct.pack_into("<I", bs, 32, 0 if small else self.total_sectors)
        bs[36] = 0x00 if self.fat_type == FAT12 else 0x80
        bs[38] = 0x29
        struct.pack_into("<I", bs, 39, 0x57494E4C)
        bs[43:54] = f"{self.label.upper()[:11]:<11}".encode("ascii")
        bs[54:62] = b"FAT12   " if self.fat_type == FAT12 else b"FAT16   "
        bs[510] = 0x55
        bs[511] = 0xAA
        return bytes(bs)

    def write(self, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("wb") as fh:
            self._emit(fh)
            fh.truncate(self.total_bytes)
        return dest


def floppy(label: str = "WINLAB") -> FatImage:
    """1.44 MB FAT12 floppy, the most reliably detected answer-file medium."""
    return FatImage(total_bytes=1474560, label=label, fat_type=FAT12)


def disk(size_mb: int, label: str = "WINLAB") -> FatImage:
    """A FAT16 disk image; the cluster size follows the size so the cluster
    count stays in FAT16's range (4085 to 65524) from 16 MB up to 2 GB."""
    spc = 4
    if size_mb > 2048:
        raise ValueError("a FAT16 image is at most 2 GB")
    for limit, per in ((128, 4), (256, 8), (512, 16), (1024, 32), (2048, 64)):
        if size_mb <= limit:
            spc = per
            break
    return FatImage(total_bytes=size_mb * 1024 * 1024, label=label, fat_type=FAT16,
                    sectors_per_cluster=spc)
