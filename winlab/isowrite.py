"""A small ISO 9660 + Joliet writer in the standard library.

Configuration Manager's media, Microsoft's ADK layouts and the prerequisite
downloads arrive on the customer's PC as folders; a lab machine has no
network share to read them from, so winlab hands them over the way a real
admin would: burned on a disc. Windows (and Linux) read the Joliet tree,
which keeps the real mixed-case names; the primary tree carries short
generated names (N00001) for readers without Joliet.

What a data disc needs and nothing more: one primary and one Joliet volume
descriptor, little- and big-endian path tables for both, directories, and
file data streamed from disk (never held in memory). No El Torito, no Rock
Ridge, no files over 4 GiB (a single extent), which none of those media have.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

SECTOR = 2048
MAX_FILE = 0xFFFFFFFF          # one extent
MAX_JOLIET = 103               # characters per name (the long Joliet form)
_CHUNK = 1024 * 1024


class IsoWriteError(Exception):
    pass


@dataclass
class _Node:
    name: str                       # the real name (Joliet)
    is_dir: bool
    source: Path | None = None      # a file's content
    size: int = 0
    children: list["_Node"] = field(default_factory=list)
    parent: "_Node | None" = None
    short: str = ""                 # primary-tree identifier
    lba: int = 0                    # file data, or the primary directory extent
    jlba: int = 0                   # the Joliet directory extent
    dsize: int = 0                  # primary directory size in bytes
    jsize: int = 0                  # Joliet directory size in bytes
    number: int = 0                 # position in the path table (1 = root)


def _both16(v: int) -> bytes:
    return struct.pack("<H", v) + struct.pack(">H", v)


def _both32(v: int) -> bytes:
    return struct.pack("<I", v) + struct.pack(">I", v)


def _rec_date(t: float) -> bytes:
    g = time.gmtime(t)
    return bytes([g.tm_year - 1900, g.tm_mon, g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec, 0])


def _vd_date(t: float) -> bytes:
    return time.strftime("%Y%m%d%H%M%S00", time.gmtime(t)).encode("ascii") + b"\x00"


def _record(ident: bytes, lba: int, size: int, is_dir: bool, when: bytes) -> bytes:
    n = len(ident)
    length = 33 + n + (1 if n % 2 == 0 else 0)
    rec = (bytes([length, 0]) + _both32(lba) + _both32(size) + when
           + bytes([0x02 if is_dir else 0x00, 0, 0]) + _both16(1) + bytes([n]) + ident)
    return rec + b"\x00" * (length - len(rec))


def _pad(text: str, n: int, joliet: bool = False) -> bytes:
    if joliet:
        raw = text.encode("utf-16-be")[: n - n % 2]
        raw += " ".encode("utf-16-be") * ((n - len(raw)) // 2)
        return raw.ljust(n, b"\x00")
    return text.encode("ascii", "replace")[:n].ljust(n, b" ")


class IsoWriter:
    """Collects files under disc paths, then writes the image in one pass:

        w = IsoWriter("MECM")
        w.add_tree(folder, "CM")
        w.add_file(msi, "ODBC/msodbcsql.msi")
        w.write(dest)
    """

    def __init__(self, volume_id: str) -> None:
        self.volume_id = "".join(c for c in volume_id.upper() if c.isalnum() or c == "_")[:32] or "CDROM"
        self.root = _Node(name="", is_dir=True)
        self.when = time.time()

    # ------------------------------------------------------------- adding
    def _dir(self, parts: list[str]) -> _Node:
        cur = self.root
        for p in parts:
            nxt = next((c for c in cur.children if c.name.lower() == p.lower()), None)
            if nxt is None:
                nxt = _Node(name=p, is_dir=True, parent=cur)
                cur.children.append(nxt)
            elif not nxt.is_dir:
                raise IsoWriteError(f"{p} is a file and a folder on the disc")
            cur = nxt
        return cur

    @staticmethod
    def _parts(disc_path: str) -> list[str]:
        parts = [p for p in disc_path.replace("\\", "/").split("/") if p]
        for p in parts:
            if len(p) > MAX_JOLIET:
                raise IsoWriteError(f"the name {p!r} is longer than {MAX_JOLIET} characters")
            if p in (".", ".."):
                raise IsoWriteError(f"bad path on the disc: {disc_path}")
        return parts

    def add_file(self, source: str | Path, disc_path: str) -> None:
        source = Path(source)
        parts = self._parts(disc_path)
        if not parts:
            raise IsoWriteError("a file needs a name on the disc")
        size = source.stat().st_size
        if size > MAX_FILE:
            raise IsoWriteError(f"{source.name} is over 4 GiB, which this writer does not split")
        parent = self._dir(parts[:-1])
        if any(c.name.lower() == parts[-1].lower() for c in parent.children):
            raise IsoWriteError(f"{disc_path} is on the disc twice")
        parent.children.append(_Node(name=parts[-1], is_dir=False, source=source, size=size, parent=parent))

    def add_tree(self, folder: str | Path, disc_path: str = "") -> int:
        """Every file under folder, at the same relative path under
        disc_path; empty folders too. Returns the number of files."""
        folder = Path(folder)
        if not folder.is_dir():
            raise IsoWriteError(f"no such folder: {folder}")
        base = self._parts(disc_path)
        self._dir(base)
        count = 0
        for p in sorted(folder.rglob("*")):
            rel = p.relative_to(folder).parts
            if p.is_dir():
                self._dir(base + [*self._parts("/".join(rel))])
            elif p.is_file():
                self.add_file(p, "/".join(base + list(rel)))
                count += 1
        return count

    def total_bytes(self) -> int:
        def walk(n: _Node) -> int:
            return n.size if not n.is_dir else sum(walk(c) for c in n.children)
        return walk(self.root)

    # ------------------------------------------------------------- layout
    def _dirs(self) -> list[_Node]:
        """Every directory in path-table order: by depth, then by parent's
        number, then by name."""
        out = [self.root]
        self.root.number = 1
        level = [self.root]
        while level:
            nxt: list[_Node] = []
            for d in level:
                for c in d.children:
                    if c.is_dir:
                        nxt.append(c)
            for i, d in enumerate(nxt):
                d.number = len(out) + i + 1
            out.extend(nxt)
            level = nxt
        if len(out) > 0xFFFF:
            raise IsoWriteError("too many folders for one disc")
        return out

    def _sort(self, n: _Node) -> None:
        n.children.sort(key=lambda c: c.name.encode("utf-16-be"))
        for i, c in enumerate(n.children, 1):
            c.short = f"N{i:05d}" if c.is_dir else f"N{i:05d}.;1"
            if c.is_dir:
                self._sort(c)

    def _ident(self, n: _Node, joliet: bool) -> bytes:
        if joliet:
            return n.name.encode("utf-16-be")
        return n.short.encode("ascii")

    def _dir_size(self, d: _Node, joliet: bool) -> int:
        size = 34 + 34                    # . and ..
        for c in d.children:
            n = len(self._ident(c, joliet))
            rec = 33 + n + (1 if n % 2 == 0 else 0)
            if size % SECTOR + rec > SECTOR:
                size += SECTOR - size % SECTOR
            size += rec
        return (size + SECTOR - 1) // SECTOR * SECTOR

    def _path_table(self, dirs: list[_Node], joliet: bool, big: bool) -> bytes:
        out = bytearray()
        for d in dirs:
            ident = b"\x00" if d is self.root else self._ident(d, joliet)
            lba = d.jlba if joliet else d.lba
            parent = 1 if d is self.root else d.parent.number
            out += bytes([len(ident), 0])
            out += struct.pack(">I" if big else "<I", lba)
            out += struct.pack(">H" if big else "<H", parent)
            out += ident + (b"\x00" if len(ident) % 2 else b"")
        return bytes(out)

    def _dir_bytes(self, d: _Node, joliet: bool) -> bytes:
        when = _rec_date(self.when)
        me = (d.jlba, d.jsize) if joliet else (d.lba, d.dsize)
        up = d.parent or d
        par = (up.jlba, up.jsize) if joliet else (up.lba, up.dsize)
        out = bytearray(_record(b"\x00", me[0], me[1], True, when) + _record(b"\x01", par[0], par[1], True, when))
        for c in d.children:
            if c.is_dir:
                rec = _record(self._ident(c, joliet), c.jlba if joliet else c.lba,
                              c.jsize if joliet else c.dsize, True, when)
            else:
                rec = _record(self._ident(c, joliet), c.lba if c.size else 0, c.size, False, when)
            if len(out) % SECTOR + len(rec) > SECTOR:
                out += b"\x00" * (SECTOR - len(out) % SECTOR)
            out += rec
        size = me[1]
        return bytes(out) + b"\x00" * (size - len(out))

    def _descriptor(self, joliet: bool, total: int, pt_size: int, l_lba: int, m_lba: int) -> bytes:
        root = self.root
        rec = _record(b"\x00", root.jlba if joliet else root.lba, root.jsize if joliet else root.dsize,
                      True, _rec_date(self.when))
        vd = bytearray(SECTOR)
        vd[0] = 2 if joliet else 1
        vd[1:6] = b"CD001"
        vd[6] = 1
        vd[8:40] = _pad("WINLAB", 32, joliet)
        vd[40:72] = _pad(self.volume_id, 32, joliet)
        vd[80:88] = _both32(total)
        if joliet:
            vd[88:91] = b"%/E"            # UCS-2 level 3
        vd[120:124] = _both16(1)
        vd[124:128] = _both16(1)
        vd[128:132] = _both16(SECTOR)
        vd[132:140] = _both32(pt_size)
        vd[140:144] = struct.pack("<I", l_lba)
        vd[148:152] = struct.pack(">I", m_lba)
        vd[156:190] = rec
        for off in (190, 318, 446):      # volume set, publisher, preparer
            vd[off:off + 128] = _pad("", 128, joliet)
        vd[574:702] = _pad("WINLAB", 128, joliet)
        for off in (702, 739, 776):
            vd[off:off + 37] = _pad("", 37, joliet)
        d = _vd_date(self.when)
        vd[813:830] = d
        vd[830:847] = d
        vd[847:864] = b"0" * 16 + b"\x00"
        vd[864:881] = d
        vd[881] = 1
        if len(vd) != SECTOR:
            raise IsoWriteError("volume descriptor layout error")
        return bytes(vd)

    # -------------------------------------------------------------- write
    def write(self, dest: str | Path, progress=None) -> Path:
        """Writes the image to dest (through a .part file). progress, if
        given, is called with (bytes written, bytes in total)."""
        dest = Path(dest)
        self._sort(self.root)
        dirs = self._dirs()
        for d in dirs:
            d.dsize = self._dir_size(d, False)
            d.jsize = self._dir_size(d, True)
        pt = len(self._path_table(dirs, False, False))
        jpt = len(self._path_table(dirs, True, False))
        sec = lambda n: (n + SECTOR - 1) // SECTOR  # noqa: E731
        lba = 19                                   # 16 PVD, 17 SVD, 18 terminator
        l_pt, lba = lba, lba + sec(pt)
        m_pt, lba = lba, lba + sec(pt)
        l_jpt, lba = lba, lba + sec(jpt)
        m_jpt, lba = lba, lba + sec(jpt)
        for d in dirs:
            d.lba, lba = lba, lba + d.dsize // SECTOR
        for d in dirs:
            d.jlba, lba = lba, lba + d.jsize // SECTOR
        files: list[_Node] = []

        def collect(n: _Node) -> None:
            for c in n.children:
                if c.is_dir:
                    collect(c)
                else:
                    files.append(c)
        collect(self.root)
        for f in files:
            if f.size:
                f.lba, lba = lba, lba + sec(f.size)
        total = lba
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_name(dest.name + ".part")
        done, whole = 0, sum(f.size for f in files)
        with part.open("wb") as fh:
            fh.write(b"\x00" * (16 * SECTOR))
            fh.write(self._descriptor(False, total, pt, l_pt, m_pt))
            fh.write(self._descriptor(True, total, jpt, l_jpt, m_jpt))
            term = bytearray(SECTOR)
            term[0], term[1:6], term[6] = 255, b"CD001", 1
            fh.write(term)
            for joliet, size in ((False, pt), (True, jpt)):
                for big in (False, True):
                    t = self._path_table(dirs, joliet, big)
                    fh.write(t + b"\x00" * (sec(size) * SECTOR - len(t)))
            for joliet in (False, True):
                for d in dirs:
                    fh.write(self._dir_bytes(d, joliet))
            for f in files:
                if not f.size:
                    continue
                if fh.tell() != f.lba * SECTOR:
                    raise IsoWriteError(f"layout error at {f.name}")
                left = f.size
                with f.source.open("rb") as src:
                    while left:
                        chunk = src.read(min(_CHUNK, left))
                        if not chunk:
                            raise IsoWriteError(f"{f.source} shrank while the disc was written")
                        fh.write(chunk)
                        left -= len(chunk)
                        done += len(chunk)
                        if progress:
                            progress(done, whole)
                if f.size % SECTOR:
                    fh.write(b"\x00" * (SECTOR - f.size % SECTOR))
            if fh.tell() != total * SECTOR:
                raise IsoWriteError("the image size does not match its layout")
        part.replace(dest)
        return dest
