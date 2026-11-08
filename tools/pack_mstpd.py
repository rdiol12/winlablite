"""Pack mstpd, built from source, as the release asset winlab fetches
(stdlib only).

The workflow .github/workflows/mstpd.yml builds mstpd at the release pinned in
winlab/mstpd.py as static Linux x86-64 programs (Alpine's musl), then runs:

    python tools/pack_mstpd.py --bin build --src mstpd-<version>-<short>-source.tar.gz \\
        --license mstpd/LICENSE --out mstpd-<version>-<short>.tar.gz

Inside, under mstpd/: bin/ (mstpd and mstpctl), LICENSE (the GNU GPL v2
mstpd ships), NOTICE (what this is, how it was built, where its source is)
and source/ with the complete corresponding source (a git archive of the
pinned commit, which carries the build scripts too), as the GPL asks of
anyone who passes the programs on.

The tarball is written the reproducible way winlab's other archives are:
names in sorted order, one fixed mtime, owner root (0/0), fixed modes, the
ustar format and gzip with no name and no time stamp in its header.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from winlab import mstpd  # noqa: E402

TOP = "mstpd"
MTIME = 1735689600  # 2025-01-01, as winlab's other reproducible archives


def notice() -> bytes:
    return "\n".join([
        f"mstpd {mstpd.VERSION} ({mstpd.SHORT}): the Linux daemon for rapid and multiple spanning tree",
        "(IEEE 802.1w RSTP and 802.1s MSTP) on Linux bridges, and its command line mstpctl.",
        "",
        f"Upstream: {mstpd.UPSTREAM}, release {mstpd.VERSION} (commit {mstpd.COMMIT}), unmodified.",
        "Licence: GNU General Public License, version 2 or (at your option) any later version",
        "(LICENSE; each source file says so in its header). hmac_md5.c carries RSA Data Security's",
        "MD5 notice from RFC 1321 and RFC 2104, as in the source.",
        f"Built by rdiol12/winlablite's workflow (.github/workflows/mstpd.yml) in {mstpd.ALPINE}",
        "(./autogen.sh, ./configure --prefix=/usr, make LDFLAGS=-all-static, strip) as static",
        "programs, so they run as they are on Alpine Linux.",
        "",
        f"source/ holds the complete corresponding source: the git archive of commit {mstpd.SHORT},",
        "with the build scripts. To rebuild: unpack it and run the commands above.",
        "",
        "winlab fetches this archive at preparation onto the customer's PC; nothing of it is in",
        "winlab's installer. The lab router runs the programs unmodified; winlab's own",
        "/sbin/bridge-stp (a small shell script) hands the switch bridges to mstpd.",
        ""]).encode()


def pack(bin_dir: Path, src: Path, license_file: Path) -> bytes:
    files: dict[str, tuple[bytes, int]] = {
        f"{TOP}/LICENSE": (license_file.read_bytes(), 0o644),
        f"{TOP}/NOTICE": (notice(), 0o644),
        f"{TOP}/source/{src.name}": (src.read_bytes(), 0o644),
    }
    for prog in mstpd.PROGRAMS:
        data = (bin_dir / prog).read_bytes()
        if not data.startswith(b"\x7fELF"):
            raise SystemExit(f"{prog} is not a Linux program")
        files[f"{TOP}/bin/{prog}"] = (data, 0o755)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            data, mode = files[name]
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, MTIME
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", required=True, type=Path, help="the folder holding the built programs")
    ap.add_argument("--src", required=True, type=Path, help="the source archive of the pinned commit")
    ap.add_argument("--license", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    data = pack(a.bin, a.src, a.license)
    a.out.write_bytes(data)
    print(f"{a.out} {len(data)} bytes sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
