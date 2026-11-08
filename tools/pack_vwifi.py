"""Pack vwifi, built from source, as the release asset winlab fetches
(stdlib only).

The workflow .github/workflows/vwifi.yml builds vwifi at the commit pinned in
winlab/vwifi.py as static Linux x86-64 programs (Alpine's musl, libnl built
from its pinned release and linked in), then runs:

    python tools/pack_vwifi.py --bin build --vwifi-src vwifi-<sha>.tar.gz \\
        --libnl-src libnl-<ver>.tar.gz --license vwifi/LICENSE.md --out vwifi-<short>.tar.gz

Inside, under vwifi/: bin/ (the four programs), LICENSE.md (vwifi's
LGPL-3.0), NOTICE (what this is, how it was built, where its source is) and
source/ with the complete corresponding source of vwifi (a git archive of the
pinned commit) and of libnl (its release tarball), as the LGPL asks for a
program that links them.

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
from winlab import vwifi  # noqa: E402

TOP = "vwifi"
MTIME = 1735689600  # 2025-01-01, as winlab's other reproducible archives


def notice() -> bytes:
    return "\n".join([
        f"vwifi {vwifi.SHORT}: Wi-Fi (802.11) simulation between Linux virtual machines",
        "",
        f"Upstream: {vwifi.UPSTREAM} at commit {vwifi.COMMIT}, unmodified.",
        "Licence: GNU Lesser General Public License v3.0 (LICENSE.md).",
        f"Built by rdiol12/winlablite's workflow (.github/workflows/vwifi.yml) in {vwifi.ALPINE}",
        "as static programs (cmake -DENABLE_VHOST=OFF, linked with -static), so they run as",
        "they are on Alpine Linux and on OpenWrt.",
        "",
        f"Linked in: libnl {vwifi.LIBNL_VERSION} (libnl-3, libnl-genl-3), GNU Lesser General Public",
        f"License v2.1, built from {vwifi.LIBNL_URL}",
        "(./configure --enable-static --disable-shared --disable-cli).",
        "",
        "source/ holds the complete corresponding source of both. To rebuild or relink with a",
        "changed libnl: build libnl from its tarball, then vwifi from its archive against it with",
        "the commands above.",
        "",
        "winlab fetches this archive at preparation onto the customer's PC; nothing of it is in",
        "winlab's installer.",
        ""]).encode()


def pack(bin_dir: Path, vwifi_src: Path, libnl_src: Path, license_file: Path) -> bytes:
    files: dict[str, tuple[bytes, int]] = {
        f"{TOP}/LICENSE.md": (license_file.read_bytes(), 0o644),
        f"{TOP}/NOTICE": (notice(), 0o644),
        f"{TOP}/source/{vwifi_src.name}": (vwifi_src.read_bytes(), 0o644),
        f"{TOP}/source/{libnl_src.name}": (libnl_src.read_bytes(), 0o644),
    }
    for prog in vwifi.PROGRAMS:
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
    ap.add_argument("--vwifi-src", required=True, type=Path)
    ap.add_argument("--libnl-src", required=True, type=Path)
    ap.add_argument("--license", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    data = pack(a.bin, a.vwifi_src, a.libnl_src, a.license)
    a.out.write_bytes(data)
    print(f"{a.out} {len(data)} bytes sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
