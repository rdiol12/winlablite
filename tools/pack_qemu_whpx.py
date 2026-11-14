"""Pack the QEMU with the WHPX reset fix as the release asset winlab fetches
(stdlib only).

QEMU 11.1.x does not put a WHPX machine's secondary processors back into
wait-for-SIPI at a reset; upstream fixed it after 11.1 (winlab/bootstrap.py
says more). The asset is qemu-system-x86_64.exe built from the 11.1 release
MSYS2 packages, with that one upstream commit added, in MSYS2's UCRT64
environment so it runs against the packaged DLLs:

    pacman -S --needed mingw-w64-ucrt-x86_64-{gcc,qemu,meson,ninja,pkgconf,python}
    git clone https://gitlab.com/qemu-project/qemu.git && cd qemu
    git checkout v11.1.3 && git cherry-pick -x 6275714a72
    mkdir build && cd build
    ../configure --target-list=x86_64-softmmu --prefix=/ucrt64 --bindir=bin \\
        --datadir=share/qemu --localedir=share/locale --mandir=share/man \\
        --docdir=share/doc/qemu --enable-whpx --enable-download --disable-werror \\
        --disable-docs --disable-guest-agent --disable-tools
    ninja qemu-system-x86_64.exe && strip qemu-system-x86_64.exe

(Without Windows' Developer Mode, scripts/symlink-install-tree.py cannot make
its links and stops the configure; it only serves running from the build
folder, so let it skip what it cannot link.)

    python tools/pack_qemu_whpx.py --exe qemu-system-x86_64.exe --license COPYING \\
        --patch 0001-target-i386-whpx-handle-processor-reset.patch --out <asset>

Inside, under qemu-whpx-reset/: the program, COPYING (the GNU GPL v2 QEMU
ships), the patch as `git format-patch` wrote it, and a NOTICE (what this is,
how it was built, where the complete source is: the upstream release tarball,
published beside the asset in the same release).

Written the reproducible way winlab's other archives are: sorted names, one
fixed mtime, owner root, fixed modes, ustar, gzip with no name or time.
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
from winlab import bootstrap as bs  # noqa: E402

TOP = "qemu-whpx-reset"
MTIME = 1735689600
SOURCE = f"qemu-{bs.WHPX_FIX_BASE}.tar.xz"


def notice() -> bytes:
    return "\n".join([
        f"QEMU {bs.WHPX_FIX_BASE} for Windows (x86_64-softmmu), with one upstream commit added:",
        f"{bs.WHPX_FIX_COMMIT} \"target/i386/whpx: handle processor reset\" (Doug Cook), which resets the",
        "WHPX partition and re-arms the secondary processors' wait-for-SIPI state when a machine resets.",
        "Without it a WHPX machine with more than one processor triple-faults at its first reboot",
        "(\"WHPX: Unexpected VP exit code 4\"). The commit is in QEMU's master and not in any 11.1 release.",
        "",
        "Upstream: https://www.qemu.org, https://gitlab.com/qemu-project/qemu",
        "Licence: GNU General Public License, version 2 (COPYING); parts of QEMU carry other",
        "GPL-compatible licences, each named in its source file and in the source's LICENSE.",
        "",
        "Modified: yes, by that one commit, unchanged from upstream (the patch is in this archive).",
        "Built in MSYS2's UCRT64 environment against MSYS2's own packages, with the configure line in",
        "tools/pack_qemu_whpx.py of winlab, then stripped. It runs against the DLLs and data files of",
        f"MSYS2's mingw-w64-ucrt-x86_64-qemu {bs.WHPX_FIX_SERIES}x package and replaces only its qemu-system-x86_64.exe.",
        "",
        f"Complete corresponding source: {SOURCE}, QEMU's own release tarball (it carries the",
        f"bundled subprojects), published beside this archive at {bs.WHPX_FIX_RELEASE}/{SOURCE}",
        "plus the patch here. To rebuild: unpack it, apply the patch, run the commands above.",
        "",
        "winlab fetches this archive onto the customer's PC after MSYS2's QEMU, when that QEMU lacks",
        "the fix; nothing of it is in winlab's installer.",
        ""]).encode()


def pack(exe: Path, license_file: Path, patch: Path) -> bytes:
    data = exe.read_bytes()
    if bs.WHPX_FIX_MARK not in data:
        raise SystemExit(f"{exe} is not a QEMU with the reset fix")
    files = {
        f"{TOP}/COPYING": (license_file.read_bytes(), 0o644),
        f"{TOP}/NOTICE": (notice(), 0o644),
        f"{TOP}/{patch.name}": (patch.read_bytes(), 0o644),
        bs.WHPX_FIX_EXE: (data, 0o755),
    }
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            body, mode = files[name]
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(body), MTIME, mode
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            tar.addfile(ti, io.BytesIO(body))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--exe", type=Path, required=True)
    ap.add_argument("--license", type=Path, required=True)
    ap.add_argument("--patch", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    blob = pack(a.exe, a.license, a.patch)
    a.out.write_bytes(blob)
    print(f"{a.out.name}: {len(blob)} bytes, sha256 {hashlib.sha256(blob).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
