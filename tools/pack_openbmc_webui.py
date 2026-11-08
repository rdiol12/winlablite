"""Pack OpenBMC's web UI (webui-vue), built from source, as the release asset
winlab fetches (stdlib only).

The servers' BMCs serve OpenBMC's own web pages (content/agent/bmc.sh,
winlab/openbmcui.py). The project publishes webui-vue as source only, so the
workflow .github/workflows/openbmc-webui.yml builds it at the pinned commit
(npm ci && npm run build) and runs this script on the checkout:

    python tools/pack_openbmc_webui.py --src webui-vue --commit <sha> --out openbmc-webui-<short>.tar.gz

The tarball is reproducible, so winlab can pin its SHA-256 in code: names in
sorted order, one fixed mtime, owner root (0/0), fixed modes, the ustar
format and gzip with no name and no time stamp in its header. The same dist
packed twice, anywhere, gives the same bytes.

Inside, under webui/: the built dist as it is (index.html, css/, js/,
favicon.ico; the large files gzipped by the build itself), webui-vue's own
LICENSE (Apache-2.0), a NOTICE saying what this is and where its source is,
and THIRD-PARTY-LICENSES.txt with the licence of every npm package the UI's
runtime dependencies pull in (from package-lock.json and node_modules).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

UPSTREAM = "https://github.com/openbmc/webui-vue"
TOP = "webui"
MTIME = 1735689600  # 2025-01-01, as winlab's other reproducible archives (alpineovl)
# Listed under "dependencies" in webui-vue's package.json but used only by its
# unit tests (a Jest transformer): nothing of it is in the built UI.
TEST_ONLY = {"@vue/vue3-jest"}
LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "license", "license.md",
                 "LICENSE-MIT", "LICENSE.MIT", "COPYING")


def _resolve(packages: dict, at: str, name: str) -> str | None:
    """The package-lock key node's resolution would load `name` from, seen from `at`."""
    base = at
    while True:
        key = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if key in packages:
            return key
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


def runtime_packages(src: Path) -> list[str]:
    """The package-lock keys of the UI's runtime dependencies, transitively."""
    lock = json.loads((src / "package-lock.json").read_text(encoding="utf-8"))
    packages = lock["packages"]
    root = packages[""]
    todo = [(_resolve(packages, "", n)) for n in sorted(root.get("dependencies", {})) if n not in TEST_ONLY]
    seen: set[str] = set()
    while todo:
        key = todo.pop()
        if not key or key in seen:
            continue
        seen.add(key)
        meta = packages[key]
        for dep in sorted({**meta.get("dependencies", {}), **meta.get("optionalDependencies", {})}):
            todo.append(_resolve(packages, key, dep))
    return sorted(seen)


def third_party(src: Path) -> bytes:
    lock = json.loads((src / "package-lock.json").read_text(encoding="utf-8"))["packages"]
    out = ["Third-party software in OpenBMC's web UI (webui-vue) as built",
           "",
           "The built UI (js/, css/) bundles code from these npm packages, the runtime",
           "dependencies of webui-vue's package.json at the pinned commit, as resolved by",
           "its package-lock.json. Each package's own licence text follows its name.",
           ""]
    names = {}
    for key in runtime_packages(src):
        name = key.split("node_modules/")[-1]
        names.setdefault((name, lock[key].get("version", "")), key)
    for (name, version), key in sorted(names.items()):
        lic = lock[key].get("license", "see the package")
        out += ["=" * 78, f"{name} {version} ({lic})", "=" * 78]
        d = src / key
        text = ""
        for fn in LICENSE_NAMES:
            if (d / fn).is_file():
                text = (d / fn).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").strip()
                break
        out += [text or f"(no licence file in the package; its package.json says {lic})", ""]
    return ("\n".join(out) + "\n").encode("utf-8")


def notice(commit: str) -> bytes:
    return (
        "OpenBMC web UI (webui-vue)\n"
        "\n"
        f"Built from {UPSTREAM} at commit {commit},\n"
        "unmodified, with `npm ci && npm run build` (the production build, as OpenBMC's\n"
        "Yocto recipe makes it). Copyright the OpenBMC project contributors, licensed\n"
        "under the Apache License 2.0 (LICENSE). Its source is at the address above.\n"
        "\n"
        "Packed by winlab (tools/pack_openbmc_webui.py, workflow openbmc-webui.yml) for\n"
        "the lab's server management processors, which serve these pages on the lab\n"
        "network only. THIRD-PARTY-LICENSES.txt lists the npm packages built into it,\n"
        "each with its licence. One of them, noVNC (@novnc/novnc), is under the Mozilla\n"
        "Public License 2.0: it is built in unmodified, and its source is the npm package\n"
        "of the version listed there and https://github.com/novnc/noVNC at that version.\n"
    ).encode("utf-8")


def collect(src: Path, commit: str) -> dict[str, bytes]:
    dist = src / "dist"
    if not (dist / "index.html").is_file():
        raise SystemExit(f"{dist}/index.html missing: build webui-vue first (npm ci && npm run build)")
    files = {f"{TOP}/{p.relative_to(dist).as_posix()}": p.read_bytes() for p in dist.rglob("*") if p.is_file()}
    files[f"{TOP}/LICENSE"] = (src / "LICENSE").read_bytes()
    files[f"{TOP}/NOTICE"] = notice(commit)
    files[f"{TOP}/THIRD-PARTY-LICENSES.txt"] = third_party(src)
    return files


def pack(files: dict[str, bytes]) -> bytes:
    """A reproducible .tar.gz of these files (and their directories)."""
    dirs = sorted({"/".join(n.split("/")[:i]) for n in files for i in range(1, n.count("/") + 1)})
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(set(dirs) | set(files)):
            ti = tarfile.TarInfo(name)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = MTIME, 0, 0, "root", "root"
            if name in files:
                ti.size, ti.mode, ti.type = len(files[name]), 0o644, tarfile.REGTYPE
                tar.addfile(ti, io.BytesIO(files[name]))
            else:
                ti.mode, ti.type = 0o755, tarfile.DIRTYPE
                tar.addfile(ti)
    out = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=out, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--src", required=True, type=Path, help="the webui-vue checkout, built")
    ap.add_argument("--commit", required=True, help="the commit it was built at")
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    data = pack(collect(a.src, a.commit))
    a.out.write_bytes(data)
    print(f"{a.out}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
