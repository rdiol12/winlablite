"""Alpine packages for the fabric and the Alpine nodes, fetched on this PC at
preparation and carried on a repository volume, so the machines install them
offline at boot.

The fabric runs the stock Alpine ISO diskless. Alpine's init (mkinitfs)
mounts every volume it finds, keeps the ones that hold an ``*.apkovl.tar.gz``
overlay or a "boot repository" (a directory at the volume's top level with a
``.boot_repository`` marker and ``x86_64/APKINDEX.tar.gz`` beside the
packages), writes those repositories to /etc/apk/repositories and installs
the overlay's /etc/apk/world from them with ``apk add
--initramfs-diskless-boot --no-network``. The ISO's own ``apks`` directory is
such a repository and carries the base system only; the lab has no internet;
so winlab prepares a second volume, ``bases/alpine-repo.img``, laid out the
same way: ``main`` and ``community`` directories, each with the mirror's
signed APKINDEX for the ISO's own release branch and the packages the
fabric's world resolves to (alpine-base included, because apk takes the
newest version it sees and the mirror moves ahead of the ISO). Nothing is
bundled with winlab: the packages come from the Alpine mirror onto the
customer's PC at preparation (LICENSING.md).
"""

from __future__ import annotations

import io
import json
import re
import sys
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from . import fatfs, paths

MIRROR = "https://dl-cdn.alpinelinux.org/alpine/"
REPOS = ("main", "community")
ARCH = "x86_64"
INDEX = "APKINDEX.tar.gz"
MARKER = ".boot_repository"
IMAGE_LABEL = "WLAPK"
IMAGE_NAME = "alpine-repo.img"
SLACK_MB = 8


class ApkError(Exception):
    pass


@dataclass
class Apk:
    name: str
    version: str = ""
    repo: str = ""
    size: int = 0
    depends: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    install_if: list[str] = field(default_factory=list)
    priority: int = 0
    origin: str = ""

    @property
    def filename(self) -> str:
        return f"{self.name}-{self.version}.apk"


_OPS = re.compile(r"[<>=~]")


def dep_name(spec: str) -> str:
    """'musl>=1.2', 'so:libc.musl-x86_64.so.1', 'cmd:nft=1.0' -> the name."""
    return _OPS.split(spec.lstrip("!"), 1)[0]


def parse_index(text: str, repo: str = "") -> dict[str, Apk]:
    """The APKINDEX text: records of 'K:value' lines separated by blank
    lines (P name, V version, S size, D depends, p provides, i install_if,
    k provider priority, o origin)."""
    db: dict[str, Apk] = {}
    rec: dict[str, str] = {}

    def flush() -> None:
        if rec.get("P"):
            pkg = Apk(name=rec["P"], version=rec.get("V", ""), repo=repo,
                      size=int(rec.get("S") or 0), depends=rec.get("D", "").split(),
                      provides=rec.get("p", "").split(), install_if=rec.get("i", "").split(),
                      priority=int(rec.get("k") or 0), origin=rec.get("o", ""))
            db.setdefault(pkg.name, pkg)
        rec.clear()

    for line in text.splitlines():
        if not line.strip():
            flush()
            continue
        if len(line) > 1 and line[1] == ":":
            rec[line[0]] = line[2:]
    flush()
    return db


def read_index(data: bytes, repo: str = "") -> dict[str, Apk]:
    """APKINDEX.tar.gz as the mirror serves it: a signature segment and a
    tar segment holding APKINDEX and DESCRIPTION, both gzip; Python's gzip
    reader walks the concatenated members."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith("APKINDEX") and m.isfile():
                f = tar.extractfile(m)
                return parse_index(f.read().decode("utf-8", "replace") if f else "", repo)
    raise ApkError("no APKINDEX member in the index archive")


def resolve(dbs: list[dict[str, Apk]], roots: list[str]) -> tuple[list[Apk], list[str]]:
    """The packages that satisfy ``roots`` and everything they depend on,
    the way apk picks them: a package by its name, a virtual (``so:``,
    ``cmd:``, ``pc:`` or a plain provides name) by its single provider, or
    among several by the highest provider priority; conflicts (``!x``) are
    skipped; and a package whose install_if list is wholly present joins in
    (that is how the ``-openrc`` subpackages arrive). The repositories are
    searched in order. Returns (packages, dependency names nobody provides)."""
    by_name: dict[str, Apk] = {}
    providers: dict[str, list[Apk]] = {}
    for db in dbs:
        for pkg in db.values():
            by_name.setdefault(pkg.name, pkg)
            for prov in pkg.provides:
                providers.setdefault(dep_name(prov), []).append(pkg)
    out: dict[str, Apk] = {}
    missing: list[str] = []

    def pick(name: str) -> Apk | None:
        if name in by_name:
            return by_name[name]
        cands = providers.get(name) or []
        if not cands:
            return None
        chosen = [c for c in cands if c.name in out]
        if chosen:
            return chosen[0]
        return sorted(cands, key=lambda c: (-c.priority, c.name))[0]

    def walk(specs: list[str]) -> None:
        queue = list(specs)
        while queue:
            spec = queue.pop()
            if spec.startswith("!"):
                continue
            name = dep_name(spec)
            if name in out:
                continue
            pkg = pick(name)
            if pkg is None:
                if name not in missing:
                    missing.append(name)
                continue
            if pkg.name in out:
                continue
            out[pkg.name] = pkg
            queue.extend(pkg.depends)

    walk(roots)
    changed = True
    while changed:
        changed = False
        names = set(out) | {dep_name(v) for pkg in out.values() for v in pkg.provides}
        for db in dbs:
            for pkg in db.values():
                if pkg.name in out or not pkg.install_if:
                    continue
                if all(dep_name(d) in names for d in pkg.install_if if not d.startswith("!")):
                    walk([pkg.name])
                    changed = True
    return sorted(out.values(), key=lambda p: (p.repo, p.name)), sorted(missing)


def branch_of(release: str) -> str:
    """'alpine-virt-3.21.3 2025-02-13' (the ISO's .alpine-release) or
    '3.21.3' -> 'v3.21'; anything else -> 'latest-stable'."""
    m = re.search(r"(\d+)\.(\d+)", release or "")
    return f"v{m.group(1)}.{m.group(2)}" if m else "latest-stable"


def iso_release(iso: Path) -> str:
    """The release the ISO carries (its .alpine-release file), or ''."""
    from . import iso9660
    try:
        with iso9660.Iso(iso) as i:
            return i.read(".alpine-release").decode("ascii", "replace").strip()
    except Exception:  # noqa: BLE001 - unreadable media: the caller falls back to the mirror's latest
        return ""


def cache_dir(branch: str) -> Path:
    return paths.downloads_dir() / "apk" / branch


def repo_dir(branch: str, repo: str) -> Path:
    return cache_dir(branch) / repo / ARCH


def manifest_path(branch: str) -> Path:
    return cache_dir(branch) / "manifest.json"


def default_roots() -> list[str]:
    from . import alpineovl
    return ["alpine-base"] + list(alpineovl.FABRIC_PACKAGES) + list(alpineovl.APPLIANCE_PACKAGES)


@dataclass
class FetchReport:
    branch: str
    release: str
    packages: list[Apk]
    missing: list[str]
    downloaded: int = 0
    bytes: int = 0

    @property
    def dir(self) -> Path:
        return cache_dir(self.branch)


def fetch(roots: list[str] | None = None, iso: Path | None = None, refresh: bool = False,
          say=lambda s: print(s, file=sys.stderr)) -> FetchReport:
    """Resolve and download the package set for the ISO's branch into the
    downloads cache (images/downloads/apk/<branch>/<repo>/x86_64). Needs
    the network like every fetch; files already there are kept unless
    ``refresh`` asks for the indexes again."""
    from . import bootstrap
    roots = list(roots or default_roots())
    release = iso_release(iso) if iso else ""
    branch = branch_of(release)
    say(f"  alpine packages for {branch}" + (f" ({release.split()[0]})" if release else ""))
    dbs: list[dict[str, Apk]] = []
    for repo in REPOS:
        idx = repo_dir(branch, repo) / INDEX
        if refresh or not idx.exists():
            bootstrap._download_to(f"{MIRROR}{branch}/{repo}/{ARCH}/{INDEX}", idx, label=f"{repo} index")
        dbs.append(read_index(idx.read_bytes(), repo))
    pkgs, missing = resolve(dbs, roots)
    report = FetchReport(branch=branch, release=release, packages=pkgs, missing=missing)
    for i, pkg in enumerate(pkgs, 1):
        dest = repo_dir(branch, pkg.repo) / pkg.filename
        if dest.exists() and (not pkg.size or dest.stat().st_size == pkg.size):
            continue
        bootstrap._download_to(f"{MIRROR}{branch}/{pkg.repo}/{ARCH}/{pkg.filename}", dest,
                               label=f"[{i}/{len(pkgs)}] {pkg.name}")
        report.downloaded += 1
    report.bytes = sum((repo_dir(branch, p.repo) / p.filename).stat().st_size
                       for p in pkgs if (repo_dir(branch, p.repo) / p.filename).exists())
    manifest_path(branch).write_text(json.dumps({
        "branch": branch, "release": release, "roots": roots,
        "packages": [{"name": p.name, "version": p.version, "repo": p.repo, "size": p.size}
                     for p in pkgs],
        "missing": missing}, indent=2), encoding="utf-8")
    say(f"  {len(pkgs)} packages, {report.bytes / (1024 ** 2):.0f} MiB"
        + (f"; not on the mirror: {', '.join(missing)}" if missing else ""))
    return report


def cached(branch: str = "") -> Path | None:
    """The fetched set for a branch, or the most recent one when no branch
    is named; None when nothing was fetched yet."""
    if branch:
        return cache_dir(branch) if manifest_path(branch).exists() else None
    root = paths.downloads_dir() / "apk"
    found = sorted(root.glob("*/manifest.json"), key=lambda p: p.stat().st_mtime) if root.exists() else []
    return found[-1].parent if found else None


def manifest(cache: Path) -> dict:
    try:
        return json.loads((cache / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def image_path() -> Path:
    return paths.bases_dir() / IMAGE_NAME


def build_image(cache: Path, dest: Path | None = None) -> Path:
    """The repository volume: a FAT image with one boot repository per Alpine
    repository at its top level (``main/.boot_repository``,
    ``main/x86_64/APKINDEX.tar.gz`` and the packages the manifest lists;
    ``community`` likewise). nlplug-findfs looks one level down for the
    marker, which is why the directories sit at the root."""
    dest = dest or image_path()
    man = manifest(cache)
    wanted = {(p["repo"], f"{p['name']}-{p['version']}.apk") for p in man.get("packages", [])}
    files: list[tuple[str, Path]] = []
    for repo in REPOS:
        d = cache / repo / ARCH
        if not (d / INDEX).exists():
            continue
        files.append((f"{repo}/{ARCH}/{INDEX}", d / INDEX))
        for f in sorted(d.iterdir()):
            if f.name.endswith(".apk") and (not wanted or (repo, f.name) in wanted):
                files.append((f"{repo}/{ARCH}/{f.name}", f))
    if not files:
        raise ApkError(f"no package indexes under {cache}")
    # Firmware beside the packages: the appliances' Webmin release tarball,
    # when it was fetched (winlab/webmin.py); the webmin role installs it.
    # And OpenBMC's web UI for the servers' BMCs on the router (winlab/openbmcui.py).
    from . import openbmcui, webmin
    files += webmin.volume_files()
    files += openbmcui.volume_files()
    total = sum(f.stat().st_size for _, f in files)
    size_mb = max(16, (total + 4096 * len(files)) // (1024 * 1024) + SLACK_MB)
    img = fatfs.disk(int(size_mb), IMAGE_LABEL)
    for repo in sorted({name.split("/")[0] for name, _ in files} & set(REPOS)):
        img.add_file(f"{repo}/{MARKER}", b"")
    for name, f in files:
        img.add_path(name, f)
    img.add_file("README.txt", (
        "winlab repository volume: the Alpine packages the fabric and the Alpine "
        "machines install at boot, fetched from the Alpine mirror at preparation.\r\n"
        f"branch {man.get('branch', '?')}, {len(files)} files\r\n").encode())
    dest.parent.mkdir(parents=True, exist_ok=True)
    return img.write(dest)


def describe(cache: Path | None = None) -> list[str]:
    """What is fetched, for `winlab images` and the Setup step."""
    cache = cache or cached()
    if not cache:
        return ["alpine packages: not fetched yet (winlab images prepare fabric)"]
    man = manifest(cache)
    pkgs = man.get("packages", [])
    size = sum(int(p.get("size") or 0) for p in pkgs)
    out = [f"alpine packages: {man.get('branch', cache.name)}, {len(pkgs)} packages, "
           f"{size / (1024 ** 2):.0f} MiB in {cache}"]
    if man.get("missing"):
        out.append(f"  not on the mirror: {', '.join(man['missing'])}")
    img = image_path()
    out.append(f"  repository volume: {img}" + ("" if img.exists() else " (not built)"))
    return out
