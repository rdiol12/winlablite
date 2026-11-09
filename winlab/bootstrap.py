"""Fetch the portable QEMU runtime into ./runtime. Installs nothing."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

# ucrt64, not mingw64: MSYS2 dropped qemu from the legacy mingw64 repo.
ENV = "ucrt64"
REPO = f"https://repo.msys2.org/mingw/{ENV}/"
DB_FILE = f"{ENV}.db.tar.zst"
PREFIX = "mingw-w64-ucrt-x86_64-"

ROOT_PACKAGES = [
    f"{PREFIX}qemu",
    f"{PREFIX}qemu-image-util",
    f"{PREFIX}qemu-guest-agent",
]

USER_AGENT = "winlab/0.1"
RETRIES = 4


@dataclass
class Pkg:
    name: str
    version: str = ""
    filename: str = ""
    sha256: str = ""
    depends: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    csize: int = 0


class BootstrapError(Exception):
    pass


def _get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise BootstrapError(f"cannot reach {url}: {exc}") from exc


def _sha256(path: Path) -> str:
    return _digest(path, "")


def _digest(path: Path, expect: str) -> str:
    """The file's SHA-256, or its SHA-512 when the expected digest is one
    (128 hex digits: Debian publishes SHA512SUMS for its cloud images, npm
    its packages' integrity), or its SHA-384 (96: MeshCentral pins its
    agents by it)."""
    h = hashlib.sha512() if len(expect) == 128 else hashlib.sha384() if len(expect) == 96 else hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# Downloads report progress two ways. On its own (the command line) a
# download redraws one console line with \r. Inside a desktop job, several
# downloads run at once in their own threads; \r there made them overwrite
# each other on the one console. So a job sets a sink for its thread: the
# percent goes to the job's own bar and log, and the console gets one whole
# line per tenth, named, so parallel fetches read as a list.
_SINK = threading.local()


def set_progress_sink(fn) -> None:
    """Send this thread's download progress to fn(line) (None: the console)."""
    _SINK.fn = fn


def _sink():
    return getattr(_SINK, "fn", None)


def _say(label: str, text: str, live: bool = False) -> None:
    """One progress report for a download named label."""
    sink = _sink()
    if sink is None:
        print(f"\r    {label:<46} {text}", end="" if live else "\n", file=sys.stderr)
        return
    print(f"    {label:<46} {text}", file=sys.stderr, flush=True)
    sink(f"{label}: {text}")


def _open_resuming(url: str, tmp: Path):
    """The response and how many bytes of tmp it continues from. A .part
    left by a closed winlab or a dropped connection is resumed with a Range
    request; a server that answers with the whole file (200) or cannot
    resume starts it over."""
    have = tmp.stat().st_size if tmp.exists() else 0
    headers = {"User-Agent": USER_AGENT}
    if have:
        headers["Range"] = f"bytes={have}-"
    try:
        resp = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=180)
    except urllib.error.HTTPError as exc:
        if exc.code != 416 or not have:
            raise
        # 416: the .part is not a prefix the server can continue (whole, or
        # from another version of the file): start it over.
        tmp.unlink(missing_ok=True)
        return _open_resuming(url, tmp)
    if have and getattr(resp, "status", 200) != 206:
        have = 0
    return resp, have


def _stream_once(url: str, tmp: Path, label: str) -> tuple[int, int]:
    in_job = _sink() is not None
    resp, have = _open_resuming(url, tmp)
    if have and label:
        _say(label, f" resuming at {have // (1 << 20)} MB")
    with resp, tmp.open("ab" if have else "wb") as fh:
        rest = int(resp.headers.get("Content-Length") or 0)
        expect = have + rest if rest else 0
        done = have
        shown = -1
        while True:
            chunk = resp.read(262144)
            if not chunk:
                break
            fh.write(chunk)
            done += len(chunk)
            if label and expect:
                if not in_job:
                    _say(label, f"{100 * done / expect:5.1f}%", live=True)
                elif (step := int(10 * done / expect)) > shown and done < expect:
                    shown = step
                    _say(label, f"{10 * step:3d}%")
    return done, expect


def _download_to(url: str, dest: Path, expect_sha: str = "", label: str = "") -> Path:
    if dest.exists() and expect_sha and _digest(dest, expect_sha) == expect_sha:
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    last = ""

    for attempt in range(1, RETRIES + 1):
        try:
            got, expect = _stream_once(url, tmp, label)
        except (urllib.error.URLError, OSError) as exc:
            last = f"transport error: {exc}"  # the .part stays: the next attempt resumes it
        else:
            # A dropped connection ends read() cleanly, so a short body looks
            # identical to a complete one unless the length is checked.
            if expect and got != expect:
                last = f"short read: {got} of {expect} bytes"  # resumed next attempt
            elif expect_sha and (actual := _digest(tmp, expect_sha)) != expect_sha:
                last = f"checksum mismatch: wanted {expect_sha[:16]}, got {actual[:16]}"
                tmp.unlink(missing_ok=True)  # bad bytes: never resume from them
            else:
                if label:
                    _say(label, " done ")
                tmp.replace(dest)
                return dest

        if attempt < RETRIES:
            if label:
                _say(label, f" retry {attempt}: {last}")
            time.sleep(1.5 * attempt)

    raise BootstrapError(f"{dest.name}: gave up after {RETRIES} attempts ({last})")


# Half files. A download's .part is kept so the next fetch resumes it, but
# one nobody fetches again would sit there for good, and an import copy
# (.copying) cannot be resumed at all. When winlab starts, leftovers that
# nothing has written to for a while are removed.
PART_KEEP_DAYS = 7
COPY_IDLE_MINUTES = 10


def clean_leftovers(roots: list[Path] | None = None, now: float | None = None) -> list[Path]:
    """Remove .part downloads untouched for PART_KEEP_DAYS and .copying
    imports untouched for COPY_IDLE_MINUTES (a copy still running keeps
    touching its file); returns what was removed."""
    now = time.time() if now is None else now
    if roots is None:
        roots = [paths.images_dir(), paths.RUNTIME, paths.VAR]
    gone: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for f in list(root.rglob("*.part")) + list(root.rglob("*.copying")):
            try:
                idle = now - f.stat().st_mtime
                limit = PART_KEEP_DAYS * 86400 if f.suffix == ".part" else COPY_IDLE_MINUTES * 60
                if f.is_file() and idle > limit:
                    f.unlink()
                    gone.append(f)
            except OSError:
                pass
    return gone


def _have_zstd_tar() -> tuple[bool, str]:
    exe = shutil.which("tar")
    if not exe:
        return False, "no tar on PATH"
    try:
        out = subprocess.run(
            [exe, "--version"], capture_output=True, timeout=30
        ).stdout.decode("utf-8", "replace")
    except (subprocess.SubprocessError, OSError) as exc:
        return False, f"tar --version failed: {exc}"
    if "libzstd" not in out:
        return False, f"tar lacks zstd support: {out.strip()[:120]}"
    return True, out.strip().splitlines()[0]


def _tar_exe() -> str:
    """Must be bsdtar: it has libzstd linked in, whereas GNU tar shells out to
    a zstd binary that is not present on Windows."""
    if os.name == "nt":
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tar.exe"
        if system32.exists():
            return str(system32)
    exe = shutil.which("tar")
    if not exe:
        raise BootstrapError("tar is required to unpack .tar.zst archives")
    return exe


# Translations, docs and man pages are dead weight for a lab runtime, and the
# locale trees are where the unextractable symlinks live.
EXCLUDES = [
    "--exclude=*/share/locale/*",
    "--exclude=*/share/man/*",
    "--exclude=*/share/doc/*",
    "--exclude=*/share/info/*",
    "--exclude=*/share/gtk-doc/*",
]


def _extract_zst(
    archive: Path, dest: Path, members: list[str] | None = None, prune: bool = False
) -> tuple[bool, int]:
    """(extracted_anything, skipped_entries).

    Per-entry failures are counted, not fatal: Windows cannot create the
    symlinks some packages carry without elevation, and nothing winlab needs
    is a symlink. Whether the runtime is actually usable is decided afterwards
    by checking for the qemu binary.
    """
    exe = _tar_exe()
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "-xf", str(archive), "-C", str(dest)]
    if prune:
        cmd += EXCLUDES
    if members:
        cmd += ["--strip-components=1"] + members
    res = subprocess.run(cmd, capture_output=True)
    err = (res.stderr or b"").decode("utf-8", "replace").strip()

    if res.returncode == 0:
        return True, 0
    if members and "Not found in archive" in err:
        return False, 0

    lines = [l.strip() for l in err.splitlines() if l.strip()]
    skipped = sum(1 for l in lines if "Can't create" in l)
    benign = sum(
        1
        for l in lines
        if "Can't create" in l
        or "Error exit delayed" in l
        or "Cannot restore" in l
    )
    if skipped and benign == len(lines):
        return True, skipped
    raise BootstrapError(f"extract failed for {archive.name}: {err[:400]}")


def load_db(refresh: bool = False) -> dict[str, Pkg]:
    cache = paths.RUNTIME / "cache" / DB_FILE
    if refresh or not cache.exists():
        print(f"  fetching package database {DB_FILE}", file=sys.stderr)
        _download_to(REPO + DB_FILE, cache, label=DB_FILE)

    with tempfile.TemporaryDirectory(prefix="winlab-db-") as tmpd:
        tmp = Path(tmpd)
        _extract_zst(cache, tmp)[0]
        db: dict[str, Pkg] = {}
        for desc in tmp.rglob("desc"):
            pkg = _parse_desc(desc.read_text(encoding="utf-8", errors="replace"))
            if pkg and pkg.name:
                db[pkg.name] = pkg
    if not db:
        raise BootstrapError("package database parsed to zero entries")
    return db


def _parse_desc(text: str) -> Pkg | None:
    fields: dict[str, list[str]] = {}
    key = None
    for line in text.splitlines():
        line = line.rstrip()
        if line.startswith("%") and line.endswith("%"):
            key = line.strip("%")
            fields[key] = []
        elif line and key:
            fields[key].append(line)
    if "NAME" not in fields:
        return None
    return Pkg(
        name=fields["NAME"][0],
        version=(fields.get("VERSION") or [""])[0],
        filename=(fields.get("FILENAME") or [""])[0],
        sha256=(fields.get("SHA256SUM") or [""])[0],
        depends=fields.get("DEPENDS", []),
        provides=fields.get("PROVIDES", []),
        csize=int((fields.get("CSIZE") or ["0"])[0] or 0),
    )


def _dep_name(spec: str) -> str:
    for sep in (">=", "<=", "==", ">", "<", "="):
        if sep in spec:
            return spec.split(sep, 1)[0]
    return spec


def resolve(db: dict[str, Pkg], roots: list[str]) -> list[Pkg]:
    provided: dict[str, str] = {}
    for pkg in db.values():
        for prov in pkg.provides:
            provided.setdefault(_dep_name(prov), pkg.name)

    out: dict[str, Pkg] = {}
    missing: list[str] = []
    queue = list(roots)
    while queue:
        name = _dep_name(queue.pop())
        if name in out:
            continue
        pkg = db.get(name) or db.get(provided.get(name, ""))
        if pkg is None:
            if name.startswith(PREFIX):
                missing.append(name)
            continue
        out[pkg.name] = pkg
        queue.extend(pkg.depends)

    if missing:
        raise BootstrapError("unresolved packages: " + ", ".join(sorted(missing)))
    return sorted(out.values(), key=lambda p: p.name)


def write_manifest(closure: list[Pkg]) -> Path:
    out = paths.RUNTIME / "manifest.txt"
    lines = [f"{p.name}\t{p.version}\t{p.sha256}" for p in closure]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def _link_linux_qemu(say) -> None:
    """Linux: the distribution's QEMU, installed with its package manager
    (the desktop asks for the password) when it is not there yet, then laid
    out in ./runtime/qemu (winlab/linuxhost.py)."""
    from . import linuxhost

    if linuxhost.missing_parts():
        say("QEMU is not installed on this PC yet")
        print("  " + linuxhost.install_hint(), file=sys.stderr)
        linuxhost.install_packages(say=lambda m: (say(m), print(f"  {m}", file=sys.stderr)))
    try:
        exe = linuxhost.link_runtime(say=lambda m: (say(m), print(f"  {m}", file=sys.stderr)))
    except linuxhost.LinuxHostError as exc:
        raise BootstrapError(str(exc)) from exc
    print(f"  using this PC's QEMU: {exe.resolve()}", file=sys.stderr)


def _fetch_windows_qemu(refresh: bool, keep_downloads: bool, say) -> None:
    """Windows: QEMU's MSYS2 build, unpacked into ./runtime/qemu."""
    ok, detail = _have_zstd_tar()
    if not ok:
        raise BootstrapError(
            f"{detail}\nwinlab unpacks .tar.zst using the bsdtar bundled with Windows 10/11; "
            f"on older hosts use the bootable appliance runtime instead"
        )
    print(f"  tar: {detail}", file=sys.stderr)

    db = load_db(refresh=refresh)
    print(f"  database: {len(db)} packages", file=sys.stderr)

    closure = resolve(db, ROOT_PACKAGES)
    total = sum(p.csize for p in closure)
    print(
        f"  closure:  {len(closure)} packages, {total / (1024 ** 2):.0f} MiB compressed",
        file=sys.stderr,
    )

    cache = paths.RUNTIME / "cache" / "pkgs"
    archives: list[Path] = []
    for i, pkg in enumerate(closure, 1):
        say(f"[{i}/{len(closure)}] {pkg.name} {pkg.version}")
        if not pkg.filename:
            raise BootstrapError(f"package {pkg.name} has no FILENAME in the database")
        archives.append(
            _download_to(
                REPO + pkg.filename,
                cache / pkg.filename,
                pkg.sha256,
                f"[{i}/{len(closure)}] {pkg.name}",
            )
        )

    target = paths.qemu_dir()
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)

    print(f"  unpacking into {target}", file=sys.stderr)
    empty = skipped = 0
    for archive in archives:
        got, n = _extract_zst(archive, target, members=[ENV], prune=True)
        if not got:
            empty += 1
        skipped += n
    if empty:
        print(f"  {empty} metapackages had no payload (expected)", file=sys.stderr)
    if skipped:
        print(f"  {skipped} symlink entries skipped (not needed)", file=sys.stderr)

    exe = paths.qemu_exe()
    if not exe.exists():
        raise BootstrapError(
            f"unpack finished but {exe.name} is missing; the qemu package layout may have changed"
        )

    write_manifest(closure)
    if not keep_downloads:
        shutil.rmtree(cache, ignore_errors=True)


def bootstrap(refresh: bool = False, keep_downloads: bool = False, progress=None) -> Path:
    """progress(line), when given, gets one line per package and per phase
    (the desktop's progress bar reads the [n/m] in them)."""
    say = progress or (lambda line: None)
    paths.ensure_dirs()

    if is_linux():
        _link_linux_qemu(say)
    else:
        _fetch_windows_qemu(refresh, keep_downloads, say)

    # The DSC resource modules the role engine compiles against: same rule,
    # fetched onto this machine, never shipped.
    from . import psmodules

    say("unpacked; fetching the DSC resource modules (PowerShell Gallery)")
    print("  fetching DSC resource modules", file=sys.stderr)
    try:
        psmodules.fetch()
    except psmodules.ModuleError as exc:
        raise BootstrapError(str(exc)) from exc

    # The browser console viewer (noVNC): fetched, pinned, never shipped.
    from . import viewer

    say("fetching the console viewer (noVNC)")
    print("  fetching the console viewer", file=sys.stderr)
    try:
        viewer.fetch()
    except viewer.ViewerError as exc:
        raise BootstrapError(str(exc)) from exc
    # The Linux machines' terminal (xterm.js), the same way.
    from . import termview

    say("fetching the terminal (xterm.js)")
    try:
        termview.fetch()
    except termview.TermError as exc:
        raise BootstrapError(str(exc)) from exc
    # The Network map's laid-out view (Cytoscape.js), the same way; without
    # it the map keeps its VLAN view, so a failure here is not fatal.
    from . import mapview

    say("fetching the network map layout (Cytoscape.js)")
    try:
        mapview.fetch()
    except mapview.MapViewError as exc:
        print(f"  warning: Cytoscape.js not fetched ({exc}); the Network map keeps its VLAN view", file=sys.stderr)
    # The Performance window's charts (uPlot), the Recordings window's player
    # (asciinema-player) and the Network map's Tidy layout (ELK, EPL-2.0,
    # served unmodified, with its Cytoscape adapter), the same way; each
    # page keeps its own drawing without them, so none of these is fatal.
    from . import castplayer, chartview, drawio, elkview, pixiview

    for part, what, keeps in ((chartview, "the performance charts (uPlot)", "the meters keep their own lines"),
                              (castplayer, "the recording player (asciinema-player)", "recordings are kept, not played"),
                              (elkview, "the map's Tidy layout (ELK)", "the map keeps its tree layout"),
                              (drawio, "the network diagram viewer (diagrams.net)",
                               "the diagram is still offered as a .drawio file"),
                              (pixiview, "the building view (PixiJS)", "the Building window keeps its own drawing")):
        say(f"fetching {what}")
        try:
            part.fetch()
        except part.TermError as exc:
            print(f"  warning: {what} not fetched ({exc}); {keeps}", file=sys.stderr)
    # winlab's own program window hosts WebView2 (part of Windows) through
    # Microsoft's loader DLL, fetched the same way. Without it the desktop
    # opens in an Edge app window, so a failure here is not fatal.
    if sys.platform == "win32":
        from . import nativewin

        say("fetching the program window's WebView2 loader")
        try:
            nativewin.fetch()
        except (nativewin.NativeWindowError, OSError, ValueError) as exc:
            print(f"  WebView2 loader not fetched ({exc}); the desktop opens in an Edge window",
                  file=sys.stderr)

    target, exe = paths.qemu_dir(), paths.qemu_exe()
    if is_linux():
        print(f"\n  runtime ready: {exe} -> {exe.resolve()}\n"
              f"  QEMU, the firmware and swtpm come from this PC's packages; winlab's own files "
              f"stay in {paths.ROOT}", file=sys.stderr)
        return exe
    size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    print(
        f"\n  runtime ready: {exe}\n"
        f"  on-disk size:  {size / (1024 ** 3):.2f} GiB\n"
        f"  footprint:     none (no installer, no registry, no service, no admin)",
        file=sys.stderr,
    )
    return exe
