"""Windows Admin Center (Microsoft), fetched from Microsoft's download link
onto this PC and carried to the machine with the wac role on its
provisioning volume, where the role installs it. Nothing is bundled with
winlab: Microsoft's licence lets a Windows Server licensee use it but not
pass it on, so every customer's PC downloads its own copy.

Microsoft publishes no checksum file for the installer, so the fetch keeps
the SHA-256 of what it got (shown in `winlab wac status`), refuses anything
that is not a Windows program, and the role checks Microsoft's Authenticode
signature inside the machine before it runs the installer.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import paths
from .bootstrap import USER_AGENT, BootstrapError, _download_to, _sha256

URL = "https://aka.ms/WACDownload"
PAGE = "https://learn.microsoft.com/windows-server/manage/windows-admin-center/overview"
LICENSE = "Microsoft software licence terms (free with Windows Server; not redistributable)"
EXE_NAME = "WindowsAdminCenter.exe"     # its name on the provisioning volume
META_NAME = "WindowsAdminCenter.json"
MAIN_FILE = EXE_NAME
PORT = 443
SIZE_TEXT = "about 200 MB"
JOB = "wac-fetch"
STEP_LABEL = "Fetch Windows Admin Center (Microsoft)"
# Anything smaller is an error page, not the installer.
MIN_BYTES = 20 * 1024 * 1024


class WacError(Exception):
    pass


def wac_dir() -> Path:
    return paths.RUNTIME / "wac"


def exe_path() -> Path:
    return wac_dir() / EXE_NAME


def meta_path() -> Path:
    return wac_dir() / META_NAME


def meta() -> dict:
    p = meta_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    p = exe_path()
    return bool(meta().get("sha256")) and p.exists() and p.stat().st_size >= MIN_BYTES


def _resolve(url: str) -> str:
    """Where Microsoft's short link points today (the versioned file name)."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.geturl()
    except (urllib.error.URLError, OSError) as exc:
        raise BootstrapError(f"cannot reach {url}: {exc}") from exc


def version_from(url: str) -> str:
    """'2410' from .../WindowsAdminCenter2410.exe; '' when the name has none."""
    name = url.rsplit("/", 1)[-1]
    m = re.search(r"(\d{4}(?:\.\d+)*)", name)
    return m.group(1) if m else ""


def check_program(path: Path) -> None:
    """A Windows program (MZ header) of a believable size, or WacError."""
    size = path.stat().st_size if path.exists() else 0
    with path.open("rb") as fh:
        head = fh.read(2)
    if head != b"MZ" or size < MIN_BYTES:
        raise WacError(f"what {URL} returned is not the Windows Admin Center installer "
                       f"({size >> 10} KB); try again later or download it from {PAGE}")


def fetch(progress=None, resolve=_resolve, download=_download_to) -> dict:
    """Fetches the installer once and records what it is."""
    say = progress or (lambda _m: None)
    try:
        real = resolve(URL)
    except BootstrapError:
        real = URL
    version = version_from(real)
    say(f"Windows Admin Center {version or '(latest)'} from {real}")
    wac_dir().mkdir(parents=True, exist_ok=True)
    try:
        download(real, exe_path(), label=EXE_NAME)
    except BootstrapError as exc:
        raise WacError(str(exc)) from exc
    try:
        check_program(exe_path())
    except WacError:
        exe_path().unlink(missing_ok=True)
        raise
    m = {"name": "Windows Admin Center", "version": version, "sha256": _sha256(exe_path()),
         "source": real, "license": LICENSE, "fetched": time.strftime("%Y-%m-%d"), "port": PORT}
    meta_path().write_text(json.dumps(m, indent=1), encoding="utf-8")
    say(f"Windows Admin Center ready: {exe_path()} (sha256 {m['sha256'][:16]}…, its Microsoft "
        f"signature is checked inside the machine before it runs)")
    return m


def files() -> dict[str, bytes]:
    """What goes on the provisioning volume for the wac role."""
    if not ready():
        return {}
    return {EXE_NAME: exe_path().read_bytes(),
            META_NAME: json.dumps(meta(), indent=1).encode("utf-8")}


def summary() -> dict:
    m = meta()
    return {"id": "windows-admin-center", "title": "Windows Admin Center (Microsoft)",
            "ready": ready(), "version": m.get("version", ""), "fetched": m.get("fetched", ""),
            "sha256": m.get("sha256", ""), "license": LICENSE, "page": PAGE, "port": PORT,
            "size_mb": round(exe_path().stat().st_size / 1048576, 1) if exe_path().exists() else 0.0}


def render_status() -> str:
    s = summary()
    state = (f"ready (version {s['version'] or 'unknown'}, {s['size_mb']} MB, fetched {s['fetched']})"
             if s["ready"] else f"not fetched ({SIZE_TEXT})")
    return (f"  windows-admin-center  {state}\n"
            f"                        {LICENSE}; installed by the wac role, https on port {PORT}\n"
            + (f"                        sha256 {s['sha256']}\n" if s["ready"] else
               "                        then:    winlab wac fetch\n"))
