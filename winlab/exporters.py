"""The Prometheus Windows exporter (windows_exporter, prometheus-community,
MIT), fetched from its GitHub release onto this PC and carried to each
Windows machine on its provisioning volume, where the metrics role installs
it. Nothing is bundled with winlab: the MSI comes from the project's own
release page, verified against the release's sha256sums.txt.

The release is discovered through GitHub's API when it answers (the latest
amd64 MSI); when it does not (rate limit, no API access), the pinned release
below is fetched instead, against the checksum recorded here.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to, _get

REPO = "prometheus-community/windows_exporter"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
PAGE = f"https://github.com/{REPO}/releases"
LICENSE = "MIT"
# The release used when the API cannot be asked.
PINNED_VERSION = "0.31.3"
PINNED_SHA256 = "afd0aaca29f32b75427dfa6e7cb27db17e9b74933818133f974c41808286d3f3"
MSI_NAME = "windows_exporter.msi"      # its name on the provisioning volume
META_NAME = "windows_exporter.json"
MAIN_FILE = MSI_NAME
PORT = 9182
SIZE_TEXT = "about 11 MB"
JOB = "exporter-fetch"
STEP_LABEL = "Fetch the Windows exporter (Prometheus community, GitHub)"


class ExporterError(Exception):
    pass


def exporter_dir() -> Path:
    return paths.RUNTIME / "exporters"


def msi_path() -> Path:
    return exporter_dir() / MSI_NAME


def meta_path() -> Path:
    return exporter_dir() / META_NAME


def meta() -> dict:
    p = meta_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    m = meta()
    p = msi_path()
    return bool(m.get("version")) and p.exists() and p.stat().st_size > 0


def _asset_url(version: str) -> str:
    return f"https://github.com/{REPO}/releases/download/v{version}/windows_exporter-{version}-amd64.msi"


def _sums_url(version: str) -> str:
    return f"https://github.com/{REPO}/releases/download/v{version}/sha256sums.txt"


def parse_sums(text: str, filename: str) -> str:
    """The SHA-256 a sha256sums.txt gives for one file, or ''."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*").rsplit("/", 1)[-1] == filename:
            return parts[0].lower()
    return ""


def discover(get=_get) -> tuple[str, str, str]:
    """(version, msi url, sums url) of the latest release, from the API; the
    pinned release when the API cannot be asked or lists no amd64 MSI."""
    try:
        rel = json.loads(get(API_URL, timeout=30).decode("utf-8"))
        version = str(rel.get("tag_name", "")).lstrip("v")
        msi = next((a["browser_download_url"] for a in rel.get("assets", [])
                    if str(a.get("name", "")).endswith("-amd64.msi")), "")
        sums = next((a["browser_download_url"] for a in rel.get("assets", [])
                     if str(a.get("name", "")) == "sha256sums.txt"), "")
        if version and msi:
            return version, msi, sums
    except (BootstrapError, ValueError, KeyError, TypeError):
        pass
    return PINNED_VERSION, _asset_url(PINNED_VERSION), _sums_url(PINNED_VERSION)


def fetch(progress=None, get=_get, download=_download_to) -> dict:
    """Fetches the exporter MSI (about 11 MB) and records what it is."""
    say = progress or (lambda _m: None)
    version, url, sums_url = discover(get)
    say(f"windows_exporter {version} from {PAGE}")
    sha = ""
    if sums_url:
        try:
            sha = parse_sums(get(sums_url, timeout=60).decode("utf-8", "replace"), url.rsplit("/", 1)[-1])
        except BootstrapError:
            sha = ""
    if not sha and version == PINNED_VERSION:
        sha = PINNED_SHA256
    if not sha:
        raise ExporterError(f"the release lists no checksum for {url.rsplit('/', 1)[-1]}; refusing "
                            f"to install an unverified MSI")
    exporter_dir().mkdir(parents=True, exist_ok=True)
    try:
        download(url, msi_path(), expect_sha=sha, label=url.rsplit("/", 1)[-1])
    except BootstrapError as exc:
        raise ExporterError(str(exc)) from exc
    m = {"name": "windows_exporter", "version": version, "sha256": sha, "source": url,
         "license": LICENSE, "fetched": time.strftime("%Y-%m-%d"), "port": PORT}
    meta_path().write_text(json.dumps(m, indent=1), encoding="utf-8")
    say(f"windows_exporter {version} ready: {msi_path()}")
    return m


def files() -> dict[str, bytes]:
    """What goes on a Windows machine's provisioning volume for the metrics
    role: the MSI under a fixed name and the record of what it is."""
    if not ready():
        return {}
    return {MSI_NAME: msi_path().read_bytes(),
            META_NAME: json.dumps(meta(), indent=1).encode("utf-8")}


def summary() -> dict:
    m = meta()
    return {"id": "windows-exporter", "title": "Prometheus Windows exporter (windows_exporter)",
            "ready": ready(), "version": m.get("version", ""), "fetched": m.get("fetched", ""),
            "license": LICENSE, "page": PAGE, "port": PORT,
            "size_mb": round(msi_path().stat().st_size / 1048576, 1) if msi_path().exists() else 0.0}


def render_status() -> str:
    s = summary()
    state = (f"ready (version {s['version']}, {s['size_mb']} MB, fetched {s['fetched']})" if s["ready"]
             else "not fetched (about 11 MB)")
    return (f"  windows-exporter  {state}\n"
            f"                    {s['title']}, {LICENSE}; installed on Windows machines by the metrics role, "
            f"listening on {PORT}\n"
            + ("" if s["ready"] else "                    then:    winlab exporter fetch\n"))
