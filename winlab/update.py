"""Updates: is a newer winlab published, and installing it.

The feed is the vendor site: GET <site>/api/updates/app/latest?current=X
returns a manifest signed with the same Ed25519 vendor key as licence tokens
(signature over canonical JSON of everything but "sig"). Nothing is trusted
until that signature checks. A newer version is offered; one whose
min_version is above this version is marked required. Installing asks the
site for a ten-minute download link with the licence key and this PC's
fingerprint, downloads into var/updates/, checks size and SHA-256 against the
signed manifest, and on Windows stops the running labs and starts the Inno
Setup installer silently; the installer starts winlab again when it is done.

Checks happen when the user asks (Help > About, `winlab update`) or, with
"Check for updates automatically" on (the default for a licensed copy), once
a day when the desktop starts: never while unlicensed and never while a
timed activity (a lab exam) is running. A check sends only the version.

A vendor test setup may point [update] url in winlab.local.toml elsewhere;
with the site URL configured ([site] url, winlab/licensing/client.py) every
feed must be signed. Only a source checkout with the site turned off falls
back to the unsigned GitHub releases API, which can tell about a release but
never installs one.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import __version__, paths

GITHUB_URL = "https://api.github.com/repos/rdiol12/winlab/releases/latest"
DEFAULT_URL = GITHUB_URL   # the dev fallback; kept under its old name
PRODUCT = "app"
USER_AGENT = f"winlab/{__version__}"
INSTALLER_ARGS = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/RELAUNCH=1"]
MAX_DOWNLOAD = 2 * 1024 ** 3
DAY = 86400
SETTINGS = paths.VAR / "update.json"


class UpdateError(Exception):
    pass


def parse_version(s: str) -> tuple[int, ...]:
    m = re.search(r"(\d+(?:\.\d+)*)", s or "")
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def is_newer(latest: str, current: str = __version__) -> bool:
    a, b = parse_version(latest), parse_version(current)
    return bool(a) and a > b


def _local_cfg() -> dict:
    cfg = paths.ROOT / "winlab.local.toml"
    if cfg.exists():
        import tomllib
        try:
            with cfg.open("rb") as fh:
                return tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError):
            pass
    return {}


def _site() -> str:
    from .licensing import client
    return client.site_url()


def feed_url() -> str:
    url = (_local_cfg().get("update") or {}).get("url")
    if url:
        return str(url)
    site = _site()
    return f"{site}/api/updates/{PRODUCT}/latest" if site else GITHUB_URL


def signed_required() -> bool:
    """A signed manifest is required whenever the site is configured, and
    always in the shipped exe."""
    return bool(_site()) or paths.FROZEN


def verify_manifest(m: dict) -> bool:
    """The manifest's Ed25519 signature against the vendor key, the same
    check as a licence token."""
    from .licensing import client
    return isinstance(m, dict) and client._verify_token(m)


def _with_current(url: str) -> str:
    if "api.github.com" in url:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}current={urllib.parse.quote(__version__)}"


def check(url: str = "", timeout: int = 15) -> dict:
    """{'current', 'latest', 'newer', 'required', 'url', 'notes', 'signed',
    'installable', 'error', 'manifest'}; never raises."""
    url = url or feed_url()
    out = {"current": __version__, "latest": "", "newer": False, "required": False, "url": "",
           "notes": "", "signed": False, "installable": False, "error": "", "manifest": {}}
    req = urllib.request.Request(_with_current(url), headers={"User-Agent": USER_AGENT,
                                                              "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(1024 * 1024).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        out["error"] = "no release published yet" if exc.code == 404 else f"HTTP {exc.code}"
        return out
    except (urllib.error.URLError, OSError, ValueError) as exc:
        out["error"] = f"cannot reach the update feed: {exc}"
        return out
    if not isinstance(data, dict):
        out["error"] = "the update feed sent something that is not a release"
        return out
    signed = bool(data.get("sig")) and verify_manifest(data)
    if data.get("sig") and not signed:
        out["error"] = "the update feed's signature does not check; nothing from it is trusted"
        return out
    if not signed and signed_required():
        out["error"] = "the update feed is not signed; nothing from it is trusted"
        return out
    tag = str(data.get("version") or data.get("tag_name") or data.get("name") or "")
    out["latest"] = tag.lstrip("vV")
    out["url"] = str(data.get("html_url") or "")
    out["notes"] = str(data.get("notes") or "")[:4000]
    out["signed"] = signed
    out["newer"] = is_newer(tag)
    mv = str(data.get("min_version") or "")
    out["required"] = bool(mv) and is_newer(mv)
    out["installable"] = bool(signed and out["newer"] and data.get("sha256") and data.get("size"))
    out["manifest"] = data if signed else {}
    return out


def render(result: dict) -> str:
    if result["error"]:
        return f"winlab {result['current']}: update check failed, {result['error']}"
    if result["newer"]:
        req = " (required: this version is no longer supported)" if result.get("required") else ""
        return (f"winlab {result['current']}: version {result['latest']} is available{req}"
                + (f"\n  {result['url']}" if result["url"] else "")
                + ("\n  install it with 'winlab update --install'" if result.get("installable") else ""))
    return f"winlab {result['current']} is the latest release"


# ------------------------------------------------------------------ download and install

def updates_dir() -> Path:
    return paths.VAR / "updates"


def _post_json(url: str, body: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(64 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        try:
            detail = json.loads(detail).get("error", detail)
        except (ValueError, AttributeError):
            pass
        raise UpdateError(f"the site refused the download: {detail}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UpdateError(f"cannot reach the site: {exc}") from exc


def _same_scheme_ok(url: str) -> bool:
    """Download links are https; plain http only when the site itself is
    (a local test server)."""
    site = _site() or "https://"
    scheme = urllib.parse.urlsplit(url).scheme
    return scheme == "https" or (scheme == "http" and site.startswith("http://"))


def download(manifest: dict, key: str = "", fingerprint: str = "", progress=None,
             timeout: int = 30) -> Path:
    """The installer the signed manifest describes, in var/updates/, its size
    and SHA-256 checked. Raises UpdateError on anything amiss and leaves no
    partial file behind."""
    if not verify_manifest(manifest):
        raise UpdateError("the release manifest is not signed by the vendor")
    from .licensing import client
    if not key or not fingerprint:
        st = client.status()
        if not st.ok:
            raise UpdateError("updates download with an activated license")
        tok = client._load_token() or {}
        key, fingerprint = str(tok.get("key", "")), client.fingerprint()
    version = str(manifest.get("version", ""))
    want_sha, want_size = str(manifest.get("sha256", "")).lower(), int(manifest.get("size") or 0)
    if not re.fullmatch(r"[0-9a-f]{64}", want_sha) or want_size <= 0 or want_size > MAX_DOWNLOAD:
        raise UpdateError("the release manifest has no usable checksum or size")
    if not re.fullmatch(r"[0-9A-Za-z.+-]{1,40}", version):
        raise UpdateError("the release manifest has no usable version")
    endpoint = str(manifest.get("download") or f"{_site()}/api/updates/{PRODUCT}/download")
    link = _post_json(endpoint, {"key": key, "fingerprint": fingerprint}, timeout)
    if str(link.get("version", version)) != version or str(link.get("sha256", want_sha)).lower() != want_sha:
        raise UpdateError("the site offered a different file than the signed manifest names; try again later")
    url = str(link.get("url", ""))
    if not url or not _same_scheme_ok(url):
        raise UpdateError("the site sent no usable download link")
    d = updates_dir()
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"winlab-{version}-setup.exe"
    part = dest.with_name(dest.name + ".part")
    h, got = hashlib.sha256(), 0
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, part.open("wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                got += len(chunk)
                if got > want_size:
                    raise UpdateError("the download is larger than the signed manifest says")
                h.update(chunk)
                fh.write(chunk)
                if progress:
                    progress(got, want_size)
    except (urllib.error.URLError, OSError) as exc:
        part.unlink(missing_ok=True)
        raise UpdateError(f"the download failed: {exc}") from exc
    except UpdateError:
        part.unlink(missing_ok=True)
        raise
    if got != want_size:
        part.unlink(missing_ok=True)
        raise UpdateError(f"the download is {got} bytes, the signed manifest says {want_size}")
    if h.hexdigest() != want_sha:
        part.unlink(missing_ok=True)
        raise UpdateError("the download's SHA-256 does not match the signed manifest; it was not kept")
    part.replace(dest)
    return dest


def stop_labs() -> list[str]:
    """Stop every running lab (their disks keep their state) before the
    installer replaces winlab."""
    from . import schema, state
    from .orchestrator import Orchestrator
    stopped = []
    for name in state.known_labs():
        try:
            lab = schema.load(name)
        except schema.LabError:
            continue
        if Orchestrator(lab, accel="").down():
            stopped.append(name)
    return stopped


def install(installer: Path, launch=None) -> list[str]:
    """Windows only: stop the labs and start the installer silently. The
    caller quits winlab right after; the installer starts it again
    (/RELAUNCH=1, see packaging/winlab.iss). Returns the argv started."""
    if os.name != "nt" and launch is None:
        raise UpdateError("installing an update runs on Windows; download the installer from the site")
    installer = Path(installer)
    if not installer.is_file():
        raise UpdateError(f"{installer} is not there")
    stop_labs()
    argv = [str(installer), *INSTALLER_ARGS]
    if launch is None:
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen(argv, close_fds=True, creationflags=flags)
    else:
        launch(argv)
    return argv


# ------------------------------------------------------------------ the daily check

def settings() -> dict:
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    try:
        SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS.write_text(json.dumps(data, indent=1), encoding="utf-8")
    except OSError:
        pass


def _licensed() -> bool:
    from .licensing import client
    return client.status().ok


def auto_enabled(data: dict | None = None) -> bool:
    """The setting; unset means on for a licensed copy, off otherwise."""
    data = settings() if data is None else data
    if "auto" in data:
        return bool(data["auto"]) and _licensed()
    return _licensed()


def set_auto(on: bool) -> None:
    data = settings()
    data["auto"] = bool(on)
    _save(data)


def exam_running(now: float | None = None) -> bool:
    """A timed activity (a lab exam) still open: started in the last day,
    neither handed in nor over."""
    now = time.time() if now is None else now
    d = paths.VAR / "activities"
    for f in d.glob("*.json") if d.is_dir() else []:
        try:
            st = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if (isinstance(st, dict) and st.get("final") is None and not st.get("handed_in")
                and now - float(st.get("started") or 0) < DAY and f.with_suffix(".wlact").exists()):
            return True
    return False


def auto_check_due(now: float | None = None) -> bool:
    now = time.time() if now is None else now
    data = settings()
    return (auto_enabled(data) and now - float(data.get("last") or 0) >= DAY
            and not exam_running())


def remember(result: dict, now: float | None = None) -> None:
    data = settings()
    data["last"] = time.time() if now is None else now
    data["result"] = {k: v for k, v in result.items() if k != "manifest"}
    data["manifest"] = result.get("manifest") or {}
    _save(data)


def auto_check(now: float | None = None, url: str = "") -> dict | None:
    """The once-a-day check at start-up; None when it was not due."""
    if not auto_check_due(now):
        return None
    result = check(url)
    remember(result, now)
    return result


def view() -> dict:
    """What Help > About shows: the setting, the last check, and whether an
    update is waiting."""
    data = settings()
    last = data.get("result") or {}
    return {"current": __version__, "auto": auto_enabled(data), "auto_set": "auto" in data,
            "licensed": _licensed(), "last": float(data.get("last") or 0), "result": last,
            "exam_running": exam_running(), "windows": os.name == "nt",
            "feed": feed_url(), "signed_required": signed_required()}
