"""OpenBMC's web UI for the servers' management processors.

A server's BMC (winlab/power.py, content/agent/bmc.sh) serves OpenBMC's own
web pages, webui-vue (Apache-2.0, github.com/openbmc/webui-vue): the Vue app
that real OpenBMC firmware serves from bmcweb. The BMC script on the router
plays bmcweb: it serves the app's files and answers the Redfish API the
pages call (sign-in, the system and its power actions, the event log, the
BMC's network port, the account).

Nothing is bundled. The project publishes webui-vue as source only, so it is
built from upstream source at a pinned commit by this repository's workflow
(.github/workflows/openbmc-webui.yml: npm ci, npm run build, then
tools/pack_openbmc_webui.py) and published as an asset of a release of
rdiol12/winlablite, with webui-vue's LICENSE, a NOTICE and the licences of the npm
packages built into it. At preparation (``winlab images prepare fabric``)
this module fetches that asset onto this PC, checked against the SHA-256
pinned here; the repository volume carries it to the router beside the
Alpine packages (apkrepo.build_image), and the router unpacks it for its
BMCs (power.render). The pack is reproducible, so the digest pinned here is
the one any build of that commit gives.

Without it (not fetched, or the fetch failed) the BMCs keep winlab's own
pages, and the server's Management box says so.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to

PRODUCT = "OpenBMC web UI (webui-vue)"
LICENSE = "Apache-2.0"
UPSTREAM = "https://github.com/openbmc/webui-vue"
COMMIT = "50e92abc421665c1d7aac2d05a7dc38d6c86ade3"  # 2026-10-19, "Fix the missing status icon in the sensors table"
SHORT = COMMIT[:7]
TAG = f"openbmc-webui-{SHORT}"
ASSET = f"{TAG}.tar.gz"
RELEASE = f"https://github.com/rdiol12/winlablite/releases/download/{TAG}"
# The reproducible pack of that commit's build (tools/pack_openbmc_webui.py,
# node 22.22.0, npm ci): computed from two clean local builds that gave the
# same bytes. The workflow refuses to publish anything else.
ASSET_SHA256 = ""
ASSET_SIZE = 595867
NODE_VERSION = "22.22.0"
# On the repository volume: <volume>/openbmc-webui/<asset>; the router finds it
# under Alpine's mount of the volume, and unpacks it next to the BMCs' folders.
VOLUME_DIR = "openbmc-webui"
ROUTER_DIR = "/var/lib/winlab-bmc/webui"


class OpenBmcUiError(Exception):
    pass


def store() -> Path:
    return paths.downloads_dir() / "openbmc-webui"


def asset_path() -> Path:
    return store() / ASSET


def ready() -> bool:
    p = asset_path()
    return p.is_file() and p.stat().st_size == ASSET_SIZE


def fetch(progress=None, download=_download_to) -> Path:
    """The pinned build from winlab's release onto this PC, verified against
    its SHA-256; files of other builds are removed."""
    say = progress or (lambda _m: None)
    dest = asset_path()
    say(f"{PRODUCT} {SHORT} from {RELEASE}/{ASSET}")
    try:
        download(f"{RELEASE}/{ASSET}", dest, expect_sha=ASSET_SHA256, label=ASSET)
    except BootstrapError as exc:
        raise OpenBmcUiError(str(exc)) from exc
    for f in store().iterdir():
        if f.name not in (ASSET, "openbmc-webui.json"):
            f.unlink()
    (store() / "openbmc-webui.json").write_text(json.dumps({
        "name": PRODUCT, "commit": COMMIT, "license": LICENSE, "sha256": ASSET_SHA256,
        "source": UPSTREAM, "asset": f"{RELEASE}/{ASSET}", "fetched": time.strftime("%Y-%m-%d")}, indent=1),
        encoding="utf-8")
    say(f"{PRODUCT} ready: {dest}")
    return dest


def volume_files() -> list[tuple[str, Path]]:
    """What the repository volume carries for the BMCs: the pack, when it
    was fetched (apkrepo.build_image)."""
    return [(f"{VOLUME_DIR}/{ASSET}", asset_path())] if ready() else []


def router_lines() -> list[str]:
    """The router's part (power.render): unpack the pack from the repository
    volume for the BMCs, once per build; nothing when it is not there."""
    find = (f"for f in /media/*/{VOLUME_DIR}/openbmc-webui-*.tar.gz; do [ -f \"$f\" ] && echo \"$f\"; done "
            "| sort | tail -n 1")
    new = f"{ROUTER_DIR}.new"
    return [
        f"wl_ui=$({find})",
        'if [ -z "$wl_ui" ] && d=$(blkid -L WLAPK 2>/dev/null) && [ -n "$d" ]; then '
        'mkdir -p /media/wlapk; mountpoint -q /media/wlapk || mount -o ro "$d" /media/wlapk 2>/dev/null; '
        f"wl_ui=$({find}); fi",
        'if [ -n "$wl_ui" ] && [ "$(cat ' + ROUTER_DIR + '/.version 2>/dev/null)" != "$(basename "$wl_ui" .tar.gz)" ]; then '
        f'rm -rf {ROUTER_DIR} {new}; mkdir -p {new} && tar -xzf "$wl_ui" -C {new} && mv {new}/webui {ROUTER_DIR} '
        f'&& basename "$wl_ui" .tar.gz > {ROUTER_DIR}/.version; rm -rf {new}; fi',
    ]


def summary() -> dict:
    m = {}
    try:
        m = json.loads((store() / "openbmc-webui.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return {"name": PRODUCT, "commit": COMMIT, "license": LICENSE, "ready": ready(),
            "fetched": m.get("fetched", ""), "asset": f"{RELEASE}/{ASSET}", "store": str(store())}
