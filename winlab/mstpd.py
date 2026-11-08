"""mstpd: real rapid spanning tree (802.1w) on the lab switches' bridges.

The lab router's kernel runs classic 802.1D on the switch bridges
(winlab/stp.py); the kernel does nothing faster. Rapid spanning tree on
Linux is mstpd (GPL-2.0-or-later, github.com/mstpd/mstpd), the daemon real
Linux-based switches use: the kernel hands it a bridge's spanning tree (the
bridge's stp_state becomes 2, "user STP") through the /sbin/bridge-stp
helper it calls when spanning tree is turned on, and mstpd sends and reads
the BPDUs, runs RSTP's proposal and agreement, keeps the port roles (root,
designated, alternate, backup), edge ports and BPDU guard, and sets each
port's state in the kernel. ``mstpctl`` is its command line.

With it, ``spanning-tree mode rapid-pvst`` on a switch is RSTP for real: the
router starts mstpd, names the switch's bridge in /run/winlab-rstp (so
winlab's own small /sbin/bridge-stp says yes for it, and no for a switch
left in pvst, which keeps the kernel's 802.1D), then sets the bridge up with
mstpctl (protocol, priority, each port's cost, priority, edge (PortFast) and
BPDU guard). ``show spanning-tree`` reads what mstpctl reports.

Nothing is bundled. mstpd is not packaged for Alpine (the router's system),
and it publishes source only, so this repository's workflow
(.github/workflows/mstpd.yml) builds the pinned release as static Linux
x86-64 programs in an Alpine container (musl, so they run as they are on the
router) and publishes them as an asset of a release of rdiol12/winlablite,
together with the complete corresponding source, the licence and a NOTICE
(tools/pack_mstpd.py), as the GPL asks. At preparation this module fetches
that asset onto this PC, checked against the SHA-256 pinned here once the
first build is published; until then nothing is fetched and the switches
keep the kernel's 802.1D, saying so. The repository volume carries the
asset to the router beside the Alpine packages (apkrepo.build_image), and
the router unpacks the two programs at boot (router_lines, run from
stp.render).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to

PRODUCT = "mstpd"
LICENSE = "GPL-2.0-or-later"
UPSTREAM = "https://github.com/mstpd/mstpd"
VERSION = "0.2.0"                                     # the release tag, 2026-03-30
COMMIT = "8995e5d11ee89f2251734e34cea711bb5a5bb911"   # what tag 0.2.0 points at
SHORT = COMMIT[:7]
ALPINE = "alpine:3.22"   # the build container: musl, so the programs are fully static
TAG = f"mstpd-{VERSION}-{SHORT}"
ASSET = f"{TAG}.tar.gz"
RELEASE = f"https://github.com/rdiol12/winlablite/releases/download/{TAG}"
# Pinned from the first published build (the workflow prints it); empty
# means not published yet, and nothing is fetched.
ASSET_SHA256 = ""
PROGRAMS = ("mstpd", "mstpctl")
# On the repository volume: <volume>/mstpd/<asset>; the router finds it under
# Alpine's mount of the volume.
VOLUME_DIR = "mstpd"
ROUTER_BIN = "/usr/local/sbin"
MSTPD = f"{ROUTER_BIN}/mstpd"
MSTPCTL = f"{ROUTER_BIN}/mstpctl"
ROUTER_DOC = "/usr/local/share/mstpd"   # LICENSE and NOTICE beside the programs
RSTP_LIST = "/run/winlab-rstp"          # the bridges that run RSTP in mstpd, one a line
HELPER = "/sbin/bridge-stp"             # what the kernel asks when spanning tree goes on


class MstpdError(Exception):
    pass


def published() -> bool:
    return len(ASSET_SHA256) == 64


def store() -> Path:
    return paths.downloads_dir() / "mstpd"


def asset_path() -> Path:
    return store() / ASSET


def _meta() -> dict:
    try:
        return json.loads((store() / "mstpd.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    """Fetched onto this PC and the build pinned here: the router will run
    rapid-pvst in mstpd."""
    return published() and asset_path().is_file() and _meta().get("sha256") == ASSET_SHA256


def fetch(progress=None, download=_download_to) -> Path | None:
    """The pinned build from winlab's release onto this PC, verified against
    its SHA-256; None (and nothing fetched) while no build is pinned."""
    say = progress or (lambda _m: None)
    if not published():
        say(f"{PRODUCT}: no build published yet (Actions > mstpd > Run workflow), skipped; "
            f"rapid-pvst stays the kernel's 802.1D with short timers")
        return None
    if ready():
        say(f"{PRODUCT} {VERSION} already fetched")
        return asset_path()
    dest = asset_path()
    say(f"{PRODUCT} {VERSION} ({SHORT}) from {RELEASE}/{ASSET}")
    try:
        download(f"{RELEASE}/{ASSET}", dest, expect_sha=ASSET_SHA256, label=ASSET)
    except BootstrapError as exc:
        raise MstpdError(str(exc)) from exc
    for f in store().iterdir():
        if f.name not in (ASSET, "mstpd.json"):
            f.unlink()
    (store() / "mstpd.json").write_text(json.dumps({
        "name": PRODUCT, "version": VERSION, "commit": COMMIT, "license": LICENSE, "sha256": ASSET_SHA256,
        "source": UPSTREAM, "asset": f"{RELEASE}/{ASSET}", "fetched": time.strftime("%Y-%m-%d")}, indent=1),
        encoding="utf-8")
    say(f"{PRODUCT} ready: {dest}")
    return dest


def volume_files() -> list[tuple[str, Path]]:
    """What the repository volume carries for the router: the pack, when it
    was fetched (apkrepo.build_image)."""
    return [(f"{VOLUME_DIR}/{ASSET}", asset_path())] if ready() else []


# The kernel calls this when spanning tree goes on (start) or off (stop) on a
# bridge; 0 on start hands the bridge to mstpd, anything else keeps the
# kernel's own 802.1D. It must not touch the bridge itself (the kernel holds
# its lock): winlab's start script adds the bridge to mstpd afterwards.
HELPER_SCRIPT = f"""#!/bin/sh
# winlab (winlab/stp.py, winlab/mstpd.py): the switch bridges named in {RSTP_LIST}
# run rapid spanning tree in mstpd; every other bridge keeps the kernel's 802.1D.
case "$2" in
  start) grep -qx "$1" {RSTP_LIST} 2>/dev/null && pidof mstpd >/dev/null 2>&1 && exit 0; exit 1 ;;
  stop) exit 0 ;;
esac
exit 1
"""


def router_lines() -> list[str]:
    """The router's part (stp.render): the two programs from the pack on the
    repository volume into ROUTER_BIN, once per build, and the bridge-stp
    helper. Sets wl_mstpd=1 when mstpd can run; nothing else when the pack
    is not there (not published or not fetched)."""
    find = (f"for f in /media/*/{VOLUME_DIR}/mstpd-*.tar.gz; do [ -f \"$f\" ] && echo \"$f\"; done "
            "| sort | tail -n 1")
    tmp = "/tmp/winlab-mstpd"
    return [
        f"wl_mstpd=; wl_ms=$({find})",
        'if [ -z "$wl_ms" ] && d=$(blkid -L WLAPK 2>/dev/null) && [ -n "$d" ]; then '
        'mkdir -p /media/wlapk; mountpoint -q /media/wlapk || mount -o ro "$d" /media/wlapk 2>/dev/null; '
        f"wl_ms=$({find}); fi",
        'if [ -n "$wl_ms" ] && [ "$(cat ' + ROUTER_DOC + '/.version 2>/dev/null)" != "$(basename "$wl_ms" .tar.gz)" ]; then '
        f'rm -rf {tmp}; mkdir -p {tmp} {ROUTER_BIN} {ROUTER_DOC} && tar -xzf "$wl_ms" -C {tmp} '
        f"&& cp {tmp}/mstpd/bin/mstpd {tmp}/mstpd/bin/mstpctl {ROUTER_BIN}/ && chmod 755 {MSTPD} {MSTPCTL} "
        f"&& cp {tmp}/mstpd/LICENSE {tmp}/mstpd/NOTICE {ROUTER_DOC}/ "
        f'&& basename "$wl_ms" .tar.gz > {ROUTER_DOC}/.version; rm -rf {tmp}; fi',
        f"if [ -x {MSTPD} ] && [ -x {MSTPCTL} ]; then wl_mstpd=1; "
        f"cat > {HELPER} <<'WINLAB_BRIDGE_STP'",
        HELPER_SCRIPT.rstrip("\n"),
        "WINLAB_BRIDGE_STP",
        f"chmod 755 {HELPER}; fi",
    ]


def summary() -> dict:
    m = _meta()
    return {"id": "mstpd", "title": f"{PRODUCT} {VERSION}", "ready": ready(), "published": published(),
            "version": VERSION, "commit": COMMIT, "license": LICENSE, "fetched": m.get("fetched", ""),
            "asset": f"{RELEASE}/{ASSET}", "source": UPSTREAM}


def render_status() -> str:
    head = f"rapid spanning tree on the switches: {PRODUCT} {VERSION} ({LICENSE})"
    if not published():
        return head + "\n  not built yet: run the mstpd workflow, then pin its SHA-256 in winlab/mstpd.py"
    return head + (f"\n  ready in {store()}" if ready() else "\n  not fetched: 'winlab images prepare fabric'")
