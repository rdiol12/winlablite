"""Termshark on the capture probe: Wireshark's packet view in a terminal.

The lab's capture probe (role ``capture``, an Alpine machine with a leg on
every VLAN) captures with tcpdump and tshark. Reading a capture there meant
scrolling tshark's one-line summaries, or carrying the file to a Windows PC
with Wireshark. Termshark (MIT, Graham Clark, termshark.io) is the terminal
user interface admins use on headless boxes: Wireshark's three panes, the
packet list, the dissected tree and the hex bytes, with Wireshark's own
display filters, live or on a saved file. It drives the tshark the probe
already installs from the Alpine packages; it adds nothing to the network.

The student opens it in the probe's Terminal window (xterm.js over the
probe's serial console, winlab/termview.py): ``termshark -i eth0.10`` for
a live look at VLAN 10, or ``termshark -r /var/lib/winlab/captures/x.pcapng``.

Nothing is bundled. The project's own release (a static Linux x86-64
binary, which runs as is on Alpine's musl) is fetched from its GitHub
release onto this PC at preparation, checked against the SHA-256 the
release's checksums.txt publishes, with its licence from the same tag; both
are carried on the Alpine repository volume (apkrepo.build_image) and the
``capture`` role copies them into the probe at boot.
"""

from __future__ import annotations

import json
import tarfile
import time
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to

PRODUCT = "Termshark"
LICENSE = "MIT"
VERSION = "2.4.0"
PAGE = "https://termshark.io/"
RELEASE = f"https://github.com/gcla/termshark/releases/download/v{VERSION}"
TARBALL = f"termshark_{VERSION}_linux_x64.tar.gz"
# From the release's checksums.txt (and checked against the downloaded file
# when this version was pinned).
TARBALL_SHA256 = "a28b2ab534ba8bf2297bbe9846281e62aa0010832b75773369e0d48912acef74"
MEMBER = f"termshark_{VERSION}_linux_x64/termshark"
LICENSE_URL = f"https://raw.githubusercontent.com/gcla/termshark/v{VERSION}/LICENSE"
LICENSE_SHA256 = "e96db14e21841660831e2964551da502438c1d1942cb70ab362792e8b977bbf5"
# On the repository volume: <volume>/termshark/{termshark,LICENSE}; the
# capture role looks for it under Alpine's mount of the volume.
VOLUME_DIR = "termshark"
BINARY = "termshark"
LICENSE_FILE = "LICENSE-termshark.txt"
SIZE_TEXT = "about 6 MB"
JOB = "termshark-fetch"
STEP_LABEL = "Fetch Termshark (its GitHub release)"
ROLES = ("capture",)


class TermsharkError(Exception):
    pass


def store() -> Path:
    return paths.downloads_dir() / "termshark"


def binary_path() -> Path:
    return store() / BINARY


def license_path() -> Path:
    return store() / LICENSE_FILE


def _meta() -> dict:
    try:
        return json.loads((store() / "termshark.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    return (binary_path().is_file() and license_path().is_file()
            and _meta().get("version") == VERSION)


def extract(tarball: Path, dest: Path) -> Path:
    """The one binary out of the release tarball, by name only."""
    try:
        with tarfile.open(tarball, mode="r:gz") as tar:
            info = tar.getmember(MEMBER)
            if not info.isfile():
                raise TermsharkError(f"{TARBALL}: {MEMBER} is not a file")
            data = tar.extractfile(info).read()
    except (KeyError, tarfile.TarError, OSError) as exc:
        raise TermsharkError(f"{TARBALL}: {exc}") from exc
    if not data.startswith(b"\x7fELF"):
        raise TermsharkError(f"{TARBALL}: {MEMBER} is not a Linux program")
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(data)
    tmp.replace(dest)
    return dest


def fetch(progress=None, download=_download_to) -> Path:
    """The pinned release from Termshark's GitHub release onto this PC,
    checked against its SHA-256; the tarball is removed once the binary is
    out of it."""
    say = progress or (lambda _m: None)
    d = store()
    if ready():
        say(f"{PRODUCT} {VERSION} already fetched")
        return binary_path()
    d.mkdir(parents=True, exist_ok=True)
    tgz = d / TARBALL
    say(f"{PRODUCT} {VERSION} from {RELEASE}/{TARBALL}")
    try:
        download(f"{RELEASE}/{TARBALL}", tgz, expect_sha=TARBALL_SHA256, label=TARBALL)
        download(LICENSE_URL, license_path(), expect_sha=LICENSE_SHA256, label="LICENSE")
    except BootstrapError as exc:
        raise TermsharkError(str(exc)) from exc
    extract(tgz, binary_path())
    tgz.unlink(missing_ok=True)
    (d / "termshark.json").write_text(json.dumps({
        "name": PRODUCT, "version": VERSION, "license": LICENSE, "sha256": TARBALL_SHA256,
        "source": f"{RELEASE}/{TARBALL}", "fetched": time.strftime("%Y-%m-%d")}, indent=1), encoding="utf-8")
    say(f"{PRODUCT} {VERSION} ready: {binary_path()}")
    return binary_path()


def volume_files() -> list[tuple[str, Path]]:
    """What the repository volume carries for the capture probe, when it was
    fetched (apkrepo.build_image)."""
    if not ready():
        return []
    return [(f"{VOLUME_DIR}/{BINARY}", binary_path()), (f"{VOLUME_DIR}/LICENSE", license_path())]


def fetch_onto_volume(progress=None) -> Path:
    """Fetch it, then rebuild the repository volume around it."""
    from . import apkrepo
    fetch(progress)
    cache = apkrepo.cached()
    if cache is None:
        raise TermsharkError("the Alpine packages are not fetched yet: prepare the fabric first "
                             "(winlab images prepare fabric), which fetches Termshark too")
    img = apkrepo.build_image(cache)
    (progress or (lambda _m: None))(f"repository volume rebuilt with {PRODUCT}: {img}")
    return img


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """A Setup step when a lab has a capture probe and Termshark is not on
    this PC (a fabric prepared before it was added)."""
    who = [n.id for n in lab.node_list() if set(n.roles or ()) & set(ROLES)]
    if not who or "termshark" in set(have or ()):
        return []
    return [{"id": "termshark", "label": STEP_LABEL, "done": ready(), "blocked": False,
             "hint": f"the packet view in the Terminal of {', '.join(who)}: {PRODUCT} {VERSION} ({LICENSE}), "
                     f"checked against its SHA-256, {SIZE_TEXT} once, carried on the Alpine repository volume",
             "link": PAGE, "job": JOB}]


def summary() -> dict:
    m = _meta()
    return {"id": "termshark", "title": f"{PRODUCT} {VERSION}", "ready": ready(), "version": VERSION,
            "license": LICENSE, "fetched": m.get("fetched", ""), "page": PAGE}


def render_status() -> str:
    head = f"capture probe packet view: {PRODUCT} {VERSION} ({LICENSE}), fetched from its GitHub release"
    return head + (f"\n  ready in {store()}" if ready()
                   else "\n  not fetched: 'winlab images prepare fabric' downloads it")
