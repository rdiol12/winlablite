"""The browser terminal: xterm.js, fetched at bootstrap, never bundled.

A Linux machine's first serial port (ttyS0, where Ubuntu and Alpine run a
login prompt) is a QEMU socket on 127.0.0.1; the dashboard bridges a
WebSocket to it (wsbridge.py) and xterm.js draws it in the machine's
Terminal window: colours, cursor addressing, scrolling, copy and paste, the
same terminal a real admin gets on a server's serial console with PuTTY.
Nothing reaches the machine but the keystrokes typed there, so the lab
stays as isolated as its screen (no SSH, no network path from this PC).

xterm.js and its fit add-on are MIT. Like noVNC (viewer.py) they are
fetched onto the customer's PC with their licence, from the npm registry's
published tarballs, each pinned by the SHA-256 of the tarball; only the
files the window needs are kept.
"""

from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

from . import paths

VERSION = "5.5.0"
FIT_VERSION = "0.10.0"
REGISTRY = "https://registry.npmjs.org/"
USER_AGENT = "winlab/0.2"
STAMP = "VERSION"

# tarball -> (sha256 of the tarball, {path inside the tarball: path kept})
PACKAGES: dict[str, tuple[str, dict[str, str]]] = {
    f"@xterm/xterm/-/xterm-{VERSION}.tgz": (
        "bd954fa721872170188cc5d7e83e88db3c83c9a18a4e8d24c2783d26491f59d2",
        {"package/lib/xterm.js": "xterm.js", "package/css/xterm.css": "xterm.css",
         "package/LICENSE": "LICENSE-xterm.txt"}),
    f"@xterm/addon-fit/-/addon-fit-{FIT_VERSION}.tgz": (
        "917ac44972453d5eed52edc1e50260c76398ce48cf2290c2e60671102bba0b33",
        {"package/lib/addon-fit.js": "addon-fit.js", "package/LICENSE": "LICENSE-addon-fit.txt"}),
}
FILES = tuple(dest for _, members in PACKAGES.values() for dest in members.values())
STAMP_TEXT = f"{VERSION} {FIT_VERSION}"


class TermError(Exception):
    pass


def term_dir() -> Path:
    return paths.RUNTIME / "xterm"


def ready() -> bool:
    d = term_dir()
    try:
        return ((d / STAMP).read_text(encoding="ascii").strip() == STAMP_TEXT
                and all((d / f).exists() for f in FILES))
    except OSError:
        return False


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise TermError(f"cannot reach {url}: {exc}") from exc


def unpack(data: bytes, digest: str, members: dict[str, str], dest: Path, name: str) -> None:
    """Checks a tarball against its pin and writes the wanted members, by
    name only: nothing else in the archive is read or written."""
    got = hashlib.sha256(data).hexdigest()
    if got != digest:
        raise TermError(f"{name}: checksum mismatch (got {got[:12]}, pinned {digest[:12]})")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member, target in members.items():
            info = tar.getmember(member)
            if not info.isfile():
                raise TermError(f"{name}: {member} is not a file")
            out = dest / target
            tmp = out.with_name(out.name + ".part")
            tmp.write_bytes(tar.extractfile(info).read())
            tmp.replace(out)


def fetch(refresh: bool = False, progress=None, get=_get) -> Path:
    d = term_dir()
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    if ready() and not refresh:
        say(f"xterm.js {VERSION} already fetched")
        return d
    d.mkdir(parents=True, exist_ok=True)
    (d / STAMP).unlink(missing_ok=True)
    for rel, (digest, members) in PACKAGES.items():
        data = get(REGISTRY + rel)
        unpack(data, digest, members, d, rel.rsplit("/", 1)[-1])
        say(f"{rel.rsplit('/', 1)[-1]} ({len(data) // 1024} KiB)")
    (d / STAMP).write_text(STAMP_TEXT + "\n", encoding="ascii")
    say(f"xterm.js {VERSION} ready in {d}")
    return d


def render_status() -> str:
    head = f"terminal: xterm.js {VERSION} (MIT), fetched from the npm registry at bootstrap"
    return head + ("\n  ready in " + str(term_dir()) if ready()
                   else "\n  not fetched: 'winlab bootstrap' or 'winlab viewer fetch' downloads it")
