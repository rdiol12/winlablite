"""The browser console viewer: noVNC, fetched at bootstrap, never bundled.

QEMU exposes every lab machine's screen on a loopback VNC port; the dashboard
bridges a WebSocket to it (wsbridge.py) and noVNC draws the screen in the
browser tab, keyboard and mouse included. noVNC is MPL-2.0 (with BSD and zlib
pieces for pako and the decoders), so winlab could ship it, but the one rule
in LICENSING.md is simpler to keep than to argue about: third-party code is
fetched onto the customer's machine, with its license texts, and winlab's own
code stays its own.

Pinned by tag and by the SHA-256 of every file, so an upgrade is a deliberate
edit here and a tampered or truncated download never reaches the browser.
The files are the ES-module sources (core/ and vendor/pako/) of the tagged
release; nothing is transpiled or bundled.
"""

from __future__ import annotations

import hashlib
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import paths

VERSION = "1.6.0"
BASE = f"https://raw.githubusercontent.com/novnc/noVNC/v{VERSION}/"
USER_AGENT = "winlab/0.2"
STAMP = "VERSION"

# path inside the noVNC tree -> sha256 of the file at tag v1.6.0
FILES: dict[str, str] = {
    "AUTHORS": "16ee0ef356d5107a4bc039f91abc99a341dc62b9aa8dd47547a2baed38507509",
    "LICENSE.txt": "3ccd2242d7f5b6c5ae831a486f63cce1f18d8cd11c511f6a7a7251673763b2d1",
    "core/base64.js": "76d6b7ec73aed8cbc72b49b8b865bcb334acc59a6b0e96b19bc39c9e8e053ae3",
    "core/crypto/aes.js": "00b9a69185f913b882270c4cc7a076b4dd3a083981edb91c1e55db22f8ffcef3",
    "core/crypto/bigint.js": "e7880d27af8bf439579f6fc40d7b81fd379a9babb1d13c83999effd8c64823ab",
    "core/crypto/crypto.js": "e6006697ce1d195c951ef1e986172d17174e533909df19e07be583ac75dd344b",
    "core/crypto/des.js": "91d8c8ed596d2beda7da9dd68c9ae1d325c673822e3ccfc8a4091e121c99a316",
    "core/crypto/dh.js": "9102454282ba646ee4a4ce34c5db5d2a9979179f9d4606737fc6bb7a669e5ebe",
    "core/crypto/md5.js": "364c0f0d44d3f8fd608c18a0e1253e5a77e9b8e4c48e3c6503a0f45c9bb2ff8d",
    "core/crypto/rsa.js": "83875db9e5d978ea0eb2a1e2af8afbb7dedfb0f18eca2bab75c2756285037476",
    "core/decoders/copyrect.js": "da3b571e10984438ea49559738e11034b5d0c85154a68eac1a6bf9ef10e5aa02",
    "core/decoders/h264.js": "96d47901c5e26dc02256b152aa642490d936bbcc395f59ffd580356118edff84",
    "core/decoders/hextile.js": "63eb86247bea83119af75f3d145a4515a2411ff28a72492d2d7b925268d50163",
    "core/decoders/jpeg.js": "0644c6a81007bdeddcf08e2ac0015f9d683a342da167f6f3dd0598956e16c5bf",
    "core/decoders/raw.js": "bc7d4517213dc1df8626e8198eadf32b2c1946f75228b31387d3916963af0727",
    "core/decoders/rre.js": "b3380dbc75310769ef24e956e1fa1f13d8217f8b1d7d6f5c9d08db9a336a4c0d",
    "core/decoders/tight.js": "a7f01df99922be812ea21c5e46597b76379a5d8267f99ec8bea9a202bec34130",
    "core/decoders/tightpng.js": "38bd2fd200f5c8e9b0905eca2389fb8e6ad2151de886e4fa9a9c59cc1c7696f0",
    "core/decoders/zlib.js": "1d1c05cdca4840ff46082103ab35aa7696b41504bec91ebd74fae9e0e5f61380",
    "core/decoders/zrle.js": "6853c115f97a1d4de39ca71ab8b519a05916bb8c173aa8112ce4881cbb612cbd",
    "core/deflator.js": "ceb6763eb3fcc53f34d08534a8d1df9b63af3a95c58f8d96d238ef5ce639ad1f",
    "core/display.js": "257694ea2ad5634fcf0528cdb91eb5a76b3e4b3820ec55c7fa691d89fe4fa277",
    "core/encodings.js": "4975904fe1da6dc22b53ecb8462ec7c9a43e99db72dba4aab9f625c4177e355d",
    "core/inflator.js": "b1955cbd1608619911b8dfd451fae07f38c5767098f6f47e4a2a1682c11feb65",
    "core/input/domkeytable.js": "5eb985e1a412d1be6b606ba0d7e912fc0842d873d252bd7ec8a363670dfc800c",
    "core/input/fixedkeys.js": "6bb21b0a2d5f5d7ad73e75b80ddc1d844ac770c4426b312d5740f2443455f0c0",
    "core/input/gesturehandler.js": "c04b67fdae6ac061c7d51cb5ee8ca296ee9c7c80aa246cee5751e74eefe61758",
    "core/input/keyboard.js": "46f82adef772b726ae3db144fb9c12b3d03374b7c803b8a5106e422a10ddcdba",
    "core/input/keysym.js": "4ddf0e21f07328358974d91aa2d7f839ba2116688b28e43d3f6f4e2eae8c45cf",
    "core/input/keysymdef.js": "76f338d45fb73b7decb7d8b4ef6e95edf7ce9583722c5220642a9be85fc2cc89",
    "core/input/util.js": "2e156ea656404afcb6cc54dd85cbe5dd2dd0ba209ae9a6fb1b78ec5db17d01ce",
    "core/input/vkeys.js": "9a1ce4393e1aa4ace5dcdcf7e032f4a1c03a9cb964b4e0e7b7fcffd3a982eb84",
    "core/input/xtscancodes.js": "f0fc982627e1c02feaac1bd50d7fdd3bcbb05f0062b910d8002f47d1b08967a6",
    "core/ra2.js": "4aeffb60af9c163365170e2af392acb6f0a7c21a0cb6827f85dd776d33277bee",
    "core/rfb.js": "563a8c8469dfb55d1deee05262a311637d0e6fe8f65ae34c8222ee22e34e8a93",
    "core/util/browser.js": "e45d2a95c9b4388042e52e19f280edd791cc2be9749d93f851afb7d0a2d055bc",
    "core/util/cursor.js": "adabe605d73f38e5f29abd302489d4b9e98a9e495823a06a2edbe7f6744856fa",
    "core/util/element.js": "13845321fc5abccc1de25594082d8db15405af56c5f4fc32b3bdd0878bd891e3",
    "core/util/events.js": "ec7f4da0407ea67f5d6f5ce53bd9b3342155feb9407707de3992c5261e460ead",
    "core/util/eventtarget.js": "9481965aa6cee36ae2decdccc6ca5203c9371a8afc33346ad4170e471766e0da",
    "core/util/int.js": "b1c4b7dec2e7767322b3464f3c186b13138cdf341c621db44ddd06ce78180c01",
    "core/util/logging.js": "c3a49715c9f908d5bb385de5787e99b824faf34d26036d993eea4740bac9d482",
    "core/util/strings.js": "77d0604c7bf9e95de780f8cb9764d918ae24c86811a0a1c5b08cd30e50ad2a3a",
    "core/websock.js": "6abe99c285e775ee43dfdbfb73c0a24052e633491232ee90446f20ffea743f16",
    "docs/LICENSE.BSD-2-Clause": "f4371b28457e3e9f2db1fc972eb5ba16353dc5f8d7f42b2d5c3c2e576e40dd05",
    "docs/LICENSE.BSD-3-Clause": "c08e5ef2e6d004c97f92d45eee4f3a0257b6c957a6c68c7b2053d013ec3725c2",
    "docs/LICENSE.MPL-2.0": "fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85",
    "docs/LICENSE.OFL-1.1": "e564f06d018e7b95bc3594c96a17f1d41865af4038c375e7aa974dd69df38602",
    "vendor/pako/lib/utils/common.js": "0749bc4661ed186714b90e7f2321c9625a8ce7c680563bfe3ac6df7aa332bf28",
    "vendor/pako/lib/zlib/adler32.js": "7412dd3ecc015888b99292f45e4d4ba69abc77f208508c9a1c93e8dfe54ba6cd",
    "vendor/pako/lib/zlib/constants.js": "9d2c0dd36349e6eec9d41a37f965b2ff7e7374fbf00fb139e3116d428b551898",
    "vendor/pako/lib/zlib/crc32.js": "897fa9eabd2bb239ec632326dbff85bc72cc81d4da80265cde59520db339f405",
    "vendor/pako/lib/zlib/deflate.js": "d2a498ad04bb5d1f67ba01696c31a2e88e8b88e4fc6c36c635294d1c445b22c1",
    "vendor/pako/lib/zlib/gzheader.js": "9f9b2da72593769fcc97d397ceb771bb11d5b96f202759e2ed014c2be24d40d7",
    "vendor/pako/lib/zlib/inffast.js": "ec1e0f7abeec681a0d5e3da46d06f499969cbf265eaaa5e21a135d2a9b878c16",
    "vendor/pako/lib/zlib/inflate.js": "321582ddc4023e47aa981a71caed0e1dad8b58f0d9e93a0b0a34fe7e3c45e05f",
    "vendor/pako/lib/zlib/inftrees.js": "94780cbdef562bcd0434c7e6f4faca1ff6be6980bf7305a200809d98d419d9c7",
    "vendor/pako/lib/zlib/messages.js": "7860a8d3c873c28e4f5f92db9ca3e45006e21b084210d87b8b7775cddccf05ed",
    "vendor/pako/lib/zlib/trees.js": "ad9cb5245b9e39edd164234d6ca19febb9dba683f1f99a67af48d62931d91426",
    "vendor/pako/lib/zlib/zstream.js": "240917347c379b1ad33b8bf07cc6981557173bc3408f35e9875866a14b9967b2",
}

LICENSE_FILES = tuple(p for p in FILES if p == "LICENSE.txt" or p.startswith("docs/LICENSE"))


class ViewerError(Exception):
    pass


def viewer_dir() -> Path:
    return paths.RUNTIME / "novnc"


def stamp_path() -> Path:
    return viewer_dir() / STAMP


def ready() -> bool:
    """Fetched and complete: the stamp is written only after every file has
    been verified, so its presence is the check the dashboard makes."""
    s = stamp_path()
    try:
        return s.read_text(encoding="ascii").strip() == VERSION and (
            viewer_dir() / "core" / "rfb.js").exists()
    except OSError:
        return False


def missing() -> list[str]:
    d = viewer_dir()
    return [p for p in FILES if not (d / p).exists()]


def verify() -> list[str]:
    """Paths whose content does not match the pinned hash (or is absent)."""
    d = viewer_dir()
    bad = []
    for rel, digest in FILES.items():
        f = d / rel
        try:
            if hashlib.sha256(f.read_bytes()).hexdigest() != digest:
                bad.append(rel)
        except OSError:
            bad.append(rel)
    return bad


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise ViewerError(f"cannot reach {url}: {exc}") from exc


def fetch(refresh: bool = False, progress=None) -> Path:
    """Downloads every pinned file, verifies it, and writes the stamp last.
    `progress(line)` receives one line per file for the dashboard log."""
    d = viewer_dir()
    d.mkdir(parents=True, exist_ok=True)
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    # Without --refresh only what is absent or fails its hash is fetched: a
    # half-written file from an interrupted fetch is replaced, an intact one
    # is kept.
    todo = list(FILES) if refresh else verify()
    if not todo and ready():
        say(f"noVNC {VERSION} already fetched ({len(FILES)} files)")
        return d
    stamp_path().unlink(missing_ok=True)
    for i, rel in enumerate(todo, 1):
        data = _get(BASE + rel)
        digest = hashlib.sha256(data).hexdigest()
        if digest != FILES[rel]:
            raise ViewerError(
                f"{rel}: checksum mismatch (got {digest[:12]}, pinned {FILES[rel][:12]}); "
                f"the download is not the pinned noVNC {VERSION} file")
        target = d / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(target)
        say(f"[{i}/{len(todo)}] {rel} ({len(data) // 1024} KiB)")
    bad = verify()
    if bad:
        raise ViewerError(f"{len(bad)} file(s) still wrong after fetch: {', '.join(bad[:5])}")
    stamp_path().write_text(VERSION + "\n", encoding="ascii")
    say(f"noVNC {VERSION} ready in {d}")
    return d


def render_status() -> str:
    lines = [f"console viewer: noVNC {VERSION} (MPL-2.0), fetched from GitHub at bootstrap"]
    if ready():
        lines.append(f"  ready in {viewer_dir()} ({len(FILES)} files)")
    else:
        m = missing()
        lines.append(f"  not fetched: {len(m)} of {len(FILES)} files missing")
        lines.append("  'winlab bootstrap' or 'winlab viewer fetch' downloads it")
    return "\n".join(lines)
