"""Voice: the office phone system runs FreePBX, the IP phones a softphone.

The phone system (role ``pbx``) is a Debian 12 machine that installs
FreePBX 17 at its first power-on, offline, from what this PC fetched at
preparation; its management is FreePBX's own web pages on port 80, opened
from a browser on a lab PC. The phones (role ``ipphone``) are small Alpine
machines whose screen is GNOME Calls, a real SIP softphone, full screen; the
student signs each one in to the phone system in its own VoIP account
settings. winlab makes no extension and signs no phone in.

What comes from where (rule 2: nothing is bundled):

- Debian's packages (Apache, MariaDB, PHP 8.2, Node.js and their
  dependencies) from deb.debian.org, each .deb against the archive index's
  SHA-256, as the ``freepbx`` pack (winlab/debpacks.py).
- Asterisk 22, as Sangoma builds it for FreePBX 17, from Sangoma's apt
  repository deb.freepbx.org (Debian 12 carries no Asterisk), in the same
  pack. Sangoma signs that repository: its InRelease, its package index and
  its signing key go on the stick beside the .debs, and the phone system
  checks the signature with gpgv, the index against the signed InRelease,
  and every Sangoma .deb against the signed index before it installs a thing.
- FreePBX itself, Sangoma's open-source tarball (framework and the open
  source modules of the stable repository, never the commercial ones) from
  mirror.freepbx.org. Sangoma publishes no checksum beside it, so this PC
  records its SHA-256 at the fetch (the phone system checks the copy on the
  stick against it) and FreePBX checks every module's own GPG signature
  (module.sig, against the FreePBX key it carries) when it installs it.

This module adds those extra files to the pack, and says what the phone
system's management pages are (winlab/adminui.py).
"""

from __future__ import annotations

import base64
import hashlib
import re
import tarfile
import time
from pathlib import Path

from . import adminui

FREEPBX_MIRROR = "https://mirror.freepbx.org/modules/packages/freepbx/"
FREEPBX_TARBALL = "freepbx-17.0-latest.tgz"
# Sangoma's apt repository for FreePBX 17 on Debian 12, as its installer
# (sng_freepbx_debian_install.sh) adds it, and the key it trusts it with.
FREEPBX_REPO = "http://deb.freepbx.org/freepbx17-prod"
FREEPBX_SUITE = "bookworm"
FREEPBX_COMPONENT = "main"
FREEPBX_KEY_URL = "http://deb.freepbx.org/gpg/aptly-pubkey.asc"

# Files beside the .debs on the stick.
TARBALL_SUM = FREEPBX_TARBALL + ".sha256"
INRELEASE = "freepbx-InRelease"
INDEX = "freepbx-Packages"
KEYRING = "freepbx-archive.gpg"
EXTRA_FILES = (FREEPBX_TARBALL, TARBALL_SUM, INRELEASE, INDEX, KEYRING)

ROLE_PBX = "pbx"
ROLE_PHONE = "ipphone"
PBX_IMAGE = "debian12"


class VoipError(Exception):
    pass


# ------------------------------------------------------------ OpenPGP bits
def dearmor(text: str) -> bytes:
    """An ASCII-armoured OpenPGP key block -> its binary packets (what gpgv
    reads as a keyring), the armour's CRC-24 checked."""
    m = re.search(r"-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n(.*?)-----END PGP PUBLIC KEY BLOCK-----",
                  text, re.S)
    if not m:
        raise VoipError("the signing key is not an armoured OpenPGP public key")
    body, crc = [], ""
    seen_blank = False
    for line in m[1].splitlines():
        line = line.strip()
        if not seen_blank:
            if not line:
                seen_blank = True
            elif ":" not in line:  # no armour headers at all
                seen_blank = True
                body.append(line)
            continue
        if line.startswith("="):
            crc = line[1:]
        elif line:
            body.append(line)
    try:
        data = base64.b64decode("".join(body), validate=True)
    except ValueError:
        raise VoipError("the signing key's armour does not decode") from None
    if crc and base64.b64decode(crc) != _crc24(data).to_bytes(3, "big"):
        raise VoipError("the signing key's armour checksum does not match")
    if not data:
        raise VoipError("the signing key is empty")
    return data


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def fingerprint(keyring: bytes) -> str:
    """The v4 fingerprint of the first public key in a binary keyring (SHA-1
    over 0x99, the length and the key packet), as gpg prints it."""
    if not keyring or not keyring[0] & 0x80:
        raise VoipError("not an OpenPGP packet")
    tag0 = keyring[0]
    if tag0 & 0x40:                       # new format
        tag = tag0 & 0x3F
        l1 = keyring[1]
        if l1 < 192:
            length, start = l1, 2
        elif l1 < 224:
            length, start = ((l1 - 192) << 8) + keyring[2] + 192, 3
        else:
            length, start = int.from_bytes(keyring[2:6], "big"), 6
    else:                                 # old format
        tag = (tag0 >> 2) & 0x0F
        kind = tag0 & 0x03
        n = {0: 1, 1: 2, 2: 4}.get(kind)
        if n is None:
            raise VoipError("indeterminate packet length")
        length, start = int.from_bytes(keyring[1:1 + n], "big"), 1 + n
    if tag != 6:
        raise VoipError("the keyring does not start with a public key")
    body = keyring[start:start + length]
    if len(body) != length or body[:1] != b"\x04":
        raise VoipError("not a version 4 public key")
    return hashlib.sha1(b"\x99" + length.to_bytes(2, "big") + body).hexdigest().upper()


# ------------------------------------------------------------- apt indexes
def release_sha256(text: str) -> dict[str, str]:
    """The SHA256 section of a Release/InRelease: {path: sha256}."""
    from .debpacks import release_hashes
    return release_hashes(text)


def index_sha256(text: str) -> dict[str, str]:
    """A Packages file -> {.deb basename: sha256}."""
    out = {}
    for stanza in text.split("\n\n"):
        name = sha = ""
        for line in stanza.splitlines():
            if line.startswith("Filename:"):
                name = line.split(":", 1)[1].strip().rsplit("/", 1)[-1]
            elif line.startswith("SHA256:"):
                sha = line.split(":", 1)[1].strip().lower()
        if name and sha:
            out[name] = sha
    return out


def check_tarball(path: Path) -> str:
    """The FreePBX tarball: its framework version, after checking it is the
    installer it should be (freepbx/install, the framework's module.xml) and
    that nothing in it leaves its own folder."""
    try:
        with tarfile.open(path, "r:gz") as tar:
            names = set()
            version = ""
            for member in tar:
                n = member.name
                if n.startswith("/") or ".." in n.split("/"):
                    raise VoipError(f"the FreePBX tarball has a path outside its folder: {n}")
                names.add(n.rstrip("/"))
                if n == "freepbx/module.xml" and member.isfile():
                    fh = tar.extractfile(member)
                    m = re.search(rb"<version>([^<]+)</version>", fh.read() if fh else b"")
                    version = m[1].decode() if m else ""
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise VoipError(f"the FreePBX tarball is unreadable ({exc}); fetch it again") from exc
    if "freepbx/install" not in names or not version:
        raise VoipError("this is not FreePBX's installer tarball (no freepbx/install and module.xml)")
    if not version.startswith("17."):
        raise VoipError(f"the tarball is FreePBX {version}, not 17")
    return version


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ----------------------------------------------- the pack's extra files
def fetch_extra(pack, d: Path, closure, get, download, say) -> dict:
    """After the .debs: Sangoma's signed index and key (and the check that
    every Sangoma .deb in the pack is the one it signed), and the FreePBX
    tarball. Returns what the pack's manifest records about them."""
    from . import debpacks
    from .bootstrap import BootstrapError
    try:
        say(f"reading Sangoma's signed release file ({FREEPBX_REPO}/dists/{FREEPBX_SUITE}/InRelease)")
        inrelease = get(f"{FREEPBX_REPO}/dists/{FREEPBX_SUITE}/InRelease").decode("utf-8", "replace")
        if "-----BEGIN PGP SIGNED MESSAGE-----" not in inrelease:
            raise VoipError("Sangoma's InRelease is not signed")
        path = f"{FREEPBX_COMPONENT}/binary-amd64/Packages"
        if path not in release_sha256(inrelease):
            # the phone system checks the plain index against this entry
            raise VoipError(f"Sangoma's InRelease lists no {path}")
        url = f"{FREEPBX_REPO}/dists/{FREEPBX_SUITE}/{path}.gz"
        packed = debpacks._fetch_index(get, url)
        try:
            debpacks.check_release(inrelease, url, packed)
        except debpacks.PackError:
            raise VoipError("Sangoma's package index does not match its signed InRelease") from None
        raw = debpacks._unpack_index(packed).encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != release_sha256(inrelease)[path]:
            raise VoipError("Sangoma's package index does not match its signed InRelease")
        say("reading Sangoma's repository key")
        keyring = dearmor(get(FREEPBX_KEY_URL).decode("ascii", "replace"))
        fpr = fingerprint(keyring)
    except BootstrapError as exc:
        raise VoipError(str(exc)) from exc
    signed = index_sha256(raw.decode("utf-8", "replace"))
    root = FREEPBX_REPO.rstrip("/")
    theirs = [deb for deb in closure if deb.base.rstrip("/") == root]
    for deb in theirs:
        if signed.get(deb.basename) != deb.sha256:
            raise VoipError(f"{deb.basename} is not the package Sangoma's signed index names")
    (d / INRELEASE).write_text(inrelease, encoding="utf-8")
    (d / INDEX).write_bytes(raw)
    (d / KEYRING).write_bytes(keyring)
    say(f"Sangoma's key {fpr[:4]} {fpr[4:8]} … {fpr[-8:-4]} {fpr[-4:]}: the phone system checks the "
        f"signature with it before it installs ({len(theirs)} packages from deb.freepbx.org)")

    dest = d / FREEPBX_TARBALL
    say(f"fetching FreePBX: {FREEPBX_MIRROR}{FREEPBX_TARBALL}")
    try:
        download(FREEPBX_MIRROR + FREEPBX_TARBALL, dest, expect_sha="", label="FreePBX 17")
    except BootstrapError as exc:
        raise VoipError(str(exc)) from exc
    version = check_tarball(dest)
    sha = _sha256_file(dest)
    (d / TARBALL_SUM).write_text(f"{sha}  {FREEPBX_TARBALL}\n", encoding="utf-8")
    say(f"FreePBX {version} (SHA-256 {sha[:12]}…, recorded here: Sangoma publishes no checksum for it; "
        f"FreePBX checks each module's own signature when it installs)")
    return {"freepbx": version, "freepbx_sha256": sha, "freepbx_fetched": time.strftime("%Y-%m-%d"),
            "key_fingerprint": fpr, "sangoma_packages": len(theirs), "files": list(EXTRA_FILES)}


def extra_ready(d: Path, man: dict) -> bool:
    extra = man.get("extra") or {}
    return bool(extra.get("freepbx")) and all((d / f).exists() and (d / f).stat().st_size > 0
                                             for f in EXTRA_FILES)


# ---------------------------------------- the phone system's own pages
def _pbx_gui(lab, node):
    if ROLE_PBX not in getattr(node, "roles", []) or getattr(node, "image", "") != PBX_IMAGE:
        return None
    return adminui.AdminGui(
        software="FreePBX 17 (Asterisk 22)", scheme="http", port=80, path="/admin",
        sign_in="the administrator you create on FreePBX's first page (Initial Setup); there is none until then",
        license="GPL-3.0 (framework GPLv2+, core GPLv3+, some modules AGPLv3+); Asterisk GPL-2.0",
        note="Extensions, trunks, routes and the SIP settings; Apply Config writes them into Asterisk.")


adminui.register(node_gui=_pbx_gui)
