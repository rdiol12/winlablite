"""One way in to content/: plain files first, then the encrypted packs.

Every loader that reads labs, lessons, exercises, guides or exams asks here
instead of opening the file itself. A plain file always wins, so a checkout
(every file plain) behaves exactly as before: that is development mode. In a
release the paid content exists only inside content/packs/*.wlpack; an entry
there opens when the licence is activated (or in its grace period) and the
token carries that pack's key, and stays locked otherwise. Decrypted bytes
live in this process's memory only; nothing decrypted is written to disk.
"""

from __future__ import annotations

import fnmatch
import os
import threading
import tomllib
from pathlib import Path, PurePosixPath

from . import edition, paths
from .packs import EXT, Pack, PackError, env_name

TRIAL_LAB = "ad-ds-basics"
UNLOCK_HINT = ("Unlock it with a license key: open Activate winlab in Settings, "
               "or run 'winlab license activate <key>'.")


class Locked(FileNotFoundError):
    """The content exists in a pack this PC has no key for."""


_lock = threading.Lock()
_packs: dict[str, tuple[tuple, list[Pack]]] = {}   # packs dir -> (stamp, packs)
_keys: dict[str, tuple[tuple, bytes | None]] = {}  # pack id -> (license stamp, key)
_plain: dict[tuple[str, str], bytes] = {}          # (pack file, entry) -> plaintext
_parsed: dict[str, tuple[bytes, dict]] = {}       # path -> (bytes it was parsed from, document)


def packs_dir() -> Path:
    return paths.CONTENT / "packs"


def reset() -> None:
    """Forget cached keys and plaintext (after activation or deactivation)."""
    with _lock:
        _packs.clear()
        _keys.clear()
        _plain.clear()
        _parsed.clear()


def rel(path: str | Path) -> str | None:
    """path relative to content/, POSIX style, or None when it lies outside."""
    p = Path(path)
    for base in (paths.CONTENT,):
        try:
            return PurePosixPath(*p.relative_to(base).parts).as_posix()
        except ValueError:
            pass
        try:
            return PurePosixPath(*p.resolve().relative_to(base.resolve()).parts).as_posix()
        except (ValueError, OSError):
            pass
    return None


def _load_packs() -> list[Pack]:
    if edition.is_core():
        return []   # core has no paid packs (winlab/edition.py)
    d = packs_dir()
    try:
        files = sorted(d.glob(f"*{EXT}"))
        stamp = tuple((f.name, f.stat().st_mtime_ns, f.stat().st_size) for f in files)
    except OSError:
        return []
    with _lock:
        hit = _packs.get(str(d))
        if hit and hit[0] == stamp:
            return hit[1]
    out = []
    for f in files:
        try:
            out.append(Pack.read(f))
        except (OSError, PackError):
            continue
    with _lock:
        _packs[str(d)] = (stamp, out)
    return out


def _license_stamp() -> tuple:
    from .licensing import client
    try:
        st = client.TOKEN_FILE.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


def pack_key(pack_id: str) -> bytes | None:
    """The key for a pack: the maintainer's environment variable, else the
    one wrapped in an activated licence token; None while locked."""
    env = os.environ.get(env_name(pack_id), "").strip()
    if env:
        try:
            k = bytes.fromhex(env)
            return k if len(k) == 32 else None
        except ValueError:
            return None
    stamp = _license_stamp()
    with _lock:
        hit = _keys.get(pack_id)
        if hit and hit[0] == stamp:
            return hit[1]
    from .licensing import client
    key = client.pack_key(pack_id)
    with _lock:
        _keys[pack_id] = (stamp, key)
    return key


def _find(r: str) -> Pack | None:
    for pk in _load_packs():
        if pk.entry(r) is not None:
            return pk
    return None


def _opens(pk: Pack) -> bool:
    key = pack_key(pk.id)
    return key is not None and pk.verify_key(key)


def _open(pk: Pack, r: str) -> bytes | None:
    key = pack_key(pk.id)
    if key is None:
        return None
    cache = (pk.source, r)
    with _lock:
        if cache in _plain:
            return _plain[cache]
    try:
        data = pk.decrypt(r, key)
    except PackError:
        return None
    with _lock:
        _plain[cache] = data
    return data


def _plain_exists(p: Path) -> bool:
    try:
        if not p.is_file():
            return False
    except OSError:
        return False
    # Core shows only its own labs, lessons and exercises (winlab/edition.py).
    return not edition.is_core() or edition.visible(rel(p))


def exists(path: str | Path) -> bool:
    """A plain file, or a pack entry this PC can open."""
    p = Path(path)
    if _plain_exists(p):
        return True
    r = rel(p)
    if r is None:
        return False
    pk = _find(r)
    return pk is not None and _opens(pk)


def locked(path: str | Path) -> bool:
    """Exists only in a pack this PC cannot open."""
    p = Path(path)
    if _plain_exists(p):
        return False
    r = rel(p)
    if r is None:
        return False
    pk = _find(r)
    return pk is not None and not exists(p)


def read_bytes(path: str | Path) -> bytes:
    p = Path(path)
    if _plain_exists(p):
        return p.read_bytes()
    r = rel(p)
    pk = _find(r) if r is not None else None
    if pk is None:
        raise FileNotFoundError(str(p))
    data = _open(pk, r)
    if data is None:
        raise Locked(f"{PurePosixPath(r).stem} is part of the full version. {UNLOCK_HINT}")
    return data


def read_text(path: str | Path) -> str:
    return read_bytes(path).decode("utf-8")


def load_toml(path: str | Path) -> dict:
    """tomllib.load of a content file, wherever it lives. Raises
    tomllib.TOMLDecodeError like tomllib does, FileNotFoundError when there
    is no such file and Locked when only a locked pack has it.

    The windows re-read every lesson and exercise on each refresh, so a
    document is parsed once per content: the bytes are still read each time
    (a changed file is parsed again) and the caller gets its own copy."""
    data = read_bytes(path)
    key = str(path)
    with _lock:
        hit = _parsed.get(key)
    if hit is None or hit[0] != data:
        hit = (data, tomllib.loads(data.decode("utf-8")))
        with _lock:
            _parsed[key] = hit
    return _copy(hit[1])


def _copy(v):
    # A TOML document holds only dicts, lists and immutable scalars.
    if type(v) is dict:
        return {k: _copy(x) for k, x in v.items()}
    if type(v) is list:
        return [_copy(x) for x in v]
    return v


def _pack_matches(d: Path, pattern: str) -> list[str]:
    r = rel(d)
    if r is None:
        return []
    prefix = "" if r in (".", "") else r.rstrip("/") + "/"
    out = []
    for pk in _load_packs():
        for name in pk.names():
            if name.startswith(prefix) and "/" not in name[len(prefix):] and fnmatch.fnmatch(name[len(prefix):], pattern):
                out.append(name)
    return out


def glob(d: str | Path, pattern: str = "*.toml") -> list[Path]:
    """Sorted files in d matching pattern: the plain ones and the pack
    entries this PC can open (as paths under content/, which read_bytes and
    load_toml understand)."""
    d = Path(d)
    found = {p.name: p for p in d.glob(pattern) if _plain_exists(p)} if d.is_dir() else {}
    for name in _pack_matches(d, pattern):
        leaf = PurePosixPath(name).name
        if leaf not in found and exists(paths.CONTENT / name):
            found[leaf] = d / leaf
    return [found[k] for k in sorted(found)]


def locked_in(d: str | Path, pattern: str = "*.toml") -> list[Path]:
    """The files in d that exist only in a pack this PC cannot open."""
    d = Path(d)
    out = []
    for name in _pack_matches(d, pattern):
        p = d / PurePosixPath(name).name
        if locked(p):
            out.append(p)
    return sorted(out)


def meta(path: str | Path) -> dict:
    """What a pack says about an entry without opening it (a lab's
    description), or {}."""
    r = rel(path)
    pk = _find(r) if r is not None else None
    return pk.meta(r) if pk else {}


def mode() -> str:
    """dev: no packs, everything is a plain file (a checkout); full: every
    pack opens on this PC; trial: a pack is locked; core: winlab core, which
    has no packs (winlab/edition.py)."""
    if edition.is_core():
        return "core"
    pks = _load_packs()
    if not pks:
        return "dev"
    return "full" if all(_opens(pk) for pk in pks) else "trial"
