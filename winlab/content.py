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
from .packs import EXT, TRIAL, Pack, PackError, env_name

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
    d = packs_dir()
    try:
        # The trial opens only its own pack (packaging/trialpack.py), never a paid one.
        files = sorted(f for f in d.glob(f"*{EXT}") if not edition.is_core() or f.stem == TRIAL)
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
    return localized(path, _copy(hit[1]))


# --- translations (docs/TRANSLATING.md) ---------------------------------------
# Content other than lessons (which have their own per-field files) is
# translated by a string table per file: content/i18n/content/<lang>/<path>.json
# maps each English text of the file to its translation. Only the text keys
# below are swapped, never scripts, commands, names of machines or ids, so a
# check runs the same in every language. Lab definitions are never translated:
# the desktop writes them back.
TEXT_KEYS = frozenset({
    "title", "brief", "tasks", "hint", "name", "summary", "description", "why", "q", "options",
    "answer", "gaps", "body", "keywords", "category", "text", "show", "missed", "debrief", "say",
    "story", "model", "ask", "subject", "hello", "letter", "checks", "notice", "weights_note",
    "what", "about", "done", "from", "sender", "label", "prompt", "need", "intro", "outro",
    "goal", "detail", "details", "note", "notes", "question", "explain", "explanation", "lead",
    "role",  # a track's job title (tracks.toml)
})
TRANSLATED_DIRS = ("exercises", "exams", "guides", "scenarios", "sites", "help", "places")
TRANSLATED_FILES = ("commands.toml", "interviews.toml", "tracks.toml")


def translation_file(path: str | Path, lang: str) -> Path | None:
    """Where a content file's <lang> string table lives, or None when the file
    is not one that is translated this way."""
    try:
        rel = PurePosixPath(Path(path).resolve().relative_to(paths.CONTENT.resolve()).as_posix())
    except (ValueError, OSError):
        return None
    if not (rel.parts and (rel.parts[0] in TRANSLATED_DIRS or str(rel) in TRANSLATED_FILES)):
        return None
    return paths.CONTENT / "i18n" / "content" / lang / rel.with_suffix(".json")


def text_strings(path: str | Path, doc: dict) -> list[str]:
    """The English texts of a content document that its translation covers."""
    out: dict[str, None] = {}
    _walk(doc, _all_text(path), lambda s: out.setdefault(s) or s)
    return [s for s in out if s.strip()]


def _all_text(path) -> bool:
    # commands.toml: every value is a description, keyed by the command itself
    return Path(path).name == "commands.toml"


def _walk(o, every: bool, fn, key: str = ""):
    if isinstance(o, dict):
        return {k: (v if (every and k == "match") else _walk(v, every, fn, k if not every else "text"))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_walk(x, every, fn, key) for x in o]
    if isinstance(o, str) and (key in TEXT_KEYS):
        return fn(o)
    return o


def localized(path: str | Path, doc: dict, lang: str | None = None) -> dict:
    """The document with its texts in the desktop's language."""
    if lang is None:
        from . import i18n
        lang = i18n.current()
    if lang == "en":
        return doc
    f = translation_file(path, lang)
    if f is None:
        return doc
    try:
        import json
        table = json.loads(read_text(f))   # a plain file or a pack entry
    except (OSError, ValueError):
        return doc
    if not isinstance(table, dict) or not table:
        return doc
    def swap(s: str) -> str:
        t = table.get(s.strip())
        return t if isinstance(t, str) and t.strip() else s
    return _walk(doc, _all_text(path), swap)


# The troubleshooting problems (guestfaults.SCENARIOS, faults.SCENARIOS) are
# written in Python, not TOML: their title, symptom, teaches and hint ladder go
# through one string table, content/i18n/content/<lang>/problems.json, keyed by
# the English text before the lab's names are filled in, so {placeholders}
# survive translation (python tools/i18n_content.py source problems).
PROBLEMS = "problems"
_PROBLEM_TABLES: dict[str, tuple[float, dict]] = {}


def problem_strings() -> list[str]:
    """Every English text a troubleshooting problem shows, in registry order."""
    from . import faults, guestfaults
    out: dict[str, None] = {}
    for s in list(guestfaults.SCENARIOS.values()) + list(faults.SCENARIOS.values()):
        for t in (s.title, s.symptom, s.teaches, *s.hints):
            if t and t.strip():
                out.setdefault(t.strip())
    for t in drill_strings():
        if t and t.strip():
            out.setdefault(t.strip())
    return list(out)


def drill_strings() -> list[str]:
    """The texts of the other graded drills a student reads (title, symptom,
    teaches, hints, fix): nms, portsec, stp and bitlocker drills, the cabling
    fault kinds, the scenario days' own faults, the rack audit, and the
    single drills of wpaent, power, ups and nestedvirt, and the PC's hardware
    faults and power-on verdicts."""
    from . import (bitlocker, nestedvirt, nms, physfaults, portsec, power, rack,
                   scenariofaults, stp, ups, wpaent)
    out: list[str] = []
    for reg in (nms.DRILLS, portsec.DRILLS, stp.DRILLS, bitlocker.DRILLS, physfaults.KINDS):
        for d in reg.values():
            out += [getattr(d, k, "") or "" for k in ("title", "symptom", "teaches")]
            out += list(getattr(d, "hints", ()) or ())
            out.append(getattr(d, "fix", "") or "")
    out += [f.title for f in scenariofaults.FAULTS.values()]
    for k in rack.AUDIT_KINDS.values():
        out += [k.title, k.hint]
    out += [wpaent.TITLE, wpaent.SYMPTOM, *wpaent.HINTS, wpaent.FIX]
    out += [*power.FAULT_HINTS, *ups.DRILL_HINTS, *nestedvirt.HINTS, *nestedvirt.LINUX_HINTS]
    # The PC's hardware faults (their ladders are problems too) and what the
    # screen window says when a PC does not start (winlab/hwfaults.py, pcbuild.py).
    from . import hwfaults, pcbuild
    for k in hwfaults.KINDS.values():
        out += [k.title, k.symptom, k.teaches, *k.hints, k.fix]
    out += [*pcbuild.POWER_WHY.values(), *pcbuild.STAGE_WHY.values(), *(t for t, _ in pcbuild.BEEPS.values())]
    return [t for t in out if isinstance(t, str)]


def problem_file(lang: str) -> Path:
    return paths.CONTENT / "i18n" / "content" / lang / f"{PROBLEMS}.json"


def problem_table(lang: str) -> dict:
    """The problems' English-to-<lang> table ({} for English or no file)."""
    if lang == "en" or not lang.isalpha():
        return {}
    f = problem_file(lang)
    try:
        mt = f.stat().st_mtime
    except OSError:
        return {}
    hit = _PROBLEM_TABLES.get(lang)
    if hit and hit[0] == mt:
        return hit[1]
    try:
        import json
        table = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        table = {}
    table = table if isinstance(table, dict) else {}
    _PROBLEM_TABLES[lang] = (mt, table)
    return table


def problem_text(text: str, lang: str | None = None) -> str:
    """A problem's text (still with its {placeholders}) in the desktop's
    language; the English text when there is no translation."""
    if not text:
        return text
    if lang is None:
        from . import i18n
        lang = i18n.current()
    t = problem_table(lang).get(text.strip())
    return t if isinstance(t, str) and t.strip() else text


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
