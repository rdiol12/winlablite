"""Encrypted content packs: the paid labs, lessons and exercises ship inside
one file that only an activated PC can open.

Pack "labs-full" holds every lab except the free trial lab (ad-ds-basics),
plus the lessons, exercises, guides and exams that belong to those labs. The
release build makes it from the plain content/ tree and deletes the plain
files that went in (``winlab packs build ... --strip``). A checkout keeps its
plain files, and a plain file always wins over a pack entry, so development,
tests and CI see exactly what they always did (winlab/content.py).

File format (``content/packs/<id>.wlpack``), stdlib only so the Godot game
can read the same file with HMACContext and HashingContext:

    magic      8 bytes  b"WLPACK\\x00\\x01"
    hlen       4 bytes  big-endian length of the header
    header     hlen bytes of UTF-8 JSON (sorted keys, no spaces):
               {"format": 1, "pack": "<id>", "check": "<hex32>",
                "entries": [{"name": "labs/x.toml", "nonce": "<hex16>",
                             "offset": n, "length": n, "tag": "<hex32>",
                             "meta": {...}}, ...]}
    blob       the entries' ciphertexts, back to back; offsets count from
               the first byte after the header

Keys, from the 32-byte pack key K:

    enc = HMAC-SHA256(K, b"winlab-pack-enc-v1")
    mac = HMAC-SHA256(K, b"winlab-pack-mac-v1")
    keystream block i (i = 0, 1, ...) = HMAC-SHA256(enc, nonce16 + i as 8 bytes big-endian)
    ct  = plaintext XOR keystream
    tag = HMAC-SHA256(mac, b"entry" + len(name) as 4 bytes big-endian + name + nonce + ct)
    check = HMAC-SHA256(mac, b"index" + header JSON without "check")

Encrypt-then-MAC: a reader checks the index and each entry's tag (constant
time) before it decrypts anything. Entry names and the lab descriptions in
"meta" are readable without the key so the app can list what a licence
unlocks; nothing else is.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"WLPACK\x00\x01"
FORMAT = 1
EXT = ".wlpack"
FULL = "labs-full"          # the pack every paid licence unlocks
TRIAL = "trial"             # the winlab trial's own pack: its labs, lessons and answers
FREE_LAB = "ad-ds-basics"   # the trial lab: always plain, always free
MAX_HEADER = 4 * 1024 * 1024


class PackError(Exception):
    pass


def env_name(pack_id: str) -> str:
    """WINLAB_PACK_KEY_LABS_FULL for labs-full: where a build (or a
    maintainer) passes the key."""
    return "WINLAB_PACK_KEY_" + pack_id.upper().replace("-", "_")


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise PackError("a pack key is 32 bytes (64 hex characters)")
    return (hmac.new(key, b"winlab-pack-enc-v1", hashlib.sha256).digest(),
            hmac.new(key, b"winlab-pack-mac-v1", hashlib.sha256).digest())


def _keystream_xor(enc: bytes, nonce: bytes, data: bytes) -> bytes:
    base = hmac.new(enc, digestmod=hashlib.sha256)
    out = bytearray(len(data))
    for i in range(0, len(data), 32):
        h = base.copy()
        h.update(nonce + (i // 32).to_bytes(8, "big"))
        block = h.digest()
        chunk = data[i:i + 32]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


def _entry_tag(mac: bytes, name: str, nonce: bytes, ct: bytes) -> bytes:
    n = name.encode("utf-8")
    return hmac.new(mac, b"entry" + len(n).to_bytes(4, "big") + n + nonce + ct, hashlib.sha256).digest()


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _index_check(mac: bytes, header: dict) -> str:
    body = {k: v for k, v in header.items() if k != "check"}
    return hmac.new(mac, b"index" + _canon(body), hashlib.sha256).hexdigest()


def encode(pack_id: str, files: dict[str, bytes], key: bytes,
           meta: dict[str, dict] | None = None, nonce=os.urandom) -> bytes:
    """A pack of files ({"labs/x.toml": bytes}) under key."""
    enc, mac = _subkeys(key)
    entries, blob = [], bytearray()
    for name in sorted(files):
        if not name or name.startswith("/") or ".." in name.split("/") or "\\" in name:
            raise PackError(f"not a content path: {name!r}")
        n = nonce(16)
        ct = _keystream_xor(enc, n, files[name])
        e = {"name": name, "nonce": n.hex(), "offset": len(blob), "length": len(ct),
             "tag": _entry_tag(mac, name, n, ct).hex()}
        if meta and meta.get(name):
            e["meta"] = meta[name]
        entries.append(e)
        blob += ct
    header = {"format": FORMAT, "pack": pack_id, "entries": entries}
    header["check"] = _index_check(mac, header)
    h = _canon(header)
    return MAGIC + len(h).to_bytes(4, "big") + h + bytes(blob)


@dataclass
class Pack:
    """A pack file read from disk or bytes: the index is readable without
    the key, the entries only with it."""
    id: str
    header: dict
    data: bytes          # the blob after the header
    source: str = ""

    @classmethod
    def parse(cls, raw: bytes, source: str = "") -> "Pack":
        if raw[:8] != MAGIC or len(raw) < 12:
            raise PackError(f"{source or 'pack'}: not a winlab content pack")
        hlen = int.from_bytes(raw[8:12], "big")
        if hlen > MAX_HEADER or 12 + hlen > len(raw):
            raise PackError(f"{source or 'pack'}: damaged header")
        try:
            header = json.loads(raw[12:12 + hlen].decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PackError(f"{source or 'pack'}: damaged header ({exc})") from None
        if not isinstance(header, dict) or header.get("format") != FORMAT or not isinstance(header.get("entries"), list):
            raise PackError(f"{source or 'pack'}: a pack format this winlab does not read; update winlab")
        return cls(id=str(header.get("pack", "")), header=header, data=raw[12 + hlen:], source=source)

    @classmethod
    def read(cls, path: Path) -> "Pack":
        return cls.parse(Path(path).read_bytes(), str(path))

    def names(self) -> list[str]:
        return [str(e.get("name", "")) for e in self.header["entries"]]

    def entry(self, name: str) -> dict | None:
        for e in self.header["entries"]:
            if e.get("name") == name:
                return e
        return None

    def meta(self, name: str) -> dict:
        e = self.entry(name)
        return dict(e.get("meta") or {}) if e else {}

    def verify_key(self, key: bytes) -> bool:
        """Whether key opens this pack and the index is untouched."""
        memo = self.__dict__.setdefault("_verified", {})
        if key not in memo:
            _, mac = _subkeys(key)
            memo[key] = hmac.compare_digest(_index_check(mac, self.header), str(self.header.get("check", "")))
        return memo[key]

    def decrypt(self, name: str, key: bytes) -> bytes:
        """One entry's plaintext. Refuses a wrong key, an edited index or an
        edited entry before decrypting anything."""
        if not self.verify_key(key):
            raise PackError(f"{self.source or self.id}: the key does not open this pack, or the pack was altered")
        e = self.entry(name)
        if e is None:
            raise PackError(f"{name} is not in pack {self.id}")
        enc, mac = _subkeys(key)
        try:
            nonce = bytes.fromhex(e["nonce"])
            off, ln = int(e["offset"]), int(e["length"])
            tag = bytes.fromhex(e["tag"])
        except (KeyError, ValueError, TypeError):
            raise PackError(f"{name}: damaged entry in pack {self.id}") from None
        if off < 0 or ln < 0 or off + ln > len(self.data) or len(nonce) != 16:
            raise PackError(f"{name}: damaged entry in pack {self.id}")
        ct = self.data[off:off + ln]
        if not hmac.compare_digest(_entry_tag(mac, name, nonce, ct), tag):
            raise PackError(f"{name}: pack {self.id} was altered; reinstall winlab")
        return _keystream_xor(enc, nonce, ct)


# ------------------------------------------------------------------ what goes in

def _toml(p: Path) -> dict:
    try:
        with p.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def plan(content: Path, free_lab: str = FREE_LAB) -> tuple[list[str], list[str]]:
    """(paths that go into labs-full, paths that stay plain and free), both
    relative to content/. Locked: every lab but the free one, and whatever
    lesson, exercise, guide or scenario names one of those labs, and the exams. An
    exercise a free lesson or the free lab uses stays free."""
    content = Path(content)
    locked_labs = {p.stem for p in (content / "labs").glob("*.toml") if p.stem != free_lab}
    packed, free = [], []

    def lab_of(p: Path, table: str) -> str:
        return str((_toml(p).get(table) or {}).get("lab", ""))

    free_ex: set[str] = set(map(str, (_toml(content / "labs" / f"{free_lab}.toml").get("lab") or {}).get("exercises", [])))
    for p in sorted((content / "lessons").glob("*.toml")):
        meta = _toml(p).get("lesson") or {}
        rel = f"lessons/{p.name}"
        if str(meta.get("lab", "")) in locked_labs:
            packed.append(rel)
        else:
            free.append(rel)
            if meta.get("exercise"):
                free_ex.add(str(meta["exercise"]))
    for p in sorted((content / "labs").glob("*.toml")):
        (packed if p.stem in locked_labs else free).append(f"labs/{p.name}")
    for p in sorted((content / "exercises").glob("*.toml")):
        rel = f"exercises/{p.name}"
        meta = _toml(p).get("exercise") or {}
        if p.stem not in free_ex and str(meta.get("id", p.stem)) not in free_ex and lab_of(p, "exercise") in locked_labs:
            packed.append(rel)
        else:
            free.append(rel)
    for p in sorted((content / "guides").glob("*.toml")):
        (packed if lab_of(p, "guide") in locked_labs else free).append(f"guides/{p.name}")
    for p in sorted((content / "scenarios").glob("*.toml")):
        (packed if lab_of(p, "scenario") in locked_labs else free).append(f"scenarios/{p.name}")
    for p in sorted((content / "exams").glob("*.toml")):
        packed.append(f"exams/{p.name}")
    # A worked solution (the self-test's, winlab/solutions.py) goes with its exercise.
    packed_ex = {Path(r).stem for r in packed if r.startswith("exercises/")}
    for p in sorted((content / "solutions").glob("*.toml")):
        (packed if p.stem in packed_ex else free).append(f"solutions/{p.name}")
    return sorted(packed), sorted(free)


# What the trial's pack holds: every lab, lesson, exercise and worked solution,
# and their translations. Help, the command reference and the desktop's own
# strings stay plain. The key is made per build and compiled into the exe
# (winlab/licensing/client.py, packaging/build-exe.ps1), so the installed
# trial reads its lessons and the files in its folder do not.
TRIAL_DIRS = ("labs", "lessons", "exercises", "solutions")


def trial_plan(content: Path) -> tuple[list[str], list[str]]:
    content = Path(content)
    packed, free = [], []
    for p in sorted(content.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(content).as_posix()
        parts = rel.split("/")
        if parts[0] == "packs":
            continue
        inside = (parts[0] in TRIAL_DIRS
                  or parts[:2] == ["i18n", "lessons"]
                  or (len(parts) > 3 and parts[:2] == ["i18n", "content"] and parts[3] in ("exercises", "solutions")))
        (packed if inside else free).append(rel)
    return packed, free


def _meta_for(rel: str, data: bytes) -> dict:
    """What the app may show about a locked entry: a lab's description."""
    if not rel.startswith("labs/"):
        return {}
    try:
        lab = tomllib.loads(data.decode("utf-8")).get("lab") or {}
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}
    return {"description": str(lab.get("description", ""))[:300]}


def build(content: Path, out: Path, key: bytes, pack_id: str = FULL, strip: bool = False) -> dict:
    """Write the pack from the plain tree; with strip, delete the plain files
    that went in (the release build only). Returns a summary."""
    content = Path(content)
    packed, free = trial_plan(content) if pack_id == TRIAL else plan(content)
    if not packed:
        raise PackError(f"nothing to pack under {content}")
    files = {rel: (content / rel).read_bytes() for rel in packed}
    blob = encode(pack_id, files, key, {rel: _meta_for(rel, b) for rel, b in files.items()})
    # Read it back before anything is deleted: a pack that does not open
    # must never replace the plain files.
    back = Pack.parse(blob, str(out))
    for rel in packed:
        if back.decrypt(rel, key) != files[rel]:
            raise PackError(f"round trip failed for {rel}")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    if strip:
        for rel in packed:
            (content / rel).unlink()
    return {"pack": pack_id, "out": str(out), "entries": len(packed), "free": len(free),
            "bytes": len(blob), "stripped": len(packed) if strip else 0}


def key_from(hex_arg: str = "", pack_id: str = FULL) -> bytes:
    raw = (hex_arg or os.environ.get(env_name(pack_id), "")).strip()
    if not raw:
        raise PackError(f"no pack key: pass --key-hex or set {env_name(pack_id)}")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise PackError("the pack key is 64 hex characters") from None
    if len(key) != 32:
        raise PackError("the pack key is 64 hex characters")
    return key
