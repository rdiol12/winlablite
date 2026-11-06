"""Content packs in the winlab trial: there are none.

The full winlab ships its paid labs as encrypted packs that a licence opens.
The trial has no packs and opens none; every lab it has is a plain file
under content/.
"""

from __future__ import annotations

from pathlib import Path

EXT = ".wlpack"
FULL = "labs-full"
FREE_LAB = "ad-ds-basics"
_NOTE = "the winlab trial has no content packs"


class PackError(Exception):
    pass


def env_name(pack_id: str) -> str:
    return "WINLAB_PACK_KEY_" + pack_id.upper().replace("-", "_")


class Pack:
    id = ""

    @classmethod
    def parse(cls, raw: bytes, source: str = "") -> "Pack":
        raise PackError(_NOTE)

    @classmethod
    def read(cls, path: Path) -> "Pack":
        raise PackError(_NOTE)

    def names(self) -> list[str]:
        return []

    def entry(self, name: str) -> dict | None:
        return None

    def meta(self, name: str) -> dict:
        return {}

    def verify_key(self, key: bytes) -> bool:
        return False

    def decrypt(self, name: str, key: bytes) -> bytes:
        raise PackError(_NOTE)


def plan(content: Path, free_lab: str = FREE_LAB):
    raise PackError(_NOTE)


def build(content: Path, out: Path, key: bytes, pack_id: str = FULL, strip: bool = False) -> dict:
    raise PackError(_NOTE)


def key_from(hex_arg: str = "", pack_id: str = FULL) -> bytes:
    raise PackError(_NOTE)
