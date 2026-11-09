"""Encrypt the trial's lessons for the installed app.

    python packaging/trialpack.py <staged-content-dir>

The release build stages the trial's content (winlab/edition.py stage()),
then runs this on the staged copy, never on the checkout. It makes a fresh
random key, packs every lab, lesson, exercise and worked solution with their
translations into content/packs/trial.wlpack (winlab/packs.py, encrypt then
MAC), deletes the plain files that went in, and writes the key as
winlab/licensing/trialkey.py. packaging/protect.py then compiles that module
and the decryption code to native code, so the exe carries no bytecode of
either and the installed folder has no lesson in the clear.

This keeps the trial's lessons from being lifted out of the installed folder
in a text editor. A determined person with a debugger can still read a key
the program itself must use; the real protection for the full winlab is that
none of its labs, lessons or code are in the trial at all.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from winlab import packs  # noqa: E402

KEY_MODULE = ROOT / "winlab" / "licensing" / "trialkey.py"


def write_key_module(key: bytes) -> None:
    # Two shares, so the key is never one constant in the compiled module.
    a = os.urandom(len(key))
    b = bytes(x ^ y for x, y in zip(key, a))
    KEY_MODULE.write_text(
        '"""The winlab trial\'s pack key: written by packaging/trialpack.py for one\n'
        'build, compiled to native code, never committed."""\n\n'
        f"_A = bytes.fromhex({a.hex()!r})\n"
        f"_B = bytes.fromhex({b.hex()!r})\n\n\n"
        "def key() -> bytes:\n"
        "    return bytes(x ^ y for x, y in zip(_A, _B))\n",
        encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[0])
        return 2
    content = Path(argv[0]).resolve()
    if content == (ROOT / "content").resolve():
        print("trialpack: run it on the staged copy, never on the checkout's content/")
        return 2
    key = os.urandom(32)
    out = content / "packs" / f"{packs.TRIAL}{packs.EXT}"
    summary = packs.build(content, out, key, pack_id=packs.TRIAL, strip=True)
    write_key_module(key)
    print(f"trialpack: {summary['entries']} files encrypted into {out.name} "
          f"({summary['bytes'] // 1024} KB), {summary['free']} left plain; key in {KEY_MODULE.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
