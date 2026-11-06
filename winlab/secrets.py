"""Per-lab generated secrets. Nothing here is ever committed: a lab's
Administrator password lives in var/labs/<lab>/admin-password, created on
first use, readable by the person who runs the lab and nobody else."""

from __future__ import annotations

import os
import secrets as _secrets
import string
from pathlib import Path

from . import paths

PASSWORD_FILE = "admin-password"

# Meets Windows complexity (three of four classes) and stays out of trouble
# in XML (unattend), TOML, JSON and single-quoted PowerShell: no quotes,
# backslashes, ampersands, angle brackets or dollar signs.
_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase
_DIGIT = string.digits
_SYMBOL = "!#%+-=_"


def generate_password(length: int = 16) -> str:
    rng = _secrets.SystemRandom()
    chars = [rng.choice(_UPPER), rng.choice(_LOWER), rng.choice(_DIGIT), rng.choice(_SYMBOL)]
    pool = _UPPER + _LOWER + _DIGIT + _SYMBOL
    chars += [rng.choice(pool) for _ in range(max(length, 12) - len(chars))]
    rng.shuffle(chars)
    # Do not start with a symbol: a leading '-' reads as a flag to some tools.
    if chars[0] in _SYMBOL:
        i = next(i for i, c in enumerate(chars) if c not in _SYMBOL)
        chars[0], chars[i] = chars[i], chars[0]
    return "".join(chars)


def password_path(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / PASSWORD_FILE


def lab_admin_password(lab_name: str) -> str:
    """The lab's Administrator password, generated the first time it is asked
    for and stable afterwards (images, exercises and students rely on it)."""
    p = password_path(lab_name)
    if p.exists():
        pw = p.read_text(encoding="utf-8").strip()
        if pw:
            return pw
    pw = generate_password()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(pw + "\n")
    return pw
