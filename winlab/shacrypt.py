"""SHA-512 crypt (the `$6$` scheme of glibc and FreeBSD's crypt(3)), in the
standard library only, so winlab can write a password hash into an
appliance's configuration without the password ever being stored in clear.

The algorithm is Ulrich Drepper's "Unix crypt using SHA-256 and SHA-512"
specification; the test suite checks its published test vector.
"""

from __future__ import annotations

import hashlib
import secrets

_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
# The order the 64 digest bytes are emitted in, three at a time, as the
# specification lays them out (the last byte stands alone).
_GROUPS = ((0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26),
           (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
           (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16),
           (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41))
DEFAULT_ROUNDS = 5000


def _b64(value: int, chars: int) -> str:
    out = []
    for _ in range(chars):
        out.append(_ALPHABET[value & 0x3F])
        value >>= 6
    return "".join(out)


def _repeat_to(block: bytes, length: int) -> bytes:
    return (block * (length // len(block) + 1))[:length]


def sha512_crypt(password: str | bytes, salt: str = "", rounds: int = DEFAULT_ROUNDS) -> str:
    """'$6$<salt>$<hash>' (with 'rounds=N$' when N is not the default), as
    crypt(3) returns it for the same inputs."""
    pw = password.encode("utf-8") if isinstance(password, str) else password
    salt = (salt or new_salt())[:16]
    sb = salt.encode("ascii")
    rounds = max(1000, min(int(rounds), 999_999_999))

    b = hashlib.sha512(pw + sb + pw).digest()
    a = hashlib.sha512(pw + sb)
    a.update(_repeat_to(b, len(pw)))
    n = len(pw)
    while n > 0:
        a.update(b if n & 1 else pw)
        n >>= 1
    da = a.digest()

    dp = hashlib.sha512(pw * len(pw)).digest()
    p = _repeat_to(dp, len(pw)) if pw else b""
    ds = hashlib.sha512(sb * (16 + da[0])).digest()
    s = _repeat_to(ds, len(sb)) if sb else b""

    c = da
    for r in range(rounds):
        h = hashlib.sha512()
        h.update(p if r & 1 else c)
        if r % 3:
            h.update(s)
        if r % 7:
            h.update(p)
        h.update(c if r & 1 else p)
        c = h.digest()

    text = "".join(_b64((c[i] << 16) | (c[j] << 8) | c[k], 4) for i, j, k in _GROUPS)
    text += _b64(c[63], 2)
    prefix = "$6$" + (f"rounds={rounds}$" if rounds != DEFAULT_ROUNDS else "")
    return f"{prefix}{salt}${text}"


def new_salt(length: int = 16) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def verify(password: str, hashed: str) -> bool:
    """True when the hash was made from this password (any rounds count)."""
    if not hashed.startswith("$6$"):
        return False
    parts = hashed.split("$")
    rounds = DEFAULT_ROUNDS
    salt = parts[2]
    if salt.startswith("rounds="):
        rounds = int(salt[7:])
        salt = parts[3]
    return secrets.compare_digest(sha512_crypt(password, salt, rounds), hashed)
