"""Pure-Python Ed25519, vendored to keep winlab dependency-free.

Verification is what the client needs; signing is used by the license server's
key-minting tool. Reference implementation (RFC 8032), not constant-time, which
is fine here: there are no secrets on the client side, only a public key.
"""

from __future__ import annotations

import hashlib

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q, 1, (_Bx * _By) % _q)


def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _q
    b = (y1 + x1) * (y2 + x2) % _q
    c = t1 * 2 * _d * t2 % _q
    dd = z1 * 2 * z2 % _q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return (x3 % _q, y3 % _q, z3 % _q, t3 % _q)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes):
    y = _decodeint(s) & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (_decodeint(s) >> 255) & 1:
        x = _q - x
    P = (x, y, 1, (x * y) % _q)
    if not _isoncurve(P):
        raise ValueError("decoded point is not on the curve")
    return P


def _isoncurve(P) -> bool:
    x, y, z, t = P
    return (
        z % _q != 0
        and (x * y) % _q == (z * t) % _q
        and (y * y - x * x - z * z - _d * t * t) % _q == 0
    )


def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """True if `signature` (64 bytes) is valid for `message` under the 32-byte
    `public_key`."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key)
    except ValueError:
        return False
    s = _decodeint(signature[32:])
    if s >= _L:
        return False
    h = _decodeint(_H(signature[:32] + public_key + message)) % _L
    left = _scalarmult(_B, s)
    right = _edwards_add(R, _scalarmult(A, h))
    return _point_equal(left, right)


def _point_equal(P, Q) -> bool:
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    if (x1 * z2 - x2 * z1) % _q != 0:
        return False
    if (y1 * z2 - y2 * z1) % _q != 0:
        return False
    return True


# --- signing (server-side key minting only) --------------------------------


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("secret key must be 32 bytes")
    h = _H(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def publickey(secret: bytes) -> bytes:
    a, _ = _secret_expand(secret)
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def _encodepoint(P) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x = (x * zi) % _q
    y = (y * zi) % _q
    bits = y & ((1 << 255) - 1)
    bits |= (x & 1) << 255
    return bits.to_bytes(32, "little")


def sign(message: bytes, secret: bytes) -> bytes:
    a, prefix = _secret_expand(secret)
    A = _encodepoint(_scalarmult(_B, a))
    r = _decodeint(_H(prefix + message)) % _L
    R = _encodepoint(_scalarmult(_B, r))
    h = _decodeint(_H(R + A + message)) % _L
    s = (r + h * a) % _L
    return R + _encodeint(s)
