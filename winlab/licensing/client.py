"""Licensing in the winlab trial: there is none.

The trial needs no key and activates nothing. Its one pack (its own
lessons, encrypted in the installed app) opens with a key built into the exe. Everything the full winlab
gates behind a licence (the other labs, content packs, the update feed,
school features) is simply not part of the trial, so every question here
has the same answer: not licensed. The full winlab is at buy_url().
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import paths

TOKEN_FILE = paths.VAR / "license.json"
PENDING_STATE = paths.STATE / "pending-key.json"
SITE_URL = "https://smartcartapp.net"
BUY_PATH = "/pricing"
TRIAL_NOTE = ("This is the winlab trial. It needs no key; the full winlab, with every lab, "
              "is at " + SITE_URL + BUY_PATH + ".")


class LicenseError(Exception):
    pass


@dataclass
class LicenseStatus:
    state: str = "unlicensed"
    key: str = ""
    seats: int = 0
    plan: str = ""
    expires: float = 0.0
    recheck: float = 0.0
    message: str = TRIAL_NOTE
    products: list = field(default_factory=list)
    features: list = field(default_factory=list)
    seats_used: int = 0
    kind: str = ""
    org: str = ""

    @property
    def ok(self) -> bool:
        return False


def site_url() -> str:
    return SITE_URL


def server_url() -> str:
    return ""


def buy_url() -> str:
    return SITE_URL + BUY_PATH


def fingerprint() -> str:
    return ""


def _load_token() -> dict | None:
    return None


def _verify_token(_tok: dict) -> bool:
    return False


def status() -> LicenseStatus:
    return LicenseStatus()


def has_feature(_name: str, _st: "LicenseStatus | None" = None) -> bool:
    return False


def pack_key(pack_id: str) -> bytes | None:
    """The trial's own pack opens with the key its build compiled in
    (winlab/licensing/trialkey.py, written by packaging/build-exe.ps1 and
    never committed). A checkout has plain files and no key."""
    from ..packs import TRIAL
    if pack_id != TRIAL:
        return None
    try:
        from . import trialkey  # type: ignore[attr-defined]
    except ImportError:
        return None
    return trialkey.key()


def activate(_key: str = "", _server: str = "", _timeout: int = 20) -> LicenseStatus:
    raise LicenseError(TRIAL_NOTE)


def activate_offline(_token_json: str) -> LicenseStatus:
    raise LicenseError(TRIAL_NOTE)


def activate_pending(_timeout: int = 20) -> dict:
    return {}


def pending_key_files() -> list:
    return []


def renew_if_due(_timeout: int = 20) -> LicenseStatus | None:
    return None


def deactivate(_online: bool = True, _server: str = "", _timeout: int = 20) -> str:
    return "Nothing to deactivate: the trial has no licence."


def render(_s: LicenseStatus | None = None) -> str:
    return TRIAL_NOTE
