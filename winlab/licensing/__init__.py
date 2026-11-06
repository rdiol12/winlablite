"""Licensing: offline-capable, signed activation. Zero third-party deps."""

from .client import (
    LicenseError,
    LicenseStatus,
    activate,
    deactivate,
    fingerprint,
    has_feature,
    status,
)

__all__ = [
    "LicenseError",
    "LicenseStatus",
    "activate",
    "deactivate",
    "fingerprint",
    "has_feature",
    "status",
]
