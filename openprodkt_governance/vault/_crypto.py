"""Lazy access to the optional 'cryptography' package."""
from __future__ import annotations

_INSTALL_HINT = (
    "The vault package needs the 'cryptography' package. "
    "Install it with: pip install 'openprodkt-governance-sdk[vault]'"
)


def aesgcm_class():
    """Return cryptography's AESGCM class, or raise a clear ImportError."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError(_INSTALL_HINT) from None
    return AESGCM
