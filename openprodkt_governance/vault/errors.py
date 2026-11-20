"""Exception classes for the vault package.

Messages are fixed text. They never carry key material, wrapped keys, record
content or caller-supplied values.
"""
from __future__ import annotations

from typing import Optional


class VaultError(Exception):
    """Base class for every error raised by the vault package."""

    _default = "vault: error"

    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(self._default if message is None else message)


class InvalidInputError(VaultError):
    """An argument or the record was refused before anything was encrypted."""

    _default = "vault: invalid input"


class RecordTooLargeError(InvalidInputError):
    """The record is over the size limit. It is an InvalidInputError with the same text."""


class EnvelopeError(VaultError):
    """The single failure class for an envelope that cannot be opened.

    It covers bad magic, a malformed or altered header, wrong authenticated data, a
    wrong key and a failed authentication tag. It deliberately says nothing more.
    """

    _default = "vault: envelope rejected"


class KeyDestroyedError(VaultError):
    """The key service reports that the key was destroyed or can no longer be used."""

    _default = "vault: key destroyed"


class KeyNotFoundError(VaultError):
    """The key service does not know the key reference."""

    _default = "vault: key not found"


class InvalidWrappedKeyError(VaultError):
    """The wrapped data key was not produced by the key, or was altered."""

    _default = "vault: wrapped key rejected"


class KeyBackendError(VaultError):
    """Wraps every failure that comes from a key backend."""

    _default = "vault: key backend failed"


class ObjectWriteError(VaultError):
    """Wraps every failure to store an envelope."""

    _default = "vault: object write failed"


class _DestroyedBackendError(KeyBackendError, KeyDestroyedError):
    _default = "vault: key backend failed: key destroyed"


class _NotFoundBackendError(KeyBackendError, KeyNotFoundError):
    _default = "vault: key backend failed: key not found"


class _InvalidWrappedBackendError(KeyBackendError, InvalidWrappedKeyError):
    _default = "vault: key backend failed: wrapped key rejected"


def backend_failure(error: BaseException) -> KeyBackendError:
    """Return the KeyBackendError that stands for a failure raised by a key backend."""
    if isinstance(error, KeyDestroyedError):
        return _DestroyedBackendError()
    if isinstance(error, KeyNotFoundError):
        return _NotFoundBackendError()
    if isinstance(error, InvalidWrappedKeyError):
        return _InvalidWrappedBackendError()
    return KeyBackendError()
