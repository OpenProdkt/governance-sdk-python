"""Writes one evidence record for a guarded call and reports why a write failed.

The vault package is imported only when a record is written, so the SDK works without
the optional ``cryptography`` dependency until the vault is used. Nothing here keeps or
logs a record, and a failure is reduced to one reason class.
"""
from __future__ import annotations

import time
from typing import Any, Optional, Tuple

from .correlation import (
    VAULT_GAP_KEY_SERVICE_UNAVAILABLE,
    VAULT_GAP_RECORD_TOO_LARGE,
    VAULT_GAP_STORAGE_UNAVAILABLE,
    VAULT_GAP_WRITE_FAILED,
    VaultRef,
    validate_vault_members,
    vault_ref_from_pointer,
)


def _reason_for(error: BaseException) -> str:
    from .vault import errors

    if isinstance(error, errors.RecordTooLargeError):
        return VAULT_GAP_RECORD_TOO_LARGE
    if isinstance(error, (errors.KeyBackendError, errors.KeyDestroyedError, errors.KeyNotFoundError,
                          errors.InvalidWrappedKeyError)):
        return VAULT_GAP_KEY_SERVICE_UNAVAILABLE
    if isinstance(error, errors.ObjectWriteError):
        return VAULT_GAP_STORAGE_UNAVAILABLE
    return VAULT_GAP_WRITE_FAILED


def write_vault_record(
    writer: Any, kind: str, organization_id: str, operation_id: str, record: Any,
) -> Tuple[Optional[VaultRef], Optional[str]]:
    """Write one record. Returns ``(pointer, None)`` or ``(None, gap_reason)``; never raises.

    The record counter is the write time in Unix milliseconds, which stays unique across
    approval retries, sessions and processes without shared state.
    """
    try:
        pointer = writer.write(kind, organization_id, operation_id, int(time.time() * 1000), record)
        ref = vault_ref_from_pointer(pointer)
        validate_vault_members({"vault_ref": ref}, kind)
        return ref, None
    except Exception as error:  # a writer may raise anything; only the class is kept
        try:
            return None, _reason_for(error)
        except Exception:
            return None, VAULT_GAP_WRITE_FAILED
