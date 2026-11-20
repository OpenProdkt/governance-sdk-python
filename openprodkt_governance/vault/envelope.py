"""The "opk-vault.v1" envelope: seal a record, open an envelope.

Layout: ``OPKV1\\n`` + canonical JSON header + ``\\n`` + AES-256-GCM ciphertext (with its
16-byte tag). The header members that name the organization, operation, kind and key
are also the authenticated data.
"""
from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from ._canonical import (
    MAX_RECORD_SIZE,
    RecordTooLarge,
    UnsupportedRecordError,
    canonical_record,
    canonical_strings,
    parse_json,
)
from ._crypto import aesgcm_class
from .errors import (
    EnvelopeError,
    InvalidInputError,
    KeyBackendError,
    RecordTooLargeError,
    VaultError,
    backend_failure,
)
from .keys import DATA_KEY_SIZE
from .validate import KIND_INPUT, KIND_OUTPUT, valid_id, valid_key_ref, valid_kind

VERSION = "opk-vault.v1"
ALGORITHM = "AES-256-GCM"

_MAGIC = b"OPKV1\n"
_NONCE_SIZE = 12
_TAG_SIZE = 16
_MAX_WRAPPED_KEY = 4096
_MAX_HEADER_BYTES = 16 << 10
_HEADER_MEMBERS = ("v", "kind", "organization_id", "operation_id", "key_ref", "wrapped_key", "nonce", "alg")


@dataclass(frozen=True)
class Header:
    """The authenticated metadata at the start of an envelope."""

    version: str
    kind: str
    organization_id: str
    operation_id: str
    key_ref: str
    wrapped_key: bytes
    nonce: bytes
    algorithm: str


def _aad(kind: str, organization_id: str, operation_id: str, key_ref: str) -> bytes:
    return canonical_strings(
        {
            "v": VERSION,
            "kind": kind,
            "organization_id": organization_id,
            "operation_id": operation_id,
            "key_ref": key_ref,
        }
    )


def _encryption_context(organization_id: str, operation_id: str) -> Dict[str, str]:
    return {"organization_id": organization_id, "operation_id": operation_id}


def _key_bytes(value: Any) -> bytes:
    try:
        return bytes(value)
    except Exception:
        raise KeyBackendError("vault: key backend failed: unusable data key") from None


def seal(backend: Any, key_ref: str, kind: str, organization_id: str, operation_id: str, record: Any) -> bytes:
    """Encrypt record for one organization and operation with a fresh data key and a
    fresh random nonce, and return the envelope bytes.

    The record is a mapping, or JSON text (str or bytes) of a JSON object. Numbers
    must be integers within +/-(2**53-1). Every failure before the key backend is
    called raises InvalidInputError.
    """
    if (
        backend is None
        or not callable(getattr(backend, "generate_data_key", None))
        or not valid_kind(kind)
        or not valid_id(organization_id)
        or not valid_id(operation_id)
        or not valid_key_ref(key_ref)
    ):
        raise InvalidInputError()
    try:
        plaintext = canonical_record(record)
    except RecordTooLarge:
        raise RecordTooLargeError() from None
    except UnsupportedRecordError:
        raise InvalidInputError() from None
    aesgcm_class()
    try:
        generated = backend.generate_data_key(key_ref, _encryption_context(organization_id, operation_id))
    except Exception as error:
        raise backend_failure(error) from error
    try:
        data_key, wrapped = generated
    except Exception:
        raise KeyBackendError("vault: key backend failed: unusable data key") from None
    data_key = _key_bytes(data_key)
    wrapped = _key_bytes(wrapped)
    if len(data_key) != DATA_KEY_SIZE or len(wrapped) == 0 or len(wrapped) > _MAX_WRAPPED_KEY:
        raise KeyBackendError("vault: key backend failed: unusable data key")
    try:
        nonce = os.urandom(_NONCE_SIZE)
    except Exception:
        raise VaultError("vault: random source failed") from None
    return _seal_with(kind, organization_id, operation_id, key_ref, data_key, wrapped, nonce, plaintext)


def _seal_with(
    kind: str,
    organization_id: str,
    operation_id: str,
    key_ref: str,
    data_key: bytes,
    wrapped: bytes,
    nonce: bytes,
    plaintext: bytes,
) -> bytes:
    """Build an envelope from explicit key material. Used by seal with fresh random
    values; tests pass fixed ones to reproduce the shared vectors."""
    if len(data_key) != DATA_KEY_SIZE or len(nonce) != _NONCE_SIZE:
        raise InvalidInputError()
    header = canonical_strings(
        {
            "v": VERSION,
            "kind": kind,
            "organization_id": organization_id,
            "operation_id": operation_id,
            "key_ref": key_ref,
            "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "alg": ALGORITHM,
        }
    )
    ciphertext = aesgcm_class()(data_key).encrypt(nonce, plaintext, _aad(kind, organization_id, operation_id, key_ref))
    return _MAGIC + header + b"\n" + ciphertext


def open_envelope(backend: Any, envelope: bytes) -> Tuple[Header, bytes]:
    """Verify and decrypt an envelope. Returns the header and the canonical JSON bytes
    of the record.

    Every structural, authenticity or key failure is EnvelopeError, except failures
    reported by the key backend, which raise KeyBackendError (for a destroyed key the
    error is also a KeyDestroyedError). No error contains key or plaintext material.
    """
    if backend is None or not callable(getattr(backend, "decrypt", None)):
        raise InvalidInputError()
    aesgcm = aesgcm_class()
    try:
        header, ciphertext = _parse_envelope(envelope)
    except Exception:
        raise EnvelopeError() from None
    try:
        key = backend.decrypt(
            header.key_ref, header.wrapped_key, _encryption_context(header.organization_id, header.operation_id)
        )
    except Exception as error:
        raise backend_failure(error) from error
    try:
        data_key = bytes(key)
        if len(data_key) != DATA_KEY_SIZE:
            raise ValueError
        plaintext = aesgcm(data_key).decrypt(
            header.nonce,
            ciphertext,
            _aad(header.kind, header.organization_id, header.operation_id, header.key_ref),
        )
    except Exception:
        raise EnvelopeError() from None
    return header, plaintext


def _parse_envelope(envelope: Any) -> Tuple[Header, bytes]:
    """Check everything that does not need the key. Raises ValueError when malformed."""
    if not isinstance(envelope, (bytes, bytearray, memoryview)):
        raise ValueError
    envelope = bytes(envelope)
    if len(envelope) > MAX_RECORD_SIZE + _TAG_SIZE + _MAX_HEADER_BYTES + len(_MAGIC) + 1 or not envelope.startswith(_MAGIC):
        raise ValueError
    rest = envelope[len(_MAGIC):]
    end = rest.find(b"\n")
    if end < 0 or end > _MAX_HEADER_BYTES:
        raise ValueError
    header_bytes, ciphertext = rest[:end], rest[end + 1:]
    if len(ciphertext) < _TAG_SIZE:
        raise ValueError
    obj = parse_json(header_bytes)
    if not isinstance(obj, dict) or len(obj) != len(_HEADER_MEMBERS):
        raise ValueError
    members: Dict[str, str] = {}
    for name in _HEADER_MEMBERS:
        text = obj.get(name)
        if not isinstance(text, str):
            raise ValueError
        members[name] = text
    # The header must already be canonical: no reordering, whitespace or alternate escapes.
    try:
        canonical = canonical_strings(members)
    except UnsupportedRecordError:
        raise ValueError from None
    if canonical != header_bytes:
        raise ValueError
    if (
        members["v"] != VERSION
        or members["alg"] != ALGORITHM
        or not valid_kind(members["kind"])
        or not valid_id(members["organization_id"])
        or not valid_id(members["operation_id"])
        or not valid_key_ref(members["key_ref"])
    ):
        raise ValueError
    wrapped = _decode_base64(members["wrapped_key"])
    if len(wrapped) == 0 or len(wrapped) > _MAX_WRAPPED_KEY:
        raise ValueError
    nonce = _decode_base64(members["nonce"])
    if len(nonce) != _NONCE_SIZE:
        raise ValueError
    header = Header(
        version=members["v"],
        kind=members["kind"],
        organization_id=members["organization_id"],
        operation_id=members["operation_id"],
        key_ref=members["key_ref"],
        wrapped_key=wrapped,
        nonce=nonce,
        algorithm=members["alg"],
    )
    return header, ciphertext


def _decode_base64(text: str) -> bytes:
    """Accept only the canonical standard alphabet with padding."""
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError from None
    if base64.b64encode(decoded).decode("ascii") != text:
        raise ValueError
    return decoded


__all__ = ["ALGORITHM", "Header", "KIND_INPUT", "KIND_OUTPUT", "VERSION", "open_envelope", "seal"]
