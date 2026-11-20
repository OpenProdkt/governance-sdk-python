"""Key backends: the interface to the caller's key service, and an in-memory backend."""
from __future__ import annotations

import abc
import os
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Set, Tuple

from ._crypto import aesgcm_class
from .errors import InvalidWrappedKeyError, KeyDestroyedError, KeyNotFoundError

# Size in bytes of every data key and of every plaintext key a KeyBackend returns.
DATA_KEY_SIZE = 32

_WRAP_NONCE_SIZE = 12


class KeyBackend(abc.ABC):
    """The caller's key service. Implementations use the ambient credentials of the
    running environment; the interface carries no credentials.

    Implementations must return a plaintext key of exactly DATA_KEY_SIZE bytes. The
    optional encryption context holds non-secret identifiers (organization and
    operation) that a key service may bind to the wrapped key.
    """

    @abc.abstractmethod
    def generate_data_key(
        self, key_ref: str, encryption_context: Optional[Mapping[str, str]] = None
    ) -> Tuple[bytes, bytes]:
        """Return (plaintext_key, wrapped_key): a new random data key and the same key
        wrapped under key_ref."""

    @abc.abstractmethod
    def decrypt(
        self, key_ref: str, wrapped_key: bytes, encryption_context: Optional[Mapping[str, str]] = None
    ) -> bytes:
        """Unwrap a data key that generate_data_key returned for the same key_ref."""


@dataclass(frozen=True)
class Call:
    """One request to a MemoryBackend. It never holds key material."""

    op: str  # "GenerateDataKey" or "Decrypt"
    key_ref: str
    context: Dict[str, str] = field(default_factory=dict)


class MemoryBackend(KeyBackend):
    """An in-memory KeyBackend for tests and local development.

    Every key reference gets its own random 32-byte key-encryption key on first use.
    Data keys are wrapped with AES-256-GCM, with the key reference as associated data.
    Keys live in process memory only.
    """

    def __init__(self) -> None:
        aesgcm_class()
        self._lock = threading.Lock()
        self._keys: Dict[str, bytes] = {}
        self._destroyed: Set[str] = set()
        self._calls: List[Call] = []

    @property
    def calls(self) -> List[Call]:
        """A copy of the call log, oldest first."""
        with self._lock:
            return [Call(c.op, c.key_ref, dict(c.context)) for c in self._calls]

    def _log(self, op: str, key_ref: object, context: Optional[Mapping[str, str]]) -> None:
        self._calls.append(Call(op, key_ref if isinstance(key_ref, str) else "", dict(context or {})))

    def generate_data_key(
        self, key_ref: str, encryption_context: Optional[Mapping[str, str]] = None
    ) -> Tuple[bytes, bytes]:
        aesgcm = aesgcm_class()
        with self._lock:
            self._log("GenerateDataKey", key_ref, encryption_context)
            if not isinstance(key_ref, str) or key_ref == "":
                raise KeyNotFoundError()
            if key_ref in self._destroyed:
                raise KeyDestroyedError()
            kek = self._keys.get(key_ref)
            if kek is None:
                kek = os.urandom(DATA_KEY_SIZE)
                self._keys[key_ref] = kek
            data_key = os.urandom(DATA_KEY_SIZE)
            nonce = os.urandom(_WRAP_NONCE_SIZE)
            try:
                associated = key_ref.encode("utf-8")
            except UnicodeEncodeError:
                raise KeyNotFoundError() from None
            wrapped = nonce + aesgcm(kek).encrypt(nonce, data_key, associated)
            return data_key, wrapped

    def decrypt(
        self, key_ref: str, wrapped_key: bytes, encryption_context: Optional[Mapping[str, str]] = None
    ) -> bytes:
        aesgcm = aesgcm_class()
        with self._lock:
            self._log("Decrypt", key_ref, encryption_context)
            if not isinstance(key_ref, str):
                raise KeyNotFoundError()
            if key_ref in self._destroyed:
                raise KeyDestroyedError()
            kek = self._keys.get(key_ref)
            if kek is None:
                raise KeyNotFoundError()
            try:
                wrapped = bytes(wrapped_key)
            except Exception:
                raise InvalidWrappedKeyError() from None
            if len(wrapped) < _WRAP_NONCE_SIZE:
                raise InvalidWrappedKeyError()
            try:
                data_key = aesgcm(kek).decrypt(
                    wrapped[:_WRAP_NONCE_SIZE], wrapped[_WRAP_NONCE_SIZE:], key_ref.encode("utf-8")
                )
            except Exception:
                raise InvalidWrappedKeyError() from None
            if len(data_key) != DATA_KEY_SIZE:
                raise InvalidWrappedKeyError()
            return data_key

    def destroy_key(self, key_ref: str) -> None:
        """Forget the key for key_ref. Afterwards decrypt raises KeyDestroyedError and
        generate_data_key refuses to create the key again. It models the caller
        destroying a key in their own key service."""
        with self._lock:
            self._keys.pop(key_ref, None)
            self._destroyed.add(key_ref)
