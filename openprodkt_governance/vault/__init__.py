"""Seal records into an authenticated, encrypted envelope ("opk-vault.v1") and write
them to object storage that the caller owns.

Everything in this package runs in the caller's process. It makes no network calls
of its own: the caller supplies the key service (KeyBackend) and the object store
(ObjectWriter). A key backend generates one fresh 32-byte data key per record and
wraps it with a key held by the caller's key service. Destroying that key in the key
service makes the stored ciphertext unreadable.

AES-256-GCM comes from the optional 'cryptography' package:
``pip install 'openprodkt-governance-sdk[vault]'``. Importing this package does not
need it; sealing, opening and creating a MemoryBackend do.
"""
from .envelope import ALGORITHM, VERSION, Header, open_envelope, seal
from .errors import (
    EnvelopeError,
    InvalidInputError,
    InvalidWrappedKeyError,
    KeyBackendError,
    KeyDestroyedError,
    KeyNotFoundError,
    ObjectWriteError,
    RecordTooLargeError,
    VaultError,
)
from .keys import DATA_KEY_SIZE, Call, KeyBackend, MemoryBackend
from .objectkey import object_key
from .validate import KIND_INPUT, KIND_OUTPUT
from .writer import (
    RETENTION_COMPLIANCE,
    RETENTION_GOVERNANCE,
    MemoryObjectWriter,
    ObjectWriter,
    Pointer,
    Retention,
    StoredObject,
    VaultWriter,
    VaultWriterConfig,
)
from ._canonical import MAX_RECORD_SIZE

# A Kind is one of the KIND_* strings.
Kind = str

__all__ = [
    "ALGORITHM",
    "Call",
    "DATA_KEY_SIZE",
    "EnvelopeError",
    "Header",
    "InvalidInputError",
    "InvalidWrappedKeyError",
    "KIND_INPUT",
    "KIND_OUTPUT",
    "KeyBackend",
    "KeyBackendError",
    "KeyDestroyedError",
    "KeyNotFoundError",
    "Kind",
    "MAX_RECORD_SIZE",
    "MemoryBackend",
    "MemoryObjectWriter",
    "ObjectWriteError",
    "ObjectWriter",
    "Pointer",
    "RecordTooLargeError",
    "RETENTION_COMPLIANCE",
    "RETENTION_GOVERNANCE",
    "Retention",
    "StoredObject",
    "VERSION",
    "VaultError",
    "VaultWriter",
    "VaultWriterConfig",
    "object_key",
    "open_envelope",
    "seal",
]
