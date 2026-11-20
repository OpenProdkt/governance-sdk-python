"""Seal records and write them through an ObjectWriter the caller supplies."""
from __future__ import annotations

import abc
import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from .envelope import seal
from .errors import InvalidInputError, ObjectWriteError
from .keys import KeyBackend
from .objectkey import object_key, to_utc
from .validate import valid_key_ref

# Lock mode names follow the S3 Object Lock vocabulary.
RETENTION_COMPLIANCE = "COMPLIANCE"
RETENTION_GOVERNANCE = "GOVERNANCE"
_MODES = (RETENTION_COMPLIANCE, RETENTION_GOVERNANCE)


@dataclass(frozen=True)
class Retention:
    """The lock an ObjectWriter applies to one object."""

    until: datetime
    mode: str


class ObjectWriter(abc.ABC):
    """Stores one object under a retention lock in storage the caller owns, with the
    caller's credentials, and returns the version id of the stored object.

    An implementation must raise, and never return an empty version id, when the
    object is not stored with the lock.
    """

    @abc.abstractmethod
    def put_locked(self, key: str, body: bytes, retention: Retention) -> str:
        """Store body under key and return its version id."""


@dataclass(frozen=True)
class Pointer:
    """Identifies a stored envelope. It holds no record content and no key material."""

    object_key: str
    version_id: str
    key_ref: str
    ciphertext_digest: str  # "sha256:" plus the lowercase hex SHA-256 of the envelope bytes
    kind: str


@dataclass
class VaultWriterConfig:
    backend: Optional[KeyBackend] = None
    objects: Optional[ObjectWriter] = None
    # key_ref names the key that wraps every data key this writer creates.
    key_ref: str = ""
    # Each object is locked until the time of the write plus retention_period.
    retention_mode: str = ""
    retention_period: Optional[timedelta] = None
    # now returns the current time; None means the system clock.
    now: Optional[Callable[[], datetime]] = None


class VaultWriter:
    """Seals records and writes them through an ObjectWriter."""

    def __init__(self, config: VaultWriterConfig) -> None:
        if (
            not isinstance(config, VaultWriterConfig)
            or config.backend is None
            or config.objects is None
            or not valid_key_ref(config.key_ref)
            or config.retention_mode not in _MODES
            or not isinstance(config.retention_period, timedelta)
            or config.retention_period <= timedelta(0)
            or (config.now is not None and not callable(config.now))
        ):
            raise InvalidInputError()
        self._backend = config.backend
        self._objects = config.objects
        self._key_ref = config.key_ref
        self._mode = config.retention_mode
        self._period = config.retention_period
        self._now = config.now or (lambda: datetime.now(timezone.utc))

    def write(self, kind: str, organization_id: str, operation_id: str, n: int, record: Any) -> Pointer:
        """Seal record and store it as record number n (starting at 1) of the operation.

        It raises, and returns no pointer, when sealing fails, when the ObjectWriter
        fails, or when it returns an empty version id.
        """
        now = to_utc(self._now())
        key = object_key(organization_id, now, operation_id, kind, n)
        envelope = seal(self._backend, self._key_ref, kind, organization_id, operation_id, record)
        try:
            retention = Retention(until=now + self._period, mode=self._mode)
        except OverflowError:
            raise InvalidInputError() from None
        try:
            version_id = self._objects.put_locked(key, envelope, retention)
        except Exception as error:
            raise ObjectWriteError() from error
        if not isinstance(version_id, str) or version_id == "":
            raise ObjectWriteError("vault: object write failed: no version id returned")
        return Pointer(
            object_key=key,
            version_id=version_id,
            key_ref=self._key_ref,
            ciphertext_digest="sha256:" + hashlib.sha256(envelope).hexdigest(),
            kind=kind,
        )


@dataclass(frozen=True)
class StoredObject:
    """One object held by a MemoryObjectWriter."""

    body: bytes
    version_id: str
    retention: Retention


class MemoryObjectWriter(ObjectWriter):
    """An in-memory ObjectWriter for tests. Like a locked bucket used with unique keys,
    it refuses to write the same key twice."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._objects: Dict[str, StoredObject] = {}
        self._next = 0

    def put_locked(self, key: str, body: bytes, retention: Retention) -> str:
        if (
            not isinstance(key, str)
            or key == ""
            or not isinstance(retention, Retention)
            or not isinstance(retention.until, datetime)
            or retention.mode not in _MODES
        ):
            raise ObjectWriteError("vault: object write failed: invalid object or retention")
        try:
            data = bytes(body)
        except Exception:
            raise ObjectWriteError("vault: object write failed: invalid object or retention") from None
        with self._lock:
            if key in self._objects:
                raise ObjectWriteError("vault: object write failed: key already written")
            self._next += 1
            version = "mem-%d" % self._next
            self._objects[key] = StoredObject(body=data, version_id=version, retention=retention)
            return version

    def get(self, key: str) -> Optional[StoredObject]:
        """Return the stored object, or None."""
        with self._lock:
            return self._objects.get(key)

    def keys(self) -> List[str]:
        """Return the stored object keys in sorted order."""
        with self._lock:
            return sorted(self._objects)
