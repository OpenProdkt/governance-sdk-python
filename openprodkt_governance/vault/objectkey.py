"""Object keys for stored envelopes."""
from __future__ import annotations

from datetime import datetime, timezone

from .errors import InvalidInputError
from .validate import valid_id, valid_kind


def to_utc(when: datetime) -> datetime:
    """Return when in UTC; a naive datetime is taken to be UTC already."""
    if not isinstance(when, datetime):
        raise InvalidInputError()
    if when.tzinfo is None or when.utcoffset() is None:
        return when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def object_key(organization_id: str, when: datetime, operation_id: str, kind: str, n: int) -> str:
    """Return the storage key of one record:

        vault/<organization>/<yyyy>/<mm>/<operation id>/<kind>-<n>.opkv

    The year and month are the UTC month of ``when``. ``n`` is the record's position
    within the operation and starts at 1. Identifiers are validated as for seal; "."
    and ".." are refused as well so a key can never be read as a relative path.
    """
    if (
        not valid_id(organization_id)
        or not valid_id(operation_id)
        or not valid_kind(kind)
        or isinstance(n, bool)
        or not isinstance(n, int)
        or n < 1
        or organization_id in (".", "..")
        or operation_id in (".", "..")
    ):
        raise InvalidInputError()
    utc = to_utc(when)
    return "vault/%s/%04d/%02d/%s/%s-%d.opkv" % (organization_id, utc.year, utc.month, operation_id, kind, n)
