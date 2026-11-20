"""Canonical JSON (RFC 8785) for envelope headers, authenticated data and records.

Numbers follow an exact-safe-integer profile: a record may hold integers within
+/-(2**53-1). Integral spellings such as 1.0, 1e2 and -0 normalize to an integer; a
fraction, an integer outside that range, an exponent beyond it, NaN and Infinity are
refused. Number text is never converted through a binary float, so every language
produces the same bytes.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, List

MAX_RECORD_SIZE = 8 << 20

_MAX_DEPTH = 256
_MAX_SAFE_INTEGER = 9007199254740991
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


class UnsupportedRecordError(ValueError):
    """The value is outside the supported JSON profile. Carries no value."""

    def __init__(self) -> None:
        super().__init__("record is outside the supported JSON profile")


class RecordTooLarge(UnsupportedRecordError):
    """The record is within the JSON profile but over MAX_RECORD_SIZE."""


class _Raw:
    """A JSON number kept as its source text until it is canonicalized."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def _reject_constant(_name: str) -> Any:
    raise UnsupportedRecordError()


def _object(pairs: List[Any]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise UnsupportedRecordError()
        result[key] = value
    return result


def parse_json(raw: Any) -> Any:
    """Parse JSON text (str or bytes) strictly. Duplicate members, NaN/Infinity,
    invalid UTF-8 and trailing data are refused. Numbers stay as source text."""
    try:
        text = raw if isinstance(raw, str) else bytes(raw).decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_Raw,
            parse_float=_Raw,
            parse_constant=_reject_constant,
        )
    except UnsupportedRecordError:
        raise
    except Exception:  # malformed JSON, invalid UTF-8, nesting that is too deep
        raise UnsupportedRecordError() from None


def exact_safe_integer(raw: str) -> int:
    """Normalize a JSON number exactly, without floating point."""
    if _NUMBER.fullmatch(raw) is None:
        raise UnsupportedRecordError()
    negative = raw.startswith("-")
    s = raw[1:] if negative else raw
    exponent = 0
    marker = re.search("[eE]", s)
    if marker is not None:
        exp = s[marker.end():]
        s = s[: marker.start()]
        exp_negative = exp.startswith("-")
        for c in exp.lstrip("+-"):
            if exponent >= 1000000:
                break
            exponent = exponent * 10 + (ord(c) - 48)
        if exp_negative:
            exponent = -exponent
    dot = s.find(".")
    if dot >= 0:
        exponent -= len(s) - dot - 1
        s = s[:dot] + s[dot + 1:]
    s = s.lstrip("0")
    if s == "":
        return 0
    trimmed = s.rstrip("0")
    exponent += len(s) - len(trimmed)
    s = trimmed
    if exponent < 0 or exponent > 16 or len(s) + exponent > 16:
        raise UnsupportedRecordError()
    n = int(s + "0" * exponent)
    if n > _MAX_SAFE_INTEGER:
        raise UnsupportedRecordError()
    return -n if negative else n


_ESCAPES = {i: "\\u%04x" % i for i in range(0x20)}
_ESCAPES.update({0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"})


def _quote(s: str) -> str:
    try:
        s.encode("utf-8")  # refuses unpaired surrogates
    except UnicodeEncodeError:
        raise UnsupportedRecordError() from None
    return '"' + s.translate(_ESCAPES) + '"'


def _utf16_key(s: str) -> bytes:
    # Big-endian UTF-16 bytes compare as UTF-16 code units, as RFC 8785 requires.
    try:
        return s.encode("utf-16-be")
    except UnicodeEncodeError:
        raise UnsupportedRecordError() from None


def _integer(n: int) -> str:
    if n > _MAX_SAFE_INTEGER or n < -_MAX_SAFE_INTEGER:
        raise UnsupportedRecordError()
    return str(int(n))


def _emit(value: Any, depth: int, out: List[str]) -> None:
    if depth > _MAX_DEPTH:
        raise UnsupportedRecordError()
    if value is None:
        out.append("null")
    elif isinstance(value, bool):
        out.append("true" if value else "false")
    elif isinstance(value, _Raw):
        out.append(str(exact_safe_integer(value.text)))
    elif isinstance(value, int):
        out.append(_integer(value))
    elif isinstance(value, float):
        if value != value or not value.is_integer():  # NaN, Infinity and fractions
            raise UnsupportedRecordError()
        out.append(_integer(int(value)))
    elif isinstance(value, Decimal):
        if not value.is_finite():
            raise UnsupportedRecordError()
        out.append(str(exact_safe_integer(str(value))))
    elif isinstance(value, str):
        out.append(_quote(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _emit(item, depth + 1, out)
        out.append("]")
    elif isinstance(value, Mapping):
        members = list(value.items())
        for key, _ in members:
            if not isinstance(key, str):
                raise UnsupportedRecordError()
        members.sort(key=lambda member: _utf16_key(member[0]))
        out.append("{")
        for index, (key, item) in enumerate(members):
            if index:
                out.append(",")
            out.append(_quote(key))
            out.append(":")
            _emit(item, depth + 1, out)
        out.append("}")
    else:
        raise UnsupportedRecordError()


def canonicalize(value: Any) -> bytes:
    """Return the canonical JSON bytes of a value (any JSON value in the profile)."""
    out: List[str] = []
    try:
        _emit(value, 0, out)
        return "".join(out).encode("utf-8")
    except UnsupportedRecordError:
        raise
    except Exception:  # RecursionError, odd mappings
        raise UnsupportedRecordError() from None


def canonical_strings(members: Mapping) -> bytes:
    """Canonical JSON of an object whose members are all strings."""
    return canonicalize(dict(members))


def canonical_record(record: Any) -> bytes:
    """Canonical JSON bytes of a record, which must be a JSON object.

    str, bytes and bytearray are JSON text; a mapping is canonicalized directly.
    """
    if record is None:
        raise UnsupportedRecordError()
    if isinstance(record, (str, bytes, bytearray)):
        if isinstance(record, str):
            try:
                raw = record.encode("utf-8")
            except UnicodeEncodeError:
                raise UnsupportedRecordError() from None
        else:
            raw = bytes(record)
        if len(raw) > MAX_RECORD_SIZE:
            raise RecordTooLarge()
        parsed = parse_json(raw)
    elif isinstance(record, Mapping):
        parsed = record
    else:
        raise UnsupportedRecordError()
    if not isinstance(parsed, Mapping):
        raise UnsupportedRecordError()
    out = canonicalize(parsed)
    if len(out) > MAX_RECORD_SIZE:
        raise RecordTooLarge()
    return out
