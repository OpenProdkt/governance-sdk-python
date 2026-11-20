"""Argument validation shared by the vault modules."""
from __future__ import annotations

import re
from typing import Any

KIND_INPUT = "input"
KIND_OUTPUT = "output"

MAX_ID_LENGTH = 128
MAX_KEY_REF_CHARS = 256

_ID = re.compile(r"[A-Za-z0-9._:-]+")


def valid_id(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_ID_LENGTH and _ID.fullmatch(value) is not None


def valid_key_ref(value: Any) -> bool:
    if not isinstance(value, str) or value == "" or len(value) > MAX_KEY_REF_CHARS:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def valid_kind(value: Any) -> bool:
    return isinstance(value, str) and value in (KIND_INPUT, KIND_OUTPUT)
