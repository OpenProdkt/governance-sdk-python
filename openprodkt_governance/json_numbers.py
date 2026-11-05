"""Lossless bounded-decimal JSON support; no ambient Decimal context/rounding."""
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any


_TOKEN = re.compile(r"-?(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?\Z")


def parse_decimal_token(text: str, *, allow_historical: bool = False) -> Decimal:
    """Validate the raw JSON token before constructing any Decimal."""
    if len(text) > 4096:
        raise ValueError("JSON number exceeds 4096 characters")
    match = _TOKEN.fullmatch(text)
    if match is None:
        raise ValueError("invalid JSON number")
    fraction = match[2] or ""
    digits = (match[1] + fraction).lstrip("0")
    if not digits:
        return Decimal(0)
    if allow_historical:
        # Management responses may contain previously authored values outside
        # today's domain. Keep them inspectable; author/evaluate validation is
        # still strict. Decimal stores a bounded coefficient and exponent, not
        # a potentially enormous expanded string.
        try:
            value = Decimal(text)
        except InvalidOperation as error:
            raise ValueError("JSON number cannot be represented as Decimal") from error
        if not value.is_finite():
            raise ValueError("JSON number cannot be represented as a finite Decimal")
        return value
    exponent_text = match[3] or "0"
    magnitude = exponent_text.lstrip("+-").lstrip("0") or "0"
    # A <=4096-character mantissa cannot offset an exponent beyond 4404.
    if len(magnitude) > 4:
        raise ValueError("number exceeds adjusted exponent [-308,308]")
    exponent = int(magnitude) * (-1 if exponent_text.startswith("-") else 1)
    adjusted = exponent - len(fraction) + len(digits) - 1
    if len(digits.rstrip("0")) > 128 or not -308 <= adjusted <= 308:
        raise ValueError("number exceeds 128 significant digits or adjusted exponent [-308,308]")
    return Decimal(text)


def _parse_integer_token(text: str) -> int:
    return int(parse_decimal_token(text))


def _reject_constant(text: str) -> None:
    raise ValueError("JSON numbers must be finite")


JSON_NUMBER_KWARGS = {
    "parse_float": parse_decimal_token,
    "parse_int": _parse_integer_token,
    "parse_constant": _reject_constant,
}


def _read_decimal_token(text: str) -> Decimal:
    return parse_decimal_token(text, allow_historical=True)


def _read_integer_token(text: str) -> int:
    return int(_read_decimal_token(text))


READ_JSON_NUMBER_KWARGS = {
    "parse_float": _read_decimal_token,
    "parse_int": _read_integer_token,
    "parse_constant": _reject_constant,
}


def loads(text: str | bytes) -> Any:
    return json.loads(text, **JSON_NUMBER_KWARGS)


def validate_number(value: int | float | Decimal) -> None:
    decimal = value if isinstance(value, Decimal) else Decimal(str(value))
    if not decimal.is_finite():
        raise ValueError("metadata numbers must be finite")
    _, digits, exponent = decimal.as_tuple()
    # Decimal does not retain its source lexeme. Check its equivalent Decimal
    # text, including sign, point and exponent, before canonical serialization.
    if len(digits) > 4096 or len(str(decimal)) > 4096:
        raise ValueError("number exceeds decimal input limits")
    if not any(digits):
        return
    significant = len(digits)
    while significant and digits[significant - 1] == 0:
        significant -= 1
    adjusted = int(exponent) + len(digits) - 1
    if significant > 128 or not -308 <= adjusted <= 308:
        raise ValueError("number exceeds 128 significant digits or adjusted exponent [-308,308]")

def _decimal_text(value: Decimal) -> str:
    validate_number(value)
    if not value:
        return "0"
    sign, digits, exponent = value.as_tuple()
    end = len(digits)
    while digits[end - 1] == 0:
        end -= 1
    coefficient = "".join(str(digit) for digit in digits[:end])
    power = int(exponent) + len(digits) - end
    point = len(coefficient) + power
    if power >= 0:
        text = coefficient + "0" * power
    elif point > 0:
        text = coefficient[:point] + "." + coefficient[point:]
    else:
        text = "0." + "0" * -point + coefficient
    return ("-" if sign else "") + text


def dumps(value: Any) -> str:
    """Encode Decimal as JSON numbers, never strings or intermediate floats."""
    def encode(item: Any, ancestors: set[int]) -> str:
        if isinstance(item, Decimal):
            return _decimal_text(item)
        if isinstance(item, (dict, list, tuple)):
            identity = id(item)
            if identity in ancestors:
                raise ValueError("JSON contains a cycle")
            ancestors.add(identity)
            try:
                if isinstance(item, dict):
                    if not all(isinstance(key, str) for key in item):
                        raise TypeError("JSON object keys must be strings")
                    return "{" + ",".join(json.dumps(key) + ":" + encode(child, ancestors) for key, child in item.items()) + "}"
                return "[" + ",".join(encode(child, ancestors) for child in item) + "]"
            finally:
                ancestors.remove(identity)
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            validate_number(item)
        return json.dumps(item, allow_nan=False)
    return encode(value, set())


def has_decimal(value: Any) -> bool:
    pending = [(value, False)]
    ancestors: set[int] = set()
    found = False
    while pending:
        item, leaving = pending.pop()
        if isinstance(item, Decimal):
            found = True
        if not isinstance(item, (dict, list, tuple)):
            continue
        if leaving:
            ancestors.remove(id(item))
            continue
        if id(item) in ancestors:
            raise ValueError("JSON contains a cycle")
        ancestors.add(id(item))
        pending.append((item, True))
        children = item.values() if isinstance(item, dict) else item
        pending.extend((child, False) for child in children)
    return found


def validate_value(value: Any, depth: int = 0, ancestors: set[int] | None = None) -> None:
    if depth > 64:
        raise ValueError("value nesting exceeds 64 levels")
    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        validate_number(value)
    if isinstance(value, (dict, list, tuple)):
        if ancestors is None:
            ancestors = set()
        if id(value) in ancestors:
            raise ValueError("value contains a cycle")
        ancestors.add(id(value))
        try:
            children = value.values() if isinstance(value, dict) else value
            for child in children:
                validate_value(child, depth + 1, ancestors)
        finally:
            ancestors.remove(id(value))


def validate_request_values(payload: Any) -> None:
    """Depth starts at metadata or EACH condition.value, never the envelope."""
    if not isinstance(payload, dict):
        return
    if "metadata" in payload:
        validate_value(payload["metadata"])
    pending = [payload.get("condition")]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        if "value" in node:
            validate_value(node["value"])
        if isinstance(node.get("all"), list):
            pending.extend(node["all"])
        if "not" in node:
            pending.append(node["not"])
