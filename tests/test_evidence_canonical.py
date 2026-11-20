# Test-only evidence JCS reference; not a public SDK API.
import hashlib
import json
import unittest
from decimal import Decimal
from pathlib import Path

MAX_SAFE_INTEGER = 2**53 - 1
VECTORS = Path(__file__).resolve().parents[2] / "testdata" / "evidence-canonical-vectors.json"


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _number(raw):
    value = Decimal(raw)
    if not value.is_finite() or abs(value) > MAX_SAFE_INTEGER or value != value.to_integral_value():
        raise ValueError("number is not an exact safe integer")
    return int(value)


def _constant(raw):
    raise ValueError("invalid JSON constant " + raw)


def _check_unicode(value, depth=0):
    if depth > 256:
        raise ValueError("excessive depth")
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_unicode(key, depth + 1)
            _check_unicode(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_unicode(item, depth + 1)


def _parse(raw):
    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_pairs,
        parse_int=_number,
        parse_float=_number,
        parse_constant=_constant,
    )
    _check_unicode(value)
    return value


def _render(value):
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_render(key) + ":" + _render(value[key]) for key in keys) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_render(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _hash(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvidenceCanonicalReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
        if cls.vectors["format"] != "opk.evidence.canonical.v1":
            raise ValueError("unsupported fixture format")

    def test_shared_positive_vectors(self):
        for vector in self.vectors["positive"]:
            with self.subTest(vector=vector["name"]):
                value = _parse(vector["raw"].encode("utf-8"))
                canonical = _render(value)
                self.assertEqual(canonical, vector["canonical"])
                self.assertEqual(_hash(canonical), vector["hash"])
                self.assertEqual(_render(_parse(canonical.encode("utf-8"))), canonical)
                if "event_hash" in vector:
                    without_integrity = {key: item for key, item in value.items() if key != "integrity"}
                    self.assertEqual(_hash(_render(without_integrity)), vector["event_hash"])

    def test_shared_negative_vectors(self):
        for vector in self.vectors["negative"]:
            with self.subTest(vector=vector["name"]):
                raw = bytes.fromhex(vector["raw_hex"]) if "raw_hex" in vector else vector["raw"].encode("utf-8")
                with self.assertRaises((ValueError, UnicodeError)):
                    _parse(raw)

    def test_entire_integrity_block_is_excluded_only_at_top_level(self):
        value = {"data": {"integrity": "retained"}}
        expected = _hash(_render(value))
        for integrity in (None, "anything", {"canon": "jcs", "event_hash": "old", "ledger_index": 4}):
            value["integrity"] = integrity
            self.assertEqual(_hash(_render({key: item for key, item in value.items() if key != "integrity"})), expected)
        value["data"]["integrity"] = "changed"
        self.assertNotEqual(_hash(_render({key: item for key, item in value.items() if key != "integrity"})), expected)


if __name__ == "__main__":
    unittest.main()
