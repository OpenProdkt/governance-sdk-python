# Test-only independent reference for the mcp-tool-definition:v1 digest profile.
# It is not a public SDK API (the SDKs carry the observation but never compute it) and it
# shares no code with the Go PEP implementation, so agreement on the shared vectors is an
# independent cross-check of the expected digests.
import hashlib
import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path

MAX_SAFE_INTEGER = 2**53 - 1
PREFIX = b"openprodkt:mcp-tool-definition:v1:"
VECTORS = Path(__file__).resolve().parents[2] / "testdata" / "mcp-tool-definition-vectors.json"
if not VECTORS.exists():
    VECTORS = Path(__file__).resolve().parents[1] / "testdata" / "mcp-tool-definition-vectors.json"


class Unsupported(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unsupported("duplicate object key")
        result[key] = value
    return result


def _number(raw):
    value = Decimal(raw)
    if not value.is_finite() or abs(value) > MAX_SAFE_INTEGER or value != value.to_integral_value():
        raise Unsupported("number is not an exact safe integer")
    return int(value)


def _constant(raw):
    raise Unsupported("invalid JSON constant " + raw)


def _jcs(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        # ensure_ascii=False emits the ECMAScript JSON.stringify escapes RFC 8785 requires.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + _jcs(value[key]) for key in keys) + "}"
    raise Unsupported("unsupported value")


def reference_digest(vector_text_schema, name, description=None, server_version=None):
    """Return the digest string, or None when the observation must be omitted."""
    try:
        schema = json.loads(vector_text_schema, object_pairs_hook=_pairs, parse_int=_number,
                            parse_float=_number, parse_constant=_constant)
    except Unsupported:
        return None
    definition = {"name": name, "inputSchema": schema}
    if description is not None:
        definition["description"] = description
    if server_version is not None:
        definition["server_version"] = server_version
    canonical = _jcs(definition).encode("utf-8")
    return "sha256:" + hashlib.sha256(PREFIX + canonical).hexdigest()


def _dump_with_raw_numbers(value):
    if isinstance(value, _RawNumber):
        return value.text
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _dump_with_raw_numbers(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_dump_with_raw_numbers(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False)


class _RawNumber:
    def __init__(self, text):
        self.text = text


def _load_with_raw_numbers():
    text = VECTORS.read_text(encoding="utf-8")
    return json.loads(text, object_pairs_hook=_pairs, parse_int=_RawNumber, parse_float=_RawNumber)


def reference_for(vector):
    schema_text = _dump_with_raw_numbers(vector["inputSchema"])
    return reference_digest(schema_text, vector["name"], vector.get("description"), vector.get("server_version"))


class MCPToolDefinitionVectors(unittest.TestCase):
    def test_vectors_match_independent_reference(self):
        document = _load_with_raw_numbers()
        self.assertEqual(document["profile"], "mcp-tool-definition:v1")
        self.assertEqual(document["prefix"].encode("utf-8"), PREFIX)
        seen = set()
        for vector in document["vectors"]:
            with self.subTest(vector["id"]):
                self.assertNotIn(vector["id"], seen)
                seen.add(vector["id"])
                got = reference_for(vector)
                want = vector["expected"]
                self.assertEqual("omit" if got is None else got, want)

    def test_vector_properties(self):
        digests = {v["id"]: reference_for(v) for v in _load_with_raw_numbers()["vectors"]}
        self.assertEqual(digests["simple"], digests["key-order-independence"])
        self.assertEqual(digests["integer-numbers"], digests["integer-numbers-canonical-spelling"])
        self.assertNotEqual(digests["unicode-composed"], digests["unicode-decomposed-differs-from-composed"])
        self.assertNotEqual(digests["absent-description"], digests["empty-description-differs-from-absent"])
        distinct = ["simple", "absent-description", "absent-server-version", "changed-description",
                    "changed-schema", "changed-server-version", "absent-description-and-server-version"]
        self.assertEqual(len({digests[i] for i in distinct}), len(distinct))
        for omitted in ("unsupported-fraction", "unsupported-unsafe-integer",
                        "unsupported-huge-exponent", "unsupported-negative-fraction-exponent"):
            self.assertIsNone(digests[omitted])


if __name__ == "__main__":
    if "--print" in sys.argv:
        for entry in _load_with_raw_numbers()["vectors"]:
            result = reference_for(entry)
            print(entry["id"], "omit" if result is None else result)
    else:
        unittest.main()
