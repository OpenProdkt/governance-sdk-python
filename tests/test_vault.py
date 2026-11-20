import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:  # the optional "vault" extra is not installed
    HAVE_CRYPTO = False

# The vault package imports without cryptography; only sealing, opening and MemoryBackend need it.
from openprodkt_governance import vault
from openprodkt_governance.vault import (
    EnvelopeError,
    InvalidInputError,
    InvalidWrappedKeyError,
    KeyBackend,
    KeyBackendError,
    KeyDestroyedError,
    KeyNotFoundError,
    MemoryBackend,
    MemoryObjectWriter,
    ObjectWriteError,
    ObjectWriter,
    VaultError,
    VaultWriter,
    VaultWriterConfig,
    object_key,
    open_envelope,
    seal,
)
from openprodkt_governance.vault import _canonical
from openprodkt_governance.vault.envelope import _aad, _parse_envelope, _seal_with

requires_crypto = unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed")

SDK_PYTHON = Path(__file__).resolve().parents[1]
_VECTOR_FILE = SDK_PYTHON.parent / "testdata" / "vault-envelope-vectors.json"
if not _VECTOR_FILE.exists():
    # A standalone mirror keeps the shared fixtures in a testdata directory at its root.
    _VECTOR_FILE = SDK_PYTHON / "testdata" / "vault-envelope-vectors.json"
VECTORS = json.loads(_VECTOR_FILE.read_text(encoding="utf-8"))


class FixedBackend(KeyBackend):
    """Returns one known data key for one known wrapped key."""

    def __init__(self, wrapped, key):
        self.wrapped = wrapped
        self.key = key

    def generate_data_key(self, key_ref, encryption_context=None):
        raise RuntimeError("not used")

    def decrypt(self, key_ref, wrapped_key, encryption_context=None):
        if bytes(wrapped_key) != self.wrapped:
            raise InvalidWrappedKeyError()
        return self.key


def _fixed(vector):
    return FixedBackend(base64.b64decode(vector["wrapped_key_b64"]), bytes.fromhex(vector["data_key_hex"]))


class StubObjects(ObjectWriter):
    def __init__(self, version="v1", error=None):
        self.version, self.error, self.calls = version, error, []

    def put_locked(self, key, body, retention):
        self.calls.append((key, body, retention))
        if self.error is not None:
            raise self.error
        return self.version


def _config(**changes):
    values = dict(
        backend=MemoryBackend(),
        objects=MemoryObjectWriter(),
        key_ref="alias/k",
        retention_mode="COMPLIANCE",
        retention_period=timedelta(hours=1),
    )
    values.update(changes)
    return VaultWriterConfig(**values)


@requires_crypto
class VectorTests(unittest.TestCase):
    def test_vectors_reproduce_reference_bytes_and_open(self):
        for vector in VECTORS["positive"]:
            with self.subTest(vector["name"]):
                plaintext = _canonical.canonical_record(vector["record_json"])
                self.assertEqual(plaintext.decode("utf-8"), vector["canonical_record"])
                aad = _aad(vector["kind"], vector["organization_id"], vector["operation_id"], vector["key_ref"])
                self.assertEqual(aad.decode("utf-8"), vector["aad"])
                envelope = _seal_with(
                    vector["kind"],
                    vector["organization_id"],
                    vector["operation_id"],
                    vector["key_ref"],
                    bytes.fromhex(vector["data_key_hex"]),
                    base64.b64decode(vector["wrapped_key_b64"]),
                    bytes.fromhex(vector["nonce_hex"]),
                    plaintext,
                )
                want = base64.b64decode(vector["envelope_b64"])
                self.assertEqual(envelope, want)
                self.assertIn(vector["header"].encode("utf-8"), envelope)
                self.assertTrue(envelope.hex().endswith(vector["ciphertext_hex"]))
                self.assertEqual("sha256:" + hashlib.sha256(envelope).hexdigest(), vector["ciphertext_digest"])

                header, opened = open_envelope(_fixed(vector), want)
                self.assertEqual(opened.decode("utf-8"), vector["canonical_record"])
                self.assertEqual(
                    (header.kind, header.organization_id, header.operation_id, header.key_ref),
                    (vector["kind"], vector["organization_id"], vector["operation_id"], vector["key_ref"]),
                )
                self.assertTrue(header.version == "opk-vault.v1" and header.algorithm == "AES-256-GCM")
                self.assertEqual(header.nonce.hex(), vector["nonce_hex"])

    def test_vectors_reject_every_negative_case(self):
        for case in VECTORS["negative"]:
            with self.subTest(case["name"]):
                backend = _fixed(VECTORS["positive"][0])
                with self.assertRaises(EnvelopeError) as raised:
                    open_envelope(backend, base64.b64decode(case["envelope_b64"]))
                self.assertNotIsInstance(raised.exception, KeyBackendError)

    def test_seal_refuses_invalid_records_without_calling_the_backend(self):
        for case in VECTORS["invalid_records"]:
            with self.subTest(case["name"]):
                backend = MemoryBackend()
                for record in (case["record_json"], case["record_json"].encode("utf-8")):
                    with self.assertRaises(InvalidInputError):
                        seal(backend, "alias/k", "input", "org_1", "op-1", record)
                self.assertEqual(backend.calls, [])

    def test_seal_refuses_invalid_identifiers_without_calling_the_backend(self):
        for case in VECTORS["invalid_ids"]:
            with self.subTest(case["name"]):
                backend = MemoryBackend()
                with self.assertRaises(InvalidInputError):
                    seal(backend, "alias/k", "input", case["organization_id"], case["operation_id"], {"a": 1})
                self.assertEqual(backend.calls, [])

    def test_seal_refuses_other_invalid_arguments_without_calling_the_backend(self):
        backend = MemoryBackend()
        big = {"a": "x" * vault.MAX_RECORD_SIZE}
        calls = {
            "none record": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", None),
            "list record": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", [1]),
            "bad kind": lambda: seal(backend, "alias/k", "both", "org_1", "op-1", {}),
            "empty key": lambda: seal(backend, "", "input", "org_1", "op-1", {}),
            "long key": lambda: seal(backend, "k" * 257, "input", "org_1", "op-1", {}),
            "surrogate key": lambda: seal(backend, "k\ud800", "input", "org_1", "op-1", {}),
            "no backend": lambda: seal(None, "alias/k", "input", "org_1", "op-1", {}),
            "newline id": lambda: seal(backend, "alias/k", "input", "org_1\n", "op-1", {}),
            "non-string id": lambda: seal(backend, "alias/k", "input", 7, "op-1", {}),
            "record over 8 MiB": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", big),
            "text over 8 MiB": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", " " * (vault.MAX_RECORD_SIZE + 1) + "{}"),
            "non-string key": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {1: 2}),
            "fraction": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"a": 1.5}),
            "nan": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"a": float("nan")}),
            "infinity": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"a": float("inf")}),
            "unsafe int": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"a": 2**53}),
            "lone surrogate value": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"a": "\ud800"}),
            "lone surrogate key": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"\udc00": 1}),
            "lone surrogate escape": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":"\\ud800"}'),
            "lone low surrogate escape": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":"\\udc00x"}'),
            "NaN text": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":NaN}'),
            "Infinity text": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":-Infinity}'),
            "invalid utf-8": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", b'{"a":"\xff"}'),
            "trailing data": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":1} {}'),
            "set value": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"a": {1}}),
            "bytes value": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", {"a": b"x"}),
            "negative exponent fraction": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":15e-1}'),
            "huge negative exponent": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":1e-999999999999}'),
            "exponent beyond range": lambda: seal(backend, "alias/k", "input", "org_1", "op-1", '{"a":1e17}'),
        }
        for name, call in calls.items():
            with self.subTest(name):
                with self.assertRaises(InvalidInputError):
                    call()
        self.assertEqual(backend.calls, [])


class CanonicalTests(unittest.TestCase):
    """The canonical form is pure Python and needs no cryptography."""

    def test_nesting_depth_limit(self):
        def nested(levels):
            return "[" * levels + "]" * levels

        self.assertTrue(_canonical.canonical_record('{"a":' + nested(256) + "}"))
        with self.assertRaises(_canonical.UnsupportedRecordError):
            _canonical.canonical_record('{"a":' + nested(257) + "}")
        with self.assertRaises(_canonical.UnsupportedRecordError):
            _canonical.canonical_record('{"a":' + nested(50000) + "}")
        value = []
        for _ in range(300):
            value = [value]
        with self.assertRaises(_canonical.UnsupportedRecordError):
            _canonical.canonical_record({"a": value})
        cyclic = {}
        cyclic["a"] = cyclic
        with self.assertRaises(_canonical.UnsupportedRecordError):
            _canonical.canonical_record(cyclic)

    def test_canonical_number_profile(self):
        def canon(text):
            return _canonical.canonical_record(text).decode("utf-8")

        self.assertEqual(
            canon('{"a":1.0,"b":1e2,"c":-0,"d":0.0,"e":-0.0e5,"f":12e0,"g":10e-1,"h":1E+1}'),
            '{"a":1,"b":100,"c":0,"d":0,"e":0,"f":12,"g":1,"h":10}',
        )
        self.assertEqual(
            canon('{"a":9007199254740991.0,"b":-9007199254740991,"c":90071992547409.91e2}'),
            '{"a":9007199254740991,"b":-9007199254740991,"c":9007199254740991}',
        )
        self.assertEqual(canon('{"a":0e999999999}'), '{"a":0}')
        for text in ('{"a":9007199254740992}', '{"a":-9007199254740992}', '{"a":1e16}', '{"a":1.0000000000000001}',
                     '{"a":0.5}', '{"a":1e400}', '{"a":1e999999999999}', '{"a":123456789012345678}'):
            with self.subTest(text):
                with self.assertRaises(_canonical.UnsupportedRecordError):
                    _canonical.canonical_record(text)
        # Mapping inputs follow the same profile.
        self.assertEqual(
            _canonical.canonical_record({"a": 2.0, "b": Decimal("1E+2"), "c": Decimal("-0"), "d": True, "e": (1, None)}).decode(),
            '{"a":2,"b":100,"c":0,"d":true,"e":[1,null]}',
        )
        for bad in (Decimal("NaN"), Decimal("1.5"), Decimal("1E+400"), float("-inf"), 2**63, -(2**53)):
            with self.subTest(repr(bad)):
                with self.assertRaises(_canonical.UnsupportedRecordError):
                    _canonical.canonical_record({"a": bad})

    def test_canonical_strings_and_key_order(self):
        text = _canonical.canonical_record('{"b":"\\u00e9\\u2028/<>&","a":"\\u0000\\u001f\\u007f\\b\\f\\n\\r\\t\\"\\\\","\\ud83d\\ude00":1,"\\uff5e":2}')
        self.assertEqual(
            text.decode("utf-8"),
            '{"a":"\\u0000\\u001f\u007f\\b\\f\\n\\r\\t\\"\\\\","b":"\u00e9\u2028/<>&","\U0001F600":1,"\uff5e":2}',
        )
        # UTF-16 order puts an astral character (D83D) before U+FF5E; code point order would not.
        self.assertLess(text.index("\U0001F600".encode()), text.index("\uff5e".encode()))
        # An escaped pair is one character; a non-ASCII literal is kept, never normalized.
        self.assertEqual(_canonical.canonical_record('{"a":"e\\u0301"}'), '{"a":"e\u0301"}'.encode("utf-8"))
        with self.assertRaises(_canonical.UnsupportedRecordError):
            _canonical.canonical_record('{"a":1,"\\u0061":2}')
        with self.assertRaises(_canonical.UnsupportedRecordError):
            _canonical.canonical_record('{"x":{"a":1,"a":1}}')


@requires_crypto
class EnvelopeTests(unittest.TestCase):
    def test_round_trip_uses_a_fresh_key_and_nonce_each_time(self):
        backend = MemoryBackend()
        record = {"tool": "pay", "amount": 12}
        first = seal(backend, "alias/team-a", "input", "org_1", "op-1", record)
        second = seal(backend, "alias/team-a", "input", "org_1", "op-1", record)
        self.assertNotEqual(first, second)
        h1, _ = _parse_envelope(first)
        h2, _ = _parse_envelope(second)
        self.assertTrue(h1.nonce != h2.nonce and h1.wrapped_key != h2.wrapped_key and len(h1.nonce) == 12)
        header, plaintext = open_envelope(backend, first)
        self.assertTrue(plaintext == b'{"amount":12,"tool":"pay"}' and header.key_ref == "alias/team-a")
        self.assertIsInstance(header, vault.Header)
        ops = [c.op for c in backend.calls]
        self.assertTrue(ops.count("GenerateDataKey") == 2 and ops.count("Decrypt") == 1)
        for call in backend.calls:
            self.assertEqual(call.context, {"organization_id": "org_1", "operation_id": "op-1"})
            self.assertEqual(call.key_ref, "alias/team-a")
        # JSON text records give the same envelope content as mappings.
        _, again = open_envelope(backend, seal(backend, "alias/team-a", "output", "org_1", "op-1", b'{"tool":"pay","amount":12.0}'))
        self.assertEqual(again, plaintext)

    def test_destroyed_key_makes_the_envelope_unreadable(self):
        backend = MemoryBackend()
        canary = "CANARY-plaintext-7f3a"
        envelope = seal(backend, "alias/person-1", "input", "org_1", "op-1", {"secret": canary})
        self.assertNotIn(canary.encode(), envelope)
        backend.destroy_key("alias/person-1")
        with self.assertRaises(KeyDestroyedError) as raised:
            open_envelope(backend, envelope)
        self.assertTrue(isinstance(raised.exception, KeyBackendError) and isinstance(raised.exception, VaultError))
        self.assertNotIn(canary, str(raised.exception))
        with self.assertRaises(KeyDestroyedError):
            seal(backend, "alias/person-1", "input", "org_1", "op-2", {"a": 1})
        seal(backend, "alias/person-2", "input", "org_1", "op-3", {"a": 1})

    def test_backend_failures_are_wrapped_with_generic_messages(self):
        class Down(KeyBackend):
            def generate_data_key(self, key_ref, encryption_context=None):
                raise RuntimeError("key service down CANARY-backend")

            def decrypt(self, key_ref, wrapped_key, encryption_context=None):
                raise KeyNotFoundError()

        with self.assertRaises(KeyBackendError) as raised:
            seal(Down(), "alias/k", "input", "org_1", "op-1", {"a": 1})
        self.assertNotIn("CANARY", str(raised.exception))
        envelope = seal(MemoryBackend(), "alias/k", "input", "org_1", "op-1", {"a": 1})
        with self.assertRaises(KeyNotFoundError) as raised:
            open_envelope(Down(), envelope)
        self.assertIsInstance(raised.exception, KeyBackendError)
        # A fresh backend does not know the key; a different key's wrapped data is not accepted either.
        other = MemoryBackend()
        other.generate_data_key("alias/k")
        with self.assertRaises(InvalidWrappedKeyError) as raised:
            open_envelope(other, envelope)
        self.assertIsInstance(raised.exception, KeyBackendError)

        class Unusable(KeyBackend):
            def __init__(self, result):
                self.result = result

            def generate_data_key(self, key_ref, encryption_context=None):
                return self.result

            def decrypt(self, key_ref, wrapped_key, encryption_context=None):
                return self.result

        for result in ((b"short", b"wrapped"), (b"k" * 32, b""), (b"k" * 32, b"w" * 4097), None, (1, 2), "x"):
            with self.subTest(repr(result)):
                with self.assertRaises(KeyBackendError):
                    seal(Unusable(result), "alias/k", "input", "org_1", "op-1", {"a": 1})
        with self.assertRaises(EnvelopeError):
            open_envelope(Unusable(b"short"), envelope)
        with self.assertRaises(EnvelopeError):
            open_envelope(Unusable(b"k" * 32), envelope)

    def test_errors_never_carry_key_or_plaintext_material(self):
        backend = MemoryBackend()
        canary = "CANARY-plaintext-91bc"
        envelope = seal(backend, "alias/k", "output", "org_1", "op-1", {"v": canary})
        header, _ = _parse_envelope(envelope)
        tampered = bytearray(envelope)
        tampered[-1] ^= 1
        backend.destroy_key("alias/k")
        failures = []
        for call in (
            lambda: open_envelope(backend, bytes(tampered)),
            lambda: open_envelope(backend, envelope),
            lambda: open_envelope(backend, b"garbage"),
            lambda: open_envelope(backend, "not bytes"),
            lambda: seal(MemoryBackend(), "alias/k", "input", "org_1", "op-1", '{"v":"%s","bad":1.5}' % canary),
            lambda: seal(MemoryBackend(), "alias/k", "input", "org_1 %s" % canary, "op-1", {}),
        ):
            with self.assertRaises(VaultError) as raised:
                call()
            failures.append(raised.exception)
        wrapped_b64 = base64.b64encode(header.wrapped_key).decode()
        for error in failures:
            text = str(error) + repr(error) + repr(error.args)
            self.assertNotIn(canary, text)
            self.assertNotIn(wrapped_b64, text)
            self.assertNotIn(header.wrapped_key.hex(), text)
        # A tampered ciphertext against a live key is an EnvelopeError.
        live = MemoryBackend()
        good = seal(live, "alias/k", "output", "org_1", "op-1", {"v": canary})
        bad = bytearray(good)
        bad[-1] ^= 1
        with self.assertRaises(EnvelopeError) as raised:
            open_envelope(live, bytes(bad))
        self.assertEqual(str(raised.exception), "vault: envelope rejected")

    def test_open_binds_the_envelope_to_its_key_reference(self):
        backend = MemoryBackend()
        backend.generate_data_key("alias/b")
        envelope = seal(backend, "alias/a", "input", "org_1", "op-1", {"a": 1})
        rewritten = envelope.replace(b'"key_ref":"alias/a"', b'"key_ref":"alias/b"', 1)
        self.assertNotEqual(rewritten, envelope)
        with self.assertRaises(VaultError):
            open_envelope(backend, rewritten)

    def test_open_refuses_bad_inputs(self):
        backend = MemoryBackend()
        with self.assertRaises(InvalidInputError):
            open_envelope(None, b"x")
        for value in (None, 5, "text", b"", b"OPKV1\n", b"OPKV1\n{}\n" + b"x" * 16, b"OPKV1\n" + b"{" * 20000 + b"\n" + b"x" * 16):
            with self.subTest(repr(value)[:40]):
                with self.assertRaises(EnvelopeError):
                    open_envelope(backend, value)
        self.assertEqual(backend.calls, [])

    def test_header_must_be_canonical_and_complete(self):
        backend = MemoryBackend()
        envelope = seal(backend, "alias/a", "input", "org_1", "op-1", {"a": 1})
        header, _ = _parse_envelope(envelope)
        for mutated in (
            envelope.replace(b'{"alg"', b'{ "alg"', 1),
            envelope.replace(b'"kind":"input"', b'"kind":"inpu\\u0074"', 1),
            envelope.replace(b'"op-1"', b'"op-1","extra":"x"', 1),
            envelope.replace(b"OPKV1\n", b"OPKV2\n", 1),
            envelope.replace(b"opk-vault.v1", b"opk-vault.v2", 1),
            envelope.replace(b"AES-256-GCM", b"AES-128-GCM", 1),
            envelope.replace(base64.b64encode(header.nonce), base64.b64encode(header.nonce)[:-2], 1),
        ):
            self.assertNotEqual(mutated, envelope)
            with self.assertRaises(EnvelopeError):
                open_envelope(backend, mutated)
        # the seal above; no key request for a bad header
        self.assertEqual([c.op for c in backend.calls], ["GenerateDataKey"])


@requires_crypto
class WriterTests(unittest.TestCase):
    def test_writer_returns_a_pointer_without_content_or_key_material(self):
        backend, objects = MemoryBackend(), MemoryObjectWriter()
        now = datetime(2026, 11, 9, 23, 59, 59, tzinfo=timezone(timedelta(hours=-5)))
        writer = VaultWriter(_config(backend=backend, objects=objects, key_ref="alias/team", retention_period=timedelta(hours=24), now=lambda: now))
        canary = "CANARY-record-55aa"
        pointer = writer.write("input", "org_1", "op-9", 1, {"text": canary})
        self.assertEqual(pointer.object_key, "vault/org_1/2026/11/op-9/input-1.opkv")
        self.assertTrue(pointer.version_id == "mem-1" and pointer.key_ref == "alias/team" and pointer.kind == "input")
        stored = objects.get(pointer.object_key)
        self.assertEqual(stored.retention.mode, "COMPLIANCE")
        self.assertEqual(stored.retention.until, now.astimezone(timezone.utc) + timedelta(hours=24))
        self.assertEqual(pointer.ciphertext_digest, "sha256:" + hashlib.sha256(stored.body).hexdigest())
        self.assertNotIn(canary, repr(pointer))
        self.assertNotIn(canary.encode(), stored.body)
        header, plaintext = open_envelope(backend, stored.body)
        self.assertTrue(plaintext == ('{"text":"%s"}' % canary).encode() and header.operation_id == "op-9")
        self.assertEqual(objects.keys(), [pointer.object_key])
        with self.assertRaises(ObjectWriteError):
            writer.write("input", "org_1", "op-9", 1, {"text": "again"})
        self.assertTrue(writer.write("output", "org_1", "op-9", 2, {"ok": True}).object_key.endswith("/output-2.opkv"))

    def test_writer_default_clock_and_naive_time(self):
        objects = MemoryObjectWriter()
        pointer = VaultWriter(_config(objects=objects)).write("input", "org_1", "op-1", 1, {})
        stored = objects.get(pointer.object_key)
        self.assertIsNotNone(stored.retention.until.tzinfo)
        naive = VaultWriter(_config(objects=MemoryObjectWriter(), now=lambda: datetime(2030, 2, 3, 4, 5, 6)))
        self.assertEqual(naive.write("input", "org_1", "op-1", 1, {}).object_key, "vault/org_1/2030/02/op-1/input-1.opkv")

    def test_writer_never_skips_a_failed_write(self):
        cases = {
            "store error": lambda: StubObjects(error=RuntimeError("bucket unavailable CANARY-store")),
            "empty version id": lambda: StubObjects(version=""),
        }
        for name, make in cases.items():
            with self.subTest(name):
                objects = make()
                writer = VaultWriter(_config(objects=objects, retention_mode="GOVERNANCE"))
                with self.assertRaises(ObjectWriteError) as raised:
                    writer.write("output", "org_1", "op-1", 2, {"a": 1})
                self.assertNotIn("CANARY", str(raised.exception))
                self.assertEqual(len(objects.calls), 1)
                key, body, retention = objects.calls[0]
                self.assertTrue(key.endswith("/output-2.opkv") and body.startswith(b"OPKV1\n") and retention.mode == "GOVERNANCE")

    def test_writer_key_service_failure_fails_the_write(self):
        class Down(KeyBackend):
            def generate_data_key(self, key_ref, encryption_context=None):
                raise RuntimeError("down")

            def decrypt(self, key_ref, wrapped_key, encryption_context=None):
                raise RuntimeError("down")

        objects = StubObjects()
        writer = VaultWriter(_config(backend=Down(), objects=objects))
        with self.assertRaises(KeyBackendError):
            writer.write("input", "org_1", "op-1", 1, {"a": 1})
        self.assertEqual(objects.calls, [])

    def test_writer_refuses_invalid_input_before_any_call(self):
        backend, objects = MemoryBackend(), StubObjects()
        writer = VaultWriter(_config(backend=backend, objects=objects))
        for args in (
            ("both", "org_1", "op-1", 1, {}),
            ("input", "org_1", "op-1", 0, {}),
            ("input", "org_1", "op-1", True, {}),
            ("input", "..", "op-1", 1, {}),
            ("input", "org_1", "op 1", 1, {}),
            ("input", "org_1", "op-1", 1, {"a": 1.5}),
            ("input", "org_1", "op-1", 1, None),
        ):
            with self.subTest(repr(args)):
                with self.assertRaises(InvalidInputError):
                    writer.write(*args)
        self.assertTrue(objects.calls == [] and backend.calls == [])

    def test_writer_validates_its_configuration(self):
        VaultWriter(_config())
        for name, changes in {
            "no backend": {"backend": None},
            "no objects": {"objects": None},
            "no key": {"key_ref": ""},
            "bad mode": {"retention_mode": "NONE"},
            "no mode": {"retention_mode": ""},
            "zero retention": {"retention_period": timedelta(0)},
            "negative retention": {"retention_period": timedelta(seconds=-1)},
            "numeric retention": {"retention_period": 3600},
            "no retention": {"retention_period": None},
            "long key": {"key_ref": "k" * 257},
            "bad clock": {"now": "now"},
        }.items():
            with self.subTest(name):
                with self.assertRaises(InvalidInputError):
                    VaultWriter(_config(**changes))
        with self.assertRaises(InvalidInputError):
            VaultWriter(None)

    def test_writer_refuses_a_retention_that_overflows(self):
        writer = VaultWriter(_config(retention_period=timedelta(days=999999999), now=lambda: datetime(9999, 12, 31, tzinfo=timezone.utc)))
        with self.assertRaises(InvalidInputError):
            writer.write("input", "org_1", "op-1", 1, {})


class ObjectStorageTests(unittest.TestCase):
    """Object keys and the in-memory object writer do not need cryptography."""

    def test_object_key_validation(self):
        when = datetime(2026, 1, 31, 23, 30, tzinfo=timezone.utc)
        self.assertEqual(object_key("org_1", when, "op-1", "output", 3), "vault/org_1/2026/01/op-1/output-3.opkv")
        late = datetime(2026, 1, 31, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
        self.assertEqual(object_key("org_1", late, "op-1", "input", 1), "vault/org_1/2026/02/op-1/input-1.opkv")
        for args in (
            ("org_1", when, "op-1", "input", 0),
            ("org_1", when, "op-1", "input", True),
            ("org_1", when, "op-1", "input", "1"),
            ("org_1", when, "op-1", "x", 1),
            ("a/b", when, "op-1", "input", 1),
            ("org_1", when, "..", "input", 1),
            (".", when, "op-1", "input", 1),
            ("org_1", when, "", "input", 1),
            ("org_1\n", when, "op-1", "input", 1),
            ("org_1", "2026-01-01", "op-1", "input", 1),
        ):
            with self.subTest(repr(args)):
                with self.assertRaises(InvalidInputError):
                    object_key(*args)

    def test_memory_object_writer_rules(self):
        objects = MemoryObjectWriter()
        retention = vault.Retention(until=datetime(2030, 1, 1, tzinfo=timezone.utc), mode="GOVERNANCE")
        self.assertEqual(objects.put_locked("a", b"body", retention), "mem-1")
        self.assertIsNone(objects.get("missing"))
        with self.assertRaises(ObjectWriteError):
            objects.put_locked("a", b"other", retention)
        with self.assertRaises(ObjectWriteError):
            objects.put_locked("", b"x", retention)
        with self.assertRaises(ObjectWriteError):
            objects.put_locked("b", b"x", vault.Retention(until=retention.until, mode="NONE"))
        self.assertTrue(objects.get("a").body == b"body" and objects.keys() == ["a"])


@requires_crypto
class MemoryBackendTests(unittest.TestCase):
    def test_memory_backend_wrapping_and_threads(self):
        backend = MemoryBackend()
        key, wrapped = backend.generate_data_key("alias/k", {"organization_id": "o"})
        self.assertTrue(len(key) == 32 and len(wrapped) == 12 + 32 + 16)
        self.assertEqual(backend.decrypt("alias/k", wrapped), key)
        with self.assertRaises(KeyNotFoundError):
            backend.decrypt("alias/unknown", wrapped)
        with self.assertRaises(KeyNotFoundError):
            backend.generate_data_key("")
        for bad in (b"short", wrapped[:-1], wrapped[:-1] + bytes([wrapped[-1] ^ 1])):
            with self.subTest(repr(bad)):
                with self.assertRaises(InvalidWrappedKeyError):
                    backend.decrypt("alias/k", bad)
        # The wrapped key is bound to its key reference.
        backend.generate_data_key("alias/other")
        with self.assertRaises(InvalidWrappedKeyError):
            backend.decrypt("alias/other", wrapped)
        self.assertTrue(backend.calls[0].op == "GenerateDataKey" and backend.calls[0].context == {"organization_id": "o"})
        backend.calls[0].context["x"] = "y"
        self.assertNotIn("x", backend.calls[0].context)

        errors = []

        def work():
            try:
                for i in range(20):
                    envelope = seal(backend, "alias/k", "input", "org_1", "op-%d" % i, {"i": i})
                    assert open_envelope(backend, envelope)[1] == ('{"i":%d}' % i).encode()
            except Exception as error:  # pragma: no cover
                errors.append(error)

        threads = [threading.Thread(target=work) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])


def _run_blocked(code):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SDK_PYTHON) + os.pathsep + env.get("PYTHONPATH", "")
    prelude = "import sys\nsys.modules['cryptography'] = None\n"
    return subprocess.run([sys.executable, "-c", prelude + code], capture_output=True, text=True, env=env, cwd=str(SDK_PYTHON), timeout=120)


class WithoutCryptographyTests(unittest.TestCase):
    """These run in a subprocess with cryptography blocked, so they never need it installed."""

    def test_core_import_works_without_cryptography_and_vault_reports_it(self):
        result = _run_blocked(
            "import openprodkt_governance\n"
            "import openprodkt_governance.vault as vault\n"
            "assert 'cryptography.hazmat.primitives.ciphers.aead' not in sys.modules\n"
            "hint = \"pip install 'openprodkt-governance-sdk[vault]'\"\n"
            "class Backend(vault.KeyBackend):\n"
            "    called = False\n"
            "    def generate_data_key(self, key_ref, encryption_context=None):\n"
            "        Backend.called = True\n"
            "        return b'k' * 32, b'wrapped'\n"
            "    def decrypt(self, key_ref, wrapped_key, encryption_context=None):\n"
            "        Backend.called = True\n"
            "        return b'k' * 32\n"
            "for call in (\n"
            "    lambda: vault.MemoryBackend(),\n"
            "    lambda: vault.seal(Backend(), 'alias/k', 'input', 'org_1', 'op-1', {'a': 1}),\n"
            "    lambda: vault.open_envelope(Backend(), b'OPKV1\\n'),\n"
            "):\n"
            "    try:\n"
            "        call()\n"
            "    except ImportError as error:\n"
            "        assert hint in str(error), str(error)\n"
            "    else:\n"
            "        raise SystemExit('expected ImportError')\n"
            "assert not Backend.called\n"
            "try:\n"
            "    vault.seal(Backend(), 'alias/k', 'input', 'org_1', 'op-1', {'a': 1.5})\n"
            "except vault.InvalidInputError:\n"
            "    pass\n"
            "else:\n"
            "    raise SystemExit('expected InvalidInputError')\n"
            "print('ok')\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_the_vault_package_imports_without_cryptography_installed_in_a_fresh_interpreter(self):
        result = _run_blocked("import openprodkt_governance.vault as v\nprint(len(v.__all__) > 10)\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "True")


if __name__ == "__main__":
    unittest.main()
