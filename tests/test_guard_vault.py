import json
import unittest
from unittest.mock import patch

import requests

from openprodkt_governance import GovernanceClient, InvalidAuthorizationInputError, PrincipalContext, VaultWriteError
from openprodkt_governance.vault import (
    InvalidWrappedKeyError,
    KeyBackendError,
    KeyDestroyedError,
    KeyNotFoundError,
    ObjectWriteError,
    Pointer,
    RecordTooLargeError,
)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

CANARY = "canary-4f1e9d-plaintext"
DIGEST = "sha256:" + "a" * 64


def _response(status, body):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(body).encode()
    return result


class StubWriter:
    """Records every write and can fail by kind. It never encrypts."""

    def __init__(self, events, fail=None):
        self.events = events
        self.fail = fail or {}
        self.writes = []

    def write(self, kind, organization_id, operation_id, n, record):
        self.events.append("write:" + kind)
        self.writes.append((kind, organization_id, operation_id, n, record))
        if kind in self.fail:
            raise self.fail[kind]
        return Pointer(object_key="vault/o/2026/11/%s/%s-%d.opkv" % (operation_id, kind, n), version_id="v1",
                       key_ref="alias/k", ciphertext_digest=DIGEST, kind=kind)


class Harness:
    def __init__(self, test):
        self.test = test
        self.events = []
        self.bodies = []
        self.patcher = patch("openprodkt_governance.client.requests.post")
        self.post = self.patcher.start()
        test.addCleanup(self.patcher.stop)
        self.post.side_effect = self._send
        self.client = GovernanceClient("https://pdp.example", "must-not-fallback")
        self.principal = PrincipalContext("explicit")

    def _send(self, url, **kwargs):
        body = kwargs["json"] if "json" in kwargs else json.loads(kwargs["data"])
        self.bodies.append((url, dict(body)))
        if url.endswith("/evaluate"):
            self.events.append("post:evaluate")
            return _response(200, {"decision": "allow", "operation_id": body["operation_id"], "decisionId": "d1"})
        self.events.append("post:outcomes")
        return _response(200, {"operation_id": body["operation_id"], "status": "succeeded", "recorded": True})

    def request(self):
        return {"version": "v1", "asset": {"key": "app.svc.prod"}, "operation_id": "op-1", "transport": {"kind": "http"}}

    def evaluate_body(self):
        return next(body for url, body in self.bodies if url.endswith("/evaluate"))

    def outcome_body(self):
        return next(body for url, body in self.bodies if url.endswith("/outcomes"))

    def guard(self, writer, callback=None, **vault):
        def run():
            self.events.append("callback")
            return {"ok": True}

        options = {"writer": writer, "organization_id": "org_1", "input": {"tool": "refund"}}
        options.update(vault)
        return self.client.guard(self.request(), callback or run, principal_context=self.principal, vault=options)


class WireTests(unittest.TestCase):
    def test_members_are_omitted_without_a_vault(self):
        h = Harness(self)
        h.client.guard(h.request(), lambda: 1, principal_context=h.principal)
        for _, body in h.bodies:
            self.assertNotIn("vault_ref", body)
            self.assertNotIn("vault_gap", body)

    def test_invalid_members_are_refused_before_any_request(self):
        h = Harness(self)
        ref = {"kind": "input", "object_key": "k", "version_id": "v", "key_ref": "alias/k", "ciphertext_digest": DIGEST}
        bad_evaluate = [
            {"vault_ref": ref, "vault_gap": {"reason": "write_failed"}},
            {"vault_ref": dict(ref, kind="output")},
            {"vault_ref": dict(ref, ciphertext_digest="sha256:ABC")},
            {"vault_ref": dict(ref, extra="x")},
            {"vault_ref": dict(ref, key_ref="k" * 257)},
            {"vault_gap": {"reason": "because"}},
            {"vault_gap": {"reason": "write_failed", "detail": "x"}},
        ]
        for members in bad_evaluate:
            with self.subTest(members=sorted(members)):
                with self.assertRaises(InvalidAuthorizationInputError):
                    h.client.evaluate_proxy(dict(h.request(), **members), principal_context=h.principal)
        report = {"operation_id": "op-1", "status": "succeeded", "completed_at": "2026-11-19T00:00:00Z"}
        for members in (
            {"vault_ref": ref},
            {"vault_ref": dict(ref, kind="output"), "vault_gap": {"reason": "write_failed"}},
        ):
            with self.subTest(report=sorted(members)):
                with self.assertRaises(InvalidAuthorizationInputError):
                    h.client.report_operation_outcome(dict(report, **members), principal_context=h.principal)
        self.assertEqual(h.post.call_count, 0)

    def test_valid_members_are_sent_as_given(self):
        h = Harness(self)
        ref = {"kind": "input", "object_key": "k", "version_id": "v", "key_ref": "alias/k", "ciphertext_digest": DIGEST}
        h.client.evaluate_proxy(dict(h.request(), vault_ref=ref), principal_context=h.principal)
        self.assertEqual(h.evaluate_body()["vault_ref"], ref)
        h.client.report_operation_outcome(
            {"operation_id": "op-1", "status": "succeeded", "completed_at": "2026-11-19T00:00:00Z",
             "vault_gap": {"reason": "storage_unavailable"}}, principal_context=h.principal)
        self.assertEqual(h.outcome_body()["vault_gap"], {"reason": "storage_unavailable"})


class GuardVaultTests(unittest.TestCase):
    def test_records_are_written_around_the_call_in_order(self):
        h = Harness(self)
        writer = StubWriter(h.events)
        result = h.guard(writer, output=lambda value: {"result": value})
        self.assertEqual(h.events, ["write:input", "post:evaluate", "callback", "write:output", "post:outcomes"])
        self.assertEqual(result.value, {"ok": True})
        self.assertEqual(h.evaluate_body()["vault_ref"]["kind"], "input")
        self.assertEqual(h.outcome_body()["vault_ref"]["kind"], "output")
        self.assertNotIn("vault_gap", h.evaluate_body())
        self.assertNotIn("vault_gap", h.outcome_body())
        self.assertEqual(result.report["vault_ref"]["kind"], "output")
        kinds = [(w[0], w[1], w[2]) for w in writer.writes]
        self.assertEqual(kinds, [("input", "org_1", "op-1"), ("output", "org_1", "op-1")])
        self.assertTrue(all(isinstance(w[3], int) and w[3] > 0 for w in writer.writes))

    def test_input_write_failure_fails_closed(self):
        reasons = {
            "key backend": (KeyBackendError(), "key_service_unavailable"),
            "key destroyed": (KeyDestroyedError(), "key_service_unavailable"),
            "key not found": (KeyNotFoundError(), "key_service_unavailable"),
            "wrapped key": (InvalidWrappedKeyError(), "key_service_unavailable"),
            "object write": (ObjectWriteError(), "storage_unavailable"),
            "too large": (RecordTooLargeError(), "record_too_large"),
            "other": (RuntimeError("secret-detail"), "write_failed"),
        }
        for name, (error, reason) in reasons.items():
            with self.subTest(name):
                h = Harness(self)
                called = []
                with self.assertRaises(VaultWriteError) as raised:
                    h.guard(StubWriter(h.events, {"input": error}), callback=lambda: called.append(1))
                self.assertEqual(raised.exception.reason, reason)
                self.assertNotIn("secret-detail", str(raised.exception))
                self.assertEqual(called, [])
                self.assertEqual(h.post.call_count, 0)

    def test_digest_only_mode_continues_and_reports_the_gap(self):
        h = Harness(self)
        result = h.guard(StubWriter(h.events, {"input": ObjectWriteError()}), continue_without_vault=True)
        self.assertEqual(result.value, {"ok": True})
        self.assertEqual(h.evaluate_body()["vault_gap"], {"reason": "storage_unavailable"})
        self.assertNotIn("vault_ref", h.evaluate_body())

    def test_output_write_failure_keeps_the_result_and_reports_a_gap(self):
        for continue_without_vault in (False, True):
            with self.subTest(continue_without_vault=continue_without_vault):
                h = Harness(self)
                calls = []

                def callback():
                    calls.append(1)
                    return "done"

                result = h.guard(StubWriter(h.events, {"output": KeyBackendError()}), callback=callback,
                                 output=lambda value: {"v": value}, continue_without_vault=continue_without_vault)
                self.assertEqual(result.value, "done")
                self.assertEqual(calls, [1])
                self.assertEqual(h.outcome_body()["status"], "succeeded")
                self.assertEqual(h.outcome_body()["vault_gap"], {"reason": "key_service_unavailable"})
                self.assertNotIn("vault_ref", h.outcome_body())

    def test_output_function_can_skip_and_a_raising_one_only_reports_a_gap(self):
        h = Harness(self)
        writer = StubWriter(h.events)
        h.guard(writer, output=lambda value: None)
        self.assertEqual([w[0] for w in writer.writes], ["input"])
        self.assertNotIn("vault_gap", h.outcome_body())
        self.assertNotIn("vault_ref", h.outcome_body())

        def explode(value):
            raise RuntimeError("secret-detail")

        h = Harness(self)
        result = h.guard(StubWriter(h.events), output=explode)
        self.assertEqual(result.value, {"ok": True})
        self.assertEqual(h.outcome_body()["vault_gap"], {"reason": "write_failed"})

    def test_a_failing_callback_is_unknown_and_writes_no_output(self):
        h = Harness(self)
        writer = StubWriter(h.events)
        marker = RuntimeError("callback failed")

        def callback():
            raise marker

        with self.assertRaises(RuntimeError) as raised:
            h.guard(writer, callback=callback, output=lambda value: {"v": value})
        self.assertIs(raised.exception, marker)
        self.assertEqual([w[0] for w in writer.writes], ["input"])
        self.assertEqual(h.outcome_body()["status"], "unknown")
        self.assertNotIn("vault_ref", h.outcome_body())

    def test_bad_options_are_refused_before_any_write(self):
        h = Harness(self)
        writer = StubWriter(h.events)
        for name, change in {
            "no organization": {"organization_id": ""},
            "no input": {"input": None},
            "bad writer": {"writer": object()},
            "bad output": {"output": "not callable"},
            "bad flag": {"continue_without_vault": "yes"},
        }.items():
            with self.subTest(name):
                with self.assertRaises(InvalidAuthorizationInputError):
                    options = {"writer": writer, "organization_id": "org_1", "input": {"a": 1}}
                    options.update(change)
                    h.client.guard(h.request(), lambda: 1, principal_context=h.principal, vault=options)
        request = dict(h.request(), vault_gap={"reason": "write_failed"})
        with self.assertRaises(InvalidAuthorizationInputError):
            h.client.guard(request, lambda: 1, principal_context=h.principal,
                           vault={"writer": writer, "organization_id": "org_1", "input": {"a": 1}})
        self.assertEqual(writer.writes, [])
        self.assertEqual(h.post.call_count, 0)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed")
class CanaryTests(unittest.TestCase):
    def test_plaintext_only_reaches_the_encrypted_object(self):
        from datetime import timedelta

        from openprodkt_governance.vault import (
            MemoryBackend,
            MemoryObjectWriter,
            VaultWriter,
            VaultWriterConfig,
            open_envelope,
        )

        h = Harness(self)
        backend, objects = MemoryBackend(), MemoryObjectWriter()
        writer = VaultWriter(VaultWriterConfig(backend=backend, objects=objects, key_ref="alias/k",
                                               retention_mode="COMPLIANCE", retention_period=timedelta(hours=1)))
        result = h.client.guard(
            h.request(), lambda: {"secret": CANARY}, principal_context=h.principal,
            vault={"writer": writer, "organization_id": "org_1", "input": {"argument": CANARY},
                   "output": lambda value: {"result": value["secret"]}})
        self.assertEqual(result.value, {"secret": CANARY})
        for _, body in h.bodies:
            self.assertNotIn(CANARY, json.dumps(body))
        self.assertEqual(len(objects.keys()), 2)
        for key in objects.keys():
            stored = objects.get(key).body
            self.assertNotIn(CANARY.encode(), stored)
            _, plaintext = open_envelope(backend, stored)
            self.assertIn(CANARY.encode(), plaintext)

        failing = VaultWriter(VaultWriterConfig(backend=backend, objects=MemoryObjectWriter(), key_ref="alias/k",
                                                retention_mode="COMPLIANCE", retention_period=timedelta(hours=1)))
        with self.assertRaises(VaultWriteError) as raised:
            h.client.guard(h.request(), lambda: 1, principal_context=h.principal,
                           vault={"writer": failing, "organization_id": "org_1", "input": {"argument": 1.5}})
        self.assertEqual(raised.exception.reason, "write_failed")
        self.assertNotIn(CANARY, repr(raised.exception))


if __name__ == "__main__":
    unittest.main()
