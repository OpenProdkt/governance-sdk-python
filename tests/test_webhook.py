from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from openprodkt_governance.webhook import (
    MAX_WEBHOOK_BODY_BYTES,
    WebhookVerificationError,
    dispatch_approval_webhook,
    verify_approval_webhook,
)


class ApprovalWebhookTests(unittest.TestCase):
    secret = "whsec_test"
    timestamp = "2026-10-04T12:00:00Z"

    def test_shared_webhook_conformance_vector(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "pep-conformance.json"
        vector = json.loads(fixture_path.read_text(encoding="utf-8"))["webhook"]
        body = vector["raw_body"].encode("utf-8")
        headers = {
            "X-OpenProdkt-Event-Id": vector["event_id"],
            "X-OpenProdkt-Timestamp": vector["timestamp"],
            "X-OpenProdkt-Signature": vector["signature"],
        }
        now = datetime.fromisoformat(vector["timestamp"].replace("Z", "+00:00"))
        event = verify_approval_webhook(body, headers, vector["secret"], now=now)
        self.assertEqual(event.event_id, vector["event_id"])
        self.assertEqual(event.approval_id, "apr_vector_1")
        rotated_event = verify_approval_webhook(body, headers, ["pep-conformance-rotated", vector["secret"]], now=now)
        self.assertEqual(rotated_event.event_id, vector["event_id"])

    def signed(self, event_type: str = "approval.approved", *, event_id: str = "obx_1") -> tuple[bytes, dict[str, str]]:
        body = json.dumps({
            "eventId": event_id,
            "eventType": event_type,
            "organizationId": "org_1",
            "aggregateId": "apr_1",
            "data": {"approvalId": "apr_1", "operation_id": "refund-1", "status": event_type.removeprefix("approval.")},
        }, separators=(",", ":")).encode()
        signature = hmac.new(self.secret.encode(), self.timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        return body, {
            "X-OpenProdkt-Event-Id": event_id,
            "X-OpenProdkt-Timestamp": self.timestamp,
            "X-OpenProdkt-Signature": f"v1=sha256={signature}",
        }

    def test_verifies_raw_body_and_parses_approval_event(self) -> None:
        body, headers = self.signed()
        event = verify_approval_webhook(
            body, headers, self.secret,
            now=datetime(2026, 10, 4, 12, tzinfo=timezone.utc),
        )
        self.assertEqual(event.event_id, "obx_1")
        self.assertEqual(event.event_type, "approval.approved")
        self.assertEqual(event.approval_id, "apr_1")
        self.assertEqual(event.data["operation_id"], "refund-1")

    def test_accepts_each_approval_lifecycle_event(self) -> None:
        for event_type in ("approval.pending", "approval.approved", "approval.rejected", "approval.expired", "approval.revoked"):
            with self.subTest(event_type=event_type):
                body, headers = self.signed(event_type)
                event = verify_approval_webhook(body, headers, self.secret, now=datetime(2026, 10, 4, 12, tzinfo=timezone.utc))
                self.assertEqual(event.event_type, event_type)

    def test_rejects_bad_signature_secret_tampering_and_header_mismatch(self) -> None:
        body, headers = self.signed()
        for invalid_secret, invalid_body, invalid_headers in (
            ("wrong", body, headers),
            (self.secret, body + b" ", headers),
            (self.secret, body, {**headers, "X-OpenProdkt-Event-Id": "obx_other"}),
        ):
            with self.subTest(secret=invalid_secret, headers=invalid_headers["X-OpenProdkt-Event-Id"]), self.assertRaises(WebhookVerificationError):
                verify_approval_webhook(invalid_body, invalid_headers, invalid_secret, now=datetime(2026, 10, 4, 12, tzinfo=timezone.utc))

    def test_body_limit_cannot_be_configured_above_hard_cap(self) -> None:
        body, headers = self.signed()
        oversized = body + b" " * (MAX_WEBHOOK_BODY_BYTES + 1)
        with self.assertRaisesRegex(WebhookVerificationError, "size limit"):
            verify_approval_webhook(
                oversized,
                headers,
                self.secret,
                now=datetime(2026, 10, 4, 12, tzinfo=timezone.utc),
                max_body_bytes=MAX_WEBHOOK_BODY_BYTES * 2,
            )

    def test_rejects_stale_future_malformed_and_unsupported_events(self) -> None:
        body, headers = self.signed()
        with self.assertRaisesRegex(WebhookVerificationError, "replay window"):
            verify_approval_webhook(body, headers, self.secret, now=datetime(2026, 10, 4, 13, tzinfo=timezone.utc))
        with self.assertRaisesRegex(WebhookVerificationError, "replay window"):
            verify_approval_webhook(body, headers, self.secret, now=datetime(2026, 10, 4, 11, tzinfo=timezone.utc))
        with self.assertRaisesRegex(WebhookVerificationError, "signature version"):
            verify_approval_webhook(body, {**headers, "X-OpenProdkt-Signature": "v2=sha256=bad"}, self.secret, now=datetime(2026, 10, 4, 12, tzinfo=timezone.utc))
        body, headers = self.signed("decision.evaluated")
        with self.assertRaisesRegex(WebhookVerificationError, "event type"):
            verify_approval_webhook(body, headers, self.secret, now=datetime(2026, 10, 4, 12, tzinfo=timezone.utc))

    def test_dispatch_callback_owns_deduplication(self) -> None:
        body, headers = self.signed()
        seen: set[str] = set()

        def dispatch(event):
            if event.event_id in seen:
                return False
            seen.add(event.event_id)
            return True

        options = {"now": datetime(2026, 10, 4, 12, tzinfo=timezone.utc)}
        first = dispatch_approval_webhook(body, headers, self.secret, dispatch, **options)
        duplicate = dispatch_approval_webhook(body, headers, self.secret, dispatch, **options)
        self.assertFalse(first.duplicate)
        self.assertTrue(duplicate.duplicate)
        self.assertEqual(first.event.event_id, "obx_1")


if __name__ == "__main__":
    unittest.main()