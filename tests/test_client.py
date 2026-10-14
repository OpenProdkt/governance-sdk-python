import unittest
import json
import threading
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from openprodkt_governance.asset_identity import AssetIdentity, generate_asset_key
from openprodkt_governance.client import ApprovalStatusAccessError, ApprovalTerminalError, AssetIdentityConflictError, AuditQuery, ClientConfigurationError, DecisionQuery, EvaluationOutcomeError, GovernanceClient, InvalidAuthorizationInputError, PendingApproval, PrincipalContext


class AssetKeyConformanceTests(unittest.TestCase):
    def test_shared_conformance_vectors(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "asset-key-conformance.json"
        cases = json.loads(fixture_path.read_text(encoding="utf-8"))
        for test_case in cases:
            with self.subTest(test_case["name"]):
                identity = test_case["identity"]
                if "error" in test_case:
                    with self.assertRaisesRegex(ValueError, test_case["error"]):
                        generate_asset_key(
                            identity.get("application", ""),
                            identity.get("service", ""),
                            identity.get("environment", ""),
                        )
                else:
                    self.assertEqual(
                        generate_asset_key(
                            identity["application"], identity["service"], identity["environment"]
                        ),
                        test_case["asset_key"],
                    )


class GovernanceClientTests(unittest.TestCase):
    @patch("openprodkt_governance.client.requests.get")
    def test_approval_status_scope_denial_is_typed(self, mock_get: Mock) -> None:
        response = Mock(status_code=403, content=b'{"code":"insufficient_scope"}')
        response.json.return_value = {"code": "insufficient_scope", "error": "api key scope not permitted"}
        mock_get.return_value = response
        client = GovernanceClient("https://api.example.com", "opk_decision_only")
        with self.assertRaises(ApprovalStatusAccessError) as raised:
            client.get_approval_status("apr_1")
        self.assertEqual(raised.exception.outcome, "approval_status_scope_required")

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_classifies_defined_http_outcomes(self, mock_post: Mock) -> None:
        for status_code, outcome in ((403, "authorization_denied"), (404, "approval_not_found"), (409, "operation_conflict"), (402, "quota_exceeded"), (400, "invalid_request"), (503, "pdp_unavailable")):
            with self.subTest(status_code=status_code):
                response = Mock(status_code=status_code)
                response.json.return_value = {"decision": "deny", "reason": "test_outcome"}
                mock_post.return_value = response
                client = GovernanceClient("https://api.example.com", "opk_live_test")
                with self.assertRaises(EvaluationOutcomeError) as raised:
                    client.authorize(asset_id="ast_1", operation_id="refund-status")
                self.assertEqual(raised.exception.status_code, status_code)
                self.assertEqual(raised.exception.outcome, outcome)
                self.assertEqual(raised.exception.result.reason, "test_outcome")
                response.raise_for_status.assert_not_called()

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_rejects_unsupported_evaluation_status(self, mock_post: Mock) -> None:
        mock_post.return_value = Mock(status_code=418)
        client = GovernanceClient("https://api.example.com", "opk_live_test")
        with self.assertRaisesRegex(requests.RequestException, "unexpected /v1/evaluate HTTP status 418"):
            client.authorize(asset_id="ast_1", operation_id="refund-status")

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_preserves_terminal_and_collision_outcomes(self, mock_post: Mock) -> None:
        client = GovernanceClient("https://api.example.com", "opk_live_test")
        for reason in ("approval_rejected", "approval_expired", "approval_revoked", "approval_consumed"):
            response = Mock(status_code=403)
            response.json.return_value = {"decision": "deny", "reason": reason}
            mock_post.return_value = response
            with self.subTest(reason=reason), self.assertRaises(ApprovalTerminalError) as raised:
                client.authorize(asset_id="ast_1", operation_id="refund-terminal")
            self.assertEqual(raised.exception.outcome, reason)

        response = Mock(status_code=409)
        response.json.return_value = {"code": "asset_identity_conflict", "error": "identity collision"}
        mock_post.return_value = response
        with self.assertRaises(AssetIdentityConflictError) as raised:
            client.authorize(asset_id="ast_1", operation_id="refund-collision")
        self.assertEqual(raised.exception.outcome, "asset_identity_conflict")

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_sends_approval_retry_tuple(self, mock_post: Mock) -> None:
        response = Mock(status_code=200)
        response.json.return_value = {
            "decision": "allow",
            "approvalStatus": "consumed",
            "payload_hash": "sha256:" + "a" * 64,
            "grant_expires_at": "2026-10-03T12:00:00Z",
        }
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        client = GovernanceClient("https://api.example.com", "opk_live_test")
        result = client.authorize(
            asset_id="ast_1",
            operation_id="refund-1",
            approval_id="apr_1",
            payload_hash="sha256:" + "a" * 64,
        )
        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(payload["approval_id"], "apr_1")
        self.assertEqual(payload["payload_hash"], "sha256:" + "a" * 64)
        self.assertEqual(result.approval_status, "consumed")
        self.assertEqual(result.grant_expires_at, "2026-10-03T12:00:00Z")

        with self.assertRaisesRegex(ValueError, "supplied together"):
            client.authorize(asset_id="ast_1", operation_id="refund-1", approval_id="apr_1")

    @patch("openprodkt_governance.client.requests.post")
    def test_concurrent_duplicate_initial_requests_stay_pending(self, mock_post: Mock) -> None:
        lock = threading.Lock()
        evaluations = 0

        def respond(*_args: object, **_kwargs: object) -> Mock:
            nonlocal evaluations
            with lock:
                evaluations += 1
            response = Mock(status_code=202)
            response.json.return_value = {
                "decision": "approval_required",
                "decisionId": "dec_pending",
                "approvalId": "apr_pending",
                "payload_hash": "sha256:" + "a" * 64,
                "approval_expires_at": "2026-10-04T12:00:00Z",
            }
            response.raise_for_status.return_value = None
            return response

        mock_post.side_effect = respond
        client = GovernanceClient("https://api.example.com", "opk_live_test")
        outcomes: list[str] = []

        def attempt() -> None:
            try:
                client.authorize(asset_id="ast_1", operation_id="refund-duplicate")
                outcomes.append("allow")
            except PendingApproval as pending:
                outcomes.append(pending.approval_id)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(outcomes, ["apr_pending"] * 16)
        self.assertEqual(evaluations, 16)

    @patch("openprodkt_governance.client.requests.post")
    def test_concurrent_approved_retries_allow_exactly_one(self, mock_post: Mock) -> None:
        lock = threading.Lock()
        redemptions = 0

        def respond(*_args: object, **_kwargs: object) -> Mock:
            nonlocal redemptions
            with lock:
                redemptions += 1
                first = redemptions == 1
            if first:
                response = Mock(status_code=200)
                response.json.return_value = {
                    "decision": "allow",
                    "approvalStatus": "consumed",
                    "payload_hash": "sha256:" + "a" * 64,
                    "grant_expires_at": "2026-10-03T12:00:00Z",
                }
                response.raise_for_status.return_value = None
                return response
            return Mock(
                status_code=403,
                json=Mock(return_value={"decision": "deny", "reason": "approval_consumed"}),
            )

        mock_post.side_effect = respond
        client = GovernanceClient("https://api.example.com", "opk_live_test")
        allowed: list[str] = []
        consumed_denials: list[str] = []
        unexpected: list[str] = []

        def attempt() -> None:
            try:
                result = client.authorize(
                    asset_id="ast_1",
                    operation_id="refund-redeem",
                    approval_id="apr_1",
                    payload_hash="sha256:" + "a" * 64,
                )
                if result.decision == "allow" and result.approval_status == "consumed":
                    allowed.append(result.decision)
                else:
                    unexpected.append(repr(result))
            except ApprovalTerminalError as terminal:
                if terminal.outcome == "approval_consumed":
                    consumed_denials.append(terminal.outcome)
                else:
                    unexpected.append(terminal.outcome)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(unexpected, [])
        self.assertEqual(len(allowed), 1)
        self.assertEqual(len(consumed_denials), 15)

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_generates_key_and_sends_identity(self, mock_post: Mock) -> None:
        response = Mock(status_code=200)
        response.json.return_value = {"decision": "allow"}
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        client = GovernanceClient("https://api.example.com", "opk_live_test")
        client.authorize(
            operation_id="refund-123",
            asset_identity=AssetIdentity("billing", "refund-api", "production"),
        )

        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(
            payload["asset"],
            {
                "key": "billing.refund-api.production",
                "application": "billing",
                "service": "refund-api",
                "environment": "production",
            },
        )

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_uses_configured_identity_when_request_omits_asset(self, mock_post: Mock) -> None:
        response = Mock(status_code=200)
        response.json.return_value = {"decision": "allow"}
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        identity = AssetIdentity("billing", "refund-api", "production")
        client = GovernanceClient("https://api.example.com", "opk_live_test", default_asset_identity=identity)
        client.authorize(operation_id="refund-default")

        self.assertEqual(mock_post.call_args.kwargs["json"]["asset"], {
            "key": "billing.refund-api.production",
            "application": "billing",
            "service": "refund-api",
            "environment": "production",
        })

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_sends_operation_id_and_asset_id(self, mock_post: Mock) -> None:
        response = Mock(status_code=202)
        response.json.return_value = {
            "version": "v1",
            "operation_id": "refund-123",
            "decision": "approval_required",
            "decisionId": "dec_test",
            "approvalId": "apr_test",
            "payload_hash": "sha256:" + "a" * 64,
            "approval_expires_at": "2026-10-04T12:00:00Z",
            "reason": "amount_threshold",
            "policyId": "pol_payment_threshold",
        }
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        client = GovernanceClient("https://api.example.com", "opk_live_test")
        with self.assertRaises(PendingApproval) as raised:
            client.authorize(
                asset_id="ast_invoice_agent",
                operation_id="refund-123",
                metadata={"environment": "production"},
            )

        self.assertEqual(raised.exception.operation_id, "refund-123")
        self.assertEqual(raised.exception.approval_id, "apr_test")
        self.assertEqual(raised.exception.payload_hash, "sha256:" + "a" * 64)
        self.assertEqual(raised.exception.asset_id, "ast_invoice_agent")
        self.assertEqual(raised.exception.status_url, "https://api.example.com/v1/approvals/apr_test")
        self.assertEqual(raised.exception.expires_at, "2026-10-04T12:00:00Z")

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer opk_live_test")
        self.assertEqual(mock_post.call_args.args[0], "https://api.example.com/v1/evaluate")
        self.assertEqual(kwargs["json"]["version"], "v1")
        self.assertEqual(kwargs["json"]["asset"]["id"], "ast_invoice_agent")
        self.assertEqual(kwargs["json"]["operation_id"], "refund-123")
        self.assertEqual(kwargs["json"]["transport"], {"kind": "http"})
        self.assertEqual(kwargs["json"]["metadata"]["environment"], "production")

    @patch("openprodkt_governance.client.requests.post")
    @patch("openprodkt_governance.client.requests.get")
    def test_authorize_and_wait_redeems_approved_approval(self, mock_get: Mock, mock_post: Mock) -> None:
        initial_response = Mock(status_code=202)
        initial_response.json.return_value = {
            "decision": "approval_required",
            "decisionId": "dec_wait",
            "approvalId": "apr_wait",
            "payload_hash": "sha256:" + "b" * 64,
            "operation_id": "refund-wait",
            "approval_expires_at": "2026-10-04T12:00:00Z",
        }
        initial_response.raise_for_status.return_value = None
        redeemed_response = Mock(status_code=200)
        redeemed_response.json.return_value = {
            "decision": "allow",
            "approvalStatus": "consumed",
            "operation_id": "refund-wait",
        }
        redeemed_response.raise_for_status.return_value = None
        mock_post.side_effect = [initial_response, redeemed_response]
        approval_response = Mock()
        approval_response.json.return_value = {"id": "apr_wait", "status": "approved"}
        approval_response.raise_for_status.return_value = None
        mock_get.return_value = approval_response

        principal_context = PrincipalContext("verified-user-token")
        client = GovernanceClient("https://api.example.com", "opk_live_test")
        result = client.authorize(
            asset_id="ast_refund",
            operation_id="refund-wait",
            metadata={"amount": 10},
            wait_for_approval_seconds=1,
            principal_context=principal_context,
        )

        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.approval_status, "consumed")
        self.assertEqual(mock_post.call_count, 2)
        for call in mock_post.call_args_list:
            self.assertEqual(call.kwargs["headers"]["Authorization"], "Bearer verified-user-token")
            self.assertNotIn("verified-user-token", json.dumps(call.kwargs["json"]))
            self.assertNotIn("principal_context", call.kwargs["json"])
        retry_payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(retry_payload["operation_id"], "refund-wait")
        self.assertEqual(retry_payload["approval_id"], "apr_wait")
        self.assertEqual(retry_payload["payload_hash"], "sha256:" + "b" * 64)
        self.assertEqual(mock_get.call_args.kwargs["headers"]["Authorization"], "Bearer verified-user-token")

    @patch("openprodkt_governance.client.requests.post")
    @patch("openprodkt_governance.client.requests.get")
    def test_authorize_wait_cancellation_preserves_pending_challenge(self, mock_get: Mock, mock_post: Mock) -> None:
        initial_response = Mock(status_code=202)
        initial_response.json.return_value = {
            "decision": "approval_required", "decisionId": "dec_wait", "approvalId": "apr_wait",
            "payload_hash": "sha256:" + "d" * 64, "approval_expires_at": "2026-10-04T12:00:00Z",
        }
        mock_post.return_value = initial_response
        approval_response = Mock(status_code=200)
        approval_response.json.return_value = {"id": "apr_wait", "status": "pending"}
        mock_get.return_value = approval_response
        cancel_event = threading.Event()
        cancel_event.set()
        client = GovernanceClient("https://api.example.com", "opk_live_test")

        with self.assertRaises(PendingApproval) as raised:
            client.authorize(
                asset_id="ast_1", operation_id="refund-cancel", wait_for_approval_seconds=5,
                cancel_event=cancel_event,
            )

        self.assertEqual(raised.exception.approval_id, "apr_wait")
        self.assertEqual(raised.exception.operation_id, "refund-cancel")
        mock_post.assert_called_once()
        mock_get.assert_called_once()

    @patch("openprodkt_governance.client.requests.post")
    @patch("openprodkt_governance.client.requests.get")
    def test_authorize_wait_timeout_preserves_pending_challenge(self, mock_get: Mock, mock_post: Mock) -> None:
        initial_response = Mock(status_code=202)
        initial_response.json.return_value = {
            "decision": "approval_required", "decisionId": "dec_timeout", "approvalId": "apr_timeout",
            "payload_hash": "sha256:" + "e" * 64, "approval_expires_at": "2026-10-04T12:00:00Z",
        }
        mock_post.return_value = initial_response
        pending_response = Mock(status_code=200)
        pending_response.json.return_value = {"id": "apr_timeout", "status": "pending"}
        mock_get.return_value = pending_response
        client = GovernanceClient("https://api.example.com", "opk_live_test")

        with self.assertRaises(PendingApproval) as raised:
            client.authorize(
                asset_id="ast_1", operation_id="refund-timeout", wait_for_approval_seconds=0.01,
                poll_interval_seconds=0.01, max_poll_interval_seconds=0.01, jitter_fraction=0,
            )

        self.assertEqual(raised.exception.approval_id, "apr_timeout")
        self.assertEqual(raised.exception.operation_id, "refund-timeout")
        mock_post.assert_called_once()

    @patch("openprodkt_governance.client.requests.post")
    @patch("openprodkt_governance.client.requests.get")
    def test_authorize_wait_propagates_scope_denial_during_polling(self, mock_get: Mock, mock_post: Mock) -> None:
        initial_response = Mock(status_code=202)
        initial_response.json.return_value = {
            "decision": "approval_required", "decisionId": "dec_scope", "approvalId": "apr_scope",
            "payload_hash": "sha256:" + "f" * 64, "approval_expires_at": "2026-10-04T12:00:00Z",
        }
        mock_post.return_value = initial_response
        pending_response = Mock(status_code=200)
        pending_response.json.return_value = {"id": "apr_scope", "status": "pending"}
        denied_response = Mock(status_code=403, content=b'{"code":"insufficient_scope"}')
        denied_response.json.return_value = {"code": "insufficient_scope", "error": "api key scope not permitted"}
        mock_get.side_effect = [pending_response, denied_response]
        client = GovernanceClient("https://api.example.com", "opk_live_test")

        with self.assertRaises(ApprovalStatusAccessError):
            client.authorize(
                asset_id="ast_1", operation_id="refund-scope", wait_for_approval_seconds=5,
                poll_interval_seconds=0.01, max_poll_interval_seconds=0.01, jitter_fraction=0,
            )

        self.assertEqual(mock_get.call_count, 2)
        mock_post.assert_called_once()

    @patch("openprodkt_governance.client.requests.post")
    @patch("openprodkt_governance.client.requests.get")
    def test_authorize_wait_terminal_poll_outcomes_never_redeem(self, mock_get: Mock, mock_post: Mock) -> None:
        for status, approval_body, outcome in (
            ("rejected", {"id": "apr_terminal", "status": "rejected"}, "approval_rejected"),
            ("expired", {"id": "apr_terminal", "status": "expired"}, "approval_expired"),
            ("consumed", {"id": "apr_terminal", "status": "consumed"}, "approval_consumed"),
            ("revoked", {"id": "apr_terminal", "status": "approved", "revokedAt": "2026-10-04T11:00:00Z"}, "approval_revoked"),
        ):
            with self.subTest(status=status):
                mock_post.reset_mock()
                mock_get.reset_mock()
                initial_response = Mock(status_code=202)
                initial_response.json.return_value = {
                    "decision": "approval_required", "decisionId": "dec_terminal", "approvalId": "apr_terminal",
                    "payload_hash": "sha256:" + "f" * 64, "approval_expires_at": "2026-10-04T12:00:00Z",
                }
                mock_post.return_value = initial_response
                approval_response = Mock(status_code=200)
                approval_response.json.return_value = approval_body
                mock_get.return_value = approval_response
                client = GovernanceClient("https://api.example.com", "opk_live_test")

                with self.assertRaises(ApprovalTerminalError) as raised:
                    client.authorize(
                        asset_id="ast_terminal", operation_id=f"refund-terminal-{status}",
                        wait_for_approval_seconds=1, poll_interval_seconds=0.01,
                        max_poll_interval_seconds=0.01, jitter_fraction=0,
                    )

                self.assertEqual(raised.exception.outcome, outcome)
                mock_post.assert_called_once()

    @patch("openprodkt_governance.client.requests.post")
    @patch("openprodkt_governance.client.requests.get")
    def test_authorize_wait_redemption_failure_is_not_reevaluated(self, mock_get: Mock, mock_post: Mock) -> None:
        initial_response = Mock(status_code=202)
        initial_response.json.return_value = {
            "decision": "approval_required", "decisionId": "dec_lost", "approvalId": "apr_lost",
            "payload_hash": "sha256:" + "a" * 64, "approval_expires_at": "2026-10-04T12:00:00Z",
        }
        unavailable_response = Mock(status_code=503)
        unavailable_response.json.return_value = {"reason": "pdp_unavailable"}
        mock_post.side_effect = [initial_response, unavailable_response]
        approval_response = Mock(status_code=200)
        approval_response.json.return_value = {"id": "apr_lost", "status": "approved"}
        mock_get.return_value = approval_response
        client = GovernanceClient("https://api.example.com", "opk_live_test")

        with self.assertRaises(EvaluationOutcomeError) as raised:
            client.authorize(
                asset_id="ast_lost", operation_id="refund-lost", wait_for_approval_seconds=1,
                poll_interval_seconds=0.01, max_poll_interval_seconds=0.01, jitter_fraction=0,
            )

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.outcome, "pdp_unavailable")
        self.assertEqual(mock_post.call_count, 2)

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_rejects_unsafe_principal_context_before_request(self, mock_post: Mock) -> None:
        client = GovernanceClient("https://api.example.com", "opk_live_test")
        with self.assertRaisesRegex(ValueError, "header-safe"):
            client.authorize(
                asset_id="ast_1", operation_id="refund-1",
                principal_context=PrincipalContext("user-token\r\ninjected: true"),
            )
        mock_post.assert_not_called()

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_rejects_missing_identity_or_operation_before_request(self, mock_post: Mock) -> None:
        client = GovernanceClient("https://api.example.com", "opk_live_test")

        with self.assertRaises(ClientConfigurationError):
            client.authorize(operation_id="refund-123")
        with self.assertRaisesRegex(ValueError, "operation_id is required"):
            client.authorize(asset_key="payments.refund-api", operation_id=" ")

        mock_post.assert_not_called()

    @patch("openprodkt_governance.client.requests.post")
    def test_authorize_rejects_unsupported_metadata_before_request(self, mock_post: Mock) -> None:
        client = GovernanceClient("https://api.example.com", "opk_live_test")
        for metadata in ({"value": object()}, {"value": "x" * (8 * 1024)}):
            with self.subTest(metadata_type=type(metadata["value"]).__name__), self.assertRaises(InvalidAuthorizationInputError):
                client.authorize(asset_id="ast_1", operation_id="refund-unsupported", metadata=metadata)
        mock_post.assert_not_called()

    @patch("openprodkt_governance.client.requests.post")
    def test_request_code(self, mock_post: Mock) -> None:
        response = Mock()
        response.json.return_value = {"sent": True}
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        client = GovernanceClient("https://api.example.com", "opk_live_test")
        result = client.request_code("ops@example.com")

        self.assertEqual(result["sent"], True)

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertNotIn("headers", kwargs)
        self.assertEqual(kwargs["json"]["email"], "ops@example.com")

    @patch("openprodkt_governance.client.requests.post")
    def test_ingest_asset_discovery_uses_stable_envelope(self, mock_post: Mock) -> None:
        response = Mock()
        response.json.return_value = {"discoveryId": "dsc_test", "status": "accepted"}
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        result = GovernanceClient("https://api.example.com", "opk_live_test").ingest_asset_discovery({
            "discovery_id": "dsc_test",
            "asset": {"key": "billing.refund", "kind": "rest_api", "environment": "production"},
            "metadata": {"operation": "refund"},
            "source": {"kind": "detection_point", "id": "dp_1"},
            "evidence": {"kind": "http_request"},
            "observed_at": "2026-09-08T12:00:00Z",
        })

        self.assertEqual(result["status"], "accepted")
        self.assertEqual(mock_post.call_args.kwargs["json"]["discovery_id"], "dsc_test")

    @patch("openprodkt_governance.client.requests.post")
    def test_bootstrap_uses_internal_admin_token(self, mock_post: Mock) -> None:
        response = Mock()
        response.json.return_value = {"organizationId": "org_test"}
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        client = GovernanceClient("https://api.example.com", "internal-admin-token")
        result = client.bootstrap("Sandbox Test", "owner@example.com", "free", "saas")

        self.assertEqual(result["organizationId"], "org_test")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer internal-admin-token")

    @patch("openprodkt_governance.client.requests.post")
    def test_approval_comment(self, mock_post: Mock) -> None:
        response = Mock()
        response.json.return_value = {"id": "apr_test", "status": "approved", "comment": "ship it"}
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        client = GovernanceClient("https://api.example.com", "opk_live_test")
        result = client.approve_approval("apr_test", "ship it")

        self.assertEqual(result["comment"], "ship it")
        self.assertEqual(mock_post.call_args.kwargs["json"], {"comment": "ship it"})

    @patch("openprodkt_governance.client.requests.get")
    def test_audit_query(self, mock_get: Mock) -> None:
        response = Mock()
        response.json.return_value = {"events": [], "total": 0, "limit": 10, "offset": 5}
        response.raise_for_status.return_value = None
        mock_get.return_value = response

        client = GovernanceClient("https://api.example.com", "opk_live_test")
        result = client.list_audit_events(AuditQuery(limit=10, offset=5, event_type="policy", outcome="created"))

        self.assertEqual(result["limit"], 10)
        self.assertEqual(mock_get.call_args.kwargs["params"], {
            "limit": 10,
            "offset": 5,
            "eventType": "policy",
            "outcome": "created",
        })

    @patch("openprodkt_governance.client.requests.get")
    def test_decision_query(self, mock_get: Mock) -> None:
        response = Mock()
        response.json.return_value = {"items": [], "total": 0, "limit": 10, "offset": 5}
        response.raise_for_status.return_value = None
        mock_get.return_value = response

        client = GovernanceClient("https://api.example.com", "opk_live_test")
        result = client.list_decision_explorer(DecisionQuery(limit=10, offset=5, status="failed", asset_id="ast_test"))

        self.assertEqual(result["offset"], 5)
        self.assertEqual(mock_get.call_args.kwargs["params"], {
            "limit": 10,
            "offset": 5,
            "status": "failed",
            "assetId": "ast_test",
        })


if __name__ == "__main__":
    unittest.main()
