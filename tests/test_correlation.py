from dataclasses import asdict
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import requests

from openprodkt_governance import (
    GovernanceClient, PrincipalContext, InvalidAuthorizationInputError,
    EvaluationOutcomeError, OperationOutcomeRejectedError,
)


FIXTURE = Path(__file__).resolve().parents[2] / "testdata" / "phase2-correlation.json"
if not FIXTURE.exists():
    FIXTURE = Path(__file__).resolve().parents[1] / "testdata" / "phase2-correlation.json"
VECTORS = json.loads(FIXTURE.read_text())
TRACE = "00-4bf92f3577b34da6a3ce929d0e0e4736-1111111111111111-01"
PRINCIPAL = PrincipalContext("explicit-principal")
BASE = {"version": "v1", "asset": {"key": "app.svc.prod"}, "operation_id": "op-1", "transport": {"kind": "http"}}
OUTCOME = {"operation_id": "op-1", "status": "succeeded", "completed_at": "2026-11-08T12:00:00Z"}


def response(status=200, body=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(body if body is not None else {"decision": "allow", "operation_id": "op-1"}).encode()
    result.headers["traceparent"] = TRACE
    return result


class Phase2CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.client = GovernanceClient("https://pdp.example", "must-not-fallback")
        self.assertEqual(VECTORS["profile"], "opk.phase2-correlation/1")

    @patch("openprodkt_governance.client.requests.post")
    def test_trace_vectors_and_request_capture(self, post):
        post.return_value = response()
        for vector in VECTORS["traceparent"]:
            with self.subTest(vector["name"]):
                trace = ",".join(vector["headers"])
                for proxy in (False, True):
                    if proxy:
                        result = self.client.evaluate_proxy(BASE, principal_context=PRINCIPAL, traceparent=trace)
                    else:
                        result = self.client.authorize(operation_id="op-1", asset_key="app.svc.prod", principal_context=PRINCIPAL, traceparent=trace)
                    self.assertEqual(result.traceparent, TRACE)
                    self.assertNotIn("traceparent", asdict(result))
                    url = post.call_args.args[0]
                    self.assertTrue(url.endswith("/v1/proxy/evaluate" if proxy else "/v1/evaluate"))
                    kwargs = post.call_args.kwargs
                    self.assertEqual(kwargs["headers"]["Authorization"], "Bearer explicit-principal")
                    self.assertEqual(kwargs["headers"].get("traceparent"), trace if vector["valid"] else None)
                    encoded = json.dumps(kwargs["json"]).lower()
                    for forbidden in ("traceparent", "authorization", "arguments", "execution_id", "attempt", "upstream_request_id", "explicit-principal"):
                        self.assertNotIn(forbidden, encoded)
        self.assertEqual(post.call_count, len(VECTORS["traceparent"]) * 2)

    @patch("openprodkt_governance.client.requests.post")
    def test_outcome_vectors(self, post):
        post.return_value = response(body={"operation_id": "op-1", "status": "succeeded", "recorded": True})
        for vector in VECTORS["outcome_fields"]:
            with self.subTest(vector["name"]):
                post.reset_mock()
                request = {**OUTCOME, **json.loads(vector["fields_json"])}
                if vector["valid"]:
                    self.client.report_operation_outcome(request, principal_context=PRINCIPAL)
                    post.assert_called_once()
                else:
                    with self.assertRaises(InvalidAuthorizationInputError):
                        self.client.report_operation_outcome(request, principal_context=PRINCIPAL)
                    post.assert_not_called()

    @patch("openprodkt_governance.client.requests.post")
    def test_optional_fields_and_identical_report_retries(self, post):
        for vector in VECTORS["sdk_requests"]:
            with self.subTest(vector["name"]):
                post.reset_mock()
                post.side_effect = [response(body={"operation_id": "op-1", "status": "succeeded", "recorded": recorded}) for recorded in (True, False)]
                request = {**OUTCOME, **vector["outcome_fields"]}
                first = self.client.report_operation_outcome(request, principal_context=PRINCIPAL)
                second = self.client.report_operation_outcome(request, principal_context=PRINCIPAL)
                self.assertTrue(first["recorded"])
                self.assertFalse(second["recorded"])
                self.assertEqual(post.call_count, 2)
                self.assertEqual(post.call_args_list[0], post.call_args_list[1])
                kwargs = post.call_args.kwargs
                self.assertEqual(post.call_args.args[0], "https://pdp.example/v1/proxy/outcomes")
                self.assertEqual(kwargs["json"], request)
                self.assertEqual(kwargs["headers"]["Authorization"], "Bearer explicit-principal")
                for forbidden in ("execution", "authorization", "arguments", "traceparent"):
                    self.assertNotIn(forbidden, kwargs["json"])

    @patch("openprodkt_governance.client.requests.post")
    def test_no_principal_fallback_or_raw_arguments(self, post):
        for principal in (None, PrincipalContext(""), PrincipalContext("\r\n")):
            with self.assertRaises(InvalidAuthorizationInputError):
                self.client.evaluate_proxy(BASE, principal_context=principal)
            with self.assertRaises(InvalidAuthorizationInputError):
                self.client.report_operation_outcome(OUTCOME, principal_context=principal)
        for vector in VECTORS["sdk_forbidden_transports"]:
            with self.subTest(vector["name"]):
                with self.assertRaises(InvalidAuthorizationInputError):
                    self.client.evaluate_proxy({**BASE, "transport": vector["transport"]}, principal_context=PRINCIPAL)
                with self.assertRaises(InvalidAuthorizationInputError):
                    self.client.authorize(operation_id="op-1", asset_key="app.svc.prod", transport=vector["transport"])
        post.assert_not_called()

    @patch("openprodkt_governance.client.requests.post")
    def test_response_trace_on_evaluation_errors(self, post):
        for status in (202, 403, 409, 503):
            body = {"decision": "deny", "code": "test"}
            if status == 202:
                body = {"decision": "approval_required", "approvalId": "approval", "payload_hash": "sha256:" + "a" * 64, "approval_expires_at": "2026-11-09T12:00:00Z"}
            post.return_value = response(status, body)
            with self.assertRaises(EvaluationOutcomeError) as raised:
                self.client.evaluate_proxy(BASE, principal_context=PRINCIPAL)
            self.assertEqual(raised.exception.result.traceparent, TRACE)

    @patch("openprodkt_governance.client.requests.post")
    def test_rejection_classification_and_no_automatic_retry(self, post):
        for status in (400, 401, 403, 404, 409, 408, 429, 500, 503):
            post.reset_mock()
            post.return_value = response(status, {})
            with self.assertRaises(requests.HTTPError) as raised:
                self.client.report_operation_outcome(OUTCOME, principal_context=PRINCIPAL)
            self.assertEqual(isinstance(raised.exception, OperationOutcomeRejectedError), 400 <= status < 500 and status not in (408, 429))
            self.assertEqual(raised.exception.response.status_code, status)
            post.assert_called_once()

    @patch("openprodkt_governance.client.requests.post")
    def test_approval_wait_preserves_explicit_trace(self, post):
        post.side_effect = [response(202, {"decision": "approval_required", "approvalId": "approval", "payload_hash": "sha256:" + "a" * 64, "approval_expires_at": "2026-11-09T12:00:00Z"}), response(body={"decision": "allow", "approvalStatus": "consumed"})]
        with patch.object(self.client, "wait_for_approval", return_value={"status": "approved"}):
            self.client.authorize(operation_id="op-1", asset_key="app.svc.prod", traceparent=TRACE, wait_for_approval_seconds=1)
        self.assertEqual(post.call_count, 2)
        for call in post.call_args_list:
            self.assertEqual(call.kwargs["headers"]["traceparent"], TRACE)
            self.assertNotIn("execution_id", call.kwargs["json"])
