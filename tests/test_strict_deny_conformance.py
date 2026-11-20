from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from openprodkt_governance.asset_identity import AssetIdentity
from openprodkt_governance.client import (
    AuthorizationDeniedError,
    EvaluationOutcomeError,
    GovernanceClient,
    PrincipalContext,
)

try:
    import grpc
    from openprodkt_governance.grpc_adapter import (
        GRPCAdapterOptions,
        GRPCAssetReference,
        UnaryUnaryClientInterceptor,
    )

    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

try:
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from openprodkt_governance.fastapi_adapter import (
        HTTPAssetReference,
        create_authorization_dependency,
        install_fastapi_exception_handlers,
    )

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


def _cases() -> list[dict]:
    path = Path(__file__).resolve().parents[2] / "testdata" / "strict-deny-conformance.json"
    if not path.exists():
        path = Path(__file__).resolve().parents[1] / "testdata" / "strict-deny-conformance.json"
    fixture = json.loads(path.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == "v1" and fixture["cases"]
    return fixture["cases"]


def _pdp_response(case: dict) -> Mock:
    response = Mock(status_code=case["http_status"], headers={})
    response.json.return_value = case["body"]
    response.raise_for_status.return_value = None
    return response


def _is_pdp_unavailable(error: BaseException) -> bool:
    if isinstance(error, AuthorizationDeniedError):
        return False
    if isinstance(error, EvaluationOutcomeError):
        return error.outcome == "pdp_unavailable"
    return isinstance(error, requests.RequestException)


class StrictDenyConformanceTests(unittest.TestCase):
    def _assert_outcome(self, case: dict, error: BaseException) -> None:
        expected = case["expected"]
        self.assertEqual(_is_pdp_unavailable(error), expected["pdp_unavailable"], case["name"])
        if expected["pdp_unavailable"]:
            return
        self.assertIsInstance(error, AuthorizationDeniedError, case["name"])
        self.assertEqual(error.status_code, 403)
        self.assertEqual(error.outcome, "authorization_denied")
        self.assertEqual(error.result.decision, expected["decision"])
        self.assertEqual(error.result.reason, expected["reason"])
        self.assertEqual(error.result.decision_id, case["body"].get("decisionId"))

    def test_authorize_and_evaluate_proxy_deny_and_fail_closed(self) -> None:
        client = GovernanceClient("https://pdp.example.test", "opk_service_key")
        for case in _cases():
            for name, call in (
                ("authorize", lambda: client.authorize(operation_id="op_strict", asset_id="ast_1")),
                (
                    "evaluate_proxy",
                    lambda: client.evaluate_proxy(
                        {"version": "v1", "operation_id": "op_strict", "asset": {"id": "ast_1"}, "transport": {"kind": "http"}},
                        principal_context=PrincipalContext("verified-user-token"),
                    ),
                ),
            ):
                with self.subTest(case=case["name"], path=name):
                    with patch("openprodkt_governance.client.requests.post", return_value=_pdp_response(case)):
                        with self.assertRaises((EvaluationOutcomeError, requests.RequestException)) as raised:
                            call()
                    self._assert_outcome(case, raised.exception)

    @unittest.skipUnless(GRPC_AVAILABLE, "install the optional grpc SDK extra to run interceptor tests")
    def test_grpc_interceptor_denies_without_calling_continuation(self) -> None:
        options = GRPCAdapterOptions(
            resolve_asset=lambda _context: GRPCAssetReference(asset_identity=AssetIdentity("billing", "refund-api", "production")),
            resolve_principal_context=lambda _context: PrincipalContext("verified-user-token"),
        )
        client = GovernanceClient("https://pdp.example.test", "opk_service_key")
        interceptor = UnaryUnaryClientInterceptor(client, options)
        details = Mock(method="/payments.PaymentService/Refund", metadata=(("idempotency-key", "op_strict"),))
        for case in _cases():
            with self.subTest(case=case["name"]):
                continuation = Mock()
                with patch("openprodkt_governance.client.requests.post", return_value=_pdp_response(case)):
                    with self.assertRaises(grpc.RpcError) as raised:
                        interceptor.intercept_unary_unary(continuation, details, {"amount": 1})
                continuation.assert_not_called()
                unavailable = case["expected"]["pdp_unavailable"]
                self.assertEqual(
                    raised.exception.code(),
                    grpc.StatusCode.UNAVAILABLE if unavailable else grpc.StatusCode.PERMISSION_DENIED,
                )
                outcome = json.loads(raised.exception.details())["outcome"]
                self.assertEqual(outcome, "pdp_unavailable" if unavailable else "authorization_denied")

    @unittest.skipUnless(FASTAPI_AVAILABLE, "install the optional fastapi SDK extra to run adapter tests")
    def test_fastapi_adapter_returns_deny_response_and_never_runs_handler(self) -> None:
        client = GovernanceClient("https://pdp.example.test", "opk_service_key")
        app = FastAPI()
        install_fastapi_exception_handlers(app)
        dependency = create_authorization_dependency(
            client,
            resolve_asset=lambda _request: HTTPAssetReference(asset_id="ast_1"),
            resolve_operation_id=lambda _request: "op_strict",
        )
        handler_calls: list[str] = []

        @app.post("/refunds")
        async def refund(result=Depends(dependency)):
            handler_calls.append(result.decision)
            return {"decision": result.decision}

        with TestClient(app, base_url="https://testserver") as http:
            for case in _cases():
                with self.subTest(case=case["name"]):
                    with patch("openprodkt_governance.client.requests.post", return_value=_pdp_response(case)):
                        response = http.post("/refunds", json={})
                    expected = case["expected"]
                    body = response.json()
                    self.assertNotEqual(response.status_code, 200)
                    if expected["pdp_unavailable"]:
                        self.assertEqual(response.status_code, 503)
                        self.assertEqual(body["outcome"], "pdp_unavailable")
                        continue
                    self.assertEqual(response.status_code, 403)
                    self.assertEqual(body["outcome"], "authorization_denied")
                    self.assertEqual(body["decision"], "deny")
                    self.assertEqual(body["reason"], expected["reason"])
                    self.assertEqual(body.get("decision_id"), case["body"].get("decisionId"))
        self.assertEqual(handler_calls, [])


if __name__ == "__main__":
    unittest.main()
