from __future__ import annotations

import json
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from openprodkt_governance.asset_identity import AssetIdentity
from openprodkt_governance.client import (
    ClientConfigurationError,
    DecisionResult,
    EvaluationOutcomeError,
    GovernanceClient,
    InvalidAuthorizationInputError,
    PendingApproval,
    PrincipalContext,
)

try:
    from fastapi import Depends, FastAPI, Request
    from fastapi.testclient import TestClient

    from openprodkt_governance.fastapi_adapter import HTTPAssetReference, _fastapi_status, create_approval_webhook_handler, create_authorization_dependency, install_fastapi_exception_handlers

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


@unittest.skipUnless(FASTAPI_AVAILABLE, "install the optional fastapi SDK extra to run adapter tests")
class FastAPIAdapterTests(unittest.TestCase):
    @patch("openprodkt_governance.client.requests.post")
    def test_dependency_builds_trusted_http_context_and_principal_header(self, mock_post: Mock) -> None:
        response = Mock(status_code=200)
        response.json.return_value = {"decision": "allow"}
        response.raise_for_status.return_value = None
        mock_post.return_value = response

        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "pep-conformance.json"
        http_vector = json.loads(fixture_path.read_text(encoding="utf-8"))["http_transport"]
        vector_input = http_vector["input"]
        sdk_client = GovernanceClient("https://pdp.example.test", "opk_service_key")
        dependency = create_authorization_dependency(
            sdk_client,
            resolve_asset=lambda _request: HTTPAssetReference(
                asset_identity=AssetIdentity("billing", "refund-api", "production")
            ),
            resolve_metadata=lambda _request, body: body["metadata"],
            resolve_principal_context=lambda request: request.state.principal_context,
            resolve_operation_id=lambda _request: "refund-123",
            resolve_host=lambda _request: vector_input["host"],
            header_allowlist=tuple(vector_input["headers"]),
        )
        app = FastAPI()

        @app.middleware("http")
        async def attach_authenticated_principal(request: Request, call_next):
            request.state.principal_context = PrincipalContext("verified-user-token")
            return await call_next(request)

        @app.post("/refunds/{refund_id}")
        async def authorize_refund(refund_id: str, result=Depends(dependency)):
            return {"decision": result.decision}

        with TestClient(app, base_url="https://testserver") as client:
            headers = dict(vector_input["headers"])
            headers.update({
                "Idempotency-Key": "gateway-operation-id",
                "X-OpenProdkt-Principal": "spoofed-user",
            })
            result = client.request(
                vector_input["method"],
                vector_input["path"],
                headers=headers,
                json={"metadata": {"amount": 12, "actor": "untrusted-metadata"}},
            )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {"decision": "allow"})
        request_payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(request_payload["operation_id"], "refund-123")
        self.assertEqual(request_payload["asset"], {
            "key": "billing.refund-api.production",
            "application": "billing",
            "service": "refund-api",
            "environment": "production",
        })
        self.assertEqual(request_payload["metadata"], {"amount": 12, "actor": "untrusted-metadata"})
        self.assertEqual(request_payload["transport"], http_vector["expected"])
        self.assertEqual(mock_post.call_args.kwargs["headers"]["Authorization"], "Bearer verified-user-token")
        self.assertNotIn("verified-user-token", json.dumps(request_payload))
        self.assertNotIn("principal", request_payload)
        self.assertNotIn("x-openprodkt-principal", request_payload["transport"]["http"]["headers"])

    def test_dependency_rejects_sensitive_header_allowlist(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be copied"):
            create_authorization_dependency(
                GovernanceClient("https://pdp.example.test", "opk_service_key"),
                resolve_asset=lambda _request: HTTPAssetReference(asset_id="ast_1"),
                header_allowlist=("Authorization",),
            )

    def test_exception_handlers_map_typed_outcomes_and_pending_headers(self) -> None:
        sdk_client = Mock(spec=GovernanceClient)
        app = FastAPI()
        install_fastapi_exception_handlers(app, retry_after_seconds=3)
        dependency = create_authorization_dependency(
            sdk_client,
            resolve_asset=lambda _request: HTTPAssetReference(asset_id="ast_1"),
            resolve_operation_id=lambda _request: "refund-123",
        )

        @app.get("/authorize")
        async def authorize(result=Depends(dependency)):
            return {"decision": result.decision}

        result = DecisionResult("deny", decision_id="dec_1", reason="policy_denied")
        expires_at = "2026-10-04T12:00:00Z"
        pending_result = DecisionResult(
            "approval_required", decision_id="dec_2", approval_id="apr_1",
            payload_hash="sha256:" + "a" * 64, approval_expires_at=expires_at,
        )
        pending = PendingApproval(
            pending_result, Mock(status_code=202), operation_id="refund-123", approval_id="apr_1",
            payload_hash=pending_result.payload_hash, asset_id="ast_1", asset_key=None,
            asset_identity=None, status_url="https://pdp.example.test/v1/approvals/apr_1", expires_at=expires_at,
        )
        outcomes = (
            (EvaluationOutcomeError(403, "authorization_denied", result, Mock(status_code=403)), 403),
            (EvaluationOutcomeError(409, "asset_identity_conflict", result, Mock(status_code=409)), 409),
            (EvaluationOutcomeError(409, "operation_conflict", result, Mock(status_code=409)), 409),
            (EvaluationOutcomeError(402, "quota_exceeded", result, Mock(status_code=402)), 402),
            (InvalidAuthorizationInputError("invalid request"), 400),
            (ClientConfigurationError("invalid client configuration"), 500),
            (requests.RequestException("network failure"), 503),
            (pending, 202),
        )
        with TestClient(app) as client:
            for error, expected_status in outcomes:
                sdk_client.authorize.side_effect = error
                response = client.get("/authorize")
                self.assertEqual(response.status_code, expected_status, error)
                self.assertNotIn("verified-user-token", response.text)
                if expected_status == 202:
                    self.assertEqual(response.headers["cache-control"], "no-store")
                    self.assertEqual(response.headers["retry-after"], "3")
                    self.assertEqual(response.json()["status_url"], pending.status_url)

    def test_shared_outcome_status_vectors(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "pep-conformance.json"
        vectors = json.loads(fixture_path.read_text(encoding="utf-8"))["outcomes"]
        for vector in vectors:
            if vector["outcome"] == "allow":
                continue
            with self.subTest(outcome=vector["outcome"]):
                result = DecisionResult(vector["decision"])
                error = EvaluationOutcomeError(vector["http_status"], vector["outcome"], result, Mock())
                self.assertEqual(_fastapi_status(error), vector["http_status"])

    def test_webhook_handler_verifies_raw_body_and_reports_deduplication(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "pep-conformance.json"
        vector = json.loads(fixture_path.read_text(encoding="utf-8"))["webhook"]
        seen: set[str] = set()
        dispatched: list[str] = []

        def dispatch(event) -> bool:
            if event.event_id in seen:
                return False
            seen.add(event.event_id)
            dispatched.append(event.event_id)
            return True

        handler = create_approval_webhook_handler(
            ["pep-conformance-rotated", vector["secret"]],
            dispatch,
            now=datetime.fromisoformat(vector["timestamp"].replace("Z", "+00:00")),
            max_body_bytes=512,
        )
        app = FastAPI()

        @app.post("/webhooks/approvals")
        async def webhook(request: Request):
            return await handler(request)

        headers = {
            "X-OpenProdkt-Event-Id": vector["event_id"],
            "X-OpenProdkt-Timestamp": vector["timestamp"],
            "X-OpenProdkt-Signature": vector["signature"],
        }
        with TestClient(app) as client:
            first = client.post("/webhooks/approvals", content=vector["raw_body"], headers=headers)
            duplicate = client.post("/webhooks/approvals", content=vector["raw_body"], headers=headers)
            invalid = client.post("/webhooks/approvals", content=vector["raw_body"] + " ", headers=headers)
            oversized = client.post("/webhooks/approvals", content=vector["raw_body"] + " " * 512, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertFalse(first.json()["duplicate"])
        self.assertTrue(duplicate.json()["duplicate"])
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(oversized.status_code, 400)
        self.assertEqual(dispatched, [vector["event_id"]])


if __name__ == "__main__":
    unittest.main()
