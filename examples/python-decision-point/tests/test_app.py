from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from openprodkt_governance.client import ApprovalTerminalError, AuthorizationDeniedError, DecisionResult, PendingApproval

from decision_point_app.app import RefundStore, Settings, create_app

WEBHOOK_SECRET = "whsec_test"


class FakeGovernance:
    """Returns queued outcomes in order. Exceptions are raised; an empty queue fails the test."""

    def __init__(self, *outcomes: DecisionResult | Exception, approval_states: tuple[dict[str, Any], ...] = ()) -> None:
        self._outcomes = list(outcomes)
        self._approval_states = list(approval_states)
        self.calls: list[dict[str, Any]] = []
        self.waits: list[dict[str, Any]] = []

    def authorize(
        self,
        *,
        operation_id: str,
        asset_key: str,
        transport: dict[str, Any],
        metadata: dict[str, Any],
        approval_id: str | None = None,
        payload_hash: str | None = None,
        wait_for_approval_seconds: float | None = None,
    ) -> DecisionResult:
        self.calls.append({
            "operation_id": operation_id,
            "asset_key": asset_key,
            "transport": transport,
            "metadata": metadata,
            "approval_id": approval_id,
            "payload_hash": payload_hash,
            "wait_for_approval_seconds": wait_for_approval_seconds,
        })
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def wait_for_approval(self, approval_id: str, *, timeout_seconds: float) -> dict[str, Any]:
        self.waits.append({"approval_id": approval_id, "timeout_seconds": timeout_seconds})
        return self._approval_states.pop(0)


@pytest.fixture
def settings() -> Settings:
    return Settings("http://control-plane.test", "opk_test", "payments.refund-api", "development", WEBHOOK_SECRET)


def client_for(settings: Settings, governance: FakeGovernance) -> TestClient:
    return TestClient(create_app(settings, governance, RefundStore()))


def send_webhook(
    client: TestClient, event_id: str, event_type: str, approval_id: str, secret: str = WEBHOOK_SECRET
) -> Any:
    body = json.dumps({
        "eventId": event_id,
        "eventType": event_type,
        "organizationId": "org_test",
        "aggregateId": approval_id,
        "data": {"approvalId": approval_id},
    }).encode()
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return client.post(
        "/webhooks/approvals",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-OpenProdkt-Event-Id": event_id,
            "X-OpenProdkt-Timestamp": timestamp,
            "X-OpenProdkt-Signature": f"v1=sha256={signature}",
        },
    )


def make_pending(refund_id: str, decision_id: str, approval_id: str = "apr_1") -> PendingApproval:
    payload_hash = "sha256:" + "a" * 64
    result = DecisionResult(
        decision="approval_required",
        decision_id=decision_id,
        policy_id="pol_refunds",
        reason="approval_required",
    )
    return PendingApproval(
        result,
        Mock(status_code=202),
        operation_id=refund_id,
        approval_id=approval_id,
        payload_hash=payload_hash,
        asset_id=None,
        asset_key="payments.refund-api",
        asset_identity=None,
        status_url=f"https://pdp.test/v1/approvals/{approval_id}",
        expires_at="2026-10-04T12:00:00Z",
    )



def test_allowed_refund_executes_once(settings: Settings) -> None:
    governance = FakeGovernance(DecisionResult(decision="allow", decision_id="dec_allow", policy_id="pol_refunds"))
    client = client_for(settings, governance)

    response = client.put("/refunds/refund-allow", json={"amount": 10})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "executed"
    assert body["decision_id"] == "dec_allow"
    assert body["policy_id"] == "pol_refunds"
    assert body["execution_count"] == 1
    assert len(governance.calls) == 1
    call = governance.calls[0]
    assert call["operation_id"] == "refund-allow"
    assert call["asset_key"] == "payments.refund-api"
    assert call["metadata"] == {"operation": "refund", "amount": 10}
    assert call["transport"]["kind"] == "http"
    assert call["transport"]["http"]["method"] == "PUT"
    assert call["transport"]["http"]["path"] == "/refunds/refund-allow"
    assert call["approval_id"] is None
    assert call["payload_hash"] is None


def test_replayed_request_returns_executed_without_another_pdp_call(settings: Settings) -> None:
    governance = FakeGovernance(DecisionResult(decision="allow", decision_id="dec_once"))
    client = client_for(settings, governance)

    first = client.put("/refunds/refund-once", json={"amount": 10})
    second = client.put("/refunds/refund-once", json={"amount": 10})

    assert first.status_code == second.status_code == 200
    assert second.json()["execution_count"] == 1
    assert len(governance.calls) == 1


def test_denied_refund_is_not_executed(settings: Settings) -> None:
    denial = AuthorizationDeniedError(
        403, "authorization_denied", DecisionResult(decision="deny", decision_id="dec_deny"), Mock(status_code=403)
    )
    client = client_for(settings, FakeGovernance(denial))

    response = client.put("/refunds/refund-deny", json={"amount": 10})

    assert response.status_code == 403
    assert response.json()["outcome"] == "authorization_denied"
    record = client.get("/refunds/refund-deny").json()
    assert record["status"] == "authorization_denied"
    assert record["execution_count"] == 0


def test_approval_blocks_then_retry_with_exact_tuple_executes_once(settings: Settings) -> None:
    governance = FakeGovernance(
        make_pending("refund-approval", "dec_approval"),
        DecisionResult(decision="allow", decision_id="dec_approval", approval_status="consumed"),
    )
    client = client_for(settings, governance)

    pending = client.put("/refunds/refund-approval", json={"amount": 100})
    assert pending.status_code == 202
    assert pending.json()["approval_id"] == "apr_1"
    assert pending.headers["Cache-Control"] == "no-store"
    assert client.get("/refunds/refund-approval").json()["status"] == "pending_approval"

    resumed = client.put("/refunds/refund-approval", json={"amount": 100})
    assert resumed.status_code == 200
    assert resumed.json()["execution_count"] == 1

    replay = client.put("/refunds/refund-approval", json={"amount": 100})
    assert replay.status_code == 200
    assert replay.json()["execution_count"] == 1

    assert len(governance.calls) == 2
    retry = governance.calls[1]
    assert retry["operation_id"] == "refund-approval"
    assert retry["approval_id"] == "apr_1"
    assert retry["payload_hash"] == "sha256:" + "a" * 64
    assert retry["metadata"] == {"operation": "refund", "amount": 100}



@pytest.mark.parametrize("outcome", ["approval_rejected", "approval_expired"])
def test_terminal_approval_keeps_refund_blocked(settings: Settings, outcome: str) -> None:
    terminal = ApprovalTerminalError(
        403, outcome, DecisionResult(decision="deny", decision_id="dec_blocked"), Mock(status_code=403)
    )
    governance = FakeGovernance(make_pending("refund-terminal", "dec_blocked"), terminal)
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-terminal", json={"amount": 100}).status_code == 202

    response = client.put("/refunds/refund-terminal", json={"amount": 100})

    assert response.status_code == 403
    assert response.json()["outcome"] == outcome
    record = client.get("/refunds/refund-terminal").json()
    assert record["status"] == outcome
    assert record["execution_count"] == 0


def test_changed_amount_for_existing_refund_is_rejected_without_pdp_call(settings: Settings) -> None:
    governance = FakeGovernance(make_pending("refund-conflict", "dec_conflict"))
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-conflict", json={"amount": 100}).status_code == 202

    response = client.put("/refunds/refund-conflict", json={"amount": 200})

    assert response.status_code == 409
    assert response.json()["outcome"] == "refund_conflict"
    assert len(governance.calls) == 1


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/refunds/refund%24bad", {"amount": 10}),
        ("/refunds/refund-invalid", {"amount": 0}),
        ("/refunds/refund-invalid", {"amount": -1}),
        ("/refunds/refund-invalid", {"amount": 1_000_001}),
        ("/refunds/refund-invalid", {}),
    ],
)
def test_invalid_request_is_rejected_before_authorization(settings: Settings, path: str, payload: dict[str, Any]) -> None:
    governance = FakeGovernance(DecisionResult(decision="allow", decision_id="dec_unused"))

    response = client_for(settings, governance).put(path, json=payload)

    assert response.status_code == 422
    assert governance.calls == []


def test_unknown_refund_returns_404(settings: Settings) -> None:
    client = client_for(settings, FakeGovernance())

    assert client.get("/refunds/missing").status_code == 404


def test_settings_report_missing_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPK_API_BASE_URL", raising=False)
    monkeypatch.delenv("OPK_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPK_API_BASE_URL, OPK_API_KEY"):
        Settings.from_environment()


def test_sync_wait_executes_in_original_request_when_approval_arrives(settings: Settings) -> None:
    governance = FakeGovernance(
        DecisionResult(decision="allow", decision_id="dec_wait", policy_id="pol_refunds", approval_status="consumed")
    )
    client = client_for(settings, governance)

    response = client.put("/refunds/refund-wait?wait_seconds=5", json={"amount": 25})

    assert response.status_code == 200
    assert response.json()["execution_count"] == 1
    assert governance.calls[0]["wait_for_approval_seconds"] == 5


def test_sync_wait_timeout_returns_pending_without_execution(settings: Settings) -> None:
    governance = FakeGovernance(make_pending("refund-wait-timeout", "dec_wait_timeout"))
    client = client_for(settings, governance)

    response = client.put("/refunds/refund-wait-timeout?wait_seconds=2", json={"amount": 25})

    assert response.status_code == 202
    assert response.json()["approval_id"] == "apr_1"
    assert governance.calls[0]["wait_for_approval_seconds"] == 2
    record = client.get("/refunds/refund-wait-timeout").json()
    assert record["status"] == "pending_approval"
    assert record["execution_count"] == 0


def test_wait_seconds_outside_bounds_is_rejected_before_authorization(settings: Settings) -> None:
    governance = FakeGovernance(DecisionResult(decision="allow", decision_id="dec_unused"))

    response = client_for(settings, governance).put("/refunds/refund-bounds?wait_seconds=31", json={"amount": 10})

    assert response.status_code == 422
    assert governance.calls == []


def test_async_poll_retries_exact_tuple_once_after_approval(settings: Settings) -> None:
    governance = FakeGovernance(
        make_pending("refund-poll", "dec_poll"),
        DecisionResult(decision="allow", decision_id="dec_poll", approval_status="consumed"),
        approval_states=({"status": "approved"},),
    )
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-poll", json={"amount": 40}).status_code == 202

    polled = client.post("/refunds/refund-poll/poll?wait_seconds=30")

    assert polled.status_code == 200
    assert polled.json()["status"] == "executed"
    assert governance.waits == [{"approval_id": "apr_1", "timeout_seconds": 30}]
    assert governance.calls[1]["approval_id"] == "apr_1"
    assert governance.calls[1]["payload_hash"] == "sha256:" + "a" * 64

    again = client.post("/refunds/refund-poll/poll?wait_seconds=30")
    assert again.json()["execution_count"] == 1
    assert len(governance.waits) == 1
    assert len(governance.calls) == 2


@pytest.mark.parametrize(("state", "outcome"), [("rejected", "approval_rejected"), ("expired", "approval_expired")])
def test_async_poll_terminal_approval_never_executes(settings: Settings, state: str, outcome: str) -> None:
    governance = FakeGovernance(make_pending("refund-poll-terminal", "dec_poll_terminal"), approval_states=({"status": state},))
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-poll-terminal", json={"amount": 40}).status_code == 202

    polled = client.post("/refunds/refund-poll-terminal/poll?wait_seconds=30")

    assert polled.json()["status"] == outcome
    assert polled.json()["execution_count"] == 0
    assert len(governance.calls) == 1


def test_poll_unknown_refund_returns_404(settings: Settings) -> None:
    assert client_for(settings, FakeGovernance()).post("/refunds/missing/poll").status_code == 404


def test_approved_webhook_executes_once_and_duplicate_delivery_is_ignored(settings: Settings) -> None:
    governance = FakeGovernance(
        make_pending("refund-hook", "dec_hook"),
        DecisionResult(decision="allow", decision_id="dec_hook", approval_status="consumed"),
    )
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-hook", json={"amount": 60}).status_code == 202

    first = send_webhook(client, "evt_1", "approval.approved", "apr_1")
    duplicate = send_webhook(client, "evt_1", "approval.approved", "apr_1")

    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    record = client.get("/refunds/refund-hook").json()
    assert record["status"] == "executed"
    assert record["execution_count"] == 1
    assert len(governance.calls) == 2


def test_approved_webhook_is_retried_until_redemption_succeeds(settings: Settings) -> None:
    governance = FakeGovernance(
        make_pending("refund-hook-retry", "dec_retry"),
        make_pending("refund-hook-retry", "dec_retry"),
        DecisionResult(decision="allow", decision_id="dec_retry", approval_status="consumed"),
    )
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-hook-retry", json={"amount": 60}).status_code == 202

    first = send_webhook(client, "evt_retry", "approval.approved", "apr_1")
    second = send_webhook(client, "evt_retry", "approval.approved", "apr_1")

    assert first.status_code == 503
    assert second.status_code == 200
    assert second.json()["duplicate"] is False
    record = client.get("/refunds/refund-hook-retry").json()
    assert record["status"] == "executed"
    assert record["execution_count"] == 1


def test_rejected_webhook_is_terminal_without_redemption(settings: Settings) -> None:
    governance = FakeGovernance(make_pending("refund-hook-reject", "dec_reject"))
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-hook-reject", json={"amount": 60}).status_code == 202

    response = send_webhook(client, "evt_reject", "approval.rejected", "apr_1")

    assert response.status_code == 200
    record = client.get("/refunds/refund-hook-reject").json()
    assert record["status"] == "approval_rejected"
    assert record["execution_count"] == 0
    assert len(governance.calls) == 1


def test_forged_webhook_changes_nothing(settings: Settings) -> None:
    governance = FakeGovernance(make_pending("refund-hook-forged", "dec_forged"))
    client = client_for(settings, governance)
    assert client.put("/refunds/refund-hook-forged", json={"amount": 60}).status_code == 202

    response = send_webhook(client, "evt_forged", "approval.approved", "apr_1", secret="whsec_wrong")

    assert response.status_code == 400
    record = client.get("/refunds/refund-hook-forged").json()
    assert record["status"] == "pending_approval"
    assert len(governance.calls) == 1


def test_webhook_for_unknown_approval_is_acknowledged_without_pdp_call(settings: Settings) -> None:
    governance = FakeGovernance()
    client = client_for(settings, governance)

    response = send_webhook(client, "evt_unknown", "approval.approved", "apr_other")

    assert response.status_code == 200
    assert response.json()["duplicate"] is False
    assert governance.calls == []
