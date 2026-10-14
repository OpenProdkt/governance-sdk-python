from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from unittest.mock import Mock

import grpc
import pytest
from openprodkt_governance.client import DecisionResult, PendingApproval
from openprodkt_governance.webhook import ApprovalWebhookEvent

from decision_point_app.app import RefundService, RefundStore
from decision_point_app.generated.refund.v1 import refund_pb2
from decision_point_app.grpc_refunds import (
    SERVICE_NAME,
    create_embedded_grpc_server,
    create_upstream_grpc_server,
)

ASSET_KEY = "payments.refund-api"


class FakeGovernance:
    """Returns queued outcomes in order. Exceptions are raised; an empty queue fails the test."""

    def __init__(self, *outcomes: DecisionResult | Exception, approval_states: tuple[dict[str, Any], ...] = ()) -> None:
        self._outcomes = list(outcomes)
        self._approval_states = list(approval_states)
        self.calls: list[dict[str, Any]] = []
        self.waits: list[dict[str, Any]] = []

    def authorize(self, **arguments: Any) -> DecisionResult:
        self.calls.append(arguments)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def wait_for_approval(self, approval_id: str, *, timeout_seconds: float) -> dict[str, Any]:
        self.waits.append({"approval_id": approval_id, "timeout_seconds": timeout_seconds})
        return self._approval_states.pop(0)


def make_pending(refund_id: str, decision_id: str, approval_id: str = "apr_1") -> PendingApproval:
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
        payload_hash="sha256:" + "a" * 64,
        asset_id=None,
        asset_key=ASSET_KEY,
        asset_identity=None,
        status_url=f"https://pdp.test/v1/approvals/{approval_id}",
        expires_at="2026-10-04T12:00:00Z",
    )


class RefundClient:
    def __init__(self, channel: grpc.Channel) -> None:
        self._create = channel.unary_unary(
            f"/{SERVICE_NAME}/CreateRefund",
            request_serializer=refund_pb2.CreateRefundRequest.SerializeToString,
            response_deserializer=refund_pb2.Refund.FromString,
        )
        self._watch = channel.unary_stream(
            f"/{SERVICE_NAME}/WatchRefund",
            request_serializer=refund_pb2.RefundLookup.SerializeToString,
            response_deserializer=refund_pb2.Refund.FromString,
        )
        self._count = channel.stream_unary(
            f"/{SERVICE_NAME}/CountRefunds",
            request_serializer=refund_pb2.RefundLookup.SerializeToString,
            response_deserializer=refund_pb2.RefundCount.FromString,
        )
        self._watch_many = channel.stream_stream(
            f"/{SERVICE_NAME}/WatchRefunds",
            request_serializer=refund_pb2.RefundLookup.SerializeToString,
            response_deserializer=refund_pb2.Refund.FromString,
        )

    def create(self, refund_id: str, amount: float) -> refund_pb2.Refund:
        return self._create(refund_pb2.CreateRefundRequest(refund_id=refund_id, amount=amount), timeout=5)

    def watch(self, refund_id: str, key: str | None) -> list[refund_pb2.Refund]:
        return list(self._watch(refund_pb2.RefundLookup(refund_id=refund_id), metadata=_key_metadata(key), timeout=5))

    def count(self, refund_ids: list[str], key: str | None) -> refund_pb2.RefundCount:
        requests = iter([refund_pb2.RefundLookup(refund_id=value) for value in refund_ids])
        return self._count(requests, metadata=_key_metadata(key), timeout=5)

    def watch_many(self, refund_ids: list[str], key: str | None) -> list[refund_pb2.Refund]:
        requests = iter([refund_pb2.RefundLookup(refund_id=value) for value in refund_ids])
        return list(self._watch_many(requests, metadata=_key_metadata(key), timeout=5))


def _key_metadata(key: str | None) -> tuple[tuple[str, str], ...] | None:
    return (("idempotency-key", key),) if key else None


Harness = Callable[..., tuple[RefundClient, RefundService, RefundStore]]


@pytest.fixture
def harness() -> Any:
    servers: list[grpc.Server] = []
    channels: list[grpc.Channel] = []

    def build(governance: FakeGovernance, *, wait: float | None = None, upstream: bool = False) -> tuple[RefundClient, RefundService, RefundStore]:
        store = RefundStore()
        service = RefundService(governance, store, ASSET_KEY)
        if upstream:
            server, port = create_upstream_grpc_server(service, store, address="127.0.0.1:0")
        else:
            server, port = create_embedded_grpc_server(
                governance,
                service,
                store,
                ASSET_KEY,
                wait_for_approval_seconds=wait,
                address="127.0.0.1:0",
            )
        server.start()
        servers.append(server)
        channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        channels.append(channel)
        return RefundClient(channel), service, store

    yield build
    for channel in channels:
        channel.close()
    for server in servers:
        server.stop(None)


def _status_code(error: pytest.ExceptionInfo[grpc.RpcError]) -> grpc.StatusCode:
    return error.value.code()


def test_create_refund_is_authorized_then_executed_once(harness: Harness) -> None:
    governance = FakeGovernance(DecisionResult(decision="allow", decision_id="dec_1"))
    client, _, _ = harness(governance)

    refund = client.create("ref_1", 10.0)

    assert refund.status == "executed"
    assert refund.execution_count == 1
    assert len(governance.calls) == 1
    call = governance.calls[0]
    assert call["operation_id"] == "ref_1"
    assert call["asset_key"] == ASSET_KEY
    assert call["metadata"] == {"operation": "refund", "amount": 10.0}
    assert call["transport"]["kind"] == "grpc"
    assert call["transport"]["grpc"]["method"] == "CreateRefund"
    assert "wait_for_approval_seconds" not in call


def test_pending_challenge_is_recorded_and_not_executed(harness: Harness) -> None:
    governance = FakeGovernance(make_pending("ref_2", "dec_2"))
    client, _, store = harness(governance)

    with pytest.raises(grpc.RpcError) as error:
        client.create("ref_2", 10.0)

    assert _status_code(error) == grpc.StatusCode.PERMISSION_DENIED
    assert json.loads(error.value.details())["outcome"] == "pending_approval"
    record = store.get("ref_2")
    assert record is not None
    assert record.status == "pending_approval"
    assert record.approval_id == "apr_1"
    assert record.payload_hash == "sha256:" + "a" * 64
    assert record.execution_count == 0


def test_sync_wait_option_is_forwarded_to_authorize(harness: Harness) -> None:
    governance = FakeGovernance(DecisionResult(decision="allow", decision_id="dec_3"))
    client, _, _ = harness(governance, wait=5)

    client.create("ref_3", 10.0)

    assert governance.calls[0]["wait_for_approval_seconds"] == 5


def test_pending_refund_resumes_once_through_poll_with_same_tuple(harness: Harness) -> None:
    governance = FakeGovernance(
        make_pending("ref_4", "dec_4"),
        DecisionResult(decision="allow", decision_id="dec_4b"),
        approval_states=({"status": "approved"},),
    )
    client, service, _ = harness(governance)

    with pytest.raises(grpc.RpcError):
        client.create("ref_4", 10.0)
    record = service.poll_pending("ref_4", wait_seconds=1)

    assert record.status == "executed"
    assert record.execution_count == 1
    assert governance.waits == [{"approval_id": "apr_1", "timeout_seconds": 1}]
    first, retry = governance.calls
    assert retry["approval_id"] == "apr_1"
    assert retry["payload_hash"] == "sha256:" + "a" * 64
    assert retry["operation_id"] == first["operation_id"]
    assert retry["metadata"] == first["metadata"]
    assert retry["transport"] == first["transport"]


def test_approval_webhook_resumes_grpc_refund_once(harness: Harness) -> None:
    governance = FakeGovernance(
        make_pending("ref_5", "dec_5"),
        DecisionResult(decision="allow", decision_id="dec_5b"),
    )
    client, service, store = harness(governance)

    with pytest.raises(grpc.RpcError):
        client.create("ref_5", 10.0)
    event = ApprovalWebhookEvent(
        event_id="evt_1",
        event_type="approval.approved",
        organization_id="org_test",
        aggregate_id="apr_1",
        data={"approvalId": "apr_1"},
    )

    assert service.apply_approval_event(event) is True
    assert service.apply_approval_event(event) is False

    record = store.get("ref_5")
    assert record is not None
    assert record.status == "executed"
    assert record.execution_count == 1
    assert len(governance.calls) == 2


def test_invalid_refund_is_rejected_before_authorization(harness: Harness) -> None:
    governance = FakeGovernance()
    client, _, _ = harness(governance)

    with pytest.raises(grpc.RpcError) as bad_id:
        client.create("bad id", 10.0)
    with pytest.raises(grpc.RpcError) as bad_amount:
        client.create("ref_6", -1.0)

    assert _status_code(bad_id) == grpc.StatusCode.INVALID_ARGUMENT
    assert _status_code(bad_amount) == grpc.StatusCode.INVALID_ARGUMENT
    assert governance.calls == []


def test_streams_are_authorized_at_establishment_and_read_only(harness: Harness) -> None:
    governance = FakeGovernance(
        DecisionResult(decision="allow", decision_id="dec_7"),
        DecisionResult(decision="allow"),
        DecisionResult(decision="allow"),
        DecisionResult(decision="allow"),
    )
    client, _, store = harness(governance)
    client.create("ref_7", 10.0)

    watched = client.watch("ref_7", key="watch-7")
    counted = client.count(["ref_7", "missing"], key="count-7")
    streamed = client.watch_many(["ref_7"], key="stream-7")

    assert [refund.status for refund in watched] == ["executed"]
    assert counted.total == 2
    assert counted.executed == 1
    assert [refund.refund_id for refund in streamed] == ["ref_7"]
    assert [call["operation_id"] for call in governance.calls[1:]] == ["watch-7", "count-7", "stream-7"]
    assert [call["transport"]["grpc"]["method"] for call in governance.calls[1:]] == [
        "WatchRefund",
        "CountRefunds",
        "WatchRefunds",
    ]
    assert all(call["metadata"] is None for call in governance.calls[1:])
    assert store.get("ref_7").execution_count == 1


def test_stream_without_idempotency_key_is_rejected(harness: Harness) -> None:
    governance = FakeGovernance()
    client, _, _ = harness(governance)

    with pytest.raises(grpc.RpcError) as error:
        client.watch("ref_8", key=None)

    assert _status_code(error) == grpc.StatusCode.INVALID_ARGUMENT
    assert governance.calls == []


def test_stream_pending_aborts_before_handler_and_records_nothing(harness: Harness) -> None:
    governance = FakeGovernance(make_pending("ref_9", "dec_9", approval_id="apr_9"))
    client, _, store = harness(governance)

    with pytest.raises(grpc.RpcError) as error:
        client.watch("ref_9", key="watch-9")

    assert _status_code(error) == grpc.StatusCode.PERMISSION_DENIED
    assert store.get("ref_9") is None


def test_stream_retry_after_challenge_carries_stored_approval_tuple(harness: Harness) -> None:
    governance = FakeGovernance(
        make_pending("ref_10", "dec_10", approval_id="apr_10"),
        DecisionResult(decision="allow", decision_id="dec_10b"),
    )
    client, _, _ = harness(governance)

    with pytest.raises(grpc.RpcError) as challenge:
        client.watch("ref_10", key="watch-10")
    assert _status_code(challenge) == grpc.StatusCode.PERMISSION_DENIED

    with pytest.raises(grpc.RpcError) as retry:
        client.watch("ref_10", key="watch-10")

    # The approved retry passed authorization; the handler then finds no refund record.
    assert _status_code(retry) == grpc.StatusCode.NOT_FOUND
    stream_retry = governance.calls[1]
    assert stream_retry["operation_id"] == "watch-10"
    assert stream_retry["approval_id"] == "apr_10"
    assert stream_retry["payload_hash"] == "sha256:" + "a" * 64


def test_stream_denied_aborts_before_handler_and_leaves_state_unchanged(harness: Harness) -> None:
    governance = FakeGovernance(
        DecisionResult(decision="allow", decision_id="dec_10"),
        DecisionResult(decision="deny", reason="policy_denied"),
    )
    client, _, store = harness(governance)
    client.create("ref_10", 10.0)
    before_count = store.get("ref_10").execution_count
    before_status = store.get("ref_10").status

    with pytest.raises(grpc.RpcError) as error:
        client.watch("ref_10", key="watch-10")

    assert _status_code(error) == grpc.StatusCode.PERMISSION_DENIED
    assert len(governance.calls) == 2
    assert store.get("ref_10").execution_count == before_count == 1
    assert store.get("ref_10").status == before_status


def test_unknown_refund_watch_is_not_found(harness: Harness) -> None:
    governance = FakeGovernance(DecisionResult(decision="allow"))
    client, _, _ = harness(governance)

    with pytest.raises(grpc.RpcError) as error:
        client.watch("missing", key="watch-missing")

    assert _status_code(error) == grpc.StatusCode.NOT_FOUND


def test_upstream_variant_executes_without_sdk(harness: Harness) -> None:
    governance = FakeGovernance()
    client, _, _ = harness(governance, upstream=True)

    refund = client.create("ref_10", 10.0)

    assert refund.status == "executed"
    assert refund.execution_count == 1
    assert governance.calls == []
