"""gRPC refund service in two deployment variants.

Embedded variant: the server installs the OpenProdkt SDK server interceptor. The interceptor
authorizes every RPC before the handler runs; the handlers contain no authorization logic.
A pending approval is recorded in the shared `RefundStore` through the `on_pending` hook, so the
HTTP poll endpoint and the approval webhook can resume the refund exactly as they do for HTTP.

Proxy-upstream variant: no SDK and no interceptor. The server must only be reachable through
Envoy, which performs the ext_authz decision before forwarding the call.

Streams are authorized once, at establishment. The streaming methods are therefore read-only.
Only the unary `CreateRefund` changes state.

Regenerate the message module after editing `proto/refund/v1/refund.proto`:
    python -m grpc_tools.protoc -I proto --python_out=decision_point_app/generated proto/refund/v1/refund.proto
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from concurrent import futures
from typing import Any

import grpc
from openprodkt_governance import ApprovalRetry, GovernanceClient, PendingApproval
from openprodkt_governance.grpc_adapter import (
    GRPCAdapterOptions,
    GRPCAssetReference,
    GRPCRequestContext,
    create_grpc_server_interceptor,
)

from .app import RefundOrder, RefundRecord, RefundService, RefundStore, refund_metadata
from .generated.refund.v1 import refund_pb2

SERVICE_NAME = "openprodkt.example.refund.v1.RefundService"
IDEMPOTENCY_HEADER = "idempotency-key"
MAX_AMOUNT = 1_000_000
_REFUND_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def order_from_request(request: refund_pb2.CreateRefundRequest) -> RefundOrder:
    """Validate a CreateRefund request. Raises ValueError before any PDP call."""
    if not _REFUND_ID_PATTERN.fullmatch(request.refund_id):
        raise ValueError("refund_id must be 1-128 characters from A-Z, a-z, 0-9, '.', '_', '-'")
    amount = request.amount
    if not (0 < amount <= MAX_AMOUNT):
        raise ValueError(f"amount must be greater than 0 and at most {MAX_AMOUNT}")
    return RefundOrder(refund_id=request.refund_id, amount=amount)


def _header(metadata: Iterable[tuple[str, str]], name: str) -> str | None:
    for key, value in metadata:
        if key.lower() == name:
            return value
    return None


def _resolve_operation_id(context: GRPCRequestContext) -> str | None:
    if context.rpc_type == "unary":
        return order_from_request(context.request).refund_id
    # Streams use the caller-supplied idempotency key. Without it the SDK rejects the call.
    return _header(context.metadata, IDEMPOTENCY_HEADER)


def _resolve_metadata(context: GRPCRequestContext) -> dict[str, Any] | None:
    if context.rpc_type == "unary":
        return refund_metadata(order_from_request(context.request))
    return None


def _to_proto(record: RefundRecord) -> refund_pb2.Refund:
    return refund_pb2.Refund(
        refund_id=record.refund_id,
        amount=record.amount,
        status=record.status,
        decision_id=record.decision_id or "",
        approval_id=record.approval_id or "",
        execution_count=record.execution_count,
    )


class RefundGrpcHandlers:
    """Business handlers. They run only after the adapter has allowed the RPC (embedded) or after Envoy has (upstream)."""

    def __init__(self, service: RefundService, store: RefundStore) -> None:
        self._service = service
        self._store = store

    def CreateRefund(self, request: refund_pb2.CreateRefundRequest, context: grpc.ServicerContext) -> refund_pb2.Refund:
        order = order_from_request(request)
        return _to_proto(self._service.execute_authorized(order))

    def WatchRefund(self, request: refund_pb2.RefundLookup, context: grpc.ServicerContext) -> Iterator[refund_pb2.Refund]:
        record = self._store.get(request.refund_id)
        if record is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "refund not found")
        yield _to_proto(record)

    def CountRefunds(self, request_iterator: Iterable[refund_pb2.RefundLookup], context: grpc.ServicerContext) -> refund_pb2.RefundCount:
        total = 0
        executed = 0
        for lookup in request_iterator:
            total += 1
            record = self._store.get(lookup.refund_id)
            if record is not None and record.status == "executed":
                executed += 1
        return refund_pb2.RefundCount(total=total, executed=executed)

    def WatchRefunds(self, request_iterator: Iterable[refund_pb2.RefundLookup], context: grpc.ServicerContext) -> Iterator[refund_pb2.Refund]:
        for lookup in request_iterator:
            record = self._store.get(lookup.refund_id)
            if record is None:
                context.abort(grpc.StatusCode.NOT_FOUND, "refund not found")
            yield _to_proto(record)


def add_refund_servicer(server: grpc.Server, handlers: RefundGrpcHandlers) -> None:
    generic = grpc.method_handlers_generic_handler(
        SERVICE_NAME,
        {
            "CreateRefund": grpc.unary_unary_rpc_method_handler(
                handlers.CreateRefund,
                request_deserializer=refund_pb2.CreateRefundRequest.FromString,
                response_serializer=refund_pb2.Refund.SerializeToString,
            ),
            "WatchRefund": grpc.unary_stream_rpc_method_handler(
                handlers.WatchRefund,
                request_deserializer=refund_pb2.RefundLookup.FromString,
                response_serializer=refund_pb2.Refund.SerializeToString,
            ),
            "CountRefunds": grpc.stream_unary_rpc_method_handler(
                handlers.CountRefunds,
                request_deserializer=refund_pb2.RefundLookup.FromString,
                response_serializer=refund_pb2.RefundCount.SerializeToString,
            ),
            "WatchRefunds": grpc.stream_stream_rpc_method_handler(
                handlers.WatchRefunds,
                request_deserializer=refund_pb2.RefundLookup.FromString,
                response_serializer=refund_pb2.Refund.SerializeToString,
            ),
        },
    )
    server.add_generic_rpc_handlers((generic,))


def create_embedded_grpc_server(
    governance: GovernanceClient,
    service: RefundService,
    store: RefundStore,
    asset_key: str,
    *,
    wait_for_approval_seconds: float | None = None,
    address: str = "127.0.0.1:0",
    max_workers: int = 8,
) -> tuple[grpc.Server, int]:
    """Embedded SDK variant. Returns an unstarted server and its bound port; call `start()` to serve."""

    def record_challenge(context: GRPCRequestContext, authorization: dict[str, Any], pending: PendingApproval) -> None:
        if context.rpc_type != "unary":
            operation_id = _resolve_operation_id(context)
            if operation_id is not None:
                store.record_stream_challenge(operation_id, pending)
            return
        order = order_from_request(context.request)
        service.record_challenge(order, authorization["transport"], pending)

    def resolve_approval_retry(context: GRPCRequestContext) -> ApprovalRetry | None:
        """Return the stored tuple so an approved retry carries approval_id and payload_hash."""
        operation_id = _resolve_operation_id(context)
        if operation_id is None:
            return None
        if context.rpc_type == "unary":
            record = store.get(operation_id)
            if record is None or record.status != "pending_approval" or not (record.approval_id and record.payload_hash):
                return None
            return ApprovalRetry(approval_id=record.approval_id, payload_hash=record.payload_hash)
        stored = store.stream_retry(operation_id)
        return ApprovalRetry(approval_id=stored[0], payload_hash=stored[1]) if stored else None

    options = GRPCAdapterOptions(
        resolve_asset=lambda _context: GRPCAssetReference(asset_key=asset_key),
        resolve_operation_id=_resolve_operation_id,
        resolve_metadata=_resolve_metadata,
        resolve_approval_retry=resolve_approval_retry,
        wait_for_approval_seconds=wait_for_approval_seconds or None,
        on_pending=record_challenge,
    )
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        interceptors=(create_grpc_server_interceptor(governance, options),),
    )
    add_refund_servicer(server, RefundGrpcHandlers(service, store))
    port = server.add_insecure_port(address)
    return server, port


def create_upstream_grpc_server(
    service: RefundService,
    store: RefundStore,
    *,
    address: str = "127.0.0.1:0",
    max_workers: int = 8,
) -> tuple[grpc.Server, int]:
    """Proxy-upstream variant. No SDK and no interceptor. Bind only to a network reachable from Envoy."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    add_refund_servicer(server, RefundGrpcHandlers(service, store))
    port = server.add_insecure_port(address)
    return server, port
