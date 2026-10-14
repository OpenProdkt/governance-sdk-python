from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

import grpc
import requests

from .asset_identity import AssetIdentity
from .client import (
    ApprovalRetry,
    ClientConfigurationError,
    DecisionResult,
    EvaluationOutcomeError,
    GovernanceClient,
    InvalidAuthorizationInputError,
    PendingApproval,
    PrincipalContext,
)


Metadata = tuple[tuple[str, str | bytes], ...]


@dataclass(frozen=True)
class GRPCAssetReference:
    asset_id: Optional[str] = None
    asset_key: Optional[str] = None
    asset_identity: Optional[AssetIdentity] = None


@dataclass(frozen=True)
class GRPCRequestContext:
    full_method: str
    service: str
    method: str
    rpc_type: str
    request: Any
    metadata: Metadata


@dataclass(frozen=True)
class GRPCAdapterOptions:
    resolve_asset: Callable[[GRPCRequestContext], GRPCAssetReference]
    resolve_metadata: Optional[Callable[[GRPCRequestContext], Any]] = None
    resolve_principal_context: Optional[Callable[[GRPCRequestContext], Optional[PrincipalContext]]] = None
    resolve_operation_id: Optional[Callable[[GRPCRequestContext], Optional[str]]] = None
    resolve_route_id: Optional[Callable[[GRPCRequestContext], Optional[str]]] = None
    # Establishment only: returns the stored approval tuple for an approved retry of this RPC.
    resolve_approval_retry: Optional[Callable[[GRPCRequestContext], Optional[ApprovalRetry]]] = None
    metadata_allowlist: Sequence[str] = ()
    # Server-side only: bounded synchronous wait for approval before the RPC is rejected.
    wait_for_approval_seconds: Optional[float] = None
    # Server-side only: receives the pending challenge and the exact authorization request
    # so an application can persist the retry tuple before the RPC is rejected.
    on_pending: Optional[Callable[[GRPCRequestContext, dict[str, Any], PendingApproval], None]] = None


class GRPCAuthorizationError(grpc.RpcError):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        super().__init__()
        self._code = code
        self._details = details

    def code(self) -> grpc.StatusCode:
        return self._code

    def details(self) -> str:
        return self._details


class _ClientInterceptorBase:
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions, rpc_type: str, request_streaming: bool) -> None:
        self.client = client
        self.options = options
        self.rpc_type = rpc_type
        self.request_streaming = request_streaming

    def authorize(self, method: str, request: Any, raw_metadata: Optional[Metadata]) -> DecisionResult:
        context = _make_request_context(method, self.rpc_type, None if self.request_streaming else request, raw_metadata)
        try:
            authorization = _make_authorization_request(context, self.options)
        except (TypeError, ValueError) as error:
            raise _grpc_authorization_error(error) from error
        try:
            result = self.client.authorize(**authorization)
        except EvaluationOutcomeError as error:
            raise _grpc_authorization_error(error) from error
        except ClientConfigurationError as error:
            raise _grpc_authorization_error(error) from error
        except InvalidAuthorizationInputError as error:
            raise _grpc_authorization_error(error) from error
        except requests.RequestException as error:
            raise _grpc_authorization_error(error) from error
        if result.decision != "allow":
            outcome = "pending_approval" if result.decision == "approval_required" else "authorization_denied"
            raise _grpc_authorization_error(EvaluationOutcomeError(403, outcome, result, None))
        return result


class UnaryUnaryClientInterceptor(_ClientInterceptorBase, grpc.UnaryUnaryClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "unary", False)

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.authorize(client_call_details.method, request, client_call_details.metadata)
        return continuation(client_call_details, request)


class UnaryStreamClientInterceptor(_ClientInterceptorBase, grpc.UnaryStreamClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "server_streaming", False)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.authorize(client_call_details.method, request, client_call_details.metadata)
        return continuation(client_call_details, request)


class StreamUnaryClientInterceptor(_ClientInterceptorBase, grpc.StreamUnaryClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "client_streaming", True)

    def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        self.authorize(client_call_details.method, None, client_call_details.metadata)
        return continuation(client_call_details, request_iterator)


class StreamStreamClientInterceptor(_ClientInterceptorBase, grpc.StreamStreamClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "bidirectional_streaming", True)

    def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        self.authorize(client_call_details.method, None, client_call_details.metadata)
        return continuation(client_call_details, request_iterator)


def create_grpc_client_interceptors(client: GovernanceClient, options: GRPCAdapterOptions) -> tuple[grpc.ClientInterceptor, ...]:
    """Return client interceptors for unary and streaming RPC establishment."""
    return (
        UnaryUnaryClientInterceptor(client, options),
        UnaryStreamClientInterceptor(client, options),
        StreamUnaryClientInterceptor(client, options),
        StreamStreamClientInterceptor(client, options),
    )


class _AioClientInterceptorBase:
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions, rpc_type: str, request_streaming: bool) -> None:
        self.authorizer = _ClientInterceptorBase(client, options, rpc_type, request_streaming)

    async def authorize(self, method: str, request: Any, metadata: Optional[Metadata]) -> None:
        await asyncio.to_thread(self.authorizer.authorize, method, request, metadata)


class UnaryUnaryAioClientInterceptor(_AioClientInterceptorBase, grpc.aio.UnaryUnaryClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "unary", False)

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        await self.authorize(client_call_details.method, request, client_call_details.metadata)
        return await continuation(client_call_details, request)


class UnaryStreamAioClientInterceptor(_AioClientInterceptorBase, grpc.aio.UnaryStreamClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "server_streaming", False)

    async def intercept_unary_stream(self, continuation, client_call_details, request):
        await self.authorize(client_call_details.method, request, client_call_details.metadata)
        return await continuation(client_call_details, request)


class StreamUnaryAioClientInterceptor(_AioClientInterceptorBase, grpc.aio.StreamUnaryClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "client_streaming", True)

    async def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        await self.authorize(client_call_details.method, None, client_call_details.metadata)
        return await continuation(client_call_details, request_iterator)


class StreamStreamAioClientInterceptor(_AioClientInterceptorBase, grpc.aio.StreamStreamClientInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        super().__init__(client, options, "bidirectional_streaming", True)

    async def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        await self.authorize(client_call_details.method, None, client_call_details.metadata)
        return await continuation(client_call_details, request_iterator)


def create_grpc_aio_client_interceptors(client: GovernanceClient, options: GRPCAdapterOptions) -> tuple[Any, ...]:
    return (
        UnaryUnaryAioClientInterceptor(client, options),
        UnaryStreamAioClientInterceptor(client, options),
        StreamUnaryAioClientInterceptor(client, options),
        StreamStreamAioClientInterceptor(client, options),
    )


class GRPCServerInterceptor(grpc.ServerInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        self.client = client
        self.options = options

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None
        method = handler_call_details.method
        raw_metadata = tuple(handler_call_details.invocation_metadata or ())

        if not handler.request_streaming and not handler.response_streaming:
            def unary_unary(request, context):
                _authorize_server(self.client, self.options, method, "unary", request, raw_metadata, context)
                return handler.unary_unary(request, context)

            return grpc.unary_unary_rpc_method_handler(unary_unary, handler.request_deserializer, handler.response_serializer)

        if not handler.request_streaming and handler.response_streaming:
            def unary_stream(request, context):
                _authorize_server(self.client, self.options, method, "server_streaming", request, raw_metadata, context)
                return handler.unary_stream(request, context)

            return grpc.unary_stream_rpc_method_handler(unary_stream, handler.request_deserializer, handler.response_serializer)

        if handler.request_streaming and not handler.response_streaming:
            def stream_unary(request_iterator, context):
                _authorize_server(self.client, self.options, method, "client_streaming", None, raw_metadata, context)
                return handler.stream_unary(request_iterator, context)

            return grpc.stream_unary_rpc_method_handler(stream_unary, handler.request_deserializer, handler.response_serializer)

        def stream_stream(request_iterator, context):
            _authorize_server(self.client, self.options, method, "bidirectional_streaming", None, raw_metadata, context)
            return handler.stream_stream(request_iterator, context)

        return grpc.stream_stream_rpc_method_handler(stream_stream, handler.request_deserializer, handler.response_serializer)


def create_grpc_server_interceptor(client: GovernanceClient, options: GRPCAdapterOptions) -> grpc.ServerInterceptor:
    return GRPCServerInterceptor(client, options)


class GRPCAioServerInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, client: GovernanceClient, options: GRPCAdapterOptions) -> None:
        self.client = client
        self.options = options

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None
        method = handler_call_details.method
        raw_metadata = tuple(handler_call_details.invocation_metadata or ())

        if not handler.request_streaming and not handler.response_streaming:
            async def unary_unary(request, context):
                await _authorize_aio_server(self.client, self.options, method, "unary", request, raw_metadata, context)
                return await handler.unary_unary(request, context)

            return grpc.unary_unary_rpc_method_handler(unary_unary, handler.request_deserializer, handler.response_serializer)

        if not handler.request_streaming and handler.response_streaming:
            async def unary_stream(request, context):
                await _authorize_aio_server(self.client, self.options, method, "server_streaming", request, raw_metadata, context)
                async for response in handler.unary_stream(request, context):
                    yield response

            return grpc.unary_stream_rpc_method_handler(unary_stream, handler.request_deserializer, handler.response_serializer)

        if handler.request_streaming and not handler.response_streaming:
            async def stream_unary(request_iterator, context):
                await _authorize_aio_server(self.client, self.options, method, "client_streaming", None, raw_metadata, context)
                return await handler.stream_unary(request_iterator, context)

            return grpc.stream_unary_rpc_method_handler(stream_unary, handler.request_deserializer, handler.response_serializer)

        async def stream_stream(request_iterator, context):
            await _authorize_aio_server(self.client, self.options, method, "bidirectional_streaming", None, raw_metadata, context)
            async for response in handler.stream_stream(request_iterator, context):
                yield response

        return grpc.stream_stream_rpc_method_handler(stream_stream, handler.request_deserializer, handler.response_serializer)


def create_grpc_aio_server_interceptor(client: GovernanceClient, options: GRPCAdapterOptions) -> grpc.aio.ServerInterceptor:
    return GRPCAioServerInterceptor(client, options)


async def _authorize_aio_server(
    client: GovernanceClient,
    options: GRPCAdapterOptions,
    method: str,
    rpc_type: str,
    request: Any,
    raw_metadata: Metadata,
    context: grpc.aio.ServicerContext,
) -> None:
    try:
        request_context = _make_request_context(method, rpc_type, request, raw_metadata)
        authorization = _make_authorization_request(request_context, options)
    except (TypeError, ValueError) as error:
        mapped = _grpc_authorization_error(error)
        await context.abort(mapped.code(), mapped.details())
    try:
        result = await asyncio.to_thread(client.authorize, **authorization)
    except PendingApproval as error:
        _notify_pending(options, request_context, authorization, error)
        mapped = _grpc_authorization_error(error)
        await context.abort(mapped.code(), mapped.details())
    except (EvaluationOutcomeError, ClientConfigurationError, InvalidAuthorizationInputError, requests.RequestException) as error:
        mapped = _grpc_authorization_error(error)
        await context.abort(mapped.code(), mapped.details())
    if result.decision != "allow":
        outcome = "pending_approval" if result.decision == "approval_required" else "authorization_denied"
        mapped = _grpc_authorization_error(EvaluationOutcomeError(403, outcome, result, None))
        await context.abort(mapped.code(), mapped.details())


def _authorize_server(client: GovernanceClient, options: GRPCAdapterOptions, method: str, rpc_type: str, request: Any, raw_metadata: Metadata, context: grpc.ServicerContext) -> None:
    request_context = _make_request_context(method, rpc_type, request, raw_metadata)
    try:
        authorization = _make_authorization_request(request_context, options)
    except (TypeError, ValueError) as error:
        mapped = _grpc_authorization_error(error)
        context.abort(mapped.code(), mapped.details())
    try:
        result = client.authorize(**authorization)
    except PendingApproval as error:
        _notify_pending(options, request_context, authorization, error)
        mapped = _grpc_authorization_error(error)
        context.abort(mapped.code(), mapped.details())
    except (EvaluationOutcomeError, ClientConfigurationError, InvalidAuthorizationInputError, requests.RequestException) as error:
        mapped = _grpc_authorization_error(error)
        context.abort(mapped.code(), mapped.details())
    if result.decision != "allow":
        outcome = "pending_approval" if result.decision == "approval_required" else "authorization_denied"
        mapped = _grpc_authorization_error(EvaluationOutcomeError(403, outcome, result, None))
        context.abort(mapped.code(), mapped.details())


def _notify_pending(
    options: GRPCAdapterOptions,
    context: GRPCRequestContext,
    authorization: dict[str, Any],
    error: PendingApproval,
) -> None:
    if options.on_pending is not None:
        options.on_pending(context, authorization, error)


def _make_request_context(method: str, rpc_type: str, request: Any, raw_metadata: Optional[Metadata]) -> GRPCRequestContext:
    service, method_name = _split_full_method(method)
    return GRPCRequestContext(method, service, method_name, rpc_type, request, tuple(raw_metadata or ()))


def _make_authorization_request(context: GRPCRequestContext, options: GRPCAdapterOptions) -> dict[str, Any]:
    asset = options.resolve_asset(context)
    if not isinstance(asset, GRPCAssetReference):
        raise TypeError("resolve_asset must return GRPCAssetReference")
    operation_id = options.resolve_operation_id(context) if options.resolve_operation_id else _metadata_value(context.metadata, "idempotency-key")
    operation_id = operation_id.strip() if isinstance(operation_id, str) else ""
    if not operation_id or len(operation_id) > 255 or any(ord(character) < 32 or ord(character) == 127 for character in operation_id):
        raise ValueError("operation_id or idempotency-key must be non-empty, header-safe, and at most 255 characters")
    application_metadata = options.resolve_metadata(context) if options.resolve_metadata else None
    principal_context = options.resolve_principal_context(context) if options.resolve_principal_context else None
    selected_metadata = _selected_metadata(context.metadata, options.metadata_allowlist)
    route_id = options.resolve_route_id(context) if options.resolve_route_id else context.full_method
    transport = {
        "kind": "grpc",
        "grpc": {
            "full_method": context.full_method,
            "service": context.service,
            "method": context.method,
            "rpc_type": context.rpc_type,
            "route_id": route_id,
            "metadata": selected_metadata,
        },
    }
    authorization: dict[str, Any] = {
        "operation_id": operation_id,
        "asset_id": asset.asset_id,
        "asset_key": asset.asset_key,
        "asset_identity": asset.asset_identity,
        "metadata": application_metadata,
        "transport": transport,
        "principal_context": principal_context,
    }
    if options.resolve_approval_retry is not None:
        retry = options.resolve_approval_retry(context)
        if retry is not None:
            if not isinstance(retry, ApprovalRetry):
                raise TypeError("resolve_approval_retry must return ApprovalRetry or None")
            if not retry.approval_id.strip() or not retry.payload_hash.strip():
                raise ValueError("approval retry requires approval_id and payload_hash")
            authorization["approval_id"] = retry.approval_id
            authorization["payload_hash"] = retry.payload_hash
    if options.wait_for_approval_seconds is not None:
        authorization["wait_for_approval_seconds"] = options.wait_for_approval_seconds
    return authorization


def _split_full_method(full_method: str) -> tuple[str, str]:
    parts = full_method.strip().lstrip("/").split("/")
    if not full_method.startswith("/") or len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("gRPC method must use /package.Service/Method form")
    return parts[0], parts[1]


def _metadata_value(metadata: Metadata, name: str) -> Optional[str]:
    wanted = name.lower()
    for key, value in metadata:
        if str(key).lower() == wanted and isinstance(value, str):
            return value
    return None


def _selected_metadata(metadata: Metadata, allowlist: Sequence[str]) -> Dict[str, str]:
    selected: Dict[str, str] = {}
    normalized = {name.strip().lower() for name in allowlist}
    for name in normalized:
        if not name:
            raise ValueError("allowlisted gRPC metadata names must not be empty")
        if name.endswith("-bin") or name in {"authorization", "cookie"} or name.startswith("x-openprodkt-"):
            raise ValueError(f"gRPC metadata {name!r} cannot be copied into transport context")
    for key, value in metadata:
        name = str(key).lower()
        if name in normalized and isinstance(value, str):
            selected[name] = value
    return selected


def _grpc_code_for_http(status_code: Optional[int]) -> grpc.StatusCode:
    outcome = {
        202: "pending_approval",
        400: "invalid_request",
        402: "quota_exceeded",
        403: "authorization_denied",
        404: "approval_not_found",
        409: "operation_conflict",
    }.get(status_code, "pdp_unavailable")
    return _grpc_code_for_outcome(outcome)


def _grpc_details_for_http(status_code: Optional[int]) -> str:
    outcome = {
        202: "pending_approval",
        400: "invalid_request",
        402: "quota_exceeded",
        403: "authorization_denied",
        404: "approval_not_found",
        409: "operation_conflict",
    }.get(status_code, "pdp_unavailable")
    return _grpc_bounded_details(outcome)


def _grpc_authorization_error(error: Exception) -> GRPCAuthorizationError:
    if isinstance(error, PendingApproval):
        outcome = "pending_approval"
    elif isinstance(error, EvaluationOutcomeError):
        outcome = error.outcome
    elif isinstance(error, ClientConfigurationError):
        outcome = "configuration_error"
    elif isinstance(error, InvalidAuthorizationInputError) or isinstance(error, (TypeError, ValueError)):
        outcome = "invalid_request"
    else:
        outcome = "pdp_unavailable"
    return GRPCAuthorizationError(_grpc_code_for_outcome(outcome), _grpc_bounded_details(outcome))


def _grpc_code_for_outcome(outcome: str) -> grpc.StatusCode:
    if outcome == "allow":
        return grpc.StatusCode.OK
    if outcome in {"authorization_denied", "pending_approval", "approval_status_scope_required", "approval_rejected", "approval_expired", "approval_revoked", "approval_consumed"}:
        return grpc.StatusCode.PERMISSION_DENIED
    if outcome in {"approval_not_found", "asset_not_found"}:
        return grpc.StatusCode.NOT_FOUND
    if outcome in {"operation_conflict", "asset_identity_conflict"}:
        return grpc.StatusCode.ALREADY_EXISTS
    if outcome == "quota_exceeded":
        return grpc.StatusCode.RESOURCE_EXHAUSTED
    if outcome == "invalid_request":
        return grpc.StatusCode.INVALID_ARGUMENT
    if outcome == "configuration_error":
        return grpc.StatusCode.FAILED_PRECONDITION
    return grpc.StatusCode.UNAVAILABLE


def _grpc_bounded_details(outcome: str) -> str:
    return json.dumps({"outcome": outcome, "code": outcome}, separators=(",", ":"))[:512]
