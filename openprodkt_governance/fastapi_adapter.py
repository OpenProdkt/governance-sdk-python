from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Sequence

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

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
from .webhook import WebhookVerificationError, dispatch_approval_webhook


@dataclass(frozen=True)
class HTTPAssetReference:
    asset_id: Optional[str] = None
    asset_key: Optional[str] = None
    asset_identity: Optional[AssetIdentity] = None


def install_fastapi_exception_handlers(app: FastAPI, *, retry_after_seconds: int = 1) -> None:
    if retry_after_seconds < 1 or retry_after_seconds > 3600:
        raise ValueError("retry_after_seconds must be between 1 and 3600")

    async def evaluation_outcome_handler(_request: Request, error: EvaluationOutcomeError) -> JSONResponse:
        status_code = _fastapi_status(error)
        result = error.result
        body: dict[str, Any] = {"outcome": error.outcome}
        if result.decision:
            body["decision"] = result.decision
        for key, value in (
            ("operation_id", error.operation_id if isinstance(error, PendingApproval) else result.operation_id),
            ("decision_id", result.decision_id),
            ("approval_id", error.approval_id if isinstance(error, PendingApproval) else result.approval_id),
            ("payload_hash", error.payload_hash if isinstance(error, PendingApproval) else result.payload_hash),
            ("approval_status", result.approval_status),
            ("approval_expires_at", error.expires_at if isinstance(error, PendingApproval) else result.approval_expires_at),
            ("status_url", error.status_url if isinstance(error, PendingApproval) else None),
            ("reason", result.reason),
        ):
            if value is not None:
                body[key] = value
        headers = {"Cache-Control": "no-store"} if isinstance(error, PendingApproval) else {}
        if isinstance(error, PendingApproval):
            headers["Retry-After"] = str(retry_after_seconds)
        return JSONResponse(status_code=status_code, content=body, headers=headers)

    async def invalid_input_handler(_request: Request, _error: InvalidAuthorizationInputError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"outcome": "invalid_request", "code": "invalid_request"})

    async def configuration_handler(_request: Request, _error: ClientConfigurationError) -> JSONResponse:
        return JSONResponse(status_code=500, content={"outcome": "configuration_error", "code": "configuration_error"})

    async def transport_handler(_request: Request, _error: requests.RequestException) -> JSONResponse:
        return JSONResponse(status_code=503, content={"outcome": "pdp_unavailable", "code": "pdp_unavailable"})

    app.add_exception_handler(EvaluationOutcomeError, evaluation_outcome_handler)
    app.add_exception_handler(InvalidAuthorizationInputError, invalid_input_handler)
    app.add_exception_handler(ClientConfigurationError, configuration_handler)
    app.add_exception_handler(requests.RequestException, transport_handler)


def create_approval_webhook_handler(
    secret: str | Sequence[str],
    dispatch: Callable[[Any], bool],
    **verification_options: Any,
) -> Callable[[Request], Any]:
    async def handle_approval_webhook(request: Request) -> JSONResponse:
        raw_body = await request.body()
        try:
            result = await asyncio.to_thread(
                dispatch_approval_webhook,
                raw_body,
                dict(request.headers),
                secret,
                dispatch,
                **verification_options,
            )
        except WebhookVerificationError as error:
            raise HTTPException(status_code=400, detail="invalid OpenProdkt webhook") from error
        except Exception as error:
            raise HTTPException(status_code=503, detail="webhook processing unavailable") from error
        return JSONResponse(
            status_code=200,
            content={"event_id": result.event.event_id, "duplicate": result.duplicate},
        )

    return handle_approval_webhook


def _fastapi_status(error: EvaluationOutcomeError) -> int:
    if isinstance(error, PendingApproval) or error.outcome == "pending_approval":
        return 202
    if error.outcome in {"authorization_denied", "approval_rejected", "approval_expired", "approval_revoked", "approval_consumed"}:
        return 403
    if error.outcome == "approval_status_scope_required":
        return 403
    if error.outcome in {"approval_not_found", "asset_not_found"}:
        return 404
    if error.outcome in {"asset_identity_conflict", "operation_conflict"}:
        return 409
    if error.outcome == "quota_exceeded":
        return 402
    if error.outcome == "invalid_request":
        return 400
    if error.outcome == "configuration_error":
        return 500
    return 503


def create_authorization_dependency(
    client: GovernanceClient,
    *,
    resolve_asset: Callable[[Request], HTTPAssetReference],
    resolve_metadata: Optional[Callable[[Request, Any], Any]] = None,
    resolve_principal_context: Optional[Callable[[Request], Optional[PrincipalContext]]] = None,
    resolve_operation_id: Optional[Callable[[Request], Optional[str]]] = None,
    resolve_host: Optional[Callable[[Request], Optional[str]]] = None,
    resolve_route_id: Optional[Callable[[Request], Optional[str]]] = None,
    resolve_approval_retry: Optional[Callable[[Request], Optional[ApprovalRetry]]] = None,
    header_allowlist: Sequence[str] = (),
    wait_for_approval_seconds: Optional[float] = None,
) -> Callable[[Request], Any]:
    """Create a FastAPI dependency that authorizes one request through the SDK.

    The host application is responsible for authenticating principals and returning
    their validated bearer token from ``resolve_principal_context``. Request headers
    are copied only when explicitly allowlisted; Authorization, cookies, and
    caller-supplied OpenProdkt headers are never forwarded as transport attributes.
    """
    normalized_headers = _validate_header_allowlist(header_allowlist)

    async def authorize_request(request: Request) -> DecisionResult:
        operation_id = resolve_operation_id(request) if resolve_operation_id else None
        if not operation_id:
            operation_id = request.headers.get("idempotency-key")
        operation_id = _validate_operation_id(operation_id)

        asset = resolve_asset(request)
        if not isinstance(asset, HTTPAssetReference):
            raise TypeError("resolve_asset must return HTTPAssetReference")
        metadata = resolve_metadata(request, await request.json()) if resolve_metadata else None
        principal_context = resolve_principal_context(request) if resolve_principal_context else None
        transport = build_http_transport_context(
            request,
            header_allowlist=normalized_headers,
            resolve_host=resolve_host,
            resolve_route_id=resolve_route_id,
        )
        approval_retry = resolve_approval_retry(request) if resolve_approval_retry else None
        if approval_retry is not None and not isinstance(approval_retry, ApprovalRetry):
            raise TypeError("resolve_approval_retry must return ApprovalRetry or None")
        return await asyncio.to_thread(
            client.authorize,
            operation_id=operation_id,
            asset_id=asset.asset_id,
            asset_key=asset.asset_key,
            asset_identity=asset.asset_identity,
            metadata=metadata,
            transport=transport,
            principal_context=principal_context,
            approval_id=approval_retry.approval_id if approval_retry else None,
            payload_hash=approval_retry.payload_hash if approval_retry else None,
            wait_for_approval_seconds=wait_for_approval_seconds,
        )

    return authorize_request


def build_http_transport_context(
    request: Request,
    *,
    header_allowlist: Sequence[str] = (),
    resolve_host: Optional[Callable[[Request], Optional[str]]] = None,
    resolve_route_id: Optional[Callable[[Request], Optional[str]]] = None,
) -> Dict[str, Any]:
    """Build the canonical HTTP transport context for one FastAPI request.

    Only allowlisted headers are copied. The same request shape always yields the same
    transport context, which is what allows an explicit approval retry to be validated
    by the PDP against the original operation.
    """
    normalized_headers = _validate_header_allowlist(header_allowlist)
    route = request.scope.get("route")
    route_id = resolve_route_id(request) if resolve_route_id else getattr(route, "path", None)
    selected_headers = {
        name: value
        for name in normalized_headers
        if (value := request.headers.get(name)) is not None
    }
    return {
        "kind": "http",
        "http": {
            "method": request.method.upper(),
            "path": request.url.path,
            "host": resolve_host(request) if resolve_host else request.url.hostname,
            "scheme": request.url.scheme,
            "route_id": route_id,
            "headers": selected_headers,
        },
    }


def _validate_operation_id(value: Optional[str]) -> str:
    operation_id = value.strip() if isinstance(value, str) else ""
    if not operation_id or len(operation_id) > 255 or any(ord(character) < 32 or ord(character) == 127 for character in operation_id):
        raise ValueError("operation_id or Idempotency-Key must be a non-empty, header-safe value of at most 255 characters")
    return operation_id


def _validate_header_allowlist(headers: Sequence[str]) -> tuple[str, ...]:
    normalized = []
    for header in headers:
        name = header.strip().lower()
        if not name:
            raise ValueError("allowlisted HTTP header names must not be empty")
        if name in {"authorization", "cookie", "set-cookie", "host"} or name.startswith("x-openprodkt-"):
            raise ValueError(f"HTTP header {name!r} cannot be copied into transport context")
        if name not in normalized:
            normalized.append(name)
    return tuple(normalized)
