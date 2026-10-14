from __future__ import annotations

import os
import threading
from dataclasses import asdict, dataclass, field, replace
from typing import Annotated, Any, Protocol

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from openprodkt_governance import ApprovalTerminalError, AuthorizationDeniedError, GovernanceClient, PendingApproval
from openprodkt_governance.client import DecisionResult
from openprodkt_governance.fastapi_adapter import (
    build_http_transport_context,
    create_approval_webhook_handler,
    install_fastapi_exception_handlers,
)
from openprodkt_governance.webhook import ApprovalWebhookEvent
from pydantic import BaseModel, Field


class GovernanceAPI(Protocol):
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
    ) -> DecisionResult: ...

    def wait_for_approval(self, approval_id: str, *, timeout_seconds: float) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Settings:
    api_base_url: str
    api_key: str
    asset_key: str = "payments.refund-api"
    asset_environment: str = "development"
    webhook_secret: str = ""

    @classmethod
    def from_environment(cls) -> Settings:
        api_base_url = os.getenv("OPK_API_BASE_URL", "").strip()
        api_key = os.getenv("OPK_API_KEY", "").strip()
        missing = [name for name, value in (("OPK_API_BASE_URL", api_base_url), ("OPK_API_KEY", api_key)) if not value]
        if missing:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
        return cls(
            api_base_url=api_base_url,
            api_key=api_key,
            asset_key=os.getenv("OPK_ASSET_KEY", "payments.refund-api").strip(),
            asset_environment=os.getenv("OPK_ASSET_ENVIRONMENT", "development").strip(),
            webhook_secret=os.getenv("OPK_WEBHOOK_SECRET", "").strip(),
        )


RefundIdPath = Annotated[str, Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")]


class RefundBody(BaseModel):
    amount: float = Field(gt=0, le=1_000_000)


@dataclass(frozen=True)
class RefundOrder:
    refund_id: str
    amount: float


def parse_refund(refund_id: RefundIdPath, body: RefundBody) -> RefundOrder:
    """Validate the request before any authorization call is made."""
    return RefundOrder(refund_id=refund_id, amount=body.amount)


def refund_metadata(order: RefundOrder) -> dict[str, Any]:
    """Application metadata sent with every refund authorization. HTTP and gRPC use the same shape so payload hashes match on resume."""
    return {"operation": "refund", "amount": order.amount}


def http_transport(request: Request) -> dict[str, Any]:
    """Canonical transport context. The same request shape yields the same context on retry."""
    return build_http_transport_context(request)


class RefundConflictError(Exception):
    """The refund_id already exists with a different amount."""


@dataclass
class RefundRecord:
    refund_id: str
    amount: float
    status: str = "created"
    decision_id: str | None = None
    policy_id: str | None = None
    reason: str | None = None
    approval_id: str | None = None
    payload_hash: str | None = None
    approval_expires_at: str | None = None
    execution_count: int = 0
    transport: dict[str, Any] = field(default_factory=dict)


class RefundStore:
    """Integration-layer state.

    Operation creation is durable and keyed by refund_id. Execution is a separate,
    idempotent step, so authorization can complete now or later without duplicating
    the refund.
    """

    def __init__(self) -> None:
        self._records: dict[str, RefundRecord] = {}
        self._refund_by_approval: dict[str, str] = {}
        self._processed_events: set[str] = set()
        # Stream establishments have no refund record; their approval tuple is keyed by operation ID.
        self._stream_retries: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()

    def begin(self, order: RefundOrder, transport: dict[str, Any]) -> RefundRecord:
        with self._lock:
            record = self._records.get(order.refund_id)
            if record is None:
                record = RefundRecord(refund_id=order.refund_id, amount=order.amount, transport=transport)
                self._records[order.refund_id] = record
            elif record.amount != order.amount:
                raise RefundConflictError("refund_id already exists with a different amount")
            return replace(record)

    def get(self, refund_id: str) -> RefundRecord | None:
        with self._lock:
            record = self._records.get(refund_id)
            return replace(record) if record else None

    def record_pending(self, refund_id: str, pending: PendingApproval) -> None:
        """Keep the exact retry tuple so the operation can be resumed later."""
        with self._lock:
            record = self._records[refund_id]
            if record.status == "executed":
                return
            record.status = "pending_approval"
            record.decision_id = pending.result.decision_id
            record.policy_id = pending.result.policy_id
            record.reason = pending.result.reason
            record.approval_id = pending.approval_id
            self._refund_by_approval[pending.approval_id] = refund_id
            record.payload_hash = pending.payload_hash
            record.approval_expires_at = pending.expires_at

    def record_terminal(self, refund_id: str, outcome: str, result: DecisionResult) -> None:
        with self._lock:
            record = self._records[refund_id]
            if record.status == "executed":
                return
            record.status = outcome
            record.decision_id = result.decision_id or record.decision_id
            record.policy_id = result.policy_id or record.policy_id
            record.reason = result.reason or record.reason

    def execute_once(self, refund_id: str, decision: DecisionResult) -> RefundRecord:
        with self._lock:
            record = self._records[refund_id]
            if record.status != "executed":
                record.status = "executed"
                record.execution_count += 1
                record.decision_id = decision.decision_id
                record.policy_id = decision.policy_id
                record.reason = decision.reason
            return replace(record)

    def find_by_approval(self, approval_id: str | None) -> RefundRecord | None:
        with self._lock:
            refund_id = self._refund_by_approval.get(approval_id or "")
            record = self._records.get(refund_id) if refund_id else None
            return replace(record) if record else None

    def record_stream_challenge(self, operation_id: str, pending: PendingApproval) -> None:
        """Keep the retry tuple for a pending stream establishment so the approved retry can carry it."""
        with self._lock:
            self._stream_retries[operation_id] = (pending.approval_id, pending.payload_hash)

    def stream_retry(self, operation_id: str) -> tuple[str, str] | None:
        with self._lock:
            return self._stream_retries.get(operation_id)

    def event_processed(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._processed_events

    def mark_event_processed(self, event_id: str) -> None:
        with self._lock:
            self._processed_events.add(event_id)


class RefundService:
    """Integration layer: owns the authorization call, the pending tuple, and execution."""

    def __init__(self, governance: GovernanceAPI, store: RefundStore, asset_key: str) -> None:
        self._governance = governance
        self._store = store
        self._asset_key = asset_key

    def submit(self, order: RefundOrder, transport: dict[str, Any], *, wait_seconds: float = 0) -> RefundRecord:
        operation = self._store.begin(order, transport)
        if operation.status == "executed":
            return operation

        arguments: dict[str, Any] = {
            "operation_id": order.refund_id,
            "asset_key": self._asset_key,
            "transport": operation.transport,
            "metadata": refund_metadata(order),
        }
        if wait_seconds:
            arguments["wait_for_approval_seconds"] = wait_seconds
        if operation.approval_id and operation.payload_hash:
            arguments["approval_id"] = operation.approval_id
            arguments["payload_hash"] = operation.payload_hash

        try:
            decision = self._governance.authorize(**arguments)
        except PendingApproval as pending:
            self._store.record_pending(order.refund_id, pending)
            raise
        except (AuthorizationDeniedError, ApprovalTerminalError) as error:
            self._store.record_terminal(order.refund_id, error.outcome, error.result)
            raise
        return self._store.execute_once(order.refund_id, decision)

    def record_challenge(self, order: RefundOrder, transport: dict[str, Any], pending: PendingApproval) -> None:
        """Persist a pending approval raised during adapter-level authorization (gRPC interceptors)."""
        self._store.begin(order, transport)
        self._store.record_pending(order.refund_id, pending)

    def execute_authorized(self, order: RefundOrder, transport: dict[str, Any] | None = None) -> RefundRecord:
        """Record execution after an adapter has already allowed the operation. Idempotent per refund_id."""
        self._store.begin(order, transport or {})
        return self._store.execute_once(order.refund_id, DecisionResult(decision="allow"))

    def resume_approved(self, refund_id: str) -> RefundRecord:
        """Retry the stored approval tuple. Execution still happens at most once."""
        record = self._require(refund_id)
        return self.submit(RefundOrder(refund_id=record.refund_id, amount=record.amount), record.transport)

    def poll_pending(self, refund_id: str, *, wait_seconds: float) -> RefundRecord:
        """Poll the scoped approval with SDK backoff, then retry the tuple once it is approved."""
        record = self._require(refund_id)
        if record.status != "pending_approval" or record.approval_id is None:
            return record
        approval = self._governance.wait_for_approval(record.approval_id, timeout_seconds=wait_seconds)
        if approval.get("status") == "approved":
            return self.resume_approved(refund_id)
        outcome = _terminal_outcome(approval)
        if outcome is not None:
            self._store.record_terminal(refund_id, outcome, DecisionResult(decision="deny"))
        return self._require(refund_id)

    def apply_approval_event(self, event: ApprovalWebhookEvent) -> bool:
        """Apply a signed approval event once. Returns False for an event ID that was already applied."""
        if self._store.event_processed(event.event_id):
            return False
        record = self._store.find_by_approval(event.approval_id)
        if record is not None:
            if event.event_type == "approval.approved":
                self.resume_approved(record.refund_id)
            elif event.event_type in TERMINAL_EVENT_OUTCOMES:
                self._store.record_terminal(
                    record.refund_id,
                    TERMINAL_EVENT_OUTCOMES[event.event_type],
                    DecisionResult(decision="deny"),
                )
        self._store.mark_event_processed(event.event_id)
        return True

    def _require(self, refund_id: str) -> RefundRecord:
        record = self._store.get(refund_id)
        if record is None:
            raise KeyError(refund_id)
        return record


TERMINAL_EVENT_OUTCOMES = {
    "approval.rejected": "approval_rejected",
    "approval.expired": "approval_expired",
    "approval.revoked": "approval_revoked",
}


def _terminal_outcome(approval: dict[str, Any]) -> str | None:
    if approval.get("revokedAt"):
        return "approval_revoked"
    state = approval.get("status")
    return f"approval_{state}" if state in {"rejected", "expired", "consumed"} else None


def _public(record: RefundRecord) -> dict[str, Any]:
    body = asdict(record)
    body.pop("transport")
    return body


def create_app(
    settings: Settings | None = None,
    governance: GovernanceAPI | None = None,
    store: RefundStore | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_environment()
    resolved_governance = governance or GovernanceClient(
        resolved_settings.api_base_url,
        resolved_settings.api_key,
    )
    resolved_store = store or RefundStore()
    service = RefundService(resolved_governance, resolved_store, resolved_settings.asset_key)

    app = FastAPI(title="OpenProdkt Decision Point Example")
    install_fastapi_exception_handlers(app)

    @app.exception_handler(RefundConflictError)
    async def refund_conflict_handler(_request: Request, error: RefundConflictError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"outcome": "refund_conflict", "detail": str(error)})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.put("/refunds/{refund_id}")
    def put_refund(
        order: RefundOrder = Depends(parse_refund),
        transport: dict[str, Any] = Depends(http_transport),
        wait_seconds: Annotated[float, Query(ge=0, le=30)] = 0,
    ) -> dict[str, Any]:
        return _public(service.submit(order, transport, wait_seconds=wait_seconds))

    @app.post("/refunds/{refund_id}/poll")
    def poll_refund(
        refund_id: RefundIdPath,
        wait_seconds: Annotated[float, Query(ge=0, le=300)] = 30,
    ) -> dict[str, Any]:
        if resolved_store.get(refund_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="refund_id not found")
        return _public(service.poll_pending(refund_id, wait_seconds=wait_seconds))

    @app.get("/refunds/{refund_id}")
    def get_refund(refund_id: RefundIdPath) -> dict[str, Any]:
        record = resolved_store.get(refund_id)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="refund_id not found")
        return _public(record)

    if resolved_settings.webhook_secret:
        app.post("/webhooks/approvals")(
            create_approval_webhook_handler(resolved_settings.webhook_secret, service.apply_approval_event)
        )

    return app
