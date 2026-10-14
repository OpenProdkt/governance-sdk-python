"""Proxy-only REST upstream. Holds no SDK and must be reachable only through Envoy."""

from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from openprodkt_governance.client import DecisionResult
from pydantic import BaseModel, Field

from .app import RefundConflictError, RefundOrder, RefundStore, _public

IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"


class UpstreamRefundBody(BaseModel):
    amount: float = Field(gt=0, le=1_000_000)


def create_upstream_app(store: RefundStore | None = None) -> FastAPI:
    refund_store = store or RefundStore()
    app = FastAPI(title="OpenProdkt Decision Point Upstream")

    @app.exception_handler(RefundConflictError)
    async def handle_conflict(_request: Request, error: RefundConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"outcome": "refund_conflict", "detail": str(error)})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/refunds")
    def create_refund(
        body: UpstreamRefundBody,
        idempotency_key: Annotated[str, Header(alias="idempotency-key", pattern=IDEMPOTENCY_KEY_PATTERN)],
    ) -> dict[str, object]:
        order = RefundOrder(refund_id=idempotency_key, amount=body.amount)
        refund_store.begin(order, {})
        record = refund_store.execute_once(order.refund_id, DecisionResult(decision="allow"))
        return _public(record)

    return app
