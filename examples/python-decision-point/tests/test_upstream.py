from __future__ import annotations

from fastapi.testclient import TestClient

from decision_point_app.serve import main
from decision_point_app.upstream import create_upstream_app


def test_upstream_creates_refund_once_and_replays_idempotently() -> None:
    client = TestClient(create_upstream_app())
    headers = {"idempotency-key": "refund-upstream-1"}

    first = client.post("/v1/refunds", json={"amount": 12.5}, headers=headers)
    replay = client.post("/v1/refunds", json={"amount": 12.5}, headers=headers)

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.json()["execution_count"] == first.json()["execution_count"] == 1


def test_upstream_rejects_missing_idempotency_key() -> None:
    client = TestClient(create_upstream_app())

    response = client.post("/v1/refunds", json={"amount": 1})

    assert response.status_code == 422


def test_upstream_reports_conflict_for_reused_key_with_different_amount() -> None:
    client = TestClient(create_upstream_app())
    headers = {"idempotency-key": "refund-upstream-2"}
    client.post("/v1/refunds", json={"amount": 5}, headers=headers)

    response = client.post("/v1/refunds", json={"amount": 6}, headers=headers)

    assert response.status_code == 409


def test_serve_rejects_unknown_mode() -> None:
    assert main(["unknown"]) == 2
