from __future__ import annotations

import json
import os
import time

from openprodkt_governance.client import AuditQuery, DecisionQuery, GovernanceClient, PendingApproval


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def main() -> None:
    client = GovernanceClient(required("E2E_API_BASE_URL"), required("E2E_API_KEY"), timeout_seconds=15)
    organization_id = required("E2E_EXPECTED_ORGANIZATION_ID")
    run_id = f"sdk-python-{time.time_ns()}"
    group = asset = None
    policies = []
    try:
        group = client.create_group(f"{run_id}-group", required("E2E_EMAIL"))
        asset = client.create_asset(
            f"{run_id}-asset",
            "local-e2e",
            group["name"],
            {"_fieldMetadata": {"metadata.environment": {"type": "string"}}},
        )
        policies.append(client.create_policy(
            asset["id"],
            f"{run_id}-allow",
            {"field": "metadata.environment", "operator": "=", "value": "development"},
            "allow",
        ))
        policies.append(client.create_policy(
            asset["id"],
            f"{run_id}-approval",
            {"field": "metadata.environment", "operator": "=", "value": "production"},
            "approval_required",
        ))
        decision = client.authorize(asset_id=asset["id"], operation_id=f"{run_id}-allow", metadata={"environment": "development"})
        assert decision.decision == "allow"
        playground = client.playground_check(asset["id"], metadata={"environment": "development"})
        assert playground["organizationId"] == organization_id
        assert playground["decision"] == "allow"
        assert decision.decision_id in json.dumps(client.list_decision_explorer(DecisionQuery(limit=25))["items"])
        assert decision.decision_id in json.dumps(client.list_audit_events(AuditQuery(limit=25))["events"])
        try:
            client.authorize(asset_id=asset["id"], operation_id=f"{run_id}-approval", metadata={"environment": "production"})
        except PendingApproval as pending:
            approval_decision = pending.result
        else:
            raise AssertionError("approval policy did not raise PendingApproval")
        approval = next(
            item for item in client.list_approvals(limit=25, status="pending")["approvals"]
            if item["decisionId"] == approval_decision.decision_id
        )
        resolved = client.approve_approval(approval["id"], "Approved by Python SDK certification")
        assert resolved["status"] == "approved"
        assert resolved["comment"] == "Approved by Python SDK certification"
        assert approval_decision.decision_id in json.dumps(client.list_audit_events(AuditQuery(limit=25))["events"])
        print("Python SDK real API E2E passed")
    finally:
        for policy in reversed(policies):
            client.delete_policy(policy["id"])
        if asset:
            client.delete_asset(asset["id"])
        if group:
            client.delete_group(group["id"])


if __name__ == "__main__":
    main()
