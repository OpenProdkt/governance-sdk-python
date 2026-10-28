from __future__ import annotations

import time
import random
import threading
import math
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

from .asset_identity import AssetIdentity, generate_asset_key
from .metadata import sanitize_metadata


@dataclass
class EntitlementSet:
    source: str
    status: str
    version: str
    organization_id: str
    modules: list[str]
    features: Dict[str, bool]
    limits: Dict[str, int]
    tenant_id: Optional[str] = None
    deployment_id: Optional[str] = None


@dataclass
class BillingSnapshot:
    provider: str
    status: str
    customer_id: Optional[str] = None
    subscription_id: Optional[str] = None
    price_id: Optional[str] = None
    current_period_end: Optional[str] = None
    cancel_at_period_end: bool = False
    canceled_at: Optional[str] = None
    updated_at: Optional[str] = None
    grace_until: Optional[str] = None


@dataclass(frozen=True)
class ApprovalRetry:
    """Stored approval tuple for an explicit retry of one approved operation."""

    approval_id: str
    payload_hash: str


@dataclass
class DecisionResult:
    decision: str
    decision_id: Optional[str] = None
    approval_id: Optional[str] = None
    reason: Optional[str] = None
    policy_id: Optional[str] = None
    version: Optional[str] = None
    operation_id: Optional[str] = None
    payload_hash: Optional[str] = None
    approval_status: Optional[str] = None
    approval_expires_at: Optional[str] = None
    grant_expires_at: Optional[str] = None
    asset_id: Optional[str] = None
    asset_key: Optional[str] = None
    code: Optional[str] = None
    error: Optional[str] = None


class EvaluationOutcomeError(requests.HTTPError):
    def __init__(self, status_code: int, outcome: str, result: DecisionResult, response: requests.Response) -> None:
        super().__init__(f"POST /v1/evaluate returned {status_code}", response=response)
        self.status_code = status_code
        self.outcome = outcome
        self.result = result


class AuthorizationDeniedError(EvaluationOutcomeError):
    pass


class PendingApproval(EvaluationOutcomeError):
    def __init__(
        self,
        result: DecisionResult,
        response: requests.Response,
        *,
        operation_id: str,
        approval_id: str,
        payload_hash: str,
        asset_id: Optional[str],
        asset_key: Optional[str],
        asset_identity: Optional[AssetIdentity],
        status_url: str,
        expires_at: str,
    ) -> None:
        super().__init__(202, "pending_approval", result, response)
        self.operation_id = operation_id
        self.approval_id = approval_id
        self.payload_hash = payload_hash
        self.asset_id = asset_id
        self.asset_key = asset_key
        self.asset_identity = asset_identity
        self.status_url = status_url
        self.expires_at = expires_at


class ApprovalTerminalError(EvaluationOutcomeError):
    pass


class ApprovalWaitCancelledError(InterruptedError):
    def __init__(self, approval_id: str) -> None:
        super().__init__("approval wait cancelled")
        self.approval_id = approval_id


class ApprovalNotFoundError(EvaluationOutcomeError):
    pass


class ApprovalStatusAccessError(EvaluationOutcomeError):
    pass


class OperationStatusAccessError(EvaluationOutcomeError):
    pass


class OperationNotFoundError(EvaluationOutcomeError):
    pass


class AssetIdentityConflictError(EvaluationOutcomeError):
    pass


class OperationConflictError(EvaluationOutcomeError):
    pass


class QuotaExceededError(EvaluationOutcomeError):
    pass


class InvalidEvaluationRequestError(EvaluationOutcomeError):
    pass


class GovernanceConfigurationError(EvaluationOutcomeError):
    pass


class PDPUnavailableError(EvaluationOutcomeError):
    pass


class ClientConfigurationError(ValueError):
    pass


class InvalidAuthorizationInputError(ValueError):
    pass


_EVALUATION_OUTCOMES = {
    403: "denied",
    404: "approval_not_found",
    409: "operation_conflict",
    402: "quota_exceeded",
    400: "invalid_request",
    503: "pdp_unavailable",
}
_EVALUATION_STATUSES = {200, 202, *_EVALUATION_OUTCOMES}


@dataclass(frozen=True)
class PrincipalContext:
    bearer_token: str


@dataclass
class AuditQuery:
    limit: int = 25
    offset: int = 0
    event_type: Optional[str] = None
    actor_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    outcome: Optional[str] = None


@dataclass
class DecisionQuery:
    limit: int = 25
    offset: int = 0
    decision: Optional[str] = None
    status: Optional[str] = None
    asset_id: Optional[str] = None
    policy_id: Optional[str] = None
    search: Optional[str] = None
    from_time: Optional[str] = None
    to_time: Optional[str] = None


class GovernanceClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 5.0,
        default_asset_identity: Optional[AssetIdentity] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.default_asset_identity = default_asset_identity

    def authorize(
        self,
        *,
        operation_id: str,
        asset_id: Optional[str] = None,
        asset_key: Optional[str] = None,
        asset_identity: Optional[AssetIdentity] = None,
        approval_id: Optional[str] = None,
        payload_hash: Optional[str] = None,
        metadata: Any = None,
        transport: Optional[Dict[str, Any]] = None,
        wait_for_approval_seconds: Optional[float] = None,
        poll_interval_seconds: float = 1.0,
        max_poll_interval_seconds: float = 5.0,
        backoff_multiplier: float = 1.5,
        jitter_fraction: float = 0.1,
        cancel_event: Optional[threading.Event] = None,
        principal_context: Optional[PrincipalContext] = None,
    ) -> DecisionResult:
        if wait_for_approval_seconds is not None and (
            not math.isfinite(wait_for_approval_seconds) or wait_for_approval_seconds < 0 or wait_for_approval_seconds > 30
        ):
            raise InvalidAuthorizationInputError("wait_for_approval_seconds must be between 0 and 30")
        if not operation_id.strip():
            raise InvalidAuthorizationInputError("operation_id is required")
        if bool(approval_id) != bool(payload_hash):
            raise InvalidAuthorizationInputError("approval_id and payload_hash must be supplied together")
        bearer_token = self.api_key
        if principal_context is not None:
            bearer_token = principal_context.bearer_token.strip()
            if not bearer_token or "\r" in bearer_token or "\n" in bearer_token:
                raise InvalidAuthorizationInputError("principal bearer_token must be non-empty and header-safe")
        if asset_identity is None and not asset_id and not asset_key:
            asset_identity = self.default_asset_identity
        if asset_identity is not None:
            generated_key = generate_asset_key(
                asset_identity.application,
                asset_identity.service,
                asset_identity.environment,
            )
            if not asset_id and not asset_key:
                asset_key = generated_key
            elif not asset_id and asset_key != generated_key:
                raise InvalidAuthorizationInputError("asset_key does not match asset_identity")
        if not asset_id and not asset_key:
            raise ClientConfigurationError("asset_id or asset_key is required when no default asset identity is configured")
        if asset_id and asset_key:
            raise InvalidAuthorizationInputError("exactly one of asset_id or asset_key is required")
        asset: Dict[str, str] = {}
        if asset_id:
            asset["id"] = asset_id
        elif asset_key:
            asset["key"] = asset_key
        if asset_identity is not None:
            asset["application"] = asset_identity.application
            asset["service"] = asset_identity.service
            asset["environment"] = asset_identity.environment
        payload: Dict[str, Any] = {
            "version": "v1",
            "asset": asset,
            "operation_id": operation_id.strip(),
            "transport": transport or {"kind": "http"},
        }
        if approval_id and payload_hash:
            payload["approval_id"] = approval_id.strip()
            payload["payload_hash"] = payload_hash.strip()
        if metadata is not None:
            try:
                payload["metadata"] = sanitize_metadata(metadata)
            except (TypeError, ValueError) as error:
                raise InvalidAuthorizationInputError(str(error)) from error
        response = requests.post(
            f"{self.base_url}/v1/evaluate",
            json=payload,
            headers={"Authorization": f"Bearer {bearer_token}"},
            timeout=self.timeout_seconds,
        )
        if response.status_code not in _EVALUATION_STATUSES:
            raise requests.RequestException(f"unexpected /v1/evaluate HTTP status {response.status_code}", response=response)
        data = response.json()
        if not isinstance(data, dict):
            raise requests.RequestException("invalid JSON body from /v1/evaluate", response=response)
        if response.status_code in {200, 202} and (not isinstance(data.get("decision"), str) or not data["decision"]):
            raise requests.RequestException("invalid decision body from /v1/evaluate", response=response)
        result = DecisionResult(
            decision=data.get("decision", ""),
            version=data.get("version"),
            operation_id=data.get("operation_id"),
            decision_id=data.get("decisionId"),
            approval_id=data.get("approvalId"),
            reason=data.get("reason"),
            policy_id=data.get("policyId"),
            payload_hash=data.get("payload_hash"),
            approval_status=data.get("approvalStatus"),
            approval_expires_at=data.get("approval_expires_at"),
            grant_expires_at=data.get("grant_expires_at"),
            asset_id=data.get("assetId"),
            asset_key=data.get("assetKey"),
            code=data.get("code"),
            error=data.get("error"),
        )
        expected_decision = {200: "allow", 202: "approval_required"}.get(response.status_code)
        if expected_decision is not None and result.decision != expected_decision:
            raise requests.RequestException(
                f"/v1/evaluate status {response.status_code} conflicts with decision {result.decision!r}",
                response=response,
            )
        if response.status_code == 200 and approval_id and result.approval_status != "consumed":
            raise requests.RequestException("approved retry was not confirmed consumed by /v1/evaluate", response=response)
        if response.status_code == 202:
            pending = self._pending_approval(
                result,
                response,
                operation_id=operation_id.strip(),
                asset_id=asset_id,
                asset_key=asset_key,
                asset_identity=asset_identity,
            )
            if wait_for_approval_seconds:
                return self._wait_for_decision_approval(
                    pending.result,
                    response,
                    wait_for_approval_seconds,
                    operation_id=operation_id.strip(),
                    asset_id=asset_id,
                    asset_key=asset_key,
                    asset_identity=asset_identity,
                    metadata=metadata,
                    transport=transport,
                    principal_context=principal_context,
                    poll_interval_seconds=poll_interval_seconds,
                    max_poll_interval_seconds=max_poll_interval_seconds,
                    backoff_multiplier=backoff_multiplier,
                    jitter_fraction=jitter_fraction,
                    cancel_event=cancel_event,
                )
            raise pending
        if response.status_code in _EVALUATION_OUTCOMES:
            raise self._evaluation_error(response.status_code, result, response)
        if result.decision == "approval_required":
            return self._wait_for_decision_approval(
                result,
                response,
                wait_for_approval_seconds,
                operation_id=operation_id.strip(),
                asset_id=asset_id,
                asset_key=asset_key,
                asset_identity=asset_identity,
                metadata=metadata,
                transport=transport,
                principal_context=principal_context,
                poll_interval_seconds=poll_interval_seconds,
                max_poll_interval_seconds=max_poll_interval_seconds,
                backoff_multiplier=backoff_multiplier,
                jitter_fraction=jitter_fraction,
                cancel_event=cancel_event,
            )
        return result

    def _evaluation_error(self, status_code: int, result: DecisionResult, response: requests.Response) -> EvaluationOutcomeError:
        reason = (result.reason or "").lower()
        code = (result.code or "").lower()
        if status_code == 403:
            if code == "approvals_disabled":
                return GovernanceConfigurationError(status_code, "configuration_error", result, response)
            terminal = {
                "approval_rejected": "approval_rejected",
                "approval_expired": "approval_expired",
                "approval_grant_expired": "approval_expired",
                "approval_revoked": "approval_revoked",
                "approval_consumed": "approval_consumed",
            }
            terminal_reason = reason or code
            if terminal_reason in terminal:
                return ApprovalTerminalError(status_code, terminal[terminal_reason], result, response)
            return AuthorizationDeniedError(status_code, "authorization_denied", result, response)
        if status_code == 404:
            if code == "asset_not_found" or (result.error or "").lower() == "asset not found":
                return EvaluationOutcomeError(status_code, "asset_not_found", result, response)
            return ApprovalNotFoundError(status_code, "approval_not_found", result, response)
        if status_code == 409 and code == "asset_identity_conflict":
            return AssetIdentityConflictError(status_code, "asset_identity_conflict", result, response)
        if status_code == 409:
            return OperationConflictError(status_code, "operation_conflict", result, response)
        if status_code == 402:
            return QuotaExceededError(status_code, "quota_exceeded", result, response)
        if status_code == 400:
            return InvalidEvaluationRequestError(status_code, "invalid_request", result, response)
        return PDPUnavailableError(status_code, "pdp_unavailable", result, response)

    def _pending_approval(
        self,
        result: DecisionResult,
        response: requests.Response,
        *,
        operation_id: str,
        asset_id: Optional[str],
        asset_key: Optional[str],
        asset_identity: Optional[AssetIdentity],
    ) -> PendingApproval:
        approval_id = result.approval_id or ""
        payload_hash = result.payload_hash or ""
        expires_at = result.approval_expires_at or ""
        if not approval_id or not re.fullmatch(r"sha256:[a-f0-9]{64}", payload_hash) or not expires_at:
            raise requests.RequestException("pending evaluation response is missing approval id, payload hash, or expiry", response=response)
        try:
            parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise requests.RequestException("pending evaluation expiry is invalid", response=response) from error
        if parsed_expiry.tzinfo is None:
            raise requests.RequestException("pending evaluation expiry must include a timezone", response=response)
        status_url = f"{self.base_url}/v1/approvals/{quote(approval_id, safe='')}"
        return PendingApproval(
            result,
            response,
            operation_id=result.operation_id or operation_id,
            approval_id=approval_id,
            payload_hash=payload_hash,
            asset_id=result.asset_id or asset_id,
            asset_key=result.asset_key or asset_key,
            asset_identity=asset_identity,
            status_url=status_url,
            expires_at=expires_at,
        )

    def playground_check(self, asset_id: str, *, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"asset_id": asset_id}
        if metadata:
            payload["metadata"] = sanitize_metadata(metadata)
        response = requests.post(
            f"{self.base_url}/v1/playground/decision",
            json=payload,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def request_code(self, email: str) -> Dict[str, Any]:
        response = requests.post(f"{self.base_url}/auth/request-code", json={"email": email}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def verify_code(self, email: str, code: str) -> Dict[str, Any]:
        response = requests.post(f"{self.base_url}/auth/verify", json={"email": email, "code": code}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def register(self, organization_name: str, email: str) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/auth/register",
            json={"organizationName": organization_name, "email": email},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def bootstrap(self, organization_name: str, owner_email: str, tier: str, mode: str) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/bootstrap",
            json={"organizationName": organization_name, "ownerEmail": owner_email, "tier": tier, "mode": mode},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def me(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/me", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def settings(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/settings", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def list_api_keys(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/v1/api-keys", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def create_api_key(self, name: str, scopes: list[str]) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/api-keys",
            json={"name": name, "scopes": scopes},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def rotate_api_key(self, key_id: str) -> Dict[str, Any]:
        response = requests.post(f"{self.base_url}/v1/api-keys/{key_id}/rotate", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def revoke_api_key(self, key_id: str) -> Dict[str, Any]:
        response = requests.post(f"{self.base_url}/v1/api-keys/{key_id}/revoke", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def list_decision_explorer(self, query: DecisionQuery) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": query.limit, "offset": query.offset}
        for key, value in {
            "decision": query.decision,
            "status": query.status,
            "assetId": query.asset_id,
            "policyId": query.policy_id,
            "search": query.search,
            "from": query.from_time,
            "to": query.to_time,
        }.items():
            if value is not None:
                params[key] = value
        response = requests.get(f"{self.base_url}/v1/decision-explorer", params=params, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def list_assets(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/v1/assets", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def create_asset(self, name: str, environment: str, group: str, definition: Optional[Dict[str, Any]] = None, preset_id: Optional[str] = None, preset_version: Optional[str] = None, owner_user_id: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"name": name, "environment": environment, "group": group}
        if definition is not None:
            payload["definition"] = definition
        if preset_id is not None:
            payload["presetId"] = preset_id
        if preset_version is not None:
            payload["presetVersion"] = preset_version
        if owner_user_id is not None:
            payload["ownerUserId"] = owner_user_id
        response = requests.post(f"{self.base_url}/v1/assets", json=payload, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def update_asset(self, asset_id: str, name: str, environment: str, group: str, definition: Optional[Dict[str, Any]] = None, preset_id: Optional[str] = None, preset_version: Optional[str] = None, owner_user_id: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"name": name, "environment": environment, "group": group}
        if definition is not None:
            payload["definition"] = definition
        if preset_id is not None:
            payload["presetId"] = preset_id
        if preset_version is not None:
            payload["presetVersion"] = preset_version
        if owner_user_id is not None:
            payload["ownerUserId"] = owner_user_id
        response = requests.patch(f"{self.base_url}/v1/assets/{asset_id}", json=payload, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def delete_asset(self, asset_id: str) -> Dict[str, Any]:
        response = requests.delete(f"{self.base_url}/v1/assets/{asset_id}", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def ingest_asset_discovery(self, discovery: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(discovery)
        if "metadata" in payload:
            payload["metadata"] = sanitize_metadata(payload["metadata"])
        response = requests.post(f"{self.base_url}/v1/asset-discoveries", json=payload, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def list_asset_discoveries(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/v1/asset-discoveries", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def delete_asset_discovery(self, discovery_id: str) -> Dict[str, Any]:
        response = requests.delete(f"{self.base_url}/v1/asset-discoveries/{discovery_id}", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def list_groups(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/v1/groups", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def create_group(self, name: str, approvers: str) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/groups",
            json={"name": name, "approvers": approvers},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def update_group(self, group_id: str, approvers: str) -> Dict[str, Any]:
        response = requests.patch(
            f"{self.base_url}/v1/groups/{group_id}",
            json={"approvers": approvers},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def delete_group(self, group_id: str) -> Dict[str, Any]:
        response = requests.delete(f"{self.base_url}/v1/groups/{group_id}", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def list_policies(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/v1/policies", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def create_policy(self, asset_id: str, name: str, condition: Dict[str, Any], decision: str) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/policies",
            json={"assetId": asset_id, "name": name, "condition": condition, "decision": decision},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def delete_policy(self, policy_id: str) -> Dict[str, Any]:
        response = requests.delete(f"{self.base_url}/v1/policies/{policy_id}", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def set_policy_active(self, policy_id: str, is_active: bool) -> Dict[str, Any]:
        response = requests.patch(
            f"{self.base_url}/v1/policies/{policy_id}/activation",
            json={"isActive": is_active},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def list_policy_revisions(self, policy_id: str) -> Dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/v1/policies/{policy_id}/revisions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def rollback_policy(self, policy_id: str, revision_id: str) -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/policies/{policy_id}/rollback",
            json={"revisionId": revision_id},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def list_approvals(self, *, limit: int, offset: int = 0, status: Optional[str] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status is not None:
            params["status"] = status
        response = requests.get(f"{self.base_url}/v1/approvals", params=params, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def reject_approval(self, approval_id: str, comment: str) -> Dict[str, Any]:
        response = requests.post(f"{self.base_url}/v1/approvals/{approval_id}/reject", json={"comment": comment}, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def get_approval(self, approval_id: str, *, principal_context: Optional[PrincipalContext] = None) -> Dict[str, Any]:
        bearer_token = self.api_key if principal_context is None else principal_context.bearer_token.strip()
        if not bearer_token or "\r" in bearer_token or "\n" in bearer_token:
            raise ValueError("principal bearer_token must be non-empty and header-safe")
        response = requests.get(f"{self.base_url}/v1/approvals/{approval_id}", headers={"Authorization": f"Bearer {bearer_token}"}, timeout=self.timeout_seconds)
        if response.status_code == 403:
            body = response.json() if response.content else {}
            result = DecisionResult("deny", code=body.get("code"), error=body.get("error"))
            if body.get("code") == "insufficient_scope":
                raise ApprovalStatusAccessError(403, "approval_status_scope_required", result, response)
            raise AuthorizationDeniedError(403, "authorization_denied", result, response)
        if response.status_code == 404:
            raise ApprovalNotFoundError(404, "approval_not_found", DecisionResult("deny"), response)
        response.raise_for_status()
        return response.json()

    def get_approval_status(self, approval_id: str, *, principal_context: Optional[PrincipalContext] = None) -> Dict[str, Any]:
        return self.get_approval(approval_id, principal_context=principal_context)

    def get_operation_status(self, operation_id: str, *, principal_context: Optional[PrincipalContext] = None) -> Dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", operation_id):
            raise InvalidAuthorizationInputError("invalid operation_id")
        bearer_token = self.api_key if principal_context is None else principal_context.bearer_token.strip()
        if not bearer_token or "\r" in bearer_token or "\n" in bearer_token:
            raise InvalidAuthorizationInputError("principal bearer_token must be non-empty and header-safe")
        response = requests.get(f"{self.base_url}/v1/proxy/operations/{quote(operation_id, safe='')}", headers={"Authorization": f"Bearer {bearer_token}"}, timeout=self.timeout_seconds)
        if response.status_code in (403, 404):
            body = response.json() if response.content else {}
            result = DecisionResult("deny", code=body.get("code"), error=body.get("error"), operation_id=operation_id)
            if response.status_code == 404:
                raise OperationNotFoundError(404, "operation_not_found", result, response)
            if body.get("code") == "insufficient_scope":
                raise OperationStatusAccessError(403, "operation_status_scope_required", result, response)
            raise AuthorizationDeniedError(403, "authorization_denied", result, response)
        response.raise_for_status()
        return response.json()

    def wait_for_approval(
        self,
        approval_id: str,
        *,
        timeout_seconds: float = 10.0,
        poll_interval_seconds: float = 1.0,
        max_poll_interval_seconds: float = 5.0,
        backoff_multiplier: float = 1.5,
        jitter_fraction: float = 0.1,
        cancel_event: Optional[threading.Event] = None,
        principal_context: Optional[PrincipalContext] = None,
    ) -> Dict[str, Any]:
        """Poll a single approval until it leaves 'pending' or timeout_seconds elapses.

        Short-wait UX only; async webhook delivery and app-managed retry remain the
        recommended defaults for production workloads.
        """
        if not math.isfinite(timeout_seconds) or timeout_seconds < 0 or timeout_seconds > 300:
            raise ValueError("timeout_seconds must be between 0 and 300")
        if not math.isfinite(poll_interval_seconds) or poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive and finite")
        if not math.isfinite(max_poll_interval_seconds) or max_poll_interval_seconds < poll_interval_seconds:
            raise ValueError("max_poll_interval_seconds must be finite and at least poll_interval_seconds")
        if not math.isfinite(backoff_multiplier) or backoff_multiplier < 1:
            raise ValueError("backoff_multiplier must be finite and at least 1")
        if not math.isfinite(jitter_fraction) or jitter_fraction < 0 or jitter_fraction > 1:
            raise ValueError("jitter_fraction must be between 0 and 1")
        deadline = time.monotonic() + timeout_seconds
        approval = self.get_approval(approval_id, principal_context=principal_context)
        interval = poll_interval_seconds
        while approval.get("status") == "pending" and time.monotonic() < deadline:
            if cancel_event is not None and cancel_event.is_set():
                raise ApprovalWaitCancelledError(approval_id)
            remaining = deadline - time.monotonic()
            jittered_interval = interval * (1 + random.uniform(-jitter_fraction, jitter_fraction))
            delay = min(remaining, jittered_interval)
            if cancel_event is not None:
                if cancel_event.wait(delay):
                    raise ApprovalWaitCancelledError(approval_id)
            else:
                time.sleep(delay)
            approval = self.get_approval(approval_id, principal_context=principal_context)
            interval = min(max_poll_interval_seconds, interval * backoff_multiplier)
        return approval

    def _wait_for_decision_approval(
        self,
        result: DecisionResult,
        response: requests.Response,
        timeout_seconds: float,
        *,
        operation_id: str,
        asset_id: Optional[str],
        asset_key: Optional[str],
        asset_identity: Optional[AssetIdentity],
        metadata: Any,
        transport: Optional[Dict[str, Any]],
        principal_context: Optional[PrincipalContext],
        poll_interval_seconds: float,
        max_poll_interval_seconds: float,
        backoff_multiplier: float,
        jitter_fraction: float,
        cancel_event: Optional[threading.Event],
    ) -> DecisionResult:
        approval_id = result.approval_id
        if not approval_id or not result.payload_hash:
            return result
        try:
            approval = self.wait_for_approval(
                approval_id,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
                max_poll_interval_seconds=max_poll_interval_seconds,
                backoff_multiplier=backoff_multiplier,
                jitter_fraction=jitter_fraction,
                cancel_event=cancel_event,
                principal_context=principal_context,
            )
        except ApprovalWaitCancelledError:
            raise self._pending_approval(
                result,
                response,
                operation_id=operation_id,
                asset_id=asset_id,
                asset_key=asset_key,
                asset_identity=asset_identity,
            )
        status = approval.get("status", "pending")
        result.approval_status = status
        if approval.get("revokedAt"):
            raise ApprovalTerminalError(403, "approval_revoked", result, response)
        if status == "approved":
            return self.authorize(
                operation_id=operation_id,
                asset_id=asset_id,
                asset_key=asset_key,
                asset_identity=asset_identity,
                approval_id=approval_id,
                payload_hash=result.payload_hash,
                metadata=metadata,
                transport=transport,
                principal_context=principal_context,
            )
        if status == "rejected":
            raise ApprovalTerminalError(403, "approval_rejected", result, response)
        if status == "expired":
            raise ApprovalTerminalError(403, "approval_expired", result, response)
        if status == "consumed":
            raise ApprovalTerminalError(403, "approval_consumed", result, response)
        raise self._pending_approval(
            result,
            response,
            operation_id=operation_id,
            asset_id=asset_id,
            asset_key=asset_key,
            asset_identity=asset_identity,
        )

    def list_audit_events(self, query: AuditQuery) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": query.limit, "offset": query.offset}
        for key, value in {
            "eventType": query.event_type,
            "actorId": query.actor_id,
            "resourceType": query.resource_type,
            "resourceId": query.resource_id,
            "outcome": query.outcome,
        }.items():
            if value is not None:
                params[key] = value
        response = requests.get(f"{self.base_url}/v1/audit", params=params, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def usage(self) -> Dict[str, Any]:
        response = requests.get(f"{self.base_url}/v1/usage", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def upload_entitlement_artifact(self, content: bytes, filename: str = "license.json") -> Dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/v1/entitlement/upload",
            files={"license": (filename, content)},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()
