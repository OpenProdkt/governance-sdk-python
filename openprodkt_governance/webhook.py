from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Sequence


APPROVAL_WEBHOOK_TYPES = {
    "approval.pending",
    "approval.approved",
    "approval.rejected",
    "approval.expired",
    "approval.revoked",
}
MAX_WEBHOOK_BODY_BYTES = 256 * 1024
DEFAULT_WEBHOOK_REPLAY_WINDOW_SECONDS = 300


@dataclass(frozen=True)
class ApprovalWebhookEvent:
    event_id: str
    event_type: str
    organization_id: str
    aggregate_id: str
    data: dict[str, Any]

    @property
    def approval_id(self) -> Optional[str]:
        value = self.data.get("approvalId")
        return value if isinstance(value, str) else None


@dataclass(frozen=True)
class WebhookDispatchResult:
    event: ApprovalWebhookEvent
    duplicate: bool


class WebhookVerificationError(ValueError):
    pass


def verify_approval_webhook(
    raw_body: bytes,
    headers: Mapping[str, str],
    secret: str | tuple[str, ...] | list[str],
    *,
    now: Optional[datetime] = None,
    replay_window_seconds: int = DEFAULT_WEBHOOK_REPLAY_WINDOW_SECONDS,
    max_body_bytes: int = MAX_WEBHOOK_BODY_BYTES,
) -> ApprovalWebhookEvent:
    if max_body_bytes <= 0 or max_body_bytes > MAX_WEBHOOK_BODY_BYTES:
        max_body_bytes = MAX_WEBHOOK_BODY_BYTES
    if not isinstance(raw_body, bytes) or not raw_body or len(raw_body) > max_body_bytes:
        raise WebhookVerificationError("webhook body is invalid or exceeds the size limit")
    secrets = (secret,) if isinstance(secret, str) else tuple(secret)
    if not secrets or any(not isinstance(candidate, str) or not candidate for candidate in secrets):
        raise WebhookVerificationError("webhook secret is required")
    if replay_window_seconds <= 0:
        raise WebhookVerificationError("replay window must be positive")

    normalized_headers = {key.lower(): value.strip() for key, value in headers.items()}
    event_id = normalized_headers.get("x-openprodkt-event-id", "")
    timestamp = normalized_headers.get("x-openprodkt-timestamp", "")
    signature = normalized_headers.get("x-openprodkt-signature", "")
    if not event_id or not timestamp or not signature:
        raise WebhookVerificationError("required OpenProdkt webhook headers are missing")
    if len(event_id) > 255 or len(timestamp) > 64:
        raise WebhookVerificationError("webhook header exceeds the size limit")

    try:
        signed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise WebhookVerificationError("webhook timestamp is invalid") from error
    if signed_at.tzinfo is None:
        raise WebhookVerificationError("webhook timestamp must include a timezone")
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        raise ValueError("now must include a timezone")
    if abs((current_time - signed_at).total_seconds()) > replay_window_seconds:
        raise WebhookVerificationError("webhook timestamp is outside the replay window")

    prefix = "v1=sha256="
    if not signature.startswith(prefix):
        raise WebhookVerificationError("webhook signature version is unsupported")
    signature_hex = signature[len(prefix):]
    if len(signature_hex) != 64:
        raise WebhookVerificationError("webhook signature is invalid")
    valid_signature = False
    signed_message = timestamp.encode("utf-8") + b"." + raw_body
    for candidate in secrets:
        expected = hmac.new(candidate.encode("utf-8"), signed_message, hashlib.sha256).hexdigest()
        valid_signature = hmac.compare_digest(signature_hex, expected) or valid_signature
    if not valid_signature:
        raise WebhookVerificationError("webhook signature is invalid")

    try:
        body = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WebhookVerificationError("webhook body is not valid JSON") from error
    if not isinstance(body, dict):
        raise WebhookVerificationError("webhook body must be an object")
    body_event_id = body.get("eventId")
    event_type = body.get("eventType")
    organization_id = body.get("organizationId")
    aggregate_id = body.get("aggregateId")
    data = body.get("data")
    if body_event_id != event_id:
        raise WebhookVerificationError("webhook event ID header does not match body")
    if not isinstance(event_type, str) or event_type not in APPROVAL_WEBHOOK_TYPES:
        raise WebhookVerificationError("webhook event type is unsupported")
    if not isinstance(organization_id, str) or not organization_id:
        raise WebhookVerificationError("webhook organization ID is required")
    if not isinstance(aggregate_id, str) or not aggregate_id:
        raise WebhookVerificationError("webhook aggregate ID is required")
    if not isinstance(data, dict):
        raise WebhookVerificationError("webhook data must be an object")
    if not isinstance(data.get("approvalId"), str) or not data["approvalId"]:
        raise WebhookVerificationError("webhook approval ID is required")
    return ApprovalWebhookEvent(event_id, event_type, organization_id, aggregate_id, data)


def dispatch_approval_webhook(
    raw_body: bytes,
    headers: Mapping[str, str],
    secret: str | Sequence[str],
    dispatch: Callable[[ApprovalWebhookEvent], bool],
    **verification_options: Any,
) -> WebhookDispatchResult:
    """Verify, then dispatch once to an application-owned durable deduplicator.

    The callback must atomically persist/deduplicate ``event.event_id`` with its
    operation-state update and return False when that event was already handled.
    The SDK never executes stored business payloads.
    """
    event = verify_approval_webhook(raw_body, headers, secret, **verification_options)
    processed = dispatch(event)
    return WebhookDispatchResult(event=event, duplicate=not processed)