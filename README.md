# Python SDK

## Install

```bash
pip install openprodkt-governance-sdk
```

For the optional FastAPI dependency adapter:

```bash
pip install "openprodkt-governance-sdk[fastapi]"
```

For gRPC interceptors, install the optional extra:

```bash
pip install "openprodkt-governance-sdk[grpc]"
```

## Supports

The Python client exposes the same current surface as the Go and TypeScript SDKs:

- Auth: `request_code`, `verify_code`, `register`, `me`, `settings`; internal-admin `bootstrap`

`bootstrap` uses the client's bearer credential and requires an internal admin token with the `org:bootstrap` scope. A tenant API key cannot bootstrap organizations.
- Governance: `authorize`, `playground_check`, `list_decision_explorer`, `list_audit_events`, `usage`
- Resources: `list_assets`, `create_asset`, `update_asset`, `delete_asset`, `ingest_asset_discovery`, `list_asset_discoveries`, `delete_asset_discovery`, `list_groups`, `create_group`, `update_group`, `delete_group`, `list_policies`, `create_policy`, `delete_policy`
- Operations: `list_api_keys`, `create_api_key`, `rotate_api_key`, `revoke_api_key`, `list_approvals`, `reject_approval` (requires a user JWT), `upload_entitlement_artifact`

## Usage

```python
from openprodkt_governance import AssetIdentity, GovernanceClient

client = GovernanceClient(
	"http://localhost:8080",
	"opk_live_xxx",
	default_asset_identity=AssetIdentity("billing", "invoice-api", "production"),
)
decision = client.authorize(operation_id="invoice-123", metadata={"amount": 125})
print(decision.decision, decision.decision_id)

profile = client.me()
print(profile)
```

Framework adapters may pass `PrincipalContext` with a bearer credential already validated by the host application. The SDK sends it only in the `Authorization` header; it is never copied into evaluation JSON or metadata.

`openprodkt_governance.fastapi_adapter.create_authorization_dependency()` builds HTTP transport context from a FastAPI `Request`. Provide callbacks that resolve the asset, application metadata, and already-validated principal; the adapter uses `Idempotency-Key` when no explicit operation ID resolver is provided and forwards only allowlisted headers.

Register the central HTTP outcome mapping on the FastAPI application with `install_fastapi_exception_handlers(app)`. It maps pending challenges to 202 with `Cache-Control: no-store` and `Retry-After`, and maps denial, quota, invalid input, configuration, conflict, and PDP failure to their contract statuses. Import this optional integration from `openprodkt_governance.fastapi_adapter`; the base SDK does not require FastAPI.

The Python gRPC interceptors map pending/denied/terminal approval to `PERMISSION_DENIED`, quota to `RESOURCE_EXHAUSTED`, collisions to `ALREADY_EXISTS`, invalid requests to `INVALID_ARGUMENT`, configuration to `FAILED_PRECONDITION`, and PDP failures to `UNAVAILABLE`. Details contain only a bounded outcome/code pair, never the raw PDP body or credentials.

The optional `openprodkt_governance.grpc_adapter` module provides client and server interceptors for all four RPC cardinalities. Streaming calls are authorized once when the RPC is established; message contents are not inspected.

`GovernanceClient.authorize()` sends one `/v1/evaluate` request per operation attempt. Allow and lifecycle pass-through return normally; HTTP 202 raises `PendingApproval` with the stable operation ID, PDP-issued approval ID/hash, asset reference, status URL, and expiry. `wait_for_approval_seconds` performs bounded polling and returns only after an approved retry is consumed. Denial, terminal approval, quota, collision, invalid input/configuration, and PDP failures have distinct typed outcomes. Asset-discovery methods remain separate administrative inventory APIs and are not part of `authorize()`.

`verify_approval_webhook(raw_body, headers, secret)` verifies the `v1=sha256=` HMAC over the exact timestamp header, `.` and raw body bytes, and enforces a replay window. Supply current and previous secrets during rotation. `create_approval_webhook_handler()` provides a FastAPI endpoint wrapper; its callback must atomically deduplicate `event.event_id` with durable operation state. Supported events include pending, approved, rejected, expired, and revoked; the SDK never executes webhook payloads.

Bounded synchronous waits accept `poll_interval_seconds`, `max_poll_interval_seconds`, `backoff_multiplier`, `jitter_fraction`, and a `threading.Event` `cancel_event`. Timeout or cancellation raises the original `PendingApproval`; use `get_approval_status()` or `wait_for_approval()` for asynchronous status/retry flows. API keys that poll must include the `approvals:read` scope; otherwise `ApprovalStatusAccessError` reports the missing scope instead of a generic PDP failure.

Authorization metadata accepts mappings, dataclass instances, and Pydantic v2 models. Dataclasses are converted from declared fields and Pydantic models use `model_dump(mode="json")`; the result must be JSON-compatible and within the SDK metadata limit. Unsupported objects and non-finite numbers are rejected before network I/O.

`verify_approval_webhook(raw_body, headers, secret)` validates the versioned HMAC over the exact timestamp header, a dot, and raw body bytes; it enforces the replay window and returns a typed lifecycle event with its outbox `event_id`. `dispatch_approval_webhook()` passes that event to an application callback. The callback must atomically deduplicate the event ID with its durable operation update; the SDK never executes business payloads.

```python
import grpc
from openprodkt_governance.grpc_adapter import (
	GRPCAdapterOptions,
	GRPCAssetReference,
	create_grpc_client_interceptors,
	create_grpc_server_interceptor,
)

options = GRPCAdapterOptions(
	resolve_asset=lambda _context: GRPCAssetReference(asset_key="billing.refund-api.production"),
	metadata_allowlist=("x-region",),
)
channel = grpc.intercept_channel(
	grpc.insecure_channel("localhost:50051"),
	*create_grpc_client_interceptors(governance_client, options),
)
server = grpc.server(
	thread_pool,
	interceptors=(create_grpc_server_interceptor(governance_client, options),),
)
```

Framework adapters may pass `PrincipalContext` with the bearer credential they have already validated for the request. It is sent only in the `Authorization` header, never in evaluation metadata or JSON.