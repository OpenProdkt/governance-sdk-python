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

### Definition observation (optional)

`authorize(..., definition_observation=...)` and the `definition_observation` member of an `EvaluateRequest` carry optional, untrusted evidence of the called MCP tool's definition: `{"digest": "sha256:<64 lowercase hex>", "canon": "mcp-tool-definition:v1", "server_version": "<optional>"}`. `server_version` is optional (1 to 128 characters, no control characters) and the encoded object is at most 512 bytes. The SDK sends the digest only (never a description or schema), omits the field when it is unset, never computes a digest, and raises `InvalidAuthorizationInputError` for a malformed value before any request is sent. Because the caller supplies it, the observation is evidence, not proof.

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

## Vault envelopes (optional)

`openprodkt_governance.vault` seals a JSON record into an encrypted envelope (`opk-vault.v1`, AES-256-GCM) and can write it to object storage that you own. It runs entirely in your process and makes no network calls of its own: you supply the key service (`KeyBackend`) and the object store (`ObjectWriter`).

```bash
pip install "openprodkt-governance-sdk[vault]"
```

The `cryptography` package is imported only when you seal, open, or create a `MemoryBackend`; `import openprodkt_governance` and `import openprodkt_governance.vault` work without it.

```python
from datetime import timedelta
from openprodkt_governance.vault import (
	MemoryBackend, MemoryObjectWriter, VaultWriter, VaultWriterConfig, open_envelope, seal,
)

backend = MemoryBackend()  # tests only; use your own KeyBackend for a real key service
envelope = seal(backend, "alias/my-key", "input", "org_1", "op-1", {"tool": "pay", "amount": 12})
header, record = open_envelope(backend, envelope)  # record: canonical JSON bytes

writer = VaultWriter(VaultWriterConfig(
	backend=backend, objects=MemoryObjectWriter(), key_ref="alias/my-key",
	retention_mode="GOVERNANCE", retention_period=timedelta(days=30),
))
pointer = writer.write("input", "org_1", "op-1", 1, {"tool": "pay"})  # no record content or key material
```

- Each seal uses a fresh data key from your key service and a fresh 12-byte nonce. Destroying the key in your key service makes the stored ciphertext unreadable.
- A record is a JSON object of at most 8 MiB, given as a mapping or JSON text. Numbers must be integers within ±(2^53−1); integral spellings such as `1.0` and `1e2` are written as integers, and fractions, `NaN` and `Infinity` are refused. The record is stored as RFC 8785 canonical JSON.
- Errors are fixed text and never contain record content, keys, or wrapped keys. An envelope that cannot be opened raises `EnvelopeError`; a failing key service raises `KeyBackendError` (`KeyDestroyedError`, `KeyNotFoundError` and `InvalidWrappedKeyError` are also `KeyBackendError` when the key service reports them).
- `MemoryBackend` and `MemoryObjectWriter` keep everything in process memory for tests. This package does not replace access control on your key service or storage; the protection of stored records depends on how you manage those keys and that storage.
## Vault evidence

Pass `vault=` to `client.guard` to store records you supply, in your own storage, and send only a pointer to each stored record. Without it nothing changes.

```python
result = client.guard(
    request, callback, principal_context=principal,
    vault={
        "writer": writer,                        # a VaultWriter, or any object with the same write method
        "organization_id": "org_1",
        "input": {"v": 1, "text": prompt_text},  # stored before the evaluation
        "output": lambda value: {"v": 1, "text": value.text},  # optional; stored after the call returned
        "continue_without_vault": False,         # default
    },
)
```

- The input record is written first and its pointer is sent as `vault_ref` on the evaluation request. The output record is written only after the callback returned normally, and its pointer is sent as `vault_ref` on the outcome report. Returning `None` from `output` skips the output write. Records are never sent to the service.
- By default the guard fails closed: if the input write fails it raises `VaultWriteError` and neither evaluates nor calls your callback. `VaultWriteError.reason` is one of `key_service_unavailable`, `storage_unavailable`, `record_too_large`, `write_failed`; the message carries no other detail. With `continue_without_vault` set to `True` the guard continues and sends `vault_gap` with that reason instead of a pointer.
- If the output write fails, the call has already run: its result is returned unchanged and the real outcome is reported with `vault_gap` and no pointer. This holds in both modes. A raising `output` function is reported the same way (`write_failed`).
- If the callback raises, the outcome is `unknown` as before and no output record is written.
- Without `output`, the guard still never reads, hashes, logs or sends the callback result. When you supply `output`, you choose to hand the result to your vault writer.
- Records must fit the vault profile: fractional numbers are refused, so carry them as strings (for example `{"ratio": "0.25"}`).
- `evaluate_proxy` and `report_operation_outcome` also accept an optional `vault_ref` (kind `input` on evaluation, `output` on outcomes) or `vault_gap`, never both. `vault_ref_from_pointer(pointer)` builds the pointer from a `VaultWriter` result. An invalid combination raises `InvalidAuthorizationInputError` before any request is sent.
- The service may ignore these members, and the guard does not check what the service does with them.
