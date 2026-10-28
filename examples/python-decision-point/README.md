# Python decision-point local journey

This service simulates a customer refund endpoint using the OpenProdkt Python SDK. Each refund operation calls `authorize()` once with its stable refund ID and asset key. The PDP asynchronously discovers unknown assets as part of evaluation; the application does not send a discovery envelope first.

The walkthrough proves this sequence:

1. An unregistered asset passes through with `asset_not_registered` and is discovered by the PDP.
2. The discovered asset is promoted in the console.
3. One policy is edited through `allow`, `deny`, and `approval_required`.
4. An approved request executes exactly once when the same refund is retried.

## Prerequisites

- Docker with Compose
- Python 3.10 or newer
- Node.js and npm for the repository E2E checks
- `jq` and `curl`

Run all commands from the repository root unless noted otherwise.

## Install the app and SDK

The SDK version used by this example is `0.7.0`. Install it from this checkout for local development, then install the example:

```bash
python3 -m venv examples/python-decision-point/.venv
examples/python-decision-point/.venv/bin/python -m pip install -e sdk/python
examples/python-decision-point/.venv/bin/python -m pip install -e 'examples/python-decision-point[test]'
examples/python-decision-point/.venv/bin/python -m pytest examples/python-decision-point/tests
```

The `sdk/python` path above is repo-relative and only valid inside this repository. In the public SDK mirror, the example is pinned to the published `openprodkt-governance-sdk[grpc]==0.7.0` release instead.

The application keeps refund state in memory. Restarting it clears all sample records.

## Start the local control plane

```bash
make e2e-ephemeral-up
make e2e-ephemeral-bootstrap

set -a
source e2e/.env.runtime
set +a

export OPK_API_BASE_URL="$E2E_API_BASE_URL"
export OPK_API_KEY="$E2E_API_KEY"
export OPK_ASSET_KEY="payments.refund-api"
export OPK_ASSET_ENVIRONMENT="sandbox"
```

Create the approver group needed by the asset form:

```bash
examples/python-decision-point/.venv/bin/python -m decision_point_app.prepare
```

Keep the printed group name. Start the customer service in another terminal with the same `OPK_*` variables:

```bash
examples/python-decision-point/.venv/bin/python -m uvicorn \
  decision_point_app.app:create_app \
  --factory \
  --app-dir examples/python-decision-point \
  --host 127.0.0.1 \
  --port 18081
```

Verify `curl -sS http://127.0.0.1:18081/health | jq` returns `{"status":"ok"}`.

## 1. Discover and pass through

```bash
curl -sS -X PUT http://127.0.0.1:18081/refunds/refund-unregistered \
  -H 'Content-Type: application/json' \
  -d '{"amount":42.50}' | jq
```

Expected values:

```json
{
  "refund_id": "refund-unregistered",
  "reason": "asset_not_registered",
  "status": "executed",
  "execution_count": 1
}
```

No decision ID is created for this lifecycle pass-through. The PDP creates a separate discovery observation for administrator review.

## 2. Promote the discovery

1. Open `http://127.0.0.1:13000`.
2. Sign in as the `E2E_EMAIL` from `e2e/.env.runtime`.
3. Read the one-time code from Mailpit at `http://127.0.0.1:18025`.
4. Open **Inventory > Discovered Assets**.
5. Find `payments.refund-api` and select **Create asset**.
6. Verify **Asset key** is `payments.refund-api` and the definition contains `operation`.
7. Select the group printed by `decision_point_app.prepare` and select **Create Asset**.
8. To narrow the capability schema later, select the asset card, remove unwanted rows under **Detected fields**, and select **Update Asset**. Keep `metadata.operation` for this walkthrough.

Do not clear the asset key. Keyed SDK decisions resolve the promoted asset through this value.

## 3. Allow

Open **Governance > Policies** and create one policy:

- Name: `Refund lifecycle`
- Asset: `Payments Refund API`
- Decision: `allow`
- Field: `metadata.operation`
- Operator: `=`
- Value: `refund`

Submit another request:

```bash
curl -sS -X PUT http://127.0.0.1:18081/refunds/refund-allow \
  -H 'Content-Type: application/json' \
  -d '{"amount":50}' | tee /tmp/refund-allow.json | jq
```

Expect HTTP `200`, `status=executed`, `policy_id` to be populated, and `execution_count=1`.

## 4. Deny

Select the `Refund lifecycle` policy card, change **Decision** to `deny`, and select **Update Policy**. Keep the condition unchanged.

```bash
curl -sS -X PUT http://127.0.0.1:18081/refunds/refund-deny \
  -H 'Content-Type: application/json' \
  -d '{"amount":60}' | tee /tmp/refund-deny.json | jq
```

Expect HTTP `403`, `outcome=authorization_denied`, `status=authorization_denied`, and `execution_count=0`. The response includes the decision ID, which should match **Governance > Decisions**.

## 5. Require and grant approval

Select the same policy card, change **Decision** to `approval_required`, and select **Update Policy**.

```bash
curl -sS -X PUT http://127.0.0.1:18081/refunds/refund-approval \
  -H 'Content-Type: application/json' \
  -d '{"amount":70}' \
  | tee /tmp/refund-approval.json | jq
```

Expect HTTP `202`, `outcome=pending_approval`, `approval_id` populated, `status=pending_approval`, and `execution_count=0`.

Open **Governance > Approvals**, find the record with the `approval_id` from `/tmp/refund-approval.json`, and select **Approve**. Then send the same PUT again, twice:

```bash
curl -sS -X PUT http://127.0.0.1:18081/refunds/refund-approval \
  -H 'Content-Type: application/json' \
  -d '{"amount":70}' | jq
curl -sS -X PUT http://127.0.0.1:18081/refunds/refund-approval \
  -H 'Content-Type: application/json' \
  -d '{"amount":70}' | jq
curl -sS http://127.0.0.1:18081/refunds/refund-approval | jq
```

The first retry submits the stored `approval_id`/`payload_hash` tuple to the PDP and executes only after the PDP confirms `approvalStatus=consumed`. If the approval is still pending, the response is HTTP `202` again. The second request returns the already-executed refund without another PDP call; `execution_count` remains `1`.

The application supports three ways to complete an approval. Each one retries the same stored `approval_id`/`payload_hash` tuple and executes at most once:

- Sync wait: `PUT /refunds/{refund_id}?wait_seconds=10` (0–30) holds the request open while the SDK polls the approval. The refund executes in that request if the approval arrives in time; otherwise the response is `202`.
- Async poll: `POST /refunds/{refund_id}/poll?wait_seconds=30` (0–300) is intended for a scheduler. It polls the scoped approval with backoff and jitter, retries the tuple once the approval is `approved`, and records `approval_rejected`, `approval_expired`, `approval_revoked`, or `approval_consumed` as terminal states.
- Signed webhook: `POST /webhooks/approvals` accepts `approval.*` events signed with `OPK_WEBHOOK_SECRET`. Invalid signatures return `400` with no state change. Each `eventId` is applied once; a failed redemption returns `503` so the delivery is retried. The route is registered only when `OPK_WEBHOOK_SECRET` is set.

The application state is in memory. Production integrations should persist the pending tuple and processed event IDs in durable storage.

## gRPC refund service

`decision_point_app/grpc_refunds.py` serves `openprodkt.example.refund.v1.RefundService` in two variants. Both reuse the same idempotent `RefundService` and `RefundStore` as the HTTP routes.

- Embedded SDK variant: `create_embedded_grpc_server(...)` installs the SDK server interceptor. Every RPC is authorized before its handler runs, and the handlers contain no authorization logic. A pending approval is recorded through the `on_pending` hook, so the HTTP poll endpoint and the signed webhook resume a gRPC-originated refund the same way. The optional `wait_for_approval_seconds` argument gives a bounded synchronous wait.
- Proxy-upstream variant: `create_upstream_grpc_server(...)` installs no SDK and no interceptor. Bind it only to a network that Envoy can reach, so that callers cannot bypass the ext_authz decision.

Methods: `CreateRefund` (unary, state-changing), `WatchRefund` (server-streaming), `CountRefunds` (client-streaming), and `WatchRefunds` (bidirectional). Streams are authorized once at establishment and are read-only, so they require an `idempotency-key` metadata header. Only `CreateRefund` changes state.

Known limitations of the embedded allow path:

- A refund allowed by the interceptor is recorded with `status=executed`, but `decision_id` and `policy_id` remain empty because the SDK interceptor does not return the decision to the handler.
- Stream authorization covers establishment only. Messages on an authorized stream are not authorized individually.

Regenerate the message module after editing `proto/refund/v1/refund.proto`:

```bash
cd examples/python-decision-point
.venv/bin/python -m grpc_tools.protoc -I proto --python_out=decision_point_app/generated proto/refund/v1/refund.proto
```

## Inspect and regress

In the console:

- Open **Policy revision history** and confirm the same policy ID has `allow`, `deny`, and `approval_required` snapshots.
- Open **Governance > Decisions** and find the three post-promotion decision IDs.
- Open **Audit** and confirm the policy updates and approval event.

Run the focused platform suites:

```bash
make e2e-install
set -a; source e2e/.env.runtime; set +a
cd e2e
npm run test:discovery
npm run test:playground-ui
npm run test:sdk
```

For stack diagnostics and cleanup, return to the repository root:

```bash
make e2e-ephemeral-logs
make e2e-ephemeral-down
```