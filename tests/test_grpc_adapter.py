from __future__ import annotations

import asyncio
import unittest
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

try:
    import grpc
    from openprodkt_governance.grpc_adapter import (
        GRPCAdapterOptions,
        GRPCAssetReference,
        GRPCAuthorizationError,
        GRPCServerInterceptor,
        StreamStreamClientInterceptor,
        StreamUnaryClientInterceptor,
        UnaryStreamClientInterceptor,
        UnaryUnaryClientInterceptor,
        _grpc_authorization_error,
        _grpc_code_for_http,
        _grpc_code_for_outcome,
        create_grpc_aio_client_interceptors,
        create_grpc_aio_server_interceptor,
        create_grpc_client_interceptors,
    )
    from openprodkt_governance.asset_identity import AssetIdentity
    from openprodkt_governance.client import ApprovalRetry, DecisionResult, EvaluationOutcomeError, GovernanceClient, PrincipalContext

    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False


def _canonical_equivalence_fixture() -> dict:
    fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "pep-conformance.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))["canonical_equivalence"]


def _canonical_payload_hash() -> str:
    return _canonical_equivalence_fixture()["approval_retry"]["payload_hash"]


@unittest.skipUnless(GRPC_AVAILABLE, "install the optional grpc SDK extra to run interceptor tests")
class GRPCAdapterTests(unittest.TestCase):
    def test_pending_evaluation_maps_to_permission_denied(self) -> None:
        self.assertEqual(_grpc_code_for_http(202), grpc.StatusCode.PERMISSION_DENIED)

    def test_typed_outcomes_map_to_canonical_codes_and_bounded_details(self) -> None:
        expected = {
            "authorization_denied": grpc.StatusCode.PERMISSION_DENIED,
            "pending_approval": grpc.StatusCode.PERMISSION_DENIED,
            "approval_expired": grpc.StatusCode.PERMISSION_DENIED,
            "approval_not_found": grpc.StatusCode.NOT_FOUND,
            "operation_conflict": grpc.StatusCode.ALREADY_EXISTS,
            "asset_identity_conflict": grpc.StatusCode.ALREADY_EXISTS,
            "quota_exceeded": grpc.StatusCode.RESOURCE_EXHAUSTED,
            "invalid_request": grpc.StatusCode.INVALID_ARGUMENT,
            "configuration_error": grpc.StatusCode.FAILED_PRECONDITION,
            "pdp_unavailable": grpc.StatusCode.UNAVAILABLE,
        }
        for outcome, code in expected.items():
            with self.subTest(outcome=outcome):
                error = EvaluationOutcomeError(403, outcome, DecisionResult("deny"), Mock())
                mapped = _grpc_authorization_error(error)
                self.assertEqual(mapped.code(), code)
                self.assertLessEqual(len(mapped.details().encode("utf-8")), 512)
                details = json.loads(mapped.details())
                self.assertEqual(details, {"outcome": outcome, "code": outcome})
                self.assertNotIn("verified-user-token", mapped.details())

    def test_shared_grpc_status_vectors(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "pep-conformance.json"
        vectors = json.loads(fixture_path.read_text(encoding="utf-8"))["outcomes"]
        for vector in vectors:
            with self.subTest(outcome=vector["outcome"]):
                self.assertEqual(_grpc_code_for_outcome(vector["outcome"]).value[0], vector["grpc_status"])

    def test_stream_establishment_carries_stored_approval_retry_tuple(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="allow")
        retry = ApprovalRetry(approval_id="apr_stream", payload_hash=_canonical_payload_hash())
        options = replace(self.options, resolve_approval_retry=lambda _context: retry)
        interceptor = StreamStreamClientInterceptor(client, options)
        details = SimpleNamespace(method="/payments.PaymentService/Watch", metadata=(("idempotency-key", "refund-stream"),))
        result = interceptor.intercept_stream_stream(lambda _details, _request: "stream", details, iter(()))
        self.assertEqual(result, "stream")
        authorization = client.authorize.call_args.kwargs
        self.assertEqual(authorization["approval_id"], "apr_stream")
        self.assertEqual(authorization["payload_hash"], retry.payload_hash)
        self.assertEqual(authorization["operation_id"], "refund-stream")

    def test_incomplete_approval_retry_tuple_is_rejected_before_pdp_call(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="allow")
        options = replace(self.options, resolve_approval_retry=lambda _context: ApprovalRetry("apr_stream", " "))
        interceptor = StreamStreamClientInterceptor(client, options)
        details = SimpleNamespace(method="/payments.PaymentService/Watch", metadata=(("idempotency-key", "refund-stream"),))
        with self.assertRaises(GRPCAuthorizationError) as raised:
            interceptor.intercept_stream_stream(lambda _details, _request: "stream", details, iter(()))
        self.assertEqual(raised.exception.code(), grpc.StatusCode.INVALID_ARGUMENT)
        client.authorize.assert_not_called()

    def test_http_and_grpc_produce_equivalent_canonical_requests(self) -> None:
        try:
            from starlette.requests import Request
            from openprodkt_governance.fastapi_adapter import HTTPAssetReference, create_authorization_dependency
        except ImportError:
            self.skipTest("install the fastapi SDK extra to run HTTP/gRPC equivalence")
        fixture = _canonical_equivalence_fixture()
        retry = ApprovalRetry(**fixture["approval_retry"])
        principal = PrincipalContext(fixture["principal_bearer_token"])
        metadata = fixture["metadata"]
        asset_key = fixture["asset_key"]

        http_client = Mock(spec=GovernanceClient)
        http_client.authorize.return_value = DecisionResult(decision="allow")
        dependency = create_authorization_dependency(
            http_client,
            resolve_asset=lambda _request: HTTPAssetReference(asset_key=asset_key),
            resolve_metadata=lambda _request, _body: metadata,
            resolve_principal_context=lambda _request: principal,
            resolve_operation_id=lambda _request: fixture["operation_id"],
            resolve_host=lambda _request: fixture["http"]["host"],
            resolve_route_id=lambda _request: fixture["http"]["route_id"],
            resolve_approval_retry=lambda _request: retry,
        )
        http_scope = {
            "type": "http",
            "method": fixture["http"]["method"],
            "path": fixture["http"]["path"],
            "query_string": b"",
            "headers": [],
            "scheme": fixture["http"]["scheme"],
            "server": (fixture["http"]["host"], 443),
        }

        async def receive() -> dict:
            return {"type": "http.request", "body": b"{}", "more_body": False}

        asyncio.run(dependency(Request(http_scope, receive)))
        http_call = http_client.authorize.call_args.kwargs

        grpc_client = Mock(spec=GovernanceClient)
        grpc_client.authorize.return_value = DecisionResult(decision="allow")
        grpc_options = GRPCAdapterOptions(
            resolve_asset=lambda _context: GRPCAssetReference(asset_key=asset_key),
            resolve_metadata=lambda _context: metadata,
            resolve_principal_context=lambda _context: principal,
            resolve_operation_id=lambda _context: fixture["operation_id"],
            resolve_route_id=lambda _context: fixture["grpc"]["route_id"],
            resolve_approval_retry=lambda _context: retry,
        )
        interceptor = UnaryUnaryClientInterceptor(grpc_client, grpc_options)
        details = SimpleNamespace(method=fixture["grpc"]["full_method"], metadata=())
        interceptor.intercept_unary_unary(lambda _details, _request: "ok", details, {"amount": 10})
        grpc_call = grpc_client.authorize.call_args.kwargs

        self.assertEqual(http_call["transport"]["kind"], "http")
        self.assertEqual(grpc_call["transport"]["kind"], "grpc")
        for field in ("operation_id", "asset_key", "metadata", "approval_id", "payload_hash"):
            with self.subTest(field=field):
                self.assertEqual(http_call[field], grpc_call[field])
        self.assertEqual(http_call["operation_id"], fixture["operation_id"])
        self.assertEqual(http_call["approval_id"], retry.approval_id)
        self.assertEqual(http_call["payload_hash"], retry.payload_hash)
        self.assertEqual(http_call["principal_context"].bearer_token, grpc_call["principal_context"].bearer_token)

    def setUp(self) -> None:
        self.options = GRPCAdapterOptions(
            resolve_asset=lambda _context: GRPCAssetReference(
                asset_identity=AssetIdentity("billing", "refund-api", "production")
            ),
            resolve_metadata=lambda context: {"operation": context.method, "actor": "untrusted-metadata"},
            resolve_principal_context=lambda _context: PrincipalContext("verified-user-token"),
            metadata_allowlist=("x-request-region",),
        )

    def test_client_interceptors_cover_all_cardinalities_once(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "pep-conformance.json"
        vectors = json.loads(fixture_path.read_text(encoding="utf-8"))["grpc_transports"]
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="allow")
        interceptors = create_grpc_client_interceptors(client, self.options)
        self.assertEqual(len(interceptors), 4)
        unary_request = {"amount": 10}
        stream_request = iter(("one", "two"))
        cases = (
            (interceptors[0].intercept_unary_unary, unary_request),
            (interceptors[2].intercept_stream_unary, stream_request),
            (interceptors[1].intercept_unary_stream, unary_request),
            (interceptors[3].intercept_stream_stream, stream_request),
        )
        for (intercept, request), vector in zip(cases, vectors, strict=True):
            rpc_type = vector["expected"]["rpc_type"]
            details = SimpleNamespace(
                method=vector["full_method"],
                metadata=(
                    ("idempotency-key", "refund-123"), ("x-request-region", "west"),
                    ("authorization", "spoofed"),
                ),
            )
            with self.subTest(rpc_type=rpc_type):
                continuation_called = False

                def continuation(_details, _request):
                    nonlocal continuation_called
                    continuation_called = True
                    return "continued"

                result = intercept(continuation, details, request)
                self.assertEqual(result, "continued")
                self.assertTrue(continuation_called)
                authorization = client.authorize.call_args.kwargs
                self.assertEqual(authorization["operation_id"], "refund-123")
                self.assertEqual(authorization["principal_context"].bearer_token, "verified-user-token")
                grpc_context = authorization["transport"]["grpc"]
                self.assertEqual(grpc_context["rpc_type"], rpc_type)
                self.assertEqual(grpc_context["service"], vector["expected"]["service"])
                self.assertEqual(grpc_context["method"], vector["expected"]["method"])
                self.assertEqual(grpc_context["full_method"], vector["full_method"])
                self.assertEqual(grpc_context["metadata"], {"x-request-region": "west"})
                self.assertIsNone(authorization["request"] if "request" in authorization else None)
        self.assertEqual(next(stream_request), "one", "client-streaming interceptors must not read RPC messages")

    def test_client_stream_pending_aborts_before_stream_creation(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="approval_required")
        interceptor = StreamStreamClientInterceptor(client, self.options)
        details = SimpleNamespace(method="/payments.PaymentService/Refund", metadata=(("idempotency-key", "refund-pending"),))
        continuation_called = False

        def continuation(_details, _request):
            nonlocal continuation_called
            continuation_called = True
            return "stream"

        with self.assertRaises(GRPCAuthorizationError) as raised:
            interceptor.intercept_stream_stream(continuation, details, iter(()))
        self.assertEqual(raised.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
        self.assertFalse(continuation_called)

    def test_server_interceptor_wraps_unary_and_all_stream_shapes(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="allow")
        interceptor = GRPCServerInterceptor(client, self.options)
        metadata = (("idempotency-key", "server-op"), ("x-request-region", "west"))
        cases = (
            (False, False, grpc.unary_unary_rpc_method_handler, "unary_unary", {}, "unary"),
            (False, True, grpc.unary_stream_rpc_method_handler, "unary_stream", {}, "server_streaming"),
            (True, False, grpc.stream_unary_rpc_method_handler, "stream_unary", None, "client_streaming"),
            (True, True, grpc.stream_stream_rpc_method_handler, "stream_stream", None, "bidirectional_streaming"),
        )
        for request_streaming, response_streaming, factory, attribute, request, rpc_type in cases:
            with self.subTest(rpc_type=rpc_type):
                handler_called = False

                def behavior(_request, _context):
                    nonlocal handler_called
                    handler_called = True
                    return iter(("ok",)) if response_streaming else "ok"

                original = factory(behavior)
                call_details = SimpleNamespace(method="/payments.PaymentService/Refund", invocation_metadata=metadata)
                wrapped = interceptor.intercept_service(lambda _details: original, call_details)
                context = _FakeServerContext()
                getattr(wrapped, attribute)(request, context)
                self.assertTrue(handler_called)
                authorization = client.authorize.call_args.kwargs
                self.assertEqual(authorization["operation_id"], "server-op")
                self.assertEqual(authorization["transport"]["grpc"]["rpc_type"], rpc_type)

    def test_server_stream_pending_aborts_before_handler(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="approval_required")
        interceptor = GRPCServerInterceptor(client, self.options)
        handler_called = False

        def behavior(_request, _context):
            nonlocal handler_called
            handler_called = True
            return iter(())

        original = grpc.stream_stream_rpc_method_handler(behavior)
        details = SimpleNamespace(method="/payments.PaymentService/Refund", invocation_metadata=(("idempotency-key", "refund-pending"),))
        wrapped = interceptor.intercept_service(lambda _details: original, details)
        with self.assertRaises(GRPCAuthorizationError) as raised:
            wrapped.stream_stream(None, _FakeServerContext())
        self.assertEqual(raised.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
        self.assertFalse(handler_called)

    def test_server_stream_denied_aborts_before_handler_or_message_reads(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="deny", reason="policy_denied")
        interceptor = GRPCServerInterceptor(client, self.options)
        cases = (
            (True, False, grpc.stream_unary_rpc_method_handler, "stream_unary"),
            (True, True, grpc.stream_stream_rpc_method_handler, "stream_stream"),
        )
        for _request_streaming, _response_streaming, factory, attribute in cases:
            with self.subTest(attribute=attribute):
                handler_called = False
                messages_read = []

                def behavior(request_iterator, _context):
                    nonlocal handler_called
                    handler_called = True
                    return iter(())

                def requests():
                    messages_read.append("read")
                    yield "message"

                original = factory(behavior)
                details = SimpleNamespace(
                    method="/payments.PaymentService/Refund",
                    invocation_metadata=(("idempotency-key", f"denied-{attribute}"),),
                )
                wrapped = interceptor.intercept_service(lambda _details: original, details)
                with self.assertRaises(GRPCAuthorizationError) as raised:
                    getattr(wrapped, attribute)(requests(), _FakeServerContext())
                self.assertEqual(raised.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
                self.assertFalse(handler_called)
                self.assertEqual(messages_read, [])

    def test_allowed_stream_authorizes_once_and_passes_every_message(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="allow")
        interceptor = GRPCServerInterceptor(client, self.options)

        def behavior(request_iterator, _context):
            for message in request_iterator:
                yield message.upper()

        original = grpc.stream_stream_rpc_method_handler(behavior)
        details = SimpleNamespace(
            method="/payments.PaymentService/Refund",
            invocation_metadata=(("idempotency-key", "bidi-once"),),
        )
        wrapped = interceptor.intercept_service(lambda _details: original, details)
        responses = list(wrapped.stream_stream(iter(("one", "two", "three")), _FakeServerContext()))

        self.assertEqual(responses, ["ONE", "TWO", "THREE"])
        self.assertEqual(client.authorize.call_count, 1, "allowed streams must not be reauthorized per message")
        self.assertEqual(client.authorize.call_args.kwargs["transport"]["grpc"]["rpc_type"], "bidirectional_streaming")

    def test_server_pending_hook_receives_challenge_and_wait_option(self) -> None:
        from dataclasses import replace

        from openprodkt_governance.client import PendingApproval

        pending = PendingApproval(
            DecisionResult(decision="approval_required", decision_id="dec_wait"),
            Mock(status_code=202),
            operation_id="server-op",
            approval_id="apr_wait",
            payload_hash="sha256:" + "b" * 64,
            asset_id=None,
            asset_key="billing.refund-api.production",
            asset_identity=None,
            status_url="https://pdp.test/v1/approvals/apr_wait",
            expires_at="2026-10-04T12:00:00Z",
        )
        client = Mock(spec=GovernanceClient)
        client.authorize.side_effect = pending
        challenges = []
        options = replace(
            self.options,
            wait_for_approval_seconds=5,
            on_pending=lambda context, authorization, error: challenges.append((context, authorization, error)),
        )
        interceptor = GRPCServerInterceptor(client, options)
        handler_called = False

        def behavior(_request, _context):
            nonlocal handler_called
            handler_called = True
            return "ok"

        original = grpc.unary_unary_rpc_method_handler(behavior)
        details = SimpleNamespace(method="/payments.PaymentService/Refund", invocation_metadata=(("idempotency-key", "server-op"),))
        wrapped = interceptor.intercept_service(lambda _details: original, details)
        with self.assertRaises(GRPCAuthorizationError) as raised:
            wrapped.unary_unary({}, _FakeServerContext())
        self.assertEqual(raised.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
        self.assertFalse(handler_called)
        self.assertEqual(client.authorize.call_args.kwargs["wait_for_approval_seconds"], 5)
        self.assertEqual(len(challenges), 1)
        context, authorization, error = challenges[0]
        self.assertIs(error, pending)
        self.assertEqual(context.rpc_type, "unary")
        self.assertEqual(authorization["operation_id"], "server-op")
        self.assertEqual(authorization["transport"]["grpc"]["method"], "Refund")

    def test_server_without_wait_option_omits_wait_argument(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult(decision="allow")
        interceptor = GRPCServerInterceptor(client, self.options)
        original = grpc.unary_unary_rpc_method_handler(lambda _request, _context: "ok")
        details = SimpleNamespace(method="/payments.PaymentService/Refund", invocation_metadata=(("idempotency-key", "server-op"),))
        wrapped = interceptor.intercept_service(lambda _details: original, details)
        self.assertEqual(wrapped.unary_unary({}, _FakeServerContext()), "ok")
        self.assertNotIn("wait_for_approval_seconds", client.authorize.call_args.kwargs)


class _FakeServerContext:
    def abort(self, code, details):
        raise GRPCAuthorizationError(code, details)


@unittest.skipUnless(GRPC_AVAILABLE, "install the optional grpc SDK extra to run async interceptor tests")
class GRPCAioAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.options = GRPCAdapterOptions(
            resolve_asset=lambda _context: GRPCAssetReference(asset_key="billing.refund-api.production"),
            resolve_operation_id=lambda context: "refund-aio",
        )

    async def test_aio_client_interceptors_cover_all_cardinalities(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult("allow")
        interceptors = create_grpc_aio_client_interceptors(client, self.options)
        vectors = (
            ("/payments.PaymentService/Refund", "unary", {}),
            ("/payments.PaymentService/RefundMany", "client_streaming", None),
            ("/payments.PaymentService/WatchRefund", "server_streaming", {}),
            ("/payments.PaymentService/RefundDuplex", "bidirectional_streaming", None),
        )
        ordered_interceptors = (interceptors[0], interceptors[2], interceptors[1], interceptors[3])
        for interceptor, (method, rpc_type, request) in zip(ordered_interceptors, vectors, strict=True):
            called = False

            async def continuation(_details, _request):
                nonlocal called
                called = True
                return "continued"

            details = SimpleNamespace(method=method, metadata=(("idempotency-key", "refund-aio"),))
            method_name = {
                "unary": "intercept_unary_unary",
                "client_streaming": "intercept_stream_unary",
                "server_streaming": "intercept_unary_stream",
                "bidirectional_streaming": "intercept_stream_stream",
            }[rpc_type]
            result = await getattr(interceptor, method_name)(continuation, details, request)
            self.assertEqual(result, "continued")
            self.assertTrue(called)
            self.assertEqual(client.authorize.call_args.kwargs["transport"]["grpc"]["rpc_type"], rpc_type)

    async def test_aio_server_interceptors_cover_all_handler_shapes(self) -> None:
        client = Mock(spec=GovernanceClient)
        client.authorize.return_value = DecisionResult("allow")
        interceptor = create_grpc_aio_server_interceptor(client, self.options)
        cases = (
            (False, False, grpc.unary_unary_rpc_method_handler, "unary_unary", "unary"),
            (True, False, grpc.stream_unary_rpc_method_handler, "stream_unary", "client_streaming"),
            (False, True, grpc.unary_stream_rpc_method_handler, "unary_stream", "server_streaming"),
            (True, True, grpc.stream_stream_rpc_method_handler, "stream_stream", "bidirectional_streaming"),
        )
        for index, (request_streaming, response_streaming, factory, attribute, rpc_type) in enumerate(cases):
            called = False

            if response_streaming:
                async def behavior(_request, _context):
                    nonlocal called
                    called = True
                    yield "ok"
            else:
                async def behavior(_request, _context):
                    nonlocal called
                    called = True
                    return "ok"

            original = factory(behavior)
            details = SimpleNamespace(method="/payments.PaymentService/Refund", invocation_metadata=(("idempotency-key", f"refund-aio-{index}"),))

            async def continuation(_details):
                return original

            wrapped = await interceptor.intercept_service(continuation, details)
            context = _FakeAioServerContext()
            handler = getattr(wrapped, attribute)
            request = None if request_streaming else {}
            if response_streaming:
                output = [item async for item in handler(request, context)]
                self.assertEqual(output, ["ok"])
            else:
                self.assertEqual(await handler(request, context), "ok")
            self.assertTrue(called)
            self.assertEqual(client.authorize.call_args.kwargs["transport"]["grpc"]["rpc_type"], rpc_type)

    async def test_aio_server_pending_hook_runs_before_abort(self) -> None:
        from dataclasses import replace

        from openprodkt_governance.client import PendingApproval

        pending = PendingApproval(
            DecisionResult(decision="approval_required", decision_id="dec_aio"),
            Mock(status_code=202),
            operation_id="refund-aio-pending",
            approval_id="apr_aio",
            payload_hash="sha256:" + "c" * 64,
            asset_id=None,
            asset_key="billing.refund-api.production",
            asset_identity=None,
            status_url="https://pdp.test/v1/approvals/apr_aio",
            expires_at="2026-10-04T12:00:00Z",
        )
        client = Mock(spec=GovernanceClient)
        client.authorize.side_effect = pending
        challenges = []
        options = replace(
            self.options,
            wait_for_approval_seconds=2,
            on_pending=lambda context, authorization, error: challenges.append((context, authorization, error)),
        )
        interceptor = create_grpc_aio_server_interceptor(client, options)
        handler_called = False

        async def behavior(_request, _context):
            nonlocal handler_called
            handler_called = True
            return "ok"

        original = grpc.unary_unary_rpc_method_handler(behavior)
        details = SimpleNamespace(method="/payments.PaymentService/Refund", invocation_metadata=(("idempotency-key", "refund-aio-pending"),))

        async def continuation(_details):
            return original

        wrapped = await interceptor.intercept_service(continuation, details)
        with self.assertRaises(GRPCAuthorizationError) as raised:
            await wrapped.unary_unary({}, _FakeAioServerContext())
        self.assertEqual(raised.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
        self.assertFalse(handler_called)
        self.assertEqual(client.authorize.call_args.kwargs["wait_for_approval_seconds"], 2)
        self.assertEqual(len(challenges), 1)
        self.assertIs(challenges[0][2], pending)


class _FakeAioServerContext:
    async def abort(self, code, details):
        raise GRPCAuthorizationError(code, details)


if __name__ == "__main__":
    unittest.main()
