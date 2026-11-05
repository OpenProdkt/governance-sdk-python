import json
import unittest
from decimal import Decimal
from unittest.mock import Mock, patch

import requests

from openprodkt_governance.client import GovernanceClient, InvalidEvaluationRequestError
from openprodkt_governance.json_numbers import dumps
from openprodkt_governance.metadata import sanitize_metadata


class ExactNumberTests(unittest.TestCase):
    def test_exact_ints_and_decimals_and_domain_boundaries(self) -> None:
        values = [9007199254740993, Decimal("0.1000000000000000000001"), Decimal("1e-308"), Decimal("9.99e308"), Decimal("9" * 128), -0.0]
        for value in values:
            with self.subTest(value=value):
                result = sanitize_metadata({"n": value})
                encoded = dumps(result)
                self.assertEqual(json.loads(encoded, parse_float=Decimal)["n"], value)
        for value in [Decimal("1e-309"), Decimal("1e309"), 10**129 - 1, float("nan"), float("inf")]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                sanitize_metadata({"n": value})

    def test_counters_are_signed_integral_and_bounded(self) -> None:
        for value in [-1, Decimal("1.0"), -(2**63), 2**63-1]:
            self.assertEqual(sanitize_metadata({"ai": {"message_count": value}})["ai"]["message_count"], int(value))
        for value in [0.1, Decimal("-0.1"), 2**63, -(2**63)-1, True, "1"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                sanitize_metadata({"ai": {"message_count": value}})
        with self.assertRaises(ValueError):
            sanitize_metadata({"ai": {"attachment_count": 65}})
        self.assertEqual(sanitize_metadata({"ai": {"message_count": 9.223372036854775e18}})["ai"]["message_count"], 9223372036854775000)
        with self.assertRaises(ValueError):
            sanitize_metadata({"ai": {"message_count": float(-(2**63))}})

    def test_numeric_resource_guards_do_not_format_huge_decimals(self) -> None:
        self.assertEqual(dumps(Decimal("0e2147483647")), "0")
        self.assertEqual(dumps(Decimal("1." + "0" * 4000)), "1")
        with self.assertRaises(ValueError):
            dumps(Decimal("1." + "0" * 4096))

    @patch("openprodkt_governance.client.requests.post")
    def test_exact_decimal_authorization_wire(self, post: Mock) -> None:
        response = Mock(status_code=200)
        response.json.return_value = {"decision": "allow"}
        post.return_value = response
        client = GovernanceClient("https://pdp.example.test", "key")
        client.authorize(asset_id="asset_1", operation_id="op_1", metadata={"n": Decimal("0.1000000000000000000001"), "large": 9007199254740993})
        kwargs = post.call_args.kwargs
        self.assertNotIn("json", kwargs)
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertIn(b'"n":0.1000000000000000000001', kwargs["data"])
        self.assertIn(b'"large":9007199254740993', kwargs["data"])

    @patch("openprodkt_governance.client.requests.get")
    @patch("openprodkt_governance.client.requests.post")
    def test_policy_decode_and_reauthor_preserve_precision(self, post: Mock, get: Mock) -> None:
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"condition":{"field":"metadata.n","operator":"=","value":0.1000000000000000000001}}'
        get.return_value = response
        post.return_value = response
        client = GovernanceClient("https://pdp.example.test", "key")
        condition = client.list_policies()["condition"]
        self.assertIsInstance(condition["value"], Decimal)
        client.create_policy("asset_1", "exact", condition, "deny")
        self.assertIn(b'"value":0.1000000000000000000001', post.call_args.kwargs["data"])

    @patch("openprodkt_governance.client.requests.post")
    def test_bad_request_codes_are_typed_400(self, post: Mock) -> None:
        for code in ("invalid_context", "invalid_request"):
            with self.subTest(code=code):
                response = Mock(status_code=400)
                response.json.return_value = {"code": code, "error": "invalid input"}
                post.return_value = response
                with self.assertRaises(InvalidEvaluationRequestError) as raised:
                    GovernanceClient("https://pdp.example.test", "key").authorize(asset_id="asset_1", operation_id="op_1")
                self.assertEqual(raised.exception.status_code, 400)
                self.assertEqual(raised.exception.outcome, code)
                self.assertEqual(raised.exception.result.code, code)
