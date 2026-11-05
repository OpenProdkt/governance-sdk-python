import unittest
from decimal import Decimal, InvalidOperation, localcontext
from unittest.mock import Mock, patch

import requests

from openprodkt_governance.client import GovernanceClient, _json_request
from openprodkt_governance.json_numbers import dumps, loads, validate_value, validate_request_values
from openprodkt_governance.metadata import sanitize_metadata


def nested(depth: int, leaf=None):
    for _ in range(depth):
        leaf = [leaf]
    return leaf


class NumberGuardTests(unittest.TestCase):
    def test_not_condition_values_and_omission(self):
        condition = {"not": {"field": "metadata.n", "operator": "exists"}}
        self.assertEqual(loads(dumps(condition)), condition)
        self.assertNotIn("value", loads(dumps(condition))["not"])
        for value in [Decimal("1e309"), Decimal("5e-324"), nested(65)]:
            send = Mock()
            payload = {"condition": {"all": [{"not": {
                "field": "metadata.n", "operator": "=", "value": value,
            }}]}}
            with self.assertRaises(ValueError):
                _json_request(send, "https://pdp.example.test", json=payload)
            send.assert_not_called()
        payload = {"condition": {"not": {"field": "metadata.n", "operator": "=", "value": Decimal("9007199254740993")}}}
        validate_request_values(payload)
        self.assertEqual(loads(dumps(payload))["condition"]["not"]["value"], Decimal("9007199254740993"))

    def test_raw_token_boundary_before_decimal_construction(self):
        tokens = [
            "1." + "0" * 4094,
            "-0e" + "9" * 4093,
            "-0.00e-" + "9" * 4089,
            "1e" + "0" * 4093 + "1",
        ]
        for token in tokens:
            self.assertEqual(len(token), 4096)
            loads('{"n":' + token + "}")
            with patch("openprodkt_governance.json_numbers.Decimal") as constructor:
                with self.assertRaises(ValueError):
                    loads('{"n":' + token + "0}")
                constructor.assert_not_called()
        for exponent in ["2147483648", "9223372036854775808", "9" * 4000, "-" + "9" * 4000]:
            self.assertEqual(loads("-0e" + exponent), Decimal(0))
            with self.assertRaises(ValueError):
                loads("1e" + exponent)

    def test_outgoing_decimal_representation_counts_all_characters(self):
        value = Decimal("-1." + "0" * 4093)
        self.assertEqual(len(str(value)), 4096)
        self.assertEqual(dumps(value), "-1")
        with self.assertRaises(ValueError):
            dumps(Decimal("-1." + "0" * 4094))

    def test_value_and_metadata_depth_include_leaves(self):
        for leaf in [None, "text", True, {}, []]:
            validate_value(nested(64, leaf))
            sanitize_metadata({"n": nested(63, leaf)})
            with self.assertRaises(ValueError):
                validate_value(nested(65, leaf))
            with self.assertRaises(ValueError):
                sanitize_metadata({"n": nested(64, leaf)})
        cycle = {}
        cycle["self"] = cycle
        with self.assertRaises(ValueError):
            sanitize_metadata(cycle)
        with self.assertRaises(ValueError):
            validate_value(cycle)

    def test_only_condition_values_not_wrappers_or_envelope_are_bounded(self):
        for depth in [64, 65]:
            condition = {"field": "metadata.n", "operator": "=", "value": nested(depth)}
            for _ in range(80):
                condition = {"all": [condition]}
            send = Mock()
            payload = {"condition": condition, "unrelated": nested(90)}
            if depth == 64:
                _json_request(send, "https://pdp.example.test", json=payload)
                send.assert_called_once()
            else:
                with self.assertRaises(ValueError):
                    _json_request(send, "https://pdp.example.test", json=payload)
                send.assert_not_called()
        # Decimal encoding must not reintroduce a whole-envelope depth cap.
        _json_request(Mock(), "https://pdp.example.test", json={"unrelated": nested(90, Decimal("0.1"))})
        cycle = {}
        cycle["self"] = cycle
        with self.assertRaises(ValueError):
            _json_request(Mock(), "https://pdp.example.test", json={"unrelated": cycle})

    @patch("openprodkt_governance.client.requests.get")
    def test_real_response_numbers_use_raw_token_guards(self, get):
        response = requests.Response()
        response.status_code = 200
        response._content = ('{"n":-0e' + "9" * 4093 + "}").encode()
        get.return_value = response
        client = GovernanceClient("https://pdp.example.test", "key")
        self.assertEqual(client.list_policies()["n"], Decimal(0))
        response._content = ('{"n":-0e' + "9" * 4094 + "}").encode()
        with self.assertRaises(ValueError):
            client.list_policies()
        response._content = ('{"n":1e' + "9" * 4000 + "}").encode()
        with localcontext() as context:
            context.traps[InvalidOperation] = False
            with self.assertRaises(ValueError):
                client.list_policies()

    @patch("openprodkt_governance.client.requests.get")
    @patch("openprodkt_governance.client.requests.post")
    def test_historical_policy_is_readable_but_cannot_be_reauthored(self, post, get):
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"condition":{"field":"metadata.n","operator":">","value":5e-324}}'
        get.return_value = response
        client = GovernanceClient("https://pdp.example.test", "key")
        condition = client.list_policies()["condition"]
        self.assertEqual(condition["value"], Decimal("5e-324"))
        with self.assertRaises(ValueError):
            client.create_policy("asset_1", "invalid historical number", condition, "deny")
        post.assert_not_called()
