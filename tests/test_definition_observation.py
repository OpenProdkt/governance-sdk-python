import json
import unittest
from unittest.mock import patch

import requests

from openprodkt_governance import GovernanceClient, InvalidAuthorizationInputError, PrincipalContext

DIGEST = "sha256:" + "ab" * 32
OBSERVATION = {"digest": DIGEST, "canon": "mcp-tool-definition:v1", "server_version": "1.2.3"}
PRINCIPAL = PrincipalContext("explicit-principal")
BASE = {"version": "v1", "asset": {"key": "app.svc.prod"}, "operation_id": "op-1", "transport": {"kind": "mcp"}}


def allow():
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps({"decision": "allow", "operation_id": "op-1"}).encode()
    return result


def sent_body(post):
    return json.loads(post.call_args.kwargs["data"] if "data" in post.call_args.kwargs else json.dumps(post.call_args.kwargs["json"]))


class DefinitionObservationTests(unittest.TestCase):
    def setUp(self):
        self.client = GovernanceClient("https://pdp.example", "key")

    @patch("openprodkt_governance.client.requests.post")
    def test_absent_when_unset(self, post):
        post.return_value = allow()
        self.client.authorize(operation_id="op-1", asset_key="app.svc.prod")
        self.assertNotIn("definition_observation", sent_body(post))
        self.client.evaluate_proxy(dict(BASE), principal_context=PRINCIPAL)
        self.assertNotIn("definition_observation", sent_body(post))
        self.client.evaluate_proxy({**BASE, "definition_observation": None}, principal_context=PRINCIPAL)
        self.assertNotIn("definition_observation", sent_body(post))

    @patch("openprodkt_governance.client.requests.post")
    def test_serialized_exactly_on_both_endpoints(self, post):
        post.return_value = allow()
        self.client.authorize(operation_id="op-1", asset_key="app.svc.prod", definition_observation=OBSERVATION)
        self.assertEqual(post.call_args.args[0], "https://pdp.example/v1/evaluate")
        self.assertEqual(sent_body(post)["definition_observation"], OBSERVATION)
        self.client.evaluate_proxy({**BASE, "definition_observation": OBSERVATION}, principal_context=PRINCIPAL)
        self.assertEqual(post.call_args.args[0], "https://pdp.example/v1/proxy/evaluate")
        self.assertEqual(sent_body(post)["definition_observation"], OBSERVATION)

    @patch("openprodkt_governance.client.requests.post")
    def test_server_version_is_optional(self, post):
        post.return_value = allow()
        without_version = {"digest": DIGEST, "canon": "mcp-tool-definition:v1"}
        self.client.authorize(operation_id="op-1", asset_key="app.svc.prod", definition_observation=without_version)
        self.assertEqual(sent_body(post)["definition_observation"], without_version)

    @patch("openprodkt_governance.client.requests.post")
    def test_invalid_observations_are_request_validation_errors_and_never_sent(self, post):
        post.return_value = allow()
        invalid = {
            "empty digest": {**OBSERVATION, "digest": ""},
            "uppercase digest": {**OBSERVATION, "digest": "sha256:" + "AB" * 32},
            "short digest": {**OBSERVATION, "digest": "sha256:" + "ab" * 31},
            "no prefix": {**OBSERVATION, "digest": "ab" * 32},
            "trailing newline": {**OBSERVATION, "digest": DIGEST + "\n"},
            "missing digest": {"canon": "mcp-tool-definition:v1"},
            "non-string digest": {**OBSERVATION, "digest": 7},
            "empty canon": {**OBSERVATION, "canon": ""},
            "unknown canon": {**OBSERVATION, "canon": "mcp-tool-definition:v2"},
            "missing canon": {"digest": DIGEST},
            "empty version": {**OBSERVATION, "server_version": ""},
            "none version": {**OBSERVATION, "server_version": None},
            "long version": {**OBSERVATION, "server_version": "v" * 129},
            "control version": {**OBSERVATION, "server_version": "1.0\n"},
            "c1 control version": {**OBSERVATION, "server_version": "1.0\x85"},
            "oversized on the wire": {**OBSERVATION, "server_version": "\u20ac" * 128},
            "unknown member": {**OBSERVATION, "description": "leak"},
            "not an object": "sha256:" + "ab" * 32,
        }
        for name, observation in invalid.items():
            with self.subTest(name):
                with self.assertRaises(InvalidAuthorizationInputError):
                    self.client.authorize(operation_id="op-1", asset_key="app.svc.prod", definition_observation=observation)
                with self.assertRaises(InvalidAuthorizationInputError):
                    self.client.evaluate_proxy({**BASE, "definition_observation": observation}, principal_context=PRINCIPAL)
        post.assert_not_called()

    @patch("openprodkt_governance.client.requests.post")
    def test_maximal_ascii_version_fits(self, post):
        post.return_value = allow()
        observation = {**OBSERVATION, "server_version": "v" * 128}
        self.client.authorize(operation_id="op-1", asset_key="app.svc.prod", definition_observation=observation)
        self.assertEqual(sent_body(post)["definition_observation"], observation)
        self.assertLessEqual(len(json.dumps(sent_body(post)["definition_observation"]).encode()), 512)

    @patch("openprodkt_governance.client.requests.post")
    def test_guard_carries_the_observation(self, post):
        post.return_value = allow()
        calls = []
        with patch.object(self.client, "report_operation_outcome", side_effect=lambda *a, **k: calls.append(a)):
            self.client.guard({**BASE, "definition_observation": OBSERVATION}, lambda: "ok", principal_context=PRINCIPAL)
        self.assertEqual(sent_body(post)["definition_observation"], OBSERVATION)


if __name__ == "__main__":
    unittest.main()
