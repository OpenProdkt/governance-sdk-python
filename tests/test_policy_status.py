import unittest
from unittest.mock import Mock, patch

from openprodkt_governance import GovernanceClient


class PolicyStatusTests(unittest.TestCase):
    def test_creation_status_is_explicit_and_legacy_omits_it(self):
        client = GovernanceClient(base_url="http://localhost", api_key="test-key")
        for status in (None, "draft", "published"):
            response = Mock()
            response.json.return_value = {"status": status or "published"}
            with patch("openprodkt_governance.client._json_request", return_value=response) as request:
                options = {} if status is None else {"status": status}
                result = client.create_policy("asset", "name", {"field": "asset.id", "operator": "=", "value": "asset"}, "deny", **options)
                body = request.call_args.kwargs["json"]
                if status is None:
                    self.assertNotIn("status", body)
                else:
                    self.assertEqual(body["status"], status)
                self.assertEqual(result["status"], status or "published")

    def test_archived_creation_is_not_supported(self):
        client = GovernanceClient(base_url="http://localhost", api_key="test-key")
        with patch("openprodkt_governance.client._json_request") as request:
            with self.assertRaises(ValueError):
                client.create_policy("asset", "name", {}, "deny", status="archived")
            request.assert_not_called()
