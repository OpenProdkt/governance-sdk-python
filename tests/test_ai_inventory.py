import json
from pathlib import Path
import unittest
from unittest.mock import patch
from openprodkt_governance import GovernanceClient
import requests

fixture = Path(__file__).resolve().parents[2] / "testdata" / "phase2-inventory.json"
if not fixture.exists():
    fixture = Path(__file__).resolve().parents[1] / "testdata" / "phase2-inventory.json"

class AIInventoryTests(unittest.TestCase):
    def test_asset_wire_parity(self):
        client = GovernanceClient("https://pdp.example", "asset-writer")
        for value in json.loads(fixture.read_text())["valid"]:
            for method in ("post", "patch"):
                with self.subTest(value=value, method=method), patch("openprodkt_governance.client.requests." + method) as send:
                    response = requests.Response()
                    response.status_code = 200
                    response._content = b'{}'
                    send.return_value = response
                    if method == "post":
                        client.create_asset("asset", "sandbox", "test", ai_inventory=value)
                    else:
                        client.update_asset("ast_test", "asset", "sandbox", "test", ai_inventory=value)
                    self.assertEqual(send.call_args.kwargs["json"]["ai_inventory"], value)
                    self.assertNotIn("definition", send.call_args.kwargs["json"])
