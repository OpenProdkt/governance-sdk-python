import json
from pathlib import Path
import unittest
from unittest.mock import patch
import requests
from openprodkt_governance import GovernanceClient, PrincipalContext, InvalidAuthorizationInputError

FIXTURE = Path(__file__).resolve().parents[2] / "testdata" / "phase4-guard.json"
if not FIXTURE.exists():
    FIXTURE = Path(__file__).resolve().parents[1] / "testdata" / "phase4-guard.json"
VECTORS = json.loads(FIXTURE.read_text())

def response(status, body):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(body).encode()
    return result

class GuardTests(unittest.TestCase):
    def test_shared_guard_vectors(self):
        self.assertEqual(VECTORS["profile"], "opk.phase4-guard/1")
        for vector in VECTORS["cases"]:
            with self.subTest(vector["name"]), patch("openprodkt_governance.client.requests.post") as post:
                reports, calls = [], []
                def send(url, **kwargs):
                    self.assertEqual(kwargs["headers"]["Authorization"], "Bearer explicit")
                    self.assertNotIn("raw-secret", json.dumps(kwargs["json"]))
                    if url.endswith("/evaluate"):
                        return response(vector["evaluate_status"], vector["evaluate_body"])
                    self.assertTrue(url.endswith("/outcomes"))
                    reports.append(dict(kwargs["json"]))
                    return response(vector["report_status"], {"recorded": True})
                post.side_effect = send
                client = GovernanceClient("https://pdp.example", "must-not-fallback")
                principal = PrincipalContext("explicit")
                request = {"version": "v1", "asset": {"key": "app.svc.prod"}, "operation_id": "guard-op", "transport": {"kind": "http"}}
                options = dict(VECTORS["tuple"])
                marker = RuntimeError("raw-secret-error")
                def callback():
                    calls.append(True)
                    options["execution_id"] = "changed"
                    options["attempt"] = 9
                    request["operation_id"] = "changed"
                    if vector["callback_error"]:
                        raise marker
                    return "raw-secret-result"
                if vector["calls"] == 0:
                    with self.assertRaises(Exception):
                        client.guard(request, callback, principal_context=principal, options=options)
                    self.assertEqual(reports, [])
                elif vector["callback_error"]:
                    with self.assertRaises(RuntimeError) as caught:
                        client.guard(request, callback, principal_context=principal, options=options)
                    self.assertIs(caught.exception, marker)
                else:
                    result = client.guard(request, callback, principal_context=principal, options=options)
                    self.assertEqual(result.value, "raw-secret-result")
                    self.assertEqual(result.reporting_error is not None, vector["report_status"] == 503)
                    self.assertEqual(result.report["status"], "succeeded")
                    # Snapshot access is detached; explicit report-only retry is identical.
                    result.report["status"] = "failed"
                    try:
                        client.report_operation_outcome(result.report, principal_context=principal)
                    except requests.RequestException:
                        pass
                    self.assertEqual(reports[0], reports[1])
                self.assertEqual(len(calls), vector["calls"])
                if vector["outcome"]:
                    self.assertEqual(reports[0]["status"], vector["outcome"])
                    self.assertEqual(reports[0]["operation_id"], "guard-op")
                    self.assertEqual(reports[0]["execution_id"], VECTORS["tuple"]["execution_id"])
                    self.assertEqual(reports[0]["attempt"], 1)
                    self.assertTrue(reports[0]["completed_at"].endswith("Z"))
                self.assertEqual(post.call_count, 1 + len(reports))

    @patch("openprodkt_governance.client.requests.post")
    def test_guard_invalid_tuple_or_principal_never_executes(self, post):
        client = GovernanceClient("https://pdp.example", "key")
        request = {"operation_id": "op"}
        for principal, options in [(None, {}), (PrincipalContext("explicit"), {"attempt": 0})]:
            with self.assertRaises(InvalidAuthorizationInputError):
                client.guard(request, lambda: self.fail("callback invoked"), principal_context=principal, options=options)
        async def async_callback():
            self.fail("async callback must not execute")
        with self.assertRaises(InvalidAuthorizationInputError):
            client.guard(request, async_callback, principal_context=PrincipalContext("explicit"))
        post.assert_not_called()
