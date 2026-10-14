import json
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from openprodkt_governance.metadata import build_openai_metadata, sanitize_metadata


class MetadataTests(unittest.TestCase):
    def test_shared_metadata_conformance_vectors(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "testdata" / "metadata-conformance.json"
        cases = json.loads(fixture_path.read_text(encoding="utf-8"))
        for test_case in cases:
            with self.subTest(test_case["name"]):
                self.assertEqual(sanitize_metadata(test_case["input"]), test_case["expected"])

    def test_build_openai_metadata(self) -> None:
        metadata = build_openai_metadata(
            "gpt-5",
            "chat",
            "prod",
            "svc-api",
            "payments",
            {
                "message_count": 4,
                "message_size_bytes": 18200,
                "input_tokens": 4200,
                "output_token_limit": 2000,
                "attachment_count": 2,
                "attachment_size_bytes": 840000,
                "tool_count": 1,
                "request_size_bytes": 22000,
            },
        )
        self.assertEqual(metadata["provider"], "openai")
        self.assertEqual(metadata["ai"]["message_count"], 4)

    def test_forbidden_metadata(self) -> None:
        with self.assertRaises(ValueError):
            sanitize_metadata({"provider": "openai", "raw_message_content": "secret"})

    def test_normalized_key_collision(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate normalized key"):
            sanitize_metadata({"operation": "refund", " operation ": "cancel"})

    def test_generic_preset_metadata(self) -> None:
        metadata = sanitize_metadata({"request": {"method": "POST", "path": "/invoices"}})
        self.assertEqual(metadata["request"]["method"], "POST")

    def test_dataclass_metadata_uses_explicit_field_serialization(self) -> None:
        @dataclass
        class RequestContext:
            operation: str
            amount: int

        metadata = sanitize_metadata({"request": RequestContext("refund", 42)})
        self.assertEqual(metadata, {"request": {"operation": "refund", "amount": 42}})

    def test_pydantic_metadata_uses_json_mode_when_available(self) -> None:
        try:
            from pydantic import BaseModel
        except ImportError:
            self.skipTest("Pydantic is an optional dependency")

        class RequestContext(BaseModel):
            operation: str
            created_at: datetime

        metadata = sanitize_metadata(RequestContext(operation="refund", created_at=datetime(2026, 10, 4, tzinfo=timezone.utc)))
        self.assertEqual(metadata, {"operation": "refund", "created_at": "2026-10-04T00:00:00Z"})

    def test_unsupported_objects_and_non_finite_numbers_are_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "not supported"):
            sanitize_metadata({"payload": object()})
        with self.assertRaisesRegex(ValueError, "finite"):
            sanitize_metadata({"amount": float("nan")})

    def test_cyclic_metadata_is_rejected(self) -> None:
        metadata: dict[str, object] = {}
        metadata["self"] = metadata
        with self.assertRaisesRegex(ValueError, "cyclic"):
            sanitize_metadata(metadata)

    def test_metadata_size_limit_applies_after_serialization(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata exceeds"):
            sanitize_metadata({"value": "x" * (8 * 1024)})


if __name__ == "__main__":
    unittest.main()
