"""Redaction must run before file or OTLP export."""

import json
import os
import tempfile
import unittest
from pathlib import Path


class TracingRedactTest(unittest.TestCase):
    def test_redact_strips_cookies_and_bearer(self):
        from agent.tracing import redact_value

        out = redact_value(
            {
                "cookie": "sid=abc",
                "note": "Authorization: Bearer tok_live_123",
            }
        )
        self.assertEqual(out["cookie"], "[redacted]")
        self.assertIn("[redacted]", out["note"])
        self.assertNotIn("tok_live_123", out["note"])

    def test_export_writes_redacted_json(self):
        from agent.tracing import Tracer

        with tempfile.TemporaryDirectory() as tmp:
            tracer = Tracer(enabled=True, output_dir=tmp, session_id="t1")
            with tracer.span("login", "tool_call", cookie="session=secret"):
                pass
            path = tracer.export()
            data = json.loads(Path(path).read_text())
            attrs = data["spans"][0]["attributes"]
            self.assertEqual(attrs.get("cookie"), "[redacted]")


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
