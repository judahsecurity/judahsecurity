"""Vanguard compact / load / spend-cap helpers."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class SessionOpsTest(unittest.TestCase):
    def test_over_budget(self):
        from agent.session_ops import over_budget

        self.assertTrue(over_budget(5.0, 5.0))
        self.assertFalse(over_budget(4.9, 5.0))
        self.assertFalse(over_budget(99.0, 0))

    def test_compact_shrinks_old_tool_results(self):
        from agent.session_ops import compact_message_tool_results

        messages = [{"role": "user", "content": "start"}]
        for i in range(10):
            messages.append({"role": "assistant", "content": [{"type": "tool_use", "id": f"t{i}"}]})
            messages.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": f"t{i}",
                    "content": "X" * 4000,
                }],
            })
        out = compact_message_tool_results(messages, keep_recent=4, max_chars=80)
        old = out[2]["content"][0]["content"]
        recent = out[-1]["content"][0]["content"]
        self.assertTrue(old.endswith("[compacted]"))
        self.assertLess(len(old), 120)
        self.assertEqual(recent, "X" * 4000)

    def test_load_jsonl_and_trace(self):
        from agent.session_ops import load_prior_brief

        with tempfile.TemporaryDirectory() as tmp:
            jsonl = Path(tmp) / "hunt.jsonl"
            jsonl.write_text(
                json.dumps({"role": "user", "content": "Focus on GraphQL"}) + "\n"
                + json.dumps({"role": "assistant", "content": "ok"}) + "\n",
                encoding="utf-8",
            )
            brief = load_prior_brief(str(jsonl))
            self.assertIn("GraphQL", brief)

            trace = Path(tmp) / "trace.json"
            trace.write_text(json.dumps({"summary": {"estimated_cost_usd": 1.2}}), encoding="utf-8")
            self.assertIn("1.2", load_prior_brief(str(trace)))


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
