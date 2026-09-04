"""HITL — control channel (queue + file), env wiring, and runner injection."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class HITLTest(unittest.TestCase):
    def test_queue_fifo_and_empty(self):
        from agent.hitl import HITLController
        c = HITLController()
        self.assertIsNone(c.poll())
        c.submit("first")
        c.submit("second")
        self.assertEqual(c.poll(), "first")
        self.assertEqual(c.poll(), "second")
        self.assertIsNone(c.poll())

    def test_blank_directive_ignored(self):
        from agent.hitl import HITLController
        c = HITLController()
        c.submit("   ")
        self.assertIsNone(c.poll())

    def test_file_channel_reads_and_clears(self):
        from agent.hitl import HITLController
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "hitl.txt"
            p.write_text("focus on /admin api", encoding="utf-8")
            c = HITLController(str(p))
            self.assertEqual(c.poll(), "focus on /admin api")
            # cleared after read → fires exactly once
            self.assertIsNone(c.poll())
            self.assertEqual(p.read_text(encoding="utf-8"), "")

    def test_poll_all_drains_queue_and_file(self):
        from agent.hitl import HITLController
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "hitl.txt"
            p.write_text("from file", encoding="utf-8")
            c = HITLController(str(p))
            c.submit("from queue")
            got = c.poll_all()
            self.assertIn("from queue", got)
            self.assertIn("from file", got)

    def test_from_env_enable_disable(self):
        from agent import hitl
        for k in ("AEGIS_HITL", "AEGIS_HITL_FILE"):
            os.environ.pop(k, None)
        self.assertIsNone(hitl.from_env())
        os.environ["AEGIS_HITL"] = "1"
        try:
            self.assertIsNotNone(hitl.from_env())
        finally:
            os.environ.pop("AEGIS_HITL", None)

    def test_from_env_file(self):
        from agent import hitl
        with tempfile.TemporaryDirectory() as tmp:
            p = str(Path(tmp) / "ctrl")
            os.environ["AEGIS_HITL_FILE"] = p
            try:
                c = hitl.from_env()
                self.assertIsNotNone(c)
                self.assertTrue(Path(p).exists())  # created for the operator
            finally:
                os.environ.pop("AEGIS_HITL_FILE", None)

    def test_format_directive(self):
        from agent.hitl import format_directive
        out = format_directive("skip subdomain enum")
        self.assertIn("OPERATOR DIRECTIVE", out)
        self.assertIn("skip subdomain enum", out)

    # --- runner integration --------------------------------------------

    def test_runner_injects_directive_into_tool_results(self):
        from agent.core import AgentRunner
        from agent.hitl import HITLController
        c = HITLController()
        c.submit("pivot to the GraphQL endpoint")
        runner = AgentRunner(hitl=c)
        tool_results = [{"type": "tool_result", "tool_use_id": "t1", "content": "{}"}]
        runner._inject_operator_directives(tool_results, SimpleNamespace(name="vuln"))
        texts = [b for b in tool_results if b.get("type") == "text"]
        self.assertEqual(len(texts), 1)
        self.assertIn("GraphQL", texts[0]["text"])

    def test_runner_noop_without_hitl(self):
        from agent.core import AgentRunner
        runner = AgentRunner(hitl=None)
        tr = [{"type": "tool_result", "tool_use_id": "t1", "content": "{}"}]
        runner._inject_operator_directives(tr, SimpleNamespace(name="vuln"))
        self.assertEqual(len(tr), 1)  # unchanged


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
