"""Offline / air-gapped mode — predicate, tool guard, model routing, tool gate."""

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class NetModeTest(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("AEGIS_OFFLINE", None)

    def test_is_offline_toggle(self):
        from agent import netmode
        os.environ.pop("AEGIS_OFFLINE", None)
        self.assertFalse(netmode.is_offline())
        os.environ["AEGIS_OFFLINE"] = "1"
        self.assertTrue(netmode.is_offline())

    def test_require_online_online_is_none(self):
        from agent import netmode
        os.environ.pop("AEGIS_OFFLINE", None)
        self.assertIsNone(netmode.require_online("lookup_cves"))

    def test_require_online_offline_returns_error(self):
        from agent import netmode
        os.environ["AEGIS_OFFLINE"] = "1"
        out = json.loads(netmode.require_online("lookup_cves"))
        self.assertTrue(out["offline"])
        self.assertFalse(out["available"])
        self.assertEqual(out["tool"], "lookup_cves")

    def test_offline_forces_local_model(self):
        from agent.core import AgentRunner, _ollama_litellm_model
        runner = AgentRunner()
        agent = SimpleNamespace(name="recon_agent", model="claude-sonnet-4-6")
        # online: honors the agent's configured model
        os.environ.pop("AEGIS_OFFLINE", None)
        self.assertEqual(runner._resolve_model(agent), "claude-sonnet-4-6")
        # offline: routes to the local ollama model regardless
        os.environ["AEGIS_OFFLINE"] = "1"
        self.assertEqual(runner._resolve_model(agent), _ollama_litellm_model())

    def test_lookup_cves_tool_gated_offline(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        os.environ["AEGIS_OFFLINE"] = "1"
        tool = ToolRegistry().get("lookup_cves")
        out = json.loads(tool.function("grafana", ""))
        self.assertTrue(out["offline"])
        self.assertFalse(out["available"])


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
