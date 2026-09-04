"""OOB — probe minting, interaction parsing/polling, config gating, tools."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class OOBTest(unittest.TestCase):
    def setUp(self):
        for k in ("AEGIS_OOB_DOMAIN", "AEGIS_OOB_POLL_URL", "AEGIS_OOB_PROVIDER"):
            os.environ.pop(k, None)
        from agent.oob import reset_oob_client
        reset_oob_client()

    def tearDown(self):
        for k in ("AEGIS_OOB_DOMAIN", "AEGIS_OOB_POLL_URL", "AEGIS_OOB_PROVIDER"):
            os.environ.pop(k, None)
        from agent.oob import reset_oob_client
        reset_oob_client()

    def _configured(self, fetch=None):
        os.environ["AEGIS_OOB_DOMAIN"] = "oob.lab.example"
        os.environ["AEGIS_OOB_POLL_URL"] = "https://collector.lab.example/poll"
        from agent.oob import OOBClient
        return OOBClient(fetch=fetch)

    # --- gating ---------------------------------------------------------

    def test_disabled_without_config(self):
        from agent.oob import OOBClient
        c = OOBClient()
        self.assertFalse(c.enabled)
        self.assertIn("howto", c.help())

    def test_enabled_with_config(self):
        self.assertTrue(self._configured().enabled)

    # --- probe minting --------------------------------------------------

    def test_new_probe_unique_and_hosted_under_domain(self):
        c = self._configured()
        p1, p2 = c.new_probe("ssrf /avatar"), c.new_probe("xxe /import")
        self.assertNotEqual(p1.token, p2.token)
        self.assertTrue(p1.dns_host.endswith(".oob.lab.example"))
        self.assertTrue(p1.http_url.startswith("http://") and p1.token in p1.http_url)

    def test_payload_hints_present(self):
        c = self._configured()
        hints = c.new_probe().payload_hints()
        for key in ("ssrf_url", "xxe_entity", "log4shell", "sqli_oob_mysql"):
            self.assertIn(key, hints)
        self.assertIn("oob.lab.example", hints["ssrf_url"])

    # --- interaction parsing -------------------------------------------

    def test_parse_list_and_wrapped(self):
        from agent.oob import parse_interactions
        raw_list = [{"protocol": "dns", "remote-address": "1.2.3.4", "timestamp": "t"}]
        self.assertEqual(len(parse_interactions(raw_list)), 1)
        wrapped = {"interactions": [{"proto": "http", "remote_addr": "5.6.7.8"}]}
        got = parse_interactions(wrapped)
        self.assertEqual(got[0].protocol, "http")
        self.assertEqual(got[0].remote_addr, "5.6.7.8")

    def test_poll_returns_interactions(self):
        captured = {}
        def fake_fetch(url):
            captured["url"] = url
            return {"interactions": [{"protocol": "dns", "remote-address": "9.9.9.9"}]}
        c = self._configured(fetch=fake_fetch)
        p = c.new_probe()
        hits = c.poll(p.token)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].protocol, "dns")
        self.assertIn(f"token={p.token}", captured["url"])

    def test_poll_empty_token_and_errors(self):
        def boom(url):
            raise ConnectionError("blocked")
        c = self._configured(fetch=boom)
        self.assertEqual(c.poll(""), [])          # empty token
        self.assertEqual(c.poll("abc"), [])       # fetch raises → []

    def test_poll_disabled_client(self):
        from agent.oob import OOBClient
        self.assertEqual(OOBClient().poll("abc"), [])

    # --- tools ----------------------------------------------------------

    def test_tools_registered_and_help_when_unconfigured(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        reg = ToolRegistry()
        self.assertIsNotNone(reg.get("register_oob_probe"))
        self.assertIsNotNone(reg.get("check_oob_interactions"))
        out = json.loads(reg.get("register_oob_probe").function(""))
        self.assertFalse(out["enabled"])  # not configured in test env

    def test_hunter_core_tools_include_oob(self):
        from agent.agents import HUNTER_CORE_TOOLS
        self.assertIn("register_oob_probe", HUNTER_CORE_TOOLS)
        self.assertIn("check_oob_interactions", HUNTER_CORE_TOOLS)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
