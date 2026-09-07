"""Every tool named in a hunter/recon/vuln palette must resolve to a registered
tool, and the interaction-first browser crawl + Caido ingestion must stay wired
into recon. Guards against a capability module existing but being unreachable
(dead code), and against palette typos.
"""

import unittest

import agent.agents as A
import agent.owasp_hunters as H
from agent.tools import ToolRegistry


def _all_palettes():
    palettes = {"RECON_TOOLS": A.RECON_TOOLS, "VULN_TOOLS": A.VULN_TOOLS}
    for name in dir(H):
        if name.endswith("_TOOLS"):
            val = getattr(H, name)
            if isinstance(val, list):
                palettes[name] = val
    return palettes


class PaletteWiringTest(unittest.TestCase):
    def setUp(self):
        self.reg = ToolRegistry()

    def test_browser_crawl_and_caido_wired_into_recon(self):
        # the interaction-first crawl and Caido ingestion must be reachable by
        # recon — otherwise the modules are dead code
        self.assertIn("browser_crawl", A.RECON_TOOLS)
        self.assertIn("ingest_caido", A.RECON_TOOLS)

    def test_wired_tools_are_registered(self):
        for name in ("browser_crawl", "ingest_caido"):
            self.assertIsNotNone(self.reg.get(name),
                                 f"{name} is in a palette but not a registered tool")

    def test_every_palette_name_resolves(self):
        bad = {}
        for pname, names in _all_palettes().items():
            miss = sorted({n for n in names
                           if isinstance(n, str) and self.reg.get(n) is None})
            if miss:
                bad[pname] = miss
        self.assertEqual(bad, {}, f"palettes reference unregistered tools: {bad}")


if __name__ == "__main__":
    unittest.main()
