"""Regression: the Aegis Censor must not block the structured scan_nuclei /
scan_nikto wrappers while keeping the raw-CLI nuclei/nikto guards intact.

The bug (seen live): scan_nuclei canonicalizes to `nuclei`, whose schema demands
a CLI `args` string; the structured tool passes target/templates instead, so
every nuclei call was rejected `missing required field 'args'` — nuclei never
ran for any hunter. The fix registers exact-name structured schemas that win
over the prefix-normalized raw schema, without touching the raw path.
"""

import os
import sys
import unittest
from pathlib import Path

_PRAETORIUM = Path(__file__).resolve().parents[2] / "backend" / "packages" / "aegis_praetorium"
sys.path.insert(0, str(_PRAETORIUM))

try:
    from aegis_praetorium.censor import Censor
    _HAVE_CENSOR = True
except Exception:  # pragma: no cover - package layout guard
    _HAVE_CENSOR = False


@unittest.skipUnless(_HAVE_CENSOR, "aegis_praetorium not importable in this env")
class CensorScanWrapperTest(unittest.TestCase):
    def setUp(self):
        self.c = Censor()

    def test_scan_nuclei_structured_passes(self):
        v = self.c.validate("scan_nuclei", {
            "target": "http://host.docker.internal:50708/",
            "templates": "tags=oauth,jwt", "severity": "low,medium", "timeout": 300})
        self.assertTrue(v.ok, v.error)

    def test_scan_nikto_structured_passes(self):
        v = self.c.validate("scan_nikto", {
            "target": "http://host.docker.internal:50708/", "timeout": 600})
        self.assertTrue(v.ok, v.error)

    def test_raw_nuclei_cli_still_valid(self):
        # the raw-CLI path (platform MCP `nuclei` with args=) is unchanged
        v = self.c.validate("nuclei", {"args": "-u http://x -t cves"})
        self.assertTrue(v.ok, v.error)

    def test_raw_nuclei_injection_still_blocked(self):
        # the raw-CLI guard must still reject shell metacharacters
        v = self.c.validate("nuclei", {"args": "-u http://x; rm -rf /"})
        self.assertFalse(v.ok)

    def test_scan_nuclei_requires_target(self):
        # target is required — an empty structured call is still rejected
        v = self.c.validate("scan_nuclei", {"templates": "tags=oauth"})
        self.assertFalse(v.ok)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
