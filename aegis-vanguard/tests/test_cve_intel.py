"""CVE intel — NVD + VulnCheck parsing, exploitability-first ranking,
provider selection, and graceful degradation."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# --- NVD 2.0 fixture --------------------------------------------------------
_NVD = {
    "totalResults": 3,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2024-1111",
            "descriptions": [{"lang": "en", "value": "Grafana 9.5.1 path traversal."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
            "references": [{"url": "https://example.com/1111"}],
            "published": "2024-02-01T00:00:00.000",
        }},
        {"cve": {
            "id": "CVE-2024-2222",
            "descriptions": [{"lang": "en", "value": "Grafana critical RCE in plugin loader."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "references": [{"url": "https://example.com/2222"}],
            "published": "2024-03-01T00:00:00.000",
        }},
        {"cve": {
            "id": "CVE-2020-0000",
            "descriptions": [{"lang": "en", "value": "Old low-severity info leak."}],
            "metrics": {"cvssMetricV2": [{"baseSeverity": "LOW", "cvssData": {"baseScore": 3.5}}]},
            "references": [],
        }},
    ],
}

# --- VulnCheck NVD++ index fixture (data = list of NVD-2.0 cve objects) ------
_VC_NVD = {
    "_meta": {"total_documents": 2},
    "data": [
        {"id": "CVE-2024-AAAA",
         "descriptions": [{"lang": "en", "value": "Grafana XSS."}],
         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
         "references": [{"url": "https://v/aaaa"}]},
        {"id": "CVE-2024-BBBB",
         "descriptions": [{"lang": "en", "value": "Grafana auth bypass, actively exploited."}],
         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.0, "baseSeverity": "MEDIUM"}}]},
         "references": [{"url": "https://v/bbbb"}]},
    ],
}
# --- VulnCheck KEV fixture --------------------------------------------------
_VC_KEV = {"data": [{"cve": ["CVE-2024-BBBB"], "vendorProject": "Grafana", "product": "grafana"}]}


def _nvd_fetch(url, params):
    return _NVD


def _vc_fetch(url, params):
    if "vulncheck-kev" in url:
        return _VC_KEV
    return _VC_NVD


def _boom_fetch(url, params):
    raise ConnectionError("Tunnel connection failed: 403 Forbidden")


class CVEIntelTest(unittest.TestCase):
    # --- NVD provider -------------------------------------------------------

    def test_parse_nvd_best_cvss_and_fields(self):
        from agent.cve_intel import parse_nvd_response
        cves, total = parse_nvd_response(_NVD)
        self.assertEqual(total, 3)
        by_id = {c.id: c for c in cves}
        self.assertEqual(by_id["CVE-2024-2222"].cvss, 9.8)
        self.assertEqual(by_id["CVE-2024-2222"].severity, "critical")
        self.assertEqual(by_id["CVE-2020-0000"].cvss, 3.5)  # v2 fallback

    def test_nvd_lookup_ranks_by_cvss(self):
        from agent.cve_intel import lookup
        res = lookup("grafana", fetch=_nvd_fetch, provider="nvd")
        self.assertTrue(res.available)
        self.assertEqual(res.provider, "nvd")
        self.assertEqual(res.cves[0].id, "CVE-2024-2222")

    def test_version_preference(self):
        from agent.cve_intel import lookup
        res = lookup("grafana", "9.5.1", fetch=_nvd_fetch, provider="nvd")
        self.assertEqual([c.id for c in res.cves], ["CVE-2024-1111"])

    # --- VulnCheck provider -------------------------------------------------

    def test_parse_vulncheck_index_and_kev(self):
        from agent.cve_intel import parse_vulncheck_index, parse_vulncheck_kev
        cves, total = parse_vulncheck_index(_VC_NVD)
        self.assertEqual(total, 2)
        self.assertEqual(cves[0].source, "vulncheck-nvd++")
        self.assertEqual(parse_vulncheck_kev(_VC_KEV), {"CVE-2024-BBBB"})

    def test_vulncheck_ranks_known_exploited_first(self):
        from agent.cve_intel import lookup
        res = lookup("grafana", fetch=_vc_fetch, provider="vulncheck")
        self.assertTrue(res.available)
        self.assertEqual(res.provider, "vulncheck")
        # BBBB (CVSS 6.0 but known-exploited) must outrank AAAA (CVSS 9.8)
        self.assertEqual(res.cves[0].id, "CVE-2024-BBBB")
        self.assertTrue(res.cves[0].known_exploited)
        self.assertFalse(res.cves[1].known_exploited)

    def test_vulncheck_kev_failure_still_returns_data(self):
        from agent.cve_intel import lookup
        def half_fetch(url, params):
            if "vulncheck-kev" in url:
                raise TimeoutError("kev slow")
            return _VC_NVD
        res = lookup("grafana", fetch=half_fetch, provider="vulncheck")
        self.assertTrue(res.available)                 # NVD++ data still returned
        self.assertTrue(res.cves)
        # KEV enrichment failed, so nothing is flagged known-exploited
        self.assertTrue(all(not c.known_exploited for c in res.cves))

    def test_provider_autoselect_prefers_vulncheck_when_token(self):
        from agent import cve_intel
        os.environ["VULNCHECK_API_KEY"] = "test-token"
        try:
            res = cve_intel.lookup("grafana", fetch=_vc_fetch)  # provider=None
            self.assertEqual(res.provider, "vulncheck")
        finally:
            os.environ.pop("VULNCHECK_API_KEY", None)

    def test_provider_autoselect_nvd_without_token(self):
        from agent import cve_intel
        os.environ.pop("VULNCHECK_API_KEY", None)
        res = cve_intel.lookup("grafana", fetch=_nvd_fetch)  # provider=None
        self.assertEqual(res.provider, "nvd")

    # --- degradation / edges ------------------------------------------------

    def test_graceful_degradation_on_block(self):
        from agent.cve_intel import lookup
        res = lookup("grafana", fetch=_boom_fetch, provider="nvd")
        self.assertFalse(res.available)
        self.assertIn("403", res.error)

    def test_empty_product(self):
        from agent.cve_intel import lookup
        self.assertFalse(lookup("", fetch=_nvd_fetch).available)

    def test_enrich_brain_marks_known_exploited(self):
        from agent.cve_intel import lookup, enrich_brain

        class FakeBrain:
            def __init__(self):
                self.notes = []
                self.saved = False
            def add_note(self, n):
                self.notes.append(n)
            def save(self):
                self.saved = True

        res = lookup("grafana", fetch=_vc_fetch, provider="vulncheck")
        brain = FakeBrain()
        n = enrich_brain(res, brain, top=2)
        self.assertEqual(n, 2)
        self.assertIn("KNOWN-EXPLOITED", brain.notes[0])  # exploited one first

    def test_tool_registered(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        self.assertIsNotNone(ToolRegistry().get("lookup_cves"))


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
