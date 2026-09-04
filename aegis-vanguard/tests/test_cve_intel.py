"""CVE intel — NVD parsing, ranking, version preference, graceful degradation."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# A trimmed but realistic NVD 2.0 response.
_FIXTURE = {
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


def _fixture_fetch(url, params):
    return _FIXTURE


def _boom_fetch(url, params):
    raise ConnectionError("Tunnel connection failed: 403 Forbidden")


class CVEIntelTest(unittest.TestCase):
    def test_parse_extracts_fields_and_best_cvss(self):
        from agent.cve_intel import parse_nvd_response
        cves, total = parse_nvd_response(_FIXTURE)
        self.assertEqual(total, 3)
        by_id = {c.id: c for c in cves}
        self.assertEqual(by_id["CVE-2024-2222"].cvss, 9.8)
        self.assertEqual(by_id["CVE-2024-2222"].severity, "critical")
        self.assertEqual(by_id["CVE-2024-1111"].url, "https://example.com/1111")
        self.assertEqual(by_id["CVE-2020-0000"].cvss, 3.5)  # falls back to v2

    def test_lookup_ranks_by_cvss_desc(self):
        from agent.cve_intel import lookup
        res = lookup("grafana", fetch=_fixture_fetch)
        self.assertTrue(res.available)
        self.assertEqual(res.cves[0].id, "CVE-2024-2222")  # 9.8 first
        self.assertEqual(res.total, 3)

    def test_version_preference(self):
        from agent.cve_intel import lookup
        res = lookup("grafana", "9.5.1", fetch=_fixture_fetch)
        # only CVE-2024-1111 mentions 9.5.1 in its summary
        self.assertEqual([c.id for c in res.cves], ["CVE-2024-1111"])

    def test_graceful_degradation_on_network_block(self):
        from agent.cve_intel import lookup
        res = lookup("grafana", fetch=_boom_fetch)
        self.assertFalse(res.available)
        self.assertIn("403", res.error)
        self.assertEqual(res.cves, [])

    def test_empty_product(self):
        from agent.cve_intel import lookup
        res = lookup("", fetch=_fixture_fetch)
        self.assertFalse(res.available)

    def test_enrich_brain_records_notes(self):
        from agent.cve_intel import lookup, enrich_brain

        class FakeBrain:
            def __init__(self):
                self.notes = []
                self.saved = False
            def add_note(self, n):
                self.notes.append(n)
            def save(self):
                self.saved = True

        res = lookup("grafana", fetch=_fixture_fetch)
        brain = FakeBrain()
        n = enrich_brain(res, brain, top=2)
        self.assertEqual(n, 2)
        self.assertTrue(brain.saved)
        self.assertIn("CVE-2024-2222", brain.notes[0])  # highest first

    def test_enrich_brain_noop_when_unavailable(self):
        from agent.cve_intel import CVEResult, enrich_brain
        self.assertEqual(enrich_brain(CVEResult("x", "", available=False), object()), 0)
        self.assertEqual(enrich_brain(CVEResult("x", "", available=True), None), 0)

    def test_tool_registered(self):
        import agent.agents  # noqa: F401
        from agent.tools import ToolRegistry
        self.assertIsNotNone(ToolRegistry().get("lookup_cves"))


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
