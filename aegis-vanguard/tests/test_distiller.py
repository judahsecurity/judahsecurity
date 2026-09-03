"""Native tool-output distiller — signal extraction, envelope compatibility,
chained pivots, and Deadend-style defense reading."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class DistillerTest(unittest.TestCase):
    def setUp(self):
        from agent.distiller import get_distiller
        self.d = get_distiller()

    # --- pass-through ---------------------------------------------------

    def test_small_clean_json_passes_through(self):
        raw = json.dumps({"subdomains": ["a.example.com"], "count": 1})
        self.assertIsNone(self.d.interpret("scan_subdomains", raw))

    def test_empty_passes_through(self):
        self.assertIsNone(self.d.interpret("scan_nuclei", ""))

    # --- finding arrays stay valid JSON --------------------------------

    def test_fitting_array_keeps_every_finding(self):
        # 200 findings that fit under the budget must NOT be trimmed — the old
        # blind path preserved them, so the distiller must too.
        vulns = [
            {"template-id": f"t{i}", "severity": "low", "matched-at": f"http://x/{i}"}
            for i in range(200)
        ]
        raw = json.dumps({"vulnerabilities": vulns, "count": 200})
        reading = self.d.interpret("scan_nuclei", raw, max_chars=50_000)
        # No pivots, fits budget → pass through untouched.
        self.assertIsNone(reading)

    def test_oversized_finding_array_trimmed_but_json_valid(self):
        vulns = [
            {"template-id": f"t{i}", "severity": "low",
             "matched-at": f"http://x/{i}", "evidence": "E" * 200}
            for i in range(200)
        ]
        raw = json.dumps({"vulnerabilities": vulns, "count": 200})
        reading = self.d.interpret("scan_nuclei", raw, max_chars=8000)
        self.assertIsNotNone(reading)
        # output must remain parseable JSON so _extract_findings still works
        parsed = json.loads(reading.to_text())
        self.assertIn("vulnerabilities", parsed)
        self.assertLess(len(parsed["vulnerabilities"]), 200)
        self.assertEqual(parsed["count"], 200)  # true total preserved
        self.assertGreater(reading.dropped, 0)
        self.assertLessEqual(len(reading.to_text()), 8000)

    def test_criticals_survive_trimming(self):
        items = [{"template-id": f"low{i}", "severity": "low",
                  "evidence": "E" * 200} for i in range(200)]
        items.append({"template-id": "crit", "severity": "critical",
                      "matched-at": "http://x/boom"})
        raw = json.dumps({"vulnerabilities": items})
        reading = self.d.interpret("scan_nuclei", raw, max_chars=8000)
        kept = json.loads(reading.to_text())["vulnerabilities"]
        self.assertTrue(any(i.get("template-id") == "crit" for i in kept),
                        "severity-first trim must never drop a critical")

    # --- chained pivots -------------------------------------------------

    def test_wordpress_signal_pivots_to_wordpress_scan(self):
        raw = json.dumps({"vulnerabilities": [
            {"template-id": "wordpress-detect", "severity": "info",
             "matched-at": "https://blog.example.com/wp-login.php",
             "info": {"tags": ["wordpress", "tech"]}},
        ]})
        reading = self.d.interpret("scan_nuclei", raw)
        self.assertIsNotNone(reading)
        tools = [ns.tool_name for ns in reading.next_steps]
        self.assertIn("wordpress_scan", tools)

    def test_git_exposure_pivots_to_fetch(self):
        raw = json.dumps({"findings": [
            {"template-id": "git-config", "severity": "medium",
             "matched-at": "https://example.com/.git/config"},
        ]})
        reading = self.d.interpret("scan_nuclei", raw)
        self.assertTrue(any(ns.tool_name == "send_http_request"
                            for ns in reading.next_steps))

    # --- envelope payload shape (Augur-compatible) ---------------------

    def test_payload_has_augur_compatible_keys(self):
        raw = json.dumps({"vulnerabilities": [
            {"template-id": "swagger", "severity": "info",
             "matched-at": "https://api.example.com/swagger.json"}]})
        reading = self.d.interpret("scan_nuclei", raw)
        payload = reading.to_payload()
        for key in ("summary", "kept", "dropped", "next_steps", "filtered_output"):
            self.assertIn(key, payload)

    # --- line lists -----------------------------------------------------

    def test_line_list_dedupes(self):
        raw = "\n".join(["https://x/a"] * 50 + ["https://x/b"])
        reading = self.d.interpret("crawl_urls", raw)
        self.assertIsNotNone(reading)
        self.assertEqual(reading.kept, 2)

    # --- defense reader (Deadend-style) --------------------------------

    def test_defense_detected_on_403(self):
        raw = json.dumps({"status": 403, "body": "Access denied by Cloudflare"})
        reading = self.d.interpret("send_http_request", raw)
        self.assertIsNotNone(reading)
        self.assertTrue(reading.defense_detected)
        self.assertEqual(reading.defense.get("vendor"), "cloudflare")
        # escalation hints are surfaced as high-priority next steps
        tools = [ns.tool_name for ns in reading.next_steps]
        self.assertIn("brain_update_waf", tools)

    def test_defense_none_on_clean_response(self):
        from agent.distiller import read_defense
        self.assertIsNone(read_defense(json.dumps({"status": 200, "body": "ok"})))

    # --- oversized non-JSON --------------------------------------------

    def test_oversized_text_smart_truncated(self):
        raw = "A" * 60_000 + "TAIL_MARKER"
        reading = self.d.interpret("scan_nikto", raw, max_chars=1000)
        self.assertIsNotNone(reading)
        self.assertTrue(reading.raw_truncated)
        self.assertIn("TAIL_MARKER", reading.to_text())  # tail preserved


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
