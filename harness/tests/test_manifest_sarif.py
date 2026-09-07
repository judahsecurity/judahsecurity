"""Reproducible manifest + unified SARIF export."""

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class ManifestTest(unittest.TestCase):
    def _config(self):
        return SimpleNamespace(
            scanner_cmd=["python3", "run_pentest.py"],
            scanner_extra_args=["--fast"],
            scanner_cwd=Path("/repo/aegis-vanguard"),
            default_model="claude-sonnet-4-6",
        )

    def test_manifest_fields(self):
        from local_harness.manifest import build_manifest
        with_tmp = Path(os.environ.get("PYTEST_TMP", "."))  # not used; gt below
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            gt = Path(tmp) / "XBEN.json"
            gt.write_text(json.dumps({"a": {"target": "http://x", "flag": "F"},
                                      "b": {"target": "http://y", "flag": "G"}}))
            m = build_manifest(self._config(), ground_truth_path=gt,
                               tools=["nuclei"], tool_probe=lambda b: "nuclei v3.1.0")
        self.assertEqual(m["agent_model"], "claude-sonnet-4-6")
        self.assertEqual(m["scanner"]["extra_args"], ["--fast"])
        self.assertEqual(m["tool_versions"]["nuclei"], "nuclei v3.1.0")
        self.assertEqual(m["ground_truth"]["target_count"], 2)
        self.assertTrue(m["ground_truth"]["sha256"])
        self.assertIn("harness_git", m)
        self.assertIn("python", m["runtime"])

    def test_model_from_env_overrides(self):
        from local_harness.manifest import build_manifest
        os.environ["AEGIS_MODEL"] = "claude-opus-4-8"
        try:
            m = build_manifest(self._config(), tools=[], tool_probe=lambda b: "x")
            self.assertEqual(m["agent_model"], "claude-opus-4-8")
        finally:
            os.environ.pop("AEGIS_MODEL", None)


class SarifTest(unittest.TestCase):
    def test_sarif_structure_and_levels(self):
        from local_harness.sarif import findings_to_sarif
        findings = [
            {"title": "SQLi at login", "vuln_type": "sqli", "severity": "critical",
             "url": "http://x/login?id=1", "evidence": "boolean differential"},
            {"title": "Missing HSTS", "vuln_type": "security_headers", "severity": "low",
             "url": "http://x/"},
        ]
        doc = findings_to_sarif(findings, version="abc123")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["version"], "abc123")
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"sqli", "security_headers"})
        levels = [r["level"] for r in run["results"]]
        self.assertIn("error", levels)   # critical
        self.assertIn("note", levels)    # low
        loc = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(loc, "http://x/login?id=1")

    def test_empty_and_malformed(self):
        from local_harness.sarif import findings_to_sarif
        doc = findings_to_sarif([])
        self.assertEqual(doc["runs"][0]["results"], [])
        doc2 = findings_to_sarif([{"foo": "bar"}, "not-a-dict"])
        self.assertEqual(len(doc2["runs"][0]["results"]), 1)  # dict kept, str skipped
        self.assertEqual(doc2["runs"][0]["results"][0]["ruleId"], "finding")


if __name__ == "__main__":
    unittest.main()
