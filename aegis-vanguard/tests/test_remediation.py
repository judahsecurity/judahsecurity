"""Remediation advisor — classification, structured fixes, tool + reporter wiring."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class RemediationTest(unittest.TestCase):
    def test_classify_sqli_beats_generic_injection(self):
        from agent.remediation import classify
        self.assertEqual(classify({"vuln_type": "sql injection"}), "sqli")
        self.assertEqual(classify({"title": "Blind SQLi at /login"}), "sqli")

    def test_classify_specific_before_generic(self):
        from agent.remediation import classify
        # "template injection" must map to ssti, not be swallowed by injection
        self.assertEqual(classify({"title": "Server-Side Template Injection"}), "ssti")
        self.assertEqual(classify({"type": "command injection"}), "rce")

    def test_classify_unknown_returns_none(self):
        from agent.remediation import classify
        self.assertIsNone(classify({"title": "some novel weirdness"}))
        self.assertIsNone(classify({}))

    def test_advise_sqli_has_cwe_and_steps(self):
        from agent.remediation import advise
        rem = advise({"vuln_type": "sqli", "url": "https://x/login?id=1",
                      "severity": "critical"})
        self.assertTrue(rem.matched)
        self.assertEqual(rem.cwe_id, "CWE-89")
        self.assertEqual(rem.endpoint, "https://x/login?id=1")
        self.assertTrue(rem.fix_steps)
        self.assertIn("%s", rem.secure_pattern)  # parameterized-query pattern

    def test_advise_unknown_uses_fallback_not_blank(self):
        from agent.remediation import advise
        rem = advise({"title": "novel issue", "url": "https://x/y"})
        self.assertFalse(rem.matched)
        self.assertEqual(rem.vuln_class, "generic")
        self.assertTrue(rem.fix_steps)          # fallback is still actionable
        self.assertTrue(rem.verification)

    def test_advise_json_roundtrip(self):
        from agent.remediation import advise_json
        out = json.loads(advise_json(json.dumps({"vuln_type": "ssrf"})))
        self.assertEqual(out["cwe"]["id"], "CWE-918")
        self.assertIn("fix_steps", out)

    def test_advise_json_bad_input(self):
        from agent.remediation import advise_json
        self.assertIn("error", json.loads(advise_json("not json")))
        self.assertIn("error", json.loads(advise_json("[1,2,3]")))

    def test_markdown_render(self):
        from agent.remediation import advise
        md = advise({"vuln_type": "xss", "url": "https://x/q"}).to_markdown()
        self.assertIn("CWE-79", md)
        self.assertIn("Root cause", md)
        self.assertIn("Verify", md)

    def test_every_kb_entry_is_complete(self):
        from agent.remediation import _KB
        for name, tmpl in _KB.items():
            self.assertTrue(tmpl.cwe_id.startswith("CWE-"), name)
            self.assertTrue(tmpl.root_cause, name)
            self.assertTrue(tmpl.fix_steps, name)
            self.assertTrue(tmpl.secure_pattern, name)
            self.assertTrue(tmpl.verification, name)

    def test_tool_registered(self):
        import agent.agents  # noqa: F401 — registers @security_tool functions
        from agent.tools import ToolRegistry
        tool = ToolRegistry().get("suggest_remediation")
        self.assertIsNotNone(tool)
        out = json.loads(tool.function(json.dumps({"vuln_type": "idor"})))
        self.assertEqual(out["cwe"]["id"], "CWE-639")


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
