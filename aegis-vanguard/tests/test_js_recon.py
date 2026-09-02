"""JS attack-surface analysis: DOM XSS sink/source flows + secrets, as leads.

A source reaching a sink in the same file is a DOM XSS candidate that aims
test_dom_xss; it is a lead (NEEDS_EVIDENCE), never auto-confirmed — the browser
prover earns the proof token.
"""

import json
import os
import re
import unittest
from pathlib import Path

from agent.js_recon import (
    analyze_js,
    load_secret_patterns,
    scan_js_for_secrets,
    scan_js_for_sinks,
    _xss_candidates,
)

VULN_JS = """
    const q = new URLSearchParams(location.search).get('q');
    document.getElementById('out').innerHTML = q;   // source -> sink
"""
SAFE_JS = "fetch('/api/data').then(r => r.json());"   # network only, no sink flow
SECRET_JS = "const key = 'AKIAIOSFODNN7EXAMPLE'; // aws"


class SinkTest(unittest.TestCase):
    def test_detects_source_and_sink(self):
        hits = scan_js_for_sinks(VULN_JS, "app.js")
        types = {h["type"] for h in hits}
        roles = {h["role"] for h in hits}
        self.assertIn("url-search-params", types)
        self.assertIn("location-read", types)
        self.assertIn("innerHTML", types)
        self.assertIn("source", roles)
        self.assertIn("sink", roles)

    def test_network_only_has_no_sink(self):
        hits = scan_js_for_sinks(SAFE_JS, "safe.js")
        self.assertTrue(all(h["role"] == "network" for h in hits))


class CandidateTest(unittest.TestCase):
    def test_source_plus_sink_is_a_candidate(self):
        leads = _xss_candidates(scan_js_for_sinks(VULN_JS, "app.js"))
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["vuln_type"], "dom_xss_candidate")
        self.assertIn("test_dom_xss", leads[0]["aim"])

    def test_sink_only_is_not_a_candidate(self):
        leads = _xss_candidates(scan_js_for_sinks("el.innerHTML = 'static';", "x.js"))
        self.assertEqual(leads, [])


class SecretTest(unittest.TestCase):
    def test_finds_aws_key(self):
        pats = [("AWS API Key", re.compile(r"AKIA[0-9A-Z]{16}"))]
        found = scan_js_for_secrets(SECRET_JS, pats)
        self.assertEqual(found[0]["name"], "AWS API Key")

    def test_vendored_db_loads(self):
        pats = load_secret_patterns()
        self.assertGreater(len(pats), 1000)   # ~1600-pattern corpus


class AnalyzeTest(unittest.TestCase):
    def test_analyze_combines_and_flags_leads(self):
        report = analyze_js({"app.js": VULN_JS, "s.js": SECRET_JS})
        self.assertEqual(len(report["dom_xss_candidates"]), 1)
        self.assertTrue(any(s["name"] == "AWS API Key" for s in report["secrets"]))
        self.assertIn("NEEDS_EVIDENCE", report["summary"])

    def test_leads_are_needs_evidence_in_the_gate(self):
        from agent.finding_oracle import (
            grade_finding, set_proof_ledger, ProofLedger, reset_proof_ledger,
            NEEDS_EVIDENCE,
        )
        reset_proof_ledger()
        set_proof_ledger(ProofLedger())
        try:
            lead = analyze_js({"app.js": VULN_JS})["dom_xss_candidates"][0]
            # a static candidate has no proof token until test_dom_xss proves it
            self.assertEqual(grade_finding(lead).status, NEEDS_EVIDENCE)
        finally:
            reset_proof_ledger()


class ToolWiringTest(unittest.TestCase):
    def setUp(self):
        from agent.http_session import reset_session, set_backend, ProxyBackend, HttpResponse

        class JsBackend(ProxyBackend):
            name = "js"

            def send(self, request):
                return HttpResponse(200, {"Content-Type": "application/javascript"}, VULN_JS)

        reset_session()
        set_backend(JsBackend())

    def tearDown(self):
        from agent.http_session import reset_session
        reset_session()

    def test_analyze_js_tool_fetches_and_reports(self):
        from agent import agents
        out = json.loads(agents.analyze_js(urls="http://t/app.js", with_secrets=False))
        self.assertEqual(out["files_scanned"], 1)
        self.assertEqual(len(out["dom_xss_candidates"]), 1)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
