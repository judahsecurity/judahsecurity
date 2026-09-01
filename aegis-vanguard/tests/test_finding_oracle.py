"""Finding proof gate: CONFIRMED requires a machine-checkable proof token.

This is the generalization of the flag oracle to every finding. A confident
report is not evidence; a verified proof token (flag capture, response-diff BAC
signature, browser JS-exec) is. Findings without one are downgraded to
NEEDS_EVIDENCE — the exact failure mode from the hallucinated pentest report.
"""

import json
import os
import unittest
from pathlib import Path

from agent.finding_oracle import (
    CONFIRMED,
    NEEDS_EVIDENCE,
    ProofLedger,
    ProofToken,
    grade_finding,
    grade_findings,
    normalize_subject,
    proof_gate_markdown,
    register_proof,
    reset_proof_ledger,
    set_proof_ledger,
)
from agent.http_session import (
    HttpResponse,
    ProxyBackend,
    SessionStore,
    set_backend,
    set_session_store,
    reset_session,
)

PRIVATE = "<h1>Account 1001</h1> SSN 555-01-1001"


class FakeBackend(ProxyBackend):
    name = "fake"

    def __init__(self, responder):
        self.responder = responder

    def send(self, request):
        return self.responder(request)


def _tok(subject, kind="response_diff", verified=True, tid="proof-x", detail=""):
    return ProofToken(token_id=tid, kind=kind, verified=verified,
                      subject=normalize_subject(subject), detail=detail)


class SubjectTest(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_subject("https://t.com/api/x?id=1"), "t.com/api/x")
        self.assertEqual(normalize_subject("/api/x/"), "/api/x")


class GradeFindingTest(unittest.TestCase):
    def test_confirmed_by_explicit_token_id(self):
        proofs = [_tok("http://t/a", tid="proof-0007")]
        v = grade_finding({"title": "x", "proof_token_id": "proof-0007"}, proofs)
        self.assertEqual(v.status, CONFIRMED)
        self.assertIn("proof-0007", v.proof_token_ids)

    def test_confirmed_by_subject_correlation(self):
        proofs = [_tok("http://t.com/account")]
        v = grade_finding({"title": "IDOR", "endpoint": "/account"}, proofs)
        self.assertEqual(v.status, CONFIRMED)

    def test_confirmed_by_flag_in_text(self):
        proofs = [_tok("http://t/redirect.php", kind="flag", detail="FLAG{abc}")]
        v = grade_finding({"title": "SSRF", "evidence": "got FLAG{abc} back"}, proofs)
        self.assertEqual(v.status, CONFIRMED)

    def test_needs_evidence_without_proof(self):
        v = grade_finding({"title": "SQLi", "endpoint": "/login"}, [])
        self.assertEqual(v.status, NEEDS_EVIDENCE)

    def test_unverified_token_does_not_confirm(self):
        proofs = [_tok("http://t/a", verified=False)]
        v = grade_finding({"title": "x", "endpoint": "/a"}, proofs)
        self.assertEqual(v.status, NEEDS_EVIDENCE)


class GradeFindingsTest(unittest.TestCase):
    def test_counts_and_markdown(self):
        proofs = [_tok("http://t/account", tid="proof-1")]
        findings = [
            {"title": "IDOR on account", "endpoint": "/account", "severity": "high"},
            {"title": "Missing headers", "endpoint": "/", "severity": "low"},
        ]
        report = grade_findings(findings, proofs)
        self.assertEqual((report["total"], report["confirmed"],
                          report["needs_evidence"]), (2, 1, 1))
        md = proof_gate_markdown(report)
        self.assertIn("1 of 2 findings", md)
        self.assertIn("✅ CONFIRMED", md)
        self.assertIn("⚠️ NEEDS_EVIDENCE", md)

    def test_hallucinated_report_all_downgraded(self):
        """No proofs recorded → nothing is CONFIRMED, mirroring the fake run."""
        findings = [{"title": f"finding {i}", "endpoint": f"/x{i}"} for i in range(7)]
        report = grade_findings(findings, [])
        self.assertEqual(report["confirmed"], 0)
        self.assertEqual(report["needs_evidence"], 7)


class LedgerTest(unittest.TestCase):
    def setUp(self):
        reset_proof_ledger()

    def tearDown(self):
        reset_proof_ledger()

    def test_register_and_verified_filter(self):
        from agent.finding_oracle import get_proof_ledger
        set_proof_ledger(ProofLedger())
        register_proof("response_diff", verified=True, subject="http://t/a")
        register_proof("response_diff", verified=False, subject="http://t/b")
        self.assertEqual(len(get_proof_ledger().all()), 2)
        self.assertEqual(len(get_proof_ledger().verified()), 1)


class ProducerIntegrationTest(unittest.TestCase):
    def setUp(self):
        reset_session()
        reset_proof_ledger()
        set_session_store(SessionStore())

    def tearDown(self):
        reset_session()
        reset_proof_ledger()

    def test_replay_bac_signature_confirms_matching_finding(self):
        from agent import agents
        # Vulnerable app: serves private body regardless of identity.
        set_backend(FakeBackend(lambda r: HttpResponse(200, {}, PRIVATE)))
        agents.replay_request(
            method="GET", url="http://t/account?id=1001",
            headers_json='{"Cookie": "session=alice"}',
            mutations_json='{"strip_auth": true}')

        v = grade_finding({"title": "Broken access control on /account",
                           "endpoint": "http://t/account"})
        self.assertEqual(v.status, CONFIRMED)

    def test_object_id_swap_is_not_auto_verified(self):
        from agent import agents
        set_backend(FakeBackend(lambda r: HttpResponse(200, {}, PRIVATE)))
        out = json.loads(agents.replay_request(
            method="GET", url="http://t/account?id=1001",
            mutations_json='{"set_query": {"id": "1002"}}'))
        self.assertEqual(out["proof"], "recorded (unverified)")
        v = grade_finding({"title": "IDOR", "endpoint": "http://t/account"})
        self.assertEqual(v.status, NEEDS_EVIDENCE)

    def test_dom_xss_registers_browser_exec_proof(self):
        from agent import agents
        import scanners
        orig, orig_bridge = scanners.run_dom_xss_test, agents._get_bridge
        scanners.run_dom_xss_test = lambda url, bridge, **kw: [
            {"url": url, "evidence": "window.__vanguard_xss=1"}]
        agents._get_bridge = lambda: None
        try:
            agents.test_dom_xss("http://t/search?q=1")
        finally:
            scanners.run_dom_xss_test = orig
            agents._get_bridge = orig_bridge

        v = grade_finding({"title": "DOM XSS in q", "url": "http://t/search"})
        self.assertEqual(v.status, CONFIRMED)


class FlagSourceTest(unittest.TestCase):
    def tearDown(self):
        from agent.flag_oracle import reset_flag_oracle
        reset_flag_oracle()
        reset_proof_ledger()

    def test_captured_flag_confirms_finding(self):
        from agent.flag_oracle import FlagOracle, set_flag_oracle
        set_flag_oracle(FlagOracle())
        set_flag_oracle(FlagOracle())  # fresh
        from agent.flag_oracle import get_flag_oracle
        get_flag_oracle().scan("send_http_request",
                               {"url": "http://t/redirect.php"},
                               '{"body": "FLAG{deadbeef}"}')
        reset_proof_ledger()
        v = grade_finding({"title": "SSRF", "evidence": "leaked FLAG{deadbeef}",
                           "endpoint": "/redirect.php"})
        # endpoint correlates to the flag token's subject even if the text flag differs
        self.assertEqual(v.status, CONFIRMED)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
