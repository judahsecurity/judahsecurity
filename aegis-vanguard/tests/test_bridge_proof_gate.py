"""The proof gate governs submission: no finding leaves labelled 'confirmed'
without a proof token, and inventory findings are untouched."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from asm_bridge import ASMBridge, Finding
from agent.finding_oracle import (
    ProofLedger,
    register_proof,
    reset_proof_ledger,
    set_proof_ledger,
)


class BridgeProofGateTest(unittest.TestCase):
    def setUp(self):
        reset_proof_ledger()
        set_proof_ledger(ProofLedger())
        # No API url → flush is a dry-run; findings are still gated + sinked.
        self.bridge = ASMBridge(api_url="", api_key="")

    def tearDown(self):
        reset_proof_ledger()

    def _vuln(self, **kw):
        base = dict(type="vulnerability", source="hunter", target="app.example.com",
                    host="app.example.com", title="BAC on /account",
                    url="http://app.example.com/account", severity="high",
                    confidence="confirmed")
        base.update(kw)
        return Finding(**base)

    def test_confirmed_finding_with_proof_is_tagged(self):
        register_proof("response_diff", verified=True,
                       subject="http://app.example.com/account", detail="BAC")
        f = self._vuln()
        self.bridge._apply_proof_gate(f)
        self.assertIn("proof:confirmed", f.tags)
        self.assertEqual(f.confidence, "confirmed")
        self.assertTrue(f.raw_data["verification"]["confirmed"])

    def test_unproven_confirmed_is_demoted(self):
        f = self._vuln()  # claims confirmed, but no proof token registered
        self.bridge._apply_proof_gate(f)
        self.assertIn("proof:needs_evidence", f.tags)
        self.assertIn("downgraded:no_proof", f.tags)
        self.assertEqual(f.confidence, "needs_evidence")
        self.assertEqual(self.bridge.stats.get("gate_downgraded"), 1)

    def test_inventory_finding_untouched(self):
        f = Finding(type="subdomain", source="subfinder", target="x.example.com",
                    host="x.example.com", title="Subdomain", confidence="high")
        self.bridge._apply_proof_gate(f)
        self.assertNotIn("proof:needs_evidence", f.tags)
        self.assertEqual(f.confidence, "high")

    def test_disabled_via_env(self):
        os.environ["AEGIS_PROOF_GATE_SUBMISSION"] = "false"
        try:
            f = self._vuln()
            self.bridge._apply_proof_gate(f)
            self.assertNotIn("proof:needs_evidence", f.tags)
            self.assertEqual(f.confidence, "confirmed")
        finally:
            del os.environ["AEGIS_PROOF_GATE_SUBMISSION"]

    def test_flush_gates_and_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            sink = Path(tmp) / "findings.jsonl"
            os.environ["AEGIS_FINDINGS_SINK"] = str(sink)
            try:
                self.bridge.submit_finding(self._vuln())  # unproven confirmed
                self.bridge.flush()
                rows = [json.loads(line) for line in sink.read_text().splitlines()]
            finally:
                del os.environ["AEGIS_FINDINGS_SINK"]
        self.assertEqual(rows[0]["confidence"], "needs_evidence")
        self.assertIn("proof:needs_evidence", rows[0]["tags"])


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
