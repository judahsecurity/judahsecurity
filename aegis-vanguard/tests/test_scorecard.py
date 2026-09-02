"""Performance scorecard: score run artifacts, aggregate, catch regressions.

Includes a full-loop test that scores the exact findings document our own
build_findings_document emits, so the measurement instrument is wired to the
real artifact shape, not a mock of it.
"""

import json
import os
import unittest
from pathlib import Path

from agent.scorecard import (
    aggregate,
    compare,
    load_runs,
    render_markdown,
    score_run,
)


def _doc(target, total, confirmed, kinds):
    return {
        "target": target,
        "total": total,
        "confirmed": confirmed,
        "needs_evidence": total - confirmed,
        "verified_proof_tokens": [{"kind": k} for k in kinds],
    }


class ScoreRunTest(unittest.TestCase):
    def test_rates_and_kinds(self):
        s = score_run(_doc("app", 4, 3, ["flag", "oob", "response_diff"]),
                      {"status": "PASS"})
        self.assertEqual(s["confirmed_rate"], 0.75)
        self.assertEqual(s["flag"], "PASS")
        self.assertEqual(s["proof_tokens"], {"flag": 1, "oob": 1, "response_diff": 1})

    def test_zero_findings_rate_is_none(self):
        s = score_run(_doc("app", 0, 0, []))
        self.assertIsNone(s["confirmed_rate"])


class AggregateTest(unittest.TestCase):
    def test_suite_aggregate(self):
        scores = [
            score_run(_doc("a", 4, 2, ["flag", "oob"]), {"status": "PASS"}),
            score_run(_doc("b", 2, 2, ["response_diff", "browser_exec"]), {"status": "FAIL"}),
            score_run(_doc("c", 0, 0, []), {"status": "NO_EXPECTED_FLAG"}),
        ]
        agg = aggregate(scores)
        self.assertEqual(agg["runs"], 3)
        self.assertEqual(agg["flag_graded"], 2)   # PASS + FAIL only
        self.assertEqual(agg["flag_pass"], 1)
        self.assertEqual(agg["flag_pass_rate"], 0.5)
        self.assertEqual(agg["confirmed"], 4)
        self.assertEqual(agg["findings_total"], 6)
        self.assertEqual(agg["overall_confirmed_rate"], round(4 / 6, 4))
        self.assertEqual(agg["proof_tokens"]["flag"], 1)
        self.assertIn("| a |", render_markdown(agg))


class CompareTest(unittest.TestCase):
    def _agg(self, pass_rate, conf_rate, total, needs):
        return {"flag_pass_rate": pass_rate, "overall_confirmed_rate": conf_rate,
                "mean_confirmed_rate": conf_rate, "confirmed": total - needs,
                "findings_total": total, "needs_evidence": needs}

    def test_regression_detected(self):
        cur = self._agg(0.4, 0.5, 10, 5)
        base = self._agg(0.6, 0.7, 10, 2)
        diff = compare(cur, base)
        self.assertTrue(diff["regressed"])
        self.assertTrue(any("flag_pass_rate" in r for r in diff["regressions"]))
        self.assertTrue(any("needs_evidence" in r for r in diff["regressions"]))

    def test_improvement_not_a_regression(self):
        cur = self._agg(0.8, 0.9, 10, 1)
        base = self._agg(0.6, 0.7, 10, 3)
        diff = compare(cur, base)
        self.assertFalse(diff["regressed"])
        self.assertTrue(diff["improvements"])

    def test_tolerance_suppresses_noise(self):
        cur = self._agg(0.60, 0.69, 10, 2)
        base = self._agg(0.60, 0.70, 10, 2)
        self.assertFalse(compare(cur, base, tolerance=0.05)["regressed"])


class LoadRunsTest(unittest.TestCase):
    def test_pairs_findings_with_grade(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "findings_s1.json").write_text(json.dumps(_doc("app", 3, 2, ["oob"])))
            (d / "grade_s1.json").write_text(json.dumps({"status": "PASS"}))
            (d / "findings_s2.json").write_text(json.dumps(_doc("app2", 1, 0, [])))
            scores = load_runs(str(d))
            self.assertEqual(len(scores), 2)
            byt = {s["target"]: s for s in scores}
            self.assertEqual(byt["app"]["flag"], "PASS")
            self.assertIsNone(byt["app2"]["flag"])


class FullLoopTest(unittest.TestCase):
    """Score the real artifact our builder emits, end to end."""

    def test_scores_real_findings_document(self):
        from agent.finding_oracle import (
            build_findings_document, set_proof_ledger, ProofLedger, register_proof,
            reset_proof_ledger,
        )
        reset_proof_ledger()
        set_proof_ledger(ProofLedger())
        register_proof("response_diff", True, subject="http://app/account")
        try:
            doc = build_findings_document(
                [{"title": "BAC", "endpoint": "http://app/account", "severity": "high"},
                 {"title": "headers", "endpoint": "/", "severity": "low"}],
                target="app")
            s = score_run(doc, {"status": "NO_EXPECTED_FLAG"})
            self.assertEqual(s["findings_total"], 2)
            self.assertEqual(s["confirmed"], 1)
            self.assertEqual(s["confirmed_rate"], 0.5)
            self.assertEqual(s["proof_tokens"].get("response_diff"), 1)
        finally:
            reset_proof_ledger()


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
