from local_harness.eval_gate import evaluate_report

SUITES = {
    "defaults": {
        "min_verified_recall": 0.6,
        "min_verified_precision": 0.8,
        "max_guardrail_blocks": 0,
        "max_scan_errors": 0,
    },
    "suites": {"strict": {"min_verified_precision": 0.95}},
}


def test_eval_gate_passes_a_healthy_report() -> None:
    report = {
        "aggregate": {
            "findings": {"verified_recall": 0.75, "verified_precision": 0.9},
            "guardrail_blocks": 0,
        },
        "scan_errors": [],
    }
    result = evaluate_report(report, skill_id="default", suites=SUITES)
    assert result.passed is True
    assert result.failures == ()


def test_eval_gate_reports_all_regressions_and_applies_override() -> None:
    report = {
        "aggregate": {
            "findings": {"verified_recall": 0.5, "verified_precision": 0.9},
            "guardrail_blocks": 2,
        },
        "scan_errors": ["target-a"],
    }
    result = evaluate_report(report, skill_id="strict", suites=SUITES)
    assert result.passed is False
    assert len(result.failures) == 4
    assert "verified_precision" in result.failures[1]
