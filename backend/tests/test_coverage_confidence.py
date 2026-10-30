"""coverage_confidence_statement: a run never reports a silent clean result."""

from app.services.agent.engagement_brain import coverage_confidence_statement


def _coverage(**overrides):
    base = {
        "denominator": 10,
        "finding": 2,
        "tested_clean": 8,
        "skipped": 0,
        "inconclusive": 0,
        "untested_count": 0,
        "cell_denominator": 40,
        "open_cell_count": 0,
        "verified_checks": 40,
        "pending_proof_escalation_count": 0,
    }
    base.update(overrides)
    return base


def test_complete_run_states_what_was_covered():
    assessment = {
        "complete": True,
        "threat_model_present": True,
        "coverage": _coverage(),
        "pending_candidates": [],
        "unpublished_candidates": [],
    }
    out = coverage_confidence_statement(assessment)
    assert "## Assessment coverage" in out
    assert "Tested 10/10 mapped surfaces" in out
    assert "findings=2, clean=8" in out
    assert "40/40 test cells complete" in out
    assert "Confidence: complete" in out
    assert "not a guarantee of security" in out


def test_partial_closure_names_the_reason():
    assessment = {
        "complete": False,
        "threat_model_present": True,
        "coverage": _coverage(
            tested_clean=5, untested_count=3, open_cell_count=12, inconclusive=2
        ),
        "pending_candidates": ["c1"],
        "unpublished_candidates": [],
    }
    out = coverage_confidence_statement(assessment, partial_reason="time budget exhausted")
    assert "Confidence: partial" in out
    assert "time budget exhausted" in out
    assert "3 untested surfaces, 2 inconclusive, 12 open cells" in out
    assert "1 pending candidates" in out


def test_open_run_tells_agent_to_review_before_closing():
    assessment = {
        "complete": False,
        "threat_model_present": True,
        "coverage": _coverage(untested_count=4, open_cell_count=9),
        "pending_candidates": [],
        "unpublished_candidates": [],
    }
    out = coverage_confidence_statement(assessment, partial_reason="")
    assert "Confidence: incomplete" in out
    assert "Review the threat model and scoped_assessment_summary before closing" in out


def test_missing_threat_model_is_called_out():
    assessment = {
        "complete": False,
        "threat_model_present": False,
        "coverage": _coverage(),
        "pending_candidates": [],
        "unpublished_candidates": [],
    }
    out = coverage_confidence_statement(assessment)
    assert "No threat model recorded." in out


def test_missing_or_malformed_coverage_does_not_crash():
    assessment = {"complete": False, "coverage": {}, "pending_candidates": []}
    out = coverage_confidence_statement(assessment)
    assert "Tested 0/0 mapped surfaces" in out
    assert "Confidence: incomplete" in out
