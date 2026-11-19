"""Last light: final reports always list what the run did not cover."""

from app.services.agent.last_light import append_gaps, coverage_gaps, format_gaps

TARGET = "https://app.test"


def _state(mode="agent", **brain):
    return {
        "mode": mode,
        "target_info": {"primary_target": TARGET},
        "capability_map": {"target": TARGET, "scope": TARGET},
        "execution_trace": [],
        "engagement_brain": brain,
    }


def test_open_cells_hypotheses_and_candidates_are_listed():
    state = _state(
        coverage_cells=[
            {"id": "a", "test_type": "sqli", "status": "untested"},
            {"id": "b", "test_type": "sqli", "status": "inconclusive"},
            {"id": "c", "test_type": "xss", "status": "tested_clean"},
            {"id": "d", "test_type": "idor", "status": "leased"},
        ],
        hypotheses=[{"title": "Coupon reuse", "status": "open"},
                    {"title": "Done", "status": "killed"}],
        candidates=[{"title": "SQLi in category", "status": "pending"},
                    {"title": "Old", "status": "confirmed"}],
    )
    gaps = coverage_gaps(state)
    assert gaps["open_cells"] == 3 and gaps["open_cells_by_class"] == {"sqli": 2, "idor": 1}
    assert gaps["open_hypotheses"] == ["Coupon reuse"]
    assert gaps["unverified_candidates"] == ["SQLi in category (pending)"]
    assert gaps["missing_steps"]  # nothing ran, so the tester loop is incomplete
    text = append_gaps("Report body.", state, "Spend cap reached")
    assert text.startswith("Report body.")
    assert "## Not covered in this run" in text and "Spend cap reached" in text
    assert "sqli (2)" in text and "Coupon reuse" in text


def test_chat_answers_are_left_alone_and_clean_runs_add_nothing():
    assert append_gaps("hi", _state(mode="assist", coverage_cells=[{"status": "untested"}])) == "hi"
    clean = {"open_cells": 0, "open_hypotheses": [], "unverified_candidates": [], "missing_steps": []}
    assert format_gaps(clean) == ""


def test_pilot_runs_list_cells_but_not_tester_loop_steps():
    gaps = coverage_gaps(_state(mode="pilot", coverage_cells=[{"test_type": "xss", "status": "untested"}]))
    assert gaps["open_cells"] == 1 and gaps["missing_steps"] == []
