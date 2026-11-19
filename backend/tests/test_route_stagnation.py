"""Dead routes stay closed without new information; stagnant classes get flagged."""

import pytest

from app.services.agent.coverage_cells import (
    class_stagnation,
    format_stagnation_note,
    record_coverage_cell,
)
from app.services.agent.engagement_brain import EngagementBrain, record_surface_coverage


def _brain() -> EngagementBrain:
    return EngagementBrain(target="https://app.test")


def _close(brain, parameter="q", test_type="sqli", evidence_id="ev-1", status="tested_clean"):
    return record_coverage_cell(
        brain, method="GET", path="/search", host="app.test", status=status,
        identity="anonymous", parameter=parameter, test_type=test_type,
        evidence_id=evidence_id, reason="paired controls identical",
    )


def test_reopening_a_clean_route_without_anything_new_is_refused() -> None:
    brain = _brain()
    _close(brain)
    with pytest.raises(ValueError, match="closed as tested_clean"):
        record_coverage_cell(
            brain, method="GET", path="/search", host="app.test", status="in_focus",
            identity="anonymous", parameter="q", test_type="sqli",
            reason="try again",
        )
    with pytest.raises(ValueError, match="new_lead"):
        record_coverage_cell(
            brain, method="GET", path="/search", host="app.test", status="untested",
            identity="anonymous", parameter="q", test_type="sqli",
            evidence_id="ev-1", reason="same evidence again",
        )


def test_new_evidence_or_a_stated_lead_reopens_the_route() -> None:
    brain = _brain()
    _close(brain)
    cell = record_coverage_cell(
        brain, method="GET", path="/search", host="app.test", status="in_focus",
        identity="anonymous", parameter="q", test_type="sqli",
        evidence_id="ev-2", reason="new error string",
    )
    assert cell["status"] == "in_focus"
    assert cell["reopened"][-1]["evidence_id"] == "ev-2"

    blocked = _brain()
    _close(blocked, status="blocked")
    cell = record_coverage_cell(
        blocked, method="GET", path="/search", host="app.test", status="untested",
        identity="anonymous", parameter="q", test_type="sqli",
        new_lead="JS bundle shows q is also read from the X-Search header",
    )
    assert cell["reopened"][-1]["new_lead"].startswith("JS bundle")


def test_closing_or_finding_on_a_dead_route_needs_no_lead() -> None:
    brain = _brain()
    _close(brain)
    cell = _close(brain, status="finding", evidence_id="ev-9")
    assert cell["status"] == "finding"
    assert "reopened" not in cell


def test_surface_coverage_passes_new_lead_through() -> None:
    brain = _brain()
    kwargs = dict(method="GET", path="/search", host="app.test", identity="anonymous",
                  parameter="q", test_type="sqli", reason="clean")
    record_surface_coverage(brain, status="tested_clean", evidence_id="ev-1", **kwargs)
    with pytest.raises(ValueError):
        record_surface_coverage(brain, status="inconclusive", **kwargs)
    row = record_surface_coverage(
        brain, status="inconclusive", new_lead="second parameter q2 found in sitemap",
        **kwargs,
    )
    assert row["coverage_cell"]["status"] == "inconclusive"


def test_class_with_repeated_empty_attempts_is_stagnant() -> None:
    brain = _brain()
    for i, parameter in enumerate(("q", "id", "page")):
        _close(brain, parameter=parameter, evidence_id=f"ev-{i}")
    _close(brain, parameter="name", test_type="xss", evidence_id="ev-x")

    rows = class_stagnation(brain)
    assert [row["test_type"] for row in rows] == ["sqli"]
    assert rows[0]["attempts"] == 3 and rows[0]["closed"] == 3
    note = format_stagnation_note(brain)
    assert "sqli: 3 attempts" in note
    assert "xss" not in note


def test_a_single_candidate_makes_the_class_productive() -> None:
    brain = _brain()
    for i, parameter in enumerate(("q", "id", "page")):
        _close(brain, parameter=parameter, evidence_id=f"ev-{i}")
    record_coverage_cell(
        brain, method="GET", path="/item", host="app.test", status="in_focus",
        identity="anonymous", parameter="sku", test_type="sqli",
        candidate_id="cand-1", reason="error-based signal",
    )
    assert class_stagnation(brain) == []
    assert format_stagnation_note(brain) == ""
