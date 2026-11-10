"""Coverage gaps: cells that cannot progress are accounted for, never clean.

Open cells that no automatic step can advance (blocked on an operator
decision, or exhausted by repeated specialist leases) used to keep a run from
ever completing, so every run ended on budget. They are now listed as
coverage gaps: they stop being leased, they let the run complete, and they
are reported as untested.
"""

from app.services.agent.coverage_cells import (
    MAX_CELL_ATTEMPTS,
    claim_coverage_cell_leases,
    coverage_gap_code,
    release_coverage_cell_lease,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain, coverage_progress


def _row(name, *, source="observed_form", artifact_id=""):
    return {"method": "GET", "host": "app.test", "path": "/catalog", "location": "query",
            "name": name, "identity": "anonymous", "source": source,
            "artifact_id": artifact_id, "testable": True}


def _brain(*names):
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_row(name) for name in names])
    return brain


def _xss_id(brain, name):
    return next(cell["id"] for cell in brain.coverage_cells
                if cell["test_type"] == "xss" and cell["parameter"] == f"query:{name}")


def _cell(brain, cell_id):
    # Migration rebuilds the cell list, so always read the live row by id.
    return next(cell for cell in brain.coverage_cells if cell["id"] == cell_id)


def _close_everything_but(brain, *keep):
    for cell in brain.coverage_cells:
        if cell["id"] not in keep:
            cell.update(status="tested_clean", evidence_ids=["e"])


def test_inconclusive_cell_stops_being_leased_after_the_attempt_cap():
    brain = _brain("q")
    cid = _xss_id(brain, "q")
    _close_everything_but(brain, cid)
    for attempt in range(1, MAX_CELL_ATTEMPTS + 1):
        lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
        assert lease.coverage_cell_id == cid and lease.attempt == attempt
        release_coverage_cell_lease(brain, lease, verdict="inconclusive", reason="no signal")
    assert coverage_gap_code(_cell(brain, cid)) == "attempts_exhausted"
    assert claim_coverage_cell_leases(brain, ["xss"]) == {}


def test_gaps_let_coverage_complete_but_are_listed_and_not_clean():
    brain = _brain("q", "id", "sort")
    exhausted, blocked, live = (_xss_id(brain, n) for n in ("q", "id", "sort"))
    _close_everything_but(brain, exhausted, blocked, live)
    _cell(brain, exhausted).update(status="inconclusive", attempts=MAX_CELL_ATTEMPTS)
    _cell(brain, blocked).update(status="blocked", first_pass_blocked_reason="identity_unavailable")
    _cell(brain, live).update(status="inconclusive", attempts=1)

    progress = coverage_progress(brain)
    assert progress["ready_to_complete_coverage"] is False  # one cell is still actionable
    assert progress["open_cell_count"] == 1
    assert progress["coverage_gap_counts"] == {
        "attempts_exhausted": 1, "needs_operator:identity_unavailable": 1,
    }

    _cell(brain, live).update(status="tested_clean", evidence_ids=["e2"])
    progress = coverage_progress(brain)
    assert progress["ready_to_complete_coverage"] is True
    assert progress["coverage_gap_count"] == 2
    assert {row["id"] for row in progress["coverage_gaps"]} == {exhausted, blocked}
    assert "2 coverage gaps (untested, not clean)" in progress["summary"]
    total = progress["cell_denominator"]
    assert f"cells {total - 2}/{total} complete" in progress["summary"]
    assert _cell(brain, exhausted)["status"] == "inconclusive"
    assert _cell(brain, blocked)["status"] == "blocked"


def test_leased_and_in_focus_cells_are_never_gaps():
    assert coverage_gap_code({"status": "leased", "lease_id": "x", "attempts": 9}) == ""
    assert coverage_gap_code({"status": "in_focus", "attempts": 9}) == ""
    assert coverage_gap_code({"status": "untested", "attempts": 9}) == ""
    assert coverage_gap_code({"status": "tested_clean"}) == ""


def test_new_browser_capture_gives_an_exhausted_cell_one_more_lease():
    brain = _brain("q")
    cid = _xss_id(brain, "q")
    _close_everything_but(brain, cid)
    _cell(brain, cid).update(status="inconclusive", attempts=MAX_CELL_ATTEMPTS,
                             probe_artifact_ids=["earlier-probe"])
    assert coverage_gap_code(_cell(brain, cid)) == "attempts_exhausted"

    seed_parameter_coverage_cells(
        brain, [_row("q", source="browser_traffic", artifact_id="fresh-capture")],
    )
    cell = _cell(brain, cid)
    assert cell["capture_id"] == "fresh-capture" and coverage_gap_code(cell) == ""
    lease = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    assert lease.coverage_cell_id == cid
    release_coverage_cell_lease(brain, lease, verdict="inconclusive")
    assert coverage_gap_code(_cell(brain, cid)) == "attempts_exhausted"
