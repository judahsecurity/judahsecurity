"""Bounded pilot runs must be able to confirm SQLi and must finish cleanly."""

import asyncio
from types import SimpleNamespace

from app.services.agent import pilot_policy
from app.services.agent.engagement_brain import (
    EngagementBrain,
    coverage_progress,
    record_surface_coverage,
    seed_coverage_from_surfaces,
)
from app.services.agent.independent_verify import (
    FindingCandidate,
    _unprovable_sql_candidate_gap,
)
from app.services.agent.orchestrator import (
    COMPLETE_GATE_PARTIAL_REASON,
    MAX_CONSECUTIVE_COMPLETE_BLOCKS,
    _complete_block_note,
    _next_complete_block,
)


class _FakePilot:
    def __init__(self):
        self.reserved = []
        self.expires_at_ms = 0

    async def acquire(self, url, method):
        self.reserved.append((url, method))
        return len(self.reserved)


def test_pilot_allows_scoped_sqli_proof_tools_as_gated_network_tools():
    for tool in ("scoped_string_sqli", "scoped_numeric_sqli"):
        assert tool in pilot_policy.PILOT_NETWORK_TOOLS
        assert tool in pilot_policy.PILOT_ALLOWED_TOOLS


def test_request_gate_is_noop_outside_pilot():
    token = pilot_policy.set_pilot(None)
    try:
        assert pilot_policy.pilot_request_gate("https://shop.test/catalog")() is None
    finally:
        pilot_policy.reset_pilot(token)


def test_request_gate_reserves_pilot_budget_from_worker_thread():
    fake = _FakePilot()
    token = pilot_policy.set_pilot(fake)
    try:
        gate = pilot_policy.pilot_request_gate("https://shop.test/catalog?category=x")

        async def run():
            # Scoped SQLi recipes call the hook from asyncio.to_thread workers.
            await asyncio.to_thread(gate)
            await asyncio.to_thread(gate)

        asyncio.run(run())
    finally:
        pilot_policy.reset_pilot(token)
    assert fake.reserved == [("https://shop.test/catalog?category=x", "GET")] * 2


def _manager():
    return SimpleNamespace(_engagement_brain={})


def test_sql_lead_without_confirmed_receipt_skips_model_verifier():
    manager = _manager()
    from app.services.agent.evidence_store import evidence_store

    differential = evidence_store(manager).record(
        "compare_requests", {"baseline": 200, "quote": 500},
        target="https://shop.test/catalog", success=True,
    )
    cand = FindingCandidate(
        id="c1", title="SQL injection in category", target="https://shop.test/catalog",
        vulnerability_class="sql_injection", parameter="query:category",
        evidence_ids=[differential],
    )
    gap = _unprovable_sql_candidate_gap(manager, cand)
    assert "scoped_string_sqli" in gap
    assert "parameter=category" in gap


def test_sql_lead_with_confirmed_scoped_receipt_goes_to_verification():
    manager = _manager()
    from app.services.agent.evidence_store import evidence_store

    receipt = evidence_store(manager).record(
        "scoped_string_sqli", {"parameter": "category", "proof_confirmed": True},
        target="https://shop.test/catalog", success=True,
    )
    cand = FindingCandidate(
        id="c2", title="SQL injection in category", target="https://shop.test/catalog",
        vulnerability_class="sql_injection", evidence_ids=[receipt],
    )
    assert _unprovable_sql_candidate_gap(manager, cand) == ""


def test_non_sql_candidate_is_not_short_circuited():
    cand = FindingCandidate(id="c3", title="Reflected XSS", vulnerability_class="xss")
    assert _unprovable_sql_candidate_gap(_manager(), cand) == ""


def test_blocked_complete_is_counted_and_shown_to_planner():
    state = {}
    for expected in range(1, MAX_CONSECUTIVE_COMPLETE_BLOCKS + 1):
        state["complete_blocks"] = _next_complete_block(state, "Blocking: sqli cell open")
        assert state["complete_blocks"]["count"] == expected
    note = _complete_block_note(state["complete_blocks"])
    assert "WAS BLOCKED" in note and "sqli cell open" in note
    assert _complete_block_note(None) == ""
    assert "completion gate blocked repeatedly" in COMPLETE_GATE_PARTIAL_REASON.lower()


def _inconclusive_brain():
    brain = EngagementBrain(surfaces=[{
        "method": "GET", "path": "/catalog", "host": "shop.test", "takes_input": True,
    }])
    seed_coverage_from_surfaces(brain)
    record_surface_coverage(
        brain, method="GET", path="/catalog", host="shop.test",
        status="inconclusive", reason="quote returned 500; verifier inconclusive",
        test_type="sqli", parameter="query:category", identity="anonymous",
    )
    return brain


def _progress(brain, pilot):
    for cell in brain.coverage_cells:
        if cell.get("status") == "inconclusive":
            cell["evidence_ids"] = ["a" * 32]
    token = pilot_policy.set_pilot(pilot)
    try:
        return coverage_progress(brain)
    finally:
        pilot_policy.reset_pilot(token)


def _open_kinds(progress):
    return sorted((c.get("status"), c.get("test_type")) for c in progress["open_cells"])


def test_pilot_treats_inconclusive_cell_with_evidence_as_accounted():
    progress = _progress(_inconclusive_brain(), _FakePilot())
    assert progress["inconclusive"] == 1  # still reported as open work
    # Only the untested surface review remains open; the probed SQLi cell is accounted.
    assert _open_kinds(progress) == [("untested", "surface_review")]


def test_non_pilot_inconclusive_cell_still_blocks_completion():
    progress = _progress(_inconclusive_brain(), None)
    assert ("inconclusive", "sqli") in _open_kinds(progress)
    assert progress["ready_to_complete_coverage"] is False


def test_pilot_inconclusive_cell_without_evidence_stays_open():
    progress = _progress_without_evidence(_inconclusive_brain())
    assert ("inconclusive", "sqli") in _open_kinds(progress)


def _progress_without_evidence(brain):
    token = pilot_policy.set_pilot(_FakePilot())
    try:
        return coverage_progress(brain)
    finally:
        pilot_policy.reset_pilot(token)
