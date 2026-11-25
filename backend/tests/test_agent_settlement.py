"""Budget settlement: unsubmitted trace leads become pending candidates, never findings."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.agent import settlement

TARGET = "https://app.example.com"
EXISTING = {"id": "cand-hunter", "title": "Confirmed SQLi", "status": "confirmed",
            "vulnerability_class": "sql_injection", "target": f"{TARGET}/a?id=1",
            "root_cause": "sql_injection|app.example.com/a|id", "specialist": "sqli",
            "revision": 1, "evidence_ids": ["e1"]}


def _state(**extra):
    state = {
        "session_id": "s1", "organization_id": 12, "mode": "agent",
        "current_iteration": 15, "max_iterations": 15, "current_phase": "exploitation",
        "original_objective": f"Assess {TARGET}",
        "capability_map": {"target": TARGET},
        "target_info": {"primary_target": TARGET},
        "engagement_brain": {"candidates": [dict(EXISTING)], "notes": ["keep me"]},
        "execution_trace": [{"iteration": 14, "phase": "exploitation", "thought": "probe",
                             "tool_name": "send_http_request", "success": True,
                             "output_analysis": "500 with ORA-01756 on q="}],
    }
    state.update(extra)
    return state


LEAD = {"title": "Possible SQLi in search q", "target": f"{TARGET}/search?q=x",
        "vulnerability_class": "sql_injection", "parameter": "q", "severity": "high",
        "description": "Quote in q returned ORA-01756", "evidence_note": "step 14",
        "claimed_request": "GET /search?q=x'"}


@pytest.mark.parametrize("reason,expected", [
    ("Reached the time budget for this turn — summarizing", True),
    ("Iteration budget reached; reporting partial coverage", True),
    ("Stopped by operator", False),
    ("Task complete", False),
    ("", False),
])
def test_settlement_applies_only_on_budget_exhaustion(reason, expected):
    assert settlement.settlement_applies(reason) is expected


def test_parse_leads_tolerates_prose_and_caps_count():
    many = [dict(LEAD, title=f"Lead {i}") for i in range(9)]
    text = "Here you go:\n" + json.dumps(many) + "\nThanks"
    assert len(settlement.parse_settlement_leads(text)) == settlement.MAX_SETTLEMENT_LEADS
    assert settlement.parse_settlement_leads("no leads") == []
    assert settlement.parse_settlement_leads("[not json") == []
    assert settlement.parse_settlement_leads('[1, "x", {"title": "ok"}]') == [{"title": "ok"}]


def test_prompt_lists_existing_candidates_and_trace():
    prompt = settlement.build_settlement_prompt(_state())
    assert "Confirmed SQLi" in prompt
    assert "ORA-01756" in prompt
    assert "sql_injection" in prompt


def test_apply_adds_pending_evidence_free_candidate():
    brain, outcomes = settlement.apply_settlement_leads(_state(), [LEAD])
    assert outcomes[0]["accepted"] is True
    by_id = {c["id"]: c for c in brain["candidates"]}
    new = by_id[outcomes[0]["candidate_id"]]
    assert new["status"] == "pending"
    assert new["specialist"] == settlement.SETTLEMENT_SPECIALIST
    assert not new.get("evidence_ids")
    assert settlement.SETTLEMENT_HEADER in new["description"]
    # Existing verdicts and other brain keys are untouched.
    assert by_id["cand-hunter"]["status"] == "confirmed"
    assert brain["notes"] == ["keep me"]


def test_apply_drops_out_of_scope_unknown_class_and_duplicates():
    leads = [
        dict(LEAD, title="Off-scope lead", target="https://evil.example.net/x"),
        dict(LEAD, title="Bogus class lead", vulnerability_class="vibes"),
        dict(LEAD, title="Same root cause", target=f"{TARGET}/a?id=2", parameter="id"),
    ]
    brain, outcomes = settlement.apply_settlement_leads(_state(), leads)
    assert brain is None
    assert [o["accepted"] for o in outcomes] == [False, False, False]
    assert "scope" in outcomes[0]["reason"]
    assert outcomes[2]["duplicate_of"] == "cand-hunter"


def test_apply_without_target_saves_nothing():
    state = _state(capability_map={}, original_objective="")
    assert settlement.apply_settlement_leads(state, [LEAD])[0] is None


def test_report_note_names_only_accepted_leads():
    note = settlement.settlement_report_note([
        {"title": "A", "accepted": True, "vulnerability_class": "xss"},
        {"title": "B", "accepted": False},
    ])
    assert "A (xss)" in note and "B" not in note.split(":", 1)[1]
    assert settlement.settlement_report_note([]) == ""


# --------------------------------------------------------- orchestrator wiring

def _orchestrator(monkeypatch, replies):
    from app.services.agent import action_ledger, orchestrator as orchestrator_module
    from app.services.agent.orchestrator import AgentOrchestrator

    calls = []

    async def fake_call(_llm, messages, **kwargs):
        calls.append((kwargs["kind"], messages[0].content))
        return SimpleNamespace(content=replies[kwargs["kind"]])

    monkeypatch.setattr(orchestrator_module, "_ledger_llm_call", fake_call)
    monkeypatch.setattr(action_ledger, "partial_report", lambda _r, reason: f"Partial: {reason}")
    orch = AgentOrchestrator()
    orch._resolve_llm = lambda *_args: object()
    orch._emit_status = AsyncMock()
    return orch, calls


def test_budget_end_saves_leads_and_tells_report(monkeypatch):
    from app.services.agent import orchestrator as orchestrator_module

    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SETTLEMENT_BACKFILL", True)
    orch, calls = _orchestrator(monkeypatch, {
        "agent_settlement": json.dumps([LEAD]), "agent_report": "final report",
    })
    out = asyncio.run(orch._generate_response_node(_state()))

    assert [kind for kind, _ in calls] == ["agent_settlement", "agent_report"]
    assert "UNVERIFIED LEADS SAVED FOR THE NEXT RUN" in calls[1][1]
    assert "Possible SQLi in search q" in calls[1][1]
    statuses = {c["title"]: c["status"] for c in out["engagement_brain"]["candidates"]}
    assert statuses == {"Confirmed SQLi": "confirmed", "Possible SQLi in search q": "pending"}
    assert out["messages"][0].content == "final report"


def test_settlement_off_by_default_makes_no_extra_call(monkeypatch):
    from app.services.agent import orchestrator as orchestrator_module

    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SETTLEMENT_BACKFILL", False)
    orch, calls = _orchestrator(monkeypatch, {"agent_report": "final report"})
    out = asyncio.run(orch._generate_response_node(_state()))
    assert [kind for kind, _ in calls] == ["agent_report"]
    assert "engagement_brain" not in out


def test_completed_run_does_not_settle(monkeypatch):
    from app.services.agent import orchestrator as orchestrator_module

    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SETTLEMENT_BACKFILL", True)
    orch, calls = _orchestrator(monkeypatch, {"agent_report": "final report"})
    asyncio.run(orch._generate_response_node(_state(completion_reason="Objective met")))
    assert [kind for kind, _ in calls] == ["agent_report"]


def test_settlement_failure_still_reports(monkeypatch):
    from app.services.agent import orchestrator as orchestrator_module

    monkeypatch.setattr(orchestrator_module.settings, "AGENT_SETTLEMENT_BACKFILL", True)
    orch, calls = _orchestrator(monkeypatch, {
        "agent_settlement": "I could not decide", "agent_report": "final report",
    })
    out = asyncio.run(orch._generate_response_node(_state()))
    assert out["messages"][0].content == "final report"
    assert "engagement_brain" not in out
    assert "UNVERIFIED LEADS" not in calls[1][1]
