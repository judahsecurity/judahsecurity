"""Scheduled hunts continue only while saved, scoped work makes progress."""

from types import SimpleNamespace

import pytest

from app.services.agent.scheduled_hunt import continuation_plan, run_tester_process_targets


TARGET = "https://app.test"


def _hypothesis(identifier: str) -> dict:
    return {
        "id": identifier, "title": f"Check {identifier}",
        "assumption": "Observed access boundary", "test": "Compare test identities",
        "pass_criteria": "Peer access", "kill_criteria": "Peer denied",
        "specialist": "api_authz", "target": TARGET,
    }


def _snapshot(identifier: str) -> dict:
    return {
        "capability_map": {"target": TARGET},
        "engagement_brain": {"hypotheses": [_hypothesis(identifier)]},
    }


def test_continuation_plan_needs_partial_scoped_work():
    plan = continuation_plan(_snapshot("h1"), {"status": "partial"}, TARGET)
    assert plan and "ready hypotheses" in plan[1]
    assert continuation_plan(_snapshot("h1"), {"status": "completed"}, TARGET) is None
    assert continuation_plan(_snapshot("h1"), {"status": "partial"}, "https://other.test") is None
    assert continuation_plan({**_snapshot("h1"), "reauthentication_required": True},
                             {"status": "partial"}, TARGET) is None
    map_only = {"capability_map": {"target": TARGET, "pages_visited": [TARGET]}}
    assert "Sync the engagement brain" in continuation_plan(
        map_only, {"status": "partial"}, TARGET,
    )[1]


@pytest.mark.asyncio
async def test_scheduled_hunt_resumes_partial_run_with_remaining_spend(monkeypatch):
    import app.services.agent.action_ledger as ledger
    import app.services.agent.orchestrator as orchestrator_module
    import app.services.agent.run_snapshot as snapshot_module
    import app.db.database as database_module

    calls = []

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                task_complete=True, cost_usd=1.0, error=None,
                answer=f"turn {len(calls)}",
                awaiting_question=False, awaiting_approval=False,
            )

    class FakeDB:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator_module, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(database_module, "SessionLocal", FakeDB)
    monkeypatch.setattr(ledger, "latest_run", lambda db, **kwargs: {
        "status": "partial" if len(calls) == 1 else "completed",
    })
    monkeypatch.setattr(snapshot_module, "load_run_snapshot", lambda *args: _snapshot("h1"))
    result = await run_tester_process_targets(
        organization_id=7, user_id="11", targets=[TARGET],
        price_limit_usd=5.0, run_key="schedule:2026-10-28", max_turns=3,
    )
    row = result["results"][0]
    assert row["complete"] is True
    assert row["turns"] == 2
    assert row["cost_usd"] == 2.0
    assert calls[0]["session_id"] == calls[1]["session_id"] == row["session_id"]
    assert calls[1]["price_limit_usd"] == 4.0
    assert "ready hypotheses" in calls[1]["question"]


@pytest.mark.asyncio
async def test_scheduled_hunt_stops_when_hypotheses_do_not_change(monkeypatch):
    import app.services.agent.action_ledger as ledger
    import app.services.agent.orchestrator as orchestrator_module
    import app.services.agent.run_snapshot as snapshot_module
    import app.db.database as database_module

    calls = []

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(task_complete=True, cost_usd=0.5, error=None,
                                   answer="partial", awaiting_question=False,
                                   awaiting_approval=False)

    class FakeDB:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator_module, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(database_module, "SessionLocal", FakeDB)
    monkeypatch.setattr(ledger, "latest_run", lambda db, **kwargs: {"status": "partial"})
    monkeypatch.setattr(snapshot_module, "load_run_snapshot", lambda *args: _snapshot("h1"))
    result = await run_tester_process_targets(
        organization_id=7, user_id="11", targets=[TARGET], max_turns=4,
    )
    assert len(calls) == 2
    assert result["results"][0]["stop_reason"] == "no new hypothesis or coverage progress"
