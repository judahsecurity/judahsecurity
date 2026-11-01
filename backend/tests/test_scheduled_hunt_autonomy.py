"""Scheduled hunts continue only while saved, scoped work makes progress."""

from types import SimpleNamespace
from datetime import datetime, timezone

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
        price_limit_usd=5.0, run_key="schedule:2026-10-28",
        autonomous_followup=True, max_turns=3,
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
        organization_id=7, user_id="11", targets=[TARGET],
        autonomous_followup=True, max_turns=4,
    )
    assert len(calls) == 2
    assert result["results"][0]["stop_reason"] == "no new hypothesis or coverage progress"


@pytest.mark.asyncio
async def test_scheduled_hunt_needs_opt_in_for_followup(monkeypatch):
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
    assert len(calls) == 1
    assert calls[0]["max_iterations"] is None
    assert result["results"][0]["complete"] is False


@pytest.mark.asyncio
async def test_schedule_worker_uses_creator_id_and_explicit_followup_opt_in(monkeypatch):
    import app.services.agent.durable_hunt as hunt_module
    from app.models.user import UserRole
    from app.workers.schedule_worker import ScheduleWorker

    calls = []
    creator = SimpleNamespace(id=11, is_active=True, role=UserRole.ANALYST,
                              is_superuser=False, organization_id=7)

    class FakeDB:
        def query(self, _model):
            return self

        def filter(self, _condition):
            return self

        def first(self):
            return creator

        def commit(self):
            pass

    def fake_enqueue(db, schedule, targets, *, user_id):
        calls.append({"schedule": schedule, "targets": targets, "user_id": user_id})
        return 1

    monkeypatch.setattr(hunt_module, "enqueue_scheduled_hunts", fake_enqueue)
    schedule = SimpleNamespace(
        id=9, organization_id=7, created_by="analyst", name="Autonomy pilot",
        config={"autonomous_followup": True},
        next_run_at=datetime(2026, 10, 30, tzinfo=timezone.utc),
        last_error=None, consecutive_failures=0, run_count=0,
        notify_on_completion=False, notify_on_findings=False,
        calculate_next_run=lambda: datetime(2026, 10, 31, tzinfo=timezone.utc),
    )
    worker = object.__new__(ScheduleWorker)
    await worker._run_tester_process_schedule(FakeDB(), schedule, [TARGET])
    assert calls[0]["user_id"] == 11
    assert calls[0]["targets"] == [TARGET]
    assert schedule.run_count == 1


@pytest.mark.asyncio
async def test_schedule_worker_stops_when_creator_loses_org_access(monkeypatch):
    import app.services.agent.scheduled_hunt as hunt_module
    from app.models.user import UserRole
    from app.workers.schedule_worker import ScheduleWorker

    class FakeDB:
        def query(self, _model):
            return self

        def filter(self, _condition):
            return self

        def first(self):
            return SimpleNamespace(id=11, is_active=True, role=UserRole.ANALYST,
                                   is_superuser=False, organization_id=8)

        def commit(self):
            pass

    async def forbidden_run(**_kwargs):
        pytest.fail("The agent must not run after organization access is revoked")

    monkeypatch.setattr(hunt_module, "run_tester_process_targets", forbidden_run)
    schedule = SimpleNamespace(
        id=9, organization_id=7, created_by="analyst", name="Autonomy pilot",
        config={"autonomous_followup": True},
        next_run_at=datetime(2026, 10, 30, tzinfo=timezone.utc),
        last_error=None, consecutive_failures=0,
        calculate_next_run=lambda: datetime(2026, 10, 31, tzinfo=timezone.utc),
    )
    worker = object.__new__(ScheduleWorker)
    await worker._run_tester_process_schedule(FakeDB(), schedule, [TARGET])
    assert "no longer has analyst access" in schedule.last_error
    assert schedule.consecutive_failures == 1
