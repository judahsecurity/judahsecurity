"""Durable autonomy turns persist, requeue once, and quarantine unknown work."""

from datetime import datetime, timedelta
from types import SimpleNamespace
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.agent_autonomy_work import AgentAutonomyWork, AgentRunSnapshot
from app.models.agent_run_ledger import AgentActionReceipt, AgentRunLedger
from app.services.agent import durable_hunt

TARGET = "https://app.example.test"


@pytest.fixture
def sessions(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    AgentAutonomyWork.__table__.create(engine)
    AgentRunSnapshot.__table__.create(engine)
    AgentRunLedger.__table__.create(engine)
    AgentActionReceipt.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(durable_hunt, "SessionLocal", factory)
    yield factory
    engine.dispose()


def _work(**overrides):
    values = {
        "id": "work-1", "schedule_id": 9, "organization_id": 7, "user_id": 11,
        "target": TARGET, "session_id": "sched-7-work-1", "status": "queued",
        "prompt": "Assess target", "revisions": [], "turns": 0, "max_turns": 3,
        "price_limit_usd": 5.0, "spent_usd": 0.0, "max_total_seconds": 3600,
        "limits": {}, "lease_owner": "", "stop_reason": "", "answer": "",
        "notification_sent": False,
    }
    values.update(overrides)
    return AgentAutonomyWork(**values)


def test_enqueue_idempotent_and_claimed_turn_is_persisted(sessions):
    schedule = SimpleNamespace(
        id=9, organization_id=7, next_run_at=datetime(2026, 10, 30),
        config={"autonomous_followup": True, "max_specialist_tool_calls": 5},
    )
    with sessions() as db:
        assert durable_hunt.enqueue_scheduled_hunts(db, schedule, [TARGET], user_id=11) == 1
        db.commit()
        assert durable_hunt.enqueue_scheduled_hunts(db, schedule, [TARGET], user_id=11) == 0
        db.commit()
        work_id = durable_hunt.claim_next(db, owner="worker-1")
        assert work_id
        assert durable_hunt.claim_next(db, owner="worker-2") is None
    with sessions() as db:
        row = db.get(AgentAutonomyWork, work_id)
        assert row.status == "running"
        assert row.limits["max_specialist_tool_calls"] == 5
        assert row.session_id.startswith("sched-7-")


def test_interrupted_turn_is_quarantined_not_replayed(sessions):
    with sessions() as db:
        db.add(_work(status="running", lease_owner="dead", lease_until=datetime.utcnow() - timedelta(seconds=1)))
        db.commit()
        assert durable_hunt.recover_expired(db) == 1
        assert durable_hunt.claim_next(db, owner="new") is None
        row = db.get(AgentAutonomyWork, "work-1")
        assert row.status == "blocked"
        assert "without a fresh costed database snapshot" in row.stop_reason


@pytest.mark.parametrize("run_status", ["running", "completed"])
def test_expired_read_only_turn_resumes_once_from_costed_snapshot(sessions, run_status):
    started = datetime.utcnow() - timedelta(seconds=10)
    with sessions() as db:
        db.add(_work(
            status="running", lease_owner="dead", turn_started_at=started,
            created_at=started - timedelta(seconds=10),
            lease_until=datetime.utcnow() - timedelta(seconds=1),
        ))
        db.add(AgentRunLedger(
            id="run-1", session_id="sched-7-work-1", organization_id=7, user_id=11,
            objective=TARGET, mode="agent", status=run_status,
            started_at=started + timedelta(seconds=1),
        ))
        db.add(AgentActionReceipt(
            run_id="run-1", action_id="action-1", event="started",
            tool_name="execute_dnsx", target=TARGET,
            created_at=started + timedelta(seconds=2),
        ))
        db.add(AgentActionReceipt(
            run_id="run-1", action_id="action-1", event="completed",
            tool_name="execute_dnsx", target=TARGET,
            created_at=started + timedelta(seconds=3),
        ))
        db.add(AgentRunSnapshot(
            session_id="sched-7-work-1", organization_id=7,
            payload={
                "schema_version": 3, "saved_at": time.time(),
                "reported_cost_usd": 0.2,
                "capability_map": {"target": TARGET},
                "engagement_brain": {"hypotheses": [{
                    "id": "h1", "title": "Check API", "assumption": "A",
                    "test": "T", "pass_criteria": "P", "kill_criteria": "K",
                    "specialist": "api_authz", "target": TARGET,
                }]},
            },
        ))
        db.commit()
        assert durable_hunt.recover_expired(db) == 1
        row = db.get(AgentAutonomyWork, "work-1")
        assert row.status == "queued" and row.turns == 1 and row.spent_usd == 0.2
        assert durable_hunt.recover_expired(db) == 0
        assert db.query(AgentAutonomyWork).count() == 1
        assert durable_hunt.claim_next(db, owner="next") == "work-1"


def test_expired_actionful_turn_stays_blocked(sessions):
    started = datetime.utcnow() - timedelta(seconds=10)
    with sessions() as db:
        db.add(_work(
            status="running", lease_owner="dead", turn_started_at=started,
            lease_until=datetime.utcnow() - timedelta(seconds=1),
        ))
        db.add(AgentRunLedger(
            id="run-1", session_id="sched-7-work-1", organization_id=7, user_id=11,
            objective=TARGET, mode="agent", status="running",
            started_at=started + timedelta(seconds=1),
        ))
        db.add(AgentActionReceipt(
            run_id="run-1", action_id="action-1", event="completed",
            tool_name="mutate_captured_request", target=TARGET,
            created_at=started + timedelta(seconds=3),
        ))
        db.add(AgentRunSnapshot(
            session_id="sched-7-work-1", organization_id=7,
            payload={"schema_version": 3, "saved_at": time.time(),
                     "reported_cost_usd": 0.2, "capability_map": {"target": TARGET}},
        ))
        db.commit()
        assert durable_hunt.recover_expired(db) == 1
        assert db.get(AgentAutonomyWork, "work-1").status == "blocked"
        assert durable_hunt.claim_next(db, owner="next") is None


def test_expired_turn_with_unresolved_action_is_blocked_even_with_snapshot(sessions):
    started = datetime.utcnow() - timedelta(seconds=10)
    with sessions() as db:
        db.add(_work(
            status="running", lease_owner="dead", turn_started_at=started,
            lease_until=datetime.utcnow() - timedelta(seconds=1),
        ))
        db.add(AgentRunLedger(
            id="run-1", session_id="sched-7-work-1", organization_id=7, user_id=11,
            objective=TARGET, mode="agent", status="running",
            started_at=started + timedelta(seconds=1),
        ))
        db.add(AgentActionReceipt(
            run_id="run-1", action_id="action-1", event="started",
            tool_name="execute_dnsx", target=TARGET,
            created_at=started + timedelta(seconds=2),
        ))
        db.add(AgentRunSnapshot(
            session_id="sched-7-work-1", organization_id=7,
            payload={"schema_version": 3, "saved_at": time.time(),
                     "reported_cost_usd": 0.2, "capability_map": {"target": TARGET}},
        ))
        db.commit()
        assert durable_hunt.recover_expired(db) == 1
        row = db.get(AgentAutonomyWork, "work-1")
        assert row.status == "blocked" and "in-flight action" in row.stop_reason
        assert durable_hunt.claim_next(db, owner="next") is None


@pytest.mark.asyncio
async def test_completed_turn_requeues_revision_and_resumes_after_restart(sessions, monkeypatch):
    from app.services.agent import action_ledger, orchestrator, run_snapshot

    with sessions() as db:
        db.add(_work())
        db.commit()
        assert durable_hunt.claim_next(db, owner="worker-1") == "work-1"

    calls = []

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            calls.append(kwargs)
            with sessions() as db:
                db.merge(AgentRunSnapshot(
                    session_id=kwargs["session_id"], organization_id=7,
                    payload={"saved_at": time.time(), "engagement_brain": {"hypotheses": []}},
                ))
                db.commit()
            return SimpleNamespace(
                error=None, awaiting_question=False, awaiting_approval=False,
                task_complete=True, cost_usd=0.5, answer="turn complete",
            )

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(durable_hunt, "_authorized", lambda db, row: (True, ""))
    monkeypatch.setattr(action_ledger, "latest_run", lambda db, **kwargs: {
        "status": "partial" if len(calls) == 1 else "completed",
    })
    monkeypatch.setattr(run_snapshot, "load_run_snapshot", lambda org, sid: {
        "capability_map": {"target": TARGET},
        "engagement_brain": {"hypotheses": [{
            "id": "h1", "title": "Check API", "assumption": "Observed boundary",
            "test": "Compare", "pass_criteria": "Diff", "kill_criteria": "Same",
            "specialist": "api_authz", "target": TARGET,
        }]},
    })
    first = await durable_hunt.process_claimed("work-1", "worker-1")
    assert first["status"] == "queued"
    with sessions() as db:
        row = db.get(AgentAutonomyWork, "work-1")
        assert row.turns == 1 and row.spent_usd == 0.5
        assert len(row.revisions) == 1
        assert durable_hunt.claim_next(db, owner="worker-2") == "work-1"
    second = await durable_hunt.process_claimed("work-1", "worker-2")
    assert second["status"] == "completed"
    assert calls[1]["price_limit_usd"] == 4.5
    assert calls[0]["session_id"] == calls[1]["session_id"]


@pytest.mark.asyncio
async def test_completed_turn_without_durable_snapshot_is_blocked(sessions, monkeypatch):
    from app.services.agent import action_ledger, orchestrator

    with sessions() as db:
        db.add(_work())
        db.commit()
        assert durable_hunt.claim_next(db, owner="worker-1") == "work-1"

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            return SimpleNamespace(
                error=None, awaiting_question=False, awaiting_approval=False,
                task_complete=False, cost_usd=0.2, answer="turn complete",
            )

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(durable_hunt, "_authorized", lambda db, row: (True, ""))
    monkeypatch.setattr(action_ledger, "latest_run", lambda db, **kwargs: None)
    result = await durable_hunt.process_claimed("work-1", "worker-1")
    assert result["status"] == "blocked"
    assert "durable database snapshot" in result["stop_reason"]


def test_scheduled_snapshot_loads_from_database_after_local_file_is_gone(sessions, monkeypatch, tmp_path):
    from app.db import database as db_module
    from app.services.agent import run_snapshot

    monkeypatch.setattr(db_module, "SessionLocal", sessions)
    monkeypatch.setattr(run_snapshot, "_DIR", tmp_path)
    run_snapshot.save_run_snapshot(7, "sched-7-work-1", {
        "capability_map": {"target": TARGET, "pages_visited": [TARGET]},
        "engagement_brain": {"hypotheses": []},
    })
    for path in tmp_path.iterdir():
        path.unlink()
    loaded = run_snapshot.load_run_snapshot(7, "sched-7-work-1")
    assert loaded["capability_map"]["target"] == TARGET
