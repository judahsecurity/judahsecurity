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
@pytest.mark.parametrize("tool_name", ["execute_dnsx", "execute_subfinder", "recon_worker:subdomain_enum"])
def test_expired_read_only_turn_resumes_once_from_costed_snapshot(sessions, run_status, tool_name):
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
            tool_name=tool_name, target=TARGET,
            created_at=started + timedelta(seconds=2),
        ))
        db.add(AgentActionReceipt(
            run_id="run-1", action_id="action-1", event="completed",
            tool_name=tool_name, target=TARGET,
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


# --- Budget-driven continuation and the independent verification turn ------

from app.services.agent.autonomy_limits import (
    limits_from_config, turn_budget_from_config,
)
from app.services.agent.scheduled_hunt import WRAPUP_REVISION


def _step(**overrides):
    values = {
        "plan": ("rev-a", "Continue"), "pending": [], "agent_complete": False,
        "prior_revisions": [], "turns_after": 1, "max_turns": 12,
        "remaining_usd": 7.0, "price_limit_usd": 8.0, "remaining_seconds": 3000,
        "max_stalled_replans": 2, "target": TARGET,
    }
    values.update(overrides)
    return durable_hunt.next_step(**values)


def test_turn_budget_defaults_and_caps():
    assert turn_budget_from_config({}) == {
        "max_turns": 12, "max_total_seconds": 3600, "max_stalled_replans": 2,
    }
    capped = turn_budget_from_config({
        "max_turns": 500, "max_total_seconds": 10 ** 6, "max_stalled_replans": 99,
    })
    assert capped == {"max_turns": 24, "max_total_seconds": 14400, "max_stalled_replans": 4}
    assert turn_budget_from_config({"max_stalled_replans": 0})["max_stalled_replans"] == 0
    # The stored limits dict round-trips an explicit zero.
    stored = limits_from_config({"max_stalled_replans": 0}, target=TARGET).__dict__
    assert limits_from_config(stored, target=TARGET).max_stalled_replans == 0


def test_new_revision_continues():
    assert _step() == {"status": "queued", "reason": "", "revision": "rev-a", "prompt": "Continue"}


def test_stalled_turn_replans_then_stops():
    first = _step(prior_revisions=["rev-a"])
    assert first["status"] == "queued" and "Re-plan" in first["prompt"]
    second = _step(prior_revisions=["rev-a", "rev-a"])
    assert second["status"] == "queued"
    stopped = _step(prior_revisions=["rev-a", "rev-a", "rev-a"])
    assert stopped["status"] == "blocked"
    assert "after 2 re-plan" in stopped["reason"]
    assert _step(prior_revisions=["rev-a"], max_stalled_replans=0)["status"] == "blocked"


def test_pending_candidates_get_a_verification_turn_before_stopping():
    stalled = _step(prior_revisions=["rev-a"] * 3, pending=["cand-1"])
    assert stalled["status"] == "queued" and stalled["revision"] == WRAPUP_REVISION
    assert "independent_verify" in stalled["prompt"] and "cand-1" in stalled["prompt"]
    # Spend inside the reserve stops exploration but still verifies.
    low = _step(remaining_usd=1.0, pending=["cand-1"])
    assert low["revision"] == WRAPUP_REVISION
    # The second-to-last turn is the last exploration turn.
    last = _step(turns_after=11, pending=["cand-1"])
    assert last["revision"] == WRAPUP_REVISION


def test_agent_completion_with_pending_candidate_is_not_completed():
    result = _step(plan=None, agent_complete=True, pending=["cand-1"])
    assert result["status"] == "queued" and result["revision"] == WRAPUP_REVISION
    assert _step(plan=None, agent_complete=True)["status"] == "completed"


def test_candidate_still_pending_after_verification_turn_is_reported():
    result = _step(
        plan=None, agent_complete=True, pending=["cand-1", "cand-2"],
        prior_revisions=["rev-a", WRAPUP_REVISION],
    )
    assert result["status"] == "blocked"
    assert "2 candidate(s) still awaiting independent verification: cand-1, cand-2" in result["reason"]


def test_no_verification_turn_without_budget():
    for overrides in ({"remaining_usd": 0.0}, {"turns_after": 12}, {"remaining_seconds": 60}):
        result = _step(pending=["cand-1"], **overrides)
        assert result["status"] == "blocked"
        assert "awaiting independent verification" in result["reason"]


def test_verification_turn_runs_once():
    result = _step(prior_revisions=["rev-a", WRAPUP_REVISION])
    assert result["status"] == "blocked"
    assert "deferred to the next run" in result["reason"]


def test_enqueue_uses_budget_defaults(sessions):
    schedule = SimpleNamespace(
        id=9, organization_id=7, next_run_at=datetime(2026, 10, 30),
        config={"autonomous_followup": True},
    )
    with sessions() as db:
        durable_hunt.enqueue_scheduled_hunts(db, schedule, [TARGET], user_id=11)
        db.commit()
        row = db.query(AgentAutonomyWork).one()
        assert row.max_turns == 12 and row.max_total_seconds == 3600
        assert row.limits["max_stalled_replans"] == 2


@pytest.mark.asyncio
async def test_pending_candidate_runs_verification_turn_end_to_end(sessions, monkeypatch):
    from app.services.agent import action_ledger, orchestrator, run_snapshot

    with sessions() as db:
        db.add(_work(max_turns=12, price_limit_usd=8.0))
        db.commit()
        assert durable_hunt.claim_next(db, owner="worker-1") == "work-1"

    prompts = []
    candidate = {"id": "cand-1", "status": "pending", "revision": 1}

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            prompts.append(kwargs["question"])
            if len(prompts) == 2:
                candidate["status"] = "confirmed"
            with sessions() as db:
                db.merge(AgentRunSnapshot(
                    session_id=kwargs["session_id"], organization_id=7,
                    payload={"saved_at": time.time(), "engagement_brain": {}},
                ))
                db.commit()
            return SimpleNamespace(
                error=None, awaiting_question=False, awaiting_approval=False,
                task_complete=True, cost_usd=0.5, answer="done",
            )

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(durable_hunt, "_authorized", lambda db, row: (True, ""))
    monkeypatch.setattr(action_ledger, "latest_run", lambda db, **kwargs: {"status": "completed"})
    monkeypatch.setattr(run_snapshot, "load_run_snapshot", lambda org, sid: {
        "capability_map": {"target": TARGET},
        "engagement_brain": {"candidates": [dict(candidate)]},
    })
    first = await durable_hunt.process_claimed("work-1", "worker-1")
    assert first["status"] == "queued"
    with sessions() as db:
        assert db.get(AgentAutonomyWork, "work-1").revisions == [WRAPUP_REVISION]
        assert durable_hunt.claim_next(db, owner="worker-2") == "work-1"
    second = await durable_hunt.process_claimed("work-1", "worker-2")
    assert second["status"] == "completed"
    assert "independent_verify" in prompts[1] and "cand-1" in prompts[1]


# --- Request-boundary budget across turns ----------------------------------

def test_request_budget_stops_exploration_but_still_verifies():
    stopped = _step(requests_exhausted=True)
    assert stopped["status"] == "blocked"
    assert stopped["reason"] == "Assessment request budget reached"
    verify = _step(requests_exhausted=True, pending=["cand-1"])
    assert verify["revision"] == WRAPUP_REVISION


def _request_turn(sessions, monkeypatch, *, requests_per_turn):
    import httpx
    from app.services.agent import action_ledger, orchestrator, run_snapshot

    seen = {}

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            transport = httpx.MockTransport(lambda r: httpx.Response(200))
            async with httpx.AsyncClient(transport=transport) as client:
                for _ in range(requests_per_turn):
                    try:
                        await client.get(f"{TARGET}/probe")
                    except httpx.TransportError as exc:
                        seen["error"] = type(exc).__name__
                        break
                await client.get("https://api.provider.test/v1/messages")
            with sessions() as db:
                db.merge(AgentRunSnapshot(
                    session_id=kwargs["session_id"], organization_id=7,
                    payload={"saved_at": time.time(), "engagement_brain": {}},
                ))
                db.commit()
            return SimpleNamespace(
                error=None, awaiting_question=False, awaiting_approval=False,
                task_complete=False, cost_usd=0.1, answer="turn",
            )

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(durable_hunt, "_authorized", lambda db, row: (True, ""))
    monkeypatch.setattr(action_ledger, "latest_run", lambda db, **kwargs: {"status": "partial"})
    monkeypatch.setattr(run_snapshot, "load_run_snapshot", lambda org, sid: {
        "capability_map": {"target": TARGET},
        "engagement_brain": {"hypotheses": [{
            "id": "h1", "title": "Check API", "assumption": "A", "test": "T",
            "pass_criteria": "P", "kill_criteria": "K", "specialist": "api_authz",
            "target": TARGET,
        }]},
    })
    return seen


@pytest.mark.asyncio
async def test_turn_requests_are_counted_at_the_request_boundary(sessions, monkeypatch):
    with sessions() as db:
        db.add(_work(max_turns=12, price_limit_usd=8.0, limits={"request_rate_per_second": 20}))
        db.commit()
        durable_hunt.claim_next(db, owner="w1")
    _request_turn(sessions, monkeypatch, requests_per_turn=3)
    result = await durable_hunt.process_claimed("work-1", "w1")
    assert result["status"] == "queued"
    assert result["requests_sent"] == 3          # the provider call is not counted
    with sessions() as db:
        assert db.get(AgentAutonomyWork, "work-1").limits["requests_sent"] == 3


@pytest.mark.asyncio
async def test_exploration_turn_leaves_the_verification_reserve(sessions, monkeypatch):
    # 100 requests, 15 held back: exploration may use 85 in total.
    with sessions() as db:
        db.add(_work(max_turns=12, price_limit_usd=8.0, limits={
            "request_rate_per_second": 20, "max_run_requests": 100, "requests_sent": 80,
        }))
        db.commit()
        durable_hunt.claim_next(db, owner="w1")
    seen = _request_turn(sessions, monkeypatch, requests_per_turn=10)
    result = await durable_hunt.process_claimed("work-1", "w1")
    assert seen["error"] == "RequestBudgetExceeded"
    assert result["requests_sent"] == 85
    assert result["status"] == "blocked"
    assert result["stop_reason"] == "Assessment request budget reached"


@pytest.mark.asyncio
async def test_turn_with_no_requests_left_does_not_start(sessions, monkeypatch):
    with sessions() as db:
        db.add(_work(limits={"max_run_requests": 100, "requests_sent": 90}))
        db.commit()
        durable_hunt.claim_next(db, owner="w1")
    _request_turn(sessions, monkeypatch, requests_per_turn=1)
    result = await durable_hunt.process_claimed("work-1", "w1")
    assert result["status"] == "blocked"
    assert result["stop_reason"] == "Assessment request budget reached"
    assert result["turns"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("limits,expected", [
    ({}, None),
    ({"delegate_replay_approval": True}, None),  # needs state_change too
    ({"delegate_replay_approval": True, "allowed_actions": ["read", "probe", "state_change"]},
     {"delegated_replay_approval": {"enabled": True}}),
])
async def test_schedule_delegation_reaches_the_agent_policy(sessions, monkeypatch, limits, expected):
    from app.services.agent import action_ledger, orchestrator, run_snapshot

    with sessions() as db:
        db.add(_work(limits=limits))
        db.commit()
        durable_hunt.claim_next(db, owner="w1")
    seen = {}

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            seen["policy"] = kwargs.get("assessment_policy")
            return SimpleNamespace(
                error=None, awaiting_question=False, awaiting_approval=False,
                task_complete=False, cost_usd=0.1, answer="",
            )

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(durable_hunt, "_authorized", lambda db, row: (True, ""))
    monkeypatch.setattr(action_ledger, "latest_run", lambda db, **kwargs: None)
    await durable_hunt.process_claimed("work-1", "w1")
    assert seen["policy"] == expected


# --- Operator requests park only themselves ---------------------------------

def _operator_turn(sessions, monkeypatch, responses, snapshot_brain):
    from app.services.agent import action_ledger, orchestrator, run_snapshot

    prompts = []

    class FakeOrchestrator:
        async def invoke(self, **kwargs):
            prompts.append(kwargs["question"])
            with sessions() as db:
                db.merge(AgentRunSnapshot(
                    session_id=kwargs["session_id"], organization_id=7,
                    payload={"saved_at": time.time(), "engagement_brain": {}},
                ))
                db.commit()
            return responses[min(len(prompts), len(responses)) - 1]

    async def get_orchestrator():
        return FakeOrchestrator()

    monkeypatch.setattr(orchestrator, "get_agent_orchestrator", get_orchestrator)
    monkeypatch.setattr(durable_hunt, "_authorized", lambda db, row: (True, ""))
    monkeypatch.setattr(action_ledger, "latest_run", lambda db, **kwargs: {"status": "paused"})
    monkeypatch.setattr(run_snapshot, "load_run_snapshot", lambda org, sid: {
        "capability_map": {"target": TARGET}, "engagement_brain": snapshot_brain(),
    })
    return prompts


def _awaiting(**fields):
    values = {"error": None, "task_complete": False, "cost_usd": 0.1, "answer": "paused",
              "awaiting_question": False, "awaiting_approval": False}
    values.update(fields)
    return SimpleNamespace(**values)


HYPOTHESES = {"hypotheses": [{
    "id": "h1", "title": "Check API", "assumption": "A", "test": "T",
    "pass_criteria": "P", "kill_criteria": "K", "specialist": "api_authz", "target": TARGET,
}]}


@pytest.mark.asyncio
async def test_approval_request_parks_and_the_run_continues(sessions, monkeypatch):
    with sessions() as db:
        db.add(_work(max_turns=12, price_limit_usd=8.0))
        db.commit()
        durable_hunt.claim_next(db, owner="w1")
    approval = _awaiting(awaiting_approval=True, approval_request={
        "from_phase": "informational", "to_phase": "exploitation", "reason": "Confirm SQLi",
    })
    revisions = iter(range(100))
    _operator_turn(sessions, monkeypatch, [approval], lambda: {
        "hypotheses": [{**HYPOTHESES["hypotheses"][0], "id": f"h{next(revisions)}"}],
    })
    result = await durable_hunt.process_claimed("work-1", "w1")
    assert result["status"] == "queued"
    with sessions() as db:
        row = db.get(AgentAutonomyWork, "work-1")
        assert [item["kind"] for item in row.limits["parked"]] == ["approval"]
        assert "exploitation" in row.limits["parked"][0]["summary"]
        assert "Operator decisions are pending and parked" in row.prompt
        assert "Do not request these again" in row.prompt
        durable_hunt.claim_next(db, owner="w2")
    # The same request again is not parked twice.
    await durable_hunt.process_claimed("work-1", "w2")
    with sessions() as db:
        assert len(db.get(AgentAutonomyWork, "work-1").limits["parked"]) == 1


@pytest.mark.asyncio
async def test_run_with_only_parked_work_left_reports_what_waits(sessions, monkeypatch):
    with sessions() as db:
        db.add(_work(max_turns=12, price_limit_usd=8.0))
        db.commit()
        durable_hunt.claim_next(db, owner="w1")
    question = _awaiting(awaiting_question=True,
                         question_request={"question": "Which tenant may I test?"})
    _operator_turn(sessions, monkeypatch, [question], lambda: {
        "hypotheses": [{**HYPOTHESES["hypotheses"][0], "status": "killed"}],
    })
    result = await durable_hunt.process_claimed("work-1", "w1")
    assert result["status"] == "blocked"
    assert "Waiting for operator: question: Which tenant may I test?" in result["stop_reason"]


@pytest.mark.asyncio
async def test_agent_error_still_stops_the_run(sessions, monkeypatch):
    with sessions() as db:
        db.add(_work())
        db.commit()
        durable_hunt.claim_next(db, owner="w1")
    failed = SimpleNamespace(error="model unavailable", task_complete=False, cost_usd=0.0,
                             answer="", awaiting_question=False, awaiting_approval=False)
    _operator_turn(sessions, monkeypatch, [failed], lambda: HYPOTHESES)
    result = await durable_hunt.process_claimed("work-1", "w1")
    assert result["status"] == "blocked" and result["stop_reason"] == "Agent error: model unavailable"


def test_parked_items_are_deduplicated_and_capped():
    item = {"kind": "question", "key": "q:1", "summary": "question: a"}
    assert durable_hunt.merge_parked([item], dict(item)) == [item]
    many = [{"kind": "question", "key": f"q:{i}", "summary": str(i)} for i in range(15)]
    assert len(durable_hunt.merge_parked(many, None)) == durable_hunt.MAX_PARKED
    assert durable_hunt.parked_item(SimpleNamespace(awaiting_approval=False,
                                                    awaiting_question=False)) is None
