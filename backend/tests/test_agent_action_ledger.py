"""A timed-out agent still has a tenant-scoped, useful work record."""

import asyncio
import hashlib
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.organization import Organization  # noqa: F401 - resolve ledger FK metadata
from app.models.user import User  # noqa: F401 - resolve ledger FK metadata
from app.models.agent_run_ledger import AgentActionReceipt, AgentHypothesisCoverage, AgentRunLedger
from app.models.agent_conversation import AgentConversation
from app.services.agent import action_ledger


def _isolated_ledger(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    AgentRunLedger.__table__.create(engine)
    AgentActionReceipt.__table__.create(engine)
    AgentHypothesisCoverage.__table__.create(engine)
    AgentConversation.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(action_ledger, "SessionLocal", factory)
    return factory


def test_started_action_survives_interruption_and_is_tenant_scoped(monkeypatch):
    factory = _isolated_ledger(monkeypatch)
    run_id = action_ledger.start_run(
        session_id="session-1", organization_id=12, user_id=7,
        objective="https://demo.example/path?token=secret", mode="agent",
        budget_seconds=3600,
    )
    action_ledger.append_action(
        run_id, "action-1", "started", "execute_httpx",
        target="https://demo.example/private?api_key=secret",
    )
    with factory() as db:
        running = action_ledger.latest_run(
            db, session_id="session-1", organization_id=12, user_id=7,
        )
        assert running["status"] == "running"
        assert running["actions"][0]["status"] == "running"
        assert running["actions"][0]["target"] == "https://demo.example"
        assert "secret" not in str(running)
        assert action_ledger.latest_run(
            db, session_id="session-1", organization_id=13, user_id=7,
        ) is None
    action_ledger.finish_run(run_id, "timeout", "External deadline")
    with factory() as db:
        finished = action_ledger.latest_run(
            db, session_id="session-1", organization_id=12, user_id=7,
        )
    assert finished["status"] == "timeout"
    assert finished["coverage"]["by_status"] == {"interrupted": 1}
    assert "execute_httpx" in action_ledger.partial_report(run_id, "time budget")


def test_completed_and_skipped_actions_have_distinct_receipts(monkeypatch):
    factory = _isolated_ledger(monkeypatch)
    run_id = action_ledger.start_run(
        session_id="session-2", organization_id=12, user_id=7,
        objective="https://demo.example", mode="agent", budget_seconds=60,
    )
    action_ledger.append_action(run_id, "a", "started", "assessment_kickoff")
    action_ledger.append_action(run_id, "a", "completed", "assessment_kickoff")
    action_ledger.append_action(run_id, "b", "skipped", "execute_nuclei",
                                detail="capability_map_required")
    action_ledger.finish_run(run_id, "partial", "Time budget reached")
    with factory() as db:
        report = action_ledger.latest_run(
            db, session_id="session-2", organization_id=12, user_id=7,
        )
    assert report["coverage"]["actions"] == 2
    assert report["coverage"]["by_status"] == {"completed": 1, "skipped": 1}
    assert report["actions"][1]["detail"] == "capability_map_required"


def test_hypothesis_coverage_distinguishes_evidence_and_unattempted(monkeypatch):
    factory = _isolated_ledger(monkeypatch)
    run_id = action_ledger.start_run(
        session_id="coverage", organization_id=12, user_id=7,
        objective="https://demo.example", mode="agent", budget_seconds=60,
    )
    action_ledger.record_hypotheses(run_id, {
        "killed": [{"id": "h1", "title": "Authorization boundary", "status": "killed",
                    "attempts": 1, "evidence_ids": ["http-1"]}],
        "pending": [{"id": "h2", "title": "Stored XSS", "status": "pending",
                     "attempts": 0, "evidence_ids": []}],
        "blocked": [{"id": "h3", "title": "Cross-account read", "status": "blocked",
                     "blocked_reason": "Requires second identity"}],
    })
    action_ledger.finish_run(run_id, "partial", "Time budget reached")
    with factory() as db:
        report = action_ledger.latest_run(
            db, session_id="coverage", organization_id=12, user_id=7,
        )
    assert report["coverage"]["hypotheses_by_state"] == {
        "negative_with_evidence": 1, "skipped_by_budget": 1, "blocked": 1,
    }
    assert next(item for item in report["hypotheses"] if item["id"] == "h1")["evidence_ids"] == ["http-1"]


def test_repeated_empty_fireteam_finishes_without_another_model_call(monkeypatch):
    from app.services.agent.orchestrator import AgentOrchestrator
    from app.services.agent import recon_workers

    async def no_workers(_session_id):
        return []

    monkeypatch.setattr(recon_workers, "list_workers", no_workers)
    state = {
        "user_id": "7", "session_id": "idle-session",
        "current_iteration": 4, "current_phase": "informational",
        "execution_trace": [
            {"tool_name": "fireteam_dispatch", "tool_output": '{"selection_source":"no_ready_hypothesis"}'},
            {"tool_name": "fireteam_dispatch", "tool_output": '{"selection_source":"no_ready_hypothesis"}'},
        ],
    }
    result = asyncio.run(AgentOrchestrator()._think_node(state))
    assert result["task_complete"] is True
    assert "No schedulable hypotheses" in result["completion_reason"]


def test_model_call_is_visible_before_any_tool(monkeypatch):
    from app.services.agent.orchestrator import _ledger_llm_call

    factory = _isolated_ledger(monkeypatch)
    run_id = action_ledger.start_run(
        session_id="planning-only", organization_id=12, user_id=7,
        objective="https://demo.example", mode="agent", budget_seconds=60,
    )

    class FakeModel:
        async def ainvoke(self, _messages):
            return "planned"

    token = action_ledger.active_run_id.set(run_id)
    try:
        assert asyncio.run(_ledger_llm_call(FakeModel(), [], kind="agent_plan")) == "planned"
    finally:
        action_ledger.active_run_id.reset(token)
    with factory() as db:
        report = action_ledger.latest_run(
            db, session_id="planning-only", organization_id=12, user_id=7,
        )
    assert report["coverage"]["model_calls"] == 1
    assert report["coverage"]["test_actions"] == 0


def test_http_evidence_writes_transport_metadata(monkeypatch):
    from app.services.agent.evidence_store import EvidenceStore

    factory = _isolated_ledger(monkeypatch)
    run_id = action_ledger.start_run(
        session_id="http-run", organization_id=12, user_id=7,
        objective="https://demo.example", mode="agent", budget_seconds=60,
    )
    token = action_ledger.active_run_id.set(run_id)
    try:
        artifact_id = EvidenceStore().record(
            "http_exchange",
            {"request": {"method": "GET"}, "response": {"status": 404, "length": 0}},
            target="https://demo.example/private?token=secret",
        )
    finally:
        action_ledger.active_run_id.reset(token)
    with factory() as db:
        report = action_ledger.latest_run(
            db, session_id="http-run", organization_id=12, user_id=7,
        )
    assert report["coverage"]["completed_by_stage"]["http_requests"] == 1
    assert report["actions"][0]["evidence_ids"] == [artifact_id]
    assert "secret" not in str(report)


def test_live_ledger_api_and_outer_timeout_keep_a_partial_record(monkeypatch):
    from app.api.deps import get_current_user
    from app.api.routes import agent as routes
    from app.db.database import get_db

    factory = _isolated_ledger(monkeypatch)
    monkeypatch.setattr(routes, "SessionLocal", factory)
    run_id = action_ledger.start_run(
        session_id="live-session", organization_id=12, user_id=7,
        objective="https://demo.example", mode="agent", budget_seconds=60,
    )
    action_ledger.append_action(run_id, "working", "started", "execute_httpx",
                                target="https://demo.example/private?token=secret")

    app = FastAPI()
    app.include_router(routes.router)

    def test_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=7, organization_id=12)
    client = TestClient(app)
    live = client.get("/agent/conversations/live-session/ledger")
    assert live.status_code == 200
    assert live.json()["actions"][0]["status"] == "running"
    assert live.json()["input_testing"]["checks"] == 0
    assert "secret" not in live.text

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=8, organization_id=12)
    assert client.get("/agent/conversations/live-session/ledger").status_code == 404

    timeout_result = routes._timeout_result("live-session", 12, 7)
    assert "execute_httpx" in timeout_result.answer
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=7, organization_id=12)
    ended = client.get("/agent/conversations/live-session/ledger")
    assert ended.status_code == 200
    assert ended.json()["status"] == "timeout"
    assert ended.json()["actions"][0]["status"] == "interrupted"


def test_active_run_cannot_be_deleted_from_another_api_request(monkeypatch, tmp_path):
    from app.api.deps import get_current_user
    from app.api.routes import agent as routes
    from app.db.database import get_db

    factory = _isolated_ledger(monkeypatch)
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    from app.services.agent.evidence_store import EvidenceStore
    from app.services.agent.tools import current_organization_id, current_session_id

    org_token = current_organization_id.set(12)
    session_token = current_session_id.set("active-session")
    try:
        namespace = hashlib.sha256(b"12:active-session").hexdigest()[:32]
        store = EvidenceStore(namespace=namespace)
        artifact_id = store.record("tool_output", {"status": "checked"})
        artifact_path = tmp_path / store.namespace / f"{artifact_id}.json"
        assert artifact_path.exists()
    finally:
        current_session_id.reset(session_token)
        current_organization_id.reset(org_token)
    with factory() as db:
        db.add(AgentConversation(session_id="active-session", user_id=7,
                                 organization_id=12, messages=[]))
        db.commit()
    run_id = action_ledger.start_run(
        session_id="active-session", organization_id=12, user_id=7,
        objective="https://demo.example", mode="agent", budget_seconds=60,
    )
    app = FastAPI()
    app.include_router(routes.router)

    def test_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=7, organization_id=12)
    client = TestClient(app)
    assert client.delete("/agent/conversations/active-session").status_code == 409
    action_ledger.finish_run(run_id, "completed")
    assert client.delete("/agent/conversations/active-session").status_code == 200
    assert not artifact_path.exists()
