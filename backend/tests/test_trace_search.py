"""Specialists can find prior run evidence without copying tool output into logs."""

import asyncio
import json

from app.models.agent_run_ledger import (
    AgentActionReceipt,
    AgentHypothesisCoverage,
    AgentRunLedger,
)
from app.services.agent import tools as agent_tools
from app.services.agent.action_ledger import active_run_id
from app.services.agent.evidence_store import EvidenceStore
from app.services.agent.trace_search import search_assessment_traces
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


def _db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    AgentRunLedger.__table__.create(engine)
    AgentActionReceipt.__table__.create(engine)
    AgentHypothesisCoverage.__table__.create(engine)
    return sessionmaker(bind=engine)


def _run(db, run_id, *, org_id=12, user_id=7, session_id="session-1"):
    db.add(AgentRunLedger(
        id=run_id, organization_id=org_id, user_id=user_id,
        session_id=session_id, objective="example.test", mode="agent",
    ))


def _search(db, store, run_id="run-1", query="owner_id", **overrides):
    args = {"run_id": run_id, "organization_id": 12, "user_id": 7,
            "session_id": "session-1", "query": query}
    args.update(overrides)
    return search_assessment_traces(db, store, **args)


def test_search_finds_redacted_evidence_without_returning_payload(monkeypatch):
    monkeypatch.delenv("AEGIS_EVIDENCE_DIR", raising=False)
    store = EvidenceStore()
    factory = _db()
    evidence_id = store.record(
        "tool_output", {"output": "Observed owner_id on the orders endpoint"},
    )
    with factory() as db:
        _run(db, "run-1")
        db.add(AgentActionReceipt(
            run_id="run-1", action_id="action-1", event="completed",
            tool_name="scoped_query_probe", target="https://example.test",
            evidence_ids=[evidence_id],
        ))
        db.add(AgentHypothesisCoverage(
            run_id="run-1", hypothesis_id="hyp-1", specialist="api_authz",
            title="Check owner boundary", evidence_ids=[evidence_id],
        ))
        db.commit()
        result = _search(db, store)

    assert result["count"] == 1
    assert result["results"][0]["evidence_ids"] == [evidence_id]
    assert result["results"][0]["specialist"] == "api_authz"
    assert result["results"][0]["matched_in"] == "evidence"
    assert "Observed owner_id" not in str(result)


def test_search_is_run_and_tenant_scoped(monkeypatch):
    monkeypatch.delenv("AEGIS_EVIDENCE_DIR", raising=False)
    store = EvidenceStore()
    factory = _db()
    evidence_id = store.record("tool_output", {"output": "owner_id"})
    with factory() as db:
        _run(db, "run-1")
        _run(db, "run-2")
        db.add(AgentActionReceipt(
            run_id="run-2", action_id="other-run", event="completed",
            tool_name="scoped_query_probe", evidence_ids=[evidence_id],
        ))
        db.commit()
        assert _search(db, store)["count"] == 0
        assert _search(db, store, run_id="run-2")["count"] == 1
        assert _search(db, store, run_id="run-2", organization_id=13)["error"]
        assert _search(db, store, run_id="run-2", session_id="other")["error"]


def test_verifier_evidence_and_search_actions_are_not_reused(monkeypatch):
    monkeypatch.delenv("AEGIS_EVIDENCE_DIR", raising=False)
    store = EvidenceStore()
    factory = _db()
    verifier_id = store.record(
        "tool_output", {"output": "verifier-only signal"},
        verifier_run_id="verifier-run",
    )
    with factory() as db:
        _run(db, "run-1")
        db.add_all([
            AgentActionReceipt(
                run_id="run-1", action_id="verify", event="completed",
                tool_name="scoped_query_probe", detail="verifier-only signal",
                evidence_ids=[verifier_id],
            ),
            AgentActionReceipt(
                run_id="run-1", action_id="search", event="completed",
                tool_name="search_assessment_traces", detail="verifier-only signal",
            ),
        ])
        db.commit()
        assert _search(db, store, query="verifier-only")["count"] == 0


def test_search_returns_matching_evidence_first_and_rejects_invalid_limit(monkeypatch):
    monkeypatch.delenv("AEGIS_EVIDENCE_DIR", raising=False)
    store = EvidenceStore()
    factory = _db()
    unrelated = store.record("tool_output", {"output": "no signal"})
    match = store.record("tool_output", {"output": "owner_id in response"})
    with factory() as db:
        _run(db, "run-1")
        db.add(AgentActionReceipt(
            run_id="run-1", action_id="action-1", event="completed",
            tool_name="scoped_query_probe", evidence_ids=[unrelated, match],
        ))
        db.commit()
        assert _search(db, store)["results"][0]["evidence_ids"][0] == match
        assert _search(db, store, limit="many")["error"]


def test_registered_tool_uses_current_run_context(monkeypatch):
    monkeypatch.delenv("AEGIS_EVIDENCE_DIR", raising=False)
    factory = _db()
    monkeypatch.setattr(agent_tools, "SessionLocal", factory)
    manager = agent_tools.ASMToolsManager()
    user_token = agent_tools.current_user_id.set(7)
    org_token = agent_tools.current_organization_id.set(12)
    session_token = agent_tools.current_session_id.set("session-1")
    run_token = active_run_id.set("run-1")
    try:
        from app.services.agent.evidence_store import evidence_store

        evidence_id = evidence_store(manager).record(
            "tool_output", {"output": "owner_id from another specialist"},
        )
        with factory() as db:
            _run(db, "run-1")
            db.add(AgentActionReceipt(
                run_id="run-1", action_id="action-1", event="completed",
                tool_name="scoped_query_probe", evidence_ids=[evidence_id],
            ))
            db.commit()
        tool = manager.get_tool("search_assessment_traces")
        assert callable(tool)
        result = json.loads(asyncio.run(tool(query="owner_id")))
        assert result["results"][0]["evidence_ids"] == [evidence_id]
        active_run_id.set("other-run")
        assert json.loads(asyncio.run(tool(query="owner_id")))["error"]
    finally:
        active_run_id.reset(run_token)
        agent_tools.current_session_id.reset(session_token)
        agent_tools.current_organization_id.reset(org_token)
        agent_tools.current_user_id.reset(user_token)
