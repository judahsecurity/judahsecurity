from __future__ import annotations

import pytest
from aegis_runtime import AgentEvent
from app.db.database import Base
from app.models.agent_runtime import (
    AgentCheckpoint,
    AgentCommand,
    AgentEventRecord,
    AgentRun,
)
from app.services.agent import runtime_store
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


def _store(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
        tables=[
            AgentRun.__table__,
            AgentEventRecord.__table__,
            AgentCommand.__table__,
            AgentCheckpoint.__table__,
        ],
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(runtime_store, "SessionLocal", factory)
    return runtime_store


def test_runtime_store_persists_runs_events_commands_and_checkpoints(monkeypatch) -> None:
    store = _store(monkeypatch)
    store.ensure_run(
        session_id="session-1",
        organization_id=7,
        user_id=42,
        mode="agent",
        objective="Map the authorized surface",
    )
    store.append_event(
        AgentEvent(
            run_id="session-1",
            organization_id=7,
            user_id="42",
            event_type="run.progress",
            payload={"message": "started"},
        )
    )
    command_id = store.queue_command("session-1", "steer", {"message": "focus on APIs"})
    digest = store.save_checkpoint(7, "session-1", {"phase": "mapping"})

    assert command_id
    assert len(digest) == 64
    assert store.get_run("session-1", 7)["status"] == "running"
    assert store.load_checkpoint(7, "session-1") == {"phase": "mapping"}
    assert [row["command_type"] for row in store.consume_commands("session-1", ("steer",))] == [
        "steer"
    ]
    event_types = [row["event_type"] for row in store.list_events("session-1", 7)]
    assert event_types == ["run.progress", "command.queued", "command.consumed"]


def test_runtime_store_rejects_cross_tenant_session_reuse(monkeypatch) -> None:
    store = _store(monkeypatch)
    store.ensure_run(session_id="shared-id", organization_id=7, user_id=42)

    with pytest.raises(ValueError, match="different organization"):
        store.ensure_run(session_id="shared-id", organization_id=8, user_id=99)
    with pytest.raises(ValueError, match="does not match"):
        store.append_event(
            AgentEvent(
                run_id="shared-id",
                organization_id=8,
                event_type="run.progress",
            )
        )
    with pytest.raises(ValueError, match="different user"):
        store.ensure_run(session_id="shared-id", organization_id=7, user_id=99)
