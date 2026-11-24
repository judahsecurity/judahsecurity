"""Operator steer / compact / load / stop must only reach sessions the caller owns.

A session id is a capability only in name: anyone who learns one must not be
able to inject instructions into, compact the context of, queue a prior-hunt
brief into, or cancel another organization's live run. REST and WebSocket paths answer the same way for a
missing session and someone else's session so ids cannot be probed.
"""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.organization import Organization  # noqa: F401 - FK metadata
from app.models.user import User  # noqa: F401 - FK metadata
from app.models.agent_conversation import AgentConversation
from app.services.agent import run_control

OWNER = SimpleNamespace(id=7, organization_id=12)
OTHER_ORG = SimpleNamespace(id=8, organization_id=99)
SAME_ORG_OTHER_USER = SimpleNamespace(id=9, organization_id=12)


@pytest.fixture
def factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    AgentConversation.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        db.add(AgentConversation(session_id="owned", user_id=OWNER.id,
                                 organization_id=OWNER.organization_id,
                                 messages=[], mode="agent"))
        # Prior hunts a load could pull in: one per org, so a refused load is
        # refused for ownership of the target, not for a missing source.
        db.add(AgentConversation(session_id="prior", user_id=OWNER.id,
                                 organization_id=OWNER.organization_id,
                                 title="owner prior hunt",
                                 messages=[{"role": "user", "content": "scan a"}],
                                 mode="agent"))
        db.add(AgentConversation(session_id="other-prior", user_id=OTHER_ORG.id,
                                 organization_id=OTHER_ORG.organization_id,
                                 title="intruder prior hunt",
                                 messages=[{"role": "user", "content": "scan b"}],
                                 mode="agent"))
        db.commit()
    yield factory
    for sid in ("owned", "missing", "late"):
        run_control.drain_steers(sid)
        run_control.consume_compact(sid)
        run_control.drain_load_briefs(sid)
        run_control.clear_stop(sid)
        run_control.unregister_run(sid)


class _FakeRun:
    """Stands in for a live run task registered with run_control."""

    def __init__(self):
        self.cancelled = False

    def done(self):
        return False

    def cancel(self):
        self.cancelled = True


def _live_run(sid):
    run = _FakeRun()
    run_control.register_run(sid, run)
    return run


@pytest.fixture
def env(factory):
    from app.api.deps import get_current_user
    from app.api.routes import agent as routes
    from app.db.database import get_db

    app = FastAPI()
    app.include_router(routes.router)

    def test_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = test_db

    def as_user(user):
        app.dependency_overrides[get_current_user] = lambda: user

    as_user(OWNER)
    return SimpleNamespace(client=TestClient(app), as_user=as_user)


def _steer(client, sid, message="focus on /api/admin"):
    return client.post(f"/agent/sessions/{sid}/steer",
                       json={"session_id": sid, "message": message})


# ----------------------------------------------------------------- REST


def test_owner_can_steer_and_compact(env):
    resp = _steer(env.client, "owned")
    assert resp.status_code == 200
    assert resp.json()["queued"] is True
    assert run_control.drain_steers("owned") == ["focus on /api/admin"]

    resp = env.client.post("/agent/sessions/owned/compact")
    assert resp.status_code == 200
    assert resp.json()["compact_queued"] is True
    assert run_control.consume_compact("owned") is True


@pytest.mark.parametrize("intruder", [OTHER_ORG, SAME_ORG_OTHER_USER])
def test_other_caller_cannot_steer_or_compact(env, intruder):
    env.as_user(intruder)
    assert _steer(env.client, "owned", "exfiltrate everything").status_code == 404
    assert env.client.post("/agent/sessions/owned/compact").status_code == 404
    assert run_control.drain_steers("owned") == []
    assert run_control.consume_compact("owned") is False


def test_unknown_session_is_404_and_queues_nothing(env):
    # A steer pre-queued for an unknown id would be drained by whoever later
    # starts a run under that id, so it is refused rather than buffered.
    assert _steer(env.client, "missing").status_code == 404
    assert env.client.post("/agent/sessions/missing/compact").status_code == 404
    assert run_control.drain_steers("missing") == []
    assert run_control.consume_compact("missing") is False


def test_user_without_org_is_still_400(env):
    env.as_user(SimpleNamespace(id=7, organization_id=None, is_superuser=False))
    assert _steer(env.client, "owned").status_code == 400
    assert env.client.post("/agent/sessions/owned/compact").status_code == 400
    assert env.client.post("/agent/sessions/owned/stop").status_code == 400
    assert _load(env.client, "owned").status_code == 400


def _load(client, sid, source="prior"):
    return client.post(f"/agent/sessions/{sid}/load",
                       json={"session_id": sid, "source_session_id": source})


def test_owner_can_load_and_stop(env):
    resp = _load(env.client, "owned")
    assert resp.status_code == 200
    briefs = run_control.drain_load_briefs("owned")
    assert len(briefs) == 1 and "prior" in briefs[0]

    run = _live_run("owned")
    resp = env.client.post("/agent/sessions/owned/stop")
    assert resp.status_code == 200
    assert resp.json()["cancelled"] is True
    assert run.cancelled is True


@pytest.mark.parametrize("intruder,source", [
    (OTHER_ORG, "other-prior"),
    (SAME_ORG_OTHER_USER, "prior"),
])
def test_other_caller_cannot_load_or_stop(env, intruder, source):
    run = _live_run("owned")
    env.as_user(intruder)
    assert _load(env.client, "owned", source).status_code == 404
    assert env.client.post("/agent/sessions/owned/stop").status_code == 404
    assert run_control.drain_load_briefs("owned") == []
    assert run.cancelled is False
    assert run_control.is_stop_requested("owned") is False


def test_unknown_session_load_and_stop_are_404(env):
    # A stop or brief recorded for an unknown id would hit whoever later runs
    # under that id, so nothing is pre-armed.
    assert _load(env.client, "missing").status_code == 404
    assert env.client.post("/agent/sessions/missing/stop").status_code == 404
    assert run_control.drain_load_briefs("missing") == []
    assert run_control.is_stop_requested("missing") is False


# ------------------------------------------------------------ WebSocket


class _Socket:
    def __init__(self, script):
        self.script = list(script)
        self.messages = []

    async def accept(self):
        pass

    async def close(self, code=None):
        self.closed = code

    async def send_json(self, message):
        self.messages.append(message)

    async def receive_json(self):
        from fastapi import WebSocketDisconnect

        if not self.script:
            raise WebSocketDisconnect()
        step = self.script.pop(0)
        return step() if callable(step) else step

    def types(self):
        return [m.get("type") for m in self.messages]


async def _run_ws(monkeypatch, factory, user, session_id, script):
    from app.api.routes import agent as routes

    monkeypatch.setattr(routes, "SessionLocal", factory)
    monkeypatch.setattr(routes, "_authenticate_ws_token",
                        lambda _t: (user, user.organization_id))
    sock = _Socket([{"type": "init", "token": "t"}, *script])
    await routes.agent_websocket(sock, session_id)
    return sock


@pytest.mark.asyncio
async def test_ws_owner_can_steer_and_compact(monkeypatch, factory):
    sock = await _run_ws(monkeypatch, factory, OWNER, "owned", [
        {"type": "steer", "message": "go deeper on auth"},
        {"type": "compact"},
    ])
    assert "steer_queued" in sock.types()
    assert "compact_queued" in sock.types()
    assert run_control.drain_steers("owned") == ["go deeper on auth"]
    assert run_control.consume_compact("owned") is True


@pytest.mark.asyncio
async def test_ws_owner_can_load_and_stop(monkeypatch, factory):
    run = _live_run("owned")
    sock = await _run_ws(monkeypatch, factory, OWNER, "owned", [
        {"type": "load", "source_session_id": "prior"},
        {"type": "stop"},
    ])
    assert "load_queued" in sock.types()
    assert "cancelled" in sock.types()
    assert len(run_control.drain_load_briefs("owned")) == 1
    assert run.cancelled is True


@pytest.mark.asyncio
async def test_ws_other_org_is_refused_at_init(monkeypatch, factory):
    sock = await _run_ws(monkeypatch, factory, OTHER_ORG, "owned", [
        {"type": "steer", "message": "exfiltrate everything"},
    ])
    assert "authenticated" not in sock.types()
    assert "steer_queued" not in sock.types()
    assert run_control.drain_steers("owned") == []


@pytest.mark.asyncio
async def test_ws_steer_refused_when_session_is_someone_elses_after_init(monkeypatch, factory):
    # No row exists at init, so the socket authenticates; the victim's run then
    # claims the id. Steer/compact on this socket must still be refused.
    def victim_claims_session():
        with factory() as db:
            db.add(AgentConversation(session_id="late", user_id=OWNER.id,
                                     organization_id=OWNER.organization_id,
                                     messages=[], mode="agent"))
            db.commit()
        return {"type": "steer", "message": "exfiltrate everything"}

    sock = await _run_ws(monkeypatch, factory, OTHER_ORG, "late", [
        {"type": "steer", "message": "pre-queue before the victim starts"},
        victim_claims_session,
        {"type": "compact"},
    ])
    assert "authenticated" in sock.types()
    assert "steer_queued" not in sock.types()
    assert "compact_queued" not in sock.types()
    assert sock.types().count("error") == 3
    assert run_control.drain_steers("late") == []
    assert run_control.consume_compact("late") is False


@pytest.mark.asyncio
async def test_ws_load_and_stop_refused_when_session_is_someone_elses_after_init(
        monkeypatch, factory):
    # The intruder holds a socket on an unclaimed id; the victim then starts a
    # run under it (over REST). Load and stop on that socket must not reach it.
    runs = {}

    def victim_starts_run():
        with factory() as db:
            db.add(AgentConversation(session_id="late", user_id=OWNER.id,
                                     organization_id=OWNER.organization_id,
                                     messages=[], mode="agent"))
            db.commit()
        runs["victim"] = _live_run("late")
        return {"type": "load", "source_session_id": "other-prior"}

    sock = await _run_ws(monkeypatch, factory, OTHER_ORG, "late", [
        {"type": "stop"},
        {"type": "load", "source_session_id": "other-prior"},
        victim_starts_run,
        {"type": "stop"},
    ])
    assert "authenticated" in sock.types()
    assert "load_queued" not in sock.types()
    assert "cancelled" not in sock.types()
    assert sock.types().count("error") == 4
    assert run_control.drain_load_briefs("late") == []
    assert runs["victim"].cancelled is False
    assert run_control.is_stop_requested("late") is False
