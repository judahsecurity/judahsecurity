"""Operator-captured logged-in traffic: tokens, HAR, encrypted inbox, apply."""

import asyncio
import base64
import json
import time

import pytest

from app.services.agent import operator_capture as oc
from app.services.agent.assessment_scope import register_scope
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.evidence_store import evidence_store
from app.services.agent.tools import ASMToolsManager

ENTRY = {
    "method": "GET", "url": "https://app.example.com/api/me",
    "request_headers": {"Cookie": "sid=abc123; theme=dark", "Authorization": "Bearer tok.en.sig",
                        "Accept": "application/json"},
    "status": 200, "response_headers": {"Content-Type": "application/json"},
    "response_body": '{"id": 7, "email": "a@example.com"}', "captured_at": "2026-11-20T10:00:00Z",
}


def test_token_round_trip_and_tamper():
    issued = oc.issue_token(organization_id=3, session_id="s-1", user_id=9, identity="user_a",
                            role="customer")
    claims = oc.verify_token(issued["token"])
    assert claims["sid"] == "s-1" and claims["identity"] == "user_a" and claims["org"] == 3
    prefix, body, sig = issued["token"].split(".")
    forged = json.loads(base64.urlsafe_b64decode(body + "=="))
    forged["org"] = 4
    forged_body = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    with pytest.raises(oc.CaptureError):
        oc.verify_token(f"{prefix}.{forged_body}.{sig}")
    with pytest.raises(oc.CaptureError):
        oc.verify_token("not-a-token")


def test_token_expiry(monkeypatch):
    issued = oc.issue_token(organization_id=1, session_id="s", user_id=1, identity="a", ttl=60)
    later = time.time() + 3600
    monkeypatch.setattr(oc.time, "time", lambda: later)
    with pytest.raises(oc.CaptureError) as err:
        oc.verify_token(issued["token"])
    assert err.value.status == 401


@pytest.mark.parametrize("name", ["anonymous", "legacy", "", "has space", "x" * 41, "../a"])
def test_identity_names_rejected(name):
    with pytest.raises(oc.CaptureError):
        oc.validate_identity(name)


def test_normalize_skips_binary_and_bad_urls():
    rows = oc.normalize_batch([
        ENTRY,
        {**ENTRY, "url": "https://app.example.com/logo.png", "mime_type": "image/png"},
        {**ENTRY, "url": "javascript:alert(1)"},
        "junk",
    ])
    assert len(rows) == 1
    assert rows[0]["request"]["headers"]["Cookie"].startswith("sid=")


def test_har_entries_decode_base64_bodies():
    har = {"log": {"entries": [{
        "startedDateTime": "2026-11-20T10:00:00Z",
        "request": {"method": "POST", "url": "https://app.example.com/api/orders",
                    "headers": [{"name": "Cookie", "value": "sid=abc"}],
                    "postData": {"text": '{"item": 1}'}},
        "response": {"status": 201, "headers": [{"name": "Content-Type", "value": "application/json"}],
                     "content": {"mimeType": "application/json", "encoding": "base64",
                                 "text": base64.b64encode(b'{"order": 55}').decode()}},
    }]}}
    rows = oc.normalize_batch(oc.har_entries(har))
    assert rows[0]["request"]["body"] == '{"item": 1}'
    assert rows[0]["response"]["body"] == '{"order": 55}'
    with pytest.raises(oc.CaptureError):
        oc.har_entries({"nope": 1})


def test_inbox_is_encrypted_and_drains_once(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    rows = oc.normalize_batch([ENTRY] * 60)
    result = oc.enqueue(3, "s-1", identity="user_a", role="", tenant="", entries=rows, source="har")
    assert result == {"accepted": 60, "batches": 2}
    assert oc.pending_count(3, "s-1") == 2
    on_disk = b"".join(p.read_bytes() for p in tmp_path.rglob("*.capture"))
    assert b"abc123" not in on_disk and b"tok.en.sig" not in on_disk
    batches = oc.drain(3, "s-1")
    assert sum(len(b["entries"]) for b in batches) == 60
    assert oc.drain(3, "s-1") == [] and oc.pending_count(3, "s-1") == 0
    assert oc.drain(4, "s-1") == []


def _manager():
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._engagement_brain = None
    register_scope(manager, "https://app.example.com")
    return manager


def test_apply_registers_identity_records_evidence_and_drops_out_of_scope():
    manager = _manager()
    mapped = []

    async def fake_map(requests, identity="anonymous", source="runtime"):
        mapped.append((requests, identity, source))
        return "{}"

    manager.map_application_traffic = fake_map
    rows = oc.normalize_batch([ENTRY, {**ENTRY, "url": "https://evil.example.net/x"}])
    summary = asyncio.run(oc.apply_batches(manager, [{"identity": "user_a", "role": "customer",
                                                      "tenant": "t1", "entries": rows}]))
    assert summary["recorded"] == 1 and summary["out_of_scope"] == 1
    assert summary["identities"] == ["user_a"]

    session = identity_registry(manager).resolve("user_a", "https://app.example.com/")
    assert {"name": "sid", "value": "abc123"} in session["cookies"]
    assert session["headers"]["Authorization"] == "Bearer tok.en.sig"
    assert session["role"] == "customer" and session["tenant"] == "t1"

    record = evidence_store(manager).records[summary["evidence_ids"][0]]
    assert record["identity"] == "user_a" and record["test_type"] == "operator_capture"
    assert record["payload"]["request"]["headers"]["Authorization"] == "[redacted]"

    requests, identity, source = mapped[0]
    assert identity == "user_a" and source == "operator_capture"
    assert all(k.lower() not in ("cookie", "authorization") for k in requests[0]["headers"])


# --- routes ---------------------------------------------------------------------

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.organization import Organization  # noqa: F401 - FK metadata
from app.models.user import User  # noqa: F401 - FK metadata
from app.models.agent_conversation import AgentConversation


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.api.deps import get_current_user
    from app.api.routes import agent as routes
    from app.db.database import get_db

    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    AgentConversation.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        db.add(AgentConversation(session_id="s1", user_id=7, organization_id=12,
                                 messages=[], mode="agent"))
        db.add(AgentConversation(session_id="other", user_id=8, organization_id=12,
                                 messages=[], mode="agent"))
        db.commit()
    app = FastAPI()
    app.include_router(routes.router)

    def test_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=7, organization_id=12)
    return TestClient(app)


def test_extension_flow_queues_encrypted_batch(client):
    issued = client.post("/agent/sessions/s1/capture-token", json={"identity": "user_a"})
    assert issued.status_code == 201, issued.text
    token = issued.json()["token"]
    sent = client.post("/agent/capture", json={"entries": [ENTRY]},
                       headers={"Authorization": f"Bearer {token}"})
    assert sent.status_code == 202, sent.text
    assert sent.json()["accepted"] == 1 and sent.json()["identity"] == "user_a"
    assert client.get("/agent/sessions/s1/captures").json()["pending_batches"] == 1
    assert oc.drain(12, "s1")[0]["identity"] == "user_a"


def test_capture_rejects_bad_token_and_foreign_session(client):
    assert client.post("/agent/capture", json={"entries": [ENTRY]},
                       headers={"Authorization": "Bearer jcap.x.y"}).status_code == 401
    assert client.post("/agent/capture", json={"entries": [ENTRY]}).status_code == 401
    assert client.post("/agent/sessions/other/capture-token",
                       json={"identity": "user_a"}).status_code == 404


def test_har_upload(client):
    har = {"log": {"entries": [{"request": {"method": "GET", "url": ENTRY["url"],
                                            "headers": [{"name": "Cookie", "value": "sid=1"}]},
                                "response": {"status": 200, "headers": [],
                                             "content": {"mimeType": "application/json",
                                                         "text": "{}"}}}]}}
    resp = client.post("/agent/sessions/s1/har", json={"identity": "user_b", "har": har})
    assert resp.status_code == 202, resp.text
    assert resp.json()["accepted"] == 1
    bad = client.post("/agent/sessions/s1/har", json={"identity": "anonymous", "har": har})
    assert bad.status_code == 422
