import json
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  (populate metadata for FK targets)
from app.db.database import Base
from app.models.asset import Asset, AssetType
from app.models.traffic import TrafficExchange, VulnerabilityTrafficRef
from app.services import roe_service, traffic_recorder
from app.services.agent.evidence_store import EvidenceStore


@pytest.fixture
def db_factory(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine, tables=[Asset.__table__, TrafficExchange.__table__, VulnerabilityTrafficRef.__table__],
    )
    factory = sessionmaker(bind=engine)
    recorder = traffic_recorder.TrafficRecorder(session_factory=factory)
    monkeypatch.setattr(traffic_recorder, "_recorder", recorder)
    monkeypatch.setattr(recorder, "_ensure_thread", lambda: None)  # flush() drains synchronously
    monkeypatch.setattr(roe_service, "check_target", lambda db, org, target, scan_type=None: (True, None))
    return factory


def _evidence(**overrides):
    payload = {
        "request": {
            "method": "post", "url": "https://app.example.com/api/login?next=/home",
            "identity": "alice",
            "headers": {"Cookie": "sid=abc123", "Authorization": "Bearer xyz", "Accept": "*/*"},
            "body": '{"user":"alice","password":"hunter2"}',
        },
        "response": {
            "status": 200, "headers": {"Content-Type": "application/json", "Set-Cookie": "sid=new"},
            "body": '{"ok":true}', "length": 11, "elapsed_s": 0.25,
        },
    }
    payload.update(overrides)
    return {"id": "a" * 32, "kind": "http_exchange", "hypothesis_id": "H1", "identity": "alice",
            "payload": payload}


def test_exchange_from_evidence_redacts_credentials():
    row = traffic_recorder.exchange_from_evidence(_evidence())
    assert row["method"] == "POST"
    assert row["host"] == "app.example.com"
    assert row["path"] == "/api/login?next=/home"
    assert row["status_code"] == 200
    assert row["elapsed_ms"] == 250
    assert row["request_headers"]["Cookie"] == "[redacted]"
    assert row["request_headers"]["Authorization"] == "[redacted]"
    assert row["request_headers"]["Accept"] == "*/*"
    assert row["response_headers"]["Set-Cookie"] == "[redacted]"
    assert "hunter2" not in row["request_body"]
    assert row["artifact_id"] == "a" * 32


def test_bodies_are_truncated_and_binary_skipped():
    big = "x" * (traffic_recorder.MAX_BODY_BYTES + 10)
    row = traffic_recorder.normalize_exchange(method="GET", url="https://h.example.com/", response_body=big)
    assert len(row["response_body"]) == traffic_recorder.MAX_BODY_BYTES
    assert row["truncated"] == 2
    image = traffic_recorder.normalize_exchange(
        method="GET", url="https://h.example.com/a.png",
        response_headers={"content-type": "image/png"}, response_body="\x89PNG",
    )
    assert image["response_body"] is None
    assert traffic_recorder.normalize_exchange(method="GET", url="ftp://h.example.com/") is None


def test_agent_exchange_is_recorded_with_provenance(db_factory):
    assert traffic_recorder.record_agent_exchange(_evidence(), 7, "sess-1")
    assert not traffic_recorder.record_agent_exchange(_evidence(), None, "sess-1")
    traffic_recorder.recorder().flush()
    db = db_factory()
    row = db.query(TrafficExchange).one()
    assert (row.organization_id, row.source, row.session_id, row.artifact_id) == (7, "agent", "sess-1", "a" * 32)


def test_recording_can_be_disabled(db_factory, monkeypatch):
    monkeypatch.setenv("AEGIS_TRAFFIC_RECORDING", "off")
    assert not traffic_recorder.record_agent_exchange(_evidence(), 7, "sess-1")


def test_extension_ingest_enforces_asset_scope(db_factory):
    db = db_factory()
    db.add_all([
        Asset(name="example.com", organization_id=7, asset_type=AssetType.DOMAIN, value="example.com", in_scope=True),
        Asset(name="excluded.other.com", organization_id=7, asset_type=AssetType.SUBDOMAIN, value="excluded.other.com", in_scope=False),
        Asset(name="tenant-b.com", organization_id=8, asset_type=AssetType.DOMAIN, value="tenant-b.com", in_scope=True),
    ])
    db.commit()
    result = traffic_recorder.ingest_extension_batch(
        db, organization_id=7, agent_key_id=3, capture_id="cap-12345678",
        entries=[
            {"method": "GET", "url": "https://app.example.com/dashboard", "status": 200,
             "page_url": "https://app.example.com/"},
            {"method": "GET", "url": "https://example.com/"},
            {"method": "GET", "url": "https://excluded.other.com/"},
            {"method": "GET", "url": "https://tenant-b.com/"},
            {"method": "GET", "url": "https://evil-example.com/"},
        ],
    )
    assert result["accepted"] == 2
    assert [r["index"] for r in result["rejected"]] == [2, 3, 4]
    rows = db.query(TrafficExchange).all()
    assert {r.source for r in rows} == {"extension"}
    assert {r.capture_id for r in rows} == {"cap-12345678"}


def test_extension_ingest_respects_roe(db_factory, monkeypatch):
    db = db_factory()
    db.add(Asset(name="example.com", organization_id=7, asset_type=AssetType.DOMAIN, value="example.com", in_scope=True))
    db.commit()
    monkeypatch.setattr(roe_service, "check_target", lambda *a, **k: (False, "excluded by RoE"))
    result = traffic_recorder.ingest_extension_batch(
        db, organization_id=7, agent_key_id=None, capture_id="cap-12345678",
        entries=[{"method": "GET", "url": "https://app.example.com/"}],
    )
    assert result["accepted"] == 0
    assert result["rejected"][0]["reason"] == "excluded by RoE"


def test_bindings_resolve_after_async_write(db_factory):
    db = db_factory()
    added = traffic_recorder.bind_artifacts(
        db, vulnerability_id=1, organization_id=7, artifact_ids=["a" * 32, "b" * 32, "a" * 32],
    )
    db.commit()
    assert added == 2
    items = traffic_recorder.traffic_for_vulnerability(db, 1, 7)
    assert [i["pending"] for i in items] == [True, True]

    traffic_recorder.record_agent_exchange(_evidence(), 7, "sess-1")
    traffic_recorder.recorder().flush()
    items = traffic_recorder.traffic_for_vulnerability(db, 1, 7)
    assert items[0]["exchange"]["method"] == "POST"
    assert items[1]["pending"] is True
    # Another tenant's exchange with the same artifact id never resolves.
    assert all(i["exchange"] is None for i in traffic_recorder.traffic_for_vulnerability(db, 1, 8))


def test_create_finding_binds_only_execution_owned_exchanges(db_factory):
    from app.services.agent.tools import ASMToolsManager

    store = EvidenceStore()
    real = store.record("http_exchange", _evidence()["payload"], target="https://app.example.com/")
    other = store.record("tool_output", {"stdout": "x"})
    manager = SimpleNamespace(_evidence_store=store)
    vuln = SimpleNamespace(id=5, asset=SimpleNamespace(organization_id=7))
    db = db_factory()
    bound = ASMToolsManager._bind_finding_traffic(
        manager, db, vuln, f'["{real}", "{other}", "{"f" * 32}"]', [real],
    )
    assert bound == 1
    refs = db.query(VulnerabilityTrafficRef).all()
    assert [(r.vulnerability_id, r.artifact_id) for r in refs] == [(5, real)]


def test_stored_traffic_hides_session_headers_and_one_time_codes():
    row = traffic_recorder.normalize_exchange(
        method="POST",
        url="https://app.example.com/oauth/callback?code=abc123&promo_code=SPRING&state=xyz",
        request_headers={"X-Session": "s-998", "X-MFA-Token": "445566", "Accept": "*/*"},
        request_body="otp=123456&remember=1",
        response_headers={"Content-Type": "application/json"},
        response_body='{"user": "alice", "session_id": "sess-1", "refresh_token": "r1", "code": "999"}',
    )
    assert row["request_headers"] == {"X-Session": "[redacted]", "X-MFA-Token": "[redacted]", "Accept": "*/*"}
    assert "abc123" not in row["url"] and "abc123" not in row["path"]
    assert "promo_code=SPRING" in row["url"] and "state=xyz" in row["url"]
    assert row["request_body"] == "otp=[redacted]&remember=1"
    body = json.loads(row["response_body"])
    assert body == {"user": "alice", "session_id": "[redacted]", "refresh_token": "[redacted]", "code": "[redacted]"}
