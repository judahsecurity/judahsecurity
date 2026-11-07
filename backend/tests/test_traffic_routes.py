from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api import deps
from app.api.routes import ingestion, traffic
from app.db.database import Base, get_db
from app.models.asset import Asset, AssetType
from app.models.traffic import TrafficExchange, VulnerabilityTrafficRef
from app.models.user import UserRole
from app.models.vulnerability import Severity, Vulnerability
from app.services import roe_service


@pytest.fixture
def env(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Asset.__table__, Vulnerability.__table__, TrafficExchange.__table__, VulnerabilityTrafficRef.__table__,
    ])
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(roe_service, "check_target", lambda *a, **k: (True, None))
    db = factory()
    db.add_all([
        Asset(id=1, name="example.com", organization_id=7, asset_type=AssetType.DOMAIN, value="example.com"),
        Asset(id=2, name="b.com", organization_id=8, asset_type=AssetType.DOMAIN, value="b.com"),
    ])
    db.flush()
    db.add_all([
        Vulnerability(id=10, title="IDOR", severity=Severity.HIGH, asset_id=1),
        Vulnerability(id=11, title="other tenant", severity=Severity.LOW, asset_id=2),
    ])
    db.commit()

    app = FastAPI()
    app.include_router(traffic.router)

    def _db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    state = {"user": SimpleNamespace(id=1, organization_id=7, is_superuser=False, role=UserRole.ANALYST,
                                     is_active=True)}
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[deps.get_current_active_user] = lambda: state["user"]
    app.dependency_overrides[deps.get_current_user] = lambda: state["user"]
    app.dependency_overrides[ingestion.get_agent_key] = lambda: state["key"]
    return TestClient(app), factory, state


def _ingest(client, entries):
    return client.post("/traffic/ingest", json={"capture_id": "cap-12345678", "entries": entries})


def test_ingest_requires_traffic_scope(env):
    client, _, state = env
    state["key"] = SimpleNamespace(id=3, organization_id=7, scopes=["ingest:findings"])
    assert _ingest(client, [{"url": "https://app.example.com/"}]).status_code == 403


def test_ingest_search_bind_and_unbind(env):
    client, factory, state = env
    state["key"] = SimpleNamespace(id=3, organization_id=7, scopes=["ingest:traffic"])
    result = _ingest(client, [
        {"method": "GET", "url": "https://app.example.com/orders/42", "status": 200,
         "response_body": '{"order":42}', "request_headers": [{"name": "Cookie", "value": "sid=1"}]},
        {"method": "GET", "url": "https://b.com/"},
    ]).json()
    assert result["accepted"] == 1 and len(result["rejected"]) == 1

    listing = client.get("/traffic", params={"q": "orders"}).json()
    assert listing["total"] == 1
    exchange_id = listing["items"][0]["id"]
    detail = client.get(f"/traffic/{exchange_id}").json()
    assert detail["request_headers"]["Cookie"] == "[redacted]"

    assert client.post("/vulnerabilities/10/traffic", json={"traffic_id": exchange_id}).status_code == 201
    items = client.get("/vulnerabilities/10/traffic").json()["items"]
    assert items[0]["exchange"]["url"].endswith("/orders/42")
    assert items[0]["bound_by"] == "user"

    # Cross-tenant access is denied both ways.
    assert client.get("/vulnerabilities/11/traffic").status_code == 403
    state["user"] = SimpleNamespace(id=2, organization_id=8, is_superuser=False, role=UserRole.ANALYST,
                                    is_active=True)
    assert client.get(f"/traffic/{exchange_id}").status_code == 404
    assert client.post("/vulnerabilities/11/traffic", json={"traffic_id": exchange_id}).status_code == 404

    state["user"] = SimpleNamespace(id=1, organization_id=7, is_superuser=False, role=UserRole.ANALYST,
                                    is_active=True)
    ref_id = items[0]["ref_id"]
    assert client.delete(f"/vulnerabilities/10/traffic/{ref_id}").status_code == 204
    assert client.get("/vulnerabilities/10/traffic").json()["items"] == []
