"""Platform audit log: recording, redaction, scoping, hooks, export."""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.platform_audit import PlatformAuditLog
from app.services import platform_audit


@pytest.fixture
def factory(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    PlatformAuditLog.__table__.create(engine)
    maker = sessionmaker(bind=engine)
    import app.db.database as database

    monkeypatch.setattr(database, "SessionLocal", maker)
    monkeypatch.setattr(platform_audit, "_last_prune", float("inf"))
    return maker


def _rows(maker):
    with maker() as db:
        return db.query(PlatformAuditLog).order_by(PlatformAuditLog.id).all()


def user(uid=1, org=7, admin=True, superuser=False):
    from app.models.user import UserRole

    return SimpleNamespace(id=uid, organization_id=org, email=f"u{uid}@acme.test", username=f"u{uid}",
                           role=UserRole.ADMIN if admin else UserRole.ANALYST,
                           is_superuser=superuser, is_active=True)


def test_record_redacts_and_never_raises(factory):
    request = SimpleNamespace(headers={"x-forwarded-for": "203.0.113.9, 10.0.0.1",
                                       "user-agent": "pytest"}, client=None)
    platform_audit.record("settings.update", user=user(), target="agent", request=request,
                          detail={"changed": {"anthropic_api_key": "sk-ant-123", "llm_model": "x"}})
    [row] = _rows(factory)
    assert (row.actor, row.organization_id, row.ip, row.user_agent) == (
        "u1@acme.test", 7, "203.0.113.9", "pytest")
    assert row.detail["changed"]["llm_model"] == "x"
    assert "sk-ant-123" not in str(row.detail)

    def broken():
        raise RuntimeError("db down")

    platform_audit.record("auth.login", user=user(), db_factory=broken)  # no exception


def test_large_detail_is_truncated(factory):
    platform_audit.record("x.big", user=user(), detail={"blob": "a" * 20000})
    [row] = _rows(factory)
    assert row.detail["truncated"] is True


def test_prune_respects_retention(factory, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 30, raising=False)
    with factory() as db:
        db.add(PlatformAuditLog(action="old", created_at=datetime.utcnow() - timedelta(days=40)))
        db.add(PlatformAuditLog(action="new"))
        db.commit()
    assert platform_audit.prune(factory) == 1
    assert [r.action for r in _rows(factory)] == ["new"]


@pytest.fixture
def client(factory):
    from app.api.deps import require_admin
    from app.api.routes import audit
    from app.db.database import get_db

    app = FastAPI()
    app.include_router(audit.router)

    def db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = db
    state = {"user": user()}
    app.dependency_overrides[require_admin] = lambda: state["user"]
    test_client = TestClient(app)
    test_client.state = state
    return test_client


def test_list_is_scoped_to_own_org_and_filterable(client):
    platform_audit.record("auth.login", user=user(1, 7))
    platform_audit.record("auth.login_failed", actor="mallory", organization_id=7, outcome="denied")
    platform_audit.record("settings.update", user=user(2, 8), target="agent")
    body = client.get("/audit/logs").json()
    assert body["total"] == 2 and {i["action"] for i in body["items"]} == {"auth.login", "auth.login_failed"}
    assert client.get("/audit/logs", params={"action": "auth.*", "outcome": "denied"}).json()["total"] == 1
    assert client.get("/audit/logs", params={"organization_id": 8}).status_code == 403

    client.state["user"] = user(9, None, superuser=True)
    assert client.get("/audit/logs").json()["total"] == 3
    assert client.get("/audit/logs", params={"organization_id": 8}).json()["total"] == 1


def test_csv_export_neutralizes_formulas_and_is_itself_audited(client, factory):
    platform_audit.record("auth.login_failed", actor="=HYPERLINK(\"x\")", organization_id=7,
                          outcome="denied")
    response = client.get("/audit/logs/export")
    assert response.status_code == 200
    assert "'=HYPERLINK" in response.text
    assert [r.action for r in _rows(factory)][-1] == "audit.export"


def test_login_hooks(factory, monkeypatch):
    from fastapi import HTTPException

    from app.api.routes import auth
    from app.core import security

    good = SimpleNamespace(id=3, organization_id=7, email="a@acme.test", username="a",
                           hashed_password="h", is_active=True, last_login=None)

    class Query:
        def __init__(self, result):
            self.result = result

        def filter(self, *_a):
            return self

        def first(self):
            return self.result

    class Db:
        def __init__(self, result):
            self.result = result

        def query(self, _model):
            return Query(self.result)

        def add(self, _x):
            pass

        def commit(self):
            pass

        def refresh(self, _x):
            pass

    monkeypatch.setattr(auth, "verify_password", lambda pw, _h: pw == "right")
    monkeypatch.setattr(auth, "verify_captcha", lambda *_a, **_k: None)
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="198.51.100.4"))
    login = auth.login.__wrapped__ if hasattr(auth.login, "__wrapped__") else auth.login
    with pytest.raises(HTTPException):
        login(request, SimpleNamespace(username="a", password="wrong"), Db(good))
    login(request, SimpleNamespace(username="a", password="right"), Db(good))
    rows = _rows(factory)
    assert [(r.action, r.outcome, r.ip) for r in rows] == [
        ("auth.login_failed", "denied", "198.51.100.4"), ("auth.login", "success", "198.51.100.4")]
