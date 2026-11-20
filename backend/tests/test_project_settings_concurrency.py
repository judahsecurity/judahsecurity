"""Settings saves with If-Match refuse to overwrite a newer save."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_current_active_user
from app.api.routes import organizations
from app.db.database import get_db
from app.models.project_settings import ProjectSettings


@pytest.fixture
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    ProjectSettings.__table__.create(engine)
    factory = sessionmaker(bind=engine)
    app = FastAPI()
    app.include_router(organizations.router)

    def db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = db
    app.dependency_overrides[get_current_active_user] = lambda: object()
    monkeypatch.setattr(organizations, "_check_org_access", lambda *_a, **_k: None)
    return TestClient(app)


URL = "/organizations/1/settings/commoncrawl"


def test_stale_if_match_is_refused_and_fresh_one_saves(client):
    first = client.get(URL)
    etag = first.headers["ETag"]

    other = client.put(URL, json={"config": {"timeout": 30}}, headers={"If-Match": etag})
    assert other.status_code == 200
    newer = other.headers["ETag"]
    assert newer != etag

    stale = client.put(URL, json={"config": {"timeout": 99}}, headers={"If-Match": etag})
    assert stale.status_code == 409
    assert "changed by someone else" in stale.json()["detail"]
    assert stale.headers["ETag"] == newer
    assert client.get(URL).json()["timeout"] == 30

    fresh = client.put(URL, json={"config": {"timeout": 99}}, headers={"If-Match": newer})
    assert fresh.status_code == 200 and fresh.json()["timeout"] == 99


def test_save_without_if_match_keeps_last_write_wins(client):
    client.put(URL, json={"config": {"timeout": 30}})
    assert client.put(URL, json={"config": {"timeout": 40}}).status_code == 200
    assert client.get(URL).json()["timeout"] == 40


def test_get_and_put_etags_agree(client):
    saved = client.put(URL, json={"config": {"timeout": 55}})
    assert client.get(URL).headers["ETag"] == saved.headers["ETag"]


def _as(client, role):
    from types import SimpleNamespace

    from app.models.user import UserRole

    user = SimpleNamespace(role=getattr(UserRole, role), is_superuser=False)
    client.app.dependency_overrides[get_current_active_user] = lambda: user


NOTIFY = "/organizations/1/settings/notifications"


def test_notification_settings_are_admin_only_and_validated(client):
    _as(client, "ANALYST")
    denied = client.put(NOTIFY, json={"config": {"telegram_enabled": True}})
    assert denied.status_code == 403

    _as(client, "ADMIN")
    bad = client.put(NOTIFY, json={"config": {"telegram_chat_ids": ["42", "evil chat"]}})
    assert bad.status_code == 422
    ok = client.put(NOTIFY, json={"config": {"telegram_enabled": True,
                                             "telegram_chat_ids": "-1001, @prowl_alerts"}})
    assert ok.status_code == 200
    assert ok.json()["telegram_chat_ids"] == ["-1001", "@prowl_alerts"]
    assert client.put(NOTIFY, json={"config": {"min_severity": "urgent"}}).status_code == 422


def test_test_notification_endpoint(client, monkeypatch):
    from app.services import chat_notifier

    _as(client, "ADMIN")
    monkeypatch.setattr(chat_notifier, "default_notifier", lambda: None)
    assert client.post("/organizations/1/notifications/test").status_code == 409

    class Rec:
        name = "fake"
        sent = []

        def send(self, chat_id, text):
            self.sent.append(chat_id)

    rec = Rec()
    monkeypatch.setattr(chat_notifier, "default_notifier", lambda: rec)
    assert client.post("/organizations/1/notifications/test").status_code == 409
    client.put(NOTIFY, json={"config": {"telegram_enabled": True, "telegram_chat_ids": ["42"]}})
    response = client.post("/organizations/1/notifications/test")
    assert response.status_code == 200 and response.json() == {"results": {"42": "sent"}}
