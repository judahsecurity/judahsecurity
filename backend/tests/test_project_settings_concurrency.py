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
