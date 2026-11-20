"""Custom roles narrow built-in roles; enforced on routes, the agent WebSocket and agent tools."""

from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import permissions
from app.core.permissions import (
    BUILTIN, effective_permissions, route_permission, user_id_restricted_from, validate_permissions,
)
from app.models.org_role import OrgRole
from app.models.user import User, UserRole


@pytest.fixture
def db(monkeypatch):
    from app.models.organization import Organization
    from app.models.platform_audit import PlatformAuditLog

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    for table in (Organization.__table__, OrgRole.__table__, User.__table__,
                  PlatformAuditLog.__table__):
        table.create(engine)
    maker = sessionmaker(bind=engine)
    import app.db.database as database

    monkeypatch.setattr(database, "SessionLocal", maker)
    permissions.clear_cache()
    with maker() as session:
        session.add(Organization(id=1, name="Acme"))
        session.add(Organization(id=2, name="Other"))
        session.add(OrgRole(id=10, organization_id=1, name="Recon only",
                            permissions=["agent.run", "reports.export", "users.manage"]))
        session.add(OrgRole(id=20, organization_id=2, name="Elsewhere", permissions=list(BUILTIN["admin"])))
        for uid, role, custom in ((1, UserRole.ADMIN, None), (2, UserRole.ANALYST, 10),
                                  (3, UserRole.ANALYST, 20), (4, UserRole.ANALYST, None)):
            session.add(User(id=uid, email=f"u{uid}@acme.test", username=f"u{uid}", hashed_password="x",
                             role=role, organization_id=1, custom_role_id=custom))
        session.commit()
    return maker


def test_validate_permissions():
    assert validate_permissions(["agent.run", "agent.run"]) == ["agent.run"]
    with pytest.raises(ValueError):
        validate_permissions(["root"])


def test_custom_role_only_narrows(db):
    with db() as session:
        analyst_custom = session.get(User, 2)
        # users.manage is in the role but not in the analyst built-in set: not granted
        assert effective_permissions(session, analyst_custom) == {"agent.run", "reports.export"}
        # Role from another organization: fail closed
        assert effective_permissions(session, session.get(User, 3)) == frozenset()
        assert effective_permissions(session, session.get(User, 4)) == BUILTIN["analyst"]


def test_route_mapping():
    assert route_permission("POST", "/api/v1/scans/", "/api/v1") == "scans.run"
    assert route_permission("GET", "/api/v1/scans/", "/api/v1") is None
    assert route_permission("POST", "/api/v1/agent/confirmations/abc/decide", "/api/v1") == "agent.approve_tools"
    assert route_permission("POST", "/api/v1/agent/query", "/api/v1") == "agent.run"
    assert route_permission("PUT", "/api/v1/organizations/1/settings/agent", "/api/v1") == "settings.edit"
    assert route_permission("GET", "/api/v1/audit/logs", "/api/v1") == "audit.read"
    assert route_permission("POST", "/api/v1/reports/findings/report", "/api/v1") == "reports.export"


def test_app_dependency_blocks_only_custom_role_users(db, monkeypatch):
    from app.api import permissions_dep
    from app.core import security

    monkeypatch.setattr(permissions_dep.settings, "API_PREFIX", "/api/v1")
    monkeypatch.setattr(security, "decode_token",
                        lambda token: {"type": "access", "sub": token})
    app = FastAPI(dependencies=[Depends(permissions_dep.enforce_route_permission)])

    @app.post("/api/v1/scans/")
    def create_scan():
        return {"ok": True}

    @app.post("/api/v1/reports/findings/report")
    def report():
        return {"ok": True}

    @app.websocket("/api/v1/agent/ws/x")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_json({"ok": True})
        await websocket.close()

    client = TestClient(app)
    auth = lambda name: {"Authorization": f"Bearer {name}"}  # noqa: E731
    assert client.post("/api/v1/scans/", headers=auth("u4")).status_code == 200
    denied = client.post("/api/v1/scans/", headers=auth("u2"))
    assert denied.status_code == 403 and "scans.run" in denied.json()["detail"]
    assert client.post("/api/v1/reports/findings/report", headers=auth("u2")).status_code == 200
    assert client.post("/api/v1/scans/").status_code == 200  # route's own auth handles anonymous
    with client.websocket_connect("/api/v1/agent/ws/x") as socket:
        assert socket.receive_json() == {"ok": True}
    with db() as session:
        from app.models.platform_audit import PlatformAuditLog

        assert session.query(PlatformAuditLog).filter_by(action="permission.denied").count() == 1


def test_agent_active_testing_withheld(db):
    from app.services.agent.tools import ASMToolsManager, current_organization_id, current_user_id

    assert user_id_restricted_from(2, "agent.active_testing") is True
    assert user_id_restricted_from(4, "agent.active_testing") is False
    manager = ASMToolsManager()
    token_user, token_org = current_user_id.set(2), current_organization_id.set(1)
    try:
        assert manager._active_testing_denied("execute_nuclei")["error"] == "permission_denied"
        assert manager._active_testing_denied("execute_httpx") is None  # light recon allowed
        assert manager._active_testing_denied("query_assets") is None
    finally:
        current_user_id.reset(token_user)
        current_organization_id.reset(token_org)


def test_roles_api(db, monkeypatch):
    from app.api.deps import require_admin
    from app.api.routes import roles
    from app.db.database import get_db

    app = FastAPI()
    app.include_router(roles.router)

    def get_session():
        session = db()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = get_session
    with db() as session:
        admin = session.get(User, 1)
        session.expunge(admin)
    app.dependency_overrides[require_admin] = lambda: admin
    client = TestClient(app)
    listing = client.get("/roles").json()
    assert [r["name"] for r in listing["roles"]] == ["Recon only"]
    assert listing["roles"][0]["members"] == 1
    assert client.post("/roles", json={"name": "Bad", "permissions": ["root"]}).status_code == 422
    created = client.post("/roles", json={"name": "Triage", "permissions": ["findings.edit"]}).json()
    assert client.post("/roles", json={"name": "Triage", "permissions": []}).status_code == 409
    assigned = client.put("/roles/assign", json={"user_id": 4, "role_id": created["id"]}).json()
    assert assigned["effective_permissions"] == ["findings.edit"]
    assert client.put("/roles/assign", json={"user_id": 4, "role_id": 20}).status_code == 404
    assert client.get("/roles", params={"organization_id": 2}).status_code == 403
    assert client.delete(f"/roles/{created['id']}").status_code == 204
    with db() as session:
        assert session.get(User, 4).custom_role_id is None
