"""Severity evaluation + business application API flow for an analyst."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.api import deps  # noqa: E402
from app.api.routes import business_apps, vulnerabilities  # noqa: E402
from app.db.database import Base, get_db  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.business_application import BusinessApplication  # noqa: E402
from app.models.netblock import Netblock  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.screenshot import Screenshot  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Netblock.__table__, BusinessApplication.__table__, Asset.__table__,
        Vulnerability.__table__, Screenshot.__table__,
    ])
    Session = sessionmaker(bind=engine)
    import app.db.database as database
    monkeypatch.setattr(database, "SessionLocal", Session)  # background backfill sessions
    s = Session()
    s.add_all([Organization(id=1, name="Acme"), Organization(id=2, name="Globex")])
    s.add(Netblock(organization_id=1, inetnum="145.97.0.0 - 145.97.255.255", start_ip="145.97.0.0",
                   end_ip="145.97.255.255", cidr_notation="145.97.0.0/16", is_owned=True, in_scope=True))
    asset = Asset(id=10, name="portal.acme.com", value="portal.acme.com", asset_type=AssetType.DOMAIN,
                  organization_id=1, ip_address="145.97.10.10", is_public=True)
    other = Asset(id=20, name="globex.com", value="globex.com", asset_type=AssetType.DOMAIN, organization_id=2)
    s.add_all([asset, other])
    s.add(Vulnerability(id=100, title="Exposed admin panel", severity=Severity.HIGH, asset_id=10,
                        detected_by="nuclei", template_id="exposed-panels/admin", metadata_={}))
    s.add(Vulnerability(id=101, title="Old jQuery", severity=Severity.LOW, asset_id=10,
                        detected_by="nuclei", template_id="tech/jquery", metadata_={}))
    s.add(BusinessApplication(id=5, organization_id=1, source="servicenow", external_id="sys1",
                              app_id="APM0001234", name="Customer Portal",
                              business_criticality="1 - most critical", criticality_level=1))
    s.add(BusinessApplication(id=6, organization_id=2, source="servicenow", external_id="sys2",
                              app_id="APM0009999", name="Globex App", criticality_level=1))
    s.commit()
    s.close()

    app = FastAPI()
    app.include_router(vulnerabilities.router)
    app.include_router(business_apps.router)

    def db_override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    analyst = User(id=1, email="a@acme.com", username="a", hashed_password="x", organization_id=1, is_superuser=False)
    app.dependency_overrides[get_db] = db_override
    app.dependency_overrides[deps.get_current_active_user] = lambda: analyst
    app.dependency_overrides[deps.require_analyst] = lambda: analyst
    return TestClient(app)


def test_analyst_flow(client):
    # Backfill evaluates every open finding.
    assert client.post("/vulnerabilities/severity-evaluation/run", json={"only_missing": True}).json()["queued"] == 2
    summary = client.get("/vulnerabilities/severity-evaluation/summary").json()
    assert summary["triage"]["needs_analyst"] == 2 and summary["triage"]["not_evaluated"] == 0

    # The table shows the fields and filters to the triage queue.
    rows = client.get("/vulnerabilities/", params={"triage": "needs_analyst", "sort": "risk"}).json()
    assert len(rows) == 2
    row = next(r for r in rows if r["id"] == 100)
    assert row["sev_network_location"] == 4 and row["sev_status"] == "needs_analyst" and row["sev_pending"] >= 1

    # Linking the asset to its business application scores Business Impact for both findings.
    apps = client.get("/business-apps", params={"q": "APM0001"}).json()
    assert [a["app_id"] for a in apps] == ["APM0001234"]
    res = client.put("/business-apps/assets/10", json={"business_app_id": 5}).json()
    assert res["findings_updated"] == 2
    view = client.get("/vulnerabilities/100/risk-factors").json()
    bi = view["factors"]["business_impact"]
    assert (bi["score"], bi["source"]) == (4, "auto") and "Customer Portal" in bi["reason"]
    assert view["factors"]["network_location"]["rating"] == "Acme Hosted"

    # Analyst scores what's left → triaged, and the column follows.
    left = view["needs_analyst"]
    view = client.put("/vulnerabilities/100/risk-factors",
                      json={"factors": {k: {"score": 3, "note": "checked"} for k in left}}).json()
    assert view["status"] == "triaged"
    rows = client.get("/vulnerabilities/", params={"triage": "triaged"}).json()
    assert [r["id"] for r in rows] == [100]
    assert rows[0]["business_app"]["app_id"] == "APM0001234" and rows[0]["business_app"]["inherited_from_asset"]


def test_cannot_link_another_orgs_app(client):
    assert client.put("/business-apps/findings/100", json={"business_app_id": 6}).status_code == 404
    assert client.put("/business-apps/assets/20", json={"business_app_id": 5}).status_code == 403
