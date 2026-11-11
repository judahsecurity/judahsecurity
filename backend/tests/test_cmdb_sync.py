"""ServiceNow CMDB sync: application services, the CIs that run them, and
attribution of assets / findings to an owner and business unit (mocked
Table API)."""

import asyncio

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")
pytest.importorskip("fastapi")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.application_service import ApplicationService, CmdbCiLink  # noqa: E402
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.business_application import BusinessApplication  # noqa: E402
from app.models.netblock import Netblock  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.screenshot import Screenshot  # noqa: E402
from app.models.servicenow_integration import ServiceNowIntegration  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services.app_attribution import ownership_for_vulns  # noqa: E402
from app.services.cmdb_sync import asset_keys, normalize_host, sync_cmdb  # noqa: E402

TABLES = [Organization, Netblock, ServiceNowIntegration, BusinessApplication, ApplicationService, CmdbCiLink,
          Asset, Vulnerability, Screenshot]


def _v(value, display=None):
    return {"value": value, "display_value": display if display is not None else value}


def _ci(prefix, sys_id, name, ip="", fqdn="", cls="cmdb_ci_linux_server"):
    return {prefix: _v(sys_id, name), f"{prefix}.name": _v(name), f"{prefix}.ip_address": _v(ip),
            f"{prefix}.fqdn": _v(fqdn), f"{prefix}.sys_class_name": _v(cls)}


CMDB = {
    "cmdb_ci_business_app": [{
        "sys_id": _v("app1"), "number": _v("APM0000001"), "name": _v("Online Store"),
        "business_criticality": _v("1", "1 - most critical"), "owned_by": _v("u1", "Pat AppOwner"),
        "business_unit": _v("bu1", "Retail"), "support_group": _v("g0", "Store App Support"),
    }],
    "cmdb_ci_service_auto": [
        {"sys_id": _v("svc1"), "number": _v("SNSVC0001"), "name": _v("Store Web PROD"),
         "sys_class_name": _v("cmdb_ci_service_discovered"), "busines_criticality": _v("2", "2 - somewhat critical"),
         "environment": _v("Production"), "owned_by": _v("u2", "Sam ServiceOwner"),
         "support_group": _v("g1", "Web Ops")},
        {"sys_id": _v("svc2"), "number": _v("SNSVC0002"), "name": _v("Store Batch"),
         "sys_class_name": _v("cmdb_ci_service_discovered")},
    ],
    # business app → (service | CI); service → CI
    "cmdb_rel_ci/app": [
        {"parent": _v("app1"), "child": _v("svc1"), "type": _v("t", "Consumes::Consumed by"),
         "child.name": _v("Store Web PROD"), "child.sys_class_name": _v("cmdb_ci_service_discovered")},
        {"parent": _v("app1"), "type": _v("t", "Runs on::Runs"), **_ci("child", "ci9", "api.acme.com")},
    ],
    "cmdb_rel_ci/svc": [
        {"parent": _v("svc2"), "type": _v("t", "Depends on::Used by"),
         **_ci("child", "ci5", "batch01", ip="203.0.113.50")},
    ],
    "svc_ci_assoc": [
        {"service_id": _v("svc1"), **_ci("ci_id", "ci1", "web01", ip="203.0.113.10", fqdn="web01.acme.com")},
    ],
    "sa_m2m_service_entry_point": [
        {"cmdb_ci_service": _v("svc1"), "entry_point": _v("ep1"), "entry_point.name": _v("https://shop.acme.com/"),
         "entry_point.sys_class_name": _v("cmdb_ci_endpoint_http")},
    ],
    "cmdb_ci_endpoint_http": [
        {"sys_id": _v("ep1"), "name": _v("https://shop.acme.com/"), "url": _v("https://shop.acme.com:443/"),
         "host": _v("shop.acme.com")},
    ],
}


def _client(data, calls, deny=()):
    def handler(request):
        table = request.url.path.rsplit("/", 1)[-1]
        calls.append(table)
        if table in deny:
            return httpx.Response(403, json={"error": "denied"})
        if table == "cmdb_rel_ci":
            q = request.url.params["sysparm_query"]
            table = "cmdb_rel_ci/app" if "cmdb_ci_business_app" in q else "cmdb_rel_ci/svc"
            if table == "cmdb_rel_ci/svc":
                assert "cmdb_ci_service_discovered" in q
        return httpx.Response(200, json={"result": data.get(table, []) if request.url.params["sysparm_offset"] == "0" else []})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture()
def Session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[t.__table__ for t in TABLES])
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Organization(id=1, name="Acme"))
    s.add(ServiceNowIntegration(organization_id=1, webhook_url="https://acme.service-now.com/api/x/notify",
                                username="svc", table_name="incident"))
    s.add(BusinessApplication(id=50, organization_id=1, source="manual", external_id="m1", name="Hand-picked"))
    for i, (value, kind) in enumerate([
        ("shop.acme.com", AssetType.SUBDOMAIN),            # entry point
        ("web01.acme.com", AssetType.SUBDOMAIN),           # service map (fqdn)
        ("203.0.113.10", AssetType.IP_ADDRESS),            # service map (ip)
        ("https://api.acme.com/v1", AssetType.URL),        # business app relationship
        ("203.0.113.50", AssetType.IP_ADDRESS),            # service relationship
        ("legacy.acme.com", AssetType.SUBDOMAIN),          # manual link, must survive
        ("gone.acme.com", AssetType.SUBDOMAIN),            # stale auto link, must clear
        ("blog.acme.com", AssetType.SUBDOMAIN),            # no match
    ], start=1):
        s.add(Asset(id=i, name=value, value=value, asset_type=kind, organization_id=1))
    s.flush()
    s.get(Asset, 6).business_app_id = 50  # pre-existing hand-made link (app_link_source NULL)
    s.get(Asset, 7).app_link_source = "service_map"
    s.add(Vulnerability(id=100, title="XSS", severity=Severity.HIGH, asset_id=1, metadata_={}))
    s.add(Vulnerability(id=101, title="TLS", severity=Severity.LOW, asset_id=8, metadata_={}))
    s.commit()
    s.close()
    return Session


def test_normalization():
    assert normalize_host("https://Shop.Acme.com:443/x") == "shop.acme.com"
    assert normalize_host("web01.acme.com.") == "web01.acme.com"
    assert normalize_host("web01") is None and normalize_host("10.0.0.1") is None
    assert asset_keys("10.0.0.1:8443") == (None, "10.0.0.1")
    assert asset_keys("https://api.acme.com/v1") == ("api.acme.com", None)


def test_sync_attributes_assets(Session):
    db = Session()
    calls = []
    result = asyncio.run(sync_cmdb(db, 1, client=_client(CMDB, calls)))
    db.commit()
    assert result["business_apps"] == 1 and result["application_services"] == 2
    assert result["warnings"] == []
    assert result["entry_point_links"] == 1 and result["service_map_links"] == 1
    assert result["relationship_links"] == 2

    svc1 = db.query(ApplicationService).filter_by(external_id="svc1").one()
    app1 = db.query(BusinessApplication).filter_by(external_id="app1").one()
    assert svc1.business_app_id == app1.id and svc1.criticality_level == 2
    assert app1.business_unit == "Retail" and app1.support_group == "Store App Support"
    svc2 = db.query(ApplicationService).filter_by(external_id="svc2").one()
    assert svc2.business_app_id is None

    a = {x.id: x for x in db.query(Asset)}
    assert (a[1].app_service_id, a[1].business_app_id, a[1].app_link_source) == (svc1.id, app1.id, "entry_point")
    assert "shop.acme.com" in a[1].app_link_detail
    assert (a[2].app_service_id, a[2].app_link_source) == (svc1.id, "service_map")
    assert (a[3].app_service_id, a[3].app_link_source) == (svc1.id, "service_map")
    assert (a[4].app_service_id, a[4].business_app_id, a[4].app_link_source) == (None, app1.id, "relationship")
    assert (a[5].app_service_id, a[5].business_app_id) == (svc2.id, None)
    assert (a[6].business_app_id, a[6].app_service_id, a[6].app_link_source) == (50, None, None)
    assert (a[7].app_service_id, a[7].app_link_source) == (None, None)
    assert a[8].app_service_id is None and a[8].business_app_id is None

    # Findings inherit; owner/support from the service, business unit falls back to the app.
    vulns = db.query(Vulnerability).order_by(Vulnerability.id).all()
    own = ownership_for_vulns(db, vulns)
    assert own[101] is None
    o = own[100]
    assert (o["business_app_number"], o["app_service_number"]) == ("APM0000001", "SNSVC0001")
    assert (o["owner"], o["support_group"], o["business_unit"]) == ("Sam ServiceOwner", "Web Ops", "Retail")
    assert o["criticality_level"] == 1 and o["link_source"] == "entry_point" and o["inherited_from_asset"]

    # A finding linked by hand to another app does not take the asset's service.
    vulns[0].business_app_id = 50
    o = ownership_for_vulns(db, [vulns[0]])[100]
    assert (o["business_app_name"], o["app_service_id"], o["link_source"]) == ("Hand-picked", None, "manual")
    db.close()


def test_optional_table_denied_keeps_going(Session):
    db = Session()
    db.add(CmdbCiLink(organization_id=1, relation="service_map", fqdn="old.acme.com"))
    db.commit()
    result = asyncio.run(sync_cmdb(db, 1, client=_client(CMDB, [], deny={"svc_ci_assoc"})))
    db.commit()
    assert any("svc_ci_assoc" in w for w in result["warnings"])
    assert "service_map_links" not in result
    # Links of the table we could not read are kept as they were.
    assert db.query(CmdbCiLink).filter_by(relation="service_map").one().fqdn == "old.acme.com"
    assert db.get(Asset, 1).app_link_source == "entry_point"
    db.close()


def test_business_apps_table_required(Session):
    with pytest.raises(PermissionError):
        asyncio.run(sync_cmdb(Session(), 1, client=_client(CMDB, [], deny={"cmdb_ci_business_app"})))


@pytest.fixture()
def api(Session, monkeypatch):
    from app.api import deps
    from app.api.routes import assets as assets_routes, business_apps, vulnerabilities
    from app.db.database import get_db
    from app.models.user import User

    db = Session()
    asyncio.run(sync_cmdb(db, 1, client=_client(CMDB, [])))
    db.commit()
    db.close()

    app = FastAPI()
    app.include_router(business_apps.router)
    app.include_router(vulnerabilities.router)
    app.include_router(assets_routes.router, prefix="/assets")

    def db_override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    analyst = User(id=1, email="a@acme.com", username="a", hashed_password="x", organization_id=1, is_superuser=False)
    app.dependency_overrides[get_db] = db_override
    for dep in (deps.get_current_active_user, deps.require_analyst, deps.require_admin):
        app.dependency_overrides[dep] = lambda: analyst
    return TestClient(app)


def test_attribution_api(api):
    rows = api.get("/business-apps/attribution", params={"group_by": "business_unit"}).json()
    retail = next(r for r in rows if r["business_unit"] == "Retail")
    assert retail["open_findings"] == 1 and retail["high"] == 1 and retail["assets"] == 4
    unattributed = next(r for r in rows if r["business_unit"] is None)
    assert unattributed["open_findings"] == 1 and unattributed["low"] == 1

    owners = api.get("/business-apps/attribution", params={"group_by": "owner"}).json()
    assert {"Sam ServiceOwner", "Pat AppOwner"} <= {r["owner"] for r in owners}

    svcs = api.get("/business-apps/services", params={"q": "PROD"}).json()
    assert [s["number"] for s in svcs] == ["SNSVC0001"]

    # Manual link to a service pulls in its business app and survives re-attribution.
    res = api.put("/business-apps/assets/8", json={"app_service_id": svcs[0]["id"]}).json()
    assert res["ownership"]["business_app_number"] == "APM0000001" and res["ownership"]["link_source"] == "manual"
    api.post("/business-apps/attribute")
    vuln = api.get("/vulnerabilities/101").json()
    assert vuln["ownership"]["app_service_name"] == "Store Web PROD"
    assert vuln["ownership"]["owner"] == "Sam ServiceOwner"

    # Clearing hands the asset back to automatic attribution (no match → unattributed).
    res = api.put("/business-apps/assets/8", json={}).json()
    assert res["ownership"] is None

    listed = api.get("/vulnerabilities/", params={"app_service_id": svcs[0]["id"]}).json()
    items = listed["items"] if isinstance(listed, dict) else listed
    assert [v["id"] for v in items] == [100]
    assert items[0]["ownership"]["business_unit"] == "Retail"
