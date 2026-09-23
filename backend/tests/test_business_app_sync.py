"""ServiceNow business application sync (mocked Table API)."""

import asyncio

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.business_application import BusinessApplication  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.servicenow_integration import ServiceNowIntegration  # noqa: E402
from app.services import business_app_sync  # noqa: E402
from app.services.business_app_sync import criticality_level, sync_business_apps  # noqa: E402


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[Organization.__table__, ServiceNowIntegration.__table__,
                                             BusinessApplication.__table__])
    s = sessionmaker(bind=engine)()
    s.add(Organization(id=1, name="Acme"))
    s.add(ServiceNowIntegration(organization_id=1, webhook_url="https://acme.service-now.com/api/x/notify",
                                username="svc", table_name="incident"))
    s.commit()
    yield s
    s.close()


def _rec(n, crit="1 - most critical"):
    return {
        "sys_id": {"value": f"sys{n}", "display_value": f"sys{n}"},
        "number": {"value": f"APM{n:07d}", "display_value": f"APM{n:07d}"},
        "name": {"value": f"App {n}", "display_value": f"App {n}"},
        "business_criticality": {"value": crit[0], "display_value": crit},
        "owned_by": {"value": "u1", "display_value": "Pat Owner"},
    }


def _client(pages, calls, status=200):
    def handler(request):
        calls.append(dict(request.url.params))
        if status != 200:
            return httpx.Response(status, json={"error": "denied"})
        offset = int(request.url.params["sysparm_offset"])
        return httpx.Response(200, json={"result": pages.get(offset, [])})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_criticality_level():
    assert criticality_level("1 - most critical") == 1
    assert criticality_level("4") == 4
    assert criticality_level("") is None


def test_sync_pages_and_upserts(db, monkeypatch):
    monkeypatch.setattr(business_app_sync, "PAGE_SIZE", 2)
    calls = []
    pages = {0: [_rec(1), _rec(2, "3 - less critical")], 2: [_rec(3)]}
    result = asyncio.run(sync_business_apps(db, 1, client=_client(pages, calls)))
    db.commit()
    assert result["synced"] == 3
    assert [c["sysparm_offset"] for c in calls] == ["0", "2"]
    app = db.query(BusinessApplication).filter_by(app_id="APM0000002").one()
    assert (app.name, app.criticality_level, app.owner) == ("App 2", 3, "Pat Owner")
    assert app.external_url.startswith("https://acme.service-now.com/nav_to.do?uri=cmdb_ci_business_app.do")

    # Re-sync updates in place instead of duplicating.
    pages = {0: [_rec(1, "2 - somewhat critical")]}
    asyncio.run(sync_business_apps(db, 1, client=_client(pages, [])))
    db.commit()
    assert db.query(BusinessApplication).count() == 3
    assert db.query(BusinessApplication).filter_by(external_id="sys1").one().criticality_level == 2


def test_sync_reports_missing_table_access(db):
    with pytest.raises(PermissionError):
        asyncio.run(sync_business_apps(db, 1, client=_client({}, [], status=403)))
