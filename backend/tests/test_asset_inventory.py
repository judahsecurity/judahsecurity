"""Asset spreadsheet import/export, bulk edit and saved views."""

import io
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from openpyxl import Workbook, load_workbook
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.asset import Asset, AssetType
from app.services import asset_inventory
from app.services.asset_inventory import detect_type, import_assets, read_rows


@pytest.fixture
def maker(monkeypatch):
    from app.models.organization import Organization
    from app.models.platform_audit import PlatformAuditLog
    from app.models.saved_view import SavedView
    from app.models.user import User

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    from app.models.org_role import OrgRole

    for table in (Organization.__table__, OrgRole.__table__, User.__table__, Asset.__table__,
                  SavedView.__table__, PlatformAuditLog.__table__):
        table.create(engine)
    factory = sessionmaker(bind=engine)
    import app.db.database as database

    monkeypatch.setattr(database, "SessionLocal", factory)
    with factory() as db:
        db.add_all([Organization(id=1, name="Acme"), Organization(id=2, name="Other")])
        db.add(Asset(organization_id=1, asset_type=AssetType.DOMAIN, value="acme.test", name="acme.test",
                     tags=["prod"], criticality="medium"))
        db.add(Asset(organization_id=2, asset_type=AssetType.DOMAIN, value="other.test", name="other.test"))
        db.commit()
    return factory


@pytest.mark.parametrize("value, kind", [
    ("acme.test", AssetType.DOMAIN), ("app.acme.test", AssetType.SUBDOMAIN),
    ("10.0.0.1", AssetType.IP_ADDRESS), ("10.0.0.0/24", AssetType.IP_RANGE),
    ("https://acme.test/login", AssetType.URL), ("not a host", None),
])
def test_detect_type(value, kind):
    assert detect_type(value) == kind


def test_import_validates_dedupes_and_respects_mode(maker):
    csv_text = (
        "value,asset_type,name,tags,criticality,in_scope\n"
        "acme.test,,Main site,prod;web,high,true\n"
        "api.acme.test,,API,api,critical,\n"
        "api.acme.test,,dup,,,\n"
        "=cmd|' /C calc'!A0,,,,,\n"
        "198.51.100.7,,,,,maybe\n"
        "bad host,,,,,\n"
    )
    records = read_rows("assets.csv", csv_text.encode())
    with maker() as db:
        dry = import_assets(db, 1, records, dry_run=True)
        assert (dry["created"], dry["skipped"], dry["invalid"]) == (1, 2, 3)
        assert db.query(Asset).filter_by(organization_id=1).count() == 1
        result = import_assets(db, 1, records, mode="update")
        assert (result["created"], result["updated"], result["invalid"]) == (1, 1, 3)
        assert {e["line"] for e in result["errors"]} == {5, 6, 7}
        main = db.query(Asset).filter_by(organization_id=1, value="acme.test").one()
        assert (main.name, main.criticality, sorted(main.tags)) == ("Main site", "high", ["prod", "web"])
        api = db.query(Asset).filter_by(value="api.acme.test").one()
        assert api.asset_type == AssetType.SUBDOMAIN and api.discovery_source == "import"


def test_xlsx_round_trip_and_formula_guard(maker):
    with maker() as db:
        db.add(Asset(organization_id=1, asset_type=AssetType.DOMAIN, value="evil.test",
                     name="=HYPERLINK(\"http://x\")"))
        db.commit()
        assets = db.query(Asset).filter_by(organization_id=1).order_by(Asset.value).all()
        sheet = load_workbook(io.BytesIO(asset_inventory.export_xlsx(assets))).active
        rows = list(sheet.iter_rows(values_only=True))
        assert rows[0][:2] == ("value", "asset_type")
        assert rows[2][2].startswith("'=")
        csv_bytes = asset_inventory.export_csv(assets)
        assert csv_bytes.startswith(b"\xef\xbb\xbf") and b"'=HYPERLINK" in csv_bytes

    workbook = Workbook()
    workbook.active.append(["Value", "Criticality"])
    workbook.active.append(["new.acme.test", "low"])
    buffer = io.BytesIO()
    workbook.save(buffer)
    assert read_rows("x.xlsx", buffer.getvalue()) == [{"value": "new.acme.test", "criticality": "low"}]
    with pytest.raises(asset_inventory.ImportError_, match="value"):
        read_rows("x.csv", b"host\nacme.test\n")
    with pytest.raises(asset_inventory.ImportError_, match=".csv or .xlsx"):
        read_rows("x.txt", b"value\n")


@pytest.fixture
def client(maker):
    from app.api.deps import get_current_active_user, require_analyst
    from app.api.routes import asset_inventory as routes
    from app.db.database import get_db
    from app.models.user import UserRole

    app = FastAPI()
    app.include_router(routes.router)

    def db():
        session = maker()
        try:
            yield session
        finally:
            session.close()

    state = {"user": SimpleNamespace(id=5, organization_id=1, is_superuser=False,
                                     role=UserRole.ANALYST, email="a@acme.test")}
    app.dependency_overrides[get_db] = db
    app.dependency_overrides[get_current_active_user] = lambda: state["user"]
    app.dependency_overrides[require_analyst] = lambda: state["user"]
    c = TestClient(app)
    c.state = state
    return c


def test_routes_import_export_bulk(client, maker):
    upload = client.post("/asset-inventory/import",
                         files={"file": ("a.csv", b"value\nnew.acme.test\n", "text/csv")})
    assert upload.status_code == 200 and upload.json()["created"] == 1
    assert client.post("/asset-inventory/import", data={"organization_id": "2"},
                       files={"file": ("a.csv", b"value\nx.test\n", "text/csv")}).status_code == 403
    export = client.get("/asset-inventory/export", params={"format": "csv"})
    assert export.status_code == 200
    assert b"new.acme.test" in export.content and b"other.test" not in export.content
    with maker() as db:
        ids = [a.id for a in db.query(Asset).all()]
    bulk = client.post("/asset-inventory/bulk-update", json={
        "asset_ids": ids, "changes": {"criticality": "critical", "add_tags": ["q4"], "remove_tags": ["prod"]}})
    assert bulk.json() == {"updated": 2}  # other org's asset untouched
    with maker() as db:
        acme = db.query(Asset).filter_by(value="acme.test").one()
        other = db.query(Asset).filter_by(value="other.test").one()
        assert acme.criticality == "critical" and acme.tags == ["q4"]
        assert other.criticality != "critical"
    assert client.post("/asset-inventory/bulk-update", json={"asset_ids": ids, "changes": {}}).status_code == 422


def test_saved_views(client):
    from app.models.user import UserRole

    mine = client.post("/saved-views", json={"page": "assets", "name": "Live prod",
                                             "filters": {"is_live": True, "tag": "prod"}}).json()
    shared = client.post("/saved-views", json={"page": "assets", "name": "Team", "filters": {},
                                               "shared": True}).json()
    client.state["user"] = SimpleNamespace(id=6, organization_id=1, is_superuser=False,
                                           role=UserRole.ANALYST, email="b@acme.test")
    names = [v["name"] for v in client.get("/saved-views", params={"page": "assets"}).json()]
    assert names == ["Team"]
    assert client.delete(f"/saved-views/{shared['id']}").status_code == 403
    client.state["user"] = SimpleNamespace(id=7, organization_id=1, is_superuser=False,
                                           role=UserRole.ADMIN, email="c@acme.test")
    assert client.delete(f"/saved-views/{mine['id']}").status_code == 403  # private, not shared
    assert client.delete(f"/saved-views/{shared['id']}").status_code == 204
    assert client.post("/saved-views", json={"page": "assets", "name": "x",
                                             "filters": {"q": "a" * 5000}}).status_code == 422
