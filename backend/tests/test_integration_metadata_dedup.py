"""HackerOne / Censys ASM imports de-duplicate on the provider id stored in
``Vulnerability.metadata_``.

``metadata_`` is a generic ``sqlalchemy.JSON`` column, so the lookup must use
the portable ``.as_string()`` accessor. The Postgres-only ``.astext`` raised
``AttributeError`` while the query was being built, which aborted every sync
that imported a report or risk with an id.
"""

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.dialects import postgresql  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.hackerone_integration import HackerOneIntegration, HackerOneReportLink  # noqa: E402
from app.models.netblock import Netblock  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.business_application import BusinessApplication  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402
from app.services import censys_asm_service, hackerone_service  # noqa: E402


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Netblock.__table__, BusinessApplication.__table__, Asset.__table__,
        Vulnerability.__table__, HackerOneIntegration.__table__, HackerOneReportLink.__table__,
    ])
    s = sessionmaker(bind=engine)()
    s.add(Organization(id=1, name="Acme"))
    s.add(Asset(id=10, name="app.acme.com", value="app.acme.com", asset_type=AssetType.DOMAIN,
                organization_id=1))
    s.commit()
    yield s
    s.close()


@pytest.mark.parametrize("key", ["hackerone_report_id", "censys_risk_id"])
def test_metadata_lookup_compiles_on_postgres(key):
    sql = str((Vulnerability.metadata_[key].as_string() == "42").compile(dialect=postgresql.dialect()))
    assert "->>" in sql


def _h1_report(title):
    return {"id": "4242", "attributes": {"title": title, "state": "triaged"}}


def test_hackerone_reimport_updates_existing_by_report_id(db):
    integration = HackerOneIntegration(id=1, organization_id=1, connection_name="h1",
                                       api_identifier="x", api_token_encrypted="x")
    db.add(integration)
    db.commit()
    asset_index = {"app.acme.com": db.get(Asset, 10)}

    for title in ("XSS on login", "Stored XSS on login (retitled)"):
        stats = hackerone_service._Stats()
        hackerone_service._import_report(
            db, 1, _h1_report(title), {}, "acme", asset_index, stats,
            can_create_assets=True, integration=integration,
        )
        db.commit()

    # Second pass changed the title, so only the metadata id can match it.
    vulns = db.query(Vulnerability).all()
    assert len(vulns) == 1
    assert vulns[0].metadata_["hackerone_report_id"] == "4242"
    assert stats.vulns_created == 0 and stats.vulns_updated == 1


def test_censys_reimport_updates_existing_by_risk_id(db):
    asset_index = {"app.acme.com": db.get(Asset, 10)}

    for title in ("Exposed admin panel", "Exposed admin panel (renamed)"):
        stats = censys_asm_service._Stats()
        risk = {"id": "risk-7", "title": title, "severity": "high",
                "affectedAssets": [{"id": "app.acme.com", "type": "DOMAIN"}]}
        censys_asm_service._import_risk(db, 1, risk, asset_index, stats, can_create_assets=False)
        db.commit()

    vulns = db.query(Vulnerability).all()
    assert len(vulns) == 1
    assert vulns[0].metadata_["censys_risk_id"] == "risk-7"
    assert stats.vulns_created == 0 and stats.vulns_updated == 1
