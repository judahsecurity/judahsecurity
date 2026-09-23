"""Severity evaluation end to end against a database: columns, triage, business app."""

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.business_application import BusinessApplication  # noqa: E402
from app.models.netblock import Netblock  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability  # noqa: E402
from app.services.risk_model import apply_overrides  # noqa: E402
from app.services.severity_evaluation import apply_effective, evaluate_finding  # noqa: E402


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    tables = [Organization.__table__, Netblock.__table__, BusinessApplication.__table__,
              Asset.__table__, Vulnerability.__table__]
    Base.metadata.create_all(engine, tables=tables)
    s = sessionmaker(bind=engine)()
    s.add(Organization(id=1, name="Acme"))
    s.add(Netblock(organization_id=1, inetnum="145.97.0.0 - 145.97.255.255", start_ip="145.97.0.0",
                   end_ip="145.97.255.255", cidr_notation="145.97.0.0/16", is_owned=True, in_scope=True))
    s.commit()
    yield s
    s.close()


def _finding(db, **kw):
    asset = Asset(name="portal.acme.com", value="portal.acme.com", asset_type=AssetType.DOMAIN,
                  organization_id=1, ip_address="145.97.10.10", is_public=True)
    db.add(asset)
    db.flush()
    v = Vulnerability(title="Exposed admin panel", severity=Severity.HIGH, asset_id=asset.id,
                      detected_by="nuclei", template_id="exposed-panels/admin", metadata_={}, **kw)
    db.add(v)
    db.commit()
    return v, asset


def test_evaluation_fills_columns_and_flags_triage(db):
    v, _ = _finding(db)
    view = evaluate_finding(db, v)
    db.commit()
    assert v.sev_network_location == 4
    assert view["factors"]["network_location"]["rating"] == "Acme Hosted"
    assert v.sev_vulnerability_severity == 3
    assert v.sev_status == "needs_analyst"
    assert v.sev_pending == len(view["needs_analyst"]) > 0
    assert "business_impact" in view["needs_analyst"]  # no criticality, no business app
    assert v.sev_level and v.sev_score is not None


def test_analyst_triage_completes_and_updates_columns(db):
    v, _ = _finding(db)
    view = evaluate_finding(db, v)
    meta = dict(v.metadata_)
    meta["risk_overrides"] = apply_overrides(
        {}, {k: {"score": 2, "note": "checked"} for k in view["needs_analyst"]}, None, analyst="a@acme.com")
    v.metadata_ = meta
    view = apply_effective(db, v)
    db.commit()
    assert v.sev_status == "triaged" and v.sev_pending == 0
    assert v.sev_business_impact == 2


def test_business_app_link_sets_business_impact(db):
    app = BusinessApplication(organization_id=1, source="servicenow", external_id="abc123",
                              app_id="APM0001234", name="Payments", business_criticality="1 - most critical",
                              criticality_level=1)
    db.add(app)
    db.commit()
    v, asset = _finding(db)
    asset.business_app_id = app.id  # inherited by every finding on the asset
    db.commit()
    evaluate_finding(db, v)
    db.commit()
    assert v.sev_business_impact == 4
    reason = v.metadata_["severity_eval"]["factors"]["business_impact"]["reason"]
    assert "Payments" in reason and "ServiceNow" in reason
