"""Org-scoped CVE impact for the threat-intel incident page."""

import importlib
import pkgutil

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models

for _m in pkgutil.iter_modules(app.models.__path__):  # resolve FK metadata
    importlib.import_module(f"app.models.{_m.name}")

from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services.cve_impact import build_cve_impact  # noqa: E402

CVE = "CVE-2026-1107"


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for model in (Organization, Asset, Vulnerability):
        model.__table__.create(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _asset(db, org, name, public=True, live=True):
    a = Asset(name=name, value=name, asset_type=AssetType.DOMAIN, organization_id=org.id,
              is_public=public, is_live=live)
    db.add(a)
    db.flush()
    return a


def _vuln(db, asset, cve=CVE, status=VulnerabilityStatus.OPEN, level=None, verdict=None, chain=False, sid=None):
    det = {"chain": [{"tool": "curl"}] if chain else []}
    if sid:
        det["session_id"] = sid
    db.add(Vulnerability(title=f"{cve} on {asset.value}", cve_id=cve, severity=Severity.CRITICAL,
                         asset_id=asset.id, status=status, verification_level=level,
                         last_validation_verdict=verdict, detected_by="nuclei",
                         metadata_={"agent_detection": det}))


def test_impact_counts_exposure_validation_and_scoping(db):
    org, other = Organization(name="A"), Organization(name="B")
    db.add_all([org, other])
    db.flush()
    gw = _asset(db, org, "llm-gw.acme.io")
    internal = _asset(db, org, "eval.internal", public=False)
    old = _asset(db, org, "old.acme.io")
    foreign = _asset(db, other, "x.other.io")

    _vuln(db, gw, level="exploit_verified", chain=True, sid="sess-9")
    _vuln(db, gw, cve=CVE.lower())
    _vuln(db, internal, chain=True, sid="sess-9")
    _vuln(db, old, status=VulnerabilityStatus.RESOLVED)
    _vuln(db, old, status=VulnerabilityStatus.FALSE_POSITIVE, level="exploit_verified")
    _vuln(db, foreign, level="exploit_verified")
    _vuln(db, gw, cve="CVE-2025-0001")
    db.commit()

    r = build_cve_impact(db, org.id, CVE.lower())
    assert r["cve_id"] == CVE
    assert r["counts"] == {"affected": 2, "exposed": 1, "exploit_verified": 1, "demonstrated": 1, "resolved": 1}
    assert [a["asset"] for a in r["assets"]] == ["llm-gw.acme.io", "eval.internal", "old.acme.io"]
    top = r["assets"][0]
    assert top["exposure"] == "internet_exposed" and top["validation"] == "exploit_verified"
    assert len(top["finding_ids"]) == 2
    # The false positive's "exploit_verified" must not leak into the resolved asset.
    assert r["assets"][2]["validation"] == "detected" and r["assets"][2]["open"] is False
    assert r["sessions"] == [{"session_id": "sess-9", "finding_ids": [3, 1], "validation": "exploit_verified"}]


def test_unaffected_org_gets_empty_result(db):
    org = Organization(name="A")
    db.add(org)
    db.commit()
    r = build_cve_impact(db, org.id, CVE)
    assert r["assets"] == [] and r["counts"]["affected"] == 0
