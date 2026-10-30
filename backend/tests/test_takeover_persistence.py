"""Takeover findings keep analyst triage and record verdict-based confidence."""

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.scan import Scan  # noqa: E402
from app.models.vulnerability import Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import takeover_scanner_service as takeover  # noqa: E402
from app.services import reactivation_service  # noqa: E402


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, Scan.__table__, Vulnerability.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Org"))
    session.commit()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def no_jira(monkeypatch):
    reopened = []
    monkeypatch.setattr(reactivation_service, "trigger_jira_reopen_background",
                        lambda vuln_id, old: reopened.append((vuln_id, old)))
    return reopened


def _result(verdict: str, confidence: int) -> takeover.TakeoverScanResult:
    return takeover.TakeoverScanResult(findings=[takeover.TakeoverFinding(
        hostname="shop.example.test", provider="GitHub Pages", verdict=verdict,
        confidence=confidence, methods=["cname"], cname_chain=["x.github.io"],
        http_signature="There isn't a GitHub Pages site here.",
    )])


def test_confirmed_verdict_sets_endpoint_confirmed(db):
    takeover.persist_takeover_findings(db, 1, None, _result("confirmed", 80))
    assert db.query(Vulnerability).one().detection_confidence == "endpoint_confirmed"


def test_likely_verdict_stays_version_only(db):
    takeover.persist_takeover_findings(db, 1, None, _result("likely", 65))
    assert db.query(Vulnerability).one().detection_confidence == "version_only"


def test_rescan_keeps_in_progress_status(db, no_jira):
    takeover.persist_takeover_findings(db, 1, None, _result("likely", 65))
    vuln = db.query(Vulnerability).one()
    vuln.status = VulnerabilityStatus.IN_PROGRESS
    db.commit()

    summary = takeover.persist_takeover_findings(db, 1, None, _result("confirmed", 80))

    db.refresh(vuln)
    assert vuln.status == VulnerabilityStatus.IN_PROGRESS
    assert vuln.detection_confidence == "endpoint_confirmed"
    assert summary["reactivated"] == 0
    assert no_jira == []


def test_rescan_reactivates_resolved_finding(db, no_jira):
    takeover.persist_takeover_findings(db, 1, None, _result("likely", 65))
    vuln = db.query(Vulnerability).one()
    vuln.status = VulnerabilityStatus.RESOLVED
    db.commit()

    summary = takeover.persist_takeover_findings(db, 1, None, _result("likely", 65))

    db.refresh(vuln)
    assert vuln.status == VulnerabilityStatus.OPEN
    assert vuln.resolved_at is None
    assert summary["reactivated"] == 1
    assert no_jira == [(vuln.id, "resolved")]
