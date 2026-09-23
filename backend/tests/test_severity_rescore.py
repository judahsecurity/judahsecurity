"""Scores re-run when their inputs change (dirty tracking + severity worker)."""

import pytest

pytest.importorskip("sqlalchemy")

from datetime import datetime, timedelta  # noqa: E402

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401  (registers dirty tracking)
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.business_application import BusinessApplication  # noqa: E402
from app.models.netblock import Netblock  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import severity_intel  # noqa: E402
from app.services import severity_agent  # noqa: E402
from app.services.severity_evaluation import run_dirty_batch  # noqa: E402
from app.services.severity_intel import mark_intel_changes  # noqa: E402
from app.workers.severity_worker import full_sweep, tick  # noqa: E402

INTEL = {}


@pytest.fixture()
def Session(monkeypatch):
    monkeypatch.setattr(severity_intel, "live_intel", lambda cve: dict(INTEL.get(cve, {})))
    INTEL.clear()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[Organization.__table__, Netblock.__table__,
                                             BusinessApplication.__table__, Asset.__table__, Vulnerability.__table__])
    factory = sessionmaker(bind=engine)
    s = factory()
    s.add(Organization(id=1, name="Acme"))
    # Asset on an IP outside Acme's (single) netblock → third-party hosted.
    s.add(Netblock(id=1, organization_id=1, inetnum="145.97.0.0 - 145.97.0.255", start_ip="145.97.0.0",
                   end_ip="145.97.0.255", cidr_notation="145.97.0.0/24", is_owned=True, in_scope=True))
    s.add(Asset(id=10, name="app.acme.com", value="app.acme.com", asset_type=AssetType.DOMAIN,
                organization_id=1, ip_address="145.97.10.10", is_public=True, criticality="high"))
    s.add(Vulnerability(id=100, title="Struts RCE", severity=Severity.HIGH, asset_id=10, cve_id="CVE-2099-1000",
                        cvss_score=7.5, detected_by="nuclei", template_id="cves/CVE-2099-1000", metadata_={}))
    s.commit()
    s.close()
    return factory


def _get(Session):
    s = Session()
    v = s.query(Vulnerability).get(100)
    s.expunge(v)
    s.close()
    return v


def _drain(Session):
    return run_dirty_batch(Session)


def test_new_findings_start_dirty_and_get_scored(Session):
    assert _get(Session).sev_dirty is True
    assert _drain(Session) == {"selected": 1, "evaluated": 1, "failed": 0}
    v = _get(Session)
    assert v.sev_dirty is False and v.sev_score is not None
    assert _drain(Session)["selected"] == 0  # evaluation doesn't re-dirty itself


def test_third_party_to_org_hosted_rescores(Session):
    _drain(Session)
    before = _get(Session)
    assert before.sev_network_location == 2  # outside Acme's netblock

    # Someone adds the range to Acme's IP inventory: it's on-prem after all.
    s = Session()
    s.query(Netblock).get(1).cidr_notation = "145.97.0.0/16"
    s.commit()
    s.close()
    assert _get(Session).sev_dirty is True
    _drain(Session)
    after = _get(Session)
    assert after.sev_network_location == 4 and after.sev_score > before.sev_score


def test_cvss_change_rescores(Session):
    _drain(Session)
    before = _get(Session)
    s = Session()
    s.query(Vulnerability).get(100).cvss_score = 9.8
    s.commit()
    s.close()
    assert _get(Session).sev_dirty is True
    _drain(Session)
    after = _get(Session)
    assert (before.sev_vulnerability_severity, after.sev_vulnerability_severity) == (3, 4)


def test_new_exploitation_rescores(Session):
    _drain(Session)
    before = _get(Session)
    # Intel refresh: the CVE lands on CISA KEV and a weaponized exploit appears.
    INTEL["CVE-2099-1000"] = {"in_kev_sources": ["cisa_kev"], "vulncheck_weaponized": True}
    assert mark_intel_changes(Session)["marked"] == 1
    assert mark_intel_changes(Session)["marked"] == 1  # still dirty until scored
    _drain(Session)
    after = _get(Session)
    assert after.sev_score > before.sev_score
    assert after.metadata_["severity_eval"]["factors"]["awareness"]["reason"].startswith("Listed in CISA KEV")
    assert mark_intel_changes(Session)["marked"] == 0  # nothing new since


def test_business_app_criticality_change_rescores(Session):
    s = Session()
    s.add(BusinessApplication(id=5, organization_id=1, source="servicenow", external_id="x", name="Portal",
                              criticality_level=4))
    s.query(Asset).get(10).business_app_id = 5
    s.commit()
    s.close()
    _drain(Session)
    assert _get(Session).sev_business_impact == 1
    s = Session()
    s.query(BusinessApplication).get(5).criticality_level = 1  # re-synced from ServiceNow
    s.commit()
    s.close()
    assert _get(Session).sev_dirty is True
    _drain(Session)
    assert _get(Session).sev_business_impact == 4


def test_change_during_evaluation_is_not_lost(Session):
    from app.services.severity_dirty import clear_dirty

    started = datetime.utcnow() - timedelta(seconds=5)
    s = Session()
    v = s.query(Vulnerability).get(100)
    v.sev_dirty_at = datetime.utcnow()  # changed after the evaluation started
    s.commit()
    clear_dirty(s, [100], started)
    s.commit()
    s.close()
    assert _get(Session).sev_dirty is True


def test_closed_findings_are_backfilled_and_worker_sweeps(Session):
    s = Session()
    s.query(Vulnerability).get(100).status = VulnerabilityStatus.RESOLVED
    s.commit()
    s.close()
    assert tick(Session)["evaluated"] == 1
    assert _get(Session).sev_score is not None
    s = Session()
    s.query(Vulnerability).get(100).status = VulnerabilityStatus.OPEN  # reopened
    s.commit()
    s.close()
    assert tick(Session)["evaluated"] == 1
    assert full_sweep(Session) == 1 and _get(Session).sev_dirty is True


def test_first_run_scores_open_and_resolved_findings(Session):
    s = Session()
    s.add(Vulnerability(id=101, title="Resolved issue", severity=Severity.LOW, asset_id=10,
                        status=VulnerabilityStatus.RESOLVED, detected_by="nuclei", metadata_={}))
    s.commit()
    s.close()

    assert tick(Session) == {"selected": 2, "evaluated": 2, "failed": 0}
    s = Session()
    rows = s.query(Vulnerability).filter(Vulnerability.id.in_([100, 101])).all()
    assert all(v.sev_score is not None and v.sev_dirty is False for v in rows)
    s.close()
    assert full_sweep(Session) == 2


def test_auto_agent_reads_state_before_session_close(Session, monkeypatch):
    submitted = []
    monkeypatch.setattr(severity_agent, "auto_enabled", lambda: True)
    monkeypatch.setattr(severity_agent, "submit", lambda vuln_id: submitted.append(vuln_id))

    result = _drain(Session)
    assert result == {"selected": 1, "evaluated": 1, "failed": 0}
    assert _get(Session).sev_dirty is False
    assert submitted == [100]
