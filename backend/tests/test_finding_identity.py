"""Cross-source finding identity: one canonical finding, one observation per source."""

from datetime import datetime

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.finding_observation import FindingObservation  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.port_service import PortService  # noqa: E402
from app.models.tenable_integration import TenableVmIntegration  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import finding_identity as fi  # noqa: E402
from app.services import wiz_service  # noqa: E402
from app.services.finding_deduplication_service import FindingDeduplicationService  # noqa: E402

import test_tenable_vm_service as tenable_tests  # noqa: E402


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, TenableVmIntegration.__table__, Asset.__table__,
        PortService.__table__, Vulnerability.__table__, FindingObservation.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.add(TenableVmIntegration(
        id=1, organization_id=1, connection_name="Tenable VM", base_url="https://cloud.tenable.com",
        access_key_encrypted="x", secret_key_encrypted="x",
    ))
    session.commit()
    yield session
    session.close()


def _asset(db, value="www.acme.com", asset_type=AssetType.SUBDOMAIN, **kw):
    asset = Asset(organization_id=1, value=value, name=value, asset_type=asset_type, **kw)
    db.add(asset)
    db.commit()
    return asset


TENABLE_APACHE = {
    "asset": {"uuid": "u-web", "fqdn": "www.acme.com", "ipv4": "93.184.216.34"},
    "plugin": {
        "id": 142960, "name": "Apache 2.4.x < 2.4.50 Multiple Vulnerabilities",
        "cve": ["cve-2021-42013", "CVE-2021-41773"], "cvss3_base_score": 9.8,
    },
    "port": {"port": 443, "protocol": "TCP", "service": "www"},
    "severity": "critical", "state": "OPEN", "last_found": "2026-11-01T00:00:00Z",
}

WIZ_APACHE = {
    "id": "wiz-f-1", "name": "CVE-2021-41773", "detailedName": "apache httpd CVE-2021-41773",
    "severity": "HIGH", "status": "OPEN", "lastDetectedAt": "2026-11-02T00:00:00Z",
}


def _tenable_sync(db, vulns=(), fixed=()):
    fake = tenable_tests.FakeTenable(assets=tenable_tests.ASSETS[:1], vulns=list(vulns), fixed=list(fixed))
    return tenable_tests._sync(db, fake)


def _wiz(db, asset, finding):
    stats = wiz_service._Stats()
    wiz_service._upsert_vulnerability(db, asset, finding, stats)
    db.commit()
    return stats


# ── pure helpers ────────────────────────────────────────────────────────────


def test_normalize_cves_dedupes_and_uppercases():
    assert fi.normalize_cves(["cve-2021-41773", "CVE-2021-41773 and CVE-2020-0001", None]) == [
        "CVE-2020-0001", "CVE-2021-41773",
    ]


def test_dedup_key_prefers_cve_over_source_rule():
    assert fi.make_dedup_key(["CVE-2021-41773"], "tenable", "plugin:1") == "cve:CVE-2021-41773"
    assert fi.make_dedup_key([], "tenable", "1001:host") == "tenable:1001:host"
    assert fi.make_dedup_key([], "tenable", None) is None


# ── cross-source merging ────────────────────────────────────────────────────


def test_wiz_then_tenable_same_cve_is_one_finding_two_observations(db):
    asset = _asset(db)
    _wiz(db, asset, WIZ_APACHE)
    result = _tenable_sync(db, vulns=[TENABLE_APACHE])
    assert result["ok"], result
    assert result["vulns_created"] == 0 and result["vulns_merged"] == 1

    vuln = db.query(Vulnerability).one()
    assert vuln.detected_by == "wiz"  # owner unchanged, title not overwritten
    assert vuln.title == "apache httpd CVE-2021-41773"
    assert vuln.cves == ["CVE-2021-41773", "CVE-2021-42013"]
    assert vuln.severity == Severity.CRITICAL  # max across sources
    assert {o.source for o in vuln.observations} == {"wiz", "tenable_vm"}

    # Re-syncing both sources stays at one finding and two observations.
    _tenable_sync(db, vulns=[TENABLE_APACHE])
    _wiz(db, asset, WIZ_APACHE)
    assert db.query(Vulnerability).count() == 1
    assert db.query(FindingObservation).count() == 2


def test_tenable_then_wiz_matches_on_any_cve_in_plugin(db):
    _tenable_sync(db, vulns=[TENABLE_APACHE])
    asset = db.query(Asset).filter_by(value="www.acme.com").one()
    wiz_other_cve = {**WIZ_APACHE, "name": "CVE-2021-42013", "detailedName": "httpd CVE-2021-42013"}
    stats = _wiz(db, asset, wiz_other_cve)
    assert stats.vulns_merged == 1 and stats.vulns_created == 0
    vuln = db.query(Vulnerability).one()
    assert vuln.template_id == "tenable:142960:443/tcp"
    assert vuln.port_service_id is not None
    assert {o.source for o in vuln.observations} == {"tenable_vm", "wiz"}


def test_fix_from_one_source_keeps_finding_open_until_all_agree(db):
    asset = _asset(db)
    _wiz(db, asset, WIZ_APACHE)
    _tenable_sync(db, vulns=[TENABLE_APACHE])

    # Tenable says fixed; Wiz still sees it.
    _tenable_sync(db, fixed=[{**TENABLE_APACHE, "state": "FIXED", "last_fixed": "2026-11-05T00:00:00Z"}])
    vuln = db.query(Vulnerability).one()
    assert vuln.status == VulnerabilityStatus.OPEN
    states = {o.source: o.state for o in vuln.observations}
    assert states == {"wiz": "open", "tenable_vm": "fixed"}

    # Wiz now agrees: resolved.
    _wiz(db, asset, {**WIZ_APACHE, "status": "RESOLVED", "resolvedAt": "2026-11-06T00:00:00Z"})
    db.refresh(vuln)
    assert vuln.status == VulnerabilityStatus.RESOLVED


def test_analyst_decision_survives_merge_and_fixes(db):
    asset = _asset(db)
    _wiz(db, asset, WIZ_APACHE)
    vuln = db.query(Vulnerability).one()
    vuln.status = VulnerabilityStatus.ACCEPTED
    db.commit()

    _tenable_sync(db, vulns=[TENABLE_APACHE])
    _wiz(db, asset, {**WIZ_APACHE, "status": "RESOLVED"})
    db.refresh(vuln)
    assert vuln.status == VulnerabilityStatus.ACCEPTED


def test_nuclei_owned_finding_not_closed_by_tenable_alone(db):
    asset = _asset(db)
    nuclei = Vulnerability(
        title="[CVE-2021-41773] Apache path traversal", severity=Severity.HIGH, asset_id=asset.id,
        detected_by="nuclei", template_id="CVE-2021-41773", cve_id="CVE-2021-41773",
        status=VulnerabilityStatus.OPEN,
    )
    db.add(nuclei)
    db.commit()

    _tenable_sync(db, vulns=[TENABLE_APACHE])
    assert db.query(Vulnerability).count() == 1
    _tenable_sync(db, fixed=[{**TENABLE_APACHE, "state": "FIXED"}])
    db.refresh(nuclei)
    assert nuclei.status == VulnerabilityStatus.OPEN


def test_merge_across_domain_and_resolved_ip(db):
    domain = _asset(db, ip_address="93.184.216.34")
    ip = _asset(db, value="93.184.216.34", asset_type=AssetType.IP_ADDRESS)
    _wiz(db, ip, WIZ_APACHE)
    match = fi.find_canonical(db, domain, ["CVE-2021-41773"], "cve:CVE-2021-41773")
    assert match is not None and match.asset_id == ip.id
    assert fi.find_canonical(db, domain, ["CVE-2021-41773"], None, include_related=False) is None


def test_non_cve_findings_from_different_ports_stay_separate(db):
    usn_a = {**TENABLE_APACHE, "plugin": {"id": 2002, "name": "SSL Certificate Expiry"},
             "port": {"port": 443, "protocol": "TCP"}}
    usn_b = {**usn_a, "port": {"port": 8443, "protocol": "TCP"}}
    result = _tenable_sync(db, vulns=[usn_a, usn_b])
    assert result["vulns_created"] == 2
    assert db.query(Vulnerability).count() == 2


def test_dedup_service_matches_cve_listed_among_many(db):
    asset = _asset(db)
    db.add(Vulnerability(
        title="Apache multiple", severity=Severity.HIGH, asset_id=asset.id, detected_by="tenable_vm",
        template_id="tenable:142960:443/tcp", cve_id="CVE-2021-41773",
        cves=["CVE-2021-41773", "CVE-2021-42013"], status=VulnerabilityStatus.OPEN,
        last_detected=datetime(2026, 11, 1),
    ))
    db.commit()
    dup = FindingDeduplicationService(db).find_duplicate_finding(asset=asset, cve_id="cve-2021-42013")
    assert dup is not None and dup.template_id == "tenable:142960:443/tcp"
