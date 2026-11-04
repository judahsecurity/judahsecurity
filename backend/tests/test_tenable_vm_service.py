"""Tenable VM export client, normalization, and importer (mocked export API)."""

import asyncio
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("sqlalchemy")
httpx = pytest.importorskip("httpx")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.port_service import PortService  # noqa: E402
from app.models.tenable_integration import TenableVmIntegration  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus  # noqa: E402
from app.services import tenable_vm_service as svc  # noqa: E402
from app.services.tenable_vm_service import (  # noqa: E402
    TenableApiError,
    TenableClient,
    _AddressFilter,
    cvss_rating,
    severity_from_cvss,
)

CLOUD_IP = "52.10.10.10"


def _filter():
    """Address filter with a fake classifier: CLOUD_IP is AWS, everything else unknown."""
    return _AddressFilter(None, 1, classify=lambda ip: SimpleNamespace(
        hosting_type="cloud" if ip == CLOUD_IP else "unknown"))


# ── URL validation & severity ───────────────────────────────────────────────


def test_default_and_fed_urls_accepted():
    assert TenableClient("", "a", "s").base_url == "https://cloud.tenable.com"
    assert TenableClient("https://fedcloud.tenable.com/", "a", "s").base_url == "https://fedcloud.tenable.com"


@pytest.mark.parametrize("url", [
    "http://cloud.tenable.com",
    "https://cloud.tenable.com.attacker.example",
    "https://user:pw@cloud.tenable.com",
    "https://cloud.tenable.com:8443",
    "https://10.0.0.5",
    "https://cloud.tenable.com/assets",
])
def test_unsafe_urls_rejected(url):
    with pytest.raises(TenableApiError):
        TenableClient(url, "a", "s")


@pytest.mark.parametrize("score,expected", [
    (10.0, Severity.CRITICAL), (9.0, Severity.CRITICAL), (8.9, Severity.HIGH), (7.0, Severity.HIGH),
    (6.9, Severity.MEDIUM), (4.0, Severity.MEDIUM), (3.9, Severity.LOW), (0.1, Severity.LOW),
    (0.0, Severity.INFO),
])
def test_cvss_thresholds(score, expected):
    assert severity_from_cvss(score) == expected


def test_temporal_score_preferred_over_base():
    assert cvss_rating({"cvss3_base_score": 9.8, "cvss3_temporal_score": 8.8}) == (8.8, Severity.HIGH)
    assert cvss_rating({"cvss3_base_score": 9.8}) == (9.8, Severity.CRITICAL)
    # No CVSSv3 at all falls back to Tenable's own label.
    assert cvss_rating({"risk_factor": "High"}) == (None, Severity.HIGH)


def test_asset_identity_skips_private_internal_and_cloud():
    f = _filter()
    assert f.identity(["host.corp", "www.example.com"], ["8.8.8.8"]) == ("www.example.com", AssetType.SUBDOMAIN)
    assert f.identity(["ec2-52-1-1-1.compute-1.amazonaws.com"], ["8.8.4.4"]) == ("8.8.4.4", AssetType.IP_ADDRESS)
    assert f.identity([], ["10.0.0.1", CLOUD_IP, "1.1.1.1"]) == ("1.1.1.1", AssetType.IP_ADDRESS)
    assert f.identity(["server01"], ["192.168.1.4", CLOUD_IP]) is None
    assert f.identity(["Example.COM."], []) == ("example.com", AssetType.DOMAIN)


# ── Export API client ───────────────────────────────────────────────────────


class FakeTenable:
    """In-memory Tenable export API."""

    def __init__(self, assets=None, vulns=None, status_code=200):
        self.data = {"assets": assets or [], "vulns": vulns or []}
        self.status_code = status_code
        self.requests = []
        self.polls = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.path, body, request.headers.get("X-ApiKeys")))
        if self.status_code != 200:
            return httpx.Response(self.status_code, json={"error": "nope"})
        parts = request.url.path.strip("/").split("/")
        kind = parts[0]
        if request.method == "POST" and parts[-1] == "export":
            return httpx.Response(200, json={"export_uuid": f"{kind}-uuid"})
        if parts[-1] == "cancel":
            return httpx.Response(200, json={"status": "CANCELLED"})
        if parts[-1] == "status":
            # Report PROCESSING once with chunk 1, then FINISHED with chunk 2.
            n = self.polls[kind] = self.polls.get(kind, 0) + 1
            if n == 1:
                return httpx.Response(200, json={"status": "PROCESSING", "chunks_available": [1]})
            return httpx.Response(200, json={"status": "FINISHED", "chunks_available": [1, 2]})
        if parts[-2] == "chunks":
            items = self.data[kind]
            half = (len(items) + 1) // 2
            return httpx.Response(200, json=items[:half] if parts[-1] == "1" else items[half:])
        return httpx.Response(404)

    def client(self):
        return TenableClient("https://cloud.tenable.com", "AK", "SK",
                             transport=httpx.MockTransport(self.handler), poll_interval=0)


def test_export_polls_and_downloads_each_chunk_once():
    fake = FakeTenable(assets=[{"id": "a"}, {"id": "b"}, {"id": "c"}])
    records = asyncio.run(fake.client().export_assets(1700000000))
    assert [r["id"] for r in records] == ["a", "b", "c"]
    chunk_gets = [path for method, path, *_ in fake.requests if "/chunks/" in path]
    assert chunk_gets == ["/assets/export/assets-uuid/chunks/1", "/assets/export/assets-uuid/chunks/2"]
    method, path, body, keys = fake.requests[0]
    assert (method, path) == ("POST", "/assets/export")
    assert body["filters"] == {"last_assessed": 1700000000}
    assert keys == "accessKey=AK;secretKey=SK"


def test_vuln_export_filters_match_spec():
    fake = FakeTenable()
    asyncio.run(fake.client().export_vulns(123))
    body = fake.requests[0][2]
    assert body["filters"] == {
        "severity": ["low", "medium", "high", "critical"],
        "state": ["OPEN", "REOPENED"],
        "last_found": 123,
    }


def test_connection_requests_both_exports_and_cancels_them():
    fake = FakeTenable()
    result = asyncio.run(svc.test_connection("https://cloud.tenable.com", "AK", "SK",
                                             transport=httpx.MockTransport(fake.handler)))
    assert result["ok"] and result["assets_export_ok"] and result["vulns_export_ok"]
    paths = [path for _, path, *_ in fake.requests]
    assert paths == ["/assets/export", "/assets/export/assets-uuid/cancel",
                     "/vulns/export", "/vulns/export/vulns-uuid/cancel"]


def test_connection_403_points_at_view_all_assets_permission():
    fake = FakeTenable(status_code=403)
    result = asyncio.run(svc.test_connection("https://cloud.tenable.com", "AK", "SK",
                                             transport=httpx.MockTransport(fake.handler)))
    assert result["ok"] is False
    assert "Can View" in result["message"] and "All Assets" in result["message"]


# ── End-to-end import ───────────────────────────────────────────────────────


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, TenableVmIntegration.__table__, Asset.__table__,
        PortService.__table__, Vulnerability.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    integration = TenableVmIntegration(
        id=1, organization_id=1, connection_name="Tenable VM", base_url="https://cloud.tenable.com",
        access_key_encrypted="x", secret_key_encrypted="x",
    )
    session.add(integration)
    session.commit()
    yield session
    session.close()


ASSETS = [
    {"id": "u-web", "fqdns": ["www.acme.com"], "ipv4s": ["93.184.216.34"], "operating_systems": ["Ubuntu 22.04"]},
    {"id": "u-internal", "fqdns": ["db01.acme.internal"], "ipv4s": ["10.1.1.1"]},
    {"id": "u-cloud", "fqdns": [], "ipv4s": [CLOUD_IP]},
]

VULNS = [
    {
        "asset": {"uuid": "u-web", "fqdn": "www.acme.com", "ipv4": "93.184.216.34"},
        "plugin": {
            "id": 142960, "name": "Apache 2.4.x < 2.4.50 Path Traversal", "family": "Web Servers",
            "synopsis": "The remote web server is affected.", "description": "Path traversal.",
            "solution": "Upgrade to Apache 2.4.51.", "see_also": ["https://httpd.apache.org/security/"],
            "cve": ["CVE-2021-41773"], "cvss3_base_score": 7.5, "cvss3_temporal_score": 7.2,
            "cvss3_vector": {"raw": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        },
        "port": {"port": 443, "protocol": "TCP", "service": "www"},
        "output": "Server: Apache/2.4.49", "severity": "high", "state": "OPEN",
        "first_found": "2026-10-01T00:00:00Z", "last_found": "2026-11-01T00:00:00Z",
    },
    {
        "asset": {"uuid": "u-web", "fqdn": "www.acme.com", "ipv4": "93.184.216.34", "agent_uuid": "agent-1"},
        "plugin": {"id": 1001, "name": "Ubuntu USN-1", "family": "Ubuntu Local Security Checks",
                   "cvss3_base_score": 5.0},
        "port": {"port": 0, "protocol": "TCP"}, "severity": "medium", "state": "REOPENED",
    },
    # Asset not in the asset export: created from the vuln record.
    {
        "asset": {"uuid": "u-vpn", "fqdn": "vpn.acme.com", "ipv4": "45.33.32.156"},
        "plugin": {"id": 2002, "name": "SSL Certificate Expiry", "cvss3_base_score": 9.1},
        "port": {"port": 8443, "protocol": "TCP", "service": "https"}, "severity": "critical", "state": "OPEN",
    },
    # Private-only asset: skipped.
    {
        "asset": {"uuid": "u-internal", "fqdn": "db01.acme.internal", "ipv4": "10.1.1.1"},
        "plugin": {"id": 3003, "name": "MySQL weak password", "cvss3_base_score": 9.8},
        "port": {"port": 3306, "protocol": "TCP"}, "severity": "critical", "state": "OPEN",
    },
]


def _sync(db, fake):
    integration = db.get(TenableVmIntegration, 1)
    return asyncio.run(svc.sync_integration(db, integration, client=fake.client(), address_filter=_filter()))


def test_sync_imports_assets_and_vulns(db):
    result = _sync(db, FakeTenable(assets=ASSETS, vulns=VULNS))
    assert result["ok"], result
    assert result["assets_created"] == 2  # www + vpn; internal & cloud skipped
    assert result["assets_skipped"] == 2
    assert result["vulns_created"] == 3 and result["vulns_skipped"] == 1

    values = {a.value for a in db.query(Asset).all()}
    assert values == {"www.acme.com", "vpn.acme.com"}
    www = db.query(Asset).filter_by(value="www.acme.com").one()
    assert www.ip_address == "93.184.216.34" and www.operating_system == "Ubuntu 22.04"

    apache = db.query(Vulnerability).filter(Vulnerability.title.like("Apache%")).one()
    assert apache.severity == Severity.HIGH and apache.cvss_score == 7.2
    assert apache.cve_id == "CVE-2021-41773"
    assert apache.remediation == "Upgrade to Apache 2.4.51."
    assert apache.references == ["https://httpd.apache.org/security/"]
    assert "Plugin output:" in apache.evidence and "Apache/2.4.49" in apache.evidence
    assert "AV:N/AC:L" in apache.evidence and "443/tcp (www)" in apache.evidence
    assert apache.affected_component == "443/tcp (www)"
    port = db.query(PortService).filter_by(asset_id=www.id, port=443).one()
    assert apache.metadata_["port_service_id"] == port.id
    assert apache.detected_by == "tenable_vm"

    host_level = db.query(Vulnerability).filter_by(title="Ubuntu USN-1").one()
    assert host_level.affected_component is None and host_level.metadata_["port"] is None
    assert host_level.detected_by == "tenable_agent"
    assert host_level.severity == Severity.MEDIUM


def test_resync_updates_without_duplicates_and_reopens(db):
    fake_data = dict(assets=ASSETS, vulns=VULNS)
    _sync(db, FakeTenable(**fake_data))
    vuln = db.query(Vulnerability).filter(Vulnerability.title.like("Apache%")).one()
    vuln.status = VulnerabilityStatus.RESOLVED
    db.commit()

    result = _sync(db, FakeTenable(**fake_data))
    assert result["ok"] and result["vulns_created"] == 0 and result["vulns_updated"] == 3
    assert result["assets_created"] == 0
    assert db.query(Vulnerability).count() == 3
    assert db.query(PortService).count() == 2
    db.refresh(vuln)
    assert vuln.status == VulnerabilityStatus.OPEN


def test_sync_failure_is_recorded(db):
    result = _sync(db, FakeTenable(status_code=401))
    assert result["ok"] is False
    integration = db.get(TenableVmIntegration, 1)
    assert integration.last_sync_ok is False and "401" in integration.last_error
