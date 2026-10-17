"""Falcon pagination and exposure import behavior without live credentials."""

from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.asset import Asset
from app.models.crowdstrike_integration import CrowdStrikeIntegration
from app.models.organization import Organization
from app.models.port_service import PortService
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.schemas.crowdstrike_schemas import CrowdStrikeIntegrationUpdate
from app.services.crowdstrike_service import (
    CrowdStrikeClient,
    CrowdStrikeError,
    _stats,
    _upsert_external,
    _upsert_finding,
    _upsert_host,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _integration(db: Session, name: str) -> CrowdStrikeIntegration:
    org = Organization(name=name)
    db.add(org)
    db.flush()
    integration = CrowdStrikeIntegration(
        organization_id=org.id, connection_name="Falcon", cloud_region="us-1",
        client_id_encrypted="test-only", client_secret_encrypted="test-only",
    )
    db.add(integration)
    db.flush()
    return integration


@pytest.mark.asyncio
async def test_cursor_pagination_uses_next_and_rejects_repeats():
    client = CrowdStrikeClient("us-1", "client", "secret")
    client._request = AsyncMock(side_effect=[
        {"resources": [{"device_id": "one"}], "meta": {"pagination": {"next": "page-2"}}},
        {"resources": [{"device_id": "two"}], "meta": {"pagination": {}}},
    ])
    pages = [batch async for batch in client.hosts()]
    assert [item["device_id"] for batch in pages for item in batch] == ["one", "two"]
    assert client._request.await_args_list[1].kwargs["params"]["offset"] == "page-2"
    await client.http.aclose()

    client = CrowdStrikeClient("us-1", "client", "secret")
    client._request = AsyncMock(return_value={"resources": [], "meta": {"pagination": {"after": "same"}}})
    with pytest.raises(CrowdStrikeError, match="repeated page cursor"):
        async for _ in client.spotlight():
            pass
    await client.http.aclose()


def test_external_import_is_tenant_scoped_and_idempotent(db):
    first = _integration(db, "first")
    second = _integration(db, "second")
    source = {
        "id": "external-1", "dns_domain": {"fqdn": "example.org", "resolved_ips": ["203.0.113.5"],
            "services": [{"port": 443, "transport": "tcp"}]},
        "ip": {"services": [{"port": 8443, "transport": "tcp"}]},
    }
    _upsert_external(db, first, source, _stats())
    db.flush()
    _upsert_external(db, first, source, _stats())
    _upsert_external(db, second, source, _stats())
    db.flush()
    assets = db.query(Asset).filter(Asset.value == "example.org").all()
    assert len(assets) == 2
    assert {asset.organization_id for asset in assets} == {first.organization_id, second.organization_id}
    assert all(asset.in_scope is False for asset in assets)
    assert db.query(PortService).count() == 4


def test_spotlight_finding_preserves_analyst_state_and_reopens_provider_resolved(db):
    integration = _integration(db, "tenant")
    _upsert_host(db, integration, {"device_id": "aid-1", "cid": "cid-1", "hostname": "server-1"}, _stats())
    db.flush()
    host = db.query(Asset).filter_by(organization_id=integration.organization_id).one()
    mapping = {("cid-1", "aid-1"): host}
    source = {"id": "finding-1", "aid": "aid-1", "cid": "cid-1", "status": "open",
              "cve": {"id": "CVE-2026-1234", "severity": "HIGH", "base_score": 8.1}}
    _upsert_finding(db, integration, source, mapping, _stats())
    db.flush()
    finding = db.query(Vulnerability).one()
    assert finding.asset_id == host.id
    assert finding.cve_id == "CVE-2026-1234"
    assert finding.detection_confidence == "version_only"
    finding.status = VulnerabilityStatus.ACCEPTED
    finding.tags = ["analyst:reviewed"]
    _upsert_finding(db, integration, source, mapping, _stats())
    assert finding.status == VulnerabilityStatus.ACCEPTED
    assert "analyst:reviewed" in finding.tags
    source["status"] = "closed"
    _upsert_finding(db, integration, source, mapping, _stats())
    assert finding.status == VulnerabilityStatus.RESOLVED
    source["status"] = "open"
    _upsert_finding(db, integration, source, mapping, _stats())
    assert finding.status == VulnerabilityStatus.OPEN
    assert db.query(Vulnerability).count() == 1


def test_update_rejects_null_required_columns():
    with pytest.raises(ValueError, match="import_hosts cannot be null"):
        CrowdStrikeIntegrationUpdate(import_hosts=None)
    assert CrowdStrikeIntegrationUpdate(import_hosts=False).import_hosts is False
