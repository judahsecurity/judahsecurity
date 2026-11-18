"""Falcon pagination and exposure import behavior without live credentials."""

from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.asset import Asset, AssetType
from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration
from app.models.exposure_evidence import ExposurePath, ExposurePathStep, FindingSourceEvidence
from app.models.organization import Organization
from app.models.port_service import PortService
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.schemas.crowdstrike_schemas import CrowdStrikeIntegrationUpdate
from app.schemas.vulnerability import FindingSourceEvidenceResponse
from app.services.crowdstrike_service import (
    CrowdStrikeClient,
    CrowdStrikeError,
    SPOTLIGHT_EXPOSED_OPEN_FILTER,
    _stats,
    _upsert_external,
    _upsert_finding,
    _upsert_host,
    test_connection as _test_crowdstrike_connection,
)
from app.services.exposure_path_mapping import map_crowdstrike_path_assets, resolve_crowdstrike_asset_ref


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



@pytest.mark.asyncio
async def test_external_asset_query_uses_supported_page_limit_and_after_cursor():
    client = CrowdStrikeClient("us-1", "client", "secret")
    client._request = AsyncMock(side_effect=[
        {"resources": ["asset-1"], "meta": {"pagination": {"after": "next-page"}}},
        {"resources": [{"id": "asset-1"}]},
        {"resources": ["asset-2"], "meta": {"pagination": {}}},
        {"resources": [{"id": "asset-2"}]},
    ])
    try:
        batches = [batch async for batch in client.external_assets()]
        assert [[asset["id"] for asset in batch] for batch in batches] == [["asset-1"], ["asset-2"]]
        query_calls = [
            call for call in client._request.await_args_list
            if call.args[1] == "/fem/queries/external-assets/v2"
        ]
        assert [call.kwargs["params"] for call in query_calls] == [
            {"limit": 100},
            {"limit": 100, "after": "next-page"},
        ]
    finally:
        await client.http.aclose()


@pytest.mark.asyncio
async def test_spotlight_uses_required_exposed_open_filter(monkeypatch):
    request = AsyncMock(return_value={"resources": [], "meta": {"pagination": {}}})
    monkeypatch.setattr(CrowdStrikeClient, "_request", request)
    result = await _test_crowdstrike_connection(
        "us-1", "client", "secret", external=False, hosts=False, spotlight=True,
    )
    assert result["ok"] is True
    spotlight_call = next(
        call for call in request.await_args_list
        if call.args[1] == "/spotlight/combined/vulnerabilities/v1"
    )
    assert spotlight_call.kwargs["params"] == {
        "limit": 1, "filter": SPOTLIGHT_EXPOSED_OPEN_FILTER,
    }

    request.reset_mock()
    client = CrowdStrikeClient("us-1", "client", "secret")
    try:
        assert [batch async for batch in client.spotlight()] == [[]]
        assert request.await_args.kwargs["params"]["filter"] == SPOTLIGHT_EXPOSED_OPEN_FILTER
    finally:
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



def test_repeated_falcon_records_before_flush_are_idempotent(db):
    integration = _integration(db, "tenant")
    external = {
        "id": "external-1",
        "dns_domain": {
            "fqdn": "example.org",
            "services": [
                {"port": 443, "transport": "tcp"},
                {"port": 443, "transport": "tcp"},
            ],
        },
        "ip": {"services": [{"port": 443, "transport": "tcp"}]},
    }
    _upsert_external(db, integration, external, _stats())
    _upsert_external(db, integration, external, _stats())
    host = {"device_id": "aid-1", "cid": "cid-1", "hostname": "server-1"}
    _upsert_host(db, integration, host, _stats())
    _upsert_host(db, integration, host, _stats())
    db.flush()
    assert db.query(CrowdStrikeAssetLink).count() == 2
    assert db.query(Asset).count() == 2
    assert db.query(PortService).count() == 1


def test_external_subdomain_retains_parent_for_graph(db):
    integration = _integration(db, "tenant")
    _upsert_external(db, integration, {
        "id": "subdomain-1", "dns_domain": {"fqdn": "app.example.org", "parent_domain": "example.org"},
    }, _stats())
    db.flush()
    asset = db.query(Asset).one()
    assert asset.asset_type == AssetType.SUBDOMAIN
    assert asset.root_domain == "example.org"


def test_spotlight_finding_preserves_analyst_state_and_reopens_provider_resolved(db):
    integration = _integration(db, "tenant")
    _upsert_host(db, integration, {"device_id": "aid-1", "cid": "cid-1", "hostname": "server-1"}, _stats())
    db.flush()
    host = db.query(Asset).filter_by(organization_id=integration.organization_id).one()
    mapping = {("cid-1", "aid-1"): host}
    source = {"id": "finding-1", "aid": "aid-1", "cid": "cid-1", "status": "open",
              "cve": {"id": "CVE-2026-1234", "severity": "HIGH", "base_score": 8.1},
              "assessment_reason": "installed package detected", "evaluation_logic": {"rule": "package-version"}}
    _upsert_finding(db, integration, source, mapping, _stats())
    db.flush()
    finding = db.query(Vulnerability).one()
    assert finding.asset_id == host.id
    assert finding.cve_id == "CVE-2026-1234"
    assert finding.detection_confidence == "unknown"
    evidence = db.query(FindingSourceEvidence).one()
    assert evidence.vulnerability_id == finding.id
    assert evidence.organization_id == integration.organization_id
    assert evidence.basis == "provider_assertion"
    assert evidence.details["evaluation_logic"] == {"rule": "package-version"}
    assert FindingSourceEvidenceResponse.model_validate(evidence).details["assessment_reason"] == "installed package detected"
    finding.status = VulnerabilityStatus.ACCEPTED
    finding.tags = ["analyst:reviewed"]
    last_detected = finding.last_detected
    _upsert_finding(db, integration, source, mapping, _stats())
    assert finding.status == VulnerabilityStatus.ACCEPTED
    assert finding.last_detected == last_detected
    assert "analyst:reviewed" in finding.tags
    source["status"] = "closed"
    _upsert_finding(db, integration, source, mapping, _stats())
    assert finding.status == VulnerabilityStatus.RESOLVED
    source["status"] = "open"
    _upsert_finding(db, integration, source, mapping, _stats())
    assert finding.status == VulnerabilityStatus.OPEN
    assert db.query(Vulnerability).count() == 1
    assert db.query(FindingSourceEvidence).count() == 1


def test_path_steps_keep_unmatched_source_nodes_and_separate_proof(db):
    integration = _integration(db, "tenant")
    _upsert_host(db, integration, {"device_id": "aid-1", "cid": "cid-1", "hostname": "server-1"}, _stats())
    db.flush()
    host = db.query(Asset).one()
    path = ExposurePath(
        organization_id=integration.organization_id, source="crowdstrike",
        source_instance_id=str(integration.id),
        source_path_id="path-1", title="External entry to server",
        source_status="open", details={"source_type": "falcon_attack_path_analysis"},
    )
    path.steps.append(ExposurePathStep(
        position=0, from_source_ref="external:unmatched-id", to_source_ref="host:aid-1",
        to_asset_id=host.id, edge_type="network_reachability", source_claim="Provider-reported edge",
        proof_state="asserted", evidence=[{"source": "crowdstrike", "kind": "path_edge"}],
    ))
    db.add(path)
    db.flush()
    db.expire_all()
    saved = db.query(ExposurePath).one()
    assert saved.steps[0].from_asset_id is None
    assert saved.steps[0].from_source_ref == "external:unmatched-id"
    assert saved.steps[0].to_asset_id == host.id
    assert saved.steps[0].proof_state == "asserted"
    assert map_crowdstrike_path_assets(db, integration_id=integration.id, path=saved) == 1
    assert saved.steps[0].from_asset_id is None
    assert saved.steps[0].to_asset_id == host.id

    other_integration = _integration(db, "another tenant")
    assert resolve_crowdstrike_asset_ref(
        db, organization_id=other_integration.organization_id, integration_id=integration.id,
        source_ref="host:aid-1",
    ) is None
    with pytest.raises(ValueError, match="different CrowdStrike connection"):
        map_crowdstrike_path_assets(db, integration_id=other_integration.id, path=saved)


def test_update_rejects_null_required_columns():
    with pytest.raises(ValueError, match="import_hosts cannot be null"):
        CrowdStrikeIntegrationUpdate(import_hosts=None)
    assert CrowdStrikeIntegrationUpdate(import_hosts=False).import_hosts is False
