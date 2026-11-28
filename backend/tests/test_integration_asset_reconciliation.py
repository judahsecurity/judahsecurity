"""Provider disappearance changes active membership without erasing history."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.asset import Asset, AssetStatus, AssetType
from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration
from app.models.organization import Organization
from app.models.vulnerability import Vulnerability
from app.models.wiz_integration import WizApplicationEndpoint, WizAssetLink, WizIntegration
from app.services import crowdstrike_service, wiz_service
from app.services.integration_asset_reconciliation import mark_asset_seen, reconcile_asset_membership
from app.services.integration_graph_service import _asset_row, graph_projection_retry_due


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False) as session:
        org = Organization(name="Asset reconciliation")
        session.add(org)
        session.flush()
        yield session, org
    engine.dispose()


def _wiz(db: Session, org: Organization) -> WizIntegration:
    row = WizIntegration(
        organization_id=org.id, connection_name="Wiz", api_endpoint="https://api.us17.app.wiz.io/graphql",
        client_id_encrypted="test", client_secret_encrypted="test",
        import_assets=True, import_vulnerabilities=False,
    )
    db.add(row)
    db.flush()
    return row


def _crowdstrike(db: Session, org: Organization) -> CrowdStrikeIntegration:
    row = CrowdStrikeIntegration(
        organization_id=org.id, connection_name="Falcon", cloud_region="us-1",
        client_id_encrypted="test", client_secret_encrypted="test",
        import_external_assets=False, import_hosts=True, import_spotlight=True,
    )
    db.add(row)
    db.flush()
    return row


def test_failed_daily_sync_retries_in_one_hour(db):
    session, org = db
    for integration in (_wiz(session, org), _crowdstrike(session, org)):
        integration.continuous_sync_enabled = True
        integration.sync_interval_minutes = 1440
        integration.last_sync_at = datetime(2026, 11, 28, 12)
        integration.last_sync_ok = False
        assert integration.next_sync_at == integration.last_sync_at + timedelta(hours=1)
        integration.last_sync_ok = True
        assert integration.next_sync_at == integration.last_sync_at + timedelta(days=1)


def test_failed_graph_projection_retries_separately(db):
    session, org = db
    integration = _wiz(session, org)
    integration.last_sync_ok = True
    integration.last_sync_stats = {
        "graph_projection": {"ok": False, "attempted_at": "2026-11-28T12:00:00"},
    }
    assert graph_projection_retry_due(integration, datetime(2026, 11, 28, 12, 59)) is False
    assert graph_projection_retry_due(integration, datetime(2026, 11, 28, 13)) is True


def test_shared_and_owned_assets_keep_history_and_active_sources(db):
    session, org = db
    wiz = _wiz(session, org)
    crowdstrike = _crowdstrike(session, org)
    shared = Asset(
        organization_id=org.id, name="shared", value="shared", asset_type=AssetType.CLOUD_RESOURCE,
        discovery_source="wiz", status=AssetStatus.DISCOVERED,
        tags=["source:wiz", "source:crowdstrike"], metadata_={"wiz": {"id": "vm-shared"}},
    )
    owned = Asset(
        organization_id=org.id, name="owned", value="owned", asset_type=AssetType.CLOUD_RESOURCE,
        discovery_source="wiz", status=AssetStatus.DISCOVERED,
        is_owned=True, tags=["source:wiz"],
    )
    session.add_all([shared, owned])
    session.flush()
    session.add_all([
        WizAssetLink(integration_id=wiz.id, asset_id=shared.id, wiz_id="vm-shared",
                     last_seen=datetime.utcnow(), is_active=False),
        WizAssetLink(integration_id=wiz.id, asset_id=owned.id, wiz_id="vm-owned",
                     last_seen=datetime.utcnow(), is_active=False),
        CrowdStrikeAssetLink(integration_id=crowdstrike.id, asset_id=shared.id,
                             source_kind="host", source_id="aid-shared", is_active=True),
    ])
    session.flush()

    assert reconcile_asset_membership(session, "wiz", org.id, [shared.id, owned.id]) == 0
    assert shared.status == owned.status == AssetStatus.DISCOVERED
    assert shared.tags == ["source:crowdstrike"]
    assert owned.tags == []
    assert shared.metadata_["wiz"]["id"] == "vm-shared"
    assert _asset_row(shared)["props"]["sources"] == ["crowdstrike"]

    session.query(CrowdStrikeAssetLink).filter_by(source_id="aid-shared").update({
        CrowdStrikeAssetLink.is_active: False,
    }, synchronize_session=False)
    assert reconcile_asset_membership(session, "crowdstrike", org.id, [shared.id]) == 1
    assert shared.status == AssetStatus.INACTIVE
    assert _asset_row(shared)["props"]["is_active"] is False
    assert _asset_row(shared)["props"]["sources"] == []
    mark_asset_seen(shared, "wiz")
    assert shared.status == AssetStatus.DISCOVERED
    assert shared.tags == ["source:wiz"]


def test_wiz_reconciles_previously_inactive_endpoint_assets(db):
    session, org = db
    integration = _wiz(session, org)
    asset = Asset(
        organization_id=org.id, name="old endpoint", value="https://old.example.org",
        asset_type=AssetType.URL, discovery_source="wiz", status=AssetStatus.DISCOVERED,
        tags=["source:wiz"],
    )
    session.add(asset)
    session.flush()
    session.add(WizApplicationEndpoint(
        integration_id=integration.id, organization_id=org.id, asset_id=asset.id,
        wiz_id="old-endpoint", is_active=False, last_seen=datetime(2026, 1, 1),
    ))
    session.flush()

    wiz_service._reconcile_wiz_assets(session, integration, wiz_service._Stats(), datetime.utcnow(), set())
    assert asset.status == AssetStatus.INACTIVE
    assert asset.tags == []


@pytest.mark.asyncio
async def test_wiz_daily_sync_retires_and_restores_vm_and_endpoint(db, monkeypatch):
    session, org = db
    integration = _wiz(session, org)
    vm = lambda name: {"id": name, "name": name, "providerUniqueId": name,
                       "hasLimitedInternetExposure": True}
    endpoint = lambda name: {"id": name, "name": f"https://{name}.example.org",
                             "host": f"{name}.example.org", "port": 443,
                             "portStatus": "OPEN", "exposureLevel": "HIGH"}
    runs = [
        ([vm("vm-one"), vm("vm-two")], [endpoint("one"), endpoint("two")]),
        ([vm("vm-two")], [endpoint("two")]),
        ([vm("vm-one"), vm("vm-two")], [endpoint("one"), endpoint("two")]),
        ([], []),
    ]

    class Client:
        PAGE_SIZE = 100
        findings_truncated = False

        def __init__(self, vms, endpoints):
            self.vms = vms
            self.endpoints = endpoints
            self.virtual_machines_total_count = len(vms)

        async def iter_virtual_machines(self, *, exposed_only):
            yield self.vms

        async def iter_application_endpoints(self, *, ids=None):
            yield self.endpoints

        async def iter_endpoint_issues(self):
            if False:
                yield []

        async def iter_ai_endpoint_paths(self):
            if False:
                yield []

    monkeypatch.setattr(wiz_service, "_client_for", lambda _: Client(*runs.pop(0)))
    first = await wiz_service.sync_integration(session, integration)
    assert first["ok"] and first["assets_created"] == 4
    missing_vm = session.query(Asset).filter_by(value="vm-one").one()
    missing_endpoint = session.query(Asset).filter_by(value="https://one.example.org").one()
    second = await wiz_service.sync_integration(session, integration)
    assert second["ok"] and second["assets_retired"] == 2
    assert second["vm_links_removed"] == 1
    assert missing_vm.status == missing_endpoint.status == AssetStatus.INACTIVE
    assert session.query(WizAssetLink).filter_by(wiz_id="vm-one").one().is_active is False
    assert session.query(WizApplicationEndpoint).filter_by(wiz_id="one").one().is_active is False
    third = await wiz_service.sync_integration(session, integration)
    assert third["ok"] and third["assets_retired"] == 0
    assert missing_vm.status == missing_endpoint.status == AssetStatus.DISCOVERED
    assert session.query(WizAssetLink).filter_by(wiz_id="vm-one").one().is_active is True
    assert session.query(WizApplicationEndpoint).filter_by(wiz_id="one").one().is_active is True
    fourth = await wiz_service.sync_integration(session, integration)
    assert fourth["ok"] and fourth["assets_retired"] == 4
    assert fourth["vm_links_removed"] == 2
    assert session.query(Asset).filter(Asset.status == AssetStatus.INACTIVE).count() == 4


@pytest.mark.asyncio
async def test_wiz_failed_inventory_does_not_retire_prior_vm(db, monkeypatch):
    session, org = db
    integration = _wiz(session, org)
    asset = Asset(
        organization_id=org.id, name="VM", value="vm-old", asset_type=AssetType.CLOUD_RESOURCE,
        discovery_source="wiz", status=AssetStatus.DISCOVERED, tags=["source:wiz"],
    )
    session.add(asset)
    session.flush()
    link = WizAssetLink(integration_id=integration.id, asset_id=asset.id, wiz_id="vm-old",
                        last_seen=datetime(2026, 1, 1), is_active=True)
    session.add(link)
    session.commit()

    class Client:
        virtual_machines_total_count = 2

        async def iter_virtual_machines(self, *, exposed_only):
            yield [{"id": "vm-new", "providerUniqueId": "vm-new"}]
            raise wiz_service.WizApiError("Later VM page failed")

    monkeypatch.setattr(wiz_service, "_client_for", lambda _: Client())
    result = await wiz_service.sync_integration(session, integration)
    assert result["ok"] is False
    session.refresh(asset)
    session.refresh(link)
    assert asset.status == AssetStatus.DISCOVERED
    assert link.is_active is True


@pytest.mark.asyncio
async def test_wiz_findings_failure_does_not_block_completed_asset_reconciliation(db, monkeypatch):
    session, org = db
    integration = _wiz(session, org)
    integration.import_vulnerabilities = True
    asset = Asset(
        organization_id=org.id, name="VM", value="vm-old", asset_type=AssetType.CLOUD_RESOURCE,
        discovery_source="wiz", status=AssetStatus.DISCOVERED, tags=["source:wiz"],
    )
    session.add(asset)
    session.flush()
    session.add(WizAssetLink(
        integration_id=integration.id, asset_id=asset.id, wiz_id="vm-old",
        last_seen=datetime(2026, 1, 1), is_active=True,
    ))
    session.commit()

    class Client:
        PAGE_SIZE = 100
        virtual_machines_total_count = 0

        async def iter_virtual_machines(self, *, exposed_only):
            if False:
                yield []

        async def iter_application_endpoints(self, *, ids=None):
            if False:
                yield []

        async def iter_endpoint_issues(self):
            if False:
                yield []

        async def iter_ai_endpoint_paths(self):
            if False:
                yield []

        async def iter_vulnerability_findings(self, *, filter_by=None):
            assert filter_by["hasRelatedIssue"] is True
            raise wiz_service.WizApiError("Findings page failed")
            yield []

    monkeypatch.setattr(wiz_service, "_client_for", lambda _: Client())
    result = await wiz_service.sync_integration(session, integration)
    assert result["ok"] is False and result["assets_complete"] is True
    session.refresh(asset)
    assert asset.status == AssetStatus.INACTIVE


@pytest.mark.asyncio
async def test_wiz_unchanged_finding_is_not_rewritten_on_daily_sync(db, monkeypatch):
    session, org = db
    integration = _wiz(session, org)
    integration.import_vulnerabilities = True
    finding = {
        "id": "finding-1", "name": "CVE-2026-1234", "severity": "HIGH",
        "status": "OPEN", "updatedAt": "2026-11-28T12:00:00Z",
        "vulnerableAsset": {
            "id": "vm-1", "__typename": "VulnerableAssetVirtualMachine",
            "providerUniqueId": "vm-1", "hasLimitedInternetExposure": True,
        },
    }

    class Client:
        PAGE_SIZE = 100
        virtual_machines_total_count = 1
        vulnerability_findings_total_count = 1
        findings_truncated = False

        async def iter_virtual_machines(self, *, exposed_only):
            yield [{"id": "vm-1", "providerUniqueId": "vm-1"}]

        async def iter_application_endpoints(self, *, ids=None):
            if False:
                yield []

        async def iter_endpoint_issues(self):
            if False:
                yield []

        async def iter_ai_endpoint_paths(self):
            if False:
                yield []

        async def iter_vulnerability_findings(self, *, filter_by=None):
            yield [finding]

    monkeypatch.setattr(wiz_service, "_client_for", lambda _: Client())
    first = await wiz_service.sync_integration(session, integration)
    second = await wiz_service.sync_integration(session, integration)
    assert first["ok"] and first["vulns_created"] == 1
    assert second["ok"] and second["findings_unchanged"] == 1
    assert second["vulns_updated"] == 0
    finding["updatedAt"] = "2026-11-28T13:00:00Z"
    third = await wiz_service.sync_integration(session, integration)
    assert third["ok"] and third["vulns_updated"] == 1


@pytest.mark.asyncio
async def test_crowdstrike_spotlight_keeps_host_seen_without_device_row(db, monkeypatch):
    session, org = db
    integration = _crowdstrike(session, org)
    source = {"id": "finding-1", "aid": "aid-two", "cid": "cid-1", "status": "open",
              "updated_timestamp": "2026-11-28T12:00:00Z",
              "cve": {"id": "CVE-2026-1234", "severity": "HIGH"}}
    runs = [
        ([{"device_id": "aid-one", "cid": "cid-1"}, {"device_id": "aid-two", "cid": "cid-1"}], [source]),
        ([{"device_id": "aid-one", "cid": "cid-1"}], [source]),
        ([{"device_id": "aid-one", "cid": "cid-1"}], []),
        ([], []),
        ([], [source]),
    ]

    class Client:
        def __init__(self, hosts, findings):
            self.host_rows = hosts
            self.findings = findings

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def hosts(self):
            yield self.host_rows

        async def spotlight(self):
            yield self.findings

    monkeypatch.setattr(crowdstrike_service, "_client_for", lambda _: Client(*runs.pop(0)))
    first = await crowdstrike_service.sync_integration(session, integration)
    assert first["ok"] and first["vulns_created"] == 1
    link = session.query(CrowdStrikeAssetLink).filter_by(source_id="aid-two").one()
    asset = session.get(Asset, link.asset_id)
    second = await crowdstrike_service.sync_integration(session, integration)
    assert second["ok"] and second["assets_retired"] == 0
    assert link.is_active is True and asset.status == AssetStatus.DISCOVERED
    third = await crowdstrike_service.sync_integration(session, integration)
    assert third["ok"] and third["host_links_removed"] == 1
    assert asset.status == AssetStatus.INACTIVE
    assert session.query(Vulnerability).count() == 1
    fourth = await crowdstrike_service.sync_integration(session, integration)
    assert fourth["ok"] and fourth["host_links_removed"] == 1
    assert session.query(Asset).filter(Asset.status == AssetStatus.INACTIVE).count() == 2
    fifth = await crowdstrike_service.sync_integration(session, integration)
    assert fifth["ok"] and fifth["findings_unchanged"] == 1
    assert link.is_active is True and asset.status == AssetStatus.DISCOVERED


@pytest.mark.asyncio
async def test_crowdstrike_failed_page_keeps_existing_membership(db, monkeypatch):
    session, org = db
    integration = _crowdstrike(session, org)
    old = Asset(organization_id=org.id, name="old", value="old", asset_type=AssetType.OTHER,
                discovery_source="crowdstrike", status=AssetStatus.DISCOVERED,
                tags=["source:crowdstrike"])
    session.add(old)
    session.flush()
    link = CrowdStrikeAssetLink(integration_id=integration.id, asset_id=old.id,
                                source_kind="host", source_id="old", cid="cid-1",
                                last_seen=datetime(2026, 1, 1), is_active=True)
    session.add(link)
    session.commit()

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def hosts(self):
            yield [{"device_id": "new", "cid": "cid-1"}]

        async def spotlight(self):
            raise crowdstrike_service.CrowdStrikeError("Later Spotlight page failed")
            yield []

    monkeypatch.setattr(crowdstrike_service, "_client_for", lambda _: Client())
    result = await crowdstrike_service.sync_integration(session, integration)
    assert result["ok"] is False
    session.refresh(old)
    session.refresh(link)
    assert old.status == AssetStatus.DISCOVERED
    assert link.is_active is True
