"""Cross-source asset deduplication on each source's own (cloud provider) IDs."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.asset_identifier import AssetIdentifier  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.tenable_integration import TenableVmIntegration  # noqa: E402
from app.models.vulnerability import Severity, Vulnerability  # noqa: E402
from app.models.wiz_integration import WizIntegration  # noqa: E402
from app.services import asset_identity as ident  # noqa: E402
from app.services import tenable_vm_service as tenable  # noqa: E402
from app.services import wiz_service as wiz  # noqa: E402
from app.services.asset_merge_service import AssetMergeService  # noqa: E402

INSTANCE = "i-0abc1234def567890"
ARN = f"arn:aws:ec2:us-east-1:123456789012:instance/{INSTANCE}"
AZURE_RID = "/subscriptions/1111/resourceGroups/RG-Web/providers/Microsoft.Compute/virtualMachines/Web01"
CLOUD_IP = "52.10.10.10"


# ── Normalizers ─────────────────────────────────────────────────────────────


def test_arn_and_bare_instance_id_share_an_identifier():
    from_arn = ident.aws_ids(ARN.upper().replace("ARN:AWS", "arn:aws"))
    assert ident.Identifier(ident.AWS_INSTANCE, INSTANCE) in from_arn
    assert ident.Identifier(ident.AWS_ARN, ARN) in from_arn
    assert ident.aws_ids(INSTANCE) == [ident.Identifier(ident.AWS_INSTANCE, INSTANCE)]
    assert ident.aws_ids("i-nothex") == []


def test_provider_ids_classify_each_cloud():
    assert ident.provider_ids(AZURE_RID) == [ident.Identifier(ident.AZURE_RESOURCE, AZURE_RID.lower())]
    assert ident.provider_ids(AZURE_RID.lower() + "/") == ident.provider_ids(AZURE_RID)
    guid = "6F1C3B2A-1111-2222-3333-444455556666"
    assert ident.provider_ids(guid, "Azure") == [ident.Identifier(ident.AZURE_VM, guid.lower())]
    assert ident.provider_ids("1234567890123", "GCP") == [ident.Identifier(ident.GCP_INSTANCE, "1234567890123")]
    link = "https://www.googleapis.com/compute/v1/projects/P1/zones/us-east1-b/instances/web"
    assert ident.provider_ids(link) == [
        ident.Identifier(ident.GCP_SELF_LINK, "projects/p1/zones/us-east1-b/instances/web")
    ]
    # Unknown shapes and bare GUIDs without a platform hint are not guessed at.
    assert ident.provider_ids(guid) == [] and ident.provider_ids("web01") == []


def test_mac_and_bios_reject_values_shared_across_machines():
    assert ident.mac_id("00-1A-2B-3C-4D-5E") == ident.Identifier(ident.MAC, "00:1a:2b:3c:4d:5e")
    assert ident.mac_id("02:42:ac:11:00:02") is None  # locally administered (Docker, cloud ENIs)
    assert ident.mac_id("00:00:00:00:00:00") is None
    assert ident.mac_id("01:00:5e:00:00:01") is None  # multicast
    assert ident.bios_id("EC2A1B2C-3D4E-5F60-7182-93A4B5C6D7E8").value == "ec2a1b2c-3d4e-5f60-7182-93a4b5c6d7e8"
    assert ident.bios_id("00000000-0000-0000-0000-000000000000") is None
    assert ident.bios_id("03000200-0400-0500-0006-000700080009") is None


# ── End to end ──────────────────────────────────────────────────────────────


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.add(TenableVmIntegration(
        id=1, organization_id=1, connection_name="Tenable", base_url="https://cloud.tenable.com",
        access_key_encrypted="x", secret_key_encrypted="x",
    ))
    session.add(WizIntegration(id=1, organization_id=1, connection_name="Wiz",
                               api_endpoint="https://api.us17.app.wiz.io/graphql",
                               client_id_encrypted="x", client_secret_encrypted="x"))
    session.commit()
    yield session
    session.close()


def _address_filter():
    return tenable._AddressFilter(None, 1, classify=lambda ip: SimpleNamespace(
        hosting_type="cloud" if ip == CLOUD_IP else "unknown"))


class _FakeTenable:
    def __init__(self, assets=(), vulns=()):
        self.assets, self.vulns = list(assets), list(vulns)

    async def export_assets(self, since):
        return self.assets

    async def export_vulns(self, since):
        return self.vulns

    async def export_fixed_vulns(self, since):
        return []


def _tenable_sync(db, assets=(), vulns=()):
    integration = db.get(TenableVmIntegration, 1)
    result = asyncio.run(tenable.sync_integration(
        db, integration, client=_FakeTenable(assets, vulns), address_filter=_address_filter()))
    assert result["ok"], result
    return result


def _wiz_vm(**overrides):
    vm = {
        "__typename": "VulnerableAssetVirtualMachine",
        "id": "wiz-vm-1",
        "name": "web-prod-1",
        "providerUniqueId": ARN,
        "cloudPlatform": "AWS",
        "operatingSystem": "Linux",
        "ipAddresses": [CLOUD_IP],
        "hasWideInternetExposure": True,
    }
    vm.update(overrides)
    return vm


def _wiz_sync(db, *vms):
    findings = [
        {"id": f"finding-{n}", "name": f"CVE-2026-000{n}", "severity": "HIGH", "status": "OPEN",
         "vulnerableAsset": vm}
        for n, vm in enumerate(vms)
    ]
    integration = db.get(WizIntegration, 1)
    with patch.object(wiz, "_client_for") as client_for:
        client_for.return_value.get_vulnerability_findings = AsyncMock(return_value=findings)
        result = asyncio.run(wiz.sync_integration(db, integration))
    assert result["ok"], result
    return result


def _vuln(asset_block, plugin_id=1001):
    return {
        "asset": asset_block,
        "plugin": {"id": plugin_id, "name": f"Plugin {plugin_id}", "cvss3_base_score": 7.5},
        "port": {"port": 443, "protocol": "TCP"}, "severity": "high", "state": "OPEN",
    }


def test_same_aws_vm_from_wiz_and_tenable_is_one_asset_without_tenable_uuid(db):
    _wiz_sync(db, _wiz_vm())
    # Tenable reports only the instance ID and a cloud IP — no UUID, no FQDN.
    result = _tenable_sync(db, assets=[{"aws_ec2_instance_id": INSTANCE, "ipv4s": [CLOUD_IP]}])

    assert result["assets_created"] == 0 and result["assets_updated"] == 1
    asset = db.query(Asset).one()
    assert asset.asset_type == AssetType.CLOUD_RESOURCE and asset.value == ARN
    assert {"source:wiz", "source:tenable"} <= set(asset.tags)
    namespaces = {row.namespace for row in db.query(AssetIdentifier).filter_by(asset_id=asset.id)}
    assert {ident.AWS_INSTANCE, ident.AWS_ARN, ident.WIZ_ID} <= namespaces


def test_tenable_first_then_wiz_enriches_without_renaming(db):
    _tenable_sync(db, assets=[{
        "id": "u-web", "fqdns": ["www.acme.com"], "ipv4s": ["93.184.216.34"],
        "aws_ec2_instance_id": INSTANCE.upper(),
    }])
    _wiz_sync(db, _wiz_vm())

    asset = db.query(Asset).one()
    assert asset.value == "www.acme.com" and asset.name == "www.acme.com"
    assert asset.asset_type == AssetType.SUBDOMAIN
    assert "source:wiz" in asset.tags and asset.metadata_["wiz"]["id"] == "wiz-vm-1"
    assert db.query(Vulnerability).filter_by(asset_id=asset.id, detected_by="wiz").count() == 1


def test_cloud_vm_with_only_a_cloud_ip_is_imported_under_its_provider_id(db):
    result = _tenable_sync(db, assets=[
        {"id": "u-vm", "ipv4s": [CLOUD_IP], "azure_resource_id": AZURE_RID, "hostnames": ["web01"]},
        {"id": "u-ephemeral", "ipv4s": [CLOUD_IP]},  # no provider ID: still skipped
    ])
    assert result["assets_created"] == 1 and result["assets_skipped"] == 1
    asset = db.query(Asset).one()
    assert asset.asset_type == AssetType.CLOUD_RESOURCE
    assert asset.value == AZURE_RID.lower() and asset.name == "web01"

    # Wiz reports the same resource ID in different case: same asset.
    _wiz_sync(db, _wiz_vm(id="wiz-az", providerUniqueId=AZURE_RID.upper(), cloudPlatform="Azure"))
    assert db.query(Asset).count() == 1


def test_different_instances_sharing_a_hostname_are_never_merged(db):
    _tenable_sync(db, assets=[
        {"id": "u-a", "fqdns": ["app.acme.com"], "ipv4s": ["93.184.216.34"], "aws_ec2_instance_id": "i-0aaaaaaaaaaaaaaaa"},
        {"id": "u-b", "fqdns": ["app.acme.com"], "ipv4s": ["93.184.216.35"], "aws_ec2_instance_id": "i-0bbbbbbbbbbbbbbbb"},
    ])
    assets = {a.value: a for a in db.query(Asset).all()}
    assert set(assets) == {"app.acme.com", "i-0bbbbbbbbbbbbbbbb"}
    assert assets["i-0bbbbbbbbbbbbbbbb"].asset_type == AssetType.CLOUD_RESOURCE

    # And a resync lands each record on its own asset again.
    result = _tenable_sync(db, assets=[
        {"fqdns": ["app.acme.com"], "ipv4s": ["93.184.216.34"], "aws_ec2_instance_id": "i-0aaaaaaaaaaaaaaaa"},
        {"fqdns": ["app.acme.com"], "ipv4s": ["93.184.216.35"], "aws_ec2_instance_id": "i-0bbbbbbbbbbbbbbbb"},
    ])
    assert result["assets_created"] == 0 and db.query(Asset).count() == 2


def test_resync_without_uuid_or_stable_ip_finds_the_same_asset(db):
    _tenable_sync(db, assets=[{"ipv4s": ["93.184.216.34"], "aws_ec2_instance_id": INSTANCE}])
    # The public IP changed; the instance ID did not.
    result = _tenable_sync(db, assets=[{"ipv4s": ["93.184.216.99"], "aws_ec2_instance_id": INSTANCE}])
    assert result["assets_created"] == 0
    asset = db.query(Asset).one()
    assert asset.value == "93.184.216.34"
    assert "93.184.216.99" not in (asset.ip_addresses or [])  # an IP asset's value is its address


def test_findings_attach_by_tenable_uuid_across_syncs(db):
    _tenable_sync(db, assets=[{"id": "U-WEB", "fqdns": ["www.acme.com"], "ipv4s": ["93.184.216.34"]}])
    # Next sync: finding's asset block has the UUID but no usable name.
    result = _tenable_sync(db, vulns=[_vuln({"uuid": "u-web", "hostname": "web01"})])
    assert result["vulns_created"] == 1
    assert db.query(Vulnerability).one().asset.value == "www.acme.com"


def test_wiz_record_missing_provider_id_still_matches_by_wiz_id(db):
    _wiz_sync(db, _wiz_vm())
    result = _wiz_sync(db, _wiz_vm(providerUniqueId=None))
    assert result["assets_created"] == 0 and db.query(Asset).count() == 1


def test_legacy_duplicates_are_merged_when_a_record_links_them(db):
    # State from before identifiers existed: Wiz VM and Tenable hostname
    # asset for the same machine, each with its own finding.
    vm = Asset(organization_id=1, name="web-prod-1", value=ARN, asset_type=AssetType.CLOUD_RESOURCE,
               discovery_source="wiz", tags=["source:wiz"],
               metadata_={"wiz": {"id": "wiz-vm-1", "provider_unique_id": ARN, "cloud_platform": "AWS"}})
    host = Asset(organization_id=1, name="www.acme.com", value="www.acme.com", asset_type=AssetType.SUBDOMAIN,
                 discovery_source="tenable_vm", tags=["source:tenable"],
                 metadata_={"tenable": {"asset_uuid": "u-web"}})
    db.add_all([vm, host])
    db.flush()
    db.add_all([
        Vulnerability(title="wiz finding", asset_id=vm.id, severity=Severity.HIGH, detected_by="wiz"),
        Vulnerability(title="tenable finding", asset_id=host.id, severity=Severity.HIGH, detected_by="tenable_vm"),
    ])
    db.commit()
    _wiz_sync(db)  # backfills Wiz identifiers from metadata

    result = _tenable_sync(db, assets=[{
        "id": "u-web", "fqdns": ["www.acme.com"], "ipv4s": ["93.184.216.34"], "aws_ec2_instance_id": INSTANCE,
    }])

    assert result["assets_merged"] == 1
    survivor = db.query(Asset).one()
    assert survivor.value == "www.acme.com"  # the hostname asset is the primary
    assert {v.title for v in survivor.vulnerabilities} == {"wiz finding", "tenable finding"}
    assert {"wiz", "tenable"} <= set(survivor.metadata_)
    assert db.query(AssetIdentifier).filter(AssetIdentifier.asset_id != survivor.id).count() == 0


# ── Merge service ───────────────────────────────────────────────────────────


def _asset(db, value, asset_type, **kw):
    asset = Asset(organization_id=1, name=value, value=value, asset_type=asset_type, **kw)
    db.add(asset)
    db.flush()
    return asset


def test_ip_merge_keeps_the_findings_it_moves(db):
    domain = _asset(db, "acme.com", AssetType.DOMAIN)
    ip = _asset(db, "93.184.216.34", AssetType.IP_ADDRESS, resolved_from="acme.com")
    db.add(Vulnerability(title="open redirect", asset_id=ip.id, severity=Severity.MEDIUM))
    db.commit()

    result = AssetMergeService(db).merge_ip_into_domain(ip.id, domain.id)

    assert result["vulnerabilities_moved"] == 1
    vuln = db.query(Vulnerability).one()
    assert vuln.asset_id == domain.id and vuln.metadata_["discovered_on_ip"] == "93.184.216.34"
    assert db.query(Asset).count() == 1


def test_merge_refuses_assets_with_different_cloud_ids(db):
    a = _asset(db, "app.acme.com", AssetType.SUBDOMAIN)
    b = _asset(db, "app.acme.com", AssetType.SUBDOMAIN)
    resolver = ident.AssetIdentityResolver(db, 1, "test")
    resolver.attach(a, ident.aws_ids("i-0aaaaaaaaaaaaaaaa"))
    resolver.attach(b, ident.aws_ids("i-0bbbbbbbbbbbbbbbb"))
    db.commit()

    result = AssetMergeService(db).merge_duplicate_domains([a.id, b.id])

    assert result["merged_count"] == 0 and result["skipped_conflicting_ids"] == [b.id]
    assert db.query(Asset).count() == 2


def test_exclusive_ids_are_never_stolen_but_aliases_follow(db):
    a = _asset(db, "a", AssetType.CLOUD_RESOURCE)
    b = _asset(db, "b", AssetType.CLOUD_RESOURCE)
    resolver = ident.AssetIdentityResolver(db, 1, "test")
    shared_alias = ident.record_id(ident.TENABLE_ASSET, "u-1")
    resolver.attach(a, [*ident.aws_ids(INSTANCE), shared_alias])
    resolver.attach(b, [*ident.aws_ids(INSTANCE), shared_alias])
    rows = {r.namespace: r.asset_id for r in db.query(AssetIdentifier)}
    assert rows[ident.AWS_INSTANCE] == a.id
    assert rows[ident.TENABLE_ASSET] == b.id
