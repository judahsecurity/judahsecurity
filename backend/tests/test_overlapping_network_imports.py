"""Overlapping source addresses retain their source network context."""

from types import SimpleNamespace

import pytest

from app.services.f5_service import (
    _collect_vip_aggregates,
    _find_f5_asset,
    _parse_destination,
    _parse_member_address,
    _upsert_member_asset,
    _Stats as F5Stats,
)
from app.services.panorama_service import _Stats, _upsert_asset
from app.services.wiz_service import _find_wiz_asset, _wiz_resource_key
from app.models.asset import AssetType


class QueryStub:
    def __init__(self, assets):
        self.assets = assets

    def filter(self, *_conditions):
        return self

    def all(self):
        return self.assets


class DatabaseStub:
    def __init__(self, assets):
        self.assets = assets

    def query(self, _model):
        return QueryStub(self.assets)


@pytest.mark.asyncio
async def test_f5_route_domains_keep_identical_vips_separate():
    class Client:
        async def list_virtuals(self):
            return [
                {"name": "vip-a", "partition": "Common", "destination": "/Common/10.0.0.5%1:443"},
                {"name": "vip-b", "partition": "Common", "destination": "/Common/10.0.0.5%2:443"},
            ]

    aggregates = await _collect_vip_aggregates(Client())
    assert len(aggregates) == 2
    assert ("10.0.0.5", "1", "Common") in aggregates
    assert ("10.0.0.5", "2", "Common") in aggregates
    assert _parse_destination("/Common/fd00::5%2.443") == ("fd00::5", "443", "2")
    assert _parse_member_address("10.0.0.6%2") == ("10.0.0.6", "2")


@pytest.mark.asyncio
async def test_f5_unqualified_vips_use_partition_scope():
    class Client:
        async def list_virtuals(self):
            return [
                {"name": "vip-a", "partition": "A", "destination": "/A/10.0.0.5:443"},
                {"name": "vip-b", "partition": "B", "destination": "/B/10.0.0.5:443"},
            ]

    aggregates = await _collect_vip_aggregates(Client())
    assert len(aggregates) == 2
    assert ("10.0.0.5", "partition:A", "A") in aggregates
    assert ("10.0.0.5", "partition:B", "B") in aggregates
    assert _parse_destination("/A/10.0.0.5:443") == ("10.0.0.5", "443", None)
    assert _parse_member_address("10.0.0.6") == ("10.0.0.6", None)


def test_f5_and_panorama_reuse_only_the_matching_source_asset():
    f5_other = SimpleNamespace(
        metadata_={"f5_integration_id": 9, "f5_route_domain": "2", "f5_partition": "Common"},
        tags=["f5:vip"],
    )
    f5_matching = SimpleNamespace(
        metadata_={"f5_integration_id": 9, "f5_route_domain": "1", "f5_partition": "Common"},
        tags=["f5:vip"],
    )
    db = DatabaseStub([f5_other, f5_matching])
    integration = SimpleNamespace(id=9, organization_id=7)
    assert _find_f5_asset(db, integration, "10.0.0.5", "vip", "1", "Common") is f5_matching

    panorama_other = SimpleNamespace(
        metadata_={"panorama_integration_id": 4, "panorama_device_group": "group-b",
                   "panorama_object_name": "server"},
        tags=[], description=None,
    )
    panorama_matching = SimpleNamespace(
        metadata_={"panorama_integration_id": 4, "panorama_device_group": "group-a",
                   "panorama_object_name": "server"},
        tags=[], description=None,
    )
    db = DatabaseStub([panorama_other, panorama_matching])
    panorama = SimpleNamespace(id=4, organization_id=7, device_group="group-a",
                               panorama_host="example.test", connection_mode="api")
    result = _upsert_asset(
        db, panorama, "10.0.0.5", AssetType.IP_ADDRESS, _Stats(),
        object_name="server", address_kind="ip", source_scope="group-a",
    )
    assert result is panorama_matching
    assert panorama_other.metadata_["panorama_device_group"] == "group-b"


def test_wiz_resources_with_the_same_provider_id_keep_account_identity():
    other = SimpleNamespace(metadata_={"wiz": {
        "id": "wiz-b", "provider_unique_id": "vm-1",
        "subscription_external_id": "account-b", "cloud_platform": "AWS",
    }})
    matching = SimpleNamespace(metadata_={"wiz": {
        "id": "wiz-a", "provider_unique_id": "vm-1",
        "subscription_external_id": "account-a", "cloud_platform": "AWS",
    }})
    db = DatabaseStub([other, matching])
    source = {"id": "wiz-a", "providerUniqueId": "vm-1",
              "subscriptionExternalId": "account-a", "cloudPlatform": "AWS"}
    assert _find_wiz_asset(db, 7, source) is matching
    assert _find_wiz_asset(DatabaseStub([other]), 7, source) is None
    assert _wiz_resource_key(source) != _wiz_resource_key({**source, "id": "wiz-b"})


def test_f5_member_reimport_drops_old_vip_links():
    member = SimpleNamespace(
        id=30, metadata_={"f5_integration_id": 9, "f5_route_domain": "1",
                          "f5_vip_links": [{"asset_id": 10, "ip": "10.0.0.10"}],
                          "f5_reachable_via_vips": ["10.0.0.10"]},
        tags=["f5:pool-member", "f5-via-vip:10.0.0.10"],
        parent_id=10, ip_address="10.0.0.20", ip_addresses=["10.0.0.20"],
    )
    vip = SimpleNamespace(id=11, metadata_={"f5_route_domain": "1"})
    integration = SimpleNamespace(id=9, organization_id=7, name="F5", bigip_host="f5.test")
    result = _upsert_member_asset(
        DatabaseStub([member]), integration, member_ip="10.0.0.20",
        route_domain="1", member_port="80", vip_ip="10.0.0.11", vip_asset=vip,
        virtual_name="new-vip", pool_name="new-pool", member_state="up",
        reset_links=True, stats=F5Stats(),
    )
    assert result is member
    assert member.metadata_["f5_vip_links"] == [{"asset_id": 11, "ip": "10.0.0.11"}]
    assert "f5-via-vip:10.0.0.10" not in member.tags
