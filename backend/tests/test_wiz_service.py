"""Focused tests for the Wiz GraphQL client and normalization helpers."""

from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.asset import Asset, AssetType
from app.models.organization import Organization
from app.models.wiz_integration import WizApplicationEndpoint, WizIntegration
from app.api.routes.integrations import list_wiz_application_endpoints
from app.services.wiz_service import (
    WizApiError,
    WizClient,
    _asset_value,
    _endpoint_is_ai,
    _cve_id,
    _is_internet_exposed,
    _is_virtual_machine,
    _map_severity,
    _parse_datetime,
    _Stats,
    _sync_application_endpoints,
    _sync_virtual_machines,
    claim_sync,
)
from app.models.vulnerability import Severity


def test_wiz_client_normalizes_graphql_endpoint():
    client = WizClient(
        "https://api.us17.app.wiz.io",
        "client",
        "secret",
    )
    assert client.api_endpoint == "https://api.us17.app.wiz.io/graphql"


@pytest.mark.parametrize(
    "url",
    [
        "http://api.us17.app.wiz.io/graphql",
        "https://127.0.0.1/graphql",
        "https://wiz.io.attacker.example/graphql",
        "https://user:pass@api.us17.app.wiz.io/graphql",
    ],
)
def test_wiz_client_rejects_unsafe_endpoints(url):
    with pytest.raises(WizApiError):
        WizClient(url, "client", "secret")


@pytest.mark.asyncio
async def test_vulnerability_findings_follow_cursor_pagination():
    client = WizClient("https://api.us17.app.wiz.io/graphql", "client", "secret")
    client.graphql = AsyncMock(
        side_effect=[
            {
                "vulnerabilityFindings": {
                    "nodes": [{"id": "one"}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                }
            },
            {
                "vulnerabilityFindings": {
                    "nodes": [{"id": "two"}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
        ]
    )

    findings = await client.get_vulnerability_findings()

    assert [item["id"] for item in findings] == ["one", "two"]
    assert client.graphql.await_args_list[1].args[1]["after"] == "cursor-1"


@pytest.mark.asyncio
async def test_vm_inventory_paginates_and_deduplicates_wiz_ids():
    client = WizClient("https://api.us17.app.wiz.io/graphql", "client", "secret")
    client.graphql = AsyncMock(side_effect=[
        {"cloudResourcesV2": {"totalCount": 2, "nodes": [
            {"id": "vm-1", "type": "VIRTUAL_MACHINE", "providerUniqueId": "i-1",
             "isAccessibleFromInternet": True, "isOpenToAllInternet": False,
             "cloudAccount": {"externalId": "account-1"},
             "typeFields": {"operatingSystem": "LINUX", "ipAddresses": ["10.0.0.1"]}},
        ], "pageInfo": {"hasNextPage": True, "endCursor": "next"}}},
        {"cloudResourcesV2": {"totalCount": 2, "nodes": [
            {"id": "vm-1", "type": "VIRTUAL_MACHINE"},
            {"id": "vm-2", "type": "VIRTUAL_MACHINE", "providerUniqueId": "i-2",
             "isAccessibleFromInternet": True, "isOpenToAllInternet": True,
             "typeFields": {"ipAddresses": []}},
        ], "pageInfo": {"hasNextPage": False}}},
    ])
    vms = [vm for page in [page async for page in client.iter_virtual_machines(exposed_only=True)] for vm in page]
    assert [vm["id"] for vm in vms] == ["vm-1", "vm-2"]
    assert vms[0]["subscriptionExternalId"] == "account-1"
    assert vms[0]["ipAddresses"] == ["10.0.0.1"]
    assert vms[1]["hasWideInternetExposure"] is True
    assert client.virtual_machines_total_count == 2
    assert client.graphql.await_args_list[0].args[1]["filterBy"]["isAccessibleFromInternet"] == {"equals": True}
    assert client.graphql.await_args_list[1].args[1]["after"] == "next"


@pytest.mark.asyncio
async def test_vm_inventory_imports_assets_without_vulnerability_findings():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False) as db:
        org = Organization(name="Wiz VM test")
        db.add(org)
        db.flush()
        integration = WizIntegration(
            organization_id=org.id, connection_name="Wiz", api_endpoint="https://api.us17.app.wiz.io/graphql",
            client_id_encrypted="test", client_secret_encrypted="test",
            import_assets=True, internet_exposed_only=True,
        )
        db.add(integration)
        db.commit()

        class Client:
            virtual_machines_total_count = 2

            async def iter_virtual_machines(self, *, exposed_only):
                assert exposed_only is True
                yield [{"id": "vm-1", "name": "VM one", "providerUniqueId": "i-1",
                        "cloudPlatform": "AWS", "operatingSystem": "LINUX",
                        "ipAddresses": ["10.0.0.1"], "hasLimitedInternetExposure": True}]
                yield [{"id": "vm-2", "name": "VM two", "providerUniqueId": "i-2",
                        "cloudPlatform": "Azure", "ipAddresses": [], "hasWideInternetExposure": True}]

        stats = _Stats()
        await _sync_virtual_machines(db, integration, Client(), stats)
        await _sync_virtual_machines(db, integration, Client(), _Stats())
        assets = db.query(Asset).order_by(Asset.value).all()
        assert [asset.value for asset in assets] == ["i-1", "i-2"]
        assert all(asset.is_public for asset in assets)
        assert assets[0].ip_addresses == ["10.0.0.1"]
        assert stats.virtual_machines_seen == stats.virtual_machines_total_count == 2
        assert stats.assets_created == 2
    engine.dispose()


def test_wiz_vm_and_exposure_classification():
    asset = {
        "__typename": "VulnerableAssetVirtualMachine",
        "providerUniqueId": "i-123",
        "hasLimitedInternetExposure": True,
    }
    assert _is_virtual_machine(asset) is True
    assert _is_internet_exposed(asset) is True
    assert _asset_value(asset) == "i-123"


def test_wiz_finding_normalization():
    assert _cve_id({"detailedName": "openssl CVE-2025-12345"}) == "CVE-2025-12345"
    assert _map_severity("CRITICAL") == Severity.CRITICAL
    assert _map_severity("unknown") == Severity.MEDIUM
    assert _parse_datetime("2026-01-01T03:00:00+03:00").isoformat() == "2026-01-01T00:00:00"
    assert _endpoint_is_ai({"hostedTechnologies": [{"technology": {"categories": [
        {"stackLayer": "MACHINE_LEARNING_AND_AI"},
    ]}}]}) is True


@pytest.mark.asyncio
async def test_application_endpoint_and_direct_issue_pagination():
    client = WizClient("https://api.us17.app.wiz.io/graphql", "client", "secret")
    client.graphql = AsyncMock(side_effect=[
        {"applicationEndpoints": {"nodes": [{"id": "endpoint-1"}], "pageInfo": {"hasNextPage": True, "endCursor": "next"}}},
        {"applicationEndpoints": {"nodes": [{"id": "endpoint-1"}, {"id": "endpoint-2"}], "pageInfo": {"hasNextPage": False}}},
        {"cloudResources": {"nodes": [{"id": "endpoint-1", "graphEntity": {
            "id": "endpoint-1", "type": "ENDPOINT", "relatedIssues": {
                "totalCount": 2, "nodes": [{"id": "issue-1"}],
                "pageInfo": {"hasNextPage": True, "endCursor": "issue-next"},
            },
        }}], "pageInfo": {"hasNextPage": False}}},
        {"graphEntity": {"id": "endpoint-1", "relatedIssues": {
            "totalCount": 2, "nodes": [{"id": "issue-2"}],
            "pageInfo": {"hasNextPage": False},
        }}},
    ])
    endpoints = [item for batch in [batch async for batch in client.iter_application_endpoints()] for item in batch]
    issues = [item for batch in [batch async for batch in client.iter_endpoint_issues()] for item in batch]
    assert [item["id"] for item in endpoints] == ["endpoint-1", "endpoint-2"]
    assert [item["id"] for item in issues[0]["issues"]] == ["issue-1", "issue-2"]
    assert client.graphql.await_args_list[1].args[1]["after"] == "next"
    assert client.graphql.await_args_list[3].args[1] == {"id": "endpoint-1", "after": "issue-next"}


@pytest.mark.asyncio
async def test_endpoint_import_is_idempotent_and_preserves_direct_issue_links():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False) as db:
        org = Organization(name="Wiz endpoint test")
        db.add(org)
        db.flush()
        integration = WizIntegration(
            organization_id=org.id, connection_name="Wiz", api_endpoint="https://api.us17.app.wiz.io/graphql",
            client_id_encrypted="test", client_secret_encrypted="test", import_assets=True,
        )
        db.add(integration)
        db.commit()
        endpoint = {
            "id": "endpoint-1", "name": "https://app.example.org:8443", "host": "app.example.org",
            "port": 8443, "portStatus": "OPEN", "exposureLevel": "HIGH",
            "httpResults": {"statusCode": 403, "pageTitle": "Sign in"},
            "resources": [{"id": "vm-1", "type": "VIRTUAL_MACHINE"}],
            "issueAnalytics": {"issueCount": 1},
            "hostedTechnologies": [],
        }

        class Client:
            PAGE_SIZE = 100

            def __init__(self, include_ai_path=True):
                self.include_ai_path = include_ai_path

            async def iter_application_endpoints(self, *, ids=None):
                yield [endpoint]

            async def iter_endpoint_issues(self):
                yield [{"id": "endpoint-1", "issue_count": 1, "issues": [
                    {"id": "issue-1", "severity": "HIGH", "status": "OPEN"},
                ]}]

            async def iter_ai_endpoint_paths(self):
                if not self.include_ai_path:
                    yield []
                    return
                yield [{"entities": [
                    {"id": "agent-1", "type": "AI_AGENT", "name": "Agent"},
                    {"id": "vm-1", "type": "VIRTUAL_MACHINE", "name": "VM"},
                    {"id": "endpoint-1", "type": "ENDPOINT", "name": endpoint["name"]},
                ]}]

        await _sync_application_endpoints(db, integration, Client(), _Stats())
        await _sync_application_endpoints(db, integration, Client(), _Stats())
        assert db.query(WizApplicationEndpoint).count() == 1
        assert db.query(Asset).count() == 1
        row = db.query(WizApplicationEndpoint).one()
        asset = db.query(Asset).one()
        assert row.asset_id == asset.id
        assert asset.asset_type == AssetType.URL
        assert asset.http_status == 403 and asset.http_title == "Sign in"
        assert row.is_ai is True
        assert row.ai_components[0]["id"] == "agent-1"
        assert row.endpoint_data["resources"][0]["id"] == "vm-1"
        assert row.related_issues[0]["id"] == "issue-1"
        assert row.related_issue_count == 1
        await _sync_application_endpoints(db, integration, Client(include_ai_path=False), _Stats())
        db.refresh(row)
        assert row.is_ai is False
        assert row.ai_components == []
    engine.dispose()


def test_wiz_endpoint_listing_is_tenant_scoped_and_sync_claim_is_exclusive():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False) as db:
        first = Organization(name="First Wiz tenant")
        second = Organization(name="Second Wiz tenant")
        db.add_all([first, second])
        db.flush()
        connections = [WizIntegration(
            organization_id=org.id, connection_name="Wiz", api_endpoint="https://api.us17.app.wiz.io/graphql",
            client_id_encrypted="test", client_secret_encrypted="test", is_active=True,
        ) for org in (first, second)]
        db.add_all(connections)
        db.flush()
        db.add_all([WizApplicationEndpoint(
            integration_id=connection.id, organization_id=connection.organization_id,
            wiz_id=f"endpoint-{connection.id}", is_ai=True, is_active=True,
            endpoint_data={"name": f"https://{connection.id}.example.org"}, related_issues=[],
        ) for connection in connections])
        db.commit()

        page = list_wiz_application_endpoints(
            connections[0].id, limit=25, offset=0, ai_only=True, exposure_level=None,
            db=db, current_user=SimpleNamespace(organization_id=first.id),
        )
        assert page["total"] == 1
        assert page["items"][0]["id"] == f"endpoint-{connections[0].id}"
        with pytest.raises(HTTPException) as exc:
            list_wiz_application_endpoints(
                connections[1].id, limit=25, offset=0, ai_only=False, exposure_level=None,
                db=db, current_user=SimpleNamespace(organization_id=first.id),
            )
        assert exc.value.status_code == 404

        assert claim_sync(db, connections[0].id) is True
        assert claim_sync(db, connections[0].id) is False
    engine.dispose()
