"""Focused tests for the Wiz GraphQL client and normalization helpers."""

from unittest.mock import AsyncMock

import pytest

from app.services.wiz_service import (
    WizApiError,
    WizClient,
    _asset_value,
    _cve_id,
    _is_internet_exposed,
    _is_virtual_machine,
    _map_severity,
    _parse_datetime,
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
