"""Focused contracts for provider record projection into the graph."""

from types import SimpleNamespace

import pytest

from app.models.asset import Asset, AssetStatus, AssetType
from app.services.integration_graph_service import (
    _asset_row,
    _endpoint_rows,
    _lock_key,
    _write_endpoint_batch,
    _write_vulnerability_batch,
    sync_integration_graph,
)


def test_asset_and_endpoint_identity_preserve_wiz_links():
    asset = Asset(
        id=42, organization_id=7, asset_type=AssetType.CLOUD_RESOURCE,
        name="VM", value="provider-id", status=AssetStatus.DISCOVERED,
        discovery_source="wiz", is_public=True,
        tags=["source:wiz"], metadata_={"wiz": {"id": "vm-wiz-id"}},
    )
    projected = _asset_row(asset)
    assert projected["id"] == 42
    assert projected["props"]["organization_id"] == 7
    assert projected["props"]["wiz_resource_id"] == "vm-wiz-id"
    assert projected["props"]["sources"] == ["wiz"]

    endpoint = SimpleNamespace(
        organization_id=7, integration_id=3, wiz_id="endpoint-1", asset_id=99,
        name="https://example.test:8443", host="example.test", port=8443,
        exposure_level="HIGH", is_ai=True, is_active=True, related_issue_count=1,
        endpoint_data={
            "httpResults": {"pageTitle": "Sign in", "statusCode": 403, "contentType": "text/html"},
            "hostedTechnologies": [{"technology": {"id": "tech-1", "name": "nginx"}}],
            "resources": [{"id": "vm-wiz-id", "type": "VIRTUAL_MACHINE", "providerUniqueId": "provider-id"}],
        },
        ai_components=[],
        related_issues=[{"id": "issue-1", "severity": "HIGH", "status": "OPEN"}],
    )
    row, issues, resources = _endpoint_rows(endpoint)
    assert row["key"] == "wiz:7:3:endpoint-1"
    assert row["props"]["title"] == "Sign in"
    assert row["props"]["content_type"] == "text/html"
    assert row["props"]["technology_names"] == ["nginx"]
    assert issues[0]["issue_key"] == "wiz:7:issue-1"
    assert resources[0]["resource_key"] == "wiz:7:vm-wiz-id"


class _Result:
    def __init__(self, count):
        self.count = count

    def single(self):
        return {"written": self.count}

    def consume(self):
        return None


class _Tx:
    def __init__(self):
        self.calls = []

    def run(self, statement, **params):
        self.calls.append((statement, params))
        return _Result(len(params.get("rows", [])))


def test_endpoint_batch_replaces_issue_and_resource_edges():
    tx = _Tx()
    endpoints = [{"key": "wiz:7:3:endpoint-1", "asset_id": 99, "props": {"organization_id": 7}}]
    issues = [{"endpoint_key": endpoints[0]["key"], "issue_key": "wiz:7:issue-1"}]
    resources = [{"endpoint_key": endpoints[0]["key"], "resource_key": "wiz:7:vm-1"}]
    _write_endpoint_batch(tx, endpoints, issues, resources, 7)
    assert all(token in statement for (statement, _), token in zip(tx.calls, (
        "MERGE (e:Endpoint", "DELETE r", "MERGE (i:WizIssue", "MERGE (r:WizResource",
    )))
    assert tx.calls[1][1]["keys"] == [endpoints[0]["key"]]


def test_vulnerability_batch_uses_asset_edge_and_cve_reference():
    tx = _Tx()
    _write_vulnerability_batch(tx, [{"id": 1, "asset_id": 42, "cve_id": "CVE-2026-12345", "props": {}}], 7)
    assert len(tx.calls) == 2
    assert "HAS_VULNERABILITY" in tx.calls[0][0]
    assert "REFERENCES" in tx.calls[1][0]


def test_graph_projection_rejects_bad_source_and_limit():
    with pytest.raises(ValueError):
        sync_integration_graph(7, "unknown")
    with pytest.raises(ValueError):
        sync_integration_graph(7, "wiz", limit=0)
    assert _lock_key(7, "wiz") != _lock_key(7, "crowdstrike")
