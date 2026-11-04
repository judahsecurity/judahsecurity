"""Verify saved Censys mappings reach imported asset and finding rows."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.services import censys_asm_service


def test_sync_applies_canonical_and_custom_mappings():
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    added = []
    db.add.side_effect = added.append

    def flush():
        for row in added:
            if isinstance(row, Asset) and row.id is None:
                row.id = 10

    db.flush.side_effect = flush
    integration = SimpleNamespace(
        organization_id=7,
        get_api_key=lambda: "test-key",
        import_assets=True,
        import_vulnerabilities=True,
        field_mappings=[
            {"entity": "host", "source_path": "host.operating_system.product", "target": "operating_system"},
            {"entity": "host", "source_path": "host.location.country", "target": "custom.reported_country"},
            {"entity": "risk", "source_path": "score", "target": "cvss_score"},
            {"entity": "risk", "source_path": "details.evidence", "target": "evidence"},
        ],
    )

    with patch.object(censys_asm_service, "CensysAsmClient") as client_class:
        client = client_class.return_value
        client.get_hosts = AsyncMock(return_value=[{
            "assetId": "192.0.2.1",
            "host": {"operating_system": {"product": "Linux"}, "location": {"country": "US"}},
        }])
        client.get_domains = AsyncMock(return_value=[])
        client.get_subdomains = AsyncMock(return_value=[])
        client.get_certificates = AsyncMock(return_value=[])
        client.get_risk_instances = AsyncMock(return_value=[{
            "title": "Exposed service", "severity": "high", "score": "8.1",
            "details": {"evidence": "Public service observed"},
            "affectedAssets": [{"id": "192.0.2.1", "type": "HOST"}],
        }])
        result = asyncio.run(censys_asm_service.sync_integration(db, integration))

    assert result["ok"] is True
    assert result["assets_created"] == 1
    assert result["vulns_created"] == 1
    asset = next(row for row in added if isinstance(row, Asset))
    finding = next(row for row in added if isinstance(row, Vulnerability))
    assert asset.organization_id == 7
    assert asset.operating_system == "Linux"
    assert asset.metadata_["censys_asm"]["custom"]["reported_country"] == "US"
    assert finding.asset_id == asset.id
    assert finding.cvss_score == 8.1
    assert finding.evidence == "Public service observed"


def test_source_failure_is_recorded_as_failed_sync():
    db = MagicMock()
    integration = SimpleNamespace(
        organization_id=7, get_api_key=lambda: "test-key",
        import_assets=True, import_vulnerabilities=True, field_mappings=[],
    )
    with patch.object(censys_asm_service, "CensysAsmClient") as client_class:
        client_class.return_value.get_hosts = AsyncMock(
            side_effect=censys_asm_service.CensysApiError("Censys ASM GET /v1/assets/hosts returned HTTP 429")
        )
        result = asyncio.run(censys_asm_service.sync_integration(db, integration))
    assert result["ok"] is False
    assert integration.last_sync_ok is False
    assert "429" in integration.last_error
    db.commit.assert_called_once()
