"""A finding has one endpoint, with source records and evidence kept separately."""

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.database import Base
import app.models  # noqa: F401 — register relationships and foreign keys
from app.api.routes.vulnerabilities import build_vuln_response
from app.core.config import settings
from app.models.asset import Asset
from app.models.finding_provenance import FindingEvidence, FindingIdentifier, FindingObservation
from app.models.organization import Organization
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.ingestion import IngestionBatchRequest
from app.schemas.unified_results import AffectedTarget, FindingIdentifierItem, ResultType, UnifiedFinding
from app.schemas.vulnerability import VulnerabilityResponse
from app.services.ingestion_service import process_ingestion_batch


@pytest.fixture()
def db(monkeypatch):
    monkeypatch.setattr(settings, "ORACLE_AUTO_ENRICH_ON_INGEST", False)
    monkeypatch.setattr(settings, "DELPHI_AUTO_ENRICH_ON_INGEST", False)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, Scan.__table__, Vulnerability.__table__,
        FindingObservation.__table__, FindingEvidence.__table__, FindingIdentifier.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add(Organization(id=1, name="Acme"))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _report():
    return UnifiedFinding(
        id="native-db-report-1", type=ResultType.VULNERABILITY,
        source="agent", target="205.175.244.0/24",
        title="Exposed database service", severity="critical",
        affected_targets=[
            {"asset_value": "205.175.245.227", "port": 3306, "service_name": "mysql"},
            {"asset_value": "205.175.245.227", "port": 9300, "service_name": "elasticsearch"},
            {"asset_value": "205.175.245.227", "port": 3306, "service_name": "mysql"},
        ],
        evidence_items=[{
            "kind": "banner", "value": "MySQL handshake received",
            "target": {"asset_value": "205.175.245.227", "port": 3306},
        }],
        identifiers=[{"kind": "cwe", "value": "CWE-306"}],
    )


def test_one_finding_per_endpoint_with_flat_detail(db):
    request = IngestionBatchRequest(agent_id="agent-01", findings=[_report()])
    result = process_ingestion_batch(db, request, 1)
    assert result.total_submitted == 1
    assert result.created == 2
    assert len(result.results) == 2
    assert len({item.finding_id for item in result.results}) == 2
    assert db.query(Asset).count() == 1
    assert db.query(Vulnerability).count() == 2
    assert db.query(FindingObservation).count() == 2
    assert db.query(FindingEvidence).count() == 1

    by_port = {row.target_port: row for row in db.query(Vulnerability).all()}
    assert set(by_port) == {3306, 9300}
    assert all(row.asset.value == "205.175.245.227" for row in by_port.values())
    assert by_port[3306].finding_key != by_port[9300].finding_key
    assert by_port[3306].target_service_name == "mysql"
    assert by_port[3306].cwe_id == "CWE-306"

    detail = build_vuln_response(by_port[3306], db=db, include_provenance=True)
    assert detail["target_value"] == "205.175.245.227"
    assert detail["target_port"] == 3306
    assert len(detail["evidence_items"]) == 1
    assert detail["evidence_items"][0]["source_record_id"] == "native-db-report-1"
    assert "affected_targets" not in detail and "observations" not in detail
    assert VulnerabilityResponse.model_validate(detail).finding_key == by_port[3306].finding_key
    assert build_vuln_response(by_port[9300], db=db, include_provenance=True)["evidence_items"] == []

    again = process_ingestion_batch(db, request, 1)
    assert again.duplicates == 2
    assert {item.finding_id for item in again.results} == {item.finding_id for item in result.results}
    assert db.query(FindingObservation).count() == 2
    assert {row.seen_count for row in db.query(FindingObservation).all()} == {2}
    assert db.query(FindingEvidence).count() == 1


def test_one_bad_source_rolls_back_without_affecting_next_item(db):
    valid = _report().model_copy(update={"affected_targets": [AffectedTarget(asset_value="205.175.245.227", port=3306)]})
    bad = valid.model_copy(update={"source": ""})
    result = process_ingestion_batch(
        db, IngestionBatchRequest(agent_id="agent-01", findings=[bad, valid]), 1,
    )
    assert (result.errors, result.created) == (1, 1)
    assert db.query(Vulnerability).count() == 1
    assert db.query(FindingObservation).count() == 1


def test_atomic_input_rejects_packed_values():
    with pytest.raises(ValidationError, match="one asset"):
        AffectedTarget(asset_value="205.175.245.227, 205.175.244.149", port=3306)
    with pytest.raises(ValidationError, match="atomic"):
        FindingIdentifierItem(kind="cve", value="CVE-2026-1, CVE-2026-2")
    with pytest.raises(ValidationError, match="evidence target"):
        UnifiedFinding(
            type=ResultType.VULNERABILITY, source="agent", target="example.com",
            affected_targets=[{"asset_value": "192.0.2.10", "port": 3306}],
            evidence_items=[{
                "kind": "banner", "value": "response",
                "target": {"asset_value": "192.0.2.11", "port": 3306},
            }],
        )
