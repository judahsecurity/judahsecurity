"""A multi-target source record stays atomic and idempotent."""

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.database import Base
import app.models  # noqa: F401 — register relationships and foreign keys
from app.models.asset import Asset, AssetType
from app.models.finding_provenance import (
    FindingEvidence, FindingIdentifier, FindingObservation, FindingObservationTarget,
    FindingTarget,
)
from app.models.organization import Organization
from app.models.scan import Scan
from app.models.vulnerability import Severity, Vulnerability
from app.schemas.unified_results import AffectedTarget, FindingIdentifierItem, ResultType, UnifiedFinding
from app.services.finding_provenance_service import record_finding_sighting, source_record_key
from app.api.routes.vulnerabilities import build_vuln_response
from app.core.config import settings
from app.schemas.ingestion import IngestionBatchRequest
from app.schemas.vulnerability import VulnerabilityResponse
from app.services.ingestion_service import process_ingestion_batch


def test_multi_target_record_is_normalized_and_repeatable():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, Scan.__table__, Vulnerability.__table__,
        FindingTarget.__table__, FindingObservation.__table__,
        FindingObservationTarget.__table__, FindingEvidence.__table__,
        FindingIdentifier.__table__,
    ])
    db = sessionmaker(bind=engine)()
    try:
        db.add(Organization(id=1, name="Acme"))
        db.flush()
        anchor = Asset(
            organization_id=1, name="205.175.244.0/24", value="205.175.244.0/24",
            asset_type=AssetType.IP_RANGE,
        )
        db.add(anchor)
        db.flush()
        canonical = Vulnerability(
            title="Exposed database services", severity=Severity.CRITICAL,
            asset_id=anchor.id,
        )
        db.add(canonical)
        db.flush()
        seen = datetime(2026, 7, 28, 23, 11)
        finding = UnifiedFinding(
            id="native-db-report-1", type=ResultType.VULNERABILITY,
            source="agent", target=anchor.value,
            title="Exposed database services", severity="critical",
            timestamp=seen,
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

        observation = record_finding_sighting(
            db, organization_id=1, vulnerability=canonical,
            asset=anchor, finding=finding, source_instance="agent-01",
        )
        db.commit()
        assert canonical.finding_key == f"F-{canonical.id:06d}"
        assert observation.source_record_key == source_record_key(finding)
        assert db.query(FindingObservation).count() == 1
        assert db.query(FindingTarget).count() == 2
        assert db.query(FindingObservationTarget).count() == 2
        assert db.query(FindingEvidence).count() == 1
        assert db.query(FindingIdentifier).count() == 1
        assert {target.port for target in db.query(FindingTarget).all()} == {3306, 9300}
        assert {target.asset.value for target in db.query(FindingTarget).all()} == {"205.175.245.227"}
        evidence = db.query(FindingEvidence).one()
        assert evidence.target.port == 3306
        detail = build_vuln_response(canonical, db=db, include_provenance=True)
        assert len(detail["affected_targets"]) == 2
        assert len(detail["observations"]) == 1
        assert sorted(detail["observations"][0]["target_ids"]) == sorted(
            item["id"] for item in detail["affected_targets"]
        )
        assert detail["observations"][0]["evidence_items"][0]["target_id"] == evidence.target_id
        assert len(VulnerabilityResponse.model_validate(detail).affected_targets) == 2

        repeat = finding.model_copy(update={"timestamp": seen + timedelta(days=1), "title": "Updated title"})
        record_finding_sighting(
            db, organization_id=1, vulnerability=canonical,
            asset=anchor, finding=repeat, source_instance="agent-01",
        )
        db.commit()
        assert db.query(FindingObservation).count() == 1
        assert db.query(FindingTarget).count() == 2
        assert db.query(FindingEvidence).count() == 1
        assert db.query(FindingObservation).one().seen_count == 2

        other_source = finding.model_copy(update={"source": "wiz"})
        record_finding_sighting(
            db, organization_id=1, vulnerability=canonical,
            asset=anchor, finding=other_source, source_instance="wiz-01",
        )
        db.commit()
        assert db.query(FindingObservation).count() == 2
        assert db.query(FindingTarget).count() == 2

        db.add(Organization(id=2, name="Other"))
        db.flush()
        other_asset = Asset(
            organization_id=2, name="other.example", value="other.example",
            asset_type=AssetType.DOMAIN,
        )
        db.add(other_asset)
        db.flush()
        with pytest.raises(ValueError, match="one organization"):
            record_finding_sighting(
                db, organization_id=1, vulnerability=canonical,
                asset=other_asset, finding=finding, source_instance="agent-01",
            )
    finally:
        db.close()
        engine.dispose()


def test_atomic_input_rejects_packed_values():
    with pytest.raises(ValidationError, match="one asset"):
        AffectedTarget(asset_value="205.175.245.227, 205.175.244.149", port=3306)
    with pytest.raises(ValidationError, match="atomic"):
        FindingIdentifierItem(kind="cve", value="CVE-2026-1, CVE-2026-2")


def test_ingestion_rolls_back_one_bad_record_and_reuses_source_identity(monkeypatch):
    monkeypatch.setattr(settings, "ORACLE_AUTO_ENRICH_ON_INGEST", False)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, Scan.__table__, Vulnerability.__table__,
        FindingTarget.__table__, FindingObservation.__table__,
        FindingObservationTarget.__table__, FindingEvidence.__table__,
        FindingIdentifier.__table__,
    ])
    db = sessionmaker(bind=engine)()
    try:
        db.add(Organization(id=1, name="Acme"))
        db.commit()
        valid = UnifiedFinding(
            id="external-123", type=ResultType.VULNERABILITY, source="agent",
            target="205.175.244.0/24", title="Exposed database services",
            affected_targets=[
                {"asset_value": "205.175.245.227", "port": 3306, "service_name": "mysql"},
            ],
        )
        bad = valid.model_copy(update={"source": ""})
        result = process_ingestion_batch(
            db, IngestionBatchRequest(agent_id="agent-01", findings=[bad, valid]), 1,
        )
        assert (result.errors, result.created) == (1, 1)
        assert db.query(Vulnerability).count() == 1
        assert db.query(FindingTarget).count() == 1
        assert db.query(FindingObservation).count() == 1
        assert db.query(Asset).count() == 2  # scope anchor and affected IP

        rediscovered = valid.model_copy(update={"title": "New vendor wording"})
        again = process_ingestion_batch(
            db, IngestionBatchRequest(agent_id="agent-01", findings=[rediscovered]), 1,
        )
        assert again.duplicates == 1
        assert again.results[0].finding_id == result.results[1].finding_id
        assert db.query(FindingObservation).one().seen_count == 2
    finally:
        db.close()
        engine.dispose()
