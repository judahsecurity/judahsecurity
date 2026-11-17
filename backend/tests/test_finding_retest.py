import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.db.database import Base
from app.models.asset import Asset, AssetType
from app.models.finding_validation import FindingValidation, ValidationStatus, ValidationVerdict
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus
from app.services import finding_retest as fr


@pytest.mark.parametrize("data, expected", [
    ({"verdict": "confirmed", "still_open": True, "confidence": "high"}, fr.STILL_REPRODUCIBLE),
    ({"verdict": "confirmed", "confidence": "medium"}, fr.STILL_REPRODUCIBLE),
    ({"verdict": "false_positive", "still_open": False, "confidence": "high"}, fr.FIXED),
    ({"verdict": "false_positive", "still_open": False, "confidence": "medium"}, fr.FIXED),
    ({"verdict": "false_positive", "still_open": False, "confidence": "low"}, fr.CANNOT_CONFIRM),
    ({"verdict": "false_positive", "still_open": False, "confidence": "high", "logical_mismatch": True},
     fr.CANNOT_CONFIRM),
    ({"verdict": "needs_more_evidence", "still_open": None, "confidence": "low"}, fr.CANNOT_CONFIRM),
    ({"verdict": "false_positive", "still_open": False, "confidence": "high", "error": "timeout"},
     fr.CANNOT_CONFIRM),
    (None, fr.CANNOT_CONFIRM),
])
def test_outcome_mapping(data, expected):
    assert fr.retest_outcome(data) == expected


def _vuln(status):
    return SimpleNamespace(status=status, resolved_at=None, metadata_={"keep": 1})


def test_fixed_resolves_open_finding_and_records_history():
    vuln = _vuln(VulnerabilityStatus.OPEN)
    assert fr.apply_retest_outcome(vuln, SimpleNamespace(id=9), fr.FIXED) == "resolved"
    assert vuln.status == VulnerabilityStatus.RESOLVED and vuln.resolved_at is not None
    assert vuln.metadata_["keep"] == 1
    assert vuln.metadata_["retests"][-1]["outcome"] == "fixed"
    assert vuln.metadata_["retests"][-1]["previous_status"] == "open"


def test_still_reproducible_reopens_resolved_finding():
    vuln = _vuln(VulnerabilityStatus.RESOLVED)
    assert fr.apply_retest_outcome(vuln, SimpleNamespace(id=1), fr.STILL_REPRODUCIBLE) == "open"
    assert vuln.status == VulnerabilityStatus.OPEN and vuln.resolved_at is None


@pytest.mark.parametrize("status", [VulnerabilityStatus.ACCEPTED, VulnerabilityStatus.FALSE_POSITIVE])
@pytest.mark.parametrize("outcome", fr.OUTCOMES)
def test_analyst_decisions_are_never_overridden(status, outcome):
    vuln = _vuln(status)
    assert fr.apply_retest_outcome(vuln, SimpleNamespace(id=1), outcome) is None
    assert vuln.status == status


def test_cannot_confirm_leaves_status_alone():
    vuln = _vuln(VulnerabilityStatus.IN_PROGRESS)
    assert fr.apply_retest_outcome(vuln, SimpleNamespace(id=1), fr.CANNOT_CONFIRM) is None
    assert vuln.status == VulnerabilityStatus.IN_PROGRESS
    assert len(vuln.metadata_["retests"]) == 1


# ---------------------------------------------------------------------------
# Real worker handler, stubbed native replay
# ---------------------------------------------------------------------------

@pytest.fixture
def worker_db(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Asset.__table__, Vulnerability.__table__, FindingValidation.__table__,
    ])
    factory = sessionmaker(bind=engine)
    db = factory()
    db.add(Asset(id=1, name="app.example.com", organization_id=7, asset_type=AssetType.SUBDOMAIN,
                 value="app.example.com"))
    db.flush()
    db.add(Vulnerability(id=10, title="Open redirect", severity=Severity.MEDIUM, asset_id=1,
                         detected_by="nuclei", template_id="open-redirect",
                         status=VulnerabilityStatus.OPEN, metadata_={"url": "https://app.example.com/r"}))
    db.commit()
    monkeypatch.setenv("AEGIS_VALIDATOR_MODE", "native")
    return factory


def _run(factory, monkeypatch, purpose, verdict):
    from app.services import detection_pattern_service, finding_revalidation_service
    from app.workers.scanner_worker import ScannerWorker

    seen = {}

    async def fake_revalidate(payload):
        seen["payload"] = payload
        return verdict

    monkeypatch.setattr(finding_revalidation_service, "revalidate_finding", fake_revalidate)
    pattern_calls = []
    monkeypatch.setattr(detection_pattern_service, "evaluate_template", lambda *a, **k: pattern_calls.append(k))
    db = factory()
    validation = FindingValidation(vulnerability_id=10, organization_id=7, status=ValidationStatus.QUEUED,
                                   purpose=purpose, retest_notes="Patched in 2.4.1")
    db.add(validation)
    db.commit()
    worker = ScannerWorker.__new__(ScannerWorker)
    worker.get_db_session = factory
    asyncio.run(worker.handle_validate_finding({"validation_id": validation.id, "vulnerability_id": 10}))
    db = factory()
    return db.get(FindingValidation, validation.id), db.get(Vulnerability, 10), seen, pattern_calls


def test_worker_retest_marks_fixed_finding_resolved(worker_db, monkeypatch):
    validation, vuln, seen, pattern_calls = _run(worker_db, monkeypatch, "retest", {
        "verdict": "false_positive", "still_open": False, "confidence": "high", "reasoning": "302 removed",
    })
    assert seen["payload"]["purpose"] == "retest"
    assert seen["payload"]["retest_notes"] == "Patched in 2.4.1"
    assert validation.status == ValidationStatus.COMPLETED
    assert validation.verdict == ValidationVerdict.FALSE_POSITIVE
    assert validation.retest_outcome == "fixed"
    assert vuln.status == VulnerabilityStatus.RESOLVED
    assert vuln.metadata_["retests"][0]["validation_id"] == validation.id
    assert pattern_calls == []  # a fix is not evidence of a bad template


def test_worker_plain_validation_is_unchanged(worker_db, monkeypatch):
    validation, vuln, _, pattern_calls = _run(worker_db, monkeypatch, "validate", {
        "verdict": "false_positive", "still_open": False, "confidence": "high",
    })
    assert validation.retest_outcome is None
    assert vuln.status == VulnerabilityStatus.OPEN
    assert "retests" not in (vuln.metadata_ or {})
    assert len(pattern_calls) == 1


def test_retest_endpoint_queues_retest_and_reuses_in_flight(worker_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api import deps
    from app.api.routes import vulnerabilities
    from app.db.database import get_db
    from app.models.user import UserRole

    monkeypatch.setattr(vulnerabilities, "send_validation_to_sqs", lambda v: False)
    api = FastAPI()
    api.include_router(vulnerabilities.router)
    user = SimpleNamespace(id=1, organization_id=7, is_superuser=False, role=UserRole.ANALYST, is_active=True)

    def _db():
        session = worker_db()
        try:
            yield session
        finally:
            session.close()

    api.dependency_overrides[get_db] = _db
    api.dependency_overrides[deps.get_current_active_user] = lambda: user
    client = TestClient(api)
    first = client.post("/vulnerabilities/10/retest", json={"notes": "Upgraded to 2.4.1"}).json()
    assert first["purpose"] == "retest" and first["status"] == "queued"
    assert first["retest_notes"] == "Upgraded to 2.4.1"
    again = client.post("/vulnerabilities/10/validate").json()
    assert again["id"] == first["id"]  # one replay in flight per finding
    user.organization_id = 8
    assert client.post("/vulnerabilities/10/retest").status_code == 403
