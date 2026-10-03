"""PROWL intake accepts only independently verified proof recipes."""

import hashlib
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 - register model relationships and foreign keys
from app.api.routes import prowl, vulnerabilities
from app.api.routes.prowl import PublishFinding, _check_proof
from app.api.deps import get_current_active_user
from app.db.database import Base, get_db
from app.models.asset import Asset, AssetType
from app.models.organization import Organization
from app.models.prowl_publication import ProwlPublication
from app.models.scoped_assessment_run import ScopedAssessmentRun
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilityStatus


def packet():
    target = "https://app.example.test/search?q=__PROWL_NONCE__"
    return PublishFinding(
        organization_id=2, asset_id=7, prowl_run_id="a" * 32,
        prowl_candidate_id="b" * 32, prowl_verification_id="c" * 32,
        verification_verdict="confirmed", title="Reflected XSS", target=target,
        severity="medium", description="Script execution was observed",
        remediation="Encode untrusted content before HTML insertion",
        hunter_evidence_ids=["hunter-artifact"],
        verifier_evidence_ids=["verifier-artifact"],
        observations=[
            {"artifact_id": "hunter-artifact", "actor": "hunter", "result": {
                "operation": "check_xss", "target_template": target,
                "executed": True, "nonce": "hunter123",
            }},
            {"artifact_id": "verifier-artifact", "actor": "verifier", "result": {
                "operation": "check_xss", "target_template": target,
                "executed": True, "nonce": "verifier456",
            }},
        ],
    )


def directory_packet():
    target = "https://app.example.test/wp-includes/"
    claim = packet()
    claim.title = "Public directory listing"
    claim.target = target
    claim.severity = "low"
    claim.description = "The directory index was visible anonymously"
    claim.remediation = "Disable directory indexing"
    for observation in claim.observations:
        observation.result = {
            "operation": "http_get", "target_template": target,
            "status": 200, "content_type": "text/html", "identity": "anonymous",
            "directory_index": True, "truncated": False,
        }
    return claim


def numeric_sqli_packet():
    target = "https://app.example.test/api/item"
    baseline = hashlib.sha256(b'{"ids":[1]}').hexdigest()
    different = hashlib.sha256(b'{"ids":[]}').hexdigest()

    def result(nonce):
        hashes = (baseline, baseline, different, baseline, different, baseline)
        names = ("baseline_first", "true_first", "false_first",
                 "true_second", "false_second", "baseline_last")
        return {
            "operation": "sqli_boolean_numeric", "proof_recipe": "numeric_and_boolean_v1",
            "proof_confirmed": True, "target": target, "parameter": "id",
            "identity": "anonymous", "nonce": nonce, "method": "GET", "location": "query",
            "checks": {name: {"status": 200, "content_type": "application/json",
                              "truncated": False, "redirected": False, "body_sha256": digest}
                       for name, digest in zip(names, hashes)},
        }

    claim = packet()
    claim.title = "Numeric SQL injection"
    claim.target = target
    claim.severity = "high"
    claim.description = "Independent numeric Boolean differential was reproduced"
    claim.remediation = "Use bound SQL parameters"
    claim.observations[0].result = result("12345")
    claim.observations[1].result = result("67890")
    return claim


def owner_only_packet():
    target = "https://app.example.test/api/owner-record"
    owned = hashlib.sha256(b'{"owner_record":"fixture"}').hexdigest()
    denied = hashlib.sha256(b'{"error":"denied"}').hexdigest()

    def result(source):
        return {
            "operation": "authz_owner_only", "proof_recipe": "owner_only_cross_identity_v1",
            "policy": "owner_only", "proof_confirmed": True, "method": "GET", "target": target,
            "owner_identity": "owner", "other_identity": "other", "captured_artifact_id": source,
            "checks": {name: {"status": 403 if "anonymous" in name else 200,
                              "content_type": "application/json", "truncated": False,
                              "redirected": False, "body_sha256": denied if "anonymous" in name else owned}
                       for name in ("owner_first", "other_first", "anonymous_first",
                                    "owner_second", "other_second", "anonymous_second")},
        }

    claim = packet()
    claim.title = "Owner-only record access"
    claim.target = target
    claim.severity = "high"
    claim.description = "An unrelated identity accessed an owner-only resource"
    claim.remediation = "Enforce object ownership"
    claim.observations[0].result = result("hunter-browser")
    claim.observations[1].result = result("verifier-browser")
    return claim


def test_separate_browser_proofs_are_accepted():
    assert _check_proof(packet()) == "browser_xss"


def test_hunter_evidence_cannot_be_reused_as_verifier_evidence():
    claim = packet()
    claim.verifier_evidence_ids = claim.hunter_evidence_ids
    with pytest.raises(HTTPException, match="distinct"):
        _check_proof(claim)


def test_reflection_or_same_nonce_does_not_confirm():
    claim = packet()
    claim.observations[1].result["executed"] = False
    with pytest.raises(HTTPException, match="execution proof"):
        _check_proof(claim)
    claim.observations[1].result["executed"] = True
    claim.observations[1].result["nonce"] = "hunter123"
    with pytest.raises(HTTPException, match="execution proof"):
        _check_proof(claim)


def test_public_directory_requires_separate_matching_anonymous_observations():
    claim = directory_packet()
    assert _check_proof(claim) == "public_directory_index"
    claim.observations[1].result["identity"] = "owner"
    with pytest.raises(HTTPException, match="directory index proof"):
        _check_proof(claim)
    claim.observations[1].result["identity"] = "anonymous"
    claim.observations[1].result["target_template"] = "https://app.example.test/other/"
    with pytest.raises(HTTPException, match="directory index proof"):
        _check_proof(claim)
    claim.observations[1].result["target_template"] = claim.target
    claim.observations[1].result["truncated"] = True
    with pytest.raises(HTTPException, match="directory index proof"):
        _check_proof(claim)


def test_numeric_boolean_sqli_requires_independent_stable_differential():
    claim = numeric_sqli_packet()
    assert _check_proof(claim) == "numeric_boolean_sqli"
    claim.observations[1].result["nonce"] = "12345"
    with pytest.raises(HTTPException, match="numeric SQLi proof"):
        _check_proof(claim)
    claim.observations[1].result["nonce"] = "67890"
    claim.observations[1].result["checks"]["false_second"]["body_sha256"] = (
        claim.observations[1].result["checks"]["baseline_first"]["body_sha256"]
    )
    with pytest.raises(HTTPException, match="numeric SQLi proof"):
        _check_proof(claim)


def test_owner_only_authorization_requires_separate_captures_and_denial():
    claim = owner_only_packet()
    assert _check_proof(claim) == "owner_only_authorization"
    claim.observations[1].result["captured_artifact_id"] = "hunter-browser"
    with pytest.raises(HTTPException, match="authorization proof"):
        _check_proof(claim)
    claim.observations[1].result["captured_artifact_id"] = "verifier-browser"
    claim.observations[1].result["checks"]["other_second"]["status"] = 403
    with pytest.raises(HTTPException, match="authorization proof"):
        _check_proof(claim)


def test_validated_finding_enters_remediation_once(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, User.__table__, Asset.__table__, Vulnerability.__table__,
        ProwlPublication.__table__, ScopedAssessmentRun.__table__,
    ])
    Session = sessionmaker(bind=engine)
    with Session() as db:
        db.add(Organization(id=2, name="Fixture organization"))
        db.add(Asset(id=7, name="app.example.test", value="app.example.test",
                     asset_type=AssetType.DOMAIN, organization_id=2))
        db.commit()

    app = FastAPI()
    app.include_router(prowl.router)
    app.include_router(vulnerabilities.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[get_current_active_user] = lambda: SimpleNamespace(is_superuser=True)
    monkeypatch.setenv("PROWL_INGEST_KEY", "test-service-key")
    monkeypatch.setattr(prowl, "_maybe_auto_create_jira_ticket", lambda *_args: None)
    monkeypatch.setattr(prowl, "_maybe_auto_push_servicenow", lambda *_args: None)
    client = TestClient(app)
    payload = packet().model_dump(mode="json")
    headers = {"X-Prowl-Key": "test-service-key"}

    assert client.post("/prowl/findings", json=payload).status_code == 403
    first = client.post("/prowl/findings", json=payload, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["already_published"] is False
    agent_rows = client.get("/vulnerabilities/", params={"detected_by": "agent_family"})
    assert agent_rows.status_code == 200, agent_rows.text
    assert [row["id"] for row in agent_rows.json()] == [first.json()["id"]]
    memory = client.get("/prowl/assets/7/memory", params={"organization_id": 2}, headers=headers)
    assert memory.status_code == 200, memory.text
    assert memory.headers["Cache-Control"] == "no-store"
    assert memory.json()["context_only"] is True
    assert memory.json()["findings"][0]["id"] == first.json()["id"]
    assert memory.json()["findings"][0]["target"] == "https://app.example.test/search"
    assert "__PROWL_NONCE__" not in memory.text
    assert client.get("/prowl/assets/7/memory", params={"organization_id": 2}).status_code == 403
    assert client.get("/prowl/assets/7/memory", params={"organization_id": 3}, headers=headers).status_code == 404
    again = client.post("/prowl/findings", json=payload, headers=headers)
    assert again.status_code == 200
    assert again.json()["id"] == first.json()["id"]
    assert again.json()["already_published"] is True

    with Session() as db:
        assert db.query(Vulnerability).count() == 1

    directory = directory_packet().model_dump(mode="json")
    directory["prowl_candidate_id"] = "g" * 32
    directory["prowl_verification_id"] = "h" * 32
    listed = client.post("/prowl/findings", json=directory, headers=headers)
    assert listed.status_code == 200, listed.text
    with Session() as db:
        assert db.query(Vulnerability).count() == 2
        assert db.query(ProwlPublication).count() == 2
        finding = db.query(Vulnerability).filter_by(id=first.json()["id"]).one()
        assert finding.status == VulnerabilityStatus.OPEN
        assert finding.detected_by == "PROWL"
        assert finding.detection_confidence == "exploit_confirmed"
        assert finding.proof_of_concept == "https://app.example.test/search"
        assert "query field q" in finding.steps_to_reproduce
        assert "__PROWL_NONCE__" not in finding.steps_to_reproduce
        listing = db.query(Vulnerability).filter_by(id=listed.json()["id"]).one()
        assert listing.detected_by == "PROWL"
        assert listing.status == VulnerabilityStatus.OPEN
        assert listing.detection_confidence == "endpoint_confirmed"
        assert "anonymously" in listing.steps_to_reproduce

    sql = numeric_sqli_packet().model_dump(mode="json")
    sql["prowl_candidate_id"] = "i" * 32
    sql["prowl_verification_id"] = "j" * 32
    injected = client.post("/prowl/findings", json=sql, headers=headers)
    assert injected.status_code == 200, injected.text
    with Session() as db:
        assert db.query(Vulnerability).count() == 3
        sql_finding = db.query(Vulnerability).filter_by(id=injected.json()["id"]).one()
        assert sql_finding.detection_confidence == "exploit_confirmed"
        assert "query field id" in sql_finding.steps_to_reproduce
        assert "12345" not in sql_finding.steps_to_reproduce

    authz = owner_only_packet().model_dump(mode="json")
    authz["prowl_candidate_id"] = "k" * 32
    authz["prowl_verification_id"] = "l" * 32
    authorized = client.post("/prowl/findings", json=authz, headers=headers)
    assert authorized.status_code == 200, authorized.text
    with Session() as db:
        assert db.query(Vulnerability).count() == 4
        authz_finding = db.query(Vulnerability).filter_by(id=authorized.json()["id"]).one()
        assert authz_finding.detection_confidence == "exploit_confirmed"
        assert "unrelated test identity" in authz_finding.steps_to_reproduce
        finding = db.query(Vulnerability).filter_by(id=first.json()["id"]).one()
        finding.status = VulnerabilityStatus.RESOLVED
        db.commit()
    current = client.get("/prowl/assets/7/memory", params={"organization_id": 2}, headers=headers)
    assert current.status_code == 200
    assert next(row for row in current.json()["findings"] if row["id"] == first.json()["id"])["status"] == "resolved"

    bad = packet().model_dump(mode="json")
    bad["prowl_candidate_id"] = "d" * 32
    bad["observations"][1]["result"]["executed"] = False
    assert client.post("/prowl/findings", json=bad, headers=headers).status_code == 400
    with Session() as db:
        assert db.query(Vulnerability).count() == 4

    wrong_asset = packet().model_dump(mode="json")
    wrong_asset["prowl_candidate_id"] = "e" * 32
    wrong_asset["organization_id"] = 99
    assert client.post("/prowl/findings", json=wrong_asset, headers=headers).status_code == 404

    wrong_target = packet().model_dump(mode="json")
    wrong_target["prowl_candidate_id"] = "f" * 32
    wrong_target["target"] = "https://other.example.test/search?q=__PROWL_NONCE__"
    assert client.post("/prowl/findings", json=wrong_target, headers=headers).status_code == 400
    with Session() as db:
        assert db.query(Vulnerability).count() == 4
