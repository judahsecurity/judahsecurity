"""Receive independently verified PROWL findings into Aegis remediation tracking."""

from __future__ import annotations

import hmac
import json
import os
import re
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.asset import Asset
from app.models.prowl_publication import ProwlPublication
from app.models.scoped_assessment_run import ScopedAssessmentRun
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus
from app.api.routes.vulnerabilities import _maybe_auto_create_jira_ticket, _maybe_auto_push_servicenow


router = APIRouter(prefix="/prowl", tags=["PROWL findings"])


class EvidenceObservation(BaseModel):
    artifact_id: str = Field(min_length=8, max_length=128)
    actor: Literal["hunter", "verifier"]
    result: dict


class PublishFinding(BaseModel):
    organization_id: int = Field(gt=0)
    asset_id: int = Field(gt=0)
    prowl_run_id: str = Field(min_length=8, max_length=64)
    prowl_candidate_id: str = Field(min_length=8, max_length=64)
    prowl_verification_id: str = Field(min_length=8, max_length=64)
    verification_verdict: Literal["confirmed"]
    title: str = Field(min_length=1, max_length=500)
    target: str = Field(min_length=1, max_length=2048)
    severity: Severity
    description: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    hunter_evidence_ids: list[str] = Field(min_length=1)
    verifier_evidence_ids: list[str] = Field(min_length=1)
    observations: list[EvidenceObservation] = Field(min_length=2)


def _require_prowl_key(x_prowl_key: str = Header(default="")) -> None:
    configured = os.environ.get("PROWL_INGEST_KEY", "")
    if not configured or not hmac.compare_digest(x_prowl_key, configured):
        raise HTTPException(status_code=403, detail="PROWL service authorization required")


def _target_host(value: str) -> str:
    parsed = urlsplit(value if "://" in value else "https://" + value)
    return (parsed.hostname or "").lower().rstrip(".")


def _memory_target(value: str | None) -> str | None:
    """Return a URL without credentials, query values, or fragments."""
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return None
    return f"{parsed.scheme.lower()}://{host}{port}{parsed.path or '/'}"[:512]


@router.get("/assets/{asset_id}/memory")
def asset_memory(
    asset_id: int,
    organization_id: int,
    response: Response,
    db: Session = Depends(get_db),
    _: None = Depends(_require_prowl_key),
):
    """Bounded, current Aegis finding context for a PROWL run on one asset.

    This is context only. PROWL still requires fresh hunter and verifier proof.
    """
    asset = db.query(Asset).filter_by(id=asset_id, organization_id=organization_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Assessment asset not found in organization")
    response.headers["Cache-Control"] = "no-store"
    rows = (
        db.query(Vulnerability)
        .filter(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.last_detected.desc(), Vulnerability.id.desc())
        .limit(20)
        .all()
    )
    return {
        "asset_id": asset_id,
        "organization_id": organization_id,
        "context_only": True,
        "findings": [
            {
                "id": row.id,
                "title": row.title[:200],
                "status": row.status.value if row.status else "unknown",
                "severity": row.severity.value if row.severity else "info",
                "detected_by": row.detected_by,
                "detection_confidence": row.detection_confidence,
                "target": _memory_target(row.proof_of_concept),
                "last_detected": row.last_detected.isoformat() if row.last_detected else None,
            }
            for row in rows
        ],
    }


def _numeric_sql_proof_valid(result: dict) -> bool:
    if (result.get("operation") != "sqli_boolean_numeric"
            or result.get("proof_recipe") != "numeric_and_boolean_v1"
            or result.get("proof_confirmed") is not True
            or result.get("method") != "GET" or result.get("location") != "query"
            or not isinstance(result.get("target"), str) or not result["target"]
            or not isinstance(result.get("parameter"), str) or not result["parameter"]
            or not re.fullmatch(r"[1-9][0-9]{4}", str(result.get("nonce", "")))):
        return False
    names = ("baseline_first", "true_first", "false_first",
             "true_second", "false_second", "baseline_last")
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(isinstance(checks.get(name), dict) for name in names):
        return False
    rows = [checks[name] for name in names]
    if any(row.get("status") != 200 or row.get("truncated") is not False
           or row.get("redirected") is not False
           or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("body_sha256", ""))) for row in rows):
        return False
    if not rows[0].get("content_type") or any(row.get("content_type") != rows[0]["content_type"] for row in rows):
        return False
    hashes = [row["body_sha256"] for row in rows]
    return hashes[0] == hashes[1] == hashes[3] == hashes[5] and hashes[2] == hashes[4] and hashes[2] != hashes[0]


def _owner_only_proof_valid(result: dict) -> bool:
    if (result.get("operation") != "authz_owner_only"
            or result.get("proof_recipe") != "owner_only_cross_identity_v1"
            or result.get("policy") != "owner_only" or result.get("method") != "GET"
            or result.get("proof_confirmed") is not True
            or not isinstance(result.get("target"), str) or not result["target"]
            or not isinstance(result.get("owner_identity"), str) or not result["owner_identity"]
            or not isinstance(result.get("other_identity"), str) or not result["other_identity"]
            or result["owner_identity"] == result["other_identity"]):
        return False
    names = ("owner_first", "other_first", "anonymous_first",
             "owner_second", "other_second", "anonymous_second")
    checks = result.get("checks")
    if not isinstance(checks, dict) or not all(isinstance(checks.get(name), dict) for name in names):
        return False
    rows = [checks[name] for name in names]
    if any(row.get("truncated") is not False or row.get("redirected") is not False
           or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("body_sha256", ""))) for row in rows):
        return False
    owner, other, anon, owner_again, other_again, anon_again = rows
    if (owner.get("status") != other.get("status") or owner.get("status") != 200
            or owner_again.get("status") != other_again.get("status") or owner_again.get("status") != 200
            or anon.get("status") not in (401, 403, 404) or anon_again.get("status") != anon.get("status")):
        return False
    if (not owner.get("content_type") or owner.get("content_type") != other.get("content_type")
            or owner.get("content_type") != owner_again.get("content_type")
            or owner.get("content_type") != other_again.get("content_type")):
        return False
    digest = owner["body_sha256"]
    return (digest == other["body_sha256"] == owner_again["body_sha256"] == other_again["body_sha256"]
            and anon["body_sha256"] == anon_again["body_sha256"] != digest)


def _check_proof(packet: PublishFinding) -> str:
    if set(packet.hunter_evidence_ids) & set(packet.verifier_evidence_ids):
        raise HTTPException(status_code=400, detail="Hunter and verifier evidence must be distinct")
    hunter = {row.artifact_id: row for row in packet.observations if row.actor == "hunter"}
    verifier = {row.artifact_id: row for row in packet.observations if row.actor == "verifier"}
    if not set(packet.hunter_evidence_ids).issubset(hunter) or not set(packet.verifier_evidence_ids).issubset(verifier):
        raise HTTPException(status_code=400, detail="Evidence roles do not match the publication receipt")
    matched_xss = any(
        h.result.get("operation") == "check_xss"
        and v.result.get("operation") == "check_xss"
        and h.result.get("executed") is True
        and v.result.get("executed") is True
        and h.result.get("target_template") == packet.target == v.result.get("target_template")
        and h.result.get("nonce") and v.result.get("nonce")
        and h.result["nonce"] != v.result["nonce"]
        for h in hunter.values() for v in verifier.values()
    )
    matched_directory = any(
        h.result.get("operation") == "http_get"
        and v.result.get("operation") == "http_get"
        and h.result.get("directory_index") is True
        and v.result.get("directory_index") is True
        and h.result.get("status") == v.result.get("status") == 200
        and h.result.get("content_type") == v.result.get("content_type") == "text/html"
        and h.result.get("identity") == v.result.get("identity") == "anonymous"
        and h.result.get("truncated") is False
        and v.result.get("truncated") is False
        and h.result.get("target_template") == packet.target == v.result.get("target_template")
        for h in hunter.values() for v in verifier.values()
    )
    matched_sqli = any(
        _numeric_sql_proof_valid(h.result) and _numeric_sql_proof_valid(v.result)
        and h.result.get("target") == packet.target == v.result.get("target")
        and h.result.get("parameter") == v.result.get("parameter")
        and h.result.get("identity") == v.result.get("identity")
        and h.result.get("nonce") != v.result.get("nonce")
        for h in hunter.values() for v in verifier.values()
    )
    matched_authz = any(
        _owner_only_proof_valid(h.result) and _owner_only_proof_valid(v.result)
        and h.result.get("target") == packet.target == v.result.get("target")
        and h.result.get("owner_identity") == v.result.get("owner_identity")
        and h.result.get("other_identity") == v.result.get("other_identity")
        and h.result.get("captured_artifact_id") and v.result.get("captured_artifact_id")
        and h.result["captured_artifact_id"] != v.result["captured_artifact_id"]
        for h in hunter.values() for v in verifier.values()
    )
    if not matched_xss and not matched_directory and not matched_sqli and not matched_authz:
        raise HTTPException(status_code=400, detail="Independent browser execution proof, public directory index proof, numeric SQLi proof, or owner-only authorization proof is required")
    return ("browser_xss" if matched_xss else "public_directory_index" if matched_directory
            else "numeric_boolean_sqli" if matched_sqli else "owner_only_authorization")


def _reproduction_steps(packet: PublishFinding, proof_kind: str) -> str:
    """Give remediation owners a repeatable procedure without credential or payload values."""
    target = _memory_target(packet.target) or "the assessed endpoint"
    if proof_kind == "browser_xss":
        names = sorted({name for name, _ in parse_qsl(urlsplit(packet.target).query)
                        if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name)})[:8]
        field = f" using query field {', '.join(names)}" if names else ""
        return (f"1. Open {target} in the scoped test browser{field}.\n"
                "2. Run the recorded nonce-marked browser XSS check.\n"
                "3. Observe a browser dialog containing the fresh nonce.\n"
                "4. Repeat independently with a different nonce; both proof artifact IDs are in the evidence record.")
    if proof_kind == "public_directory_index":
        return (f"1. Request {target} anonymously with GET.\n"
                "2. Confirm a complete HTTP 200 HTML directory index response.\n"
                "3. Repeat anonymously and compare the independent proof artifacts.")
    if proof_kind == "numeric_boolean_sqli":
        names = {row.result.get("parameter") for row in packet.observations
                 if row.result.get("operation") == "sqli_boolean_numeric"}
        name = next(iter(names)) if len(names) == 1 else None
        field = f" query field {name}" if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name) else " observed numeric query field"
        return (f"1. Capture a GET to {target} with the{field} in the scoped browser.\n"
                "2. Run the bounded numeric Boolean proof: stable baseline, two true responses, and two false responses.\n"
                "3. Confirm that baseline and true response hashes match while both false hashes differ.\n"
                "4. Repeat the proof independently with a different nonce; see the evidence record for hashes and artifact IDs.")
    return (f"1. Capture the owner-only GET resource {target} with the registered owner test identity.\n"
            "2. Compare two requests each as owner, unrelated test identity, and anonymous visitor.\n"
            "3. Confirm that the unrelated identity receives the same protected content while anonymous requests are denied.\n"
            "4. Repeat with a separate browser capture and verifier proof; see the evidence record for hashes and artifact IDs.")


@router.post("/findings")
def publish_finding(
    packet: PublishFinding,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: None = Depends(_require_prowl_key),
):
    """Create one open Aegis finding per confirmed PROWL candidate."""
    prior = db.query(ProwlPublication).filter_by(candidate_id=packet.prowl_candidate_id).first()
    if prior:
        if prior.run_id != packet.prowl_run_id or prior.verification_id != packet.prowl_verification_id:
            raise HTTPException(status_code=409, detail="Candidate ID was already used for a different proof")
        existing = db.query(Vulnerability).filter_by(id=prior.vulnerability_id).first()
        return {"id": prior.vulnerability_id,
                "status": existing.status.value if existing and existing.status else "open",
                "already_published": True}

    asset = db.query(Asset).filter_by(id=packet.asset_id, organization_id=packet.organization_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Assessment asset not found in organization")
    parsed = urlsplit(packet.target)
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Absolute HTTP(S) target required")
    if _target_host(packet.target) != _target_host(asset.value):
        raise HTTPException(status_code=400, detail="Finding target does not match the Aegis asset")
    binding = db.query(ScopedAssessmentRun).filter_by(service_run_id=packet.prowl_run_id).first()
    if binding is not None:
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        if (binding.organization_id != packet.organization_id or binding.asset_id != packet.asset_id
                or target_origin != binding.allowed_origin):
            raise HTTPException(status_code=400, detail="Finding target does not match the bound assessment run")
    proof_kind = _check_proof(packet)

    metadata = {
        "prowl_run_id": packet.prowl_run_id,
        "prowl_candidate_id": packet.prowl_candidate_id,
        "prowl_verification_id": packet.prowl_verification_id,
        "hunter_evidence_ids": packet.hunter_evidence_ids,
        "verifier_evidence_ids": packet.verifier_evidence_ids,
        "proof_kind": proof_kind,
    }
    vulnerability = Vulnerability(
        title=packet.title, severity=packet.severity, description=packet.description,
        remediation=packet.remediation, asset_id=packet.asset_id,
        detected_by="PROWL", proof_of_concept=_memory_target(packet.target),
        steps_to_reproduce=_reproduction_steps(packet, proof_kind),
        detection_confidence="endpoint_confirmed" if proof_kind == "public_directory_index" else "exploit_confirmed",
        evidence=json.dumps([row.model_dump() for row in packet.observations], sort_keys=True),
        metadata_=metadata, status=VulnerabilityStatus.OPEN,
    )
    db.add(vulnerability)
    db.flush()
    db.add(ProwlPublication(
        candidate_id=packet.prowl_candidate_id, run_id=packet.prowl_run_id,
        verification_id=packet.prowl_verification_id,
        organization_id=packet.organization_id, vulnerability_id=vulnerability.id,
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        prior = db.query(ProwlPublication).filter_by(candidate_id=packet.prowl_candidate_id).first()
        if not prior or prior.run_id != packet.prowl_run_id or prior.verification_id != packet.prowl_verification_id:
            raise HTTPException(status_code=409, detail="Publication conflict")
        existing = db.query(Vulnerability).filter_by(id=prior.vulnerability_id).first()
        return {"id": prior.vulnerability_id,
                "status": existing.status.value if existing and existing.status else "open",
                "already_published": True}

    _maybe_auto_create_jira_ticket(db, vulnerability, background_tasks, asset.organization_id)
    _maybe_auto_push_servicenow(db, vulnerability, background_tasks, asset.organization_id)
    return {"id": vulnerability.id, "status": "open", "already_published": False}
