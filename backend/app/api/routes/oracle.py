"""
Aegis Oracle proxy routes.

Forwards requests from the ASM frontend to the aegis-oracle service
running on http://aegis-oracle:8742 (or ORACLE_URL env var).

All routes require authentication via the standard ASM JWT token.
The proxy adds no additional transformation — it forwards the request
body verbatim and streams the response back, so the frontend talks
directly to Oracle's JSON API through the ASM auth layer.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_current_user
from app.db.database import get_db
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.oracle_enrichment_service import (
    ENRICH_TTL_HOURS,
    OracleInputError,
    OracleUnavailable,
    enrich_many,
    enrich_vulnerability,
    open_vulnerabilities_to_enrich,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oracle", tags=["oracle"])

ORACLE_URL = os.getenv("ORACLE_URL", "http://aegis-oracle:8742").rstrip("/")
ORACLE_TIMEOUT = float(os.getenv("ORACLE_TIMEOUT", "180"))


def _oracle_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=ORACLE_URL, timeout=ORACLE_TIMEOUT)


# ─────────────────────────── Chat ──────────────────────────────────────

class ChatRequest(BaseModel):
    question: str


class AnalyzeRequest(BaseModel):
    cve_id: str
    asset_id: str


@router.post("/chat")
async def oracle_chat(
    body: ChatRequest,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Natural-language CVE query.

    Parses the question to detect a CVE ID + asset ID pair, calls
    Oracle's /analyze endpoint, and returns a structured answer with
    an optional OracleFinding payload for rich UI rendering.
    """
    cve_id, asset_id = _parse_cve_asset(body.question)

    # Route everything through Oracle's ReAct /chat endpoint.
    # The Go ReAct loop handles all question types: CVE+asset analysis,
    # findings listing, KB lookups, and fallback explanations.
    async with _oracle_client() as client:
        try:
            resp = await client.post("/chat", json={"question": body.question})
            resp.raise_for_status()
            data = resp.json()
            return {
                "answer": data.get("answer", ""),
                "finding": data.get("finding"),
                "iterations": data.get("iterations"),
                "trace": data.get("trace"),
            }
        except httpx.HTTPStatusError as e:
            detail = _safe_error(e)
            raise HTTPException(status_code=502, detail=f"Oracle error: {detail}")
        except httpx.RequestError:
            raise HTTPException(
                status_code=503,
                detail="Aegis Oracle service is unreachable. Make sure the aegis-oracle container is running.",
            )


@router.post("/analyze")
async def oracle_analyze(
    body: AnalyzeRequest,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Directly trigger analysis for a (CVE, asset) pair."""
    async with _oracle_client() as client:
        try:
            resp = await client.post("/analyze", json={"cve_id": body.cve_id, "asset_id": body.asset_id})
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=502, detail=_safe_error(e))
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Aegis Oracle service is unreachable.")


@router.get("/findings")
async def oracle_findings(
    cve_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Return open findings, optionally filtered."""
    async with _oracle_client() as client:
        try:
            params: Dict[str, str] = {}
            if cve_id:
                params["cve_id"] = cve_id
            if asset_id:
                params["asset_id"] = asset_id
            resp = await client.get("/findings", params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError:
            # Oracle might not be running yet — return empty rather than 503
            # so the UI renders gracefully.
            return {"findings": [], "count": 0}


@router.get("/health")
async def oracle_health(current_user=Depends(get_current_user)) -> Dict[str, Any]:
    """Liveness check — verifies Oracle service is reachable."""
    async with _oracle_client() as client:
        try:
            resp = await client.get("/health", timeout=5)
            resp.raise_for_status()
            return {"status": "ok", "oracle": resp.json()}
        except Exception:
            return {"status": "unavailable", "oracle": None}


# ─────────────────────────── CVE lookup (Phase A only) ─────────────────────


@router.get("/cve/{cve_id}")
async def oracle_cve_lookup(
    cve_id: str,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Phase-A-only CVE intelligence — no asset required.

    Returns the analyst brief, attack path class, preconditions, CVSS
    reconciliation, and observed exploitation evidence (KEV, VulnCheck XDB,
    Metasploit, etc.). Intended for ad-hoc CVE questions where an analyst
    needs Oracle's view of a CVE *before* deciding which assets to scope.
    Results are cached on Oracle's side by (cve_id, prompt_version).
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="cve_id must be of the form CVE-YYYY-NNNN")

    async with _oracle_client() as client:
        try:
            resp = await client.get(f"/cve/{cve_id}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=_safe_error(e))
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Aegis Oracle service is unreachable.")


# ─────────────────────────── ASM enrichment ────────────────────────────────


class EnrichBatchRequest(BaseModel):
    """Batch-enrichment request body."""

    limit: int = 200
    force: bool = False
    organization_id: Optional[int] = None  # superuser-only override


class BackfillRequest(BaseModel):
    """Full-backfill request body — enriches every open finding with no cap."""

    force: bool = False
    organization_id: Optional[int] = None  # superuser-only override


class EnrichResponse(BaseModel):
    """Per-vulnerability enrichment result returned by the single-vuln route."""

    vulnerability_id: int
    cve_id: Optional[str] = None
    mode: str
    enriched_at: Optional[str] = None
    opes_score: Optional[float] = None
    opes_category: Optional[str] = None
    opes_label: Optional[str] = None
    opes_confidence: Optional[str] = None
    attack_path_class: Optional[str] = None
    lateral_movement_potential: Optional[str] = None
    recommendation_text: Optional[str] = None
    analyst_brief: Optional[Dict[str, Any]] = None
    cvss_reconciliation: Optional[Dict[str, Any]] = None
    exploitation_evidence: Optional[Dict[str, Any]] = None
    contextual_assessment: Optional[Dict[str, Any]] = None
    analysis_status: Optional[str] = None
    analysis_error: Optional[str] = None


@router.post("/enrich/{vuln_id}", response_model=EnrichResponse)
def oracle_enrich_one(
    vuln_id: int,
    force: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> EnrichResponse:
    """Run Oracle enrichment for a single ASM vulnerability.

    Picks the strongest path automatically:
      • If the linked asset has an Oracle asset id → full /analyze
      • Else → /cve/{{id}} Phase-A analysis

    The result is persisted to `Vulnerability.metadata_["oracle"]` and
    returned as a summary. Pass `force=true` to bypass the
    {ttl}h freshness window.
    """.format(ttl=ENRICH_TTL_HOURS)
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="vulnerability not found")

        # Scope check — non-superusers may only enrich their own org's vulns.
        if not current_user.is_superuser:
            asset = vuln.asset
            if not asset or asset.organization_id != current_user.organization_id:
                raise HTTPException(status_code=403, detail="not authorised for this vulnerability")

        payload = enrich_vulnerability(db, vuln, force=force)

    except HTTPException:
        raise
    except OracleInputError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OracleUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.exception("oracle enrichment unexpected error for vuln=%s", vuln_id)
        raise HTTPException(status_code=500, detail=f"Oracle enrichment failed: {e}")

    return EnrichResponse(
        vulnerability_id=vuln.id,
        cve_id=vuln.cve_id,
        mode=payload.get("mode") or "",
        enriched_at=payload.get("enriched_at"),
        opes_score=payload.get("opes_score"),
        opes_category=payload.get("opes_category"),
        opes_label=payload.get("opes_label"),
        opes_confidence=payload.get("opes_confidence"),
        attack_path_class=payload.get("attack_path_class"),
        lateral_movement_potential=payload.get("lateral_movement_potential"),
        recommendation_text=payload.get("recommendation_text"),
        analyst_brief=payload.get("analyst_brief"),
        cvss_reconciliation=payload.get("cvss_reconciliation"),
        exploitation_evidence=payload.get("exploitation_evidence"),
        contextual_assessment=payload.get("contextual_assessment"),
        analysis_status=payload.get("analysis_status"),
        analysis_error=payload.get("analysis_error"),
    )


@router.post("/enrich/batch")
def oracle_enrich_batch(
    body: EnrichBatchRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Enrich up to `limit` open vulnerabilities with Oracle analysis.

    Runs synchronously for small batches (≤ 25) so the caller gets a result
    in the response; queues a BackgroundTask for larger batches so the API
    call doesn't hold a worker for minutes. Either way, results are visible
    on the vulnerability records via `metadata_["oracle"]` as they finish.
    """
    org_id: Optional[int]
    if current_user.is_superuser:
        org_id = body.organization_id  # may be None → "all orgs"
    else:
        org_id = current_user.organization_id
        if body.organization_id and body.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="cannot target a different organisation")

    vulns = open_vulnerabilities_to_enrich(db, organization_id=org_id, limit=body.limit)
    if not vulns:
        return {"queued": False, "selected": 0, "message": "no open vulnerabilities matched"}

    if len(vulns) <= 25:
        counts = enrich_many(db, vulns, force=body.force)
        return {"queued": False, "selected": len(vulns), **counts}

    # Large batch → background. Pull primary keys so the background task
    # opens a fresh session and re-fetches the rows (Session objects don't
    # cross tasks safely).
    vuln_ids: List[int] = [v.id for v in vulns]
    background.add_task(_run_batch_in_background, vuln_ids, body.force)
    return {"queued": True, "selected": len(vuln_ids), "message": "batch running in background"}


@router.post("/enrich/backfill")
def oracle_enrich_backfill(
    body: BackfillRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Enrich **all** open vulnerabilities with Oracle analysis — no row cap.

    Always runs as a BackgroundTask so the HTTP call returns immediately.
    Use `force=true` to re-enrich findings that already have a fresh Oracle
    payload (within the {ttl}h TTL window). Poll the Findings page or query
    `oracle_enriched_at` on vulnerability records to track progress.
    """.format(ttl=ENRICH_TTL_HOURS)
    org_id: Optional[int]
    if current_user.is_superuser:
        org_id = body.organization_id
    else:
        org_id = current_user.organization_id
        if body.organization_id and body.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="cannot target a different organisation")

    vulns = open_vulnerabilities_to_enrich(db, organization_id=org_id, limit=None)
    if not vulns:
        return {"queued": False, "selected": 0, "message": "no open vulnerabilities found"}

    vuln_ids: List[int] = [v.id for v in vulns]
    background.add_task(_run_batch_in_background, vuln_ids, body.force)
    return {
        "queued": True,
        "selected": len(vuln_ids),
        "message": f"backfill running in background — {len(vuln_ids)} findings queued",
    }


def _run_batch_in_background(vuln_ids: List[int], force: bool) -> None:
    """Worker entry point for batch/backfill enrichment.

    Opens its own DB session and processes each vulnerability via the
    enrichment service so failures don't poison the caller's session.
    """
    from app.db.database import SessionLocal  # local import keeps cyclic risk away
    session = SessionLocal()
    try:
        vulns = (
            session.query(Vulnerability)
            .filter(Vulnerability.id.in_(vuln_ids))
            .all()
        )
        counts = enrich_many(session, vulns, force=force)
        logger.info("oracle batch enrichment finished: %s", counts)
    except OracleUnavailable as e:
        logger.warning("oracle batch aborted (transient): %s", e)
    except Exception:  # noqa: BLE001
        logger.exception("oracle batch enrichment crashed")
    finally:
        session.close()


# ─────────────────────────── Helpers ────────────────────────────────────

def _parse_cve_asset(question: str):
    """Extract (CVE-XXXX-XXXXX, asset_id) from freeform text."""
    import re
    cve_match = re.search(r'CVE-\d{4}-\d+', question, re.IGNORECASE)
    cve_id = cve_match.group(0).upper() if cve_match else None

    # Asset ID: look for "on asset <id>" or "on <id>"
    asset_match = re.search(r'on\s+(?:asset\s+)?([\w\-\.]+)', question, re.IGNORECASE)
    asset_id = asset_match.group(1) if asset_match else None
    # Don't treat CVE-… as asset_id
    if asset_id and asset_id.upper().startswith("CVE-"):
        asset_id = None

    return cve_id, asset_id


def _parse_category_filter(question: str) -> Optional[str]:
    import re
    m = re.search(r'\b(P[0-4])\b', question, re.IGNORECASE)
    return m.group(1).upper() if m else None


def _finding_to_prose(finding: Dict[str, Any]) -> str:
    if not finding:
        return "Analysis complete."
    opes = finding.get("opes", {})
    score = opes.get("score", 0)
    cat = opes.get("category", "?")
    label = opes.get("label", "")
    confidence = opes.get("confidence", "")
    dampener = opes.get("dampener", "")
    rec = finding.get("recommendation", "")

    lines = [
        f"{finding.get('cve_id', '')} on {finding.get('asset_id', '')}",
        f"OPES {score:.1f} / {cat} — {label} (confidence: {confidence})",
    ]
    if dampener:
        lines.append(f"⚠ {dampener}")
    if rec:
        lines.append("")
        lines.append(rec)
    return "\n".join(lines)


def _findings_summary(findings: list) -> str:
    lines = []
    for f in findings[:20]:
        opes = f.get("opes", {})
        lines.append(
            f"• {f.get('cve_id','?')} on {f.get('asset_id','?')} "
            f"— {opes.get('category','?')} ({opes.get('score',0):.1f}) {opes.get('label','')}"
        )
    if len(findings) > 20:
        lines.append(f"  … and {len(findings) - 20} more")
    return "\n".join(lines)


def _safe_error(e: httpx.HTTPStatusError) -> str:
    try:
        return e.response.json().get("error", str(e))
    except Exception:
        return str(e)
