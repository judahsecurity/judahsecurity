"""
Delphi - CISA KEV + FIRST EPSS Enrichment API.

Endpoints
---------
    GET  /delphi/status               catalog stats (KEV count, EPSS date, refresh age)
    POST /delphi/refresh              force re-fetch of both feeds
    GET  /delphi/lookup/{cve_id}      signals for a single CVE (public — no org needed)
    POST /delphi/enrich/{vuln_id}     enrich a single vulnerability row
    POST /delphi/batch-enrich         enrich every CVE-bearing finding in the caller's org
    GET  /delphi/priorities           top N open findings ordered by Delphi priority
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
from app.services.delphi_enrichment_service import TIER_RANK, get_delphi_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/delphi", tags=["Delphi (KEV + EPSS)"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class EPSSInfo(BaseModel):
    score: float
    percentile: float
    # Display-only percentile label (e.g. "top 5%"). EPSS never drives priority.
    display_label: Optional[str] = None
    date: Optional[str] = None
    informational_only: bool = True
    scoring_note: Optional[str] = None


class KEVEntry(BaseModel):
    cve_id: str
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[str] = None
    known_ransomware_use: Optional[str] = None
    notes: Optional[str] = None
    cwes: Optional[List[str]] = None


class LookupResponse(BaseModel):
    cve_id: str
    enriched: bool
    kev: Optional[KEVEntry] = None
    vulncheck_kev: Optional[Dict[str, Any]] = None
    kevintel: Optional[Dict[str, Any]] = None
    shadowserver_exploited: Optional[bool] = None
    kev_sources: Optional[List[str]] = None
    epss: Optional[EPSSInfo] = None
    priority: Optional[str] = None
    likelihood_score: Optional[int] = None
    priority_reason: Optional[str] = None
    priority_signals: Optional[List[str]] = None
    factors: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


class BatchEnrichResponse(BaseModel):
    total: int
    kev_hits: int
    epss_hits: int
    no_signal: int
    errors: int
    error: Optional[str] = None


class StatusResponse(BaseModel):
    enabled: bool
    kev_entries: int
    epss_entries: int
    epss_score_date: Optional[str] = None
    kev_catalog_version: Optional[str] = None
    kev_date_released: Optional[str] = None
    refresh_hours: int
    last_loaded: Optional[str] = None
    epss_role: Optional[str] = None
    extended_kev_enabled: Optional[bool] = None
    vulncheck_kev_entries: Optional[int] = None
    shadowserver_exploited_entries: Optional[int] = None
    kevintel_entries: Optional[int] = None
    breach_intel: Optional[Dict[str, Any]] = None
    priority_drivers: Optional[List[str]] = None
    priority_model: Optional[str] = None


class PriorityFinding(BaseModel):
    vulnerability_id: int
    cve_id: str
    title: Optional[str]
    severity: str
    asset_value: Optional[str]
    priority: str
    likelihood_score: Optional[int] = None
    priority_reason: Optional[str]
    priority_signals: Optional[List[str]] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    on_kev: bool
    ransomware: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=StatusResponse)
async def delphi_status():
    """Return catalog stats (KEV count, EPSS date, refresh window)."""
    return StatusResponse(**get_delphi_service().stats())


@router.post("/refresh", response_model=StatusResponse)
async def delphi_refresh(current_user: User = Depends(get_current_user)):
    """Force an immediate refetch of CISA KEV + EPSS into the on-disk cache."""
    return StatusResponse(**get_delphi_service().refresh())


@router.get("/lookup/{cve_id}", response_model=LookupResponse)
async def delphi_lookup(cve_id: str, current_user: User = Depends(get_current_user)):
    """Lookup Delphi signals for a CVE. Works for any CVE, even ones you don't own."""
    svc = get_delphi_service()
    result = svc.lookup(cve_id)
    return LookupResponse(**result)


@router.post("/enrich/{vulnerability_id}", response_model=LookupResponse)
async def delphi_enrich_one(vulnerability_id: int, current_user: User = Depends(get_current_user)):
    """Enrich a single vulnerability by id and persist the result to metadata."""
    svc = get_delphi_service()
    result = svc.enrich_and_update(vulnerability_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return LookupResponse(**result)


@router.post("/batch-enrich", response_model=BatchEnrichResponse)
async def delphi_batch_enrich(
    limit: Optional[int] = Query(None, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
):
    """Enrich every CVE-bearing finding in the caller's organization."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")

    svc = get_delphi_service()
    result = svc.batch_enrich(org_id, limit=limit)
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])
    return BatchEnrichResponse(**result)


@router.get("/priorities", response_model=List[PriorityFinding])
async def delphi_priorities(
    limit: int = Query(50, ge=1, le=500),
    include_resolved: bool = Query(False),
    current_user: User = Depends(get_current_user),
):
    """
    Return the caller's highest-priority open findings according to Delphi's
    exploitation-likelihood model.

    Ordering:
        1. Priority tier (critical > high > elevated > moderate > low > none)
        2. Delphi likelihood_score (0-100) desc within a tier
        3. Ransomware-flagged KEV, then other KEV, as tie-breakers

    EPSS is returned for display only and never affects ordering.
    """
    from app.db.database import SessionLocal
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")

    svc = get_delphi_service()
    svc.ensure_loaded()

    db = SessionLocal()
    try:
        q = (
            db.query(Vulnerability, Asset)
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .filter(Asset.organization_id == org_id)
            .filter(Vulnerability.cve_id.isnot(None))
        )
        if not include_resolved:
            q = q.filter(Vulnerability.status == VulnerabilityStatus.OPEN)

        rows = q.all()

        enriched: List[Dict[str, Any]] = []
        for vuln, asset in rows:
            lookup = svc.lookup(
                vuln.cve_id,
                cvss_score=vuln.cvss_score,
                cvss_vector=vuln.cvss_vector,
                detection_confidence=getattr(vuln, "detection_confidence", None),
                exposure={
                    "internet_facing": bool(getattr(asset, "is_public", False)),
                    "is_live": bool(getattr(asset, "is_live", False)),
                    "has_login_portal": bool(getattr(asset, "has_login_portal", False)),
                },
            )
            if not lookup.get("enriched"):
                continue
            epss = lookup.get("epss") or {}
            kev = lookup.get("kev")
            enriched.append({
                "vulnerability_id": vuln.id,
                "cve_id": vuln.cve_id,
                "title": vuln.title,
                "severity": vuln.severity.value if vuln.severity else "info",
                "asset_value": asset.value,
                "priority": lookup.get("priority") or "none",
                "likelihood_score": lookup.get("likelihood_score"),
                "priority_reason": lookup.get("priority_reason"),
                "priority_signals": lookup.get("priority_signals"),
                "epss_score": epss.get("score"),
                "epss_percentile": epss.get("percentile"),
                "on_kev": bool(kev),
                "ransomware": bool(kev and (kev.get("known_ransomware_use") or "").lower() in ("known", "yes")),
            })

        enriched.sort(
            key=lambda r: (
                TIER_RANK.get(r["priority"], 99),
                -(r.get("likelihood_score") or 0),
                not r["ransomware"],
                not r["on_kev"],
            )
        )

        return [PriorityFinding(**r) for r in enriched[:limit]]
    finally:
        db.close()
