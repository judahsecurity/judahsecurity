"""
LLM Red Team API Routes

Endpoints for running AI/LLM security assessments against chatbot endpoints.
"""

import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.models.user import User
from app.db.database import SessionLocal
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import Vulnerability, Severity
from app.models.asset import Asset, AssetType, AssetStatus
from app.services.llm_red_team.payloads import get_category_metadata, get_payloads_by_category
from app.services.llm_red_team.scanner import (
    run_scan, ScanConfig, ChatEndpoint, ScanResult, build_finding_data,
    discover_chat_endpoints,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/llm-red-team", tags=["LLM Red Team"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class EndpointConfig(BaseModel):
    url: str
    method: str = "POST"
    message_field: str = "message"
    response_field: Optional[str] = None
    headers: Dict[str, str] = {}
    auth_token: Optional[str] = None
    extra_body: Dict[str, Any] = {}


class LLMRedTeamRequest(BaseModel):
    """Request to run an LLM red team scan."""
    target_url: str = Field(..., description="Target URL to scan for chatbot endpoints")
    organization_id: int = Field(..., description="Organization ID")
    endpoints: List[EndpointConfig] = Field(default=[], description="Known chatbot endpoints to test")
    categories: Optional[List[str]] = Field(default=None, description="Attack categories to test (None = all)")
    auto_discover: bool = Field(default=True, description="Auto-discover chatbot endpoints")
    use_llm_grading: bool = Field(default=True, description="Use LLM to grade inconclusive results")
    rate_limit_delay: float = Field(default=1.0, description="Delay between payloads in seconds")
    max_payloads: Optional[int] = Field(default=None, description="Max payloads per endpoint")
    create_findings: bool = Field(default=True, description="Create vulnerability findings for failed tests")


class DiscoverEndpointsRequest(BaseModel):
    """Request to discover chatbot endpoints."""
    target_url: str = Field(..., description="Target URL to scan")
    timeout: int = Field(default=30, description="Request timeout in seconds")


class LLMRedTeamScanResponse(BaseModel):
    """Response for an LLM red team scan."""
    scan_id: Optional[int] = None
    target_url: str
    status: str
    endpoints_tested: int = 0
    payloads_sent: int = 0
    vulnerabilities_found: int = 0
    results: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {}
    errors: List[str] = []


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/categories")
async def list_categories(
    current_user: User = Depends(get_current_user),
):
    """List available LLM red team test categories with metadata."""
    return get_category_metadata()


@router.get("/payloads")
async def list_payloads(
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List available test payloads, optionally filtered by category."""
    categories = [category] if category else None
    payloads = get_payloads_by_category(categories)
    return [
        {
            "id": p.id,
            "category": p.category,
            "name": p.name,
            "severity": p.severity,
            "cwe_id": p.cwe_id,
            "description": p.description,
        }
        for p in payloads
    ]


@router.post("/discover")
async def discover_endpoints(
    request: DiscoverEndpointsRequest,
    current_user: User = Depends(get_current_user),
):
    """Discover chatbot/AI endpoints on a target URL."""
    try:
        endpoints = await discover_chat_endpoints(
            request.target_url,
            timeout=request.timeout,
        )
        return {
            "target_url": request.target_url,
            "endpoints_found": len(endpoints),
            "endpoints": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "message_field": ep.message_field,
                    "response_field": ep.response_field,
                    "endpoint_type": ep.endpoint_type,
                    "detected_by": ep.detected_by,
                }
                for ep in endpoints
            ],
        }
    except Exception as e:
        logger.exception("Endpoint discovery failed")
        raise HTTPException(status_code=500, detail=f"Discovery failed: {e}")


@router.post("/scan", response_model=LLMRedTeamScanResponse)
async def run_llm_red_team_scan(
    request: LLMRedTeamRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    """
    Run an LLM red team scan against chatbot/AI endpoints.

    This will:
    1. Optionally discover chatbot endpoints on the target
    2. Send red team payloads (prompt injection, jailbreak, etc.)
    3. Analyze responses for vulnerabilities
    4. Create findings in the ASM database
    """
    endpoints = [
        ChatEndpoint(
            url=ep.url,
            method=ep.method,
            message_field=ep.message_field,
            response_field=ep.response_field,
            headers=ep.headers,
            auth_token=ep.auth_token,
            extra_body=ep.extra_body,
            detected_by="manual",
        )
        for ep in request.endpoints
    ]

    config = ScanConfig(
        target_url=request.target_url,
        endpoints=endpoints,
        categories=request.categories,
        auto_discover=request.auto_discover,
        use_llm_grading=request.use_llm_grading,
        rate_limit_delay=request.rate_limit_delay,
        max_payloads=request.max_payloads,
    )

    db = SessionLocal()
    try:
        scan = Scan(
            name=f"LLM Red Team - {request.target_url}",
            scan_type=ScanType.LLM_RED_TEAM,
            organization_id=request.organization_id,
            targets=[request.target_url],
            config={
                "categories": request.categories,
                "auto_discover": request.auto_discover,
                "use_llm_grading": request.use_llm_grading,
                "endpoints": [ep.dict() for ep in request.endpoints],
            },
            status=ScanStatus.RUNNING,
            started_by=current_user.email,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    except Exception as e:
        db.rollback()
        logger.exception("Failed to create scan record")
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {e}")
    finally:
        db.close()

    try:
        scan_result = await run_scan(config)
    except Exception as e:
        logger.exception("LLM red team scan failed")
        _update_scan_status(scan_id, ScanStatus.FAILED, error_message=str(e))
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    findings_created = 0
    if request.create_findings and scan_result.vulnerabilities_found > 0:
        findings_created = _create_findings_from_results(
            scan_result, scan_id, request.organization_id, request.target_url
        )

    _update_scan_status(
        scan_id,
        ScanStatus.COMPLETED,
        vulnerabilities_found=scan_result.vulnerabilities_found,
        results=scan_result.summary,
    )

    return LLMRedTeamScanResponse(
        scan_id=scan_id,
        target_url=scan_result.target_url,
        status="completed",
        endpoints_tested=scan_result.endpoints_tested,
        payloads_sent=scan_result.payloads_sent,
        vulnerabilities_found=scan_result.vulnerabilities_found,
        results=scan_result.results,
        summary=scan_result.summary,
        errors=scan_result.errors,
    )


@router.get("/scan/{scan_id}")
async def get_scan_results(
    scan_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get results for a specific LLM red team scan."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.scan_type == ScanType.LLM_RED_TEAM,
        ).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        vulns = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id,
            Vulnerability.detected_by == "llm_red_team",
        ).all()

        return {
            "scan_id": scan.id,
            "name": scan.name,
            "status": scan.status.value,
            "target_url": scan.targets[0] if scan.targets else None,
            "config": scan.config,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "results": scan.results,
            "findings": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "cwe_id": v.cwe_id,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "tags": v.tags,
                    "metadata": v.metadata_,
                }
                for v in vulns
            ],
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        }
    finally:
        db.close()


# =============================================================================
# HELPERS
# =============================================================================

def _update_scan_status(
    scan_id: int,
    status: ScanStatus,
    error_message: str = None,
    vulnerabilities_found: int = None,
    results: dict = None,
):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = status
            if error_message:
                scan.error_message = error_message
            if vulnerabilities_found is not None:
                scan.vulnerabilities_found = vulnerabilities_found
            if results is not None:
                scan.results = results
            if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                from datetime import datetime
                scan.completed_at = datetime.utcnow()
            db.commit()
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to update scan {scan_id} status")
    finally:
        db.close()


def _create_findings_from_results(
    scan_result: ScanResult,
    scan_id: int,
    organization_id: int,
    target_url: str,
) -> int:
    """Create Vulnerability records for failed test results."""
    from urllib.parse import urlparse
    db = SessionLocal()
    created = 0
    try:
        parsed = urlparse(target_url)
        hostname = parsed.netloc or parsed.path.split("/")[0]

        asset = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value == hostname,
        ).first()
        if not asset:
            asset = Asset(
                name=hostname,
                value=hostname,
                asset_type=AssetType.URL if "://" in target_url else AssetType.DOMAIN,
                organization_id=organization_id,
                status=AssetStatus.DISCOVERED,
            )
            db.add(asset)
            db.flush()

        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        for test_result in scan_result.results:
            if test_result.get("verdict") != "fail":
                continue

            finding_data = build_finding_data(test_result, target_url)

            existing = db.query(Vulnerability).filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == finding_data.get("template_id"),
                Vulnerability.detected_by == "llm_red_team",
            ).first()
            if existing:
                from datetime import datetime
                existing.last_detected = datetime.utcnow()
                continue

            vuln = Vulnerability(
                title=finding_data["title"][:500],
                description=finding_data.get("description", "")[:10000],
                severity=sev_map.get(finding_data.get("severity", "medium"), Severity.MEDIUM),
                asset_id=asset.id,
                scan_id=scan_id,
                detected_by="llm_red_team",
                template_id=finding_data.get("template_id"),
                evidence=finding_data.get("evidence", "")[:5000],
                cwe_id=finding_data.get("cwe_id"),
                remediation=finding_data.get("remediation", "")[:5000],
                tags=finding_data.get("tags", []),
                verification_level=finding_data.get("verification_level"),
                detection_confidence=finding_data.get("detection_confidence", "unknown"),
                metadata_=finding_data.get("metadata", {}),
            )
            db.add(vuln)
            created += 1

        db.commit()
        logger.info(f"Created {created} LLM red team findings for scan {scan_id}")
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to create findings for scan {scan_id}")
    finally:
        db.close()
    return created
