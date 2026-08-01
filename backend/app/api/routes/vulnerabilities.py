"""Vulnerability routes."""

import json
import logging
import os
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func

from app.db.database import get_db
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.models.finding_validation import FindingValidation, ValidationStatus
from app.models.asset import Asset
from app.models.user import User
from app.schemas.vulnerability import VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityResponse
from app.api.deps import get_current_active_user, require_analyst

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

# ── SQS enqueue for on-demand validation (best-effort; DB poll is the fallback) ─
_SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
_AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
_validation_sqs_client = None


def _get_validation_sqs_client():
    global _validation_sqs_client
    if _validation_sqs_client is None and _SQS_QUEUE_URL:
        try:
            import boto3
            _validation_sqs_client = boto3.client('sqs', region_name=_AWS_REGION)
        except Exception as e:
            logger.error(f"Failed to initialize SQS client for validation: {e}")
    return _validation_sqs_client


def send_validation_to_sqs(validation: FindingValidation) -> bool:
    """Enqueue a VALIDATE_FINDING job. Returns False if SQS is not configured.

    The scanner worker also polls the DB for queued validations, so a False
    return here simply means the job will be picked up on the next DB poll.
    """
    if not _SQS_QUEUE_URL:
        return False
    sqs = _get_validation_sqs_client()
    if not sqs:
        return False
    body = {
        'job_type': 'VALIDATE_FINDING',
        'validation_id': validation.id,
        'vulnerability_id': validation.vulnerability_id,
        'organization_id': validation.organization_id,
    }
    try:
        sqs.send_message(
            QueueUrl=_SQS_QUEUE_URL,
            MessageBody=json.dumps(body),
            MessageAttributes={
                'job_type': {'StringValue': 'VALIDATE_FINDING', 'DataType': 'String'},
            },
        )
        return True
    except Exception as e:
        logger.error(f"Failed to enqueue validation {validation.id} to SQS: {e}")
        return False


def _validation_to_dict(v: FindingValidation) -> dict:
    raw = v.raw_output if isinstance(v.raw_output, dict) else {}
    return {
        "id": v.id,
        "vulnerability_id": v.vulnerability_id,
        "organization_id": v.organization_id,
        "status": v.status.value if v.status else None,
        "verdict": v.verdict.value if v.verdict else None,
        "confidence": v.confidence,
        "recommended_severity": v.recommended_severity,
        "reasoning": v.reasoning,
        "evidence": v.evidence,
        "template_logic_issue": v.template_logic_issue,
        "error": v.error,
        # Enhanced re-validation signals (from validator JSON / sanity short-circuit)
        "still_open": raw.get("still_open"),
        "logical_mismatch": raw.get("logical_mismatch"),
        "sanity_flags": raw.get("sanity_flags"),
        "requested_by_user_id": v.requested_by_user_id,
        "created_at": v.created_at,
        "started_at": v.started_at,
        "completed_at": v.completed_at,
    }


def check_org_access(db: Session, user: User, asset_id: int) -> bool:
    """Check if user has access to asset's organization."""
    if user.is_superuser:
        return True
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return False
    return user.organization_id == asset.organization_id


def build_vuln_response(vuln: Vulnerability, db: Optional[Session] = None) -> dict:
    """Build vulnerability response with computed fields. Ensures required fields are never None."""
    d = {k: v for k, v in vuln.__dict__.items() if k != "_sa_instance_state" and k != "metadata_"}
    d["name"] = vuln.title
    d["host"] = vuln.asset.value if vuln.asset else None
    d["matched_at"] = (vuln.evidence[:200] if vuln.evidence else None)
    d["organization_id"] = vuln.asset.organization_id if vuln.asset else None

    # Latest asset screenshot for analyst visual context on the findings page
    screenshot_id = getattr(vuln.asset, "latest_screenshot_id", None) if vuln.asset else None
    d["screenshot_id"] = screenshot_id
    d["screenshot_page_title"] = None
    d["screenshot_captured_at"] = None
    if screenshot_id and db is not None:
        from app.models.screenshot import Screenshot, ScreenshotStatus
        shot = (
            db.query(Screenshot)
            .filter(
                Screenshot.id == screenshot_id,
                Screenshot.status == ScreenshotStatus.SUCCESS,
            )
            .first()
        )
        if shot:
            d["screenshot_page_title"] = shot.page_title
            d["screenshot_captured_at"] = shot.captured_at
        else:
            # Cached ID may be stale / failed — don't surface a broken image
            d["screenshot_id"] = None

    # Surface Delphi (CISA KEV + EPSS) and Aegis Oracle enrichment so the UI
    # can show KEV / EPSS / OPES badges and sort by combined priority.
    # Everything else in metadata_ stays internal.
    if vuln.metadata_ and isinstance(vuln.metadata_, dict):
        delphi = vuln.metadata_.get("delphi")
        if delphi:
            d["delphi"] = delphi
        oracle = vuln.metadata_.get("oracle")
        if oracle:
            d["oracle"] = oracle
    # Ensure list fields are never None (JSON columns can be NULL in DB)
    if d.get("references") is None:
        d["references"] = []
    if d.get("tags") is None:
        d["tags"] = []
    # Ensure datetimes required by schema are set (legacy rows may have None)
    if d.get("first_detected") is None:
        d["first_detected"] = vuln.created_at
    if d.get("last_detected") is None:
        d["last_detected"] = vuln.updated_at or vuln.created_at
    if d.get("created_at") is None:
        d["created_at"] = vuln.first_detected or vuln.last_detected or datetime.utcnow()
    if d.get("updated_at") is None:
        d["updated_at"] = d["created_at"]
    # Ensure status is set (legacy rows may have NULL)
    if d.get("status") is None:
        d["status"] = VulnerabilityStatus.OPEN
    return d


@router.get("/", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[Severity] = None,
    status: Optional[VulnerabilityStatus] = None,
    asset_id: Optional[int] = None,
    cve_id: Optional[str] = None,
    include_out_of_scope: bool = Query(
        False,
        description="Include findings on assets that have been marked out of scope"
    ),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List vulnerabilities with filtering options.

    By default only returns findings for in-scope assets.  Pass
    ``include_out_of_scope=true`` to include findings on assets that have
    been marked out of scope (useful for audit/compliance review).
    """
    query = db.query(Vulnerability).join(Asset).options(joinedload(Vulnerability.asset))

    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return []
        query = query.filter(Asset.organization_id == current_user.organization_id)

    # Exclude out-of-scope asset findings by default
    if not include_out_of_scope:
        query = query.filter(Asset.in_scope == True)

    # Apply filters
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if asset_id:
        query = query.filter(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.filter(Vulnerability.cve_id == cve_id)

    vulns = query.order_by(Vulnerability.severity.desc(), Vulnerability.created_at.desc()).offset(skip).limit(limit).all()

    # Batch-load screenshot metadata for listed assets (avoids N+1)
    from app.models.screenshot import Screenshot, ScreenshotStatus
    screenshot_ids = {
        getattr(v.asset, "latest_screenshot_id", None)
        for v in vulns
        if v.asset and getattr(v.asset, "latest_screenshot_id", None)
    }
    shots_by_id = {}
    if screenshot_ids:
        shots_by_id = {
            s.id: s
            for s in db.query(Screenshot)
            .filter(
                Screenshot.id.in_(screenshot_ids),
                Screenshot.status == ScreenshotStatus.SUCCESS,
            )
            .all()
        }

    responses = []
    for v in vulns:
        d = build_vuln_response(v)
        sid = d.get("screenshot_id")
        shot = shots_by_id.get(sid) if sid else None
        if shot:
            d["screenshot_page_title"] = shot.page_title
            d["screenshot_captured_at"] = shot.captured_at
        elif sid:
            d["screenshot_id"] = None
        responses.append(d)
    return responses


@router.post("/", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
def create_vulnerability(
    vuln_data: VulnerabilityCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new vulnerability."""
    asset = db.query(Asset).filter(Asset.id == vuln_data.asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    if not current_user.is_superuser and current_user.organization_id != asset.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    new_vuln = Vulnerability(**vuln_data.model_dump())
    db.add(new_vuln)
    db.commit()
    db.refresh(new_vuln)

    # Auto-create Jira ticket if the org has an active integration with auto-create enabled
    _maybe_auto_create_jira_ticket(db, new_vuln, background_tasks, asset.organization_id)

    return new_vuln


# NOTE: Static paths MUST be defined before parameterized paths like /{vuln_id}
# Otherwise FastAPI will try to parse "duplicates" as an integer ID

@router.get("/duplicates")
def find_duplicate_findings(
    organization_id: Optional[int] = None,
    dry_run: bool = Query(True, description="If true, report but don't link duplicates"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Find and optionally link duplicate findings across related assets.
    
    This identifies cases where the same vulnerability exists on:
    - A domain and its resolved IP address
    - A subdomain and its parent domain
    - Multiple assets that resolve to the same IP
    
    Useful for cleaning up WAF bypass scenarios where findings are
    detected on both the domain (protected) and IP (unprotected).
    """
    from app.services.finding_deduplication_service import get_deduplication_service
    
    # Use organization from user if not specified
    if organization_id is None and not current_user.is_superuser:
        organization_id = current_user.organization_id
    
    if organization_id is None:
        raise HTTPException(
            status_code=400,
            detail="organization_id is required for non-superuser users"
        )
    
    dedup_service = get_deduplication_service(db)
    result = dedup_service.deduplicate_findings_for_organization(
        organization_id=organization_id,
        dry_run=dry_run
    )
    
    return {
        "dry_run": dry_run,
        "message": "Duplicate analysis complete" if dry_run else "Duplicates linked",
        **result
    }


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability by ID."""
    vuln = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .filter(Vulnerability.id == vuln_id)
        .first()
    )
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return build_vuln_response(vuln, db=db)


@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
def update_vulnerability(
    vuln_id: int,
    vuln_data: VulnerabilityUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()

    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    update_data = vuln_data.model_dump(exclude_unset=True)
    old_status = vuln.status.value if vuln.status else "open"
    new_status = update_data.get("status")

    if new_status == VulnerabilityStatus.RESOLVED and vuln.status != VulnerabilityStatus.RESOLVED:
        vuln.resolved_at = datetime.utcnow()

    for field, value in update_data.items():
        setattr(vuln, field, value)

    db.commit()
    db.refresh(vuln)

    # Sync linked Jira ticket when status changes
    if new_status and new_status != old_status:
        _maybe_sync_jira_ticket(
            db=db,
            vuln=vuln,
            old_status=old_status,
            new_status=new_status.value if hasattr(new_status, "value") else str(new_status),
            changed_by=current_user.email or current_user.username or "unknown",
            background_tasks=background_tasks,
        )

    # Manually marking a finding as a false positive is a suppression signal.
    if (
        new_status == VulnerabilityStatus.FALSE_POSITIVE
        and old_status != "false_positive"
        and vuln.template_id
    ):
        try:
            from app.services.detection_pattern_service import evaluate_template
            asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
            org_id = asset.organization_id if asset else current_user.organization_id
            evaluate_template(
                db,
                organization_id=org_id,
                template_id=vuln.template_id,
                detected_by=vuln.detected_by or "nuclei",
            )
        except Exception as e:
            logger.warning(f"Detection pattern evaluation failed: {e}")

    return vuln


@router.delete("/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    db.delete(vuln)
    db.commit()
    
    return None


@router.post("/bulk-update")
def bulk_update_vulnerabilities(
    update_data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Bulk update multiple vulnerabilities at once.
    
    Body should contain:
    - vulnerability_ids: List[int] - IDs of vulnerabilities to update
    - status: Optional[str] - New status for all vulnerabilities
    - assigned_to: Optional[str] - User to assign findings to
    - remediation_deadline: Optional[str] - Deadline for remediation
    
    Returns count of updated vulnerabilities.
    """
    vuln_ids = update_data.get("vulnerability_ids", [])
    
    if not vuln_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="vulnerability_ids is required"
        )
    
    # Get all vulnerabilities
    vulns = db.query(Vulnerability).filter(Vulnerability.id.in_(vuln_ids)).all()
    
    if not vulns:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No vulnerabilities found"
        )
    
    # Check access to all vulnerabilities
    for vuln in vulns:
        if not check_org_access(db, current_user, vuln.asset_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied for vulnerability {vuln.id}"
            )
    
    updated_count = 0
    new_status = update_data.get("status")
    assigned_to = update_data.get("assigned_to")
    remediation_deadline = update_data.get("remediation_deadline")
    fp_templates: set = set()  # templates newly marked false_positive
    
    for vuln in vulns:
        if new_status:
            status_enum = VulnerabilityStatus(new_status)
            # Handle status change to resolved
            if status_enum == VulnerabilityStatus.RESOLVED and vuln.status != VulnerabilityStatus.RESOLVED:
                vuln.resolved_at = datetime.utcnow()
            if (
                status_enum == VulnerabilityStatus.FALSE_POSITIVE
                and vuln.status != VulnerabilityStatus.FALSE_POSITIVE
                and vuln.template_id
            ):
                fp_templates.add((vuln.asset_id, vuln.template_id, vuln.detected_by))
            vuln.status = status_enum
        
        if assigned_to is not None:  # Allow empty string to unassign
            vuln.assigned_to = assigned_to if assigned_to else None
        
        if remediation_deadline:
            vuln.remediation_deadline = datetime.fromisoformat(remediation_deadline.replace('Z', '+00:00'))
        
        updated_count += 1
    
    db.commit()

    # Re-evaluate false-positive patterns for any templates just marked FP.
    if fp_templates:
        try:
            from app.services.detection_pattern_service import evaluate_template
            asset_ids = {asset_id for asset_id, _, _ in fp_templates}
            asset_orgs = {
                a.id: a.organization_id
                for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
            }
            seen: set = set()
            for asset_id, template_id, detected_by in fp_templates:
                org_id = asset_orgs.get(asset_id)
                if org_id is None or (org_id, template_id) in seen:
                    continue
                seen.add((org_id, template_id))
                evaluate_template(
                    db,
                    organization_id=org_id,
                    template_id=template_id,
                    detected_by=detected_by or "nuclei",
                )
        except Exception as e:
            logger.warning(f"Detection pattern evaluation failed: {e}")
    
    return {
        "success": True,
        "updated_count": updated_count,
        "message": f"Updated {updated_count} vulnerabilities"
    }


@router.get("/stats/summary")
def get_vulnerabilities_summary(
    include_out_of_scope: bool = Query(False, description="Include findings on out-of-scope assets"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability statistics summary.

    Note: 'total' count excludes informational findings.
    By default only counts findings on in-scope assets.
    """
    query = db.query(Vulnerability).join(Asset)

    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {"total": 0, "by_severity": {}, "by_status": {}, "info_count": 0}
        query = query.filter(Asset.organization_id == current_user.organization_id)

    if not include_out_of_scope:
        query = query.filter(Asset.in_scope == True)

    vulns = query.all()
    
    # Calculate stats
    by_severity = {}
    by_status = {}
    actionable_count = 0  # Count of non-info findings
    info_count = 0  # Track info separately
    
    for vuln in vulns:
        sev_key = vuln.severity.value.lower() if hasattr(vuln.severity, 'value') else str(vuln.severity).lower()
        status_key = vuln.status.value if hasattr(vuln.status, 'value') else str(vuln.status)
        
        by_severity[sev_key] = by_severity.get(sev_key, 0) + 1
        by_status[status_key] = by_status.get(status_key, 0) + 1
        
        # Only count non-info findings toward the total
        if sev_key != 'info' and sev_key != 'informational':
            actionable_count += 1
        else:
            info_count += 1
    
    return {
        "total": actionable_count,  # Excludes info findings
        "total_all": len(vulns),  # Includes info findings
        "info_count": info_count,
        "by_severity": by_severity,
        "by_status": by_status
    }


@router.get("/stats/remediation-efficiency")
def get_remediation_efficiency(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get remediation efficiency statistics for the specified time period.
    
    Returns metrics showing how quickly vulnerabilities are being resolved.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {
                "period_days": days,
                "new_findings": 0,
                "resolved_findings": 0,
                "resolution_rate": 0,
                "avg_resolution_time_days": None,
                "mttr_days": None,  # Mean Time To Remediate
                "open_critical": 0,
                "open_high": 0,
                "overdue_count": 0
            }
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # New findings in period
    new_findings = query.filter(
        Vulnerability.first_detected >= cutoff_date
    ).count()
    
    # Resolved in period
    resolved_in_period = query.filter(
        Vulnerability.resolved_at >= cutoff_date,
        Vulnerability.status == VulnerabilityStatus.RESOLVED
    ).all()
    
    resolved_count = len(resolved_in_period)
    
    # Calculate average resolution time
    resolution_times = []
    for vuln in resolved_in_period:
        if vuln.first_detected and vuln.resolved_at:
            time_to_resolve = (vuln.resolved_at - vuln.first_detected).total_seconds() / 86400  # days
            if time_to_resolve >= 0:
                resolution_times.append(time_to_resolve)
    
    avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else None
    
    # Currently open critical and high
    open_critical = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.severity == Severity.CRITICAL
    ).count()
    
    open_high = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.severity == Severity.HIGH
    ).count()
    
    # Overdue count (past deadline)
    overdue = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.remediation_deadline < datetime.utcnow()
    ).count()
    
    # Resolution rate
    total_in_period = new_findings + query.filter(
        Vulnerability.first_detected < cutoff_date,
        Vulnerability.status == VulnerabilityStatus.OPEN
    ).count()
    resolution_rate = (resolved_count / total_in_period * 100) if total_in_period > 0 else 0
    
    return {
        "period_days": days,
        "new_findings": new_findings,
        "resolved_findings": resolved_count,
        "resolution_rate": round(resolution_rate, 1),
        "avg_resolution_time_days": round(avg_resolution_time, 1) if avg_resolution_time else None,
        "mttr_days": round(avg_resolution_time, 1) if avg_resolution_time else None,
        "open_critical": open_critical,
        "open_high": open_high,
        "overdue_count": overdue
    }


@router.get("/stats/exposure")
def get_vulnerability_exposure(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability exposure statistics.
    
    Shows overall exposure level and risk distribution across assets.
    """
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {
                "total_exposure_score": 0,
                "total_findings": 0,
                "assets_with_vulnerabilities": 0,
                "total_assets": 0,
                "exposure_percentage": 0,
                "severity_distribution": {},
                "by_source": [],
                "top_vulnerable_assets": [],
                "exposure_trend": "stable"
            }
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Get all open vulnerabilities (excluding info)
    open_vulns = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.severity != Severity.INFO
    ).all()
    
    # Calculate exposure score (weighted by severity)
    severity_weights = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 5,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0
    }
    
    total_exposure_score = sum(severity_weights.get(v.severity, 0) for v in open_vulns)
    
    # Get assets with vulnerabilities
    asset_vuln_counts: dict = {}
    for vuln in open_vulns:
        asset_vuln_counts[vuln.asset_id] = asset_vuln_counts.get(vuln.asset_id, 0) + 1
    
    assets_with_vulns = len(asset_vuln_counts)
    
    # Get total assets count
    assets_query = db.query(Asset)
    if not current_user.is_superuser and current_user.organization_id:
        assets_query = assets_query.filter(Asset.organization_id == current_user.organization_id)
    total_assets = assets_query.count()
    
    exposure_percentage = (assets_with_vulns / total_assets * 100) if total_assets > 0 else 0
    
    # Severity distribution
    severity_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    for vuln in open_vulns:
        sev_key = vuln.severity.value.lower() if hasattr(vuln.severity, 'value') else str(vuln.severity).lower()
        if sev_key in severity_distribution:
            severity_distribution[sev_key] += 1
    
    # Top vulnerable assets
    top_assets = []
    for asset_id, count in sorted(asset_vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            top_assets.append({
                "asset_id": asset_id,
                "asset_name": asset.name or asset.value,
                "asset_value": asset.value,
                "vulnerability_count": count,
                "asset_type": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)
            })
    
    # Trend calculation (compare last 7 days to previous 7 days)
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    two_weeks_ago = now - timedelta(days=14)
    
    recent_new = query.filter(
        Vulnerability.first_detected >= week_ago,
        Vulnerability.severity != Severity.INFO
    ).count()
    
    previous_new = query.filter(
        Vulnerability.first_detected >= two_weeks_ago,
        Vulnerability.first_detected < week_ago,
        Vulnerability.severity != Severity.INFO
    ).count()
    
    if recent_new > previous_new * 1.2:
        trend = "increasing"
    elif recent_new < previous_new * 0.8:
        trend = "decreasing"
    else:
        trend = "stable"

    # By source (detected_by) for attack-surface visualization: source -> count
    by_source_query = db.query(
        func.coalesce(Vulnerability.detected_by, "unknown").label("source"),
        func.count(Vulnerability.id).label("count")
    ).join(Asset)
    if not current_user.is_superuser and current_user.organization_id:
        by_source_query = by_source_query.filter(Asset.organization_id == current_user.organization_id)
    by_source_query = by_source_query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.severity != Severity.INFO
    ).group_by(func.coalesce(Vulnerability.detected_by, "unknown")).order_by(
        func.count(Vulnerability.id).desc()
    )
    by_source = [{"source": r.source, "count": r.count} for r in by_source_query.all()]

    return {
        "total_exposure_score": total_exposure_score,
        "total_findings": len(open_vulns),
        "assets_with_vulnerabilities": assets_with_vulns,
        "total_assets": total_assets,
        "exposure_percentage": round(exposure_percentage, 1),
        "severity_distribution": severity_distribution,
        "by_source": by_source,
        "top_vulnerable_assets": top_assets,
        "exposure_trend": trend
    }


@router.get("/{vulnerability_id}/related")
def get_related_findings(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get findings related to this vulnerability (duplicates on related assets).
    
    Returns:
    - Linked duplicate findings
    - Findings on related assets with the same template_id
    - The asset relationship (domain/IP, subdomain/parent, etc.)
    """
    from app.services.finding_deduplication_service import get_deduplication_service
    
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if not vuln.asset:
        return {
            "vulnerability_id": vulnerability_id,
            "related_findings": [],
            "linked_findings": [],
            "message": "No asset associated with this finding"
        }
    
    # Get linked findings from metadata
    linked_findings = []
    if vuln.metadata_ and vuln.metadata_.get("linked_findings"):
        for link in vuln.metadata_["linked_findings"]:
            linked_vuln = db.query(Vulnerability).filter(
                Vulnerability.id == link["finding_id"]
            ).first()
            if linked_vuln:
                linked_findings.append({
                    "id": linked_vuln.id,
                    "title": linked_vuln.title,
                    "severity": linked_vuln.severity.value if linked_vuln.severity else None,
                    "asset_id": linked_vuln.asset_id,
                    "asset_value": linked_vuln.asset.value if linked_vuln.asset else None,
                    "relationship": link.get("relationship", "linked")
                })
    
    # Also check if this finding is a duplicate of another
    if vuln.metadata_ and vuln.metadata_.get("primary_finding_id"):
        primary = db.query(Vulnerability).filter(
            Vulnerability.id == vuln.metadata_["primary_finding_id"]
        ).first()
        if primary:
            linked_findings.append({
                "id": primary.id,
                "title": primary.title,
                "severity": primary.severity.value if primary.severity else None,
                "asset_id": primary.asset_id,
                "asset_value": primary.asset.value if primary.asset else None,
                "relationship": "primary_finding"
            })
    
    # Find related assets
    dedup_service = get_deduplication_service(db)
    related_assets = dedup_service.get_related_assets(vuln.asset)
    
    # Find similar findings on related assets
    related_findings = []
    if vuln.template_id and related_assets:
        related_asset_ids = [a.id for a in related_assets]
        similar = db.query(Vulnerability).filter(
            Vulnerability.asset_id.in_(related_asset_ids),
            Vulnerability.template_id == vuln.template_id,
            Vulnerability.id != vulnerability_id
        ).all()
        
        for v in similar:
            related_findings.append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value if v.severity else None,
                "asset_id": v.asset_id,
                "asset_value": v.asset.value if v.asset else None,
                "status": v.status.value if v.status else None
            })
    
    # Get also_affects from metadata
    also_affects = []
    if vuln.metadata_ and vuln.metadata_.get("also_affects"):
        also_affects = vuln.metadata_["also_affects"]
    
    return {
        "vulnerability_id": vulnerability_id,
        "template_id": vuln.template_id,
        "asset": {
            "id": vuln.asset.id,
            "value": vuln.asset.value,
            "type": vuln.asset.asset_type.value
        },
        "related_assets": [
            {
                "id": a.id,
                "value": a.value,
                "type": a.asset_type.value
            }
            for a in related_assets
        ],
        "linked_findings": linked_findings,
        "related_findings": related_findings,
        "also_affects": also_affects
    }


# ── Jira integration hooks ───────────────────────────────────────────────────

def _maybe_auto_create_jira_ticket(
    db: Session,
    vuln: Vulnerability,
    background_tasks: BackgroundTasks,
    org_id: int,
) -> None:
    """Queue a Jira ticket creation if the org has auto-create enabled and severity qualifies."""
    try:
        from app.models.jira_integration import JiraIntegration, severity_meets_threshold
        from app.services.jira_service import auto_create_ticket_sync

        integration = (
            db.query(JiraIntegration)
            .filter(
                JiraIntegration.organization_id == org_id,
                JiraIntegration.is_active == True,
                JiraIntegration.auto_create_enabled == True,
            )
            .first()
        )
        if not integration or not integration.default_project_key:
            return

        vuln_severity = vuln.severity.value if vuln.severity else "info"
        min_severity = integration.auto_create_min_severity or "high"
        if not severity_meets_threshold(vuln_severity, min_severity):
            return

        background_tasks.add_task(auto_create_ticket_sync, integration, vuln)
    except Exception:
        logger.exception("Error scheduling Jira auto-create for vuln %s", vuln.id)


def _maybe_sync_jira_ticket(
    db: Session,
    vuln: Vulnerability,
    old_status: str,
    new_status: str,
    changed_by: str,
    background_tasks: BackgroundTasks,
) -> None:
    """Queue a Jira status sync if there are active tickets linked to this vulnerability."""
    try:
        from app.models.jira_integration import JiraIntegration, JiraTicket
        from app.services.jira_service import sync_ticket_for_status_change_sync

        asset = vuln.asset
        if not asset:
            return
        org_id = asset.organization_id

        integration = (
            db.query(JiraIntegration)
            .filter(
                JiraIntegration.organization_id == org_id,
                JiraIntegration.is_active == True,
            )
            .first()
        )
        if not integration:
            return

        # Only sync if transitions are configured in either direction
        has_close = bool(integration.open_to_close_transitions)
        has_reopen = bool(integration.close_to_open_transitions)
        if not has_close and not has_reopen:
            return

        tickets = (
            db.query(JiraTicket)
            .filter(
                JiraTicket.vulnerability_id == vuln.id,
                JiraTicket.integration_id == integration.id,
                JiraTicket.disconnected_at.is_(None),
            )
            .all()
        )
        for ticket in tickets:
            background_tasks.add_task(
                sync_ticket_for_status_change_sync,
                integration, ticket, old_status, new_status, changed_by,
            )
    except Exception:
        logger.exception("Error scheduling Jira sync for vuln %s", vuln.id)


# =============================================================================
# ON-DEMAND FINDING VALIDATION (Aegis Vanguard validator agent)
# =============================================================================


class DetectionFeedbackCreate(BaseModel):
    """Analyst-submitted detection-logic feedback for a finding's template."""
    logic_issue: str
    verdict: Optional[str] = "false_positive"


@router.post("/{vuln_id}/validate")
def validate_finding(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Queue an on-demand validation of this finding by the Aegis Vanguard validator agent.

    The agent actively re-tests the live target and writes a verdict back to the
    finding. Returns the queued FindingValidation record; poll
    GET /vulnerabilities/{id}/validation for the result.
    """
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    # Avoid stacking duplicate in-flight validations for the same finding.
    in_flight = db.query(FindingValidation).filter(
        FindingValidation.vulnerability_id == vuln.id,
        FindingValidation.status.in_([ValidationStatus.QUEUED, ValidationStatus.RUNNING]),
    ).first()
    if in_flight:
        return _validation_to_dict(in_flight)

    asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
    organization_id = asset.organization_id if asset else current_user.organization_id

    validation = FindingValidation(
        vulnerability_id=vuln.id,
        organization_id=organization_id,
        status=ValidationStatus.QUEUED,
        requested_by_user_id=current_user.id,
    )
    db.add(validation)
    vuln.validation_status = "queued"
    db.commit()
    db.refresh(validation)

    send_validation_to_sqs(validation)  # best-effort; DB poll is the fallback

    return _validation_to_dict(validation)


@router.get("/{vuln_id}/validation")
def get_finding_validation(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Return the most recent validation run for this finding (for polling)."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    validation = db.query(FindingValidation).filter(
        FindingValidation.vulnerability_id == vuln.id
    ).order_by(FindingValidation.created_at.desc()).first()
    if not validation:
        return None
    return _validation_to_dict(validation)


@router.post("/{vuln_id}/detection-feedback")
def create_finding_detection_feedback(
    vuln_id: int,
    payload: DetectionFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Log a detection-logic issue for this finding's template.

    Records a DetectionFeedback entry keyed on the finding's template_id and
    generates a copy-pasteable upstream bug report.
    """
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    if not vuln.template_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Finding has no template_id to attribute the detection issue to",
        )

    from app.services.detection_feedback_service import record_detection_feedback
    from app.api.routes.detection_feedback import feedback_to_dict

    asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
    organization_id = asset.organization_id if asset else current_user.organization_id
    target = asset.value if asset else None

    feedback = record_detection_feedback(
        db,
        organization_id=organization_id,
        template_id=vuln.template_id,
        logic_issue=payload.logic_issue,
        detected_by=vuln.detected_by or "nuclei",
        verdict=payload.verdict or "false_positive",
        severity=vuln.severity.value if vuln.severity else None,
        target=target,
        evidence=vuln.evidence,
        example_vulnerability_id=vuln.id,
        source="analyst",
        reported_by_user_id=current_user.id,
    )

    # Re-evaluate the false-positive pattern for this template (recommend-only).
    if vuln.template_id:
        try:
            from app.services.detection_pattern_service import evaluate_template
            evaluate_template(
                db,
                organization_id=organization_id,
                template_id=vuln.template_id,
                detected_by=vuln.detected_by or "nuclei",
            )
        except Exception as e:
            logger.warning(f"Detection pattern evaluation failed: {e}")

    return feedback_to_dict(feedback)















