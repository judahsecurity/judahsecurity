"""Remediation playbook API routes."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.vulnerability import Vulnerability
from app.models.user import User
from app.api.deps import get_current_active_user
from app.services.remediation_playbook_service import (
    RemediationPlaybookService,
    RemediationPlaybook,
    REMEDIATION_PLAYBOOKS,
)
from app.services.cwe_service import get_cwe_service
from app.services.campaign_mitigations import campaigns_for_finding

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.get("/playbooks")
def list_playbooks(
    current_user: User = Depends(get_current_active_user)
):
    """
    List all available remediation playbooks.
    
    Returns a summary of each playbook including ID, title, priority, and effort.
    """
    playbooks = RemediationPlaybookService.get_all_playbooks()
    
    return {
        "playbooks": [
            {
                "id": p.id,
                "title": p.title,
                "summary": p.summary,
                "priority": p.priority.value,
                "effort": p.effort.value,
                "estimated_time": p.estimated_time,
                "tags": p.tags,
            }
            for p in playbooks
        ],
        "total": len(playbooks),
    }


@router.get("/playbooks/search")
def search_playbooks(
    query: str = Query(..., min_length=2),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search for remediation playbooks.
    
    Searches by title, summary, and tags.
    """
    results = RemediationPlaybookService.search_playbooks(query)
    
    return {
        "query": query,
        "results": [
            {
                "id": p.id,
                "title": p.title,
                "summary": p.summary,
                "priority": p.priority.value,
                "effort": p.effort.value,
                "tags": p.tags,
            }
            for p in results
        ],
        "total": len(results),
    }


@router.get("/playbooks/{playbook_id}")
def get_playbook(
    playbook_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific remediation playbook by ID.
    
    Returns the full playbook with all steps, verification, and references.
    """
    playbook = RemediationPlaybookService.get_playbook(playbook_id)
    
    if not playbook:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_id}' not found"
        )
    
    return playbook.to_dict()


@router.get("/cwe/{cwe_id}")
def get_cwe_info(cwe_id: str, current_user: User = Depends(get_current_active_user)):
    """
    Get CWE (Common Weakness Enumeration) details from MITRE for remediation guidance.

    Returns name, description, and potential mitigations. Data is loaded from
    https://cwe.mitre.org/data/downloads.html when available.
    """
    data = get_cwe_service().get_dict(cwe_id)
    if not data:
        raise HTTPException(
            status_code=404,
            detail=f"CWE '{cwe_id}' not found or invalid (use format CWE-NNN)",
        )
    return data


@router.post("/cwe/refresh")
def refresh_cwe_cache(current_user: User = Depends(get_current_active_user)):
    """Force refresh of CWE data from MITRE (e.g. after CWE list updates)."""
    ok = get_cwe_service().refresh()
    return {"success": ok, "message": "CWE cache refreshed" if ok else "Refresh failed, using fallback"}


@router.get("/for-finding/{finding_id}")
def get_remediation_for_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get remediation guidance for a specific finding/vulnerability.
    
    Automatically matches the finding to the most relevant playbook based on
    title, template ID, port, or tags.
    """
    # Get the finding
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Extract matching criteria from finding
    title = finding.title
    template_id = finding.template_id
    tags = finding.tags or []
    cwe_id = finding.cwe_id
    cve_id = finding.cve_id
    
    # Try to extract port from metadata or evidence
    port = None
    if finding.metadata_:
        port = finding.metadata_.get("port")
    
    # Find matching playbook - includes CWE/CVE matching for Nuclei findings
    playbook = RemediationPlaybookService.get_playbook_for_finding(
        title=title,
        template_id=template_id,
        port=port,
        tags=tags,
        cwe_id=cwe_id,
        cve_id=cve_id,
    )
    
    # Attach CWE-based remediation guidance when finding has cwe_id
    cwe_info = None
    if cwe_id:
        cwe_info = get_cwe_service().get_dict(cwe_id)

    # Interim mitigations and compromise checks from active exploitation
    # campaigns that name this finding's CVE or exposed product.
    active_campaigns = campaigns_for_finding(
        cve_id=cve_id, title=title, template_id=template_id, tags=tags
    )

    if not playbook:
        # Return the finding's built-in remediation if no playbook matches
        return {
            "finding_id": finding_id,
            "finding_title": finding.title,
            "has_playbook": False,
            "remediation": finding.remediation,
            "references": finding.references or [],
            "cwe_id": cwe_id,
            "cwe": cwe_info,
            "active_campaigns": active_campaigns,
            "message": "No specific playbook found. Showing finding's built-in remediation."
        }

    return {
        "finding_id": finding_id,
        "finding_title": finding.title,
        "has_playbook": True,
        "playbook": playbook.to_dict(),
        "cwe_id": cwe_id,
        "cwe": cwe_info,
        "active_campaigns": active_campaigns,
    }


@router.post("/for-finding/{finding_id}/assign")
def assign_playbook_to_finding(
    finding_id: int,
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Assign a specific playbook to a finding.
    
    This copies the playbook's remediation guidance to the finding's remediation field.
    """
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    playbook = RemediationPlaybookService.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    # Build remediation text from playbook
    remediation_text = f"## {playbook.title}\n\n"
    remediation_text += f"**Priority:** {playbook.priority.value.upper()}\n"
    remediation_text += f"**Estimated Effort:** {playbook.estimated_time}\n\n"
    remediation_text += "### Steps\n\n"
    
    for step in playbook.steps:
        remediation_text += f"**{step.order}. {step.title}**\n"
        remediation_text += f"{step.description}\n"
        if step.command:
            remediation_text += f"\n```\n{step.command}\n```\n"
        if step.notes:
            remediation_text += f"\n> Note: {step.notes}\n"
        remediation_text += "\n"
    
    remediation_text += "### Verification\n\n"
    for v in playbook.verification:
        remediation_text += f"- {v.description}: {v.expected_result}\n"
    
    # Update the finding
    finding.remediation = remediation_text
    
    # Store playbook reference in metadata
    metadata = finding.metadata_ or {}
    metadata["assigned_playbook"] = playbook_id
    finding.metadata_ = metadata
    
    db.commit()
    
    return {
        "success": True,
        "finding_id": finding_id,
        "playbook_id": playbook_id,
        "message": f"Playbook '{playbook.title}' assigned to finding",
    }


@router.get("/stats")
def get_remediation_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get remediation statistics.
    
    Returns counts by priority, effort, and status.
    """
    from sqlalchemy import func
    from app.models.vulnerability import VulnerabilityStatus
    
    # Count findings by status
    status_counts = db.query(
        Vulnerability.status,
        func.count(Vulnerability.id)
    ).group_by(Vulnerability.status).all()
    
    status_dict = {str(s.value): c for s, c in status_counts}
    
    # Count findings with remediation
    with_remediation = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.remediation.isnot(None),
        Vulnerability.remediation != ""
    ).scalar()
    
    total_findings = db.query(func.count(Vulnerability.id)).scalar()
    
    return {
        "total_findings": total_findings,
        "with_remediation_guidance": with_remediation,
        "without_remediation_guidance": total_findings - with_remediation,
        "by_status": status_dict,
        "available_playbooks": len(REMEDIATION_PLAYBOOKS),
    }


@router.get("/workload")
def get_remediation_workload(
    organization_id: Optional[int] = None,
    include_info: bool = Query(False, description="Include informational findings in workload"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Calculate total remediation workload vs 40-hour work week.
    
    Returns:
    - Total estimated hours for all open findings
    - Comparison to 40-hour work weeks
    - Breakdown by severity, effort level, and playbook
    - Prioritized action list (quick wins, highest impact)
    
    Note: Informational findings are excluded by default since they 
    typically don't require remediation. Use include_info=true to include them.
    """
    import logging
    from sqlalchemy import func
    from sqlalchemy.orm import joinedload
    from app.models.vulnerability import VulnerabilityStatus, Severity
    from app.models.asset import Asset
    
    logger = logging.getLogger(__name__)
    
    # Effort level to hours mapping
    EFFORT_HOURS = {
        "minimal": 0.5,    # 30 minutes
        "low": 1.5,        # 1-2 hours
        "medium": 4,       # Half day
        "high": 12,        # 1.5 days
        "significant": 40, # 1 week
    }
    
    # Default hours if no playbook match
    SEVERITY_DEFAULT_HOURS = {
        "critical": 4,
        "high": 2,
        "medium": 1,
        "low": 0.5,
        "info": 0.25,
    }
    
    try:
        # Build base query for open findings with eager loading
        query = db.query(Vulnerability).options(
            joinedload(Vulnerability.asset)
        ).filter(
            Vulnerability.status.in_([
                VulnerabilityStatus.OPEN,
                VulnerabilityStatus.IN_PROGRESS,
            ])
        )
        
        # Exclude informational findings by default
        if not include_info:
            query = query.filter(Vulnerability.severity != Severity.INFO)
        
        if organization_id:
            query = query.join(Asset).filter(Asset.organization_id == organization_id)
        
        findings = query.all()
    except Exception as e:
        logger.error(f"Error fetching findings for workload: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    # Calculate workload
    total_hours = 0
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_effort = {"minimal": 0, "low": 0, "medium": 0, "high": 0, "significant": 0}
    by_playbook = {}
    quick_wins = []  # Low effort, high impact
    high_priority = []  # Critical/high severity
    
    for finding in findings:
        try:
            severity = (finding.severity.value if finding.severity else "medium").lower()
            
            # Try to get playbook for this finding
            playbook = RemediationPlaybookService.get_playbook_for_finding(
                title=finding.title,
                template_id=finding.template_id,
                tags=finding.tags or [],
                cwe_id=finding.cwe_id,
                cve_id=finding.cve_id,
            )
            
            if playbook:
                effort = playbook.effort.value
                hours = EFFORT_HOURS.get(effort, 2)
                playbook_id = playbook.id
                playbook_title = playbook.title
            else:
                effort = "medium" if severity in ["critical", "high"] else "low"
                hours = SEVERITY_DEFAULT_HOURS.get(severity, 1)
                playbook_id = None
                playbook_title = "No playbook matched"
            
            total_hours += hours
            
            # Track by severity
            if severity in by_severity:
                by_severity[severity] += hours
                by_severity_count[severity] += 1
            
            # Track by effort
            if effort in by_effort:
                by_effort[effort] += 1
            
            # Track by playbook
            if playbook_id:
                if playbook_id not in by_playbook:
                    by_playbook[playbook_id] = {
                        "id": playbook_id,
                        "title": playbook_title,
                        "count": 0,
                        "total_hours": 0,
                        "effort": effort,
                        "priority": playbook.priority.value if playbook else "medium",
                    }
                by_playbook[playbook_id]["count"] += 1
                by_playbook[playbook_id]["total_hours"] += hours
            
            # Get asset value safely
            asset_value = None
            try:
                asset_value = finding.asset.value if finding.asset else None
            except Exception:
                pass
            
            # Identify quick wins (low effort, any severity)
            if effort in ["minimal", "low"] and severity in ["critical", "high", "medium"]:
                quick_wins.append({
                    "id": finding.id,
                    "title": finding.title,
                    "severity": severity,
                    "effort": effort,
                    "hours": hours,
                    "playbook_id": playbook_id,
                    "playbook_title": playbook_title,
                    "asset_value": asset_value,
                })
            
            # Identify high priority (critical/high severity)
            if severity in ["critical", "high"]:
                high_priority.append({
                    "id": finding.id,
                    "title": finding.title,
                    "severity": severity,
                    "effort": effort,
                    "hours": hours,
                    "playbook_id": playbook_id,
                    "playbook_title": playbook_title,
                    "asset_value": asset_value,
                })
        except Exception as e:
            # Log and skip problematic findings
            logger.warning(f"Error processing finding {finding.id}: {e}")
    
    # Calculate work weeks
    work_week_hours = 40
    total_weeks = total_hours / work_week_hours
    
    # Sort and limit lists
    quick_wins.sort(key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 5), x["hours"]))
    high_priority.sort(key=lambda x: ({"critical": 0, "high": 1}.get(x["severity"], 2), x["hours"]))
    
    # Convert playbook dict to sorted list
    playbook_list = sorted(by_playbook.values(), key=lambda x: -x["count"])
    
    return {
        "summary": {
            "total_findings": len(findings),
            "total_hours": round(total_hours, 1),
            "total_work_weeks": round(total_weeks, 2),
            "work_week_hours": work_week_hours,
            "hours_display": f"{int(total_hours)}h {int((total_hours % 1) * 60)}m",
            "weeks_display": f"{total_weeks:.1f} weeks" if total_weeks >= 1 else f"{int(total_hours)} hours",
        },
        "by_severity": {
            "hours": by_severity,
            "counts": by_severity_count,
        },
        "by_effort": by_effort,
        "by_playbook": playbook_list[:20],  # Top 20 playbooks
        "quick_wins": quick_wins[:15],  # Top 15 quick wins
        "high_priority": high_priority[:15],  # Top 15 high priority
        "work_week_breakdown": {
            "critical_hours": by_severity.get("critical", 0),
            "high_hours": by_severity.get("high", 0),
            "medium_hours": by_severity.get("medium", 0),
            "low_hours": by_severity.get("low", 0),
            "info_hours": by_severity.get("info", 0),
        },
    }


@router.get("/prioritized-list")
def get_prioritized_remediation_list(
    organization_id: Optional[int] = None,
    include_info: bool = Query(False, description="Include informational findings"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a prioritized list of findings to remediate.
    
    Sorted by severity and then by effort (easier fixes first).
    Groups findings by playbook for batch remediation.
    
    Note: Informational findings are excluded by default since they 
    typically don't require remediation. Use include_info=true to include them.
    """
    from sqlalchemy.orm import joinedload
    from app.models.vulnerability import VulnerabilityStatus, Severity
    from app.models.asset import Asset
    
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        query = db.query(Vulnerability).options(
            joinedload(Vulnerability.asset)
        ).filter(
            Vulnerability.status.in_([
                VulnerabilityStatus.OPEN,
                VulnerabilityStatus.IN_PROGRESS,
            ])
        )
        
        # Exclude informational findings by default
        if not include_info:
            query = query.filter(Vulnerability.severity != Severity.INFO)
        
        if organization_id:
            query = query.join(Asset).filter(Asset.organization_id == organization_id)
        
        # Order by severity first
        findings = query.order_by(
            Vulnerability.severity.desc(),
            Vulnerability.created_at.asc()
        ).limit(limit).all()
    except Exception as e:
        logger.error(f"Error fetching prioritized findings: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    result = []
    for finding in findings:
        try:
            playbook = RemediationPlaybookService.get_playbook_for_finding(
                title=finding.title,
                template_id=finding.template_id,
                tags=finding.tags or [],
                cwe_id=finding.cwe_id,
                cve_id=finding.cve_id,
            )
            
            # Get asset value safely
            asset_value = None
            try:
                asset_value = finding.asset.value if finding.asset else None
            except Exception:
                pass
            
            result.append({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value if finding.severity else "medium",
                "status": finding.status.value if finding.status else "open",
                "asset_id": finding.asset_id,
                "asset_value": asset_value,
                "template_id": finding.template_id,
                "has_playbook": playbook is not None,
                "playbook": {
                    "id": playbook.id,
                    "title": playbook.title,
                    "effort": playbook.effort.value,
                    "estimated_time": playbook.estimated_time,
                    "priority": playbook.priority.value,
                } if playbook else None,
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
            })
        except Exception as e:
            logger.warning(f"Error processing finding {finding.id}: {e}")
    
    return {
        "findings": result,
        "total": len(result),
    }


# =============================================================================
# NUCLEI TEMPLATE PARSING ENDPOINTS
# =============================================================================

@router.get("/nuclei-templates/stats")
def get_nuclei_template_stats(
    subdirectory: Optional[str] = Query(None, description="Subdirectory to scan (e.g., 'http/cves')"),
    severity: Optional[str] = Query(None, description="Filter by severity (comma-separated)"),
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get statistics about available Nuclei templates.
    
    Shows counts by severity, category, and how many have built-in remediation.
    """
    from app.services.nuclei_template_parser_service import get_template_parser
    
    parser = get_template_parser()
    
    # Parse severity filter
    severity_filter = None
    if severity:
        severity_filter = [s.strip().lower() for s in severity.split(',')]
    
    templates = parser.parse_templates_directory(
        subdirectory=subdirectory,
        limit=limit,
        severity_filter=severity_filter,
    )
    
    stats = parser.get_templates_stats(templates)
    
    return {
        "templates_path": parser.templates_path,
        **stats,
    }


@router.get("/nuclei-templates/search")
def search_nuclei_templates(
    query: str = Query(..., min_length=2, description="Search term"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search Nuclei templates by ID, name, or tags.
    
    Returns matching templates with their remediation info.
    """
    from app.services.nuclei_template_parser_service import get_template_parser
    
    parser = get_template_parser()
    query_lower = query.lower()
    
    # Parse severity filter
    severity_filter = None
    if severity:
        severity_filter = [s.strip().lower() for s in severity.split(',')]
    
    # Search through templates
    templates = parser.parse_templates_directory(
        limit=5000,  # Search a reasonable number
        severity_filter=severity_filter,
    )
    
    results = []
    for t in templates:
        # Match on id, name, or tags
        if (query_lower in t.id.lower() or 
            query_lower in t.name.lower() or 
            any(query_lower in tag.lower() for tag in t.tags)):
            
            stub = parser.generate_playbook_stub(t)
            results.append({
                "template_id": t.id,
                "name": t.name,
                "severity": t.severity,
                "category": t.category,
                "tags": t.tags,
                "has_remediation": bool(t.remediation),
                "remediation_preview": t.remediation[:200] if t.remediation else None,
                "cve_id": t.cve_id,
                "cwe_id": t.cwe_id,
                "suggested_effort": stub.effort,
                "suggested_time": stub.estimated_time,
            })
            
            if len(results) >= limit:
                break
    
    return {
        "query": query,
        "results": results,
        "total": len(results),
    }


@router.get("/nuclei-templates/{template_id}")
def get_nuclei_template_details(
    template_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get detailed information about a specific Nuclei template.
    
    Includes full remediation text and generated playbook stub.
    """
    from app.services.nuclei_template_parser_service import find_matching_nuclei_template, get_template_parser
    
    template = find_matching_nuclei_template(template_id)
    
    if not template:
        raise HTTPException(
            status_code=404,
            detail=f"Nuclei template '{template_id}' not found"
        )
    
    parser = get_template_parser()
    stub = parser.generate_playbook_stub(template)
    
    return {
        "template": template.to_dict(),
        "generated_playbook": stub.to_dict(),
    }


@router.post("/nuclei-templates/generate-playbooks")
def generate_playbooks_from_templates(
    subdirectory: Optional[str] = Query(None, description="Subdirectory to scan"),
    severity: Optional[str] = Query(None, description="Filter by severity (comma-separated)"),
    only_with_remediation: bool = Query(True, description="Only include templates with remediation text"),
    limit: int = Query(500, ge=1, le=5000),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate playbook stubs from Nuclei templates.
    
    This creates a JSON file with playbook stubs that can be imported
    into the remediation playbook system.
    
    Returns statistics about generated playbooks.
    """
    import tempfile
    from app.services.nuclei_template_parser_service import generate_playbooks_from_nuclei
    
    # Parse severity filter
    severity_filter = None
    if severity:
        severity_filter = [s.strip().lower() for s in severity.split(',')]
    
    # Generate to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_path = f.name
    
    stats = generate_playbooks_from_nuclei(
        output_path=output_path,
        subdirectory=subdirectory,
        severity_filter=severity_filter,
        only_with_remediation=only_with_remediation,
        limit=limit,
    )
    
    # Read the generated file
    import json
    with open(output_path, 'r') as f:
        playbooks = json.load(f)
    
    # Clean up
    import os
    os.unlink(output_path)
    
    return {
        "stats": stats,
        "playbooks": playbooks[:50],  # Return first 50 as preview
        "message": f"Generated {stats['exported']} playbook stubs from {stats['total']} templates",
    }
