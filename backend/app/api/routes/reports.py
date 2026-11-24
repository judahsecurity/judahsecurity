"""Report generation routes for PDF exports."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.user import User
from app.api.deps import get_current_active_user
from app.services.report_service import get_report_service


def _audit_export(user, *, organization_id, target, fmt, detail=None):
    from app.services.platform_audit import record as audit

    audit("report.export", user=user, organization_id=organization_id, target=target,
          detail={"format": fmt, **(detail or {})})

router = APIRouter(prefix="/reports", tags=["Reports"])


class FindingsReportRequest(BaseModel):
    """Request body for generating a findings report."""
    finding_ids: List[int]
    report_title: Optional[str] = None
    organization_name: Optional[str] = None


def check_asset_access(db: Session, user: User, asset_id: int) -> Asset:
    """Check if user has access to the asset and return it."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not user.is_superuser and user.organization_id != asset.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return asset


@router.get("/assets/{asset_id}/report")
def generate_asset_report(
    asset_id: int,
    format: str = Query("pdf", description="Output format: pdf, html or docx"),
    include_info: bool = Query(False, description="Include informational findings"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate a security findings report for an asset.
    
    Returns a PDF or HTML report containing all vulnerabilities
    associated with the specified asset, sorted by severity.
    """
    asset = check_asset_access(db, current_user, asset_id)
    
    org_name = None
    if hasattr(asset, 'organization') and asset.organization:
        org_name = asset.organization.name
    
    report_service = get_report_service(db)
    _audit_export(current_user, organization_id=asset.organization_id,
                  target=f"asset:{asset.value}", fmt=format.lower(),
                  detail={"include_info": include_info})
    
    try:
        if format.lower() == "docx":
            docx_bytes = report_service.generate_asset_report_docx(
                asset_id=asset_id,
                include_info_findings=include_info,
                organization_name=org_name
            )
            safe_filename = asset.value.replace("/", "_").replace("\\", "_").replace(":", "_")
            return Response(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={
                    "Content-Disposition": f'attachment; filename="findings_report_{safe_filename}.docx"'
                }
            )
        if format.lower() == "html":
            html_content = report_service.generate_asset_report_html(
                asset_id=asset_id,
                include_info_findings=include_info,
                organization_name=org_name
            )
            return Response(
                content=html_content,
                media_type="text/html",
                headers={
                    "Content-Disposition": f'inline; filename="report_{asset.value}.html"'
                }
            )
        else:
            pdf_bytes = report_service.generate_asset_report_pdf(
                asset_id=asset_id,
                include_info_findings=include_info,
                organization_name=org_name
            )
            
            safe_filename = asset.value.replace("/", "_").replace("\\", "_").replace(":", "_")
            
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="findings_report_{safe_filename}.pdf"'
                }
            )
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation not available: {str(e)}"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )


@router.post("/findings/report")
def generate_findings_report(
    request: FindingsReportRequest,
    format: str = Query("pdf", description="Output format: pdf, html or docx"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate a security findings report for selected findings.
    
    Allows selecting specific findings to include in the report,
    which can span multiple assets.
    """
    if not request.finding_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one finding ID is required"
        )
    
    findings = db.query(Vulnerability).filter(
        Vulnerability.id.in_(request.finding_ids)
    ).all()
    
    if not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No findings found with the provided IDs"
        )
    
    for finding in findings:
        asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
        if asset:
            if not current_user.is_superuser and current_user.organization_id != asset.organization_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied for finding {finding.id}"
                )
    
    report_service = get_report_service(db)
    _audit_export(current_user, organization_id=current_user.organization_id,
                  target="findings", fmt=format.lower(),
                  detail={"finding_ids": request.finding_ids[:200]})
    
    try:
        if format.lower() == "docx":
            docx_bytes = report_service.generate_findings_report_docx(
                finding_ids=request.finding_ids,
                report_title=request.report_title,
                organization_name=request.organization_name
            )
            return Response(
                content=docx_bytes,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={
                    "Content-Disposition": 'attachment; filename="findings_report.docx"'
                }
            )
        if format.lower() == "html":
            html_content = report_service.generate_findings_report_html(
                finding_ids=request.finding_ids,
                report_title=request.report_title,
                organization_name=request.organization_name
            )
            return Response(
                content=html_content,
                media_type="text/html",
                headers={
                    "Content-Disposition": 'inline; filename="findings_report.html"'
                }
            )
        else:
            pdf_bytes = report_service.generate_findings_report_pdf(
                finding_ids=request.finding_ids,
                report_title=request.report_title,
                organization_name=request.organization_name
            )
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": 'attachment; filename="findings_report.pdf"'
                }
            )
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation not available: {str(e)}"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )


@router.get("/assets/{asset_id}/findings/count")
def get_asset_findings_count(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a count of findings for an asset by severity.
    
    Useful for previewing what will be in a report before generating it.
    """
    asset = check_asset_access(db, current_user, asset_id)
    
    from app.services.agent.unverified_findings import exclude_hidden_levels

    findings = exclude_hidden_levels(db.query(Vulnerability).filter(
        Vulnerability.asset_id == asset_id
    ), Vulnerability).all()
    
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    manual_count = 0
    
    for f in findings:
        sev = f.severity.value.lower() if hasattr(f.severity, 'value') else str(f.severity).lower()
        if sev in counts:
            counts[sev] += 1
        counts["total"] += 1
        if getattr(f, 'is_manual', False):
            manual_count += 1
    
    return {
        "asset_id": asset_id,
        "asset_value": asset.value,
        "severity_counts": counts,
        "manual_findings": manual_count,
        "automated_findings": counts["total"] - manual_count
    }
