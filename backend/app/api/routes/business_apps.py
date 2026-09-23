"""Business applications (ServiceNow CMDB) and their links to findings."""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_analyst
from app.api.routes.vulnerabilities import business_app_summary, check_org_access
from app.db.database import get_db
from app.models.asset import Asset
from app.models.business_application import BusinessApplication
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/business-apps", tags=["business-apps"])


def _org_id(user: User) -> int:
    if not user.organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No organization")
    return user.organization_id


def _app_for_org(db: Session, app_id: Optional[int], org_id: int) -> Optional[BusinessApplication]:
    if app_id is None:
        return None
    app = db.query(BusinessApplication).filter(BusinessApplication.id == app_id).first()
    if app is None or app.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business application not found")
    return app


@router.get("")
def list_business_apps(
    q: Optional[str] = Query(None, description="Search by application id or name"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    query = db.query(BusinessApplication).filter(BusinessApplication.organization_id == _org_id(current_user))
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(BusinessApplication.app_id.ilike(like), BusinessApplication.name.ilike(like)))
    apps = query.order_by(BusinessApplication.criticality_level.asc().nullslast(), BusinessApplication.name).limit(limit).all()
    return [business_app_summary(a) for a in apps]


@router.post("/sync")
async def sync_from_servicenow(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Pull business applications from the org's ServiceNow CMDB."""
    from app.services.business_app_sync import sync_business_apps

    try:
        result = await sync_business_apps(db, _org_id(current_user))
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Business app sync failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="ServiceNow request failed")
    db.commit()
    return result


class LinkRequest(BaseModel):
    business_app_id: Optional[int] = None  # null clears the link


def _reevaluate(db: Session, vulns: List[Vulnerability]) -> None:
    from app.services.severity_evaluation import evaluate_finding

    for v in vulns:
        try:
            evaluate_finding(db, v)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Severity re-evaluation failed for vuln %s: %s", v.id, exc)


@router.put("/findings/{vuln_id}")
def link_finding(
    vuln_id: int,
    payload: LinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Link one finding to a business application (overrides the asset's link)."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
    app = _app_for_org(db, payload.business_app_id, asset.organization_id)
    vuln.business_app_id = app.id if app else None
    _reevaluate(db, [vuln])
    db.commit()
    effective = app or (
        db.query(BusinessApplication).filter(BusinessApplication.id == asset.business_app_id).first()
        if asset.business_app_id else None
    )
    return {"business_app": business_app_summary(effective, inherited=app is None) if effective else None}


@router.put("/assets/{asset_id}")
def link_asset(
    asset_id: int,
    payload: LinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Link an asset to a business application; its findings inherit it."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not check_org_access(db, current_user, asset_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    app = _app_for_org(db, payload.business_app_id, asset.organization_id)
    asset.business_app_id = app.id if app else None
    open_vulns = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.asset_id == asset_id,
            Vulnerability.business_app_id.is_(None),
            Vulnerability.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]),
        )
        .all()
    )
    _reevaluate(db, open_vulns)
    db.commit()
    return {"business_app": business_app_summary(app) if app else None, "findings_updated": len(open_vulns)}
