"""Business applications and application services (ServiceNow CMDB), and the
attribution of assets and findings to them — owner, support group and
business unit."""

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
from app.models.application_service import ApplicationService
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
    """Pull business applications, application services and the CIs that run
    them from the org's ServiceNow CMDB, then attribute assets to them."""
    from app.services.cmdb_sync import sync_cmdb

    try:
        result = await sync_cmdb(db, _org_id(current_user))
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.warning("ServiceNow CMDB sync failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="ServiceNow request failed")
    db.commit()
    return result


@router.post("/attribute")
def reattribute_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Re-match assets to the last synced CMDB data (e.g. after discovery
    adds assets) without calling ServiceNow."""
    from app.services.cmdb_sync import attribute_assets

    result = attribute_assets(db, _org_id(current_user))
    db.commit()
    return result


def service_summary(svc: ApplicationService) -> dict:
    return {
        "id": svc.id,
        "number": svc.number,
        "name": svc.name,
        "service_class": svc.service_class,
        "business_app_id": svc.business_app_id,
        "business_criticality": svc.business_criticality,
        "criticality_level": svc.criticality_level,
        "environment": svc.environment,
        "owner": svc.owner,
        "support_group": svc.support_group,
        "business_unit": svc.business_unit,
        "external_url": svc.external_url,
    }


@router.get("/services")
def list_app_services(
    q: Optional[str] = Query(None, description="Search by service number or name"),
    business_app_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    query = db.query(ApplicationService).filter(ApplicationService.organization_id == _org_id(current_user))
    if business_app_id:
        query = query.filter(ApplicationService.business_app_id == business_app_id)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(ApplicationService.number.ilike(like), ApplicationService.name.ilike(like)))
    svcs = query.order_by(ApplicationService.criticality_level.asc().nullslast(), ApplicationService.name).limit(limit).all()
    return [service_summary(s) for s in svcs]


@router.get("/attribution")
def attribution_summary(
    group_by: str = Query("business_unit", pattern="^(business_unit|owner|support_group|business_app|app_service)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Assets and open findings per business unit / owner / support group /
    business application / application service. Unattributed ones are
    grouped under ``null``."""
    from app.services.app_attribution import effective_ids, ownership_summary

    org_id = _org_id(current_user)
    apps = {a.id: a for a in db.query(BusinessApplication).filter(BusinessApplication.organization_id == org_id)}
    services = {s.id: s for s in db.query(ApplicationService).filter(ApplicationService.organization_id == org_id)}
    keys = {"business_app": "business_app_name", "app_service": "app_service_name"}
    field = keys.get(group_by, group_by)
    cache: dict = {}

    def group(app_id, svc_id):
        if (app_id, svc_id) not in cache:
            svc = services.get(svc_id)
            app = apps.get(app_id) or (apps.get(svc.business_app_id) if svc else None)
            summary = ownership_summary(app, svc)
            cache[(app_id, svc_id)] = summary.get(field) if summary else None
        return cache[(app_id, svc_id)]

    groups: dict = {}

    def bucket(name):
        return groups.setdefault(name, {
            group_by: name, "assets": 0, "open_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        })

    asset_rows = (
        db.query(Asset.id, Asset.business_app_id, Asset.app_service_id)
        .filter(Asset.organization_id == org_id, Asset.in_scope.is_(True))
        .all()
    )
    by_asset = {}
    for asset_id, app_id, svc_id in asset_rows:
        by_asset[asset_id] = (app_id, svc_id)
        bucket(group(app_id, svc_id))["assets"] += 1

    vuln_rows = (
        db.query(Vulnerability.asset_id, Vulnerability.business_app_id, Vulnerability.severity)
        .join(Asset, Asset.id == Vulnerability.asset_id)
        .filter(
            Asset.organization_id == org_id,
            Asset.in_scope.is_(True),
            Vulnerability.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]),
        )
        .all()
    )

    class _A:  # minimal asset stand-in for effective_ids
        __slots__ = ("business_app_id", "app_service_id")

    for asset_id, vuln_app_id, severity in vuln_rows:
        a = _A()
        a.business_app_id, a.app_service_id = by_asset.get(asset_id, (None, None))
        b = bucket(group(*effective_ids(vuln_app_id, a, services)))
        b["open_findings"] += 1
        sev = getattr(severity, "value", severity) or "info"
        b[sev if sev in b else "info"] += 1

    return sorted(
        groups.values(),
        key=lambda g: (g[group_by] is None, -g["critical"], -g["high"], -g["open_findings"], str(g[group_by])),
    )


class LinkRequest(BaseModel):
    business_app_id: Optional[int] = None  # null clears the link
    app_service_id: Optional[int] = None  # assets only; null clears it


def _service_for_org(db: Session, svc_id: Optional[int], org_id: int) -> Optional[ApplicationService]:
    if svc_id is None:
        return None
    svc = db.query(ApplicationService).filter(ApplicationService.id == svc_id).first()
    if svc is None or svc.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application service not found")
    return svc


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
    from app.services.app_attribution import ownership_for_vulns

    return {
        "business_app": business_app_summary(effective, inherited=app is None) if effective else None,
        "ownership": ownership_for_vulns(db, [vuln]).get(vuln.id),
    }


@router.put("/assets/{asset_id}")
def link_asset(
    asset_id: int,
    payload: LinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Link an asset to a business application and/or application service;
    its findings inherit it. A manual link is never replaced by CMDB sync;
    clearing both hands the asset back to automatic attribution."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not check_org_access(db, current_user, asset_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    svc = _service_for_org(db, payload.app_service_id, asset.organization_id)
    app = _app_for_org(db, payload.business_app_id, asset.organization_id)
    if app is None and svc is not None and svc.business_app_id:
        app = db.query(BusinessApplication).filter(BusinessApplication.id == svc.business_app_id).first()
    asset.business_app_id = app.id if app else None
    asset.app_service_id = svc.id if svc else None
    if app or svc:
        asset.app_link_source, asset.app_link_detail = "manual", "Linked by an analyst"
    else:
        asset.app_link_source = asset.app_link_detail = None
        from app.services.cmdb_sync import attribute_assets

        attribute_assets(db, asset.organization_id, [asset])
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
    from app.services.app_attribution import ownership_for_assets

    return {
        "business_app": business_app_summary(app) if app else None,
        "ownership": ownership_for_assets(db, [asset]).get(asset.id),
        "findings_updated": len(open_vulns),
    }
