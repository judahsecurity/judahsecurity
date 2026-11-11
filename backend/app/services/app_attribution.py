"""Ownership attribution for assets and findings.

An asset is attributed to the application service that runs it and the
business application that consumes that service (see ``cmdb_sync``). A
finding inherits its asset's attribution unless an analyst linked the finding
to a different business application.

Owner, support group and business unit come from the application service
when it has them, otherwise from the business application.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.application_service import ApplicationService
from app.models.business_application import BusinessApplication


def _first(*values: Any) -> Any:
    return next((v for v in values if v), None)


def ownership_summary(
    app: Optional[BusinessApplication],
    service: Optional[ApplicationService],
    *,
    link_source: Optional[str] = None,
    link_detail: Optional[str] = None,
    inherited_from_asset: bool = False,
) -> Optional[Dict[str, Any]]:
    if app is None and service is None:
        return None
    a, s = app, service
    return {
        "business_app_id": a.id if a else None,
        "business_app_number": a.app_id if a else None,
        "business_app_name": a.name if a else None,
        "business_app_url": a.external_url if a else None,
        "app_service_id": s.id if s else None,
        "app_service_number": s.number if s else None,
        "app_service_name": s.name if s else None,
        "app_service_url": s.external_url if s else None,
        "environment": s.environment if s else None,
        "owner": _first(s and s.owner, a and a.owner),
        "it_owner": _first(a and a.it_owner, s and s.managed_by),
        "support_group": _first(s and s.support_group, a and a.support_group),
        "business_unit": _first(s and s.business_unit, a and a.business_unit),
        "department": _first(s and s.department, a and a.department),
        "company": _first(s and s.company, a and a.company),
        "criticality_level": _first(a and a.criticality_level, s and s.criticality_level),
        "business_criticality": _first(a and a.business_criticality, s and s.business_criticality),
        "link_source": link_source,
        "link_detail": link_detail,
        "inherited_from_asset": inherited_from_asset,
    }


def effective_ids(vuln_app_id: Optional[int], asset: Any, services: Dict[int, ApplicationService]) -> Tuple[Optional[int], Optional[int]]:
    """(business_app_id, app_service_id) for a finding on ``asset``. The
    asset's service applies unless the finding was linked to another app."""
    asset_app = getattr(asset, "business_app_id", None) if asset is not None else None
    asset_svc = getattr(asset, "app_service_id", None) if asset is not None else None
    if vuln_app_id is None:
        return asset_app, asset_svc
    svc = services.get(asset_svc) if asset_svc else None
    keep = svc is not None and svc.business_app_id in (None, vuln_app_id) and asset_app in (None, vuln_app_id)
    return vuln_app_id, asset_svc if keep else None


def _load(db: Session, app_ids: Iterable[Optional[int]], svc_ids: Iterable[Optional[int]]):
    app_ids = {i for i in app_ids if i}
    svc_ids = {i for i in svc_ids if i}
    services = (
        {s.id: s for s in db.query(ApplicationService).filter(ApplicationService.id.in_(svc_ids))} if svc_ids else {}
    )
    app_ids |= {s.business_app_id for s in services.values() if s.business_app_id}
    apps = (
        {a.id: a for a in db.query(BusinessApplication).filter(BusinessApplication.id.in_(app_ids))} if app_ids else {}
    )
    return apps, services


def ownership_for_assets(db: Session, assets: Iterable[Any]) -> Dict[int, Optional[Dict[str, Any]]]:
    assets = list(assets)
    apps, services = _load(db, (a.business_app_id for a in assets), (getattr(a, "app_service_id", None) for a in assets))
    out = {}
    for a in assets:
        svc = services.get(getattr(a, "app_service_id", None))
        app = apps.get(a.business_app_id) or (apps.get(svc.business_app_id) if svc else None)
        out[a.id] = ownership_summary(
            app, svc, link_source=getattr(a, "app_link_source", None), link_detail=getattr(a, "app_link_detail", None)
        )
    return out


def ownership_for_vulns(db: Session, vulns: Iterable[Any]) -> Dict[int, Optional[Dict[str, Any]]]:
    vulns = list(vulns)
    assets = [v.asset for v in vulns if v.asset is not None]
    apps, services = _load(
        db,
        [v.business_app_id for v in vulns] + [a.business_app_id for a in assets],
        [getattr(a, "app_service_id", None) for a in assets],
    )
    out = {}
    for v in vulns:
        app_id, svc_id = effective_ids(v.business_app_id, v.asset, services)
        svc = services.get(svc_id)
        app = apps.get(app_id) or (apps.get(svc.business_app_id) if svc else None)
        inherited = v.business_app_id is None
        out[v.id] = ownership_summary(
            app,
            svc,
            link_source=getattr(v.asset, "app_link_source", None) if inherited else "manual",
            link_detail=getattr(v.asset, "app_link_detail", None) if inherited else "Linked on the finding",
            inherited_from_asset=inherited,
        )
    return out
