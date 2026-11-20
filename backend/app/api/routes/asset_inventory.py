"""Asset spreadsheet import/export, bulk edits, and saved list views."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.asset import Asset, AssetType
from app.models.saved_view import SavedView
from app.models.user import User
from app.services import asset_inventory
from app.services.platform_audit import record as audit

router = APIRouter(tags=["Asset inventory"])
EXPORT_LIMIT = 100_000


def _org(user: User, organization_id: Optional[int]) -> int:
    if organization_id is None:
        organization_id = user.organization_id
    if not organization_id:
        raise HTTPException(status_code=400, detail="organization_id is required")
    if not user.is_superuser and user.organization_id != organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return organization_id


@router.get("/asset-inventory/export")
def export_assets(
    format: Literal["csv", "xlsx"] = "csv",
    organization_id: Optional[int] = None,
    asset_type: Optional[str] = None,
    search: Optional[str] = Query(None, max_length=200),
    in_scope: Optional[bool] = None,
    is_live: Optional[bool] = None,
    tag: Optional[str] = Query(None, max_length=64),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _org(current_user, organization_id)
    query = db.query(Asset).filter(Asset.organization_id == org_id)
    if asset_type:
        try:
            query = query.filter(Asset.asset_type == AssetType(asset_type.upper()))
        except ValueError:
            raise HTTPException(status_code=422, detail="Unknown asset_type") from None
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Asset.value.ilike(like), Asset.name.ilike(like)))
    if in_scope is not None:
        query = query.filter(Asset.in_scope == in_scope)
    if is_live is not None:
        query = query.filter(Asset.is_live == is_live)
    assets = query.order_by(Asset.value).limit(EXPORT_LIMIT).all()
    if tag:
        assets = [a for a in assets if tag in (a.tags or [])]
    audit("asset.export", user=current_user, organization_id=org_id, target=format,
          detail={"rows": len(assets), "asset_type": asset_type, "search": search})
    if format == "xlsx":
        return Response(asset_inventory.export_xlsx(assets),
                        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": 'attachment; filename="assets.xlsx"'})
    return Response(asset_inventory.export_csv(assets), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="assets.csv"'})


@router.post("/asset-inventory/import")
async def import_assets(
    file: UploadFile = File(...),
    organization_id: Optional[int] = Form(None),
    mode: Literal["skip", "update"] = Form("skip"),
    dry_run: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _org(current_user, organization_id)
    content = await file.read(asset_inventory.MAX_IMPORT_BYTES + 1)
    try:
        records = asset_inventory.read_rows(file.filename or "", content)
        result = asset_inventory.import_assets(db, org_id, records, mode=mode, dry_run=dry_run)
    except asset_inventory.ImportError_ as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if not dry_run:
        audit("asset.import", user=current_user, organization_id=org_id, target=file.filename or "",
              detail={k: result[k] for k in ("created", "updated", "skipped", "invalid")} | {"mode": mode})
    return result


@router.get("/asset-inventory/template")
def import_template():
    header = ",".join(asset_inventory.IMPORT_COLUMNS)
    example = "app.example.com,SUBDOMAIN,Customer portal,Login and billing,prod;customer-facing,high,true,true"
    return Response(f"{header}\n{example}\n", media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="asset_import_template.csv"'})


class BulkChanges(BaseModel):
    criticality: Optional[Literal["low", "medium", "high", "critical"]] = None
    in_scope: Optional[bool] = None
    is_monitored: Optional[bool] = None
    description: Optional[str] = Field(None, max_length=5000)
    add_tags: List[str] = Field(default_factory=list, max_length=20)
    remove_tags: List[str] = Field(default_factory=list, max_length=20)


class BulkUpdateBody(BaseModel):
    organization_id: Optional[int] = None
    asset_ids: List[int] = Field(min_length=1, max_length=5000)
    changes: BulkChanges


@router.post("/asset-inventory/bulk-update")
def bulk_update(body: BulkUpdateBody, db: Session = Depends(get_db),
                current_user: User = Depends(require_analyst)):
    org_id = _org(current_user, body.organization_id)
    changes = body.changes.model_dump(exclude_none=True)
    if not any(changes.get(k) for k in ("add_tags", "remove_tags")) and not any(
            k in changes for k in ("criticality", "in_scope", "is_monitored", "description")):
        raise HTTPException(status_code=422, detail="No changes given")
    updated = asset_inventory.bulk_update(db, org_id, body.asset_ids, changes)
    audit("asset.bulk_update", user=current_user, organization_id=org_id,
          target=f"{updated} assets", detail={"changes": changes, "requested": len(body.asset_ids)})
    return {"updated": updated}


# ------------------------------------------------------------- saved views

class ViewBody(BaseModel):
    page: Literal["assets", "findings"]
    name: str = Field(min_length=1, max_length=80)
    filters: Dict[str, Any] = Field(default_factory=dict)
    shared: bool = False


def _view_out(view: SavedView, user: User) -> dict:
    return {"id": view.id, "page": view.page, "name": view.name, "filters": view.filters or {},
            "shared": view.shared, "mine": view.user_id == user.id}


def _check_filters(filters: Dict[str, Any]) -> None:
    import json

    if len(json.dumps(filters, default=str)) > 4000:
        raise HTTPException(status_code=422, detail="filters are too large")


@router.get("/saved-views")
def list_views(page: Literal["assets", "findings"], db: Session = Depends(get_db),
               current_user: User = Depends(get_current_active_user)):
    org_id = _org(current_user, None)
    views = db.query(SavedView).filter(
        SavedView.organization_id == org_id, SavedView.page == page,
        or_(SavedView.user_id == current_user.id, SavedView.shared.is_(True)),
    ).order_by(SavedView.name).all()
    return [_view_out(v, current_user) for v in views]


@router.post("/saved-views", status_code=201)
def create_view(body: ViewBody, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_active_user)):
    org_id = _org(current_user, None)
    _check_filters(body.filters)
    if db.query(SavedView).filter(SavedView.user_id == current_user.id).count() >= 100:
        raise HTTPException(status_code=409, detail="At most 100 saved views per user")
    view = SavedView(organization_id=org_id, user_id=current_user.id, **body.model_dump())
    db.add(view)
    db.commit()
    db.refresh(view)
    return _view_out(view, current_user)


def _editable_view(db: Session, view_id: int, user: User) -> SavedView:
    view = db.get(SavedView, view_id)
    if view is None or view.organization_id != user.organization_id:
        raise HTTPException(status_code=404, detail="View not found")
    is_admin = user.is_superuser or getattr(user.role, "value", user.role) == "admin"
    if view.user_id != user.id and not (view.shared and is_admin):
        raise HTTPException(status_code=403, detail="Only the owner (or an admin, for shared views) can change it")
    return view


@router.put("/saved-views/{view_id}")
def update_view(view_id: int, body: ViewBody, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_active_user)):
    view = _editable_view(db, view_id, current_user)
    _check_filters(body.filters)
    for key, value in body.model_dump().items():
        setattr(view, key, value)
    db.commit()
    return _view_out(view, current_user)


@router.delete("/saved-views/{view_id}", status_code=204)
def delete_view(view_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_active_user)):
    view = _editable_view(db, view_id, current_user)
    db.delete(view)
    db.commit()
