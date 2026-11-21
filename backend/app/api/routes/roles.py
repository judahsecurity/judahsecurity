"""Custom roles: permission catalog, CRUD, and assignment (org admins)."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.permissions import (
    BUILTIN, PERMISSIONS, clear_cache, effective_permissions, validate_permissions,
)
from app.db.database import get_db
from app.models.org_role import OrgRole
from app.models.user import User

router = APIRouter(prefix="/roles", tags=["Roles"])


class RoleBody(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=300)
    permissions: List[str]


class AssignBody(BaseModel):
    user_id: int
    role_id: Optional[int] = None  # None removes the custom role


def _org(user: User, organization_id: Optional[int]) -> int:
    if user.is_superuser and organization_id:
        return organization_id
    if not user.organization_id:
        raise HTTPException(status_code=403, detail="No organization")
    if organization_id and organization_id != user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return user.organization_id


def _out(role: OrgRole, members: int = 0) -> dict:
    return {"id": role.id, "name": role.name, "description": role.description,
            "permissions": sorted(role.permissions or []), "members": members}


def _role(db: Session, role_id: int, org_id: int) -> OrgRole:
    role = db.get(OrgRole, role_id)
    if role is None or role.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


def _audit(action, user, org_id, target, detail):
    from app.services.platform_audit import record as audit

    audit(action, user=user, organization_id=org_id, target=target, detail=detail)


@router.get("")
def list_roles(organization_id: Optional[int] = None, db: Session = Depends(get_db),
               current_user: User = Depends(require_admin)):
    org_id = _org(current_user, organization_id)
    roles = db.query(OrgRole).filter(OrgRole.organization_id == org_id).order_by(OrgRole.name).all()
    counts = {}
    for (rid,) in db.query(User.custom_role_id).filter(User.organization_id == org_id,
                                                       User.custom_role_id.isnot(None)):
        counts[rid] = counts.get(rid, 0) + 1
    return {
        "permissions": [{"name": k, "description": v} for k, v in PERMISSIONS.items()],
        "builtin": {k: sorted(v) for k, v in BUILTIN.items()},
        "roles": [_out(r, counts.get(r.id, 0)) for r in roles],
    }


@router.post("", status_code=201)
def create_role(body: RoleBody, organization_id: Optional[int] = None,
                db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    org_id = _org(current_user, organization_id)
    try:
        perms = validate_permissions(body.permissions)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if db.query(OrgRole).filter(OrgRole.organization_id == org_id, OrgRole.name == body.name).first():
        raise HTTPException(status_code=409, detail="A role with this name exists")
    role = OrgRole(organization_id=org_id, name=body.name, description=body.description,
                   permissions=perms)
    db.add(role)
    db.commit()
    db.refresh(role)
    _audit("role.create", current_user, org_id, role.name, {"permissions": perms})
    return _out(role)


@router.put("/assign")
def assign_role(body: AssignBody, organization_id: Optional[int] = None,
                db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    org_id = _org(current_user, organization_id)
    user = db.get(User, body.user_id)
    if user is None or user.organization_id != org_id:
        raise HTTPException(status_code=404, detail="User not found")
    role = _role(db, body.role_id, org_id) if body.role_id is not None else None
    user.custom_role_id = role.id if role else None
    db.commit()
    clear_cache(user.id)
    _audit("role.assign", current_user, org_id, user.email or user.username,
           {"user_id": user.id, "role": role.name if role else None})
    return {"user_id": user.id, "role_id": user.custom_role_id,
            "effective_permissions": sorted(effective_permissions(db, user))}


@router.put("/{role_id}")
def update_role(role_id: int, body: RoleBody, organization_id: Optional[int] = None,
                db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    org_id = _org(current_user, organization_id)
    role = _role(db, role_id, org_id)
    try:
        perms = validate_permissions(body.permissions)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    before = sorted(role.permissions or [])
    role.name, role.description, role.permissions = body.name, body.description, perms
    db.commit()
    clear_cache()
    _audit("role.update", current_user, org_id, role.name, {"before": before, "after": perms})
    return _out(role)


@router.delete("/{role_id}", status_code=204)
def delete_role(role_id: int, organization_id: Optional[int] = None,
                db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    org_id = _org(current_user, organization_id)
    role = _role(db, role_id, org_id)
    db.query(User).filter(User.custom_role_id == role.id).update({User.custom_role_id: None})
    name = role.name
    db.delete(role)
    db.commit()
    clear_cache()
    _audit("role.delete", current_user, org_id, name, {})
