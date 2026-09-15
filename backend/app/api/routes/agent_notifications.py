"""Tenant-scoped configuration for event-driven agent notifications."""

from __future__ import annotations

import re
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.database import get_db
from app.models.agent_runtime import AgentNotificationEndpoint
from app.models.user import User
from app.services.agent.notifications import ACTIONABLE_EVENTS

router = APIRouter(prefix="/agent/notifications", tags=["agent-notifications"])

Channel = Literal["email", "webhook", "slack", "teams"]
Severity = Literal["info", "low", "medium", "high", "critical"]
_CONFIG_REF = re.compile(r"^[A-Z_][A-Z0-9_]{2,254}$")


class EndpointCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    channel: Channel
    config_ref: str = Field(min_length=3, max_length=255)
    event_types: list[str] = Field(default_factory=list)
    minimum_severity: Optional[Severity] = None
    enabled: bool = True
    organization_id: Optional[int] = None

    @field_validator("config_ref")
    @classmethod
    def validate_config_ref(cls, value: str) -> str:
        value = value.strip()
        if not _CONFIG_REF.fullmatch(value):
            raise ValueError("config_ref must be an uppercase environment-variable name")
        return value

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, values: list[str]) -> list[str]:
        unique = list(dict.fromkeys(values))
        invalid = sorted(set(unique) - ACTIONABLE_EVENTS)
        if invalid:
            raise ValueError(f"unsupported event types: {', '.join(invalid)}")
        return unique


class EndpointUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    channel: Optional[Channel] = None
    config_ref: Optional[str] = Field(default=None, min_length=3, max_length=255)
    event_types: Optional[list[str]] = None
    minimum_severity: Optional[Severity] = None
    enabled: Optional[bool] = None

    @field_validator("config_ref")
    @classmethod
    def validate_config_ref(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if not _CONFIG_REF.fullmatch(value):
            raise ValueError("config_ref must be an uppercase environment-variable name")
        return value

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, values: Optional[list[str]]) -> Optional[list[str]]:
        if values is None:
            return values
        unique = list(dict.fromkeys(values))
        invalid = sorted(set(unique) - ACTIONABLE_EVENTS)
        if invalid:
            raise ValueError(f"unsupported event types: {', '.join(invalid)}")
        return unique


def _organization_id(user: User, requested: Optional[int] = None) -> int:
    if user.is_superuser and requested is not None:
        return int(requested)
    organization_id = getattr(user, "organization_id", None)
    if not organization_id:
        raise HTTPException(status_code=400, detail="organization_required")
    return int(organization_id)


def _endpoint(db: Session, endpoint_id: int, user: User) -> AgentNotificationEndpoint:
    row = db.query(AgentNotificationEndpoint).filter(AgentNotificationEndpoint.id == endpoint_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="notification endpoint not found")
    if not user.is_superuser and row.organization_id != user.organization_id:
        raise HTTPException(status_code=403, detail="access denied")
    return row


def _serialize(row: AgentNotificationEndpoint) -> dict:
    return {
        "id": row.id,
        "organization_id": row.organization_id,
        "name": row.name,
        "channel": row.channel,
        "config_ref": row.config_ref,
        "event_types": list(row.event_types or []),
        "minimum_severity": row.minimum_severity,
        "enabled": row.enabled,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


@router.get("")
def list_endpoints(
    organization_id: Optional[int] = None,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    org_id = _organization_id(current_user, organization_id)
    rows = (
        db.query(AgentNotificationEndpoint)
        .filter(AgentNotificationEndpoint.organization_id == org_id)
        .order_by(AgentNotificationEndpoint.name.asc())
        .all()
    )
    return [_serialize(row) for row in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_endpoint(
    payload: EndpointCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    org_id = _organization_id(current_user, payload.organization_id)
    duplicate = db.query(AgentNotificationEndpoint.id).filter(
        AgentNotificationEndpoint.organization_id == org_id,
        AgentNotificationEndpoint.name == payload.name.strip(),
    ).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="notification endpoint name already exists")
    row = AgentNotificationEndpoint(
        organization_id=org_id,
        name=payload.name.strip(),
        channel=payload.channel,
        config_ref=payload.config_ref,
        event_types=payload.event_types,
        minimum_severity=payload.minimum_severity,
        enabled=payload.enabled,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.patch("/{endpoint_id}")
def update_endpoint(
    endpoint_id: int,
    payload: EndpointUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = _endpoint(db, endpoint_id, current_user)
    updates = payload.model_dump(exclude_unset=True)
    if "name" in updates:
        updates["name"] = updates["name"].strip()
        duplicate = db.query(AgentNotificationEndpoint.id).filter(
            AgentNotificationEndpoint.organization_id == row.organization_id,
            AgentNotificationEndpoint.name == updates["name"],
            AgentNotificationEndpoint.id != row.id,
        ).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="notification endpoint name already exists")
    for key, value in updates.items():
        setattr(row, key, value)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.delete("/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_endpoint(
    endpoint_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = _endpoint(db, endpoint_id, current_user)
    db.delete(row)
    db.commit()
    return None
