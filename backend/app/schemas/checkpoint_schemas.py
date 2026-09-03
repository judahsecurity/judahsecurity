"""Pydantic schemas for the Check Point integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class CheckPointIntegrationCreate(BaseModel):
    name: str = Field(..., description="Label to identify this connection (e.g. 'HQ Management').")
    management_host: str = Field(..., description="Full URL of the Security Management Server.")
    username: str = Field(..., description="Management API username.")
    password: str = Field(..., description="Management API password.")
    domain: Optional[str] = Field(
        None,
        description="Optional domain for a Multi-Domain Server. Leave blank for a single-domain SMS.",
    )
    verify_ssl: bool = Field(True, description="Verify TLS certificates when calling the management server.")
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("management_host")
    @classmethod
    def normalize_host(cls, v: str) -> str:
        host = (v or "").strip().rstrip("/")
        if not host:
            raise ValueError("Management host is required.")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host

    @field_validator("username", "password")
    @classmethod
    def non_empty_credential(cls, v: str, info) -> str:
        if not (v or "").strip():
            raise ValueError(f"{info.field_name} is required.")
        return v.strip()

    @field_validator("domain")
    @classmethod
    def empty_domain_as_none(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        return trimmed or None


class CheckPointIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    management_host: Optional[str] = None
    username: Optional[str] = Field(
        None, description="Provide a new username, or omit to keep the existing one."
    )
    password: Optional[str] = Field(
        None, description="Provide a new password, or omit to keep the existing one."
    )
    domain: Optional[str] = None
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("management_host")
    @classmethod
    def normalize_host(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        host = v.strip().rstrip("/")
        if not host:
            return None
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host


class CheckPointIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    management_host: str
    domain: Optional[str] = None
    verify_ssl: bool
    is_active: bool
    continuous_sync_enabled: bool
    sync_interval_minutes: int
    last_tested_at: Optional[datetime]
    last_test_ok: Optional[bool]
    last_sync_at: Optional[datetime]
    last_sync_ok: Optional[bool]
    next_sync_at: Optional[datetime] = None
    last_sync_stats: Optional[Dict[str, Any]] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CheckPointTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    object_count: Optional[int] = None


class CheckPointSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    hosts_seen: int = 0
    networks_seen: int = 0
    ranges_seen: int = 0
    ips_imported: int = 0
    cidrs_imported: int = 0
    ranges_seeded: int = 0
    assets_missing_from_source: int = 0
