"""Pydantic schemas for the Fortinet FortiGate integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class FortiGateIntegrationCreate(BaseModel):
    name: str = Field(..., description="Label to identify this connection (e.g. 'Perimeter FortiGate').")
    fortigate_host: str = Field(..., description="Full URL of the FortiGate management interface.")
    api_token: str = Field(..., description="FortiOS REST API token (from a REST API admin).")
    vdom: Optional[str] = Field(
        None,
        description="Optional VDOM scope (e.g. root). Leave blank for the management VDOM.",
    )
    verify_ssl: bool = Field(True, description="Verify TLS certificates when calling FortiGate.")
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("fortigate_host")
    @classmethod
    def normalize_host(cls, v: str) -> str:
        host = (v or "").strip().rstrip("/")
        if not host:
            raise ValueError("FortiGate host is required.")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host

    @field_validator("api_token")
    @classmethod
    def non_empty_token(cls, v: str) -> str:
        if not (v or "").strip():
            raise ValueError("API token is required.")
        return v.strip()

    @field_validator("vdom")
    @classmethod
    def empty_vdom_as_none(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        return trimmed or None


class FortiGateIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    fortigate_host: Optional[str] = None
    api_token: Optional[str] = Field(
        None, description="Provide a new API token, or omit to keep the existing one."
    )
    vdom: Optional[str] = None
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("fortigate_host")
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


class FortiGateIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    fortigate_host: str
    vdom: Optional[str] = None
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


class FortiGateTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    address_count: Optional[int] = None


class FortiGateSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    addresses_seen: int = 0
    address_groups_seen: int = 0
    ips_imported: int = 0
    cidrs_imported: int = 0
    fqdns_imported: int = 0
    ranges_seeded: int = 0
    assets_missing_from_source: int = 0
