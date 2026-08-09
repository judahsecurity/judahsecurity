"""Pydantic schemas for the F5 BIG-IP LTM reachability integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class F5IntegrationCreate(BaseModel):
    name: str = Field(..., description="Label to identify this connection (e.g. 'DC1 BIG-IP').")
    bigip_host: str = Field(..., description="Full URL of the BIG-IP management interface.")
    username: str = Field(..., description="BIG-IP management username.")
    password: str = Field(..., description="BIG-IP management password.")
    partition: Optional[str] = Field(
        None,
        description="Optional partition scope (e.g. Common). Leave blank for all partitions.",
    )
    verify_ssl: bool = Field(True, description="Verify TLS certificates when calling BIG-IP.")
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("bigip_host")
    @classmethod
    def normalize_host(cls, v: str) -> str:
        host = (v or "").strip().rstrip("/")
        if not host:
            raise ValueError("BIG-IP host is required.")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host

    @field_validator("username", "password")
    @classmethod
    def non_empty_credential(cls, v: str, info) -> str:
        if not (v or "").strip():
            raise ValueError(f"{info.field_name} is required.")
        return v.strip()

    @field_validator("partition")
    @classmethod
    def empty_partition_as_none(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        return trimmed or None


class F5IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    bigip_host: Optional[str] = None
    username: Optional[str] = Field(
        None, description="Provide a new username, or omit to keep the existing one."
    )
    password: Optional[str] = Field(
        None, description="Provide a new password, or omit to keep the existing one."
    )
    partition: Optional[str] = None
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("bigip_host")
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


class F5IntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    bigip_host: str
    partition: Optional[str] = None
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


class F5TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    virtual_count: Optional[int] = None


class F5SyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    virtuals_seen: int = 0
    vips_imported: int = 0
    members_imported: int = 0
    mappings_seen: int = 0
    assets_missing_from_source: int = 0
