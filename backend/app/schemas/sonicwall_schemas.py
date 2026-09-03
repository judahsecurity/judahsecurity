"""Pydantic schemas for the SonicWall (SonicOS) integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class SonicWallIntegrationCreate(BaseModel):
    name: str = Field(..., description="Label to identify this connection (e.g. 'Branch SonicWall').")
    sonicwall_host: str = Field(..., description="Full URL of the SonicOS management interface.")
    username: str = Field(..., description="SonicOS management username.")
    password: str = Field(..., description="SonicOS management password.")
    verify_ssl: bool = Field(True, description="Verify TLS certificates when calling SonicOS.")
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("sonicwall_host")
    @classmethod
    def normalize_host(cls, v: str) -> str:
        host = (v or "").strip().rstrip("/")
        if not host:
            raise ValueError("SonicWall host is required.")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host

    @field_validator("username", "password")
    @classmethod
    def non_empty_credential(cls, v: str, info) -> str:
        if not (v or "").strip():
            raise ValueError(f"{info.field_name} is required.")
        return v.strip()


class SonicWallIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    sonicwall_host: Optional[str] = None
    username: Optional[str] = Field(
        None, description="Provide a new username, or omit to keep the existing one."
    )
    password: Optional[str] = Field(
        None, description="Provide a new password, or omit to keep the existing one."
    )
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("sonicwall_host")
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


class SonicWallIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    sonicwall_host: str
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


class SonicWallTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    address_count: Optional[int] = None


class SonicWallSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    addresses_seen: int = 0
    ips_imported: int = 0
    cidrs_imported: int = 0
    fqdns_imported: int = 0
    ranges_seeded: int = 0
    assets_missing_from_source: int = 0
