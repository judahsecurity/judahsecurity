"""Pydantic schemas for the pfSense integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class PfSenseIntegrationCreate(BaseModel):
    name: str = Field(..., description="Label to identify this connection (e.g. 'Edge pfSense').")
    pfsense_host: str = Field(..., description="Full URL of the pfSense web interface.")
    api_key: str = Field(..., description="pfSense REST API key (sent as X-API-Key).")
    verify_ssl: bool = Field(True, description="Verify TLS certificates when calling pfSense.")
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("pfsense_host")
    @classmethod
    def normalize_host(cls, v: str) -> str:
        host = (v or "").strip().rstrip("/")
        if not host:
            raise ValueError("pfSense host is required.")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host

    @field_validator("api_key")
    @classmethod
    def non_empty_key(cls, v: str) -> str:
        if not (v or "").strip():
            raise ValueError("API key is required.")
        return v.strip()


class PfSenseIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    pfsense_host: Optional[str] = None
    api_key: Optional[str] = Field(
        None, description="Provide a new API key, or omit to keep the existing one."
    )
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("pfsense_host")
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


class PfSenseIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    pfsense_host: str
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


class PfSenseTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    alias_count: Optional[int] = None


class PfSenseSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    aliases_seen: int = 0
    entries_seen: int = 0
    ips_imported: int = 0
    cidrs_imported: int = 0
    fqdns_imported: int = 0
    assets_missing_from_source: int = 0
