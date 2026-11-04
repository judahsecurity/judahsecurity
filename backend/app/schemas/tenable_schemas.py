"""Pydantic schemas for the Tenable VM integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator

DEFAULT_TENABLE_URL = "https://cloud.tenable.com"


def _clean_url(value: str) -> str:
    return value.strip().rstrip("/")


class TenableIntegrationCreate(BaseModel):
    connection_name: str = Field("Tenable VM", min_length=1, max_length=255)
    base_url: str = Field(DEFAULT_TENABLE_URL, min_length=1, max_length=500)
    access_key: str = Field(..., min_length=1)
    secret_key: str = Field(..., min_length=1)
    import_assets: bool = True
    import_vulnerabilities: bool = True
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=15, le=10080)

    _normalize_base_url = field_validator("base_url")(_clean_url)


class TenableIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = Field(None, min_length=1, max_length=255)
    base_url: Optional[str] = Field(None, min_length=1, max_length=500)
    access_key: Optional[str] = Field(None, min_length=1)
    secret_key: Optional[str] = Field(None, min_length=1)
    import_assets: Optional[bool] = None
    import_vulnerabilities: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("base_url")
    @classmethod
    def normalize_optional_url(cls, value: Optional[str]) -> Optional[str]:
        return _clean_url(value) if value else value


class TenableIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    base_url: str
    import_assets: bool
    import_vulnerabilities: bool
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


class TenableTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    assets_export_ok: bool = False
    vulns_export_ok: bool = False


class TenableSyncResult(BaseModel):
    ok: bool
    message: str
    assets_seen: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    assets_skipped: int = 0
    vulns_seen: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    vulns_skipped: int = 0
    ports_created: int = 0
