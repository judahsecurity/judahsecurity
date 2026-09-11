"""Pydantic schemas for the Wiz integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


def _clean_url(value: str) -> str:
    return value.strip().rstrip("/")


class WizIntegrationCreate(BaseModel):
    connection_name: str = Field(..., min_length=1, max_length=255)
    api_endpoint: str = Field(..., min_length=1, max_length=500)
    auth_url: str = Field(
        "https://auth.app.wiz.io/oauth/token", min_length=1, max_length=500
    )
    audience: str = Field("wiz-api", min_length=1, max_length=100)
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    import_assets: bool = True
    import_vulnerabilities: bool = True
    internet_exposed_only: bool = True
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=15, le=10080)

    _normalize_api_endpoint = field_validator("api_endpoint")(_clean_url)
    _normalize_auth_url = field_validator("auth_url")(_clean_url)


class WizIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = Field(None, min_length=1, max_length=255)
    api_endpoint: Optional[str] = Field(None, min_length=1, max_length=500)
    auth_url: Optional[str] = Field(None, min_length=1, max_length=500)
    audience: Optional[str] = Field(None, min_length=1, max_length=100)
    client_id: Optional[str] = Field(None, min_length=1)
    client_secret: Optional[str] = Field(None, min_length=1)
    import_assets: Optional[bool] = None
    import_vulnerabilities: Optional[bool] = None
    internet_exposed_only: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("api_endpoint", "auth_url")
    @classmethod
    def normalize_optional_url(cls, value: Optional[str]) -> Optional[str]:
        return _clean_url(value) if value else value


class WizIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    api_endpoint: str
    auth_url: str
    audience: str
    import_assets: bool
    import_vulnerabilities: bool
    internet_exposed_only: bool
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


class WizTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    findings_accessible: bool = False


class WizSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    findings_seen: int = 0
    findings_filtered: int = 0
