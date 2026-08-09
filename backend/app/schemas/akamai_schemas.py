"""Pydantic schemas for the Akamai WAF integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


def _normalize_api_host(value: str) -> str:
    host = (value or "").strip()
    if not host:
        raise ValueError("missing Akamai API host")
    lower = host.lower()
    if lower.startswith("https://") or lower.startswith("http://"):
        raise ValueError("API Host should not include protocol — enter only the hostname")
    # Strip any trailing slash / path the user may have pasted.
    host = host.split("/")[0].strip()
    if not host:
        raise ValueError("missing Akamai API host")
    return host


class AkamaiIntegrationCreate(BaseModel):
    connection_name: str = Field(
        ..., description="Label to identify this connection (e.g. 'Production')."
    )
    api_host: str = Field(
        ...,
        description="Akamai EdgeGrid API hostname (e.g. akab-xxxxx.luna.akamaiapis.net).",
    )
    client_token: str = Field(..., description="EdgeGrid client token.")
    client_secret: str = Field(..., description="EdgeGrid client secret.")
    access_token: str = Field(..., description="EdgeGrid access token.")
    import_configurations: bool = True
    import_hostnames: bool = True
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("api_host")
    @classmethod
    def validate_api_host(cls, v: str) -> str:
        return _normalize_api_host(v)

    @field_validator("client_token", "client_secret", "access_token")
    @classmethod
    def non_empty_credential(cls, v: str, info) -> str:
        if not (v or "").strip():
            raise ValueError(f"missing EdgeGrid {info.field_name}")
        return v.strip()


class AkamaiIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = None
    api_host: Optional[str] = Field(
        None,
        description="Akamai EdgeGrid API hostname. Omit to keep the existing value.",
    )
    client_token: Optional[str] = Field(
        None, description="Provide a new client token, or omit to keep the existing one."
    )
    client_secret: Optional[str] = Field(
        None, description="Provide a new client secret, or omit to keep the existing one."
    )
    access_token: Optional[str] = Field(
        None, description="Provide a new access token, or omit to keep the existing one."
    )
    import_configurations: Optional[bool] = None
    import_hostnames: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("api_host")
    @classmethod
    def validate_api_host(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _normalize_api_host(v)


class AkamaiIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    api_host: str
    import_configurations: bool
    import_hostnames: bool
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


class AkamaiTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    configs_found: Optional[int] = None


class AkamaiSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    configs_seen: int = 0
    policies_seen: int = 0
    hostnames_seen: int = 0
