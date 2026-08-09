"""Pydantic schemas for the Palo Alto Networks Panorama integration."""

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

ConnectionMode = Literal["api", "config_export"]


class PanoramaIntegrationCreate(BaseModel):
    name: str = Field(..., description="Label to identify this connection (e.g. 'HQ Panorama').")
    connection_mode: ConnectionMode = Field(
        "api",
        description="api = live REST pull; config_export = ingest Panorama configuration export files.",
    )
    panorama_host: Optional[str] = Field(
        None,
        description="Full URL of the Panorama instance (required for api mode).",
    )
    api_key: Optional[str] = Field(
        None, description="Panorama API key / X-PAN-KEY (required for api mode)."
    )
    device_group: Optional[str] = Field(
        None,
        description="Device group to scope the import. Leave blank for shared (api) or all scopes (config export).",
    )
    api_version: str = Field("v11.1", description="REST API version segment (default v11.1).")
    verify_ssl: bool = Field(True, description="Verify TLS certificates when calling Panorama.")
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("panorama_host")
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

    @field_validator("api_version")
    @classmethod
    def normalize_api_version(cls, v: str) -> str:
        version = (v or "v11.1").strip()
        if not version.startswith("v"):
            version = f"v{version}"
        return version

    @field_validator("device_group")
    @classmethod
    def empty_device_group_as_none(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        return trimmed or None

    @model_validator(mode="after")
    def validate_mode_requirements(self) -> "PanoramaIntegrationCreate":
        if self.connection_mode == "api":
            if not self.panorama_host:
                raise ValueError("Panorama host is required for API mode.")
            if not (self.api_key or "").strip():
                raise ValueError("API key is required for API mode.")
        return self


class PanoramaIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    connection_mode: Optional[ConnectionMode] = None
    panorama_host: Optional[str] = None
    api_key: Optional[str] = Field(
        None, description="Provide a new API key, or omit to keep the existing one."
    )
    device_group: Optional[str] = None
    api_version: Optional[str] = None
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("panorama_host")
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

    @field_validator("api_version")
    @classmethod
    def normalize_api_version(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        version = v.strip()
        if not version.startswith("v"):
            version = f"v{version}"
        return version


class PanoramaIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    connection_mode: str = "api"
    panorama_host: Optional[str] = None
    device_group: Optional[str] = None
    api_version: str
    verify_ssl: bool
    export_filename: Optional[str] = None
    export_file_size: Optional[int] = None
    export_uploaded_at: Optional[datetime] = None
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


class PanoramaTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    address_count: Optional[int] = None


class PanoramaSyncResult(BaseModel):
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
    source: Optional[str] = None  # "api" | "config_export"


class PanoramaUploadResponse(BaseModel):
    ok: bool
    message: str
    filename: Optional[str] = None
    file_size: Optional[int] = None
    address_count: Optional[int] = None
    address_groups_count: Optional[int] = None
    sync: Optional[PanoramaSyncResult] = None
