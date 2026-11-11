"""Pydantic schemas for the CrowdStrike Falcon Exposure Management integration."""

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field

FalconCloud = Literal["us-1", "us-2", "eu-1", "us-gov-1", "us-gov-2"]


class CrowdStrikeIntegrationCreate(BaseModel):
    connection_name: str = Field(..., min_length=1, max_length=255)
    cloud: FalconCloud = "us-1"
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    member_cid: Optional[str] = Field(None, max_length=64)
    asset_filter: Optional[str] = Field(None, max_length=2000)
    import_assets: bool = True
    import_vulnerabilities: bool = True
    import_policies: bool = True
    internet_exposed_only: bool = True
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=15, le=10080)


class CrowdStrikeIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = Field(None, min_length=1, max_length=255)
    cloud: Optional[FalconCloud] = None
    client_id: Optional[str] = Field(None, min_length=1)
    client_secret: Optional[str] = Field(None, min_length=1)
    member_cid: Optional[str] = Field(None, max_length=64)
    asset_filter: Optional[str] = Field(None, max_length=2000)
    import_assets: Optional[bool] = None
    import_vulnerabilities: Optional[bool] = None
    import_policies: Optional[bool] = None
    internet_exposed_only: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)


class CrowdStrikeIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    cloud: str
    member_cid: Optional[str] = None
    asset_filter: Optional[str] = None
    import_assets: bool
    import_vulnerabilities: bool
    import_policies: bool
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


class CrowdStrikeTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    scopes: Dict[str, bool] = Field(default_factory=dict)


class CrowdStrikeSyncResult(BaseModel):
    ok: bool
    message: str
    external_assets_seen: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    ports_created: int = 0
    ports_updated: int = 0
    vulns_seen: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    vulns_unlinked: int = 0
    hosts_seen: int = 0
    policies_seen: int = 0
    hosts_prevent: int = 0
    hosts_detect_only: int = 0
    hosts_unprotected: int = 0
    exposure_paths: int = 0
