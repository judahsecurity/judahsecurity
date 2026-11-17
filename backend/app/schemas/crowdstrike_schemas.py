"""CrowdStrike integration API contracts."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class CrowdStrikeIntegrationCreate(BaseModel):
    connection_name: str = Field(..., min_length=1, max_length=255)
    cloud_region: str = Field(..., pattern=r"^(us-1|us-2|eu-1|us-gov-1)$")
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    import_external_assets: bool = True
    import_hosts: bool = True
    import_spotlight: bool = True
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=15, le=10080)

    @model_validator(mode="after")
    def require_module(self):
        if not (self.import_external_assets or self.import_hosts or self.import_spotlight):
            raise ValueError("Enable at least one CrowdStrike module")
        if self.import_spotlight and not self.import_hosts:
            raise ValueError("Spotlight requires Hosts for asset correlation")
        return self


class CrowdStrikeIntegrationUpdate(BaseModel):
    connection_name: str | None = Field(None, min_length=1, max_length=255)
    cloud_region: str | None = Field(None, pattern=r"^(us-1|us-2|eu-1|us-gov-1)$")
    client_id: str | None = Field(None, min_length=1)
    client_secret: str | None = Field(None, min_length=1)
    import_external_assets: bool | None = None
    import_hosts: bool | None = None
    import_spotlight: bool | None = None
    is_active: bool | None = None
    continuous_sync_enabled: bool | None = None
    sync_interval_minutes: int | None = Field(None, ge=15, le=10080)

    @model_validator(mode="after")
    def reject_null_updates(self):
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null; omit it to keep the current value")
        return self


class CrowdStrikeIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    cloud_region: str
    import_external_assets: bool
    import_hosts: bool
    import_spotlight: bool
    is_active: bool
    continuous_sync_enabled: bool
    sync_interval_minutes: int
    last_tested_at: datetime | None
    last_test_ok: bool | None
    last_sync_at: datetime | None
    last_sync_ok: bool | None
    next_sync_at: datetime | None = None
    last_sync_stats: dict[str, Any] | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CrowdStrikeTestResult(BaseModel):
    ok: bool
    message: str


class CrowdStrikeSyncResult(CrowdStrikeTestResult):
    assets_created: int = 0
    assets_updated: int = 0
    ports_created: int = 0
    ports_updated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    vulns_resolved: int = 0
    external_seen: int = 0
    hosts_seen: int = 0
    findings_seen: int = 0
