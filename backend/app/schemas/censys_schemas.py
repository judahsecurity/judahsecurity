"""Pydantic schemas for the Censys ASM integration."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CensysIntegrationCreate(BaseModel):
    workspace_name: str = Field(
        ..., description="Label to identify this connection (e.g. 'Production')."
    )
    api_key: str = Field(..., description="Workspace-scoped Censys ASM API key.")
    import_vulnerabilities: bool = True
    import_assets: bool = True
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)  # 15 min .. 7 days


class CensysIntegrationUpdate(BaseModel):
    workspace_name: Optional[str] = None
    api_key: Optional[str] = Field(
        None, description="Provide a new API key, or omit to keep the existing one."
    )
    import_vulnerabilities: Optional[bool] = None
    import_assets: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)


class CensysIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    workspace_name: str
    import_vulnerabilities: bool
    import_assets: bool
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
    field_mappings: List[Dict[str, str]] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CensysTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    workspace_id: Optional[str] = None


class CensysSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    hosts_seen: int = 0
    domains_seen: int = 0
    subdomains_seen: int = 0
    certificates_seen: int = 0
    risks_seen: int = 0


class CensysFieldMappingRule(BaseModel):
    entity: str
    source_path: str
    target: str


class CensysFieldMappingUpdate(BaseModel):
    rules: List[CensysFieldMappingRule] = Field(default_factory=list, max_length=50)
