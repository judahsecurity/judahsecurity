"""Pydantic schemas for the SecurityScorecard integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


def _strip(value: Optional[str]) -> Optional[str]:
    return value.strip() if isinstance(value, str) else value


class SecurityScorecardIntegrationCreate(BaseModel):
    connection_name: str = Field("SecurityScorecard", min_length=1, max_length=255)
    api_key: str = Field(..., min_length=1)
    import_risks: bool = True
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=15, le=10080)

    _strip_fields = field_validator("connection_name", "api_key")(_strip)


class SecurityScorecardIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = Field(None, min_length=1, max_length=255)
    api_key: Optional[str] = Field(None, min_length=1)
    import_risks: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    _strip_fields = field_validator("connection_name", "api_key")(_strip)


class SecurityScorecardIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    username: str
    import_risks: bool
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


class SecurityScorecardTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    portfolio_count: int = 0


class SecurityScorecardSyncResult(BaseModel):
    ok: bool
    message: str
    portfolios_seen: int = 0
    companies_seen: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    risks_created: int = 0
    risks_updated: int = 0
    risks_resolved: int = 0
    companies_without_factors: int = 0
    definitions_missing: int = 0
