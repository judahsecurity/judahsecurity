"""Pydantic schemas for the Black Kite integration."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


def split_csv(value: Union[str, List[str], None]) -> List[str]:
    """Accept a comma-separated string or a list; return trimmed, de-duplicated items."""
    if value is None:
        return []
    items = value.split(",") if isinstance(value, str) else value
    seen: Dict[str, str] = {}
    for item in items:
        cleaned = str(item or "").strip()
        if cleaned and cleaned.lower() not in seen:
            seen[cleaned.lower()] = cleaned
    return list(seen.values())


class BlackKiteIntegrationCreate(BaseModel):
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    ecosystem_names: List[str] = Field(
        default_factory=list,
        description="Ecosystem names grouping your own companies (comma-separated or list).",
    )
    company_domains: List[str] = Field(
        default_factory=list,
        description="Domains of your own companies (comma-separated or list).",
    )
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=60, le=10080)

    @field_validator("ecosystem_names", "company_domains", mode="before")
    @classmethod
    def _split(cls, value):
        return split_csv(value)

    @model_validator(mode="after")
    def require_scope(self):
        if not self.ecosystem_names and not self.company_domains:
            raise ValueError("Provide at least one ecosystem name or company domain.")
        return self


class BlackKiteIntegrationUpdate(BaseModel):
    client_id: Optional[str] = Field(None, min_length=1)
    client_secret: Optional[str] = Field(None, min_length=1)
    ecosystem_names: Optional[List[str]] = None
    company_domains: Optional[List[str]] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=60, le=10080)

    @field_validator("ecosystem_names", "company_domains", mode="before")
    @classmethod
    def _split(cls, value):
        return None if value is None else split_csv(value)


class BlackKiteMatchedCompany(BaseModel):
    id: str
    name: Optional[str] = None
    domain: Optional[str] = None


class BlackKiteIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    ecosystem_names: List[str] = []
    company_domains: List[str] = []
    matched_companies: List[BlackKiteMatchedCompany] = []
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


class BlackKiteTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    matched_companies: List[BlackKiteMatchedCompany] = []


class BlackKiteSyncResult(BaseModel):
    ok: bool
    message: str
    companies_synced: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    vulns_resolved: int = 0
    subdomains_seen: int = 0
    findings_seen: int = 0
    fraudulent_domains_seen: int = 0
