"""Pydantic schemas for the Cloudflare WAF integration."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


def _normalize_zones(value: Optional[List[str]]) -> List[str]:
    if not value:
        return []
    out: List[str] = []
    seen = set()
    for raw in value:
        name = (raw or "").strip().lower().rstrip(".")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _normalize_ips(value: Optional[List[str]]) -> List[str]:
    if not value:
        return []
    out: List[str] = []
    seen = set()
    for raw in value:
        ip = (raw or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


class CloudflareIntegrationCreate(BaseModel):
    connection_name: str = Field(
        ..., description="Label to identify this connection (e.g. 'Production')."
    )
    api_token: str = Field(
        ...,
        description=(
            "Cloudflare API token with Account Rulesets:Read, Zone WAF:Edit, "
            "Zone Settings:Read."
        ),
    )
    zones: List[str] = Field(
        default_factory=list,
        description="Optional zone names to scope. Empty = all zones on the account.",
    )
    scanner_ips: List[str] = Field(
        default_factory=list,
        description=(
            "Optional scanner egress IPs for this connection. Empty = use "
            "platform ASM_SCANNER_EGRESS_IPS."
        ),
    )
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=15, le=10080)

    @field_validator("api_token")
    @classmethod
    def non_empty_token(cls, v: str) -> str:
        if not (v or "").strip():
            raise ValueError("missing Cloudflare API token")
        return v.strip()

    @field_validator("zones")
    @classmethod
    def clean_zones(cls, v: Optional[List[str]]) -> List[str]:
        return _normalize_zones(v)

    @field_validator("scanner_ips")
    @classmethod
    def clean_ips(cls, v: Optional[List[str]]) -> List[str]:
        return _normalize_ips(v)


class CloudflareIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = None
    api_token: Optional[str] = Field(
        None, description="Provide a new API token, or omit to keep the existing one."
    )
    zones: Optional[List[str]] = None
    scanner_ips: Optional[List[str]] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("zones")
    @classmethod
    def clean_zones(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        return _normalize_zones(v)

    @field_validator("scanner_ips")
    @classmethod
    def clean_ips(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        return _normalize_ips(v)


class CloudflareIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    zones: List[str] = []
    scanner_ips: List[str] = []
    scan_header_name: str
    scanner_user_agent: str
    effective_scanner_ips: List[str] = []
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


class CloudflareTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    zones_found: Optional[int] = None


class CloudflareSyncResult(BaseModel):
    ok: bool
    message: str
    zones_seen: int = 0
    rules_created: int = 0
    rules_updated: int = 0
    rules_skipped: int = 0
    rules_failed: int = 0
