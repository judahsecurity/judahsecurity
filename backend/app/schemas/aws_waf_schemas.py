"""Pydantic schemas for the AWS WAF integration."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class AwsWafIntegrationCreate(BaseModel):
    name: str = Field(..., description="Label to identify this connection (e.g. 'Prod AWS').")
    access_key_id: str = Field(..., description="AWS access key ID.")
    secret_access_key: str = Field(..., description="AWS secret access key.")
    session_token: Optional[str] = Field(None, description="Optional AWS session token (for temporary credentials).")
    regions: List[str] = Field(
        default_factory=lambda: ["us-east-1"],
        description="Regions to enumerate REGIONAL Web ACLs in.",
    )
    include_cloudfront: bool = Field(True, description="Enumerate CloudFront (global) Web ACLs.")
    include_regional: bool = Field(True, description="Enumerate regional Web ACLs (ALB / API Gateway / AppSync).")
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)

    @field_validator("access_key_id", "secret_access_key")
    @classmethod
    def non_empty_credential(cls, v: str, info) -> str:
        if not (v or "").strip():
            raise ValueError(f"{info.field_name} is required.")
        return v.strip()

    @field_validator("regions")
    @classmethod
    def clean_regions(cls, v: List[str]) -> List[str]:
        cleaned = [r.strip() for r in (v or []) if isinstance(r, str) and r.strip()]
        # De-dup, preserve order.
        seen: set[str] = set()
        out: List[str] = []
        for r in cleaned:
            if r not in seen:
                seen.add(r)
                out.append(r)
        return out or ["us-east-1"]


class AwsWafIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    access_key_id: Optional[str] = Field(None, description="Provide a new access key ID, or omit to keep the existing one.")
    secret_access_key: Optional[str] = Field(None, description="Provide a new secret access key, or omit to keep the existing one.")
    session_token: Optional[str] = None
    regions: Optional[List[str]] = None
    include_cloudfront: Optional[bool] = None
    include_regional: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    @field_validator("regions")
    @classmethod
    def clean_regions(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        return [r.strip() for r in v if isinstance(r, str) and r.strip()]


class AwsWafIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    regions: List[str] = []
    include_cloudfront: bool
    include_regional: bool
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


class AwsWafTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    web_acls_found: Optional[int] = None


class AwsWafSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    web_acls_seen: int = 0
    hostnames_seen: int = 0
    resources_seen: int = 0
    assets_missing_from_source: int = 0
