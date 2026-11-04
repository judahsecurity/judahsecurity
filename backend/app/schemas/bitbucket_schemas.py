"""Pydantic schemas for the Bitbucket Cloud integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class BitbucketIntegrationCreate(BaseModel):
    workspace_url: str = Field(..., min_length=1, max_length=500)
    access_token: str = Field(..., min_length=1)
    scan_secrets: bool = True
    max_repo_size_mb: int = Field(500, ge=1, le=5000)
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=60, le=10080)


class BitbucketIntegrationUpdate(BaseModel):
    access_token: Optional[str] = Field(None, min_length=1)
    scan_secrets: Optional[bool] = None
    max_repo_size_mb: Optional[int] = Field(None, ge=1, le=5000)
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=60, le=10080)


class BitbucketIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    workspace: str
    workspace_url: str
    scan_secrets: bool
    max_repo_size_mb: int
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


class BitbucketTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    repositories_accessible: bool = False


class BitbucketSyncResult(BaseModel):
    ok: bool
    message: str
    repos_seen: int = 0
    repos_skipped_forks: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    repos_scanned: int = 0
    repos_scan_skipped: int = 0
    repos_scan_failed: int = 0
    secrets_created: int = 0
    secrets_updated: int = 0
    secrets_resolved: int = 0
