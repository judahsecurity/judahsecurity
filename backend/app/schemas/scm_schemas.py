"""Pydantic schemas for source code manager (SCM) integrations."""

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

AuthMethod = Literal["entra_id", "pat"]


def _strip(value: Optional[str]) -> Optional[str]:
    return value.strip() if isinstance(value, str) else value


class AzureDevOpsIntegrationCreate(BaseModel):
    connection_name: str = Field(..., min_length=1, max_length=255)
    scope_url: str = Field(..., min_length=1, max_length=1000)
    auth_method: AuthMethod = "entra_id"
    personal_access_token: Optional[str] = Field(None, min_length=1)
    tenant_id: Optional[str] = Field(None, min_length=1, max_length=255)
    client_id: Optional[str] = Field(None, min_length=1, max_length=255)
    client_secret: Optional[str] = Field(None, min_length=1)
    secret_scanning_enabled: bool = True
    include_unverified_secrets: bool = False
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=60, le=10080)

    _strip_fields = field_validator(
        "connection_name", "scope_url", "personal_access_token", "tenant_id", "client_id", "client_secret"
    )(_strip)

    @model_validator(mode="after")
    def require_credentials_for_method(self):
        if self.auth_method == "pat" and not self.personal_access_token:
            raise ValueError("A Personal Access Token is required for PAT authentication.")
        if self.auth_method == "entra_id" and not (self.tenant_id and self.client_id and self.client_secret):
            raise ValueError("Tenant ID, Application (client) ID and client secret are required for Entra ID authentication.")
        return self


class AzureDevOpsIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = Field(None, min_length=1, max_length=255)
    scope_url: Optional[str] = Field(None, min_length=1, max_length=1000)
    auth_method: Optional[AuthMethod] = None
    personal_access_token: Optional[str] = Field(None, min_length=1)
    tenant_id: Optional[str] = Field(None, min_length=1, max_length=255)
    client_id: Optional[str] = Field(None, min_length=1, max_length=255)
    client_secret: Optional[str] = Field(None, min_length=1)
    secret_scanning_enabled: Optional[bool] = None
    include_unverified_secrets: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=60, le=10080)

    _strip_fields = field_validator(
        "connection_name", "scope_url", "personal_access_token", "tenant_id", "client_id", "client_secret"
    )(_strip)


class AzureDevOpsIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    provider: str
    connection_name: str
    scope_url: str
    scm_organization: str
    scm_project: Optional[str] = None
    auth_method: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    has_access_token: bool = False
    has_client_secret: bool = False
    secret_scanning_enabled: bool
    include_unverified_secrets: bool
    is_active: bool
    continuous_sync_enabled: bool
    sync_interval_minutes: int
    last_tested_at: Optional[datetime] = None
    last_test_ok: Optional[bool] = None
    last_sync_at: Optional[datetime] = None
    last_sync_ok: Optional[bool] = None
    next_sync_at: Optional[datetime] = None
    last_sync_stats: Optional[Dict[str, Any]] = None
    last_scan_id: Optional[int] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AzureDevOpsTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    projects_accessible: int = 0


class AzureDevOpsSyncResult(BaseModel):
    ok: bool
    message: str
    projects_seen: int = 0
    repositories_seen: int = 0
    repositories_created: int = 0
    repositories_updated: int = 0
    forks_skipped: int = 0
    disabled_skipped: int = 0
    scan_id: Optional[int] = None
