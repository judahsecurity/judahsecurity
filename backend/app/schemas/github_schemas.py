"""Pydantic schemas for the GitHub source-code-manager integration."""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class GitHubConnectionOptions(BaseModel):
    import_member_repos: bool = True
    scan_secrets: bool = True
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=60, le=10080)


class GitHubPatIntegrationCreate(GitHubConnectionOptions):
    token: str = Field(..., min_length=1, max_length=500)
    organization_url: str = Field(..., min_length=1, max_length=500)
    allow_fix_pull_requests: bool = False

    @field_validator("token")
    @classmethod
    def strip_token(cls, value: str) -> str:
        return value.strip()


class GitHubIntegrationUpdate(BaseModel):
    token: Optional[str] = Field(None, min_length=1, max_length=500)
    import_member_repos: Optional[bool] = None
    scan_secrets: Optional[bool] = None
    allow_fix_pull_requests: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=60, le=10080)


class GitHubIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    auth_method: str
    account_login: str
    account_type: str
    account_url: str
    installation_id: Optional[int] = None
    repository_selection: Optional[str] = None
    installed_by_github_login: Optional[str] = None
    import_member_repos: bool
    scan_secrets: bool
    allow_fix_pull_requests: bool
    can_open_pull_requests: bool
    is_active: bool
    continuous_sync_enabled: bool
    sync_interval_minutes: int
    last_tested_at: Optional[datetime] = None
    last_test_ok: Optional[bool] = None
    last_sync_at: Optional[datetime] = None
    last_sync_ok: Optional[bool] = None
    next_sync_at: Optional[datetime] = None
    last_sync_stats: Optional[Dict[str, Any]] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class GitHubAppStatus(BaseModel):
    """Whether the platform's GitHub App is configured, plus pending installs."""

    app_configured: bool
    app_slug: Optional[str] = None
    app_install_url: Optional[str] = None
    pending_requests: List[Dict[str, Any]] = []


class GitHubAppInstallStart(GitHubConnectionOptions):
    pass


class GitHubAppInstallStartResponse(BaseModel):
    install_url: str
    expires_at: datetime


class GitHubAppCallbackRequest(BaseModel):
    state: str = Field(..., min_length=16, max_length=200)
    installation_id: Optional[int] = None
    setup_action: Optional[str] = Field(None, max_length=32)
    code: Optional[str] = Field(None, max_length=200)


class GitHubAppCallbackResponse(BaseModel):
    status: Literal["connected", "requested", "authorize"]
    message: str
    integration_id: Optional[int] = None
    # Set when the user must authorize the App so ownership can be verified.
    authorize_url: Optional[str] = None


class GitHubTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    account_type: Optional[str] = None
    repos_accessible: bool = False
    members_accessible: bool = False
    can_write: Optional[bool] = None


class GitHubSyncResult(BaseModel):
    ok: bool
    message: str
    repos_seen: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    member_repos_seen: int = 0
    members_skipped: bool = False
    repos_scanned: int = 0
    repos_scan_skipped: int = 0
    secrets_created: int = 0
    secrets_updated: int = 0
    secrets_resolved: int = 0


class GitHubFileChange(BaseModel):
    path: str = Field(..., min_length=1, max_length=1000)
    # Full new file contents. ``None`` deletes the file.
    content: Optional[str] = None


class GitHubPullRequestCreate(BaseModel):
    vulnerability_id: int
    repository: Optional[str] = Field(
        None, max_length=300, description="owner/name; defaults to the finding's repository"
    )
    title: str = Field(..., min_length=1, max_length=256)
    body: Optional[str] = Field(None, max_length=60000)
    base_branch: Optional[str] = Field(None, max_length=255)
    commit_message: Optional[str] = Field(None, max_length=1000)
    changes: List[GitHubFileChange] = Field(..., min_length=1, max_length=50)


class GitHubPullRequestResponse(BaseModel):
    number: int
    html_url: str
    branch: str
    repository: str
