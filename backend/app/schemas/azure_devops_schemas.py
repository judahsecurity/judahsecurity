"""Pydantic schemas for the Azure DevOps Boards integration."""

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

AuthMethod = Literal["pat", "entra_id"]
CloseAs = Literal["resolved", "mitigated", "false_positive", "accepted"]
SeverityName = Literal["critical", "high", "medium", "low", "info"]


# ── Connection ───────────────────────────────────────────────────────────────

class AzureDevOpsIntegrationCreate(BaseModel):
    organization_url: str = Field(..., description="https://dev.azure.com/<organization>")
    auth_method: AuthMethod = "pat"
    pat: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    sync_enabled: bool = True
    remote_closed_states: List[str] = ["Closed", "Resolved", "Done"]
    accept_close_as: CloseAs = "resolved"
    close_state: Optional[str] = None
    reopen_state: Optional[str] = None
    notify_severity_change: bool = True


class AzureDevOpsIntegrationUpdate(BaseModel):
    organization_url: Optional[str] = None
    auth_method: Optional[AuthMethod] = None
    pat: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    sync_enabled: Optional[bool] = None
    remote_closed_states: Optional[List[str]] = None
    accept_close_as: Optional[CloseAs] = None
    close_state: Optional[str] = None
    reopen_state: Optional[str] = None
    notify_severity_change: Optional[bool] = None
    is_active: Optional[bool] = None


class AzureDevOpsIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    organization_url: str
    auth_method: str
    has_pat: bool
    tenant_id: Optional[str]
    client_id: Optional[str]
    has_client_secret: bool
    sync_enabled: bool
    remote_closed_states: List[str]
    accept_close_as: str
    close_state: Optional[str]
    reopen_state: Optional[str]
    notify_severity_change: bool
    is_active: bool
    last_tested_at: Optional[datetime]
    last_test_ok: Optional[bool]
    last_pull_at: Optional[datetime]
    last_error: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AzureDevOpsTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    project_count: Optional[int] = None


# ── Metadata ─────────────────────────────────────────────────────────────────

class AzureDevOpsProject(BaseModel):
    id: str
    name: str
    description: Optional[str] = None


class AzureDevOpsProjectsResponse(BaseModel):
    projects: List[AzureDevOpsProject]


class AzureDevOpsWorkItemType(BaseModel):
    name: str
    reference_name: Optional[str] = None
    description: Optional[str] = None


class AzureDevOpsWorkItemTypesResponse(BaseModel):
    work_item_types: List[AzureDevOpsWorkItemType]


# ── Templates ────────────────────────────────────────────────────────────────

class AzureDevOpsTemplateCreate(BaseModel):
    name: str
    project: str
    work_item_type: str = "Bug"
    area_path: Optional[str] = None
    iteration_path: Optional[str] = None
    extra_tags: List[str] = []
    auto_create_enabled: bool = False
    auto_create_min_severity: SeverityName = "high"
    is_active: bool = True


class AzureDevOpsTemplateUpdate(BaseModel):
    name: Optional[str] = None
    project: Optional[str] = None
    work_item_type: Optional[str] = None
    area_path: Optional[str] = None
    iteration_path: Optional[str] = None
    extra_tags: Optional[List[str]] = None
    auto_create_enabled: Optional[bool] = None
    auto_create_min_severity: Optional[SeverityName] = None
    is_active: Optional[bool] = None


class AzureDevOpsTemplateResponse(BaseModel):
    id: int
    integration_id: int
    name: str
    project: str
    work_item_type: str
    area_path: Optional[str]
    iteration_path: Optional[str]
    extra_tags: List[str]
    auto_create_enabled: bool
    auto_create_min_severity: Optional[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Work items ───────────────────────────────────────────────────────────────

class CreateAzureDevOpsWorkItemRequest(BaseModel):
    """Either template_id, or project + work_item_type, must be supplied."""
    template_id: Optional[int] = None
    project: Optional[str] = None
    work_item_type: Optional[str] = None


class AssociateAzureDevOpsWorkItemRequest(BaseModel):
    work_item_id: int = Field(..., description="Existing Azure DevOps work item id, e.g. 1234")


class AzureDevOpsWorkItemResponse(BaseModel):
    id: int
    integration_id: int
    template_id: Optional[int]
    vulnerability_id: int
    work_item_id: int
    work_item_url: str
    project: Optional[str]
    work_item_type: Optional[str]
    state: Optional[str]
    assigned_to: Optional[str]
    last_synced_at: Optional[datetime]
    is_associated: bool
    disconnected_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class AzureDevOpsSyncResult(BaseModel):
    ok: bool
    message: str
    refreshed: int = 0
    closed_in_asm: int = 0
    errors: int = 0
