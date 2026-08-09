"""Pydantic schemas for ServiceNow integration."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class ServiceNowIntegrationCreate(BaseModel):
    webhook_url: str = Field(
        ...,
        description="Full Scripted REST API URL including /notification path",
    )
    username: Optional[str] = Field(
        None, description="ServiceNow service account username for Basic Auth"
    )
    password: Optional[str] = Field(
        None, description="ServiceNow service account password for Basic Auth"
    )
    auto_create_enabled: bool = False
    auto_create_min_severity: Optional[str] = "high"
    sync_enabled: bool = False
    table_name: str = "incident"
    close_state: str = "6"
    reopen_state: str = "2"
    remote_closed_states: List[str] = ["6", "7"]
    validate_on_remote_close: bool = True
    accept_close_as: str = "resolved"

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, v: str) -> str:
        url = (v or "").strip()
        if not url.startswith("https://"):
            raise ValueError("webhook_url must be an https:// URL")
        return url.rstrip("/")

    @field_validator("accept_close_as")
    @classmethod
    def validate_accept_close_as(cls, v: str) -> str:
        allowed = {"resolved", "false_positive", "mitigated", "accepted"}
        if v not in allowed:
            raise ValueError(f"accept_close_as must be one of {sorted(allowed)}")
        return v


class ServiceNowIntegrationUpdate(BaseModel):
    webhook_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    auto_create_enabled: Optional[bool] = None
    auto_create_min_severity: Optional[str] = None
    sync_enabled: Optional[bool] = None
    table_name: Optional[str] = None
    close_state: Optional[str] = None
    reopen_state: Optional[str] = None
    remote_closed_states: Optional[List[str]] = None
    validate_on_remote_close: Optional[bool] = None
    accept_close_as: Optional[str] = None

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        url = v.strip()
        if not url.startswith("https://"):
            raise ValueError("webhook_url must be an https:// URL")
        return url.rstrip("/")

    @field_validator("accept_close_as")
    @classmethod
    def validate_accept_close_as(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"resolved", "false_positive", "mitigated", "accepted"}
        if v not in allowed:
            raise ValueError(f"accept_close_as must be one of {sorted(allowed)}")
        return v


class ServiceNowIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    webhook_url: str
    username: Optional[str]
    has_password: bool = False
    auto_create_enabled: bool
    auto_create_min_severity: Optional[str]
    sync_enabled: bool = False
    table_name: str = "incident"
    close_state: str = "6"
    reopen_state: str = "2"
    remote_closed_states: List[str] = ["6", "7"]
    validate_on_remote_close: bool = True
    accept_close_as: str = "resolved"
    is_active: bool
    last_tested_at: Optional[datetime]
    last_test_ok: Optional[bool]
    last_delivery_at: Optional[datetime]
    last_pull_at: Optional[datetime] = None
    last_error: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ServiceNowTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    http_status: Optional[int] = None
    table_api_ok: Optional[bool] = None


class CreateServiceNowDeliveryRequest(BaseModel):
    include_description: bool = True
    include_evidence: bool = True
    include_remediation: bool = True
    include_references: bool = True
    include_enrichment: bool = True


class AssociateServiceNowDeliveryRequest(BaseModel):
    sys_id: Optional[str] = None
    number: Optional[str] = Field(None, description="Incident number, e.g. INC0012345")


class ServiceNowDeliveryResponse(BaseModel):
    id: int
    vulnerability_id: int
    snow_sys_id: Optional[str]
    snow_number: Optional[str]
    snow_url: Optional[str]
    snow_state: Optional[str] = None
    snow_state_label: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    pending_close_validation: bool = False
    pending_close_validation_id: Optional[int] = None
    last_close_validation_verdict: Optional[str] = None
    http_status: Optional[int]
    disconnected_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class ServiceNowSyncResult(BaseModel):
    ok: bool
    message: str
    state_updated: bool = False
    work_note_added: bool = False
    validation_queued: bool = False
    asm_status_updated: bool = False
    snow_state: Optional[str] = None
    snow_state_label: Optional[str] = None
