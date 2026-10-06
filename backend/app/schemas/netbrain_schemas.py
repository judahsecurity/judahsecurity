"""API schemas for the NetBrain exploit-prerequisite integration."""

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


def _normalize_url(value: str) -> str:
    value = (value or "").strip().rstrip("/")
    if not value:
        raise ValueError("NetBrain URL is required.")
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


class NetBrainIntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    base_url: str
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    authentication_id: str | None = None
    tenant_id: str = Field(min_length=1, max_length=128)
    domain_id: str = Field(min_length=1, max_length=128)
    verify_ssl: bool = True
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)
    max_config_age_hours: int = Field(24, ge=1, le=720)
    auto_mitigate_enabled: bool = False

    @field_validator("base_url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return _normalize_url(value)

    @field_validator("name", "username", "password", "tenant_id", "domain_id")
    @classmethod
    def strip_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value is required.")
        return value

    @field_validator("authentication_id")
    @classmethod
    def empty_auth_as_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class NetBrainIntegrationUpdate(BaseModel):
    name: str | None = None
    base_url: str | None = None
    username: str | None = None
    password: str | None = None
    authentication_id: str | None = None
    tenant_id: str | None = None
    domain_id: str | None = None
    verify_ssl: bool | None = None
    is_active: bool | None = None
    continuous_sync_enabled: bool | None = None
    sync_interval_minutes: int | None = Field(None, ge=15, le=10080)
    max_config_age_hours: int | None = Field(None, ge=1, le=720)
    auto_mitigate_enabled: bool | None = None

    @field_validator("base_url")
    @classmethod
    def normalize_url(cls, value: str | None) -> str | None:
        return _normalize_url(value) if value is not None else None

    @field_validator("name", "tenant_id", "domain_id")
    @classmethod
    def strip_required_update(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be empty.")
        return value

    @field_validator("username")
    @classmethod
    def empty_username_as_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("password")
    @classmethod
    def empty_password_as_none(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("authentication_id")
    @classmethod
    def empty_auth_as_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class NetBrainIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    base_url: str
    authentication_id: str | None = None
    tenant_id: str
    domain_id: str
    verify_ssl: bool
    is_active: bool
    continuous_sync_enabled: bool
    sync_interval_minutes: int
    max_config_age_hours: int
    auto_mitigate_enabled: bool
    last_tested_at: datetime | None = None
    last_test_ok: bool | None = None
    last_sync_at: datetime | None = None
    last_sync_ok: bool | None = None
    next_sync_at: datetime | None = None
    last_sync_stats: dict[str, Any] | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime

    @field_validator("last_sync_stats", mode="before")
    @classmethod
    def decode_stats(cls, value):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                return None
        return value

    model_config = {"from_attributes": True}


class NetBrainTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    device_count: int | None = None


class NetBrainAssessmentResult(BaseModel):
    ok: bool
    message: str
    findings_seen: int = 0
    findings_assessed: int = 0
    findings_mitigated: int = 0
    findings_reopened: int = 0
    prerequisites_present: int = 0
    prerequisites_absent: int = 0
    unknown: int = 0
