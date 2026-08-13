"""Pydantic schemas for the HackerOne bug bounty integration."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class HackerOneIntegrationCreate(BaseModel):
    connection_name: str = Field(
        ..., description="Label to identify this connection (e.g. 'Production')."
    )
    api_identifier: str = Field(
        ..., description="HackerOne API Identifier (username)."
    )
    api_token: str = Field(..., description="HackerOne API Token (secret).")
    import_vulnerabilities: bool = True
    import_scopes: bool = True
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)  # 15 min .. 7 days


class HackerOneIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = None
    api_identifier: Optional[str] = None
    api_token: Optional[str] = Field(
        None, description="Provide a new API token, or omit to keep the existing one."
    )
    import_vulnerabilities: Optional[bool] = None
    import_scopes: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)


class HackerOneIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    api_identifier: str
    import_vulnerabilities: bool
    import_scopes: bool
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


class HackerOneTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    program_count: Optional[int] = None


class HackerOneSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    programs_seen: int = 0
    scopes_seen: int = 0
    reports_seen: int = 0
    reports_skipped: int = 0


# ── Report linking (associate existing H1 report ↔ finding) ─────────────────

class AssociateHackerOneReportRequest(BaseModel):
    report_id_or_url: str = Field(
        ...,
        description="HackerOne report ID (e.g. 1234567) or full URL (https://hackerone.com/reports/1234567).",
    )
    integration_id: Optional[int] = Field(
        None,
        description="Optional HackerOne connection id when the org has more than one.",
    )


class HackerOneReportLinkResponse(BaseModel):
    id: int
    vulnerability_id: int
    integration_id: int
    hackerone_report_id: str
    hackerone_report_url: str
    hackerone_program: Optional[str] = None
    hackerone_title: Optional[str] = None
    hackerone_state: Optional[str] = None
    hackerone_severity: Optional[str] = None
    hackerone_reporter: Optional[str] = None
    is_associated: bool
    disconnected_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
