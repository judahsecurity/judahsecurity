"""Pydantic schemas for the VM scanner (Tenable/Qualys/Rapid7/Nessus) integrations."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VmScannerCredentialField(BaseModel):
    key: str
    label: str
    secret: bool = True


class VmScannerProviderInfo(BaseModel):
    """Provider metadata the UI uses to render the right connection form."""

    provider: str
    label: str
    default_base_url: Optional[str] = None
    base_url_required: bool
    base_url_hint: Optional[str] = None
    credential_fields: List[VmScannerCredentialField]
    docs_url: Optional[str] = None


class VmScannerIntegrationCreate(BaseModel):
    provider: str = Field(..., description="One of: tenable, qualys, rapid7, nessus.")
    connection_name: str = Field(
        ..., description="Label to identify this connection (e.g. 'Corporate Qualys')."
    )
    base_url: Optional[str] = Field(
        None, description="API base URL (required for Qualys and Nessus)."
    )
    credentials: Dict[str, str] = Field(
        ..., description="Provider-specific credential fields (see /vm-scanners/providers)."
    )
    verify_ssl: bool = True
    import_vulnerabilities: bool = True
    import_assets: bool = True
    continuous_sync_enabled: bool = False
    sync_interval_minutes: int = Field(360, ge=15, le=10080)  # 15 min .. 7 days


class VmScannerIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = None
    base_url: Optional[str] = None
    credentials: Optional[Dict[str, str]] = Field(
        None, description="Provide new credentials, or omit to keep the existing ones."
    )
    verify_ssl: Optional[bool] = None
    import_vulnerabilities: Optional[bool] = None
    import_assets: Optional[bool] = None
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)


class VmScannerIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    provider: str
    connection_name: str
    base_url: Optional[str]
    verify_ssl: bool
    import_vulnerabilities: bool
    import_assets: bool
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


class VmScannerTestConnectionResponse(BaseModel):
    ok: bool
    message: str


class VmScannerSyncResult(BaseModel):
    ok: bool
    message: str
    assets_created: int = 0
    assets_updated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    hosts_seen: int = 0
    findings_seen: int = 0
