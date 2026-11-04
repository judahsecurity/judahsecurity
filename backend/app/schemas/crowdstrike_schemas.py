"""Pydantic schemas for the CrowdStrike Falcon integration."""

import re
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

CloudRegion = Literal["us-1", "us-2", "eu-1", "us-gov-1"]
FilterMode = Literal["prioritized", "all"]

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _clean_cves(values: Optional[List[str]]) -> Optional[List[str]]:
    if values is None:
        return None
    cleaned = sorted({str(v).strip().upper() for v in values if str(v).strip()})
    bad = [v for v in cleaned if not _CVE_RE.match(v)]
    if bad:
        raise ValueError(f"Invalid CVE id(s): {', '.join(bad[:5])}")
    return cleaned


class CrowdStrikeIntegrationCreate(BaseModel):
    connection_name: str = Field(..., min_length=1, max_length=255)
    cloud_region: CloudRegion = "us-1"
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    import_hosts: bool = True
    import_spotlight: bool = True
    spotlight_filter_mode: FilterMode = "prioritized"
    extra_cve_ids: List[str] = Field(default_factory=list, max_length=2000)
    host_lookback_days: int = Field(7, ge=1, le=90)
    continuous_sync_enabled: bool = True
    sync_interval_minutes: int = Field(1440, ge=15, le=10080)

    _normalize_cves = field_validator("extra_cve_ids")(_clean_cves)


class CrowdStrikeIntegrationUpdate(BaseModel):
    connection_name: Optional[str] = Field(None, min_length=1, max_length=255)
    cloud_region: Optional[CloudRegion] = None
    client_id: Optional[str] = Field(None, min_length=1)
    client_secret: Optional[str] = Field(None, min_length=1)
    import_hosts: Optional[bool] = None
    import_spotlight: Optional[bool] = None
    spotlight_filter_mode: Optional[FilterMode] = None
    extra_cve_ids: Optional[List[str]] = Field(None, max_length=2000)
    host_lookback_days: Optional[int] = Field(None, ge=1, le=90)
    is_active: Optional[bool] = None
    continuous_sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)

    _normalize_cves = field_validator("extra_cve_ids")(_clean_cves)


class CrowdStrikeIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    connection_name: str
    cloud_region: str
    import_hosts: bool
    import_spotlight: bool
    spotlight_filter_mode: str
    extra_cve_ids: Optional[List[str]] = None
    host_lookback_days: int
    is_active: bool
    continuous_sync_enabled: bool
    sync_interval_minutes: int
    last_tested_at: Optional[datetime]
    last_test_ok: Optional[bool]
    last_test_modules: Optional[Dict[str, Any]] = None
    last_sync_at: Optional[datetime]
    last_sync_ok: Optional[bool]
    last_spotlight_sync_at: Optional[datetime] = None
    next_sync_at: Optional[datetime] = None
    last_sync_stats: Optional[Dict[str, Any]] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CrowdStrikeTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    modules: Dict[str, Any] = Field(default_factory=dict)


class CrowdStrikeSyncResult(BaseModel):
    ok: bool
    message: str
    hosts_seen: int = 0
    hosts_skipped: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    findings_seen: int = 0
    findings_filtered: int = 0
    findings_uncorrelated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    vulns_resolved: int = 0
    graph_synced: Optional[int] = None
