"""Scan schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field

from app.models.scan import ScanType, ScanStatus


class ScanBase(BaseModel):
    """Base scan schema."""
    name: str = Field(..., min_length=1, max_length=255)
    scan_type: ScanType


class ScanCreate(ScanBase):
    """Schema for creating a new scan."""
    organization_id: int
    targets: List[str] = []
    label_ids: List[int] = []  # Optional: scan assets with these labels
    match_all_labels: bool = False  # If true, assets must have ALL specified labels
    config: dict[str, Any] = {}
    profile_id: Optional[int] = None


class ScanByLabelRequest(BaseModel):
    """Schema for starting a scan by label."""
    name: str = Field(..., min_length=1, max_length=255)
    scan_type: ScanType
    organization_id: int
    label_ids: List[int]
    match_all_labels: bool = False
    config: dict[str, Any] = {}


class BulkDomainScanRequest(BaseModel):
    """Schema for bulk domain port scan."""
    organization_id: int
    domains: List[str] = Field(default=[], description="List of domains to scan")
    domains_text: Optional[str] = Field(default=None, description="Raw text with one domain per line (alternative to domains list)")
    name: Optional[str] = Field(default=None, description="Scan name (auto-generated if not provided)")
    ports: Optional[str] = Field(default=None, description="Ports to scan (e.g., '80,443,8080' or '1-1000')")
    top_ports: int = Field(default=100, ge=1, le=1000, description="Scan top N ports if ports not specified")
    resolve_first: bool = Field(default=False, description="Pre-resolve domains to IPs before scanning")
    create_assets: bool = Field(default=True, description="Create domain assets if they don't exist")
    scanner: str = Field(default="naabu", description="Scanner to use: naabu, nmap, or masscan")
    rate: int = Field(default=500, ge=10, le=10000, description="Scan rate (packets per second)")
    service_detection: bool = Field(default=True, description="Enable service detection (nmap only)")


class BulkDomainScanResponse(BaseModel):
    """Response for bulk domain scan."""
    scan_id: int
    scan_name: str
    domains_count: int
    resolved_ips: Optional[List[str]] = None
    assets_created: int = 0
    message: str


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[ScanStatus] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    error_message: Optional[str] = None
    results: Optional[dict[str, Any]] = None


class ScanResponse(ScanBase):
    """Schema for scan response."""
    id: int
    organization_id: int
    organization_name: Optional[str] = None
    targets: List[str] = []
    config: dict[str, Any] = {}
    status: ScanStatus
    progress: Optional[int] = 0
    assets_discovered: Optional[int] = 0
    technologies_found: Optional[int] = 0
    vulnerabilities_found: Optional[int] = 0
    targets_count: Optional[int] = 0
    findings_count: Optional[int] = 0
    started_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    results: Optional[dict[str, Any]] = {}
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class AdhocScanRequest(BaseModel):
    """Schema for creating an adhoc scan with any scan type (including scheduled scan types)."""
    name: str = Field(..., min_length=1, max_length=255, description="Name for the scan")
    scan_type: str = Field(..., description="Scan type (any from CONTINUOUS_SCAN_TYPES)")
    organization_id: int = Field(..., description="Organization ID")
    targets: List[str] = Field(default=[], description="Explicit list of targets (optional)")
    label_ids: List[int] = Field(default=[], description="Target assets with these labels")
    match_all_labels: bool = Field(default=False, description="Require assets to have ALL labels")
    use_all_in_scope: bool = Field(default=False, description="If no targets/labels, use all in-scope assets")
    include_netblocks: bool = Field(default=True, description="Include in-scope netblocks as targets")
    config: dict[str, Any] = Field(default={}, description="Override default scan config")
    profile_id: Optional[int] = Field(default=None, description="Reusable scan profile ID")












