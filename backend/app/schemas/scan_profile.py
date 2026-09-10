"""Scan profile schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

from app.models.scan_profile import ProfileType


class ScanProfileBase(BaseModel):
    """Base scan profile schema."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    profile_type: ProfileType = ProfileType.CUSTOM


class ScanProfileCreate(ScanProfileBase):
    """Schema for creating a new scan profile."""
    organization_id: Optional[int] = None
    # Nuclei settings
    nuclei_severity: List[str] = Field(default_factory=lambda: ["critical", "high"])
    nuclei_tags: List[str] = Field(default_factory=list)
    nuclei_exclude_tags: List[str] = Field(default_factory=list)
    nuclei_templates: List[str] = Field(default_factory=list)
    nuclei_rate_limit: int = Field(default=150, ge=1, le=1000)
    nuclei_bulk_size: int = Field(default=25, ge=1, le=100)
    nuclei_concurrency: int = Field(default=25, ge=1, le=100)
    nuclei_timeout: int = Field(default=10, ge=1, le=60)
    
    # Discovery settings
    enable_subdomain_enum: bool = True
    enable_port_scan: bool = True
    enable_http_probe: bool = True
    enable_technology_detection: bool = True
    enable_vulnerability_scan: bool = True
    
    # Port scanning settings
    port_scan_top: int = Field(default=1000, ge=1, le=65535)
    port_scan_custom: List[int] = Field(default_factory=list)
    
    # Rate limiting
    max_concurrent_hosts: int = Field(default=50, ge=1, le=200)
    requests_per_second: int = Field(default=100, ge=1, le=1000)
    is_default: bool = False


class ScanProfileUpdate(BaseModel):
    """Schema for updating a scan profile."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    profile_type: Optional[ProfileType] = None
    
    nuclei_severity: Optional[List[str]] = None
    nuclei_tags: Optional[List[str]] = None
    nuclei_exclude_tags: Optional[List[str]] = None
    nuclei_templates: Optional[List[str]] = None
    nuclei_rate_limit: Optional[int] = Field(None, ge=1, le=1000)
    nuclei_bulk_size: Optional[int] = Field(None, ge=1, le=100)
    nuclei_concurrency: Optional[int] = Field(None, ge=1, le=100)
    nuclei_timeout: Optional[int] = Field(None, ge=1, le=60)
    
    enable_subdomain_enum: Optional[bool] = None
    enable_port_scan: Optional[bool] = None
    enable_http_probe: Optional[bool] = None
    enable_technology_detection: Optional[bool] = None
    enable_vulnerability_scan: Optional[bool] = None
    
    port_scan_top: Optional[int] = Field(None, ge=1, le=65535)
    port_scan_custom: Optional[List[int]] = None
    
    max_concurrent_hosts: Optional[int] = Field(None, ge=1, le=200)
    requests_per_second: Optional[int] = Field(None, ge=1, le=1000)
    
    is_default: Optional[bool] = None
    is_active: Optional[bool] = None


class ScanProfileResponse(ScanProfileBase):
    """Schema for scan profile response."""
    id: int
    organization_id: Optional[int] = None
    created_by: Optional[str] = None
    
    nuclei_severity: List[str]
    nuclei_tags: List[str]
    nuclei_exclude_tags: List[str]
    nuclei_templates: List[str]
    nuclei_rate_limit: int
    nuclei_bulk_size: int
    nuclei_concurrency: int
    nuclei_timeout: int
    
    enable_subdomain_enum: bool
    enable_port_scan: bool
    enable_http_probe: bool
    enable_technology_detection: bool
    enable_vulnerability_scan: bool
    
    port_scan_top: int
    port_scan_custom: List[int]
    
    max_concurrent_hosts: int
    requests_per_second: int
    
    is_default: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class NucleiScanRequest(BaseModel):
    """Schema for initiating a Nuclei scan."""
    targets: List[str] = Field(..., description="List of targets (URLs, domains, IPs)")
    organization_id: int
    profile_id: Optional[int] = Field(default=None, description="Scan profile ID (uses default if not specified)")
    
    # Override profile settings
    severity: Optional[List[str]] = Field(default=None, description="Override severity filter")
    tags: Optional[List[str]] = Field(default=None, description="Override template tags")
    exclude_tags: Optional[List[str]] = Field(default=None, description="Override exclude tags")
    
    # Asset association
    asset_ids: Optional[List[int]] = Field(default=None, description="Asset IDs to associate findings with")
    create_labels: bool = Field(default=True, description="Create labels on assets from findings")


class NucleiScanResultResponse(BaseModel):
    """Schema for Nuclei scan results."""
    success: bool
    scan_id: int
    targets_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    cves_found: List[str]
    duration_seconds: float
    errors: List[str] = []


class NucleiFindingResponse(BaseModel):
    """Schema for a single Nuclei finding."""
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_at: str
    description: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = []
    reference: List[str] = []


class ToolStatusResponse(BaseModel):
    """Schema for tool installation status."""
    nuclei: bool
    subfinder: bool
    httpx: bool
    dnsx: bool
    naabu: bool
    katana: bool
















