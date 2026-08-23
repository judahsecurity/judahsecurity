"""Asset schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field

from app.models.asset import AssetType, AssetStatus


class AssetBase(BaseModel):
    """Base asset schema."""
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetType
    value: str = Field(..., min_length=1, max_length=500)


class AssetCreate(AssetBase):
    """Schema for creating a new asset."""
    organization_id: int
    parent_id: Optional[int] = None
    description: Optional[str] = None
    tags: List[str] = []
    metadata_: dict[str, Any] = Field(default={})
    discovery_source: Optional[str] = None
    criticality: str = "medium"
    is_monitored: bool = True


class AssetUpdate(BaseModel):
    """Schema for updating an asset."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    asset_type: Optional[AssetType] = None
    value: Optional[str] = Field(None, min_length=1, max_length=500)
    status: Optional[AssetStatus] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata_: Optional[dict[str, Any]] = Field(default=None)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    criticality: Optional[str] = None
    is_monitored: Optional[bool] = None
    in_scope: Optional[bool] = None
    is_owned: Optional[bool] = None
    acs_score: Optional[int] = Field(None, ge=0, le=10, description="Asset Criticality Score (0-10)")


class TechnologySummary(BaseModel):
    """Summary of a technology associated with an asset."""
    name: str
    slug: str
    categories: List[str] = []
    version: Optional[str] = None


class PortServiceSummary(BaseModel):
    """Summary of a port service for asset response."""
    id: int
    port: int
    protocol: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    state: str
    is_ssl: bool = False
    is_risky: bool = False
    port_string: str  # e.g., "443-tcp-https"


class AssetResponse(AssetBase):
    """Schema for asset response."""
    id: int
    organization_id: int
    organization_name: Optional[str] = None  # Populated from relationship
    parent_id: Optional[int] = None
    status: AssetStatus
    description: Optional[str] = None
    tags: List[str] = []
    metadata_: dict[str, Any] = Field(default={})
    discovery_source: Optional[str] = None
    discovery_chain: List[dict] = []
    association_reason: Optional[str] = None
    association_confidence: int = 100
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    criticality: str
    is_monitored: bool
    
    # ACS/ARS scoring
    acs_score: int = 5  # Asset Criticality Score (0-10)
    acs_drivers: dict = {}  # Key drivers for ACS
    ars_score: int = 0  # Asset Risk Score (0-100)
    
    # Asset Classification
    system_type: Optional[str] = None  # firewall, server, workstation, etc.
    operating_system: Optional[str] = None  # Detected OS
    device_class: Optional[str] = None  # Network Infrastructure, Server, etc.
    device_subclass: Optional[str] = None  # Firewall and NGFW, Web Server, etc.
    is_public: bool = True
    is_licensed: bool = True
    
    # HTTP info
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    live_url: Optional[str] = None
    root_domain: Optional[str] = None
    
    # DNS info
    dns_records: dict = {}
    
    # Geo-location info
    ip_address: Optional[str] = None
    ip_addresses: List[str] = []  # All resolved IPs (multi-value for load balancers, CDNs)
    ip_history: List[dict] = []  # Historical IP tracking
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    isp: Optional[str] = None
    
    # Scope and ownership
    in_scope: bool = True
    is_owned: bool = False
    is_live: bool = False
    netblock_id: Optional[int] = None
    asn: Optional[str] = None
    
    # Hosting classification (for IP assets - distinguishes owned vs cloud infrastructure)
    hosting_type: Optional[str] = None  # owned, cloud, cdn, third_party, unknown
    hosting_provider: Optional[str] = None  # azure, aws, gcp, cloudflare, akamai, etc.
    is_ephemeral_ip: bool = True  # True if IP could change (cloud/CDN = ephemeral)
    resolved_from: Optional[str] = None  # Domain this IP was resolved from via DNS
    
    # Scan tracking
    last_scan_id: Optional[str] = None
    last_scan_name: Optional[str] = None
    last_scan_date: Optional[datetime] = None
    last_scan_target: Optional[str] = None
    last_authenticated_scan_status: Optional[str] = None
    
    # Discovered endpoints and parameters
    endpoints: List[str] = []
    parameters: List[str] = []
    js_files: List[str] = []
    rest_endpoints: List[dict] = []
    api_specs: List[dict] = []
    
    # Technologies
    technologies: List[TechnologySummary] = []
    
    # Port services
    port_services: List[PortServiceSummary] = []
    open_ports_count: int = 0
    risky_ports_count: int = 0
    
    # Vulnerability counts
    vulnerability_count: int = 0
    critical_vuln_count: int = 0
    high_vuln_count: int = 0
    medium_vuln_count: int = 0
    low_vuln_count: int = 0
    
    # Screenshot
    screenshot_id: Optional[int] = None  # Latest successful screenshot ID
    
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class AssetWithPortsResponse(AssetResponse):
    """Asset response with detailed port information."""
    
    # Detailed port breakdown
    ports_by_protocol: dict = {}  # {"tcp": [...], "udp": [...]}
    ports_by_service: dict = {}   # {"https": [...], "ssh": [...]}


class AssetTreeResponse(BaseModel):
    """Hierarchical view of assets for a domain."""
    domain: str
    total_assets: int
    total_ports: int
    total_risky_ports: int
    asset_tree: dict


class AssetPortsSummary(BaseModel):
    """Summary of ports for an asset."""
    asset_id: int
    asset_value: str
    total_ports: int
    open_ports: int
    filtered_ports: int
    risky_ports: int
    tcp_ports: int
    udp_ports: int
    services: List[str]
    ports: List[PortServiceSummary]


class PaginatedAssetsResponse(BaseModel):
    """Paginated response for assets list."""
    items: List[AssetResponse]
    total: int
    skip: int
    limit: int
    has_more: bool
