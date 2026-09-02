"""Port scanner schemas for request/response validation."""

from typing import Optional, List
from pydantic import BaseModel, Field

from app.services.port_scanner_service import ScannerType


class PortScanRequest(BaseModel):
    """Schema for initiating a port scan."""
    targets: List[str] = Field(..., description="List of targets (IPs, domains, CIDRs like 205.175.240.0/24)")
    organization_id: int = Field(..., description="Organization ID to associate results with")
    scanner: ScannerType = Field(default=ScannerType.NAABU, description="Scanner to use: naabu, masscan, nmap")
    ports: Optional[str] = Field(default=None, description="Port specification (e.g., '80,443' or '1-1000' or '-' for all)")
    
    # Naabu options
    top_ports: int = Field(default=100, ge=1, le=65535, description="Top N ports to scan (naabu)")
    exclude_cdn: bool = Field(default=True, description="Exclude CDN IPs (naabu)")
    
    # Rate limiting and reliability settings
    rate: int = Field(default=500, ge=1, le=100000, description="Packets per second (lower = more reliable)")
    timeout: int = Field(default=30, ge=5, le=300, description="Timeout in seconds per host")
    retries: int = Field(default=2, ge=0, le=5, description="Number of retry attempts on network errors")
    chunk_size: int = Field(default=64, ge=8, le=256, description="Max hosts per scan chunk (for large CIDR ranges)")
    
    # Nmap options
    service_detection: bool = Field(default=True, description="Enable service/version detection -sV (nmap)")
    nmap_scan_type: str = Field(default="-sT", description="Nmap scan technique flag (e.g. -sT, -sS, -sU). Validated against an allowlist.")
    timing: int = Field(default=4, ge=0, le=5, description="Nmap timing template T0-T5 (higher = faster)")
    os_detection: bool = Field(default=False, description="Enable OS detection -O (nmap, requires root)")
    nse_scripts: List[str] = Field(default_factory=list, description="NSE scripts or categories to run (nmap --script)")

    # Import options
    create_assets: bool = Field(default=True, description="Create assets for new hosts")
    import_results: bool = Field(default=True, description="Import results to database")


class HostResult(BaseModel):
    """Schema for a scanned host result."""
    host: str
    ip: str
    is_live: bool = True
    open_ports: List[int] = []
    port_count: int = 0
    asset_id: Optional[int] = None
    asset_created: bool = False


class PortScanResultResponse(BaseModel):
    """Schema for port scan results."""
    success: bool
    scanner: str
    targets_scanned: int
    ports_found: int
    hosts_found: int = 0
    live_hosts: int = 0
    duration_seconds: float
    errors: List[str] = []
    
    # Import summary
    ports_imported: int = 0
    ports_updated: int = 0
    assets_created: int = 0
    
    # Detailed host results
    hosts: List[HostResult] = []


class PortResultItem(BaseModel):
    """Schema for a single port result."""
    host: str
    ip: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    scanner: str


class ImportPortsRequest(BaseModel):
    """Schema for importing port scan results from external tools."""
    organization_id: int
    scanner: ScannerType = Field(..., description="Scanner that produced the output")
    output: str = Field(..., description="Raw scanner output (JSON for naabu/masscan, XML for nmap)")
    create_assets: bool = Field(default=True, description="Create assets for new hosts")


class ImportPortsResponse(BaseModel):
    """Schema for import results."""
    success: bool
    ports_imported: int
    ports_updated: int
    assets_created: int
    errors: List[str] = []


class ScannerStatusResponse(BaseModel):
    """Schema for scanner status."""
    naabu: bool
    masscan: bool
    nmap: bool

















