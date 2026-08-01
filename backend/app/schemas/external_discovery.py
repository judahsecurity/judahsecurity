"""Pydantic schemas for external discovery and API configuration."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# =============================================================================
# API Configuration Schemas
# =============================================================================

class APIConfigCreate(BaseModel):
    """Schema for creating or updating an API configuration."""
    service_name: str = Field(..., description="Service name (e.g., virustotal, otx, whoisxml)")
    api_key: Optional[str] = Field(default=None, description="API key for the service (optional for config-only updates)")
    api_user: Optional[str] = Field(default=None, description="Username if required")
    api_secret: Optional[str] = Field(default=None, description="API secret if separate from key")
    config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Service-specific configuration",
        examples=[{
            "organization_names": ["Company Inc"],
            "registration_emails": ["admin@company.com"]
        }]
    )


class APIConfigUpdate(BaseModel):
    """Schema for updating an API configuration."""
    api_key: Optional[str] = None
    api_user: Optional[str] = None
    api_secret: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class APIConfigResponse(BaseModel):
    """Response schema for API configuration (key masked)."""
    id: int
    organization_id: int
    service_name: str
    api_user: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_active: bool
    is_valid: bool
    last_used: Optional[datetime] = None
    usage_count: int
    daily_usage: int
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    # Key is masked for security
    api_key_masked: Optional[str] = None
    
    class Config:
        from_attributes = True


class APIConfigListResponse(BaseModel):
    """List of API configurations."""
    configs: List[APIConfigResponse]
    available_services: List[str]


# =============================================================================
# External Discovery Request Schemas
# =============================================================================

class ExternalDiscoveryRequest(BaseModel):
    """Request schema for running external discovery."""
    domain: str = Field(..., description="Primary domain to discover (e.g., rockwellautomation.com)")
    organization_id: int = Field(..., description="Organization ID")
    
    # Options for what sources to use
    include_free_sources: bool = Field(default=True, description="Include free sources (crt.sh, crt.name, shodan CTL, wayback, rapiddns, m365)")
    include_paid_sources: bool = Field(default=True, description="Include paid API sources")
    
    # Specific sources to enable/disable
    sources: Optional[List[str]] = Field(
        default=None,
        description="Specific sources to use (if None, uses all available)",
        examples=[["crtsh", "virustotal", "otx", "wayback", "rapiddns", "m365"]]
    )
    
    # Additional configuration
    organization_names: Optional[List[str]] = Field(
        default=None,
        description="Organization names for WHOIS lookups"
    )
    registration_emails: Optional[List[str]] = Field(
        default=None,
        description="Registration emails for reverse WHOIS"
    )
    
    # Common Crawl comprehensive search options
    commoncrawl_org_name: Optional[str] = Field(
        default=None,
        description="Organization name for Common Crawl search (e.g., 'rockwellautomation' to find rockwellautomation.*)"
    )
    commoncrawl_keywords: Optional[List[str]] = Field(
        default=None,
        description="Additional keywords to search in Common Crawl (e.g., ['rockwell'] to find *rockwell* domains)",
        examples=[["rockwell", "factory", "automation"]]
    )
    
    # SNI IP Ranges - Cloud Asset Discovery
    include_sni_discovery: bool = Field(
        default=True,
        description="Include SNI IP ranges discovery (discovers cloud-hosted assets on AWS, GCP, Azure, etc.)"
    )
    sni_keywords: Optional[List[str]] = Field(
        default=None,
        description="Additional keywords for SNI search (e.g., ['rockwell', 'ra-', 'allen-bradley'])",
        examples=[["rockwell", "factory", "allen-bradley"]]
    )
    
    # Options
    create_assets: bool = Field(default=True, description="Automatically create discovered assets")
    skip_existing: bool = Field(default=True, description="Skip assets that already exist")
    
    # Automated subdomain enumeration on discovered domains
    enumerate_discovered_domains: bool = Field(
        default=True,
        description="Run subdomain enumeration (crt.sh, brute-force) on all discovered domains from Whoxy and other sources"
    )
    max_domains_to_enumerate: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum number of discovered domains to run subdomain enumeration on"
    )

    # Automated technology fingerprinting on discovered hosts
    run_technology_scan: bool = Field(
        default=True,
        description="Run Wappalyzer tech scan on all discovered domains/subdomains to identify technologies and add tags",
    )
    max_technology_scan: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Maximum number of hosts to scan for technologies (runs in background batches)",
    )
    
    # Automated screenshots on discovered hosts
    run_screenshots: bool = Field(
        default=True,
        description="Capture screenshots of all discovered domains/subdomains using EyeWitness",
    )
    max_screenshots: int = Field(
        default=200,
        ge=1,
        le=1000,
        description="Maximum number of hosts to screenshot (runs in background)",
    )
    screenshot_timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Timeout in seconds for each screenshot",
    )

    # HTTP probing - check if sites are live and get status codes
    run_http_probe: bool = Field(
        default=True,
        description="Probe discovered hosts for HTTP response (sets is_live, http_status, http_title)",
    )
    max_http_probe: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Maximum number of hosts to probe for HTTP (runs in background)",
    )
    
    # DNS resolution - get IP addresses for discovered hosts
    run_dns_resolution: bool = Field(
        default=True,
        description="Resolve DNS for discovered hosts (sets ip_address field)",
    )
    max_dns_resolution: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Maximum number of hosts to resolve DNS for (runs in background)",
    )
    
    # Geolocation enrichment - get country, city, lat/lon for IPs
    run_geo_enrichment: bool = Field(
        default=True,
        description="Enrich assets with geolocation (country, city, lat/lon) based on resolved IPs",
    )
    max_geo_enrichment: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Maximum number of assets to enrich with geolocation (runs in background)",
    )


class SourceResult(BaseModel):
    """Result from a single discovery source."""
    source: str
    success: bool
    domains_found: int = 0
    subdomains_found: int = 0
    ips_found: int = 0
    cidrs_found: int = 0
    elapsed_time: float = 0.0
    error: Optional[str] = None


class ExternalDiscoveryResponse(BaseModel):
    """Response schema for external discovery."""
    domain: str
    organization_id: int
    
    # Summary
    total_domains: int
    total_subdomains: int
    total_ips: int
    total_cidrs: int
    
    # Results by source
    source_results: List[SourceResult]
    
    # Aggregated unique findings
    domains: List[str]
    subdomains: List[str]
    ip_addresses: List[str]
    ip_ranges: List[str]
    
    # Asset creation stats
    assets_created: int = 0
    assets_skipped: int = 0
    
    # Timing
    total_elapsed_time: float


class SingleSourceRequest(BaseModel):
    """Request to run a single discovery source."""
    domain: str
    organization_id: int
    source: str = Field(..., description="Source to use (e.g., virustotal, wayback, crtsh)")
    create_assets: bool = Field(default=True, description="Automatically create discovered assets")
    enumerate_discovered_domains: bool = Field(
        default=True,
        description="Run subdomain enumeration on any related domains this source discovers",
    )
    max_domains_to_enumerate: int = Field(
        default=50,
        description="Cap on how many discovered domains to chain-enumerate",
    )


class SingleSourceResponse(BaseModel):
    """Response from a single discovery source."""
    source: str
    domain: str
    success: bool
    domains: List[str] = []
    subdomains: List[str] = []
    ip_addresses: List[str] = []
    ip_ranges: List[str] = []
    error: Optional[str] = None
    elapsed_time: float = 0.0
    assets_created: int = 0


class ReverseDiscoveryRequest(BaseModel):
    """Run reverse-NS/MX discovery on an explicitly-selected set of pivots.

    Intended to be driven by the reverse-pivot preview: the user reviews the
    credit-free plan, unchecks noisy hosts, and runs on exactly what remains.
    """
    organization_id: int = Field(..., description="Organization ID")
    domain: Optional[str] = Field(
        default=None,
        description="Optional primary domain (used only for attribution/context)",
    )
    nameservers: List[str] = Field(
        default_factory=list,
        description="Nameserver hosts to reverse-pivot on (from the preview plan)",
    )
    mailservers: List[str] = Field(
        default_factory=list,
        description="Mailserver hosts to reverse-pivot on (from the preview plan)",
    )
    create_assets: bool = Field(default=True, description="Create discovered domains as assets")
    enumerate_discovered_domains: bool = Field(
        default=True,
        description="Immediately run subdomain enumeration on each domain found via the pivots",
    )
    max_domains_to_enumerate: int = Field(
        default=50,
        description="Cap on how many discovered domains to chain-enumerate",
    )


class ReverseDiscoveryResponse(BaseModel):
    """Result of a selected-pivot reverse discovery run."""
    organization_id: int
    success: bool
    domains: List[str] = []
    domains_by_nameserver: Dict[str, List[str]] = {}
    domains_by_mailserver: Dict[str, List[str]] = {}
    pivoted_nameservers: List[str] = []
    pivoted_mailservers: List[str] = []
    providers: List[str] = []
    total_domains_found: int = 0
    assets_created: int = 0
    # Chained subdomain enumeration on the discovered domains
    subdomains_enumerated: int = 0
    subdomain_assets_created: int = 0
    error: Optional[str] = None
    elapsed_time: float = 0.0


# =============================================================================
# Available Services
# =============================================================================

class AvailableServicesResponse(BaseModel):
    """List of available external discovery services."""
    paid_services: List[Dict[str, Any]]
    free_services: List[Dict[str, Any]]
    configured_services: List[str]


# Service information
PAID_SERVICES_INFO = [
    {
        "name": "virustotal",
        "display_name": "VirusTotal",
        "description": "Subdomain enumeration from VT database",
        "requires_key": True,
        "rate_limit": "4/second, varies by plan",
        "website": "https://www.virustotal.com/",
    },
    {
        "name": "otx",
        "display_name": "AlienVault OTX",
        "description": "Passive DNS and URL data from OTX",
        "requires_key": True,
        "rate_limit": "10,000/hour",
        "website": "https://otx.alienvault.com/",
    },
    {
        "name": "whoisxml",
        "display_name": "WhoisXML API",
        "description": "IP netblocks by org name, plus reverse-NS/MX/WHOIS domain discovery",
        "requires_key": True,
        "rate_limit": "Varies by plan",
        "website": "https://whoisxmlapi.com/",
        "config_options": [
            "organization_names",
            "owned_nameservers",
            "owned_mailservers",
        ],
    },
    {
        "name": "whoxy",
        "display_name": "Whoxy",
        "description": "Reverse WHOIS by registration email",
        "requires_key": True,
        "rate_limit": "Varies by plan",
        "website": "https://www.whoxy.com/",
        "config_options": ["registration_emails"],
    },
    {
        "name": "shodan",
        "display_name": "Shodan",
        "description": "Internet-wide scanning data",
        "requires_key": True,
        "rate_limit": "1/second",
        "website": "https://www.shodan.io/",
    },
    {
        "name": "censys",
        "display_name": "Censys",
        "description": "Internet scanning and certificate data",
        "requires_key": True,
        "rate_limit": "0.4/second, 250/day (free)",
        "website": "https://censys.io/",
    },
    {
        "name": "securitytrails",
        "display_name": "SecurityTrails",
        "description": "Reverse lookups (NS/MX/WHOIS), associated domains, and historical WHOIS",
        "requires_key": True,
        "rate_limit": "50/month (free), varies by plan",
        "website": "https://securitytrails.com/",
        "config_options": [
            "registration_emails",
            "registrar_names",
            "owned_nameservers",
            "owned_mailservers",
        ],
    },
]

FREE_SERVICES_INFO = [
    {
        "name": "crtsh",
        "display_name": "crt.sh",
        "description": "Certificate transparency log search",
        "requires_key": False,
        "rate_limit": "Be respectful",
        "website": "https://crt.sh/",
    },
    {
        "name": "shodan_ctl",
        "display_name": "Shodan CTL",
        "description": "Shodan Certificate Transparency Logs hostname mirror",
        "requires_key": False,
        "rate_limit": "1/second recommended",
        "website": "https://ctl.shodan.io/",
    },
    {
        "name": "crt_name",
        "display_name": "crt.name",
        "description": "Aggregated CT/DNS subdomain index (live CT, backfill, Chaos, CZDS, probes) with first-seen dates",
        "requires_key": False,
        "rate_limit": "1000 requests/IP/day",
        "website": "https://crt.name/",
    },
    {
        "name": "wayback",
        "display_name": "Wayback Machine",
        "description": "Historical web crawl data",
        "requires_key": False,
        "rate_limit": "1/second recommended",
        "website": "https://web.archive.org/",
    },
    {
        "name": "rapiddns",
        "display_name": "RapidDNS",
        "description": "DNS database subdomain lookup",
        "requires_key": False,
        "rate_limit": "Unknown",
        "website": "https://rapiddns.io/",
    },
    {
        "name": "m365",
        "display_name": "Microsoft 365",
        "description": "Federated domain discovery via autodiscover",
        "requires_key": False,
        "rate_limit": "1/second recommended",
        "website": "https://www.microsoft.com/",
    },
    {
        "name": "commoncrawl",
        "display_name": "Common Crawl",
        "description": "Web archive with billions of crawled URLs - finds subdomains from historical crawl data",
        "requires_key": False,
        "rate_limit": "1/second recommended",
        "website": "https://commoncrawl.org/",
    },
    {
        "name": "sni_ip_ranges",
        "display_name": "SNI IP Ranges",
        "description": "Cloud provider SSL/TLS certificate scan data - discovers assets hosted on AWS, GCP, Azure, Oracle, DigitalOcean",
        "requires_key": False,
        "rate_limit": "Local data, no limit",
        "website": "https://kaeferjaeger.gay/?dir=sni-ip-ranges",
        "notes": "Scans cloud provider IP ranges for SSL certificates, revealing domains/subdomains hosted on cloud infrastructure",
    },
]















