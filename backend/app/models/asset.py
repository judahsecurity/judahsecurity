"""Asset model for attack surface management."""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship

from app.db.database import Base


class AssetType(str, enum.Enum):
    """Types of assets in the attack surface."""
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    IP_RANGE = "IP_RANGE"
    URL = "URL"
    CERTIFICATE = "CERTIFICATE"
    PORT = "PORT"
    SERVICE = "SERVICE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    API_ENDPOINT = "API_ENDPOINT"
    EMAIL = "EMAIL"
    OTHER = "OTHER"


class AssetStatus(str, enum.Enum):
    """Asset discovery and verification status."""
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


class Asset(Base):
    """Asset model representing elements of the attack surface."""
    
    __tablename__ = "assets"
    
    # Composite indexes for common query patterns - improves query performance
    __table_args__ = (
        Index('ix_assets_org_created', 'organization_id', 'created_at'),
        Index('ix_assets_org_is_live', 'organization_id', 'is_live'),
        Index('ix_assets_org_in_scope', 'organization_id', 'in_scope'),
        Index('ix_assets_org_type', 'organization_id', 'asset_type'),
        Index('ix_assets_org_value', 'organization_id', 'value'),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Asset identification
    name = Column(String(255), index=True, nullable=False)
    asset_type = Column(Enum(AssetType), nullable=False, index=True)
    value = Column(String(500), nullable=False)  # The actual domain/IP/URL etc.
    root_domain = Column(String(255), nullable=True, index=True)  # The root domain (e.g., "rockwellautomation.com" for "sic.rockwellautomation.com")
    
    # Organization
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    organization = relationship("Organization", back_populates="assets")
    
    # Parent asset (for hierarchical relationships)
    parent_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    parent = relationship("Asset", remote_side=[id], backref="children")
    
    # Asset details
    status = Column(Enum(AssetStatus), default=AssetStatus.DISCOVERED)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=list)  # List of tags
    metadata_ = Column("metadata", JSON, default=dict)  # Additional metadata
    
    # Discovery info
    discovery_source = Column(String(100), nullable=True)  # How was it discovered (e.g., "whoxy", "subfinder", "nuclei")
    discovery_chain = Column(JSON, default=list)  # Full path of how this asset was associated with the org
    # Example: [{"step": 1, "source": "manual", "value": "rockwellautomation.com"}, 
    #           {"step": 2, "source": "whoxy_reverse_whois", "query": "Rockwell Automation", "found": "raracing.com"}]
    association_reason = Column(Text, nullable=True)  # Human-readable explanation of why this asset is associated
    association_confidence = Column(Integer, default=100)  # 0-100 confidence in the association
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Risk scoring
    risk_score = Column(Integer, default=0)  # 0-100
    criticality = Column(String(20), default="medium")  # low, medium, high, critical
    
    # Asset Criticality Score (ACS) - Business criticality rating
    acs_score = Column(Integer, default=5)  # 0-10 scale
    acs_drivers = Column(JSON, default=dict)  # Key drivers for ACS (e.g., {"device_class": "NI", "is_public": true})
    
    # Asset Risk Score (ARS) - Calculated from vulnerabilities and exposure
    ars_score = Column(Integer, default=0)  # 0-100 scale
    
    # Asset Classification
    system_type = Column(String(100), nullable=True)  # firewall, server, workstation, router, switch, etc.
    operating_system = Column(String(200), nullable=True)  # Detected OS (e.g., "Palo Alto Networks PAN-OS", "Windows Server 2019")
    device_class = Column(String(100), nullable=True)  # Network Infrastructure, Server, Workstation, IoT, etc.
    device_subclass = Column(String(200), nullable=True)  # Firewall and Next Generation Firewall, Web Server, etc.
    is_public = Column(Boolean, default=True, index=True)  # Is the asset publicly accessible
    
    # State
    is_monitored = Column(Boolean, default=True)
    is_licensed = Column(Boolean, default=True)  # Is the asset licensed/tracked
    is_live = Column(Boolean, default=False, index=True)  # Has the asset responded to probes (port scan, HTTP, etc.)
    has_login_portal = Column(Boolean, default=False, index=True)  # Has detected login/admin pages
    login_portals = Column(JSON, default=list)  # List of detected login URLs [{"url": "...", "type": "...", "status": 200}]
    
    # Screenshot cache (denormalized for performance - avoids loading all screenshots for list views)
    latest_screenshot_id = Column(Integer, nullable=True)  # ID of most recent successful screenshot
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    technologies = relationship(
        "Technology",
        secondary="asset_technologies",
        back_populates="assets"
    )
    port_services = relationship("PortService", back_populates="asset", cascade="all, delete-orphan")
    screenshots = relationship("Screenshot", back_populates="asset", cascade="all, delete-orphan", order_by="desc(Screenshot.captured_at)")
    sitemap_entries = relationship(
        "SitemapEntry",
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    
    # Labels (many-to-many relationship)
    labels = relationship("Label", secondary="asset_labels", back_populates="assets")
    
    # HTTP info (for web assets)
    http_status = Column(Integer, nullable=True)
    http_title = Column(String(500), nullable=True)
    http_headers = Column(JSON, default=dict)
    live_url = Column(String(500), nullable=True)  # The actual URL that responded (e.g., https://example.com)
    
    # DNS info
    dns_records = Column(JSON, default=dict)  # A, AAAA, MX, TXT, NS, etc.
    
    # SSL/TLS info
    ssl_info = Column(JSON, default=dict)  # Certificate details
    
    # Discovered endpoints and parameters (from ffuf, ParamSpider, Katana, etc.)
    endpoints = Column(JSON, default=list)  # List of discovered URL paths/endpoints
    parameters = Column(JSON, default=list)  # List of discovered URL parameters
    js_files = Column(JSON, default=list)  # JavaScript files found (often contain secrets/endpoints)
    # Vespasian / OpenAPI REST catalog — method, path, params, access, response
    rest_endpoints = Column(JSON, default=list)
    # Discovered swagger/openapi documents [{url, title, version, spec, last_captured}]
    api_specs = Column(JSON, default=list)
    
    # IP Resolution - multi-value to handle load balancers, CDNs, and IP changes over time
    ip_addresses = Column(JSON, default=list)  # Current IPs: ["1.2.3.4", "5.6.7.8"]
    ip_history = Column(JSON, default=list)  # Historical IPs with timestamps: [{"ip": "1.2.3.4", "first_seen": "...", "last_seen": "..."}]
    ip_address = Column(String(45), nullable=True)  # Primary/first resolved IP (for backward compatibility)
    
    # Geo-location info (based on primary IP)
    latitude = Column(String(20), nullable=True)
    longitude = Column(String(20), nullable=True)
    region = Column(String(50), nullable=True, index=True)  # Geographic region (e.g., "North America", "EMEA", "APAC")
    city = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    country_code = Column(String(10), nullable=True, index=True)
    isp = Column(String(200), nullable=True)
    asn = Column(String(50), nullable=True)
    
    # Scope and ownership tracking
    in_scope = Column(Boolean, default=True, index=True)  # Is this asset in scope for scanning
    is_owned = Column(Boolean, default=False, index=True)  # Is this asset confirmed owned by the org
    netblock_id = Column(Integer, ForeignKey("netblocks.id"), nullable=True)  # Associated netblock if any
    
    # Hosting classification (for IPs discovered via DNS resolution)
    # This helps distinguish between owned infrastructure vs cloud-hosted ephemeral IPs
    hosting_type = Column(String(50), nullable=True, index=True)  # owned, cloud, cdn, third_party, unknown
    hosting_provider = Column(String(100), nullable=True)  # azure, aws, gcp, cloudflare, akamai, digitalocean, oracle
    is_ephemeral_ip = Column(Boolean, default=True)  # True if IP could change (cloud/CDN) - safe default
    resolved_from = Column(String(255), nullable=True)  # Domain/subdomain this IP was resolved from
    
    # Scan tracking
    last_scan_id = Column(String(100), nullable=True)  # ID of the last scan that touched this asset
    last_scan_name = Column(String(255), nullable=True)  # Name of the last scan
    last_scan_date = Column(DateTime, nullable=True)  # When the last scan occurred
    last_scan_target = Column(String(500), nullable=True)  # The target used in the last scan
    last_authenticated_scan_status = Column(String(50), nullable=True)  # N/A, Success, Failed
    
    @property
    def open_ports_count(self) -> int:
        """Get count of open ports."""
        from app.models.port_service import PortState
        return len([p for p in self.port_services if p.state == PortState.OPEN])
    
    @property
    def risky_ports_count(self) -> int:
        """Get count of risky ports."""
        return len([p for p in self.port_services if p.is_risky])
    
    def update_ip_addresses(self, new_ips: list) -> None:
        """
        Update IP addresses for this asset. Handles multi-value IPs and history tracking.
        
        Args:
            new_ips: List of IP addresses currently resolving for this asset
        """
        now = datetime.utcnow().isoformat()
        
        # Initialize if needed
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.ip_history is None:
            self.ip_history = []
        
        # Convert to sets for comparison
        current_ips = set(self.ip_addresses or [])
        new_ip_set = set(new_ips)
        
        # Update history for IPs no longer active
        history = list(self.ip_history or [])
        for old_ip in current_ips - new_ip_set:
            # Mark as last seen
            for entry in history:
                if entry.get('ip') == old_ip and not entry.get('removed_at'):
                    entry['last_seen'] = now
                    entry['removed_at'] = now
        
        # Add new IPs to history
        for new_ip in new_ip_set - current_ips:
            history.append({
                'ip': new_ip,
                'first_seen': now,
                'last_seen': now,
                'removed_at': None
            })
        
        # Update last_seen for IPs still active
        for ip in new_ip_set & current_ips:
            for entry in history:
                if entry.get('ip') == ip and not entry.get('removed_at'):
                    entry['last_seen'] = now
        
        # Update fields
        self.ip_addresses = list(new_ip_set)
        self.ip_history = history
        
        # Set primary IP for backward compatibility
        if new_ips:
            self.ip_address = new_ips[0]
    
    def add_ip_address(self, ip: str) -> None:
        """Add a single IP address to this asset."""
        current = list(self.ip_addresses or [])
        if ip not in current:
            current.append(ip)
            self.update_ip_addresses(current)
    
    def __repr__(self):
        return f"<Asset {self.asset_type.value}: {self.value}>"


# Register mapper target for sitemap_entries (workers often import Asset only).
from app.models.sitemap_entry import SitemapEntry  # noqa: E402, F401
