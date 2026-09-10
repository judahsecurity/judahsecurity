"""Scan profile model for configurable scanning options."""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class ProfileType(str, enum.Enum):
    """Types of scan profiles."""
    NUCLEI = "nuclei"
    DISCOVERY = "discovery"
    FULL = "full"
    CUSTOM = "custom"


class ScanProfile(Base):
    """Scan profile model for reusable scan configurations."""
    
    __tablename__ = "scan_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Profile identification
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    profile_type = Column(Enum(ProfileType), default=ProfileType.CUSTOM)

    # NULL profiles are platform-provided and immutable. Organization profiles
    # are tenant-owned and may be managed by that organization's analysts.
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    organization = relationship("Organization", backref="scan_profiles")
    created_by = Column(String(100), nullable=True)
    
    # Nuclei-specific settings
    nuclei_templates = Column(JSON, default=list)  # List of template paths/tags
    nuclei_severity = Column(JSON, default=list)  # ["critical", "high", "medium", "low", "info"]
    nuclei_tags = Column(JSON, default=list)  # Template tags to include
    nuclei_exclude_tags = Column(JSON, default=list)  # Template tags to exclude
    nuclei_rate_limit = Column(Integer, default=150)  # Requests per second
    nuclei_bulk_size = Column(Integer, default=25)  # Parallel hosts
    nuclei_concurrency = Column(Integer, default=25)  # Parallel templates
    nuclei_timeout = Column(Integer, default=10)  # Request timeout in seconds
    
    # Discovery settings
    enable_subdomain_enum = Column(Boolean, default=True)
    enable_port_scan = Column(Boolean, default=True)
    enable_http_probe = Column(Boolean, default=True)
    enable_technology_detection = Column(Boolean, default=True)
    enable_vulnerability_scan = Column(Boolean, default=True)
    
    # Port scanning settings
    port_scan_top = Column(Integer, default=1000)  # Top N ports
    port_scan_custom = Column(JSON, default=list)  # Custom port list
    
    # Rate limiting
    max_concurrent_hosts = Column(Integer, default=50)
    requests_per_second = Column(Integer, default=100)
    
    # Profile state
    is_default = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScanProfile {self.name}>"
    
    def to_nuclei_args(self) -> list[str]:
        """Convert profile to Nuclei CLI arguments."""
        args = []
        
        # Severity filter
        if self.nuclei_severity:
            args.extend(["-severity", ",".join(self.nuclei_severity)])
        
        # Tags
        if self.nuclei_tags:
            args.extend(["-tags", ",".join(self.nuclei_tags)])
        
        # Exclude tags
        if self.nuclei_exclude_tags:
            args.extend(["-exclude-tags", ",".join(self.nuclei_exclude_tags)])
        
        # Rate limiting
        args.extend(["-rate-limit", str(self.nuclei_rate_limit)])
        args.extend(["-bulk-size", str(self.nuclei_bulk_size)])
        args.extend(["-concurrency", str(self.nuclei_concurrency)])
        args.extend(["-timeout", str(self.nuclei_timeout)])
        
        return args


# Default scan profiles
DEFAULT_PROFILES = [
    {
        "name": "Quick Scan",
        "description": "Fast scan focusing on critical and high severity vulnerabilities",
        "profile_type": ProfileType.NUCLEI,
        "nuclei_severity": ["critical", "high"],
        "nuclei_tags": ["cve", "rce", "sqli", "xss", "ssrf", "lfi"],
        "nuclei_rate_limit": 200,
        "nuclei_bulk_size": 50,
        "enable_vulnerability_scan": True,
        "enable_technology_detection": True,
        "is_default": True,
    },
    {
        "name": "Full Scan",
        "description": "Comprehensive scan with all severity levels and templates",
        "profile_type": ProfileType.FULL,
        "nuclei_severity": ["critical", "high", "medium", "low", "info"],
        "nuclei_tags": [],
        "nuclei_rate_limit": 100,
        "nuclei_bulk_size": 25,
        "enable_subdomain_enum": True,
        "enable_port_scan": True,
        "enable_http_probe": True,
        "enable_technology_detection": True,
        "enable_vulnerability_scan": True,
    },
    {
        "name": "CVE Only",
        "description": "Scan only for known CVEs",
        "profile_type": ProfileType.NUCLEI,
        "nuclei_severity": ["critical", "high", "medium"],
        "nuclei_tags": ["cve"],
        "nuclei_rate_limit": 150,
        "enable_vulnerability_scan": True,
    },
    {
        "name": "Misconfiguration",
        "description": "Focus on misconfigurations and exposed services",
        "profile_type": ProfileType.NUCLEI,
        "nuclei_severity": ["critical", "high", "medium", "low"],
        "nuclei_tags": ["misconfig", "exposure", "default-login", "unauth"],
        "nuclei_rate_limit": 150,
        "enable_vulnerability_scan": True,
    },
    {
        "name": "Technology Detection",
        "description": "Identify technologies without vulnerability scanning",
        "profile_type": ProfileType.NUCLEI,
        "nuclei_severity": ["info"],
        "nuclei_tags": ["tech"],
        "nuclei_rate_limit": 200,
        "enable_vulnerability_scan": False,
        "enable_technology_detection": True,
    },
    {
        "name": "Discovery Only",
        "description": "Asset discovery without vulnerability scanning",
        "profile_type": ProfileType.DISCOVERY,
        "enable_subdomain_enum": True,
        "enable_port_scan": True,
        "enable_http_probe": True,
        "enable_technology_detection": True,
        "enable_vulnerability_scan": False,
    },
    {
        "name": "Passive Recon",
        "description": "Passive reconnaissance only - no active scanning",
        "profile_type": ProfileType.DISCOVERY,
        "enable_subdomain_enum": True,
        "enable_port_scan": False,
        "enable_http_probe": False,
        "enable_technology_detection": False,
        "enable_vulnerability_scan": False,
    },
]
















