"""
Unified ASM Scan Results Schema

Provides a standardized JSON format for all scan results, inspired by:
- H-ISAC (Health Information Sharing and Analysis Center) threat intel format
- ASM Recon output standardization
- STIX/TAXII cybersecurity data standards

This allows consistent handling of results from any scanner:
- Port scanners (naabu, masscan, nmap)
- Vulnerability scanners (nuclei)
- Discovery tools (subfinder, httpx, dnsx)
- External APIs (crt.sh, VirusTotal, etc.)
"""

from datetime import datetime
import re
from typing import Optional, List, Dict, Any, Union, Literal
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class ResultType(str, Enum):
    """Types of ASM scan results."""
    PORT = "port"
    VULNERABILITY = "vulnerability"
    SUBDOMAIN = "subdomain"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    URL = "url"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    SCREENSHOT = "screenshot"
    WAYBACK_URL = "wayback_url"
    TAKEOVER = "takeover"
    TLS_ANALYSIS = "tls_analysis"
    SECURITY_HEADER = "security_header"
    MAIL_INFRASTRUCTURE = "mail_infrastructure"
    THIRD_PARTY_VENDOR = "third_party_vendor"


class Severity(str, Enum):
    """Severity levels aligned with CVSS."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Confidence in the finding."""
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# =============================================================================
# Unified Finding Schema
# =============================================================================

class AffectedTarget(BaseModel):
    """One affected asset or endpoint. Submit one item for each IP/port pair."""

    asset_value: str = Field(..., min_length=1, max_length=500)
    asset_type: Optional[Literal["domain", "subdomain", "ip_address", "ip_range", "url", "cloud_resource", "api_endpoint", "other"]] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, max_length=10)
    service_name: Optional[str] = Field(None, max_length=100)
    url: Optional[str] = Field(None, max_length=2048)

    @field_validator("asset_value")
    @classmethod
    def one_asset_per_value(cls, value: str) -> str:
        value = value.strip()
        if not value or any(separator in value for separator in (",", "\n", "\r")):
            raise ValueError("asset_value must identify one asset; use another affected_targets item")
        return value


class FindingEvidenceItem(BaseModel):
    """One proof item, separate from narrative and target identifiers."""

    kind: str = Field(..., min_length=1, max_length=30)
    value: str = Field(..., min_length=1)
    observed_at: Optional[datetime] = None
    target: Optional[AffectedTarget] = Field(None, description="Exact target this proof supports, if narrower than the source record")


class FindingIdentifierItem(BaseModel):
    """One issue identifier, such as a CVE or CWE."""

    kind: str = Field(..., min_length=1, max_length=20)
    value: str = Field(..., min_length=1, max_length=255)

    @field_validator("value")
    @classmethod
    def one_identifier_per_value(cls, value: str) -> str:
        value = value.strip()
        if not value or any(separator in value for separator in (",", ";", "\n", "\r")):
            raise ValueError("identifier value must be atomic; use another identifiers item")
        return value


class UnifiedFinding(BaseModel):
    """
    Unified finding schema for any ASM scan result.
    
    This is the core data model that all scanner outputs are normalized to.
    Compatible with H-ISAC and ASM Recon output formats.
    """
    
    # Core identification
    id: Optional[str] = Field(None, max_length=500, description="Stable native source record ID, distinct from the platform finding ID")
    type: ResultType = Field(..., description="Type of finding")
    source: str = Field(..., max_length=100, description="Tool/source that discovered this (e.g., 'naabu', 'nuclei', 'crtsh')")
    
    # Target information
    target: str = Field(..., description="Original target (domain, IP, CIDR)")
    host: Optional[str] = Field(None, description="Resolved hostname")
    ip: Optional[str] = Field(None, description="Resolved IP address")
    port: Optional[int] = Field(None, description="Port number (for port/service findings)")
    protocol: Optional[str] = Field(None, description="Protocol (tcp/udp)")
    url: Optional[str] = Field(None, description="Full URL (for web findings)")
    affected_targets: List[AffectedTarget] = Field(default_factory=list, max_length=1000, description="Atomic affected asset/endpoint records")
    evidence_items: List[FindingEvidenceItem] = Field(default_factory=list, max_length=1000, description="Atomic source proof items")
    identifiers: List[FindingIdentifierItem] = Field(default_factory=list, max_length=100, description="Additional atomic issue identifiers")
    
    # Finding details
    title: Optional[str] = Field(None, description="Human-readable title")
    description: Optional[str] = Field(None, description="Detailed description")
    severity: Severity = Field(default=Severity.INFO, description="Severity level")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH, description="Confidence level")
    
    # Vulnerability-specific fields
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS score")
    template_id: Optional[str] = Field(None, description="Scanner template ID (e.g., Nuclei template)")

    @field_validator("cve_id", "cwe_id")
    @classmethod
    def one_standard_identifier(cls, value: Optional[str], info) -> Optional[str]:
        if value is None:
            return None
        value = value.strip().upper()
        pattern = r"CVE-\d{4}-\d{4,}" if info.field_name == "cve_id" else r"CWE-\d+"
        if not re.fullmatch(pattern, value):
            raise ValueError(f"{info.field_name} must contain one identifier; use identifiers for additional values")
        return value
    
    # Service/technology fields
    service_name: Optional[str] = Field(None, description="Service name (e.g., 'ssh', 'http')")
    service_version: Optional[str] = Field(None, description="Service version")
    service_product: Optional[str] = Field(None, description="Product name")
    banner: Optional[str] = Field(None, description="Service banner")
    technologies: List[str] = Field(default_factory=list, description="Detected technologies")
    
    # State and risk
    state: Optional[str] = Field(None, description="State (open, closed, filtered)")
    is_risky: bool = Field(default=False, description="Is this a risky finding")
    risk_reason: Optional[str] = Field(None, description="Reason for risk classification")
    
    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When discovered")
    first_seen: Optional[datetime] = Field(None, description="First seen timestamp")
    last_seen: Optional[datetime] = Field(None, description="Last seen timestamp")
    tags: List[str] = Field(default_factory=list, description="Tags/labels")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    
    # Subdomain takeover fields
    takeover_status: Optional[str] = Field(None, description="Takeover status: confirmed, potential, safe")
    takeover_service: Optional[str] = Field(None, description="Vulnerable service (e.g., 'github', 'aws-s3')")
    cname_target: Optional[str] = Field(None, description="CNAME chain endpoint for takeover checks")

    # TLS deep analysis fields
    tls_version: Optional[str] = Field(None, description="TLS protocol version")
    cipher_suite: Optional[str] = Field(None, description="Negotiated cipher suite")
    cert_score: Optional[str] = Field(None, description="Certificate grade A-F")
    key_algorithm: Optional[str] = Field(None, description="Key algorithm (RSA/ECDSA)")
    key_size: Optional[int] = Field(None, description="Key size in bits")
    ca_type: Optional[str] = Field(None, description="CA type: lets_encrypt, paid, self_signed")
    cert_expiry_days: Optional[int] = Field(None, description="Days until certificate expiry")

    # Security header fields
    security_headers: Optional[Dict[str, Any]] = Field(None, description="Security header analysis results")
    cors_policy: Optional[Dict[str, Any]] = Field(None, description="CORS policy analysis")

    # Mail infrastructure fields
    mail_records: Optional[Dict[str, Any]] = Field(None, description="MX/SPF/DKIM/DMARC/DNSSEC records")
    mail_provider: Optional[str] = Field(None, description="Detected mail provider")
    email_risk_score: Optional[int] = Field(None, description="Email security risk score 0-100")

    # Third-party vendor fields
    vendor_name: Optional[str] = Field(None, description="Detected vendor name")
    vendor_category: Optional[str] = Field(None, description="Vendor category (CDN, Analytics, Auth, etc.)")
    vendor_detection_source: Optional[str] = Field(None, description="How vendor was detected (csp, js, header)")

    # Raw data for debugging/analysis
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Original scanner output")
    
    # Organization context
    organization_id: Optional[int] = Field(None, description="Associated organization")
    asset_id: Optional[int] = Field(None, description="Associated asset ID")
    scan_id: Optional[int] = Field(None, description="Associated scan ID")
    
    class Config:
        json_schema_extra = {
            "example": {
                "type": "port",
                "source": "naabu",
                "target": "205.175.240.0/24",
                "host": "rockwellautomation.com",
                "ip": "205.175.241.128",
                "port": 443,
                "protocol": "tcp",
                "title": "HTTPS Service",
                "service_name": "https",
                "state": "open",
                "is_risky": False,
                "timestamp": "2024-01-04T12:00:00Z"
            }
        }


# =============================================================================
# Unified Scan Result Schema
# =============================================================================

class UnifiedScanResult(BaseModel):
    """
    Unified scan result container for any scanner output.
    
    This wraps all findings from a scan in a consistent format.
    """
    
    # Scan identification
    scan_id: Optional[int] = Field(None, description="Database scan ID")
    scan_type: str = Field(..., description="Type of scan (port_scan, vulnerability, discovery)")
    scanner: str = Field(..., description="Scanner used (naabu, nuclei, subfinder)")
    
    # Status
    success: bool = Field(..., description="Whether scan completed successfully")
    status: str = Field(default="completed", description="Scan status")
    
    # Targets
    targets_original: List[str] = Field(default_factory=list, description="Original targets")
    targets_scanned: int = Field(default=0, description="Number of targets scanned")
    targets_expanded: int = Field(default=0, description="Number after CIDR expansion")
    
    # Results
    findings: List[UnifiedFinding] = Field(default_factory=list, description="All findings")
    findings_count: int = Field(default=0, description="Total findings count")
    
    # Statistics
    stats: Dict[str, Any] = Field(default_factory=dict, description="Scan statistics")
    
    # Timing
    started_at: Optional[datetime] = Field(None, description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")
    duration_seconds: float = Field(default=0, description="Scan duration")
    
    # Errors
    errors: List[str] = Field(default_factory=list, description="Error messages")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")
    
    # Metadata
    organization_id: Optional[int] = Field(None, description="Organization ID")
    started_by: Optional[str] = Field(None, description="User who started the scan")
    
    def add_finding(self, finding: UnifiedFinding):
        """Add a finding to the results."""
        self.findings.append(finding)
        self.findings_count = len(self.findings)
    
    def get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of findings by severity."""
        breakdown = {s.value: 0 for s in Severity}
        for f in self.findings:
            breakdown[f.severity.value] = breakdown.get(f.severity.value, 0) + 1
        return breakdown
    
    def get_type_breakdown(self) -> Dict[str, int]:
        """Get count of findings by type."""
        breakdown = {}
        for f in self.findings:
            breakdown[f.type.value] = breakdown.get(f.type.value, 0) + 1
        return breakdown


# =============================================================================
# Conversion Functions
# =============================================================================

def port_result_to_unified(
    port_result,  # PortResult from port_scanner_service
    target: str,
    organization_id: Optional[int] = None,
    scan_id: Optional[int] = None
) -> UnifiedFinding:
    """Convert PortResult to UnifiedFinding."""
    from app.models.port_service import RISKY_PORTS, SERVICE_NAMES
    
    is_risky = port_result.port in RISKY_PORTS
    service_name = port_result.service_name or SERVICE_NAMES.get(port_result.port)
    
    return UnifiedFinding(
        type=ResultType.PORT,
        source=port_result.scanner,
        target=target,
        host=port_result.host,
        ip=port_result.ip,
        port=port_result.port,
        protocol=port_result.protocol,
        title=f"Port {port_result.port}/{port_result.protocol} Open",
        service_name=service_name,
        service_product=port_result.service_product,
        service_version=port_result.service_version,
        banner=port_result.banner,
        state=port_result.state,
        is_risky=is_risky,
        risk_reason=RISKY_PORTS.get(port_result.port) if is_risky else None,
        severity=Severity.MEDIUM if is_risky else Severity.INFO,
        organization_id=organization_id,
        scan_id=scan_id
    )


def nuclei_result_to_unified(
    nuclei_result,  # NucleiResult from nuclei_service
    target: str,
    organization_id: Optional[int] = None,
    scan_id: Optional[int] = None
) -> UnifiedFinding:
    """Convert NucleiResult to UnifiedFinding."""
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    
    return UnifiedFinding(
        type=ResultType.VULNERABILITY,
        source="nuclei",
        target=target,
        host=nuclei_result.host,
        ip=nuclei_result.ip,
        url=nuclei_result.matched_at,
        title=nuclei_result.template_name,
        description=nuclei_result.description,
        severity=severity_map.get(nuclei_result.severity.lower(), Severity.INFO),
        template_id=nuclei_result.template_id,
        cve_id=nuclei_result.cve_id,
        cwe_id=nuclei_result.cwe_id,
        cvss_score=nuclei_result.cvss_score,
        tags=nuclei_result.tags,
        references=nuclei_result.reference,
        timestamp=nuclei_result.timestamp or datetime.utcnow(),
        organization_id=organization_id,
        scan_id=scan_id,
        raw_data={"matcher_name": nuclei_result.matcher_name, "curl_command": nuclei_result.curl_command}
    )


def discovery_result_to_unified_list(
    discovery_result,  # DiscoveryResult from external_discovery_service
    organization_id: Optional[int] = None
) -> List[UnifiedFinding]:
    """Convert DiscoveryResult to list of UnifiedFindings."""
    findings = []
    
    for domain in discovery_result.domains:
        findings.append(UnifiedFinding(
            type=ResultType.DOMAIN,
            source=discovery_result.source,
            target=domain,
            host=domain,
            title=f"Domain: {domain}",
            severity=Severity.INFO,
            organization_id=organization_id
        ))
    
    for subdomain in discovery_result.subdomains:
        findings.append(UnifiedFinding(
            type=ResultType.SUBDOMAIN,
            source=discovery_result.source,
            target=subdomain,
            host=subdomain,
            title=f"Subdomain: {subdomain}",
            severity=Severity.INFO,
            organization_id=organization_id
        ))
    
    for ip in discovery_result.ip_addresses:
        findings.append(UnifiedFinding(
            type=ResultType.IP_ADDRESS,
            source=discovery_result.source,
            target=ip,
            ip=ip,
            title=f"IP Address: {ip}",
            severity=Severity.INFO,
            organization_id=organization_id
        ))
    
    for cidr in discovery_result.ip_ranges:
        findings.append(UnifiedFinding(
            type=ResultType.IP_RANGE,
            source=discovery_result.source,
            target=cidr,
            title=f"IP Range: {cidr}",
            severity=Severity.INFO,
            organization_id=organization_id
        ))
    
    return findings


def httpx_result_to_unified(
    httpx_result,  # HttpxResult from projectdiscovery_service
    target: str,
    organization_id: Optional[int] = None
) -> UnifiedFinding:
    """Convert HttpxResult to UnifiedFinding."""
    return UnifiedFinding(
        type=ResultType.URL,
        source="httpx",
        target=target,
        host=httpx_result.host,
        ip=httpx_result.ip,
        url=httpx_result.url,
        title=httpx_result.title or httpx_result.url,
        description=f"HTTP {httpx_result.status_code} - {httpx_result.webserver or 'Unknown'}",
        technologies=httpx_result.technologies,
        severity=Severity.INFO,
        organization_id=organization_id,
        raw_data={
            "status_code": httpx_result.status_code,
            "content_type": httpx_result.content_type,
            "content_length": httpx_result.content_length,
            "cdn": httpx_result.cdn,
            "tls_version": httpx_result.tls_version,
        }
    )


# =============================================================================
# Export Schema (H-ISAC / ASM Recon compatible)
# =============================================================================

class ASMExportFormat(BaseModel):
    """
    Export format compatible with H-ISAC and ASM Recon standards.
    
    This can be used for:
    - Sharing with other security teams
    - Importing into SIEMs
    - Integration with threat intel platforms
    """
    
    # Header
    version: str = Field(default="1.0", description="Schema version")
    format: str = Field(default="asm-unified", description="Format identifier")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generator: str = Field(default="Judah Security ASM Platform")
    
    # Organization context
    organization: Optional[str] = Field(None, description="Organization name")
    organization_id: Optional[int] = Field(None, description="Organization ID")
    
    # Scan metadata
    scan_info: Optional[Dict[str, Any]] = Field(None, description="Scan metadata")
    
    # Findings
    findings: List[UnifiedFinding] = Field(default_factory=list)
    total_count: int = Field(default=0)
    
    # Statistics
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    type_breakdown: Dict[str, int] = Field(default_factory=dict)
    source_breakdown: Dict[str, int] = Field(default_factory=dict)
    
    @classmethod
    def from_scan_result(cls, scan_result: UnifiedScanResult, organization_name: Optional[str] = None):
        """Create export from scan result."""
        source_breakdown = {}
        for f in scan_result.findings:
            source_breakdown[f.source] = source_breakdown.get(f.source, 0) + 1
        
        return cls(
            organization=organization_name,
            organization_id=scan_result.organization_id,
            scan_info={
                "scan_id": scan_result.scan_id,
                "scan_type": scan_result.scan_type,
                "scanner": scan_result.scanner,
                "targets": scan_result.targets_original,
                "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
                "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                "duration_seconds": scan_result.duration_seconds,
            },
            findings=scan_result.findings,
            total_count=len(scan_result.findings),
            severity_breakdown=scan_result.get_severity_breakdown(),
            type_breakdown=scan_result.get_type_breakdown(),
            source_breakdown=source_breakdown,
        )
