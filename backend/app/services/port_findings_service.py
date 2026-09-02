"""
Port findings service for creating vulnerabilities from port scan results.

Automatically generates security findings for:
- Open risky ports (SSH, RDP, databases, etc.)
- Filtered ports that may indicate firewall issues
- Unencrypted services (HTTP, FTP, Telnet)
- Default/dangerous ports
"""

import logging
from typing import Optional, List
from datetime import datetime
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.port_service import PortService, PortState, Protocol
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus

logger = logging.getLogger(__name__)


@dataclass
class PortFindingRule:
    """Rule for generating findings from port scans."""
    ports: List[int]
    title: str
    description: str
    severity: Severity
    remediation: str
    tags: List[str]
    cwe_id: Optional[str] = None
    states: List[PortState] = None  # None = all states
    
    def __post_init__(self):
        if self.states is None:
            self.states = [PortState.OPEN, PortState.OPEN_FILTERED]


# Port finding rules - categorized by risk type
PORT_FINDING_RULES = [
    # ==================== REMOTE ACCESS ====================
    PortFindingRule(
        ports=[22],
        title="SSH Service Exposed",
        description="SSH (Secure Shell) service is exposed to the network. While SSH is encrypted, exposed SSH services are common targets for brute-force attacks and credential stuffing.",
        severity=Severity.MEDIUM,
        remediation="1. Restrict SSH access to specific IP ranges using firewall rules\n2. Implement key-based authentication and disable password auth\n3. Use fail2ban or similar to block brute-force attempts\n4. Consider using a VPN or bastion host for SSH access\n5. Change default SSH port if possible",
        tags=["remote-access", "ssh", "brute-force-target"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[3389],
        title="RDP Service Exposed",
        description="Remote Desktop Protocol (RDP) is exposed to the network. RDP is a high-value target for attackers and has been associated with numerous ransomware attacks.",
        severity=Severity.HIGH,
        remediation="1. Never expose RDP directly to the internet\n2. Use a VPN or Remote Desktop Gateway\n3. Enable Network Level Authentication (NLA)\n4. Implement account lockout policies\n5. Use multi-factor authentication\n6. Keep systems patched (BlueKeep, etc.)",
        tags=["remote-access", "rdp", "ransomware-vector", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[5900, 5901, 5902, 5903],
        title="VNC Service Exposed",
        description="VNC (Virtual Network Computing) remote desktop service is exposed. VNC often lacks strong authentication and encryption.",
        severity=Severity.HIGH,
        remediation="1. Do not expose VNC to the internet\n2. Use SSH tunneling or VPN for VNC access\n3. Enable strong authentication\n4. Use VNC variants with encryption (e.g., TightVNC with SSL)",
        tags=["remote-access", "vnc", "weak-authentication"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[23],
        title="Telnet Service Exposed",
        description="Telnet transmits all data including credentials in cleartext. This service should never be exposed.",
        severity=Severity.CRITICAL,
        remediation="1. Disable Telnet immediately\n2. Replace with SSH for remote access\n3. If Telnet is required for legacy devices, isolate on a separate network segment",
        tags=["remote-access", "telnet", "cleartext", "deprecated-protocol"],
        cwe_id="CWE-319"
    ),
    PortFindingRule(
        ports=[512, 513, 514],
        title="R-Services Exposed (rexec/rlogin/rsh)",
        description="Legacy BSD r-services are exposed. These services use weak authentication and transmit data in cleartext.",
        severity=Severity.CRITICAL,
        remediation="1. Disable all r-services immediately\n2. Replace with SSH\n3. Remove .rhosts files",
        tags=["remote-access", "r-services", "legacy", "cleartext"],
        cwe_id="CWE-319"
    ),
    
    # ==================== DATABASES ====================
    PortFindingRule(
        ports=[3306],
        title="MySQL Database Exposed",
        description="MySQL database server is directly accessible from the network. Exposed databases are targets for data theft and ransomware.",
        severity=Severity.CRITICAL,
        remediation="1. Never expose databases directly to the internet\n2. Use firewall rules to restrict access to application servers only\n3. Enable SSL/TLS for database connections\n4. Use strong, unique passwords\n5. Disable remote root login",
        tags=["database", "mysql", "data-exposure", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[5432],
        title="PostgreSQL Database Exposed",
        description="PostgreSQL database server is directly accessible from the network. Exposed databases are targets for data theft.",
        severity=Severity.CRITICAL,
        remediation="1. Restrict database access to application servers only\n2. Configure pg_hba.conf to limit connections\n3. Enable SSL for connections\n4. Use strong authentication",
        tags=["database", "postgresql", "data-exposure", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[1433, 1434],
        title="Microsoft SQL Server Exposed",
        description="MS SQL Server is directly accessible from the network. This is a high-value target for attackers.",
        severity=Severity.CRITICAL,
        remediation="1. Block SQL Server ports at the perimeter firewall\n2. Use Windows Authentication instead of SQL Authentication\n3. Enable encryption for connections\n4. Disable the SQL Server Browser service if not needed",
        tags=["database", "mssql", "data-exposure", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[1521, 1522, 1525],
        title="Oracle Database Exposed",
        description="Oracle database listener is directly accessible from the network.",
        severity=Severity.CRITICAL,
        remediation="1. Restrict access to authorized application servers\n2. Enable Oracle Advanced Security encryption\n3. Configure listener security",
        tags=["database", "oracle", "data-exposure", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[27017, 27018, 27019, 28017],
        title="MongoDB Exposed",
        description="MongoDB database is accessible from the network. MongoDB has been involved in numerous data breaches when exposed without authentication.",
        severity=Severity.CRITICAL,
        remediation="1. Enable authentication (disabled by default in older versions)\n2. Bind to localhost or specific IPs only\n3. Use TLS encryption\n4. Disable HTTP interface (28017)",
        tags=["database", "mongodb", "nosql", "data-exposure", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[6379],
        title="Redis Exposed",
        description="Redis in-memory database is accessible from the network. Redis often runs without authentication and can be exploited for remote code execution.",
        severity=Severity.CRITICAL,
        remediation="1. Enable requirepass authentication\n2. Bind to localhost or use firewall rules\n3. Disable dangerous commands (CONFIG, EVAL, etc.)\n4. Use TLS in Redis 6+",
        tags=["database", "redis", "cache", "rce-possible", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[9200, 9300],
        title="Elasticsearch Exposed",
        description="Elasticsearch cluster is accessible from the network. Exposed Elasticsearch instances have led to massive data breaches.",
        severity=Severity.CRITICAL,
        remediation="1. Enable X-Pack security or Search Guard\n2. Use firewall rules to restrict access\n3. Disable dynamic scripting if not needed\n4. Enable TLS encryption",
        tags=["database", "elasticsearch", "nosql", "data-exposure", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[5984, 6984],
        title="CouchDB Exposed",
        description="CouchDB database is accessible from the network.",
        severity=Severity.CRITICAL,
        remediation="1. Enable authentication\n2. Bind to specific interfaces\n3. Use a reverse proxy with authentication",
        tags=["database", "couchdb", "nosql", "data-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[11211],
        title="Memcached Exposed",
        description="Memcached cache server is accessible. Exposed Memcached servers have been used for amplification DDoS attacks.",
        severity=Severity.HIGH,
        remediation="1. Bind Memcached to localhost only\n2. Use SASL authentication\n3. Disable UDP if not needed\n4. Use firewall rules",
        tags=["cache", "memcached", "ddos-amplification"],
        cwe_id="CWE-284"
    ),
    
    # ==================== FILE TRANSFER ====================
    PortFindingRule(
        ports=[21],
        title="FTP Service Exposed",
        description="FTP service is exposed. FTP transmits credentials and data in cleartext and often allows anonymous access.",
        severity=Severity.HIGH,
        remediation="1. Replace FTP with SFTP or FTPS\n2. If FTP is required, disable anonymous access\n3. Use strong passwords\n4. Restrict to specific directories",
        tags=["file-transfer", "ftp", "cleartext", "anonymous-access"],
        cwe_id="CWE-319"
    ),
    PortFindingRule(
        ports=[69],
        title="TFTP Service Exposed",
        description="TFTP (Trivial File Transfer Protocol) has no authentication mechanism.",
        severity=Severity.HIGH,
        remediation="1. Disable TFTP if not needed\n2. If required, restrict to specific network segments\n3. Limit accessible directories",
        tags=["file-transfer", "tftp", "no-authentication"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[445],
        title="SMB/CIFS Service Exposed",
        description="SMB (Server Message Block) file sharing is exposed to the network. SMB has been the vector for major attacks including WannaCry and NotPetya ransomware.",
        severity=Severity.CRITICAL,
        remediation="1. Never expose SMB to the internet (block port 445 at perimeter)\n2. Disable SMBv1\n3. Keep systems patched for SMB vulnerabilities\n4. Use SMB signing",
        tags=["file-sharing", "smb", "ransomware-vector", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[139],
        title="NetBIOS Session Service Exposed",
        description="NetBIOS session service is exposed, which can leak sensitive information about the system.",
        severity=Severity.MEDIUM,
        remediation="1. Block NetBIOS ports at the perimeter\n2. Disable NetBIOS over TCP/IP if not needed\n3. Use host-based firewalls",
        tags=["file-sharing", "netbios", "information-disclosure"],
        cwe_id="CWE-200"
    ),
    PortFindingRule(
        ports=[2049],
        title="NFS Service Exposed",
        description="NFS (Network File System) is exposed to the network. Misconfigured NFS shares can lead to unauthorized data access.",
        severity=Severity.HIGH,
        remediation="1. Restrict NFS exports to specific hosts\n2. Use NFSv4 with Kerberos authentication\n3. Avoid using no_root_squash option",
        tags=["file-sharing", "nfs", "data-exposure"],
        cwe_id="CWE-284"
    ),
    
    # ==================== WEB/PROXY ====================
    PortFindingRule(
        ports=[80],
        title="HTTP Service (Unencrypted)",
        description="HTTP service is running without encryption. All data transmitted is visible to network observers.",
        severity=Severity.LOW,
        remediation="1. Implement HTTPS with TLS 1.2 or higher\n2. Redirect all HTTP traffic to HTTPS\n3. Enable HSTS headers",
        tags=["web", "http", "unencrypted"],
        cwe_id="CWE-319"
    ),
    PortFindingRule(
        ports=[8080, 8000, 8888, 3000],
        title="Alternative HTTP Port Exposed",
        description="Web service running on non-standard port. These ports often host development servers, proxies, or admin interfaces.",
        severity=Severity.LOW,
        remediation="1. Determine if service should be publicly accessible\n2. Implement HTTPS\n3. Add authentication if it's an admin interface\n4. Consider using standard ports behind a reverse proxy",
        tags=["web", "http-alt", "development-server"],
        cwe_id="CWE-200"
    ),
    PortFindingRule(
        ports=[3128, 8080, 1080],
        title="Proxy Server Exposed",
        description="A proxy server may be exposed. Open proxies can be abused for anonymous browsing and attacks.",
        severity=Severity.MEDIUM,
        remediation="1. Implement authentication\n2. Restrict to internal networks\n3. Monitor for abuse",
        tags=["proxy", "open-proxy", "abuse-potential"],
        cwe_id="CWE-441"
    ),
    
    # ==================== EMAIL ====================
    PortFindingRule(
        ports=[25],
        title="SMTP Service Exposed",
        description="SMTP mail server is exposed. Open SMTP relays can be abused for spam.",
        severity=Severity.MEDIUM,
        remediation="1. Ensure open relay is disabled\n2. Implement SPF, DKIM, and DMARC\n3. Use TLS (STARTTLS)\n4. Implement rate limiting",
        tags=["email", "smtp", "spam-potential"],
        cwe_id="CWE-441"
    ),
    PortFindingRule(
        ports=[110],
        title="POP3 Service (Unencrypted)",
        description="POP3 email service is running without encryption, exposing email credentials.",
        severity=Severity.MEDIUM,
        remediation="1. Enable POP3S (port 995) with TLS\n2. Disable unencrypted POP3\n3. Consider migrating to IMAP",
        tags=["email", "pop3", "cleartext"],
        cwe_id="CWE-319"
    ),
    PortFindingRule(
        ports=[143],
        title="IMAP Service (Unencrypted)",
        description="IMAP email service is running without encryption, exposing email credentials.",
        severity=Severity.MEDIUM,
        remediation="1. Enable IMAPS (port 993) with TLS\n2. Disable unencrypted IMAP\n3. Use STARTTLS",
        tags=["email", "imap", "cleartext"],
        cwe_id="CWE-319"
    ),
    
    # ==================== DIRECTORY/LDAP ====================
    PortFindingRule(
        ports=[389],
        title="LDAP Service Exposed (Unencrypted)",
        description="LDAP directory service is exposed without encryption, potentially exposing user information and credentials.",
        severity=Severity.HIGH,
        remediation="1. Use LDAPS (port 636) with TLS\n2. Restrict LDAP access to internal networks\n3. Implement proper access controls",
        tags=["directory", "ldap", "cleartext", "credential-exposure"],
        cwe_id="CWE-319"
    ),
    PortFindingRule(
        ports=[88],
        title="Kerberos Service Exposed",
        description="Kerberos authentication service is exposed. This may allow ticket-based attacks.",
        severity=Severity.MEDIUM,
        remediation="1. Restrict Kerberos to internal networks\n2. Ensure strong passwords for service accounts\n3. Monitor for Kerberoasting attacks",
        tags=["directory", "kerberos", "authentication"],
        cwe_id="CWE-522"
    ),
    
    # ==================== MANAGEMENT/MONITORING ====================
    PortFindingRule(
        ports=[161, 162],
        title="SNMP Service Exposed",
        description="SNMP service is exposed. SNMPv1/v2c use community strings that are transmitted in cleartext.",
        severity=Severity.MEDIUM,
        remediation="1. Use SNMPv3 with authentication and encryption\n2. Change default community strings\n3. Restrict SNMP to management networks\n4. Disable SNMP write access if not needed",
        tags=["management", "snmp", "information-disclosure"],
        cwe_id="CWE-200"
    ),
    PortFindingRule(
        ports=[2375, 2376],
        title="Docker API Exposed",
        description="Docker daemon API is exposed. This allows remote control of Docker and can lead to complete host compromise.",
        severity=Severity.CRITICAL,
        remediation="1. Never expose Docker API to the internet\n2. Use TLS authentication for remote Docker access\n3. Use Docker socket only for local access",
        tags=["container", "docker", "rce-possible", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    PortFindingRule(
        ports=[6443, 10250],
        title="Kubernetes API Exposed",
        description="Kubernetes API server or Kubelet is exposed. This can allow cluster takeover.",
        severity=Severity.CRITICAL,
        remediation="1. Use proper RBAC and authentication\n2. Restrict API server access\n3. Enable audit logging\n4. Use network policies",
        tags=["container", "kubernetes", "k8s", "critical-exposure"],
        cwe_id="CWE-284"
    ),
    
    # ==================== OT/ICS - INDUSTRIAL CONTROL SYSTEMS ====================
    PortFindingRule(
        ports=[502],
        title="Modbus Protocol Exposed",
        description="Modbus industrial protocol is exposed. Modbus lacks authentication and encryption, allowing attackers to read/write to PLCs and industrial controllers.",
        severity=Severity.CRITICAL,
        remediation="1. NEVER expose Modbus to the internet\n2. Segment OT networks from IT networks\n3. Use industrial firewalls or data diodes\n4. Implement monitoring for anomalous Modbus traffic\n5. Consider Modbus/TCP security extensions if available",
        tags=["ot", "ics", "scada", "modbus", "plc", "critical-infrastructure"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[102],
        title="Siemens S7 Protocol Exposed",
        description="Siemens S7comm protocol (ISO-TSAP) is exposed. This allows direct communication with Siemens PLCs and has been targeted by malware like Stuxnet.",
        severity=Severity.CRITICAL,
        remediation="1. NEVER expose S7 protocol to the internet\n2. Implement network segmentation between IT/OT\n3. Use Siemens security features (access protection)\n4. Deploy industrial IDS/IPS\n5. Monitor for S7comm exploitation attempts",
        tags=["ot", "ics", "scada", "siemens", "s7", "plc", "critical-infrastructure"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[44818],
        title="EtherNet/IP Protocol Exposed",
        description="EtherNet/IP (CIP) industrial protocol is exposed. Used by Rockwell/Allen-Bradley PLCs. Lacks built-in authentication.",
        severity=Severity.CRITICAL,
        remediation="1. NEVER expose EtherNet/IP to untrusted networks\n2. Implement industrial DMZ architecture\n3. Use CIP Security if supported by devices\n4. Deploy network monitoring for OT protocols\n5. Segment control networks",
        tags=["ot", "ics", "scada", "ethernet-ip", "cip", "rockwell", "allen-bradley", "plc"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[20000],
        title="DNP3 Protocol Exposed",
        description="DNP3 (Distributed Network Protocol) is exposed. Used in utilities and SCADA systems. Vulnerable to manipulation and replay attacks.",
        severity=Severity.CRITICAL,
        remediation="1. NEVER expose DNP3 to the internet\n2. Implement DNP3 Secure Authentication if supported\n3. Use encrypted VPN tunnels for remote DNP3 access\n4. Deploy DNP3-aware firewalls\n5. Monitor for protocol anomalies",
        tags=["ot", "ics", "scada", "dnp3", "utilities", "critical-infrastructure"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[47808],
        title="BACnet Protocol Exposed",
        description="BACnet building automation protocol is exposed. Used for HVAC, lighting, and access control systems. Lacks authentication.",
        severity=Severity.HIGH,
        remediation="1. Restrict BACnet to building management networks\n2. Use BACnet/SC (Secure Connect) if available\n3. Implement network segmentation\n4. Monitor for unauthorized BACnet commands\n5. Disable BACnet broadcast if not needed",
        tags=["ot", "ics", "bacnet", "building-automation", "hvac"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[1911, 1962],
        title="Niagara Fox Protocol Exposed",
        description="Tridium Niagara Fox protocol is exposed. Used in building automation and smart grid systems.",
        severity=Severity.HIGH,
        remediation="1. Restrict access to management networks only\n2. Update to latest Niagara firmware\n3. Enable TLS for Fox protocol\n4. Use strong authentication\n5. Review CVE-2012-4701 and related vulnerabilities",
        tags=["ot", "ics", "niagara", "fox", "building-automation", "tridium"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[789],
        title="Red Lion Crimson Protocol Exposed",
        description="Red Lion Crimson protocol is exposed. Used for HMI and industrial device configuration.",
        severity=Severity.HIGH,
        remediation="1. Restrict to control network segments\n2. Use VPN for remote access\n3. Update device firmware regularly\n4. Implement network monitoring",
        tags=["ot", "ics", "red-lion", "hmi"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[2222],
        title="EtherNet/IP I/O Exposed",
        description="EtherNet/IP implicit messaging (I/O) port is exposed. Used for real-time I/O data between PLCs and devices.",
        severity=Severity.HIGH,
        remediation="1. Never expose I/O traffic outside control networks\n2. Use industrial firewalls\n3. Implement strict network segmentation\n4. Monitor for unauthorized I/O connections",
        tags=["ot", "ics", "ethernet-ip", "io", "plc"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[4840],
        title="OPC UA Protocol Exposed",
        description="OPC Unified Architecture protocol is exposed. While OPC UA supports security, misconfigured instances may allow unauthenticated access.",
        severity=Severity.HIGH,
        remediation="1. Enable OPC UA security mode (Sign or SignAndEncrypt)\n2. Require certificate-based authentication\n3. Restrict to trusted networks\n4. Audit OPC UA access regularly\n5. Keep OPC UA stack updated",
        tags=["ot", "ics", "opc-ua", "industrial-automation"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[18245, 18246],
        title="GE SRTP Protocol Exposed",
        description="GE SRTP (Service Request Transport Protocol) is exposed. Used by GE PLCs and controllers.",
        severity=Severity.CRITICAL,
        remediation="1. Restrict to control network segments only\n2. Implement industrial firewalls\n3. Use VPN for any remote access\n4. Monitor for protocol anomalies",
        tags=["ot", "ics", "ge", "srtp", "plc"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[1089, 1090, 1091],
        title="FF HSE Protocol Exposed",
        description="Foundation Fieldbus HSE (High Speed Ethernet) protocol is exposed. Used in process automation.",
        severity=Severity.HIGH,
        remediation="1. Segment fieldbus networks\n2. Use industrial firewalls\n3. Implement OT network monitoring\n4. Document and audit all HSE connections",
        tags=["ot", "ics", "fieldbus", "process-automation"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[9600],
        title="OMRON FINS Protocol Exposed",
        description="OMRON FINS industrial protocol is exposed. Used for communication with OMRON PLCs. Lacks authentication.",
        severity=Severity.CRITICAL,
        remediation="1. Never expose FINS to untrusted networks\n2. Implement network segmentation\n3. Use FINS/UDP filtering\n4. Deploy OT-aware IDS",
        tags=["ot", "ics", "omron", "fins", "plc"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[5007],
        title="Mitsubishi MELSEC Protocol Exposed",
        description="Mitsubishi MELSEC-Q protocol is exposed. Used for PLC programming and communication. No built-in authentication.",
        severity=Severity.CRITICAL,
        remediation="1. Restrict to engineering workstations only\n2. Segment control networks\n3. Use industrial firewalls\n4. Monitor for unauthorized MELSEC traffic",
        tags=["ot", "ics", "mitsubishi", "melsec", "plc"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[2404],
        title="IEC 60870-5-104 Protocol Exposed",
        description="IEC 60870-5-104 telecontrol protocol is exposed. Used in power grids and utilities for SCADA communication.",
        severity=Severity.CRITICAL,
        remediation="1. Never expose IEC 104 to the internet\n2. Use IEC 62351 security extensions\n3. Implement encrypted tunnels\n4. Deploy protocol-aware monitoring\n5. Follow NERC CIP compliance",
        tags=["ot", "ics", "scada", "iec-104", "utilities", "power-grid", "critical-infrastructure"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[4000],
        title="Emerson ROC Protocol Exposed",
        description="Emerson ROC (Remote Operations Controller) protocol is exposed. Used in oil & gas pipeline monitoring.",
        severity=Severity.CRITICAL,
        remediation="1. Restrict to SCADA network segments\n2. Use encrypted tunnels for remote access\n3. Implement ROC Plus security features\n4. Monitor for unauthorized access",
        tags=["ot", "ics", "emerson", "roc", "oil-gas", "pipeline"],
        cwe_id="CWE-306"
    ),
    PortFindingRule(
        ports=[5094, 5095],
        title="HART-IP Protocol Exposed",
        description="HART-IP industrial protocol is exposed. Used for smart field device communication in process industries.",
        severity=Severity.HIGH,
        remediation="1. Restrict to instrument networks\n2. Use industrial firewalls\n3. Implement HART-IP security features\n4. Monitor device configurations",
        tags=["ot", "ics", "hart", "field-devices", "process-automation"],
        cwe_id="CWE-306"
    ),
    
    # ==================== FILTERED PORTS ====================
    PortFindingRule(
        ports=[22, 3389, 445, 3306, 5432, 1433],
        title="Critical Port in Filtered State",
        description="A security-critical port is in a filtered state, which may indicate incomplete firewall rules or a partially exposed service.",
        severity=Severity.INFO,
        remediation="1. Review firewall rules to ensure consistent policy\n2. Verify if the service should be completely blocked or allowed\n3. Document the intended access policy for this port",
        tags=["filtered", "firewall-review", "policy-check"],
        states=[PortState.FILTERED, PortState.OPEN_FILTERED, PortState.CLOSED_FILTERED]
    ),
]


class PortFindingsService:
    """
    Service for automatically creating findings from port scan results.
    
    Generates security findings based on:
    - Open risky ports
    - Filtered ports on critical services
    - Unencrypted services
    """
    
    def __init__(self, rules: Optional[List[PortFindingRule]] = None):
        """
        Initialize port findings service.
        
        Args:
            rules: Custom finding rules (defaults to PORT_FINDING_RULES)
        """
        self.rules = rules or PORT_FINDING_RULES
    
    def create_findings_for_port(
        self,
        db: Session,
        port_service: PortService,
        scan_id: Optional[int] = None
    ) -> List[Vulnerability]:
        """
        Create findings for a single port service.
        
        Args:
            db: Database session
            port_service: The port service to evaluate
            scan_id: Optional scan ID to associate findings with
            
        Returns:
            List of created Vulnerability objects
        """
        findings = []
        
        for rule in self.rules:
            if self._matches_rule(port_service, rule):
                # Check if finding already exists
                existing = db.query(Vulnerability).filter(
                    Vulnerability.asset_id == port_service.asset_id,
                    Vulnerability.title.contains(f"Port {port_service.port}"),
                    Vulnerability.status.in_([
                        VulnerabilityStatus.OPEN,
                        VulnerabilityStatus.IN_PROGRESS
                    ])
                ).first()
                
                if existing:
                    # Update last detected
                    existing.last_detected = datetime.utcnow()
                    continue
                
                # Create new finding
                finding = self._create_finding(db, port_service, rule, scan_id)
                findings.append(finding)
        
        if findings:
            db.commit()
        
        return findings
    
    def create_findings_for_asset(
        self,
        db: Session,
        asset: Asset,
        scan_id: Optional[int] = None
    ) -> List[Vulnerability]:
        """
        Create findings for all ports on an asset.
        
        Args:
            db: Database session
            asset: The asset to evaluate
            scan_id: Optional scan ID
            
        Returns:
            List of created findings
        """
        findings = []
        
        for port_service in asset.port_services:
            port_findings = self.create_findings_for_port(db, port_service, scan_id)
            findings.extend(port_findings)
        
        return findings
    
    def create_findings_from_scan(
        self,
        db: Session,
        organization_id: int,
        scan_id: Optional[int] = None,
        port_ids: Optional[List[int]] = None
    ) -> dict:
        """
        Create findings for all recently scanned ports.
        
        Args:
            db: Database session
            organization_id: Organization ID
            scan_id: Optional scan ID
            port_ids: Optional list of specific port IDs to evaluate
            
        Returns:
            Summary of findings created
        """
        summary = {
            "findings_created": 0,
            "findings_updated": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "findings": []
        }
        
        # Query ports
        query = db.query(PortService).join(Asset).filter(
            Asset.organization_id == organization_id
        )
        
        if port_ids:
            query = query.filter(PortService.id.in_(port_ids))
        
        ports = query.all()
        
        # Import deduplication service for cross-asset duplicate detection
        from app.services.finding_deduplication_service import get_deduplication_service
        dedup_service = get_deduplication_service(db)
        
        for port_service in ports:
            for rule in self.rules:
                if self._matches_rule(port_service, rule):
                    # Check for existing finding on this asset
                    existing = self._find_existing(db, port_service, rule)
                    
                    if existing:
                        existing.last_detected = datetime.utcnow()
                        summary["findings_updated"] += 1
                    else:
                        # Check for duplicate on related assets (domain/IP deduplication)
                        if port_service.asset:
                            duplicate = dedup_service.find_duplicate_finding(
                                asset=port_service.asset,
                                port=port_service.port,
                                include_related_assets=True
                            )
                            
                            if duplicate:
                                # Same port finding exists on related asset
                                ip_info = f" at IP {port_service.scanned_ip}" if port_service.scanned_ip else ""
                                dedup_service.merge_finding_into_existing(
                                    existing=duplicate,
                                    new_asset=port_service.asset,
                                    new_evidence=f"Port {port_service.port}/{port_service.protocol.value}{ip_info}",
                                    new_matched_at=port_service.asset.value
                                )
                                summary["findings_updated"] += 1
                                if "deduplicated" not in summary:
                                    summary["deduplicated"] = 0
                                summary["deduplicated"] += 1
                                logger.info(
                                    f"Deduplicated port {port_service.port} finding on {port_service.asset.value} - "
                                    f"already exists on related asset (finding #{duplicate.id})"
                                )
                                continue
                        
                        # Create new finding
                        finding = self._create_finding(db, port_service, rule, scan_id)
                        summary["findings_created"] += 1
                        summary["by_severity"][rule.severity.value] += 1
                        summary["findings"].append({
                            "id": finding.id,
                            "title": finding.title,
                            "severity": finding.severity.value,
                            "asset": port_service.asset.value if port_service.asset else None,
                            "port": port_service.port
                        })
        
        db.commit()
        return summary
    
    def _matches_rule(self, port_service: PortService, rule: PortFindingRule) -> bool:
        """Check if port service matches a finding rule."""
        # Check port
        if port_service.port not in rule.ports:
            return False
        
        # Check state
        if port_service.state not in rule.states:
            return False
        
        return True
    
    def _find_existing(
        self,
        db: Session,
        port_service: PortService,
        rule: PortFindingRule
    ) -> Optional[Vulnerability]:
        """Find existing open finding for this port/rule combination."""
        # Build a unique identifier for the finding - match on port number in title
        # This is more reliable than JSON tag matching
        title_pattern = f"%Port {port_service.port}/{port_service.protocol.value}%"
        
        query = db.query(Vulnerability).filter(
            Vulnerability.asset_id == port_service.asset_id,
            Vulnerability.title.like(title_pattern),
            Vulnerability.status.in_([
                VulnerabilityStatus.OPEN,
                VulnerabilityStatus.IN_PROGRESS
            ])
        )
        
        return query.first()
    
    def _create_finding(
        self,
        db: Session,
        port_service: PortService,
        rule: PortFindingRule,
        scan_id: Optional[int] = None
    ) -> Vulnerability:
        """Create a finding from a port and rule."""
        # OT/ICS device identity, when the OT NSE scripts fingerprinted the device.
        ot_device = (port_service.metadata_ or {}).get("ot_device") if port_service.metadata_ else None
        ot_name = ot_device.get("display_name") if isinstance(ot_device, dict) else None

        # Build title with port info (and device identity when known)
        title = f"[Port {port_service.port}/{port_service.protocol.value}] {rule.title}"
        if ot_name:
            title += f" — {ot_name}"

        # Build description with context
        description = rule.description
        if isinstance(ot_device, dict) and ot_name:
            description += f"\n\n**Identified device:** {ot_name}"
            detail_lines = [
                ("Vendor", ot_device.get("vendor")),
                ("Model", ot_device.get("product")),
                ("Device type", ot_device.get("device_type")),
                ("Firmware/Revision", ot_device.get("revision")),
                ("Serial", ot_device.get("serial")),
            ]
            for label, value in detail_lines:
                if value:
                    description += f"\n- {label}: {value}"
        
        # Include IP address where port was found (important for domain assets)
        if port_service.scanned_ip:
            description += f"\n\n**Found at IP:** {port_service.scanned_ip}"
        
        if port_service.service_name:
            description += f"\n\nDetected service: {port_service.service_name}"
        if port_service.service_product:
            description += f" ({port_service.service_product}"
            if port_service.service_version:
                description += f" {port_service.service_version}"
            description += ")"
        if port_service.banner:
            description += f"\n\nBanner: {port_service.banner[:500]}"
        
        # Build evidence with IP information
        evidence_parts = [f"Port {port_service.port}/{port_service.protocol.value} is in {port_service.state.value} state"]
        if port_service.scanned_ip:
            evidence_parts.append(f"Detected on IP: {port_service.scanned_ip}")
        if port_service.asset:
            evidence_parts.append(f"Asset: {port_service.asset.value}")
        evidence = ". ".join(evidence_parts)
        
        # Build metadata including IP
        metadata = {
            "port": port_service.port,
            "protocol": port_service.protocol.value,
            "state": port_service.state.value,
            "service": port_service.service_name,
            "product": port_service.service_product,
            "version": port_service.service_version,
            "discovered_by": port_service.discovered_by
        }
        if port_service.scanned_ip:
            metadata["scanned_ip"] = port_service.scanned_ip

        # Tags and extra identity metadata for OT devices.
        tags = rule.tags + [f"port:{port_service.port}"]
        if isinstance(ot_device, dict):
            metadata["ot_device"] = ot_device
            if ot_name:
                evidence += f". Device: {ot_name}"
            new_tags = ["ot-device", "ics"]
            vendor = ot_device.get("vendor")
            if vendor:
                import re as _re
                new_tags.append("vendor:" + _re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-"))
            for tag in new_tags:
                if tag not in tags:
                    tags.append(tag)

        # Create finding
        finding = Vulnerability(
            title=title,
            description=description,
            severity=rule.severity,
            asset_id=port_service.asset_id,
            scan_id=scan_id,
            detected_by="port_scanner",
            status=VulnerabilityStatus.OPEN,
            cwe_id=rule.cwe_id,
            remediation=rule.remediation,
            tags=tags,
            evidence=evidence,
            metadata_=metadata
        )
        
        db.add(finding)
        db.flush()
        
        logger.info(f"Created finding: {title} for asset {port_service.asset_id}")
        
        return finding
    
    def get_risk_summary(self, db: Session, organization_id: int) -> dict:
        """
        Get a summary of port-based risks for an organization.
        
        Returns:
            Risk summary with counts and recommendations
        """
        from sqlalchemy import func
        
        # Get all ports for org
        ports = db.query(PortService).join(Asset).filter(
            Asset.organization_id == organization_id,
            PortService.state.in_([PortState.OPEN, PortState.OPEN_FILTERED])
        ).all()
        
        # Categorize risks
        critical_ports = []
        high_risk_ports = []
        medium_risk_ports = []
        
        for port in ports:
            for rule in self.rules:
                if port.port in rule.ports and port.state in rule.states:
                    entry = {
                        "port": port.port,
                        "protocol": port.protocol.value,
                        "asset": port.asset.value if port.asset else None,
                        "service": port.service_name,
                        "issue": rule.title
                    }
                    
                    if rule.severity == Severity.CRITICAL:
                        critical_ports.append(entry)
                    elif rule.severity == Severity.HIGH:
                        high_risk_ports.append(entry)
                    elif rule.severity == Severity.MEDIUM:
                        medium_risk_ports.append(entry)
                    break
        
        return {
            "total_open_ports": len(ports),
            "critical_exposures": len(critical_ports),
            "high_risk_exposures": len(high_risk_ports),
            "medium_risk_exposures": len(medium_risk_ports),
            "critical_ports": critical_ports[:20],  # Limit for response size
            "high_risk_ports": high_risk_ports[:20],
            "recommendations": self._generate_recommendations(critical_ports, high_risk_ports)
        }
    
    def _generate_recommendations(
        self,
        critical: List[dict],
        high: List[dict]
    ) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Check for specific critical issues
        ports_found = set()
        for entry in critical + high:
            ports_found.add(entry["port"])
        
        if 445 in ports_found:
            recommendations.append("CRITICAL: Block SMB (port 445) at the perimeter immediately - ransomware vector")
        
        if 3389 in ports_found:
            recommendations.append("CRITICAL: Remove RDP (port 3389) from internet exposure - use VPN instead")
        
        if any(p in ports_found for p in [3306, 5432, 1433, 27017, 6379]):
            recommendations.append("CRITICAL: Database ports exposed to internet - restrict to application servers only")
        
        if 2375 in ports_found or 2376 in ports_found:
            recommendations.append("CRITICAL: Docker API exposed - this allows complete host takeover")
        
        if 23 in ports_found:
            recommendations.append("CRITICAL: Telnet is deprecated - replace with SSH immediately")
        
        if not recommendations:
            if critical:
                recommendations.append("Review and remediate critical port exposures")
            elif high:
                recommendations.append("Review high-risk port exposures and implement access controls")
            else:
                recommendations.append("No critical port exposures detected")
        
        return recommendations

















