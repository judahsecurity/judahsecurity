"""Scan Schedule model for continuous monitoring."""

import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class ScheduleFrequency(str, enum.Enum):
    """Frequency for scheduled scans."""
    EVERY_15_MINUTES = "every_15_minutes"
    EVERY_30_MINUTES = "every_30_minutes"
    HOURLY = "hourly"
    EVERY_2_HOURS = "every_2_hours"
    EVERY_4_HOURS = "every_4_hours"
    EVERY_6_HOURS = "every_6_hours"
    EVERY_12_HOURS = "every_12_hours"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


class ScanSchedule(Base):
    """Model for scheduling automated scans."""
    
    __tablename__ = "scan_schedules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Organization
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    organization = relationship("Organization", backref="scan_schedules")
    
    # Scan configuration
    scan_type = Column(String(50), nullable=False)  # nuclei, port_scan, discovery, masscan
    targets = Column(JSON, default=list)  # Static list of targets
    label_ids = Column(JSON, default=list)  # Labels to use for dynamic targeting
    match_all_labels = Column(Boolean, default=False)
    config = Column(JSON, default=dict)  # Additional scan configuration
    
    # Schedule settings
    frequency = Column(Enum(ScheduleFrequency), default=ScheduleFrequency.DAILY)
    cron_expression = Column(String(100), nullable=True)  # For custom schedules
    run_at_hour = Column(Integer, default=2)  # Hour of day (0-23) for daily/weekly/monthly
    run_on_day = Column(Integer, nullable=True)  # Day of week (0-6) for weekly, day of month (1-31) for monthly
    timezone = Column(String(50), default="UTC")
    
    # State
    is_enabled = Column(Boolean, default=True, index=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    run_count = Column(Integer, default=0)
    
    # Error tracking
    consecutive_failures = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    # Notifications
    notify_on_completion = Column(Boolean, default=False)
    notify_on_findings = Column(Boolean, default=True)
    notification_emails = Column(JSON, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<ScanSchedule(id={self.id}, name='{self.name}', freq={self.frequency.value})>"
    
    def calculate_next_run(self):
        """Calculate the next run time based on frequency."""
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        
        if self.frequency == ScheduleFrequency.EVERY_15_MINUTES:
            # Next 15-minute mark
            minutes = (now.minute // 15 + 1) * 15
            if minutes >= 60:
                next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            else:
                next_run = now.replace(minute=minutes, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_30_MINUTES:
            # Next 30-minute mark
            if now.minute < 30:
                next_run = now.replace(minute=30, second=0, microsecond=0)
            else:
                next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif self.frequency == ScheduleFrequency.HOURLY:
            next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif self.frequency == ScheduleFrequency.EVERY_2_HOURS:
            next_hour = ((now.hour // 2) + 1) * 2
            if next_hour >= 24:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            else:
                next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_4_HOURS:
            next_hour = ((now.hour // 4) + 1) * 4
            if next_hour >= 24:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            else:
                next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_6_HOURS:
            next_hour = ((now.hour // 6) + 1) * 6
            if next_hour >= 24:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            else:
                next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_12_HOURS:
            if now.hour < 12:
                next_run = now.replace(hour=12, minute=0, second=0, microsecond=0)
            else:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        elif self.frequency == ScheduleFrequency.DAILY:
            next_run = now.replace(hour=self.run_at_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
        elif self.frequency == ScheduleFrequency.WEEKLY:
            # Find next occurrence of the target day
            days_ahead = (self.run_on_day or 0) - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            next_run = now.replace(hour=self.run_at_hour, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)
        elif self.frequency == ScheduleFrequency.MONTHLY:
            # Next month on the specified day
            next_run = now.replace(day=min(self.run_on_day or 1, 28), hour=self.run_at_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                if now.month == 12:
                    next_run = next_run.replace(year=now.year + 1, month=1)
                else:
                    next_run = next_run.replace(month=now.month + 1)
        else:
            # Custom - calculate from cron
            next_run = now + timedelta(hours=1)  # Fallback
        
        return next_run


# Critical ports that should be monitored for exposure
CRITICAL_PORTS = {
    # Remote Access - High value targets
    "remote_access": [22, 23, 3389, 5900, 5901, 5902, 5903, 512, 513, 514],
    # Databases - Data exposure risk
    "databases": [3306, 5432, 1433, 1434, 1521, 27017, 27018, 6379, 9200, 9300, 5984, 11211],
    # File Sharing - Ransomware vectors
    "file_sharing": [21, 69, 445, 139, 2049],
    # Container/Orchestration - Host takeover
    "container": [2375, 2376, 6443, 10250],
    # Management
    "management": [161, 162, 389, 636, 88],
    # Email
    "email": [25, 110, 143],
    # Web (for service detection)
    "web": [80, 443, 8080, 8000, 8443, 8888, 3000],
}

# ICS/OT/SCADA ports for industrial control system monitoring
ICS_OT_PORTS = {
    # PLC Protocols - Direct control of industrial equipment
    "plc_protocols": [
        102,    # Siemens S7comm (ISO-TSAP) - Stuxnet targeted
        502,    # Modbus/TCP - Most common ICS protocol
        44818,  # EtherNet/IP (Rockwell/Allen-Bradley)
        2222,   # EtherNet/IP I/O implicit messaging
        9600,   # OMRON FINS
        5007,   # Mitsubishi MELSEC-Q
        18245, 18246,  # GE SRTP
        2455,   # Codesys
    ],
    # SCADA/Utilities - Critical infrastructure
    "scada_utilities": [
        20000,  # DNP3 - Used in power grids, water systems
        2404,   # IEC 60870-5-104 - Power grid telecontrol
        4000,   # Emerson ROC - Oil & gas pipelines
        4911,   # Niagara Fox/Tridium - Smart grid
    ],
    # Building Automation - HVAC, access control
    "building_automation": [
        47808,  # BACnet - Building automation
        1911, 1962,  # Niagara Fox - Building management
        789,    # Red Lion Crimson - HMI
    ],
    # Industrial Automation
    "industrial_automation": [
        4840,   # OPC UA - Industrial data exchange
        1089, 1090, 1091,  # Foundation Fieldbus HSE
        5094, 5095,  # HART-IP - Field devices
        34962, 34963, 34964,  # PROFINET
        2000,   # MMS (Manufacturing Message Specification)
    ],
    # HMI/SCADA Servers
    "hmi_scada_servers": [
        1433,   # Historian databases (SQL Server)
        4712,   # ABB TDC
        5450,   # OSIsoft PI
        11234,  # Inductive Automation Ignition
        8088,   # Ignition web interface
        62900,  # GE iFIX
        502,    # Modbus gateway (secondary)
    ],
    # Remote Access to OT
    "ot_remote_access": [
        5900, 5901,  # VNC to HMI
        3389,   # RDP to engineering workstations
        22,     # SSH to embedded devices
        23,     # Telnet (legacy ICS)
        4911,   # Niagara
    ],
}

# All ICS/OT ports flattened
ALL_ICS_OT_PORTS = sorted(set(
    port for ports in ICS_OT_PORTS.values() for port in ports
))

# Flatten all critical ports for quick scanning
ALL_CRITICAL_PORTS = sorted(set(
    port for ports in CRITICAL_PORTS.values() for port in ports
))


# Tool-specific scan types for continuous monitoring
CONTINUOUS_SCAN_TYPES = {
    "critical_ports": {
        "name": "Critical Port Monitoring",
        "description": "Monitor for exposed critical ports (databases, remote access, file sharing, containers) using high-speed masscan. Generates security findings for exposed services.",
        "default_config": {
            "ports": ",".join(str(p) for p in ALL_CRITICAL_PORTS),
            "scanner": "masscan",  # Masscan is faster for CIDR blocks
            "rate": 10000,  # 10k packets/sec - fast but safe for most networks
            "service_detection": True,
            "generate_findings": True,
            "alert_on_new": True,
        }
    },
    "masscan": {
        "name": "Masscan Port Scan",
        "description": "High-speed port scanning using masscan",
        "default_config": {
            "rate": 1000,  # packets per second
            "ports": "1-65535",
            "timeout": 5,
        }
    },
    "nuclei": {
        "name": "Nuclei Vulnerability Scan (All Severities)",
        "description": "Full template-based vulnerability scanning - all severity levels. Can take a long time for large targets.",
        "default_config": {
            "severity": ["critical", "high", "medium", "low", "info"],
            "rate_limit": 150,
            "timeout": 10,
        }
    },
    "nuclei_critical": {
        "name": "Nuclei - Critical Only",
        "description": "Fast scan for critical vulnerabilities only. Runs quickly, catches the most severe issues.",
        "default_config": {
            "severity": ["critical"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "daily",
    },
    "nuclei_high": {
        "name": "Nuclei - High Severity",
        "description": "Scan for high severity vulnerabilities. Runs faster than full scan.",
        "default_config": {
            "severity": ["high"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "daily",
    },
    "nuclei_critical_high": {
        "name": "Nuclei - Critical & High",
        "description": "Scan for critical and high severity vulnerabilities. Best balance of speed and coverage.",
        "default_config": {
            "severity": ["critical", "high"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "daily",
    },
    "nuclei_medium": {
        "name": "Nuclei - Medium Severity",
        "description": "Scan for medium severity vulnerabilities.",
        "default_config": {
            "severity": ["medium"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "weekly",
    },
    "nuclei_low_info": {
        "name": "Nuclei - Low & Info",
        "description": "Scan for low severity and informational findings. Slowest but most comprehensive.",
        "default_config": {
            "severity": ["low", "info"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "weekly",
    },
    "port_scan": {
        "name": "Port Service Scan",
        "description": "Detailed port and service enumeration",
        "default_config": {
            "ports": "top1000",
            "version_detection": True,
        }
    },
    "discovery": {
        "name": "Asset Discovery",
        "description": "Subdomain and asset discovery",
        "default_config": {
            "passive": True,
            "active": False,
            "dns_bruteforce": False,
        }
    },
    "screenshot": {
        "name": "Web Screenshot Capture",
        "description": "Capture screenshots of web assets for visual monitoring and change detection. Run daily to track website changes.",
        "default_config": {
            "timeout": 30,
            "viewport_width": 1920,
            "viewport_height": 1080,
            "threads": 5,
        },
        "recommended_frequency": "daily",
    },
    "subdomain_enum": {
        "name": "Subdomain Enumeration",
        "description": "Discover new subdomains using Subfinder. Run daily to find newly created subdomains and expand attack surface visibility.",
        "default_config": {
            "sources": ["all"],
            "recursive": False,
            "timeout": 300,
        },
        "recommended_frequency": "daily",
    },
    "technology": {
        "name": "Technology Detection",
        "description": "Detect web technologies and frameworks using Wappalyzer fingerprinting",
        "default_config": {}
    },
    "whatweb": {
        "name": "WhatWeb Technology Enrichment",
        "description": "Enrich technology detection using WhatWeb CLI (1800+ plugins: CMS, frameworks, servers, versions). Install: gem install whatweb or apt install whatweb. Complements Wappalyzer.",
        "default_config": {"source": "whatweb", "max_hosts": 200},
        "recommended_frequency": "weekly",
    },
    "http_probe": {
        "name": "HTTP Probe",
        "description": "Check which assets are live and responding to HTTP requests. Updates is_live status and discovers web services.",
        "default_config": {
            "timeout": 30,
            "follow_redirects": True,
        },
        "recommended_frequency": "daily",
    },
    "dns_resolution": {
        "name": "DNS Resolution",
        "description": "Resolve domains to IP addresses and enrich with geolocation data. Detects infrastructure changes.",
        "default_config": {
            "include_geo": True,
            "limit": 1000,
        },
        "recommended_frequency": "daily",
    },
    "login_portal": {
        "name": "Login Portal Detection",
        "description": "Detect login pages, admin panels, and authentication endpoints using waybackurls and pattern matching",
        "default_config": {
            "include_subdomains": True,
            "use_wayback": True,
        }
    },
    "full_discovery": {
        "name": "Full Asset Discovery",
        "description": "Complete discovery including subdomains, DNS, HTTP probing, and technology detection",
        "default_config": {
            "passive": True,
            "active": True,
            "dns_bruteforce": False,
        }
    },
    "full": {
        "name": "Full Scan (All)",
        "description": "Complete comprehensive scan: asset discovery, subdomain enumeration, port scanning, technology detection, and vulnerability scanning. Use for thorough assessment of new targets.",
        "default_config": {
            "passive": True,
            "active": True,
            "include_vuln_scan": True,
            "include_port_scan": True,
            "include_tech_detection": True,
        },
        "recommended_frequency": "weekly",
    },
    "web_scan": {
        "name": "Web Application Scan",
        "description": "Comprehensive web application vulnerability scanning using Nuclei. Focuses on web-specific vulnerabilities like XSS, SQLi, SSRF, and misconfigurations.",
        "default_config": {
            "severity": ["critical", "high", "medium"],
            "rate_limit": 150,
            "timeout": 10,
            "tags": ["web", "xss", "sqli", "ssrf", "lfi", "rfi", "rce"],
        },
        "recommended_frequency": "weekly",
    },
    "paramspider": {
        "name": "Parameter Discovery (ParamSpider)",
        "description": "Discover URL parameters from web archives for vulnerability testing. Finds XSS, SQLi, and other injection points. IPs/CIDRs are auto-skipped (archive mining is by hostname), and large surfaces are covered in rotating batches across runs.",
        "default_config": {
            "max_domains": 500,      # domains scanned per run (batch size); rotates across runs for full coverage
            "max_concurrent": 15,    # archive mining is I/O bound, so concurrency is the main speed lever
            "timeout": 120,          # per-domain timeout (seconds)
        },
        "recommended_frequency": "daily",
    },
    "waybackurls": {
        "name": "Historical URL Discovery (WaybackURLs)",
        "description": "Fetch historical URLs from Wayback Machine to find forgotten endpoints, old configs, and sensitive files.",
        "default_config": {
            "include_subdomains": True,
            "timeout_per_domain": 120,
            "max_concurrent": 3,
        },
        "recommended_frequency": "weekly",
    },
    "katana": {
        "name": "Deep Web Crawling (Katana)",
        "description": "Active deep crawling with JS parsing. Discovers endpoints, parameters, JS files, and forms. Stores all findings on assets.",
        "default_config": {
            "depth": 5,
            "js_crawl": True,
            "form_extraction": True,
            "rate_limit": 150,
            "concurrency": 10,
            "timeout": 600,
            "ai_secrets_scan": False,
        },
        "recommended_frequency": "weekly",
    },
    "cleanup": {
        "name": "System Cleanup",
        "description": "Clean up old scan files, temporary files, and orphaned data. Frees disk space and maintains system health.",
        "default_config": {
            "screenshots_retention_days": 90,
            "scan_files_retention_days": 30,
            "temp_files_retention_days": 1,
            "failed_scans_retention_days": 14,
            "dry_run": False,
        },
        "recommended_frequency": "weekly",
    },
    "geo_enrich": {
        "name": "Geolocation Enrichment",
        "description": "Enrich all assets with country, region, and lat/lon coordinates. Uses netblock country data (no API) and IP geolocation APIs. Essential for geographic risk analysis and compliance mapping.",
        "default_config": {
            "max_assets": 10000,
            "force": False,  # Don't re-enrich assets that already have geo data
        },
        "recommended_frequency": "weekly",
    },
    "tldfinder": {
        "name": "TLD/Domain Discovery (tldfinder)",
        "description": "Discover subdomains and domains using ProjectDiscovery tldfinder. Run against org root domain or keywords (e.g. Rockwell Automation). Improves coverage from multiple sources (Wayback, whoisxmlapi, etc.).",
        "default_config": {
            "discovery_mode": "domain",
            "max_time_minutes": 10,
        },
        "recommended_frequency": "weekly",
    },
    
    # ==================== ICS/OT/SCADA SCAN TYPES ====================
    "ics_ot_ports": {
        "name": "ICS/OT Port Monitoring",
        "description": "Monitor for exposed Industrial Control System and Operational Technology ports. Detects PLCs, SCADA systems, building automation, and industrial protocols. Critical for OT security and compliance (NERC CIP, IEC 62443).",
        "default_config": {
            "ports": ",".join(str(p) for p in ALL_ICS_OT_PORTS),
            "scanner": "masscan",
            "rate": 5000,  # Lower rate - OT devices can be fragile
            "service_detection": True,
            "generate_findings": True,
            "alert_on_new": True,
            "finding_category": "ics_ot",
        },
        "recommended_frequency": "daily",
        "tags": ["ics", "ot", "scada", "critical-infrastructure"],
    },
    "ics_plc_scan": {
        "name": "PLC Protocol Detection",
        "description": "Scan for exposed PLC (Programmable Logic Controller) protocols including Modbus, S7comm, EtherNet/IP, FINS, and MELSEC. These should NEVER be exposed to untrusted networks.",
        "default_config": {
            "ports": "102,502,2222,2455,5007,9600,18245,18246,44818",
            "scanner": "nmap",
            "rate": 1000,
            "service_detection": True,
            "nse_scripts": ["modbus-discover", "s7-info", "enip-info", "omron-info"],
            "generate_findings": True,
            "finding_category": "ics_plc",
        },
        "recommended_frequency": "daily",
        "tags": ["ics", "plc", "modbus", "s7", "ethernet-ip"],
    },
    "ics_scada_scan": {
        "name": "SCADA/Utility Protocol Scan",
        "description": "Scan for exposed SCADA and utility protocols like DNP3 and IEC 60870-5-104. Used in power grids, water systems, and oil & gas. Critical infrastructure exposure.",
        "default_config": {
            "ports": "2404,4000,4911,20000",
            "scanner": "nmap",
            "rate": 1000,
            "service_detection": True,
            # dnp3-info is not in stock nmap; iec-identify is official (when package is new enough)
            "nse_scripts": ["iec-identify"],
            "generate_findings": True,
            "finding_category": "ics_scada",
        },
        "recommended_frequency": "daily",
        "tags": ["ics", "scada", "dnp3", "iec104", "utilities", "critical-infrastructure"],
    },
    "ics_building_automation": {
        "name": "Building Automation Scan",
        "description": "Scan for exposed building automation protocols like BACnet, Niagara Fox, and KNX. Controls HVAC, lighting, and physical access systems.",
        "default_config": {
            "ports": "789,1911,1962,47808",
            "scanner": "nmap",
            "rate": 1000,
            "service_detection": True,
            "nse_scripts": ["bacnet-info", "fox-info"],
            "generate_findings": True,
            "finding_category": "ics_building",
        },
        "recommended_frequency": "weekly",
        "tags": ["ics", "bacnet", "building-automation", "hvac"],
    },
    "nuclei_ics": {
        "name": "Nuclei ICS/SCADA Vulnerabilities",
        "description": "Scan for ICS/SCADA specific vulnerabilities using Nuclei ICS templates. Detects vulnerable HMIs, exposed historians, default credentials on industrial devices, and known CVEs.",
        "default_config": {
            "tags": ["ics", "scada", "iot", "plc"],
            "severity": ["critical", "high", "medium"],
            "rate_limit": 50,  # Lower rate for OT devices
            "timeout": 15,
        },
        "recommended_frequency": "weekly",
        "tags": ["ics", "scada", "nuclei", "vulnerability"],
    },
    "ics_full_discovery": {
        "name": "Full ICS/OT Discovery",
        "description": "Comprehensive ICS/OT discovery combining port scanning, protocol detection, and vulnerability assessment. Use for initial OT network assessment or periodic audits.",
        "default_config": {
            "ports": ",".join(str(p) for p in ALL_ICS_OT_PORTS),
            "scanner": "nmap",
            "rate": 500,  # Very conservative for OT networks
            "service_detection": True,
            # Only stock nmap NSE scripts — community scripts (dnp3-info,
            # codesys-v2-discover, opcua-info) abort nmap if missing. Runtime
            # filtering in PortScannerService also skips anything not installed.
            "nse_scripts": [
                "modbus-discover", "s7-info", "enip-info", "bacnet-info",
                "fox-info", "omron-info", "iec-identify",
            ],
            "nuclei_tags": ["ics", "scada"],
            "generate_findings": True,
            "run_nuclei": True,
        },
        "recommended_frequency": "monthly",
        "tags": ["ics", "ot", "scada", "full-discovery", "assessment"],
    },
}




