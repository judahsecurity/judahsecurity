"""
Scan Configuration model for managing port lists and scan settings.

Allows easy management of:
- Custom port lists (critical, quick, full, custom)
- Service definitions
- Rate limiting defaults
- Scan profiles
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
from datetime import datetime

from app.db.database import Base


class ScanConfig(Base):
    """
    Model for storing scan configuration including custom port lists.
    
    Types:
    - port_list: Custom port lists for scanning
    - service_def: Service name to port mappings
    - scan_profile: Pre-configured scan profiles
    - global_setting: Global scan settings
    """
    __tablename__ = "scan_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Configuration identification
    config_type = Column(String(50), nullable=False, index=True)
    # Types: "port_list", "service_def", "scan_profile", "global_setting"
    
    name = Column(String(100), nullable=False, index=True)
    # e.g., "critical_ports", "web_ports", "database_ports"
    
    description = Column(Text, nullable=True)
    
    # The actual configuration data
    config = Column(JSON, nullable=False)
    # For port_list: {"ports": [22, 80, 443], "categories": {"databases": [3306, 5432]}}
    # For service_def: {"22": "ssh", "80": "http"}
    # For scan_profile: {"rate": 1000, "timeout": 30, "ports": "critical"}
    
    # Flags
    is_default = Column(Boolean, default=False)  # System default, don't delete
    is_active = Column(Boolean, default=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<ScanConfig {self.config_type}/{self.name}>"
    
    @classmethod
    def get_port_list(cls, db, name: str) -> list:
        """Get ports from a named port list."""
        config = db.query(cls).filter(
            cls.config_type == "port_list",
            cls.name == name,
            cls.is_active == True
        ).first()
        
        if config and config.config:
            return config.config.get("ports", [])
        return []
    
    @classmethod
    def get_port_string(cls, db, name: str) -> str:
        """Get ports as comma-separated string."""
        ports = cls.get_port_list(db, name)
        return ",".join(str(p) for p in ports)


# Default port lists - used to seed the database
DEFAULT_PORT_LISTS = {
    "critical": {
        "description": "Critical infrastructure ports that should never be exposed",
        "categories": {
            "remote_access": [22, 23, 3389, 5900, 5901, 5902, 5903, 512, 513, 514],
            "databases": [3306, 5432, 1433, 1434, 1521, 27017, 27018, 27019, 6379, 9200, 9300, 5984, 11211],
            "file_sharing": [21, 69, 445, 139, 2049],
            "container": [2375, 2376, 6443, 10250, 10255],
            "management": [161, 162, 389, 636, 88],
            "email": [25, 110, 143, 993, 995, 465, 587],
            "web": [80, 443, 8080, 8000, 8443, 8888, 3000],
        }
    },
    "quick": {
        "description": "Quick scan - most common ports",
        "ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443],
    },
    "databases": {
        "description": "Database and cache services",
        "ports": [1433, 1434, 1521, 1830, 3306, 5432, 6379, 9200, 9300, 27017, 27018, 27019, 28017, 5984, 6984, 11211, 9042, 7000, 7001, 7199, 8086, 2181],
    },
    "web": {
        "description": "Web servers and proxies",
        "ports": [80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 3001, 4443, 5000, 5001, 9000, 9090, 9443],
    },
    "remote_access": {
        "description": "Remote access services",
        "ports": [22, 23, 512, 513, 514, 3389, 5900, 5901, 5902, 5903, 5938, 4899, 1494, 2598],
    },
    "mail": {
        "description": "Email services",
        "ports": [25, 110, 143, 465, 587, 993, 995, 106, 2525],
    },
    "file_transfer": {
        "description": "File transfer and sharing",
        "ports": [20, 21, 22, 69, 115, 139, 445, 873, 2049, 548, 631],
    },
    "full": {
        "description": "Comprehensive scan - top 1000+ ports",
        "ports_string": "1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254,255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4443,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157",
    },
}


def seed_default_port_lists(db):
    """Seed the database with default port lists."""
    for name, config in DEFAULT_PORT_LISTS.items():
        existing = db.query(ScanConfig).filter(
            ScanConfig.config_type == "port_list",
            ScanConfig.name == name
        ).first()

        if not existing:
            # Flatten categories into ports list if present
            if "categories" in config:
                ports = []
                for category_ports in config["categories"].values():
                    ports.extend(category_ports)
                config["ports"] = sorted(set(ports))

            scan_config = ScanConfig(
                config_type="port_list",
                name=name,
                description=config.get("description", ""),
                config=config,
                is_default=True,
                is_active=True,
                created_by="system"
            )
            db.add(scan_config)

    db.commit()


# ==================== NMAP SCAN CONFIGURATION CATALOG ====================
#
# Reference data for the custom nmap scan configuration picker. The scan
# technique allowlist lives with the scanner service (the single source of
# truth for what is actually safe to run); everything else that the picker
# needs to render is defined here.

# Timing templates (nmap -T0 .. -T5).
NMAP_TIMING_TEMPLATES = [
    {"value": 0, "label": "T0 — Paranoid", "description": "Very slow; evades intrusion detection"},
    {"value": 1, "label": "T1 — Sneaky", "description": "Slow; light IDS evasion"},
    {"value": 2, "label": "T2 — Polite", "description": "Slows down to use less bandwidth"},
    {"value": 3, "label": "T3 — Normal", "description": "Nmap default timing"},
    {"value": 4, "label": "T4 — Aggressive", "description": "Fast; assumes a reliable network (recommended)"},
    {"value": 5, "label": "T5 — Insane", "description": "Fastest; may sacrifice accuracy"},
]

# NSE scripts grouped for the picker. Categories are always safe to request
# (nmap resolves them itself); individual scripts are filtered against what is
# installed on the scanner host at run time.
NMAP_NSE_CATALOG = [
    {
        "group": "Categories",
        "scripts": [
            {"value": "default", "label": "default", "description": "Nmap's default (-sC) script set"},
            {"value": "safe", "label": "safe", "description": "Non-intrusive scripts only"},
            {"value": "discovery", "label": "discovery", "description": "Host/service discovery"},
            {"value": "version", "label": "version", "description": "Assist version detection"},
            {"value": "vuln", "label": "vuln", "description": "Known-vulnerability checks"},
            {"value": "auth", "label": "auth", "description": "Authentication-related checks"},
        ],
    },
    {
        "group": "Web / TLS",
        "scripts": [
            {"value": "http-title", "label": "http-title", "description": "Grab page titles"},
            {"value": "http-headers", "label": "http-headers", "description": "Dump HTTP response headers"},
            {"value": "http-methods", "label": "http-methods", "description": "Enumerate allowed HTTP methods"},
            {"value": "ssl-cert", "label": "ssl-cert", "description": "Retrieve TLS certificate details"},
            {"value": "ssl-enum-ciphers", "label": "ssl-enum-ciphers", "description": "Enumerate supported TLS ciphers"},
        ],
    },
    {
        "group": "Infrastructure",
        "scripts": [
            {"value": "banner", "label": "banner", "description": "Grab service banners"},
            {"value": "ssh-auth-methods", "label": "ssh-auth-methods", "description": "SSH authentication methods"},
            {"value": "smb-os-discovery", "label": "smb-os-discovery", "description": "OS info over SMB"},
            {"value": "dns-recursion", "label": "dns-recursion", "description": "Check for open DNS recursion"},
            {"value": "ftp-anon", "label": "ftp-anon", "description": "Check for anonymous FTP"},
        ],
    },
]

# Pre-built nmap scan profiles seeded for every deployment. These give users a
# working starting point they can clone/tweak in the picker.
DEFAULT_NMAP_PROFILES = {
    "nmap-quick-tcp": {
        "description": "Fast TCP connect scan of common ports with service detection",
        "config": {
            "scanner": "nmap",
            "nmap_scan_type": "-sT",
            "timing": 4,
            "service_detection": True,
            "os_detection": False,
            "nse_scripts": [],
            "ports": "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443",
        },
    },
    "nmap-service-fingerprint": {
        "description": "Service/version fingerprint with default NSE scripts",
        "config": {
            "scanner": "nmap",
            "nmap_scan_type": "-sT",
            "timing": 4,
            "service_detection": True,
            "os_detection": False,
            "nse_scripts": ["default", "banner"],
            "ports": None,
        },
    },
    "nmap-web-tls": {
        "description": "Web + TLS inspection on common web ports",
        "config": {
            "scanner": "nmap",
            "nmap_scan_type": "-sT",
            "timing": 4,
            "service_detection": True,
            "os_detection": False,
            "nse_scripts": ["http-title", "http-headers", "ssl-cert", "ssl-enum-ciphers"],
            "ports": "80,443,8080,8443,8000,8888,3000",
        },
    },
    "nmap-vuln-sweep": {
        "description": "Version detection plus the NSE vuln category (intrusive)",
        "config": {
            "scanner": "nmap",
            "nmap_scan_type": "-sT",
            "timing": 4,
            "service_detection": True,
            "os_detection": False,
            "nse_scripts": ["vuln"],
            "ports": None,
        },
    },
}


def seed_default_nmap_profiles(db):
    """Seed the database with default nmap scan profiles."""
    for name, profile in DEFAULT_NMAP_PROFILES.items():
        existing = db.query(ScanConfig).filter(
            ScanConfig.config_type == "scan_profile",
            ScanConfig.name == name
        ).first()

        if not existing:
            scan_config = ScanConfig(
                config_type="scan_profile",
                name=name,
                description=profile.get("description", ""),
                config=profile["config"],
                is_default=True,
                is_active=True,
                created_by="system"
            )
            db.add(scan_config)

    db.commit()

