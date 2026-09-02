"""
Device Type Inference Service.

Infers device type, operating system, and classification based on discovered
ports, services, and banners.
"""

import logging
import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.port_service import PortService, PortState

logger = logging.getLogger(__name__)


@dataclass
class DeviceInference:
    """Results from device type inference."""
    system_type: Optional[str] = None
    operating_system: Optional[str] = None
    device_class: Optional[str] = None
    device_subclass: Optional[str] = None
    confidence: int = 0  # 0-100
    evidence: List[str] = None
    ot_device: Optional[dict] = None  # Full OT/ICS identity record, when available

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


# Port-based device indicators
PORT_INDICATORS = {
    # Windows indicators
    3389: {"os": "Windows", "type": "Windows Server", "class": "Server", "confidence": 80},
    445: {"os": "Windows", "type": None, "class": None, "confidence": 40},  # Could be Samba
    135: {"os": "Windows", "type": None, "class": None, "confidence": 50},
    139: {"os": "Windows", "type": None, "class": None, "confidence": 40},
    5985: {"os": "Windows", "type": "Windows Server", "class": "Server", "confidence": 70},  # WinRM
    5986: {"os": "Windows", "type": "Windows Server", "class": "Server", "confidence": 70},  # WinRM HTTPS
    
    # Linux/Unix indicators
    22: {"os": "Linux/Unix", "type": None, "class": None, "confidence": 30},  # Could be anything
    
    # Network infrastructure
    161: {"os": None, "type": "Network Device", "class": "Network Infrastructure", "confidence": 60},  # SNMP
    179: {"os": None, "type": "Router", "class": "Network Infrastructure", "confidence": 85},  # BGP
    1812: {"os": None, "type": "RADIUS Server", "class": "Security Infrastructure", "confidence": 80},
    1813: {"os": None, "type": "RADIUS Server", "class": "Security Infrastructure", "confidence": 80},
    
    # Firewalls
    4443: {"os": None, "type": "Firewall", "class": "Network Infrastructure", "subclass": "Firewall/Next-Gen Firewall", "confidence": 60},
    
    # Databases
    3306: {"os": None, "type": "Database Server", "class": "Server", "subclass": "MySQL Database", "confidence": 85},
    5432: {"os": None, "type": "Database Server", "class": "Server", "subclass": "PostgreSQL Database", "confidence": 85},
    1433: {"os": "Windows", "type": "Database Server", "class": "Server", "subclass": "Microsoft SQL Server", "confidence": 85},
    1521: {"os": None, "type": "Database Server", "class": "Server", "subclass": "Oracle Database", "confidence": 85},
    27017: {"os": None, "type": "Database Server", "class": "Server", "subclass": "MongoDB", "confidence": 85},
    6379: {"os": None, "type": "Cache Server", "class": "Server", "subclass": "Redis", "confidence": 85},
    
    # Web servers
    80: {"os": None, "type": "Web Server", "class": "Server", "confidence": 50},
    443: {"os": None, "type": "Web Server", "class": "Server", "confidence": 50},
    8080: {"os": None, "type": "Web Server", "class": "Server", "confidence": 40},
    8443: {"os": None, "type": "Web Server", "class": "Server", "confidence": 40},
    
    # Mail servers
    25: {"os": None, "type": "Mail Server", "class": "Server", "subclass": "SMTP Server", "confidence": 75},
    110: {"os": None, "type": "Mail Server", "class": "Server", "subclass": "POP3 Server", "confidence": 75},
    143: {"os": None, "type": "Mail Server", "class": "Server", "subclass": "IMAP Server", "confidence": 75},
    587: {"os": None, "type": "Mail Server", "class": "Server", "subclass": "SMTP Submission", "confidence": 75},
    993: {"os": None, "type": "Mail Server", "class": "Server", "subclass": "IMAP SSL", "confidence": 75},
    995: {"os": None, "type": "Mail Server", "class": "Server", "subclass": "POP3 SSL", "confidence": 75},
    
    # Printers
    9100: {"os": None, "type": "Printer", "class": "IoT/Peripheral", "confidence": 80},
    515: {"os": None, "type": "Printer", "class": "IoT/Peripheral", "confidence": 70},
    631: {"os": None, "type": "Printer", "class": "IoT/Peripheral", "subclass": "CUPS Printer", "confidence": 80},
    
    # VoIP/Telephony
    5060: {"os": None, "type": "VoIP System", "class": "Telephony", "subclass": "SIP Server", "confidence": 85},
    5061: {"os": None, "type": "VoIP System", "class": "Telephony", "subclass": "SIP TLS", "confidence": 85},
    
    # IoT/Embedded
    1883: {"os": None, "type": "IoT Device", "class": "IoT/Embedded", "subclass": "MQTT Broker", "confidence": 80},
    8883: {"os": None, "type": "IoT Device", "class": "IoT/Embedded", "subclass": "MQTT SSL", "confidence": 80},
    
    # Management interfaces
    10000: {"os": None, "type": "Management Console", "class": "Server", "subclass": "Webmin", "confidence": 80},
    2082: {"os": None, "type": "Web Hosting Panel", "class": "Server", "subclass": "cPanel", "confidence": 85},
    2083: {"os": None, "type": "Web Hosting Panel", "class": "Server", "subclass": "cPanel SSL", "confidence": 85},
    
    # Docker/Containers
    2375: {"os": None, "type": "Container Host", "class": "Server", "subclass": "Docker API", "confidence": 90},
    2376: {"os": None, "type": "Container Host", "class": "Server", "subclass": "Docker TLS", "confidence": 90},
    6443: {"os": None, "type": "Container Orchestrator", "class": "Server", "subclass": "Kubernetes API", "confidence": 90},
}


# Banner patterns for OS/device detection
BANNER_PATTERNS = [
    # Windows
    (r"Microsoft", "Windows", None, "Server", 70),
    (r"Windows", "Windows", None, "Server", 70),
    (r"Microsoft-IIS", "Windows", "Web Server", "Server", 85),
    (r"Microsoft-HTTPAPI", "Windows", "Windows Server", "Server", 80),
    
    # Linux distributions
    (r"Ubuntu", "Ubuntu Linux", None, "Server", 85),
    (r"Debian", "Debian Linux", None, "Server", 85),
    (r"CentOS", "CentOS Linux", None, "Server", 85),
    (r"Red Hat|RHEL", "Red Hat Enterprise Linux", None, "Server", 85),
    (r"Fedora", "Fedora Linux", None, "Server", 80),
    (r"Alpine", "Alpine Linux", None, "Server", 80),
    
    # Web servers
    (r"nginx", None, "Web Server", "Server", 75),
    (r"Apache", None, "Web Server", "Server", 75),
    (r"LiteSpeed", None, "Web Server", "Server", 75),
    (r"Caddy", None, "Web Server", "Server", 75),
    
    # Network devices
    (r"Cisco", "Cisco IOS", "Router/Switch", "Network Infrastructure", 90),
    (r"Juniper|JunOS", "JunOS", "Router/Switch", "Network Infrastructure", 90),
    (r"MikroTik|RouterOS", "MikroTik RouterOS", "Router", "Network Infrastructure", 90),
    (r"Ubiquiti|UniFi|EdgeOS", "Ubiquiti", "Network Device", "Network Infrastructure", 90),
    (r"Arista", "Arista EOS", "Switch", "Network Infrastructure", 90),
    (r"FortiOS|Fortinet|FortiGate", "FortiOS", "Firewall", "Network Infrastructure", 95),
    
    # Firewalls
    (r"PAN-OS|Palo Alto", "Palo Alto PAN-OS", "Firewall", "Network Infrastructure", 95),
    (r"Sophos", "Sophos", "Firewall", "Network Infrastructure", 90),
    (r"pfSense", "pfSense", "Firewall", "Network Infrastructure", 90),
    (r"OPNsense", "OPNsense", "Firewall", "Network Infrastructure", 90),
    (r"Checkpoint|Check Point", "Check Point", "Firewall", "Network Infrastructure", 90),
    (r"SonicWall|SonicOS", "SonicWall", "Firewall", "Network Infrastructure", 90),
    (r"WatchGuard", "WatchGuard", "Firewall", "Network Infrastructure", 90),
    
    # Storage/NAS
    (r"Synology", "Synology DSM", "NAS", "Storage", 95),
    (r"QNAP", "QNAP QTS", "NAS", "Storage", 95),
    (r"TrueNAS|FreeNAS", "TrueNAS", "NAS", "Storage", 95),
    (r"NetApp", "NetApp ONTAP", "Storage Array", "Storage", 95),
    (r"EMC|Dell EMC", "Dell EMC", "Storage Array", "Storage", 90),
    
    # Virtualization
    (r"VMware|ESXi", "VMware ESXi", "Hypervisor", "Virtualization", 95),
    (r"Proxmox", "Proxmox VE", "Hypervisor", "Virtualization", 95),
    (r"Hyper-V", "Windows Hyper-V", "Hypervisor", "Virtualization", 90),
    
    # Industrial/SCADA
    (r"Siemens", "Siemens", "Industrial Controller", "Industrial/SCADA", 85),
    (r"Rockwell|Allen-Bradley", "Rockwell", "Industrial Controller", "Industrial/SCADA", 85),
    (r"Schneider|Modicon", "Schneider Electric", "Industrial Controller", "Industrial/SCADA", 85),
    (r"ABB", "ABB", "Industrial Controller", "Industrial/SCADA", 80),
    (r"Honeywell", "Honeywell", "Industrial Controller", "Industrial/SCADA", 80),
    
    # Printers
    (r"HP.*LaserJet|LaserJet", "HP", "Printer", "IoT/Peripheral", 90),
    (r"RICOH|Ricoh", "Ricoh", "Printer", "IoT/Peripheral", 90),
    (r"Canon", None, "Printer", "IoT/Peripheral", 75),
    (r"Xerox", "Xerox", "Printer", "IoT/Peripheral", 90),
    (r"Brother", "Brother", "Printer", "IoT/Peripheral", 85),
    (r"Epson", "Epson", "Printer", "IoT/Peripheral", 85),
    (r"KONICA MINOLTA|Konica", "Konica Minolta", "Printer", "IoT/Peripheral", 90),
    
    # Cameras/DVR
    (r"Hikvision", "Hikvision", "IP Camera", "IoT/Security", 95),
    (r"Dahua", "Dahua", "IP Camera", "IoT/Security", 95),
    (r"Axis", "Axis", "IP Camera", "IoT/Security", 90),
    (r"Foscam", "Foscam", "IP Camera", "IoT/Security", 90),
]


class DeviceInferenceService:
    """
    Service for inferring device type from ports, services, and banners.
    """
    
    def infer_from_asset(self, asset: Asset) -> DeviceInference:
        """
        Infer device type from an asset's port services.
        
        Args:
            asset: Asset with port_services relationship loaded
            
        Returns:
            DeviceInference with detected characteristics
        """
        result = DeviceInference()
        
        if not asset.port_services:
            return result
        
        # Collect evidence from all ports
        port_evidence = []
        banner_evidence = []
        ot_evidence = []
        best_ot_device = None  # highest-confidence OT identity record on the asset

        for port_service in asset.port_services:
            if port_service.state not in [PortState.OPEN, PortState.OPEN_FILTERED]:
                continue

            # Structured OT/ICS device identity (from OT NSE scripts) is the
            # most specific evidence available — it names the exact controller.
            ot_device = (port_service.metadata_ or {}).get("ot_device")
            if isinstance(ot_device, dict):
                # System Type should stay short (asset.system_type is String(100)),
                # so use "<vendor> <model>" rather than the family-suffixed label.
                vendor = ot_device.get("vendor")
                product = ot_device.get("product")
                system_type = " ".join(p for p in (vendor, product) if p).strip()
                system_type = system_type or ot_device.get("display_name") or ot_device.get("device_type")
                if system_type:
                    confidence = int(ot_device.get("confidence") or 90)
                    revision = ot_device.get("revision")
                    ot_evidence.append({
                        "port": port_service.port,
                        "type": system_type[:100],
                        "os": f"Firmware {revision}" if revision else None,
                        "class": "Industrial/SCADA",
                        "subclass": (ot_device.get("family") or ot_device.get("device_type") or "")[:200] or None,
                        "confidence": confidence,
                        "source": f"OT identity ({ot_device.get('source', 'nse')})",
                    })
                    if best_ot_device is None or confidence > int(best_ot_device.get("confidence") or 0):
                        best_ot_device = ot_device

            # Check port-based indicators
            if port_service.port in PORT_INDICATORS:
                indicator = PORT_INDICATORS[port_service.port]
                port_evidence.append({
                    "port": port_service.port,
                    "service": port_service.service_name,
                    **indicator
                })
            
            # Check banner patterns
            texts_to_check = [
                port_service.banner or "",
                port_service.service_product or "",
                port_service.service_extra_info or "",
            ]
            combined_text = " ".join(texts_to_check)
            
            for pattern, os_hint, type_hint, class_hint, confidence in BANNER_PATTERNS:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    banner_evidence.append({
                        "port": port_service.port,
                        "match": pattern,
                        "os": os_hint,
                        "type": type_hint,
                        "class": class_hint,
                        "confidence": confidence,
                        "source": combined_text[:100]
                    })
        
        # Aggregate and determine best inference
        result = self._aggregate_evidence(port_evidence, banner_evidence, ot_evidence)
        result.ot_device = best_ot_device

        return result

    def _aggregate_evidence(
        self,
        port_evidence: List[dict],
        banner_evidence: List[dict],
        ot_evidence: Optional[List[dict]] = None,
    ) -> DeviceInference:
        """Aggregate evidence to determine best device inference."""
        result = DeviceInference()

        # Priority: OT identity > banner evidence > port evidence (most specific first)
        all_evidence = []

        for ev in (ot_evidence or []):
            all_evidence.append({
                "source": "ot-identity",
                "confidence": ev["confidence"],
                "os": ev.get("os"),
                "type": ev.get("type"),
                "class": ev.get("class"),
                "subclass": ev.get("subclass"),
                "description": f"Port {ev['port']}: {ev.get('source', 'OT identity')} -> {ev.get('type')}",
            })

        for ev in banner_evidence:
            all_evidence.append({
                "source": "banner",
                "confidence": ev["confidence"],
                "os": ev.get("os"),
                "type": ev.get("type"),
                "class": ev.get("class"),
                "description": f"Port {ev['port']}: matched pattern '{ev['match']}'"
            })
        
        for ev in port_evidence:
            all_evidence.append({
                "source": "port",
                "confidence": ev["confidence"],
                "os": ev.get("os"),
                "type": ev.get("type"),
                "class": ev.get("class"),
                "subclass": ev.get("subclass"),
                "description": f"Port {ev['port']} ({ev.get('service', 'unknown')})"
            })
        
        if not all_evidence:
            return result
        
        # Sort by confidence (descending)
        all_evidence.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Use highest confidence evidence
        best = all_evidence[0]
        result.confidence = best["confidence"]
        result.evidence = [e["description"] for e in all_evidence[:5]]
        
        # Set values from best evidence, with fallback to other evidence
        for ev in all_evidence:
            if ev.get("os") and not result.operating_system:
                result.operating_system = ev["os"]
            if ev.get("type") and not result.system_type:
                result.system_type = ev["type"]
            if ev.get("class") and not result.device_class:
                result.device_class = ev["class"]
            if ev.get("subclass") and not result.device_subclass:
                result.device_subclass = ev["subclass"]
        
        return result
    
    def update_asset_device_info(
        self,
        db: Session,
        asset: Asset
    ) -> DeviceInference:
        """
        Infer device type and update asset.
        
        Args:
            db: Database session
            asset: Asset to update
            
        Returns:
            DeviceInference results
        """
        inference = self.infer_from_asset(asset)

        # High-confidence OT/ICS identity is specific enough to override an
        # earlier generic guess (e.g. "Web Server" from an exposed device UI).
        ot_override = (
            inference.confidence >= 90
            and inference.device_class == "Industrial/SCADA"
        )

        if inference.confidence > 50:
            if inference.system_type and (not asset.system_type or ot_override):
                asset.system_type = inference.system_type[:100]
                logger.info(f"Set system_type for {asset.value}: {inference.system_type}")

            if inference.operating_system and (not asset.operating_system or ot_override):
                asset.operating_system = inference.operating_system[:200]
                logger.info(f"Set operating_system for {asset.value}: {inference.operating_system}")

            if inference.device_class and (not asset.device_class or ot_override):
                asset.device_class = inference.device_class[:100]
                logger.info(f"Set device_class for {asset.value}: {inference.device_class}")

            if inference.device_subclass and (not asset.device_subclass or ot_override):
                asset.device_subclass = inference.device_subclass[:200]

        # Persist the full OT/ICS identity onto the asset so it is queryable and
        # available to the UI beyond the truncated classification columns.
        if inference.ot_device:
            try:
                meta = dict(asset.metadata_ or {})
                meta["ot_device"] = inference.ot_device
                asset.metadata_ = meta
            except Exception as e:
                logger.debug(f"Failed to store ot_device metadata for {asset.value}: {e}")

        return inference


def get_device_inference_service() -> DeviceInferenceService:
    """Get device inference service instance."""
    return DeviceInferenceService()
