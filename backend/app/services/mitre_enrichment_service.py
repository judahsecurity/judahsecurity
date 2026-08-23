"""
MITRE ATT&CK Enrichment Service

Enriches vulnerability findings with MITRE ATT&CK framework data,
mapping CWE weaknesses to CAPEC attack patterns and ATT&CK techniques.
"""

import json
import logging
import os
from typing import Optional, List, Dict, Any
from functools import lru_cache

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


# CWE to CAPEC mapping - most common mappings
# Full database at: https://cwe.mitre.org/data/downloads.html
CWE_TO_CAPEC = {
    # Injection vulnerabilities
    "CWE-79": {  # XSS
        "capec_ids": ["CAPEC-86", "CAPEC-198", "CAPEC-199"],
        "attack_techniques": ["T1059.007"],
        "description": "Cross-Site Scripting (XSS)",
        "attack_patterns": [
            "XSS Through HTTP Headers",
            "XSS Using Doubled Characters",
            "XSS Using Alternate Syntax",
        ],
    },
    "CWE-89": {  # SQL Injection
        "capec_ids": ["CAPEC-66", "CAPEC-108", "CAPEC-109", "CAPEC-110"],
        "attack_techniques": ["T1190"],
        "description": "SQL Injection",
        "attack_patterns": [
            "SQL Injection",
            "Command Line Execution through SQL Injection",
            "Object Relational Mapping Injection",
            "SQL Injection through UNION Operator",
        ],
    },
    "CWE-78": {  # OS Command Injection
        "capec_ids": ["CAPEC-88"],
        "attack_techniques": ["T1059"],
        "description": "OS Command Injection",
        "attack_patterns": [
            "OS Command Injection",
        ],
    },
    "CWE-77": {  # Command Injection
        "capec_ids": ["CAPEC-88", "CAPEC-6"],
        "attack_techniques": ["T1059"],
        "description": "Command Injection",
        "attack_patterns": [
            "OS Command Injection",
            "Argument Injection",
        ],
    },
    "CWE-94": {  # Code Injection
        "capec_ids": ["CAPEC-242"],
        "attack_techniques": ["T1055"],
        "description": "Code Injection",
        "attack_patterns": [
            "Code Injection",
        ],
    },
    "CWE-90": {  # LDAP Injection
        "capec_ids": ["CAPEC-136"],
        "attack_techniques": ["T1087"],
        "description": "LDAP Injection",
        "attack_patterns": [
            "LDAP Injection",
        ],
    },
    "CWE-91": {  # XML Injection
        "capec_ids": ["CAPEC-250"],
        "attack_techniques": ["T1059"],
        "description": "XML Injection",
        "attack_patterns": [
            "XML Injection",
        ],
    },
    
    # Authentication vulnerabilities
    "CWE-287": {  # Improper Authentication
        "capec_ids": ["CAPEC-114", "CAPEC-115"],
        "attack_techniques": ["T1078"],
        "description": "Improper Authentication",
        "attack_patterns": [
            "Authentication Abuse",
            "Authentication Bypass",
        ],
    },
    "CWE-306": {  # Missing Authentication
        "capec_ids": ["CAPEC-115"],
        "attack_techniques": ["T1078"],
        "description": "Missing Authentication for Critical Function",
        "attack_patterns": [
            "Authentication Bypass",
        ],
    },
    "CWE-798": {  # Hardcoded Credentials
        "capec_ids": ["CAPEC-70"],
        "attack_techniques": ["T1552.001"],
        "description": "Use of Hard-coded Credentials",
        "attack_patterns": [
            "Try Common Usernames and Passwords",
        ],
    },
    "CWE-259": {  # Hardcoded Password
        "capec_ids": ["CAPEC-70"],
        "attack_techniques": ["T1552.001"],
        "description": "Use of Hard-coded Password",
        "attack_patterns": [
            "Try Common Usernames and Passwords",
        ],
    },
    "CWE-321": {  # Hardcoded Cryptographic Key
        "capec_ids": ["CAPEC-20"],
        "attack_techniques": ["T1552.004"],
        "description": "Use of Hard-coded Cryptographic Key",
        "attack_patterns": [
            "Encryption Brute Forcing",
        ],
    },
    "CWE-307": {  # Improper Restriction of Excessive Authentication Attempts
        "capec_ids": ["CAPEC-49"],
        "attack_techniques": ["T1110"],
        "description": "Improper Restriction of Excessive Authentication Attempts",
        "attack_patterns": [
            "Password Brute Forcing",
        ],
    },
    "CWE-522": {  # Insufficiently Protected Credentials
        "capec_ids": ["CAPEC-49", "CAPEC-50"],
        "attack_techniques": ["T1552"],
        "description": "Insufficiently Protected Credentials",
        "attack_patterns": [
            "Password Brute Forcing",
            "Password Recovery Exploitation",
        ],
    },
    
    # Authorization vulnerabilities
    "CWE-284": {  # Improper Access Control
        "capec_ids": ["CAPEC-122", "CAPEC-1"],
        "attack_techniques": ["T1548"],
        "description": "Improper Access Control",
        "attack_patterns": [
            "Privilege Abuse",
            "Accessing Functionality Not Properly Constrained",
        ],
    },
    "CWE-862": {  # Missing Authorization
        "capec_ids": ["CAPEC-122"],
        "attack_techniques": ["T1548"],
        "description": "Missing Authorization",
        "attack_patterns": [
            "Privilege Abuse",
        ],
    },
    "CWE-863": {  # Incorrect Authorization
        "capec_ids": ["CAPEC-122"],
        "attack_techniques": ["T1548"],
        "description": "Incorrect Authorization",
        "attack_patterns": [
            "Privilege Abuse",
        ],
    },
    "CWE-639": {  # Insecure Direct Object Reference
        "capec_ids": ["CAPEC-122", "CAPEC-1"],
        "attack_techniques": ["T1548"],
        "description": "Insecure Direct Object Reference (IDOR)",
        "attack_patterns": [
            "Privilege Abuse",
            "Accessing Functionality Not Properly Constrained",
        ],
    },
    
    # Cryptographic issues
    "CWE-327": {  # Use of Broken Crypto
        "capec_ids": ["CAPEC-97"],
        "attack_techniques": ["T1600.001"],
        "description": "Use of Broken or Risky Cryptographic Algorithm",
        "attack_patterns": [
            "Cryptanalysis",
        ],
    },
    "CWE-328": {  # Weak Hash
        "capec_ids": ["CAPEC-97"],
        "attack_techniques": ["T1110.002"],
        "description": "Weak Hash Algorithm",
        "attack_patterns": [
            "Cryptanalysis",
        ],
    },
    "CWE-311": {  # Missing Encryption
        "capec_ids": ["CAPEC-157"],
        "attack_techniques": ["T1040"],
        "description": "Missing Encryption of Sensitive Data",
        "attack_patterns": [
            "Sniffing Attacks",
        ],
    },
    "CWE-295": {  # Improper Certificate Validation
        "capec_ids": ["CAPEC-94"],
        "attack_techniques": ["T1557"],
        "description": "Improper Certificate Validation",
        "attack_patterns": [
            "Adversary in the Middle (AitM)",
        ],
    },
    
    # Path traversal
    "CWE-22": {  # Path Traversal
        "capec_ids": ["CAPEC-126", "CAPEC-139"],
        "attack_techniques": ["T1083"],
        "description": "Path Traversal",
        "attack_patterns": [
            "Path Traversal",
            "Directory Indexing",
        ],
    },
    "CWE-23": {  # Relative Path Traversal
        "capec_ids": ["CAPEC-126"],
        "attack_techniques": ["T1083"],
        "description": "Relative Path Traversal",
        "attack_patterns": [
            "Path Traversal",
        ],
    },
    
    # Server-side request forgery
    "CWE-918": {  # SSRF
        "capec_ids": ["CAPEC-664"],
        "attack_techniques": ["T1090"],
        "description": "Server-Side Request Forgery (SSRF)",
        "attack_patterns": [
            "Server Side Request Forgery",
        ],
    },
    
    # Deserialization
    "CWE-502": {  # Deserialization of Untrusted Data
        "capec_ids": ["CAPEC-586"],
        "attack_techniques": ["T1055"],
        "description": "Deserialization of Untrusted Data",
        "attack_patterns": [
            "Object Injection",
        ],
    },
    
    # Memory issues
    "CWE-119": {  # Buffer Overflow
        "capec_ids": ["CAPEC-100"],
        "attack_techniques": ["T1055"],
        "description": "Buffer Overflow",
        "attack_patterns": [
            "Overflow Buffers",
        ],
    },
    "CWE-120": {  # Buffer Copy without Size Check
        "capec_ids": ["CAPEC-100"],
        "attack_techniques": ["T1055"],
        "description": "Buffer Copy without Checking Size of Input",
        "attack_patterns": [
            "Overflow Buffers",
        ],
    },
    "CWE-416": {  # Use After Free
        "capec_ids": ["CAPEC-169"],
        "attack_techniques": ["T1055"],
        "description": "Use After Free",
        "attack_patterns": [
            "Pointer Manipulation",
        ],
    },
    
    # Information exposure
    "CWE-200": {  # Information Exposure
        "capec_ids": ["CAPEC-116", "CAPEC-118"],
        "attack_techniques": ["T1087"],
        "description": "Information Exposure",
        "attack_patterns": [
            "Excavation",
            "Collect and Analyze Information",
        ],
    },
    "CWE-209": {  # Error Message Information Exposure
        "capec_ids": ["CAPEC-118"],
        "attack_techniques": ["T1087"],
        "description": "Error Message Information Exposure",
        "attack_patterns": [
            "Collect and Analyze Information",
        ],
    },
    
    # XXE
    "CWE-611": {  # XXE
        "capec_ids": ["CAPEC-201"],
        "attack_techniques": ["T1059"],
        "description": "XML External Entity (XXE)",
        "attack_patterns": [
            "XML Injection",
        ],
    },
    
    # Open Redirect
    "CWE-601": {  # Open Redirect
        "capec_ids": ["CAPEC-194"],
        "attack_techniques": ["T1189"],
        "description": "URL Redirection to Untrusted Site (Open Redirect)",
        "attack_patterns": [
            "Fake the Source of Data",
        ],
    },
    
    # CSRF
    "CWE-352": {  # CSRF
        "capec_ids": ["CAPEC-62", "CAPEC-111"],
        "attack_techniques": ["T1185"],
        "description": "Cross-Site Request Forgery (CSRF)",
        "attack_patterns": [
            "Cross Site Request Forgery",
            "JSON Hijacking",
        ],
    },
}

# ATT&CK Technique descriptions
ATTACK_TECHNIQUES = {
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade process-based defenses and elevate privileges.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
    },
    "T1059.007": {
        "name": "JavaScript",
        "tactic": "Execution",
        "description": "Adversaries may abuse JavaScript for execution.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Initial Access, Persistence, Privilege Escalation",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses.",
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may use a connection proxy to direct network traffic between systems.",
    },
    "T1110.002": {
        "name": "Password Cracking",
        "tactic": "Credential Access",
        "description": "Adversaries may use password cracking to attempt to recover usable credentials.",
    },
    "T1185": {
        "name": "Browser Session Hijacking",
        "tactic": "Collection",
        "description": "Adversaries may take advantage of security vulnerabilities in browser-based authentication sessions.",
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may gain access through a user visiting a website.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing applications.",
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "Credential Access, Discovery",
        "description": "Adversaries may sniff network traffic to capture information about the environment.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories to discover sensitive information.",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems for insecurely stored credentials.",
    },
    "T1552.001": {
        "name": "Credentials In Files",
        "tactic": "Credential Access",
        "description": "Adversaries may search local file systems for files containing credentials.",
    },
    "T1552.004": {
        "name": "Private Keys",
        "tactic": "Credential Access",
        "description": "Adversaries may search for private key material or hardcoded cryptographic secrets.",
    },
    "T1592.004": {
        "name": "Gather Victim Host Information: Client Configurations",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather client configuration files and publicly exposed application bundles.",
    },
    "T1565.002": {
        "name": "Data Manipulation: Transmitted Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may alter data in transit to bypass integrity controls.",
    },
    "T1595.002": {
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan victims for vulnerabilities that can be used during targeting.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
    },
    "T1550.001": {
        "name": "Application Access Token",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may steal or forge application access tokens to bypass authentication.",
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may use alternate authentication material to bypass typical authentication.",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Collection, Credential Access",
        "description": "Adversaries may attempt to position themselves between two or more networked devices.",
    },
    "T1600.001": {
        "name": "Reduce Key Space",
        "tactic": "Defense Evasion",
        "description": "Adversaries may reduce the level of security implemented by cryptographic protocols.",
    },
}


class MITREEnrichmentService:
    """
    Service for enriching vulnerabilities with MITRE ATT&CK data.
    """
    
    def __init__(self):
        self.enabled = settings.MITRE_ENRICHMENT_ENABLED
    
    def enrich_vulnerability(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """
        Enrich a single vulnerability with MITRE data.
        
        Args:
            vulnerability: Vulnerability to enrich
        
        Returns:
            Dict with MITRE enrichment data
        """
        if not self.enabled:
            return {}
        
        cwe_id = vulnerability.cwe_id
        if not cwe_id:
            return {"enriched": False, "reason": "No CWE ID"}
        
        # Normalize CWE ID format
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        
        # Look up CWE mapping
        mapping = CWE_TO_CAPEC.get(cwe_id)
        if not mapping:
            return {"enriched": False, "reason": f"No mapping for {cwe_id}"}
        
        # Get ATT&CK technique details
        techniques = []
        for tech_id in mapping.get("attack_techniques", []):
            tech_info = ATTACK_TECHNIQUES.get(tech_id, {})
            if tech_info:
                techniques.append({
                    "id": tech_id,
                    "name": tech_info.get("name"),
                    "tactic": tech_info.get("tactic"),
                    "description": tech_info.get("description"),
                })
        
        return {
            "enriched": True,
            "cwe_id": cwe_id,
            "cwe_description": mapping.get("description"),
            "capec_ids": mapping.get("capec_ids", []),
            "attack_patterns": mapping.get("attack_patterns", []),
            "attack_techniques": techniques,
        }
    
    def enrich_and_update(self, vulnerability_id: int) -> Dict[str, Any]:
        """
        Enrich a vulnerability and update its metadata in the database.
        
        Args:
            vulnerability_id: ID of the vulnerability to enrich
        
        Returns:
            Enrichment result
        """
        db = SessionLocal()
        try:
            vuln = db.query(Vulnerability).filter(
                Vulnerability.id == vulnerability_id
            ).first()
            
            if not vuln:
                return {"error": "Vulnerability not found"}
            
            enrichment = self.enrich_vulnerability(vuln)
            
            if enrichment.get("enriched"):
                # Update metadata with MITRE data
                current_metadata = vuln.metadata_ or {}
                current_metadata["mitre"] = {
                    "capec_ids": enrichment.get("capec_ids", []),
                    "attack_patterns": enrichment.get("attack_patterns", []),
                    "attack_techniques": enrichment.get("attack_techniques", []),
                }
                vuln.metadata_ = current_metadata
                db.commit()
            
            return enrichment
        
        except Exception as e:
            logger.error(f"Error enriching vulnerability: {e}")
            db.rollback()
            return {"error": str(e)}
        finally:
            db.close()
    
    def batch_enrich(self, organization_id: int) -> Dict[str, Any]:
        """
        Enrich all vulnerabilities for an organization.
        
        Args:
            organization_id: Organization ID
        
        Returns:
            Summary of enrichment results
        """
        db = SessionLocal()
        try:
            from app.models.asset import Asset
            
            vulns = db.query(Vulnerability).join(Asset).filter(
                Asset.organization_id == organization_id,
                Vulnerability.cwe_id.isnot(None)
            ).all()
            
            enriched_count = 0
            failed_count = 0
            
            for vuln in vulns:
                enrichment = self.enrich_vulnerability(vuln)
                
                if enrichment.get("enriched"):
                    current_metadata = vuln.metadata_ or {}
                    current_metadata["mitre"] = {
                        "capec_ids": enrichment.get("capec_ids", []),
                        "attack_patterns": enrichment.get("attack_patterns", []),
                        "attack_techniques": enrichment.get("attack_techniques", []),
                    }
                    vuln.metadata_ = current_metadata
                    enriched_count += 1
                else:
                    failed_count += 1
            
            db.commit()
            
            return {
                "total": len(vulns),
                "enriched": enriched_count,
                "not_mapped": failed_count,
            }
        
        except Exception as e:
            logger.error(f"Error in batch enrichment: {e}")
            db.rollback()
            return {"error": str(e)}
        finally:
            db.close()
    
    def get_attack_techniques_for_cwe(self, cwe_id: str) -> List[Dict[str, Any]]:
        """
        Get ATT&CK techniques associated with a CWE.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")
        
        Returns:
            List of ATT&CK techniques
        """
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        
        mapping = CWE_TO_CAPEC.get(cwe_id, {})
        techniques = []
        
        for tech_id in mapping.get("attack_techniques", []):
            tech_info = ATTACK_TECHNIQUES.get(tech_id, {})
            if tech_info:
                techniques.append({
                    "id": tech_id,
                    "name": tech_info.get("name"),
                    "tactic": tech_info.get("tactic"),
                    "description": tech_info.get("description"),
                    "mitre_url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                })
        
        return techniques
    
    def get_capec_for_cwe(self, cwe_id: str) -> List[Dict[str, str]]:
        """
        Get CAPEC attack patterns for a CWE.
        
        Args:
            cwe_id: CWE identifier
        
        Returns:
            List of CAPEC attack patterns
        """
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        
        mapping = CWE_TO_CAPEC.get(cwe_id, {})
        
        patterns = []
        for i, capec_id in enumerate(mapping.get("capec_ids", [])):
            pattern_name = mapping.get("attack_patterns", [])[i] if i < len(mapping.get("attack_patterns", [])) else "Unknown"
            patterns.append({
                "id": capec_id,
                "name": pattern_name,
                "url": f"https://capec.mitre.org/data/definitions/{capec_id.replace('CAPEC-', '')}.html",
            })
        
        return patterns
    
    def get_supported_cwes(self) -> List[str]:
        """Get list of CWEs that have MITRE mappings."""
        return list(CWE_TO_CAPEC.keys())


# Global service instance
_mitre_service: Optional[MITREEnrichmentService] = None


def get_mitre_service() -> MITREEnrichmentService:
    """Get or create the global MITRE enrichment service."""
    global _mitre_service
    if _mitre_service is None:
        _mitre_service = MITREEnrichmentService()
    return _mitre_service
