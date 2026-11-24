"""Risk Driver Service.

Calculates and populates meaningful risk drivers for assets based on:
- System type classification and data sensitivity profile
- Login portal detection
- Technology fingerprinting (SAP, databases, admin panels, etc.)
- Open/risky ports
- Vulnerability count and severity
- Public accessibility
- Hosting classification

Risk drivers are stored in the asset's acs_drivers field and influence the ACS score.
The system_type_profile driver sets a minimum ACS floor based on the likely data
sensitivity of the system, independent of active vulnerabilities.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# System type profiles — classify what kind of data a system likely holds.
#
# Each entry defines:
#   system_type : short identifier surfaced in the driver output
#   data_labels : human-readable data sensitivity tags shown in the UI
#   acs_floor   : minimum ACS score regardless of other drivers (0–10)
#   risk        : driver risk level fed into overall_risk calculation
#   reason      : one-line explanation shown to analysts
# ---------------------------------------------------------------------------
SYSTEM_TYPE_PROFILES: Dict[str, Dict[str, Any]] = {
    # ── Financial & payment ──────────────────────────────────────────────
    "erp_financial": {
        "system_type": "erp_financial",
        "data_labels": ["Financial records", "Business transactions", "Payroll"],
        "acs_floor": 8,
        "risk": "critical",
        "reason": "ERP / financial system — likely holds financial records and business-critical transactions",
    },
    "payment_processing": {
        "system_type": "payment_processing",
        "data_labels": ["PCI data", "Card holder data", "Payment transactions"],
        "acs_floor": 9,
        "risk": "critical",
        "reason": "Payment processing system — PCI-scoped, card holder data in scope",
    },
    "accounting": {
        "system_type": "accounting",
        "data_labels": ["Financial records", "Tax data", "Invoices"],
        "acs_floor": 7,
        "risk": "high",
        "reason": "Accounting system — contains financial records and tax data",
    },

    # ── HR & people data ─────────────────────────────────────────────────
    "hr_people_data": {
        "system_type": "hr_people_data",
        "data_labels": ["PII", "Employee records", "Compensation", "SSN / NI numbers"],
        "acs_floor": 8,
        "risk": "critical",
        "reason": "HR / people system — contains employee PII, compensation, and sensitive personal records",
    },

    # ── Healthcare / PHI ─────────────────────────────────────────────────
    "healthcare_phi": {
        "system_type": "healthcare_phi",
        "data_labels": ["PHI", "Patient records", "HIPAA-scoped data"],
        "acs_floor": 9,
        "risk": "critical",
        "reason": "Healthcare system — HIPAA-scoped, contains protected health information (PHI)",
    },

    # ── Identity & authentication ────────────────────────────────────────
    "identity_auth": {
        "system_type": "identity_auth",
        "data_labels": ["Credentials", "Authentication tokens", "Directory data"],
        "acs_floor": 9,
        "risk": "critical",
        "reason": "Identity / authentication system — compromise gives broad lateral access across the org",
    },

    # ── Source code & IP ─────────────────────────────────────────────────
    "source_code_ip": {
        "system_type": "source_code_ip",
        "data_labels": ["Source code", "Intellectual property", "Secrets in code"],
        "acs_floor": 7,
        "risk": "high",
        "reason": "Source code / DevOps system — contains intellectual property and often embedded secrets",
    },

    # ── Data stores ──────────────────────────────────────────────────────
    "database_admin": {
        "system_type": "database_admin",
        "data_labels": ["Database access", "Potentially all application data"],
        "acs_floor": 9,
        "risk": "critical",
        "reason": "Database administration interface — direct, unauthenticated-feeling access to all stored data",
    },
    "data_store": {
        "system_type": "data_store",
        "data_labels": ["Stored application data", "Potentially PII or financial records"],
        "acs_floor": 7,
        "risk": "high",
        "reason": "Data store — content sensitivity depends on application; treat as high until confirmed otherwise",
    },

    # ── Infrastructure control ───────────────────────────────────────────
    "infrastructure_control": {
        "system_type": "infrastructure_control",
        "data_labels": ["Server credentials", "Network access", "Full infrastructure control"],
        "acs_floor": 9,
        "risk": "critical",
        "reason": "Infrastructure control panel — compromise gives access to all hosted systems",
    },
    "network_device": {
        "system_type": "network_device",
        "data_labels": ["Network routing", "Traffic inspection", "Network credentials"],
        "acs_floor": 8,
        "risk": "critical",
        "reason": "Network device — compromise enables traffic interception and lateral movement across network segments",
    },

    # ── Industrial / OT ──────────────────────────────────────────────────
    "industrial_ot": {
        "system_type": "industrial_ot",
        "data_labels": ["Physical process control", "Safety systems", "Operational data"],
        "acs_floor": 10,
        "risk": "critical",
        "reason": "Industrial / OT system — compromise can cause physical harm or safety incidents",
    },

    # ── Remote access ────────────────────────────────────────────────────
    "remote_access": {
        "system_type": "remote_access",
        "data_labels": ["Remote session data", "Credential relay", "Full desktop access"],
        "acs_floor": 8,
        "risk": "critical",
        "reason": "Remote access gateway — provides direct interactive access to internal systems",
    },

    # ── Email & communications ───────────────────────────────────────────
    "email_communications": {
        "system_type": "email_communications",
        "data_labels": ["Business email", "Potentially sensitive communications", "Attachments"],
        "acs_floor": 6,
        "risk": "high",
        "reason": "Email / communications system — contains business correspondence and often sensitive attachments",
    },

    # ── Devops / CI pipeline ─────────────────────────────────────────────
    "devops_pipeline": {
        "system_type": "devops_pipeline",
        "data_labels": ["Build secrets", "Deployment keys", "Source code access"],
        "acs_floor": 7,
        "risk": "high",
        "reason": "DevOps / CI pipeline — contains deployment credentials and build secrets; supply-chain risk",
    },

    # ── CRM & customer data ──────────────────────────────────────────────
    "crm_customer_data": {
        "system_type": "crm_customer_data",
        "data_labels": ["Customer PII", "Contact data", "Sales pipeline"],
        "acs_floor": 7,
        "risk": "high",
        "reason": "CRM system — contains customer PII and contact data",
    },
}


# ---------------------------------------------------------------------------
# Technology-to-system-type mapping.
# Key: substring matched (case-insensitive) against technology name.
# Value: system_type key from SYSTEM_TYPE_PROFILES.
# ---------------------------------------------------------------------------
TECH_TO_SYSTEM_TYPE: Dict[str, str] = {
    # ERP / financial
    "sap":             "erp_financial",
    "oracle e-business": "erp_financial",
    "oracle financials": "erp_financial",
    "oracle erp":      "erp_financial",
    "peoplesoft":      "erp_financial",
    "netsuite":        "erp_financial",
    "epicor":          "erp_financial",
    "infor":           "erp_financial",
    "sage erp":        "erp_financial",
    "dynamics ax":     "erp_financial",
    "dynamics 365":    "erp_financial",
    "dynamics nav":    "erp_financial",
    "dynamics gp":     "erp_financial",
    "quickbooks":      "accounting",
    "xero":            "accounting",
    "freshbooks":      "accounting",
    "sage accounting": "accounting",
    "wave accounting": "accounting",

    # Payment
    "stripe":          "payment_processing",
    "paypal":          "payment_processing",
    "braintree":       "payment_processing",
    "square":          "payment_processing",
    "authorize.net":   "payment_processing",
    "adyen":           "payment_processing",
    "worldpay":        "payment_processing",
    "checkout.com":    "payment_processing",

    # HR / people
    "workday":         "hr_people_data",
    "bamboohr":        "hr_people_data",
    "adp":             "hr_people_data",
    "ceridian":        "hr_people_data",
    "dayforce":        "hr_people_data",
    "kronos":          "hr_people_data",
    "ultipro":         "hr_people_data",
    "successfactors":  "hr_people_data",
    "namely":          "hr_people_data",
    "gusto":           "hr_people_data",
    "rippling":        "hr_people_data",
    "zenefits":        "hr_people_data",

    # Healthcare
    "epic systems":    "healthcare_phi",
    "cerner":          "healthcare_phi",
    "meditech":        "healthcare_phi",
    "allscripts":      "healthcare_phi",
    "athenahealth":    "healthcare_phi",
    "eclinicalworks":  "healthcare_phi",
    "nextgen":         "healthcare_phi",
    "healtheon":       "healthcare_phi",

    # Identity / auth
    "active directory": "identity_auth",
    "okta":            "identity_auth",
    "azure ad":        "identity_auth",
    "ping identity":   "identity_auth",
    "cyberark":        "identity_auth",
    "beyond trust":    "identity_auth",
    "beyondtrust":     "identity_auth",
    "sailpoint":       "identity_auth",
    "one login":       "identity_auth",
    "onelogin":        "identity_auth",
    "duo security":    "identity_auth",
    "hashicorp vault": "identity_auth",
    "vault":           "identity_auth",
    "keycloak":        "identity_auth",
    "ldap":            "identity_auth",
    "freeipa":         "identity_auth",
    "samba":           "identity_auth",

    # Database admin panels
    "phpmyadmin":      "database_admin",
    "adminer":         "database_admin",
    "pgadmin":         "database_admin",
    "dbeavor":         "database_admin",
    "sequel pro":      "database_admin",
    "dbeaver":         "database_admin",
    "redisinsight":    "database_admin",
    "mongo express":   "database_admin",
    "nosqlclient":     "database_admin",
    "elastichq":       "database_admin",
    "kibana":          "database_admin",

    # Data stores
    "mysql":           "data_store",
    "postgresql":      "data_store",
    "mongodb":         "data_store",
    "redis":           "data_store",
    "elasticsearch":   "data_store",
    "cassandra":       "data_store",
    "couchdb":         "data_store",
    "influxdb":        "data_store",
    "mssql":           "data_store",
    "mariadb":         "data_store",
    "oracle database": "data_store",
    "oracle db":       "data_store",
    "db2":             "data_store",
    "teradata":        "data_store",
    "snowflake":       "data_store",
    "databricks":      "data_store",

    # Infrastructure control
    "cpanel":          "infrastructure_control",
    "plesk":           "infrastructure_control",
    "webmin":          "infrastructure_control",
    "directadmin":     "infrastructure_control",
    "ispconfig":       "infrastructure_control",
    "virtualmin":      "infrastructure_control",
    "proxmox":         "infrastructure_control",
    "esxi":            "infrastructure_control",
    "vmware vcenter":  "infrastructure_control",
    "vcenter":         "infrastructure_control",
    "nutanix":         "infrastructure_control",
    "xen orchestra":   "infrastructure_control",
    "cockpit":         "infrastructure_control",

    # Network devices
    "cisco":           "network_device",
    "juniper":         "network_device",
    "palo alto":       "network_device",
    "fortinet":        "network_device",
    "fortigate":       "network_device",
    "f5 big-ip":       "network_device",
    "big-ip":          "network_device",
    "netscaler":       "network_device",
    "checkpoint":      "network_device",
    "sophos":          "network_device",
    "ubiquiti":        "network_device",
    "mikrotik":        "network_device",
    "barracuda":       "network_device",

    # Industrial / OT
    "scada":           "industrial_ot",
    "wonderware":      "industrial_ot",
    "ignition":        "industrial_ot",
    "inductive automation": "industrial_ot",
    "plc":             "industrial_ot",
    "hmi":             "industrial_ot",
    "rockwell":        "industrial_ot",
    "siemens":         "industrial_ot",
    "schneider":       "industrial_ot",
    "allen-bradley":   "industrial_ot",
    "ge digital":      "industrial_ot",
    "honeywell dcs":   "industrial_ot",
    "emerson deltav":  "industrial_ot",
    "abb":             "industrial_ot",

    # Remote access
    "citrix":          "remote_access",
    "rdp":             "remote_access",
    "vnc":             "remote_access",
    "teamviewer":      "remote_access",
    "anydesk":         "remote_access",
    "logmein":         "remote_access",
    "openvpn":         "remote_access",
    "pulse secure":    "remote_access",
    "globalprotect":   "remote_access",
    "ivanti connect":  "remote_access",
    "netscaler gateway": "remote_access",
    "fortinet ssl-vpn": "remote_access",
    "sslvpn":          "remote_access",
    "apache guacamole": "remote_access",
    "guacamole":       "remote_access",

    # Email
    "microsoft exchange": "email_communications",
    "exchange":        "email_communications",
    "zimbra":          "email_communications",
    "roundcube":       "email_communications",
    "squirrelmail":    "email_communications",
    "horde":           "email_communications",
    "postfix":         "email_communications",
    "sendmail":        "email_communications",
    "icewarp":         "email_communications",

    # DevOps / CI
    "jenkins":         "devops_pipeline",
    "gitlab":          "devops_pipeline",
    "github":          "devops_pipeline",
    "bitbucket":       "devops_pipeline",
    "bamboo":          "devops_pipeline",
    "teamcity":        "devops_pipeline",
    "circle ci":       "devops_pipeline",
    "circleci":        "devops_pipeline",
    "travis":          "devops_pipeline",
    "drone":           "devops_pipeline",
    "concourse":       "devops_pipeline",
    "argocd":          "devops_pipeline",
    "flux":            "devops_pipeline",
    "sonarqube":       "devops_pipeline",
    "nexus":           "devops_pipeline",
    "artifactory":     "devops_pipeline",
    "harbor":          "devops_pipeline",

    # CRM
    "salesforce":      "crm_customer_data",
    "hubspot":         "crm_customer_data",
    "zoho crm":        "crm_customer_data",
    "sugar crm":       "crm_customer_data",
    "sugarcrm":        "crm_customer_data",
    "pipedrive":       "crm_customer_data",
    "freshsales":      "crm_customer_data",
    "dynamics crm":    "crm_customer_data",
    "microsoft crm":   "crm_customer_data",
}


# ---------------------------------------------------------------------------
# Wappalyzer category → system_type fallback.
# Applied when no technology-name match is found.
# ---------------------------------------------------------------------------
CATEGORY_TO_SYSTEM_TYPE: Dict[str, str] = {
    "Payment processors":  "payment_processing",
    "Ecommerce":           "payment_processing",
    "Accounting":          "accounting",
    "CRM":                 "crm_customer_data",
    "Database managers":   "database_admin",
    "Databases":           "data_store",
    "Hosting panels":      "infrastructure_control",
    "Control systems":     "industrial_ot",
    "Remote access":       "remote_access",
    "Web mail":            "email_communications",
    "Network devices":     "network_device",
    "Authentication":      "identity_auth",
    "CI":                  "devops_pipeline",
    "Document management": "data_store",
    "Network storage":     "data_store",
}


# ---------------------------------------------------------------------------
# Hostname / subdomain patterns → system_type.
# Matched against the leftmost subdomain labels (e.g. "hr.corp.example.com"
# → matches "hr").  Patterns are plain substring checks after lowercasing.
# ---------------------------------------------------------------------------
HOSTNAME_PATTERNS: List[Dict[str, Any]] = [
    {"patterns": ["sap", "erp", "fiori", "s4hana", "hana"],          "system_type": "erp_financial"},
    {"patterns": ["pay", "payroll", "payslip", "paystub"],            "system_type": "erp_financial"},
    {"patterns": ["finance", "financial", "accounting", "ledger",
                  "billing", "invoice", "ap.", "ar."],               "system_type": "accounting"},
    {"patterns": ["payment", "checkout", "cart", "pci", "ecom"],     "system_type": "payment_processing"},
    {"patterns": ["hr", "hris", "hrms", "people", "workforce",
                  "benefits", "onboard", "talent", "recruit"],        "system_type": "hr_people_data"},
    {"patterns": ["ehr", "emr", "patient", "clinical", "hipaa",
                  "health", "phr", "epic", "cerner"],                 "system_type": "healthcare_phi"},
    {"patterns": ["iam", "idp", "sso", "auth", "login", "ldap",
                  "ad.", "okta", "vault", "secret"],                  "system_type": "identity_auth"},
    {"patterns": ["git", "gitlab", "github", "ci", "cd", "build",
                  "jenkins", "sonar", "nexus", "artifactory",
                  "registry", "harbor"],                              "system_type": "devops_pipeline"},
    {"patterns": ["db", "database", "mysql", "postgres", "mongo",
                  "redis", "elastic", "sql", "data"],                 "system_type": "data_store"},
    {"patterns": ["vpn", "remote", "rdp", "jump", "bastion",
                  "gateway", "access", "citrix"],                     "system_type": "remote_access"},
    {"patterns": ["mail", "email", "smtp", "imap", "webmail",
                  "exchange", "zimbra"],                              "system_type": "email_communications"},
    {"patterns": ["scada", "ics", "plc", "hmi", "ot", "ops",
                  "control", "dcs"],                                  "system_type": "industrial_ot"},
    {"patterns": ["crm", "salesforce", "hubspot", "customer"],       "system_type": "crm_customer_data"},
    {"patterns": ["admin", "panel", "mgmt", "manage", "control",
                  "dashboard", "portal"],                             "system_type": "infrastructure_control"},
    {"patterns": ["fw", "firewall", "router", "switch", "vpn-gw",
                  "network", "nms"],                                  "system_type": "network_device"},
]


# ---------------------------------------------------------------------------
# High-risk technology categories (from Wappalyzer) — used for the legacy
# technology driver (separate from system_type_profile).
# ---------------------------------------------------------------------------
HIGH_RISK_CATEGORIES = {
    "CRM": {"risk": "high", "reason": "Contains customer data"},
    "Database managers": {"risk": "critical", "reason": "Database administration interface"},
    "Databases": {"risk": "high", "reason": "Direct database access"},
    "Hosting panels": {"risk": "critical", "reason": "Server control panel"},
    "Control systems": {"risk": "critical", "reason": "Industrial control system"},
    "Remote access": {"risk": "critical", "reason": "Remote access service"},
    "Web mail": {"risk": "high", "reason": "Email access portal"},
    "Ecommerce": {"risk": "high", "reason": "Payment/transaction system"},
    "Payment processors": {"risk": "critical", "reason": "Payment processing"},
    "Accounting": {"risk": "high", "reason": "Financial system"},
    "Document management": {"risk": "medium", "reason": "Document storage"},
    "Network devices": {"risk": "high", "reason": "Network infrastructure"},
    "Network storage": {"risk": "high", "reason": "File storage system"},
    "Webcams": {"risk": "medium", "reason": "Surveillance system"},
    "CI": {"risk": "medium", "reason": "CI/CD pipeline"},
    "Issue trackers": {"risk": "medium", "reason": "Project management system"},
    "Authentication": {"risk": "high", "reason": "Authentication service"},
}

# High-risk technology names (specific products) — legacy driver, kept for
# backwards compat.  New logic should prefer system_type_profile.
HIGH_RISK_TECHNOLOGIES = {
    # ERP/Business Systems
    "sap": {"risk": "critical", "reason": "SAP ERP System"},
    "oracle": {"risk": "critical", "reason": "Oracle Enterprise System"},
    "salesforce": {"risk": "high", "reason": "Salesforce CRM"},
    "dynamics": {"risk": "high", "reason": "Microsoft Dynamics"},
    "workday": {"risk": "high", "reason": "Workday HR System"},
    "netsuite": {"risk": "high", "reason": "NetSuite ERP"},

    # Databases
    "mysql": {"risk": "high", "reason": "MySQL Database"},
    "postgresql": {"risk": "high", "reason": "PostgreSQL Database"},
    "mongodb": {"risk": "high", "reason": "MongoDB Database"},
    "redis": {"risk": "high", "reason": "Redis Database"},
    "elasticsearch": {"risk": "high", "reason": "Elasticsearch"},
    "phpmyadmin": {"risk": "critical", "reason": "phpMyAdmin Database Admin"},
    "adminer": {"risk": "critical", "reason": "Adminer Database Admin"},
    "pgadmin": {"risk": "critical", "reason": "pgAdmin Database Admin"},

    # Admin/Control Panels
    "cpanel": {"risk": "critical", "reason": "cPanel Hosting Control"},
    "plesk": {"risk": "critical", "reason": "Plesk Hosting Control"},
    "webmin": {"risk": "critical", "reason": "Webmin Server Admin"},
    "directadmin": {"risk": "critical", "reason": "DirectAdmin Control Panel"},

    # Remote Access
    "citrix": {"risk": "critical", "reason": "Citrix Remote Access"},
    "vmware": {"risk": "high", "reason": "VMware Infrastructure"},
    "rdp": {"risk": "critical", "reason": "Remote Desktop"},
    "vnc": {"risk": "critical", "reason": "VNC Remote Access"},
    "teamviewer": {"risk": "high", "reason": "TeamViewer Remote Access"},

    # CI/CD
    "jenkins": {"risk": "high", "reason": "Jenkins CI/CD"},
    "gitlab": {"risk": "high", "reason": "GitLab DevOps"},
    "bamboo": {"risk": "high", "reason": "Bamboo CI/CD"},
    "teamcity": {"risk": "high", "reason": "TeamCity CI/CD"},

    # Email
    "exchange": {"risk": "high", "reason": "Microsoft Exchange"},
    "zimbra": {"risk": "high", "reason": "Zimbra Email"},
    "roundcube": {"risk": "medium", "reason": "Roundcube Webmail"},

    # CMS with known vulns
    "wordpress": {"risk": "medium", "reason": "WordPress CMS"},
    "drupal": {"risk": "medium", "reason": "Drupal CMS"},
    "joomla": {"risk": "medium", "reason": "Joomla CMS"},

    # Industrial/OT
    "scada": {"risk": "critical", "reason": "SCADA System"},
    "plc": {"risk": "critical", "reason": "PLC Controller"},
    "hmi": {"risk": "critical", "reason": "HMI Interface"},
    "rockwell": {"risk": "critical", "reason": "Rockwell Automation"},
    "siemens": {"risk": "critical", "reason": "Siemens Industrial"},
    "schneider": {"risk": "critical", "reason": "Schneider Electric"},
    "allen-bradley": {"risk": "critical", "reason": "Allen-Bradley PLC"},
}

# Risky ports and services
RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class RiskDriverService:
    """Service to calculate and populate risk drivers for assets."""

    def __init__(self, db: Session):
        self.db = db

    def calculate_risk_drivers(self, asset: Asset) -> Dict[str, Any]:
        """Calculate risk drivers for an asset based on all available data.

        Returns a dict of risk drivers.  The ``system_type_profile`` key is
        the primary new driver — it classifies the asset by what kind of data
        it likely holds and sets a minimum ACS floor accordingly.
        """
        drivers: Dict[str, Any] = {}

        # 1. System type profile (data sensitivity classification) — runs first
        #    so its ACS floor is available to update_asset_risk_drivers.
        system_profile = self._classify_system_type(asset)
        if system_profile:
            drivers["system_type_profile"] = system_profile

        # 2. Login portals
        if asset.has_login_portal:
            login_count = len(asset.login_portals or [])
            drivers["login_portal"] = {
                "value": True,
                "count": login_count,
                "risk": "high",
                "reason": f"Has {login_count} login portal(s) detected",
            }

        # 3. Technology fingerprint (legacy driver — name/category match)
        tech_drivers = self._analyze_technologies(asset)
        if tech_drivers:
            drivers["technologies"] = tech_drivers

        # 4. Risky ports
        port_drivers = self._analyze_ports(asset)
        if port_drivers:
            drivers["risky_ports"] = port_drivers

        # 5. Vulnerability counts
        vuln_drivers = self._analyze_vulnerabilities(asset)
        if vuln_drivers:
            drivers["vulnerabilities"] = vuln_drivers

        # 6. Public accessibility
        if asset.is_public:
            drivers["public_facing"] = {
                "value": True,
                "risk": "medium",
                "reason": "Publicly accessible from internet",
            }

        # 7. Hosting type
        if asset.hosting_type == "owned":
            drivers["owned_infrastructure"] = {
                "value": True,
                "risk": "high",
                "reason": "Owned infrastructure (not CDN/cloud ephemeral)",
            }

        # 8. Overall risk level
        drivers["overall_risk"] = self._calculate_overall_risk(drivers)

        return drivers

    # ------------------------------------------------------------------
    # System type classification
    # ------------------------------------------------------------------

    def _classify_system_type(self, asset: Asset) -> Optional[Dict[str, Any]]:
        """Classify the asset by its likely system type and data sensitivity.

        Resolution order (first match wins):
          1. Technology name substring match (TECH_TO_SYSTEM_TYPE)
          2. Wappalyzer category match (CATEGORY_TO_SYSTEM_TYPE)
          3. Hostname / subdomain pattern match (HOSTNAME_PATTERNS)

        Returns a driver dict compatible with the rest of the risk driver
        framework, or None if no classification could be made.
        """
        matched_type: Optional[str] = None
        match_source: Optional[str] = None
        match_evidence: Optional[str] = None

        # 1. Technology name match
        for tech in asset.technologies or []:
            tech_name = (tech.name or "").lower()
            for pattern, sys_type in TECH_TO_SYSTEM_TYPE.items():
                if pattern in tech_name:
                    matched_type = sys_type
                    match_source = "technology_name"
                    match_evidence = tech.name
                    break
            if matched_type:
                break

        # 2. Wappalyzer category match (fallback)
        if not matched_type:
            for tech in asset.technologies or []:
                for category in (tech.categories or []):
                    if category in CATEGORY_TO_SYSTEM_TYPE:
                        matched_type = CATEGORY_TO_SYSTEM_TYPE[category]
                        match_source = "technology_category"
                        match_evidence = category
                        break
                if matched_type:
                    break

        # 3. Hostname pattern match (fallback)
        if not matched_type and asset.value:
            hostname = asset.value.lower()
            for entry in HOSTNAME_PATTERNS:
                for pat in entry["patterns"]:
                    # Match against subdomain labels or full hostname
                    if re.search(r'(^|\.)' + re.escape(pat) + r'(\.|$|-|_)', hostname):
                        matched_type = entry["system_type"]
                        match_source = "hostname_pattern"
                        match_evidence = pat
                        break
                if matched_type:
                    break

        if not matched_type:
            return None

        profile = SYSTEM_TYPE_PROFILES.get(matched_type)
        if not profile:
            return None

        return {
            "system_type": profile["system_type"],
            "data_labels": profile["data_labels"],
            "acs_floor": profile["acs_floor"],
            "risk": profile["risk"],
            "reason": profile["reason"],
            "match_source": match_source,
            "match_evidence": match_evidence,
        }
    
    def _analyze_technologies(self, asset: Asset) -> Optional[Dict[str, Any]]:
        """Analyze detected technologies for risk factors."""
        if not asset.technologies:
            return None
        
        high_risk_techs = []
        
        for tech in asset.technologies:
            tech_name = tech.name.lower()
            categories = tech.categories or []
            
            # Check by technology name
            for pattern, info in HIGH_RISK_TECHNOLOGIES.items():
                if pattern in tech_name:
                    high_risk_techs.append({
                        "name": tech.name,
                        "risk": info["risk"],
                        "reason": info["reason"]
                    })
                    break
            else:
                # Check by category
                for category in categories:
                    if category in HIGH_RISK_CATEGORIES:
                        cat_info = HIGH_RISK_CATEGORIES[category]
                        high_risk_techs.append({
                            "name": tech.name,
                            "category": category,
                            "risk": cat_info["risk"],
                            "reason": cat_info["reason"]
                        })
                        break
        
        if not high_risk_techs:
            return None
        
        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        high_risk_techs.sort(key=lambda x: risk_order.get(x["risk"], 4))
        
        highest_risk = high_risk_techs[0]["risk"] if high_risk_techs else "low"
        
        return {
            "count": len(high_risk_techs),
            "risk": highest_risk,
            "items": high_risk_techs[:5],  # Top 5
            "reason": f"{len(high_risk_techs)} high-risk technologies detected"
        }
    
    def _analyze_ports(self, asset: Asset) -> Optional[Dict[str, Any]]:
        """Analyze open ports for risk factors."""
        if not asset.port_services:
            return None
        
        risky_ports = []
        
        for port_service in asset.port_services:
            if port_service.is_risky or port_service.port in RISKY_PORTS:
                service_name = RISKY_PORTS.get(port_service.port, port_service.service or "Unknown")
                risky_ports.append({
                    "port": port_service.port,
                    "service": service_name,
                    "protocol": port_service.protocol
                })
        
        if not risky_ports:
            return None
        
        # Determine risk level based on what's exposed
        critical_ports = {23, 3389, 5900, 445, 135, 139}  # Telnet, RDP, VNC, SMB, etc.
        has_critical = any(p["port"] in critical_ports for p in risky_ports)
        
        return {
            "count": len(risky_ports),
            "risk": "critical" if has_critical else "high",
            "items": risky_ports[:10],  # Top 10
            "reason": f"{len(risky_ports)} risky port(s) exposed"
        }
    
    def _analyze_vulnerabilities(self, asset: Asset) -> Optional[Dict[str, Any]]:
        """Analyze vulnerabilities for risk factors."""
        from app.services.agent.unverified_findings import is_visible

        # Unverified agent leads do not drive asset risk until promoted.
        visible = [v for v in (asset.vulnerabilities or []) if is_visible(v)]
        if not visible:
            return None
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in visible:
            severity = (vuln.severity or "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total = sum(severity_counts.values())
        if total == 0:
            return None
        
        # Determine overall risk
        if severity_counts["critical"] > 0:
            risk = "critical"
        elif severity_counts["high"] > 0:
            risk = "high"
        elif severity_counts["medium"] > 0:
            risk = "medium"
        else:
            risk = "low"
        
        return {
            "total": total,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "risk": risk,
            "reason": f"{total} vulnerabilities ({severity_counts['critical']} critical, {severity_counts['high']} high)"
        }
    
    def _calculate_overall_risk(self, drivers: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk level from all drivers."""
        risk_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_risk = "low"
        max_score = 0
        risk_factors = []
        
        for key, value in drivers.items():
            if key == "overall_risk":
                continue
            if isinstance(value, dict) and "risk" in value:
                risk = value["risk"]
                score = risk_scores.get(risk, 0)
                if score > max_score:
                    max_score = score
                    max_risk = risk
                if score >= 3:  # high or critical
                    risk_factors.append(value.get("reason", key))
        
        return {
            "level": max_risk,
            "score": max_score,
            "factors": risk_factors[:5]  # Top 5 risk factors
        }
    
    def update_asset_risk_drivers(self, asset: Asset) -> Dict[str, Any]:
        """Calculate and update risk drivers for an asset.

        ACS is set to the highest of:
          • The floor from system_type_profile (data sensitivity minimum)
          • The score derived from the overall risk level of all other drivers

        ACS only ever increases — it is never lowered by this calculation.
        """
        drivers = self.calculate_risk_drivers(asset)
        asset.acs_drivers = drivers

        overall = drivers.get("overall_risk", {})
        risk_level = overall.get("level", "low")

        risk_to_acs = {
            "critical": 9,
            "high": 7,
            "medium": 5,
            "low": 3,
        }
        driver_acs = risk_to_acs.get(risk_level, 3)

        # Honour the data-sensitivity floor set by the system type profile.
        profile_floor = drivers.get("system_type_profile", {}).get("acs_floor", 0)

        calculated_acs = max(driver_acs, profile_floor)
        if calculated_acs > (asset.acs_score or 0):
            asset.acs_score = calculated_acs

        self.db.commit()

        system_type = drivers.get("system_type_profile", {}).get("system_type", "unknown")
        logger.info(
            "Updated risk drivers for asset %s (%s): risk=%s system_type=%s acs=%s",
            asset.id, asset.value, risk_level, system_type, asset.acs_score,
        )

        return drivers
    
    def update_all_assets(
        self, 
        organization_id: Optional[int] = None,
        limit: int = 1000
    ) -> Dict[str, int]:
        """
        Update risk drivers for multiple assets.
        
        Args:
            organization_id: Optional filter by organization
            limit: Maximum assets to process
            
        Returns:
            Statistics about the update
        """
        query = self.db.query(Asset)
        
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
        
        assets = query.limit(limit).all()
        
        stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for asset in assets:
            drivers = self.update_asset_risk_drivers(asset)
            stats["total"] += 1
            
            overall = drivers.get("overall_risk", {})
            risk_level = overall.get("level", "low")
            if risk_level in stats:
                stats[risk_level] += 1
        
        logger.info(f"Updated risk drivers for {stats['total']} assets")
        return stats


def get_risk_driver_service(db: Session) -> RiskDriverService:
    """Factory function to create a RiskDriverService instance."""
    return RiskDriverService(db)
