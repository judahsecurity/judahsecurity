"""Canonical mapping from public scan identifiers to worker jobs."""

from app.models.scan import ScanType


JOB_TYPE_BY_SCAN_TYPE: dict[ScanType, str] = {
    ScanType.VULNERABILITY: "NUCLEI_SCAN",
    ScanType.WEB_SCAN: "NUCLEI_SCAN",
    ScanType.PORT_SCAN: "PORT_SCAN",
    ScanType.PORT_VERIFY: "PORT_VERIFY",
    ScanType.SERVICE_DETECT: "SERVICE_DETECT",
    ScanType.DISCOVERY: "DISCOVERY",
    ScanType.FULL: "RECON_PIPELINE",
    ScanType.SUBDOMAIN_ENUM: "SUBDOMAIN_ENUM",
    ScanType.DNS_RESOLUTION: "DNS_RESOLUTION",
    ScanType.DNS_ENUM: "DNS_RESOLUTION",
    ScanType.HTTP_PROBE: "HTTP_PROBE",
    ScanType.LOGIN_PORTAL: "LOGIN_PORTAL",
    ScanType.SCREENSHOT: "SCREENSHOT",
    ScanType.TECHNOLOGY: "TECHNOLOGY_SCAN",
    ScanType.WHATWEB: "WHATWEB_SCAN",
    ScanType.PARAMSPIDER: "PARAMSPIDER",
    ScanType.WAYBACKURLS: "WAYBACKURLS",
    ScanType.KATANA: "KATANA",
    ScanType.CLEANUP: "CLEANUP",
    ScanType.GEO_ENRICH: "GEO_ENRICH",
    ScanType.TLDFINDER: "TLDFINDER",
    ScanType.COMMONCRAWL_ENUM: "COMMONCRAWL_ENUM",
    ScanType.LLM_RED_TEAM: "LLM_RED_TEAM",
    ScanType.ATLAS_DISCOVERY: "ATLAS_DISCOVERY",
    ScanType.ARGUS_SECRETS: "ARGUS_SECRETS",
    ScanType.HERMES_SECRETS: "HERMES_SECRETS",
    ScanType.JANUS_DAST: "JANUS_DAST",
    ScanType.THEMIS_CSPM: "THEMIS_CSPM",
    ScanType.SUBDOMAIN_TAKEOVER: "SUBDOMAIN_TAKEOVER",
    ScanType.GRAPHQL_SCAN: "GRAPHQL_SCAN",
    ScanType.JS_RECON: "JS_RECON",
    ScanType.JSLUICE_SCAN: "JSLUICE_SCAN",
    ScanType.TRUFFLEHOG_SCAN: "TRUFFLEHOG_SCAN",
    ScanType.EMAIL_BREACH: "EMAIL_BREACH",
    ScanType.DNS_THREAT: "DNS_THREAT",
    ScanType.URLHAUS_LOOKUP: "URLHAUS_LOOKUP",
    ScanType.BGP_LOOKUP: "BGP_LOOKUP",
}

SCAN_TYPE_ALIASES = {
    **{scan_type.value: scan_type for scan_type in JOB_TYPE_BY_SCAN_TYPE},
    "nuclei": ScanType.VULNERABILITY,
    "nuclei_critical": ScanType.VULNERABILITY,
    "nuclei_high": ScanType.VULNERABILITY,
    "nuclei_critical_high": ScanType.VULNERABILITY,
    "nuclei_medium": ScanType.VULNERABILITY,
    "nuclei_low_info": ScanType.VULNERABILITY,
    "nuclei_ics": ScanType.VULNERABILITY,
    "masscan": ScanType.PORT_SCAN,
    "critical_ports": ScanType.PORT_SCAN,
    "ics_ot_ports": ScanType.PORT_SCAN,
    "ics_plc_scan": ScanType.PORT_SCAN,
    "ics_scada_scan": ScanType.PORT_SCAN,
    "ics_building_automation": ScanType.PORT_SCAN,
    "ics_full_discovery": ScanType.PORT_SCAN,
    "ics_hmi_screenshot": ScanType.SCREENSHOT,
    "logix_runtime_status": ScanType.PORT_SCAN,
    "logix_program_inventory": ScanType.PORT_SCAN,
    "full_discovery": ScanType.DISCOVERY,
}

SCHEDULE_ONLY_SCAN_TYPES = {"tester_process"}


def resolve_scan_type(scan_type_id: str) -> ScanType:
    if scan_type_id in SCHEDULE_ONLY_SCAN_TYPES:
        raise ValueError(f"Scan type '{scan_type_id}' can only run through a schedule")
    try:
        return SCAN_TYPE_ALIASES[scan_type_id]
    except KeyError as exc:
        raise ValueError(f"Scan type '{scan_type_id}' has no execution mapping") from exc


def job_type_for_scan_type(scan_type: ScanType, config: dict | None = None) -> str:
    if (config or {}).get("scan_engine") == "logix_runtime":
        return "LOGIX_RUNTIME"
    try:
        return JOB_TYPE_BY_SCAN_TYPE[scan_type]
    except KeyError as exc:
        raise ValueError(f"Scan type '{scan_type.value}' has no worker handler") from exc
