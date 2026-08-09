"""Static catalog of workflow tools wrapping existing scanner capabilities."""

from typing import Any, Dict, List, Optional


def _port(name: str, type_: str, required: bool = False, description: str = "") -> Dict[str, Any]:
    return {
        "name": name,
        "type": type_,
        "required": required,
        "description": description,
    }


def _param(
    name: str,
    type_: str = "string",
    default: Any = None,
    description: str = "",
    required: bool = False,
) -> Dict[str, Any]:
    return {
        "name": name,
        "type": type_,
        "default": default,
        "description": description,
        "required": required,
    }


TOOL_CATALOG: Dict[str, Dict[str, Any]] = {
    "subfinder_discovery": {
        "id": "subfinder_discovery",
        "name": "Domain Discovery",
        "description": "Enumerate subdomains and create assets from a seed domain.",
        "category": "discovery",
        "job_type": "DISCOVERY",
        "input_ports": [
            _port("domain", "STRING", True, "Seed domain"),
            _port("domains", "FILE_LIST", False, "Optional list of seed domains"),
        ],
        "output_ports": [
            _port("hosts", "FILE_LIST", False, "Discovered hostnames"),
            _port("assets_json", "JSON", False, "Asset summary JSON"),
        ],
        "params": [
            _param("enable_http_probe", "boolean", False, "Probe HTTP during discovery"),
        ],
    },
    "port_scan": {
        "id": "port_scan",
        "name": "Port Scan",
        "description": "Scan open ports and services on hosts.",
        "category": "discovery",
        "job_type": "PORT_SCAN",
        "input_ports": [
            _port("hosts", "FILE_LIST", True, "Hosts to scan"),
        ],
        "output_ports": [
            _port("ports", "JSON", False, "Open ports JSON"),
            _port("hosts", "FILE_LIST", False, "Hosts with open ports"),
        ],
        "params": [
            _param("scanner", "string", "naabu", "Scanner backend (naabu/masscan/nmap)"),
            _param("ports", "string", "top-1000", "Port specification"),
        ],
    },
    "http_probe": {
        "id": "http_probe",
        "name": "HTTP Probe",
        "description": "Probe hosts for live HTTP/HTTPS endpoints.",
        "category": "discovery",
        "job_type": "HTTP_PROBE",
        "input_ports": [
            _port("hosts", "FILE_LIST", True, "Hosts to probe"),
        ],
        "output_ports": [
            _port("urls", "FILE_LIST", False, "Live URLs"),
            _port("hosts", "FILE_LIST", False, "Live hostnames"),
        ],
        "params": [],
    },
    "katana": {
        "id": "katana",
        "name": "Katana Crawl",
        "description": "Deep web crawl with JS parsing.",
        "category": "recon",
        "job_type": "KATANA",
        "input_ports": [
            _port("urls", "FILE_LIST", True, "Seed URLs"),
        ],
        "output_ports": [
            _port("urls", "FILE_LIST", False, "Discovered URLs/endpoints"),
            _port("endpoints", "JSON", False, "Endpoint details"),
        ],
        "params": [
            _param("depth", "integer", 3, "Crawl depth"),
        ],
    },
    "waybackurls": {
        "id": "waybackurls",
        "name": "Wayback URLs",
        "description": "Historical URL discovery via Wayback Machine.",
        "category": "recon",
        "job_type": "WAYBACKURLS",
        "input_ports": [
            _port("hosts", "FILE_LIST", True, "Domains to query"),
        ],
        "output_ports": [
            _port("urls", "FILE_LIST", False, "Historical URLs"),
        ],
        "params": [],
    },
    "paramspider": {
        "id": "paramspider",
        "name": "ParamSpider",
        "description": "Discover URL parameters for domains.",
        "category": "recon",
        "job_type": "PARAMSPIDER",
        "input_ports": [
            _port("hosts", "FILE_LIST", True, "Domains to query"),
        ],
        "output_ports": [
            _port("urls", "FILE_LIST", False, "URLs with parameters"),
            _port("params", "JSON", False, "Parameter details"),
        ],
        "params": [],
    },
    "nuclei": {
        "id": "nuclei",
        "name": "Nuclei Scan",
        "description": "Template-based vulnerability scanning.",
        "category": "vuln",
        "job_type": "NUCLEI_SCAN",
        "input_ports": [
            _port("urls", "FILE_LIST", True, "Targets to scan"),
            _port("hosts", "FILE_LIST", False, "Fallback host targets"),
        ],
        "output_ports": [
            _port("findings", "JSON", False, "Vulnerability findings"),
        ],
        "params": [
            _param("severity", "string", "critical,high,medium", "Severity filter"),
            _param("tags", "string", "", "Template tags"),
        ],
    },
    "screenshot": {
        "id": "screenshot",
        "name": "Screenshot",
        "description": "Capture web screenshots for live URLs.",
        "category": "recon",
        "job_type": "SCREENSHOT",
        "input_ports": [
            _port("urls", "FILE_LIST", True, "URLs to screenshot"),
        ],
        "output_ports": [
            _port("results", "JSON", False, "Screenshot metadata"),
        ],
        "params": [],
    },
    "technology": {
        "id": "technology",
        "name": "Technology Detect",
        "description": "Fingerprint web technologies.",
        "category": "recon",
        "job_type": "TECHNOLOGY_SCAN",
        "input_ports": [
            _port("urls", "FILE_LIST", True, "URLs to fingerprint"),
        ],
        "output_ports": [
            _port("tech", "JSON", False, "Detected technologies"),
        ],
        "params": [],
    },
}


def list_tools() -> List[Dict[str, Any]]:
    return list(TOOL_CATALOG.values())


def get_tool(tool_id: str) -> Optional[Dict[str, Any]]:
    return TOOL_CATALOG.get(tool_id)
