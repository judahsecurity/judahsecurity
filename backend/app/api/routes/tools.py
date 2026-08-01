"""Tools status and management API routes."""

import subprocess
import shutil
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.api.deps import get_current_active_user
from app.models.user import User
from app.models.api_config import APIConfig

router = APIRouter(prefix="/tools", tags=["Tools"])


# Tool definitions with their check commands and categories
TOOLS = {
    # Installed CLI Tools
    "nuclei": {
        "name": "Nuclei",
        "description": "Fast vulnerability scanner with YAML-based templates",
        "category": "vulnerability",
        "type": "cli",
        "check_command": ["nuclei", "-version"],
        "installed": False,
        "version": None,
    },
    "subfinder": {
        "name": "Subfinder",
        "description": "ProjectDiscovery subdomain enumeration tool",
        "category": "dns",
        "type": "cli",
        "check_command": ["subfinder", "-version"],
        "installed": False,
        "version": None,
    },
    "httpx": {
        "name": "HTTPX",
        "description": "Multi-purpose HTTP toolkit with probing capabilities",
        "category": "http",
        "type": "cli",
        "check_command": ["httpx", "-version"],
        "installed": False,
        "version": None,
    },
    "naabu": {
        "name": "Naabu",
        "description": "Fast port scanner with focus on reliability",
        "category": "ports",
        "type": "cli",
        "check_command": ["naabu", "-version"],
        "installed": False,
        "version": None,
    },
    "katana": {
        "name": "Katana",
        "description": "Next-gen crawling and spidering framework",
        "category": "crawler",
        "type": "cli",
        "check_command": ["katana", "-version"],
        "installed": False,
        "version": None,
    },
    "waybackurls": {
        "name": "Wayback Machine",
        "description": "Historical subdomain discovery from web archives",
        "category": "passive",
        "type": "cli",
        "check_command": ["waybackurls", "-h"],
        "installed": False,
        "version": None,
    },
    "masscan": {
        "name": "Masscan",
        "description": "Fast port scanner with banner grabbing",
        "category": "ports",
        "type": "cli",
        "check_command": ["masscan", "--version"],
        "installed": False,
        "version": None,
    },
    "nmap": {
        "name": "Nmap",
        "description": "Advanced port scanner with NSE scripts for service detection",
        "category": "ports",
        "type": "cli",
        "check_command": ["nmap", "--version"],
        "installed": False,
        "version": None,
    },
    "dnsx": {
        "name": "dnsx",
        "description": "Fast DNS resolver and enumeration tool",
        "category": "dns",
        "type": "cli",
        "check_command": ["dnsx", "-version"],
        "installed": False,
        "version": None,
    },
    "eyewitness": {
        "name": "EyeWitness",
        "description": "Screenshot and header capture for web assets",
        "category": "screenshot",
        "type": "cli",
        "check_command": None,  # Python script, check differently
        "check_path": "/opt/EyeWitness/Python/EyeWitness.py",
        "installed": False,
        "version": None,
    },
    # API-based services
    "whoisxml_netblocks": {
        "name": "WhoisXML IP Netblocks",
        "description": "Organization IP netblock discovery",
        "category": "whois",
        "type": "api",
        "service_name": "whoisxml_netblocks",
        "configured": False,
    },
    "whoxy": {
        "name": "Whoxy API",
        "description": "WHOIS lookups and domain intelligence",
        "category": "whois",
        "type": "api",
        "service_name": "whoxy",
        "configured": False,
    },
    "ip2location": {
        "name": "IP2Location / ip-api.com",
        "description": "IP geolocation lookup for mapping asset locations",
        "category": "intelligence",
        "type": "builtin",
        "configured": True,
    },
    # Passive/Free services
    "crtsh": {
        "name": "crt.sh",
        "description": "Certificate Transparency log subdomain discovery (passive, queries CT logs for SSL/TLS certificate subdomains)",
        "category": "passive",
        "type": "builtin",
        "configured": True,
    },
    "crt_name": {
        "name": "crt.name",
        "description": "Aggregated CT/DNS subdomain index (live CT, historical backfill, Chaos, CZDS, active probes) — free, 1000 req/IP/day",
        "category": "passive",
        "type": "builtin",
        "configured": True,
    },
    "subfaster": {
        "name": "Subfaster",
        "description": "Fast passive subdomain enumerator (subfinder fork). Default keyless sources include crt.name, shodanct, rapiddns, thc, submd, hackertarget, sitedossier",
        "category": "passive",
        "type": "cli",
        "check_command": ["subfaster", "-h"],
        "installed": False,
        "version": None,
    },
    "wappalyzer": {
        "name": "Wappalyzer",
        "description": "Technology fingerprinting with 6,000+ fingerprints (CMS, frameworks, analytics, CDN, WAF, payment processors)",
        "category": "technology",
        "type": "builtin",
        "configured": True,
    },
    "knockpy": {
        "name": "Knockpy",
        "description": "Active subdomain brute-forcing and DNS enumeration with wordlist-based discovery",
        "category": "dns",
        "type": "cli",
        "check_command": ["knockpy", "-h"],
        "installed": False,
        "version": None,
    },
    "gau": {
        "name": "GAU (GetAllUrls)",
        "description": "Passive URL discovery from Wayback Machine, Common Crawl, OTX, and URLScan",
        "category": "passive",
        "type": "cli",
        "check_command": ["gau", "-version"],
        "installed": False,
        "version": None,
    },
    "kiterunner": {
        "name": "Kiterunner",
        "description": "API endpoint brute-forcer for discovering hidden REST/GraphQL API routes",
        "category": "fuzzer",
        "type": "cli",
        "check_command": ["kiterunner", "version"],
        "installed": False,
        "version": None,
    },
    "schemathesis": {
        "name": "Schemathesis",
        "description": "API fuzzer that auto-generates tests from OpenAPI/GraphQL schemas to find server errors and security flaws",
        "category": "fuzzer",
        "type": "cli",
        "check_command": ["schemathesis", "--version"],
        "installed": False,
        "version": None,
    },
    "browser_automation": {
        "name": "Browser Automation",
        "description": "Playwright-based headless browser for live exploit execution (XSS, injection, auth bypass, SSRF)",
        "category": "vulnerability",
        "type": "builtin",
        "configured": True,
    },
    "whatruns": {
        "name": "WhatRuns",
        "description": "Enhanced technology detection via WhatRuns API (CMS, JS frameworks, analytics, fonts, security)",
        "category": "technology",
        "type": "builtin",
        "configured": True,
    },
    # Not yet installed
    "amass": {
        "name": "OWASP Amass",
        "description": "In-depth attack surface mapping and asset discovery",
        "category": "dns",
        "type": "cli",
        "check_command": ["amass", "version"],
        "installed": False,
        "version": None,
    },
    "rustscan": {
        "name": "RustScan",
        "description": "Modern fast port scanner with adaptive timing",
        "category": "ports",
        "type": "cli",
        "check_command": ["rustscan", "--version"],
        "installed": False,
        "version": None,
    },
    "massdns": {
        "name": "MassDNS",
        "description": "High-performance DNS resolver for subdomain enumeration",
        "category": "dns",
        "type": "cli",
        "check_command": ["massdns", "--help"],
        "installed": False,
        "version": None,
    },
    "paramspider": {
        "name": "ParamSpider",
        "description": "Web parameter discovery from web archives (Wayback Machine)",
        "category": "crawler",
        "type": "cli",
        "check_command": ["paramspider", "-h"],
        "installed": False,
        "version": None,
    },
    "ffuf": {
        "name": "ffuf",
        "description": "Fast web fuzzer for directory/endpoint discovery",
        "category": "fuzzer",
        "type": "cli",
        "check_command": ["ffuf", "-V"],
        "installed": False,
        "version": None,
    },
    # API services not yet configured
    "virustotal": {
        "name": "VirusTotal",
        "description": "Domain and IP threat analysis and reputation",
        "category": "intelligence",
        "type": "api",
        "service_name": "virustotal",
        "configured": False,
    },
    "alienvault": {
        "name": "AlienVault OTX",
        "description": "Threat intelligence and passive DNS data",
        "category": "intelligence",
        "type": "api",
        "service_name": "alienvault_otx",
        "configured": False,
    },
    "chaos": {
        "name": "Chaos",
        "description": "ProjectDiscovery subdomain dataset for passive recon",
        "category": "passive",
        "type": "env_api",  # Uses environment variable for API key
        "env_key": "PDCP_API_KEY",
        "configured": False,
    },
    "certspotter": {
        "name": "CertSpotter",
        "description": "Certificate transparency log monitoring by SSLMate",
        "category": "passive",
        "type": "api",
        "service_name": "certspotter",
        "configured": False,
    },
    "rapiddns": {
        "name": "RapidDNS",
        "description": "Fast subdomain enumeration via RapidDNS",
        "category": "passive",
        "type": "builtin",
        "configured": True,  # Free API
    },
    "commoncrawl": {
        "name": "Common Crawl",
        "description": "Passive subdomain discovery from web archives",
        "category": "passive",
        "type": "builtin",
        "configured": True,  # Free API
    },
}

# Categories for grouping
CATEGORIES = {
    "vulnerability": {"name": "Vulnerability Scanning", "icon": "shield"},
    "dns": {"name": "DNS & Subdomain Enumeration", "icon": "globe"},
    "ports": {"name": "Port Scanning", "icon": "network"},
    "http": {"name": "HTTP Analysis", "icon": "globe"},
    "crawler": {"name": "Web Crawling", "icon": "spider"},
    "passive": {"name": "Passive Reconnaissance", "icon": "search"},
    "screenshot": {"name": "Screenshot Capture", "icon": "camera"},
    "whois": {"name": "WHOIS & Domain Intel", "icon": "info"},
    "intelligence": {"name": "Threat Intelligence", "icon": "alert"},
    "technology": {"name": "Technology Detection", "icon": "cpu"},
    "cloud": {"name": "Cloud Enumeration", "icon": "cloud"},
}


def check_cli_tool(tool_config: dict) -> dict:
    """Check if a CLI tool is installed and get its version."""
    result = tool_config.copy()
    
    if tool_config.get("check_path"):
        # Check if file exists
        import os
        result["installed"] = os.path.exists(tool_config["check_path"])
        if result["installed"]:
            result["version"] = "Installed"
        return result
    
    if not tool_config.get("check_command"):
        return result
    
    try:
        # Check if command exists
        if shutil.which(tool_config["check_command"][0]):
            result["installed"] = True
            # Try to get version
            try:
                proc = subprocess.run(
                    tool_config["check_command"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = proc.stdout or proc.stderr
                # Extract version from first line
                if output:
                    lines = output.strip().split('\n')
                    result["version"] = lines[0][:100]  # Limit length
            except:
                result["version"] = "Unknown"
        else:
            result["installed"] = False
    except Exception as e:
        result["installed"] = False
        result["error"] = str(e)
    
    return result


def check_api_tool(tool_config: dict, db: Session) -> dict:
    """Check if an API tool is configured."""
    import os
    result = tool_config.copy()
    
    if tool_config.get("type") == "builtin":
        result["configured"] = True
        return result
    
    # Check for environment variable based API keys (e.g., Chaos)
    if tool_config.get("type") == "env_api":
        env_key = tool_config.get("env_key")
        if env_key:
            api_key = os.environ.get(env_key, "")
            result["configured"] = bool(api_key)
        return result
    
    service_name = tool_config.get("service_name")
    if not service_name:
        return result
    
    # Check if API key exists in database
    config = db.query(APIConfig).filter(
        APIConfig.service_name == service_name,
        APIConfig.is_active == True
    ).first()
    
    result["configured"] = config is not None
    if config:
        result["organization_id"] = config.organization_id
    
    return result


@router.get("/status")
def get_tools_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get status of all enumeration tools."""
    tools_status = {}
    
    for tool_id, tool_config in TOOLS.items():
        if tool_config["type"] == "cli":
            tools_status[tool_id] = check_cli_tool(tool_config)
        else:
            tools_status[tool_id] = check_api_tool(tool_config, db)
    
    # Group by category
    by_category = {}
    for tool_id, tool_data in tools_status.items():
        category = tool_data.get("category", "other")
        if category not in by_category:
            by_category[category] = {
                **CATEGORIES.get(category, {"name": category, "icon": "tool"}),
                "tools": []
            }
        by_category[category]["tools"].append({
            "id": tool_id,
            **tool_data
        })
    
    # Calculate summary
    total = len(tools_status)
    installed_cli = sum(1 for t in tools_status.values() if t.get("type") == "cli" and t.get("installed"))
    configured_api = sum(1 for t in tools_status.values() if t.get("type") in ["api", "builtin", "env_api"] and t.get("configured"))
    
    return {
        "summary": {
            "total_tools": total,
            "cli_tools_installed": installed_cli,
            "cli_tools_total": sum(1 for t in tools_status.values() if t.get("type") == "cli"),
            "api_tools_configured": configured_api,
            "api_tools_total": sum(1 for t in tools_status.values() if t.get("type") in ["api", "builtin", "env_api"]),
        },
        "tools": tools_status,
        "by_category": by_category,
        "categories": CATEGORIES,
    }


@router.get("/categories")
def get_tool_categories():
    """Get tool categories."""
    return CATEGORIES


@router.get("/{tool_id}")
def get_tool_status(
    tool_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get status of a specific tool."""
    if tool_id not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found")
    
    tool_config = TOOLS[tool_id]
    
    if tool_config["type"] == "cli":
        return check_cli_tool(tool_config)
    else:
        return check_api_tool(tool_config, db)


@router.post("/{tool_id}/test")
async def test_tool(
    tool_id: str,
    target: Optional[str] = "example.com",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Test a specific tool with a sample target."""
    if tool_id not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found")
    
    tool_config = TOOLS[tool_id]
    
    if tool_config["type"] != "cli":
        return {"error": "Only CLI tools can be tested directly"}
    
    # Map tool to test command
    test_commands = {
        "nuclei": ["nuclei", "-u", target, "-silent", "-no-update-templates", "-timeout", "10"],
        "subfinder": ["subfinder", "-d", target, "-silent", "-timeout", "10"],
        "httpx": ["httpx", "-u", f"https://{target}", "-silent", "-timeout", "10"],
        "naabu": ["naabu", "-host", target, "-top-ports", "10", "-silent"],
        "masscan": ["masscan", target, "-p80", "--rate=100", "--wait=0"],
        "nmap": ["nmap", "-sT", "-p80", "--open", target],
        "dnsx": ["dnsx", "-d", target, "-silent"],
    }
    
    if tool_id not in test_commands:
        return {"error": f"No test command configured for {tool_id}"}
    
    try:
        proc = subprocess.run(
            test_commands[tool_id],
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout[:2000] if proc.stdout else None,
            "stderr": proc.stderr[:2000] if proc.stderr else None,
            "return_code": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out after 30 seconds"}
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# Data Schema & Field Mapping Endpoints
# =============================================================================

@router.get("/data-sources", response_model=List[Dict])
def list_data_sources(
    current_user: User = Depends(get_current_active_user)
):
    """
    List all supported data sources with their field mappings.
    
    Returns information about how each tool's output maps to the unified ASMDataModel.
    This is useful for understanding what fields are available from each source.
    """
    from app.services.data_normalizer_service import get_source_info, get_supported_sources
    from app.schemas.data_sources import DATA_SOURCE_MAPPINGS
    
    sources = []
    for source_name in get_supported_sources():
        info = get_source_info(source_name)
        if info:
            sources.append(info)
    
    return sources


@router.get("/data-sources/{source_name}", response_model=Dict)
def get_data_source_details(
    source_name: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get detailed field mapping for a specific data source.
    
    Shows how the tool's native output fields map to the unified ASMDataModel.
    """
    from app.services.data_normalizer_service import get_source_info
    from app.schemas.data_sources import (
        DataSourceType, get_source_mapping,
        get_fields_for_source, get_unmapped_fields_for_source
    )
    
    try:
        source = DataSourceType(source_name.lower())
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Unknown data source: {source_name}")
    
    info = get_source_info(source)
    if not info:
        raise HTTPException(status_code=404, detail=f"No mapping found for source: {source_name}")
    
    # Add additional details
    info["fields_populated"] = get_fields_for_source(source)
    info["fields_not_populated"] = get_unmapped_fields_for_source(source)
    
    return info


@router.get("/data-model/fields", response_model=Dict)
def get_data_model_schema(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the complete unified ASMDataModel schema with all fields.
    
    This shows ALL fields available in the normalized data model, 
    organized by category. Use this to understand what data can be
    collected across all sources.
    """
    from app.schemas.data_sources import ASMDataModel, list_all_model_fields
    
    # Get field info from Pydantic model
    schema = ASMDataModel.model_json_schema()
    
    # Organize fields by category (based on field names)
    categories = {
        "identification": [],
        "target": [],
        "finding": [],
        "service": [],
        "http": [],
        "tls": [],
        "dns": [],
        "vulnerability": [],
        "technology": [],
        "infrastructure": [],
        "geolocation": [],
        "whois": [],
        "screenshot": [],
        "email": [],
        "archive": [],
        "classification": [],
        "raw": [],
    }
    
    # Field prefixes to category mapping
    prefix_map = {
        "id": "identification",
        "source": "identification",
        "category": "identification",
        "timestamp": "identification",
        "first_seen": "identification",
        "last_seen": "identification",
        "organization_id": "identification",
        "asset_id": "identification",
        "scan_id": "identification",
        
        "target": "target",
        "hostname": "target",
        "ip": "target",
        "cidr": "target",
        "asn": "target",
        "url": "target",
        "scheme": "target",
        "path": "target",
        "query": "target",
        "port": "target",
        "protocol": "target",
        
        "title": "finding",
        "description": "finding",
        "severity": "finding",
        "confidence": "finding",
        "is_risky": "finding",
        "risk": "finding",
        
        "service": "service",
        "banner": "service",
        "cpe": "service",
        
        "http": "http",
        
        "tls": "tls",
        
        "dns": "dns",
        "cname": "dns",
        "mx": "dns",
        "ns": "dns",
        "txt": "dns",
        
        "vuln": "vulnerability",
        "template": "vulnerability",
        "cve": "vulnerability",
        "cwe": "vulnerability",
        "cvss": "vulnerability",
        "epss": "vulnerability",
        "exploit": "vulnerability",
        "patch": "vulnerability",
        "matched": "vulnerability",
        "matcher": "vulnerability",
        "extracted": "vulnerability",
        "curl": "vulnerability",
        "proof": "vulnerability",
        
        "tech": "technology",
        "framework": "technology",
        "cms": "technology",
        "language": "technology",
        
        "cdn": "infrastructure",
        "waf": "infrastructure",
        "cloud": "infrastructure",
        "hosting": "infrastructure",
        
        "country": "geolocation",
        "city": "geolocation",
        "region": "geolocation",
        "latitude": "geolocation",
        "longitude": "geolocation",
        
        "whois": "whois",
        
        "screenshot": "screenshot",
        
        "email": "email",
        
        "archive": "archive",
        "commoncrawl": "archive",
        
        "tag": "classification",
        "label": "classification",
        "categories": "classification",
        "reference": "classification",
        "evidence": "classification",
        "note": "classification",
        
        "raw": "raw",
    }
    
    all_fields = list_all_model_fields()
    properties = schema.get("properties", {})
    
    for field_name in all_fields:
        field_info = properties.get(field_name, {})
        
        # Find category
        category = "raw"
        for prefix, cat in prefix_map.items():
            if field_name.startswith(prefix):
                category = cat
                break
        
        categories[category].append({
            "name": field_name,
            "type": field_info.get("type", "any"),
            "description": field_info.get("description", ""),
            "default": field_info.get("default"),
        })
    
    return {
        "total_fields": len(all_fields),
        "categories": categories,
        "all_fields": all_fields,
    }


@router.post("/normalize-test", response_model=Dict)
def test_normalization(
    source: str,
    data: str,
    target: Optional[str] = None,
    current_user: User = Depends(get_current_active_user)
):
    """
    Test data normalization by converting raw tool output to unified format.
    
    Useful for debugging field mappings and understanding how data is normalized.
    """
    from app.services.data_normalizer_service import normalize_tool_output
    from app.schemas.data_sources import DataSourceType
    
    try:
        source_type = DataSourceType(source.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown data source: {source}")
    
    try:
        findings = normalize_tool_output(source_type, data, target=target)
        return {
            "success": True,
            "findings_count": len(findings),
            "findings": [f.model_dump(mode="json", exclude_none=True) for f in findings],
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "findings_count": 0,
            "findings": [],
        }




