"""
Specialized Security Agents for Aegis Vanguard

Defines the multi-agent architecture:
  Orchestrator -> Recon Agent -> Vuln Agent -> Exploit Agent -> Report Agent

Each agent has focused instructions, specific tools, and knows
when to hand off to the next agent in the chain.
"""

import json
import logging
from typing import List

from agent.core import Agent
from agent.tools import security_tool, ToolRegistry
from agent.http_session import (
    HttpRequest,
    apply_mutations,
    get_backend,
    get_session_store,
    response_diff,
    response_from_scanner_dict,
)
from agent.finding_oracle import register_proof
from agent.oob_oracle import get_oob_oracle

logger = logging.getLogger("agent.agents")

# Ensure scanners module is importable (adds /agent to path if needed)
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm_bridge import ASMBridge

_bridge = None

def _get_bridge() -> ASMBridge:
    global _bridge
    if _bridge is None:
        _bridge = ASMBridge()
    return _bridge


# =========================================================================
# Registered Security Tools (wrapped scanners for LLM tool-calling)
# =========================================================================

@security_tool(category="recon", risk="safe")
def scan_subdomains(domain: str, timeout: int = 300) -> str:
    """Enumerate subdomains for a domain using subfinder, subfaster, and subcat.

    Args:
        domain: Root domain to enumerate (e.g. example.com)
        timeout: Max seconds to run per tool
    """
    import scanners
    results_subfinder = scanners.run_subfinder(domain, _get_bridge(), timeout=timeout)
    results_subfaster = scanners.run_subfaster(domain, _get_bridge(), timeout=min(timeout, 180))
    results_subcat = scanners.run_subcat(domain, _get_bridge(), timeout=min(timeout, 180))
    results = list(set(results_subfinder + results_subfaster + results_subcat))
    return json.dumps({"subdomains": results, "count": len(results)})


@security_tool(category="recon", risk="safe")
def resolve_dns(hosts: list, timeout: int = 300) -> str:
    """Resolve hostnames to IPs using dnsx.

    Args:
        hosts: List of hostnames to resolve
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_dnsx(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"resolved": results, "count": len(results)})


@security_tool(category="recon", risk="safe")
def probe_http(hosts: list, timeout: int = 300) -> str:
    """Probe hosts for live HTTP services, detect technologies and status codes.

    Args:
        hosts: List of hostnames or IPs to probe
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_httpx(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"live_hosts": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="low")
def scan_ports(target: str, ports: str = "top-1000", rate: int = 1000, timeout: int = 600) -> str:
    """Fast port scanning using naabu.

    Args:
        target: Host or IP to scan
        ports: Port spec (top-1000, full, or specific like 80,443,8080)
        rate: Packets per second
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_naabu(target, _get_bridge(), ports=ports, rate=rate, timeout=timeout)
    return json.dumps({"ports": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="low")
def scan_ports_nmap(target: str, ports: str = "1-1000", args: str = "-sV -sC", timeout: int = 900) -> str:
    """Service detection and scripting via nmap.

    Args:
        target: Host or IP to scan
        ports: Port range
        args: Nmap arguments
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_nmap(target, _get_bridge(), ports=ports, args=args, timeout=timeout)
    return json.dumps({"services": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="safe")
def fingerprint_tech(target_url: str, timeout: int = 300) -> str:
    """Identify technologies, frameworks, and CMS using whatweb.

    Args:
        target_url: URL to fingerprint
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_whatweb(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"technologies": results}, default=str)


@security_tool(category="recon", risk="safe")
def detect_waf(target_url: str, timeout: int = 120) -> str:
    """Detect Web Application Firewall using wafw00f.

    Args:
        target_url: URL to check for WAF
        timeout: Max seconds to run
    """
    import scanners
    waf = scanners.run_wafw00f(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"waf_detected": waf or None})


@security_tool(category="recon", risk="safe")
def detect_cms(target_url: str, timeout: int = 300) -> str:
    """Detect Content Management System using CMSeeK.

    Args:
        target_url: URL to check for CMS
        timeout: Max seconds to run
    """
    import scanners
    cms = scanners.run_cmseek(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"cms_detected": cms or None})


@security_tool(category="recon", risk="safe")
def fingerprint_gitlab(target_url: str, hash_db_path: str = "", timeout: int = 30) -> str:
    """Fingerprint GitLab instances by hashing /help stylesheet assets.

    Non-destructive version-correlation technique inspired by Praetorian-style
    GitLab assessments. It fetches /help, hashes linked CSS assets, and compares
    them against an optional local hash database. It does NOT execute exploits
    or send out-of-band RCE payloads.

    Args:
        target_url: GitLab base URL or candidate URL
        hash_db_path: Optional JSON hash database path; defaults to GITLAB_HASH_DB_PATH
        timeout: HTTP timeout per request
    """
    import scanners
    result = scanners.run_gitlab_fingerprint(
        target_url=target_url,
        bridge=_get_bridge(),
        hash_db_path=hash_db_path,
        timeout=timeout,
    )
    return json.dumps(result, default=str)


@security_tool(category="recon", risk="safe")
def crawl_urls(target_url: str, depth: int = 5, timeout: int = 600) -> str:
    """Crawl a web application to discover URLs and endpoints using katana.

    Args:
        target_url: Starting URL to crawl
        depth: Crawl depth
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_katana(target_url, _get_bridge(), depth=depth, timeout=timeout)
    return json.dumps({"urls": results[:400], "total_count": len(results)})


@security_tool(category="recon", risk="safe")
def scan_js_urls_for_secrets(urls: str, max_urls: int = 30) -> str:
    """Download remote JavaScript and scan for hardcoded secrets (Gitleaks + regex + CWE-321 client HMAC).

    Detects Object.keys(obj).join("") HMAC-SHA256 signing keys, MQTT/RFID ICS creds,
    client_id/client_secret, and EmailJS keys. Large Angular main-es2015 bundles (5–10MB)
    are in scope. If client_signing_summary.submit_without_live_api is true, public
    reconstruction is the finding — API timeout is not a kill.

    Use after crawl_urls or discover_historical_urls: pass discovered .js URLs (newline- or comma-separated).

    Args:
        urls: Newline- or comma-separated https URLs to fetch and scan
        max_urls: Maximum URLs to fetch (default 30, max 100)
    """
    import scanners
    try:
        mu = int(max_urls) if max_urls is not None else 30
    except (TypeError, ValueError):
        mu = 30
    result = scanners.run_js_url_secret_scan(urls, _get_bridge(), max_urls=mu)
    return json.dumps(result, default=str)


@security_tool(category="recon", risk="safe")
def analyze_js_with_jsluice(urls: str, max_urls: int = 20) -> str:
    """Extract endpoints, paths, and hardcoded secrets from JavaScript files using jsluice (BishopFox).

    Uses AST-based analysis rather than regex — accurately finds URLs passed to fetch(),
    XHR, document.location, window.open(), etc., and detects hardcoded secrets with context.
    Complements scan_js_urls_for_secrets (gitleaks) with deeper structural JS analysis.

    Use after crawl_urls to analyse discovered .js bundles for hidden API endpoints and leaked credentials.

    Args:
        urls: Newline- or comma-separated JS file URLs to fetch and analyse
        max_urls: Maximum number of URLs to process (default 20, max 50)
    """
    import scanners
    raw = urls.replace(",", "\n")
    parsed = [u.strip() for u in raw.splitlines() if u.strip().startswith("http")]
    try:
        limit = min(int(max_urls) if max_urls else 20, 50)
    except (TypeError, ValueError):
        limit = 20
    result = scanners.run_jsluice(parsed[:limit], _get_bridge())
    return json.dumps(result, default=str)


@security_tool(category="recon", risk="safe")
def discover_historical_urls(domain: str, timeout: int = 300) -> str:
    """Find historical URLs from Wayback Machine and other archives.

    Args:
        domain: Domain to search historical URLs for
        timeout: Max seconds to run
    """
    import scanners
    wb = scanners.run_waybackurls(domain, _get_bridge(), timeout=timeout)
    gau_urls = scanners.run_gau(domain, _get_bridge(), timeout=timeout)
    combined = list(set(wb + gau_urls))
    return json.dumps({"urls": combined[:300], "total_count": len(combined)})


@security_tool(category="recon", risk="low")
def fuzz_directories(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 600) -> str:
    """Fuzz directories and API paths using ffuf.

    Args:
        target_url: Base URL to fuzz (FUZZ keyword appended automatically)
        wordlist: Path to wordlist file
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_ffuf(target_url, _get_bridge(), wordlist=wordlist, timeout=timeout)
    return json.dumps({"paths": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="low")
def discover_parameters(target_url: str, timeout: int = 300) -> str:
    """Discover hidden HTTP parameters on an endpoint using arjun.

    Args:
        target_url: URL to discover parameters on
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_arjun(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"parameters": results, "count": len(results)})


@security_tool(category="recon", risk="low")
def discover_api_surface(target_url: str, timeout: int = 120, max_pages: int = 20) -> str:
    """Discover API endpoints from browser traffic, page links, scripts, and JSON responses.

    Blackbox-safe Vespasian-style inventory pass. Use it after initial crawling,
    especially for SPAs, API-heavy applications, GraphQL apps, or targets where
    katana finds few URLs. It observes traffic and extracts endpoint structure;
    it does not mutate data or attempt authorization bypasses.

    Args:
        target_url: Starting URL to observe and crawl
        timeout: Max seconds to run
        max_pages: Maximum pages to visit while observing traffic
    """
    import scanners
    results = scanners.run_api_surface_discovery(
        target_url, _get_bridge(), timeout=timeout, max_pages=max_pages
    )
    return json.dumps(results, default=str)


# --- Vulnerability Analysis Tools ---

@security_tool(category="recon", risk="low")
def reverse_whois_search(
    terms: str,
    search_type: str = "current",
    mode: str = "preview",
    exclude: str = "",
    max_terms: int = 10,
    max_domains: int = 500,
    timeout: int = 60,
) -> str:
    """Search WhoisXML reverse WHOIS for related domains by brand, org, email, or domain term.

    Blackbox-safe OSINT pivot inspired by haltman-io/reverse-whois. Defaults to
    preview mode, which returns counts only, to avoid unexpectedly spending API
    credits on full domain-list retrieval. Use mode="purchase" only when the
    engagement authorizes retrieving domain lists from WhoisXML.

    Args:
        terms: Newline- or comma-separated search terms (brand, org, email, domain)
        search_type: current or historic
        mode: preview for counts only, purchase for matching domains
        exclude: Optional newline- or comma-separated exclusion terms (max 4)
        max_terms: Maximum terms to query
        max_domains: Maximum returned domains to keep
        timeout: HTTP timeout per API request
    """
    import scanners
    result = scanners.run_reverse_whois_search(
        terms=terms,
        bridge=_get_bridge(),
        search_type=search_type,
        mode=mode,
        exclude=exclude,
        max_terms=max_terms,
        max_domains=max_domains,
        timeout=timeout,
    )
    return json.dumps(result, default=str)


@security_tool(category="recon", risk="safe")
def atlas_map_attack_surface(
    org: str,
    domain: str = "",
    asn: str = "",
    mode: str = "passive",
    timeout: int = 900,
) -> str:
    """Atlas — map an organization's external attack surface (wraps Praetorian pius).

    Given a company name, discovers owned domains, subdomains, and IP netblocks
    (CIDRs) across all 5 RIRs using 24+ OSINT plugins (CT logs, passive DNS,
    WHOIS, GLEIF, BGP, etc.). Each result is streamed to the ASM platform.

    Args:
        org: Organization / company name (required, e.g. "Acme Corp")
        domain: Optional known root domain hint (unlocks crt-sh, DNS plugins)
        asn: Optional ASN hint (e.g. "AS12345") for direct BGP lookup
        mode: "passive" (default, safe), "active", or "all"
        timeout: Max seconds to run
    """
    import scanners
    summary = scanners.run_atlas(
        org=org,
        bridge=_get_bridge(),
        domain=domain or None,
        asn=asn or None,
        mode=mode,
        timeout=timeout,
    )
    return json.dumps(summary, default=str)


# --- Swagger / OpenAPI Discovery & Testing ---

@security_tool(category="recon", risk="safe")
def discover_swagger_spec(target_url: str, timeout: int = 60) -> str:
    """Discover exposed Swagger/OpenAPI spec files using multi-phase discovery.

    Runs three phases (AutoSwagger-style):
    1. Direct spec check — if target_url ends in .json/.yaml, parse it directly.
    2. Swagger UI scraping — probe known UI paths (/swagger-ui, /docs, /redoc)
       and extract the embedded spec URL from the HTML/JS initializer.
    3. Common-path bruteforce — probe 30+ standard spec paths on the origin
       (/swagger.json, /openapi.json, /api-docs, /v2/api-docs, etc.).

    When a spec is found, returns all documented endpoints (method, path, operationId,
    summary, tags) so the agent can prioritize which to test. Also submits the exposed
    spec as an informational finding to the ASM platform.

    Use this whenever an API surface or Swagger-like interface is suspected. Follow
    with test_swagger_api to exercise the discovered endpoints for data exposure.

    Args:
        target_url: Base URL or direct spec URL (e.g. https://api.example.com)
        timeout:    Max seconds to run
    """
    import scanners
    result = scanners.run_swagger_spec_discovery(target_url, _get_bridge(), timeout=timeout)
    return json.dumps(result, default=str)


@security_tool(category="vuln_analysis", risk="low")
def test_swagger_api(
    target_url: str,
    risk_mode: bool = False,
    brute_params: bool = False,
    rate: int = 20,
    timeout: int = 300,
) -> str:
    """Test all documented API endpoints for unauthenticated access, PII exposure, and secret leakage.

    Implements AutoSwagger-style endpoint testing:
    1. Discovers the OpenAPI/Swagger spec automatically (same phases as discover_swagger_spec).
    2. Exercises every documented endpoint — GET only by default; set risk_mode=True to also
       test POST/PUT/PATCH/DELETE (requires explicit engagement authorization).
    3. Scans each response for PII — emails, phone numbers, SSNs, credit cards — using
       contextual regex patterns (Presidio-inspired, reduces false positives).
    4. Scans responses for leaked secrets using TruffleHog-style patterns — AWS keys,
       GitHub tokens, JWTs, database URLs, Stripe keys, generic API keys, private keys.
    5. Flags large JSON responses (>5 KB) that may represent unintended bulk data exposure.

    Uses the autoswagger CLI (intruder-io/autoswagger) if installed; otherwise falls back
    to a native httpx-based tester. All flagged findings are submitted to the ASM platform.

    Typical workflow:
      1. discover_swagger_spec → shows documented endpoints and spec location
      2. test_swagger_api → confirms which are unauthenticated and what data leaks

    Args:
        target_url:   Base URL or spec URL of the target API
        risk_mode:    Include non-GET methods (POST/PUT/PATCH/DELETE) — only when authorized
        brute_params: Exhaustively fuzz parameter values to bypass naive validations
        rate:         Max requests per second (default 20; 0 = no limit)
        timeout:      Max seconds to run
    """
    import scanners
    result = scanners.run_autoswagger(
        target_url=target_url,
        bridge=_get_bridge(),
        risk=risk_mode,
        brute=brute_params,
        rate=rate,
        timeout=timeout,
    )
    return json.dumps(result, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def argus_scan_secrets(path: str, validate: bool = False, timeout: int = 900) -> str:
    """Argus — all-seeing secrets scanner (wraps Praetorian titus, 487 rules).

    Scans a filesystem path (directory / file / local git repo) for leaked
    credentials across AWS, GCP, Azure, GitHub, Slack, databases, CI/CD, etc.
    When validate=True, detected secrets are checked against their source
    APIs and marked active / inactive (slower, makes outbound requests).

    Args:
        path: Absolute filesystem path (directory, file, or git clone) to scan
        validate: Enable live credential validation (default False)
        timeout: Max seconds to run
    """
    import scanners
    findings = scanners.run_argus(
        path=path,
        bridge=_get_bridge(),
        validate=validate,
        timeout=timeout,
    )
    return json.dumps({"findings": findings, "count": len(findings)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def hermes_scan_remote_secrets(
    source: str,
    target: str,
    only_verified: bool = False,
    timeout: int = 900,
) -> str:
    """Hermes — remote secrets-finder (wraps TruffleHog v3, 800+ detectors).

    Hunts leaked credentials in sources that live OUTSIDE the local filesystem —
    GitHub/GitLab orgs, S3/GCS/Azure buckets, Docker images, Postman workspaces,
    Jenkins, Jira, Confluence, etc. Complement to Argus (local paths).

    Args:
        source: One of: git, github, gitlab, s3, gcs, azure, docker, postman,
                jenkins, jira, confluence, filesystem
        target: Primary target for the source — repo URL for git, org name for
                github/gitlab, bucket for s3, image ref for docker, directory
                for filesystem, etc.
        only_verified: Emit only live-validated credentials (reduces noise)
        timeout: Max seconds to run
    """
    import scanners
    findings = scanners.run_hermes(
        source=source,
        target=target,
        bridge=_get_bridge(),
        only_verified=only_verified,
        timeout=timeout,
    )
    return json.dumps({"findings": findings, "count": len(findings)}, default=str)


@security_tool(category="vuln_analysis", risk="low")
def janus_dast_baseline(target_url: str, minutes: int = 5, ajax: bool = False, timeout: int = 1800) -> str:
    """Janus (baseline) — passive DAST gatekeeper (wraps OWASP ZAP).

    Runs ZAP's baseline scan: spider + passive rules only. Safe for
    continuous monitoring / CI. Finds missing security headers, cookie flags,
    information disclosure, SSL/TLS issues that the app's *responses* already
    reveal — without sending attack payloads.

    Args:
        target_url: Fully qualified URL (https://example.com)
        minutes: Max spider duration (caps ZAP internal timer)
        ajax: Enable ajax-spider (required for heavy SPAs)
        timeout: Outer subprocess timeout (seconds)
    """
    import scanners
    summary = scanners.run_janus(
        target_url=target_url,
        bridge=_get_bridge(),
        mode="baseline",
        minutes=minutes,
        ajax=ajax,
        timeout=timeout,
    )
    return json.dumps(summary, default=str)


@security_tool(category="exploit", risk="high")
def janus_dast_full(target_url: str, minutes: int = 10, ajax: bool = False, timeout: int = 3600) -> str:
    """Janus (full) — active DAST with real attack payloads (wraps OWASP ZAP).

    Runs ZAP's full-scan: baseline + active scan. Sends attack payloads to
    discover reflective XSS, SQLi, command injection, insecure deserialisation,
    CSRF, CORS misconfigs, and business-logic flaws nuclei can't find (spider-
    aware, session-aware). **In-scope only** — requires written authorization.

    Args:
        target_url: Fully qualified URL (https://example.com)
        minutes: Max spider/scan duration (caps ZAP internal timer)
        ajax: Enable ajax-spider (required for heavy SPAs)
        timeout: Outer subprocess timeout (seconds, should exceed minutes*60)
    """
    import scanners
    summary = scanners.run_janus(
        target_url=target_url,
        bridge=_get_bridge(),
        mode="full",
        minutes=minutes,
        ajax=ajax,
        timeout=timeout,
    )
    return json.dumps(summary, default=str)


@security_tool(category="vuln_analysis", risk="low")
def scan_nuclei(target: str, templates: str = "", severity: str = "low,medium,high,critical", timeout: int = 900) -> str:
    """Run nuclei vulnerability scanner with template-based detection.

    Args:
        target: URL or host to scan
        templates: Specific template path/tag (empty = all templates)
        severity: Comma-separated severity filter
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_nuclei(
        target, _get_bridge(), templates=templates or None, severity=severity, timeout=timeout,
    )
    summary = []
    for v in results:
        info = v.get("info", {})
        summary.append({
            "template": v.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "matched_at": v.get("matched-at"),
            "tags": info.get("tags", [])[:5],
        })
    return json.dumps({"vulnerabilities": summary, "count": len(summary)}, default=str)


@security_tool(category="vuln_analysis", risk="low")
def scan_nikto(target: str, timeout: int = 600) -> str:
    """Web server vulnerability scanning via nikto.

    Args:
        target: URL to scan
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_nikto(target, _get_bridge(), timeout=timeout)
    return json.dumps({"findings": results, "count": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def analyze_security_headers(hosts: list, timeout: int = 300) -> str:
    """Check security headers (HSTS, CSP, X-Frame-Options, CORS) on live hosts.

    Args:
        hosts: List of hostnames to analyze
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_security_headers(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results, "count": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def analyze_tls(hosts: list, timeout: int = 300) -> str:
    """Deep TLS/SSL analysis: cipher grading, cert scoring A-F, key analysis.

    Args:
        hosts: List of hostnames to analyze TLS on
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_tlsx(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results, "count": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def check_subdomain_takeover(hosts: list, timeout: int = 300) -> str:
    """Check subdomains for dangling CNAME takeover vulnerabilities (55+ fingerprints).

    Args:
        hosts: List of subdomains to check
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_subdomain_takeover(hosts, _get_bridge(), timeout=timeout)
    risky = [r for r in results if r.get("status") in ("confirmed", "potential")]
    return json.dumps({"results": results, "at_risk": len(risky), "total": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def analyze_mail_security(domains: list, timeout: int = 300) -> str:
    """Map mail infrastructure: MX, SPF, DKIM, DMARC, BIMI, MTA-STS, DANE with risk scoring.

    Args:
        domains: List of root domains to analyze
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_mail_intel(domains, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def detect_third_party_vendors(hosts: list, timeout: int = 300) -> str:
    """Detect third-party vendors from response body, CSP headers, and JS sources.

    Args:
        hosts: List of hostnames to analyze
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_third_party_intel(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results}, default=str)


# --- Exploit Validation Tools ---

@security_tool(category="exploit", risk="high")
def sql_injection_test(
    target_url: str,
    timeout: int = 600,
    data: str = "",
    param: str = "",
    cookie: str = "",
    method: str = "",
    level: int = 3,
    risk: int = 2,
) -> str:
    """Confirm SQL injection with sqlmap after probe_sqli_params flags a candidate.

    Prefer probe_sqli_params first to find the parameter, then call this with
    param= that name. Supports POST --data and cookies.

    Args:
        target_url: URL with parameters (e.g. https://site.com/page?id=1)
        timeout: Max seconds to run
        data: Optional POST body (form-urlencoded or as needed by sqlmap --data)
        param: Specific parameter name to test (-p)
        cookie: Cookie header value
        method: Optional HTTP method override
        level: sqlmap level 1-5 (default 3)
        risk: sqlmap risk 1-3 (default 2)
    """
    import scanners
    results = scanners.run_sqlmap(
        target_url,
        _get_bridge(),
        timeout=timeout,
        data=data,
        param=param,
        cookie=cookie,
        method=method,
        level=level,
        risk=risk,
    )
    return json.dumps({
        "results": results,
        "findings": results,
        "vulnerable": len(results) > 0,
        "count": len(results),
    }, default=str)


@security_tool(category="exploit", risk="high")
def xss_test(target_url: str, timeout: int = 300) -> str:
    """Test a URL for reflected XSS using XSStrike.

    Prefer probe_xss_reflection first to map reflection contexts, then xss_test /
    test_dom_xss for confirmation.

    Args:
        target_url: URL with parameters to test for XSS
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_xsstrike(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({
        "results": results,
        "findings": results,
        "vulnerable": len(results) > 0,
        "count": len(results),
    }, default=str)


@security_tool(category="exploit", risk="high")
def probe_sqli_params(
    target_url: str,
    method: str = "GET",
    body: str = "",
    params: str = "",
    headers_json: str = "{}",
    timeout: int = 25,
) -> str:
    """Deterministic SQLi differential probe across parameters.

    For each param: baseline → quote error → boolean true/false → short time delay.
    Call this BEFORE sql_injection_test. Returns candidates with signals.

    Priority params: id, search, q, sort, filter, page, order_id, user_id, etc.

    Args:
        target_url: URL to probe (include query string when possible)
        method: GET or POST
        body: POST body if applicable
        params: Comma-separated param names (optional — auto-detected from URL/body)
        headers_json: Optional request headers JSON
        timeout: Per-request timeout seconds
    """
    import scanners
    result = scanners.run_probe_sqli_params(
        target_url,
        _get_bridge(),
        method=method,
        body=body,
        params=params,
        headers_json=headers_json,
        timeout=timeout,
    )
    return json.dumps(result, default=str)


@security_tool(category="exploit", risk="high")
def probe_xss_reflection(
    target_url: str,
    method: str = "GET",
    body: str = "",
    params: str = "",
    headers_json: str = "{}",
    timeout: int = 20,
) -> str:
    """Map XSS reflection contexts with a unique canary, then try context payloads.

    Call this BEFORE xss_test / test_dom_xss. Returns reflections[] (param → context)
    and any unescaped-payload candidates.

    Args:
        target_url: URL to probe
        method: GET or POST
        body: POST body if applicable
        params: Comma-separated param names (optional)
        headers_json: Optional request headers JSON
        timeout: Per-request timeout seconds
    """
    import scanners
    result = scanners.run_probe_xss_reflection(
        target_url,
        _get_bridge(),
        method=method,
        body=body,
        params=params,
        headers_json=headers_json,
        timeout=timeout,
    )
    return json.dumps(result, default=str)


@security_tool(category="exploit", risk="medium")
def wordpress_scan(target_url: str, timeout: int = 600) -> str:
    """Scan a WordPress site for vulnerabilities using wpscan.

    Args:
        target_url: WordPress site URL
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_wpscan(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"findings": results, "count": len(results)}, default=str)


@security_tool(category="exploit", risk="medium")
def deep_tls_test(target: str, timeout: int = 600) -> str:
    """Comprehensive TLS testing via testssl.sh for hosts with poor TLS grades.

    Args:
        target: Hostname to test
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_testssl(target, _get_bridge(), timeout=timeout)
    return json.dumps({"issues": results, "count": len(results)}, default=str)


# --- Browser / Playwright Tools ---

@security_tool(category="recon", risk="low")
def crawl_urls_authenticated(
    target_url: str,
    username: str = "",
    password: str = "",
    timeout: int = 120,
) -> str:
    """Crawl a web application using a real Chromium browser (Playwright), handling JS-rendered SPAs and optional authentication.

    Prefer over crawl_urls when: the target is a React/Angular/Vue SPA, authentication
    is required to access deeper routes, or katana misses routes that only appear after
    user interaction or client-side routing.

    Args:
        target_url: Starting URL to crawl
        username: Optional login username — attempts to fill a login form if provided
        password: Optional login password
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_playwright_crawl_authenticated(
        target_url, _get_bridge(), username=username, password=password, timeout=timeout
    )
    return json.dumps({"urls": results[:500], "total_count": len(results)})


@security_tool(category="exploit", risk="high")
def test_dom_xss(
    target_url: str,
    params: str = "",
    timeout: int = 60,
) -> str:
    """Test for DOM-based XSS using a real Chromium browser (Playwright).

    Detects payloads that execute in the JavaScript context but produce no reflection
    in HTTP responses — a class of vulnerability entirely missed by XSStrike and nuclei.
    Tests URL fragment (#), query parameter, and common sink injections.

    Use after xss_test when: XSStrike finds nothing but the target has heavy
    client-side JS, hash-based routing, or postMessage/eval sinks.

    Args:
        target_url: URL to test (parameters optional — pass via params arg)
        params: Comma-separated parameter names to inject (e.g. "q,search,redirect")
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_dom_xss_test(
        target_url, _get_bridge(), params=params, timeout=timeout
    )
    confirmed = len(results) > 0
    # A DOM-XSS hit here means a payload actually executed JS in a real browser
    # (dialog fired / window.__vanguard_xss set) — a verified browser_exec proof.
    try:
        register_proof("browser_exec", verified=confirmed, subject=target_url,
                       detail=f"DOM XSS: {len(results)} executing payload(s)")
    except Exception as e:
        logger.debug("proof registration failed for dom xss: %s", e)
    return json.dumps({
        "findings": results,
        "count": len(results),
        "confirmed": confirmed,
    })


@security_tool(category="exploit", risk="high")
def confirm_vulnerability_poc(
    host: str,
    finding_title: str,
    vuln_type: str,
    endpoint: str,
    payload: str,
    request_raw: str = "",
    response_snippet: str = "",
    current_severity: str = "medium",
    tool: str = "",
) -> str:
    """Confirm a vulnerability with PoC evidence and submit to the platform with escalated severity.

    Call this after ANY tool (sqlmap, xss_test, test_dom_xss, nuclei) produces a
    positive finding. Attaches the request/response proof to the finding record and
    automatically escalates severity based on confirmation
    (e.g. medium SQLi → critical, medium XSS → high).

    Args:
        host: Hostname of the target (e.g. api.example.com)
        finding_title: Short description of the finding (e.g. "SQL Injection in /login")
        vuln_type: Vulnerability class: sqli, xss, dom-xss, ssrf, rce, idor, lfi, ssti, xxe
        endpoint: The exact URL or endpoint where the vuln was confirmed
        payload: The payload that triggered the vulnerability
        request_raw: Raw HTTP request (method + headers + body) used in the PoC
        response_snippet: Relevant portion of the HTTP response proving exploitation
        current_severity: Severity from the original detection (info/low/medium/high/critical)
        tool: Tool that produced the confirmation (sqlmap, playwright, xsstrike, nuclei, manual)
    """
    from asm_bridge import PoCEvidence
    poc = PoCEvidence(
        vuln_type=vuln_type,
        endpoint=endpoint,
        payload=payload,
        request_raw=request_raw,
        response_snippet=response_snippet,
        tool=tool or vuln_type,
    )
    bridge = _get_bridge()
    escalated = bridge.confirm_finding(
        host=host,
        title=finding_title,
        vuln_type=vuln_type,
        poc=poc,
        current_severity=current_severity,
    )
    bridge.flush()
    return json.dumps({
        "confirmed": True,
        "finding": finding_title,
        "title": finding_title,
        "name": finding_title,
        "host": host,
        "vuln_type": vuln_type,
        "original_severity": current_severity,
        "escalated_severity": escalated,
        "severity": escalated,
        "escalated": escalated != current_severity,
        "poc_endpoint": endpoint,
        "endpoint": endpoint,
        "url": endpoint,
        "matched_at": endpoint,
        "payload": payload,
        "findings": [{
            "title": finding_title,
            "name": finding_title,
            "url": endpoint,
            "matched_at": endpoint,
            "severity": escalated,
            "vuln_type": vuln_type,
            "host": host,
            "confirmed": True,
            "payload": payload,
            "source": tool or "confirm_vulnerability_poc",
        }],
    })


# --- Reporting Tools ---

@security_tool(category="report", risk="safe")
def generate_report(
    target_url: str,
    scope_domain: str,
    pre_recon: str,
    discovery: str,
    vuln_analysis: str,
    exploit_validation: str,
) -> str:
    """Generate comprehensive pentest report from collected findings.

    Args:
        target_url: The target URL that was tested
        scope_domain: Root domain scope
        pre_recon: JSON string of pre-recon findings
        discovery: JSON string of discovery findings
        vuln_analysis: JSON string of vulnerability analysis findings
        exploit_validation: JSON string of exploit validation findings
    """
    from reporter import PentestReporter

    report = PentestReporter(
        target_url=target_url,
        scope_domain=scope_domain,
        started_at="",
        pre_recon=json.loads(pre_recon) if isinstance(pre_recon, str) else pre_recon,
        discovery=json.loads(discovery) if isinstance(discovery, str) else discovery,
        vuln_analysis=json.loads(vuln_analysis) if isinstance(vuln_analysis, str) else vuln_analysis,
        exploit_validation=json.loads(exploit_validation) if isinstance(exploit_validation, str) else exploit_validation,
        bridge_stats=_get_bridge().stats,
    ).generate()

    report_path = "/agent/workspaces/latest/deliverables/pentest_report.md"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)

    return json.dumps({"report_path": report_path, "report_length": len(report)})


@security_tool(category="report", risk="safe")
def submit_findings_to_platform() -> str:
    """Flush any remaining buffered findings to the ASM platform."""
    bridge = _get_bridge()
    bridge.flush()
    return json.dumps({"stats": bridge.stats})


# =========================================================================
# Manual Probing Tools (new — enables CSRF, OAuth, open redirect, race testing)
# =========================================================================

@security_tool(category="exploit", risk="medium")
def send_http_request(
    method: str,
    url: str,
    headers_json: str = "{}",
    body: str = "",
    follow_redirects: bool = True,
) -> str:
    """Send a single HTTP request with custom method, headers, and body.

    Use for: manual CSRF probes, OAuth redirect_uri tests, open redirect confirmation,
    custom header injection tests, and any case where a specific raw request is needed.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
        url: Full URL (must be in-scope — out-of-scope URLs are blocked by guardrails)
        headers_json: JSON object of request headers (e.g. '{"Origin": "https://evil.com"}')
        body: Request body string (plain text, JSON, or form-encoded)
        follow_redirects: Whether to follow HTTP redirects (default True)
    """
    import scanners
    result = scanners.run_send_http_request(
        method=method,
        url=url,
        headers_json=headers_json,
        body=body,
        follow_redirects=follow_redirects,
        bridge=_get_bridge(),
    )
    # Record into the session store so this request can later be replayed under
    # a mutated identity (see replay_request) — the substrate for authz/IDOR/CSRF
    # proof. Never let bookkeeping break the tool.
    try:
        headers = json.loads(headers_json) if headers_json and headers_json.strip() else {}
    except (ValueError, TypeError):
        headers = {}
    try:
        txn = get_session_store().record(
            HttpRequest(method=method, url=url, headers=headers, body=body),
            response_from_scanner_dict(result),
        )
        if isinstance(result, dict):
            result = {**result, "transaction_id": txn.id}
    except Exception as e:
        logger.debug("session record failed for %s %s: %s", method, url, e)
    return json.dumps(result, default=str)


@security_tool(category="exploit", risk="medium")
def replay_request(
    transaction_id: str = "",
    method: str = "",
    url: str = "",
    headers_json: str = "{}",
    body: str = "",
    mutations_json: str = "{}",
) -> str:
    """Replay a request under a mutation and diff the response — the proof
    primitive for broken access control / IDOR / CSRF.

    Give a recorded `transaction_id` (from send_http_request or
    session_transactions) OR an inline request (method+url+headers_json+body),
    plus `mutations_json` describing how to change the identity/parameters:

      {"strip_auth": true}                          # replay as nobody
      {"set_headers": {"Cookie": "session=<victim>"}}  # replay as another user
      {"set_query": {"id": "1002"}}                 # IDOR: another object id

    Returns the original response, the mutated response, and a structured diff.
    A near-identical 200 under a changed/absent identity is the signature of
    broken access control — the two responses are the evidence.
    """
    store = get_session_store()
    backend = get_backend()

    base_txn = store.get(transaction_id) if transaction_id else None
    if base_txn is not None:
        base_req = base_txn.request
        base_resp = base_txn.response
    else:
        if not url:
            return json.dumps({"error": "provide transaction_id or method+url"})
        try:
            headers = json.loads(headers_json) if headers_json and headers_json.strip() else {}
        except (ValueError, TypeError):
            return json.dumps({"error": f"headers_json is not valid JSON: {headers_json[:120]}"})
        base_req = HttpRequest(method=method or "GET", url=url, headers=headers, body=body)
        base_txn = store.exchange(backend, base_req, label="replay:baseline")
        base_resp = base_txn.response

    try:
        mutations = json.loads(mutations_json) if mutations_json and mutations_json.strip() else {}
    except (ValueError, TypeError):
        return json.dumps({"error": f"mutations_json is not valid JSON: {mutations_json[:120]}"})

    mutated_req = apply_mutations(base_req, mutations)
    mutated_txn = store.exchange(backend, mutated_req, label="replay:mutated")
    diff = response_diff(base_resp, mutated_txn.response)

    # Register a proof token for the finding gate. The broken-access-control
    # signature is an identity change (strip_auth / set_headers) that still
    # returns the same 2xx body — access was NOT re-checked. Object-id swaps
    # (set_query) are recorded but not auto-verified: same-vs-different body
    # there needs two-account reasoning, so leave that to the analyst.
    identity_changed = bool(mutations.get("strip_auth") or mutations.get("set_headers"))
    bac_signature = (
        identity_changed
        and diff.get("identical_body")
        and mutated_txn.response.status == base_resp.status
        and 200 <= (base_resp.status or 0) < 300
    )
    try:
        register_proof(
            "response_diff",
            verified=bool(bac_signature),
            subject=mutated_req.url,
            detail=diff.get("summary", ""),
        )
    except Exception as e:
        logger.debug("proof registration failed for replay: %s", e)

    return json.dumps({
        "backend": backend.name,
        "proof": "response_diff verified" if bac_signature else "recorded (unverified)",
        "mutation": mutations,
        "original": {"transaction_id": base_txn.id, "status": base_resp.status,
                     "url": base_req.url},
        "mutated": {"transaction_id": mutated_txn.id,
                    "status": mutated_txn.response.status, "url": mutated_req.url},
        "diff": diff,
    }, default=str)


@security_tool(category="recon", risk="safe")
def session_transactions(limit: int = 20) -> str:
    """List recently recorded HTTP transactions (id, method, url, status) so a
    request can be picked by id for replay_request."""
    return json.dumps(get_session_store().summary(limit=limit), default=str)


@security_tool(category="recon", risk="safe")
def fingerprint_stack(max_transactions: int = 100) -> str:
    """Passive tech-stack fingerprint over ALREADY-captured traffic → targeting.

    Reads the session store (responses from send_http_request / crawl / replay),
    infers the technology stack from headers, cookie names, server banners, and
    error shapes — no new requests — and returns `recommended_focus`: the vuln
    classes worth prioritising for the detected stack (PHP→LFI, Spring→actuator
    SSRF, Express→prototype pollution, API gateway→authz bypass, …). Call it
    after some traffic is recorded to aim the fireteam instead of spraying.
    """
    from agent.fingerprint import fingerprint_transactions
    txns = get_session_store().all()[:max_transactions]
    return json.dumps(fingerprint_transactions(txns), default=str)


@security_tool(category="recon", risk="safe")
def analyze_js(urls: str = "", max_urls: int = 25, with_secrets: bool = True) -> str:
    """Static DOM XSS sink/source + secret analysis of JavaScript — attack-surface
    recall that AIMS the provers.

    Fetches each JS URL and finds attacker-controllable sources
    (location.hash/search, URLSearchParams, postMessage, window.name, cookie)
    that reach dangerous sinks (innerHTML, eval, document.write, location assign)
    in the same file — DOM XSS candidates — plus hardcoded secrets (~1600-pattern
    corpus). Results are LEADS (needs-evidence), not confirmed: for each DOM XSS
    candidate, run test_dom_xss on a page that loads that bundle, injecting into
    the named source, to earn a browser_exec proof token; verify secrets live.
    Pass comma-separated JS URLs (from crawl_urls / scan_js_urls_for_secrets).
    """
    from agent.js_recon import analyze_js as _analyze
    backend = get_backend()
    js_by_name = {}
    for u in [x.strip() for x in urls.split(",") if x.strip()][:max_urls]:
        try:
            resp = backend.send(HttpRequest("GET", u, {}, ""))
            if resp.ok and resp.body:
                js_by_name[u] = resp.body
        except Exception as e:
            logger.debug("analyze_js fetch failed for %s: %s", u, e)
    return json.dumps(_analyze(js_by_name, with_secrets=with_secrets), default=str)


@security_tool(category="exploit", risk="medium")
def authz_matrix(
    transaction_ids: str = "",
    identity_b_headers_json: str = "{}",
    include_unauth: bool = True,
    max_requests: int = 40,
) -> str:
    """Differential authorization test (Autorize-style) — automated broken
    access control / IDOR detection, the #1 real-world web vuln class.

    Replays recorded AUTHENTICATED requests under other identities and diffs:
    - unauthenticated (default) → catches missing authorization; and
    - as user B, if `identity_b_headers_json` gives their creds (e.g.
      '{"Cookie": "session=<userB>"}') → catches horizontal IDOR.

    A same-2xx-body result under the changed/absent identity is broken access
    control; each hit registers a verified proof token so it passes the gate.
    Only requests that originally carried an auth header are tested, so public
    pages are never flagged. Pass `transaction_ids` (comma-separated, from
    session_transactions) to target specific requests, or leave empty to test
    all recorded authenticated requests. Browse/authenticate first so there are
    requests to replay.
    """
    from agent.authz_matrix import run_authorization_matrix

    store = get_session_store()
    if transaction_ids.strip():
        ids = [t.strip() for t in transaction_ids.split(",") if t.strip()]
        txns = [store.get(i) for i in ids]
        requests = [t.request for t in txns if t is not None]
    else:
        requests = [t.request for t in store.all()]
    requests = requests[:max_requests]

    try:
        identity_b = json.loads(identity_b_headers_json) if identity_b_headers_json.strip() else None
    except (ValueError, TypeError):
        return json.dumps({"error": f"identity_b_headers_json invalid: {identity_b_headers_json[:120]}"})
    if not isinstance(identity_b, dict):
        identity_b = None

    report = run_authorization_matrix(
        requests, get_backend(), identity_b=identity_b, include_unauth=include_unauth)
    return json.dumps(report.to_dict(), default=str)


@security_tool(category="exploit", risk="medium")
def oob_probe(label: str = "") -> str:
    """Mint a unique out-of-band callback URL to PROVE a blind vulnerability
    (blind SSRF / RCE / XXE / SSTI — anything with no readable response).

    Inject the returned `payload_url` into the suspected sink (e.g.
    ?url=<payload_url>, an XXE SYSTEM entity, `curl <payload_url>`), then call
    oob_check(probe_id). A recorded callback is machine-checkable proof that
    server-side code reached a host you control — it registers an `oob` proof
    token, so the finding can pass the proof gate. `label` should name the
    target/sink (e.g. "ssrf /redirect.php?url").
    """
    probe = get_oob_oracle().register_probe(label=label)
    return json.dumps({
        "probe_id": probe.probe_id,
        "payload_url": probe.payload_url,
        "next": "inject payload_url into the sink, then call oob_check(probe_id)",
    })


@security_tool(category="exploit", risk="safe")
def oob_check(probe_id: str) -> str:
    """Poll for a callback on an oob_probe. `fired: true` means the blind vuln
    is proven — it registers a verified `oob` proof token. Poll again after a
    few seconds if not yet fired (some sinks are asynchronous)."""
    return json.dumps(get_oob_oracle().check(probe_id), default=str)


@security_tool(category="exploit", risk="medium")
def run_custom_probe(source: str, allowed_hosts: str = "", timeout_sec: float = 20.0) -> str:
    """Run a short sandboxed Python HTTP probe (json/re/httpx only). Not a shell.

    Use when wrappers miss a one-off request. Source is AST-gated and DNS is
    limited to allowed_hosts. No os, subprocess, eval, or files.

    Args:
        source: Python that prints results to stdout
        allowed_hosts: Comma-separated in-scope hosts (required)
        timeout_sec: Max seconds (capped at 45)
    """
    from agent.custom_probe import run_custom_probe as _run

    hosts = [h.strip() for h in (allowed_hosts or "").split(",") if h.strip()]
    result = _run(source, allowed_hosts=hosts, timeout_sec=timeout_sec)
    return json.dumps(result, default=str)


@security_tool(category="vuln_analysis", risk="low")
def test_cors_policy(target_url: str, timeout: int = 60) -> str:
    """Test CORS policy by probing with attacker-controlled Origin headers.

    Detects: wildcard ACAO, reflected origins (mirrors Origin back), null-origin
    allowance, and credentialed cross-origin access (ACAC: true).

    Args:
        target_url: URL to test CORS on
        timeout: Max seconds to run
    """
    import scanners
    result = scanners.run_cors_test(target_url, _get_bridge(), timeout=timeout)
    return json.dumps(result, default=str)


@security_tool(category="exploit", risk="medium")
def test_race_condition(
    url: str,
    method: str = "POST",
    body_json: str = "{}",
    num_concurrent: int = 10,
    timeout: int = 30,
) -> str:
    """Send N concurrent requests to detect race conditions.

    Use on: coupon/promo redemption, payment endpoints, like/vote/reaction endpoints,
    account credit/balance operations, inventory operations, referral bonus claims.

    Args:
        url: Endpoint to race
        method: HTTP method (default POST)
        body_json: JSON body to send with each request
        num_concurrent: Number of simultaneous requests (max 20, default 10)
        timeout: Per-request timeout in seconds
    """
    import scanners
    result = scanners.run_race_condition_test(
        url=url,
        method=method,
        body_json=body_json,
        num_concurrent=num_concurrent,
        bridge=_get_bridge(),
        timeout=timeout,
    )
    return json.dumps(result, default=str)


@security_tool(category="exploit", risk="medium")
def test_file_upload(upload_url: str, timeout: int = 120) -> str:
    """Test a file upload endpoint with extension bypass, MIME mismatch, and polyglot payloads.

    Tests: double extension (.php.jpg), null byte (.php\\x00.jpg), MIME confusion
    (PHP file with image/jpeg content-type), SVG XSS, path traversal in filename,
    and polyglot file (valid image header + PHP code).

    Args:
        upload_url: The form POST endpoint that receives file uploads
        timeout: Max seconds to run
    """
    import scanners
    result = scanners.run_file_upload_test(
        upload_url=upload_url,
        bridge=_get_bridge(),
        timeout=timeout,
    )
    return json.dumps(result, default=str)


# =========================================================================
# Brain Tools — persistent cross-run engagement memory
# =========================================================================

@security_tool(category="recon", risk="safe")
def brain_query(topic: str) -> str:
    """Query the engagement brain for prior knowledge about a topic.

    Returns effective payloads, exhausted techniques, confirmed vulns, and WAF
    profile data relevant to the topic. Call this before testing a surface to
    avoid repeating exhausted techniques and to start with proven payloads.

    Args:
        topic: Keyword to search (e.g. "sqli", "ssrf", "/api/v1/users", "xss")
    """
    from agent.brain import get_brain
    brain = get_brain()
    if brain is None:
        return json.dumps({"status": "brain not initialized (no prior runs)"})
    return json.dumps(brain.query(topic), default=str)


@security_tool(category="recon", risk="safe")
def brain_mark_exhausted(endpoint: str, category: str, technique: str) -> str:
    """Record that a technique has already been tried on an endpoint (no findings).

    Call this when a test produces no results so subsequent runs and the next
    re-run of the agent skip it automatically.

    Args:
        endpoint: URL or path tested (e.g. "/api/v1/users?id=1")
        category: Vuln category (e.g. "sqli", "xss", "ssrf")
        technique: Technique name (e.g. "union_sqli", "polyglot_xss", "level3_bypass")
    """
    from agent.brain import get_brain
    brain = get_brain()
    if brain is None:
        return json.dumps({"status": "brain not initialized"})
    brain.mark_exhausted(endpoint, category, technique)
    brain.save()
    return json.dumps({"recorded": True, "endpoint": endpoint, "technique": technique})


@security_tool(category="recon", risk="safe")
def brain_add_payload(category: str, payload: str) -> str:
    """Save a payload that successfully bypassed a WAF or triggered a vuln.

    These payloads are surfaced first in future runs for the same category.

    Args:
        category: Vuln category (e.g. "sqli", "xss")
        payload: The exact payload string that worked
    """
    from agent.brain import get_brain
    brain = get_brain()
    if brain is None:
        return json.dumps({"status": "brain not initialized"})
    brain.add_effective_payload(category, payload)
    brain.save()
    return json.dumps({"recorded": True, "category": category})


@security_tool(category="recon", risk="safe")
def brain_add_note(note: str) -> str:
    """Record a free-form observation to the engagement brain.

    Use for: WAF behaviour observations, interesting app behaviour, test account
    creds discovered, custom headers needed, unusual rate limits, etc.

    Args:
        note: Observation text (max 2000 chars)
    """
    from agent.brain import get_brain
    brain = get_brain()
    if brain is None:
        return json.dumps({"status": "brain not initialized"})
    brain.add_note(note)
    brain.save()
    return json.dumps({"recorded": True})


@security_tool(category="recon", risk="safe")
def brain_update_waf(
    detected: str = "",
    bypass_ok: str = "",
    bypass_fail: str = "",
) -> str:
    """Update the WAF profile in the engagement brain.

    Args:
        detected: WAF vendor name if detected (e.g. "Cloudflare", "ModSecurity")
        bypass_ok: Comma-separated bypass levels that worked (e.g. "url_encode,double_encode")
        bypass_fail: Comma-separated bypass levels that failed
    """
    from agent.brain import get_brain
    brain = get_brain()
    if brain is None:
        return json.dumps({"status": "brain not initialized"})
    brain.update_waf(
        detected=detected or None,
        bypass_ok=[x.strip() for x in bypass_ok.split(",") if x.strip()],
        bypass_fail=[x.strip() for x in bypass_fail.split(",") if x.strip()],
    )
    brain.save()
    return json.dumps({"updated": True})


# =========================================================================
# Prior Art Tools — knowledge base search
# =========================================================================

@security_tool(category="recon", risk="safe")
def search_prior_art(query: str, category: str = "", top_k: int = 6) -> str:
    """Search the technique knowledge base for proven payloads and patterns.

    Call this BEFORE testing a new surface or vulnerability class to get
    curated attack patterns, known-good payloads, bypass notes, and
    success indicators from the prior-art library.

    Args:
        query: Free-text search (e.g. "mongodb nosql injection login bypass")
        category: Optional filter — one of: injection, xss, ssrf, auth, authz,
                  csrf, cors, file_upload, open_redirect, race_condition,
                  business_logic, oauth, llm_ai, sast
        top_k: Max results to return (default 6)
    """
    from agent.prior_art import search, format_results
    try:
        k = int(top_k)
    except (TypeError, ValueError):
        k = 6
    results = search(query, category=category, top_k=k)
    return format_results(results)


# =========================================================================
# SAST Tools — static source code analysis
# =========================================================================

@security_tool(category="vuln_analysis", risk="safe")
def sast_scan_secrets(source_dir: str, timeout: int = 300) -> str:
    """Scan source code directory for hardcoded secrets, API keys, and credentials.

    Uses Gitleaks (if installed) and regex pattern matching. Finds AWS keys,
    API tokens, private keys, database passwords, and connection strings.

    Args:
        source_dir: Absolute path to source code directory
        timeout: Max seconds to run
    """
    import scanners
    result = scanners.run_sast_secrets(source_dir, bridge=_get_bridge(), timeout=timeout)
    return json.dumps(result, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def sast_run_semgrep(source_dir: str, ruleset: str = "auto", timeout: int = 600) -> str:
    """Run semgrep static analysis over source code.

    Rulesets: 'auto' (language-appropriate), 'p/owasp-top-ten', 'p/taint',
    'p/sql-injection', 'p/xss', 'p/python', 'p/java', 'p/javascript'.
    Requires semgrep to be installed (pip install semgrep).

    Args:
        source_dir: Absolute path to source code directory
        ruleset: Semgrep ruleset or registry path
        timeout: Max seconds to run
    """
    import scanners
    result = scanners.run_semgrep(source_dir, ruleset=ruleset, timeout=timeout)
    return json.dumps(result, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def sast_grep_source(
    pattern: str,
    source_dir: str,
    case_sensitive: bool = False,
    max_results: int = 50,
) -> str:
    """Regex search across source code files for dangerous patterns.

    Searches .py, .js, .ts, .go, .rb, .java, .php and config files.
    Excludes node_modules, vendor, __pycache__, .git directories.

    Args:
        pattern: Python regex pattern (e.g. r"execute\\s*\\(" or "password\\s*=")
        source_dir: Absolute path to source directory
        case_sensitive: Whether search is case-sensitive (default False)
        max_results: Max matches to return (default 50)
    """
    import scanners
    result = scanners.grep_source(
        pattern=pattern,
        source_dir=source_dir,
        case_sensitive=case_sensitive,
        max_results=max_results,
    )
    return json.dumps(result, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def sast_read_file(path: str, start_line: int = 1, num_lines: int = 30, source_dir: str = "") -> str:
    """Read lines from a source file with context around a finding.

    Use after sast_grep_source or sast_run_semgrep to read the code
    surrounding a match to confirm whether it's a real vulnerability.

    Args:
        path: File path (absolute, or relative to source_dir)
        start_line: Line to start reading from (1-indexed)
        num_lines: Number of lines to read (default 30)
        source_dir: Optional root directory for relative path resolution
    """
    import scanners
    result = scanners.read_source_file(
        path=path,
        start_line=start_line,
        num_lines=num_lines,
        source_dir=source_dir or None,
    )
    return json.dumps(result, default=str)


# =========================================================================
# Agent Definitions
# =========================================================================

RECON_TOOLS = [
    "scan_subdomains", "resolve_dns", "probe_http", "scan_ports",
    "scan_ports_nmap", "fingerprint_tech", "detect_waf", "detect_cms",
    "fingerprint_gitlab", "crawl_urls", "crawl_urls_authenticated",
    "discover_historical_urls", "discover_api_surface", "scan_js_urls_for_secrets",
    "analyze_js_with_jsluice",
    "fuzz_directories", "discover_parameters", "reverse_whois_search",
    "atlas_map_attack_surface",
    # Swagger/OpenAPI discovery
    "discover_swagger_spec",
]

VULN_TOOLS = [
    "scan_nuclei", "scan_nikto", "analyze_security_headers", "analyze_tls",
    "check_subdomain_takeover", "analyze_mail_security", "detect_third_party_vendors",
    "scan_js_urls_for_secrets", "analyze_js_with_jsluice", "discover_api_surface", "fingerprint_gitlab",
    # Praetorium tools — now wired so LLM can invoke them
    "janus_dast_baseline", "argus_scan_secrets", "hermes_scan_remote_secrets",
    # Swagger/OpenAPI endpoint testing
    "discover_swagger_spec", "test_swagger_api",
]

EXPLOIT_TOOLS = [
    "sql_injection_test", "xss_test", "test_dom_xss", "wordpress_scan",
    "deep_tls_test", "scan_nuclei", "confirm_vulnerability_poc",
    "janus_dast_full",
    # Manual probing tools
    "send_http_request", "test_cors_policy", "test_race_condition", "test_file_upload",
    "run_custom_probe",
]

REPORT_TOOLS = [
    "generate_report", "submit_findings_to_platform",
]


APP_MAPPER_TOOLS = [
    "crawl_urls",
    "crawl_urls_authenticated",
    "discover_api_surface",
    "discover_swagger_spec",
    "fingerprint_tech",
    "detect_waf",
    "detect_cms",
    "discover_parameters",
    "fuzz_directories",
    "scan_js_urls_for_secrets",
    "janus_dast_baseline",
]

VALIDATOR_TOOLS = [
    "send_http_request",
    "scan_nuclei",
    "confirm_vulnerability_poc",
    "submit_findings_to_platform",
]

CHAIN_TOOLS = [
    "send_http_request",
    "crawl_urls",
    "discover_parameters",
    "confirm_vulnerability_poc",
    "submit_findings_to_platform",
    "brain_add_note",
]

SAST_TOOLS = [
    "sast_scan_secrets",
    "sast_run_semgrep",
    "sast_grep_source",
    "sast_read_file",
    "search_prior_art",
    "confirm_vulnerability_poc",
    "submit_findings_to_platform",
    "brain_add_note",
]

# Tools available to all hunters for brain + prior-art access
HUNTER_CORE_TOOLS = [
    "search_prior_art",
    "brain_query",
    "brain_mark_exhausted",
    "brain_add_payload",
    "brain_add_note",
]


def create_app_mapper_agent() -> Agent:
    """Maps application functionality before hunters run — gives hunters business context."""
    return Agent(
        name="app_mapper_agent",
        instructions="""You are the **Application Mapper** for Aegis Vanguard.
Your job is to understand WHAT the application does (not just what URLs exist)
so the vulnerability hunters have business-logic context when they test.

## Goal
Produce a structured "App Profile" covering:
1. **Application type** — e-commerce, SaaS, banking, social, API gateway, admin panel, etc.
2. **Authentication model** — session cookies, JWT, OAuth, SAML, API keys, MFA?
3. **Key features / workflows** — file uploads, payments, user invitations, data export,
   webhooks, search, messaging, admin panel, API, integrations
4. **API surface** — REST, GraphQL, WebSocket? Known endpoints, object types, operations
5. **Tech stack** — frontend framework, backend language, CMS, cloud provider, CDN, WAF
6. **Third-party integrations** — payment processors, auth providers, analytics, CDN, email
7. **Interesting attack vectors** — anything that handles user-supplied data, file processing,
   URL fetching, or privilege-sensitive operations

## Steps
1. fingerprint_tech on the target URL to get the tech stack.
2. detect_waf to note WAF behavior for hunters.
3. detect_cms to check for WordPress/Drupal/etc.
4. crawl_urls to discover the URL structure — look at the URL patterns for clues about features.
5. discover_api_surface to find the API inventory — REST routes, GraphQL schema hints, WebSocket.
6. discover_swagger_spec on the target base URL — multi-phase OpenAPI/Swagger discovery (direct
   spec check → Swagger UI scraping → 30+ common-path bruteforce). If a spec is found, the
   returned endpoint list tells hunters exactly which routes exist and what they do.
7. If it looks like a SPA, crawl_urls_authenticated for deeper route discovery.
8. discover_parameters on 3-5 interesting endpoints to find hidden fields.
9. fuzz_directories to find: /admin, /api, /upload, /import, /export, /webhook, /payment.
10. scan_js_urls_for_secrets on JS bundles to find hardcoded secrets and internal endpoint names.
11. janus_dast_baseline for a passive DAST pass (no active payloads — observes responses only).

## Ranked attack surface (required section)
After mapping, emit a **Ranked Hunt Queue** (highest first) so hunters spend turns wisely:
1. Auth / SSO / reset / MFA
2. Object-ID APIs + GraphQL
3. Upload / webhook / URL-fetch / PDF render (SSRF)
4. Admin / actuator / swagger / debug
5. Framework-specific hot paths (Next.js, Spring, Laravel, ASP.NET) if fingerprint matches
6. Everything else

Also flag **tech-conditional skills** hunters should load (Next.js middleware, Spring actuators, etc.).
Flag **perimeter signals** for enterprise specialists: Entra/Okta, SharePoint, VPN appliances,
vCenter, cloud keys/buckets, GraphQL/gRPC/WebSocket.

## Output format
Produce a structured markdown App Profile including:
- Application Type, Authentication, Key Features, API Surface, Tech Stack
- Interesting Attack Vectors
- **Perimeter / IdP / Cloud signals** (explicit yes/no bullets)
- **Ranked Hunt Queue** (ordered list with why each matters)
- **Suggested hunter focus** (e.g. authz_hunter on /api/v1/orders/{id}; graphql_hunter if /graphql)

This profile is passed directly to the hunter fireteam as their attack-surface context.
""",
        tool_names=APP_MAPPER_TOOLS,
        max_turns=30,
        temperature=0.0,
    )


def create_validator_agent() -> Agent:
    """7-Question Gate: validates findings before they flow to the ASM platform."""
    return Agent(
        name="validator_agent",
        instructions="""You are the **Finding Validator** for Aegis Vanguard.
Your job is to apply a 7-Question Gate to every finding before it reaches the ASM platform.
A single NO kills the finding. Be strict — false positives waste everyone's time.

## Logical sanity (check FIRST)
Before the numbered gate: does this finding even make sense on the observed host/port/service?
- LDAP / AD / Kerberos / SMB / SSH / SMTP / Redis / MySQL / Mongo / RDP on HTTP(S) 80/443/8080/8443 → KILL (logical mismatch)
- Template implies protocol X but live response is a normal web app → KILL
- When re-validating an existing Open finding: confirm it is STILL reproducible. If fixed or port closed → KILL (no longer open)

## The 7-Question Gate (apply in order, first NO = KILL)

**Q1: Can an attacker trigger this RIGHT NOW with a real HTTP request?**
- Must have exact request + response proving the issue
- "Nuclei template matched" alone → KILL Q1 (unless you can manually reproduce)
- "Code review suggests..." → KILL Q1

**Q2: Is the impact type meaningful?**
- Does not return: "server version disclosed" → KILL Q2 (informational only)
- Does not return: "missing header" alone without exploitability proof → KILL Q2

**Q3: Is the asset in scope?**
- Third-party service (CDN, support chat, analytics) → KILL Q3
- Staging/dev endpoint outside engagement scope → KILL Q3

**Q4: Does it work without privileges the attacker can't realistically obtain?**
- "Admin can do X" → KILL Q4 (admins can admin)
- Requires physical device access → KILL Q4

**Q5: Is this not already known/documented?**
- In changelogs or public CVE → KILL Q5 (unless unpatched in this instance)

**Q6: Is impact demonstrated, not theoretical?**
- XSS: need cookie in exfil, not just alert()
- SSRF: need internal HTTP data or metadata, not DNS-only ping
- IDOR: need another user's data in response, not just a 200 status code
- SQLi: need time delay or error or data, not just a 500 error

**Q7: Is the severity calibrated to achieved impact?**
- Missing CSRF token + SameSite=Strict → KILL Q7 (SameSite prevents it)
- XSS in admin-only panel with no user reachable → downgrade severity

**Q8: Identity check (authz/auth findings) — which session proved it?**
- Record: anonymous vs user_A vs user_B vs privileged
- Missing auth (works with no cookie) ≠ IDOR (cross-user with A's token)
- Own-data-only responses → KILL Q8
- Cannot answer identity questions on authz findings → NEEDS_MORE_EVIDENCE

## Decision
For each finding: PASS / KILL (Q#) / DOWNGRADE / NEEDS_MORE_EVIDENCE

For PASS findings: call confirm_vulnerability_poc to lock in severity and submit.
For NEEDS_MORE_EVIDENCE: use send_http_request or scan_nuclei to re-test before deciding.
For KILL/DOWNGRADE: explain why in one sentence.

## Never-submit list (instant KILL without a working chain)
- Missing security headers alone (X-Frame-Options, X-Content-Type-Options, etc.)
- GraphQL introspection alone (need authz bypass or cross-user node access)
- Self-XSS (attacker can only attack themselves) without CSRF delivery
- Open redirect alone without OAuth token theft or SSRF chain
- Host header injection alone without password-reset poisoning proof
- SSRF DNS-only without HTTP response body from internal/metadata
- CORS wildcard without ACAC: true (credentials blocked by spec)
- Missing cookie flags alone (report only if leads to concrete exploit)
- SPAs exposing client_id (public by design)
- Clickjacking on non-sensitive pages; rate-limit missing on non-auth forms
- Non-HTTP service findings (LDAP/SSH/SMTP/DB/…) matched against web ports
""",
        tool_names=VALIDATOR_TOOLS,
        max_turns=25,
        temperature=0.0,
    )


def create_report_agent() -> Agent:
    return Agent(
        name="report_agent",
        instructions="""You are the Report Agent. Your job is to compile all findings
from reconnaissance, vulnerability analysis, and exploit validation into a
comprehensive security assessment report.

When you receive findings from the Exploit Agent:
1. Organize findings by severity (Critical > High > Medium > Low)
2. Generate the report using the generate_report tool
3. Submit remaining findings to the platform
4. Provide a brief executive summary to the user""",
        tool_names=REPORT_TOOLS,
        max_turns=15,
    )


def create_exploit_chain_agent() -> Agent:
    """Chains confirmed individual findings into compound multi-step attack paths."""
    return Agent(
        name="exploit_chain_agent",
        instructions="""You are the **Exploit Chain Builder** for Aegis Vanguard.
Your mission: take the list of confirmed findings and build multi-step attack
chains that demonstrate compound, escalated impact. A chain of 3 medium findings
can constitute a critical account takeover or full compromise.

## Core chain patterns to evaluate

### Account Takeover chains
- Open Redirect + OAuth state abuse → steal auth code → account takeover
- XSS + CSRF token extraction → bypass SameSite cookies → admin action as victim
- Password reset + weak token + no rate limit → brute force takeover
- IDOR + PII exposure → targeted phishing → credential takeover
- Stored XSS in profile → admin views profile → admin account takeover

### Privilege Escalation chains
- IDOR (read another user) + mass assignment (role field) → become admin
- SSRF (internal) + cloud metadata → IAM credentials → cloud admin
- JWT algorithm confusion → forge admin token → full access
- SQLi (read) + SQLi (write) → create admin account

### Data Exfiltration chains
- SSRF → internal Redis/MongoDB → dump all data
- XXE → SSRF → cloud metadata → S3 access → dump bucket
- SQL injection + LOAD_FILE → read /etc/passwd → further recon
- Path traversal + LFI → read .env → extract DB credentials → dump DB

### Remote Code Execution chains
- SSTI + no output filtering → RCE
- Deserialization + file upload → upload malicious payload → trigger deserialization
- Open redirect + XSS → DOM-based RCE via eval() sink
- SSRF → internal service (Jira/Jenkins RCE) → pivot

## Workflow

1. Review the findings list provided in your task message.
2. Group findings by their chain potential using the patterns above.
3. For each promising chain:
   a. Map out the A→B→C steps with the exact endpoints and parameters.
   b. Use send_http_request to verify each step is reachable in sequence.
   c. Document the full request sequence as the PoC.
   d. Estimate the compound severity: if any step in the chain yields critical
      impact, the chain severity is critical.
4. Confirm each chain via confirm_vulnerability_poc:
   - vuln_type = "exploit_chain"
   - payload = the step-by-step PoC
   - impact = compound impact description
5. Use brain_add_note to record any new observations about the app for future runs.
6. If no chains are possible (all findings are isolated), say so explicitly.

## Rules
- Document chains, never execute them destructively.
- Only test steps against the authorised scope.
- A chain requires at least 2 confirmed findings; don't invent hypotheticals.
""",
        tool_names=CHAIN_TOOLS,
        max_turns=30,
        temperature=0.0,
    )


def create_exploit_agent() -> Agent:
    report_agent = create_report_agent()
    return Agent(
        name="exploit_agent",
        instructions="""You are the Exploit Validation Agent. Your job is to confirm
discovered vulnerabilities with targeted validation attempts and attach proof-of-concept
evidence to every confirmed finding.

RULES:
- Only validate, never escalate or cause damage
- sqlmap: always use --batch mode (already enforced)
- Focus on parameterized URLs from the discovery/vuln phases
- Skip validation if no injectable endpoints were found

Strategy:
1. Review nuclei findings — re-validate any high/critical with targeted templates
2. Test parameterized URLs for SQL injection (sql_injection_test)
   → If sqlmap confirms: call confirm_vulnerability_poc with vuln_type="sqli"
3. Test parameterized URLs for XSS (xss_test for reflected, test_dom_xss for DOM-based)
   → If XSS confirmed: call confirm_vulnerability_poc with vuln_type="xss" or "dom-xss"
4. If WordPress detected, run wpscan
   → If wpscan finds critical vulns: call confirm_vulnerability_poc
5. If TLS grades are D/F, run deep TLS testing
6. ALWAYS call confirm_vulnerability_poc for any confirmed finding before handing off —
   this escalates severity automatically (e.g. medium SQLi → critical) and attaches
   the request/response evidence to the platform record
7. When done, hand off to the Report Agent with a summary of confirmed findings
   including their escalated severities""",
        tool_names=EXPLOIT_TOOLS,
        handoffs=[report_agent],
        max_turns=20,
    )


def create_vuln_agent() -> Agent:
    exploit_agent = create_exploit_agent()
    return Agent(
        name="vuln_agent",
        instructions="""You are the Vulnerability Analysis Agent. Your job is to
identify vulnerabilities across the discovered attack surface.

Strategy:
1. Run nuclei against all discovered live URLs (most important)
2. If the Recon Agent found a Swagger/OpenAPI spec: run test_swagger_api against the
   target base URL. This exercises every documented endpoint, checks for unauthenticated
   access, and scans responses for PII (emails, phone numbers, SSNs) and leaked secrets
   (AWS keys, JWTs, API tokens). This is the primary API vuln check — do not skip it.
   - If endpoints return data without auth → high-severity finding
   - If responses contain PII → medium/high
   - If responses contain secret patterns → high/critical
3. Run scan_js_urls_for_secrets on high-value .js URLs from crawling (API bundles, clientlibs) — complements nuclei for leaked credentials in static assets
4. Run nikto against the primary target
5. Analyze security headers on all live hosts
6. Analyze TLS certificates and grades
7. Check all subdomains for takeover risk
8. Analyze mail infrastructure for the root domain
9. Detect third-party vendors

When you have a comprehensive picture, hand off to the Exploit Agent with:
- List of nuclei high/critical findings
- Results from test_swagger_api (flagged endpoints, PII/secret hits)
- Any parameterized URLs that should be tested for injection
- Whether WordPress or other CMS was detected
- Which hosts have poor TLS grades""",
        tool_names=VULN_TOOLS,
        handoffs=[exploit_agent],
        max_turns=25,
    )


def create_recon_agent() -> Agent:
    vuln_agent = create_vuln_agent()
    return Agent(
        name="recon_agent",
        instructions="""You are the Reconnaissance Agent. Your job is to map the
complete attack surface of the target.

Strategy (adapt based on what you find):
1. Start with fingerprint_tech and detect_waf on the target URL
2. Enumerate subdomains for the root domain
3. If a company or brand name is available, use reverse_whois_search in preview
   mode to estimate related-domain exposure; use purchase mode only when API
   credit usage is explicitly authorized
4. If GitLab is detected or suspected, run fingerprint_gitlab to hash /help
   stylesheet assets and correlate versions without exploitation
5. Resolve DNS for all discovered hosts
6. Probe for live HTTP services
7. Port scan the primary target (nmap for service detection)
8. Crawl the target for URLs and endpoints using crawl_urls (katana)
9. Run discover_api_surface to build a blackbox API inventory from browser traffic,
   page links, JavaScript bundles, JSON responses, GraphQL routes, and WebSocket hints
10. Run discover_swagger_spec on the target base URL (and any live API subdomains).
    This probes 30+ common spec paths (/swagger.json, /openapi.json, /api-docs, etc.)
    and also scrapes Swagger UI pages for the embedded spec URL. If a spec is found,
    note ALL documented endpoints and pass them to the Vulnerability Agent — this is
    the highest-signal API surface artifact available.
11. If the target appears to be a SPA (React/Angular/Vue), also run crawl_urls_authenticated
    to capture routes that only render after JS execution
12. Discover historical URLs
13. For discovered JavaScript bundles (e.g. .js under /static, /clientlibs), run scan_js_urls_for_secrets with those URLs to detect hardcoded keys/tokens
14. Fuzz for hidden directories/API paths
15. Discover parameters on interesting endpoints
16. Flag **enterprise perimeter signals** explicitly in your summary when seen:
    - Entra/M365: login.microsoftonline.com, *.onmicrosoft.com, autodiscover
    - Okta: *.okta.com / custom Okta domains
    - SharePoint: /_layouts/, /_vti_bin/, Authentication.asmx
    - SSL VPN portals: AnyConnect, FortiGate, NetScaler, GlobalProtect, Ivanti, F5
    - vCenter / Workspace ONE / Aria management UIs
    - Cloud credential leaks (AKIA/ASIA keys, SA JSON) and public bucket hints
    - GraphQL / gRPC / WebSocket endpoints (name them for specialist hunters)

ADAPT your approach:
- If WAF detected, note it for the vuln agent to adjust strategy
- If CMS detected (WordPress etc), flag for CMS-specific scanning
- If many subdomains found, prioritize live ones
- If reverse_whois_search returns related domains in purchase mode, treat them as
  candidates requiring scope confirmation before active probing
- If fingerprint_gitlab maps a vulnerable version, report the fingerprint and
  recommend explicit authorization for any OOB validation; do not run RCE payloads
- If discover_api_surface finds REST/GraphQL/WebSocket endpoints, summarize methods,
  parameters, auth hints, sensitive-looking routes, and public admin/internal APIs
- If discover_swagger_spec finds a spec: treat the endpoint list as the authoritative
  API surface map; flag the spec URL as an informational finding; ensure the Vuln
  Agent runs test_swagger_api against it (unauthenticated access + PII/secret testing)
- If katana finds few URLs but the page has heavy JS (React/Angular/Vue fingerprinted),
  use crawl_urls_authenticated to get the full authenticated surface

When you have a comprehensive attack surface map, hand off to the
Vulnerability Analysis Agent with your findings.""",
        tool_names=RECON_TOOLS,
        handoffs=[vuln_agent],
        max_turns=30,
    )


def create_orchestrator() -> Agent:
    """Create the top-level orchestrator that manages the full pipeline."""
    recon_agent = create_recon_agent()

    return Agent(
        name="orchestrator",
        instructions="""You are the Aegis Vanguard Orchestrator. You coordinate autonomous
web application penetration testing.

When given a target:
1. Briefly acknowledge the target and scope
2. Immediately hand off to the Recon Agent to begin the assessment

The pipeline flows: Recon -> Vuln Analysis -> Exploit Validation -> Reporting
Each agent hands off to the next when its phase is complete.""",
        tool_names=[],
        handoffs=[recon_agent],
        max_turns=3,
    )


def build_agent_chain() -> dict:
    """Build the full multi-agent chain and return as a dict for AgentRunner.run_multi()."""
    report_agent = create_report_agent()
    exploit_agent = Agent(
        name="exploit_agent",
        instructions=create_exploit_agent().instructions,
        tool_names=EXPLOIT_TOOLS,
        handoffs=[report_agent],
        max_turns=25,
    )
    vuln_agent = Agent(
        name="vuln_agent",
        instructions=create_vuln_agent().instructions,
        tool_names=VULN_TOOLS,
        handoffs=[exploit_agent],
        max_turns=25,
    )
    recon_agent = Agent(
        name="recon_agent",
        instructions=create_recon_agent().instructions,
        tool_names=RECON_TOOLS,
        handoffs=[vuln_agent],
        max_turns=35,
    )
    orchestrator = Agent(
        name="orchestrator",
        instructions=create_orchestrator().instructions,
        tool_names=[],
        handoffs=[recon_agent],
        max_turns=3,
    )

    return {
        "orchestrator": orchestrator,
        "recon_agent": recon_agent,
        "vuln_agent": vuln_agent,
        "exploit_agent": exploit_agent,
        "report_agent": report_agent,
    }
