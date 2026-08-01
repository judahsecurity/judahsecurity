"""
Subdomain enumeration service for attack surface discovery.

Features:
- Recursive/multi-level subdomain enumeration
- Multiple data sources (Subfinder, Subfaster, Chaos, crt.sh, crt.name, DNS brute-force)
- Extended wordlists with cloud/enterprise patterns
- Configurable recursion depth
"""

import asyncio
import logging
import os
from typing import Optional, Callable, Set
from dataclasses import dataclass, field

import dns.resolver
import dns.exception
import httpx

from app.services.chaos_service import ChaosService, CHAOS_CONFIGURED
from app.services.wildcard_filter_service import (
    WildcardProfile,
    filter_wildcards as _filter_wildcards,
)

logger = logging.getLogger(__name__)

# Check if subfinder is available
def _check_subfinder_available() -> bool:
    """Check if subfinder binary is available."""
    import subprocess
    try:
        result = subprocess.run(
            ["subfinder", "-version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False

SUBFINDER_AVAILABLE = _check_subfinder_available()


def _check_subcat_available() -> bool:
    """Check if subcat is installed (pip install subcat)."""
    import subprocess
    try:
        result = subprocess.run(
            ["subcat", "-h"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False

SUBCAT_AVAILABLE = _check_subcat_available()


def _check_subfaster_available() -> bool:
    """Check if subfaster binary is available (crt.name + other fast passive sources)."""
    import subprocess
    try:
        result = subprocess.run(
            ["subfaster", "-version"],
            capture_output=True,
            timeout=5,
        )
        # Some builds may only support -h; treat either as available.
        if result.returncode == 0:
            return True
        result = subprocess.run(
            ["subfaster", "-h"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


SUBFASTER_AVAILABLE = _check_subfaster_available()


# Base subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "email", "vpn",
    "remote", "admin", "administrator", "app", "apps", "api", "apis", "dev",
    "development", "stage", "staging", "test", "testing", "prod", "production",
    "uat", "qa", "demo", "sandbox", "beta", "alpha", "preview", "portal",
    "web", "www1", "www2", "www3", "m", "mobile", "wap", "blog", "blogs",
    "news", "shop", "store", "cart", "secure", "ssl", "login", "signin",
    "auth", "sso", "id", "identity", "account", "accounts", "my", "support",
    "help", "helpdesk", "ticket", "tickets", "forum", "forums", "community",
    "wiki", "docs", "doc", "documentation", "kb", "knowledge", "faq", "cdn",
    "static", "assets", "images", "img", "media", "video", "videos", "files",
    "download", "downloads", "upload", "uploads", "backup", "backups", "db",
    "database", "mysql", "postgres", "postgresql", "mongodb", "redis", "cache",
    "memcache", "memcached", "elastic", "elasticsearch", "kibana", "grafana",
    "prometheus", "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
    "svn", "repo", "repository", "code", "build", "deploy", "release", "jira",
    "confluence", "slack", "teams", "zoom", "meet", "calendar", "drive", "cloud",
    "aws", "azure", "gcp", "s3", "ec2", "lambda", "k8s", "kubernetes", "docker",
    "container", "registry", "harbor", "nexus", "artifactory", "sonar", "vault",
    "consul", "nomad", "terraform", "ansible", "puppet", "chef", "nagios",
    "zabbix", "splunk", "elk", "logstash", "graylog", "sentry", "newrelic",
    "datadog", "pagerduty", "opsgenie", "statuspage", "status", "health",
    "monitor", "monitoring", "metrics", "analytics", "track", "tracking", "crm",
    "erp", "hr", "payroll", "finance", "billing", "invoice", "payment", "pay",
    "checkout", "order", "orders", "inventory", "warehouse", "shipping", "delivery",
    "internal", "intranet", "extranet", "partner", "partners", "vendor", "vendors",
    "client", "clients", "customer", "customers", "member", "members", "user",
    "users", "profile", "profiles", "dashboard", "panel", "console", "control",
    "manager", "management", "office", "outlook", "exchange", "autodiscover",
    "lyncdiscover", "sip", "voip", "pbx", "phone", "tel", "fax", "print", "printer",
    "scan", "scanner", "ntp", "time", "log", "logs", "audit", "report", "reports",
    "export", "import", "sync", "api-v1", "api-v2", "v1", "v2", "v3", "old", "new",
    "legacy", "archive", "archives", "temp", "tmp", "data", "info", "about", "contact",
    "feedback", "survey", "poll", "search", "sitemap", "rss", "feed", "xml", "json",
    "rest", "graphql", "websocket", "ws", "wss", "socket", "proxy", "gateway", "lb",
    "loadbalancer", "haproxy", "nginx", "apache", "iis", "tomcat", "jboss", "weblogic",
    "websphere", "glassfish", "wildfly", "node", "express", "django", "flask", "rails",
    "spring", "laravel", "symfony", "wordpress", "wp", "joomla", "drupal", "magento",
    "shopify", "woocommerce", "prestashop", "opencart"
]

# Extended enterprise/cloud subdomain patterns
ENTERPRISE_SUBDOMAINS = [
    # Cloud environments
    "cloud", "cloud-dev", "cloud-qa", "cloud-uat", "cloud-prod", "cloud-preprod",
    "cloud-staging", "cloud-test", "cloud-sandbox",
    # Azure regions
    "eastus", "eastus2", "westus", "westus2", "centralus", "northeurope", 
    "westeurope", "southeastasia", "brazilsouth", "australiaeast",
    # Common cloud prefixes with regions
    "api-eastus", "api-eastus2", "api-westus", "api-centralus",
    "portal-eastus", "portal-eastus2", "portal-westus",
    "home-eastus", "home-eastus2", "common-eastus", "common-eastus2",
    # Environment patterns
    "dev", "dev1", "dev2", "dev3", "devops", "dev-api", "dev-portal",
    "qa", "qa1", "qa2", "qa3", "qa-api", "qa-portal",
    "uat", "uat1", "uat2", "uat-api", "uat-portal",
    "staging", "staging1", "staging2", "stg", "stage",
    "preprod", "pre-prod", "pre", "preprod-api",
    "prod", "prod1", "prod2", "production", "prd",
    "sandbox", "sandbox1", "sandbox2", "sbox", "sbx",
    "demo", "demo1", "demo2", "demo-api", "demo-portal",
    "test", "test1", "test2", "test3", "testing",
    # API patterns
    "api", "api-dev", "api-qa", "api-prod", "api-v1", "api-v2", "api-v3",
    "api-notifications", "api-notifications-eastus2", "api-gateway",
    "rest", "rest-api", "graphql", "grpc",
    # Admin/management
    "admin", "admin-dev", "admin-qa", "admin-prod",
    "common-admin", "common-admin-eastus2",
    "portal", "portal-dev", "portal-qa", "portal-prod",
    "management", "mgmt", "console", "dashboard",
    # Data/analytics
    "data", "datamosaix", "datamosaix-admin", "datamosaix-portal",
    "analytics", "metrics", "telemetry", "logs",
    "dm-admin", "dm-portal", "dm-access-mgmt", "dm-applications",
    "dm-extractors", "dm-utilities", "dm-feature-flags",
    # Infrastructure
    "vault", "vault-eastus2", "grafana", "grafana-eastus2",
    "prometheus", "alertmanager", "kibana", "elasticsearch",
    "jenkins", "gitlab", "artifactory", "nexus", "sonar",
    "helpdesk", "helpdesk-eastus2", "pushgateway",
    # Edge/IoT
    "edge", "edgecloud", "edgecontrol", "edgemanager",
    "iot", "iot101", "iot102", "devices", "device-management",
    # Security
    "auth", "auth0", "sso", "identity", "login", "logind", "loginq",
    "access", "accessserver", "access-mgmt",
    "certs", "certificates", "pki",
    # Enterprise apps
    "crm", "erp", "sap", "salesforce", "workday", "servicenow",
    "jira", "confluence", "sharepoint", "teams", "slack",
    "onbase", "documentum", "fileserver", "files",
    # Notifications/messaging  
    "notifications", "notificationsv2", "email", "mail", "smtp",
    "messaging", "pubsub", "events", "eventlistener",
    # Feature flags/config
    "feature-flags", "flags", "config", "configuration",
    "settings", "options", "preferences",
    # Common services
    "home", "common", "shared", "core", "base", "foundation",
    "platform", "hub", "central", "main",
    # Version/maintenance
    "version", "ft-version", "maintenance", "upgrade",
    # Misc enterprise
    "advisor", "optix", "ftra", "ftem", "ftma", "ftds",
    "commerce", "ecommerce", "store", "shop", "catalog",
    "support", "helpdesk", "tickets", "servicedesk",
]

# Patterns for recursive subdomain discovery
RECURSIVE_PREFIXES = [
    # Cloud/environment prefixes to prepend to discovered subdomains
    "api", "portal", "admin", "home", "common", "status", "help",
    "dev", "qa", "uat", "staging", "prod", "demo", "test",
    "eastus", "eastus2", "westus", "centralus",
    "common-admin", "dm-admin", "dm-portal",
]


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    subdomain: str
    ip_addresses: list[str]
    source: str  # How it was discovered
    is_alive: bool = False
    depth: int = 0  # Recursion depth at which this was discovered


@dataclass
class RecursiveEnumerationResult:
    """Result of recursive subdomain enumeration."""
    root_domain: str
    total_subdomains: int
    subdomains_by_depth: dict = field(default_factory=dict)  # depth -> count
    all_subdomains: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    duration_seconds: float = 0


class SubdomainService:
    """Service for subdomain enumeration using multiple sources including subfinder and Chaos."""
    
    def __init__(
        self,
        nameservers: Optional[list[str]] = None,
        timeout: float = 3.0,
        max_concurrent: int = 50,
        use_subfinder: bool = True,
        use_chaos: bool = True,
        organization_id: Optional[int] = None,
    ):
        """
        Initialize subdomain service.
        
        Args:
            nameservers: Custom DNS servers to use
            timeout: Query timeout in seconds
            max_concurrent: Maximum concurrent DNS queries
            use_subfinder: Whether to use subfinder if available
            use_chaos: Whether to use Chaos if configured
            organization_id: Optional org id. When set, Chaos (and other API-keyed
                sources) use the API key rotator to pick the next healthy key
                configured for this org.
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.use_subfinder = use_subfinder and SUBFINDER_AVAILABLE
        self.use_subcat = SUBCAT_AVAILABLE
        self.use_subfaster = SUBFASTER_AVAILABLE
        self.organization_id = organization_id
        # With the rotator we can use Chaos if *either* env var is set or the
        # org has at least one ``pdcp`` APIConfig row — we optimistically flip
        # ``use_chaos`` on and let the rotator report "no healthy key" later.
        self.use_chaos = use_chaos and (CHAOS_CONFIGURED or organization_id is not None)
        self.chaos_service = (
            ChaosService(organization_id=organization_id) if self.use_chaos else None
        )
        
        if self.use_subfinder:
            logger.info("Subfinder is available and will be used for subdomain enumeration")
        else:
            logger.info("Subfinder not available")

        if self.use_subcat:
            logger.info("Subcat is available and will be used for passive subdomain enumeration")
        else:
            logger.info("Subcat not available (pip install subcat to enable)")

        if self.use_subfaster:
            logger.info("Subfaster is available and will be used for fast passive subdomain enumeration")
        else:
            logger.info("Subfaster not available (install github.com/melvinsh/subfaster to enable)")

        if self.use_chaos:
            logger.info("Chaos is configured and will be used for passive subdomain lookup")
        else:
            logger.info("Chaos not configured (set PDCP_API_KEY to enable)")
    
    async def enumerate_subdomains(
        self,
        domain: str,
        wordlist: Optional[list[str]] = None,
        use_crtsh: bool = True,
        use_subfinder: bool = True,
        use_chaos: bool = True,
        use_extended_wordlist: bool = True,
        depth: int = 0,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        filter_wildcards: bool = True,
        wildcard_profile: Optional[WildcardProfile] = None,
    ) -> list[SubdomainResult]:
        """
        Enumerate subdomains using multiple techniques including subfinder and Chaos.
        
        Args:
            domain: Base domain to enumerate
            wordlist: Custom wordlist (defaults to COMMON_SUBDOMAINS + ENTERPRISE_SUBDOMAINS)
            use_crtsh: Whether to query crt.sh for certificate transparency logs
            use_subfinder: Whether to use subfinder (if available)
            use_chaos: Whether to use Chaos dataset (if configured)
            use_extended_wordlist: Whether to include enterprise/cloud patterns
            depth: Current recursion depth (for tracking)
            progress_callback: Optional callback for progress updates (current, total)
            
        Returns:
            List of discovered subdomains
        """
        discovered = {}

        # Steps 1–3: run every passive source concurrently. Each source is
        # independent — they hit different APIs — so running them serially
        # wastes the full duration of the slowest on every scan.
        async def _from_chaos() -> tuple[str, list[str]]:
            if not (use_chaos and self.use_chaos and self.chaos_service):
                return "chaos", []
            logger.info(f"[Depth {depth}] Querying Chaos dataset for {domain}")
            try:
                return "chaos", await self.chaos_service.fetch_subdomains(domain)
            except Exception as exc:
                logger.warning(f"[Depth {depth}] Chaos failed for {domain}: {exc}")
                return "chaos", []

        async def _from_subfinder() -> tuple[str, list[str]]:
            if not (use_subfinder and self.use_subfinder):
                return "subfinder", []
            logger.info(f"[Depth {depth}] Running subfinder for {domain}")
            try:
                return "subfinder", await self._run_subfinder(domain, recursive=(depth == 0))
            except Exception as exc:
                logger.warning(f"[Depth {depth}] Subfinder failed for {domain}: {exc}")
                return "subfinder", []

        async def _from_crtsh() -> tuple[str, list[str]]:
            if not use_crtsh:
                return "crt.sh", []
            logger.info(f"[Depth {depth}] Querying certificate transparency logs for {domain}")
            try:
                return "crt.sh", await self._query_crtsh(domain)
            except Exception as exc:
                logger.warning(f"[Depth {depth}] crt.sh failed for {domain}: {exc}")
                return "crt.sh", []

        async def _from_shodan_ctl() -> tuple[str, list[str]]:
            if not use_crtsh:
                return "shodan_ctl", []
            logger.info(f"[Depth {depth}] Querying Shodan CTL for {domain}")
            try:
                return "shodan_ctl", await self._query_shodan_ctl(domain)
            except Exception as exc:
                logger.warning(f"[Depth {depth}] Shodan CTL failed for {domain}: {exc}")
                return "shodan_ctl", []

        async def _from_crt_name() -> tuple[str, list[str]]:
            if not use_crtsh:
                return "crt_name", []
            logger.info(f"[Depth {depth}] Querying crt.name index for {domain}")
            try:
                return "crt_name", await self._query_crt_name(domain)
            except Exception as exc:
                logger.warning(f"[Depth {depth}] crt.name failed for {domain}: {exc}")
                return "crt_name", []

        async def _from_subcat() -> tuple[str, list[str]]:
            if not self.use_subcat:
                return "subcat", []
            logger.info(f"[Depth {depth}] Running subcat for {domain}")
            try:
                return "subcat", await self._run_subcat(domain)
            except Exception as exc:
                logger.warning(f"[Depth {depth}] Subcat failed for {domain}: {exc}")
                return "subcat", []

        async def _from_subfaster() -> tuple[str, list[str]]:
            if not self.use_subfaster:
                return "subfaster", []
            logger.info(f"[Depth {depth}] Running subfaster for {domain}")
            try:
                return "subfaster", await self._run_subfaster(domain)
            except Exception as exc:
                logger.warning(f"[Depth {depth}] Subfaster failed for {domain}: {exc}")
                return "subfaster", []

        passive_results = await asyncio.gather(
            _from_chaos(),
            _from_subfinder(),
            _from_crtsh(),
            _from_shodan_ctl(),
            _from_crt_name(),
            _from_subcat(),
            _from_subfaster(),
        )

        for source, hosts in passive_results:
            for subdomain in hosts:
                if subdomain not in discovered:
                    discovered[subdomain] = SubdomainResult(
                        subdomain=subdomain,
                        ip_addresses=[],
                        source=source,
                        depth=depth,
                    )
            logger.info(f"[Depth {depth}] {source} found {len(hosts)} subdomains for {domain}")
        
        # 4. Brute-force subdomains with extended wordlist
        if wordlist:
            brute_wordlist = wordlist
        elif use_extended_wordlist:
            brute_wordlist = COMMON_SUBDOMAINS + ENTERPRISE_SUBDOMAINS
        else:
            brute_wordlist = COMMON_SUBDOMAINS
            
        logger.info(f"[Depth {depth}] Brute-forcing {len(brute_wordlist)} subdomain names for {domain}")
        
        total = len(brute_wordlist)
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_subdomain(prefix: str, index: int):
            async with semaphore:
                subdomain = f"{prefix}.{domain}"
                result = await self._check_subdomain_exists(subdomain)
                result.depth = depth
                if progress_callback:
                    progress_callback(index + 1, total)
                return result
        
        tasks = [check_subdomain(prefix, i) for i, prefix in enumerate(brute_wordlist)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, SubdomainResult) and result.ip_addresses:
                if result.subdomain not in discovered:
                    discovered[result.subdomain] = result
                else:
                    # Update with IP addresses
                    discovered[result.subdomain].ip_addresses = result.ip_addresses
                    discovered[result.subdomain].is_alive = True
        
        # 5. Resolve IPs for all discovered subdomains
        logger.info(f"[Depth {depth}] Resolving IP addresses for {len(discovered)} discovered subdomains")
        resolve_tasks = []
        subdomain_keys = list(discovered.keys())
        
        for subdomain in subdomain_keys:
            result = discovered[subdomain]
            if not result.ip_addresses:
                resolve_tasks.append(self._resolve_subdomain(subdomain))
        
        if resolve_tasks:
            resolved_ips = await asyncio.gather(*resolve_tasks, return_exceptions=True)
            for subdomain, ips in zip(subdomain_keys, resolved_ips):
                if isinstance(ips, list):
                    discovered[subdomain].ip_addresses = ips
                    discovered[subdomain].is_alive = len(ips) > 0

        if filter_wildcards and discovered:
            try:
                resolved_map = {
                    sub: (set(res.ip_addresses or []), set())
                    for sub, res in discovered.items()
                }
                kept, dropped, _profile = await _filter_wildcards(
                    zone=domain,
                    hostnames=list(discovered.keys()),
                    resolved=resolved_map,
                    profile=wildcard_profile,
                )
                if dropped:
                    logger.info(
                        f"[Depth {depth}] Wildcard filter removed {len(dropped)} subdomains for {domain}"
                    )
                    for host in dropped:
                        discovered.pop(host, None)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(f"[Depth {depth}] Wildcard filter failed for {domain}: {exc}")

        logger.info(f"[Depth {depth}] Total subdomains discovered for {domain}: {len(discovered)}")
        return list(discovered.values())
    
    async def enumerate_recursive(
        self,
        domain: str,
        max_depth: int = 2,
        min_subdomains_for_recursion: int = 3,
        use_crtsh: bool = True,
        use_subfinder: bool = True,
        use_chaos: bool = True,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> RecursiveEnumerationResult:
        """
        Perform recursive multi-level subdomain enumeration.
        
        This discovers subdomains at multiple depth levels. For example:
        - Depth 0: cloud.example.com
        - Depth 1: api.cloud.example.com, portal.cloud.example.com
        - Depth 2: dev.api.cloud.example.com
        
        Args:
            domain: Root domain to enumerate
            max_depth: Maximum recursion depth (default 2 for 3 levels total)
            min_subdomains_for_recursion: Only recurse into subdomains with at least this many children
            use_crtsh: Whether to use crt.sh
            use_subfinder: Whether to use subfinder
            use_chaos: Whether to use Chaos
            progress_callback: Callback(current_domain, depth, total_found)
            
        Returns:
            RecursiveEnumerationResult with all discovered subdomains
        """
        from datetime import datetime
        start_time = datetime.utcnow()
        
        result = RecursiveEnumerationResult(root_domain=domain)
        all_discovered: Set[str] = set()
        domains_to_enumerate = [(domain, 0)]  # (domain, depth)
        enumerated_domains: Set[str] = set()
        
        logger.info(f"Starting recursive enumeration for {domain} (max_depth={max_depth})")
        
        while domains_to_enumerate:
            current_domain, current_depth = domains_to_enumerate.pop(0)
            
            # Skip if already enumerated or beyond max depth
            if current_domain in enumerated_domains:
                continue
            if current_depth > max_depth:
                continue
                
            enumerated_domains.add(current_domain)
            
            logger.info(f"[Depth {current_depth}] Enumerating {current_domain}")
            
            if progress_callback:
                progress_callback(current_domain, current_depth, len(all_discovered))
            
            try:
                # Enumerate subdomains at this level
                subdomains = await self.enumerate_subdomains(
                    domain=current_domain,
                    use_crtsh=use_crtsh,
                    use_subfinder=use_subfinder,
                    use_chaos=use_chaos,
                    use_extended_wordlist=(current_depth == 0),  # Use extended list only at root
                    depth=current_depth
                )
                
                # Track new discoveries
                new_count = 0
                for sub in subdomains:
                    if sub.subdomain not in all_discovered:
                        all_discovered.add(sub.subdomain)
                        sub.depth = current_depth
                        result.all_subdomains.append(sub)
                        new_count += 1
                        
                        # Track by depth
                        if current_depth not in result.subdomains_by_depth:
                            result.subdomains_by_depth[current_depth] = 0
                        result.subdomains_by_depth[current_depth] += 1
                
                logger.info(f"[Depth {current_depth}] Found {new_count} new subdomains for {current_domain}")
                
                # Find intermediate subdomains to recurse into
                # E.g., if we find "api.cloud.example.com", we should also enumerate "cloud.example.com"
                if current_depth < max_depth:
                    intermediate_domains = self._extract_intermediate_subdomains(
                        subdomains=[s.subdomain for s in subdomains],
                        root_domain=domain
                    )
                    
                    for intermediate in intermediate_domains:
                        if intermediate not in enumerated_domains and intermediate != domain:
                            # Count how many subdomains this intermediate has
                            child_count = sum(
                                1 for s in subdomains 
                                if s.subdomain.endswith(f".{intermediate}")
                            )
                            
                            if child_count >= min_subdomains_for_recursion or intermediate.count('.') <= domain.count('.') + 2:
                                domains_to_enumerate.append((intermediate, current_depth + 1))
                                logger.debug(f"Queuing {intermediate} for depth {current_depth + 1} enumeration (has {child_count} children)")
                
            except Exception as e:
                error_msg = f"Error enumerating {current_domain}: {str(e)}"
                logger.error(error_msg)
                result.errors.append(error_msg)
        
        result.total_subdomains = len(all_discovered)
        result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(
            f"Recursive enumeration complete for {domain}: "
            f"{result.total_subdomains} subdomains in {result.duration_seconds:.2f}s"
        )
        
        return result
    
    def _extract_intermediate_subdomains(
        self, 
        subdomains: list[str], 
        root_domain: str
    ) -> Set[str]:
        """
        Extract intermediate subdomain levels for recursive enumeration.
        
        E.g., from "api.cloud.example.com" extract "cloud.example.com"
        """
        intermediates = set()
        root_parts = root_domain.split('.')
        root_depth = len(root_parts)
        
        for subdomain in subdomains:
            parts = subdomain.split('.')
            # Skip if it's the root domain
            if len(parts) <= root_depth:
                continue
            
            # Extract each intermediate level
            # E.g., for "a.b.c.example.com" with root "example.com", extract:
            # - "c.example.com"
            # - "b.c.example.com"
            for i in range(1, len(parts) - root_depth):
                intermediate = '.'.join(parts[i:])
                if intermediate != root_domain and intermediate.endswith(f".{root_domain}"):
                    intermediates.add(intermediate)
        
        return intermediates
    
    async def _run_subfinder(
        self, 
        domain: str, 
        timeout: int = 120,
        recursive: bool = False
    ) -> list[str]:
        """
        Run subfinder for passive subdomain enumeration.
        
        Subfinder queries 40+ passive sources including:
        - Certificate transparency (crtsh, certspotter, digicert, etc.)
        - DNS databases (DNSDumpster, RapidDNS, etc.)
        - Search engines (Bing, Yahoo, etc.)
        - Threat intelligence (VirusTotal, AlienVault, ThreatCrowd, etc.)
        - Web archives (Wayback Machine, CommonCrawl)
        - And many more...
        
        Args:
            domain: Target domain
            timeout: Execution timeout in seconds
            recursive: If True, use subfinder's recursive mode for multi-level discovery
        
        Reference: https://github.com/projectdiscovery/subfinder
        """
        import tempfile
        import json
        
        subdomains = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                "subfinder",
                "-d", domain,
                "-json",
                "-o", output_path,
                "-silent",
                "-timeout", str(timeout),
                "-all",  # Use all sources for maximum coverage
            ]
            
            # Enable recursive enumeration for multi-level subdomain discovery
            if recursive:
                cmd.append("-recursive")
                logger.info(f"Executing subfinder with recursive mode: {' '.join(cmd)}")
            else:
                logger.info(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout + 60  # Extra buffer for recursive mode
            )
            
            if stderr:
                stderr_text = stderr.decode()[:500]
                if "error" in stderr_text.lower():
                    logger.warning(f"Subfinder stderr: {stderr_text}")
                else:
                    logger.debug(f"Subfinder output: {stderr_text}")
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                subdomain = data.get("host", "")
                                if subdomain:
                                    subdomains.append(subdomain.lower())
                            except json.JSONDecodeError:
                                # Plain text output - just the subdomain
                                if '.' in line and not line.startswith('#'):
                                    subdomains.append(line.lower())
            
            logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
            
        except asyncio.TimeoutError:
            logger.warning(f"Subfinder timed out for {domain} after {timeout}s")
        except Exception as e:
            logger.error(f"Subfinder failed for {domain}: {e}")
        finally:
            if os.path.exists(output_path):
                try:
                    os.unlink(output_path)
                except Exception:
                    pass
        
        return list(set(subdomains))  # Remove duplicates

    async def _run_subfaster(self, domain: str, timeout: int = 120) -> list[str]:
        """
        Run subfaster for fast passive subdomain enumeration.

        Speed-focused subfinder fork. Default sources (no keys): thc, submd,
        crt (crt.name), shodanct, rapiddns, hackertarget, sitedossier.

        Reference: https://github.com/melvinsh/subfaster
        """
        subdomains = []

        try:
            # -silent is default; pass -d only. Output is one hostname per line.
            cmd = ["subfaster", "-d", domain]
            logger.info(f"Executing: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout + 30,
            )

            if stderr:
                stderr_text = stderr.decode()[:500]
                if "error" in stderr_text.lower():
                    logger.warning(f"Subfaster stderr: {stderr_text}")
                else:
                    logger.debug(f"Subfaster output: {stderr_text}")

            for line in stdout.decode().splitlines():
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                for prefix in ("https://", "http://"):
                    if line.startswith(prefix):
                        line = line[len(prefix):]
                        break
                line = line.split("/")[0].split(":")[0]
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.append(line)

            logger.info(f"Subfaster found {len(subdomains)} subdomains for {domain}")

        except asyncio.TimeoutError:
            logger.warning(f"Subfaster timed out for {domain} after {timeout}s")
        except FileNotFoundError:
            logger.warning("Subfaster binary not found")
        except Exception as e:
            logger.error(f"Subfaster failed for {domain}: {e}")

        return list(set(subdomains))

    async def _run_subcat(self, domain: str, timeout: int = 120) -> list[str]:
        """
        Run subcat for passive subdomain enumeration.

        Subcat aggregates data from 19 passive sources including dnsdumpster,
        hackertarget, anubis, crt.sh, wayback, virustotal, securitytrails, shodan,
        and more. Free-tier modules work without API keys; paid modules activate when
        ~/.subcat/config.yaml is populated.

        Reference: https://github.com/duty1g/subcat
        """
        subdomains = []

        try:
            cmd = [
                "subcat",
                "-d", domain,
                "-silent",
            ]
            logger.info(f"Executing: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout + 30,
            )

            if stderr:
                stderr_text = stderr.decode()[:500]
                if "error" in stderr_text.lower():
                    logger.warning(f"Subcat stderr: {stderr_text}")
                else:
                    logger.debug(f"Subcat output: {stderr_text}")

            for line in stdout.decode().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip URL scheme if present (subcat can output full URLs in some modes)
                for prefix in ("https://", "http://"):
                    if line.startswith(prefix):
                        line = line[len(prefix):]
                        break
                # Strip path/port if present
                line = line.split("/")[0].split(":")[0].lower()
                if "." in line and line.endswith(f".{domain}") or line == domain:
                    subdomains.append(line)

            logger.info(f"Subcat found {len(subdomains)} subdomains for {domain}")

        except asyncio.TimeoutError:
            logger.warning(f"Subcat timed out for {domain} after {timeout}s")
        except Exception as e:
            logger.error(f"Subcat failed for {domain}: {e}")

        return list(set(subdomains))

    async def _query_crtsh(self, domain: str) -> list[str]:
        """Query crt.sh certificate transparency logs."""
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    follow_redirects=True
                )
                
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Split by newline (crt.sh returns multiple names per cert)
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            # Remove wildcard prefix
                            if n.startswith("*."):
                                n = n[2:]
                            # Ensure it's a subdomain of the target
                            if n.endswith(f".{domain}") or n == domain:
                                subdomains.add(n)
        except Exception as e:
            logger.warning(f"crt.sh query failed for {domain}: {e}")
        
        return list(subdomains)

    async def _query_shodan_ctl(self, domain: str) -> list[str]:
        """Query Shodan's Certificate Transparency Logs mirror for hostnames.

        Returns a flat deduplicated list of every hostname seen across all CT
        logs for the given domain — free, no API key required.
        """
        subdomains = set()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://ctl.shodan.io/api/v1/domain/{domain}/hostnames",
                    follow_redirects=True,
                )
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        for hostname in data:
                            if not isinstance(hostname, str):
                                continue
                            hostname = hostname.strip().lower()
                            if hostname.startswith("*."):
                                hostname = hostname[2:]
                            if hostname.endswith(f".{domain}") or hostname == domain:
                                subdomains.add(hostname)
        except Exception as e:
            logger.warning(f"Shodan CTL query failed for {domain}: {e}")

        return list(subdomains)

    async def _query_crt_name(self, domain: str) -> list[str]:
        """Query crt.name aggregated subdomain index.

        Indexes live + historical CT, Common Crawl, CZDS, Chaos, blocklists,
        and active probes. Free, no API key (1000 req/IP/day).
        """
        subdomains = set()
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    f"https://crt.name/v1/search?apex={domain}&format=json&dates=1",
                    follow_redirects=True,
                )
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        for entry in data:
                            if isinstance(entry, str):
                                hostname = entry
                            elif isinstance(entry, dict):
                                hostname = entry.get("sub") or entry.get("name") or ""
                            else:
                                continue
                            if not isinstance(hostname, str):
                                continue
                            hostname = hostname.strip().lower()
                            if hostname.startswith("*."):
                                hostname = hostname[2:]
                            if hostname.endswith(f".{domain}") or hostname == domain:
                                subdomains.add(hostname)
                elif response.status_code == 429:
                    logger.warning(f"crt.name rate limited for {domain}")
        except Exception as e:
            logger.warning(f"crt.name query failed for {domain}: {e}")

        return list(subdomains)
    
    async def _check_subdomain_exists(self, subdomain: str) -> SubdomainResult:
        """Check if a subdomain exists via DNS."""
        result = SubdomainResult(
            subdomain=subdomain,
            ip_addresses=[],
            source="bruteforce"
        )
        
        ips = await self._resolve_subdomain(subdomain)
        if ips:
            result.ip_addresses = ips
            result.is_alive = True
        
        return result
    
    async def _resolve_subdomain(self, subdomain: str) -> list[str]:
        """Resolve subdomain to IP addresses."""
        ips = []
        
        # Run DNS resolution in executor to not block
        loop = asyncio.get_event_loop()
        
        try:
            # Try A records
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(subdomain, 'A')
            )
            ips.extend([str(rdata.address) for rdata in answers])
        except Exception:
            pass
        
        try:
            # Try AAAA records
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(subdomain, 'AAAA')
            )
            ips.extend([str(rdata.address) for rdata in answers])
        except Exception:
            pass
        
        return ips
    
    def enumerate_subdomains_sync(
        self,
        domain: str,
        wordlist: Optional[list[str]] = None,
        use_crtsh: bool = True
    ) -> list[SubdomainResult]:
        """Synchronous wrapper for subdomain enumeration."""
        return asyncio.run(
            self.enumerate_subdomains(domain, wordlist, use_crtsh)
        )

















