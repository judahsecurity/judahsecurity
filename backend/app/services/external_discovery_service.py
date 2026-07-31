"""
External Discovery Service

Integrates multiple external intelligence sources for comprehensive asset discovery:
- WhoisXML API - IP/CIDR ranges by organization name
- Whoxy - Reverse WHOIS by registration email
- VirusTotal - Subdomain enumeration
- AlienVault OTX - Passive DNS and URL data
- Wayback Machine - Historical subdomains
- RapidDNS - Subdomain enumeration
- Common Crawl - Web crawl data
- Microsoft 365 - Federated domain discovery
- ASN Discovery - BGP/ASN data for organizations
- Shodan CTL - Certificate Transparency Logs hostname discovery (free, no key)
- crt.name - Aggregated CT/DNS subdomain index with first-seen dates (free, no key)

Based on ASM Recon discovery methodology.
"""

import asyncio
import logging
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Set, Tuple
import json

import httpx
from sqlalchemy.orm import Session

from app.models.api_config import APIConfig, ExternalService, DEFAULT_RATE_LIMITS

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    """Result from an external discovery source."""
    source: str
    success: bool
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)  # CIDRs
    asns: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    error: Optional[str] = None
    raw_data: Optional[Dict] = None
    elapsed_time: float = 0.0


class ExternalDiscoveryService:
    """
    Service for discovering assets using external intelligence sources.
    """
    
    def __init__(self, db: Session, organization_id: int):
        """
        Initialize the external discovery service.
        
        Args:
            db: Database session
            organization_id: Organization to use API configs from
        """
        self.db = db
        self.organization_id = organization_id
        self._api_configs: Dict[str, APIConfig] = {}
        self._load_api_configs()
    
    def _load_api_configs(self):
        """Load API configurations for the organization."""
        configs = self.db.query(APIConfig).filter(
            APIConfig.organization_id == self.organization_id,
            APIConfig.is_active == True
        ).all()
        
        for config in configs:
            self._api_configs[config.service_name] = config
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service."""
        config = self._api_configs.get(service)
        if config:
            return config.get_api_key()
        return None
    
    def get_config(self, service: str) -> Optional[Dict]:
        """Get service-specific configuration."""
        config = self._api_configs.get(service)
        if config:
            return config.config
        return {}
    
    async def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[str] = None,
        timeout: int = 30
    ) -> Tuple[bool, Any]:
        """Make an HTTP request with error handling."""
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=params)
                else:
                    response = await client.post(url, headers=headers, data=data)
                
                if response.status_code == 200:
                    try:
                        return True, response.json()
                    except:
                        return True, response.text
                else:
                    return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            return False, str(e)

    # =========================================================================
    # WhoisXML API - IP/CIDR Ranges by Organization
    # =========================================================================
    
    async def discover_whoisxml(
        self,
        organization_names: Optional[List[str]] = None
    ) -> DiscoveryResult:
        """
        Discover IP ranges and CIDRs using WhoisXML API based on organization names.
        
        Args:
            organization_names: List of organization names to search for
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.WHOISXML, success=False)
        
        api_key = self.get_api_key(ExternalService.WHOISXML)
        if not api_key:
            result.error = "WhoisXML API key not configured"
            return result
        
        config = self.get_config(ExternalService.WHOISXML)
        org_names = organization_names or config.get("organization_names", [])
        
        if not org_names:
            result.error = "No organization names configured"
            return result
        
        url = "https://ip-netblocks.whoisxmlapi.com/api/v2"
        
        all_ips = set()
        all_cidrs = set()
        
        for org_name in org_names:
            try:
                params = {
                    "apiKey": api_key,
                    "org[]": org_name,
                    "limit": 1000
                }
                
                success, data = await self._make_request(url, params=params)
                
                if not success:
                    logger.warning(f"WhoisXML error for {org_name}: {data}")
                    continue
                
                if "result" in data and "inetnums" in data["result"]:
                    for inetnum in data["result"]["inetnums"]:
                        if "org" not in inetnum:
                            continue
                        
                        org = inetnum.get("org", {})
                        org_name_found = org.get("name", "").lower()
                        org_email = org.get("email", "").lower()
                        
                        # Verify this matches our organization
                        org_search = org_name.lower()
                        if org_search not in org_name_found and org_search not in org_email:
                            continue
                        
                        inetnum_value = inetnum.get("inetnum", "")
                        if ":" in inetnum_value:  # Skip IPv6
                            continue
                        
                        # Parse IP range
                        if " - " in inetnum_value:
                            first, last = inetnum_value.split(" - ")
                            # Convert to CIDR(s)
                            cidrs = self._ip_range_to_cidrs(first.strip(), last.strip())
                            all_cidrs.update(cidrs)
                            # Also expand to individual IPs for small ranges
                            ips = self._expand_ip_range(first.strip(), last.strip())
                            all_ips.update(ips)
                
                await asyncio.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                logger.error(f"WhoisXML error for {org_name}: {e}")
        
        result.success = True
        result.ip_addresses = list(all_ips)
        result.ip_ranges = list(all_cidrs)
        result.elapsed_time = time.time() - start_time
        
        return result
    
    def _ip_range_to_cidrs(self, first: str, last: str) -> List[str]:
        """Convert IP range to CIDR notation."""
        try:
            import ipaddress
            first_ip = ipaddress.IPv4Address(first)
            last_ip = ipaddress.IPv4Address(last)
            
            cidrs = []
            for cidr in ipaddress.summarize_address_range(first_ip, last_ip):
                cidrs.append(str(cidr))
            return cidrs
        except Exception as e:
            logger.warning(f"Could not convert IP range {first}-{last}: {e}")
            return []
    
    def _expand_ip_range(self, first: str, last: str, max_ips: int = 256) -> List[str]:
        """Expand IP range to individual IPs (limited to max_ips)."""
        try:
            import ipaddress
            first_ip = ipaddress.IPv4Address(first)
            last_ip = ipaddress.IPv4Address(last)
            
            count = int(last_ip) - int(first_ip) + 1
            if count > max_ips:
                return []  # Too large to expand
            
            ips = []
            current = first_ip
            while current <= last_ip:
                # Skip network and broadcast addresses for /24 and larger
                ips.append(str(current))
                current += 1
            return ips
        except Exception as e:
            logger.warning(f"Could not expand IP range {first}-{last}: {e}")
            return []

    # =========================================================================
    # Whoxy - Full Domain Reconnaissance (WHOIS + Reverse WHOIS)
    # =========================================================================
    
    async def discover_whoxy(
        self,
        domain: Optional[str] = None,
        registration_emails: Optional[List[str]] = None,
        organization_names: Optional[List[str]] = None
    ) -> DiscoveryResult:
        """
        Discover domains using Whoxy with full reconnaissance workflow:
        1. WHOIS lookup on target domain (if provided)
        2. Extract emails and company names from WHOIS
        3. Reverse WHOIS by emails and companies
        
        Args:
            domain: Target domain for WHOIS lookup
            registration_emails: Additional email addresses for reverse WHOIS
            organization_names: Additional company names for reverse WHOIS
        """
        from app.services.whoxy_service import get_whoxy_service
        
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.WHOXY, success=False)
        
        api_key = self.get_api_key(ExternalService.WHOXY)
        if not api_key:
            result.error = "Whoxy API key not configured"
            return result
        
        config = self.get_config(ExternalService.WHOXY)
        emails = registration_emails or config.get("registration_emails", [])
        companies = organization_names or config.get("organization_names", [])
        
        # If no domain, emails, or companies to search, return error
        if not domain and not emails and not companies:
            result.error = "No domain, registration emails, or organization names configured"
            return result
        
        try:
            whoxy_service = get_whoxy_service(api_key)
            
            # Full discovery workflow
            # Increased to 20 pages to capture more domains (2000 per query)
            discovery_data = await whoxy_service.discover_related_domains(
                domain=domain or "",
                additional_emails=emails,
                additional_companies=companies,
                max_pages_per_query=20  # Increased from 5 to get more domains
            )
            
            result.success = True
            result.domains = discovery_data.get("related_domains", [])
            result.raw_data = {
                "whois_data": discovery_data.get("whois_data", {}),
                "discovered_emails": discovery_data.get("discovered_emails", []),
                "discovered_companies": discovery_data.get("discovered_companies", []),
                "domains_by_email": discovery_data.get("domains_by_email", {}),
                "domains_by_company": discovery_data.get("domains_by_company", {}),
                "total_domains_found": discovery_data.get("total_domains_found", 0)
            }
            
            logger.info(f"Whoxy discovery found {len(result.domains)} domains")
            
        except Exception as e:
            logger.error(f"Whoxy discovery error: {e}")
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # SecurityTrails - Reverse lookups (NS / MX / WHOIS) + associated domains
    # =========================================================================

    async def discover_securitytrails(
        self,
        domain: Optional[str] = None,
        registration_emails: Optional[List[str]] = None,
        organization_names: Optional[List[str]] = None,
    ) -> DiscoveryResult:
        """
        Discover related domains via SecurityTrails reverse lookups.

        This is the privacy-proof / off-corporate-registrar pivot: it finds
        domains sharing the org's registrant email (current OR historical WHOIS),
        SecurityTrails' associated-domain graph, and — when the operator has
        configured explicitly-owned nameservers/mailservers — reverse-NS/MX.

        Config (api_configs.config for service "securitytrails"):
            - registration_emails: seed registrant emails to reverse
            - registrar_names:     scoped registrar names for reverse-by-registrar
            - owned_nameservers:   org-specific NS to reverse (shared providers skipped)
            - owned_mailservers:   org-specific MX to reverse (shared providers skipped)
        """
        from app.services.securitytrails_service import get_securitytrails_service

        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.SECURITYTRAILS, success=False)

        api_key = self.get_api_key(ExternalService.SECURITYTRAILS)
        if not api_key:
            result.error = "SecurityTrails API key not configured"
            return result

        config = self.get_config(ExternalService.SECURITYTRAILS) or {}
        emails = registration_emails or config.get("registration_emails", [])
        registrar_names = config.get("registrar_names", [])

        if not domain and not emails:
            result.error = "No domain or registration emails configured"
            return result

        try:
            st = get_securitytrails_service(api_key)
            # NS/MX reverse lookups are handled by the provider-agnostic
            # `discover_reverse_dns` source, so we leave them empty here to
            # avoid duplicate API calls / credit usage.
            data = await st.discover_related_domains(
                domain=domain,
                registration_emails=emails,
                registrar_names=registrar_names,
                owned_nameservers=None,
                owned_mailservers=None,
                use_history=True,
                max_pages_per_query=5,
            )

            base = (domain or "").lower()
            related = data.get("related_domains", [])
            # Split apex/registrable domains vs subdomains of the seed
            for host in related:
                if base and (host == base or host.endswith("." + base)):
                    result.subdomains.append(host)
                else:
                    result.domains.append(host)

            result.success = True
            result.raw_data = {
                "discovered_emails": data.get("discovered_emails", []),
                "domains_by_email": data.get("domains_by_email", {}),
                "domains_by_registrar": data.get("domains_by_registrar", {}),
                "domains_by_ns": data.get("domains_by_ns", {}),
                "domains_by_mx": data.get("domains_by_mx", {}),
                "domains_associated": data.get("domains_associated", []),
                "total_domains_found": data.get("total_domains_found", 0),
            }
            logger.info(
                f"SecurityTrails discovery found {len(result.domains)} domains "
                f"and {len(result.subdomains)} subdomains"
            )
        except Exception as e:
            logger.error(f"SecurityTrails discovery error: {e}")
            result.error = str(e)

        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Reverse-NS / Reverse-MX - privacy-proof infrastructure pivot
    # (provider-agnostic: uses WhoisXML and/or SecurityTrails)
    # =========================================================================

    def _get_owned_infrastructure(self) -> Tuple[List[str], List[str]]:
        """
        Read explicitly-owned nameservers/mailservers from whichever service
        config carries them (securitytrails or whoisxml). These are the
        org-specific hosts to reverse on (e.g. dns1.cscdns.net, the Proofpoint
        tenant MX mxa-XXXXXXXX.gslb.pphosted.com).
        """
        owned_ns: List[str] = []
        owned_mx: List[str] = []
        for svc in (ExternalService.SECURITYTRAILS, ExternalService.WHOISXML):
            cfg = self.get_config(svc) or {}
            owned_ns.extend(cfg.get("owned_nameservers", []) or [])
            owned_mx.extend(cfg.get("owned_mailservers", []) or [])
        # Dedupe, preserve order
        owned_ns = list(dict.fromkeys(n.strip().lower() for n in owned_ns if n and n.strip()))
        owned_mx = list(dict.fromkeys(m.strip().lower() for m in owned_mx if m and m.strip()))
        return owned_ns, owned_mx

    async def _resolve_domain_infrastructure(self, domain: str) -> Tuple[List[str], List[str]]:
        """
        Resolve the primary domain's NS + MX via DNS (free, no API credits) and
        return only the org-specific hosts (shared providers filtered out).
        Used to auto-seed reverse-NS/MX pivots without manual configuration.
        """
        from app.services.securitytrails_service import _is_shared_pivot
        from app.services.dns_service import DNSService

        ns_hosts: List[str] = []
        mx_hosts: List[str] = []
        try:
            svc = DNSService()
            records = await asyncio.to_thread(svc.enumerate_domain, domain)
            for ns in records.ns_records or []:
                host = str(ns).strip().rstrip(".").lower()
                if host and not _is_shared_pivot(host):
                    ns_hosts.append(host)
            for mx in records.mx_records or []:
                host = str(mx.get("host", "")).strip().rstrip(".").lower()
                if host and not _is_shared_pivot(host):
                    mx_hosts.append(host)
        except Exception as e:
            logger.warning(f"Auto-seed DNS resolution failed for {domain}: {e}")
        return list(dict.fromkeys(ns_hosts)), list(dict.fromkeys(mx_hosts))

    @staticmethod
    def _hosts_from_dns_records(dns_records: Any) -> Tuple[List[str], List[str]]:
        """Extract (ns_hosts, mx_hosts) from a stored Asset.dns_records blob."""
        ns_hosts: List[str] = []
        mx_hosts: List[str] = []
        if not isinstance(dns_records, dict):
            return ns_hosts, mx_hosts
        for ns in dns_records.get("NS", []) or dns_records.get("ns", []) or []:
            host = (ns if isinstance(ns, str) else ns.get("host", "")).strip().rstrip(".").lower()
            if host:
                ns_hosts.append(host)
        for mx in dns_records.get("MX", []) or dns_records.get("mx", []) or []:
            host = (mx if isinstance(mx, str) else mx.get("host", "")).strip().rstrip(".").lower()
            if host:
                mx_hosts.append(host)
        return ns_hosts, mx_hosts

    async def _collect_org_infra_counts(
        self,
        sample_size: int = 150,
        live_resolve_cap: int = 40,
    ) -> Tuple["Counter", "Counter", int]:
        """
        Sample NS/MX across many in-scope assets and count how often each
        org-specific host recurs. Uses stored ``Asset.dns_records`` when present
        (free) and live-resolves up to ``live_resolve_cap`` assets that lack
        records. Returns (ns_counter, mx_counter, sampled_asset_count).
        """
        from collections import Counter
        from app.models.asset import Asset, AssetType
        from app.services.securitytrails_service import _is_shared_pivot

        ns_counter: Counter = Counter()
        mx_counter: Counter = Counter()
        try:
            assets = (
                self.db.query(Asset)
                .filter(
                    Asset.organization_id == self.organization_id,
                    Asset.in_scope == True,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                )
                .limit(sample_size)
                .all()
            )
        except Exception as e:
            logger.warning(f"Infra sampling DB query failed: {e}")
            return ns_counter, mx_counter, 0

        needs_live: List[str] = []
        sampled_assets = 0
        for asset in assets:
            ns_hosts, mx_hosts = self._hosts_from_dns_records(asset.dns_records)
            if ns_hosts or mx_hosts:
                sampled_assets += 1
                for h in set(ns_hosts):
                    if not _is_shared_pivot(h):
                        ns_counter[h] += 1
                for h in set(mx_hosts):
                    if not _is_shared_pivot(h):
                        mx_counter[h] += 1
            elif asset.value:
                needs_live.append(asset.value.strip().lower())

        needs_live = needs_live[:live_resolve_cap]
        if needs_live:
            sem = asyncio.Semaphore(10)

            async def _resolve(host: str) -> Tuple[List[str], List[str]]:
                async with sem:
                    return await self._resolve_domain_infrastructure(host)

            for ns_hosts, mx_hosts in await asyncio.gather(
                *[_resolve(h) for h in needs_live], return_exceptions=False
            ):
                if ns_hosts or mx_hosts:
                    sampled_assets += 1
                for h in set(ns_hosts):
                    ns_counter[h] += 1
                for h in set(mx_hosts):
                    mx_counter[h] += 1

        return ns_counter, mx_counter, sampled_assets

    async def _sample_org_infrastructure(
        self,
        sample_size: int = 150,
        live_resolve_cap: int = 40,
        min_shared: int = 2,
    ) -> Tuple[List[str], List[str]]:
        """
        Learn the org's shared infrastructure by sampling NS/MX across MANY
        in-scope assets — not just the primary domain. This is what surfaces
        pivots like the Proofpoint tenant MX or CSC nameservers even when the
        apex domain itself sits on a shared provider (e.g. Azure DNS).

        Returns only org-specific hosts that recur on ``min_shared``+ assets
        (recurrence is the ownership signal; one-offs are dropped as noise).
        """
        ns_counter, mx_counter, sampled_assets = await self._collect_org_infra_counts(
            sample_size, live_resolve_cap
        )
        # Adaptive threshold: for tiny orgs a single occurrence is enough
        threshold = 1 if sampled_assets < 10 else min_shared
        ns_seeds = sorted([h for h, c in ns_counter.items() if c >= threshold],
                          key=lambda h: -ns_counter[h])
        mx_seeds = sorted([h for h, c in mx_counter.items() if c >= threshold],
                          key=lambda h: -mx_counter[h])
        if ns_seeds or mx_seeds:
            logger.info(
                f"Sampled {sampled_assets} assets -> org infra pivots "
                f"NS={ns_seeds[:10]} MX={mx_seeds[:10]}"
            )
        return ns_seeds, mx_seeds

    async def get_reverse_pivot_plan(
        self,
        domain: Optional[str] = None,
        whois_preview: bool = True,
        min_shared: int = 2,
    ) -> Dict[str, Any]:
        """
        Read-only "what would reverse discovery pivot on?" plan. Spends NO
        purchase credits: NS/MX pivots come from config + free DNS/stored
        records, and reverse-WHOIS uses WhoisXML's free ``preview`` mode to
        report the would-return domain count per registrant term.
        """
        from app.services.securitytrails_service import _is_shared_pivot

        cfg_ns, cfg_mx = self._get_owned_infrastructure()
        st_cfg = self.get_config(ExternalService.SECURITYTRAILS) or {}
        wx_cfg = self.get_config(ExternalService.WHOISXML) or {}

        # host -> {seen_on_assets, sources}
        ns_plan: Dict[str, Dict[str, Any]] = {}
        mx_plan: Dict[str, Dict[str, Any]] = {}

        def _add(plan, host, source, seen=None):
            host = (host or "").strip().rstrip(".").lower()
            if not host or _is_shared_pivot(host):
                return
            entry = plan.setdefault(host, {"host": host, "seen_on_assets": 0, "sources": []})
            if source not in entry["sources"]:
                entry["sources"].append(source)
            if seen is not None:
                entry["seen_on_assets"] = max(entry["seen_on_assets"], seen)

        for h in cfg_ns:
            _add(ns_plan, h, "config")
        for h in cfg_mx:
            _add(mx_plan, h, "config")

        if domain:
            d_ns, d_mx = await self._resolve_domain_infrastructure(domain)
            for h in d_ns:
                _add(ns_plan, h, "primary_domain")
            for h in d_mx:
                _add(mx_plan, h, "primary_domain")

        ns_counter, mx_counter, sampled_assets = await self._collect_org_infra_counts()
        threshold = 1 if sampled_assets < 10 else min_shared
        for h, c in ns_counter.items():
            if c >= threshold:
                _add(ns_plan, h, "sampled", seen=c)
        for h, c in mx_counter.items():
            if c >= threshold:
                _add(mx_plan, h, "sampled", seen=c)

        # Reverse-WHOIS preview (free) for configured registrant terms
        whois_terms = list(dict.fromkeys(
            (st_cfg.get("registration_emails", []) or [])
            + (wx_cfg.get("registration_emails", []) or [])
            + (wx_cfg.get("organization_names", []) or [])
        ))
        whois_preview_results: List[Dict[str, Any]] = []
        wx_key = self.get_api_key(ExternalService.WHOISXML)
        if whois_preview and wx_key and whois_terms:
            from app.services.whoisxml_reverse_service import get_whoisxml_reverse_service
            wx = get_whoisxml_reverse_service(wx_key)
            for term in whois_terms:
                count = await wx.reverse_whois_preview([term])
                whois_preview_results.append({
                    "term": term,
                    "would_return_domains": count,  # -1 == preview error/unknown
                })

        providers = [
            p for p, key in (
                ("whoisxml", self.get_api_key(ExternalService.WHOISXML)),
                ("securitytrails", self.get_api_key(ExternalService.SECURITYTRAILS)),
            ) if key
        ]

        return {
            "organization_id": self.organization_id,
            "primary_domain": domain,
            "sampled_assets": sampled_assets,
            "min_shared_threshold": threshold,
            "providers_available": providers,
            "nameserver_pivots": sorted(ns_plan.values(), key=lambda x: -x["seen_on_assets"]),
            "mailserver_pivots": sorted(mx_plan.values(), key=lambda x: -x["seen_on_assets"]),
            "reverse_whois_preview": whois_preview_results,
            "note": (
                "Read-only plan. NS/MX pivots and asset sampling are free; "
                "reverse-WHOIS counts use WhoisXML preview mode (no credits spent). "
                "Running discovery will spend provider quota/credits."
            ),
        }

    async def discover_reverse_dns(
        self,
        owned_nameservers: Optional[List[str]] = None,
        owned_mailservers: Optional[List[str]] = None,
        domain: Optional[str] = None,
        auto_seed: bool = True,
        sample_org_assets: bool = True,
        pivot_nameservers: Optional[List[str]] = None,
        pivot_mailservers: Optional[List[str]] = None,
    ) -> DiscoveryResult:
        """
        Discover domains that share the org's OWNED nameservers or mail servers.

        This is the privacy-proof pivot that catches redacted/off-registrar
        domains (e.g. everything on Rockwell's Proofpoint tenant or CSC managed
        DNS). It queries WhoisXML and/or SecurityTrails — whichever have keys —
        and unions the results. Shared/too-broad providers (azure-dns, awsdns,
        bare provider apexes) are skipped automatically.

        NS/MX to pivot on come from (unioned): the explicit argument, service
        config (`owned_nameservers`/`owned_mailservers`), and — when
        ``auto_seed`` is set — auto-discovered infrastructure: the primary
        ``domain``'s own NS/MX plus (when ``sample_org_assets`` is set) hosts
        that recur across many in-scope assets. All auto-seeding uses free DNS /
        stored records and keeps only org-specific hosts.
        """
        from app.services.securitytrails_service import (
            get_securitytrails_service,
            _is_shared_pivot,
        )
        from app.services.whoisxml_reverse_service import get_whoisxml_reverse_service

        start_time = time.time()
        result = DiscoveryResult(source="reverse_dns", success=False)

        # Explicit allowlist mode: when the caller passes a curated set of
        # pivots (e.g. the user toggled hosts on the preview card), pivot on
        # EXACTLY those hosts — no config merge, no auto-seeding, no surprises.
        explicit_pivots = pivot_nameservers is not None or pivot_mailservers is not None
        if explicit_pivots:
            auto_seed = False
            owned_ns = list(dict.fromkeys(
                h.strip().rstrip(".").lower() for h in (pivot_nameservers or []) if h and h.strip()
            ))
            owned_mx = list(dict.fromkeys(
                h.strip().rstrip(".").lower() for h in (pivot_mailservers or []) if h and h.strip()
            ))
        else:
            cfg_ns, cfg_mx = self._get_owned_infrastructure()
            owned_ns = list(owned_nameservers if owned_nameservers is not None else cfg_ns)
            owned_mx = list(owned_mailservers if owned_mailservers is not None else cfg_mx)

        # Auto-seed pivots (org-specific hosts only):
        #   (a) the primary domain's own live NS/MX, and
        #   (b) infra that recurs across MANY in-scope assets (Proofpoint tenant,
        #       CSC nameservers, etc.) — this catches org infra even when the
        #       apex domain sits on a shared provider like Azure DNS.
        auto_ns: List[str] = []
        auto_mx: List[str] = []
        if auto_seed:
            if domain:
                d_ns, d_mx = await self._resolve_domain_infrastructure(domain)
                auto_ns.extend(d_ns)
                auto_mx.extend(d_mx)
            if sample_org_assets:
                s_ns, s_mx = await self._sample_org_infrastructure()
                auto_ns.extend(s_ns)
                auto_mx.extend(s_mx)
            auto_ns = list(dict.fromkeys(auto_ns))
            auto_mx = list(dict.fromkeys(auto_mx))
            owned_ns = list(dict.fromkeys(owned_ns + auto_ns))
            owned_mx = list(dict.fromkeys(owned_mx + auto_mx))

        wx_key = self.get_api_key(ExternalService.WHOISXML)
        st_key = self.get_api_key(ExternalService.SECURITYTRAILS)

        if not wx_key and not st_key:
            result.error = "No reverse-lookup provider configured (need WhoisXML or SecurityTrails key)"
            return result
        if not owned_ns and not owned_mx:
            result.error = "No owned or auto-seeded nameservers / mailservers to pivot on"
            return result

        wx = get_whoisxml_reverse_service(wx_key) if wx_key else None
        st = get_securitytrails_service(st_key) if st_key else None

        domains_by_ns: Dict[str, List[str]] = {}
        domains_by_mx: Dict[str, List[str]] = {}
        all_domains: Set[str] = set()

        async def _reverse(host: str, kind: str) -> List[str]:
            found: Set[str] = set()
            try:
                if wx:
                    found.update(await (wx.reverse_ns(host) if kind == "ns" else wx.reverse_mx(host)))
                if st:
                    found.update(await (st.reverse_ns(host) if kind == "ns" else st.reverse_mx(host)))
            except Exception as e:
                logger.error(f"reverse-{kind} error for {host}: {e}")
            return sorted(d for d in found if d and "." in d)

        for ns in owned_ns:
            if _is_shared_pivot(ns):
                logger.info(f"Skipping reverse-NS on shared/too-broad host: {ns}")
                continue
            found = await _reverse(ns, "ns")
            domains_by_ns[ns] = found
            all_domains.update(found)

        for mx in owned_mx:
            if _is_shared_pivot(mx):
                logger.info(f"Skipping reverse-MX on shared/too-broad host: {mx}")
                continue
            found = await _reverse(mx, "mx")
            domains_by_mx[mx] = found
            all_domains.update(found)

        result.success = True
        result.domains = sorted(all_domains)
        result.raw_data = {
            "domains_by_ns": domains_by_ns,
            "domains_by_mx": domains_by_mx,
            "providers": [p for p, on in (("whoisxml", wx), ("securitytrails", st)) if on],
            "auto_seeded_ns": auto_ns,
            "auto_seeded_mx": auto_mx,
            "pivoted_nameservers": owned_ns,
            "pivoted_mailservers": owned_mx,
            "total_domains_found": len(all_domains),
        }
        logger.info(
            f"Reverse-DNS discovery found {len(all_domains)} domains from "
            f"{len(domains_by_ns)} NS + {len(domains_by_mx)} MX pivots"
        )
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # VirusTotal - Subdomain Enumeration
    # =========================================================================
    
    async def discover_virustotal(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains using VirusTotal API.
        
        Args:
            domain: Domain to search for subdomains
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.VIRUSTOTAL, success=False)
        
        api_key = self.get_api_key(ExternalService.VIRUSTOTAL)
        if not api_key:
            result.error = "VirusTotal API key not configured"
            return result
        
        # Using v2 API as it returns up to 100 subdomains in one request
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            "apikey": api_key,
            "domain": domain
        }
        
        try:
            success, data = await self._make_request(url, params=params)
            
            if not success:
                result.error = f"VirusTotal error: {data}"
                return result
            
            if isinstance(data, dict):
                if "error" in data:
                    result.error = data["error"]
                    return result
                
                subdomains = data.get("subdomains", [])
                if subdomains:
                    result.subdomains = [s.lower() for s in subdomains]
                    result.success = True
                else:
                    result.success = True  # No error, just no subdomains
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # AlienVault OTX - Passive DNS
    # =========================================================================
    
    async def discover_otx(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains using AlienVault OTX passive DNS and URL data.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.OTX, success=False)
        
        api_key = self.get_api_key(ExternalService.OTX)
        if not api_key:
            result.error = "OTX API key not configured"
            return result
        
        base_url = "https://otx.alienvault.com/api/v1"
        headers = {"X-OTX-API-KEY": api_key}
        
        all_subdomains = set()
        
        try:
            # Encode domain for punycode
            try:
                punycode_domain = domain.encode("idna").decode()
            except:
                punycode_domain = domain
            
            # Get passive DNS data
            url = f"{base_url}/indicators/domain/{punycode_domain}/passive_dns"
            success, data = await self._make_request(url, headers=headers)
            
            if success and "passive_dns" in data:
                for record in data["passive_dns"]:
                    hostname = record.get("hostname", "").lower()
                    if hostname.endswith(f".{domain}"):
                        all_subdomains.add(hostname)
            
            await asyncio.sleep(0.5)
            
            # Get URL list data
            url = f"{base_url}/indicators/domain/{punycode_domain}/url_list"
            success, data = await self._make_request(url, headers=headers)
            
            if success and "url_list" in data:
                for record in data["url_list"]:
                    hostname = record.get("hostname", "").lower()
                    if hostname.endswith(f".{domain}"):
                        all_subdomains.add(hostname)
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Wayback Machine - Historical Subdomains
    # =========================================================================
    
    async def discover_wayback(self, domain: str) -> DiscoveryResult:
        """
        Discover historical subdomains from Wayback Machine.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.WAYBACK, success=False)
        
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "txt",
            "fl": "original",
            "collapse": "urlkey"
        }
        
        try:
            success, data = await self._make_request(url, params=params, timeout=60)
            
            if not success:
                result.error = f"Wayback error: {data}"
                return result
            
            all_subdomains = set()
            
            if isinstance(data, str):
                lines = data.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        parsed = urllib.parse.urlparse(line)
                        hostname = parsed.netloc.lower()
                        
                        # Remove port if present
                        if ":" in hostname:
                            hostname = hostname.split(":")[0]
                        
                        if hostname and hostname.endswith(f".{domain}"):
                            all_subdomains.add(hostname)
                    except:
                        continue
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # RapidDNS - Subdomain Enumeration
    # =========================================================================
    
    async def discover_rapiddns(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains using RapidDNS.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.RAPIDDNS, success=False)
        
        url = f"https://rapiddns.io/subdomain/{domain}"
        params = {"full": "1"}
        
        try:
            success, data = await self._make_request(url, params=params, timeout=30)
            
            if not success:
                result.error = f"RapidDNS error: {data}"
                return result
            
            all_subdomains = set()
            
            if isinstance(data, str):
                # Parse HTML response - look for subdomains in table
                # Simple regex extraction
                pattern = rf'<td>([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(domain)})</td>'
                matches = re.findall(pattern, data, re.IGNORECASE)
                
                for match in matches:
                    subdomain = match.lower()
                    if subdomain.endswith(f".{domain}"):
                        all_subdomains.add(subdomain)
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Microsoft 365 - Federated Domain Discovery
    # =========================================================================
    
    async def discover_m365(self, domain: str) -> DiscoveryResult:
        """
        Discover Microsoft 365 federated domains.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.M365, success=False)
        
        # SOAP request to Microsoft autodiscover
        body = f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
            xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
            <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
            <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
            <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
            <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <Request>
                <Domain>{domain}</Domain>
            </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
        </soap:Envelope>"""
        
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "User-Agent": "AutodiscoverClient"
        }
        
        url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        
        # Unrelated domains to filter out
        unrelated_domains = ["call2teams.com", "onmicrosoft.com", "audiocodesaas.com"]
        
        try:
            success, data = await self._make_request(
                url, method="POST", headers=headers, data=body, timeout=30
            )
            
            if not success:
                result.error = f"M365 error: {data}"
                return result
            
            all_domains = set()
            
            if isinstance(data, str):
                try:
                    tree = ET.fromstring(data)
                    ns = "{http://schemas.microsoft.com/exchange/2010/Autodiscover}"
                    
                    for elem in tree.iter(f"{ns}Domain"):
                        found_domain = elem.text.lower() if elem.text else ""
                        
                        # Filter out unrelated domains
                        skip = False
                        for unrelated in unrelated_domains:
                            if unrelated in found_domain:
                                skip = True
                                break
                        
                        if not skip and found_domain:
                            all_domains.add(found_domain)
                except ET.ParseError:
                    result.error = "Failed to parse M365 response"
                    return result
            
            result.success = True
            result.domains = list(all_domains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # crt.sh - Certificate Transparency
    # =========================================================================
    
    async def discover_crtsh(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains from certificate transparency logs (crt.sh).
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.CRTSH, success=False)
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            success, data = await self._make_request(url, timeout=60)
            
            if not success:
                result.error = f"crt.sh error: {data}"
                return result
            
            all_subdomains = set()
            
            if isinstance(data, list):
                for cert in data:
                    name_value = cert.get("name_value", "")
                    # Split by newlines (multiple names per cert)
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        # Remove wildcard prefix
                        if name.startswith("*."):
                            name = name[2:]
                        
                        if name.endswith(f".{domain}") or name == domain:
                            all_subdomains.add(name)
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Shodan CTL - Certificate Transparency Logs
    # =========================================================================

    async def discover_shodan_ctl(self, domain: str) -> DiscoveryResult:
        """
        Discover hostnames from Shodan's Certificate Transparency Logs mirror.

        Queries https://ctl.shodan.io/api/v1/domain/{domain}/hostnames which
        returns a deduplicated flat list of every hostname seen across all CT
        logs for the given domain — no API key required.

        Args:
            domain: Root domain to search (e.g. "example.com")
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.SHODAN_CTL, success=False)

        url = f"https://ctl.shodan.io/api/v1/domain/{domain}/hostnames"

        try:
            success, data = await self._make_request(url, timeout=30)

            if not success:
                result.error = f"Shodan CTL error: {data}"
                return result

            # Response is a plain JSON array of hostname strings
            if isinstance(data, list):
                all_subdomains = set()
                for hostname in data:
                    if not isinstance(hostname, str):
                        continue
                    hostname = hostname.strip().lower()
                    if hostname.startswith("*."):
                        hostname = hostname[2:]
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        all_subdomains.add(hostname)

                result.success = True
                result.subdomains = list(all_subdomains)
            else:
                result.error = "Unexpected response format from Shodan CTL"

        except Exception as e:
            result.error = str(e)

        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # crt.name - Aggregated CT / DNS subdomain index
    # =========================================================================

    async def discover_crt_name(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains from crt.name's aggregated subdomain index.

        Queries https://crt.name/v1/search which indexes live CT logs, retired
        CT backfill, Common Crawl, ICANN CZDS, Chaos, DNS blocklists, and
        active probing. Free, no API key (1000 req/IP/day). Returns names with
        optional first-seen dates.

        Args:
            domain: Apex / eTLD+1 domain to search (e.g. "example.com")
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.CRT_NAME, success=False)

        # format=json&dates=1 → [{sub, first_seen}, ...]
        url = f"https://crt.name/v1/search?apex={domain}&format=json&dates=1"

        try:
            success, data = await self._make_request(url, timeout=60)

            if not success:
                result.error = f"crt.name error: {data}"
                return result

            all_subdomains = set()
            first_seen: Dict[str, str] = {}

            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, str):
                        hostname = entry
                        seen = None
                    elif isinstance(entry, dict):
                        hostname = entry.get("sub") or entry.get("name") or ""
                        seen = entry.get("first_seen")
                    else:
                        continue

                    if not isinstance(hostname, str):
                        continue
                    hostname = hostname.strip().lower()
                    if hostname.startswith("*."):
                        hostname = hostname[2:]
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        all_subdomains.add(hostname)
                        if seen and hostname not in first_seen:
                            first_seen[hostname] = seen

                result.success = True
                result.subdomains = list(all_subdomains)
                if first_seen:
                    result.raw_data = {"first_seen": first_seen, "count": len(all_subdomains)}
            else:
                result.error = "Unexpected response format from crt.name"

        except Exception as e:
            result.error = str(e)

        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Common Crawl - Web Crawl Data
    # =========================================================================
    
    async def discover_commoncrawl(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains from Common Crawl web archive.
        
        Uses S3-backed index if CC_S3_BUCKET is configured (fast, ~100ms).
        Falls back to CC Index API if S3 not configured or S3 sync fails.
        
        Args:
            domain: Domain to search (e.g., rockwellautomation.com)
        """
        import os
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.COMMONCRAWL, success=False)
        
        try:
            s3_bucket = os.getenv("CC_S3_BUCKET")
            used_s3 = False
            
            if s3_bucket:
                try:
                    from app.services.commoncrawl_s3_service import CommonCrawlS3Service
                    
                    cc_service = CommonCrawlS3Service(s3_bucket=s3_bucket)
                    synced = await cc_service.sync_from_s3()
                    
                    if synced:
                        cc_result = await cc_service.search_domain(domain)
                        
                        if not cc_result.error:
                            result.success = True
                            result.subdomains = cc_result.subdomains
                            used_s3 = True
                            logger.info(f"Common Crawl (S3) found {len(result.subdomains)} subdomains for {domain}")
                        else:
                            logger.warning(f"CC S3 search error: {cc_result.error}, falling back to API")
                    else:
                        logger.warning("CC S3 sync failed (index may not exist), falling back to API")
                except Exception as e:
                    logger.warning(f"CC S3 service error: {e}, falling back to API")
            
            if not used_s3:
                from app.services.commoncrawl_service import CommonCrawlService
                
                cc_service = CommonCrawlService(timeout=60.0)
                cc_result = await cc_service.search_domain(domain)
                
                if cc_result.error:
                    result.error = cc_result.error
                else:
                    result.success = True
                    result.subdomains = cc_result.subdomains
                    result.urls = cc_result.urls[:500]
                    
                logger.info(f"Common Crawl (API) found {len(result.subdomains)} subdomains for {domain}")
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Common Crawl error: {e}")
        
        result.elapsed_time = time.time() - start_time
        return result
    
    async def discover_commoncrawl_comprehensive(
        self,
        primary_domain: str,
        org_name: Optional[str] = None,
        keywords: Optional[List[str]] = None
    ) -> DiscoveryResult:
        """
        Comprehensive Common Crawl discovery for an organization.
        
        Searches for:
        1. Subdomains of primary domain (e.g., *.rockwellautomation.com)
        2. org_name.* across all TLDs (e.g., rockwellautomation.net, rockwellautomation.io)
        3. *org_name* pattern (e.g., mycompany-rockwellautomation.com)
        4. Keyword patterns (e.g., *rockwell* finds rockwellcollins.com, rockwell.com)
        
        Example:
            discover_commoncrawl_comprehensive(
                primary_domain="rockwellautomation.com",
                org_name="rockwellautomation",
                keywords=["rockwell"]
            )
        
        Args:
            primary_domain: Primary domain for subdomain search
            org_name: Organization name for TLD and pattern searches
            keywords: Additional keywords to search (e.g., ["rockwell"])
            
        Returns:
            DiscoveryResult with domains and subdomains
        """
        start_time = time.time()
        result = DiscoveryResult(source="commoncrawl_comprehensive", success=False)
        
        try:
            from app.services.commoncrawl_service import CommonCrawlService
            
            cc_service = CommonCrawlService(timeout=120.0)
            
            # Run comprehensive search
            cc_result = await cc_service.comprehensive_org_search(
                org_name=org_name or primary_domain.split(".")[0],
                keywords=keywords,
                primary_domain=primary_domain
            )
            
            if cc_result.error:
                result.error = cc_result.error
            else:
                result.success = True
                result.domains = cc_result.domains
                result.subdomains = cc_result.subdomains
                
            logger.info(
                f"Common Crawl comprehensive search: "
                f"{len(result.domains)} domains, {len(result.subdomains)} subdomains"
            )
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Common Crawl comprehensive error: {e}")
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # SNI IP Ranges Discovery - Cloud Asset Discovery
    # =========================================================================
    
    async def discover_sni_ip_ranges(
        self,
        domain: str,
        org_name: Optional[str] = None,
        keywords: Optional[List[str]] = None
    ) -> DiscoveryResult:
        """
        Discover cloud-hosted assets using SNI IP ranges data.
        
        Uses S3-backed index if SNI_S3_BUCKET or CC_S3_BUCKET is configured (fast).
        Falls back to direct download from kaeferjaeger.gay if S3 not available.
        
        Args:
            domain: Primary domain to search for
            org_name: Organization name for broader search
            keywords: Additional keywords to search
            
        Returns:
            DiscoveryResult with discovered domains, subdomains, and IPs
        """
        import os
        start_time = time.time()
        result = DiscoveryResult(source="sni_ip_ranges", success=False)
        
        effective_org = org_name or domain.split('.')[0]
        used_s3 = False
        
        try:
            # Try S3-backed service first (fast, pre-built index)
            s3_bucket = os.getenv("SNI_S3_BUCKET") or os.getenv("CC_S3_BUCKET")
            
            if s3_bucket:
                try:
                    from app.services.sni_s3_service import SNIS3Service
                    
                    sni_s3 = SNIS3Service(s3_bucket=s3_bucket)
                    synced = await sni_s3.sync_from_s3()
                    
                    if synced:
                        sni_result = await sni_s3.search_organization(
                            org_name=effective_org,
                            primary_domain=domain,
                            keywords=keywords
                        )
                        
                        if not sni_result.error:
                            result.success = True
                            result.domains = sni_result.domains
                            result.subdomains = sni_result.subdomains
                            result.ip_addresses = sni_result.ips
                            result.raw_data = {
                                "total_records": sni_result.total_records,
                                "by_cloud_provider": sni_result.by_provider,
                                "query": sni_result.query,
                                "source_mode": "s3",
                            }
                            used_s3 = True
                            
                            logger.info(
                                f"SNI IP ranges (S3): found {len(result.domains)} domains, "
                                f"{len(result.subdomains)} subdomains, {len(result.ip_addresses)} IPs"
                            )
                        else:
                            logger.warning(f"SNI S3 search error: {sni_result.error}, falling back to direct download")
                    else:
                        logger.warning("SNI S3 sync failed (index may not exist), falling back to direct download")
                except Exception as e:
                    logger.warning(f"SNI S3 service error: {e}, falling back to direct download")
            
            if not used_s3:
                from app.services.sni_scanner_service import get_sni_service
                
                service = get_sni_service()
                
                stats = service.get_stats()
                if stats["unique_domains"] == 0:
                    logger.info("SNI data not loaded, attempting sync from kaeferjaeger.gay...")
                    await service.sync_all_providers()
                
                sni_result = await service.search_organization(
                    org_name=effective_org,
                    primary_domain=domain,
                    keywords=keywords
                )
                
                if sni_result.success:
                    result.success = True
                    result.domains = sni_result.domains
                    result.subdomains = sni_result.subdomains
                    result.ip_addresses = sni_result.ips
                    result.raw_data = {
                        "total_records": sni_result.total_records,
                        "by_cloud_provider": sni_result.by_cloud_provider,
                        "query": sni_result.query,
                        "source_mode": "direct",
                    }
                    
                    logger.info(
                        f"SNI IP ranges (direct): found {len(result.domains)} domains, "
                        f"{len(result.subdomains)} subdomains, {len(result.ip_addresses)} IPs "
                        f"across {sni_result.by_cloud_provider}"
                    )
                else:
                    result.error = sni_result.error
                
        except ImportError:
            result.error = "SNI scanner service not available"
            logger.warning("SNI scanner service not installed")
        except Exception as e:
            result.error = str(e)
            logger.error(f"SNI IP ranges error: {e}")
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Full Discovery - Run All Sources
    # =========================================================================
    
    async def full_discovery(
        self,
        domain: str,
        include_paid: bool = True,
        include_free: bool = True,
        organization_names: Optional[List[str]] = None,
        registration_emails: Optional[List[str]] = None,
        commoncrawl_org_name: Optional[str] = None,
        commoncrawl_keywords: Optional[List[str]] = None,
        include_sni_discovery: bool = True,
        sni_keywords: Optional[List[str]] = None
    ) -> Dict[str, DiscoveryResult]:
        """
        Run full discovery using all available sources.
        
        Args:
            domain: Primary domain to discover assets for
            include_paid: Include paid API sources
            include_free: Include free sources
            organization_names: Organization names for WHOIS lookups
            registration_emails: Emails for reverse WHOIS
            commoncrawl_org_name: Organization name for CC comprehensive search
                                  (e.g., "rockwellautomation" to find rockwellautomation.*)
            commoncrawl_keywords: Keywords for CC keyword search
                                  (e.g., ["rockwell"] to find *rockwell* domains)
            include_sni_discovery: Include SNI IP ranges discovery (cloud asset discovery)
            sni_keywords: Additional keywords for SNI search
            
        Returns:
            Dictionary of results by source
        """
        results = {}
        tasks = []
        
        # Free sources (always available)
        if include_free:
            tasks.append(("wayback", self.discover_wayback(domain)))
            tasks.append(("rapiddns", self.discover_rapiddns(domain)))
            tasks.append(("crtsh", self.discover_crtsh(domain)))
            tasks.append(("shodan_ctl", self.discover_shodan_ctl(domain)))
            tasks.append(("crt_name", self.discover_crt_name(domain)))
            tasks.append(("m365", self.discover_m365(domain)))
            
            # Use comprehensive CC search if org_name or keywords provided
            if commoncrawl_org_name or commoncrawl_keywords:
                tasks.append(("commoncrawl", self.discover_commoncrawl_comprehensive(
                    primary_domain=domain,
                    org_name=commoncrawl_org_name,
                    keywords=commoncrawl_keywords
                )))
            else:
                # Basic subdomain search
                tasks.append(("commoncrawl", self.discover_commoncrawl(domain)))
            
            # SNI IP Ranges - discover cloud-hosted assets
            if include_sni_discovery:
                org_name = None
                if organization_names:
                    org_name = organization_names[0]
                elif commoncrawl_org_name:
                    org_name = commoncrawl_org_name
                else:
                    # Extract org name from domain (e.g., "rockwellautomation" from "rockwellautomation.com")
                    parts = domain.split('.')
                    if len(parts) >= 2:
                        org_name = parts[0]
                
                if org_name:
                    tasks.append(("sni_ip_ranges", self.discover_sni_ip_ranges(
                        domain=domain,
                        org_name=org_name,
                        keywords=sni_keywords or commoncrawl_keywords
                    )))
        
        # Paid sources (require API keys)
        if include_paid:
            if self.get_api_key(ExternalService.VIRUSTOTAL):
                tasks.append(("virustotal", self.discover_virustotal(domain)))
            
            if self.get_api_key(ExternalService.OTX):
                tasks.append(("otx", self.discover_otx(domain)))
            
            if self.get_api_key(ExternalService.WHOXY):
                # Whoxy can work with domain, emails, or company names
                tasks.append(("whoxy", self.discover_whoxy(
                    domain=domain,
                    registration_emails=registration_emails,
                    organization_names=organization_names
                )))
            
            if self.get_api_key(ExternalService.WHOISXML) and organization_names:
                tasks.append(("whoisxml", self.discover_whoisxml(organization_names)))

            if self.get_api_key(ExternalService.SECURITYTRAILS):
                # SecurityTrails reverse lookups (WHOIS + associated domains).
                # Privacy-proof pivot that catches off-corporate-registrar domains.
                tasks.append(("securitytrails", self.discover_securitytrails(
                    domain=domain,
                    registration_emails=registration_emails,
                    organization_names=organization_names,
                )))

            # Reverse-NS / reverse-MX on owned infrastructure (Proofpoint tenant,
            # CSC managed DNS, etc.). Runs when a reverse-lookup provider key
            # exists; NS/MX pivots come from config AND/OR are auto-seeded from
            # the primary domain's live NS/MX (org-specific hosts only).
            if (self.get_api_key(ExternalService.WHOISXML)
                    or self.get_api_key(ExternalService.SECURITYTRAILS)):
                tasks.append(("reverse_dns", self.discover_reverse_dns(
                    domain=domain,
                    auto_seed=True,
                )))
        
        # Run all tasks concurrently
        task_results = await asyncio.gather(
            *[t[1] for t in tasks],
            return_exceptions=True
        )
        
        # Map results to source names
        for i, (name, _) in enumerate(tasks):
            if isinstance(task_results[i], Exception):
                results[name] = DiscoveryResult(
                    source=name,
                    success=False,
                    error=str(task_results[i])
                )
            else:
                results[name] = task_results[i]
        
        return results
    
    def aggregate_results(
        self,
        results: Dict[str, DiscoveryResult],
        base_domain: str
    ) -> Dict[str, Set[str]]:
        """
        Aggregate results from all sources into deduplicated sets.
        
        Args:
            results: Results from full_discovery
            base_domain: Base domain for filtering
            
        Returns:
            Aggregated results with domains, subdomains, IPs, CIDRs
        """
        aggregated = {
            "domains": set(),
            "subdomains": set(),
            "ip_addresses": set(),
            "ip_ranges": set(),
            "asns": set(),
            "urls": set(),
        }
        
        for source, result in results.items():
            if not result.success:
                continue
            
            aggregated["domains"].update(result.domains)
            aggregated["subdomains"].update(result.subdomains)
            aggregated["ip_addresses"].update(result.ip_addresses)
            aggregated["ip_ranges"].update(result.ip_ranges)
            aggregated["asns"].update(result.asns)
            aggregated["urls"].update(result.urls)
        
        # Add base domain
        aggregated["domains"].add(base_domain)
        
        # Move exact domain matches from subdomains to domains
        to_move = []
        for sub in aggregated["subdomains"]:
            if sub == base_domain:
                to_move.append(sub)
        for sub in to_move:
            aggregated["subdomains"].remove(sub)
            aggregated["domains"].add(sub)
        
        return aggregated















