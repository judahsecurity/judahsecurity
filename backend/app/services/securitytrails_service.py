"""
SecurityTrails service for reverse-lookup domain discovery.

SecurityTrails is the single highest-coverage reverse-lookup source: one API
provides reverse-NS, reverse-MX, reverse-WHOIS (by registrant email / registrar),
associated-domain discovery, and historical WHOIS (which defeats GDPR/privacy
redaction on the registrant pivot).

This is the capability that catches the "off-corporate-registrar" long tail —
e.g. domains registered through Squarespace/GoDaddy by a marketing team but still
tied to the org via a shared registrant email or historical WHOIS record.

API docs: https://docs.securitytrails.com/reference
Auth: request header ``APIKEY: <key>``.
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)


# Nameserver / mail-server providers that are SHARED across huge numbers of
# unrelated tenants. Reverse-NS / reverse-MX on these returns millions of
# unrelated domains, so we never auto-pivot on them (they can only be used if
# an operator explicitly lists them as owned infrastructure).
SHARED_DNS_PROVIDERS = {
    "azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",
    "googledomains.com", "google.com", "googlemail.com", "domaincontrol.com",
    "cloudflare.com", "awsdns-01.org", "awsdns.com", "amazonaws.com",
    "ns.cloudflare.com", "registrar-servers.com", "dnsmadeeasy.com",
    "akam.net", "akamai.net", "ultradns.com", "ultradns.net", "ultradns.org",
    "nsone.net", "dnsimple.com", "name-services.com", "worldnic.com",
    "wixdns.net", "squarespacedns.com", "sedoparking.com", "parkingcrew.net",
    "outlook.com", "pphosted.com", "mailgun.org", "sendgrid.net",
    "messagelabs.com", "protection.outlook.com", "secureserver.net",
    "1and1.com", "ovh.net", "gandi.net",
}


# Providers that are shared even at hostname granularity: their per-zone
# hostnames (e.g. ns1-08.azure-dns.com) are NOT tenant-specific, so reverse
# lookups on them return unrelated domains regardless of how specific the host.
ALWAYS_SHARED_TOKENS = (
    "azure-dns", "awsdns", "googledomains", "google.com", "googlemail",
    "cloudflare", "domaincontrol.com", "registrar-servers.com",
    "name-services.com", "worldnic.com", "wixdns", "squarespacedns",
)


def _registrable(host: str) -> str:
    """Best-effort registrable-domain reduction for provider blocklist checks."""
    host = (host or "").strip(".").lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_shared_pivot(host: str) -> bool:
    """
    Decide whether reversing on `host` would return unrelated domains.

    A fully-qualified, tenant-specific hostname (e.g.
    ``mxa-001e2002.gslb.pphosted.com`` or ``dns1.cscdns.net``) IS a valid
    org pivot even though its registrable domain (pphosted.com / cscdns.net)
    is a shared provider. We only skip:
      - bare provider apexes (``pphosted.com``), which are too broad, and
      - providers that are shared even per-hostname (azure-dns, awsdns, ...).
    """
    h = (host or "").strip(".").lower()
    if not h:
        return True
    if any(tok in h for tok in ALWAYS_SHARED_TOKENS):
        return True
    registrable = _registrable(h)
    # Bare provider apex (host == its own registrable) that is a known shared
    # provider -> too broad to pivot on.
    if h == registrable and registrable in SHARED_DNS_PROVIDERS:
        return True
    return False


class SecurityTrailsService:
    """SecurityTrails API client focused on reverse-lookup asset discovery."""

    BASE_URL = "https://api.securitytrails.com/v1"
    RATE_LIMIT_DELAY = 1.0  # seconds between requests (free tier is strict)

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._headers = {
            "APIKEY": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------ #
    # Low-level request helpers
    # ------------------------------------------------------------------ #
    async def _get(self, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        url = f"{self.BASE_URL}{path}"
        try:
            async with httpx.AsyncClient(timeout=30.0, headers=self._headers) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 429:
                    logger.warning("SecurityTrails rate limited, backing off 10s")
                    await asyncio.sleep(10)
                    return await self._get(path, params)
                if resp.status_code == 401:
                    logger.error("SecurityTrails: invalid/unauthorized API key")
                    return None
                if resp.status_code != 200:
                    logger.warning(f"SecurityTrails GET {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
                    return None
                return resp.json()
        except Exception as e:
            logger.error(f"SecurityTrails GET {path} error: {e}")
            return None

    async def _post(self, path: str, body: Dict, params: Optional[Dict] = None) -> Optional[Dict]:
        url = f"{self.BASE_URL}{path}"
        try:
            async with httpx.AsyncClient(timeout=30.0, headers=self._headers) as client:
                resp = await client.post(url, params=params, json=body)
                if resp.status_code == 429:
                    logger.warning("SecurityTrails rate limited, backing off 10s")
                    await asyncio.sleep(10)
                    return await self._post(path, body, params)
                if resp.status_code == 401:
                    logger.error("SecurityTrails: invalid/unauthorized API key")
                    return None
                if resp.status_code != 200:
                    logger.warning(f"SecurityTrails POST {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
                    return None
                return resp.json()
        except Exception as e:
            logger.error(f"SecurityTrails POST {path} error: {e}")
            return None

    @staticmethod
    def _extract_hostnames(payload: Optional[Dict]) -> List[str]:
        """Pull hostnames out of a /domains/list or /associated response."""
        if not payload:
            return []
        out: List[str] = []
        for rec in payload.get("records", []) or []:
            host = rec.get("hostname") or rec.get("apex_domain")
            if host:
                out.append(host.strip().lower())
        return out

    # ------------------------------------------------------------------ #
    # Seed enrichment: learn the org's registrant identity + infrastructure
    # ------------------------------------------------------------------ #
    async def get_whois(self, domain: str) -> Dict[str, Any]:
        """Current WHOIS for a domain (registrant emails, registrar, org)."""
        return await self._get(f"/domain/{domain}/whois") or {}

    async def get_whois_history(self, domain: str) -> Dict[str, Any]:
        """Historical WHOIS — exposes registrant identity from before redaction."""
        return await self._get(f"/history/{domain}/whois") or {}

    async def get_dns(self, domain: str) -> Dict[str, Any]:
        """Current DNS record set (used to read NS/MX for the seed)."""
        return await self._get(f"/domain/{domain}") or {}

    @staticmethod
    def _emails_from_whois(whois: Dict[str, Any]) -> Set[str]:
        emails: Set[str] = set()
        if not whois:
            return emails
        top = whois.get("contactEmail")
        if top and "@" in str(top):
            emails.add(str(top).strip().lower())
        for contact in whois.get("contacts", []) or []:
            em = contact.get("email")
            if em and "@" in str(em):
                emails.add(str(em).strip().lower())
        # Historical WHOIS nests records under result.items[]
        result = whois.get("result") or {}
        for item in result.get("items", []) or []:
            em = item.get("contactEmail")
            if em and "@" in str(em):
                emails.add(str(em).strip().lower())
            for contact in item.get("contact", []) or item.get("contacts", []) or []:
                cem = contact.get("email")
                if cem and "@" in str(cem):
                    emails.add(str(cem).strip().lower())
        return {e for e in emails if _is_valid_email(e) and not _is_privacy_email(e)}

    # ------------------------------------------------------------------ #
    # Reverse lookups (the core capability)
    # ------------------------------------------------------------------ #
    async def _list_by_filter(self, filt: Dict[str, str], max_pages: int = 5) -> List[str]:
        """Reverse lookup via the documented `filter` body on /domains/list."""
        hostnames: List[str] = []
        page = 1
        while page <= max_pages:
            payload = await self._post(
                "/domains/list",
                body={"filter": filt},
                params={"include_ips": "false", "scroll": "false", "page": page},
            )
            if not payload:
                break
            batch = self._extract_hostnames(payload)
            hostnames.extend(batch)
            total_pages = payload.get("meta", {}).get("total_pages") or 1
            if page >= total_pages or not batch:
                break
            page += 1
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return hostnames

    async def _list_by_dsl(self, query: str, max_pages: int = 5) -> List[str]:
        """Reverse lookup via the DSL `query` body (needed for registrar field)."""
        hostnames: List[str] = []
        page = 1
        while page <= max_pages:
            payload = await self._post(
                "/domains/list",
                body={"query": query},
                params={"include_ips": "false", "scroll": "false", "page": page},
            )
            if not payload:
                break
            batch = self._extract_hostnames(payload)
            hostnames.extend(batch)
            total_pages = payload.get("meta", {}).get("total_pages") or 1
            if page >= total_pages or not batch:
                break
            page += 1
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return hostnames

    async def reverse_whois_email(self, email: str, max_pages: int = 5) -> List[str]:
        """All domains whose WHOIS registrant email matches `email`."""
        logger.info(f"SecurityTrails reverse-WHOIS by email: {email}")
        return await self._list_by_filter({"whois_email": email}, max_pages)

    async def reverse_whois_registrar(self, registrar: str, max_pages: int = 5) -> List[str]:
        """All domains registered through `registrar` (use with a keyword to scope)."""
        safe = registrar.replace("'", "")
        logger.info(f"SecurityTrails reverse-WHOIS by registrar: {registrar}")
        return await self._list_by_dsl(f"whois_registrar = '{safe}'", max_pages)

    async def reverse_ns(self, nameserver: str, max_pages: int = 5) -> List[str]:
        """All domains served by nameserver `nameserver`."""
        logger.info(f"SecurityTrails reverse-NS: {nameserver}")
        return await self._list_by_filter({"ns": nameserver}, max_pages)

    async def reverse_mx(self, mailserver: str, max_pages: int = 5) -> List[str]:
        """All domains whose MX points at `mailserver`."""
        logger.info(f"SecurityTrails reverse-MX: {mailserver}")
        return await self._list_by_filter({"mx": mailserver}, max_pages)

    async def associated_domains(self, domain: str, max_pages: int = 5) -> List[str]:
        """Domains SecurityTrails associates with `domain` (registrant/infra graph)."""
        logger.info(f"SecurityTrails associated domains for: {domain}")
        hostnames: List[str] = []
        page = 1
        while page <= max_pages:
            payload = await self._get(f"/domain/{domain}/associated", params={"page": page})
            if not payload:
                break
            batch = self._extract_hostnames(payload)
            hostnames.extend(batch)
            total_pages = payload.get("meta", {}).get("total_pages") or 1
            if page >= total_pages or not batch:
                break
            page += 1
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return hostnames

    # ------------------------------------------------------------------ #
    # Full reverse-discovery workflow
    # ------------------------------------------------------------------ #
    async def discover_related_domains(
        self,
        domain: Optional[str] = None,
        registration_emails: Optional[List[str]] = None,
        registrar_names: Optional[List[str]] = None,
        owned_nameservers: Optional[List[str]] = None,
        owned_mailservers: Optional[List[str]] = None,
        use_history: bool = True,
        max_pages_per_query: int = 5,
    ) -> Dict[str, Any]:
        """
        Reverse-lookup discovery workflow:

        1. Enrich the seed domain: read current + historical WHOIS (registrant
           emails) and its associated-domain graph.
        2. Reverse-WHOIS on every discovered/registrant email.
        3. Reverse-WHOIS by registrar (only when scoped registrar names given).
        4. Reverse-NS / reverse-MX ONLY on explicitly-owned infrastructure
           (shared providers like azure-dns/mailgun are skipped automatically).

        Returns a dict with the aggregated `related_domains` plus a breakdown by
        pivot so each discovered domain can be attributed to how it was found.
        """
        result: Dict[str, Any] = {
            "target_domain": domain,
            "discovered_emails": [],
            "related_domains": [],
            "domains_by_email": {},
            "domains_by_registrar": {},
            "domains_by_ns": {},
            "domains_by_mx": {},
            "domains_associated": [],
            "total_domains_found": 0,
            "timestamp": datetime.utcnow().isoformat(),
        }

        emails: Set[str] = set()
        for e in registration_emails or []:
            if _is_valid_email(e.lower()) and not _is_privacy_email(e.lower()):
                emails.add(e.lower())

        all_domains: Set[str] = set()

        # Step 1: seed enrichment (WHOIS + history + associated)
        if domain:
            whois = await self.get_whois(domain)
            emails |= self._emails_from_whois(whois)
            if use_history:
                await asyncio.sleep(self.RATE_LIMIT_DELAY)
                history = await self.get_whois_history(domain)
                emails |= self._emails_from_whois(history)

            await asyncio.sleep(self.RATE_LIMIT_DELAY)
            assoc = await self.associated_domains(domain, max_pages_per_query)
            result["domains_associated"] = assoc
            all_domains.update(assoc)

        result["discovered_emails"] = sorted(emails)

        # Step 2: reverse-WHOIS by email
        for email in emails:
            domains = await self.reverse_whois_email(email, max_pages_per_query)
            result["domains_by_email"][email] = domains
            all_domains.update(domains)
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        # Step 3: reverse-WHOIS by registrar (must be scoped; only if provided)
        for registrar in registrar_names or []:
            domains = await self.reverse_whois_registrar(registrar, max_pages_per_query)
            result["domains_by_registrar"][registrar] = domains
            all_domains.update(domains)
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        # Step 4: reverse-NS / reverse-MX on OWNED infra only
        for ns in owned_nameservers or []:
            if _is_shared_pivot(ns):
                logger.info(f"Skipping reverse-NS on shared/too-broad provider: {ns}")
                continue
            domains = await self.reverse_ns(ns, max_pages_per_query)
            result["domains_by_ns"][ns] = domains
            all_domains.update(domains)
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        for mx in owned_mailservers or []:
            if _is_shared_pivot(mx):
                logger.info(f"Skipping reverse-MX on shared/too-broad provider: {mx}")
                continue
            domains = await self.reverse_mx(mx, max_pages_per_query)
            result["domains_by_mx"][mx] = domains
            all_domains.update(domains)
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        # Clean + finalize
        all_domains = {d.strip().lower() for d in all_domains if d and "." in d}
        result["related_domains"] = sorted(all_domains)
        result["total_domains_found"] = len(all_domains)
        logger.info(
            f"SecurityTrails reverse-discovery for {domain}: "
            f"{len(all_domains)} related domains from {len(emails)} email(s)"
        )
        return result


def _is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email))


def _is_privacy_email(email: str) -> bool:
    privacy_markers = [
        "privacy", "proxy", "protect", "whoisguard", "redacted", "withheld",
        "gdpr", "domainsbyproxy", "perfectprivacy", "contactprivacy",
        "not.disclosed", "anonymize", "identity-protect",
    ]
    e = email.lower()
    return any(m in e for m in privacy_markers)


def get_securitytrails_service(api_key: str) -> SecurityTrailsService:
    """Get a SecurityTrails service instance with the given API key."""
    return SecurityTrailsService(api_key)
