"""
WhoisXML reverse-lookup service (Reverse NS / Reverse MX / Reverse WHOIS).

This complements ``whoisxml_netblock_service`` (which covers org -> IP netblocks)
by exposing WhoisXML's domain-discovery reverse APIs. It uses the SAME WhoisXML
API key already configured for netblock discovery, so no new vendor is required.

Endpoints:
  - Reverse NS:    https://reverse-ns.whoisxmlapi.com/api/v1
  - Reverse MX:    https://reverse-mx.whoisxmlapi.com/api/v1
  - Reverse WHOIS: https://reverse-whois.whoisxmlapi.com/api/v2

Reverse NS/MX are privacy-proof pivots (they defeat GDPR/registrant redaction);
Reverse WHOIS pivots on registrant email/organization.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class WhoisXMLReverseService:
    """WhoisXML reverse-lookup client for domain discovery."""

    REVERSE_NS_URL = "https://reverse-ns.whoisxmlapi.com/api/v1"
    REVERSE_MX_URL = "https://reverse-mx.whoisxmlapi.com/api/v1"
    REVERSE_WHOIS_URL = "https://reverse-whois.whoisxmlapi.com/api/v2"
    RATE_LIMIT_DELAY = 0.5

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def _get_json(self, url: str, params: Dict) -> Optional[Dict]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 429:
                    logger.warning("WhoisXML reverse rate limited, backing off 10s")
                    await asyncio.sleep(10)
                    return await self._get_json(url, params)
                if resp.status_code != 200:
                    logger.warning(f"WhoisXML reverse {url} -> HTTP {resp.status_code}: {resp.text[:200]}")
                    return None
                return resp.json()
        except Exception as e:
            logger.error(f"WhoisXML reverse GET {url} error: {e}")
            return None

    async def _reverse_dns(self, url: str, key: str, value: str, max_pages: int = 5) -> List[str]:
        """
        Shared pager for Reverse NS / Reverse MX (both share response shape).

        Response: {"result": [{"name": "domain.com", ...}, ...], "size": N}
        Pagination: pass ``from=<last domain name>`` to fetch the next page.
        """
        domains: List[str] = []
        cursor: Optional[str] = None
        for _ in range(max_pages):
            params = {"apiKey": self.api_key, key: value, "outputFormat": "JSON"}
            if cursor:
                params["from"] = cursor
            data = await self._get_json(url, params)
            if not data:
                break
            batch = [r.get("name", "").strip().lower() for r in data.get("result", []) or []]
            batch = [b for b in batch if b]
            if not batch:
                break
            domains.extend(batch)
            # WhoisXML returns up to 300/page; fewer means we're done
            if len(batch) < 300:
                break
            cursor = batch[-1]
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        return domains

    async def reverse_ns(self, nameserver: str, max_pages: int = 5) -> List[str]:
        logger.info(f"WhoisXML reverse-NS: {nameserver}")
        return await self._reverse_dns(self.REVERSE_NS_URL, "ns", nameserver, max_pages)

    async def reverse_mx(self, mailserver: str, max_pages: int = 5) -> List[str]:
        logger.info(f"WhoisXML reverse-MX: {mailserver}")
        return await self._reverse_dns(self.REVERSE_MX_URL, "mx", mailserver, max_pages)

    def _build_reverse_whois_body(self, include_terms: List[str], search_type: str, mode: str) -> Dict:
        return {
            "apiKey": self.api_key,
            "searchType": search_type,
            "mode": mode,
            "punycode": True,
            "advancedSearchTerms": [
                {"field": "RegistrantContact.Email", "term": t, "exactMatch": True}
                if "@" in t else
                {"field": "RegistrantContact.Organization", "term": t, "exactMatch": False}
                for t in include_terms
            ],
        }

    async def reverse_whois_preview(
        self,
        include_terms: List[str],
        search_type: str = "current",
    ) -> int:
        """
        Cheap credit-guard: return how many domains a reverse-WHOIS query WOULD
        return, WITHOUT spending purchase credits (``mode=preview``).
        Returns -1 on error so callers can distinguish "unknown" from "zero".
        """
        if not include_terms:
            return 0
        body = self._build_reverse_whois_body(include_terms, search_type, "preview")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(self.REVERSE_WHOIS_URL, json=body)
                if resp.status_code != 200:
                    logger.warning(f"WhoisXML reverse-WHOIS preview HTTP {resp.status_code}: {resp.text[:200]}")
                    return -1
                data = resp.json()
                return int(data.get("domainsCount", 0) or 0)
        except Exception as e:
            logger.error(f"WhoisXML reverse-WHOIS preview error: {e}")
            return -1

    async def reverse_whois(
        self,
        include_terms: List[str],
        search_type: str = "current",
        preview_first: bool = True,
        max_domains: int = 5000,
    ) -> List[str]:
        """
        Reverse WHOIS by registrant term(s) (email or organization name).

        Credit-guarded: by default runs a free ``preview`` first and only spends
        ``purchase`` credits when the result set is non-empty and within
        ``max_domains``. A count above ``max_domains`` almost always means the
        term is too broad (e.g. a privacy-service org) and is skipped to protect
        your credit balance.
        """
        if not include_terms:
            return []

        if preview_first:
            count = await self.reverse_whois_preview(include_terms, search_type)
            if count == 0:
                logger.info(f"WhoisXML reverse-WHOIS preview: 0 domains for {include_terms}, skipping purchase")
                return []
            if count > max_domains:
                logger.warning(
                    f"WhoisXML reverse-WHOIS preview: {count} domains for {include_terms} "
                    f"exceeds max_domains={max_domains}; skipping purchase to protect credits"
                )
                return []
            logger.info(f"WhoisXML reverse-WHOIS preview: {count} domains for {include_terms}, purchasing")

        body = self._build_reverse_whois_body(include_terms, search_type, "purchase")
        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(self.REVERSE_WHOIS_URL, json=body)
                if resp.status_code != 200:
                    logger.warning(f"WhoisXML reverse-WHOIS HTTP {resp.status_code}: {resp.text[:200]}")
                    return []
                data = resp.json()
                return [d.strip().lower() for d in data.get("domainsList", []) or [] if d]
        except Exception as e:
            logger.error(f"WhoisXML reverse-WHOIS error: {e}")
            return []


def get_whoisxml_reverse_service(api_key: str) -> WhoisXMLReverseService:
    """Get a WhoisXML reverse-lookup service instance."""
    return WhoisXMLReverseService(api_key)
