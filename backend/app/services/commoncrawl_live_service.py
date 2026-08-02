"""
CommonCrawl Live CDX API service — two discovery modes.

MODE 1 — Subdomain enumeration (depth)
    Queries ``*.domain.com`` patterns to find every subdomain of root domains
    the org already owns.  Uses the same approach as CCrawlDNS.

MODE 2 — Brand / keyword discovery (breadth)
    Queries ``*keyword*`` patterns (e.g. "rockwellautomation", "factorytalk",
    "allen-bradley") to find hostnames the org may not know about yet:
    partner portals, shadow-IT, acquired-brand sites, unofficial domains, etc.
    Uses the org's ``commoncrawl_org_name`` and ``commoncrawl_keywords`` fields.

Both modes run through the live CommonCrawl CDX API — no S3 index required.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

CCRAWL_COLLECTIONS_URL = "https://index.commoncrawl.org/collinfo.json"
CCRAWL_INDEX_URL = "https://index.commoncrawl.org/{release}-index"

DEFAULT_YEARS = "last1"
DEFAULT_MAX_PER_YEAR = 1
DEFAULT_TIMEOUT = 120.0
DEFAULT_RATE_LIMIT_DELAY = 1.0
DEFAULT_MAX_RESULTS_PER_RELEASE = 100_000

# Very loose hostname validator — rejects obvious junk while keeping edge cases
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")


def _is_valid_hostname(h: str) -> bool:
    return bool(h) and "." in h and bool(_HOSTNAME_RE.match(h)) and len(h) <= 253


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CCrawlLiveResult:
    """Result from Mode 1 (subdomain enumeration) for a single root domain."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    releases_queried: List[str] = field(default_factory=list)
    elapsed_time: float = 0.0
    source: str = "commoncrawl-live"
    error: Optional[str] = None


@dataclass
class CCrawlKeywordResult:
    """
    Result from Mode 2 (keyword / brand discovery).

    ``hostnames`` contains every unique hostname found across all CC releases
    for all queried keywords.  Callers should classify them further:
      - hostname ends with a known root domain  →  treat as subdomain
      - hostname IS a known root domain         →  already known, skip
      - hostname contains the keyword but is under an unknown root  →  new asset
    """
    keywords: List[str]
    hostnames: List[str] = field(default_factory=list)
    releases_queried: List[str] = field(default_factory=list)
    elapsed_time: float = 0.0
    source: str = "commoncrawl-keyword"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Core service
# ---------------------------------------------------------------------------

class CommonCrawlLiveService:
    """
    Live CommonCrawl CDX API service for subdomain + brand discovery.

    Instantiate once, then call:
      • ``search_domain(domain)``            — Mode 1, single domain
      • ``search_domains(domains)``          — Mode 1, multiple domains
      • ``search_keywords(keywords, known)`` — Mode 2, brand keyword sweep

    Year config:
      "last1"      — last 1 calendar year (default, fastest)
      "last2"      — last 2 calendar years
      "lastN"      — last N calendar years
      "all"        — every available release (slowest)
      "2025"       — a single specific year
      "2025,2024"  — comma-separated specific years
    """

    def __init__(
        self,
        years: str = DEFAULT_YEARS,
        max_per_year: int = DEFAULT_MAX_PER_YEAR,
        timeout: float = DEFAULT_TIMEOUT,
        rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY,
        max_results_per_release: int = DEFAULT_MAX_RESULTS_PER_RELEASE,
    ):
        self.years = years
        self.max_per_year = max_per_year
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.max_results_per_release = max_results_per_release

    # ------------------------------------------------------------------
    # Collection / release helpers
    # ------------------------------------------------------------------

    async def _get_collections(self, client: httpx.AsyncClient) -> List[dict]:
        """Fetch available crawl releases from collinfo.json."""
        try:
            response = await client.get(CCRAWL_COLLECTIONS_URL, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.error(f"Failed to fetch CC collections: {exc}")
            return []

    def _filter_releases(self, collections: List[dict]) -> List[str]:
        """
        Select CC release IDs matching ``self.years`` / ``self.max_per_year``.

        Release IDs are like "CC-MAIN-2025-13" — third segment is the year.
        collinfo.json is newest-first within each year.
        """
        current_year = datetime.now(timezone.utc).year
        target_years: Optional[Set[int]]

        if self.years == "all":
            target_years = None
        elif self.years.startswith("last"):
            n = int(self.years[4:])
            target_years = {current_year - i for i in range(n)}
        else:
            target_years = {
                int(y.strip()) for y in self.years.split(",") if y.strip().isdigit()
            }

        by_year: Dict[int, List[str]] = {}
        for col in collections:
            col_id = col.get("id", "")
            parts = col_id.split("-")
            if len(parts) >= 3 and parts[2].isdigit():
                year = int(parts[2])
                if target_years is None or year in target_years:
                    by_year.setdefault(year, []).append(col_id)

        selected: List[str] = []
        for year in sorted(by_year.keys(), reverse=True):
            selected.extend(by_year[year][: self.max_per_year])
        return selected

    # ------------------------------------------------------------------
    # CDX query helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_hostname(raw_url: str) -> Optional[str]:
        """Parse and normalise the hostname from a raw URL string."""
        try:
            parsed = urlparse(raw_url)
            hostname = parsed.netloc.lower()
            if ":" in hostname:
                hostname = hostname.rsplit(":", 1)[0]
            return hostname if hostname else None
        except Exception:
            return None

    async def _query_release_subdomain(
        self,
        client: httpx.AsyncClient,
        release: str,
        domain: str,
    ) -> Set[str]:
        """Mode 1: ``*.domain`` → subdomains of a known root domain."""
        found: Set[str] = set()
        suffix = f".{domain}"
        try:
            response = await client.get(
                CCRAWL_INDEX_URL.format(release=release),
                params={
                    "url": f"*.{domain}",
                    "output": "json",
                    "fl": "url",
                    "limit": self.max_results_per_release,
                },
                timeout=self.timeout,
            )
            if response.status_code == 404:
                return found
            response.raise_for_status()

            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    hostname = self._extract_hostname(record.get("url", ""))
                    if hostname and hostname.endswith(suffix) and hostname != domain:
                        found.add(hostname)
                except Exception:
                    continue

            logger.info(f"CC {release} subdomain: {len(found)} hits for {domain}")
        except httpx.TimeoutException:
            logger.warning(f"CC {release} timed out for {domain}")
        except Exception as exc:
            logger.warning(f"CC {release} subdomain query error ({domain}): {exc}")
        return found

    @staticmethod
    def _keyword_patterns(keyword: str) -> List[tuple[str, str]]:
        """
        Return all CDX URL patterns to query for a keyword, paired with the
        hostname filter string to apply when parsing results.

        Three patterns are generated per keyword:

          1. ``*keyword*``   — any URL where the HOSTNAME contains the keyword
                               (partner portals, hyphenated brand names, …)
          2. ``keyword.*``   — URLs where the hostname STARTS WITH the keyword
                               (finds rockwellautomation.net, .de, .io, …)
          3. ``*.keyword.*`` — subdomains of any TLD domain starting with
                               keyword  (e.g. mail.rockwellautomation.de)

        Returns a list of (cdx_pattern, hostname_must_contain) tuples.
        The second element is used to filter CDX results to hostnames that
        genuinely match the brand, not just pages that mention it in a path.
        """
        kw = keyword.lower().replace(" ", "")
        return [
            (f"*{kw}*",    kw),       # contains anywhere in hostname
            (f"{kw}.*",    kw),       # starts with keyword (any TLD)
            (f"*.{kw}.*",  kw),       # subdomains of keyword.TLD
        ]

    async def _query_release_keyword(
        self,
        client: httpx.AsyncClient,
        release: str,
        keyword: str,
    ) -> Set[str]:
        """
        Mode 2: run all CDX patterns for ``keyword`` and collect unique hostnames.

        Patterns used per keyword (see ``_keyword_patterns``):
          • ``*rockwellautomation*``  — hostname contains keyword
          • ``rockwellautomation.*``  — hostname starts with keyword (any TLD)
          • ``*.rockwellautomation.*``— subdomains of keyword.TLD domains
        """
        found: Set[str] = set()
        patterns = self._keyword_patterns(keyword)

        for cdx_pattern, must_contain in patterns:
            try:
                response = await client.get(
                    CCRAWL_INDEX_URL.format(release=release),
                    params={
                        "url": cdx_pattern,
                        "output": "json",
                        "fl": "url",
                        "limit": self.max_results_per_release,
                    },
                    timeout=self.timeout,
                )
                if response.status_code == 404:
                    continue
                response.raise_for_status()

                for line in response.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        hostname = self._extract_hostname(record.get("url", ""))
                        # Only keep hostnames that actually contain the keyword —
                        # discards URLs where the brand only appears in the path.
                        if hostname and must_contain in hostname and _is_valid_hostname(hostname):
                            found.add(hostname)
                    except Exception:
                        continue

                logger.debug(
                    f"CC {release} pattern '{cdx_pattern}': {len(found)} cumulative hits"
                )

                # Brief pause between patterns on the same release
                if self.rate_limit_delay > 0:
                    await asyncio.sleep(self.rate_limit_delay * 0.5)

            except httpx.TimeoutException:
                logger.warning(f"CC {release} timed out for pattern '{cdx_pattern}'")
            except Exception as exc:
                logger.warning(f"CC {release} pattern '{cdx_pattern}' error: {exc}")

        logger.info(f"CC {release} keyword '{keyword}': {len(found)} unique hostname hits")
        return found

    # ------------------------------------------------------------------
    # Public interface — Mode 1 (subdomain enumeration)
    # ------------------------------------------------------------------

    async def search_domain(self, domain: str) -> CCrawlLiveResult:
        """
        Enumerate subdomains of ``domain`` using the live CommonCrawl CDX API.

        Args:
            domain: Root domain (e.g. "rockwellautomation.com")

        Returns:
            CCrawlLiveResult with deduplicated subdomains.
        """
        result = CCrawlLiveResult(domain=domain)
        start = datetime.now(timezone.utc)
        all_subdomains: Set[str] = set()

        async with httpx.AsyncClient(
            headers={"User-Agent": "Judah-ASM/1.0 (+https://judahsecurity.com)"},
            follow_redirects=True,
        ) as client:
            collections = await self._get_collections(client)
            if not collections:
                result.error = "Failed to fetch CommonCrawl collection index"
                result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            releases = self._filter_releases(collections)
            if not releases:
                result.error = f"No CC releases matched years={self.years!r}"
                result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            logger.info(
                f"CC subdomain enum: {len(releases)} release(s) for {domain}: "
                + ", ".join(releases)
            )
            result.releases_queried = releases

            for release in releases:
                subs = await self._query_release_subdomain(client, release, domain)
                all_subdomains.update(subs)
                if self.rate_limit_delay > 0 and release != releases[-1]:
                    await asyncio.sleep(self.rate_limit_delay)

        result.subdomains = sorted(all_subdomains)
        result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
        logger.info(
            f"CC subdomain enum complete: {len(result.subdomains)} subdomains "
            f"for {domain} in {result.elapsed_time:.1f}s"
        )
        return result

    async def search_domains(self, domains: List[str]) -> Dict[str, CCrawlLiveResult]:
        """Run ``search_domain`` for multiple root domains sequentially."""
        results: Dict[str, CCrawlLiveResult] = {}
        for domain in domains:
            results[domain] = await self.search_domain(domain)
        return results

    # ------------------------------------------------------------------
    # Public interface — Mode 2 (brand / keyword discovery)
    # ------------------------------------------------------------------

    async def search_keywords(
        self,
        keywords: List[str],
        known_root_domains: Optional[List[str]] = None,
    ) -> CCrawlKeywordResult:
        """
        Discover unknown hostnames by searching the CC index for brand/product
        name strings.  Returns every hostname whose label contains at least one
        keyword — regardless of whether that domain is already known.

        Callers use ``known_root_domains`` to classify results:
          • subdomain of a known root  →  pure subdomain discovery win
          • new root domain entirely   →  flag for analyst review (shadow-IT,
                                          partner portal, acquired brand, etc.)

        Args:
            keywords:           Brand / product terms (e.g. ["rockwellautomation",
                                "factorytalk", "allen-bradley"]).  Spaces are
                                stripped before querying.
            known_root_domains: Optional list of already-known root domains used
                                to classify results in ``result.hostnames``.
                                Does NOT filter the output — all hits are returned.

        Returns:
            CCrawlKeywordResult with deduplicated hostnames.
        """
        result = CCrawlKeywordResult(keywords=keywords)
        if not keywords:
            result.error = "No keywords provided"
            return result

        start = datetime.now(timezone.utc)
        all_hostnames: Set[str] = set()

        async with httpx.AsyncClient(
            headers={"User-Agent": "Judah-ASM/1.0 (+https://judahsecurity.com)"},
            follow_redirects=True,
        ) as client:
            collections = await self._get_collections(client)
            if not collections:
                result.error = "Failed to fetch CommonCrawl collection index"
                result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            releases = self._filter_releases(collections)
            if not releases:
                result.error = f"No CC releases matched years={self.years!r}"
                result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            logger.info(
                f"CC keyword sweep: {len(keywords)} keyword(s) × {len(releases)} release(s): "
                + ", ".join(keywords)
            )
            result.releases_queried = releases

            for release in releases:
                for keyword in keywords:
                    hits = await self._query_release_keyword(client, release, keyword)
                    all_hostnames.update(hits)
                    if self.rate_limit_delay > 0:
                        await asyncio.sleep(self.rate_limit_delay)

        result.hostnames = sorted(all_hostnames)
        result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
        logger.info(
            f"CC keyword sweep complete: {len(result.hostnames)} unique hostnames "
            f"across {len(keywords)} keyword(s) in {result.elapsed_time:.1f}s"
        )
        return result
