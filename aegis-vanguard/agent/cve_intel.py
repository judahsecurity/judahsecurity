"""
CVE intel — live vulnerability enrichment for the engagement brain.

Borrowed from PentAGI, which queries the web for the latest CVE data
mid-engagement and feeds it into memory. When recon fingerprints a technology
and version, the agent looks up known CVEs and stashes the high-signal ones in
the engagement brain — so hunters start from "this build has CVE-… (known
exploited), test that path" instead of re-deriving it, and it persists across
runs.

Sources (provider abstraction):
  * **VulnCheck (preferred)** — used when ``VULNCHECK_API_KEY`` is set. Pulls
    reliable NVD data from VulnCheck's **NVD++** mirror (NVD.gov itself is
    rate-limited and has had long enrichment backlogs) *and* the **VulnCheck
    KEV** catalog of known-exploited CVEs. This lets us rank by what actually
    matters to a pentester — **exploitability first** (known-exploited, then
    CVSS) — not raw score alone.
  * **NVD (fallback)** — the zero-config NVD 2.0 API, used when no VulnCheck
    token is present or a VulnCheck call fails.

Design for an ephemeral-network agent:
  * The HTTP fetch is **injectable** (``fetch=``) so parsing/ranking is
    deterministic and unit-tested against fixtures.
  * Every network failure degrades gracefully to ``available=False`` with a
    reason — a blocked egress or a rate-limit never crashes a tool call.

Note: the VulnCheck v3 index search parameter is centralized in
``_VC_SEARCH_PARAM``; confirm it against your account's current API docs if a
live query returns nothing.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("agent.cve_intel")

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_VC_BASE = "https://api.vulncheck.com/v3/index"
_VC_NVD_INDEX = f"{_VC_BASE}/nist-nvd2"      # NVD++ mirror (NVD 2.0 schema)
_VC_KEV_INDEX = f"{_VC_BASE}/vulncheck-kev"  # known-exploited catalog
_VC_SEARCH_PARAM = "keyword"                 # tracks VulnCheck v3 index search

# Injectable fetch: (url, params) -> parsed JSON dict. Raises on failure.
Fetcher = Callable[[str, Dict[str, Any]], Dict[str, Any]]


@dataclass
class CVE:
    id: str
    cvss: Optional[float]
    severity: str
    summary: str
    url: str
    published: str = ""
    known_exploited: bool = False   # in a KEV catalog (VulnCheck / CISA)
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cvss": self.cvss,
            "severity": self.severity,
            "summary": self.summary,
            "url": self.url,
            "published": self.published,
            "known_exploited": self.known_exploited,
            "source": self.source,
        }


@dataclass
class CVEResult:
    product: str
    version: str
    available: bool
    cves: List[CVE] = field(default_factory=list)
    total: int = 0
    error: str = ""
    provider: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "product": self.product,
            "version": self.version,
            "available": self.available,
            "provider": self.provider,
            "total": self.total,
            "returned": len(self.cves),
            "known_exploited": sum(1 for c in self.cves if c.known_exploited),
            "cves": [c.to_dict() for c in self.cves],
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Parsing (pure — unit-tested against fixtures)
# ---------------------------------------------------------------------------


def _best_cvss(metrics: Dict[str, Any]) -> tuple:
    """Return (score, severity) preferring CVSS v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), (data.get("baseSeverity") or "").lower()
    v2 = metrics.get("cvssMetricV2") or []
    if v2:
        data = v2[0].get("cvssData", {})
        return data.get("baseScore"), (v2[0].get("baseSeverity") or "").lower()
    return None, ""


def _cve_from_obj(cve: Dict[str, Any], source: str) -> Optional[CVE]:
    """Build a CVE from an NVD-2.0-shaped ``cve`` object (NVD or NVD++)."""
    cid = cve.get("id") or ""
    if not cid:
        return None
    descs = cve.get("descriptions") or []
    summary = next(
        (d.get("value", "") for d in descs if d.get("lang") == "en"),
        descs[0].get("value", "") if descs else "",
    )
    score, severity = _best_cvss(cve.get("metrics") or {})
    refs = cve.get("references") or []
    return CVE(
        id=cid,
        cvss=score,
        severity=severity,
        summary=(summary or "").strip()[:400],
        url=refs[0].get("url", "") if refs else "",
        published=(cve.get("published") or "")[:10],
        source=source,
    )


def parse_nvd_response(data: Dict[str, Any]) -> tuple:
    """Parse an NVD 2.0 response into (List[CVE], total_results)."""
    total = int(data.get("totalResults", 0) or 0)
    out: List[CVE] = []
    for wrapper in data.get("vulnerabilities", []) or []:
        cve = _cve_from_obj((wrapper or {}).get("cve") or {}, source="nvd")
        if cve:
            out.append(cve)
    return out, total


def parse_vulncheck_index(data: Dict[str, Any]) -> tuple:
    """Parse a VulnCheck NVD++ index response into (List[CVE], total).

    VulnCheck index responses carry the documents under ``data`` (each an
    NVD-2.0 ``cve`` object, sometimes wrapped as ``{"cve": {...}}``) and totals
    under ``_meta.total_documents``."""
    meta = data.get("_meta") or {}
    total = int(meta.get("total_documents", 0) or 0)
    out: List[CVE] = []
    for item in data.get("data", []) or []:
        obj = item.get("cve") if isinstance(item, dict) and "cve" in item else item
        cve = _cve_from_obj(obj or {}, source="vulncheck-nvd++")
        if cve:
            out.append(cve)
    return out, (total or len(out))


def parse_vulncheck_kev(data: Dict[str, Any]) -> set:
    """Extract the set of known-exploited CVE IDs from a VulnCheck KEV response.

    KEV entries carry a ``cve`` field that is a list of IDs (occasionally a
    single string)."""
    ids: set = set()
    for item in data.get("data", []) or []:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if isinstance(cve, str):
            ids.add(cve)
        elif isinstance(cve, list):
            ids.update(str(c) for c in cve if c)
    return ids


# ---------------------------------------------------------------------------
# Default fetchers (replaceable in tests)
# ---------------------------------------------------------------------------


def _http_get_json(url: str, params: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    try:
        import httpx  # optional; falls back to urllib
        resp = httpx.get(url, params=params, headers=headers, timeout=20.0)
        resp.raise_for_status()
        return resp.json()
    except ImportError:
        pass
    query = urllib.parse.urlencode(params)
    req = urllib.request.Request(f"{url}?{query}", headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (fixed hosts)
        return json.load(r)


def _nvd_fetch(url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    headers = {"User-Agent": "aegis-vanguard/cve-intel"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return _http_get_json(url, params, headers)


def _vulncheck_fetch(url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    token = os.environ.get("VULNCHECK_API_KEY", "")
    headers = {
        "User-Agent": "aegis-vanguard/cve-intel",
        "Authorization": f"Bearer {token}",
    }
    return _http_get_json(url, params, headers)


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


def _rank(cves: List[CVE]) -> List[CVE]:
    """Exploitability-first: known-exploited before high CVSS."""
    return sorted(
        cves,
        key=lambda c: (c.known_exploited, c.cvss if c.cvss is not None else -1.0),
        reverse=True,
    )


def _apply_version(cves: List[CVE], version: str) -> List[CVE]:
    if not version:
        return cves
    with_ver = [c for c in cves if version in c.summary]
    return with_ver or cves  # keyword search is fuzzy; never drop everything


def _lookup_nvd(product: str, version: str, limit: int, fetch: Fetcher) -> CVEResult:
    keyword = f"{product} {version}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": max(limit * 3, 20)}
    data = fetch(_NVD_URL, params)
    cves, total = parse_nvd_response(data)
    cves = _rank(_apply_version(cves, version))
    return CVEResult(product, version, available=True, cves=cves[:limit],
                     total=total, provider="nvd")


def _lookup_vulncheck(product: str, version: str, limit: int, fetch: Fetcher) -> CVEResult:
    keyword = f"{product} {version}".strip()
    # 1. Reliable NVD data from the NVD++ mirror.
    data = fetch(_VC_NVD_INDEX, {_VC_SEARCH_PARAM: keyword, "limit": max(limit * 3, 20)})
    cves, total = parse_vulncheck_index(data)
    # 2. Flag known-exploited via the VulnCheck KEV catalog (best effort).
    try:
        kev_data = fetch(_VC_KEV_INDEX, {_VC_SEARCH_PARAM: product})
        kev = parse_vulncheck_kev(kev_data)
    except Exception as exc:  # KEV is enrichment, not required
        logger.info("cve_intel: VulnCheck KEV enrichment skipped — %s", exc)
        kev = set()
    for c in cves:
        if c.id in kev:
            c.known_exploited = True
    cves = _rank(_apply_version(cves, version))
    return CVEResult(product, version, available=True, cves=cves[:limit],
                     total=total, provider="vulncheck")


def _select_provider(provider: Optional[str]) -> str:
    if provider:
        return provider
    if os.environ.get("VULNCHECK_API_KEY"):
        return "vulncheck"
    return "nvd"


# ---------------------------------------------------------------------------
# Public lookup
# ---------------------------------------------------------------------------


def lookup(
    product: str,
    version: str = "",
    limit: int = 8,
    fetch: Optional[Fetcher] = None,
    provider: Optional[str] = None,
) -> CVEResult:
    """Look up CVEs for a product (+ optional version), exploitability-ranked.

    Provider defaults to VulnCheck when ``VULNCHECK_API_KEY`` is set, else NVD.
    A VulnCheck failure falls back to NVD. ``fetch`` is injectable for testing.
    Any failure returns ``available=False`` with a reason rather than raising.
    """
    product = (product or "").strip()
    version = (version or "").strip()
    if not product:
        return CVEResult(product, version, available=False, error="no product given")

    chosen = _select_provider(provider)

    if chosen == "vulncheck":
        vc_fetch = fetch or _vulncheck_fetch
        try:
            return _lookup_vulncheck(product, version, limit, vc_fetch)
        except Exception as exc:
            logger.info("cve_intel: VulnCheck lookup failed (%s) — falling back to NVD",
                        exc)
            # fall through to NVD unless the caller pinned a fetch mock
            if fetch is not None:
                return CVEResult(product, version, available=False,
                                 error=f"vulncheck: {type(exc).__name__}: {str(exc)[:140]}",
                                 provider="vulncheck")
            chosen = "nvd"

    nvd_fetch = fetch or _nvd_fetch
    try:
        return _lookup_nvd(product, version, limit, nvd_fetch)
    except Exception as exc:
        logger.info("cve_intel: NVD lookup for %r unavailable — %s", product, exc)
        return CVEResult(product, version, available=False,
                         error=f"nvd: {type(exc).__name__}: {str(exc)[:140]}",
                         provider="nvd")


def enrich_brain(result: CVEResult, brain: Any, top: int = 5) -> int:
    """Stash the highest-ranked CVEs from a lookup into the engagement brain as
    notes. Returns how many were recorded. No-op if the brain is None."""
    if brain is None or not result.available or not result.cves:
        return 0
    recorded = 0
    for c in result.cves[:top]:
        score = f"CVSS {c.cvss}" if c.cvss is not None else "CVSS n/a"
        kev = "KNOWN-EXPLOITED, " if c.known_exploited else ""
        brain.add_note(
            f"CVE {c.id} ({kev}{score}, {c.severity or 'unknown'}) may affect "
            f"{result.product} {result.version}: {c.summary[:200]}"
        )
        recorded += 1
    try:
        brain.save()
    except Exception:  # pragma: no cover - best effort
        pass
    return recorded


def lookup_json(product: str, version: str = "", limit: int = 8) -> str:
    """String out helper for the @security_tool wrapper (also enriches brain)."""
    result = lookup(product, version, limit=limit)
    try:
        from agent.brain import get_brain
        enrich_brain(result, get_brain())
    except Exception:  # pragma: no cover - brain optional
        pass
    return json.dumps(result.to_dict(), default=str)


__all__ = [
    "CVE",
    "CVEResult",
    "parse_nvd_response",
    "parse_vulncheck_index",
    "parse_vulncheck_kev",
    "lookup",
    "enrich_brain",
    "lookup_json",
]
