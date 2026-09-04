"""
CVE intel — live vulnerability enrichment for the engagement brain.

Borrowed from PentAGI, which queries the web for the latest CVE data
mid-engagement and feeds it into memory. Here, when recon fingerprints a
technology and version, the agent can look up known CVEs from the NVD 2.0 API
and stash the high-signal ones in the engagement brain — so hunters start from
"this Grafana build has CVE-2024-… (CVSS 9.8), test that path" instead of
re-deriving it, and the knowledge persists across runs.

Design for an ephemeral-network agent:
  * The HTTP fetch is **injectable** (``fetch=`` parameter) so the parsing and
    ranking logic is deterministic and unit-tested against a fixture.
  * Every network failure degrades gracefully to ``available=False`` with a
    reason — a blocked egress or an NVD rate-limit never crashes a tool call.
  * No API key required; an ``NVD_API_KEY`` env var is used if present to lift
    the rate limit.
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cvss": self.cvss,
            "severity": self.severity,
            "summary": self.summary,
            "url": self.url,
            "published": self.published,
        }


@dataclass
class CVEResult:
    product: str
    version: str
    available: bool
    cves: List[CVE] = field(default_factory=list)
    total: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "product": self.product,
            "version": self.version,
            "available": self.available,
            "total": self.total,
            "returned": len(self.cves),
            "cves": [c.to_dict() for c in self.cves],
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Parsing (pure — unit-tested against an NVD fixture)
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


def parse_nvd_response(data: Dict[str, Any]) -> tuple:
    """Parse an NVD 2.0 response into (List[CVE], total_results)."""
    total = int(data.get("totalResults", 0) or 0)
    out: List[CVE] = []
    for wrapper in data.get("vulnerabilities", []) or []:
        cve = wrapper.get("cve") or {}
        cid = cve.get("id") or ""
        if not cid:
            continue
        descs = cve.get("descriptions") or []
        summary = next(
            (d.get("value", "") for d in descs if d.get("lang") == "en"),
            descs[0].get("value", "") if descs else "",
        )
        score, severity = _best_cvss(cve.get("metrics") or {})
        refs = cve.get("references") or []
        url = refs[0].get("url", "") if refs else ""
        out.append(CVE(
            id=cid,
            cvss=score,
            severity=severity,
            summary=(summary or "").strip()[:400],
            url=url,
            published=(cve.get("published") or "")[:10],
        ))
    return out, total


# ---------------------------------------------------------------------------
# Default fetcher (httpx if present, else urllib) — replaceable in tests
# ---------------------------------------------------------------------------


def _default_fetch(url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    headers = {"User-Agent": "aegis-vanguard/cve-intel"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        import httpx  # optional; falls back to urllib
        resp = httpx.get(url, params=params, headers=headers, timeout=20.0)
        resp.raise_for_status()
        return resp.json()
    except ImportError:
        pass
    query = urllib.parse.urlencode(params)
    req = urllib.request.Request(f"{url}?{query}", headers=headers)
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (fixed host)
        return json.load(r)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def lookup(
    product: str,
    version: str = "",
    limit: int = 8,
    fetch: Optional[Fetcher] = None,
) -> CVEResult:
    """Look up CVEs for a product (+ optional version), ranked by CVSS desc.

    ``fetch`` is injectable for testing; defaults to NVD over the network.
    Any failure returns ``available=False`` with a reason rather than raising.
    """
    product = (product or "").strip()
    version = (version or "").strip()
    if not product:
        return CVEResult(product, version, available=False,
                         error="no product given")

    fetcher = fetch or _default_fetch
    keyword = f"{product} {version}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max(limit * 3, 20),  # over-fetch, then rank + trim
    }
    try:
        data = fetcher(_NVD_URL, params)
    except Exception as exc:  # network blocked, rate-limited, timeout, etc.
        logger.info("cve_intel: lookup for %r unavailable — %s", keyword, exc)
        return CVEResult(product, version, available=False,
                         error=f"{type(exc).__name__}: {str(exc)[:160]}")

    try:
        cves, total = parse_nvd_response(data)
    except Exception as exc:
        return CVEResult(product, version, available=False,
                         error=f"parse error: {exc}")

    # If a version was given, prefer CVEs that mention it, but never drop
    # everything (keyword search is fuzzy).
    if version:
        with_ver = [c for c in cves if version in c.summary]
        if with_ver:
            cves = with_ver

    cves.sort(key=lambda c: (c.cvss if c.cvss is not None else -1.0), reverse=True)
    return CVEResult(product, version, available=True,
                     cves=cves[:limit], total=total)


def enrich_brain(result: CVEResult, brain: Any, top: int = 5) -> int:
    """Stash the highest-CVSS CVEs from a lookup into the engagement brain as
    notes. Returns how many were recorded. No-op if the brain is None."""
    if brain is None or not result.available or not result.cves:
        return 0
    recorded = 0
    for c in result.cves[:top]:
        score = f"CVSS {c.cvss}" if c.cvss is not None else "CVSS n/a"
        brain.add_note(
            f"CVE {c.id} ({score}, {c.severity or 'unknown'}) may affect "
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
    "lookup",
    "enrich_brain",
    "lookup_json",
]
