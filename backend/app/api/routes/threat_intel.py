"""
Threat Intelligence — Exploitation Intelligence Feed

Aggregates CVEs from all major public exploitation intelligence sources:
  - CISA KEV              (free, no key)
  - VulnCheck KEV         (requires VULNCHECK_API_TOKEN)
  - ENISA EU KEV          (free, no key)
  - EUVD                  (EU Vulnerability Database, free, no key)
  - Shadowserver          (honeypot exploited via CIRCL, free)
  - KEVIntel              (attestations via CIRCL KEV catalog, free)

Enriched with:
  - Detection coverage via ProjectDiscovery PDCP (optional key)
  - Active campaign signals via AlienVault OTX (free)
  - NVD / OSV / GHSA first-party CVE metadata (on CVE detail)
  - Public exploit indexes: PoC-in-GitHub, trickest/cve, GitHub repos, Exploit-DB, CXSecurity
  - Oracle OPES analysis from local DB
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user
from app.core.config import settings
from app.models.api_config import ExternalService, resolve_api_key
from app.services.vuln_intel_enrichment import enrich_cve_catalog
from app.services.vuln_intel_feeds import (
    fetch_kevintel_attestations,
    fetch_shadowserver_from_circl_kev,
    fetch_vulncheck_kev,
    read_json_cache,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])
logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 8.0
_ENRICH_CONCURRENCY = 8
# Hard budget so the Vulnerability Intel list cannot hang behind CIRCL/VulnCheck.
_FEED_TIMEOUT_S = 10.0
_CVE_ID_RE = re.compile(r"(CVE-\d{4}-\d+)", re.I)


def _get_vulncheck_token(db: Session, org_id: int | None = None) -> str:
    return (
        resolve_api_key(db, ExternalService.VULNCHECK, org_id)
        or getattr(settings, "VULNCHECK_API_TOKEN", None)
        or ""
    )


def _get_pdcp_key(db: Session, org_id: int | None = None) -> str:
    return resolve_api_key(db, ExternalService.PDCP, org_id) or ""


def _canonical_cve_id(value: Any) -> str:
    match = _CVE_ID_RE.search(str(value or ""))
    return match.group(1).upper() if match else ""


def _parse_intel_date(value: Any) -> datetime | None:
    """Parse CISA YYYY-MM-DD, ENISA slashes, and RFC3339Nano (VulnCheck) dates."""
    raw = str(value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    if "." in raw:
        head, rest = raw.split(".", 1)
        digits = []
        tz = ""
        for idx, char in enumerate(rest):
            if char.isdigit():
                digits.append(char)
            else:
                tz = rest[idx:]
                break
        raw = f"{head}.{''.join(digits + ['0'] * 6)[:6]}{tz}"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        parsed = _parse_enisa_date(str(value or "").strip())
        return parsed
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _entry_in_window(entry: dict, cutoff: datetime, *, days: int) -> bool:
    """Keep a merged CVE if any source listed it inside the window."""
    if days <= 0:
        return True
    raw_dates = list(entry.get("source_dates") or [])
    if entry.get("date_added") and entry.get("date_added") not in raw_dates:
        raw_dates.append(entry.get("date_added"))
    parsed = [dt for dt in (_parse_intel_date(d) for d in raw_dates) if dt is not None]
    if not parsed:
        return False
    return any(dt >= cutoff for dt in parsed)


async def _feed_or_empty(name: str, coro, *, timeout: float = _FEED_TIMEOUT_S) -> list[dict]:
    """Run one feed fetch; return [] on timeout or error so other sources still render."""
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
        return result if isinstance(result, list) else []
    except asyncio.TimeoutError:
        logger.warning("threat-intel %s feed timed out after %.0fs", name, timeout)
        return []
    except Exception as exc:
        logger.warning("threat-intel %s feed failed: %s", name, exc)
        return []


# ── VulnCheck KEV ─────────────────────────────────────────────────────────────

async def _fetch_vulncheck_kev(client: httpx.AsyncClient, days: int, token: str) -> list[dict]:
    """Serve VulnCheck KEV from disk cache. Live bootstrap is refresh_vuln_intel."""
    # List path is cache-only. Live VulnCheck (backup / incremental) is the
    # refresh_vuln_intel job — a hanging index call must not empty this page.
    mapped = await asyncio.to_thread(
        fetch_vulncheck_kev,
        token or "",
        cache_only=True,
        request_timeout=20,
        page_limit=100,
    )

    entries: list[dict] = []
    for cve, entry in mapped.items():
        cve_id = _canonical_cve_id(cve) or _canonical_cve_id(entry.get("cve_id"))
        if not cve_id:
            continue
        date_str = entry.get("date_added") or ""
        extra_dates = [entry.get("cisa_date_added"), entry.get("_timestamp")]
        source_dates = [d for d in [date_str, *extra_dates] if d]
        entries.append({
            "cve_id": cve_id,
            "all_cves": entry.get("all_cves") or [cve_id],
            "date_added": date_str,
            "source_dates": source_dates,
            "vendor_project": entry.get("vendor_project", ""),
            "product": entry.get("product", ""),
            "vulnerability_name": entry.get("vulnerability_name", ""),
            "short_description": entry.get("short_description", ""),
            "known_ransomware_use": entry.get("known_ransomware_use", "Unknown"),
            "kev_sources": ["vulncheck_kev"],
            "cvss_score": entry.get("cvss_score"),
        })
    return entries


# ── CISA KEV ──────────────────────────────────────────────────────────────────

async def _fetch_cisa_kev(client: httpx.AsyncClient, cutoff: datetime) -> list[dict]:
    """Serve CISA KEV from disk cache. Live pull is refresh_vuln_intel (cisa.gov often hangs from AWS)."""
    cached = await asyncio.to_thread(read_json_cache, "cisa_kev.json")
    vulns = list((cached or {}).get("vulnerabilities") or [])
    if not vulns:
        return []

    entries = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        date_str = v.get("dateAdded") or ""
        cve_id = _canonical_cve_id(v.get("cveID"))
        if not cve_id:
            continue
        entries.append({
            "cve_id": cve_id,
            "all_cves": [cve_id],
            "date_added": date_str,
            "source_dates": [date_str] if date_str else [],
            "vendor_project": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "short_description": v.get("shortDescription", ""),
            "known_ransomware_use": v.get("knownRansomwareUse", "Unknown"),
            "kev_sources": ["cisa_kev"],
        })
    return entries

# ── ENISA EU KEV (CNW EUKEV) ──────────────────────────────────────────────────

def _parse_enisa_date(date_str: str) -> datetime | None:
    """Parse ENISA date strings like 2026/07/31 or ISO timestamps."""
    raw = (date_str or "").strip()
    if not raw:
        return None
    for fmt in ("%Y/%m/%d", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw.replace("Z", "+0000"), fmt) if "%z" in fmt else datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


async def _fetch_enisa_kev(client: httpx.AsyncClient, cutoff: datetime) -> list[dict]:
    """Serve ENISA EUKEV from disk cache. Live pull is refresh_vuln_intel."""
    cached = await asyncio.to_thread(read_json_cache, "enisa_eukev.json")
    rows = list((cached or {}).get("rows") or [])
    if not rows:
        return []
    entries = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve_id = _canonical_cve_id(
            row.get("cveID") or row.get("CVE ID") or row.get("cve_id") or row.get("CVE")
        )
        if not cve_id:
            continue
        date_str = (
            row.get("dateReported")
            or row.get("dateAdded")
            or row.get("Date Added")
            or row.get("date_added")
            or ""
        )
        date_str = str(date_str).strip()
        ransomware = "Unknown"
        exploitation = (row.get("exploitationType") or "").strip().lower()
        if "ransomware" in exploitation:
            ransomware = "Known"
        entries.append({
            "cve_id": cve_id,
            "all_cves": [cve_id],
            "date_added": date_str,
            "source_dates": [date_str] if date_str else [],
            "vendor_project": row.get("vendorProject") or row.get("Vendor/Project") or "",
            "product": row.get("product") or row.get("Product") or "",
            "vulnerability_name": (
                row.get("vulnerabilityName")
                or row.get("Vulnerability Name")
                or (row.get("shortDescription") or "")[:120]
            ),
            "short_description": row.get("shortDescription") or row.get("Short Description") or "",
            "known_ransomware_use": ransomware,
            "kev_sources": ["enisa_kev"],
            "euvd_id": row.get("euvdID") or "",
            "exploitation_type": row.get("exploitationType") or "",
        })
    return entries

# ── EUVD (EU Vulnerability Database) ──────────────────────────────────────────

def _euvd_cve_ids(item: dict) -> list[str]:
    """Extract CVE IDs from an EUVD record (aliases / nested fields)."""
    found: list[str] = []
    blobs: list[Any] = []
    for key in ("aliases", "assigner", "cve", "cves"):
        blobs.append(item.get(key))
    for key in ("id", "euvdId", "cveId", "cve_id"):
        blobs.append(item.get(key))
    for blob in blobs:
        if isinstance(blob, list):
            for item_val in blob:
                cve = _canonical_cve_id(item_val)
                if cve:
                    found.append(cve)
        else:
            cve = _canonical_cve_id(blob)
            if cve:
                found.append(cve)
    out: list[str] = []
    seen = set()
    for cve in found:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


async def _fetch_euvd(
    client: httpx.AsyncClient,
    cutoff: datetime,
    *,
    paginated: bool = False,
) -> list[dict]:
    """
    Fetch ENISA EUVD exploited-in-the-wild entries (free, no auth).

    Uses euvdservices.enisa.europa.eu (the old euvd.enisa.europa.eu/api/v1/*
    paths now serve the SPA HTML shell).

    paginated=False (list UI): one convenience request only, so this cannot
    stall the emerging feed behind 25 search pages.
    """
    headers = {"User-Agent": "aegis-oracle/1.0", "Accept": "application/json"}
    entries: list[dict] = []
    seen: set[str] = set()

    async def _ingest_items(items: list) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            cves = _euvd_cve_ids(item)
            if not cves:
                continue
            date_str = (
                item.get("datePublished")
                or item.get("dateUpdated")
                or item.get("dateAdded")
                or item.get("published")
                or item.get("exploitedSince")
                or ""
            )
            date_str = str(date_str).strip()
            vendors = item.get("enisaIdVendor") or item.get("vendor") or []
            products = item.get("enisaIdProduct") or item.get("product") or []
            vendor = ""
            product = ""
            if isinstance(vendors, list) and vendors:
                vendor = str((vendors[0] or {}).get("name") if isinstance(vendors[0], dict) else vendors[0])
            elif isinstance(vendors, str):
                vendor = vendors
            if isinstance(products, list) and products:
                product = str((products[0] or {}).get("name") if isinstance(products[0], dict) else products[0])
            elif isinstance(products, str):
                product = products
            desc = str(item.get("description") or item.get("summary") or "")
            for cve_id in cves:
                if cve_id in seen:
                    continue
                seen.add(cve_id)
                entries.append({
                    "cve_id": cve_id,
                    "all_cves": [cve_id],
                    "date_added": date_str,
                    "source_dates": [date_str] if date_str else [],
                    "vendor_project": vendor,
                    "product": product,
                    "vulnerability_name": desc[:120],
                    "short_description": desc[:300],
                    "known_ransomware_use": "Unknown",
                    "kev_sources": ["euvd"],
                    "euvd_id": item.get("id") or item.get("euvd_id") or "",
                })

    # 1) Convenience exploited list (small fixed batch — always try)
    try:
        resp = await client.get(
            "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities",
            headers=headers,
            timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code == 200 and "application/json" in (resp.headers.get("content-type") or ""):
            data = resp.json()
            items = data if isinstance(data, list) else data.get("items") or data.get("data") or []
            await _ingest_items(items if isinstance(items, list) else [])
    except Exception as exc:
        logger.debug("EUVD exploitedvulnerabilities failed: %s", exc)

    if not paginated:
        return entries

    # 2) Search pagination for fuller exploited coverage (detail/background only)
    page = 0
    per_page = 100
    for _ in range(25):
        try:
            resp = await client.get(
                "https://euvdservices.enisa.europa.eu/api/search",
                params={"exploited": "true", "page": page, "size": per_page},
                headers=headers,
                timeout=_HTTP_TIMEOUT,
            )
            if resp.status_code in (403, 404):
                break
            if resp.status_code != 200:
                break
            ctype = resp.headers.get("content-type") or ""
            if "application/json" not in ctype:
                break
            data = resp.json()
        except Exception as exc:
            logger.debug("EUVD search page %s failed: %s", page, exc)
            break

        items = (
            data if isinstance(data, list)
            else data.get("items") or data.get("content") or data.get("data") or data.get("results") or []
        )
        if not isinstance(items, list) or not items:
            break
        await _ingest_items(items)
        total = 0
        if isinstance(data, dict):
            total = int(data.get("totalElements") or data.get("total") or data.get("totalResults") or 0)
        if total and (page + 1) * per_page >= total:
            break
        if len(items) < per_page:
            break
        page += 1
        await asyncio.sleep(0.35)  # ENISA rate-limit courtesy

    return entries


# ── Shadowserver (CIRCL honeypot exploited) ────────────────────────────────────

async def _fetch_shadowserver(cutoff: datetime) -> list[dict]:
    """
    Shadowserver honeypot-exploited CVEs via CIRCL.

    Prefer CIRCL KEV assertions (dated, gcve-eu-kev compatible). Fall back to the
    undated sightings set for all-time queries when the KEV catalog is empty.
    """
    refresh_hours = int(getattr(settings, "DELPHI_REFRESH_HOURS", 24))
    entries: list[dict] = []
    try:
        mapped = await asyncio.to_thread(
            fetch_shadowserver_from_circl_kev,
            force=False,
            refresh_hours=refresh_hours,
            cache_only=True,
            stale_ok=True,
        )
        for cve, entry in mapped.items():
            cve_id = _canonical_cve_id(cve)
            if not cve_id:
                continue
            date_str = entry.get("date_added") or ""
            entries.append({
                "cve_id": cve_id,
                "all_cves": [cve_id],
                "date_added": date_str,
                "source_dates": [date_str] if date_str else [],
                "vendor_project": entry.get("vendor_project", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerability_name", ""),
                "short_description": (entry.get("short_description") or "Observed in Shadowserver honeypot feed")[:300],
                "known_ransomware_use": entry.get("known_ransomware_use", "Unknown"),
                "kev_sources": ["shadowserver"],
            })
    except Exception as exc:
        logger.debug("Shadowserver CIRCL-KEV fetch failed: %s", exc)

    # Sightings fallback is a 40+ page CIRCL walk — never on the list path.
    # Delphi warms that cache separately.
    return entries

# ── KEVIntel (CIRCL KEV catalog) ───────────────────────────────────────────────

async def _fetch_kevintel(cutoff: datetime) -> list[dict]:
    """KEVIntel attestations via CIRCL KEV catalog (free, no Pro API key)."""
    try:
        refresh_hours = int(getattr(settings, "DELPHI_REFRESH_HOURS", 24))
        mapped = await asyncio.to_thread(
            fetch_kevintel_attestations,
            force=False,
            refresh_hours=refresh_hours,
            cache_only=True,
            stale_ok=True,
        )
    except Exception:
        return []
    entries = []
    for cve, entry in mapped.items():
        cve_id = _canonical_cve_id(cve)
        if not cve_id:
            continue
        date_str = entry.get("date_added") or ""
        entries.append({
            "cve_id": cve_id,
            "all_cves": [cve_id],
            "date_added": date_str,
            "source_dates": [date_str] if date_str else [],
            "vendor_project": entry.get("vendor_project", ""),
            "product": entry.get("product", ""),
            "vulnerability_name": entry.get("vulnerability_name", ""),
            "short_description": (entry.get("short_description") or "")[:300],
            "known_ransomware_use": entry.get("known_ransomware_use", "Unknown"),
            "kev_sources": ["kevintel"],
        })
    return entries


# ── Multi-source merge ─────────────────────────────────────────────────────────

def _merge_intel_sources(source_lists: list[list[dict]]) -> list[dict]:
    """
    Merge CVE entries from multiple sources, deduplicating by canonical CVE ID.
    Keep every source that knows the CVE; display date is the most recent listing.
    """
    merged: dict[str, dict] = {}
    for entries in source_lists:
        for entry in entries:
            cve_id = _canonical_cve_id(entry.get("cve_id"))
            if not cve_id:
                continue
            incoming = dict(entry)
            incoming["cve_id"] = cve_id
            incoming["source_dates"] = [
                d for d in (incoming.get("source_dates") or [incoming.get("date_added")]) if d
            ]
            if cve_id not in merged:
                merged[cve_id] = incoming
                continue
            existing = merged[cve_id]
            existing["kev_sources"] = sorted(set(
                (existing.get("kev_sources") or []) + (incoming.get("kev_sources") or [])
            ))
            existing["source_dates"] = list(dict.fromkeys(
                (existing.get("source_dates") or []) + (incoming.get("source_dates") or [])
            ))
            for field in ("vulnerability_name", "short_description", "vendor_project", "product"):
                if not existing.get(field) and incoming.get(field):
                    existing[field] = incoming[field]
            parsed_dates = [dt for dt in (_parse_intel_date(d) for d in existing["source_dates"]) if dt]
            if parsed_dates:
                latest = max(parsed_dates)
                existing["date_added"] = latest.date().isoformat()
            if incoming.get("known_ransomware_use") == "Known":
                existing["known_ransomware_use"] = "Known"
    return list(merged.values())


# ── ProjectDiscovery PDCP (vulnx backend) ────────────────────────────────────

async def _fetch_pdcp_cve(client: httpx.AsyncClient, cve_id: str, pdcp_key: str) -> dict:
    """
    Fetch per-CVE enrichment from ProjectDiscovery Cloud Platform.
    Returns the raw PDCP payload for the CVE, or {} on failure.

    Key fields returned by PDCP that we surface:
      is_template  — Nuclei template exists (detection possible)
      is_poc       — Public proof-of-concept available
      is_remote    — Remotely exploitable
      cvss_score   — CVSS base score
      severity     — critical / high / medium / low
      epss_score   — EPSS probability (informational)
      tags         — vulnerability tags (rce, sqli, xss, etc.)
    """
    if not pdcp_key:
        return {}
    try:
        resp = await client.get(
            f"https://api.projectdiscovery.io/v1/vulnerability/{cve_id}",
            headers={
                "X-Api-Key": pdcp_key,
                "Accept": "application/json",
                "User-Agent": "aegis-oracle/1.0",
            },
            timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json() or {}
    except Exception:
        return {}


async def _fetch_pdcp_batch(
    client: httpx.AsyncClient, cve_ids: list[str], pdcp_key: str
) -> dict[str, dict]:
    """Fetch PDCP enrichment for a batch of CVEs with bounded concurrency."""
    if not pdcp_key or not cve_ids:
        return {}
    sem = asyncio.Semaphore(_ENRICH_CONCURRENCY)
    out: dict[str, dict] = {}

    async def _one(cve_id: str) -> None:
        async with sem:
            out[cve_id] = await _fetch_pdcp_cve(client, cve_id, pdcp_key)

    await asyncio.gather(*[_one(cid) for cid in cve_ids], return_exceptions=True)
    return out


# ── OTX pulse count ───────────────────────────────────────────────────────────

async def _fetch_otx_pulse_count(client: httpx.AsyncClient, cve_id: str) -> int:
    """Quick OTX pulse count — free, no API key needed."""
    try:
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/indicator/cve/{cve_id}/general",
            headers={"User-Agent": "aegis-oracle/1.0", "Accept": "application/json"},
            timeout=10.0,
        )
        if resp.status_code != 200:
            return 0
        return resp.json().get("pulse_info", {}).get("count", 0)
    except Exception:
        return 0


async def _fetch_otx_batch(
    client: httpx.AsyncClient, cve_ids: list[str], *, max_cves: int = 40
) -> dict[str, int]:
    """
    OTX pulse counts with bounded concurrency.

    AlienVault OTX is ~5–12s per CVE and rate-limits under fan-out. The emerging
    list endpoint disables this by default; CVE detail fetches OTX on demand.
    """
    if not cve_ids:
        return {}
    targets = cve_ids[: max(0, max_cves)]
    sem = asyncio.Semaphore(_ENRICH_CONCURRENCY)
    out: dict[str, int] = {cid: 0 for cid in cve_ids}

    async def _one(cve_id: str) -> None:
        async with sem:
            out[cve_id] = await _fetch_otx_pulse_count(client, cve_id)

    await asyncio.gather(*[_one(cid) for cid in targets], return_exceptions=True)
    return out


# ── FIRST.org EPSS (free, no key) ────────────────────────────────────────────

async def _fetch_epss_batch(
    client: httpx.AsyncClient, cve_ids: list[str]
) -> dict[str, dict]:
    """
    Fetch EPSS scores + percentiles for a batch of CVEs from FIRST.org (free).
    Returns a map of cve_id → {epss_score, epss_percentile}.
    FIRST.org supports up to ~200 CVEs per request via comma-separated cve= param.
    """
    if not cve_ids:
        return {}
    results: dict[str, dict] = {}
    chunk_size = 200
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        try:
            resp = await client.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(chunk), "limit": len(chunk)},
                headers={"User-Agent": "aegis-oracle/1.0", "Accept": "application/json"},
                timeout=15.0,
            )
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                cve = row.get("cve", "").upper()
                if cve:
                    results[cve] = {
                        "epss_score": float(row["epss"]) if row.get("epss") else None,
                        "epss_percentile": float(row["percentile"]) if row.get("percentile") else None,
                    }
        except Exception:
            pass
    return results


# ── DB: Oracle analysis ───────────────────────────────────────────────────────

def _get_oracle_analysis_for_cves(db: Session, cve_ids: list[str]) -> dict[str, dict]:
    """
    Look up any existing Oracle enrichment results for these CVE IDs.

    Uses the promoted oracle_* columns on vulnerabilities (not legacy
    opes_score / delphi_priority names that are not on the ORM model).
    """
    if not cve_ids:
        return {}
    try:
        from app.models.vulnerability import Vulnerability

        rows = (
            db.query(
                Vulnerability.cve_id,
                Vulnerability.oracle_opes_score,
                Vulnerability.oracle_opes_category,
                Vulnerability.oracle_attack_path,
                Vulnerability.severity,
                Vulnerability.cvss_score,
            )
            .filter(Vulnerability.cve_id.in_(cve_ids))
            .all()
        )
        result: dict[str, dict] = {}
        for row in rows:
            if row.cve_id and row.cve_id not in result:
                sev = row.severity.value if hasattr(row.severity, "value") else row.severity
                result[row.cve_id] = {
                    "opes_score": row.oracle_opes_score,
                    "opes_category": row.oracle_opes_category,
                    "delphi_priority": row.oracle_attack_path,
                    "severity": sev,
                    "cvss_score": row.cvss_score,
                }
        return result
    except Exception:
        return {}


# ── Synthesis ─────────────────────────────────────────────────────────────────

def _detection_tier(pdcp: dict) -> str:
    """
    Map PDCP flags to a human-readable detection tier.
    The user wants to know: 'can we detect this?'
    """
    is_template = pdcp.get("is_template") or pdcp.get("nuclei_templates")
    is_poc = pdcp.get("is_poc")
    is_remote = pdcp.get("is_remote")

    if is_template:
        return "nuclei_template"   # can auto-detect with Nuclei
    if is_poc:
        return "poc_available"     # PoC exists, can verify manually
    if is_remote:
        return "remote_no_template"  # remotely exploitable, no auto-detection
    return "no_detection"


def _safe_float(value: Any) -> Optional[float]:
    """Coerce CVSS/EPSS to a JSON-safe float. Strings, NaN, and inf become None."""
    if value is None or value is False:
        return None
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        return None
    return parsed


def _severity_from_cvss(score: Optional[float]) -> str:
    parsed = _safe_float(score)
    if parsed is None:
        return "unknown"
    if parsed >= 9.0:
        return "critical"
    if parsed >= 7.0:
        return "high"
    if parsed >= 4.0:
        return "medium"
    return "low"


def _normalize_severity(value: Any, cvss: Optional[float]) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    if hasattr(value, "value"):
        return str(getattr(value, "value") or "").strip().lower() or _severity_from_cvss(cvss)
    return _severity_from_cvss(cvss)


def _as_tag_list(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if not isinstance(value, list):
        return []
    tags: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            tags.append(item.strip())
        elif isinstance(item, dict):
            label = item.get("name") or item.get("tag") or item.get("label")
            if label:
                tags.append(str(label))
    return tags[:10]


def _as_affected_products(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    products: list[dict] = []
    for item in value[:5]:
        if isinstance(item, dict):
            products.append({
                "vendor": str(item.get("vendor") or ""),
                "product": str(item.get("product") or item.get("name") or ""),
            })
        elif isinstance(item, str) and item.strip():
            products.append({"vendor": "", "product": item.strip()})
    return products


def _build_entry(
    kev: dict,
    pdcp: dict,
    otx_count: int,
    oracle: dict,
    epss: dict | None = None,
) -> dict:
    if not isinstance(pdcp, dict):
        pdcp = {}
    if not isinstance(oracle, dict):
        oracle = {}
    cve_id = kev["cve_id"]
    cvss = _safe_float(
        pdcp.get("cvss_score")
        or pdcp.get("cvss")
        or oracle.get("cvss_score")
        or kev.get("cvss_score")
    )
    epss_score = _safe_float(pdcp.get("epss_score"))
    if epss_score is None:
        epss_score = _safe_float((epss or {}).get("epss_score"))
    epss_percentile = _safe_float((epss or {}).get("epss_percentile"))
    severity = _normalize_severity(pdcp.get("severity") or oracle.get("severity"), cvss)
    try:
        pulses = int(otx_count or 0)
    except (TypeError, ValueError):
        pulses = 0

    return {
        "cve_id": cve_id,
        "date_added_kev": kev.get("date_added") or "",
        "vendor_project": kev.get("vendor_project") or "",
        "product": kev.get("product") or "",
        "vulnerability_name": kev.get("vulnerability_name") or pdcp.get("name") or "",
        "short_description": kev.get("short_description") or pdcp.get("description") or "",
        "known_ransomware_use": kev.get("known_ransomware_use") or "Unknown",
        "kev_sources": kev.get("kev_sources") or ["vulncheck_kev"],
        "severity": severity,
        "cvss_score": cvss,
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "is_template": bool(pdcp.get("is_template") or pdcp.get("nuclei_templates")),
        "is_poc": bool(pdcp.get("is_poc")),
        "is_remote": bool(pdcp.get("is_remote")),
        "detection_tier": _detection_tier(pdcp),
        "template_count": pdcp.get("template_count") or (1 if pdcp.get("is_template") else 0),
        "otx_pulse_count": pulses,
        "otx_active_campaign": pulses >= 20,
        "tags": _as_tag_list(pdcp.get("tags")),
        "affected_products": _as_affected_products(pdcp.get("affected_products")),
        "oracle_analyzed": bool(oracle),
        "opes_score": oracle.get("opes_score"),
        "opes_category": oracle.get("opes_category"),
        "delphi_priority": oracle.get("delphi_priority"),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/emerging")
async def get_emerging_vulnerabilities(
    days: int = Query(30, ge=0, le=3650, description="KEV entries added in the last N days; 0 = all time"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical,high,medium,low)"),
    detection: Optional[str] = Query(None, description="Filter: nuclei_template | poc_available | remote_no_template | no_detection"),
    source: Optional[str] = Query(None, description="Filter by source(s): cisa_kev,vulncheck_kev,enisa_kev,euvd,shadowserver,kevintel (comma-separated)"),
    limit: int = Query(500, ge=1, le=2000),
    include_otx: bool = Query(
        False,
        description="Enrich with AlienVault OTX pulse counts. Off by default — OTX is slow (~10s/CVE) and loads on CVE detail instead.",
    ),
    organization_id: Optional[int] = Query(None, description="Org whose stored API keys to use; omit to use any available key"),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_active_user),
):
    """
    Returns CVEs from ALL exploitation intelligence sources merged by CVE ID:
      - CISA KEV          (free)
      - VulnCheck KEV     (requires VULNCHECK_API_TOKEN)
      - ENISA EU KEV      (free — CNW EUKEV JSON)
      - EUVD              (free)
      - Shadowserver      (free via CIRCL)
      - KEVIntel          (free via CIRCL)

    OTX campaign pulses are deferred to GET /threat-intel/cve/{id} by default so
    this list endpoint stays fast enough for the Vulnerability Intel UI.
    """
    vulncheck_token = _get_vulncheck_token(db, organization_id)
    pdcp_key = _get_pdcp_key(db, organization_id)

    cutoff = (
        datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        - timedelta(days=days)
        if days > 0
        else datetime.min.replace(tzinfo=timezone.utc)
    )

    empty_summary = {
        "total": 0,
        "with_nuclei_template": 0,
        "with_poc": 0,
        "remote_exploitable": 0,
        "ransomware_associated": 0,
        "otx_active_campaigns": 0,
        "oracle_analyzed": 0,
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_source": {
            "cisa_kev": 0,
            "vulncheck_kev": 0,
            "enisa_kev": 0,
            "euvd": 0,
            "shadowserver": 0,
            "kevintel": 0,
        },
        "multi_source_count": 0,
        "vulncheck_configured": bool(vulncheck_token),
        "pdcp_configured": bool(pdcp_key),
        "otx_deferred": not include_otx,
        "catalog": {
            "cisa_kev": 0,
            "vulncheck_kev": 0,
            "enisa_kev": 0,
            "euvd": 0,
            "shadowserver": 0,
            "kevintel": 0,
        },
    }

    async with httpx.AsyncClient(timeout=httpx.Timeout(_HTTP_TIMEOUT, connect=5.0)) as client:
        (
            vulncheck_entries,
            cisa_entries,
            enisa_entries,
            euvd_entries,
            shadowserver_entries,
            kevintel_entries,
        ) = await asyncio.gather(
            _feed_or_empty("vulncheck", _fetch_vulncheck_kev(client, days, vulncheck_token)),
            _feed_or_empty("cisa", _fetch_cisa_kev(client, cutoff)),
            _feed_or_empty("enisa", _fetch_enisa_kev(client, cutoff)),
            _feed_or_empty("euvd", _fetch_euvd(client, cutoff, paginated=False)),
            _feed_or_empty("shadowserver", _fetch_shadowserver(cutoff)),
            _feed_or_empty("kevintel", _fetch_kevintel(cutoff)),
        )

        try:
            merged_entries = _merge_intel_sources([
                vulncheck_entries,
                cisa_entries,
                enisa_entries,
                euvd_entries,
                shadowserver_entries,
                kevintel_entries,
            ])
        except Exception:
            logger.exception("threat-intel merge failed; serving unmerged feed rows")
            merged_entries = [
                row
                for group in (
                    vulncheck_entries,
                    cisa_entries,
                    enisa_entries,
                    euvd_entries,
                    shadowserver_entries,
                    kevintel_entries,
                )
                if isinstance(group, list)
                for row in group
                if isinstance(row, dict) and row.get("cve_id")
            ]

        catalog = {
            "cisa_kev": len(cisa_entries),
            "vulncheck_kev": len(vulncheck_entries),
            "enisa_kev": len(enisa_entries),
            "euvd": len(euvd_entries),
            "shadowserver": len(shadowserver_entries),
            "kevintel": len(kevintel_entries),
        }
        empty_summary["catalog"] = catalog

        merged_entries = [
            row for row in merged_entries
            if _entry_in_window(row, cutoff, days=days)
        ]

        if not merged_entries:
            return {
                "total": 0,
                "days": days,
                "entries": [],
                "summary": empty_summary,
            }

        cve_ids = [e["cve_id"] for e in merged_entries if e["cve_id"]][:limit]

        async def _empty_otx() -> dict[str, int]:
            return {}

        try:
            pdcp_map, otx_map, epss_map = await asyncio.wait_for(
                asyncio.gather(
                    _fetch_pdcp_batch(client, cve_ids, pdcp_key),
                    _fetch_otx_batch(client, cve_ids) if include_otx else _empty_otx(),
                    _fetch_epss_batch(client, cve_ids),
                ),
                timeout=8.0,
            )
        except Exception as exc:
            logger.warning("threat-intel emerging enrichment failed (%s); returning feed-only data", exc)
            pdcp_map, otx_map, epss_map = {}, {}, {}

    if not isinstance(pdcp_map, dict):
        pdcp_map = {}
    if not isinstance(otx_map, dict):
        otx_map = {}
    if not isinstance(epss_map, dict):
        epss_map = {}

    # Oracle DB lookup (sync, local DB — no HTTP)
    oracle_map = _get_oracle_analysis_for_cves(db, cve_ids)

    entries = []
    cve_ids_set = set(cve_ids)
    for kev in merged_entries:
        cve_id = kev.get("cve_id", "")
        if not cve_id or cve_id not in cve_ids_set:
            continue
        try:
            entry = _build_entry(
                kev=kev,
                pdcp=pdcp_map.get(cve_id) or {},
                otx_count=otx_map.get(cve_id, 0),
                oracle=oracle_map.get(cve_id) or {},
                epss=epss_map.get(cve_id),
            )
        except Exception:
            logger.warning("threat-intel skipped malformed row %s", cve_id, exc_info=True)
            continue
        entries.append(entry)

    # Apply filters
    if severity:
        allowed = {s.strip().lower() for s in severity.split(",")}
        entries = [e for e in entries if e.get("severity", "").lower() in allowed]
    if detection:
        allowed_tiers = {d.strip() for d in detection.split(",")}
        entries = [e for e in entries if e.get("detection_tier") in allowed_tiers]
    if source:
        required_sources = {s.strip() for s in source.split(",")}
        entries = [
            e for e in entries
            if required_sources.intersection(set(e.get("kev_sources", [])))
        ]

    # Sort: multi-source CVEs first, then by severity
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    entries.sort(key=lambda e: (
        -len(e.get("kev_sources") or []),
        _sev_order.get(str(e.get("severity") or "unknown"), 4),
    ))

    # Summary stats
    total = len(entries)
    summary = {
        "total": total,
        "with_nuclei_template": sum(1 for e in entries if e["is_template"]),
        "with_poc": sum(1 for e in entries if e["is_poc"]),
        "remote_exploitable": sum(1 for e in entries if e["is_remote"]),
        "ransomware_associated": sum(
            1 for e in entries if e.get("known_ransomware_use", "Unknown") == "Known"
        ),
        "otx_active_campaigns": sum(1 for e in entries if e.get("otx_active_campaign")),
        "oracle_analyzed": sum(1 for e in entries if e.get("oracle_analyzed")),
        "by_severity": {
            "critical": sum(1 for e in entries if e.get("severity") == "critical"),
            "high": sum(1 for e in entries if e.get("severity") == "high"),
            "medium": sum(1 for e in entries if e.get("severity") == "medium"),
            "low": sum(1 for e in entries if e.get("severity") == "low"),
        },
        "by_source": {
            "cisa_kev": sum(1 for e in entries if "cisa_kev" in e.get("kev_sources", [])),
            "vulncheck_kev": sum(1 for e in entries if "vulncheck_kev" in e.get("kev_sources", [])),
            "enisa_kev": sum(1 for e in entries if "enisa_kev" in e.get("kev_sources", [])),
            "euvd": sum(1 for e in entries if "euvd" in e.get("kev_sources", [])),
            "shadowserver": sum(1 for e in entries if "shadowserver" in e.get("kev_sources", [])),
            "kevintel": sum(1 for e in entries if "kevintel" in e.get("kev_sources", [])),
        },
        "multi_source_count": sum(1 for e in entries if len(e.get("kev_sources", [])) > 1),
        "vulncheck_configured": bool(vulncheck_token),
        "pdcp_configured": bool(pdcp_key),
        "otx_deferred": not include_otx,
        "catalog": catalog,
    }

    return {
        "total": total,
        "days": days,
        "entries": entries,
        "summary": summary,
    }


@router.get("/cve/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    organization_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_active_user),
):
    """
    Full enrichment for a single CVE: PDCP data + OTX + NVD/OSV/GHSA catalog
    metadata + public exploit indexes (PoC-in-GitHub, trickest/cve, GitHub repos,
    Exploit-DB, CXSecurity) + any Oracle analysis on record.
    """
    cve_id = cve_id.upper().strip()
    pdcp_key = _get_pdcp_key(db, organization_id)
    nvd_key = resolve_api_key(db, ExternalService.NVD, organization_id) or getattr(settings, "NVD_API_KEY", None)
    github_token = getattr(settings, "GITHUB_TOKEN", None)

    async with httpx.AsyncClient() as client:
        pdcp, otx_count, catalog = await asyncio.gather(
            _fetch_pdcp_cve(client, cve_id, pdcp_key),
            _fetch_otx_pulse_count(client, cve_id),
            asyncio.to_thread(
                enrich_cve_catalog,
                cve_id,
                nvd_api_key=nvd_key,
                github_token=github_token,
            ),
        )

    oracle = _get_oracle_analysis_for_cves(db, [cve_id]).get(cve_id, {})

    return {
        "cve_id": cve_id,
        "pdcp": pdcp,
        "otx_pulse_count": otx_count,
        "otx_active_campaign": otx_count >= 20,
        "detection_tier": _detection_tier(pdcp),
        "is_template": bool(pdcp.get("is_template")),
        "is_poc": bool(pdcp.get("is_poc")),
        "is_remote": bool(pdcp.get("is_remote")),
        "catalog": catalog,
        "oracle": oracle,
    }


@router.post("/analyze/{cve_id}")
async def analyze_kev_cve(
    cve_id: str,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_active_user),
):
    """
    Trigger Oracle intrinsic analysis for a CVE from the threat-intel feed.

    Calls the Oracle's GET /cve/{id} endpoint (Phase A — no asset context
    required) and returns the analysis result. If the CVE already exists
    as a Vulnerability in the DB, the result is persisted there too.

    Returns attack_path_class, analyst_brief, confidence, and any available
    OPES score so the frontend can display it next to severity.
    """
    import os

    cve_id = cve_id.upper().strip()
    oracle_url = os.getenv("ORACLE_URL", "http://aegis-oracle:8742").rstrip("/")
    oracle_timeout = float(os.getenv("ORACLE_TIMEOUT", "60"))

    try:
        async with httpx.AsyncClient(base_url=oracle_url, timeout=oracle_timeout) as client:
            resp = await client.get(f"/cve/{cve_id}")
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Oracle returned {e.response.status_code} for {cve_id}: {e.response.text[:200]}",
        )
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Oracle service unreachable: {e}")

    analysis = data.get("analysis") or {}
    exploitation = data.get("exploitation") or {}
    opes = analysis.get("opes") or {}

    def _str(v: Any) -> str | None:
        """Return v as a string, or None — never returns a raw object to the frontend."""
        if v is None:
            return None
        if isinstance(v, str):
            return v
        if isinstance(v, (int, float, bool)):
            return str(v)
        return None  # drop objects/lists silently

    result = {
        "cve_id": cve_id,
        "analysis_status": _str(data.get("analysis_status")) or "complete",
        # OPES scoring (present when Oracle has enough signal)
        "opes_score": opes.get("score") if isinstance(opes.get("score"), (int, float)) else None,
        "opes_category": _str(opes.get("category")),
        "opes_label": _str(opes.get("label")),
        "opes_confidence": _str(opes.get("confidence")),
        # Intrinsic analysis fields — all forced to str | None so React can render them
        "attack_path_class": _str(analysis.get("attack_path_class")),
        "lateral_movement_potential": bool(analysis.get("lateral_movement_potential")),
        "remote_triggerability": _str(analysis.get("remote_triggerability")),
        "exploit_complexity": _str(analysis.get("exploit_complexity")),
        "attacker_capability": _str(analysis.get("attacker_capability")),
        "confidence": _str(analysis.get("confidence")),
        "analyst_brief": _str(analysis.get("analyst_brief")),
        # Exploitation summary scalars only (avoids sending raw object to React)
        "exploitability_score": exploitation.get("exploitability_score") if isinstance(exploitation.get("exploitability_score"), (int, float)) else None,
        "exploitability_tier": _str(exploitation.get("exploitability_tier")),
    }

    # If this CVE exists as a Vulnerability in the DB, persist the result
    try:
        from app.models.vulnerability import Vulnerability
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
        if vuln:
            meta = dict(vuln.metadata_) if isinstance(vuln.metadata_, dict) else {}
            meta["oracle"] = result
            vuln.metadata_ = meta
            if opes.get("score") is not None and isinstance(opes.get("score"), (int, float)):
                vuln.oracle_opes_score = float(opes["score"])
            if opes.get("category"):
                vuln.oracle_opes_category = str(opes["category"])
            if opes.get("label"):
                vuln.oracle_opes_label = str(opes["label"])
            if opes.get("confidence"):
                vuln.oracle_opes_confidence = str(opes["confidence"])
            if result.get("attack_path_class"):
                vuln.oracle_attack_path = result["attack_path_class"]
            vuln.oracle_enriched_at = datetime.utcnow()
            vuln.oracle_analysis_status = result.get("analysis_status") or "complete"
            db.commit()
    except Exception:
        pass  # non-fatal — return result regardless

    return result


@router.get("/stats")
async def get_threat_intel_stats(
    organization_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_active_user),
):
    """Quick health-check showing which data sources are configured."""
    vulncheck_token = _get_vulncheck_token(db, organization_id)
    pdcp_key = _get_pdcp_key(db, organization_id)
    nvd_key = resolve_api_key(db, ExternalService.NVD, organization_id) or getattr(settings, "NVD_API_KEY", None)
    return {
        "sources": {
            "vulncheck_kev": {
                "configured": bool(vulncheck_token),
                "description": "VulnCheck KEV — broadest exploitation catalog (primary Delphi KEV-class signal)",
                "key_source": "db" if resolve_api_key(db, ExternalService.VULNCHECK, organization_id) else "env",
            },
            "pdcp_vulnx": {
                "configured": bool(pdcp_key),
                "description": "ProjectDiscovery PDCP — Nuclei template & PoC availability",
                "key_source": "db" if resolve_api_key(db, ExternalService.PDCP, organization_id) else "env",
            },
            "nvd": {
                "configured": bool(nvd_key),
                "description": "NVD CVE API — first-party CVSS/CWE metadata (key raises rate limits)",
                "key_source": "db" if resolve_api_key(db, ExternalService.NVD, organization_id) else "env",
            },
            "osv": {
                "configured": True,
                "description": "OSV.dev — ecosystem package advisories (free)",
                "key_source": "none_required",
            },
            "ghsa": {
                "configured": True,
                "description": "GitHub Security Advisories — free (GITHUB_TOKEN raises rate limits)",
                "key_source": "none_required",
            },
            "poc_github": {
                "configured": True,
                "description": "nomi-sec/PoC-in-GitHub — indexed public PoC repositories (free)",
                "key_source": "none_required",
            },
            "trickest": {
                "configured": True,
                "description": "trickest/cve — broader GitHub PoC aggregator Markdown index (free)",
                "key_source": "none_required",
            },
            "github_repos": {
                "configured": True,
                "description": "GitHub repository search for CVE-named PoCs (GITHUB_TOKEN raises rate limits)",
                "key_source": "none_required",
            },
            "exploitdb": {
                "configured": True,
                "description": "Exploit-DB via offensive-security/exploitdb mirror (GITHUB_TOKEN raises rate limits)",
                "key_source": "none_required",
            },
            "cxsecurity": {
                "configured": True,
                "description": "CXSecurity cveshow advisories (best-effort HTML, free)",
                "key_source": "none_required",
            },
            "shadowserver": {
                "configured": True,
                "description": "Shadowserver honeypot exploited CVEs via CIRCL (free)",
                "key_source": "none_required",
            },
            "kevintel": {
                "configured": True,
                "description": "KEVIntel attestations via CIRCL KEV catalog (free)",
                "key_source": "none_required",
            },
            "otx": {
                "configured": True,
                "description": "AlienVault OTX — free, no API key needed",
                "key_source": "none_required",
            },
        }
    }
