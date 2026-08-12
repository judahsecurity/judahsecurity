"""
Extended exploitation-intelligence feed loaders for Delphi + threat-intel.

Sources
-------
  - VulnCheck KEV          (optional VULNCHECK_API_TOKEN)
  - CIRCL / Shadowserver   (free honeypot exploited sightings via vulnerability.circl.lu)
  - CIRCL / KEVIntel       (free early-warning attestations via CIRCL KEV catalog)
  - FIRE breach intel      (optional operator-supplied JSON overlay)

All feeds are cached on disk under DELPHI_CACHE_DIR and refreshed on the same
cadence as CISA KEV / EPSS. Failures are best-effort — stale cache is preferred
over empty when a live fetch fails.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

CIRCL_BASE = "https://vulnerability.circl.lu/api"
VULNCHECK_KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
SHADOWSERVER_SIGHTING_SOURCE = "honeypot/exploited-vulnerabilities"
KEVINTEL_API_URL = "https://kevintel.com/api/v1/kevs"
CISA_KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # GitHub mirror maintained by CISA (fallback when cisa.gov is slow/blocked)
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
)


def _cache_dir() -> str:
    path = os.environ.get("DELPHI_CACHE_DIR") or "/tmp/delphi_cache"
    os.makedirs(path, exist_ok=True)
    return path


def _http_get_json(url: str, *, headers: Optional[Dict[str, str]] = None, timeout: int = 60) -> Any:
    req_headers = {"User-Agent": "judahsecurity-asm-vuln-intel/1.0", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed public URLs
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _cache_fresh(path: str, refresh_hours: int) -> bool:
    if not os.path.exists(path):
        return False
    age_hours = (time.time() - os.path.getmtime(path)) / 3600.0
    return age_hours < refresh_hours


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: str, payload: Any) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.replace(tmp, path)


# ── VulnCheck KEV ──────────────────────────────────────────────────────────────

def _vulncheck_next_cursor(payload: Dict[str, Any]) -> Optional[str]:
    """Extract next page cursor from VulnCheck v3 index responses."""
    meta = payload.get("_meta") or payload.get("meta") or {}
    cursor = (
        meta.get("next_cursor")
        or payload.get("_next")
        or payload.get("cursor")
        or meta.get("cursor")
    )
    if cursor is None:
        return None
    cursor_s = str(cursor).strip()
    return cursor_s or None


def fetch_vulncheck_kev(
    token: str,
    *,
    force: bool = False,
    refresh_hours: int = 24,
    max_pages: int = 80,
    page_limit: int = 300,
) -> Dict[str, Dict[str, Any]]:
    """
    Return {CVE-ID: entry} for VulnCheck KEV. Empty dict when no token.

    Uses VulnCheck v3 cursor pagination correctly:
      1st page: start_cursor=true
      next pages: cursor=<\_meta.next_cursor>

    Caches the full mapped payload on disk so Delphi + threat-intel share one pull.
    """
    path = os.path.join(_cache_dir(), "vulncheck_kev.json")
    if not token:
        if os.path.exists(path):
            try:
                data = _read_json(path)
                return {k: v for k, v in (data.get("entries") or {}).items()}
            except Exception:
                return {}
        return {}

    if not force and _cache_fresh(path, refresh_hours):
        try:
            data = _read_json(path)
            return {k: v for k, v in (data.get("entries") or {}).items()}
        except Exception:
            pass

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    mapped: Dict[str, Dict[str, Any]] = {}
    cursor: Optional[str] = None
    try:
        for page_idx in range(max_pages):
            # Docs: https://docs.vulncheck.com/api/v3/indice
            # SDK requires start_cursor=true on the first page of a session.
            params: Dict[str, Any] = {
                "sort": "date_added",
                "order": "desc",
                "limit": page_limit,
            }
            if cursor:
                params["cursor"] = cursor
            else:
                params["start_cursor"] = "true"
            url = VULNCHECK_KEV_URL + "?" + urllib.parse.urlencode(params)
            payload = _http_get_json(url, headers=headers, timeout=90)
            if not isinstance(payload, dict):
                logger.warning("Vuln intel: unexpected VulnCheck payload type %s", type(payload))
                break
            entries = payload.get("data") or []
            if not entries:
                break
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                cves = entry.get("cve") or []
                if not cves:
                    # Some rows use id=CVE-...
                    maybe = str(entry.get("id") or "").strip().upper()
                    if maybe.startswith("CVE-"):
                        cves = [maybe]
                if not cves:
                    continue
                cve = str(cves[0]).strip().upper()
                if not cve.startswith("CVE-"):
                    continue
                cvss_obj = entry.get("cvss") or entry.get("cvssMetrics") or {}
                if not isinstance(cvss_obj, dict):
                    cvss_obj = {}
                cvss_score = (
                    cvss_obj.get("v3Score")
                    or cvss_obj.get("cvssV3Score")
                    or cvss_obj.get("baseScore")
                    or entry.get("cvssV3Score")
                    or entry.get("cvss_v3_score")
                )
                mapped[cve] = {
                    "cve_id": cve,
                    "all_cves": [str(c).upper() for c in cves if str(c).upper().startswith("CVE-")],
                    "date_added": entry.get("dateAdded") or entry.get("date_added"),
                    "vendor_project": entry.get("vendorProject") or "",
                    "product": entry.get("product") or "",
                    "vulnerability_name": entry.get("vulnerabilityName") or "",
                    "short_description": entry.get("shortDescription") or "",
                    "known_ransomware_use": entry.get("knownRansomwareUse") or "Unknown",
                    "cvss_score": float(cvss_score) if cvss_score is not None else None,
                    "source": "vulncheck_kev",
                }
            cursor = _vulncheck_next_cursor(payload)
            meta = payload.get("_meta") or payload.get("meta") or {}
            total_docs = meta.get("total_documents")
            if page_idx == 0 and total_docs:
                logger.info(
                    "Vuln intel: VulnCheck KEV reports %s total documents",
                    total_docs,
                )
            if not cursor:
                break
        _write_json(
            path,
            {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "count": len(mapped),
                "entries": mapped,
            },
        )
        logger.info("Vuln intel: cached %d VulnCheck KEV entries", len(mapped))
    except Exception as exc:
        logger.warning("Vuln intel: VulnCheck KEV fetch failed (%s); using stale cache", exc)
        if os.path.exists(path):
            try:
                data = _read_json(path)
                return {k: v for k, v in (data.get("entries") or {}).items()}
            except Exception:
                return mapped
    return mapped

# ── Shadowserver via CIRCL sightings ───────────────────────────────────────────

def fetch_shadowserver_exploited(
    *,
    force: bool = False,
    refresh_hours: int = 24,
    max_pages: int = 45,
    per_page: int = 1000,
) -> Set[str]:
    """
    Unique CVE IDs Shadowserver honeypots observed as exploited.
    Sourced via CIRCL Vulnerability-Lookup sightings (no Shadowserver API key).
    """
    path = os.path.join(_cache_dir(), "shadowserver_exploited.json")
    if not force and _cache_fresh(path, refresh_hours):
        try:
            data = _read_json(path)
            return {str(c).upper() for c in (data.get("cves") or []) if str(c).upper().startswith("CVE-")}
        except Exception:
            pass

    cves: Set[str] = set()
    try:
        for page in range(1, max_pages + 1):
            qs = urllib.parse.urlencode({
                "source": SHADOWSERVER_SIGHTING_SOURCE,
                "type": "exploited",
                "per_page": per_page,
                "page": page,
            })
            payload = _http_get_json(f"{CIRCL_BASE}/sighting/?{qs}", timeout=90)
            rows = payload.get("data") or []
            if not rows:
                break
            for row in rows:
                vuln = (row.get("vulnerability") or "").strip().upper()
                if vuln.startswith("CVE-"):
                    cves.add(vuln)
            meta = payload.get("metadata") or {}
            total = int(meta.get("count") or 0)
            if page * per_page >= total:
                break
        _write_json(
            path,
            {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "count": len(cves),
                "cves": sorted(cves),
            },
        )
        logger.info("Vuln intel: cached %d Shadowserver exploited CVEs", len(cves))
    except Exception as exc:
        logger.warning("Vuln intel: Shadowserver fetch failed (%s); using stale cache", exc)
        if os.path.exists(path):
            try:
                data = _read_json(path)
                return {str(c).upper() for c in (data.get("cves") or []) if str(c).upper().startswith("CVE-")}
            except Exception:
                return cves
    return cves


# ── CIRCL KEV catalog (KEVIntel + Shadowserver assertions) ─────────────────────

def _circl_kev_date(row: Dict[str, Any], detail: Dict[str, Any]) -> str:
    ts = row.get("timestamps") or {}
    return (
        detail.get("added_date")
        or ts.get("asserted_at")
        or ts.get("first_seen_at")
        or ts.get("last_seen_at")
        or ""
    )


def fetch_circl_kev_by_source(
    source: str,
    *,
    force: bool = False,
    refresh_hours: int = 24,
    max_pages: int = 40,
    per_page: int = 200,
) -> Dict[str, Dict[str, Any]]:
    """
    Return {CVE-ID: entry} for CIRCL KEV assertions whose evidence includes `source`.

    Aligns with gcve-eu-kev sources that land in Vulnerability-Lookup:
      - kevintel
      - shadowserver
      - cisa-kev / enisa-cnw-kev (also present, but we pull those natively)
    """
    source_l = (source or "").strip().lower()
    path = os.path.join(_cache_dir(), f"circl_kev_{source_l or 'all'}.json")
    if not force and _cache_fresh(path, refresh_hours):
        try:
            data = _read_json(path)
            return {k: v for k, v in (data.get("entries") or {}).items()}
        except Exception:
            pass

    mapped: Dict[str, Dict[str, Any]] = {}
    try:
        for page in range(1, max_pages + 1):
            qs = urllib.parse.urlencode({"per_page": per_page, "page": page})
            payload = _http_get_json(f"{CIRCL_BASE}/kev/?{qs}", timeout=90)
            rows = payload.get("data") or []
            if not rows:
                break
            for row in rows:
                if not isinstance(row, dict):
                    continue
                evidence = row.get("evidence") or []
                match = None
                for ev in evidence:
                    if str(ev.get("source") or "").lower() == source_l:
                        match = ev
                        break
                if match is None:
                    continue
                vuln = ((row.get("vulnerability") or {}).get("vulnId") or "").strip().upper()
                if not vuln.startswith("CVE-"):
                    continue
                detail = match.get("details") or {}
                if not isinstance(detail, dict):
                    detail = {}
                mapped[vuln] = {
                    "cve_id": vuln,
                    "date_added": _circl_kev_date(row, detail),
                    "vendor_project": detail.get("vendor") or detail.get("vendorProject") or "",
                    "product": detail.get("product") or "",
                    "vulnerability_name": detail.get("title") or detail.get("vulnerabilityName") or "",
                    "short_description": (row.get("scope") or {}).get("notes") or "",
                    "known_ransomware_use": (
                        "Known"
                        if str(detail.get("used_in_malware") or detail.get("exploitationType") or "").lower()
                        in ("yes", "true", "known", "ransomware")
                        else "Unknown"
                    ),
                    "confidence": match.get("confidence"),
                    "not_yet_in_cisa_kev": bool(detail.get("not_yet_in_cisa_kev")),
                    "source": source_l,
                }
            meta = payload.get("metadata") or {}
            total = int(meta.get("count") or 0)
            if page * per_page >= total:
                break
        _write_json(
            path,
            {"fetched_at": datetime.now(timezone.utc).isoformat(), "count": len(mapped), "entries": mapped},
        )
        logger.info("Vuln intel: cached %d CIRCL KEV entries for source=%s", len(mapped), source_l)
    except Exception as exc:
        logger.warning("Vuln intel: CIRCL KEV (%s) fetch failed (%s); using stale cache", source_l, exc)
        if os.path.exists(path):
            try:
                data = _read_json(path)
                return {k: v for k, v in (data.get("entries") or {}).items()}
            except Exception:
                return mapped
    return mapped


def fetch_kevintel_direct(
    *,
    force: bool = False,
    refresh_hours: int = 24,
    max_pages: int = 100,
    per_page: int = 100,
) -> Dict[str, Dict[str, Any]]:
    """
    Prefer the first-party KEVIntel API (https://kevintel.com/api/v1/kevs),
    matching gcve-eu-kev. Falls back to empty dict on failure so CIRCL can cover.
    """
    path = os.path.join(_cache_dir(), "kevintel_direct.json")
    if not force and _cache_fresh(path, refresh_hours):
        try:
            data = _read_json(path)
            return {k: v for k, v in (data.get("entries") or {}).items()}
        except Exception:
            pass

    mapped: Dict[str, Dict[str, Any]] = {}
    try:
        page = 1
        for _ in range(max_pages):
            qs = urllib.parse.urlencode({"per_page": per_page, "page": page})
            payload = _http_get_json(f"{KEVINTEL_API_URL}?{qs}", timeout=60)
            # Live API returns {"kevs":[...], "pagination":{...}}.
            # Some deployments currently return an OpenAPI "filters" schema — treat as failure.
            if not isinstance(payload, dict) or "filters" in payload and "kevs" not in payload:
                raise ValueError("KEVIntel API returned schema/docs instead of kevs data")
            kevs = payload.get("kevs") or []
            if not isinstance(kevs, list) or not kevs:
                break
            for item in kevs:
                if not isinstance(item, dict):
                    continue
                cve = str(item.get("cve_id") or "").strip().upper()
                if not cve.startswith("CVE-"):
                    continue
                mapped[cve] = {
                    "cve_id": cve,
                    "date_added": item.get("added_date") or "",
                    "vendor_project": item.get("vendor") or "",
                    "product": item.get("product") or "",
                    "vulnerability_name": item.get("title") or "",
                    "short_description": item.get("title") or "",
                    "known_ransomware_use": (
                        "Known"
                        if str(item.get("used_in_malware") or "").lower() in ("yes", "true", "known")
                        else "Unknown"
                    ),
                    "not_yet_in_cisa_kev": bool(item.get("not_yet_in_cisa_kev")),
                    "cvss_score": item.get("cvss_score"),
                    "source": "kevintel",
                }
            pagination = payload.get("pagination") or {}
            next_page = pagination.get("next_page")
            if not next_page:
                break
            page = int(next_page)
        if mapped:
            _write_json(
                path,
                {"fetched_at": datetime.now(timezone.utc).isoformat(), "count": len(mapped), "entries": mapped},
            )
            logger.info("Vuln intel: cached %d KEVIntel direct entries", len(mapped))
    except Exception as exc:
        logger.warning("Vuln intel: KEVIntel direct fetch failed (%s)", exc)
        if os.path.exists(path):
            try:
                data = _read_json(path)
                return {k: v for k, v in (data.get("entries") or {}).items()}
            except Exception:
                return {}
        return {}
    return mapped


def fetch_kevintel_attestations(
    *,
    force: bool = False,
    refresh_hours: int = 24,
    max_pages: int = 40,
    per_page: int = 200,
) -> Dict[str, Dict[str, Any]]:
    """
    Return {CVE-ID: entry} for KEVIntel attestations.

    Prefers kevintel.com (gcve-eu-kev path); falls back to CIRCL Vulnerability-Lookup
    KEV catalog evidence source=kevintel.
    """
    direct = fetch_kevintel_direct(force=force, refresh_hours=refresh_hours)
    if direct:
        return direct
    return fetch_circl_kev_by_source(
        "kevintel",
        force=force,
        refresh_hours=refresh_hours,
        max_pages=max_pages,
        per_page=per_page,
    )


def fetch_shadowserver_from_circl_kev(
    *,
    force: bool = False,
    refresh_hours: int = 24,
) -> Dict[str, Dict[str, Any]]:
    """Shadowserver honeypot KEV assertions via CIRCL (dated, unlike raw sightings)."""
    return fetch_circl_kev_by_source(
        "shadowserver",
        force=force,
        refresh_hours=refresh_hours,
    )

# ── FIRE + breach-intel overlays ───────────────────────────────────────────────

def load_fire_cves(path: Optional[str] = None) -> Set[str]:
    """
    Load FIRE (insurance-loss) CVEs from an operator-supplied JSON file.

    Accepted shapes:
      {"cves": ["CVE-...", ...]}
      ["CVE-...", ...]
      {"CVE-...": {...}, ...}   # object keyed by CVE ID
    """
    candidates: List[str] = []
    if path:
        candidates.append(path)
    env_path = os.environ.get("DELPHI_FIRE_CVE_PATH")
    if env_path:
        candidates.append(env_path)
    candidates.append(os.path.join(_cache_dir(), "fire_cves.json"))
    # Repo-relative default for deployments that mount backend/data
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.normpath(os.path.join(here, "..", "..", "data", "breach_intel", "fire_cves.json")))

    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            raw = _read_json(candidate)
            cves: Set[str] = set()
            if isinstance(raw, list):
                cves = {str(c).upper() for c in raw if str(c).upper().startswith("CVE-")}
            elif isinstance(raw, dict):
                if "cves" in raw and isinstance(raw["cves"], list):
                    cves = {str(c).upper() for c in raw["cves"] if str(c).upper().startswith("CVE-")}
                else:
                    cves = {str(k).upper() for k in raw.keys() if str(k).upper().startswith("CVE-")}
            if cves:
                logger.info("Vuln intel: loaded %d FIRE CVEs from %s", len(cves), candidate)
                return cves
        except Exception as exc:
            logger.warning("Vuln intel: FIRE load failed for %s: %s", candidate, exc)
    return set()


def load_breach_overlay(filename: str, directory: Optional[str] = None) -> Set[str]:
    """
    Optional JSON overlay for Mandiant / CrowdStrike lists so operators can
    refresh annually without a code change. Looks in DELPHI_BREACH_INTEL_DIR
    and backend/data/breach_intel/.
    """
    dirs: List[str] = []
    if directory:
        dirs.append(directory)
    env_dir = os.environ.get("DELPHI_BREACH_INTEL_DIR")
    if env_dir:
        dirs.append(env_dir)
    here = os.path.dirname(os.path.abspath(__file__))
    dirs.append(os.path.normpath(os.path.join(here, "..", "..", "data", "breach_intel")))

    for d in dirs:
        path = os.path.join(d, filename)
        if not os.path.exists(path):
            continue
        try:
            raw = _read_json(path)
            if isinstance(raw, list):
                return {str(c).upper() for c in raw if str(c).upper().startswith("CVE-")}
            if isinstance(raw, dict) and isinstance(raw.get("cves"), list):
                return {str(c).upper() for c in raw["cves"] if str(c).upper().startswith("CVE-")}
        except Exception as exc:
            logger.warning("Vuln intel: breach overlay %s failed: %s", path, exc)
    return set()


def load_extended_feeds(
    *,
    vulncheck_token: str = "",
    force: bool = False,
    refresh_hours: int = 24,
    enabled: bool = True,
) -> Tuple[Dict[str, Dict[str, Any]], Set[str], Dict[str, Dict[str, Any]], Set[str]]:
    """
    Load VulnCheck / Shadowserver / KEVIntel / FIRE caches.

    Returns:
      (vulncheck_map, shadowserver_set, kevintel_map, fire_set)
    """
    if not enabled:
        return {}, set(), {}, load_fire_cves()

    vkev = fetch_vulncheck_kev(vulncheck_token, force=force, refresh_hours=refresh_hours)
    shadow = fetch_shadowserver_exploited(force=force, refresh_hours=refresh_hours)
    kevintel = fetch_kevintel_attestations(force=force, refresh_hours=refresh_hours)
    fire = load_fire_cves()
    return vkev, shadow, kevintel, fire
