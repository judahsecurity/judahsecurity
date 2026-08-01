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

def fetch_vulncheck_kev(
    token: str,
    *,
    force: bool = False,
    refresh_hours: int = 24,
    max_pages: int = 20,
) -> Dict[str, Dict[str, Any]]:
    """
    Return {CVE-ID: entry} for VulnCheck KEV. Empty dict when no token.
    Caches the full mapped payload on disk.
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
        for _ in range(max_pages):
            # VulnCheck index API accepts sort=_timestamp|date_added (not camelCase).
            params = {"sort": "date_added", "order": "desc", "limit": 500}
            if cursor:
                params["cursor"] = cursor
            url = VULNCHECK_KEV_URL + "?" + urllib.parse.urlencode(params)
            payload = _http_get_json(url, headers=headers, timeout=60)
            entries = payload.get("data") or []
            if not entries:
                break
            for entry in entries:
                cves = entry.get("cve") or []
                if not cves:
                    continue
                cve = str(cves[0]).strip().upper()
                if not cve.startswith("CVE-"):
                    continue
                mapped[cve] = {
                    "cve_id": cve,
                    "all_cves": [str(c).upper() for c in cves],
                    "date_added": entry.get("dateAdded") or entry.get("date_added"),
                    "vendor_project": entry.get("vendorProject") or "",
                    "product": entry.get("product") or "",
                    "vulnerability_name": entry.get("vulnerabilityName") or "",
                    "short_description": entry.get("shortDescription") or "",
                    "known_ransomware_use": entry.get("knownRansomwareUse") or "Unknown",
                    "source": "vulncheck_kev",
                }
            meta = payload.get("_meta") or payload.get("meta") or {}
            cursor = (
                payload.get("_next")
                or payload.get("cursor")
                or meta.get("next_cursor")
            )
            if not cursor:
                break
        _write_json(path, {"fetched_at": datetime.now(timezone.utc).isoformat(), "entries": mapped})
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


# ── KEVIntel via CIRCL KEV catalog ─────────────────────────────────────────────

def fetch_kevintel_attestations(
    *,
    force: bool = False,
    refresh_hours: int = 24,
    max_pages: int = 20,
    per_page: int = 500,
) -> Dict[str, Dict[str, Any]]:
    """
    Return {CVE-ID: entry} for CVEs attested by KEVIntel in the CIRCL KEV catalog.
    Free public feed — no KEVIntel Pro API key required.
    """
    path = os.path.join(_cache_dir(), "kevintel_circl.json")
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
                evidence = row.get("evidence") or []
                sources = {str(ev.get("source") or "").lower() for ev in evidence}
                if "kevintel" not in sources:
                    continue
                vuln = ((row.get("vulnerability") or {}).get("vulnId") or "").strip().upper()
                if not vuln.startswith("CVE-"):
                    continue
                # Prefer the kevintel evidence block for metadata.
                detail = {}
                for ev in evidence:
                    if str(ev.get("source") or "").lower() == "kevintel":
                        detail = ev.get("details") or {}
                        break
                mapped[vuln] = {
                    "cve_id": vuln,
                    "date_added": detail.get("added_date") or (row.get("timestamps") or {}).get("asserted_at"),
                    "vendor_project": detail.get("vendor") or "",
                    "product": detail.get("product") or "",
                    "vulnerability_name": detail.get("title") or "",
                    "short_description": (row.get("scope") or {}).get("notes") or "",
                    "known_ransomware_use": "Known" if str(detail.get("used_in_malware") or "").lower() in ("yes", "true", "known") else "Unknown",
                    "confidence": next((ev.get("confidence") for ev in evidence if str(ev.get("source") or "").lower() == "kevintel"), None),
                    "not_yet_in_cisa_kev": bool(detail.get("not_yet_in_cisa_kev")),
                    "source": "kevintel",
                }
            meta = payload.get("metadata") or {}
            total = int(meta.get("count") or 0)
            if page * per_page >= total:
                break
        _write_json(path, {"fetched_at": datetime.now(timezone.utc).isoformat(), "entries": mapped})
        logger.info("Vuln intel: cached %d KEVIntel attestations", len(mapped))
    except Exception as exc:
        logger.warning("Vuln intel: KEVIntel/CIRCL fetch failed (%s); using stale cache", exc)
        if os.path.exists(path):
            try:
                data = _read_json(path)
                return {k: v for k, v in (data.get("entries") or {}).items()}
            except Exception:
                return mapped
    return mapped


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
