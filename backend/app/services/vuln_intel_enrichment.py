"""
On-demand CVE catalog enrichment: NVD, OSV, and GitHub Security Advisories.

Used by the threat-intel CVE detail endpoint (and any caller that needs
first-party CVE metadata without going through ProjectDiscovery vulnx).
Lookups are short-TTL cached in-process to avoid hammering upstream APIs.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/vulns"
GHSA_URL = "https://api.github.com/advisories"

_CACHE_TTL_SECONDS = 6 * 3600
_cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
_lock = threading.RLock()


def _http_get_json(url: str, *, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Any:
    req_headers = {
        "User-Agent": "judahsecurity-asm-vuln-intel/1.0",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed public URLs
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _normalize_cve(cve_id: str) -> str:
    s = (cve_id or "").strip().upper()
    if s and not s.startswith("CVE-"):
        s = f"CVE-{s}"
    return s


def _fetch_nvd(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    headers = {}
    key = api_key or os.environ.get("NVD_API_KEY") or ""
    if key:
        headers["apiKey"] = key
    try:
        url = f"{NVD_URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
        payload = _http_get_json(url, headers=headers, timeout=30)
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return None
        cve = (vulns[0] or {}).get("cve") or {}
        metrics = cve.get("metrics") or {}
        cvss_score = None
        cvss_vector = None
        cvss_version = None
        for key_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key_name) or []
            if not rows:
                continue
            primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
            data = primary.get("cvssData") or {}
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")
            cvss_version = data.get("version")
            break
        descriptions = cve.get("descriptions") or []
        desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
        if not desc and descriptions:
            desc = descriptions[0].get("value")
        weaknesses: List[str] = []
        for w in cve.get("weaknesses") or []:
            for desc_row in w.get("description") or []:
                val = desc_row.get("value")
                if val and val.upper().startswith("CWE-"):
                    weaknesses.append(val.upper())
        return {
            "source": "nvd",
            "cve_id": cve_id,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": cve.get("vulnStatus"),
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "cwes": sorted(set(weaknesses)),
            "references": [
                r.get("url") for r in (cve.get("references") or [])[:15] if r.get("url")
            ],
        }
    except Exception as exc:
        logger.debug("NVD lookup failed for %s: %s", cve_id, exc)
        return None


def _fetch_osv(cve_id: str) -> Optional[Dict[str, Any]]:
    """OSV accepts some CVE IDs directly as vulnerability IDs."""
    try:
        payload = _http_get_json(f"{OSV_URL}/{urllib.parse.quote(cve_id)}", timeout=20)
        if not isinstance(payload, dict) or payload.get("code"):
            return None
        affected = []
        for a in payload.get("affected") or []:
            pkg = a.get("package") or {}
            affected.append({
                "ecosystem": pkg.get("ecosystem"),
                "name": pkg.get("name"),
                "purl": pkg.get("purl"),
            })
        return {
            "source": "osv",
            "id": payload.get("id") or cve_id,
            "aliases": payload.get("aliases") or [],
            "summary": payload.get("summary") or payload.get("details"),
            "severity": ((payload.get("database_specific") or {}).get("severity")
                          or (payload.get("severity") or {}).get("type")
                          or None),
            "affected_packages": affected[:25],
            "references": [
                r.get("url") for r in (payload.get("references") or [])[:15] if r.get("url")
            ],
            "published": payload.get("published"),
            "modified": payload.get("modified"),
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        logger.debug("OSV lookup failed for %s: %s", cve_id, exc)
        return None
    except Exception as exc:
        logger.debug("OSV lookup failed for %s: %s", cve_id, exc)
        return None


def _fetch_ghsa(cve_id: str, github_token: Optional[str] = None) -> List[Dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json"}
    token = github_token or os.environ.get("GITHUB_TOKEN") or ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        url = f"{GHSA_URL}?{urllib.parse.urlencode({'cve_id': cve_id, 'per_page': 5})}"
        payload = _http_get_json(url, headers=headers, timeout=20)
        if not isinstance(payload, list):
            return []
        out: List[Dict[str, Any]] = []
        for row in payload:
            out.append({
                "source": "ghsa",
                "ghsa_id": row.get("ghsa_id"),
                "cve_id": row.get("cve_id") or cve_id,
                "severity": row.get("severity"),
                "summary": row.get("summary"),
                "html_url": row.get("html_url"),
                "published_at": row.get("published_at"),
                "updated_at": row.get("updated_at"),
                "vulnerabilities": [
                    {
                        "ecosystem": (v.get("package") or {}).get("ecosystem"),
                        "name": (v.get("package") or {}).get("name"),
                        "vulnerable_version_range": v.get("vulnerable_version_range"),
                        "first_patched_version": v.get("first_patched_version"),
                    }
                    for v in (row.get("vulnerabilities") or [])[:20]
                ],
            })
        return out
    except Exception as exc:
        logger.debug("GHSA lookup failed for %s: %s", cve_id, exc)
        return []


def enrich_cve_catalog(
    cve_id: str,
    *,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    First-party CVE metadata from NVD + OSV + GHSA.

    Returns a dict with keys: cve_id, nvd, osv, ghsa, enriched.
    """
    cve = _normalize_cve(cve_id)
    if not cve:
        return {"cve_id": cve, "enriched": False, "reason": "empty_cve"}

    cache_key = f"catalog:{cve}"
    now = time.time()
    if use_cache:
        with _lock:
            hit = _cache.get(cache_key)
            if hit and (now - hit[0]) < _CACHE_TTL_SECONDS:
                return hit[1]

    nvd = _fetch_nvd(cve, api_key=nvd_api_key)
    osv = _fetch_osv(cve)
    ghsa = _fetch_ghsa(cve, github_token=github_token)

    # If OSV missed on the CVE id but GHSA has an id, try that.
    if not osv:
        for g in ghsa:
            gid = g.get("ghsa_id")
            if gid:
                try:
                    payload = _http_get_json(f"{OSV_URL}/{urllib.parse.quote(gid)}", timeout=20)
                    if isinstance(payload, dict) and not payload.get("code"):
                        affected = []
                        for a in payload.get("affected") or []:
                            pkg = a.get("package") or {}
                            affected.append({
                                "ecosystem": pkg.get("ecosystem"),
                                "name": pkg.get("name"),
                                "purl": pkg.get("purl"),
                            })
                        osv = {
                            "source": "osv",
                            "id": payload.get("id") or gid,
                            "aliases": payload.get("aliases") or [],
                            "summary": payload.get("summary") or payload.get("details"),
                            "severity": ((payload.get("database_specific") or {}).get("severity")),
                            "affected_packages": affected[:25],
                            "references": [
                                r.get("url") for r in (payload.get("references") or [])[:15] if r.get("url")
                            ],
                            "published": payload.get("published"),
                            "modified": payload.get("modified"),
                        }
                        break
                except Exception:
                    continue

    result = {
        "cve_id": cve,
        "enriched": bool(nvd or osv or ghsa),
        "nvd": nvd,
        "osv": osv,
        "ghsa": ghsa,
    }
    with _lock:
        _cache[cache_key] = (now, result)
    return result
