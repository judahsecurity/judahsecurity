"""
On-demand CVE catalog enrichment: NVD, OSV, GHSA, plus public exploit indexes.

Catalog metadata:
  - NVD, OSV, GitHub Security Advisories

Public exploit / PoC sources (aligned with Aegis Oracle enrichers):
  - nomi-sec/PoC-in-GitHub
  - trickest/cve (broader GitHub PoC aggregator)
  - GitHub repo search (CVE in name)
  - Exploit-DB (offensive-security/exploitdb mirror)
  - CXSecurity cveshow

Used by the threat-intel CVE detail endpoint (and any caller that needs
first-party CVE metadata without going through ProjectDiscovery vulnx).
Lookups are short-TTL cached in-process to avoid hammering upstream APIs.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/vulns"
GHSA_URL = "https://api.github.com/advisories"
POC_GITHUB_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
TRICKEST_CVE_RAW = "https://raw.githubusercontent.com/trickest/cve/main"
GITHUB_SEARCH_REPOS = "https://api.github.com/search/repositories"
GITHUB_SEARCH_CODE = "https://api.github.com/search/code"
CXSECURITY_CVE_SHOW = "https://cxsecurity.com/cveshow"
_GITHUB_REPO_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
_TRICKEST_SKIP_REPOS = {
    "blob", "tree", "raw", "commit", "issues", "pull", "wiki",
    "releases", "actions", "projects", "settings",
}

_CACHE_TTL_SECONDS = 6 * 3600
_cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
_lock = threading.RLock()

_CX_WLB_HREF_RE = re.compile(
    r"""(?i)href=["']((?:https?://(?:www\.)?cxsecurity\.com)?/issue/WLB-[^"']+)["']"""
)
_CX_TITLE_RE = re.compile(r"(?i)<title[^>]*>([^<]+)</title>")
_CX_NOT_FOUND_RE = re.compile(r"(?i)(not\s+found|no\s+results|404)")


def _http_get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    accept: str = "application/json",
) -> tuple[int, bytes]:
    req_headers = {
        "User-Agent": "judahsecurity-asm-vuln-intel/1.0",
        "Accept": accept,
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed public URLs
            return resp.getcode() or 200, resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return exc.code, body


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


def _github_headers(github_token: Optional[str] = None) -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = github_token or os.environ.get("GITHUB_TOKEN") or ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _cve_year(cve_id: str) -> Optional[str]:
    parts = cve_id.split("-")
    if len(parts) >= 2 and parts[1].isdigit() and len(parts[1]) == 4:
        return parts[1]
    return None


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
    headers = _github_headers(github_token)
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


def _fetch_poc_github(cve_id: str) -> Dict[str, Any]:
    """nomi-sec/PoC-in-GitHub raw index (same source as Aegis Oracle)."""
    year = _cve_year(cve_id)
    if not year:
        return {"source": "poc_github", "found": False, "note": "unparseable CVE year"}
    url = f"{POC_GITHUB_RAW}/{year}/{cve_id}.json"
    try:
        status, body = _http_get(url, timeout=12)
        if status == 404:
            return {"source": "poc_github", "found": False, "count": 0, "pocs": []}
        if status != 200:
            return {"source": "poc_github", "found": False, "note": f"HTTP {status}"}
        payload = json.loads(body.decode("utf-8", errors="replace"))
        rows = payload if isinstance(payload, list) else []
        pocs: List[Dict[str, Any]] = []
        for row in rows[:15]:
            if not isinstance(row, dict):
                continue
            pocs.append({
                "name": row.get("name"),
                "full_name": row.get("full_name"),
                "url": row.get("html_url") or row.get("url"),
                "description": row.get("description"),
                "stars": row.get("stargazers_count") or row.get("stars") or 0,
                "created_at": row.get("created_at"),
            })
        return {
            "source": "poc_github",
            "found": bool(pocs),
            "count": len(pocs),
            "pocs": pocs,
            "note": "nomi-sec/PoC-in-GitHub",
        }
    except Exception as exc:
        logger.debug("PoC-in-GitHub lookup failed for %s: %s", cve_id, exc)
        return {"source": "poc_github", "found": False, "note": str(exc)}


def _extract_github_repos_from_md(md: str) -> List[Dict[str, str]]:
    """Extract unique github.com/owner/repo links from Markdown text."""
    seen: Dict[str, Dict[str, str]] = {}
    for match in _GITHUB_REPO_RE.finditer(md or ""):
        owner = match.group(1).removesuffix(".git")
        repo = match.group(2).removesuffix(".git")
        if not owner or not repo or repo.lower() in _TRICKEST_SKIP_REPOS:
            continue
        full_name = f"{owner}/{repo}"
        if full_name in seen:
            continue
        seen[full_name] = {
            "full_name": full_name,
            "url": f"https://github.com/{full_name}",
        }
    return sorted(seen.values(), key=lambda r: r["full_name"])


def _extract_trickest_repos(md: str) -> List[Dict[str, str]]:
    """Extract unique github.com/owner/repo links from trickest Markdown."""
    # Prefer the #### Github section when present; fall back to full doc.
    idx = md.find("#### Github")
    if idx >= 0:
        repos = _extract_github_repos_from_md(md[idx:])
        if repos:
            return repos
    return _extract_github_repos_from_md(md)


def _fetch_trickest(cve_id: str) -> Dict[str, Any]:
    """trickest/cve Markdown index (same source as Aegis Oracle / exploit-availability-check)."""
    year = _cve_year(cve_id)
    if not year:
        return {"source": "trickest", "found": False, "note": "unparseable CVE year"}
    url = f"{TRICKEST_CVE_RAW}/{year}/{cve_id}.md"
    try:
        status, body = _http_get(url, timeout=12, accept="text/plain, text/markdown, */*")
        if status == 404:
            return {"source": "trickest", "found": False, "count": 0, "pocs": []}
        if status != 200:
            return {"source": "trickest", "found": False, "note": f"HTTP {status}"}
        md = body.decode("utf-8", errors="replace")
        pocs = _extract_trickest_repos(md)
        return {
            "source": "trickest",
            "found": bool(pocs),
            "count": len(pocs),
            "pocs": pocs[:25],
            "note": "trickest/cve",
        }
    except Exception as exc:
        logger.debug("trickest/cve lookup failed for %s: %s", cve_id, exc)
        return {"source": "trickest", "found": False, "note": str(exc)}


def _fetch_github_repos(cve_id: str, github_token: Optional[str] = None) -> Dict[str, Any]:
    """GitHub repository search for CVE-named / described PoC repos."""
    try:
        q = f"{cve_id} in:name,description"
        url = f"{GITHUB_SEARCH_REPOS}?{urllib.parse.urlencode({'q': q, 'per_page': 10, 'sort': 'stars'})}"
        payload = _http_get_json(url, headers=_github_headers(github_token), timeout=15)
        items = payload.get("items") or []
        repos = []
        for row in items[:10]:
            repos.append({
                "full_name": row.get("full_name"),
                "url": row.get("html_url"),
                "description": row.get("description"),
                "stars": row.get("stargazers_count") or 0,
                "created_at": row.get("created_at"),
            })
        return {
            "source": "github_repos",
            "found": bool(repos),
            "count": int(payload.get("total_count") or len(repos)),
            "repos": repos,
            "note": "GitHub repository search",
        }
    except Exception as exc:
        logger.debug("GitHub repo search failed for %s: %s", cve_id, exc)
        return {"source": "github_repos", "found": False, "note": str(exc)}


def _fetch_exploitdb(cve_id: str, github_token: Optional[str] = None) -> Dict[str, Any]:
    """Exploit-DB via offensive-security/exploitdb GitHub code search."""
    try:
        q = f"{cve_id} repo:offensive-security/exploitdb"
        url = f"{GITHUB_SEARCH_CODE}?{urllib.parse.urlencode({'q': q, 'per_page': 10})}"
        status, body = _http_get(url, headers=_github_headers(github_token), timeout=15)
        if status in (401, 403):
            return {
                "source": "exploitdb",
                "found": False,
                "note": "GitHub rate limit; set GITHUB_TOKEN for higher limits",
            }
        if status != 200:
            return {"source": "exploitdb", "found": False, "note": f"HTTP {status}"}
        payload = json.loads(body.decode("utf-8", errors="replace"))
        total = int(payload.get("total_count") or 0)
        exploits: List[Dict[str, Any]] = []
        for item in payload.get("items") or []:
            name = item.get("name") or ""
            path = item.get("path") or ""
            if name.endswith(".csv") or name.endswith(".md"):
                continue
            exp_type = "exploit"
            if "/remote/" in path:
                exp_type = "remote"
            elif "/local/" in path:
                exp_type = "local"
            elif "/webapps/" in path:
                exp_type = "webapps"
            elif path.startswith("shellcodes/"):
                exp_type = "shellcode"
            exploits.append({
                "file": path,
                "url": item.get("html_url"),
                "type": exp_type,
            })
            if len(exploits) >= 8:
                break
        return {
            "source": "exploitdb",
            "found": bool(exploits),
            "count": total,
            "exploits": exploits,
            "note": "exploit-db.com via offensive-security/exploitdb mirror",
        }
    except Exception as exc:
        logger.debug("Exploit-DB lookup failed for %s: %s", cve_id, exc)
        return {"source": "exploitdb", "found": False, "note": str(exc)}


def _fetch_cxsecurity(cve_id: str) -> Dict[str, Any]:
    """CXSecurity cveshow page (best-effort HTML parse)."""
    page_url = f"{CXSECURITY_CVE_SHOW}/{cve_id}/"
    try:
        status, body = _http_get(page_url, timeout=12, accept="text/html")
        html = body.decode("utf-8", errors="replace")
        if status == 404:
            return {"source": "cxsecurity", "found": False, "page_url": page_url, "entries": []}
        if status != 200:
            return {"source": "cxsecurity", "found": False, "page_url": page_url, "note": f"HTTP {status}"}
        if _CX_NOT_FOUND_RE.search(html) and cve_id not in html.upper():
            return {"source": "cxsecurity", "found": False, "page_url": page_url, "entries": []}

        seen: set[str] = set()
        entries: List[Dict[str, Any]] = []
        for match in _CX_WLB_HREF_RE.findall(html)[:20]:
            href = match
            if href.startswith("/"):
                href = "https://cxsecurity.com" + href
            if href in seen:
                continue
            seen.add(href)
            entries.append({"title": "CXSecurity advisory", "url": href})
            if len(entries) >= 10:
                break

        if not entries and cve_id in html.upper():
            title = cve_id
            tm = _CX_TITLE_RE.search(html)
            if tm:
                title = tm.group(1).strip()
            return {
                "source": "cxsecurity",
                "found": True,
                "count": 1,
                "page_url": page_url,
                "entries": [{"title": title, "url": page_url}],
                "note": "cveshow page present; no WLB issue links parsed",
            }

        return {
            "source": "cxsecurity",
            "found": bool(entries),
            "count": len(entries),
            "page_url": page_url,
            "entries": entries,
            "note": "cxsecurity.com cveshow (best-effort HTML)",
        }
    except Exception as exc:
        logger.debug("CXSecurity lookup failed for %s: %s", cve_id, exc)
        return {"source": "cxsecurity", "found": False, "page_url": page_url, "note": str(exc)}


def enrich_cve_catalog(
    cve_id: str,
    *,
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    use_cache: bool = True,
    include_exploit_sources: bool = True,
) -> Dict[str, Any]:
    """
    First-party CVE metadata from NVD + OSV + GHSA, plus public exploit indexes.

    Returns a dict with keys: cve_id, nvd, osv, ghsa, exploit_sources, enriched.
    """
    cve = _normalize_cve(cve_id)
    if not cve:
        return {"cve_id": cve, "enriched": False, "reason": "empty_cve"}

    cache_key = f"catalog:{cve}:x={int(include_exploit_sources)}"
    now = time.time()
    if use_cache:
        with _lock:
            hit = _cache.get(cache_key)
            if hit and (now - hit[0]) < _CACHE_TTL_SECONDS:
                return hit[1]

    with ThreadPoolExecutor(max_workers=8) as pool:
        fut_nvd = pool.submit(_fetch_nvd, cve, nvd_api_key)
        fut_osv = pool.submit(_fetch_osv, cve)
        fut_ghsa = pool.submit(_fetch_ghsa, cve, github_token)
        fut_poc = fut_trickest = fut_repos = fut_edb = fut_cx = None
        if include_exploit_sources:
            fut_poc = pool.submit(_fetch_poc_github, cve)
            fut_trickest = pool.submit(_fetch_trickest, cve)
            fut_repos = pool.submit(_fetch_github_repos, cve, github_token)
            fut_edb = pool.submit(_fetch_exploitdb, cve, github_token)
            fut_cx = pool.submit(_fetch_cxsecurity, cve)

        nvd = fut_nvd.result()
        osv = fut_osv.result()
        ghsa = fut_ghsa.result()
        exploit_sources: Dict[str, Any] = {}
        if (
            include_exploit_sources
            and fut_poc
            and fut_trickest
            and fut_repos
            and fut_edb
            and fut_cx
        ):
            exploit_sources = {
                "poc_github": fut_poc.result(),
                "trickest": fut_trickest.result(),
                "github_repos": fut_repos.result(),
                "exploitdb": fut_edb.result(),
                "cxsecurity": fut_cx.result(),
            }

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

    exploit_found = any(
        isinstance(v, dict) and v.get("found") for v in exploit_sources.values()
    )
    result = {
        "cve_id": cve,
        "enriched": bool(nvd or osv or ghsa or exploit_found),
        "nvd": nvd,
        "osv": osv,
        "ghsa": ghsa,
        "exploit_sources": exploit_sources,
    }
    with _lock:
        _cache[cache_key] = (now, result)
    return result
