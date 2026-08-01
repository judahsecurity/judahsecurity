"""
jsluice Standalone Service
==========================

Direct invocation of the jsluice binary on JavaScript files/URLs.
Designed to be used both as a standalone scan and as a post-Katana
step inside the recon pipeline (Katana populates asset.js_files, then
this service processes them).

Extracts:
  - URL paths with query params, body params, HTTP method, and jsluice
    call type (fetchCall, locationAssignment, windowOpen, etc.)
  - Secrets (all jsluice built-in matchers: AWS, GitHub, GCP, …)

Usage:
  # Standalone: discover and analyse JS from target homepages
  result = await run_jsluice_scan(targets=["example.com"])

  # Recon pipeline: skip discovery, use Katana's pre-built list
  result = await run_jsluice_scan(js_urls=asset.js_files)

  # Persist findings to DB
  created = persist_jsluice_findings(db, org_id, scan_id, result)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

_SLUG_RE = re.compile(r"[^a-z0-9]+")
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class JSluicePath:
    """A URL/path extracted by jsluice from a JS file."""
    url: str
    method: str                     # GET, POST, …
    query_params: list[str]         # parameter names from query string
    body_params: list[str]          # parameter names from request body
    url_type: str                   # jsluice call type: fetchCall, XHROpen, etc.
    source_js: str                  # URL of the JS file it came from


@dataclass
class JSluiceSecret:
    """A secret extracted by jsluice from a JS file."""
    kind: str                       # e.g. "AWSAccessKeyId", "GitHubToken"
    severity: str                   # critical / high / medium / low
    data: dict                      # raw jsluice data payload
    source_js: str


@dataclass
class JSluiceResult:
    js_files_analyzed: int = 0
    paths_found: int = 0
    params_found: int = 0          # total query + body params across all paths
    secrets_found: int = 0
    paths: list[JSluicePath] = field(default_factory=list)
    secrets: list[JSluiceSecret] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _have_jsluice() -> bool:
    return shutil.which("jsluice") is not None


async def _fetch(client: httpx.AsyncClient, url: str) -> Optional[tuple[str, str]]:
    """Return (final_url, body) or None on failure."""
    try:
        r = await client.get(url, timeout=15.0, follow_redirects=True)
        if r.status_code >= 400:
            return None
        return str(r.url), r.text
    except Exception as exc:
        logger.debug("jsluice fetch %s: %s", url, exc)
        return None


async def _run_subcmd(body_bytes: bytes, subcmd: str) -> str:
    """Run ``jsluice <subcmd> -`` with *body_bytes* on stdin, return stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "jsluice", subcmd, "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=body_bytes[:5_000_000]),
            timeout=30.0,
        )
        return stdout.decode(errors="ignore")
    except Exception as exc:
        logger.debug("jsluice %s failed: %s", subcmd, exc)
        return ""


async def _analyze_js_body(js_url: str, body: str) -> tuple[list[JSluicePath], list[JSluiceSecret]]:
    """
    Run jsluice urls + secrets on *body*, return (paths, secrets).
    """
    body_bytes = body.encode()
    urls_out, secrets_out = await asyncio.gather(
        _run_subcmd(body_bytes, "urls"),
        _run_subcmd(body_bytes, "secrets"),
    )

    paths: list[JSluicePath] = []
    for line in urls_out.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        u = obj.get("url", "")
        if not u:
            continue
        paths.append(JSluicePath(
            url=u[:1000],
            method=(obj.get("method") or "GET").upper(),
            query_params=obj.get("queryParams") or [],
            body_params=obj.get("bodyParams") or [],
            url_type=obj.get("type") or "",
            source_js=js_url,
        ))

    _sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    secrets: list[JSluiceSecret] = []
    for line in secrets_out.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        secrets.append(JSluiceSecret(
            kind=obj.get("kind") or "secret",
            severity=_sev_map.get(obj.get("severity", ""), "high"),
            data=obj.get("data") or {},
            source_js=js_url,
        ))

    return paths, secrets


async def _discover_js_from_targets(
    client: httpx.AsyncClient,
    targets: list[str],
    max_js: int,
) -> list[str]:
    """Discover JS file URLs from target homepage HTML."""
    js_urls: list[str] = []
    for target in targets:
        if not target.startswith("http"):
            target = f"https://{target}"
        fetched = await _fetch(client, target)
        if not fetched:
            continue
        final_url, html = fetched
        for src in SCRIPT_SRC_RE.findall(html):
            abs_url = urljoin(final_url, src)
            if ".js" in abs_url.split("?")[0]:
                js_urls.append(abs_url)
        if len(js_urls) >= max_js:
            break
    return list(dict.fromkeys(js_urls))[:max_js]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_jsluice_scan(
    *,
    js_urls: Optional[list[str]] = None,
    targets: Optional[list[str]] = None,
    max_js: int = 500,
    timeout: int = 600,
    concurrency: int = 20,
) -> JSluiceResult:
    """
    Run jsluice on JavaScript files and return a :class:`JSluiceResult`.

    Supply *js_urls* directly (e.g. from Katana's ``asset.js_files``) to
    skip discovery.  If *js_urls* is empty/None and *targets* is provided,
    the service will fetch the target homepages and extract ``<script src>``
    links first.
    """
    start = datetime.utcnow()
    result = JSluiceResult()

    if not _have_jsluice():
        result.errors.append("jsluice binary not found in PATH")
        return result

    async with httpx.AsyncClient(
        http2=True,
        verify=False,
        headers={"User-Agent": "ASM-jsluice/1.0"},
        timeout=httpx.Timeout(30.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    ) as client:
        work_urls: list[str] = list(js_urls or [])

        if not work_urls and targets:
            work_urls = await _discover_js_from_targets(client, targets, max_js)

        work_urls = list(dict.fromkeys(work_urls))[:max_js]

        if not work_urls:
            return result

        sem = asyncio.Semaphore(concurrency)

        async def _process(url: str):
            async with sem:
                try:
                    fetched = await _fetch(client, url)
                    if not fetched:
                        return [], []
                    final_url, body = fetched
                    return await _analyze_js_body(final_url, body)
                except Exception as exc:
                    result.errors.append(f"{url}: {exc}")
                    return [], []

        chunks = await asyncio.gather(*(_process(u) for u in work_urls))

    for paths, secrets in chunks:
        result.paths.extend(paths)
        result.secrets.extend(secrets)

    result.js_files_analyzed = len(work_urls)
    result.paths_found = len(result.paths)
    result.params_found = sum(
        len(p.query_params) + len(p.body_params) for p in result.paths
    )
    result.secrets_found = len(result.secrets)
    result.duration_seconds = (datetime.utcnow() - start).total_seconds()
    return result


# ---------------------------------------------------------------------------
# Helpers for summary dict (stored in scan.results)
# ---------------------------------------------------------------------------


def build_results_summary(result: JSluiceResult) -> dict:
    """Return the comprehensive dict stored in ``scan.results``.

    Includes every JS file analyzed, all extracted paths/params, and all
    discovered secrets so analysts can audit the full scan inventory.
    """
    # Deduplicated JS file list across all path source_js entries
    js_files_list = sorted({p.source_js for p in result.paths if p.source_js})

    all_paths = [
        {
            "url": p.url,
            "method": p.method,
            "query_params": p.query_params,
            "body_params": p.body_params,
            "url_type": p.url_type,
            "source_js": p.source_js,
            "has_params": bool(p.query_params or p.body_params),
        }
        for p in result.paths
    ]

    secrets_list = [
        {
            "kind": s.kind,
            "severity": s.severity,
            "match": (s.data.get("match") or s.data.get("key") or s.data.get("value") or "")[:80],
            "source_js": s.source_js,
        }
        for s in result.secrets
    ]

    return {
        # Summary counts
        "js_files_analyzed": result.js_files_analyzed,
        "paths_found": result.paths_found,
        "params_found": result.params_found,
        "secrets_found": result.secrets_found,
        "duration_seconds": round(result.duration_seconds, 1),
        "errors": result.errors[:20],
        # Full inventories (capped to keep JSON column manageable)
        "js_files": js_files_list[:500],
        "jsluice_paths": [p for p in all_paths if p["has_params"]][:200],
        "jsluice_all_paths": all_paths[:1000],
        "secrets": secrets_list[:500],
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-") or "unknown"


def _hash12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def persist_jsluice_findings(
    db,
    organization_id: int,
    scan_id: Optional[int],
    result: JSluiceResult,
) -> int:
    """
    Persist jsluice paths and secrets as ``Vulnerability`` rows and update asset
    app-structure fields so everything discovered is visible in the UI.

    - ALL paths are written to ``asset.endpoints`` / ``asset.parameters`` /
      ``asset.js_files`` so the App Structure tab shows the full inventory.
    - Paths with at least one parameter also get a Vulnerability row at INFO
      severity (attack-surface endpoint worth reviewing for IDOR / injection).
    - Secrets are stored at the severity reported by jsluice (high / critical).

    Returns the number of new Vulnerability rows created.
    """
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    _sev = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    def _get_or_create_asset(hostname: str) -> "Asset":  # noqa: F821
        a = (
            db.query(Asset)
            .filter(Asset.organization_id == organization_id, Asset.value == hostname)
            .first()
        )
        if not a:
            a = Asset(
                organization_id=organization_id,
                asset_type=AssetType.DOMAIN,
                name=hostname,
                value=hostname,
                discovery_source="jsluice",
            )
            db.add(a)
            db.flush()
        return a

    now = datetime.utcnow()
    created = 0

    # ── write ALL paths + JS source files back to asset app-structure fields ──
    # Group by hostname so we only flush each asset once.
    from collections import defaultdict
    _by_host_endpoints: dict = defaultdict(set)
    _by_host_params: dict = defaultdict(set)
    _by_host_js: dict = defaultdict(set)

    for p in result.paths:
        hostname = urlparse(p.source_js).netloc or p.source_js
        _by_host_endpoints[hostname].add(p.url[:500])
        _by_host_js[hostname].add(p.source_js[:500])
        for param in p.query_params + p.body_params:
            _by_host_params[hostname].add(str(param))

    for hostname in set(list(_by_host_endpoints) + list(_by_host_js)):
        a = _get_or_create_asset(hostname)
        if _by_host_endpoints[hostname]:
            existing_eps = list(a.endpoints or [])
            merged = list(dict.fromkeys(existing_eps + sorted(_by_host_endpoints[hostname])))[:2000]
            a.endpoints = merged
        if _by_host_js[hostname]:
            existing_js = list(a.js_files or [])
            merged_js = list(dict.fromkeys(existing_js + sorted(_by_host_js[hostname])))[:1000]
            a.js_files = merged_js
        if _by_host_params[hostname]:
            existing_params = list(a.parameters or [])
            merged_params = list(dict.fromkeys(existing_params + sorted(_by_host_params[hostname])))[:1000]
            a.parameters = merged_params

    # ── paths with parameters → Vulnerability rows ─────────────────────────
    for p in result.paths:
        if not (p.query_params or p.body_params):
            continue  # no params = app-structure only, no vuln row needed

        hostname = urlparse(p.source_js).netloc or p.source_js
        asset = _get_or_create_asset(hostname)

        template_id = f"jsluice-path-{_slug(p.method)}-{_hash12(p.url)}"
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == template_id,
            )
            .first()
        )

        all_params = p.query_params + p.body_params
        meta = {
            "url": p.url,
            "method": p.method,
            "query_params": p.query_params,
            "body_params": p.body_params,
            "url_type": p.url_type,
            "source_js": p.source_js,
        }

        if existing:
            existing.metadata_ = meta
            existing.last_detected = now
            existing.status = VulnerabilityStatus.OPEN
            continue

        param_preview = ", ".join(all_params[:8])
        vuln = Vulnerability(
            title=f"JS Endpoint: {p.method} {p.url[:120]}",
            description=(
                f"jsluice discovered the endpoint `{p.method} {p.url}` inside "
                f"`{p.source_js}`.\n\n"
                f"**Query parameters:** {', '.join(p.query_params) or 'none'}\n"
                f"**Body parameters:** {', '.join(p.body_params) or 'none'}\n\n"
                f"These parameters may be attack surface for injection, IDOR, "
                f"or business-logic abuse."
            )[:4000],
            severity=Severity.INFO,
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="jsluice",
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            evidence=f"Source file: {p.source_js}  |  params: {param_preview}",
            tags=["jsluice", "js-endpoint", p.method.lower()],
            metadata_=meta,
            remediation=(
                "Review these endpoint parameters for injection, IDOR, or "
                "business-logic vulnerabilities. Ensure proper input validation "
                "and authorization checks are enforced server-side."
            ),
            last_detected=now,
        )
        db.add(vuln)
        created += 1

    # ── secrets ───────────────────────────────────────────────────────────
    for s in result.secrets:
        hostname = urlparse(s.source_js).netloc or s.source_js
        asset = _get_or_create_asset(hostname)

        val = (
            s.data.get("match")
            or s.data.get("key")
            or s.data.get("value")
            or s.source_js
        )
        template_id = f"jsluice-secret-{_slug(s.kind)}-{_hash12(val)}"
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == template_id,
            )
            .first()
        )

        if existing:
            existing.last_detected = now
            existing.status = VulnerabilityStatus.OPEN
            continue

        vuln = Vulnerability(
            title=f"JS Secret: {s.kind}",
            description=(
                f"jsluice detected a `{s.kind}` credential in `{s.source_js}`.\n\n"
                f"Secrets shipped to browsers are retrievable by any visitor "
                f"and should be treated as compromised."
            )[:4000],
            severity=_sev.get(s.severity, Severity.HIGH),
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="jsluice",
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            evidence=json.dumps(s.data)[:2000],
            tags=["jsluice", "secret", s.kind],
            metadata_={"kind": s.kind, "data": s.data, "source_js": s.source_js},
            remediation=(
                "Rotate the leaked credential immediately. Remove it from the "
                "browser bundle and move secrets to a server-side proxy so the "
                "browser never receives raw credentials."
            ),
            last_detected=now,
        )
        db.add(vuln)
        created += 1

    db.commit()
    return created
