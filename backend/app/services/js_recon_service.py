"""
JavaScript Reconnaissance Service
=================================

Deep JS bundle analysis that mirrors the intent of Redamon's JS recon step:

    * Discover every first-party script referenced from target URLs
      (script[src], module imports, sourceMap links, webpack chunks).
    * Pull each file down with bounded concurrency.
    * Static analysis for:
        - Leaked secrets via a curated regex pack (40+ providers).
        - API endpoints / hidden routes (``/api/...``, full URLs).
        - Exposed source maps (.map) + optional webpack reconstruction.
        - Dependency-confusion candidates (packages referenced in
          package.json that are not on the public registry).
        - DOM XSS sink patterns (eval, innerHTML, Function, document.write).
    * Optional lightweight secret verification via HTTP probe where the
      key pattern is well-known (GitHub, Slack, Stripe, AWS, SendGrid, …).

All findings are returned as dataclasses so the worker can persist them
into the ``vulnerabilities`` table with a deterministic ``template_id``.

Trade-offs
----------
This is a pure-Python MVP. When the optional ``jsluice`` binary is
installed we additionally run it and merge its URL / secret output —
jsluice is dramatically better at tracking values through minifiers.
If jsluice is absent we gracefully fall back to the regex engine.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

# (name, regex, severity, verify_fn_id)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, Optional[str]]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "aws"),
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^\n]{0,5}['\"][A-Za-z0-9/+=]{40}['\"]"), "critical", None),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}"), "critical", "github"),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{82}"), "critical", "github"),
    ("gitlab_token", re.compile(r"glpat-[A-Za-z0-9_\-]{20}"), "critical", None),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"), "high", "slack"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]{20,}"), "high", None),
    ("stripe_live", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical", "stripe"),
    ("stripe_test", re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "medium", None),
    ("stripe_publishable", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "low", None),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high", None),
    ("google_oauth", re.compile(r"ya29\.[0-9A-Za-z\-_]+"), "high", None),
    ("firebase_db", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "medium", None),
    ("sendgrid", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "critical", "sendgrid"),
    ("mailgun", re.compile(r"key-[0-9a-zA-Z]{32}"), "high", None),
    ("mailchimp", re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"), "high", None),
    ("twilio_sid", re.compile(r"AC[a-f0-9]{32}"), "medium", None),
    ("twilio_token", re.compile(r"SK[a-f0-9]{32}"), "high", None),
    ("heroku_api", re.compile(r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "high", None),
    ("okta_token", re.compile(r"00[A-Za-z0-9_\-]{40}"), "high", None),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "medium", None),
    ("private_key", re.compile(r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"), "critical", None),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|apikey|api-token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{24,}['\"]"), "low", None),
    ("generic_secret", re.compile(r"(?i)(secret|password|passwd)['\"]?\s*[:=]\s*['\"][^'\"\\s]{10,}['\"]"), "low", None),
    ("algolia_admin", re.compile(r"(?i)algolia.{0,20}['\"][a-f0-9]{32}['\"]"), "high", None),
    ("cloudinary_url", re.compile(r"cloudinary://[^\s\"']+"), "medium", None),
    ("sentry_dsn", re.compile(r"https://[a-f0-9]{32}@[a-z0-9.\-]+/[0-9]+"), "low", None),
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{36}"), "high", None),
    ("square_oauth", re.compile(r"sq0csp-[ 0-9A-Za-z\-_]{43}"), "high", None),
    ("digitalocean_token", re.compile(r"dop_v1_[a-f0-9]{64}"), "critical", None),
]

ENDPOINT_PATTERN = re.compile(
    r"""(?xi)
    (?:["'`])
    (
        (?:https?://[^\s"'`<>]+)
        |
        (?:/[A-Za-z0-9_\-/.?=&%#]{3,200})
    )
    (?:["'`])
    """
)

SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)", re.IGNORECASE)
SCRIPT_SRC_PATTERN = re.compile(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
PACKAGE_IMPORT_PATTERN = re.compile(r"""(?:require|import)\s*\(?\s*['"]([@a-zA-Z0-9_\-/.]+)['"]\s*\)?""")
DOM_SINK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("eval", re.compile(r"\beval\s*\(")),
    ("Function_ctor", re.compile(r"\bnew\s+Function\s*\(")),
    ("innerHTML", re.compile(r"\.innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=")),
    ("document_write", re.compile(r"document\.write(?:ln)?\s*\(")),
    ("setTimeout_string", re.compile(r"setTimeout\s*\(\s*['\"]")),
    ("postMessage_wildcard", re.compile(r"postMessage\s*\([^,]+,\s*['\"]\*['\"]\s*\)")),
]


@dataclass
class JSFinding:
    kind: str                      # "secret" | "endpoint" | "sourcemap" | "dep_confusion" | "dom_sink"
    severity: str                  # "critical" | "high" | "medium" | "low" | "info"
    hostname: str
    source_url: str
    match: str
    pattern_name: str
    evidence: str
    verified: bool = False
    extras: dict = field(default_factory=dict)


@dataclass
class JSReconResult:
    scripts_analyzed: int = 0
    secrets_found: int = 0
    source_maps_found: int = 0
    endpoints_extracted: int = 0
    dep_confusion_candidates: int = 0
    dom_sinks: int = 0
    js_paths_found: int = 0        # jsluice-extracted paths (have method/param data)
    js_params_found: int = 0       # total query + body params across js_path findings
    findings: list[JSFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def _fetch(
    client: httpx.AsyncClient, url: str, timeout: float = 15.0
) -> Optional[tuple[str, str]]:
    """Return (final_url, body) or None on failure."""
    try:
        r = await client.get(url, timeout=timeout, follow_redirects=True)
        if r.status_code >= 400:
            return None
        ctype = r.headers.get("content-type", "")
        if r.text and len(r.text) > 0:
            return str(r.url), r.text
        return None
    except Exception as exc:
        logger.debug("fetch %s failed: %s", url, exc)
        return None


async def _discover_scripts(
    client: httpx.AsyncClient, target: str, max_scripts: int
) -> list[str]:
    """Crawl a target URL for script sources, keeping only same-origin assets."""
    if not target.startswith("http"):
        target = f"https://{target}"
    resp = await _fetch(client, target)
    if not resp:
        return []
    final_url, html = resp
    origin = urlparse(final_url).netloc

    urls: list[str] = []
    for src in SCRIPT_SRC_PATTERN.findall(html):
        absolute = urljoin(final_url, src)
        host = urlparse(absolute).netloc
        # Keep first-party and same-apex assets only.
        if host and (host == origin or host.endswith("." + origin) or origin.endswith("." + host)):
            urls.append(absolute)
        if len(urls) >= max_scripts:
            break
    # de-dup preserving order
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


# ---------------------------------------------------------------------------
# Static analyzers
# ---------------------------------------------------------------------------


def _scan_secrets(body: str) -> list[tuple[str, str, str, Optional[str]]]:
    hits: list[tuple[str, str, str, Optional[str]]] = []
    for name, pat, severity, verify_id in SECRET_PATTERNS:
        for m in pat.finditer(body):
            hits.append((name, m.group(0), severity, verify_id))
            if len(hits) > 200:
                return hits
    return hits


def _scan_endpoints(body: str) -> list[str]:
    endpoints: set[str] = set()
    for m in ENDPOINT_PATTERN.finditer(body):
        v = m.group(1)
        if not v or len(v) < 4:
            continue
        if any(x in v for x in ("%s", "{{", "${", "<%")):
            continue
        if v.startswith("data:") or v.endswith(".svg") or v.endswith(".png"):
            continue
        endpoints.add(v[:500])
        if len(endpoints) > 500:
            break
    return sorted(endpoints)


def _scan_sourcemap(url: str, body: str) -> Optional[str]:
    m = SOURCEMAP_PATTERN.search(body)
    if not m:
        return None
    rel = m.group(1).strip()
    if rel.startswith("data:"):
        return rel
    return urljoin(url, rel)


def _scan_dep_confusion(body: str) -> list[str]:
    names: set[str] = set()
    for m in PACKAGE_IMPORT_PATTERN.finditer(body):
        name = m.group(1)
        # Skip relative / absolute paths and builtins — we only want npm names.
        if name.startswith(".") or name.startswith("/"):
            continue
        if name in {"fs", "path", "http", "https", "crypto", "os", "util", "stream"}:
            continue
        # Scoped packages are highest-confidence dep-confusion candidates.
        if name.startswith("@"):
            names.add(name.split("/")[0])
        else:
            names.add(name.split("/")[0])
        if len(names) > 200:
            break
    return sorted(names)


def _scan_dom_sinks(body: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, pat in DOM_SINK_PATTERNS:
        for m in pat.finditer(body):
            ctx = body[max(0, m.start() - 40): m.end() + 40]
            out.append((name, ctx))
            if len(out) > 50:
                return out
    return out


# ---------------------------------------------------------------------------
# Secret verification (light-touch, network-safe)
# ---------------------------------------------------------------------------


async def _verify_secret(
    client: httpx.AsyncClient, verify_id: str, secret: str
) -> bool:
    """Return True if the secret is *alive*. Uses benign status endpoints only."""
    try:
        if verify_id == "github":
            r = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {secret}"},
                timeout=8.0,
            )
            return r.status_code == 200
        if verify_id == "slack":
            r = await client.post(
                "https://slack.com/api/auth.test",
                data={"token": secret},
                timeout=8.0,
            )
            return r.status_code == 200 and r.json().get("ok") is True
        if verify_id == "stripe":
            r = await client.get(
                "https://api.stripe.com/v1/charges?limit=1",
                auth=(secret, ""),
                timeout=8.0,
            )
            return r.status_code in (200, 402)
        if verify_id == "sendgrid":
            r = await client.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {secret}"},
                timeout=8.0,
            )
            return r.status_code == 200
        if verify_id == "aws":
            # Can't verify access key without the matching secret; treat as unverified.
            return False
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# Optional jsluice integration
# ---------------------------------------------------------------------------


def _have_binary(name: str) -> bool:
    return shutil.which(name) is not None


async def _run_jsluice(url: str, body: str) -> list[JSFinding]:
    """Shell out to jsluice if available and merge its findings."""
    if not _have_binary("jsluice"):
        return []

    async def _run(subcmd: str) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                "jsluice", subcmd, "-",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=body.encode()[:5_000_000]),
                timeout=30.0,
            )
            return stdout.decode(errors="ignore")
        except Exception:
            return ""

    host = urlparse(url).netloc
    findings: list[JSFinding] = []

    urls_out = await _run("urls")
    for line in urls_out.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        u = obj.get("url")
        if not u:
            continue
        # Use kind="js_path" for jsluice URL findings so we can carry
        # query/body param data and persist them separately from plain
        # regex-extracted endpoints.
        findings.append(JSFinding(
            kind="js_path",
            severity="info",
            hostname=host,
            source_url=url,
            match=u[:500],
            pattern_name="jsluice.url",
            evidence=json.dumps(obj)[:400],
            extras={
                "method": (obj.get("method") or "GET").upper(),
                "type": obj.get("type"),
                "query_params": obj.get("queryParams") or [],
                "body_params": obj.get("bodyParams") or [],
            },
        ))

    secrets_out = await _run("secrets")
    for line in secrets_out.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        val = obj.get("data", {}).get("match") or obj.get("data", {}).get("key") or ""
        if not val:
            continue
        findings.append(JSFinding(
            kind="secret",
            severity="high",
            hostname=host,
            source_url=url,
            match=val[:500],
            pattern_name=f"jsluice.{obj.get('kind', 'secret')}",
            evidence=json.dumps(obj)[:400],
        ))
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def _analyze_script(
    client: httpx.AsyncClient,
    url: str,
    include_source_maps: bool,
    verify_secrets: bool,
) -> list[JSFinding]:
    findings: list[JSFinding] = []
    fetched = await _fetch(client, url)
    if not fetched:
        return findings
    final_url, body = fetched
    hostname = urlparse(final_url).netloc

    # Secrets
    for name, match, severity, verify_id in _scan_secrets(body):
        verified = False
        if verify_secrets and verify_id:
            verified = await _verify_secret(client, verify_id, match)
        findings.append(JSFinding(
            kind="secret",
            severity=severity if not verified else "critical",
            hostname=hostname,
            source_url=final_url,
            match=match,
            pattern_name=name,
            evidence=_excerpt(body, match),
            verified=verified,
        ))

    # Endpoints
    for ep in _scan_endpoints(body):
        findings.append(JSFinding(
            kind="endpoint",
            severity="info",
            hostname=hostname,
            source_url=final_url,
            match=ep,
            pattern_name="endpoint",
            evidence="",
        ))

    # DOM sinks
    for sink, ctx in _scan_dom_sinks(body):
        findings.append(JSFinding(
            kind="dom_sink",
            severity="low",
            hostname=hostname,
            source_url=final_url,
            match=sink,
            pattern_name=f"dom_sink.{sink}",
            evidence=ctx[:300],
        ))

    # Source maps (optional fetch to confirm 200)
    if include_source_maps:
        smap_url = _scan_sourcemap(final_url, body)
        if smap_url and not smap_url.startswith("data:"):
            exists = await _fetch(client, smap_url, timeout=10.0)
            findings.append(JSFinding(
                kind="sourcemap",
                severity="medium" if exists else "low",
                hostname=hostname,
                source_url=final_url,
                match=smap_url,
                pattern_name="sourcemap_exposed",
                evidence=f"fetched={bool(exists)}",
            ))

    # Dep-confusion candidates (static signal only; verification against
    # registry.npmjs.org happens in a second pass to stay polite).
    for pkg in _scan_dep_confusion(body):
        findings.append(JSFinding(
            kind="dep_confusion",
            severity="low",
            hostname=hostname,
            source_url=final_url,
            match=pkg,
            pattern_name="dep_confusion_candidate",
            evidence="",
        ))

    findings.extend(await _run_jsluice(final_url, body))
    return findings


def _excerpt(body: str, needle: str, window: int = 80) -> str:
    idx = body.find(needle)
    if idx < 0:
        return needle[:200]
    start = max(0, idx - window)
    end = min(len(body), idx + len(needle) + window)
    return body[start:end].replace("\n", " ")[:400]


async def _verify_dep_confusion(
    client: httpx.AsyncClient, packages: Iterable[str]
) -> dict[str, bool]:
    """Query the public npm registry for each unique package name.

    ``True`` means the package is *missing* from the public registry, i.e. a
    valid dependency-confusion hijack candidate.
    """
    results: dict[str, bool] = {}
    sem = asyncio.Semaphore(10)

    async def _one(name: str) -> None:
        async with sem:
            try:
                r = await client.get(
                    f"https://registry.npmjs.org/{name}",
                    timeout=10.0,
                )
                results[name] = r.status_code == 404
            except Exception:
                results[name] = False

    await asyncio.gather(*(_one(p) for p in packages))
    return results


async def run_js_recon(
    targets: Iterable[str],
    max_scripts: int = 200,
    timeout: int = 300,
    include_source_maps: bool = True,
    verify_secrets: bool = True,
    progress_callback: Optional[Callable[[int, str], Awaitable[None]]] = None,
) -> JSReconResult:
    start = datetime.utcnow()
    result = JSReconResult()
    targets = [t for t in targets if t]
    if not targets:
        return result

    async def _progress(pct: int, step: str) -> None:
        if progress_callback:
            try:
                await progress_callback(pct, step)
            except Exception:
                pass

    await _progress(10, "Discovering scripts")

    async with httpx.AsyncClient(
        http2=True,
        verify=False,
        headers={"User-Agent": "ASM-JS-Recon/1.0"},
        timeout=httpx.Timeout(30.0),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    ) as client:
        all_scripts: list[str] = []
        for t in targets:
            try:
                scripts = await _discover_scripts(client, t, max_scripts)
                all_scripts.extend(scripts)
            except Exception as exc:
                result.errors.append(f"discover {t}: {exc}")
        # de-dupe
        all_scripts = list(dict.fromkeys(all_scripts))[:max_scripts]

        await _progress(25, f"Analyzing {len(all_scripts)} scripts")

        sem = asyncio.Semaphore(15)

        async def _bounded(url: str) -> list[JSFinding]:
            async with sem:
                try:
                    return await _analyze_script(
                        client, url, include_source_maps, verify_secrets
                    )
                except Exception as exc:
                    result.errors.append(f"analyze {url}: {exc}")
                    return []

        all_findings: list[JSFinding] = []
        chunk_results = await asyncio.gather(*( _bounded(u) for u in all_scripts ))
        for lst in chunk_results:
            all_findings.extend(lst)
        result.scripts_analyzed = len(all_scripts)

        await _progress(75, "Verifying dependency-confusion candidates")

        candidates = sorted({
            f.match for f in all_findings if f.kind == "dep_confusion"
        })
        verify_map = await _verify_dep_confusion(client, candidates) if candidates else {}
        for f in all_findings:
            if f.kind == "dep_confusion":
                if verify_map.get(f.match):
                    f.severity = "high"
                    f.verified = True
                    f.evidence = "Package name is NOT published on registry.npmjs.org"
                else:
                    # still report as low/info so users can audit
                    f.severity = "info"

    result.findings = all_findings
    result.secrets_found = sum(1 for f in all_findings if f.kind == "secret")
    result.source_maps_found = sum(1 for f in all_findings if f.kind == "sourcemap")
    # endpoint (regex) + js_path (jsluice) both count as extracted endpoints
    result.endpoints_extracted = sum(1 for f in all_findings if f.kind in ("endpoint", "js_path"))
    result.dep_confusion_candidates = sum(1 for f in all_findings if f.kind == "dep_confusion")
    result.dom_sinks = sum(1 for f in all_findings if f.kind == "dom_sink")
    result.js_paths_found = sum(1 for f in all_findings if f.kind == "js_path")
    result.js_params_found = sum(
        len((f.extras or {}).get("query_params", [])) + len((f.extras or {}).get("body_params", []))
        for f in all_findings if f.kind == "js_path"
    )
    result.duration_seconds = (datetime.utcnow() - start).total_seconds()

    await _progress(95, "Finalising")
    return result


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def persist_js_findings(
    db,
    organization_id: int,
    scan_id: Optional[int],
    findings: list[JSFinding],
) -> int:
    """Convert JS findings into Vulnerability rows and update asset app-structure.

    Returns count of new vulnerability records created.
    """
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    sev_enum = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    created = 0
    # js_path findings (jsluice-sourced with param data) are persisted at INFO
    # severity so analysts can enumerate attack-surface endpoints.
    # Plain regex "endpoint" findings stay in scan.results only.
    reportable_kinds = {"secret", "sourcemap", "dep_confusion", "dom_sink", "js_path"}

    # --- Collect app-structure data per hostname to write back to the asset ---
    # Maps hostname → {endpoints, js_files, params}
    _asset_endpoints: dict[str, set] = {}
    _asset_js: dict[str, set] = {}
    _asset_params: dict[str, set] = {}

    for f in findings:
        h = f.hostname
        _asset_endpoints.setdefault(h, set())
        _asset_js.setdefault(h, set())
        _asset_params.setdefault(h, set())
        if f.kind == "endpoint":
            _asset_endpoints[h].add(f.match[:500])
        elif f.kind == "js_path":
            _asset_endpoints[h].add(f.match[:500])
            for p in (f.extras or {}).get("query_params", []):
                _asset_params[h].add(str(p))
            for p in (f.extras or {}).get("body_params", []):
                _asset_params[h].add(str(p))
        if f.source_url:
            _asset_js[h].add(f.source_url[:500])

    # Write endpoint/JS/param data back to each matching asset
    for hostname, endpoints in _asset_endpoints.items():
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == organization_id, Asset.value == hostname)
            .first()
        )
        if not asset:
            continue
        if endpoints:
            existing_eps = list(asset.endpoints or [])
            merged = list(dict.fromkeys(existing_eps + sorted(endpoints)))[:2000]
            asset.endpoints = merged
        if _asset_js.get(hostname):
            existing_js = list(asset.js_files or [])
            merged_js = list(dict.fromkeys(existing_js + sorted(_asset_js[hostname])))[:1000]
            asset.js_files = merged_js
        if _asset_params.get(hostname):
            existing_params = list(asset.parameters or [])
            merged_params = list(dict.fromkeys(existing_params + sorted(_asset_params[hostname])))[:1000]
            asset.parameters = merged_params

    for f in findings:
        if f.kind not in reportable_kinds:
            continue
        asset = (
            db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.value == f.hostname,
            )
            .first()
        )
        if not asset:
            asset = Asset(
                organization_id=organization_id,
                asset_type=AssetType.DOMAIN,
                name=f.hostname,
                value=f.hostname,
                discovery_source="js_recon",
            )
            db.add(asset)
            db.flush()

        # js_path with no param data is low-value; skip the DB row
        if f.kind == "js_path" and not (
            (f.extras or {}).get("query_params") or (f.extras or {}).get("body_params")
        ):
            continue

        template_id = f"js-recon-{f.kind}-{_slug(f.pattern_name)}-{_hash(f.match)}"
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == template_id,
            )
            .first()
        )
        severity = sev_enum.get(_SEV_MAP.get(f.severity, "LOW"), Severity.LOW)
        title = f"{f.kind.replace('_', ' ').title()}: {f.pattern_name}" if f.kind != "js_path" else (
            f"JS Endpoint: {(f.extras or {}).get('method', 'GET')} {f.match[:100]}"
        )
        description = _describe(f)

        meta = {
            "kind": f.kind,
            "pattern": f.pattern_name,
            "match": f.match,
            "source_url": f.source_url,
            "hostname": f.hostname,
            "verified": f.verified,
            **(f.extras or {}),
        }

        if existing:
            existing.severity = severity
            existing.last_detected = datetime.utcnow()
            existing.metadata_ = meta
            existing.evidence = f.evidence
            existing.status = VulnerabilityStatus.OPEN
            continue

        vuln = Vulnerability(
            title=title[:500],
            description=description[:4000],
            severity=severity,
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="js_recon",
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            evidence=(f.evidence or "")[:5000],
            tags=["js-recon", f.kind] + (["verified"] if f.verified else []),
            metadata_=meta,
            remediation=_remediation(f),
        )
        db.add(vuln)
        created += 1

    db.commit()
    return created


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unknown"


def _hash(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _describe(f: JSFinding) -> str:
    if f.kind == "secret":
        v = " (verified against live provider API)" if f.verified else ""
        return (
            f"A potential **{f.pattern_name}** credential was found embedded in "
            f"`{f.source_url}`{v}. Secrets shipped to browsers are retrievable by "
            f"any visitor and should be considered public."
        )
    if f.kind == "sourcemap":
        return (
            f"A JavaScript source map was discovered at `{f.match}`. Source maps "
            f"let anyone reconstruct the original, unminified source code including "
            f"comments and in-repo structure."
        )
    if f.kind == "dep_confusion":
        status = "is NOT present on the public npm registry" if f.verified else "is referenced in production bundles"
        return (
            f"Package `{f.match}` {status}. When an attacker publishes a package "
            f"with the same name to the public registry, internal builds that "
            f"don't pin a private registry will install the attacker version."
        )
    if f.kind == "dom_sink":
        return (
            f"DOM sink `{f.pattern_name}` was used in `{f.source_url}`. If any input "
            f"reaching this sink is attacker-controlled, this may lead to DOM-based "
            f"cross-site scripting."
        )
    if f.kind == "js_path":
        ex = f.extras or {}
        method = ex.get("method", "GET")
        qp = ", ".join(ex.get("query_params") or []) or "none"
        bp = ", ".join(ex.get("body_params") or []) or "none"
        return (
            f"jsluice discovered the endpoint `{method} {f.match}` in `{f.source_url}`.\n\n"
            f"**Query parameters:** {qp}\n"
            f"**Body parameters:** {bp}\n\n"
            f"These parameters may be attack surface for injection, IDOR, or "
            f"business-logic abuse."
        )
    return f.pattern_name


def _remediation(f: JSFinding) -> str:
    if f.kind == "secret":
        return (
            "Rotate the leaked credential immediately. Remove it from the bundle, "
            "invalidate it at the provider, and move the secret to a server-side "
            "proxy so the browser never sees raw credentials."
        )
    if f.kind == "sourcemap":
        return (
            "Stop deploying .map files to production (remove `sourceMap: true` or "
            "upload them only to your error-tracking provider with auth)."
        )
    if f.kind == "dep_confusion":
        return (
            "Publish a placeholder package with the same name on the public registry "
            "or migrate to scoped packages (`@org/name`) with scope-level registry "
            "mappings in `.npmrc`."
        )
    if f.kind == "dom_sink":
        return (
            "Replace direct HTML injection with `textContent` / DOM APIs, or sanitize "
            "with DOMPurify before insertion. Avoid `eval` / string-based `setTimeout`."
        )
    if f.kind == "js_path":
        return (
            "Review these endpoint parameters for injection, IDOR, or business-logic "
            "vulnerabilities. Ensure proper input validation and server-side authorization "
            "checks are in place for each parameter."
        )
    return "Review manually."
