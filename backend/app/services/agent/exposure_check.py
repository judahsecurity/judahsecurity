"""Deterministic check for sensitive content reachable without logging in.

AntiFox's worker prompt treats an unauthenticated admin/debug interface, API
schema, config, backup or credential file as a finding in its own right.
Prowl only reported these if the model happened to notice one. This module
makes it structural:

- A short list of well-known paths (git metadata, .env, API schemas, Spring
  actuator, server-status, phpinfo, cloud credentials, pprof) is requested
  once per origin with an anonymous GET that follows no redirects, through the
  normal tool path (scope, method policy, request ceiling, evidence store).
  Paths the crawl or enrichment already found that look like one of these are
  checked too.
- A hit needs status 200 and a content signature specific to that file, so a
  "not found" page served with 200 does not count.
- Each hit is submitted as an ``exposure`` candidate citing the recorded
  anonymous GET and a literal of at least 12 characters from the body, which
  is exactly what the ``response_match`` proof requires. The independent
  verifier still decides.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 512 * 1024
MAX_MAP_PATHS = 10


@dataclass(frozen=True)
class ExposureCheck:
    key: str
    path: str
    title: str
    severity: str
    impact: str
    marker: Callable[[str], Optional[str]]
    path_re: str = ""


def _search(pattern: str, flags: int = 0) -> Callable[[str], Optional[str]]:
    rx = re.compile(pattern, flags)

    def find(body: str) -> Optional[str]:
        match = rx.search(body or "")
        if not match:
            return None
        text = match.group(0)
        return text if len(text.strip()) >= 12 else None
    return find


def _not_html(find: Callable[[str], Optional[str]]) -> Callable[[str], Optional[str]]:
    def wrapped(body: str) -> Optional[str]:
        head = (body or "").lstrip()[:200].lower()
        if head.startswith("<!doctype") or head.startswith("<html"):
            return None
        return find(body)
    return wrapped


def _env_marker(body: str) -> Optional[str]:
    head = (body or "").lstrip()
    if head[:1] == "<":
        return None
    keys = re.findall(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,63})=", body or "")
    if len(keys) < 2:
        return None
    # Quote a key name, not a secret value, whenever a key is long enough.
    for key in sorted(set(keys), key=len, reverse=True):
        if len(key) + 1 >= 12:
            return f"{key}="
    match = re.search(r"(?m)^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,63}=.{0,24}", body or "")
    text = (match.group(0).strip() if match else "")[:24]
    return text if len(text) >= 12 else None


def _api_schema_marker(body: str) -> Optional[str]:
    if '"paths"' not in (body or "") and "paths:" not in (body or ""):
        return None
    return _search(r'"(?:openapi|swagger)"\s*:\s*"[0-9][^"]{0,20}"')(body)


CHECKS: List[ExposureCheck] = [
    ExposureCheck("git_config", "/.git/config", "Git repository metadata exposed",
                  "medium", "The .git directory is served, so source code and history "
                  "can usually be reconstructed.",
                  _not_html(_search(r"repositoryformatversion\s*=\s*\d")),
                  r"/\.git(/|$)"),
    ExposureCheck("dotenv", "/.env", "Environment file exposed", "high",
                  "An .env file is served; these usually hold database, API and "
                  "signing secrets.", _env_marker, r"/\.env(\.[a-z]+)?$"),
    ExposureCheck("openapi", "/openapi.json", "API schema exposed without authentication",
                  "low", "The full API schema is public, mapping every operation for an "
                  "attacker.", _not_html(_api_schema_marker),
                  r"/(openapi|swagger)(\.json|\.yaml)?$|/api-docs"),
    ExposureCheck("swagger", "/swagger.json", "API schema exposed without authentication",
                  "low", "The full API schema is public, mapping every operation for an "
                  "attacker.", _not_html(_api_schema_marker)),
    ExposureCheck("api_docs_v2", "/v2/api-docs", "API schema exposed without authentication",
                  "low", "The full API schema is public, mapping every operation for an "
                  "attacker.", _not_html(_api_schema_marker)),
    ExposureCheck("api_docs_v3", "/v3/api-docs", "API schema exposed without authentication",
                  "low", "The full API schema is public, mapping every operation for an "
                  "attacker.", _not_html(_api_schema_marker)),
    ExposureCheck("actuator_env", "/actuator/env", "Spring Boot actuator environment exposed",
                  "high", "The actuator env endpoint lists configuration properties, "
                  "often including credentials.",
                  _not_html(_search(r'"(?:propertySources|activeProfiles)"\s*:')),
                  r"/actuator(/|$)"),
    ExposureCheck("actuator", "/actuator", "Spring Boot actuator index exposed", "low",
                  "Actuator management endpoints are reachable without logging in.",
                  _not_html(_search(r'"href"\s*:\s*"[^"]*/actuator[^"]*"'))),
    ExposureCheck("server_status", "/server-status", "Apache server-status exposed", "medium",
                  "Live server status shows client addresses and requested URLs, "
                  "including other users' query strings.",
                  _search(r"Apache Server Status for [^<\n]{1,80}"), r"/server-status$"),
    ExposureCheck("phpinfo", "/phpinfo.php", "phpinfo() page exposed", "medium",
                  "phpinfo() discloses the PHP build, modules, paths and environment.",
                  _search(r"PHP Version [0-9]+\.[0-9]+\.[0-9]+"), r"/(php)?info\.php$"),
    ExposureCheck("aws_credentials", "/.aws/credentials", "AWS credentials file exposed",
                  "high", "An AWS shared credentials file is served.",
                  _not_html(_search(r"aws_access_key_id\s*=")), r"/\.aws/"),
    ExposureCheck("pprof", "/debug/pprof/", "Go pprof debug endpoint exposed", "medium",
                  "The Go profiler is reachable; it leaks internals and can be used "
                  "to exhaust the service.",
                  _search(r"Types of profiles available"), r"/debug/pprof"),
]


def _origin(target: str) -> str:
    parts = urlsplit(target if "://" in target else f"https://{target}")
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""


def map_paths(capability_map: Any) -> List[str]:
    """Already-discovered URLs (crawl, enrichment) that look like a known exposure."""
    cmap = capability_map if isinstance(capability_map, dict) else {}
    seen: List[str] = []
    candidates: List[str] = []
    for row in cmap.get("discovered_links") or []:
        if isinstance(row, dict) and row.get("url"):
            candidates.append(str(row["url"]))
    candidates += [str(p) for p in cmap.get("pages_visited") or []]
    candidates += [str(e.get("path") or "") for e in cmap.get("api_endpoints") or []
                   if isinstance(e, dict)]
    for raw in candidates:
        path = urlsplit(raw).path or ""
        if not path or path in seen:
            continue
        if any(check.path_re and re.search(check.path_re, path, re.I) for check in CHECKS):
            seen.append(path)
        if len(seen) >= MAX_MAP_PATHS:
            break
    return seen


def checks_for_path(path: str) -> List[ExposureCheck]:
    exact = [c for c in CHECKS if c.path == path]
    if exact:
        return exact
    return [c for c in CHECKS if c.path_re and re.search(c.path_re, path, re.I)]


async def run_exposure_checks(manager: Any, target: str,
                              capability_map: Any = None) -> Dict[str, Any]:
    """Request each known path once, submit a candidate per signature hit."""
    origin = _origin(target)
    if not origin:
        return {"success": False, "error": "no_target", "hits": [], "checked": 0}
    plan: List[tuple] = [(c.path, [c]) for c in CHECKS]
    known = {c.path for c in CHECKS}
    for path in map_paths(capability_map):
        if path not in known:
            plan.append((path, checks_for_path(path)))
            known.add(path)

    hits: List[Dict[str, Any]] = []
    errors: List[str] = []
    checked = 0
    for path, checks in plan:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            # map_traffic=False: a 404 on /.env is not part of the application,
            # and mapping it planned a coverage check for every probed path.
            result = await manager._http_exchange(
                "GET", url, use_auth_session=False, follow_redirects=False,
                timeout=15, max_response_bytes=MAX_BODY_BYTES, map_traffic=False)
        except Exception as exc:  # scope, budget, oversized body, network
            message = str(exc)[:120]
            errors.append(f"{path}: {type(exc).__name__}: {message}")
            if "budget" in message.lower() or "ceiling" in message.lower():
                break
            continue
        checked += 1
        status = int((result.get("response") or {}).get("status") or 0)
        body = str(result.get("_body_text") or "")
        if status != 200 or not body:
            continue
        for check in checks:
            marker = check.marker(body)
            if not marker:
                continue
            hit = {"key": check.key, "url": url, "title": check.title,
                   "severity": check.severity, "evidence_id": result.get("evidence_id"),
                   "contains": marker}
            hit["submission"] = await _submit(manager, check, url, hit)
            hits.append(hit)
            break
    return {"success": True, "checked": checked, "hits": hits, "errors": errors[:10],
            "origin": origin}


async def _submit(manager: Any, check: ExposureCheck, url: str, hit: Dict[str, Any]) -> str:
    import json

    if not hit.get("evidence_id"):
        return "no_evidence"
    try:
        response = await manager.submit_finding_candidate(
            title=f"{check.title}: {urlsplit(url).path}",
            description=(f"{check.impact} An anonymous GET with no cookies or "
                         f"credentials returned HTTP 200 and the response body contains "
                         f"\"{hit['contains']}\". Proof kind: response_match."),
            severity=check.severity, target=url,
            evidence=(f"Anonymous GET {url} -> 200; body contains {hit['contains']!r} "
                      f"(evidence {hit['evidence_id']})."),
            specialist="exposure_check", evidence_ids=[hit["evidence_id"]],
            vulnerability_class="exposure",
        )
    except Exception as exc:
        logger.exception("exposure candidate submission failed for %s", url)
        return f"error: {type(exc).__name__}"
    if isinstance(response, str):
        try:
            data = json.loads(response)
        except ValueError:
            return "submitted"
        if isinstance(data, dict) and data.get("error"):
            return f"error: {str(data['error'])[:120]}"
    return "submitted"


def format_result(result: Dict[str, Any]) -> str:
    if not result.get("success"):
        return f"Exposure check did not run: {result.get('error')}"
    lines = [f"Exposure check on {result.get('origin')}: {result['checked']} paths requested "
             f"anonymously, {len(result['hits'])} exposed."]
    for hit in result["hits"]:
        lines.append(f"- [{hit['severity']}] {hit['title']} at {hit['url']} "
                     f"(evidence {hit['evidence_id']}; candidate {hit['submission']})")
    if result.get("errors"):
        lines.append(f"Skipped: {'; '.join(result['errors'][:4])}")
    lines.append("Each hit is an exposure candidate; the independent verifier replays "
                 "the anonymous GET before anything is published.")
    return "\n".join(lines)
