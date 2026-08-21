"""
Fast assessment kickoff — give the agent early signal before the long crawl.

When the user pastes a URL, we immediately:
  1. Probe reachability / status / title
  2. Fingerprint the homepage with local Wappalyzer + WhatRuns (both)
  3. Fetch robots.txt + sitemap.xml (bounded)
  4. Probe a tiny set of high-value paths (login, reset, admin, swagger, .git)

This runs in seconds, emits thinking heartbeats, and injects a compact brief
into agent state so the LLM is not planning blind while Interceptor starts.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

_QUICK_PATHS = (
    "robots.txt",
    "sitemap.xml",
    "login",
    "signin",
    "account/login",
    "password/reset",
    "forgot-password",
    "admin",
    "wp-admin",
    "swagger",
    "swagger.json",
    "openapi.json",
    "api/schema",
    ".git/config",
    ".well-known/security.txt",
)

_ROOT_BODY_LIMIT = 250_000
_PATH_BODY_LIMIT = 2_000
_WHATRUNS_TIMEOUT_SEC = 8.0
_EMPTY_SURFACE_RE = re.compile(
    r"\b(404|not found|doesn'?t exist|does not exist|page not found|cannot get)\b",
    re.I,
)


def root_needs_dir_brute(hits: Sequence[Dict[str, Any]]) -> bool:
    """404 / forbidden / empty root → directory brute-force is mandatory."""
    root = next((h for h in hits if h.get("kind") == "root"), hits[0] if hits else None)
    if not root:
        return False
    try:
        status = int(root.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    if status in (404, 403, 410):
        return True
    blob = f"{root.get('title') or ''} {root.get('snippet') or ''}"
    if _EMPTY_SURFACE_RE.search(blob):
        return True
    try:
        size = int(root.get("bytes") or 0)
    except (TypeError, ValueError):
        size = 0
    return bool(status == 200 and size < 180 and not (root.get("title") or "").strip())


def _normalize_base(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if not u.startswith("http"):
        u = f"https://{u}"
    parsed = urlparse(u)
    return f"{parsed.scheme}://{parsed.netloc}"


def _tech_label(name: str, version: Optional[str] = None) -> str:
    name = (name or "").strip()
    version = (version or "").strip()
    if version and version.lower() not in name.lower():
        return f"{name}:{version}"
    return name


def merge_tech_labels(
    wappalyzer: Sequence[Any],
    whatruns: Sequence[Any],
) -> List[str]:
    """Prefer versioned Wappalyzer labels; keep WhatRuns-only apps."""
    by_key: Dict[str, str] = {}
    for tech in wappalyzer or []:
        name = getattr(tech, "name", None) or (tech.get("name") if isinstance(tech, dict) else "")
        version = getattr(tech, "version", None) or (tech.get("version") if isinstance(tech, dict) else None)
        slug = (getattr(tech, "slug", None) or str(name).lower())
        if not name:
            continue
        by_key[str(slug).lower()] = _tech_label(str(name), version)
    for tech in whatruns or []:
        name = getattr(tech, "name", None) or (tech.get("name") if isinstance(tech, dict) else "")
        slug = (getattr(tech, "slug", None) or str(name).lower())
        if not name:
            continue
        key = str(slug).lower()
        if key not in by_key:
            by_key[key] = _tech_label(str(name))
    return sorted(by_key.values(), key=str.lower)


async def _emit(thought: str) -> None:
    try:
        from app.services.agent.orchestrator import _status_callback_var

        cb = _status_callback_var.get(None)
        if not cb:
            return
        maybe = cb({"type": "thinking", "phase": "informational", "thought": thought[:500]})
        if asyncio.iscoroutine(maybe):
            await maybe
    except Exception:
        pass


async def _fetch(
    client: Any,
    url: str,
    *,
    timeout: float = 8.0,
    body_limit: int = _PATH_BODY_LIMIT,
    keep_headers: bool = False,
) -> Dict[str, Any]:
    try:
        resp = await client.get(url, follow_redirects=True, timeout=timeout)
        text = ""
        try:
            text = (resp.text or "")[: max(0, int(body_limit))]
        except Exception:
            text = ""
        title = ""
        m = re.search(r"<title[^>]*>([^<]{1,120})</title>", text, re.I)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
        out: Dict[str, Any] = {
            "url": str(resp.url),
            "status": int(resp.status_code),
            "title": title,
            "bytes": len(text),
            "snippet": re.sub(r"\s+", " ", text)[:180] if text else "",
        }
        if keep_headers:
            out["body"] = text
            out["headers"] = {str(k).lower(): str(v) for k, v in resp.headers.items()}
            cookies: Dict[str, str] = {}
            try:
                cookies = {c.name: c.value for c in resp.cookies.jar}
            except Exception:
                try:
                    cookies = {k: str(v) for k, v in dict(resp.cookies).items()}
                except Exception:
                    cookies = {}
            out["cookies"] = cookies
        return out
    except Exception as e:
        return {"url": url, "status": 0, "error": str(e)[:120]}


async def _run_wappalyzer(base: str, root: Dict[str, Any]) -> List[Any]:
    try:
        from app.services.wappalyzer_service import get_wappalyzer_service

        svc = get_wappalyzer_service()
        html = root.get("body") or ""
        headers = root.get("headers") or {}
        cookies = root.get("cookies") or {}
        return await asyncio.to_thread(
            svc.analyze_page,
            base + "/",
            html,
            headers,
            cookies,
        )
    except Exception as e:
        logger.warning("kickoff Wappalyzer failed for %s: %s", base, e)
        return []


async def _run_whatruns(base: str) -> List[Any]:
    try:
        from app.services.whatruns_service import WhatRunsService

        host = urlparse(base).netloc
        svc = WhatRunsService(timeout=_WHATRUNS_TIMEOUT_SEC)
        return await asyncio.wait_for(
            svc.detect_technologies(host, base + "/"),
            timeout=_WHATRUNS_TIMEOUT_SEC,
        )
    except Exception as e:
        logger.warning("kickoff WhatRuns failed for %s: %s", base, e)
        return []


def _format_tech_line(label: str, techs: Sequence[Any], *, with_version: bool) -> str:
    names: List[str] = []
    for tech in techs or []:
        name = getattr(tech, "name", None) or (tech.get("name") if isinstance(tech, dict) else "")
        version = getattr(tech, "version", None) or (tech.get("version") if isinstance(tech, dict) else None)
        if not name:
            continue
        names.append(_tech_label(str(name), version if with_version else None))
    if not names:
        return f"  Tech ({label}): (none)"
    return f"  Tech ({label}): " + ", ".join(names[:24])


async def run_assessment_kickoff(seed_url: str) -> Dict[str, Any]:
    """
    Fast parallel probes. Always returns a dict with ``brief`` for the LLM.
    Soft-fails — never raises into the agent loop.
    """
    base = _normalize_base(seed_url)
    empty = {
        "success": False,
        "brief": "",
        "hits": [],
        "technologies": [],
        "tech_by_source": {"wappalyzer": [], "whatruns": []},
        "base": base,
    }
    if not base:
        return empty

    await _emit(f"Kickoff: probing {base} (status, robots, key paths, tech)…")

    hits: List[Dict[str, Any]] = []
    wapp_techs: List[Any] = []
    wr_techs: List[Any] = []
    try:
        import httpx
    except ImportError:
        return {
            **empty,
            "brief": f"Kickoff skipped (httpx unavailable). Seed: {base}",
        }

    try:
        async with httpx.AsyncClient(
            verify=False,
            headers={"User-Agent": "JudahASM-Kickoff/1.0"},
        ) as client:
            root = await _fetch(
                client,
                base + "/",
                body_limit=_ROOT_BODY_LIMIT,
                keep_headers=True,
            )
            hits.append({
                "kind": "root",
                "url": root.get("url"),
                "status": root.get("status"),
                "title": root.get("title"),
                "bytes": root.get("bytes"),
                "snippet": root.get("snippet"),
                "error": root.get("error"),
            })

            async def _one(path: str) -> Dict[str, Any]:
                return {
                    "kind": "path",
                    "path": path,
                    **(await _fetch(client, urljoin(base + "/", path))),
                }

            path_results, wapp_techs, wr_techs = await asyncio.gather(
                asyncio.gather(*[_one(p) for p in _QUICK_PATHS]),
                _run_wappalyzer(base, root),
                _run_whatruns(base),
            )
            for r in path_results:
                st = r.get("status") or 0
                if st in (200, 201, 204, 301, 302, 307, 308, 401, 403) or (
                    r.get("path") in ("robots.txt", "sitemap.xml") and st and st < 500
                ):
                    hits.append(r)
    except Exception as e:
        logger.warning("assessment kickoff failed: %s", e)
        return {
            **empty,
            "brief": f"Kickoff probe error for {base}: {e}",
        }

    technologies = merge_tech_labels(wapp_techs, wr_techs)
    tech_by_source = {
        "wappalyzer": [
            _tech_label(getattr(t, "name", ""), getattr(t, "version", None))
            for t in wapp_techs
            if getattr(t, "name", None)
        ],
        "whatruns": [
            _tech_label(getattr(t, "name", ""), getattr(t, "version", None))
            for t in wr_techs
            if getattr(t, "name", None)
        ],
    }

    lines = [
        f"KICKOFF RECON (fast — before Interceptor crawl) for {base}:",
        f"  Root: status={hits[0].get('status') if hits else '?'} title={hits[0].get('title') if hits else ''}",
        _format_tech_line("wappalyzer", wapp_techs, with_version=True),
        _format_tech_line("whatruns", wr_techs, with_version=False),
    ]
    blob = " ".join(technologies).lower()
    if "wordpress" in blob:
        lines.append(
            "  CMS: WordPress is in-play now — REST /wp-json/wp/v2/users and "
            "wp-admin hunts should run immediately; do not wait on WPScan."
        )
    interesting = [h for h in hits[1:] if (h.get("status") or 0) > 0]
    if interesting:
        lines.append("  Notable paths:")
        for h in interesting[:25]:
            path = h.get("path") or urlparse(h.get("url") or "").path
            lines.append(
                f"    [{h.get('status')}] /{path}"
                + (f" — {h.get('title')}" if h.get("title") else "")
            )
    else:
        lines.append("  No high-value paths from the quick list (still run Interceptor).")

    robots = next((h for h in hits if h.get("path") == "robots.txt" and h.get("status") == 200), None)
    if robots and robots.get("snippet"):
        lines.append(f"  robots.txt snippet: {robots['snippet'][:240]}")

    needs_dirs = root_needs_dir_brute(hits)
    root_status = hits[0].get("status") if hits else None
    if needs_dirs:
        lines.append(
            "  EMPTY/404 SURFACE: this is not 'no vulns'. Bounded directory brute-force "
            "(ferox/ffuf + app-dirs-common.txt) is mandatory, then parameter mining on "
            "anything that answers. Do not complete after fingerprinting."
        )
        lines.append(
            "NEXT: spawn_recon_workers(pack='enrich') is already starting (ferox+katana) → "
            "execute_interceptor/deep_crawl → ingest_urls_into_map → discover_parameters/"
            "arjun → sync_engagement_brain → fireteam_dispatch(specialists='auto')."
        )
    else:
        lines.append(
            "NEXT: execute_interceptor (attaches to early-queued crawl if workers were online) → "
            "spawn_recon_workers(pack='enrich') for ferox+katana → ingest_urls_into_map → "
            "discover_parameters on live URLs → sync_engagement_brain → "
            "fireteam_dispatch(specialists='auto'). Do not complete after recon."
        )
    brief = "\n".join(lines)
    await _emit(
        f"Kickoff done — {len(interesting)} interesting paths, "
        f"{len(technologies)} technologies; start Interceptor next."
    )
    return {
        "success": True,
        "brief": brief,
        "hits": hits,
        "base": base,
        "technologies": technologies,
        "tech_by_source": tech_by_source,
        "root_status": root_status,
        "needs_dir_brute": needs_dirs,
    }
