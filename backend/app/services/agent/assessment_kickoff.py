"""
Fast assessment kickoff — give the agent early signal before the long crawl.

When the user pastes a URL, we immediately:
  1. Probe reachability / status / title (httpx-ish via aiohttp or httpx)
  2. Fetch robots.txt + sitemap.xml (bounded)
  3. Probe a tiny set of high-value paths (login, reset, admin, swagger, .git)

This runs in seconds, emits thinking heartbeats, and injects a compact brief
into agent state so the LLM is not planning blind while Interceptor starts.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional
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


def _normalize_base(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if not u.startswith("http"):
        u = f"https://{u}"
    parsed = urlparse(u)
    return f"{parsed.scheme}://{parsed.netloc}"


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
) -> Dict[str, Any]:
    try:
        resp = await client.get(url, follow_redirects=True, timeout=timeout)
        text = ""
        try:
            text = (resp.text or "")[:2000]
        except Exception:
            text = ""
        title = ""
        m = re.search(r"<title[^>]*>([^<]{1,120})</title>", text, re.I)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
        return {
            "url": str(resp.url),
            "status": int(resp.status_code),
            "title": title,
            "bytes": len(text),
            "snippet": re.sub(r"\s+", " ", text)[:180] if text else "",
        }
    except Exception as e:
        return {"url": url, "status": 0, "error": str(e)[:120]}


async def run_assessment_kickoff(seed_url: str) -> Dict[str, Any]:
    """
    Fast parallel probes. Always returns a dict with ``brief`` for the LLM.
    Soft-fails — never raises into the agent loop.
    """
    base = _normalize_base(seed_url)
    if not base:
        return {"success": False, "brief": "", "hits": []}

    await _emit(f"Kickoff: probing {base} (status, robots, key paths)…")

    hits: List[Dict[str, Any]] = []
    try:
        import httpx
    except ImportError:
        return {
            "success": False,
            "brief": f"Kickoff skipped (httpx unavailable). Seed: {base}",
            "hits": [],
        }

    try:
        async with httpx.AsyncClient(
            verify=False,
            headers={"User-Agent": "JudahASM-Kickoff/1.0"},
        ) as client:
            root = await _fetch(client, base + "/")
            hits.append({"kind": "root", **root})

            async def _one(path: str) -> Dict[str, Any]:
                return {"kind": "path", "path": path, **(await _fetch(client, urljoin(base + "/", path)))}

            path_results = await asyncio.gather(*[_one(p) for p in _QUICK_PATHS])
            for r in path_results:
                st = r.get("status") or 0
                # Keep interesting statuses only
                if st in (200, 201, 204, 301, 302, 307, 308, 401, 403) or (
                    r.get("path") in ("robots.txt", "sitemap.xml") and st and st < 500
                ):
                    hits.append(r)
    except Exception as e:
        logger.warning("assessment kickoff failed: %s", e)
        return {
            "success": False,
            "brief": f"Kickoff probe error for {base}: {e}",
            "hits": [],
        }

    lines = [
        f"KICKOFF RECON (fast — before Interceptor crawl) for {base}:",
        f"  Root: status={hits[0].get('status') if hits else '?'} title={hits[0].get('title') if hits else ''}",
    ]
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

    lines.append(
        "NEXT: execute_interceptor (attaches to early-queued crawl if workers were online) → "
        "bounded feroxbuster (/opt/wordlists/app-dirs-common.txt) → ingest_urls_into_map → "
        "sync_engagement_brain."
    )
    brief = "\n".join(lines)
    await _emit(f"Kickoff done — {len(interesting)} interesting paths; start Interceptor next.")
    return {"success": True, "brief": brief, "hits": hits, "base": base}
