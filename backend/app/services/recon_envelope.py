"""Shared helpers to turn normalised recon into capability_map envelopes."""

from __future__ import annotations

from typing import Any, Dict, Optional


def envelope_from_normalized(
    normalized: Dict[str, Any],
    *,
    auth_session: Optional[Dict[str, Any]] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the agent tool envelope (capability_map + auth_session) from normalised recon."""
    from app.services.agent.capability_map import build_capability_map_from_crawl

    class _Crawl:
        pass

    crawl = _Crawl()
    crawl.target = normalized.get("target") or ""
    crawl.scope = normalized.get("scope") or ""
    crawl.pages_visited = list(normalized.get("pages_visited") or [])
    crawl.forms = list(normalized.get("forms") or [])
    crawl.js_files = set(normalized.get("js_files") or [])
    crawl.endpoints_from_js = set(normalized.get("endpoints_from_js") or [])
    crawl.websockets = set(normalized.get("websockets") or [])
    crawl.sse = set(normalized.get("sse") or [])
    crawl.source_maps = set(normalized.get("source_maps") or [])
    crawl.third_party = set(normalized.get("third_party") or [])
    crawl.api_calls = dict(normalized.get("api_calls") or {})
    crawl.api_samples = list(normalized.get("api_samples") or [])
    crawl.authenticated = normalized.get("authenticated")

    cmap = build_capability_map_from_crawl(crawl)
    cmap_dict = cmap.to_dict()

    lines = [
        f"Interceptor worker recon complete (engine={normalized.get('engine', 'interceptor')}).",
        f"Target: {crawl.target}  (scope: {crawl.scope})",
        f"Pages visited: {len(crawl.pages_visited)}",
        f"API hosts: {len(crawl.api_calls)}  JS files: {len(crawl.js_files)}",
        f"Capability map quality={cmap_dict.get('quality_score')} ready={cmap_dict.get('ready_for_attack')}",
    ]
    for p in crawl.pages_visited[:20]:
        lines.append(f"  - {p}")
    if note:
        lines.insert(0, f"[NOTE] {note}")

    sess = auth_session
    if sess is None and isinstance(normalized.get("auth_session"), dict):
        sess = normalized["auth_session"]
    if sess is None and normalized.get("storage_state"):
        cookies = (normalized.get("storage_state") or {}).get("cookies") or []
        sess = {
            "target": crawl.target,
            "scope": crawl.scope,
            "authenticated": crawl.authenticated,
            "storage_state": normalized.get("storage_state"),
            "cookies": cookies[:80],
            "cookie_names": [c.get("name") for c in cookies[:40] if isinstance(c, dict)],
        }

    return {
        "success": True,
        "output": "\n".join(lines),
        "error": "; ".join((normalized.get("errors") or [])[:3]) or None,
        "exit_code": 0,
        "normalized": normalized,
        "capability_map": cmap_dict,
        "auth_session": sess,
    }
