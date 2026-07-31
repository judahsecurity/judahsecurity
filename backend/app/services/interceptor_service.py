"""
Interceptor Service — harness entrypoint for the `execute_interceptor` tool.

The real Hacker-Valley-Media/Interceptor CLI is an *agent-driven browser
controller* (verbs: open/read/act/net log/...). It has **no built-in crawler**,
and it only runs where a real Chrome/Brave + the loaded Interceptor extension
exist — i.e. an operator's desktop, **not** a headless Linux/Ubuntu server.

So this service does the environment-correct thing:

    * If the `interceptor` binary is reachable on this host (operator desktop, or
      a workstation running the agent), it drives the REAL Interceptor through the
      interaction-first crawl in ``interceptor_recon`` — real cookies, real
      logged-in session, non-CDP synthetic input that beats anti-automation.

    * Otherwise (the common case for the containerised harness on Linux), it
      transparently falls back to the Playwright ``deep_crawl`` engine, which is
      hardened to crawl "like a normal user" and runs anywhere the images do.

Either way the agent gets an interaction-first recon result in one envelope.

Config (env):
    INTERCEPTOR_BIN          — path to the interceptor binary (default: PATH lookup)
    INTERCEPTOR_CMD_TIMEOUT  — per-verb timeout seconds (default: 45)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _parse_args(args: Any) -> Dict[str, Any]:
    """Accept a bare URL string or a JSON object of options."""
    if isinstance(args, dict):
        return args
    s = str(args or "").strip()
    if not s:
        return {}
    if s.startswith("{"):
        try:
            return json.loads(s)
        except (json.JSONDecodeError, TypeError):
            return {"url": s}
    # Bare URL / host, possibly with trailing flags we ignore for the driver.
    return {"url": s.split()[0]}


async def run_interceptor(args: Any) -> Dict[str, Any]:
    """
    Run interaction-first recon: real Interceptor when reachable, else deep_crawl.

    Returns the ASM tool envelope: {success, output, error, exit_code}.
    """
    opts = _parse_args(args)
    url = str(opts.get("url") or opts.get("target") or "").strip()
    if not url:
        return {
            "success": False,
            "output": 'No target. Pass a URL, e.g. execute_interceptor(args="https://target.com").',
            "error": "no_target",
            "exit_code": 1,
        }

    # Try the real Interceptor first (only succeeds where a browser + extension live).
    try:
        from app.services.interceptor_recon import (
            resolve_bin,
            run_recon,
            format_output,
            to_normalized_dict,
        )

        if resolve_bin():
            result = await run_recon(url, opts)
            if result.pages_visited:
                return {
                    "success": True,
                    "output": format_output(result),
                    "error": "; ".join(result.errors[:3]) or None,
                    "exit_code": 0,
                    "normalized": to_normalized_dict(result),
                }
            reason = (
                "Interceptor binary is present but produced no pages "
                f"({'; '.join(result.errors[:2]) or 'daemon/extension not reachable'}). "
                "Falling back to deep_crawl."
            )
        else:
            reason = (
                "The real Interceptor CLI is not installed/reachable on this host "
                "(it needs a real Chrome/Brave + loaded extension and does not run in a "
                "headless container). Falling back to the deep_crawl engine — this is "
                "expected on a Linux server. To use the real tool, run the standalone "
                "driver on your desktop: python -m app.services.interceptor_recon <url>."
            )
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("interceptor_recon unavailable: %s", e)
        reason = f"Interceptor driver error ({e}); falling back to deep_crawl."

    return await _fallback(opts, reason)


async def _fallback(opts: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """Run the hardened Playwright deep_crawl and prefix an explanatory note."""
    try:
        from app.services.deep_crawl_service import run_deep_crawl
    except Exception as e:
        return {
            "success": False,
            "output": reason + f"\n\n(deep_crawl fallback also unavailable: {e})",
            "error": "interceptor_unavailable",
            "exit_code": -1,
        }

    # Pass the URL plus any authenticated-session options straight through so the
    # fallback can also crawl "like a normal user" / logged in.
    result = await run_deep_crawl(opts)
    note = f"[NOTE] {reason}\n\n"
    result["output"] = note + (result.get("output") or "")
    return result
