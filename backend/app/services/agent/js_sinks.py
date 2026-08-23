"""DOM sink/source scan on first-party JS (JShero / jxscout regex layer).

Not the 1600-pattern secrets DB — Gitleaks covers secrets. This flags
eval / innerHTML / postMessage / location sinks for spa_client to prove.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

import httpx

MAX_URLS = 20
MAX_BYTES = 1_500_000
MAX_HITS_PER_KIND = 5

# High-signal only. Skip fetch/xhr/cookie — every SPA trips those.
SINK_PATTERNS = {
    "eval": r"\beval\s*\(|new\s+Function\s*\(",
    "innerHTML": r"\.(?:inner|outer)HTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(",
    "dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
    "postMessage-send": r"\.postMessage\s*\(",
    "message-listener": r"addEventListener\s*\(\s*[\"']message[\"']|\.onmessage\s*=",
    "location-sink": r"location\s*\.\s*(?:href|assign|replace)\s*[=(]|(?:window|document)\.location\s*=",
    "document.domain": r"document\.domain\s*=",
    "window.open": r"window\.open\s*\(",
}
_COMPILED = {k: re.compile(v) for k, v in SINK_PATTERNS.items()}


def scan_body(body: str, *, source: str = "") -> List[Dict[str, Any]]:
    text = body or ""
    hits: List[Dict[str, Any]] = []
    for kind, rx in _COMPILED.items():
        n = 0
        for m in rx.finditer(text):
            snippet = text[max(0, m.start() - 24) : m.start() + 72].replace("\n", " ").strip()
            hits.append({
                "type": kind,
                "source": source,
                "line": text.count("\n", 0, m.start()) + 1,
                "snippet": snippet[:160],
            })
            n += 1
            if n >= MAX_HITS_PER_KIND:
                break
    return hits


async def scan_js_sinks(
    urls: Iterable[str],
    *,
    origin_host: str = "",
    timeout: float = 12.0,
) -> Dict[str, Any]:
    urls = [u.strip() for u in urls if str(u).strip().startswith("http")][:MAX_URLS]
    if not urls:
        return {"ok": False, "error": "no https URLs"}
    origin_host = origin_host or (urlparse(urls[0]).hostname or "")
    sinks: List[Dict[str, Any]] = []
    analyzed = 0
    errors: List[str] = []
    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
        for url in urls:
            host = (urlparse(url).hostname or "").lower()
            if origin_host and host and host != origin_host.lower() and not host.endswith("." + origin_host.lower()):
                continue
            try:
                r = await client.get(url)
                sinks.extend(scan_body((r.text or "")[:MAX_BYTES], source=url))
                analyzed += 1
            except Exception as exc:
                errors.append(f"{url}: {exc}"[:180])
    by_type: Dict[str, int] = {}
    for row in sinks:
        by_type[row["type"]] = by_type.get(row["type"], 0) + 1
    return {
        "ok": True,
        "js_analyzed": analyzed,
        "sink_count": len(sinks),
        "sinks_by_type": by_type,
        "sinks": sinks[:80],
        "errors": errors[:8],
        "next": (
            "DOM XSS / postMessage / open-redirect leads for spa_client. "
            "Prove with mutate_captured_request or execute_browser — listing a sink is not a finding."
        ),
    }
