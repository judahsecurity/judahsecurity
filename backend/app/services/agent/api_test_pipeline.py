"""/api-test pipeline — interceptor, then lazy-chunks ∥ fingerprint, then JS endpoints.

Judah mapping of the Claude Code slash command. No Codex, no Caido, no operator
Chrome. Concurrent step 2 is two tools in the same round, not Agent subagent_types.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

STEPS: List[Dict[str, Any]] = [
    {
        "id": "visit",
        "title": "Visit with interceptor",
        "tools": ["execute_interceptor"],
        "parallel": False,
        "report_before_next": True,
        "note": (
            "Open the target (Mac worker → Ubuntu → CLI → deep_crawl). Capture origin, "
            "js_files, publicPath hints, and XHR api_samples. Not the operator's Chrome."
        ),
    },
    {
        "id": "chunks_and_fingerprint",
        "title": "Download chunks AND fingerprint the API (concurrent)",
        "tools": ["fetch_lazy_chunks", "fingerprint_api"],
        "parallel": True,
        "report_before_next": True,
        "note": (
            "Same tool round: fetch_lazy_chunks(dry_run then download) using Step 1 base URL; "
            "fingerprint_api on the original target host (sibling API discovery). "
            "Fingerprint does not wait on chunks. Empty Caido is irrelevant — blocked/no-data "
            "only if Judah has no captured samples."
        ),
    },
    {
        "id": "extract",
        "title": "Extract endpoints from the JS",
        "tools": ["extract_js_endpoints"],
        "parallel": False,
        "report_before_next": True,
        "note": (
            "Mine bundle + fetched chunks. Triage /api, IDOR, SSRF/redirect. "
            "ingest_urls_into_map. Do not write all_endpoints.txt to disk — return the list."
        ),
    },
]


def looks_like_target(token: str) -> bool:
    t = (token or "").strip()
    if not t or t.startswith("-"):
        return False
    if t.startswith("http://") or t.startswith("https://"):
        return True
    if "://" in t:
        return False
    return "." in t and " " not in t


def pipeline_prompt(target: str) -> str:
    t = (target or "").strip() or "<TARGET URL REQUIRED — ask the user before any tool>"
    return (
        f"You are running /api-test against {t}. Authorized recon only.\n"
        "If the target is empty, stop and ask for the URL. Do not invent a host.\n\n"
        "Run these steps IN ORDER. Report each step's result before the next.\n\n"
        "Step 1 — execute_interceptor on the target (interact=true). Capture origin, "
        "js_files, and api_samples. Fallback execute_deep_crawl. Not the user's desktop browser.\n\n"
        "Step 2 — SAME tool round (concurrent, do not serialize):\n"
        "  2a. fetch_lazy_chunks(dry_run=true) then download, using Step 1 origin/publicPath.\n"
        "  2b. fingerprint_api with the original target string (sibling API hosts). "
        "If blocked/no-data, relay that and continue. Do not require Caido.\n"
        "Wait for both before Step 3.\n\n"
        "Step 3 — extract_js_endpoints on js_files + fetched chunk URLs, then "
        "ingest_urls_into_map.\n\n"
        "Final report: target visited, base URL, chunk ok/FAIL tally, fingerprint "
        "(host candidates + tech + coverage matrix), endpoint count, highest-value "
        "IDOR/SSRF/API leads. This skill maps surface; it does not prove vulns."
    )


def next_step(tools_already_run: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    ran = {str(t) for t in (tools_already_run or [])}
    for step in STEPS:
        if not set(step["tools"]).intersection(ran):
            return step
        # parallel step: both tools must have run
        if step.get("parallel") and not set(step["tools"]).issubset(ran):
            return step
    return None
