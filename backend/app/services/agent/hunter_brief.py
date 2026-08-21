"""Notes-only specialist context — URL, param, hypothesis, next mutation.

Joshua and fireteam hunters must not receive raw httpx/nmap dumps. This is
the compact hunt brief (Haddix context engineering, Maestro-style fresh session).
"""

from __future__ import annotations

from typing import Any, Optional

MAX_BRIEF_CHARS = 1400


def format_hunter_brief(
    *,
    specialist: str = "",
    directive: Any = None,
    cmap: Optional[dict] = None,
    palace_snippet: str = "",
    oob_hint: bool = True,
) -> str:
    lines = [
        f"HUNT NOTES — {specialist or 'specialist'} (not a scan dump)",
    ]
    target = ""
    if directive is not None:
        target = str(getattr(directive, "target", "") or "")
        goal = str(getattr(directive, "goal", "") or "")[:220]
        assumption = str(getattr(directive, "assumption", "") or "")[:180]
        test = str(getattr(directive, "test", "") or "")[:280]
        rewrite = str(getattr(directive, "rewrite_note", "") or "")[:180]
        if target:
            lines.append(f"- URL: {target}")
        if goal:
            lines.append(f"- Hypothesis: {goal}")
        if assumption:
            lines.append(f"- Assumption: {assumption}")
        if test:
            lines.append(f"- Next mutation: {test}")
        if rewrite:
            lines.append(f"- Rewrite: {rewrite}")
        hyps = list(getattr(directive, "hypothesis_ids", None) or [])[:4]
        if hyps:
            lines.append(f"- Cards: {', '.join(str(h) for h in hyps)}")
    cmap = cmap if isinstance(cmap, dict) else {}
    samples = list(cmap.get("api_samples") or [])[:5]
    if samples:
        preview = []
        for s in samples:
            if not isinstance(s, dict):
                continue
            preview.append(
                f"{s.get('method') or 'GET'} {str(s.get('url') or '')[:80]}"
            )
        if preview:
            lines.append("- Captured: " + " | ".join(preview[:4]))
            lines.append(
                "- Mutate with mutate_captured_request(sample_index, location, field, value)"
            )
            lines.append("- fingerprint_api on captured samples if the stack is still unknown")
    js_files = cmap.get("js_files") or []
    if js_files:
        lines.append(
            "- JS: fetch_lazy_chunks then extract_js_endpoints on first-party bundles "
            f"({len(js_files)} mapped)"
        )
    if oob_hint:
        lines.append(
            "- SSRF/OOB: execute_interactsh register → plant payload_url "
            "(never 169.254.169.254 / localhost; Lictor blocks those). "
            "run_custom_probe may fetch Interactsh/OAST hosts."
        )
    palace = (palace_snippet or "").strip()
    if palace:
        # Keep a few diary lines, not the wake-up novel.
        clipped = []
        used = 0
        for row in palace.splitlines():
            row = row.strip()
            if not row or row.startswith("Joshua"):
                continue
            if used + len(row) > 400:
                break
            clipped.append(row[:180])
            used += len(row)
            if len(clipped) >= 4:
                break
        if clipped:
            lines.append("- Prior notes: " + " // ".join(clipped))
    brief = "\n".join(lines)
    return brief[:MAX_BRIEF_CHARS]


def format_executor_notes(summary: str, verdict: str, evidence: str, tools: list) -> str:
    """One-line handoff Joshua should store instead of tool stdout."""
    tools_s = ",".join(str(t) for t in (tools or [])[:6])
    ev = (evidence or "").replace("\n", " ")[:180]
    return (
        f"verdict={verdict or 'inconclusive'} tools={tools_s} "
        f"notes={(summary or '')[:200]} evidence={ev}"
    )
