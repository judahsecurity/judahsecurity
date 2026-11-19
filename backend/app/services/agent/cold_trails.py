"""Cold trails: directions the agent keeps working without anything to show.

The orchestrator's repetition guard catches the same tool repeated in the last
few steps. A cold trail is broader and spans the whole run: one *direction*
(tool family + normalized endpoint + hypothesis/coverage cell) attempted
:data:`COLD_AFTER` or more times with no actionable output, no finding
candidate and no new evidence. Different payloads against the same endpoint
count as the same direction.

The planner sees a short "Cold trails" block listing them, so it moves on to
untested surface instead of spending budget re-walking a dead end. It is a
steer, not a block: new inputs on a cold trail are still allowed.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from typing import Any, Iterable, Optional

COLD_AFTER = 3
MAX_LISTED = 5
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
# Tools whose repetition is bookkeeping, not a testing direction.
_IGNORED = frozenset({
    "sync_engagement_brain", "get_engagement_brain", "get_methodology_progress",
    "lookup_methodology_procedure", "update_hypothesis", "save_note", "get_notes",
    "wait_recon_workers", "list_recon_workers", "read_evidence", "get_coverage",
    "store_memory", "search_memory", "search_knowledge_base", "log_engagement_approach",
})
_PRODUCTIVE_KEYS = ("actionable_findings", "candidate_id", "finding_id")


def _family(tool_name: str) -> str:
    name = tool_name.removeprefix("execute_")
    return name.removesuffix("_assigned")


def _first_url(args: Any) -> str:
    if isinstance(args, dict):
        for key in ("url", "target", "endpoint", "request_url"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    try:
        blob = json.dumps(args, default=str)
    except (TypeError, ValueError):
        blob = str(args)
    match = _URL_RE.search(blob)
    return match.group(0) if match else ""


def direction_key(step: dict) -> Optional[str]:
    tool = str(step.get("tool_name") or "")
    if not tool or tool in _IGNORED or tool.endswith("_help"):
        return None
    from app.services.agent.independent_verify import normalized_endpoint

    args = step.get("tool_args") or {}
    anchor = ""
    if isinstance(args, dict):
        anchor = str(args.get("coverage_cell_id") or args.get("hypothesis_id") or "")
    url = _first_url(args)
    endpoint = normalized_endpoint(url) if url else ""
    if not (anchor or endpoint):
        return None
    return "|".join(filter(None, (_family(tool), endpoint, anchor)))


def _productive(step: dict) -> bool:
    if any(step.get(key) for key in _PRODUCTIVE_KEYS):
        return True
    analysis = step.get("output_analysis")
    if isinstance(analysis, dict):
        return bool(analysis.get("actionable_findings") or analysis.get("vulnerabilities")
                    or analysis.get("findings"))
    return False


def cold_trails(trace: Optional[Iterable[Any]]) -> list[dict]:
    """Return cold directions, most-attempted first."""
    stats: "OrderedDict[str, dict]" = OrderedDict()
    for step in trace or []:
        if not isinstance(step, dict):
            continue
        key = direction_key(step)
        if not key:
            continue
        row = stats.setdefault(key, {"direction": key, "attempts": 0, "productive": False})
        row["attempts"] += 1
        if _productive(step):
            row["productive"] = True
    cold = [r for r in stats.values() if r["attempts"] >= COLD_AFTER and not r["productive"]]
    return sorted(cold, key=lambda r: -r["attempts"])


def format_cold_trails(trails: list[dict]) -> str:
    if not trails:
        return ""
    lines = "\n".join(
        f"- {t['direction']} — {t['attempts']} attempts, nothing actionable"
        for t in trails[:MAX_LISTED]
    )
    return (
        "\n\n## Cold trails — move on unless you have a genuinely new input\n"
        f"{lines}\n"
        "Record each as tested_clean or inconclusive (record_surface_coverage) and spend "
        "the next steps on untested coverage cells or hypotheses."
    )


__all__ = ["COLD_AFTER", "cold_trails", "direction_key", "format_cold_trails"]
