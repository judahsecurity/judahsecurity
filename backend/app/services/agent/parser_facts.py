"""Surface parsed scanner output to the model and record it as attack-graph facts.

The MCP server attaches ``result["parsed"]`` (asm_scanner_core.parsers) to
scanner tool results. Here the agent tool layer (1) prefixes a compact text
summary to the model-facing output, keeping the raw output after it, and
(2) records each observation as a ``parser`` fact on the engagement brain.

Facts are planning state, never proof: nothing here creates a finding.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_FACTS_PER_CALL = 20


def _host_of(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    parts = urlsplit(text if "://" in text else f"//{text}")
    return (parts.hostname or "").lower().rstrip(".")


def _in_scope(manager: Any, target: str) -> bool:
    """Targets outside a registered assessment scope are not recorded."""
    host = _host_of(target)
    if not host:
        return True
    try:
        from app.services.agent.assessment_scope import allowed_hosts, assert_url_in_scope

        if not allowed_hosts(manager):
            return True
        assert_url_in_scope(manager, f"https://{host}/")
        return True
    except ValueError:
        return False
    except Exception:
        logger.debug("parser fact scope check failed", exc_info=True)
        return False


def record_parser_facts(manager: Any, tool_name: str, parsed: Optional[Dict[str, Any]]) -> List[str]:
    """Record parsed observations as ``parser`` facts. Returns the fact ids."""
    if not isinstance(parsed, dict) or not parsed.get("observations"):
        return []
    from app.services.agent.planning_graph import LineageError, ensure_origin_fact, record_fact
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    brain = engagement_brain_from_dict(getattr(manager, "_engagement_brain", None))
    if not brain.target:
        brain.target = str(getattr(manager, "_fallback_target", "") or "")
    if not brain.target:
        return []
    tool = str(parsed.get("tool") or tool_name)
    origin = ensure_origin_fact(brain, brain.target)
    ids: List[str] = []
    for obs in parsed.get("observations")[:MAX_FACTS_PER_CALL]:
        if not isinstance(obs, dict):
            continue
        location = str(obs.get("target") or "")
        if not _in_scope(manager, location):
            continue
        fact_target = location if "://" in location else brain.target
        try:
            fact = record_fact(
                brain, kind="parser",
                summary=f"{tool} {obs.get('severity', 'info')} {obs.get('kind', '')}: {obs.get('title', '')}",
                target=fact_target, source=f"parser:{tool}", parents=[origin["id"]],
                key="|".join(str(obs.get(k) or "") for k in ("kind", "title", "target", "parameter")),
                data={
                    "tool": tool, "run_status": parsed.get("status"), "kind": obs.get("kind"),
                    "severity_hint": obs.get("severity"), "parameter": obs.get("parameter") or "",
                    "location": location, "detail": obs.get("detail") or "",
                    "attributes": obs.get("attributes") or {}, "planning_only": True,
                },
            )
        except (LineageError, ValueError):
            continue
        ids.append(fact["id"])
    manager._engagement_brain = brain.to_dict()
    return ids


def with_parsed_summary(manager: Any, tool_name: str, result: Dict[str, Any],
                        payload: Dict[str, Any], *, prefix: bool = True) -> Dict[str, Any]:
    """Attach ``parsed`` to the payload, add its text summary, record facts.

    Successful runs get the summary before the raw output (so truncation of
    long output never hides it); failed runs get it after the error text.
    """
    parsed = result.get("parsed") if isinstance(result, dict) else None
    if not isinstance(parsed, dict):
        return payload
    try:
        from asm_scanner_core.parsers import summary_text

        payload["parsed"] = parsed
        text = summary_text(parsed)
        if text:
            body = str(payload.get("output") or "")
            payload["output"] = f"{text}\n\n{body}" if prefix else f"{body}\n\n{text}"
    except Exception:
        logger.exception("Could not attach parsed summary for %s", tool_name)
    try:
        fact_ids = record_parser_facts(manager, tool_name, parsed)
        if fact_ids:
            payload["parser_fact_ids"] = fact_ids
    except Exception:
        logger.exception("Could not record parser facts for %s", tool_name)
    return payload
