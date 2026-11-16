"""Per-org never-touch policy for agent tool calls.

Feeds ``aegis_praetorium.denylist`` from the org's Rules of Engagement row:

  - ``scope_out``      -> host rules (always enforced, even with RoE disabled)
  - ``deny_patterns``  -> regex rules over the tool's argument text
  - ``deny_dry_run``   -> org rules log "would block" instead of blocking
  - ``scope_in``       -> explicit authorization that lifts a built-in default
                          (e.g. a .gov customer), only once an RoE document has
                          been accepted and never for a bare suffix like "gov"

Also provides ``check_tool_call`` for the agent's ``ToolManager.execute``, which
covers the Python HTTP/browser tools that never pass through Lictor.
"""

from __future__ import annotations

import logging
import time
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional, Tuple

from aegis_praetorium.denylist import (
    DEFAULT_DENY_RULES,
    DenyPolicy,
    DenyRule,
    DenyVerdict,
    evaluate,
)

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 30.0
_cache: Dict[int, Tuple[float, DenyPolicy]] = {}
_cache_lock = Lock()

_DEFAULT_SUFFIXES = {r.pattern for r in DEFAULT_DENY_RULES}

# Tools that only read platform state, write notes, or plan. Their arguments can
# mention a host without sending it any traffic. Everything else is checked,
# including tools not listed here, so a new network tool is covered by default.
_EXEMPT_PREFIXES = (
    "query_", "get_", "search_", "save_", "store_", "list_", "record_", "sync_",
    "update_hypothesis", "update_threat_model", "build_threat_model", "assess_",
    "sanitize_", "lookup_", "log_", "add_engagement_", "queue_finding_",
    "compact_", "load_prior_",
)
_EXEMPT_TOOLS = frozenset({
    "create_finding", "submit_finding_candidate", "add_asset", "web_search",
    "vulnx_query", "check_cve_applicability", "read_evidence", "detect_bug_chains",
    "generate_injection_payloads", "plan_intruder_mutations", "analyze_attack_surface",
    "rank_attack_surface", "auto_select_tools", "fireteam_dispatch",
    "independent_verify", "wait_recon_workers", "mcp_list", "mcp_disconnect",
    "scoped_assessment_status", "scoped_assessment_plan", "scoped_assessment_memory",
    "scoped_assessment_summary", "complete_scoped_assessment",
    "register_test_identity", "fingerprint_passive_stack",
})


def is_exempt(tool_name: str) -> bool:
    name = tool_name or ""
    return name in _EXEMPT_TOOLS or name.endswith("_help") or name.startswith(_EXEMPT_PREFIXES)


def _allow_entry_is_specific(entry: str) -> bool:
    e = (entry or "").strip().lower().lstrip("*.").rstrip(".")
    return bool(e) and e not in _DEFAULT_SUFFIXES


def policy_from_roe(roe: Dict[str, Any]) -> DenyPolicy:
    rules: List[DenyRule] = []
    for host in roe.get("scope_out") or []:
        if str(host).strip():
            rules.append(DenyRule(kind="host", pattern=str(host).strip(),
                                  reason="Excluded by the org's Rules of Engagement.", source="org"))
    for pat in roe.get("deny_patterns") or []:
        if str(pat).strip():
            rules.append(DenyRule(kind="regex", pattern=str(pat),
                                  reason="Matches an org never-touch pattern.", source="org"))
    authorized = bool(roe.get("document_text")) and bool(roe.get("document_hash"))
    allow = tuple(
        str(h).strip() for h in (roe.get("scope_in") or [])
        if authorized and _allow_entry_is_specific(str(h))
    )
    return DenyPolicy(rules=tuple(rules), allow_hosts=allow, dry_run=bool(roe.get("deny_dry_run")))


class RoEDenyPolicyProvider:
    """Reads the org's RoE row, cached briefly per org."""

    def policy_for(self, org_id: Optional[int]) -> DenyPolicy:
        if org_id is None:
            return DenyPolicy()
        now = time.monotonic()
        with _cache_lock:
            hit = _cache.get(org_id)
            if hit and now - hit[0] < _CACHE_TTL_SECONDS:
                return hit[1]
        from app.db.database import SessionLocal
        from app.services import roe_service

        with SessionLocal() as db:
            policy = policy_from_roe(roe_service.load_roe(db, org_id))
        with _cache_lock:
            _cache[org_id] = (now, policy)
        return policy


def invalidate(org_id: Optional[int] = None) -> None:
    with _cache_lock:
        if org_id is None:
            _cache.clear()
        else:
            _cache.pop(org_id, None)


def _strings(value: Any, out: List[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out, depth + 1)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            _strings(v, out, depth + 1)


def argument_text(tool_args: Any) -> str:
    """All string values in a tool's arguments, newline-joined."""
    out: List[str] = []
    _strings(tool_args, out)
    return "\n".join(out)


def check_tool_call(tool_name: str, tool_args: Any, org_id: Optional[int]) -> DenyVerdict:
    """Denylist verdict for one agent tool call (exempt tools always pass)."""
    if is_exempt(tool_name):
        return DenyVerdict()
    return evaluate([argument_text(tool_args)], org_id=org_id)


def preview(texts: Iterable[str], roe: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate sample targets against a candidate RoE without saving it."""
    policy = policy_from_roe(roe)
    results = []
    for t in texts:
        v = evaluate([t], policy=policy)
        results.append({
            "target": t,
            "blocked": v.blocked,
            "matched_rule": v.rule.pattern if v.rule else None,
            "rule_source": v.rule.source if v.rule else None,
            "would_block": v.dry_run_hits,
        })
    return {"results": results}


__all__ = [
    "RoEDenyPolicyProvider",
    "argument_text",
    "check_tool_call",
    "invalidate",
    "is_exempt",
    "policy_from_roe",
    "preview",
]

