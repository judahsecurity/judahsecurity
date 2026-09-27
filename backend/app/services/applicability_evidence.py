"""Finding-scoped observations for Oracle's deterministic prerequisite checks.

Inventory identifies candidates. These observations establish runtime facts;
they never contain executable probes or an analyst-assigned OPES score.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def timestamp(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def evidence_deadline(oracle: Dict[str, Any]) -> Optional[datetime]:
    context = oracle.get("contextual_assessment") or {}
    deadlines = []
    for item in [*(context.get("preconditions") or []), *(context.get("transitions") or [])]:
        for observation in item.get("evidence") or []:
            deadline = timestamp(observation.get("valid_until"))
            if deadline:
                deadlines.append(deadline)
    return min(deadlines) if deadlines else None


def verification_checks(oracle: Dict[str, Any]) -> list[dict]:
    """Expose exact signal paths from vulnerability research, with collection instructions."""
    context = oracle.get("contextual_assessment") or {}
    evaluated = context.get("preconditions") or oracle.get("preconditions_evaluated") or []
    prerequisites = evaluated or [{"precondition": p} for p in oracle.get("preconditions") or []]
    checks = []
    for entry in prerequisites:
        p = entry.get("precondition") or {}
        path = p.get("verification_signal")
        if not path:
            continue
        checks.append({
            "id": p.get("id"), "signal_path": path,
            "description": p.get("description") or path,
            "method": p.get("verification_method") or f"Establish {path} from the deployed configuration.",
            "match_kind": p.get("match_kind"), "match_value": p.get("match_value"),
            "source_reference": p.get("source_reference"),
            "status": entry.get("status") or "unknown", "reason": entry.get("reason"),
            "evidence": entry.get("evidence") or [],
        })
    for entry in context.get("transitions") or []:
        transition = entry.get("transition") or {}
        for kind in ("access", "capability"):
            path = transition.get(f"{kind}_signal")
            if path and not any(c["signal_path"] == path for c in checks):
                checks.append({
                    "id": f"{transition.get('id')}.{kind}", "signal_path": path,
                    "description": transition.get(f"{kind}_required") or transition.get("description") or path,
                    "method": f"Verify {kind} for {transition.get('target') or 'the affected component'} using deployment or runtime evidence.",
                    "match_kind": "equals", "match_value": "true",
                    "status": entry.get(f"{kind}_status") or "unknown", "evidence": entry.get("evidence") or [],
                })
    return checks


def finding_observations(vuln: Any) -> dict:
    meta = vuln.metadata_ or {}
    saved = meta.get("applicability_evidence") or {}
    # Never carry observations across a relinked asset or changed CVE.
    if saved.get("asset_id") != vuln.asset_id or saved.get("cve_id") != (vuln.cve_id or ""):
        return {}
    return saved.get("signals") or {}


def oracle_asset_with_observations(vuln: Any, payload: Optional[dict]) -> Optional[dict]:
    if payload is not None:
        observations = finding_observations(vuln)
        if observations:
            payload.setdefault("signals", {})["observed_signals"] = observations
    return payload


def evidence_view(vuln: Any) -> dict:
    oracle = (vuln.metadata_ or {}).get("oracle") or {}
    deadline = evidence_deadline(oracle)
    expired = bool(deadline and deadline <= datetime.now(timezone.utc))
    context = oracle.get("contextual_assessment") or {}
    checks = verification_checks(oracle)
    if expired:
        for check in checks:
            check["status"] = "unknown"
            check["reason"] = "Evidence has expired; refresh the observation and rerun Oracle."
    return {
        "finding_id": vuln.id, "asset_id": vuln.asset_id, "cve_id": vuln.cve_id,
        "state": "needs_evidence" if expired else context.get("state", "needs_evidence"),
        "summary": "Evidence has expired; verification is required." if expired else context.get("summary"),
        "affected_component": context.get("affected_component"),
        "checks": checks, "observations": finding_observations(vuln),
        "valid_until": deadline.isoformat() if deadline else None,
        "analysis_status": oracle.get("analysis_status"),
    }


def invalidate_local_assessment(vuln: Any, reason: str) -> None:
    """Keep research and evidence, but withdraw conclusions awaiting reevaluation."""
    meta = dict(vuln.metadata_ or {})
    oracle = dict(meta.get("oracle") or {})
    context = dict(oracle.get("contextual_assessment") or {})
    context.update(state="needs_evidence", summary=reason)
    for key in ("preconditions", "paths", "transitions"):
        context[key] = [dict(item, status="unknown", reason=reason) for item in context.get(key) or []]
        if key == "transitions":
            context[key] = [dict(item, access_status="unknown", capability_status="unknown") for item in context[key]]
    oracle["contextual_assessment"] = context
    oracle["preconditions_evaluated"] = context.get("preconditions") or []
    oracle["analysis_status"] = "needs_evidence"
    oracle.pop("context_hash", None)
    oracle.pop("recommendation_text", None)
    for key in ("opes_score", "opes_category", "opes_label", "opes_confidence", "opes_components", "opes_top_contributors", "opes_override", "opes_dampener"):
        oracle.pop(key, None)
    for column in ("oracle_opes_score", "oracle_opes_category", "oracle_opes_label", "oracle_opes_confidence"):
        setattr(vuln, column, None)
    vuln.oracle_analysis_status = "needs_evidence"
    meta["oracle"] = oracle
    vuln.metadata_ = meta
    vuln.sev_dirty = True
