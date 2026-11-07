"""Bounded search of execution-owned traces from the current assessment run.

The action ledger stays metadata-only. Evidence payloads are searched in their
existing redacted store and never copied into the search response.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.agent_run_ledger import (
    AgentActionReceipt,
    AgentHypothesisCoverage,
    AgentRunLedger,
)

_TERMINAL_EVENTS = ("completed", "failed", "interrupted", "skipped")
_EXCLUDED_TOOLS = frozenset({
    "read_evidence", "search_assessment_traces", "independent_verify",
    "record_verify_verdict",
})


def search_assessment_traces(
    db: Session,
    evidence_store,
    *,
    run_id: str,
    organization_id: int,
    user_id: int,
    session_id: str,
    query: str,
    limit: int = 8,
) -> dict:
    """Return matching action receipts and inspectable IDs from one live run."""
    needle = str(query or "").strip().casefold()
    if len(needle) < 2 or len(needle) > 80:
        return {"error": "query must contain 2 to 80 characters"}
    try:
        limit = max(1, min(int(limit), 10))
    except (TypeError, ValueError):
        return {"error": "limit must be an integer from 1 to 10"}

    run = db.query(AgentRunLedger.id).filter(
        AgentRunLedger.id == run_id,
        AgentRunLedger.organization_id == organization_id,
        AgentRunLedger.user_id == user_id,
        AgentRunLedger.session_id == session_id,
    ).one_or_none()
    if run is None:
        return {"error": "assessment run not found"}

    coverage = db.query(AgentHypothesisCoverage).filter(
        AgentHypothesisCoverage.run_id == run_id,
    ).all()
    evidence_owner = {
        str(evidence_id): row
        for row in coverage
        for evidence_id in (row.evidence_ids or [])
    }
    receipts = db.query(AgentActionReceipt).filter(
        AgentActionReceipt.run_id == run_id,
        AgentActionReceipt.event.in_(_TERMINAL_EVENTS),
    ).order_by(AgentActionReceipt.id.desc()).limit(300).all()

    matches = []
    seen_actions = set()
    for receipt in receipts:
        if receipt.action_id in seen_actions or receipt.tool_name in _EXCLUDED_TOOLS:
            continue
        seen_actions.add(receipt.action_id)
        metadata = " ".join((receipt.tool_name, receipt.target, receipt.detail or ""))
        matched_in = "action" if needle in metadata.casefold() else ""
        available_ids = []
        matched_ids = []
        verifier_only = False
        owner = None
        for evidence_id in (receipt.evidence_ids or [])[:8]:
            view = evidence_store.search_view(str(evidence_id))
            if view is None:
                continue
            if view["verifier_run_id"]:
                verifier_only = True
                continue
            available_ids.append(str(evidence_id))
            owner = owner or evidence_owner.get(str(evidence_id))
            if needle in view["search_text"].casefold():
                matched_in = "evidence"
                matched_ids.append(str(evidence_id))
        if verifier_only and not available_ids:
            continue
        if not matched_in:
            continue
        matches.append({
            "action_id": receipt.action_id,
            "tool": receipt.tool_name,
            "status": receipt.event,
            "target_origin": receipt.target,
            "detail": receipt.detail or "",
            "evidence_ids": (matched_ids + [item for item in available_ids
                                             if item not in matched_ids])[:4],
            "hypothesis_id": owner.hypothesis_id if owner else "",
            "specialist": owner.specialist if owner else "",
            "matched_in": matched_in,
        })
        if len(matches) >= limit:
            break

    return {
        "results": matches,
        "count": len(matches),
        "note": "Prior traces are leads. Recheck relevant evidence and use fresh proof for findings.",
    }
