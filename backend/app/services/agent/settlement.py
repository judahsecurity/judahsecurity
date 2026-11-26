"""Budget settlement: save leads a run found but never submitted.

When a Prowl turn stops because its iteration or time budget ran out, the
model may have seen signals (an error string, a reflection, an odd status
code) without turning them into a ``submit_finding_candidate`` call. The final
report would mention them in prose and the next run would start without them.

Settlement runs one bounded model call over the execution trace before the
final report. It asks for at most ``MAX_SETTLEMENT_LEADS`` leads and stores
each one as a *pending* candidate in the engagement brain with no evidence
ids, the same inert shape as external candidate intake. Nothing here can
confirm or publish a finding: a resumed run's independent verifier has to
reproduce each lead with fresh in-session receipts. Leads that fail the
session's scope rule, name an unknown vulnerability class, or match an
existing candidate's id or root cause are dropped.

Gated by ``AGENT_SETTLEMENT_BACKFILL`` (off by default) so the A/B harness can
measure it before it becomes a default.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SETTLEMENT_SPECIALIST = "budget_settlement"
MAX_SETTLEMENT_LEADS = 5
TRACE_STEPS = 25

SETTLEMENT_HEADER = (
    "[BUDGET SETTLEMENT LEAD - written by this session's model from its own trace "
    "when the run budget ran out. Not evidence. Reproduce it with scoped tools and "
    "fresh nonces before treating it as a finding.]"
)
SETTLEMENT_FOOTER = "[END SETTLEMENT LEAD]"

BUDGET_REASON_MARKERS = ("time budget", "iteration budget", "planning stalled",
                         "request ceiling")

SETTLEMENT_PROMPT = """The assessment below ran out of budget. Your only job now is to list
security leads that the trace shows but that were NOT already submitted as candidates.

A lead must be grounded in a specific step of the trace (a response, an error, a
reflection, a status difference). Do not list anything inferred only from a product
version, a CVE, or a generic best practice. Do not repeat a candidate already listed
below. Zero leads is a valid and common answer.

Return ONLY a JSON array (no prose) of at most {max_leads} objects:
[{{"title": str, "target": "full in-scope URL", "vulnerability_class": one of {classes},
   "parameter": str, "severity": "info|low|medium|high|critical",
   "description": "what was observed and why it may be a vulnerability",
   "evidence_note": "which step number showed it",
   "claimed_request": "the request to replay, if known"}}]

Objective: {objective}

Already-submitted candidates (do not repeat):
{existing}

Execution trace (most recent {steps} steps):
{trace}
"""


def settlement_enabled() -> bool:
    from app.core.config import settings

    return bool(getattr(settings, "AGENT_SETTLEMENT_BACKFILL", False))


def settlement_applies(completion_reason: str) -> bool:
    """Budget exhaustion or a planning stall settles; stops, completions and errors do not."""
    reason = (completion_reason or "").lower()
    return any(marker in reason for marker in BUDGET_REASON_MARKERS)


def _brain_dict(brain_state: Any) -> Dict[str, Any]:
    if hasattr(brain_state, "to_dict"):
        return dict(brain_state.to_dict())
    return dict(brain_state or {})


def _existing_rows(raw_brain: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (raw_brain.get("candidates") or []) if isinstance(r, dict)]


def build_settlement_prompt(state: Dict[str, Any]) -> str:
    from app.services.agent.proof_policy import PROOFS_BY_CLASS
    from app.services.agent.state import format_execution_trace

    rows = _existing_rows(_brain_dict(state.get("engagement_brain")))
    existing = "\n".join(
        f"- {r.get('title')} | {r.get('vulnerability_class') or '?'} | {r.get('target')} "
        f"| status={r.get('status')}"
        for r in rows[:40]
    ) or "(none)"
    return SETTLEMENT_PROMPT.format(
        max_leads=MAX_SETTLEMENT_LEADS,
        classes=json.dumps(sorted(PROOFS_BY_CLASS)),
        objective=str(state.get("original_objective") or "")[:2000],
        existing=existing,
        steps=TRACE_STEPS,
        trace=format_execution_trace(state.get("execution_trace") or [], max_steps=TRACE_STEPS),
    )


def parse_settlement_leads(text: str) -> List[Dict[str, Any]]:
    """Pull the first JSON array out of the model's reply; malformed replies yield []."""
    if not text:
        return []
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)][:MAX_SETTLEMENT_LEADS]


def _settlement_description(description: str, evidence_note: str, severity: str) -> str:
    from app.services.agent.external_candidates import clean_text

    parts = [
        SETTLEMENT_HEADER,
        f"Claimed severity: {severity}",
        f"Lead: {clean_text(description, 2000, multiline=True) or '(none)'}",
    ]
    note = clean_text(evidence_note, 1000, multiline=True)
    if note:
        parts.append(f"Trace reference (not evidence): {note}")
    parts.append(SETTLEMENT_FOOTER)
    return "\n".join(parts)


def apply_settlement_leads(
    state: Dict[str, Any], leads: List[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Add validated leads to the brain as pending candidates.

    Returns ``(new_brain_dict_or_None, outcomes)``. The brain is None when no
    lead was added, so callers leave state untouched.
    """
    from app.services.agent.engagement_brain import engagement_brain_from_dict
    from app.services.agent.external_candidates import (
        IntakeError, _matching_row, _validated_payload, session_seed,
    )
    from app.services.agent.independent_verify import submit_candidate

    if not leads:
        return None, []
    seed = session_seed(state)
    if not seed:
        return None, [{"accepted": False, "reason": "no recoverable assessment target"}]

    raw_brain = _brain_dict(state.get("engagement_brain"))
    brain = engagement_brain_from_dict(raw_brain)
    outcomes: List[Dict[str, Any]] = []
    added = False
    for lead in leads[:MAX_SETTLEMENT_LEADS]:
        title = str(lead.get("title") or "")
        try:
            payload = _validated_payload(
                seed,
                title=title,
                target=str(lead.get("target") or ""),
                vulnerability_class=str(lead.get("vulnerability_class") or ""),
                description="",
                claimed_request=str(lead.get("claimed_request") or ""),
                severity=str(lead.get("severity") or "medium"),
                parameter=str(lead.get("parameter") or ""),
                evidence_note="",
            )
        except IntakeError as exc:
            outcomes.append({"title": title[:200], "accepted": False, "reason": exc.detail})
            continue
        rows = [r for r in (brain.candidates or []) if isinstance(r, dict)]
        match = _matching_row(rows, payload["candidate_id"], payload["root_cause"])
        if match is not None:
            outcomes.append({"title": payload["title"], "accepted": False,
                             "duplicate_of": match.get("id")})
            continue
        cand = submit_candidate(
            brain,
            title=payload["title"],
            description=_settlement_description(
                str(lead.get("description") or ""), str(lead.get("evidence_note") or ""),
                payload["severity"],
            ),
            severity=payload["severity"],
            target=payload["target"],
            evidence="",
            claimed_request=payload["claimed_request"],
            specialist=SETTLEMENT_SPECIALIST,
            parameter=payload["parameter"],
            evidence_ids=[],
            vulnerability_class=payload["vulnerability_class"],
        )
        added = True
        outcomes.append({"title": payload["title"], "accepted": True, "candidate_id": cand.id,
                         "vulnerability_class": payload["vulnerability_class"],
                         "severity": payload["severity"]})
    if not added:
        return None, outcomes
    raw_brain["candidates"] = list(brain.candidates)
    return raw_brain, outcomes


def settlement_report_note(outcomes: List[Dict[str, Any]]) -> str:
    """Line for the final report prompt naming leads saved for the next run."""
    accepted = [o for o in outcomes if o.get("accepted")]
    if not accepted:
        return ""
    items = "; ".join(f"{o['title']} ({o.get('vulnerability_class')})" for o in accepted)
    return (
        "\n\nUNVERIFIED LEADS SAVED FOR THE NEXT RUN (pending verification, not findings; "
        f"list them under follow-up work, never as confirmed vulnerabilities): {items}"
    )
