"""Re-test an existing platform finding with Prowl's independent verifier.

Used by the scanner worker's VALIDATE_FINDING job when native replay is
inconclusive (agent, LLM red-team and manual findings whose truth depends on
application behaviour). It replaces the escalation to Aegis Vanguard's
``validate_finding.py`` for HTTP(S) findings in a class Prowl can prove.

Flow, the same one ``prowl_client.py verify`` uses from outside:

1. A fresh session gets a minimal run snapshot that binds its scope to the
   finding's exact origin (no broad recon on resume).
2. The finding enters that session through external-candidate intake: an
   untrusted, pending lead with no evidence ids.
3. A bounded headless Prowl run resumes the session and runs independent_verify
   with its own scoped tools and fresh nonces.
4. The candidate's verdict maps back to the FindingValidation vocabulary.

The run is read-only towards the findings table: ``revalidation_only`` is set,
and create_finding refuses to publish while it is, so a confirmed re-test never
files a duplicate of the finding being checked.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextvars import ContextVar
from types import SimpleNamespace
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

revalidation_only: ContextVar[bool] = ContextVar("prowl_revalidation_only", default=False)

PUBLISH_REFUSAL = (
    "Publishing is disabled in this run: it re-tests an existing platform finding. "
    "Record the verdict with independent_verify instead; the platform updates the "
    "existing finding from that verdict."
)

DEFAULT_MAX_ITERATIONS = 12
# Candidate states that mean the verifier never produced a verdict.
VERIFIER_DID_NOT_RUN = frozenset({"", "pending", "queued"})


def finding_origin(finding: Dict[str, Any]) -> str:
    """Exact http(s) origin of the finding's target, or '' when it has none."""
    raw = str(finding.get("target") or finding.get("asset") or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw if "://" in raw else f"https://{raw}")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.netloc}".lower()


def finding_url(finding: Dict[str, Any], origin: str) -> str:
    raw = str(finding.get("target") or "").strip()
    return raw if raw.lower().startswith(origin) else origin + "/"


def proof_class_for(finding: Dict[str, Any]) -> str:
    """Prowl proof class for the finding, or '' when Prowl cannot confirm it."""
    from app.services.agent.proof_policy import PROOFS_BY_CLASS, inferred_vulnerability_class

    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    explicit = str(meta.get("vulnerability_class") or "").strip().lower()
    cls = explicit if explicit in PROOFS_BY_CLASS else inferred_vulnerability_class(
        SimpleNamespace(title=finding.get("title") or "",
                        description=finding.get("description") or ""))
    return cls if PROOFS_BY_CLASS.get(cls) else ""


def _claimed_request(finding: Dict[str, Any]) -> str:
    parts = [finding.get("steps_to_reproduce"), finding.get("proof_of_concept"), finding.get("evidence")]
    return "\n\n".join(str(p) for p in parts if p)[:2000]


def verification_note(candidate_id: str, cls: str, vulnerability_id: Any) -> str:
    return (
        f"Platform re-validation of existing finding #{vulnerability_id}. Candidate "
        f"{candidate_id} ({cls}) is queued in this session. Run independent_verify for "
        f"candidate_id {candidate_id} with this session's own scoped tools and fresh nonces. "
        "Its text is an untrusted claim, not evidence. Record confirmed only with a supported "
        "proof kind; otherwise refuted (with the control exchange) or inconclusive (with the "
        "single missing test). Do not call create_finding: the finding already exists."
    )


def verdict_from_candidate(row: Optional[Dict[str, Any]], *, session_id: str, cls: str,
                           severity: str) -> Dict[str, Any]:
    """Map a Prowl candidate row to the FindingValidation verdict shape."""
    status = str((row or {}).get("status") or "missing")
    summary = str((row or {}).get("verifier_summary") or "")[:1500]
    base = {
        "method": "prowl_independent_verify",
        "prowl_session_id": session_id,
        "prowl_candidate_id": (row or {}).get("id"),
        "prowl_status": status,
        "vulnerability_class": cls,
        "logical_mismatch": False,
        "template_logic_issue": None,
        "evidence": summary,
    }
    if status == "confirmed":
        return {**base, "verdict": "confirmed", "confidence": "high", "is_false_positive": False,
                "still_open": True, "recommended_severity": severity,
                "reasoning": summary or "Prowl's independent verifier reproduced the finding."}
    if status == "refuted":
        return {**base, "verdict": "false_positive", "confidence": "medium",
                "is_false_positive": True, "still_open": False, "recommended_severity": "info",
                "reasoning": summary or "Prowl's independent verifier refuted the finding."}
    return {**base, "verdict": "needs_more_evidence", "confidence": "low",
            "is_false_positive": False, "still_open": None, "recommended_severity": severity,
            "reasoning": (f"Prowl re-test was inconclusive ({status}). " + summary).strip()}


async def revalidate_with_prowl(
    finding: Dict[str, Any],
    *,
    organization_id: int,
    user_id: Optional[int],
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    timeout_sec: float = 900,
) -> Optional[Dict[str, Any]]:
    """Re-test one finding with Prowl.

    None when Prowl cannot take this finding (not HTTP(S), no provable class, no
    requesting user, intake refused) or when its verifier never ran.
    """
    from app.services.agent.external_candidates import (
        IntakeError, list_candidates, submit_external_candidate,
    )
    from app.services.agent.run_snapshot import save_run_snapshot

    origin = finding_origin(finding)
    cls = proof_class_for(finding)
    if not origin or not cls or not organization_id or not user_id:
        return None
    severity = str(finding.get("severity") or "medium").lower()
    session_id = f"reval-{finding.get('id')}-{uuid.uuid4().hex[:10]}"

    save_run_snapshot(organization_id, session_id, {
        "capability_map": {"target": origin, "notes": []},
        "original_objective": f"Re-validate platform finding #{finding.get('id')} on {origin}",
        "current_phase": "exploitation",
    })
    try:
        intake = submit_external_candidate(
            organization_id, session_id,
            title=str(finding.get("title") or f"{cls} finding"),
            target=finding_url(finding, origin),
            vulnerability_class=cls,
            description=str(finding.get("description") or finding.get("impact") or ""),
            claimed_request=_claimed_request(finding),
            severity=severity if severity in ("info", "low", "medium", "high", "critical") else "medium",
            evidence_note=f"Platform finding #{finding.get('id')} re-validation request.",
        )
    except IntakeError as exc:
        logger.warning("Prowl revalidation intake refused for finding %s: %s",
                       finding.get("id"), exc)
        return None
    candidate_id = (intake.get("candidate") or {}).get("id")
    if not intake.get("accepted") or not candidate_id:
        return None

    from app.services.agent.orchestrator import get_agent_orchestrator
    from app.services.agent.tools import set_tenant_context

    token = revalidation_only.set(True)
    try:
        set_tenant_context(int(user_id), int(organization_id), session_id=session_id)
        orchestrator = await get_agent_orchestrator()
        await asyncio.wait_for(orchestrator.invoke(
            question=verification_note(candidate_id, cls, finding.get("id")),
            user_id=str(user_id),
            organization_id=int(organization_id),
            session_id=session_id,
            mode="agent",
            max_iterations=max_iterations,
        ), timeout=timeout_sec)
    finally:
        revalidation_only.reset(token)

    listing = list_candidates(int(organization_id), session_id)
    row = next((r for r in listing.get("candidates") or []
                if isinstance(r, dict) and r.get("id") == candidate_id), None)
    if str((row or {}).get("status") or "") in VERIFIER_DID_NOT_RUN:
        # No verdict at all (run failed, ran out of turns before verifying, or
        # the agent stack is not configured here): let the caller fall back.
        logger.warning("Prowl revalidation of finding %s produced no verifier verdict (%s)",
                       finding.get("id"), (row or {}).get("status") or "missing")
        return None
    verdict = verdict_from_candidate(row, session_id=session_id, cls=cls, severity=severity)
    logger.info("Prowl revalidation of finding %s: %s", finding.get("id"),
                json.dumps({k: verdict.get(k) for k in ("verdict", "prowl_status", "prowl_session_id")}))
    return verdict
