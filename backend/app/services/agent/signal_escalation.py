"""Turn strong execution signals into bounded proof work, never findings.

Heuristic differentials are useful for routing but are not publication
evidence.  This module records a stable proof escalation, links it to the exact
coverage cell, and tells the assigned specialist which deterministic proof bar
must be satisfied next.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


ESCALATION_VERDICTS = frozenset(
    {
        "LIKELY_IMPACT",
        "MUTANT_BYPASS_CANDIDATE",
        "TIME_BASED_INJECTION_CANDIDATE",
    }
)
ESCALATION_TERMINAL = frozenset({"confirmed", "refuted", "published"})
MAX_ESCALATIONS = 500


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _strategy(
    verdict: str, signals: list[str], proof: dict[str, Any]
) -> tuple[str, str, list[str]]:
    lane = _text(proof.get("lane")).lower()
    signal_blob = " ".join(_text(value).lower() for value in signals)
    if lane:
        lane_specialists = {
            "auth_header_bypass": "api_authz",
            "email_change_ato": "auth_logic",
            "socketio_idor": "api_authz",
            "ml_pipeline_rbac": "business_logic",
        }
        return (
            "independent_lane_replay",
            lane_specialists.get(lane, "auth_logic"),
            [
                "Replay the exact bounded baseline/mutant pair in a fresh verifier run",
                "Cite both fresh HTTP evidence IDs and the demonstrated impact",
                "Refute on a holding control; never promote the signal by narrative alone",
            ],
        )
    if verdict == "TIME_BASED_INJECTION_CANDIDATE":
        return (
            "timing_confirmation",
            "sqli",
            [
                "Repeat matched control and time payloads with the same request shape",
                "Show a repeatable timing separation, not one slow response",
                "Submit fresh evidence IDs for independent verification",
            ],
        )
    if (
        "interest_field_deltas" in signal_blob
        or "auth" in signal_blob
        or "cross_identity" in signal_blob
        or "owner" in signal_blob
        or "tenant" in signal_blob
    ):
        return (
            "authorization_differential",
            "api_authz",
            [
                "Re-run with a verified owner and a distinct attacker identity",
                "Prove the same controlled object or sensitive field crosses the boundary",
                "Use a fresh authorization proof receipt or structured differential proof",
            ],
        )
    if "write" in signal_blob or "state" in signal_blob:
        return (
            "controlled_state_change",
            "business_logic",
            [
                "Write a fresh bounded canary and read it back as the legitimate owner",
                "Record mandatory cleanup evidence",
                "Submit the write/read/cleanup evidence IDs for independent verification",
            ],
        )
    return (
        "response_differential",
        "auth_logic",
        [
            "Reproduce the differential with a matched negative control",
            "Demonstrate sensitive content or persisted impact beyond status/length changes",
            "Submit fresh evidence IDs for independent verification",
        ],
    )


def should_escalate(verdict: str, evidence_ids: list[str]) -> bool:
    return (
        _text(verdict).upper() in ESCALATION_VERDICTS
        and len([value for value in evidence_ids if _text(value)]) >= 2
    )


def escalation_id(
    *,
    verdict: str,
    target: str,
    coverage_cell_id: str = "",
    hypothesis_id: str = "",
    evidence_ids: list[str] | None = None,
) -> str:
    dimensions = (
        _text(verdict).upper(),
        _text(target),
        _text(coverage_cell_id),
        _text(hypothesis_id),
        tuple(sorted(_text(value) for value in (evidence_ids or []) if _text(value))),
    )
    return "proof-" + hashlib.sha256(json.dumps(dimensions).encode()).hexdigest()[:24]


def queue_signal_escalation(
    brain: Any,
    *,
    verdict: str,
    signals: list[str],
    evidence_ids: list[str],
    target: str,
    source_tool: str,
    coverage_cell_id: str = "",
    hypothesis_id: str = "",
    operation_id: str = "",
    identity: str = "",
    tenant: str = "",
    parameter: str = "",
    test_type: str = "",
    proof: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Queue one deduplicated proof job from execution-owned evidence."""
    verdict = _text(verdict).upper()
    evidence_ids = list(
        dict.fromkeys(_text(value) for value in evidence_ids if _text(value))
    )
    if not should_escalate(verdict, evidence_ids):
        return None
    proof = dict(proof or {})
    strategy, specialist, requirements = _strategy(verdict, signals, proof)
    eid = escalation_id(
        verdict=verdict,
        target=target,
        coverage_cell_id=coverage_cell_id,
        hypothesis_id=hypothesis_id,
        evidence_ids=evidence_ids,
    )
    rows = [
        dict(row)
        for row in (getattr(brain, "proof_escalations", None) or [])
        if isinstance(row, dict) and row.get("id")
    ]
    existing = next((row for row in rows if row["id"] == eid), None)
    now = _now()
    if existing is None:
        existing = {
            "id": eid,
            "status": "pending",
            "source_tool": _text(source_tool),
            "signal_verdict": verdict,
            "signals": list(
                dict.fromkeys(_text(value) for value in signals if _text(value))
            ),
            "evidence_ids": evidence_ids,
            "target": _text(target),
            "coverage_cell_id": _text(coverage_cell_id),
            "hypothesis_id": _text(hypothesis_id),
            "operation_id": _text(operation_id),
            "identity": _text(identity),
            "tenant": _text(tenant),
            "parameter": _text(parameter),
            "test_type": _text(test_type),
            "strategy": strategy,
            "specialist": specialist,
            "requirements": requirements,
            "proof_hint": {
                key: value
                for key, value in proof.items()
                if key
                in {
                    "lane",
                    "demonstrated",
                    "submit",
                    "baseline_status",
                    "mutant_status",
                }
            },
            "candidate_id": "",
            "proof_run_id": "",
            "verifier_run_id": "",
            "finding_id": "",
            "attempts": 0,
            "created_at": now,
            "updated_at": now,
        }
        rows.append(existing)
    elif existing.get("status") not in ESCALATION_TERMINAL:
        existing["status"] = "pending"
        existing["updated_at"] = now
        existing["evidence_ids"] = list(
            dict.fromkeys([*(existing.get("evidence_ids") or []), *evidence_ids])
        )
        existing["signals"] = list(
            dict.fromkeys([*(existing.get("signals") or []), *signals])
        )
    brain.proof_escalations = rows[-MAX_ESCALATIONS:]

    if coverage_cell_id:
        for cell in getattr(brain, "coverage_cells", None) or []:
            if cell.get("id") != coverage_cell_id:
                continue
            if cell.get("status") not in {"finding", "tested_clean", "skipped"}:
                cell["status"] = "in_focus"
            cell["proof_escalation_id"] = eid
            cell["proof_strategy"] = strategy
            cell["proof_requirements"] = list(requirements)
            cell["signal_evidence_ids"] = list(evidence_ids)
            cell["specialist"] = specialist
            cell["reason"] = f"{verdict} escalated to {strategy}"
    for hypothesis in getattr(brain, "hypotheses", None) or []:
        if hypothesis_id and getattr(hypothesis, "id", "") == hypothesis_id:
            if getattr(hypothesis, "status", "") == "open":
                hypothesis.status = "in_progress"
            hypothesis.evidence = (
                f"{source_tool} {verdict}; proof escalation {eid}; "
                f"evidence={','.join(evidence_ids[:4])}"
            )[:2000]
            hypothesis.updated_at = now
    return dict(existing)


def bind_candidate(
    brain: Any,
    escalation_id_value: str,
    *,
    candidate_id: str,
    proof_run_id: str = "",
) -> dict[str, Any] | None:
    for row in getattr(brain, "proof_escalations", None) or []:
        if row.get("id") != escalation_id_value:
            continue
        row.update(
            status="verifying",
            candidate_id=_text(candidate_id),
            proof_run_id=_text(proof_run_id) or row.get("proof_run_id", ""),
            updated_at=_now(),
        )
        return row
    return None


def apply_verifier_result(
    brain: Any,
    escalation_id_value: str,
    *,
    verdict: str,
    verifier_run_id: str,
) -> dict[str, Any] | None:
    normalized = _text(verdict).lower()
    for row in getattr(brain, "proof_escalations", None) or []:
        if row.get("id") != escalation_id_value:
            continue
        row.update(
            status=(
                "confirmed"
                if normalized == "confirmed"
                else "refuted"
                if normalized == "refuted"
                else "pending"
            ),
            verifier_run_id=_text(verifier_run_id),
            updated_at=_now(),
        )
        return row
    return None
