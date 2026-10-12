"""Bounded first pass over discovered SQLi and XSS inputs.

This queue does not replace the specialists. It gives every observed input a
small, execution-owned test before a specialist spends a whole LLM wave on one
lead. Inconclusive and unsupported shapes stay visible for follow-up.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any
from urllib.parse import urlsplit

from app.services.agent.coverage_cells import (
    CELL_OPEN,
    claim_coverage_cell_leases,
    migrate_coverage_cells,
    parameter_test_funnel,
    release_coverage_cell_lease,
)
from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.parameter_inventory import _origin
from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

logger = logging.getLogger(__name__)


async def _invoke(manager: Any, name: str, kwargs: dict[str, Any]) -> Any:
    """Keep nested active probes inside the normal tool policy and ledger."""
    if callable(getattr(manager, "execute", None)):
        wrapped = await manager.execute(name, kwargs)
        output = wrapped.get("output") if isinstance(wrapped, dict) else None
        return output if isinstance(output, dict) else wrapped
    return await getattr(manager, name)(**kwargs)


def pending_first_pass_cells(brain: Any, *, target: str = "") -> list[dict[str, Any]]:
    """Return exact input/class checks not yet given a bounded first pass."""
    active_origin = _origin(target) if target else ""
    if target and not active_origin:
        return []
    scheme = urlsplit(active_origin).scheme if active_origin else ""
    cells = brain.get("coverage_cells", []) if isinstance(brain, dict) else getattr(brain, "coverage_cells", [])
    return sorted(
        (
            cell for cell in cells
            if isinstance(cell, dict)
            and cell.get("source") == "parameter_inventory"
            and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
            and cell.get("test_type") in {"sqli", "xss"}
            and cell.get("specialist") in {"sqli", "xss"}
            and (not active_origin or _origin(
                f"{scheme}://{cell.get('host') or ''}"
            ) == active_origin)
            and (
                cell.get("status") in CELL_OPEN
                or (cell.get("status") == "leased"
                    and float(cell.get("lease_deadline") or 0) <= time.time())
            )
            and not cell.get("first_pass_outcome")
            and not cell.get("candidate_id")
            and not cell.get("probe_artifact_ids")
            and not cell.get("service_probe_artifact_ids")
        ),
        key=lambda cell: (
            int(cell.get("attempts") or 0),
            int(cell.get("priority_rank", 2)),
            cell.get("surface_key", ""),
            cell.get("parameter", ""),
            cell.get("test_type", ""),
        ),
    )


async def run_observed_input_batch(
    manager: Any, *, target: str = "", max_checks: int = 8,
    max_seconds: int = 180,
) -> dict[str, Any]:
    """Probe a small fair slice, and persist a result even when proof is blocked."""
    max_checks = max(1, min(int(max_checks), 8))
    max_seconds = max(15, min(int(max_seconds), 180))
    deadline = time.monotonic() + max_seconds
    brain = engagement_brain_from_dict(getattr(manager, "_engagement_brain", None))
    migrate_coverage_cells(brain)
    manager._engagement_brain = brain.to_dict()
    cmap = getattr(manager, "_capability_map", None) or {}
    active_target = str(target or getattr(manager, "_fallback_target", "") or
                        cmap.get("target") or "")
    active_origin = _origin(active_target)
    map_origins = [
        _origin(str(cmap[key])) for key in ("target", "scope") if cmap.get(key)
    ]
    if (not active_origin or not map_origins
            or any(origin != active_origin for origin in map_origins)):
        return {
            "processed": 0, "remaining": 0, "results": [],
            "error": "assessment_target_mismatch",
            "funnel": parameter_test_funnel(brain),
        }
    results: list[dict[str, Any]] = []

    while len(results) < max_checks and time.monotonic() < deadline - 5:
        brain = engagement_brain_from_dict(getattr(manager, "_engagement_brain", None))
        pending = pending_first_pass_cells(brain, target=active_target)
        if not pending:
            break
        # Claiming only first-pass cells prevents an inconclusive lead from
        # starving the remaining discovered inputs. Balance the two classes
        # so a run that expires midway has exercised both specialists.
        completed = {
            name: sum(1 for row in brain.coverage_cells
                      if row.get("source") == "parameter_inventory"
                      and row.get("specialist") == name
                      and row.get("first_pass_outcome"))
            for name in ("sqli", "xss")
        }
        specialist = min(
            {str(row["specialist"]) for row in pending},
            key=lambda name: (completed[name], 0 if name == "sqli" else 1),
        )
        leases = claim_coverage_cell_leases(
            brain, [specialist],
            allowed_observation_sources=OBSERVED_INPUT_SOURCES,
            allowed_test_types=frozenset({"sqli", "xss"}),
            allowed_cell_ids=frozenset(row["id"] for row in pending),
            first_pass_only=True,
            lease_seconds=max_seconds + 60,
        )
        lease = leases.get(specialist)
        if not lease:
            break
        cell = next(row for row in brain.coverage_cells if row["id"] == lease.coverage_cell_id)
        manager._engagement_brain = brain.to_dict()
        location, _, parameter = str(cell.get("parameter") or "").partition(":")
        method = str(cell.get("method") or "GET").upper()
        outcome = "unattempted"
        reason = "No supported scoped first-pass probe for this input shape"
        evidence_id = ""
        candidate_id = ""
        result: dict[str, Any] = {}
        followup_failure = ""

        try:
            remaining = max(1.0, deadline - time.monotonic() - 2)
            if method == "GET" and location == "query" and parameter:
                if specialist == "sqli" and cell.get("value_type") in {"positive_integer", "number"}:
                    if cell.get("observation_source") == "browser_traffic" and cell.get("capture_id"):
                        operation = _invoke(
                            manager, "scoped_assessment_probe_assigned",
                            {"coverage_cell_id": cell["id"], "coverage_lease_id": lease.id},
                        )
                    else:
                        operation = None
                        reason = "Numeric SQLi needs a captured positive value"
                else:
                    operation = _invoke(
                        manager, "scoped_input_probe_assigned",
                        {"coverage_cell_id": cell["id"], "coverage_lease_id": lease.id,
                         "technique": "html_body"},
                    )
            elif (cell.get("observation_source") == "browser_traffic"
                  and cell.get("capture_id") and method == "POST"
                  and location in {"body_json", "body_form"}):
                operation = _invoke(
                    manager, "scoped_assessment_probe_assigned",
                    {"coverage_cell_id": cell["id"], "coverage_lease_id": lease.id},
                )
            else:
                operation = None
            if operation is not None:
                result = await asyncio.wait_for(operation, timeout=min(remaining, 50.0))
                evidence_id = str(result.get("evidence_id") or next(
                    iter(result.get("service_artifact_ids") or []), ""
                ))
                if (specialist == "xss" and result.get("success") is True
                        and result.get("evidence_id")
                        and result.get("proof_confirmed") is not True):
                    contexts = set((result.get("probe_result") or {}).get("reflection_contexts") or [])
                    techniques = (
                        (["html_attribute"] if "html_attribute" in contexts else [])
                        + (["js_single", "js_double"] if "javascript" in contexts else [])
                    )[:3]
                    for technique in techniques:
                        remaining = deadline - time.monotonic() - 5
                        if remaining < 5:
                            break
                        followup = await asyncio.wait_for(_invoke(
                            manager, "scoped_input_probe_assigned",
                            {"coverage_cell_id": cell["id"], "coverage_lease_id": lease.id,
                             "technique": technique},
                        ), timeout=min(remaining, 35.0))
                        if followup.get("success") is not True or not followup.get("evidence_id"):
                            followup_failure = str(followup.get("error") or "missing_followup_receipt")[:100]
                            break
                        result = followup
                        if result.get("proof_confirmed") is True:
                            break
                evidence_id = str(result.get("evidence_id") or next(
                    iter(result.get("service_artifact_ids") or []), ""
                ))
                if result.get("success") is not True:
                    reason = str(result.get("error") or "probe_failed")[:160]
                    if result.get("reason"):
                        reason += ": " + str(result["reason"])[:120]
                elif not evidence_id:
                    reason = "Probe completed without an evidence receipt"
                else:
                    signal = result.get("proof_confirmed") is True or (
                        result.get("probe_result") or {}
                    ).get("proof_confirmed") is True or (
                        result.get("probe_result") or {}
                    ).get("executed") is True
                    if signal:
                        outcome = "proof_signal"
                        reason = "Execution-owned proof signal; fresh verification required"
                        # Local proof artifacts can be handed directly to the
                        # independent verifier. Service artifacts have their
                        # own candidate bridge and stay in focus for the agent.
                        if result.get("evidence_id"):
                            origin = urlsplit(active_origin)
                            if (origin.scheme in {"http", "https"} and _origin(
                                f"{origin.scheme}://{cell.get('host') or ''}"
                            ) == active_origin):
                                scoped_target = f"{origin.scheme}://{origin.netloc}{cell['path']}"
                                await _invoke(manager, "submit_finding_candidate", {
                                    "title": f"{specialist.upper()} proof on {method} {cell['path']} ({parameter})",
                                    "description": "Bounded observed-input probe returned an execution-owned proof signal.",
                                    "target": scoped_target,
                                    "evidence": f"First-pass proof receipt: {evidence_id}",
                                    "specialist": specialist,
                                    "coverage_cell_id": cell["id"],
                                    "evidence_ids": [evidence_id],
                                    "vulnerability_class": "sql_injection" if specialist == "sqli" else "xss",
                                })
                                submitted_brain = engagement_brain_from_dict(
                                    getattr(manager, "_engagement_brain", None)
                                )
                                candidate_id = next((
                                    str(row.get("id") or "")
                                    for row in submitted_brain.candidates
                                    if isinstance(row, dict)
                                    and row.get("coverage_cell_id") == cell["id"]
                                    and row.get("status") == "pending"
                                ), "")
                    elif specialist == "sqli" and result.get("evidence_id"):
                        receipt = await _invoke(manager, "record_surface_coverage", {
                            "path": cell["path"], "method": method, "host": cell.get("host", ""),
                            "identity": cell.get("identity", ""), "test_type": "sqli",
                            "parameter": cell["parameter"], "status": "tested_clean",
                            "evidence_id": evidence_id, "coverage_cell_id": cell["id"],
                            "coverage_lease_id": lease.id,
                            "reason": "Complete bounded SQLi controls did not confirm injection",
                        })
                        receipt_brain = engagement_brain_from_dict(
                            getattr(manager, "_engagement_brain", None)
                        )
                        closed = next((row for row in receipt_brain.coverage_cells
                                       if row.get("id") == cell["id"]), {})
                        if closed.get("status") == "tested_clean":
                            outcome = "tested_clean"
                            reason = "Complete bounded SQLi controls did not confirm injection"
                        else:
                            outcome = "inconclusive"
                            try:
                                reason = str(json.loads(receipt).get("error") or "SQLi controls were inconclusive")[:200]
                            except (ValueError, TypeError):
                                reason = "SQLi controls were inconclusive"
                    else:
                        outcome = "inconclusive"
                        reason = (
                            "XSS browser execution not observed in bounded reflected contexts"
                            if specialist == "xss" else
                            "Captured request changed without an independent SQLi proof"
                        )
                        if followup_failure:
                            reason += f"; follow-up blocked: {followup_failure}"
        except asyncio.TimeoutError:
            outcome = "inconclusive" if evidence_id else "unattempted"
            reason = "First-pass probe timed out" + (" after a partial receipt" if evidence_id else " without a proof receipt")
            logger.warning("Observed input first pass timed out for %s", cell["id"])
        except asyncio.CancelledError:
            interrupted = engagement_brain_from_dict(getattr(manager, "_engagement_brain", None))
            release_coverage_cell_lease(
                interrupted, lease, verdict="inconclusive",
                reason="First-pass tool was interrupted before a receipt",
            )
            manager._engagement_brain = interrupted.to_dict()
            raise
        except Exception as exc:
            outcome = "inconclusive" if evidence_id else "unattempted"
            reason = f"First-pass probe failed: {type(exc).__name__}"
            logger.exception("Observed input first pass failed for %s", cell["id"])

        live = engagement_brain_from_dict(getattr(manager, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells if row.get("id") == cell["id"]), None)
        if current:
            current["first_pass_outcome"] = outcome
            current["first_pass_reason"] = reason[:300]
            current["first_pass_at"] = time.time()
            if evidence_id:
                current["first_pass_evidence_id"] = evidence_id
            if candidate_id:
                current["candidate_id"] = candidate_id
            release_coverage_cell_lease(
                live, lease, verdict="proven" if outcome == "proof_signal" else "inconclusive",
                evidence_ids=[evidence_id] if evidence_id else [], candidate_id=candidate_id,
                reason=reason,
            )
            if (outcome == "unattempted" and current.get("status") == "inconclusive"
                    and reason.split(":", 1)[0] in {
                        "policy_denied", "confirmation_denied",
                        "assessment_scope_denied", "scope_mismatch",
                    }):
                current["status"] = "blocked"
        manager._engagement_brain = live.to_dict()
        results.append({
            "coverage_cell_id": cell["id"], "test_type": cell.get("test_type"),
            "outcome": outcome, "reason": reason, "evidence_id": evidence_id,
            "candidate_id": candidate_id,
        })

    brain = engagement_brain_from_dict(getattr(manager, "_engagement_brain", None))
    return {
        "processed": len(results), "remaining": len(pending_first_pass_cells(
            brain, target=active_target,
        )),
        "results": results, "funnel": parameter_test_funnel(brain),
    }
