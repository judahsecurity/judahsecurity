"""Evidence-backed work items: observed behavior and specialist leads.

Name heuristics in :mod:`vulnerability_catalog` give every observed input a
guaranteed minimum set of checks. This module adds the checks the evidence
justifies after the site has been exercised:

* **Observed behavior**: a benign canary's placement (script, attribute,
  ``Location`` header, ...) maps to the test classes that placement can carry.
* **Specialist leads**: a specialist may propose a check for a *different*
  class on an input it touched, but only by citing execution-owned evidence
  from its own tool calls.

The LLM proposes; code decides. A lead is accepted only when it names an
input already in the coverage ledger (so it is observed and in scope), a known
test class the input's location can carry, and evidence the specialist's own
tool calls produced. Accepted leads become ordinary coverage cells, so the
existing leases, first-pass waves, and independent verification apply.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.services.agent.coverage_cells import CELL_OPEN, CELL_TERMINAL, _new_cell
from app.services.agent.vulnerability_catalog import (
    ENDPOINT_TEST_CLASSES,
    PARAMETER_TEST_CLASSES,
    classes_from_reflection,
    lead_class_allowed,
    specialist_for_class,
)

LEAD_ORIGIN_BEHAVIOR = "observed_behavior"
LEAD_ORIGIN_SPECIALIST = "specialist_lead"
MAX_LEADS_PER_REPORT = 6
MAX_LEAD_CELLS = 400
MAX_REASON_CHARS = 300
# Sources whose cells name a concrete observed input a lead may anchor on.
ANCHOR_SOURCES = frozenset({
    "parameter_inventory", "surface_applicability", "authorization_capture",
})


def _text(value: Any) -> str:
    return str(value or "").strip()


def _ids(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)):
        return []
    return list(dict.fromkeys(_text(value) for value in values if _text(value)))[:8]


def normalize_leads(raw: Any) -> list[dict[str, Any]]:
    """Coerce a specialist's ``leads`` payload into bounded, typed rows."""
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    leads = []
    for item in raw[: MAX_LEADS_PER_REPORT * 2]:
        if not isinstance(item, dict):
            continue
        lead = {
            "coverage_cell_id": _text(item.get("coverage_cell_id") or item.get("cell_id")),
            "method": _text(item.get("method")).upper(),
            "path": _text(item.get("path")),
            "host": _text(item.get("host")),
            "parameter": _text(item.get("parameter")),
            "identity": _text(item.get("identity")),
            "test_type": _text(item.get("test_type") or item.get("test_class")).lower(),
            "evidence_ids": _ids(item.get("evidence_ids") or item.get("evidence_id")),
            "reason": _text(item.get("reason"))[:MAX_REASON_CHARS],
        }
        if lead["test_type"]:
            leads.append(lead)
    return leads[:MAX_LEADS_PER_REPORT]


def _location(parameter: str) -> str:
    return parameter.split(":", 1)[0] if ":" in parameter else ""


def find_anchor(
    brain: Any,
    *,
    coverage_cell_id: str = "",
    method: str = "",
    path: str = "",
    parameter: str = "",
    host: str = "",
    identity: str = "",
) -> dict[str, Any] | None:
    """Return an existing cell for the exact observed input a lead names."""
    cells = [
        cell for cell in getattr(brain, "coverage_cells", None) or []
        if isinstance(cell, dict) and cell.get("source") in ANCHOR_SOURCES
    ]
    if coverage_cell_id:
        return next((cell for cell in cells if cell.get("id") == coverage_cell_id), None)
    if not (path and parameter):
        return None
    method = (method or "GET").upper()
    matches = [
        cell for cell in cells
        if cell.get("method") == method
        and cell.get("path") == path
        and cell.get("parameter") == parameter
        and (not host or _text(cell.get("host")).lower() == host.lower())
        and (not identity or _text(cell.get("identity")) == identity)
    ]
    # Prefer a replayable capture, then the parameter-level cell.
    matches.sort(key=lambda cell: (
        not cell.get("capture_id"),
        cell.get("source") != "parameter_inventory",
    ))
    return matches[0] if matches else None


def _input_parameter(anchor: dict[str, Any]) -> str:
    """Parameter-level cells keep their input; endpoint anchors have none."""
    parameter = _text(anchor.get("parameter"))
    return "" if parameter in {"", "endpoint"} else parameter


def _hypothesis_for(brain: Any, specialist: str) -> str:
    return next((
        _text(getattr(h, "id", ""))
        for h in getattr(brain, "hypotheses", None) or []
        if getattr(h, "specialist", "") == specialist
        and getattr(h, "status", "") in ("open", "in_progress")
    ), "")


def _lead_cell_count(brain: Any) -> int:
    return sum(
        1 for cell in getattr(brain, "coverage_cells", None) or []
        if isinstance(cell, dict) and cell.get("lead_created")
    )


def add_evidence_backed_cell(
    brain: Any,
    anchor: dict[str, Any],
    test_type: str,
    *,
    origin: str,
    evidence_ids: Iterable[str],
    reason: str,
    proposed_by: str = "",
) -> tuple[str, dict[str, Any] | None]:
    """Create or prioritize one check on ``anchor``'s input.

    Returns ``(outcome, cell)`` where outcome is ``created``, ``prioritized``,
    ``already_running``, ``already_terminal``, or ``rejected:<reason>``.
    Basis evidence is stored apart from ``evidence_ids`` so the cell still
    reads as unattempted until an execution receipt lands on it.
    """
    test_type = _text(test_type).lower()
    evidence = list(dict.fromkeys(_text(v) for v in evidence_ids if _text(v)))
    if not evidence:
        return "rejected:no_evidence", None
    if test_type not in PARAMETER_TEST_CLASSES | ENDPOINT_TEST_CLASSES:
        return "rejected:unknown_test_type", None
    endpoint_class = test_type in ENDPOINT_TEST_CLASSES
    parameter = "endpoint" if endpoint_class else _input_parameter(anchor)
    if not parameter:
        return "rejected:anchor_has_no_input", None
    if not endpoint_class and not lead_class_allowed(_location(parameter), test_type):
        return "rejected:class_not_applicable_to_location", None

    specialist = specialist_for_class(test_type)
    candidate = _new_cell(
        brain,
        method=_text(anchor.get("method")) or "GET",
        path=_text(anchor.get("path")) or "/",
        host=_text(anchor.get("host")),
        operation_id=_text(anchor.get("operation_id")),
        identity=_text(anchor.get("identity")),
        tenant=_text(anchor.get("tenant")),
        parameter=parameter,
        test_type=test_type,
        hypothesis_id=_hypothesis_for(brain, specialist),
        source="surface_applicability" if endpoint_class else "parameter_inventory",
        reason=f"{origin}: {reason}"[:500],
        capture_id=anchor.get("capture_id", ""),
    )
    cells = getattr(brain, "coverage_cells", None)
    if not isinstance(cells, list):
        return "rejected:no_ledger", None
    existing = next((cell for cell in cells if cell.get("id") == candidate["id"]), None)
    basis = {
        "origin": origin, "evidence_ids": evidence[:8],
        "reason": _text(reason)[:MAX_REASON_CHARS], "proposed_by": _text(proposed_by),
    }
    if existing is not None:
        if not any(row.get("evidence_ids") == basis["evidence_ids"]
                   for row in existing.get("lead_basis") or []):
            existing["lead_basis"] = [*(existing.get("lead_basis") or []), basis][-6:]
        if existing.get("status") in CELL_TERMINAL:
            return "already_terminal", existing
        if existing.get("lease_id") or existing.get("status") == "leased":
            return "already_running", existing
        if existing.get("status") in CELL_OPEN:
            # Evidence outranks a name match: run this check first.
            existing["priority_rank"] = 0
        return "prioritized", existing
    if _lead_cell_count(brain) >= MAX_LEAD_CELLS:
        return "rejected:lead_budget_exhausted", None
    candidate.update({
        "priority_rank": 0,
        "observation_source": _text(anchor.get("observation_source")),
        "value_type": _text(anchor.get("value_type")),
        "lead_created": origin,
        "lead_basis": [basis],
    })
    cells.append(candidate)
    return "created", candidate


def apply_reflection_observations(
    brain: Any,
    observations: Iterable[dict[str, Any]],
    *,
    host: str,
    evidence_ids: Iterable[str],
) -> list[dict[str, Any]]:
    """Turn canary placements into prioritized checks on the same GET input.

    ``evidence_ids`` must align with ``observations``: one execution-owned
    evidence ID per observation, recorded by the caller.
    """
    results = []
    for observation, evidence_id in zip(observations, evidence_ids):
        if not isinstance(observation, dict) or not evidence_id:
            continue
        contexts = observation.get("reflection_contexts") or []
        classes = classes_from_reflection(contexts)
        if not classes:
            continue
        anchor = find_anchor(
            brain, method="GET", path=_text(observation.get("path")),
            parameter=f"query:{_text(observation.get('parameter'))}", host=host,
        )
        if anchor is None:
            continue
        for test_type in classes:
            outcome, cell = add_evidence_backed_cell(
                brain, anchor, test_type, origin=LEAD_ORIGIN_BEHAVIOR,
                evidence_ids=[evidence_id],
                reason=f"benign canary observed in {', '.join(map(str, contexts))}",
                proposed_by="reflection_probe",
            )
            results.append({
                "outcome": outcome, "test_type": test_type,
                "coverage_cell_id": (cell or {}).get("id", ""),
                "parameter": anchor.get("parameter"), "path": anchor.get("path"),
            })
    return results


def apply_specialist_leads(
    brain: Any,
    leads: Any,
    *,
    specialist: str,
    allowed_evidence_ids: Iterable[str],
) -> list[dict[str, Any]]:
    """Validate a specialist's leads and record the accepted ones as cells.

    ``allowed_evidence_ids`` is the execution-owned evidence from that
    specialist's own tool calls (and its leased cell). A lead citing anything
    else is rejected: the model cannot invent the reason for new work.
    """
    allowed = {_text(v) for v in allowed_evidence_ids if _text(v)}
    results = []
    for lead in normalize_leads(leads):
        row = {
            "specialist": specialist, "test_type": lead["test_type"],
            "coverage_cell_id": "", "anchor_cell_id": lead["coverage_cell_id"],
            "parameter": lead["parameter"], "path": lead["path"],
            "reason": lead["reason"],
        }
        cited = [eid for eid in lead["evidence_ids"] if eid in allowed]
        if not lead["evidence_ids"]:
            results.append({**row, "outcome": "rejected:no_evidence"})
            continue
        if len(cited) != len(lead["evidence_ids"]):
            results.append({**row, "outcome": "rejected:evidence_not_execution_owned"})
            continue
        if not lead["reason"]:
            results.append({**row, "outcome": "rejected:no_reason"})
            continue
        anchor = find_anchor(
            brain,
            coverage_cell_id=lead["coverage_cell_id"],
            method=lead["method"], path=lead["path"], parameter=lead["parameter"],
            host=lead["host"], identity=lead["identity"],
        )
        if anchor is None:
            results.append({**row, "outcome": "rejected:input_not_observed"})
            continue
        outcome, cell = add_evidence_backed_cell(
            brain, anchor, lead["test_type"], origin=LEAD_ORIGIN_SPECIALIST,
            evidence_ids=cited, reason=lead["reason"], proposed_by=specialist,
        )
        results.append({
            **row, "outcome": outcome,
            "coverage_cell_id": (cell or {}).get("id", ""),
            "anchor_cell_id": anchor.get("id", ""),
            "parameter": anchor.get("parameter"), "path": anchor.get("path"),
        })
    return results
