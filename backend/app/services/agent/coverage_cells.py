"""Normalized assessment coverage cells and execution leases.

The legacy engagement ledger stored one status per HTTP surface and optional
``checks`` below it.  That shape is useful for a UI summary but cannot answer
whether every identity, parameter, or test family was exercised.  This module
keeps a flat, deterministic cell ledger while leaving the legacy rows intact
for older snapshots and callers.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

CELL_TERMINAL = frozenset({"finding", "tested_clean", "skipped"})
CELL_OPEN = frozenset({"untested", "in_focus", "inconclusive"})
CELL_STATUSES = frozenset({*CELL_TERMINAL, *CELL_OPEN, "leased", "blocked"})
MAX_COVERAGE_CELLS = 10_000


def scoped_replay_eligible(cell: dict[str, Any]) -> bool:
    """Whether the scoped service can replay this private browser capture."""
    location, separator, parameter = str(cell.get("parameter") or "").partition(":")
    method = str(cell.get("method") or "").upper()
    return bool(
        cell.get("source") == "parameter_inventory"
        and cell.get("test_type") in {"xss", "sqli"}
        and cell.get("observation_source") == "browser_traffic"
        and cell.get("capture_id")
        and separator and parameter
        and ((method == "GET" and location == "query")
             or (method == "POST" and location in {"body_json", "body_form"}))
    )


def _text(value: Any) -> str:
    return str(value or "").strip()


def _surface_parts(method: str, path: str, host: str = "") -> tuple[str, str, str, str]:
    method = (_text(method) or "GET").upper()
    raw_path = _text(path) or "/"
    host = _text(host).lower()
    if raw_path.startswith(("http://", "https://")):
        parsed = urlsplit(raw_path)
        host = host or (parsed.netloc or "").lower()
        raw_path = parsed.path or "/"
    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path
    key = f"{method} {host}{raw_path}" if host else f"{method} {raw_path}"
    return method, raw_path, host, key


def coverage_cell_id(
    *,
    method: str = "GET",
    path: str = "/",
    host: str = "",
    operation_id: str = "",
    identity: str = "",
    tenant: str = "",
    parameter: str = "",
    test_type: str = "",
) -> str:
    """Return a stable ID for the dimensions that define one coverage unit."""
    method, path, host, _ = _surface_parts(method, path, host)
    dimensions = (
        method,
        host,
        path,
        _text(operation_id),
        _text(identity) or "unspecified",
        _text(tenant),
        _text(parameter) or "endpoint",
        _text(test_type).lower() or "surface_review",
    )
    digest = hashlib.sha256(json.dumps(dimensions).encode()).hexdigest()[:24]
    return "cov-" + digest


def _status(value: Any, default: str = "untested") -> str:
    value = _text(value).lower()
    aliases = {
        "pending": "untested",
        "running": "leased",
        "in_progress": "in_focus",
        "tested": "in_focus",
        "candidate": "in_focus",
        "validated": "finding",
        "rejected": "tested_clean",
        "error": "inconclusive",
    }
    value = aliases.get(value, value)
    return value if value in CELL_STATUSES else default


def _specialist_for(test_type: str, hypothesis_id: str, brain: Any) -> str:
    for hypothesis in getattr(brain, "hypotheses", None) or []:
        if getattr(hypothesis, "id", "") == hypothesis_id:
            return _text(getattr(hypothesis, "specialist", "")) or "app_mapper"
    from app.services.agent.vulnerability_catalog import specialist_for_class

    kind = _text(test_type).lower()
    catalog_specialist = specialist_for_class(kind)
    if catalog_specialist != "app_mapper":
        return catalog_specialist
    if kind in {"authorization", "auth", "authz", "csrf", "business_logic"}:
        return "auth_logic"
    if "xss" in kind:
        return "xss"
    if kind == "js_secret_review":
        return "js_secrets"
    if "sql" in kind:
        return "sqli"
    if kind == "xxe":
        return "sqli"
    if "ssrf" in kind or "url_fetch" in kind:
        return "ssrf"
    if "path" in kind or "command" in kind or kind in {"cmdi", "input_boundary"}:
        return "injection"
    return "app_mapper"


def _new_cell(
    brain: Any,
    *,
    method: str,
    path: str,
    host: str = "",
    operation_id: str = "",
    identity: str = "",
    tenant: str = "",
    parameter: str = "",
    test_type: str = "",
    hypothesis_id: str = "",
    status: str = "untested",
    source: str = "coverage",
    reason: str = "",
    evidence_ids: Iterable[str] | None = None,
    **trace: Any,
) -> dict[str, Any]:
    method, path, host, surface_key = _surface_parts(method, path, host)
    identity = _text(identity) or "unspecified"
    parameter = _text(parameter) or "endpoint"
    test_type = _text(test_type).lower() or "surface_review"
    hypothesis_id = _text(hypothesis_id)
    cell = {
        "id": coverage_cell_id(
            method=method,
            path=path,
            host=host,
            operation_id=operation_id,
            identity=identity,
            tenant=tenant,
            parameter=parameter,
            test_type=test_type,
        ),
        "surface_key": surface_key,
        "method": method,
        "path": path,
        "host": host,
        "operation_id": _text(operation_id),
        "identity": identity,
        "tenant": _text(tenant),
        "parameter": parameter,
        "test_type": test_type,
        "hypothesis_id": hypothesis_id,
        "specialist": _specialist_for(test_type, hypothesis_id, brain),
        "status": _status(status),
        "source": _text(source) or "coverage",
        "reason": _text(reason)[:500],
        "evidence_ids": list(
            dict.fromkeys(_text(v) for v in (evidence_ids or []) if _text(v))
        ),
        "capture_id": _text(trace.get("capture_id")),
        "request_ids": list(
            dict.fromkeys(
                _text(v) for v in (trace.get("request_ids") or []) if _text(v)
            )
        ),
        "candidate_id": _text(trace.get("candidate_id")),
        "proof_run_id": _text(trace.get("proof_run_id")),
        "verifier_run_id": _text(trace.get("verifier_run_id")),
        "finding_id": _text(trace.get("finding_id")),
        "finding_title": _text(trace.get("finding_title")),
        "lease_id": _text(trace.get("lease_id")),
        "lease_owner": _text(trace.get("lease_owner")),
        "lease_started_at": float(trace.get("lease_started_at") or 0),
        "lease_deadline": float(trace.get("lease_deadline") or 0),
        "task_lease_id": _text(trace.get("task_lease_id")),
        "attempts": int(trace.get("attempts") or 0),
        "updated_at": _text(trace.get("updated_at")),
    }
    return cell


def _merge_cell(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Merge newly-derived dimensions without erasing execution-owned state."""
    merged = dict(incoming)
    merged.update(existing)
    merged["status"] = _status(
        existing.get("status"), incoming.get("status", "untested")
    )
    merged["evidence_ids"] = list(
        dict.fromkeys(
            [
                *(incoming.get("evidence_ids") or []),
                *(existing.get("evidence_ids") or []),
            ]
        )
    )
    merged["request_ids"] = list(
        dict.fromkeys(
            [*(incoming.get("request_ids") or []), *(existing.get("request_ids") or [])]
        )
    )
    for key in (
        "operation_id",
        "hypothesis_id",
        "capture_id",
        "candidate_id",
        "proof_run_id",
        "verifier_run_id",
        "finding_id",
        "finding_title",
    ):
        merged[key] = _text(existing.get(key) or incoming.get(key))
    return merged


def migrate_coverage_cells(
    brain: Any,
    *,
    denominator: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Idempotently adapt legacy rows, operations, and auth matrix rows to cells."""
    cells: dict[str, dict[str, Any]] = {}

    def put(cell: dict[str, Any]) -> None:
        cell_id = cell["id"]
        if cell_id in cells:
            cells[cell_id] = _merge_cell(cells[cell_id], cell)
        elif len(cells) < MAX_COVERAGE_CELLS:
            cells[cell_id] = cell

    for raw in getattr(brain, "coverage_cells", None) or []:
        if not isinstance(raw, dict):
            continue
        normalized = _new_cell(
            brain,
            **{
                "method": raw.get("method", "GET"),
                "path": raw.get("path", "/"),
                "host": raw.get("host", ""),
                "operation_id": raw.get("operation_id", ""),
                "identity": raw.get("identity", ""),
                "tenant": raw.get("tenant", ""),
                "parameter": raw.get("parameter", ""),
                "test_type": raw.get("test_type", ""),
                "hypothesis_id": raw.get("hypothesis_id", ""),
                "status": raw.get("status", "untested"),
                "source": raw.get("source", "coverage"),
                "reason": raw.get("reason", ""),
                "evidence_ids": raw.get("evidence_ids", []),
                **{
                    key: raw.get(key)
                    for key in (
                        "capture_id",
                        "request_ids",
                        "candidate_id",
                        "proof_run_id",
                        "verifier_run_id",
                        "finding_id",
                        "finding_title",
                        "lease_id",
                        "lease_owner",
                        "lease_started_at",
                        "lease_deadline",
                        "task_lease_id",
                        "attempts",
                        "updated_at",
                    )
                },
            },
        )
        if raw.get("proof_escalation_id") and raw.get("specialist"):
            normalized["specialist"] = _text(raw.get("specialist"))
        # Recompute old or missing IDs so equivalent legacy cells coalesce.
        put(_merge_cell(normalized, raw))

    # Adapt endpoint rows and their nested checks.
    for row in getattr(brain, "coverage", None) or []:
        if not isinstance(row, dict):
            continue
        checks = [item for item in (row.get("checks") or []) if isinstance(item, dict)]
        sources = checks or [{}]
        for check in sources:
            evidence_id = _text(check.get("evidence_id"))
            inventory_row = row.get("source") == "surface_inventory"
            cell = _new_cell(
                brain,
                method=row.get("method", "GET"),
                path=row.get("path", "/"),
                host=row.get("host", ""),
                operation_id=check.get("operation_id") or row.get("operation_id", ""),
                identity=(
                    check.get("identity")
                    or row.get("identity", "")
                    or ("anonymous" if inventory_row else "unspecified")
                ),
                tenant=check.get("tenant") or row.get("tenant", ""),
                parameter=check.get("parameter")
                or row.get("parameter", "")
                or "endpoint",
                test_type=(
                    check.get("test_type")
                    or row.get("test_type", "")
                    or ("surface_review" if inventory_row else "legacy_surface")
                ),
                hypothesis_id=check.get("hypothesis_id")
                or row.get("hypothesis_id", ""),
                status=check.get("status") or row.get("status", "untested"),
                source="legacy_check" if checks else "legacy_surface",
                reason=check.get("reason") or row.get("reason", ""),
                evidence_ids=[evidence_id]
                if evidence_id
                else row.get("evidence_ids", []),
                capture_id=check.get("capture_id") or row.get("capture_id", ""),
                candidate_id=check.get("candidate_id") or row.get("candidate_id", ""),
                proof_run_id=check.get("proof_run_id") or row.get("proof_run_id", ""),
                verifier_run_id=check.get("verifier_run_id")
                or row.get("verifier_run_id", ""),
                finding_id=check.get("finding_id") or row.get("finding_id", ""),
                finding_title=row.get("finding_title", ""),
                updated_at=check.get("updated_at") or row.get("updated_at", ""),
            )
            put(cell)

    # Every observed operation has operation-level and parameter-level work.
    for operation in getattr(brain, "application_operations", None) or []:
        if not isinstance(operation, dict):
            continue
        identities = operation.get("identities") or ["anonymous"]
        parameters = ["", *(operation.get("parameters") or [])]
        for identity in identities:
            for parameter in parameters:
                test_type = "input_boundary" if parameter else "operation_review"
                cell = _new_cell(
                    brain,
                    method=operation.get("method", "GET"),
                    path=operation.get("path") or operation.get("url") or "/",
                    host=operation.get("host", ""),
                    operation_id=operation.get("id", ""),
                    identity=identity,
                    parameter=parameter or "endpoint",
                    test_type=test_type,
                    hypothesis_id="operation-" + _text(operation.get("id")),
                    source="application_operation",
                )
                put(cell)

    # Authorization matrix cells are authoritative for tenant/identity boundaries.
    operations = {
        _text(op.get("id")): op
        for op in (getattr(brain, "application_operations", None) or [])
        if isinstance(op, dict)
    }
    for matrix in getattr(brain, "authorization_matrix", None) or []:
        if not isinstance(matrix, dict):
            continue
        operation = operations.get(_text(matrix.get("operation_id")), {})
        verdict = _text(matrix.get("verifier_verdict") or matrix.get("verdict")).lower()
        matrix_status = _text(matrix.get("status")).lower()
        if verdict == "confirmed":
            status = "finding"
        elif verdict == "refuted":
            status = "tested_clean"
        elif matrix_status == "blocked":
            status = "blocked"
        elif matrix_status in {"inconclusive", "tested"}:
            status = "inconclusive" if matrix_status == "inconclusive" else "in_focus"
        else:
            status = "untested"
        cell = _new_cell(
            brain,
            method=operation.get("method", "GET"),
            path=operation.get("path") or operation.get("url") or "/",
            host=operation.get("host", ""),
            operation_id=matrix.get("operation_id", ""),
            identity=matrix.get("identity", ""),
            tenant=matrix.get("tenant", ""),
            parameter=matrix.get("parameter", "") or "endpoint",
            test_type="authorization",
            hypothesis_id=matrix.get("hypothesis_id", ""),
            status=status,
            source="authorization_matrix",
            reason=matrix.get("reason", ""),
            evidence_ids=matrix.get("evidence_ids", []),
            capture_id=matrix.get("capture_id", ""),
            candidate_id=matrix.get("candidate_id", ""),
            proof_run_id=matrix.get("proof_run_id", ""),
            verifier_run_id=matrix.get("verifier_run_id", ""),
            finding_id=matrix.get("finding_id", ""),
        )
        matrix["coverage_cell_id"] = cell["id"]
        put(cell)

    # Surfaces without richer operation/check data still receive one baseline cell.
    for surface in denominator or []:
        if not isinstance(surface, dict):
            continue
        _, _, _, key = _surface_parts(
            surface.get("method", "GET"),
            surface.get("path", "/"),
            surface.get("host", ""),
        )
        if any(cell.get("surface_key") == key for cell in cells.values()):
            continue
        cell = _new_cell(
            brain,
            method=surface.get("method", "GET"),
            path=surface.get("path", "/"),
            host=surface.get("host", ""),
            identity="anonymous",
            parameter="endpoint",
            test_type="surface_review",
            status="in_focus" if surface.get("in_focus") else "untested",
            source="surface_inventory",
        )
        put(cell)

    brain.coverage_cells = sorted(
        cells.values(),
        key=lambda row: (
            row.get("surface_key", ""),
            row.get("operation_id", ""),
            row.get("identity", ""),
            row.get("parameter", ""),
            row.get("test_type", ""),
        ),
    )
    return brain.coverage_cells


def seed_parameter_coverage_cells(brain: Any, inventory: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create durable, applicable vulnerability work for observed inputs.

    Repeated mapping cannot reset a completed or leased cell. Parameters that
    carry authentication or anti-CSRF state remain in the inventory but are
    excluded from automatic injection work.
    """
    from app.services.agent.parameter_inventory import _SOURCE_RANK, parameter_priority
    from app.services.agent.vulnerability_catalog import (
        endpoint_test_classes,
        parameter_test_classes,
    )

    existing = {row.get("id"): row for row in getattr(brain, "coverage_cells", [])
                if isinstance(row, dict)}
    for raw in inventory:
        if not isinstance(raw, dict) or raw.get("testable") is not True:
            continue
        for test_type in parameter_test_classes(raw):
            specialist = _specialist_for(test_type, "", brain)
            hypothesis = next((
                h for h in getattr(brain, "hypotheses", []) or []
                if getattr(h, "specialist", "") == specialist
                and getattr(h, "status", "") in ("open", "in_progress")
            ), None)
            cell = _new_cell(
                brain,
                method=raw.get("method", "GET"), path=raw.get("path", "/"),
                host=raw.get("host", ""), identity=raw.get("identity", "anonymous"),
                parameter=f"{raw.get('location', 'query')}:{raw.get('name', '')}",
                test_type=test_type,
                hypothesis_id=getattr(hypothesis, "id", ""),
                source="parameter_inventory", capture_id=raw.get("artifact_id", ""),
            )
            cell["priority_rank"] = parameter_priority(raw, specialist)
            if test_type in {"command_injection", "ssrf", "authz"}:
                cell["priority_rank"] = 0
            elif test_type in {"stored_xss", "xxe", "race_condition"}:
                cell["priority_rank"] = 2
            cell["value_type"] = str(raw.get("value_type") or "")[:40]
            cell["observation_source"] = str(raw.get("source") or "")[:40]
            prior = existing.get(cell["id"])
            if (prior and prior.get("status") in CELL_OPEN
                    and not prior.get("lease_id")
                    and _SOURCE_RANK.get(cell["observation_source"], 0)
                    > _SOURCE_RANK.get(str(prior.get("observation_source") or ""), 0)):
                prior["observation_source"] = cell["observation_source"]
            if (prior and prior.get("status") in CELL_OPEN
                    and not prior.get("lease_id")
                    and cell["observation_source"] == "browser_traffic"
                    and cell.get("capture_id")
                    and (prior.get("observation_source") != "browser_traffic"
                         or prior.get("capture_id") != cell["capture_id"])):
                # Mapping often sees a form or link before its private browser
                # exchange. Upgrade the same work item when a replayable
                # capture arrives; never reset a completed or leased verdict.
                prior["capture_id"] = cell["capture_id"]
                prior["observation_source"] = "browser_traffic"
                prior["value_type"] = cell["value_type"] or prior.get("value_type", "")
                prior["priority_rank"] = min(
                    int(prior.get("priority_rank", 2)), cell["priority_rank"],
                )
                if (prior.get("first_pass_outcome") in {"unattempted", "inconclusive"}
                        and not (prior.get("first_pass_evidence_id")
                                 or prior.get("probe_artifact_ids")
                                 or prior.get("service_probe_artifact_ids"))):
                    prior.pop("first_pass_outcome", None)
                    prior.pop("first_pass_reason", None)
                    prior.pop("first_pass_at", None)
                    prior.pop("first_pass_handoff_error", None)
                    if prior["status"] == "inconclusive":
                        prior["status"] = "untested"
            if cell["id"] not in existing and len(existing) < MAX_COVERAGE_CELLS:
                brain.coverage_cells.append(cell)
                existing[cell["id"]] = cell
        for test_type in endpoint_test_classes(raw):
            specialist = _specialist_for(test_type, "", brain)
            hypothesis = next((
                h for h in getattr(brain, "hypotheses", []) or []
                if getattr(h, "specialist", "") == specialist
                and getattr(h, "status", "") in ("open", "in_progress")
            ), None)
            cell = _new_cell(
                brain,
                method=raw.get("method", "GET"), path=raw.get("path", "/"),
                host=raw.get("host", ""), identity=raw.get("identity", "anonymous"),
                parameter="endpoint", test_type=test_type,
                hypothesis_id=getattr(hypothesis, "id", ""),
                source="surface_applicability", capture_id=raw.get("artifact_id", ""),
            )
            cell["priority_rank"] = 2
            cell["observation_source"] = str(raw.get("source") or "")[:40]
            if cell["id"] not in existing and len(existing) < MAX_COVERAGE_CELLS:
                brain.coverage_cells.append(cell)
                existing[cell["id"]] = cell
    return migrate_coverage_cells(brain)


def verified_input_paths(brain: Any) -> set[str]:
    """Return paths with an independently confirmed input finding in this run."""
    cells = brain.get("coverage_cells", []) if isinstance(brain, dict) else getattr(brain, "coverage_cells", [])
    candidates = brain.get("candidates", []) if isinstance(brain, dict) else getattr(brain, "candidates", [])
    by_id = {row.get("id"): row for row in cells if isinstance(row, dict)}
    return {
        source["path"]
        for candidate in candidates
        if isinstance(candidate, dict)
        and (candidate.get("status") == "confirmed" or candidate.get("finding_id"))
        for source in [by_id.get(candidate.get("coverage_cell_id"), {})]
        if source.get("source") == "parameter_inventory" and source.get("path")
    }


def parameter_test_funnel(brain: Any) -> dict[str, Any]:
    """Summarize exact input tests without treating discovery as proof."""
    if isinstance(brain, dict) or brain is None:
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(brain)
    cells = [row for row in getattr(brain, "coverage_cells", []) or []
             if isinstance(row, dict) and row.get("source") in {
                 "parameter_inventory", "surface_applicability",
             }]
    candidates: dict[str, list[dict[str, Any]]] = {}
    for row in getattr(brain, "candidates", []) or []:
        if isinstance(row, dict) and row.get("coverage_cell_id"):
            candidates.setdefault(str(row["coverage_cell_id"]), []).append(row)
    counts = {key: 0 for key in (
        "checks", "attempted", "unattempted", "probed", "tested_clean",
        "proof_signals", "candidate_handoffs_pending", "service_candidate_handoffs_pending",
        "candidates", "verified", "published", "open", "blocked",
    )}
    by_class: dict[str, dict[str, int]] = {}
    inputs: set[tuple[str, str, str, str, str]] = set()
    open_rows: list[dict[str, str]] = []
    handoff_rows: list[dict[str, str]] = []
    for cell in cells:
        kind = str(cell.get("test_type") or "unknown")
        group = by_class.setdefault(kind, {key: 0 for key in counts})
        proof_signal = cell.get("first_pass_outcome") == "proof_signal"
        proof_id = str(cell.get("first_pass_evidence_id") or "")
        matching_candidates = candidates.get(str(cell.get("id") or ""), [])
        if proof_signal and proof_id:
            matching_candidates = [row for row in matching_candidates
                                   if proof_id in (row.get("evidence_ids") or [])]
        candidate = matching_candidates[-1] if matching_candidates else {}
        handoff_pending = bool(proof_signal and proof_id and not candidate)
        service_handoff = handoff_pending and (
            cell.get("first_pass_evidence_source") == "service"
            or (not cell.get("first_pass_evidence_source")
                and proof_id in (cell.get("service_probe_artifact_ids") or []))
        )
        status = str(cell.get("status") or "untested")
        has_probe = bool(cell.get("service_probe_artifact_ids") or
                         cell.get("probe_artifact_ids") or
                         cell.get("first_pass_evidence_id") or
                         candidate.get("evidence_ids"))
        attempted = has_probe or cell.get("first_pass_outcome") in {
            "proof_signal", "tested_clean", "inconclusive",
        } or (status in {"tested_clean", "finding"} and bool(cell.get("evidence_ids")))
        checks = {
            "checks": True,
            "attempted": attempted,
            "unattempted": not attempted,
            "probed": has_probe or (
                status in {"tested_clean", "finding"} and bool(cell.get("evidence_ids"))
            ),
            "tested_clean": status == "tested_clean",
            "proof_signals": proof_signal,
            "candidate_handoffs_pending": handoff_pending,
            "service_candidate_handoffs_pending": service_handoff,
            "candidates": bool(candidate),
            "verified": candidate.get("status") == "confirmed",
            "published": bool(cell.get("finding_id") or candidate.get("finding_id")),
            "open": status not in CELL_TERMINAL,
            "blocked": status == "blocked",
        }
        for key, matched in checks.items():
            if matched:
                counts[key] += 1
                group[key] += 1
        inputs.add(tuple(str(cell.get(key) or "") for key in (
            "host", "method", "path", "identity", "parameter",
        )))
        if checks["open"] and len(open_rows) < 20:
            open_rows.append({
                "method": str(cell.get("method") or "GET"),
                "path": str(cell.get("path") or "/"),
                "parameter": str(cell.get("parameter") or ""),
                "test_type": kind,
                "status": status,
                "reason": str(cell.get("reason") or "")[:160],
            })
        if handoff_pending and len(handoff_rows) < 20:
            handoff_rows.append({
                "coverage_cell_id": str(cell.get("id") or ""),
                "method": str(cell.get("method") or "GET"),
                "path": str(cell.get("path") or "/"),
                "parameter": str(cell.get("parameter") or ""),
                "test_type": kind,
                "evidence_id": proof_id,
                "evidence_source": "service" if service_handoff else "local",
                "error": str(cell.get("first_pass_candidate_handoff_error") or "")[:160],
            })
    return {
        "inputs": len(inputs), **counts, "by_class": by_class,
        "classes_planned": len(by_class),
        "classes_without_probes": sorted(
            kind for kind, group in by_class.items() if group["probed"] == 0
        ),
        "open_rows": open_rows, "handoff_rows": handoff_rows,
    }


def seed_js_coverage_cells(brain: Any, cmap: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep durable review cells for observed scripts and their passive leads."""
    target = urlsplit(str(cmap.get("target") or ""))
    if target.scheme not in {"http", "https"} or not target.netloc:
        return migrate_coverage_cells(brain)
    sources = {
        str(row.get("url")): row
        for row in (cmap.get("js_sources") or [])[:160]
        if isinstance(row, dict) and row.get("kind") != "inline"
        and isinstance(row.get("url"), str)
    }
    existing = {row.get("id") for row in getattr(brain, "coverage_cells", []) if isinstance(row, dict)}
    hypothesis = next((
        h for h in getattr(brain, "hypotheses", []) or []
        if getattr(h, "specialist", "") == "js_secrets"
        and getattr(h, "status", "") in {"open", "in_progress"}
    ), None)
    for url in (cmap.get("js_files") or [])[:160]:
        parts = urlsplit(str(url))
        if (parts.scheme, parts.netloc) != (target.scheme, target.netloc) or not parts.path:
            continue
        script_url = f"{parts.scheme}://{parts.netloc}{parts.path}"
        source = sources.get(script_url) or {}
        cell = _new_cell(
            brain, method="GET", path=parts.path, host=parts.netloc,
            identity="anonymous", parameter="script", test_type="js_secret_review",
            hypothesis_id=getattr(hypothesis, "id", ""), source="js_inventory",
            capture_id=source.get("artifact_id", ""),
        )
        cell["script_url"] = script_url
        cell["expected_sha256"] = str(source.get("sha256") or "")[:64]
        cell["priority_rank"] = 0 if any(hint in parts.path.lower() for hint in ("_next/", "admin", "main", "chunk")) else 1
        if cell["id"] not in existing and len(existing) < MAX_COVERAGE_CELLS:
            brain.coverage_cells.append(cell)
            existing.add(cell["id"])
        if re.search(r"(?:^|[/_.-])\d+[._-]\d+(?:[._-]\d+)?(?:[._-]|\.js$)", parts.path, re.I):
            dependency = _new_cell(
                brain, method="GET", path=parts.path, host=parts.netloc,
                identity="anonymous", parameter="script", test_type="js_dependency_review",
                source="js_inventory", capture_id=source.get("artifact_id", ""),
            )
            dependency["script_url"] = script_url
            dependency["priority_rank"] = 2
            if dependency["id"] not in existing and len(existing) < MAX_COVERAGE_CELLS:
                brain.coverage_cells.append(dependency)
                existing.add(dependency["id"])
    client_classes = {
        "dom_open_redirect": "dom_open_redirect",
        "dom_link_manipulation": "dom_link_manipulation",
        "dom_data_manipulation": "dom_data_manipulation",
        "request_url_override": "request_url_override",
        "client_template_injection": "client_template_injection",
        "prototype_pollution": "client_prototype_pollution",
    }
    for source in (cmap.get("js_sources") or [])[:160]:
        if not isinstance(source, dict):
            continue
        parts = urlsplit(str(source.get("url") or ""))
        if (parts.scheme, parts.netloc) != (target.scheme, target.netloc) or not parts.path:
            continue
        script_url = f"{parts.scheme}://{parts.netloc}{parts.path}"
        inline = source.get("kind") == "inline"
        parameter = f"inline_script:{source.get('index', 0)}" if inline else "script"
        source_leads = list(source.get("source_leads") or [])[:10]
        sink_leads = list(source.get("sink_leads") or [])[:30]
        if source_leads and any(
            isinstance(lead, dict) and lead.get("kind") in {"html_assignment", "dynamic_code"}
            for lead in sink_leads
        ):
            dom = _new_cell(
                brain, method="GET", path=parts.path, host=parts.netloc,
                identity="anonymous", parameter=parameter, test_type="dom_xss",
                source="js_inventory", capture_id=source.get("artifact_id", ""),
            )
            dom["script_url"] = script_url
            dom["script_kind"] = "inline" if inline else "external"
            dom["page_path"] = str(source.get("page_path") or (parts.path if inline else ""))[:512]
            dom["source_leads"] = source_leads
            dom["sink_leads"] = sink_leads
            dom["priority_rank"] = 2
            if dom["id"] not in existing and len(existing) < MAX_COVERAGE_CELLS:
                brain.coverage_cells.append(dom)
                existing.add(dom["id"])
        for lead in (source.get("client_leads") or [])[:18]:
            kind = client_classes.get(lead.get("kind")) if isinstance(lead, dict) else None
            if not kind or not source_leads:
                continue
            cell = _new_cell(
                brain, method="GET", path=parts.path, host=parts.netloc,
                identity="anonymous", parameter=parameter, test_type=kind,
                source="js_inventory", capture_id=source.get("artifact_id", ""),
            )
            cell["script_url"] = script_url
            cell["script_kind"] = "inline" if inline else "external"
            cell["source_leads"] = source_leads
            cell["client_leads"] = [lead]
            cell["priority_rank"] = 2
            if cell["id"] not in existing and len(existing) < MAX_COVERAGE_CELLS:
                brain.coverage_cells.append(cell)
                existing.add(cell["id"])
    return migrate_coverage_cells(brain)


def record_coverage_cell(
    brain: Any,
    *,
    method: str,
    path: str,
    host: str = "",
    status: str,
    identity: str = "",
    tenant: str = "",
    parameter: str = "",
    test_type: str = "",
    operation_id: str = "",
    hypothesis_id: str = "",
    evidence_id: str = "",
    reason: str = "",
    coverage_cell_id_value: str = "",
    coverage_lease_id: str = "",
    **trace: Any,
) -> dict[str, Any]:
    """Upsert one exact cell and enforce lease ownership when a lease is cited."""
    migrate_coverage_cells(brain)
    proposed = _new_cell(
        brain,
        method=method,
        path=path,
        host=host,
        operation_id=operation_id,
        identity=identity,
        tenant=tenant,
        parameter=parameter,
        test_type=test_type,
        hypothesis_id=hypothesis_id,
        status=status,
        reason=reason,
        evidence_ids=[evidence_id] if evidence_id else [],
        source="record_surface_coverage",
        **trace,
    )
    wanted = _text(coverage_cell_id_value)
    if not wanted and not any(
        cell.get("id") == proposed["id"] for cell in brain.coverage_cells
    ):
        # An old snapshot may only have an endpoint-level legacy cell.  Let an
        # old-style endpoint update close that exact migrated cell instead of
        # creating a second baseline beside it.
        legacy = [
            cell
            for cell in brain.coverage_cells
            if cell.get("surface_key") == proposed["surface_key"]
            and cell.get("source") == "legacy_surface"
            and cell.get("parameter") == "endpoint"
        ]
        if len(legacy) == 1:
            wanted = legacy[0]["id"]
    if wanted and wanted != proposed["id"]:
        # Permit callers to provide only the stable ID and inherit its dimensions.
        existing = next(
            (c for c in brain.coverage_cells if c.get("id") == wanted), None
        )
        if existing is None:
            raise ValueError("Unknown coverage_cell_id")
        proposed = _new_cell(
            brain,
            method=existing.get("method", method),
            path=existing.get("path", path),
            host=existing.get("host", host),
            operation_id=existing.get("operation_id", operation_id),
            identity=existing.get("identity", identity),
            tenant=existing.get("tenant", tenant),
            parameter=existing.get("parameter", parameter),
            test_type=existing.get("test_type", test_type),
            hypothesis_id=existing.get("hypothesis_id", hypothesis_id),
            status=status,
            reason=reason,
            evidence_ids=[evidence_id] if evidence_id else [],
            source="record_surface_coverage",
            **trace,
        )
    existing = next(
        (c for c in brain.coverage_cells if c.get("id") == proposed["id"]), None
    )
    if coverage_lease_id and (
        not existing or existing.get("lease_id") != coverage_lease_id
    ):
        raise ValueError(
            "Coverage lease is missing, expired, or belongs to another executor"
        )
    updated = _merge_cell(existing or proposed, proposed)
    updated["status"] = _status(status)
    updated["reason"] = _text(reason)[:500]
    if evidence_id:
        updated["evidence_ids"] = list(
            dict.fromkeys([*(updated.get("evidence_ids") or []), evidence_id])
        )
    for key in (
        "capture_id",
        "candidate_id",
        "proof_run_id",
        "verifier_run_id",
        "finding_id",
        "finding_title",
    ):
        if trace.get(key) not in (None, ""):
            updated[key] = _text(trace.get(key))
    if updated["status"] in CELL_TERMINAL or coverage_lease_id:
        for key, value in (
            ("lease_id", ""),
            ("lease_owner", ""),
            ("lease_started_at", 0.0),
            ("lease_deadline", 0.0),
            ("task_lease_id", ""),
        ):
            updated[key] = value
    brain.coverage_cells = [
        updated if cell.get("id") == updated["id"] else cell
        for cell in brain.coverage_cells
    ]
    if not any(cell.get("id") == updated["id"] for cell in brain.coverage_cells):
        brain.coverage_cells.append(updated)
    return updated


@dataclass(frozen=True)
class CoverageCellLease:
    id: str
    coverage_cell_id: str
    specialist: str
    hypothesis_id: str
    task_lease_id: str
    attempt: int
    started_at: float
    deadline: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def recover_expired_coverage_leases(
    brain: Any, *, now: float | None = None
) -> list[str]:
    current = time.time() if now is None else float(now)
    recovered = []
    for cell in getattr(brain, "coverage_cells", None) or []:
        if (
            cell.get("status") == "leased"
            and cell.get("lease_id")
            and float(cell.get("lease_deadline") or 0) <= current
        ):
            cell.update(
                status="inconclusive",
                reason="Coverage lease expired before a terminal receipt was recorded",
                lease_id="",
                lease_owner="",
                lease_started_at=0.0,
                lease_deadline=0.0,
                task_lease_id="",
            )
            recovered.append(cell["id"])
    return recovered


def claim_coverage_cell_leases(
    brain: Any,
    specialists: Iterable[str],
    *,
    task_leases: dict[str, Any] | None = None,
    denominator: Iterable[dict[str, Any]] | None = None,
    allowed_observation_sources: frozenset[str] | None = None,
    allowed_sources: frozenset[str] | None = None,
    excluded_test_types: frozenset[str] | None = None,
    allowed_test_types: frozenset[str] | None = None,
    allowed_cell_ids: frozenset[str] | None = None,
    first_pass_only: bool = False,
    lease_seconds: int = 3600,
    now: float | None = None,
) -> dict[str, CoverageCellLease]:
    """Lease one exact cell per specialist, preferring its task hypothesis."""
    migrate_coverage_cells(brain, denominator=denominator)
    current = time.time() if now is None else float(now)
    recover_expired_coverage_leases(brain, now=current)
    focus_paths = verified_input_paths(brain)
    leases: dict[str, CoverageCellLease] = {}
    for specialist in dict.fromkeys(_text(item) for item in specialists if _text(item)):
        task = (task_leases or {}).get(specialist)
        hypothesis_id = _text(
            getattr(task, "hypothesis_id", "")
            or (task.get("hypothesis_id", "") if isinstance(task, dict) else "")
        )
        task_lease_id = _text(
            getattr(task, "id", "")
            or (task.get("id", "") if isinstance(task, dict) else "")
        )
        candidates = [
            cell
            for cell in brain.coverage_cells
            if cell.get("status") in CELL_OPEN
            and not cell.get("lease_id")
            and (not allowed_sources or cell.get("source") in allowed_sources)
            and (not excluded_test_types or cell.get("test_type") not in excluded_test_types)
            and (allowed_cell_ids is None or cell.get("id") in allowed_cell_ids)
            and (not first_pass_only or not (
                cell.get("first_pass_outcome") or cell.get("candidate_id")
                or cell.get("probe_artifact_ids") or cell.get("service_probe_artifact_ids")
            ))
            and (allowed_test_types is None or cell.get("test_type") in allowed_test_types)
            and (
                allowed_observation_sources is None
                or (
                    cell.get("source") == "parameter_inventory"
                    and cell.get("observation_source") in allowed_observation_sources
                )
            )
            and (
                cell.get("specialist") == specialist
                or (hypothesis_id and cell.get("hypothesis_id") == hypothesis_id)
            )
        ]
        candidates.sort(
            key=lambda cell: (
                # A positive proof belongs with candidate verification, not
                # another manual specialist probing the same input.
                int(bool(cell.get("candidate_id") or cell.get("finding_id")
                         or cell.get("first_pass_outcome") == "proof_signal")),
                # Give untouched SQLi/XSS inputs a turn before deeper probes
                # on an input that already has a first-pass receipt.
                int(bool(cell.get("first_pass_outcome")))
                if specialist in {"sqli", "xss"} else 0,
                int(cell.get("attempts") or 0) if first_pass_only else 0,
                0 if cell.get("path") in focus_paths else 1,
                int(cell.get("priority_rank", 2)),
                0 if specialist in {"xss", "sqli"} and scoped_replay_eligible(cell) else 1,
                0
                if hypothesis_id and cell.get("hypothesis_id") == hypothesis_id
                else 1,
                0 if cell.get("proof_escalation_id") else 1,
                int(cell.get("attempts") or 0),
                cell.get("surface_key", ""),
                cell.get("identity", ""),
                cell.get("parameter", ""),
            )
        )
        if not candidates:
            continue
        cell = candidates[0]
        lease_id = uuid.uuid4().hex
        cell.update(
            status="leased",
            lease_id=lease_id,
            lease_owner=specialist,
            lease_started_at=current,
            lease_deadline=current + max(60, int(lease_seconds)),
            task_lease_id=task_lease_id,
            attempts=int(cell.get("attempts") or 0) + 1,
        )
        leases[specialist] = CoverageCellLease(
            id=lease_id,
            coverage_cell_id=cell["id"],
            specialist=specialist,
            hypothesis_id=_text(cell.get("hypothesis_id") or hypothesis_id),
            task_lease_id=task_lease_id,
            attempt=cell["attempts"],
            started_at=current,
            deadline=cell["lease_deadline"],
        )
    return leases


def release_coverage_cell_lease(
    brain: Any,
    lease: CoverageCellLease | dict[str, Any],
    *,
    verdict: str = "inconclusive",
    evidence_ids: Iterable[str] | None = None,
    candidate_id: str = "",
    reason: str = "",
) -> dict[str, Any] | None:
    lease_id = _text(
        getattr(lease, "id", "") or (lease.get("id") if isinstance(lease, dict) else "")
    )
    cell_id = _text(
        getattr(lease, "coverage_cell_id", "")
        or (lease.get("coverage_cell_id") if isinstance(lease, dict) else "")
    )
    cell = next(
        (c for c in getattr(brain, "coverage_cells", []) if c.get("id") == cell_id),
        None,
    )
    if not cell or cell.get("lease_id") != lease_id:
        return None
    ids = list(dict.fromkeys(_text(v) for v in (evidence_ids or []) if _text(v)))
    cell["evidence_ids"] = list(
        dict.fromkeys([*(cell.get("evidence_ids") or []), *ids])
    )
    if candidate_id:
        cell["candidate_id"] = _text(candidate_id)
    if cell.get("status") == "leased":
        # A report can cite unrelated discovery evidence. Only the explicit
        # record_surface_coverage tool validates a negative receipt and closes
        # a cell; a summary alone cannot claim that this input was tested.
        if _text(verdict).lower() == "proven":
            cell["status"] = "in_focus"
        else:
            cell["status"] = "inconclusive"
        cell["reason"] = (
            _text(reason)[:500]
            or f"executor verdict={_text(verdict) or 'inconclusive'}"
        )
    cell.update(
        lease_id="",
        lease_owner="",
        lease_started_at=0.0,
        lease_deadline=0.0,
        task_lease_id="",
    )
    return cell


def trace_for_cell(brain: Any, cell_id: str) -> dict[str, Any]:
    cell = next(
        (
            row
            for row in getattr(brain, "coverage_cells", None) or []
            if row.get("id") == cell_id
        ),
        None,
    )
    if not cell:
        return {}
    return {
        key: cell.get(key, "")
        for key in (
            "operation_id",
            "hypothesis_id",
            "identity",
            "tenant",
            "parameter",
            "test_type",
            "candidate_id",
            "proof_run_id",
            "proof_escalation_id",
            "verifier_run_id",
            "finding_id",
        )
    } | {"coverage_cell_id": cell["id"]}
