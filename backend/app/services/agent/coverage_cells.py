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
    kind = _text(test_type).lower()
    if kind in {"authorization", "auth", "authz", "csrf", "business_logic"}:
        return "auth_logic"
    if "xss" in kind:
        return "xss"
    if "sql" in kind:
        return "sqli"
    if "ssrf" in kind or "url_fetch" in kind:
        return "ssrf"
    if "path" in kind or "command" in kind or kind == "input_boundary":
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
    lease_seconds: int = 3600,
    now: float | None = None,
) -> dict[str, CoverageCellLease]:
    """Lease one exact cell per specialist, preferring its task hypothesis."""
    migrate_coverage_cells(brain, denominator=denominator)
    current = time.time() if now is None else float(now)
    recover_expired_coverage_leases(brain, now=current)
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
            and (
                cell.get("specialist") == specialist
                or (hypothesis_id and cell.get("hypothesis_id") == hypothesis_id)
            )
        ]
        candidates.sort(
            key=lambda cell: (
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
        # A summary cannot invent terminal coverage.  Only a cited clean result or
        # publication can close the cell; a hunter's signal remains in focus.
        if _text(verdict).lower() == "killed" and ids:
            cell["status"] = "tested_clean"
            escalation_id = _text(cell.get("proof_escalation_id"))
            if escalation_id:
                for escalation in getattr(brain, "proof_escalations", None) or []:
                    if escalation.get("id") == escalation_id:
                        escalation.update(
                            status="refuted",
                            refuted_by="evidence_backed_specialist_control",
                            evidence_ids=list(
                                dict.fromkeys(
                                    [*(escalation.get("evidence_ids") or []), *ids]
                                )
                            ),
                        )
        elif _text(verdict).lower() == "proven":
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
