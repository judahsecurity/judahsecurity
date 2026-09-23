"""Durable run snapshots so a restart does not wipe the engagement brain.

LangGraph MemorySaver stays in-process. This writes capability_map + brain +
todos next to ~/.aegis/sessions so the next invoke of the same session_id
resumes the tester loop instead of starting cold.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_DIR = Path.home() / ".aegis" / "sessions"
_SAFE = re.compile(r"[^a-zA-Z0-9._-]+")
_MAX_SNAPSHOT_BYTES = 2_000_000
_SCHEMA_VERSION = 3


def _recover_brain_after_restart(brain: Any) -> Any:
    """Quarantine interrupted leases and requeue unfinished proof verification."""
    if not isinstance(brain, dict):
        return brain
    recovered = 0
    graph = brain.get("task_graph") or {}
    nodes = graph.get("nodes") or {}
    if isinstance(nodes, dict):
        for node in nodes.values():
            if not isinstance(node, dict) or node.get("status") != "running":
                continue
            node.update(
                status="blocked",
                recovery_required=True,
                blocked_reason=(
                    "Backend restarted during an execution lease; reconcile durable "
                    "evidence before retrying"
                ),
                last_failure="execution interrupted by backend restart",
                lease_id="",
                lease_owner="",
                lease_started_at=0.0,
                lease_deadline=0.0,
            )
            recovered += 1

    for cell in brain.get("coverage_cells") or []:
        if not isinstance(cell, dict) or cell.get("status") != "leased":
            continue
        cell.update(
            status="inconclusive",
            reason="Backend restarted before the coverage lease produced a terminal receipt",
            lease_id="",
            lease_owner="",
            lease_started_at=0.0,
            lease_deadline=0.0,
            task_lease_id="",
        )
        recovered += 1

    candidates = {
        str(row.get("id") or ""): row
        for row in (brain.get("candidates") or [])
        if isinstance(row, dict) and row.get("id")
    }
    durable_receipts = {
        str(row.get("candidate_id") or ""): row
        for row in (brain.get("verification_receipts") or {}).values()
        if isinstance(row, dict) and row.get("candidate_id")
    }
    for candidate_id, candidate in candidates.items():
        if candidate.get("status") != "confirmed":
            continue
        receipt = durable_receipts.get(candidate_id) or {}
        receipt_is_complete = (
            receipt.get("verdict") == "confirmed"
            and receipt.get("run_id") == candidate.get("verifier_run_id")
            and receipt.get("revision") == candidate.get("revision")
            and receipt.get("nonce") == candidate.get("nonce")
            and receipt.get("nonce_observed") is True
            and bool(receipt.get("evidence_ids"))
        )
        if receipt_is_complete:
            continue
        candidate.update(
            status="pending",
            verifier_run_id="",
            verified_at="",
            verifier_evidence="",
            verifier_summary=(
                "Restart recovery: durable verifier receipt was incomplete; reverify"
            ),
        )
        for cell in brain.get("coverage_cells") or []:
            if isinstance(cell, dict) and cell.get("candidate_id") == candidate_id:
                cell["verifier_run_id"] = ""
                if cell.get("status") != "finding":
                    cell["status"] = "in_focus"
        recovered += 1
    for escalation in brain.get("proof_escalations") or []:
        if not isinstance(escalation, dict) or escalation.get("status") != "verifying":
            continue
        candidate = candidates.get(str(escalation.get("candidate_id") or "")) or {}
        candidate_status = str(candidate.get("status") or "")
        if candidate_status == "confirmed":
            escalation["status"] = "confirmed"
        elif candidate_status == "refuted":
            escalation["status"] = "refuted"
        else:
            escalation.update(
                status="pending",
                recovery_reason="Verifier execution was interrupted by backend restart",
            )
        recovered += 1

    if recovered:
        notes = list(brain.get("notes") or [])
        note = f"Recovered {recovered} interrupted lease/proof record(s) after restart."
        if note not in notes:
            notes.append(note)
        brain["notes"] = notes[-200:]
    return brain


def _path(organization_id: int, session_id: str) -> Path:
    sid = _SAFE.sub("_", (session_id or "")[:80]).strip("_") or "session"
    return _DIR / f"{int(organization_id)}_{sid}.json"


def save_run_snapshot(
    organization_id: Optional[int],
    session_id: Optional[str],
    state: Optional[Dict[str, Any]],
) -> None:
    if not organization_id or not session_id or not isinstance(state, dict):
        return
    from app.services.agent.observability import redact_value

    brain = deepcopy(state.get("engagement_brain"))
    reauthentication_required = False
    if isinstance(brain, dict) and brain.get("credentials"):
        reauthentication_required = True
        brain["credentials"] = []
        notes = list(brain.get("notes") or [])
        note = "Credentials were omitted from the restart snapshot; register identities again."
        if note not in notes:
            notes.append(note)
        brain["notes"] = notes[-200:]
    if state.get("auth_session"):
        reauthentication_required = True
    payload = redact_value({
        "schema_version": _SCHEMA_VERSION,
        "saved_at": time.time(),
        "engagement_brain": brain,
        "capability_map": state.get("capability_map"),
        "todo_list": state.get("todo_list"),
        "current_phase": state.get("current_phase"),
        "original_objective": state.get("original_objective"),
        "reauthentication_required": reauthentication_required,
    })
    if not payload["engagement_brain"] and not payload["capability_map"]:
        return
    try:
        encoded = json.dumps(payload, default=str, separators=(",", ":")).encode()
        if len(encoded) > _MAX_SNAPSHOT_BYTES:
            logger.warning("run snapshot exceeds %d bytes; prior snapshot retained", _MAX_SNAPSHOT_BYTES)
            return
        _DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(_DIR, 0o700)
        destination = _path(int(organization_id), session_id)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except Exception:
        logger.debug("run snapshot save skipped", exc_info=True)


def load_run_snapshot(
    organization_id: Optional[int],
    session_id: Optional[str],
) -> Dict[str, Any]:
    if not organization_id or not session_id:
        return {}
    path = _path(int(organization_id), session_id)
    if not path.is_file():
        return {}
    try:
        if path.stat().st_size > _MAX_SNAPSHOT_BYTES:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        version = data.get("schema_version", 1)
        if version not in (1, 2, _SCHEMA_VERSION):
            return {}
        # Legacy snapshots may contain bearer tokens and cookies. They are not
        # execution authority after a process restart.
        if data.pop("auth_session", None):
            data["reauthentication_required"] = True
        brain = data.get("engagement_brain")
        if isinstance(brain, dict) and brain.get("credentials"):
            brain["credentials"] = []
            data["reauthentication_required"] = True
        data["engagement_brain"] = _recover_brain_after_restart(brain)
        return data
    except Exception:
        logger.debug("run snapshot load skipped", exc_info=True)
        return {}
