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
_SCHEMA_VERSION = 2


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
        # Primary production checkpoint: organization-scoped PostgreSQL row.
        # Keep the local file below as a single-node fallback for development and
        # for upgrades where the migration has not run yet.
        try:
            from app.services.agent.runtime_store import safe_call

            safe_call(
                "save_checkpoint",
                int(organization_id),
                session_id,
                json.loads(encoded.decode("utf-8")),
                schema_version=_SCHEMA_VERSION,
            )
        except Exception:
            logger.debug("database run checkpoint skipped", exc_info=True)
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
    try:
        from app.services.agent.runtime_store import safe_call

        durable = safe_call("load_checkpoint", int(organization_id), session_id)
        if isinstance(durable, dict) and durable:
            return durable
    except Exception:
        logger.debug("database run checkpoint load skipped", exc_info=True)
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
        if version not in (1, _SCHEMA_VERSION):
            return {}
        # Legacy snapshots may contain bearer tokens and cookies. They are not
        # execution authority after a process restart.
        if data.pop("auth_session", None):
            data["reauthentication_required"] = True
        brain = data.get("engagement_brain")
        if isinstance(brain, dict) and brain.get("credentials"):
            brain["credentials"] = []
            data["reauthentication_required"] = True
        return data
    except Exception:
        logger.debug("run snapshot load skipped", exc_info=True)
        return {}
