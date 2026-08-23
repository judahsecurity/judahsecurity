"""Durable run snapshots so a restart does not wipe the engagement brain.

LangGraph MemorySaver stays in-process. This writes capability_map + brain +
todos next to ~/.aegis/sessions so the next invoke of the same session_id
resumes the tester loop instead of starting cold.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_DIR = Path.home() / ".aegis" / "sessions"
_SAFE = re.compile(r"[^a-zA-Z0-9._-]+")


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
    payload = {
        "engagement_brain": state.get("engagement_brain"),
        "capability_map": state.get("capability_map"),
        "todo_list": state.get("todo_list"),
        "current_phase": state.get("current_phase"),
        "auth_session": state.get("auth_session"),
        "original_objective": state.get("original_objective"),
    }
    if not payload["engagement_brain"] and not payload["capability_map"]:
        return
    try:
        _DIR.mkdir(parents=True, exist_ok=True)
        _path(int(organization_id), session_id).write_text(
            json.dumps(payload, default=str)[:2_000_000],
            encoding="utf-8",
        )
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
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        logger.debug("run snapshot load skipped", exc_info=True)
        return {}
