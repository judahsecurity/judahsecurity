"""Hindsight notes: what analysts already ruled out, shown before the agent retests it.

A note is derived, never written by a model. Each one comes from an agent
finding that an analyst triaged as a false positive in the same organization:

* the finding's status is ``false_positive``, or
* it is linked to an active (approved, unexpired) ``false_positive`` exception.

Automated validator verdicts are not used: only analyst decisions teach.

Notes are computed on read, so a reversed decision (finding reopened, exception
rejected or expired) removes the note on the next run with nothing to clean up.

Notes are grouped by root cause (class, normalized endpoint, parameter), capped
at :data:`MAX_NOTES` / :data:`MAX_CHARS`, and sealed as untrusted data because
titles and justifications can carry target text.

Org switch ``hindsight_mode``: ``"shadow"`` (default) computes and logs the
notes without showing them to the agent, ``"inject"`` adds them to the prompt,
``"off"`` skips the lookup.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

MAX_NOTES = 8
MAX_CHARS = 1800
_REASON_CHARS = 160
_AGENT_SOURCES = ("agent", "llm_red_team")
MODES = ("off", "shadow", "inject")


@dataclass(frozen=True)
class HindsightNote:
    key: str
    title: str
    endpoint: str
    reason: str
    finding_id: int

    def line(self) -> str:
        reason = f" Analyst: {self.reason}" if self.reason else ""
        return f"- [{self.key}] {self.title} @ {self.endpoint} (finding #{self.finding_id}).{reason}"


def hindsight_mode(agent_config: Optional[dict]) -> str:
    mode = str((agent_config or {}).get("hindsight_mode") or "shadow").lower()
    return mode if mode in MODES else "shadow"


def _clip(text: Any, limit: int) -> str:
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def note_from_row(row: dict) -> Optional[HindsightNote]:
    """Build a note from a plain finding dict (pure, used by tests and the loader)."""
    from app.services.agent.independent_verify import normalized_endpoint, root_cause_key

    trace = (row.get("metadata") or {}).get("trace") or {}
    endpoint_src = row.get("affected_component") or row.get("asset") or ""
    endpoint = normalized_endpoint(str(endpoint_src)) if endpoint_src else ""
    klass = trace.get("test_type") or row.get("cwe_id") or ""
    key = root_cause_key(klass, str(endpoint_src), trace.get("parameter") or "") if klass else ""
    if not key:
        title_key = _clip(row.get("title"), 80).lower()
        key = f"title|{endpoint}|{title_key}" if endpoint else f"title|{title_key}"
    return HindsightNote(
        key=key,
        title=_clip(row.get("title") or "Agent finding", 120),
        endpoint=endpoint or "unknown",
        reason=_clip(row.get("reason"), _REASON_CHARS),
        finding_id=int(row.get("id") or 0),
    )


def build_notes(rows: Iterable[dict]) -> list[HindsightNote]:
    """Dedup by root cause (newest first wins) and apply the caps."""
    notes: list[HindsightNote] = []
    seen: set[str] = set()
    used = 0
    for row in rows:
        note = note_from_row(row)
        if note is None or note.key in seen:
            continue
        cost = len(note.line()) + 1
        if len(notes) >= MAX_NOTES or used + cost > MAX_CHARS:
            break
        seen.add(note.key)
        notes.append(note)
        used += cost
    return notes


def format_hindsight(notes: list[HindsightNote]) -> str:
    if not notes:
        return ""
    from app.services.agent.content_shield import seal

    body = "\n".join(n.line() for n in notes)
    return (
        "## Hindsight — analysts already ruled these out\n"
        "Earlier agent findings below were triaged as false positives in this organization. "
        "Do not report the same root cause again unless you demonstrate a different "
        "mechanism with new evidence; say what is new in the candidate.\n"
        + seal(body)
    )


def load_rows(db: Any, organization_id: int, *, limit: int = 60) -> list[dict]:
    """Agent findings an analyst marked false positive, newest first."""
    from sqlalchemy import or_

    from app.models.asset import Asset
    from app.models.finding_exception import ExceptionType, FindingException
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    query = (
        db.query(Vulnerability, Asset.value, FindingException)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .outerjoin(FindingException, Vulnerability.exception_id == FindingException.id)
        .filter(Asset.organization_id == organization_id)
        .filter(Vulnerability.detected_by.in_(_AGENT_SOURCES))
        .filter(or_(
            Vulnerability.status == VulnerabilityStatus.FALSE_POSITIVE,
            FindingException.exception_type == ExceptionType.FALSE_POSITIVE,
        ))
        .order_by(Vulnerability.updated_at.desc())
        .limit(limit)
    )
    rows: list[dict] = []
    for vuln, asset_value, exc in query.all():
        status = getattr(vuln.status, "value", vuln.status)
        active_fp_exception = (
            exc is not None and exc.exception_type == ExceptionType.FALSE_POSITIVE
            and exc.is_active
        )
        if status != "false_positive" and not active_fp_exception:
            continue  # exception rejected or expired, or the finding was reopened
        rows.append({
            "id": vuln.id,
            "title": vuln.title,
            "affected_component": vuln.affected_component,
            "asset": asset_value,
            "cwe_id": vuln.cwe_id,
            "metadata": vuln.metadata_ or {},
            "reason": (exc.justification if active_fp_exception else "") or "",
        })
    return rows


def hindsight_brief(organization_id: Optional[int], agent_config: Optional[dict] = None) -> tuple[str, str, int]:
    """Return ``(mode, prompt_block, note_count)``. The block is empty unless mode is inject."""
    if organization_id is None:
        return hindsight_mode(agent_config), "", 0
    try:
        from app.db.database import SessionLocal

        db = SessionLocal()
        try:
            if agent_config is None:
                from app.models.project_settings import MODULE_AGENT, ProjectSettings

                agent_config = ProjectSettings.get_config(db, organization_id, MODULE_AGENT) or {}
            mode = hindsight_mode(agent_config)
            if mode == "off":
                return mode, "", 0
            notes = build_notes(load_rows(db, organization_id))
        finally:
            db.close()
    except Exception:
        logger.warning("hindsight notes unavailable for org %s", organization_id, exc_info=True)
        return hindsight_mode(agent_config), "", 0
    logger.info("hindsight: org=%s mode=%s notes=%d keys=%s", organization_id, mode,
                len(notes), [n.key for n in notes])
    return mode, (format_hindsight(notes) if mode == "inject" else ""), len(notes)


__all__ = [
    "HindsightNote",
    "MAX_CHARS",
    "MAX_NOTES",
    "build_notes",
    "format_hindsight",
    "hindsight_brief",
    "hindsight_mode",
    "load_rows",
    "note_from_row",
]
