"""Remediation retest: turn a revalidation verdict into a fix conclusion.

A *validation* asks "was this detection right?". A *retest* asks "is the
issue still there after the fix?" and runs the same replay. The conclusion is
one of:

* ``still_reproducible`` — the replay reproduced the issue.
* ``fixed`` — the replay ran cleanly, did not reproduce it, and the
  validator is at least medium-confident. Only this outcome resolves the
  finding automatically.
* ``cannot_confirm`` — anything else (errors, low confidence, a logical
  mismatch that questions the original detection, an unreachable target).
  Status is left alone; an analyst decides.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

PURPOSE_VALIDATE = "validate"
PURPOSE_RETEST = "retest"

STILL_REPRODUCIBLE = "still_reproducible"
FIXED = "fixed"
CANNOT_CONFIRM = "cannot_confirm"
OUTCOMES = (STILL_REPRODUCIBLE, FIXED, CANNOT_CONFIRM)

_MAX_HISTORY = 20


def retest_outcome(verdict_data: Optional[dict]) -> str:
    if not isinstance(verdict_data, dict):
        return CANNOT_CONFIRM
    verdict = str(verdict_data.get("verdict") or "").lower()
    still_open = verdict_data.get("still_open")
    confidence = str(verdict_data.get("confidence") or "").lower()
    if verdict_data.get("error") or verdict_data.get("logical_mismatch"):
        return CANNOT_CONFIRM
    if still_open is True or (still_open is None and verdict == "confirmed"):
        return STILL_REPRODUCIBLE
    if still_open is False and verdict != "confirmed" and confidence in ("high", "medium"):
        return FIXED
    return CANNOT_CONFIRM


def apply_retest_outcome(vuln: Any, validation: Any, outcome: str, *, now: Optional[datetime] = None) -> Optional[str]:
    """Update the finding for a retest outcome; return the new status value if it changed.

    ``fixed`` resolves an open, in-progress or mitigated finding.
    ``still_reproducible`` reopens a finding that had been marked resolved or
    mitigated (the fix did not hold). Accepted-risk and false-positive
    findings are never changed. Every retest is appended to
    ``metadata.retests`` so the history survives later validations.
    """
    from app.models.vulnerability import VulnerabilityStatus

    now = now or datetime.utcnow()
    previous = vuln.status
    if outcome == FIXED and previous in (
        VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS, VulnerabilityStatus.MITIGATED,
    ):
        vuln.status = VulnerabilityStatus.RESOLVED
        vuln.resolved_at = now
    elif outcome == STILL_REPRODUCIBLE and previous in (
        VulnerabilityStatus.RESOLVED, VulnerabilityStatus.MITIGATED,
    ):
        vuln.status = VulnerabilityStatus.OPEN
        vuln.resolved_at = None

    meta = dict(vuln.metadata_ or {})
    history = list(meta.get("retests") or [])
    history.append({
        "validation_id": getattr(validation, "id", None),
        "outcome": outcome,
        "at": now.isoformat(),
        "previous_status": getattr(previous, "value", previous),
        "status": getattr(vuln.status, "value", vuln.status),
    })
    meta["retests"] = history[-_MAX_HISTORY:]
    vuln.metadata_ = meta  # reassign so SQLAlchemy sees the JSON change
    return getattr(vuln.status, "value", vuln.status) if vuln.status != previous else None
