"""Show a finding candidate to the analyst the moment it exists.

A specialist's candidate waits for independent verification before it can
become a finding, which is right for precision but hides early signal. Each
submission and each verdict is written to the run's action ledger (the Run
Ledger panel), clearly marked UNVERIFIED until the verifier decides. Nothing
here publishes a finding or changes the verification rules.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)


def _line(candidate: Any) -> str:
    title = str(getattr(candidate, "title", "") or "")[:160]
    severity = str(getattr(candidate, "severity", "") or "").upper()
    target = str(getattr(candidate, "target", "") or "")[:160]
    return " ".join(part for part in (severity, title, f"@ {target}" if target else "") if part)


def signal(candidate: Any, event: str) -> None:
    """event: 'submitted' or a verifier verdict (confirmed|refuted|inconclusive)."""
    try:
        from app.services.agent.action_ledger import active_run_id, append_action

        if event == "submitted":
            name = "unverified_candidate"
            detail = f"UNVERIFIED (awaiting independent verification): {_line(candidate)}"
        else:
            name = "candidate_verdict"
            detail = f"Verifier {event.upper()}: {_line(candidate)}"
        append_action(
            active_run_id.get(), uuid.uuid4().hex, "completed", name,
            target=str(getattr(candidate, "target", "") or ""), phase="verification",
            detail=detail[:400],
            evidence_ids=[str(i) for i in (getattr(candidate, "evidence_ids", None) or [])][:10],
        )
    except Exception:  # visibility only: never fail the caller
        logger.debug("candidate signal skipped", exc_info=True)
