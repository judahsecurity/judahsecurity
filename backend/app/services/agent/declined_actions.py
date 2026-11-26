"""Operator-declined actions: never retried, but they do not end the run.

A bounded pilot used to treat any declined approval as a stop. On
ginandjuice.shop the operator declined a third identical SQLi comparison
after two successful pairs; the run ended there, so the independent verifier
never ran and the strong candidate was never published.

Declining one action now means "not this action": its exact signature is
recorded and refused if the model proposes it again, and the run continues so
it can verify and publish what it already has. The run still stops when the
operator declines ``max_declines()`` actions (they clearly want it to stop),
when a confirmation expires (no operator is present to approve anything
else), on server-policy denials, and on the Stop button.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List

from app.services.agent.action_fingerprint import _canonical

DECLINED = "confirmation_denied"
PREVIOUSLY_DECLINED = "operator_declined_previously"
# Errors that still end a pilot run: nobody can approve, or policy refused.
PILOT_STOP_ERRORS = frozenset({
    "confirmation_expired", "policy_denied",
    "confirmation_policy_unavailable", "pilot_policy_denied",
})


def max_declines() -> int:
    from app.core.config import settings

    try:
        return max(1, int(getattr(settings, "AGENT_PILOT_MAX_DECLINES", 3)))
    except (TypeError, ValueError):
        return 3


def action_signature(tool_name: str, tool_args: Dict[str, Any]) -> str:
    canonical = json.dumps(_canonical(dict(tool_args or {})), sort_keys=True, default=str)
    return hashlib.sha256(f"{tool_name}\n{canonical}".encode()).hexdigest()[:24]


def is_declined(signatures: Iterable[str], tool_name: str, tool_args: Dict[str, Any]) -> bool:
    return action_signature(tool_name, tool_args) in set(signatures or [])


def pending_candidates(brain: Any) -> List[Dict[str, Any]]:
    rows = (brain or {}).get("candidates") if isinstance(brain, dict) else None
    return [row for row in rows or [] if isinstance(row, dict)
            and str(row.get("status") or "pending") == "pending"]


def continue_note(tool_name: str, declines: int, brain: Any) -> str:
    """Model-facing guidance after a decline: what not to do, and what to do next."""
    lines = [
        f"The operator declined this {tool_name} call. Do not propose it again; "
        f"the identical call will be refused ({declines}/{max_declines()} declines; "
        "the run stops at the limit)."
    ]
    pending = pending_candidates(brain)
    if pending:
        ids = ", ".join(str(row.get("id")) for row in pending[:5])
        lines.append(
            f"Pending candidates need independent verification before they can be published: "
            f"{ids}. Run independent_verify on them next instead of repeating evidence collection."
        )
    else:
        lines.append("Continue with a different input or check, or finish with honest coverage.")
    return " ".join(lines)
