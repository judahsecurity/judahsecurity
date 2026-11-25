"""Operator-chosen verification strictness and POST replay path suggestions.

Strictness is set per assessment by the operator (``assessment_policy``), never
by a model tool:

* ``conservative`` - only class-specific proofs publish; inconclusive candidates
  are logged but not published; the generic ``replay_reproduction`` proof is off.
* ``standard`` (default) - class proofs, the generic reproduction proof (filed as
  ``reproduced``, capped at high) and the ``unverified`` review tier.
* ``aggressive`` - standard, plus observed same-origin POST paths that do not
  look destructive are approved for body replay automatically (up to the
  policy limit of 8), and the deep assessment budget unless the operator
  chose a depth. Use it on staging or lab targets.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

STRICTNESS_LEVELS = ("conservative", "standard", "aggressive")
DEFAULT_STRICTNESS = "standard"
MAX_BODY_REPLAY_PATHS = 8

# Paths whose name suggests an irreversible or account-level effect. They are
# never auto-approved and are listed separately so an operator decides.
_DESTRUCTIVE = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|remove|purge|drop|wipe|erase|truncate|"
    r"reset|deactivate|disable|terminate|cancel|close|revoke|unsubscribe|"
    r"logout|signout|sign-out|log-out|"
    r"pay|payment|payments|charge|checkout|purchase|order|orders|refund|transfer|withdraw|"
    r"invoice|billing|subscribe|subscription|"
    r"password|passwd|email|phone|mfa|2fa|totp|otp|recovery|"
    r"admin|role|roles|permission|permissions|invite|impersonate|"
    r"import|upload|deploy|publish|send|notify|broadcast)(?:$|[/_.-])"
)


def normalize_strictness(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in STRICTNESS_LEVELS else DEFAULT_STRICTNESS


def strictness(manager: Any) -> str:
    return normalize_strictness(getattr(manager, "_verification_strictness", None))


def depth_for_strictness(strictness_value: Any, current_mode: str | None) -> str | None:
    """Aggressive defaults to the deep assessment budget; others keep ``current_mode``.

    Only used when the operator did not pass an explicit assessment_mode. Pilot
    and scheduled runs still fall back to standard in assessment_depth().
    """
    if normalize_strictness(strictness_value) == "aggressive":
        return "deep"
    return current_mode


def unverified_tier_allowed(manager: Any) -> bool:
    return strictness(manager) != "conservative"


def generic_reproduction_allowed(manager: Any) -> bool:
    return strictness(manager) != "conservative"


def looks_destructive(path: str) -> bool:
    return bool(_DESTRUCTIVE.search(path or ""))


def _valid_path(path: str) -> bool:
    return (isinstance(path, str) and path.startswith("/") and not path.startswith("//")
            and path != "/" and len(path) <= 256
            and not any(char in path for char in "?#\\\r\n\t "))


def suggest_body_replay_paths(brain: Any, approved: Iterable[str] = ()) -> dict:
    """POST paths seen during mapping that body replay has not been approved for.

    Sources: coverage cells blocked with ``post_path_not_approved`` and POST
    cells still pending. Paths are grouped with their input counts; destructive
    looking ones are returned separately and never auto-approved.
    """
    approved = set(approved or ())
    counts: dict[str, dict] = {}
    for cell in getattr(brain, "coverage_cells", None) or []:
        if not isinstance(cell, dict) or str(cell.get("method") or "").upper() != "POST":
            continue
        path = str(cell.get("path") or "")
        if not _valid_path(path) or path in approved:
            continue
        blocked = cell.get("first_pass_blocked_reason") == "post_path_not_approved"
        if not blocked and cell.get("status") not in ("untested", "blocked"):
            continue
        row = counts.setdefault(path, {"path": path, "inputs": 0, "classes": set(),
                                       "host": str(cell.get("host") or "")})
        row["inputs"] += 1
        for key in ("vulnerability_class", "test_type", "bug_class"):
            if cell.get(key):
                row["classes"].add(str(cell[key]))
    safe, destructive = [], []
    for row in sorted(counts.values(), key=lambda r: (-r["inputs"], r["path"])):
        row["classes"] = sorted(row["classes"])
        (destructive if looks_destructive(row["path"]) else safe).append(row)
    return {"suggested": safe, "needs_review": destructive,
            "approved": sorted(approved), "limit": MAX_BODY_REPLAY_PATHS}


def auto_approve_body_paths(manager: Any, brain: Any) -> list[str]:
    """Aggressive profile: approve non-destructive suggested POST paths.

    Returns the newly approved paths. A no-op for other profiles.
    """
    if strictness(manager) != "aggressive":
        return []
    current = set(getattr(manager, "_scoped_body_replay_paths", None) or set())
    room = MAX_BODY_REPLAY_PATHS - len(current)
    if room <= 0:
        return []
    picks = [row["path"] for row in suggest_body_replay_paths(brain, current)["suggested"]][:room]
    if picks:
        manager._scoped_body_replay_paths = current | set(picks)
        auto = list(getattr(manager, "_auto_approved_body_paths", None) or [])
        manager._auto_approved_body_paths = auto + [p for p in picks if p not in auto]
    return picks
