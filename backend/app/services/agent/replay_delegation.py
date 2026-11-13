"""Operator-delegated approval of write paths the agent itself observed.

Without delegation, every POST replay path and DELETE cleanup path must be
named by an operator before a run. With delegation, the operator states the
rules once and the agent may propose a path; it is approved automatically
only when all of the following hold:

* the operator turned delegation on for this run;
* the agent observed that exact method and path in captured browser traffic
  in this session (a private capture exists), not only a JavaScript lead;
* the path stays inside the run's authorized scope;
* the path does not touch authentication, account, payment or administrative
  functions, which always need a person;
* cleanup (DELETE) paths are approved only when the operator allowed them;
* the number of approved paths stays within the operator's cap.

Every decision, approved or not, is recorded on the engagement brain so the
operator can audit what the agent unlocked.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

KINDS = {"body_replay": "POST", "stored_xss_cleanup": "DELETE"}
POLICY_PATH_LIMIT = 8
DEFAULT_MAX_PATHS = 4

# A path word equal to one of these (or its plural) always needs an operator.
SENSITIVE_WORDS = frozenset({
    "login", "logout", "logon", "signin", "signout", "signup", "register", "auth",
    "oauth", "sso", "saml", "session", "password", "passwd", "reset", "recover",
    "verify", "verification", "2fa", "mfa", "otp", "totp", "token", "key", "apikey",
    "secret", "credential", "account", "profile", "email", "phone", "payment", "pay",
    "checkout", "billing", "invoice", "subscription", "order", "purchase", "transfer",
    "withdraw", "wallet", "refund", "admin", "role", "permission", "invite", "member",
    "user", "delete", "remove", "destroy", "purge", "deactivate", "webhook", "import",
    "upload", "export", "backup", "config", "setting",
})

_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,255}$")


def normalize_delegation(raw: Any) -> dict:
    """Operator delegation settings; anything malformed means delegation is off."""
    if raw is True:
        raw = {"enabled": True}
    if not isinstance(raw, dict) or raw.get("enabled") is not True:
        return {"enabled": False, "max_paths": 0, "allow_cleanup": False}
    try:
        max_paths = int(raw.get("max_paths") or DEFAULT_MAX_PATHS)
    except (TypeError, ValueError):
        max_paths = DEFAULT_MAX_PATHS
    return {
        "enabled": True,
        "max_paths": max(1, min(max_paths, POLICY_PATH_LIMIT)),
        "allow_cleanup": raw.get("allow_cleanup") is True,
    }


def _words(path: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", path)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


# A DELETE cleanup path naturally says delete/remove; the stored-XSS flow only
# ever deletes the agent's own nonce-tagged entry through it.
CLEANUP_ALLOWED_WORDS = frozenset({"delete", "remove"})


def sensitive_reason(path: str, *, allowed: frozenset[str] = frozenset()) -> str:
    for word in _words(path):
        stem = word[:-1] if word.endswith("s") and word[:-1] in SENSITIVE_WORDS else word
        if stem in SENSITIVE_WORDS and stem not in allowed:
            return f"path word '{word}' touches a sensitive function"
    return ""


def observed_operation(
    operations: Iterable[dict], *, method: str, path: str,
) -> dict | None:
    """The captured operation for this exact method and path, if any."""
    for op in operations or []:
        if not isinstance(op, dict):
            continue
        if (str(op.get("method") or "").upper() == method
                and op.get("path") == path
                and op.get("capture_ids")):
            return op
    return None


def evaluate(
    *,
    path: str,
    kind: str,
    delegation: dict,
    operations: Iterable[dict],
    approved_paths: set[str],
    in_scope,
) -> tuple[bool, str, dict | None]:
    """Decide one proposal. ``in_scope(url)`` raises when a URL is out of scope."""
    if kind not in KINDS:
        return False, f"unsupported kind; use one of {sorted(KINDS)}", None
    if not delegation.get("enabled"):
        return False, "operator_approval_required: delegated approval is off for this run", None
    if (not isinstance(path, str) or not _PATH_RE.fullmatch(path) or path == "/"
            or path.startswith("//") or ".." in path):
        return False, "invalid path: use an exact absolute path without query or fragment", None
    if kind == "stored_xss_cleanup" and not delegation.get("allow_cleanup"):
        return False, "operator_approval_required: cleanup paths are not delegated", None
    reason = sensitive_reason(
        path, allowed=CLEANUP_ALLOWED_WORDS if kind == "stored_xss_cleanup" else frozenset(),
    )
    if reason:
        return False, f"operator_approval_required: {reason}", None
    op = observed_operation(operations, method=KINDS[kind], path=path)
    if op is None:
        return False, (
            f"not observed: no captured {KINDS[kind]} {path} in this session; "
            "exercise the form or request in the browser first"
        ), None
    try:
        in_scope(str(op.get("url") or ""))
    except ValueError as exc:
        return False, f"out of scope: {exc}", op
    if path in approved_paths:
        return True, "already approved", op
    if len(approved_paths) >= delegation.get("max_paths", 0):
        return False, (
            f"operator_approval_required: the delegated limit of "
            f"{delegation.get('max_paths')} paths is reached"
        ), op
    return True, "observed in captured traffic and within delegated rules", op


def decision_record(
    *, path: str, kind: str, approved: bool, reason: str, op: dict | None, note: str = "",
) -> dict:
    return {
        "path": path,
        "kind": kind,
        "method": KINDS.get(kind, ""),
        "decision": "approved" if approved else "denied",
        "reason": reason[:300],
        "operation_id": str((op or {}).get("id") or ""),
        "capture_id": str(((op or {}).get("capture_ids") or [""])[0]),
        "note": str(note or "")[:300],
        "source": "delegated",
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }


def approved_paths(records: Iterable[dict], kind: str) -> list[str]:
    return [
        str(row.get("path"))
        for row in records or []
        if isinstance(row, dict) and row.get("decision") == "approved"
        and row.get("kind") == kind and row.get("source") == "delegated"
    ]
