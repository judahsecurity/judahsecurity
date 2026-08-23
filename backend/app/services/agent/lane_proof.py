"""Apply Guard-lane proof guards to live HTTP tools.

Keeps compare_requests / curl / replay from spraying, crashing ICS, completing
ATO, or deleting production ML models — and labels the differential when the
gold-bar pair is on the wire.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.services.agent import auth_header_bypass as auth_hdr
from app.services.agent import email_change_ato as email_ato
from app.services.agent import ml_pipeline_rbac as ml_rbac
from app.services.agent import socketio_idor as socketio
from app.services.agent.unauth_account_lookup import spray_violation as account_spray
from app.services.agent.unauth_settings_write import (
    sanitize_settings_write,
    should_force_unauth_session as settings_force_unauth,
)


def request_violation(
    url: str,
    method: str = "GET",
    body: Optional[str] = None,
) -> Optional[str]:
    blocked = account_spray(url)
    if blocked:
        return blocked
    blocked = email_ato.spray_violation(url, body)
    if blocked:
        return blocked
    blocked = socketio.crash_violation(f"{url} {body or ''}")
    if blocked:
        return blocked
    blocked = ml_rbac.destructive_violation(method, url)
    if blocked:
        return blocked
    return None


def sanitize_live_request(
    url: str,
    method: str,
    body: Optional[str],
    headers: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], Dict[str, Any], Optional[str], Optional[str]]:
    """Rewrite canaries first, then block leftover spray / crash / DELETE.

    Returns (body, headers, note, error).
    """
    notes: List[str] = []
    hdrs = {str(k): str(v) for k, v in dict(headers or {}).items()}

    body, hdrs, note = sanitize_settings_write(url, method, body, hdrs)
    if note:
        notes.append(note)

    body, hdrs, note = email_ato.sanitize_email_change(url, method, body, hdrs)
    if note:
        notes.append(note)

    if socketio.is_socketio_path(url) or socketio.NULL_CRASH_RE.search(body or ""):
        new_body, note = socketio.rewrite_null_payload(body or "")
        if note:
            body = new_body
            notes.append(note)

    body, note = ml_rbac.sanitize_ml_body(url, method, body)
    if note:
        notes.append(note)

    err = request_violation(url, method, body)
    if err:
        return body, hdrs, ("; ".join(notes) if notes else None), err

    return body, hdrs, ("; ".join(notes) if notes else None), None


def should_force_unauth_session(
    baseline_url: str,
    mutant_url: str,
    baseline_headers: Optional[Dict[str, Any]] = None,
    mutant_headers: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[str]]:
    if settings_force_unauth(baseline_url, mutant_url, baseline_headers, mutant_headers):
        return True, (
            "use_auth_session forced false (missing-[Authorize] settings write; "
            "crawl cookies would hide the 401 sibling)"
        )
    if email_ato.should_force_unauth_session(
        baseline_url, mutant_url, baseline_headers, mutant_headers
    ):
        return True, (
            "use_auth_session forced false (email-change ATO pair; crawl cookies "
            "would hide the set_password 401)"
        )
    if auth_hdr.should_force_unauth_session(
        baseline_url, mutant_url, baseline_headers, mutant_headers
    ):
        return True, (
            "use_auth_session forced false (auth-header bypass pair; session "
            "cookies would mask the missing-header skip)"
        )
    if socketio.is_socketio_path(baseline_url) or socketio.is_socketio_path(mutant_url):
        return True, "use_auth_session forced false (anonymous Socket.IO get_stream)"
    return False, None


def rewrite_cli_args(args: str) -> Tuple[str, Optional[str]]:
    notes: List[str] = []
    out = args or ""
    from app.services.agent.unauth_settings_write import rewrite_cli_args as rewrite_settings

    out, note = rewrite_settings(out)
    if note:
        notes.append(note)
    out, note = email_ato.rewrite_cli_args(out)
    if note:
        notes.append(note)
    out, note = socketio.rewrite_null_payload(out)
    if note:
        notes.append(note)
    return out, ("; ".join(notes) if notes else None)


def cli_violation(args: str) -> Optional[str]:
    from app.services.agent.unauth_account_lookup import spray_violation_in_text
    from app.services.agent.unauth_settings_write import destructive_violation_in_text

    blocked = spray_violation_in_text(args)
    if blocked:
        return blocked
    blocked = email_ato.spray_violation_in_text(args)
    if blocked:
        return blocked
    blocked = destructive_violation_in_text(args)
    if blocked:
        return blocked
    blocked = socketio.crash_violation(args)
    if blocked:
        return blocked
    blocked = ml_rbac.destructive_violation_in_text(args)
    if blocked:
        return blocked
    return None


def annotate_compare_proof(
    *,
    baseline_url: str,
    mutant_url: str,
    baseline_headers: Optional[Dict[str, Any]],
    mutant_headers: Optional[Dict[str, Any]],
    baseline_status: int,
    mutant_status: int,
    baseline_body: str = "",
    mutant_body: str = "",
) -> Tuple[List[str], Optional[Dict[str, Any]], Optional[str]]:
    signals: List[str] = []
    proof: Optional[Dict[str, Any]] = None
    verdict: Optional[str] = None

    for fn, kwargs in (
        (
            email_ato.annotate_compare_proof,
            dict(
                baseline_url=baseline_url,
                mutant_url=mutant_url,
                baseline_status=baseline_status,
                mutant_status=mutant_status,
                mutant_body=mutant_body,
            ),
        ),
        (
            auth_hdr.annotate_compare_proof,
            dict(
                baseline_headers=baseline_headers,
                mutant_headers=mutant_headers,
                baseline_status=baseline_status,
                mutant_status=mutant_status,
            ),
        ),
        (
            socketio.annotate_compare_proof,
            dict(
                baseline_url=baseline_url,
                mutant_url=mutant_url,
                mutant_body=mutant_body,
                baseline_body=baseline_body,
            ),
        ),
        (
            ml_rbac.annotate_compare_proof,
            dict(
                baseline_url=baseline_url,
                mutant_url=mutant_url,
                baseline_status=baseline_status,
                mutant_status=mutant_status,
            ),
        ),
    ):
        extra, p, v = fn(**kwargs)
        signals.extend(extra)
        if p and proof is None:
            proof = p
        if v and verdict is None:
            verdict = v
    return signals, proof, verdict
