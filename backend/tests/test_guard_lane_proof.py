"""Guard-lane proof: canaries, spray/crash/DELETE blocks, Deborah, Marcus High."""

from __future__ import annotations

import json

from app.services.agent.auth_header_bypass import (
    INVALID_BEARER,
    annotate_compare_proof as auth_header_proof,
    caps_critical_as_high as auth_header_caps,
    has_auth_header_proof,
    is_auth_header_finding,
    should_force_unauth_session as auth_header_force_unauth,
)
from app.services.agent.email_change_ato import (
    CANARY_EMAIL,
    caps_critical_as_high as email_change_caps,
    has_email_change_proof,
    is_email_change_finding,
    sanitize_email_change_body,
    should_force_unauth_session as email_force_unauth,
    spray_violation,
    spray_violation_in_text,
)
from app.services.agent.independent_verify import FindingCandidate, verifier_mission
from app.services.agent.lane_proof import (
    annotate_compare_proof,
    cli_violation,
    request_violation,
    sanitize_live_request,
    should_force_unauth_session,
)
from app.services.agent.ml_pipeline_rbac import (
    canary_train_body,
    caps_critical_as_high as ml_rbac_caps,
    destructive_violation,
    has_ml_rbac_proof,
    is_ml_rbac_finding,
)
from app.services.agent.risk_assessment import validate_risk_assessment
from app.services.agent.socketio_idor import (
    FABRICATED_SITE,
    caps_critical_as_high as socketio_caps,
    crash_violation,
    has_socketio_proof,
    is_socketio_finding,
    rewrite_null_payload,
)


def _ra(*, title: str, severity: str = "high", why: str, demonstrated: list, **overrides):
    payload = {
        "verdict": "confirm",
        "confirmed_severity": severity,
        "why_this_severity": why,
        "why_not_higher": (
            "No write/RCE, no live mailbox takeover, and the canary was not redeemed "
            "against a production account."
        ),
        "why_not_lower": (
            "The paired live differential is demonstrated compromise, not a scanner "
            "banner or an unproven foothold."
        ),
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "demonstrated": demonstrated,
        "not_demonstrated": [{"target": "production ATO", "outcome": "not attempted"}],
        "control_failures": [{"control": "authz", "failure": "control skipped"}],
        "business_risk": "Internet users can hit the gold-bar pair without a session.",
        "remediation_sequence": [
            {"when": "now", "action": "fail closed on missing auth", "done_when": "unauth is 401"},
            {"when": "this_week", "action": "rate limit the pair", "done_when": "repeat canary is 429"},
        ],
        "retest_criteria": [
            "gold-bar pair returns 401",
            "canary is not accepted",
            "invalid token does not enumerate",
        ],
        "ticket_title": title,
        "ra_note": "Confirm High. Do not inflate to Critical without write/RCE.",
        "sla": "now",
        "cwes": ["CWE-306"],
    }
    payload.update(overrides)
    return payload


def test_email_change_rewrites_real_mailbox_to_canary():
    body, note = sanitize_email_change_body(
        "https://app.example.com/api/auth/users/reset_email/",
        "POST",
        json.dumps({"email": "victim@customer.com"}),
    )
    data = json.loads(body)
    assert data["email"] == CANARY_EMAIL
    assert note and "rewrote" in note
    empty, injected = sanitize_email_change_body(
        "https://app.example.com/api/auth/users/reset_email/",
        "POST",
        "",
    )
    assert CANARY_EMAIL in empty
    assert injected and "injected" in injected


def test_email_change_spray_blocks_after_leftover_real_inbox():
    url = "https://app.example.com/api/auth/users/reset_email/"
    assert spray_violation(url, json.dumps({"email": "admin@test.com"}))
    assert spray_violation(url, json.dumps({"email": CANARY_EMAIL})) is None
    curl_hit = spray_violation_in_text(
        '-d \'{"email":"victim@corp.com"}\' https://app.example.com/api/auth/users/reset_email/'
    )
    assert curl_hit and "spray" in curl_hit.lower()


def test_email_change_sanitized_request_is_not_spray():
    body, hdrs, note, err = sanitize_live_request(
        "https://app.example.com/api/auth/users/reset_email/",
        "POST",
        json.dumps({"email": "victim@customer.com"}),
        {},
    )
    assert err is None
    assert CANARY_EMAIL in (body or "")
    assert note and "rewrote" in note
    assert hdrs.get("Content-Type") == "application/json"


def test_email_change_force_unauth_and_proof_vs_foothold():
    set_pw = "https://app.example.com/api/auth/users/set_password/"
    reset = "https://app.example.com/api/auth/users/reset_email/"
    assert email_force_unauth(set_pw, reset, {}, {})
    force, why = should_force_unauth_session(set_pw, reset, {}, {})
    assert force and why and "email-change" in why
    paired = (
        "Unauthenticated Email Change via djoser reset_email. "
        "set_password 401; reset_email 204 aegis-ato-canary@example.invalid"
    )
    assert is_email_change_finding(paired)
    assert has_email_change_proof(paired)
    foothold = "reset_email endpoint exists on the API"
    assert is_email_change_finding(foothold)
    assert not has_email_change_proof(foothold)
    signals, proof, verdict = annotate_compare_proof(
        baseline_url=set_pw,
        mutant_url=reset,
        baseline_headers={},
        mutant_headers={},
        baseline_status=401,
        mutant_status=204,
        mutant_body="",
    )
    assert "email_change_unauth" in signals
    assert proof and proof["lane"] == "email_change_ato"
    assert verdict == "MUTANT_BYPASS_CANDIDATE"


def test_email_change_marcus_keeps_high():
    parsed, gaps = validate_risk_assessment(
        _ra(
            title="High — Unauth POST reset_email",
            why=(
                "Unauth POST /api/auth/users/set_password/ returns 401 while unauth "
                "POST reset_email with aegis-ato-canary@example.invalid returns 204."
            ),
            demonstrated=[
                {"asset": "https://app.example.com/api/auth/users/set_password/", "result": "401"},
                {
                    "asset": "https://app.example.com/api/auth/users/reset_email/",
                    "result": "204 canary aegis-ato-canary@example.invalid",
                },
            ],
        )
    )
    assert gaps == [], gaps
    assert parsed["confirmed_severity"] == "high"
    inflated, crit_gaps = validate_risk_assessment(
        _ra(
            title="Critical — Unauth email change ATO",
            severity="critical",
            verdict="upgrade",
            why="reset_email 204 while set_password 401",
            demonstrated=[
                {"asset": "https://app.example.com/api/auth/users/set_password/", "result": "401"},
                {"asset": "https://app.example.com/api/auth/users/reset_email/", "result": "204 djoser canary"},
            ],
        )
    )
    assert inflated is None
    assert any("High" in g and "reset_email" in g for g in crit_gaps)
    assert email_change_caps("djoser reset_email 204 set_password 401 canary")
    assert not email_change_caps(
        "djoser reset_email mailbox takeover logged in as victim"
    )


def test_email_change_deborah_mission_includes_canary():
    cand = FindingCandidate(
        id="ato1",
        title="Unauthenticated Email Change Endpoints Enable Account Takeover Chain",
        description="djoser reset_email skips JWT",
        evidence="set_password 401; reset_email 204",
        target="https://app.example.com",
        nonce="deadbeef",
    )
    mission = verifier_mission(cand)
    assert CANARY_EMAIL in mission
    assert "use_auth_session=false" in mission
    assert "do not complete ATO" in mission.lower() or "do not spray" in mission.lower()
    other = FindingCandidate(
        id="xyz",
        title="IDOR on /api/users",
        target="https://app.example.com",
        nonce="aa",
    )
    assert CANARY_EMAIL not in verifier_mission(other)


def test_auth_header_pair_proof_and_force_unauth():
    url = "https://api.example.com/v1/orders"
    no_hdr, bad = {}, {"Authorization": INVALID_BEARER}
    assert auth_header_force_unauth(url, url, no_hdr, bad)
    force, why = should_force_unauth_session(url, url, no_hdr, bad)
    assert force and why and "auth-header" in why
    signals, proof, verdict = auth_header_proof(
        baseline_headers=no_hdr,
        mutant_headers=bad,
        baseline_status=400,
        mutant_status=401,
    )
    assert "auth_header_skip" in signals
    assert proof and proof["no_header_status"] == 400
    assert verdict == "MUTANT_BYPASS_CANDIDATE"
    paired = (
        "Backend API Authentication Middleware Bypass via Missing Authorization Header. "
        "no-header 400 missing params; Bearer aegis-invalid 401"
    )
    assert is_auth_header_finding(paired)
    assert has_auth_header_proof(paired)
    assert not has_auth_header_proof("auth middleware exists on the API")
    inflated, gaps = validate_risk_assessment(
        _ra(
            title="Critical — auth middleware skip",
            severity="critical",
            verdict="upgrade",
            why="no authorization header 400 vs aegis-invalid 401",
            demonstrated=[
                {"asset": url, "result": "auth_header_bypass no-header 400"},
                {"asset": url, "result": "Bearer aegis-invalid 401"},
            ],
        )
    )
    assert inflated is None
    assert any("Auth-header skip is High" in g for g in gaps)
    assert auth_header_caps(paired)


def test_auth_header_deborah_mission():
    cand = FindingCandidate(
        id="hdr1",
        title="Backend API Authentication Middleware Bypass via Missing Authorization Header",
        evidence="no header 400; Bearer aegis-invalid 401",
        target="https://api.example.com",
        nonce="ab",
    )
    mission = verifier_mission(cand)
    assert "aegis-invalid" in mission
    assert "use_auth_session=false" in mission


def test_socketio_rewrites_null_crash_and_blocks_leftover():
    raw = '42["get_stream",null]'
    assert crash_violation(raw)
    rewritten, note = rewrite_null_payload(raw)
    assert FABRICATED_SITE in rewritten
    assert note and "crash" in note.lower()
    assert crash_violation(rewritten) is None
    body, _hdrs, snote, err = sanitize_live_request(
        "https://vstream.example.com/socket.io/?EIO=3&transport=polling",
        "POST",
        raw,
        {},
    )
    assert err is None
    assert FABRICATED_SITE in (body or "")
    assert snote and "fabricated" in snote
    leftover = cli_violation('curl -d \'42["get_stream",null]\' https://x/socket.io/')
    # rewrite_cli_args runs first in MCP; leftover crash is still a violation on raw CLI
    assert leftover and "crash" in leftover.lower()


def test_socketio_proof_url_key_not_open_socket():
    paired = (
        "Unauthenticated Camera Stream Access via Socket.IO IDOR. "
        'anonymous get_stream returned "url_key": "/ns/site_AEGIS_PROOF"'
    )
    assert is_socketio_finding(paired)
    assert has_socketio_proof(paired)
    foothold = "socket.io endpoint is open"
    assert not is_socketio_finding(foothold) or not has_socketio_proof(foothold)
    signals, proof, verdict = annotate_compare_proof(
        baseline_url="https://vstream.example.com/socket.io/",
        mutant_url="https://vstream.example.com/socket.io/",
        baseline_headers={},
        mutant_headers={},
        baseline_status=200,
        mutant_status=200,
        mutant_body='{"url_key":"/ns/cam1"}',
    )
    assert "socketio_url_key" in signals
    assert proof and proof["lane"] == "socketio_idor"
    assert verdict == "MUTANT_BYPASS_CANDIDATE"
    inflated, gaps = validate_risk_assessment(
        _ra(
            title="Critical — Socket.IO get_stream",
            severity="critical",
            verdict="upgrade",
            why="anonymous get_stream url_key for fabricated siteId",
            demonstrated=[
                {"asset": "/socket.io/", "result": "url_key socketio_idor"},
                {"asset": "/socket.io/", "result": "fabricated siteId accepted"},
            ],
        )
    )
    assert inflated is None
    assert any("url_key is High" in g for g in gaps)
    assert socketio_caps(paired)
    cand = FindingCandidate(
        id="sio1",
        title="Unauthenticated Camera Stream Access via Socket.IO IDOR",
        evidence="get_stream url_key",
        target="https://vstream.example.com",
        nonce="cc",
    )
    mission = verifier_mission(cand)
    assert FABRICATED_SITE in mission or "url_key" in mission
    assert "null" in mission.lower()


def test_ml_blocks_delete_and_injects_canary_train():
    url = "https://twin.example.com/api/v1/celery-task/abc"
    assert destructive_violation("DELETE", url)
    assert request_violation(url, "DELETE", None)
    assert destructive_violation("POST", "https://twin.example.com/api/v1/train/") is None
    body, _hdrs, note, err = sanitize_live_request(
        "https://twin.example.com/api/v1/train/",
        "POST",
        "",
        {},
    )
    assert err is None
    assert json.loads(body) == canary_train_body()
    assert note and "canary" in note.lower()
    curl_hit = cli_violation(
        '-X DELETE https://twin.example.com/api/v1/celery-task/prod-model'
    )
    assert curl_hit and "DELETE" in curl_hit
    paired = (
        "Missing Authorization on ML Model Training. self-registered throwaway "
        "POST /api/v1/train/ 202"
    )
    assert is_ml_rbac_finding(paired)
    assert has_ml_rbac_proof(paired)
    foothold = "ML pipeline /api/v1/train exists"
    assert is_ml_rbac_finding(foothold)
    assert not has_ml_rbac_proof(foothold)
    signals, proof, verdict = annotate_compare_proof(
        baseline_url="https://twin.example.com/api/admin/models",
        mutant_url="https://twin.example.com/api/v1/train/",
        baseline_headers={},
        mutant_headers={"Authorization": "Bearer low-priv"},
        baseline_status=401,
        mutant_status=202,
    )
    assert "ml_rbac_bypass" in signals
    assert proof and proof["lane"] == "ml_pipeline_rbac"
    assert verdict == "MUTANT_BYPASS_CANDIDATE"
    force, _why = should_force_unauth_session(
        "https://twin.example.com/api/v1/train/",
        "https://twin.example.com/api/v1/train/",
        {},
        {"Authorization": "Bearer low-priv"},
    )
    assert not force
    inflated, gaps = validate_risk_assessment(
        _ra(
            title="Critical — ML pipeline missing RBAC",
            severity="critical",
            verdict="upgrade",
            why="self-reg POST /api/v1/train/ 202 ml_pipeline_rbac",
            demonstrated=[
                {"asset": "/api/v1/train/", "result": "202 self-reg"},
                {"asset": "/api/admin/models", "result": "401 anonymous"},
            ],
        )
    )
    assert inflated is None
    assert any("ML train missing RBAC is High" in g for g in gaps)
    assert ml_rbac_caps(paired)
    cand = FindingCandidate(
        id="ml1",
        title="Missing Authorization on ML Model Training and Deletion Endpoints",
        evidence="self-reg POST /api/v1/train/ 202 celery-task",
        target="https://twin.example.com",
        nonce="dd",
    )
    mission = verifier_mission(cand)
    assert "Do NOT DELETE" in mission or "do not DELETE" in mission.lower()
    assert "/api/v1/train/" in mission
