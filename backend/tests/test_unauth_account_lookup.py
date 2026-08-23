"""Unauth OpenAPI account lookup — canary, 404 oracle, Critical RA, no inferred 200."""

from __future__ import annotations

from app.services.agent.independent_verify import FindingCandidate, verifier_mission
from app.services.agent.risk_assessment import validate_risk_assessment
from app.services.agent.unauth_account_lookup import (
    CANARY_EMAIL,
    allows_critical_ra,
    has_account_lookup_proof,
    inferred_role_payload,
    is_account_lookup_finding,
    rewrite_cli_args,
    spray_violation,
    spray_violation_in_text,
)


def _ra(**overrides):
    payload = {
        "verdict": "confirm",
        "confirmed_severity": "critical",
        "why_this_severity": (
            "OpenAPI documents GET /api/auth/account/ with security: {} and "
            "UserAccount fields is_staff/role. Sibling /api/auth/profile/ is 401 "
            "while the canary lookup is 404 User does not exist — JWT skipped."
        ),
        "why_not_higher": (
            "No RCE, no account takeover, no 200 UserAccount body with role bytes."
        ),
        "why_not_lower": (
            "Schema-unauth plus 401-vs-404 is demonstrated user enum and privilege "
            "contract, not a scanner banner."
        ),
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "demonstrated": [
            {
                "asset": "https://ics.example.com/api/schema/",
                "result": "security: {} on /api/auth/account/; UserAccount is_staff/role",
            },
            {
                "asset": "https://ics.example.com/api/auth/account/?email=" + CANARY_EMAIL,
                "result": "404 User does not exist while /api/auth/profile/ is 401",
            },
        ],
        "not_demonstrated": [
            {"target": "registered ICS user", "outcome": "did not spray employee inboxes"},
        ],
        "control_failures": [
            {"control": "JWT middleware", "failure": "lookup skips auth that siblings enforce"},
        ],
        "business_risk": (
            "ICS/OT monitoring login oracle lets an attacker confirm accounts and "
            "aim credential attacks at admin-role users."
        ),
        "remediation_sequence": [
            {"when": "now", "action": "Require JWT on GET /api/auth/account/", "done_when": "unauth lookup returns 401"},
            {"when": "this_week", "action": "Strip is_staff/role from any pre-login check", "done_when": "body is generic boolean or identical for all emails"},
        ],
        "retest_criteria": [
            "unauth GET /api/auth/account/?email=canary returns 401",
            "unauth GET /api/auth/profile/ still 401",
            "OpenAPI no longer marks the lookup security: {}",
        ],
        "ticket_title": "Require JWT on /api/auth/account/ lookup",
        "ra_note": (
            "Confirm Critical. Schema public + 401-vs-404 is enough. Do not invent "
            "a 200 role payload. ACAO * is extra."
        ),
        "sla": "now",
        "cwes": ["CWE-204", "CWE-200", "CWE-862"],
    }
    payload.update(overrides)
    return payload


def test_spray_blocks_admin_probe_allows_canary():
    blocked = spray_violation(
        "https://ics.example.com/api/auth/account/?email=admin@test.com"
    )
    assert blocked and "canary" in blocked.lower()
    assert spray_violation(
        f"https://ics.example.com/api/auth/account/?email={CANARY_EMAIL}"
    ) is None
    assert spray_violation("https://ics.example.com/api/auth/profile/") is None
    assert spray_violation("https://ics.example.com/api/schema/") is None
    curl_hit = spray_violation_in_text(
        '-sS "https://ics.example.com/api/auth/account/?email=test@example.com"'
    )
    assert curl_hit and "spray" in curl_hit.lower()
    rewritten, note = rewrite_cli_args(
        "https://ics.example.com/api/auth/account/?email=admin@test.com"
    )
    assert CANARY_EMAIL in rewritten or "aegis-enum-canary%40example.invalid" in rewritten
    assert note and "rewrote" in note


def test_404_oracle_and_schema_are_proof():
    schema = (
        "GET /api/auth/account/ security: {} without authentication "
        "UserAccount is_staff role valid_through"
    )
    assert is_account_lookup_finding(schema)
    assert has_account_lookup_proof(schema)
    jwt_skip = (
        "Unauthenticated user enumeration via /api/auth/account/ "
        "profile 401 vs lookup 404 User does not exist"
    )
    assert has_account_lookup_proof(jwt_skip)
    assert allows_critical_ra(jwt_skip)
    assert not has_account_lookup_proof("swagger.json found on the host")


def test_do_not_infer_200_useraccount_body():
    inferred = (
        "Unauthenticated User Enumeration via /api/auth/account/. "
        "A registered email returns HTTP 200 with the full UserAccount payload "
        "including is_staff and role."
    )
    assert inferred_role_payload(inferred)
    quoted = (
        'GET /api/auth/account/?email=aegis-enum-canary@example.invalid '
        'HTTP 200 {"email":"x","is_staff": false, "role": "viewer"}'
    )
    assert not inferred_role_payload(quoted)
    oracle = (
        "GET /api/auth/account/ 404 User does not exist! siblings 401. "
        "Did not retrieve a 200 UserAccount body."
    )
    assert not inferred_role_payload(oracle)


def test_marcus_allows_critical_for_account_lookup_not_generic_ssrf():
    parsed, gaps = validate_risk_assessment(_ra())
    assert gaps == []
    assert parsed["confirmed_severity"] == "critical"

    signup = _ra(
        ticket_title="Open self-registration on marketing wiki",
        why_this_severity=(
            "Anyone on the internet can create a wiki account without an invite. "
            "That is internet exposure of the signup form, not a privileged write."
        ),
        why_not_lower=(
            "Unauthenticated signup succeeded and issued a session cookie for a "
            "throwaway account. That is demonstrated, not theoretical."
        ),
        why_not_higher=(
            "No sandbox page write, no internal page read, no RCE, no cloud token."
        ),
        business_risk=(
            "A public wiki signup increases spam and reconnaissance, but it is not "
            "a control-plane compromise of the customer estate."
        ),
        demonstrated=[
            {"asset": "wiki.example.com/signup", "result": "self-registration returned 200"},
            {"asset": "wiki.example.com/login", "result": "throwaway account session issued"},
        ],
        ra_note="Confirm High. Open signup is exposure until a sandbox write is shown.",
    )
    _, signup_gaps = validate_risk_assessment(signup)
    assert any("Critical requires" in g for g in signup_gaps), signup_gaps


def test_deborah_mission_includes_404_oracle_and_canary():
    cand = FindingCandidate(
        id="abc123",
        title="Unauthenticated User Enumeration via /api/auth/account/",
        description="OpenAPI security: {} returns is_staff and role",
        evidence="siblings 401; lookup 500 DB down",
        target="https://ics.example.com",
        nonce="deadbeef",
    )
    mission = verifier_mission(cand)
    assert CANARY_EMAIL in mission
    assert "404" in mission
    assert "do not spray" in mission.lower() or "do not hunt" in mission.lower()
    assert "existence oracle" in mission.lower() or "user does not exist" in mission.lower()
    other = FindingCandidate(
        id="xyz",
        title="Unauthenticated Settings Write",
        description="SaveSettings 200 void",
        target="https://app.example.com",
        nonce="aa",
    )
    other_mission = verifier_mission(other)
    assert "existence oracle" not in other_mission.lower()
