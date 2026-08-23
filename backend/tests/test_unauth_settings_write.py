"""Unauth ASP.NET settings write — canary, void 200, High not Critical."""

from __future__ import annotations

import json

from app.services.agent.independent_verify import FindingCandidate, verifier_mission
from app.services.agent.risk_assessment import validate_risk_assessment
from app.services.agent.unauth_settings_write import (
    CANARY_KEY,
    allows_critical_ra,
    caps_critical_as_high,
    destructive_settings_payload,
    destructive_violation_in_text,
    has_settings_write_proof,
    is_settings_write_finding,
    is_settings_write_path,
    rewrite_cli_args,
    sanitize_settings_body,
    should_force_unauth_session,
)


def _ra(**overrides):
    payload = {
        "verdict": "confirm",
        "confirmed_severity": "high",
        "why_this_severity": (
            "Unauth POST /api/TaskAdmin/UpdateTask returns 401 while unauth POST "
            "/api/Settings/SaveSettings returns 200 Content-Length: 0 (ASP.NET void). "
            "Missing [Authorize] on the settings write is demonstrated."
        ),
        "why_not_higher": (
            "GetSettings returned 500 / NRE so the canary was not round-tripped. "
            "No production flag flip, no BFLA with a low-priv session."
        ),
        "why_not_lower": (
            "Any internet user can POST SaveSettings without a token while a sibling "
            "write is 401. That is missing auth, not a scanner banner."
        ),
        "cvss_score": 8.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        "demonstrated": [
            {
                "asset": "https://app.example.com/api/TaskAdmin/UpdateTask",
                "result": "unauth POST 401",
            },
            {
                "asset": "https://app.example.com/api/Settings/SaveSettings",
                "result": "unauth POST 200 Content-Length: 0 void with aegis-verify-key",
            },
        ],
        "not_demonstrated": [
            {"target": "GetSettings read-back", "outcome": "500 NullReferenceException"},
        ],
        "control_failures": [
            {"control": "[Authorize]", "failure": "SettingsController SaveSettings has no auth attribute"},
        ],
        "business_risk": (
            "Internet users can overwrite org-wide Document Centre settings on the "
            "customer App Service without signing in."
        ),
        "remediation_sequence": [
            {
                "when": "now",
                "action": "Add [Authorize] on SettingsController",
                "done_when": "unauth POST SaveSettings returns 401",
            },
            {
                "when": "this_week",
                "action": "Restrict SaveSettings to Admin role",
                "done_when": "non-admin session is 403",
            },
        ],
        "retest_criteria": [
            "unauth POST SaveSettings returns 401 like UpdateTask",
            "GetSettings is not required for the close",
            "non-admin authenticated SaveSettings is 403",
        ],
        "ticket_title": "High — Unauth POST /api/Settings/SaveSettings",
        "ra_note": (
            "Confirm High. Sibling 401 vs SaveSettings 200 void is enough. Do not "
            "raise to Critical without GetSettings round-trip of the canary."
        ),
        "sla": "now",
        "cwes": ["CWE-306", "CWE-862"],
    }
    payload.update(overrides)
    return payload


def test_write_path_not_getsettings():
    assert is_settings_write_path(
        "https://app.azurewebsites.net/api/Settings/SaveSettings"
    )
    assert is_settings_write_path(
        "https://app.azurewebsites.net/api/Settings/WriteSettings"
    )
    assert not is_settings_write_path(
        "https://app.azurewebsites.net/api/Settings/GetSettings"
    )
    assert not is_settings_write_path(
        "https://app.azurewebsites.net/api/TaskAdmin/UpdateTask"
    )


def test_sanitize_nulls_flags_and_keeps_one_canary():
    body, note = sanitize_settings_body(
        "https://app.example.com/api/Settings/SaveSettings",
        "POST",
        json.dumps({
            "enableNotifications": True,
            "createPlannerTasks": False,
            "powerBIReportId": "prod-report",
            "settings": [
                {"key": "theme", "value": "dark"},
                {"key": CANARY_KEY, "value": "ok"},
            ],
        }),
    )
    data = json.loads(body)
    assert data["enableNotifications"] is None
    assert data["createPlannerTasks"] is None
    assert data["powerBIReportId"] is None
    assert data["settings"] == [{"key": CANARY_KEY, "value": "ok"}]
    assert note and "nulled" in note
    assert not destructive_settings_payload(body)

    empty, injected = sanitize_settings_body(
        "https://app.example.com/api/Settings/SaveSettings",
        "POST",
        "",
    )
    assert CANARY_KEY in empty
    assert injected and "injected" in injected

    sibling, sibling_note = sanitize_settings_body(
        "https://app.example.com/api/TaskAdmin/UpdateTask",
        "POST",
        "",
    )
    assert sibling == ""
    assert sibling_note is None


def test_force_unauth_session_unless_bearer():
    save = "https://app.example.com/api/Settings/SaveSettings"
    sibling = "https://app.example.com/api/TaskAdmin/UpdateTask"
    assert should_force_unauth_session(sibling, save, {}, {})
    assert not should_force_unauth_session(
        sibling,
        save,
        {},
        {"Authorization": "Bearer low-priv"},
    )
    assert not should_force_unauth_session(
        "https://app.example.com/api/users/1",
        "https://app.example.com/api/users/2",
        {},
        {},
    )


def test_curl_rewrites_then_blocks_leftover_flags():
    args = (
        'https://app.example.com/api/Settings/SaveSettings '
        '-d \'{"createPlannerTasks": false, "settings": '
        f'[{{"key":"{CANARY_KEY}","value":"ok"}}]}}\''
    )
    rewritten, note = rewrite_cli_args(args)
    assert '"createPlannerTasks": null' in rewritten
    assert note and "nulled" in note
    assert destructive_violation_in_text(rewritten) is None
    assert destructive_violation_in_text(args)


def test_proof_requires_401_and_void_200():
    paired = (
        "Unauthenticated Application Settings Write via /api/Settings/SaveSettings. "
        "UpdateTask 401; SaveSettings 200 Content-Length: 0 void."
    )
    assert is_settings_write_finding(paired)
    assert has_settings_write_proof(paired)
    foothold = (
        "Settings API exists at /api/Settings/SaveSettings on azurewebsites.net"
    )
    assert is_settings_write_finding(foothold)
    assert not has_settings_write_proof(foothold)
    assert not is_settings_write_finding(
        "Anonymous Azure Function Tester env dump on *.azurewebsites.net"
    )


def test_marcus_keeps_high_rejects_critical_without_persistence():
    parsed, gaps = validate_risk_assessment(_ra())
    assert gaps == [], gaps
    assert parsed["confirmed_severity"] == "high"

    inflated = _ra(
        confirmed_severity="critical",
        verdict="upgrade",
        ticket_title="Critical — Unauth POST /api/Settings/SaveSettings",
    )
    parsed_c, crit_gaps = validate_risk_assessment(inflated)
    assert parsed_c is None
    assert any("High on sibling 401" in g or "void 200" in g for g in crit_gaps)
    assert caps_critical_as_high(
        "SaveSettings 200 void UpdateTask 401; GetSettings 500"
    )
    persist = (
        "unauth settings write SaveSettings canary round-trip GetSettings returned "
        "aegis-verify-key; enableNotifications flipped"
    )
    assert allows_critical_ra(persist)
    assert not caps_critical_as_high(persist)


def test_deborah_mission_forces_unauth_canary():
    cand = FindingCandidate(
        id="abc123",
        title="Unauthenticated Application Settings Write via /api/Settings/SaveSettings",
        description="Missing [Authorize] on SettingsController",
        evidence="UpdateTask 401; SaveSettings 200 void; GetSettings 500",
        target="https://app.azurewebsites.net",
        nonce="deadbeef",
    )
    mission = verifier_mission(cand)
    assert "use_auth_session=false" in mission
    assert CANARY_KEY in mission
    assert "GetSettings" in mission
    assert "401" in mission
    other = FindingCandidate(
        id="xyz",
        title="IDOR on /api/users",
        target="https://app.example.com",
        nonce="aa",
    )
    other_mission = verifier_mission(other)
    assert CANARY_KEY not in other_mission
