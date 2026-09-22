from agent.owasp_hunters import (
    create_hunters_for_engagement,
    detect_core_hunter_signals,
)


def _surface(action="https://example.test/search", method="GET", params=None):
    return {
        "forms": [{
            "action_url": action,
            "method": method,
            "content_type": "application/x-www-form-urlencoded",
            "eligible_parameters": params or ["q"],
        }],
        "request_templates": [],
    }


def test_minimal_input_surface_uses_small_core_baseline():
    signals = detect_core_hunter_signals(input_surface=_surface())

    assert {name for name, active in signals.items() if active} == {"injection", "xss"}


def test_login_and_multiple_identities_activate_identity_hunters():
    signals = detect_core_hunter_signals(
        input_surface=_surface(
            action="https://example.test/login",
            method="POST",
            params=["username", "password"],
        ),
        identities=[{"label": "member"}, {"label": "admin"}],
    )

    assert signals["auth"]
    assert signals["authz"]
    assert signals["csrf"]


def test_requested_hunter_overrides_adaptive_signal_selection():
    hunters = create_hunters_for_engagement(
        max_turns=5,
        input_surface=_surface(),
        include_api_framework=False,
        include_enterprise=False,
        requested_hunters=["open_redirect"],
    )

    assert {hunter.name for hunter in hunters} == {
        "injection_hunter", "xss_hunter", "open_redirect_hunter",
    }


def test_requested_hunter_substring_preserves_cli_compatibility():
    hunters = create_hunters_for_engagement(
        max_turns=5,
        input_surface=_surface(),
        include_api_framework=False,
        include_enterprise=False,
        requested_hunters=["upload"],
    )

    assert "file_upload_hunter" in {hunter.name for hunter in hunters}


def test_adaptive_core_can_be_disabled_for_full_legacy_fireteam():
    hunters = create_hunters_for_engagement(
        max_turns=5,
        input_surface=_surface(),
        include_api_framework=False,
        include_enterprise=False,
        adaptive_core=False,
    )

    assert len(hunters) == 17
