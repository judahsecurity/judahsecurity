"""Tests for methodology procedure packs."""

from app.services.agent.methodology_catalog import methodologies_from_capability_map
from app.services.agent.methodology_procedures import (
    format_procedures_for_prompt,
    list_procedure_ids,
    load_procedure,
)
from app.services.agent.operation_directive import OperationDirective


def test_packs_on_disk():
    ids = list_procedure_ids()
    assert "csrf_state_changing" in ids
    assert "api_idor_bola" in ids
    assert "open_redirect" in ids
    assert "session_token_quality" in ids
    assert "login_injection" in ids
    assert "aspnet_unauth_settings_write" in ids
    assert "email_change_ato" in ids
    assert "auth_header_bypass" in ids
    assert "socketio_unauth_stream_idor" in ids
    assert "ml_pipeline_missing_rbac" in ids
    assert len(ids) >= 10


def test_load_csrf_pack():
    pack = load_procedure("csrf_state_changing")
    assert pack is not None
    assert pack["id"] == "csrf_state_changing"
    assert pack["steps"]
    assert "compare_requests" in pack["tools"]


def test_format_procedures_for_prompt():
    text = format_procedures_for_prompt(["csrf_state_changing", "api_idor_bola"])
    assert "PROCEDURE PACK" in text
    assert "csrf_state_changing" in text
    assert "api_idor_bola" in text


def test_directive_includes_procedure_pack():
    d = OperationDirective(
        specialist="auth_logic",
        epithet="Ezra",
        target="https://example.com",
        goal="CSRF",
        methodology_ids=["csrf_state_changing"],
        allowed_tools=["compare_requests"],
    )
    block = d.to_prompt_block()
    assert "PROCEDURE PACK" in block
    assert "csrf_state_changing" in block


def test_catalog_seeds_new_auth_cards():
    cmap = {
        "target": "https://app.example.com",
        "has_login_form": True,
        "has_auth": True,
        "pages_visited": [
            "https://app.example.com/login?next=/home",
            "https://app.example.com/account",
        ],
        "forms": [
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://app.example.com/login",
            }
        ],
        "param_rich_paths": [
            "https://app.example.com/login?next=https://evil.example",
        ],
        "api_endpoints": [],
        "js_files": [],
        "api_samples": [],
    }
    methods = {m.id for m in methodologies_from_capability_map(cmap)}
    assert "csrf_state_changing" in methods
    assert "session_token_quality" in methods
    assert "open_redirect" in methods
    assert "auth_session_boundary" in methods
    assert "login_injection" in methods
    pack = load_procedure("login_injection")
    assert pack is not None
    assert "compare_requests" in pack["tools"]
    assert "run_custom_probe" in pack["tools"]
    assert any("login" in s.lower() for s in pack["steps"])


def test_ssrf_pack_requires_interactsh_not_canarytokens():
    pack = load_procedure("ssrf_url_fetch")
    assert pack is not None
    blob = " ".join(pack["steps"]).lower() + " " + " ".join(pack["tools"])
    assert "execute_interactsh" in pack["tools"]
    assert "register" in blob
    assert "poll" in blob
    assert "canarytokens" in blob

