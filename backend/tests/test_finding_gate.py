"""Solomon finding gate — medium+ requires SUBMIT receipt."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_GATE = Path(__file__).resolve().parents[1] / "app" / "services" / "agent" / "finding_gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("finding_gate_under_test", _GATE)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_medium_requires_receipt():
    g = _load()
    store = {}
    ok, msg = g.consume_or_check_receipt(
        store, title="IDOR", target="https://app.example.com", severity="high"
    )
    assert not ok
    assert "JUDGE GATE" in msg


def test_submit_unlocks_create():
    g = _load()
    store = {}
    rid = g.record_submit_receipt(
        store,
        title="IDOR on /api/users",
        target="https://app.example.com/x",
        severity="high",
        score="8/8",
    )
    assert rid
    ok, msg = g.consume_or_check_receipt(
        store,
        title="IDOR on /api/users",
        target="app.example.com",
        severity="high",
    )
    assert ok
    assert msg.startswith("gate_ok:")


def test_info_skips_gate():
    g = _load()
    ok, msg = g.consume_or_check_receipt(
        {}, title="banner", target="x.com", severity="info"
    )
    assert ok
    assert msg == "gate_skipped"


def test_writeup_guidance_requires_privileged_impact():
    g = _load()
    text = g.FINDING_WRITEUP_GUIDANCE.lower()
    assert "demonstrated-compromise" in text
    assert "assess_finding_risk" in text or "marcus" in text
    assert "why_not_higher" in text or "risk assessment" in text
    assert "login" in text
    assert "impact" in text
    assert "remediation" in text
    assert "elasticsearch" in text
    assert "aegis_test_index" in text
    assert "painless" in text
    assert "9264" in text
    assert "duckdb" in text
    assert "no such file" in text
    assert "mass assignment" in text or "readonly" in text
    assert "cwe-915" in text or "api/schema" in text
    assert "cors" in text
    assert "weborigins" in text or "keycloak" in text
    assert "credentials" in text
    assert "admin-cli" in text or "cwe-307" in text
    assert "password grant" in text or "invalid_grant" in text
    assert "cwe-204" in text or "/api/auth/account" in text
    assert "is_staff" in text or "user account" in text
    assert "404" in text or "existence oracle" in text
    assert "do not claim" in text or "stdout" in text
    assert "critical" in text
    assert "savesettings" in text or "missing [authorize]" in text or "cwe-306" in text
    assert "void" in text or "content-length" in text
    assert "arangodb" in text
    assert "wiki" in text
    assert "binary" in text
    assert "azurecr" in text or "anonymous pull" in text
    assert "anonymouspullenabled" in text or "oauth2" in text
    assert "package-lock" in text or "ghp_" in text
    assert "cwe-321" in text
    assert "interactsh" in text or "payload_url" in text
    review = g.FINDING_REVIEW_GUIDANCE.lower()
    assert "verdict" in review
    assert "retest" in review
    assert "do not re-probe" in review or "deny-check" in review
    assert "savesettings" in review or "void 200" in review
    assert "account" in review or "is_staff" in review
    assert "404" in review or "existence oracle" in review
    assert "cwe-321" in review or "hmac" in review
    assert "interactsh" in review or "payload_url" in review


def test_acr_anonymous_pull_signals():
    g = _load()
    catalog = g.acr_anonymous_pull_signals(
        "Azure Container Registry Anonymous Pull Enabled "
        "https://digipdevelopment.azurecr.io oauth2/token issued an access_token "
        "scope=registry:catalog:* GET /v2/_catalog repositories "
        "ads-namespace-graphql-service"
    )
    assert catalog["is_finding"]
    assert catalog["has_anon_proof"]
    assert not catalog["live_privileged_token"]

    banner = g.acr_anonymous_pull_signals(
        "https://fdudevaksregistry.azurecr.io resolves on the public internet"
    )
    assert banner["is_finding"]
    assert not banner["has_anon_proof"]

    pats = g.acr_anonymous_pull_signals(
        "azurecr.io anonymous pull catalog repositories "
        "ghp_ token in package-lock.json git+https classic personal access "
        "permissions admin write:packages workflow"
    )
    assert pats["has_secret_class"]
    assert pats["live_privileged_token"]
