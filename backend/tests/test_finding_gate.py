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


def test_writeup_guidance_uses_shared_proof_policy():
    from app.services.agent.proof_policy import PROOF_GUIDANCE
    g = _load()
    assert g.FINDING_WRITEUP_GUIDANCE.startswith(PROOF_GUIDANCE)
    assert g.FINDING_REVIEW_GUIDANCE.startswith(PROOF_GUIDANCE)


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
