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
    assert "arangodb" in text
    assert "wiki" in text
    assert "binary" in text
