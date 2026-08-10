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
