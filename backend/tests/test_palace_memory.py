"""Palace memory: tenant isolation, redaction, wake-up, search, tool drawers.

Loads palace_memory by file path so the suite does not import the full
ASM service stack (DNS, Nuclei, LangChain).
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parents[1]
_AGENT = ROOT / "app" / "services" / "agent"


def _ensure_pkg(name: str, path: Path) -> None:
    existing = sys.modules.get(name)
    if existing is not None and getattr(existing, "__path__", None):
        return
    mod = types.ModuleType(name)
    mod.__path__ = [str(path)]
    mod.__package__ = name
    sys.modules[name] = mod


def _load(modname: str, path: Path):
    if modname in sys.modules and getattr(sys.modules[modname], "__file__", None):
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


_ensure_pkg("app", ROOT / "app")
_ensure_pkg("app.db", ROOT / "app" / "db")
_ensure_pkg("app.core", ROOT / "app" / "core")
_ensure_pkg("app.models", ROOT / "app" / "models")

_load("app.core.config", ROOT / "app" / "core" / "config.py")
dbmod = _load("app.db.database", ROOT / "app" / "db" / "database.py")
palace_model = _load("app.models.agent_palace", ROOT / "app" / "models" / "agent_palace.py")
pm = _load("palace_memory_under_test", _AGENT / "palace_memory.py")
prompts = _load("prompts_under_test", _AGENT / "prompts.py")

Base = dbmod.Base
AgentPalaceDrawer = palace_model.AgentPalaceDrawer
is_tool_allowed_in_phase = prompts.is_tool_allowed_in_phase


def _session(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[AgentPalaceDrawer.__table__])
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(pm, "SessionLocal", Session)
    monkeypatch.setattr(pm, "ensure_knowledge_mined", lambda *_a, **_k: None)
    return Session


def test_search_memory_allowed_in_all_phases():
    for phase in ("informational", "exploitation", "post_exploitation"):
        assert is_tool_allowed_in_phase("search_memory", phase)
        assert is_tool_allowed_in_phase("store_memory", phase)
        assert is_tool_allowed_in_phase("search_knowledge_base", phase)


def test_redact_strips_passwords_and_keys():
    raw = (
        'login password=hunter2 token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 '
        '{"password": "supersecret", "host": "api.acme.com"} '
        "AKIAIOSFODNN7EXAMPLE"
    )
    out = pm.redact_for_palace(raw)
    assert "hunter2" not in out
    assert "supersecret" not in out
    assert "ghp_" not in out
    assert "AKIA" not in out
    assert "api.acme.com" in out
    assert "***REDACTED" in out


def test_tenant_isolation(monkeypatch):
    _session(monkeypatch)
    pm.store_drawer(1, "Cloudflare in front of api.acme.com", room="waf", title="waf acme")
    pm.store_drawer(2, "No WAF on api.other.com", room="waf", title="waf other")

    hits = pm.search_memory(1, "Cloudflare acme WAF")
    blobs = " ".join(h["snippet"] for h in hits)
    assert "api.acme.com" in blobs
    assert "api.other.com" not in blobs
    assert all(h.get("wing") != "org:2" for h in hits)


def test_dedup_same_drawer(monkeypatch):
    Session = _session(monkeypatch)
    ids1 = pm.store_drawer(1, "same verbatim fact about waf", room="waf", title="waf")
    ids2 = pm.store_drawer(1, "same verbatim fact about waf", room="waf", title="waf")
    assert ids1 == ids2
    db = Session()
    try:
        assert db.query(AgentPalaceDrawer).filter_by(organization_id=1).count() == 1
    finally:
        db.close()


def test_wake_up_stays_under_budget(monkeypatch):
    _session(monkeypatch)
    for i in range(20):
        pm.store_drawer(
            1,
            f"scope note {i}: example.com is in-scope including api.example.com " + ("x" * 400),
            room="scope_roe",
            title=f"scope {i}",
        )
    text = pm.wake_up(1, target="example.com")
    assert "Joshua" in text
    assert "search_memory" in text
    assert len(text) <= pm.WAKE_UP_MAX_CHARS + 80


def test_search_finds_stored_tool_output(monkeypatch):
    _session(monkeypatch)
    pm.store_drawer(
        1,
        "execute_wafw00f args: https://shop.acme.com\n\nshop.acme.com is behind Cloudflare",
        room="waf",
        title="execute_wafw00f ok",
        source="tool",
        tool_name="execute_wafw00f",
        target="https://shop.acme.com",
    )
    hits = pm.search_memory(1, "Cloudflare shop.acme.com", room="waf")
    assert hits
    assert hits[0]["room"] == "waf"
    assert "Cloudflare" in hits[0]["snippet"]


def test_remember_skips_search_and_query_tools(monkeypatch):
    Session = _session(monkeypatch)
    monkeypatch.setattr(pm, "_current_tenant", lambda: (7, "sess-1"))
    pm.remember_tool_result(
        "search_memory",
        {"query": "waf"},
        {"success": True, "output": "some long palace hit " * 20},
    )
    pm.remember_tool_result(
        "query_assets",
        {"search": "acme"},
        {"success": True, "output": "asset list " * 20},
    )
    db = Session()
    try:
        assert db.query(AgentPalaceDrawer).count() == 0
    finally:
        db.close()


def test_remember_stores_redacted_nuclei(monkeypatch):
    Session = _session(monkeypatch)
    monkeypatch.setattr(pm, "_current_tenant", lambda: (7, "sess-1"))
    output = (
        'nuclei found CVE-2024-1234 on https://app.acme.com '
        '{"password": "should-not-persist", "template": "cve-2024-1234"}'
    )
    pm.remember_tool_result(
        "execute_nuclei",
        {"args": "-u https://app.acme.com -jsonl"},
        {"success": True, "output": output},
    )
    db = Session()
    try:
        rows = db.query(AgentPalaceDrawer).filter_by(organization_id=7).all()
        assert len(rows) == 1
        assert rows[0].room == "nuclei"
        assert "should-not-persist" not in rows[0].content
        assert "CVE-2024-1234" in rows[0].content
        assert rows[0].target and "app.acme.com" in rows[0].target
    finally:
        db.close()


def test_global_drawers_visible_to_orgs(monkeypatch):
    _session(monkeypatch)
    pm.store_drawer(
        None,
        "Global RoE: never test production payroll.",
        room="scope_roe",
        title="global roe",
        source="knowledge",
    )
    hits = pm.search_memory(3, "payroll production")
    assert any("payroll" in h["snippet"] for h in hits)


def test_org_cannot_see_other_org_via_global_wing_spoof(monkeypatch):
    _session(monkeypatch)
    pm.store_drawer(
        9,
        "secret finding on tenant nine",
        wing="global",
        room="findings",
        title="spoof",
    )
    hits = pm.search_memory(3, "secret finding tenant nine")
    assert not any("tenant nine" in (h.get("snippet") or "") for h in hits)
