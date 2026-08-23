"""Interactsh is the OOB collaborator — poll proof, not Canarytokens."""

from __future__ import annotations

from app.services.agent.independent_verify import FindingCandidate, verifier_mission
from app.services.agent.interactsh_proof import (
    has_interactsh_proof,
    has_ssrf_proof,
    is_oob_finding,
    mailbox_for_domain,
)
from app.services.agent.methodology_catalog import methodologies_from_capability_map
from app.models.project_settings import default_nuclei_config


def test_nuclei_interactsh_on_by_default():
    assert default_nuclei_config()["interactsh"] is True


def test_mailbox_and_finding_vs_foothold():
    assert mailbox_for_domain("abc123.oast.fun") == "aegis@abc123.oast.fun"
    foothold = "Webhook URL-fetch exists on /api/v1/actions/execute (possible SSRF)"
    assert is_oob_finding(foothold)
    assert not has_ssrf_proof(foothold)
    assert not has_interactsh_proof("canarytokens.org nest DNS token fired")
    poll = (
        "SSRF via requestUrl. execute_interactsh poll xyz "
        'new_interactions=1 "protocol": "dns" payload_domain=abc.oast.fun'
    )
    assert has_interactsh_proof(poll)
    assert has_ssrf_proof(poll)
    internal = (
        "Grafana datasource proxy SSRF returned prometheus /api/v1/targets "
        "internal body without Interactsh"
    )
    assert is_oob_finding(internal)
    assert has_ssrf_proof(internal)


def test_deborah_mission_forces_interactsh_poll():
    cand = FindingCandidate(
        id="ssrf1",
        title="Unauthenticated SSRF via Appsmith actions/execute",
        description="Server fetches requestUrl",
        evidence="webhook url-fetch 200",
        target="https://appsmith.example.com",
        nonce="ab",
    )
    mission = verifier_mission(cand)
    assert "execute_interactsh" in mission
    assert "payload_url" in mission
    assert "Canarytokens" in mission or "canarytokens" in mission.lower()
    other = FindingCandidate(
        id="xyz",
        title="IDOR on /api/users",
        target="https://app.example.com",
        nonce="aa",
    )
    other_mission = verifier_mission(other)
    assert "payload_url" not in other_mission


def test_ssrf_methodology_names_interactsh_register_poll():
    cmap = {
        "target": "https://appsmith.example.com",
        "pages_visited": ["https://appsmith.example.com/"],
        "param_rich_paths": ["https://appsmith.example.com/api/v1/actions/execute?url="],
        "api_samples": [{"url": "/api/v1/actions/execute", "method": "POST"}],
        "api_endpoints": [],
        "forms": [],
        "js_files": [],
    }
    methods = methodologies_from_capability_map(cmap)
    ssrf = next(m for m in methods if m.id == "ssrf_url_fetch")
    assert "execute_interactsh" in ssrf.test
    assert "poll" in ssrf.test.lower()
    assert "canarytokens" in ssrf.test.lower()


def test_ensure_session_reuses_live_payload_domain():
    from app.services import interactsh_service as ish

    class _Alive:
        def poll(self):
            return None

    sid = "reuse1"
    session = ish._Session(
        sid=sid,
        proc=_Alive(),
        output_file="/tmp/interactsh_reuse_test.jsonl",
        payload_domain="xyz.oast.fun",
    )
    ish._SESSIONS[sid] = session
    try:
        first = ish.ensure_session()
        assert first["success"] is True
        assert first["reused"] is True
        assert first["session_id"] == sid
        assert first["payload_domain"] == "xyz.oast.fun"
        assert first["payload_url"] == "https://xyz.oast.fun"
        assert first["payload_email"] == "aegis@xyz.oast.fun"
        assert "Canarytokens" in first["next"]
        second = ish.ensure_session()
        assert second["session_id"] == sid
    finally:
        ish._SESSIONS.pop(sid, None)


def test_ensure_session_registers_when_empty(monkeypatch):
    from app.services import interactsh_service as ish

    ish._SESSIONS.clear()

    def fake_register(server=None, token=None):
        return {
            "success": True,
            "session_id": "new1",
            "payload_domain": "abc.oast.fun",
            "reused": False,
        }

    monkeypatch.setattr(ish, "register", fake_register)
    out = ish.ensure_session()
    assert out["session_id"] == "new1"
    assert out["payload_domain"] == "abc.oast.fun"


def test_generate_payloads_auto_fills_interactsh_collaborator(monkeypatch):
    monkeypatch.setattr(
        "app.services.interactsh_service.ensure_session",
        lambda: {
            "success": True,
            "session_id": "sid1",
            "payload_domain": "abc.oast.fun",
            "payload_url": "https://abc.oast.fun",
            "payload_email": "aegis@abc.oast.fun",
        },
    )
    from app.services.agent.injection_payloads import generate_payloads

    out = generate_payloads("ssrf")
    blob = "\n".join(out["payloads"])
    assert "http://abc.oast.fun/" in blob
    assert "COLLABORATOR" not in blob
    assert out["collaborator_url"] == "abc.oast.fun"
    assert out["interactsh"]["session_id"] == "sid1"
    assert out["interactsh"]["next"] == "execute_interactsh poll sid1"


def test_generate_payloads_keeps_placeholder_when_oob_unavailable(monkeypatch):
    monkeypatch.setattr(
        "app.services.interactsh_service.ensure_session",
        lambda: {"success": False, "error": "interactsh-client not installed"},
    )
    from app.services.agent.injection_payloads import generate_payloads

    out = generate_payloads("ssrf")
    assert any("COLLABORATOR" in p for p in out["payloads"])
    assert "interactsh" not in out


def test_generate_payloads_supplied_collaborator_skips_provision(monkeypatch):
    def boom():
        raise AssertionError("must not provision when collaborator_url is set")

    monkeypatch.setattr("app.services.interactsh_service.ensure_session", boom)
    from app.services.agent.injection_payloads import generate_payloads

    out = generate_payloads("xxe", collaborator_url="planted.oast.fun")
    assert any("planted.oast.fun" in p for p in out["payloads"])
    assert "COLLABORATOR" not in "".join(out["payloads"])
    assert "interactsh" not in out
