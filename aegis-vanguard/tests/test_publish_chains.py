"""/chain -> platform export (.claude/skills/_lib/publish_chains.py)."""

import importlib.util
import json
from pathlib import Path

from asm_bridge import ASMBridge

_PATH = Path(__file__).resolve().parents[1] / ".claude" / "skills" / "_lib" / "publish_chains.py"
_spec = importlib.util.spec_from_file_location("publish_chains", _PATH)
publish_chains = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(publish_chains)


def _run_dir(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps({"findings": [
        {"id": "F1", "title": "Open redirect on /login", "severity": "low",
         "vuln_class": "open_redirect", "endpoint": "https://idp.example.com/login?next=",
         "evidence": "HTTP/1.1 302 Location: https://attacker.test"},
        {"id": "F2", "title": "OAuth redirect_uri accepts redirector", "severity": "medium",
         "vuln_class": "oauth", "endpoint": "https://idp.example.com/authorize"},
        {"id": "F3", "title": "Self-XSS", "severity": "low", "endpoint": "https://app.example.com/me"},
    ]}))
    (tmp_path / "chains.json").write_text(json.dumps([
        {"chain_id": "C1", "name": "Open redirect + OAuth -> ATO", "status": "demonstrated",
         "severity": "critical", "evidence": "code=abc reached attacker.test", "prowl_session": "prowl-77",
         "links": [{"finding_id": "F1", "role": "A", "verdict": "confirmed", "link_confirmed": True},
                   {"finding_id": "F2", "role": "B", "verdict": "confirmed", "link_confirmed": True}]},
        {"chain_id": "C2", "name": "Self-XSS + CSRF", "status": "links_confirmed_not_demonstrated",
         "next_step": "deliver via login-CSRF",
         "links": [{"finding_id": "F3", "role": "A", "verdict": "confirmed", "link_confirmed": True},
                   {"finding_id": "F1", "role": "B", "verdict": "confirmed", "link_confirmed": True}]},
        {"chain_id": "C3", "name": "incomplete", "status": "incomplete", "links": []},
    ]))
    return tmp_path


def _bridge(monkeypatch):
    monkeypatch.delenv("ASM_API_URL", raising=False)
    return ASMBridge(api_url="", api_key="", auto_flush=False)


def test_only_demonstrated_chains_are_sent(tmp_path, monkeypatch):
    bridge = _bridge(monkeypatch)
    buffered = []
    monkeypatch.setattr(bridge, "flush", lambda: buffered.extend(f.to_dict() for f in bridge._buffer))

    sent = publish_chains.publish(_run_dir(tmp_path), bridge=bridge)

    assert [s["chain_id"] for s in sent] == ["C1"]
    [finding] = buffered
    assert finding["severity"] == "critical" and finding["host"] == "idp.example.com"
    detection = finding["raw_data"]["agent_detection"]
    assert detection["session_id"] == "prowl-77"
    chain = detection["chain"]
    assert [s["finding_ref"] for s in chain[:2]] == ["Open redirect on /login", "OAuth redirect_uri accepts redirector"]
    assert chain[0]["asset"].startswith("https://idp.example.com/login")
    assert chain[-1]["summary"].startswith("End-to-end")
    assert detection["not_demonstrated"] == ""


def test_unproven_chains_opt_in_with_link_severity(tmp_path, monkeypatch):
    bridge = _bridge(monkeypatch)
    buffered = []
    monkeypatch.setattr(bridge, "flush", lambda: buffered.extend(f.to_dict() for f in bridge._buffer))

    sent = publish_chains.publish(_run_dir(tmp_path), bridge=bridge, include_unproven=True)

    assert [s["chain_id"] for s in sent] == ["C1", "C2"]
    c2 = buffered[1]
    assert c2["severity"] == "low"          # highest link, not a chain severity
    assert c2["raw_data"]["agent_detection"]["not_demonstrated"] == "deliver via login-CSRF"
    assert c2["raw_data"]["agent_detection"]["session_id"] == f"vanguard:{tmp_path.name}"


def test_dry_run_never_sends_even_with_url_in_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASM_API_URL", "https://asm.invalid")
    monkeypatch.setenv("ASM_API_KEY", "tfasm_x")
    posted = []
    monkeypatch.setattr(ASMBridge, "_post", lambda self, *a, **k: posted.append(a))
    sent = publish_chains.publish(_run_dir(tmp_path), dry_run=True)
    assert len(sent) == 1 and posted == []
