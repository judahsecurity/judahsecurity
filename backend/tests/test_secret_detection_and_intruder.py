"""Regression tests for assessment secret hygiene and Intruder planning."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from app.services.agent.intruder_automation import plan_intruder_mutations
from app.services.jsluice_service import (
    JSluiceResult,
    JSluiceSecret,
    build_results_summary,
)
from app.services.js_url_secrets_service import (
    _run_gitleaks_no_git,
    _safe_client_signing_finding,
    _safe_gitleaks_finding,
)
from app.services.js_recon_service import _scan_dom_sinks, _scan_endpoints
from app.services.secret_safety import redact_secret, secret_fingerprint


CANARY = "aegis_test_secret_material_123456789"


def test_secret_fingerprint_is_stable_and_redaction_reveals_no_fragment():
    first = secret_fingerprint(CANARY)
    assert first == secret_fingerprint(CANARY)
    assert first != secret_fingerprint(CANARY + "x")
    redacted = redact_secret(CANARY)
    assert CANARY not in redacted
    assert CANARY[:4] not in redacted
    assert first in redacted


def test_jsluice_summary_never_returns_raw_secret():
    result = JSluiceResult(
        js_files_analyzed=1,
        secrets_found=1,
        secrets=[JSluiceSecret(
            kind="GenericSecret",
            severity="high",
            data={"match": CANARY, "line": 10},
            source_js="https://app.example.test/main.js",
        )],
    )
    summary = build_results_summary(result)
    serialized = json.dumps(summary)
    assert CANARY not in serialized
    assert summary["secrets"][0]["fingerprint"] == secret_fingerprint(CANARY)


def test_agent_visible_js_findings_remove_raw_and_reconstructable_fragments():
    structural = _safe_client_signing_finding({
        "kind": "hmac_signing_key",
        "severity": "critical",
        "reconstructed": CANARY,
        "property_keys": ["aegis_", "test_", "secret_material"],
        "source_url": "https://app.example.test/main.js?sig=do-not-store",
    })
    gitleaks = _safe_gitleaks_finding({
        "RuleID": "generic-api-key",
        "Secret": CANARY,
        "Fingerprint": "main.js:generic-api-key:10",
        "source_url": "https://app.example.test/main.js?sig=do-not-store",
    })
    serialized = json.dumps({"structural": structural, "gitleaks": gitleaks})
    assert CANARY not in serialized
    assert "property_keys" not in structural
    assert "sig=do-not-store" not in serialized
    assert gitleaks["fingerprint"] == "main.js:generic-api-key:10"


def test_intruder_planner_builds_bounded_one_field_read_only_queue():
    samples = [
        {
            "method": "GET",
            "url": "https://app.example.test/api/users/41?redirect=https://app.example.test&id=41&q=alpha",
        },
        {
            "method": "POST",
            "url": "https://app.example.test/api/users",
            "body": {"user_id": 41, "admin": False},
        },
    ]
    plan = plan_intruder_mutations(samples, max_mutations=3)
    assert plan["dry_run"] is True
    assert plan["mutation_count"] == 3
    assert plan["skipped_state_changing"] == 1
    assert all(set(m) >= {"sample_index", "location", "field", "value", "category"} for m in plan["mutations"])
    assert all(m["sample_index"] == 0 for m in plan["mutations"])


def test_intruder_state_changing_requests_require_explicit_opt_in():
    samples = [{
        "method": "POST",
        "url": "https://app.example.test/api/users",
        "body": {"user_id": 41, "admin": False},
    }]
    blocked = plan_intruder_mutations(samples)
    enabled = plan_intruder_mutations(samples, allow_state_change=True)
    assert blocked["mutation_count"] == 0
    assert blocked["skipped_state_changing"] == 1
    assert enabled["mutation_count"] == 2


def test_extended_js_surface_includes_websockets_and_modern_dom_sinks():
    body = (
        'const socket="wss://api.example.test/realtime";'
        'node.insertAdjacentHTML("beforeend", input);'
        'window.addEventListener("message", handler);'
        'localStorage.setItem("authToken", token);'
    )
    assert "wss://api.example.test/realtime" in _scan_endpoints(body)
    sinks = {name for name, _context in _scan_dom_sinks(body)}
    assert {"insertAdjacentHTML", "message_event_listener", "client_storage_sensitive"} <= sinks


def test_gitleaks_reads_json_report_file(tmp_path: Path, monkeypatch):
    def fake_run(cmd, **_kwargs):
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text(json.dumps([{
            "RuleID": "generic-api-key",
            "Secret": "REDACTED",
            "Fingerprint": "main.js:generic-api-key:1",
        }]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.services.js_url_secrets_service.shutil.which", lambda _name: "/usr/bin/gitleaks")
    monkeypatch.setattr("app.services.js_url_secrets_service.subprocess.run", fake_run)
    findings, error = _run_gitleaks_no_git(str(tmp_path))
    assert error is None
    assert findings[0]["RuleID"] == "generic-api-key"
