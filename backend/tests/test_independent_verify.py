"""Independent verifier gate + coverage completeness (offline)."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.agent.engagement_brain import (
    EngagementBrain,
    Hypothesis,
    coverage_progress,
    methodology_progress,
    record_surface_coverage,
    seed_coverage_from_surfaces,
)
from app.services.agent.independent_verify import (
    FindingCandidate,
    apply_verdict,
    check_verify_receipt,
    finding_publish_allowed,
    ingest_report_findings,
    record_verify_receipt,
    submit_candidate,
)

_AGENT_DIR = Path(__file__).resolve().parents[1] / "app" / "services" / "agent"


def _allowlists() -> dict[str, list[str]]:
    src = (_AGENT_DIR / "fireteam_service.py").read_text()
    tree = ast.parse(src)
    allowlists: dict[str, list[str]] = {}
    for node in tree.body:
        value = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "DEFAULT_SPECIALISTS":
                value = node.value
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "DEFAULT_SPECIALISTS" for t in node.targets):
                value = node.value
        if not isinstance(value, ast.List):
            continue
        for elt in value.elts:
            if not isinstance(elt, ast.Call):
                continue
            kwargs = {kw.arg: kw.value for kw in elt.keywords if kw.arg}
            name_node = kwargs.get("name")
            tools_node = kwargs.get("allowed_tools")
            if not isinstance(name_node, ast.Constant) or not isinstance(tools_node, ast.List):
                continue
            tools = [
                t.value for t in tools_node.elts
                if isinstance(t, ast.Constant) and isinstance(t.value, str)
            ]
            allowlists[str(name_node.value)] = tools
    return allowlists


def _killed_card() -> Hypothesis:
    return Hypothesis(
        id="m1",
        title="Authz card",
        assumption="x",
        test="y",
        pass_criteria="z",
        kill_criteria="k",
        specialist="api_authz",
        priority="high",
        status="killed",
        source="methodology",
        methodology_id="idor",
    )


def test_hunters_submit_candidates_not_create_finding():
    allowlists = _allowlists()
    hunters = (
        "js_secrets",
        "graphql_api",
        "auth_logic",
        "credential_assault",
        "api_authz",
        "host_tenant",
        "business_logic",
        "injection",
        "file_upload",
        "saml_sso",
        "spa_client",
        "agent_tools",
        "coverage",
        "code_sast",
    )
    for name in hunters:
        tools = allowlists[name]
        assert "create_finding" not in tools, name
        assert "submit_finding_candidate" in tools, name


def test_independent_verifier_is_isolated():
    tools = _allowlists()["independent_verifier"]
    assert "create_finding" not in tools
    assert "submit_finding_candidate" not in tools
    assert "get_engagement_brain" not in tools
    assert "record_verify_verdict" in tools
    assert "compare_requests" in tools
    assert "finding_judge" in _allowlists()
    assert "create_finding" not in _allowlists()["finding_judge"]
    assert "submit_finding_candidate" not in _allowlists()["finding_judge"]
    marcus = _allowlists()["risk_assessor"]
    assert "assess_finding_risk" in marcus
    assert "create_finding" not in marcus
    assert "execute_curl" not in marcus


def test_medium_plus_requires_verify_receipt_when_flag_set():
    tm = SimpleNamespace(
        _require_independent_verify=True,
        _verify_receipts={},
        _finding_receipts={},
        _engagement_brain={},
    )
    ok, msg = finding_publish_allowed(
        tm, title="IDOR /api/users", target="https://app.example.com", severity="high"
    )
    assert ok is False
    assert "INDEPENDENT VERIFY" in msg

    record_verify_receipt(
        tm._verify_receipts,
        title="IDOR /api/users",
        target="https://app.example.com",
        verdict="confirmed",
        candidate_id="abc",
    )
    ok, msg = finding_publish_allowed(
        tm, title="IDOR /api/users", target="https://app.example.com", severity="high"
    )
    assert ok is True
    assert msg.startswith("verify_ok:")


def test_legacy_judge_gate_when_no_fireteam():
    tm = SimpleNamespace(
        _require_independent_verify=False,
        _verify_receipts={},
        _finding_receipts={},
        _engagement_brain={},
    )
    ok, msg = finding_publish_allowed(
        tm, title="IDOR /api/users", target="https://app.example.com", severity="high"
    )
    assert ok is False
    assert "JUDGE GATE" in msg


def test_info_findings_skip_gate():
    tm = SimpleNamespace(
        _require_independent_verify=True,
        _verify_receipts={},
        _finding_receipts={},
        _engagement_brain={},
    )
    ok, _ = finding_publish_allowed(
        tm, title="Missing header", target="https://app.example.com", severity="info"
    )
    assert ok is True


def test_apply_verdict_issues_receipt():
    brain = EngagementBrain(target="https://app.example.com")
    cand = submit_candidate(
        brain,
        title="Host header bypass",
        target="https://app.example.com",
        evidence="GET / with Host: peer",
        severity="high",
    )
    tm = SimpleNamespace(
        _engagement_brain=brain.to_dict(),
        _verify_receipts={},
    )
    updated = apply_verdict(
        tm,
        candidate_id=cand.id,
        verdict="confirmed",
        evidence="reproduced other-tenant fields",
    )
    assert updated is not None
    assert updated.status == "confirmed"
    ok, _ = check_verify_receipt(
        tm._verify_receipts,
        title="Host header bypass",
        target="https://app.example.com",
    )
    assert ok is True


def test_ingest_lifts_hunter_key_findings():
    brain = EngagementBrain(target="https://app.example.com")
    report = SimpleNamespace(
        specialist="api_authz",
        mission="Hunt IDOR on https://app.example.com/api/users",
        summary="User B object returned",
        key_findings=["IDOR on GET /api/users/{id} returns other user PII"],
    )
    created = ingest_report_findings(brain, [report])
    assert created
    assert brain.candidates
    assert brain.candidates[0]["status"] == "pending"


def test_untested_denom_blocks_complete():
    brain = EngagementBrain(target="https://app.example.com")
    brain.hypotheses = [_killed_card()]
    brain.surfaces = [
        {"method": "POST", "path": "/login", "host": "app.example.com", "takes_input": True},
        {"method": "GET", "path": "/api/users", "host": "app.example.com", "takes_input": True},
    ]
    seed_coverage_from_surfaces(brain)
    progress = methodology_progress(brain)
    assert progress["ready_to_complete_methods"] is True
    assert progress["ready_to_complete"] is False
    assert progress["coverage"]["untested_count"] >= 1


def test_skip_requires_reason_then_unblocks():
    brain = EngagementBrain(target="https://app.example.com")
    brain.hypotheses = [_killed_card()]
    brain.surfaces = [
        {"method": "POST", "path": "/login", "host": "app.example.com", "takes_input": True},
    ]
    seed_coverage_from_surfaces(brain)
    with pytest.raises(ValueError, match="reason"):
        record_surface_coverage(brain, method="POST", path="/login", status="skipped")
    record_surface_coverage(
        brain,
        method="POST",
        path="/login",
        host="app.example.com",
        status="skipped",
        reason="out of scope login SSO",
    )
    cov = coverage_progress(brain)
    assert cov["skipped"] == 1
    assert cov["ready_to_complete_coverage"] is True
    progress = methodology_progress(brain)
    assert progress["ready_to_complete"] is True


def test_pending_candidate_blocks_complete_even_if_coverage_done():
    brain = EngagementBrain(target="https://app.example.com")
    brain.hypotheses = [_killed_card()]
    brain.surfaces = [
        {"method": "GET", "path": "/api/users", "host": "app.example.com", "takes_input": True},
    ]
    seed_coverage_from_surfaces(brain)
    record_surface_coverage(
        brain,
        method="GET",
        path="/api/users",
        host="app.example.com",
        status="tested_clean",
        reason="no IDOR",
    )
    submit_candidate(
        brain,
        title="Maybe XSS",
        target="https://app.example.com",
        severity="medium",
    )
    progress = methodology_progress(brain)
    assert progress["pending_candidates"] == 1
    assert progress["ready_to_complete"] is False


def test_verifier_mission_includes_nonce_and_adversarial_framing():
    from app.services.agent.independent_verify import verifier_mission

    cand = FindingCandidate(
        id="abc",
        title="IDOR",
        nonce="deadbeefcafebabe",
        target="https://app.example.com",
    )
    text = verifier_mission(cand)
    assert "ADVERSARIAL" in text
    assert "X-Aegis-Verify: deadbeefcafebabe" in text
    assert "record_verify_verdict" in text
