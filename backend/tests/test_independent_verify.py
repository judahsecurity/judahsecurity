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
    publication_invariants,
    record_verify_receipt,
    submit_candidate,
    verified_publication_claim,
    verify_receipt_key,
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
    leo = _allowlists()["risk_assessor"]
    assert "assess_finding_risk" in leo
    assert "create_finding" not in leo
    assert "execute_curl" not in leo


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
    assert ok is False
    assert "Candidate changed" in msg


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
    assert "INDEPENDENT VERIFY GATE" in msg


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


def _confirmed_candidate() -> FindingCandidate:
    return FindingCandidate(
        id="candidate-1",
        title="IDOR /api/orders/1",
        description="Attacker reads the owner's controlled order",
        severity="high",
        target="https://app.example.com/api/orders/1",
        status="confirmed",
        nonce="nonce-1",
        verifier_run_id="verify-1",
        evidence_ids=["evidence-1"],
        verified_at="2026-09-23T00:00:00+00:00",
    )


def test_publication_invariants_reject_duplicate_or_mismatched_verifier_trace():
    brain = EngagementBrain(target="https://app.example.com")
    candidate = _confirmed_candidate()
    receipt = {
        "title": candidate.title,
        "target": candidate.target,
        "candidate_id": candidate.id,
        "revision": candidate.revision,
        "run_id": candidate.verifier_run_id,
        "nonce": candidate.nonce,
        "nonce_observed": True,
        "evidence_ids": ["evidence-1"],
    }
    assert publication_invariants(brain, candidate, receipt)[0] is True

    receipt["run_id"] = "different-verifier"
    assert publication_invariants(brain, candidate, receipt)[0] is False
    receipt["run_id"] = candidate.verifier_run_id
    candidate.finding_id = "finding-7"
    ok, why = publication_invariants(brain, candidate, receipt)
    assert ok is False
    assert "already published" in why


def test_durable_verify_receipt_rehydrates_after_restart(monkeypatch):
    brain = EngagementBrain(target="https://app.example.com")
    candidate = _confirmed_candidate()
    brain.candidates = [candidate.to_dict()]
    key = verify_receipt_key(candidate.title, candidate.target)
    brain.verification_receipts[key] = {
        "title": candidate.title,
        "target": candidate.target,
        "verdict": "confirmed",
        "candidate_id": candidate.id,
        "nonce": candidate.nonce,
        "nonce_observed": True,
        "evidence_ids": ["evidence-1"],
        "run_id": candidate.verifier_run_id,
        "revision": candidate.revision,
    }
    manager = SimpleNamespace(
        _engagement_brain=brain.to_dict(),
        _verify_receipts={},
    )
    store = SimpleNamespace(validate=lambda *args, **kwargs: (True, ""))
    monkeypatch.setattr(
        "app.services.agent.evidence_store.evidence_store",
        lambda _manager: store,
    )

    ok, why = check_verify_receipt(
        manager._verify_receipts,
        title=candidate.title,
        target=candidate.target,
        tools_manager=manager,
    )
    assert ok is True, why
    assert manager._verify_receipts[key]["run_id"] == candidate.verifier_run_id


def test_apply_verdict_requires_active_verifier_execution():
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
    assert updated is None
    ok, _ = check_verify_receipt(
        tm._verify_receipts,
        title="Host header bypass",
        target="https://app.example.com",
    )
    assert ok is False


def test_publication_uses_verified_description_without_changing_claim():
    candidate = FindingCandidate(
        id="proof-1", title="SQL injection in category",
        target="https://app.example.com/catalog", severity="high",
        description="Verified Boolean response difference on category.",
    )
    valid, reason, description = verified_publication_claim(
        candidate, title=candidate.title, target=candidate.target,
        severity="high",
    )
    assert valid and not reason
    assert description == candidate.description
    valid, reason, _ = verified_publication_claim(
        candidate, title=candidate.title, target="https://app.example.com/other",
        severity="high",
    )
    assert not valid and "target" in reason


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


def test_ingest_does_not_promote_failed_probe_to_vulnerability_candidate():
    brain = EngagementBrain(target="https://app.example.com")
    report = SimpleNamespace(
        specialist="xss", mission="Test https://app.example.com/catalog",
        summary="Probe handoff failed", key_findings=[
            "scoped_input_probe_assigned returned success=false, error=invalid_coverage_lease",
        ],
    )
    assert ingest_report_findings(brain, [report]) == []
    assert brain.candidates == []


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


def test_confirmed_candidate_blocks_complete_until_published():
    brain = EngagementBrain(target="https://app.example.com")
    brain.hypotheses = [_killed_card()]
    candidate = _confirmed_candidate().to_dict()
    brain.candidates = [candidate]

    progress = methodology_progress(brain)
    assert progress["unpublished_candidates"] == 1
    assert progress["ready_to_complete"] is False
    assert any(row["methodology_id"] == "publish" for row in progress["blockers"])

    candidate["finding_id"] = "finding-7"
    progress = methodology_progress(brain)
    assert progress["unpublished_candidates"] == 0
    assert progress["ready_to_complete"] is True


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


def test_cve_version_is_only_a_lead_in_verifier_mission():
    from app.services.agent.independent_verify import verifier_mission

    candidate = FindingCandidate(id="cve", title="CVE-2025-12345 on server")
    mission = verifier_mission(candidate)
    assert "Vulnerability class: known_cve; supported proof kinds: none yet" in mission
    assert "applicability lead" in mission
    assert "confirmed if your GET still shows" not in mission


def test_methodology_progress_surfaces_inconclusive_verdict_reason():
    brain = EngagementBrain(target="https://app.example.com")
    brain.hypotheses = [_killed_card()]
    candidate = FindingCandidate(
        id="candidate-1", title="SQL injection in search", status="inconclusive",
        verifier_summary="No independent Boolean SQLi proof",
    )
    brain.candidates = [candidate.to_dict()]
    progress = methodology_progress(brain)
    assert progress["candidate_verdicts"]["inconclusive"] == 1
    assert progress["inconclusive_candidates"][0]["reason"] == candidate.verifier_summary
    assert "Candidates inconclusive: 1" in progress["summary"]


def test_refutation_without_counterevidence_keeps_proof_gap_open():
    from app.services.agent.evidence_store import VerificationRun, verification_run
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    brain = EngagementBrain(target="https://app.example.com")
    brain.coverage_cells = [{"id": "cell-1", "status": "in_focus"}]
    candidate = submit_candidate(
        brain, title="Possible IDOR", target="https://app.example.com/api/orders/1",
        coverage_cell_id="cell-1",
    )
    manager = SimpleNamespace(_engagement_brain=brain.to_dict(), _verify_receipts={})
    token = verification_run.set(VerificationRun("verifier-1", candidate.id, candidate.revision, candidate.nonce))
    try:
        result = apply_verdict(
            manager, candidate_id=candidate.id, verdict="refuted",
            summary="Could not reproduce the claimed read",
        )
    finally:
        verification_run.reset(token)

    assert result.status == "inconclusive"
    assert result.counterevidence == {}
    assert "structured counterevidence" in result.proof_gap["reason"]
    assert manager._engagement_brain["coverage_cells"][0]["status"] == "inconclusive"
    progress = methodology_progress(engagement_brain_from_dict(manager._engagement_brain))
    assert progress["open_proof_gaps"][0]["next_step"]


@pytest.mark.parametrize(
    "response_path,expected",
    [("/api/orders/1", "refuted"), ("/login", "inconclusive")],
)
def test_fresh_counterevidence_can_refute_exact_candidate_path(response_path, expected):
    from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run

    target = "https://app.example.com/api/orders/1"
    brain = EngagementBrain(target="https://app.example.com")
    brain.coverage_cells = [{"id": "cell-1", "status": "in_focus"}]
    candidate = submit_candidate(
        brain, title="Possible IDOR", target=target, coverage_cell_id="cell-1",
    )
    store = EvidenceStore()
    manager = SimpleNamespace(
        _engagement_brain=brain.to_dict(), _verify_receipts={}, _evidence_store=store,
    )
    token = verification_run.set(VerificationRun("verifier-1", candidate.id, candidate.revision, candidate.nonce))
    try:
        artifact_id = store.record(
            "http_exchange",
            {"request": {"url": target}, "response": {
                "status": 403, "url": "https://app.example.com" + response_path,
            }},
            target=target, success=False,
        )
        result = apply_verdict(
            manager, candidate_id=candidate.id, verdict="refuted",
            summary="Attacker request was denied by the object owner check",
            evidence_ids=[artifact_id],
            proof={
                "kind": "counterevidence", "artifact_id": artifact_id,
                "control": "object owner authorization", "attacker_path": target,
                "response_status": 403, "observation": "403 on cross-owner read",
            },
        )
    finally:
        verification_run.reset(token)

    assert result.status == expected
    if expected == "refuted":
        assert result.counterevidence["artifact_id"] == artifact_id
        assert result.proof_gap == {}
    else:
        assert result.counterevidence == {}
        assert result.proof_gap["reason"]
    assert manager._engagement_brain["coverage_cells"][0]["status"] == (
        "tested_clean" if expected == "refuted" else "inconclusive"
    )


def test_refutation_cannot_cite_another_verifier_run():
    from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run

    target = "https://app.example.com/api/orders/1"
    brain = EngagementBrain(target="https://app.example.com")
    candidate = submit_candidate(brain, title="Possible IDOR", target=target)
    store = EvidenceStore()
    manager = SimpleNamespace(
        _engagement_brain=brain.to_dict(), _verify_receipts={}, _evidence_store=store,
    )
    old_token = verification_run.set(VerificationRun("old-run", candidate.id, candidate.revision, candidate.nonce))
    try:
        artifact_id = store.record(
            "http_exchange",
            {"request": {"url": target}, "response": {"status": 403}},
            target=target, success=False,
        )
    finally:
        verification_run.reset(old_token)
    token = verification_run.set(VerificationRun("new-run", candidate.id, candidate.revision, candidate.nonce))
    try:
        result = apply_verdict(
            manager, candidate_id=candidate.id, verdict="refuted",
            evidence_ids=[artifact_id],
            proof={
                "kind": "counterevidence", "artifact_id": artifact_id,
                "control": "object owner authorization", "attacker_path": target,
                "response_status": 403, "observation": "403 on cross-owner read",
            },
        )
    finally:
        verification_run.reset(token)
    assert result.status == "inconclusive"
    assert "fresh, complete HTTP exchange" in result.proof_gap["reason"]


def test_trusted_refuted_workflow_receipt_closes_candidate():
    from app.services.agent.evidence_store import VerificationRun, verification_run

    target = "https://app.example.com/api/orders/1"
    brain = EngagementBrain(target="https://app.example.com")
    candidate = submit_candidate(
        brain, title="Unauthorized order mutation", target=target, hypothesis_id="authz-1",
    )
    receipt = SimpleNamespace(
        run_id="proof-1", verdict="refuted", candidate_id=candidate.id,
        candidate_revision=candidate.revision, verifier_run_id="verifier-1",
        target=target, hypothesis_id="authz-1", evidence_ids=("setup", "attack", "verify"),
        strategy="authorization_mutation", attack_url=target,
        reason="Owner readback shows the controlled value unchanged",
    )
    manager = SimpleNamespace(
        _engagement_brain=brain.to_dict(), _verify_receipts={},
        _proof_engine=SimpleNamespace(receipts={"proof-1": receipt}),
    )
    token = verification_run.set(VerificationRun("verifier-1", candidate.id, candidate.revision, candidate.nonce))
    try:
        result = apply_verdict(
            manager, candidate_id=candidate.id, verdict="refuted",
            evidence_ids=list(receipt.evidence_ids),
            proof={"kind": "workflow", "run_id": "proof-1"},
        )
    finally:
        verification_run.reset(token)
    assert result.status == "refuted"
    assert result.counterevidence["observation"] == receipt.reason


def test_candidate_class_survives_serialization_and_revision():
    brain = EngagementBrain(target="https://app.example.com")
    candidate = submit_candidate(
        brain, title="SQL injection in search", vulnerability_class="sql_injection",
    )
    assert brain.candidates[0]["vulnerability_class"] == "sql_injection"
    updated = submit_candidate(
        brain, title=candidate.title, vulnerability_class="sql_injection", evidence="new evidence",
    )
    assert updated.vulnerability_class == "sql_injection"
    assert updated.revision == 2
