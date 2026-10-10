"""String SQLi proof must be bounded, observed, and independently repeated."""

import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.evidence_store import EvidenceStore, VerificationRun, evidence_store, verification_run
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.fireteam_service import get_specialist
from app.services.agent.independent_verify import apply_verdict, check_verify_receipt, submit_candidate
from app.services.agent.proof_policy import validate_proof
from app.services.agent.scoped_assessment import sqli_string
from app.services.agent.tools import ASMToolsManager


TARGET = "https://app.example.test/catalog"
URL = TARGET + "?category=gin"


def _observe(url, allowed_origins, storage_state):
    assert allowed_origins == ["https://app.example.test"]
    value = parse_qs(urlsplit(url).query)["category"][0]
    if value == "gin'":
        status, body = 500, b"Internal Server Error"
    elif " OR " in value and "--" in value:
        status, body = 200, b"all products" * 200 if value.split("'")[2] == value.split("'")[4] else b"no products" * 60
    elif value == "gin''":
        status, body = 200, b"no products" * 60
    else:
        status, body = 200, b"one product" * 70
    return {
        "status": status, "content_type": "text/html", "bytes_captured": len(body),
        "truncated": False, "redirected": False,
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }


def _proof(monkeypatch, nonce):
    monkeypatch.setattr(sqli_string.secrets, "randbelow", lambda _: int(nonce) - 10000)
    monkeypatch.setattr(sqli_string, "observe_get", _observe)
    baseline, variants, generated = sqli_string.plan_string_boolean(
        URL, parameter="category", allowed_origins=["https://app.example.test"],
    )
    result = sqli_string.probe_string_boolean(
        baseline, variants, generated, parameter="category",
        allowed_origins=["https://app.example.test"], storage_state=None,
        before_request=lambda: None,
    )
    assert result["requests_sent"] == 8
    assert result["proof_confirmed"]
    return result


def test_string_boolean_requires_quote_controls_stability_and_distinct_branches(monkeypatch):
    proof = _proof(monkeypatch, "12345")
    assert sqli_string.string_sql_proof_valid(proof)
    proof["checks"]["true_second"]["body_sha256"] = "f" * 64
    assert sqli_string.string_sql_proof_valid(proof)
    proof["checks"]["quote_error"]["status"] = 200
    assert not sqli_string.string_sql_proof_valid(proof)
    proof = _proof(monkeypatch, "12345")
    proof["checks"]["false_second"]["bytes_captured"] += 200
    assert not sqli_string.string_sql_proof_valid(proof)


def test_string_boolean_rejects_nonordinary_or_duplicate_input():
    with pytest.raises(ValueError, match="ordinary observed string"):
        sqli_string.plan_string_boolean(
            TARGET + "?category=gin%27", parameter="category",
            allowed_origins=["https://app.example.test"],
        )
    with pytest.raises(ValueError, match="exactly once"):
        sqli_string.plan_string_boolean(
            URL + "&category=gin", parameter="category",
            allowed_origins=["https://app.example.test"],
        )


def test_string_boolean_publication_needs_independent_matching_receipts(monkeypatch):
    store = EvidenceStore()
    hunter = store.record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        verifier = store.record(
            "scoped_string_sqli", _proof(monkeypatch, "67890"),
            target=TARGET, identity="anonymous",
        )
    finally:
        verification_run.reset(token)
    candidate = SimpleNamespace(target=TARGET, evidence_ids=[hunter],
                                title="SQL injection in category")
    receipt = {"kind": "string_boolean_sqli", "hunter_artifact_id": hunter, "artifact_id": verifier}
    assert validate_proof(store, candidate, receipt, [verifier])[0]
    assert not validate_proof(store, candidate, receipt, [hunter])[0]


@pytest.mark.asyncio
async def test_string_tool_requires_mapped_parameter_and_exact_scope(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {
        "scope": "https://app.example.test",
        "pages_visited": [URL],
    }

    def fake_probe(baseline, variants, nonce, **kwargs):
        assert baseline == URL and len(variants) == 8
        return {"target": TARGET, "operation": "sqli_boolean_string",
                "proof_confirmed": True, "nonce": nonce, "parameter": "category"}

    monkeypatch.setattr(sqli_string, "probe_string_boolean", fake_probe)
    result = json.loads(await manager.scoped_string_sqli(URL, "category"))
    assert result["proof_confirmed"] and result["finding"] is False
    canonical = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    assert canonical["proof_confirmed"]
    assert manager.get_tool("scoped_string_sqli") is not None
    with pytest.raises(ValueError, match="mapped GET query parameter"):
        await manager.scoped_string_sqli(TARGET + "?other=gin", "other")
    with pytest.raises(ValueError):
        await manager.scoped_string_sqli("https://other.example.test/catalog?category=gin", "category")

    manager._capability_map = {
        "scope": "https://app.example.test",
        "forms": [{"method": "GET", "action": TARGET, "fields": ["category"]}],
    }
    preflights = []

    def observe_form(url, allowed_origins, storage_state):
        preflights.append(url)
        return {"status": 200, "redirected": False, "truncated": False}

    def probe_form(baseline, variants, nonce, **kwargs):
        assert baseline == preflights[0]
        assert parse_qs(urlsplit(baseline).query)["category"][0].startswith("AegisProbe")
        return {"target": TARGET, "operation": "sqli_boolean_string",
                "proof_confirmed": False, "nonce": nonce, "parameter": "category"}

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.http_observe.observe_get", observe_form)
    monkeypatch.setattr(sqli_string, "probe_string_boolean", probe_form)
    form_result = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    assert form_result["baseline_source"] == "observed_get_form"
    assert len(preflights) == 1


@pytest.mark.asyncio
async def test_string_tool_uses_private_browser_link_and_reserves_verifier_budget(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {
        "scope": "https://app.example.test",
        "parameter_inventory": [{"method": "GET", "path": "/catalog",
                                 "name": "category", "location": "query",
                                 "source": "browser_link"}],
    }
    manager._scoped_link_baselines = {"anonymous": [URL]}

    def fake_probe(baseline, variants, nonce, **kwargs):
        assert baseline == URL
        return {"target": TARGET, "operation": "sqli_boolean_string",
                "proof_confirmed": False, "nonce": nonce, "parameter": "category"}

    monkeypatch.setattr(sqli_string, "probe_string_boolean", fake_probe)
    manager._scoped_get_count = 160
    with pytest.raises(ValueError, match="budget exhausted"):
        await manager.scoped_string_sqli(TARGET, "category")
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        result = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    finally:
        verification_run.reset(token)
    assert result["baseline_source"] == "observed_url"
    assert manager._scoped_verify_get_count == 8
    assert manager._scoped_get_count == 160


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["browser_link", "page_url", "captured_api"])
async def test_string_tool_preflights_observed_link_when_browser_kept_only_names(monkeypatch, source):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {
        "scope": "https://app.example.test",
        "parameter_inventory": [{"method": "GET", "path": "/catalog",
                                 "name": "category", "location": "query",
                                 "source": source}],
    }
    preflights = []

    def observe(url, allowed_origins, storage_state):
        preflights.append(url)
        return {"status": 200, "redirected": False, "truncated": False}

    def probe(baseline, variants, nonce, **kwargs):
        assert baseline == preflights[0]
        assert parse_qs(urlsplit(baseline).query)["category"][0].startswith("AegisProbe")
        return {"target": TARGET, "operation": "sqli_boolean_string",
                "proof_confirmed": False, "nonce": nonce, "parameter": "category",
                "requests_sent": 8}

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.http_observe.observe_get", observe)
    monkeypatch.setattr(sqli_string, "probe_string_boolean", probe)
    result = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    assert result["baseline_source"] == "observed_parameter_preflight"
    assert len(preflights) == 1
    assert manager._scoped_get_count == 9


@pytest.mark.asyncio
async def test_browser_link_reaches_string_proof_without_exposing_its_value(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")

    async def fake_browser(**kwargs):
        kwargs["link_baselines"].append(URL)
        return ({"operation": "map", "final_origin": "https://app.example.test",
                 "final_path": "/catalog", "status": 200, "requests": [],
                 "link_query_inputs": [{"path": "/catalog", "query_keys": ["category"]}],
                 "forms": []}, None)

    monkeypatch.setattr(
        "app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser,
    )
    observed = await manager.scoped_browser_assessment("map", TARGET)
    assert "category=gin" not in observed

    def fake_probe(baseline, variants, nonce, **kwargs):
        assert baseline == URL
        return {"target": TARGET, "operation": "sqli_boolean_string",
                "proof_confirmed": False, "nonce": nonce, "parameter": "category"}

    monkeypatch.setattr(sqli_string, "probe_string_boolean", fake_probe)
    result = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    assert result["baseline_source"] == "observed_url"


def test_inconclusive_candidate_requires_new_proof_before_retry():
    brain = EngagementBrain(target="https://app.example.test")
    candidate = submit_candidate(
        brain, title="String SQLi", target=TARGET, evidence_ids=["hunter-old"],
    )
    brain.candidates[0]["status"] = "inconclusive"
    brain.candidates[0]["verifier_summary"] = "Unsupported proof kind"
    manager = SimpleNamespace(_engagement_brain=brain.to_dict(), _verify_receipts={})
    ok, message = check_verify_receipt(
        manager._verify_receipts, title="String SQLi", target=TARGET,
        tools_manager=manager,
    )
    assert not ok and "Do not retry" in message and "Unsupported proof kind" in message
    unchanged = submit_candidate(brain, title="String SQLi", target=TARGET, evidence_ids=["hunter-old"])
    assert unchanged.revision == candidate.revision and unchanged.status == "inconclusive"
    reworded = submit_candidate(brain, title="String SQLi", target=TARGET, evidence="Same proof, new wording")
    assert reworded.revision == candidate.revision and reworded.status == "inconclusive"
    revised = submit_candidate(brain, title="String SQLi", target=TARGET, evidence_ids=["hunter-new"])
    assert revised.revision == candidate.revision + 1 and revised.status == "pending"


def test_hunter_and_independent_verifier_can_use_string_proof():
    assert "scoped_string_sqli" in get_specialist("sqli").allowed_tools
    assert "scoped_string_sqli" in get_specialist("independent_verifier").allowed_tools


@pytest.mark.parametrize("serialized_proof", [False, True])
def test_string_proof_issues_publication_receipt_after_fresh_verifier(monkeypatch, serialized_proof):
    manager = ASMToolsManager()
    store = evidence_store(manager)
    hunter = store.record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )
    brain = EngagementBrain(target="https://app.example.test")
    candidate = submit_candidate(
        brain, title="String SQLi", description="Boolean control changed catalog results",
        target=TARGET, evidence_ids=[hunter], severity="high",
    )
    manager._engagement_brain = brain.to_dict()
    token = verification_run.set(VerificationRun("verifier-run", candidate.id, 1, candidate.nonce))
    try:
        verifier = store.record(
            "scoped_string_sqli", _proof(monkeypatch, "67890"),
            target=TARGET, identity="anonymous",
        )
        proof = {"kind": "string_boolean_sqli", "hunter_artifact_id": hunter,
                 "artifact_id": verifier}
        verdict = apply_verdict(
            manager, candidate_id=candidate.id, verdict="confirmed",
            evidence="Fresh verifier reproduced quote error and stable Boolean branch expansion",
            evidence_ids=[verifier],
            proof=json.dumps(proof) if serialized_proof else proof,
        )
    finally:
        verification_run.reset(token)
    assert verdict.status == "confirmed", verdict.verifier_summary
    assert check_verify_receipt(
        manager._verify_receipts, title=candidate.title, target=TARGET,
        tools_manager=manager,
    )[0]


def test_malformed_verifier_proof_is_inconclusive_not_a_crash(monkeypatch):
    manager = ASMToolsManager()
    store = evidence_store(manager)
    hunter = store.record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )
    brain = EngagementBrain(target="https://app.example.test")
    candidate = submit_candidate(
        brain, title="String SQLi", target=TARGET, evidence_ids=[hunter], severity="high",
    )
    manager._engagement_brain = brain.to_dict()
    token = verification_run.set(VerificationRun("verifier-run", candidate.id, 1, candidate.nonce))
    try:
        verifier = store.record(
            "scoped_string_sqli", _proof(monkeypatch, "67890"),
            target=TARGET, identity="anonymous",
        )
        verdict = apply_verdict(
            manager, candidate_id=candidate.id, verdict="confirmed",
            evidence="Fresh response controls", evidence_ids=[verifier], proof="not JSON",
        )
    finally:
        verification_run.reset(token)
    assert verdict.status == "inconclusive"
