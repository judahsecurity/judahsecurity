"""String SQLi proof must be bounded, observed, and independently repeated."""

import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.evidence_store import EvidenceStore, VerificationRun, evidence_store, verification_run
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.coverage_cells import seed_parameter_coverage_cells
from app.services.agent.fireteam_service import get_specialist
from app.services.agent.independent_verify import (
    apply_verdict, check_verify_receipt, run_independent_verifiers,
    submit_candidate,
)
from app.services.agent.proof_policy import validate_proof
from app.services.agent.scoped_assessment import sqli_string
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.scoped_assessment.http_observe import _sql_error_family
from app.services.agent.scoped_assessment_tools import HUNTER_GET_BUDGET
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


def _observe_and(url, allowed_origins, storage_state):
    assert allowed_origins == ["https://app.example.test"]
    value = parse_qs(urlsplit(url).query)["category"][0]
    if " AND " in value and "--" in value:
        body = (b"one product" * 180 if value.split("'")[2] == value.split("'")[4]
                else b"no products" * 20)
    else:
        # Quote errors are suppressed, and OR is not a useful differential.
        body = b"one product" * 180
    return {
        "status": 200, "content_type": "text/html", "bytes_captured": len(body),
        "truncated": False, "redirected": False,
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }


def _and_proof(monkeypatch, nonce):
    monkeypatch.setattr(sqli_string.secrets, "randbelow", lambda _: int(nonce) - 10000)
    monkeypatch.setattr(sqli_string, "observe_get", _observe_and)
    baseline, variants, generated = sqli_string.plan_string_and_boolean(
        URL, parameter="category", allowed_origins=["https://app.example.test"],
    )
    proof = sqli_string.probe_string_and_boolean(
        baseline, variants, generated, parameter="category",
        allowed_origins=["https://app.example.test"], storage_state=None,
        before_request=lambda: None,
    )
    assert proof["requests_sent"] == 6 and proof["proof_confirmed"]
    return proof


def _observe_error(url, allowed_origins, storage_state):
    assert allowed_origins == ["https://app.example.test"]
    value = parse_qs(urlsplit(url).query)["category"][0]
    if value == "gin'":
        status, body, family = 500, b"PostgreSQL ERROR: unterminated string", "postgresql"
    else:
        status, body, family = 200, b"one product" * 180, ""
    return {
        "status": status, "content_type": "text/html", "bytes_captured": len(body),
        "truncated": False, "redirected": False,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "sql_error_family": family,
    }


def _error_proof(monkeypatch):
    monkeypatch.setattr(sqli_string, "observe_get", _observe_error)
    baseline, variants, _ = sqli_string.plan_string_boolean(
        URL, parameter="category", allowed_origins=["https://app.example.test"],
    )
    proof = sqli_string.probe_string_error(
        baseline, variants, parameter="category",
        allowed_origins=["https://app.example.test"], storage_state=None,
        before_request=lambda: None,
    )
    assert proof["proof_confirmed"] and proof["requests_sent"] == 5
    return proof


def test_sql_error_classifier_returns_only_specific_family():
    assert _sql_error_family(b"PostgreSQL ERROR: syntax error") == "postgresql"
    assert _sql_error_family(b"You have an error in your SQL syntax") == "mysql"
    assert _sql_error_family(b"PostgreSQL ERROR: invalid input syntax for type integer") == ""
    assert _sql_error_family(b"sqlite3.OperationalError: database is locked") == ""
    assert _sql_error_family(b"Internal Server Error") == ""


def test_error_proof_requires_repeated_specific_diagnostic(monkeypatch):
    proof = _error_proof(monkeypatch)
    proof["checks"]["quote_second"]["sql_error_family"] = ""
    assert not sqli_string.string_error_proof_valid(proof)
    proof = _error_proof(monkeypatch)
    proof["checks"]["baseline_first"]["sql_error_family"] = "postgresql"
    assert not sqli_string.string_error_proof_valid(proof)


def test_error_proof_requires_independent_matching_receipts(monkeypatch):
    store = EvidenceStore()
    hunter = store.record(
        "scoped_string_sqli", _error_proof(monkeypatch),
        target=TARGET, identity="anonymous",
    )
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        verifier = store.record(
            "scoped_string_sqli", _error_proof(monkeypatch),
            target=TARGET, identity="anonymous",
        )
    finally:
        verification_run.reset(token)
    candidate = SimpleNamespace(target=TARGET, evidence_ids=[hunter],
                                title="SQL injection in category")
    receipt = {"kind": "string_error_sqli", "hunter_artifact_id": hunter,
               "artifact_id": verifier}
    assert validate_proof(store, candidate, receipt, [verifier])[0]
    assert not validate_proof(store, candidate, receipt, [hunter])[0]


def test_error_proof_issues_publication_receipt_after_fresh_verifier(monkeypatch):
    manager = ASMToolsManager()
    store = evidence_store(manager)
    hunter = store.record(
        "scoped_string_sqli", _error_proof(monkeypatch),
        target=TARGET, identity="anonymous",
    )
    brain = EngagementBrain(target="https://app.example.test")
    candidate = submit_candidate(
        brain, title="SQL injection in category", target=TARGET,
        evidence_ids=[hunter], severity="high",
    )
    manager._engagement_brain = brain.to_dict()
    token = verification_run.set(VerificationRun("verifier-run", candidate.id, 1, candidate.nonce))
    try:
        verifier = store.record(
            "scoped_string_sqli", _error_proof(monkeypatch),
            target=TARGET, identity="anonymous",
        )
        verdict = apply_verdict(
            manager, candidate_id=candidate.id, verdict="confirmed",
            evidence="Repeated database-specific error under quote input",
            evidence_ids=[verifier],
            proof={"kind": "string_error_sqli", "hunter_artifact_id": hunter,
                   "artifact_id": verifier},
        )
    finally:
        verification_run.reset(token)
    assert verdict.status == "confirmed", verdict.verifier_summary
    assert check_verify_receipt(
        manager._verify_receipts, title=candidate.title, target=TARGET,
        tools_manager=manager,
    )[0]


@pytest.mark.asyncio
async def test_string_tool_confirms_database_error_before_and_controls(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {"scope": "https://app.example.test", "pages_visited": [URL]}
    monkeypatch.setattr(sqli_string, "observe_get", _observe_error)

    result = json.loads(await manager.scoped_string_sqli(URL, "category"))
    assert result["proof_confirmed"] is True
    assert result["proof_recipe"] == "string_error_v1"
    assert result["total_requests_sent"] == 13
    assert result["prior_or_evidence_id"]
    assert manager._scoped_get_count == 13


def test_and_boolean_proof_requires_repeated_differential(monkeypatch):
    proof = _and_proof(monkeypatch, "12345")
    assert sqli_string.string_sql_proof_valid(proof)
    proof["checks"]["false_second"]["bytes_captured"] += 200
    assert not sqli_string.string_sql_proof_valid(proof)
    proof = _and_proof(monkeypatch, "12345")
    proof["checks"]["false_first"]["bytes_captured"] = proof["checks"]["true_first"]["bytes_captured"]
    proof["checks"]["false_second"]["bytes_captured"] = proof["checks"]["true_second"]["bytes_captured"]
    assert not sqli_string.string_sql_proof_valid(proof)


def test_and_boolean_independent_receipts_must_use_matching_recipe(monkeypatch):
    store = EvidenceStore()
    hunter = store.record(
        "scoped_string_sqli", _and_proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        verifier = store.record(
            "scoped_string_sqli", _and_proof(monkeypatch, "67890"),
            target=TARGET, identity="anonymous",
        )
        different_recipe = store.record(
            "scoped_string_sqli", _proof(monkeypatch, "98765"),
            target=TARGET, identity="anonymous",
        )
    finally:
        verification_run.reset(token)
    candidate = SimpleNamespace(target=TARGET, evidence_ids=[hunter],
                                title="SQL injection in category")
    receipt = {"kind": "string_boolean_sqli", "hunter_artifact_id": hunter,
               "artifact_id": verifier}
    assert validate_proof(store, candidate, receipt, [verifier])[0]
    receipt["artifact_id"] = different_recipe
    assert not validate_proof(store, candidate, receipt, [different_recipe])[0]


@pytest.mark.asyncio
async def test_string_tool_tries_and_after_stable_unproven_or(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {"scope": "https://app.example.test", "pages_visited": [URL]}
    monkeypatch.setattr(sqli_string, "observe_get", _observe_and)
    result = json.loads(await manager.scoped_string_sqli(URL, "category"))
    assert result["proof_confirmed"] is True
    assert result["proof_recipe"] == "string_and_boolean_v1"
    assert result["total_requests_sent"] == 14
    assert result["prior_or_evidence_id"]
    assert manager._scoped_get_count == 14


@pytest.mark.asyncio
async def test_string_tool_preserves_or_receipt_when_and_budget_is_exhausted(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {"scope": "https://app.example.test", "pages_visited": [URL]}
    manager._scoped_get_count = HUNTER_GET_BUDGET - 8
    monkeypatch.setattr(sqli_string, "observe_get", _observe_and)

    result = json.loads(await manager.scoped_string_sqli(URL, "category"))
    assert result["proof_confirmed"] is False
    assert result["proof_recipe"] == "string_or_boolean_v1"
    assert result["and_followup_error"] == "ValueError"
    assert result["evidence_id"]
    assert result["requests_sent"] == 8
    assert "total_requests_sent" not in result
    assert manager._scoped_get_count == HUNTER_GET_BUDGET


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
async def test_string_tool_preflights_mapped_application_operation(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {
        "scope": "https://app.example.test",
        "parameter_inventory": [{
            "method": "GET", "path": "/catalog", "name": "category",
            "location": "query", "source": "application_operation",
        }],
    }
    preflights = []

    def observe(url, allowed_origins, storage_state):
        preflights.append(url)
        assert allowed_origins == ["https://app.example.test"]
        assert parse_qs(urlsplit(url).query)["category"][0].startswith("AegisProbe")
        return {"status": 200, "redirected": False, "truncated": False}

    def probe(baseline, variants, nonce, **_kwargs):
        assert baseline == preflights[0]
        return {"target": TARGET, "operation": "sqli_boolean_string",
                "proof_confirmed": False, "nonce": nonce, "parameter": "category"}

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.http_observe.observe_get", observe)
    monkeypatch.setattr(sqli_string, "probe_string_boolean", probe)
    result = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    assert result["baseline_source"] == "observed_parameter_preflight"
    assert len(preflights) == 1


@pytest.mark.asyncio
async def test_string_tool_prefers_private_observed_get_over_invented_baseline(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    manager._capability_map = {
        "scope": "https://app.example.test",
        "parameter_inventory": [{
            "method": "GET", "path": "/catalog", "name": "category",
            "location": "query", "source": "browser_traffic",
            "artifact_id": "capture-category",
        }],
    }
    public, private = package_exchange(
        url=URL, expected_origin="https://app.example.test",
        action_ref="catalog-filter", method="GET", resource_type="fetch",
        status=200, content_type="text/html", request_body=b"",
        response_body=b"catalog",
    )
    manager._scoped_browser_exchanges = {
        "capture-category": {"identity": "anonymous", "private": private,
                             "public": public, "verifier_run_id": None},
    }

    def probe(baseline, variants, nonce, **_kwargs):
        assert baseline == URL
        return {"target": TARGET, "operation": "sqli_boolean_string",
                "proof_confirmed": False, "nonce": nonce,
                "parameter": "category", "requests_sent": 8}

    monkeypatch.setattr(sqli_string, "probe_string_boolean", probe)
    result = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    assert result["baseline_source"] == "observed_url"
    assert manager._scoped_get_count == 8


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
    manager._scoped_get_count = HUNTER_GET_BUDGET
    with pytest.raises(ValueError, match="budget exhausted"):
        await manager.scoped_string_sqli(TARGET, "category")
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        result = json.loads(await manager.scoped_string_sqli(TARGET, "category"))
    finally:
        verification_run.reset(token)
    assert result["baseline_source"] == "observed_url"
    assert manager._scoped_verify_get_count == 8
    assert manager._scoped_get_count == HUNTER_GET_BUDGET


@pytest.mark.asyncio
@pytest.mark.parametrize("source", [
    "browser_link", "page_url", "captured_api", "observed_form", "api_endpoint",
])
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


@pytest.mark.asyncio
@pytest.mark.parametrize("linked_at_submission", [False, True])
async def test_independent_verifier_replays_exact_observed_string_sqli_before_model(
    monkeypatch, linked_at_submission,
):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    store = evidence_store(manager)
    hunter = store.record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "sqli")
    candidate = submit_candidate(
        brain, title="SQL injection in catalog category", target=TARGET,
        vulnerability_class="sql_injection",
        coverage_cell_id=cell["id"] if linked_at_submission else "",
        identity="anonymous", parameter="query:category", evidence_ids=[hunter],
    )
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def execute(name, args):
        calls.append((name, args))
        assert name == "scoped_string_sqli"
        proof = _proof(monkeypatch, "67890")
        artifact_id = store.record(
            "scoped_string_sqli", proof, target=TARGET, identity="anonymous",
        )
        return {"success": True, "output": json.dumps({**proof, "evidence_id": artifact_id})}

    manager.execute = execute
    reports = await run_independent_verifiers(
        [candidate], llm=None, tools_manager=manager, targets=[TARGET],
    )
    assert reports[0]["status"] == "confirmed"
    assert manager._engagement_brain["candidates"][0]["coverage_cell_id"] == cell["id"]
    assert calls == [("scoped_string_sqli", {
        "url": TARGET, "parameter": "category", "identity": "anonymous",
    })]
    assert check_verify_receipt(
        manager._verify_receipts, title=candidate.title, target=TARGET,
        tools_manager=manager,
    )[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("candidate_target", [TARGET, "https://app.example.test:443/catalog"])
async def test_candidate_handoff_links_real_sql_proof_to_observed_cell(monkeypatch, candidate_target):
    manager = ASMToolsManager()
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    manager._engagement_brain = brain.to_dict()
    proof = _proof(monkeypatch, "12345")
    proof["target"] = candidate_target
    proof_id = evidence_store(manager).record(
        "scoped_string_sqli", proof,
        target=candidate_target, identity="anonymous",
    )
    await manager.submit_finding_candidate(
        title="SQL injection in catalog category", target=candidate_target,
        evidence_ids=[proof_id], vulnerability_class="sql_injection",
    )
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "sqli")
    assert manager._engagement_brain["candidates"][0]["coverage_cell_id"] == cell["id"]
    assert manager._engagement_brain["candidates"][0]["parameter"] == "query:category"


@pytest.mark.asyncio
async def test_candidate_handoff_recovers_uncited_exact_sql_proof(monkeypatch):
    manager = ASMToolsManager()
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    manager._engagement_brain = brain.to_dict()
    proof_id = evidence_store(manager).record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )

    await manager.submit_finding_candidate(
        title="SQL injection in catalog category",
        target=TARGET + "?category=gin", vulnerability_class="sql_injection",
    )

    candidate = manager._engagement_brain["candidates"][0]
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "sqli")
    assert candidate["target"] == TARGET
    assert candidate["coverage_cell_id"] == cell["id"]
    assert candidate["evidence_ids"] == [proof_id]


@pytest.mark.asyncio
async def test_uncited_sql_proof_is_not_borrowed_for_generic_claim(monkeypatch):
    manager = ASMToolsManager()
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    manager._engagement_brain = brain.to_dict()
    evidence_store(manager).record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )

    await manager.submit_finding_candidate(
        title="Possible SQL injection in catalog", target=TARGET,
        vulnerability_class="sql_injection",
    )

    candidate = manager._engagement_brain["candidates"][0]
    assert candidate["coverage_cell_id"] == ""
    assert candidate["evidence_ids"] == []


@pytest.mark.asyncio
async def test_fresh_sql_proof_revises_same_observed_candidate(monkeypatch):
    manager = ASMToolsManager()
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    manager._engagement_brain = brain.to_dict()
    store = evidence_store(manager)
    first_id = store.record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )
    await manager.submit_finding_candidate(
        title="SQL injection in catalog category", target=TARGET,
        evidence_ids=[first_id], vulnerability_class="sql_injection",
    )
    first = manager._engagement_brain["candidates"][0]
    manager._engagement_brain["candidates"][0]["status"] = "inconclusive"
    second_id = store.record(
        "scoped_string_sqli", _proof(monkeypatch, "67890"),
        target=TARGET, identity="anonymous",
    )

    await manager.submit_finding_candidate(
        title="Different wording for SQLi in category", target=TARGET,
        evidence_ids=[second_id], vulnerability_class="sql_injection",
    )

    candidates = manager._engagement_brain["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["id"] == first["id"]
    assert candidates[0]["revision"] == 2
    assert candidates[0]["status"] == "pending"
    assert set(candidates[0]["evidence_ids"]) == {first_id, second_id}


@pytest.mark.asyncio
async def test_sql_verifier_inconclusive_replay_does_not_fall_into_model_loop(monkeypatch):
    manager = ASMToolsManager()
    store = evidence_store(manager)
    hunter = store.record(
        "scoped_string_sqli", _proof(monkeypatch, "12345"),
        target=TARGET, identity="anonymous",
    )
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    cell = next(row for row in brain.coverage_cells if row.get("test_type") == "sqli")
    candidate = submit_candidate(
        brain, title="SQL injection in catalog category", target=TARGET,
        vulnerability_class="sql_injection", coverage_cell_id=cell["id"],
        evidence_ids=[hunter],
    )
    manager._engagement_brain = brain.to_dict()
    calls = []

    async def execute(name, args):
        calls.append(name)
        return {"success": True, "output": json.dumps({"proof_confirmed": False})}

    manager.execute = execute
    reports = await run_independent_verifiers(
        [candidate], llm=None, tools_manager=manager, targets=[TARGET],
    )
    assert calls == ["scoped_string_sqli"]
    assert reports[0]["status"] == "inconclusive"
    assert "did not confirm" in reports[0]["verifier_summary"]


def _numeric_receipt(nonce):
    names = ("baseline_first", "true_first", "false_first",
             "true_second", "false_second", "baseline_last")
    hashes = ("a" * 64, "a" * 64, "b" * 64,
              "a" * 64, "b" * 64, "a" * 64)
    return {
        "operation": "sqli_boolean_numeric", "proof_recipe": "numeric_and_boolean_v1",
        "proof_confirmed": True, "method": "GET", "location": "query",
        "target": TARGET, "parameter": "category", "nonce": nonce,
        "checks": {name: {"status": 200, "content_type": "text/html",
                          "truncated": False, "redirected": False,
                          "body_sha256": digest}
                   for name, digest in zip(names, hashes)},
    }


@pytest.mark.asyncio
async def test_numeric_sql_proof_handoff_and_independent_replay():
    manager = ASMToolsManager()
    store = evidence_store(manager)
    hunter = store.record(
        "scoped_numeric_sqli", _numeric_receipt("12345"),
        target=TARGET, identity="anonymous",
    )
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.test", "path": "/catalog",
        "name": "category", "location": "query", "identity": "anonymous",
        "source": "browser_link", "testable": True,
    }])
    manager._engagement_brain = brain.to_dict()
    await manager.submit_finding_candidate(
        title="Numeric SQL injection in category", target=TARGET,
        evidence_ids=[hunter], vulnerability_class="sql_injection",
    )
    candidate = manager._engagement_brain["candidates"][0]
    assert candidate["coverage_cell_id"]
    calls = []

    async def execute(name, args):
        calls.append(name)
        assert args == {"url": TARGET, "parameter": "category", "identity": "anonymous"}
        proof = _numeric_receipt("67890")
        artifact_id = store.record(
            "scoped_numeric_sqli", proof, target=TARGET, identity="anonymous",
        )
        return {"success": True, "output": json.dumps({**proof, "evidence_id": artifact_id})}

    manager.execute = execute
    from app.services.agent.independent_verify import candidate_from_dict
    reports = await run_independent_verifiers(
        [candidate_from_dict(candidate)], llm=None, tools_manager=manager,
        targets=[TARGET],
    )
    assert calls == ["scoped_numeric_sqli"]
    assert reports[0]["status"] == "confirmed"
