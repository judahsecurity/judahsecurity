"""Offline POST form and JSON SQLi regressions from captured requests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.coverage_cells import seed_parameter_coverage_cells
from app.services.agent.independent_verify import (
    FindingCandidate, _verify_scoped_sql_candidate, observed_sql_cell_for_proof,
)
from app.services.agent.evidence_store import VerificationRun, evidence_store, verification_run
from app.services.agent.proof_policy import validate_proof
from app.services.agent.observed_input_batch import run_observed_input_batch
from app.services.agent.scoped_assessment import body_probe
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.tools import ASMToolsManager


TARGET = "https://app.example.test/controllers/extraeDataContenido"
MYSQL_ERROR = (b"SQLSTATE[42000]: Syntax error or access violation: 1064 "
               b"You have an error in your SQL syntax near 'WHERE activo=1'")


def _capture(body: bytes) -> bytes:
    return json.dumps({
        "url": TARGET, "method": "POST", "resource_type": "xhr",
        "request_content_type": "application/x-www-form-urlencoded",
        "request_body_base64": base64.b64encode(body).decode(),
    }).encode()


def _row(data: bytes, request_body: bytes = b"template=botox") -> dict:
    return {
        "status": 200, "content_type": "text/html", "bytes_captured": len(data),
        "truncated": False, "redirected": False,
        "body_sha256": hashlib.sha256(data).hexdigest(),
        "request_sha256": hashlib.sha256(request_body).hexdigest(),
        "sql_error_family": "mysql" if b"You have an error in your SQL syntax" in data else "",
    }


@pytest.mark.parametrize("captured_body, parameter", [
    (b"template=fotos_AyD&filtro=All", "template"),
    (b"template=botox", "template"),
    (b"data%5Busername%5D=dfdf", "data[username]"),
])
def test_post_form_baseline_quote_and_independent_error_controls(monkeypatch, captured_body, parameter):
    private = _capture(captured_body)
    url, mime, baseline, quote_body, escaped_body = body_probe.plan_sql_error_form(
        private, parameter=parameter, allowed_origins=["https://app.example.test"],
    )
    assert baseline == captured_body
    assert quote_body != baseline and escaped_body != quote_body
    if b"filtro=" in captured_body:
        assert parse_qs(quote_body.decode())["filtro"] == ["All"]

    sent = []

    def observe(_url, _mime, request_body, *_args, **_kwargs):
        sent.append(request_body)
        value = parse_qs(request_body.decode())[parameter][0]
        return _row(MYSQL_ERROR if value.endswith("'") and not value.endswith("''")
                    else b"ordinary response", request_body)

    monkeypatch.setattr(body_probe, "_observe_post", observe)
    lead = body_probe.probe_observed_body(
        url, mime, baseline, quote_body, parameter=parameter,
        allowed_origins=["https://app.example.test"], storage_state=None,
    )
    assert lead["changed"] and lead["sql_error_signal"]
    assert lead["finding"] is False
    proof = body_probe.probe_sql_error_form(
        url, mime, baseline, quote_body, escaped_body,
        parameter=parameter, allowed_origins=["https://app.example.test"],
        storage_state=None, initial=lead,
    )
    assert sent == [baseline, quote_body, escaped_body, quote_body, baseline]
    assert proof["proof_confirmed"] is True
    assert body_probe.post_sql_error_proof_valid(proof)
    assert proof["finding"] is False


def test_post_error_controls_reject_a_preexisting_or_escaped_quote_error(monkeypatch):
    url, mime, baseline, quote_body, escaped_body = body_probe.plan_sql_error_form(
        _capture(b"template=botox"), parameter="template",
        allowed_origins=["https://app.example.test"],
    )
    monkeypatch.setattr(body_probe, "_observe_post", lambda _url, _mime, body, *_args, **_kwargs: _row(MYSQL_ERROR, body))
    lead = body_probe.probe_observed_body(
        url, mime, baseline, quote_body, parameter="template",
        allowed_origins=["https://app.example.test"], storage_state=None,
    )
    assert lead["sql_error_signal"] is False

    def escaped_also_errors(_url, _mime, request_body, *_args, **_kwargs):
        return _row(b"ordinary response" if request_body == baseline else MYSQL_ERROR, request_body)

    monkeypatch.setattr(body_probe, "_observe_post", escaped_also_errors)
    proof = body_probe.probe_sql_error_form(
        url, mime, baseline, quote_body, escaped_body,
        parameter="template", allowed_origins=["https://app.example.test"],
        storage_state=None,
    )
    assert proof["proof_confirmed"] is False


def test_post_json_error_controls_preserve_other_observed_fields(monkeypatch):
    private = json.dumps({
        "url": TARGET, "method": "POST", "resource_type": "xhr",
        "request_content_type": "application/json",
        "request_body_base64": base64.b64encode(
            b'{"filter":{"template":"botox"},"page":2}',
        ).decode(),
    }).encode()
    url, mime, baseline, quote_body, escaped_body = body_probe.plan_sql_error_body(
        private, parameter="/filter/template", allowed_origins=["https://app.example.test"],
    )
    assert all(json.loads(body)["page"] == 2 for body in (baseline, quote_body, escaped_body))
    assert json.loads(quote_body)["filter"]["template"] == "botox'"
    assert json.loads(escaped_body)["filter"]["template"] == "botox''"

    def observe(_url, _mime, request_body, *_args, **_kwargs):
        value = json.loads(request_body)["filter"]["template"]
        return _row(MYSQL_ERROR if value.endswith("'") and not value.endswith("''")
                    else b"ordinary response", request_body)

    monkeypatch.setattr(body_probe, "_observe_post", observe)
    lead = body_probe.probe_observed_body(
        url, mime, baseline, quote_body, parameter="/filter/template",
        allowed_origins=["https://app.example.test"], storage_state=None,
    )
    proof = body_probe.probe_sql_error_body(
        url, mime, baseline, quote_body, escaped_body, parameter="/filter/template",
        allowed_origins=["https://app.example.test"], storage_state=None, initial=lead,
    )
    assert proof["proof_recipe"] == "post_json_error_v1"
    assert proof["proof_confirmed"] is True
    assert body_probe.post_sql_error_proof_valid(proof)


def test_post_error_proof_binds_same_capture_field_and_independent_receipt():
    request_bodies = {"baseline_first": b"template=botox", "quote_first": b"template=botox%27",
                      "escaped_quote": b"template=botox%27%27", "quote_second": b"template=botox%27",
                      "baseline_last": b"template=botox"}
    checks = {key: _row(MYSQL_ERROR if key.startswith("quote") else b"ordinary response", request_bodies[key])
              for key in body_probe.SQL_ERROR_CHECK_ORDER}
    payload = {
        "operation": "sqli_error_form", "proof_recipe": "post_form_error_v1",
        "method": "POST", "location": "form", "parameter": "template",
        "target": TARGET, "source_artifact_id": "capture-1",
        "baseline_request_sha256": hashlib.sha256(b"template=botox").hexdigest(),
        "requests_sent": 5, "checks": checks, "proof_confirmed": True,
    }
    assert body_probe.post_sql_error_proof_valid(payload)
    hunter = {"id": "hunter", "kind": "scoped_body_sqli_error", "target": TARGET,
              "identity": "owner", "created_at": 1, "payload": copy.deepcopy(payload)}
    verifier = {"id": "verifier", "kind": "scoped_body_sqli_error", "target": TARGET,
                "identity": "owner", "created_at": 2, "payload": copy.deepcopy(payload)}
    store = SimpleNamespace(records={"hunter": hunter, "verifier": verifier})
    candidate = SimpleNamespace(target=TARGET, evidence_ids=["hunter"],
                                title="SQL injection in template", description="",
                                vulnerability_class="sql_injection")
    proof = {"kind": "post_error_sqli", "hunter_artifact_id": "hunter",
             "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"])[0]
    brain = SimpleNamespace(coverage_cells=[{
        "id": "cell-1", "source": "parameter_inventory",
        "observation_source": "browser_traffic", "test_type": "sqli",
        "method": "POST", "host": "app.example.test",
        "path": "/controllers/extraeDataContenido",
        "parameter": "body_form:template", "identity": "owner",
        "capture_id": "capture-1",
    }])
    assert observed_sql_cell_for_proof(
        brain, store, target=TARGET, evidence_ids=["hunter"],
    )["id"] == "cell-1"
    verifier["payload"]["checks"]["quote_second"]["request_sha256"] = hashlib.sha256(b"different").hexdigest()
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"]["checks"]["quote_second"]["request_sha256"] = checks["quote_first"]["request_sha256"]
    verifier["payload"]["source_artifact_id"] = "capture-2"
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


@pytest.mark.parametrize("request_body, content_type, parameter, cell_location", [
    (b"template=botox", "application/x-www-form-urlencoded; charset=UTF-8", "template", "body_form"),
    (b'{"template":"botox","page":2}', "application/json", "/template", "body_json"),
])
@pytest.mark.asyncio
async def test_approved_capture_reaches_fresh_post_verifier(
    monkeypatch, request_body, content_type, parameter, cell_location,
):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    manager._assessment_scope.add("app.example.test")
    manager.set_scoped_assessment_policy({
        "body_replay_paths": ["/controllers/extraeDataContenido"],
    })
    public, private = package_exchange(
        url=TARGET, expected_origin="https://app.example.test",
        action_ref="navigate", method="POST", resource_type="xhr", status=200,
        content_type="text/html", request_body=request_body,
        response_body=b"ordinary response",
        request_content_type=content_type,
        request_headers={
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Origin": "https://app.example.test",
            "Referer": "https://app.example.test/materials/botox",
            "Cookie": "never-copy=this",
        },
    )
    assert body_probe.safe_replay_headers(private) == {
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Origin": "https://app.example.test",
        "Referer": "https://app.example.test/materials/botox",
    }
    store = evidence_store(manager)
    capture_id = store.record("scoped_browser_exchange", public, target=TARGET,
                              identity="anonymous")
    manager._scoped_browser_exchanges = {
        capture_id: {"identity": "anonymous", "private": private,
                     "public": public, "verifier_run_id": None},
    }

    def observe(_url, _mime, request_body, *_args, **_kwargs):
        value = (parse_qs(request_body.decode())["template"][0]
                 if cell_location == "body_form" else json.loads(request_body)["template"])
        return _row(MYSQL_ERROR if value.endswith("'") and not value.endswith("''")
                    else b"ordinary response", request_body)

    monkeypatch.setattr(body_probe, "_observe_post", observe)
    hunter = json.loads(await manager.scoped_body_probe(capture_id, parameter))
    assert hunter["proof_confirmed"] is True
    assert store.records[hunter["evidence_id"]]["kind"] == "scoped_body_sqli_error"
    assert manager._scoped_post_count == 5

    brain = EngagementBrain(target=TARGET)
    brain.coverage_cells = [{
        "id": "cell-1", "source": "parameter_inventory",
        "observation_source": "browser_traffic", "test_type": "sqli",
        "method": "POST", "host": "app.example.test",
        "path": "/controllers/extraeDataContenido",
        "parameter": f"{cell_location}:{parameter}", "identity": "anonymous",
        "capture_id": capture_id,
    }]
    candidate = FindingCandidate(
        id="candidate-1", title="SQL injection in template", target=TARGET,
        vulnerability_class="sql_injection", coverage_cell_id="cell-1",
        parameter=f"{cell_location}:{parameter}", evidence_ids=[hunter["evidence_id"]],
    )
    brain.candidates = [candidate.to_dict()]
    manager._engagement_brain = brain.to_dict()
    run = VerificationRun("fresh-post-run", "candidate-1", 1, "nonce")
    token = verification_run.set(run)
    try:
        verdict = await _verify_scoped_sql_candidate(manager, candidate, run)
    finally:
        verification_run.reset(token)
    assert verdict["status"] == "confirmed"
    fresh_ids = [artifact_id for artifact_id, row in store.records.items()
                 if row.get("run_id") == run.id and row.get("kind") == "scoped_body_sqli_error"]
    assert len(fresh_ids) == 1 and fresh_ids[0] != hunter["evidence_id"]
    assert manager._scoped_verifier_post_count == 5


@pytest.mark.asyncio
async def test_token_bearing_post_uses_browser_controls_and_independent_verifier(monkeypatch):
    from app.services.agent.scoped_assessment import browser_post_replay

    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    manager._assessment_scope.add("app.example.test")
    manager.set_scoped_assessment_policy({
        "body_replay_paths": ["/controllers/extraeDataContenido"],
    })
    public, private = package_exchange(
        url=TARGET, expected_origin="https://app.example.test",
        action_ref="navigate", method="POST", resource_type="xhr", status=200,
        content_type="text/html", request_body=b"template=botox&csrf_token=old-token",
        response_body=b"ordinary response",
        request_content_type="application/x-www-form-urlencoded",
        page_url="https://app.example.test/materials/botox",
    )
    store = evidence_store(manager)
    capture_id = store.record("scoped_browser_exchange", public, target=TARGET,
                              identity="anonymous")
    manager._scoped_browser_exchanges = {
        capture_id: {"identity": "anonymous", "private": private,
                     "public": public, "verifier_run_id": None},
    }
    serial = 0

    async def replay(capture, *, parameter, payloads, allowed_origins, storage_state):
        nonlocal serial
        assert capture == private and allowed_origins == ["https://app.example.test"]
        checks = {}
        for key, suffix in payloads.items():
            serial += 1
            _, _, baseline, planned = body_probe.plan_observed_body(
                capture, parameter=parameter, allowed_origins=allowed_origins,
                payload=suffix or "'",
            )
            if not suffix:
                planned = baseline
            actual = planned.replace(b"old-token", f"fresh-{serial}".encode())
            value = parse_qs(actual.decode())["template"][0]
            row = _row(MYSQL_ERROR if value.endswith("'") and not value.endswith("''")
                       else b"ordinary response", actual)
            row["variant_sha256"] = hashlib.sha256(planned).hexdigest()
            row["body_match_mode"] = "volatile_fields"
            row["volatile_fields"] = ["csrf_token"]
            checks[key] = row
        return checks

    monkeypatch.setattr(browser_post_replay, "replay_observed_post_controls", replay)
    hunter = json.loads(await manager.scoped_body_probe(capture_id, "template"))
    assert hunter["proof_confirmed"] is True
    assert hunter["replay_mode"] == "browser_fresh_post"
    assert len({row["request_sha256"] for row in hunter["checks"].values()}) == 5
    assert manager._scoped_post_count == 5

    brain = EngagementBrain(target=TARGET)
    brain.coverage_cells = [{
        "id": "cell-1", "source": "parameter_inventory",
        "observation_source": "browser_traffic", "test_type": "sqli",
        "method": "POST", "host": "app.example.test",
        "path": "/controllers/extraeDataContenido",
        "parameter": "body_form:template", "identity": "anonymous",
        "capture_id": capture_id,
    }]
    candidate = FindingCandidate(
        id="candidate-1", title="SQL injection in template", target=TARGET,
        vulnerability_class="sql_injection", coverage_cell_id="cell-1",
        parameter="body_form:template", evidence_ids=[hunter["evidence_id"]],
    )
    brain.candidates = [candidate.to_dict()]
    manager._engagement_brain = brain.to_dict()
    run = VerificationRun("fresh-token-post-run", "candidate-1", 1, "nonce")
    token = verification_run.set(run)
    try:
        verdict = await _verify_scoped_sql_candidate(manager, candidate, run)
    finally:
        verification_run.reset(token)
    assert verdict["status"] == "confirmed"
    assert manager._scoped_verifier_post_count == 5


@pytest.mark.parametrize("request_body, content_type, parameter, location", [
    (b"template=botox&filtro=All", "application/x-www-form-urlencoded", "template", "body_form"),
    (b'{"template":"botox","page":2}', "application/json", "/template", "body_json"),
])
@pytest.mark.asyncio
async def test_blind_post_boolean_controls_reach_independent_verifier(
    monkeypatch, request_body, content_type, parameter, location,
):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    manager._assessment_scope.add("app.example.test")
    manager.set_scoped_assessment_policy({
        "body_replay_paths": ["/controllers/extraeDataContenido"],
    })
    public, private = package_exchange(
        url=TARGET, expected_origin="https://app.example.test",
        action_ref="navigate", method="POST", resource_type="xhr", status=200,
        content_type="text/html", request_body=request_body,
        response_body=b"ordinary response", request_content_type=content_type,
    )
    store = evidence_store(manager)
    capture_id = store.record("scoped_browser_exchange", public, target=TARGET,
                              identity="anonymous")
    manager._scoped_browser_exchanges = {
        capture_id: {"identity": "anonymous", "private": private,
                     "public": public, "verifier_run_id": None},
    }
    sent = []

    def observe(_url, _mime, body, *_args, **_kwargs):
        sent.append(body)
        value = (parse_qs(body.decode())["template"][0]
                 if location == "body_form" else json.loads(body)["template"])
        if location == "body_form":
            assert parse_qs(body.decode())["filtro"] == ["All"]
        else:
            assert json.loads(body)["page"] == 2
        condition = re.search(r" OR '(\d{5})'='(\d{5})'-- $", value)
        expanded = bool(condition and condition.group(1) == condition.group(2))
        return _row(b"A" * (700 if expanded else 100), body)

    monkeypatch.setattr(body_probe, "_observe_post", observe)
    hunter = json.loads(await manager.scoped_body_probe(capture_id, parameter))
    assert hunter["proof_recipe"] == "post_or_boolean_v1"
    assert hunter["proof_confirmed"] is True
    assert body_probe.post_sql_boolean_proof_valid(hunter)
    assert len(sent) == 8 and manager._scoped_post_count == 8
    assert store.records[hunter["evidence_id"]]["kind"] == "scoped_body_sqli_boolean"

    brain = EngagementBrain(target=TARGET)
    brain.coverage_cells = [{
        "id": "cell-1", "source": "parameter_inventory",
        "observation_source": "browser_traffic", "test_type": "sqli",
        "method": "POST", "host": "app.example.test",
        "path": "/controllers/extraeDataContenido",
        "parameter": f"{location}:{parameter}", "identity": "anonymous",
        "capture_id": capture_id,
    }]
    candidate = FindingCandidate(
        id="candidate-1", title="Blind SQL injection in template", target=TARGET,
        vulnerability_class="sql_injection", coverage_cell_id="cell-1",
        parameter=f"{location}:{parameter}", evidence_ids=[hunter["evidence_id"]],
    )
    brain.candidates = [candidate.to_dict()]
    manager._engagement_brain = brain.to_dict()
    run = VerificationRun("fresh-post-boolean-run", "candidate-1", 1, "nonce")
    token = verification_run.set(run)
    try:
        verdict = await _verify_scoped_sql_candidate(manager, candidate, run)
    finally:
        verification_run.reset(token)
    assert verdict["status"] == "confirmed"
    verifier = [row["payload"] for row in store.records.values()
                if row.get("run_id") == run.id and row.get("kind") == "scoped_body_sqli_boolean"]
    assert len(verifier) == 1
    assert verifier[0]["nonce"] != hunter["nonce"]
    assert manager._scoped_verifier_post_count == 6


def test_post_boolean_rejects_reflection_and_unstable_controls(monkeypatch):
    private = _capture(b"template=botox")
    url, mime, variants, nonce = body_probe.plan_sql_boolean_body(
        private, parameter="template", allowed_origins=["https://app.example.test"],
    )
    monkeypatch.setattr(body_probe, "_observe_post", lambda _url, _mime, body, *_a, **_kw: _row(body, body))
    reflected = body_probe.probe_sql_boolean_body(
        url, mime, variants, nonce, parameter="template",
        allowed_origins=["https://app.example.test"], storage_state=None,
    )
    assert reflected["proof_confirmed"] is False
    reflected["checks"]["baseline_last"]["bytes_captured"] = 500
    assert body_probe.post_sql_boolean_proof_valid(reflected) is False


def test_post_boolean_accepts_stable_small_json_result_expansion(monkeypatch):
    url, mime, variants, nonce = body_probe.plan_sql_boolean_body(
        _capture(b"template=botox"), parameter="template",
        allowed_origins=["https://app.example.test"],
    )

    def observe(_url, _mime, body, *_args, **_kwargs):
        value = parse_qs(body.decode())["template"][0]
        condition = re.search(r" OR '(\d{5})'='(\d{5})'-- $", value)
        expanded = bool(condition and condition.group(1) == condition.group(2))
        data = b'{"results":[1,2]}' if expanded else b'{"results":[]}'
        row = _row(data, body)
        row["content_type"] = "application/json"
        row["json_array_lengths"] = {"results": 2 if expanded else 0}
        return row

    monkeypatch.setattr(body_probe, "_observe_post", observe)
    proof = body_probe.probe_sql_boolean_body(
        url, mime, variants, nonce, parameter="template",
        allowed_origins=["https://app.example.test"], storage_state=None,
    )
    assert proof["proof_confirmed"] is True


@pytest.mark.asyncio
async def test_blind_post_first_pass_submits_a_candidate(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    manager._assessment_scope.add("app.example.test")
    manager._capability_map = {"target": "https://app.example.test",
                               "scope": "https://app.example.test"}
    manager.set_scoped_assessment_policy({
        "body_replay_paths": ["/controllers/extraeDataContenido"],
    })
    public, private = package_exchange(
        url=TARGET, expected_origin="https://app.example.test",
        action_ref="navigate", method="POST", resource_type="xhr", status=200,
        content_type="text/html", request_body=b"template=botox",
        response_body=b"ordinary response",
        request_content_type="application/x-www-form-urlencoded",
    )
    store = evidence_store(manager)
    capture_id = store.record("scoped_browser_exchange", public, target=TARGET,
                              identity="anonymous")
    manager._scoped_browser_exchanges = {
        capture_id: {"identity": "anonymous", "private": private,
                     "public": public, "verifier_run_id": None},
    }
    brain = EngagementBrain(target="https://app.example.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "POST", "host": "app.example.test",
        "path": "/controllers/extraeDataContenido", "name": "template",
        "location": "body_form", "source": "browser_traffic",
        "artifact_id": capture_id, "identity": "anonymous", "testable": True,
    }])
    for cell in brain.coverage_cells:
        if cell.get("test_type") == "xss":
            cell["status"] = "skipped"
    manager._engagement_brain = brain.to_dict()

    def observe(_url, _mime, body, *_args, **_kwargs):
        value = parse_qs(body.decode())["template"][0]
        condition = re.search(r" OR '(\d{5})'='(\d{5})'-- $", value)
        expanded = bool(condition and condition.group(1) == condition.group(2))
        return _row(b"A" * (700 if expanded else 100), body)

    monkeypatch.setattr(body_probe, "_observe_post", observe)
    async def execute(name, args):
        output = await getattr(manager, name)(**args)
        return {"output": output}
    manager.execute = execute
    batch = await run_observed_input_batch(manager, target="https://app.example.test",
                                           max_checks=1)
    assert batch["results"][0]["outcome"] == "proof_signal"
    assert batch["results"][0]["candidate_id"]
