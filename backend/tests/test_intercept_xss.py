"""XSS on inputs a GET navigation cannot carry: header, cookie, request body and
path segment, proven by changing only that input in one intercepted browser
request. The browser is faked (``browser_intercept.check_intercept_xss``);
the real Chromium path is in test_browser_intercept_chromium.py (opt-in)."""

import json
import secrets

import pytest

from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.scoped_assessment import browser_intercept as bi
from app.services.agent.scoped_assessment import intent_request as ir

from test_operator_intent_shapes import (  # noqa: F401 - env is a fixture
    BODY, T, _cell, _intent, _manager_with_intent, env,
)

PAYLOAD = '<img src=x onerror=alert("__PROWL_NONCE__")>'


def _fake_intercept(monkeypatch, calls, *, executes=True, **overrides):
    async def fake(spec, *, allowed_origins, storage_state=None):
        assert allowed_origins == [T]
        calls.append(spec)
        result = {"operation": "check_intercept_xss",
                  **{key: spec[key] for key in bi.BINDING_FIELDS},
                  "nonce": secrets.token_hex(8), "intercept_mutated": True,
                  "mutated_response_seen": True, "mutated_status": 200,
                  "mutated_redirect_refused": False, "intercept_error": "",
                  "executed": executes, "dialog_count": int(executes),
                  "reflection_contexts": ["html_text"], "reflection_observations": []}
        result.update(overrides)
        return result, None

    monkeypatch.setattr(bi, "check_intercept_xss", fake)


async def _verify(manager, lease, target):
    from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate

    active = engagement_brain_from_dict(manager._engagement_brain)
    out = [c for c in active.coverage_cells if c["id"] == lease.coverage_cell_id][0]
    candidate = submit_candidate(
        active, title="Reflected XSS", target=target, vulnerability_class="xss",
        identity="anonymous", coverage_cell_id=lease.coverage_cell_id,
        evidence_ids=list(out["probe_artifact_ids"]))
    manager._engagement_brain = active.to_dict()
    return (await run_independent_verifiers([candidate], llm=None, tools_manager=manager,
                                            targets=[target]))[0]


# ---------------------------------------------------------------- plans and mutation

def test_mutation_changes_only_the_one_input():
    headers = {"accept": "*/*", "x-theme": "light", "cookie": "sid=s1; lang=en; a=b"}
    spec = bi.plan_intercept(method="GET", url=T + "/r", location="header",
                             parameter="X-Theme", payload_template=PAYLOAD)
    _, _, changed, _ = bi.mutate_request(spec, url=T + "/r", method="GET",
                                         headers=headers, body=None, payload="<b>n")
    assert changed == {"accept": "*/*", "cookie": headers["cookie"], "X-Theme": "<b>n"}

    spec = bi.plan_intercept(method="GET", url=T + "/r", location="cookie",
                             parameter="lang", payload_template=PAYLOAD)
    _, _, changed, _ = bi.mutate_request(spec, url=T + "/r", method="GET",
                                         headers=headers, body=None, payload='<b x="1">;n')
    assert changed["cookie"] == "sid=s1; lang=<b%20x=%221%22>%3Bn; a=b"

    spec = bi.plan_intercept(method="GET", url=T + "/u/alice/view?x=1", location="path",
                             parameter="1", payload_template=PAYLOAD)
    assert (spec["path_template"], spec["path_segment_index"]) == ("/u/alice/view", 2)
    url, _, _, _ = bi.mutate_request(spec, url=T + "/u/alice/view?x=1", method="GET",
                                     headers={}, body=None, payload="<b>/n")
    assert url == T + "/u/%3Cb%3E%2Fn/view?x=1"
    with pytest.raises(bi.InterceptError, match="path_template_mismatch"):
        bi.mutate_request(spec, url=T + "/u/bob/view", method="GET", headers={}, body=None,
                          payload="n")

    page = T + "/page"
    for location, parameter, mime, body, expected in (
        ("body_form", "q", "application/x-www-form-urlencoded", b"a=1&q=old&z=%20",
         b"a=1&q=%3Cb%3En&z=%20"),
        ("body_json", "/a/b", "application/json; charset=utf-8",
         b'{"k": [1, {"b": 2}],\n "a": {"b": "old", "c": null}}',
         b'{"k": [1, {"b": 2}],\n "a": {"b": "<b>n", "c": null}}'),
        ("body_xml", "/o/n", "application/xml",
         b'<?xml version="1.0"?>\n<o a="1"><k>1</k><n>old</n></o>',
         b'<?xml version="1.0"?>\n<o a="1"><k>1</k><n>&lt;b&gt;n</n></o>'),
    ):
        spec = bi.plan_intercept(method="POST", url=T + "/api", location=location,
                                 parameter=parameter, payload_template=PAYLOAD, page_url=page)
        assert spec["intercept_mode"] == "fetch"
        assert spec["request_match"]["method"] == "POST"
        _, method, _, changed = bi.mutate_request(
            spec, url=T + "/api", method="POST", headers={"content-type": mime},
            body=body, payload="<b>n")
        assert (method, changed) == ("POST", expected)


def test_document_body_navigation_becomes_a_one_field_post():
    spec = bi.plan_intercept(method="POST", url=T + "/comment?lang=en", location="body_json",
                             parameter="/c/text", payload_template=PAYLOAD)
    assert spec["intercept_mode"] == "document"
    assert spec["request_match"] == {"resource_type": "document", "method": "GET",
                                     "path": "/comment", "content_type": ""}
    url, method, headers, body = bi.mutate_request(
        spec, url=T + "/comment?lang=en", method="GET", headers={"accept": "text/html"},
        body=None, payload="<b>n")
    assert (url, method, headers["content-type"]) == (T + "/comment?lang=en", "POST",
                                                      "application/json")
    assert json.loads(body) == {"c": {"text": "<b>n"}}


def test_fetch_body_field_must_exist_once_and_types_must_match():
    spec = bi.plan_intercept(method="POST", url=T + "/api", location="body_json",
                             parameter="/a", payload_template=PAYLOAD, page_url=T + "/page")
    for body, error in ((b'{"b": "x"}', "json_field_missing"), (b'{"a": {"x": 1}}', "json_field_not_scalar"),
                        (b'{"a": "x", "a": "y"}', "json_field_ambiguous")):
        with pytest.raises(bi.InterceptError, match=error):
            bi.mutate_request(spec, url=T + "/api", method="POST",
                              headers={"content-type": "application/json"}, body=body,
                              payload="n")
    with pytest.raises(bi.InterceptError, match="content_type_mismatch"):
        bi.mutate_request(spec, url=T + "/api", method="POST",
                          headers={"content-type": "text/plain"}, body=b'{"a": "x"}', payload="n")
    xml = bi.plan_intercept(method="POST", url=T + "/api", location="body_xml",
                            parameter="/o/n", payload_template=PAYLOAD, page_url=T + "/page")
    with pytest.raises(bi.InterceptError, match="xml_markup_unsupported"):
        bi.mutate_request(xml, url=T + "/api", method="POST",
                          headers={"content-type": "application/xml"},
                          body=b'<!DOCTYPE o [<!ENTITY e "x">]><o><n>&e;</n></o>', payload="n")
    assert bi.request_matches(spec, url=T + "/api", method="POST", resource_type="fetch",
                              content_type="application/json")
    assert not bi.request_matches(spec, url=T + "/api", method="POST", resource_type="document")
    assert not bi.request_matches(spec, url=T + "/api/2", method="POST", resource_type="xhr",
                                  content_type="application/json")


@pytest.mark.parametrize("name", ["Authorization", "Host", "Cookie", "Origin",
                                  "X-Forwarded-Host", "Forwarded", "Content-Length",
                                  "Transfer-Encoding", "Connection", "X-CSRF-Token",
                                  "X-Api-Key", "Sec-Fetch-Site", "Proxy-Authorization"])
def test_protected_headers_are_refused(name):
    assert bi.intercept_shape_error("GET", "header", name) == "protected_header"
    with pytest.raises(ir.UnsupportedShape, match="protected_header"):
        bi.plan_intercept(method="GET", url=T + "/r", location="header", parameter=name,
                          payload_template=PAYLOAD)


def test_protected_cookies_are_refused():
    assert bi.intercept_shape_error("GET", "cookie", "sessionid") == "protected_cookie"
    state = {"cookies": [{"name": "lang", "value": "en", "domain": "app.example.com",
                          "path": "/", "httpOnly": True}]}
    with pytest.raises(ir.UnsupportedShape, match="protected_cookie"):
        bi.plan_intercept(method="GET", url=T + "/r", location="cookie", parameter="lang",
                          payload_template=PAYLOAD, state=state)


@pytest.mark.parametrize("method,location,reason", [
    ("PUT", "body_json", "xss_write_method_unsupported"),
    ("PATCH", "header", "xss_write_method_unsupported"),
    ("DELETE", "cookie", "xss_write_method_unsupported"),
    ("GET", "body_form", "body_requires_post"),
    ("POST", "path", "path_xss_requires_get"),
])
def test_unsupported_methods(method, location, reason):
    assert bi.intercept_shape_error(method, location, "x") == reason


def test_render_page_must_be_a_bare_same_origin_page():
    for page in (T + "/page?x=1", "https://other.example.com/page", T + "/page#x"):
        with pytest.raises(ir.UnsupportedShape):
            bi.plan_intercept(method="GET", url=T + "/api", location="header",
                              parameter="X-A", payload_template=PAYLOAD, page_url=page)


# ---------------------------------------------------------------- receipts

def _receipt(**changes):
    spec = bi.plan_intercept(method="GET", url=T + "/u/alice", location="path",
                             parameter="alice", payload_template=PAYLOAD)
    row = {"operation": "check_intercept_xss", **{k: spec[k] for k in bi.BINDING_FIELDS},
           "nonce": secrets.token_hex(8), "intercept_mutated": True,
           "mutated_response_seen": True, "mutated_status": 200,
           "mutated_redirect_refused": False, "executed": True, "coverage_cell_id": "c1"}
    row.update(changes)
    return row


@pytest.mark.parametrize("changes", [
    {"executed": False},                                  # reflection only / unrelated dialog
    {"intercept_mutated": False},                         # mutated request never sent
    {"mutated_response_seen": False},                     # response never arrived
    {"mutated_redirect_refused": True, "mutated_status": 302},
    {"path_segment_index": 1},                            # does not bind to the cell segment
    {"path_template": "/u/bob"},
    {"sent_method": "POST"},
    {"payload_template": "<b>"},
])
def test_receipt_inconclusive_cases(changes):
    assert bi.receipt_valid(_receipt())
    assert not bi.receipt_valid(_receipt(**changes))


def test_pair_must_agree_on_the_interception():
    first = _receipt()
    assert bi.pair_valid(first, _receipt())
    assert not bi.pair_valid(first, {**first})  # same nonce
    for key, value in (("target_template", T + "/other"), ("input_parameter", "0"),
                       ("request_match", {**first["request_match"], "method": "POST"}),
                       ("coverage_cell_id", "c2")):
        assert not bi.pair_valid(first, _receipt(**{key: value}))


# ---------------------------------------------------------------- probe + verifier

@pytest.mark.asyncio
@pytest.mark.parametrize("location,parameter,method,target", [
    ("header", "X-Theme", "GET", T + "/render?lang=en"),
    ("cookie", "lang", "GET", T + "/render"),
    ("body_form", "comment", "POST", T + "/comment"),
    ("body_json", "/note/text", "POST", T + "/comment"),
    ("body_xml", "/note/text", "POST", T + "/comment"),
    ("path", "1", "GET", T + "/u/alice"),
])
async def test_intent_xss_each_location_probe_and_verifier_parity(
        monkeypatch, location, parameter, method, target):
    from urllib.parse import urlsplit

    manager, intent, lease = _manager_with_intent(
        test_type="xss", location=location, parameter=parameter, method=method, target=target)
    if method == "POST":
        manager._scoped_body_replay_paths = {urlsplit(target).path}
    calls = []
    _fake_intercept(monkeypatch, calls)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is True, out
    assert out["operation"] == "scoped_browser_check_intercept_xss"
    assert out["request_context"] == f"intent_{location}"
    spec = calls[0]
    assert spec["intercept_mode"] == "document" and spec["target_template"] == target
    assert spec["sent_method"] == method and spec["input_location"] == location
    if location == "path":
        assert (out["probe_result"]["path_template"],
                out["probe_result"]["path_segment_index"]) == ("/u/alice", 2)
    assert _intent(manager, intent)["status"] == "done"
    report = await _verify(manager, lease, T + urlsplit(target).path)
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert len(calls) == 2
    assert all(calls[1][key] == spec[key] for key in (*bi.BINDING_FIELDS, "request_url"))


@pytest.mark.asyncio
async def test_fetch_mode_render_page_is_replayed_by_the_verifier(monkeypatch):
    manager, _intent_row, lease = _manager_with_intent(
        test_type="xss", location="body_json", parameter="/a/b", method="POST",
        target=T + "/api/notes")
    manager._scoped_body_replay_paths = {"/api/notes"}
    calls = []
    _fake_intercept(monkeypatch, calls)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id,
                                                    render_page="/notes")
    assert out["proof_confirmed"] is True, out
    assert calls[0]["intercept_mode"] == "fetch"
    assert calls[0]["target_template"] == T + "/notes"
    assert calls[0]["request_match"] == {"resource_type": "xhr_fetch", "method": "POST",
                                         "path": "/api/notes",
                                         "content_type": "application/json"}
    report = await _verify(manager, lease, T + "/api/notes")
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert calls[1]["target_template"] == T + "/notes"


@pytest.mark.asyncio
async def test_body_xss_without_post_approval_is_refused(monkeypatch):
    manager, intent, lease = _manager_with_intent(
        test_type="xss", location="body_form", parameter="q", method="POST",
        target=T + "/comment")
    calls = []
    _fake_intercept(monkeypatch, calls)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["error"] == "operator_approval_required" and calls == []
    assert _cell(manager, lease)["status"] == "leased"
    assert _intent(manager, intent)["status"] == "open"


@pytest.mark.asyncio
@pytest.mark.parametrize("location,parameter,reason", [
    ("header", "Authorization", "protected_header"),
    ("header", "X-Forwarded-Host", "protected_header"),
    ("cookie", "session_id", "protected_cookie"),
])
async def test_protected_header_cookie_intent_is_blocked_unprobed(monkeypatch, location,
                                                                  parameter, reason):
    manager, intent, lease = _manager_with_intent(
        test_type="xss", location=location, parameter=parameter, target=T + "/render")
    calls = []
    _fake_intercept(monkeypatch, calls)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["error"] == "unsupported_request_shape" and out["reason"] == reason
    assert calls == [] and _intent(manager, intent)["status"] == "blocked"


@pytest.mark.asyncio
async def test_write_method_body_xss_stays_unsupported(monkeypatch):
    manager, intent, lease = _manager_with_intent(
        test_type="xss", location="body_json", parameter="text", method="PUT",
        target=T + "/api/notes/1")
    calls = []
    _fake_intercept(monkeypatch, calls)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["reason"] == "xss_write_method_unsupported" and calls == []
    assert _cell(manager, lease)["status"] != "tested_clean"


@pytest.mark.asyncio
@pytest.mark.parametrize("overrides", [
    {"executed": False},                                     # reflection only
    {"executed": False, "dialog_count": 1},                  # unrelated dialog
    {"executed": False, "intercept_mutated": False,
     "mutated_response_seen": False, "mutated_status": None,
     "intercept_error": ""},                                 # never sent
])
async def test_inconclusive_probe_keeps_intent_open(monkeypatch, overrides):
    manager, intent, lease = _manager_with_intent(
        test_type="xss", location="header", parameter="X-Theme", target=T + "/render")
    calls = []
    _fake_intercept(monkeypatch, calls, **overrides)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is False
    assert _intent(manager, intent)["status"] == "open"
    assert _cell(manager, lease)["status"] == "leased"


@pytest.mark.asyncio
async def test_verifier_refuses_tampered_receipt_and_failed_replay(monkeypatch):
    from app.services.agent.evidence_store import evidence_store

    manager, _intent_row, lease = _manager_with_intent(
        test_type="xss", location="path", parameter="alice", target=T + "/u/alice")
    calls = []
    # A receipt for segment 2 named by index, not the cell's literal input.
    _fake_intercept(monkeypatch, calls, input_parameter="1")
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True
    assert bi.receipt_valid(evidence_store(manager).records[out["evidence_id"]]["payload"])
    report = await _verify(manager, lease, T + "/u/alice")
    assert report["status"] == "inconclusive" and len(calls) == 1

    manager, _intent_row, lease = _manager_with_intent(
        test_type="xss", location="header", parameter="X-Theme", target=T + "/render")
    calls = []
    _fake_intercept(monkeypatch, calls)
    await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    _fake_intercept(monkeypatch, calls, executes=False)
    report = await _verify(manager, lease, T + "/render")
    assert report["status"] == "inconclusive" and len(calls) == 2


@pytest.mark.asyncio
async def test_verifier_needs_the_approval_to_still_hold(monkeypatch):
    manager, _intent_row, lease = _manager_with_intent(
        test_type="xss", location="body_form", parameter="q", method="POST",
        target=T + "/comment")
    manager._scoped_body_replay_paths = {"/comment"}
    calls = []
    _fake_intercept(monkeypatch, calls)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True
    manager._scoped_body_replay_paths = set()
    report = await _verify(manager, lease, T + "/comment")
    assert report["status"] == "inconclusive" and len(calls) == 1


@pytest.mark.asyncio
async def test_observed_header_xss_cell_uses_the_intercept_lane(monkeypatch):
    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.coverage_cells import (
        claim_coverage_cell_leases, seed_parameter_coverage_cells,
    )
    from app.services.agent.tools import ASMToolsManager

    brain = EngagementBrain(target=T)
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.example.com", "path": "/render", "name": "X-Theme",
        "location": "header", "identity": "anonymous", "source": "browser_request",
        "testable": True}])
    cell = next(c for c in brain.coverage_cells if c["test_type"] == "xss")
    lease = claim_coverage_cell_leases(brain, [cell["specialist"]],
                                       allowed_cell_ids=frozenset({cell["id"]}))[cell["specialist"]]
    manager = ASMToolsManager()
    manager._fallback_target = T
    manager._capability_map = {"target": T, "scope": T}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.example.com")
    calls = []
    _fake_intercept(monkeypatch, calls)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["operation"] == "scoped_browser_check_intercept_xss", out
    assert out["request_context"] == "observed_header" and out["proof_confirmed"] is True
    report = await _verify(manager, lease, T + "/render")
    assert report["status"] == "confirmed", report["verifier_summary"]


def test_proof_kind_is_in_the_xss_class():
    from app.services.agent.proof_policy import PROOFS_BY_CLASS

    assert "scoped_browser_intercept_xss" in PROOFS_BY_CLASS["xss"]


@pytest.mark.parametrize("patch,code", [
    ({"test_type": "xss", "location": "header", "parameter": "X-Theme"}, 201),
    ({"test_type": "xss", "location": "body_json", "parameter": "a", "method": "PUT"}, 422),
    ({"test_type": "xss", "location": "path", "parameter": "0", "method": "POST"}, 422),
])
def test_intake_xss_intercept_shapes(env, patch, code):
    resp = env.client.post("/agent/sessions/s1/intents", json={**BODY, **patch})
    assert resp.status_code == code, resp.text
