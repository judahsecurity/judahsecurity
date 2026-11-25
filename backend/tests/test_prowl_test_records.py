"""Prowl-owned test records: PUT/PATCH/DELETE probes never touch existing data.

Write probes only ever reach a dummy record Prowl created (POST create_path
with a fresh nonce), verified as its own (GET shows the nonce), probed and then
cleaned up. No network: every request goes through a fake transport and every
sent URL is asserted.
"""

import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.scoped_assessment import test_records as tr
from test_operator_intent_shapes import (  # noqa: F401 - env is a fixture
    BODY, T, _Resp, _cell, _evaluate, _intent, _manager_with_intent, _sent, env,
)

NOTES = {"create_path": "/api/notes", "create_body": {"note": {"title": "__PROWL_NONCE__"}},
         "content_type": "json", "record_path": "/api/notes/{id}", "id_source": "location",
         "write_methods": ["PUT", "PATCH", "DELETE"], "cleanup": "delete",
         "cleanup_delete_approved": True}


class NotesApp:
    """A fake notes API holding one real company record (id 42)."""

    def __init__(self, *, create_status=201, id_mode="location", echo_nonce=True,
                 delete_works=True, probe=None):
        self.store = {"42": "company quarterly plan"}
        self.create_status = create_status
        self.id_mode = id_mode
        self.echo_nonce = echo_nonce
        self.delete_works = delete_works
        self.probe = probe or (lambda req, record: _Resp(200, _evaluate(req.header("X-Template"))))
        self.created = []

    def __call__(self, req):
        path = urlsplit(req.url).path
        if req.method == "POST" and path == "/api/notes":
            if self.create_status >= 300:
                return _Resp(self.create_status, b"no")
            record = f"p{len(self.created) + 1}"
            self.created.append(record)
            self.store[record] = req.body.decode()
            if self.id_mode == "location":
                return _Resp(201, b"{}", {"Location": f"/api/notes/{record}"})
            if self.id_mode == "json":
                return _Resp(201, json.dumps({"data": {"id": record}}).encode())
            return _Resp(201, b"{}")
        match = re.fullmatch(r"/api/notes/([^/]+)", path)
        assert match, f"unexpected request {req.method} {req.url}"
        record = match.group(1)
        if req.method == "GET":
            if record not in self.store:
                return _Resp(404, b"gone")
            return _Resp(200, self.store[record].encode() if self.echo_nonce else b"{}")
        if record not in self.store:
            return _Resp(404, b"gone")
        response = self.probe(req, record) if req.method != "DELETE" or not self.cleanup_only(
            req) else _Resp(204, b"")
        if req.method == "DELETE" and self.delete_works:
            self.store.pop(record, None)
        return response

    @staticmethod
    def cleanup_only(req):
        # Prowl's own cleanup DELETE carries no probe input.
        return not urlsplit(req.url).query and not req.header("X-Template")


def _write_manager(*, method="PUT", target=T + "/api/notes/42", test_type="ssti",
                   location="header", parameter="X-Template", endpoint=None):
    manager, intent, lease = _manager_with_intent(
        test_type=test_type, location=location, parameter=parameter, method=method,
        target=target)
    manager.set_scoped_assessment_policy({"test_record_endpoints": [endpoint or NOTES]})
    return manager, intent, lease


def _own_paths(app):
    return {f"/api/notes/{record}" for record in app.created}


def _assert_only_own_records(sent, app, *, write_method):
    """Every non-create request goes to a record Prowl created; 42 is never touched."""
    for req in sent:
        path = urlsplit(req.url).path
        assert "/42" not in path and tr.PLAN_ID not in req.url
        if req.method == "POST":
            assert path == "/api/notes" and b"__PROWL_NONCE__" not in req.body
        else:
            assert path in _own_paths(app), (req.method, req.url)
        assert req.method in {"POST", "GET", write_method, "DELETE"}
    assert app.store["42"] == "company quarterly plan"


# ---------------------------------------------------------------- policy

def test_policy_test_record_endpoints_validation():
    from pydantic import ValidationError

    from app.api.routes.agent import AgentAssessmentPolicy
    from app.services.agent.tools import ASMToolsManager

    form = {"create_path": "/api/items", "create_body": "name=__PROWL_NONCE__&kind=test",
            "content_type": "form", "record_path": "/api/items/{id}/detail",
            "id_source": "json:item.id", "write_methods": ["PATCH"], "cleanup": "none"}
    ok = AgentAssessmentPolicy(test_record_endpoints=[NOTES, form])
    manager = ASMToolsManager()
    manager.set_scoped_assessment_policy(ok.model_dump())
    assert [e["record_path"] for e in manager._scoped_test_record_endpoints] == [
        "/api/notes/{id}", "/api/items/{id}/detail"]
    assert manager._scoped_test_record_endpoints[1]["write_methods"] == ["PATCH"]
    bad_rows = [
        {**NOTES, "create_path": "/api/notes?x=1"},
        {**NOTES, "create_path": "https://evil.example/api"},
        {**NOTES, "create_path": "/api/{id}"},
        {**NOTES, "record_path": "/api/notes/42"},
        {**NOTES, "record_path": "/api/{id}/notes/{id}"},
        {**NOTES, "record_path": "/api/notes/{id}#x"},
        {**NOTES, "record_path": "/api/../notes/{id}"},
        {**NOTES, "create_body": {"title": "no nonce"}},
        {**NOTES, "create_body": "title=__PROWL_NONCE__"},  # form body with json type
        {**NOTES, "create_body": {"t": "__PROWL_NONCE__" + "x" * 5000}},
        {**NOTES, "id_source": "header:X-Id"},
        {**NOTES, "id_source": "json:"},
        {**NOTES, "write_methods": ["POST"]},
        {**NOTES, "write_methods": []},
        {**NOTES, "cleanup": "purge"},
        {**NOTES, "cleanup_delete_approved": False},  # cleanup delete not approved
        {**form, "cleanup_delete_approved": True},  # approval without cleanup delete
        {**NOTES, "extra": 1},
    ]
    for row in bad_rows:
        with pytest.raises(ValidationError):
            AgentAssessmentPolicy(test_record_endpoints=[row])
        with pytest.raises(ValueError):
            ASMToolsManager().set_scoped_assessment_policy({"test_record_endpoints": [row]})
    for policy in ({"test_record_endpoints": [NOTES] * 5},
                   {"test_record_endpoints": [NOTES, NOTES]},
                   {"write_method_paths": [{"method": "PUT", "path": "/api/profile"}]}):
        with pytest.raises(ValidationError):
            AgentAssessmentPolicy(**policy)
        with pytest.raises(ValueError):
            ASMToolsManager().set_scoped_assessment_policy(policy)


def test_template_match_and_id_extraction():
    endpoint = tr.normalize_endpoint(NOTES)
    assert tr.path_matches("/api/notes/{id}", "/api/notes/42")
    assert tr.path_matches("/api/notes/{id}", "/api/notes/%7Bid%7D")
    assert not tr.path_matches("/api/notes/{id}", "/api/notes/42/share")
    assert tr.match_endpoint([endpoint], "PUT", "/api/notes/{id}") is endpoint
    assert tr.match_endpoint([endpoint], "POST", "/api/notes/1") is None
    create = T + "/api/notes"
    assert tr.extract_id(endpoint, create_url=create, location="/api/notes/ab-1_c", body=b"") == "ab-1_c"
    for location in ("https://other.example/api/notes/1", "/api/users/1",
                     "/api/notes/" + "a" * 65, "/api/notes/a.b"):
        assert tr.extract_id(endpoint, create_url=create, location=location, body=b"") == ""
    by_json = {**endpoint, "id_source": "json:data.id"}
    assert tr.extract_id(by_json, create_url=create, location="",
                         body=b'{"data": {"id": 17}}') == "17"
    for body in (b'{"data": {"id": true}}', b'{"data": {"id": "../x"}}', b"not json", b"{}"):
        assert tr.extract_id(by_json, create_url=create, location="", body=body) == ""
    with pytest.raises(tr.TestRecordAborted):
        tr.record_path_for(endpoint, "a/b")


# ---------------------------------------------------------------- approval

@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
async def test_write_intent_without_matching_endpoint_sends_nothing(monkeypatch, method):
    manager, intent, lease = _manager_with_intent(
        test_type="ssti", location="header", parameter="X-Template", method=method,
        target=T + "/api/notes/42")
    sent = _sent(monkeypatch, lambda req: pytest.fail("nothing may be sent"))
    manager._scoped_body_replay_paths = {"/api/notes/42"}  # POST approval is not enough
    manager.set_scoped_assessment_policy({"test_record_endpoints": [
        {**NOTES, "write_methods": [m for m in ("PUT", "PATCH", "DELETE") if m != method]}]})
    denied = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert denied["error"] == "operator_approval_required" and sent == []
    assert "test_record_endpoints" in denied["reason"]
    assert _cell(manager, lease)["status"] == "leased"
    assert _intent(manager, intent)["status"] == "open"
    assert manager._scoped_test_records == []


@pytest.mark.asyncio
async def test_write_path_location_is_unsupported(monkeypatch):
    manager, intent, lease = _write_manager(location="path", parameter="1",
                                            target=T + "/api/notes/42")
    sent = _sent(monkeypatch, lambda req: pytest.fail("nothing may be sent"))
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["error"] == "unsupported_request_shape" and sent == []
    assert _cell(manager, lease)["status"] != "tested_clean"


# ---------------------------------------------------------------- lifecycle

@pytest.mark.asyncio
@pytest.mark.parametrize("method,target", [("PUT", T + "/api/notes/42"),
                                           ("PATCH", T + "/api/notes/{id}")])
async def test_write_probe_retargets_to_own_record_and_verifier_uses_fresh_one(
        monkeypatch, method, target):
    from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate

    manager, _intent_row, lease = _write_manager(method=method, target=target)
    app = NotesApp()
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is True, out
    assert len(app.created) == 1
    own = f"/api/notes/{app.created[0]}"
    probes = [r for r in sent if r.method == method]
    assert probes and {urlsplit(r.url).path for r in probes} == {own}
    _assert_only_own_records(sent, app, write_method=method)
    assert own not in {f"/api/notes/{k}" for k in app.store}  # cleaned up
    assert out["probe_result"]["record_paths"] == [own]
    (record,) = manager._scoped_test_records
    assert record["state"] == "cleaned" and record["role"] == "hunter"
    assert record["path"] == own and "nonce" not in json.dumps(record).replace("nonce_sha256", "")
    # Creates and cleanups are charged to the POST budget with the probes.
    assert manager._scoped_post_count >= len([r for r in sent if r.method != "GET"])

    active = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        active, title="Template injection in note", target=T + urlsplit(target).path,
        vulnerability_class="ssti", identity="anonymous",
        coverage_cell_id=lease.coverage_cell_id, evidence_ids=[out["evidence_id"]])
    manager._engagement_brain = active.to_dict()
    hunter_count = len(sent)
    reports = await run_independent_verifiers([candidate], llm=None, tools_manager=manager,
                                              targets=[T + urlsplit(target).path])
    assert reports[0]["status"] == "confirmed", reports[0]["verifier_summary"]
    assert len(app.created) == 2
    fresh = f"/api/notes/{app.created[1]}"
    replay = sent[hunter_count:]
    assert replay[0].method == "POST" and urlsplit(replay[0].url).path == "/api/notes"
    assert {urlsplit(r.url).path for r in replay if r.method == method} == {fresh}
    assert own not in {urlsplit(r.url).path for r in replay}
    _assert_only_own_records(sent, app, write_method=method)
    roles = [(r["role"], r["state"]) for r in manager._scoped_test_records]
    assert roles == [("hunter", "cleaned"), ("verifier", "cleaned")]


@pytest.mark.asyncio
@pytest.mark.parametrize("app_kwargs,state", [
    ({"create_status": 500}, "create_failed"),
    ({"id_mode": "none"}, "cleanup_pending"),
    ({"echo_nonce": False}, "cleanup_pending"),
])
async def test_record_not_provably_own_aborts_without_probe(monkeypatch, app_kwargs, state):
    manager, intent, lease = _write_manager()
    app = NotesApp(**app_kwargs)
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is False and out["error"] == "test_record_aborted", out
    assert not [r for r in sent if r.method in {"PUT", "PATCH"}]  # no probe
    # A record that is not provably Prowl's is never deleted either.
    assert not [r for r in sent if r.method == "DELETE"]
    _assert_only_own_records(sent, app, write_method="PUT")
    if app_kwargs.get("echo_nonce") is False:
        # The cleanup attempt is a second read; the record stays for the operator.
        assert [r.method for r in sent] == ["POST", "GET", "GET"]
    assert _cell(manager, lease)["status"] == "leased"
    assert _intent(manager, intent)["status"] == "open"
    assert [r["state"] for r in manager._scoped_test_records] == [state]
    assert out["test_records"][0]["state"] == state


@pytest.mark.asyncio
async def test_cleanup_failure_is_reported_in_status_and_list_tool(monkeypatch):
    manager, _intent_row, lease = _write_manager()
    app = NotesApp(delete_works=False)
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is True
    own = f"/api/notes/{app.created[0]}"
    assert [urlsplit(r.url).path for r in sent if r.method == "DELETE"] == [own]
    _assert_only_own_records(sent, app, write_method="PUT")
    (record,) = manager._scoped_test_records
    assert record["state"] == "cleanup_pending" and "still present" in record["reason"]

    summary = json.loads(await manager.scoped_assessment_summary())
    assert summary["test_records"]["by_state"] == {"cleanup_pending": 1}
    assert summary["test_records"]["cleanup_pending"][0]["path"] == own
    assert own in summary["test_records_notice"]
    listed = json.loads(await manager.list_test_records())
    assert listed["cleanup_pending"][0]["path"] == own
    assert listed["endpoints"][0]["record_path"] == "/api/notes/{id}"
    assert "create_body" not in json.dumps(listed)


@pytest.mark.asyncio
async def test_cleanup_none_leaves_record_pending_without_delete(monkeypatch):
    manager, _intent_row, lease = _write_manager(endpoint={
        **NOTES, "write_methods": ["PUT"], "cleanup": "none", "cleanup_delete_approved": False})
    app = NotesApp()
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True
    assert not [r for r in sent if r.method == "DELETE"]
    assert [r["state"] for r in manager._scoped_test_records] == ["cleanup_pending"]
    assert "cleanup none" in manager._scoped_test_records[0]["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("delete_works,states", [(True, ["cleaned", "cleaned"]),
                                                 (False, ["cleanup_pending", "cleanup_pending"])])
async def test_delete_probe_only_on_own_records(monkeypatch, delete_works, states):
    manager, _intent_row, lease = _write_manager(
        method="DELETE", test_type="open_redirect", location="query", parameter="next",
        target=T + "/api/notes/42?next=/", endpoint={
            **NOTES, "write_methods": ["DELETE"], "cleanup": "none",
            "cleanup_delete_approved": False})

    def redirect(req, record):
        return _Resp(302, b"", {"Location": parse_qs(urlsplit(req.url).query)["next"][0]})

    app = NotesApp(delete_works=delete_works, probe=redirect)
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_response_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is True, out
    deletes = [r for r in sent if r.method == "DELETE"]
    # control + probe each consume a fresh record; a cleanup DELETE (allowed:
    # the probe is a DELETE on Prowl's own record) follows each that survived.
    assert len(app.created) == 2
    assert len(deletes) == (2 if delete_works else 4)
    assert {urlsplit(r.url).path for r in deletes} == _own_paths(app)
    assert all(r.body is None for r in deletes)
    _assert_only_own_records(sent, app, write_method="DELETE")
    assert [r["state"] for r in manager._scoped_test_records] == states


@pytest.mark.asyncio
async def test_verifier_rechecks_endpoint_approval(monkeypatch):
    from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate

    manager, _intent_row, lease = _write_manager()
    app = NotesApp()
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True
    active = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        active, title="Template injection via header", target=T + "/api/notes/42",
        vulnerability_class="ssti", identity="anonymous",
        coverage_cell_id=lease.coverage_cell_id, evidence_ids=[out["evidence_id"]])
    manager._engagement_brain = active.to_dict()
    manager._scoped_test_record_endpoints = []  # approval withdrawn before verification
    count = len(sent)
    reports = await run_independent_verifiers([candidate], llm=None, tools_manager=manager,
                                              targets=[T + "/api/notes/42"])
    assert reports[0]["status"] == "inconclusive" and len(sent) == count


@pytest.mark.asyncio
async def test_sqli_patch_intent_uses_own_record(monkeypatch):
    manager, _intent_row, lease = _write_manager(
        method="PATCH", test_type="sqli", location="body_json", parameter="title")
    html = {"Content-Type": "text/html"}

    def sql(req, record):
        value = json.loads(req.body)["title"]
        match = re.search(r"' OR '(\d+)'='(\d+)'-- $", value)
        if match:
            rows = 400 if match.group(1) == match.group(2) else 0
            return _Resp(200, b"<html>" + b"x" * 100 + b"<tr>row</tr>" * rows, html)
        if value.endswith("'") and not value.endswith("''"):
            return _Resp(500, b"server error", html)
        return _Resp(200, b"<html>" + b"x" * 100, html)

    app = NotesApp(probe=sql)
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is True, out
    assert len(app.created) == 1
    _assert_only_own_records(sent, app, write_method="PATCH")
    assert [r["state"] for r in manager._scoped_test_records] == ["cleaned"]


def test_list_test_records_is_a_read_only_tool_spec():
    from app.services.agent.tool_specs import get_spec

    spec = get_spec("list_test_records")
    assert spec is not None and spec.read_only and spec.run == "list_test_records"


def test_cleanup_notice_lists_pending_records():
    rows = [{"path": "/api/notes/p1", "state": "cleaned"},
            {"path": "/api/notes/p2", "state": "cleanup_pending", "reason": "cleanup DELETE 500"}]
    notice = tr.cleanup_notice(rows)
    assert "1 record" in notice and "/api/notes/p2" in notice and "/api/notes/p1" not in notice
    assert tr.cleanup_notice(rows[:1]) == ""


# ---------------------------------------------------------------- intake route

def test_write_intent_intake_requires_matching_endpoint(env):
    from app.services.agent.run_snapshot import save_session_sidecar

    write = {**BODY, "target": T + "/api/notes/42", "method": "PUT"}
    resp = env.client.post("/agent/sessions/s1/intents", json=write)
    assert resp.status_code == 422 and "test_record_endpoints" in resp.text
    save_session_sidecar(12, "s1", test_record_endpoints=[NOTES])
    path_probe = {**write, "location": "path", "parameter": "1"}
    assert env.client.post("/agent/sessions/s1/intents", json=path_probe).status_code == 422
    other = {**write, "target": T + "/api/users/42"}
    assert env.client.post("/agent/sessions/s1/intents", json=other).status_code == 422
    resp = env.client.post("/agent/sessions/s1/intents", json=write)
    assert resp.status_code == 201, resp.text
    save_session_sidecar(12, "s1", test_records=[
        {"id": "tr_1", "path": "/api/notes/p9", "state": "cleanup_pending",
         "reason": "cleanup DELETE 500", "endpoint": "/api/notes/{id}", "created_at": 1.0}])
    listed = env.client.get("/agent/sessions/s1/intents").json()
    assert listed["test_records"]["cleanup_pending"][0]["path"] == "/api/notes/p9"
    assert "/api/notes/p9" in listed["test_records_notice"]
    assert listed["test_record_endpoints"][0]["record_path"] == "/api/notes/{id}"
