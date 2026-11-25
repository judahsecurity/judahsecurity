"""NoSQL beyond query/form/JSON and numeric/UNION SQLi on intent-backed cells.

NoSQL: cookie-parser ``j:`` JSON cookies, JSON-valued headers (JSON baseline
only), XML operator elements, string recipes on a path segment. SQLi: the
numeric Boolean and UNION recipes with the baseline from the linked capture or
the operator's ``baseline_value``. Hunter and independent verifier go through
the same builder. No network: every request is faked.
"""

import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from app.services.agent import attack_graph as graph
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.scoped_assessment import intent_request as ir
from app.services.agent.scoped_assessment.injection_probe import NOSQL_SEQUENCE
from test_operator_intent_shapes import (  # noqa: F401 - env is a fixture
    BODY, T, _Resp, _cell, _intent, _sent, env,
)

HTML = {"Content-Type": "text/html"}
ROWS = b"<html><ul><li>alice</li><li>bob</li><li>carol</li></ul></html>"
NONE = b"<html><ul></ul></html>"


def _manager(*, test_type, location, parameter, method="GET", target=T + "/api/users",
             baseline_value=None, source_capture_id="", created_by="operator"):
    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.coverage_cells import claim_coverage_cell_leases
    from app.services.agent.tools import ASMToolsManager

    brain = EngagementBrain(target=T)
    fact = graph.record_fact(brain, kind="operator", summary="operator lead")
    intent = graph.add_intent(brain, objective="", test_type=test_type, target=target,
                              parents=[fact["id"]], parameter=parameter, location=location,
                              method=method, created_by=created_by,
                              baseline_value=baseline_value,
                              source_capture_id=source_capture_id,
                              source_evidence_id=source_capture_id)
    specialist = next(c["specialist"] for c in brain.coverage_cells
                      if c["id"] == intent["coverage_cell_id"])
    lease = claim_coverage_cell_leases(brain, [specialist],
                                       allowed_cell_ids=frozenset({intent["coverage_cell_id"]}))
    manager = ASMToolsManager()
    manager._fallback_target = T
    manager._capability_map = {"target": T, "scope": T}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.example.com")
    return manager, intent, lease[specialist]


def _capture(manager, capture_id, *, url, method="GET", headers=None, body=b"",
             content_type="", identity="anonymous"):
    import base64

    manager._scoped_browser_exchanges = {
        **(getattr(manager, "_scoped_browser_exchanges", None) or {}),
        capture_id: {"identity": identity, "verifier_run_id": None, "public": {},
                     "private": json.dumps({
                         "url": url, "method": method, "resource_type": "xhr",
                         "replay_headers": headers or {},
                         "request_body_base64": base64.b64encode(body).decode(),
                         "request_content_type": content_type}).encode()}}


def _operator_filter(value):
    """What a vulnerable server makes of one decoded input object."""
    if isinstance(value, dict) and "$ne" in value:
        return ROWS
    return NONE  # literal or $eq on the random literal: nothing matches


async def _verify(manager, lease, out, *, klass, path):
    from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate

    active = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        active, title=f"{klass} on intent input", target=T + path, vulnerability_class=klass,
        identity="anonymous", coverage_cell_id=lease.coverage_cell_id,
        evidence_ids=[out["evidence_id"]])
    manager._engagement_brain = active.to_dict()
    reports = await run_independent_verifiers([candidate], llm=None, tools_manager=manager,
                                              targets=[T + path])
    return reports[0]


# ---------------------------------------------------------------- NoSQL plans

def test_cookie_plan_uses_cookie_parser_json_prefix():
    plans = ir.injection_requests(method="GET", url=T + "/api/users", location="cookie",
                                  parameter="filter", test_type="nosql", nonce="abcd1234",
                                  factors=(0, 0), state=None)
    assert set(plans) == set(NOSQL_SEQUENCE)

    def cookie(step):
        raw = plans[step].header("Cookie").partition("filter=")[2]
        return unquote(raw)

    assert cookie("control_first") == "prowlabcd1234"
    assert cookie("true_first") == 'j:{"$ne":"prowlabcd1234"}'
    assert cookie("false_first") == 'j:{"$eq":"prowlabcd1234"}'
    assert plans["true_first"].url == T + "/api/users"


def test_header_plan_replaces_the_one_string_field_of_the_json_baseline():
    plans = ir.injection_requests(method="GET", url=T + "/api/users", location="header",
                                  parameter="X-Filter", test_type="nosql", nonce="abcd1234",
                                  factors=(0, 0), state=None,
                                  baseline='{"user":"alice","limit":5}')
    assert json.loads(plans["control_first"].header("X-Filter")) == {
        "user": "prowlabcd1234", "limit": 5}
    assert json.loads(plans["true_first"].header("X-Filter")) == {
        "user": {"$ne": "prowlabcd1234"}, "limit": 5}
    assert json.loads(plans["false_first"].header("X-Filter")) == {
        "user": {"$eq": "prowlabcd1234"}, "limit": 5}
    nested = ir.json_operator_values('[{"q":{"name":"x"}}]', "L")
    assert json.loads(nested["true"]) == [{"q": {"name": {"$ne": "L"}}}]


@pytest.mark.parametrize("baseline,reason", [
    ("", "header_baseline_not_json"),
    ("alice", "header_baseline_not_json"),
    ('"alice"', "header_baseline_not_json"),
    ("42", "header_baseline_not_json"),
    ('{"limit":5}', "header_json_needs_one_string_field"),
    ('{"a":"x","b":"y"}', "header_json_string_field_ambiguous"),
])
def test_header_nosql_without_a_json_object_baseline_is_unsupported(baseline, reason):
    with pytest.raises(ir.UnsupportedShape, match=reason):
        ir.injection_requests(method="GET", url=T + "/x", location="header",
                              parameter="X-Filter", test_type="nosql", nonce="abcd1234",
                              factors=(0, 0), state=None, baseline=baseline)


def test_xml_plan_uses_operator_elements_against_a_literal_control():
    plans = ir.injection_requests(method="POST", url=T + "/api/login", location="body_xml",
                                  parameter="/login/user", test_type="nosql", nonce="abcd1234",
                                  factors=(0, 0), state=None, write_approved=True)
    head = b'<?xml version="1.0" encoding="UTF-8"?>'
    assert plans["control_first"].body == head + b"<login><user>prowlabcd1234</user></login>"
    assert plans["true_first"].body == (
        head + b"<login><user><$ne>prowlabcd1234</$ne></user></login>")
    assert plans["false_first"].body == (
        head + b"<login><user><$eq>prowlabcd1234</$eq></user></login>")
    assert all(b"DOCTYPE" not in p.body for p in plans.values())
    with pytest.raises(ir.ApprovalRequired):
        ir.injection_requests(method="POST", url=T + "/api/login", location="body_xml",
                              parameter="user", test_type="nosql", nonce="abcd1234",
                              factors=(0, 0), state=None)


def test_path_plan_carries_only_string_recipes():
    assert ir.nosql_recipes_for("path") == ir.NOSQL_PATH_RECIPES
    plans = ir.injection_requests(method="GET", url=T + "/api/users/alice/profile",
                                  location="path", parameter="2", test_type="nosql",
                                  nonce="abcd1234", factors=(0, 0), state=None,
                                  nosql_recipe="where_single_quote")

    def segment(step):
        return unquote(urlsplit(plans[step].url).path.split("/")[3])

    assert segment("control_first") == "prowlabcd1234"
    assert segment("true_first") == "prowlabcd1234' || 'a'=='a"
    assert segment("false_first") == "prowlabcd1234' && 'a'=='b"
    assert all(urlsplit(p.url).path.endswith("/profile") for p in plans.values())
    regex = ir.injection_requests(method="GET", url=T + "/u/alice", location="path",
                                  parameter="1", test_type="nosql", nonce="abcd1234",
                                  factors=(0, 0), state=None, nosql_recipe="regex_alternation")
    assert unquote(urlsplit(regex["true_second"].url).path) == "/u/prowlabcd1234|.*"
    assert unquote(urlsplit(regex["false_first"].url).path) == "/u/(?:prowlabcd1234)"
    with pytest.raises(ir.UnsupportedShape, match="recipe_unknown"):
        ir.injection_requests(method="GET", url=T + "/u/alice", location="path",
                              parameter="1", test_type="nosql", nonce="abcd1234",
                              factors=(0, 0), state=None, nosql_recipe="operator_ne")


# ---------------------------------------------------------------- NoSQL servers

def _cookie_server(*, reflect=False, parse=True):
    def server(req):
        raw = req.header("Cookie").partition("filter=")[2].split(";")[0]
        value = unquote(raw)
        if reflect:
            return _Resp(200, NONE + value.encode(), HTML)
        if parse and value.startswith("j:"):
            return _Resp(200, _operator_filter(json.loads(value[2:])), HTML)
        return _Resp(200, NONE, HTML)

    return server


def _header_server(req):
    document = json.loads(req.header("X-Filter"))
    return _Resp(200, _operator_filter(document["user"]), HTML)


def _xml_server(req):
    match = re.search(rb"<user>(?:<(\$ne|\$eq)>)?([^<]*)", req.body)
    operator = match.group(1)
    return _Resp(200, ROWS if operator == b"$ne" else NONE, HTML)


def _regex_path_server(req):
    segment = unquote(urlsplit(req.url).path.split("/")[3])
    if "'" in segment or '"' in segment:
        return _Resp(400, b"bad name", HTML)  # quotes rejected: the $where recipes fail
    try:
        found = [u for u in ("alice", "bob") if re.search(segment, u)]
    except re.error:
        found = []
    return _Resp(200, ("<ul>" + "".join(f"<li>{u}</li>" for u in found) + "</ul>").encode(), HTML)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["cookie", "header", "body_xml", "path"])
async def test_nosql_intent_locations_confirm_and_verifier_replays(monkeypatch, case):
    if case == "cookie":
        manager, intent, lease = _manager(test_type="nosql", location="cookie",
                                          parameter="filter")
        server, path, expected = _cookie_server(), "/api/users", 5
    elif case == "header":
        manager, intent, lease = _manager(test_type="nosql", location="header",
                                          parameter="X-Filter",
                                          baseline_value='{"user":"alice"}')
        server, path, expected = _header_server, "/api/users", 5
    elif case == "body_xml":
        manager, intent, lease = _manager(test_type="nosql", location="body_xml",
                                          parameter="/login/user", method="POST",
                                          target=T + "/api/login")
        manager._scoped_body_replay_paths = {"/api/login"}
        server, path, expected = _xml_server, "/api/login", 5
    else:
        manager, intent, lease = _manager(test_type="nosql", location="path", parameter="2",
                                          target=T + "/api/users/alice/profile")
        server, path, expected = _regex_path_server, "/api/users/alice/profile", 15
    sent = _sent(monkeypatch, server)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is True, out
    assert out["request_context"] == f"intent_{case}"
    assert len(sent) == expected
    assert _cell(manager, lease)["status"] == "in_focus"
    assert _intent(manager, intent)["status"] == "done"
    from app.services.agent.evidence_store import evidence_store

    receipt = evidence_store(manager).records[out["evidence_id"]]["payload"]
    assert receipt["location"] == case and receipt["recipe"] == (
        "regex_alternation" if case == "path" else "operator_ne")
    count = len(sent)
    report = await _verify(manager, lease, out, klass="nosql", path=path)
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert len(sent) - count == 5  # the hunter's recipe only, fresh nonce
    first = {r.url + str(r.headers) + str(r.body) for r in sent[:count]}
    assert not first & {r.url + str(r.headers) + str(r.body) for r in sent[count:]}


@pytest.mark.asyncio
@pytest.mark.parametrize("server", [
    _cookie_server(reflect=True),   # reflection: the $eq variant differs from the control
    _cookie_server(parse=False),    # no JSON cookies: true variant equals the control
])
async def test_nosql_cookie_without_differential_is_not_clean(monkeypatch, server):
    manager, _intent_row, lease = _manager(test_type="nosql", location="cookie",
                                           parameter="filter")
    _sent(monkeypatch, server)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is False
    assert _cell(manager, lease)["status"] not in {"tested_clean", "in_focus"}


@pytest.mark.asyncio
@pytest.mark.parametrize("baseline", [None, "plain-text", '{"a":1}'])
async def test_nosql_header_without_json_baseline_stays_open(monkeypatch, baseline):
    manager, intent, lease = _manager(test_type="nosql", location="header",
                                      parameter="X-Filter", baseline_value=baseline)
    sent = _sent(monkeypatch, lambda req: pytest.fail("nothing is sent"))
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["error"] == "unsupported_request_shape" and sent == []
    cell = _cell(manager, lease)
    assert cell["status"] == "inconclusive" and cell["unsupported_shape"]
    assert _intent(manager, intent)["status"] == "blocked"


@pytest.mark.asyncio
async def test_nosql_header_baseline_from_linked_capture(monkeypatch):
    manager, _intent_row, lease = _manager(test_type="nosql", location="header",
                                           parameter="X-Filter", source_capture_id="cap-h1",
                                           created_by="agent")
    _capture(manager, "cap-h1", url=T + "/api/users?page=2",
             headers={"X-Filter": '{"user":"alice"}'})
    sent = _sent(monkeypatch, _header_server)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True, out
    assert all(json.loads(r.header("X-Filter"))["user"] != "alice" for r in sent)


@pytest.mark.asyncio
async def test_nosql_xml_post_needs_body_replay_approval(monkeypatch):
    manager, intent, lease = _manager(test_type="nosql", location="body_xml",
                                      parameter="user", method="POST", target=T + "/api/login")
    sent = _sent(monkeypatch, lambda req: pytest.fail("no request without approval"))
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["error"] == "operator_approval_required" and sent == []
    assert _cell(manager, lease)["status"] == "leased"
    assert _intent(manager, intent)["status"] == "open"


@pytest.mark.asyncio
async def test_nosql_xml_put_only_touches_prowls_own_record(monkeypatch):
    from test_prowl_test_records import NOTES, NotesApp

    def probe(req, record):
        assert record.startswith("p"), "only Prowl's own record"
        return _xml_server(req)

    app = NotesApp(probe=probe)
    manager, _intent_row, lease = _manager(test_type="nosql", location="body_xml",
                                           parameter="/note/user", method="PUT",
                                           target=T + "/api/notes/42")
    manager.set_scoped_assessment_policy({"test_record_endpoints": [NOTES]})
    sent = _sent(monkeypatch, app)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True, out
    assert app.store["42"] == "company quarterly plan"
    assert all(urlsplit(r.url).path != "/api/notes/42" for r in sent)
    assert out["probe_result"]["record_paths"]


def _where_path_server(req):
    """``$where: "this.name == '" + segment + "'"`` evaluated for two users."""
    segment = unquote(urlsplit(req.url).path.split("/")[3])
    found = []
    for user in ("alice", "bob"):
        expression = f"'{user}' == '{segment}'"
        clauses = [c.strip() for c in expression.split("||")]
        truth = any(all(eval_eq(part) for part in clause.split("&&")) for clause in clauses)
        if truth:
            found.append(user)
    return _Resp(200, ("<ul>" + "".join(f"<li>{u}</li>" for u in found) + "</ul>").encode(), HTML)


def eval_eq(part):
    left, _sep, right = part.strip().partition("==")
    return left.strip() == right.strip()


@pytest.mark.asyncio
async def test_nosql_path_where_recipe_and_verifier(monkeypatch):
    manager, _intent_row, lease = _manager(test_type="nosql", location="path", parameter="2",
                                           target=T + "/api/users/alice/profile")
    sent = _sent(monkeypatch, _where_path_server)
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True and len(sent) == 5, out
    report = await _verify(manager, lease, out, klass="nosql", path="/api/users/alice/profile")
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert len(sent) == 10


@pytest.mark.asyncio
async def test_nosql_path_without_string_evaluation_is_not_clean(monkeypatch):
    manager, _intent_row, lease = _manager(test_type="nosql", location="path", parameter="2",
                                           target=T + "/api/users/alice/profile")
    sent = _sent(monkeypatch, lambda req: _Resp(200, NONE, HTML))
    out = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is False and len(sent) == 15  # every string recipe once
    assert _cell(manager, lease)["status"] != "tested_clean"


# ---------------------------------------------------------------- numeric SQLi

def _numeric_server(read, *, require=None):
    def server(req):
        if require:
            require(req)
        value = read(req)
        match = re.fullmatch(r"(\d+) AND (\d+)=(\d+)", value)
        if match:
            ok = match.group(2) == match.group(3)
            return _Resp(200, b"<html>item " + match.group(1).encode() + b"</html>" if ok
                         else b"<html>not found</html>", HTML)
        if re.fullmatch(r"\d+", value):
            return _Resp(200, b"<html>item " + value.encode() + b"</html>", HTML)
        return _Resp(200, b"<html>not found</html>", HTML)

    return server


@pytest.mark.asyncio
async def test_numeric_sqli_intent_from_operator_baseline_value(monkeypatch):
    from app.services.agent.evidence_store import evidence_store

    manager, intent, lease = _manager(test_type="sqli", location="body_json", parameter="id",
                                      method="POST", target=T + "/api/item",
                                      baseline_value="7")
    manager._scoped_body_replay_paths = {"/api/item"}
    sent = _sent(monkeypatch, _numeric_server(lambda r: json.loads(r.body)["id"]))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["success"] is True and out["proof_confirmed"] is True, out
    assert out["operation"] == "scoped_numeric_sqli"
    assert out["probe_result"]["proof_recipe"] == "numeric_and_boolean_v1"
    assert out["probe_result"]["baseline_value_source"] == "operator_baseline_value"
    assert json.loads(sent[0].body) == {"id": "7"}  # fresh baseline with the exact value
    assert len(sent) == 7 and {r.method for r in sent} == {"POST"}
    record = evidence_store(manager).records[out["evidence_id"]]
    assert record["kind"] == "scoped_numeric_sqli"
    assert record["payload"]["request_context"] == "intent_body_json"
    count = len(sent)
    report = await _verify(manager, lease, out, klass="sql_injection", path="/api/item")
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert len(sent) - count == 7
    assert _intent(manager, intent)["status"] == "done"


@pytest.mark.asyncio
async def test_numeric_sqli_intent_from_captured_baseline(monkeypatch):
    def require(req):
        assert parse_qs(urlsplit(req.url).query)["view"] == ["full"]  # captured request kept

    manager, intent, lease = _manager(test_type="sqli", location="query", parameter="id",
                                      target=T + "/api/items", source_capture_id="cap-7",
                                      created_by="agent")
    assert intent["source_capture_id"] == "cap-7"
    _capture(manager, "cap-7", url=T + "/api/items?id=42&view=full")
    sent = _sent(monkeypatch, _numeric_server(
        lambda r: parse_qs(urlsplit(r.url).query)["id"][0], require=require))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True, out
    assert out["probe_result"]["baseline_value_source"] == "captured_request"
    assert parse_qs(urlsplit(sent[0].url).query)["id"] == ["42"]
    count = len(sent)
    report = await _verify(manager, lease, out, klass="sql_injection", path="/api/items")
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert len(sent) - count == 7


@pytest.mark.asyncio
async def test_numeric_recipe_refused_when_baseline_is_not_a_positive_integer(monkeypatch):
    manager, _intent_row, lease = _manager(test_type="sqli", location="header",
                                           parameter="X-Item", baseline_value="abc7")
    sent = _sent(monkeypatch, _numeric_server(lambda r: r.header("X-Item")))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is False
    assert out["probe_result"]["numeric_skipped"] == "baseline_not_positive_integer"
    assert not any(re.fullmatch(r"\S+ AND \d+=\d+", r.header("X-Item")) for r in sent)
    assert _cell(manager, lease)["status"] != "tested_clean"
    cell = _cell(manager, lease)
    with pytest.raises(ir.UnsupportedShape, match="baseline_not_positive_integer"):
        await manager._run_shaped_sqli(cell, "anonymous", scoped_origin=T,
                                       recipe="numeric_and_boolean_v1")


# ---------------------------------------------------------------- UNION SQLi

def _union_server(read, *, reflect=True):
    def server(req):
        value = read(req)
        if "' UNION SELECT " in value:
            cells = value.split("' UNION SELECT ", 1)[1].rsplit("-- ", 1)[0].split(",")
            if len(cells) == 2 and cells[1].startswith("0x"):
                marker = bytes.fromhex(cells[1][2:])
                return _Resp(200, b"<table><tr><td>" + marker + b"</td></tr></table>", HTML)
            return _Resp(200, b"<html>error</html>", HTML)
        if value == "apple" and reflect:
            return _Resp(200, b"<table><tr><td>apple pie</td></tr></table>", HTML)
        return _Resp(200, b"<table></table>", HTML)

    return server


@pytest.mark.asyncio
async def test_union_sqli_intent_from_operator_target_value(monkeypatch):
    from app.services.agent.evidence_store import evidence_store

    manager, _intent_row, lease = _manager(test_type="sqli", location="query", parameter="q",
                                           target=T + "/search?q=apple&lang=en",
                                           baseline_value="apple")
    sent = _sent(monkeypatch, _union_server(lambda r: parse_qs(urlsplit(r.url).query)["q"][0]))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True, out
    result = out["probe_result"]
    assert result["proof_recipe"] == "string_union_v1"
    assert result["column_count"] == 2 and result["reflected_position"] == 2
    assert all(parse_qs(urlsplit(r.url).query)["lang"] == ["en"] for r in sent)
    payload = evidence_store(manager).records[out["evidence_id"]]["payload"]
    assert payload["intent_request"] is True and payload["request_context"] == "intent_query"
    assert payload["sql_family"] == "mysql"
    count = len(sent)
    report = await _verify(manager, lease, out, klass="sql_injection", path="/search")
    assert report["status"] == "confirmed", report["verifier_summary"]
    assert len(sent) - count == 1 + 3 + 4  # fresh baseline, discovery, confirm


@pytest.mark.asyncio
async def test_union_sqli_intent_from_captured_header_baseline(monkeypatch):
    manager, _intent_row, lease = _manager(test_type="sqli", location="header",
                                           parameter="X-Product", source_capture_id="cap-u",
                                           created_by="agent", target=T + "/api/products")
    _capture(manager, "cap-u", url=T + "/api/products", headers={"X-Product": "apple"})
    _sent(monkeypatch, _union_server(lambda r: r.header("X-Product")))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is True, out
    assert out["probe_result"]["proof_recipe"] == "string_union_v1"
    assert out["probe_result"]["baseline_value_source"] == "captured_request"
    report = await _verify(manager, lease, out, klass="sql_injection", path="/api/products")
    assert report["status"] == "confirmed", report["verifier_summary"]


@pytest.mark.asyncio
async def test_union_refused_when_baseline_response_does_not_reflect_results(monkeypatch):
    manager, _intent_row, lease = _manager(test_type="sqli", location="query", parameter="q",
                                           target=T + "/search?q=apple")
    sent = _sent(monkeypatch, _union_server(lambda r: parse_qs(urlsplit(r.url).query)["q"][0],
                                            reflect=False))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["proof_confirmed"] is False
    assert out["probe_result"]["union_skipped"] == "baseline_result_not_reflected"
    assert not any("UNION" in unquote(r.url) for r in sent)
    assert _cell(manager, lease)["status"] != "tested_clean"


@pytest.mark.asyncio
async def test_union_needs_an_ordinary_string_baseline(monkeypatch):
    manager, _intent_row, lease = _manager(test_type="sqli", location="cookie", parameter="q")
    sent = _sent(monkeypatch, lambda req: _Resp(200, b"<html>same</html>", HTML))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["probe_result"]["union_skipped"] == "baseline_not_ordinary_string"
    assert not any("UNION" in unquote(r.header("Cookie")) for r in sent)


@pytest.mark.asyncio
async def test_numeric_put_intent_without_test_record_endpoint_is_refused(monkeypatch):
    manager, intent, lease = _manager(test_type="sqli", location="body_json", parameter="id",
                                      method="PUT", target=T + "/api/items/1",
                                      baseline_value="1")
    sent = _sent(monkeypatch, lambda req: pytest.fail("no request without approval"))
    out = await manager.scoped_input_probe_assigned(lease.coverage_cell_id, lease.id)
    assert out["error"] == "operator_approval_required" and sent == []
    assert _intent(manager, intent)["status"] == "open"


# ---------------------------------------------------------------- receipts

def test_numeric_and_union_validators_accept_intent_shapes_only_with_matching_context():
    from app.services.agent.scoped_assessment import sqli_boolean, sqli_union

    rows = {key: {"status": 200, "truncated": False, "redirected": False,
                  "content_type": "text/html",
                  "body_sha256": ("b" if key.startswith("false") else "a") * 64}
            for key in sqli_boolean.CHECK_ORDER}
    numeric = {"operation": "sqli_boolean_numeric", "proof_recipe": "numeric_and_boolean_v1",
               "target": T + "/x", "parameter": "id", "nonce": "12345", "checks": rows,
               "method": "PUT", "location": "body_json", "intent_request": True,
               "request_context": "intent_body_json"}
    assert sqli_boolean.numeric_sql_proof_valid(numeric)
    assert not sqli_boolean.numeric_sql_proof_valid({**numeric, "request_context": "intent_query"})
    assert not sqli_boolean.numeric_sql_proof_valid({**numeric, "intent_request": False})
    union_rows = {key: {"status": 200, "truncated": False, "redirected": False,
                        "reflection_detected": key.startswith("union")}
                  for key in sqli_union.UNION_CHECK_ORDER}
    union = {"operation": "sqli_union_string", "proof_recipe": "string_union_v1",
             "target": T + "/x", "parameter": "q", "nonce": "12345", "sql_family": "mysql",
             "column_count": 2, "reflected_position": 2, "requests_sent": 4,
             "checks": union_rows, "method": "GET", "location": "header",
             "intent_request": True, "request_context": "intent_header"}
    assert sqli_union.union_sql_proof_valid(union)
    assert not sqli_union.union_sql_proof_valid({**union, "location": "fragment",
                                                 "request_context": "intent_fragment"})


def test_proof_policy_pairs_intent_sqli_by_request_shape_and_baseline_source():
    from types import SimpleNamespace

    from app.services.agent.proof_policy import validate_proof
    from app.services.agent.scoped_assessment import sqli_boolean

    def payload(nonce, **extra):
        rows = {key: {"status": 200, "truncated": False, "redirected": False,
                      "content_type": "text/html",
                      "body_sha256": ("b" if key.startswith("false") else "a") * 64}
                for key in sqli_boolean.CHECK_ORDER}
        return {"operation": "sqli_boolean_numeric", "proof_recipe": "numeric_and_boolean_v1",
                "target": T + "/x", "parameter": "id", "nonce": nonce, "checks": rows,
                "method": "GET", "location": "header", "intent_request": True,
                "request_context": "intent_header", "proof_confirmed": True,
                "baseline_value_source": "operator_baseline_value", **extra}

    def store(second):
        return SimpleNamespace(records={
            "h": {"id": "h", "kind": "scoped_numeric_sqli", "target": T + "/x",
                  "identity": "anonymous", "created_at": 1, "payload": payload("12345")},
            "v": {"id": "v", "kind": "scoped_numeric_sqli", "target": T + "/x",
                  "identity": "anonymous", "created_at": 2, "payload": second}})

    cand = SimpleNamespace(vulnerability_class="sql_injection", target=T + "/x",
                           evidence_ids=["h"], title="SQLi", parameter="", identity="anonymous")
    proof = {"kind": "numeric_boolean_sqli", "hunter_artifact_id": "h", "artifact_id": "v"}
    ok, why = validate_proof(store(payload("23456")), cand, proof, ["v"])
    assert ok, why
    for changed in ({"location": "cookie", "request_context": "intent_cookie"},
                    {"baseline_value_source": "captured_request"}, {"method": "POST"}):
        ok, _why = validate_proof(store(payload("23456", **changed)), cand, proof, ["v"])
        assert not ok, changed


# ---------------------------------------------------------------- provenance

def test_intent_provenance_round_trips_and_is_additive():
    brain = EngagementBrain(target=T)
    fact = graph.record_fact(brain, kind="operator", summary="lead")
    plain = graph.add_intent(brain, objective="", test_type="sqli", target=T + "/a",
                             parents=[fact["id"]], parameter="id", location="query")
    assert "source_capture_id" not in plain and "baseline_value" not in plain
    again = graph.add_intent(brain, objective="", test_type="sqli", target=T + "/a",
                             parents=[fact["id"]], parameter="id", location="query",
                             source_capture_id="cap-1", source_evidence_id="cap-1",
                             baseline_value="5")
    assert again["id"] == plain["id"] and again["source_capture_id"] == "cap-1"
    assert again["baseline_value"] == "5"
    graph.add_intent(brain, objective="", test_type="sqli", target=T + "/a",
                     parents=[fact["id"]], parameter="id", location="query",
                     baseline_value="9")
    restored = engagement_brain_from_dict(brain.to_dict())
    row = graph.get_intent(restored, plain["id"])
    assert row["baseline_value"] == "5" and row["source_evidence_id"] == "cap-1"
    for bad in ({"baseline_value": "a\nb"}, {"baseline_value": "x" * 513},
                {"source_capture_id": "../etc"}):
        with pytest.raises(ValueError):
            graph.add_intent(brain, objective="", test_type="sqli", target=T + "/b",
                             parents=[fact["id"]], parameter="id", location="query", **bad)
    with pytest.raises(ValueError):
        graph.add_intent(brain, objective="", test_type="xss", target=T + "/b",
                         parents=[fact["id"]], parameter="q", location="fragment",
                         baseline_value="x")


@pytest.mark.asyncio
async def test_agent_add_intent_links_capture_as_evidence_fact_parent():
    manager, _intent_row, _lease = _manager(test_type="ssti", location="query", parameter="q")
    _capture(manager, "cap-9", url=T + "/api/items?id=3")
    brain = engagement_brain_from_dict(manager._engagement_brain)
    parent = brain.facts[-1]["id"]
    out = json.loads(await manager.add_intent(
        test_type="sqli", target=T + "/api/items", parents=[parent], parameter="id",
        location="query", source_capture_id="cap-9"))
    intent = out["intent"]
    assert intent["source_capture_id"] == "cap-9" == intent["source_evidence_id"]
    brain = engagement_brain_from_dict(manager._engagement_brain)
    evidence = [graph.get_fact(brain, p) for p in intent["parents"]]
    assert any(f and f["kind"] == "evidence" and f["evidence_ids"] == ["cap-9"]
               for f in evidence)
    for kwargs, error in (({"target": T + "/other"}, "different request"),
                          ({"identity": "alice"}, "another identity"),
                          ({"method": "POST"}, "different request"),
                          ({"source_capture_id": "nope"}, "unknown")):
        args = {"test_type": "sqli", "target": T + "/api/items", "parents": [parent],
                "parameter": "id", "location": "query", "source_capture_id": "cap-9",
                **kwargs}
        assert error in json.loads(await manager.add_intent(**args))["error"]


@pytest.mark.parametrize("patch,code", [
    ({"test_type": "sqli", "location": "body_json", "parameter": "id", "method": "POST",
      "baseline_value": "7"}, 201),
    ({"test_type": "sqli", "location": "query", "parameter": "lang", "baseline_value": "en"},
     201),
    ({"test_type": "sqli", "location": "query", "parameter": "lang", "baseline_value": "de"},
     422),  # differs from the value the target carries
    ({"test_type": "sqli", "location": "query", "parameter": "lang",
      "baseline_value": "a\nb"}, 422),
    ({"test_type": "xss", "location": "fragment", "parameter": "q", "baseline_value": "x"},
     422),
    ({"test_type": "nosql", "location": "header", "parameter": "X-Filter"}, 422),
    ({"test_type": "nosql", "location": "header", "parameter": "X-Filter",
      "baseline_value": "alice"}, 422),
    ({"test_type": "nosql", "location": "header", "parameter": "X-Filter",
      "baseline_value": '{"user":"alice"}'}, 201),
    ({"test_type": "nosql", "location": "cookie", "parameter": "filter"}, 201),
    ({"test_type": "nosql", "location": "path", "parameter": "reset"}, 201),
])
def test_intake_validates_baseline_value(env, patch, code):
    from app.services.agent import run_snapshot

    resp = env.client.post("/agent/sessions/s1/intents", json={**BODY, "note": "", **patch})
    assert resp.status_code == code, resp.text
    if code == 201:
        stored = run_snapshot.load_run_snapshot(12, "s1")["engagement_brain"]["intents"][-1]
        assert stored.get("baseline_value") == patch.get("baseline_value")
        assert resp.json()["intent"]["baseline_value_supplied"] is bool(
            patch.get("baseline_value"))
