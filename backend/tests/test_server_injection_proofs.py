"""Deterministic proofs for SSTI, command injection, traversal, and CSRF, plus
the discipline rules, root-cause dedup, CVE cap, and completion override."""

from __future__ import annotations

import asyncio
import re
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import pytest

from app.services.agent import proof_discipline
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.finding_gate import cap_version_only_cve_severity
from app.services.agent.independent_verify import (
    normalized_endpoint,
    root_cause_key,
    submit_candidate,
)
from app.services.agent.proof_policy import (
    PROOFS_BY_CLASS,
    inferred_vulnerability_class,
    proof_kind_allowed,
    validate_proof,
)
from app.services.agent.scoped_assessment import csrf_probe
from app.services.agent.scoped_assessment.injection_probe import (
    control_value,
    injection_proof_valid,
    new_factors,
    probe_injection,
    probe_value,
    recipes_for,
)
from app.services.agent.tester_loop import (
    SYSTEM_CVE_COMPLETE_REASON,
    completion_override_allowed,
)
from app.services.agent.vulnerability_catalog import specialist_for_class

ORIGIN = "https://app.test"
PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"


def _urls(test_type: str, nonce: str, factors=(0, 0)) -> dict:
    a, b = factors
    urls = {"control": f"{ORIGIN}/p?v={quote(control_value(test_type, nonce), safe='')}"}
    for recipe in recipes_for(test_type):
        urls[recipe] = f"{ORIGIN}/p?v={quote(probe_value(test_type, recipe, a, b), safe='')}"
    return urls


def _evaluating_server(url: str, **_):
    value = parse_qs(urlsplit(url).query)["v"][0]
    match = re.search(r"\{\{(\d+)\*(\d+)\}\}", value)
    body = str(int(match.group(1)) * int(match.group(2))) if match else value
    return 200, f"<p>Hello {body}</p>".encode()


def _reflecting_server(url: str, **_):
    return 200, f"<p>Hello {parse_qs(urlsplit(url).query)['v'][0]}</p>".encode()


def _shell_server(url: str, **_):
    value = parse_qs(urlsplit(url).query)["v"][0]
    match = re.search(r"[;|]expr (\d+) \\\* (\d+)", value)
    return 200, (f"PING ok\n{int(match.group(1)) * int(match.group(2))}" if match else "PING ok").encode()


def _file_server(url: str, **_):
    value = parse_qs(urlsplit(url).query)["v"][0]
    if value.endswith("/etc/passwd"):
        return 200, PASSWD
    return 404, b"not found"


def test_ssti_computed_output_confirms_and_reflection_does_not():
    factors = new_factors()
    nonce = "a1b2c3d4e5f6a7b8"
    hit = probe_injection(_urls("ssti", nonce, factors), test_type="ssti",
                          allowed_origin=ORIGIN, state=None, nonce=nonce,
                          factors=factors, fetch=_evaluating_server)
    assert hit["proof_confirmed"] is True and hit["recipe"] == "jinja_twig"
    assert injection_proof_valid({**hit, "nonce": nonce})
    reflected = probe_injection(_urls("ssti", nonce, factors), test_type="ssti",
                                allowed_origin=ORIGIN, state=None, nonce=nonce,
                                factors=factors, fetch=_reflecting_server)
    assert reflected["proof_confirmed"] is False
    assert len(reflected["probes"]) == len(recipes_for("ssti"))


def test_command_injection_and_traversal_signals():
    factors = new_factors()
    nonce = "0123456789abcdef"
    cmd = probe_injection(_urls("command_injection", nonce, factors),
                          test_type="command_injection", allowed_origin=ORIGIN,
                          state=None, nonce=nonce, factors=factors, fetch=_shell_server)
    assert cmd["proof_confirmed"] is True and cmd["recipe"] == "semicolon_expr"
    trav = probe_injection(_urls("path_traversal", nonce), test_type="path_traversal",
                           allowed_origin=ORIGIN, state=None, nonce=nonce, fetch=_file_server)
    assert trav["proof_confirmed"] is True and trav["signature"] == "passwd"


def test_control_showing_signal_blocks_proof_marker_discipline():
    nonce = "0123456789abcdef"
    always_passwd = lambda url, **_: (200, PASSWD)  # noqa: E731
    result = probe_injection(_urls("path_traversal", nonce), test_type="path_traversal",
                             allowed_origin=ORIGIN, state=None, nonce=nonce, fetch=always_passwd)
    assert result["proof_confirmed"] is False and result["control"]["signal"] is True


def test_short_nonce_and_stale_factors_are_rejected():
    with pytest.raises(ValueError):
        probe_injection(_urls("ssti", "short", (12345, 23456)), test_type="ssti",
                        allowed_origin=ORIGIN, state=None, nonce="short",
                        factors=(12345, 23456), fetch=_evaluating_server)
    with pytest.raises(ValueError):
        probe_injection(_urls("ssti", "0123456789abcdef", (2, 3)), test_type="ssti",
                        allowed_origin=ORIGIN, state=None, nonce="0123456789abcdef",
                        factors=(2, 3), fetch=_evaluating_server)


class _Store:
    def __init__(self):
        self.records = {}

    def add(self, rid, kind, payload, *, created_at, target=f"{ORIGIN}/p", identity="anonymous"):
        self.records[rid] = {"id": rid, "kind": kind, "payload": payload, "target": target,
                             "identity": identity, "created_at": created_at}


def _receipt(test_type, nonce, fetch, factors=None):
    factors = factors or (new_factors() if test_type != "path_traversal" else (0, 0))
    row = probe_injection(_urls(test_type, nonce, factors), test_type=test_type,
                          allowed_origin=ORIGIN, state=None, nonce=nonce,
                          factors=factors, fetch=fetch)
    return {**row, "nonce": nonce, "parameter": "v", "request_context": "browser_traffic"}


def _candidate(klass, title):
    return SimpleNamespace(vulnerability_class=klass, title=title, description="",
                           target=f"{ORIGIN}/p", evidence_ids=["h1"])


def test_validate_proof_accepts_fresh_matching_pair_only():
    store = _Store()
    store.add("h1", "scoped_injection_probe", _receipt("ssti", "aaaaaaaa11111111", _evaluating_server), created_at=1)
    store.add("v1", "scoped_injection_probe", _receipt("ssti", "bbbbbbbb22222222", _evaluating_server), created_at=2)
    cand = _candidate("ssti", "SSTI in greeting message")
    proof = {"kind": "scoped_ssti_eval", "hunter_artifact_id": "h1", "artifact_id": "v1"}
    assert validate_proof(store, cand, proof, ["v1"]) == (True, "")
    # Verifier reused the hunter marker.
    store.records["v1"]["payload"]["nonce"] = "aaaaaaaa11111111"
    ok, why = validate_proof(store, cand, proof, ["v1"])
    assert not ok and "Marker discipline" in why
    # Wrong proof kind for the class.
    assert not proof_kind_allowed(cand, "scoped_cmdi_eval")[0]


def test_validate_proof_rejects_mismatched_recipe_and_order():
    store = _Store()
    store.add("h1", "scoped_injection_probe", _receipt("path_traversal", "aaaaaaaa11111111", _file_server), created_at=1)
    verifier = _receipt("path_traversal", "bbbbbbbb22222222", _file_server)
    verifier["recipe"] = "absolute_passwd"
    store.add("v1", "scoped_injection_probe", verifier, created_at=2)
    cand = _candidate("path_traversal", "Path traversal in download")
    proof = {"kind": "scoped_traversal_read", "hunter_artifact_id": "h1", "artifact_id": "v1"}
    assert not validate_proof(store, cand, proof, ["v1"])[0]
    store.records["v1"]["created_at"] = 0
    assert not validate_proof(store, cand, proof, ["v1"])[0]


def test_new_classes_have_proof_kinds_and_dedicated_lane():
    for klass, kind in (("ssti", "scoped_ssti_eval"), ("command_injection", "scoped_cmdi_eval"),
                        ("path_traversal", "scoped_traversal_read"), ("csrf", "scoped_csrf_state_change")):
        assert kind in PROOFS_BY_CLASS[klass]
    assert PROOFS_BY_CLASS["known_cve"] == frozenset()
    for klass in ("ssti", "command_injection", "path_traversal", "nosql"):
        assert specialist_for_class(klass) == "server_injection"
    assert inferred_vulnerability_class(SimpleNamespace(
        title="Server-side template injection in /greeting", description="")) == "ssti"
    assert inferred_vulnerability_class(SimpleNamespace(
        title="Client-side template injection", description="")) == "client_template_injection"


def test_discipline_timing_and_layer_ordering_rules():
    assert not proof_discipline.timing_differential_ok([100] * 5, [900] * 5)[0]
    assert proof_discipline.timing_differential_ok([100, 110, 95, 105] * 3, [900] * 12)[0]
    assert not proof_discipline.timing_differential_ok([100, 400] * 6, [300] * 12)[0]
    assert not proof_discipline.layer_ordering_ok(400)[0]
    assert not proof_discipline.layer_ordering_ok(422, well_formed_retest_status=401)[0]
    assert proof_discipline.layer_ordering_ok(400, well_formed_retest_status=200)[0]
    assert proof_discipline.layer_ordering_ok(200)[0]


def _csrf_transport(*, token_required=False, anonymous_writes=False):
    state = {"value": "initial"}

    def handler(request: httpx.Request) -> httpx.Response:
        authed = "lab_session=abc" in request.headers.get("cookie", "")
        if request.method == "GET":
            return httpx.Response(200, text=f"<p>{state['value']}</p>")
        if request.method == "POST":
            if (not authed and not anonymous_writes) or token_required:
                return httpx.Response(401 if not authed else 403)
            state["value"] = parse_qs(request.content.decode())["display_name"][0]
            return httpx.Response(302, headers={"Location": "/profile"})
        if request.method == "DELETE":
            state["value"] = "initial"
            return httpx.Response(204)
        return httpx.Response(405)

    return httpx.MockTransport(handler)


def _session(same_site="None"):
    return {"cookies": [{"name": "lab_session", "value": "abc", "domain": "app.test",
                         "path": "/", "secure": True, "sameSite": same_site,
                         "expires": -1}]}


@pytest.mark.parametrize("same_site,token_required,anonymous_writes,expected", [
    ("None", False, False, True),
    ("Lax", False, False, False),
    ("None", True, False, False),
    ("None", False, True, False),
])
def test_csrf_probe(monkeypatch, same_site, token_required, anonymous_writes, expected):
    transport = _csrf_transport(token_required=token_required, anonymous_writes=anonymous_writes)
    monkeypatch.setattr(csrf_probe, "assessment_httpx_options", lambda: {"transport": transport})
    result = asyncio.run(csrf_probe.probe_csrf(
        f"{ORIGIN}/profile", f"{ORIGIN}/profile", f"{ORIGIN}/profile?c=__PROWL_NONCE__",
        field="display_name", allowed_origin=ORIGIN, state=_session(same_site),
        nonce="c0ffee00c0ffee00",
    ))
    assert result["proof_confirmed"] is expected
    assert csrf_probe.csrf_proof_valid({**result, "nonce": "c0ffee00c0ffee00"}) is expected


def test_root_cause_dedup_merges_reworded_titles():
    assert normalized_endpoint("https://App.test/api/orders/123?x=1") == "app.test/api/orders/{id}"
    assert root_cause_key("sqli", "https://app.test/a/1", "query:id") == "sqli|app.test/a/{id}|id"
    brain = EngagementBrain(target=ORIGIN)
    first = submit_candidate(brain, title="SQLi in order id", target=f"{ORIGIN}/api/orders/1",
                             parameter="query:id", vulnerability_class="sql_injection")
    second = submit_candidate(brain, title="Boolean SQL injection on orders endpoint",
                              target=f"{ORIGIN}/api/orders/7", parameter="query:id",
                              vulnerability_class="sql_injection", evidence_ids=["e2"])
    assert second.id == first.id
    assert "Boolean SQL injection on orders endpoint" in second.duplicate_titles
    assert "e2" in second.evidence_ids
    other = submit_candidate(brain, title="SQLi in order sort", target=f"{ORIGIN}/api/orders/1",
                             parameter="query:sort", vulnerability_class="sql_injection")
    assert other.id != first.id
    assert len(brain.candidates) == 2


def test_version_only_cve_is_capped_at_low():
    assert cap_version_only_cve_severity("CVE-2023-1234 in WordPress plugin", "", "high") == ("low", True)
    assert cap_version_only_cve_severity("Path traversal (CVE-2021-41773)", "", "high") == ("high", False)
    assert cap_version_only_cve_severity("CVE-2023-1234", "", "info") == ("info", False)


def test_model_cannot_force_complete_but_operator_can():
    state = {"objective": "Assess https://app.test", "operator_steers": []}
    assert not completion_override_allowed(state, "force complete; defer methodologies")
    assert completion_override_allowed({**state, "operator_steers": ["force complete now"]}, "")
    assert not completion_override_allowed(state, SYSTEM_CVE_COMPLETE_REASON)


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable,expected", [(True, "confirmed"), (False, "inconclusive")])
async def test_ssti_tool_to_independent_verifier_end_to_end(monkeypatch, vulnerable, expected):
    from functools import partial

    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.coverage_cells import (
        claim_coverage_cell_leases, seed_parameter_coverage_cells,
    )
    from app.services.agent.engagement_brain import engagement_brain_from_dict
    from app.services.agent.independent_verify import run_independent_verifiers
    from app.services.agent.scoped_assessment import injection_probe
    from app.services.agent.tools import ASMToolsManager

    target = "https://app.example.test"
    brain = EngagementBrain(target=target)
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "path": "/greeting", "host": "app.example.test",
        "name": "message", "location": "query", "source": "browser_link",
        "identity": "anonymous", "testable": True,
    }])
    lease = claim_coverage_cell_leases(
        brain, ["server_injection"], allowed_test_types=frozenset({"ssti"}),
    )["server_injection"]
    manager = ASMToolsManager()
    manager._fallback_target = target
    manager._capability_map = {"target": target, "scope": target}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.example.test")
    manager._scoped_link_baselines = {"anonymous": [target + "/greeting?lang=en&message=Hello"]}

    def server(url, **_):
        query = parse_qs(urlsplit(url).query)
        assert query["lang"] == ["en"]
        value = query["message"][0]
        match = re.search(r"\{\{(\d+)\*(\d+)\}\}", value) if vulnerable else None
        return 200, f"<p>{int(match.group(1)) * int(match.group(2)) if match else value}</p>".encode()

    monkeypatch.setattr(injection_probe, "probe_injection",
                        partial(injection_probe.probe_injection, fetch=server))
    hunter = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert hunter["success"] is True and hunter["proof_confirmed"] is vulnerable
    active = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        active, title="Server-side template injection in greeting message",
        target=target + "/greeting", vulnerability_class="ssti", identity="anonymous",
        coverage_cell_id=lease.coverage_cell_id, evidence_ids=[hunter["evidence_id"]],
    )
    manager._engagement_brain = active.to_dict()
    reports = await run_independent_verifiers([candidate], llm=None, tools_manager=manager,
                                              targets=[target + "/greeting"])
    assert reports[0]["status"] == expected, reports[0]["verifier_summary"]


# --- NoSQL operator differential -------------------------------------------------

def _nosql_urls(nonce: str) -> dict:
    from app.services.agent.scoped_assessment.injection_probe import (
        NOSQL_SEQUENCE, nosql_field_name, rename_query_field,
    )

    base = f"{ORIGIN}/users?sort=asc&name=prowl{nonce}"
    return {step: rename_query_field(base, "name", nosql_field_name("name", step))
            for step in NOSQL_SEQUENCE}


def _mongo_server(*, parses_operators: bool):
    def fetch(url, **_):
        query = parse_qs(urlsplit(url).query)
        if "name[$ne]" in query:
            matches = ["alice", "bob"] if parses_operators else []
        elif "name[$eq]" in query:
            matches = [] if parses_operators else ["alice", "bob"]
        else:
            matches = []
        token = "csrf-" + "x" * 20 + str(len(url))
        return 200, f"<ul>{''.join(f'<li>{m}</li>' for m in matches)}</ul><i>{token}</i>".encode()
    return fetch


@pytest.mark.parametrize("parses,expected", [(True, True), (False, False)])
def test_nosql_operator_differential(parses, expected):
    from app.services.agent.scoped_assessment.injection_probe import probe_nosql

    nonce = "feedbeef12345678"
    result = probe_nosql(_nosql_urls(nonce), allowed_origin=ORIGIN, state=None,
                         nonce=nonce, fetch=_mongo_server(parses_operators=parses))
    assert result["proof_confirmed"] is expected
    assert injection_proof_valid({**result, "nonce": nonce}) is expected
    assert "sort=asc" in _nosql_urls(nonce)["true_first"]
    assert "name%5B%24ne%5D=" in _nosql_urls(nonce)["true_first"]


# --- JWT signature enforcement -------------------------------------------------

def _b64(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _token() -> str:
    import json as _json
    header = _b64(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(_json.dumps({"sub": "alice", "exp": 4102444800}).encode())
    return f"{header}.{payload}.{_b64(b'signature-bytes-here')}"


def _jwt_server(*, verifies: bool):
    import base64
    import json as _json

    good = _token()

    def send(url, *, token, **_):
        if token is None:
            return 401, b"login required"
        if token == good:
            return 200, b'{"user":"alice","orders":[1,2]}'
        parts = token.split(".")
        try:
            header = _json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            _json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except Exception:
            return 401, b"bad token"
        if verifies:
            return 401, b"bad signature"
        if header.get("alg") == "none" or parts[2]:
            return 200, b'{"user":"alice","orders":[1,2]}'
        return 401, b"bad token"
    return send


@pytest.mark.parametrize("verifies,expected", [(False, True), (True, False)])
def test_jwt_forgery_probe(verifies, expected):
    from app.services.agent.scoped_assessment.jwt_probe import jwt_proof_valid, probe_jwt

    session = {"headers": {"Authorization": f"Bearer {_token()}"}, "cookies": []}
    result = probe_jwt(f"{ORIGIN}/api/me", allowed_origin=ORIGIN, session=session,
                       nonce="0a1b2c3d4e5f6071", send=_jwt_server(verifies=verifies))
    assert result["auth_enforced"] is True
    assert result["proof_confirmed"] is expected
    assert jwt_proof_valid({**result, "nonce": "0a1b2c3d4e5f6071"}) is expected


def test_jwt_probe_requires_auth_enforcement_layer_ordering():
    from app.services.agent.scoped_assessment.jwt_probe import probe_jwt

    def public(url, *, token, **_):
        return 200, b'{"public":true}'

    session = {"headers": {"Authorization": f"Bearer {_token()}"}, "cookies": []}
    result = probe_jwt(f"{ORIGIN}/api/me", allowed_origin=ORIGIN, session=session,
                       nonce="0a1b2c3d4e5f6071", send=public)
    assert result["auth_enforced"] is False and result["proof_confirmed"] is False
    assert result["probes"] == []


# --- Blind command injection OOB ------------------------------------------------

def test_cmdi_oob_template_and_policy_require_lookup():
    from app.services.agent.scoped_assessment.cmdi_oob import plan_oob_cmdi

    field, template = plan_oob_cmdi(f"{ORIGIN}/ping?host=localhost", parameter="host",
                                    shell="posix_subshell")
    assert field == "host" and template == "localhost$(nslookup {{callback_host}})"
    with pytest.raises(ValueError):
        plan_oob_cmdi(f"{ORIGIN}/ping?host=localhost", parameter="host", shell="bash -c")
    assert "oob_callback" in PROOFS_BY_CLASS["command_injection"]


def test_cmdi_oob_callback_rejects_plain_url_fetch():
    store = _Store()
    domain = "abc123.oast.example"
    cand = SimpleNamespace(vulnerability_class="command_injection", title="Blind command injection in ping",
                           description="", target=f"{ORIGIN}/ping", evidence_ids=[], nonce="n")

    def records(planted_value):
        store.records.clear()
        store.add("r", "oob_register", {"payload_domain": domain, "session_id": "s"}, created_at=1)
        store.add("p", "http_exchange", {"request": {"url": f"{ORIGIN}/ping?host={planted_value}",
                                                       "method": "GET"}}, created_at=2)
        store.add("q", "oob_poll", {"session_id": "s", "interactions": [
            {"protocol": "dns", "unique_id": "abc123"}]}, created_at=3)

    proof = {"kind": "oob_callback", "register_id": "r", "plant_id": "p", "poll_id": "q"}
    records(f"localhost%24%28nslookup+x.{domain}%29")
    assert validate_proof(store, cand, proof, ["r", "p", "q"]) == (True, "")
    records(f"https://{domain}/")
    ok, why = validate_proof(store, cand, proof, ["r", "p", "q"])
    assert not ok and "nslookup" in why


# --- POST bodies ----------------------------------------------------------------

def test_body_mutation_replace_mode_for_traversal():
    from app.services.agent.scoped_assessment.body_probe import _mutate_form, _mutate_json

    assert _mutate_form(b"file=report.txt&x=1", "file", "../../etc/passwd", replace=True) == \
        b"file=..%2F..%2Fetc%2Fpasswd&x=1"
    assert _mutate_json(b'{"tpl":"hi","n":1}', "/tpl", "{{1*2}}") == b'{"tpl":"hi{{1*2}}","n":1}'


@pytest.mark.asyncio
async def test_post_body_injection_requires_operator_approval_and_confirms(monkeypatch):
    import base64
    import json as _json

    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.coverage_cells import (
        claim_coverage_cell_leases, seed_parameter_coverage_cells,
    )
    from app.services.agent.scoped_assessment import body_probe
    from app.services.agent.tools import ASMToolsManager

    target = "https://app.example.test"
    brain = EngagementBrain(target=target)
    seed_parameter_coverage_cells(brain, [{
        "method": "POST", "path": "/api/render", "host": "app.example.test",
        "name": "/template", "location": "body_json", "source": "browser_traffic",
        "identity": "anonymous", "testable": True, "artifact_id": "cap1",
    }])
    lease = claim_coverage_cell_leases(
        brain, ["server_injection"], allowed_test_types=frozenset({"ssti"}),
    )["server_injection"]
    assert lease is not None
    manager = ASMToolsManager()
    manager._fallback_target = target
    manager._capability_map = {"target": target, "scope": target}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, "app.example.test")
    exchange = _json.dumps({
        "method": "POST", "resource_type": "fetch", "url": target + "/api/render",
        "request_content_type": "application/json",
        "request_body_base64": base64.b64encode(b'{"template":"Hello"}').decode(),
    }).encode()
    monkeypatch.setattr(manager, "_scoped_exchange", lambda artifact_id, identity: exchange)

    def observe_post(url, mime, body, allowed, state, **_):
        value = _json.loads(body)["template"]
        match = re.search(r"\{\{(\d+)\*(\d+)\}\}", value)
        out = str(int(match.group(1)) * int(match.group(2))) if match else value
        return {"status": 200, "_private_body": f'{{"html":"{out}"}}'.encode()}

    monkeypatch.setattr(body_probe, "_observe_post", observe_post)
    denied = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert denied["error"] == "operator_approval_required"
    manager._scoped_body_replay_paths = {"/api/render"}
    result = await manager.scoped_injection_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["success"] is True and result["proof_confirmed"] is True
    assert result["probe_result"]["recipe"] == "jinja_twig"


# --- Cache-poisoning probe safety -------------------------------------------------

@pytest.mark.asyncio
async def test_cache_poisoning_probe_uses_unique_cache_buster(monkeypatch):
    import json as _json

    from app.services.agent.tools import ASMToolsManager

    seen = []

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            seen.append(url)
            return httpx.Response(200, text="ok", request=httpx.Request("GET", url))

        async def request(self, method, url, **kwargs):
            seen.append(url)
            return httpx.Response(200, text="ok", request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    out = _json.loads(await ASMToolsManager().test_cache_poisoning(
        "https://app.example.test/home", probe_headers=["X-Forwarded-Host", "X-Host"]))
    assert out["headers_probed"] == 2
    assert seen and all("prowlcb=" in url for url in seen)
    busters = {parse_qs(urlsplit(url).query)["prowlcb"][0] for url in seen}
    assert len(busters) == 3  # one per header probe pair, one for the fat GET


@pytest.mark.asyncio
async def test_jwt_tool_to_independent_verifier_end_to_end(monkeypatch):
    from functools import partial

    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.assessment_sessions import identity_registry
    from app.services.agent.engagement_brain import engagement_brain_from_dict
    from app.services.agent.independent_verify import run_independent_verifiers
    from app.services.agent.scoped_assessment import jwt_probe
    from app.services.agent.tools import ASMToolsManager

    target = "https://app.example.test"
    endpoint = target + "/api/me"
    manager = ASMToolsManager()
    manager._fallback_target = target
    manager._capability_map = {"target": target, "scope": target, "pages_visited": [endpoint]}
    manager._engagement_brain = EngagementBrain(target=target).to_dict()
    register_scope(manager, "app.example.test")
    identity_registry(manager).register(
        "alice", target, headers={"Authorization": f"Bearer {_token()}"})
    monkeypatch.setattr(jwt_probe, "probe_jwt",
                        partial(jwt_probe.probe_jwt, send=_jwt_server(verifies=False)))
    assert (await manager.scoped_jwt_probe(endpoint, "anonymous"))["error"] == \
        "registered_identity_required"
    assert (await manager.scoped_jwt_probe(target + "/unseen", "alice"))["error"] == \
        "observed_endpoint_required"
    hunter = await manager.scoped_jwt_probe(endpoint, "alice")
    assert hunter["success"] is True and hunter["proof_confirmed"] is True
    active = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        active, title="JWT signature not verified on /api/me (alg none accepted)",
        target=endpoint, vulnerability_class="jwt", identity="alice",
        evidence_ids=[hunter["evidence_id"]],
    )
    manager._engagement_brain = active.to_dict()
    reports = await run_independent_verifiers([candidate], llm=None, tools_manager=manager,
                                              targets=[endpoint])
    assert reports[0]["status"] == "confirmed", reports[0]["verifier_summary"]


def test_reworded_duplicate_cannot_reopen_confirmed_candidate():
    brain = EngagementBrain(target=ORIGIN)
    first = submit_candidate(brain, title="SSTI in greeting", target=f"{ORIGIN}/greeting",
                             parameter="query:message", vulnerability_class="ssti",
                             description="original claim", specialist="server_injection")
    raw = brain.candidates[0]
    raw["status"] = "confirmed"
    brain.candidates = [raw]
    again = submit_candidate(brain, title="Template injection via message param",
                             target=f"{ORIGIN}/greeting", parameter="query:message",
                             vulnerability_class="ssti", description="different text",
                             specialist="vanguard_external", evidence_ids=["e9"])
    assert again.id == first.id
    assert again.status == "confirmed"
    assert again.description == "original claim" and again.specialist == "server_injection"
    assert "e9" in again.evidence_ids
