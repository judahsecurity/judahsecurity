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
