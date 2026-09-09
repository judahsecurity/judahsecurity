"""In-product tools, HTTP transport, proof execution and publication gate together."""

import asyncio
import json

import httpx
import pytest

from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.evidence_store import (
    EvidenceStore,
    VerificationRun,
    verification_run,
    evidence_store,
)
from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.independent_verify import (
    submit_candidate,
    apply_verdict,
    check_verify_receipt,
)
from app.services.agent.prompts import is_tool_allowed_in_phase
from app.services.agent.assessment_scope import register_scope


@pytest.fixture
def manager(monkeypatch):
    original = httpx.AsyncClient
    state = {"objects": {}, "calls": [], "vulnerable": True}

    def handle(req):
        cookie = req.headers.get("cookie", "")
        identity = (
            "a" if "sid=a" in cookie else "b" if "sid=b" in cookie else "anonymous"
        )
        state["calls"].append((req.url.host, req.url.path, identity))
        if req.url.path == "/me":
            return httpx.Response(200, json={"principal": identity})
        if req.url.path == "/objects" and req.method == "POST":
            data = json.loads(req.content)
            obj = {"id": len(state["objects"]) + 1, "marker": data["marker"]}
            state["objects"][str(obj["id"])] = obj
            return httpx.Response(201, json=obj)
        if req.url.path.startswith("/objects/"):
            obj = state["objects"].get(req.url.path.rsplit("/", 1)[1])
            if obj is None:
                return httpx.Response(404, json={"error": "missing"})
            if req.method == "PATCH" and (identity == "a" or state["vulnerable"]):
                obj.update(json.loads(req.content))
            return httpx.Response(200, json=obj)
        return httpx.Response(200, json={"message": "ordinary public response"})

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(handle), **kw),
    )
    manager = ASMToolsManager()
    register_scope(manager, "app.test", "other.test")
    return manager, state


async def prepare(m):
    for name in ("a", "b"):
        await m.register_test_identity(
            name, "https://app.test", cookies=[dict(name="sid", value=name)]
        )
        result = json.loads(
            await m.check_test_identity(name, "https://app.test/me", "principal", name)
        )
        assert result["authenticated"]
    await m.map_application_traffic(
        [
            dict(
                url="https://app.test/objects/1",
                method="PATCH",
                body={"marker": "before"},
            )
        ]
    )
    op = next(
        o
        for o in m._engagement_brain["application_operations"]
        if o["method"] == "PATCH"
    )
    await m.generate_authorization_matrix(
        [dict(operation_id=op["id"], identity="b", expected="deny")],
        operation_ids=[op["id"]],
        identity_names=["b"],
    )
    cell = next(
        c for c in m._engagement_brain["authorization_matrix"] if not c["parameter"]
    )
    plan = dict(
        strategy="authorization_mutation",
        controlled_resource=True,
        target=op["url"],
        owner_identity="a",
        value_path="/marker",
        object_path="/id",
        setup=dict(
            url="https://app.test/objects", method="POST", body={"marker": "before"}
        ),
        attack=dict(
            url="https://app.test/objects/{{object_id}}",
            method="PATCH",
            body={"marker": "{{nonce}}"},
        ),
        verify=dict(url="https://app.test/objects/{{object_id}}", method="GET"),
    )
    return cell, plan


@pytest.mark.asyncio
async def test_real_transport_workflow_requires_fresh_independent_receipt(manager):
    m, state = manager
    cell, plan = await prepare(m)
    hunter = json.loads(await m.run_authorization_proof(cell["hypothesis_id"], plan))[
        "receipt"
    ]
    assert hunter["verdict"] == "confirmed"
    brain = engagement_brain_from_dict(m._engagement_brain)
    candidate = submit_candidate(
        brain,
        title="Unauthorized mutation",
        target=plan["target"],
        hypothesis_id=cell["hypothesis_id"],
    )
    m._engagement_brain = brain.to_dict()
    run = VerificationRun(
        "fresh-verifier", candidate.id, candidate.revision, candidate.nonce
    )
    token = verification_run.set(run)
    try:
        rejected = apply_verdict(
            m,
            candidate_id=candidate.id,
            verdict="confirmed",
            evidence="Owner marker changed",
            evidence_ids=hunter["evidence_ids"],
            proof={"kind": "workflow", "run_id": hunter["run_id"]},
        )
        assert rejected.status == "inconclusive"
        fresh = json.loads(await m.run_authorization_proof(cell["hypothesis_id"]))[
            "receipt"
        ]
        confirmed = apply_verdict(
            m,
            candidate_id=candidate.id,
            verdict="confirmed",
            evidence="Owner readback contains fresh mutation marker",
            evidence_ids=fresh["evidence_ids"],
            proof={"kind": "workflow", "run_id": fresh["run_id"]},
        )
        assert confirmed.status == "confirmed"
    finally:
        verification_run.reset(token)
    assert check_verify_receipt(
        m._verify_receipts,
        title=candidate.title,
        target=candidate.target,
        tools_manager=m,
    )[0]
    cov = json.loads(await m.get_assessment_coverage())
    assert cov["counts"] == {"tested": 1, "blocked": 1}
    # Raw model-supplied response-match proof cannot bypass matrix discipline.
    token = verification_run.set(run)
    try:
        rejected = apply_verdict(
            m,
            candidate_id=candidate.id,
            verdict="confirmed",
            evidence="response matches",
            evidence_ids=fresh["evidence_ids"],
            proof={
                "kind": "response_match",
                "artifact_id": fresh["evidence_ids"][0],
                "contains": "ordinary public response",
            },
        )
        assert rejected.status == "inconclusive"
    finally:
        verification_run.reset(token)
    assert not check_verify_receipt(
        m._verify_receipts,
        title=candidate.title,
        target=candidate.target,
        tools_manager=m,
    )[0]
    assert json.loads(await m.get_assessment_coverage())["counts"]["inconclusive"] == 1


@pytest.mark.asyncio
async def test_patched_response_200_is_not_confirmation(manager):
    m, state = manager
    cell, plan = await prepare(m)
    state["vulnerable"] = False
    result = json.loads(await m.run_authorization_proof(cell["hypothesis_id"], plan))
    assert result["receipt"]["verdict"] == "refuted"
    assert not m._verify_receipts


@pytest.mark.asyncio
async def test_same_named_identity_has_independent_host_sessions(manager):
    m, state = manager
    await m.register_test_identity(
        "a", "https://app.test", cookies=[dict(name="sid", value="a")]
    )
    await m.register_test_identity(
        "a", "https://other.test", cookies=[dict(name="sid", value="b")]
    )
    await asyncio.gather(
        m._http_exchange("GET", "https://app.test/me", identity="a"),
        m._http_exchange("GET", "https://other.test/me", identity="a"),
        m._http_exchange("GET", "https://app.test/me", identity="anonymous"),
    )
    assert ("app.test", "/me", "a") in state["calls"]
    assert ("other.test", "/me", "b") in state["calls"]
    assert ("app.test", "/me", "anonymous") in state["calls"]
    assert len(json.loads(await m.list_test_identities())) == 2


def test_immutable_artifacts_and_org_session_isolation():
    m = ASMToolsManager()
    org = current_organization_id.set(1)
    sess = current_session_id.set("first")
    try:
        proof, js = m._assessment_engines()
        store = evidence_store(m)
        value = {"response": {"body": "original"}}
        eid = store.record("http_exchange", value)
        value["response"]["body"] = "tampered"
        store.records[eid]["payload"]["response"]["body"] = "also tampered"
        assert store.records[eid]["payload"]["response"]["body"] == "original"
        with pytest.raises(TypeError):
            store.records[eid] = {}
        other = current_session_id.set("second")
        try:
            assert m._assessment_engines()[0] is not proof
            assert eid not in evidence_store(m).records
        finally:
            current_session_id.reset(other)
        assert m._assessment_engines()[0] is proof
    finally:
        current_session_id.reset(sess)
        current_organization_id.reset(org)


def test_js_secret_redacted_in_execution_artifact():
    store = EvidenceStore()
    secret = "ghp_" + "x" * 36
    eid = store.record(
        "http_exchange", {"response": {"body": 'const key="' + secret + '";'}}
    )
    assert secret not in json.dumps(store.records[eid])


def test_new_tools_are_registered_and_phase_allowed():
    m = ASMToolsManager()
    for name in (
        "map_application_traffic",
        "run_authorization_proof",
        "get_assessment_coverage",
        "collect_js_intelligence",
        "browse_as_identity",
    ):
        assert name in m.tools and is_tool_allowed_in_phase(name, "exploitation")
    assert not is_tool_allowed_in_phase("run_authorization_proof", "informational")


@pytest.mark.asyncio
async def test_parameter_cell_cannot_be_closed_by_testing_another_field(manager):
    m, state = manager
    cell, plan = await prepare(m)
    expectations = [
        dict(operation_id=cell["operation_id"], identity="b", expected="deny"),
        dict(
            operation_id=cell["operation_id"],
            identity="b",
            parameter="body:marker",
            expected="deny",
        ),
    ]
    # An unexecuted unknown policy can be supplied later without losing coverage.
    await m.generate_authorization_matrix(
        expectations, operation_ids=[cell["operation_id"]], identity_names=["b"]
    )
    brain = engagement_brain_from_dict(m._engagement_brain)
    param = next(r for r in brain.authorization_matrix if r["parameter"])
    plan["value_path"] = "/other"
    with pytest.raises(ValueError, match="parameter"):
        await m.run_authorization_proof(param["hypothesis_id"], plan)
    assert json.loads(await m.get_assessment_coverage())["counts"] == {"untested": 2}


@pytest.mark.asyncio
async def test_named_request_cannot_override_registered_api_header_or_host(manager):
    m, state = manager
    await m.register_test_identity(
        "a", "https://app.test", cookies={"sid": "a"}, headers={"X-Api-Key": "private"}
    )
    for headers in (
        {"x-api-key": "other"},
        {"Host": "other.test"},
        {"Cookie": "sid=b"},
    ):
        with pytest.raises(ValueError, match="credential overrides"):
            await m._http_exchange(
                "GET", "https://app.test/me", identity="a", headers=headers
            )
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_js_fetch_stream_limit_is_enforced(manager):
    m, state = manager
    with pytest.raises(ValueError, match="byte budget"):
        await m._http_exchange(
            "GET", "https://app.test/me", identity="anonymous", max_response_bytes=4
        )


@pytest.mark.asyncio
async def test_expectation_change_cannot_reuse_tested_proof_history(manager):
    m, _ = manager
    cell, plan = await prepare(m)
    await m.run_authorization_proof(cell["hypothesis_id"], plan)
    with pytest.raises(ValueError, match="Expectation changed"):
        await m.generate_authorization_matrix(
            [dict(operation_id=cell["operation_id"], identity="b", expected="allow")],
            operation_ids=[cell["operation_id"]],
            identity_names=["b"],
        )
