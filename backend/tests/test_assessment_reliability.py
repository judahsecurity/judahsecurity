"""Regression tests exercise production transport, proof gates, and scheduler code."""

import asyncio
import json
import time
from types import SimpleNamespace

import httpx
import pytest

from app.services.agent.assessment_sessions import cookie_jar, identity_registry
from app.services.agent.pilot_policy import PilotDenied, PilotPolicy, reset_pilot, set_pilot
from app.services.agent.evidence_store import (
    VerificationRun,
    evidence_store,
    verification_run,
)
from app.services.agent.engagement_brain import EngagementBrain, Hypothesis
from app.services.agent.independent_verify import (
    apply_verdict,
    check_verify_receipt,
    finding_publish_allowed,
    submit_candidate,
)
from app.services.agent.penetration_task_graph import (
    ExecutorSummary,
    PenetrationTaskGraph,
    TaskNode,
    apply_executor_summary,
)
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)


@pytest.fixture
def manager():
    org = current_organization_id.set(98765)
    session = current_session_id.set("assessment-reliability-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"a.test", "b.test", "app.test", "other.test"})
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


@pytest.fixture
def transport(monkeypatch):
    original = httpx.AsyncClient

    def install(handler):
        monkeypatch.setattr(
            httpx,
            "AsyncClient",
            lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
        )

    return install


def candidate(manager, title="Sensitive configuration exposure", hypothesis_id=""):
    brain = EngagementBrain()
    cand = submit_candidate(
        brain,
        title=title,
        target="https://app.test/config",
        hypothesis_id=hypothesis_id,
    )
    manager._engagement_brain = brain.to_dict()
    return cand


def check(manager, cand):
    return check_verify_receipt(
        manager._verify_receipts,
        title=cand.title,
        target=cand.target,
        tools_manager=manager,
    )[0]


@pytest.mark.asyncio
async def test_bounded_pilot_blocks_unmetered_and_out_of_scope_http(manager, transport, monkeypatch):
    policy = PilotPolicy(
        target="https://app.test:443", source_ip="203.0.113.25",
        organization_id=98765, session_id="assessment-reliability-test",
        expires_at_ms=int(time.time() * 1000) + 60_000,
    )
    requests = []
    sent = []

    async def acquire(self, url, method):
        self.check_request(url, method)
        requests.append((method, url))
        return len(requests)

    monkeypatch.setattr(PilotPolicy, "acquire", acquire)
    transport(lambda req: (sent.append(req), httpx.Response(200, text="ok"))[1])
    token = set_pilot(policy)
    try:
        await manager._http_exchange("GET", "https://app.test/", use_auth_session=False)
        assert requests == [("GET", "https://app.test/")]
        assert len(sent) == 1
        with pytest.raises(PilotDenied):
            await manager._http_exchange("POST", "https://app.test/", use_auth_session=False)
        await manager._http_exchange("GET", "https://app.test:8443/", use_auth_session=False)
        assert requests[-1] == ("GET", "https://app.test:8443/")
        with pytest.raises(ValueError):
            await manager._http_exchange("GET", "https://other.test/", use_auth_session=False)
        assert len(sent) == 2
        denied = await manager._execute_impl("execute_curl", {"args": "https://app.test/"})
        assert denied["error"] == "pilot_policy_denied"
    finally:
        reset_pilot(token)


@pytest.mark.asyncio
async def test_bounded_pilot_rejects_browser_write_action_before_tool_call(manager):
    policy = PilotPolicy(
        target="https://app.test:443", source_ip="203.0.113.25",
        organization_id=98765, session_id="pilot-browser-actions",
        expires_at_ms=int(time.time() * 1000) + 60_000,
    )
    token = set_pilot(policy)
    try:
        result = await manager._execute_impl("execute_browser", {
            "args": json.dumps({"actions": [
                {"action": "set_cookie", "name": "session", "value": "x"},
            ]}),
        })
        assert result["error"] == "pilot_policy_denied"
    finally:
        reset_pilot(token)


@pytest.mark.asyncio
async def test_bounded_pilot_browser_route_checks_each_request(monkeypatch):
    from app.services.agent.assessment_sessions import configure_browser_origin

    policy = PilotPolicy(
        target="https://app.test:443", source_ip="203.0.113.25",
        organization_id=98765, session_id="browser-pilot",
        expires_at_ms=int(time.time() * 1000) + 60_000,
    )
    seen = []

    async def acquire(self, url, method):
        self.check_request(url, method)
        seen.append((method, url))
        return len(seen)

    monkeypatch.setattr(PilotPolicy, "acquire", acquire)

    class Context:
        async def route(self, _pattern, callback):
            self.callback = callback

        async def route_web_socket(self, _pattern, callback):
            self.socket_callback = callback

    class Route:
        def __init__(self, method, url):
            self.request = SimpleNamespace(method=method, url=url)
            self.result = None

        async def continue_(self):
            self.result = "continued"

        async def abort(self):
            self.result = "aborted"

    context = Context()
    token = set_pilot(policy)
    try:
        await configure_browser_origin(context, policy.target)
        for method, url, expected in (
            ("GET", "https://app.test/shop", "continued"),
            ("POST", "https://app.test/cart", "aborted"),
            ("GET", "https://api.app.test/", "aborted"),
        ):
            route = Route(method, url)
            await context.callback(route)
            assert route.result == expected
        assert seen == [("GET", "https://app.test/shop")]
        socket = SimpleNamespace(url="wss://app.test/socket", close=lambda: seen.append("closed"))
        context.socket_callback(socket)
        assert seen[-1] == "closed"
    finally:
        reset_pilot(token)


def cookies_for(jar, url):
    request = httpx.Request("GET", url)
    jar.set_cookie_header(request)
    return request.headers.get("cookie", "")


def test_cookie_scope_path_secure_expiry_and_explicit_override():
    jar = cookie_jar(
        "https://a.test/",
        [
            {
                "name": "a",
                "value": "one",
                "domain": "a.test",
                "path": "/private",
                "secure": True,
            },
            {"name": "b", "value": "two", "domain": "b.test"},
            {
                "name": "old",
                "value": "expired",
                "domain": "a.test",
                "expires": time.time() - 5,
            },
        ],
        {"explicit": "yes"},
    )
    assert cookies_for(jar, "https://a.test/private/item") == "a=one; explicit=yes"
    assert cookies_for(jar, "https://a.test/public") == "explicit=yes"
    assert cookies_for(jar, "https://b.test/") == "b=two"
    assert cookies_for(jar, "https://sub.a.test/private") == ""
    assert "a=one" not in cookies_for(jar, "http://a.test/private")


@pytest.mark.asyncio
async def test_redirect_never_forwards_cookie_or_authorization_to_another_host(
    manager, transport
):
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.host == "a.test":
            return httpx.Response(302, headers={"location": "https://b.test/"})
        return httpx.Response(200, text="ok")

    transport(handler)
    await manager._http_exchange(
        "GET",
        "https://a.test/",
        headers={"Cookie": "private=one", "Authorization": "Bearer fake"},
    )
    assert "cookie" not in seen[1].headers
    assert "authorization" not in seen[1].headers


@pytest.mark.asyncio
async def test_explicit_cookies_work_without_legacy_session(manager, transport):
    transport(
        lambda req: httpx.Response(200, json={"cookie": req.headers.get("cookie")})
    )
    result = await manager._http_exchange(
        "GET", "https://a.test/", cookies={"test": "yes"}, use_auth_session=False
    )
    assert json.loads(result["_body_text"])["cookie"] == "test=yes"


@pytest.mark.asyncio
async def test_http_transport_verifies_tls_by_default(manager, monkeypatch):
    original = httpx.AsyncClient
    options = {}

    def client(**kwargs):
        options.update(kwargs)
        return original(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text="ok")),
            **kwargs,
        )

    monkeypatch.delenv("AEGIS_ALLOW_INSECURE_TLS", raising=False)
    monkeypatch.delenv("AEGIS_ASSESSMENT_CA_BUNDLE", raising=False)
    monkeypatch.setattr(httpx, "AsyncClient", client)
    await manager._http_exchange("GET", "https://a.test/")
    assert options["verify"] is True


@pytest.mark.asyncio
async def test_http_transport_blocks_unregistered_scope_before_network(manager, transport):
    called = False

    def handler(req):
        nonlocal called
        called = True
        return httpx.Response(200, text="should not run")

    transport(handler)
    with pytest.raises(ValueError, match="Out-of-scope"):
        await manager._http_exchange("GET", "https://unrelated.test/")
    assert not called


@pytest.mark.asyncio
async def test_identity_registration_cannot_expand_assessment_scope(manager):
    with pytest.raises(ValueError, match="Out-of-scope"):
        await manager.register_test_identity("foreign", "https://unrelated.test/")


def test_explicit_wildcard_scope_matches_subdomains_without_suffix_tricks(manager):
    from app.services.agent.assessment_scope import assert_url_in_scope

    manager._assessment_scope.add("*.example.test")
    assert assert_url_in_scope(manager, "https://api.example.test/") == "api.example.test"
    with pytest.raises(ValueError, match="Out-of-scope"):
        assert_url_in_scope(manager, "https://api.example.test.attacker.test/")


@pytest.mark.asyncio
async def test_confirmation_policy_failure_blocks_active_tool(manager, monkeypatch):
    import app.services.agent.confirmation_service as confirmation

    async def broken(*args, **kwargs):
        raise RuntimeError("policy database unavailable")

    monkeypatch.setattr(confirmation, "gate", broken)
    result = await manager._execute_impl(
        "record_surface_coverage", {"path": "/", "status": "tested_clean"}
    )
    assert result["error"] == "confirmation_policy_unavailable"


def test_prose_and_bypass_flags_cannot_publish(manager):
    cand = candidate(manager)
    assert (
        apply_verdict(
            manager,
            candidate_id=cand.id,
            verdict="confirmed",
            evidence="I reproduced it",
        )
        is None
    )
    assert not finding_publish_allowed(
        manager, title=cand.title, target=cand.target, severity="high", skip=True
    )[0]


@pytest.mark.asyncio
async def test_fresh_http_proof_confirms_then_refutation_revokes(manager, transport):
    transport(lambda req: httpx.Response(200, text="private diagnostic configuration"))
    cand = candidate(manager)
    token = verification_run.set(
        VerificationRun("verify-1", cand.id, cand.revision, cand.nonce)
    )
    try:
        response = await manager._http_exchange(
            "GET", cand.target, use_auth_session=False
        )
        eid = response["evidence_id"]
        verdict = apply_verdict(
            manager,
            candidate_id=cand.id,
            verdict="confirmed",
            evidence="Private diagnostic configuration was disclosed",
            evidence_ids=[eid],
            proof={
                "kind": "response_match",
                "artifact_id": eid,
                "contains": "private diagnostic configuration",
            },
        )
        assert verdict.status == "confirmed"
        assert check(manager, cand)
        apply_verdict(
            manager,
            candidate_id=cand.id,
            verdict="refuted",
            evidence="Independent control disproved it",
        )
        assert not check(manager, cand)
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,body",
    [(500, "private diagnostic configuration"), (404, "not found"), (200, "")],
)
async def test_errors_and_empty_success_do_not_confirm(
    manager, transport, status, body
):
    transport(lambda req: httpx.Response(status, text=body))
    cand = candidate(manager)
    token = verification_run.set(VerificationRun("verify-1", cand.id, 1, cand.nonce))
    try:
        result = await manager._http_exchange("GET", cand.target)
        eid = result["evidence_id"]
        verdict = apply_verdict(
            manager,
            candidate_id=cand.id,
            verdict="confirmed",
            evidence="claimed impact",
            evidence_ids=[eid],
            proof={"kind": "response_match", "artifact_id": eid, "contains": body},
        )
        assert verdict.status == "inconclusive"
        assert not check(manager, cand)
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_candidate_update_invalidates_verified_revision(manager, transport):
    transport(lambda req: httpx.Response(200, text="private diagnostic configuration"))
    cand = candidate(manager)
    token = verification_run.set(VerificationRun("verify-1", cand.id, 1, cand.nonce))
    try:
        result = await manager._http_exchange("GET", cand.target)
        eid = result["evidence_id"]
        apply_verdict(
            manager,
            candidate_id=cand.id,
            verdict="confirmed",
            evidence="Private config exposed",
            evidence_ids=[eid],
            proof={
                "kind": "response_match",
                "artifact_id": eid,
                "contains": "private diagnostic configuration",
            },
        )
        assert check(manager, cand)
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(manager._engagement_brain)
        updated = submit_candidate(
            brain, title=cand.title, target=cand.target, evidence="New claim"
        )
        manager._engagement_brain = brain.to_dict()
        assert updated.revision == 2
        assert not check(manager, cand)
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_foreign_run_and_target_evidence_rejected(manager, transport):
    transport(lambda req: httpx.Response(200, text="private diagnostic configuration"))
    cand = candidate(manager)
    token = verification_run.set(VerificationRun("other-run", cand.id, 1, cand.nonce))
    result = await manager._http_exchange("GET", "https://other.test/")
    verification_run.reset(token)
    ok, _ = evidence_store(manager).validate(
        [result["evidence_id"]],
        candidate_id=cand.id,
        revision=1,
        run_id="other-run",
        target=cand.target,
    )
    assert not ok
    ok, _ = evidence_store(manager).validate(
        [result["evidence_id"]],
        candidate_id=cand.id,
        revision=1,
        run_id="new-run",
        target="https://other.test/",
    )
    assert not ok


@pytest.mark.asyncio
@pytest.mark.parametrize("patched", [False, True])
async def test_two_user_authorization_replay_and_expiry(manager, transport, patched):
    def handler(req):
        user = req.headers.get("x-test-user")
        if req.url.path == "/me":
            return httpx.Response(200, json={"id": user})
        if patched and user == "B":
            return httpx.Response(403, json={"error": "denied"})
        return httpx.Response(200, json={"owner_id": "A", "record_id": "private-A"})

    transport(handler)
    for name in ("A", "B"):
        await manager.register_test_identity(
            name, "https://app.test/", headers={"x-test-user": name}
        )
        assert json.loads(
            await manager.check_test_identity(name, "https://app.test/me", "id", name)
        )["authenticated"]
    result = json.loads(
        await manager.test_authorization_boundary(
            "https://app.test/private-A", "A", "B", "owner_id", "h1"
        )
    )
    assert result["status"]["mutant"] == (403 if patched else 200)
    assert result["baseline"]["request"]["identity"] == "A"
    assert result["mutant"]["request"]["identity"] == "B"
    transport(lambda req: httpx.Response(401, json={"error": "session expired"}))
    result = json.loads(
        await manager.test_authorization_boundary(
            "https://app.test/private-A", "A", "B", "owner_id", "h1"
        )
    )
    assert result["verdict"] == "blocked"


def test_summary_does_not_close_unrelated_hypotheses():
    brain = EngagementBrain(
        hypotheses=[
            Hypothesis(
                id=i,
                title=i,
                assumption="",
                test="",
                pass_criteria="",
                kill_criteria="",
                specialist="api_authz",
            )
            for i in ("a", "b")
        ]
    )
    graph = PenetrationTaskGraph(
        nodes={
            i: TaskNode(id=i, title=i, specialist="api_authz", status="running")
            for i in ("a", "b")
        }
    )
    apply_executor_summary(
        graph,
        brain,
        ExecutorSummary(
            specialist="api_authz",
            verdict="killed",
            evidence="Checked A only",
            hypothesis_results=[
                {
                    "hypothesis_id": "a",
                    "verdict": "killed",
                    "evidence_ids": ["execution-A"],
                    "evidence": "A denied",
                }
            ],
        ),
    )
    assert graph.nodes["a"].status == "killed"
    assert graph.nodes["b"].status != "killed"


@pytest.mark.asyncio
async def test_parallel_sessions_do_not_share_identities_or_artifacts(manager):
    async def one(session):
        token = current_session_id.set(session)
        try:
            manager._assessment_scope.add("app.test")
            await manager.register_test_identity(
                "user", "https://app.test/", headers={"x-test-user": session}
            )
            manager._verify_receipts["test"] = session
            eid = evidence_store(manager).record("tool_output", {"message": session})
            await asyncio.sleep(0)
            assert (
                identity_registry(manager).identities["user"]["headers"]["x-test-user"]
                == session
            )
            assert manager._verify_receipts["test"] == session
            return eid, evidence_store(manager)
        finally:
            current_session_id.reset(token)

    (aid, astore), (bid, bstore) = await asyncio.gather(one("a"), one("b"))
    assert aid not in bstore.records and bid not in astore.records


@pytest.mark.asyncio
async def test_fireteam_dispatch_executes_only_its_leased_hypothesis(
    manager, monkeypatch
):
    from app.services.agent.fireteam_service import (
        FireteamResult,
        SpecialistReport,
        ToolInvocation,
    )

    brain = EngagementBrain(
        target="https://app.test",
        hypotheses=[
            Hypothesis(
                id=hypothesis_id,
                title=f"Authorization test {hypothesis_id}",
                assumption="Object access may cross users",
                test=f"Test object {hypothesis_id}",
                pass_criteria="Another user reads it",
                kill_criteria="Another user is denied",
                specialist="api_authz",
            )
            for hypothesis_id in ("authz-a", "authz-b")
        ],
    )
    manager._engagement_brain = brain.to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    checkpoints = []

    def record_checkpoint(_organization_id, _session_id, state):
        checkpoints.append(state)

    monkeypatch.setattr(
        "app.services.agent.run_snapshot.save_run_snapshot", record_checkpoint
    )

    async def fake_fireteam(*, mission, directives, **kwargs):
        from app.core.config import settings

        assert 0 < kwargs["member_timeout_sec"] < kwargs["wave_timeout_sec"]
        assert kwargs["wave_timeout_sec"] < settings.AGENT_TOOL_HARD_TIMEOUT_SECONDS
        directive = directives["api_authz"]
        assert len(directive.hypothesis_ids) == 1
        hypothesis_id = directive.hypothesis_ids[0]
        return FireteamResult(
            mission=mission,
            specialists_run=["api_authz"],
            reports=[
                SpecialistReport(
                    specialist="api_authz",
                    role="authorization",
                    mission=mission,
                    summary="The leased object was denied.",
                    verdict="killed",
                    hypothesis_ids=[hypothesis_id],
                    assigned_hypothesis_id=hypothesis_id,
                    lease_id=directive.lease_id,
                    hypothesis_results=[
                        {
                            "hypothesis_id": hypothesis_id,
                            "verdict": "killed",
                            "evidence_ids": ["http-denied"],
                            "evidence": "Attacker received a denial",
                        }
                    ],
                    tool_calls=[
                        ToolInvocation(
                            tool="compare_requests",
                            args={"hypothesis_id": hypothesis_id},
                            success=True,
                            summary="denied",
                            evidence_ids=["http-denied"],
                        )
                    ],
                )
            ],
        )

    monkeypatch.setattr(
        "app.services.agent.fireteam_service.run_fireteam", fake_fireteam
    )
    result = json.loads(
        await manager.fireteam_dispatch(
            mission="Test authorization cards",
            targets=["https://app.test"],
            specialists=["api_authz"],
        )
    )

    leased_id = result["task_leases"]["api_authz"]["hypothesis_id"]
    rows = manager._engagement_brain["task_graph"]["nodes"]
    sibling_id = ({"authz-a", "authz-b"} - {leased_id}).pop()
    assert rows[leased_id]["status"] == "killed"
    assert rows[leased_id]["evidence_ids"] == ["http-denied"]
    assert rows[sibling_id]["status"] == "ready"
    assert any(
        checkpoint["engagement_brain"]["task_graph"]["nodes"][leased_id]["lease_id"]
        for checkpoint in checkpoints
    )
    assert checkpoints[-1]["engagement_brain"]["task_graph"]["nodes"][leased_id]["lease_id"] == ""


@pytest.mark.asyncio
async def test_fireteam_dispatch_continues_parameter_cells_after_xss_hypothesis_is_killed(
    manager, monkeypatch
):
    from app.services.agent.capability_map import build_capability_map_from_dict
    from app.services.agent.engagement_brain import engagement_brain_from_dict
    from app.services.agent.fireteam_service import FireteamResult, SpecialistReport, ToolInvocation

    manager._capability_map = build_capability_map_from_dict({
        "target": "https://app.test/", "scope": "https://app.test",
        "forms": [{"method": "GET", "action": "/search", "inputs": ["q", "sort"]}],
        "pages_visited": ["https://app.test/search?q=one&sort=recent"],
    }).to_dict()
    synced = json.loads(await manager.sync_engagement_brain())
    assert synced["parameter_coverage"]["xss"]["total"] >= 2
    brain = engagement_brain_from_dict(manager._engagement_brain)
    assert any(c.get("specialist") == "xss" and c.get("source") == "parameter_inventory"
               for c in brain.coverage_cells)
    for hypothesis in brain.hypotheses:
        if hypothesis.specialist == "xss":
            hypothesis.status = "killed"
    brain.task_graph = {}
    manager._engagement_brain = brain.to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())

    async def fake_fireteam(*, mission, directives, **kwargs):
        directive = directives["xss"]
        assert directive.parameter_work["name"] in {"q", "sort"}
        assert directive.coverage_cell_id
        return FireteamResult(
            mission=mission, specialists_run=["xss"], reports=[SpecialistReport(
                specialist="xss", role="XSS", mission=mission,
                summary="Assigned input did not render the canary.", verdict="killed",
                tool_calls=[ToolInvocation(
                    tool="compare_requests", args={"coverage_cell_id": directive.coverage_cell_id},
                    success=True, summary="No reflection", evidence_ids=["http-clean"],
                )],
            )],
        )

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(mission="Cover XSS inputs", specialists=["xss"]))
    assert result["specialists_run"] == ["xss"]
    assert "xss" not in result["task_leases"]
    assert result["coverage_leases"]["xss"]["coverage_cell_id"]
    assert result["parameter_coverage"]["xss"]["remaining"] > 0
    rows = [c for c in manager._engagement_brain["coverage_cells"]
            if c.get("specialist") == "xss" and c.get("source") == "parameter_inventory"]
    assert any(c["status"] == "tested_clean" for c in rows)
    assert any(c["status"] == "untested" for c in rows)


@pytest.mark.asyncio
async def test_fireteam_dispatch_does_not_bypass_interrupted_lease(
    manager, monkeypatch
):
    hypothesis = Hypothesis(
        id="uncertain-action",
        title="Uncertain state change",
        assumption="A write may cross users",
        test="Attempt one bounded write",
        pass_criteria="Owner observes the write",
        kill_criteria="Attacker is denied",
        specialist="api_authz",
    )
    brain = EngagementBrain(target="https://app.test", hypotheses=[hypothesis])
    brain.task_graph = {
        "nodes": {
            hypothesis.id: TaskNode(
                id=hypothesis.id,
                title=hypothesis.title,
                specialist=hypothesis.specialist,
                status="running",
                lease_id="expired-lease",
                lease_owner="api_authz",
                lease_started_at=1,
                lease_deadline=2,
            ).to_dict()
        }
    }
    manager._engagement_brain = brain.to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    monkeypatch.setattr(
        "app.services.agent.run_snapshot.save_run_snapshot",
        lambda *_args, **_kwargs: None,
    )

    async def should_not_run(**_kwargs):
        raise AssertionError("interrupted hypothesis was dispatched without reconciliation")

    monkeypatch.setattr(
        "app.services.agent.fireteam_service.run_fireteam", should_not_run
    )
    result = json.loads(
        await manager.fireteam_dispatch(
            mission="Resume authorization testing",
            targets=["https://app.test"],
            specialists=["api_authz"],
        )
    )

    assert result["specialists_run"] == []
    assert result["selection_source"] == "no_ready_hypothesis"
    node = result["task_graph"]["blocked"][0]
    assert node["id"] == hypothesis.id
    assert node["recovery_required"] is True


@pytest.mark.asyncio
async def test_fireteam_verifies_candidate_on_hunter_completion(manager, monkeypatch):
    from app.services.agent.fireteam_service import FireteamResult, SpecialistReport
    from app.services.agent.independent_verify import FindingCandidate
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    hypothesis = Hypothesis(
        id="observed-xss", title="Observed input reflection", assumption="Input reflects",
        test="Use a bounded canary", pass_criteria="Browser execution",
        kill_criteria="No execution", specialist="xss",
    )
    manager._engagement_brain = EngagementBrain(
        target="https://app.test", hypotheses=[hypothesis],
    ).to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())
    monkeypatch.setattr("app.services.agent.run_snapshot.save_run_snapshot",
                        lambda *_args, **_kwargs: None)
    verifier_calls = []

    async def fake_verify(candidates, **_kwargs):
        verifier_calls.append([candidate.id for candidate in candidates])
        live = engagement_brain_from_dict(manager._engagement_brain)
        live.candidates[0]["status"] = "confirmed"
        live.candidates[0]["verified_at"] = "2026-10-07T00:00:00Z"
        live.hypotheses[0].status = "proven"
        manager._engagement_brain = live.to_dict()
        return [{"candidate_id": candidates[0].id, "status": "confirmed"}]

    async def fake_fireteam(*, mission, directives, report_callback, **_kwargs):
        lease = directives["xss"]
        live = engagement_brain_from_dict(manager._engagement_brain)
        live.candidates = [FindingCandidate(
            id="cand-xss", title="XSS candidate", target="https://app.test",
            hypothesis_id=hypothesis.id,
        ).to_dict()]
        manager._engagement_brain = live.to_dict()
        stale_hunter_state = live.to_dict()
        report = SpecialistReport(
            specialist="xss", role="XSS", mission=mission,
            summary="Candidate submitted", verdict="proven",
            hypothesis_ids=[hypothesis.id], assigned_hypothesis_id=hypothesis.id,
            lease_id=lease.lease_id,
        )
        await report_callback(report)
        assert verifier_calls == [["cand-xss"]]
        # A sibling hunter can finish with the brain it read before verification.
        manager._engagement_brain = stale_hunter_state
        return FireteamResult(mission=mission, specialists_run=["xss"], reports=[report])

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    monkeypatch.setattr("app.services.agent.independent_verify.run_independent_verifiers", fake_verify)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Test observed XSS input", targets=["https://app.test"], specialists=["xss"],
    ))
    assert result["verify_wave"] == [{"candidate_id": "cand-xss", "status": "confirmed"}]
    assert manager._engagement_brain["candidates"][0]["status"] == "confirmed"
    assert manager._engagement_brain["task_graph"]["nodes"][hypothesis.id]["status"] == "proven"


@pytest.mark.asyncio
async def test_workflow_resumes_and_cleans_up_after_prerequisite_failure(
    manager, transport
):
    seen = []

    def handler(req):
        seen.append((req.method, req.url.path))
        if req.url.path == "/create":
            return httpx.Response(201, json={"id": "canary-1"})
        if req.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(500)

    transport(handler)
    steps = [
        {
            "id": "create",
            "request": {
                "method": "POST",
                "url": "https://app.test/create",
                "identity": "anonymous",
            },
            "expect_status": [201],
            "extract": {"object": "id"},
        },
        {
            "id": "read",
            "request": {"url": "https://app.test/{{object}}", "identity": "anonymous"},
        },
        {
            "id": "dependent",
            "request": {"url": "https://app.test/never", "identity": "anonymous"},
        },
        {
            "id": "cleanup",
            "cleanup": True,
            "request": {
                "method": "DELETE",
                "url": "https://app.test/{{object}}",
                "identity": "anonymous",
            },
            "expect_status": [204],
        },
    ]
    first = json.loads(await manager.run_assessment_workflow(steps=steps, max_steps=1))
    assert not first["complete"]
    second = json.loads(
        await manager.run_assessment_workflow(workflow_id=first["workflow_id"])
    )
    assert second["complete"] and second["failed"]
    assert seen == [("POST", "/create"), ("GET", "/canary-1"), ("DELETE", "/canary-1")]
    assert second["results"]["dependent"]["status"] == "blocked"


@pytest.mark.asyncio
async def test_verifier_loop_requires_evidence_and_valid_proof(
    manager, transport, monkeypatch
):
    """Real specialist loop -> tool execution -> verifier -> publication gate."""
    from app.services.agent.independent_verify import run_independent_verifiers
    import app.services.agent.confirmation_service as confirmation
    import app.services.agent.palace_memory as palace

    async def auto(*args, **kwargs):
        return {"decision": "auto"}

    monkeypatch.setattr(confirmation, "gate", auto)
    monkeypatch.setattr(palace, "remember_tool_result", lambda *a, **kw: None)
    monkeypatch.setattr(palace, "store_specialist_diary", lambda *a, **kw: None)
    # Keep offline context assembly from opening model/vector-store connections.
    monkeypatch.setattr(manager, "_cheap_llm", lambda: None)
    transport(lambda req: httpx.Response(200, text="private diagnostic configuration"))
    cand = candidate(manager)

    class ScriptedVerifier:
        def __init__(self):
            self.calls = 0

        async def ainvoke(self, messages):
            self.calls += 1
            if self.calls == 1:
                payload = {
                    "tool_calls": [
                        {
                            "tool": "replay_http_request",
                            "args": {"url": cand.target, "identity": "anonymous"},
                        }
                    ]
                }
            elif self.calls == 2:
                rows = [
                    r
                    for r in evidence_store(manager).records.values()
                    if r["kind"] == "http_exchange"
                ]
                eid = rows[-1]["id"]
                payload = {
                    "tool_calls": [
                        {
                            "tool": "record_verify_verdict",
                            "args": {
                                "candidate_id": cand.id,
                                "verdict": "confirmed",
                                "evidence": "Private configuration exposed",
                                "evidence_ids": [eid],
                                "proof": {
                                    "kind": "response_match",
                                    "artifact_id": eid,
                                    "contains": "private diagnostic configuration",
                                },
                            },
                        }
                    ]
                }
            else:
                payload = {"done": True, "summary": "Recorded supported confirmation"}
            return SimpleNamespace(content=json.dumps(payload))

    llm = ScriptedVerifier()
    result = await run_independent_verifiers([cand], llm=llm, tools_manager=manager)
    assert result[0]["status"] == "confirmed"
    assert finding_publish_allowed(
        manager, title=cand.title, target=cand.target, severity="high"
    )[0]
    assert llm.calls == 3


@pytest.mark.asyncio
async def test_text_only_verifier_is_inconclusive(manager, monkeypatch):
    import app.services.agent.fireteam_service as fireteam
    from app.services.agent.independent_verify import run_independent_verifiers

    cand = candidate(manager)

    async def fabricated(*a, **kw):
        return fireteam.SpecialistReport(
            specialist="independent_verifier",
            role="verifier",
            mission="",
            summary="Confirmed and reproduced!",
            key_findings=["Exploitable"],
        )

    monkeypatch.setattr(fireteam, "_run_specialist", fabricated)
    result = await run_independent_verifiers([cand], llm=None, tools_manager=manager)
    assert result[0]["status"] == "inconclusive"
    assert not check(manager, cand)


def test_artifact_redacts_nested_json_credentials_and_keeps_late_evidence(manager):
    body = json.dumps(
        {
            "password": "do-not-store",
            "secret": "hidden",
            "padding": "x" * 8000,
            "owner_id": "A",
        }
    )
    eid = evidence_store(manager).record(
        "http_exchange",
        {
            "request": {"headers": {"Cookie": "session=hidden"}},
            "response": {"body": body},
        },
    )
    text = json.dumps(evidence_store(manager).records[eid])
    assert "do-not-store" not in text and "session=hidden" not in text
    assert "owner_id" in evidence_store(manager).read(eid, 7500)["content"]


@pytest.mark.asyncio
async def test_authorization_proof_requires_distinct_verified_owners(
    manager, transport
):
    from app.services.agent.proof_policy import validate_proof

    transport(lambda req: httpx.Response(200, json={"owner_id": "A"}))
    cand = candidate(manager, "IDOR on private test object")
    for name in ("A", "B"):
        await manager.register_test_identity(name, "https://app.test/")
        identity_registry(manager).identities[name].update(
            authenticated=True, identity_check={"expected": name}
        )
    token = verification_run.set(VerificationRun("v", cand.id, 1, cand.nonce))
    try:
        baseline = await manager._http_exchange("GET", cand.target, identity="A")
        mutant = await manager._http_exchange("GET", cand.target, identity="B")
        ids = [baseline["evidence_id"], mutant["evidence_id"]]
        proof = {
            "kind": "authorization",
            "baseline_id": ids[0],
            "mutant_id": ids[1],
            "field": "owner_id",
        }
        assert validate_proof(evidence_store(manager), cand, proof, ids)[0]
        proof["field"] = "nonexistent"
        assert not validate_proof(evidence_store(manager), cand, proof, ids)[0]
    finally:
        verification_run.reset(token)


def test_browser_reflection_does_not_satisfy_xss_proof(manager):
    from app.services.agent.proof_policy import validate_proof

    cand = candidate(manager, "Reflected XSS")
    eid = evidence_store(manager).record(
        "browser_xss",
        {"dialog_triggered": False, "reflected_in_source": True},
        target=cand.target,
    )
    assert not validate_proof(
        evidence_store(manager),
        cand,
        {"kind": "browser_xss", "artifact_id": eid},
        [eid],
    )[0]
    eid = evidence_store(manager).record(
        "browser_xss",
        {"dialog_triggered": True, "alert_text": "aegis-verify-" + cand.nonce},
        target=cand.target,
    )
    assert validate_proof(
        evidence_store(manager),
        cand,
        {"kind": "browser_xss", "artifact_id": eid},
        [eid],
    )[0]


@pytest.mark.asyncio
async def test_state_change_rejects_authorized_self_write_and_requires_cleanup(
    manager, transport
):
    from app.services.agent.proof_policy import validate_proof

    canary = ""

    def handler(req):
        nonlocal canary
        if req.method in ("PUT", "PATCH"):
            canary = json.loads(req.content)["display_name"]
            return httpx.Response(200, json={"display_name": canary})
        if req.method == "DELETE":
            canary = ""
            return httpx.Response(204)
        return httpx.Response(200, json={"display_name": canary})

    transport(handler)
    cand = candidate(manager, "Profile display-name update")
    await manager.register_test_identity("A", "https://app.test/")
    identity_registry(manager).identities["A"].update(
        authenticated=True, identity_check={"expected": "A"}
    )
    token = verification_run.set(VerificationRun("v", cand.id, 1, cand.nonce))
    try:
        value = "aegis-verify-" + cand.nonce
        write = await manager._http_exchange(
            "PATCH", cand.target, identity="A", body={"display_name": value}
        )
        read = await manager._http_exchange("GET", cand.target, identity="A")
        cleanup = await manager._http_exchange("DELETE", cand.target, identity="A")
        ids = [write["evidence_id"], read["evidence_id"], cleanup["evidence_id"]]
        proof = {
            "kind": "state_change",
            "write_id": ids[0],
            "read_id": ids[1],
            "cleanup_id": ids[2],
            "field": "display_name",
            "value": value,
            "owner_identity": "A",
        }
        assert not validate_proof(evidence_store(manager), cand, proof, ids)[0]
        proof.pop("cleanup_id")
        assert not validate_proof(evidence_store(manager), cand, proof, ids)[0]
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_anonymous_state_change_with_readback_and_cleanup_can_confirm(
    manager, transport
):
    from app.services.agent.proof_policy import validate_proof

    value = ""

    def handler(req):
        nonlocal value
        if req.method == "PUT":
            value = json.loads(req.content)["canary"]
            return httpx.Response(200, json={"canary": value})
        if req.method == "DELETE":
            value = ""
            return httpx.Response(204)
        return httpx.Response(200, json={"canary": value})

    transport(handler)
    cand = candidate(manager, "Unauthenticated public settings write")
    token = verification_run.set(VerificationRun("v", cand.id, 1, cand.nonce))
    try:
        canary = "aegis-verify-" + cand.nonce
        write = await manager._http_exchange(
            "PUT", cand.target, identity="anonymous", body={"canary": canary}
        )
        read = await manager._http_exchange("GET", cand.target, identity="anonymous")
        cleanup = await manager._http_exchange("DELETE", cand.target, identity="anonymous")
        ids = [write["evidence_id"], read["evidence_id"], cleanup["evidence_id"]]
        assert validate_proof(
            evidence_store(manager),
            cand,
            {
                "kind": "state_change",
                "write_id": ids[0],
                "read_id": ids[1],
                "cleanup_id": ids[2],
                "field": "canary",
                "value": canary,
            },
            ids,
        )[0]
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_clean_coverage_requires_dimensioned_execution_evidence(manager):
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    manager._engagement_brain = EngagementBrain(
        target="https://app.test", surfaces=[{
            "method": "GET", "path": "/search", "host": "app.test", "takes_input": True
        }]
    ).to_dict()
    rejected = json.loads(await manager.record_surface_coverage(
        path="/search", host="app.test", status="tested_clean", reason="no reflection"
    ))
    assert "test_type" in rejected["error"]
    eid = evidence_store(manager).record(
        "http_exchange",
        {"request": {"method": "GET", "url": "https://app.test/search"},
         "response": {"status": 200, "body": "clean"}},
        target="https://app.test/search",
        identity="anonymous",
    )
    accepted = json.loads(await manager.record_surface_coverage(
        path="/search", host="app.test", status="tested_clean", reason="encoded canary",
        identity="anonymous", test_type="reflected_xss", parameter="q", evidence_id=eid,
    ))
    assert accepted["coverage"]["verified_checks"] == 1
    row = engagement_brain_from_dict(manager._engagement_brain).coverage[0]
    assert row["checks"][0]["test_type"] == "reflected_xss"


@pytest.mark.asyncio
async def test_oob_proof_requires_fresh_registration_plant_and_matching_callback(
    manager, transport
):
    cand = candidate(manager, "Blind SSRF")
    token = verification_run.set(VerificationRun("oob-run", cand.id, 1, cand.nonce))
    transport(lambda req: httpx.Response(202))
    try:
        store = evidence_store(manager)
        reg = store.record(
            "oob_register",
            {"session_id": "s", "payload_domain": "unique.oast.test", "reused": False},
        )
        plant = await manager._http_exchange(
            "POST", cand.target, body={"url": "https://unique.oast.test"}
        )
        poll = store.record(
            "oob_poll",
            {
                "session_id": "s",
                "interactions": [{"protocol": "http", "unique_id": "unique.oast.test"}],
            },
        )
        verdict = apply_verdict(
            manager,
            candidate_id=cand.id,
            verdict="confirmed",
            evidence="Planted URL produced matching HTTP callback",
            evidence_ids=[reg, plant["evidence_id"], poll],
            proof={
                "kind": "oob_callback",
                "register_id": reg,
                "plant_id": plant["evidence_id"],
                "poll_id": poll,
            },
        )
        assert verdict.status == "confirmed"
        assert check(manager, cand)
    finally:
        verification_run.reset(token)


@pytest.mark.asyncio
async def test_named_crawl_preserves_separate_capture_and_does_not_replace_legacy(
    manager, monkeypatch
):
    import app.services.agent.confirmation_service as confirmation

    async def auto(*args, **kwargs):
        return {"decision": "auto"}

    monkeypatch.setattr(confirmation, "gate", auto)
    seen = []

    async def call_tool(name, args):
        spec = json.loads(args["args"])
        seen.append(spec)
        return {
            "success": True,
            "output": "Crawled",
            "capability_map": {
                "target": spec["url"],
                "api_samples": [{"url": spec["url"] + "/private"}],
            },
            "auth_session": {
                "cookies": spec["cookies"],
                "storage_state": spec["storage_state"],
            },
        }

    manager._mcp_server = SimpleNamespace(call_tool=call_tool)
    manager._auth_session = {"target": "https://legacy.test/", "cookies": []}
    await manager.register_test_identity(
        "A",
        "https://app.test",
        cookies=[{"name": "session", "value": "test-A", "domain": "app.test"}],
    )
    result = await manager._execute_impl(
        "execute_deep_crawl",
        {"args": json.dumps({"url": "https://app.test", "identity": "A"})},
    )
    assert result["success"]
    assert seen[0]["cookies"][0]["value"] == "test-A"
    assert "auth_session" not in result
    assert manager._auth_session["target"] == "https://legacy.test/"
    assert manager._identity_captures["A"]["target"] == "https://app.test"


def test_oversized_evidence_is_bounded_and_cannot_confirm(manager):
    store = evidence_store(manager)
    token = verification_run.set(VerificationRun("v", "candidate", 1, "nonce"))
    try:
        eid = store.record(
            "http_exchange",
            {"response": {"status": 200, "body": "a" * 3_000_000}},
            target="https://app.test/",
        )
        assert store.records[eid]["truncated"]
        assert store.total_bytes < 2_000_000
        assert not store.validate(
            [eid],
            candidate_id="candidate",
            revision=1,
            run_id="v",
            target="https://app.test/",
        )[0]
    finally:
        verification_run.reset(token)


def test_evidence_eviction_removes_persisted_artifact(manager, tmp_path, monkeypatch):
    from app.services.agent.evidence_store import EvidenceStore

    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    store = EvidenceStore(max_records=1)
    first = store.record("tool_output", {"message": "first"})
    first_path = tmp_path / store.id / f"{first}.json"
    assert first_path.exists()
    second = store.record("tool_output", {"message": "second"})
    assert not first_path.exists()
    assert (tmp_path / store.id / f"{second}.json").exists()
    store.clear()
    assert not (tmp_path / store.id).exists()


def test_evidence_rehydrates_within_same_session_namespace(tmp_path, monkeypatch):
    from app.services.agent.evidence_store import EvidenceStore

    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    namespace = "assessment_session_123"
    first = EvidenceStore(namespace=namespace)
    token = verification_run.set(VerificationRun("run-1", "candidate-1", 2, "nonce"))
    try:
        artifact_id = first.record(
            "oob_poll",
            {"interactions": [{"protocol": "dns"}]},
            target="https://app.test/fetch?token=secret-token",
            success=True,
        )
    finally:
        verification_run.reset(token)

    persisted_path = tmp_path / namespace / f"{artifact_id}.json"
    assert "secret-token" not in persisted_path.read_text()

    restarted = EvidenceStore(namespace=namespace)
    assert restarted.records[artifact_id]["payload"]["interactions"][0]["protocol"] == "dns"
    assert restarted.read(artifact_id)["run_id"] == "run-1"
    assert not restarted.validate(
        [artifact_id], candidate_id="candidate-1", revision=2,
        run_id="run-1", target="https://app.test/fetch",
    )[0]


def test_evidence_rejects_tampered_persisted_artifact(tmp_path, monkeypatch):
    from app.services.agent.evidence_store import EvidenceStore

    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    namespace = "assessment_session_456"
    store = EvidenceStore(namespace=namespace)
    artifact_id = store.record("oob_poll", {"interactions": []})
    path = tmp_path / namespace / f"{artifact_id}.json"
    persisted = json.loads(path.read_text())
    persisted["payload"]["interactions"] = [{"protocol": "dns"}]
    path.write_text(json.dumps(persisted))

    restarted = EvidenceStore(namespace=namespace)
    assert artifact_id not in restarted.records


def test_inactive_session_evidence_expires_on_cleanup(tmp_path, monkeypatch):
    from app.services.agent.evidence_store import prune_expired_evidence

    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    old_dir = tmp_path / "old-session"
    old_dir.mkdir()
    old_file = old_dir / "artifact.json"
    old_file.write_text("{}")
    stale = time.time() - 90000
    import os

    os.utime(old_file, (stale, stale))
    assert prune_expired_evidence() == 1
    assert not old_file.exists()


def test_session_runtime_is_lru_bounded(manager):
    from app.services.agent.session_runtime import MAX_MANAGER_SESSIONS

    for index in range(MAX_MANAGER_SESSIONS + 3):
        token = current_session_id.set(f"bounded-{index}")
        try:
            manager._verify_receipts["index"] = index
        finally:
            current_session_id.reset(token)
    assert len(manager.__dict__["_session_runtime"]) <= MAX_MANAGER_SESSIONS


def test_tester_prompt_formats_web_progress_without_undefined_state():
    from app.services.agent.tester_loop import format_tester_loop_for_prompt

    text = format_tester_loop_for_prompt(
        {"is_web": True, "summary": "Mapped application", "missing": []}
    )
    assert "Mapped application" in text
