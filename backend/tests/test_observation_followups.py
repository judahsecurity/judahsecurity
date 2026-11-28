"""Observation -> proposal -> claim -> result, with one work item per fact."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    lead_packet_for_cell,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import (
    EngagementBrain,
    engagement_brain_from_dict,
)
from app.services.agent.observation_followups import (
    FOLLOWUP_SOURCE,
    FollowupPlanner,
    FollowupPolicy,
    apply_proposals,
    capture_facts,
    chain_report,
    claim_followup,
    commit_observation,
    complete_followup,
    fact_packet,
    record_first_request,
    release_held_proposals,
    validate_proposal,
)

T0 = 1_800_000_000.0


class FakeLLM:
    def __init__(self, content):
        self.content = content
        self.calls = 0
        self.messages = []

    async def ainvoke(self, messages):
        self.calls += 1
        self.messages.append(messages)
        return SimpleNamespace(content=self.content)


def _policy(*identities, run_id="run-1"):
    return FollowupPolicy(
        run_id=run_id, scope_hosts=frozenset({"app.test"}),
        approved_identities=frozenset(identities or {"anonymous"}),
    )


def _capture(brain, evidence="cap-1", url="https://app.test/orders?order_id=123",
             identity="user-a", planner=None, at=T0):
    return commit_observation(
        brain, run_id="run-1", kind="capture", evidence_ids=[evidence],
        identity=identity, facts=capture_facts("GET", url), observed_at=at,
        on_commit=planner.notify if planner else None,
    )


def _target(**overrides):
    return {"method": "GET", "host": "app.test", "path": "/orders",
            "parameter": "query:order_id", **overrides}


SQLI = {"target": _target(), "test_class": "sqli",
        "reason": "Numeric order reference reaches a lookup",
        "prerequisites": {}, "evidence_ids": ["cap-1"]}
AUTHZ = {"target": _target(), "test_class": "authz",
         "reason": "Order reference may not be owner-checked",
         "prerequisites": {"identities": ["user-b"]}, "evidence_ids": ["cap-1"]}


def _cells(brain, test_type, path="/orders"):
    return [c for c in brain.coverage_cells
            if c["test_type"] == test_type and c["path"] == path]


@pytest.mark.asyncio
async def test_captured_order_request_creates_each_followup_once():
    brain = EngagementBrain(target="https://app.test")
    policy = _policy("user-a", "user-b")
    llm = FakeLLM(json.dumps({"proposals": [
        {**AUTHZ, "prerequisites": {"identities": ["user-c"]}},          # unapproved
        SQLI, AUTHZ,                                                       # replaces the held one
        {**SQLI, "test_class": "ssrf"},                                    # not applicable
        {**SQLI, "target": _target(path="/admin")},                       # not observed
        {**SQLI, "target": _target(host="evil.test")},                    # not observed
        {**SQLI, "evidence_ids": ["cap-invented"]},                       # unknown evidence
        {**SQLI, "reason": "Repeated in the same reply"},                 # duplicate
    ]}))
    planner = FollowupPlanner(lambda: llm)

    event, created = _capture(brain, planner=planner)
    assert created and event["status"] == "committed"
    assert event["facts"]["parameters"] == [{"location": "query", "name": "order_id"}]
    assert {"run_id", "evidence_ids", "identity", "scope", "observed_at"} <= set(event)
    assert await planner.wait(timeout=0.1)

    summary = await planner.drain(brain, policy)
    assert llm.calls == 1
    assert summary["accepted"] == 2
    assert summary["duplicate"] >= 1
    sent = llm.messages[0][1].content
    assert "order_id" in sent and "123" not in sent

    [sqli] = _cells(brain, "sqli")
    [authz] = _cells(brain, "authz")
    assert sqli["source"] == authz["source"] == FOLLOWUP_SOURCE
    assert sqli["identity"] == authz["identity"] == "user-a"
    assert authz["followup"]["required_identities"] == ["user-a", "user-b"]
    assert sqli["evidence_ids"] == ["cap-1"]
    assert not _cells(brain, "ssrf") and not _cells(brain, "sqli", "/admin")
    reasons = {p["reason"] for p in brain.followup_proposals if p["status"] == "rejected"}
    assert {"class_not_applicable", "target_not_observed", "evidence_not_on_event"} <= reasons
    # The unapproved replay identity never reaches the work item.
    assert not any(p["status"] == "held" for p in brain.followup_proposals)
    assert "user-c" not in json.dumps(authz)

    # The same request captured again: evidence joins the event, no new planning.
    again, created = _capture(brain, evidence="cap-2", planner=planner, at=T0 + 5)
    assert not created and again is event and again["seen_count"] == 2
    assert again["evidence_ids"] == ["cap-1", "cap-2"]
    _capture(brain, evidence="cap-3", url="https://app.test/orders?order_id=124", at=T0 + 6)
    assert (await planner.drain(brain, policy))["planned"] == 0
    assert llm.calls == 1
    assert len(_cells(brain, "sqli")) == len(_cells(brain, "authz")) == 1

    # Claims are exclusive and never repeat a work item.
    lease = claim_followup(brain, "sqli", policy, now=T0 + 10)
    assert lease and lease.coverage_cell_id == sqli["id"]
    assert claim_followup(brain, "sqli", policy, now=T0 + 11) is None
    assert claim_coverage_cell_leases(brain, ["sqli"], now=T0 + 11) == {}
    authz_lease = claim_followup(brain, "auth_logic", policy, now=T0 + 12)
    assert authz_lease.coverage_cell_id == authz["id"]
    assert lead_packet_for_cell(authz)["followup"]["required_identities"] == ["user-a", "user-b"]

    record_first_request(brain, lease, now=T0 + 13)
    result = complete_followup(brain, lease, run_id="run-1", verdict="inconclusive",
                               evidence_ids=["probe-1"], now=T0 + 20, on_commit=planner.notify)
    assert result["kind"] == "worker_result" and result["status"] == "committed"
    assert result["facts"]["lease_id"] == lease.id
    assert result["evidence_ids"] == ["probe-1"]
    assert claim_followup(brain, "sqli", policy, now=T0 + 21) is not None  # retry is a new claim

    [first] = [row for row in chain_report(brain) if row["lease_id"] == lease.id]
    assert first["claim_to_first_request_ms"] == 3000
    assert first["first_request_to_verdict_ms"] == 7000
    assert first["observation_to_verdict_ms"] is not None
    assert first["waiting"]["model_ms"] is not None


@pytest.mark.asyncio
async def test_followup_can_combine_two_recorded_observations_without_inventing_evidence():
    brain = EngagementBrain(target="https://app.test")
    earlier, _ = _capture(brain, evidence="cap-profile",
                          url="https://app.test/profile?user_id=7", at=T0)
    current, _ = _capture(brain, evidence="cap-order", at=T0 + 1)
    proposal = {**AUTHZ, "evidence_ids": ["cap-order", "cap-profile"],
                "supporting_event_ids": [earlier["id"]]}
    llm = FakeLLM(json.dumps({"proposals": [proposal]}))
    planner = FollowupPlanner(lambda: llm)
    policy = _policy("user-a", "user-b")

    summary = await planner.drain(brain, policy)
    assert summary["accepted"] == 1
    assert earlier["id"] in llm.messages[1][1].content
    [cell] = _cells(brain, "authz")
    assert set(cell["evidence_ids"]) == {"cap-order", "cap-profile"}
    assert set(cell["followup"]["event_ids"]) == {earlier["id"], current["id"]}
    assert claim_followup(brain, "auth_logic", policy) is not None

    invented = {**proposal, "supporting_event_ids": ["obs-invented"]}
    assert validate_proposal(brain, current, invented, policy).reason == "supporting_event_not_observed"
    uncited = {**proposal, "evidence_ids": ["cap-order"]}
    assert validate_proposal(brain, current, uncited, policy).reason == "evidence_not_on_event"


def test_new_clue_can_reopen_an_earlier_observed_target():
    brain = EngagementBrain(target="https://app.test")
    earlier, _ = _capture(brain, evidence="cap-order", at=T0)
    current, _ = _capture(brain, evidence="cap-profile",
                          url="https://app.test/profile?user_id=7", at=T0 + 1)
    policy = _policy("user-a", "user-b")
    proposal = {**AUTHZ, "target_event_id": earlier["id"],
                "supporting_event_ids": [earlier["id"]],
                "evidence_ids": ["cap-order", "cap-profile"]}

    assert apply_proposals(brain, current, [proposal], policy)["accepted"] == 1
    [cell] = _cells(brain, "authz")
    assert cell["path"] == "/orders" and cell["capture_id"] == "cap-order"
    assert set(cell["followup"]["event_ids"]) == {earlier["id"], current["id"]}
    assert validate_proposal(brain, current,
                             {**proposal, "supporting_event_ids": []}, policy).reason == "target_event_not_cited"


def test_context_excludes_other_runs_and_out_of_scope_observations():
    brain = EngagementBrain(target="https://app.test")
    other_run, _ = commit_observation(
        brain, run_id="run-2", kind="capture", evidence_ids=["other-run"],
        identity="user-a", facts=capture_facts("GET", "https://app.test/other?key=secret"),
        observed_at=T0,
    )
    out_of_scope, _ = commit_observation(
        brain, run_id="run-1", kind="capture", evidence_ids=["other-host"],
        identity="user-a", facts=capture_facts("GET", "https://evil.test/other?key=secret"),
        observed_at=T0 + 1,
    )
    current, _ = _capture(brain, at=T0 + 2)
    policy = _policy("user-a", "user-b")

    packet = fact_packet(brain, current, policy)
    assert packet["context_events"] == []
    assert "secret" not in json.dumps(packet)
    for prior in (other_run, out_of_scope):
        proposal = {**AUTHZ, "supporting_event_ids": [prior["id"]],
                    "evidence_ids": ["cap-1", prior["evidence_ids"][0]]}
        assert validate_proposal(brain, current, proposal, policy).reason == "supporting_event_not_observed"


@pytest.mark.asyncio
async def test_authz_waits_for_an_approved_second_identity():
    brain = EngagementBrain(target="https://app.test")
    llm = FakeLLM(json.dumps({"proposals": [
        AUTHZ, {**AUTHZ, "prerequisites": {"identities": []}}, SQLI,
    ]}))
    planner = FollowupPlanner(lambda: llm)
    _capture(brain)
    summary = await planner.drain(brain, _policy("user-a"))
    assert summary["held"] == 1 and summary["accepted"] == 1
    assert any(p["reason"] == "authz_requires_second_identity" for p in brain.followup_proposals)
    assert not _cells(brain, "authz")
    assert claim_followup(brain, "auth_logic", _policy("user-a")) is None

    approved = _policy("user-a", "user-b")
    assert release_held_proposals(brain, approved, now=T0 + 60) == 1
    [authz] = _cells(brain, "authz")
    record = next(p for p in brain.followup_proposals if p["cell_id"] == authz["id"])
    assert record["status"] == "accepted" and record["approval_wait_ms"] is not None
    assert release_held_proposals(brain, approved) == 0

    # Withdrawing approval after acceptance blocks the claim.
    assert claim_followup(brain, "auth_logic", _policy("user-a")) is None
    assert claim_followup(brain, "auth_logic", approved).coverage_cell_id == authz["id"]


@pytest.mark.asyncio
async def test_followup_links_to_work_seeded_by_the_inventory_lane():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.test", "path": "/orders", "name": "order_id",
        "location": "query", "identity": "user-a", "source": "browser_traffic",
        "artifact_id": "cap-1", "testable": True,
    }])
    [seeded] = _cells(brain, "sqli")
    planner = FollowupPlanner(lambda: FakeLLM(json.dumps({"proposals": [SQLI]})))
    _capture(brain)
    assert (await planner.drain(brain, _policy("user-a")))["merged"] == 1
    [sqli] = _cells(brain, "sqli")
    assert sqli["id"] == seeded["id"] and sqli["source"] == "parameter_inventory"
    lease = claim_followup(brain, "sqli", _policy("user-a"))
    assert lease.coverage_cell_id == seeded["id"]
    assert "sqli" not in claim_coverage_cell_leases(
        brain, ["sqli"], allowed_cell_ids=frozenset({seeded["id"]}))


@pytest.mark.asyncio
async def test_concurrent_claims_lease_one_work_item_once():
    brain = EngagementBrain(target="https://app.test")
    _capture(brain)
    await FollowupPlanner(lambda: FakeLLM(json.dumps({"proposals": [SQLI]}))).drain(
        brain, _policy("user-a"))

    async def claim():
        await asyncio.sleep(0)
        return claim_followup(brain, "sqli", _policy("user-a"))

    leases = [lease for lease in await asyncio.gather(*[claim() for _ in range(5)]) if lease]
    assert len(leases) == 1


@pytest.mark.asyncio
async def test_dependent_followup_waits_for_its_prerequisite_verdict():
    brain = EngagementBrain(target="https://app.test")
    dependent = {**AUTHZ, "prerequisites": {"identities": ["user-b"], "depends_on": ["sqli"]}}
    llm = FakeLLM(json.dumps({"proposals": [SQLI, dependent]}))
    _capture(brain)
    policy = _policy("user-a", "user-b")
    assert (await FollowupPlanner(lambda: llm).drain(brain, policy))["accepted"] == 2
    assert claim_followup(brain, "auth_logic", policy) is None
    lease = claim_followup(brain, "sqli", policy)
    assert claim_followup(brain, "auth_logic", policy) is None
    complete_followup(brain, lease, run_id="run-1", verdict="killed", evidence_ids=["probe-1"])
    assert claim_followup(brain, "auth_logic", policy) is not None


@pytest.mark.asyncio
async def test_model_failure_keeps_event_for_retry_then_stops():
    brain = EngagementBrain(target="https://app.test")

    class Broken(FakeLLM):
        async def ainvoke(self, messages):
            self.calls += 1
            return SimpleNamespace(content="not json")

    llm = Broken("")
    planner = FollowupPlanner(lambda: llm)
    event, _ = _capture(brain)
    for _ in range(3):
        assert (await planner.drain(brain, _policy("user-a")))["unavailable"] == 1
    assert event["status"] == "unplanned" and event["planning_error"] == "ValueError"
    assert (await planner.drain(brain, _policy("user-a")))["unavailable"] == 0
    assert llm.calls == 3 and not brain.coverage_cells


@pytest.mark.asyncio
async def test_planner_assigns_against_live_state_after_model_returns():
    brain = EngagementBrain(target="https://app.test")
    gate = asyncio.Event()

    class Slow(FakeLLM):
        async def ainvoke(self, messages):
            await gate.wait()
            return SimpleNamespace(content=json.dumps({"proposals": [SQLI]}))

    _capture(brain)
    planner = FollowupPlanner(lambda: Slow(""))
    task = asyncio.create_task(planner.drain(brain, _policy("user-a")))
    await asyncio.sleep(0.05)
    # The inventory lane seeds the same work while the model is thinking.
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.test", "path": "/orders", "name": "order_id",
        "location": "query", "identity": "user-a", "source": "browser_traffic",
        "artifact_id": "cap-1", "testable": True,
    }])
    gate.set()
    assert (await task)["merged"] == 1
    assert len(_cells(brain, "sqli")) == 1


def test_results_must_cite_the_live_lease_and_evidence():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.test", "path": "/orders", "name": "order_id",
        "location": "query", "identity": "user-a", "source": "browser_traffic",
        "artifact_id": "cap-1", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    with pytest.raises(ValueError, match="evidence"):
        complete_followup(brain, lease, run_id="run-1", verdict="killed", evidence_ids=[])
    stale = type(lease)(**{**lease.to_dict(), "id": "someone-else"})
    with pytest.raises(ValueError, match="lease"):
        complete_followup(brain, stale, run_id="run-1", verdict="killed", evidence_ids=["e-1"])
    complete_followup(brain, lease, run_id="run-1", verdict="killed", evidence_ids=["e-1"])
    with pytest.raises(ValueError, match="lease"):
        complete_followup(brain, lease, run_id="run-1", verdict="killed", evidence_ids=["e-2"])


def test_event_validation_and_snapshot_round_trip():
    brain = EngagementBrain(target="https://app.test")
    with pytest.raises(ValueError):
        commit_observation(brain, run_id="", kind="capture", evidence_ids=["e"],
                           identity="anonymous", facts=capture_facts("GET", "https://app.test/"))
    with pytest.raises(ValueError, match="query values"):
        commit_observation(brain, run_id="r", kind="capture", evidence_ids=["e"],
                           identity="anonymous", facts={"host": "app.test", "path": "/o?id=1"})
    with pytest.raises(ValueError, match="secret"):
        commit_observation(brain, run_id="r", kind="credential", evidence_ids=["e"],
                           identity="anonymous",
                           facts={"host": "app.test", "credential_identity": "admin",
                                  "password": "hunter2"})
    commit_observation(brain, run_id="r", kind="credential", evidence_ids=["e"],
                       identity="anonymous",
                       facts={"host": "app.test", "credential_identity": "admin"})
    _capture(brain)
    restored = engagement_brain_from_dict(json.loads(json.dumps(brain.to_dict())))
    assert [e["id"] for e in restored.observation_events] == [e["id"] for e in brain.observation_events]
    _, created = _capture(restored, evidence="cap-9")
    assert not created


@pytest.mark.asyncio
async def test_live_sync_and_dispatch_claim_each_followup_once(monkeypatch):
    """GET /orders?order_id=123 through the real Brain sync and dispatch tools."""
    import time as _time

    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.assessment_sessions import identity_registry
    from app.services.agent.fireteam_service import (
        FireteamResult,
        SpecialistReport,
        ToolInvocation,
    )
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    register_scope(manager, "https://app.test")
    registry = identity_registry(manager)
    registry.register("user-a", "https://app.test", cookies={"sid": "a"})
    registry.register("user-b", "https://app.test", cookies={"sid": "b"})
    manager._capability_map = {
        "target": "https://app.test", "scope": "https://app.test",
        "api_samples": [{"method": "GET", "url": "https://app.test/orders?order_id=123",
                         "identity": "user-a", "artifact_id": "cap-1"}],
        "ready_for_attack": True,
    }
    class RoutingLLM(FakeLLM):
        """Answers Brain hypothesis review and follow-up planning separately."""

        async def ainvoke(self, messages):
            if "follow-up planner" not in messages[0].content:
                return SimpleNamespace(content=json.dumps({"hypotheses": []}))
            return await super().ainvoke(messages)

    llm = RoutingLLM(json.dumps({"proposals": [SQLI, AUTHZ]}))
    monkeypatch.setattr(manager, "_hypothesis_llm", lambda: llm)
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())

    first = json.loads(await manager.sync_engagement_brain())
    assert first["followup_planning"]["status"] == "planning"
    assert first["followup_planning"]["new_capture_events"] == 1
    brain = engagement_brain_from_dict(manager._engagement_brain)
    key = manager._followup_key(brain)
    await manager._followup_runtime.settle(key)
    applied = json.loads(await manager.sync_engagement_brain())["followup_planning"]
    # The inventory lane already seeded both cells; follow-ups link to them.
    assert applied["applied"]["merged"] == 2
    assert applied["claimable"] == 2
    assert "new_capture_events" not in applied
    assert llm.calls == 1

    seen = {}

    async def fake_fireteam(*, mission, directives, **_kwargs):
        seen.update(directives)
        reports = []
        for name, directive in directives.items():
            reports.append(SpecialistReport(
                specialist=name, role=name, mission=mission, summary="No proof yet",
                verdict="inconclusive",
                coverage_cell_id=directive.coverage_cell_id,
                coverage_lease_id=directive.coverage_lease_id,
                tool_calls=[ToolInvocation(tool="probe", args={}, success=True, summary="",
                                           evidence_ids=[f"probe-{name}"],
                                           started_at=_time.time())],
            ))
        return FireteamResult(mission=mission, specialists_run=list(directives),
                              reports=reports)

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Follow up on observed order request", specialists=["sqli", "auth_logic"],
    ))
    assert set(result["followup_leases"]) == {"sqli", "auth_logic"}
    assert seen["auth_logic"].allowed_identities == ["user-a", "user-b"]
    assert seen["auth_logic"].lead_packet["followup"]["required_identities"] == ["user-a", "user-b"]

    brain = engagement_brain_from_dict(manager._engagement_brain)
    results = [e for e in brain.observation_events if e["kind"] == "worker_result"]
    assert sorted(e["evidence_ids"][0] for e in results) == ["probe-auth_logic", "probe-sqli"]
    report = chain_report(brain)
    assert len(report) == 2
    assert all(row["claim_to_first_request_ms"] is not None for row in report)
    assert all(row["observation_to_verdict_ms"] is not None for row in report)

    # Capturing the same request again assigns nothing new.
    manager._capability_map["api_samples"].append(
        {"method": "GET", "url": "https://app.test/orders?order_id=124",
         "identity": "user-a", "artifact_id": "cap-2"})
    again = json.loads(await manager.sync_engagement_brain())["followup_planning"]
    assert "new_capture_events" not in again
    brain = engagement_brain_from_dict(manager._engagement_brain)
    assert len(_cells(brain, "sqli")) == len(_cells(brain, "authz")) == 1
    await manager._followup_runtime.settle(key)
    for job in list(manager._followup_runtime._jobs.values()):
        await asyncio.wait_for(job.task, timeout=2)


def test_restart_recovery_requeues_events_that_were_mid_planning():
    from app.services.agent.run_snapshot import _recover_brain_after_restart

    brain = EngagementBrain(target="https://app.test")
    event, _ = _capture(brain)
    event["status"] = "planning"
    recovered = _recover_brain_after_restart(brain.to_dict())
    assert recovered["observation_events"][0]["status"] == "committed"
