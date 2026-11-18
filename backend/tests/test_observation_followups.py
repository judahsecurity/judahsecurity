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
    capture_facts,
    chain_report,
    claim_followup,
    commit_observation,
    complete_followup,
    record_first_request,
    release_held_proposals,
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
