"""The reasoning model may rank real work, but cannot invent work or proof."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from app.services.agent.async_hypothesis_review import AsyncHypothesisReviews
from app.services.agent.brain_hypothesis_planner import plan_coverage_hypotheses
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    lead_packet_for_cell,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import (
    EngagementBrain,
    engagement_brain_from_dict,
)
from app.services.agent.operation_directive import OperationDirective
from app.services.agent.tools import ASMToolsManager


def _brain():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.test", "path": "/orders",
        "name": "order_id", "location": "query", "identity": "user-a",
        "source": "browser_traffic", "artifact_id": "capture-1",
        "testable": True,
    }])
    return brain


class FakeLLM:
    def __init__(self, content):
        self.content = content
        self.calls = 0
        self.messages = None

    async def ainvoke(self, messages):
        self.calls += 1
        self.messages = messages
        return SimpleNamespace(content=self.content)


@pytest.mark.asyncio
async def test_planner_attaches_only_observed_class_and_preserves_request_values():
    brain = _brain()
    authz = next(c for c in brain.coverage_cells if c["test_type"] == "authz")
    fake = FakeLLM(json.dumps({"hypotheses": [
        {"cell_id": "cov-invented", "hypothesis": "Fabricated work",
         "next_check": "Probe outside scope", "priority": "high"},
        {"cell_id": authz["id"],
         "hypothesis": "An order reference may lack an owner check",
         "next_check": "Compare with approved second identity", "priority": "high"},
    ]}))
    result = await plan_coverage_hypotheses(brain, fake)
    assert result["hypotheses"] == 1
    assert fake.calls == 1
    assert "cov-invented" not in repr(brain.coverage_cells)
    proposal = authz["llm_hypothesis"]
    assert proposal["cell_id"] == authz["id"]
    assert proposal["test_class"] == "authz"
    assert proposal["evidence_ids"] == ["capture-1"]
    assert authz["status"] == "untested"
    assert authz["llm_priority_rank"] == 0
    packet = lead_packet_for_cell(authz)
    assert packet["llm_hypothesis"] == proposal
    directive = OperationDirective(
        specialist="auth_logic", epithet="Authorization",
        target="https://app.test", goal="Review order access",
        lead_packet=packet,
    )
    assert "An order reference may lack an owner check" in directive.to_prompt_block()
    sent = fake.messages[1].content
    assert "capture-1" in sent
    assert "order_id" in sent
    assert "order_id=123" not in sent

    unchanged = await plan_coverage_hypotheses(brain, fake)
    assert unchanged["status"] == "unchanged"
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_new_evidence_revises_hypothesis_without_reopening_proof():
    brain = _brain()
    sqli = next(c for c in brain.coverage_cells if c["test_type"] == "sqli")
    fake = FakeLLM(json.dumps({"hypotheses": [{
        "cell_id": sqli["id"], "hypothesis": "SQL parsing may differ",
        "next_check": "Use controlled differential", "priority": "medium",
    }]}))
    await plan_coverage_hypotheses(brain, fake)
    sqli["first_pass_outcome"] = "inconclusive"
    sqli["first_pass_evidence_id"] = "probe-2"
    fake.content = json.dumps({"hypotheses": [{
        "cell_id": sqli["id"], "hypothesis": "Input transform may affect SQL proof",
        "next_check": "Inspect transform before a bounded replay", "priority": "high",
    }]})
    revised = await plan_coverage_hypotheses(brain, fake)
    assert revised["hypotheses"] == 1
    assert fake.calls == 2
    assert sqli["llm_hypothesis"]["evidence_ids"] == ["capture-1", "probe-2"]
    assert sqli["llm_hypothesis"]["hypothesis"].startswith("Input transform")
    assert sqli["status"] == "untested"


@pytest.mark.asyncio
async def test_invalid_model_output_leaves_work_retryable():
    brain = _brain()
    fake = FakeLLM("not json")
    with pytest.raises(ValueError, match="valid hypotheses array"):
        await plan_coverage_hypotheses(brain, fake)
    assert not any(c.get("llm_review_digest") for c in brain.coverage_cells)
    assert claim_coverage_cell_leases(brain, ["sqli"])["sqli"].coverage_cell_id


@pytest.mark.asyncio
async def test_planner_priority_changes_the_next_claimed_cell():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        {"method": "GET", "host": "app.test", "path": "/alpha", "name": "q",
         "location": "query", "identity": "anonymous", "source": "browser_traffic",
         "artifact_id": "capture-a", "testable": True},
        {"method": "GET", "host": "app.test", "path": "/zeta", "name": "q",
         "location": "query", "identity": "anonymous", "source": "browser_traffic",
         "artifact_id": "capture-z", "testable": True},
    ])
    sqli = [c for c in brain.coverage_cells if c["test_type"] == "sqli"]
    for cell in sqli:
        cell["priority_rank"] = 2
    target = next(c for c in sqli if c["path"] == "/zeta")
    fake = FakeLLM(json.dumps({"hypotheses": [{
        "cell_id": target["id"], "hypothesis": "Observed input may reach SQL",
        "next_check": "Compare controlled responses", "priority": "high",
    }]}))
    await plan_coverage_hypotheses(brain, fake)
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    assert lease.coverage_cell_id == target["id"]


@pytest.mark.asyncio
async def test_sync_brain_runs_planner_and_keeps_ledgers_assignable(monkeypatch):
    manager = ASMToolsManager()
    manager._capability_map = {
        "target": "https://app.test", "scope": "https://app.test",
        "parameter_inventory": [{
            "method": "GET", "path": "/orders", "name": "order_id",
            "location": "query", "source": "browser_traffic",
            "artifact_id": "capture-1", "identity": "user-a",
        }],
    }
    fake = FakeLLM(json.dumps({"hypotheses": []}))
    monkeypatch.setattr(manager, "_hypothesis_llm", lambda: fake)
    output = json.loads(await manager.sync_engagement_brain())
    assert output["hypothesis_planning"]["status"] == "queued"
    assert any(c["test_type"] == "authz" for c in manager._engagement_brain["coverage_cells"])
    assert not any(c.get("llm_review_digest") for c in manager._engagement_brain["coverage_cells"])
    key = manager._hypothesis_review_key(engagement_brain_from_dict(manager._engagement_brain))
    await asyncio.wait_for(manager._hypothesis_reviews._jobs[key].task, timeout=2)
    completed = json.loads(await manager.sync_engagement_brain())
    assert completed["hypothesis_planning"]["status"] == "applied"
    assert completed["hypothesis_planning"]["reviewed"] > 0
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_sync_reports_model_failure_without_losing_work(monkeypatch):
    manager = ASMToolsManager()
    manager._capability_map = {
        "target": "https://app.test", "scope": "https://app.test",
        "parameter_inventory": [{
            "method": "GET", "path": "/orders", "name": "order_id",
            "location": "query", "source": "browser_traffic",
            "artifact_id": "capture-1", "identity": "user-a",
        }],
    }

    def unavailable():
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(manager, "_hypothesis_llm", unavailable)
    result = json.loads(await manager.sync_engagement_brain())
    assert result["hypothesis_planning"]["status"] == "queued"
    key = manager._hypothesis_review_key(engagement_brain_from_dict(manager._engagement_brain))
    await asyncio.wait_for(manager._hypothesis_reviews._jobs[key].task, timeout=2)
    result = json.loads(await manager.sync_engagement_brain())
    assert result["hypothesis_planning"]["status"] == "unavailable"
    assert result["parameter_coverage"]["sqli"]["remaining"] > 0
    assert not any(c.get("llm_review_digest") for c in manager._engagement_brain["coverage_cells"])


@pytest.mark.asyncio
async def test_async_review_cannot_reprioritize_a_cell_claimed_during_model_call():
    brain = _brain()
    sqli = next(c for c in brain.coverage_cells if c["test_type"] == "sqli")
    fake = FakeLLM(json.dumps({"hypotheses": [{
        "cell_id": sqli["id"], "hypothesis": "Possible SQL parsing issue",
        "next_check": "Compare controlled responses", "priority": "high",
    }]}))
    queue = AsyncHypothesisReviews()
    key = (1, 2, "run-1", brain.target)
    assert queue.queue(key, brain, lambda: fake)["status"] == "queued"
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    assert lease.coverage_cell_id == sqli["id"]
    await asyncio.wait_for(queue._jobs[key].task, timeout=2)
    completed = queue.collect(key, brain)
    assert completed["status"] == "applied"
    live_claimed = next(cell for cell in brain.coverage_cells if cell["id"] == sqli["id"])
    assert "llm_hypothesis" not in live_claimed
    assert "llm_review_digest" not in live_claimed
    assert queue.collect((1, 3, "run-1", brain.target), brain)["status"] == "unchanged"


@pytest.mark.asyncio
async def test_async_review_prioritizes_only_unclaimed_work_in_next_wave():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [
        {"method": "GET", "host": "app.test", "path": "/alpha", "name": "q",
         "location": "query", "identity": "anonymous", "source": "browser_traffic",
         "artifact_id": "capture-a", "testable": True},
        {"method": "GET", "host": "app.test", "path": "/zeta", "name": "q",
         "location": "query", "identity": "anonymous", "source": "browser_traffic",
         "artifact_id": "capture-z", "testable": True},
    ])
    sqli = [cell for cell in brain.coverage_cells if cell["test_type"] == "sqli"]
    for cell in sqli:
        cell["priority_rank"] = 2
    target = next(cell for cell in sqli if cell["path"] == "/zeta")
    fake = FakeLLM(json.dumps({"hypotheses": [{
        "cell_id": target["id"], "hypothesis": "Possible SQL parsing issue",
        "next_check": "Compare controlled responses", "priority": "high",
    }]}))
    queue = AsyncHypothesisReviews()
    key = (1, 2, "run-1", brain.target)
    assert queue.queue(key, brain, lambda: fake)["status"] == "queued"
    first = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    assert first.coverage_cell_id != target["id"]
    await asyncio.wait_for(queue._jobs[key].task, timeout=2)
    assert queue.collect(key, brain)["hypotheses"] == 1
    live_target = next(cell for cell in brain.coverage_cells if cell["id"] == target["id"])
    assert live_target["llm_priority_rank"] == 0
    second = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    assert second.coverage_cell_id == target["id"]


@pytest.mark.asyncio
async def test_dispatch_claims_input_while_hypothesis_model_is_stalled(monkeypatch):
    from app.services.agent.fireteam_service import FireteamResult, SpecialistReport

    release_model = asyncio.Event()

    class SlowLLM(FakeLLM):
        async def ainvoke(self, messages):
            self.calls += 1
            self.messages = messages
            await release_model.wait()
            return SimpleNamespace(content=self.content)

    manager = ASMToolsManager()
    manager._capability_map = {
        "target": "https://app.test", "scope": "https://app.test",
        "forms": [{"method": "GET", "action": "/orders", "inputs": ["order_id"]}],
        "pages_visited": ["https://app.test/orders?order_id=123"],
        "ready_for_attack": True,
    }
    model = SlowLLM(json.dumps({"hypotheses": []}))
    monkeypatch.setattr(manager, "_hypothesis_llm", lambda: model)
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())

    async def fake_fireteam(*, mission, directives, **_kwargs):
        assert directives["sqli"].coverage_cell_id
        assert not release_model.is_set()
        return FireteamResult(
            mission=mission, specialists_run=["sqli"],
            reports=[SpecialistReport(
                specialist="sqli", role="SQLi", mission=mission,
                summary="No proof yet", verdict="inconclusive",
            )],
        )

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    try:
        result = json.loads(await asyncio.wait_for(
            manager.fireteam_dispatch(
                mission="Review observed order input", specialists=["sqli"],
                mode="observed_inputs",
            ), timeout=3,
        ))
        assert result["coverage_leases"]["sqli"]["coverage_cell_id"]
        assert result["hypothesis_planning"]["status"] == "queued"
        assert result["assignment_latency_ms"] < 3000
        assert not release_model.is_set()
    finally:
        release_model.set()
        for job in manager._hypothesis_reviews._jobs.values():
            await asyncio.wait_for(job.task, timeout=2)
