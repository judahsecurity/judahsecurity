"""The reasoning model may rank real work, but cannot invent work or proof."""

import json
from types import SimpleNamespace

import pytest
from app.services.agent.brain_hypothesis_planner import plan_coverage_hypotheses
from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    lead_packet_for_cell,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
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
    assert output["hypothesis_planning"]["status"] == "planned"
    assert output["hypothesis_planning"]["reviewed"] > 0
    assert fake.calls == 1
    assert any(c["test_type"] == "authz" for c in manager._engagement_brain["coverage_cells"])
    await manager.sync_engagement_brain()
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
    assert result["hypothesis_planning"]["status"] == "unavailable"
    assert result["parameter_coverage"]["sqli"]["remaining"] > 0
    assert not any(c.get("llm_review_digest") for c in manager._engagement_brain["coverage_cells"])
