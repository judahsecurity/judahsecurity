"""Steps 3-5 of the testing-graph work: lineage, fact-gated chains, planner
wake-up, and EvoGraph lessons / specialist steps."""

import asyncio
from types import SimpleNamespace

import pytest

from app.services.agent import evograph, exploration_graph
from app.services.agent.coverage_cells import _new_cell
from app.services.agent.engagement_brain import EngagementBrain, Hypothesis
from app.services.agent.penetration_task_graph import (
    NODE_BLOCKED, NODE_KILLED, NODE_PROVEN, NODE_READY, sync_graph_from_brain,
)


def _hyp(hid, title, status="open", source="map", parent=""):
    return Hypothesis(id=hid, title=title, assumption="", test="", pass_criteria="", kill_criteria="",
                      specialist="injection", status=status, source=source, parent_finding=parent,
                      target="https://app.example.com/")


def _brain():
    brain = EngagementBrain(target="https://app.example.com/")
    brain.hypotheses = [
        _hyp("h1", "SQLi in /search q", status="proven"),
        _hyp("h2", "Dump users via SQLi", source="chain", parent="SQLi in /search q"),
        _hyp("h3", "IDOR on /orders", status="killed"),
    ]
    cell = _new_cell(brain, method="GET", path="/search", host="app.example.com",
                     parameter="q", test_type="sqli", status="finding", hypothesis_id="h1",
                     finding_title="SQLi in /search q")
    follow = _new_cell(brain, method="GET", path="/export", host="app.example.com",
                       parameter="fmt", test_type="ssrf", status="untested", source="observation_followup")
    follow["followup"] = {"event_ids": ["obs-cap1"], "reason": "fmt reflects URLs"}
    brain.coverage_cells = [cell, follow]
    brain.observation_events = [
        {"id": "obs-cap1", "kind": "capture", "status": "committed",
         "facts": {"method": "GET", "host": "app.example.com", "path": "/export"}},
        {"id": "obs-res1", "kind": "worker_result", "status": "committed",
         "facts": {"coverage_cell_id": cell["id"], "verdict": "proven", "host": "app.example.com",
                   "path": "/search", "test_class": "sqli"}},
        {"id": "obs-vf1", "kind": "verified_finding", "status": "committed",
         "facts": {"coverage_cell_id": cell["id"], "finding_id": "F-9", "host": "app.example.com",
                   "path": "/search", "test_class": "sqli"}},
    ]
    sync_graph_from_brain(brain)
    return brain


def test_lineage_has_typed_nodes_and_edges():
    graph = exploration_graph.build(_brain(), objective="Assess app")
    kinds = {n["key"]: n["kind"] for n in graph["nodes"]}
    edges = {(e["source"], e["rel"], e["target"]) for e in graph["edges"]}

    assert kinds["goal"] == "goal"
    assert kinds["intent:h1"] == "intent" and kinds["obs-cap1"] == "fact"
    assert ("goal", "spawns", "intent:h1") in edges
    assert ("intent:h1", "proves", "finding:h1") in edges
    # The chain card is spawned by the finding it builds on.
    assert ("finding:h1", "spawns", "intent:h2") in edges
    # Follow-up intent planned from a capture fact.
    followup = next(k for k in kinds if k.startswith("followup:"))
    assert (followup, "derived_from", "obs-cap1") in edges
    # Work on the h1 cell yielded a result fact and proved the verified finding.
    assert ("intent:h1", "yields", "obs-res1") in edges
    assert ("intent:h1", "proves", "finding:F-9") in edges
    assert all(n.get("host") == "app.example.com" for n in graph["nodes"] if n["kind"] != "goal")


def test_chain_card_waits_for_proof_and_retires_when_parent_refuted():
    brain = EngagementBrain(target="app.example.com")
    brain.hypotheses = [
        _hyp("p", "Parent SQLi"),
        _hyp("c", "Chain from SQLi", source="chain", parent="Parent SQLi"),
    ]
    graph = sync_graph_from_brain(brain)
    assert graph.nodes["c"].status == NODE_BLOCKED                  # parent not proven yet

    brain.hypotheses[0].status = "proven"
    graph = sync_graph_from_brain(brain)
    assert graph.nodes["c"].status == NODE_READY

    brain2 = EngagementBrain(target="app.example.com")
    brain2.hypotheses = [_hyp("p", "Parent SQLi", status="killed"),
                         _hyp("c", "Chain from SQLi", source="chain", parent="Parent SQLi")]
    graph = sync_graph_from_brain(brain2)
    assert graph.nodes["c"].status == NODE_KILLED
    assert graph.nodes["c"].last_failure.startswith("Prerequisite refuted: Parent SQLi")
    # The hypothesis is closed too, so completion gates stop counting it.
    assert brain2.hypotheses[1].status == "killed"
    assert "Prerequisite refuted" in brain2.hypotheses[1].evidence


def test_non_chain_children_still_start_after_parent_starts():
    brain = EngagementBrain(target="app.example.com")
    parent = _hyp("p", "Map API", status="in_progress")
    child = _hyp("k", "Probe API params")
    child.parent_finding = "Map API"
    brain.hypotheses = [parent, child]
    graph = sync_graph_from_brain(brain)
    assert graph.nodes["k"].status == NODE_READY


def test_lineage_persist_writes_anchors_once(monkeypatch):
    from sqlalchemy import Column, MetaData, Table, create_engine
    from sqlalchemy.orm import sessionmaker

    import app.models  # noqa: F401
    import app.models.business_application  # noqa: F401
    import app.models.org_role  # noqa: F401
    from app.db.database import Base
    from app.models.agent_exploration import AgentExplorationAnchor, AgentExplorationGraph
    from app.models.asset import Asset, AssetType

    engine = create_engine("sqlite://")
    md = MetaData()
    for name in ("assets", "agent_exploration_graphs", "agent_exploration_anchors"):
        src = Base.metadata.tables[name]
        Table(name, md, *[Column(c.name, c.type, primary_key=c.primary_key) for c in src.columns])
    md.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(Asset(name="app", value="app.example.com", asset_type=AssetType.SUBDOMAIN, organization_id=1))
    db.commit()

    brain = _brain().to_dict()
    assert exploration_graph.persist(1, "s1", brain, objective="Assess app", db=db) is True
    assert exploration_graph.persist(1, "s1", brain, objective="Assess app", db=db) is False  # unchanged
    row = db.get(AgentExplorationGraph, "s1")
    assert row.node_counts["intent"] >= 3 and row.node_counts["finding"] >= 1
    anchors = db.query(AgentExplorationAnchor).filter_by(session_id="s1").all()
    assert anchors and all(a.asset_id for a in anchors)
    assert {a.kind for a in anchors} <= {"intent", "fact", "finding"}
    # Another organization cannot overwrite this session's graph.
    assert exploration_graph.persist(2, "s1", brain, db=db) is False


def test_new_fact_wakes_planner_and_finished_planning_applies_after_tools(monkeypatch):
    from app.services.agent.followup_runtime import FollowupRuntime

    runtime = FollowupRuntime()
    key = ("u", 1, "s", "t")

    async def scenario():
        async def work():
            return []
        task = asyncio.create_task(work())
        runtime._jobs[key] = SimpleNamespace(task=task, event_ids=[], queued_at=0.0)
        task.add_done_callback(lambda _t, k=key: runtime._finished.add(k))
        await task
        await asyncio.sleep(0)

    asyncio.run(scenario())
    assert runtime.has_finished(key)
    runtime.cancel(key)
    assert not runtime.has_finished(key)


def test_apply_finished_followups_waits_for_other_tools(monkeypatch):
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager.__new__(ASMToolsManager)
    calls = []
    manager._engagement_brain = EngagementBrain(target="t").to_dict()
    manager._followup_runtime = SimpleNamespace(has_finished=lambda key: True)
    manager._followup_key = lambda brain: ("k",)
    manager._refresh_followups = lambda brain: calls.append(brain) or {"status": "applied"}

    manager._tools_in_flight = 1
    manager._apply_finished_followups()
    assert calls == []                       # another tool holds a brain copy

    manager._tools_in_flight = 0
    manager._apply_finished_followups()
    assert len(calls) == 1


@pytest.mark.parametrize("error,expect", [
    ("HTTP 403 Forbidden by Cloudflare", "WAF"),
    ("401 Unauthorized", "authenticated identity"),
    ("Request timed out after 30s", "timed out"),
    ("got an unexpected keyword argument 'urll'", "malformed"),
    ("weird failure", "change approach"),
])
def test_failure_lessons_are_actionable(error, expect):
    lesson = evograph.lesson_for_failure("execute_curl", error, {"url": "https://app.example.com/x"})
    assert expect in lesson and "https://app.example.com/x" in lesson
    assert "args" not in lesson


def test_specialist_steps_are_recorded_under_the_dispatching_step(monkeypatch):
    runs = []

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, cypher, **params):
            runs.append((cypher, params))

    monkeypatch.setattr(evograph, "_get_driver", lambda: SimpleNamespace(session=lambda: _Session()))
    report = SimpleNamespace(
        specialist="sqli", mission="test q", verdict="proven", summary="UNION worked", error=None,
        stop_reason="done", hypothesis_ids=["h1"],
        tool_calls=[SimpleNamespace(tool="scoped_string_sqli", success=True, evidence_ids=["ev1"]),
                    SimpleNamespace(tool="execute_curl", success=False, evidence_ids=[])],
    )
    assert evograph.record_specialist_steps("s1", [report]) == 1
    cypher, params = runs[0]
    assert "SpecialistStep" in cypher and "DELEGATED" in cypher
    row = params["rows"][0]
    assert row["specialist"] == "sqli" and row["tool_count"] == 2 and row["failed_tools"] == 1
    assert row["evidence_ids"] == ["ev1"]


def test_exploration_endpoint_is_org_scoped(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.deps import get_current_user
    from app.api.routes import agent as agent_routes
    from app.db.database import get_db

    row = SimpleNamespace(session_id="s1", organization_id=1, updated_at=None,
                          node_counts={"intent": 2}, graph={"nodes": [{"key": "goal"}], "edges": []})
    db = SimpleNamespace(get=lambda model, key: row if key == "s1" else None)
    app = FastAPI()
    app.include_router(agent_routes.router)
    app.dependency_overrides[get_db] = lambda: db
    org = {"id": 1}
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=1, organization_id=org["id"])
    monkeypatch.setattr(agent_routes, "_resolve_agent_organization_id", lambda user, db: user.organization_id)
    client = TestClient(app)
    prefix = agent_routes.router.prefix or ""

    body = client.get(f"{prefix}/sessions/s1/exploration").json()
    assert body["node_counts"] == {"intent": 2} and body["nodes"] == [{"key": "goal"}]
    org["id"] = 2
    assert client.get(f"{prefix}/sessions/s1/exploration").status_code == 404
    assert client.get(f"{prefix}/sessions/nope/exploration").status_code == 404
