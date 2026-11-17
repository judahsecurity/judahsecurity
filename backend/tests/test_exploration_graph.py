from app.services.agent.exploration_graph import (
    MAX_NODES,
    build_exploration_graph,
    finding_ids_in_snapshot,
    hosts_in_snapshot,
)


def _snapshot():
    return {
        "saved_at": 1700000000,
        "engagement_brain": {
            "target": "https://app.example.com",
            "phase": "attack",
            "recon_observations": [
                {"id": "o1", "kind": "api_endpoint", "value": "/api/orders/{id}",
                 "target": "https://app.example.com/api/orders", "source": "js"},
                {"id": "o2", "kind": "live_host", "value": "admin", "target": "https://admin.example.com"},
            ],
            "hypotheses": [
                {"id": "h1", "title": "IDOR on orders", "specialist": "authz", "status": "open",
                 "observation_id": "o1", "target": "https://app.example.com/api/orders/1",
                 "parameter": "id"},
                {"id": "h2", "title": "Mass assignment on order update", "specialist": "logic",
                 "status": "open", "target": "https://app.example.com/api/orders/1", "parent_finding": "42"},
                {"id": "h3", "title": "Admin default creds", "specialist": "auth", "status": "killed",
                 "observation_id": "o2", "target": "https://admin.example.com/login"},
            ],
            "task_graph": {"nodes": {
                "h1": {"status": "proven", "attempts": 2, "depends_on": []},
                "h2": {"status": "pending", "depends_on": ["h1"], "parent_hypothesis_id": "h1"},
                "h3": {"status": "killed", "blocked_reason": "Authorization: Bearer abc123 rejected"},
            }},
            "candidates": [
                {"id": "c1", "hypothesis_id": "h1", "title": "Order IDOR", "status": "verified",
                 "target": "https://app.example.com/api/orders/1", "finding_id": "42"},
            ],
            "verification_receipts": {},
        },
    }


def _graph():
    return build_exploration_graph(
        _snapshot(),
        assets=[(1, "app.example.com"), (2, "admin.example.com")],
        findings=[{"id": 42, "title": "IDOR on /api/orders", "severity": "high", "status": "open",
                   "asset_id": 1}],
    )


def _edges(graph, kind):
    return {(e["source"], e["target"]) for e in graph["edges"] if e["kind"] == kind}


def test_lineage_edges():
    graph = _graph()
    assert ("obs:o1", "hyp:h1") in _edges(graph, "spawns")
    assert ("hyp:h1", "hyp:h2") in _edges(graph, "depends_on")
    assert ("hyp:h1", "hyp:h2") in _edges(graph, "derived_from")
    assert ("hyp:h1", "cand:c1") in _edges(graph, "yields")
    assert ("cand:c1", "finding:42") in _edges(graph, "proves")
    assert ("finding:42", "hyp:h2") in _edges(graph, "chains_to")


def test_task_graph_status_wins_and_assets_are_linked():
    graph = _graph()
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert nodes["hyp:h1"]["status"] == "proven" and nodes["hyp:h1"]["bucket"] == "proven"
    assert nodes["hyp:h1"]["attempts"] == 2
    assert nodes["asset:app.example.com"]["asset_id"] == 1
    assert nodes["asset:app.example.com"]["primary"] is True
    assert "abc123" not in nodes["hyp:h3"]["blocked_reason"]


def test_asset_coverage_counts():
    nodes = {n["id"]: n for n in _graph()["nodes"]}
    app = nodes["asset:app.example.com"]["coverage"]
    assert (app["hypotheses"], app["proven"], app["open"], app["candidates"], app["findings"]) == (2, 1, 1, 1, 1)
    admin = nodes["asset:admin.example.com"]["coverage"]
    assert (admin["observations"], admin["hypotheses"], admin["killed"]) == (1, 1, 1)


def test_findings_from_other_tenants_are_not_invented():
    graph = build_exploration_graph(_snapshot(), assets=[], findings=[])
    assert not any(n["type"] == "finding" for n in graph["nodes"])
    assert graph["counts"]["hypothesis"] == 3


def test_helpers_and_node_cap():
    assert finding_ids_in_snapshot(_snapshot()) == {42}
    assert hosts_in_snapshot(_snapshot()) == {"app.example.com", "admin.example.com"}
    big = {"engagement_brain": {"hypotheses": [
        {"id": f"h{i}", "title": "t", "target": "https://x.example.com"} for i in range(MAX_NODES + 50)
    ]}}
    graph = build_exploration_graph(big)
    assert graph["truncated"] is True
    assert len(graph["nodes"]) == MAX_NODES


def test_empty_snapshot():
    graph = build_exploration_graph({})
    assert graph["nodes"] == [] and graph["edges"] == []


def test_endpoint_scopes_assets_and_findings_to_the_org(monkeypatch):
    from types import SimpleNamespace

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import app.models  # noqa: F401
    from app.api import deps
    from app.api.routes import agent
    from app.db.database import Base, get_db
    from app.models.agent_conversation import AgentConversation
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import Severity, Vulnerability
    from app.services.agent import action_ledger, run_snapshot

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[Asset.__table__, Vulnerability.__table__, AgentConversation.__table__])
    factory = sessionmaker(bind=engine)
    db = factory()
    db.add_all([
        Asset(id=1, name="app", organization_id=7, asset_type=AssetType.SUBDOMAIN, value="app.example.com"),
        Asset(id=2, name="app-b", organization_id=8, asset_type=AssetType.SUBDOMAIN, value="admin.example.com"),
    ])
    db.flush()
    db.add_all([
        Vulnerability(id=42, title="Order IDOR", severity=Severity.HIGH, asset_id=1),
        AgentConversation(session_id="s-1", user_id=1, organization_id=7),
    ])
    db.commit()
    loaded = []
    monkeypatch.setattr(run_snapshot, "load_run_snapshot", lambda org, sid: loaded.append((org, sid)) or _snapshot())
    monkeypatch.setattr(action_ledger, "latest_run", lambda *a, **k: None)

    api = FastAPI()
    api.include_router(agent.router)
    user = SimpleNamespace(id=1, organization_id=7, is_superuser=False)

    def _db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    api.dependency_overrides[get_db] = _db
    api.dependency_overrides[deps.get_current_user] = lambda: user
    client = TestClient(api)

    graph = client.get("/agent/conversations/s-1/exploration-graph").json()
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert loaded == [(7, "s-1")]
    assert nodes["asset:app.example.com"]["asset_id"] == 1
    assert nodes["asset:admin.example.com"]["asset_id"] is None  # other tenant's asset is not linked
    assert nodes["finding:42"]["severity"] == "high"

    user.id = 2  # not the conversation owner and no run of their own
    assert client.get("/agent/conversations/s-1/exploration-graph").status_code == 404
