"""GET /agent/sessions/{id}/chain and run-control routes are org-scoped."""

from types import SimpleNamespace

from app.services.agent import evograph


class _Result:
    def __init__(self, single=None, data=None):
        self._single, self._data = single, data or []

    def single(self):
        return self._single

    def data(self):
        return self._data


class _FakeNeo4jSession:
    """Answers EvoGraph's chain queries for one AgentChain owned by org 1."""

    CHAINS = {("s1", 1): {"objective": "map the edge", "status": "running", "mode": "agent",
                          "started_at": "2026-01-01T00:00:00Z", "step_count": 1,
                          "final_phase": "informational"}}

    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        assert "organization_id: $org" in query, "chain query must be org-scoped"
        chain = self.CHAINS.get((params["sid"], params["org"]))
        if "HAS_STEP" in query:
            steps = [{"iteration": 1, "phase": "informational", "tool_name": "http_probe",
                      "tool_args": "{}", "output_summary": "200 OK", "success": True,
                      "thought": "", "created_at": None, "findings": [], "failures": []}]
            return _Result(data=steps if chain else [])
        return _Result(single=chain)


class _FakeDriver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _FakeNeo4jSession(self.calls)


def _client(monkeypatch, driver, org):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.deps import get_current_user
    from app.api.routes import agent as agent_routes
    from app.db.database import get_db

    monkeypatch.setattr(evograph, "_get_driver", lambda: driver)
    app = FastAPI()
    app.include_router(agent_routes.router)
    app.dependency_overrides[get_db] = lambda: SimpleNamespace()
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=1, organization_id=org["id"])
    monkeypatch.setattr(agent_routes, "_resolve_agent_organization_id", lambda user, db: user.organization_id)
    return TestClient(app), agent_routes.router.prefix or ""


def test_session_chain_endpoint_is_org_scoped(monkeypatch):
    driver = _FakeDriver()
    org = {"id": 1}
    client, prefix = _client(monkeypatch, driver, org)

    resp = client.get(f"{prefix}/sessions/s1/chain")
    assert resp.status_code == 200
    body = resp.json()
    assert body["meta"]["session_id"] == "s1" and body["meta"]["objective"] == "map the edge"
    assert [n["type"] for n in body["nodes"]] == ["chain", "step"]
    assert all(params["org"] == 1 for _q, params in driver.calls)

    org["id"] = 2
    resp = client.get(f"{prefix}/sessions/s1/chain")
    assert resp.status_code == 404
    assert "map the edge" not in resp.text
    assert client.get(f"{prefix}/sessions/nope/chain").status_code == 404

    org["id"] = None
    assert client.get(f"{prefix}/sessions/s1/chain").status_code == 404


def test_get_session_chain_without_org_never_queries(monkeypatch):
    driver = _FakeDriver()
    monkeypatch.setattr(evograph, "_get_driver", lambda: driver)
    assert evograph.get_session_chain("s1", None) == {"nodes": [], "edges": [], "meta": {}}
    assert evograph.get_session_chain("s1", 2) == {"nodes": [], "edges": [], "meta": {}}
    assert driver.calls and all(params["org"] == 2 for _q, params in driver.calls)


def test_run_control_refuses_other_org_session(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.deps import get_current_user
    from app.api.routes import agent as agent_routes
    from app.db.database import get_db
    from app.services.agent import run_control

    conv = SimpleNamespace(session_id="s1", organization_id=1, user_id=1)

    class _Query:
        def __init__(self):
            self.sid = None

        def filter(self, *clauses):
            self.sid = clauses[0].right.value
            return self

        def first(self):
            return conv if self.sid == "s1" else None

    db = SimpleNamespace(query=lambda model: _Query())
    org = {"id": 2}
    app = FastAPI()
    app.include_router(agent_routes.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=9, organization_id=org["id"])
    monkeypatch.setattr(agent_routes, "_resolve_agent_organization_id", lambda user, db: user.organization_id)
    stopped, steered, compacted = [], [], []
    monkeypatch.setattr(agent_routes, "_stop_agent_session", lambda sid: stopped.append(sid) or False)
    monkeypatch.setattr(run_control, "queue_steer", lambda sid, msg: steered.append(sid) or False)
    monkeypatch.setattr(run_control, "request_compact", lambda sid: compacted.append(sid))
    client = TestClient(app)
    prefix = agent_routes.router.prefix or ""

    assert client.post(f"{prefix}/sessions/s1/stop").status_code == 404
    assert client.post(f"{prefix}/sessions/s1/steer",
                       json={"session_id": "s1", "message": "exfiltrate"}).status_code == 404
    assert client.post(f"{prefix}/sessions/s1/compact").status_code == 404
    assert client.post(f"{prefix}/sessions/s1/load",
                       json={"session_id": "s1", "source_session_id": "x"}).status_code == 404
    assert stopped == steered == compacted == []

    org["id"] = 1
    assert client.post(f"{prefix}/sessions/s1/stop").status_code == 200
    assert client.post(f"{prefix}/sessions/s1/compact").status_code == 200
    assert stopped == ["s1"] and compacted == ["s1"]
