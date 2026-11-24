"""POST /graph/query: JSON body, server-bound $org_id, read-only."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.api.routes import graph as graph_routes


@pytest.fixture
def client(monkeypatch):
    calls = []

    class _Graph:
        def query(self, cypher, params=None):
            calls.append((cypher, params))
            return [{"ok": 1}]

    monkeypatch.setattr(graph_routes, "get_graph_service", lambda: _Graph())
    app = FastAPI()
    app.include_router(graph_routes.router)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(is_superuser=True, organization_id=5)
    url = (graph_routes.router.prefix or "") + "/query"
    return TestClient(app), url, calls


def test_body_query_gets_org_bound_and_params_passed(client):
    c, url, calls = client
    r = c.post(url, json={"cypher": "MATCH (a:Asset) WHERE a.organization_id = $org_id AND a.value = $v RETURN a",
                          "params": {"v": "x", "org_id": 999}})
    assert r.status_code == 200 and r.json()["count"] == 1
    cypher, params = calls[0]
    assert params == {"v": "x", "org_id": 5}           # caller cannot override the org
    assert "n.organization_id" not in cypher            # no text rewriting


def test_query_without_org_filter_is_refused(client):
    c, url, calls = client
    r = c.post(url, json={"cypher": "MATCH (asset:Asset) RETURN asset"})
    assert r.status_code == 422 and "$org_id" in r.json()["detail"]
    assert calls == []


@pytest.mark.parametrize("cypher", [
    "MATCH (n) WHERE n.organization_id = $org_id DETACH DELETE n",
    "MATCH (n) WHERE n.organization_id = $org_id SET n.x = 1",
    "MERGE (n:Asset {organization_id: $org_id})",
    "CALL dbms.components() YIELD name WHERE $org_id > 0 RETURN name",
])
def test_writes_are_refused(client, cypher):
    c, url, calls = client
    assert c.post(url, json={"cypher": cypher}).status_code == 422
    assert calls == []


def test_keywords_inside_strings_are_not_writes(client):
    c, url, calls = client
    r = c.post(url, json={"cypher": "MATCH (v:Vulnerability) WHERE v.organization_id = $org_id "
                                    "AND v.title CONTAINS 'SET cookie' RETURN v"})
    assert r.status_code == 200


def test_legacy_query_param_still_accepted(client):
    c, url, calls = client
    r = c.post(url + "?query=MATCH%20(n)%20WHERE%20n.organization_id%20%3D%20%24org_id%20RETURN%20n")
    assert r.status_code == 200 and calls[0][1] == {"org_id": 5}
