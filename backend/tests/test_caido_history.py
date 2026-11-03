"""Assessment-Caido IDOR lead source stays gated, in-scope, and value-free."""

import pytest

from app.services.agent.caido_history import (
    caido_graphql_config,
    caido_history_observations,
    parse_requests_payload,
)

ALLOWED = ["https://app.example.test"]


def _edge(host, path, query="", method="GET", is_tls=True, port=443):
    return {"node": {"host": host, "port": port, "path": path, "query": query,
                     "method": method, "isTls": is_tls}}


def _payload(*edges):
    return {"data": {"requestsByOffset": {"edges": list(edges)}}}


def test_in_scope_record_becomes_endpoint_and_param_row():
    payload = _payload(_edge("app.example.test", "/api/orders", "id=5"))
    rows, endpoints = parse_requests_payload(payload, ALLOWED)
    assert endpoints == [{"method": "GET", "path": "/api/orders", "identity": "caido_history"}]
    assert len(rows) == 1
    assert rows[0]["name"] == "id" and rows[0]["value_type"] == "positive_integer"
    assert rows[0]["source"] == "caido_history" and rows[0]["identity"] == "caido_history"


def test_out_of_scope_record_dropped():
    payload = _payload(_edge("evil.example.test", "/api/orders", "id=5"))
    rows, endpoints = parse_requests_payload(payload, ALLOWED)
    assert rows == [] and endpoints == []


def test_http_vs_https_and_nondefault_port_origin():
    payload = _payload(
        _edge("app.example.test", "/a", is_tls=False, port=80),      # http://app.example.test
        _edge("app.example.test", "/b", is_tls=True, port=8443),     # https://app...:8443
    )
    _, endpoints = parse_requests_payload(payload, ["http://app.example.test"])
    assert endpoints == [{"method": "GET", "path": "/a", "identity": "caido_history"}]


def test_protected_and_oversized_query_names_skipped():
    payload = _payload(_edge("app.example.test", "/x", "csrf_token=abc&session=zzz&id=7"))
    rows, _ = parse_requests_payload(payload, ALLOWED)
    assert [r["name"] for r in rows] == ["id"]


def test_no_request_values_in_output():
    payload = _payload(_edge("app.example.test", "/api/orders", "id=424242"))
    rows, endpoints = parse_requests_payload(payload, ALLOWED)
    text = repr((rows, endpoints))
    assert "424242" not in text  # the value never leaves the module


def test_tolerates_items_and_nodes_envelopes():
    items = {"data": {"requestsByOffset": {"items": [
        {"host": "app.example.test", "port": 443, "path": "/i", "method": "GET", "isTls": True}]}}}
    nodes = {"data": {"requestsByOffset": {"nodes": [
        {"host": "app.example.test", "port": 443, "path": "/n", "method": "GET", "isTls": True}]}}}
    _, items_eps = parse_requests_payload(items, ALLOWED)
    _, nodes_eps = parse_requests_payload(nodes, ALLOWED)
    assert items_eps and nodes_eps


def test_malformed_payload_yields_nothing():
    for bad in ({}, {"data": None}, {"data": {"requestsByOffset": None}}, {"data": {}}, []):
        assert parse_requests_payload(bad if isinstance(bad, dict) else {}, ALLOWED) == ([], [])


def test_config_requires_clean_url(monkeypatch):
    monkeypatch.delenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", raising=False)
    assert caido_graphql_config() is None
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "http://user:pass@caido/graphql")
    with pytest.raises(ValueError):
        caido_graphql_config()
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "http://caido-assessment:8080/graphql")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_TOKEN", "tok")
    assert caido_graphql_config() == ("http://caido-assessment:8080/graphql", "tok")


def test_observations_unset_url_reports_disabled(monkeypatch):
    monkeypatch.delenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", raising=False)
    rows, endpoints, status = caido_history_observations(ALLOWED)
    assert (rows, endpoints) == ([], [])
    assert status["ok"] is False and status["reason"] == "caido_graphql_url_unset"


def test_observations_queries_and_parses(monkeypatch):
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "http://caido-assessment:8080/graphql")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_TOKEN", "tok")
    captured = {}

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return _payload(_edge("app.example.test", "/api/orders", "id=5"))

    class _Client:
        def __init__(self, *a, **k):
            captured["trust_env"] = k.get("trust_env")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json, headers):
            captured["url"] = url
            captured["auth"] = headers.get("Authorization")
            captured["is_query"] = "query" in json and "mutation" not in json["query"]
            return _Resp()

    import httpx
    monkeypatch.setattr(httpx, "Client", _Client, raising=True)
    _rows, endpoints, status = caido_history_observations(ALLOWED)
    assert status["ok"] is True and status["records_in_scope"] == 1
    assert captured["auth"] == "Bearer tok"
    assert captured["trust_env"] is False
    assert captured["is_query"] is True  # never a mutation
    assert endpoints[0]["path"] == "/api/orders"


def test_binding_reports_isolation_state(monkeypatch):
    from app.services.agent.caido_history import assessment_caido_binding
    monkeypatch.delenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", raising=False)
    monkeypatch.delenv("AEGIS_ASSESSMENT_CAIDO_PROJECT", raising=False)
    assert assessment_caido_binding()["isolation"] == "unconfigured"
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "http://caido-assessment:8080/graphql")
    b = assessment_caido_binding()
    assert b["isolation"] == "unlabeled_shared" and b["endpoint"] == "caido-assessment:8080"
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_PROJECT", "engagement-acme-2026")
    b = assessment_caido_binding()
    assert b["isolation"] == "labeled" and b["project"] == "engagement-acme-2026"


def test_observations_status_includes_binding(monkeypatch):
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "http://caido-assessment:8080/graphql")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CAIDO_PROJECT", "engagement-acme-2026")

    class _Resp:
        def raise_for_status(self): return None
        def json(self): return _payload(_edge("app.example.test", "/api/orders", "id=5"))

    class _Client:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, *a, **k): return _Resp()

    import httpx
    monkeypatch.setattr(httpx, "Client", _Client, raising=True)
    _rows, _eps, status = caido_history_observations(ALLOWED)
    assert status["binding"]["project"] == "engagement-acme-2026"
    assert status["binding"]["isolation"] == "labeled"
