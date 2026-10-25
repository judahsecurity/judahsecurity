"""A browser capture keeps GraphQL values private and replays only safe context."""

import json
from io import BytesIO

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.scoped_assessment.body_probe import (
    plan_observed_body,
    probe_observed_body,
    safe_replay_headers,
)
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.scoped_assessment.query_probe import plan_observed_query
from app.services.agent.tools import ASMToolsManager


def test_graphql_capture_exposes_variable_shape_and_safe_header_names():
    body = json.dumps({
        "query": "query Search($term: String!) { search(term: $term) { id } }",
        "operationName": "Search",
        "variables": {"term": "private-search-value", "nested": {"limit": 5}},
    }).encode()
    public, private = package_exchange(
        url="https://app.example.test/graphql", expected_origin="https://app.example.test",
        action_ref="search-click", method="POST", resource_type="fetch", status=200,
        content_type="application/json", request_content_type="application/json",
        request_body=body, response_body=b'{"data":{"search":[]}}',
        request_headers={
            "Authorization": "Bearer private-token", "Cookie": "sid=private-cookie",
            "X-CSRF-Token": "private-csrf", "X-Requested-With": "XMLHttpRequest",
            "Apollo-Require-Preflight": "true", "X-Other": "private-header",
        },
        page_url="https://app.example.test/search",
    )
    assert public["protocol"] == "graphql"
    assert public["graphql_operation_type"] == "query"
    assert public["graphql_operation_name"] == "Search"
    assert {row["path"] for row in public["body_fields"]} == {
        "/variables/term", "/variables/nested/limit",
    }
    assert public["replay_header_names"] == ["Apollo-Require-Preflight", "X-Requested-With"]
    assert "private-search-value" not in json.dumps(public)
    assert "private-token" not in private.decode()
    assert "private-cookie" not in private.decode()
    assert "private-csrf" not in private.decode()
    assert safe_replay_headers(private) == {
        "Apollo-Require-Preflight": "true", "X-Requested-With": "XMLHttpRequest",
    }
    _, _, baseline, mutated = plan_observed_body(
        private, parameter="/variables/term", allowed_origins=["https://app.example.test"],
    )
    assert json.loads(baseline)["variables"]["term"] == "private-search-value"
    assert json.loads(mutated)["variables"]["term"] == "private-search-value'"
    assert json.loads(mutated)["query"] == json.loads(baseline)["query"]


def test_graphql_mutation_cannot_use_two_request_generic_probe():
    for query in (
        "mutation Save($name: String!) { save(name: $name) }",
        "query Read { read } mutation Save($name: String!) { save(name: $name) }",
        "fragment F on Item { id } mutation Save($name: String!) { save(name: $name) }",
    ):
        _, private = package_exchange(
            url="https://app.example.test/graphql", expected_origin="https://app.example.test",
            action_ref="save-click", method="POST", resource_type="fetch", status=200,
            content_type="application/json", request_content_type="application/json",
            request_body=json.dumps({"query": query, "variables": {"name": "hello"}}).encode(),
            response_body=b"{}",
        )
        with pytest.raises(ValueError, match="disposable workflow proof"):
            plan_observed_body(private, parameter="/variables/name",
                               allowed_origins=["https://app.example.test"])


def test_document_navigation_capture_supplies_private_query_baseline():
    public, private = package_exchange(
        url="https://app.example.test/search?q=private-value",
        expected_origin="https://app.example.test", action_ref="search-link",
        method="GET", resource_type="document", status=200,
        content_type="text/html", request_body=b"", response_body=b"<html></html>",
    )
    assert public["query_keys"] == ["q"]
    assert "private-value" not in json.dumps(public)
    baseline, changed = plan_observed_query(
        private, parameter="q", allowed_origins=["https://app.example.test"],
    )
    assert baseline.endswith("q=private-value")
    assert changed.endswith("q=private-value%27")
    with pytest.raises(ValueError, match="input-bearing GET"):
        package_exchange(
            url="https://app.example.test/search", expected_origin="https://app.example.test",
            action_ref="navigate", method="GET", resource_type="document", status=200,
            content_type="text/html", request_body=b"", response_body=b"",
        )


def test_graphql_query_replay_preserves_allowed_headers_and_named_identity(monkeypatch):
    seen = []

    class Response(BytesIO):
        status = 200
        headers = {"Content-Type": "application/json"}

    class Opener:
        def open(self, request, timeout):
            body = json.loads(request.data)
            seen.append({"body": body, "cookie": request.get_header("Cookie"),
                         "requested_with": request.get_header("X-requested-with"),
                         "preflight": request.get_header("Apollo-require-preflight"),
                         "authorization": request.get_header("Authorization")})
            return Response(json.dumps({"data": {"search": body["variables"]["term"]}}).encode())

    monkeypatch.setattr("app.services.agent.scoped_assessment.body_probe.build_opener",
                        lambda *_args: Opener())
    base = "https://app.example.test"
    _, private = package_exchange(
        url=base + "/graphql", expected_origin=base, action_ref="search-click",
        method="POST", resource_type="fetch", status=200,
        content_type="application/json", request_content_type="application/json",
        request_body=b'{"query":"query Search { search }","variables":{"term":"plain"}}',
        response_body=b"{}",
        request_headers={"X-Requested-With": "XMLHttpRequest",
                         "Apollo-Require-Preflight": "true",
                         "Authorization": "Bearer captured-secret"},
    )
    url, mime, baseline, changed = plan_observed_body(
        private, parameter="/variables/term", allowed_origins=[base],
    )
    receipt = probe_observed_body(
        url, mime, baseline, changed, parameter="/variables/term",
        allowed_origins=[base],
        storage_state={"cookies": [{"name": "sid", "value": "named-user", "domain": "app.example.test"}]},
        replay_headers=safe_replay_headers(private),
    )
    assert receipt["requests_sent"] == 2 and receipt["finding"] is False
    assert not receipt["inconclusive"]
    assert [row["body"]["variables"]["term"] for row in seen] == ["plain", "plain'"]
    assert all(row["cookie"] == "sid=named-user" for row in seen)
    assert all(row["requested_with"] == "XMLHttpRequest" and row["preflight"] == "true"
               for row in seen)
    assert all(row["authorization"] is None for row in seen)


@pytest.mark.asyncio
async def test_browser_handoff_keeps_identity_and_graphql_operation_separate(monkeypatch):
    base = "https://app.example.test"
    manager = ASMToolsManager()
    manager._fallback_target = base
    register_scope(manager, "app.example.test")
    identity_registry(manager).register("owner", base)
    gql_public, gql_private = package_exchange(
        url=base + "/graphql", expected_origin=base, action_ref="search-click",
        method="POST", resource_type="fetch", status=200,
        content_type="application/json", request_content_type="application/json",
        request_body=b'{"query":"query Search($term: String!) { search(term: $term) }",'
                     b'"operationName":"Search","variables":{"term":"private-value"}}',
        response_body=b'{"data":{"search":[]}}', page_url=base + "/search",
    )
    nav_public, nav_private = package_exchange(
        url=base + "/search?q=private-value", expected_origin=base,
        action_ref="search-link", method="GET", resource_type="document",
        status=200, content_type="text/html", request_body=b"", response_body=b"<html></html>",
    )

    async def fake_browser(**kwargs):
        kwargs["traffic_exchanges"].extend([
            {"public": gql_public, "private": gql_private},
            {"public": nav_public, "private": nav_private},
        ])
        return ({"operation": "map", "final_origin": base, "final_path": "/",
                 "requests": [], "actions": [], "status": 200}, None)

    monkeypatch.setattr("app.services.agent.scoped_assessment_tools.browser.check_browser", fake_browser)
    result = json.loads(await manager.scoped_browser_assessment("map", base + "/", identity="owner"))
    assert result["identity"] == "owner"
    assert "private-value" not in json.dumps(result)
    inventory = manager._capability_map["parameter_inventory"]
    assert any(row["path"] == "/graphql" and row["name"] == "/variables/term"
               and row["identity"] == "owner" for row in inventory)
    assert any(row["path"] == "/search" and row["name"] == "q"
               and row["identity"] == "owner" for row in inventory)
    brain = engagement_brain_from_dict(manager._engagement_brain)
    graphql = [row for row in brain.application_operations if row["protocol"] == "graphql"]
    assert len(graphql) == 1
    assert graphql[0]["operation"].startswith("query:Search:")
    assert graphql[0]["identities"] == ["owner"]
    assert graphql[0]["parameters"] == ["body_json:/variables/term"]
    assert len(graphql[0]["capture_ids"]) == 1
    assert any(cell["parameter"] == "body_json:/variables/term" and cell["identity"] == "owner"
               and cell["capture_id"] == graphql[0]["capture_ids"][0]
               for cell in brain.coverage_cells)
