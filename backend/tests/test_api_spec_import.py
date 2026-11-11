"""Operator-supplied API specs become in-scope, value-free Prowl work items."""

import asyncio
import json

import pytest

from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.tools import ASMToolsManager
from app.services.api_spec_import import (
    import_api_document,
    parse_api_document,
)

ORIGIN = "https://shop.example.test"

OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Shop", "version": "1"},
    "servers": [{"url": "/api/v1"}, {"url": "https://other.example.test"}],
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "Order": {"type": "object", "properties": {
                "id": {"type": "integer", "readOnly": True},
                "note": {"type": "string", "example": "SECRET-EXAMPLE"},
                "quantity": {"type": "integer"},
            }},
        },
    },
    "security": [{"bearer": []}],
    "paths": {
        "/orders/{orderId}": {
            "parameters": [{"name": "orderId", "in": "path", "required": True,
                            "schema": {"type": "integer"}}],
            "get": {"summary": "Get order"},
            "put": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Order"}}}}},
        },
        "/search": {
            "get": {"security": [], "parameters": [
                {"name": "q", "in": "query", "schema": {"type": "string"}},
                {"name": "page", "in": "query", "schema": {"type": "integer"}},
            ]},
        },
    },
}

POSTMAN = {
    "info": {"name": "Shop collection", "_postman_id": "x",
             "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "auth": {"type": "bearer"},
    "variable": [{"key": "baseUrl", "value": ""}],
    "item": [
        {"name": "Folder", "item": [
            {"name": "User", "request": {"method": "GET",
                                         "url": "{{baseUrl}}/users/:userId?expand=true"}},
            {"name": "Login", "request": {
                "method": "POST", "auth": {"type": "noauth"},
                "url": {"raw": "{{baseUrl}}/login"},
                "body": {"mode": "urlencoded", "urlencoded": [
                    {"key": "email", "value": "a@b.c"}, {"key": "password", "value": "hunter2"},
                ]}}},
        ]},
        {"name": "Elsewhere", "request": {"method": "GET", "url": "https://evil.example.test/x"}},
        {"name": "Comment", "request": {
            "method": "POST", "url": "{{baseUrl}}/comments",
            "body": {"mode": "raw", "raw": "{\"text\": \"{{msg}}\", \"postId\": 7}",
                     "options": {"raw": {"language": "json"}}}}},
    ],
}


def test_detects_formats_and_rejects_garbage():
    assert parse_api_document(json.dumps(OPENAPI)).kind == "openapi"
    assert parse_api_document(json.dumps(POSTMAN)).kind == "postman"
    yaml_doc = "swagger: '2.0'\ninfo: {title: t}\npaths:\n  /a:\n    get: {}\n"
    assert parse_api_document(yaml_doc).kind == "openapi"
    with pytest.raises(ValueError):
        parse_api_document('{"hello": "world"}')
    with pytest.raises(ValueError):
        parse_api_document("")


def test_openapi_import_is_scoped_and_value_free():
    result = import_api_document(json.dumps(OPENAPI), ORIGIN)
    urls = {(r["method"], r["url"]) for r in result.requests}
    assert ("GET", f"{ORIGIN}/api/v1/orders/1") in urls
    assert ("GET", f"{ORIGIN}/api/v1/search?q=test&page=1") in urls
    put = next(r for r in result.requests if r["method"] == "PUT")
    assert put["headers"]["Content-Type"] == "application/json"
    assert put["body"] == {"note": "test", "quantity": 1}  # readOnly id dropped, example not copied
    assert "SECRET-EXAMPLE" not in json.dumps(result.requests)
    summary = result.summary()
    assert summary["out_of_scope_origins"] == ["https://other.example.test"]
    assert summary["suggested_identities"][0]["scheme"] == "bearer"
    assert summary["owner_only_candidates"] == [{
        "method": "GET", "path_template": "/api/v1/orders/{orderId}",
        "object_parameters": ["orderId"], "requires_auth": True,
    }]
    search = next(r for r in result.rest_rows if r["path"] == "/api/v1/search")
    assert search["access"] == "no_auth"


def test_openapi_with_only_foreign_servers_imports_nothing():
    doc = {**OPENAPI, "servers": [{"url": "https://other.example.test"}]}
    result = import_api_document(json.dumps(doc), ORIGIN)
    assert result.requests == []
    assert result.summary()["out_of_scope_dropped"] == 1


def test_postman_import_expands_variables_and_drops_foreign_hosts():
    result = import_api_document(json.dumps(POSTMAN), ORIGIN)
    by_path = {r["url"].split("?")[0]: r for r in result.requests}
    assert set(by_path) == {f"{ORIGIN}/users/1", f"{ORIGIN}/login", f"{ORIGIN}/comments"}
    assert by_path[f"{ORIGIN}/users/1"]["url"].endswith("?expand=test")
    assert by_path[f"{ORIGIN}/login"]["body"] == "email=test&password=test"
    assert "hunter2" not in json.dumps(result.requests)
    assert by_path[f"{ORIGIN}/comments"]["body"] == {"text": "test", "postId": 1}
    assert result.summary()["out_of_scope_origins"] == ["https://evil.example.test"]
    assert result.owner_only_candidates[0]["object_parameters"] == ["userId"]
    assert result.suggested_identities[0]["type"] == "bearer"


def test_agent_tool_seeds_operations_and_coverage_cells():
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._engagement_brain = {"target": ORIGIN}
    manager._capability_map = {"target": ORIGIN, "scope": ORIGIN}
    out = json.loads(asyncio.run(manager.import_api_spec(document=json.dumps(OPENAPI))))
    assert out["operations_added"] == 3
    brain = engagement_brain_from_dict(manager._engagement_brain)
    sources = {s for op in brain.application_operations for s in op.get("sources", [])}
    assert sources == {"api_spec"}
    params = {c.get("parameter") for c in brain.coverage_cells}
    assert {"query:q", "body_json:note"} <= params


def test_agent_tool_refuses_a_different_origin():
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._engagement_brain = {"target": ORIGIN}
    manager._capability_map = {"target": ORIGIN, "scope": ORIGIN}
    with pytest.raises(ValueError):
        asyncio.run(manager.import_api_spec(document=json.dumps(OPENAPI),
                                            origin="https://other.example.test"))


class _Query:
    def __init__(self, asset):
        self.asset = asset

    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        return self.asset


class _DB:
    def __init__(self, asset):
        self.asset, self.commits = asset, 0

    def query(self, _model):
        return _Query(self.asset)

    def commit(self):
        self.commits += 1


def _analyst(org_id=1):
    from types import SimpleNamespace
    return SimpleNamespace(is_superuser=False, organization_id=org_id, role="analyst", id=5)


def test_upload_endpoint_stores_spec_and_rest_rows(monkeypatch):
    from types import SimpleNamespace

    from app.api.routes import assets as routes

    monkeypatch.setattr(routes, "check_org_access", lambda _user, org: org == 1)
    asset = SimpleNamespace(value="shop.example.test", organization_id=1,
                            api_specs=[], rest_endpoints=[])
    db = _DB(asset)
    out = routes.import_asset_api_spec(
        7, routes.ApiSpecImportRequest(document=json.dumps(OPENAPI), name="shop"),
        db=db, current_user=_analyst(),
    )
    assert out["operations"] == 3 and db.commits == 1
    assert asset.api_specs[0]["format"] == "openapi"
    assert asset.api_specs[0]["discovered_by"] == "operator_upload"
    assert {row["method"] for row in asset.rest_endpoints} == {"GET", "PUT"}

    with pytest.raises(routes.HTTPException) as foreign:
        routes.import_asset_api_spec(
            7, routes.ApiSpecImportRequest(document=json.dumps(OPENAPI),
                                           origin="https://other.example.test"),
            db=db, current_user=_analyst(),
        )
    assert foreign.value.status_code == 400

    with pytest.raises(routes.HTTPException) as denied:
        monkeypatch.setattr(routes, "check_org_access", lambda _user, _org: False)
        routes.import_asset_api_spec(
            7, routes.ApiSpecImportRequest(document=json.dumps(OPENAPI)),
            db=db, current_user=_analyst(),
        )
    assert denied.value.status_code == 403
