"""The agent bridge must keep scope and service capabilities out of model I/O."""

from types import SimpleNamespace

import pytest

from app.models.asset import AssetType
from app.services.agent import prowl_service_bridge as bridge
from app.services.agent.scoped_assessment.browser import _link_query_inputs


def _asset(value="app.example", kind=AssetType.DOMAIN, in_scope=True):
    return SimpleNamespace(id=14, value=value, asset_type=kind, in_scope=in_scope)


@pytest.mark.parametrize("origin", [
    "https://other.example", "https://app.example.evil", "https://app.example/path",
    "https://user@app.example", "https://app.example?x=1", "ftp://app.example",
])
def test_exact_asset_origin_rejects_scope_expansion(origin):
    with pytest.raises(ValueError):
        bridge.exact_asset_origin(_asset(), origin)


def test_exact_asset_origin_accepts_only_stored_web_asset():
    assert bridge.exact_asset_origin(_asset(), "https://app.example") == "https://app.example"
    assert bridge.exact_asset_origin(_asset(), "https://APP.example:443") == "https://app.example"
    assert bridge.exact_asset_origin(
        _asset("https://app.example/", AssetType.URL), "https://app.example"
    ) == "https://app.example"
    with pytest.raises(ValueError):
        bridge.exact_asset_origin(_asset("https://app.example/login", AssetType.URL), "https://app.example")
    with pytest.raises(ValueError):
        bridge.exact_asset_origin(_asset(in_scope=False), "https://app.example")


def test_browser_observation_feeds_aegis_capability_map():
    observation = {
        "signal": "browser_map",
        "result": {
            "target_template": "https://app.example/",
            "final_origin": "https://app.example", "final_path": "/", "status": 200,
            "forms": [{"method": "GET", "action": "https://app.example/search",
                       "fields": [{"name": "q", "control_type": "search"}]}],
            "requests": [{"resource_type": "xhr", "method": "GET", "path": "/api/search",
                          "query_keys": ["term"]},
                         {"resource_type": "script", "method": "GET",
                          "path": "/static/app.js"}],
            "traffic": [{"method": "POST", "path": "/api/comment", "artifact_id": "capture-9",
                         "resource_type": "fetch", "status": 201,
                         "content_type": "application/json",
                         "query_fields": [{"name": "draft", "value_type": "boolean"}],
                         "body_fields": [{"location": "json", "path": "/comment/text",
                                          "value_type": "string"}]}],
            "scripts": [{"kind": "external", "path": "/static/app.js",
                         "artifact_id": "script-9", "sha256": "abc", "bytes": 100,
                         "analysis": {"query_leads": []}}],
        },
    }
    cmap = bridge.capability_map_from_observation(observation)
    assert cmap["pages_visited"] == ["https://app.example/"]
    assert cmap["forms"][0]["inputs"] == ["q"]
    assert cmap["api_endpoints"][0]["path"] == "/api/search"
    assert any(row["path"] == "/api/comment" and row["artifact_id"] == "capture-9"
               for row in cmap["api_endpoints"])
    assert cmap["js_files"] == ["https://app.example/static/app.js"]
    assert cmap["js_sources"][0]["artifact_id"] == "script-9"
    assert cmap["has_api"] is True
    assert {row["name"] for row in cmap["parameter_inventory"]} >= {
        "q", "term", "draft", "/comment/text",
    }
    assert next(row for row in cmap["parameter_inventory"]
                if row["name"] == "/comment/text")["artifact_id"] == "capture-9"


def test_browser_link_query_names_reach_parameter_inventory_without_values():
    hrefs = [
        "https://app.example/catalog?category=Gifts&searchTerm=private-value",
        "https://app.example/catalog?category=Other",
        "https://other.example/catalog?outside=1",
        "https://app.example/delete?unsafe=1",
    ]
    inputs = _link_query_inputs(hrefs, ["https://app.example"])
    assert inputs == [{"path": "/catalog", "query_keys": ["category", "searchTerm"]}]
    observation = {
        "signal": "browser_crawl",
        "result": {
            "target_template": "https://app.example/",
            "final_origin": "https://app.example",
            "pages": [{"url": "https://app.example/", "status": 200,
                       "link_query_inputs": inputs}],
        },
    }
    cmap = bridge.capability_map_from_observation(observation)
    catalog = [row for row in cmap["parameter_inventory"] if row["path"] == "/catalog"]
    assert {(row["name"], row["source"]) for row in catalog} == {
        ("category", "browser_link"), ("searchTerm", "browser_link"),
    }
    assert "private-value" not in str(cmap)


@pytest.mark.asyncio
async def test_scoped_browser_observation_persists_on_bound_asset(monkeypatch):
    from app.services.agent import tools as agent_tools
    from app.services.agent.tools import ASMToolsManager
    from app.services import sitemap_service

    binding = SimpleNamespace(asset_id=14, allowed_origin="https://app.example")
    db = _DB(binding)
    db.close = lambda: None
    monkeypatch.setattr(agent_tools, "SessionLocal", lambda: db)
    monkeypatch.setattr(agent_tools, "get_tenant_context", lambda: (8, 4))
    async def fake_hunter(*_args, **_kwargs):
        return {
            "run_id": "a" * 32, "signal": "browser_inspect_js",
            "result": {
                "target_template": "https://app.example/",
                "final_origin": "https://app.example", "final_path": "/",
                "status": 200,
                "requests": [{"method": "GET", "path": "/app.js",
                              "resource_type": "script"}],
            },
        }
    monkeypatch.setattr(bridge, "hunter_operation", fake_hunter)
    saved = []
    monkeypatch.setattr(sitemap_service, "persist_capability_map_safe",
                        lambda *args, **kwargs: saved.append((args, kwargs)) or 1)
    token = agent_tools.current_session_id.set("session-1")
    try:
        manager = ASMToolsManager()
        result = await manager.scoped_assessment_observe("browser_inspect_js", {})
    finally:
        agent_tools.current_session_id.reset(token)
    assert result["success"] is True
    assert result["capability_map"]["js_files"] == ["https://app.example/app.js"]
    assert saved[0][0][0] == 4
    assert saved[0][1]["asset_id"] == 14
    assert saved[0][1]["source"] == "scoped_assessment"


def test_scoped_operations_are_available_to_aegis_agent(monkeypatch):
    from app.core import config
    from app.services.agent import prompts
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager()
    for name in ("scoped_assessment_observe", "scoped_assessment_probe",
                 "scoped_assessment_candidate", "scoped_assessment_status",
                 "scoped_assessment_publish", "scoped_assessment_plan",
                 "scoped_assessment_memory"):
        assert callable(manager.get_tool(name))
    assert prompts.is_tool_allowed_in_phase("scoped_assessment_observe", "informational")
    assert not prompts.is_tool_allowed_in_phase("scoped_assessment_probe", "informational")
    assert prompts.is_tool_allowed_in_phase("scoped_assessment_probe", "exploitation")

    monkeypatch.setattr(config, "settings", SimpleNamespace(
        PROWL_ASSESSMENT_URL="http://prowl-assessment:8833", PROWL_ADMIN_TOKEN="admin",
    ))
    assert "scoped_assessment_observe" in prompts.get_phase_tools("informational")
    assert "scoped_assessment_plan" in prompts.get_phase_tools("informational")
    assert "scoped_assessment_memory" in prompts.get_phase_tools("informational")
    assert "scoped_assessment_probe" in prompts.get_phase_tools("exploitation")


class _Query:
    def __init__(self, row=None):
        self.row = row

    def filter_by(self, **_filters):
        return self

    def first(self):
        return self.row


class _DB:
    def __init__(self, row=None):
        self.row = row
        self.added = None

    def query(self, _model):
        return _Query(self.row)

    def add(self, row):
        self.added = row

    def commit(self):
        pass

    def refresh(self, _row):
        pass


@pytest.mark.asyncio
async def test_provision_keeps_service_tokens_encrypted(monkeypatch):
    monkeypatch.setenv("API_KEY_ENCRYPTION_KEY", "scoped-assessment-test-key")
    monkeypatch.setattr(bridge, "settings", SimpleNamespace(PROWL_ADMIN_TOKEN="admin-secret"))
    seen = []

    async def fake_request(method, path, token, body):
        seen.append((method, path, token, body))
        return {
            "run_id": "a" * 32, "organization_id": 4, "asset_id": 14,
            "allowed_origins": ["https://app.example"],
            "hunter_token": "hunter-secret", "verifier_token": "verifier-secret",
        }

    monkeypatch.setattr(bridge, "_request", fake_request)
    db = _DB()
    binding = await bridge.provision_run(
        db, organization_id=4, user_id=8, session_id="session-1",
        asset=_asset(), origin="https://app.example",
    )
    assert seen[0][2] == "admin-secret"
    assert binding.hunter_token() == "hunter-secret"
    assert binding.verifier_token() == "verifier-secret"
    assert "hunter-secret" not in binding.hunter_token_encrypted
    assert "verifier-secret" not in binding.verifier_token_encrypted


@pytest.mark.asyncio
async def test_hunter_tool_cannot_select_verifier_or_arbitrary_path(monkeypatch):
    calls = []

    async def fake_request(method, path, token, body):
        calls.append((method, path, token, body))
        return {"run_id": "a" * 32, "kind": "observation", "artifact_ids": ["proof-1"]}

    monkeypatch.setattr(bridge, "_request", fake_request)
    binding = SimpleNamespace(
        service_run_id="a" * 32,
        hunter_token=lambda: "hunter-secret",
        verifier_token=lambda: "verifier-secret",
    )
    db = _DB(binding)
    result = await bridge.hunter_operation(
        db, organization_id=4, user_id=8, session_id="session-1",
        operation="browser_map", body={"url": "https://app.example"},
    )
    assert result["artifact_ids"] == ["proof-1"]
    assert calls[0][2] == "hunter-secret"
    assert "verifier-secret" not in repr(result)
    with pytest.raises(ValueError):
        await bridge.hunter_operation(
            db, organization_id=4, user_id=8, session_id="session-1",
            operation="../../candidates/verify", body={},
        )
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_agent_can_update_coverage_and_recall_scoped_memory(monkeypatch):
    calls = []

    async def fake_request(method, path, token, body):
        calls.append((method, path, token, body))
        return {"run_id": "a" * 32}

    monkeypatch.setattr(bridge, "_request", fake_request)
    binding = SimpleNamespace(service_run_id="a" * 32,
                              hunter_token=lambda: "hunter-secret")
    db = _DB(binding)
    await bridge.hunter_operation(
        db, organization_id=4, user_id=8, session_id="session-1",
        operation="coverage_update",
        body={"coverage_id": "b" * 32, "status": "tested", "evidence_ids": ["proof-1"]},
    )
    await bridge.hunter_operation(
        db, organization_id=4, user_id=8, session_id="session-1",
        operation="memory_recall", body={"target": "https://app.example/admin"},
    )
    assert calls[0] == (
        "POST", f"/v1/runs/{'a' * 32}/coverage/{'b' * 32}", "hunter-secret",
        {"status": "tested", "evidence_ids": ["proof-1"]},
    )
    assert calls[1][1].endswith("/memory/recall")
    assert calls[1][2] == "hunter-secret"
    with pytest.raises(ValueError, match="Invalid coverage ID"):
        await bridge.hunter_operation(
            db, organization_id=4, user_id=8, session_id="session-1",
            operation="coverage_update", body={"coverage_id": "../verify"},
        )
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_fresh_verifier_uses_separate_capability_and_publishes_only_after_confirmation(monkeypatch):
    calls = []
    candidate_id = "b" * 32
    run_id = "a" * 32
    target = "https://app.example/search?q=__PROWL_NONCE__"

    async def fake_request(method, path, token, body=None):
        calls.append((method, path, token, body))
        if method == "GET":
            return {"run_id": run_id, "candidate_id": candidate_id,
                    "target": target, "status": "pending"}
        if path.endswith("/browser/check-xss"):
            return {"run_id": run_id, "actor": "verifier",
                    "result": {"executed": True}, "artifact_ids": ["fresh-proof"]}
        if path.endswith("/verify"):
            return {"verification_id": "c" * 32}
        return {"platform_finding_id": "91"}

    monkeypatch.setattr(bridge, "_request", fake_request)
    binding = SimpleNamespace(
        service_run_id=run_id,
        hunter_token=lambda: "hunter-secret",
        verifier_token=lambda: "verifier-secret",
    )
    result = await bridge.verify_candidate_with_fresh_proof(
        _DB(binding), organization_id=4, user_id=8, session_id="session-1",
        candidate_id=candidate_id, recipe="browser_xss",
    )
    assert result["verdict"] == "confirmed"
    assert result["publication"]["platform_finding_id"] == "91"
    assert len(calls) == 4
    assert all(call[2] == "verifier-secret" for call in calls)
    assert calls[2][3]["evidence_ids"] == ["fresh-proof"]


@pytest.mark.asyncio
async def test_inconclusive_verifier_does_not_publish(monkeypatch):
    calls = []
    candidate_id = "b" * 32
    run_id = "a" * 32

    async def fake_request(method, path, token, body=None):
        calls.append(path)
        if method == "GET":
            return {"run_id": run_id, "candidate_id": candidate_id,
                    "target": "https://app.example/private/", "status": "pending"}
        if path.endswith("/http/get"):
            return {"run_id": run_id, "actor": "verifier",
                    "result": {"directory_index": False, "status": 403, "truncated": False},
                    "artifact_ids": ["fresh-proof"]}
        return {"verification_id": "c" * 32}

    monkeypatch.setattr(bridge, "_request", fake_request)
    binding = SimpleNamespace(service_run_id=run_id, verifier_token=lambda: "verifier-secret")
    result = await bridge.verify_candidate_with_fresh_proof(
        _DB(binding), organization_id=4, user_id=8, session_id="session-1",
        candidate_id=candidate_id, recipe="public_directory_index",
    )
    assert result["verdict"] == "inconclusive"
    assert result["publication"] is None
    assert not any(path.endswith("/publish") for path in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("recipe,target,identity,parameter,proof_path,proof_result", [
    ("numeric_sqli", "https://app.example/api/items?id=7", "member", "id",
     "/http/sqli-boolean", {"proof_confirmed": True, "parameter": "id"}),
    ("owner_only_authz", "https://app.example/api/items?id=7", "owner", "",
     "/http/authz-owner-only", {"proof_confirmed": True, "owner_identity": "owner"}),
])
async def test_fresh_browser_capture_supports_sql_and_owner_proof(
    monkeypatch, recipe, target, identity, parameter, proof_path, proof_result,
):
    calls = []
    run_id, candidate_id = "a" * 32, "b" * 32
    capture_id = "fresh-browser-exchange"

    async def fake_request(method, path, token, body=None):
        calls.append((method, path, token, body))
        if method == "GET":
            return {"run_id": run_id, "candidate_id": candidate_id,
                    "status": "pending", "target": target}
        if path.endswith("/browser/inspect-js"):
            return {"run_id": run_id, "actor": "verifier", "result": {"traffic": [{
                "method": "GET", "path": "/api/items", "query_keys": ["id"],
                "query_fields": [{"name": "id", "value_type": "positive_integer"}],
                "artifact_id": capture_id,
            }]}}
        if path.endswith(proof_path):
            return {"run_id": run_id, "actor": "verifier", "artifact_ids": ["fresh-proof"],
                    "result": {"target": target, "captured_artifact_id": capture_id,
                               **proof_result}}
        if path.endswith("/verify"):
            return {"verification_id": "c" * 32}
        return {"platform_finding_id": "91"}

    monkeypatch.setattr(bridge, "_request", fake_request)
    binding = SimpleNamespace(service_run_id=run_id,
                              allowed_origin="https://app.example",
                              verifier_token=lambda: "verifier-secret")
    result = await bridge.verify_candidate_with_fresh_proof(
        _DB(binding), organization_id=4, user_id=8, session_id="session-1",
        candidate_id=candidate_id, recipe=recipe, identity=identity,
        page_url="https://app.example/dashboard", parameter=parameter,
    )
    assert result["verdict"] == "confirmed"
    assert result["publication"]["platform_finding_id"] == "91"
    assert all(call[2] == "verifier-secret" for call in calls)
    assert calls[2][3]["artifact_id"] == capture_id
    assert calls[3][3]["evidence_ids"] == ["fresh-proof"]


@pytest.mark.asyncio
async def test_ambiguous_verifier_capture_stays_pending(monkeypatch):
    calls = []
    run_id, candidate_id = "a" * 32, "b" * 32

    async def fake_request(method, path, token, body=None):
        calls.append(path)
        if method == "GET":
            return {"run_id": run_id, "candidate_id": candidate_id,
                    "status": "pending", "target": "https://app.example/api/items?id=7"}
        return {"run_id": run_id, "actor": "verifier", "result": {"traffic": [
            {"method": "GET", "path": "/api/items", "query_keys": ["id"],
             "query_fields": [{"name": "id", "value_type": "positive_integer"}],
             "artifact_id": artifact_id}
            for artifact_id in ("first", "second")
        ]}}

    monkeypatch.setattr(bridge, "_request", fake_request)
    binding = SimpleNamespace(service_run_id=run_id,
                              allowed_origin="https://app.example",
                              verifier_token=lambda: "verifier-secret")
    with pytest.raises(ValueError, match="one matching GET"):
        await bridge.verify_candidate_with_fresh_proof(
            _DB(binding), organization_id=4, user_id=8, session_id="session-1",
            candidate_id=candidate_id, recipe="numeric_sqli", identity="member",
            page_url="https://app.example/dashboard", parameter="id",
        )
    assert len(calls) == 2
