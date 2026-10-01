"""The agent bridge must keep scope and service capabilities out of model I/O."""

from types import SimpleNamespace

import pytest

from app.models.asset import AssetType
from app.services.agent import scoped_assessment as bridge


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
            "requests": [{"resource_type": "xhr", "method": "GET", "path": "/api/search"}],
        },
    }
    cmap = bridge.capability_map_from_observation(observation)
    assert cmap["pages_visited"] == ["https://app.example/"]
    assert cmap["forms"][0]["inputs"] == ["q"]
    assert cmap["api_endpoints"][0]["path"] == "/api/search"
    assert cmap["has_api"] is True


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
