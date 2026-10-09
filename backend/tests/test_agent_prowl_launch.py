"""Normal Agent launches bind only an exact in-scope PROWL origin."""

from types import SimpleNamespace

import pytest

from app.api.routes import agent as agent_routes
from app.models.asset import Asset, AssetType
from app.models.scoped_assessment_run import ScopedAssessmentRun


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter_by(self, **_kwargs):
        return self

    def filter(self, *_args):
        return self

    def limit(self, _count):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows


class _DB:
    def __init__(self, assets=(), binding=None):
        self.assets = list(assets)
        self.binding = binding

    def query(self, model):
        if model is ScopedAssessmentRun:
            return _Query([self.binding] if self.binding else [])
        assert model is Asset
        return _Query(self.assets)


@pytest.mark.asyncio
async def test_agent_launch_keeps_standard_mode_when_prowl_is_unconfigured(monkeypatch):
    monkeypatch.setattr(agent_routes.settings, "PROWL_ASSESSMENT_URL", "")
    monkeypatch.setattr(agent_routes.settings, "PROWL_ADMIN_TOKEN", "")
    assert await agent_routes._bind_agent_assessment(
        _DB(), organization_id=2, user_id=3, session_id="session-1",
        mode="agent", target="https://ginandjuice.shop", question="Assess the site",
    ) is None


@pytest.mark.asyncio
async def test_agent_launch_provisions_exact_in_scope_asset(monkeypatch):
    monkeypatch.setattr(agent_routes.settings, "PROWL_ASSESSMENT_URL", "http://prowl-assessment:8833")
    monkeypatch.setattr(agent_routes.settings, "PROWL_ADMIN_TOKEN", "test-admin")
    asset = SimpleNamespace(id=14, value="ginandjuice.shop", asset_type=AssetType.DOMAIN,
                            in_scope=True)
    binding = SimpleNamespace(allowed_origin="https://ginandjuice.shop")
    calls = []

    async def fake_provision(_db, **kwargs):
        calls.append(kwargs)
        return binding

    monkeypatch.setattr(agent_routes, "provision_run", fake_provision)
    result = await agent_routes._bind_agent_assessment(
        _DB([asset]), organization_id=2, user_id=3, session_id="session-1",
        mode="agent", target=None, question="Assess https://ginandjuice.shop/catalog",
        assessment_policy={"body_replay_paths": ["/catalog/subscribe"]},
    )
    assert result is binding
    assert len(calls) == 1
    assert calls[0]["asset"] is asset
    assert calls[0]["origin"] == "https://ginandjuice.shop"
    assert calls[0]["body_replay_paths"] == ["/catalog/subscribe"]


@pytest.mark.asyncio
async def test_agent_launch_rejects_other_or_out_of_scope_asset(monkeypatch):
    monkeypatch.setattr(agent_routes.settings, "PROWL_ASSESSMENT_URL", "http://prowl-assessment:8833")
    monkeypatch.setattr(agent_routes.settings, "PROWL_ADMIN_TOKEN", "test-admin")
    wrong = SimpleNamespace(id=15, value="example.com", asset_type=AssetType.DOMAIN,
                            in_scope=True)
    with pytest.raises(ValueError, match="exact host"):
        await agent_routes._bind_agent_assessment(
            _DB([wrong]), organization_id=2, user_id=3, session_id="session-1",
            mode="agent", target="https://ginandjuice.shop", question="Assess the site",
        )
    excluded = SimpleNamespace(id=16, value="ginandjuice.shop", asset_type=AssetType.DOMAIN,
                               in_scope=False)
    with pytest.raises(ValueError, match="exact host"):
        await agent_routes._bind_agent_assessment(
            _DB([excluded]), organization_id=2, user_id=3, session_id="session-2",
            mode="agent", target="https://ginandjuice.shop", question="Assess the site",
        )


@pytest.mark.asyncio
async def test_agent_followup_reuses_binding_without_switching_origin(monkeypatch):
    monkeypatch.setattr(agent_routes.settings, "PROWL_ASSESSMENT_URL", "http://prowl-assessment:8833")
    monkeypatch.setattr(agent_routes.settings, "PROWL_ADMIN_TOKEN", "test-admin")
    binding = SimpleNamespace(allowed_origin="https://ginandjuice.shop")
    db = _DB(binding=binding)
    assert await agent_routes._bind_agent_assessment(
        db, organization_id=2, user_id=3, session_id="session-1", mode="agent",
        target=None, question="Compare this with https://example.com",
    ) is binding
    with pytest.raises(ValueError, match="already bound"):
        await agent_routes._bind_agent_assessment(
            db, organization_id=2, user_id=3, session_id="session-1", mode="agent",
            target="https://example.com", question="Switch target",
        )
