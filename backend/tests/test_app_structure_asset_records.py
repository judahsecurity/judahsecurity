"""Application Structure includes scoped observations stored on URL assets."""

from types import SimpleNamespace

import pytest

from app.api.routes.app_structure import get_app_structure_by_asset
from app.models.asset import Asset


class _Query:
    def __init__(self, model, asset):
        self.model = model
        self.asset = asset

    def filter(self, *_args):
        return self

    def order_by(self, *_args):
        return self

    def first(self):
        return self.asset if self.model is Asset else None

    def all(self):
        return []


class _DB:
    def __init__(self, asset):
        self.asset = asset

    def query(self, model):
        return _Query(model, self.asset)


@pytest.mark.asyncio
async def test_url_asset_shows_first_party_js_outside_its_stored_path(monkeypatch):
    asset = SimpleNamespace(
        id=7, organization_id=3, value="https://app.test/login",
        root_domain=None, endpoints=["/login"], parameters=["q"],
        js_files=["https://app.test/static/app.js", "https://evil.test/app.js"],
        login_portals=[], rest_endpoints=[], api_specs=[],
    )
    monkeypatch.setattr("app.services.sitemap_service.hydrate_from_asset_json",
                        lambda *_args: 0)
    monkeypatch.setattr("app.services.sitemap_service.entries_for_asset",
                        lambda *_args, **_kwargs: [])

    response = await get_app_structure_by_asset(
        7, db=_DB(asset),
        current_user=SimpleNamespace(
            role=SimpleNamespace(value="analyst"), organization_id=3,
        ),
    )

    assert response.js_files == ["https://app.test/static/app.js"]
    assert response.summary.total_js_files == 1
    assert "/login" in response.paths and "q" in response.parameters
