"""Scoped observations are saved on their bound asset without secret values."""

from types import SimpleNamespace

from app.models.asset import Asset
from app.models.sitemap_entry import SitemapEntry
from app.models.scoped_assessment_run import ScopedAssessmentRun
from app.services.sitemap_service import persist_capability_map, persist_js_review_safe


class _Query:
    def __init__(self, db, model):
        self.db = db
        self.model = model

    def filter(self, *_args):
        return self

    def filter_by(self, **_kwargs):
        return self

    def first(self):
        if self.model is Asset:
            return self.db.asset
        if self.model is ScopedAssessmentRun:
            return self.db.binding
        return None

    def all(self):
        return []


class _DB:
    def __init__(self, asset):
        self.asset = asset
        self.binding = None
        self.added = []
        self.committed = False

    def query(self, model):
        return _Query(self, model)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.committed = True

    def rollback(self):
        pass

    def close(self):
        pass


def _asset(value="https://app.test/"):
    return SimpleNamespace(
        id=7, organization_id=3, value=value, live_url=None,
        endpoints=["/existing"], parameters=["existing_param"], js_files=[],
        rest_endpoints=[], api_specs=[], metadata_={"owner": "team"},
    )


def test_scoped_map_updates_url_asset_and_related_sitemap():
    asset = _asset()
    asset.live_url = "https://other.test/"
    db = _DB(asset)
    cmap = {
        "target": "https://app.test/", "scope": "https://app.test",
        "pages_visited": ["https://app.test/search?q=private-value"],
        "js_files": ["https://app.test/static/app.js?v=secret-value",
                     "https://evil.test/offscope.js"],
        "api_endpoints": [
            {"host": "app.test", "method": "GET", "path": "/api/items",
             "query_keys": ["id"], "status": 200, "source": "browser_traffic"},
            {"host": "evil.test", "method": "GET", "path": "/api/evil"},
            {"host": "app.test", "method": "GET", "path": "//evil.test/api/proxy"},
            {"host": "app.test", "method": "GET",
             "path": "https://evil.test/api/claimed"},
            {"host": "app.test", "method": "GET",
             "path": "https://app.test:8443/api/other-port"},
        ],
        "api_samples": [{"method": "POST", "url": "https://evil.test/api/write",
                         "status": 200}],
        "parameter_inventory": [{"method": "GET", "path": "/search",
                                 "name": "q", "location": "query"}],
    }
    count = persist_capability_map(
        db, 3, cmap, source="scoped_assessment", asset_id=7,
    )
    assert count > 0
    assert "/existing" in asset.endpoints
    assert "/search" in asset.endpoints and "/api/items" in asset.endpoints
    assert "/api/evil" not in asset.endpoints
    assert "/api/proxy" not in asset.endpoints
    assert "/api/claimed" not in asset.endpoints
    assert "/api/other-port" not in asset.endpoints
    assert asset.js_files == ["https://app.test/static/app.js"]
    assert {"existing_param", "q", "id"}.issubset(set(asset.parameters))
    assert any(row["path"] == "/api/items" and row["parameters"] == ["id"]
               and row["status"] == 200 for row in asset.rest_endpoints)
    assert not any(row["path"] == "/api/write" for row in asset.rest_endpoints)
    assert not any(row["path"] in {"/api/proxy", "/api/claimed", "/api/other-port"}
                   for row in asset.rest_endpoints)
    assert all(not (isinstance(row, SitemapEntry) and row.host == "evil.test"
                    and row.kind == "api") for row in db.added)
    assert any(isinstance(row, SitemapEntry) and row.host == "app.test"
               and row.kind == "api" for row in db.added)
    assert asset.metadata_["owner"] == "team"
    assert asset.metadata_["assessment_api_fingerprint"]["observed_api_metadata_count"] == 1
    assert "private-value" not in repr(asset.__dict__)
    assert "secret-value" not in repr(asset.__dict__)


def test_scoped_map_rejects_bound_asset_host_mismatch():
    asset = _asset("https://other.test/")
    db = _DB(asset)
    assert persist_capability_map(
        db, 3, {"target": "https://app.test/", "scope": "https://app.test",
                "js_files": ["https://app.test/app.js"]},
        source="scoped_assessment", asset_id=7,
    ) == 0
    assert asset.js_files == [] and not db.added


def test_js_review_receipt_updates_bound_asset_without_secret_values(monkeypatch):
    asset = _asset()
    db = _DB(asset)
    db.binding = SimpleNamespace(asset_id=7, allowed_origin="https://app.test")
    monkeypatch.setattr("app.db.database.SessionLocal", lambda: db)
    assert persist_js_review_safe(
        3, "session-1", "https://app.test/app.js",
        {"status": "in_focus", "counts": {"gitleaks": 1, "regex": 2,
                                           "client_signing": 0},
         "secret_value": "never-store-this"},
        "evidence-1",
    )
    assert db.committed
    review = asset.metadata_["assessment_js_reviews"][0]
    assert review["url"] == "https://app.test/app.js"
    assert review["counts"] == {"gitleaks": 1, "regex": 2, "client_signing": 0}
    assert review["evidence_id"] == "evidence-1"
    assert asset.js_files == ["https://app.test/app.js"]
    assert "never-store-this" not in repr(asset.__dict__)
    assert not persist_js_review_safe(
        3, "session-1", "https://evil.test/app.js",
        {"status": "in_focus", "counts": {}}, "evidence-2",
    )
    assert len(asset.metadata_["assessment_js_reviews"]) == 1
