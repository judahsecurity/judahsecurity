"""REST inventory on the asset: OpenAPI parse + Vespasian capability-map rows."""

from types import SimpleNamespace

from app.services.rest_inventory_service import (
    ACCESS_NO_AUTH,
    ACCESS_REQUIRED,
    endpoints_from_openapi,
    hydrate_rest_from_existing,
    looks_like_rest,
    merge_rest_endpoints,
    normalize_api_path,
    rest_rows_from_capability_map,
    store_openapi_spec,
    summarize_rest,
    to_openapi_yaml,
)


def test_normalize_path_clusters_ids():
    assert normalize_api_path("/consent/abc/it.json") == "/consent/abc/it.json"
    assert (
        normalize_api_path("/consent/eaabdb57-a37e-4cc7-8553-1731316aa39d.json")
        == "/consent/{id}.json"
    )
    assert normalize_api_path("/users/42/profile") == "/users/{id}/profile"


def test_looks_like_rest_keeps_xhr_not_static():
    assert looks_like_rest("POST", "/newsletter_signup")
    assert looks_like_rest("POST", "/quick-contact.php")
    assert looks_like_rest("GET", "/api/config.json")
    assert looks_like_rest("GET", "/cookieconsentpub/v1/geo/location")
    assert looks_like_rest("POST", "/g/collect")
    assert not looks_like_rest("GET", "/about")
    assert not looks_like_rest("GET", "/static/app.js")


def test_openapi_paths_become_vespasian_rows():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Demo"},
        "security": [{"apiKey": []}],
        "paths": {
            "/api/config.json": {
                "get": {
                    "parameters": [
                        {"name": "env", "in": "query"},
                        {"name": "locale", "in": "query"},
                    ],
                    "security": [{"apiKey": []}],
                    "responses": {"403": {"description": "auth"}},
                }
            },
            "/newsletter_signup": {
                "post": {
                    "security": [],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
    rows = endpoints_from_openapi(spec)
    by_path = {(r["method"], r["path"]): r for r in rows}
    cfg = by_path[("GET", "/api/config.json")]
    assert cfg["access"] == ACCESS_REQUIRED
    assert cfg["status"] == 403
    assert cfg["param_count"] == 2
    signup = by_path[("POST", "/newsletter_signup")]
    assert signup["access"] == ACCESS_NO_AUTH
    assert signup["status"] == 200


def test_capability_map_writes_observed_xhr_and_forms():
    rows = rest_rows_from_capability_map(
        {
            "api_endpoints": [
                {"method": "GET", "path": "/about"},
                {"method": "GET", "path": "/api/config.json"},
                {"method": "POST", "path": "/g/collect"},
            ],
            "api_samples": [
                {
                    "method": "GET",
                    "url": "https://www.example.com/consent/abc/it.json",
                    "headers": {},
                    "status": 200,
                }
            ],
            "forms": [
                {
                    "method": "POST",
                    "action": "/newsletter_signup",
                    "inputs": ["email"],
                }
            ],
        }
    )
    paths = {(r["method"], r["path"]) for r in rows}
    assert ("GET", "/about") not in paths
    assert ("GET", "/api/config.json") in paths
    assert ("POST", "/g/collect") in paths
    assert ("GET", "/consent/abc/it.json") in paths
    assert ("POST", "/newsletter_signup") in paths
    sample = next(r for r in rows if r["path"] == "/consent/abc/it.json")
    assert sample["status"] == 200


def test_merge_and_summary_on_asset():
    asset = SimpleNamespace(rest_endpoints=[], api_specs=[], value="www.example.com")
    merge_rest_endpoints(
        asset,
        [
            {"method": "GET", "path": "/api/config.json", "status": 403, "parameters": ["env"]},
            {"method": "POST", "path": "/newsletter_signup", "status": 200},
        ],
        source="vespasian",
    )
    summary = summarize_rest(asset)
    assert summary["endpoint_count"] == 2
    assert summary["unauthenticated_count"] == 1
    assert summary["method_count"] == 2
    assert summary["discovered_by"] == "vespasian"
    yaml_text = to_openapi_yaml(asset)
    assert yaml_text and "/api/config.json" in yaml_text


def test_store_spec_and_hydrate_from_katana_metadata():
    asset = SimpleNamespace(
        rest_endpoints=[],
        api_specs=[],
        value="www.example.com",
        metadata_={"katana_api_endpoints": ["https://www.example.com/api/v1/users"]},
    )
    spec = {
        "openapi": "3.0.1",
        "info": {"title": "Katana"},
        "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    store_openapi_spec(asset, url="https://www.example.com/openapi.json", spec=spec, source="openapi")
    assert any(e["path"] == "/health" for e in asset.rest_endpoints)

    empty = SimpleNamespace(
        rest_endpoints=[],
        api_specs=[],
        value="www.example.com",
        metadata_={"katana_api_endpoints": ["https://www.example.com/api/config.json"]},
    )
    n = hydrate_rest_from_existing(empty)
    assert n >= 1
    assert empty.rest_endpoints[0]["path"] == "/api/config.json"
