"""Tests for dual Interceptor recon envelope + job preference helpers."""

from app.services.recon_envelope import envelope_from_normalized
from app.services.recon_jobs_service import DEFAULT_PREFER, WORKER_KINDS


def test_envelope_from_normalized_builds_capability_map():
    normalized = {
        "target": "https://www.emulate3d.com/",
        "scope": "emulate3d.com",
        "engine": "interceptor",
        "pages_visited": [
            "https://www.emulate3d.com/",
            "https://www.emulate3d.com/products",
            "https://www.emulate3d.com/contact",
        ],
        "api_calls": {
            "www.emulate3d.com": ["GET /api/v1/products", "POST /api/contact"],
        },
        "js_files": ["https://www.emulate3d.com/static/app.js"],
        "endpoints_from_js": ["/api/v1/products"],
        "websockets": [],
        "sse": [],
        "source_maps": [],
        "third_party": ["cdn.example.com"],
        "forms": [{"action": "/login", "inputs": ["email", "password"]}],
        "errors": [],
        "authenticated": None,
    }
    env = envelope_from_normalized(normalized, note="unit-test")
    assert env["success"] is True
    assert env["capability_map"]
    assert env["capability_map"]["target"] == "https://www.emulate3d.com/"
    assert env["capability_map"].get("has_api") is True
    assert "unit-test" in env["output"]
    assert env["normalized"]["engine"] == "interceptor"


def test_worker_kinds_and_prefer_order():
    assert WORKER_KINDS == ("mac", "ubuntu")
    assert DEFAULT_PREFER == ["mac", "ubuntu"]
