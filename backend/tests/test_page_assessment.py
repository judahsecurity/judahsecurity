"""Human-like page assessment: start hunts from what the page showed."""

from types import SimpleNamespace

from app.services.agent.capability_map import (
    build_capability_map_from_crawl,
    select_specialists_for_map,
)
from app.services.agent.page_assessment import (
    assess_page,
    classify_app_kind,
    specialists_from_assessment,
    start_here_from_observations,
)


def _crawl(**overrides):
    base = dict(
        target="https://app.example.com",
        scope="example.com",
        authenticated=False,
        pages_visited=[
            "https://app.example.com/",
            "https://app.example.com/login",
            "https://app.example.com/search?q=test",
            "https://app.example.com/admin",
        ],
        forms=[
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://app.example.com/login",
            },
            {
                "method": "GET",
                "action": "/search",
                "inputs": ["q"],
                "page": "https://app.example.com/search",
            },
        ],
        api_calls={"app.example.com": {"GET /api/users?id=1", "POST /api/webhooks?url=https://x"}},
        js_files={"https://app.example.com/static/app.js"},
        endpoints_from_js={"/api/v1/items"},
        websockets=set(),
        sse=set(),
        source_maps=set(),
        third_party=set(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_saas_starts_with_login_and_idor_not_nuclei():
    cmap = build_capability_map_from_crawl(_crawl())
    assert cmap.assessment
    assert cmap.assessment["app_kind"] in ("saas", "mixed")
    start = [r["specialist"] for r in cmap.assessment["start_here"]]
    assert "credential_assault" in start or "auth_logic" in start
    assert "api_authz" in start
    assert start[0] != "coverage"
    assert "Nuclei" in (cmap.assessment.get("do_not_start_with") or "")


def test_search_page_starts_xss_not_combined_injection():
    cmap = build_capability_map_from_crawl(_crawl())
    hunts = [r["hunt"] for r in cmap.assessment["start_here"]]
    assert "xss" in hunts
    names = select_specialists_for_map(cmap)
    assert "xss" in names
    assert "independent_verifier" not in names
    assert "risk_assessor" not in names


def test_empty_root_starts_with_dir_brute():
    assessment = assess_page(
        None,
        kickoff={"needs_dir_brute": True, "brief": "EMPTY/404 SURFACE: brute dirs"},
    )
    assert assessment["app_kind"] == "empty"
    assert assessment["start_here"][0]["specialist"] == "content_api"


def test_spa_without_apis_reconstructs_js_first():
    cmap = build_capability_map_from_crawl(
        _crawl(
            pages_visited=["https://app.example.com/"],
            forms=[],
            api_calls={},
            endpoints_from_js=set(),
            js_files={
                "https://app.example.com/_next/static/chunks/main.js",
                "https://app.example.com/_next/static/chunks/app.js",
                "https://app.example.com/_next/static/chunks/webpack.js",
            },
        )
    )
    assert cmap.has_spa_signals
    kind = classify_app_kind(cmap)
    assert kind in ("spa", "marketing", "mixed")
    start = start_here_from_observations(cmap)
    specs = [r["specialist"] for r in start]
    if kind == "spa":
        assert specs[0] == "spa_client" or "spa_client" in specs


def test_appsmith_kickoff_is_login_wall_not_wordpress():
    assessment = assess_page(
        None,
        kickoff={
            "brief": "Product: Appsmith (low-code). SPA catch-all.",
            "technologies": ["Tailwind CSS", "HSTS"],
            "hits": [
                {
                    "kind": "root",
                    "title": "Appsmith",
                    "status": 200,
                    "product": "appsmith",
                    "content_type": "text/html",
                    "snippet": "<!doctype html><title>Appsmith</title>",
                },
                {
                    "kind": "path",
                    "path": "wp-json/wp/v2/users",
                    "status": 200,
                    "spa_shell": True,
                    "content_type": "text/html",
                    "title": "Appsmith",
                },
                {
                    "kind": "path",
                    "path": "user/login",
                    "status": 200,
                    "spa_shell": True,
                    "content_type": "text/html",
                    "title": "Appsmith",
                },
                {
                    "kind": "path",
                    "path": "api/v1/tenants/current",
                    "status": 200,
                    "content_type": "application/json",
                    "snippet": '{"responseMeta":{"status":200}}',
                },
            ],
        },
    )
    assert assessment["app_kind"] == "login_wall"
    hunts = [r["hunt"] for r in assessment["start_here"]]
    assert "wordpress" not in hunts
    assert "credential_assault" in hunts or "spa_client" in hunts
    assert "ssrf" in hunts
    assert "sqli" in hunts
    assert hunts.index("spa_client") < hunts.index("ssrf") or hunts.index("credential_assault") < hunts.index("ssrf")


def test_wordpress_kickoff_aims_rest_and_ajax_before_wpscan_spray():
    assessment = assess_page(
        None,
        kickoff={
            "brief": "CMS: WordPress is in-play now",
            "technologies": ["WordPress:6.4"],
            "hits": [{"kind": "path", "path": "wp-admin", "status": 302}],
        },
    )
    assert assessment["app_kind"] == "wordpress"
    assert any(r["specialist"] == "injection" for r in assessment["start_here"])
    assert any(r.get("hunt") == "wordpress" for r in assessment["start_here"])


def test_auto_dispatch_is_not_nuclei_first():
    cmap = build_capability_map_from_crawl(_crawl())
    names = select_specialists_for_map(cmap)
    assert names[0] != "coverage"
    assert "Nuclei" in (cmap.assessment.get("do_not_start_with") or "")
    start = [r["specialist"] for r in cmap.assessment["start_here"]]
    assert start[0] in ("credential_assault", "auth_logic", "api_authz", "xss", "content_api")


def test_login_wall_starts_sqli_on_login_fields():
    cmap = build_capability_map_from_crawl(
        _crawl(
            pages_visited=["https://app.example.com/login"],
            forms=[
                {
                    "method": "POST",
                    "action": "/login",
                    "inputs": ["username", "password"],
                    "page": "https://app.example.com/login",
                }
            ],
            api_calls={},
        )
    )
    start = cmap.assessment["start_here"]
    specs = [r["specialist"] for r in start]
    hunts = [r["hunt"] for r in start]
    assert "sqli" in specs
    assert "login_injection" in hunts or "sqli" in hunts
    assert specs[0] != "coverage"


def test_appsmith_login_wall_does_not_aim_login_field_sqli():
    assessment = assess_page(
        None,
        kickoff={
            "brief": "Product: Appsmith (low-code). SPA catch-all.",
            "technologies": ["Tailwind CSS"],
            "hits": [
                {
                    "kind": "path",
                    "path": "user/login",
                    "status": 200,
                    "spa_shell": True,
                    "title": "Appsmith",
                    "product": "appsmith",
                }
            ],
        },
    )
    login_sqli = [
        r for r in assessment["start_here"]
        if r.get("hunt") == "login_injection"
    ]
    assert login_sqli == []

    names = specialists_from_assessment(
        {
            "start_here": [
                {"specialist": "xss"},
                {"specialist": "finding_judge"},
                {"specialist": "risk_assessor"},
                {"specialist": "sqli"},
            ]
        },
        max_specialists=4,
    )
    assert names[0] == "app_mapper"
    assert "xss" in names
    assert "finding_judge" not in names
    assert "risk_assessor" not in names
