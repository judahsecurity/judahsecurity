"""Tests for tester-style application capability map + specialist dispatch."""

from types import SimpleNamespace

from app.services.agent.capability_map import (
    build_capability_map_from_crawl,
    build_capability_map_from_dict,
    format_capability_map_for_prompt,
    merge_capability_maps,
    select_specialists_for_map,
)


def _fake_crawl(**overrides):
    base = dict(
        target="https://app.example.com",
        scope="example.com",
        authenticated=False,
        pages_visited=[
            "https://app.example.com/",
            "https://app.example.com/login",
            "https://app.example.com/admin",
            "https://app.example.com/search",
        ],
        forms=[
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://app.example.com/login",
            },
            {
                "method": "POST",
                "action": "/upload",
                "inputs": ["file", "title"],
                "page": "https://app.example.com/upload",
            },
            {
                "method": "GET",
                "action": "/search",
                "inputs": ["q"],
                "page": "https://app.example.com/search",
            },
        ],
        api_calls={
            "app.example.com": {
                "GET /api/users?id=1",
                "POST /api/graphql",
                "GET /oauth/authorize",
            }
        },
        js_files={"https://app.example.com/static/app.js", "https://app.example.com/static/vendor.js"},
        endpoints_from_js={"/api/v1/items", "/graphql"},
        websockets={"wss://app.example.com/ws"},
        sse=set(),
        source_maps=set(),
        third_party={"cdn.example.net"},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_build_capability_map_detects_surfaces():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    assert cmap.ready_for_attack is True
    assert cmap.quality_score >= 0.35
    assert "auth" in cmap.capabilities
    assert "api" in cmap.capabilities
    assert "graphql" in cmap.capabilities
    assert "file_upload" in cmap.capabilities
    assert "search" in cmap.capabilities
    assert cmap.has_login_form is True
    assert cmap.has_upload is True
    assert any(h["hunt"] == "auth_logic" for h in cmap.ranked_hunt_queue)
    assert any(h["hunt"] == "graphql" for h in cmap.ranked_hunt_queue)


def test_select_specialists_auto_from_map():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    names = select_specialists_for_map(cmap)
    assert "app_mapper" in names
    assert "auth_logic" in names or "saml_sso" in names
    assert "graphql_api" in names
    assert "xss" in names or "injection" in names
    assert "independent_verifier" not in names
    assert "risk_assessor" not in names
    assert len(names) <= 8


def test_graphql_survives_long_human_start_here():
    """Forced GraphQL slot is not dropped when start_here already fills the cap."""
    cmap = build_capability_map_from_crawl(_fake_crawl())
    names = select_specialists_for_map(cmap, max_specialists=6)
    assert "app_mapper" in names
    assert "graphql_api" in names
    assert names.index("graphql_api") < names.index("finding_judge") if "finding_judge" in names else True


def test_ai_agent_surface_hunts_agent_tools():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            pages_visited=[
                "https://app.example.com/",
                "https://app.example.com/support",
            ],
            forms=[],
            api_calls={
                "app.example.com": {
                    "POST /api/chat",
                    "GET /api/v1/messages",
                }
            },
            endpoints_from_js={"/api/chat", "/mcp"},
            websockets=set(),
        )
    )
    assert cmap.has_ai_agent is True
    assert "ai_agent" in cmap.capabilities
    assert any(h["hunt"] == "agent_tools" for h in cmap.ranked_hunt_queue)
    names = select_specialists_for_map(cmap, max_specialists=8)
    assert "agent_tools" in names


def test_thin_map_not_ready():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            pages_visited=[],
            forms=[],
            api_calls={},
            js_files=set(),
            endpoints_from_js=set(),
            websockets=set(),
        )
    )
    assert cmap.ready_for_attack is False
    names = select_specialists_for_map(cmap)
    assert "content_api" in names
    assert "app_mapper" in names
    assert "js_secrets" in names


def test_merge_and_format():
    a = build_capability_map_from_crawl(_fake_crawl()).to_dict()
    b = build_capability_map_from_dict({
        "target": "https://app.example.com",
        "pages_visited": ["https://app.example.com/settings"],
        "api_endpoints": [{"host": "app.example.com", "method": "PUT", "path": "/api/profile"}],
        "forms": [],
        "js_files": [],
        "js_endpoints": [],
        "websockets": [],
        "sse": [],
        "source_maps": [],
        "third_party": [],
    })
    merged = merge_capability_maps(a, b)
    assert "https://app.example.com/settings" in merged["pages_visited"]
    assert any(e.get("path") == "/api/profile" for e in merged["api_endpoints"])
    text = format_capability_map_for_prompt(merged)
    assert "Suggested fireteam" in text
    assert "Capabilities:" in text


def test_openapi_schema_surfaces_unauth_account_lookup_hunt():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://ics.example.com",
            pages_visited=[
                "https://ics.example.com/",
                "https://ics.example.com/api/schema/",
            ],
            forms=[],
            api_calls={"ics.example.com": {"GET /api/auth/account/", "GET /api/schema/"}},
        )
    )
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "unauth_account_lookup" in hunts
    why = " ".join(h.get("why", "") for h in cmap.ranked_hunt_queue if h["hunt"] == "unauth_account_lookup")
    assert "account" in why.lower() or "security" in why.lower() or "401" in why
    names = select_specialists_for_map(cmap, max_specialists=8)
    assert "api_authz" in names
    assert cmap.ready_for_attack is True or "api_authz" in names


def test_settings_save_surfaces_unauth_settings_write_hunt():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://doccentrum-sensia.azurewebsites.net",
            pages_visited=["https://doccentrum-sensia.azurewebsites.net/"],
            forms=[],
            api_calls={
                "doccentrum-sensia.azurewebsites.net": {
                    "POST /api/Settings/SaveSettings",
                    "POST /api/TaskAdmin/UpdateTask",
                }
            },
        )
    )
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "unauth_settings_write" in hunts
    why = " ".join(
        h.get("why", "") for h in cmap.ranked_hunt_queue if h["hunt"] == "unauth_settings_write"
    )
    assert "401" in why or "void" in why.lower() or "SaveSettings" in why
    names = select_specialists_for_map(cmap, max_specialists=8)
    assert "api_authz" in names


def test_socketio_and_reset_email_surface_dedicated_hunts():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://vstream.glensserver.com",
            pages_visited=["https://vstream.glensserver.com/socket.io/"],
            forms=[],
            api_calls={
                "vstream.glensserver.com": {"GET /socket.io/?EIO=3&transport=polling"}
            },
            websockets={"wss://vstream.glensserver.com/socket.io/"},
        )
    )
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "socketio_idor" in hunts
    names = select_specialists_for_map(cmap, max_specialists=8)
    assert "api_authz" in names

    cmap2 = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://guardianaicoe.azurewebsites.net",
            pages_visited=["https://guardianaicoe.azurewebsites.net/api/schema/"],
            forms=[],
            api_calls={
                "guardianaicoe.azurewebsites.net": {
                    "POST /api/auth/users/reset_email/",
                }
            },
        )
    )
    hunts2 = [h["hunt"] for h in cmap2.ranked_hunt_queue]
    assert "email_change_ato" in hunts2
