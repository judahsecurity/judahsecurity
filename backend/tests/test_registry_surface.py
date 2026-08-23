"""ACR surface: harvest hosts → mandatory anonymous-pull probe."""

import asyncio
import json
from unittest.mock import patch

from app.services.agent.registry_surface import (
    host_is_azurecr,
    parse_catalog_names,
    probe_anonymous_pull,
    redact_token_json,
    registry_forced_step,
    registry_hosts_from_state,
    registry_hunt_note,
    registry_missing_probes,
    registry_probe_status,
    stamp_registry_on_map,
    token_was_issued,
)
from app.services.agent.tester_loop import complete_blocked_reason, forced_next_step


def test_harvests_azurecr_hosts_from_objective_and_trace():
    state = {
        "original_objective": "Assess https://contoso.azurecr.io",
        "target_info": {"primary_target": "https://contoso.azurecr.io"},
        "execution_trace": [
            {
                "tool_name": "query_assets",
                "tool_args": {"search": "azurecr.io"},
                "tool_output": "- [url] https://fabrikam.azurecr.io (ID: 9)",
            }
        ],
    }
    hosts = registry_hosts_from_state(state)
    assert "contoso.azurecr.io" in hosts
    assert "fabrikam.azurecr.io" in hosts


def test_forced_probe_before_crawl_on_registry_primary():
    url = "https://contoso.azurecr.io"
    state = {
        "original_objective": url,
        "target_info": {"primary_target": url},
        "execution_trace": [],
    }
    step = forced_next_step(state)
    assert step and step["tool_name"] == "probe_registry_anonymous"
    assert step["tool_args"]["host"] == "contoso.azurecr.io"


def test_inventory_query_only_with_organization_id():
    web = {
        "original_objective": "https://www.emulate3d.com",
        "target_info": {"primary_target": "https://www.emulate3d.com"},
        "execution_trace": [],
    }
    assert registry_forced_step(web) is None
    step = forced_next_step(web)
    assert step and step["tool_name"] in ("execute_deep_crawl", "execute_interceptor")

    org = {**web, "organization_id": 42}
    step = registry_forced_step(org)
    assert step and step["tool_name"] == "query_assets"
    assert step["tool_args"]["search"] == "azurecr.io"

    after = {
        **org,
        "execution_trace": [
            {
                "tool_name": "query_assets",
                "tool_args": {"search": "azurecr.io", "limit": 30},
                "tool_output": "Found 0 assets",
            }
        ],
    }
    assert registry_forced_step(after) is None
    step = forced_next_step(after)
    assert step and step["tool_name"] == "execute_deep_crawl"


def test_wordpress_probes_still_win_after_crawl_without_org():
    url = "https://www.emulate3d.com"
    state = {
        "original_objective": url,
        "target_info": {
            "primary_target": url,
            "technologies": ["WordPress:5.8.1"],
        },
        "kickoff_brief": "CMS: WordPress is in-play now",
        "execution_trace": [{"tool_name": "execute_deep_crawl", "success": True}],
    }
    step = forced_next_step(state)
    assert step and step["tool_name"] == "execute_curl"
    assert "wp-json/wp/v2/users" in (step.get("tool_args") or {}).get("args", "")


def test_complete_blocked_until_registry_probe():
    url = "https://contoso.azurecr.io"
    state = {
        "original_objective": url,
        "target_info": {"primary_target": url},
        "execution_trace": [],
        "capability_map": {"target": url, "pages_visited": ["/v2/"]},
    }
    reason = complete_blocked_reason(state)
    assert reason
    assert "acr_anonymous_pull" in reason or "probe_registry_anonymous" in reason
    missing = registry_missing_probes(state)
    assert {m["id"] for m in missing} >= {"acr_anonymous_pull"}


def test_registry_probe_unlocks_complete_without_website_pipeline():
    url = "https://contoso.azurecr.io"
    state = {
        "original_objective": url,
        "target_info": {"primary_target": url},
        "execution_trace": [
            {
                "tool_name": "probe_registry_anonymous",
                "tool_args": {"host": "contoso.azurecr.io"},
                "tool_output": json.dumps({"verdict": "KILL", "anonymous": False}),
                "success": True,
            }
        ],
        "capability_map": {"target": url, "pages_visited": ["/v2/"]},
    }
    assert registry_probe_status(state)["contoso.azurecr.io"] is True
    assert registry_missing_probes(state) == []
    assert complete_blocked_reason(state) is None
    assert forced_next_step(state) is None


def test_kickoff_brief_does_not_count_as_probe():
    state = {
        "original_objective": "https://contoso.azurecr.io",
        "target_info": {"primary_target": "https://contoso.azurecr.io"},
        "execution_trace": [
            {
                "tool_name": "assessment_kickoff",
                "tool_output": (
                    "GET https://contoso.azurecr.io/oauth2/token?service="
                    "contoso.azurecr.io&scope=registry:catalog:* and /v2/_catalog"
                ),
            }
        ],
    }
    assert registry_probe_status(state)["contoso.azurecr.io"] is False
    step = forced_next_step(state)
    assert step and step["tool_name"] == "probe_registry_anonymous"


def test_token_catalog_helpers_and_redact():
    fake = json.dumps({
        "access_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "expires_in": 60,
    })
    assert token_was_issued(fake) is True
    redacted = redact_token_json(fake)
    assert "REDACTED" in redacted
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in redacted
    names = parse_catalog_names(json.dumps({"repositories": ["app/web", "app/api"]}))
    assert names == ["app/web", "app/api"]
    assert token_was_issued("{}") is False


def test_probe_refuses_non_azurecr_hosts():
    result = asyncio.run(probe_anonymous_pull("example.com"))
    assert result["anonymous"] is False
    assert result["error"] == "not_a_registry_host"


def test_probe_normalizes_url_and_submits_on_token_plus_catalog():
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None, timeout=15.0):
            class _Resp:
                def __init__(self, status, text):
                    self.status_code = status
                    self.text = text

            if "/oauth2/token" in str(url):
                return _Resp(
                    200,
                    json.dumps({"access_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
                )
            if "/v2/_catalog" in str(url):
                return _Resp(200, json.dumps({"repositories": ["svc/api", "svc/web"]}))
            return _Resp(404, "")

    async def _run():
        with patch("httpx.AsyncClient", _Client):
            return await probe_anonymous_pull("https://contoso.azurecr.io/v2/")

    result = asyncio.run(_run())
    assert result["host"] == "contoso.azurecr.io"
    assert result["token_issued"] is True
    assert result["anonymous"] is True
    assert result["verdict"] == "SUBMIT"
    assert "create_finding" in result["next"]
    assert "svc/api" in result["sample_repositories"]
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in (result.get("token_body") or "")


def test_stamp_and_hunt_note():
    state = {
        "target_info": {"primary_target": "https://contoso.azurecr.io"},
        "execution_trace": [],
    }
    stamped = stamp_registry_on_map({"target": "", "notes": []}, state)
    assert "Azure Container Registry" in " ".join(stamped.get("notes") or [])
    note = registry_hunt_note(state)
    assert "probe_registry_anonymous" in note
    assert "contoso.azurecr.io" in note


def test_host_is_azurecr():
    assert host_is_azurecr("https://Contoso.azurecr.io/v2/") is True
    assert host_is_azurecr("www.emulate3d.com") is False
