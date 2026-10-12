"""Browser assets remain source evidence without becoming attack scenarios."""

from types import SimpleNamespace

from app.services.agent.application_surface_inventory import build_application_surface_inventory
from app.services.agent.capability_map import build_capability_map_from_crawl, ingest_passive_urls
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.runtime_mapper import ingest_capability_map_operations, normalize_request
from app.services.agent.scenario_surface import project_scenario_surface


def test_static_requests_do_not_seed_operation_hypotheses_or_scenarios():
    origin = "https://app.example.test"
    assert normalize_request({"url": origin + "/assets/app.js?v=7"}) == []
    crawl = SimpleNamespace(
        target=origin, scope=origin, authenticated=False,
        pages_visited=[origin + "/catalog", origin + "/assets/app.js?v=7"],
        discovered_links=[], forms=[], js_files={origin + "/assets/app.js"},
        endpoints_from_js=set(), websockets=set(), sse=set(), source_maps=set(),
        third_party=set(), api_samples=[],
        api_calls={"app.example.test": {
            "GET /catalog?category=fruit", "GET /assets/app.js?v=7",
            "GET /image/fruit.png?v=2", "GET /fonts/shop.woff2",
        }},
    )
    cmap = build_capability_map_from_crawl(crawl).to_dict()
    paths = {row["path"] for row in cmap["api_endpoints"]}
    assert paths == {"/catalog?category=fruit"}
    brain = EngagementBrain(target=origin)
    ingest_capability_map_operations(brain, cmap)
    assert all("/assets/" not in row["path"] for row in brain.application_operations)
    assert all("/image/" not in row["path"] for row in brain.application_operations)
    surface = project_scenario_surface(cmap)
    assert all(not item["path"].endswith((".js", ".png", ".woff2"))
               for item in surface["items"])
    assert origin + "/assets/app.js" in cmap["js_files"]


def test_passive_static_urls_do_not_seed_testable_inputs():
    origin = "https://app.example.test"
    cmap = ingest_passive_urls(None, [
        origin + "/assets/app.js?v=7", origin + "/image/fruit.png?size=large",
        origin + "/catalog?category=fruit",
    ], target=origin)
    assert any("app.js" in url for url in cmap["js_files"])
    assert not any(".png" in url for url in cmap["pages_visited"])
    inventory = build_application_surface_inventory(SimpleNamespace(
        target=origin, api_samples=[
            {"url": origin + "/assets/app.js?v=7", "method": "GET"},
            {"url": origin + "/catalog?category=fruit", "method": "GET"},
        ], discovered_links=[], endpoints_from_js=set(), js_endpoint_sources={},
    ))
    assert {(row["path"], row["name"]) for row in inventory["parameters"]} == {
        ("/catalog", "category")
    }
