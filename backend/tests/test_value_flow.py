"""Value flows: an id from one response sent in a later request, without storing values."""

import json

from app.core.config import settings
from app.services.agent import tester_loop
from app.services.agent.capability_map import (
    build_capability_map_from_crawl, format_capability_map_for_prompt, merge_capability_maps,
)
from app.services.deep_crawl_service import CrawlResult
from app.services.agent.hunt_engine import facts_from_brain
from app.services.agent.runtime_mapper import merge_operations
from app.services.agent.value_flow import ValueFlowTracker, operation_shape, value_type

API = "https://shop.test/api"
ORDERS = json.dumps({"orders": [{"id": 4711, "total": 12}, {"id": 4712, "total": 3}],
                     "page": 1, "owner": {"userId": "9f1c2d3e-0000-4000-8000-1234567890ab"}})


def _tracker():
    tracker = ValueFlowTracker()
    tracker.observe_response("GET", f"{API}/orders?page=1", "application/json", ORDERS, seen_at=1.0)
    return tracker


def test_value_types_and_operation_shapes():
    assert value_type(4711) == "numeric_id" and value_type("4711") == "numeric_id"
    assert value_type("9f1c2d3e-0000-4000-8000-1234567890ab") == "uuid"
    assert value_type("a" * 32) == "hex_id"
    assert value_type("hello") == "" and value_type(True) == "" and value_type(None) == ""
    assert operation_shape("get", f"{API}/orders/4711/items") == "GET /api/orders/{id}/items"


def test_path_id_from_a_listing_is_linked_and_values_are_not_stored():
    tracker = _tracker()
    assert tracker.observe_request("GET", f"{API}/orders/4711", action_ref="r-action-3",
                                   seen_at=2.0) == 1
    flow = tracker.flows[0]
    assert flow == {"value_type": "numeric_id", "producer": "GET /api/orders",
                    "field": "orders[].id", "consumer": "GET /api/orders/{id}",
                    "location": "path:3", "seen": 1, "action_ref": "r-action-3"}
    assert "4711" not in json.dumps(tracker.flows)
    # The same link again only counts.
    tracker.observe_request("GET", f"{API}/orders/4712", seen_at=3.0)
    assert len(tracker.flows) == 1 and tracker.flows[0]["seen"] == 2


def test_query_and_json_body_consumers():
    tracker = _tracker()
    tracker.observe_request("POST", f"{API}/profile", body=json.dumps(
        {"userId": "9f1c2d3e-0000-4000-8000-1234567890ab"}), content_type="application/json",
        seen_at=2.0)
    tracker.observe_request("GET", f"{API}/invoice?orderId=4711", seen_at=2.0)
    shapes = {(f["consumer"], f["location"], f["field"]) for f in tracker.flows}
    assert ("POST /api/profile", "body:userId", "owner.userId") in shapes
    assert ("GET /api/invoice", "query:orderId", "orders[].id") in shapes


def test_noise_is_not_linked():
    tracker = ValueFlowTracker()
    # "page" is not an id-like key, so it is never a producer.
    tracker.observe_response("GET", f"{API}/list", "application/json",
                             json.dumps({"page": 2, "items": [{"id": 2}]}), seen_at=1.0)
    # page=2 and a short number under a non-id name are not followed.
    tracker.observe_request("GET", f"{API}/other?page=2&n=2", seen_at=2.0)
    # Same operation is not a flow, and non-JSON responses are ignored.
    tracker.observe_request("GET", f"{API}/list?id=2", seen_at=2.0)
    assert tracker.observe_response("GET", f"{API}/x", "text/html", "<b>1</b>") == 0
    assert tracker.flows == []


def test_a_producer_read_late_still_links_to_a_later_request():
    tracker = ValueFlowTracker()
    tracker.observe_request("GET", f"{API}/orders/4711", seen_at=2.0)  # before the body was read
    tracker.observe_response("GET", f"{API}/orders", "application/json", ORDERS, seen_at=1.0)
    assert [f["consumer"] for f in tracker.flows] == ["GET /api/orders/{id}"]
    # A request sent before the response arrived is not caused by it.
    early = ValueFlowTracker()
    early.observe_request("GET", f"{API}/orders/4711", seen_at=0.5)
    early.observe_response("GET", f"{API}/orders", "application/json", ORDERS, seen_at=1.0)
    assert early.flows == []


def test_operations_keep_the_actions_that_sent_them():
    op = {"id": "a", "identities": ["anonymous"], "sources": ["deep_crawl"], "parameters": []}
    rows = merge_operations([], [dict(op, action_refs=["r-initial"])])
    rows = merge_operations(rows, [dict(op, action_refs=["r-action-2"])])
    rows = merge_operations(rows, [dict(op, action_refs=["r-action-2"])])
    assert rows[0]["action_refs"] == ["r-initial", "r-action-2"]


def _crawl_with_flow():
    tracker = _tracker()
    tracker.observe_request("GET", f"{API}/orders/4711", seen_at=2.0)
    crawl = CrawlResult(target="https://shop.test/", scope="shop.test")
    crawl.value_flows = tracker.flows
    return crawl


def test_capability_map_carries_merges_and_shows_flows():
    cmap = build_capability_map_from_crawl(_crawl_with_flow())
    assert cmap.value_flows[0]["consumer"] == "GET /api/orders/{id}"
    merged = merge_capability_maps(cmap.to_dict(), build_capability_map_from_crawl(_crawl_with_flow()))
    assert len(merged["value_flows"]) == 1
    text = format_capability_map_for_prompt(merged)
    assert "Value flows" in text and "orders[].id" in text


def test_flows_become_hunt_facts_and_start_the_hunt(monkeypatch):
    cmap = build_capability_map_from_crawl(_crawl_with_flow()).to_dict()
    facts = facts_from_brain({}, cmap)
    assert facts[0]["source"] == "value_flow" and facts[0]["confidence"] == "observed"
    assert facts[0]["target"] == "/api/orders/{id}" and facts[0]["parameter"] == "path:3"

    monkeypatch.setattr(settings, "AGENT_HUNT_ENGINE", True, raising=False)
    state = {"mode": "agent", "engagement_brain": {}, "capability_map": cmap}
    step = tester_loop._hunt_engine_step(state, [], "https://shop.test/")
    assert step and step["tool_args"]["signal_count"] == 1
