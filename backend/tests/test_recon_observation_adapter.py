"""Recon signals are scoped leads, never confirmed findings."""

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.penetration_task_graph import NODE_READY, sync_graph_from_brain
from app.services.agent.recon_observation_adapter import (
    ingest_dnsx_cnames, ingest_httpx_observations, ingest_js_api_paths,
    ingest_takeover_findings, ingest_capability_observations,
    observation_event, ingest_event,
)
from types import SimpleNamespace


def test_scoped_dns_cname_creates_one_takeover_work_item():
    brain = EngagementBrain(target="https://app.example.test")
    output = (
        '{"host":"app.example.test","cname":["customer.github.io"]}\n'
        '{"host":"other.example.test","cname":"other.github.io"}\n'
    )
    assert ingest_dnsx_cnames(brain, output, scope_hosts={"app.example.test"}) == 1
    assert ingest_dnsx_cnames(brain, output, scope_hosts={"app.example.test"}) == 0
    assert len(brain.recon_observations) == 1
    assert len(brain.hypotheses) == 1
    hypothesis = brain.hypotheses[0]
    assert hypothesis.specialist == "takeover"
    assert hypothesis.status == "open"
    assert hypothesis.target == "https://app.example.test"
    graph = sync_graph_from_brain(brain)
    assert graph.nodes[hypothesis.id].status == NODE_READY


def test_dns_output_needs_recognized_provider_and_explicit_scope():
    brain = EngagementBrain(target="https://example.test")
    output = (
        '{"host":"sub.example.test","cname":"tenant.github.io"}\n'
        '{"host":"example.test","cname":"ordinary.example.net"}\n'
    )
    assert ingest_dnsx_cnames(brain, output, scope_hosts={"example.test"}) == 0
    assert ingest_dnsx_cnames(brain, output, scope_hosts={"*.example.test"}) == 1
    assert brain.hypotheses[0].target == "https://sub.example.test"


def test_js_api_handoff_is_first_party_and_deduplicated():
    brain = EngagementBrain()
    cmap = {
        "target": "https://app.example.test",
        "js_endpoints": [
            "/api/orders?token=private", "/api/orders?token=other",
            "https://other.test/api/admin", "//other.test/api/admin",
            "/static/app.js", "/graphql",
        ],
    }
    assert ingest_js_api_paths(brain, cmap, scope_hosts={"app.example.test"}) == 2
    assert ingest_js_api_paths(brain, cmap, scope_hosts={"app.example.test"}) == 0
    assert {h.target for h in brain.hypotheses} == {
        "https://app.example.test/api/orders", "https://app.example.test/graphql",
    }
    assert all("private" not in h.evidence for h in brain.hypotheses)
    assert all(h.status == "open" for h in brain.hypotheses)


def test_saved_event_contract_dedupes_to_one_ready_dispatch():
    from app.services.agent.tester_loop import _ready_hypothesis_wave

    target = "https://app.example.test"
    event = observation_event(
        "js_api_endpoint", f"{target}/api/orders", "/api/orders",
        source="capability_map", scope_hosts={"app.example.test"},
        evidence_ref="artifact:42",
    )
    brain = EngagementBrain(target=target)
    assert ingest_event(brain, event) is True
    assert ingest_event(brain, event) is False
    assert len(brain.recon_observations) == len(brain.hypotheses) == 1
    assert {"target", "source", "observed_at", "evidence_ref", "scope", "dedupe_key"} <= event.keys()
    state = {
        "mode": "agent", "capability_map": {"target": target},
        "engagement_brain": brain.to_dict(),
    }
    wave = _ready_hypothesis_wave(state, [], target)
    assert wave and wave["tool_args"]["specialists"] == ["api_authz"]
    assert wave["tool_args"]["targets"] == [target]


def test_observation_event_removes_url_credentials_and_query():
    event = observation_event(
        "api_endpoint", "https://user:secret@app.example.test/api/orders?token=private",
        "/api/orders", source="capability_map", scope_hosts={"app.example.test"},
    )
    assert event["target"] == "https://app.example.test/api/orders"
    assert "secret" not in str(event) and "private" not in str(event)


def test_live_technology_and_takeover_scanner_use_same_contract():
    brain = EngagementBrain(target="https://app.example.test")
    output = '{"url":"https://app.example.test","status_code":200,"tech":["nginx"]}'
    assert ingest_httpx_observations(
        brain, output, scope_hosts={"app.example.test"}, evidence_ref="artifact:1",
    ) == 2
    finding = SimpleNamespace(hostname="app.example.test", cname_chain=["unused.github.io"])
    assert ingest_takeover_findings(
        brain, [finding], scope_hosts={"app.example.test"}, evidence_ref="scan:2",
    ) == 1
    assert {o["kind"] for o in brain.recon_observations} == {
        "live_host", "technology", "dns_cname",
    }
    assert {h.specialist for h in brain.hypotheses} == {
        "web_recon", "vuln_triage", "takeover",
    }


def test_api_and_script_observations_dispatch_to_distinct_specialists():
    brain = EngagementBrain(target="https://app.example.test")
    cmap = {
        "target": "https://app.example.test",
        "api_endpoints": [{"host": "app.example.test", "method": "GET", "path": "/api/orders?id=1"}],
        "js_files": ["https://app.example.test/assets/app.js", "https://outside.test/app.js"],
    }
    assert ingest_capability_observations(brain, cmap, scope_hosts={"app.example.test"}) == 2
    assert ingest_capability_observations(brain, cmap, scope_hosts={"app.example.test"}) == 0
    assert {h.specialist for h in brain.hypotheses} == {"api_authz", "spa_client"}
