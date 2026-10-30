"""Recon signals are scoped leads, never confirmed findings."""

from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.penetration_task_graph import NODE_READY, sync_graph_from_brain
from app.services.agent.recon_observation_adapter import (
    ingest_dnsx_cnames, ingest_js_api_paths,
)


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
