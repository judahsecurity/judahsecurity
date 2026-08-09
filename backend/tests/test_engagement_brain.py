"""Tests for tester-process engagement brain + hypothesis chaining."""

from app.services.agent.capability_map import build_capability_map_from_crawl
from app.services.agent.engagement_brain import (
    classify_finding_type,
    engagement_brain_from_dict,
    format_engagement_brain_for_prompt,
    queue_followups_for_finding,
    seed_hypotheses_from_capability_map,
    specialists_from_open_hypotheses,
    update_hypothesis,
    add_credential,
)
from types import SimpleNamespace


def _fake_crawl(**overrides):
    base = dict(
        target="https://tenant-a.app.example.com",
        scope="example.com",
        authenticated=True,
        pages_visited=[
            "https://tenant-a.app.example.com/",
            "https://tenant-a.app.example.com/login",
            "https://tenant-b.app.example.com/",
            "https://tenant-a.app.example.com/admin",
        ],
        forms=[
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://tenant-a.app.example.com/login",
            },
            {
                "method": "POST",
                "action": "/checkout",
                "inputs": ["quantity", "price"],
                "page": "https://tenant-a.app.example.com/checkout",
            },
        ],
        api_calls={
            "tenant-a.app.example.com": {
                "GET /api/users?id=1",
                "GET /api/orders/100",
            },
            "tenant-b.app.example.com": {
                "GET /api/users?id=2",
            },
        },
        js_files={"https://tenant-a.app.example.com/static/app.js"},
        endpoints_from_js={"/api/v1/items"},
        websockets=set(),
        sse=set(),
        source_maps=set(),
        third_party=set(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_seed_hypotheses_includes_host_tenant_and_business_logic():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    hunts = {h.specialist for h in brain.hypotheses}
    titles = " ".join(h.title.lower() for h in brain.hypotheses)
    assert "host_tenant" in hunts
    assert "business_logic" in hunts or "business" in titles
    assert "api_authz" in hunts or "auth_logic" in hunts
    assert any(h.specialist == "coverage" for h in brain.hypotheses)
    assert brain.phase in ("map", "attack")
    assert "authenticated" in brain.identities


def test_specialists_from_open_hypotheses_priority():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    names = specialists_from_open_hypotheses(brain, max_specialists=6)
    assert names[0] == "app_mapper"
    assert "vuln_triage" in names
    assert len(names) <= 6
    # Should prefer attack specialists over empty
    assert any(n in names for n in ("host_tenant", "api_authz", "auth_logic", "injection"))


def test_default_login_queues_grafana_chain_and_credential():
    brain = engagement_brain_from_dict(None)
    brain.target = "https://grafana.qa.example.com"
    created = queue_followups_for_finding(
        brain,
        vuln_type="default_login",
        title="Grafana Default Login admin:prom-operator",
        target="https://grafana.qa.example.com",
        evidence="grafana_session cookie; Logged in",
    )
    assert created
    assert any("9264" in h.title or "Authenticated CVE" in h.title for h in created)
    assert brain.credentials
    assert brain.credentials[0].username == "admin"
    assert brain.credentials[0].secret == "prom-operator"
    assert "authenticated" in brain.identities


def test_host_header_queues_tenant_bypass_card():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="host_header",
        title="Host header reflection",
        target="https://tenant-a.example.com",
    )
    assert any(h.specialist == "host_tenant" for h in created)
    assert any("tenant" in h.title.lower() for h in created)


def test_update_hypothesis_and_prompt_format():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    hyp = brain.hypotheses[0]
    updated = update_hypothesis(
        brain, hyp.id, status="proven", evidence="compare_requests LIKELY_IMPACT"
    )
    assert updated is not None
    assert updated.status == "proven"
    text = format_engagement_brain_for_prompt(brain.to_dict())
    assert "Hypotheses:" in text
    assert "Proven:" in text
    assert "compare_requests" in text


def test_classify_finding_type():
    assert classify_finding_type(title="Grafana Default Login") == "default_login"
    assert classify_finding_type(title="Host Header Injection") == "host_header"
    assert classify_finding_type(title="IDOR on /api/orders") == "idor"
    assert classify_finding_type(title="Random info") == "unknown"


def test_add_credential_dedupes():
    brain = engagement_brain_from_dict(None)
    add_credential(brain, username="admin", secret="x", valid_on=["a"])
    add_credential(brain, username="admin", secret="x", valid_on=["b"])
    assert len(brain.credentials) == 1
    assert set(brain.credentials[0].valid_on) == {"a", "b"}


def test_capability_map_hunt_queue_has_host_tenant():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "host_tenant" in hunts
    assert "coverage" in hunts
