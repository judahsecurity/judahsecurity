"""Tests for observation → methodology catalog and engagement seeding."""

from types import SimpleNamespace
from unittest.mock import patch

from app.services.agent.capability_map import (
    build_capability_map_from_crawl,
    ingest_passive_urls,
)
from app.services.agent.engagement_brain import (
    boost_methodologies_for_cwes,
    engagement_brain_from_dict,
    format_engagement_brain_for_prompt,
    methodology_progress,
    seed_hypotheses_from_capability_map,
    update_hypothesis,
)
from app.services.agent.methodology_catalog import (
    methodologies_from_capability_map,
)
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.vuln_intel_enrichment import build_cwe_intel, enrich_cve_catalog


def _fake_crawl(**overrides):
    base = dict(
        target="https://tenant-a.app.example.com",
        scope="example.com",
        authenticated=True,
        pages_visited=[
            "https://tenant-a.app.example.com/",
            "https://tenant-a.app.example.com/login",
            "https://tenant-a.app.example.com/forgot-password",
            "https://tenant-a.app.example.com/signup",
            "https://tenant-b.app.example.com/",
            "https://tenant-a.app.example.com/admin",
            "https://tenant-a.app.example.com/search?q=test",
            "https://tenant-a.app.example.com/swagger/index.html",
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
                "action": "/forgot-password",
                "inputs": ["email"],
                "page": "https://tenant-a.app.example.com/forgot-password",
            },
            {
                "method": "GET",
                "action": "/search",
                "inputs": ["q"],
                "page": "https://tenant-a.app.example.com/search",
            },
            {
                "method": "POST",
                "action": "/checkout",
                "inputs": ["quantity", "price"],
                "page": "https://tenant-a.app.example.com/checkout",
            },
            {
                "method": "POST",
                "action": "/upload",
                "inputs": ["file", "title"],
                "page": "https://tenant-a.app.example.com/upload",
            },
        ],
        api_calls={
            "tenant-a.app.example.com": {
                "GET /api/users?id=1",
                "GET /api/orders/100",
                "POST /api/webhooks?url=https://example.com",
            },
            "tenant-b.app.example.com": {
                "GET /api/users?id=2",
            },
        },
        js_files={"https://tenant-a.app.example.com/static/app.js"},
        endpoints_from_js={"/api/v1/items", "/api/v1/api_key/status"},
        websockets={"wss://tenant-a.app.example.com/ws"},
        sse=set(),
        source_maps=set(),
        third_party=set(),
        api_samples=[{"url": "/api/webhooks?url=https://example.com", "method": "POST"}],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_methodologies_from_rich_crawl():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    methods = methodologies_from_capability_map(cmap)
    ids = {m.id for m in methods}
    assert "default_weak_creds" in ids
    assert "password_reset_abuse" in ids
    assert "api_idor_bola" in ids
    assert "host_tenant_isolation" in ids
    assert "reflected_xss" in ids
    assert "unsafe_file_upload" in ids
    assert "ssrf_url_fetch" in ids
    assert "realtime_channel_auth" in ids
    assert "admin_surface_exposure" in ids
    assert "coverage_known_vulns" in ids
    assert "registration_invite_abuse" in ids
    assert "openapi_schema_authz" in ids
    assert "js_apikey_exposure" in ids
    xss = next(m for m in methods if m.id == "reflected_xss")
    assert "CWE-79" in xss.cwe_ids
    assert xss.capec_ids
    assert cmap.methodologies
    assert any(h.get("methodology_id") for h in cmap.ranked_hunt_queue)


def test_seed_hypotheses_uses_methodology_cards():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    method_hyps = [h for h in brain.hypotheses if h.source == "methodology"]
    assert method_hyps
    assert any(h.methodology_id == "reflected_xss" for h in method_hyps)
    assert any("CWE-79" in h.cwe_ids for h in method_hyps)
    text = format_engagement_brain_for_prompt(brain.to_dict())
    assert "CWE=" in text or "method=" in text
    assert "Methodology" in text or "ready_to_complete" in text


def test_methodology_progress_blocks_complete_until_high_pri_resolved():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    progress = methodology_progress(brain, cmap=cmap.to_dict())
    assert progress["seeded"] is True
    assert progress["blocking_high_priority"] > 0
    assert progress["ready_to_complete"] is False

    for h in list(brain.hypotheses):
        if h.priority in ("critical", "high") and h.specialist != "coverage":
            update_hypothesis(brain, h.id, status="killed", evidence="tested clean")
    progress2 = methodology_progress(brain, cmap=cmap.to_dict())
    assert progress2["ready_to_complete"] is True
    assert progress2["ready_for_coverage_spray"] is True


def test_cve_cwe_loopback_boosts_related_cards():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    xss = next(h for h in brain.hypotheses if h.methodology_id == "reflected_xss")
    boosted = boost_methodologies_for_cwes(
        brain, ["CWE-79"], cve_id="CVE-2024-0001", evidence="nuclei hit"
    )
    assert any(h.methodology_id == "reflected_xss" for h in boosted)
    assert "CVE-2024-0001" in (xss.evidence or "")


def test_ingest_passive_urls_enriches_map():
    cmap = build_capability_map_from_crawl(_fake_crawl(pages_visited=["https://app.example.com/"]))
    merged = ingest_passive_urls(
        cmap.to_dict(),
        [
            "https://app.example.com/api/users?id=9",
            "https://app.example.com/swagger.json",
            "https://app.example.com/static/vendor.js",
            "https://app.example.com/forgot-password",
        ],
        source="katana",
        target="https://app.example.com",
    )
    blob = " ".join(merged.get("pages_visited") or []) + " ".join(
        e.get("path") or "" for e in (merged.get("api_endpoints") or [])
    )
    assert "swagger" in blob.lower() or "forgot-password" in blob.lower() or "users" in blob.lower()
    ids = {m.get("id") for m in merged.get("methodologies") or []}
    assert ids & {
        "openapi_schema_authz",
        "api_idor_bola",
        "password_reset_abuse",
        "js_secrets_retire",
    }


def test_operation_directive_includes_cwe_and_methodologies():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )

    class _P:
        def __init__(self, name):
            self.name = name
            self.epithet = name
            self.role = f"{name} specialist."
            self.allowed_tools = ["compare_requests", "execute_curl"]
            self.max_iterations = 6

    profiles = {
        "injection": _P("injection"),
        "api_authz": _P("api_authz"),
        "app_mapper": _P("app_mapper"),
    }
    directives = directives_from_hypotheses(
        brain=brain,
        profiles_by_name=profiles,
        specialists=["injection", "api_authz"],
        default_target=cmap.target,
    )
    inj = directives["injection"]
    assert inj.methodology_ids
    assert inj.cwe_ids
    block = inj.to_prompt_block()
    assert "Methodologies:" in block
    assert "CWE:" in block


def test_build_cwe_intel_from_nvd_cwes():
    intel = build_cwe_intel(["CWE-502", "CWE-79"])
    ids = {row["cwe_id"] for row in intel}
    assert "CWE-502" in ids
    assert "CWE-79" in ids
    xss = next(r for r in intel if r["cwe_id"] == "CWE-79")
    assert xss["capec"]
    assert any(c["id"].startswith("CAPEC-") for c in xss["capec"])
    assert xss["name"]


def test_enrich_cve_catalog_exposes_cwes():
    nvd = {
        "source": "nvd",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "description": "Log4Shell",
        "cwes": ["CWE-502"],
        "references": [],
    }
    with patch("app.services.vuln_intel_enrichment._fetch_nvd", return_value=nvd), \
         patch("app.services.vuln_intel_enrichment._fetch_osv", return_value=None), \
         patch("app.services.vuln_intel_enrichment._fetch_ghsa", return_value=[]), \
         patch("app.services.vuln_intel_enrichment._fetch_poc_github", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_trickest", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_github_repos", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_exploitdb", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_cxsecurity", return_value={"found": False}):
        out = enrich_cve_catalog("CVE-2021-44228", use_cache=False)

    assert out["cwes"] == ["CWE-502"]
    assert out["cwe_intel"]
    assert out["cwe_intel"][0]["cwe_id"] == "CWE-502"
    assert out["cwe_intel"][0]["capec"]
