"""Curious-tester loop: crawl, dir brute, params, fireteam — not fingerprint-and-stop."""

import json

from app.services.agent.assessment_kickoff import root_needs_dir_brute
from app.services.agent.tester_loop import (
    cms_followup_product,
    complete_blocked_reason,
    forced_next_step,
    format_tester_loop_for_prompt,
    normalized_tools_run,
    observed_input_signature,
    surface_looks_empty,
    tester_loop_progress as loop_progress,
)


def test_404_root_needs_dir_brute():
    assert root_needs_dir_brute([
        {"kind": "root", "status": 404, "title": "Not Found", "bytes": 80, "snippet": "404"},
    ])
    assert root_needs_dir_brute([
        {"kind": "root", "status": 200, "title": "Page Not Found", "bytes": 400, "snippet": ""},
    ])
    assert not root_needs_dir_brute([
        {"kind": "root", "status": 200, "title": "Dashboard", "bytes": 12000, "snippet": "Welcome"},
    ])


def test_ferox_worker_aliases_as_dir_brute():
    names = normalized_tools_run([
        {"tool_name": "recon_worker:ferox_dirs", "success": True},
    ])
    assert "execute_feroxbuster" in names
    started = normalized_tools_run([
        {"tool_name": "spawn_recon_workers", "tool_args": {"pack": "enrich"}},
    ])
    assert "dir_brute_started" in started
    assert "execute_feroxbuster" not in started


def test_failed_interceptor_falls_back_to_deep_crawl():
    url = "https://example.com"
    state = {
        "original_objective": url,
        "target_info": {"primary_target": url},
        "interceptor_job_id": "stalled-job",
        "execution_trace": [
            {"tool_name": "execute_interceptor", "success": False,
             "tool_output": "tool timed out"},
        ],
    }
    assert "execute_interceptor" not in normalized_tools_run(state["execution_trace"])
    assert loop_progress(state)["crawled"] is False
    assert forced_next_step(state)["tool_name"] == "execute_deep_crawl"

    state["execution_trace"].append(
        {"tool_name": "execute_deep_crawl", "success": False}
    )
    assert forced_next_step(state) is None


def test_prowl_uses_built_in_browser_after_crawl_and_as_fallback():
    target = "https://ginandjuice.shop"
    base = {
        "mode": "agent", "original_objective": f"Assess {target}",
        "target_info": {"primary_target": target},
    }
    failed = {**base, "execution_trace": [
        {"tool_name": "execute_deep_crawl", "success": False},
    ]}
    fallback = forced_next_step(failed)
    assert fallback["tool_name"] == "scoped_browser_assessment"
    assert fallback["tool_args"]["operation"] == "crawl"

    crawled = {**base, "execution_trace": [
        {"tool_name": "execute_deep_crawl", "success": True},
    ]}
    inspection = forced_next_step(crawled)
    assert inspection["tool_name"] == "scoped_browser_assessment"
    assert inspection["tool_args"]["operation"] == "inspect_js"
    inspected = {**base, "execution_trace": [
        *crawled["execution_trace"],
        {"tool_name": "scoped_browser_assessment", "tool_args": inspection["tool_args"],
         "success": True},
    ]}
    assert forced_next_step(inspected)["tool_name"] == "spawn_recon_workers"


def test_forced_pipeline_crawl_then_enrich_then_fireteam():
    url = "https://appsmith-dmpc.unifytwin.com"
    empty = {
        "original_objective": url,
        "target_info": {"primary_target": url},
        "execution_trace": [],
    }
    step = forced_next_step(empty)
    assert step and step["tool_name"] == "execute_deep_crawl"

    after_crawl = {
        **empty,
        "execution_trace": [{"tool_name": "execute_deep_crawl", "success": True}],
    }
    step = forced_next_step(after_crawl)
    assert step and step["tool_name"] == "spawn_recon_workers"
    assert (step.get("tool_args") or {}).get("pack") == "enrich"

    after_spawn = {
        **empty,
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "spawn_recon_workers", "tool_args": {"pack": "enrich"}},
        ],
    }
    step = forced_next_step(after_spawn)
    assert step and step["tool_name"] == "wait_recon_workers"

    after_ferox = {
        **empty,
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "recon_worker:ferox_dirs", "success": True},
        ],
    }
    step = forced_next_step(after_ferox)
    assert step and step["tool_name"] == "fingerprint_api"

    after_fp = {
        **empty,
        "execution_trace": after_ferox["execution_trace"] + [
            {"tool_name": "fingerprint_api", "success": True},
        ],
    }
    step = forced_next_step(after_fp)
    assert step and step["tool_name"] == "fetch_lazy_chunks"

    after_chunks = {
        **empty,
        "execution_trace": after_fp["execution_trace"] + [
            {"tool_name": "fetch_lazy_chunks", "success": True},
        ],
    }
    step = forced_next_step(after_chunks)
    assert step and step["tool_name"] == "extract_js_endpoints"

    after_js = {
        **empty,
        "execution_trace": after_chunks["execution_trace"] + [
            {"tool_name": "extract_js_endpoints", "success": True},
        ],
    }
    step = forced_next_step(after_js)
    assert step and step["tool_name"] == "sync_engagement_brain"

    after_aim = {
        **empty,
        "execution_trace": after_js["execution_trace"] + [
            {"tool_name": "sync_engagement_brain", "success": True},
        ],
        "engagement_brain": {"hypotheses": [{"id": "h1"}], "threat_model": {"threats": []}},
    }
    step = forced_next_step(after_aim)
    assert step and step["tool_name"] == "fireteam_dispatch"
    assert (step.get("tool_args") or {}).get("specialists") == "auto"

    after_hunt = {
        **after_aim,
        "execution_trace": after_aim["execution_trace"] + [
            {"tool_name": "fireteam_dispatch", "success": True},
        ],
    }
    assert forced_next_step(after_hunt) is None
    assert complete_blocked_reason(after_hunt) is None


def test_confirmed_candidate_is_published_with_exact_verified_claim_once():
    from app.services.agent.independent_verify import verify_receipt_key
    from app.services.agent.session_ops import compact_execution_trace

    target = "https://app.example.com/catalog?category=1"
    candidate = {
        "id": "candidate-1", "title": "Confirmed catalog SQL injection",
        "description": "A controlled Boolean differential changed catalog results.",
        "severity": "medium", "target": target, "status": "confirmed",
        "revision": 2, "nonce": "verify-nonce", "verified_at": "2026-10-09T00:00:00Z",
        "verifier_run_id": "run-1", "evidence_ids": ["hunter-1", "verifier-1"],
        "evidence": "Finder observed a differential.",
        "verifier_evidence": "Verifier reproduced it independently.",
    }
    receipt = {
        "title": candidate["title"], "target": target, "verdict": "confirmed",
        "candidate_id": candidate["id"], "revision": 2, "run_id": "run-1",
        "nonce": "verify-nonce", "nonce_observed": True,
        "evidence_ids": ["verifier-1"],
    }
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": "https://app.example.com"},
        "execution_trace": [],
        "engagement_brain": {
            "candidates": [candidate],
            "verification_receipts": {verify_receipt_key(candidate["title"], target): receipt},
        },
    }
    step = forced_next_step(state)
    assert step["tool_name"] == "create_finding"
    assert step["tool_args"]["description"] == candidate["description"]
    assert step["tool_args"]["target"] == target
    assert "Verifier reproduced" in step["tool_args"]["evidence"]

    state["execution_trace"] = [{
        "tool_name": "create_finding",
        "tool_args": {**step["tool_args"], "description": "Rewritten claim"},
    }]
    assert forced_next_step(state)["tool_args"]["description"] == candidate["description"]
    state["execution_trace"].append({"tool_name": "create_finding", "tool_args": step["tool_args"]})
    assert forced_next_step(state) is None

    state["execution_trace"] = [{"tool_name": "create_finding", "tool_args": step["tool_args"]}]
    assert forced_next_step(state) is None
    state["execution_trace"] = compact_execution_trace([
        *state["execution_trace"],
        *({"tool_name": "other", "success": True} for _ in range(20)),
    ])[0]
    assert forced_next_step(state) is None
    state["execution_trace"] = compact_execution_trace([
        *state["execution_trace"],
        *({"tool_name": "other", "success": True} for _ in range(20)),
    ])[0]
    assert forced_next_step(state) is None
    state["execution_trace"] = []
    candidate["finding_id"] = "123"
    assert forced_next_step(state) is None


def test_confirmed_candidate_handoff_requires_matching_receipt_and_scope():
    from app.services.agent.independent_verify import verify_receipt_key

    target = "https://other.example.com/catalog"
    candidate = {
        "id": "candidate-1", "title": "Claim", "description": "Proof",
        "severity": "medium", "target": target, "status": "confirmed",
        "revision": 1, "nonce": "nonce", "verified_at": "now",
        "verifier_run_id": "run-1", "evidence_ids": ["verifier-1"],
    }
    receipt = {
        "title": "Claim", "target": target, "verdict": "confirmed",
        "candidate_id": "candidate-1", "revision": 1, "run_id": "run-1",
        "nonce": "nonce", "nonce_observed": True,
        "evidence_ids": ["verifier-1"],
    }
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": "https://app.example.com"},
        "execution_trace": [],
        "engagement_brain": {
            "candidates": [candidate],
            "verification_receipts": {verify_receipt_key("Claim", target): receipt},
        },
    }
    assert forced_next_step(state) is None
    candidate["target"] = "https://app.example.com/catalog"
    assert forced_next_step(state) is None  # stale receipt cannot unlock another target


def test_observed_input_hunt_starts_before_enrichment_join_and_js_pipeline():
    target = "https://app.example.com"
    cmap = {
        "target": target,
        "scope": target,
        "pages_visited": [target + "/catalog"],
        "forms": [{
            "method": "POST", "action": "/catalog/subscribe",
            "inputs": ["email", "csrf"],
        }],
    }
    state = {
        "mode": "agent",
        "target_info": {"primary_target": target},
        "capability_map": cmap,
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "spawn_recon_workers", "success": True,
             "tool_args": {"pack": "enrich"}},
        ],
    }
    signature = observed_input_signature(state)
    assert signature
    inspection = forced_next_step(state)
    assert inspection["tool_name"] == "scoped_browser_assessment"
    assert inspection["tool_args"]["operation"] == "inspect_js"
    state["execution_trace"].append({
        "tool_name": "scoped_browser_assessment", "tool_args": inspection["tool_args"],
        "success": True,
    })
    assert forced_next_step(state)["tool_name"] == "sync_engagement_brain"

    state["execution_trace"].append({"tool_name": "sync_engagement_brain", "success": True})
    wave = forced_next_step(state)
    assert wave["tool_name"] == "fireteam_dispatch"
    assert wave["tool_args"]["surface_signature"] == signature

    state["execution_trace"].append({
        "tool_name": "fireteam_dispatch", "success": True,
        "tool_args": wave["tool_args"],
    })
    assert forced_next_step(state)["tool_name"] == "wait_recon_workers"

    cmap["forms"].append({"method": "GET", "action": "/catalog", "inputs": ["q"]})
    second = forced_next_step(state)
    assert second["tool_name"] == "fireteam_dispatch"
    assert second["tool_args"]["surface_signature"] != signature


def test_cms_followup_runs_with_observed_input_hunters_once():
    target = "https://cms.example.com"
    state = {
        "target_info": {"primary_target": target, "technologies": ["Drupal:10"]},
        "capability_map": {
            "target": target, "scope": target,
            "forms": [{"method": "GET", "action": "/search", "inputs": ["q"]}],
        },
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "spawn_recon_workers", "success": True,
             "tool_args": {"pack": "enrich"}},
            {"tool_name": "sync_engagement_brain", "success": True},
        ],
    }
    assert cms_followup_product(state) == "Drupal"
    first = forced_next_step(state)
    assert first["tool_args"]["specialists"] == ["xss", "sqli", "cms_followup"]
    state["execution_trace"].append({
        "tool_name": "fireteam_dispatch", "success": True,
        "tool_args": first["tool_args"],
    })
    assert loop_progress(state)["fireteam"] is False
    assert forced_next_step(state)["tool_name"] == "wait_recon_workers"


def test_cms_followup_runs_without_input_and_does_not_complete_full_wave():
    target = "https://cms.example.com"
    state = {
        "target_info": {"primary_target": target, "technologies": ["Joomla 5"]},
        "capability_map": {"target": target, "scope": target},
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "spawn_recon_workers", "success": True,
             "tool_args": {"pack": "enrich"}},
        ],
    }
    first = forced_next_step(state)
    assert first["tool_args"]["specialists"] == ["cms_followup"]
    state["execution_trace"].append({
        "tool_name": "fireteam_dispatch", "success": True,
        "tool_args": first["tool_args"],
    })
    assert loop_progress(state)["fireteam"] is False
    assert forced_next_step(state)["tool_name"] == "wait_recon_workers"


def test_observed_input_hunt_precedes_wordpress_followups(monkeypatch):
    monkeypatch.setattr(
        "app.services.agent.wordpress_surface.wordpress_forced_step",
        lambda _state: {"tool_name": "check_cve_applicability", "tool_args": {}},
    )
    target = "https://wp.example.com"
    state = {
        "target_info": {"primary_target": target},
        "capability_map": {
            "target": target, "scope": target,
            "forms": [{"method": "GET", "action": "/search", "inputs": ["q"]}],
        },
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "spawn_recon_workers", "success": True,
             "tool_args": {"pack": "enrich"}},
            {"tool_name": "sync_engagement_brain", "success": True},
        ],
    }
    assert forced_next_step(state)["tool_name"] == "fireteam_dispatch"


def test_static_js_endpoint_without_observed_input_does_not_start_early_hunt():
    state = {
        "target_info": {"primary_target": "https://app.example.com"},
        "capability_map": {
            "target": "https://app.example.com",
            "scope": "https://app.example.com",
            "js_endpoints": ["/api/guess"],
        },
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "spawn_recon_workers", "success": True,
             "tool_args": {"pack": "enrich"}},
        ],
    }
    assert observed_input_signature(state) == ""
    assert forced_next_step(state)["tool_name"] == "wait_recon_workers"


def test_observed_input_queue_advances_only_after_progress_then_runs_full_wave():
    target = "https://app.example.com"
    state = {
        "mode": "agent",
        "target_info": {"primary_target": target},
        "capability_map": {
            "target": target, "scope": target,
            "forms": [{"method": "GET", "action": "/search", "inputs": ["q", "sort"]}],
        },
        "engagement_brain": {"coverage_cells": [
            {"source": "parameter_inventory", "observation_source": "observed_form",
             "specialist": "xss", "status": "untested"},
            {"source": "parameter_inventory", "observation_source": "observed_form",
             "specialist": "sqli", "status": "untested"},
        ]},
        "execution_trace": [
            {"tool_name": name, "success": True}
            for name in (
                "execute_deep_crawl", "recon_worker:ferox_dirs", "fingerprint_api",
                "fetch_lazy_chunks", "extract_js_endpoints", "sync_engagement_brain",
            )
        ],
    }
    signature = observed_input_signature(state)
    state["execution_trace"].append({
        "tool_name": "scoped_browser_assessment", "success": True,
        "tool_args": {"operation": "inspect_js", "url": target},
    })
    state["execution_trace"].append({
        "tool_name": "fireteam_dispatch", "success": True,
        "tool_args": {"surface_signature": signature, "pending_input_count": 4},
    })
    next_wave = forced_next_step(state)
    assert next_wave["tool_name"] == "fireteam_dispatch"
    assert next_wave["tool_args"]["pending_input_count"] == 2

    state["engagement_brain"]["coverage_cells"][1]["status"] = "tested_clean"
    narrowed = forced_next_step(state)
    assert narrowed["tool_args"]["specialists"] == ["xss"]
    state["engagement_brain"]["coverage_cells"][1]["status"] = "untested"

    state["execution_trace"].append({
        "tool_name": "fireteam_dispatch", "success": True,
        "tool_args": next_wave["tool_args"],
    })
    assert loop_progress(state)["fireteam"] is False
    full_wave = forced_next_step(state)
    assert full_wave["tool_name"] == "fireteam_dispatch"
    assert full_wave["tool_args"]["specialists"] == "auto"
    assert not full_wave["tool_args"].get("surface_signature")


def test_mapped_assessment_follow_up_skips_first_turn_pipeline():
    state = {
        "mode": "agent",
        "assessment_resume": True,
        "original_objective": "Continue stock-check testing on https://ginandjuice.shop",
        "target_info": {"primary_target": "https://ginandjuice.shop"},
        "capability_map": {"target": "https://ginandjuice.shop", "pages_visited": ["/catalog"]},
        "execution_trace": [],
    }
    assert forced_next_step(state) is None
    progress = loop_progress(state)
    assert progress["ready_to_complete"] is True
    assert progress["missing"] == []
    assert "Do not restart broad discovery" in format_tester_loop_for_prompt(progress, state)
    assert complete_blocked_reason(state) is None


def test_interceptor_job_forces_attach_not_second_crawl():
    url = "https://app.example.com"
    step = forced_next_step({
        "original_objective": url,
        "interceptor_job_id": "job-123",
        "target_info": {"primary_target": url},
        "execution_trace": [],
    })
    assert step and step["tool_name"] == "execute_interceptor"


def test_bounded_pilot_never_enters_unavailable_tester_pipeline():
    target = "https://ginandjuice.shop:443"
    state = {
        "mode": "pilot",
        "organization_id": 42,
        "original_objective": f"Assess {target}",
        "target_info": {"primary_target": target},
        "execution_trace": [],
    }
    step = forced_next_step(state)
    assert step and step["tool_name"] == "execute_browser"
    assert json.loads(step["tool_args"]["args"])["actions"] == [
        {"action": "navigate", "url": target},
        {"action": "get_source"},
    ]
    after_browser = {
        **state,
        "execution_trace": [{"tool_name": "execute_browser", "success": True}],
    }
    next_step = forced_next_step(after_browser)
    assert next_step and next_step["tool_name"] == "probe_pilot_ports"
    assert next_step["tool_args"]["protocol"] == "tcp"
    assert 443 in next_step["tool_args"]["ports"]
    assert len(next_step["tool_args"]["ports"]) <= 20
    after_ports = {
        **state,
        "execution_trace": [
            {"tool_name": "execute_browser", "success": True},
            {"tool_name": "probe_pilot_ports", "tool_args": {"protocol": "tcp"}, "success": True},
        ],
    }
    udp_step = forced_next_step(after_ports)
    assert udp_step and udp_step["tool_args"]["protocol"] == "udp"
    after_udp = {
        **after_ports,
        "execution_trace": [*after_ports["execution_trace"],
                            {"tool_name": "probe_pilot_ports",
                             "tool_args": {"protocol": "udp"}, "success": True}],
    }
    assert forced_next_step(after_udp) is None
    assert complete_blocked_reason(after_browser) is None


def test_complete_blocked_after_fingerprint_only():
    state = {
        "original_objective": "Assess https://appsmith-dmpc.unifytwin.com",
        "execution_trace": [
            {
                "tool_name": "assessment_kickoff",
                "tool_args": {"url": "https://appsmith-dmpc.unifytwin.com", "root_status": 200},
                "tool_output": "Root: status=200 title=Appsmith",
            },
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "recon_worker:httpx_tech", "success": True},
            {"tool_name": "recon_worker:whatweb", "success": True},
        ],
        "capability_map": {"target": "https://appsmith-dmpc.unifytwin.com", "pages_visited": ["/"]},
    }
    reason = complete_blocked_reason(state)
    assert reason
    assert "dir_brute" in reason or "ferox" in reason.lower()
    assert "fireteam" in reason.lower()
    progress = loop_progress(state)
    assert progress["crawled"] is True
    assert progress["dir_brute"] is False
    assert progress["fireteam"] is False
    assert progress["ready_to_complete"] is False


def test_404_forces_dir_brute_even_with_crawl():
    state = {
        "needs_dir_brute": True,
        "original_objective": "https://empty.example.com",
        "execution_trace": [
            {
                "tool_name": "assessment_kickoff",
                "tool_args": {"root_status": 404, "needs_dir_brute": True},
                "tool_output": "Root: status=404 title=Not Found",
            },
            {"tool_name": "execute_deep_crawl", "success": True},
        ],
    }
    assert surface_looks_empty(state)
    progress = loop_progress(state)
    assert any(m["id"] == "dir_brute" for m in progress["missing"])


def test_loop_complete_after_crawl_ferox_params_fireteam():
    state = {
        "original_objective": "https://app.example.com",
        "execution_trace": [
            {"tool_name": "execute_interceptor", "success": True},
            {"tool_name": "recon_worker:ferox_dirs", "success": True},
            {"tool_name": "fingerprint_api", "success": True},
            {"tool_name": "fetch_lazy_chunks", "success": True},
            {"tool_name": "extract_js_endpoints", "success": True},
            {"tool_name": "discover_parameters", "success": True},
            {"tool_name": "sync_engagement_brain", "success": True},
            {"tool_name": "fireteam_dispatch", "success": True},
        ],
        "engagement_brain": {"hypotheses": [{"id": "h1"}]},
        "capability_map": {"target": "https://app.example.com", "pages_visited": ["/login"]},
    }
    progress = loop_progress(state)
    assert progress["js_surface"] is True
    assert progress["ready_to_complete"] is True
    assert complete_blocked_reason(state) is None


def test_force_complete_bypass():
    state = {
        "original_objective": "https://app.example.com",
        "execution_trace": [],
    }
    assert complete_blocked_reason(state, completion_reason="force complete") is None
