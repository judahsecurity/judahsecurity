"""Curious-tester loop: crawl, dir brute, params, fireteam — not fingerprint-and-stop."""

import json
import pytest

from app.services.agent.assessment_kickoff import root_needs_dir_brute
from app.services.agent.tester_loop import (
    _coverage_followup_wave,
    _observed_input_batch_step,
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


def test_agent_inspects_javascript_after_observed_input_first_pass():
    target = "https://app.example.test"
    cell = {
        "id": "cell-1", "host": "app.example.test", "method": "GET",
        "path": "/search", "parameter": "query:q", "test_type": "xss",
        "specialist": "xss", "source": "parameter_inventory",
        "observation_source": "browser_link", "status": "untested",
    }
    state = {
        "mode": "agent", "target_info": {"primary_target": target},
        "capability_map": {
            "target": target, "scope": target,
            "forms": [{"method": "GET", "action": "/search", "inputs": ["q"]}],
            "js_files": [target + "/static/app.js"],
        },
        "engagement_brain": {"coverage_cells": [cell]},
        "execution_trace": [
            {"tool_name": name, "success": True} for name in (
                "execute_deep_crawl", "recon_worker:ferox_dirs",
                "sync_engagement_brain",
            )
        ],
    }
    assert forced_next_step(state)["tool_name"] == "probe_observed_input_batch"
    cell.update(status="inconclusive", first_pass_outcome="inconclusive")
    step = forced_next_step(state)
    assert step["tool_name"] == "scoped_browser_assessment"
    assert step["tool_args"]["operation"] == "inspect_js"


def test_observed_input_queue_batches_first_pass_before_specialist_wave():
    target = "https://app.example.com"
    state = {
        "mode": "agent",
        "target_info": {"primary_target": target},
        "capability_map": {
            "target": target, "scope": target,
            "forms": [{"method": "GET", "action": "/search", "inputs": ["q", "sort"]}],
        },
        "engagement_brain": {"coverage_cells": [
            {"host": "app.example.com", "source": "parameter_inventory", "observation_source": "observed_form",
             "specialist": "xss", "test_type": "xss", "status": "untested"},
            {"host": "app.example.com", "source": "parameter_inventory", "observation_source": "observed_form",
             "specialist": "sqli", "test_type": "sqli", "status": "untested"},
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
    first_batch = forced_next_step(state)
    assert first_batch["tool_name"] == "probe_observed_input_batch"
    assert first_batch["tool_args"]["pending_input_count"] == 2
    state["execution_trace"].append({
        "tool_name": "probe_observed_input_batch", "success": True,
        "tool_args": first_batch["tool_args"],
    })
    state["engagement_brain"]["coverage_cells"][0]["first_pass_outcome"] = "inconclusive"
    state["engagement_brain"]["coverage_cells"][0]["status"] = "inconclusive"
    second_batch = forced_next_step(state)
    assert second_batch["tool_name"] == "probe_observed_input_batch"
    assert second_batch["tool_args"]["pending_input_count"] == 1
    state["execution_trace"].append({
        "tool_name": "probe_observed_input_batch", "success": True,
        "tool_args": second_batch["tool_args"],
    })
    state["engagement_brain"]["coverage_cells"][1]["first_pass_outcome"] = "tested_clean"
    state["engagement_brain"]["coverage_cells"][1]["status"] = "tested_clean"
    wave = forced_next_step(state)
    assert wave["tool_name"] == "fireteam_dispatch"
    assert wave["tool_args"]["specialists"] == ["xss", "sqli"]
    state["execution_trace"].append({
        "tool_name": "fireteam_dispatch", "success": True,
        "tool_args": wave["tool_args"],
    })
    assert loop_progress(state)["fireteam"] is False
    full_wave = forced_next_step(state)
    assert full_wave["tool_name"] == "fireteam_dispatch"
    assert full_wave["tool_args"]["specialists"] == "auto"
    assert not full_wave["tool_args"].get("surface_signature")


@pytest.mark.parametrize("prior_success", [True, False])
def test_new_inputs_keep_first_pass_running_when_pending_count_is_unchanged(prior_success):
    target = "https://app.example.com"
    def cell(cell_id):
        return {
            "id": cell_id, "host": "app.example.com", "method": "GET",
            "path": "/catalog", "parameter": f"query:{cell_id}",
            "source": "parameter_inventory", "observation_source": "browser_link",
            "specialist": "xss", "test_type": "xss", "status": "untested",
        }

    state = {
        "target_info": {"primary_target": target},
        "engagement_brain": {"coverage_cells": [cell("a"), cell("b")]},
    }
    first = _observed_input_batch_step(state, [], "surface-a")
    assert first["tool_args"]["pending_input_count"] == 2
    trace = [{"tool_name": "probe_observed_input_batch", "success": prior_success,
              "tool_args": first["tool_args"]}]
    # A completed no-progress batch must not spin. A failed tool call gets
    # one bounded retry because it did not test any of the pending inputs.
    retry = _observed_input_batch_step(state, trace, "surface-a")
    if prior_success:
        assert retry is None
    else:
        assert retry["tool_name"] == "probe_observed_input_batch"
        trace.append({"tool_name": "probe_observed_input_batch", "success": False,
                      "tool_args": retry["tool_args"]})
        assert _observed_input_batch_step(state, trace, "surface-a") is None

    state["engagement_brain"]["coverage_cells"][0]["first_pass_outcome"] = "inconclusive"
    state["engagement_brain"]["coverage_cells"].append(cell("c"))
    second = _observed_input_batch_step(state, trace, "surface-a")
    assert second["tool_args"]["pending_input_count"] == 2
    assert second["tool_args"]["pending_batch_signature"] != first["tool_args"]["pending_batch_signature"]


def test_retryable_handoff_gets_new_batch_signature_after_cooldown():
    cell = {
        "id": "xss-search", "host": "app.example.com", "method": "GET",
        "path": "/catalog", "parameter": "query:searchTerm",
        "source": "parameter_inventory", "observation_source": "browser_link",
        "specialist": "xss", "test_type": "xss", "status": "untested",
    }
    state = {
        "target_info": {"primary_target": "https://app.example.com"},
        "engagement_brain": {"coverage_cells": [cell]},
    }
    first = _observed_input_batch_step(state, [], "surface-a")
    trace = [{"tool_name": "probe_observed_input_batch", "success": True,
              "tool_args": first["tool_args"]}]
    cell.update(first_pass_outcome="unattempted", first_pass_attempts=1,
                first_pass_handoff_error="invalid_coverage_lease: lease_changed",
                first_pass_retry_at=0)
    second = _observed_input_batch_step(state, trace, "surface-a")
    assert second["tool_args"]["pending_batch_signature"] != first["tool_args"]["pending_batch_signature"]


def test_link_discovered_input_enters_observed_first_pass():
    target = "https://app.example.com"
    state = {
        "target_info": {"primary_target": target},
        "capability_map": {
            "target": target, "scope": target,
            "discovered_links": [{"url": target + "/catalog", "query_keys": ["searchTerm"]}],
        },
        "engagement_brain": {"coverage_cells": [{
            "host": "app.example.com", "source": "parameter_inventory", "observation_source": "browser_link",
            "specialist": "xss", "test_type": "xss", "status": "untested",
        }]},
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "spawn_recon_workers", "success": True,
             "tool_args": {"pack": "enrich"}},
            {"tool_name": "sync_engagement_brain", "success": True},
        ],
    }
    assert observed_input_signature(state)
    assert forced_next_step(state)["tool_name"] == "probe_observed_input_batch"


def test_pending_proof_is_verified_before_next_input_batch():
    target = "https://app.example.com"
    state = {
        "target_info": {"primary_target": target},
        "capability_map": {
            "target": target, "scope": target,
            "discovered_links": [{"url": target + "/catalog", "query_keys": ["q"]}],
        },
        "engagement_brain": {
            "candidates": [{"id": "candidate-1", "status": "pending",
                            "vulnerability_class": "sql_injection"}],
            "coverage_cells": [{
                "source": "parameter_inventory", "observation_source": "browser_link",
                "specialist": "xss", "test_type": "xss", "status": "untested",
            }],
        },
        "execution_trace": [{"tool_name": "execute_deep_crawl", "success": True}],
    }
    first = forced_next_step(state)
    assert first["tool_name"] == "independent_verify"
    assert first["tool_args"]["candidate_id"] == "candidate-1"
    assert first["tool_args"]["candidate_revision"] == 1
    state["execution_trace"].append({
        "tool_name": "independent_verify", "success": False,
        "tool_args": first["tool_args"],
    })
    retry = forced_next_step(state)
    assert retry["tool_name"] == "independent_verify"
    state["execution_trace"].append({
        "tool_name": "independent_verify", "success": False,
        "tool_args": retry["tool_args"],
    })
    assert forced_next_step(state)["tool_name"] != "independent_verify"
    state["engagement_brain"]["candidates"][0]["revision"] = 2
    assert forced_next_step(state)["tool_args"]["candidate_revision"] == 2


@pytest.mark.parametrize("specialist,vulnerability_class", [
    ("sqli", "sql_injection"), ("xss", "xss"),
])
def test_positive_first_pass_receipt_is_handed_to_candidate_before_more_work(
    specialist, vulnerability_class,
):
    target = "https://app.example.com"
    evidence_id = specialist + "-proof-receipt"
    cell = {
        "id": "cov-proof", "source": "parameter_inventory",
        "host": "app.example.com", "method": "GET", "path": "/catalog",
        "parameter": "query:category", "specialist": specialist, "test_type": specialist,
        "status": "in_focus", "first_pass_outcome": "proof_signal",
        "first_pass_evidence_id": evidence_id,
    }
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": target},
        "capability_map": {"target": target, "scope": target},
        "engagement_brain": {"coverage_cells": [cell], "candidates": []},
        "execution_trace": [],
    }
    step = forced_next_step(state)
    assert step["tool_name"] == "submit_finding_candidate"
    assert step["tool_args"]["coverage_cell_id"] == cell["id"]
    assert step["tool_args"]["evidence_ids"] == [evidence_id]
    assert step["tool_args"]["vulnerability_class"] == vulnerability_class
    assert step["tool_args"]["target"] == target + "/catalog"
    assert "candidate_handoff" in complete_blocked_reason(state)

    state["engagement_brain"]["candidates"] = [{
        "id": "old-candidate", "status": "refuted",
        "coverage_cell_id": cell["id"], "evidence_ids": ["old-proof"],
    }]
    assert forced_next_step(state)["tool_name"] == "submit_finding_candidate"
    state["engagement_brain"]["candidates"] = []

    state["execution_trace"].extend([{
        "tool_name": "submit_finding_candidate", "success": False,
        "tool_args": step["tool_args"],
    }] * 2)
    assert forced_next_step(state) is None  # no unbounded candidate retry
    state["engagement_brain"]["candidates"] = [{
        "id": "candidate-1", "status": "pending",
        "coverage_cell_id": cell["id"], "vulnerability_class": vulnerability_class,
        "evidence_ids": [evidence_id],
    }]
    assert forced_next_step(state)["tool_name"] == "independent_verify"
    assert complete_blocked_reason(state) is None


def test_saved_proof_cannot_handoff_to_another_origin():
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": "https://app.example.com"},
        "engagement_brain": {"coverage_cells": [{
            "id": "cov-other", "source": "parameter_inventory",
            "host": "other.example.com", "path": "/catalog",
            "specialist": "sqli", "test_type": "sqli",
            "first_pass_outcome": "proof_signal",
            "first_pass_evidence_id": "other-proof",
        }]},
        "execution_trace": [],
    }
    assert forced_next_step(state) is None
    assert complete_blocked_reason(state) is None


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


def test_resumed_assessment_tests_observed_inputs_on_its_current_target():
    target = "https://ginandjuice.shop"
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": target},
        "capability_map": {
            "target": target, "scope": target,
            "discovered_links": [{"url": target + "/catalog?searchTerm=gin",
                                  "query_keys": ["searchTerm"]}],
        },
        "engagement_brain": {"coverage_cells": [{
            "host": "ginandjuice.shop", "source": "parameter_inventory",
            "observation_source": "browser_link", "specialist": "xss",
            "test_type": "xss", "status": "untested",
        }]},
        "execution_trace": [],
    }
    step = forced_next_step(state)
    assert step["tool_name"] == "probe_observed_input_batch"
    assert step["tool_args"]["target"] == target
    assert loop_progress(state)["ready_to_complete"] is False
    assert "observed_input_first_pass" in complete_blocked_reason(state)

    state["target_info"]["primary_target"] = "https://old.example.com"
    assert forced_next_step(state) is None


def test_resumed_assessment_drains_saved_inputs_without_inventory_signature():
    target = "https://app.test"
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": target},
        "capability_map": {"target": target, "scope": target},
        "engagement_brain": {"coverage_cells": [{
            "id": "saved-xss", "host": "app.test", "path": "/search",
            "method": "GET", "parameter": "query:q", "status": "untested",
            "source": "parameter_inventory", "observation_source": "browser_link",
            "specialist": "xss", "test_type": "xss",
        }]},
        "execution_trace": [],
    }
    assert observed_input_signature(state) == ""
    step = forced_next_step(state)
    assert step["tool_name"] == "probe_observed_input_batch"
    assert step["tool_args"]["surface_signature"] == "saved-coverage"
    assert "observed_input_first_pass" in complete_blocked_reason(state)


def test_resumed_assessment_dispatches_other_classes_and_keeps_stalls_open():
    target = "https://app.test"
    state = {
        "mode": "agent", "assessment_resume": True,
        "target_info": {"primary_target": target},
        "capability_map": {"target": target, "scope": target},
        "engagement_brain": {"coverage_cells": [{
            "id": "saved-ssrf", "host": "app.test", "path": "/preview",
            "method": "GET", "parameter": "query:url", "status": "untested",
            "source": "parameter_inventory", "observation_source": "browser_link",
            "specialist": "ssrf", "test_type": "ssrf",
        }]},
        "execution_trace": [],
    }
    step = forced_next_step(state)
    assert step["tool_name"] == "fireteam_dispatch"
    assert step["tool_args"]["mode"] == "coverage_followup"
    assert "class_coverage_first_pass" in complete_blocked_reason(state)

    state["execution_trace"] = [{
        "tool_name": "fireteam_dispatch", "tool_args": step["tool_args"],
        "success": True,
    }]
    assert forced_next_step(state) is None  # No identical retry without a receipt.
    assert "class_coverage_first_pass" in complete_blocked_reason(state)


def test_normal_assessment_runs_mapped_class_checks_before_general_fireteam():
    target = "https://app.test"
    trace = [{"tool_name": name, "success": True} for name in (
        "execute_deep_crawl", "execute_feroxbuster", "fingerprint_api",
        "fetch_lazy_chunks", "extract_js_endpoints", "sync_engagement_brain",
    )]
    trace.append({"tool_name": "scoped_browser_assessment", "success": True,
                  "tool_args": {"operation": "inspect_js", "url": target}})
    state = {
        "mode": "agent", "target_info": {"primary_target": target},
        "capability_map": {"target": target, "scope": target},
        "execution_trace": trace,
        "engagement_brain": {"coverage_cells": [{
            "id": "header-check", "host": "app.test", "path": "/search",
            "method": "GET", "parameter": "query:q", "status": "untested",
            "source": "parameter_inventory", "observation_source": "browser_link",
            "specialist": "injection", "test_type": "crlf",
        }]},
    }
    step = forced_next_step(state)
    assert step["tool_name"] == "fireteam_dispatch"
    assert step["tool_args"]["mode"] == "coverage_followup"
    assert step["tool_args"]["specialists"] == ["injection"]


def test_finished_surface_loop_still_requires_class_probe_receipt():
    target = "https://app.test"
    trace = [{"tool_name": name, "success": True} for name in (
        "execute_deep_crawl", "execute_feroxbuster", "fingerprint_api",
        "fetch_lazy_chunks", "extract_js_endpoints", "sync_engagement_brain",
        "fireteam_dispatch",
    )]
    state = {
        "mode": "agent", "target_info": {"primary_target": target},
        "capability_map": {"target": target}, "execution_trace": trace,
        "engagement_brain": {"coverage_cells": [{
            "id": "ssrf", "host": "app.test", "path": "/preview",
            "status": "untested", "source": "parameter_inventory",
            "specialist": "ssrf", "test_type": "ssrf",
        }]},
    }
    progress = loop_progress(state)
    assert [row["id"] for row in progress["missing"]] == [
        "class_coverage_first_pass",
    ]
    assert progress["ready_to_complete"] is False
    assert "class_coverage_first_pass" in complete_blocked_reason(state)

    state["engagement_brain"]["coverage_cells"][0]["probe_artifact_ids"] = ["receipt-1"]
    assert loop_progress(state)["ready_to_complete"] is True


def test_stalled_coverage_wave_does_not_starve_other_specialists():
    target = "https://app.test"
    state = {"engagement_brain": {"coverage_cells": [{
        "id": f"cell-{index}", "host": "app.test", "path": f"/item/{index}",
        "status": "untested", "source": "parameter_inventory",
        "specialist": f"specialist_{index}", "test_type": f"class_{index}",
    } for index in range(7)]}}
    first = _coverage_followup_wave(state, [], target)
    assert first["tool_args"]["specialists"] == [
        "specialist_0", "specialist_1", "specialist_2", "specialist_3",
    ]
    trace = [{"tool_name": "fireteam_dispatch", "tool_args": first["tool_args"]}]
    second = _coverage_followup_wave(state, trace, target)
    assert second["tool_args"]["specialists"] == [
        "specialist_4", "specialist_5", "specialist_6",
    ]
    trace.append({"tool_name": "fireteam_dispatch", "tool_args": second["tool_args"]})
    assert _coverage_followup_wave(state, trace, target) is None


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


def test_no_directory_constraint_still_runs_observed_input_first_pass():
    target = "https://app.test"
    state = {
        "mode": "agent",
        "target_info": {"primary_target": target},
        "skip_directory_enrichment": True,
        "capability_map": {
            "target": target, "scope": target,
            "forms": [{"method": "GET", "action": "/catalog", "inputs": ["category"]}],
        },
        "engagement_brain": {"coverage_cells": [{
            "id": "catalog-category-sqli", "host": "app.test", "path": "/catalog",
            "method": "GET", "parameter": "query:category", "status": "untested",
            "source": "parameter_inventory", "observation_source": "observed_form",
            "specialist": "sqli", "test_type": "sqli",
        }]},
        "execution_trace": [
            {"tool_name": "execute_deep_crawl", "success": True},
            {"tool_name": "sync_engagement_brain", "success": True},
        ],
    }

    step = forced_next_step(state)
    assert step["tool_name"] == "probe_observed_input_batch"
    assert step["tool_args"]["pending_input_count"] == 1
