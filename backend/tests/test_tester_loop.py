"""Curious-tester loop: crawl, dir brute, params, fireteam — not fingerprint-and-stop."""

from app.services.agent.assessment_kickoff import root_needs_dir_brute
from app.services.agent.tester_loop import (
    complete_blocked_reason,
    forced_next_step,
    normalized_tools_run,
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


def test_interceptor_job_forces_attach_not_second_crawl():
    url = "https://app.example.com"
    step = forced_next_step({
        "original_objective": url,
        "interceptor_job_id": "job-123",
        "target_info": {"primary_target": url},
        "execution_trace": [],
    })
    assert step and step["tool_name"] == "execute_interceptor"


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
