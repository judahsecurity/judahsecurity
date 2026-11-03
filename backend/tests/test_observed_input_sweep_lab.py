"""Exercise the first sweep against independent vulnerable and patched apps."""

import asyncio
import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.coverage_cells import claim_coverage_cell_leases, seed_parameter_coverage_cells
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.evidence_store import evidence_store
from app.services.agent.independent_verify import candidate_from_dict, run_independent_verifiers
from app.services.agent.observed_input_batch import run_observed_input_batch
from app.services.agent.private_capture_store import load_capture
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.scoped_assessment import browser_post_replay
from app.services.agent.scoped_assessment import http_observe
from app.services.agent.tools import ASMToolsManager
from harness.local_harness.benchmark.class_lab import handler_for


@pytest.mark.parametrize("bug_class", ["sqli", "xss"])
@pytest.mark.parametrize("vulnerable", [True, False])
def test_exact_observed_input_sweep_retains_both_responses(
    bug_class, vulnerable, tmp_path, monkeypatch,
):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), handler_for(bug_class, vulnerable, ""),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        manager = ASMToolsManager()
        register_scope(manager, base)
        manager._fallback_target = base
        manager._capability_map = {"target": base, "scope": base}
        observed_url = base + "/search?q=public&view=full"
        manager._scoped_link_baselines = {"anonymous": [observed_url]}
        brain = EngagementBrain(target=base)
        seed_parameter_coverage_cells(brain, [{
            "method": "GET", "host": f"127.0.0.1:{server.server_port}",
            "path": "/search", "name": "q", "location": "query",
            "identity": "anonymous", "source": "browser_link", "testable": True,
        }])
        for row in brain.coverage_cells:
            if row["test_type"] != bug_class:
                row["status"] = "skipped"
        lease = claim_coverage_cell_leases(
            brain, [bug_class], allowed_cell_ids=frozenset(
                row["id"] for row in brain.coverage_cells if row["test_type"] == bug_class
            ), first_pass_only=True,
        )[bug_class]
        manager._engagement_brain = brain.to_dict()
        result = asyncio.run(manager.scoped_input_sweep_assigned(
            lease.coverage_cell_id, lease.id,
        ))
        assert result["success"] is True, result
        assert result["proof_confirmed"] is False
        assert result["baseline_evidence_id"] != result["probe_evidence_id"]
        assert result["probe_result"]["baseline_status"] == 200
        assert result["probe_result"]["lead_kind"] == (
            "reflected" if bug_class == "xss" else "sql_difference"
        )
        store = evidence_store(manager)
        captures = [load_capture(store.namespace, result[key]) for key in
                    ("baseline_evidence_id", "probe_evidence_id")]
        assert all(capture and capture["identity"] == "anonymous" for capture in captures)
        baseline, probe = [json.loads(capture["private"]) for capture in captures]
        assert baseline["request_url"] == observed_url
        assert "view=full" in probe["request_url"]
        assert base64.b64decode(baseline["response_body_base64"])
        assert base64.b64decode(probe["response_body_base64"])
        assert manager._engagement_brain["candidates"] == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("bug_class", ["sqli", "xss"])
def test_captured_post_sweep_replays_one_mutation_and_saves_both_responses(
    bug_class, tmp_path, monkeypatch,
):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    base = "https://app.test"
    public, private = package_exchange(
        url=base + "/api/search", expected_origin=base, action_ref="search",
        method="POST", resource_type="fetch", status=200,
        content_type="text/html", request_body=b"q=public&view=full&csrf_token=old",
        response_body=b"initial", request_content_type="application/x-www-form-urlencoded",
        page_url=base + "/search",
    )
    manager = ASMToolsManager()
    register_scope(manager, base)
    manager._fallback_target = base
    manager._capability_map = {"target": base, "scope": base}
    manager._scoped_browser_exchanges = {"capture-id": {
        "identity": "anonymous", "verifier_run_id": None,
        "private": private, "public": public,
    }}
    manager._scoped_body_replay_paths = {"/api/search"}
    brain = EngagementBrain(target=base)
    seed_parameter_coverage_cells(brain, [{
        "method": "POST", "host": "app.test", "path": "/api/search",
        "name": "q", "location": "body_form", "identity": "anonymous",
        "source": "browser_traffic", "artifact_id": "capture-id", "testable": True,
    }])
    for row in brain.coverage_cells:
        if row["test_type"] != bug_class:
            row["status"] = "skipped"
    lease = claim_coverage_cell_leases(brain, [bug_class], first_pass_only=True)[bug_class]
    manager._engagement_brain = brain.to_dict()
    seen = []

    async def replay(_private, *, payloads, capture_body, **_kwargs):
        seen.append(payloads)
        assert capture_body is True
        result = {}
        for kind, suffix in payloads.items():
            response = ("response " + suffix).encode()
            request = ("q=public" + suffix + "&view=full&csrf_token=fresh").encode()
            result[kind] = {
                "status": 200, "content_type": "text/html",
                "bytes_captured": len(response), "truncated": False,
                "body_sha256": hashlib.sha256(response).hexdigest(),
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "json_array_lengths": {}, "sql_error_family": "",
                "redirected": False, "_private_body": response,
                "_private_request_body": request,
            }
        return result

    monkeypatch.setattr(browser_post_replay, "replay_observed_post_controls", replay)
    result = asyncio.run(manager.scoped_input_sweep_assigned(
        lease.coverage_cell_id, lease.id,
    ))
    assert result["success"] is True, result
    assert list(seen[0]) == ["baseline", "probe"]
    assert seen[0]["baseline"] == ""
    if bug_class == "xss":
        assert seen[0]["probe"].startswith("prowlxss")
    else:
        assert seen[0]["probe"] == "'"
    assert result["proof_confirmed"] is False
    assert result["baseline_evidence_id"] != result["probe_evidence_id"]
    store = evidence_store(manager)
    for key in ("baseline_evidence_id", "probe_evidence_id"):
        row = load_capture(store.namespace, result[key])
        assert row is not None
        captured = json.loads(row["private"])
        assert captured["request_url"] == base + "/api/search"
        assert b"view=full" in base64.b64decode(captured["request_body_base64"])
        assert base64.b64decode(captured["response_body_base64"])


def test_captured_get_xhr_sweep_uses_browser_replay(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    base = "https://app.test"
    public, private = package_exchange(
        url=base + "/api/search?q=public&view=full", expected_origin=base,
        action_ref="search", method="GET", resource_type="fetch", status=200,
        content_type="application/json", request_body=b"",
        response_body=b'{"results":[]}', page_url=base + "/search",
        request_headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
    )
    manager = ASMToolsManager()
    register_scope(manager, base)
    manager._fallback_target = base
    manager._capability_map = {"target": base, "scope": base}
    manager._scoped_browser_exchanges = {"capture-id": {
        "identity": "anonymous", "verifier_run_id": None,
        "private": private, "public": public,
    }}
    brain = EngagementBrain(target=base)
    seed_parameter_coverage_cells(brain, [{
        "method": "GET", "host": "app.test", "path": "/api/search",
        "name": "q", "location": "query", "identity": "anonymous",
        "source": "browser_traffic", "artifact_id": "capture-id", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"], first_pass_only=True)["sqli"]
    manager._engagement_brain = brain.to_dict()
    seen = []

    async def replay(_private, *, variants, capture_body, **_kwargs):
        assert capture_body is True
        seen.append(variants)
        key, url = next(iter(variants.items()))
        response = b"baseline" if key == "baseline" else b"mutated"
        return {key: {
            "status": 200, "content_type": "application/json",
            "bytes_captured": len(response), "truncated": False,
            "body_sha256": hashlib.sha256(response).hexdigest(),
            "location_sha256": "", "sql_error_family": "",
            "redirected": False, "_private_body": response,
            "_private_location": "", "target_template": url,
        }}

    monkeypatch.setattr(browser_post_replay, "has_replayable_source",
                        lambda *_args: True)
    monkeypatch.setattr(browser_post_replay, "replay_observed_get_controls", replay)
    monkeypatch.setattr(http_observe, "observe_get", lambda *_args, **_kwargs:
                        (_ for _ in ()).throw(AssertionError("Direct GET bypassed browser")))
    result = asyncio.run(manager.scoped_input_sweep_assigned(
        lease.coverage_cell_id, lease.id,
    ))
    assert result["success"] is True, result
    assert [list(row) for row in seen] == [["baseline"], ["probe"]]
    assert seen[0]["baseline"] == base + "/api/search?q=public&view=full"
    assert "view=full" in seen[1]["probe"]


@pytest.mark.parametrize("vulnerable", [True, False])
def test_sql_lab_sweep_controls_and_independent_repeat(vulnerable, tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), handler_for("sqli", vulnerable, ""),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        manager = ASMToolsManager()
        register_scope(manager, base)
        manager._fallback_target = base
        observed_url = base + "/search?q=public&view=full"
        manager._capability_map = {
            "target": base, "scope": base,
            "api_samples": [{"url": observed_url, "method": "GET",
                             "identity": "anonymous"}],
        }
        manager._scoped_link_baselines = {"anonymous": [observed_url]}
        brain = EngagementBrain(target=base)
        seed_parameter_coverage_cells(brain, [{
            "method": "GET", "host": f"127.0.0.1:{server.server_port}",
            "path": "/search", "name": "q", "location": "query",
            "identity": "anonymous", "source": "browser_link", "testable": True,
        }])
        for row in brain.coverage_cells:
            if row["test_type"] != "sqli":
                row["status"] = "skipped"
        manager._engagement_brain = brain.to_dict()

        async def run():
            batch = await run_observed_input_batch(manager, target=base, max_checks=2)
            candidates = [candidate_from_dict(row)
                          for row in manager._engagement_brain["candidates"]]
            reports = await run_independent_verifiers(
                candidates, llm=None, tools_manager=manager, targets=[base],
            ) if candidates else []
            return batch, reports

        batch, reports = asyncio.run(run())
        assert batch["processed"] == 2
        assert batch["results"][0]["outcome"] == "inconclusive"
        assert batch["results"][0]["baseline_evidence_id"]
        assert batch["results"][0]["probe_evidence_id"]
        assert batch["results"][1]["outcome"] == (
            "proof_signal" if vulnerable else "inconclusive"
        )
        assert [report["status"] for report in reports] == (
            ["confirmed"] if vulnerable else []
        )
        assert [row["status"] for row in manager._engagement_brain["candidates"]] == (
            ["confirmed"] if vulnerable else []
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_stable_redirect_baseline_is_saved_and_compared(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            from urllib.parse import parse_qs, urlsplit

            value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            self.send_response(302)
            self.send_header("Location", "/result?q=" + value)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        manager = ASMToolsManager()
        register_scope(manager, base)
        manager._fallback_target = base
        manager._capability_map = {"target": base, "scope": base}
        manager._scoped_link_baselines = {"anonymous": [base + "/search?q=public"]}
        brain = EngagementBrain(target=base)
        seed_parameter_coverage_cells(brain, [{
            "method": "GET", "host": f"127.0.0.1:{server.server_port}",
            "path": "/search", "name": "q", "location": "query",
            "identity": "anonymous", "source": "browser_link", "testable": True,
        }])
        lease = claim_coverage_cell_leases(brain, ["sqli"], first_pass_only=True)["sqli"]
        manager._engagement_brain = brain.to_dict()
        result = asyncio.run(manager.scoped_input_sweep_assigned(
            lease.coverage_cell_id, lease.id,
        ))
        assert result["success"] is True
        assert result["probe_result"]["baseline_status"] == 302
        assert result["probe_result"]["inconclusive"] is False
        assert result["probe_result"]["baseline_failure_reason"] == ""
        assert result["probe_result"]["lead_kind"] == "sql_difference"
        store = evidence_store(manager)
        baseline = load_capture(store.namespace, result["baseline_evidence_id"])
        assert json.loads(baseline["private"])["response_location"] == "/result?q=public"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
