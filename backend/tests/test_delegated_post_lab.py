"""Unattended POST testing: observe a blocked write, propose it, verify independently.

Runs real Chromium against the class lab's POST bug classes. Browser discovery
clicks a plain button in write-observation mode, records the POST without
sending it, the agent proposes the path under delegated approval, the observed
input sweep tests it, and the independent verifier must reproduce the proof.
Without delegation the inputs stay blocked; the patched app yields no finding.
"""

import json
import os
import threading
from http.server import ThreadingHTTPServer

import pytest

from app.services.agent import confirmation_service
from app.services.agent.assessment_scope import register_scope
from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.independent_verify import candidate_from_dict, run_independent_verifiers
from app.services.agent.observed_input_batch import run_observed_input_batch
from app.services.agent.tools import (
    ASMToolsManager, current_organization_id, current_session_id,
)
from harness.local_harness.benchmark.class_lab import handler_for

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
    reason="Opt-in local Chromium fixture",
)


def _lab(bug_class, vulnerable):
    posts = []
    base_handler = handler_for(bug_class, vulnerable, "")

    class Recording(base_handler):
        def do_POST(self):
            posts.append(self.path)
            return super().do_POST()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Recording)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, posts


async def _run(bug_class, test_type, *, vulnerable, delegated):
    server, posts = _lab(bug_class, vulnerable)
    base = f"http://127.0.0.1:{server.server_port}"
    org = current_organization_id.set(77)
    session = current_session_id.set(f"post-lab-{bug_class}-{vulnerable}-{delegated}")
    try:
        manager = ASMToolsManager()
        register_scope(manager, base)
        manager._fallback_target = base
        manager.set_scoped_assessment_policy(
            {"delegated_replay_approval": {"enabled": True}} if delegated else {}
        )
        discovery = json.loads(await manager.scoped_browser_assessment(
            operation="inspect_js", url=base + "/",
        ))
        posts_after_discovery = len(posts)
        brain = engagement_brain_from_dict(manager._engagement_brain)
        observed = [op for op in brain.application_operations
                    if op.get("method") == "POST" and op.get("capture_ids")]
        proposals = [json.loads(await manager.propose_replay_path(op["path"]))
                     for op in observed]
        brain = engagement_brain_from_dict(manager._engagement_brain)
        for cell in brain.coverage_cells:
            if cell.get("test_type") != test_type:
                cell["status"] = "skipped"
        manager._engagement_brain = brain.to_dict()
        for _ in range(4):
            batch = await run_observed_input_batch(manager, target=base, max_checks=8)
            if not batch.get("processed"):
                break
        brain = engagement_brain_from_dict(manager._engagement_brain)
        candidates = [candidate_from_dict(row) for row in brain.candidates]
        reports = await run_independent_verifiers(
            candidates, llm=None, tools_manager=manager, targets=[base],
        ) if candidates else []
        brain = engagement_brain_from_dict(manager._engagement_brain)
        return {
            "discovery": discovery,
            "posts_after_discovery": posts_after_discovery,
            "observed": observed,
            "proposals": proposals,
            "cells": [cell for cell in brain.coverage_cells if cell.get("test_type") == test_type],
            "candidates": brain.candidates,
            "verifier": [report.get("status") for report in reports],
        }
    finally:
        current_session_id.reset(session)
        current_organization_id.reset(org)
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def operator_policy(monkeypatch, tmp_path):
    # No confirmation database in this fixture: stand in for an operator
    # policy that has approved the run.
    async def allow(*_args, **_kwargs):
        return {"decision": "auto"}

    monkeypatch.setattr(confirmation_service, "gate", allow)
    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))


@pytest.mark.asyncio
@pytest.mark.parametrize("bug_class,test_type,path", [
    ("sqli_post_blind", "sqli", "/api/filter"),
    ("xss_post_xhr", "xss", "/api/render"),
])
async def test_observed_post_needs_delegation(bug_class, test_type, path):
    result = await _run(bug_class, test_type, vulnerable=True, delegated=False)
    assert [op["path"] for op in result["observed"]] == [path]
    if bug_class == "sqli_post_blind":
        # A plain button: the write is recorded and blocked, never sent.
        assert result["discovery"]["blocked_writes_recorded"] == 1
        assert result["posts_after_discovery"] == 0
    assert all(not p["approved"] for p in result["proposals"])
    assert result["cells"] and all(cell["status"] == "blocked" for cell in result["cells"])
    assert result["candidates"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("bug_class,test_type", [
    ("sqli_post_blind", "sqli"),
    ("xss_post_xhr", "xss"),
])
async def test_delegated_post_is_found_and_independently_reproduced(bug_class, test_type):
    result = await _run(bug_class, test_type, vulnerable=True, delegated=True)
    assert [p["approved"] for p in result["proposals"]] == [True]
    assert [row["status"] for row in result["candidates"]] == ["confirmed"]
    assert result["verifier"] == ["confirmed"]


@pytest.mark.asyncio
@pytest.mark.parametrize("bug_class,test_type", [
    ("sqli_post_blind", "sqli"),
    ("xss_post_xhr", "xss"),
])
async def test_delegated_post_on_patched_app_has_no_finding(bug_class, test_type):
    result = await _run(bug_class, test_type, vulnerable=False, delegated=True)
    assert [p["approved"] for p in result["proposals"]] == [True]
    assert result["cells"] and all(cell["status"] != "blocked" for cell in result["cells"])
    assert result["candidates"] == []
