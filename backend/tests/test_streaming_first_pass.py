"""First-pass input testing runs while the deep crawl is still mapping."""

import asyncio

import pytest

from app.core.config import settings
from app.services.agent import observed_input_batch, streaming_first_pass as sfp
from app.services.deep_crawl_service import CrawlResult

TARGET = "https://shop.test"


class Manager:
    def __init__(self):
        self._capability_map = {}
        self._engagement_brain = None
        self._fallback_target = TARGET


def _crawl_with_catalog():
    result = CrawlResult(target=TARGET, scope=TARGET)
    result.pages_visited = [f"{TARGET}/", f"{TARGET}/catalog?category=Gin"]
    result.discovered_links = [{"url": f"{TARGET}/catalog", "query_keys": ["category"],
                                "source_path": "/"}]
    return result


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STREAMING_FIRST_PASS", True)


def _fake_batch(monkeypatch, calls, outcome="proof_signal"):
    async def batch(manager, *, target, max_checks, max_seconds):
        cells = observed_input_batch.pending_first_pass_cells(
            manager._engagement_brain or {}, target=target)
        calls.append({"target": target, "max_checks": max_checks,
                      "pending": [(c.get("path"), c.get("parameter"), c.get("specialist"))
                                  for c in cells]})
        return {"results": [{"coverage_cell_id": c["id"], "outcome": outcome,
                             "candidate_id": "cand-1" if outcome == "proof_signal" else ""}
                            for c in cells[:max_checks]]}

    monkeypatch.setattr(observed_input_batch, "run_observed_input_batch", batch)


def test_inputs_are_tested_before_the_crawl_returns(monkeypatch, enabled):
    calls = []
    _fake_batch(monkeypatch, calls)
    manager = Manager()
    seen_during_crawl = []

    async def crawl():
        result = _crawl_with_catalog()
        sfp.report_crawl_progress(result)
        # Give the background tester a chance to run while "crawling".
        for _ in range(20):
            await asyncio.sleep(0)
            if calls:
                break
        seen_during_crawl.append(bool(calls))
        return {"success": True, "output": "crawl done"}

    out = asyncio.run(sfp.run_with_streaming_first_pass(manager, TARGET, crawl))
    assert seen_during_crawl == [True]
    tested = {(path, param) for path, param, _ in calls[0]["pending"]}
    assert ("/catalog", "query:category") in tested
    assert calls[0]["max_checks"] == sfp.BATCH_CHECKS
    assert out["streaming_first_pass"]["checks"] >= 1
    assert out["streaming_first_pass"]["candidates"] == ["cand-1"]
    assert "First pass during the crawl" in out["output"]
    # The partial map reached the manager, so baselines resolve as usual.
    assert manager._capability_map.get("target")


def test_same_surface_is_not_retested_on_every_page(monkeypatch, enabled):
    calls = []
    _fake_batch(monkeypatch, calls, outcome="tested_clean")
    manager = Manager()

    async def crawl():
        result = _crawl_with_catalog()
        for _ in range(3):
            sfp.report_crawl_progress(result)
            for _ in range(10):
                await asyncio.sleep(0)
        return {"success": True, "output": ""}

    asyncio.run(sfp.run_with_streaming_first_pass(manager, TARGET, crawl))
    assert len(calls) == 1


def test_missing_baseline_blocks_are_reopened_for_the_post_crawl_pass(monkeypatch, enabled):
    manager = Manager()

    async def batch(mgr, *, target, max_checks, max_seconds):
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(mgr._engagement_brain)
        for cell in brain.coverage_cells:
            cell.update(status="blocked", first_pass_outcome="unattempted",
                        first_pass_blocked_reason="observed_query_baseline_missing",
                        first_pass_at=10**10)
        mgr._engagement_brain = brain.to_dict()
        return {"results": []}

    monkeypatch.setattr(observed_input_batch, "run_observed_input_batch", batch)

    async def crawl():
        sfp.report_crawl_progress(_crawl_with_catalog())
        for _ in range(20):
            await asyncio.sleep(0)
        return {"success": True, "output": ""}

    asyncio.run(sfp.run_with_streaming_first_pass(manager, TARGET, crawl))
    cells = manager._engagement_brain["coverage_cells"]
    assert cells and all(c.get("status") == "untested" for c in cells)
    assert not any(c.get("first_pass_blocked_reason") for c in cells)
    assert observed_input_batch.pending_first_pass_cells(manager._engagement_brain, target=TARGET)


def test_disabled_or_pilot_runs_the_crawl_unchanged(monkeypatch):
    calls = []
    _fake_batch(monkeypatch, calls)
    monkeypatch.setattr(settings, "AGENT_STREAMING_FIRST_PASS", False)

    async def crawl():
        sfp.report_crawl_progress(_crawl_with_catalog())
        await asyncio.sleep(0)
        return {"success": True, "output": "x"}

    out = asyncio.run(sfp.run_with_streaming_first_pass(Manager(), TARGET, crawl))
    assert out == {"success": True, "output": "x"} and not calls

    monkeypatch.setattr(settings, "AGENT_STREAMING_FIRST_PASS", True)
    from app.services.agent import pilot_policy

    monkeypatch.setattr(pilot_policy, "current_pilot", lambda: object())
    assert not sfp.streaming_enabled()


def test_a_failing_tester_never_fails_the_crawl(monkeypatch, enabled):
    async def broken(*args, **kwargs):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(observed_input_batch, "run_observed_input_batch", broken)

    async def crawl():
        sfp.report_crawl_progress(_crawl_with_catalog())
        for _ in range(20):
            await asyncio.sleep(0)
        return {"success": True, "output": "ok"}

    out = asyncio.run(sfp.run_with_streaming_first_pass(Manager(), TARGET, crawl))
    assert out["success"] is True
    assert "RuntimeError" in out["streaming_first_pass"]["errors"]


def test_hook_is_a_noop_outside_a_streaming_crawl():
    sfp.report_crawl_progress(object())  # must not raise


# ------------------------------------------- end to end against the SQLi lab

@pytest.mark.parametrize("vulnerable", [True, False])
def test_lab_sqli_is_found_during_the_crawl_and_verified(vulnerable, tmp_path, monkeypatch,
                                                         enabled):
    """True positive on the vulnerable twin, nothing on the patched twin."""
    import threading
    from http.server import ThreadingHTTPServer

    from app.services.agent.assessment_scope import register_scope
    from app.services.agent.independent_verify import (
        candidate_from_dict, run_independent_verifiers,
    )
    from app.services.agent.tools import ASMToolsManager
    from harness.local_harness.benchmark.class_lab import handler_for

    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for("sqli", vulnerable, ""))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        manager = ASMToolsManager()
        register_scope(manager, base)
        manager._fallback_target = base
        observed = base + "/search?q=public&view=full"
        manager._scoped_link_baselines = {"anonymous": [observed]}

        crawl_result = CrawlResult(target=base, scope=base)
        crawl_result.pages_visited = [base + "/", observed]
        crawl_result.discovered_links = [{"url": base + "/search", "query_keys": ["q", "view"],
                                          "source_path": "/"}]

        async def crawl():
            sfp.report_crawl_progress(crawl_result)
            # The crawl keeps "mapping" while the tester probes the lab.
            for _ in range(200):
                await asyncio.sleep(0.05)
                cells = (manager._engagement_brain or {}).get("coverage_cells") or []
                if any(c.get("first_pass_outcome") == "proof_signal" for c in cells) or (
                        not vulnerable and any(c.get("first_pass_outcome") for c in cells
                                               if c.get("parameter") == "query:q")):
                    break
            return {"success": True, "output": "crawl"}

        async def run():
            out = await sfp.run_with_streaming_first_pass(manager, base, crawl)
            candidates = [candidate_from_dict(row)
                          for row in manager._engagement_brain.get("candidates") or []]
            reports = await run_independent_verifiers(
                candidates, llm=None, tools_manager=manager, targets=[base],
            ) if candidates else []
            return out, reports

        out, reports = asyncio.run(run())
        summary = out["streaming_first_pass"]
        assert summary["checks"] >= 1, summary
        q_cells = [c for c in manager._engagement_brain["coverage_cells"]
                   if c.get("parameter") == "query:q" and c.get("test_type") == "sqli"]
        assert q_cells and q_cells[0].get("first_pass_outcome"), q_cells
        if vulnerable:
            assert summary["outcomes"].get("proof_signal", 0) >= 1, summary
            assert [r["status"] for r in reports] == ["confirmed"]
        else:
            assert "proof_signal" not in summary["outcomes"], summary
            assert reports == []
    finally:
        server.shutdown()
        server.server_close()
