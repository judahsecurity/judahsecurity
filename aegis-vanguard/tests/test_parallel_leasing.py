"""Breadth-before-depth leasing in the parallel fireteam orchestrator."""
import json

from agent.core import Agent, RunResult
from agent.coverage import CoverageLedger
from agent.parallel_subagents import ParallelVulnPhase


def _surface(n=6):
    return {"forms": [{
        "action_url": f"https://example.test/p{i}", "method": "GET",
        "eligible_parameters": ["q"],
    } for i in range(n)]}


class _CapturingRunner:
    """Runner that records each hunter's task and returns a canned result."""

    def __init__(self, raise_for=None):
        self.tasks = {}
        self.calls = {}
        self.raise_for = raise_for or set()

        class _Tracer:
            def span(self, *a, **k):
                import contextlib
                return contextlib.nullcontext()
        self.tracer = _Tracer()

    def run(self, agent, task, context):
        self.calls[agent.name] = self.calls.get(agent.name, 0) + 1
        self.tasks[agent.name] = task
        if agent.name in self.raise_for:
            raise RuntimeError("handoff timed out")
        return RunResult(
            agent_name=agent.name, messages=[], final_text="done",
            tool_calls_made=1, turns_used=1,
        )


def _hunter(name):
    return Agent(name=name, instructions="hunt", max_turns=3)


def test_hunter_task_embeds_leased_worklist():
    ledger = CoverageLedger.from_input_surface(_surface(n=4))
    runner = _CapturingRunner()
    phase = ParallelVulnPhase(
        runner=runner, hunters=[_hunter("injection_hunter")], coverage=ledger,
    )
    phase.run(task="hunt", shared_ctx={}, recon_brief="")

    task = runner.tasks["injection_hunter"]
    assert "leased worklist" in task
    # The worklist names the SQLi cells the injection hunter owns.
    assert "query:q" in task and "sqli" in task


def test_two_hunters_get_disjoint_worklists():
    ledger = CoverageLedger.from_input_surface(_surface(n=8))
    runner = _CapturingRunner()
    phase = ParallelVulnPhase(
        runner=runner,
        hunters=[_hunter("injection_hunter"), _hunter("xss_hunter")],
        coverage=ledger,
        lease_limit=4,
    )
    phase.run(task="hunt", shared_ctx={}, recon_brief="")

    # Injection owns sqli; xss owns xss — different classes, no shared cells.
    inj = runner.tasks["injection_hunter"]
    xss = runner.tasks["xss_hunter"]
    assert "sqli" in inj and "xss" in xss
    # Neither leased worklist should contain the other's class rows.
    assert '"vulnerability_class": "xss"' not in inj
    assert '"vulnerability_class": "sqli"' not in xss


def test_failed_hunter_releases_its_lease_after_one_retry():
    ledger = CoverageLedger.from_input_surface(_surface(n=3))
    runner = _CapturingRunner(raise_for={"injection_hunter"})
    phase = ParallelVulnPhase(
        runner=runner, hunters=[_hunter("injection_hunter")], coverage=ledger,
    )
    result = phase.run(task="hunt", shared_ctx={}, recon_brief="")

    # Retried exactly once (two attempts total) before giving up.
    assert runner.calls["injection_hunter"] == 2
    assert result.hunters[0].error
    # Its leased SQLi cells returned to the pending pool — coverage not lost.
    sqli_states = {r["state"] for r in ledger.snapshot()
                   if r["vulnerability_class"] == "sqli"}
    assert sqli_states == {"pending"}


def test_no_coverage_ledger_runs_without_worklist():
    runner = _CapturingRunner()
    phase = ParallelVulnPhase(runner=runner, hunters=[_hunter("xss_hunter")])
    phase.run(task="hunt", shared_ctx={}, recon_brief="")
    assert "leased worklist" not in runner.tasks["xss_hunter"]
