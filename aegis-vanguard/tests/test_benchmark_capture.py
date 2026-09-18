"""Authorized-local-benchmark (flag-capture) mode wiring.

Covers the three pieces that turn "detect the vuln" into "capture the flag"
without ever handing the agent the answer:

* the ``AEGIS_BENCHMARK_PROOF`` env toggle + directive text,
* injection of the directive into every parallel hunter's opening task, and
* the ``confirm_vulnerability_poc`` evidence path carrying a captured
  ``FLAG{...}`` all the way into the findings sink the judge reads.
"""

import json

import pytest

from agent import hunt_patterns
from agent.parallel_subagents import ParallelVulnPhase


# --- Directive toggle ------------------------------------------------------

def test_benchmark_mode_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_BENCHMARK_PROOF", raising=False)
    assert hunt_patterns.benchmark_mode_enabled() is False
    assert hunt_patterns.benchmark_directive() == ""


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_benchmark_mode_enabled_by_env(monkeypatch, value):
    monkeypatch.setenv("AEGIS_BENCHMARK_PROOF", value)
    assert hunt_patterns.benchmark_mode_enabled() is True
    directive = hunt_patterns.benchmark_directive()
    assert "FLAG{" in directive
    # Integrity guardrail: the flag must come from the target, never be supplied.
    assert "NOT given to you" in directive


def test_benchmark_directive_does_not_leak_a_concrete_flag(monkeypatch):
    """The directive teaches how to capture a flag, never what the flag is."""
    monkeypatch.setenv("AEGIS_BENCHMARK_PROOF", "1")
    directive = hunt_patterns.benchmark_directive()
    # Only the literal placeholder token, no 64-hex XBEN-style answer baked in.
    assert "FLAG{...}" in directive
    import re
    assert re.search(r"FLAG\{[0-9a-f]{16,}\}", directive) is None


# --- Hunter-task injection -------------------------------------------------

def _hunter(name="injection_hunter"):
    class _Stub:
        pass
    h = _Stub()
    h.name = name
    return h


def test_hunter_task_carries_directive_when_enabled(monkeypatch):
    monkeypatch.setenv("AEGIS_BENCHMARK_PROOF", "1")
    task = ParallelVulnPhase._build_hunter_task(_hunter(), "Hunt.", "recon brief")
    assert "capture the proof token" in task.lower()
    # It leads the message so the hunter reads it before anything else.
    assert task.strip().startswith("## AUTHORIZED LOCAL CTF BENCHMARK")


def test_hunter_task_omits_directive_when_disabled(monkeypatch):
    monkeypatch.delenv("AEGIS_BENCHMARK_PROOF", raising=False)
    task = ParallelVulnPhase._build_hunter_task(_hunter(), "Hunt.", "recon brief")
    assert "FLAG{" not in task
    assert "AUTHORIZED LOCAL CTF BENCHMARK" not in task


# --- Evidence capture path (flag → sink the judge reads) -------------------

def test_confirm_poc_carries_execution_evidence_to_sink(monkeypatch, tmp_path):
    import agent.agents as agents

    sink = tmp_path / "findings.jsonl"
    monkeypatch.setenv("AEGIS_FINDINGS_SINK", str(sink))
    monkeypatch.delenv("ASM_API_URL", raising=False)  # dry-run, no network
    monkeypatch.setattr(agents, "_bridge", None)  # fresh bridge picks up the sink

    flag = "FLAG{" + "f" * 64 + "}"
    agents.confirm_vulnerability_poc(
        host="localhost",
        finding_title="IDOR to flag disclosure",
        vuln_type="idor",
        endpoint="http://localhost/api/orders/2",
        payload="GET /api/orders/2 as user_A",
        response_snippet=f"200 OK\n\n{flag}\n",
        execution_evidence=flag,
        current_severity="high",
        tool="authz_diff",
    )

    lines = [json.loads(l) for l in sink.read_text().splitlines() if l.strip()]
    assert len(lines) == 1
    poc = lines[0]["raw_data"]["poc"]
    assert poc["execution_evidence"] == flag
    # The judge's _finding_blob dumps the whole record; the flag must be in it.
    assert flag in json.dumps(lines[0])
