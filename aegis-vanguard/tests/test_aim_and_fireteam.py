"""Aim (core-hunter ranking) + fireteam tail-latency deadline.

Covers the three efficiency levers added to the autonomous fireteam:
  1. rank/select the core categories a page actually invites (aim),
  2. cap the core fireteam to the top-N (drop blind stragglers),
  3. abandon a hung hunter at a wall-clock deadline instead of blocking.

The budget-reserve lever is a two-line runner.price_limit_usd swap in
run_pentest._run_parallel_pipeline and is exercised there, not here.
"""

import sys
import time
import types

# Stub the LLM SDKs so agent.* imports without network deps.
for _m in ("anthropic", "litellm"):
    sys.modules.setdefault(_m, types.ModuleType(_m))

from agent.owasp_hunters import (  # noqa: E402
    CORE_CATEGORY_ORDER,
    create_hunters_for_engagement,
    rank_core_categories,
    select_core_categories,
)
from agent.parallel_subagents import ParallelVulnPhase  # noqa: E402
from agent.core import RunResult  # noqa: E402


# --------------------------------------------------------------------- aim

def test_injection_page_ranks_injection_first_and_drops_stragglers():
    recon = "POST /login form, ?id= and ?q= query params, mysql backend, /api/v1"
    sel, ranking = select_core_categories(recon, "", max_core_hunters=6)
    assert ranking[0]["category"] == "injection"
    assert "injection" in sel and "auth" in sel
    # The classes that wasted 30+ min on the real SQLi run must be dropped.
    for wasteful in ("open_redirect", "host_header", "saml_sso", "cache_poison"):
        assert wasteful not in sel


def test_ssrf_page_keeps_ssrf():
    recon = "minimal surface — just the main page with an SSRF form, url= param fetched server-side"
    sel, _ = select_core_categories(recon, "", max_core_hunters=6)
    assert "ssrf" in sel


def test_silent_page_keeps_high_yield_floor():
    # No signals at all: the base-prior classes must still be covered.
    sel, _ = select_core_categories("", "", max_core_hunters=6)
    for floor in ("injection", "auth", "authz", "xss"):
        assert floor in sel


def test_no_cap_keeps_every_core_category():
    sel, _ = select_core_categories("anything", "", max_core_hunters=None)
    assert set(sel) == set(CORE_CATEGORY_ORDER)
    # A cap >= core count is also a no-op.
    sel2, _ = select_core_categories("anything", "", max_core_hunters=99)
    assert set(sel2) == set(CORE_CATEGORY_ORDER)


def test_signal_beats_silent_base_prior():
    # An OAuth-heavy page: oauth (no base prior) must outrank silent cors/csrf.
    recon = "/oauth/authorize, /callback, client_id, redirect_uri, .well-known/openid-configuration, PKCE"
    ranking = {r["category"]: r["score"] for r in rank_core_categories(recon, "")}
    assert ranking["oauth"] > ranking["csrf"]
    assert ranking["oauth"] > ranking["cors"]


def test_create_hunters_respects_cap():
    recon = "SSRF form, url= param"
    full = create_hunters_for_engagement(max_turns=25, recon_brief=recon)
    capped = create_hunters_for_engagement(max_turns=25, recon_brief=recon, max_core_hunters=6)
    assert len(full) == len(CORE_CATEGORY_ORDER)  # no specialists signalled here
    assert len(capped) == 6
    assert {h.name for h in capped} <= {h.name for h in full}


# ---------------------------------------------------------- fireteam deadline

class _FakeSpan:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeTracer:
    def span(self, *a, **k):
        return _FakeSpan()


class _FakeRunner:
    """Returns fast for most hunters; one 'slow' hunter blocks past the deadline."""

    tracer = _FakeTracer()

    def run(self, agent, task, context):
        if "slow" in agent.name:
            time.sleep(10)
        return RunResult(
            agent_name=agent.name, messages=[], final_text="done",
            turns_used=2, tool_calls_made=3,
        )


class _FakeAgent:
    def __init__(self, name):
        self.name = name
        self.max_turns = 5


def test_deadline_abandons_straggler_without_blocking():
    hunters = [_FakeAgent("injection_hunter"), _FakeAgent("xss_hunter"), _FakeAgent("slow_hunter")]
    phase = ParallelVulnPhase(runner=_FakeRunner(), hunters=hunters, per_hunter_timeout_sec=2.0)

    start = time.time()
    result = phase.run(task="t", shared_ctx={}, recon_brief="r")
    elapsed = time.time() - start

    # The phase must not wait the full 10s for the straggler.
    assert elapsed < 6.0, f"deadline not honored: blocked {elapsed:.1f}s"
    by_name = {h.name: h for h in result.hunters}
    assert by_name["slow_hunter"].error == "timed_out"
    assert by_name["injection_hunter"].error is None
    assert by_name["xss_hunter"].error is None


def test_harvest_flag_from_out_of_category_hunter():
    # Reproduces XBEN-020: a hunter READS the flag in a tool result but never
    # confirms it (wrong category). The fan-in must still capture it.
    from agent.parallel_subagents import ParallelVulnPhase
    flag = "FLAG{6e5d772fb6e28ca52985079acf7bfa46d729870e6bae73166208f1fdcd831667}"
    msgs = [
        {"role": "assistant", "content": [{"type": "text", "text": "SSRF territory, not mine."}]},
        {"role": "user", "content": [{
            "type": "tool_result", "tool_use_id": "t1",
            "content": '{"status":200,"body":"<h1>Internal Service</h1> FLAG: ' + flag + '"}',
        }]},
    ]
    rr = RunResult(agent_name="host_header_hunter", messages=msgs, final_text="done",
                   turns_used=5, tool_calls_made=9)
    harvested = ParallelVulnPhase._harvest_flags(rr, _FakeAgent("host_header_hunter"))
    assert len(harvested) == 1
    assert harvested[0]["flag"] == flag
    assert harvested[0]["severity"] == "critical"
    assert harvested[0]["vuln_type"] == "flag_capture"


def test_harvest_no_flag_is_noop():
    from agent.parallel_subagents import ParallelVulnPhase
    rr = RunResult(agent_name="xss_hunter", messages=[
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t",
                                       "content": '{"status":404,"body":"Not Found"}'}]},
    ], final_text="nothing found", turns_used=3, tool_calls_made=4)
    assert ParallelVulnPhase._harvest_flags(rr, _FakeAgent("xss_hunter")) == []


def test_no_deadline_waits_for_all():
    hunters = [_FakeAgent("injection_hunter"), _FakeAgent("xss_hunter")]
    phase = ParallelVulnPhase(runner=_FakeRunner(), hunters=hunters, per_hunter_timeout_sec=None)
    result = phase.run(task="t", shared_ctx={}, recon_brief="r")
    assert len(result.hunters) == 2
    assert all(h.error is None for h in result.hunters)
