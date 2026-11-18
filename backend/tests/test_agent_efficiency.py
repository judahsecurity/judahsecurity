"""Specialist wrap-up, stop reasons, wave deltas and shared LLM breakers."""

import json
from types import SimpleNamespace

import pytest
from app.services.agent import fireteam_service, orchestrator
from app.services.agent.auto_prompter import (
    EXHAUSTED,
    LLM_ERROR,
    Rewrite,
    apply_rewrite_to_directive,
    classify_failure,
    rewrite_note,
)
from app.services.agent.fireteam_service import SpecialistProfile, _run_specialist
from app.services.agent.operation_directive import OperationDirective
from app.services.agent.penetration_task_graph import (
    ExecutorSummary,
    parse_executor_summary,
    wave_changes,
)

TARGET = "https://app.example.test"


class _Manager:
    _credential_testing_allowed = False
    _oob_callbacks_allowed = False

    def get_tool(self, name):
        def tool():
            pass
        return tool


def _profile(tools=("safe_tool", "submit_finding_candidate", "save_note"), max_iterations=5):
    return SpecialistProfile(
        name="bounded", role="Safe test", allowed_tools=list(tools),
        max_iterations=max_iterations, max_tools_per_iteration=4,
    )


def _directive(**kwargs):
    base = dict(specialist="bounded", epithet="Bounded", target=TARGET, goal="Check")
    base.update(kwargs)
    return OperationDirective(**base)


def _patch(monkeypatch, llm_replies):
    """llm_replies(kind, n) -> dict reply. Records tool calls and LLM kinds."""
    calls, kinds = [], []

    async def fake_llm(*_args, kind="", **_kwargs):
        kinds.append(kind)
        return SimpleNamespace(content=json.dumps(llm_replies(kind, len(kinds))))

    async def fake_invoke(_manager, name, args, **_kwargs):
        calls.append(name)
        return fireteam_service.ToolInvocation(tool=name, args=args, success=True, summary="ok")

    monkeypatch.setattr(orchestrator, "_ledger_llm_call", fake_llm)
    monkeypatch.setattr(fireteam_service, "_safe_invoke", fake_invoke)
    return calls, kinds


def _probe_then_wrap_up(kind, _n):
    if kind == "agent_specialist_wrapup":
        if _n and _wrap_state.get("sent"):
            return {
                "done": True, "summary": "Saved the reflected parameter lead.",
                "verdict": "inconclusive",
                "progress": "Tested q on /search; next: attribute-context payload",
            }
        _wrap_state["sent"] = True
        return {"tool_calls": [
            {"tool": "submit_finding_candidate", "args": {"title": "lead"}},
            {"tool": "safe_tool", "args": {}},  # probing is not allowed in wrap-up
        ]}
    return {"tool_calls": [{"tool": "safe_tool", "args": {}} for _ in range(3)]}


_wrap_state: dict = {}


@pytest.mark.asyncio
async def test_tool_budget_stop_gets_write_back_only_wrap_up(monkeypatch):
    _wrap_state.clear()
    calls, kinds = _patch(monkeypatch, _probe_then_wrap_up)
    report = await _run_specialist(
        _profile(), "Assess", [TARGET], llm=None, tools_manager=_Manager(),
        directive=_directive(max_tool_calls=2),
    )
    assert calls == ["safe_tool", "safe_tool", "submit_finding_candidate"]
    assert kinds.count("agent_specialist_wrapup") == 2
    assert report.stop_reason == "exhausted"
    assert report.verdict == "inconclusive"
    assert report.progress.startswith("Tested q on /search")
    assert "tool calls" in report.summary and "Saved the reflected" in report.summary


@pytest.mark.asyncio
async def test_turn_budget_stop_also_wraps_up(monkeypatch):
    _wrap_state.clear()
    calls, kinds = _patch(monkeypatch, _probe_then_wrap_up)
    report = await _run_specialist(
        _profile(max_iterations=1), "Assess", [TARGET], llm=None, tools_manager=_Manager(),
        directive=_directive(max_iterations=1),
    )
    assert "agent_specialist_wrapup" in kinds
    assert report.stop_reason == "exhausted"
    assert report.progress


@pytest.mark.asyncio
async def test_spend_stop_makes_no_further_model_call(monkeypatch):
    calls, kinds = _patch(monkeypatch, _probe_then_wrap_up)
    monkeypatch.setattr(
        "app.services.agent.observability.estimate_cost_usd", lambda *_a: 5.0,
    )
    monkeypatch.setattr(
        "app.services.agent.observability.usage_from_llm_response",
        lambda _r: {"input_tokens": 1, "output_tokens": 1},
    )
    report = await _run_specialist(
        _profile(), "Assess", [TARGET], llm=None, tools_manager=_Manager(),
        directive=_directive(max_spend_usd=1.0),
    )
    assert "agent_specialist_wrapup" not in kinds
    assert report.stop_reason == "exhausted"
    assert calls == []


@pytest.mark.asyncio
async def test_soft_deadline_stops_before_hard_timeout(monkeypatch):
    _wrap_state.clear()
    calls, kinds = _patch(monkeypatch, _probe_then_wrap_up)
    clock = iter(range(0, 10_000, 10))
    monkeypatch.setattr(fireteam_service.time, "monotonic", lambda: float(next(clock)))
    report = await _run_specialist(
        _profile(), "Assess", [TARGET], llm=None, tools_manager=_Manager(),
        directive=_directive(max_seconds=15),
    )
    assert report.rewrite_hint == "specialist time budget exhausted"
    assert report.stop_reason == "exhausted"
    assert "agent_specialist_wrapup" in kinds


@pytest.mark.asyncio
async def test_llm_failure_is_blocked_and_concluded_run_is_done(monkeypatch):
    async def boom(*_a, **_k):
        raise RuntimeError("provider down")

    monkeypatch.setattr(orchestrator, "_ledger_llm_call", boom)
    report = await _run_specialist(
        _profile(), "Assess", [TARGET], llm=None, tools_manager=_Manager(),
        directive=_directive(),
    )
    assert report.stop_reason == "blocked"

    _patch(monkeypatch, lambda _k, _n: {"done": True, "summary": "clean", "verdict": "killed"})
    report = await _run_specialist(
        _profile(), "Assess", [TARGET], llm=None, tools_manager=_Manager(),
        directive=_directive(),
    )
    assert report.stop_reason == "done"


def test_exhausted_retry_continues_with_full_budget():
    report = SimpleNamespace(
        specialist="api_authz", verdict="inconclusive", tool_calls=[
            SimpleNamespace(tool="compare_requests", success=True, args={}, evidence_ids=[]),
        ],
        summary="Stopped after 12 tool calls; remaining checks are open.",
        stop_reason="exhausted", progress="Compared owner vs other on /api/orders/2; next: PUT",
        error=None,
    )
    summary = parse_executor_summary(report)
    assert summary.stop_reason == "exhausted"
    assert classify_failure(summary, report) == EXHAUSTED
    note = rewrite_note(EXHAUSTED, summary)
    assert "Continue from where it stopped" in note
    assert "/api/orders/2" in note and "compare_requests" in note
    directive = SimpleNamespace(specialist="api_authz", test="idor", max_iterations=10, rewrite_note="")
    apply_rewrite_to_directive(directive, Rewrite("api_authz", EXHAUSTED, note, note))
    assert directive.max_iterations == 10
    apply_rewrite_to_directive(directive, Rewrite("api_authz", LLM_ERROR, "x", "x"))
    assert directive.max_iterations == 10


def test_wave_changes_is_compact_and_keeps_progress():
    summaries = [
        ExecutorSummary(specialist="xss", verdict="inconclusive", stop_reason="exhausted",
                        progress="q reflected in attribute; next: quote break", summary="long" * 200),
        ExecutorSummary(specialist="sqli", verdict="killed", stop_reason="done", summary="clean"),
    ]
    out = wave_changes(summaries, candidates_lifted=1, spawned=["graphql_api"], rewrites=["xss"])
    assert out["stop_reasons"] == {"exhausted": 1, "done": 1}
    assert out["specialists"][0]["progress"].startswith("q reflected")
    assert "result" not in out["specialists"][0]
    assert out["specialists"][1]["result"] == "clean"
    assert out["candidates_lifted"] == 1 and out["retried"] == ["xss"]
    assert len(json.dumps(out)) < 1000


# --- shared LLM circuit breakers ---------------------------------------------

_CALLS: list = []


def _chat_models():
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from pydantic import ConfigDict

    class Counting(BaseChatModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)
        fail: bool = False
        name_: str = "m"

        @property
        def _llm_type(self):
            return "counting"

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            _CALLS.append(self.name_)
            if self.fail:
                raise Exception("Your credit balance is too low to access the API")
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.name_))])

        async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
            return self._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    return Counting


def _wrapped(Counting, primary_key):
    from app.services.agent.model_router import (
        ResilientFallbackChatModel,
        provider_breaker_key,
    )

    return ResilientFallbackChatModel(
        primary=Counting(fail=True, name_="primary"),
        fallbacks=[Counting(name_="backup")],
        fallback_labels=["openai:gpt"],
        primary_label="anthropic:claude",
        breaker_keys=[
            provider_breaker_key("anthropic:claude", primary_key),
            provider_breaker_key("openai:gpt", "backup-key"),
        ],
    )


def test_credit_failure_trips_breaker_for_every_chain_sharing_the_key():
    from app.services.agent.model_router import reset_provider_breakers
    from langchain_core.messages import HumanMessage

    reset_provider_breakers()
    Counting = _chat_models()
    calls = _CALLS
    calls.clear()
    try:
        assert _wrapped(Counting, "org-a-key").invoke([HumanMessage(content="hi")]).content == "backup"
        assert calls == ["primary", "backup"]
        calls.clear()
        # A second task with the same credential skips the known-bad key.
        assert _wrapped(Counting, "org-a-key").invoke([HumanMessage(content="hi")]).content == "backup"
        assert calls == ["backup"]
        calls.clear()
        # Another organization's key for the same provider is unaffected.
        _wrapped(Counting, "org-b-key").invoke([HumanMessage(content="hi")])
        assert calls == ["primary", "backup"]
    finally:
        reset_provider_breakers()


def test_breaker_cooling_ladder_and_reset(monkeypatch):
    from app.services.agent import model_router as mr

    breakers = mr._ProviderBreakers()
    now = [1000.0]
    monkeypatch.setattr(mr.time, "monotonic", lambda: now[0])
    breakers.trip("k")
    assert breakers.is_open("k")
    now[0] += 61
    assert not breakers.is_open("k")
    breakers.trip("k")
    now[0] += 61
    assert breakers.is_open("k")  # second trip cools for five minutes
    now[0] += 300
    assert not breakers.is_open("k")
    breakers.reset("k")
    breakers.trip("k")
    now[0] += 61
    assert not breakers.is_open("k")  # a success restarts the ladder
    assert not breakers.is_open("")  # untracked members are never skipped
