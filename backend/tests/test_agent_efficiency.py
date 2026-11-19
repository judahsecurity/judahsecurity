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
        "app.services.agent.observability.estimate_cost_usd", lambda *_a, **_k: 5.0,
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


# --- peer trace search --------------------------------------------------------

def test_peer_board_excludes_own_run_and_matches_all_terms():
    board = fireteam_service.PeerTraceBoard()
    inv = fireteam_service.ToolInvocation
    board.record("run-a", "xss", [inv(tool="http_get", args={"url": "/search"}, success=True,
                                      summary="500 error: hidden param debug_mode=1 leaked")])
    board.record("run-b", "sqli", [inv(tool="http_get", args={}, success=True, summary="200 ok")])
    hits = board.search("debug_mode leaked", exclude_run="run-b")
    assert [h["specialist"] for h in hits] == ["xss"]
    assert "debug_mode=1" in hits[0]["excerpt"]
    assert board.search("debug_mode", exclude_run="run-a") == []
    assert board.search("debug_mode missing", exclude_run="run-b") == []
    assert [h["specialist"] for h in board.search("", exclude_run="nobody")] == ["sqli", "xss"]


def test_peer_board_is_bounded():
    board = fireteam_service.PeerTraceBoard()
    inv = fireteam_service.ToolInvocation(tool="t", args={}, success=True, summary="x" * 5000)
    for i in range(fireteam_service._PEER_BOARD_MAX + 50):
        board.record(f"r{i}", "s", [inv])
    assert len(board._entries) == fireteam_service._PEER_BOARD_MAX
    assert len(board._entries[-1]["summary"]) == fireteam_service._PEER_SUMMARY_CHARS


@pytest.mark.asyncio
async def test_specialist_reads_peer_results_without_spending_tool_budget(monkeypatch):
    manager = _Manager()
    board = fireteam_service._peer_board(manager)
    board.record("earlier-run", "api_authz", [fireteam_service.ToolInvocation(
        tool="compare_requests", args={}, success=True, summary="X-Debug-Token header echoed",
    )])
    prompts = []

    def replies(_kind, n):
        if n == 1:
            return {"tool_calls": [
                {"tool": "search_peer_traces", "args": {"q": "x-debug-token"}},
            ]}
        return {"done": True, "summary": "used peer lead", "verdict": "inconclusive"}

    calls, _kinds = _patch(monkeypatch, replies)

    async def capture_llm(_llm, messages, **kwargs):
        prompts.append([getattr(m, "content", "") for m in messages])
        return SimpleNamespace(content=json.dumps(replies(kwargs.get("kind"), len(prompts))))

    monkeypatch.setattr(orchestrator, "_ledger_llm_call", capture_llm)
    report = await _run_specialist(
        _profile(), "Assess", [TARGET], llm=None, tools_manager=manager,
        directive=_directive(max_tool_calls=1),
    )
    assert calls == []
    assert report.stop_reason == "done"
    assert "search_peer_traces" in prompts[0][0]  # offered in the system prompt
    peer_feedback = json.loads(prompts[1][-1])["peer_results"][0]
    assert peer_feedback["matches"][0]["specialist"] == "api_authz"


@pytest.mark.asyncio
async def test_peer_search_is_capped_per_run(monkeypatch):
    manager = _Manager()

    def replies(_kind, n):
        if n <= 6:
            return {"tool_calls": [{"tool": "search_peer_traces", "args": {"q": "x"}}]}
        return {"done": True, "summary": "s", "verdict": "inconclusive"}

    seen = []

    async def capture_llm(_llm, messages, **kwargs):
        seen.append(getattr(messages[-1], "content", ""))
        return SimpleNamespace(content=json.dumps(replies(kwargs.get("kind"), len(seen))))

    _patch(monkeypatch, replies)
    monkeypatch.setattr(orchestrator, "_ledger_llm_call", capture_llm)
    await _run_specialist(
        _profile(max_iterations=10), "Assess", [TARGET], llm=None, tools_manager=manager,
        directive=_directive(max_iterations=10),
    )
    limited = [m for m in seen if "peer search limit reached" in m]
    assert len(limited) == 2  # searches 5 and 6 are refused


# --- out-of-lane leads --------------------------------------------------------

def _report_with(leads, evidence=("ev-1",)):
    report = fireteam_service.SpecialistReport(specialist="xss", role="r", mission="m", summary="")
    report.tool_calls = [fireteam_service.ToolInvocation(
        tool="http_get", args={}, success=True, summary="500: see /internal/admin",
        evidence_ids=list(evidence),
    )]
    fireteam_service._fill_summary_contract(report, {"leads": leads})
    return report


def test_leads_need_scope_and_own_evidence():
    report = _report_with([
        {"method": "get", "url": "https://app.example.test/internal/admin?x=1",
         "why": "path leaked in 500 body", "evidence_ids": ["ev-1"]},
        {"url": "https://evil.example.org/admin", "evidence_ids": ["ev-1"]},     # out of scope
        {"url": "https://app.example.test/made-up", "evidence_ids": ["ev-9"]},  # not its evidence
        {"url": "ftp://app.example.test/file", "evidence_ids": ["ev-1"]},       # not http
        {"method": "TRACE", "url": "https://app.example.test/t", "evidence_ids": ["ev-1"]},
    ])
    assert len(report.leads) == 5
    leads = fireteam_service.validated_leads(report, ["app.example.test"])
    assert [lead["url"] for lead in leads] == ["https://app.example.test/internal/admin?x=1"]
    assert leads[0]["method"] == "GET" and leads[0]["evidence_ids"] == ["ev-1"]


def test_leads_are_capped_and_shown_in_wave_changes():
    report = _report_with([
        {"url": f"https://app.example.test/p{i}", "why": "w", "evidence_ids": ["ev-1"]}
        for i in range(9)
    ])
    assert len(report.leads) == fireteam_service._MAX_LEADS
    summary = parse_executor_summary(report)
    out = wave_changes([summary], leads_recorded=2)
    assert out["leads_recorded"] == 2
    assert out["specialists"][0]["leads"][0].startswith("GET https://app.example.test/p0")


def test_lead_becomes_a_capture_event_without_values():
    from app.services.agent.engagement_brain import EngagementBrain
    from app.services.agent.observation_followups import capture_facts, commit_observation

    brain = EngagementBrain(target="https://app.example.test")
    lead = fireteam_service.validated_leads(_report_with([
        {"url": "https://app.example.test/internal/admin?token=abc", "evidence_ids": ["ev-1"]},
    ]), ["app.example.test"])[0]
    event, created = commit_observation(
        brain, run_id="run", kind="capture", identity="anonymous",
        evidence_ids=lead["evidence_ids"], facts=capture_facts(lead["method"], lead["url"]),
    )
    assert created and event["status"] == "committed"
    assert event["facts"]["path"] == "/internal/admin"
    assert event["facts"]["parameters"] == [{"location": "query", "name": "token"}]
    assert "abc" not in json.dumps(event)


# --- evidence full-text search -----------------------------------------------

def test_evidence_search_matches_all_terms_newest_first(tmp_path, monkeypatch):
    from app.services.agent.evidence_store import EvidenceStore

    monkeypatch.setenv("AEGIS_EVIDENCE_DIR", str(tmp_path))
    store = EvidenceStore(namespace="t")
    old = store.record("http_exchange", {
        "request": {"method": "GET", "url": "https://app.example.test/a"},
        "response": {"status": 500, "body": "Traceback ... at db.internal.corp:5432"},
    }, target="https://app.example.test/a")
    new = store.record("http_exchange", {
        "request": {"method": "GET", "url": "https://app.example.test/b"},
        "response": {"status": 200, "body": "upstream db.internal.corp ok"},
    }, target="https://app.example.test/b")
    store.record("tool_output", {"output": "db.internal.corp"})
    hits = store.search("DB.INTERNAL.CORP")
    assert [h["evidence_id"] for h in hits] == [new, old]
    assert hits[0]["status"] == 200 and hits[0]["url"].endswith("/b")
    assert [h["evidence_id"] for h in store.search("internal.corp traceback")] == [old]
    assert len(store.search("db.internal.corp", kind="")) == 3
    full = store.read(old, offset=hits[1]["offset"], limit=400)
    assert "db.internal.corp" in full["content"]
    with pytest.raises(ValueError):
        store.search("ab")


@pytest.mark.asyncio
async def test_search_evidence_tool_is_registered_and_offered_to_specialists():
    from app.services.agent import content_shield, pilot_policy

    assert "search_evidence" in content_shield.TARGET_CONTENT_TOOLS
    assert "search_evidence" in pilot_policy.PILOT_LOCAL_TOOLS
    assert fireteam_service._action_kind("search_evidence", {}) == "read"


def test_turn_multiplier_scales_and_is_bounded(monkeypatch):
    from app.core.config import settings

    for factor, turns, expected in ((1.0, 8, 8), (2.5, 8, 20), (10, 8, 32), (0.1, 8, 4), ("bad", 8, 8)):
        monkeypatch.setattr(settings, "AGENT_SPECIALIST_TURN_MULTIPLIER", factor, raising=False)
        assert fireteam_service._scaled_turns(turns) == expected
