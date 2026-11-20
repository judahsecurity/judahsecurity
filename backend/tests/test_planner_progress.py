"""Planner no-progress guard: gate feedback reaches the model, repeats stop."""

import asyncio

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from app.services.agent import planner_progress as pp
from app.services.agent import tester_loop
from app.services.agent.orchestrator import AgentOrchestrator

BLOCK = "Cannot complete: directory brute-force has not run."


def test_fingerprint_ignores_only_the_iteration_counter() -> None:
    a = "## Current State\n- **Iteration**: 3/40\n- trace: x"
    b = "## Current State\n- **Iteration**: 9/40\n- trace: x"
    pilot = "- Iteration: 9/40\n- trace: x"
    assert pp.prompt_fingerprint(a) == pp.prompt_fingerprint(b)
    assert pp.prompt_fingerprint(a) != pp.prompt_fingerprint(a + "y")
    assert pp.prompt_fingerprint("- Iteration: 1/40\n- trace: x") == pp.prompt_fingerprint(pilot)


def test_feedback_expires_when_a_tool_runs_and_does_not_duplicate() -> None:
    state = {"execution_trace": [{"tool_name": "a"}]}
    state["planner_feedback"] = pp.record_feedback(state, BLOCK)
    state["planner_feedback"] = pp.record_feedback(state, BLOCK)

    assert pp.active_feedback(state) == [BLOCK]
    assert BLOCK in pp.format_feedback(state)

    state["execution_trace"] = state["execution_trace"] + [{"tool_name": "b"}]
    assert pp.active_feedback(state) == []
    assert pp.format_feedback(state) == ""


def test_repeat_count_resets_on_new_context() -> None:
    state = {"planner_fingerprint": "abc", "planner_repeats": 2}
    assert pp.repeat_count(state, "abc") == 3
    assert pp.repeat_count(state, "def") == 1
    assert pp.repeat_count({}, "abc") == 1


class _CompleteForever(BaseChatModel):
    calls: list = []

    @property
    def _llm_type(self) -> str:
        return "complete-forever"

    def _generate(self, *args, **kwargs):
        raise NotImplementedError

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        self.calls.append(list(messages))
        text = '{"thought":"done","reasoning":"r","action":"complete","completion_reason":"all done"}'
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])


def _run_until_done(monkeypatch, state, max_steps=10):
    model = _CompleteForever(calls=[])
    monkeypatch.setattr(tester_loop, "forced_next_step", lambda state=None: None)
    monkeypatch.setattr(
        tester_loop, "complete_blocked_reason", lambda state, completion_reason="": BLOCK,
    )
    orch = AgentOrchestrator()
    monkeypatch.setattr(orch, "_resolve_llm", lambda state, task: model)
    for _ in range(max_steps):
        update = asyncio.run(orch._think_node(state))
        state = {**state, **{k: v for k, v in update.items() if k != "messages"}}
        if orch._route_after_think(state) != "think":
            break
    return state, model.calls


def _state() -> dict:
    return {
        "user_id": "7", "session_id": "stall", "current_iteration": 0,
        "max_iterations": 20, "current_phase": "informational", "mode": "agent",
        "objective": "assess https://demo.example",
        "execution_trace": [{"iteration": 1, "tool_name": "execute_httpx", "tool_output": "200"}],
    }


def test_gated_complete_loop_stops_without_paying_for_repeats(monkeypatch) -> None:
    state, calls = _run_until_done(monkeypatch, _state())

    # First call, then the same rejected context twice; the third repeat is skipped.
    assert len(calls) == 3
    assert state["task_complete"] is True
    assert "Coverage is incomplete" in state["completion_reason"]
    assert BLOCK in state["completion_reason"]
    # The model saw why its completion was rejected.
    assert "Previous decision rejected" not in calls[0][1].content
    assert BLOCK in calls[1][1].content


def test_new_tool_output_resets_the_guard(monkeypatch) -> None:
    state, calls = _run_until_done(monkeypatch, _state(), max_steps=2)
    assert len(calls) == 2 and not state.get("task_complete")

    state["execution_trace"] = state["execution_trace"] + [
        {"iteration": 3, "tool_name": "execute_ffuf", "tool_output": "12 paths"},
    ]
    state, more = _run_until_done(monkeypatch, state, max_steps=1)

    assert len(more) == 1
    assert state["planner_repeats"] == 1
    assert BLOCK not in more[0][1].content
