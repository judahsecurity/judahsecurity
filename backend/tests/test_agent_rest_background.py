"""REST /query must return immediately so nginx/ALB cannot 504 a long hunt."""

from app.api.routes.agent import AgentResponse, _run_timeout_s


def test_agent_response_running_flag():
    payload = AgentResponse(
        answer="",
        session_id="s1",
        current_phase="running",
        iteration_count=0,
        task_complete=False,
        todo_list=[],
        execution_trace_summary="started",
        running=True,
    )
    assert payload.running is True
    assert payload.task_complete is False
    dumped = payload.model_dump()
    assert dumped["running"] is True


def test_run_timeout_is_at_least_one_hour():
    assert _run_timeout_s() >= 3600
