"""Bridge the orchestrator's legacy status callbacks to the durable event log."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Mapping, Optional

from aegis_runtime import AgentEvent, AgentEventType, RunStatus

from app.services.agent import runtime_store

logger = logging.getLogger(__name__)

StatusCallback = Optional[Callable[[dict[str, Any]], Awaitable[None] | None]]


def start_run(
    *,
    session_id: str,
    organization_id: int,
    user_id: Any,
    mode: str,
    objective: str,
    price_limit_usd: Optional[float],
) -> None:
    _ensure_run_scope(
        session_id=session_id,
        organization_id=organization_id,
        user_id=user_id,
        mode=mode,
        objective=objective,
        price_limit_usd=price_limit_usd,
    )
    emit(
        AgentEvent(
            run_id=session_id,
            organization_id=organization_id,
            user_id=str(user_id),
            event_type=AgentEventType.RUN_STARTED.value,
            payload={"mode": mode, "objective": objective[:1000]},
        )
    )


def emit(event: AgentEvent) -> None:
    runtime_store.safe_call("append_event", event)
    if event.event_type in {
        AgentEventType.RUN_WAITING.value,
        AgentEventType.RUN_COMPLETED.value,
        AgentEventType.RUN_FAILED.value,
        AgentEventType.RUN_CANCELLED.value,
        AgentEventType.FINDING_VERIFIED.value,
        AgentEventType.FINDING_PUBLISHED.value,
    }:
        try:
            loop = asyncio.get_running_loop()
            from app.services.agent.notifications import dispatch_event

            loop.run_in_executor(None, dispatch_event, event)
        except (RuntimeError, ImportError):
            logger.debug("agent notification scheduling skipped", exc_info=True)


def resume_run(
    *,
    session_id: str,
    organization_id: int,
    user_id: Any,
    reason: str,
) -> None:
    _ensure_run_scope(
        session_id=session_id,
        organization_id=organization_id,
        user_id=user_id,
    )
    emit(
        AgentEvent(
            run_id=session_id,
            organization_id=organization_id,
            user_id=str(user_id),
            event_type=AgentEventType.RUN_RESUMED.value,
            payload={"reason": reason[:64]},
        )
    )


def callback_for(
    *,
    session_id: str,
    organization_id: int,
    user_id: Any,
    downstream: StatusCallback,
) -> Callable[[dict[str, Any]], Awaitable[None]]:
    async def _callback(message: dict[str, Any]) -> None:
        if isinstance(message, Mapping):
            event = AgentEvent.from_stream_message(
                run_id=session_id,
                organization_id=organization_id,
                user_id=str(user_id),
                message=message,
            )
            emit(event)
            runtime_store.safe_call(
                "update_run",
                session_id,
                current_phase=str(message.get("phase") or "") or None,
                current_step=str(message.get("tool_name") or message.get("thought") or "")[:255] or None,
                iteration_count=_int_or_none(message.get("iteration")),
            )
        if downstream:
            result = downstream(message)
            if asyncio.iscoroutine(result):
                await result

    return _callback


def finish_run(
    *,
    session_id: str,
    organization_id: int,
    user_id: Any,
    response: Any,
) -> None:
    error = getattr(response, "error", None)
    complete = bool(getattr(response, "task_complete", False))
    awaiting = bool(
        getattr(response, "awaiting_approval", False)
        or getattr(response, "awaiting_question", False)
    )
    if error:
        status = RunStatus.FAILED
        event_type = AgentEventType.RUN_FAILED
    elif awaiting or not complete:
        status = RunStatus.WAITING
        event_type = AgentEventType.RUN_WAITING
    else:
        status = RunStatus.COMPLETED
        event_type = AgentEventType.RUN_COMPLETED
    runtime_store.safe_call(
        "update_run",
        session_id,
        status=status.value,
        current_phase=getattr(response, "current_phase", None),
        iteration_count=getattr(response, "iteration_count", None),
        cost_usd=getattr(response, "cost_usd", None),
        error_message=str(error) if error else None,
        completed=status in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED),
    )
    emit(
        AgentEvent(
            run_id=session_id,
            organization_id=organization_id,
            user_id=str(user_id),
            event_type=event_type.value,
            payload={
                "phase": getattr(response, "current_phase", None),
                "iterations": getattr(response, "iteration_count", None),
                "cost_usd": getattr(response, "cost_usd", None),
                "error": str(error)[:1000] if error else None,
            },
        )
    )


def cancel_run(*, session_id: str, organization_id: int, user_id: Any) -> None:
    runtime_store.safe_call(
        "update_run", session_id, status=RunStatus.CANCELLED.value, completed=True
    )
    emit(
        AgentEvent(
            run_id=session_id,
            organization_id=organization_id,
            user_id=str(user_id),
            event_type=AgentEventType.RUN_CANCELLED.value,
            payload={"reason": "operator_stop"},
        )
    )


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _ensure_run_scope(**kwargs: Any) -> None:
    """Fail closed on ID ownership collisions, tolerate telemetry outages."""
    try:
        runtime_store.ensure_run(**kwargs)
    except ValueError:
        raise
    except Exception:
        logger.debug("durable run initialization skipped", exc_info=True)
