"""Canonical events shared by the product agent, Vanguard, CLI, and workers."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentEventType(str, Enum):
    RUN_STARTED = "run.started"
    RUN_RESUMED = "run.resumed"
    RUN_WAITING = "run.waiting"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"
    RUN_CANCELLED = "run.cancelled"
    PLAN_CREATED = "plan.created"
    AGENT_SPAWNED = "agent.spawned"
    AGENT_COMPLETED = "agent.completed"
    TOOL_REQUESTED = "tool.requested"
    TOOL_APPROVED = "tool.approved"
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    MEMORY_READ = "memory.read"
    MEMORY_WRITTEN = "memory.written"
    FINDING_PROPOSED = "finding.proposed"
    FINDING_VERIFIED = "finding.verified"
    FINDING_PUBLISHED = "finding.published"
    COMMAND_QUEUED = "command.queued"
    COMMAND_CONSUMED = "command.consumed"
    PROGRESS = "run.progress"


_STREAM_EVENT_MAP = {
    "thinking": AgentEventType.PROGRESS.value,
    "tool_start": AgentEventType.TOOL_STARTED.value,
    "tool_complete": AgentEventType.TOOL_COMPLETED.value,
    "tool_end": AgentEventType.TOOL_COMPLETED.value,
    "tool_error": AgentEventType.TOOL_FAILED.value,
    "approval_required": AgentEventType.RUN_WAITING.value,
    "question_required": AgentEventType.RUN_WAITING.value,
    "cancelled": AgentEventType.RUN_CANCELLED.value,
}


def normalize_event_type(value: str) -> str:
    """Map legacy WebSocket event names onto the durable event vocabulary."""
    text = (value or "").strip().lower().replace("_", ".")
    if value in _STREAM_EVENT_MAP:
        return _STREAM_EVENT_MAP[value]
    if text in {item.value for item in AgentEventType}:
        return text
    return AgentEventType.PROGRESS.value


@dataclass(frozen=True)
class AgentEvent:
    run_id: str
    organization_id: int
    event_type: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    step_id: Optional[str] = None
    severity: Optional[str] = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_stream_message(
        cls,
        *,
        run_id: str,
        organization_id: int,
        message: Mapping[str, Any],
        user_id: Optional[str] = None,
    ) -> "AgentEvent":
        kind = str(message.get("type") or message.get("event") or "progress")
        return cls(
            run_id=run_id,
            organization_id=organization_id,
            user_id=user_id,
            event_type=normalize_event_type(kind),
            agent_id=_optional_text(message.get("agent") or message.get("agent_id")),
            step_id=_optional_text(message.get("step_id") or message.get("iteration")),
            severity=_optional_text(message.get("severity")),
            payload=dict(message),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _optional_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
