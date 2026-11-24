"""Correct or stop a running specialist without losing its progress.

A specialist that has gone off course used to burn its whole budget. Each
running specialist now has a control channel:

* ``steer`` queues a correction that the specialist reads before its next
  model call ("stop retrying X, test Y"); its context and evidence stay.
* ``stop`` ends it at the next turn boundary through the normal wrap-up, so
  its evidenced leads are still written back.

A code-only reviewer watches each specialist's tool calls and steers it when
it repeats an identical call or several calls in a row fail; if the same
problem continues after the correction, it stops the run. Operators can
steer or stop a named specialist from the session's steer box
("@injection focus on the id parameter", "@stop injection").
"""

from __future__ import annotations

import json
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Optional

MAX_STEERS = 6
FAILURE_STREAK = 3


@dataclass
class MemberControl:
    id: str
    session_id: str
    specialist: str
    organization_id: Optional[int] = None
    lease_id: str = ""
    hypothesis_ids: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    steers: list[str] = field(default_factory=list)
    stop_reason: str = ""
    stopped_by: str = ""
    corrections: dict[str, int] = field(default_factory=dict)
    seen_calls: set = field(default_factory=set)
    reviewed: int = 0
    tool_calls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "specialist": self.specialist, "lease_id": self.lease_id,
                "hypothesis_ids": list(self.hypothesis_ids), "tool_calls": self.tool_calls,
                "running_seconds": round(time.time() - self.started_at, 1),
                "stopping": bool(self.stop_reason)}


_MEMBERS: dict[str, MemberControl] = {}
current_member: ContextVar[Optional[MemberControl]] = ContextVar("current_member", default=None)


def register(session_id: str, specialist: str, *, lease_id: str = "",
             hypothesis_ids: Optional[list[str]] = None,
             organization_id: Optional[int] = None) -> MemberControl:
    control = MemberControl(id=uuid.uuid4().hex[:12], session_id=str(session_id or ""),
                            specialist=specialist, organization_id=organization_id,
                            lease_id=lease_id,
                            hypothesis_ids=list(hypothesis_ids or []))
    _MEMBERS[control.id] = control
    return control


def unregister(control: Optional[MemberControl]) -> None:
    if control is not None:
        _MEMBERS.pop(control.id, None)


def _owned(member: MemberControl, session_id: str, organization_id: Optional[int]) -> bool:
    return (member.session_id == str(session_id or "")
            and (organization_id is None or member.organization_id == organization_id))


def running_members(session_id: str, organization_id: Optional[int] = None) -> list[dict[str, Any]]:
    return [m.to_dict() for m in _MEMBERS.values() if _owned(m, session_id, organization_id)]


def _matching(session_id: str, who: str, organization_id: Optional[int] = None) -> list[MemberControl]:
    who = (who or "").strip().lower()
    return [m for m in _MEMBERS.values()
            if _owned(m, session_id, organization_id)
            and who in (m.id.lower(), m.specialist.lower(), m.lease_id.lower(),
                        *(h.lower() for h in m.hypothesis_ids))]


def steer(session_id: str, who: str, message: str, *, by: str = "operator",
          organization_id: Optional[int] = None) -> int:
    """Queue a correction for matching running specialists; returns how many."""
    text = " ".join(str(message or "").split())[:1000]
    if not text:
        return 0
    members = _matching(session_id, who, organization_id)
    for member in members:
        if len(member.steers) < MAX_STEERS:
            member.steers.append(f"[{by}] {text}")
    return len(members)


def stop(session_id: str, who: str, reason: str, *, by: str = "operator",
         organization_id: Optional[int] = None) -> int:
    members = _matching(session_id, who, organization_id)
    for member in members:
        member.stop_reason = " ".join(str(reason or "stopped").split())[:300]
        member.stopped_by = by
    return len(members)


def drain(control: Optional[MemberControl]) -> tuple[list[str], str]:
    if control is None:
        return [], ""
    steers, control.steers = control.steers, []
    return steers, control.stop_reason


def _call_key(call: Any) -> str:
    args = getattr(call, "args", None)
    try:
        encoded = json.dumps(args, sort_keys=True, default=str)
    except (TypeError, ValueError):
        encoded = str(args)
    return f"{getattr(call, 'tool', '')}|{encoded}"


def review(control: Optional[MemberControl], tool_calls: list[Any]) -> None:
    """Steer on wasted work; stop if it continues after one correction."""
    if control is None:
        return
    new = tool_calls[control.reviewed:]
    control.reviewed = len(tool_calls)
    control.tool_calls = len(tool_calls)
    problem = ""
    repeated = []
    for call in new:
        key = _call_key(call)
        if key in control.seen_calls:
            repeated.append(getattr(call, "tool", "?"))
        control.seen_calls.add(key)
    if repeated:
        problem = "repeat"
        message = (f"You repeated {', '.join(sorted(set(repeated)))} with identical arguments; "
                   "the result will not change. Use a different technique, input or "
                   "location, or conclude with the evidence you have.")
    recent = tool_calls[-FAILURE_STREAK:]
    if not problem and len(recent) == FAILURE_STREAK and new and all(
        getattr(call, "success", True) is False for call in recent
    ):
        problem = "failing"
        errors = "; ".join(sorted({str(getattr(c, "error", "") or "failed")[:80] for c in recent}))
        message = (f"Your last {FAILURE_STREAK} tool calls failed ({errors}). Check the "
                   "arguments, scope and allowlist, then change approach rather than retrying.")
    if not problem:
        return
    if control.corrections.get(problem):
        control.stop_reason = f"{problem} continued after a correction"
        control.stopped_by = "supervisor"
        return
    control.corrections[problem] = 1
    control.steers.append(f"[supervisor] {message}")


def route_operator_message(session_id: str, message: str,
                           organization_id: Optional[int] = None) -> Optional[dict[str, Any]]:
    """'@<specialist> text' steers it; '@stop <specialist> [reason]' stops it.

    Returns None when the message is not addressed to a running specialist,
    so it falls through to the normal session steer.
    """
    text = (message or "").strip()
    if not text.startswith("@"):
        return None
    head, _, rest = text[1:].partition(" ")
    if head.lower() == "stop":
        who, _, reason = rest.strip().partition(" ")
        count = stop(session_id, who, reason or "stopped by the operator",
                     organization_id=organization_id)
        return {"action": "stop", "target": who, "matched": count} if count else None
    count = steer(session_id, head, rest, organization_id=organization_id)
    return {"action": "steer", "target": head, "matched": count} if count else None
