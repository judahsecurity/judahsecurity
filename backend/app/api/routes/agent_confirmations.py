"""
Agent per-tool confirmation routes.

Workflow:

    1. Agent calls a dangerous tool.
    2. The confirmation gate returns ``{"decision": "confirm", "token": ...}``.
    3. Frontend/operator calls ``POST /agent/confirmations/{token}/decide``
       with ``{"approved": true|false, "reason": "..."}``.
    4. The paused agent tool-call resumes (approved) or fails (denied).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import require_analyst
from app.models.user import User
from app.services.agent.confirmation_service import get_store, preview_tool_args

router = APIRouter(prefix="/agent/confirmations", tags=["agent-confirmations"])


class DecidePayload(BaseModel):
    approved: bool
    reason: Optional[str] = None


@router.get("")
def list_confirmations(
    organization_id: Optional[int] = None,
    session_id: Optional[str] = None,
    current_user: User = Depends(require_analyst),
):
    org_id = organization_id
    if not current_user.is_superuser and organization_id and current_user.organization_id != organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    if not current_user.is_superuser and org_id is None:
        org_id = current_user.organization_id
    pending = get_store().list_pending(organization_id=org_id, session_id=session_id)
    return [
        {
            "token": pc.token,
            "tool_name": pc.tool_name,
            "tool_args": preview_tool_args(pc.tool_args),
            "organization_id": pc.organization_id,
            "session_id": pc.session_id,
            "created_at": pc.created_at,
            "timeout_seconds": pc.timeout_seconds,
            "status": pc.status,
        }
        for pc in pending
    ]


@router.post("/{token}/decide", status_code=status.HTTP_200_OK)
def decide_confirmation(
    token: str,
    payload: DecidePayload,
    current_user: User = Depends(require_analyst),
):
    pc = get_store().get(token)
    if not pc:
        raise HTTPException(status_code=404, detail="Unknown or expired confirmation token")
    if not current_user.is_superuser and pc.organization_id and pc.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied to this confirmation")
    decided = get_store().decide(
        token,
        approved=payload.approved,
        decided_by=current_user.email or current_user.username or "",
        reason=payload.reason or "",
    )
    if not decided:
        raise HTTPException(status_code=404, detail="Token missing")
    return {
        "token": decided.token,
        "status": decided.status,
        "decided_by": decided.decided_by,
        "reason": decided.reason,
    }
