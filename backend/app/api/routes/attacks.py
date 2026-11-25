"""Attack-path workspace API — Chariot-style campaign graphs per organization."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.db.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.services.attack_path_campaign import build_workspace

router = APIRouter(prefix="/attacks", tags=["Attacks"])


def _resolve_org_id(current_user: User, organization_id: Optional[int]) -> int:
    if current_user.is_superuser:
        if organization_id:
            return organization_id
        if current_user.organization_id:
            return current_user.organization_id
        raise HTTPException(status_code=400, detail="Select an organization")
    org_id = current_user.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    if organization_id and organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return org_id


@router.get("/workspace")
def get_attack_workspace(
    organization_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Named attack-path campaigns, capabilities, signatures, and juicy fruit for an org."""
    org_id = _resolve_org_id(current_user, organization_id)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return build_workspace(db, org_id)


@router.get("/sessions/{session_id}/graph")
def get_attack_session_graph(
    session_id: str,
    organization_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Entity attack path for an agent session, visible to the whole org.

    /agent/sessions/{id}/attack-graph is owner-only; this read is for the
    org-wide /attacks page, so it checks that the session belongs to the
    caller's organization instead of to the caller. Evidence is redacted
    by the graph builder.
    """
    from app.models.agent_conversation import AgentConversation
    from app.services.agent import evograph
    from app.services.agent.attack_graph import attach_verified_graph

    org_id = _resolve_org_id(current_user, organization_id)
    conv = (
        db.query(AgentConversation)
        .filter(AgentConversation.session_id == session_id, AgentConversation.organization_id == org_id)
        .first()
    )
    if conv is None:
        raise HTTPException(status_code=404, detail="Session not found")
    chain = attach_verified_graph(evograph.get_session_chain(session_id, org_id), org_id, session_id, db)
    return chain.get("attack_graph") or {"nodes": [], "edges": [], "meta": {}}
