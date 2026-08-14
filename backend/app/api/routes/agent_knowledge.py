"""CRUD API for agent knowledge (org-scoped RAG documents)."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.models.agent_knowledge import AgentKnowledge
from app.api.deps import require_admin

router = APIRouter(tags=["Agent Knowledge"])


class AgentKnowledgeCreate(BaseModel):
    """Create or update agent knowledge document."""
    title: str = Field(..., min_length=1, max_length=512)
    content: str = Field(..., min_length=1)
    tags: List[str] = Field(default_factory=list)


class AgentKnowledgeUpdate(BaseModel):
    """Partial update."""
    title: Optional[str] = Field(None, min_length=1, max_length=512)
    content: Optional[str] = Field(None, min_length=1)
    tags: Optional[List[str]] = None


class AgentKnowledgeResponse(BaseModel):
    """Response model."""
    id: int
    organization_id: Optional[int]
    title: str
    content: str
    tags: List[str]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


def _check_org_access(current_user: User, org_id: Optional[int], db: Session) -> None:
    """Raise 403 if user cannot access this org (or global when org_id is None)."""
    if org_id is None:
        if not getattr(current_user, "is_superuser", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superusers can manage global agent knowledge",
            )
        return
    if not current_user.is_superuser and getattr(current_user, "organization_id", None) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for this organization",
        )
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")


def _mine_into_palace(doc: AgentKnowledge) -> None:
    """Best-effort: copy a knowledge doc into verbatim palace drawers."""
    try:
        from app.services.agent.palace_memory import mine_knowledge_doc

        mine_knowledge_doc(
            organization_id=doc.organization_id,
            title=doc.title,
            content=doc.content,
            tags=doc.tags or [],
            doc_id=doc.id,
        )
    except Exception:
        pass


@router.get("/organizations/{organization_id}/agent-knowledge", response_model=List[AgentKnowledgeResponse])
def list_agent_knowledge(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """List agent knowledge documents for an organization (org-specific only; global docs are not listed here)."""
    _check_org_access(current_user, organization_id, db)
    docs = (
        db.query(AgentKnowledge)
        .filter(AgentKnowledge.organization_id == organization_id)
        .order_by(AgentKnowledge.updated_at.desc())
        .all()
    )
    return [
        AgentKnowledgeResponse(
            id=d.id,
            organization_id=d.organization_id,
            title=d.title,
            content=d.content,
            tags=d.tags or [],
            created_at=d.created_at.isoformat() if d.created_at else "",
            updated_at=d.updated_at.isoformat() if d.updated_at else "",
        )
        for d in docs
    ]


@router.post("/organizations/{organization_id}/agent-knowledge", response_model=AgentKnowledgeResponse)
def create_agent_knowledge(
    organization_id: int,
    body: AgentKnowledgeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Create an agent knowledge document for the organization."""
    _check_org_access(current_user, organization_id, db)
    doc = AgentKnowledge(
        organization_id=organization_id,
        title=body.title,
        content=body.content,
        tags=body.tags,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    _mine_into_palace(doc)
    return AgentKnowledgeResponse(
        id=doc.id,
        organization_id=doc.organization_id,
        title=doc.title,
        content=doc.content,
        tags=doc.tags or [],
        created_at=doc.created_at.isoformat() if doc.created_at else "",
        updated_at=doc.updated_at.isoformat() if doc.updated_at else "",
    )


@router.get("/agent-knowledge/global", response_model=List[AgentKnowledgeResponse])
def list_global_agent_knowledge(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """List global agent knowledge documents (organization_id is NULL). Superuser only."""
    _check_org_access(current_user, None, db)
    docs = (
        db.query(AgentKnowledge)
        .filter(AgentKnowledge.organization_id.is_(None))
        .order_by(AgentKnowledge.updated_at.desc())
        .all()
    )
    return [
        AgentKnowledgeResponse(
            id=d.id,
            organization_id=d.organization_id,
            title=d.title,
            content=d.content,
            tags=d.tags or [],
            created_at=d.created_at.isoformat() if d.created_at else "",
            updated_at=d.updated_at.isoformat() if d.updated_at else "",
        )
        for d in docs
    ]


@router.post("/agent-knowledge/global", response_model=AgentKnowledgeResponse)
def create_global_agent_knowledge(
    body: AgentKnowledgeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Create a global agent knowledge document. Superuser only."""
    _check_org_access(current_user, None, db)
    doc = AgentKnowledge(
        organization_id=None,
        title=body.title,
        content=body.content,
        tags=body.tags,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    _mine_into_palace(doc)
    return AgentKnowledgeResponse(
        id=doc.id,
        organization_id=doc.organization_id,
        title=doc.title,
        content=doc.content,
        tags=doc.tags or [],
        created_at=doc.created_at.isoformat() if doc.created_at else "",
        updated_at=doc.updated_at.isoformat() if doc.updated_at else "",
    )


@router.put("/agent-knowledge/global/{doc_id}", response_model=AgentKnowledgeResponse)
def update_global_agent_knowledge(
    doc_id: int,
    body: AgentKnowledgeUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Update a global agent knowledge document. Superuser only."""
    _check_org_access(current_user, None, db)
    doc = db.query(AgentKnowledge).filter(
        AgentKnowledge.id == doc_id,
        AgentKnowledge.organization_id.is_(None),
    ).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    if body.title is not None:
        doc.title = body.title
    if body.content is not None:
        doc.content = body.content
    if body.tags is not None:
        doc.tags = body.tags
    db.commit()
    db.refresh(doc)
    _mine_into_palace(doc)
    return AgentKnowledgeResponse(
        id=doc.id,
        organization_id=doc.organization_id,
        title=doc.title,
        content=doc.content,
        tags=doc.tags or [],
        created_at=doc.created_at.isoformat() if doc.created_at else "",
        updated_at=doc.updated_at.isoformat() if doc.updated_at else "",
    )


@router.delete("/agent-knowledge/global/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_global_agent_knowledge(
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete a global agent knowledge document. Superuser only."""
    _check_org_access(current_user, None, db)
    doc = db.query(AgentKnowledge).filter(
        AgentKnowledge.id == doc_id,
        AgentKnowledge.organization_id.is_(None),
    ).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    db.delete(doc)
    db.commit()
    return None


@router.put("/organizations/{organization_id}/agent-knowledge/{doc_id}", response_model=AgentKnowledgeResponse)
def update_agent_knowledge(
    organization_id: int,
    doc_id: int,
    body: AgentKnowledgeUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Update an agent knowledge document."""
    doc = db.query(AgentKnowledge).filter(
        AgentKnowledge.id == doc_id,
        AgentKnowledge.organization_id == organization_id,
    ).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    _check_org_access(current_user, organization_id, db)
    if body.title is not None:
        doc.title = body.title
    if body.content is not None:
        doc.content = body.content
    if body.tags is not None:
        doc.tags = body.tags
    db.commit()
    db.refresh(doc)
    _mine_into_palace(doc)
    return AgentKnowledgeResponse(
        id=doc.id,
        organization_id=doc.organization_id,
        title=doc.title,
        content=doc.content,
        tags=doc.tags or [],
        created_at=doc.created_at.isoformat() if doc.created_at else "",
        updated_at=doc.updated_at.isoformat() if doc.updated_at else "",
    )


@router.delete("/organizations/{organization_id}/agent-knowledge/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent_knowledge(
    organization_id: int,
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete an agent knowledge document."""
    doc = db.query(AgentKnowledge).filter(
        AgentKnowledge.id == doc_id,
        AgentKnowledge.organization_id == organization_id,
    ).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    _check_org_access(current_user, organization_id, db)
    db.delete(doc)
    db.commit()
    return None
