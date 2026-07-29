"""
Findings Ingestion API

Authenticated endpoints for external agents (Aegis Vanguard, CI/CD, custom scanners)
to submit findings to the ASM platform. Supports both API key auth (for agents)
and JWT auth (for admin management of API keys).
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Request, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.database import get_db
from app.models.user import User
from app.models.agent_api_key import AgentAPIKey
from app.schemas.ingestion import (
    IngestionBatchRequest,
    IngestionBatchResponse,
    IngestionHeartbeat,
    IngestionHeartbeatResponse,
    AgentAPIKeyCreate,
    AgentAPIKeyResponse,
)
from app.services.ingestion_service import (
    process_ingestion_batch,
    verify_agent_api_key,
    create_agent_api_key,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["Ingestion"])


# =========================================================================
# Agent API Key Authentication Dependency
# =========================================================================

def get_agent_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> AgentAPIKey:
    """Authenticate an external agent via API key.
    
    Accepts the key in either X-API-Key header or Authorization: Bearer header.
    """
    api_key = x_api_key
    if not api_key and authorization:
        if authorization.startswith("Bearer tfasm_"):
            api_key = authorization[7:]  # strip "Bearer "

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header or Authorization: Bearer tfasm_...",
        )

    record = verify_agent_api_key(db, api_key)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    return record


def require_scope(scope: str):
    """Factory for scope-checking dependencies."""
    def _check(agent_key: AgentAPIKey = Depends(get_agent_key)):
        if agent_key.scopes and scope not in agent_key.scopes:
            raise HTTPException(
                status_code=403,
                detail=f"API key lacks required scope: {scope}",
            )
        return agent_key
    return _check


# =========================================================================
# Agent Endpoints (API Key Auth)
# =========================================================================

@router.post("/findings", response_model=IngestionBatchResponse)
async def submit_findings(
    request: IngestionBatchRequest,
    req: Request,
    agent_key: AgentAPIKey = Depends(require_scope("ingest:findings")),
    db: Session = Depends(get_db),
):
    """Submit a batch of findings from an external agent.
    
    Accepts the UnifiedFinding format. Each finding is mapped into the
    platform's data model (Assets, PortServices, Vulnerabilities).
    Duplicate findings are detected and deduplicated.
    """
    agent_key.last_agent_ip = req.client.host if req.client else None
    db.commit()

    logger.info(
        f"Ingestion from agent '{request.agent_id}' "
        f"(org={agent_key.organization_id}): {len(request.findings)} findings"
    )

    return process_ingestion_batch(db, request, agent_key.organization_id)


@router.post("/heartbeat", response_model=IngestionHeartbeatResponse)
async def agent_heartbeat(
    heartbeat: IngestionHeartbeat,
    agent_key: AgentAPIKey = Depends(require_scope("ingest:heartbeat")),
    db: Session = Depends(get_db),
):
    """Agent heartbeat for health monitoring."""
    logger.debug(f"Heartbeat from agent '{heartbeat.agent_id}' (status={heartbeat.status})")

    return IngestionHeartbeatResponse(
        ack=True,
        server_time=datetime.utcnow(),
        agent_id=heartbeat.agent_id,
        config=None,
    )


# =========================================================================
# Admin Endpoints (JWT Auth) - API Key Management
# =========================================================================

@router.post("/api-keys", response_model=AgentAPIKeyResponse)
async def create_api_key(
    request: AgentAPIKeyCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a new API key for an external agent.
    
    The full key is returned only once in the response. Store it securely.
    """
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        from app.models.organization import Organization
        first_org = db.query(Organization).order_by(Organization.id).first()
        if first_org:
            org_id = first_org.id
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization found")

    record, plaintext_key = create_agent_api_key(
        db=db,
        organization_id=org_id,
        name=request.name,
        agent_type=request.agent_type.value,
        scopes=request.scopes,
        expires_in_days=request.expires_in_days,
        created_by_user_id=current_user.id,
    )

    return AgentAPIKeyResponse(
        key_id=record.key_id,
        api_key=plaintext_key,
        name=record.name,
        agent_type=request.agent_type,
        scopes=record.scopes,
        organization_id=record.organization_id,
        expires_at=record.expires_at,
        created_at=record.created_at,
    )


@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List all agent API keys for the current organization."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        from app.models.organization import Organization
        first_org = db.query(Organization).order_by(Organization.id).first()
        if first_org:
            org_id = first_org.id

    keys = (
        db.query(AgentAPIKey)
        .filter(AgentAPIKey.organization_id == org_id)
        .order_by(AgentAPIKey.created_at.desc())
        .all()
    )

    return [
        {
            "key_id": k.key_id,
            "key_prefix": k.key_prefix,
            "name": k.name,
            "agent_type": k.agent_type,
            "scopes": k.scopes,
            "is_active": k.is_active,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "usage_count": k.usage_count,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created_at": k.created_at.isoformat(),
        }
        for k in keys
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Revoke an agent API key."""
    org_id = getattr(current_user, "organization_id", None)
    record = (
        db.query(AgentAPIKey)
        .filter(AgentAPIKey.key_id == key_id)
        .first()
    )

    if not record:
        raise HTTPException(status_code=404, detail="API key not found")

    if org_id and record.organization_id != org_id:
        if not getattr(current_user, "is_superuser", False):
            raise HTTPException(status_code=403, detail="Cannot revoke keys from other organizations")

    record.is_active = False
    record.revoked_at = datetime.utcnow()
    db.commit()

    return {"ok": True, "key_id": key_id, "status": "revoked"}
