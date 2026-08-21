"""
AI Agent API Routes

REST and WebSocket endpoints for the AI security agent.
Includes conversation history CRUD and real-time WebSocket streaming.
"""

import asyncio
import json
import logging
import uuid
from typing import Optional, Literal, List
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel, field_validator, Field

from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import decode_token
from app.db.database import get_db, SessionLocal
from app.models.user import User
from app.models.organization import Organization
from app.models.agent_conversation import AgentConversation
from app.services.agent.orchestrator import get_agent_orchestrator
from app.services.agent.playbooks import build_initial_objective, list_playbooks
from app.services.agent import evograph
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["Agent"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class AgentQueryRequest(BaseModel):
    """Request to query the AI agent."""
    question: str
    session_id: Optional[str] = None
    playbook_id: Optional[str] = None
    target: Optional[str] = None
    mode: Optional[Literal["assist", "agent"]] = "assist"
    load_session_id: Optional[str] = None
    price_limit_usd: Optional[float] = None

    @field_validator("question")
    @classmethod
    def validate_question_length(cls, v: str) -> str:
        if len(v) > 10_000:
            raise ValueError("question must be at most 10,000 characters")
        if not v.strip():
            raise ValueError("question must not be empty")
        return v


class AgentSteerRequest(BaseModel):
    session_id: str
    message: str

    @field_validator("message")
    @classmethod
    def validate_steer(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("message must not be empty")
        if len(v) > 4000:
            raise ValueError("message must be at most 4,000 characters")
        return v.strip()


class AgentLoadRequest(BaseModel):
    session_id: str
    source_session_id: str


class AgentApprovalRequest(BaseModel):
    """Request to approve/modify/abort a phase transition."""
    session_id: str
    decision: str  # "approve", "modify", "abort"
    modification: Optional[str] = None


class AgentAnswerRequest(BaseModel):
    """Request to answer an agent question."""
    session_id: str
    answer: str


class AgentResponse(BaseModel):
    """Response from the AI agent."""
    answer: str
    session_id: str
    current_phase: str
    iteration_count: int
    task_complete: bool
    todo_list: list
    execution_trace_summary: str
    awaiting_approval: bool = False
    approval_request: Optional[dict] = None
    awaiting_question: bool = False
    question_request: Optional[dict] = None
    error: Optional[str] = None
    # Soft notice when preferred LLM was unavailable but a fallback kept serving
    warning: Optional[str] = None
    engagement_replay: list = Field(default_factory=list)
    token_usage: Optional[dict] = None
    cost_usd: Optional[float] = None
    price_limit_usd: Optional[float] = None


class ConversationSummary(BaseModel):
    """Summary of a conversation for the history list."""
    session_id: str
    title: Optional[str] = None
    mode: str = "assist"
    current_phase: str = "informational"
    is_active: bool = True
    message_count: int = 0
    created_at: str
    updated_at: str


# =============================================================================
# HELPERS
# =============================================================================

def _resolve_agent_organization_id(current_user: User, db: Session):
    """Resolve organization_id for agent: user's org, or first org for superusers without org."""
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        return org_id
    if getattr(current_user, "is_superuser", False):
        first_org = db.query(Organization).order_by(Organization.id).first()
        if first_org:
            return first_org.id
    return None


def _handle_agent_error(result_error: str):
    """Raise appropriate HTTP exception for agent errors."""
    err = result_error.lower()
    if "529" in result_error or "overloaded" in err or "overloaded_error" in err:
        raise HTTPException(
            status_code=503,
            detail="The AI provider (Anthropic/Claude) is temporarily overloaded. Please try again in a few minutes."
        )
    if any(
        m in err
        for m in (
            "credit balance",
            "insufficient_quota",
            "insufficient quota",
            "exceeded your current quota",
            "purchase credits",
            "plans & billing",
            "out of credits",
        )
    ):
        raise HTTPException(
            status_code=402,
            detail=(
                "Cloud LLM credits are exhausted. Top up the provider, or enable local "
                "Ollama fallback (COMPOSE_PROFILES=ollama, OLLAMA_FALLBACK_ENABLED=true) "
                "and restart the backend."
            ),
        )
    if any(
        m in err
        for m in (
            "authentication_error",
            "api key is invalid",
            "invalid api key",
            "invalid x-api-key",
            "incorrect api key",
            "invalid_api_key",
        )
    ):
        raise HTTPException(
            status_code=401,
            detail=(
                "Cloud LLM API key is invalid. Update ANTHROPIC_API_KEY / OPENAI_API_KEY "
                "in .env, or enable local Ollama fallback "
                "(COMPOSE_PROFILES=ollama, OLLAMA_FALLBACK_ENABLED=true) and restart."
            ),
        )
    raise HTTPException(status_code=500, detail=result_error)


def _save_conversation(
    db: Session,
    session_id: str,
    user_id: int,
    org_id: int,
    role: str,
    content: str,
    result=None,
    mode: str = "assist",
):
    """Upsert conversation record and append the message."""
    conv = db.query(AgentConversation).filter(AgentConversation.session_id == session_id).first()
    if not conv:
        title = content[:80] if role == "user" else None
        conv = AgentConversation(
            session_id=session_id,
            user_id=user_id,
            organization_id=org_id,
            title=title,
            mode=mode,
            messages=[],
        )
        db.add(conv)

    msgs = list(conv.messages or [])
    msgs.append({"role": role, "content": content[:5000]})

    if result:
        if role != "agent":
            msgs.append({"role": "agent", "content": (result.answer or "")[:5000]})
        conv.current_phase = result.current_phase
        conv.is_active = not result.task_complete
        conv.todo_list = result.todo_list or []
        conv.execution_summary = result.execution_trace_summary or ""
        if getattr(result, "engagement_replay", None) is not None:
            conv.engagement_replay = result.engagement_replay
        if getattr(result, "token_usage", None) is not None:
            conv.token_usage = result.token_usage
        if getattr(result, "cost_usd", None) is not None:
            conv.cost_usd = result.cost_usd
        try:
            from app.services.agent.observability import export_otlp_replay

            export_otlp_replay(
                {
                    "steps": result.engagement_replay or [],
                    "token_usage": result.token_usage or {},
                },
                service_name="judah-agent",
                session_id=session_id,
            )
        except Exception:
            logger.debug("OTLP replay export skipped", exc_info=True)

    conv.messages = msgs
    db.commit()
    try:
        from app.services.agent.palace_memory import mine_conversation_turn

        mine_conversation_turn(org_id, role, content, session_id=session_id)
        if result and role != "agent":
            mine_conversation_turn(
                org_id,
                "agent",
                result.answer or "",
                session_id=session_id,
            )
    except Exception:
        logger.debug("palace conversation mine skipped", exc_info=True)


def _agent_runtime_available() -> bool:
    """True when any cloud key is set or local Ollama can serve requests."""
    from app.services.agent.model_router import ollama_fallback_available
    return bool(
        settings.OPENAI_API_KEY
        or settings.ANTHROPIC_API_KEY
        or getattr(settings, "DEEPSEEK_API_KEY", None)
        or getattr(settings, "MOONSHOT_API_KEY", None)
        or getattr(settings, "GROQ_API_KEY", None)
        or ollama_fallback_available()
    )


def _build_agent_response(result, session_id: str) -> AgentResponse:
    return AgentResponse(
        answer=result.answer,
        session_id=session_id,
        current_phase=result.current_phase,
        iteration_count=result.iteration_count,
        task_complete=result.task_complete,
        todo_list=result.todo_list,
        execution_trace_summary=result.execution_trace_summary,
        awaiting_approval=result.awaiting_approval,
        approval_request=result.approval_request,
        awaiting_question=result.awaiting_question,
        question_request=result.question_request,
        warning=getattr(result, "warning", None),
        engagement_replay=getattr(result, "engagement_replay", None) or [],
        token_usage=getattr(result, "token_usage", None),
        cost_usd=getattr(result, "cost_usd", None),
        price_limit_usd=getattr(result, "price_limit_usd", None),
    )


# =============================================================================
# REST ENDPOINTS
# =============================================================================

@router.post("/query", response_model=AgentResponse)
async def query_agent(
    request: AgentQueryRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Send a query to the AI security agent."""
    if not _agent_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "AI agent not available — configure a cloud LLM API key or enable "
                "local Ollama (COMPOSE_PROFILES=ollama)."
            ),
        )
    
    orchestrator = await get_agent_orchestrator()
    session_id = request.session_id or str(uuid.uuid4())
    
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    
    question = request.question
    initial_todos = None
    if request.playbook_id:
        objective, initial_todos = build_initial_objective(request.playbook_id, request.target)
        if objective:
            question = objective
    
    _save_conversation(db, session_id, current_user.id, org_id, "user", question, mode=request.mode or "assist")

    try:
        invoke_task = asyncio.create_task(
            orchestrator.invoke(
                question=question,
                user_id=str(current_user.id),
                organization_id=org_id,
                session_id=session_id,
                initial_todos=initial_todos,
                mode=request.mode or "assist",
                max_iterations=settings.AGENT_REST_MAX_ITERATIONS,
                load_session_id=request.load_session_id,
                price_limit_usd=request.price_limit_usd,
            )
        )
        result = await asyncio.wait_for(
            invoke_task,
            timeout=settings.AGENT_REQUEST_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning(f"Agent query timed out after {settings.AGENT_REQUEST_TIMEOUT_SECONDS}s for session {session_id}")
        raise HTTPException(
            status_code=504,
            detail=f"The agent took longer than {settings.AGENT_REQUEST_TIMEOUT_SECONDS // 60} minutes. "
                   "Try a more specific question, or use WebSocket mode for real-time streaming (avoids timeouts)."
        )
    
    if result.error:
        _handle_agent_error(result.error)

    _save_conversation(db, session_id, current_user.id, org_id, "agent", result.answer or "", result)

    return _build_agent_response(result, session_id)


@router.post("/approve", response_model=AgentResponse)
async def approve_phase_transition(
    request: AgentApprovalRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Respond to a phase transition approval request."""
    if not _agent_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "AI agent not available — configure a cloud LLM API key or enable "
                "local Ollama (COMPOSE_PROFILES=ollama)."
            ),
        )
    
    if request.decision not in ["approve", "modify", "abort"]:
        raise HTTPException(status_code=400, detail="Decision must be 'approve', 'modify', or 'abort'")
    
    orchestrator = await get_agent_orchestrator()
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    
    try:
        invoke_task = asyncio.create_task(
            orchestrator.resume_after_approval(
                session_id=request.session_id,
                user_id=str(current_user.id),
                organization_id=org_id,
                decision=request.decision,
                modification=request.modification,
            )
        )
        result = await asyncio.wait_for(
            invoke_task,
            timeout=settings.AGENT_REQUEST_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Agent timed out after {settings.AGENT_REQUEST_TIMEOUT_SECONDS // 60} minutes. Use WebSocket mode for long operations."
        )
    
    if result.error:
        _handle_agent_error(result.error)

    _save_conversation(db, request.session_id, current_user.id, org_id, "agent", result.answer or "", result)
    return _build_agent_response(result, request.session_id)


@router.post("/answer", response_model=AgentResponse)
async def answer_agent_question(
    request: AgentAnswerRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Answer a question from the AI agent."""
    if not _agent_runtime_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "AI agent not available — configure a cloud LLM API key or enable "
                "local Ollama (COMPOSE_PROFILES=ollama)."
            ),
        )
    
    orchestrator = await get_agent_orchestrator()
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    
    _save_conversation(db, request.session_id, current_user.id, org_id, "user", request.answer)

    try:
        invoke_task = asyncio.create_task(
            orchestrator.resume_after_answer(
                session_id=request.session_id,
                user_id=str(current_user.id),
                organization_id=org_id,
                answer=request.answer,
            )
        )
        result = await asyncio.wait_for(
            invoke_task,
            timeout=settings.AGENT_REQUEST_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Agent timed out after {settings.AGENT_REQUEST_TIMEOUT_SECONDS // 60} minutes. Use WebSocket mode for long operations."
        )

    if result.error:
        _handle_agent_error(result.error)

    _save_conversation(db, request.session_id, current_user.id, org_id, "agent", result.answer or "", result)
    return _build_agent_response(result, request.session_id)


@router.post("/sessions/{session_id}/stop")
async def stop_agent_run(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cancel an in-flight agent run so it stops spending LLM tokens."""
    if not session_id or not session_id.strip():
        raise HTTPException(status_code=400, detail="session_id is required")
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    cancelled = _stop_agent_session(session_id)
    logger.info(
        "Agent stop requested by user %s for session %s (task_cancelled=%s)",
        current_user.id,
        session_id,
        cancelled,
    )
    return {"ok": True, "cancelled": cancelled, "session_id": session_id}


@router.post("/sessions/{session_id}/steer")
async def steer_agent_run(
    session_id: str,
    request: AgentSteerRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Inject an operator instruction into a live hunt without cancelling it."""
    if request.session_id != session_id:
        raise HTTPException(status_code=400, detail="session_id mismatch")
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    from app.services.agent.run_control import has_running_task, queue_steer

    in_flight = queue_steer(session_id, request.message)
    return {
        "ok": True,
        "session_id": session_id,
        "queued": True,
        "run_in_progress": in_flight or has_running_task(session_id),
    }


@router.post("/sessions/{session_id}/compact")
async def compact_agent_run(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Queue a CAI-style context compact for the next think turn."""
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    from app.services.agent.run_control import request_compact

    request_compact(session_id)
    return {"ok": True, "session_id": session_id, "compact_queued": True}


@router.post("/sessions/{session_id}/load")
async def load_prior_hunt(
    session_id: str,
    request: AgentLoadRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Queue a prior conversation brief into this session (CAI /load)."""
    if request.session_id != session_id:
        raise HTTPException(status_code=400, detail="session_id mismatch")
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    from app.services.agent.run_control import queue_load_brief
    from app.services.agent.session_ops import load_prior_conversation_brief

    brief = load_prior_conversation_brief(db, org_id, request.source_session_id)
    if not brief:
        raise HTTPException(status_code=404, detail="Prior session not found")
    queue_load_brief(session_id, brief)
    return {"ok": True, "session_id": session_id, "source_session_id": request.source_session_id}


@router.get("/playbooks")
async def get_agent_playbooks():
    """List preset playbook objectives for the agent."""
    return list_playbooks()


@router.get("/status")
async def get_agent_status():
    """Check if the AI agent is available."""
    from app.services.agent.model_router import (
        ollama_fallback_available,
        _ollama_fallback_model_name,
    )

    has_openai = bool(settings.OPENAI_API_KEY)
    has_anthropic = bool(settings.ANTHROPIC_API_KEY)
    has_ollama = ollama_fallback_available()
    available = _agent_runtime_available()
    
    provider = settings.AI_PROVIDER.lower()
    if provider == "anthropic" and has_anthropic:
        active_provider, active_model = "anthropic", settings.ANTHROPIC_MODEL
    elif provider == "openai" and has_openai:
        active_provider, active_model = "openai", settings.OPENAI_MODEL
    elif has_anthropic:
        active_provider, active_model = "anthropic", settings.ANTHROPIC_MODEL
    elif has_openai:
        active_provider, active_model = "openai", settings.OPENAI_MODEL
    elif has_ollama:
        active_provider, active_model = "ollama", _ollama_fallback_model_name()
    else:
        active_provider, active_model = None, None
    
    hint = None
    if not available:
        hint = (
            "Set a cloud LLM API key (ANTHROPIC_API_KEY / OPENAI_API_KEY) in .env, "
            "or enable local Ollama with COMPOSE_PROFILES=ollama, then restart the backend."
        )
    elif not has_anthropic and not has_openai and has_ollama:
        hint = (
            "Running on local Ollama. Add cloud API keys anytime for higher-quality models; "
            "if those keys run out of credits, the agent will keep working on Ollama."
        )

    return {
        "available": available,
        "provider": active_provider,
        "model": active_model,
        "providers_configured": {
            "openai": has_openai,
            "anthropic": has_anthropic,
            "ollama": has_ollama,
        },
        "resilient_fallback": True,
        "hint": hint,
        "max_iterations": settings.AGENT_MAX_ITERATIONS if available else None,
        "features": {
            "attack_surface_analysis": True,
            "vulnerability_queries": True,
            "remediation_guidance": True,
            "natural_language_queries": True,
            "websocket_streaming": True,
            "cross_session_learning": True,
            "conversation_history": True,
            "mid_run_steer": True,
            "session_compact": True,
            "spend_cap": True,
            "mcp_client": True,
            "custom_probe": True,
        } if available else {},
        "price_limit_usd": settings.AGENT_PRICE_LIMIT_USD if available else None,
    }


# =============================================================================
# CONVERSATION HISTORY ENDPOINTS
# =============================================================================

@router.get("/conversations", response_model=List[ConversationSummary])
async def list_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, le=200),
):
    """List the current user's agent conversations."""
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        return []

    convs = (
        db.query(AgentConversation)
        .filter(
            AgentConversation.user_id == current_user.id,
            AgentConversation.organization_id == org_id,
        )
        .order_by(AgentConversation.updated_at.desc())
        .limit(limit)
        .all()
    )

    return [
        ConversationSummary(
            session_id=c.session_id,
            title=c.title,
            mode=c.mode or "assist",
            current_phase=c.current_phase or "informational",
            is_active=c.is_active if c.is_active is not None else True,
            message_count=len(c.messages) if c.messages else 0,
            created_at=c.created_at.isoformat() if c.created_at else "",
            updated_at=c.updated_at.isoformat() if c.updated_at else "",
        )
        for c in convs
    ]


@router.get("/conversations/{session_id}")
async def get_conversation(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Load a single conversation with full message history."""
    conv = (
        db.query(AgentConversation)
        .filter(
            AgentConversation.session_id == session_id,
            AgentConversation.user_id == current_user.id,
        )
        .first()
    )
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    return {
        "session_id": conv.session_id,
        "title": conv.title,
        "mode": conv.mode,
        "current_phase": conv.current_phase,
        "is_active": conv.is_active,
        "messages": conv.messages or [],
        "todo_list": conv.todo_list or [],
        "execution_summary": conv.execution_summary,
        "engagement_replay": conv.engagement_replay or [],
        "token_usage": conv.token_usage,
        "cost_usd": conv.cost_usd,
        "created_at": conv.created_at.isoformat() if conv.created_at else "",
        "updated_at": conv.updated_at.isoformat() if conv.updated_at else "",
    }


@router.delete("/conversations/{session_id}")
async def delete_conversation(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a conversation."""
    conv = (
        db.query(AgentConversation)
        .filter(
            AgentConversation.session_id == session_id,
            AgentConversation.user_id == current_user.id,
        )
        .first()
    )
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    db.delete(conv)
    db.commit()
    return {"ok": True}


# =============================================================================
# ATTACK SCENARIO / EVOGRAPH CHAIN
# =============================================================================

@router.get("/sessions/{session_id}/chain")
async def get_session_chain(
    session_id: str,
    include_attack_paths: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch the EvoGraph attack chain for a session as graph nodes/edges.
    
    If include_attack_paths=true, also fetches Neo4j attack paths for the
    organization and merges them into the response.
    """
    chain = evograph.get_session_chain(session_id)

    if include_attack_paths:
        org_id = _resolve_agent_organization_id(current_user, db)
        if org_id:
            try:
                from app.services.graph_service import get_graph_service
                graph_svc = get_graph_service()
                if graph_svc.connect():
                    paths = graph_svc.get_attack_paths(org_id, max_depth=4)
                    chain["attack_paths"] = paths[:10]
            except Exception:
                chain["attack_paths"] = []

    return chain


# =============================================================================
# WEBSOCKET ENDPOINT
# =============================================================================

class WebSocketManager:
    """Manage WebSocket connections for real-time agent streaming."""
    
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, session_id: str):
        await websocket.accept()
        self.active_connections[session_id] = websocket
    
    def disconnect(self, session_id: str):
        self.active_connections.pop(session_id, None)
    
    async def send_message(self, session_id: str, message: dict):
        ws = self.active_connections.get(session_id)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(session_id)


def _stop_agent_session(session_id: str) -> bool:
    """Cancel an in-flight agent run and its recon streams."""
    from app.services.agent.run_control import request_stop
    from app.services.agent import recon_workers

    cancelled = request_stop(session_id)
    try:
        recon_workers.clear_session(session_id)
    except Exception:
        logger.debug("recon worker clear on stop failed", exc_info=True)
    return cancelled


def _ws_response_payload(result) -> dict:
    return {
        "type": "response",
        "answer": result.answer,
        "current_phase": result.current_phase,
        "iteration_count": result.iteration_count,
        "task_complete": result.task_complete,
        "todo_list": result.todo_list,
        "execution_trace_summary": result.execution_trace_summary,
        "awaiting_approval": result.awaiting_approval,
        "approval_request": result.approval_request,
        "awaiting_question": result.awaiting_question,
        "question_request": result.question_request,
        "warning": getattr(result, "warning", None),
        "engagement_replay": getattr(result, "engagement_replay", None) or [],
        "token_usage": getattr(result, "token_usage", None),
        "cost_usd": getattr(result, "cost_usd", None),
        "price_limit_usd": getattr(result, "price_limit_usd", None),
    }


def _authenticate_ws_token(token: str):
    """Validate a JWT token from the WebSocket init message. Returns (user, org_id) or raises."""
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        return None, None

    subject = payload.get("sub")
    if not subject:
        return None, None

    db = SessionLocal()
    try:
        user = db.query(User).filter((User.username == subject) | (User.email == subject)).first()
        if not user:
            return None, None
        org_id = _resolve_agent_organization_id(user, db)
        return user, org_id
    finally:
        db.close()


@router.websocket("/ws/{session_id}")
async def agent_websocket(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for real-time agent interaction.
    
    Message format (client -> server):
    - {"type": "init", "token": "jwt_token"}
    - {"type": "query", "question": "...", "playbook_id": "...", "target": "...", "mode": "...",
       "load_session_id": "...", "price_limit_usd": 5.0}
    - {"type": "steer", "message": "..."}  # mid-run; does not cancel the hunt
    - {"type": "compact"}
    - {"type": "load", "source_session_id": "..."}
    - {"type": "approval", "decision": "approve|modify|abort", "modification": "..."}
    - {"type": "answer", "answer": "..."}
    - {"type": "stop"}
    - {"type": "ping"}
    
    Message format (server -> client):
    - {"type": "connected", "session_id": "..."}
    - {"type": "authenticated", "user_id": N}
    - {"type": "thinking", "iteration": N, "phase": "...", "thought": "..."}
    - {"type": "tool_start", "tool_name": "...", "tool_args": {...}}
    - {"type": "capability_map_update", "quality_score": ..., "ranked_hunt_queue": [...]}
    - {"type": "auth_session_update", "authenticated": bool, "cookie_count": N}
    - {"type": "pending_confirmation", "token": "...", "tool_name": "..."}
    - {"type": "tool_complete", "tool_name": "...", "success": true, "output_summary": "..."}
    - {"type": "cost", "cost_usd": N, "limit_usd": N, "capped": bool}
    - {"type": "steered", "message": "..."}
    - {"type": "compacted", "brief": "..."}
    - {"type": "steer_queued" | "compact_queued" | "load_queued"}
    - {"type": "response", ...full AgentResponse fields...}
    - {"type": "cancelled", "message": "..."}
    - {"type": "error", "message": "..."}
    - {"type": "pong"}
    """
    await ws_manager.connect(websocket, session_id)

    try:
        await websocket.send_json({"type": "connected", "session_id": session_id})

        user = None
        user_id = None
        org_id = None
        authenticated = False
        run_holder: dict = {"task": None, "cancelled_sent": False}

        async def status_callback(msg: dict):
            """Forward orchestrator status updates to WebSocket."""
            await ws_manager.send_message(session_id, msg)

        async def emit_cancelled():
            if run_holder["cancelled_sent"]:
                return
            run_holder["cancelled_sent"] = True
            await ws_manager.send_message(session_id, {
                "type": "cancelled",
                "message": "Stopped by operator. No further LLM or tool calls will run.",
            })

        async def finish_result(result, *, save_user_question=None, mode=None):
            from app.services.agent.run_control import is_stop_requested
            if run_holder["cancelled_sent"] or is_stop_requested(session_id):
                if not run_holder["cancelled_sent"]:
                    await emit_cancelled()
                return
            db = SessionLocal()
            try:
                if save_user_question:
                    _save_conversation(
                        db, session_id, user_id, org_id, "user", save_user_question, mode=mode,
                    )
                if not result.error:
                    _save_conversation(db, session_id, user_id, org_id, "agent", result.answer or "", result)
            finally:
                db.close()
            if result.error:
                await websocket.send_json({"type": "error", "message": result.error})
            else:
                await websocket.send_json(_ws_response_payload(result))

        def spawn_run(coro):
            from app.services.agent.run_control import register_run

            async def _guarded():
                try:
                    await coro
                except asyncio.CancelledError:
                    await emit_cancelled()

            task = asyncio.create_task(_guarded())
            run_holder["task"] = task
            run_holder["cancelled_sent"] = False
            register_run(session_id, task)
            return task

        def run_in_progress() -> bool:
            task = run_holder.get("task")
            return bool(task is not None and not task.done())

        # Require authentication within 30 seconds
        try:
            data = await asyncio.wait_for(websocket.receive_json(), timeout=30.0)
        except asyncio.TimeoutError:
            await websocket.send_json({"type": "error", "message": "Authentication timeout. Send {type: 'init', token: '...'} within 30 seconds."})
            await websocket.close(code=4001)
            return

        if data.get("type") != "init":
            await websocket.send_json({"type": "error", "message": "First message must be {type: 'init', token: '...'}"})
            await websocket.close(code=4002)
            return

        token = data.get("token", "")
        user, org_id = _authenticate_ws_token(token)
        if not user or not org_id:
            await websocket.send_json({"type": "error", "message": "Authentication failed"})
            await websocket.close(code=4003)
            return
        user_id = user.id
        authenticated = True
        await websocket.send_json({"type": "authenticated", "user_id": user_id})

        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")
            
            if msg_type == "init":
                token = data.get("token", "")
                user, org_id = _authenticate_ws_token(token)
                if not user or not org_id:
                    await websocket.send_json({"type": "error", "message": "Authentication failed"})
                    continue
                user_id = user.id
                await websocket.send_json({"type": "authenticated", "user_id": user_id})
            
            elif msg_type == "query":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated. Send {type: 'init', token: '...'} first."})
                    continue
                if run_in_progress():
                    await websocket.send_json({
                        "type": "error",
                        "message": "A run is already in progress. Stop it first.",
                    })
                    continue
                
                question = data.get("question", "")
                if not question or not question.strip():
                    await websocket.send_json({"type": "error", "message": "question must not be empty"})
                    continue
                if len(question) > 10_000:
                    await websocket.send_json({"type": "error", "message": "question must be at most 10,000 characters"})
                    continue
                playbook_id = data.get("playbook_id")
                target = data.get("target")
                mode = data.get("mode", "assist")
                load_session_id = data.get("load_session_id") or None
                price_limit_usd = None
                if data.get("price_limit_usd") is not None:
                    try:
                        price_limit_usd = float(data.get("price_limit_usd"))
                    except (TypeError, ValueError):
                        await websocket.send_json({
                            "type": "error",
                            "message": "price_limit_usd must be a number",
                        })
                        continue

                initial_todos = None
                if playbook_id:
                    objective, initial_todos = build_initial_objective(playbook_id, target)
                    if objective:
                        question = objective

                async def _run_query(
                    q=question,
                    todos=initial_todos,
                    run_mode=mode,
                    load_id=load_session_id,
                    limit=price_limit_usd,
                ):
                    try:
                        orchestrator = await get_agent_orchestrator()
                        result = await asyncio.wait_for(
                            orchestrator.invoke(
                                question=q,
                                user_id=str(user_id),
                                organization_id=org_id,
                                session_id=session_id,
                                initial_todos=todos,
                                mode=run_mode,
                                status_callback=status_callback,
                                max_iterations=settings.AGENT_WS_MAX_ITERATIONS,
                                load_session_id=load_id,
                                price_limit_usd=limit,
                            ),
                            timeout=settings.AGENT_REQUEST_TIMEOUT_SECONDS,
                        )
                        await finish_result(result, save_user_question=q, mode=run_mode)
                    except asyncio.CancelledError:
                        await emit_cancelled()
                    except asyncio.TimeoutError:
                        logger.warning(f"WS agent query timed out after {settings.AGENT_REQUEST_TIMEOUT_SECONDS}s for session {session_id}")
                        await websocket.send_json({
                            "type": "error",
                            "message": f"The agent took longer than {settings.AGENT_REQUEST_TIMEOUT_SECONDS // 60} minutes and timed out. Try a more specific question.",
                        })
                    except Exception as e:
                        logger.error(f"WS agent query error for session {session_id}: {e}")
                        await websocket.send_json({"type": "error", "message": f"Agent error: {e}"})

                spawn_run(_run_query())
            
            elif msg_type == "approval":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                if run_in_progress():
                    await websocket.send_json({
                        "type": "error",
                        "message": "A run is already in progress. Stop it first.",
                    })
                    continue

                async def _run_approval(decision=data.get("decision", "abort"), modification=data.get("modification")):
                    try:
                        orchestrator = await get_agent_orchestrator()
                        result = await asyncio.wait_for(
                            orchestrator.resume_after_approval(
                                session_id=session_id,
                                user_id=str(user_id),
                                organization_id=org_id,
                                decision=decision,
                                modification=modification,
                                status_callback=status_callback,
                            ),
                            timeout=settings.AGENT_REQUEST_TIMEOUT_SECONDS,
                        )
                        await finish_result(result)
                    except asyncio.CancelledError:
                        await emit_cancelled()
                    except asyncio.TimeoutError:
                        logger.warning(f"WS agent approval timed out for session {session_id}")
                        await websocket.send_json({"type": "error", "message": "Agent approval processing timed out."})
                    except Exception as e:
                        logger.error(f"WS agent approval error for session {session_id}: {e}")
                        await websocket.send_json({"type": "error", "message": f"Agent error: {e}"})

                spawn_run(_run_approval())
            
            elif msg_type == "answer":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                if run_in_progress():
                    await websocket.send_json({
                        "type": "error",
                        "message": "A run is already in progress. Stop it first.",
                    })
                    continue
                
                answer_text = data.get("answer", "")

                db = SessionLocal()
                try:
                    _save_conversation(db, session_id, user_id, org_id, "user", answer_text)
                finally:
                    db.close()

                async def _run_answer(answer=answer_text):
                    try:
                        orchestrator = await get_agent_orchestrator()
                        result = await asyncio.wait_for(
                            orchestrator.resume_after_answer(
                                session_id=session_id,
                                user_id=str(user_id),
                                organization_id=org_id,
                                answer=answer,
                                status_callback=status_callback,
                            ),
                            timeout=settings.AGENT_REQUEST_TIMEOUT_SECONDS,
                        )
                        await finish_result(result)
                    except asyncio.CancelledError:
                        await emit_cancelled()
                    except asyncio.TimeoutError:
                        logger.warning(f"WS agent answer timed out for session {session_id}")
                        await websocket.send_json({"type": "error", "message": "Agent answer processing timed out."})
                    except Exception as e:
                        logger.error(f"WS agent answer error for session {session_id}: {e}")
                        await websocket.send_json({"type": "error", "message": f"Agent error: {e}"})

                spawn_run(_run_answer())

            elif msg_type == "steer":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                message = (data.get("message") or "").strip()
                if not message:
                    await websocket.send_json({"type": "error", "message": "message must not be empty"})
                    continue
                if len(message) > 4000:
                    await websocket.send_json({
                        "type": "error",
                        "message": "message must be at most 4,000 characters",
                    })
                    continue
                from app.services.agent.run_control import has_running_task, queue_steer

                in_flight = queue_steer(session_id, message)
                await websocket.send_json({
                    "type": "steer_queued",
                    "queued": True,
                    "run_in_progress": in_flight or has_running_task(session_id),
                })

            elif msg_type == "compact":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                from app.services.agent.run_control import request_compact

                request_compact(session_id)
                await websocket.send_json({"type": "compact_queued", "session_id": session_id})

            elif msg_type == "load":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                source = (data.get("source_session_id") or "").strip()
                if not source:
                    await websocket.send_json({
                        "type": "error",
                        "message": "source_session_id is required",
                    })
                    continue
                from app.services.agent.run_control import queue_load_brief
                from app.services.agent.session_ops import load_prior_conversation_brief

                db = SessionLocal()
                try:
                    brief = load_prior_conversation_brief(db, org_id, source)
                finally:
                    db.close()
                if not brief:
                    await websocket.send_json({"type": "error", "message": "Prior session not found"})
                    continue
                queue_load_brief(session_id, brief)
                await websocket.send_json({
                    "type": "load_queued",
                    "source_session_id": source,
                })

            elif msg_type == "stop":
                _stop_agent_session(session_id)
                await emit_cancelled()
            
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})
    
    except WebSocketDisconnect:
        _stop_agent_session(session_id)
        ws_manager.disconnect(session_id)
        logger.info(f"WebSocket disconnected: {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        _stop_agent_session(session_id)
        ws_manager.disconnect(session_id)
