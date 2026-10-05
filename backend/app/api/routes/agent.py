"""
AI Agent API Routes

REST and WebSocket endpoints for the AI security agent.
Includes conversation history CRUD and real-time WebSocket streaming.
"""

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Optional, Literal, List
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel, field_validator, model_validator, Field

from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import decode_token
from app.db.database import get_db, SessionLocal
from app.models.user import User
from app.models.organization import Organization
from app.models.agent_conversation import AgentConversation
from app.models.asset import Asset
from app.services.agent.prowl_service_bridge import provision_run
from app.services.agent.orchestrator import get_agent_orchestrator
from app.services.agent.state import InvokeResponse
from app.services.agent.playbooks import build_initial_objective, list_playbooks
from app.services.agent import evograph
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["Agent"])


def _run_timeout_s() -> int:
    """Wall-clock cap for one invoke. Never below 1h — nginx 60s must not win."""
    return max(int(settings.AGENT_REQUEST_TIMEOUT_SECONDS), 3600)


def _timeout_result(session_id: str, org_id: int, user_id: int) -> InvokeResponse:
    """Build a user-facing partial report from receipts after an outer cutoff."""
    from app.services.agent.action_ledger import finish_run, latest_run, partial_report

    db = SessionLocal()
    try:
        run = latest_run(db, session_id=session_id,
                         organization_id=org_id, user_id=user_id)
    finally:
        db.close()
    if run:
        finish_run(run["run_id"], "timeout", "Outer request time limit")
    answer = partial_report(run["run_id"], "external time limit") if run else (
        "The agent reached its time limit before a tool action was recorded. "
        "Review the run ledger before continuing."
    )
    return InvokeResponse(answer=answer, task_complete=True)


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class OwnerOnlyResource(BaseModel):
    target: str = Field(max_length=2048)
    owner_identity: str = Field(min_length=1, max_length=80)
    other_identity: str = Field(min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_resource(self):
        from app.services.agent.scoped_assessment.browser import origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path

        parts = urlsplit(self.target)
        path = parts.path or "/"
        if (self.owner_identity == self.other_identity or parts.query or parts.fragment
                or not allowed_discovery_path(path)
                or self.target != origin(self.target) + path):
            raise ValueError("Owner-only resource needs an exact safe path and distinct identities")
        return self


class AgentAssessmentPolicy(BaseModel):
    body_replay_paths: list[str] = Field(default_factory=list, max_length=8)
    owner_only_resources: list[OwnerOnlyResource] = Field(default_factory=list, max_length=8)

    @field_validator("body_replay_paths")
    @classmethod
    def validate_body_paths(cls, paths: list[str]) -> list[str]:
        for path in paths:
            if (not path.startswith("/") or path.startswith("//") or path == "/"
                    or len(path) > 256 or any(char in path for char in "?#\\\r\n\t ")):
                raise ValueError("Body replay needs exact absolute paths without query values")
        return paths


class AgentQueryRequest(BaseModel):
    """Request to query the AI agent."""
    question: str
    session_id: Optional[str] = None
    playbook_id: Optional[str] = None
    target: Optional[str] = None
    mode: Optional[Literal["assist", "agent", "pilot"]] = "assist"
    pilot: Optional[dict] = None
    load_session_id: Optional[str] = None
    price_limit_usd: Optional[float] = None
    assessment_policy: Optional[AgentAssessmentPolicy] = None

    @field_validator("question")
    @classmethod
    def validate_question_length(cls, v: str) -> str:
        if len(v) > 10_000:
            raise ValueError("question must be at most 10,000 characters")
        if not v.strip():
            raise ValueError("question must not be empty")
        return v


class ScopedAssessmentStartRequest(BaseModel):
    asset_id: int
    origin: str
    session_id: Optional[str] = None
    identities: dict[str, dict] = Field(default_factory=dict)
    body_replay_paths: list[str] = Field(default_factory=list)
    authz_expectations: list[dict] = Field(default_factory=list)

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and (not v or len(v) > 64):
            raise ValueError("session_id must be 1 to 64 characters")
        return v


def _pilot_launch_config(raw: Optional[dict], organization_id: int, session_id: str) -> dict:
    """Server-owned two-hour window; reject missing/invalid preflight fields."""
    from app.services.agent.pilot_policy import PilotDenied, PilotPolicy, configured_egress_ip

    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="Pilot target is required")
    config = {
        "target": (raw or {}).get("target"),
        "source_ip": configured_egress_ip(),
        "expires_at_ms": int(time.time() * 1000) + 7_200_000,
    }
    try:
        return PilotPolicy.from_config(config, organization_id, session_id).as_config()
    except PilotDenied as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _check_pilot_session(db: Session, session_id: str, user_id: int, mode: str) -> None:
    """A bounded pilot starts in a fresh conversation and cannot be downgraded."""
    existing = db.query(AgentConversation).filter(
        AgentConversation.session_id == session_id,
    ).first()
    if existing and (mode == "pilot" or existing.mode == "pilot"):
        raise HTTPException(
            status_code=409,
            detail="Start a new conversation for a bounded pilot or a different mode",
        )


def _pilot_question(question: str, config: dict, playbook_id: Optional[str],
                    load_session_id: Optional[str]) -> str:
    """Keep a pilot's seed target and objective tied to its server-validated host."""
    if playbook_id or load_session_id:
        raise HTTPException(status_code=400, detail="A bounded pilot requires a fresh, direct objective")
    return (
        f"Pilot seed: {config['target']}/. Only assess this exact hostname or public IP. "
        "The seed is a starting web URL; other ports on this host may be probed within the shared budget. "
        "Use anonymous GET, HEAD, or OPTIONS HTTP requests and the bounded pilot tools. "
        "Every network tool call requires analyst approval.\n"
        f"Assessment objective: {question}"
    )


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
    # REST /query returns immediately and runs the hunt in the background so
    # nginx/ALB cannot 504 the browser. Poll GET /conversations/{session_id}.
    running: bool = False


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
            status_code=502,
            detail=(
                "Cloud LLM API key is invalid. Update the configured provider key "
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
    """Upsert conversation record and append the message; return persistence status.

    Always uses a short-lived session. The request-scoped ``db`` can sit idle
    for the whole invoke (tens of minutes) and then fail on commit with a
    stale-connection SQLAlchemyError — which the API surfaces as
    "A database error occurred." and kills a successful agent run.
    Persistence failure must not fail the agent request.
    """
    del db  # request session is often stale after a long invoke
    session = SessionLocal()
    try:
        conv = session.query(AgentConversation).filter(AgentConversation.session_id == session_id).first()
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
            session.add(conv)

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
        session.commit()
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
        return True
    except Exception:
        logger.exception("Failed to persist agent conversation session=%s", session_id)
        try:
            session.rollback()
        except Exception:
            pass
        return False
    finally:
        session.close()


def _agent_runtime_available() -> bool:
    """True when any cloud key is set or local Ollama can serve requests."""
    from app.services.agent.model_router import global_runtime_model_spec
    return global_runtime_model_spec() is not None


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

@router.post("/scoped-assessments", status_code=201)
async def start_scoped_assessment(
    request: ScopedAssessmentStartRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Operator provisions an exact-origin executor for an Aegis agent session."""
    import httpx

    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization")
    asset = db.query(Asset).filter(Asset.id == request.asset_id, Asset.organization_id == org_id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="In-scope asset not found")
    session_id = request.session_id or str(uuid.uuid4())
    conversation = db.query(AgentConversation).filter_by(session_id=session_id).first()
    if conversation is not None and (conversation.user_id != current_user.id or conversation.organization_id != org_id):
        raise HTTPException(status_code=403, detail="Agent session belongs to another user or organization")
    if conversation is None:
        conversation = AgentConversation(
            session_id=session_id, user_id=current_user.id, organization_id=org_id,
            title=f"Assessment: {asset.value[:70]}", mode="agent", messages=[],
        )
        db.add(conversation)
    try:
        binding = await provision_run(
            db, organization_id=org_id, user_id=current_user.id,
            session_id=session_id, asset=asset, origin=request.origin,
            identities=request.identities,
            body_replay_paths=request.body_replay_paths,
            authz_expectations=request.authz_expectations,
        )
    except httpx.RequestError:
        db.rollback()
        raise HTTPException(status_code=502, detail="Scoped assessment service is unavailable")
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "session_id": session_id, "run_id": binding.service_run_id,
        "asset_id": binding.asset_id, "allowed_origin": binding.allowed_origin,
    }


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
    
    session_id = request.session_id or str(uuid.uuid4())
    
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=400, detail="User must belong to an organization to use the agent.")
    existing = db.query(AgentConversation).filter_by(session_id=session_id).first()
    if existing is not None and (existing.user_id != current_user.id or existing.organization_id != org_id):
        raise HTTPException(status_code=403, detail="Agent session belongs to another user or organization")
    
    question = request.question
    initial_todos = None
    if request.playbook_id:
        objective, initial_todos = build_initial_objective(request.playbook_id, request.target)
        if objective:
            question = objective

    mode = request.mode or "assist"
    _check_pilot_session(db, session_id, current_user.id, mode)
    if mode == "pilot" and request.assessment_policy is not None:
        raise HTTPException(status_code=400, detail="Bounded pilot does not accept an assessment policy")
    pilot_config = _pilot_launch_config(request.pilot, org_id, session_id) if mode == "pilot" else None
    if pilot_config is not None:
        question = _pilot_question(question, pilot_config, request.playbook_id, request.load_session_id)
    saved = _save_conversation(db, session_id, current_user.id, org_id, "user", question, mode=mode)
    if pilot_config is not None and not saved:
        raise HTTPException(status_code=503, detail="Pilot session could not be persisted")

    # Do not hold this HTTP request for the hunt. Playbooks against a live
    # target routinely exceed nginx/ALB idle timeouts; the UI then shows 504
    # with no agent message saved. Run in the background and let the client
    # poll GET /conversations/{session_id}.
    user_id = current_user.id
    load_session_id = request.load_session_id
    price_limit_usd = request.price_limit_usd
    assessment_policy = request.assessment_policy.model_dump() if request.assessment_policy else None
    todos = initial_todos

    async def _run_rest_query() -> None:
        from app.services.agent.run_control import register_run

        timeout_s = _run_timeout_s()
        try:
            orch = await get_agent_orchestrator(initialize=False)
            invoke_task = asyncio.create_task(
                orch.invoke(
                    question=question,
                    user_id=str(user_id),
                    organization_id=org_id,
                    session_id=session_id,
                    initial_todos=todos,
                    mode=mode,
                    max_iterations=settings.AGENT_WS_MAX_ITERATIONS,
                    load_session_id=load_session_id,
                    price_limit_usd=price_limit_usd,
                    assessment_policy=assessment_policy,
                    pilot_config=pilot_config,
                )
            )
            register_run(session_id, invoke_task)
            result = await asyncio.wait_for(invoke_task, timeout=timeout_s)
        except asyncio.TimeoutError:
            logger.warning(
                "Background REST agent query timed out after %ss session=%s",
                timeout_s,
                session_id,
            )
            timeout_result = _timeout_result(session_id, org_id, user_id)
            _save_conversation(None, session_id, user_id, org_id, "agent",
                               timeout_result.answer, timeout_result, mode=mode)
            return
        except Exception:
            logger.exception("Background REST agent query failed session=%s", session_id)
            _save_conversation(
                None,
                session_id,
                user_id,
                org_id,
                "agent",
                "Agent failed before it could return a report. Check the run ledger "
                "for completed actions and backend logs for the failure.",
                mode=mode,
            )
            return
        if result.error:
            _save_conversation(
                None, session_id, user_id, org_id, "agent", result.error, result, mode=mode
            )
            return
        _save_conversation(
            None, session_id, user_id, org_id, "agent", result.answer or "", result, mode=mode
        )

    asyncio.create_task(_run_rest_query())
    return AgentResponse(
        answer="",
        session_id=session_id,
        current_phase="running",
        iteration_count=0,
        task_complete=False,
        todo_list=todos or [],
        execution_trace_summary="Agent run started. This conversation will update when it finishes.",
        running=True,
    )


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
            timeout=_run_timeout_s(),
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Agent timed out after {_run_timeout_s() // 60} minutes. Use WebSocket mode for long operations."
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
            timeout=_run_timeout_s(),
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Agent timed out after {_run_timeout_s() // 60} minutes. Use WebSocket mode for long operations."
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
    from app.services.agent.model_router import global_runtime_model_spec, ollama_fallback_available

    configured = {
        "openai": bool(settings.OPENAI_API_KEY),
        "anthropic": bool(settings.ANTHROPIC_API_KEY),
        "deepseek": bool(settings.DEEPSEEK_API_KEY),
        "kimi": bool(settings.MOONSHOT_API_KEY),
        "groq": bool(settings.GROQ_API_KEY),
        "ollama": ollama_fallback_available(),
    }
    selection = global_runtime_model_spec()
    available = selection is not None
    active_provider, active_model = selection or (None, None)
    
    hint = None
    if not available:
        hint = (
            "Set a supported cloud LLM API key in .env, "
            "or enable local Ollama with COMPOSE_PROFILES=ollama, then restart the backend."
        )
    elif active_provider == "ollama":
        hint = (
            "Running on local Ollama. Add cloud API keys anytime for higher-quality models; "
            "if those keys run out of credits, the agent will keep working on Ollama."
        )

    return {
        "available": available,
        "provider": active_provider,
        "model": active_model,
        "providers_configured": configured,
        "resilient_fallback": True,
        "hint": hint,
        "max_iterations": settings.AGENT_MAX_ITERATIONS if available else None,
        "request_timeout_seconds": _run_timeout_s(),
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


@router.get("/pilot/status")
async def get_pilot_status(current_user: User = Depends(get_current_user)):
    """Report bounded-pilot launch readiness without exposing the egress IP."""
    import ipaddress

    del current_user
    from app.services.agent.pilot_policy import configured_egress_ip
    raw_ip = configured_egress_ip()
    try:
        egress_ready = bool(ipaddress.ip_address(raw_ip).is_global)
    except ValueError:
        egress_ready = False
    redis_ready = False
    try:
        import redis

        client = redis.Redis.from_url(
            os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            socket_connect_timeout=1, socket_timeout=2,
        )
        redis_ready = bool(await asyncio.to_thread(client.ping))
    except Exception:
        pass
    return {
        "ready": egress_ready and redis_ready,
        "egress_ready": egress_ready,
        "redis_ready": redis_ready,
        "max_requests": 500,
        "requests_per_second": 1,
        "duration_seconds": 7200,
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


@router.get("/conversations/{session_id}/ledger")
async def get_conversation_ledger(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return persisted run receipts while a hunt is active or after it ends."""
    conv = db.query(AgentConversation).filter(
        AgentConversation.session_id == session_id,
        AgentConversation.user_id == current_user.id,
    ).first()
    from app.services.agent.action_ledger import latest_run

    org_id = conv.organization_id if conv else _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(status_code=404, detail="Run not found")
    run = latest_run(
        db, session_id=session_id,
        organization_id=org_id, user_id=current_user.id,
    )
    if not conv and not run:
        raise HTTPException(status_code=404, detail="Run not found")
    result = run or {"run_id": None, "status": "not_started", "actions": [],
                     "coverage": {"actions": 0, "by_status": {}, "published_findings": 0}}
    from app.services.agent.run_snapshot import load_run_snapshot
    from app.services.agent.scenario_surface import project_scenario_surface

    snapshot = load_run_snapshot(org_id, session_id)
    result["scenario_surface"] = project_scenario_surface(
        snapshot.get("capability_map"), snapshot.get("engagement_brain"),
    )
    return result


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

    from app.services.agent.run_control import has_running_task
    if has_running_task(session_id):
        raise HTTPException(status_code=409, detail="Stop the active assessment before deleting its work record")

    from app.models.agent_run_ledger import AgentActionReceipt, AgentHypothesisCoverage, AgentRunLedger

    active_record = db.query(AgentRunLedger).filter(
        AgentRunLedger.session_id == session_id,
        AgentRunLedger.organization_id == conv.organization_id,
        AgentRunLedger.user_id == current_user.id,
        AgentRunLedger.status == "running",
        AgentRunLedger.ended_at.is_(None),
    ).first()
    if active_record and (active_record.deadline_at is None or
                          active_record.deadline_at > datetime.utcnow()):
        raise HTTPException(status_code=409, detail="Stop the active assessment before deleting its work record")

    run_ids = [row.id for row in db.query(AgentRunLedger.id).filter(
        AgentRunLedger.session_id == session_id,
        AgentRunLedger.organization_id == conv.organization_id,
        AgentRunLedger.user_id == current_user.id,
    ).all()]
    if run_ids:
        db.query(AgentActionReceipt).filter(AgentActionReceipt.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(AgentHypothesisCoverage).filter(AgentHypothesisCoverage.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(AgentRunLedger).filter(AgentRunLedger.id.in_(run_ids)).delete(synchronize_session=False)
    db.delete(conv)
    db.commit()
    from app.services.agent.evidence_store import purge_session_evidence
    from app.services.agent.session_runtime import clear_session_runtime
    from importlib import import_module

    purge_session_evidence(conv.organization_id, session_id)
    agent_module = import_module("app.services.agent.orchestrator")
    active_orchestrator = getattr(agent_module, "_orchestrator", None)
    manager = getattr(active_orchestrator, "tool_manager", None)
    if manager is not None:
        clear_session_runtime(manager, conv.organization_id, session_id)
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
    
    async def connect(self, websocket: WebSocket, session_id: str, *, accepted: bool = False):
        if not accepted:
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


ws_manager = WebSocketManager()


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
    await websocket.accept()

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
        db = SessionLocal()
        try:
            existing = db.query(AgentConversation).filter_by(session_id=session_id).first()
            session_owned = existing is None or (
                existing.user_id == user.id and existing.organization_id == org_id
            )
        finally:
            db.close()
        if not session_owned:
            await websocket.send_json({"type": "error", "message": "Agent session belongs to another user or organization"})
            await websocket.close(code=4003)
            return
        if session_id in ws_manager.active_connections:
            await websocket.send_json({"type": "error", "message": "Agent session already connected"})
            await websocket.close(code=4009)
            return
        await ws_manager.connect(websocket, session_id, accepted=True)
        user_id = user.id
        authenticated = True
        await websocket.send_json({"type": "authenticated", "user_id": user_id})

        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")
            
            if msg_type == "init":
                token = data.get("token", "")
                next_user, next_org_id = _authenticate_ws_token(token)
                if not next_user or next_user.id != user_id or next_org_id != org_id:
                    await websocket.send_json({"type": "error", "message": "Authentication failed"})
                    continue
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
                if mode not in ("assist", "agent", "pilot"):
                    await websocket.send_json({"type": "error", "message": "Invalid agent mode"})
                    continue
                db_check = SessionLocal()
                try:
                    _check_pilot_session(db_check, session_id, user_id, mode)
                except HTTPException as exc:
                    await websocket.send_json({"type": "error", "message": exc.detail})
                    continue
                finally:
                    db_check.close()
                try:
                    pilot_config = _pilot_launch_config(
                        data.get("pilot"), org_id, session_id,
                    ) if mode == "pilot" else None
                except HTTPException as exc:
                    await websocket.send_json({"type": "error", "message": exc.detail})
                    continue
                load_session_id = data.get("load_session_id") or None
                assessment_policy = None
                if data.get("assessment_policy") is not None:
                    if mode == "pilot":
                        await websocket.send_json({
                            "type": "error", "message": "Bounded pilot does not accept an assessment policy",
                        })
                        continue
                    try:
                        assessment_policy = AgentAssessmentPolicy.model_validate(
                            data["assessment_policy"]
                        ).model_dump()
                    except Exception:
                        await websocket.send_json({
                            "type": "error", "message": "Invalid bounded assessment policy",
                        })
                        continue
                if pilot_config is not None:
                    try:
                        question = _pilot_question(question, pilot_config, playbook_id, load_session_id)
                    except HTTPException as exc:
                        await websocket.send_json({"type": "error", "message": exc.detail})
                        continue
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

                # Persist the session before invoking so the authenticated
                # ledger endpoint can show live receipts during a WebSocket run.
                saved = _save_conversation(None, session_id, user_id, org_id,
                                           "user", question, mode=mode)
                if pilot_config is not None and not saved:
                    await websocket.send_json({"type": "error", "message": "Pilot session could not be persisted"})
                    continue

                async def _run_query(
                    q=question,
                    todos=initial_todos,
                    run_mode=mode,
                    load_id=load_session_id,
                    limit=price_limit_usd,
                    policy=assessment_policy,
                    pilot=pilot_config,
                ):
                    try:
                        orchestrator = await get_agent_orchestrator(initialize=False)
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
                                assessment_policy=policy,
                                pilot_config=pilot,
                            ),
                            timeout=_run_timeout_s(),
                        )
                        await finish_result(result, mode=run_mode)
                    except asyncio.CancelledError:
                        await emit_cancelled()
                    except asyncio.TimeoutError:
                        logger.warning(f"WS agent query timed out after {_run_timeout_s()}s for session {session_id}")
                        await finish_result(_timeout_result(session_id, org_id, user_id),
                                            mode=run_mode)
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
                            timeout=_run_timeout_s(),
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
                            timeout=_run_timeout_s(),
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
        if ws_manager.active_connections.get(session_id) is websocket:
            _stop_agent_session(session_id)
            ws_manager.disconnect(session_id)
        logger.info(f"WebSocket disconnected: {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if ws_manager.active_connections.get(session_id) is websocket:
            _stop_agent_session(session_id)
            ws_manager.disconnect(session_id)
