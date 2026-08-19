"""
Agent Orchestrator

ReAct-style agent orchestrator for security analysis and autonomous assessment.
Uses LangGraph for state management and LangChain for LLM interactions.
Supports WebSocket streaming callbacks and cross-session learning via EvoGraph.
"""

import json
import logging
import re
import time
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable, Awaitable

from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

# Conditionally import Anthropic
try:
    from langchain_anthropic import ChatAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    ChatAnthropic = None

from contextvars import ContextVar

from app.core.config import settings
from app.services.agent.state import (
    AgentState,
    InvokeResponse,
    ExecutionStep,
    TargetInfo,
    PhaseTransitionRequest,
    PhaseHistoryEntry,
    LLMDecision,
    OutputAnalysis,
    ExtractedTargetInfo,
    UserQuestionRequest,
    QAHistoryEntry,
    ConversationObjective,
    ObjectiveOutcome,
    TodoItem,
    format_todo_list,
    format_execution_trace,
    format_qa_history,
    format_objective_history,
    summarize_trace_for_response,
    migrate_legacy_objective,
    utc_now,
)
from app.services.agent.prompts import (
    REACT_SYSTEM_PROMPT,
    OUTPUT_ANALYSIS_PROMPT,
    PHASE_TRANSITION_MESSAGE,
    USER_QUESTION_MESSAGE,
    FINAL_REPORT_PROMPT,
    get_phase_tools,
    is_tool_allowed_in_phase,
    TOOL_PHASE_MAP,
)
from app.services.agent.tools import ASMToolsManager, set_tenant_context
from app.services.agent.model_router import LLMTask
from app.services.agent.confirmation_service import set_autonomous_mode
from app.services.agent import evograph
from app.services.agent.tool_selector import get_tool_recommendations

logger = logging.getLogger(__name__)

# Type alias for the optional WebSocket status callback
StatusCallback = Optional[Callable[[Dict[str, Any]], Awaitable[None]]]

# Per-request status callback stored in a ContextVar for thread/task safety.
# This avoids the race condition of storing it as instance state on the singleton.
_max_iterations_var: ContextVar[Optional[int]] = ContextVar('_max_iterations_var', default=None)
_status_callback_var: ContextVar[StatusCallback] = ContextVar('_status_callback_var', default=None)
# Monotonic wall-clock deadline (time.monotonic() seconds) for the current turn.
# Set at the start of every invoke/resume so the ReAct loop stops picking new
# tools once the budget is spent, and so a single tool call can be bounded by the
# remaining budget. None means "no deadline" (falls back to iteration cap only).
_turn_deadline_var: ContextVar[Optional[float]] = ContextVar('_turn_deadline_var', default=None)

# Global checkpointer for session persistence.
# NOTE: MemorySaver stores all checkpoints in-memory. For production deployments
# with many sessions, replace with a persistent checkpointer (e.g. PostgresSaver
# from langgraph-checkpoint-postgres, or RedisSaver) to avoid unbounded memory
# growth and to survive backend restarts.
# See: https://langchain-ai.github.io/langgraph/concepts/persistence/
checkpointer = MemorySaver()


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def json_dumps_safe(obj, **kwargs):
    """JSON dumps with datetime support."""
    return json.dumps(obj, cls=DateTimeEncoder, **kwargs)


# Keys whose values are credentials/secrets and must never be persisted to the
# execution trace or streamed to the UI (e.g. when the operator hands the agent
# login creds via ask_user, or passes them inline to execute_deep_crawl).
_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token",
    "refresh_token", "authorization", "cookie", "cookies", "storage_state",
    "local_storage", "api_key", "apikey", "x-api-key", "username", "user",
    "email", "basic_auth",
}
# Values with these prefixes are *references*, not the secret itself, so they're
# safe to keep visible (they help the operator see where a cred came from).
_SAFE_REF_PREFIXES = ("env:", "secret:", "file:")
_REDACTED = "***REDACTED***"


def _mask_value(v):
    if isinstance(v, str) and v.startswith(_SAFE_REF_PREFIXES):
        return v
    return _REDACTED


def _redact_struct(obj):
    """Recursively redact sensitive values in a parsed dict/list structure."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in _SENSITIVE_KEYS:
                out[k] = _mask_value(v) if isinstance(v, str) else _REDACTED
            else:
                out[k] = _redact_struct(v)
        return out
    if isinstance(obj, list):
        return [_redact_struct(x) for x in obj]
    return obj


def redact_tool_args(tool_args):
    """
    Return a copy of tool_args safe to persist/stream — credentials removed.

    Handles both nested dicts and the common case where args ride inside a JSON
    string (e.g. execute_deep_crawl(args='{"login": {"password": "..."}}')).
    """
    if not isinstance(tool_args, dict):
        return tool_args
    out = {}
    for k, v in tool_args.items():
        # Sensitive top-level key (cookies, storage_state, basic_auth, …) —
        # redact wholesale regardless of value type.
        if str(k).lower() in _SENSITIVE_KEYS:
            out[k] = _mask_value(v) if isinstance(v, str) else _REDACTED
            continue
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("{") and any(
                sk in s.lower()
                for sk in ("password", "login", "authorization", "cookie", "token", "storage_state", "secret")
            ):
                try:
                    out[k] = json.dumps(_redact_struct(json.loads(s)))
                    continue
                except Exception:
                    pass
            out[k] = v
        else:
            out[k] = _redact_struct(v)
    return out


class AgentOrchestrator:
    """
    ReAct-style agent orchestrator for security analysis.
    
    Implements the Thought-Tool-Output pattern with:
    - Phase tracking (Informational → Exploitation → Post-Exploitation)
    - LLM-managed todo lists
    - Checkpoint-based approval for phase transitions
    - Full execution trace in memory
    - WebSocket streaming callbacks for real-time UI updates
    - Cross-session learning via EvoGraph (Neo4j)
    
    Supports multiple LLM providers:
    - OpenAI (GPT-4, GPT-4o, etc.)
    - Anthropic (Claude 3.5 Sonnet, Claude 3 Opus, etc.)
    """
    
    def __init__(self):
        """Initialize the orchestrator."""
        self.llm: Optional[BaseChatModel] = None
        self.tool_manager: Optional[ASMToolsManager] = None
        self.graph = None
        self._initialized = False
        self._provider = None
    
    async def initialize(self) -> None:
        """Initialize all components asynchronously."""
        if self._initialized:
            logger.warning("Orchestrator already initialized")
            return
        
        logger.info("Initializing AgentOrchestrator...")
        
        # Check for available API keys / local Ollama so the product can run
        # even when a customer's preferred cloud provider has no credits.
        from app.services.agent.model_router import ollama_fallback_available

        has_openai = bool(settings.OPENAI_API_KEY)
        has_anthropic = bool(settings.ANTHROPIC_API_KEY)
        has_ollama = ollama_fallback_available()
        
        if not has_openai and not has_anthropic and not has_ollama:
            logger.warning(
                "No AI API key configured and Ollama is not reachable — AI agent will not function"
            )
            return
        
        self._setup_llm()
        # Cascade to other cloud keys / Ollama when preferred provider is out of credits.
        try:
            from app.services.agent.model_router import _attach_credit_fallback
            if self.llm is not None and self._provider:
                self.llm = _attach_credit_fallback(
                    self.llm,
                    self._provider,
                    temperature=0,
                    max_tokens=settings.AGENT_MAX_OUTPUT_TOKENS,
                    timeout=120,
                    max_retries=2,
                    model=getattr(settings, f"{self._provider.upper()}_MODEL", None),
                )
        except Exception:
            logger.debug("Could not attach resilient LLM fallback to default LLM", exc_info=True)
        self._setup_tools()
        self._build_graph()
        self._initialized = True
        
        logger.info(f"AgentOrchestrator initialized successfully with {self._provider} provider")
    
    def _setup_llm(self) -> None:
        """Initialize the LLM based on configuration."""
        provider = settings.AI_PROVIDER.lower()
        
        # Auto-detect provider if not explicitly set or if configured provider is unavailable
        if provider == "anthropic" and settings.ANTHROPIC_API_KEY:
            self._setup_anthropic()
        elif provider == "openai" and settings.OPENAI_API_KEY:
            self._setup_openai()
        elif settings.ANTHROPIC_API_KEY:
            # Fallback to Anthropic if available
            self._setup_anthropic()
        elif settings.OPENAI_API_KEY:
            # Fallback to OpenAI if available
            self._setup_openai()
        else:
            # Last resort: local Ollama so the product still boots without cloud keys
            from app.services.agent.model_router import (
                build_ollama_chat_model,
                ollama_fallback_available,
                _ollama_fallback_model_name,
            )
            if not ollama_fallback_available():
                raise ValueError("No valid AI provider configuration found")
            self.llm = build_ollama_chat_model(
                temperature=0,
                max_tokens=settings.AGENT_MAX_OUTPUT_TOKENS,
                timeout=120,
                max_retries=2,
            )
            self._provider = "ollama"
            logger.info(
                "Setting up Ollama LLM (no cloud keys): %s",
                _ollama_fallback_model_name(),
            )
    
    def _setup_openai(self) -> None:
        """Initialize OpenAI LLM."""
        logger.info(f"Setting up OpenAI LLM: {settings.OPENAI_MODEL} (max_tokens={settings.AGENT_MAX_OUTPUT_TOKENS})")
        self.llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            api_key=settings.OPENAI_API_KEY,
            temperature=0,
            max_tokens=settings.AGENT_MAX_OUTPUT_TOKENS,
            timeout=120,
            max_retries=2,
        )
        self._provider = "openai"
    
    def _setup_anthropic(self) -> None:
        """Initialize Anthropic/Claude LLM. Uses ANTHROPIC_API_KEY from env so the SDK sends it unchanged."""
        import os
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("langchain-anthropic is not installed. Run: pip install langchain-anthropic")
        
        key = settings.ANTHROPIC_API_KEY or ""
        key = (key.strip() if isinstance(key, str) else "").strip()
        if not key:
            raise ValueError("ANTHROPIC_API_KEY is empty. Set it in .env with a key from https://console.anthropic.com (API Keys), not a Cursor/Claude Code key.")
        if not key.startswith("sk-ant-"):
            logger.warning(
                "ANTHROPIC_API_KEY does not start with 'sk-ant-'. "
                "Use an API key from https://console.anthropic.com (API Keys); "
                "keys from Cursor/Claude Code are not valid for this API."
            )
        # Let the SDK read the key from env (avoids any encoding/quoting issues from passing it in code)
        os.environ["ANTHROPIC_API_KEY"] = key
        logger.info(f"Setting up Anthropic LLM: {settings.ANTHROPIC_MODEL} (max_tokens={settings.AGENT_MAX_OUTPUT_TOKENS})")
        self.llm = ChatAnthropic(
            model=settings.ANTHROPIC_MODEL,
            temperature=0,
            max_tokens=settings.AGENT_MAX_OUTPUT_TOKENS,
            timeout=120,
            max_retries=2,
        )
        self._provider = "anthropic"

    def _resolve_llm(self, state: AgentState, task: str) -> BaseChatModel:
        """Resolve the chat model for ``task`` using the caller's org config.

        Reads only ``organization_id`` from state — the resolved API key stays
        local to this call and is never written back into agent state. Falls
        back to the process default ``self.llm`` if per-org resolution fails so
        the agent never hard-breaks on a misconfigured tenant.
        """
        org_id = state.get("organization_id")
        try:
            from app.db.database import SessionLocal
            from app.services.agent.model_router import get_llm_for_task

            db = SessionLocal()
            try:
                return get_llm_for_task(
                    db, org_id, task,
                    temperature=0,
                    max_tokens=settings.AGENT_MAX_OUTPUT_TOKENS,
                    timeout=120,
                    max_retries=2,
                )
            finally:
                db.close()
        except Exception:
            logger.warning(
                "Per-task LLM resolution failed for org=%s task=%s; using default provider",
                org_id, task, exc_info=True,
            )
            return self.llm

    def _setup_tools(self) -> None:
        """Set up ASM tools for the agent."""
        self.tool_manager = ASMToolsManager()
        logger.info(f"Tools initialized: {len(self.tool_manager.get_all_tools())} available")
    
    def _build_graph(self) -> None:
        """Build the ReAct LangGraph."""
        logger.info("Building ReAct LangGraph...")
        
        builder = StateGraph(AgentState)
        
        # Add nodes
        builder.add_node("initialize", self._initialize_node)
        builder.add_node("think", self._think_node)
        builder.add_node("execute_tool", self._execute_tool_node)
        builder.add_node("analyze_output", self._analyze_output_node)
        builder.add_node("await_approval", self._await_approval_node)
        builder.add_node("process_approval", self._process_approval_node)
        builder.add_node("await_question", self._await_question_node)
        builder.add_node("process_answer", self._process_answer_node)
        builder.add_node("generate_response", self._generate_response_node)
        
        # Entry point
        builder.add_edge(START, "initialize")
        
        # Route after initialize
        builder.add_conditional_edges(
            "initialize",
            self._route_after_initialize,
            {
                "process_approval": "process_approval",
                "process_answer": "process_answer",
                "think": "think",
            }
        )
        
        # Main routing from think node
        builder.add_conditional_edges(
            "think",
            self._route_after_think,
            {
                "execute_tool": "execute_tool",
                "await_approval": "await_approval",
                "await_question": "await_question",
                "generate_response": "generate_response",
            }
        )
        
        # Tool execution flow
        builder.add_edge("execute_tool", "analyze_output")
        
        # After analysis, continue or end
        builder.add_conditional_edges(
            "analyze_output",
            self._route_after_analyze,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )
        
        # Approval flow
        builder.add_edge("await_approval", END)
        builder.add_conditional_edges(
            "process_approval",
            self._route_after_approval,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )
        
        # Q&A flow
        builder.add_edge("await_question", END)
        builder.add_conditional_edges(
            "process_answer",
            self._route_after_answer,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )
        
        # Final response ends
        builder.add_edge("generate_response", END)
        
        self.graph = builder.compile(checkpointer=checkpointer)
        logger.info("ReAct LangGraph compiled")
    
    # =========================================================================
    # STREAMING HELPERS
    # =========================================================================

    async def _emit_status(self, msg: Dict[str, Any]) -> None:
        """Send a status update to the WebSocket callback if one is registered."""
        callback = _status_callback_var.get(None)
        if callback:
            try:
                await callback(msg)
            except Exception:
                logger.debug("Status callback failed", exc_info=True)

    # =========================================================================
    # TURN WALL-CLOCK BUDGET
    # =========================================================================

    def _start_turn_deadline(self) -> None:
        """Arm the per-turn wall-clock budget for the current invoke/resume.

        The deadline lives in a ContextVar so the sync routing functions and the
        tool-execution node can read it without threading it through LangGraph
        state (which isn't populated on resume paths).
        """
        budget = getattr(settings, "AGENT_TURN_BUDGET_SECONDS", 0) or 0
        if budget > 0:
            _turn_deadline_var.set(time.monotonic() + float(budget))
        else:
            _turn_deadline_var.set(None)

    def _turn_time_remaining(self) -> Optional[float]:
        """Seconds left in the turn budget, or None when no budget is armed."""
        deadline = _turn_deadline_var.get(None)
        if deadline is None:
            return None
        return deadline - time.monotonic()

    def _turn_budget_exceeded(self) -> bool:
        """True once the turn wall-clock budget has been spent."""
        remaining = self._turn_time_remaining()
        return remaining is not None and remaining <= 0

    def _unavailable_tools_note(self) -> str:
        """Prompt block listing execute_* tools whose binary isn't installed here.

        Steers the LLM away from tools that can only return "Command not found",
        so a worker with a partial toolset still makes progress with what it has
        (many web checks are pure-Python and need no external binary). Cached per
        process since installed binaries don't change at runtime.
        """
        cached = getattr(self, "_unavailable_tools_note_cache", None)
        if cached is not None:
            return cached
        note = ""
        try:
            mcp = self.tool_manager._get_mcp_server() if self.tool_manager else None
            missing = mcp.unavailable_tools() if mcp else []
        except Exception:
            missing = []
        if missing:
            note = (
                "\n\n## Tools UNAVAILABLE on this worker — do NOT call these "
                "(the binary is not installed; they will fail):\n"
                + ", ".join(missing)
                + "\nMany web checks need no external binary and remain available: "
                "bypass_403, replay_http_request, compare_requests, discover_parameters, "
                "scan_js_urls_for_secrets, the test_* probes, and the query_* DB tools. "
                "Prefer those over an unavailable scanner."
            )
        self._unavailable_tools_note_cache = note
        return note

    # =========================================================================
    # LANGGRAPH NODES
    # =========================================================================
    
    async def _initialize_node(self, state: AgentState, config=None) -> dict:
        """Initialize state for new conversation."""
        user_id = state.get("user_id", "unknown")
        org_id = state.get("organization_id")
        session_id = state.get("session_id", "unknown")
        
        logger.info(f"[{user_id}/{session_id}] Initializing state...")
        
        # Migrate legacy state if needed
        state = migrate_legacy_objective(state)
        
        # If resuming after approval/answer, preserve state
        if state.get("user_approval_response") and state.get("phase_transition_pending"):
            return {}
        
        if state.get("user_question_answer") and state.get("pending_question"):
            return {}
        
        # Extract latest user message
        messages = state.get("messages", [])
        latest_message = ""
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage):
                latest_message = msg.content
                break
        
        # Initialize conversation objectives
        objectives = state.get("conversation_objectives", [])
        if not objectives and latest_message:
            objectives = [ConversationObjective(content=latest_message).model_dump()]
        
        todo_list = state.get("initial_todos") if state.get("initial_todos") else []
        mode = state.get("mode") or "assist"

        # Seed primary_target from the user's message so execute_* can recover
        # when the LLM omits tool_args.args (common empty-{} failure loop).
        target_info = TargetInfo().model_dump()
        kickoff_brief = ""
        seed = None
        try:
            from app.services.agent.tools import extract_seed_target, set_seed_target
            seed = extract_seed_target(latest_message)
            if seed:
                target_info["primary_target"] = seed
                set_seed_target(seed)
                try:
                    self.tool_manager._fallback_target = seed
                except Exception:
                    pass
        except Exception:
            pass

        # Fast parallel probes + early Interceptor queue so crawl starts while
        # the LLM plans. execute_interceptor later attaches to the same job_id.
        # Also spawn Copilot-style recon streams (httpx/waf/whatweb) in background.
        execution_trace: list = []
        interceptor_job_id: Optional[str] = None
        recon_worker_briefs: List[str] = []
        if seed:
            session_id = state.get("session_id")
            org_id = state.get("organization_id")
            uid_raw = state.get("user_id")
            try:
                uid_int = int(uid_raw) if uid_raw is not None and str(uid_raw).isdigit() else None
            except Exception:
                uid_int = None
            try:
                from app.services.agent.assessment_kickoff import run_assessment_kickoff
                from app.services.interceptor_service import queue_early_pentester_crawl
                from app.services.agent import recon_workers

                kickoff_coro = run_assessment_kickoff(seed)
                queue_coro = queue_early_pentester_crawl(
                    seed,
                    session_id=session_id,
                    organization_id=org_id,
                )
                streams_coro = recon_workers.spawn_workers(
                    url=seed,
                    session_id=str(session_id or ""),
                    pack="early",
                    tools_manager=self.tool_manager,
                    user_id=uid_int,
                    organization_id=org_id if isinstance(org_id, int) else None,
                )
                kickoff, queued, streams = await asyncio.wait_for(
                    asyncio.gather(
                        kickoff_coro, queue_coro, streams_coro, return_exceptions=True
                    ),
                    timeout=28.0,
                )
                if isinstance(kickoff, Exception):
                    logger.warning("assessment kickoff failed: %s", kickoff)
                    kickoff = {}
                if isinstance(queued, Exception):
                    logger.warning("early interceptor queue failed: %s", queued)
                    queued = {}
                if isinstance(streams, Exception):
                    logger.warning("early recon streams failed: %s", streams)
                    streams = []

                kickoff_brief = (kickoff or {}).get("brief") or ""
                if isinstance(queued, dict) and queued.get("job_id"):
                    interceptor_job_id = str(queued["job_id"])
                    qnote = (
                        f"\n  Interceptor: early-queued job {interceptor_job_id[:8]}… "
                        f"({queued.get('note')}; online={queued.get('online')}). "
                        "Call execute_interceptor next — it will attach, not start a second crawl."
                    )
                    kickoff_brief = (kickoff_brief + qnote) if kickoff_brief else qnote.strip()
                elif isinstance(queued, dict) and queued.get("note") == "no_workers_online":
                    qnote = (
                        "\n  Interceptor: no Mac/Ubuntu workers online yet — "
                        "execute_interceptor will use local CLI or deep_crawl fallback."
                    )
                    kickoff_brief = (kickoff_brief + qnote) if kickoff_brief else qnote.strip()

                if isinstance(streams, list) and streams:
                    kinds = ", ".join(
                        f"{s.get('kind')}({s.get('note')})" for s in streams if isinstance(s, dict)
                    )
                    snote = (
                        f"\n  Parallel recon streams (running): {kinds}. "
                        "Results inject automatically; use wait_recon_workers or "
                        "spawn_recon_workers(pack='enrich') for ferox/katana."
                    )
                    kickoff_brief = (kickoff_brief + snote) if kickoff_brief else snote.strip()

                if kickoff_brief:
                    next_steps = [
                        "execute_interceptor (attaches to early job if queued)",
                        "spawn_recon_workers(pack='enrich') for ferox+katana streams",
                        "ingest_urls_into_map → sync_engagement_brain",
                    ]
                    execution_trace.append(
                        ExecutionStep(
                            iteration=0,
                            phase="informational",
                            thought="Automatic kickoff + Interceptor queue + recon streams",
                            reasoning="Surface signal + parallel streams while LLM plans",
                            tool_name="assessment_kickoff",
                            tool_args={
                                "url": seed,
                                "interceptor_job_id": interceptor_job_id,
                                "streams": streams if isinstance(streams, list) else [],
                            },
                            tool_output=kickoff_brief,
                            success=bool((kickoff or {}).get("success")) or bool(interceptor_job_id),
                            actionable_findings=[
                                "Attach via execute_interceptor"
                                if interceptor_job_id
                                else "Start execute_interceptor next"
                            ],
                            recommended_next_steps=next_steps,
                        ).model_dump()
                    )
            except Exception as e:
                logger.warning("assessment kickoff skipped: %s", e)
                kickoff_brief = ""
        
        return {
            "current_iteration": 0,
            "max_iterations": _max_iterations_var.get(None) or settings.AGENT_MAX_ITERATIONS,
            "task_complete": False,
            "current_phase": "informational",
            "phase_history": [PhaseHistoryEntry(phase="informational").model_dump()],
            "execution_trace": execution_trace,
            "todo_list": todo_list,
            "conversation_objectives": objectives,
            "current_objective_index": 0,
            "objective_history": [],
            "original_objective": latest_message,
            "target_info": target_info,
            "capability_map": None,
            "auth_session": None,
            "engagement_brain": None,
            "kickoff_brief": kickoff_brief or None,
            "interceptor_job_id": interceptor_job_id,
            "recon_worker_briefs": recon_worker_briefs,
            "awaiting_user_approval": False,
            "phase_transition_pending": None,
            "qa_history": [],
            "mode": mode,
        }
    
    def _wordpress_hunt_note(self, state: AgentState) -> str:
        """When WordPress is fingerprinted, force the high-value WP surfaces
        that a human tester (and Claude) hits immediately: WPScan, REST user
        enum, login oracle, admin-ajax injection. Returns empty when WP is
        not in play."""
        tech = " ".join(
            str(t).lower()
            for t in (state.get("target_info", {}) or {}).get("technologies", [])
        )
        blob = tech
        for s in state.get("execution_trace", []) or []:
            blob += " " + str(s.get("tool_output") or "").lower()[:400]
            blob += " " + str(s.get("thought") or "").lower()[:200]
        if "wordpress" not in blob and "wp-content" not in blob and "wp-json" not in blob:
            return ""

        ran = {s.get("tool_name") for s in (state.get("execution_trace") or []) if s.get("tool_name")}
        origin = ((state.get("target_info") or {}).get("primary_target") or "").rstrip("/")
        url = origin or "https://TARGET"

        lines = [
            "\n\n## WordPress detected — hunt these surfaces NOW",
            "WPScan is OPTIONAL (known CVEs / plugin list). Do not wait on it, "
            "and do not retry it. Claude-style findings on WordPress come from "
            "REST user enum + admin-ajax time-based SQLi, not from WPScan.",
        ]
        lines.append(
            f"1. Unauth REST user enum FIRST: execute_curl(args=\"-sS -D- {url}/wp-json/wp/v2/users?per_page=100\"). "
            "A 200 with slug/name is a finding (user enumeration). Then create_finding "
            "with title/description/severity/target filled in."
        )
        lines.append(
            f"2. Time-based SQLi PoC (do this even if WPScan failed). "
            f"compare_requests on POST {url}/wp-admin/admin-ajax.php with "
            "Content-Type: application/x-www-form-urlencoded. "
            "baseline body: action=loadmore&page=1&query={{\"tax_query\":{{\"0\":{{\"terms\":[\"1\"]}}}}}} "
            "mutant body: same but terms=[\"1) AND (SELECT 1 FROM (SELECT SLEEP(2))x)-- -\"]. "
            "timeout=20. If elapsed_s delta ≥ 1.5s (TIME_BASED_INJECTION_CANDIDATE), "
            "repeat with SLEEP(4) then execute_sqlmap --technique=BT and create_finding "
            "with the timing table as evidence."
        )
        lines.append(
            f"3. Login oracle (ONE attempt per username, no brute force): POST {url}/wp-login.php "
            "and compare 'not registered' vs 'password you entered for the username X is incorrect'."
        )
        if "execute_wpscan" not in ran:
            lines.append(
                "4. OPTIONAL later: execute_wpscan for plugin CVE mapping. Skip if it aborted "
                "(token/quota). Do not block the ajax/REST hunts on WPScan."
            )
        else:
            lines.append(
                "4. WPScan already ran or aborted — do NOT call it again. Continue ajax/REST."
            )
        return "\n".join(lines)

    def _repetition_guard_note(self, state: AgentState, phase: str) -> str:
        """Detect an unproductive loop — the model re-running the same tool over
        and over without surfacing anything new — and steer it toward a
        different, higher-value action. Returns a prompt block (empty string
        when no loop is detected).

        This is a soft steer (prompt-level), matching how the rest of the loop
        is guided; it does not hard-override the model's choice, because the
        same tool against *different* inputs (e.g. compare_requests on distinct
        endpoints) is legitimate.
        """
        trace = state.get("execution_trace", []) or []
        recent = [s for s in trace[-8:] if s.get("tool_name")]
        if len(recent) < 3:
            return ""

        from collections import Counter

        counts = Counter(s.get("tool_name") for s in recent)
        tool, n = counts.most_common(1)[0]
        if n < 3:
            return ""

        # Did those repeats produce anything actionable? If so, it's productive
        # work, not a stuck loop — leave it alone.
        produced = any(
            s.get("tool_name") == tool
            and (s.get("actionable_findings") or s.get("output_analysis"))
            for s in recent
        )
        if produced and n < 5:
            return ""

        ran = {s.get("tool_name") for s in trace if s.get("tool_name")}
        tech = " ".join(
            str(t).lower()
            for t in (state.get("target_info", {}) or {}).get("technologies", [])
        )
        cmap = state.get("capability_map") or {}

        suggestions: List[str] = []
        if "wordpress" in tech and "execute_wpscan" not in ran:
            suggestions.append(
                "run execute_wpscan (WordPress detected — enumerate plugins, "
                "themes, users, and known CVEs)"
            )
        if "fireteam_dispatch" not in ran and cmap.get("ready_for_attack"):
            suggestions.append(
                "dispatch fireteam_dispatch(specialists='auto') to hunt the "
                "capability-map surfaces with specialists"
            )
        if "execute_nuclei" not in ran:
            suggestions.append(
                "run execute_nuclei for template-based vulnerability detection"
            )
        if "execute_cmseek" not in ran and "wordpress" not in tech:
            suggestions.append("run execute_cmseek to fingerprint the CMS")
        if not suggestions:
            suggestions.append(
                "synthesize your findings and finish (action=complete) instead "
                "of repeating tools"
            )
        alt = "; ".join(f"({i + 1}) {s}" for i, s in enumerate(suggestions))

        return (
            "\n\n## Loop detected — change your approach\n"
            f"You have run `{tool}` {n} times in the last {len(recent)} steps"
            f"{'' if produced else ' without surfacing new findings'}. "
            f"Do NOT call `{tool}` again unless you have genuinely new inputs "
            f"for it. Choose a different, higher-value action now: {alt}."
        )

    async def _think_node(self, state: AgentState, config=None) -> dict:
        """Core ReAct reasoning node."""
        user_id = state.get("user_id", "unknown")
        org_id = state.get("organization_id")
        
        iteration = state.get("current_iteration", 0) + 1
        phase = state.get("current_phase", "informational")
        
        logger.info(f"[{user_id}] Think node - iteration {iteration}, phase: {phase}")

        await self._emit_status({
            "type": "thinking",
            "iteration": iteration,
            "phase": phase,
            "thought": "Reasoning about next action...",
        })
        
        # Set tenant context for tools (including session_id for save_note/get_notes)
        session_id = state.get("session_id")
        if org_id:
            set_tenant_context(
                int(user_id) if user_id.isdigit() else 0,
                org_id,
                session_id=session_id,
            )

        # Drain completed parallel recon streams into state before the LLM thinks
        # (non-blocking collect; soft 1.5s join so fast httpx/waf results land early).
        drained_briefs: List[str] = list(state.get("recon_worker_briefs") or [])
        drain_trace_extra: list = []
        try:
            from app.services.agent import recon_workers

            soft_wait = 1.5 if iteration <= 2 else 0.0
            newly = await recon_workers.drain_completed(
                str(session_id or ""),
                wait_sec=soft_wait,
            )
            for item in newly:
                brief = (item.get("brief") or "").strip()
                if not brief:
                    continue
                drained_briefs.append(brief)
                drain_trace_extra.append(
                    ExecutionStep(
                        iteration=iteration,
                        phase=phase,
                        thought=f"Recon stream completed: {item.get('kind')}",
                        reasoning="Parallel worker result injected into context",
                        tool_name=f"recon_worker:{item.get('kind')}",
                        tool_args={"worker_id": item.get("worker_id")},
                        tool_output=brief[:8000],
                        success=item.get("status") == "completed",
                        error_message=item.get("error"),
                    ).model_dump()
                )
                await self._emit_status({
                    "type": "thinking",
                    "iteration": iteration,
                    "phase": phase,
                    "thought": f"Recon stream [{item.get('kind')}] results ready",
                })
        except Exception as drain_err:
            logger.debug("recon worker drain skipped: %s", drain_err)
        
        # Get current objective
        objectives = state.get("conversation_objectives", [])
        current_idx = state.get("current_objective_index", 0)
        current_objective = objectives[current_idx].get("content", "") if current_idx < len(objectives) else state.get("original_objective", "")
        
        # Session notes for prompt
        session_notes = (
            self.tool_manager.get_session_notes(session_id=session_id)
            if self.tool_manager else "No session notes."
        )
        
        # Palace wake-up: L0 identity + L1 critical facts (~900 tokens).
        # Full org knowledge / prior tool output is on-demand via search_memory.
        knowledge_context = ""
        if org_id:
            from app.services.agent.palace_memory import wake_up as palace_wake_up
            knowledge_context = palace_wake_up(
                org_id,
                target=str((state.get("target_info") or {}).get("primary_target") or "")
                or None,
            )
        if not knowledge_context:
            knowledge_context = "None. Use search_memory after you store results."

        # Cross-session graph summaries only when the palace is still empty.
        prior_chain_context = ""
        palace_has_drawers = "Palace has" in knowledge_context
        if org_id and session_id and not palace_has_drawers:
            prior_chain_context = evograph.get_prior_chain_context(
                organization_id=org_id,
                current_session_id=session_id,
            )

        # Build prompt
        merged_trace = list(state.get("execution_trace", []) or []) + drain_trace_extra
        execution_trace_formatted = format_execution_trace(merged_trace)
        todo_list_formatted = format_todo_list(state.get("todo_list", []))
        target_info_formatted = json_dumps_safe(state.get("target_info", {}), indent=2)
        qa_history_formatted = format_qa_history(state.get("qa_history", []))
        objective_history_formatted = format_objective_history(state.get("objective_history", []))
        available_tools = get_phase_tools(phase)
        available_tools += self._unavailable_tools_note()

        # Append prior session intelligence to knowledge context
        combined_knowledge = knowledge_context
        if prior_chain_context:
            combined_knowledge = f"{knowledge_context}\n\n{prior_chain_context}"
        kickoff_brief = (state.get("kickoff_brief") or "").strip()
        if kickoff_brief and iteration <= 2:
            combined_knowledge = (
                f"{combined_knowledge}\n\n## Kickoff recon (already ran — use this)\n{kickoff_brief}"
            )
        if drained_briefs:
            from app.services.agent.recon_workers import format_briefs_for_prompt
            # Only show the most recent briefs in the prompt (full text is in execution_trace)
            recent_for_prompt = [
                {"kind": "stream", "status": "completed", "worker_id": "cached", "brief": b}
                for b in drained_briefs[-6:]
            ]
            combined_knowledge = (
                f"{combined_knowledge}\n\n{format_briefs_for_prompt(recent_for_prompt)}"
            )

        # Auto tool recommendations based on discovered state
        target_info_raw = state.get("target_info", {})
        primary_target = target_info_raw.get("primary_target") or ""
        # Extract WAF from execution trace
        waf_detected = None
        for step in reversed(state.get("execution_trace", [])):
            if step.get("tool_name") == "execute_wafw00f" and step.get("success"):
                output = step.get("tool_output", "")
                if "is behind" in output.lower() or "detected" in output.lower():
                    waf_detected = output[:200]
                break
        # Extract discovered parameters
        discovered_params = {}
        for step in reversed(state.get("execution_trace", [])):
            if step.get("tool_name") == "discover_parameters" and step.get("success"):
                try:
                    import json as _json
                    param_data = _json.loads(step.get("tool_output", "{}"))
                    discovered_params = param_data.get("parameters", {})
                except Exception:
                    pass
                break

        tool_recommendations = ""
        if primary_target:
            tool_recommendations = get_tool_recommendations(
                target=primary_target,
                target_info=target_info_raw,
                execution_trace=state.get("execution_trace", []),
                current_phase=phase,
                parameters=discovered_params,
                waf_detected=waf_detected,
            )
        # WordPress-specific hunt: once WP is fingerprinted, do not wait for
        # methodology cards — run wpscan + REST user enum + ajax SQLi probes.
        tool_recommendations += self._wordpress_hunt_note(state)
        # Break unproductive loops: if the model has been hammering one tool
        # without new findings, steer it to a different, higher-value action.
        tool_recommendations += self._repetition_guard_note(state, phase)

        from app.services.agent.capability_map import format_capability_map_for_prompt
        from app.services.agent.engagement_brain import format_engagement_brain_for_prompt
        capability_map_formatted = format_capability_map_for_prompt(
            state.get("capability_map")
        )
        engagement_brain_formatted = format_engagement_brain_for_prompt(
            state.get("engagement_brain")
        )

        system_prompt = REACT_SYSTEM_PROMPT.format(
            current_phase=phase,
            available_tools=available_tools,
            iteration=iteration,
            max_iterations=state.get("max_iterations", settings.AGENT_MAX_ITERATIONS),
            objective=current_objective,
            objective_history_summary=objective_history_formatted,
            execution_trace=execution_trace_formatted,
            todo_list=todo_list_formatted,
            target_info=target_info_formatted,
            capability_map=capability_map_formatted,
            engagement_brain=engagement_brain_formatted,
            session_notes=session_notes,
            knowledge_context=combined_knowledge,
            qa_history=qa_history_formatted,
            tool_recommendations=tool_recommendations,
        )
        
        # Get LLM decision
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content="Based on the current state, what is your next action? Output EXACTLY ONE valid JSON object.")
        ]
        
        llm = self._resolve_llm(state, LLMTask.REASONING)
        response = await llm.ainvoke(messages)
        response_text = response.content.strip()
        
        logger.debug(f"LLM response: {response_text[:500]}...")
        
        # Parse decision
        decision = self._parse_llm_decision(response_text)
        
        logger.info(f"[{user_id}] Decision: action={decision.action}, tool={decision.tool_name}")

        await self._emit_status({
            "type": "thinking",
            "iteration": iteration,
            "phase": phase,
            "thought": decision.thought[:300],
            "action": decision.action,
            "tool_name": decision.tool_name,
        })
        
        # Fill execute_* args at decision time so empty {} never reaches the UI/gate
        tool_args_for_step = decision.tool_args if decision.action == "use_tool" else None
        if (
            decision.action == "use_tool"
            and decision.tool_name
            and decision.tool_name.startswith("execute_")
        ):
            try:
                from app.services.agent.tools import (
                    extract_seed_target,
                    normalize_execute_tool_args,
                    set_seed_target,
                )
                seed = (target_info_raw.get("primary_target") or "").strip()
                if not seed:
                    seed = extract_seed_target(
                        " ".join(
                            [
                                current_objective or "",
                                state.get("original_objective") or "",
                                decision.thought or "",
                                decision.reasoning or "",
                            ]
                        )
                    )
                if seed:
                    set_seed_target(seed)
                    try:
                        self.tool_manager._fallback_target = seed
                    except Exception:
                        pass
                tool_args_for_step = normalize_execute_tool_args(
                    decision.tool_name,
                    decision.tool_args,
                    fallback_target=seed,
                )
            except Exception as fill_err:
                logger.debug("Could not pre-fill execute args: %s", fill_err)

        # Create execution step
        step = ExecutionStep(
            iteration=iteration,
            phase=phase,
            thought=decision.thought,
            reasoning=decision.reasoning,
            tool_name=decision.tool_name if decision.action == "use_tool" else None,
            tool_args=tool_args_for_step,
        )
        
        # Update todo list
        todo_list = [item.model_dump() for item in decision.updated_todo_list] if decision.updated_todo_list else state.get("todo_list", [])
        
        updates = {
            "current_iteration": iteration,
            "todo_list": todo_list,
            "_current_step": step.model_dump(),
            "_decision": decision.model_dump(),
            "recon_worker_briefs": drained_briefs[-12:],
        }
        if drain_trace_extra:
            updates["execution_trace"] = merged_trace

        
        # Handle actions
        if decision.action == "complete":
            reason = (decision.completion_reason or "").lower()
            force_complete = (
                "force complete" in reason
                or "defer methodologies" in reason
                or "defer remaining" in reason
                or "non-browser" in reason
            )
            brain_state = state.get("engagement_brain") or {}
            cmap = state.get("capability_map") or {}
            webby = bool(cmap) or any(
                t in (state.get("objective") or "").lower()
                for t in ("http", "https", "web", "app", "url")
            )
            if webby and not force_complete:
                try:
                    from app.services.agent.engagement_brain import methodology_progress
                    progress = methodology_progress(brain_state, cmap=cmap)
                    if not progress.get("ready_to_complete"):
                        blockers = progress.get("blockers") or []
                        blocker_txt = "; ".join(
                            f"{b.get('methodology_id') or b.get('id')}: {b.get('title')}"
                            for b in blockers[:5]
                        ) or "methodology cards not seeded"
                        step.thought = (
                            (step.thought or "")
                            + " | Complete blocked — unresolved methodologies, coverage, or pending verify."
                        )
                        step.tool_name = None
                        updates["_current_step"] = step.model_dump()
                        updates["messages"] = [AIMessage(content=(
                            "Cannot complete yet — application assessment methodology incomplete.\n"
                            f"{progress.get('summary')}\n"
                            f"Blocking: {blocker_txt}\n\n"
                            "Prove or kill those cards (update_hypothesis), "
                            "independent_verify pending candidates, and "
                            "record_surface_coverage for untested inventory "
                            "(finding | tested_clean | skipped+reason), then complete. "
                            "Or set completion_reason to include 'defer methodologies' / "
                            "'force complete' if intentionally skipping."
                        ))]
                        return updates
                except Exception:
                    logger.exception("methodology complete-gate failed")
            updates["task_complete"] = True
            updates["completion_reason"] = decision.completion_reason or "Task completed"
        
        elif decision.action == "transition_phase":
            to_phase = decision.phase_transition.to_phase if decision.phase_transition else "exploitation"
            cmap = state.get("capability_map") or {}
            map_ready = bool(cmap.get("ready_for_attack"))
            reason = (
                decision.phase_transition.reason
                if decision.phase_transition
                else ""
            )
            non_browser = "non-browser" in reason.lower() or "force" in reason.lower()
            if (
                to_phase == "exploitation"
                and not map_ready
                and not non_browser
            ):
                # Keep thinking — require browser walkthrough first (tester methodology)
                step.thought = (
                    (step.thought or "")
                    + " | Capability map missing — run execute_deep_crawl before exploitation."
                )
                step.tool_name = None
                updates["_current_step"] = step.model_dump()
                updates["messages"] = [AIMessage(content=(
                    "Before transitioning to exploitation, walk the application like a tester: "
                    "call **execute_deep_crawl** on the primary URL (click links/menus), "
                    "review the capability map / methodology cards, then "
                    "**sync_engagement_brain** + **fireteam_dispatch(specialists='auto')**. "
                    "If this target is not a web app, request the transition again with reason "
                    "containing 'non-browser'."
                ))]
                return updates

            # Soft nudge: exploitation with map but no methodology cards
            brain_state = state.get("engagement_brain") or {}
            has_method_cards = any(
                (h.get("source") == "methodology") or h.get("methodology_id")
                for h in (brain_state.get("hypotheses") or [])
            ) or bool(cmap.get("methodologies"))
            if (
                to_phase == "exploitation"
                and map_ready
                and not has_method_cards
                and not non_browser
            ):
                step.thought = (
                    (step.thought or "")
                    + " | Methodology cards missing — sync_engagement_brain before exploitation spray."
                )
                step.tool_name = None
                updates["_current_step"] = step.model_dump()
                updates["messages"] = [AIMessage(content=(
                    "Capability map exists but methodology cards are not seeded. "
                    "Call **sync_engagement_brain** so observation→methodology hypotheses "
                    "(CWE/CAPEC-tagged) drive the fireteam, then transition again."
                ))]
                return updates

            if to_phase == phase:
                # Already in this phase, continue
                pass
            elif state.get("mode") == "agent":
                # Autonomous mode: apply phase transition immediately
                updates["current_phase"] = to_phase
                phase_history = state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase=to_phase).model_dump()
                ]
                updates["phase_history"] = phase_history
                updates["phase_transition_pending"] = None
                updates["awaiting_user_approval"] = False
                logger.info(f"[{user_id}] Agent mode: auto-approved transition to {to_phase}")
            else:
                # Assist mode: request approval for phase transition
                updates["phase_transition_pending"] = PhaseTransitionRequest(
                    from_phase=phase,
                    to_phase=to_phase,
                    reason=reason,
                    planned_actions=decision.phase_transition.planned_actions if decision.phase_transition else [],
                    risks=decision.phase_transition.risks if decision.phase_transition else [],
                ).model_dump()
                updates["awaiting_user_approval"] = True
        
        elif decision.action == "ask_user":
            if decision.user_question:
                updates["pending_question"] = UserQuestionRequest(
                    question=decision.user_question.question,
                    context=decision.user_question.context,
                    format=decision.user_question.format,
                    options=decision.user_question.options,
                    phase=phase,
                ).model_dump()
                updates["awaiting_user_question"] = True
        
        return updates
    
    async def _execute_tool_node(self, state: AgentState, config=None) -> dict:
        """Execute the selected tool."""
        user_id = state.get("user_id", "unknown")
        org_id = state.get("organization_id")
        session_id = state.get("session_id", "")
        
        step_data = state.get("_current_step") or {}
        tool_name = step_data.get("tool_name")
        tool_args = dict(step_data.get("tool_args") or {})
        phase = state.get("current_phase", "informational")
        iteration = state.get("current_iteration", 0)

        if not tool_name:
            step_data["tool_output"] = "Error: No tool specified"
            step_data["success"] = False
            return {"_current_step": step_data}

        # Resolve seed URL/host for execute_* arg recovery (empty tool_args loop)
        seed_target = ""
        try:
            ti = state.get("target_info") or {}
            seed_target = (ti.get("primary_target") or "").strip()
            if not seed_target:
                cmap = state.get("capability_map") or {}
                if isinstance(cmap, dict):
                    seed_target = (cmap.get("target") or "").strip()
            if not seed_target:
                from app.services.agent.tools import extract_seed_target
                seed_target = extract_seed_target(
                    state.get("original_objective") or ""
                )
        except Exception:
            seed_target = ""
        if seed_target:
            try:
                from app.services.agent.tools import set_seed_target
                set_seed_target(seed_target)
                self.tool_manager._fallback_target = seed_target
            except Exception:
                pass

        # Preview-normalize execute_* so the UI shows the real CLI args
        if tool_name.startswith("execute_"):
            from app.services.agent.tools import (
                extract_seed_target,
                normalize_execute_tool_args,
            )
            if not seed_target:
                seed_target = extract_seed_target(
                    f"{step_data.get('thought') or ''} "
                    f"{step_data.get('reasoning') or ''} "
                    f"{state.get('original_objective') or ''}"
                )
                if seed_target:
                    try:
                        from app.services.agent.tools import set_seed_target
                        set_seed_target(seed_target)
                        self.tool_manager._fallback_target = seed_target
                    except Exception:
                        pass
            tool_args = normalize_execute_tool_args(
                tool_name, tool_args, fallback_target=seed_target,
            )

        # Redacted view for streaming + trace persistence so credentials the
        # operator hands the agent (or inline login secrets) never leak into the
        # UI, execution trace, or cross-session learning store.
        safe_args = redact_tool_args(tool_args)

        logger.info(f"[{user_id}] Executing tool: {tool_name} args={safe_args}")

        await self._emit_status({
            "type": "tool_start",
            "tool_name": tool_name or "",
            "tool_args": safe_args,
            "iteration": iteration,
        })
        
        # Set tenant context (including session_id for save_note)
        if org_id:
            set_tenant_context(
                int(user_id) if user_id.isdigit() else 0,
                org_id,
                session_id=session_id,
            )
        
        # Check phase restriction. In autonomous ("agent") mode a phase transition
        # is auto-approved anyway (see _analyze_node), so when the agent reaches
        # for an active-testing tool while still in the informational phase, treat
        # it as an implicit transition and promote in place instead of returning a
        # dead-end error the model just retries (which stalls the turn). Keep the
        # "walk the app first" rule: only promote once the capability map is ready
        # (execute_deep_crawl has produced a usable map).
        auto_promoted_phase: Optional[str] = None
        if not is_tool_allowed_in_phase(tool_name, phase):
            allowed_phases = TOOL_PHASE_MAP.get(tool_name, [])
            target_phase = (
                "exploitation" if "exploitation" in allowed_phases
                else (allowed_phases[0] if allowed_phases else None)
            )
            cmap_ready = bool((state.get("capability_map") or {}).get("ready_for_attack"))
            # Fallback readiness: even without a full deep_crawl capability map, the
            # target may be well-enough characterized to begin active testing — the
            # tech stack is fingerprinted AND concrete attack surface is known
            # (parameters discovered or capabilities mapped). This keeps the "walk
            # the app first" intent (we don't promote on an empty recon) while
            # preventing the informational-phase stall where the model wants an
            # exploitation tool but a deep_crawl map never materialized.
            _cmap = state.get("capability_map") or {}
            _tech = (state.get("target_info") or {}).get("technologies") or []
            _params_found = any(
                s.get("tool_name") in ("discover_parameters", "execute_arjun")
                and s.get("success")
                for s in state.get("execution_trace", []) or []
            )
            _wp = "wordpress" in " ".join(str(t).lower() for t in _tech)
            if not _wp:
                _wp = any(
                    "wordpress" in str(s.get("tool_output") or "").lower()
                    or "wp-content" in str(s.get("tool_output") or "").lower()
                    for s in (state.get("execution_trace") or [])
                )
            recon_ready = bool(_tech) and (
                _params_found or bool(_cmap.get("capabilities"))
            ) or _wp
            if (
                state.get("mode") == "agent"
                and phase == "informational"
                and target_phase
                and (cmap_ready or recon_ready)
            ):
                logger.info(
                    "[%s] Agent mode: auto-promoting informational->%s so %s can run "
                    "(cmap_ready=%s recon_ready=%s)",
                    user_id, target_phase, tool_name, cmap_ready, recon_ready,
                )
                phase = target_phase
                auto_promoted_phase = target_phase
                await self._emit_status({
                    "type": "phase_transition",
                    "from_phase": "informational",
                    "to_phase": target_phase,
                    "reason": f"autonomous active testing ({tool_name})",
                })
            else:
                if target_phase == "exploitation" and not cmap_ready:
                    step_data["tool_output"] = (
                        f"Error: '{tool_name}' needs the exploitation phase. Run "
                        "execute_deep_crawl on the target first to build the "
                        "capability map, then retry this tool."
                    )
                else:
                    step_data["tool_output"] = (
                        f"Error: Tool '{tool_name}' not allowed in '{phase}' phase"
                    )
                step_data["success"] = False
                await self._emit_status({
                    "type": "tool_complete",
                    "tool_name": tool_name,
                    "success": False,
                    "output_summary": (step_data.get("tool_output") or "")[:300],
                    "iteration": iteration,
                })
                return {"_current_step": step_data}
        
        # Inject agent state context for auto_select_tools
        if tool_name == "auto_select_tools":
            tool_args["_target_info"] = state.get("target_info", {})
            tool_args["_execution_trace"] = state.get("execution_trace", [])
            tool_args["_current_phase"] = phase
            # Extract params and WAF from trace
            for step in reversed(state.get("execution_trace", [])):
                if step.get("tool_name") == "discover_parameters" and step.get("success"):
                    try:
                        param_data = json.loads(step.get("tool_output", "{}"))
                        tool_args["_parameters"] = param_data.get("parameters", {})
                    except Exception:
                        pass
                    break
            for step in reversed(state.get("execution_trace", [])):
                if step.get("tool_name") == "execute_wafw00f" and step.get("success"):
                    output = step.get("tool_output", "")
                    if "is behind" in output.lower() or "detected" in output.lower():
                        tool_args["_waf_detected"] = output[:200]
                    break

        # Inject session capability map + engagement brain into fireteam / brain tools
        if tool_name in (
            "fireteam_dispatch",
            "sync_engagement_brain",
            "compare_requests",
            "update_hypothesis",
            "queue_finding_followups",
            "add_engagement_credential",
            "log_engagement_approach",
            "get_engagement_brain",
            "build_threat_model",
            "get_threat_model",
            "update_threat_model",
            "submit_finding_candidate",
            "independent_verify",
            "record_verify_verdict",
            "record_surface_coverage",
            "get_coverage",
            "ingest_urls_into_map",
        ):
            if state.get("capability_map") and not tool_args.get("capability_map"):
                if tool_name in ("fireteam_dispatch", "sync_engagement_brain", "build_threat_model"):
                    tool_args["capability_map"] = state.get("capability_map")
            try:
                self.tool_manager._capability_map = state.get("capability_map")
                self.tool_manager._engagement_brain = state.get("engagement_brain")
            except Exception:
                pass

        # Auth session handoff: seed browser/deep_crawl/replay with prior login
        auth_sess = state.get("auth_session")
        try:
            self.tool_manager._auth_session = auth_sess
        except Exception:
            pass
        if auth_sess and tool_name in (
            "execute_deep_crawl",
            "execute_browser",
            "execute_interceptor",
        ):
            tool_args = self._inject_auth_session(tool_name, tool_args, auth_sess)

        # Remote Interceptor workers need session_id / org on the crawl job.
        if tool_name == "execute_interceptor":
            tool_args = self._inject_interceptor_job_context(tool_args, state)

        if tool_name == "replay_http_request" and state.get("capability_map"):
            # Convenience: if only an index is provided, pull from api_samples
            samples = (state.get("capability_map") or {}).get("api_samples") or []
            idx = tool_args.get("sample_index")
            if idx is not None and not tool_args.get("url") and samples:
                try:
                    sample = samples[int(idx)]
                    tool_args.setdefault("method", sample.get("method") or "GET")
                    tool_args.setdefault("url", sample.get("url") or "")
                    tool_args.setdefault("headers", sample.get("headers") or {})
                    if sample.get("body") and "body" not in tool_args:
                        tool_args["body"] = sample.get("body")
                except Exception:
                    pass

        # Soft gate: block broad active scanners until capability map + methodology cards exist
        # (unless the operator forces, or this is clearly a non-HTTP engagement).
        # NOTE: execute_wpscan is intentionally NOT here — WordPress enumeration
        # (version/plugins/themes/users, known-CVE mapping) is *targeted* recon against
        # an already-detected CMS, not a blind broad spray, so it should run as soon as
        # WordPress is fingerprinted rather than waiting on the full methodology flow.
        cmap = state.get("capability_map") or {}
        map_ready = bool(cmap.get("ready_for_attack"))
        spray_tools = {
            "execute_nuclei", "execute_xsstrike", "execute_nikto",
            "execute_ffuf",
        }
        force = bool(tool_args.get("force"))
        if tool_name in spray_tools and not map_ready and not force:
            step_data["tool_output"] = (
                f"Blocked: '{tool_name}' before application capability map. "
                "Walk the app like a tester first with execute_interceptor (or execute_deep_crawl) on the primary URL, "
                "then sync_engagement_brain + fireteam_dispatch(specialists='auto'), then resume scanning. "
                "Pass force=true only for intentionally non-browser targets."
            )
            step_data["success"] = False
            step_data["error_message"] = "capability_map_required"
            await self._emit_status({
                "type": "tool_complete",
                "tool_name": tool_name,
                "success": False,
                "output_summary": (step_data.get("tool_output") or "")[:300],
                "iteration": iteration,
            })
            return {"_current_step": step_data}

        if tool_name in spray_tools and map_ready and not force:
            brain_state = state.get("engagement_brain") or {}
            try:
                from app.services.agent.engagement_brain import methodology_progress
                progress = methodology_progress(brain_state, cmap=cmap)
                if not progress.get("seeded"):
                    step_data["tool_output"] = (
                        f"Blocked: '{tool_name}' before methodology cards are seeded. "
                        "Call sync_engagement_brain so observation→methodology hypotheses exist, "
                        "run fireteam_dispatch on high-priority cards, then resume coverage. "
                        "Pass force=true to override."
                    )
                    step_data["success"] = False
                    step_data["error_message"] = "methodology_required"
                    await self._emit_status({
                        "type": "tool_complete",
                        "tool_name": tool_name,
                        "success": False,
                        "output_summary": (step_data.get("tool_output") or "")[:300],
                        "iteration": iteration,
                    })
                    return {"_current_step": step_data}
                if not progress.get("ready_for_coverage_spray"):
                    blockers = progress.get("blockers") or []
                    blocker_txt = ", ".join(
                        (b.get("methodology_id") or b.get("title") or "?") for b in blockers[:4]
                    ) or "high-priority methodology cards"
                    step_data["tool_output"] = (
                        f"Blocked: '{tool_name}' while high-priority methodologies are unresolved "
                        f"({blocker_txt}). Prove/kill those cards first (fireteam / compare_requests / "
                        "update_hypothesis), then run coverage scanners. Pass force=true to override."
                    )
                    step_data["success"] = False
                    step_data["error_message"] = "methodology_incomplete"
                    await self._emit_status({
                        "type": "tool_complete",
                        "tool_name": tool_name,
                        "success": False,
                        "output_summary": (step_data.get("tool_output") or "")[:300],
                        "iteration": iteration,
                    })
                    return {"_current_step": step_data}
            except Exception:
                logger.exception("methodology spray-gate failed")

        # Execute tool
        # Skip a second WPScan when the first already produced a complete scan
        # (including exit-code-5 "vulnerabilities found"). Re-running burns the
        # remaining turn budget and is what kept us from hunting REST users /
        # admin-ajax.php.
        if tool_name == "execute_wpscan":
            from app.services.mcp.cli_results import wpscan_output_looks_complete
            prior_scans = [
                s for s in (state.get("execution_trace") or [])
                if s.get("tool_name") == "execute_wpscan"
            ]
            complete = next(
                (
                    s for s in reversed(prior_scans)
                    if wpscan_output_looks_complete(str(s.get("tool_output") or ""))
                ),
                None,
            )
            if complete or len(prior_scans) >= 2:
                origin = (
                    (state.get("target_info") or {}).get("primary_target") or ""
                ).rstrip("/")
                prior_out = str((complete or prior_scans[-1]).get("tool_output") or "")
                step_data["success"] = True
                step_data["error_message"] = None
                step_data["tool_output"] = (
                    "WPScan already completed this session — do not re-run it. "
                    "Treat the prior output as SUCCESS (exit 5 means findings, "
                    "not failure). create_finding for each CVE/user, then hunt "
                    f"{origin or 'the origin'}/wp-json/wp/v2/users and "
                    f"{origin or 'the origin'}/wp-admin/admin-ajax.php "
                    "(loadmore / tax_query time-based SQLi).\n\n"
                    + prior_out[:8000]
                )
                await self._emit_status({
                    "type": "tool_complete",
                    "tool_name": tool_name,
                    "success": True,
                    "output_summary": "skipped duplicate WPScan; using prior results",
                    "iteration": iteration,
                })
                return {"_current_step": step_data}

        # Break identical execute_* failure loops (empty args / same error)
        if tool_name and tool_name.startswith("execute_"):
            recent = state.get("execution_trace") or []
            same_fail = 0
            for prev in reversed(recent[-6:]):
                if prev.get("tool_name") != tool_name:
                    break
                if prev.get("success"):
                    break
                out = str(prev.get("tool_output") or "")
                if "Missing required parameter" in out or "expects a single 'args'" in out:
                    same_fail += 1
                else:
                    break
            if same_fail >= 2 and seed_target:
                # Force a concrete CLI string so we stop burning iterations
                from app.services.agent.tools import _default_args_for_tool
                forced = _default_args_for_tool(tool_name, seed_target)
                if forced:
                    tool_args = {"args": forced}
                    logger.warning(
                        "[%s] Breaking %s empty-args loop; forcing args=%s",
                        user_id, tool_name, forced,
                    )

        # Bound a single tool call so a hung/blocking tool can never stall the
        # turn. Cap = min(configured per-tool ceiling, remaining turn budget) so
        # we always exit before the outer request timeout. `result` is assigned
        # in every path (success, failure, timeout, raise), so the tool_complete
        # emit below always fires and the UI never dangles on the tool_start.
        tool_cap = getattr(settings, "AGENT_TOOL_HARD_TIMEOUT_SECONDS", 600) or 600
        remaining = self._turn_time_remaining()
        tool_timeout = (
            max(1.0, min(float(tool_cap), remaining))
            if remaining is not None
            else float(tool_cap)
        )
        try:
            result = await asyncio.wait_for(
                self.tool_manager.execute(tool_name, tool_args),
                timeout=tool_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "[%s] Tool %s exceeded node cap of %.0fs — aborted",
                user_id, tool_name, tool_timeout,
            )
            result = {
                "success": False,
                "output": "",
                "error": (
                    f"Tool '{tool_name}' exceeded its {int(tool_timeout)}s time "
                    "budget and was aborted. The backend stopped waiting."
                ),
            }
        except Exception as e:
            logger.error("[%s] Tool %s raised: %s", user_id, tool_name, e)
            result = {
                "success": False,
                "output": "",
                "error": f"Tool '{tool_name}' raised: {e}",
            }

        step_data["tool_output"] = result.get("output") or result.get("error") or ""
        step_data["success"] = result.get("success", False)
        step_data["error_message"] = result.get("error")
        # WPScan exit 5 / findings-in-stdout must never land as a failed step.
        if tool_name == "execute_wpscan":
            from app.services.mcp.cli_results import (
                normalize_cli_result,
                wpscan_output_looks_complete,
            )
            normalized = normalize_cli_result("execute_wpscan", {
                "success": step_data["success"],
                "output": step_data["tool_output"],
                "error": step_data.get("error_message"),
                "exit_code": result.get("exit_code"),
            })
            if normalized.get("success") or wpscan_output_looks_complete(
                step_data["tool_output"]
            ):
                step_data["success"] = True
                step_data["error_message"] = None
                if normalized.get("output"):
                    step_data["tool_output"] = normalized["output"]
        if result.get("capability_map"):
            step_data["capability_map"] = result.get("capability_map")
        if result.get("auth_session"):
            step_data["auth_session"] = result.get("auth_session")

        # ingest_urls_into_map / sync tools return JSON with capability_map embedded
        if tool_name in ("ingest_urls_into_map", "sync_engagement_brain") and not step_data.get("capability_map"):
            try:
                parsed_out = json.loads(step_data.get("tool_output") or "")
                if isinstance(parsed_out, dict) and parsed_out.get("capability_map"):
                    step_data["capability_map"] = parsed_out["capability_map"]
            except Exception:
                pass
        
        logger.info(f"[{user_id}] Tool result: success={step_data['success']}")

        await self._emit_status({
            "type": "tool_complete",
            "tool_name": tool_name,
            "success": step_data["success"],
            "output_summary": (step_data["tool_output"] or "")[:300],
            "iteration": iteration,
        })

        # Persist only the redacted args to the trace (state), never raw creds.
        step_data["tool_args"] = safe_args

        # EvoGraph: record step (fire-and-forget) — redacted args only.
        evograph.record_step(
            session_id=session_id,
            iteration=iteration,
            phase=phase,
            tool_name=tool_name,
            tool_args=safe_args,
            tool_output_summary=(step_data["tool_output"] or "")[:500],
            success=step_data["success"],
            thought=step_data.get("thought", ""),
        )
        if not step_data["success"] and step_data.get("error_message"):
            evograph.record_failure(
                session_id=session_id,
                iteration=iteration,
                tool_name=tool_name,
                error=step_data["error_message"][:300],
                lesson=f"{tool_name} failed with args {str(safe_args)[:200]}",
            )

        # Emit attack scenario update so the frontend can render the chain in real-time
        chain_data = evograph.get_session_chain(session_id)
        if chain_data.get("nodes"):
            await self._emit_status({
                "type": "attack_scenario_update",
                "chain": chain_data,
            })

        node_updates: Dict[str, Any] = {"_current_step": step_data}
        if auto_promoted_phase:
            node_updates["current_phase"] = auto_promoted_phase
            node_updates["phase_history"] = state.get("phase_history", []) + [
                PhaseHistoryEntry(phase=auto_promoted_phase).model_dump()
            ]
        return node_updates
    
    async def _analyze_output_node(self, state: AgentState, config=None) -> dict:
        """Analyze tool output and extract intelligence."""
        step_data = state.get("_current_step") or {}
        tool_output = step_data.get("tool_output") or ""
        tool_name = step_data.get("tool_name") or "unknown"
        
        if not tool_output:
            tool_output = step_data.get("error_message") or "No output"
        
        # Truncate for LLM
        max_chars = settings.AGENT_TOOL_OUTPUT_MAX_CHARS
        truncated_output = tool_output[:max_chars] if len(tool_output) > max_chars else tool_output
        
        # Build analysis prompt
        analysis_prompt = OUTPUT_ANALYSIS_PROMPT.format(
            tool_name=tool_name,
            tool_args=json_dumps_safe(step_data.get("tool_args") or {}),
            tool_output=truncated_output,
            current_target_info=json_dumps_safe(state.get("target_info") or {}, indent=2),
        )
        
        llm = self._resolve_llm(state, LLMTask.OFFENSIVE)
        response = await llm.ainvoke([HumanMessage(content=analysis_prompt)])
        analysis = self._parse_analysis_response(response.content)
        
        # Update step with analysis
        step_data["output_analysis"] = analysis.interpretation
        step_data["actionable_findings"] = analysis.actionable_findings or []
        step_data["recommended_next_steps"] = analysis.recommended_next_steps or []
        
        # Merge target info
        current_target = TargetInfo(**state.get("target_info", {}))
        new_target = TargetInfo(
            primary_target=analysis.extracted_info.primary_target,
            ports=analysis.extracted_info.ports,
            services=analysis.extracted_info.services,
            technologies=analysis.extracted_info.technologies,
            vulnerabilities=analysis.extracted_info.vulnerabilities,
        )
        merged_target = current_target.merge_from(new_target)
        
        # Add to execution trace
        execution_trace = state.get("execution_trace", []) + [step_data]

        # EvoGraph: record actionable findings
        session_id = state.get("session_id", "")
        iteration = step_data.get("iteration", 0)
        for finding_text in (analysis.actionable_findings or []):
            evograph.record_finding(
                session_id=session_id,
                iteration=iteration,
                finding_type="actionable",
                severity="medium",
                description=finding_text,
            )
        for vuln in (analysis.extracted_info.vulnerabilities or []):
            evograph.record_finding(
                session_id=session_id,
                iteration=iteration,
                finding_type="vulnerability",
                severity="high",
                description=vuln,
            )
        
        updates: Dict[str, Any] = {
            "_current_step": step_data,
            "execution_trace": execution_trace,
            "target_info": merged_target.model_dump(),
            "messages": [AIMessage(content=f"**Step {step_data.get('iteration')}** [{state.get('current_phase')}]\n\n{analysis.interpretation[:500]}")],
        }

        # Persist browser walkthrough → capability map into session state
        raw_map = step_data.get("capability_map")
        if not raw_map and tool_name in ("execute_deep_crawl", "execute_interceptor") and step_data.get("success"):
            # Fallback: try to recover map markers from text if structured block missing
            raw_map = None
        if raw_map:
            from app.services.agent.capability_map import merge_capability_maps
            updates["capability_map"] = merge_capability_maps(
                state.get("capability_map"),
                raw_map,
            )
            await self._emit_status({
                "type": "capability_map_update",
                "quality_score": updates["capability_map"].get("quality_score"),
                "ready_for_attack": updates["capability_map"].get("ready_for_attack"),
                "capabilities": updates["capability_map"].get("capabilities", []),
                "ranked_hunt_queue": updates["capability_map"].get("ranked_hunt_queue", [])[:8],
                "authenticated": updates["capability_map"].get("authenticated"),
                "api_sample_count": len(updates["capability_map"].get("api_samples") or []),
            })

        if step_data.get("auth_session"):
            updates["auth_session"] = step_data["auth_session"]
            await self._emit_status({
                "type": "auth_session_update",
                "authenticated": step_data["auth_session"].get("authenticated"),
                "cookie_count": len(step_data["auth_session"].get("cookies") or []),
                "target": step_data["auth_session"].get("target"),
            })

        # Persist engagement brain updates from tester-process tools / fireteam
        brain_update = None
        try:
            brain_update = getattr(self.tool_manager, "_engagement_brain", None)
        except Exception:
            brain_update = None
        # Prefer explicit engagement_brain embedded in JSON tool output
        raw_out = step_data.get("tool_output") or ""
        if tool_name in (
            "sync_engagement_brain",
            "update_hypothesis",
            "queue_finding_followups",
            "add_engagement_credential",
            "log_engagement_approach",
            "compare_requests",
            "fireteam_dispatch",
            "get_engagement_brain",
            "get_methodology_progress",
            "ingest_urls_into_map",
            "build_threat_model",
            "get_threat_model",
            "update_threat_model",
            "submit_finding_candidate",
            "independent_verify",
            "record_verify_verdict",
            "record_surface_coverage",
            "get_coverage",
        ) and "engagement_brain" in raw_out:
            try:
                parsed = json.loads(raw_out)
                if isinstance(parsed, dict) and parsed.get("engagement_brain"):
                    brain_update = parsed["engagement_brain"]
            except Exception:
                pass
        # Auto-seed brain when capability map first becomes ready
        if updates.get("capability_map") and updates["capability_map"].get("ready_for_attack"):
            try:
                from app.services.agent.engagement_brain import (
                    engagement_brain_from_dict,
                    seed_hypotheses_from_capability_map,
                )
                brain = engagement_brain_from_dict(
                    brain_update or state.get("engagement_brain")
                )
                brain = seed_hypotheses_from_capability_map(
                    brain, updates["capability_map"]
                )
                brain_update = brain.to_dict()
            except Exception:
                logger.exception("auto-seed engagement brain failed")

        if brain_update:
            updates["engagement_brain"] = brain_update
            try:
                self.tool_manager._engagement_brain = brain_update
            except Exception:
                pass
            open_n = len(
                [
                    h
                    for h in (brain_update.get("hypotheses") or [])
                    if h.get("status") in ("open", "in_progress")
                ]
            )
            await self._emit_status({
                "type": "engagement_brain_update",
                "phase": brain_update.get("phase"),
                "open_hypotheses": open_n,
                "credentials": len(brain_update.get("credentials") or []),
                "next_steps": (brain_update.get("next_steps") or [])[:5],
            })

        return updates

    @staticmethod
    def _inject_auth_session(
        tool_name: str,
        tool_args: Dict[str, Any],
        auth_sess: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Merge stored storage_state/cookies into browser/crawl tool args."""
        if not auth_sess:
            return tool_args
        args = dict(tool_args or {})
        storage = auth_sess.get("storage_state")
        cookies = auth_sess.get("cookies")

        # MCP tools usually take a single string `args` that may be JSON.
        if "args" in args and isinstance(args.get("args"), str):
            raw = args["args"].strip()
            try:
                parsed = json.loads(raw) if raw.startswith("{") else {"url": raw}
            except Exception:
                parsed = {"url": raw}
            if storage and "storage_state" not in parsed and "login" not in parsed:
                parsed["storage_state"] = storage
            elif cookies and "cookies" not in parsed and "login" not in parsed:
                parsed["cookies"] = cookies
            args["args"] = json.dumps(parsed)
            return args

        # Structured dict args (browser JSON object)
        if storage and "storage_state" not in args and "login" not in args:
            args["storage_state"] = storage
        elif cookies and "cookies" not in args and "login" not in args:
            args["cookies"] = cookies
        return args

    @staticmethod
    def _inject_interceptor_job_context(
        tool_args: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Attach session_id / org / early job_id and pentester crawl defaults."""
        from app.services.interceptor_service import apply_pentester_defaults

        args = dict(tool_args or {})
        session_id = state.get("session_id")
        org_id = state.get("organization_id")
        early_job = state.get("interceptor_job_id")
        patch: Dict[str, Any] = {}
        if session_id:
            patch["session_id"] = session_id
        if org_id is not None:
            patch["organization_id"] = org_id
        if early_job:
            patch["job_id"] = early_job

        if "args" in args and isinstance(args.get("args"), str):
            raw = args["args"].strip()
            try:
                parsed = json.loads(raw) if raw.startswith("{") else {"url": raw}
            except Exception:
                parsed = {"url": raw}
            parsed = apply_pentester_defaults(parsed)
            for k, v in patch.items():
                parsed.setdefault(k, v)
            args["args"] = json.dumps(parsed)
            return args

        # Flattened dict form
        merged = apply_pentester_defaults({**args, **{k: v for k, v in patch.items()}})
        return merged
    
    async def _await_approval_node(self, state: AgentState, config=None) -> dict:
        """Request user approval for phase transition."""
        transition = state.get("phase_transition_pending", {})
        
        planned_actions = "\n".join(f"- {a}" for a in transition.get("planned_actions", []))
        risks = "\n".join(f"- {r}" for r in transition.get("risks", []))
        
        message = PHASE_TRANSITION_MESSAGE.format(
            from_phase=transition.get("from_phase", "informational"),
            to_phase=transition.get("to_phase", "exploitation"),
            reason=transition.get("reason", "No reason provided"),
            planned_actions=planned_actions or "- No specific actions planned",
            risks=risks or "- Standard risks apply",
        )
        
        return {
            "awaiting_user_approval": True,
            "messages": [AIMessage(content=message)],
        }
    
    async def _process_approval_node(self, state: AgentState, config=None) -> dict:
        """Process user's approval response."""
        approval = state.get("user_approval_response")
        transition = state.get("phase_transition_pending", {})
        
        clear_state = {
            "awaiting_user_approval": False,
            "phase_transition_pending": None,
            "user_approval_response": None,
            "user_modification": None,
        }
        
        if approval == "approve":
            new_phase = transition.get("to_phase", "exploitation")
            return {
                **clear_state,
                "current_phase": new_phase,
                "phase_history": state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase=new_phase).model_dump()
                ],
                "messages": [AIMessage(content=f"Phase transition approved. Now in **{new_phase}** phase.")],
            }
        
        elif approval == "modify":
            modification = state.get("user_modification", "")
            return {
                **clear_state,
                "messages": [
                    HumanMessage(content=f"User modification: {modification}"),
                    AIMessage(content="Adjusting approach based on your feedback."),
                ],
            }
        
        else:  # abort
            return {
                **clear_state,
                "task_complete": True,
                "completion_reason": "Phase transition cancelled by user",
                "messages": [AIMessage(content="Phase transition cancelled. Session ended.")],
            }
    
    async def _await_question_node(self, state: AgentState, config=None) -> dict:
        """Request user answer to a question."""
        question = state.get("pending_question", {})
        
        options_text = "\n".join(f"- {opt}" for opt in question.get("options", [])) if question.get("options") else "Free text"
        
        message = USER_QUESTION_MESSAGE.format(
            question=question.get("question", ""),
            context=question.get("context", ""),
            format=question.get("format", "text"),
            options=options_text,
            default=question.get("default_value") or "None",
        )
        
        return {
            "awaiting_user_question": True,
            "messages": [AIMessage(content=message)],
        }
    
    async def _process_answer_node(self, state: AgentState, config=None) -> dict:
        """Process user's answer to a question."""
        answer = state.get("user_question_answer")
        question = state.get("pending_question", {})
        
        qa_entry = QAHistoryEntry(
            question=UserQuestionRequest(**question),
            answer={"question_id": question.get("question_id", ""), "answer": answer or ""},
            answered_at=utc_now(),
        )
        
        qa_history = state.get("qa_history", []) + [qa_entry.model_dump()]
        
        return {
            "awaiting_user_question": False,
            "pending_question": None,
            "user_question_answer": None,
            "qa_history": qa_history,
            "messages": [
                HumanMessage(content=f"User answer: {answer}"),
                AIMessage(content="Thank you. Continuing with the analysis..."),
            ],
        }
    
    async def _generate_response_node(self, state: AgentState, config=None) -> dict:
        """Generate final response."""
        completion_reason = state.get("completion_reason")
        if not completion_reason and self._turn_budget_exceeded():
            completion_reason = (
                "Reached the time budget for this turn — summarizing the findings "
                "gathered so far. Ask a follow-up to continue where this left off."
            )
        completion_reason = completion_reason or "Session ended"

        report_prompt = FINAL_REPORT_PROMPT.format(
            objective=state.get("original_objective", ""),
            iteration_count=state.get("current_iteration", 0),
            final_phase=state.get("current_phase", "informational"),
            completion_reason=completion_reason,
            execution_trace=format_execution_trace(state.get("execution_trace", [])),
            target_info=json_dumps_safe(state.get("target_info", {}), indent=2),
            todo_list=format_todo_list(state.get("todo_list", [])),
        )
        
        llm = self._resolve_llm(state, LLMTask.REPORT)
        response = await llm.ainvoke([HumanMessage(content=report_prompt)])
        
        return {
            "messages": [AIMessage(content=response.content)],
            "task_complete": True,
            "completion_reason": completion_reason,
        }
    
    # =========================================================================
    # ROUTING FUNCTIONS
    # =========================================================================
    
    def _route_after_initialize(self, state: AgentState) -> str:
        if state.get("user_approval_response") and state.get("phase_transition_pending"):
            return "process_approval"
        if state.get("user_question_answer") and state.get("pending_question"):
            return "process_answer"
        return "think"
    
    def _route_after_think(self, state: AgentState) -> str:
        if self._turn_budget_exceeded():
            return "generate_response"
        if state.get("current_iteration", 0) >= state.get("max_iterations", 15):
            return "generate_response"
        if state.get("task_complete"):
            return "generate_response"
        if state.get("awaiting_user_approval"):
            return "await_approval"
        if state.get("awaiting_user_question"):
            return "await_question"
        
        decision = state.get("_decision", {})
        action = decision.get("action", "use_tool")
        
        if action == "complete":
            return "generate_response"
        elif action == "ask_user" and state.get("pending_question"):
            return "await_question"
        elif action == "transition_phase" and state.get("phase_transition_pending"):
            return "await_approval"
        elif action == "use_tool" and decision.get("tool_name"):
            return "execute_tool"
        else:
            return "generate_response"
    
    def _route_after_analyze(self, state: AgentState) -> str:
        if state.get("task_complete"):
            return "generate_response"
        if self._turn_budget_exceeded():
            return "generate_response"
        if state.get("current_iteration", 0) >= state.get("max_iterations", 15):
            return "generate_response"
        return "think"
    
    def _route_after_approval(self, state: AgentState) -> str:
        if state.get("task_complete"):
            return "generate_response"
        return "think"
    
    def _route_after_answer(self, state: AgentState) -> str:
        if state.get("task_complete"):
            return "generate_response"
        return "think"
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _extract_json(self, text: str) -> Optional[str]:
        """Extract JSON from text."""
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            return text[json_start:json_end]
        return None
    
    def _parse_llm_decision(self, text: str) -> LLMDecision:
        """Parse LLM decision from response."""
        try:
            json_str = self._extract_json(text)
            if json_str:
                data = json.loads(json_str)
                
                # Clean empty objects
                if "user_question" in data and not data["user_question"]:
                    data["user_question"] = None
                if "phase_transition" in data and not data["phase_transition"]:
                    data["phase_transition"] = None

                # Coerce a common LLM slip: putting the tool name directly in
                # `action` (e.g. action="fireteam_dispatch") instead of
                # action="use_tool" with tool_name set. Without this the decision
                # fails literal validation and the whole turn is wasted on a parse
                # error, which manifests as the agent stalling.
                _valid_actions = {"use_tool", "complete", "transition_phase", "ask_user"}
                _act = data.get("action")
                if isinstance(_act, str) and _act not in _valid_actions and _act.strip():
                    data["tool_name"] = data.get("tool_name") or data.get("tool") or _act
                    data["action"] = "use_tool"

                return LLMDecision.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to parse LLM decision: {e}")

        # No usable JSON. Distinguish a provider content-filter refusal (the model
        # declined in prose) from a plain formatting miss, so the operator can tell
        # which layer stopped an authorized run instead of seeing a vague error.
        if self._looks_like_refusal(text):
            logger.warning("LLM returned a content-filter refusal (no decision JSON)")
            return LLMDecision(
                thought=text,
                reasoning="LLM provider declined the request",
                action="complete",
                completion_reason=(
                    "The LLM provider's content filter declined this step "
                    "(the model refused rather than returning a decision). This is "
                    "authorized in-scope testing — retry, rephrase the objective, or "
                    "switch the agent to a provider/model that permits security testing."
                ),
                updated_todo_list=[],
            )

        return LLMDecision(
            thought=text,
            reasoning="Failed to parse response",
            action="complete",
            completion_reason="Parse error",
            updated_todo_list=[],
        )

    @staticmethod
    def _looks_like_refusal(text: str) -> bool:
        """Heuristic: does an un-parseable LLM reply read like a safety refusal?"""
        if not text:
            return False
        low = text.lower()
        markers = (
            "i can't help", "i cannot help", "i can't assist", "i cannot assist",
            "i'm unable to", "i am unable to", "i'm not able to", "i am not able to",
            "i won't", "i will not", "cannot comply", "can't comply",
            "against my guidelines", "i must decline", "i have to decline",
            "not able to provide", "unable to provide assistance",
            "i can't provide", "i cannot provide",
        )
        return any(m in low for m in markers)
    
    def _parse_analysis_response(self, text: str) -> OutputAnalysis:
        """Parse analysis response."""
        try:
            json_str = self._extract_json(text)
            if json_str:
                data = json.loads(json_str)
                return OutputAnalysis.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to parse analysis: {e}")
        
        return OutputAnalysis(
            interpretation=text[:1000],
            extracted_info=ExtractedTargetInfo(),
            actionable_findings=[],
            recommended_next_steps=[],
        )
    
    # =========================================================================
    # PUBLIC API
    # =========================================================================
    
    def set_status_callback(self, callback: StatusCallback) -> None:
        """Register a callback for streaming status updates (WebSocket).

        Uses a ContextVar so concurrent invocations don't overwrite each other.
        """
        _status_callback_var.set(callback)

    def clear_status_callback(self) -> None:
        """Remove the streaming status callback."""
        _status_callback_var.set(None)

    async def invoke(
        self,
        question: str,
        user_id: str,
        organization_id: int,
        session_id: str,
        initial_todos: Optional[List[Dict[str, Any]]] = None,
        mode: str = "assist",
        status_callback: StatusCallback = None,
        max_iterations: Optional[int] = None,
    ) -> InvokeResponse:
        """Main entry point for agent invocation.
        
        Args:
            max_iterations: Override the default iteration cap. REST routes
                pass AGENT_REST_MAX_ITERATIONS to keep responses under proxy
                timeout limits.
        """
        if not self._initialized:
            await self.initialize()
        
        if not self._initialized:
            return InvokeResponse(error="Agent not initialized - check OPENAI_API_KEY")
        
        _max_iterations_var.set(max_iterations)
        self._start_turn_deadline()
        set_autonomous_mode(mode == "agent")
        logger.info(f"[{user_id}/{session_id}] Invoking with: {question[:100]}... (mode={mode}, max_iter={max_iterations or 'default'})")

        if status_callback:
            self.set_status_callback(status_callback)
        
        # EvoGraph: record chain start
        evograph.record_chain_start(
            session_id=session_id,
            organization_id=organization_id,
            user_id=user_id,
            objective=question,
            mode=mode,
        )

        try:
            config = {"configurable": {"thread_id": session_id}}
            input_data = {
                "messages": [HumanMessage(content=question)],
                "user_id": user_id,
                "organization_id": organization_id,
                "session_id": session_id,
                "mode": mode,
            }
            if initial_todos is not None:
                input_data["initial_todos"] = initial_todos
            
            final_state = await self.graph.ainvoke(input_data, config)
            response = self._build_response(final_state)

            # EvoGraph: record chain end
            evograph.record_chain_end(
                session_id=session_id,
                status="completed" if response.task_complete else "paused",
                outcome=response.answer[:300] if response.answer else "",
                final_phase=response.current_phase,
                iteration_count=response.iteration_count,
            )
            self._persist_palace_brain(organization_id, session_id, final_state)

            return response
        
        except Exception as e:
            logger.exception(f"[{user_id}/{session_id}] Error: {e}")
            evograph.record_chain_end(session_id=session_id, status="error", outcome=str(e)[:300])
            return InvokeResponse(error=str(e))
        finally:
            if status_callback:
                self.clear_status_callback()
    
    async def _arm_autonomous_from_state(self, config: dict) -> None:
        """Restore autonomous auto-approval on resume from the checkpointed run
        mode. An agent-mode run that paused (e.g. asked the user a question)
        should keep auto-approving confirm-gated tools on resume rather than
        stalling; assist-mode resumes stay interactive. Best-effort: defaults to
        interactive (False) if the checkpoint can't be read."""
        mode = None
        try:
            snap = await self.graph.aget_state(config)
            mode = (getattr(snap, "values", None) or {}).get("mode")
        except Exception:
            logger.debug("Could not read checkpoint mode for autonomous arm", exc_info=True)
        set_autonomous_mode(mode == "agent")

    async def resume_after_approval(
        self,
        session_id: str,
        user_id: str,
        organization_id: int,
        decision: str,
        modification: Optional[str] = None,
        status_callback: StatusCallback = None,
    ) -> InvokeResponse:
        """Resume after user approval."""
        if not self._initialized:
            return InvokeResponse(error="Agent not initialized")

        self._start_turn_deadline()
        if status_callback:
            self.set_status_callback(status_callback)
        
        try:
            config = {"configurable": {"thread_id": session_id}}
            await self._arm_autonomous_from_state(config)
            
            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
                "user_id": user_id,
                "organization_id": organization_id,
            }
            
            final_state = await self.graph.ainvoke(update_data, config)
            self._persist_palace_brain(organization_id, session_id, final_state)
            return self._build_response(final_state)
        
        except Exception as e:
            logger.error(f"[{user_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))
        finally:
            if status_callback:
                self.clear_status_callback()
    
    async def resume_after_answer(
        self,
        session_id: str,
        user_id: str,
        organization_id: int,
        answer: str,
        status_callback: StatusCallback = None,
    ) -> InvokeResponse:
        """Resume after user answers a question."""
        if not self._initialized:
            return InvokeResponse(error="Agent not initialized")

        self._start_turn_deadline()
        if status_callback:
            self.set_status_callback(status_callback)
        
        try:
            config = {"configurable": {"thread_id": session_id}}
            await self._arm_autonomous_from_state(config)
            
            update_data = {
                "user_question_answer": answer,
                "user_id": user_id,
                "organization_id": organization_id,
            }
            
            final_state = await self.graph.ainvoke(update_data, config)
            self._persist_palace_brain(organization_id, session_id, final_state)
            return self._build_response(final_state)
        
        except Exception as e:
            logger.error(f"[{user_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))
        finally:
            if status_callback:
                self.clear_status_callback()
    
    def _persist_palace_brain(
        self,
        organization_id: int,
        session_id: str,
        final_state: Any,
    ) -> None:
        """Write a redacted engagement-brain snapshot so later sessions can recall it."""
        try:
            from app.services.agent.palace_memory import persist_engagement_brain

            brain = final_state.get("engagement_brain") if isinstance(final_state, dict) else None
            persist_engagement_brain(
                organization_id,
                brain,
                session_id=session_id,
            )
        except Exception:
            logger.debug("palace engagement brain persist skipped", exc_info=True)

    def _build_response(self, state: dict) -> InvokeResponse:
        """Build response from final state."""
        final_answer = ""
        messages = state.get("messages", [])
        for msg in reversed(messages):
            if isinstance(msg, AIMessage):
                final_answer = msg.content
                break
        
        step = state.get("_current_step", {})

        from app.services.agent.model_router import consume_llm_degrade_notice
        warning = consume_llm_degrade_notice()
        
        return InvokeResponse(
            answer=final_answer,
            tool_used=step.get("tool_name"),
            tool_output=step.get("tool_output"),
            current_phase=state.get("current_phase", "informational"),
            iteration_count=state.get("current_iteration", 0),
            task_complete=state.get("task_complete", False),
            todo_list=state.get("todo_list", []),
            execution_trace_summary=summarize_trace_for_response(state.get("execution_trace", [])),
            awaiting_approval=state.get("awaiting_user_approval", False),
            approval_request=state.get("phase_transition_pending"),
            awaiting_question=state.get("awaiting_user_question", False),
            question_request=state.get("pending_question"),
            warning=warning,
        )


# Global orchestrator instance
_orchestrator: Optional[AgentOrchestrator] = None


async def get_agent_orchestrator() -> AgentOrchestrator:
    """Get or create the global agent orchestrator."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator()
        await _orchestrator.initialize()
    return _orchestrator
