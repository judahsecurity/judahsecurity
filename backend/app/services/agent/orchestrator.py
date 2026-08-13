"""
Agent Orchestrator

ReAct-style agent orchestrator for security analysis and autonomous assessment.
Uses LangGraph for state management and LangChain for LLM interactions.
Supports WebSocket streaming callbacks and cross-session learning via EvoGraph.
"""

import json
import logging
import re
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
)
from app.services.agent.tools import ASMToolsManager, set_tenant_context
from app.services.agent.model_router import LLMTask
from app.services.agent.knowledge import retrieve_knowledge
from app.services.agent import evograph
from app.services.agent.tool_selector import get_tool_recommendations

logger = logging.getLogger(__name__)

# Type alias for the optional WebSocket status callback
StatusCallback = Optional[Callable[[Dict[str, Any]], Awaitable[None]]]

# Per-request status callback stored in a ContextVar for thread/task safety.
# This avoids the race condition of storing it as instance state on the singleton.
_max_iterations_var: ContextVar[Optional[int]] = ContextVar('_max_iterations_var', default=None)
_status_callback_var: ContextVar[StatusCallback] = ContextVar('_status_callback_var', default=None)

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
        
        return {
            "current_iteration": 0,
            "max_iterations": _max_iterations_var.get(None) or settings.AGENT_MAX_ITERATIONS,
            "task_complete": False,
            "current_phase": "informational",
            "phase_history": [PhaseHistoryEntry(phase="informational").model_dump()],
            "execution_trace": [],
            "todo_list": todo_list,
            "conversation_objectives": objectives,
            "current_objective_index": 0,
            "objective_history": [],
            "original_objective": latest_message,
            "target_info": target_info,
            "capability_map": None,
            "auth_session": None,
            "engagement_brain": None,
            "awaiting_user_approval": False,
            "phase_transition_pending": None,
            "qa_history": [],
            "mode": mode,
        }
    
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
        
        # Get current objective
        objectives = state.get("conversation_objectives", [])
        current_idx = state.get("current_objective_index", 0)
        current_objective = objectives[current_idx].get("content", "") if current_idx < len(objectives) else state.get("original_objective", "")
        
        # Session notes for prompt
        session_notes = (
            self.tool_manager.get_session_notes(session_id=session_id)
            if self.tool_manager else "No session notes."
        )
        
        # RAG: org knowledge (scope, ROE, methodology)
        knowledge_context = ""
        if org_id:
            knowledge_context = retrieve_knowledge(
                org_id,
                current_objective[:200] if current_objective else "",
                limit=5,
                max_chars=1500,
            )
        if not knowledge_context:
            knowledge_context = "None."

        # Cross-session learning: load prior chain context from EvoGraph
        prior_chain_context = ""
        if org_id and session_id:
            prior_chain_context = evograph.get_prior_chain_context(
                organization_id=org_id,
                current_session_id=session_id,
            )
        
        # Build prompt
        execution_trace_formatted = format_execution_trace(state.get("execution_trace", []))
        todo_list_formatted = format_todo_list(state.get("todo_list", []))
        target_info_formatted = json_dumps_safe(state.get("target_info", {}), indent=2)
        qa_history_formatted = format_qa_history(state.get("qa_history", []))
        objective_history_formatted = format_objective_history(state.get("objective_history", []))
        available_tools = get_phase_tools(phase)

        # Append prior session intelligence to knowledge context
        combined_knowledge = knowledge_context
        if prior_chain_context:
            combined_knowledge = f"{knowledge_context}\n\n{prior_chain_context}"

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
        }
        
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
                            + " | Complete blocked — unresolved high-priority methodologies."
                        )
                        step.tool_name = None
                        updates["_current_step"] = step.model_dump()
                        updates["messages"] = [AIMessage(content=(
                            "Cannot complete yet — application assessment methodology incomplete.\n"
                            f"{progress.get('summary')}\n"
                            f"Blocking: {blocker_txt}\n\n"
                            "Prove or kill those cards (update_hypothesis), then complete. "
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
        
        # Check phase restriction
        if not is_tool_allowed_in_phase(tool_name, phase):
            step_data["tool_output"] = f"Error: Tool '{tool_name}' not allowed in '{phase}' phase"
            step_data["success"] = False
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
        ):
            if state.get("capability_map") and not tool_args.get("capability_map"):
                if tool_name in ("fireteam_dispatch", "sync_engagement_brain"):
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
        cmap = state.get("capability_map") or {}
        map_ready = bool(cmap.get("ready_for_attack"))
        spray_tools = {
            "execute_nuclei", "execute_sqlmap", "execute_xsstrike", "execute_nikto",
            "execute_ffuf", "execute_wpscan",
        }
        force = bool(tool_args.get("force"))
        if tool_name in spray_tools and not map_ready and not force:
            step_data["tool_output"] = (
                f"Blocked: '{tool_name}' before application capability map. "
                "Walk the app like a tester first with execute_deep_crawl on the primary URL, "
                "then sync_engagement_brain + fireteam_dispatch(specialists='auto'), then resume scanning. "
                "Pass force=true only for intentionally non-browser targets."
            )
            step_data["success"] = False
            step_data["error_message"] = "capability_map_required"
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
                    return {"_current_step": step_data}
            except Exception:
                logger.exception("methodology spray-gate failed")

        # Execute tool
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

        result = await self.tool_manager.execute(tool_name, tool_args)
        
        step_data["tool_output"] = result.get("output") or result.get("error") or ""
        step_data["success"] = result.get("success", False)
        step_data["error_message"] = result.get("error")
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

        return {"_current_step": step_data}
    
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
        report_prompt = FINAL_REPORT_PROMPT.format(
            objective=state.get("original_objective", ""),
            iteration_count=state.get("current_iteration", 0),
            final_phase=state.get("current_phase", "informational"),
            completion_reason=state.get("completion_reason", "Session ended"),
            execution_trace=format_execution_trace(state.get("execution_trace", [])),
            target_info=json_dumps_safe(state.get("target_info", {}), indent=2),
            todo_list=format_todo_list(state.get("todo_list", [])),
        )
        
        llm = self._resolve_llm(state, LLMTask.REPORT)
        response = await llm.ainvoke([HumanMessage(content=report_prompt)])
        
        return {
            "messages": [AIMessage(content=response.content)],
            "task_complete": True,
            "completion_reason": state.get("completion_reason") or "Task completed",
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
                
                return LLMDecision.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to parse LLM decision: {e}")
        
        return LLMDecision(
            thought=text,
            reasoning="Failed to parse response",
            action="complete",
            completion_reason="Parse error",
            updated_todo_list=[],
        )
    
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

            return response
        
        except Exception as e:
            logger.error(f"[{user_id}/{session_id}] Error: {e}")
            evograph.record_chain_end(session_id=session_id, status="error", outcome=str(e)[:300])
            return InvokeResponse(error=str(e))
        finally:
            if status_callback:
                self.clear_status_callback()
    
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

        if status_callback:
            self.set_status_callback(status_callback)
        
        try:
            config = {"configurable": {"thread_id": session_id}}
            
            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
                "user_id": user_id,
                "organization_id": organization_id,
            }
            
            final_state = await self.graph.ainvoke(update_data, config)
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

        if status_callback:
            self.set_status_callback(status_callback)
        
        try:
            config = {"configurable": {"thread_id": session_id}}
            
            update_data = {
                "user_question_answer": answer,
                "user_id": user_id,
                "organization_id": organization_id,
            }
            
            final_state = await self.graph.ainvoke(update_data, config)
            return self._build_response(final_state)
        
        except Exception as e:
            logger.error(f"[{user_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))
        finally:
            if status_callback:
                self.clear_status_callback()
    
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
