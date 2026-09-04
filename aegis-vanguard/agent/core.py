"""
ReACT Agent Loop for Aegis Vanguard Agent Framework

The core reasoning engine. Implements the Reason-Act-Observe cycle:
  1. Send context + tool schemas to LLM
  2. LLM reasons and selects tool(s) to call
  3. Execute tools (with guardrails)
  4. Feed results back to LLM
  5. Repeat until LLM decides it's done or hands off to another agent

Supports multi-agent handoffs: an agent can transfer control to a
specialized sub-agent, passing accumulated context.
"""

import inspect
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

try:
    import anthropic
except Exception:  # pragma: no cover - optional when running LiteLLM-only
    anthropic = None

try:
    import litellm
except Exception:  # pragma: no cover - optional until Phase 2 deps installed
    litellm = None

from agent.tools import ToolDef, ToolRegistry
from agent.guardrails import GuardrailEngine
from agent.tracing import Tracer, TokenUsage
from agent.session_ops import compact_message_tool_results, over_budget
from agent.distiller import get_distiller

# Cloud billing / quota / auth signals (Anthropic, OpenAI, etc.) that should
# trigger a local Ollama retry when OLLAMA_FALLBACK_ENABLED is on.
_CREDIT_QUOTA_MARKERS = (
    "credit balance is too low",
    "credit balance",
    "plans & billing",
    "plans and billing",
    "purchase credits",
    "insufficient_quota",
    "insufficient quota",
    "exceeded your current quota",
    "exceeded your quota",
    "billing hard limit",
    "billing_not_active",
    "payment required",
    "usage limit",
    "quota exceeded",
    "out of credits",
    "no credits",
    "authentication_error",
    "api key is invalid",
    "invalid api key",
    "invalid x-api-key",
    "incorrect api key",
    "invalid_api_key",
    "unauthorized",
)


def _is_credit_or_quota_error(exc: BaseException) -> bool:
    parts = [str(exc), type(exc).__name__]
    cause = getattr(exc, "__cause__", None)
    if cause is not None:
        parts.extend([str(cause), type(cause).__name__])
    for attr in ("message", "body", "response"):
        val = getattr(exc, attr, None)
        if val is not None:
            parts.append(str(val))
    haystack = " ".join(parts).lower()
    if any(m in haystack for m in _CREDIT_QUOTA_MARKERS):
        return True
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    return status in (401, 402)


def _ollama_fallback_enabled() -> bool:
    return os.environ.get("OLLAMA_FALLBACK_ENABLED", "true").lower() not in (
        "0", "false", "no", "off",
    )


def _ollama_api_base() -> str:
    base = (
        os.environ.get("OLLAMA_API_BASE")
        or os.environ.get("OLLAMA_BASE_URL")
        or "http://127.0.0.1:11434"
    ).rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return base


def _ollama_litellm_model() -> str:
    model = os.environ.get("OLLAMA_MODEL") or "qwen2.5:14b"
    if "/" in model:
        return model
    return f"ollama/{model}"


def _ollama_is_reachable(timeout: float = 0.75) -> bool:
    try:
        from urllib.request import urlopen
        url = f"{_ollama_api_base()}/api/tags"
        with urlopen(url, timeout=timeout) as resp:  # nosec B310 — local admin URL
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception:
        return False

# Aegis Praetorium — shared guard layer (Lictor / Censor / Augur). Imported
# lazily-tolerantly so a missing install does not break the agent on dev
# machines that haven't pip-installed the package.
try:
    from aegis_praetorium import (
        HookContext as LictorHookContext,
        PostHookContext as LictorPostHookContext,
        get_augur,
        get_censor,
        get_config as get_praetorium_config,
        get_lictor,
    )
    _AEGIS_AVAILABLE = True
except Exception as _aegis_err:  # noqa: F841
    _AEGIS_AVAILABLE = False

logger = logging.getLogger("agent.core")


@dataclass
class Agent:
    """A specialized security agent with its own instructions, tools, and handoffs."""
    name: str
    instructions: str
    tool_names: Optional[List[str]] = None  # None = all tools
    model: str = ""
    handoffs: List["Agent"] = field(default_factory=list)
    max_turns: int = 50
    temperature: float = 0.0

    def available_tools(self, registry: ToolRegistry) -> List[ToolDef]:
        if self.tool_names is None:
            return registry.all_tools()
        return [t for t in registry.all_tools() if t.name in self.tool_names]


@dataclass
class RunResult:
    """Result of an agent run."""
    agent_name: str
    messages: List[dict]
    final_text: str
    tool_calls_made: int
    turns_used: int
    handoff_to: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


def _anthropic_create_kwargs(create_fn: Callable, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Drop kwargs the installed anthropic SDK's Messages.create() does not accept."""
    try:
        params = inspect.signature(create_fn).parameters
    except (TypeError, ValueError):
        return kwargs
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return kwargs
    return {k: v for k, v in kwargs.items() if k in params}


class AgentRunner:
    """Executes the ReACT loop for one or more agents."""

    def __init__(
        self,
        guardrails: Optional[GuardrailEngine] = None,
        tracer: Optional[Tracer] = None,
        default_model: str = "",
        price_limit_usd: float = 0.0,
        compact_keep_recent: int = 6,
        hitl: Optional[Any] = None,
    ):
        self.registry = ToolRegistry()
        self.guardrails = guardrails or GuardrailEngine()
        self.tracer = tracer or Tracer(enabled=False)
        # Human-in-the-loop steering (CAI-style). None disables it.
        self.hitl = hitl
        self.default_model = default_model or os.environ.get("AEGIS_MODEL", "claude-sonnet-4-6")
        self.llm_backend = os.environ.get("AEGIS_LLM_BACKEND", "auto").lower()
        self.price_limit_usd = float(price_limit_usd or 0)
        self.compact_keep_recent = int(compact_keep_recent or 6)
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key and self.llm_backend in ("auto", "anthropic"):
            logger.warning("ANTHROPIC_API_KEY not set - agent loop will fail")
        self.client = (
            anthropic.Anthropic(api_key=api_key)
            if anthropic is not None and api_key else None
        )
        if litellm is not None:
            # Keep retries in the framework loop where traces/guardrails are visible.
            litellm.drop_params = True

        # Circuit breaker: 5 consecutive WAF/rate-limit blocks → 60s backoff.
        self._consecutive_blocks: int = 0
        self._circuit_backoff_sec: float = 60.0

    def run(
        self,
        agent: Agent,
        task: str,
        context: Optional[Dict[str, Any]] = None,
        messages: Optional[List[dict]] = None,
    ) -> RunResult:
        """Execute the ReACT loop for an agent.

        Args:
            agent: The agent to run
            task: The initial task/prompt
            context: Shared context dict (findings, state, etc.)
            messages: Pre-existing message history (for handoffs)
        """
        self._ensure_model_available(agent)

        ctx = context or {}
        model = self._resolve_model(agent)

        if messages is None:
            messages = [{"role": "user", "content": task}]

        tools_schemas = self._build_tool_schemas(agent)
        system_prompt = self._build_system_prompt(agent, ctx)

        total_tool_calls = 0
        final_text = ""
        backend = self._backend_for_model(model)

        for turn in range(agent.max_turns):
            spent = self.tracer.tokens.cost(model)
            if over_budget(spent, self.price_limit_usd):
                final_text = (
                    f"Spend cap reached (${spent:.4f} of ${self.price_limit_usd:.2f}). "
                    "Stopping before more LLM calls."
                )
                logger.warning("[%s] %s", agent.name, final_text)
                messages.append({"role": "assistant", "content": final_text})
                break

            messages = compact_message_tool_results(
                messages, keep_recent=self.compact_keep_recent,
            )

            with self.tracer.span(
                f"turn_{turn}", "agent_turn", agent_name=agent.name,
                turn=turn, model=model, llm_backend=backend,
            ):
                logger.info(
                    "[%s] Turn %d/%d model=%s backend=%s",
                    agent.name, turn + 1, agent.max_turns, model, backend,
                )

                try:
                    response = self._call_model(
                        model=model,
                        agent=agent,
                        system_prompt=system_prompt,
                        tools_schemas=tools_schemas,
                        messages=messages,
                    )
                except Exception as e:
                    logger.error(f"API error: {e}")
                    break

                self.tracer.record_tokens(
                    TokenUsage(
                        input_tokens=response.usage.input_tokens,
                        output_tokens=response.usage.output_tokens,
                        cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
                    ),
                    model=model,
                )
                spent = self.tracer.tokens.cost(model)
                if over_budget(spent, self.price_limit_usd):
                    final_text = (
                        f"Spend cap reached (${spent:.4f} of ${self.price_limit_usd:.2f}). "
                        "Stopping after this turn."
                    )
                    logger.warning("[%s] %s", agent.name, final_text)
                    break

                assistant_content = response.content
                messages.append({"role": "assistant", "content": assistant_content})

                tool_uses = [b for b in assistant_content if b.type == "tool_use"]
                text_blocks = [b for b in assistant_content if b.type == "text"]

                if text_blocks:
                    final_text = text_blocks[-1].text
                    logger.info(f"[{agent.name}] Thinking: {final_text[:200]}...")

                if not tool_uses:
                    logger.info(f"[{agent.name}] No more tool calls - done")
                    break

                tool_results = []
                for tool_use in tool_uses:
                    result_content = self._execute_tool(
                        agent, tool_use.name, tool_use.input, tool_use.id,
                    )
                    total_tool_calls += 1
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use.id,
                        "content": result_content,
                    })

                    if tool_use.name.startswith("handoff_to_"):
                        target_name = tool_use.name.replace("handoff_to_", "")
                        return RunResult(
                            agent_name=agent.name,
                            messages=messages,
                            final_text=final_text,
                            tool_calls_made=total_tool_calls,
                            turns_used=turn + 1,
                            handoff_to=target_name,
                            context=ctx,
                        )

                self._inject_operator_directives(tool_results, agent)
                messages.append({"role": "user", "content": tool_results})

                if response.stop_reason == "end_turn":
                    break

        return RunResult(
            agent_name=agent.name,
            messages=messages,
            final_text=final_text,
            tool_calls_made=total_tool_calls,
            turns_used=min(turn + 1, agent.max_turns),
            context=ctx,
        )

    def run_multi(
        self,
        agents: Dict[str, Agent],
        entry_agent: str,
        task: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> RunResult:
        """Run a multi-agent pipeline with handoffs.

        Starts with entry_agent, follows handoffs until an agent completes
        without handing off or max chain depth is reached.
        """
        ctx = context or {}
        current_agent = agents[entry_agent]
        messages = [{"role": "user", "content": task}]
        max_chain = 10

        for chain_step in range(max_chain):
            logger.info(f"=== Agent: {current_agent.name} (chain step {chain_step + 1}) ===")

            with self.tracer.span(
                f"agent_{current_agent.name}", "handoff",
                agent_name=current_agent.name, chain_step=chain_step,
            ):
                result = self.run(current_agent, task="", context=ctx, messages=messages)

            if not result.handoff_to:
                return result

            target_name = result.handoff_to
            if target_name not in agents:
                logger.warning(f"Handoff target '{target_name}' not found, ending chain")
                return result

            logger.info(f"Handoff: {current_agent.name} -> {target_name}")
            self.tracer._handoffs += 1
            current_agent = agents[target_name]
            messages = result.messages

        return result

    def _build_system_prompt(self, agent: Agent, context: Dict[str, Any]) -> str:
        parts = [agent.instructions]

        if context:
            # Build a context snapshot that's always serialisable.
            # Large lists/dicts are truncated rather than silently dropped so
            # agents like the validator can always see findings metadata.
            _MAX_VALUE_CHARS = 4000
            ctx_snap: dict = {}
            for k, v in context.items():
                raw = json.dumps(v, default=str)
                if len(raw) <= _MAX_VALUE_CHARS:
                    ctx_snap[k] = v
                elif isinstance(v, list):
                    ctx_snap[k] = {
                        "_type": "truncated_list",
                        "_total_items": len(v),
                        "_first_10": v[:10],
                        "_note": (
                            f"List has {len(v)} items; first 10 shown. "
                            "Full list is also inlined in the task message."
                        ),
                    }
                elif isinstance(v, dict):
                    ctx_snap[k] = {
                        "_type": "truncated_dict",
                        "_keys": list(v.keys()),
                        "_note": "Dict too large for system prompt; key list shown.",
                    }
                elif isinstance(v, str):
                    ctx_snap[k] = v[:_MAX_VALUE_CHARS] + "… [truncated]"
                else:
                    ctx_snap[k] = str(v)[:_MAX_VALUE_CHARS]
            ctx_summary = json.dumps(ctx_snap, indent=2, default=str)
            parts.append(f"\n\n## Current Context\n```json\n{ctx_summary}\n```")

        if agent.handoffs:
            handoff_list = ", ".join(a.name for a in agent.handoffs)
            parts.append(
                f"\n\n## Available Handoffs\n"
                f"You can transfer control to: {handoff_list}\n"
                f"Use the handoff_to_<agent_name> tool when appropriate."
            )

        return "\n".join(parts)

    def _build_tool_schemas(self, agent: Agent) -> List[dict]:
        tools = agent.available_tools(self.registry)
        schemas = [t.to_anthropic_schema() for t in tools]

        for handoff_agent in agent.handoffs:
            safe_name = handoff_agent.name.lower().replace(" ", "_")
            schemas.append({
                "name": f"handoff_to_{safe_name}",
                "description": (
                    f"Transfer control to {handoff_agent.name}. "
                    f"Use this when: {handoff_agent.instructions[:200]}"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "reason": {
                            "type": "string",
                            "description": "Why you are handing off to this agent",
                        },
                        "findings_summary": {
                            "type": "string",
                            "description": "Summary of findings so far for the next agent",
                        },
                    },
                    "required": ["reason"],
                },
            })

        return schemas

    # ───────────────────────── model routing / LLM adapters ──────────────────

    def _resolve_model(self, agent: Agent) -> str:
        """Resolve a model for this agent.

        Priority:
          1. Exact env var: AEGIS_MODEL_<AGENT_NAME> (e.g. AEGIS_MODEL_RECON_AGENT)
          2. Category env vars: AEGIS_MODEL_RECON / VULN / EXPLOIT / REPORT / HUNTER
          3. Agent.model from code
          4. AEGIS_MODEL default

        This keeps the ReAct prompts/analysis intact while allowing cost-aware
        routing: e.g. cheap model for recon/report, Opus/GPT-5.5 for exploit
        validation or the OWASP hunters.
        """
        exact = os.environ.get(f"AEGIS_MODEL_{self._env_key(agent.name)}")
        if exact:
            return exact

        category = self._model_category(agent)
        if category:
            routed = os.environ.get(f"AEGIS_MODEL_{category}")
            if routed:
                return routed

        return agent.model or self.default_model

    @staticmethod
    def _env_key(name: str) -> str:
        return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")

    @staticmethod
    def _model_category(agent: Agent) -> str:
        name = agent.name.lower()
        if name.endswith("_hunter"):
            # Exact category lets you put GPT-5.5 on injection/authz but cheaper
            # models on lower-risk hunters if desired.
            exact = name.replace("_hunter", "").upper()
            if os.environ.get(f"AEGIS_MODEL_{exact}"):
                return exact
            return "HUNTER"
        for prefix, category in (
            ("orchestrator", "ORCHESTRATOR"),
            ("recon", "RECON"),
            ("vuln", "VULN"),
            ("exploit", "EXPLOIT"),
            ("report", "REPORT"),
        ):
            if name.startswith(prefix):
                return category
        return ""

    def _backend_for_model(self, model: str) -> str:
        if self.llm_backend in ("anthropic", "litellm"):
            return self.llm_backend
        # Auto mode: preserve the native Anthropic path for existing Claude
        # deployments unless the model is clearly routed through another
        # provider (e.g. openai/gpt-5.5, gemini/gemini-2.5-pro, bedrock/...).
        if model.startswith("claude-") and self.client is not None:
            return "anthropic"
        return "litellm"

    def _ensure_model_available(self, agent: Agent):
        model = self._resolve_model(agent)
        backend = self._backend_for_model(model)
        if backend == "anthropic":
            if self.client is None:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY not set or anthropic package unavailable"
                )
            return
        if litellm is None:
            raise RuntimeError(
                "LiteLLM backend requested but litellm is not installed. "
                "Run: pip install -r requirements.txt"
            )

    def _call_model(
        self,
        *,
        model: str,
        agent: Agent,
        system_prompt: str,
        tools_schemas: List[dict],
        messages: List[dict],
    ):
        backend = self._backend_for_model(model)
        try:
            if backend == "anthropic":
                create_fn = self.client.messages.create
                payload = {
                    "model": model,
                    "max_tokens": 8192,
                    "temperature": agent.temperature,
                    "system": system_prompt,
                    "tools": tools_schemas,
                    "messages": messages,
                }
                # anthropic 1.0 dropped temperature from Messages.create;
                # keep sending it on 0.x SDKs.
                return create_fn(**_anthropic_create_kwargs(create_fn, payload))

            return self._call_litellm(
                model=model,
                agent=agent,
                system_prompt=system_prompt,
                tools_schemas=tools_schemas,
                messages=messages,
            )
        except Exception as exc:
            if not self._should_fallback_to_ollama(model, exc):
                raise
            ollama_model = _ollama_litellm_model()
            logger.warning(
                "Cloud LLM credit/quota failure on model=%s; falling back to %s: %s",
                model, ollama_model, exc,
            )
            return self._call_litellm(
                model=ollama_model,
                agent=agent,
                system_prompt=system_prompt,
                tools_schemas=tools_schemas,
                messages=messages,
                api_base=_ollama_api_base(),
            )

    def _should_fallback_to_ollama(self, model: str, exc: BaseException) -> bool:
        if not _ollama_fallback_enabled():
            return False
        if model.startswith("ollama/") or model.startswith("ollama_chat/"):
            return False
        if not _is_credit_or_quota_error(exc):
            return False
        if litellm is None:
            logger.warning(
                "Ollama credit fallback requested but litellm is not installed"
            )
            return False
        if not _ollama_is_reachable():
            logger.warning(
                "Ollama credit fallback requested but daemon not reachable at %s",
                _ollama_api_base(),
            )
            return False
        return True

    def _call_litellm(
        self,
        *,
        model: str,
        agent: Agent,
        system_prompt: str,
        tools_schemas: List[dict],
        messages: List[dict],
        api_base: Optional[str] = None,
    ):
        """Call any LiteLLM-supported provider and normalize to Anthropic-like blocks."""
        llm_messages = self._to_litellm_messages(system_prompt, messages)
        llm_tools = self._to_litellm_tools(tools_schemas)

        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": llm_messages,
            "tools": llm_tools or None,
            "max_tokens": 8192,
            "temperature": agent.temperature,
        }
        if api_base:
            kwargs["api_base"] = api_base

        response = litellm.completion(**kwargs)

        choice = response.choices[0]
        message = choice.message
        content_blocks = []
        if getattr(message, "content", None):
            content_blocks.append(
                SimpleNamespace(type="text", text=message.content)
            )

        for call in getattr(message, "tool_calls", None) or []:
            function = call.function
            try:
                args = json.loads(function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            content_blocks.append(
                SimpleNamespace(
                    type="tool_use",
                    id=call.id,
                    name=function.name,
                    input=args,
                )
            )

        usage = getattr(response, "usage", None) or SimpleNamespace()
        return SimpleNamespace(
            content=content_blocks,
            stop_reason=getattr(choice, "finish_reason", ""),
            usage=SimpleNamespace(
                input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                output_tokens=getattr(usage, "completion_tokens", 0) or 0,
                cache_read_input_tokens=0,
            ),
        )

    @staticmethod
    def _to_litellm_tools(tools_schemas: List[dict]) -> List[dict]:
        """Convert Anthropic-style tool schemas to OpenAI/LiteLLM schemas."""
        return [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {"type": "object"}),
                },
            }
            for tool in tools_schemas
        ]

    def _to_litellm_messages(
        self, system_prompt: str, messages: List[dict],
    ) -> List[dict]:
        """Convert internal Anthropic-style history to LiteLLM chat history."""
        out = [{"role": "system", "content": system_prompt}]
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")

            if role == "assistant" and isinstance(content, list):
                text_parts = []
                tool_calls = []
                for block in content:
                    btype = getattr(block, "type", None)
                    if btype == "text":
                        text_parts.append(getattr(block, "text", ""))
                    elif btype == "tool_use":
                        tool_calls.append({
                            "id": getattr(block, "id", ""),
                            "type": "function",
                            "function": {
                                "name": getattr(block, "name", ""),
                                "arguments": json.dumps(
                                    getattr(block, "input", {}) or {}
                                ),
                            },
                        })
                item = {"role": "assistant", "content": "\n".join(text_parts) or None}
                if tool_calls:
                    item["tool_calls"] = tool_calls
                out.append(item)
                continue

            if role == "user" and isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        out.append({
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id", ""),
                            "content": block.get("content", ""),
                        })
                continue

            out.append({"role": role, "content": content})
        return out

    def _execute_tool(
        self, agent: Agent, tool_name: str, arguments: dict, tool_use_id: str,
    ) -> str:
        """Execute a tool call with guardrails (legacy + Aegis Praetorium) and tracing."""

        if tool_name.startswith("handoff_to_"):
            return json.dumps({"status": "handoff_initiated", "target": tool_name})

        tool_def = self.registry.get(tool_name)
        if not tool_def:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        # Legacy guardrail engine (kept as defense in depth; covers reverse-shell
        # and base64-encoded payload patterns that Aegis Lictor doesn't model).
        violation = self.guardrails.check_tool_call(
            tool_name, arguments, tool_def.risk_level,
        )
        if violation:
            self.tracer.record_guardrail_block(violation.rule, tool_name)
            logger.warning(f"BLOCKED by guardrail: {violation.description}")
            return json.dumps({
                "error": "blocked_by_guardrail",
                "rule": violation.rule,
                "description": violation.description,
            })

        # ── Aegis Praetorium: Censor (input validation) ────────────────────
        org_id_env = os.environ.get("ASM_ORGANIZATION_ID")
        org_id = int(org_id_env) if (org_id_env or "").isdigit() else None
        if _AEGIS_AVAILABLE and get_praetorium_config().censor_enabled:
            verdict = get_censor().validate(tool_name, arguments)
            if not verdict.ok:
                self.tracer.record_guardrail_block("aegis_censor", tool_name)
                logger.warning(f"AEGIS CENSOR BLOCK: {verdict.error}")
                return json.dumps({
                    "error": "blocked_by_aegis_censor",
                    "description": verdict.error,
                })

        # ── Aegis Praetorium: Lictor pre-hooks (SSRF, scope, rate limit, …) ─
        if _AEGIS_AVAILABLE and get_praetorium_config().lictor_enabled:
            string_values = [str(v) for v in arguments.values() if isinstance(v, str)]
            ctx = LictorHookContext(
                tool_name=tool_name,
                args="",
                parsed_args=string_values,
                command=[tool_name, *string_values],
                inspectable_text=json.dumps(arguments, default=str),
                org_id=org_id,
                user_id=None,
                session_id=os.environ.get("ASM_AGENT_ID"),
            )
            pre = get_lictor().run_pre(ctx)
            if not pre.allowed:
                self.tracer.record_guardrail_block("aegis_lictor", tool_name)
                logger.warning(f"AEGIS LICTOR BLOCK: {pre.reason}")
                return json.dumps({
                    "error": "blocked_by_aegis_lictor",
                    "description": pre.reason,
                })

        with self.tracer.span(
            tool_name, "tool_call",
            agent_name=agent.name,
            arguments=arguments,
            risk_level=tool_def.risk_level,
            category=tool_def.category,
        ) as span:
            logger.info(f"[{agent.name}] Calling: {tool_name}({json.dumps(arguments)[:200]})")
            start = time.time()
            result = self.registry.execute(tool_name, arguments)
            elapsed = time.time() - start
            if span:
                span.attributes["duration_sec"] = round(elapsed, 1)
                span.attributes["result_length"] = len(result)
            logger.info(f"[{agent.name}] {tool_name} completed in {elapsed:.1f}s ({len(result)} chars)")

        # ── Aegis Praetorium: Lictor post-hooks (audit log, hard-cap clip) ──
        if _AEGIS_AVAILABLE and get_praetorium_config().lictor_enabled:
            post_ctx = LictorPostHookContext(
                tool_name=tool_name,
                args="",
                command=[tool_name],
                result={"success": True, "output": result, "error": None, "exit_code": 0},
                duration_ms=elapsed * 1000.0,
                org_id=org_id,
                session_id=os.environ.get("ASM_AGENT_ID"),
            )
            post = get_lictor().run_post(post_ctx)
            if post.modified_result is not None:
                result = post.modified_result.get("output", result)

        # ── Aegis Praetorium: Augur (semantic output filter + next-step pivots) ─
        if _AEGIS_AVAILABLE and get_praetorium_config().augur_enabled and result:
            try:
                cap = get_praetorium_config().tool_output_max_chars
                reading = get_augur().interpret(tool_name, result, max_chars=cap)
            except Exception as e:
                logger.warning(f"Augur interpret failed for {tool_name}: {e}")
                reading = None
            if reading is not None:
                next_steps = [ns.to_dict() for ns in reading.next_steps]
                if next_steps:
                    logger.info(
                        "Augur produced %d next-step pivot(s) for %s: %s",
                        len(next_steps), tool_name,
                        ", ".join(ns["tool_name"] for ns in next_steps),
                    )
                augur_payload = {
                    "summary": reading.summary,
                    "kept": reading.kept,
                    "dropped": reading.dropped,
                    "actionable_signals": reading.actionable_signals,
                    "next_steps": next_steps,
                    "filtered_output": reading.to_text(),
                }
                # Return a JSON envelope so the LLM sees both the filtered text
                # AND the structured next_steps it can choose to follow up on.
                return json.dumps({"output": reading.to_text(), "augur": augur_payload})

        # ── Native distiller: standalone signal extraction ────────────────
        # Runs only when Aegis Praetorium/Augur isn't on the path (standalone
        # run_pentest.py / harness). Mirrors the Augur envelope so the fireteam
        # unwraps it identically, and — unlike a blind head-truncation — keeps
        # finding-bearing JSON valid so no findings are lost at fan-in.
        augur_active = _AEGIS_AVAILABLE and get_praetorium_config().augur_enabled
        if not augur_active and result:
            try:
                reading = get_distiller().interpret(tool_name, result, max_chars=50_000)
            except Exception as e:  # never let distillation break a tool call
                logger.warning("distiller failed for %s: %s", tool_name, e)
                reading = None
            if reading is not None:
                if reading.next_steps:
                    logger.info(
                        "distiller produced %d next-step pivot(s) for %s: %s",
                        len(reading.next_steps), tool_name,
                        ", ".join(ns.tool_name for ns in reading.next_steps),
                    )
                if reading.injection:
                    self._record_injection_attempt(tool_name, reading.injection)
                self._register_block_signal(
                    self._is_blocked_response(result) or reading.defense_detected
                )
                return json.dumps({
                    "output": reading.to_text(),
                    "augur": reading.to_payload(),
                })

        if len(result) > 50_000:
            result = result[:50_000] + "\n...[truncated]"

        self._register_block_signal(self._is_blocked_response(result))
        return result

    def _inject_operator_directives(self, tool_results: list, agent: Agent) -> None:
        """Append any pending HITL operator directives to the tool-result user
        turn (keeps role alternation) so the agent adapts mid-run."""
        if self.hitl is None:
            return
        try:
            directives = self.hitl.poll_all()
        except Exception as e:  # steering must never break the loop
            logger.warning("hitl poll failed: %s", e)
            return
        if not directives:
            return
        from agent.hitl import format_directive
        for d in directives:
            logger.info("[%s] operator directive injected: %s", agent.name, d[:200])
            tool_results.append({"type": "text", "text": format_directive(d)})
            try:
                from agent.brain import get_brain
                brain = get_brain()
                if brain is not None:
                    brain.add_note(f"Operator steering: {d[:400]}")
                    brain.save()
            except Exception:
                pass

    def _record_injection_attempt(self, tool_name: str, verdict: dict) -> None:
        """Log and persist a prompt-injection attempt seen in tool output."""
        cats = ", ".join(verdict.get("categories", []))
        logger.warning(
            "PROMPT-INJECTION in %s output (severity=%s): %s",
            tool_name, verdict.get("severity"), cats,
        )
        try:
            from agent.brain import get_brain
            brain = get_brain()
            if brain is not None:
                brain.add_note(
                    f"Prompt-injection attempt in {tool_name} output "
                    f"(severity={verdict.get('severity')}, {cats}) — treated as "
                    "untrusted data. Target content may be adversarial."
                )
                brain.save()
        except Exception:  # best effort — never break a tool call
            pass

    def _register_block_signal(self, blocked: bool) -> None:
        """Circuit breaker: back off after 5 consecutive WAF/rate-limit blocks."""
        if blocked:
            self._consecutive_blocks += 1
            if self._consecutive_blocks >= 5:
                logger.warning(
                    "Circuit breaker OPEN after %d consecutive blocks — "
                    "backing off %.0fs before next tool call",
                    self._consecutive_blocks,
                    self._circuit_backoff_sec,
                )
                time.sleep(self._circuit_backoff_sec)
                self._consecutive_blocks = 0
        else:
            self._consecutive_blocks = 0

    @staticmethod
    def _is_blocked_response(result: str) -> bool:
        """Return True if the tool result looks like a WAF or rate-limit rejection."""
        if not result:
            return False
        try:
            data = json.loads(result)
        except (json.JSONDecodeError, TypeError, ValueError):
            return False
        status = data.get("status") or data.get("status_code")
        if isinstance(status, int) and status in (403, 429, 503):
            return True
        lowered = result.lower()
        return any(
            token in lowered
            for token in ("403 forbidden", "429 too many", "rate limit", "rate-limit",
                          "blocked by waf", "access denied", "cloudflare ray id",
                          "waf block", "security check")
        )
