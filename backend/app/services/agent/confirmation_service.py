"""
Per-tool confirmation gate for the ASM agent.

Workflow
--------
1. Before the agent executes any tool, ``gate(tool_name, tool_args)`` is
   called. It consults the per-org agent settings policy and returns one of:

        {"decision": "auto"}   - proceed immediately
        {"decision": "deny",   ...} - refuse; error message included
        {"decision": "confirm",
         "token": "<uuid>", ...} - register a pending request and surface
                                   it back to the UI for approval

2. The frontend (or a human operator via ``POST /agent/confirmations``) then
   approves or denies the token. The agent polls ``is_approved(token)`` and
   proceeds or halts accordingly.

The in-memory store is keyed by ``organization_id + session_id + token``
so a single worker sees a consistent view; for multi-worker deployments the
store can be swapped for Redis without touching callers.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any, Optional

from app.db.database import SessionLocal
from app.models.project_settings import (
    MODULE_AGENT,
    MODULE_RULES_OF_ENGAGEMENT,
    ProjectSettings,
)

logger = logging.getLogger(__name__)


# Set by the orchestrator for autonomous ("agent") runs. When enabled, tools
# whose policy decision is "confirm" are auto-approved instead of pausing for an
# operator (which would just stall an unattended turn until the 5-minute
# confirmation timeout). Explicit "deny" always still wins. Autonomous mode is
# unattended by design — it also auto-approves phase transitions — so this keeps
# the confirmation gate meaningful for interactive ("assist") sessions while
# letting the agent actually run active testing on its own.
_autonomous_mode: ContextVar[bool] = ContextVar("agent_autonomous_mode", default=False)


def set_autonomous_mode(enabled: bool) -> Any:
    """Enable/disable auto-approval of confirm-gated tools for this context.

    Returns the ContextVar token so callers can reset it if desired.
    """
    return _autonomous_mode.set(bool(enabled))


def autonomous_mode_enabled() -> bool:
    return bool(_autonomous_mode.get())


READONLY_TOOLS = {
    "query_assets",
    "query_vulnerabilities",
    "query_ports",
    "query_technologies",
    "query_graph",
    "get_asset_details",
    "search_cve",
    "analyze_attack_surface",
    "get_notes",
    "web_search",
    "search_memory",
    "search_knowledge_base",
    "query_prior_sessions",
    "get_threat_model",
    "get_coverage",
    "get_engagement_brain",
    "get_methodology_progress",
}

# Passive / light recon: always auto-allow unless explicitly denied.
# Prevents assessment kickoff from stalling on approve-every-httpx.
SAFE_RECON_TOOLS = {
    "execute_httpx",
    "execute_dnsx",
    "execute_wafw00f",
    "execute_wappalyzer",
    "execute_whatweb",
    "execute_curl",
    "probe_registry_anonymous",
    "execute_katana",
    "execute_gau",
    "execute_waybackurls",
    "execute_crtsh",
    "execute_crt_name",
    "execute_subfinder",
    "execute_subfaster",
    "execute_deep_crawl",
    "execute_interceptor",
    "execute_feroxbuster",  # bounded wordlist streams (app-dirs-common)
    "spawn_recon_workers",
    "wait_recon_workers",
    "list_recon_workers",
    "sync_engagement_brain",
    "build_threat_model",
    "get_threat_model",
    "update_threat_model",
    "submit_finding_candidate",
    "independent_verify",
    "record_verify_verdict",
    "record_surface_coverage",
    "get_coverage",
    "httpx_help",
    "dnsx_help",
    "mutate_list",
    "list_captured_requests",
    "fetch_lazy_chunks",
    "extract_js_endpoints",
    "scan_js_sinks",
    "fingerprint_api",
}


@dataclass
class PendingConfirmation:
    token: str
    tool_name: str
    tool_args: dict
    organization_id: Optional[int]
    session_id: Optional[str]
    created_at: float
    status: str = "pending"  # pending | approved | denied | expired
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None
    reason: Optional[str] = None
    timeout_seconds: int = 300
    waiters: list[asyncio.Future] = field(default_factory=list)


class ConfirmationStore:
    def __init__(self) -> None:
        self._items: dict[str, PendingConfirmation] = {}
        self._lock = threading.Lock()

    def create(
        self,
        tool_name: str,
        tool_args: dict,
        organization_id: Optional[int],
        session_id: Optional[str],
        timeout_seconds: int = 300,
    ) -> PendingConfirmation:
        token = uuid.uuid4().hex
        pc = PendingConfirmation(
            token=token,
            tool_name=tool_name,
            tool_args=tool_args,
            organization_id=organization_id,
            session_id=session_id,
            created_at=time.time(),
            timeout_seconds=timeout_seconds,
        )
        with self._lock:
            self._items[token] = pc
        return pc

    def get(self, token: str) -> Optional[PendingConfirmation]:
        with self._lock:
            return self._items.get(token)

    def decide(
        self,
        token: str,
        approved: bool,
        decided_by: str = "",
        reason: str = "",
    ) -> Optional[PendingConfirmation]:
        with self._lock:
            pc = self._items.get(token)
            if not pc:
                return None
            pc.status = "approved" if approved else "denied"
            pc.decided_by = decided_by
            pc.decided_at = time.time()
            pc.reason = reason
            for fut in pc.waiters:
                if not fut.done():
                    fut.set_result(approved)
            pc.waiters.clear()
            return pc

    def list_pending(
        self, organization_id: Optional[int] = None, session_id: Optional[str] = None
    ) -> list[PendingConfirmation]:
        with self._lock:
            items = list(self._items.values())
        out = []
        now = time.time()
        for pc in items:
            if pc.status != "pending":
                continue
            if (now - pc.created_at) > pc.timeout_seconds:
                pc.status = "expired"
                continue
            if organization_id is not None and pc.organization_id != organization_id:
                continue
            if session_id is not None and pc.session_id != session_id:
                continue
            out.append(pc)
        return out

    async def wait_for(self, token: str, timeout: Optional[float] = None) -> Optional[bool]:
        with self._lock:
            pc = self._items.get(token)
            if not pc:
                return None
            if pc.status == "approved":
                return True
            if pc.status in ("denied", "expired"):
                return False
            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            pc.waiters.append(fut)
            effective = timeout if timeout is not None else pc.timeout_seconds
        try:
            return await asyncio.wait_for(fut, timeout=effective)
        except asyncio.TimeoutError:
            with self._lock:
                pc.status = "expired"
            return False


_STORE: Optional[ConfirmationStore] = None


def get_store() -> ConfirmationStore:
    global _STORE
    if _STORE is None:
        _STORE = ConfirmationStore()
    return _STORE


# ---------------------------------------------------------------------------
# Policy resolution
# ---------------------------------------------------------------------------


def _load_policy(organization_id: Optional[int]) -> dict:
    if organization_id is None:
        return {}
    db = SessionLocal()
    try:
        return ProjectSettings.get_config(db, organization_id, MODULE_AGENT) or {}
    finally:
        db.close()


def _roe_requires_confirmation(organization_id: Optional[int]) -> bool:
    if organization_id is None:
        return False
    db = SessionLocal()
    try:
        cfg = ProjectSettings.get_config(db, organization_id, MODULE_RULES_OF_ENGAGEMENT)
        return bool(cfg.get("enabled")) and bool(cfg.get("requires_agent_confirmation", True))
    finally:
        db.close()


def _resolve_decision(policy_map: dict, tool_name: str) -> str:
    """Longest-prefix/most-specific match wins."""
    if not policy_map:
        return "auto"
    # Exact first
    if tool_name in policy_map:
        return policy_map[tool_name]
    best: tuple[int, str] = (-1, "auto")
    for pattern, decision in policy_map.items():
        if fnmatch(tool_name, pattern):
            if len(pattern) > best[0]:
                best = (len(pattern), decision)
    return best[1]


# ---------------------------------------------------------------------------
# Public gate
# ---------------------------------------------------------------------------


async def gate(
    tool_name: str,
    tool_args: dict,
    organization_id: Optional[int],
    session_id: Optional[str],
) -> dict[str, Any]:
    """
    Decide whether a tool invocation should proceed.

    Returns one of:

        {"decision": "auto"}
        {"decision": "deny", "reason": "..."}
        {"decision": "confirm", "token": "...", "tool_name": "...",
         "tool_args": {...}, "expires_at": <epoch>}

    If caller previously obtained a token and is re-invoking with
    ``_confirm_token`` in ``tool_args``, the gate checks the approval state
    and either returns ``{"decision": "auto"}`` (approved) or raises back
    a fresh ``confirm`` payload if the token is unknown/expired.
    """
    existing_token = tool_args.get("_confirm_token") if isinstance(tool_args, dict) else None

    policy_cfg = _load_policy(organization_id)
    if not policy_cfg.get("tool_confirmation_enabled", True):
        if existing_token:
            tool_args.pop("_confirm_token", None)
        return {"decision": "auto"}

    readonly_auto = policy_cfg.get("tool_confirmation_readonly_auto_allow", True)
    if readonly_auto and tool_name in READONLY_TOOLS:
        if existing_token:
            tool_args.pop("_confirm_token", None)
        return {"decision": "auto"}

    policy_map = policy_cfg.get("tool_confirmation_policy") or {}
    decision = _resolve_decision(policy_map, tool_name)

    # Light recon must not block assessment kickoff behind approve dialogs.
    # Explicit "deny" still wins; everything else becomes auto for SAFE_RECON_TOOLS.
    if tool_name in SAFE_RECON_TOOLS and decision != "deny":
        decision = "auto"

    # RoE escalates "auto" -> "confirm" for non-readonly tools when enabled,
    # but keep SAFE_RECON_TOOLS auto so httpx/dns fingerprinting can start.
    roe_escalated = False
    if (
        decision == "auto"
        and _roe_requires_confirmation(organization_id)
        and tool_name not in READONLY_TOOLS
        and tool_name not in SAFE_RECON_TOOLS
    ):
        decision = "confirm"
        roe_escalated = True

    if decision == "deny":
        return {
            "decision": "deny",
            "reason": f"Tool '{tool_name}' is denied by the organization's agent policy.",
        }

    # Autonomous ("agent") runs auto-approve policy "confirm" decisions so an
    # unattended engagement doesn't stall waiting for an operator who will never
    # answer. Guardrails preserved: explicit "deny" (above) still wins, an
    # RoE-mandated confirmation is a compliance control and is NOT bypassed, and
    # operators can turn this off via the agent config flag.
    if (
        decision == "confirm"
        and _autonomous_mode.get()
        and not roe_escalated
        and policy_cfg.get("agent_autonomous_auto_approve", True)
    ):
        logger.info(
            "Autonomous agent mode: auto-approving confirm-gated tool %s", tool_name
        )
        if existing_token:
            tool_args.pop("_confirm_token", None)
        return {"decision": "auto"}

    if decision == "auto":
        if existing_token:
            tool_args.pop("_confirm_token", None)
        return {"decision": "auto"}

    # decision == "confirm" ----------------------------------------------
    store = get_store()
    if existing_token:
        pc = store.get(existing_token)
        if pc and pc.status == "approved":
            tool_args.pop("_confirm_token", None)
            return {"decision": "auto"}
        if pc and pc.status == "denied":
            return {
                "decision": "deny",
                "reason": pc.reason or "Operator denied this tool invocation.",
            }
        if pc and pc.status == "expired":
            return {
                "decision": "deny",
                "reason": "Confirmation token expired; request a new one.",
            }
        # Unknown token → create a fresh request below.

    sanitized = {k: v for k, v in (tool_args or {}).items() if k != "_confirm_token"}
    pc = store.create(
        tool_name=tool_name,
        tool_args=sanitized,
        organization_id=organization_id,
        session_id=session_id,
        timeout_seconds=int(policy_cfg.get("tool_confirmation_timeout_seconds", 300)),
    )
    logger.info(
        "Agent confirmation requested: tool=%s org=%s session=%s token=%s",
        tool_name, organization_id, session_id, pc.token,
    )
    return {
        "decision": "confirm",
        "token": pc.token,
        "tool_name": tool_name,
        "tool_args": sanitized,
        "expires_at": pc.created_at + pc.timeout_seconds,
    }


async def wait_for_decision(token: str, timeout: Optional[float] = None) -> bool:
    """Block until ``token`` is approved/denied/expired. Returns True iff approved."""
    return bool(await get_store().wait_for(token, timeout=timeout))
