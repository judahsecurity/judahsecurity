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
import json
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


# Set by the orchestrator for autonomous ("agent") runs. An organization may
# explicitly enable auto-approval of policy "confirm" decisions, but the
# default is to pause for an analyst.
_autonomous_mode: ContextVar[bool] = ContextVar("agent_autonomous_mode", default=False)
_scoped_browser_read_origin: ContextVar[tuple[str, str, int] | None] = ContextVar(
    "agent_scoped_browser_read_origin", default=None,
)


def set_autonomous_mode(enabled: bool) -> Any:
    """Enable/disable auto-approval of confirm-gated tools for this context.

    Returns the ContextVar token so callers can reset it if desired.
    """
    return _autonomous_mode.set(bool(enabled))


def autonomous_mode_enabled() -> bool:
    return bool(_autonomous_mode.get())


def set_scoped_browser_reads(enabled: bool, target: str = "") -> None:
    """Arm an operator-selected, exact-origin browser read grant for this run."""
    approved_origin = None
    if enabled and target:
        from app.services.agent.evidence_store import origin

        try:
            approved_origin = origin(target)
        except ValueError:
            pass
    _scoped_browser_read_origin.set(approved_origin)


def scoped_browser_read_granted(tool_args: dict, *, allow_approved_paths: bool = False) -> bool:
    """Only simple anonymous browser observations qualify for unattended reads."""
    approved_origin = _scoped_browser_read_origin.get()
    if not _autonomous_mode.get() or approved_origin is None:
        return False
    raw = tool_args.get("args") if isinstance(tool_args, dict) else None
    try:
        spec = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return False
    if not isinstance(spec, dict) or not set(spec) <= {
        "actions", "allowed_origin", "allowed_methods",
        "approved_post_paths", "approved_delete_paths", "block_web_sockets",
    }:
        return False
    if set(spec.get("allowed_methods") or []) != {"GET", "HEAD"}:
        return False
    if not allow_approved_paths and (spec.get("approved_post_paths")
                                     or spec.get("approved_delete_paths")):
        return False
    if not allow_approved_paths and spec.get("block_web_sockets") is not True:
        return False
    from app.services.agent.evidence_store import origin

    try:
        if origin(spec.get("allowed_origin") or "") != approved_origin:
            return False
    except (TypeError, ValueError):
        return False
    actions = spec.get("actions")
    if not isinstance(actions, list) or not 1 <= len(actions) <= 10:
        return False
    allowed_keys = {
        "navigate": {"action", "url"},
        "check_response": {"action", "url", "expected_status", "description"},
        "get_source": {"action"},
        "screenshot": {"action", "full_page"},
        "wait": {"action", "ms"},
    }
    has_navigation = False
    total_wait_ms = 0
    for action in actions:
        if not isinstance(action, dict):
            return False
        kind = action.get("action")
        if kind not in allowed_keys or not set(action) <= allowed_keys[kind]:
            return False
        if kind in {"navigate", "check_response"}:
            try:
                if origin(action.get("url") or "") != approved_origin:
                    return False
            except (TypeError, ValueError):
                return False
            has_navigation = True
        if kind == "wait":
            ms = action.get("ms", 2000)
            if type(ms) is not int or not 0 <= ms <= 5000:
                return False
            total_wait_ms += ms
    return has_navigation and total_wait_ms <= 10000


READONLY_TOOLS = {
    "lookup_component_vulns",
    "record_recon_inventory",
    "get_parameter_inventory",
    "get_api_operation_inventory",
    "scoped_assessment_status",
    "scoped_assessment_memory",
    "get_assessment_coverage", "map_application_traffic", "generate_authorization_matrix",
    "query_assets",
    "query_vulnerabilities",
    "query_ports",
    "query_technologies",
    "query_graph",
    "get_asset_details",
    "search_cve",
    "search_vulnx",
    "vulnx_query",
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
    "plan_intruder_mutations",
    # Brain-only bookkeeping (no target traffic).
    "suggest_capability_chains",
    "analyze_screenshot",  # reads a local screenshot; no target traffic
    "describe_tools",
    # Background tool execution control: reads, waits and cancels only.
    "get_tool_execution",
    "wait_tool_execution",
    "cancel_tool_execution",
    "list_tool_executions",
}

# Passive / light recon: always auto-allow unless explicitly denied.
# Prevents assessment kickoff from stalling on approve-every-httpx.
SAFE_RECON_TOOLS = {
    "scoped_assessment_observe",
    "scoped_assessment_plan",
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
    "plan_intruder_mutations",
    "fetch_lazy_chunks",
    "extract_js_endpoints",
    "scan_js_sinks",
    "fingerprint_api",
    "fingerprint_passive_stack",
    "check_cve_applicability",
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
    ai_review: Optional[dict] = None


def preview_tool_args(tool_args: dict) -> dict:
    """Show the action being approved without disclosing browser session state."""
    from app.services.agent.orchestrator import redact_tool_args

    return redact_tool_args(tool_args or {})


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
            if pc.status != "pending" or time.time() >= pc.created_at + pc.timeout_seconds:
                if pc.status == "pending":
                    pc.status = "expired"
                return None
            pc.status = "approved" if approved else "denied"
            pc.decided_by = decided_by
            pc.decided_at = time.time()
            pc.reason = reason
            waiters = list(pc.waiters)
            pc.waiters.clear()
        # The FastAPI decision route is synchronous and runs in a worker
        # thread. asyncio futures must be completed on their owning loop.
        for fut in waiters:
            fut.get_loop().call_soon_threadsafe(
                lambda waiter=fut: waiter.set_result(approved)
                if not waiter.done() else None
            )
        return pc

    def list_pending(
        self, organization_id: Optional[int] = None, session_id: Optional[str] = None
    ) -> list[PendingConfirmation]:
        with self._lock:
            out = []
            now = time.time()
            for pc in self._items.values():
                if pc.status != "pending":
                    continue
                if now >= pc.created_at + pc.timeout_seconds:
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
            if time.time() >= pc.created_at + pc.timeout_seconds:
                pc.status = "expired"
                return False
            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            pc.waiters.append(fut)
            remaining = max(0.0, pc.created_at + pc.timeout_seconds - time.time())
            effective = min(timeout, remaining) if timeout is not None else remaining
        try:
            return await asyncio.wait_for(fut, timeout=effective)
        except asyncio.TimeoutError:
            with self._lock:
                if pc.status == "pending":
                    pc.status = "expired"
                return pc.status == "approved"
        finally:
            with self._lock:
                if fut in pc.waiters:
                    pc.waiters.remove(fut)


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


def _is_bounded_nuclei_recon(tool_name: str, tool_args: Optional[dict]) -> bool:
    """Informational Nuclei recon (tech/exposure/panel) is light recon, not CVE spray."""
    if tool_name != "execute_nuclei":
        return False
    args = ""
    if isinstance(tool_args, dict):
        args = str(tool_args.get("args") or "")
    try:
        from app.services.agent.recon_workers import is_bounded_nuclei_recon_args

        return is_bounded_nuclei_recon_args(args)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public gate
# ---------------------------------------------------------------------------


def _is_login_crawl(tool_name: str, tool_args: dict) -> bool:
    """A crawl with a login action must reach the analyst gate."""
    if tool_name not in {"execute_interceptor", "execute_deep_crawl"}:
        return False
    raw = (tool_args or {}).get("args")
    try:
        options = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return False
    return isinstance(options, dict) and bool(options.get("login"))


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
    from app.services.agent.pilot_policy import PILOT_NETWORK_TOOLS, current_pilot
    pilot = current_pilot()
    pilot_network_action = pilot is not None and tool_name in PILOT_NETWORK_TOOLS
    login_crawl = _is_login_crawl(tool_name, tool_args)
    if not policy_cfg.get("tool_confirmation_enabled", True) and not pilot_network_action and not login_crawl:
        if existing_token:
            tool_args.pop("_confirm_token", None)
        return {"decision": "auto"}

    readonly_auto = policy_cfg.get("tool_confirmation_readonly_auto_allow", True)
    if readonly_auto and tool_name in READONLY_TOOLS and not pilot_network_action:
        if existing_token:
            tool_args.pop("_confirm_token", None)
        return {"decision": "auto"}

    policy_map = policy_cfg.get("tool_confirmation_policy") or {}
    decision = _resolve_decision(policy_map, tool_name)

    nuclei_recon = _is_bounded_nuclei_recon(tool_name, tool_args)

    # Light recon must not block assessment kickoff behind approve dialogs.
    # Explicit "deny" still wins; everything else becomes auto for SAFE_RECON_TOOLS.
    # Bounded informational Nuclei (tech/exposure/panel) is the same class as httpx.
    if (tool_name in SAFE_RECON_TOOLS or nuclei_recon) and decision != "deny" and not login_crawl:
        decision = "auto"

    # RoE escalates "auto" -> "confirm" for non-readonly tools when enabled,
    # but keep SAFE_RECON_TOOLS auto so httpx/dns fingerprinting can start.
    roe_escalated = False
    if (
        decision == "auto"
        and _roe_requires_confirmation(organization_id)
        and tool_name not in READONLY_TOOLS
        and tool_name not in SAFE_RECON_TOOLS
        and not nuclei_recon
    ):
        decision = "confirm"
        roe_escalated = True

    # Every network-capable action in a bounded pilot goes to the analyst,
    # including tools normally covered by an organization auto policy. The
    # request-level budget still applies after approval.
    if login_crawl and decision != "deny":
        decision = "confirm"
        roe_escalated = True

    if pilot_network_action and decision != "deny":
        decision = "confirm"
        roe_escalated = True

    if decision == "deny":
        return {
            "decision": "deny",
            "reason": f"Tool '{tool_name}' is denied by the organization's agent policy.",
        }

    # An explicit run grant removes repetitive prompts only for anonymous,
    # same-origin GET/HEAD browser observations. RoE and pilot approvals win.
    if (
        tool_name == "execute_browser"
        and decision == "confirm"
        and not pilot_network_action
        and not _roe_requires_confirmation(organization_id)
        and not (tool_args.get("_confirm_token") if isinstance(tool_args, dict) else None)
        and scoped_browser_read_granted(tool_args)
    ):
        logger.info("Scoped browser read grant: auto-approving exact-origin observation")
        return {"decision": "auto"}

    # Autonomous ("agent") runs auto-approve policy "confirm" decisions so an
    # unattended engagement doesn't stall waiting for an operator who will never
    # answer. Guardrails preserved: explicit "deny" (above) still wins, an
    # RoE-mandated confirmation is a compliance control and is NOT bypassed, and
    # operators can turn this off via the agent config flag.
    if (
        decision == "confirm"
        and _autonomous_mode.get()
        and not roe_escalated
        and not _roe_requires_confirmation(organization_id)
        and tool_name not in {"run_intruder_batch"}
        and policy_cfg.get("agent_autonomous_auto_approve", False)
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
    timeout_seconds = int(policy_cfg.get("tool_confirmation_timeout_seconds", 300))
    if pilot_network_action:
        # Slow model turns can outlast the normal five-minute review window.
        # A Pilot still requires explicit approval, and its own deadline is
        # the latest time an outstanding request may remain actionable.
        remaining_seconds = max(1, int(pilot.expires_at_ms / 1000 - time.time()))
        timeout_seconds = min(max(timeout_seconds, 900), remaining_seconds)
    pc = store.create(
        tool_name=tool_name,
        tool_args=sanitized,
        organization_id=organization_id,
        session_id=session_id,
        timeout_seconds=timeout_seconds,
    )
    logger.info(
        "Agent confirmation requested: tool=%s org=%s session=%s token=%s",
        tool_name, organization_id, session_id, pc.token,
    )
    from app.services.agent.approval_reviewer import eligible as ai_eligible

    return {
        "decision": "confirm",
        "token": pc.token,
        "tool_name": tool_name,
        "tool_args": sanitized,
        "expires_at": pc.created_at + pc.timeout_seconds,
        # RoE-mandated, login-crawl and pilot approvals always go to a human.
        "ai_review": (not roe_escalated and not pilot_network_action and not login_crawl
                      and ai_eligible(tool_name, policy_cfg)),
    }


async def wait_for_decision(token: str, timeout: Optional[float] = None) -> bool:
    """Block until ``token`` is approved/denied/expired. Returns True iff approved."""
    return bool(await get_store().wait_for(token, timeout=timeout))
