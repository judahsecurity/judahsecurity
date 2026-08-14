"""
Agent Tools

Tools for the AI agent to interact with the ASM platform.
"""

import json
import logging
import re as _re
from collections import deque
from typing import List, Optional, Dict, Any
from contextvars import ContextVar
from sqlalchemy.orm import Session

import httpx

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.vulnerability import Vulnerability, Severity
from app.models.port_service import PortService
from app.models.technology import Technology
from app.models.agent_note import AgentNote
from app.core.config import settings

# Max chars for tool output (used for truncation; align with AGENT_TOOL_OUTPUT_MAX_CHARS)
def _tool_output_max_chars() -> int:
    return getattr(settings, "AGENT_TOOL_OUTPUT_MAX_CHARS", 20000)

logger = logging.getLogger(__name__)

# Context variables for tenant isolation and session
current_user_id: ContextVar[Optional[int]] = ContextVar('current_user_id', default=None)
current_organization_id: ContextVar[Optional[int]] = ContextVar('current_organization_id', default=None)
current_session_id: ContextVar[Optional[str]] = ContextVar('current_session_id', default=None)
# Seed URL/host from the user objective — used when LLMs omit execute_* args
current_seed_target: ContextVar[Optional[str]] = ContextVar('current_seed_target', default=None)


def set_tenant_context(user_id: int, organization_id: int, session_id: Optional[str] = None) -> None:
    """Set the current tenant context for tool execution."""
    current_user_id.set(user_id)
    current_organization_id.set(organization_id)
    if session_id is not None:
        current_session_id.set(session_id)


def set_seed_target(target: Optional[str]) -> None:
    """Remember the engagement seed URL for empty execute_* arg recovery."""
    current_seed_target.set((target or "").strip() or None)


def get_tenant_context() -> tuple:
    """Get the current tenant context (user_id, organization_id)."""
    return current_user_id.get(), current_organization_id.get()


_URL_IN_TEXT_RE = _re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    _re.I,
)
_DOMAIN_IN_TEXT_RE = _re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b",
    _re.I,
)


def extract_seed_target(text: str) -> str:
    """Pull the first URL or domain from free text (user objective / tool args)."""
    if not text or not isinstance(text, str):
        return ""
    m = _URL_IN_TEXT_RE.search(text)
    if m:
        url = m.group(0).rstrip(").,;]")
        if url.lower().startswith("www."):
            url = "https://" + url
        return url
    # Prefer domains that look like real hosts (skip common words)
    skip = {"example.com", "target.com", "localhost", "github.com"}
    for m in _DOMAIN_IN_TEXT_RE.finditer(text):
        host = m.group(0).lower().rstrip(".")
        if host in skip or host.endswith(".png") or host.endswith(".jpg"):
            continue
        return f"https://{host}"
    return ""


def _default_args_for_tool(tool_name: str, target: str) -> str:
    """Build a sensible CLI args string when the LLM omits ``args``."""
    target = (target or "").strip()
    if not target:
        return ""
    # Domain-only tools
    host = target
    if "://" in host:
        try:
            from urllib.parse import urlparse
            host = urlparse(target).hostname or target
        except Exception:
            host = target.replace("https://", "").replace("http://", "").split("/")[0]

    name = tool_name.replace("execute_", "")
    if name in ("httpx",):
        return f"-u {target} -json -tech-detect -status-code -title -follow-redirects"
    if name in ("nuclei", "katana", "ffuf", "sqlmap", "dalfox", "xsstrike", "arjun", "cmseek"):
        return f"-u {target}"
    if name in ("nikto",):
        return f"-h {target} -Format json"
    if name in ("wpscan",):
        return f"--url {target} --enumerate vp,vt,u"
    if name in ("subfinder", "subfaster", "dnsx", "tldfinder"):
        return f"-d {host}"
    if name in ("naabu", "nmap", "masscan"):
        return f"-host {host}" if name == "naabu" else host
    if name in ("wafw00f", "whatweb", "wappalyzer", "testssl", "curl"):
        if name == "curl":
            return f"-sI {target}"
        if name == "whatweb":
            return f"{target} -a 1"
        return target
    if name in ("deep_crawl", "interceptor"):
        return target
    # Generic: prefer -u for HTTP-ish tools
    if any(x in name for x in ("http", "web", "crawl", "scan")):
        return f"-u {target}"
    return target


def normalize_execute_tool_args(
    tool_name: str,
    tool_args: Optional[Dict[str, Any]],
    *,
    fallback_target: str = "",
) -> Dict[str, Any]:
    """Normalize LLM tool args into MCP ``{\"args\": \"<cli>\"}`` shape.

    LLMs frequently call ``execute_httpx`` with ``{}``, ``{\"url\": \"...\"}``,
    or ``{\"args\": null}``. Empty args cause a missing-parameter failure loop.
    """
    raw = dict(tool_args or {}) if isinstance(tool_args, dict) else {}
    # Drop internal keys
    for k in list(raw.keys()):
        if k.startswith("_"):
            raw.pop(k, None)

    args_val = raw.get("args", None)

    # Already a usable CLI string
    if isinstance(args_val, str) and args_val.strip():
        return {"args": args_val.strip()}

    # args as list of tokens
    if isinstance(args_val, (list, tuple)):
        joined = " ".join(str(x).strip() for x in args_val if str(x).strip())
        if joined:
            return {"args": joined}

    # args as nested dict → flatten
    parts: List[str] = []
    source = args_val if isinstance(args_val, dict) else raw

    if isinstance(source, dict):
        for k, v in source.items():
            if k == "args" or v is None:
                continue
            sv = str(v).strip() if not isinstance(v, (list, dict)) else ""
            if isinstance(v, (list, tuple)):
                sv = " ".join(str(x).strip() for x in v if str(x).strip())
            if not sv:
                continue
            key = str(k).lower().strip()
            if key in ("url", "target", "host", "domain", "u", "uri", "website", "site"):
                if sv.startswith("-"):
                    parts.insert(0, sv)
                elif tool_name in (
                    "execute_subfinder", "execute_subfaster", "execute_dnsx", "execute_tldfinder",
                ):
                    host = sv.replace("https://", "").replace("http://", "").split("/")[0]
                    parts.insert(0, f"-d {host}")
                elif tool_name in (
                    "execute_wafw00f", "execute_whatweb", "execute_wappalyzer",
                    "execute_testssl", "execute_deep_crawl", "execute_interceptor",
                ):
                    parts.insert(0, sv if "://" in sv or tool_name == "execute_whatweb" else sv)
                elif tool_name == "execute_curl":
                    parts.insert(0, sv)
                elif tool_name == "execute_nikto":
                    parts.insert(0, f"-h {sv}")
                else:
                    parts.insert(0, f"-u {sv}" if not sv.startswith("-u") else sv)
            elif key in ("flags", "options", "arguments", "command", "cli"):
                parts.append(sv)
            elif key in ("json", "tech-detect", "status-code", "title", "silent", "follow-redirects"):
                flag = key if key.startswith("-") else f"-{key}"
                if sv.lower() in ("1", "true", "yes", ""):
                    parts.append(flag)
                else:
                    parts.append(f"{flag} {sv}")
            else:
                # Unknown keys: if value looks like a URL, treat as target
                if "://" in sv or sv.startswith("www."):
                    parts.insert(0, f"-u {sv}" if "://" in sv or tool_name.startswith("execute_http") else sv)
                elif sv.startswith("-"):
                    parts.append(sv)

    if parts:
        normalized = {"args": " ".join(parts)}
        logger.info("Normalized MCP args for %s: %s", tool_name, normalized)
        return normalized

    # Last resort: seed from fallback target / any URL buried in values
    seed = (fallback_target or "").strip()
    if not seed:
        blob = " ".join(str(v) for v in raw.values() if v is not None)
        seed = extract_seed_target(blob)
    if seed:
        default = _default_args_for_tool(tool_name, seed)
        if default:
            normalized = {"args": default}
            logger.info(
                "Filled empty MCP args for %s from seed target %s → %s",
                tool_name, seed, normalized,
            )
            return normalized

    # Keep empty args key so MCP returns a clear missing/empty error (not KeyError)
    return {"args": ""} if tool_name.startswith("execute_") else raw


def _format_vulnx_search_output(raw_json: str, query: str) -> str:
    """Format vulnx search JSON output into a compact analyst-readable summary."""
    import json as _json
    try:
        vulns = _json.loads(raw_json)
        # Handle vulnx CLI output envelope: {"vulnerabilities": [...]} or flat list
        if isinstance(vulns, dict):
            vulns = (
                vulns.get("vulnerabilities")
                or vulns.get("data")
                or vulns.get("results")
                or []
            )
        if not isinstance(vulns, list):
            return raw_json
        if not vulns:
            return f"No CVEs matched the query: '{query}'"
        lines = [f"# vulnx search — `{query}`  ({len(vulns)} results)\n"]
        for v in vulns[:20]:
            cve_id = v.get("cve_id") or v.get("CVE") or "?"
            severity = (v.get("severity") or "?").upper()
            cvss = v.get("cvss_score") or 0
            epss = v.get("epss_score") or 0
            flags = []
            if v.get("is_kev"):
                flags.append("KEV⚠️")
            if v.get("is_poc"):
                flags.append(f"PoC({v.get('poc_count',1)})")
            if v.get("is_template"):
                flags.append("nuclei")
            if v.get("is_remote"):
                flags.append("remote")
            if v.get("h1", {}).get("reports"):
                flags.append(f"h1({v['h1']['reports']})")
            desc = (v.get("description") or "")[:120]
            flag_str = "  [" + ", ".join(flags) + "]" if flags else ""
            lines.append(
                f"- **{cve_id}** {severity} CVSS:{cvss:.1f} EPSS:{epss:.3f}{flag_str}\n"
                f"  {desc}"
            )
        if len(vulns) > 20:
            lines.append(f"\n…and {len(vulns) - 20} more results")
        return "\n".join(lines)
    except Exception:
        return raw_json


class ASMToolsManager:
    """Manager for ASM platform tools accessible by the AI agent."""
    
    def __init__(self):
        self.tools = self._register_tools()
        self._mcp_server = None
        # Solomon judge receipts: validate_finding SUBMIT → create_finding gate
        self._finding_receipts: Dict[str, Dict[str, Any]] = {}
        # Live tool traces for Praetorian-style demonstrated chains
        self._recent_invocations: deque = deque(maxlen=48)
    
    def _get_mcp_server(self):
        """Lazy load MCP server."""
        if self._mcp_server is None:
            from app.services.mcp.server import get_mcp_server
            self._mcp_server = get_mcp_server()
        return self._mcp_server
    
    def _register_tools(self) -> Dict[str, callable]:
        """Register all available tools."""
        tools = {
            # ASM Query Tools
            "query_assets": self.query_assets,
            "query_vulnerabilities": self.query_vulnerabilities,
            "query_ports": self.query_ports,
            "query_technologies": self.query_technologies,
            "query_graph": self.query_graph,
            "analyze_attack_surface": self.analyze_attack_surface,
            "rank_attack_surface": self.rank_attack_surface,
            "get_asset_details": self.get_asset_details,
            "search_cve": self.search_cve,
            # Asset management
            "add_asset": self.add_asset,
            # Scan management
            "create_scan": self.create_scan,
            # Session notes and findings
            "save_note": self.save_note,
            "get_notes": self.get_notes,
            "create_finding": self.create_finding,
            "sanitize_evidence": self.sanitize_evidence,
            # LLM Red Team Scanner
            "execute_llm_red_team": self.execute_llm_red_team,
            # Garak LLM vulnerability scanner (NVIDIA) — CLI wrapper via MCP
            "execute_garak": self.execute_mcp_tool,
            "garak_help": self.execute_mcp_tool,
            # Injection testing tools (pure-Python, no external binary)
            "generate_injection_payloads": self.generate_injection_payloads,
            "discover_parameters": self.discover_parameters,
            # Auto tool selection
            "auto_select_tools": self.auto_select_tools,
            # MCP Security Tools (delegated)
            "execute_nuclei": self.execute_mcp_tool,
            "execute_naabu": self.execute_mcp_tool,
            "execute_httpx": self.execute_mcp_tool,
            "execute_subfinder": self.execute_mcp_tool,
            "execute_subfaster": self.execute_mcp_tool,
            "subfaster_help": self.execute_mcp_tool,
            "execute_dnsx": self.execute_mcp_tool,
            "execute_katana": self.execute_mcp_tool,
            "execute_curl": self.execute_mcp_tool,
            "execute_tldfinder": self.execute_mcp_tool,
            "execute_atlas": self.execute_mcp_tool,
            "execute_argus": self.execute_mcp_tool,
            "execute_hermes": self.execute_mcp_tool,
            "execute_themis": self.execute_mcp_tool,
            "execute_janus": self.execute_mcp_tool,
            "execute_waybackurls": self.execute_mcp_tool,
            "execute_nmap": self.execute_mcp_tool,
            "execute_masscan": self.execute_mcp_tool,
            "execute_ffuf": self.execute_mcp_tool,
            "execute_amass": self.execute_mcp_tool,
            "execute_whatweb": self.execute_mcp_tool,
            "execute_knockpy": self.execute_mcp_tool,
            "execute_gau": self.execute_mcp_tool,
            "execute_kiterunner": self.execute_mcp_tool,
            "execute_wappalyzer": self.execute_mcp_tool,
            "execute_crtsh": self.execute_mcp_tool,
            "execute_crt_name": self.execute_mcp_tool,
            "execute_schemathesis": self.execute_mcp_tool,
            "execute_browser": self.execute_mcp_tool,
            "execute_deep_crawl": self.execute_mcp_tool,
            "execute_interceptor": self.execute_mcp_tool,
            # Guardian-parity tools
            "execute_sqlmap": self.execute_mcp_tool,
            "execute_nikto": self.execute_mcp_tool,
            "execute_wafw00f": self.execute_mcp_tool,
            "execute_testssl": self.execute_mcp_tool,
            "execute_sslyze": self.execute_mcp_tool,
            "execute_arjun": self.execute_mcp_tool,
            "execute_wpscan": self.execute_mcp_tool,
            "execute_xsstrike": self.execute_mcp_tool,
            "execute_dalfox": self.execute_mcp_tool,
            "execute_commix": self.execute_mcp_tool,
            "execute_hydra": self.execute_mcp_tool,
            "execute_feroxbuster": self.execute_mcp_tool,
            "execute_gitleaks": self.execute_mcp_tool,
            "scan_js_urls_for_secrets": self.scan_js_urls_for_secrets,
            "execute_retirejs": self.scan_js_urls_for_vulns,
            "execute_jwt": self.execute_mcp_tool,
            "execute_interactsh": self.execute_mcp_tool,
            "execute_semgrep": self.execute_mcp_tool,
            "execute_trivy": self.execute_mcp_tool,
            "execute_cmseek": self.execute_mcp_tool,
            "nuclei_help": self.execute_mcp_tool,
            "naabu_help": self.execute_mcp_tool,
            "httpx_help": self.execute_mcp_tool,
            "subfinder_help": self.execute_mcp_tool,
            "dnsx_help": self.execute_mcp_tool,
            "katana_help": self.execute_mcp_tool,
            "tldfinder_help": self.execute_mcp_tool,
            "atlas_help": self.execute_mcp_tool,
            "argus_help": self.execute_mcp_tool,
            "hermes_help": self.execute_mcp_tool,
            "themis_help": self.execute_mcp_tool,
            "janus_help": self.execute_mcp_tool,
            "waybackurls_help": self.execute_mcp_tool,
            "nmap_help": self.execute_mcp_tool,
            "masscan_help": self.execute_mcp_tool,
            "ffuf_help": self.execute_mcp_tool,
            "amass_help": self.execute_mcp_tool,
            "whatweb_help": self.execute_mcp_tool,
            "knockpy_help": self.execute_mcp_tool,
            "gau_help": self.execute_mcp_tool,
            "kiterunner_help": self.execute_mcp_tool,
            "schemathesis_help": self.execute_mcp_tool,
            "sqlmap_help": self.execute_mcp_tool,
            "nikto_help": self.execute_mcp_tool,
            "wafw00f_help": self.execute_mcp_tool,
            "testssl_help": self.execute_mcp_tool,
            "sslyze_help": self.execute_mcp_tool,
            "arjun_help": self.execute_mcp_tool,
            "wpscan_help": self.execute_mcp_tool,
            "xsstrike_help": self.execute_mcp_tool,
            "dalfox_help": self.execute_mcp_tool,
            "commix_help": self.execute_mcp_tool,
            "hydra_help": self.execute_mcp_tool,
            "feroxbuster_help": self.execute_mcp_tool,
            "gitleaks_help": self.execute_mcp_tool,
            "jwt_help": self.execute_mcp_tool,
            "semgrep_help": self.execute_mcp_tool,
            "trivy_help": self.execute_mcp_tool,
            "cmseek_help": self.execute_mcp_tool,
            # Fireteam: scatter-gather specialists in parallel
            "fireteam_dispatch": self.fireteam_dispatch,
            # Replay captured XHR/API requests (from capability map samples)
            "replay_http_request": self.replay_http_request,
            # EvoGraph: cross-session memory lookup
            "query_prior_sessions": self.query_prior_sessions,
            # ProjectDiscovery Uncover: multi-engine search
            "execute_uncover": self.execute_uncover,
            # Knowledge base (RAG) search — palace-backed
            "search_knowledge_base": self.search_knowledge_base,
            "search_memory": self.search_memory,
            "store_memory": self.store_memory,
            # Offensive workflow tools
            "validate_finding": self.validate_finding,
            "detect_bug_chains": self.detect_bug_chains,
            "bypass_403": self.bypass_403,
            "test_request_smuggling": self.test_request_smuggling,
            "test_cache_poisoning": self.test_cache_poisoning,
            "test_race_condition": self.test_race_condition,
            "test_saml_sso": self.test_saml_sso,
            "test_credential_spray": self.test_credential_spray,
            # Tester-process control plane
            "compare_requests": self.compare_requests,
            "sync_engagement_brain": self.sync_engagement_brain,
            "update_hypothesis": self.update_hypothesis,
            "queue_finding_followups": self.queue_finding_followups,
            "log_engagement_approach": self.log_engagement_approach,
            "add_engagement_credential": self.add_engagement_credential,
            "get_engagement_brain": self.get_engagement_brain,
            "get_methodology_progress": self.get_methodology_progress,
            "ingest_urls_into_map": self.ingest_urls_into_map,
        }
        # Optional: web search (RedAmon-style) when Tavily API key is set
        if getattr(settings, "TAVILY_API_KEY", None):
            tools["web_search"] = self.web_search
        # vulnx: ProjectDiscovery vulnerability intelligence API (CVE ID lookup + search)
        # Available with or without PDCP_API_KEY (unauthenticated has rate limits)
        tools["search_vulnx"] = self.search_vulnx       # single CVE deep-dive by ID
        tools["vulnx_query"] = self.vulnx_query         # search CVEs by technology/query
        return tools

    def get_tool(self, name: str) -> Optional[callable]:
        """Get a tool by name."""
        return self.tools.get(name)
    
    def get_all_tools(self) -> Dict[str, callable]:
        """Get all registered tools."""
        return self.tools
    
    def record_invocation(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]],
        result: Optional[Dict[str, Any]],
    ) -> None:
        """Keep a ring buffer of live tool calls for demonstrated-chain attach."""
        try:
            from app.services.agent.demonstrated_chain import should_record_tool

            if not should_record_tool(tool_name):
                return
            result = result or {}
            output = result.get("output")
            if output is not None and not isinstance(output, str):
                output = str(output)
            self._recent_invocations.append({
                "tool": tool_name,
                "args": (tool_args or {}).get("args", tool_args),
                "output": output or "",
                "error": result.get("error") or "",
                "exit_code": result.get("exit_code"),
                "success": bool(result.get("success")),
            })
        except Exception:
            logger.debug("record_invocation skipped", exc_info=True)

    async def execute(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with the given arguments."""
        result = await self._execute_impl(tool_name, tool_args)
        self.record_invocation(tool_name, tool_args, result)
        try:
            from app.services.agent.palace_memory import remember_tool_result
            remember_tool_result(tool_name, tool_args, result)
        except Exception as exc:
            logger.debug("palace remember skipped: %s", exc)
        return result

    async def _execute_impl(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with the given arguments."""
        tool_args = dict(tool_args or {}) if isinstance(tool_args, dict) else {}

        # Normalize execute_* BEFORE the confirmation gate so approvals show
        # real CLI args and empty-{} LLM calls never reach MCP.
        if tool_name.startswith("execute_"):
            fallback = str(tool_args.pop("_fallback_target", "") or "")
            if not fallback:
                fallback = getattr(self, "_fallback_target", "") or ""
            if not fallback:
                fallback = current_seed_target.get() or ""
            tool_args = normalize_execute_tool_args(
                tool_name,
                tool_args,
                fallback_target=fallback,
            )
            if not (tool_args.get("args") or "").strip():
                return {
                    "success": False,
                    "output": (
                        f"Error: Missing required parameter: args\n\n"
                        f"HINT: {tool_name} requires tool_args like "
                        f'{{"args": "-u https://target.com -json"}}. '
                        f"Do not call it with empty tool_args."
                    ),
                    "error": "Missing required parameter: args",
                }

        # -- Per-tool confirmation gate ---------------------------------------
        # Consult the org's agent confirmation policy. Dangerous tools
        # (execute_*, create_scan, ...) either pause for a human ``approve`` or
        # are outright denied by policy. Read-only queries fast-path through.
        try:
            from app.services.agent.confirmation_service import gate as _gate_tool
            _, org_id = get_tenant_context()
            _sess = current_session_id.get()
            gate_result = await _gate_tool(tool_name, tool_args or {}, org_id, _sess)
            if gate_result.get("decision") == "deny":
                return {
                    "success": False,
                    "output": gate_result.get("reason")
                    or f"Tool '{tool_name}' is blocked by policy.",
                    "error": "policy_denied",
                }
            if gate_result.get("decision") == "confirm":
                token = gate_result.get("token") or ""
                # Notify the UI, then block until the operator decides.
                try:
                    from app.services.agent.orchestrator import _status_callback_var
                    cb = _status_callback_var.get(None)
                    if cb:
                        await cb({
                            "type": "pending_confirmation",
                            "token": token,
                            "tool_name": tool_name,
                            "tool_args": gate_result.get("tool_args") or {},
                            "expires_at": gate_result.get("expires_at"),
                            "message": (
                                f"Tool '{tool_name}' requires operator approval before continuing."
                            ),
                        })
                except Exception as emit_err:
                    logger.debug("Could not emit pending_confirmation: %s", emit_err)
                from app.services.agent.confirmation_service import wait_for_decision
                approved = await wait_for_decision(token)
                if not approved:
                    return {
                        "success": False,
                        "output": (
                            f"Operator denied or confirmation timed out for '{tool_name}'."
                        ),
                        "error": "confirmation_denied",
                        "confirmation": {**gate_result, "status": "denied"},
                    }
                # Approved — fall through and execute the tool.
        except Exception as _gate_err:  # fail-open on gate internal error
            logger.warning(f"Confirmation gate error (fail-open): {_gate_err}")

        # Route MCP tools: execute_* and *_help (dynamic CLI + help)
        if tool_name.startswith("execute_") or tool_name.endswith("_help"):
            try:
                mcp = self._get_mcp_server()
                result = await mcp.call_tool(tool_name, tool_args)

                max_chars = _tool_output_max_chars()
                augur_block = result.get("augur")  # Augur reading: kept/dropped/next_steps/signals
                capability_map = result.get("capability_map")  # deep_crawl / interceptor map
                auth_session = result.get("auth_session")
                if result.get("success"):
                    output = result.get("output", "")
                    payload = {
                        "success": True,
                        "output": output or "Command completed.",
                        "error": None,
                    }
                    if result.get("exit_code") is not None:
                        payload["exit_code"] = result.get("exit_code")
                    if augur_block:
                        payload["augur"] = augur_block
                    if capability_map:
                        payload["capability_map"] = capability_map
                    if auth_session:
                        payload["auth_session"] = auth_session
                    if len(output) > max_chars and not augur_block:
                        payload["output"] = (
                            output[:max_chars]
                            + f"\n\n... (truncated, total {len(result.get('output', ''))} chars)"
                        )
                    return payload
                else:
                    err = result.get("error", "Unknown error")
                    out = result.get("output", "")
                    err_max = min(8000, max_chars)
                    hint = (
                        f"\n\nHINT: {tool_name} expects a single 'args' parameter with CLI arguments as a string. "
                        f"Example: {tool_name}(args=\"-u https://target.com -json\")"
                    ) if "Missing required parameter" in err or "unexpected keyword" in err else ""
                    combined = f"Error: {err}{hint}"
                    if out and out.strip():
                        combined += f"\nStdout:\n{out[:err_max]}" + ("\n... (truncated)" if len(out) > err_max else "")
                    fail_payload = {
                        "success": False,
                        "output": combined,
                        "error": err,
                    }
                    if result.get("exit_code") is not None:
                        fail_payload["exit_code"] = result.get("exit_code")
                    return fail_payload
            except Exception as e:
                logger.error(f"MCP tool execution failed: {tool_name} - {e}")
                err_txt = str(e)
                # Only append the args-shape HINT when the failure is actually about params
                args_related = any(
                    m in err_txt.lower()
                    for m in (
                        "missing required",
                        "unexpected keyword",
                        "required parameter",
                        "got an unexpected",
                    )
                )
                hint = (
                    f"\n\nHINT: All execute_* tools accept a single 'args' parameter with CLI arguments. "
                    f"Example: {tool_name}(args=\"-u https://target.com\")"
                    if args_related
                    else ""
                )
                return {
                    "success": False,
                    "output": f"Error: {e}{hint}",
                    "error": err_txt,
                }
        
        # Regular ASM tool
        tool = self.get_tool(tool_name)
        if not tool:
            return {
                "success": False,
                "output": None,
                "error": f"Tool '{tool_name}' not found"
            }
        
        try:
            result = await tool(**tool_args)
            return {
                "success": True,
                "output": result,
                "error": None
            }
        except TypeError as e:
            import inspect
            sig = inspect.signature(tool)
            params = [p for p in sig.parameters if p != "self"]
            hint = f"Tool '{tool_name}' accepts: {', '.join(params)}. You passed: {list(tool_args.keys())}."
            logger.error(f"Tool argument mismatch: {tool_name} - {e}. {hint}")
            return {
                "success": False,
                "output": hint,
                "error": f"{e}. {hint}"
            }
        except Exception as e:
            logger.error(f"Tool execution failed: {tool_name} - {e}")
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }
    
    async def query_assets(
        self,
        asset_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query assets from the ASM database.
        
        Args:
            asset_type: Filter by asset type (domain, subdomain, ip_address, url, etc.)
            search: Search term to filter asset values
            limit: Maximum number of results
        
        Returns:
            JSON string with asset information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply type filter
            if asset_type:
                try:
                    asset_type_enum = AssetType(asset_type.lower())
                    query = query.filter(Asset.asset_type == asset_type_enum)
                except ValueError:
                    pass
            
            # Apply search filter
            if search:
                query = query.filter(Asset.value.ilike(f"%{search}%"))
            
            # Limit results
            assets = query.limit(limit).all()
            
            result = []
            for asset in assets:
                result.append({
                    "id": asset.id,
                    "value": asset.value,
                    "type": asset.asset_type.value if asset.asset_type else None,
                    "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
                    "is_live": getattr(asset, 'is_live', None),
                    "risk_score": getattr(asset, 'ars_score', None),
                })
            
            return f"Found {len(result)} assets:\n" + "\n".join(
                f"- [{a['type']}] {a['value']} (ID: {a['id']}, Risk: {a.get('risk_score', 'N/A')})"
                for a in result
            )
        finally:
            db.close()
    
    async def query_vulnerabilities(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query vulnerabilities from the ASM database.
        
        Args:
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (open, in_progress, resolved, etc.)
            cve_id: Filter by CVE ID
            limit: Maximum number of results
        
        Returns:
            JSON string with vulnerability information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Vulnerability).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply severity filter (handles both string "critical" and list ["critical","high"])
            if severity:
                if isinstance(severity, list):
                    sev_enums = []
                    for s in severity:
                        try:
                            sev_enums.append(Severity(str(s).lower()))
                        except (ValueError, AttributeError):
                            pass
                    if sev_enums:
                        query = query.filter(Vulnerability.severity.in_(sev_enums))
                else:
                    try:
                        severity_enum = Severity(str(severity).lower())
                        query = query.filter(Vulnerability.severity == severity_enum)
                    except (ValueError, AttributeError):
                        pass
            
            # Apply CVE filter
            if cve_id:
                query = query.filter(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
            
            # Limit results
            vulns = query.limit(limit).all()
            
            result = []
            for vuln in vulns:
                result.append({
                    "id": vuln.id,
                    "title": vuln.title,
                    "severity": vuln.severity.value if vuln.severity else None,
                    "cvss_score": vuln.cvss_score,
                    "cve_id": vuln.cve_id,
                    "cwe_id": vuln.cwe_id,
                    "status": vuln.status.value if vuln.status else None,
                    "asset": vuln.asset.value if vuln.asset else None,
                })
            
            return f"Found {len(result)} vulnerabilities:\n" + "\n".join(
                f"- [{v['severity'].upper()}] {v['title']} ({v['cve_id'] or 'No CVE'}) on {v['asset']}"
                for v in result
            )
        finally:
            db.close()
    
    async def query_ports(
        self,
        port: Optional[int] = None,
        service: Optional[str] = None,
        is_risky: Optional[bool] = None,
        limit: int = 50
    ) -> str:
        """
        Query open ports and services from the ASM database.
        
        Args:
            port: Filter by port number
            service: Filter by service name
            is_risky: Filter by risky port flag
            limit: Maximum number of results
        
        Returns:
            String with port/service information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(PortService).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply port filter
            if port:
                query = query.filter(PortService.port == port)
            
            # Apply service filter
            if service:
                query = query.filter(PortService.service.ilike(f"%{service}%"))
            
            # Apply risky filter
            if is_risky is not None:
                query = query.filter(PortService.is_risky == is_risky)
            
            # Limit results
            ports = query.limit(limit).all()
            
            result = []
            for p in ports:
                result.append({
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "is_risky": p.is_risky,
                    "asset": p.asset.value if p.asset else None,
                })
            
            # Group by port for summary
            port_summary = {}
            for p in result:
                port_key = f"{p['port']}/{p['protocol']}"
                if port_key not in port_summary:
                    port_summary[port_key] = {"count": 0, "service": p["service"], "risky": p["is_risky"]}
                port_summary[port_key]["count"] += 1
            
            return f"Found {len(result)} open ports:\n" + "\n".join(
                f"- {pk}: {pv['service'] or 'unknown'} ({pv['count']} hosts){' [RISKY]' if pv['risky'] else ''}"
                for pk, pv in sorted(port_summary.items())
            )
        finally:
            db.close()
    
    async def query_technologies(
        self,
        category: Optional[str] = None,
        name: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query detected technologies from the ASM database.
        
        Args:
            category: Filter by technology category
            name: Filter by technology name
            limit: Maximum number of results
        
        Returns:
            String with technology information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Technology).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply category filter
            if category:
                query = query.filter(Technology.category.ilike(f"%{category}%"))
            
            # Apply name filter
            if name:
                query = query.filter(Technology.name.ilike(f"%{name}%"))
            
            # Limit results
            techs = query.limit(limit).all()
            
            # Group by technology
            tech_summary = {}
            for t in techs:
                key = f"{t.name} ({t.category})" if t.category else t.name
                if key not in tech_summary:
                    tech_summary[key] = {"count": 0, "versions": set()}
                tech_summary[key]["count"] += 1
                if t.version:
                    tech_summary[key]["versions"].add(t.version)
            
            return f"Found {len(tech_summary)} unique technologies:\n" + "\n".join(
                f"- {tk}: {tv['count']} instances" + (f" (versions: {', '.join(tv['versions'])})" if tv['versions'] else "")
                for tk, tv in sorted(tech_summary.items(), key=lambda x: -x[1]["count"])
            )
        finally:
            db.close()
    
    # Cypher keywords that are allowed in read-only queries
    _CYPHER_READ_KEYWORDS = {"MATCH", "WHERE", "RETURN", "WITH", "OPTIONAL", "ORDER", "BY",
                              "LIMIT", "SKIP", "UNWIND", "AS", "AND", "OR", "NOT", "IN",
                              "IS", "NULL", "TRUE", "FALSE", "DISTINCT", "COUNT", "COLLECT",
                              "EXISTS", "CASE", "WHEN", "THEN", "ELSE", "END", "DESC", "ASC",
                              "CONTAINS", "STARTS", "ENDS", "CALL", "YIELD", "UNION", "ALL"}
    _CYPHER_WRITE_KEYWORDS = {"CREATE", "DELETE", "DETACH", "SET", "REMOVE", "MERGE",
                               "DROP", "FOREACH", "LOAD", "CSV"}

    async def query_graph(
        self,
        cypher: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        limit: int = 50,
        # Accept common LLM argument name variations
        cypher_query: Optional[str] = None,
        query: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """
        Run a READ-ONLY Cypher query against the Neo4j attack surface graph.

        Use this to understand relationships: Domain → Subdomain → IP → Port → Service
        → Technology → Vulnerability → CVE. Always include a filter on organization_id
        for tenant safety (use $org_id in your WHERE clause).

        Write operations (CREATE, DELETE, SET, MERGE, REMOVE, DROP) are blocked.

        Args:
            cypher: Cypher query string. Must filter by organization_id, e.g.
                    WHERE a.organization_id = $org_id
            params: Optional query parameters (org_id is added automatically from context)
            limit: Max rows to return (default 50)

        Returns:
            JSON string of query results
        """
        cypher = cypher or cypher_query or query or kwargs.get("cypher_string", "")
        if not cypher:
            return json.dumps({"error": "No Cypher query provided. Pass the query as the 'cypher' argument."})
        user_id, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "No organization context. Set organization for this session."})

        # Security: block write operations to prevent Cypher injection
        cypher_upper = cypher.upper()
        for keyword in self._CYPHER_WRITE_KEYWORDS:
            # Check for the keyword as a standalone word (not part of a property name)
            if _re.search(r'\b' + keyword + r'\b', cypher_upper):
                return json.dumps({
                    "error": f"Write operation '{keyword}' is not allowed. query_graph is read-only. "
                             f"Use MATCH ... RETURN queries only."
                })

        try:
            from app.services.graph_service import get_graph_service
            graph = get_graph_service()
            if not graph.connect():
                return json.dumps({"error": "Neo4j graph not available."})

            merged = dict(params or {})
            merged["org_id"] = org_id
            if "LIMIT" not in cypher_upper:
                cypher = cypher.rstrip() + f" LIMIT {limit}"
            results = graph.query(cypher, merged)
            return json.dumps(results[:limit], default=str)
        except Exception as e:
            logger.exception("query_graph failed")
            return json.dumps({"error": str(e)})
    
    async def analyze_attack_surface(self) -> str:
        """
        Get a comprehensive attack surface summary.
        
        Returns:
            String with attack surface analysis
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            # Count assets by type
            asset_counts = {}
            for asset_type in AssetType:
                query = db.query(Asset).filter(Asset.asset_type == asset_type)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_counts[asset_type.value] = query.count()
            
            # Count vulnerabilities by severity
            vuln_counts = {}
            for severity in Severity:
                query = db.query(Vulnerability).join(Asset).filter(Vulnerability.severity == severity)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                vuln_counts[severity.value] = query.count()
            
            # Count risky ports
            query = db.query(PortService).join(Asset).filter(PortService.is_risky == True)
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            risky_ports = query.count()
            
            # Total ports
            query = db.query(PortService).join(Asset)
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            total_ports = query.count()
            
            report = "# Attack Surface Summary\n\n"
            
            report += "## Assets\n"
            for at, count in asset_counts.items():
                if count > 0:
                    report += f"- {at}: {count}\n"
            
            report += "\n## Vulnerabilities\n"
            total_vulns = sum(vuln_counts.values())
            report += f"- Total: {total_vulns}\n"
            for sev, count in vuln_counts.items():
                if count > 0:
                    report += f"  - {sev.upper()}: {count}\n"
            
            report += f"\n## Exposed Services\n"
            report += f"- Total open ports: {total_ports}\n"
            report += f"- Risky ports: {risky_ports}\n"
            
            return report
        finally:
            db.close()

    async def rank_attack_surface(
        self,
        target: Optional[str] = None,
        limit: int = 20,
    ) -> str:
        """
        Rank assets by likely testing value using stored ASM data.

        This is a lightweight triage helper for the surface-ranking skill. It
        does not scan; it prioritizes known assets based on exposure, tech,
        existing findings, and high-value route/asset signals.

        Args:
            target: Optional hostname/domain substring to focus ranking.
            limit: Maximum ranked assets to return.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "No organization context."}, indent=2)

        limit = max(1, min(int(limit or 20), 100))
        focus = (target or "").strip().lower()

        db = SessionLocal()
        try:
            query = db.query(Asset).filter(Asset.organization_id == org_id)
            if focus:
                query = query.filter(Asset.value.ilike(f"%{focus}%"))
            assets = query.limit(500).all()

            ranked = []
            high_value_terms = {
                "admin": 20,
                "api": 18,
                "auth": 18,
                "login": 16,
                "sso": 16,
                "oauth": 16,
                "graphql": 16,
                "swagger": 15,
                "openapi": 15,
                "upload": 14,
                "files": 10,
                "export": 10,
                "webhook": 10,
                "payment": 12,
                "billing": 12,
                "chat": 10,
                "support": 8,
                "dev": 8,
                "staging": 8,
                "test": 6,
            }
            risky_ports = {21, 22, 23, 25, 445, 3389, 5432, 3306, 6379, 9200, 9300, 11211}
            severity_weight = {
                "critical": 40,
                "high": 28,
                "medium": 12,
                "low": 4,
                "info": 1,
            }
            tech_weight = {
                "wordpress": 12,
                "gitlab": 14,
                "jenkins": 16,
                "jira": 12,
                "confluence": 12,
                "spring": 10,
                "struts": 14,
                "apache tomcat": 12,
                "graphql": 12,
                "swagger": 10,
                "intercom": 10,
                "zendesk": 10,
                "drift": 10,
                "crisp": 10,
                "tawk": 10,
                "livechat": 10,
                "freshchat": 10,
                "custom chat widget": 10,
                "kubernetes": 14,
                "elasticsearch": 14,
            }

            for asset in assets:
                score = float(getattr(asset, "ars_score", None) or 0)
                reasons = []
                value = (asset.value or "").lower()

                if getattr(asset, "is_live", False):
                    score += 10
                    reasons.append("live asset")

                for term, weight in high_value_terms.items():
                    if term in value:
                        score += weight
                        reasons.append(f"name contains {term}")

                for vuln in getattr(asset, "vulnerabilities", [])[:50]:
                    sev = getattr(getattr(vuln, "severity", None), "value", None) or "info"
                    weight = severity_weight.get(str(sev).lower(), 1)
                    score += weight
                    reasons.append(f"{str(sev).upper()} finding: {vuln.title[:80]}")

                for port in getattr(asset, "ports", [])[:50]:
                    port_num = getattr(port, "port", None)
                    if getattr(port, "is_risky", False) or port_num in risky_ports:
                        score += 12
                        reasons.append(f"risky exposed port {port_num}")
                    elif port_num in (80, 443, 8080, 8443):
                        score += 4
                        reasons.append(f"web port {port_num}")

                for tech in getattr(asset, "technologies", [])[:50]:
                    name = (getattr(tech, "name", "") or "").lower()
                    for needle, weight in tech_weight.items():
                        if needle in name:
                            score += weight
                            label = getattr(tech, "name", "") or needle
                            reasons.append(f"high-value technology: {label}")

                if score <= 0 and not reasons:
                    continue

                ranked.append({
                    "asset_id": asset.id,
                    "asset": asset.value,
                    "type": asset.asset_type.value if asset.asset_type else None,
                    "score": round(score, 1),
                    "reasons": list(dict.fromkeys(reasons))[:8],
                    "recommended_next_skill": self._recommend_skill_for_asset(value, reasons),
                })

            ranked.sort(key=lambda item: item["score"], reverse=True)
            return json.dumps({
                "target_filter": focus or None,
                "ranked_count": len(ranked[:limit]),
                "ranked_assets": ranked[:limit],
            }, indent=2, default=str)[:_tool_output_max_chars()]
        finally:
            db.close()

    def _recommend_skill_for_asset(self, asset_value: str, reasons: List[str]) -> str:
        reason_blob = " ".join(reasons).lower()
        if any(x in asset_value or x in reason_blob for x in ("chat", "intercom", "zendesk", "drift", "crisp", "tawk", "livechat")):
            return "llm-redteam"
        if any(x in asset_value or x in reason_blob for x in ("swagger", "openapi", "api", "graphql")):
            return "api-authz-validation"
        if any(x in asset_value or x in reason_blob for x in ("login", "auth", "sso", "oauth")):
            return "api-authz-validation"
        if any(x in asset_value or x in reason_blob for x in ("upload", "files")):
            return "vuln-scan"
        if "xss" in reason_blob:
            return "vuln-scan"
        if "sqli" in reason_blob or "sql injection" in reason_blob:
            return "vuln-scan"
        return "vuln-scan"
    
    async def get_asset_details(
        self,
        asset_id: Optional[int] = None,
        # Accept common LLM argument name variations
        asset_identifier: Optional[Any] = None,
        hostname: Optional[str] = None,
        asset: Optional[Any] = None,
        id: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        """
        Get detailed information about a specific asset.
        
        Args:
            asset_id: ID (integer) of the asset to retrieve. Use query_assets first to find asset IDs.
        
        Returns:
            String with detailed asset information
        """
        resolved_id = asset_id or id or asset_identifier or asset or kwargs.get("asset_value")
        lookup_by_name = hostname or (resolved_id if isinstance(resolved_id, str) and not str(resolved_id).isdigit() else None)

        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            if lookup_by_name:
                query = db.query(Asset).filter(Asset.value.ilike(f"%{lookup_by_name}%"))
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_obj = query.first()
            else:
                try:
                    resolved_id = int(resolved_id)
                except (TypeError, ValueError):
                    return f"Invalid asset_id: {resolved_id}. Use query_assets to find integer asset IDs."
                query = db.query(Asset).filter(Asset.id == resolved_id)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_obj = query.first()
            
            if not asset_obj:
                return f"Asset '{resolved_id or lookup_by_name}' not found. Use query_assets to list available assets."
            
            asset = asset_obj
            
            details = f"# Asset Details: {asset.value}\n\n"
            details += f"- **Type**: {asset.asset_type.value if asset.asset_type else 'Unknown'}\n"
            details += f"- **First Seen**: {asset.first_seen.isoformat() if asset.first_seen else 'Unknown'}\n"
            details += f"- **Live**: {'Yes' if getattr(asset, 'is_live', False) else 'No'}\n"
            
            if hasattr(asset, 'ars_score') and asset.ars_score:
                details += f"- **Risk Score (ARS)**: {asset.ars_score}/100\n"
            
            if hasattr(asset, 'acs_score') and asset.acs_score:
                details += f"- **Criticality Score (ACS)**: {asset.acs_score}/10\n"
            
            # Get vulnerabilities
            if asset.vulnerabilities:
                details += f"\n## Vulnerabilities ({len(asset.vulnerabilities)})\n"
                for vuln in asset.vulnerabilities[:10]:
                    details += f"- [{vuln.severity.value.upper()}] {vuln.title}\n"
                if len(asset.vulnerabilities) > 10:
                    details += f"... and {len(asset.vulnerabilities) - 10} more\n"
            
            # Get ports
            if hasattr(asset, 'ports') and asset.ports:
                details += f"\n## Open Ports ({len(asset.ports)})\n"
                for port in asset.ports[:10]:
                    risky = " [RISKY]" if port.is_risky else ""
                    details += f"- {port.port}/{port.protocol}: {port.service or 'unknown'}{risky}\n"
            
            # Get technologies
            if hasattr(asset, 'technologies') and asset.technologies:
                details += f"\n## Technologies ({len(asset.technologies)})\n"
                for tech in asset.technologies[:10]:
                    version = f" v{tech.version}" if tech.version else ""
                    details += f"- {tech.name}{version} ({tech.category or 'unknown'})\n"
            
            return details
        finally:
            db.close()
    
    async def search_cve(self, cve_id: str) -> str:
        """
        Search for CVE information in the database.
        
        Args:
            cve_id: CVE ID to search for (e.g., CVE-2021-44228)
        
        Returns:
            String with CVE information and affected assets
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Vulnerability).join(Asset).filter(
                Vulnerability.cve_id.ilike(f"%{cve_id}%")
            )
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            vulns = query.all()
            
            if not vulns:
                return f"No findings for {cve_id} in your attack surface."
            
            result = f"# CVE Search: {cve_id}\n\n"
            result += f"Found {len(vulns)} affected assets:\n\n"
            
            for vuln in vulns[:20]:
                result += f"## {vuln.asset.value if vuln.asset else 'Unknown Asset'}\n"
                result += f"- **Severity**: {vuln.severity.value.upper()}\n"
                result += f"- **CVSS**: {vuln.cvss_score or 'N/A'}\n"
                result += f"- **Status**: {vuln.status.value if vuln.status else 'Unknown'}\n"
                if vuln.description:
                    result += f"- **Description**: {vuln.description[:200]}...\n"
                result += "\n"
            
            if len(vulns) > 20:
                result += f"... and {len(vulns) - 20} more affected assets.\n"
            
            return result
        finally:
            db.close()

    async def web_search(self, query: str, max_results: int = 5) -> str:
        """
        Search the web for CVE details, exploit info, or general security research (RedAmon-style).
        Uses Tavily API when TAVILY_API_KEY is set.
        
        Args:
            query: Search query (e.g. "CVE-2021-44228 exploit", "Log4j remediation")
            max_results: Max results to return (1-10, default 5)
        
        Returns:
            Summarized search results or an error message.
        """
        api_key = getattr(settings, "TAVILY_API_KEY", None)
        if not api_key:
            return "Web search is not configured. Set TAVILY_API_KEY in .env to enable (get a key at tavily.com)."
        max_results = max(1, min(10, max_results))
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "search_depth": "basic",
                        "max_results": max_results,
                    },
                )
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPStatusError as e:
            logger.warning(f"Tavily API error: {e.response.status_code} - {e.response.text[:200]}")
            return f"Web search failed: HTTP {e.response.status_code}. Check TAVILY_API_KEY and quota."
        except Exception as e:
            logger.exception("Tavily web_search failed")
            return f"Web search failed: {e!s}"
        results = data.get("results") or []
        if not results:
            return f"No results for: {query}"
        out = [f"# Web search: {query}\n"]
        for i, hit in enumerate(results, 1):
            title = hit.get("title", "")
            url = hit.get("url", "")
            content = (hit.get("content") or "")[:_tool_output_max_chars() // max_results]
            out.append(f"## {i}. {title}\nURL: {url}\n{content}\n")
        return "\n".join(out)

    async def search_vulnx(self, cve_id: str) -> str:
        """
        Query the ProjectDiscovery vulnx API for rich CVE intelligence.

        Returns a comprehensive snapshot including:
          - CVSS score & vector, EPSS score & percentile
          - CISA KEV and VulnCheck KEV membership
          - Public PoC count and URLs (source, added date)
          - HackerOne disclosed report count and rank
          - Nuclei template name and raw YAML (when available)
          - Affected products with CPEs and deployment models
          - Internet exposure estimates (Shodan/Fofa min–max hosts)
          - Requirements / preconditions (structured attacker prerequisites)
          - Remediation guidance

        Uses PDCP_API_KEY when set (higher rate limits); works unauthenticated
        with stricter limits. Key is the same one used by other PD tools.

        Args:
            cve_id: CVE identifier, e.g. CVE-2021-44228
        """
        import re as _re
        cve_id = cve_id.strip().upper()
        if not _re.match(r"^CVE-\d{4}-\d+$", cve_id):
            return f"Invalid CVE ID format: {cve_id}. Expected CVE-YYYY-NNNNN."

        base_url = "https://api.projectdiscovery.io"
        headers = {"User-Agent": "aegis-vanguard/1.0"}
        api_key = getattr(settings, "PDCP_API_KEY", None)
        if api_key:
            headers["X-PDCP-Key"] = api_key

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(
                    f"{base_url}/v2/vulnerability/{cve_id}",
                    headers=headers,
                )
                if r.status_code == 404:
                    return f"{cve_id} not found in the ProjectDiscovery vulnerability database."
                if r.status_code == 429:
                    return (
                        f"vulnx API rate limit hit for {cve_id}. "
                        "Set PDCP_API_KEY in .env for higher limits (free at cloud.projectdiscovery.io)."
                    )
                r.raise_for_status()
                data = r.json().get("data") or {}
        except httpx.HTTPStatusError as e:
            return f"vulnx API error for {cve_id}: HTTP {e.response.status_code}"
        except Exception as e:
            return f"vulnx lookup failed for {cve_id}: {e}"

        if not data:
            return f"No data returned for {cve_id}."

        lines = [f"# vulnx — {cve_id}\n"]

        # Core severity
        lines.append(f"**Severity**: {data.get('severity', 'N/A').upper()}")
        lines.append(f"**CVSS Score**: {data.get('cvss_score', 'N/A')}  ({data.get('cvss_metrics', '')})")
        lines.append(f"**EPSS Score**: {data.get('epss_score', 'N/A')}  (percentile: {data.get('epss_percentile', 'N/A')})")
        lines.append(f"**Status**: {data.get('vuln_status', 'N/A')}")
        lines.append("")

        # Exploitation signals
        kev_entries = data.get("kev") or []
        is_kev = data.get("is_kev", False)
        is_vkev = data.get("is_vkev", False)
        lines.append(f"**CISA KEV**: {'YES ⚠️' if is_kev else 'No'}")
        lines.append(f"**VulnCheck KEV**: {'YES ⚠️' if is_vkev else 'No'}")
        if kev_entries:
            for k in kev_entries:
                added = k.get("added_date", "")[:10] if k.get("added_date") else ""
                ransomware = " (ransomware)" if k.get("known_ransomware_campaign_use") else ""
                lines.append(f"  - KEV source: {k.get('source', '?')}  added: {added}{ransomware}")

        poc_count = data.get("poc_count", 0)
        is_poc = data.get("is_poc", False)
        lines.append(f"**Public PoC**: {'YES' if is_poc else 'No'}  ({poc_count} PoC(s))")
        pocs = data.get("pocs") or []
        for p in pocs[:5]:
            added = p.get("added_at", "")[:10] if p.get("added_at") else ""
            lines.append(f"  - [{p.get('source','?')}] {p.get('url','')}  (added {added})")
        lines.append("")

        # HackerOne
        h1 = data.get("h1") or {}
        if h1:
            lines.append(f"**HackerOne**: {h1.get('reports', 0)} reports  rank #{h1.get('rank', '?')}  (Δ reports: {h1.get('delta_reports', 0)})")
            lines.append("")

        # Nuclei template
        is_template = data.get("is_template", False)
        lines.append(f"**Nuclei Template**: {'YES — ' + data.get('filename','') if is_template else 'No'}")
        if is_template and data.get("tags"):
            lines.append(f"  Tags: {', '.join(data.get('tags', []))}")
        lines.append("")

        # Requirements / preconditions
        reqs = data.get("requirements", "")
        req_type = data.get("requirement_type", "")
        if reqs:
            lines.append(f"**Requirements (preconditions)**:")
            lines.append(f"  Type: {req_type}")
            lines.append(f"  {reqs}")
            lines.append("")

        # Internet exposure
        exposure = data.get("exposure") or {}
        exp_values = exposure.get("values") or []
        if exp_values:
            total_min = sum(v.get("min_hosts", 0) for v in exp_values)
            total_max = sum(v.get("max_hosts", 0) for v in exp_values)
            lines.append(f"**Internet Exposure**: ~{total_min:,}–{total_max:,} hosts (Shodan/Fofa)")
            lines.append("")

        # Affected products
        products = data.get("affected_products") or []
        if products:
            lines.append(f"**Affected Products** ({len(products)} total, showing first 5):")
            for p in products[:5]:
                vendor = p.get("vendor", "")
                product = p.get("product", "")
                deploy = p.get("deployment_model", "")
                cpes = ", ".join((p.get("cpe") or [])[:2])
                lines.append(f"  - {vendor} / {product}  [{deploy}]  CPE: {cpes}")
            lines.append("")

        # Description + remediation
        desc = data.get("description", "")
        if desc:
            lines.append(f"**Description**: {desc[:500]}{'...' if len(desc) > 500 else ''}")
        remediation = data.get("remediation", "")
        if remediation:
            lines.append(f"**Remediation**: {remediation[:400]}{'...' if len(remediation) > 400 else ''}")

        # CWEs
        cwes = data.get("cwe") or []
        if cwes:
            lines.append(f"**CWEs**: {', '.join(cwes)}")
            try:
                from app.services.vuln_intel_enrichment import build_cwe_intel
                for row in build_cwe_intel([str(c) for c in cwes])[:5]:
                    capecs = ", ".join(c.get("id", "") for c in (row.get("capec") or [])[:4])
                    lines.append(
                        f"  - {row.get('cwe_id')}: {row.get('name') or ''}"
                        + (f" → {capecs}" if capecs else "")
                    )
            except Exception:
                pass

        return "\n".join(lines)

    async def vulnx_query(self, query: str, limit: int = 10, sort_by: str = "cvss_score") -> str:
        """
        Search the ProjectDiscovery vulnerability database using a rich query string.

        Use this to DISCOVER CVEs relevant to a technology stack — for example when
        you've identified that a target runs Apache Tomcat 9.x and want to find all
        recent high-severity exploitable CVEs for it.

        Query syntax supports:
          - Boolean:  apache && severity:high && is_remote:true
          - Field:    affected_products.product:tomcat, cvss_score:>8.0, epss_score:>0.7
          - KEV/PoC:  is_kev:true, is_poc:true, is_template:true
          - Date:     cve_created_at:>=2024, age_in_days:<30
          - Vendor:   affected_products.vendor:microsoft

        Examples:
          - 'nodejs && severity:high && is_remote:true'
          - 'apache && is_kev:true'
          - 'severity:critical && is_poc:true && age_in_days:<30'
          - 'affected_products.product:spring && cvss_score:>8.0'

        Args:
            query:   vulnx query string (see syntax above)
            limit:   max results (default 10, max 25)
            sort_by: field to sort descending by (cvss_score, epss_score, cve_created_at)
        """
        import re as _re
        import subprocess
        import shutil

        if not query.strip():
            return "query is required"
        if limit > 25:
            limit = 25

        base_url = "https://api.projectdiscovery.io"
        headers = {"User-Agent": "aegis-vanguard/1.0"}
        api_key = getattr(settings, "PDCP_API_KEY", None)
        if api_key:
            headers["X-PDCP-Key"] = api_key

        # ── Try vulnx binary first (richest output) ──────────────────────────
        vulnx_path = shutil.which("vulnx")
        if vulnx_path:
            try:
                cmd = [
                    vulnx_path, "search", query,
                    "--json", "--silent", "--disable-update-check",
                    "--limit", str(limit),
                    "--sort-desc", sort_by,
                ]
                env = {**dict(__import__("os").environ)}
                if api_key:
                    env["PDCP_API_KEY"] = api_key
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30, env=env
                )
                if result.returncode == 0 and result.stdout.strip():
                    return _format_vulnx_search_output(result.stdout, query)
            except Exception:
                pass  # fall through to HTTP API

        # ── Fall back to PDCP HTTP search API ────────────────────────────────
        from urllib.parse import quote
        search_url = (
            f"{base_url}/v2/vulnerability"
            f"?q={quote(query)}&limit={limit}&sort-desc={sort_by}"
        )
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(search_url, headers=headers)
                if r.status_code == 429:
                    return (
                        f"vulnx search rate limit hit for query '{query}'. "
                        "Set PDCP_API_KEY in .env for higher limits."
                    )
                if r.status_code == 401:
                    return "vulnx: unauthorized — PDCP_API_KEY may be invalid."
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPStatusError as e:
            return f"vulnx search API error: HTTP {e.response.status_code}"
        except Exception as e:
            return f"vulnx search failed: {e}"

        # Normalise response envelope
        vulns = []
        if isinstance(data, dict):
            inner = data.get("data") or data
            if isinstance(inner, dict):
                vulns = inner.get("vulnerabilities") or inner.get("data") or []
            elif isinstance(inner, list):
                vulns = inner
        elif isinstance(data, list):
            vulns = data

        if not vulns:
            return f"No CVEs matched the query: '{query}'"

        return _format_vulnx_search_output(
            __import__("json").dumps(vulns), query
        )

    def _resolve_asset_type(self, value: str) -> AssetType:
        """Infer AssetType from a raw value string."""
        import re
        v = value.strip().lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
            return AssetType.IP_ADDRESS
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", v):
            return AssetType.IP_RANGE
        if v.startswith(("http://", "https://")):
            return AssetType.URL
        if "." in v and v.count(".") >= 2:
            return AssetType.SUBDOMAIN
        if "." in v:
            return AssetType.DOMAIN
        return AssetType.OTHER

    def _extract_hostname(self, value: str) -> str:
        """Extract clean hostname/domain from a URL or value."""
        v = value.strip()
        if v.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse
                p = urlparse(v)
                return (p.netloc or p.path.split("/")[0] or v).split(":")[0]
            except Exception:
                pass
        return v.rstrip("/").split("/")[0].split(":")[0]

    def _get_or_create_asset(self, db, org_id: int, target: str) -> "Asset":
        """Find existing asset or create a new one for the given target.

        Tries exact match, then case-insensitive, then creates a new asset.
        Returns the Asset ORM object (already flushed so it has an id).
        """
        target_clean = self._extract_hostname(target)
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.value == target_clean)
            .first()
        )
        if asset:
            return asset
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.value.ilike(target_clean))
            .first()
        )
        if asset:
            return asset

        asset_type = self._resolve_asset_type(target)
        root = target_clean
        parts = target_clean.split(".")
        if len(parts) > 2:
            root = ".".join(parts[-2:])

        new_asset = Asset(
            organization_id=org_id,
            name=target_clean,
            value=target_clean,
            asset_type=asset_type,
            root_domain=root,
            discovery_source="agent",
            status=AssetStatus.DISCOVERED,
            is_monitored=True,
        )
        db.add(new_asset)
        db.flush()
        return new_asset

    async def add_asset(
        self,
        value: str,
        asset_type: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Add a target to the asset inventory so it can be scanned and receive findings.

        Use this when a target URL/domain/IP is not yet in the database. The asset
        will be created with status=discovered and can then be used with create_finding,
        query_assets, and scan tools.

        Args:
            value: The hostname, domain, IP, or URL to add (e.g. "test-git.glensserver.com")
            asset_type: Optional override — DOMAIN, SUBDOMAIN, IP_ADDRESS, URL, etc. Auto-detected if omitted.
            description: Optional description of the asset.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context."
        if not value or not value.strip():
            return "Error: 'value' is required (hostname, domain, IP, or URL)."

        target_clean = self._extract_hostname(value.strip())

        db = SessionLocal()
        try:
            existing = (
                db.query(Asset)
                .filter(Asset.organization_id == org_id, Asset.value.ilike(target_clean))
                .first()
            )
            if existing:
                return (
                    f"Asset already exists: id={existing.id}, value={existing.value}, "
                    f"type={existing.asset_type.value if existing.asset_type else 'N/A'}. "
                    f"No action needed — you can now use create_finding with target='{existing.value}'."
                )

            resolved_type = self._resolve_asset_type(value.strip())
            if asset_type:
                try:
                    resolved_type = AssetType(asset_type.upper())
                except (ValueError, KeyError):
                    pass

            root = target_clean
            parts = target_clean.split(".")
            if len(parts) > 2:
                root = ".".join(parts[-2:])

            new_asset = Asset(
                organization_id=org_id,
                name=target_clean,
                value=target_clean,
                asset_type=resolved_type,
                root_domain=root,
                discovery_source="agent",
                status=AssetStatus.DISCOVERED,
                is_monitored=True,
                description=(description or "")[:2000] if description else None,
            )
            db.add(new_asset)
            db.commit()
            db.refresh(new_asset)
            return (
                f"Asset added: id={new_asset.id}, value={new_asset.value}, "
                f"type={new_asset.asset_type.value}. "
                f"You can now scan it and use create_finding with target='{new_asset.value}'."
            )
        except Exception as e:
            db.rollback()
            logger.exception("add_asset failed")
            return f"Error adding asset: {e}"
        finally:
            db.close()

    async def create_scan(
        self,
        scan_type: str,
        targets: Optional[List[str]] = None,
        name: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        """Create an async scan job processed by the scanner worker. Use this for
        bulk operations (scanning many IPs/domains) instead of execute_* tools.

        The scan runs in the background — results appear in the Scans page and
        update asset records automatically.

        Args:
            scan_type: One of: port_scan, vulnerability, waybackurls, katana,
                       paramspider, http_probe, technology, screenshot,
                       login_portal, subdomain_enum, dns_resolution, discovery,
                       full, geo_enrich, tldfinder, whatweb, atlas_discovery,
                       argus_secrets, hermes_secrets, janus_dast, themis_cspm,
                       graphql_scan, subdomain_takeover, js_recon, jsluice_scan,
                       llm_red_team, commoncrawl_enum
            targets: List of hostnames, domains, or IPs to scan. If omitted,
                     scans all org domains/assets automatically.
            name: Optional scan name (auto-generated if omitted).
            config: Optional dict with scan-specific settings, e.g.
                    {"severity": ["critical","high"]} for vulnerability scans,
                    {"ports": "80,443,8080"} for port_scan.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context."
        if not scan_type:
            return "Error: scan_type is required."

        from app.models.scan import Scan, ScanType as ST, ScanStatus

        type_map = {
            "port_scan": ST.PORT_SCAN,
            "vulnerability": ST.VULNERABILITY,
            "waybackurls": ST.WAYBACKURLS,
            "katana": ST.KATANA,
            "paramspider": ST.PARAMSPIDER,
            "http_probe": ST.HTTP_PROBE,
            "technology": ST.TECHNOLOGY,
            "whatweb": ST.WHATWEB,
            "screenshot": ST.SCREENSHOT,
            "login_portal": ST.LOGIN_PORTAL,
            "subdomain_enum": ST.SUBDOMAIN_ENUM,
            "dns_resolution": ST.DNS_RESOLUTION,
            "discovery": ST.DISCOVERY,
            "full": ST.FULL,
            "geo_enrich": ST.GEO_ENRICH,
            "tldfinder": ST.TLDFINDER,
            "atlas_discovery": ST.ATLAS_DISCOVERY,
            "argus_secrets": ST.ARGUS_SECRETS,
            "hermes_secrets": ST.HERMES_SECRETS,
            "janus_dast": ST.JANUS_DAST,
            "themis_cspm": ST.THEMIS_CSPM,
            "graphql_scan": ST.GRAPHQL_SCAN,
            "subdomain_takeover": ST.SUBDOMAIN_TAKEOVER,
            "js_recon": ST.JS_RECON,
            "jsluice_scan": ST.JSLUICE_SCAN,
            "llm_red_team": ST.LLM_RED_TEAM,
            "commoncrawl_enum": ST.COMMONCRAWL_ENUM,
        }
        st = type_map.get(scan_type.lower().strip())
        if not st:
            return (
                f"Unknown scan_type '{scan_type}'. Valid types: {', '.join(sorted(type_map.keys()))}"
            )

        auto_name = name or f"Agent {scan_type} scan"
        scan_config = dict(config or {})
        scan_config["created_by"] = "agent"

        db = SessionLocal()
        try:
            new_scan = Scan(
                name=auto_name[:255],
                scan_type=st,
                organization_id=org_id,
                targets=targets or [],
                config=scan_config,
                status=ScanStatus.PENDING,
                started_by="agent",
            )
            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)

            try:
                from app.api.routes.scans import send_scan_to_sqs
                send_scan_to_sqs(new_scan)
            except Exception:
                pass

            target_desc = f"{len(targets)} targets" if targets else "all org assets"
            return (
                f"Scan created: id={new_scan.id}, type={scan_type}, status=pending, "
                f"targets={target_desc}. The scanner worker will pick it up automatically. "
                f"Results will appear on the Scans page and update asset records."
            )
        except Exception as e:
            db.rollback()
            logger.exception("create_scan failed")
            return f"Error creating scan: {e}"
        finally:
            db.close()

    async def create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        evidence: Optional[str] = None,
        cve_id: Optional[str] = None,
        remediation: Optional[str] = None,
        steps_to_reproduce: Optional[str] = None,
        proof_of_concept: Optional[str] = None,
        affected_component: Optional[str] = None,
        impact: Optional[str] = None,
        demonstrated_chain: Optional[str] = None,
        not_demonstrated: Optional[str] = None,
        context: Optional[str] = None,
        references: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Create a vulnerability/finding in the platform findings table.

        Medium+ requires prior validate_finding SUBMIT (Solomon judge gate).
        Write demonstrated-compromise reports, not scanner hits. Map onto these fields:
        - description: how access was obtained (product/version, credential or pattern, how it was found, rate-limit/lockout notes)
        - impact: what was retrieved (database counts, PII, hashes, topology, config) — not merely 'login succeeded'
        - target: full URL of the affected asset (scheme + host + port)
        - remediation: immediate credential rotation, access controls, password policy, follow-up resets
        - references: vendor hardening docs and OWASP/CWE URLs
        - demonstrated_chain: JSON array of proof steps [{summary, outcome, tool, args, result}]
        - not_demonstrated: what was NOT attempted (hash cracking, data modification, lateral movement)
        Default/weak login alone is not a finding until privileged impact is proven.
        If demonstrated_chain is omitted, the last live execute_* calls against this target are attached.
        """
        from app.services.agent.finding_gate import consume_or_check_receipt

        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context. create_finding requires an active session."

        # Solomon / Praetorian-style demonstrated-compromise gate
        ok, gate_msg = consume_or_check_receipt(
            getattr(self, "_finding_receipts", {}),
            title=title or "",
            target=target,
            severity=severity or "info",
            require=not bool(kwargs.get("skip_judge_gate")),
        )
        if not ok:
            return gate_msg

        # Normalize target for asset lookup: strip scheme and path
        target_clean = (target or "").strip()
        if target_clean.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse
                p = urlparse(target_clean)
                target_clean = p.netloc or p.path.split("/")[0] or target_clean
            except Exception:
                pass
        target_clean = target_clean.rstrip("/").split("/")[0].split(":")[0] or target
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
        severity_enum = sev_map.get((severity or "info").strip().lower(), Severity.INFO)
        db = SessionLocal()
        try:
            asset = self._get_or_create_asset(db, org_id, target_clean)
            auto_added = not asset.id or db.is_modified(asset)
            if auto_added:
                db.flush()
                logger.info(f"create_finding auto-added asset: {asset.value} (id={asset.id})")
            steps = steps_to_reproduce or kwargs.get("steps_to_reproduce")
            poc = proof_of_concept or kwargs.get("proof_of_concept") or kwargs.get("poc")
            component = affected_component or kwargs.get("affected_component")
            impact_text = impact or kwargs.get("impact")
            chain_raw = demonstrated_chain or kwargs.get("demonstrated_chain")
            not_demo = not_demonstrated or kwargs.get("not_demonstrated")
            context_text = context or kwargs.get("context")
            refs_raw = references or kwargs.get("references")
            from app.services.agent.demonstrated_chain import (
                build_agent_detection,
                parse_references,
            )
            agent_detection = build_agent_detection(
                chain=chain_raw,
                invocations=list(getattr(self, "_recent_invocations", [])),
                target=target_clean or target,
                context=context_text,
                not_demonstrated=not_demo,
                references=refs_raw,
                assets=target,
                session_id=current_session_id.get(),
            )
            parsed_refs = parse_references(refs_raw)
            vuln = Vulnerability(
                title=(title or "Agent finding")[:500],
                description=(description or "")[:10000] if description else None,
                severity=severity_enum,
                asset_id=asset.id,
                detected_by="agent",
                evidence=(evidence or "")[:5000] if evidence else None,
                cve_id=(cve_id or "").strip() or None,
                remediation=(remediation or "")[:5000] if remediation else None,
                steps_to_reproduce=(str(steps)[:10000] if steps else None),
                proof_of_concept=(str(poc)[:10000] if poc else None),
                affected_component=(str(component)[:1000] if component else None),
                impact=(str(impact_text)[:5000] if impact_text else None),
                references=parsed_refs or None,
                metadata_={"agent_detection": agent_detection},
            )
            db.add(vuln)
            db.commit()
            db.refresh(vuln)
            chain_n = (agent_detection or {}).get("step_count") or 0
            msg = (
                f"Finding created: id={vuln.id}, title={vuln.title[:60]}..., "
                f"severity={vuln.severity.value}, asset={asset.value}"
                f"{f', demonstrated_chain={chain_n} steps' if chain_n else ''}"
            )
            # CVE→CWE loop-back into engagement brain methodologies
            if vuln.cve_id:
                try:
                    from app.services.vuln_intel_enrichment import enrich_cve_catalog
                    from app.services.agent.engagement_brain import (
                        engagement_brain_from_dict,
                        boost_methodologies_for_cwes,
                    )
                    catalog = enrich_cve_catalog(
                        vuln.cve_id, use_cache=True, include_exploit_sources=False
                    )
                    cwes = list(catalog.get("cwes") or [])
                    if cwes:
                        brain = engagement_brain_from_dict(
                            getattr(self, "_engagement_brain", None)
                        )
                        boosted = boost_methodologies_for_cwes(
                            brain,
                            cwes,
                            cve_id=vuln.cve_id,
                            evidence=title,
                        )
                        self._engagement_brain = brain.to_dict()
                        if boosted:
                            msg += (
                                f" | CVE→CWE loop-back boosted "
                                f"{len(boosted)} methodology card(s): "
                                + ", ".join(
                                    (h.methodology_id or h.id) for h in boosted[:4]
                                )
                            )
                        if catalog.get("cwe_intel"):
                            names = [
                                f"{r.get('cwe_id')} ({r.get('name')})"
                                for r in catalog["cwe_intel"][:3]
                            ]
                            msg += f" | CWEs: {', '.join(names)}"
                except Exception:
                    logger.debug("create_finding CVE→CWE loop-back failed", exc_info=True)
            return msg
        except Exception as e:
            db.rollback()
            logger.exception("create_finding failed")
            return f"Error creating finding: {e}"
        finally:
            db.close()

    async def sanitize_evidence(
        self,
        evidence: str,
        preserve_last: int = 4,
    ) -> str:
        """
        Redact sensitive values from evidence before creating a finding or report.

        Args:
            evidence: Raw request/response/log/screenshot OCR text to sanitize.
            preserve_last: Number of trailing characters to keep for token fingerprints.
        """
        if not evidence:
            return json.dumps({"sanitized": "", "redactions": []}, indent=2)

        preserve_last = max(0, min(int(preserve_last or 4), 8))
        redactions: List[Dict[str, Any]] = []

        def replacement(label: str, value: str) -> str:
            suffix = value[-preserve_last:] if preserve_last and len(value) > preserve_last else ""
            redactions.append({"type": label, "length": len(value)})
            return f"[REDACTED_{label}{':' + suffix if suffix else ''}]"

        sanitized = evidence

        header_patterns = [
            (r"(?i)(authorization:\s*bearer\s+)([A-Za-z0-9._~+/=-]{12,})", "BEARER_TOKEN"),
            (r"(?i)(api[-_]?key:\s*)([A-Za-z0-9._~+/=-]{12,})", "API_KEY"),
            (r"(?i)(x-api-key:\s*)([A-Za-z0-9._~+/=-]{12,})", "API_KEY"),
            (r"(?i)(cookie:\s*)([^\r\n]+)", "COOKIE_HEADER"),
            (r"(?i)(set-cookie:\s*)([^\r\n;]+)", "SET_COOKIE"),
        ]
        for pattern, label in header_patterns:
            sanitized = _re.sub(
                pattern,
                lambda m, lbl=label: m.group(1) + replacement(lbl, m.group(2)),
                sanitized,
            )

        value_patterns = [
            (r"\bAKIA[0-9A-Z]{16}\b", "AWS_ACCESS_KEY"),
            (r"\bASIA[0-9A-Z]{16}\b", "AWS_TEMP_ACCESS_KEY"),
            (r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "GITHUB_TOKEN"),
            (r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", "SLACK_TOKEN"),
            (r"\bsk_live_[A-Za-z0-9]{16,}\b", "STRIPE_SECRET"),
            (r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "PRIVATE_KEY"),
            (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JWT"),
            (r"\b(?:\d[ -]*?){13,19}\b", "PAYMENT_CARD"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL"),
        ]
        for pattern, label in value_patterns:
            flags = _re.DOTALL if label == "PRIVATE_KEY" else 0
            sanitized = _re.sub(
                pattern,
                lambda m, lbl=label: replacement(lbl, m.group(0)),
                sanitized,
                flags=flags,
            )

        # Redact common JSON/form secret fields while preserving field names.
        field_pattern = (
            r'(?i)("?(?:password|passwd|secret|token|access_token|refresh_token|'
            r'id_token|client_secret|api_key|apikey|session|sessionid|auth_code)"?\s*[:=]\s*)'
            r'("?)([^",\s&}]{6,})\2'
        )
        sanitized = _re.sub(
            field_pattern,
            lambda m: m.group(1) + m.group(2) + replacement("SECRET_FIELD", m.group(3)) + m.group(2),
            sanitized,
        )

        return json.dumps({
            "sanitized": sanitized[:_tool_output_max_chars()],
            "redaction_count": len(redactions),
            "redactions": redactions[:100],
        }, indent=2)

    async def scan_js_urls_for_secrets(
        self,
        urls: str,
        max_urls: int = 30,
    ) -> str:
        """Fetch remote JS/text URLs, run Gitleaks --no-git, and regex hints. urls = newline- or comma-separated https URLs."""
        import asyncio

        from app.services.js_url_secrets_service import scan_js_urls_for_secrets as run_scan

        try:
            mu = int(max_urls) if max_urls is not None else 30
        except (TypeError, ValueError):
            mu = 30
        mu = max(1, min(mu, 100))
        try:
            result = await asyncio.to_thread(run_scan, urls, mu)
        except Exception as e:
            logger.exception("scan_js_urls_for_secrets failed")
            return json.dumps({"success": False, "error": str(e)}, indent=2)
        return json.dumps(result, indent=2, default=str)

    async def scan_js_urls_for_vulns(
        self,
        urls: str,
        max_urls: int = 30,
    ) -> str:
        """Fetch remote JS bundle URLs and run Retire.js to detect vulnerable libraries (by CVE). urls = newline- or comma-separated https URLs (or a JSON object)."""
        import asyncio

        from app.services.retirejs_service import scan_js_urls_for_vulns as run_scan

        # Accept a JSON object {"urls": ..., "max_urls": ...} as well as a bare list.
        url_input = urls
        if isinstance(urls, str) and urls.strip().startswith("{"):
            try:
                obj = json.loads(urls)
                url_input = obj.get("urls", "")
                if obj.get("max_urls") is not None:
                    max_urls = obj.get("max_urls")
            except json.JSONDecodeError:
                pass

        try:
            mu = int(max_urls) if max_urls is not None else 30
        except (TypeError, ValueError):
            mu = 30
        mu = max(1, min(mu, 100))
        try:
            result = await asyncio.to_thread(run_scan, url_input, mu)
        except Exception as e:
            logger.exception("scan_js_urls_for_vulns failed")
            return json.dumps({"success": False, "error": str(e)}, indent=2)
        return json.dumps(result, indent=2, default=str)

    async def execute_llm_red_team(
        self,
        target_url: str,
        categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        message_field: Optional[str] = None,
        auto_discover: bool = True,
        max_payloads: Optional[int] = None,
        create_findings: bool = True,
        **kwargs: Any,
    ) -> str:
        """Run LLM red team scan against chatbot/AI endpoints on a target URL. Tests for prompt injection, jailbreak, data exfiltration, SSRF, excessive agency, tool_enumeration (enumerate agent tools then abuse params), and more. Optionally auto-discovers chat endpoints. If endpoint_url is provided, it will be tested directly. categories = prompt_injection|system_prompt_leakage|data_exfiltration|jailbreak|ssrf_tool_abuse|excessive_agency|tool_enumeration|hallucination|harmful_content (comma-separated or list; omit for all). Returns a formatted report of findings."""
        from app.services.llm_red_team.scanner import (
            run_scan, ScanConfig, ChatEndpoint, format_scan_report, build_finding_data,
        )
        _, org_id = get_tenant_context()

        cat_list = None
        if categories:
            if isinstance(categories, str):
                cat_list = [c.strip() for c in categories.split(",")]
            else:
                cat_list = list(categories)

        endpoints = []
        if endpoint_url:
            endpoints.append(ChatEndpoint(
                url=endpoint_url.strip(),
                message_field=message_field or "message",
                detected_by="agent",
            ))

        config = ScanConfig(
            target_url=target_url.strip(),
            endpoints=endpoints,
            categories=cat_list,
            auto_discover=auto_discover,
            use_llm_grading=True,
            max_payloads=int(max_payloads) if max_payloads else None,
        )

        try:
            scan_result = await run_scan(config)
        except Exception as e:
            logger.exception("LLM red team scan failed")
            return f"Error running LLM red team scan: {e}"

        if create_findings and org_id and scan_result.vulnerabilities_found > 0:
            db = SessionLocal()
            try:
                created_count = 0
                for test_result in scan_result.results:
                    if test_result.get("verdict") != "fail":
                        continue
                    finding_data = build_finding_data(test_result, target_url)
                    asset = self._get_or_create_asset(db, org_id, target_url.strip())
                    if not asset.id or db.is_modified(asset):
                        db.flush()
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                    vuln = Vulnerability(
                        title=finding_data["title"][:500],
                        description=finding_data.get("description", "")[:10000],
                        severity=sev_map.get(finding_data.get("severity", "medium"), Severity.MEDIUM),
                        asset_id=asset.id,
                        detected_by="llm_red_team",
                        template_id=finding_data.get("template_id"),
                        evidence=finding_data.get("evidence", "")[:5000],
                        cwe_id=finding_data.get("cwe_id"),
                        remediation=finding_data.get("remediation", "")[:5000],
                        tags=finding_data.get("tags", []),
                        metadata_=finding_data.get("metadata", {}),
                    )
                    db.add(vuln)
                    created_count += 1
                db.commit()
                logger.info(f"LLM red team: created {created_count} findings for {target_url}")
            except Exception as e:
                db.rollback()
                logger.exception("Failed to create LLM red team findings")
                scan_result.errors.append(f"Finding creation error: {e}")
            finally:
                db.close()

        report = format_scan_report(scan_result)
        max_chars = _tool_output_max_chars()
        if len(report) > max_chars:
            report = report[:max_chars] + "\n\n... (truncated)"
        return report

    async def save_note(
        self,
        category: str,
        content: str,
        target: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Save a session note (credential, vulnerability, finding, artifact). Uses current org/session from context."""
        user_id, org_id = get_tenant_context()
        session_id = current_session_id.get()
        if not org_id:
            return "Error: No organization context. save_note requires an active session."
        db = SessionLocal()
        try:
            note = AgentNote(
                organization_id=org_id,
                user_id=user_id,
                session_id=session_id,
                category=category.strip().lower() if category else "finding",
                content=content[:10000] if content else "",
                target=target[:512] if target else None,
            )
            db.add(note)
            db.commit()
            return f"Saved note: category={note.category}, target={note.target or 'N/A'}"
        except Exception as e:
            db.rollback()
            logger.exception("save_note failed")
            return f"Error saving note: {e}"
        finally:
            db.close()

    def get_session_notes(
        self,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
    ) -> str:
        """Return formatted session notes for prompt injection. Used by orchestrator or get_notes tool."""
        _, org_id = get_tenant_context()
        if not org_id:
            return "No session notes (no organization context)."
        db = SessionLocal()
        try:
            q = db.query(AgentNote).filter(AgentNote.organization_id == org_id)
            if session_id:
                q = q.filter(AgentNote.session_id == session_id)
            if category:
                q = q.filter(AgentNote.category == category.strip().lower())
            notes = q.order_by(AgentNote.created_at.desc()).limit(50).all()
            if not notes:
                return "No session notes yet."
            lines = []
            for n in notes:
                target_str = f" target={n.target}" if n.target else ""
                lines.append(f"- [{n.category}]{target_str}: {n.content[:500]}{'...' if len(n.content) > 500 else ''}")
            return "\n".join(lines)
        finally:
            db.close()

    async def get_notes(
        self,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Get session notes (optionally filtered by category). Uses current session from context if session_id not provided."""
        sid = session_id or current_session_id.get()
        return self.get_session_notes(session_id=sid, category=category)
    
    async def generate_injection_payloads(
        self,
        vuln_type: str = "sqli",
        technique: Optional[str] = None,
        max_payloads: int = 20,
        collaborator_url: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Generate injection payloads for a given vulnerability type.

        Args:
            vuln_type: sqli, xss, ssti, cmdi, path_traversal, xxe, ssrf, crlf, open_redirect
            technique: Sub-technique (e.g. "time_based" for sqli, "encoded" for xss).
                       Omit to get payloads from all sub-techniques.
            max_payloads: Max payloads to return (default 20).
            collaborator_url: Replace COLLABORATOR placeholder for out-of-band payloads.
        """
        from app.services.agent.injection_payloads import generate_payloads
        result = generate_payloads(
            vuln_type=vuln_type,
            technique=technique,
            max_payloads=max_payloads,
            collaborator_url=collaborator_url,
        )
        return json.dumps(result, indent=2)

    async def discover_parameters(
        self,
        url: str = "",
        **kwargs: Any,
    ) -> str:
        """Fetch a URL and extract injectable parameters from HTML forms, URL query strings, and JavaScript.

        Args:
            url: The URL to analyze for parameters.

        Returns:
            JSON with discovered parameters, their locations, and which vuln classes they may be prone to.
        """
        if not url or not url.strip():
            return json.dumps({"error": "url is required"})

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        import re as _re_local
        from app.services.agent.injection_payloads import INTERESTING_PARAM_NAMES

        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
        except Exception as e:
            return json.dumps({"error": f"Failed to fetch {url}: {e}"})

        body = resp.text
        params_found: Dict[str, Dict[str, Any]] = {}

        # 1. Query string params from the final URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(str(resp.url))
        for name in parse_qs(parsed.query):
            params_found[name] = {"source": "query_string", "method": "GET"}

        # 2. HTML form inputs
        form_pattern = _re_local.compile(
            r'<form[^>]*>(.*?)</form>', _re_local.DOTALL | _re_local.IGNORECASE
        )
        input_pattern = _re_local.compile(
            r'<(?:input|textarea|select)[^>]*?name=["\']([^"\']+)["\']', _re_local.IGNORECASE
        )
        action_pattern = _re_local.compile(
            r'action=["\']([^"\']*)["\']', _re_local.IGNORECASE
        )
        method_pattern = _re_local.compile(
            r'method=["\']([^"\']*)["\']', _re_local.IGNORECASE
        )

        for form_match in form_pattern.finditer(body):
            form_html = form_match.group(0)
            action = action_pattern.search(form_html)
            method = method_pattern.search(form_html)
            form_action = action.group(1) if action else ""
            form_method = (method.group(1) if method else "GET").upper()

            for inp in input_pattern.finditer(form_html):
                name = inp.group(1)
                params_found[name] = {
                    "source": "form",
                    "method": form_method,
                    "form_action": form_action,
                }

        # 3. Hidden inputs (sometimes outside forms)
        hidden_pattern = _re_local.compile(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']', _re_local.IGNORECASE
        )
        for m in hidden_pattern.finditer(body):
            name = m.group(1)
            if name not in params_found:
                params_found[name] = {"source": "hidden_input", "method": "POST"}

        # 4. JavaScript variable names and AJAX params
        js_param_patterns = [
            _re_local.compile(r'[?&](\w+)=', _re_local.IGNORECASE),
            _re_local.compile(r'["\']([\w]+)["\']:\s*["\']', _re_local.IGNORECASE),
        ]
        for pat in js_param_patterns:
            for m in pat.finditer(body):
                name = m.group(1)
                if len(name) >= 2 and name not in params_found and not name.startswith(("__", "0x")):
                    params_found[name] = {"source": "javascript", "method": "GET/POST"}

        # 5. Classify parameters by vulnerability proneness
        for name, info in params_found.items():
            name_lower = name.lower()
            prone_to = []
            for vuln_class, param_names in INTERESTING_PARAM_NAMES.items():
                if name_lower in param_names:
                    prone_to.append(vuln_class.replace("_prone", ""))
            if prone_to:
                info["likely_vulnerable_to"] = prone_to

        return json.dumps({
            "url": str(resp.url),
            "status_code": resp.status_code,
            "parameter_count": len(params_found),
            "parameters": params_found,
        }, indent=2)

    async def auto_select_tools(
        self,
        target: str = "",
        **kwargs: Any,
    ) -> str:
        """Analyze the current assessment state and return prioritized tool
        recommendations based on discovered technologies, ports, parameters,
        and WAF presence.

        This tool reads the agent's accumulated target_info and execution_trace
        from the orchestrator state (passed via kwargs by the orchestrator) and
        returns a ranked list of tools to run next with rationale.

        Args:
            target: The primary target hostname/URL to generate recommendations for.
        """
        from app.services.agent.tool_selector import get_tool_recommendations_json

        target_info = kwargs.get("_target_info") or {}
        execution_trace = kwargs.get("_execution_trace") or []
        current_phase = kwargs.get("_current_phase") or "informational"
        parameters = kwargs.get("_parameters") or {}
        waf_detected = kwargs.get("_waf_detected")

        if not target:
            target = target_info.get("primary_target") or ""

        if not target:
            return json.dumps({
                "error": "No target specified. Provide a target URL or hostname.",
                "hint": "Use auto_select_tools(target='example.com') or run execute_httpx first to populate target_info.",
            }, indent=2)

        recs = get_tool_recommendations_json(
            target=target,
            target_info=target_info,
            execution_trace=execution_trace,
            current_phase=current_phase,
            parameters=parameters,
            waf_detected=waf_detected,
        )

        return json.dumps({
            "target": target,
            "current_phase": current_phase,
            "tools_already_run": list({
                s.get("tool_name") for s in execution_trace if s.get("tool_name")
            }),
            "recommendation_count": len(recs),
            "recommendations": recs,
        }, indent=2)

    async def execute_mcp_tool(self, tool_name: str = None, args: str = "", **kwargs) -> str:
        """
        Execute an MCP security tool.
        
        This method delegates to the MCP server for tool execution.
        
        Args:
            tool_name: Name of the MCP tool to execute
            args: CLI arguments for the tool
        
        Returns:
            Tool output as string
        """
        mcp = self._get_mcp_server()
        
        # Get the actual tool name from kwargs if provided
        actual_tool = tool_name or kwargs.get("_tool_name", "")
        
        if not actual_tool:
            return "Error: No tool name specified"
        
        # Build arguments
        arguments = {"args": args} if args else kwargs
        
        # Call MCP tool
        result = await mcp.call_tool(actual_tool, arguments)
        
        max_chars = _tool_output_max_chars()
        if result.get("success"):
            output = result.get("output", "")
            if len(output) > max_chars:
                output = output[:max_chars] + f"\n\n... (truncated, {len(result['output'])} total chars)"
            return output or "Command completed with no output."
        else:
            err = result.get("error", "Unknown error")
            out = result.get("output", "")
            err_max = min(8000, max_chars)
            if out and out.strip():
                return f"Error: {err}\nStdout:\n{out[:err_max]}" + ("\n... (truncated)" if len(out) > err_max else "")
            return f"Error: {err}"

    async def execute_uncover(
        self,
        query: str,
        engines: Optional[List[str]] = None,
        limit: int = 100,
        timeout: int = 120,
        persist: bool = False,
    ) -> str:
        """ProjectDiscovery Uncover - search Shodan/Censys/FOFA/Hunter/Quake in one go.

        Args:
            query: Engine-specific search DSL (e.g. ``"apache" country:"US"``).
            engines: List of engines to hit. Defaults to ["shodan","censys","fofa"].
            limit: Max results per engine.
            timeout: Command timeout in seconds.
            persist: If True, materialize discovered hosts as Assets in the DB.
        """
        from app.services.uncover_service import run_uncover, persist_uncover_assets
        if not query or not query.strip():
            return "Error: query is required."

        result = await run_uncover(
            query=query,
            engines=engines,
            limit=limit,
            timeout=timeout,
        )

        persisted = 0
        if persist:
            _, org_id = get_tenant_context()
            if org_id:
                db = SessionLocal()
                try:
                    persisted = persist_uncover_assets(db, org_id, result)
                finally:
                    db.close()

        payload = {
            "query": result.query,
            "engines": result.engines,
            "used_binary": result.used_binary,
            "duration_seconds": result.duration_seconds,
            "hit_count": len(result.hits),
            "errors": result.errors,
            "persisted_assets": persisted,
            "hits": [
                {
                    "host": h.host,
                    "port": h.port,
                    "engine": h.engine,
                }
                for h in result.hits[:200]
            ],
        }
        return json.dumps(payload, indent=2)[:_tool_output_max_chars()]

    async def search_memory(
        self,
        query: str,
        room: Optional[str] = None,
        limit: int = 5,
    ) -> str:
        """Semantic search over org-scoped verbatim palace memory.

        Covers RoE/scope docs, prior tool output, specialist diaries, and
        mined knowledge. Use before repeating recon, crawl, WAF, or Nuclei.
        """
        from app.services.agent.palace_memory import search_memory as palace_search

        _, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "no tenant context"}, indent=2)
        if not query or not str(query).strip():
            return json.dumps({"error": "query is required"}, indent=2)
        rows = palace_search(
            org_id,
            query,
            room=(room or None),
            limit=max(1, min(int(limit or 5), 10)),
        )
        return json.dumps(
            {"query": query, "count": len(rows), "results": rows},
            indent=2,
        )[:_tool_output_max_chars()]

    async def store_memory(
        self,
        content: str,
        room: str = "general",
        title: str = "",
        target: Optional[str] = None,
    ) -> str:
        """Store a verbatim (redacted) drawer in this org's palace.

        Use for durable notes that should survive this session: WAF vendor,
        in-scope hosts, killed techniques, confirmed findings.
        """
        from app.services.agent.palace_memory import HALL_FACTS, store_drawer, wing_for_org

        _, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "no tenant context"}, indent=2)
        if not content or not str(content).strip():
            return json.dumps({"error": "content is required"}, indent=2)
        ids = store_drawer(
            org_id,
            content,
            wing=wing_for_org(org_id),
            room=(room or "general")[:128],
            hall=HALL_FACTS,
            title=title or "",
            source="manual",
            session_id=current_session_id.get() or None,
            target=target,
        )
        return json.dumps({"stored": len(ids), "ids": ids, "room": room or "general"})

    async def search_knowledge_base(
        self,
        query: str,
        limit: int = 5,
    ) -> str:
        """Alias of search_memory — palace search including mined knowledge docs."""
        return await self.search_memory(query=query, limit=limit)

    async def query_prior_sessions(
        self,
        max_chains: int = 5,
        max_findings: int = 15,
        max_failures: int = 10,
    ) -> str:
        """Return a markdown digest of prior sessions, findings and lessons learned
        for the current organization, pulled from the EvoGraph cross-session memory
        (Neo4j). Returns an empty string if Neo4j is unavailable or empty.
        """
        from app.services.agent import evograph
        _user_id, org_id = get_tenant_context()
        session_id = current_session_id.get() or ""
        if not org_id:
            return ""
        return evograph.get_prior_chain_context(
            organization_id=org_id,
            current_session_id=session_id,
            max_chains=max_chains,
            max_findings=max_findings,
            max_failures=max_failures,
        ) or ""

    # ──────────────────────────────────────────────────────────────────────
    # Bug chain lookup table: confirmed_vuln → likely follow-on vulns
    # ──────────────────────────────────────────────────────────────────────
    _BUG_CHAINS: Dict[str, List[Dict[str, str]]] = {
        "ssrf": [
            {"vuln": "Cloud Metadata Exfiltration", "severity": "critical", "why": "SSRF reaches AWS/GCP/Azure metadata endpoints exposing IAM credentials."},
            {"vuln": "Internal Network Pivot (Redis, Elasticsearch, Jenkins)", "severity": "high", "why": "SSRF pivots to unauthenticated internal services."},
            {"vuln": "SSRF → RCE via internal Consul/Kubernetes API", "severity": "critical", "why": "Internal orchestration APIs often have no auth."},
            {"vuln": "SSRF via PDF/Image renderer → LFI (file:// scheme)", "severity": "high", "why": "wkhtmltopdf / Headless Chrome server-side renderers follow file:// URIs."},
        ],
        "xss": [
            {"vuln": "Account Takeover via Cookie Theft", "severity": "high", "why": "Stored XSS + document.cookie exfil = ATO when HttpOnly is absent."},
            {"vuln": "CSRF via XSS (SameSite bypass)", "severity": "high", "why": "In-browser execution bypasses SameSite cookie restrictions for CSRF."},
            {"vuln": "Admin Privilege Escalation via Admin-visible XSS", "severity": "critical", "why": "XSS in admin panel can create new admins or dump secrets."},
            {"vuln": "postMessage Hijacking (DOM XSS)", "severity": "medium", "why": "Insecure postMessage listeners amplify DOM XSS to cross-origin data theft."},
        ],
        "sqli": [
            {"vuln": "Authentication Bypass", "severity": "critical", "why": "OR-based SQLi in login forms defeats authentication entirely."},
            {"vuln": "PII / Credential Exfiltration", "severity": "critical", "why": "UNION or error-based SQLi dumps user tables and password hashes."},
            {"vuln": "File Read/Write → RCE (MySQL LOAD/INTO OUTFILE)", "severity": "critical", "why": "MySQL FILE privilege with misconfigured secure_file_priv allows shell upload."},
            {"vuln": "Second-Order SQLi", "severity": "high", "why": "Payload stored in DB, triggered on a later query — bypasses most scanners."},
        ],
        "idor": [
            {"vuln": "Mass Account Enumeration", "severity": "high", "why": "Sequential/predictable IDs allow scraping all user records."},
            {"vuln": "Privilege Escalation to Admin", "severity": "critical", "why": "Accessing admin-role object IDs or manipulating role fields."},
            {"vuln": "Private File / Document Disclosure", "severity": "high", "why": "IDOR on file IDs leaks contracts, PII, medical records."},
            {"vuln": "IDOR + Mass Assignment → Account Takeover", "severity": "critical", "why": "Combining writable user fields with IDOR enables full ATO."},
        ],
        "open_redirect": [
            {"vuln": "OAuth Access Token Theft via redirect_uri", "severity": "high", "why": "Open redirect in redirect_uri leaks OAuth tokens to attacker."},
            {"vuln": "Phishing / Credential Harvesting", "severity": "medium", "why": "Trusted-domain redirect enables convincing phishing pages."},
            {"vuln": "SSRF via server-side redirect following", "severity": "high", "why": "If the server follows the redirect, it becomes an SSRF pivot."},
        ],
        "xxe": [
            {"vuln": "LFI via XXE (file:// entity)", "severity": "high", "why": "XXE reads /etc/passwd, ~/.aws/credentials, app config files."},
            {"vuln": "SSRF via XXE (http:// entity)", "severity": "high", "why": "XXE forces internal HTTP requests — same impact as SSRF."},
            {"vuln": "Blind XXE via OOB DNS / HTTP callback", "severity": "high", "why": "Error-blind XXE exfiltrates data through DNS or HTTP callbacks."},
            {"vuln": "XXE → RCE via PHP expect:// or phar:// wrapper", "severity": "critical", "why": "PHP stream wrappers convert XXE into code execution on legacy stacks."},
        ],
        "lfi": [
            {"vuln": "Log Poisoning → RCE", "severity": "critical", "why": "Include access.log after injecting PHP into User-Agent → RCE."},
            {"vuln": "SSH Key / Credential Disclosure", "severity": "high", "why": "LFI of ~/.ssh/id_rsa or /etc/shadow leaks credentials."},
            {"vuln": "PHP Session File Disclosure", "severity": "high", "why": "LFI of /tmp/sess_<token> discloses active PHP sessions."},
            {"vuln": "LFI → RCE via phar:// / zip:// wrapper", "severity": "critical", "why": "PHP stream wrappers escalate file inclusion to code execution."},
        ],
        "csrf": [
            {"vuln": "Account Takeover via Password/Email Change", "severity": "high", "why": "CSRF on password-change or email-update = ATO."},
            {"vuln": "Admin Action Execution", "severity": "high", "why": "CSRF on admin-only actions when admin visits attacker-controlled page."},
            {"vuln": "SSRF via CSRF (server-side request forgery chain)", "severity": "high", "why": "CSRF on an SSRF-prone action chains into SSRF impact."},
        ],
        "broken_auth": [
            {"vuln": "Account Takeover via Password Reset Flaw", "severity": "critical", "why": "Weak tokens, host-header injection in reset link, or token reuse."},
            {"vuln": "MFA Bypass", "severity": "high", "why": "Missing MFA on API endpoints or OTP brute-force with no rate limiting."},
            {"vuln": "Session Fixation", "severity": "high", "why": "Token not rotated on login/logout allows session fixation attack."},
            {"vuln": "JWT Algorithm Confusion (RS256 → HS256)", "severity": "critical", "why": "RS256 public key used as HS256 HMAC secret forges arbitrary tokens."},
        ],
        "rce": [
            {"vuln": "Reverse Shell / C2 Persistence", "severity": "critical", "why": "RCE enables persistent foothold and lateral movement."},
            {"vuln": "Credential Harvesting from Config / Env Vars", "severity": "critical", "why": "DB credentials, API keys, k8s secrets are trivially readable."},
            {"vuln": "Cloud Metadata → IAM Privilege Escalation", "severity": "critical", "why": "EC2/GCP instance metadata provides IAM role credentials."},
            {"vuln": "Container Escape (privileged / CAP_SYS_ADMIN)", "severity": "critical", "why": "Privileged Docker container or host-mounted socket → host escape."},
        ],
        "mass_assignment": [
            {"vuln": "Privilege Escalation (role = admin)", "severity": "critical", "why": "Mass-assigning the role field promotes any user to admin."},
            {"vuln": "Account Balance / Credits Manipulation", "severity": "critical", "why": "Assigning balance/credits field bypasses payment logic."},
            {"vuln": "Email Takeover via email field assignment", "severity": "high", "why": "Overwriting email field hijacks the account without a reset flow."},
            {"vuln": "DRF/OpenAPI writable id/created across CRUD serializers", "severity": "high", "why": "Request schemas without readOnly on id/created enable resource overwrite via ID collision. Schema proof is enough if the DB is down."},
            {"vuln": "Writable user/owner on group/asset create", "severity": "critical", "why": "Any authenticated user can assign ownership to an arbitrary user (cross-user mass assignment)."},
            {"vuln": "List endpoints with no tenant isolation", "severity": "critical", "why": "Operation text like 'shared across all users' means every registrant sees the same object hierarchy."},
            {"vuln": "Writable schedule/periodic_task on monitoring assets", "severity": "high", "why": "Unauthorized task scheduling on ICS/OT monitoring assets. Prove via schema; do not enable production schedules."},
            {"vuln": "Unauth GET /api/auth/account/?email= (security: {} + role leak)", "severity": "critical", "why": "Same schema often marks account lookup public. 500 vs sibling 401 proves JWT was skipped. One canary email; do not spray."},
        ],
        "unauth_account_lookup": [
            {"vuln": "Schema-documented public account lookup (security: {} + is_staff/role)", "severity": "critical", "why": "OpenAPI marks GET /api/auth/account/ unauthenticated and the UserAccount model returns email, is_active, valid_through, is_staff, role."},
            {"vuln": "JWT bypass proven by 401 siblings vs 500/200 lookup", "severity": "critical", "why": "Protected /api/auth/profile/ and /users/me/ return 401 without a token. The lookup reaches app code (200 or 500). A down database is not a kill."},
            {"vuln": "Privilege-targeted credential attacks", "severity": "high", "why": "Enumerating is_staff/role lets an attacker aim password attacks at admin/maintainer accounts. One canary email only — do not spray employee inboxes or dump ICS users."},
        ],
        "business_logic": [
            {"vuln": "Race Condition on Transaction / Balance", "severity": "high", "why": "Concurrent requests exploit TOCTOU in balance/inventory checks."},
            {"vuln": "Negative Price / Discount Stacking", "severity": "high", "why": "Missing input validation on price/discount fields."},
            {"vuln": "Order State Skip (unpaid → shipped)", "severity": "medium", "why": "Manipulating workflow state variables skips payment enforcement."},
        ],
        "subdomain_takeover": [
            {"vuln": "Cookie Tossing / Session Hijacking", "severity": "high", "why": "Taken-over subdomain sets cookies for the parent domain."},
            {"vuln": "Phishing via Trusted Company Subdomain", "severity": "medium", "why": "Company subdomain used for convincing phishing campaigns."},
            {"vuln": "CSP Whitelist Bypass", "severity": "medium", "why": "Subdomain in CSP whitelist — takeover bypasses Content Security Policy."},
        ],
        "cache_poisoning": [
            {"vuln": "Stored XSS via Cached Response", "severity": "high", "why": "Poisoned cache serves malicious payload to all visitors of the page."},
            {"vuln": "Denial of Service via Cache Corruption", "severity": "medium", "why": "Injecting error responses into cache causes widespread availability issues."},
            {"vuln": "Open Redirect via X-Forwarded-Host", "severity": "medium", "why": "Poisoned redirect target serves attacker-controlled redirect to all users."},
        ],
        "request_smuggling": [
            {"vuln": "Cache Poisoning via Smuggled Poison", "severity": "high", "why": "Smuggled poison request poisons the cache for subsequent victims."},
            {"vuln": "Authentication Bypass via Smuggled Prefix", "severity": "critical", "why": "Prefix injected by smuggling rewrites the next victim's request."},
            {"vuln": "XSS via Smuggled Reflected Content", "severity": "high", "why": "Reflected content from smuggled request executes in victim's browser."},
            {"vuln": "Internal Service Access via Smuggling", "severity": "high", "why": "Smuggled request routes to internal endpoints not exposed externally."},
        ],
        "host_header": [
            {"vuln": "Password Reset Poisoning → ATO", "severity": "critical", "why": "Reset email absolute URL uses attacker Host / X-Forwarded-Host."},
            {"vuln": "Host-Header Tenant Isolation Bypass", "severity": "critical", "why": "Same session + peer-tenant Host/X-Forwarded-Host returns other tenant data."},
            {"vuln": "Web Cache Poisoning via Unkeyed Host", "severity": "high", "why": "Host influences cache key inconsistently across layers."},
            {"vuln": "Routing SSRF", "severity": "high", "why": "Host selects upstream → internal service or metadata access."},
        ],
        "default_login": [
            {"vuln": "Grafana Admin Settings / Service-Account Enum", "severity": "critical", "why": "Server Admin GET /api/admin/settings and /api/serviceaccounts/search disclose pod identity, DB config, and API token inventory."},
            {"vuln": "Grafana Existing Prometheus Datasource Proxy → Cluster Topology", "severity": "critical", "why": "Relay PromQL via the existing kube-prometheus-stack datasource (/api/datasources/proxy) to enumerate in-cluster exporters and kubelets — no new datasource required."},
            {"vuln": "CouchDB _config Secret + Admin Salt Exposure", "severity": "critical", "why": "GET /_node/_local/_config returns couch_httpd_auth.secret, timeout, and [admins] salts — the HMAC inputs for AuthSession. Survives password rotation."},
            {"vuln": "CouchDB AuthSession Cookie Forgery", "severity": "critical", "why": "HMAC-SHA1(secret+admin_salt) forges a valid AuthSession for any server admin without their password; prove via /_session _admin + /_all_dbs."},
            {"vuln": "Grafana CVE-2024-9264 SQL expressions (Viewer+)", "severity": "critical", "why": "POST /api/ds/query type=sql forks DuckDB. Missing binary still confirms the vulnerable path; sqlExpressions=0 in /metrics does not disable the backend. Patch is 11.2.2+."},
            {"vuln": "Grafana Datasource-Proxy SSRF → Internal AKS/K8s", "severity": "critical", "why": "If no existing Prometheus DS: Server Admin can create one pointing at kubernetes.default.svc / metadata when whitelist is empty."},
            {"vuln": "Admin API / Config Abuse", "severity": "critical", "why": "Admin session can change auth, datasources, or exfil secrets."},
            {"vuln": "Privilege Persistence", "severity": "high", "why": "Create backdoor users/tokens before password change."},
        ],
        "elasticsearch_unauth": [
            {"vuln": "Cluster/node metadata disclosure", "severity": "critical", "why": "Unauth GET /_cluster/health and /_nodes/os,jvm disclose hostname, OS, kernel, JVM."},
            {"vuln": "Index enumeration + sample read", "severity": "critical", "why": "Unauth GET /_cat/indices plus size=1 sample of user indices (prompts, chat, ransomware notes). Do not dump all docs."},
            {"vuln": "Arbitrary write via test index", "severity": "critical", "why": "PUT then DELETE aegis_test_index proves create/delete without credentials. Do not write into customer indices."},
            {"vuln": "Prior compromise / ransomware note", "severity": "high", "why": "User indices named read_me often contain extortion notes — evidence the cluster was already hit."},
        ],
        "arangodb_default": [
            {"vuln": "ArangoDB collection sample / PII", "severity": "critical", "why": "root JWT lists databases; one collection sample proves read of registration/Cookie_Data without dumping PII."},
        ],
        "mongodb_unauth": [
            {"vuln": "MongoDB listDatabases + ransomware-note integrity", "severity": "critical", "why": "Anonymous listDatabases; READ_ME_TO_RECOVER_YOUR_DATA means prior compromise."},
        ],
        "emqx_default": [
            {"vuln": "EMQX authn/plugin admin", "severity": "critical", "why": "admin:public unlocks listeners, users, and plugin upload — do not upload plugins."},
        ],
        "cors_credentials": [
            {"vuln": "CORS ACAO reflection + credentials=true", "severity": "critical", "why": "Arbitrary Origin echoed with Access-Control-Allow-Credentials: true lets attacker JS read cookie-authenticated responses. Header proof is enough; no victim tab required."},
            {"vuln": "Keycloak webOrigins=* on token/userinfo/admin", "severity": "critical", "why": "IdP CORS on /auth/realms/*/protocol/openid-connect/* and /auth/admin/realms/* exposes userinfo claims and admin user/client APIs to any website. Fix: webOrigins explicit or '+', never '*'."},
            {"vuln": "Preflight allows Authorization + POST/PUT/DELETE from any origin", "severity": "high", "why": "OPTIONS from a canary origin is approved with Authorization in Allow-Headers."},
            {"vuln": "Socket.IO unauth get_stream IDOR", "severity": "high", "why": "After ACAO+credentials, get_stream accepts empty userType and arbitrary siteId."},
        ],
        "keycloak_password_grant": [
            {"vuln": "admin-cli public client + password grant", "severity": "critical", "why": "grant_type=password with client_id=admin-cli and no client_secret returns invalid_grant, not invalid_client. Master tokens are full realm-admin."},
            {"vuln": "No brute-force detection on the token endpoint", "severity": "critical", "why": "Bounded failed password-grant attempts are all processed with no 429 or lockout. Do not hydra; 8 attempts is enough proof."},
            {"vuln": "CORS compounds browser credential stuffing", "severity": "high", "why": "Filed separately: ACAO+credentials on the token endpoint lets a malicious page submit password grants."},
        ],
        "client_role_param": [
            {"vuln": "Cross-tenant inventory via userType=Admin", "severity": "critical", "why": "publicPortal trusts client userType; Admin returns the full site list."},
        ],
        "vendorjson_unauth": [
            {"vuln": "Internal IP / SuperRegulator map", "severity": "high", "why": "vendorJson discloses userId, roles, and RFC1918 addresses for every tenant."},
        ],
        "auth0_mgmt_token": [
            {"vuln": "Auth0 user/client directory read", "severity": "critical", "why": "Unauth token is accepted by /api/v2 with read:users/read:clients — prove with per_page=1."},
        ],
        "gitlab_unauth": [
            {"vuln": "Hardcoded secrets in public GitLab files", "severity": "critical", "why": "Unauth /api/v4/projects then one-file sample for passwords/keys."},
        ],
        "docker_registry": [
            {"vuln": "Registry image pull / possible push", "severity": "high", "why": "/v2/_catalog with no auth; do not push."},
        ],
        "django_debug": [
            {"vuln": "Leaked Redis key from DEBUG traceback", "severity": "critical", "why": "admin:admin + DEBUG=True 500 dumps Azure Redis and env; ping only, no FLUSHALL."},
        ],
        "openai_proxy_unauth": [
            {"vuln": "Unauth model spend / tool execution", "severity": "high", "why": "POST /api/chat proxies to Azure OpenAI with no session — one canary then stop."},
        ],
        "wiki_open_reg": [
            {"vuln": "Self-registered wiki write / internal PII", "severity": "high", "why": "Open CreateAccount grants sandbox write or internal page read — do not deface production."},
        ],
        "binary_hardcoded_creds": [
            {"vuln": "Production password in public installer/firmware", "severity": "critical", "why": "strings extracts live creds; prove one in-scope login. Do not reverse for exploits."},
        ],
        "client_side_auth": [
            {"vuln": "Admin/eLogbook API without server session", "severity": "critical", "why": "JS-only isAdmin/userType gate; backing API returns privileged records anonymously."},
        ],
        "saml": [
            {"vuln": "Account Takeover via Assertion Tampering", "severity": "critical", "why": "Unsigned or wrapped assertions change NameID to victim."},
            {"vuln": "SSO Privilege Escalation", "severity": "critical", "why": "Group/role attributes accepted without signature validation."},
            {"vuln": "Metadata XXE / SSRF", "severity": "high", "why": "IdP metadata fetch parses attacker XML or URLs."},
        ],
        "graphql": [
            {"vuln": "BOLA via node(id) / global IDs", "severity": "high", "why": "GraphQL object IDs lack field-level authz."},
            {"vuln": "Auth Bypass Mutation", "severity": "critical", "why": "Unauth mutations change email/password/role."},
            {"vuln": "Batching / Alias Rate-Limit Bypass", "severity": "medium", "why": "Aliased queries evade per-request throttles."},
        ],
        "js_secrets": [
            {"vuln": "Hostname-keyed client_id/client_secret in Next.js chunks", "severity": "critical", "why": "Admin/sandbox /_next/static/chunks often embed prod/dev/qa OAuth client secrets keyed by hostname."},
            {"vuln": "Live IAM/API gateway access with leaked headers", "severity": "critical", "why": "client_id/client_secret HTTP headers authenticate to locations/account APIs and return non-public records."},
            {"vuln": "Cross-environment secret reuse (sandbox ships prod)", "severity": "critical", "why": "A sandbox UI bundle that contains production client_secret requires rotating ALL env pairs, not just sandbox."},
            {"vuln": "Bulk enumeration via search/queryText", "severity": "high", "why": "Authenticated search parameters enable targeted or bulk record retrieval — prove with a bounded sample, then recommend rate limits."},
            {"vuln": "EmailJS unauthorized send (phishing via authorized ESP)", "severity": "critical", "why": "Hardcoded EmailJS user_id/service_id/template_id in JS lets any site send mail as the app from a visitor's browser; template_params set the recipient."},
        ],
        "azure_function_env_dump": [
            {"vuln": "Classify runtime secret classes", "severity": "critical", "why": "Anonymous Tester/debug HTTP trigger returns process env: Cosmos master keys, Storage account keys, MACHINEKEY, EasyAuth WEBSITE_AUTH_*, AAD client secrets, App Insights, Key Vault URIs."},
            {"vuln": "Cosmos master key → internet-accessible DB", "severity": "critical", "why": "Master key grants read/write/delete on employee identity and project records. Prove with one read-only list of databases/containers; no item dumps or writes."},
            {"vuln": "Storage account key inventory", "severity": "critical", "why": "AzureWebJobsStorage account key lists the Function App content share. List containers only — do not upload packages or write wwwroot."},
            {"vuln": "Peer Function App via -dev- naming", "severity": "high", "why": "Tenants pair ra-*-fa (prod) with ra-*-dev-fa. The same anonymous trigger is often on both."},
            {"vuln": "Managed identity / Key Vault blast radius (prerequisites only)", "severity": "critical", "why": "Storage key + MACHINEKEY can lead to code as the system-assigned MI with Key Vault secret get/set. Document prerequisites via ARM/Graph; do not inject code or wait for a restart."},
            {"vuln": "AAD client secret rotation order", "severity": "high", "why": "Env may hold an expired secret while Key Vault holds the live one. Rotate AAD secrets last, after Tester is removed, so new values cannot re-leak."},
        ],
    }

    async def detect_bug_chains(
        self,
        vuln_type: str,
        target: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> str:
        """Return vulnerability classes that commonly chain with a confirmed finding.

        Use this after confirming a vulnerability to discover what else to test.
        Returns chains ranked by severity with attack path explanations.

        Args:
            vuln_type: Confirmed or suspected vulnerability class. Supported:
                       ssrf, xss, sqli, idor, open_redirect, xxe, lfi, csrf,
                       broken_auth, rce, mass_assignment, business_logic,
                       subdomain_takeover, cache_poisoning, request_smuggling,
                       host_header, saml, graphql, default_login, js_secrets,
                       elasticsearch_unauth, azure_function_env_dump, arangodb_default,
                       mongodb_unauth, emqx_default, cors_credentials, unauth_account_lookup,
                       client_role_param,
                       vendorjson_unauth, auth0_mgmt_token, gitlab_unauth, docker_registry,
                       django_debug, openai_proxy_unauth, wiki_open_reg, binary_hardcoded_creds,
                       client_side_auth.
            target: Optional hostname/URL for context in the output.
            notes: Optional notes about the confirmed finding.
        """
        key = (vuln_type or "").strip().lower().replace("-", "_").replace(" ", "_")
        alias_map = {
            "bola": "idor", "object_injection": "idor",
            "reflected_xss": "xss", "stored_xss": "xss", "dom_xss": "xss",
            "sql_injection": "sqli", "injection": "sqli",
            "redirect": "open_redirect",
            "xml_injection": "xxe",
            "path_traversal": "lfi", "directory_traversal": "lfi",
            "authentication_bypass": "broken_auth", "auth_bypass": "broken_auth",
            "account_takeover": "broken_auth",
            "code_execution": "rce", "command_injection": "rce", "cmdi": "rce",
            "parameter_pollution": "mass_assignment",
            "logic_flaw": "business_logic",
            "smuggling": "request_smuggling", "http_smuggling": "request_smuggling",
            "cache": "cache_poisoning", "web_cache": "cache_poisoning",
            "subdomain_takeover": "subdomain_takeover", "takeover": "subdomain_takeover",
            "hostheader": "host_header", "host_header_injection": "host_header",
            "password_reset_poisoning": "host_header",
            "default_credentials": "default_login", "default-login": "default_login",
            "default_creds": "default_login", "weak_password": "default_login",
            "grafana": "default_login", "grafana_default_login": "default_login",
            "cwe_1393": "default_login", "cwe-1393": "default_login",
            "couchdb": "default_login", "authsession": "default_login",
            "cookie_forgery": "default_login", "session_forgery": "default_login",
            "js_secrets": "js_secrets", "hardcoded_credentials": "js_secrets",
            "client_secret": "js_secrets", "cwe_312": "js_secrets", "cwe-312": "js_secrets",
            "cwe_540": "js_secrets", "cwe-540": "js_secrets",
            "emailjs": "js_secrets", "email_js": "js_secrets",
            "elasticsearch": "elasticsearch_unauth",
            "elasticsearch_unauth": "elasticsearch_unauth",
            "exposed_elasticsearch": "elasticsearch_unauth",
            "xpack_security": "elasticsearch_unauth",
            "azure_function_env_dump": "azure_function_env_dump",
            "azure_function": "azure_function_env_dump",
            "function_app": "azure_function_env_dump",
            "authlevel_anonymous": "azure_function_env_dump",
            "tester_function": "azure_function_env_dump",
            "cwe_526": "azure_function_env_dump",
            "cwe-526": "azure_function_env_dump",
            "arangodb": "arangodb_default", "arangodb_default": "arangodb_default",
            "mongodb": "mongodb_unauth", "mongodb_unauth": "mongodb_unauth",
            "emqx": "emqx_default", "emqx_default": "emqx_default",
            "cors": "cors_credentials", "cors_credentials": "cors_credentials",
            "keycloak_password_grant": "keycloak_password_grant",
            "admin-cli": "keycloak_password_grant",
            "password_grant": "keycloak_password_grant",
            "cwe-307": "keycloak_password_grant",
            "unauth_account_lookup": "unauth_account_lookup",
            "user_enum": "unauth_account_lookup",
            "user_enumeration": "unauth_account_lookup",
            "account_enumeration": "unauth_account_lookup",
            "cwe-204": "unauth_account_lookup",
            "cwe_204": "unauth_account_lookup",
            "usertype": "client_role_param", "client_role_param": "client_role_param",
            "vendorjson": "vendorjson_unauth", "vendorjson_unauth": "vendorjson_unauth",
            "auth0": "auth0_mgmt_token", "auth0_mgmt_token": "auth0_mgmt_token",
            "gitlab": "gitlab_unauth", "gitlab_unauth": "gitlab_unauth",
            "docker_registry": "docker_registry",
            "django": "django_debug", "django_debug": "django_debug",
            "openai_proxy": "openai_proxy_unauth", "openai_proxy_unauth": "openai_proxy_unauth",
            "wiki": "wiki_open_reg", "wiki_open_reg": "wiki_open_reg",
            "binary_hardcoded_creds": "binary_hardcoded_creds",
            "downloadable_binary": "binary_hardcoded_creds",
            "client_side_auth": "client_side_auth",
            "sso": "saml", "saml_sso": "saml",
            "gql": "graphql",
        }
        key = alias_map.get(key, key)
        chains = self._BUG_CHAINS.get(key)
        if not chains:
            return json.dumps({
                "error": f"No chain data for '{vuln_type}'.",
                "supported_types": sorted(self._BUG_CHAINS.keys()),
            }, indent=2)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranked = sorted(chains, key=lambda c: sev_order.get(c.get("severity", "medium"), 4))
        by_sev: Dict[str, list] = {}
        for c in ranked:
            by_sev.setdefault(c["severity"], []).append(c)
        return json.dumps({
            "confirmed_vuln": vuln_type,
            "target": target or "not specified",
            "notes": notes or None,
            "chain_count": len(chains),
            "chains_by_severity": by_sev,
            "next_steps": [
                f"[{c['severity'].upper()}] Test for {c['vuln']}: {c['why']}"
                for c in ranked
            ],
        }, indent=2)

    async def validate_finding(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        target: Optional[str] = None,
        evidence: Optional[str] = None,
        cve_id: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> str:
        """Validation gate — score a proposed finding before reporting.

        Evaluates the finding against demonstrated-compromise criteria and returns
        SUBMIT, IMPROVE, or DROP. Default/weak login IMPROVE until privileged
        API impact is documented.

        Args:
            title: Short finding title.
            description: Full description of the vulnerability.
            severity: Proposed severity (critical/high/medium/low/info).
            target: Affected hostname or URL.
            evidence: Request/response snippet or reproduction proof.
            cve_id: Optional CVE ID if mapping to a known CVE.
            remediation: Optional remediation guidance.
        """
        text = f"{title} {description} {evidence or ''} {remediation or ''}".lower()
        questions: List[Dict[str, Any]] = []

        # Q1: Demonstrable technical impact
        impact_words = ["access", "execute", "exfiltrat", "bypass", "steal", "read", "write",
                        "delete", "escalat", "takeover", "inject", "expose", "leak", "dump",
                        "disclose", "overwrite", "redirect", "forge"]
        q1 = any(w in text for w in impact_words)
        questions.append({
            "question": "Is there demonstrable technical impact?",
            "pass": q1,
            "feedback": "PASS — clear impact language found." if q1 else
                        "FAIL — describe the concrete impact (data exposed, action achievable, etc.).",
        })

        # Q2: Reachable by an external attacker
        privileged_only = any(w in text for w in ["requires admin", "internal only", "localhost only",
                                                    "requires physical", "requires vpn access",
                                                    "not internet-facing"])
        q2 = not privileged_only
        questions.append({
            "question": "Is this reachable by an external attacker without prior privileged access?",
            "pass": q2,
            "feedback": "PASS — no privileged-access gating found." if q2 else
                        "FAIL — if it requires admin/VPN/internal access, severity and scope need adjustment.",
        })

        # Q3: Reproducible attack path
        path_words = ["step", "request", "payload", "parameter", "endpoint", "curl", "poc",
                      "proof", "reproduct", "navigate", "visit", "send", "intercept"]
        q3 = any(w in text for w in path_words) or bool(evidence and len(evidence.strip()) > 20)
        questions.append({
            "question": "Is there a clear, reproducible attack path?",
            "pass": q3,
            "feedback": "PASS — reproduction steps or evidence present." if q3 else
                        "FAIL — add step-by-step reproduction instructions or a PoC request.",
        })

        # Q4: Crosses a meaningful security boundary
        boundary_words = ["other user", "another user", "admin", "privilege", "unauthorized",
                          "unauthenticated", "tenant", "account", "cross-user", "cross-tenant",
                          "without authentication", "without authorization", "arbitrary"]
        q4 = any(w in text for w in boundary_words)
        questions.append({
            "question": "Does the impact cross an auth, privilege, or data-ownership boundary?",
            "pass": q4,
            "feedback": "PASS — boundary crossing language found." if q4 else
                        "FAIL — clarify the security boundary violated (e.g. 'access another user's data').",
        })

        # Q5: Has direct evidence (not purely theoretical)
        theoretical_words = ["might", "could potentially", "it is possible that", "theoretically",
                              "in theory", "may be possible", "hypothetically"]
        q5_theoretical = any(w in text for w in theoretical_words)
        q5_has_evidence = bool(evidence and len(evidence.strip()) > 30)
        q5 = q5_has_evidence or not q5_theoretical
        questions.append({
            "question": "Is the finding backed by direct evidence (not purely theoretical)?",
            "pass": q5,
            "feedback": "PASS — evidence provided or non-theoretical language." if q5 else
                        "FAIL — replace theoretical language with a tested payload and observed response.",
        })

        # Q6: Non-trivial severity
        sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        q6 = sev_weight.get(severity.strip().lower(), 0) >= 2
        questions.append({
            "question": "Is the severity at least Medium (meaningful real-world impact)?",
            "pass": q6,
            "feedback": f"PASS — severity '{severity}' is medium or above." if q6 else
                        f"FAIL — severity '{severity}' findings rarely justify submission effort.",
        })

        # Q7: Would survive duplicate/informational review
        dupe_risk_words = ["default page", "missing header", "server version", "banner",
                           "clickjacking", "self-xss", "csrf on logout", "logout csrf",
                           "rate limit on non-sensitive", "no rate limit on login page only",
                           "options method", "http methods", "cors wildcard on public",
                           "graphql introspection alone", "open redirect alone",
                           "host header alone", "dns callback only"]
        q7 = not any(w in text for w in dupe_risk_words)
        questions.append({
            "question": "Is this unlikely to be marked as N/A / Informational / Duplicate?",
            "pass": q7,
            "feedback": "PASS — no common N/A patterns detected." if q7 else
                        "FAIL — common low-value pattern detected; review program policy for acceptability.",
        })

        # Q8: Identity discipline for authz-class findings
        authz_signal = any(w in text for w in [
            "idor", "bola", "bfla", "authorization", "authz", "other user",
            "another user", "cross-user", "cross-tenant", "object-level",
        ])
        identity_signal = any(w in text for w in [
            "user a", "user b", "anonymous", "unauthenticated", "without auth",
            "session a", "session b", "low-priv", "cross-identity", "two accounts",
            "victim user", "attacker account",
            "any authenticated", "shared across", "all users", "readonly",
            "request serializer", "writable id",
            "acao", "allow-credentials", "credentialed", "preflight", "canary origin",
        ])
        q8 = (not authz_signal) or identity_signal
        questions.append({
            "question": "For authz findings: is the proving identity documented (anon / A / B)?",
            "pass": q8,
            "feedback": "PASS — identity context present or not an authz finding." if q8 else
                        "FAIL — document anonymous vs user-A vs user-B repro before submitting IDOR/BOLA.",
        })

        # Q9: Demonstrated-compromise writeup for default/weak credential findings
        cred_finding = any(w in text for w in [
            "default login", "default-login", "default credential", "weak password",
            "prom-operator", "cwe-1393", "cwe 1393", "kube-prometheus",
            "client_secret", "hardcoded credential", "hardcoded api",
            "javascript bundle", "js bundle", "_next/static", "cwe-312", "cwe-540",
            "couchdb-default", "authsession", "couch_httpd_auth", "kevin:kevin",
            "emailjs", "api.emailjs.com",
        ])
        privileged_followup = any(w in text for w in [
            "admin/settings", "/api/admin", "datasources", "serviceaccount",
            "service account", "prometheus", "internal", "cluster", "proxy",
            "retrieved", "enumerated", "disclosed", "pod identity", "grafana.ini",
            "records", "locations", "accountid", "accountname", "postalcode",
            "_node/_local/_config", "couch_httpd_auth", "_all_dbs", "userctx",
            "_admin", "authsession", "forged cookie", "session cookie",
            "template_params", "sent email", "canary inbox", "email/send",
            "duckdb", "fork/exec", "/api/ds/query", "sql expression",
        ])
        q9 = (not cred_finding) or privileged_followup
        questions.append({
            "question": (
                "For default/weak creds or JS-leaked secrets: is privileged impact proven "
                "(admin APIs, live API records) — not merely login success or a key in a bundle?"
            ),
            "pass": q9,
            "feedback": (
                "PASS — privileged impact present or not a credential/secret finding." if q9 else
                "FAIL — foothold only. Prove privileged APIs or a live in-scope API response "
                "(count + redacted sample) before SUBMIT."
            ),
        })

        # Q10: Elasticsearch unauth — banner is a foothold
        es_finding = any(w in text for w in [
            "elasticsearch", ":9200", "xpack.security", "you know, for search",
        ])
        es_read = any(w in text for w in [
            "_cat/indices", "indices", "cluster_name", "_nodes", "_cluster/health",
            "sample", "read_me",
        ])
        es_write = any(w in text for w in [
            "aegis_test_index", "test_index", "acknowledged", "write access",
        ])
        q10 = (not es_finding) or (es_read and es_write)
        questions.append({
            "question": (
                "For unauthenticated Elasticsearch: are indices enumerated AND write "
                "proven (create+delete test index) — not merely an open :9200 banner?"
            ),
            "pass": q10,
            "feedback": (
                "PASS — ES read+write proven or not an Elasticsearch finding." if q10 else
                "FAIL — banner is a foothold. Prove GET /_cat/indices + sample read and "
                "PUT+DELETE aegis_test_index. Do not dump all docs or run Painless RCE."
            ),
        })

        # Q11: Azure Function env dump — classify secret classes, not 'env leaked'
        azfn_finding = any(w in text for w in [
            "azure function", "function app", "authlevel", "azurewebjobsstorage",
            "machinekey", "website_auth", "tester function", "azurewebsites.net",
            "cwe-526", "cwe 526",
        ])
        azfn_classified = any(w in text for w in [
            "cosmos", "storage account", "azurewebjobsstorage", "machinekey",
            "easyauth", "website_auth", "client secret", "application insights",
            "key vault", "instrumentation key",
        ])
        q11 = (not azfn_finding) or azfn_classified
        questions.append({
            "question": (
                "For anonymous Azure Function env dump: are leaked secret classes named "
                "(Cosmos, Storage, MACHINEKEY, EasyAuth, AAD) — not merely 'env vars leaked'?"
            ),
            "pass": q11,
            "feedback": (
                "PASS — secret classes classified or not an Azure Function env-dump finding."
                if q11 else
                "FAIL — env dump is a foothold. Name which classes were retrieved "
                "(Cosmos / Storage / MACHINEKEY / EasyAuth / AAD). Do not inject code; "
                "list managed-identity ACE under not_demonstrated."
            ),
        })

        # Q12: OpenAPI/DRF mass assignment — schema-confirmed writable fields.
        # Do not match bare OpenAPI/schema mentions (account-lookup writeups cite
        # the schema without being mass assignment).
        ma_finding = any(w in text for w in [
            "mass assignment", "mass-assignment", "writable id", "extra_kwargs",
            "property-level", "property level authorization", "cwe-915",
            "request serializer",
        ])
        ma_proof = any(w in text for w in [
            "readonly", "read_only", "writable id", "writable user",
            "shared across", "all users", "periodic_task", "extra_kwargs",
            "not readonly", "without readonly",
        ])
        q12 = (not ma_finding) or ma_proof
        questions.append({
            "question": (
                "For OpenAPI/DRF mass assignment: are writable privileged fields named "
                "(id/created/user without readOnly) or is missing tenant isolation quoted "
                "— not merely 'swagger found'? A down database is not a fail."
            ),
            "pass": q12,
            "feedback": (
                "PASS — schema names writable privileged fields / shared-list, or not a "
                "mass-assignment finding." if q12 else
                "FAIL — OpenAPI without field analysis is a foothold. Count request "
                "serializers missing readOnly on id/created/user, or quote 'all users' "
                "list text. Do not kill because the DB is down."
            ),
        })

        # Q13: CORS ACAO + credentials — header proof is enough.
        # ACAO * without credentials is not this bug (and is extra on account-lookup writeups).
        cors_finding = any(w in text for w in [
            "weborigins",
            "allow-credentials", "allow_credentials",
            "cors reflection", "credentialed cors",
            "acao+credentials",
        ]) or (
            ("acao" in text or "access-control-allow-origin" in text or "cors origin" in text)
            and any(w in text for w in [
                "allow-credentials", "credentials: true", "credentials=true",
                "weborigins", "credentialed cors",
            ])
        )
        cors_proof = any(w in text for w in [
            "credentials: true", "credentials=true", "allow-credentials: true",
            "allow-credentials=true", "reflected", "canary origin", "echoes",
            "echoed", "aegis-cors-canary",
        ])
        q13 = (not cors_finding) or cors_proof
        questions.append({
            "question": (
                "For CORS: is ACAO reflection of a canary Origin proven WITH "
                "Access-Control-Allow-Credentials: true — not merely 'CORS enabled'? "
                "A missing victim browser tab is not a fail."
            ),
            "pass": q13,
            "feedback": (
                "PASS — ACAO+credentials proven or not a CORS finding." if q13 else
                "FAIL — 'CORS enabled' is a foothold. Prove a never-seen Origin is "
                "reflected in ACAO with credentials=true. Do not ship an HTML exploit; "
                "do not dump Keycloak /users. Kill only ACAO=* without credentials."
            ),
        })

        # Q14: Keycloak admin-cli password grant / no lockout
        kc_grant_finding = any(w in text for w in [
            "admin-cli", "admin_cli", "password grant", "direct access grant",
            "resource owner password", "invalid_grant", "cwe-307",
        ])
        kc_grant_proof = any(w in text for w in [
            "invalid_grant", "no client_secret", "without a client secret",
            "public client", "no 429", "no lockout", "not invalid_client",
            "unsupported_grant_type",
        ])
        q14 = (not kc_grant_finding) or kc_grant_proof
        questions.append({
            "question": (
                "For Keycloak admin-cli: is the public password grant proven "
                "(invalid_grant without client_secret) and/or no lockout on a bounded "
                "probe — not merely 'token endpoint exists'? Guessing a valid password "
                "is not required."
            ),
            "pass": q14,
            "feedback": (
                "PASS — public password grant / no-lockout proven, or not an admin-cli finding."
                if q14 else
                "FAIL — prove POST grant_type=password client_id=admin-cli with no secret "
                "returns invalid_grant (not invalid_client). Cap lockout tests at 8. "
                "Do not hydra/rockyou. Do not kill because no password was guessed."
            ),
        })

        # Q15: Unauth OpenAPI account lookup — schema unauth + privilege fields
        # and/or 401 siblings vs 200/500 lookup. DB down is not a fail.
        acct_finding = any(w in text for w in [
            "/api/auth/account", "account lookup", "user enumeration",
            "user account statistics", "account statistics without",
            "cwe-204", "cwe 204",
        ])
        acct_proof = any(w in text for w in [
            "security: {}", "security:{}", "without authentication",
            "is_staff", "valid_through",
            "401 vs 500", "401 vs 200", "vs 401", "versus 401",
            "bypasses the jwt", "bypasses jwt", "jwt authentication middleware",
        ]) or ("401" in text and ("500" in text or "is_staff" in text or "role" in text))
        q15 = (not acct_finding) or acct_proof
        questions.append({
            "question": (
                "For unauth account lookup: is security: {} / 'without authentication' "
                "quoted with privilege fields (is_staff/role), OR is JWT skip proven by "
                "sibling 401 vs lookup 200/500 — not merely 'swagger found'? A down "
                "database is not a fail. One canary email; do not spray."
            ),
            "pass": q15,
            "feedback": (
                "PASS — schema-unauth + privilege fields or 401-vs-500/200 proven, "
                "or not an account-lookup finding." if q15 else
                "FAIL — OpenAPI without security: {} / privilege fields / 401-vs-500 "
                "is a foothold. Quote the public operation and UserAccount fields, or "
                "compare_requests a 401 sibling vs the lookup. Do not kill because the "
                "DB is down or the canary email is unregistered. Do not spray inboxes."
            ),
        })

        score = sum(1 for q in questions if q["pass"])
        total = len(questions)
        if cred_finding and not privileged_followup:
            verdict = "IMPROVE"
            verdict_detail = (
                "Default/weak login or a JS-leaked secret is a foothold, not a finding. "
                "Prove privileged impact (admin APIs, or live API records from leaked "
                "client_id/client_secret) and write description + impact + assets + remediation."
            )
        elif es_finding and not (es_read and es_write):
            verdict = "IMPROVE"
            verdict_detail = (
                "Unauthenticated Elasticsearch banner is a foothold, not a finding. "
                "Prove index enumeration + sample read and PUT+DELETE aegis_test_index. "
                "Do not dump all documents or run Painless RCE."
            )
        elif azfn_finding and not azfn_classified:
            verdict = "IMPROVE"
            verdict_detail = (
                "Anonymous Azure Function env dump is a foothold until leaked secret "
                "classes are named (Cosmos, Storage, MACHINEKEY, EasyAuth, AAD). "
                "Do not inject code as the managed identity; list ACE under not_demonstrated. "
                "Write description + impact + assets + remediation (remove Tester or "
                "authLevel=function; rotate keys; AAD secrets last)."
            )
        elif ma_finding and not ma_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "OpenAPI without named writable privileged fields is a foothold. "
                "Count request serializers missing readOnly on id/created/user/owner, "
                "or quote a list description that shares objects across all users. "
                "A down database is not a kill."
            )
        elif cors_finding and not cors_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "'CORS enabled' is a foothold. Prove a never-seen Origin is reflected "
                "in ACAO with Access-Control-Allow-Credentials: true. Header proof is "
                "enough — no victim tab. Do not dump Keycloak /users or ship an HTML exploit."
            )
        elif kc_grant_finding and not kc_grant_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "Keycloak token endpoint existence is a foothold. Prove admin-cli accepts "
                "grant_type=password with no client_secret (invalid_grant) and/or that "
                "<=8 failures have no 429/lockout. Do not hydra. Do not kill because a "
                "valid password was not guessed."
            )
        elif acct_finding and not acct_proof:
            verdict = "IMPROVE"
            verdict_detail = (
                "OpenAPI/Swagger without a public account operation is a foothold. "
                "Quote security: {} / 'without authentication' and is_staff/role, or "
                "prove JWT skip (sibling 401 vs lookup 200/500). A down database is "
                "not a kill. One canary email; do not spray employee inboxes."
            )
        elif score >= total - 1:
            verdict = "SUBMIT"
            verdict_detail = "Strong finding. Submit with the evidence and steps provided."
        elif score >= 3:
            verdict = "IMPROVE"
            gaps = [q["feedback"] for q in questions if not q["pass"]]
            verdict_detail = "Address the gaps before submitting: " + " | ".join(gaps)
        else:
            verdict = "DROP"
            verdict_detail = "Fundamental issues — likely to be rejected. Address all failing questions."

        receipt_id = None
        if verdict == "SUBMIT":
            from app.services.agent.finding_gate import record_submit_receipt

            if not hasattr(self, "_finding_receipts") or self._finding_receipts is None:
                self._finding_receipts = {}
            receipt_id = record_submit_receipt(
                self._finding_receipts,
                title=title or "",
                target=target,
                severity=severity or "info",
                score=f"{score}/{total}",
            )

        return json.dumps({
            "title": title,
            "severity": severity,
            "target": target or "not specified",
            "score": f"{score}/{total}",
            "verdict": verdict,
            "verdict_detail": verdict_detail,
            "receipt_id": receipt_id,
            "questions": questions,
            "has_evidence": bool(evidence),
            "has_remediation": bool(remediation),
            "has_cve": bool(cve_id),
            "next_step": (
                "create_finding with the same title/target is now unlocked for medium+"
                if receipt_id
                else "Do not create_finding until verdict is SUBMIT"
            ),
        }, indent=2)

    async def bypass_403(
        self,
        url: str,
        techniques: Optional[List[str]] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
    ) -> str:
        """Test for 403/401/302 access restriction bypasses via header tricks,
        path normalization, and method overrides.

        Args:
            url: The restricted URL to test (must return 403/401/302 normally).
            techniques: Subset of bypass classes to run. Options:
                        ip_headers, path_tricks, method_override, protocol_headers.
                        Omit to run all.
            additional_headers: Extra headers to include in every probe (e.g. auth cookies).
            timeout: Per-request timeout in seconds.
        """
        from urllib.parse import urlparse, urlunparse
        import asyncio as _asyncio

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        all_techniques = {"ip_headers", "path_tricks", "method_override", "protocol_headers"}
        active = set(techniques or all_techniques) & all_techniques

        base_headers = dict(additional_headers or {})
        base_headers.setdefault("User-Agent", "Mozilla/5.0 (Security Assessment)")

        parsed = urlparse(url)
        path = parsed.path or "/"

        probes: List[Dict[str, Any]] = []

        if "ip_headers" in active:
            ip_bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
                {"X-Client-IP": "127.0.0.1"},
                {"True-Client-IP": "127.0.0.1"},
                {"CF-Connecting-IP": "127.0.0.1"},
                {"X-Forwarded-For": "::1"},
                {"X-Forwarded-For": "0.0.0.0"},
            ]
            for hdr in ip_bypass_headers:
                probes.append({"label": f"IP header: {list(hdr.keys())[0]}={list(hdr.values())[0]}", "url": url, "headers": {**base_headers, **hdr}, "method": "GET"})

        if "path_tricks" in active:
            path_variants = [
                path + "/",
                path + "/..",
                "/" + path.lstrip("/"),
                path + "%20",
                path + "%09",
                path.replace("/", "//", 1),
                path + "#",
                path + "?",
                _re.sub(r"^(/[^/])", lambda m: "/" + m.group(1), path),
            ]
            # URL-encode first char of last segment
            parts = path.rsplit("/", 1)
            if len(parts) == 2 and parts[1]:
                enc_path = parts[0] + "/" + "%" + format(ord(parts[1][0]), "02X") + parts[1][1:]
                path_variants.append(enc_path)
            for vpath in path_variants:
                vurl = urlunparse(parsed._replace(path=vpath))
                probes.append({"label": f"Path trick: {vpath}", "url": vurl, "headers": base_headers, "method": "GET"})

        if "method_override" in active:
            method_hdrs = [
                {"X-HTTP-Method-Override": "GET"},
                {"X-Method-Override": "GET"},
                {"X-HTTP-Method": "GET"},
            ]
            for hdr in method_hdrs:
                probes.append({"label": f"Method override: {list(hdr.keys())[0]}", "url": url, "headers": {**base_headers, **hdr}, "method": "POST"})
            probes.append({"label": "Method: HEAD", "url": url, "headers": base_headers, "method": "HEAD"})

        if "protocol_headers" in active:
            proto_hdrs = [
                {"X-Forwarded-Proto": "https"},
                {"X-Forwarded-Scheme": "https"},
                {"X-Forwarded-Host": parsed.netloc},
                {"X-Original-URL": path},
                {"X-Rewrite-URL": path},
            ]
            for hdr in proto_hdrs:
                probes.append({"label": f"Protocol header: {list(hdr.keys())[0]}", "url": url, "headers": {**base_headers, **hdr}, "method": "GET"})

        # Baseline request
        baseline_status = None
        baseline_length = 0
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
                br = await client.get(url, headers=base_headers)
                baseline_status = br.status_code
                baseline_length = len(br.content)
        except Exception as e:
            return json.dumps({"error": f"Baseline request failed: {e}"}, indent=2)

        results: List[Dict[str, Any]] = []

        async def probe_one(p: Dict) -> Dict:
            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
                    method = p.get("method", "GET")
                    if method == "POST":
                        resp = await client.post(p["url"], headers=p["headers"])
                    elif method == "HEAD":
                        resp = await client.head(p["url"], headers=p["headers"])
                    else:
                        resp = await client.get(p["url"], headers=p["headers"])
                    return {
                        "label": p["label"],
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "bypassed": resp.status_code not in (401, 403, 302) and resp.status_code < 400,
                    }
            except Exception as ex:
                return {"label": p["label"], "status": "error", "length": 0, "bypassed": False, "error": str(ex)}

        results = await _asyncio.gather(*[probe_one(p) for p in probes])

        bypasses = [r for r in results if r.get("bypassed")]
        return json.dumps({
            "url": url,
            "baseline_status": baseline_status,
            "baseline_length": baseline_length,
            "probes_run": len(probes),
            "bypasses_found": len(bypasses),
            "bypasses": bypasses,
            "all_results": list(results),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_request_smuggling(
        self,
        url: str,
        technique: str = "all",
        timeout: int = 20,
    ) -> str:
        """Probe for HTTP/1.1 request smuggling via timing-based CL.TE and TE.CL
        detection, plus TE.TE obfuscation variants.

        Uses raw TCP/TLS sockets to send precisely crafted requests that bypass
        HTTP client normalization. Timing differences of >5 s indicate a
        vulnerable desync condition.

        Args:
            url: Target base URL (scheme://host[:port]).
            technique: cl_te | te_cl | te_te | all (default).
            timeout: Socket timeout in seconds for the timing probe.
        """
        import asyncio as _asyncio
        import ssl as _ssl
        import time as _time
        from urllib.parse import urlparse as _urlparse

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = _urlparse(url)
        host = parsed.hostname or ""
        use_tls = parsed.scheme == "https"
        port = parsed.port or (443 if use_tls else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        active = {"cl_te", "te_cl", "te_te"} if technique == "all" else {technique}
        findings: List[Dict[str, Any]] = []

        async def raw_send(payload: bytes, label: str) -> Dict[str, Any]:
            start = _time.monotonic()
            try:
                if use_tls:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    reader, writer = await _asyncio.wait_for(
                        _asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
                    )
                else:
                    reader, writer = await _asyncio.wait_for(
                        _asyncio.open_connection(host, port), timeout=timeout
                    )
                writer.write(payload)
                await writer.drain()
                try:
                    data = await _asyncio.wait_for(reader.read(4096), timeout=timeout)
                    elapsed = _time.monotonic() - start
                    status_line = data.decode("utf-8", errors="replace").splitlines()[0] if data else ""
                    writer.close()
                    return {"label": label, "elapsed_s": round(elapsed, 2), "status_line": status_line, "timed_out": False}
                except _asyncio.TimeoutError:
                    elapsed = _time.monotonic() - start
                    writer.close()
                    return {"label": label, "elapsed_s": round(elapsed, 2), "status_line": "TIMEOUT", "timed_out": True}
            except Exception as ex:
                return {"label": label, "elapsed_s": round(_time.monotonic() - start, 2), "status_line": f"ERROR: {ex}", "timed_out": False}

        if "cl_te" in active:
            # CL.TE timing probe: CL says 4 bytes but body has incomplete chunked body.
            # A TE-speaking backend will wait for the continuation → detectable timeout.
            body = b"1\r\nZ\r\nQ"
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode() + body
            r = await raw_send(req, "CL.TE timing probe")
            r["technique"] = "CL.TE"
            r["vulnerable"] = r["timed_out"]
            r["note"] = ("Timeout indicates backend uses Transfer-Encoding — CL.TE desync likely."
                         if r["timed_out"] else "No timeout detected for CL.TE.")
            findings.append(r)

        if "te_cl" in active:
            # TE.CL timing probe: sends a 0-chunk then extra data; CL-speaking backend waits.
            body = b"0\r\n\r\nX"
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode() + body
            r = await raw_send(req, "TE.CL timing probe")
            r["technique"] = "TE.CL"
            r["vulnerable"] = r["timed_out"]
            r["note"] = ("Timeout indicates backend uses Content-Length — TE.CL desync likely."
                         if r["timed_out"] else "No timeout detected for TE.CL.")
            findings.append(r)

        if "te_te" in active:
            # TE.TE: two Transfer-Encoding headers, one obfuscated; only one side de-obfuscates.
            obfuscations = [
                b"Transfer-Encoding: xchunked\r\n",
                b"Transfer-Encoding : chunked\r\n",
                b"Transfer-Encoding: chunked\r\nTransfer-encoding: x\r\n",
                b"Transfer-Encoding:\tchunked\r\n",
                b'Transfer-Encoding: "chunked"\r\n',
            ]
            for obf in obfuscations:
                body = b"0\r\n\r\n"
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 5\r\n"
                ).encode() + b"Transfer-Encoding: chunked\r\n" + obf + b"\r\n" + body
                label = f"TE.TE — {obf.decode('utf-8', errors='replace').strip()}"
                r = await raw_send(req, label)
                r["technique"] = "TE.TE"
                r["vulnerable"] = r["timed_out"]
                r["note"] = ("Timeout with TE.TE obfuscation — one side misparses the TE header."
                             if r["timed_out"] else "No timeout for this TE.TE variant.")
                findings.append(r)

        vulnerable = [f for f in findings if f.get("vulnerable")]
        return json.dumps({
            "url": url,
            "host": host,
            "techniques_tested": list(active),
            "probe_count": len(findings),
            "vulnerable_probes": len(vulnerable),
            "verdict": "LIKELY VULNERABLE" if vulnerable else "Not detected",
            "findings": findings,
            "next_steps": (
                ["Confirm with a differential attack (poison a victim's next request).",
                 "Use Burp Suite's HTTP Request Smuggler extension for deep confirmation.",
                 "Test with execute_curl for response differential if timing is inconclusive."]
                if vulnerable else
                ["No timing-based desync detected. Target may use HTTP/2 or sanitize headers.",
                 "Try HTTP/2 downgrade smuggling (H2.CL / H2.TE) if the site supports HTTP/2."]
            ),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_cache_poisoning(
        self,
        url: str,
        probe_headers: Optional[List[str]] = None,
        timeout: int = 15,
    ) -> str:
        """Probe for web cache poisoning via unkeyed header injection.

        Sends requests with canary values in common unkeyed headers, then
        re-fetches without those headers to check if the canary is reflected
        in a cached response. Also checks for unkeyed query parameter and
        fat GET attack vectors.

        Args:
            url: Target URL to probe.
            probe_headers: List of header names to probe. Defaults to a
                           comprehensive set of known unkeyed headers.
            timeout: Per-request timeout in seconds.
        """
        import uuid as _uuid
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        canary = f"cp-{_uuid.uuid4().hex[:12]}"

        default_headers = [
            "X-Forwarded-Host",
            "X-Host",
            "X-HTTP-Host-Override",
            "Forwarded",
            "X-Forwarded-Scheme",
            "X-Forwarded-Port",
            "X-Forwarded-For",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Prefix",
            "X-Forwarded-Proto",
        ]
        headers_to_probe = probe_headers or default_headers

        results: List[Dict[str, Any]] = []

        async def probe_header(header_name: str) -> Dict[str, Any]:
            canary_value = f"{canary}.attacker.example.com" if "host" in header_name.lower() else canary
            probe_hdrs = {header_name: canary_value, "Cache-Control": "no-cache", "Pragma": "no-cache"}
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                    # Poison probe
                    r1 = await client.get(url, headers={**probe_hdrs, "User-Agent": "Mozilla/5.0 (Security Assessment)"})
                    body1 = r1.text[:4000]
                    reflected_in_poison = canary in body1 or canary_value in body1
                    cache_status_poison = r1.headers.get("X-Cache", r1.headers.get("CF-Cache-Status", "unknown"))

                    # Re-fetch without the probe header (would hit cache)
                    r2 = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (Victim Simulation)"})
                    body2 = r2.text[:4000]
                    reflected_in_clean = canary in body2 or canary_value in body2
                    cache_status_clean = r2.headers.get("X-Cache", r2.headers.get("CF-Cache-Status", "unknown"))

                    poisoned = reflected_in_clean and reflected_in_poison
                    return {
                        "header": header_name,
                        "canary_value": canary_value,
                        "poison_status": r1.status_code,
                        "poison_cache_status": cache_status_poison,
                        "reflected_in_poison_response": reflected_in_poison,
                        "clean_status": r2.status_code,
                        "clean_cache_status": cache_status_clean,
                        "reflected_in_clean_response": reflected_in_clean,
                        "potentially_poisoned": poisoned,
                        "note": (
                            "CANARY REFLECTED IN CLEAN FETCH — cache may be poisoned!" if poisoned else
                            "Canary reflected in poison response only — header is unkeyed but cache not confirmed." if reflected_in_poison else
                            "Canary not reflected."
                        ),
                    }
            except Exception as ex:
                return {"header": header_name, "error": str(ex), "potentially_poisoned": False}

        import asyncio as _asyncio
        results = list(await _asyncio.gather(*[probe_header(h) for h in headers_to_probe]))

        # Fat GET probe: inject query param into body for GET request
        fat_get_result = None
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                r = await client.request("GET", url, content=f"utm_content={canary}",
                                         headers={"Content-Length": str(len(f"utm_content={canary}")),
                                                  "Content-Type": "application/x-www-form-urlencoded"})
                fat_get_result = {"reflected": canary in r.text, "status": r.status_code}
        except Exception:
            fat_get_result = {"reflected": False, "status": "error"}

        confirmed = [r for r in results if r.get("potentially_poisoned")]
        candidates = [r for r in results if r.get("reflected_in_poison_response") and not r.get("potentially_poisoned")]

        return json.dumps({
            "url": url,
            "canary": canary,
            "headers_probed": len(headers_to_probe),
            "confirmed_poisoning": len(confirmed),
            "unkeyed_header_candidates": len(candidates),
            "fat_get_canary_reflected": fat_get_result.get("reflected", False),
            "confirmed": confirmed,
            "candidates": candidates,
            "all_results": results,
            "verdict": (
                "CONFIRMED CACHE POISONING" if confirmed else
                "UNKEYED HEADERS FOUND — manual confirmation needed" if candidates else
                "No cache poisoning indicators detected"
            ),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_race_condition(
        self,
        url: str,
        method: str = "POST",
        concurrency: int = 15,
        body: Optional[Dict[str, Any]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        expected_unique_field: Optional[str] = None,
        timeout: int = 30,
    ) -> str:
        """Fire N concurrent requests to detect race conditions (TOCTOU flaws).

        Useful for testing: coupon/voucher single-use enforcement, balance
        deductions, inventory limits, rate limit bypasses, and idempotency.

        Args:
            url: Target endpoint URL.
            method: HTTP method (GET/POST/PUT/PATCH, default POST).
            concurrency: Number of simultaneous requests (default 15, max 50).
            body: JSON body dict to send with each request.
            auth_headers: Authentication headers (Bearer token, Cookie, etc.).
            expected_unique_field: JSON response field to check for uniqueness
                                   across responses (e.g. "transaction_id").
            timeout: Total timeout in seconds.
        """
        import asyncio as _asyncio
        import time as _time

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        concurrency = max(2, min(50, int(concurrency or 15)))
        method = (method or "POST").upper()
        headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (Race Condition Test)"}
        if auth_headers:
            headers.update(auth_headers)

        responses: List[Dict[str, Any]] = []
        start = _time.monotonic()

        async def one_request(idx: int) -> Dict[str, Any]:
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                    req_start = _time.monotonic()
                    if method in ("POST", "PUT", "PATCH"):
                        resp = await client.request(method, url, json=body, headers=headers)
                    else:
                        resp = await client.get(url, headers=headers)
                    elapsed = round(_time.monotonic() - req_start, 3)
                    try:
                        resp_body = resp.json()
                    except Exception:
                        resp_body = resp.text[:500]
                    return {
                        "idx": idx, "status": resp.status_code,
                        "elapsed_s": elapsed, "body": resp_body,
                        "unique_field": (resp_body.get(expected_unique_field) if isinstance(resp_body, dict) and expected_unique_field else None),
                    }
            except Exception as ex:
                return {"idx": idx, "status": "error", "elapsed_s": 0.0, "body": str(ex), "unique_field": None}

        # Fire all requests concurrently (Last Byte Sync — all requests start as close together as possible)
        responses = list(await _asyncio.gather(*[one_request(i) for i in range(concurrency)]))
        total_elapsed = round(_time.monotonic() - start, 2)

        status_counter: Dict[str, int] = {}
        for r in responses:
            k = str(r["status"])
            status_counter[k] = status_counter.get(k, 0) + 1

        success_responses = [r for r in responses if isinstance(r["status"], int) and r["status"] < 300]

        unique_field_values = [r["unique_field"] for r in responses if r.get("unique_field") is not None]
        duplicate_field_values = len(unique_field_values) != len(set(str(v) for v in unique_field_values))

        race_indicators = []
        if len(success_responses) > 1:
            race_indicators.append(f"{len(success_responses)}/{concurrency} requests succeeded (expected ≤1 for single-use resources).")
        if duplicate_field_values and unique_field_values:
            race_indicators.append(f"Duplicate values in '{expected_unique_field}' field — uniqueness constraint may be broken.")
        if len(set(str(r["status"]) for r in responses)) > 2:
            race_indicators.append("Inconsistent status codes across concurrent requests — non-deterministic state detected.")

        return json.dumps({
            "url": url,
            "method": method,
            "concurrency": concurrency,
            "total_elapsed_s": total_elapsed,
            "status_distribution": status_counter,
            "success_count": len(success_responses),
            "race_indicators": race_indicators,
            "verdict": "RACE CONDITION INDICATORS FOUND" if race_indicators else "No race condition indicators detected",
            "responses": responses,
            "next_steps": (
                ["Run with higher concurrency (30-50) to increase pressure.",
                 "Try with last-byte-sync: pre-connect, send all but last byte, then flush simultaneously.",
                 "Focus on state-changing endpoints: balance, coupon, invite, vote, order."]
                if not race_indicators else
                ["Confirm with a controlled experiment showing state inconsistency.",
                 "Document the duplicated field values or multiple successes as evidence.",
                 "Recommend atomic DB operations or distributed locks as remediation."]
            ),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_saml_sso(
        self,
        url: str,
        categories: Optional[List[str]] = None,
        saml_response_b64: Optional[str] = None,
        timeout: int = 20,
    ) -> str:
        """Probe for SAML/SSO/OAuth misconfigurations and known attack vectors.

        Performs passive endpoint discovery + active probing for common
        authentication bypass techniques. Does NOT attempt credential theft.

        Categories: xml_injection, signature_wrapping, oauth_bypass,
                    jwt_confusion, oidc_misconfig, saml_endpoints.
                    Omit to run all.

        Args:
            url: Base URL of the target application.
            categories: Subset of test categories to run.
            saml_response_b64: Optional base64-encoded SAMLResponse to
                               analyze for signature validation weaknesses.
            timeout: Per-request timeout in seconds.
        """
        import base64 as _b64
        import xml.etree.ElementTree as _ET

        url = url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        all_cats = {"xml_injection", "signature_wrapping", "oauth_bypass", "jwt_confusion", "oidc_misconfig", "saml_endpoints"}
        active = set(categories or all_cats) & all_cats

        findings: List[Dict[str, Any]] = []
        probes_run = 0

        # 1. SAML endpoint discovery
        if "saml_endpoints" in active:
            saml_paths = [
                "/saml/consume", "/saml/acs", "/auth/saml/callback",
                "/sso/saml", "/api/auth/saml", "/saml2/acs",
                "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
                "/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
                "/auth/realms/", "/auth/oauth2/callback", "/login/oauth/callback",
            ]
            discovered_endpoints: List[str] = []
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                for p in saml_paths:
                    probes_run += 1
                    try:
                        r = await client.get(f"{url}{p}")
                        if r.status_code not in (404, 410):
                            discovered_endpoints.append(f"{p} → HTTP {r.status_code}")
                    except Exception:
                        pass
            if discovered_endpoints:
                findings.append({
                    "category": "saml_endpoints",
                    "severity": "info",
                    "title": f"Discovered {len(discovered_endpoints)} auth-related endpoints",
                    "detail": discovered_endpoints,
                })

        # 2. OAuth state parameter check
        if "oauth_bypass" in active:
            oauth_paths = ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize", "/auth/realms/"]
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                for p in oauth_paths:
                    probes_run += 1
                    try:
                        r = await client.get(f"{url}{p}?response_type=code&client_id=test&redirect_uri=https://evil.example.com")
                        if r.status_code in (200, 302, 400):
                            location = r.headers.get("location", "")
                            if "evil.example.com" in location:
                                findings.append({
                                    "category": "oauth_bypass",
                                    "severity": "high",
                                    "title": "Open OAuth Redirect — redirect_uri not validated",
                                    "detail": f"Request to {p} redirected to attacker-controlled evil.example.com. Allows OAuth token theft.",
                                    "evidence": f"Location: {location[:200]}",
                                })
                            elif r.status_code == 200 and "state" not in r.text.lower():
                                findings.append({
                                    "category": "oauth_bypass",
                                    "severity": "medium",
                                    "title": "OAuth authorize endpoint responded — verify state parameter enforcement",
                                    "detail": f"{p} returned 200 without state parameter rejection.",
                                })
                    except Exception:
                        pass

        # 3. OIDC discovery misconfiguration
        if "oidc_misconfig" in active:
            probes_run += 1
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                    r = await client.get(f"{url}/.well-known/openid-configuration")
                    if r.status_code == 200:
                        try:
                            oidc = r.json()
                            issues: List[str] = []
                            if oidc.get("claims_supported") and "email" in oidc.get("claims_supported", []):
                                issues.append("email claim available — verify unique_claim enforcement to prevent account takeover via email match")
                            algos = oidc.get("id_token_signing_alg_values_supported", [])
                            if "none" in algos:
                                issues.append("alg=none supported in id_token — JWT signature bypass possible")
                            if "HS256" in algos:
                                issues.append("HS256 supported alongside RS256 — test for algorithm confusion attack")
                            if issues:
                                findings.append({
                                    "category": "oidc_misconfig",
                                    "severity": "high",
                                    "title": "OIDC Configuration Weaknesses Detected",
                                    "detail": issues,
                                    "oidc_url": f"{url}/.well-known/openid-configuration",
                                })
                        except Exception:
                            pass
            except Exception:
                pass

        # 4. SAMLResponse analysis (if provided)
        if "signature_wrapping" in active and saml_response_b64:
            try:
                decoded = _b64.b64decode(saml_response_b64).decode("utf-8", errors="replace")
                saml_issues: List[str] = []
                if "ds:Signature" not in decoded and "Signature" not in decoded:
                    saml_issues.append("No XML Signature found — response may not be verified")
                if decoded.count("<saml:Assertion") > 1:
                    saml_issues.append("Multiple Assertion elements — possible XSW (XML Signature Wrapping) attack surface")
                if "NotOnOrAfter" not in decoded:
                    saml_issues.append("Missing NotOnOrAfter time constraint — token replay may be possible")
                if "<ds:Reference" in decoded and 'URI=""' in decoded:
                    saml_issues.append("Signature covers empty URI — may allow wrapping attack by adding unsigned assertion")
                try:
                    root = _ET.fromstring(decoded)
                    ns_map = {v: k for k, v in dict(root.nsmap).items()} if hasattr(root, "nsmap") else {}
                except Exception:
                    ns_map = {}
                if saml_issues:
                    findings.append({
                        "category": "signature_wrapping",
                        "severity": "critical",
                        "title": "SAMLResponse Signature Issues Found",
                        "detail": saml_issues,
                        "raw_length": len(decoded),
                    })
                else:
                    findings.append({
                        "category": "signature_wrapping",
                        "severity": "info",
                        "title": "SAMLResponse appears correctly signed",
                        "detail": "No obvious signature wrapping indicators. Manual review recommended.",
                    })
            except Exception as ex:
                findings.append({"category": "signature_wrapping", "severity": "info", "title": "SAMLResponse parse error", "detail": str(ex)})

        # 5. JWT algorithm confusion discovery hint
        if "jwt_confusion" in active:
            findings.append({
                "category": "jwt_confusion",
                "severity": "info",
                "title": "JWT Algorithm Confusion — Manual Test Required",
                "detail": [
                    "Capture a valid JWT from the application.",
                    "Decode the header — note the 'alg' field (RS256, ES256, etc.).",
                    "Fetch the public key from JWKS endpoint (/.well-known/jwks.json or /auth/keys).",
                    "Re-sign the token using the public key as the HMAC-SHA256 secret (alg: HS256).",
                    "If accepted, the server is vulnerable to algorithm confusion (CVE class).",
                    "Tools: jwt_tool.py, python-jwt, or Burp JWT Editor extension.",
                ],
            })

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        return json.dumps({
            "url": url,
            "categories_tested": list(active),
            "probes_run": probes_run,
            "findings_count": len(findings),
            "high_or_critical": len([f for f in findings if f.get("severity") in ("critical", "high")]),
            "findings": findings,
        }, indent=2)[:_tool_output_max_chars()]

    async def test_credential_spray(
        self,
        login_url: str,
        usernames: List[str],
        passwords: List[str],
        username_field: str = "username",
        password_field: str = "password",
        max_attempts: int = 10,
        delay_seconds: float = 2.0,
        success_indicators: Optional[List[str]] = None,
        failure_indicators: Optional[List[str]] = None,
        authorized: bool = False,
    ) -> str:
        """Credential spray test — requires explicit authorization flag.

        Sends login requests with provided credentials, stops at max_attempts
        (hard cap: 20), detects lockout/rate-limiting, and reports hits.

        LEGAL GUARDRAIL: authorized=True MUST be set; the tool refuses
        otherwise. Only use against systems you have explicit written
        permission to test.

        Args:
            login_url: URL of the login endpoint.
            usernames: List of usernames to test.
            passwords: List of passwords to spray (1 password per user is safer).
            username_field: Form/JSON field name for username (default 'username').
            password_field: Form/JSON field name for password (default 'password').
            max_attempts: Hard stop — maximum total login attempts (capped at 20).
            delay_seconds: Delay between each attempt in seconds (minimum 1.0).
            success_indicators: Strings whose presence in the response indicates success.
            failure_indicators: Strings that confirm a failed attempt.
            authorized: MUST be True to proceed. Required legal guardrail.
        """
        import asyncio as _asyncio

        if not authorized:
            return json.dumps({
                "error": "AUTHORIZATION REQUIRED",
                "detail": (
                    "test_credential_spray refused to run. You MUST set authorized=True and "
                    "have explicit written permission to test this system. "
                    "Unauthorized credential testing is illegal under the CFAA, CMA, and similar laws."
                ),
            }, indent=2)

        login_url = login_url.strip()
        if not login_url.startswith(("http://", "https://")):
            login_url = f"https://{login_url}"

        max_attempts = max(1, min(20, int(max_attempts or 10)))
        delay_seconds = max(1.0, float(delay_seconds or 2.0))

        default_success = ["dashboard", "logout", "welcome", "account", "/home", "token", "access_token"]
        default_failure = ["invalid", "incorrect", "wrong", "failed", "error", "locked", "too many"]
        success_ind = success_indicators or default_success
        failure_ind = failure_indicators or default_failure

        results: List[Dict[str, Any]] = []
        attempts = 0
        lockout_detected = False

        for username in usernames:
            for password in passwords:
                if attempts >= max_attempts:
                    results.append({"note": f"Hard stop reached at {max_attempts} attempts."})
                    break
                if lockout_detected:
                    results.append({"note": "Lockout detected — stopping spray to avoid account lockout."})
                    break
                await _asyncio.sleep(delay_seconds)
                try:
                    payload = {username_field: username, password_field: password}
                    async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                        resp = await client.post(login_url, json=payload,
                                                 headers={"Content-Type": "application/json",
                                                          "User-Agent": "Mozilla/5.0 (Authorized Security Test)"})
                        body = resp.text[:2000]
                        body_lower = body.lower()
                        success = (resp.status_code in (200, 302) and
                                   any(s.lower() in body_lower for s in success_ind) and
                                   not any(f.lower() in body_lower for f in failure_ind))
                        lockout = any(w in body_lower for w in ["locked", "too many", "rate limit", "blocked", "captcha"])
                        if lockout:
                            lockout_detected = True
                        results.append({
                            "username": username,
                            "password": "***REDACTED***",
                            "status": resp.status_code,
                            "success": success,
                            "lockout_indicator": lockout,
                            "response_snippet": body[:300],
                        })
                        attempts += 1
                except Exception as ex:
                    results.append({"username": username, "error": str(ex), "success": False})
                    attempts += 1
            if attempts >= max_attempts or lockout_detected:
                break

        hits = [r for r in results if r.get("success")]
        return json.dumps({
            "login_url": login_url,
            "authorized": authorized,
            "attempts_made": attempts,
            "max_attempts": max_attempts,
            "lockout_detected": lockout_detected,
            "successful_logins": len(hits),
            "hits": [{"username": h["username"], "status": h["status"]} for h in hits],
            "all_results": results,
            "verdict": f"CREDENTIALS FOUND: {len(hits)} valid login(s)" if hits else ("LOCKOUT DETECTED — spray aborted" if lockout_detected else "No valid credentials found"),
        }, indent=2)[:_tool_output_max_chars()]

    def _resolve_request_cookies(
        self,
        headers: Dict[str, str],
        cookies: Optional[Any],
        use_auth_session: bool,
    ) -> Dict[str, str]:
        hdrs = dict(headers)
        cookie_header = hdrs.get("Cookie") or hdrs.get("cookie")
        if use_auth_session and not cookie_header:
            sess = getattr(self, "_auth_session", None) or {}
            jar = sess.get("cookies") or []
            parts = []
            for c in jar:
                if isinstance(c, dict) and c.get("name"):
                    parts.append(f"{c['name']}={c.get('value', '')}")
            if isinstance(cookies, list):
                for c in cookies:
                    if isinstance(c, dict) and c.get("name"):
                        parts.append(f"{c['name']}={c.get('value', '')}")
            elif isinstance(cookies, dict):
                for k, v in cookies.items():
                    parts.append(f"{k}={v}")
            if parts:
                hdrs["Cookie"] = "; ".join(parts[:40])
        return hdrs

    async def _http_exchange(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        cookies: Optional[Any] = None,
        use_auth_session: bool = True,
        timeout: int = 25,
        follow_redirects: bool = True,
    ) -> Dict[str, Any]:
        import httpx

        method = (method or "GET").upper().strip()
        hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
        hdrs = self._resolve_request_cookies(hdrs, cookies, use_auth_session)
        async with httpx.AsyncClient(
            follow_redirects=follow_redirects, verify=False, timeout=timeout
        ) as client:
            resp = await client.request(method, url, headers=hdrs, content=body)
        body_text = resp.text or ""
        return {
            "request": {
                "method": method,
                "url": url,
                "headers": {
                    k: ("***" if k.lower() in ("authorization", "cookie") else v)
                    for k, v in hdrs.items()
                },
                "body_len": len(body or ""),
            },
            "response": {
                "status": resp.status_code,
                "headers": dict(list(resp.headers.items())[:40]),
                "body_preview": body_text[:4000],
                "length": len(resp.content or b""),
            },
            "_body_text": body_text,
        }

    async def replay_http_request(
        self,
        method: str = "GET",
        url: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        cookies: Optional[Any] = None,
        use_auth_session: bool = True,
        timeout: int = 25,
    ) -> str:
        """Replay a captured HTTP request (tester-style request tampering).

        Prefer samples from the capability map (api_samples). Optionally attaches
        cookies from the session auth handoff after deep_crawl login.
        """
        if not url or not str(url).strip():
            return "Error: url is required (e.g. from capability_map.api_samples)."

        try:
            exchange = await self._http_exchange(
                method=method,
                url=url,
                headers=headers,
                body=body,
                cookies=cookies,
                use_auth_session=use_auth_session,
                timeout=timeout,
            )
            out = {
                "request": exchange["request"],
                "response": exchange["response"],
                "note": (
                    "Use this to tamper method/headers/body on captured APIs. "
                    "Prefer compare_requests when proving authz/tenant/Host logic bugs. "
                    "Pair with execute_interactsh for blind OOB sinks."
                ),
            }
            return json.dumps(out, indent=2)[:_tool_output_max_chars()]
        except Exception as exc:
            return f"Error replaying request: {exc}"

    async def compare_requests(
        self,
        baseline: Dict[str, Any],
        mutant: Dict[str, Any],
        interest_fields: Optional[List[str]] = None,
        use_auth_session: bool = True,
        timeout: int = 25,
        hypothesis_id: Optional[str] = None,
    ) -> str:
        """Differential HTTP proof — baseline vs one mutation (tester core loop).

        Use for IDOR, host-header tenant bypass, authz, and workflow tampers.
        A 200 alone is never enough; this tool diffs status/length/body/fields.

        Args:
            baseline: {method, url, headers?, body?, cookies?}
            mutant: same shape; typically one trust signal changed (Host, object id, header)
            interest_fields: optional JSON/body keys to extract and compare (owner_id, email, tenant…)
            use_auth_session: attach deep_crawl auth cookies when Cookie absent
            timeout: per-request timeout
            hypothesis_id: optional engagement hypothesis to annotate with result
        """
        import json as _json
        import re as _re

        def _norm(spec: Optional[Dict[str, Any]], label: str) -> Dict[str, Any]:
            if not isinstance(spec, dict):
                raise ValueError(f"{label} must be an object with at least url")
            url = str(spec.get("url") or "").strip()
            if not url:
                raise ValueError(f"{label}.url is required")
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            return {
                "method": spec.get("method") or "GET",
                "url": url,
                "headers": spec.get("headers") or {},
                "body": spec.get("body"),
                "cookies": spec.get("cookies"),
            }

        try:
            b = _norm(baseline, "baseline")
            m = _norm(mutant, "mutant")
        except ValueError as exc:
            return json.dumps({"error": str(exc)}, indent=2)

        try:
            base_ex = await self._http_exchange(
                method=b["method"],
                url=b["url"],
                headers=b["headers"],
                body=b["body"],
                cookies=b["cookies"],
                use_auth_session=use_auth_session,
                timeout=timeout,
                follow_redirects=False,
            )
            mut_ex = await self._http_exchange(
                method=m["method"],
                url=m["url"],
                headers=m["headers"],
                body=m["body"],
                cookies=m["cookies"],
                use_auth_session=use_auth_session,
                timeout=timeout,
                follow_redirects=False,
            )
        except Exception as exc:
            return json.dumps({"error": f"compare_requests failed: {exc}"}, indent=2)

        def _extract_fields(text: str) -> Dict[str, Any]:
            found: Dict[str, Any] = {}
            if not interest_fields:
                return found
            # Try JSON first
            try:
                data = _json.loads(text)
            except Exception:
                data = None
            for field_name in interest_fields:
                if data is not None:
                    # shallow + one-level nested
                    if isinstance(data, dict) and field_name in data:
                        found[field_name] = data.get(field_name)
                        continue
                    if isinstance(data, dict):
                        for v in data.values():
                            if isinstance(v, dict) and field_name in v:
                                found[field_name] = v.get(field_name)
                                break
                if field_name not in found:
                    mobj = _re.search(
                        rf'"{_re.escape(field_name)}"\s*:\s*"?([^",\s\}}]+)"?',
                        text or "",
                    )
                    if mobj:
                        found[field_name] = mobj.group(1)
            return found

        b_body = base_ex.pop("_body_text", "")
        m_body = mut_ex.pop("_body_text", "")
        b_fields = _extract_fields(b_body)
        m_fields = _extract_fields(m_body)

        status_delta = mut_ex["response"]["status"] - base_ex["response"]["status"]
        length_delta = mut_ex["response"]["length"] - base_ex["response"]["length"]
        body_changed = b_body != m_body
        field_deltas = {
            k: {"baseline": b_fields.get(k), "mutant": m_fields.get(k)}
            for k in set(b_fields) | set(m_fields)
            if b_fields.get(k) != m_fields.get(k)
        }

        # Heuristic signals (not auto-confirm — agent must interpret)
        signals: List[str] = []
        if status_delta != 0:
            signals.append(f"status_delta={status_delta}")
        if abs(length_delta) >= 32:
            signals.append(f"length_delta={length_delta}")
        if body_changed:
            signals.append("body_changed")
        if field_deltas:
            signals.append(f"interest_field_deltas={list(field_deltas)}")

        interesting = bool(signals) and mut_ex["response"]["status"] < 400
        verdict = "NEEDS_INTERPRETATION"
        if interesting and field_deltas:
            verdict = "LIKELY_IMPACT"
        elif not body_changed and status_delta == 0 and abs(length_delta) < 16:
            verdict = "NO_MATERIAL_DIFF"
        elif mut_ex["response"]["status"] in (401, 403, 404) and base_ex["response"]["status"] < 400:
            verdict = "MUTANT_DENIED"
        elif base_ex["response"]["status"] in (401, 403) and mut_ex["response"]["status"] < 400:
            verdict = "MUTANT_BYPASS_CANDIDATE"

        out = {
            "verdict": verdict,
            "signals": signals,
            "status": {
                "baseline": base_ex["response"]["status"],
                "mutant": mut_ex["response"]["status"],
                "delta": status_delta,
            },
            "length": {
                "baseline": base_ex["response"]["length"],
                "mutant": mut_ex["response"]["length"],
                "delta": length_delta,
            },
            "interest_fields": {"baseline": b_fields, "mutant": m_fields, "deltas": field_deltas},
            "baseline": base_ex,
            "mutant": mut_ex,
            "guidance": (
                "LIKELY_IMPACT / MUTANT_BYPASS_CANDIDATE → update_hypothesis(status='proven') "
                "with evidence, validate_finding, create_finding, then queue_finding_followups. "
                "NO_MATERIAL_DIFF / MUTANT_DENIED → update_hypothesis(status='killed') unless "
                "another mutation remains. Never report on status-200 alone."
            ),
        }

        # Annotate engagement brain if present on the tool manager
        if hypothesis_id:
            try:
                from app.services.agent.engagement_brain import (
                    engagement_brain_from_dict,
                    update_hypothesis,
                )
                brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                status = (
                    "proven"
                    if verdict in ("LIKELY_IMPACT", "MUTANT_BYPASS_CANDIDATE")
                    else (
                        "killed"
                        if verdict in ("NO_MATERIAL_DIFF", "MUTANT_DENIED")
                        else "in_progress"
                    )
                )
                evidence = (
                    f"compare_requests verdict={verdict}; signals={signals}; "
                    f"status {base_ex['response']['status']}→{mut_ex['response']['status']}; "
                    f"len {base_ex['response']['length']}→{mut_ex['response']['length']}"
                )
                update_hypothesis(brain, hypothesis_id, status=status, evidence=evidence)
                self._engagement_brain = brain.to_dict()
                out["engagement_brain"] = self._engagement_brain
                out["hypothesis_update"] = {"id": hypothesis_id, "status": status}
            except Exception as exc:
                out["hypothesis_update_error"] = str(exc)

        return json.dumps(out, indent=2)[:_tool_output_max_chars()]

    async def sync_engagement_brain(
        self,
        capability_map: Optional[Dict[str, Any]] = None,
        reset: bool = False,
    ) -> str:
        """Seed/refresh the engagement brain from the session capability map.

        Call after execute_deep_crawl (or when the map updates) so open hypotheses
        drive fireteam_dispatch(specialists='auto').
        """
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            format_engagement_brain_for_prompt,
            seed_hypotheses_from_capability_map,
            specialists_from_open_hypotheses,
        )

        cmap = capability_map or getattr(self, "_capability_map", None) or {}
        brain = (
            engagement_brain_from_dict(None)
            if reset
            else engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        )
        brain = seed_hypotheses_from_capability_map(brain, cmap if isinstance(cmap, dict) else {})
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "phase": brain.phase,
                "target": brain.target,
                "open_hypotheses": [
                    h.to_dict()
                    for h in brain.hypotheses
                    if h.status in ("open", "in_progress")
                ],
                "credentials_redacted": [c.redacted() for c in brain.credentials],
                "next_steps": brain.next_steps,
                "suggested_specialists": specialists_from_open_hypotheses(brain),
                "prompt_view": format_engagement_brain_for_prompt(self._engagement_brain),
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def update_hypothesis(
        self,
        hypothesis_id: str,
        status: str,
        evidence: str = "",
    ) -> str:
        """Mark a hypothesis open|in_progress|proven|killed with evidence."""
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            update_hypothesis as _update,
        )

        status = (status or "").strip().lower()
        if status not in ("open", "in_progress", "proven", "killed"):
            return json.dumps(
                {"error": "status must be one of open|in_progress|proven|killed"},
                indent=2,
            )
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        hyp = _update(brain, hypothesis_id, status=status, evidence=evidence)
        if not hyp:
            return json.dumps(
                {"error": f"hypothesis not found: {hypothesis_id}", "known": [h.id for h in brain.hypotheses]},
                indent=2,
            )
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {"updated": hyp.to_dict(), "engagement_brain": self._engagement_brain},
            indent=2,
        )[:_tool_output_max_chars()]

    async def queue_finding_followups(
        self,
        vuln_type: str = "",
        title: str = "",
        target: str = "",
        evidence: str = "",
        cve_id: str = "",
        cwe_ids: Optional[List[str]] = None,
    ) -> str:
        """Enqueue chain cards after a confirmed finding (creds→auth CVE, Host→tenant, …).

        Optional cve_id / cwe_ids trigger CVE→CWE loop-back: boost open methodology
        cards that share those weakness IDs.
        """
        from app.services.agent.engagement_brain import (
            classify_finding_type,
            engagement_brain_from_dict,
            queue_followups_for_finding,
            specialists_from_open_hypotheses,
            boost_methodologies_for_cwes,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        vtype = vuln_type or classify_finding_type(title=title, description=evidence)
        created = queue_followups_for_finding(
            brain,
            vuln_type=vtype,
            title=title,
            target=target,
            evidence=evidence,
        )

        cwe_intel = []
        boosted = []
        resolved_cwes = list(cwe_ids or [])
        if cve_id and not resolved_cwes:
            try:
                from app.services.vuln_intel_enrichment import enrich_cve_catalog
                catalog = enrich_cve_catalog(cve_id, use_cache=True, include_exploit_sources=False)
                resolved_cwes = list(catalog.get("cwes") or [])
                cwe_intel = list(catalog.get("cwe_intel") or [])
            except Exception as exc:
                logger.debug("CVE→CWE enrich failed for %s: %s", cve_id, exc)
        if resolved_cwes:
            boosted = boost_methodologies_for_cwes(
                brain,
                resolved_cwes,
                cve_id=cve_id or "",
                evidence=evidence or title,
            )

        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "classified_as": vtype,
                "queued": [h.to_dict() for h in created],
                "cve_id": cve_id or None,
                "cwes": resolved_cwes,
                "cwe_intel": cwe_intel[:5],
                "boosted_methodologies": [h.to_dict() for h in boosted],
                "suggested_specialists": specialists_from_open_hypotheses(brain),
                "next_steps": brain.next_steps,
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def log_engagement_approach(
        self,
        technique: str,
        target: str = "",
        result: str = "failed",
        detail: str = "",
    ) -> str:
        """Record an approach tried so the agent does not blindly repeat failures."""
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            log_approach,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        rec = log_approach(
            brain,
            technique=technique,
            target=target,
            result=result,
            detail=detail,
        )
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {"logged": rec.to_dict(), "engagement_brain": self._engagement_brain},
            indent=2,
        )[:_tool_output_max_chars()]

    async def add_engagement_credential(
        self,
        username: str,
        secret: str,
        source: str = "manual",
        valid_on: Optional[List[str]] = None,
        secret_type: str = "password",
        notes: str = "",
    ) -> str:
        """Store a working credential for authenticated follow-up hypotheses."""
        from app.services.agent.engagement_brain import (
            add_credential,
            engagement_brain_from_dict,
        )

        if not username or not secret:
            return json.dumps({"error": "username and secret are required"}, indent=2)
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        rec = add_credential(
            brain,
            username=username,
            secret=secret,
            source=source,
            valid_on=valid_on,
            secret_type=secret_type,
            notes=notes,
        )
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "stored": rec.redacted(),
                "hint": (
                    "Replay as client_id/client_secret HTTP headers against the in-scope API "
                    "(one read-only call). queue_finding_followups(vuln_type='js_secrets'). "
                    "sanitize_evidence before create_finding."
                    if secret_type == "oauth_client"
                    else (
                    "Prove EmailJS with ONE browser-context POST to "
                    "https://api.emailjs.com/api/v1.0/email/send using an engagement-controlled "
                    "canary inbox (never employees). queue_finding_followups(vuln_type='emailjs')."
                    if secret_type == "emailjs"
                    else
                    "Use these creds for authenticated nuclei (-var username=… -var password=…) "
                    "and queue_finding_followups(vuln_type='default_login')."
                    )
                ),
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def get_engagement_brain(self) -> str:
        """Return the current engagement brain (hypotheses, creds redacted, next steps)."""
        from app.services.agent.engagement_brain import (
            format_engagement_brain_for_prompt,
            specialists_from_open_hypotheses,
            engagement_brain_from_dict,
            methodology_progress,
            format_methodology_progress_for_prompt,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cmap = getattr(self, "_capability_map", None) or {}
        progress = methodology_progress(brain, cmap=cmap if isinstance(cmap, dict) else {})
        return json.dumps(
            {
                "prompt_view": format_engagement_brain_for_prompt(brain.to_dict()),
                "methodology_progress": progress,
                "methodology_checklist": format_methodology_progress_for_prompt(progress),
                "suggested_specialists": specialists_from_open_hypotheses(brain),
                "engagement_brain": brain.to_dict(),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def get_methodology_progress(self) -> str:
        """Return the observation→methodology assessment checklist and readiness gates."""
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            methodology_progress,
            format_methodology_progress_for_prompt,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cmap = getattr(self, "_capability_map", None) or {}
        progress = methodology_progress(brain, cmap=cmap if isinstance(cmap, dict) else {})
        return json.dumps(
            {
                "progress": progress,
                "prompt_view": format_methodology_progress_for_prompt(progress),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def ingest_urls_into_map(
        self,
        urls: Optional[Any] = None,
        source: str = "passive",
        target: str = "",
        resync_brain: bool = True,
    ) -> str:
        """
        Merge katana/gau/wayback/httpx URL lists into the capability map so methodologies
        update from passive crawl observations (not only Playwright deep_crawl).

        urls: newline/comma-separated string, JSON array, or list of URL strings.
        """
        from app.services.agent.capability_map import ingest_passive_urls
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            seed_hypotheses_from_capability_map,
            methodology_progress,
        )

        raw = urls
        parsed: List[str] = []
        if isinstance(raw, list):
            parsed = [str(u) for u in raw]
        elif isinstance(raw, str):
            text = raw.strip()
            if text.startswith("["):
                try:
                    loaded = json.loads(text)
                    if isinstance(loaded, list):
                        parsed = [str(u) for u in loaded]
                except Exception:
                    parsed = []
            if not parsed:
                parsed = [p.strip() for p in _re.split(r"[\n,]+", text) if p.strip()]
        if not parsed:
            return json.dumps({"error": "urls required (list or newline/comma-separated)"}, indent=2)

        existing = getattr(self, "_capability_map", None)
        merged = ingest_passive_urls(
            existing if isinstance(existing, dict) else None,
            parsed,
            target=target or (existing or {}).get("target", "") if isinstance(existing, dict) else target,
            source=source,
        )
        self._capability_map = merged
        brain_out = None
        if resync_brain:
            brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            brain = seed_hypotheses_from_capability_map(brain, merged)
            self._engagement_brain = brain.to_dict()
            brain_out = self._engagement_brain
        progress = methodology_progress(
            getattr(self, "_engagement_brain", None), cmap=merged
        )
        return json.dumps(
            {
                "ingested": len(parsed),
                "source": source,
                "pages": len(merged.get("pages_visited") or []),
                "apis": len(merged.get("api_endpoints") or []),
                "methodologies": len(merged.get("methodologies") or []),
                "methodology_progress": progress,
                "capability_map": merged,
                "engagement_brain": brain_out,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def fireteam_dispatch(
        self,
        mission: str = "",
        targets: Optional[List[str]] = None,
        specialists: Optional[Any] = None,
        max_parallel: int = 4,
        capability_map: Optional[Dict[str, Any]] = None,
        mode: str = "attack",
    ) -> str:
        """Scatter-gather: spawn N parallel specialist sub-agents on the same mission.

        Args:
            mission: Plain-English task description. Optional when capability_map
                is provided (auto-built from the map).
            targets: Hostnames / URLs the specialists should focus on.
            specialists: Names from fireteam_service, or ``"auto"`` / ``["auto"]``
                to select from the capability map (tester branching). Defaults to
                map-based attack specialists when a map is present, else recon triad.
            max_parallel: How many specialists to run concurrently.
            capability_map: Structured map from execute_deep_crawl (optional if
                the orchestrator injects session state).
            mode: ``attack`` (default, map-driven hunters) or ``recon`` (legacy triad).
        """
        from app.services.agent.capability_map import (
            build_capability_map_from_dict,
            mission_from_capability_map,
            select_specialists_for_map,
        )
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            format_engagement_brain_for_prompt,
            mission_from_hypotheses,
            seed_hypotheses_from_capability_map,
            specialists_from_open_hypotheses,
        )
        from app.services.agent.fireteam_service import run_fireteam

        cmap_raw = capability_map or getattr(self, "_capability_map", None)
        cmap = build_capability_map_from_dict(cmap_raw) if cmap_raw else None

        # Keep engagement brain in sync with the map before specialist selection.
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if cmap:
            brain = seed_hypotheses_from_capability_map(brain, cmap.to_dict())
            self._engagement_brain = brain.to_dict()

        # Resolve specialists: "auto" → open hypotheses, else capability-map selection
        auto = False
        if specialists is None:
            auto = bool(cmap) or mode == "attack" or bool(brain.hypotheses)
            chosen = None
        elif specialists in ("auto", ["auto"], ("auto",)):
            auto = True
            chosen = None
        elif isinstance(specialists, str):
            chosen = [s.strip() for s in specialists.split(",") if s.strip()]
        else:
            chosen = list(specialists)
            if chosen == ["auto"]:
                auto = True
                chosen = None

        selection_source = "explicit"
        if auto:
            open_hyps = [h for h in brain.hypotheses if h.status in ("open", "in_progress")]
            if open_hyps and mode != "recon":
                chosen = specialists_from_open_hypotheses(brain)
                selection_source = "hypotheses"
            else:
                chosen = select_specialists_for_map(
                    cmap,
                    include_recon=(mode == "recon"),
                )
                selection_source = "capability_map"
        if not chosen:
            chosen = (
                ["web_recon", "vuln_triage", "secrets_hunter"]
                if mode == "recon"
                else select_specialists_for_map(cmap)
            )
            selection_source = selection_source if auto else "default"

        if not mission or not str(mission).strip():
            if brain.hypotheses:
                mission = mission_from_hypotheses(brain)
            elif cmap and cmap.target:
                mission = mission_from_capability_map(cmap)
            else:
                return "Error: mission is required (or provide a capability_map)."

        # Ground the mission in concrete map evidence + open hypotheses.
        if cmap and cmap.ready_for_attack:
            api_preview = [
                f"{e.get('method')} {e.get('path')}" for e in cmap.api_endpoints[:15]
            ]
            mission = (
                f"{mission}\n\nCAPABILITY MAP (use these concrete surfaces):\n"
                f"- capabilities: {', '.join(cmap.capabilities)}\n"
                f"- pages: {cmap.pages_visited[:12]}\n"
                f"- apis: {api_preview}\n"
                f"- forms: {cmap.forms[:8]}\n"
                f"- hunt_queue: {cmap.ranked_hunt_queue[:8]}\n"
            )
        if brain.hypotheses:
            mission = (
                f"{mission}\n\nENGAGEMENT BRAIN:\n"
                f"{format_engagement_brain_for_prompt(brain.to_dict())}\n"
            )

        target_list = list(targets or [])
        if not target_list and cmap and cmap.target:
            target_list = [cmap.target]
            target_list.extend(cmap.pages_visited[:5])

        # Lazy-build a cheap LLM instance. Reuse the orchestrator factory if available.
        try:
            from app.services.agent.orchestrator import AgentOrchestrator
            llm = AgentOrchestrator()._build_llm() if hasattr(AgentOrchestrator, "_build_llm") else None
        except Exception:
            llm = None

        if llm is None:
            try:
                from langchain_anthropic import ChatAnthropic
                llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
            except Exception:
                from langchain_openai import ChatOpenAI
                llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

        from app.services.agent.aegis_pantheon import epithet_for, pantheon_line
        from app.services.agent.fireteam_service import get_specialist
        from app.services.agent.operation_directive import directives_from_hypotheses

        profiles = {n: get_specialist(n) for n in chosen if get_specialist(n)}
        default_target = target_list[0] if target_list else (cmap.target if cmap else "")
        directives = directives_from_hypotheses(
            brain=brain,
            profiles_by_name=profiles,
            specialists=chosen,
            default_target=default_target or "",
        )

        result = await run_fireteam(
            mission=mission,
            targets=target_list,
            specialists=chosen,
            llm=llm,
            tools_manager=self,
            max_parallel=max_parallel,
            directives=directives,
        )
        out = {
            "commander": pantheon_line("orchestrator"),
            "mission": result.mission[:2000],
            "specialists_requested": chosen,
            "specialists_epithets": {
                n: epithet_for(n) for n in chosen
            },
            "operation_directives": {
                n: d.to_dict() for n, d in directives.items()
            },
            "specialists_run": result.specialists_run,
            "selection_mode": "auto" if auto else "explicit",
            "selection_source": selection_source,
            "capability_map_ready": bool(cmap and cmap.ready_for_attack),
            "open_hypotheses": [
                {"id": h.id, "title": h.title, "specialist": h.specialist, "status": h.status}
                for h in brain.hypotheses
                if h.status in ("open", "in_progress")
            ][:12],
            "engagement_brain": getattr(self, "_engagement_brain", None),
            "total_tool_calls": result.total_tool_calls,
            "duration_seconds": result.duration_seconds,
            "merged_summary": result.merged_summary,
            "reports": [
                {
                    "specialist": r.specialist,
                    "epithet": epithet_for(r.specialist),
                    "role": r.role,
                    "summary": r.summary,
                    "key_findings": r.key_findings,
                    "tool_calls": [
                        {"tool": t.tool, "success": t.success, "summary": t.summary[:500]}
                        for t in r.tool_calls
                    ],
                    "duration_seconds": r.duration_seconds,
                    "error": r.error,
                }
                for r in result.reports
            ],
        }
        return json.dumps(out, indent=2)[:_tool_output_max_chars()]

    # ------------------------------------------------------------------
    # Email breach discovery (XposedOrNot)
    # ------------------------------------------------------------------

    async def check_email_breach(
        self,
        domain: Optional[str] = None,
        emails: Optional[List[str]] = None,
    ) -> str:
        """
        Check whether an organisation's email addresses have appeared in known
        data-breach dumps using the XposedOrNot public API (keyless, free).

        Provide a domain (e.g. "target.com") to get aggregate domain-level
        exposure, and/or a list of specific email addresses for per-address
        results.  Both can be supplied together.

        Returns breach names, data types exposed (passwords, credit cards…),
        and total breached-account counts.  A clean result means no known
        breach exposure was found — not a guarantee of safety.
        """
        from app.services.email_breach_service import get_email_breach_service

        service = get_email_breach_service()
        output: dict = {}

        if domain:
            dom_result = await service.check_domain_breach_exposure(domain)
            output["domain"] = dom_result.to_dict()

        if emails:
            email_results = await service.batch_check_emails(emails[:20])
            output["emails"] = {e: r.to_dict() for e, r in email_results.items()}

        if not output:
            return "Error: provide domain= and/or emails= to check."

        return json.dumps(output, indent=2)[:_tool_output_max_chars()]

    # ------------------------------------------------------------------
    # DNS Threat / DNSBL check (Spamhaus + multi-DNSBL, keyless)
    # ------------------------------------------------------------------

    async def check_dns_threat(
        self,
        targets: Optional[List[str]] = None,
        target: Optional[str] = None,
    ) -> str:
        """
        Check whether discovered IPs or domains are listed on Spamhaus ZEN/DBL,
        Barracuda BRBL, SORBS, SpamCop, SURBL, URIBL, or other major DNSBLs.

        All lookups are pure DNS queries — keyless, free, and fast.
        Returns hit_count, severity (clean/low/medium/high), and which
        blocklists matched.  A "high" severity means Spamhaus or SURBL
        confirmed the target as malicious.

        Accepts a single target= string or a targets= list.
        """
        from app.services.dns_threat_service import get_dns_threat_service

        service = get_dns_threat_service()
        all_targets = list(targets or [])
        if target:
            all_targets.insert(0, target)

        if not all_targets:
            return "Error: provide target= or targets= to check."

        results = await service.check_bulk(all_targets[:50])
        out = {t: r.to_dict() for t, r in results.items()}
        listed = [t for t, r in results.items() if r.is_listed]
        summary = {
            "targets_checked": len(all_targets),
            "listed_count": len(listed),
            "listed_targets": listed,
            "details": out,
        }
        return json.dumps(summary, indent=2)[:_tool_output_max_chars()]

    # ------------------------------------------------------------------
    # URLhaus active lookup (abuse.ch, free key or keyless)
    # ------------------------------------------------------------------

    async def lookup_urlhaus(
        self,
        target: Optional[str] = None,
        targets: Optional[List[str]] = None,
    ) -> str:
        """
        Query abuse.ch URLhaus to check whether a URL, domain, IP, or file hash
        is associated with malware distribution.

        For URLs — checks if the exact URL serves/served malware.
        For domains/IPs — lists all malware URLs hosted on that host.
        For hashes (MD5/SHA256) — identifies the malware payload.

        Uses URLHAUS_KEY env var if set (fewer rate limits); works without it.
        Accepts a single target= or a list via targets=.
        """
        from app.services.urlhaus_lookup_service import get_urlhaus_lookup_service

        service = get_urlhaus_lookup_service()
        all_targets = list(targets or [])
        if target:
            all_targets.insert(0, target)

        if not all_targets:
            return "Error: provide target= or targets= to query."

        sem = asyncio.Semaphore(5)

        async def _lookup(t: str) -> tuple[str, dict]:
            async with sem:
                await asyncio.sleep(0.2)
                return t, await service.lookup(t)

        pairs = await asyncio.gather(*[_lookup(t) for t in all_targets[:20]])
        results = dict(pairs)
        malicious = {t: r for t, r in results.items() if r.get("is_malicious")}

        summary = {
            "targets_checked": len(all_targets),
            "malicious_count": len(malicious),
            "malicious_targets": list(malicious.keys()),
            "details": results,
        }
        return json.dumps(summary, indent=2)[:_tool_output_max_chars()]

    # ------------------------------------------------------------------
    # BGP / ASN lookup (RIPEstat, keyless)
    # ------------------------------------------------------------------

    async def lookup_bgp(
        self,
        target: Optional[str] = None,
        targets: Optional[List[str]] = None,
        asn: Optional[str] = None,
    ) -> str:
        """
        Look up BGP routing context for discovered IPs or domains using RIPEstat
        (stat.ripe.net) — the authoritative Regional Internet Registry source.

        For IPs/domains — returns the covering prefix, owning ASN, and ASN name.
        For an ASN (e.g. "AS15169") — returns all announced IP prefixes, useful
        for discovering additional IP ranges owned by the target organisation.

        Keyless and free. Replaces bgpview.io which is no longer operational.
        """
        from app.services.ripestat_service import get_ripestat_service

        service = get_ripestat_service()
        all_targets = list(targets or [])
        if target:
            all_targets.insert(0, target)

        if not all_targets and not asn:
            return "Error: provide target=, targets=, or asn= to look up."

        results: dict = {}

        if asn:
            res = await service.lookup_asn(asn)
            results[asn] = res.to_dict()

        sem = asyncio.Semaphore(10)

        async def _lookup(t: str) -> tuple[str, dict]:
            async with sem:
                # Auto-detect ASN vs IP/domain
                if t.upper().startswith("AS") or (t.isdigit() and len(t) <= 10):
                    res = await service.lookup_asn(t)
                else:
                    try:
                        import ipaddress as _ip
                        _ip.ip_address(t)
                        res = await service.lookup_ip(t)
                    except ValueError:
                        res = await service.lookup_domain(t)
                return t, res.to_dict()

        if all_targets:
            pairs = await asyncio.gather(*[_lookup(t) for t in all_targets[:50]])
            results.update(dict(pairs))

        asn_distribution: dict[str, int] = {}
        for r in results.values():
            if isinstance(r, dict) and r.get("asn"):
                asn_distribution[r["asn"]] = asn_distribution.get(r["asn"], 0) + 1

        summary = {
            "targets_resolved": len(results),
            "unique_asns": len(asn_distribution),
            "asn_distribution": asn_distribution,
            "details": results,
        }
        return json.dumps(summary, indent=2)[:_tool_output_max_chars()]
