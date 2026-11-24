"""Shared helpers for the ASM agent tool mixins.

Moved verbatim from tools.py; tools.py re-exports every name here.
"""

# ruff: noqa: F401  (names re-exported for the tool mixins and tools.py)
import asyncio
import hashlib
import json
import logging
import os
import re
import re as _re
import signal
from collections import deque
from copy import deepcopy
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
# Dispatch modes that keep their own narrow lanes and skip model follow-ups.
_FOLLOWUP_EXCLUDED_MODES = frozenset({"recon", "coverage_followup", "cms_followup"})


def _tool_output_max_chars() -> int:
    return getattr(settings, "AGENT_TOOL_OUTPUT_MAX_CHARS", 20000)

logger = logging.getLogger("app.services.agent.tools")


def _lease_failure_reason(cell: Optional[Dict[str, Any]], lease_id: str) -> str:
    """Name why a coverage-cell lease check failed, for the action ledger.

    The lease state is checked first; when it is valid the cell itself did
    not fit the tool (wrong test type, method, location or source).
    """
    import time

    from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path

    if not cell:
        return "missing_cell"
    if cell.get("status") != "leased":
        return "not_leased"
    if cell.get("lease_id") != lease_id:
        return "lease_mismatch"
    if float(cell.get("lease_deadline") or 0) <= time.time():
        return "lease_expired"
    if not allowed_discovery_path(str(cell.get("path") or "/")):
        return "unsafe_path"
    return "unsupported_input"


def _emit_finding_to_sink(
    *,
    title: str,
    description: str,
    severity: str,
    target: str,
    host: str,
    evidence: Optional[str] = None,
    poc: Optional[str] = None,
    cve_id: Optional[str] = None,
    confirmed: bool = False,
) -> None:
    """Append a finding to ``AEGIS_FINDINGS_SINK`` as JSONL, if configured.

    Lets the local benchmark harness score the platform agent's output using
    the same sink contract the standalone Vanguard scanner uses. No-op unless
    the env var is set; never raises into the create_finding path.
    """
    sink = os.environ.get("AEGIS_FINDINGS_SINK")
    if not sink:
        return
    try:
        url = target if str(target).startswith(("http://", "https://")) else None
        tags = ["confirmed"] if confirmed else []
        record = {
            "type": "vulnerability",
            "source": "aegis-agent",
            "target": host or target,
            "host": host or target,
            "url": url,
            "title": title,
            "description": description,
            "severity": (severity or "info"),
            "confidence": "confirmed" if confirmed else "high",
            "cve_id": (cve_id or "").strip() or None,
            "tags": tags,
            "raw_data": {"poc": {
                "confirmed": confirmed,
                "endpoint": url or target,
                "response_snippet": (poc or evidence or "")[:4000],
            }},
        }
        os.makedirs(os.path.dirname(os.path.abspath(sink)), exist_ok=True)
        with open(sink, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception:
        logger.debug("finding sink append failed", exc_info=True)


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
_FILE_SUFFIXES = {
    "css", "gif", "html", "ico", "jpeg", "jpg", "js", "json", "map",
    "pdf", "png", "svg", "txt", "webp", "woff", "woff2", "xml",
    "yaml", "yml",
}


def is_probable_file_target(target: str) -> bool:
    """Reject a source filename accidentally promoted to an assessment host."""
    from urllib.parse import urlsplit

    host = urlsplit(target if "://" in target else f"https://{target}").hostname or ""
    return host.rsplit(".", 1)[-1].lower() in _FILE_SUFFIXES


def recover_assessment_target(
    existing_target: str, snapshot_objective: str, snapshot_target: str = "",
) -> str:
    """Keep a conversation on its original host when a follow-up is submitted."""
    for candidate in (existing_target, snapshot_target):
        candidate = (candidate or "").strip()
        if candidate and not is_probable_file_target(candidate):
            return candidate
    return extract_seed_target(snapshot_objective)


def same_assessment_target(left: str, right: str) -> bool:
    """Compare saved target seeds without URL scheme or trailing-slash noise."""
    from urllib.parse import urlsplit

    def host_port(value: str) -> tuple[str, int | None]:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return (parsed.hostname or "").lower(), port
        except ValueError:
            return "", None

    return bool(left and right and host_port(left)[0] and host_port(left) == host_port(right))


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
        if host in skip or host.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
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
        # Passive plugin detection finds HTML-referenced plugins (e.g. Yoast via
        # the generator comment) in seconds instead of brute-forcing thousands of
        # known locations (which took ~5 min and ate the whole turn budget). Drop
        # the theme brute (vt) for speed; keep vulnerable-plugin + user enum. The
        # WPSCAN_API_TOKEN is picked up from the environment automatically and is
        # what enables the vp (known-CVE) mapping.
        return (
            f"--url {target} --enumerate vp,u --plugins-detection passive "
            "--random-user-agent --disable-tls-checks"
        )
    if name in ("subfinder", "subfaster", "dnsx", "tldfinder"):
        host = host[4:] if host.lower().startswith("www.") else host
        return f"-d {host}"
    if name in ("naabu", "nmap", "masscan"):
        return f"-host {host}" if name == "naabu" else host
    if name in ("wafw00f", "whatweb", "wappalyzer", "testssl", "curl"):
        if name == "curl":
            return f"-s -I {target}"
        if name == "whatweb":
            return f"{target} -a 1"
        return target
    if name in ("deep_crawl", "interceptor"):
        # Pentester defaults as JSON so workers get depth/interact/max_pages
        return (
            '{"url":"%s","depth":3,"max_pages":25,"interact":true,"max_clicks":14}'
            % target
        )
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

    # Browser actions are JSON, not CLI flags. Specialists sometimes supply a
    # URL, a JSON string, or Playwright-style action aliases; normalize these
    # before the confirmation gate so the analyst sees the actual action.
    if tool_name == "execute_browser":
        browser_spec: Any = args_val if isinstance(args_val, (dict, list)) else raw
        if isinstance(args_val, str):
            value = args_val.strip()
            browser_spec = None
            if value.startswith(("{", "[")):
                try:
                    browser_spec = json.loads(value)
                except json.JSONDecodeError:
                    pass
            elif value.startswith(("--url ", "-u ")):
                import shlex

                try:
                    tokens = shlex.split(value)
                except ValueError:
                    tokens = []
                if len(tokens) >= 2 and tokens[0] in ("--url", "-u"):
                    actions = [{"action": "navigate", "url": tokens[1]}]
                    remainder = tokens[2:]
                    if len(remainder) == 2 and remainder[0] in ("--wait", "--wait-ms"):
                        try:
                            actions.append({"action": "wait", "ms": int(remainder[1])})
                            remainder = []
                        except ValueError:
                            pass
                    if not remainder:
                        browser_spec = {"actions": [*actions, {"action": "get_source"}]}
            elif value.startswith(("https://", "http://")):
                browser_spec = {"url": value}
        if isinstance(browser_spec, list) and all(isinstance(item, dict) for item in browser_spec):
            browser_spec = {"actions": browser_spec}
        if isinstance(browser_spec, dict):
            browser_spec = dict(browser_spec)
            actions = browser_spec.get("actions")
            if not isinstance(actions, list):
                browser_url = browser_spec.get("url") or browser_spec.get("target")
                if not browser_url:
                    browser_url = fallback_target
                if isinstance(browser_url, str) and browser_url.strip():
                    actions = [{"action": "navigate", "url": browser_url}]
                    wait_ms = browser_spec.pop("wait_ms", None)
                    if isinstance(wait_ms, (int, float)) and wait_ms > 0:
                        actions.append({"action": "wait", "ms": min(int(wait_ms), 10000)})
                    actions.append({"action": "get_source"})
                    browser_spec.pop("url", None)
                    browser_spec.pop("target", None)
                    browser_spec["actions"] = actions
            if isinstance(actions, list):
                aliases = {"goto": "navigate", "evaluate": "execute_js"}
                browser_url = browser_spec.get("url") or browser_spec.get("target") or fallback_target
                normalized_actions = []
                for item in actions:
                    if isinstance(item, str):
                        item = {"action": item}
                    if not isinstance(item, dict):
                        normalized_actions.append(item)
                        continue
                    action = dict(item)
                    action_name = str(action.pop("type", action.get("action") or "")).lower()
                    action["action"] = aliases.get(action_name, action_name)
                    if action["action"] in {"navigate", "check_response", "check_xss"} and not action.get("url") and browser_url:
                        action["url"] = browser_url
                    if action["action"] == "execute_js" and not action.get("script"):
                        action["script"] = action.pop("expression", "")
                    normalized_actions.append(action)
                browser_spec["actions"] = normalized_actions
                return {"args": json.dumps(browser_spec)}

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


async def _run_vulnx_binary(command: list[str], *, env: dict[str, str]) -> str | None:
    """Use a cancellable process group for the optional local intelligence CLI."""
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=env, start_new_session=(os.name == "posix"),
    )

    async def terminate() -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            elif process.returncode is None:
                process.kill()
        except ProcessLookupError:
            pass
        if process.returncode is None:
            await asyncio.wait_for(process.wait(), timeout=5)

    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=30)
        return stdout.decode("utf-8", errors="replace") if process.returncode == 0 else None
    except asyncio.TimeoutError:
        await terminate()
        return None
    except asyncio.CancelledError:
        await asyncio.shield(terminate())
        raise


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


from app.services.agent.session_runtime import SessionValue


from app.services.agent.assessment_capabilities import AssessmentCapabilities, CAPABILITY_TOOLS
from app.services.agent.scoped_assessment_tools import ScopedAssessmentTools


