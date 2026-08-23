"""Praetorian-style demonstrated-compromise chain for agent findings.

A chain is an ordered list of live tool invocations that prove impact — not a
scanner template hit. Persisted on ``Vulnerability.metadata_["agent_detection"]``.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Dict, Iterable, List, Optional, Sequence

MAX_STEPS = 12
MAX_STDOUT = 4000
MAX_STDERR = 1500
MAX_SUMMARY = 280
MAX_OUTCOME = 280

# Tools whose output can constitute proof. Query/memory/judge tools are skipped.
PROOF_TOOLS = frozenset({
    "execute_curl",
    "probe_registry_anonymous",
    "execute_httpx",
    "execute_browser",
    "execute_nuclei",
    "execute_nikto",
    "execute_sqlmap",
    "execute_jwt",
    "execute_hydra",
    "execute_commix",
    "execute_dalfox",
    "execute_xsstrike",
    "execute_feroxbuster",
    "execute_ffuf",
    "execute_nmap",
    "compare_requests",
    "replay_http_request",
    "test_credential_spray",
    "test_saml_sso",
    "execute_interactsh",
    "execute_interceptor",
})

_SKIP_RECORD = frozenset({
    "create_finding",
    "assess_finding_risk",
    "validate_finding",
    "save_note",
    "get_notes",
    "query_assets",
    "query_vulnerabilities",
    "query_ports",
    "query_technologies",
    "query_graph",
    "query_prior_sessions",
    "search_memory",
    "store_memory",
    "auto_select_tools",
    "sanitize_evidence",
    "sync_engagement_brain",
    "fireteam_dispatch",
    "transition_phase",
    "complete",
})

_HTTP_STATUS_RE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})")
_JSON_ERROR_RE = re.compile(r'"error"\s*:\s*"([^"]{3,80})"', re.I)
_WELCOME_RE = re.compile(r'"couchdb"\s*:\s*"Welcome".*?"version"\s*:\s*"([^"]+)"', re.I | re.S)
_BASIC_AUTH_RE = re.compile(r"(?i)(authorization:\s*basic\s+)([A-Za-z0-9+/=_\-]{8,})")
_URL_USERPASS_RE = re.compile(r"(://)([^/\s:@]{1,64}):([^/\s@]{1,128})@")
_U_FLAG_RE = re.compile(r"(?i)(-u\s+)([^:\s]+):([^\s]+)")
_DERIVED_KEY_RE = re.compile(r'(?i)("(?:derived_key|password|passwd|secret|token)"\s*:\s*")([^"]{6,})"')
_AZURE_CONN_RE = re.compile(r"(?i)(AccountKey=)([^;\s\"']+)")
_AZURE_SAS_RE = re.compile(r"(?i)(SharedAccessSignature=)([^;\s\"']+)")
_AZURE_ENVKEY_RE = re.compile(
    r'(?i)("(?:MACHINEKEY_DecryptionKey|WEBSITE_AUTH_ENCRYPTION_KEY|WEBSITE_AUTH_SIGNING_KEY|'
    r'APPINSIGHTS_INSTRUMENTATIONKEY|APPLICATIONINSIGHTS_CONNECTION_STRING|'
    r'AzureWebJobsStorage|COSMOS[^"]*KEY|DOCUMENTDB[^"]*KEY)"\s*:\s*")([^"]{8,})"'
)
_AUTHSESSION_RE = re.compile(r"(?i)(AuthSession=)[A-Za-z0-9+/=_\-]{12,}")
_COUCH_SECRET_LINE_RE = re.compile(
    r"(?i)((?:couch_httpd_auth\s+)?secret\s*[:=]\s*)([A-Fa-f0-9]{16,}|\[REDACTED\])"
)
_USERCTX_ADMIN_RE = re.compile(
    r'"userCtx"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"[^}]*"roles"\s*:\s*\[[^\]]*"_admin"',
    re.I | re.S,
)
_ALL_DBS_RE = re.compile(
    r'GET\s+/_all_dbs|/_all_dbs\b|\[(?:\s*"_global_changes"|\s*"_replicator")',
    re.I,
)
_ES_TAGLINE_RE = re.compile(r'"tagline"\s*:\s*"You Know, for Search"', re.I)
_ES_CLUSTER_RE = re.compile(
    r'"name"\s*:\s*"([^"]+)".*?"cluster_name"\s*:\s*"([^"]+)".*?"number"\s*:\s*"([^"]+)"',
    re.I | re.S,
)
_ES_ACK_RE = re.compile(r'"acknowledged"\s*:\s*true', re.I)


def redact_secrets(text: Optional[str]) -> str:
    """Keep usernames visible; strip passwords, basic-auth blobs, and hash material."""
    if not text:
        return ""
    s = str(text)
    s = _BASIC_AUTH_RE.sub(r"\1[REDACTED]", s)
    s = _URL_USERPASS_RE.sub(r"\1\2:[REDACTED]@", s)
    s = _U_FLAG_RE.sub(r"\1\2:[REDACTED]", s)
    s = _DERIVED_KEY_RE.sub(r"\1[REDACTED]\"", s)
    s = _AUTHSESSION_RE.sub(r"\1[REDACTED]", s)
    s = _COUCH_SECRET_LINE_RE.sub(r"\1[REDACTED]", s)
    s = _AZURE_CONN_RE.sub(r"\1[REDACTED]", s)
    s = _AZURE_SAS_RE.sub(r"\1[REDACTED]", s)
    s = _AZURE_ENVKEY_RE.sub(r"\1[REDACTED]\"", s)
    return s


def should_record_tool(tool_name: str) -> bool:
    name = (tool_name or "").strip()
    if not name or name in _SKIP_RECORD or name.endswith("_help"):
        return False
    if name.startswith("query_") or name.startswith("search_"):
        return False
    return True


def parse_args(raw: Any) -> List[str]:
    """Normalize tool args to a Praetorian-style argv list."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return _redact_argv([str(x) for x in raw if str(x).strip()][:80])
    if isinstance(raw, dict):
        if "args" in raw:
            return parse_args(raw.get("args"))
        parts: List[str] = []
        for key, val in raw.items():
            if val is None or val is False:
                continue
            if val is True:
                parts.append(str(key))
            else:
                parts.extend([f"--{key}", str(val)])
        return _redact_argv(parts[:80])
    text = redact_secrets(str(raw).strip())
    if not text:
        return []
    try:
        return shlex.split(text)[:80]
    except ValueError:
        return text.split()[:80]


def _redact_argv(args: List[str]) -> List[str]:
    out: List[str] = []
    pending_u = False
    for arg in args:
        if pending_u:
            if ":" in arg:
                user, _pwd = arg.split(":", 1)
                out.append(f"{user}:[REDACTED]")
            else:
                out.append(redact_secrets(arg))
            pending_u = False
            continue
        if arg in ("-u", "--user", "--auth"):
            pending_u = True
            out.append(arg)
            continue
        out.append(redact_secrets(arg))
    return out


def _clip(text: Optional[str], limit: int) -> str:
    s = (text or "").replace("\x00", "")
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n… (truncated, {len(s)} chars total)"


def summarize_output(tool: str, args: Sequence[str], stdout: str, stderr: str, exit_code: Any) -> tuple[str, str]:
    """Return (summary, outcome) one-liners for a chain step."""
    blob = stdout or stderr or ""
    status_m = _HTTP_STATUS_RE.search(blob)
    status = status_m.group(1) if status_m else None
    err_m = _JSON_ERROR_RE.search(blob)
    welcome = _WELCOME_RE.search(blob)

    arg_preview = " ".join(args)[:120]
    tool_label = (tool or "tool").replace("execute_", "")

    if welcome and status == "200":
        summary = f"Authenticated to CouchDB and received welcome message"
        outcome = f"HTTP {status} with CouchDB welcome confirming version {welcome.group(1)}"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    if any(
        k in blob
        for k in (
            "AzureWebJobsStorage",
            "FUNCTIONS_WORKER_RUNTIME",
            "WEBSITE_SITE_NAME",
            "MACHINEKEY_DecryptionKey",
        )
    ):
        summary = "Unauthenticated GET to Azure Function returned runtime environment"
        outcome = f"HTTP {status or '200'} with Function App process environment JSON (secrets redacted)"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    es_cluster = _ES_CLUSTER_RE.search(blob)
    if (es_cluster or _ES_TAGLINE_RE.search(blob)) and status in ("200", None):
        if es_cluster:
            node, cluster, ver = es_cluster.group(1), es_cluster.group(2), es_cluster.group(3)
            outcome = (
                f"HTTP {status or '200'} cluster {cluster} version {ver} node {node} "
                "without credentials"
            )
        else:
            outcome = f"HTTP {status or '200'} Elasticsearch tagline without credentials"
        summary = "Queried the Elasticsearch root endpoint to confirm unauthenticated access"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    args_l = " ".join(args).lower()
    if "_nodes" in args_l or "_cluster/health" in args_l:
        summary = "Retrieved cluster health and node details including OS information"
        outcome = f"HTTP {status or '200'} — node/OS metadata returned"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]
    if "_cat/indices" in args_l or "/_all" in args_l:
        summary = "Listed all indices to enumerate stored data"
        outcome = f"HTTP {status or '200'} — index list returned"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]
    if _ES_ACK_RE.search(blob) and ("aegis_test_index" in args_l or "test_index" in args_l):
        if "delete" in args_l or "-x delete" in args_l:
            summary = "Deleted the test index to clean up"
        else:
            summary = "Created a test index to confirm write access"
        outcome = f"HTTP {status or '200'} acknowledged=true"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    admin_sess = _USERCTX_ADMIN_RE.search(blob)
    if admin_sess:
        name = admin_sess.group(1)
        summary = f"Confirmed _admin session for {name} via /_session"
        outcome = f"HTTP {status or '200'} userCtx.name={name} roles includes _admin"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    if _COUCH_SECRET_LINE_RE.search(blob) or (
        "couch_httpd_auth" in blob.lower() and "secret" in blob.lower()
    ):
        summary = "Retrieved couch_httpd_auth secret from server configuration"
        outcome = f"HTTP {status or '200'} — couch_httpd_auth secret (redacted) readable from /_config"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    if _ALL_DBS_RE.search(blob) and (status == "200" or "[" in blob):
        summary = "Enumerated databases via /_all_dbs"
        outcome = f"HTTP {status or '200'} — database list returned"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    if status:
        outcome = f"HTTP {status}"
        if err_m:
            outcome += f" with JSON error: {err_m.group(1)}"
        elif status == "200":
            first = next((ln.strip() for ln in blob.splitlines() if ln.strip() and not ln.upper().startswith("HTTP/")), "")
            if first:
                outcome += f" — {first[:160]}"
        summary = f"Sent {tool_label} request"
        if arg_preview:
            summary += f" ({arg_preview[:80]})"
        return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]

    if blob.strip():
        first = next((ln.strip() for ln in blob.splitlines() if ln.strip()), blob.strip())
        outcome = first[:MAX_OUTCOME]
    else:
        outcome = f"exit {exit_code}" if exit_code not in (None, "") else "no output"

    summary = f"Ran {tool_label}"
    if arg_preview:
        summary += f": {arg_preview[:100]}"
    return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]


DISPLAY_TOOLS = {
    "execute_browser": "click",
    "execute_interceptor": "click",
    "replay_http_request": "request",
    "compare_requests": "request",
}

MAX_JSON_LIST = 40
MAX_PREVIEW = 10


def display_tool(tool: str) -> str:
    name = (tool or "").strip()
    if name in DISPLAY_TOOLS:
        return DISPLAY_TOOLS[name]
    alias = str(name).replace("execute_", "") or "tool"
    if alias in ("click", "request"):
        return alias
    return alias


def _coerce_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text.startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _clip_click_payload(obj: Dict[str, Any]) -> Dict[str, Any]:
    elements = obj.get("elements") if isinstance(obj.get("elements"), list) else []
    slim_elements = []
    for el in elements[:MAX_JSON_LIST]:
        if not isinstance(el, dict):
            continue
        slim_elements.append({
            "selector": str(el.get("selector") or "")[:200],
            "text": str(el.get("text") or "")[:120],
            "type": str(el.get("type") or "")[:40],
        })
    preview = obj.get("new_preview") if isinstance(obj.get("new_preview"), list) else []
    slim_preview = []
    for row in preview[:MAX_PREVIEW]:
        if isinstance(row, dict):
            slim_preview.append({
                "method": row.get("method"),
                "mime_type": row.get("mime_type"),
                "request_id": row.get("request_id"),
                "status_code": row.get("status_code"),
                "url": redact_secrets(str(row.get("url") or ""))[:300],
            })
    return {
        "dom_changed": bool(obj.get("dom_changed")),
        "elements": slim_elements,
        "new_preview": slim_preview,
        "new_requests": obj.get("new_requests"),
        "status": obj.get("status") or "ok",
    }


def _clip_request_payload(obj: Dict[str, Any]) -> Dict[str, Any]:
    resp = obj.get("response") if isinstance(obj.get("response"), dict) else None
    req = obj.get("request") if isinstance(obj.get("request"), dict) else None
    if resp:
        headers = resp.get("headers") if isinstance(resp.get("headers"), dict) else {}
        return {
            "ok": True,
            "raw_body": redact_secrets(str(resp.get("body") or resp.get("text") or obj.get("raw_body") or ""))[:MAX_STDOUT],
            "response_headers": {
                str(k)[:80]: redact_secrets(str(v))[:300] for k, v in list(headers.items())[:24]
            },
            "status": resp.get("status") or resp.get("status_code") or obj.get("status"),
            "url": redact_secrets(str((req or {}).get("url") or obj.get("url") or ""))[:400],
        }
    headers = obj.get("response_headers") if isinstance(obj.get("response_headers"), dict) else {}
    raw_body = obj.get("raw_body")
    if isinstance(raw_body, dict):
        raw_body = json.dumps(raw_body)
    return {
        "ok": obj.get("ok", True),
        "raw_body": redact_secrets(str(raw_body or obj.get("body") or ""))[:MAX_STDOUT],
        "response_headers": {
            str(k)[:80]: redact_secrets(str(v))[:300] for k, v in list(headers.items())[:24]
        },
        "status": obj.get("status") or obj.get("status_code"),
        "url": redact_secrets(str(obj.get("url") or ""))[:400],
    }


def claim_payload(tool: str, stdout: str, result: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Native Detection Claims JSON (click / request) when the tool returned structured output."""
    result = result if isinstance(result, dict) else {}
    parsed = None
    for candidate in (result.get("payload"), result, _coerce_json(stdout)):
        if isinstance(candidate, dict) and candidate:
            parsed = candidate
            break
    if not isinstance(parsed, dict):
        return None
    if set(parsed.keys()) <= {"stdout", "stderr", "exit_code", "output", "error", "success"}:
        return None
    if any(k in parsed for k in ("dom_changed", "elements", "new_preview")):
        return _clip_click_payload(parsed)
    if any(k in parsed for k in ("raw_body", "response_headers")) or isinstance(parsed.get("response"), dict):
        return _clip_request_payload(parsed)
    alias = display_tool(tool)
    if alias == "click":
        return _clip_click_payload(parsed) if "elements" in parsed else None
    if alias == "request":
        return _clip_request_payload(parsed)
    return None


def summarize_claim(alias: str, payload: Dict[str, Any]) -> tuple[str, str]:
    if alias == "click":
        preview = payload.get("new_preview") or []
        login = next(
            (p for p in preview if isinstance(p, dict) and "login" in str(p.get("url") or "").lower()),
            None,
        )
        if login:
            return (
                "Authenticated via login form, received session cookie",
                f"Login successful, session issued (HTTP {login.get('status_code') or 200})",
            )
        n_el = len(payload.get("elements") or [])
        n_req = payload.get("new_requests") or 0
        return (
            "Browser interaction changed the DOM",
            f"dom_changed={payload.get('dom_changed')} · {n_el} elements · {n_req} new requests",
        )
    url = str(payload.get("url") or "")
    status = payload.get("status") or ""
    path = ""
    if "://" in url:
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
    summary = f"Request {path or url}".strip()
    if path:
        summary = f"POST {path}"
    outcome = f"HTTP {status}" if status else "response received"
    return summary[:MAX_SUMMARY], outcome[:MAX_OUTCOME]


def normalize_step(raw: Any, index: int) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    tool = str(raw.get("tool") or raw.get("tool_name") or "tool").strip() or "tool"
    args = parse_args(raw.get("args") if "args" in raw else raw.get("tool_args"))
    result = raw.get("result") if isinstance(raw.get("result"), dict) else {}
    stdout = raw.get("stdout")
    if stdout is None:
        stdout = result.get("stdout")
    if stdout is None:
        stdout = result.get("output") or raw.get("output") or ""
    stderr = raw.get("stderr")
    if stderr is None:
        stderr = result.get("stderr")
    if stderr is None:
        stderr = result.get("error") or raw.get("error") or ""
    exit_code = raw.get("exit_code")
    if exit_code is None:
        exit_code = result.get("exit_code")
    if exit_code is None:
        exit_code = 0 if raw.get("success", True) else 1

    stdout = redact_secrets(str(stdout or ""))
    stderr = redact_secrets(str(stderr or ""))
    args = [redact_secrets(a) for a in args]
    alias = str(raw.get("display_tool") or display_tool(tool)).strip() or display_tool(tool)
    payload = None
    if isinstance(raw.get("result"), dict) and any(
        k in raw["result"] for k in ("dom_changed", "elements", "raw_body", "response_headers", "url")
    ):
        payload = claim_payload(tool, stdout, raw.get("result"))
    if payload is None:
        payload = claim_payload(tool, stdout, result if result else None)

    auto_summary, auto_outcome = summarize_output(tool, args, stdout, stderr, exit_code)
    if payload:
        claim_summary, claim_outcome = summarize_claim(alias, payload)
        auto_summary = claim_summary or auto_summary
        auto_outcome = claim_outcome or auto_outcome
    summary = redact_secrets(str(raw.get("summary") or raw.get("description") or auto_summary).strip())
    outcome = redact_secrets(str(raw.get("outcome") or raw.get("result_summary") or auto_outcome).strip())

    try:
        step_n = int(raw.get("step") or index)
    except (TypeError, ValueError):
        step_n = index

    stored_result: Dict[str, Any]
    if payload:
        stored_result = payload
    else:
        stored_result = {
            "stdout": _clip(str(stdout), MAX_STDOUT),
            "stderr": _clip(str(stderr or ""), MAX_STDERR),
            "exit_code": int(exit_code) if isinstance(exit_code, (int, float)) else exit_code,
        }

    return {
        "step": step_n,
        "summary": summary[:MAX_SUMMARY],
        "outcome": outcome[:MAX_OUTCOME],
        "tool": tool[:120],
        "display_tool": alias[:40],
        "args": args,
        "result": stored_result,
    }


def parse_chain_payload(raw: Any) -> List[Any]:
    """Accept a list, a JSON string, or a dict wrapping ``steps``/``chain``."""
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            return []
    if isinstance(raw, dict):
        raw = raw.get("steps") or raw.get("chain") or raw.get("demonstrated_chain") or []
    if not isinstance(raw, list):
        return []
    return raw


def normalize_chain(raw: Any) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    for i, item in enumerate(parse_chain_payload(raw), start=1):
        step = normalize_step(item, i)
        if step:
            steps.append(step)
        if len(steps) >= MAX_STEPS:
            break
    for i, step in enumerate(steps, start=1):
        step["step"] = i
    return steps


def invocation_to_step(inv: Dict[str, Any], index: int) -> Optional[Dict[str, Any]]:
    return normalize_step(
        {
            "tool": inv.get("tool") or inv.get("tool_name"),
            "args": inv.get("args") if "args" in inv else inv.get("tool_args"),
            "stdout": inv.get("stdout") or inv.get("output"),
            "stderr": inv.get("stderr") or inv.get("error"),
            "exit_code": inv.get("exit_code"),
            "success": inv.get("success", True),
            "summary": inv.get("summary"),
            "outcome": inv.get("outcome"),
        },
        index,
    )


def _mentions_target(inv: Dict[str, Any], target: str) -> bool:
    if not target:
        return True
    needle = target.lower().split("://")[-1].split("/")[0].split(":")[0]
    if not needle or len(needle) < 3:
        return True
    blob = json.dumps(inv, default=str).lower()
    return needle in blob


def select_proof_invocations(
    invocations: Iterable[Dict[str, Any]],
    target: Optional[str] = None,
    limit: int = 8,
) -> List[Dict[str, Any]]:
    """Pick the live proof steps for a finding (most recent matching tools)."""
    items = [i for i in invocations if isinstance(i, dict) and should_record_tool(str(i.get("tool") or i.get("tool_name") or ""))]
    if not items:
        return []

    proof = [i for i in items if (i.get("tool") or i.get("tool_name")) in PROOF_TOOLS]
    pool = proof or items
    targeted = [i for i in pool if _mentions_target(i, target or "")]
    chosen = targeted or pool
    # Keep chronological order, take the last `limit` (closest to the finding).
    return list(chosen)[-limit:]


def parse_asset_urls(raw: Any, fallback: Optional[str] = None) -> List[str]:
    """Keep full URLs (scheme + host + port + path) for Assets Affected."""
    items: List[str] = []
    if isinstance(raw, list):
        items = [str(x).strip() for x in raw if str(x).strip()]
    elif isinstance(raw, str) and raw.strip():
        text = raw.strip()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    items = [str(x).strip() for x in parsed if str(x).strip()]
            except json.JSONDecodeError:
                items = [text]
        else:
            items = [text]
    if not items and fallback:
        items = [str(fallback).strip()]
    out: List[str] = []
    for item in items[:20]:
        if not item:
            continue
        if item.startswith(("http://", "https://")):
            out.append(item)
        elif "." in item or item[0].isdigit():
            out.append(f"https://{item.lstrip('/')}")
        else:
            out.append(item)
    return out


def parse_references(raw: Any) -> List[str]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()][:20]
    text = str(raw).strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()][:20]
        except json.JSONDecodeError:
            pass
    parts = re.split(r"[\s,]+", text)
    return [p.strip() for p in parts if p.strip().startswith("http")][:20]


def build_agent_detection(
    *,
    chain: Any = None,
    invocations: Optional[Sequence[Dict[str, Any]]] = None,
    target: Optional[str] = None,
    context: Optional[str] = None,
    not_demonstrated: Optional[str] = None,
    references: Any = None,
    assets: Any = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    steps = normalize_chain(chain)
    if not steps and invocations:
        selected = select_proof_invocations(invocations, target=target)
        steps = []
        for i, inv in enumerate(selected, start=1):
            step = invocation_to_step(inv, i)
            if step:
                steps.append(step)

    payload: Dict[str, Any] = {
        "source": "agent",
        "chain": steps,
        "step_count": len(steps),
    }
    if session_id:
        payload["session_id"] = str(session_id)[:128]
    if context:
        payload["context"] = str(context)[:8000]
    if not_demonstrated:
        payload["not_demonstrated"] = str(not_demonstrated)[:4000]
    refs = parse_references(references)
    if refs:
        payload["references"] = refs
    asset_urls = parse_asset_urls(assets, fallback=target)
    if asset_urls:
        payload["assets"] = asset_urls
    return payload
    steps = normalize_chain(chain)
    if not steps and invocations:
        selected = select_proof_invocations(invocations, target=target)
        steps = []
        for i, inv in enumerate(selected, start=1):
            step = invocation_to_step(inv, i)
            if step:
                steps.append(step)

    payload: Dict[str, Any] = {
        "source": "agent",
        "chain": steps,
        "step_count": len(steps),
    }
    if session_id:
        payload["session_id"] = str(session_id)[:128]
    if context:
        payload["context"] = str(context)[:8000]
    if not_demonstrated:
        payload["not_demonstrated"] = str(not_demonstrated)[:4000]
    refs = parse_references(references)
    if refs:
        payload["references"] = refs
    return payload
