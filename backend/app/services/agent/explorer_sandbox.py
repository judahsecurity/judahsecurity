"""Explorer sandbox: a real shell and Python for deep assessments.

Fixed-payload probes confirm the bugs Prowl already suspects; finding the rest
takes improvising (custom scripts, adapted payloads, multi-step flows). This
module gives the model that room without giving it the platform:

- Commands run in a separate ``prowl-sandbox`` container that holds no
  platform credentials. Each assessment gets its own workspace and uid.
- The sandbox's only network path is the ``prowl-sandbox-egress`` proxy, which
  admits only this assessment's scoped hosts, pins each connection to a
  validated public address, enforces a request budget, and records every
  exchange. Scope is enforced on the wire, not by parsing shell text.
- Recorded exchanges land in the evidence store, so a candidate built from
  sandbox work cites real evidence IDs and still goes through independent
  verification before anything is published.
- A text pre-check rejects destructive flags (Lictor's denylist) and, without
  operator authorization, credential-guessing tools. It is defence in depth;
  the egress proxy is the boundary.

Available only in deep mode, never in pilot runs, scheduled runs with
autonomy limits, or runs under an operator's method/path approval policy.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

KEY_PREFIX = "prowl:sandbox"
SCOPE_TTL_SECONDS = 6 * 3600
EXCHANGES_PER_CALL = 200
SANDBOX_TOOLS = ("sandbox_exec", "sandbox_python", "sandbox_write_file")

# Credential guessing needs the same operator opt-in as the platform's
# credential tools. Matched as whole command words.
CREDENTIAL_TOOLS = ("hydra", "medusa", "ncrack", "patator", "crackmapexec", "netexec",
                    "nxc", "kerbrute", "cewl")
_EXTRA_DENIED = {
    # Out-of-band tooling needs the operator's callback opt-in.
    "interactsh-client": "oob",
}


def sandbox_configured() -> bool:
    return bool(_url() and _token())


def _url() -> str:
    return str(getattr(settings, "PROWL_SANDBOX_URL", "") or "").rstrip("/")


def _token() -> str:
    return str(getattr(settings, "PROWL_SANDBOX_TOKEN", "") or "")


def sandbox_unavailable_reason(manager: Any) -> str:
    """Empty when the sandbox may be used in this run, else why not."""
    from app.services.agent.assessment_depth import assessment_depth

    if not sandbox_configured():
        return "The explorer sandbox is not configured (PROWL_SANDBOX_URL / PROWL_SANDBOX_TOKEN)."
    if assessment_depth().name != "deep":
        return "The explorer sandbox is only available in deep assessments."
    if getattr(manager, "_scoped_policy_applied", False):
        return ("The explorer sandbox cannot enforce operator method and path approvals; "
                "use structured replay tools.")
    from app.services.agent.assessment_scope import allowed_hosts

    if not allowed_hosts(manager):
        return "No assessment scope is registered yet; map the target first."
    return ""


def _command_words(text: str) -> set[str]:
    return {word.rsplit("/", 1)[-1] for word in re.findall(r"[\w./+-]+", text or "")}


def precheck(text: str, *, credential_testing: bool, oob_callbacks: bool) -> str:
    """Defence-in-depth text check. Returns a denial reason or ''."""
    from aegis_praetorium.lictor import _DESTRUCTIVE_FLAGS, _SSRF_PATTERNS

    lowered = (text or "").lower()
    words = _command_words(lowered)
    for tool, flags in _DESTRUCTIVE_FLAGS.items():
        if tool.removeprefix("execute_") in words:
            for flag in flags:
                if flag.lower() in lowered:
                    return f"{tool} flag {flag} is denied (destructive)."
    for needle in _SSRF_PATTERNS:
        if needle.strip() and needle.lower() in lowered:
            return (f"'{needle.strip()}' is denied: cloud metadata, loopback and non-HTTP "
                    "handlers are never reachable from the sandbox.")
    if not credential_testing:
        for tool in CREDENTIAL_TOOLS:
            if tool in words:
                return (f"{tool} needs operator authorization for credential testing; "
                        "use supplied test identities instead.")
    if not oob_callbacks:
        for tool, kind in _EXTRA_DENIED.items():
            if kind == "oob" and tool in words:
                return "Out-of-band callbacks need operator authorization in this run."
    return ""


def _redis():
    import redis

    return redis.Redis.from_url(
        os.environ.get("REDIS_URL", "redis://redis:6379/0"),
        socket_connect_timeout=2, socket_timeout=3,
    )


def _session(manager: Any) -> dict:
    session = manager._explorer_sandbox
    if not session.get("token"):
        session["token"] = secrets.token_hex(16)
        session["workspace"] = secrets.token_hex(16)
    return session


def session_scope(manager: Any) -> dict:
    from app.services.agent.assessment_scope import allowed_hosts
    from app.services.agent.custom_probe import OOB_HOST_SUFFIXES

    return {
        "hosts": sorted(allowed_hosts(manager)),
        "oob_suffixes": list(OOB_HOST_SUFFIXES) if getattr(manager, "_oob_callbacks_allowed", False) else [],
        "max_requests": int(getattr(settings, "PROWL_SANDBOX_MAX_REQUESTS", 2000) or 2000),
    }


def _publish_scope(client, token: str, scope: dict) -> None:
    client.set(f"{KEY_PREFIX}:scope:{token}", json.dumps(scope), ex=SCOPE_TTL_SECONDS)


def _drain(client, token: str) -> tuple[list[dict], list[dict], int]:
    """Pop recorded exchanges and denials for this session."""
    def pop_all(key: str) -> list[dict]:
        pipe = client.pipeline()
        pipe.lrange(key, 0, -1)
        pipe.delete(key)
        raw, _ = pipe.execute()
        rows = []
        for item in raw or []:
            try:
                rows.append(json.loads(item))
            except (TypeError, ValueError):
                continue
        return rows

    exchanges = pop_all(f"{KEY_PREFIX}:exchanges:{token}")
    denied = pop_all(f"{KEY_PREFIX}:denied:{token}")
    used = int(client.get(f"{KEY_PREFIX}:count:{token}") or 0)
    return exchanges, denied, used


def record_exchanges(manager: Any, exchanges: list[dict]) -> list[dict]:
    """Store sandbox exchanges as evidence and return a compact index."""
    from app.services.agent.evidence_store import evidence_store

    store = evidence_store(manager)
    index = []
    for exchange in exchanges[-EXCHANGES_PER_CALL:]:
        request = exchange.get("request") or {}
        response = exchange.get("response") or {}
        url = str(request.get("url") or "")
        evidence_id = store.record("sandbox_http_exchange", exchange, target=url,
                                   test_type="explorer_sandbox")
        index.append({
            "evidence_id": evidence_id,
            "method": request.get("method"),
            "url": url[:300],
            "status": response.get("status"),
            "response_bytes": (response.get("body") or {}).get("bytes"),
        })
    return index


async def _post(path: str, payload: dict, timeout: float) -> dict:
    import httpx

    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        response = await client.post(
            f"{_url()}{path}", json=payload,
            headers={"Authorization": f"Bearer {_token()}"},
        )
    try:
        body = response.json()
    except ValueError:
        body = {"error": response.text[:300]}
    if response.status_code != 200:
        raise RuntimeError(body.get("error") or f"sandbox returned HTTP {response.status_code}")
    return body


async def run_in_sandbox(manager: Any, *, kind: str, source: str, timeout_sec: int) -> dict:
    reason = sandbox_unavailable_reason(manager)
    if reason:
        return {"ok": False, "error": reason}
    denial = precheck(
        source,
        credential_testing=bool(getattr(manager, "_credential_testing_allowed", False)),
        oob_callbacks=bool(getattr(manager, "_oob_callbacks_allowed", False)),
    )
    if denial:
        return {"ok": False, "error": denial, "blocked_by": "sandbox_precheck"}
    session = _session(manager)
    scope = session_scope(manager)
    limit = int(getattr(settings, "PROWL_SANDBOX_EXEC_TIMEOUT_SECONDS", 300) or 300)
    timeout = max(1, min(int(timeout_sec or 60), limit))
    client = _redis()
    await asyncio.to_thread(_publish_scope, client, session["token"], scope)
    error = ""
    result: dict = {}
    try:
        result = await _post("/v1/exec", {
            "workspace": session["workspace"], "kind": kind, "source": source,
            "timeout_sec": timeout, "proxy_token": session["token"],
        }, timeout=timeout + 30)
    except Exception as exc:  # report, then still collect any traffic it made
        error = f"{type(exc).__name__}: {exc}"
    exchanges, denied, used = await asyncio.to_thread(_drain, client, session["token"])
    index = record_exchanges(manager, exchanges)
    out = {
        "ok": not error,
        "exit_code": result.get("exit_code"),
        "timed_out": result.get("timed_out"),
        "duration_sec": result.get("duration_sec"),
        "stdout": result.get("stdout"),
        "stderr": result.get("stderr"),
        "http_exchanges": index,
        "egress_denied": [
            {"url": str(row.get("url"))[:300], "reason": row.get("reason")} for row in denied[-20:]
        ],
        "requests_used": used,
        "request_budget": scope["max_requests"],
        "scope_hosts": scope["hosts"],
        "note": (
            "Every HTTP exchange above is recorded evidence. Cite evidence_id values in "
            "submit_finding_candidate; findings are published only after independent "
            "verification. Traffic outside scope is refused by the egress proxy."
        ),
    }
    if error:
        out["error"] = error
    return out


async def write_sandbox_file(manager: Any, *, path: str, content: str) -> dict:
    reason = sandbox_unavailable_reason(manager)
    if reason:
        return {"ok": False, "error": reason}
    session = _session(manager)
    try:
        result = await _post("/v1/files", {
            "workspace": session["workspace"], "path": path, "content": content,
        }, timeout=30)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, **result}
