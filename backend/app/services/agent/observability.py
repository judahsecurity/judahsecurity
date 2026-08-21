"""Internal LLM observability: redaction, cost, engagement replay, optional OTLP.

Traces from pentest/agent runs contain cookies, Authorization headers, and
exploit payloads. Nothing in this module should export raw secrets. The OTLP
path is for a self-hosted sidecar (Phoenix / Langfuse), never a customer UI.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# USD per million tokens. Keep in sync with aegis-vanguard/agent/tracing.py.
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-sonnet-4-5": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0},
    "claude-opus-4-1": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-20250414": {"input": 0.80, "output": 4.0},
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "deepseek-chat": {"input": 0.28, "output": 0.42},
    "qwen2.5:14b": {"input": 0.0, "output": 0.0},
}

_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|authorization|cookie|api[_-]?key|"
    r"set-cookie|csrf|sessionid|auth[_-]?header|bearer)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+=/]+")
_COOKIE_PAIR = re.compile(
    r"(?i)((?:set-)?cookie\s*[:=]\s*)[^;\s]+"
)
_REDACTED = "[redacted]"
_PREVIEW_CHARS = 400
_MAX_REPLAY_STEPS = 200


def redact_string(value: str) -> str:
    if not value:
        return value
    value = _BEARER.sub(r"\1" + _REDACTED, value)
    value = _COOKIE_PAIR.sub(r"\1" + _REDACTED, value)
    return value


def redact_value(value: Any, key: str = "") -> Any:
    if key and _SECRET_KEY.search(str(key)):
        return _REDACTED
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, dict):
        return {k: redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, key) for v in value]
    return value


def usage_from_llm_response(response: Any) -> Dict[str, int]:
    """Pull input/output tokens off a LangChain AIMessage or similar."""
    meta = getattr(response, "usage_metadata", None)
    if isinstance(meta, dict) and (meta.get("input_tokens") or meta.get("output_tokens")):
        return {
            "input_tokens": int(meta.get("input_tokens") or 0),
            "output_tokens": int(meta.get("output_tokens") or 0),
        }
    rm = getattr(response, "response_metadata", None) or {}
    if not isinstance(rm, dict):
        rm = {}
    usage = rm.get("usage") or rm.get("token_usage") or {}
    if isinstance(usage, dict):
        inp = usage.get("input_tokens") or usage.get("prompt_tokens") or 0
        out = usage.get("output_tokens") or usage.get("completion_tokens") or 0
        if inp or out:
            return {"input_tokens": int(inp), "output_tokens": int(out)}
    return {"input_tokens": 0, "output_tokens": 0}


def model_id(llm: Any) -> str:
    for attr in ("model", "model_name", "model_id"):
        v = getattr(llm, attr, None)
        if v:
            return str(v)
    return ""


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    pricing = MODEL_PRICING.get(model)
    if pricing is None:
        for key, rates in MODEL_PRICING.items():
            if key in (model or ""):
                pricing = rates
                break
    if pricing is None:
        pricing = {"input": 3.0, "output": 15.0}
    return round(
        (input_tokens / 1_000_000) * pricing["input"]
        + (output_tokens / 1_000_000) * pricing["output"],
        6,
    )


def empty_token_usage() -> Dict[str, Any]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cost_usd": 0.0,
        "calls": [],
    }


def record_llm_usage(
    bucket: Dict[str, Any],
    response: Any,
    *,
    task: str = "",
    model: str = "",
) -> Dict[str, int]:
    """Accumulate usage onto a mutable dict (agent state or orchestrator bucket)."""
    usage = usage_from_llm_response(response)
    totals = bucket.get("token_usage") or empty_token_usage()
    totals["input_tokens"] = int(totals.get("input_tokens") or 0) + usage["input_tokens"]
    totals["output_tokens"] = int(totals.get("output_tokens") or 0) + usage["output_tokens"]
    totals["total_tokens"] = totals["input_tokens"] + totals["output_tokens"]
    call_cost = estimate_cost_usd(model, usage["input_tokens"], usage["output_tokens"])
    totals["cost_usd"] = round(float(totals.get("cost_usd") or 0) + call_cost, 6)
    calls = list(totals.get("calls") or [])
    calls.append(
        {
            "task": task,
            "model": model,
            "input_tokens": usage["input_tokens"],
            "output_tokens": usage["output_tokens"],
            "cost_usd": call_cost,
        }
    )
    totals["calls"] = calls[-50:]
    bucket["token_usage"] = totals
    usage["cost_usd"] = call_cost  # type: ignore[assignment]
    usage["model"] = model  # type: ignore[assignment]
    return usage


def replay_from_execution_trace(
    trace: Iterable[Any],
    *,
    token_usage: Optional[Dict[str, Any]] = None,
    finding_titles: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Customer-safe thought → tool → evidence timeline. No raw payloads."""
    steps: List[Dict[str, Any]] = []
    for raw in list(trace or [])[-_MAX_REPLAY_STEPS:]:
        if not isinstance(raw, dict):
            continue
        output = raw.get("tool_output") or raw.get("output_preview") or ""
        preview = redact_string(str(output))[:_PREVIEW_CHARS] if output else ""
        evidence = raw.get("actionable_findings") or []
        if not isinstance(evidence, list):
            evidence = []
        finding = raw.get("finding") if isinstance(raw.get("finding"), dict) else None
        steps.append(
            {
                "iteration": raw.get("iteration"),
                "phase": raw.get("phase") or raw.get("agent") or "",
                "agent": raw.get("agent") or "",
                "thought": redact_string(str(raw.get("thought") or ""))[:500],
                "tool_name": raw.get("tool_name") or None,
                "success": raw.get("success"),
                "evidence": [str(e)[:300] for e in evidence if e][:8],
                "finding_title": (finding or {}).get("title") if finding else None,
                "output_preview": preview,
                "token_usage": raw.get("token_usage"),
            }
        )
    usage = token_usage or empty_token_usage()
    return {
        "steps": steps,
        "token_usage": {
            "input_tokens": int(usage.get("input_tokens") or 0),
            "output_tokens": int(usage.get("output_tokens") or 0),
            "total_tokens": int(usage.get("total_tokens") or 0),
            "cost_usd": float(usage.get("cost_usd") or 0),
        },
        "cost_usd": float(usage.get("cost_usd") or 0),
        "finding_titles": list(finding_titles or []),
    }


def otlp_endpoint() -> str:
    return (
        os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.environ.get("LANGFUSE_OTLP_ENDPOINT")
        or ""
    ).rstrip("/")


def _otlp_headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    raw = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS") or ""
    if raw:
        for part in raw.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                headers[k.strip()] = v.strip()
    pub = os.environ.get("LANGFUSE_PUBLIC_KEY") or ""
    sec = os.environ.get("LANGFUSE_SECRET_KEY") or ""
    if pub and sec:
        import base64

        token = base64.b64encode(f"{pub}:{sec}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def _hex_id(nbytes: int) -> str:
    return os.urandom(nbytes).hex()


def _attr(key: str, value: Any) -> Dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float):
            return {"key": key, "value": {"doubleValue": float(value)}}
        return {"key": key, "value": {"intValue": str(int(value))}}
    return {"key": key, "value": {"stringValue": str(value)[:512]}}


def export_otlp_replay(
    replay: Dict[str, Any],
    *,
    service_name: str,
    session_id: str,
    timeout_sec: float = 2.0,
) -> bool:
    """Best-effort OTLP/JSON export of a *redacted* replay. Never raises."""
    endpoint = otlp_endpoint()
    if not endpoint:
        return False
    url = endpoint if endpoint.endswith("/v1/traces") else f"{endpoint}/v1/traces"
    now_ns = int(time.time() * 1_000_000_000)
    trace_id = _hex_id(16)
    spans = []
    for i, step in enumerate(replay.get("steps") or []):
        start = now_ns - (len(replay.get("steps") or []) - i) * 1_000_000
        name = step.get("tool_name") or "thought"
        spans.append(
            {
                "traceId": trace_id,
                "spanId": _hex_id(8),
                "name": f"{name}",
                "kind": 1,
                "startTimeUnixNano": str(start),
                "endTimeUnixNano": str(start + 500_000),
                "attributes": [
                    _attr("session.id", session_id),
                    _attr("iteration", step.get("iteration") or 0),
                    _attr("thought", step.get("thought") or ""),
                    _attr("success", bool(step.get("success"))),
                ],
                "status": {"code": 1 if step.get("success") is not False else 2},
            }
        )
    usage = replay.get("token_usage") or {}
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _attr("service.name", service_name),
                        _attr("session.id", session_id),
                        _attr("cost.usd", usage.get("cost_usd") or 0),
                    ]
                },
                "scopeSpans": [{"scope": {"name": service_name}, "spans": spans}],
            }
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=_otlp_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        logger.debug("OTLP export skipped: %s", exc)
        return False
