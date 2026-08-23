"""
Observability & Tracing for Aegis Vanguard Agent Framework

OpenTelemetry-based tracing that records every agent decision, tool call,
token usage, and cost. Exports to file (default) or OTLP endpoint.
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent.tracing")

_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|authorization|cookie|api[_-]?key|"
    r"set-cookie|csrf|sessionid|auth[_-]?header|bearer)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+=/]+")
_COOKIE_PAIR = re.compile(r"(?i)((?:set-)?cookie\s*[:=]\s*)[^;\s]+")
_REDACTED = "[redacted]"


def redact_value(value: Any, key: str = "") -> Any:
    """Strip cookies, bearer tokens, and secret-named keys before export."""
    if key and _SECRET_KEY.search(str(key)):
        return _REDACTED
    if isinstance(value, str):
        value = _BEARER.sub(r"\1" + _REDACTED, value)
        value = _COOKIE_PAIR.sub(r"\1" + _REDACTED, value)
        return value
    if isinstance(value, dict):
        return {k: redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, key) for v in value]
    return value

ANTHROPIC_PRICING = {
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-sonnet-4-5": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0},
    "claude-opus-4-1": {"input": 15.0, "output": 75.0},
    # Legacy dated IDs kept so historical traces still price correctly.
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-20250414": {"input": 0.80, "output": 4.0},
    "claude-opus-4-20250514": {"input": 15.0, "output": 75.0},
}


@dataclass
class Span:
    """A single traced operation."""
    name: str
    span_type: str  # agent_turn, tool_call, handoff, guardrail_check
    agent_name: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    status: str = "ok"  # ok, error, blocked
    children: List["Span"] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.span_type,
            "agent": self.agent_name,
            "start": self.start_time,
            "end": self.end_time,
            "duration_ms": round(self.duration_ms, 1),
            "status": self.status,
            "attributes": self.attributes,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def add(self, other: "TokenUsage"):
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens

    def cost(self, model: str) -> float:
        pricing = ANTHROPIC_PRICING.get(model, {"input": 3.0, "output": 15.0})
        return (
            (self.input_tokens / 1_000_000) * pricing["input"]
            + (self.output_tokens / 1_000_000) * pricing["output"]
        )


class Tracer:
    """Records and exports trace data for agent operations."""

    def __init__(
        self,
        enabled: bool = True,
        output_dir: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        self.enabled = enabled if os.environ.get("AEGIS_TRACING", "true").lower() != "false" else False
        self.output_dir = Path(
            output_dir
            or os.environ.get("AEGIS_TRACES_DIR")
            or "/agent/traces"
        )
        self.session_id = session_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.spans: List[Span] = []
        self.tokens = TokenUsage()
        self.model: str = ""
        self._active_span: Optional[Span] = None
        self._tool_calls: int = 0
        self._agent_turns: int = 0
        self._handoffs: int = 0
        self._guardrail_blocks: int = 0

        if self.enabled:
            self.output_dir.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def span(self, name: str, span_type: str, agent_name: str = "", **attrs):
        if not self.enabled:
            yield None
            return

        s = Span(
            name=name,
            span_type=span_type,
            agent_name=agent_name,
            start_time=time.time(),
            attributes=attrs,
        )
        parent = self._active_span
        self._active_span = s

        try:
            yield s
            s.status = "ok"
        except Exception as e:
            s.status = "error"
            s.attributes["error"] = str(e)
            raise
        finally:
            s.end_time = time.time()
            self._active_span = parent
            if parent:
                parent.children.append(s)
            else:
                self.spans.append(s)

            if span_type == "tool_call":
                self._tool_calls += 1
            elif span_type == "agent_turn":
                self._agent_turns += 1
            elif span_type == "handoff":
                self._handoffs += 1

    def record_tokens(self, usage: TokenUsage, model: str = ""):
        if model:
            self.model = model
        self.tokens.add(usage)

    def record_guardrail_block(self, rule: str, tool_name: str = ""):
        self._guardrail_blocks += 1
        if self.enabled:
            logger.info(f"[trace] guardrail_block rule={rule} tool={tool_name}")

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "model": self.model,
            "agent_turns": self._agent_turns,
            "tool_calls": self._tool_calls,
            "handoffs": self._handoffs,
            "guardrail_blocks": self._guardrail_blocks,
            "tokens": {
                "input": self.tokens.input_tokens,
                "output": self.tokens.output_tokens,
                "total": self.tokens.total,
                "cache_read": self.tokens.cache_read_tokens,
            },
            "estimated_cost_usd": round(self.tokens.cost(self.model), 4),
            "total_spans": len(self.spans),
        }

    def export(self) -> str:
        if not self.enabled:
            return ""

        trace_data = redact_value({
            "summary": self.summary(),
            "spans": [s.to_dict() for s in self.spans],
        })

        path = self.output_dir / f"trace_{self.session_id}.json"
        with open(path, "w") as f:
            json.dump(trace_data, f, indent=2, default=str)
        logger.info(f"Trace exported to {path}")
        self._export_otlp(trace_data)
        return str(path)

    def _export_otlp(self, trace_data: dict) -> None:
        endpoint = (
            os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
            or os.environ.get("LANGFUSE_OTLP_ENDPOINT")
            or ""
        ).rstrip("/")
        if not endpoint:
            return
        url = endpoint if endpoint.endswith("/v1/traces") else f"{endpoint}/v1/traces"
        now_ns = int(time.time() * 1_000_000_000)
        trace_id = os.urandom(16).hex()
        spans = []
        for i, span in enumerate(trace_data.get("spans") or []):
            start = now_ns - max(0, len(trace_data.get("spans") or []) - i) * 1_000_000
            attrs = span.get("attributes") or {}
            otlp_attrs = []
            for k, v in list(attrs.items())[:24]:
                otlp_attrs.append({"key": str(k), "value": {"stringValue": str(v)[:512]}})
            spans.append({
                "traceId": trace_id,
                "spanId": os.urandom(8).hex(),
                "name": span.get("name") or span.get("type") or "span",
                "kind": 1,
                "startTimeUnixNano": str(start),
                "endTimeUnixNano": str(start + int(float(span.get("duration_ms") or 1) * 1_000_000)),
                "attributes": otlp_attrs,
                "status": {"code": 1 if span.get("status") != "error" else 2},
            })
        payload = {
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "aegis-vanguard"}},
                        {"key": "session.id", "value": {"stringValue": self.session_id}},
                    ]
                },
                "scopeSpans": [{"scope": {"name": "aegis-vanguard"}, "spans": spans}],
            }]
        }
        headers = {"Content-Type": "application/json"}
        raw = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS") or ""
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
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=2.0).read()
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            logger.debug("OTLP export skipped: %s", exc)

    def print_summary(self):
        s = self.summary()
        print(f"\n{'='*50}")
        print(f"  Aegis Vanguard Agent Trace Summary")
        print(f"{'='*50}")
        print(f"  Session:          {s['session_id']}")
        print(f"  Model:            {s['model']}")
        print(f"  Agent turns:      {s['agent_turns']}")
        print(f"  Tool calls:       {s['tool_calls']}")
        print(f"  Handoffs:         {s['handoffs']}")
        print(f"  Guardrail blocks: {s['guardrail_blocks']}")
        print(f"  Tokens (in/out):  {s['tokens']['input']:,} / {s['tokens']['output']:,}")
        print(f"  Estimated cost:   ${s['estimated_cost_usd']:.4f}")
        print(f"{'='*50}\n")
