"""Thread-safe HTTP request/response memory for adaptive vulnerability hunting.

The ledger keeps the full request in process so a later hunter can replay an
authenticated or otherwise delicate request without reconstructing it. Tool
outputs expose a redacted view; authorization material remains available only
to the replay path. Records are isolated by assessment/session namespace and
bounded to avoid unbounded memory growth during large scans.
"""

from __future__ import annotations

import contextlib
import contextvars
import difflib
import hashlib
import json
import os
import re
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


_SOURCE = contextvars.ContextVar("aegis_request_source", default={})
_SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-auth-token", "api-key",
}
_SENSITIVE_FIELD_RE = re.compile(
    r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|authorization|cookie)", re.I,
)
_BEARER_VALUE_RE = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{12,}")
_JWT_VALUE_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_FLAG_RE = re.compile(r"FLAG\{[0-9a-f]{64}\}", re.I)
_SQL_ERROR_RE = re.compile(
    r"(?:SQL syntax|mysql_fetch|mysqli_|pg_query|PostgreSQL.*ERROR|ORA-\d{5}|"
    r"ODBC SQL|SQLite3?::|Unclosed quotation mark|SQLSTATE\[|PDOException)", re.I,
)
_TEMPLATE_ERROR_RE = re.compile(
    r"(?:TemplateSyntaxError|jinja2\.|twig.{0,40}error|freemarker|velocityexception|"
    r"undefined variable.*template)", re.I,
)
_BLOCK_RE = re.compile(
    r"(?:access denied|request blocked|blocked by waf|security check|captcha|"
    r"cloudflare ray id|mod_security|not acceptable)", re.I,
)


def _namespace() -> str:
    return (
        os.environ.get("AEGIS_LEDGER_SESSION")
        or os.environ.get("ASM_AGENT_ID")
        or "default"
    )


@contextlib.contextmanager
def request_source(agent_name: str, tool_name: str) -> Iterator[None]:
    """Attach the current agent/tool identity to HTTP exchanges it produces."""
    token = _SOURCE.set({"agent": agent_name, "tool": tool_name})
    try:
        yield
    finally:
        _SOURCE.reset(token)


def _redact_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    return {
        str(k): "[REDACTED]" if str(k).lower() in _SENSITIVE_HEADER_NAMES else v
        for k, v in headers.items()
    }


def _redact_url(url: str) -> str:
    parsed = urlparse(url)
    query = [
        (key, "[REDACTED]" if _SENSITIVE_FIELD_RE.search(key) else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _redact_body(body: str) -> str:
    if not body:
        return ""
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        def clean(value: Any, key: str = "") -> Any:
            if key and _SENSITIVE_FIELD_RE.search(key):
                return "[REDACTED]"
            if isinstance(value, dict):
                return {k: clean(v, str(k)) for k, v in value.items()}
            if isinstance(value, list):
                return [clean(v) for v in value]
            return value
        return json.dumps(clean(parsed), separators=(",", ":"), default=str)

    pairs = parse_qsl(body, keep_blank_values=True)
    if pairs and ("=" in body or "&" in body):
        return "&".join(
            f"{k}={'[REDACTED]' if _SENSITIVE_FIELD_RE.search(k) else v}"
            for k, v in pairs
        )
    return body


def redact_response_body(body: str) -> str:
    """Redact credential-shaped response data without hiding vuln evidence."""
    redacted = _redact_body(str(body or ""))
    redacted = _BEARER_VALUE_RE.sub(r"\1[REDACTED]", redacted)
    return _JWT_VALUE_RE.sub("[REDACTED-JWT]", redacted)


def _response_headers(response: Dict[str, Any]) -> Dict[str, str]:
    headers = response.get("headers")
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    raw = str(response.get("raw_headers") or "")
    parsed: Dict[str, str] = {}
    for line in raw.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip().lower()] = value.strip()
    return parsed


def _candidate_values(url: str, body: str) -> List[str]:
    values = [v for _, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    try:
        parsed = json.loads(body) if body else None
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed = None

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
        elif value is not None:
            values.append(str(value))

    if parsed is not None:
        walk(parsed)
    else:
        values.extend(v for _, v in parse_qsl(body, keep_blank_values=True))
    return [v for v in values if len(v) >= 4 and v.lower() not in {"true", "false", "null"}]


def classify_response(request: Dict[str, Any], response: Dict[str, Any]) -> List[str]:
    """Classify response evidence into stable signals used by adaptive hunters."""
    classes: List[str] = []
    status = response.get("status")
    body = str(response.get("body") or "")
    low = body.lower()

    if response.get("error"):
        classes.append("request_error")
    if status in (401, 407):
        classes.append("authentication_required")
    if status == 403:
        classes.append("access_denied")
    if status == 429:
        classes.append("rate_limited")
    if isinstance(status, int) and 300 <= status < 400:
        classes.append("redirect")
    if isinstance(status, int) and status >= 500:
        classes.append("server_error")
    if not body and not response.get("error"):
        classes.append("empty_body")
    if _BLOCK_RE.search(body):
        classes.append("filter_blocked")
    if _SQL_ERROR_RE.search(body):
        classes.append("sql_error")
    if _TEMPLATE_ERROR_RE.search(body):
        classes.append("template_error")
    if _FLAG_RE.search(body):
        classes.append("objective_found")
    if any(value in body for value in _candidate_values(
        str(request.get("url") or ""), str(request.get("body") or "")
    )):
        classes.append("input_reflected")
    if any(token in low for token in ("stack trace", "traceback (most recent", "exception in thread")):
        classes.append("debug_error")
    return list(dict.fromkeys(classes))


def adaptive_hints(classes: List[str]) -> List[str]:
    hints: List[str] = []
    if "objective_found" in classes:
        hints.append("Exact benchmark objective observed; stop and report it.")
    if "filter_blocked" in classes or "access_denied" in classes:
        hints.append("Change one axis at a time and compare against a clean baseline before retrying.")
    if "authentication_required" in classes:
        hints.append("Establish an identity, then replay the same request with its session state preserved.")
    if "input_reflected" in classes:
        hints.append("Classify the physical reflection context before selecting the next payload family.")
    if "server_error" in classes:
        hints.append("Diff against baseline; treat a 5xx alone as a parser clue, not proof.")
    return hints


class RequestLedger:
    def __init__(self, max_records: Optional[int] = None):
        self.max_records = max_records or int(os.environ.get("AEGIS_LEDGER_MAX_RECORDS", "1000"))
        self._records: Dict[str, OrderedDict[str, Dict[str, Any]]] = {}
        self._counters: Dict[str, int] = {}
        self._lock = threading.RLock()

    def clear(self, namespace: Optional[str] = None) -> None:
        ns = namespace or _namespace()
        with self._lock:
            self._records.pop(ns, None)
            self._counters.pop(ns, None)

    def record(
        self,
        method: str,
        url: str,
        headers: Dict[str, Any],
        body: str,
        follow_redirects: bool,
        response: Dict[str, Any],
    ) -> Dict[str, Any]:
        ns = _namespace()
        with self._lock:
            counter = self._counters.get(ns, 0) + 1
            self._counters[ns] = counter
            request_id = f"req-{counter:06d}"
            request = {
                "method": method.upper(), "url": url, "headers": dict(headers),
                "body": body or "", "follow_redirects": bool(follow_redirects),
            }
            response_copy = dict(response)
            classes = classify_response(request, response_copy)
            record = {
                "request_id": request_id,
                "timestamp": time.time(),
                "source": dict(_SOURCE.get() or {}),
                "request": request,
                "response": response_copy,
                "classes": classes,
            }
            bucket = self._records.setdefault(ns, OrderedDict())
            bucket[request_id] = record
            while len(bucket) > self.max_records:
                bucket.popitem(last=False)
            return record

    def get_raw(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get(_namespace(), {}).get(request_id)
            return dict(record) if record else None

    def tag_identity(self, request_id: str, identity_label: str) -> bool:
        """Attach a non-secret identity label to an existing exchange."""
        label = str(identity_label or "").strip()
        if not label:
            return False
        with self._lock:
            record = self._records.get(_namespace(), {}).get(request_id)
            if not record:
                return False
            source = dict(record.get("source") or {})
            source["identity"] = label
            record["source"] = source
            return True

    def _public(self, record: Dict[str, Any], include_bodies: bool = False) -> Dict[str, Any]:
        request = record["request"]
        response = record["response"]
        body = str(response.get("body") or "")
        public = {
            "request_id": record["request_id"],
            "timestamp": record["timestamp"],
            "source": record.get("source") or {},
            "method": request.get("method"),
            "url": _redact_url(str(request.get("url") or "")),
            "request_headers": _redact_headers(request.get("headers") or {}),
            "status": response.get("status"),
            "elapsed_ms": response.get("elapsed_ms"),
            "response_length": len(body),
            "response_sha256": hashlib.sha256(body.encode(errors="replace")).hexdigest(),
            "classes": record.get("classes") or [],
            "adaptive_hints": adaptive_hints(record.get("classes") or []),
        }
        if include_bodies:
            public["request_body"] = _redact_body(str(request.get("body") or ""))[:8000]
            public["response_headers"] = _redact_headers(_response_headers(response))
            public["response_body"] = redact_response_body(body)[:8000]
            if response.get("error"):
                public["error"] = response.get("error")
        return public

    def get(self, request_id: str) -> Optional[Dict[str, Any]]:
        raw = self.get_raw(request_id)
        return self._public(raw, include_bodies=True) if raw else None

    def list(
        self, limit: int = 50, classification: str = "", url_contains: str = "",
    ) -> List[Dict[str, Any]]:
        with self._lock:
            records = list(self._records.get(_namespace(), {}).values())
        if classification:
            records = [r for r in records if classification in (r.get("classes") or [])]
        if url_contains:
            needle = url_contains.lower()
            records = [r for r in records if needle in str(r["request"].get("url") or "").lower()]
        return [self._public(r) for r in records[-max(1, min(int(limit), 200)):]]

    def diff(self, baseline_id: str, candidate_id: str) -> Dict[str, Any]:
        baseline = self.get_raw(baseline_id)
        candidate = self.get_raw(candidate_id)
        if not baseline or not candidate:
            missing = baseline_id if not baseline else candidate_id
            return {"error": f"request not found in current assessment: {missing}"}

        a_resp, b_resp = baseline["response"], candidate["response"]
        a_body = str(a_resp.get("body") or "")
        b_body = str(b_resp.get("body") or "")
        similarity = difflib.SequenceMatcher(None, a_body[:8000], b_body[:8000]).ratio()
        a_status, b_status = a_resp.get("status"), b_resp.get("status")
        a_elapsed = a_resp.get("elapsed_ms")
        b_elapsed = b_resp.get("elapsed_ms")
        elapsed_delta = (
            b_elapsed - a_elapsed
            if isinstance(a_elapsed, (int, float)) and isinstance(b_elapsed, (int, float))
            else None
        )
        a_classes = set(baseline.get("classes") or [])
        b_classes = set(candidate.get("classes") or [])
        signals: List[str] = []
        if a_status != b_status:
            signals.append("status_change")
        if a_status in (401, 403) and isinstance(b_status, int) and 200 <= b_status < 300:
            signals.append("authorization_difference")
        if similarity < 0.92 or abs(len(b_body) - len(a_body)) >= 32:
            signals.append("content_difference")
        if elapsed_delta is not None and elapsed_delta >= 1500 and b_elapsed >= max(2000, a_elapsed * 2):
            signals.append("timing_signal")
        if "objective_found" in b_classes - a_classes:
            signals.append("objective_found")
        if {"sql_error", "template_error", "debug_error"} & (b_classes - a_classes):
            signals.append("new_error_signal")
        if "input_reflected" in b_classes - a_classes:
            signals.append("new_reflection")

        a_headers, b_headers = _response_headers(a_resp), _response_headers(b_resp)
        changed_headers = sorted(
            key for key in set(a_headers) | set(b_headers)
            if a_headers.get(key) != b_headers.get(key)
        )
        return {
            "baseline_request_id": baseline_id,
            "candidate_request_id": candidate_id,
            "status": {"baseline": a_status, "candidate": b_status},
            "body_length": {"baseline": len(a_body), "candidate": len(b_body),
                            "delta": len(b_body) - len(a_body)},
            "body_similarity": round(similarity, 4),
            "elapsed_ms": {"baseline": a_elapsed, "candidate": b_elapsed,
                           "delta": elapsed_delta},
            "added_classes": sorted(b_classes - a_classes),
            "removed_classes": sorted(a_classes - b_classes),
            "changed_response_headers": changed_headers,
            "signals": signals,
            "interesting": bool(signals),
        }


_LEDGER = RequestLedger()


def get_request_ledger() -> RequestLedger:
    return _LEDGER
