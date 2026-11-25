"""Stable response labels, next-step hints and stored-exchange diffs.

Ported from the Vanguard request ledger. Classification reads a request and
its response and returns labels only: no header value, body excerpt, or
request value leaves this module, so the labels are safe to keep on capture
records and to show in tool output. A label is a lead for the next probe,
never proof.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlsplit

RESPONSE_CLASSES = (
    "request_error",
    "authentication_required",
    "access_denied",
    "rate_limited",
    "redirect",
    "server_error",
    "empty_body",
    "filter_blocked",
    "sql_error",
    "template_error",
    "debug_error",
    "input_reflected",
)

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
_DEBUG_MARKERS = ("stack trace", "traceback (most recent", "exception in thread")
_MAX_SCAN = 200_000


def _body(response: Mapping[str, Any]) -> str:
    for key in ("body", "body_preview", "_body_text"):
        value = response.get(key)
        if isinstance(value, str) and value:
            return value[:_MAX_SCAN]
    return ""


def _status(response: Mapping[str, Any]) -> int | None:
    value = response.get("status", response.get("status_code"))
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _length(response: Mapping[str, Any], body: str) -> int:
    for key in ("length", "response_length"):
        value = response.get(key)
        if isinstance(value, int):
            return value
    return len(body)


def _request_values(request: Mapping[str, Any]) -> list[str]:
    url = str(request.get("url") or "")
    values = [value for _, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    body = request.get("body")
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    parsed: Any = body if isinstance(body, (dict, list)) else None
    if isinstance(body, str) and body:
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
            values.extend(value for _, value in parse_qsl(body, keep_blank_values=True))

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
        elif value is not None and not isinstance(value, bool):
            values.append(str(value))

    if parsed is not None:
        walk(parsed)
    # Short or boolean-like values reflect everywhere and say nothing.
    return [value for value in values[:64]
            if len(value) >= 4 and value.lower() not in {"true", "false", "null"}]


def classify_response(request: Mapping[str, Any] | None,
                      response: Mapping[str, Any] | None) -> list[str]:
    """Return ordered labels from ``RESPONSE_CLASSES`` for one exchange."""
    request = request if isinstance(request, Mapping) else {}
    response = response if isinstance(response, Mapping) else {}
    classes: list[str] = []
    status = _status(response)
    body = _body(response)
    has_body_view = any(key in response for key in ("body", "body_preview", "_body_text"))
    if response.get("error") or response.get("failed"):
        classes.append("request_error")
    if status in (401, 407):
        classes.append("authentication_required")
    if status == 403:
        classes.append("access_denied")
    if status == 429:
        classes.append("rate_limited")
    if status is not None and 300 <= status < 400:
        classes.append("redirect")
    if status is not None and status >= 500:
        classes.append("server_error")
    if (has_body_view and not body and not _length(response, body)
            and "request_error" not in classes):
        classes.append("empty_body")
    if body:
        if _BLOCK_RE.search(body):
            classes.append("filter_blocked")
        if _SQL_ERROR_RE.search(body):
            classes.append("sql_error")
        if _TEMPLATE_ERROR_RE.search(body):
            classes.append("template_error")
        low = body.lower()
        if any(marker in low for marker in _DEBUG_MARKERS):
            classes.append("debug_error")
        if any(value in body for value in _request_values(request)):
            classes.append("input_reflected")
    return list(dict.fromkeys(classes))


_HINTS = (
    ("sql_error", "A database error string appeared; run the scoped SQLi proof on this exact input "
                  "with a baseline before claiming injection."),
    ("template_error", "A template engine error appeared; try a computed-output SSTI control "
                       "(e.g. a unique product) rather than a bare syntax break."),
    ("debug_error", "Debug output leaks internals; read it for framework, paths and parameters, "
                    "then diff against a clean baseline."),
    ("filter_blocked", "Change one axis at a time (encoding, location, case) and compare against a "
                       "clean baseline before retrying."),
    ("access_denied", "Compare the same request across identities; a denial is the control for an "
                      "authorization test, not a dead end."),
    ("authentication_required", "Establish an identity, then replay the same request with its "
                                "session state preserved."),
    ("rate_limited", "Back off; repeated requests now measure the rate limiter, not the input."),
    ("input_reflected", "Classify the physical reflection context before selecting the next "
                        "payload family."),
    ("server_error", "Diff against baseline; treat a 5xx alone as a parser clue, not proof."),
    ("redirect", "Check whether a request value controls the Location target before probing "
                 "open redirect or CRLF."),
)


def adaptive_hints(classes: Iterable[str]) -> list[str]:
    """Next-step guidance for the labels on one exchange (most specific first)."""
    present = set(classes or ())
    return [hint for label, hint in _HINTS if label in present][:4]


def _headers(response: Mapping[str, Any]) -> dict[str, str]:
    headers = response.get("headers")
    if isinstance(headers, Mapping):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    return {}


def _elapsed_ms(response: Mapping[str, Any]) -> float | None:
    if isinstance(response.get("elapsed_ms"), (int, float)):
        return float(response["elapsed_ms"])
    if isinstance(response.get("elapsed_s"), (int, float)):
        return float(response["elapsed_s"]) * 1000.0
    return None


def diff_exchanges(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two stored exchanges ({request, response}) without sending anything.

    Header deltas list names only; values (cookies, tokens) never leave the
    stored, redacted evidence.
    """
    a_req = baseline.get("request") if isinstance(baseline.get("request"), Mapping) else {}
    b_req = candidate.get("request") if isinstance(candidate.get("request"), Mapping) else {}
    a_resp = baseline.get("response") if isinstance(baseline.get("response"), Mapping) else {}
    b_resp = candidate.get("response") if isinstance(candidate.get("response"), Mapping) else {}
    a_body, b_body = _body(a_resp), _body(b_resp)
    a_len, b_len = _length(a_resp, a_body), _length(b_resp, b_body)
    similarity = difflib.SequenceMatcher(None, a_body[:8000], b_body[:8000]).ratio()
    a_status, b_status = _status(a_resp), _status(b_resp)
    a_ms, b_ms = _elapsed_ms(a_resp), _elapsed_ms(b_resp)
    elapsed_delta = round(b_ms - a_ms, 1) if a_ms is not None and b_ms is not None else None
    a_classes = set(a_resp.get("classes") or classify_response(a_req, a_resp))
    b_classes = set(b_resp.get("classes") or classify_response(b_req, b_resp))
    signals: list[str] = []
    if a_status != b_status:
        signals.append("status_change")
    if a_status in (401, 403) and b_status is not None and 200 <= b_status < 300:
        signals.append("authorization_difference")
    if similarity < 0.92 or abs(b_len - a_len) >= 32:
        signals.append("content_difference")
    if (elapsed_delta is not None and elapsed_delta >= 1500
            and b_ms >= max(2000.0, a_ms * 2)):
        signals.append("timing_signal")
    if {"sql_error", "template_error", "debug_error"} & (b_classes - a_classes):
        signals.append("new_error_signal")
    if "input_reflected" in b_classes - a_classes:
        signals.append("new_reflection")
    a_headers, b_headers = _headers(a_resp), _headers(b_resp)
    changed = sorted(key for key in set(a_headers) | set(b_headers)
                     if a_headers.get(key) != b_headers.get(key))
    return {
        "request": {
            "baseline": {"method": a_req.get("method"), "identity": a_req.get("identity")},
            "candidate": {"method": b_req.get("method"), "identity": b_req.get("identity")},
            "same_url": str(a_req.get("url") or "") == str(b_req.get("url") or ""),
        },
        "status": {"baseline": a_status, "candidate": b_status},
        "body_length": {"baseline": a_len, "candidate": b_len, "delta": b_len - a_len},
        "body_similarity": round(similarity, 4),
        "body_compared": bool(a_body or b_body),
        "elapsed_ms": {"baseline": a_ms, "candidate": b_ms, "delta": elapsed_delta},
        "added_classes": sorted(b_classes - a_classes),
        "removed_classes": sorted(a_classes - b_classes),
        "header_delta": {
            "added": sorted(set(b_headers) - set(a_headers)),
            "removed": sorted(set(a_headers) - set(b_headers)),
            "changed": [key for key in changed if key in a_headers and key in b_headers],
        },
        "signals": signals,
        "interesting": bool(signals),
        "adaptive_hints": adaptive_hints(b_classes),
    }
