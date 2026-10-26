"""Operator-authorized POST replay from browser evidence.

A two-request difference is a lead; a repeated SQL error recipe can produce a
candidate that still requires an independent verifier before publication.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import re
from urllib.error import HTTPError
from urllib.parse import unquote_plus, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .browser import assert_in_scope, origin
from .browser_traffic import MAX_BODY_BYTES, _replay_headers
from .http_observe import MAX_BODY, _NoRedirect, _cookie_header, _sql_error_family


MAX_REPLAY_BODY = min(MAX_BODY_BYTES, 64 * 1024)
_SAFE_SQL_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,39}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
SQL_ERROR_CHECK_ORDER = (
    "baseline_first", "quote_first", "escaped_quote", "quote_second", "baseline_last",
)


def safe_replay_headers(private_exchange: bytes) -> dict[str, str]:
    """Revalidate the private capture's small non-credential header allowlist."""
    try:
        captured = json.loads(private_exchange)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid captured exchange") from exc
    headers = captured.get("replay_headers") if isinstance(captured, dict) else None
    url = captured.get("url") if isinstance(captured, dict) else None
    return _replay_headers(headers if isinstance(headers, dict) else None,
                           expected_origin=origin(url) if isinstance(url, str) else "")


def _mutate_json(data: bytes, pointer: str, payload: str = "'") -> bytes:
    if not pointer.startswith("/") or len(pointer) > 300:
        raise ValueError("A bounded JSON pointer is required")
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Captured JSON body is invalid") from exc
    current = document
    tokens = pointer.split("/")[1:]
    for token in tokens[:-1]:
        if re.search(r"~(?![01])", token):
            raise ValueError("Invalid JSON pointer escape")
        key = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and (key == "*" and len(current) == 1 or key.isdecimal() and int(key) < len(current)):
            current = current[0 if key == "*" else int(key)]
        else:
            raise ValueError("JSON pointer does not identify an observed field")
    token = tokens[-1]
    if re.search(r"~(?![01])", token):
        raise ValueError("Invalid JSON pointer escape")
    key = token.replace("~1", "/").replace("~0", "~")
    if isinstance(current, dict) and key in current:
        value = current[key]
        setter = lambda changed: current.__setitem__(key, changed)
    elif isinstance(current, list) and (key == "*" and len(current) == 1 or key.isdecimal() and int(key) < len(current)):
        index = 0 if key == "*" else int(key)
        value = current[index]
        setter = lambda changed: current.__setitem__(index, changed)
    else:
        raise ValueError("JSON pointer does not identify an observed field")
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError("Body probe requires a string or numeric field")
    setter(str(value) + payload)
    changed = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    if len(changed) > MAX_REPLAY_BODY:
        raise ValueError("Mutated body exceeds replay limit")
    return changed


def _mutate_form(data: bytes, parameter: str, payload: str = "'") -> bytes:
    try:
        raw = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Captured form body is not ASCII encoded") from exc
    if not 0 < len(parameter) <= 80 or len(raw) > MAX_REPLAY_BODY:
        raise ValueError("A bounded form field is required")
    fields = raw.split("&")
    if len(fields) > 40:
        raise ValueError("Captured form has too many fields")
    matches = [index for index, field in enumerate(fields)
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("Form field must occur exactly once")
    index = matches[0]
    name, separator, value = fields[index].partition("=")
    from urllib.parse import quote

    fields[index] = name + "=" + value + quote(payload, safe="") if separator else name + "=" + quote(payload, safe="")
    changed = "&".join(fields).encode("ascii")
    if len(changed) > MAX_REPLAY_BODY:
        raise ValueError("Mutated body exceeds replay limit")
    return changed


def plan_observed_body(private_exchange: bytes, *, parameter: str,
                       allowed_origins: list[str], payload: str = "'") -> tuple[str, str, bytes, bytes]:
    """Validate a captured POST and change one JSON or form field."""
    try:
        captured = json.loads(private_exchange)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid captured exchange") from exc
    if not isinstance(captured, dict) or captured.get("method") != "POST" or captured.get("resource_type") not in ("xhr", "fetch"):
        raise ValueError("Body probe requires a browser-observed POST XHR/fetch exchange")
    if captured.get("graphql_operation_type") not in (None, "", "query"):
        raise ValueError("GraphQL mutation or subscription needs a disposable workflow proof")
    url = captured.get("url")
    if not isinstance(url, str) or not isinstance(parameter, str):
        raise ValueError("Observed URL and parameter name are required")
    assert_in_scope(url, allowed_origins)
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        raise ValueError("Body replay does not accept query or fragment values")
    mime = captured.get("request_content_type")
    json_body = mime == "application/json" or (isinstance(mime, str) and mime.endswith("+json"))
    if not json_body and mime != "application/x-www-form-urlencoded":
        raise ValueError("Body replay requires captured JSON or form content type")
    try:
        body = base64.b64decode(captured.get("request_body_base64", ""), validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ValueError("Invalid captured request body") from exc
    if not body or len(body) > MAX_REPLAY_BODY:
        raise ValueError("Captured body is empty or exceeds replay limit")
    if not isinstance(payload, str) or not 0 < len(payload) <= 300:
        raise ValueError("A bounded body probe payload is required")
    changed = (_mutate_json(body, parameter, payload)
               if json_body else _mutate_form(body, parameter, payload))
    return url, mime, body, changed


def plan_sql_error_form(private_exchange: bytes, *, parameter: str,
                        allowed_origins: list[str]) -> tuple[str, str, bytes, bytes, bytes]:
    """Plan a bounded error proof from one ordinary, captured form value."""
    url, mime, body, quote_body = plan_observed_body(
        private_exchange, parameter=parameter, allowed_origins=allowed_origins,
    )
    if mime != "application/x-www-form-urlencoded":
        raise ValueError("POST SQL error proof currently requires a captured form")
    raw = body.decode("ascii")
    matches = [field.partition("=")[2] for field in raw.split("&")
               if unquote_plus(field.partition("=")[0]) == parameter]
    if len(matches) != 1 or not _SAFE_SQL_VALUE.fullmatch(unquote_plus(matches[0])):
        raise ValueError("POST SQL error proof requires an ordinary observed form value")
    _, _, _, escaped_body = plan_observed_body(
        private_exchange, parameter=parameter, allowed_origins=allowed_origins,
        payload="''",
    )
    return url, mime, body, quote_body, escaped_body


def _observe_post(url: str, mime: str, body: bytes,
                  allowed_origins: list[str], storage_state: dict | None,
                  reflection_text: str = "", replay_headers: dict[str, str] | None = None,
                  timeout: int = 15) -> dict:
    assert_in_scope(url, allowed_origins)
    headers = {"Accept": "application/json, text/html;q=0.9, */*;q=0.8", "Content-Type": mime}
    headers.update(_replay_headers(replay_headers, expected_origin=origin(url)))
    cookies = _cookie_header(storage_state, url)
    if cookies:
        headers["Cookie"] = cookies
    request = Request(url, data=body, headers=headers, method="POST")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        data = response.read(MAX_BODY + 1)
        truncated = len(data) > MAX_BODY
        data = data[:MAX_BODY]
        result = {
            "status": response.status,
            "content_type": response.headers.get("Content-Type", "").split(";", 1)[0].lower()[:100],
            "bytes_captured": len(data), "truncated": truncated,
            "body_sha256": hashlib.sha256(data).hexdigest(),
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "sql_error_family": _sql_error_family(data),
            "redirected": bool(response.headers.get("Location", "")),
        }
        if reflection_text:
            page = data.decode("utf-8", errors="replace")
            result["raw_reflection"] = reflection_text in page
            result["html_encoded_reflection"] = html.escape(reflection_text) in page
        return result


def probe_observed_body(url: str, mime: str, body: bytes, changed_body: bytes, *,
                        parameter: str, allowed_origins: list[str], storage_state: dict | None,
                        replay_headers: dict[str, str] | None = None) -> dict:
    baseline = _observe_post(url, mime, body, allowed_origins, storage_state, replay_headers=replay_headers)
    probe = _observe_post(url, mime, changed_body, allowed_origins, storage_state, replay_headers=replay_headers)
    parts = urlsplit(url)
    return {
        "operation": "body_probe", "target": origin(url) + (parts.path or "/"),
        "method": "POST", "parameter": parameter,
        "location": "json" if mime == "application/json" or mime.endswith("+json") else "form",
        "technique": "append_single_quote", "requests_sent": 2,
        "identity_transport": "named_identity_cookies_only",
        "replay_header_names": sorted(_replay_headers(replay_headers, expected_origin=origin(url))),
        "baseline": baseline, "probe": probe,
        "changed": baseline["status"] != probe["status"] or baseline["body_sha256"] != probe["body_sha256"],
        "sql_error_signal": bool(probe.get("sql_error_family") and not baseline.get("sql_error_family")),
        "inconclusive": any(row["truncated"] or row["redirected"] or row["status"] in (401, 403)
                            for row in (baseline, probe)),
        "finding": False,
    }


def post_sql_error_proof_valid(result: dict) -> bool:
    """Require repeated DB-specific errors with stable clean and escape controls."""
    if (result.get("operation") != "sqli_error_form"
            or result.get("proof_recipe") != "post_form_error_v1"
            or result.get("method") != "POST" or result.get("location") != "form"
            or not result.get("target") or not result.get("parameter")
            or not _DIGEST.fullmatch(str(result.get("baseline_request_sha256", "")))
            or result.get("requests_sent") != len(SQL_ERROR_CHECK_ORDER)):
        return False
    checks = result.get("checks")
    if not isinstance(checks, dict) or any(not isinstance(checks.get(key), dict)
                                            for key in SQL_ERROR_CHECK_ORDER):
        return False
    rows = {key: checks[key] for key in SQL_ERROR_CHECK_ORDER}
    if any(row.get("truncated") is not False or row.get("redirected") is not False
           or not _DIGEST.fullmatch(str(row.get("body_sha256", "")))
           or not _DIGEST.fullmatch(str(row.get("request_sha256", "")))
           or not isinstance(row.get("bytes_captured"), int)
           for row in rows.values()):
        return False
    baseline_digest = result["baseline_request_sha256"]
    quote_digest = rows["quote_first"]["request_sha256"]
    escape_digest = rows["escaped_quote"]["request_sha256"]
    if (rows["baseline_first"]["request_sha256"] != baseline_digest
            or rows["baseline_last"]["request_sha256"] != baseline_digest
            or rows["quote_second"]["request_sha256"] != quote_digest
            or len({baseline_digest, quote_digest, escape_digest}) != 3):
        return False
    normal = (rows["baseline_first"], rows["escaped_quote"], rows["baseline_last"])
    errors = (rows["quote_first"], rows["quote_second"])
    if any(row.get("status") != 200 or row.get("sql_error_family") for row in normal):
        return False
    family = errors[0].get("sql_error_family")
    if (family not in {"postgresql", "mysql", "sqlite", "oracle", "sqlserver"}
            or family != errors[1].get("sql_error_family")
            or errors[0].get("status") not in {200, 500, 501, 502, 503, 504}
            or errors[0].get("status") != errors[1].get("status")):
        return False
    if (not normal[0].get("content_type")
            or any(row.get("content_type") != normal[0]["content_type"] for row in normal)
            or not errors[0].get("content_type")
            or errors[0]["content_type"] != errors[1].get("content_type")):
        return False
    stable = lambda a, b: abs(a - b) <= max(64, max(a, b) // 100)
    return (stable(normal[0]["bytes_captured"], normal[2]["bytes_captured"])
            and stable(errors[0]["bytes_captured"], errors[1]["bytes_captured"]))


def probe_sql_error_form(url: str, mime: str, body: bytes, quote_body: bytes,
                         escaped_body: bytes, *, parameter: str,
                         allowed_origins: list[str], storage_state: dict | None,
                         replay_headers: dict[str, str] | None = None,
                         initial: dict | None = None) -> dict:
    """Replay a captured form with five bounded requests; return metadata only."""
    checks = {}
    if initial is not None:
        checks["baseline_first"] = initial["baseline"]
        checks["quote_first"] = initial["probe"]
    else:
        checks["baseline_first"] = _observe_post(
            url, mime, body, allowed_origins, storage_state, replay_headers=replay_headers,
            timeout=8,
        )
        checks["quote_first"] = _observe_post(
            url, mime, quote_body, allowed_origins, storage_state, replay_headers=replay_headers,
            timeout=8,
        )
    for key, request_body in (("escaped_quote", escaped_body),
                              ("quote_second", quote_body), ("baseline_last", body)):
        checks[key] = _observe_post(
            url, mime, request_body, allowed_origins, storage_state,
            replay_headers=replay_headers, timeout=8,
        )
    parts = urlsplit(url)
    result = {
        "operation": "sqli_error_form", "proof_recipe": "post_form_error_v1",
        "target": origin(url) + (parts.path or "/"), "method": "POST",
        "location": "form", "parameter": parameter,
        "baseline_request_sha256": hashlib.sha256(body).hexdigest(),
        "requests_sent": len(SQL_ERROR_CHECK_ORDER),
        "identity_transport": "named_identity_cookies_only",
        "replay_header_names": sorted(_replay_headers(replay_headers, expected_origin=origin(url))),
        "checks": checks,
        "finding": False,
    }
    result["proof_confirmed"] = post_sql_error_proof_valid(result)
    return result


def probe_observed_body_reflection(
    url: str, mime: str, body: bytes, changed_body: bytes, *,
    parameter: str, payload: str, allowed_origins: list[str],
    storage_state: dict | None, replay_headers: dict[str, str] | None = None,
) -> dict:
    """Check a captured POST for reflection; browser execution is still required."""
    baseline = _observe_post(url, mime, body, allowed_origins, storage_state, replay_headers=replay_headers)
    probe = _observe_post(url, mime, changed_body, allowed_origins, storage_state,
                          reflection_text=payload, replay_headers=replay_headers)
    parts = urlsplit(url)
    inconclusive = any(row["truncated"] or row["redirected"] or row["status"] in (401, 403)
                       for row in (baseline, probe))
    return {
        "operation": "body_xss_reflection", "target": origin(url) + (parts.path or "/"),
        "method": "POST", "parameter": parameter,
        "location": "json" if mime == "application/json" or mime.endswith("+json") else "form",
        "requests_sent": 2, "baseline": baseline, "probe": probe,
        "replay_header_names": sorted(_replay_headers(replay_headers, expected_origin=origin(url))),
        "reflection_detected": bool(probe.get("raw_reflection") or probe.get("html_encoded_reflection")),
        "raw_html_reflection": bool(probe.get("raw_reflection") and probe["content_type"] == "text/html"),
        "inconclusive": inconclusive,
        "proof_confirmed": False, "finding": False,
        "next_test": "Reproduce execution in the target browser context",
    }
