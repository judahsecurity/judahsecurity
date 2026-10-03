"""Operator-authorized, two-request POST body comparison from browser evidence.

The response difference is exploratory. It is never a finding proof.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from urllib.error import HTTPError
from urllib.parse import unquote_plus, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .browser import assert_in_scope, origin
from .browser_traffic import MAX_BODY_BYTES
from .http_observe import MAX_BODY, _NoRedirect, _cookie_header


MAX_REPLAY_BODY = min(MAX_BODY_BYTES, 64 * 1024)


def _mutate_json(data: bytes, pointer: str) -> bytes:
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
    setter(str(value) + "'")
    changed = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    if len(changed) > MAX_REPLAY_BODY:
        raise ValueError("Mutated body exceeds replay limit")
    return changed


def _mutate_form(data: bytes, parameter: str) -> bytes:
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
    fields[index] = name + "=" + value + "%27" if separator else name + "=%27"
    changed = "&".join(fields).encode("ascii")
    if len(changed) > MAX_REPLAY_BODY:
        raise ValueError("Mutated body exceeds replay limit")
    return changed


def plan_observed_body(private_exchange: bytes, *, parameter: str,
                       allowed_origins: list[str]) -> tuple[str, str, bytes, bytes]:
    """Validate a captured POST and change one JSON or form field."""
    try:
        captured = json.loads(private_exchange)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid captured exchange") from exc
    if not isinstance(captured, dict) or captured.get("method") != "POST" or captured.get("resource_type") not in ("xhr", "fetch"):
        raise ValueError("Body probe requires a browser-observed POST XHR/fetch exchange")
    url = captured.get("url")
    if not isinstance(url, str) or not isinstance(parameter, str):
        raise ValueError("Observed URL and parameter name are required")
    assert_in_scope(url, allowed_origins)
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        raise ValueError("Body replay does not accept query or fragment values")
    mime = captured.get("request_content_type")
    if mime not in ("application/json", "application/x-www-form-urlencoded"):
        raise ValueError("Body replay requires captured JSON or form content type")
    try:
        body = base64.b64decode(captured.get("request_body_base64", ""), validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ValueError("Invalid captured request body") from exc
    if not body or len(body) > MAX_REPLAY_BODY:
        raise ValueError("Captured body is empty or exceeds replay limit")
    changed = _mutate_json(body, parameter) if mime == "application/json" else _mutate_form(body, parameter)
    return url, mime, body, changed


def _observe_post(url: str, mime: str, body: bytes,
                  allowed_origins: list[str], storage_state: dict | None) -> dict:
    assert_in_scope(url, allowed_origins)
    headers = {"Accept": "application/json, text/html;q=0.9, */*;q=0.8", "Content-Type": mime}
    cookies = _cookie_header(storage_state, url)
    if cookies:
        headers["Cookie"] = cookies
    request = Request(url, data=body, headers=headers, method="POST")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        data = response.read(MAX_BODY + 1)
        truncated = len(data) > MAX_BODY
        data = data[:MAX_BODY]
        return {
            "status": response.status,
            "content_type": response.headers.get("Content-Type", "").split(";", 1)[0].lower()[:100],
            "bytes_captured": len(data), "truncated": truncated,
            "body_sha256": hashlib.sha256(data).hexdigest(),
            "redirected": bool(response.headers.get("Location", "")),
        }


def probe_observed_body(url: str, mime: str, body: bytes, changed_body: bytes, *,
                        parameter: str, allowed_origins: list[str], storage_state: dict | None) -> dict:
    baseline = _observe_post(url, mime, body, allowed_origins, storage_state)
    probe = _observe_post(url, mime, changed_body, allowed_origins, storage_state)
    parts = urlsplit(url)
    return {
        "operation": "body_probe", "target": origin(url) + (parts.path or "/"),
        "method": "POST", "parameter": parameter,
        "location": "json" if mime == "application/json" else "form",
        "technique": "append_single_quote", "requests_sent": 2,
        "identity_transport": "named_identity_cookies_only",
        "baseline": baseline, "probe": probe,
        "changed": baseline["status"] != probe["status"] or baseline["body_sha256"] != probe["body_sha256"],
        "inconclusive": any(row["truncated"] or row["redirected"] or row["status"] in (401, 403)
                            for row in (baseline, probe)),
        "finding": False,
    }
