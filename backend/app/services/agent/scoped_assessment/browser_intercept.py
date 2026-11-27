"""Browser XSS proof for inputs a GET navigation cannot carry.

``check_xss`` navigates to a URL; it can only place a payload in the query or
the fragment. Header, cookie, request-body and path-segment inputs reach the
server inside one specific request. Here the rendering page is loaded in
Chromium and that one outgoing request is intercepted (``context.route``) and
re-sent with only the one input changed:

* ``document`` mode: the rendering page *is* the cell URL. The top-level
  navigation is intercepted. Header/cookie/path inputs keep the GET; body
  inputs (``body_form``/``body_json``/``body_xml``) are sent as POST with a
  one-field body (the operator approved that path in ``body_replay_paths``).
* ``fetch`` mode: a separate same-origin rendering page (no query, no
  fragment) issues a fetch/XHR to the cell's endpoint. The first request whose
  method, exact path and (for bodies) content type match is intercepted; the
  input is changed inside the page's own request (header value, one cookie
  pair, one form/JSON/XML field located by span, or the exact path segment),
  every other byte of the URL and body stays as the page built it.

The mutated request is re-sent with ``route.fetch`` (``max_redirects=0``) and
its response handed back to the page with ``route.fulfill``: the response
the page renders is the server's real answer to the mutated request, and a
redirect is never followed (a 3xx is refused and the proof is inconclusive).
The request keeps the browser's own header set (``request.all_headers()``),
cookie jar and body except for the one input.

Proof is the same standard as the in-browser XHR lane: a dialog carrying the
fresh nonce after the mutated response arrived and rendered. Reflection
alone, a dialog without the nonce, a dialog before the mutated response, or
a mutated request that was never sent are inconclusive.

Safety rules (on top of ``intent_request``'s):

* exact origin for every request, WebSockets included; anything else aborted;
* only GET/HEAD/OPTIONS on discovery-safe paths pass besides the one matched
  request; any other POST is aborted;
* headers: never Host, Cookie, Authorization, framing headers, Origin,
  X-Forwarded-Host, Forwarded or credential-like names;
* cookies: never a credential-like name, never an HttpOnly cookie of the
  identity's session jar or of the live browser jar;
* bodies: POST only (PUT/PATCH/DELETE body XSS is unsupported);
* path: GET only; the receipt records the cell's path template and the
  mutated segment index so it binds back to the cell.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
from json.decoder import scanstring
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlsplit, urlunsplit

from .browser import NONCE_MARKER, _storage_for_origin, assert_in_scope, origin
from .browser_runtime import launch_options

INTERCEPT_LOCATIONS = frozenset({"header", "cookie", "body_form", "body_json", "body_xml",
                                 "path"})
BODY_CONTENT_TYPES = {
    "body_form": "application/x-www-form-urlencoded",
    "body_json": "application/json",
    "body_xml": "application/xml",
}
MAX_BODY = 64 * 1024
MAX_PAYLOAD = 300
MAX_REQUESTS = 60
# Request fields a receipt pair must agree on (hunter vs verifier).
BINDING_FIELDS = ("intercept_mode", "target_template", "request_match", "sent_method",
                  "input_location", "input_parameter", "payload_template", "path_template",
                  "path_segment_index", "body_content_type")
# Characters a cookie value cannot carry raw; everything else is sent as is.
_COOKIE_SAFE = "!#$&'()*+-./:<=>?@[]^_`{|}~"


class InterceptError(ValueError):
    """The matched request could not be changed in exactly one input."""


def _ir():
    from . import intent_request

    return intent_request


def intercept_shape_error(method: str, location: str, parameter: str) -> str:
    """Empty when an intercepted browser request can carry this XSS input."""
    ir = _ir()
    method = str(method or "GET").upper()
    if location not in INTERCEPT_LOCATIONS:
        return "location_unsupported"
    if method in ir.WRITE_METHODS:
        # Body/header XSS on a record write would need Prowl's own record in a
        # browser flow; not built, so it stays open instead of touching data.
        return "xss_write_method_unsupported"
    if method not in {"GET", "POST"}:
        return "method_unsupported"
    if location in BODY_CONTENT_TYPES and method != "POST":
        return "body_requires_post"
    if location == "path" and method != "GET":
        return "path_xss_requires_get"
    if not parameter:
        return "parameter_required"
    if location == "header":
        if (not ir._TOKEN.fullmatch(parameter) or ir._credential_header(parameter)
                or parameter.lower().startswith(("sec-", "proxy-"))):
            return "protected_header"
    elif location == "cookie":
        if not ir._TOKEN.fullmatch(parameter) or ir._credential_cookie(parameter):
            return "protected_cookie"
    elif location == "body_json":
        try:
            ir._json_tokens(parameter)
        except ir.UnsupportedShape as exc:
            return str(exc)
    elif location == "body_xml":
        try:
            ir._xml_tokens(parameter)
        except ir.UnsupportedShape as exc:
            return str(exc)
    elif location == "body_form":
        if not ir._FIELD.fullmatch(parameter):
            return "field_unsupported"
    elif location == "path":
        if not (parameter.isdecimal() and int(parameter) < ir.MAX_PATH_SEGMENTS
                or not parameter.isdecimal() and ir._SEGMENT.fullmatch(parameter)
                and parameter not in {".", ".."}):
            return "path_segment_unsupported"
    return ""


def _document_body(location: str, parameter: str, value: str) -> bytes:
    ir = _ir()
    if location == "body_form":
        return (quote(parameter, safe="") + "=" + quote(value, safe="")).encode()
    if location == "body_json":
        return ir._json_body(parameter, value)
    return ir._xml_body(parameter, value)


def plan_intercept(*, method: str, url: str, location: str, parameter: str,
                   payload_template: str, page_url: str = "",
                   state: Optional[dict] = None) -> Dict[str, Any]:
    """The request match and the one-input mutation for a cell, without a nonce.

    ``url`` is the cell URL (an intent may carry query fields; they are kept).
    ``page_url`` empty or equal to it: document mode. Otherwise the rendering
    page must be a same-origin exact path (no query, no fragment) different
    from the endpoint: fetch mode.
    """
    from .browser_actions import allowed_discovery_path

    ir = _ir()
    method = str(method or "GET").upper()
    reason = intercept_shape_error(method, location, parameter)
    if reason:
        raise ir.UnsupportedShape(reason)
    if (not isinstance(payload_template, str) or payload_template.count(NONCE_MARKER) != 1
            or len(payload_template) > MAX_PAYLOAD
            or any(ch in payload_template for ch in "\r\n\x00")):
        raise ValueError("A bounded payload with one nonce marker is required")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or len(url) > ir.MAX_URL:
        raise ir.UnsupportedShape("url_unsupported")
    cell_url = urlunsplit(parts._replace(fragment=""))
    cell_path = parts.path or "/"
    if not allowed_discovery_path(cell_path):
        raise ir.UnsupportedShape("unsafe_path")
    page = page_url or cell_url
    page_parts = urlsplit(page)
    if page_parts.fragment or origin(page) != origin(cell_url):
        raise ir.UnsupportedShape("render_page_unsupported")
    mode = "document" if page == cell_url else "fetch"
    if mode == "fetch":
        if (page_parts.query or (page_parts.path or "/") == cell_path
                or not allowed_discovery_path(page_parts.path or "/")
                or len(page) > ir.MAX_URL):
            raise ir.UnsupportedShape("render_page_unsupported")
        if parts.query:
            # The page builds the fetch URL itself; an intent query cannot be
            # matched byte for byte, so fetch mode needs a bare endpoint.
            raise ir.UnsupportedShape("fetch_endpoint_query_unsupported")
    if location == "cookie" and ir._protected_identity_cookie(state, parameter):
        raise ir.UnsupportedShape("protected_cookie")
    spec: Dict[str, Any] = {
        "intercept_mode": mode,
        "target_template": page,
        "request_url": cell_url,
        "request_match": {
            "resource_type": "document" if mode == "document" else "xhr_fetch",
            # A navigation is always a GET; body locations re-send it as POST.
            "method": "GET" if mode == "document" else method,
            "path": cell_path,
            "content_type": (BODY_CONTENT_TYPES[location]
                             if mode == "fetch" and location in BODY_CONTENT_TYPES else ""),
        },
        "sent_method": method,
        "input_location": location,
        "input_parameter": parameter,
        "payload_template": payload_template,
        "path_template": "",
        "path_segment_index": None,
        "body_content_type": BODY_CONTENT_TYPES.get(location, ""),
    }
    if location == "path":
        spec["path_template"] = cell_path
        spec["path_segment_index"] = ir.path_segment_index(cell_url, parameter)
    if location in BODY_CONTENT_TYPES and mode == "document":
        body = _document_body(location, parameter, payload_template)
        if len(body) > MAX_BODY or body.count(NONCE_MARKER.encode()) != 1:
            raise ir.UnsupportedShape("body_unsupported")
    return spec


# ------------------------------------------------------------------ mutation

def _cookie_value(value: str) -> str:
    return quote(value, safe=_COOKIE_SAFE)


def _skip_ws(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\n\r":
        index += 1
    return index


_JSON_SCALAR = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null")


def _json_scan(text: str, index: int, depth: int = 0) -> Tuple[int, Any]:
    """End of the JSON value at ``index`` and, for objects, its members."""
    if depth > 16 or index >= len(text):
        raise InterceptError("json_unsupported")
    char = text[index]
    if char == '"':
        _, end = scanstring(text, index + 1)
        return end, None
    if char == "{":
        members = []
        index = _skip_ws(text, index + 1)
        if text[index:index + 1] == "}":
            return index + 1, members
        while True:
            if text[index:index + 1] != '"':
                raise InterceptError("json_unsupported")
            key, index = scanstring(text, index + 1)
            index = _skip_ws(text, index)
            if text[index:index + 1] != ":":
                raise InterceptError("json_unsupported")
            start = _skip_ws(text, index + 1)
            end, children = _json_scan(text, start, depth + 1)
            members.append((key, start, end, children))
            index = _skip_ws(text, end)
            if text[index:index + 1] == ",":
                index = _skip_ws(text, index + 1)
                continue
            if text[index:index + 1] == "}":
                return index + 1, members
            raise InterceptError("json_unsupported")
    if char == "[":
        index = _skip_ws(text, index + 1)
        if text[index:index + 1] == "]":
            return index + 1, None
        while True:
            end, _ = _json_scan(text, index, depth + 1)
            index = _skip_ws(text, end)
            if text[index:index + 1] == ",":
                index = _skip_ws(text, index + 1)
                continue
            if text[index:index + 1] == "]":
                return index + 1, None
            raise InterceptError("json_unsupported")
    match = _JSON_SCALAR.match(text, index)
    if not match:
        raise InterceptError("json_unsupported")
    return match.end(), None


def _replace_json_field(body: bytes, parameter: str, value: str) -> bytes:
    """Replace one string/number member's bytes; every other byte is kept."""
    ir = _ir()
    tokens = ir._json_tokens(parameter)
    try:
        text = body.decode("utf-8")
        json.loads(text)  # well-formed before any span is trusted
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InterceptError("json_unsupported") from exc
    start = _skip_ws(text, 0)
    if text[start:start + 1] != "{":
        raise InterceptError("json_field_missing")
    end, members = _json_scan(text, start)
    if _skip_ws(text, end) != len(text):
        raise InterceptError("json_unsupported")
    span = None
    for depth, token in enumerate(tokens):
        found = [row for row in (members or []) if row[0] == token]
        if len(found) != 1:
            raise InterceptError("json_field_missing" if not found else "json_field_ambiguous")
        _key, value_start, value_end, children = found[0]
        if depth < len(tokens) - 1:
            if text[value_start] != "{":
                raise InterceptError("json_field_missing")
            members = children
        else:
            span = (value_start, value_end)
    if span is None or text[span[0]] in "{[tfn":
        raise InterceptError("json_field_not_scalar")
    changed = text[:span[0]] + json.dumps(value, ensure_ascii=False) + text[span[1]:]
    return changed.encode("utf-8")


def _replace_xml_field(body: bytes, parameter: str, value: str) -> bytes:
    """Replace the text of one leaf element located by its element path."""
    import xml.etree.ElementTree as ET

    ir = _ir()
    tokens = ir._xml_tokens(parameter)
    if b"<!" in body or b"&" in body.replace(b"&amp;", b"").replace(b"&lt;", b"").replace(
            b"&gt;", b"").replace(b"&quot;", b"").replace(b"&apos;", b""):
        # No DOCTYPE, entity, CDATA or comment handling: refuse rather than guess.
        raise InterceptError("xml_markup_unsupported")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise InterceptError("xml_unsupported") from exc

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    node = root
    if local(root.tag) != tokens[0]:
        raise InterceptError("xml_field_missing")
    for token in tokens[1:]:
        children = [child for child in node if local(child.tag) == token]
        if len(children) != 1:
            raise InterceptError("xml_field_missing" if not children else "xml_field_ambiguous")
        node = children[0]
    if len(node):
        raise InterceptError("xml_field_not_leaf")
    leaf = tokens[-1].encode()
    opens = list(re.finditer(rb"<(?:[A-Za-z_][\w.-]*:)?" + re.escape(leaf) + rb"(?=[\s>/])[^>]*>",
                             body))
    if len(opens) != 1 or opens[0].group(0).endswith(b"/>"):
        raise InterceptError("xml_field_ambiguous")
    start = opens[0].end()
    close = body.find(b"</", start)
    if close < 0 or b"<" in body[start:close]:
        raise InterceptError("xml_unsupported")
    return body[:start] + ir._xml_escape(value).encode() + body[close:]


def _replace_form_field(body: bytes, parameter: str, value: str) -> bytes:
    from .body_probe import _mutate_form

    try:
        return _mutate_form(body, parameter, value, replace=True)
    except ValueError as exc:
        raise InterceptError("form_field_missing") from exc


def mutate_request(spec: Dict[str, Any], *, url: str, method: str, headers: Dict[str, str],
                   body: Optional[bytes], payload: str) -> Tuple[str, str, Dict[str, str], Optional[bytes]]:
    """(url, method, headers, body) of the matched request with only the input changed.

    ``headers`` are the request's own lower-case header set. ``payload`` is
    the template with the nonce in place of the marker.
    """
    location = spec["input_location"]
    parameter = spec["input_parameter"]
    headers = dict(headers)
    if any(ch in payload for ch in "\r\n\x00") or len(payload) > MAX_PAYLOAD + 64:
        raise InterceptError("payload_unsupported")
    if location == "header":
        names = [name for name in headers if name.lower() == parameter.lower()]
        for name in names:
            headers.pop(name)
        headers[parameter] = payload
        return url, method, headers, body
    if location == "cookie":
        raw = next((value for name, value in headers.items() if name.lower() == "cookie"), "")
        pairs = [pair for pair in (raw.split(";") if raw else []) if pair.strip()]
        found = [i for i, pair in enumerate(pairs) if pair.strip().partition("=")[0] == parameter]
        if len(found) > 1:
            raise InterceptError("cookie_ambiguous")
        pair = f"{parameter}={_cookie_value(payload)}"
        if found:
            pairs[found[0]] = (" " if pairs[found[0]].startswith(" ") else "") + pair
        else:
            pairs.append((" " if pairs else "") + pair)
        for name in [name for name in headers if name.lower() == "cookie"]:
            headers.pop(name)
        headers["cookie"] = ";".join(pairs)
        return url, method, headers, body
    if location == "path":
        parts = urlsplit(url)
        if (parts.path or "/") != spec["path_template"]:
            raise InterceptError("path_template_mismatch")
        segments = (parts.path or "/").split("/")
        index = spec["path_segment_index"]
        if not isinstance(index, int) or not 0 < index < len(segments) or not segments[index]:
            raise InterceptError("path_segment_missing")
        segments[index] = quote(payload, safe="")
        return urlunsplit(parts._replace(path="/".join(segments))), method, headers, body
    content_type = BODY_CONTENT_TYPES[location]
    if spec["intercept_mode"] == "document":
        for name in [name for name in headers if name.lower() == "content-type"]:
            headers.pop(name)
        headers["content-type"] = content_type
        return url, "POST", headers, _document_body(location, parameter, payload)
    live = next((value for name, value in headers.items() if name.lower() == "content-type"), "")
    mime = live.split(";", 1)[0].strip().lower()
    if not (mime == content_type or location == "body_json" and mime.endswith("+json")
            or location == "body_xml" and mime == "text/xml"):
        raise InterceptError("content_type_mismatch")
    if not body or len(body) > MAX_BODY or NONCE_MARKER.encode() in body:
        raise InterceptError("body_unsupported")
    if location == "body_form":
        changed = _replace_form_field(body, parameter, payload)
    elif location == "body_json":
        changed = _replace_json_field(body, parameter, payload)
    else:
        changed = _replace_xml_field(body, parameter, payload)
    if len(changed) > MAX_BODY:
        raise InterceptError("body_unsupported")
    return url, method, headers, changed


def request_matches(spec: Dict[str, Any], *, url: str, method: str, resource_type: str,
                    content_type: str = "") -> bool:
    match = spec["request_match"]
    parts = urlsplit(url)
    if match["resource_type"] == "document":
        return (resource_type == "document" and method.upper() == "GET"
                and url == spec["request_url"])
    if resource_type not in {"xhr", "fetch"} or method.upper() != match["method"]:
        return False
    if (parts.path or "/") != match["path"] or parts.fragment:
        return False
    if match["content_type"]:
        mime = content_type.split(";", 1)[0].strip().lower()
        wanted = match["content_type"]
        return (mime == wanted or wanted == "application/json" and mime.endswith("+json")
                or wanted == "application/xml" and mime == "text/xml")
    return True


# ------------------------------------------------------------------ receipts

def receipt_valid(row: Any) -> bool:
    """A self-consistent executed intercept receipt (one actor)."""
    if not isinstance(row, dict) or row.get("operation") != "check_intercept_xss":
        return False
    location = row.get("input_location")
    match = row.get("request_match")
    if (location not in INTERCEPT_LOCATIONS or not isinstance(match, dict)
            or row.get("intercept_mode") not in {"document", "fetch"}
            or match.get("resource_type") != ("document" if row["intercept_mode"] == "document"
                                              else "xhr_fetch")
            or not isinstance(match.get("path"), str) or not match["path"].startswith("/")
            or row.get("sent_method") not in {"GET", "POST"}
            or intercept_shape_error(row["sent_method"], location,
                                     str(row.get("input_parameter") or ""))
            or str(row.get("payload_template") or "").count(NONCE_MARKER) != 1
            or not row.get("nonce")
            or row.get("executed") is not True
            or row.get("intercept_mutated") is not True
            or row.get("mutated_response_seen") is not True
            or row.get("mutated_redirect_refused") is not False
            or not isinstance(row.get("mutated_status"), int)
            or 300 <= row["mutated_status"] < 400):
        return False
    if location == "path":
        index = row.get("path_segment_index")
        if (row.get("path_template") != match["path"] or not isinstance(index, int)
                or isinstance(index, bool) or index < 1):
            return False
        try:
            if _ir().path_segment_index(
                    "https://bound.invalid" + row["path_template"],
                    str(row["input_parameter"])) != index:
                return False
        except ValueError:
            return False
    elif row.get("path_template") or row.get("path_segment_index") is not None:
        return False
    if location in BODY_CONTENT_TYPES:
        if (row.get("sent_method") != "POST"
                or row.get("body_content_type") != BODY_CONTENT_TYPES[location]):
            return False
    return True


def pair_valid(first: Any, second: Any) -> bool:
    """Hunter and verifier replayed the same interception with distinct nonces."""
    return (receipt_valid(first) and receipt_valid(second)
            and first["nonce"] != second["nonce"]
            and all(first.get(key) == second.get(key) for key in BINDING_FIELDS)
            and first.get("coverage_cell_id") == second.get("coverage_cell_id"))


# ------------------------------------------------------------------ browser

async def check_intercept_xss(spec: Dict[str, Any], *, allowed_origins: list,
                              storage_state: Optional[dict] = None
                              ) -> Tuple[Dict[str, Any], Optional[bytes]]:
    """Load the rendering page, change the one input in the matched request."""
    from playwright.async_api import async_playwright

    from .browser import REFLECTION_CONTEXT_JS
    from .browser_actions import allowed_discovery_path

    page_url = spec["target_template"]
    assert_in_scope(page_url, allowed_origins)
    assert_in_scope(spec["request_url"], allowed_origins)
    expected_origin = origin(page_url)
    nonce = secrets.token_hex(8)
    payload = spec["payload_template"].replace(NONCE_MARKER, nonce)
    state: Dict[str, Any] = {
        "mutated": False, "request": None, "response_seen": False, "status": None,
        "redirect_refused": False, "error": "", "blocked": 0, "seen": 0,
        "unchanged_sha256": "", "sent_sha256": "",
    }
    dialogs: list = []
    response_dialogs: list = []

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(**launch_options())
        try:
            context_args = {"service_workers": "block", "ignore_https_errors": False}
            scoped_state = _storage_for_origin(storage_state, page_url)
            if scoped_state:
                context_args["storage_state"] = scoped_state
            context = await browser.new_context(**context_args)

            async def mutate(route, request) -> None:
                if spec["input_location"] == "cookie":
                    jar = await context.cookies(request.url)
                    if any(row.get("name") == spec["input_parameter"] and row.get("httpOnly")
                           for row in jar):
                        raise InterceptError("protected_cookie")
                headers = {name.lower(): value for name, value in
                           (await request.all_headers()).items()
                           if not name.startswith(":")}
                body = request.post_data_buffer
                url, method, changed_headers, changed_body = mutate_request(
                    spec, url=request.url, method=request.method, headers=headers,
                    body=body, payload=payload)
                assert_in_scope(url, allowed_origins)
                if origin(url) != expected_origin:
                    raise InterceptError("origin_changed")
                state["unchanged_sha256"] = hashlib.sha256(
                    (request.method + " " + request.url).encode() + b"\n" + (body or b"")
                ).hexdigest()
                state["sent_sha256"] = hashlib.sha256(
                    (method + " " + url).encode() + b"\n" + (changed_body or b"")).hexdigest()
                state["request"] = request
                state["mutated"] = True
                response = await route.fetch(
                    url=url, method=method, headers=changed_headers,
                    post_data=changed_body, max_redirects=0, timeout=15_000)
                state["status"] = response.status
                if 300 <= response.status < 400:
                    # Never follow: the page would render a different request.
                    state["redirect_refused"] = True
                    await route.abort()
                    return
                await route.fulfill(response=response)

            async def route_request(route):
                request = route.request
                state["seen"] += 1
                try:
                    in_origin = origin(request.url) == expected_origin
                    path = urlsplit(request.url).path or "/"
                    method = request.method.upper()
                    if state["seen"] > MAX_REQUESTS or not in_origin:
                        raise InterceptError("blocked")
                    if state["redirect_refused"]:
                        # After a refused redirect the probe is over. Some browser
                        # builds retry the aborted navigation on their own; that
                        # retry (and its redirect) must not reach the target.
                        raise InterceptError("blocked")
                    if not state["mutated"] and request_matches(
                            spec, url=request.url, method=method,
                            resource_type=request.resource_type,
                            content_type=request.headers.get("content-type", "")):
                        try:
                            await mutate(route, request)
                        except (InterceptError, ValueError) as exc:
                            state["error"] = str(exc)[:100] or type(exc).__name__
                            state["blocked"] += 1
                            await route.abort()
                        return
                    allowed = method in {"GET", "HEAD", "OPTIONS"} and allowed_discovery_path(path)
                except (InterceptError, ValueError):
                    allowed = False
                if allowed:
                    await route.continue_()
                else:
                    state["blocked"] += 1
                    await route.abort()

            await context.route("**/*", route_request)
            if not hasattr(context, "route_web_socket"):
                raise RuntimeError("Playwright 1.48+ is required for WebSocket scope control")

            async def route_socket(socket):
                value = socket.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
                try:
                    allowed = origin(value) == expected_origin
                except ValueError:
                    allowed = False
                if allowed:
                    socket.connect_to_server()
                else:
                    state["blocked"] += 1
                    await socket.close()

            await context.route_web_socket("**/*", route_socket)
            page = await context.new_page()

            def record_response(response):
                if state["request"] is not None and response.request is state["request"]:
                    state["response_seen"] = True

            page.on("response", record_response)

            async def accept_dialog(dialog):
                dialogs.append(dialog.message[:200])
                if state["response_seen"]:
                    response_dialogs.append(dialog.message[:200])
                await dialog.dismiss()

            page.on("dialog", lambda dialog: asyncio.create_task(accept_dialog(dialog)))
            navigation_error = ""
            try:
                await page.goto(page_url, wait_until="domcontentloaded", timeout=20_000)
            except Exception as exc:  # aborted document (refused redirect, error)
                navigation_error = type(exc).__name__
            await page.wait_for_timeout(1200)
            if not state["mutated"] and spec["intercept_mode"] == "fetch":
                await page.wait_for_timeout(800)
            final_url = page.url
            if final_url.startswith(("http://", "https://")):
                # An aborted document leaves about:blank or Chromium's error page.
                assert_in_scope(final_url, allowed_origins)
            result: Dict[str, Any] = {
                "operation": "check_intercept_xss",
                **{key: spec[key] for key in (
                    "intercept_mode", "target_template", "request_match", "sent_method",
                    "input_location", "input_parameter", "payload_template",
                    "path_template", "path_segment_index", "body_content_type")},
                "final_origin": origin(final_url) if final_url.startswith("http") else "",
                "final_path": urlsplit(final_url).path or "/",
                "nonce": nonce,
                "intercept_mutated": state["mutated"],
                "mutated_response_seen": state["response_seen"],
                "mutated_status": state["status"],
                "mutated_redirect_refused": state["redirect_refused"],
                "intercept_error": state["error"],
                "navigation_error": navigation_error,
                "unchanged_request_sha256": state["unchanged_sha256"],
                "sent_request_sha256": state["sent_sha256"],
                "browser_requests_seen": state["seen"],
                "blocked_requests": state["blocked"],
                "dialog_count": len(dialogs),
            }
            # Execution: the nonce dialog after the mutated response rendered.
            result["executed"] = bool(
                any(nonce in message for message in response_dialogs)
                and state["mutated"] and state["response_seen"]
                and not state["redirect_refused"]
                and isinstance(state["status"], int) and not 300 <= state["status"] < 400)
            try:
                reflection = await page.evaluate(REFLECTION_CONTEXT_JS, nonce)
                result["reflection_contexts"] = reflection["contexts"]
                result["reflection_observations"] = reflection["observations"]
            except Exception:
                result["reflection_contexts"] = []
                result["reflection_observations"] = []
            try:
                screenshot = await page.screenshot(full_page=True)
            except Exception:
                screenshot = None
            await context.unroute_all(behavior="ignoreErrors")
            await context.close()
            return result, screenshot
        finally:
            await browser.close()
