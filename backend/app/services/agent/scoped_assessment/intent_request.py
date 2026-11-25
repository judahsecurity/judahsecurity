"""Request plans for coverage cells that have no captured baseline.

Intent-backed cells (``planning_graph.add_intent``: operator- or planner-directed
tests on inputs Prowl never observed) and observed header/cookie inputs name a
method, URL, parameter and location, but carry no replayable capture. This
module builds the inert control and the fixed probes for exactly one such
input and sends them. The caller still chooses nothing: values come from the
proof modules (``injection_probe``, the response canaries, the string,
numeric and UNION SQLi recipes, the XSS browser payloads), and every request
here differs from the control only in that one input.

NoSQL (``nosql_requests``) goes beyond bracket/JSON operators only where the
server plausibly turns the input into an object: cookie-parser ``j:`` JSON
cookies, a header whose baseline value is a JSON object/array, XML operator
elements, and string ``$where``/``$regex`` recipes on a path segment.
Baselines for numeric/UNION SQLi and JSON headers (``url_value``,
``captured_value``, operator ``baseline_value``) are chosen by the caller.

Locations: ``query``, ``header``, ``cookie``, ``body_form``, ``body_json``,
``body_xml`` (a slash path of element names, the value XML-escaped in a text
node, never a DOCTYPE), ``path`` (one segment, named by its 0-based index or
its exact current literal; the rest of the path is kept byte for byte) and
``fragment`` (browser XSS only: the server never receives a fragment, so only
a client-side probe can test it).

Shapes this module cannot build exactly raise ``UnsupportedShape``; the caller
leaves the cell open/inconclusive (never ``tested_clean``).

Safety rules enforced here:

* exact origin (``assert_in_scope``) on every request, no redirects followed;
* GET is free; any other method needs ``write_approved=True`` from the caller
  (POST: ``body_replay_paths``; PUT/PATCH/DELETE: a matching
  ``test_record_endpoints`` entry, and the caller retargets every such request
  to a dummy record Prowl created and verified as its own, see
  ``test_records``), else ``ApprovalRequired`` is raised before anything is
  planned;
* header mutation never names Host, Cookie, Authorization, framing headers or
  anything credential-like (``parameter_inventory._CREDENTIAL_HEADER``);
* cookie mutation never names a credential-like cookie and never replaces an
  HttpOnly cookie of the identity's session jar; the identity's other cookies
  are sent unchanged;
* no Authorization header is ever sent (identity state is cookies only).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import quote, unquote, unquote_plus, urljoin, urlsplit, urlunsplit
from urllib.request import Request, build_opener

from app.services.agent.assessment_proxy import assessment_urllib_handlers

from .browser import assert_in_scope
from .http_observe import _NoRedirect, _cookie_header

MAX_BODY = 256 * 1024
MAX_URL = 2048
INJECTION_LOCATIONS = frozenset({"query", "header", "cookie", "body_form", "body_json",
                                 "body_xml", "path"})
SUPPORTED_LOCATIONS: Dict[str, frozenset] = {
    "ssti": INJECTION_LOCATIONS,
    "command_injection": INJECTION_LOCATIONS,
    "path_traversal": INJECTION_LOCATIONS,
    "crlf": INJECTION_LOCATIONS,
    "open_redirect": INJECTION_LOCATIONS,
    # Operator syntax only where the server plausibly builds an object from the
    # input: bracket field names (query/form), JSON bodies, cookie-parser JSON
    # cookies (``j:``), JSON-valued headers (only with a JSON object/array
    # baseline, checked at plan time), XML bodies converted to objects
    # (operator element names), and string-only recipes on one path segment
    # (``nosql_requests``).
    "nosql": INJECTION_LOCATIONS,
    # String Boolean/error/time recipes: the value is a string in every location.
    "sqli": INJECTION_LOCATIONS,
    # Browser nonce execution navigates with GET: only URL parts the browser
    # sends (query) or keeps client-side (fragment) can carry the payload.
    "xss": frozenset({"query", "fragment"}),
}
BODY_LOCATIONS = frozenset({"body_form", "body_json", "body_xml"})
WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
REQUEST_METHODS = frozenset({"GET", "POST"}) | WRITE_METHODS
MAX_PATH_SEGMENTS = 32
_XML_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
_SEGMENT = re.compile(r"[^\x00-\x1f\x7f/?#]{1,128}\Z")
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}\Z")
_FIELD = re.compile(r"[^\x00-\x1f\x7f&=#]{1,80}\Z")
_FORBIDDEN_HEADERS = frozenset({
    "host", "cookie", "cookie2", "authorization", "proxy-authorization", "content-length",
    "content-type", "transfer-encoding", "connection", "keep-alive", "proxy-connection",
    "te", "trailer", "upgrade", "expect", "origin", "x-forwarded-host", "forwarded",
})
_ACCEPT = "text/html, application/json, */*;q=0.8"


class UnsupportedShape(ValueError):
    """This request shape cannot be built exactly; leave the cell open."""


class ApprovalRequired(ValueError):
    """A non-GET request without the operator's exact method/path approval."""

    def __init__(self, reason: str = "operator_approval_required"):
        super().__init__(reason)


@dataclass(frozen=True)
class PlannedRequest:
    method: str
    url: str
    headers: Tuple[Tuple[str, str], ...]
    body: Optional[bytes] = None

    def header(self, name: str) -> str:
        return next((v for k, v in self.headers if k.lower() == name.lower()), "")


def _credential_header(name: str) -> bool:
    from app.services.agent.parameter_inventory import _CREDENTIAL_HEADER

    return name.lower() in _FORBIDDEN_HEADERS or bool(_CREDENTIAL_HEADER.search(name))


def _credential_cookie(name: str) -> bool:
    from app.services.agent.parameter_inventory import is_credential_cookie

    return is_credential_cookie(name)


def _json_tokens(parameter: str) -> list:
    if parameter.startswith("/"):
        tokens = [t.replace("~1", "/").replace("~0", "~") for t in parameter.split("/")[1:]]
    else:
        tokens = [parameter]
    if (not tokens or len(tokens) > 5 or len(parameter) > 200
            or any(not t or len(t) > 64 or re.search(r"[\x00-\x1f\x7f]", t)
                   or t.isdecimal() or t == "*" for t in tokens)):
        raise UnsupportedShape("json_field_unsupported")
    return tokens


def _xml_tokens(parameter: str) -> list:
    tokens = parameter.strip("/").split("/") if parameter.startswith("/") else [parameter]
    if (not tokens or len(tokens) > 5 or len(parameter) > 200
            or any(not _XML_NAME.fullmatch(t) or t.lower().startswith("xml") for t in tokens)):
        raise UnsupportedShape("xml_field_unsupported")
    return tokens


def shape_error(test_type: str, method: str, location: str, parameter: str) -> str:
    """Empty when this module can build the shape exactly, else a fixed reason.

    Approval is a separate check (``ApprovalRequired``): an unapproved write
    is not an unsupported shape, so its cell stays open for the operator.
    """
    if location == "fragment" and test_type != "xss":
        # The server never receives a fragment; only a browser probe can test it.
        return "fragment_client_side_only"
    if location not in SUPPORTED_LOCATIONS.get(test_type, frozenset()):
        return "location_unsupported"
    if method not in REQUEST_METHODS:
        return "method_unsupported"
    if test_type == "xss" and method != "GET":
        return "xss_requires_get_navigation"
    if location in BODY_LOCATIONS and method == "GET":
        return "body_requires_post"
    if not parameter:
        return "parameter_required"
    if location == "header":
        if not _TOKEN.fullmatch(parameter) or _credential_header(parameter):
            return "protected_header"
    elif location == "cookie":
        if not _TOKEN.fullmatch(parameter) or _credential_cookie(parameter):
            return "protected_cookie"
    elif location == "body_json":
        try:
            _json_tokens(parameter)
        except UnsupportedShape as exc:
            return str(exc)
    elif location == "body_xml":
        try:
            _xml_tokens(parameter)
        except UnsupportedShape as exc:
            return str(exc)
    elif location == "path":
        if not (parameter.isdecimal() and int(parameter) < MAX_PATH_SEGMENTS
                or not parameter.isdecimal() and _SEGMENT.fullmatch(parameter)
                and parameter not in {".", ".."}):
            return "path_segment_unsupported"
    elif location == "fragment":
        if parameter != "*" and not _FIELD.fullmatch(parameter):
            return "field_unsupported"
    elif not _FIELD.fullmatch(parameter):
        return "field_unsupported"
    return ""


def path_segment_index(url: str, parameter: str) -> int:
    """Index into ``path.split("/")`` of the one segment ``parameter`` names.

    A decimal parameter is the 0-based position among non-empty segments; any
    other parameter must equal exactly one segment's decoded literal.
    """
    segments = (urlsplit(url).path or "/").split("/")
    if len(segments) > MAX_PATH_SEGMENTS + 1:
        raise UnsupportedShape("path_too_deep")
    positions = [i for i, segment in enumerate(segments) if segment]
    if parameter.isdecimal():
        if int(parameter) >= len(positions):
            raise UnsupportedShape("path_segment_not_found")
        return positions[int(parameter)]
    matches = [i for i in positions if unquote(segments[i]) == parameter]
    if len(matches) != 1:
        raise UnsupportedShape("path_segment_not_found" if not matches
                               else "path_segment_ambiguous")
    return matches[0]


def _set_path_segment(url: str, parameter: str, value: str) -> str:
    text = str(value)
    if not text:
        raise UnsupportedShape("path_value_empty")
    parts = urlsplit(url)
    segments = (parts.path or "/").split("/")
    segments[path_segment_index(url, parameter)] = quote(text, safe="")
    out = urlunsplit(parts._replace(path="/".join(segments), fragment=""))
    if len(out) > MAX_URL:
        raise UnsupportedShape("url_too_long")
    return out


def _xml_escape(text: str) -> str:
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", text):
        raise UnsupportedShape("xml_value_unsupported")
    out = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
           .replace('"', "&quot;").replace("'", "&apos;"))
    # Character references survive XML end-of-line normalisation.
    return out.replace("\r", "&#13;").replace("\n", "&#10;").replace("\t", "&#9;")


def _xml_body(parameter: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise UnsupportedShape("xml_value_unsupported")
    tokens = _xml_tokens(parameter)
    opened = "".join(f"<{t}>" for t in tokens)
    closed = "".join(f"</{t}>" for t in reversed(tokens))
    return ('<?xml version="1.0" encoding="UTF-8"?>' + opened + _xml_escape(value)
            + closed).encode()


_XML_OPERATORS = frozenset({"$ne", "$eq"})


def _xml_operator_body(parameter: str, operator: str, value: Any) -> bytes:
    """``<a><b><$ne>value</$ne></b></a>``: an operator element under the field.

    XML-to-object converters that keep element names as keys turn this into
    ``{"a": {"b": {"$ne": "value"}}}``. ``$`` is not an XML name character,
    so a strict parser rejects the body; the differential then shows nothing
    and the probe is not confirmed (fails safe).
    """
    if operator not in _XML_OPERATORS or not isinstance(value, str):
        raise UnsupportedShape("xml_value_unsupported")
    tokens = _xml_tokens(parameter)
    opened = "".join(f"<{t}>" for t in tokens)
    closed = "".join(f"</{t}>" for t in reversed(tokens))
    return ('<?xml version="1.0" encoding="UTF-8"?>' + opened + f"<{operator}>"
            + _xml_escape(value) + f"</{operator}>" + closed).encode()


def _set_query(url: str, parameter: str, value: str, *, name: str = "") -> str:
    parts = urlsplit(url)
    fields = [f for f in parts.query.split("&") if f] if parts.query else []
    if len(fields) > 40:
        raise UnsupportedShape("query_too_large")
    matches = [i for i, f in enumerate(fields) if unquote_plus(f.split("=", 1)[0]) == parameter]
    if len(matches) > 1:
        raise UnsupportedShape("query_field_ambiguous")
    pair = quote(name or parameter, safe="") + "=" + quote(value, safe="")
    if matches:
        fields[matches[0]] = pair
    else:
        fields.append(pair)
    out = urlunsplit(parts._replace(query="&".join(fields), fragment=""))
    if len(out) > MAX_URL:
        raise UnsupportedShape("url_too_long")
    return out


def _json_body(parameter: str, value: Any) -> bytes:
    document: Any = value
    for token in reversed(_json_tokens(parameter)):
        document = {token: document}
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()


def _cookie_pairs(state: Optional[dict], url: str) -> list:
    raw = _cookie_header(state, url)
    return [tuple(p.split("=", 1)) for p in raw.split("; ") if "=" in p] if raw else []


def _protected_identity_cookie(state: Optional[dict], name: str) -> bool:
    for cookie in (state or {}).get("cookies", []) or []:
        if str(cookie.get("name") or "") == name and (
                cookie.get("httpOnly") or _credential_cookie(name)):
            return True
    return False


def plan_requests(*, method: str, url: str, location: str, parameter: str,
                  values: Dict[str, Any], state: Optional[dict], test_type: str,
                  field_names: Optional[Dict[str, str]] = None,
                  write_approved: bool = False,
                  xml_operators: Optional[Dict[str, str]] = None) -> Dict[str, PlannedRequest]:
    """One request per entry of ``values`` (``control`` plus recipes or steps).

    ``values[name]`` replaces the single input; ``field_names[name]`` renames
    it instead (query/form NoSQL operator steps); ``xml_operators[name]``
    wraps a body_xml value in one fixed operator element (NoSQL steps). The
    URL keeps its own query
    fields; header/cookie/body locations leave the URL unchanged, and a path
    location changes only its one segment. Any method but GET needs
    ``write_approved`` (the caller's exact operator approval).
    """
    method = str(method or "GET").upper()
    reason = shape_error(test_type, method, location, parameter)
    if reason:
        raise UnsupportedShape(reason)
    if location == "fragment":
        # Never sent to the server; the browser probe uses browser_template.
        raise UnsupportedShape("fragment_client_side_only")
    if method != "GET" and not write_approved:
        raise ApprovalRequired()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or len(url) > MAX_URL:
        raise UnsupportedShape("url_unsupported")
    base_url = urlunsplit(parts._replace(fragment=""))
    if location == "path":
        path_segment_index(base_url, parameter)
    if location == "cookie" and _protected_identity_cookie(state, parameter):
        raise UnsupportedShape("protected_cookie")
    identity_cookies = _cookie_pairs(state, base_url)
    out: Dict[str, PlannedRequest] = {}
    for name, value in values.items():
        rename = (field_names or {}).get(name, "")
        req_url = base_url
        body = b"" if method in {"POST", "PUT", "PATCH"} else None
        headers = [("Accept", _ACCEPT)]
        cookies = list(identity_cookies)
        if location == "query":
            req_url = _set_query(base_url, parameter, str(value), name=rename)
        elif location == "path":
            req_url = _set_path_segment(base_url, parameter, str(value))
        elif location == "header":
            text = str(value)
            if any(ch in text for ch in "\r\n\x00") or len(text) > 512:
                raise UnsupportedShape("header_value_unsupported")
            headers.append((parameter, text))
        elif location == "cookie":
            encoded = quote(str(value), safe="")
            cookies = [(k, v) for k, v in cookies if k != parameter] + [(parameter, encoded)]
        elif location == "body_form":
            body = (quote(rename or parameter, safe="") + "=" + quote(str(value), safe="")).encode()
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))
        elif location == "body_json":
            body = _json_body(parameter, value)
            headers.append(("Content-Type", "application/json"))
        elif location == "body_xml":
            operator = (xml_operators or {}).get(name, "")
            body = (_xml_operator_body(parameter, operator, value) if operator
                    else _xml_body(parameter, value))
            headers.append(("Content-Type", "application/xml"))
        if cookies:
            headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in cookies)))
        if body is not None and len(body) > 64 * 1024:
            raise UnsupportedShape("body_too_large")
        out[name] = PlannedRequest(method=method, url=req_url, headers=tuple(headers), body=body)
    return out


def browser_template(url: str, location: str, parameter: str, payload: str) -> str:
    """The GET navigation URL for a browser XSS payload on one intent input.

    ``query`` sets the one field (other fields kept); ``fragment`` appends
    ``#<payload>`` for parameter ``*`` or ``#<parameter>=<payload>``.
    """
    reason = shape_error("xss", "GET", location, parameter)
    if reason:
        raise UnsupportedShape(reason)
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or len(url) > MAX_URL:
        raise UnsupportedShape("url_unsupported")
    base_url = urlunsplit(parts._replace(fragment=""))
    if location == "query":
        return _set_query(base_url, parameter, payload)
    fragment = (quote(payload, safe="") if parameter == "*"
                else quote(parameter, safe="") + "=" + quote(payload, safe=""))
    out = base_url + "#" + fragment
    if len(out) > MAX_URL:
        raise UnsupportedShape("url_too_long")
    return out


def browser_template_value(template: str, location: str, parameter: str) -> str:
    """The payload ``browser_template`` placed, or '' when the shape differs."""
    parts = urlsplit(template)
    if location == "query":
        fields = [f for f in parts.query.split("&") if f]
        values = [unquote_plus(f.partition("=")[2]) for f in fields
                  if unquote_plus(f.partition("=")[0]) == parameter]
        return values[0] if len(values) == 1 and not parts.fragment else ""
    if location == "fragment":
        if parameter == "*":
            return unquote(parts.fragment)
        name, sep, value = parts.fragment.partition("=")
        return unquote(value) if sep and unquote(name) == parameter else ""
    return ""


def _open(req: PlannedRequest, *, allowed_origin: str, timeout: int = 20):
    assert_in_scope(req.url, [allowed_origin])
    request = Request(req.url, data=req.body, headers=dict(req.headers), method=req.method)
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())
    try:
        return opener.open(request, timeout=timeout)
    except HTTPError as error:
        return error


def fetch_body(req: PlannedRequest, *, allowed_origin: str, state: Any = None,
               **_ignored: Any) -> Tuple[int, bytes]:
    """``fetch`` for injection_probe: cookies were fixed at plan time."""
    with _open(req, allowed_origin=allowed_origin) as response:
        return int(response.status or 0), response.read(MAX_BODY)


def observe_headers(req: PlannedRequest, *, allowed_origin: str, nonce: str) -> dict:
    """Same fixed observation as response_probe._headers, for a planned request."""
    with _open(req, allowed_origin=allowed_origin, timeout=15) as response:
        location = response.headers.get("Location", "")
        try:
            resolved = urlsplit(urljoin(req.url, location)) if location else None
        except ValueError:
            resolved = None
        marker_values = response.headers.get_all("X-Prowl-Probe", []) or []
        return {
            "status": response.status,
            "header_marker": any(value.strip() == nonce for value in marker_values),
            "redirect_canary": bool(300 <= response.status < 400
                                    and resolved and resolved.scheme == "https"
                                    and resolved.hostname == "prowl.invalid"
                                    and resolved.path == "/" + nonce),
            "location_present": bool(location),
        }


def probe_response_requests(control: PlannedRequest, probe: PlannedRequest, *, test_type: str,
                            allowed_origin: str, nonce: str, observe=observe_headers) -> dict:
    """``response_probe.probe_response`` for planned requests (same receipt shape)."""
    if test_type not in {"crlf", "open_redirect"}:
        raise ValueError("Unsupported response probe")
    if not nonce or len(nonce) > 40:
        raise ValueError("A bounded nonce is required")
    first = observe(control, allowed_origin=allowed_origin, nonce=nonce)
    second = observe(probe, allowed_origin=allowed_origin, nonce=nonce)
    key = "header_marker" if test_type == "crlf" else "redirect_canary"
    return {
        "operation": "scoped_response_probe", "test_type": test_type,
        "requests_sent": 2, "control": first, "probe": second,
        "proof_confirmed": bool(second[key] and not first[key]),
        "finding": False,
    }


def response_values(test_type: str, location: str, nonce: str, scoped_origin: str) -> Tuple[str, str]:
    """Inert control and canary probe for one location.

    A header value cannot carry raw CR/LF, so the header probe sends the
    percent-encoded sequence (servers that decode and reflect it are the bug)
    and the control double-encodes it. Every other location encodes the raw
    sequence itself (URL, form and cookie quoting; JSON string escaping).
    """
    if test_type == "crlf":
        if location == "header":
            return "%250D%250AX-Prowl-Probe: " + nonce, "%0D%0AX-Prowl-Probe: " + nonce
        return "%0D%0AX-Prowl-Probe: " + nonce, "\r\nX-Prowl-Probe: " + nonce
    if test_type == "open_redirect":
        return scoped_origin + "/__prowl_control_" + nonce, "https://prowl.invalid/" + nonce
    raise ValueError("Unsupported response probe")


def injection_requests(*, method: str, url: str, location: str, parameter: str,
                       test_type: str, nonce: str, factors: Tuple[int, int],
                       state: Optional[dict], recipes: Iterable[str] = (),
                       write_approved: bool = False, baseline: str = "",
                       nosql_recipe: str = "") -> Dict[str, PlannedRequest]:
    """Control + fixed recipes (or the NoSQL differential steps) for one input.

    ``baseline`` (header NoSQL only: the JSON value the header carries) and
    ``nosql_recipe`` (path NoSQL: one of ``NOSQL_PATH_RECIPES``) feed
    ``nosql_requests`` for the cookie/header/XML/path locations.
    """
    from .injection_probe import NOSQL_SEQUENCE, control_value, probe_value, recipes_for

    if test_type == "nosql" and location in NOSQL_OBJECT_LOCATIONS:
        return nosql_requests(method=method, url=url, location=location, parameter=parameter,
                              nonce=nonce, state=state, baseline=baseline,
                              recipe=nosql_recipe or nosql_recipes_for(location)[0],
                              write_approved=write_approved)
    if test_type == "nosql":
        literal = control_value(test_type, nonce)
        if location == "body_json":
            values = {step: ({"$ne": literal} if step.startswith("true") else
                             {"$eq": literal} if step.startswith("false") else literal)
                      for step in NOSQL_SEQUENCE}
            return plan_requests(method=method, url=url, location=location, parameter=parameter,
                                 values=values, state=state, test_type=test_type,
                                 write_approved=write_approved)
        names = {step: (f"{parameter}[$ne]" if step.startswith("true") else
                        f"{parameter}[$eq]" if step.startswith("false") else "")
                 for step in NOSQL_SEQUENCE}
        return plan_requests(method=method, url=url, location=location, parameter=parameter,
                             values={step: literal for step in NOSQL_SEQUENCE}, state=state,
                             test_type=test_type, field_names=names,
                             write_approved=write_approved)
    a, b = factors
    wanted = [r for r in recipes_for(test_type) if not recipes or r in set(recipes)]
    if recipes and not wanted:
        raise UnsupportedShape("recipe_unknown")
    values = {"control": control_value(test_type, nonce)}
    for recipe in wanted:
        values[recipe] = probe_value(test_type, recipe, a, b)
    return plan_requests(method=method, url=url, location=location, parameter=parameter,
                         values=values, state=state, test_type=test_type,
                         write_approved=write_approved)


# ---------------------------------------------------------------- string SQLi

_SQL_SAFE_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,39}\Z")
SQLI_RECIPES = ("or", "and", "error", "time")


def sqli_baseline_value(url: str, location: str, parameter: str) -> str:
    """The intent's own ordinary value for the input, else a fresh harmless canary."""
    value = ""
    try:
        if location == "query":
            fields = [f for f in urlsplit(url).query.split("&") if f]
            found = [unquote_plus(f.partition("=")[2]) for f in fields
                     if unquote_plus(f.partition("=")[0]) == parameter]
            value = found[0] if len(found) == 1 else ""
        elif location == "path":
            segments = (urlsplit(url).path or "/").split("/")
            value = unquote(segments[path_segment_index(url, parameter)])
    except UnsupportedShape:
        value = ""
    if _SQL_SAFE_VALUE.fullmatch(value):
        return value
    return "AegisProbe" + str(secrets.randbelow(900000) + 100000)


def sqli_nonces() -> Tuple[str, str]:
    nonce = str(secrets.randbelow(90000) + 10000)
    return nonce, nonce[:-1] + str((int(nonce[-1]) + 1) % 10)


def sqli_values(recipe: str, base: str, nonce: str, false_nonce: str,
                family: str = "") -> Dict[str, str]:
    """Raw (unencoded) input values per check key; the planner encodes per location.

    The same suffixes as the observed GET lane (``sqli_string``/``sqli_time``).
    """
    from . import sqli_string, sqli_time

    if recipe == "or":
        true = base + f"' OR '{nonce}'='{nonce}'-- "
        false = base + f"' OR '{nonce}'='{false_nonce}'-- "
        values = {"baseline_first": base, "quote_error": base + "'",
                  "escaped_quote": base + "''", "true_first": true, "false_first": false,
                  "true_second": true, "false_second": false, "baseline_last": base}
        order = sqli_string.CHECK_ORDER
    elif recipe == "and":
        true = base + f"' AND '{nonce}'='{nonce}'-- "
        false = base + f"' AND '{nonce}'='{false_nonce}'-- "
        values = {"baseline_first": base, "true_first": true, "false_first": false,
                  "true_second": true, "false_second": false, "baseline_last": base}
        order = sqli_string.AND_CHECK_ORDER
    elif recipe == "error":
        values = {"baseline_first": base, "quote_first": base + "'",
                  "escaped_quote": base + "''", "quote_second": base + "'",
                  "baseline_last": base}
        order = sqli_string.ERROR_CHECK_ORDER
    elif recipe == "time":
        true = base + unquote(sqli_time._conditional_suffix(family, True, nonce, false_nonce))
        false = base + unquote(sqli_time._conditional_suffix(family, False, nonce, false_nonce))
        values = {"baseline_first": base, "false_first": false, "true_first": true,
                  "false_second": false, "true_second": true, "baseline_last": base}
        order = sqli_time.TIME_CHECK_ORDER
    else:
        raise UnsupportedShape("recipe_unknown")
    return {key: values[key] for key in order}


def observe_planned(req: PlannedRequest, *, allowed_origin: str,
                    reflection_marker: str = "") -> dict:
    """The bounded response metadata ``http_observe.observe_get`` records.

    ``reflection_marker`` (UNION recipe and its baseline precondition) sets
    ``reflection_detected``; the body itself never leaves this function.
    """
    from .http_observe import MAX_BODY as OBSERVE_MAX, _sql_error_family

    started = time.perf_counter()
    with _open(req, allowed_origin=allowed_origin, timeout=15) as response:
        data = response.read(OBSERVE_MAX + 1)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        truncated = len(data) > OBSERVE_MAX
        data = data[:OBSERVE_MAX]
        content_type = (response.headers.get("Content-Type", "") or "").split(";", 1)[0]
        content_type = content_type.lower()[:100]
        location = response.headers.get("Location", "")
        lengths: Dict[str, int] = {}
        if content_type == "application/json" and not truncated:
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    lengths = {key: min(len(parsed[key]), 1000)
                               for key in ("results", "items", "records", "data")
                               if isinstance(parsed.get(key), list)}
            except (UnicodeDecodeError, ValueError):
                pass
        return {
            "status": int(response.status or 0), "content_type": content_type,
            "bytes_captured": len(data), "truncated": truncated,
            "body_sha256": hashlib.sha256(data).hexdigest(), "redirected": bool(location),
            "elapsed_ms": elapsed_ms, "sql_error_family": _sql_error_family(data),
            "json_array_lengths": lengths,
            "reflection_detected": bool(reflection_marker
                                        and reflection_marker.encode() in data),
        }


def probe_sqli_requests(requests: Dict[str, PlannedRequest], *, recipe: str,
                        allowed_origin: str, observe=observe_planned,
                        reflection_marker: str = "") -> Dict[str, dict]:
    """Send each check in order; keep the fields the recipe's validator reads."""
    keep = ("status", "content_type", "bytes_captured", "truncated", "body_sha256",
            "redirected")
    extra = {"or": ("sql_error_family", "json_array_lengths"), "and": (),
             "error": ("sql_error_family",), "time": ("elapsed_ms",),
             "numeric": (), "union": ("reflection_detected",)}[recipe]
    marker = {"reflection_marker": reflection_marker} if reflection_marker else {}
    checks: Dict[str, dict] = {}
    for key, req in requests.items():
        row = observe(req, allowed_origin=allowed_origin, **marker)
        checks[key] = {name: row.get(name) for name in (*keep, *extra)}
    return checks


# ---------------------------------------------------------------- NoSQL locations

# Locations ``nosql_requests`` builds (query/form/JSON keep the steps above).
NOSQL_OBJECT_LOCATIONS = frozenset({"cookie", "header", "body_xml", "path"})
NOSQL_OPERATOR_RECIPE = "operator_ne"
# A path segment is always a string: only string-carried recipes. Each pairs an
# always-true variant with a variant that means the same as the literal control.
#   where_*: the segment is concatenated into a ``$where`` JavaScript string
#     (``this.f == '<seg>'``): ``' || 'a'=='a`` is always true, ``' && 'a'=='b``
#     always false, exactly like the control literal that matches nothing.
#   regex_alternation: the segment becomes a ``$regex``: ``<lit>|.*`` matches
#     everything, ``(?:<lit>)`` matches exactly what the control matches.
# A server that compares or reflects the segment literally makes the false
# variant differ from the control (reflection) or the true variant equal it
# (no evaluation): never confirmed.
NOSQL_PATH_RECIPES = ("where_single_quote", "where_double_quote", "regex_alternation")
MAX_JSON_BASELINE = 512


def nosql_recipes_for(location: str) -> Tuple[str, ...]:
    return NOSQL_PATH_RECIPES if location == "path" else (NOSQL_OPERATOR_RECIPE,)


def _nosql_path_values(recipe: str, literal: str) -> Tuple[str, str]:
    if recipe == "where_single_quote":
        return literal + "' || 'a'=='a", literal + "' && 'a'=='b"
    if recipe == "where_double_quote":
        return literal + '" || "a"=="a', literal + '" && "a"=="b'
    if recipe == "regex_alternation":
        return literal + "|.*", "(?:" + literal + ")"
    raise UnsupportedShape("recipe_unknown")


def _json_string_leaves(document: Any, path: Tuple[Any, ...] = (), depth: int = 0) -> list:
    if depth > 5:
        raise UnsupportedShape("json_baseline_too_deep")
    if isinstance(document, dict):
        return [leaf for key, child in list(document.items())[:40]
                for leaf in _json_string_leaves(child, (*path, key), depth + 1)]
    if isinstance(document, list):
        return [leaf for index, child in enumerate(document[:40])
                for leaf in _json_string_leaves(child, (*path, index), depth + 1)]
    return [path] if isinstance(document, str) else []


def _json_replace(document: Any, path: Tuple[Any, ...], value: Any) -> Any:
    if not path:
        return value
    head, rest = path[0], path[1:]
    if isinstance(document, dict):
        return {k: (_json_replace(v, rest, value) if k == head else v)
                for k, v in document.items()}
    return [(_json_replace(v, rest, value) if i == head else v)
            for i, v in enumerate(document)]


def json_operator_values(baseline: str, literal: str) -> Dict[str, str]:
    """Control/true/false header values from a JSON object/array baseline.

    Exactly one string leaf must exist (the input the server filters on); it
    becomes the literal, ``{"$ne": literal}`` and ``{"$eq": literal}``. Every
    other part of the baseline is kept. Anything else is unsupported.
    """
    if not isinstance(baseline, str) or not baseline or len(baseline) > MAX_JSON_BASELINE:
        raise UnsupportedShape("header_baseline_not_json")
    try:
        document = json.loads(baseline)
    except ValueError:
        raise UnsupportedShape("header_baseline_not_json") from None
    if not isinstance(document, (dict, list)):
        raise UnsupportedShape("header_baseline_not_json")
    leaves = _json_string_leaves(document)
    if len(leaves) != 1:
        raise UnsupportedShape("header_json_needs_one_string_field" if not leaves
                               else "header_json_string_field_ambiguous")

    def dump(value: Any) -> str:
        return json.dumps(_json_replace(document, leaves[0], value), separators=(",", ":"))

    return {"control": dump(literal), "true": dump({"$ne": literal}),
            "false": dump({"$eq": literal})}


def nosql_requests(*, method: str, url: str, location: str, parameter: str, nonce: str,
                   state: Optional[dict], baseline: str = "",
                   recipe: str = NOSQL_OPERATOR_RECIPE,
                   write_approved: bool = False) -> Dict[str, PlannedRequest]:
    """The ``NOSQL_SEQUENCE`` steps for one cookie/header/XML/path input.

    * cookie: ``j:{"$ne":"<lit>"}`` / ``j:{"$eq":"<lit>"}`` (Express
      cookie-parser JSON cookies) against the plain literal;
    * header: the JSON baseline with its one string field replaced
      (``json_operator_values``); a non-JSON baseline is unsupported;
    * body_xml: ``<field><$ne>lit</$ne></field>`` / ``<$eq>`` against
      ``<field>lit</field>``;
    * path: the string recipes in ``NOSQL_PATH_RECIPES``.
    """
    from .injection_probe import NOSQL_SEQUENCE, control_value

    if location not in NOSQL_OBJECT_LOCATIONS:
        raise UnsupportedShape("location_unsupported")
    if recipe not in nosql_recipes_for(location):
        raise UnsupportedShape("recipe_unknown")
    literal = control_value("nosql", nonce)
    kinds = {step: step.split("_", 1)[0] for step in NOSQL_SEQUENCE}
    operators: Dict[str, str] = {}
    if location == "cookie":
        by_kind = {"control": literal,
                   "true": "j:" + json.dumps({"$ne": literal}, separators=(",", ":")),
                   "false": "j:" + json.dumps({"$eq": literal}, separators=(",", ":"))}
    elif location == "header":
        by_kind = json_operator_values(baseline, literal)
    elif location == "body_xml":
        by_kind = {"control": literal, "true": literal, "false": literal}
        operators = {step: {"true": "$ne", "false": "$eq"}[kind]
                     for step, kind in kinds.items() if kind != "control"}
    else:
        true, false = _nosql_path_values(recipe, literal)
        by_kind = {"control": literal, "true": true, "false": false}
    return plan_requests(method=method, url=url, location=location, parameter=parameter,
                         values={step: by_kind[kind] for step, kind in kinds.items()},
                         state=state, test_type="nosql", write_approved=write_approved,
                         xml_operators=operators)


# ---------------------------------------------------------------- baselines

_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]{0,8}\Z")
MAX_BASELINE_VALUE = 512


def positive_integer(value: Any) -> bool:
    return bool(isinstance(value, str) and _POSITIVE_INTEGER.fullmatch(value))


def sqli_safe_value(value: Any) -> bool:
    """An ordinary string value the string/UNION recipes may extend."""
    return bool(isinstance(value, str) and _SQL_SAFE_VALUE.fullmatch(value))


def valid_baseline_value(value: Any) -> bool:
    """Operator-supplied ``baseline_value``: bounded printable text."""
    return (isinstance(value, str) and 0 < len(value) <= MAX_BASELINE_VALUE
            and not re.search(r"[\x00-\x1f\x7f]", value))


def url_value(url: str, location: str, parameter: str) -> str:
    """The value the URL already carries for a query field or path segment."""
    try:
        if location == "query":
            fields = [f for f in urlsplit(url).query.split("&") if f]
            found = [unquote_plus(f.partition("=")[2]) for f in fields
                     if unquote_plus(f.partition("=")[0]) == parameter]
            return found[0] if len(found) == 1 else ""
        if location == "path":
            segments = (urlsplit(url).path or "/").split("/")
            return unquote(segments[path_segment_index(url, parameter)])
    except ValueError:
        return ""
    return ""


def captured_value(captured: Dict[str, Any], location: str, parameter: str) -> Optional[str]:
    """The value one input had in a private browser capture, or None.

    Captures hold the URL, the sanitized replay headers and the request body;
    never cookies (credentials come from the named identity), so a cookie
    baseline needs the operator's ``baseline_value``. XML bodies are not
    parsed here either.
    """
    import base64
    import binascii

    url = str(captured.get("url") or "")
    if location in {"query", "path"}:
        return url_value(url, location, parameter) or None
    if location == "header":
        headers = captured.get("replay_headers") or {}
        found = [str(v) for k, v in headers.items() if str(k).lower() == parameter.lower()]
        return found[0] if len(found) == 1 and found[0] else None
    try:
        body = base64.b64decode(str(captured.get("request_body_base64") or ""), validate=True)
    except (ValueError, binascii.Error):
        return None
    mime = str(captured.get("request_content_type") or "").lower()
    if location == "body_form" and mime == "application/x-www-form-urlencoded":
        from urllib.parse import parse_qsl

        try:
            pairs = parse_qsl(body.decode("utf-8"), keep_blank_values=True, max_num_fields=100)
        except (UnicodeDecodeError, ValueError):
            return None
        found = [v for k, v in pairs if k == parameter]
        return found[0] if len(found) == 1 and found[0] else None
    if location == "body_json" and (mime == "application/json" or mime.endswith("+json")):
        try:
            document: Any = json.loads(body)
            for token in _json_tokens(parameter):
                document = document[token] if isinstance(document, dict) else None
        except (ValueError, KeyError, TypeError):
            return None
        if isinstance(document, bool) or not isinstance(document, (str, int)):
            return None
        return str(document) or None
    return None


def result_data_reflected(row: Dict[str, Any]) -> bool:
    """A baseline response that renders query results (the UNION precondition).

    JSON with a non-empty result array, or a body that shows the baseline
    value itself (``reflection_detected`` with the value as marker).
    """
    if row.get("status") != 200 or row.get("truncated") is not False or row.get("redirected"):
        return False
    lengths = row.get("json_array_lengths") or {}
    return bool(row.get("reflection_detected") is True
                or any(isinstance(n, int) and n > 0 for n in lengths.values()))


def numeric_values(base: str, nonce: str) -> Dict[str, str]:
    """The observed numeric lane's checks (``sqli_boolean``) as raw values."""
    from . import sqli_boolean

    if not positive_integer(base):
        raise UnsupportedShape("baseline_not_positive_integer")
    true = f"{base} AND {nonce}={nonce}"
    false = f"{base} AND {nonce}={int(nonce) + 1}"
    values = {"baseline_first": base, "true_first": true, "false_first": false,
              "true_second": true, "false_second": false, "baseline_last": base}
    return {key: values[key] for key in sqli_boolean.CHECK_ORDER}


def union_value(base: str, family: str, columns: int, position: int, marker: str) -> str:
    """The observed UNION lane's payload (``sqli_union._union_suffix``) as a raw value."""
    from . import sqli_union

    if not sqli_safe_value(base):
        raise UnsupportedShape("baseline_not_ordinary_string")
    return base + unquote(sqli_union._union_suffix(family, columns, position, marker))
