"""Request plans for coverage cells that have no captured baseline.

Intent-backed cells (``attack_graph.add_intent``: operator- or planner-directed
tests on inputs Prowl never observed) and observed header/cookie inputs name a
method, URL, parameter and location, but carry no replayable capture. This
module builds the inert control and the fixed probes for exactly one such
input and sends them. The caller still chooses nothing: values come from the
proof modules (``injection_probe``, the response canaries), and every request
here differs from the control only in that one input.

Shapes this module cannot build exactly raise ``UnsupportedShape``; the caller
leaves the cell open/inconclusive (never ``tested_clean``).

Safety rules enforced here:

* exact origin (``assert_in_scope``) on every request, no redirects followed;
* only GET, or POST for body locations and approved paths (the caller checks
  ``body_replay_paths`` before planning, exactly as for captured POST bodies);
* header mutation never names Host, Cookie, Authorization, framing headers or
  anything credential-like (``parameter_inventory._CREDENTIAL_HEADER``);
* cookie mutation never names a credential-like cookie and never replaces an
  HttpOnly cookie of the identity's session jar; the identity's other cookies
  are sent unchanged;
* no Authorization header is ever sent (identity state is cookies only).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import quote, unquote_plus, urljoin, urlsplit, urlunsplit
from urllib.request import Request, build_opener

from app.services.agent.assessment_proxy import assessment_urllib_handlers

from .browser import assert_in_scope
from .http_observe import _NoRedirect, _cookie_header

MAX_BODY = 256 * 1024
MAX_URL = 2048
INJECTION_LOCATIONS = frozenset({"query", "header", "cookie", "body_form", "body_json"})
SUPPORTED_LOCATIONS: Dict[str, frozenset] = {
    "ssti": INJECTION_LOCATIONS,
    "command_injection": INJECTION_LOCATIONS,
    "path_traversal": INJECTION_LOCATIONS,
    "crlf": INJECTION_LOCATIONS,
    "open_redirect": INJECTION_LOCATIONS,
    # Operator syntax only exists where a server parses field names or JSON.
    "nosql": frozenset({"query", "body_form", "body_json"}),
}
BODY_LOCATIONS = frozenset({"body_form", "body_json"})
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


def shape_error(test_type: str, method: str, location: str, parameter: str) -> str:
    """Empty when this module can build the shape exactly, else a fixed reason."""
    if location not in SUPPORTED_LOCATIONS.get(test_type, frozenset()):
        return "location_unsupported"
    if method not in {"GET", "POST"}:
        return "method_unsupported"
    if location in BODY_LOCATIONS and method != "POST":
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
    elif not _FIELD.fullmatch(parameter):
        return "field_unsupported"
    return ""


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
                  field_names: Optional[Dict[str, str]] = None) -> Dict[str, PlannedRequest]:
    """One request per entry of ``values`` (``control`` plus recipes or steps).

    ``values[name]`` replaces the single input; ``field_names[name]`` renames
    it instead (query/form NoSQL operator steps). The URL keeps its own query
    fields; header/cookie/body locations leave the URL unchanged.
    """
    method = str(method or "GET").upper()
    reason = shape_error(test_type, method, location, parameter)
    if reason:
        raise UnsupportedShape(reason)
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or len(url) > MAX_URL:
        raise UnsupportedShape("url_unsupported")
    base_url = urlunsplit(parts._replace(fragment=""))
    if location == "cookie" and _protected_identity_cookie(state, parameter):
        raise UnsupportedShape("protected_cookie")
    identity_cookies = _cookie_pairs(state, base_url)
    out: Dict[str, PlannedRequest] = {}
    for name, value in values.items():
        rename = (field_names or {}).get(name, "")
        req_url, body = base_url, (b"" if method == "POST" else None)
        headers = [("Accept", _ACCEPT)]
        cookies = list(identity_cookies)
        if location == "query":
            req_url = _set_query(base_url, parameter, str(value), name=rename)
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
        if cookies:
            headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in cookies)))
        if body is not None and len(body) > 64 * 1024:
            raise UnsupportedShape("body_too_large")
        out[name] = PlannedRequest(method=method, url=req_url, headers=tuple(headers), body=body)
    return out


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
                       state: Optional[dict], recipes: Iterable[str] = ()) -> Dict[str, PlannedRequest]:
    """Control + fixed recipes (or the NoSQL differential steps) for one input."""
    from .injection_probe import NOSQL_SEQUENCE, control_value, probe_value, recipes_for

    if test_type == "nosql":
        literal = control_value(test_type, nonce)
        if location == "body_json":
            values = {step: ({"$ne": literal} if step.startswith("true") else
                             {"$eq": literal} if step.startswith("false") else literal)
                      for step in NOSQL_SEQUENCE}
            return plan_requests(method=method, url=url, location=location, parameter=parameter,
                                 values=values, state=state, test_type=test_type)
        names = {step: (f"{parameter}[$ne]" if step.startswith("true") else
                        f"{parameter}[$eq]" if step.startswith("false") else "")
                 for step in NOSQL_SEQUENCE}
        return plan_requests(method=method, url=url, location=location, parameter=parameter,
                             values={step: literal for step in NOSQL_SEQUENCE}, state=state,
                             test_type=test_type, field_names=names)
    a, b = factors
    wanted = [r for r in recipes_for(test_type) if not recipes or r in set(recipes)]
    if recipes and not wanted:
        raise UnsupportedShape("recipe_unknown")
    values = {"control": control_value(test_type, nonce)}
    for recipe in wanted:
        values[recipe] = probe_value(test_type, recipe, a, b)
    return plan_requests(method=method, url=url, location=location, parameter=parameter,
                         values=values, state=state, test_type=test_type)
