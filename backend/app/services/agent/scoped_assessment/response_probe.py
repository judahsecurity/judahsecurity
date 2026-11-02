"""Bounded response-header and redirect checks on observed GET inputs."""

from __future__ import annotations

from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, build_opener

from app.services.agent.assessment_proxy import assessment_urllib_handlers

from .browser import assert_in_scope
from .http_observe import _NoRedirect, _cookie_header


def _headers(url: str, *, allowed_origin: str, state: dict | None,
             nonce: str) -> dict:
    assert_in_scope(url, [allowed_origin])
    headers = {"Accept": "text/html, */*;q=0.8"}
    cookie = _cookie_header(state, url)
    if cookie:
        headers["Cookie"] = cookie
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())
    try:
        response = opener.open(Request(url, headers=headers, method="GET"), timeout=15)
    except HTTPError as error:
        response = error
    with response:
        location = response.headers.get("Location", "")
        try:
            resolved = urlsplit(urljoin(url, location)) if location else None
        except ValueError:
            resolved = None
        marker_values = response.headers.get_all("X-Prowl-Probe", [])
        return {
            "status": response.status,
            "header_marker": any(value.strip() == nonce for value in marker_values),
            "redirect_canary": bool(300 <= response.status < 400
                                    and resolved and resolved.scheme == "https"
                                    and resolved.hostname == "prowl.invalid"
                                    and resolved.path == "/" + nonce),
            "location_present": bool(location),
        }


def probe_response(control_url: str, probe_url: str, *, test_type: str,
                   allowed_origin: str, state: dict | None, nonce: str) -> dict:
    """Compare an inert control and one probe without following redirects."""
    if test_type not in {"crlf", "open_redirect"}:
        raise ValueError("Unsupported response probe")
    if not nonce or len(nonce) > 40:
        raise ValueError("A bounded nonce is required")
    control = _headers(control_url, allowed_origin=allowed_origin, state=state, nonce=nonce)
    probe = _headers(probe_url, allowed_origin=allowed_origin, state=state, nonce=nonce)
    key = "header_marker" if test_type == "crlf" else "redirect_canary"
    confirmed = probe[key] and not control[key]
    return {
        "operation": "scoped_response_probe", "test_type": test_type,
        "requests_sent": 2, "control": control, "probe": probe,
        "proof_confirmed": confirmed,
        "finding": False,
    }


def _canary_origin(nonce: str) -> str:
    """A never-seen origin bound to this run's nonce.

    An allowlist that only echoes known origins will not reflect it, so a
    reflected canary means the server mirrors arbitrary origins.
    """
    return f"https://aegis-cors-canary-{nonce}.example"


def _cors_headers(url: str, *, origin: str | None, allowed_origin: str,
                  state: dict | None) -> dict:
    assert_in_scope(url, [allowed_origin])
    headers = {"Accept": "*/*"}
    if origin:
        headers["Origin"] = origin
    cookie = _cookie_header(state, url)
    if cookie:
        headers["Cookie"] = cookie
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())
    try:
        response = opener.open(Request(url, headers=headers, method="GET"), timeout=15)
    except HTTPError as error:
        response = error
    with response:
        acao = (response.headers.get("Access-Control-Allow-Origin", "") or "").strip()
        acac = (response.headers.get("Access-Control-Allow-Credentials", "") or "").strip()
        reflected = bool(origin) and acao == origin
        credentialed = acac.lower() == "true"
        return {
            "status": response.status,
            "origin_sent": origin or "",
            "acao": acao[:256],
            "acac": acac[:32],
            # Credentialed reflection of the exact canary. ACAO=* cannot carry
            # credentials in a browser, so it never satisfies this signal.
            "cors_canary": bool(reflected and credentialed and acao != "*"),
        }


def probe_cors(url: str, *, allowed_origin: str, state: dict | None,
               nonce: str) -> dict:
    """Prove credentialed CORS origin reflection with a control and one probe.

    The control sends no Origin; the probe sends a nonce-bound canary origin.
    Confirmed only when the probe echoes that exact origin with
    Access-Control-Allow-Credentials: true and the control does not.
    """
    if not nonce or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A bounded alphanumeric nonce is required")
    canary = _canary_origin(nonce)
    control = _cors_headers(url, origin=None, allowed_origin=allowed_origin, state=state)
    probe = _cors_headers(url, origin=canary, allowed_origin=allowed_origin, state=state)
    confirmed = bool(probe["cors_canary"] and not control["cors_canary"])
    return {
        "operation": "scoped_response_probe", "test_type": "cors",
        "requests_sent": 2, "control": control, "probe": probe,
        "canary_origin": canary,
        "proof_confirmed": confirmed,
        "finding": False,
    }
