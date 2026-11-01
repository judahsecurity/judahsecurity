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
