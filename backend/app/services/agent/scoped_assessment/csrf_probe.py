"""Bounded CSRF proof on an operator-approved, state-changing form action.

A request is forgeable cross-site when a browser would attach the victim's
session to it and the server accepts it without an anti-CSRF token or an
origin check. The probe sends exactly what a cross-site HTML form could send:
``application/x-www-form-urlencoded``, a foreign ``Origin``/``Referer``,
``Sec-Fetch-Site: cross-site``, the session cookie, and no token. It then
proves the state change through an independent readback of a nonce canary.

Controls:
* the same forged request without the session cookie must not write its own
  canary (otherwise this is an unauthenticated write, not CSRF);
* at least one session cookie must be eligible for cross-site POSTs
  (``SameSite=None``); Lax/Strict cookies are not sent on a cross-site POST.

Both canaries are cleaned up. The action path, readback page, and cleanup path
are operator policy; the canaries are nonce bound.
"""

from __future__ import annotations

import httpx

from app.services.agent.assessment_proxy import assessment_httpx_options

from .browser import assert_in_scope
from .http_observe import _cookie_header

_READBACK_SCAN_BYTES = 256 * 1024
SIMPLE_CONTENT_TYPE = "application/x-www-form-urlencoded"


def _probe_canary(nonce: str) -> str:
    return f"aegis-csrf-{nonce}"


def _control_canary(nonce: str) -> str:
    return f"aegis-csrf-anon-{nonce}"


def forged_origin(nonce: str) -> str:
    return f"https://prowl-csrf-{nonce}.invalid"


def cross_site_cookie_eligible(state: dict | None, url: str) -> bool:
    """True when a cookie the browser would send for ``url`` is SameSite=None."""
    if not state or not _cookie_header(state, url):
        return False
    for cookie in state.get("cookies", []) or []:
        same_site = str(cookie.get("sameSite") or cookie.get("same_site") or "").lower()
        if same_site == "none" and cookie.get("secure", True) is not False:
            return True
    return False


async def _post(client: httpx.AsyncClient, url: str, *, field: str, canary: str,
                cookie: str, nonce: str) -> int:
    headers = {
        "Content-Type": SIMPLE_CONTENT_TYPE,
        "Origin": forged_origin(nonce),
        "Referer": forged_origin(nonce) + "/",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Accept": "text/html,*/*;q=0.8",
    }
    if cookie:
        headers["Cookie"] = cookie
    try:
        response = await client.post(url, data={field: canary}, headers=headers)
        return response.status_code
    except httpx.HTTPError:
        return 0


async def _readback(client: httpx.AsyncClient, url: str, *, canary: str, cookie: str) -> int:
    headers = {"Accept": "text/html, application/json, */*;q=0.8"}
    if cookie:
        headers["Cookie"] = cookie
    try:
        response = await client.get(url, headers=headers)
    except httpx.HTTPError:
        return -1
    return response.text[:_READBACK_SCAN_BYTES].count(canary)


async def _cleanup(client: httpx.AsyncClient, template: str, *, canary: str, cookie: str) -> bool:
    url = template.replace("__PROWL_NONCE__", canary)
    headers = {"Cookie": cookie} if cookie else {}
    for method in ("DELETE", "PUT", "PATCH"):
        try:
            response = await client.request(method, url, headers=headers)
        except httpx.HTTPError:
            continue
        if 200 <= response.status_code < 300:
            return True
    return False


async def probe_csrf(action_url: str, readback_url: str, cleanup_template: str, *,
                     field: str, allowed_origin: str, state: dict | None,
                     nonce: str) -> dict:
    """Prove a cross-site, token-less form POST changes the victim's state."""
    if not nonce or len(nonce) < 8 or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A random alphanumeric nonce of at least 8 characters is required")
    if not field or len(field) > 128:
        raise ValueError("A bounded form field is required")
    if "__PROWL_NONCE__" not in cleanup_template:
        raise ValueError("The cleanup template must carry __PROWL_NONCE__")
    for url in (action_url, readback_url, cleanup_template.replace("__PROWL_NONCE__", "x")):
        assert_in_scope(url, [allowed_origin])
    cookie = _cookie_header(state, action_url)
    if not cookie:
        raise ValueError("CSRF proof requires an authenticated test identity")
    eligible = cross_site_cookie_eligible(state, action_url)
    probe_canary, control_canary = _probe_canary(nonce), _control_canary(nonce)
    options = assessment_httpx_options()
    async with httpx.AsyncClient(timeout=30, follow_redirects=False, **options) as client:
        before = await _readback(client, readback_url, canary=probe_canary, cookie=cookie)
        control_status = await _post(client, action_url, field=field, canary=control_canary,
                                     cookie="", nonce=nonce)
        control_count = await _readback(client, readback_url, canary=control_canary, cookie=cookie)
        probe_status = await _post(client, action_url, field=field, canary=probe_canary,
                                   cookie=cookie, nonce=nonce)
        probe_count = await _readback(client, readback_url, canary=probe_canary, cookie=cookie)
        cleanup_probe = await _cleanup(client, cleanup_template, canary=probe_canary, cookie=cookie)
        cleanup_control = (True if control_count <= 0 else
                           await _cleanup(client, cleanup_template, canary=control_canary,
                                          cookie=cookie))
    confirmed = bool(
        eligible
        and before == 0
        and control_count == 0
        and probe_count >= 1
        and 200 <= probe_status < 400
        and cleanup_probe and cleanup_control
    )
    return {
        "operation": "scoped_csrf_probe", "test_type": "csrf", "field": field,
        "content_type": SIMPLE_CONTENT_TYPE, "token_sent": False,
        "origin_sent": forged_origin(nonce), "requests_sent": 6,
        "cross_site_cookie_eligible": eligible,
        "control": {"canary": control_canary, "status": control_status,
                    "readback_count": control_count, "anonymous": True},
        "probe": {"canary": probe_canary, "status": probe_status,
                  "readback_before": before, "readback_count": probe_count},
        "cleanup_confirmed": bool(cleanup_probe and cleanup_control),
        "proof_confirmed": confirmed,
        "finding": False,
    }


def csrf_proof_valid(row: dict) -> bool:
    if not isinstance(row, dict) or row.get("operation") != "scoped_csrf_probe":
        return False
    control, probe = row.get("control") or {}, row.get("probe") or {}
    return bool(
        row.get("test_type") == "csrf"
        and row.get("proof_confirmed") is True
        and row.get("token_sent") is False
        and row.get("content_type") == SIMPLE_CONTENT_TYPE
        and row.get("cross_site_cookie_eligible") is True
        and row.get("cleanup_confirmed") is True
        and control.get("anonymous") is True
        and control.get("readback_count") == 0
        and probe.get("readback_before") == 0
        and int(probe.get("readback_count") or 0) >= 1
        and len(str(row.get("nonce") or "")) >= 8
    )
