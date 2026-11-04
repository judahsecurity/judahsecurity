"""Operator-enabled, read-only IDOR lead source from the assessment Caido project.

Prowl's own value-free capability map and capture receipts remain the source of
truth. This module is an *optional* convenience: when an operator points Prowl at
the assessment Caido GraphQL endpoint, it reads request *metadata* (method, host,
path, query parameter names) from Caido's HTTP history and turns it into the same
value-free observations the IDOR lead extractor already consumes. It produces
leads only — never evidence, never proof.

Guard rails:
  * Off unless ``AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL`` is set *and* the session's
    assessment policy enabled ``caido_idor_leads`` (operator-supplied, never
    model-supplied).
  * Read-only: a single bounded GraphQL *query* (never a mutation).
  * In-scope only: a record is dropped unless its origin is one of the caller's
    allowed origins.
  * Value-free: only methods, paths, and parameter *names* leave this module; no
    request/response bodies, cookies, auth headers, or parameter values.

Caido's GraphQL API is explicitly unstable across releases, so the network call
is best-effort and the response parser is deliberately tolerant of shape; callers
wrap this module and treat any failure as "no leads".
"""

from __future__ import annotations

import os
from urllib.parse import parse_qsl, urlsplit

# Names we never surface as replay candidates even if Caido saw them.
_PROTECTED_NAMES = (
    "csrf", "xsrf", "nonce", "session", "token", "secret", "apikey",
    "api_key", "api-key", "authorization", "jwt", "bearer", "password",
)
MAX_RECORDS = 500
MAX_QUERY_FIELDS = 40

# Caido history query. Offset pagination (``requestsByOffset``) is the documented
# listing field; the exact nested shape has changed between releases, so the
# parser below accepts several envelope shapes rather than assuming one.
HISTORY_QUERY = """
query ProwlIdorHistory($limit: Int!, $offset: Int!) {
  requestsByOffset(limit: $limit, offset: $offset) {
    edges { node { host port path query method isTls } }
  }
}
""".strip()


def caido_graphql_config() -> tuple[str, str] | None:
    """Return (endpoint_url, bearer_token) when the operator configured Caido."""
    url = os.environ.get("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "").strip()
    if not url:
        return None
    parts = urlsplit(url)
    if (parts.scheme not in ("http", "https") or not parts.hostname
            or parts.username or parts.password):
        raise ValueError("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL must be a clean http(s) URL")
    token = os.environ.get("AEGIS_ASSESSMENT_CAIDO_TOKEN", "").strip()
    return url.rstrip("/"), token


def assessment_caido_binding() -> dict:
    """Describe which Caido instance/project this deployment is bound to.

    A shared assessment Caido keeps one active project at a time, so isolating
    concurrent engagements means one instance (or at least one project) per
    engagement. This records the configured binding so the active project is
    explicit and auditable, and flags an unlabeled (pooled) configuration.
    """
    url = os.environ.get("AEGIS_ASSESSMENT_CAIDO_GRAPHQL_URL", "").strip()
    project = os.environ.get("AEGIS_ASSESSMENT_CAIDO_PROJECT", "").strip()
    endpoint_host = urlsplit(url).netloc if url else ""
    return {
        "endpoint": endpoint_host,
        "project": project,
        # Operators should run one instance/project per engagement; an unlabeled
        # endpoint cannot be attributed to a single engagement.
        "isolation": "labeled" if project else ("unlabeled_shared" if url else "unconfigured"),
    }


def graphql_error_reason(payload: object) -> str:
    """Classify a Caido GraphQL error envelope. '' means no error.

    Caido returns HTTP 200 with an ``errors`` array on auth failure, so the HTTP
    status alone never reveals a stale token. An AUTHORIZATION / INVALID_TOKEN
    extension means the token is missing, the wrong type, or expired (the local
    API's session token lasts about 7 days).
    """
    if not isinstance(payload, dict):
        return "caido_invalid_response"
    errors = payload.get("errors")
    if not isinstance(errors, list) or not errors:
        return ""
    for err in errors:
        caido = (err.get("extensions") or {}).get("CAIDO") if isinstance(err, dict) else None
        if isinstance(caido, dict) and (caido.get("code") == "AUTHORIZATION"
                                        or caido.get("reason") == "INVALID_TOKEN"):
            return "caido_auth_invalid_or_expired"
    return "caido_graphql_error"


def _iter_nodes(payload: dict):
    """Yield request nodes from the tolerated GraphQL envelope shapes."""
    data = payload.get("data") if isinstance(payload, dict) else None
    listing = data.get("requestsByOffset") if isinstance(data, dict) else None
    if not isinstance(listing, dict):
        return
    if isinstance(listing.get("edges"), list):
        for edge in listing["edges"]:
            node = edge.get("node") if isinstance(edge, dict) else None
            if isinstance(node, dict):
                yield node
    elif isinstance(listing.get("items"), list):
        for node in listing["items"]:
            if isinstance(node, dict):
                yield node
    elif isinstance(listing.get("nodes"), list):
        for node in listing["nodes"]:
            if isinstance(node, dict):
                yield node


def _record_origin(node: dict) -> str:
    """Reconstruct the request origin from a Caido node, or '' if unusable."""
    host = str(node.get("host") or "").strip().lower()
    if not host:
        return ""
    is_tls = bool(node.get("isTls") if node.get("isTls") is not None else node.get("isTLS"))
    scheme = "https" if is_tls else "http"
    try:
        port = int(node.get("port")) if node.get("port") not in (None, "") else None
    except (TypeError, ValueError):
        port = None
    default = 443 if scheme == "https" else 80
    netloc = host if (port is None or port == default) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def parse_requests_payload(payload: dict, allowed_origins: list[str]) -> tuple[list[dict], list[dict]]:
    """Pure parser: GraphQL payload -> (value-free param rows, observed endpoints).

    Only in-scope records survive. Rows match the ``collect_parameter_inventory``
    shape closely enough for ``identifier_leads`` to consume them.
    """
    allowed = {o for o in (allowed_origins or []) if isinstance(o, str) and o}
    rows: list[dict] = []
    endpoints: list[dict] = []
    seen: set[tuple] = set()
    for node in _iter_nodes(payload):
        record_origin = _record_origin(node)
        if not record_origin or record_origin not in allowed:
            continue
        path = str(node.get("path") or "/")
        if not path.startswith("/") or len(path) > 2048:
            continue
        method = str(node.get("method") or "GET").upper()[:12]
        host = urlsplit(record_origin).netloc
        endpoints.append({"method": method, "path": path, "identity": "caido_history"})
        raw_query = str(node.get("query") or "").lstrip("?")
        if not raw_query:
            continue
        try:
            pairs = parse_qsl(raw_query, keep_blank_values=True, max_num_fields=100)
        except ValueError:
            continue
        for name, value in pairs[:MAX_QUERY_FIELDS]:
            if not (0 < len(name) <= 80):
                continue
            lowered = name.lower()
            if any(marker in lowered for marker in _PROTECTED_NAMES):
                continue
            key = (method, path, name)
            if key in seen:
                continue
            seen.add(key)
            value_type = "positive_integer" if value and value.isdigit() and value[0] != "0" else ""
            rows.append({
                "method": method, "host": host, "path": path, "name": name,
                "location": "query", "source": "caido_history", "value_type": value_type,
                "identity": "caido_history", "artifact_id": "", "testable": True,
            })
        if len(endpoints) >= MAX_RECORDS:
            break
    return rows, endpoints


def caido_history_observations(allowed_origins: list[str]) -> tuple[list[dict], list[dict], dict]:
    """Query the assessment Caido project (if enabled) for in-scope IDOR leads."""
    config = caido_graphql_config()
    if config is None:
        return [], [], {"enabled": True, "ok": False, "reason": "caido_graphql_url_unset"}
    if not allowed_origins:
        return [], [], {"enabled": True, "ok": False, "reason": "no_in_scope_origin"}
    url, token = config

    import httpx

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = {"query": HISTORY_QUERY, "variables": {"limit": MAX_RECORDS, "offset": 0}}
    # Caido is reached directly (loopback/compose network), never via the
    # target assessment proxy, so trust_env stays off.
    with httpx.Client(timeout=15.0, trust_env=False) as client:
        response = client.post(url, json=request, headers=headers)
    response.raise_for_status()
    payload = response.json()
    reason = graphql_error_reason(payload)
    if reason:
        # A stale/invalid token or any GraphQL error must be visible, never a
        # silent empty result that looks like "no leads".
        return [], [], {"enabled": True, "ok": False, "endpoint": url,
                        "reason": reason, "binding": assessment_caido_binding()}
    rows, endpoints = parse_requests_payload(payload, allowed_origins)
    status = {
        "enabled": True, "ok": True, "endpoint": url,
        "records_in_scope": len(endpoints),
        "binding": assessment_caido_binding(),
    }
    return rows, endpoints, status
