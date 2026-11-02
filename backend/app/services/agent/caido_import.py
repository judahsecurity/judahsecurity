"""Read analyst-browsed traffic back out of Caido for passive API fingerprinting.

Prowl normally only writes to Caido (see docs/PROWL_CAIDO_CAPTURE.md). When an
analyst browses an authenticated or multi-step flow through the same Caido
project, that history covers API hosts and endpoints the crawler cannot reach.
This module imports it as *observations only*:

* in-scope hosts only (same apex rule as the crawler), static assets dropped;
* requests that carry Prowl's own probe markers are skipped;
* request bodies are never read, and credential header values are redacted;
* samples are returned separately and never merged into ``api_samples``, so
  replay/mutation tools cannot pick up an analyst's (or Prowl's) request.

A Caido sample is a lead for fingerprinting, never evidence for a finding.
Configure with ``AEGIS_CAIDO_API_URL`` (e.g. ``http://caido-assessment:8082``)
and ``AEGIS_CAIDO_API_TOKEN``. ``AEGIS_CAIDO_IMPORT_FILTER`` optionally adds an
HTTPQL clause (for example a time window) that is AND-ed with the host filter.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

DEFAULT_LIMIT = 200
HARD_LIMIT = 1000
PAGE_SIZE = 100
_RESPONSE_BODY_CHARS = 500

_STATIC_EXT = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|mp4|webm|mp3)$",
    re.I,
)
_KEEP_REQUEST_HEADERS = {
    "content-type", "accept", "x-requested-with", "origin", "cookie", "authorization",
}
_SECRET_HEADERS = {"authorization", "x-api-key", "x-auth-token", "proxy-authorization"}
# Markers Prowl itself sends; their traffic is not analyst browsing.
_PROWL_MARKERS = re.compile(
    r"^(?:x-prowl-probe|x-aegis-verify)\s*:|^user-agent\s*:.*(?:aegis-vanguard|judahasm|"
    r"security assessment|authorized security test|victim simulation|race condition test)",
    re.I | re.M,
)

_QUERY = """
query ProwlCaidoImport($first: Int!, $after: String, $filter: HTTPQLInput) {
  requests(first: $first, after: $after, filter: $filter) {
    pageInfo { hasNextPage endCursor }
    edges { node {
      id host port path query method isTls source raw
      response { statusCode raw }
    } }
  }
}
"""


class CaidoImportError(RuntimeError):
    """Caido is not configured, unreachable, or returned an error."""


def caido_api_config() -> Optional[Tuple[str, str]]:
    url = os.environ.get("AEGIS_CAIDO_API_URL", "").strip().rstrip("/")
    token = os.environ.get("AEGIS_CAIDO_API_TOKEN", "").strip()
    if not url or not token:
        return None
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
        raise CaidoImportError("AEGIS_CAIDO_API_URL must be an http(s) URL without credentials")
    if not parsed.path.endswith("/graphql"):
        url = f"{url}/graphql"
    return url, token


def scope_apex(target: str) -> str:
    host = (urlsplit(target if "://" in target else f"//{target}").hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _in_scope(host: str, apex: str) -> bool:
    host = (host or "").lower()
    return bool(apex) and (host == apex or host.endswith("." + apex))


def _decode_blob(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return value


def _split_http(raw: str) -> Tuple[str, Dict[str, str], str]:
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    lines = head.split("\n")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            key = name.strip().lower()
            headers[key] = f"{headers[key]}, {value.strip()}" if key in headers else value.strip()
    return (lines[0] if lines else ""), headers, body


def _redact_request_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name, value in headers.items():
        if name not in _KEEP_REQUEST_HEADERS and name not in _SECRET_HEADERS:
            continue
        if name in _SECRET_HEADERS:
            out[name] = "[redacted]"
        elif name == "cookie":
            names = [part.split("=", 1)[0].strip() for part in value.split(";") if part.strip()]
            out[name] = "; ".join(f"{n}=[redacted]" for n in names if n)
        else:
            out[name] = value[:200]
    return out


def _redact_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for name, value in headers.items():
        if name == "set-cookie":
            names = re.findall(r"(?:^|,\s*)([^=;,\s]+)=", value)
            out[name] = ", ".join(f"{n}=[redacted]" for n in names)
        else:
            out[name] = value[:200]
    return out


def samples_from_caido_nodes(nodes: Iterable[Dict[str, Any]], apex: str) -> List[Dict[str, Any]]:
    """Turn Caido ``Request`` nodes into redacted fingerprint samples."""
    samples: List[Dict[str, Any]] = []
    seen = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        host = str(node.get("host") or "").lower()
        path = str(node.get("path") or "/")
        method = str(node.get("method") or "GET").upper()
        if not _in_scope(host, apex) or _STATIC_EXT.search(path):
            continue
        _, req_headers, _ = _split_http(_decode_blob(node.get("raw")))
        raw_head = "\n".join(f"{k}: {v}" for k, v in req_headers.items())
        if _PROWL_MARKERS.search(raw_head):
            continue
        key = (method, host, path)
        if key in seen:
            continue
        seen.add(key)
        scheme = "https" if node.get("isTls") else "http"
        port = node.get("port")
        default_port = 443 if scheme == "https" else 80
        netloc = host if not port or int(port) == default_port else f"{host}:{port}"
        query = str(node.get("query") or "")
        sample: Dict[str, Any] = {
            "method": method,
            "url": f"{scheme}://{netloc}{path}" + (f"?{query[:200]}" if query else ""),
            "headers": _redact_request_headers(req_headers),
            "source": "caido",
            "caido_request_id": str(node.get("id") or ""),
        }
        response = node.get("response") or {}
        if isinstance(response, dict) and response:
            _, resp_headers, body = _split_http(_decode_blob(response.get("raw")))
            sample["status"] = response.get("statusCode")
            sample["response_headers"] = _redact_response_headers(resp_headers)
            sample["response_body"] = body[:_RESPONSE_BODY_CHARS]
        samples.append(sample)
    return samples


def _host_filter(apex: str) -> str:
    if not re.fullmatch(r"[a-z0-9.-]+", apex):
        raise CaidoImportError("target host is not a valid hostname")
    clause = f'req.host.cont:"{apex}"'
    extra = os.environ.get("AEGIS_CAIDO_IMPORT_FILTER", "").strip()
    return f"({clause}) AND ({extra})" if extra else clause


async def fetch_caido_samples(target: str, *, limit: int = DEFAULT_LIMIT, client: Any = None) -> Dict[str, Any]:
    """Page through Caido history for ``target``'s apex and return redacted samples."""
    config = caido_api_config()
    if not config:
        raise CaidoImportError("Caido import is not configured (AEGIS_CAIDO_API_URL / AEGIS_CAIDO_API_TOKEN)")
    url, token = config
    apex = scope_apex(target)
    if not apex:
        raise CaidoImportError("a target host is required")
    limit = max(1, min(int(limit or DEFAULT_LIMIT), HARD_LIMIT))
    variables: Dict[str, Any] = {"first": min(PAGE_SIZE, limit), "after": None,
                                 "filter": {"code": _host_filter(apex)}}
    nodes: List[Dict[str, Any]] = []
    own_client = client is None
    if own_client:
        import httpx

        client = httpx.AsyncClient(timeout=30, trust_env=False)
    try:
        while len(nodes) < limit:
            resp = await client.post(
                url,
                json={"query": _QUERY, "variables": variables},
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code != 200:
                raise CaidoImportError(f"Caido API returned HTTP {resp.status_code}")
            payload = resp.json()
            if payload.get("errors"):
                message = str((payload["errors"][0] or {}).get("message") or "error")
                raise CaidoImportError(f"Caido API error: {message[:200]}")
            page = ((payload.get("data") or {}).get("requests")) or {}
            nodes.extend(edge.get("node") or {} for edge in page.get("edges") or [])
            info = page.get("pageInfo") or {}
            if not info.get("hasNextPage") or not info.get("endCursor"):
                break
            variables["after"] = info["endCursor"]
    finally:
        if own_client:
            await client.aclose()
    samples = samples_from_caido_nodes(nodes[:limit], apex)
    return {"apex": apex, "requests_read": len(nodes[:limit]), "samples": samples}
