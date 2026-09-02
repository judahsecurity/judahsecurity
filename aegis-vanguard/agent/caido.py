"""
Caido integration — capture the full browse surface, then hunt it.

The agent's own tools see only the requests they make. Caido, sitting as the
proxy in front of the browser, captures *everything* the page does — every XHR,
fetch, chunk, and API call the crawl triggered. This pulls that captured traffic
into our SessionStore, so fingerprint_stack / authz_matrix / analyze_js run over
the real, complete surface instead of the handful of requests a tool issued.

Two seams:
  • CaidoClient — talks to Caido's GraphQL API (HTTP POST, or the caido-graphql
    CLI), runs the requestsByOffset query, and decodes the base64 raw HTTP
    messages into HttpRequest/HttpResponse.
  • ingest_caido_traffic — records those transactions into the SessionStore.

Replay-through-Caido lives in http_session.CaidoBackend, which routes an
HttpRequest through Caido's proxy listener so replays are captured too.

GraphQL query and raw-message parsing follow the api-fingerprint-caido
collector (Caido's schema is version-stable for requestsByOffset).
"""

import base64
import json
import logging
import os
import subprocess
import urllib.request
from typing import Callable, List, Optional

from agent.http_session import HttpRequest, HttpResponse

logger = logging.getLogger("agent.caido")

_TRAFFIC_QUERY = """
query FingerprintTraffic($limit: Int, $offset: Int, $filter: HTTPQLInput) {
  requestsByOffset(limit: $limit, offset: $offset, filter: $filter) {
    nodes {
      id host method path query port isTls createdAt raw
      response { id statusCode length roundtripTime raw }
    }
  }
}
""".strip()


def _decode_blob(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except Exception:
        return value


def _parse_http_message(raw: str) -> dict:
    """Split a raw HTTP message into start line, headers dict, and body."""
    if not raw:
        return {"start_line": "", "headers": {}, "body": ""}
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    start_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    return {"start_line": start_line, "headers": headers, "body": body}


def _node_url(node: dict) -> str:
    scheme = "https" if node.get("isTls") else "http"
    host = node.get("host") or ""
    port = node.get("port")
    default = 443 if scheme == "https" else 80
    netloc = f"{host}:{port}" if port and port != default else host
    path = node.get("path") or "/"
    query = node.get("query") or ""
    return f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")


def node_to_transaction(node: dict):
    """Map one Caido request node → (HttpRequest, HttpResponse)."""
    req_msg = _parse_http_message(_decode_blob(node.get("raw")))
    resp = node.get("response") or {}
    resp_msg = _parse_http_message(_decode_blob(resp.get("raw")))
    request = HttpRequest(
        method=node.get("method") or (req_msg["start_line"].split(" ")[0] if req_msg["start_line"] else "GET"),
        url=_node_url(node),
        headers=req_msg["headers"],
        body=req_msg["body"],
    )
    response = HttpResponse(
        status=int(resp.get("statusCode") or 0),
        headers=resp_msg["headers"],
        body=resp_msg["body"],
        elapsed_ms=int(resp["roundtripTime"]) if resp.get("roundtripTime") is not None else None,
    )
    return request, response


class CaidoClient:
    """Queries Caido's GraphQL API. `transport` is injectable for tests:
    transport(query, variables) -> the GraphQL `data` dict."""

    def __init__(self, endpoint: Optional[str] = None, token: Optional[str] = None,
                 cli_path: Optional[str] = None,
                 transport: Optional[Callable[[str, dict], dict]] = None):
        self.endpoint = (endpoint or os.environ.get("AEGIS_CAIDO_API")
                         or "http://127.0.0.1:8080/graphql")
        self.token = token or os.environ.get("AEGIS_CAIDO_TOKEN")
        self.cli_path = cli_path or os.environ.get("AEGIS_CAIDO_CLI")
        self._transport = transport

    def call(self, query: str, variables: dict) -> dict:
        if self._transport is not None:
            return self._transport(query, variables)
        if self.cli_path:
            return self._call_cli(query, variables)
        return self._call_http(query, variables)

    def _call_http(self, query: str, variables: dict) -> dict:
        body = json.dumps({"query": query, "variables": variables}).encode()
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8", "ignore") or "{}")
        if payload.get("errors"):
            raise RuntimeError(f"Caido GraphQL error: {payload['errors']}")
        return payload.get("data", {}) or {}

    def _call_cli(self, query: str, variables: dict) -> dict:
        cmd = [self.cli_path, "--no-pretty", "call", query, "--variables", json.dumps(variables)]
        out = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if out.returncode != 0:
            raise RuntimeError(f"caido CLI failed: {out.stderr.strip() or out.stdout.strip()}")
        payload = json.loads(out.stdout)
        if payload.get("errors"):
            raise RuntimeError(f"Caido GraphQL error: {payload['errors']}")
        return payload.get("data", {}) or {}

    def fetch_requests(self, httpql: str, limit: int = 300, offset: int = 0) -> List[dict]:
        data = self.call(_TRAFFIC_QUERY,
                         {"limit": limit, "offset": offset, "filter": {"code": httpql}})
        return (data.get("requestsByOffset") or {}).get("nodes") or []


def httpql_for_host(host: str) -> str:
    return f'req.host.cont:"{host}"'


def ingest_caido_traffic(store, client: CaidoClient, httpql: str, limit: int = 300) -> dict:
    """Pull Caido-captured traffic into the SessionStore. Returns a summary."""
    nodes = client.fetch_requests(httpql, limit=limit)
    hosts = set()
    ingested = 0
    for node in nodes:
        try:
            request, response = node_to_transaction(node)
        except Exception as e:  # skip malformed nodes, never abort the ingest
            logger.debug("skip caido node: %s", e)
            continue
        store.record(request, response, label="caido")
        hosts.add(node.get("host") or "")
        ingested += 1
    return {"ingested": ingested, "hosts": sorted(h for h in hosts if h),
            "httpql": httpql}
