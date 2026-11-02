"""Caido history import: in-scope, redacted, Prowl's own probes excluded."""

import asyncio
import base64

import pytest

from app.services.agent import caido_import
from app.services.agent.api_fingerprint import fingerprint_from_map
from app.services.agent.caido_import import (
    CaidoImportError,
    fetch_caido_samples,
    samples_from_caido_nodes,
)


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _node(host, path, req_headers="", status=200, resp_headers="Server: nginx", body="{}",
          method="GET", node_id="1", port=443, tls=True, query=""):
    raw_req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{req_headers}\r\n\r\nsecret-body"
    raw_resp = f"HTTP/1.1 {status} OK\r\n{resp_headers}\r\n\r\n{body}"
    return {"id": node_id, "host": host, "port": port, "path": path, "query": query,
            "method": method, "isTls": tls, "source": "INTERCEPT", "raw": _b64(raw_req),
            "response": {"statusCode": status, "raw": _b64(raw_resp)}}


def test_scope_static_and_dedupe():
    nodes = [
        _node("api.example.com", "/v1/users"),
        _node("api.example.com", "/v1/users", node_id="2"),
        _node("app.example.com", "/static/main.js"),
        _node("evil-example.com", "/v1/x"),
        _node("api.example.com", "/v1/users", method="POST", node_id="3"),
    ]
    samples = samples_from_caido_nodes(nodes, "example.com")
    assert [(s["method"], s["url"]) for s in samples] == [
        ("GET", "https://api.example.com/v1/users"),
        ("POST", "https://api.example.com/v1/users"),
    ]
    assert all(s["source"] == "caido" for s in samples)


def test_credentials_redacted_and_request_body_dropped():
    node = _node(
        "api.example.com", "/v1/me",
        req_headers="Authorization: Bearer abc.def\r\nCookie: sid=s3cret; theme=dark\r\nX-Custom: 1",
        resp_headers="Set-Cookie: JSESSIONID=zzz; Path=/\r\nX-Powered-By: Express",
    )
    (sample,) = samples_from_caido_nodes([node], "example.com")
    flat = repr(sample)
    for secret in ("abc.def", "s3cret", "zzz", "secret-body"):
        assert secret not in flat
    assert sample["headers"]["authorization"] == "[redacted]"
    assert sample["headers"]["cookie"] == "sid=[redacted]; theme=[redacted]"
    assert "x-custom" not in sample["headers"]
    assert sample["response_headers"]["set-cookie"] == "JSESSIONID=[redacted]"
    assert sample["response_headers"]["x-powered-by"] == "Express"


@pytest.mark.parametrize("marker", [
    "X-Prowl-Probe: abc", "X-Aegis-Verify: n1", "User-Agent: aegis-vanguard/1.0",
    "User-Agent: Mozilla/5.0 (Security Assessment)",
])
def test_prowl_own_traffic_skipped(marker):
    assert samples_from_caido_nodes([_node("example.com", "/api/x", req_headers=marker)], "example.com") == []


def test_non_default_port_kept_in_url():
    (sample,) = samples_from_caido_nodes(
        [_node("example.com", "/api", port=8443, query="a=1")], "example.com")
    assert sample["url"] == "https://example.com:8443/api?a=1"


def test_fingerprint_marks_caido_samples_as_leads():
    samples = samples_from_caido_nodes(
        [_node("api.example.com", "/api/v1/users", resp_headers="X-Powered-By: Express")],
        "example.com")
    report = fingerprint_from_map({"target": "https://example.com"}, target="https://example.com",
                                  caido_samples=samples)
    assert report["caido_sample_count"] == 1
    assert "not finding evidence" in report["note"]
    assert any(c["host"] == "api.example.com" for c in report["api_host_candidates"])


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status

    def json(self):
        return self.payload


class FakeClient:
    def __init__(self, pages):
        self.pages, self.posts = list(pages), []

    async def post(self, url, json=None, headers=None):
        self.posts.append((url, json, headers))
        return FakeResponse(self.pages.pop(0))


def _page(nodes, cursor=None):
    return {"data": {"requests": {
        "pageInfo": {"hasNextPage": bool(cursor), "endCursor": cursor},
        "edges": [{"node": n} for n in nodes]}}}


def test_fetch_paginates_and_filters(monkeypatch):
    monkeypatch.setenv("AEGIS_CAIDO_API_URL", "http://caido-assessment:8082")
    monkeypatch.setenv("AEGIS_CAIDO_API_TOKEN", "tok")
    monkeypatch.setenv("AEGIS_CAIDO_IMPORT_FILTER", 'req.created_at.gt:"2026-11-01T00:00:00Z"')
    client = FakeClient([_page([_node("www.example.com", "/api/a")], cursor="c1"),
                         _page([_node("www.example.com", "/api/b", node_id="2")])])
    out = asyncio.run(fetch_caido_samples("https://www.example.com/", client=client))
    assert out["apex"] == "example.com" and out["requests_read"] == 2
    assert len(out["samples"]) == 2
    url, body, headers = client.posts[0]
    assert url == "http://caido-assessment:8082/graphql"
    assert headers["Authorization"] == "Bearer tok"
    assert body["variables"]["filter"]["code"] == (
        '(req.host.cont:"example.com") AND (req.created_at.gt:"2026-11-01T00:00:00Z")')
    assert client.posts[1][1]["variables"]["after"] == "c1"


def test_fetch_errors(monkeypatch):
    monkeypatch.delenv("AEGIS_CAIDO_API_URL", raising=False)
    with pytest.raises(CaidoImportError):
        asyncio.run(fetch_caido_samples("example.com", client=FakeClient([])))
    monkeypatch.setenv("AEGIS_CAIDO_API_URL", "http://caido:8082/graphql")
    monkeypatch.setenv("AEGIS_CAIDO_API_TOKEN", "tok")
    client = FakeClient([{"errors": [{"message": "Unauthorized"}]}])
    with pytest.raises(CaidoImportError, match="Unauthorized"):
        asyncio.run(fetch_caido_samples("example.com", client=client))
    with pytest.raises(CaidoImportError):
        caido_import._host_filter('x" OR "1')
