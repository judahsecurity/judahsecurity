"""MCP client handshake helpers — no live Burp required."""

from app.services.agent.mcp_client import _decode_rpc_body, _key, _parse_sse_endpoint, list_sessions


class _FakeResp:
    def __init__(self, text="", content_type="application/json", json_body=None):
        self.text = text
        self.headers = {"content-type": content_type}
        self._json = json_body if json_body is not None else {}

    def json(self):
        if self._json is None:
            raise ValueError("not json")
        return self._json


def test_parse_sse_endpoint_relative():
    url = _parse_sse_endpoint(
        "event: endpoint\ndata: /messages?sessionId=abc",
        "http://127.0.0.1:9876/sse",
    )
    assert url == "http://127.0.0.1:9876/messages?sessionId=abc"


def test_parse_sse_endpoint_absolute():
    url = _parse_sse_endpoint(
        "event: endpoint\ndata: http://127.0.0.1:9876/mcp",
        "http://127.0.0.1:9876/sse",
    )
    assert url == "http://127.0.0.1:9876/mcp"


def test_decode_event_stream_json():
    resp = _FakeResp(
        text="event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]}}\n\n",
        content_type="text/event-stream",
    )
    body = _decode_rpc_body(resp)
    assert body["result"]["tools"] == []


def test_session_key_and_empty_list():
    assert _key(7, "Burp") == "7:burp"
    assert list_sessions(999_001) == []
