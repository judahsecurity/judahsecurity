"""Caido integration: pull the full browse surface into the session store, and
replay through Caido's proxy. Parsing + ingest are tested with a mock transport;
live Caido is not required."""

import base64
import os
import unittest
from pathlib import Path

from agent.caido import (
    CaidoClient,
    httpql_for_host,
    ingest_caido_traffic,
    node_to_transaction,
    _node_url,
)
from agent.http_session import (
    CaidoBackend,
    HttpRequest,
    HttpResponse,
    SessionStore,
)


def _b64(s: bytes) -> str:
    return base64.b64encode(s).decode()


RAW_REQ = _b64(b"GET /api/users?id=1 HTTP/1.1\r\nHost: app.example.com\r\n"
               b"Cookie: JSESSIONID=abc\r\n\r\n")
RAW_RESP = _b64(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"X-Powered-By: Express\r\n\r\n{\"ok\":true}")
NODE = {
    "id": "1", "host": "app.example.com", "method": "GET", "path": "/api/users",
    "query": "id=1", "port": 443, "isTls": True, "raw": RAW_REQ,
    "response": {"statusCode": 200, "roundtripTime": 12, "raw": RAW_RESP},
}


class ParseTest(unittest.TestCase):
    def test_node_url(self):
        self.assertEqual(_node_url(NODE), "https://app.example.com/api/users?id=1")
        self.assertEqual(
            _node_url({"host": "h", "port": 8443, "isTls": True, "path": "/x"}),
            "https://h:8443/x")
        self.assertEqual(
            _node_url({"host": "h", "port": 80, "isTls": False, "path": "/"}),
            "http://h/")

    def test_node_to_transaction(self):
        req, resp = node_to_transaction(NODE)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.url, "https://app.example.com/api/users?id=1")
        self.assertEqual(req.headers.get("Cookie"), "JSESSIONID=abc")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("X-Powered-By"), "Express")
        self.assertIn("ok", resp.body)


class ClientIngestTest(unittest.TestCase):
    def _client(self, nodes):
        return CaidoClient(transport=lambda q, v: {"requestsByOffset": {"nodes": nodes}})

    def test_fetch_requests(self):
        nodes = self._client([NODE]).fetch_requests('req.host.cont:"app.example.com"')
        self.assertEqual(len(nodes), 1)

    def test_ingest_records_into_store(self):
        store = SessionStore()
        res = ingest_caido_traffic(store, self._client([NODE, NODE]),
                                   httpql_for_host("app.example.com"))
        self.assertEqual(res["ingested"], 2)
        self.assertEqual(res["hosts"], ["app.example.com"])
        self.assertEqual(len(store.all()), 2)
        # ingested transactions are usable by the rest of the stack
        self.assertEqual(store.all()[0].request.url, "https://app.example.com/api/users?id=1")

    def test_malformed_node_skipped(self):
        store = SessionStore()
        res = ingest_caido_traffic(store, self._client([None]), "x")
        self.assertEqual(res["ingested"], 0)


class BackendTest(unittest.TestCase):
    def test_send_via_injected_sender(self):
        b = CaidoBackend(sender=lambda r: HttpResponse(200, {}, "served via caido"))
        self.assertEqual(b.send(HttpRequest("GET", "http://t")).body, "served via caido")

    def test_unconfigured_raises_actionable(self):
        with self.assertRaises(RuntimeError) as ctx:
            CaidoBackend(proxy_url=None).send(HttpRequest("GET", "http://t"))
        self.assertIn("AEGIS_CAIDO_PROXY", str(ctx.exception))


class ToolTest(unittest.TestCase):
    def test_ingest_caido_tool_requires_target(self):
        from agent import agents
        import json
        out = json.loads(agents.ingest_caido())
        self.assertIn("error", out)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
