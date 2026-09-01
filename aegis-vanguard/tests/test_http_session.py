"""Session store + replay + response-diff: the evidence substrate for authz.

The property under test: a captured request can be replayed under a changed or
stripped identity, and the response-diff is a structured, auditable artifact —
the thing that turns "I think this is IDOR" into machine-checkable proof.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent.http_session import (
    CaidoBackend,
    HttpRequest,
    HttpResponse,
    ProxyBackend,
    ScannersBackend,
    SessionStore,
    apply_mutations,
    get_session_store,
    reset_session,
    response_diff,
    response_from_scanner_dict,
    set_backend,
    set_session_store,
)

PRIVATE_BODY = "<h1>Account 1001</h1><p>SSN 555-01-1001, balance $9,000</p>"


class FakeBackend(ProxyBackend):
    """Deterministic backend for tests: a responder maps request → response."""

    name = "fake"

    def __init__(self, responder):
        self.responder = responder
        self.sent = []

    def send(self, request: HttpRequest) -> HttpResponse:
        self.sent.append(request)
        return self.responder(request)


class MutationTest(unittest.TestCase):
    def _req(self):
        return HttpRequest("GET", "http://t/api/account?id=1001",
                           {"Cookie": "session=alice", "Accept": "*/*"}, "")

    def test_replace_method_url_body(self):
        out = apply_mutations(self._req(), {"method": "POST", "url": "http://t/x",
                                            "body": "hi"})
        self.assertEqual((out.method, out.url, out.body), ("POST", "http://t/x", "hi"))

    def test_strip_auth_removes_only_auth_headers(self):
        out = apply_mutations(self._req(), {"strip_auth": True})
        self.assertNotIn("Cookie", out.headers)
        self.assertIn("Accept", out.headers)

    def test_set_headers_overwrite_case_insensitive_and_delete(self):
        out = apply_mutations(self._req(), {"set_headers": {"cookie": "session=bob",
                                                            "Accept": None}})
        self.assertEqual(out.headers.get("cookie"), "session=bob")
        self.assertNotIn("Cookie", out.headers)  # old casing replaced
        self.assertNotIn("Accept", out.headers)  # deleted

    def test_set_query_add_overwrite_delete(self):
        out = apply_mutations(self._req(), {"set_query": {"id": "1002", "debug": "1"}})
        self.assertIn("id=1002", out.url)
        self.assertIn("debug=1", out.url)
        self.assertNotIn("id=1001", out.url)
        out2 = apply_mutations(self._req(), {"set_query": {"id": None}})
        self.assertNotIn("id=", out2.url)

    def test_mutations_do_not_touch_the_original(self):
        base = self._req()
        apply_mutations(base, {"strip_auth": True, "url": "http://other"})
        self.assertIn("Cookie", base.headers)
        self.assertEqual(base.url, "http://t/api/account?id=1001")


class ResponseDiffTest(unittest.TestCase):
    def test_identical_responses(self):
        a = HttpResponse(200, {}, PRIVATE_BODY)
        d = response_diff(a, HttpResponse(200, {}, PRIVATE_BODY))
        self.assertTrue(d["identical_body"])
        self.assertEqual(d["body_similarity"], 1.0)
        self.assertFalse(d["status_changed"])

    def test_rejected_replay_reads_as_enforced(self):
        d = response_diff(HttpResponse(200, {}, PRIVATE_BODY),
                          HttpResponse(403, {}, "Forbidden"))
        self.assertTrue(d["status_changed"])
        self.assertIn("ENFORCED", d["summary"])

    def test_same_private_body_reads_as_possible_bac(self):
        d = response_diff(HttpResponse(200, {}, PRIVATE_BODY),
                          HttpResponse(200, {}, PRIVATE_BODY))
        self.assertIn("broken access control", d["summary"].lower())

    def test_replay_error_is_inconclusive(self):
        d = response_diff(HttpResponse(200, {}, PRIVATE_BODY),
                          HttpResponse(error="timeout"))
        self.assertIn("errored", d["summary"])


class SessionStoreTest(unittest.TestCase):
    def test_record_get_all_summary(self):
        store = SessionStore()
        t = store.record(HttpRequest("GET", "http://t/a"), HttpResponse(200, {}, "ok"))
        self.assertEqual(t.id, "txn-0001")
        self.assertIs(store.get("txn-0001"), t)
        self.assertEqual(len(store.all()), 1)
        self.assertEqual(store.summary()[0]["url"], "http://t/a")

    def test_exchange_sends_and_records(self):
        store = SessionStore()
        backend = FakeBackend(lambda r: HttpResponse(200, {}, "served"))
        t = store.exchange(backend, HttpRequest("GET", "http://t/a"))
        self.assertEqual(t.response.body, "served")
        self.assertEqual(len(backend.sent), 1)

    def test_persist_is_redacted_but_memory_is_full(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.jsonl"
            store = SessionStore(persist_path=str(path))
            store.record(
                HttpRequest("GET", "http://t/a", {"Cookie": "session=topsecret"}),
                HttpResponse(200, {}, "ok"),
            )
            on_disk = path.read_text()
            self.assertNotIn("topsecret", on_disk)          # redacted on disk
            self.assertIn("[redacted]", on_disk)
            self.assertEqual(                                # full in memory
                store.get("txn-0001").request.headers["Cookie"], "session=topsecret")

    def test_broken_access_control_scenario(self):
        """Base returns private data with a cookie; stripping auth still returns
        it → the diff flags possible broken access control."""
        store = SessionStore()
        backend = FakeBackend(lambda r: HttpResponse(200, {}, PRIVATE_BODY))  # ignores auth
        base = store.exchange(
            backend, HttpRequest("GET", "http://t/account?id=1001",
                                 {"Cookie": "session=alice"}))
        mutated = store.exchange(backend, apply_mutations(base.request, {"strip_auth": True}))
        d = response_diff(base.response, mutated.response)
        self.assertTrue(d["identical_body"])
        self.assertIn("broken access control", d["summary"].lower())

    def test_enforced_access_control_scenario(self):
        store = SessionStore()

        def responder(r):
            return HttpResponse(200, {}, PRIVATE_BODY) if "Cookie" in r.headers \
                else HttpResponse(403, {}, "Forbidden")

        backend = FakeBackend(responder)
        base = store.exchange(
            backend, HttpRequest("GET", "http://t/account", {"Cookie": "session=alice"}))
        mutated = store.exchange(backend, apply_mutations(base.request, {"strip_auth": True}))
        d = response_diff(base.response, mutated.response)
        self.assertIn("ENFORCED", d["summary"])


class BackendTest(unittest.TestCase):
    def test_scanners_backend_maps_dict(self):
        import scanners
        orig = scanners.run_send_http_request
        scanners.run_send_http_request = lambda **kw: {
            "status": 200, "headers": {"Server": "nginx"}, "body": "hi",
            "elapsed_ms": 12, "redirect_history": []}
        try:
            resp = ScannersBackend().send(HttpRequest("GET", "http://t"))
            self.assertEqual((resp.status, resp.body, resp.headers["Server"]),
                             (200, "hi", "nginx"))
        finally:
            scanners.run_send_http_request = orig

    def test_response_from_scanner_error_dict(self):
        resp = response_from_scanner_dict({"error": "blocked: internal/loopback"})
        self.assertFalse(resp.ok)
        self.assertIn("blocked", resp.error)

    def test_caido_backend_unconfigured_raises_actionable(self):
        with self.assertRaises(RuntimeError) as ctx:
            CaidoBackend(api_url="").send(HttpRequest("GET", "http://t"))
        self.assertIn("AEGIS_CAIDO_API", str(ctx.exception))


class SingletonTest(unittest.TestCase):
    def setUp(self):
        reset_session()

    def tearDown(self):
        reset_session()

    def test_set_and_get_share_store(self):
        store = set_session_store(SessionStore())
        get_session_store().record(HttpRequest("GET", "http://t"), HttpResponse(200))
        self.assertIs(get_session_store(), store)
        self.assertEqual(len(store.all()), 1)


class AgentToolWiringTest(unittest.TestCase):
    def setUp(self):
        reset_session()
        self.store = set_session_store(SessionStore())
        # Backend that serves the private body regardless of identity (vuln app).
        set_backend(FakeBackend(lambda r: HttpResponse(200, {}, PRIVATE_BODY)))

    def tearDown(self):
        reset_session()

    def test_send_records_then_replay_produces_diff(self):
        from agent import agents

        # send_http_request goes through scanners; stub it and the bridge.
        import scanners
        orig_send, orig_bridge = scanners.run_send_http_request, agents._get_bridge
        scanners.run_send_http_request = lambda **kw: {
            "status": 200, "headers": {}, "body": PRIVATE_BODY,
            "elapsed_ms": 5, "redirect_history": []}
        agents._get_bridge = lambda: None
        try:
            out = json.loads(agents.send_http_request(
                "GET", "http://t/account?id=1001",
                headers_json='{"Cookie": "session=alice"}'))
            self.assertEqual(out["transaction_id"], "txn-0001")

            listed = json.loads(agents.session_transactions())
            self.assertEqual(listed[0]["id"], "txn-0001")

            replay = json.loads(agents.replay_request(
                transaction_id="txn-0001", mutations_json='{"strip_auth": true}'))
            self.assertEqual(replay["backend"], "fake")
            self.assertIn("broken access control", replay["diff"]["summary"].lower())
        finally:
            scanners.run_send_http_request = orig_send
            agents._get_bridge = orig_bridge

    def test_replay_requires_id_or_url(self):
        from agent import agents
        out = json.loads(agents.replay_request())
        self.assertIn("error", out)


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    unittest.main()
