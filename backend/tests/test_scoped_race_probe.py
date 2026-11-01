"""The scoped race probe proves a TOCTOU limit overrun with a real server."""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from app.services.agent.scoped_assessment.race_probe import probe_race


def _make_server(*, enforce: bool):
    """A toy single-use store.

    With ``enforce`` the check-then-insert window carries a small delay, so a
    canary submitted in series is rejected the second time (single-use holds)
    while a concurrent burst slips through the window (the race). Without it the
    store simply dedupes, so neither series nor burst can overrun.
    """
    seen: list[str] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _canary(self) -> str:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            # Body is JSON {"coupon": "<canary>"}; pull the value crudely.
            return body.split('"coupon"', 1)[-1].strip(' :"}\n') if "coupon" in body else ""

        def do_POST(self):
            canary = self._canary()
            if enforce:
                already = canary in seen
                time.sleep(0.15)  # check-to-insert window the burst races through
                if already:
                    self.send_response(409)
                    self.end_headers()
                    return
                seen.append(canary)
            else:
                with lock:
                    if canary in seen:
                        self.send_response(409)
                        self.end_headers()
                        return
                    seen.append(canary)
            self.send_response(201)
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write((" ".join(seen)).encode("utf-8"))

        def do_DELETE(self):
            canary = urlsplit(self.path).path.rsplit("/", 1)[-1]
            with lock:
                while canary in seen:
                    seen.remove(canary)
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def _run(base: str) -> dict:
    return await probe_race(
        base + "/api/coupons", base + "/api/coupons",
        base + "/api/coupons/__PROWL_NONCE__",
        method="POST", field="coupon", allowed_origin=base, state=None,
        nonce="abc123", concurrency=8,
    )


@pytest.mark.asyncio
async def test_race_probe_confirms_concurrent_overrun():
    server, thread = _make_server(enforce=True)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        proof = await _run(base)
        assert proof["control"]["single_use_enforced"] is True
        assert proof["control"]["readback_count"] == 1
        assert proof["probe"]["overrun"] is True
        assert proof["probe"]["readback_count"] >= 2
        assert proof["proof_confirmed"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_race_probe_does_not_confirm_a_properly_locked_endpoint():
    server, thread = _make_server(enforce=False)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        proof = await _run(base)
        # A dedup-under-lock endpoint keeps exactly one of each canary.
        assert proof["probe"]["readback_count"] == 1
        assert proof["proof_confirmed"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_race_probe_rejects_a_cleanup_template_without_nonce():
    with pytest.raises(ValueError):
        await probe_race(
            "https://app.test/a", "https://app.test/a", "https://app.test/a/fixed",
            method="POST", field="coupon", allowed_origin="https://app.test",
            state=None, nonce="abc123", concurrency=4,
        )
