"""Crawls submit GET forms so their inputs get a real observed baseline.

Uses a real Chromium against a local server (skipped if Playwright or its
browser is unavailable).
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
    reason="Opt-in local Chromium fixture",
)
pytest.importorskip("playwright")

from app.services.agent.scoped_assessment.browser import (  # noqa: E402
    GET_FORM_OBSERVATION_VALUE, check_browser,
)

PAGE = b"""<!doctype html><html><head><title>Shop</title></head><body>
<form id="search" method="get" action="/catalog">
  <input type="text" name="searchTerm"><input type="hidden" name="category" value="all">
  <button>Search</button>
</form>
<form method="get" action="/delete-account"><input name="confirm"><button>Go</button></form>
<form method="post" action="/subscribe"><input name="email"><button>Subscribe</button></form>
</body></html>"""


def _server(hits):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802
            hits.append(("GET", self.path))
            parts = urlsplit(self.path)
            if parts.path == "/catalog" and parts.query:
                term = parse_qs(parts.query).get("searchTerm", [""])[0]
                body = f"<html><title>Results</title><p>Results for {term}</p></html>".encode()
            else:
                body = PAGE
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            hits.append(("POST", self.path))
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.asyncio
async def test_crawl_submits_safe_get_forms_and_records_baselines(monkeypatch):
    monkeypatch.setattr("app.services.agent.assessment_proxy.assessment_proxy_url", lambda: None)
    hits = []
    server = _server(hits)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        traffic, baselines = [], []
        result, _ = await check_browser(
            operation="crawl", url=base + "/", allowed_origins=[base], max_pages=1,
            traffic_exchanges=traffic, link_baselines=baselines,
        )
    finally:
        server.shutdown()

    observations = result["get_form_observations"]
    assert [o["form_path"] for o in observations] == ["/catalog"]
    assert observations[0]["fields"] == ["category", "searchTerm"]

    submitted = [path for method, path in hits if method == "GET" and path.startswith("/catalog?")]
    assert submitted, "the search form was submitted"
    query = parse_qs(urlsplit(submitted[0]).query)
    assert query["searchTerm"] == [GET_FORM_OBSERVATION_VALUE]
    assert query["category"] == ["all"], "hidden fields keep their real values"

    # Never a state-changing path, never a write method.
    assert not any(path.startswith("/delete-account") for _, path in hits)
    assert not any(method == "POST" for method, _ in hits)

    # The submitted request is now a baseline a probe can replay.
    assert any("searchTerm=" in url for url in baselines)
