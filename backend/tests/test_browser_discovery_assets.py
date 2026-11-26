"""Discovery crawls skip binary assets and Chromium stays quiet.

A crawled page used to load every product image, font and media file through
the assessment proxy, so a 12-page crawl spent ~750 target requests. Crawls
need links, forms and scripts only.
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services.agent.scoped_assessment.browser_runtime import QUIET_CHROMIUM_ARGS, launch_options


def test_launch_disables_chromium_background_traffic(monkeypatch):
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_URL", raising=False)
    args = launch_options()["args"]
    assert "--disable-background-networking" in args
    assert "--disable-component-update" in args
    assert args == list(QUIET_CHROMIUM_ARGS)


PAGE = b"""<!doctype html><html><head><title>Shop</title>
<link rel="stylesheet" href="/style.css">
<style>@font-face { font-family: X; src: url(/font.woff2); } body { font-family: X; }</style>
<script src="/app.js"></script></head><body>
<img src="/product1.png"><img src="/product2.png"><img src="/tracker.gif?searchTerms=x">
<video src="/clip.mp4" autoplay muted></video>
<a href="/catalog?category=gin">Gin</a>
</body></html>"""
TYPES = {"/style.css": "text/css", "/app.js": "application/javascript",
         "/product1.png": "image/png", "/product2.png": "image/png",
         "/font.woff2": "font/woff2", "/clip.mp4": "video/mp4", "/tracker.gif": "image/gif"}


@pytest.mark.skipif(os.environ.get("RUN_ASSESSMENT_BROWSER_TESTS") != "1",
                    reason="Opt-in local Chromium fixture")
@pytest.mark.asyncio
async def test_crawl_skips_images_fonts_and_media(monkeypatch):
    pytest.importorskip("playwright")
    from app.services.agent.scoped_assessment.browser import check_browser

    monkeypatch.setattr("app.services.agent.assessment_proxy.assessment_proxy_url", lambda: None)
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            hits.append(path)
            body = b"body{}" if path in TYPES else PAGE
            self.send_response(200)
            self.send_header("Content-Type", TYPES.get(path, "text/html"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        result, _ = await check_browser(operation="crawl", url=base + "/",
                                        allowed_origins=[base], max_pages=2)
    finally:
        server.shutdown()

    assert "/style.css" in hits and "/app.js" in hits
    # An image with a query string can carry an input, so it still loads.
    assert "/tracker.gif" in hits
    assert not {"/product1.png", "/product2.png", "/font.woff2", "/clip.mp4"} & set(hits)
    # Links are still discovered and followed.
    assert "/catalog" in hits
    assert result["pages_visited"] == 2
