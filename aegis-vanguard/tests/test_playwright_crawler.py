import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scanners


class _Bridge:
    def __init__(self):
        self.urls = []
        self.flushed = False

    def submit_url(self, url, **metadata):
        self.urls.append(url)

    def flush(self):
        self.flushed = True


def test_initial_network_request_does_not_skip_start_page_links(monkeypatch):
    target = "https://app.example/"
    about = "https://app.example/about"

    class Page:
        def __init__(self):
            self.handler = None
            self.goto_calls = []
            self.current = ""

        def on(self, event, handler):
            assert event == "request"
            self.handler = handler

        def goto(self, url, **kwargs):
            self.current = url
            self.goto_calls.append(url)
            self.handler(types.SimpleNamespace(url=url))

        def eval_on_selector_all(self, selector, expression):
            return [about] if self.current == target else []

    page = Page()

    class Browser:
        def new_context(self, **kwargs):
            return types.SimpleNamespace(new_page=lambda: page)

        def close(self):
            pass

    playwright = types.SimpleNamespace(
        chromium=types.SimpleNamespace(launch=lambda **kwargs: Browser())
    )

    class Manager:
        def __enter__(self):
            return playwright

        def __exit__(self, *args):
            return False

    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: Manager()
    sync_api.TimeoutError = RuntimeError
    package = types.ModuleType("playwright")
    package.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    bridge = _Bridge()
    discovered = scanners.run_playwright_crawl_authenticated(target, bridge)

    # First goto is initial navigation; second proves BFS did not treat the
    # network callback as proof the page's anchors had already been crawled.
    assert page.goto_calls[:2] == [target, target]
    assert about in discovered
    assert bridge.flushed
