import sys
import types
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scanners


class _Bridge:
    def __init__(self):
        self.vulnerabilities = []
        self.flushed = 0

    def submit_vulnerability(self, **finding):
        self.vulnerabilities.append(finding)

    def flush(self):
        self.flushed += 1


# --- Pure case-builder --------------------------------------------------------

def test_build_cases_carries_classified_context_breakout():
    cases = scanners._build_xss_confirm_cases(
        "https://t.example/catalog?searchTerm=x",
        ["searchTerm"],
        ["attr_single"],
        "vanguardXSSabcdef",
    )
    assert len(cases) == 1
    case = cases[0]
    assert case["context"] == "attr_single"
    # single-quote attribute breakout, not the generic html_body payload
    assert case["payload"].startswith("'><img")
    # payload is injected into the named parameter
    val = dict(parse_qsl(urlparse(case["url"]).query))["searchTerm"]
    assert val == case["payload"]


def test_build_cases_dedupes_identical_payloads_and_falls_back_to_all():
    # No contexts given -> try every context, but html_body and raw_reflection
    # share a payload and must collapse to one case.
    cases = scanners._build_xss_confirm_cases(
        "https://t.example/?q=x", ["q"], [], "vanguardXSSabcdef"
    )
    payloads = [c["payload"] for c in cases]
    assert len(payloads) == len(set(payloads))  # no duplicate fetches
    assert len(cases) == 6  # 7 contexts, html_body == raw_reflection


def test_build_cases_unknown_context_falls_back_to_all():
    cases = scanners._build_xss_confirm_cases(
        "https://t.example/?q=x", ["q"], ["bogus_context"], "vanguardXSSabcdef"
    )
    assert len(cases) == 6


# --- Browser confirmation (fake Playwright) -----------------------------------

def _install_fake_playwright(monkeypatch, vulnerable_when):
    """Install a fake playwright whose page 'executes' (sets the marker) only when
    the decoded injected value satisfies vulnerable_when(value)."""

    class Page:
        def __init__(self):
            self.marker = None
            self.goto_urls = []

        def on(self, event, handler):
            pass

        def goto(self, url, **kwargs):
            self.goto_urls.append(url)
            q = dict(parse_qsl(urlparse(url).query))
            for value in q.values():
                if vulnerable_when(value):
                    self.marker = url
                    break

        def wait_for_timeout(self, _ms):
            pass

        def evaluate(self, script):
            if "undefined" in script:  # reset call
                self.marker = None
                return None
            return self.marker

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
    return page


def _single_quote_attr_vulnerable(value):
    # App that only executes when the payload breaks out of a single-quoted attribute.
    return value.startswith("'>") and "onerror=" in value


def test_confirm_verifies_single_quote_attribute_context(monkeypatch):
    _install_fake_playwright(monkeypatch, _single_quote_attr_vulnerable)
    bridge = _Bridge()
    result = scanners.run_confirm_xss_reflection(
        "https://t.example/catalog?searchTerm=x",
        bridge,
        param="searchTerm",
        contexts="attr_single",
    )
    assert result["confirmed"] is True
    assert result["count"] == 1
    finding = result["findings"][0]
    assert finding["context"] == "attr_single"
    assert finding["confirmed"] is True
    assert len(bridge.vulnerabilities) == 1
    submitted = bridge.vulnerabilities[0]
    assert submitted["confidence"] == "confirmed"
    assert "browser-confirmed" in submitted["tags"]
    assert "attr_single" in submitted["tags"]


def test_wrong_context_misses_what_right_context_catches(monkeypatch):
    # The same single-quote-only-vulnerable app is NOT confirmed when we only try
    # the generic contexts (html_body/attr_double) that test_dom_xss would use...
    _install_fake_playwright(monkeypatch, _single_quote_attr_vulnerable)
    miss = scanners.run_confirm_xss_reflection(
        "https://t.example/catalog?searchTerm=x",
        _Bridge(),
        param="searchTerm",
        contexts="html_body,attr_double",
    )
    assert miss["confirmed"] is False

    # ...but IS confirmed once the classified single-quote context is carried through.
    _install_fake_playwright(monkeypatch, _single_quote_attr_vulnerable)
    hit = scanners.run_confirm_xss_reflection(
        "https://t.example/catalog?searchTerm=x",
        _Bridge(),
        param="searchTerm",
        contexts="attr_single",
    )
    assert hit["confirmed"] is True


def test_confirm_no_params_is_ok_not_a_finding(monkeypatch):
    _install_fake_playwright(monkeypatch, lambda _v: True)
    result = scanners.run_confirm_xss_reflection(
        "https://t.example/static", _Bridge()
    )
    assert result["status"] == "ok"
    assert result["confirmed"] is False
    assert "no parameters" in result["error"]


def test_confirm_without_playwright_is_inconclusive(monkeypatch):
    # Force the inner import to fail.
    monkeypatch.setitem(sys.modules, "playwright", None)
    result = scanners.run_confirm_xss_reflection(
        "https://t.example/?q=x", _Bridge(), param="q"
    )
    assert result["status"] == "unavailable"
    assert result["inconclusive"] is True
    assert result["confirmed"] is False
