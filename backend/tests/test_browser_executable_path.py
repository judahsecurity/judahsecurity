"""Every agent browser honors the same Chromium executable setting."""

import asyncio

import playwright.async_api as pw_api

from app.services import browser_automation_service as service


class _Stop(Exception):
    pass


def _launch_kwargs(monkeypatch):
    seen = {}

    class Chromium:
        async def launch(self, **kwargs):
            seen.update(kwargs)
            raise _Stop

    class Context:
        chromium = Chromium()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(pw_api, "async_playwright", lambda: Context())
    try:
        asyncio.run(service.execute_browser_actions('[{"action": "navigate", "url": "https://a.test/"}]'))
    except _Stop:
        pass
    return seen


def test_configured_chromium_path_is_used(monkeypatch):
    for name in ("AEGIS_CHROMIUM_PATH", "PROWL_CHROMIUM_PATH", "CHROME_BIN"):
        monkeypatch.delenv(name, raising=False)
    assert "executable_path" not in _launch_kwargs(monkeypatch)
    monkeypatch.setenv("CHROME_BIN", "/opt/chrome-bin")
    assert _launch_kwargs(monkeypatch)["executable_path"] == "/opt/chrome-bin"
    monkeypatch.setenv("AEGIS_CHROMIUM_PATH", "/opt/aegis-chrome")
    assert _launch_kwargs(monkeypatch)["executable_path"] == "/opt/aegis-chrome"
