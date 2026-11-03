"""The in-container crawler routes through the assessment Caido proxy when set."""

import pytest

from app.services import deep_crawl_service


def _set_proxy(monkeypatch, tmp_path):
    ca = tmp_path / "caido-ca.crt"
    ca.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", "http://caido-assessment:8082")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", str(ca))
    monkeypatch.delenv("AEGIS_ALLOW_INSECURE_TLS", raising=False)


def test_no_proxy_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_URL", raising=False)
    assert deep_crawl_service._assessment_launch_kwargs() == {}


def test_proxy_kwargs_when_configured(monkeypatch, tmp_path):
    _set_proxy(monkeypatch, tmp_path)
    assert deep_crawl_service._assessment_launch_kwargs() == {
        "proxy": {"server": "http://caido-assessment:8082"}}


def test_misconfigured_proxy_degrades_to_direct(monkeypatch):
    # Proxy set but CA bundle missing -> assessment_browser_proxy raises; the
    # crawler must still run (direct) rather than fail to launch.
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", "http://caido-assessment:8082")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", "/nonexistent/ca.crt")
    assert deep_crawl_service._assessment_launch_kwargs() == {}


@pytest.mark.asyncio
async def test_launch_passes_proxy_to_chromium(monkeypatch, tmp_path):
    _set_proxy(monkeypatch, tmp_path)
    seen = {}

    class _Chromium:
        async def launch(self, **kwargs):
            seen.update(kwargs)
            return "browser"

    class _PW:
        chromium = _Chromium()

    browser = await deep_crawl_service._launch_chromium(_PW())
    assert browser == "browser"
    assert seen.get("proxy") == {"server": "http://caido-assessment:8082"}
    assert seen.get("headless") is True
