"""Target-only Caido routing keeps TLS verification and scope controls intact."""

from __future__ import annotations

import inspect
import ssl
from urllib.request import HTTPSHandler, ProxyHandler

import httpx
import pytest

from app.services.agent.assessment_proxy import (
    assessment_browser_proxy,
    assessment_httpx_options,
    assessment_proxy_url,
    assessment_urllib_handlers,
)
from app.services.agent.scoped_assessment.browser_runtime import launch_options


def test_proxy_is_disabled_without_explicit_configuration(monkeypatch):
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_URL", raising=False)
    monkeypatch.delenv("AEGIS_ASSESSMENT_CA_BUNDLE", raising=False)
    monkeypatch.delenv("AEGIS_ALLOW_INSECURE_TLS", raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://unrelated.test:8000")
    assert assessment_httpx_options() == {"verify": True, "trust_env": False}
    assert assessment_browser_proxy() is None
    assert "proxy" not in launch_options()
    handlers = assessment_urllib_handlers()
    assert len(handlers) == 1 and isinstance(handlers[0], ProxyHandler)
    assert handlers[0].proxies == {}


@pytest.mark.parametrize("value", [
    "https://caido:8082", "http://user:pass@caido:8082",
    "http://caido:8082/path", "http://caido:8082/?q=1",
    "http://caido", "http://caido:bad",
])
def test_proxy_url_rejects_unsupported_or_credentialed_values(monkeypatch, value):
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", value)
    with pytest.raises(ValueError, match="AEGIS_ASSESSMENT_PROXY_URL"):
        assessment_proxy_url()


def test_proxy_requires_ca_and_refuses_insecure_tls(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", "http://caido:8082")
    monkeypatch.delenv("AEGIS_ASSESSMENT_CA_BUNDLE", raising=False)
    with pytest.raises(ValueError, match="CA_BUNDLE"):
        assessment_httpx_options()
    bundle = tmp_path / "ca.crt"
    bundle.write_text("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", str(bundle))
    monkeypatch.setenv("AEGIS_ALLOW_INSECURE_TLS", "true")
    with pytest.raises(ValueError, match="TLS verification"):
        assessment_httpx_options()


def test_proxy_routes_httpx_and_browser_with_trusted_ca(monkeypatch, tmp_path):
    bundle = tmp_path / "ca.crt"
    bundle.write_text("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", "http://caido:8082")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", str(bundle))
    monkeypatch.delenv("AEGIS_ALLOW_INSECURE_TLS", raising=False)
    options = assessment_httpx_options()
    assert options["verify"] == str(bundle)
    assert options["trust_env"] is False
    proxy_key = "proxy" if "proxy" in inspect.signature(httpx.AsyncClient).parameters else "proxies"
    assert options[proxy_key] == "http://caido:8082"
    assert launch_options()["proxy"] == {"server": "http://caido:8082"}


def test_urllib_scoped_probes_use_caido_and_its_ca(monkeypatch, tmp_path):
    bundle = tmp_path / "ca.crt"
    bundle.write_text("placeholder")
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", "http://caido:8082")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", str(bundle))
    monkeypatch.delenv("AEGIS_ALLOW_INSECURE_TLS", raising=False)
    original_context = ssl.create_default_context
    seen = {}

    def context(*, cafile):
        seen["cafile"] = cafile
        return original_context()

    monkeypatch.setattr(ssl, "create_default_context", context)
    handlers = assessment_urllib_handlers()
    assert seen["cafile"] == str(bundle)
    assert isinstance(handlers[0], ProxyHandler)
    assert handlers[0].proxies == {
        "http": "http://caido:8082", "https": "http://caido:8082",
    }
    assert isinstance(handlers[1], HTTPSHandler)
