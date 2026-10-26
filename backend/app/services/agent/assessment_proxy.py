"""Explicit, certificate-verified proxy for target assessment traffic only.

Do not set process-wide HTTP_PROXY: the backend also calls model providers and
internal services. Callers opt in when sending an in-scope target request.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path
from urllib.parse import urlsplit


def assessment_proxy_url() -> str | None:
    value = os.environ.get("AEGIS_ASSESSMENT_PROXY_URL", "").strip()
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "http"
            and bool(parsed.hostname)
            and parsed.port is not None
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
            and not any(char.isspace() for char in value)
        )
    except ValueError as exc:
        raise ValueError("Invalid AEGIS_ASSESSMENT_PROXY_URL") from exc
    if not valid:
        raise ValueError("AEGIS_ASSESSMENT_PROXY_URL must be an HTTP proxy URL without credentials or a path")
    return value.rstrip("/")


def assessment_ca_bundle(proxy_url: str | None) -> str | bool:
    bundle = os.environ.get("AEGIS_ASSESSMENT_CA_BUNDLE", "").strip()
    insecure = os.environ.get("AEGIS_ALLOW_INSECURE_TLS", "").lower() in ("1", "true", "yes")
    if proxy_url:
        if insecure:
            raise ValueError("Assessment proxy requires TLS verification; disable AEGIS_ALLOW_INSECURE_TLS")
        if not bundle or not Path(bundle).is_file():
            raise ValueError("Assessment proxy requires a readable AEGIS_ASSESSMENT_CA_BUNDLE")
        return bundle
    return False if insecure else (bundle or True)


def assessment_httpx_options() -> dict:
    proxy_url = assessment_proxy_url()
    options = {"verify": assessment_ca_bundle(proxy_url), "trust_env": False}
    if proxy_url:
        import httpx

        argument = "proxy" if "proxy" in inspect.signature(httpx.AsyncClient).parameters else "proxies"
        options[argument] = proxy_url
    return options


def assessment_urllib_handlers() -> list:
    """Build a target-only urllib opener with Caido's CA when configured."""
    import ssl
    from urllib.request import HTTPSHandler, ProxyHandler

    proxy_url = assessment_proxy_url()
    certificate = assessment_ca_bundle(proxy_url)
    handlers = [ProxyHandler({"http": proxy_url, "https": proxy_url} if proxy_url else {})]
    if isinstance(certificate, str):
        handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=certificate)))
    return handlers


def assessment_browser_proxy() -> dict | None:
    proxy_url = assessment_proxy_url()
    if proxy_url:
        assessment_ca_bundle(proxy_url)
        return {"server": proxy_url}
    return None
