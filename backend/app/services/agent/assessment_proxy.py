"""Explicit, certificate-verified proxy for target assessment traffic only.

Do not set process-wide HTTP_PROXY: the backend also calls model providers and
internal services. Callers opt in when sending an in-scope target request.
"""

from __future__ import annotations

import inspect
import io
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

PROXY_PAGE_SCAN_BYTES = 20000


class AssessmentProxyAnswered(RuntimeError):
    """The assessment proxy answered with its own error page; the target never did.

    Recording that page as the target's response gives every request the same
    fake 500, so replays, mutations and comparisons all look identical.
    """


def proxy_answered(status: int | None, headers: dict | None, body: str = "",
                   title: str = "") -> bool:
    """True when a 5xx response came from the assessment proxy (Caido), not the target."""
    if status is None or status < 500 or not assessment_proxy_url():
        return False
    if not title and body:
        match = re.search(r"<title[^>]*>(.*?)</title>", body[:PROXY_PAGE_SCAN_BYTES], re.I | re.S)
        title = match.group(1).strip() if match else ""
    lowered = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    return (
        "caido" in (title or "").lower()
        or "caido" in lowered.get("server", "")
        or any(name.startswith("x-caido") for name in lowered)
    )


def proxy_page_reason(body: str) -> str:
    """Visible text of the proxy's error page, so the run says why the proxy failed."""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", body[:PROXY_PAGE_SCAN_BYTES])
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:300]


def proxy_answered_message(status: int | None, url: str, body: str = "") -> str:
    reason = proxy_page_reason(body)
    return (
        f"The assessment proxy (AEGIS_ASSESSMENT_PROXY_URL) returned its own HTTP {status} "
        f"page for {urlsplit(url).path or '/'} instead of the target's response. Nothing "
        "reached the target, so this is not evidence about the target. Check that the proxy "
        "has an active project and can reach the target (DNS, outbound network, upstream TLS)."
        + (f" Proxy page said: {reason}" if reason else "")
    )


def _forget_readiness(url: str) -> None:
    from app.services.agent.assessment_proxy_bootstrap import invalidate

    invalidate(url)


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


async def _reject_proxy_error_page(response) -> None:
    """httpx response hook: never let the proxy's own error page pass as the target's."""
    if response.status_code < 500:
        return
    await response.aread()
    body = response.text or ""
    if proxy_answered(response.status_code, dict(response.headers), body):
        url = str(response.request.url)
        _forget_readiness(url)
        raise AssessmentProxyAnswered(proxy_answered_message(response.status_code, url, body))


def assessment_httpx_options() -> dict:
    """Options for an httpx.AsyncClient that sends in-scope target traffic."""
    proxy_url = assessment_proxy_url()
    options = {"verify": assessment_ca_bundle(proxy_url), "trust_env": False}
    if proxy_url:
        import httpx

        argument = "proxy" if "proxy" in inspect.signature(httpx.AsyncClient).parameters else "proxies"
        options[argument] = proxy_url
        options["event_hooks"] = {"response": [_reject_proxy_error_page]}
    return options


def _proxy_error_page_handler():
    from urllib.request import BaseHandler
    from urllib.response import addinfourl

    class ProxyErrorPageHandler(BaseHandler):
        # Before HTTPErrorProcessor (1000) turns a 5xx into an HTTPError that
        # probes would record as the target's answer.
        handler_order = 900

        def http_response(self, request, response):
            if response.code < 500:
                return response
            data = response.read()
            body = data[:PROXY_PAGE_SCAN_BYTES].decode("utf-8", "replace")
            if proxy_answered(response.code, dict(response.headers), body):
                url = request.full_url
                _forget_readiness(url)
                raise AssessmentProxyAnswered(proxy_answered_message(response.code, url, body))
            replay = addinfourl(io.BytesIO(data), response.headers, response.url, response.code)
            replay.msg = getattr(response, "msg", "")
            return replay

        https_response = http_response

    return ProxyErrorPageHandler()


def assessment_urllib_handlers() -> list:
    """Build a target-only urllib opener with Caido's CA when configured."""
    import ssl
    from urllib.request import HTTPSHandler, ProxyHandler

    proxy_url = assessment_proxy_url()
    certificate = assessment_ca_bundle(proxy_url)
    handlers = [ProxyHandler({"http": proxy_url, "https": proxy_url} if proxy_url else {})]
    if isinstance(certificate, str):
        handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=certificate)))
    if proxy_url:
        handlers.append(_proxy_error_page_handler())
    return handlers


def assessment_browser_proxy() -> dict | None:
    proxy_url = assessment_proxy_url()
    if proxy_url:
        assessment_ca_bundle(proxy_url)
        return {"server": proxy_url}
    return None
