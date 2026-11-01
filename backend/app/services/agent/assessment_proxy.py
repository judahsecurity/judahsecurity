"""Explicit, certificate-verified proxy for target assessment traffic only.

Do not set process-wide HTTP_PROXY: the backend also calls model providers and
internal services. Callers opt in when sending an in-scope target request.
"""

from __future__ import annotations

import inspect
import logging
import os
import socket
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_WARNED_DIRECT = False


def _warn_if_direct(proxy_url: str | None) -> None:
    """Warn once per process when target traffic bypasses the capture proxy.

    When AEGIS_ASSESSMENT_PROXY_URL is unset the assessment transports send
    requests straight to the target with no capture. That silent fall-through
    is why a run's traffic can go unrecorded by Caido; surface it loudly.
    """
    global _WARNED_DIRECT
    if proxy_url is None and not _WARNED_DIRECT:
        _WARNED_DIRECT = True
        logger.warning(
            "AEGIS_ASSESSMENT_PROXY_URL is not set: assessment target traffic is "
            "going DIRECT to the target and is NOT being captured by Caido. Set "
            "AEGIS_ASSESSMENT_PROXY_URL to the Caido assessment proxy to capture "
            "this run's traffic."
        )


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
    _warn_if_direct(proxy_url)
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
    _warn_if_direct(proxy_url)
    certificate = assessment_ca_bundle(proxy_url)
    handlers = [ProxyHandler({"http": proxy_url, "https": proxy_url} if proxy_url else {})]
    if isinstance(certificate, str):
        handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=certificate)))
    return handlers


def assessment_browser_proxy() -> dict | None:
    proxy_url = assessment_proxy_url()
    _warn_if_direct(proxy_url)
    if proxy_url:
        assessment_ca_bundle(proxy_url)
        return {"server": proxy_url}
    return None


def assessment_proxy_status(timeout: float = 2.0) -> dict:
    """Confirm whether this run's target traffic can reach the capture proxy.

    The backend has no Caido API binding, so it cannot read back a capture
    count. What it *can* confirm — and previously did not expose anywhere — is
    whether an assessment proxy is configured at all and whether it is actually
    accepting connections. A zero "logged HTTP exchanges" ledger plus
    ``configured: false`` here means traffic went direct and nothing captured
    it; ``configured: true, reachable: true`` means the proxy is in the path
    (though Caido still only retains captures when a project database is
    selected). This is a reachability signal, not a retention guarantee.
    """
    try:
        proxy_url = assessment_proxy_url()
    except ValueError as exc:
        return {
            "configured": False, "reachable": False, "url": "",
            "capture_expected": False,
            "detail": f"invalid AEGIS_ASSESSMENT_PROXY_URL: {exc}",
        }
    if not proxy_url:
        return {
            "configured": False, "reachable": None, "url": "",
            "capture_expected": False,
            "detail": (
                "AEGIS_ASSESSMENT_PROXY_URL is not set; target traffic went "
                "direct to the target and was not captured by Caido"
            ),
        }
    parsed = urlsplit(proxy_url)
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=timeout):
            return {
                "configured": True, "reachable": True, "url": proxy_url,
                "capture_expected": True,
                "detail": (
                    "assessment proxy is configured and accepting connections; "
                    "Caido retains captures only when a project database is selected"
                ),
            }
    except OSError as exc:
        return {
            "configured": True, "reachable": False, "url": proxy_url,
            "capture_expected": False,
            "detail": f"assessment proxy configured but unreachable: {exc}",
        }
