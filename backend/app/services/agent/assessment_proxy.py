"""Explicit, certificate-verified proxy for target assessment traffic only.

When Judah Gate is running, target traffic for a run goes to the run's Gate
lease (scope check, per-host pacing, request cap), and the Gate chains to the
configured Caido proxy itself.

Do not set process-wide HTTP_PROXY: the backend also calls model providers and
internal services. Callers opt in when sending an in-scope target request.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path
from urllib.parse import urlsplit


def _gate_lease():
    """The run's Judah Gate lease, when the Gate is running for this process."""
    try:
        from app.services.agent.judah_gate import current_lease
    except Exception:
        return None
    return current_lease()


def assessment_proxy_url() -> str | None:
    """Proxy for target traffic: the run's Judah Gate lease, else Caido, else none."""
    lease = _gate_lease()
    if lease is not None:
        from app.services.agent.judah_gate import lease_proxy_url

        return lease_proxy_url(lease)
    return _configured_proxy_url()


def configured_upstream_proxy() -> tuple[str | None, str | bool]:
    """Caido (or other) proxy that Judah Gate itself chains through, with its CA."""
    upstream = _configured_proxy_url()
    return upstream, assessment_ca_bundle(upstream, _for_gate_upstream=True)


def _configured_proxy_url() -> str | None:
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


def assessment_ca_bundle(proxy_url: str | None, *, _for_gate_upstream: bool = False) -> str | bool:
    lease = None if _for_gate_upstream else _gate_lease()
    if lease is not None and proxy_url:
        from app.services.agent.judah_gate_ca import ca_cert_path

        return str(ca_cert_path())
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
    lease = _gate_lease()
    if lease is not None:
        from app.services.agent.judah_gate import gate_address

        host, port = gate_address()
        return {"server": f"http://{host}:{port}", "username": lease.token, "password": "x"}
    proxy_url = assessment_proxy_url()
    if proxy_url:
        assessment_ca_bundle(proxy_url)
        return {"server": proxy_url}
    return None
