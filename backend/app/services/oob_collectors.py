"""Callback collectors for out-of-band (OOB) proof.

A collector hands out one unique callback host per registration and reports
the DNS/HTTP/SMTP/LDAP interactions that reached it. Two providers exist:

* ``interactsh`` (default): ``interactsh_service`` sessions, unchanged. Each
  registration is a fresh interactsh-client session with its own payload
  domain.
* ``http_poll``: a self-hosted DNS/HTTP logger or webhook bin. Each
  registration mints a random token; the callback host is
  ``<token>.<AEGIS_OOB_DOMAIN>`` and the collector is polled with
  ``GET <AEGIS_OOB_POLL_URL>?token=<token>`` (Bearer ``AEGIS_OOB_POLL_KEY``
  when set). Poll responses are parsed leniently (a bare list, or a list under
  ``interactions`` / ``data`` / ``results`` / ``hits``, with alternate key
  names), as in the Vanguard harness.

The provider is chosen by operator settings only (``AEGIS_OOB_PROVIDER``).
Nothing the agent passes can switch it.

Correlation: an ``http_poll`` interaction is kept only when the probe's own
token appears in it (its id/host/query fields or its raw request). A collector
that ignores the ``token`` filter, or returns another probe's hits, cannot
attribute a callback to the wrong probe. Kept interactions carry the token in
``unique_id``, which is what ``proof_policy`` correlates on.

Both providers return the same shapes as ``interactsh_service`` (``register``:
success, session_id, payload_domain, payload_url, reused; ``poll``: success,
session_id, payload_domain, interactions[protocol, unique_id, remote_address,
timestamp, q_type, raw_request]).
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)

PROVIDERS = ("interactsh", "http_poll")
_PROVIDER_ALIASES = {"webhook": "http_poll", "generic": "http_poll", "http-poll": "http_poll"}

# (url, headers, timeout_seconds) -> parsed JSON. Raises on failure.
Transport = Callable[[str, dict[str, str], float], Any]

_MAX_SESSIONS = 64
_SESSION_TTL = 3600
_MAX_POLL_BYTES = 1_000_000
_MAX_ITEMS = 200
_DOMAIN_RE = re.compile(r"^(?=.{4,200}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class CallbackCollector(Protocol):
    name: str

    def register(self, server: str | None = None, token: str | None = None) -> dict[str, Any]: ...

    def poll(self, session_id: str) -> dict[str, Any]: ...

    def stop(self, session_id: str) -> dict[str, Any]: ...


class InteractshCollector:
    """The existing interactsh_service sessions (looked up at call time)."""

    name = "interactsh"

    def register(self, server: str | None = None, token: str | None = None) -> dict[str, Any]:
        from app.services import interactsh_service

        return interactsh_service.register(server, token)

    def poll(self, session_id: str) -> dict[str, Any]:
        from app.services import interactsh_service

        return interactsh_service.poll(session_id)

    def stop(self, session_id: str) -> dict[str, Any]:
        from app.services import interactsh_service

        return interactsh_service.stop(session_id)


# ---------------------------------------------------------------- http_poll

def _default_transport(url: str, headers: dict[str, str], timeout: float) -> Any:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(_MAX_POLL_BYTES + 1)
    if len(raw) > _MAX_POLL_BYTES:
        raise ValueError("collector response too large")
    return json.loads(raw.decode("utf-8", errors="replace") or "null")


def _first(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def parse_interactions(data: Any) -> list[dict[str, Any]]:
    """Parse a collector poll response into interaction dicts (lenient).

    Accepts a list of interaction objects, or a dict wrapping them under
    ``interactions`` / ``data`` / ``results`` / ``hits``. Unknown shapes parse
    to an empty list. Each item keeps its original JSON in ``_source`` for
    correlation.
    """
    items: Any = data
    if isinstance(data, dict):
        for key in ("interactions", "data", "results", "hits"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        else:
            items = []
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items[:_MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        source = json.dumps(item, default=str, sort_keys=True)
        out.append({
            "protocol": (_first(item, "protocol", "proto", "type") or "http").lower(),
            "unique_id": _first(item, "unique-id", "unique_id", "full-id", "full_id", "id",
                                "subdomain", "host", "token"),
            "remote_address": _first(item, "remote-address", "remote_address", "remote_addr",
                                     "source-ip", "source_ip", "client", "ip"),
            "timestamp": _first(item, "timestamp", "time", "ts", "created_at"),
            "q_type": _first(item, "q-type", "q_type", "qtype"),
            "raw_request": _first(item, "raw-request", "raw_request", "raw", "q", "query",
                                  "request")[:2000] or source[:2000],
            "_source": source,
        })
    return out


def correlate(interactions: list[dict[str, Any]], token: str) -> tuple[list[dict[str, Any]], int]:
    """Keep only interactions that carry ``token``; return (kept, dropped)."""
    needle = (token or "").lower()
    kept: list[dict[str, Any]] = []
    dropped = 0
    for item in interactions:
        source = str(item.get("_source") or "").lower()
        if not needle or needle not in source:
            dropped += 1
            continue
        row = {k: v for k, v in item.items() if k != "_source"}
        uid = str(row.get("unique_id") or "")
        row["unique_id"] = uid if needle in uid.lower() else token
        kept.append(row)
    return kept, dropped


@dataclass
class _Probe:
    session_id: str
    token: str
    payload_domain: str
    created_at: float = field(default_factory=time.time)
    seen: set = field(default_factory=set)


class HttpPollCollector:
    """Generic self-hosted collector: fresh token subdomain per probe, HTTP poll."""

    name = "http_poll"

    def __init__(self, *, domain: str, poll_url: str, poll_key: str | None = None,
                 transport: Transport | None = None, timeout: float = 15.0) -> None:
        self.domain = (domain or "").strip().strip(".").lower()
        self.poll_url = (poll_url or "").strip()
        self._key = (poll_key or "").strip() or None
        self._transport = transport or _default_transport
        self._timeout = timeout
        self._probes: dict[str, _Probe] = {}
        self._lock = threading.Lock()

    def config_error(self) -> str:
        if not self.domain or not self.poll_url:
            return ("http_poll OOB collector is not configured: set AEGIS_OOB_DOMAIN and "
                    "AEGIS_OOB_POLL_URL (optional AEGIS_OOB_POLL_KEY)")
        if not _DOMAIN_RE.match(self.domain):
            return "AEGIS_OOB_DOMAIN is not a valid DNS name"
        parts = urllib.parse.urlsplit(self.poll_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return "AEGIS_OOB_POLL_URL must be an absolute http(s) URL"
        return ""

    def _reap_locked(self) -> None:
        now = time.time()
        for sid in [s for s, p in self._probes.items() if now - p.created_at > _SESSION_TTL]:
            self._probes.pop(sid, None)

    def register(self, server: str | None = None, token: str | None = None) -> dict[str, Any]:
        # server/token belong to interactsh; this provider ignores them so the
        # agent cannot point it at another collector.
        error = self.config_error()
        if error:
            return {"success": False, "error": error}
        with self._lock:
            self._reap_locked()
            if len(self._probes) >= _MAX_SESSIONS:
                return {"success": False,
                        "error": f"Too many active OOB probes ({_MAX_SESSIONS}). Stop one first."}
            probe_token = secrets.token_hex(8)  # 16 hex chars, DNS-safe, per probe
            while any(p.token == probe_token for p in self._probes.values()):
                probe_token = secrets.token_hex(8)
            domain = f"{probe_token}.{self.domain}"
            probe = _Probe(session_id=f"hp-{probe_token}", token=probe_token, payload_domain=domain)
            self._probes[probe.session_id] = probe
        return {
            "success": True,
            "provider": self.name,
            "session_id": probe.session_id,
            "payload_domain": domain,
            "payload_url": f"http://{domain}/",
            "payload_email": f"aegis@{domain}",
            "server": "operator http_poll collector",
            "reused": False,
        }

    def poll(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            probe = self._probes.get(session_id)
        if probe is None:
            return {"success": False, "error": f"Unknown or expired session '{session_id}'. Register a new one."}
        sep = "&" if "?" in self.poll_url else "?"
        url = f"{self.poll_url}{sep}token={urllib.parse.quote(probe.token)}"
        headers = {"User-Agent": "prowl-oob-collector", "Accept": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        try:
            data = self._transport(url, headers, self._timeout)
        except Exception as exc:  # noqa: BLE001 — never raise from a poll
            logger.info("http_poll collector poll failed: %s", type(exc).__name__)
            return {"success": False, "session_id": session_id,
                    "payload_domain": probe.payload_domain,
                    "error": f"collector poll failed: {type(exc).__name__}", "interactions": []}
        try:
            parsed = parse_interactions(data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("http_poll collector returned an unparseable response: %s", exc)
            parsed = []
        kept, dropped = correlate(parsed, probe.token)
        fresh = []
        for row in kept:
            key = json.dumps(row, sort_keys=True, default=str)
            if key in probe.seen:
                continue
            probe.seen.add(key)
            fresh.append(row)
        return {
            "success": True,
            "provider": self.name,
            "session_id": session_id,
            "payload_domain": probe.payload_domain,
            "alive": True,
            "new_interactions": len(fresh),
            "interactions": fresh,
            "uncorrelated_dropped": dropped,
        }

    def stop(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            ok = self._probes.pop(session_id, None) is not None
        return {"success": ok, "stopped": session_id} if ok else {
            "success": False, "error": f"Unknown session '{session_id}'"}


# ---------------------------------------------------------------- selection

_INTERACTSH = InteractshCollector()
_HTTP_POLL: HttpPollCollector | None = None
_HTTP_POLL_KEY: tuple = ()
_SELECT_LOCK = threading.Lock()


def provider_name(settings: Any) -> str:
    raw = str(getattr(settings, "AEGIS_OOB_PROVIDER", "") or "interactsh").strip().lower()
    raw = _PROVIDER_ALIASES.get(raw, raw)
    return raw if raw in PROVIDERS else ""


def get_collector(settings: Any = None, *, transport: Transport | None = None) -> Any:
    """The operator-configured collector. Unknown providers raise ValueError."""
    if settings is None:
        from app.core.config import get_settings

        settings = get_settings()
    name = provider_name(settings)
    if not name:
        raise ValueError(
            f"unsupported AEGIS_OOB_PROVIDER {getattr(settings, 'AEGIS_OOB_PROVIDER', '')!r}; "
            f"use one of {', '.join(PROVIDERS)}"
        )
    if name == "interactsh":
        return _INTERACTSH
    key = (
        str(getattr(settings, "AEGIS_OOB_DOMAIN", "") or ""),
        str(getattr(settings, "AEGIS_OOB_POLL_URL", "") or ""),
        str(getattr(settings, "AEGIS_OOB_POLL_KEY", "") or ""),
    )
    if transport is not None:
        return HttpPollCollector(domain=key[0], poll_url=key[1], poll_key=key[2], transport=transport)
    global _HTTP_POLL, _HTTP_POLL_KEY
    with _SELECT_LOCK:
        # One instance per configuration so a probe registered in one call can
        # be polled in a later one.
        if _HTTP_POLL is None or _HTTP_POLL_KEY != key:
            _HTTP_POLL = HttpPollCollector(domain=key[0], poll_url=key[1], poll_key=key[2])
            _HTTP_POLL_KEY = key
        return _HTTP_POLL


__all__ = [
    "PROVIDERS",
    "CallbackCollector",
    "HttpPollCollector",
    "InteractshCollector",
    "correlate",
    "get_collector",
    "parse_interactions",
    "provider_name",
]
