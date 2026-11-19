"""Judah Gate: one local egress point for Prowl's traffic to targets.

Every assessment request that is routed through the Gate is:

* **Bound to a run.** Each run gets a lease with its own token. Tools send it
  as proxy credentials, so the Gate is not an open proxy and every request is
  counted against the run that made it.
* **Checked against scope.** A request to a host outside the lease's allowed
  hosts gets ``403`` and never leaves the machine. This holds even when a tool
  ignores Prowl's own scope checks.
* **Paced per host.** A token bucket per (run, host) limits the request rate
  and in-flight requests. A ``429`` or ``503`` from the target backs that host
  off (``Retry-After`` when given, otherwise exponential with jitter).
* **Counted against a hard cap.** ``max_requests`` per run; once reached the
  Gate answers ``429`` with ``X-Judah-Gate: request-budget`` instead of
  contacting the target.

HTTPS is terminated with the private Judah Gate CA (see
:mod:`judah_gate_ca`) so pacing and counting apply to each request, not each
connection. The Gate's own connection to the target verifies TLS normally, and
chains through the Caido proxy when ``AEGIS_ASSESSMENT_PROXY_URL`` is set, so
capture keeps working.

Not covered: raw TCP tools (nmap, naabu, masscan) and anything that cannot be
pointed at an HTTP proxy. WebSocket upgrades and HTTP/2 are not proxied.

Configuration (environment):

* ``JUDAH_GATE_ENABLED=1`` starts the Gate with the API process.
* ``JUDAH_GATE_BIND`` (default ``127.0.0.1:8899``).
* ``JUDAH_GATE_PROFILE``: ``quiet`` | ``balanced`` (default) | ``aggressive``.
* ``JUDAH_GATE_MAX_REQUESTS`` per run (default 5000, 0 = no cap).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import random
import secrets
import threading
import time
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

import h11

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 25 * 1024 * 1024
MAX_PACE_WAIT_SECONDS = 60.0
MAX_BACKOFF_SECONDS = 120.0
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailer", "transfer-encoding", "upgrade", "proxy-connection",
})


@dataclass(frozen=True)
class Pace:
    rps: float
    burst: int
    inflight: int


PROFILES = {
    "quiet": Pace(rps=1.0, burst=2, inflight=1),
    "balanced": Pace(rps=5.0, burst=10, inflight=4),
    "aggressive": Pace(rps=20.0, burst=40, inflight=10),
}


def gate_enabled() -> bool:
    return os.environ.get("JUDAH_GATE_ENABLED", "").strip().lower() in ("1", "true", "yes")


def gate_bind() -> tuple[str, int]:
    raw = os.environ.get("JUDAH_GATE_BIND", "127.0.0.1:8899").strip()
    host, _, port = raw.rpartition(":")
    return (host or "127.0.0.1"), int(port or 8899)


def pace_for(profile: str = "", max_rps: Optional[float] = None) -> Pace:
    base = PROFILES.get((profile or os.environ.get("JUDAH_GATE_PROFILE", "")).lower(), PROFILES["balanced"])
    if max_rps and max_rps > 0 and max_rps < base.rps:
        return Pace(rps=float(max_rps), burst=max(1, min(base.burst, int(max_rps * 2))), inflight=base.inflight)
    return base


class HostPacer:
    """Token bucket plus backoff for one host within one run."""

    def __init__(self, pace: Pace, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.pace = pace
        self._clock = clock
        self._tokens = float(pace.burst)
        self._updated = clock()
        self.backoff_until = 0.0
        self.strikes = 0
        self._lock = asyncio.Lock()
        self.inflight = asyncio.Semaphore(max(1, pace.inflight))

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(float(self.pace.burst), self._tokens + (now - self._updated) * self.pace.rps)
        self._updated = now

    def wait_needed(self) -> float:
        """Seconds until a request may start (0 if it may start now)."""
        self._refill()
        backoff = max(0.0, self.backoff_until - self._clock())
        token_wait = 0.0 if self._tokens >= 1 else (1 - self._tokens) / max(self.pace.rps, 1e-6)
        return max(backoff, token_wait)

    async def acquire(self, max_wait: float = MAX_PACE_WAIT_SECONDS) -> tuple[bool, float]:
        """Take one token, waiting if needed. Returns ``(ok, waited_seconds)``."""
        waited = 0.0
        async with self._lock:
            while True:
                need = self.wait_needed()
                if need <= 0:
                    self._tokens -= 1
                    return True, waited
                if waited + need > max_wait:
                    return False, waited
                await asyncio.sleep(need)
                waited += need

    def note_status(self, status: int, retry_after: Optional[str] = None) -> float:
        """Record a response status; return the backoff applied (0 if none)."""
        if status not in (429, 503):
            self.strikes = 0
            return 0.0
        self.strikes += 1
        delay = None
        if retry_after:
            with suppress(ValueError):
                delay = float(retry_after.strip())
        if delay is None:
            delay = min(MAX_BACKOFF_SECONDS, 2 ** min(self.strikes, 7)) * (0.75 + random.random() * 0.5)
        delay = max(0.5, min(MAX_BACKOFF_SECONDS, delay))
        self.backoff_until = max(self.backoff_until, self._clock() + delay)
        return delay


def _host_allowed(host: str, allowed: Iterable[str]) -> bool:
    host = (host or "").lower().rstrip(".").strip("[]")
    for item in allowed:
        item = (item or "").lower().rstrip(".")
        if not item:
            continue
        if item.startswith("*."):
            if host.endswith(item[1:]) and host != item[2:]:
                return True
        elif host == item:
            return True
    return False


@dataclass
class GateLease:
    run_id: str
    token: str
    allowed_hosts: frozenset
    pace: Pace
    max_requests: int = 0
    expires_at: float = 0.0
    requests: int = 0
    denied_scope: int = 0
    denied_budget: int = 0
    denied_pace: int = 0
    backoffs: int = 0
    paced_seconds: float = 0.0
    by_host: Counter = field(default_factory=Counter)
    pacers: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def host_allowed(self, host: str) -> bool:
        return _host_allowed(host, self.allowed_hosts)

    def pacer(self, host: str) -> HostPacer:
        host = host.lower()
        pacer = self.pacers.get(host)
        if pacer is None:
            pacer = self.pacers[host] = HostPacer(self.pace)
        return pacer

    def take_request(self, host: str) -> bool:
        with self._lock:
            if self.max_requests and self.requests >= self.max_requests:
                self.denied_budget += 1
                return False
            self.requests += 1
            self.by_host[host.lower()] += 1
            return True

    @property
    def budget_exhausted(self) -> bool:
        return bool(self.max_requests) and self.requests >= self.max_requests

    def stats(self) -> dict:
        return {
            "requests": self.requests, "max_requests": self.max_requests,
            "denied_scope": self.denied_scope, "denied_budget": self.denied_budget,
            "denied_pace": self.denied_pace, "backoffs": self.backoffs,
            "paced_seconds": round(self.paced_seconds, 3),
            "by_host": dict(self.by_host.most_common(20)),
            "profile": {"rps": self.pace.rps, "burst": self.pace.burst, "inflight": self.pace.inflight},
        }


class GateRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_run: dict[str, GateLease] = {}
        self._by_token: dict[str, GateLease] = {}

    def open(self, run_id: str, allowed_hosts: Iterable[str], *, pace: Optional[Pace] = None,
             max_requests: Optional[int] = None, ttl_seconds: float = 4 * 3600) -> GateLease:
        hosts = frozenset(h.lower() for h in allowed_hosts if h)
        if max_requests is None:
            max_requests = int(os.environ.get("JUDAH_GATE_MAX_REQUESTS", "5000") or 0)
        with self._lock:
            lease = self._by_run.get(run_id)
            if lease is None:
                lease = GateLease(run_id=run_id, token=secrets.token_urlsafe(18), allowed_hosts=hosts,
                                  pace=pace or pace_for(), max_requests=max(0, int(max_requests)),
                                  expires_at=time.time() + ttl_seconds)
                self._by_run[run_id] = lease
                self._by_token[lease.token] = lease
            else:
                lease.allowed_hosts = hosts  # scope can only be what the run currently allows
                lease.expires_at = time.time() + ttl_seconds
            self._purge()
            return lease

    def by_token(self, token: str) -> Optional[GateLease]:
        with self._lock:
            lease = self._by_token.get(token or "")
        if lease and lease.expires_at < time.time():
            return None
        return lease

    def for_run(self, run_id: Optional[str]) -> Optional[GateLease]:
        if not run_id:
            return None
        with self._lock:
            return self._by_run.get(run_id)

    def close(self, run_id: str) -> Optional[GateLease]:
        with self._lock:
            lease = self._by_run.pop(run_id, None)
            if lease:
                self._by_token.pop(lease.token, None)
            return lease

    def _purge(self) -> None:
        now = time.time()
        for run_id in [r for r, lease in self._by_run.items() if lease.expires_at < now]:
            lease = self._by_run.pop(run_id)
            self._by_token.pop(lease.token, None)

    def reset(self) -> None:
        with self._lock:
            self._by_run.clear()
            self._by_token.clear()


registry = GateRegistry()
_RUNNING: dict[str, Any] = {}


def current_lease() -> Optional[GateLease]:
    """The Gate lease for the run in the current context, when the Gate is running."""
    if not _RUNNING.get("server"):
        return None
    try:
        from app.services.agent.action_ledger import active_run_id
    except Exception:
        return None
    return registry.for_run(active_run_id.get())


def lease_proxy_url(lease: GateLease) -> str:
    host, port = _RUNNING.get("address") or gate_bind()
    return f"http://{lease.token}:x@{host}:{port}"


def gate_address() -> Optional[tuple[str, int]]:
    return _RUNNING.get("address")


# ---------------------------------------------------------------------------
# Proxy server
# ---------------------------------------------------------------------------

class GateConflict(ValueError):
    """A tool call tried to bypass the Gate."""


class _Reject(Exception):
    def __init__(self, status: int, reason: str, *, header: str = "", extra: Optional[list] = None):
        super().__init__(reason)
        self.status, self.reason, self.header, self.extra = status, reason, header, extra or []


async def _next_event(conn: h11.Connection, reader: asyncio.StreamReader):
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            data = await reader.read(65536)
            conn.receive_data(data)
            continue
        return event


async def _send(conn: h11.Connection, writer: asyncio.StreamWriter, event) -> None:
    data = conn.send(event)
    if data:
        writer.write(data)
        await writer.drain()


async def _send_simple(conn, writer, status: int, text: str, *, header: str = "",
                       extra: Optional[list] = None, close: bool = True) -> None:
    body = (text + "\n").encode()
    headers = [("content-type", "text/plain; charset=utf-8"), ("content-length", str(len(body)))]
    if header:
        headers.append(("x-judah-gate", header))
    headers.extend(extra or [])
    if close:
        headers.append(("connection", "close"))
    with suppress(h11.LocalProtocolError):
        await _send(conn, writer, h11.Response(status_code=status, headers=headers))
        await _send(conn, writer, h11.Data(data=body))
        await _send(conn, writer, h11.EndOfMessage())


def _header(headers, name: bytes) -> Optional[str]:
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _lease_from_auth(headers) -> GateLease:
    raw = _header(headers, b"proxy-authorization") or ""
    scheme, _, value = raw.partition(" ")
    token = ""
    if scheme.lower() == "basic":
        with suppress(Exception):
            token = base64.b64decode(value.strip()).decode().split(":", 1)[0]
    lease = registry.by_token(token) if token else None
    if lease is None:
        raise _Reject(407, "Judah Gate: proxy credentials required", header="auth",
                      extra=[("proxy-authenticate", 'Basic realm="judah-gate"')])
    return lease


class JudahGate:
    def __init__(self, *, upstream_proxy: Optional[str] = None, upstream_verify: Any = True,
                 ca_directory: Any = None) -> None:
        self.upstream_proxy = upstream_proxy
        self.upstream_verify = upstream_verify
        self.ca_directory = ca_directory
        self._server: Optional[asyncio.base_events.Server] = None
        self._client = None

    def _http(self):
        if self._client is None:
            import inspect

            import httpx

            kwargs: dict = {"verify": self.upstream_verify, "trust_env": False,
                            "follow_redirects": False, "timeout": httpx.Timeout(60.0, connect=15.0)}
            if self.upstream_proxy:
                arg = "proxy" if "proxy" in inspect.signature(httpx.AsyncClient).parameters else "proxies"
                kwargs[arg] = self.upstream_proxy
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._handle_client, host, port)
        sock = self._server.sockets[0].getsockname()
        return sock[0], sock[1]

    async def close(self) -> None:
        if self._server:
            self._server.close()
            with suppress(Exception):
                await self._server.wait_closed()
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._serve(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, h11.RemoteProtocolError):
            pass
        except Exception:
            logger.exception("Judah Gate connection failed")
        finally:
            with suppress(Exception):
                writer.close()

    async def _serve(self, reader, writer) -> None:
        conn = h11.Connection(h11.SERVER)
        while True:
            event = await _next_event(conn, reader)
            if not isinstance(event, h11.Request):
                return
            try:
                lease = _lease_from_auth(event.headers)
                if event.method == b"CONNECT":
                    authority = event.target.decode("latin-1")
                    host, _, port = authority.rpartition(":")
                    host = host.strip("[]")
                    if not host or not port.isdigit():
                        raise _Reject(400, "Judah Gate: bad CONNECT target", header="bad-request")
                    if not lease.host_allowed(host):
                        lease.denied_scope += 1
                        raise _Reject(403, f"Judah Gate: {host} is outside this run's scope", header="scope")
                    await _next_event(conn, reader)  # EndOfMessage
                    await _send(conn, writer, h11.Response(status_code=200, headers=[]))
                    leftover, _closed = conn.trailing_data
                    await self._tunnel(reader, writer, lease, host, int(port), leftover)
                    return
                body = await self._read_body(conn, reader)
                url = event.target.decode("latin-1")
                if not url.startswith(("http://", "https://")):
                    raise _Reject(400, "Judah Gate: absolute URL required", header="bad-request")
                keep = await self._forward(conn, writer, lease, event, url, body)
            except _Reject as rej:
                await _send_simple(conn, writer, rej.status, rej.reason, header=rej.header, extra=rej.extra)
                return
            if not keep or conn.our_state is h11.MUST_CLOSE:
                return
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                return

    async def _read_body(self, conn, reader) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while True:
            event = await _next_event(conn, reader)
            if isinstance(event, h11.Data):
                size += len(event.data)
                if size > MAX_BODY_BYTES:
                    raise _Reject(413, "Judah Gate: request body too large", header="body")
                chunks.append(event.data)
            elif isinstance(event, h11.EndOfMessage):
                return b"".join(chunks)
            else:
                raise _Reject(400, "Judah Gate: malformed request", header="bad-request")

    async def _tunnel(self, reader, writer, lease: GateLease, host: str, port: int, leftover: bytes) -> None:
        from app.services.agent.judah_gate_ca import server_context

        if leftover:
            # A client must wait for the 200 before starting TLS.
            return
        await writer.start_tls(server_context(host, self.ca_directory))
        conn = h11.Connection(h11.SERVER)
        origin = f"https://{host}" + ("" if port == 443 else f":{port}")
        while True:
            event = await _next_event(conn, reader)
            if not isinstance(event, h11.Request):
                return
            try:
                if event.method == b"CONNECT":
                    raise _Reject(400, "Judah Gate: nested CONNECT", header="bad-request")
                body = await self._read_body(conn, reader)
                target = event.target.decode("latin-1")
                if not target.startswith("/"):
                    target = "/" + target if not target.startswith("http") else urlsplit(target).path or "/"
                keep = await self._forward(conn, writer, lease, event, origin + target, body)
            except _Reject as rej:
                await _send_simple(conn, writer, rej.status, rej.reason, header=rej.header, extra=rej.extra)
                return
            if not keep or conn.our_state is h11.MUST_CLOSE:
                return
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                return

    async def _forward(self, conn, writer, lease: GateLease, request: h11.Request, url: str, body: bytes) -> bool:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host or not lease.host_allowed(host):
            lease.denied_scope += 1
            raise _Reject(403, f"Judah Gate: {host or 'host'} is outside this run's scope", header="scope")
        if _header(request.headers, b"upgrade"):
            raise _Reject(501, "Judah Gate: protocol upgrades are not proxied", header="upgrade")
        if not lease.take_request(host):
            raise _Reject(429, "Judah Gate: this run's request budget is exhausted", header="request-budget")
        pacer = lease.pacer(host)
        ok, waited = await pacer.acquire()
        lease.paced_seconds += waited
        if not ok:
            lease.denied_pace += 1
            raise _Reject(429, f"Judah Gate: {host} is backing off; retry later", header="paced",
                          extra=[("retry-after", str(int(max(1, pacer.wait_needed()))))])
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers
                   if k.lower().decode("latin-1") not in _HOP_BY_HOP]
        async with pacer.inflight:
            client = self._http()
            try:
                upstream = await client.send(
                    client.build_request(request.method.decode(), url, headers=headers, content=body),
                    stream=True,
                )
            except Exception as exc:
                raise _Reject(502, f"Judah Gate: upstream error ({type(exc).__name__})", header="upstream")
            try:
                if pacer.note_status(upstream.status_code, upstream.headers.get("retry-after")):
                    lease.backoffs += 1
                out_headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in upstream.headers.raw
                               if k.lower().decode("latin-1") not in _HOP_BY_HOP]
                await _send(conn, writer, h11.Response(status_code=upstream.status_code, headers=out_headers,
                                                       reason=(upstream.reason_phrase or "").encode()))
                async for chunk in upstream.aiter_raw():
                    if chunk:
                        await _send(conn, writer, h11.Data(data=chunk))
                await _send(conn, writer, h11.EndOfMessage())
            finally:
                await upstream.aclose()
        return True


# ---------------------------------------------------------------------------
# Lifecycle and wiring helpers
# ---------------------------------------------------------------------------

async def start_gate_from_env() -> Optional[tuple[str, int]]:
    """Start the Gate in this process when ``JUDAH_GATE_ENABLED`` is set."""
    if not gate_enabled() or _RUNNING.get("server"):
        return _RUNNING.get("address")
    from app.services.agent.assessment_proxy import configured_upstream_proxy
    from app.services.agent.judah_gate_ca import ensure_ca

    upstream, verify = configured_upstream_proxy()
    ensure_ca()
    gate = JudahGate(upstream_proxy=upstream, upstream_verify=verify)
    host, port = gate_bind()
    address = await gate.start(host, port)
    _RUNNING.update(server=gate, address=address)
    logger.info("Judah Gate listening on %s:%s (upstream proxy: %s)", address[0], address[1],
                "yes" if upstream else "no")
    return address


async def stop_gate() -> None:
    gate = _RUNNING.pop("server", None)
    _RUNNING.pop("address", None)
    if gate:
        await gate.close()


def ensure_lease_for_run(run_id: Optional[str], allowed_hosts: Iterable[str], *,
                         max_rps: Optional[float] = None) -> Optional[GateLease]:
    """Open or refresh the run's lease. No-op when the Gate is not running."""
    if not run_id or not _RUNNING.get("server"):
        return None
    hosts = [h for h in allowed_hosts if h]
    if not hosts:
        return registry.for_run(run_id)
    return registry.open(run_id, hosts, pace=pace_for(max_rps=max_rps))


# Flags that point a CLI tool at an HTTP proxy, and (where the tool verifies
# TLS by default) make it accept the Gate's local certificate.
CLI_PROXY_FLAGS: dict[str, tuple[list[str], list[str]]] = {
    # tool name: (proxy flag tokens with {url}, extra TLS tokens)
    "execute_nuclei": (["-proxy", "{url}"], []),
    "execute_httpx": (["-http-proxy", "{url}"], []),
    "execute_katana": (["-proxy", "{url}"], []),
    "execute_ffuf": (["-x", "{url}"], []),
    "execute_feroxbuster": (["--proxy", "{url}"], ["-k"]),
    "execute_sqlmap": (["--proxy", "{url}"], []),
    "execute_dalfox": (["--proxy", "{url}"], []),
    "execute_wpscan": (["--proxy", "{url}"], ["--disable-tls-checks"]),
    "execute_curl": (["-x", "{url}"], ["--cacert", "{ca}"]),
}
_EXISTING_PROXY_FLAGS = ("-proxy", "-http-proxy", "-x", "--proxy", "--proxy-cred", "-useproxy")


def cli_gate_tokens(tool_name: str, existing_args: list[str]) -> list[str]:
    """Tokens to append so a CLI tool sends its traffic through the run's Gate lease."""
    spec = CLI_PROXY_FLAGS.get(tool_name)
    lease = current_lease()
    if not spec or lease is None:
        return []
    if any(tok.split("=", 1)[0] in _EXISTING_PROXY_FLAGS for tok in existing_args):
        # A tool may not pick its own proxy while the Gate is on: that would
        # route around scope, pacing and the request cap.
        raise GateConflict(
            f"{tool_name} was given its own proxy flag; Judah Gate routes target "
            "traffic for this run. Remove the proxy flag and retry."
        )
    from app.services.agent.judah_gate_ca import ca_cert_path

    url = lease_proxy_url(lease)
    proxy, tls = spec
    out = [t.replace("{url}", url) for t in proxy]
    out += [t.replace("{ca}", str(ca_cert_path())) for t in tls]
    return out


__all__ = [
    "CLI_PROXY_FLAGS", "GateConflict", "GateLease", "GateRegistry", "HostPacer", "JudahGate", "PROFILES", "Pace",
    "cli_gate_tokens", "current_lease", "ensure_lease_for_run", "gate_address", "gate_enabled",
    "lease_proxy_url", "pace_for", "registry", "start_gate_from_env", "stop_gate",
]
