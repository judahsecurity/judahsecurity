"""
Out-of-band interaction oracle — proof for blind vulnerabilities.

Blind SSRF / RCE / XXE / SSTI produce no response an agent can read; the only
ground truth is a callback from the target's own infrastructure to a host you
control, correlated by a unique nonce. This oracle mints that nonce + payload
URL, catches the callback, and on a correlated hit registers a **verified `oob`
proof token** into the finding gate — the blind-vuln analog of the flag oracle.

Pluggable backend (same shape as the proxy/flag layers):

  LocalListenerBackend (default) — runs a threaded HTTP listener in-process and
    mints /oob/<nonce> URLs. Proves HTTP-based OOB (SSRF, RCE via curl/wget)
    whenever the target can reach this host (benchmarks on a shared Docker
    network, or an operator-provided AEGIS_OOB_PUBLIC_BASE that forwards here).
    Fully testable with no external service.
  RemoteCollaboratorBackend — polls an operator-run collaborator
    (interactsh/Burp Collaborator/webhook) via AEGIS_OOB_POLL_URL for internet
    targets and DNS-only callbacks. Raises if unconfigured rather than silently
    failing, so you always know whether OOB was actually armed.
"""

import json
import logging
import os
import secrets
import threading
import time
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

from agent.finding_oracle import register_proof

logger = logging.getLogger("agent.oob_oracle")


@dataclass
class InteractionEvent:
    protocol: str            # http, dns, ...
    remote_addr: str = ""
    method: str = ""
    path: str = ""
    host: str = ""
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OobProbe:
    probe_id: str            # == nonce; poll by this
    nonce: str
    payload_url: str
    label: str = ""
    created_at: float = field(default_factory=time.time)


# ── Backends ───────────────────────────────────────────────────────────────
class OobBackend(ABC):
    name = "abstract"

    def start(self) -> None:  # optional
        pass

    def stop(self) -> None:  # optional
        pass

    @abstractmethod
    def new_probe(self, label: str = "") -> OobProbe:  # pragma: no cover
        ...

    @abstractmethod
    def poll(self, probe: OobProbe) -> List[InteractionEvent]:  # pragma: no cover
        ...


def _make_handler(backend: "LocalListenerBackend"):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence default stderr logging
            pass

        def _candidate_nonces(self):
            cands = []
            segs = [s for s in (self.path or "").split("/") if s]
            if segs and segs[0] == "oob" and len(segs) > 1:
                cands.append(segs[1])
            cands.extend(segs)
            host = (self.headers.get("Host") or "").split(":")[0]
            if host:
                cands.append(host.split(".")[0])
            return cands

        def _handle(self, method):
            for token in self._candidate_nonces():
                if backend.matches(token):
                    backend.record(token, InteractionEvent(
                        protocol="http",
                        remote_addr=self.client_address[0] if self.client_address else "",
                        method=method,
                        path=self.path,
                        host=self.headers.get("Host", ""),
                    ))
                    break
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(b"ok")

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_HEAD(self):
            self._handle("HEAD")

    return _Handler


class LocalListenerBackend(OobBackend):
    """In-process HTTP callback catcher. Bundled default; fully testable."""

    name = "local"

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 public_base: Optional[str] = None):
        self.host = host
        self.port = port
        self.public_base = public_base or os.environ.get("AEGIS_OOB_PUBLIC_BASE")
        self._events: Dict[str, List[InteractionEvent]] = {}
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    def start(self) -> None:
        if self._server:
            return
        self._server = ThreadingHTTPServer((self.host, self.port), _make_handler(self))
        self.host, self.port = self._server.server_address[0], self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("OOB listener on %s:%s", self.host, self.port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def _base(self) -> str:
        return (self.public_base or f"http://{self.host}:{self.port}").rstrip("/")

    def matches(self, token: str) -> bool:
        with self._lock:
            return token in self._events

    def record(self, nonce: str, event: InteractionEvent) -> None:
        with self._lock:
            self._events.setdefault(nonce, []).append(event)

    def new_probe(self, label: str = "") -> OobProbe:
        self.start()
        nonce = secrets.token_hex(12)
        with self._lock:
            self._events.setdefault(nonce, [])
        return OobProbe(probe_id=nonce, nonce=nonce, label=label,
                        payload_url=f"{self._base()}/oob/{nonce}")

    def poll(self, probe: OobProbe) -> List[InteractionEvent]:
        with self._lock:
            return list(self._events.get(probe.nonce, []))


class RemoteCollaboratorBackend(OobBackend):
    """Adapter for an operator-run collaborator (interactsh/Burp/webhook).

    Configure AEGIS_OOB_PUBLIC_BASE (the callback domain payloads should hit)
    and AEGIS_OOB_POLL_URL (a JSON endpoint returning events for a nonce, called
    as `<poll_url>?id=<nonce>`). Optional AEGIS_OOB_TOKEN is sent as a bearer.
    """

    name = "remote"

    def __init__(self, poll_url: Optional[str] = None,
                 payload_base: Optional[str] = None, token: Optional[str] = None):
        self.poll_url = poll_url or os.environ.get("AEGIS_OOB_POLL_URL")
        self.payload_base = payload_base or os.environ.get("AEGIS_OOB_PUBLIC_BASE")
        self.token = token or os.environ.get("AEGIS_OOB_TOKEN")

    def new_probe(self, label: str = "") -> OobProbe:
        if not (self.poll_url and self.payload_base):
            raise RuntimeError(
                "RemoteCollaboratorBackend needs AEGIS_OOB_PUBLIC_BASE (callback "
                "domain) and AEGIS_OOB_POLL_URL (event poll endpoint). Unconfigured "
                "OOB would silently never fire."
            )
        nonce = secrets.token_hex(12)
        return OobProbe(probe_id=nonce, nonce=nonce, label=label,
                        payload_url=f"{self.payload_base.rstrip('/')}/{nonce}")

    def poll(self, probe: OobProbe) -> List[InteractionEvent]:
        if not self.poll_url:
            raise RuntimeError("RemoteCollaboratorBackend requires AEGIS_OOB_POLL_URL")
        url = f"{self.poll_url}{'&' if '?' in self.poll_url else '?'}id={probe.nonce}"
        req = urllib.request.Request(
            url, headers=({"Authorization": f"Bearer {self.token}"} if self.token else {}))
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                rows = json.loads(resp.read().decode("utf-8", "ignore") or "[]")
        except Exception as e:  # noqa: BLE001
            logger.debug("oob remote poll failed: %s", e)
            return []
        events = []
        for r in rows if isinstance(rows, list) else []:
            events.append(InteractionEvent(
                protocol=str(r.get("protocol", "http")),
                remote_addr=str(r.get("remote_addr", r.get("remote-address", ""))),
                method=str(r.get("method", "")),
                path=str(r.get("path", "")),
                host=str(r.get("host", "")),
            ))
        return events


def make_oob_backend(name: Optional[str] = None) -> OobBackend:
    name = (name or os.environ.get("AEGIS_OOB_BACKEND") or "local").lower()
    if name == "remote":
        return RemoteCollaboratorBackend()
    return LocalListenerBackend()


# ── Oracle ─────────────────────────────────────────────────────────────────
class OobOracle:
    def __init__(self, backend: Optional[OobBackend] = None):
        self.backend = backend or make_oob_backend()
        self._probes: Dict[str, OobProbe] = {}
        self._lock = threading.Lock()

    def register_probe(self, label: str = "") -> OobProbe:
        probe = self.backend.new_probe(label=label)
        with self._lock:
            self._probes[probe.probe_id] = probe
        return probe

    def get_probe(self, probe_id: str) -> Optional[OobProbe]:
        with self._lock:
            return self._probes.get(probe_id)

    def check(self, probe_id: str) -> dict:
        probe = self.get_probe(probe_id)
        if probe is None:
            return {"error": f"unknown probe_id: {probe_id}"}
        events = self.backend.poll(probe)
        fired = len(events) > 0
        if fired:
            first = events[0]
            register_proof(
                "oob", verified=True,
                subject=probe.label or probe.payload_url,
                detail=f"{len(events)} OOB callback(s); first {first.protocol} "
                       f"from {first.remote_addr}",
            )
        return {
            "probe_id": probe_id,
            "payload_url": probe.payload_url,
            "fired": fired,
            "count": len(events),
            "events": [e.to_dict() for e in events],
            "proof": "oob verified" if fired else "no callback yet",
        }


# ── Singleton ──────────────────────────────────────────────────────────────
_ORACLE: Optional[OobOracle] = None
_LOCK = threading.Lock()


def get_oob_oracle() -> OobOracle:
    global _ORACLE
    if _ORACLE is None:
        with _LOCK:
            if _ORACLE is None:
                _ORACLE = OobOracle()
    return _ORACLE


def set_oob_oracle(oracle: OobOracle) -> OobOracle:
    global _ORACLE
    with _LOCK:
        _ORACLE = oracle
    return oracle


def reset_oob_oracle() -> None:
    global _ORACLE
    with _LOCK:
        if _ORACLE is not None:
            try:
                _ORACLE.backend.stop()
            except Exception:
                pass
        _ORACLE = None
