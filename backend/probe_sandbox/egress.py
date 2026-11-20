"""probe-egress: job relay and scope-enforcing forward proxy for probe-runner.

Two listeners, standard library only:

* Relay (PROBE_RELAY_PORT, default 9000), reached by the backend. POST /run
  with ``Authorization: Bearer $PROBE_RELAY_TOKEN`` registers a one-job scope,
  forwards the script to probe-runner with a per-job proxy credential, waits
  for the result, and returns it with this job's egress log.
* Proxy (PROBE_PROXY_PORT, default 3128), reached by probe-runner over an
  internal network with no other route out. Every CONNECT or absolute-URI
  request must carry the job credential, name an in-scope host (or an OAST
  suffix), and resolve to a public address. The proxy connects to the address
  it checked, so DNS rebinding cannot swap the destination afterwards.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import secrets
import select
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

RELAY_TOKEN = os.environ.get("PROBE_RELAY_TOKEN", "")
RUNNER_TOKEN = os.environ.get("PROBE_RUNNER_TOKEN", "")
RUNNER_URL = os.environ.get("PROBE_RUNNER_URL", "http://probe-runner:8000").rstrip("/")
PROXY_HOST = os.environ.get("PROBE_PROXY_HOST", "probe-egress")
RELAY_PORT = int(os.environ.get("PROBE_RELAY_PORT", "9000"))
PROXY_PORT = int(os.environ.get("PROBE_PROXY_PORT", "3128"))
# Lab only: let scope entries resolve to private/loopback addresses.
ALLOW_PRIVATE = os.environ.get("PROBE_ALLOW_PRIVATE_TARGETS", "").lower() in ("1", "true", "yes")
MAX_REQUESTS_PER_JOB = int(os.environ.get("PROBE_MAX_REQUESTS_PER_JOB", "300"))
MAX_SCRIPT_BYTES = 200_000
MAX_TIMEOUT = 45.0
IDLE_TUNNEL_SECONDS = 60

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _norm_host(value: str) -> str:
    return (value or "").strip().lower().rstrip(".").strip("[]")


def host_in_scope(host: str, allowed: list[str], oob: list[str]) -> bool:
    host = _norm_host(host)
    if not host:
        return False
    for raw in allowed:
        item = _norm_host(raw).lstrip(".")
        if item and (host == item or host.endswith("." + item)):
            return True
    for raw in oob:
        item = _norm_host(raw).lstrip(".")
        if item and (host == item or host.endswith("." + item)):
            return True
    return False


def _public(ip: ipaddress._BaseAddress) -> bool:
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def resolve_checked(host: str, port: int, allowed: list[str]) -> tuple[str | None, str]:
    """Return (ip, "") for an allowed destination, else (None, reason)."""
    host = _norm_host(host)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        exact = {_norm_host(item) for item in allowed}
        if host not in exact:
            return None, "IP destinations need an exact scope entry"
        if not _public(literal) and not ALLOW_PRIVATE:
            return None, "non-public address blocked"
        return host, ""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None, "DNS resolution failed"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _public(ip) or ALLOW_PRIVATE:
            return str(ip), ""
    return None, "resolves only to non-public addresses"


def _job_for(header: str | None) -> tuple[str, dict] | tuple[None, None]:
    if not header or not header.lower().startswith("basic "):
        return None, None
    try:
        user, _, token = base64.b64decode(header[6:].strip()).decode().partition(":")
    except (ValueError, UnicodeDecodeError):
        return None, None
    if user != "job" or not token:
        return None, None
    with _jobs_lock:
        job = _jobs.get(token)
    return (token, job) if job else (None, None)


def _pipe(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    last = time.monotonic()
    while time.monotonic() - last < IDLE_TUNNEL_SECONDS:
        readable, _, errored = select.select(sockets, [], sockets, 5)
        if errored:
            return
        for sock in readable:
            data = sock.recv(65536)
            if not data:
                return
            (b if sock is a else a).sendall(data)
            last = time.monotonic()


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "probe-egress"

    def log_message(self, *_args) -> None:
        return

    def _deny(self, code: int, reason: str) -> None:
        body = reason.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _admit(self, host: str, port: int) -> tuple[dict | None, str | None]:
        _token, job = _job_for(self.headers.get("Proxy-Authorization"))
        if job is None:
            self._deny(407, "job credential required")
            return None, None
        entry = {"method": self.command, "host": _norm_host(host), "port": port,
                 "at": round(time.time(), 3)}
        with _jobs_lock:
            over = len(job["log"]) >= MAX_REQUESTS_PER_JOB
            job["log"].append(entry)
        if over:
            entry.update(allowed=False, reason="request budget exhausted")
            self._deny(429, entry["reason"])
            return None, None
        if not host_in_scope(host, job["allowed"], job["oob"]):
            entry.update(allowed=False, reason="host not in scope")
            self._deny(403, "host not in engagement scope")
            return None, None
        ip, reason = resolve_checked(host, port, job["allowed"])
        if ip is None:
            entry.update(allowed=False, reason=reason)
            self._deny(403, reason)
            return None, None
        entry.update(allowed=True, ip=ip)
        return job, ip

    def do_CONNECT(self) -> None:
        host, _, port_text = self.path.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            self._deny(400, "bad CONNECT target")
            return
        job, ip = self._admit(host, port)
        if job is None:
            return
        try:
            upstream = socket.create_connection((ip, port), timeout=15)
        except OSError:
            self._deny(502, "upstream connect failed")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        try:
            _pipe(self.connection, upstream)
        finally:
            upstream.close()
            self.close_connection = True

    def _forward(self) -> None:
        parts = urlsplit(self.path)
        if parts.scheme != "http" or not parts.hostname:
            self._deny(400, "absolute http:// URL required; use CONNECT for https")
            return
        port = parts.port or 80
        job, ip = self._admit(parts.hostname, port)
        if job is None:
            return
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{self.command} {path} HTTP/1.1"]
        for name, value in self.headers.items():
            if name.lower() in ("proxy-authorization", "proxy-connection", "connection", "keep-alive"):
                continue
            lines.append(f"{name}: {value}")
        lines.append("Connection: close")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        try:
            upstream = socket.create_connection((ip, port), timeout=15)
        except OSError:
            self._deny(502, "upstream connect failed")
            return
        try:
            upstream.sendall(head + body)
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        finally:
            upstream.close()
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _forward


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "probe-relay"

    def log_message(self, *_args) -> None:
        return

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/run":
            self._json(404, {"error": "not found"})
            return
        supplied = self.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied.encode(), f"Bearer {RELAY_TOKEN}".encode()):
            self._json(401, {"error": "unauthorized"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_SCRIPT_BYTES + 20_000:
            self._json(413, {"error": "bad request size"})
            return
        try:
            req = json.loads(self.rfile.read(length))
            script = str(req["script"])
            allowed = [str(h) for h in req.get("allowed_hosts") or []]
            oob = [str(h) for h in req.get("oob_suffixes") or []]
            timeout = max(3.0, min(float(req.get("timeout_sec") or 20), MAX_TIMEOUT))
        except (ValueError, KeyError, TypeError):
            self._json(400, {"error": "invalid job"})
            return
        if not allowed or len(script.encode()) > MAX_SCRIPT_BYTES:
            self._json(400, {"error": "scope and a bounded script are required"})
            return
        token = secrets.token_urlsafe(24)
        job = {"allowed": allowed, "oob": oob, "log": []}
        with _jobs_lock:
            _jobs[token] = job
        try:
            result = _run_on_runner(script, timeout, f"http://job:{token}@{PROXY_HOST}:{PROXY_PORT}")
        finally:
            with _jobs_lock:
                _jobs.pop(token, None)
        result["egress"] = job["log"]
        self._json(200, result)


def _run_on_runner(script: str, timeout: float, proxy_url: str) -> dict:
    payload = json.dumps({"script": script, "timeout_sec": timeout, "proxy_url": proxy_url}).encode()
    request = urllib.request.Request(
        f"{RUNNER_URL}/run", data=payload, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {RUNNER_TOKEN}"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout + 10) as response:
            data = json.loads(response.read())
            return data if isinstance(data, dict) else {"ok": False, "error": "invalid runner reply"}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"runner failed: {type(exc).__name__}"}


def main() -> None:
    if len(RELAY_TOKEN) < 24 or len(RUNNER_TOKEN) < 24:
        sys.exit("PROBE_RELAY_TOKEN and PROBE_RUNNER_TOKEN must each be at least 24 characters")
    proxy = ThreadingHTTPServer(("0.0.0.0", PROXY_PORT), ProxyHandler)
    proxy.daemon_threads = True
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    relay = ThreadingHTTPServer(("0.0.0.0", RELAY_PORT), RelayHandler)
    relay.daemon_threads = True
    relay.serve_forever()


if __name__ == "__main__":
    main()
