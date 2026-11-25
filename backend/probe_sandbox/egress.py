"""probe-egress: job relay and recording, scope-enforcing proxy for probe-runner.

Two listeners:

* Relay (PROBE_RELAY_PORT, default 9000), reached by the backend. POST /run
  with ``Authorization: Bearer $PROBE_RELAY_TOKEN`` registers a one-job scope,
  forwards the script to probe-runner with a per-job proxy credential and this
  proxy's CA certificate, waits for the result, and returns it with the job's
  egress log and recorded HTTP exchanges.
* Proxy (PROBE_PROXY_PORT, default 3128), reached by probe-runner over an
  internal network with no other route out. Every CONNECT or absolute-URI
  request must carry the job credential, name an in-scope host (or an OAST
  suffix), and resolve to a public address. The proxy connects to the address
  it checked, so DNS rebinding cannot swap the destination afterwards.

HTTPS is intercepted: the proxy terminates TLS with a per-host certificate from
an ephemeral CA generated at startup (the private key never leaves this
process), verifies the real server's certificate upstream, and records each
request/response. One request is served per connection (``Connection: close``)
and HTTP/1.1 is forced through ALPN, so every exchange is parsed exactly.
"""

from __future__ import annotations

import base64
import datetime
import gzip
import hmac
import ipaddress
import json
import os
import secrets
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zlib
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
# Lab only: accept self-signed or mismatched upstream certificates.
UPSTREAM_VERIFY = os.environ.get("PROBE_UPSTREAM_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
MAX_REQUESTS_PER_JOB = int(os.environ.get("PROBE_MAX_REQUESTS_PER_JOB", "300"))
SOCKS_PORT = int(os.environ.get("PROBE_SOCKS_PORT", "1080"))
# Raw TCP connections (port scans) per job, logged but counted separately.
MAX_TCP_PER_JOB = int(os.environ.get("PROBE_MAX_TCP_PER_JOB", "4000"))
MAX_SCRIPT_BYTES = 200_000
MAX_TIMEOUT = 45.0
MAX_SHELL_TIMEOUT = 120.0
MAX_HEAD_BYTES = 64 * 1024
MAX_MESSAGE_BODY = 32 * 1024 * 1024       # relayed in full up to this size
MAX_RECORDED_BODY = 256 * 1024             # stored per request or response body
MAX_RECORDED_PER_JOB = 8 * 1024 * 1024     # stored across one job
SOCKET_TIMEOUT = 20

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------

def _norm_host(value: str) -> str:
    return (value or "").strip().lower().rstrip(".").strip("[]")


def host_in_scope(host: str, allowed: list[str], oob: list[str]) -> bool:
    host = _norm_host(host)
    if not host:
        return False
    for raw in list(allowed) + list(oob):
        item = _norm_host(raw).lstrip(".")
        if item and (host == item or host.endswith("." + item)):
            return True
    return False


_WRITE_POLICY_METHODS = ("POST", "DELETE")


def parse_method_policy(raw) -> dict | None:
    """Normalise an operator method policy sent with a job; None means no policy.

    The backend applies one in every Prowl-mode run: GET/HEAD are free, and a
    write is allowed only as POST or DELETE to an exact approved path.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("method policy must be an object")
    def paths(key):
        values = raw.get(key) or []
        if not isinstance(values, list) or len(values) > 32:
            raise ValueError(f"{key} must be a short list")
        out = set()
        for value in values:
            if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
                    or len(value) > 256 or any(c in value for c in "?#\\\r\n\t ")):
                raise ValueError(f"invalid path in {key}")
            out.add(value)
        return out
    return {"post_paths": paths("approved_post_paths"),
            "delete_paths": paths("approved_delete_paths")}


def method_allowed(policy: dict | None, method: str, target: str) -> tuple[bool, str]:
    """Mirror assessment_scope.assert_method_allowed for proxied traffic."""
    if policy is None:
        return True, ""
    method = (method or "").upper()
    path = urlsplit(target if "://" in target else "http://x" + (target or "/")).path or "/"
    if method in ("GET", "HEAD"):
        return True, ""
    if method == "POST" and path in policy["post_paths"]:
        return True, ""
    if method == "DELETE" and path in policy["delete_paths"]:
        return True, ""
    return False, f"{method} {path} requires an exact operator-approved path"


def _public(ip) -> bool:
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def resolve_checked_all(host: str, port: int, allowed: list[str]) -> tuple[list[str], str]:
    """Return (addresses, "") for an allowed destination, else ([], reason).

    Every resolved address that passes the address policy is returned, in
    resolver order, so callers can fall back across address families. A
    dual-stack name usually resolves to its IPv6 address first; when that path
    is closed (no IPv6 route, or a service bound to IPv4 only) the IPv4
    address must still be tried. Callers connect only to these checked
    addresses and never re-resolve the name.
    """
    host = _norm_host(host)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if host not in {_norm_host(item) for item in allowed}:
            return [], "IP destinations need an exact scope entry"
        if not _public(literal) and not ALLOW_PRIVATE:
            return [], "non-public address blocked"
        return [host], ""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return [], "DNS resolution failed"
    addresses: list[str] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (_public(ip) or ALLOW_PRIVATE) and str(ip) not in addresses:
            addresses.append(str(ip))
    if not addresses:
        return [], "resolves only to non-public addresses"
    return addresses, ""


def resolve_checked(host: str, port: int, allowed: list[str]) -> tuple[str | None, str]:
    """Return (ip, "") for an allowed destination, else (None, reason)."""
    addresses, reason = resolve_checked_all(host, port, allowed)
    return (addresses[0], "") if addresses else (None, reason)


def connect_checked(addresses: list[str], port: int, timeout: float) -> tuple[socket.socket, str]:
    """Connect to the first reachable checked address; return (socket, address).

    Raises the last connection error when none is reachable.
    """
    error: OSError = OSError("no checked address")
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=timeout), address
        except OSError as exc:
            error = exc
    raise error


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


# --------------------------------------------------------------------------
# certificate authority
# --------------------------------------------------------------------------

class CertificateAuthority:
    """Ephemeral CA; issues and caches one server context per host."""

    def __init__(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        self._x509, self._hashes, self._ec, self._oid = x509, hashes, ec, NameOID
        self._key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Judah probe-egress CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        self._name = name
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()),
                           critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        from cryptography.hazmat.primitives.serialization import Encoding

        self.cert_pem = self.cert.public_bytes(Encoding.PEM).decode()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()
        self._dir = tempfile.mkdtemp(prefix="probe-ca-")
        os.chmod(self._dir, 0o700)

    def context_for(self, host: str) -> ssl.SSLContext:
        host = _norm_host(host)
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is None:
                ctx = self._issue(host)
                if len(self._contexts) > 2048:
                    self._contexts.clear()
                self._contexts[host] = ctx
            return ctx

    def _issue(self, host: str) -> ssl.SSLContext:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat,
        )

        x509 = self._x509
        key = self._ec.generate_private_key(self._ec.SECP256R1())
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(self._oid.COMMON_NAME, host[:64])]))
            .issuer_name(self._name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._key.public_key()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .sign(self._key, self._hashes.SHA256())
        )
        fd, path = tempfile.mkstemp(dir=self._dir, suffix=".pem")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
                handle.write(cert.public_bytes(Encoding.PEM))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_alpn_protocols(["http/1.1"])
            ctx.load_cert_chain(path)
        finally:
            os.unlink(path)
        return ctx


_ca: CertificateAuthority | None = None


def certificate_authority() -> CertificateAuthority:
    global _ca
    if _ca is None:
        _ca = CertificateAuthority()
    return _ca


def _upstream_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not UPSTREAM_VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


# --------------------------------------------------------------------------
# HTTP/1.1 message parsing
# --------------------------------------------------------------------------

class Message:
    def __init__(self, start: str, headers: list[tuple[str, str]], raw_body: bytes, body: bytes):
        self.start, self.headers, self.raw_body, self.body = start, headers, raw_body, body

    def header(self, name: str) -> str:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), "")


def _read_head(rfile) -> tuple[str, list[tuple[str, str]]] | None:
    raw = b""
    while True:
        line = rfile.readline(MAX_HEAD_BYTES + 1)
        if not line:
            return None if not raw else _bad("truncated message head")
        if not raw and line in (b"\r\n", b"\n"):
            continue
        raw += line
        if len(raw) > MAX_HEAD_BYTES:
            _bad("message head too large")
        if line in (b"\r\n", b"\n"):
            break
    lines = raw.decode("latin-1").split("\r\n") if b"\r\n" in raw else raw.decode("latin-1").split("\n")
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            _bad("malformed header line")
        headers.append((name.strip(), value.strip()))
    return lines[0], headers


def _bad(reason: str):
    raise ValueError(reason)


def _read_exact(rfile, n: int) -> bytes:
    data = rfile.read(n)
    if len(data) != n:
        _bad("truncated body")
    return data


def _read_chunked(rfile) -> tuple[bytes, bytes]:
    raw, body = bytearray(), bytearray()
    while True:
        size_line = rfile.readline(1024)
        if not size_line:
            _bad("truncated chunked body")
        raw += size_line
        size = int(size_line.split(b";")[0].strip() or b"0", 16)
        if size == 0:
            while True:  # trailers, ending with an empty line
                trailer = rfile.readline(MAX_HEAD_BYTES)
                raw += trailer
                if trailer in (b"\r\n", b"\n", b""):
                    return bytes(raw), bytes(body)
        chunk = _read_exact(rfile, size)
        raw += chunk
        body += chunk
        raw += rfile.readline(4)
        if len(body) > MAX_MESSAGE_BODY:
            _bad("body too large")


def read_message(rfile, *, response: bool = False, request_method: str = "GET") -> Message | None:
    head = _read_head(rfile)
    if head is None:
        return None
    start, headers = head
    msg = Message(start, headers, b"", b"")
    te = msg.header("Transfer-Encoding").lower()
    length = msg.header("Content-Length")
    if response:
        parts = start.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if request_method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200:
            return msg
    if "chunked" in te:
        msg.raw_body, msg.body = _read_chunked(rfile)
    elif length:
        n = int(length)
        if n < 0 or n > MAX_MESSAGE_BODY:
            _bad("bad content length")
        msg.raw_body = msg.body = _read_exact(rfile, n)
    elif response:
        data = rfile.read(MAX_MESSAGE_BODY + 1)
        if len(data) > MAX_MESSAGE_BODY:
            _bad("body too large")
        msg.raw_body = msg.body = data
    return msg


_HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization",
               "proxy-authenticate", "te", "trailer", "upgrade"}


def _serialize(start: str, headers: list[tuple[str, str]], raw_body: bytes) -> bytes:
    lines = [start] + [f"{k}: {v}" for k, v in headers if k.lower() not in _HOP_BY_HOP]
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + raw_body


def _decoded(body: bytes, encoding: str) -> tuple[bytes, str]:
    encoding = (encoding or "").lower().strip()
    try:
        if encoding in ("gzip", "x-gzip"):
            return gzip.decompress(body), ""
        if encoding == "deflate":
            try:
                return zlib.decompress(body), ""
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), ""
    except (OSError, zlib.error, EOFError):
        return body, f"could not decode {encoding}"
    if encoding and encoding != "identity":
        return body, f"stored still {encoding}-encoded"
    return body, ""


def _body_record(body: bytes, content_type: str) -> dict:
    clipped = body[:MAX_RECORDED_BODY]
    out = {"length": len(body), "truncated": len(body) > MAX_RECORDED_BODY}
    textual = any(t in (content_type or "").lower() for t in
                  ("text", "json", "xml", "html", "javascript", "form", "graphql", "csv"))
    try:
        text = clipped.decode("utf-8")
        out["body"] = text
    except UnicodeDecodeError:
        if textual:
            out["body"] = clipped.decode("utf-8", "replace")
        else:
            out["body"] = ""
            out["binary"] = True
    return out


# --------------------------------------------------------------------------
# proxy
# --------------------------------------------------------------------------

class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "probe-egress"
    timeout = SOCKET_TIMEOUT

    def log_message(self, *_args) -> None:
        return

    def _deny(self, code: int, reason: str, wfile=None) -> None:
        body = reason.encode()
        head = (f"HTTP/1.1 {code} Denied\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        (wfile or self.wfile).write(head + body)
        self.close_connection = True

    def _admit(self, host: str, port: int) -> tuple[dict | None, str | None, dict | None]:
        _token, job = _job_for(self.headers.get("Proxy-Authorization"))
        if job is None:
            self._deny(407, "job credential required")
            return None, None, None
        entry = {"method": self.command, "host": _norm_host(host), "port": port,
                 "at": round(time.time(), 3)}
        with _jobs_lock:
            over = len(job["log"]) >= MAX_REQUESTS_PER_JOB
            job["log"].append(entry)
        if over:
            entry.update(allowed=False, reason="request budget exhausted")
            self._deny(429, entry["reason"])
            return None, None, None
        if not host_in_scope(host, job["allowed"], job["oob"]):
            entry.update(allowed=False, reason="host not in scope")
            self._deny(403, "host not in engagement scope")
            return None, None, None
        addresses, reason = resolve_checked_all(host, port, job["allowed"])
        if not addresses:
            entry.update(allowed=False, reason=reason)
            self._deny(403, reason)
            return None, None, None
        entry.update(allowed=True, ip=addresses[0])
        return job, addresses, entry

    def do_CONNECT(self) -> None:
        host, _, port_text = self.path.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            self._deny(400, "bad CONNECT target")
            return
        job, addresses, entry = self._admit(host, port)
        if job is None:
            return
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        self.close_connection = True
        try:
            client = certificate_authority().context_for(host).wrap_socket(
                self.connection, server_side=True,
            )
        except (ssl.SSLError, OSError) as exc:
            entry.update(allowed=False, reason=f"client TLS handshake failed: {type(exc).__name__}")
            return
        client.settimeout(SOCKET_TIMEOUT)
        rfile, wfile = client.makefile("rb"), client.makefile("wb")
        try:
            try:
                request = read_message(rfile)
            except (ValueError, OSError) as exc:
                entry["reason"] = f"bad request: {exc}"
                return
            if request is None:
                return
            method, _, rest = request.start.partition(" ")
            target = rest.rsplit(" ", 1)[0] or "/"
            self._exchange(job, entry, "https", host, port, addresses, method, target, request, wfile)
        finally:
            for handle in (wfile, rfile):
                try:
                    handle.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass

    def _forward(self) -> None:
        parts = urlsplit(self.path)
        if parts.scheme != "http" or not parts.hostname:
            self._deny(400, "absolute http:// URL required; use CONNECT for https")
            return
        port = parts.port or 80
        job, addresses, entry = self._admit(parts.hostname, port)
        if job is None:
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_MESSAGE_BODY:
            self._deny(413, "request body too large")
            return
        body = self.rfile.read(length) if length else b""
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        request = Message(f"{self.command} {target} HTTP/1.1", list(self.headers.items()), body, body)
        self.close_connection = True
        self._exchange(job, entry, "http", parts.hostname, port, addresses, self.command, target,
                       request, self.wfile)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _forward

    def _exchange(self, job, entry, scheme, host, port, addresses, method, target, request, wfile) -> None:
        ok, why = method_allowed(job.get("policy"), method, target)
        if not ok:
            entry.update(allowed=False, reason=why)
            self._deny(403, why, wfile)
            return
        started = time.monotonic()
        try:
            upstream, entry["ip"] = connect_checked(addresses, port, SOCKET_TIMEOUT)
        except OSError:
            entry["reason"] = "upstream connect failed"
            self._deny(502, "upstream connect failed", wfile)
            return
        try:
            if scheme == "https":
                try:
                    upstream = _upstream_context().wrap_socket(upstream, server_hostname=_norm_host(host))
                except ssl.SSLCertVerificationError:
                    entry["reason"] = "upstream certificate verification failed"
                    self._deny(502, entry["reason"], wfile)
                    return
                except (ssl.SSLError, OSError):
                    entry["reason"] = "upstream TLS handshake failed"
                    self._deny(502, entry["reason"], wfile)
                    return
            upstream.settimeout(SOCKET_TIMEOUT)
            upstream.sendall(_serialize(f"{method} {target} HTTP/1.1", request.headers, request.raw_body))
            try:
                response = read_message(upstream.makefile("rb"), response=True, request_method=method)
            except (ValueError, OSError) as exc:
                entry["reason"] = f"bad upstream response: {exc}"
                self._deny(502, "bad upstream response", wfile)
                return
            if response is None:
                entry["reason"] = "upstream closed without a response"
                self._deny(502, entry["reason"], wfile)
                return
            wfile.write(_serialize(response.start, response.headers, response.raw_body))
            wfile.flush()
            self._record(job, entry, scheme, host, port, method, target, request, response,
                         time.monotonic() - started)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    @staticmethod
    def _record(job, entry, scheme, host, port, method, target, request, response, elapsed) -> None:
        default = 443 if scheme == "https" else 80
        authority = _norm_host(host) + ("" if port == default else f":{port}")
        url = f"{scheme}://{authority}{target}"
        req_body, _ = _decoded(request.body, request.header("Content-Encoding"))
        resp_body, decode_note = _decoded(response.body, response.header("Content-Encoding"))
        parts = response.start.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        exchange = {
            "request": {"method": method, "url": url, "headers": dict(request.headers),
                        **_body_record(req_body, request.header("Content-Type"))},
            "response": {"status": status, "url": url, "headers": dict(response.headers),
                         "elapsed_s": round(elapsed, 3),
                         **_body_record(resp_body, response.header("Content-Type"))},
        }
        if decode_note:
            exchange["response"]["decode_note"] = decode_note
        size = len(json.dumps(exchange, default=str))
        with _jobs_lock:
            if job["recorded_bytes"] + size > MAX_RECORDED_PER_JOB:
                entry["recorded"] = False
                job["dropped"] += 1
                return
            job["recorded_bytes"] += size
            job["exchanges"].append(exchange)
        entry.update(recorded=True, status=status)


# --------------------------------------------------------------------------
# SOCKS5 (raw TCP: nmap -sT, netcat, protocol clients via proxychains)
# --------------------------------------------------------------------------

def _tcp_summary(job: dict) -> dict:
    """Per-destination connection counts; a port scan would flood the log."""
    rows = sorted(job["tcp"].values(), key=lambda r: (-r["allowed"], r["host"], r["port"]))
    return {"connections": job["tcp_count"], "destinations": rows[:300],
            "truncated": len(rows) > 300}


def _tcp_note(job: dict, host: str, port: int, allowed: bool, reason: str = "") -> None:
    key = f"{host}:{port}"
    with _jobs_lock:
        row = job["tcp"].setdefault(key, {"host": host, "port": port, "allowed": allowed,
                                          "count": 0, "reason": reason})
        row["count"] += 1


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("client closed")
        data += chunk
    return data


def _relay_tcp(a: socket.socket, b: socket.socket, idle: float = 60.0) -> None:
    import select

    sockets = [a, b]
    last = time.monotonic()
    while time.monotonic() - last < idle:
        readable, _, errored = select.select(sockets, [], sockets, 5)
        if errored:
            return
        for sock in readable:
            data = sock.recv(65536)
            if not data:
                return
            (b if sock is a else a).sendall(data)
            last = time.monotonic()


def _socks_reply(code: int) -> bytes:
    return bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0])


class SocksHandler(socketserver.BaseRequestHandler):
    """RFC 1928 CONNECT with RFC 1929 username/password = job/<token>."""

    def handle(self) -> None:
        client = self.request
        client.settimeout(SOCKET_TIMEOUT)
        try:
            version, count = _recv_exact(client, 2)
            methods = _recv_exact(client, count)
            if version != 5 or 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            _ver, ulen = _recv_exact(client, 2)
            user = _recv_exact(client, ulen).decode("latin-1")
            plen = _recv_exact(client, 1)[0]
            token = _recv_exact(client, plen).decode("latin-1")
            with _jobs_lock:
                job = _jobs.get(token) if user == "job" else None
            if job is None:
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
            _ver, cmd, _rsv, atyp = _recv_exact(client, 4)
            if atyp == 1:
                host = socket.inet_ntoa(_recv_exact(client, 4))
            elif atyp == 3:
                raw_name = _recv_exact(client, _recv_exact(client, 1)[0])
                try:
                    host = raw_name.decode("ascii")
                except UnicodeDecodeError:
                    client.sendall(_socks_reply(8))
                    return
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
            else:
                client.sendall(_socks_reply(8))
                return
            port = int.from_bytes(_recv_exact(client, 2), "big")
            host = _norm_host(host)
            if cmd != 1:
                client.sendall(_socks_reply(7))  # only CONNECT; no BIND/UDP
                return
            with _jobs_lock:
                job["tcp_count"] += 1
                over = job["tcp_count"] > MAX_TCP_PER_JOB
            if over:
                _tcp_note(job, host, port, False, "connection budget exhausted")
                client.sendall(_socks_reply(2))
                return
            if job.get("policy") is not None:
                # Raw TCP bytes cannot be checked against a method policy (a
                # socket could carry an unapproved POST), so the lane is closed.
                _tcp_note(job, host, port, False,
                          "raw TCP is unavailable under the operator method policy")
                client.sendall(_socks_reply(2))
                return
            if not host_in_scope(host, job["allowed"], job["oob"]):
                _tcp_note(job, host, port, False, "host not in scope")
                client.sendall(_socks_reply(2))
                return
            addresses, reason = resolve_checked_all(host, port, job["allowed"])
            if not addresses:
                _tcp_note(job, host, port, False, reason)
                client.sendall(_socks_reply(2))
                return
            try:
                upstream, _address = connect_checked(addresses, port, 10)
            except ConnectionRefusedError:
                _tcp_note(job, host, port, True, "refused")
                client.sendall(_socks_reply(5))
                return
            except OSError:
                _tcp_note(job, host, port, True, "unreachable")
                client.sendall(_socks_reply(4))
                return
            _tcp_note(job, host, port, True, "open")
            client.sendall(_socks_reply(0))
            try:
                _relay_tcp(client, upstream)
            finally:
                upstream.close()
        except (OSError, ValueError, IndexError):
            return


class _SocksServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


# --------------------------------------------------------------------------
# relay
# --------------------------------------------------------------------------

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
            command = str(req.get("command") or "")
            script = "" if command else str(req["script"])
            allowed = [str(h) for h in req.get("allowed_hosts") or []]
            oob = [str(h) for h in req.get("oob_suffixes") or []]
            policy = parse_method_policy(req.get("method_policy"))
            ceiling = MAX_SHELL_TIMEOUT if command else MAX_TIMEOUT
            timeout = max(3.0, min(float(req.get("timeout_sec") or 20), ceiling))
        except (ValueError, KeyError, TypeError):
            self._json(400, {"error": "invalid job"})
            return
        if not allowed or len(script.encode()) > MAX_SCRIPT_BYTES or len(command.encode()) > 8000:
            self._json(400, {"error": "scope and a bounded script are required"})
            return
        token = secrets.token_urlsafe(24)
        job = {"allowed": allowed, "oob": oob, "log": [], "exchanges": [],
               "recorded_bytes": 0, "dropped": 0, "tcp": {}, "tcp_count": 0,
               "policy": policy}
        with _jobs_lock:
            _jobs[token] = job
        try:
            result = _run_on_runner(
                script, timeout, f"http://job:{token}@{PROXY_HOST}:{PROXY_PORT}",
                certificate_authority().cert_pem, command=command,
                socks_url=f"socks5://job:{token}@{PROXY_HOST}:{SOCKS_PORT}",
            )
        finally:
            with _jobs_lock:
                _jobs.pop(token, None)
        result["egress"] = job["log"]
        result["exchanges"] = job["exchanges"]
        result["exchanges_dropped"] = job["dropped"]
        result["tcp"] = _tcp_summary(job)
        self._json(200, result)


def _run_on_runner(script: str, timeout: float, proxy_url: str, ca_pem: str,
                   *, command: str = "", socks_url: str = "") -> dict:
    payload = json.dumps({"script": script, "command": command, "timeout_sec": timeout,
                          "proxy_url": proxy_url, "ca_pem": ca_pem,
                          "socks_url": socks_url}).encode()
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
    certificate_authority()
    proxy = ThreadingHTTPServer(("0.0.0.0", PROXY_PORT), ProxyHandler)
    proxy.daemon_threads = True
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    socks = _SocksServer(("0.0.0.0", SOCKS_PORT), SocksHandler)
    threading.Thread(target=socks.serve_forever, daemon=True).start()
    relay = ThreadingHTTPServer(("0.0.0.0", RELAY_PORT), RelayHandler)
    relay.daemon_threads = True
    relay.serve_forever()


if __name__ == "__main__":
    main()
