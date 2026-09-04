"""
Request-smuggling probe — timing-based CL.TE / TE.CL desync detection.

HTTP request smuggling happens when a front-end and back-end disagree on where a
request ends (Content-Length vs Transfer-Encoding). The safe, non-destructive way
to *detect* it — the one that doesn't poison other users' connections — is the
timing technique from James Kettle's research: craft a request that makes the
back-end wait for more body bytes if (and only if) it parses the boundary the
"wrong" way; a desync shows up as a response that stalls until the socket times
out, far longer than a control request.

We implement detection only (a stalled self-request), never the second
victim-facing request that actual exploitation needs — that stays a manual,
explicitly-authorized step, consistent with the repo's "validate, don't exploit"
ROE. The timed transport is injectable so the verdict logic is unit-tested; the
default sender uses a raw socket because httpx/requests normalize the very
headers the probe depends on.
"""
from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("agent.smuggling_probe")

# (elapsed_ms, status_or_None). status None means the request timed out/stalled.
TimedSend = Callable[[str, str], Tuple[float, Optional[int]]]

# A desync is flagged when an attack request stalls this many ms longer than the
# control, near the socket timeout.
_DELAY_THRESHOLD_MS = 4000.0
_SOCKET_TIMEOUT_S = 8.0


def _cl_te_body() -> str:
    # Front-end uses Content-Length (3), back-end uses chunked and waits for the
    # next chunk that never arrives → back-end stalls on a vulnerable chain.
    return "1\r\nA\r\nX"


def build_requests(url: str) -> Dict[str, str]:
    """Return {name: raw_http_request} for a control + CL.TE + TE.CL test."""
    p = urlparse(url)
    host = p.netloc
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    common = f"Host: {host}\r\nConnection: close\r\n"
    control = f"GET {path} HTTP/1.1\r\n{common}\r\n"
    clte = (
        f"POST {path} HTTP/1.1\r\n{common}"
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\nX"
    )
    tecl = (
        f"POST {path} HTTP/1.1\r\n{common}"
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
    )
    return {"control": control, "clte": clte, "tecl": tecl}


def _desync_verdict(control_ms: float, clte_ms: float, clte_status: Optional[int],
                    tecl_ms: float, tecl_status: Optional[int]) -> Optional[str]:
    """Flag a desync if an attack request stalls far longer than the control."""
    for name, ms, status in (("CL.TE", clte_ms, clte_status), ("TE.CL", tecl_ms, tecl_status)):
        stalled = status is None or ms - control_ms >= _DELAY_THRESHOLD_MS
        if stalled:
            return (f"{name}: attack request stalled {ms:.0f}ms vs control "
                    f"{control_ms:.0f}ms — front/back-end disagree on request boundary")
    return None


def _raw_timed_send(url: str, raw_request: str,
                    timeout_s: float = _SOCKET_TIMEOUT_S) -> Tuple[float, Optional[int]]:
    """Send a raw HTTP request over a socket; return (elapsed_ms, status|None)."""
    p = urlparse(url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    start = time.time()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout_s)
        sock.sendall(raw_request.encode())
        data = sock.recv(256)
        elapsed = (time.time() - start) * 1000
        status = None
        if data.startswith(b"HTTP/"):
            try:
                status = int(data.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status = None
        return elapsed, status
    except socket.timeout:
        return (time.time() - start) * 1000, None
    except Exception as exc:
        logger.info("smuggling: raw send failed — %s", exc)
        return (time.time() - start) * 1000, -1  # -1 = connection error, not a stall
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def run_probe_smuggling(target_url: str, send: Optional[TimedSend] = None) -> Dict[str, Any]:
    """Timing-based HTTP request-smuggling (CL.TE / TE.CL) detection."""
    sender = send or (lambda url, req: _raw_timed_send(url, req))
    reqs = build_requests(target_url)
    control_ms, _ = sender(target_url, reqs["control"])
    clte_ms, clte_status = sender(target_url, reqs["clte"])
    tecl_ms, tecl_status = sender(target_url, reqs["tecl"])
    # A connection error (-1) is inconclusive, not a stall.
    if clte_status == -1 and tecl_status == -1:
        return {"probe": "smuggling", "target": target_url, "candidates": [],
                "note": "could not establish raw connections (blocked or unreachable)"}
    why = _desync_verdict(control_ms, clte_ms, clte_status, tecl_ms, tecl_status)
    candidates = []
    if why:
        candidates.append({
            "title": "Potential HTTP Request Smuggling (timing desync)",
            "vuln_type": "http_smuggling", "severity": "high", "url": target_url,
            "evidence": why,
            "note": "timing signal only — confirm manually with an authorized "
                    "differential-response test before exploiting",
            "confirmed": False,
        })
    return {"probe": "smuggling", "target": target_url,
            "timings_ms": {"control": round(control_ms), "clte": round(clte_ms),
                           "tecl": round(tecl_ms)},
            "candidates": candidates}


__all__ = ["run_probe_smuggling", "build_requests", "_desync_verdict"]
