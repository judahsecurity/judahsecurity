"""
Interactsh — out-of-band (OOB) interaction detection for blind vulnerabilities.

Blind SSRF, blind XXE, blind SQLi/command injection, blind RCE, and OOB data
exfiltration produce no visible response — the only signal is the target's
server reaching back out to an attacker-controlled host. Interactsh gives the
agent that host: a unique DNS/HTTP/SMTP payload domain. The agent plants the
payload (e.g. `http://<payload>/x`) in a suspected sink, then polls this
service to see whether the target's infrastructure phoned home.

Because a payload domain must outlive a single tool call (register now, inject,
poll later), this module keeps `interactsh-client` running as a background
process per session and exposes register / poll / list / stop verbs. Captured
interactions are streamed by the client to a JSONL file which `poll` tails.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Public Interactsh servers hand out payloads under oast.* apex domains. We also
# accept an arbitrary token when a self-hosted server is supplied.
_DOMAIN_RE = re.compile(r"\b([a-z0-9]{10,}\.(?:oast\.[a-z]+|[a-z0-9.\-]+\.[a-z]{2,}))\b", re.I)

_MAX_SESSIONS = 16
_SESSION_TTL = 3600  # seconds; idle sessions are reaped after this
_REGISTER_TIMEOUT = 20  # seconds to wait for the payload domain to appear


@dataclass
class _Session:
    sid: str
    proc: subprocess.Popen
    output_file: str
    server: Optional[str] = None
    payload_domain: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    raw_lines: List[str] = field(default_factory=list)
    read_offset: int = 0  # lines of the JSONL output already returned by poll
    _reader: Optional[threading.Thread] = None


_SESSIONS: Dict[str, _Session] = {}
_LOCK = threading.Lock()


def _binary() -> Optional[str]:
    return shutil.which("interactsh-client")


def _drain(session: _Session) -> None:
    """Continuously read the client's stdout so the pipe never blocks; sniff the domain."""
    try:
        assert session.proc.stdout is not None
        for line in session.proc.stdout:
            line = line.rstrip("\n")
            session.raw_lines.append(line)
            if len(session.raw_lines) > 400:
                session.raw_lines = session.raw_lines[-400:]
            if session.payload_domain is None:
                m = _DOMAIN_RE.search(line)
                if m:
                    session.payload_domain = m.group(1)
    except Exception:  # noqa: BLE001 — process closed / killed
        return


def _reap_locked() -> None:
    """Remove dead or expired sessions. Caller must hold _LOCK."""
    now = time.time()
    dead = []
    for sid, s in _SESSIONS.items():
        expired = (now - s.last_used) > _SESSION_TTL
        finished = s.proc.poll() is not None
        if expired or finished:
            dead.append(sid)
    for sid in dead:
        _stop_locked(sid)


def _stop_locked(sid: str) -> bool:
    s = _SESSIONS.pop(sid, None)
    if not s:
        return False
    try:
        if s.proc.poll() is None:
            s.proc.terminate()
            try:
                s.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                s.proc.kill()
    except Exception:  # noqa: BLE001
        pass
    try:
        os.unlink(s.output_file)
    except OSError:
        pass
    return True


def register(server: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
    """Start an interactsh-client session and return its unique payload domain."""
    exe = _binary()
    if not exe:
        return {
            "success": False,
            "error": (
                "interactsh-client not installed. Install with "
                "`go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`."
            ),
        }

    with _LOCK:
        _reap_locked()
        if len(_SESSIONS) >= _MAX_SESSIONS:
            return {
                "success": False,
                "error": f"Too many active OOB sessions ({_MAX_SESSIONS}). Stop one first.",
            }

    sid = uuid.uuid4().hex[:12]
    fd, out_path = tempfile.mkstemp(prefix=f"interactsh_{sid}_", suffix=".jsonl")
    os.close(fd)

    cmd = [exe, "-json", "-o", out_path]
    if server:
        cmd += ["-s", server]
    if token:
        cmd += ["-t", token]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception as e:  # noqa: BLE001
        try:
            os.unlink(out_path)
        except OSError:
            pass
        return {"success": False, "error": f"failed to launch interactsh-client: {e}"}

    session = _Session(sid=sid, proc=proc, output_file=out_path, server=server)
    reader = threading.Thread(target=_drain, args=(session,), daemon=True)
    session._reader = reader
    reader.start()

    deadline = time.time() + _REGISTER_TIMEOUT
    while time.time() < deadline:
        if session.payload_domain:
            break
        if proc.poll() is not None:
            break
        time.sleep(0.25)

    if not session.payload_domain:
        banner = "\n".join(session.raw_lines[-15:])
        _stop_locked_direct(session)
        return {
            "success": False,
            "error": "interactsh-client did not return a payload domain in time",
            "client_output": banner,
        }

    with _LOCK:
        _SESSIONS[sid] = session

    return _public_session(session, reused=False)


def _public_session(session: _Session, *, reused: bool = False) -> Dict[str, Any]:
    domain = session.payload_domain or ""
    sid = session.sid
    return {
        "success": True,
        "session_id": sid,
        "payload_domain": domain,
        "payload_url": f"https://{domain}" if domain else "",
        "payload_email": f"aegis@{domain}" if domain else "",
        "server": session.server or "default (oast.*)",
        "reused": reused,
        "next": (
            "Plant payload_url in the sink (SSRF/XXE/webhook) or payload_email "
            f"as the mail recipient. Then execute_interactsh poll {sid}. "
            "Do not use Canarytokens."
        ),
        "usage": (
            "Plant payload_url in blind sinks (SSRF url params, XXE SYSTEM, "
            "Host/Referer, webhooks) or payload_email as the mail recipient. "
            f"Then execute_interactsh poll {sid}. Do not use Canarytokens. "
            "Any DNS/HTTP/SMTP interaction is demonstrated OOB."
        ),
    }


def ensure_session(
    server: Optional[str] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Reuse a live Interactsh session or register a new one."""
    with _LOCK:
        _reap_locked()
        for session in _SESSIONS.values():
            if session.proc.poll() is None and session.payload_domain:
                if server and session.server and session.server != server:
                    continue
                session.last_used = time.time()
                return _public_session(session, reused=True)
    return register(server, token)


def _stop_locked_direct(session: _Session) -> None:
    """Stop a session object not yet registered in _SESSIONS."""
    try:
        if session.proc.poll() is None:
            session.proc.terminate()
            try:
                session.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                session.proc.kill()
    except Exception:  # noqa: BLE001
        pass
    try:
        os.unlink(session.output_file)
    except OSError:
        pass


def poll(session_id: str, only_new: bool = True) -> Dict[str, Any]:
    """Return interactions captured by a session since the last poll."""
    import json as _json

    with _LOCK:
        session = _SESSIONS.get(session_id)
    if not session:
        return {"success": False, "error": f"Unknown or expired session '{session_id}'. Register a new one."}

    session.last_used = time.time()

    lines: List[str] = []
    try:
        with open(session.output_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError as e:
        return {"success": False, "error": f"could not read session output: {e}"}

    start = session.read_offset if only_new else 0
    new_lines = lines[start:]
    if only_new:
        session.read_offset = len(lines)

    interactions: List[Dict[str, Any]] = []
    for ln in new_lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            evt = _json.loads(ln)
        except _json.JSONDecodeError:
            continue
        interactions.append({
            "protocol": evt.get("protocol"),
            "unique_id": evt.get("unique-id") or evt.get("full-id"),
            "remote_address": evt.get("remote-address"),
            "timestamp": evt.get("timestamp"),
            "q_type": evt.get("q-type"),
            "raw_request": (evt.get("raw-request") or "")[:2000],
        })

    alive = session.proc.poll() is None
    return {
        "success": True,
        "session_id": session_id,
        "payload_domain": session.payload_domain,
        "alive": alive,
        "new_interactions": len(interactions),
        "interactions": interactions,
        "note": None if alive else "session process has exited; register a new one for further testing",
    }


def list_sessions() -> Dict[str, Any]:
    with _LOCK:
        _reap_locked()
        sessions = [
            {
                "session_id": s.sid,
                "payload_domain": s.payload_domain,
                "server": s.server or "default",
                "alive": s.proc.poll() is None,
                "age_seconds": int(time.time() - s.created_at),
            }
            for s in _SESSIONS.values()
        ]
    return {"success": True, "active_sessions": len(sessions), "sessions": sessions}


def stop(session_id: str) -> Dict[str, Any]:
    with _LOCK:
        ok = _stop_locked(session_id)
    if not ok:
        return {"success": False, "error": f"Unknown session '{session_id}'"}
    return {"success": True, "stopped": session_id}
