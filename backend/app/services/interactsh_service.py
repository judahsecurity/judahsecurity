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

import json
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
from pathlib import Path
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
    session_file: Optional[str] = None
    metadata_file: Optional[str] = None
    server: Optional[str] = None
    payload_domain: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    raw_lines: List[str] = field(default_factory=list)
    read_offset: int = 0  # lines of the JSONL output already returned by poll
    _reader: Optional[threading.Thread] = None


_SESSIONS: Dict[str, _Session] = {}
_LOCK = threading.Lock()


def _truthy(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _rpc_enabled() -> bool:
    return _truthy("AEGIS_INTERACTSH_RPC_ENABLED") and not _truthy(
        "AEGIS_INTERACTSH_LOCAL"
    )


def _rpc_call(operation: str, **arguments) -> Dict[str, Any]:
    """Send one command to the dedicated Interactsh worker over Redis."""
    try:
        import redis

        timeout = max(
            5, int(os.environ.get("AEGIS_INTERACTSH_RPC_TIMEOUT_SECONDS", "35"))
        )
        client = redis.Redis.from_url(
            os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=timeout + 2,
        )
        request_id = uuid.uuid4().hex
        response_key = f"aegis:interactsh:response:{request_id}"
        request = json.dumps(
            {
                "id": request_id,
                "operation": operation,
                "arguments": arguments,
                "response_key": response_key,
            },
            default=str,
        )
        client.rpush("aegis:interactsh:requests", request)
        response = client.blpop(response_key, timeout=timeout)
        client.delete(response_key)
        if not response:
            return {
                "success": False,
                "error": "Interactsh worker did not respond before the RPC timeout",
            }
        payload = json.loads(response[1])
        return payload if isinstance(payload, dict) else {
            "success": False,
            "error": "Interactsh worker returned an invalid response",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Interactsh worker RPC failed: %s", exc)
        return {"success": False, "error": f"Interactsh worker unavailable: {exc}"}


def _state_dir() -> Optional[Path]:
    configured = (os.environ.get("AEGIS_INTERACTSH_STATE_DIR") or "").strip()
    if not configured:
        return None
    root = Path(configured)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def _session_paths(sid: str) -> tuple[str, Optional[str], Optional[str]]:
    root = _state_dir()
    if root is None:
        fd, output_file = tempfile.mkstemp(prefix=f"interactsh_{sid}_", suffix=".jsonl")
        os.close(fd)
        return output_file, None, None
    output_file = root / f"{sid}.jsonl"
    output_file.touch(mode=0o600, exist_ok=True)
    return str(output_file), str(root / f"{sid}.session"), str(root / f"{sid}.metadata.json")


def _persist_session(session: _Session) -> None:
    if not session.metadata_file:
        return
    payload = {
        "sid": session.sid,
        "output_file": session.output_file,
        "session_file": session.session_file,
        "server": session.server,
        "payload_domain": session.payload_domain,
        "created_at": session.created_at,
        "last_used": session.last_used,
        "read_offset": session.read_offset,
    }
    path = Path(session.metadata_file)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _delete_session_files(session: _Session) -> None:
    for filename in (session.output_file, session.session_file, session.metadata_file):
        if filename:
            try:
                os.unlink(filename)
            except OSError:
                pass


def _binary() -> Optional[str]:
    configured = (os.environ.get("AEGIS_INTERACTSH_CLIENT_BIN") or "").strip()
    candidates = [
        configured,
        str(Path(__file__).resolve().parents[3] / ".tools" / "bin" / "interactsh-client"),
        shutil.which("interactsh-client") or "",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)
    return None


def health() -> Dict[str, Any]:
    """Report whether the standalone callback client is executable."""
    if _rpc_enabled():
        return _rpc_call("health")
    exe = _binary()
    if not exe:
        return {
            "success": False,
            "installed": False,
            "error": (
                "interactsh-client not found in PATH, AEGIS_INTERACTSH_CLIENT_BIN, "
                "or the project .tools/bin directory"
            ),
        }
    try:
        result = subprocess.run(
            [exe, "-version"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "success": False,
            "installed": True,
            "binary": exe,
            "error": str(exc),
        }
    output = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    return {
        "success": result.returncode == 0,
        "installed": True,
        "binary": exe,
        "version_output": output[:1000],
        "active_sessions": len(_SESSIONS),
        "error": None if result.returncode == 0 else output[:1000],
    }


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
    _delete_session_files(s)
    return True


def register(server: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
    """Start an interactsh-client session and return its unique payload domain."""
    if _rpc_enabled():
        return _rpc_call("register", server=server, token=token)
    exe = _binary()
    if not exe:
        return {
            "success": False,
            "error": (
                "interactsh-client not installed. Install with "
                "`go install github.com/projectdiscovery/interactsh/cmd/"
                "interactsh-client@v1.3.1`."
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
    out_path, session_file, metadata_file = _session_paths(sid)

    cmd = [exe, "-json", "-o", out_path]
    if session_file:
        cmd += ["-sf", session_file]
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
        for filename in (out_path, session_file, metadata_file):
            if filename:
                try:
                    os.unlink(filename)
                except OSError:
                    pass
        return {"success": False, "error": f"failed to launch interactsh-client: {e}"}

    session = _Session(
        sid=sid,
        proc=proc,
        output_file=out_path,
        session_file=session_file,
        metadata_file=metadata_file,
        server=server,
    )
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
        _persist_session(session)

    if session_file and os.path.exists(session_file):
        try:
            os.chmod(session_file, 0o600)
        except OSError:
            pass

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
    if _rpc_enabled():
        return _rpc_call("ensure_session", server=server, token=token)
    with _LOCK:
        _reap_locked()
        for session in _SESSIONS.values():
            if session.proc.poll() is None and session.payload_domain:
                if server and session.server and session.server != server:
                    continue
                session.last_used = time.time()
                _persist_session(session)
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
    _delete_session_files(session)


def recover_sessions() -> Dict[str, Any]:
    """Resume persisted Interactsh registrations after the worker restarts."""
    root = _state_dir()
    exe = _binary()
    if root is None or not exe:
        return {"success": bool(exe), "recovered": 0}

    recovered = 0
    now = time.time()
    for metadata_path in sorted(root.glob("*.metadata.json")):
        if recovered >= _MAX_SESSIONS:
            break
        proc = None
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            sid = str(metadata.get("sid") or "")
            if not re.fullmatch(r"[0-9a-f]{12}", sid):
                raise ValueError("invalid session id")
            created_at = float(metadata.get("created_at") or 0)
            last_used = float(metadata.get("last_used") or created_at)
            if not created_at or now - last_used > _SESSION_TTL:
                raise TimeoutError("expired session")
            output_file = root / f"{sid}.jsonl"
            session_file = root / f"{sid}.session"
            if not session_file.is_file():
                raise FileNotFoundError("missing Interactsh session file")
            output_file.touch(mode=0o600, exist_ok=True)
            command = [
                exe,
                "-json",
                "-o",
                str(output_file),
                "-sf",
                str(session_file),
            ]
            server = metadata.get("server")
            if server:
                command += ["-s", str(server)]
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            session = _Session(
                sid=sid,
                proc=proc,
                output_file=str(output_file),
                session_file=str(session_file),
                metadata_file=str(metadata_path),
                server=str(server) if server else None,
                payload_domain=str(metadata.get("payload_domain") or "") or None,
                created_at=created_at,
                last_used=last_used,
                read_offset=max(0, int(metadata.get("read_offset") or 0)),
            )
            reader = threading.Thread(target=_drain, args=(session,), daemon=True)
            session._reader = reader
            reader.start()
            time.sleep(0.05)
            if proc.poll() is not None:
                raise RuntimeError("resumed Interactsh client exited")
            with _LOCK:
                _SESSIONS[sid] = session
                _persist_session(session)
            recovered += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not recover Interactsh session %s: %s", metadata_path, exc)
            if proc is not None and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    try:
                        proc.kill()
                    except Exception:  # noqa: BLE001
                        pass
            for candidate in (
                metadata_path,
                root / f"{metadata_path.name.removesuffix('.metadata.json')}.jsonl",
                root / f"{metadata_path.name.removesuffix('.metadata.json')}.session",
            ):
                try:
                    candidate.unlink(missing_ok=True)
                except OSError:
                    pass
    return {"success": True, "recovered": recovered}


def poll(session_id: str, only_new: bool = True) -> Dict[str, Any]:
    """Return interactions captured by a session since the last poll."""
    if _rpc_enabled():
        return _rpc_call("poll", session_id=session_id, only_new=only_new)

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
            evt = json.loads(ln)
        except json.JSONDecodeError:
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
    _persist_session(session)
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
    if _rpc_enabled():
        return _rpc_call("list")
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
    if _rpc_enabled():
        return _rpc_call("stop", session_id=session_id)
    with _LOCK:
        ok = _stop_locked(session_id)
    if not ok:
        return {"success": False, "error": f"Unknown session '{session_id}'"}
    return {"success": True, "stopped": session_id}
