"""Operator-captured logged-in traffic: browser extension and HAR upload.

An analyst logs in to the target in their own browser (captcha, OTP, 2FA, SSO
all handled by a human), and either the Judah capture extension streams the
session's requests/responses here or they upload a DevTools HAR. Each batch:

* is bound to one agent session and one named test identity by a short-lived,
  HMAC-signed capture token (or the analyst's own login for HAR upload);
* is normalized (text bodies only, bounded sizes) and stored encrypted at rest
  until the running assessment drains it;
* on drain, is filtered to the engagement's network scope, registers or
  refreshes the identity's cookies and auth headers in the identity registry
  (never shown to the model), records every exchange as redacted
  ``http_exchange`` evidence, and maps the requests into operations so
  specialists can mutate them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

TOKEN_TTL_SECONDS = 4 * 3600
MAX_ENTRIES_PER_BATCH = 50
MAX_BODY_CHARS = 256 * 1024
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_PENDING_BATCHES = 200
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}\Z")
_SESSION = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_MAGIC = b"JUDAH_OPCAPTURE_1\0"
# Request headers that carry the logged-in session, replayed for the identity.
_SESSION_HEADERS = ("authorization", "x-csrf-token", "x-xsrf-token", "x-api-key", "x-auth-token")
_SKIP_MIME = ("image/", "font/", "video/", "audio/", "application/octet-stream",
              "application/zip", "application/pdf", "application/wasm")


class CaptureError(ValueError):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


# --------------------------------------------------------------------------
# capture tokens
# --------------------------------------------------------------------------

def _token_key() -> bytes:
    return hashlib.sha256(b"judah-operator-capture-token-v1\0" + settings.SECRET_KEY.encode()).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def validate_identity(name: str) -> str:
    name = str(name or "").strip()
    if not _IDENTITY.fullmatch(name) or name in ("anonymous", "legacy"):
        raise CaptureError(422, "identity must be 1-40 letters, digits, dot, dash or underscore, "
                                "and not 'anonymous' or 'legacy'")
    return name


def issue_token(*, organization_id: int, session_id: str, user_id: int, identity: str,
                role: str = "", tenant: str = "", ttl: int = TOKEN_TTL_SECONDS) -> Dict[str, Any]:
    if not _SESSION.fullmatch(str(session_id or "")):
        raise CaptureError(422, "invalid session id")
    claims = {
        "org": int(organization_id), "sid": session_id, "uid": int(user_id),
        "identity": validate_identity(identity), "role": str(role or "")[:40],
        "tenant": str(tenant or "")[:80], "exp": int(time.time()) + max(60, min(int(ttl), 12 * 3600)),
        "jti": uuid.uuid4().hex,
    }
    body = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_token_key(), body.encode(), hashlib.sha256).digest())
    return {"token": f"jcap.{body}.{sig}", "expires_at": claims["exp"], "identity": claims["identity"]}


def verify_token(token: str) -> Dict[str, Any]:
    try:
        prefix, body, sig = str(token or "").split(".")
    except ValueError:
        raise CaptureError(401, "invalid capture token") from None
    expected = _b64(hmac.new(_token_key(), body.encode(), hashlib.sha256).digest())
    if prefix != "jcap" or not hmac.compare_digest(sig, expected):
        raise CaptureError(401, "invalid capture token")
    try:
        claims = json.loads(_unb64(body))
    except (ValueError, UnicodeDecodeError):
        raise CaptureError(401, "invalid capture token") from None
    if int(claims.get("exp") or 0) < time.time():
        raise CaptureError(401, "capture token expired")
    return claims


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------

def _headers(raw: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(raw, dict):
        items: Iterable = raw.items()
    elif isinstance(raw, list):
        items = ((h.get("name"), h.get("value")) for h in raw if isinstance(h, dict))
    else:
        return out
    for name, value in items:
        name = str(name or "").strip()
        if not name or name.startswith(":") or len(out) >= 80:
            continue
        out[name[:100]] = str(value or "")[:8000]
    return out


def _header(headers: Dict[str, str], name: str) -> str:
    name = name.lower()
    return next((v for k, v in headers.items() if k.lower() == name), "")


def normalize_entry(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One captured exchange in the shape the extension sends."""
    if not isinstance(raw, dict):
        return None
    method = str(raw.get("method") or "GET").upper()[:10]
    url = str(raw.get("url") or "")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or len(url) > 8000:
        return None
    req_headers = _headers(raw.get("request_headers"))
    resp_headers = _headers(raw.get("response_headers"))
    mime = (str(raw.get("mime_type") or "") or _header(resp_headers, "content-type")).lower()
    if any(mime.startswith(prefix) for prefix in _SKIP_MIME):
        return None
    try:
        status = int(raw.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    request_body = str(raw.get("request_body") or "")
    response_body = str(raw.get("response_body") or "")
    return {
        "request": {"method": method, "url": url, "headers": req_headers,
                    "body": request_body[:MAX_BODY_CHARS], "body_len": len(request_body)},
        "response": {"status": status, "url": url, "headers": resp_headers,
                     "body": response_body[:MAX_BODY_CHARS],
                     "body_preview": response_body[:4000], "length": len(response_body),
                     "truncated": len(response_body) > MAX_BODY_CHARS},
        "captured_at": raw.get("captured_at") or time.time(),
    }


def har_entries(har: Any) -> List[Dict[str, Any]]:
    """Convert a DevTools HAR (dict or JSON text) into extension-shaped entries."""
    if isinstance(har, (str, bytes)):
        try:
            har = json.loads(har)
        except ValueError:
            raise CaptureError(422, "HAR is not valid JSON") from None
    entries = ((har or {}).get("log") or {}).get("entries") if isinstance(har, dict) else None
    if not isinstance(entries, list):
        raise CaptureError(422, "HAR has no log.entries")
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        content = response.get("content") or {}
        text = content.get("text") or ""
        if content.get("encoding") == "base64":
            try:
                text = base64.b64decode(text).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                text = ""
        out.append({
            "method": request.get("method"), "url": request.get("url"),
            "request_headers": request.get("headers"),
            "request_body": (request.get("postData") or {}).get("text") or "",
            "status": response.get("status"),
            "response_headers": response.get("headers"),
            "response_body": text, "mime_type": content.get("mimeType") or "",
            "captured_at": entry.get("startedDateTime"),
        })
    return out


def normalize_batch(entries: Any) -> List[Dict[str, Any]]:
    if not isinstance(entries, list):
        raise CaptureError(422, "entries must be a list")
    clean = [row for row in (normalize_entry(e) for e in entries[: MAX_ENTRIES_PER_BATCH * 20]) if row]
    return clean


# --------------------------------------------------------------------------
# encrypted inbox
# --------------------------------------------------------------------------

def _inbox_dir(organization_id: int, session_id: str) -> Optional[Path]:
    root = (os.environ.get("AEGIS_EVIDENCE_DIR") or "").strip()
    if not root or not _SESSION.fullmatch(str(session_id or "")):
        return None
    name = hashlib.sha256(f"{int(organization_id)}:{session_id}".encode()).hexdigest()[:32]
    return Path(root) / "operator_captures" / name


def _box_key() -> bytes:
    return hashlib.sha256(b"judah-operator-capture-inbox-v1\0" + settings.SECRET_KEY.encode()).digest()


def enqueue(organization_id: int, session_id: str, *, identity: str, role: str, tenant: str,
            entries: List[Dict[str, Any]], source: str) -> Dict[str, Any]:
    directory = _inbox_dir(organization_id, session_id)
    if directory is None:
        raise CaptureError(503, "capture storage is not configured (AEGIS_EVIDENCE_DIR)")
    if not entries:
        return {"accepted": 0, "batches": 0}
    if directory.is_symlink():
        raise CaptureError(500, "capture storage path is invalid")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if len(list(directory.glob("*.capture"))) >= MAX_PENDING_BATCHES:
        raise CaptureError(429, "too many undelivered capture batches; start or resume the assessment")
    batches = 0
    for start in range(0, len(entries), MAX_ENTRIES_PER_BATCH):
        chunk = entries[start:start + MAX_ENTRIES_PER_BATCH]
        payload = json.dumps({"identity": identity, "role": role, "tenant": tenant,
                              "source": source, "entries": chunk}).encode()
        if len(payload) > MAX_BATCH_BYTES:
            raise CaptureError(413, "capture batch too large")
        batch_id = f"{int(time.time() * 1000):015d}-{uuid.uuid4().hex}"
        nonce = os.urandom(12)
        blob = _MAGIC + nonce + AESGCM(_box_key()).encrypt(nonce, payload, batch_id.encode())
        temporary = directory / f".{batch_id}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(blob)
        os.replace(temporary, directory / f"{batch_id}.capture")
        batches += 1
    return {"accepted": len(entries), "batches": batches}


def pending_count(organization_id: int, session_id: str) -> int:
    directory = _inbox_dir(organization_id, session_id)
    return len(list(directory.glob("*.capture"))) if directory and directory.is_dir() else 0


def drain(organization_id: int, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    directory = _inbox_dir(organization_id, session_id)
    if directory is None or not directory.is_dir() or directory.is_symlink():
        return []
    batches = []
    for path in sorted(directory.glob("*.capture"))[:limit]:
        try:
            blob = path.read_bytes()
            nonce = blob[len(_MAGIC):len(_MAGIC) + 12]
            payload = AESGCM(_box_key()).decrypt(nonce, blob[len(_MAGIC) + 12:], path.stem.encode())
            batches.append(json.loads(payload))
        except (OSError, InvalidTag, ValueError):
            pass
        finally:
            path.unlink(missing_ok=True)
    return batches


# --------------------------------------------------------------------------
# apply to a running assessment
# --------------------------------------------------------------------------

def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


def _session_material(entries: List[Dict[str, Any]]) -> Tuple[List[Dict[str, str]], Dict[str, str]]:
    """Cookies and auth headers from the most recent requests that carried them."""
    cookies: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    for entry in sorted(entries, key=lambda e: str(e.get("captured_at") or "")):
        req_headers = entry["request"]["headers"]
        for pair in _header(req_headers, "cookie").split(";"):
            name, sep, value = pair.strip().partition("=")
            if sep and name:
                cookies[name] = value
        for name in _SESSION_HEADERS:
            value = _header(req_headers, name)
            if value:
                headers[name.title() if name == "authorization" else name] = value
    return [{"name": k, "value": v} for k, v in cookies.items()], headers


async def apply_batches(manager: Any, batches: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Register identities, record evidence and map operations. Returns a summary."""
    from app.services.agent.assessment_scope import assert_url_in_scope
    from app.services.agent.assessment_sessions import identity_registry
    from app.services.agent.evidence_store import evidence_store

    summary: Dict[str, Any] = {"recorded": 0, "out_of_scope": 0, "identities": [], "evidence_ids": []}
    store = evidence_store(manager)
    for batch in batches:
        identity = str(batch.get("identity") or "")
        entries = [e for e in batch.get("entries") or [] if isinstance(e, dict) and e.get("request")]
        in_scope = []
        for entry in entries:
            try:
                assert_url_in_scope(manager, entry["request"]["url"])
            except ValueError:
                summary["out_of_scope"] += 1
                continue
            in_scope.append(entry)
        by_origin: Dict[str, List[Dict[str, Any]]] = {}
        for entry in in_scope:
            by_origin.setdefault(_origin(entry["request"]["url"]), []).append(entry)
        for origin, rows in by_origin.items():
            cookies, headers = _session_material(rows)
            if cookies or headers:
                try:
                    identity_registry(manager).register(
                        identity, origin, cookies=cookies, headers=headers,
                        role=str(batch.get("role") or ""), tenant=str(batch.get("tenant") or ""),
                    )
                    if identity not in summary["identities"]:
                        summary["identities"].append(identity)
                except ValueError:
                    pass
            for entry in rows:
                status = int(entry["response"].get("status") or 0)
                evidence_id = store.record(
                    "http_exchange", {**entry, "source": "operator_capture"},
                    target=entry["request"]["url"], identity=identity,
                    test_type="operator_capture", success=0 < status < 400,
                )
                summary["evidence_ids"].append(evidence_id)
                summary["recorded"] += 1
            mapper = getattr(manager, "map_application_traffic", None)
            if callable(mapper):
                await mapper(
                    [dict(method=e["request"]["method"], url=e["request"]["url"],
                          headers={k: v for k, v in e["request"]["headers"].items()
                                   if k.lower() not in ("cookie",) + _SESSION_HEADERS},
                          body=e["request"]["body"]) for e in rows],
                    identity=identity, source="operator_capture",
                )
    summary["evidence_ids"] = summary["evidence_ids"][-50:]
    return summary
