"""Durable traffic recording for Prowl and the operator browser extension.

* Agent traffic: ``EvidenceStore.record("http_exchange", ...)`` calls
  :func:`record_agent_exchange`, which queues a redacted copy for a background
  writer so the agent's event loop never waits on Postgres.
* Extension traffic: :func:`ingest_extension_batch` validates scope and stores
  operator-captured exchanges synchronously in the request.
* Findings cite traffic through :class:`VulnerabilityTrafficRef` rows.

Everything stored here is redacted with the same rules as the evidence store
and truncated to ``MAX_BODY_BYTES`` per body.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
from datetime import datetime
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 256 * 1024
MAX_HEADER_COUNT = 100
MAX_EXTENSION_BATCH = 50
_QUEUE_SIZE = 2000

_SKIP_CONTENT_PREFIXES = ("image/", "font/", "audio/", "video/")
_SKIP_CONTENT_TYPES = ("application/octet-stream", "application/pdf", "application/zip")


def recording_enabled() -> bool:
    return os.environ.get("AEGIS_TRAFFIC_RECORDING", "1").strip().lower() not in ("0", "false", "no", "off")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

# Stricter than the evidence-store rules because stored traffic outlives the
# run: also hide custom session headers, one-time codes, OAuth codes and
# signatures, which do not match the shared secret-name list.
_EXTRA_SECRET_HEADER = re.compile(
    r"(?i)(session|^sess$|^sid$|auth|otp|mfa|2fa|totp|jwt|signature|security-token|id-token|refresh)"
)
_EXTRA_SECRET_KEY = re.compile(
    r"(?i)^(otp|totp|code|mfa_?code|verification_?code|one_?time_?code|session(_?id)?|sid|jwt"
    r"|id_?token|refresh_?token|signature|sig|x-amz-signature|x-amz-security-token|x-amz-credential)$"
)
_EXTRA_SECRET_PARAM = re.compile(
    r"(?i)((?:^|[?&;])(?:otp|totp|code|mfa_?code|verification_?code|one_?time_?code|session(?:_?id)?|sid"
    r"|jwt|id_?token|refresh_?token|signature|sig|x-amz-signature|x-amz-security-token|x-amz-credential)=)"
    r"[^&#\s;]+"
)
_REDACTED = "[redacted]"


def _redact_extra(value: Any, key: str = "") -> Any:
    if key and _EXTRA_SECRET_KEY.match(str(key)):
        return _REDACTED
    if isinstance(value, dict):
        return {k: _redact_extra(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_extra(v, key) for v in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return _EXTRA_SECRET_PARAM.sub(r"\1" + _REDACTED, value)
        if isinstance(parsed, (dict, list)):
            return json.dumps(_redact_extra(parsed))
        return _EXTRA_SECRET_PARAM.sub(r"\1" + _REDACTED, value)
    return value


def _redact(value: Any) -> Any:
    from app.services.agent.evidence_store import redact_artifact

    return _redact_extra(redact_artifact(value))


def _truncate(text: Any) -> tuple[Optional[str], bool]:
    if text is None:
        return None, False
    if not isinstance(text, str):
        text = str(text)
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= MAX_BODY_BYTES:
        return text, False
    return encoded[:MAX_BODY_BYTES].decode("utf-8", "ignore"), True


def _headers(raw: Any) -> dict:
    if isinstance(raw, list):
        pairs = [(h.get("name"), h.get("value")) for h in raw if isinstance(h, dict)]
    elif isinstance(raw, dict):
        pairs = list(raw.items())
    else:
        return {}
    out: dict[str, str] = {}
    for name, value in pairs[:MAX_HEADER_COUNT]:
        if not name:
            continue
        name = str(name)[:200]
        out[name] = _REDACTED if _EXTRA_SECRET_HEADER.search(name) else str(value if value is not None else "")[:4000]
    return _redact(out)


def _content_type(headers: dict) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == "content-type":
            return str(value).split(";", 1)[0].strip().lower()
    return ""


def is_binary_content(headers: dict) -> bool:
    ctype = _content_type(headers)
    return ctype.startswith(_SKIP_CONTENT_PREFIXES) or ctype in _SKIP_CONTENT_TYPES


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def normalize_exchange(
    *,
    method: str,
    url: str,
    request_headers: Any = None,
    request_body: Any = None,
    status_code: Any = None,
    response_headers: Any = None,
    response_body: Any = None,
    response_length: Any = None,
    elapsed_ms: Any = None,
) -> Optional[dict]:
    """Return column values for one exchange, or ``None`` when unusable."""
    url = str(url or "").strip()
    parts = urlsplit(url) if url else None
    if not parts or parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    req_headers = _headers(request_headers)
    resp_headers = _headers(response_headers)
    req_body, req_cut = _truncate(_redact(request_body) if request_body not in (None, "") else None)
    if is_binary_content(resp_headers):
        resp_body, resp_cut = None, False
    else:
        resp_body, resp_cut = _truncate(_redact(response_body) if response_body not in (None, "") else None)
    try:
        status = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status = None
    try:
        length = int(response_length) if response_length is not None else (
            len(response_body.encode()) if isinstance(response_body, str) else None
        )
    except (TypeError, ValueError):
        length = None
    try:
        elapsed = int(elapsed_ms) if elapsed_ms is not None else None
    except (TypeError, ValueError):
        elapsed = None
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return {
        "method": (str(method or "GET").upper().strip() or "GET")[:16],
        "url": _redact(url),
        "host": parts.hostname.lower()[:255],
        "path": _redact(path),
        "status_code": status,
        "request_headers": req_headers,
        "request_body": req_body,
        "response_headers": resp_headers,
        "response_body": resp_body,
        "response_length": length,
        "elapsed_ms": elapsed,
        "truncated": (1 if req_cut else 0) | (2 if resp_cut else 0),
    }


def exchange_from_evidence(record: dict) -> Optional[dict]:
    """Map an evidence-store ``http_exchange`` record to column values."""
    payload = record.get("payload") if isinstance(record, dict) else None
    if not isinstance(payload, dict) or payload.get("truncated"):
        return None
    req = payload.get("request") or {}
    resp = payload.get("response") or {}
    if not isinstance(req, dict) or not isinstance(resp, dict):
        return None
    elapsed = resp.get("elapsed_s")
    row = normalize_exchange(
        method=req.get("method"),
        url=req.get("url") or record.get("target"),
        request_headers=req.get("headers"),
        request_body=req.get("body"),
        status_code=resp.get("status"),
        response_headers=resp.get("headers"),
        response_body=resp.get("body", resp.get("body_preview")),
        response_length=resp.get("length"),
        elapsed_ms=round(float(elapsed) * 1000) if isinstance(elapsed, (int, float)) else None,
    )
    if row is None:
        return None
    row.update(
        artifact_id=str(record.get("id") or "")[:32] or None,
        hypothesis_id=str(record.get("hypothesis_id") or "")[:64] or None,
        identity=str(record.get("identity") or req.get("identity") or "")[:64] or None,
    )
    return row


# ---------------------------------------------------------------------------
# Background writer for agent traffic
# ---------------------------------------------------------------------------

class TrafficRecorder:
    """Bounded queue drained by one daemon thread. Drops (and logs) on overload."""

    def __init__(self, session_factory: Optional[Callable[[], Any]] = None):
        self._session_factory = session_factory
        self._queue: "queue.Queue[dict]" = queue.Queue(maxsize=_QUEUE_SIZE)
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.dropped = 0

    def _factory(self):
        if self._session_factory is None:
            from app.db.database import SessionLocal

            self._session_factory = SessionLocal
        return self._session_factory

    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="traffic-recorder", daemon=True)
                self._thread.start()

    def submit(self, row: dict) -> bool:
        try:
            self._queue.put_nowait(row)
        except queue.Full:
            self.dropped += 1
            if self.dropped % 100 == 1:
                logger.warning("traffic recorder queue full; dropped %d exchanges", self.dropped)
            return False
        self._ensure_thread()
        return True

    def _write(self, rows: list[dict]) -> None:
        from app.models.traffic import TrafficExchange

        db = self._factory()()
        try:
            db.add_all([TrafficExchange(**row) for row in rows])
            db.commit()
        except Exception:
            db.rollback()
            logger.warning("traffic recorder write failed for %d rows", len(rows), exc_info=True)
        finally:
            db.close()

    def _drain(self, first: dict) -> None:
        rows = [first]
        while len(rows) < 50:
            try:
                rows.append(self._queue.get_nowait())
            except queue.Empty:
                break
        try:
            self._write(rows)
        finally:
            for _ in rows:
                self._queue.task_done()

    def _run(self) -> None:
        while True:
            self._drain(self._queue.get())

    def flush(self) -> None:
        """Synchronously write everything queued (tests and shutdown)."""
        while True:
            try:
                first = self._queue.get_nowait()
            except queue.Empty:
                return
            self._drain(first)


_recorder = TrafficRecorder()


def recorder() -> TrafficRecorder:
    return _recorder


def record_agent_exchange(record: dict, organization_id: Optional[int], session_id: Optional[str]) -> bool:
    """Mirror one evidence-store exchange. Never raises into the agent."""
    if not organization_id or not recording_enabled():
        return False
    try:
        row = exchange_from_evidence(record)
        if row is None:
            return False
        row.update(
            organization_id=int(organization_id),
            source="agent",
            session_id=str(session_id or "")[:64] or None,
            created_at=datetime.utcnow(),
        )
        return _recorder.submit(row)
    except Exception:
        logger.debug("record_agent_exchange failed", exc_info=True)
        return False


# ---------------------------------------------------------------------------
# Extension ingest
# ---------------------------------------------------------------------------

def host_in_org_scope(db, organization_id: int, host: str) -> tuple[bool, str]:
    """A host is accepted only when RoE allows it and it belongs to an in-scope asset."""
    from app.models.asset import Asset, AssetType
    from app.services import roe_service

    host = (host or "").lower().strip(".")
    if not host:
        return False, "missing host"
    allowed, reason = roe_service.check_target(db, organization_id, host)
    if not allowed:
        return False, reason or "blocked by rules of engagement"
    candidates = {host}
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        candidates.add(".".join(labels[i:]))
    rows = db.query(Asset.value, Asset.asset_type).filter(
        Asset.organization_id == organization_id,
        Asset.in_scope.isnot(False),
        Asset.value.in_(list(candidates)),
    ).all()
    for value, asset_type in rows:
        value = (value or "").lower()
        if value == host:
            return True, ""
        if asset_type in (AssetType.DOMAIN, AssetType.DOMAIN.value) and host.endswith("." + value):
            return True, ""
    return False, f"host '{host}' is not an in-scope asset of this organization"


def ingest_extension_batch(db, *, organization_id: int, agent_key_id: Optional[int],
                           capture_id: str, entries: Iterable[dict]) -> dict:
    from app.models.traffic import TrafficExchange

    accepted = 0
    rejected: list[dict] = []
    skipped = 0
    scope_cache: dict[str, tuple[bool, str]] = {}
    for index, entry in enumerate(list(entries)[:MAX_EXTENSION_BATCH]):
        if not isinstance(entry, dict):
            rejected.append({"index": index, "reason": "not an object"})
            continue
        host = host_of(str(entry.get("url") or ""))
        if host not in scope_cache:
            scope_cache[host] = host_in_org_scope(db, organization_id, host)
        ok, reason = scope_cache[host]
        if not ok:
            rejected.append({"index": index, "reason": reason})
            continue
        row = normalize_exchange(
            method=entry.get("method"),
            url=entry.get("url"),
            request_headers=entry.get("request_headers"),
            request_body=entry.get("request_body"),
            status_code=entry.get("status"),
            response_headers=entry.get("response_headers"),
            response_body=entry.get("response_body"),
            elapsed_ms=entry.get("elapsed_ms"),
        )
        if row is None:
            skipped += 1
            continue
        page_url = str(entry.get("page_url") or "")[:2000] or None
        db.add(TrafficExchange(
            organization_id=organization_id,
            source="extension",
            capture_id=(capture_id or "")[:64] or None,
            page_url=_redact(page_url) if page_url else None,
            agent_key_id=agent_key_id,
            created_at=datetime.utcnow(),
            **row,
        ))
        accepted += 1
    db.commit()
    return {"accepted": accepted, "skipped": skipped, "rejected": rejected}


# ---------------------------------------------------------------------------
# Queries and bindings
# ---------------------------------------------------------------------------

def summary(row) -> dict:
    return {
        "id": row.id,
        "source": row.source,
        "session_id": row.session_id,
        "artifact_id": row.artifact_id,
        "capture_id": row.capture_id,
        "identity": row.identity,
        "method": row.method,
        "url": row.url,
        "host": row.host,
        "status_code": row.status_code,
        "response_length": row.response_length,
        "elapsed_ms": row.elapsed_ms,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def detail(row) -> dict:
    return {
        **summary(row),
        "path": row.path,
        "page_url": row.page_url,
        "hypothesis_id": row.hypothesis_id,
        "request_headers": row.request_headers or {},
        "request_body": row.request_body,
        "response_headers": row.response_headers or {},
        "response_body": row.response_body,
        "truncated": {"request_body": bool(row.truncated & 1), "response_body": bool(row.truncated & 2)},
    }


def search(db, organization_id: int, *, q: str = "", host: str = "", method: str = "",
           status_code: Optional[int] = None, source: str = "", session_id: str = "",
           limit: int = 50, offset: int = 0):
    from sqlalchemy import or_

    from app.models.traffic import TrafficExchange

    query = db.query(TrafficExchange).filter(TrafficExchange.organization_id == organization_id)
    if host:
        query = query.filter(TrafficExchange.host == host.lower().strip())
    if method:
        query = query.filter(TrafficExchange.method == method.upper().strip())
    if status_code is not None:
        query = query.filter(TrafficExchange.status_code == status_code)
    if source:
        query = query.filter(TrafficExchange.source == source)
    if session_id:
        query = query.filter(TrafficExchange.session_id == session_id)
    if q:
        like = f"%{q.strip()[:200]}%"
        query = query.filter(or_(
            TrafficExchange.url.ilike(like),
            TrafficExchange.request_body.ilike(like),
            TrafficExchange.response_body.ilike(like),
        ))
    total = query.count()
    rows = query.order_by(TrafficExchange.created_at.desc(), TrafficExchange.id.desc()) \
        .offset(max(0, offset)).limit(max(1, min(limit, 200))).all()
    return total, rows


def bind_artifacts(db, *, vulnerability_id: int, organization_id: int,
                   artifact_ids: Iterable[str], start_position: int = 0) -> int:
    """Bind agent evidence artifacts to a finding (idempotent, order-preserving)."""
    from app.models.traffic import VulnerabilityTrafficRef

    existing = {
        ref.artifact_id for ref in db.query(VulnerabilityTrafficRef.artifact_id).filter(
            VulnerabilityTrafficRef.vulnerability_id == vulnerability_id,
            VulnerabilityTrafficRef.artifact_id.isnot(None),
        )
    }
    added = 0
    for artifact_id in artifact_ids:
        artifact_id = str(artifact_id or "")[:32]
        if not artifact_id or artifact_id in existing:
            continue
        existing.add(artifact_id)
        db.add(VulnerabilityTrafficRef(
            vulnerability_id=vulnerability_id,
            organization_id=organization_id,
            artifact_id=artifact_id,
            position=start_position + added,
            bound_by="agent",
        ))
        added += 1
    return added


def traffic_for_vulnerability(db, vulnerability_id: int, organization_id: int) -> list[dict]:
    from app.models.traffic import TrafficExchange, VulnerabilityTrafficRef

    refs = db.query(VulnerabilityTrafficRef).filter(
        VulnerabilityTrafficRef.vulnerability_id == vulnerability_id,
    ).order_by(VulnerabilityTrafficRef.position.asc(), VulnerabilityTrafficRef.id.asc()).all()
    by_artifact: dict[str, Any] = {}
    artifact_ids = [r.artifact_id for r in refs if r.artifact_id and not r.traffic_id]
    if artifact_ids:
        for row in db.query(TrafficExchange).filter(
            TrafficExchange.organization_id == organization_id,
            TrafficExchange.artifact_id.in_(artifact_ids),
        ):
            by_artifact[row.artifact_id] = row
    traffic_ids = [r.traffic_id for r in refs if r.traffic_id]
    by_id = {
        row.id: row for row in db.query(TrafficExchange).filter(
            TrafficExchange.organization_id == organization_id,
            TrafficExchange.id.in_(traffic_ids),
        )
    } if traffic_ids else {}
    out = []
    for ref in refs:
        row = by_id.get(ref.traffic_id) if ref.traffic_id else by_artifact.get(ref.artifact_id)
        out.append({
            "ref_id": ref.id,
            "position": ref.position,
            "note": ref.note,
            "bound_by": ref.bound_by,
            "artifact_id": ref.artifact_id,
            "exchange": summary(row) if row is not None else None,
            "pending": row is None,
        })
    return out
