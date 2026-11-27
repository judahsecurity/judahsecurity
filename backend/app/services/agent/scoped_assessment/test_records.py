"""Prowl-owned test records for intent-backed PUT/PATCH/DELETE probes.

The rule: **write probes only ever touch records Prowl created and verified as
its own.** A company's existing data is never the target of a write probe, not
even when the operator's intent names a concrete record URL.

The operator approves, per assessment (``AgentAssessmentPolicy.
test_record_endpoints``, at most four), how Prowl may make a dummy record:

``create_path``     exact path; Prowl POSTs ``create_body`` here
``create_body``     JSON object or form string holding ``__PROWL_NONCE__``
``content_type``    ``json`` | ``form``
``record_path``     exact path with exactly one ``{id}`` placeholder
``id_source``       ``location`` | ``json:<dotted.field>``
``write_methods``   subset of PUT/PATCH/DELETE probes may send to the record
``cleanup``         ``delete`` | ``none``; ``delete`` also needs
                    ``cleanup_delete_approved: true``

Lifecycle (``OwnRecordWriter``): match the cell to ``record_path`` (a concrete
id in the intent is never used; the request is retargeted), POST create with
a fresh nonce, GET the new record and require the nonce (ownership), send the
probe requests to that record URL only, then clean up (DELETE + GET confirm)
when ``cleanup`` is ``delete`` or the probe itself was a DELETE. A record that
could not be confirmed as Prowl's own is never deleted: it is reported
``cleanup_pending`` for the operator.

All requests go through ``intent_request._open`` (exact origin, no redirects,
identity cookies only, no Authorization header).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

NONCE = "__PROWL_NONCE__"
MAX_ENDPOINTS = 4
MAX_CREATE_BODY = 4096
MAX_REGISTRY = 200
WRITE_METHODS = ("PUT", "PATCH", "DELETE")
ID_PLACEHOLDER = "{id}"
RECORD_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_JSON_FIELD = re.compile(r"[A-Za-z0-9_-]{1,64}(?:\.[A-Za-z0-9_-]{1,64}){0,4}\Z")
_ENDPOINT_KEYS = frozenset({"create_path", "create_body", "content_type", "record_path",
                            "id_source", "write_methods", "cleanup", "cleanup_delete_approved"})
_REQUIRED_KEYS = _ENDPOINT_KEYS - {"cleanup_delete_approved"}
# Placeholder id used only to plan requests; ``OwnRecordWriter.bind`` always
# replaces the whole path before anything is sent.
PLAN_ID = "prowl-record-pending"
STATES = ("active", "create_failed", "cleaned", "cleanup_pending")
MAX_READ = 256 * 1024


class TestRecordAborted(ValueError):
    """The dummy record could not be created or verified; no probe was sent to it."""

    __test__ = False  # not a pytest class


def _exact_path(path: Any, *, allow_id: bool) -> str:
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or path == "/" or len(path) > 256
            or any(char in path for char in "?#\\\r\n\t %")
            or any(segment in {".", ".."} for segment in path.split("/"))
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in path)):
        raise ValueError("test record paths must be exact absolute paths without query, "
                         "fragment, percent-escapes or dot segments")
    rest = path.replace(ID_PLACEHOLDER, "", 1) if allow_id else path
    if allow_id and path.count(ID_PLACEHOLDER) != 1:
        raise ValueError("record_path must hold exactly one {id} placeholder")
    if "{" in rest or "}" in rest:
        raise ValueError("{id} may appear only once, in record_path")
    return path


def normalize_endpoint(row: Any) -> Dict[str, Any]:
    """One validated endpoint (canonical dict) or ``ValueError``."""
    if not isinstance(row, dict) or not _REQUIRED_KEYS <= set(row) or set(row) - _ENDPOINT_KEYS:
        raise ValueError("test_record_endpoints entries need exactly create_path, create_body, "
                         "content_type, record_path, id_source, write_methods, cleanup "
                         "(and cleanup_delete_approved)")
    create_path = _exact_path(row["create_path"], allow_id=False)
    record_path = _exact_path(row["record_path"], allow_id=True)
    content_type = row["content_type"]
    body = row["create_body"]
    if content_type == "json":
        if not isinstance(body, dict):
            raise ValueError("a json create_body must be a JSON object")
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    elif content_type == "form":
        if (not isinstance(body, str) or not body
                or any(ord(char) < 0x20 or ord(char) == 0x7f for char in body)):
            raise ValueError("a form create_body must be one urlencoded line")
        encoded = body
    else:
        raise ValueError("content_type must be json or form")
    if NONCE not in encoded:
        raise ValueError("create_body must contain __PROWL_NONCE__ at least once")
    if len(encoded.encode()) > MAX_CREATE_BODY:
        raise ValueError(f"create_body must be at most {MAX_CREATE_BODY} bytes")
    id_source = row["id_source"]
    if not isinstance(id_source, str) or not (
            id_source == "location"
            or id_source.startswith("json:") and _JSON_FIELD.fullmatch(id_source[5:])):
        raise ValueError("id_source must be location or json:<dotted field>")
    methods = row["write_methods"]
    if (not isinstance(methods, list) or not methods or len(set(methods)) != len(methods)
            or any(m not in WRITE_METHODS for m in methods)):
        raise ValueError("write_methods must be a non-empty subset of PUT, PATCH, DELETE")
    cleanup = row["cleanup"]
    if cleanup not in ("delete", "none"):
        raise ValueError("cleanup must be delete or none")
    approved = row.get("cleanup_delete_approved", False)
    if not isinstance(approved, bool):
        raise ValueError("cleanup_delete_approved must be a boolean")
    if cleanup == "delete" and approved is not True:
        # The cleanup DELETE is the only DELETE Prowl sends besides a DELETE
        # probe on its own record: the operator approves it by name.
        raise ValueError("cleanup delete requires cleanup_delete_approved: true")
    if cleanup == "none" and approved:
        raise ValueError("cleanup_delete_approved is only valid with cleanup delete")
    return {"create_path": create_path, "create_body": body, "content_type": content_type,
            "record_path": record_path, "id_source": id_source,
            "write_methods": [m for m in WRITE_METHODS if m in methods],
            "cleanup": cleanup, "cleanup_delete_approved": approved}


def validate_endpoints(rows: Any) -> List[Dict[str, Any]]:
    if rows is None:
        return []
    if not isinstance(rows, list) or len(rows) > MAX_ENDPOINTS:
        raise ValueError(f"test_record_endpoints must be a list of at most {MAX_ENDPOINTS}")
    out = [normalize_endpoint(row) for row in rows]
    if len({row["record_path"] for row in out}) != len(out):
        raise ValueError("test_record_endpoints must not repeat a record_path")
    return out


def _template_regex(record_path: str) -> "re.Pattern[str]":
    head, _sep, tail = record_path.partition(ID_PLACEHOLDER)
    return re.compile(re.escape(head) + r"([^/]{1,128})" + re.escape(tail) + r"\Z")


def path_matches(record_path: str, path: str) -> bool:
    """The cell path names this record template (literal ``{id}`` or any one id)."""
    decoded = unquote(str(path or ""))
    return decoded == record_path or bool(_template_regex(record_path).fullmatch(decoded))


def match_endpoint(endpoints: List[Dict[str, Any]], method: str,
                   path: str) -> Optional[Dict[str, Any]]:
    method = str(method or "").upper()
    return next((row for row in endpoints or []
                 if method in row["write_methods"] and path_matches(row["record_path"], path)),
                None)


def record_path_for(endpoint: Dict[str, Any], record_id: str) -> str:
    if not RECORD_ID.fullmatch(record_id or ""):
        raise TestRecordAborted("record id is not a short safe token")
    return endpoint["record_path"].replace(ID_PLACEHOLDER, record_id, 1)


def create_body_bytes(endpoint: Dict[str, Any], nonce: str) -> bytes:
    if endpoint["content_type"] == "json":
        encoded = json.dumps(endpoint["create_body"], ensure_ascii=False, separators=(",", ":"))
    else:
        encoded = endpoint["create_body"]
    # The nonce is lowercase hex: safe in JSON strings and form values alike.
    return encoded.replace(NONCE, nonce).encode()


def _walk(document: Any, dotted: str) -> Any:
    for token in dotted.split("."):
        if not isinstance(document, dict) or token not in document:
            return None
        document = document[token]
    return document


def extract_id(endpoint: Dict[str, Any], *, create_url: str, location: str,
               body: bytes) -> str:
    """The new record's id from the create response, or '' when absent or unsafe."""
    source = endpoint["id_source"]
    if source == "location":
        if not location:
            return ""
        try:
            resolved = urlsplit(urljoin(create_url, location))
        except ValueError:
            return ""
        created = urlsplit(create_url)
        if (resolved.scheme, resolved.netloc) != (created.scheme, created.netloc):
            return ""
        match = _template_regex(endpoint["record_path"]).fullmatch(unquote(resolved.path))
        value = match.group(1) if match else ""
    else:
        try:
            value = _walk(json.loads(body or b"null"), source[5:])
        except (UnicodeDecodeError, ValueError):
            return ""
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return ""
        value = str(value)
    return value if RECORD_ID.fullmatch(value) else ""


def nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()[:16]


def public_record(row: Dict[str, Any]) -> Dict[str, Any]:
    """Operator/model view of one registry row (no raw nonce, no bodies)."""
    keys = ("id", "endpoint", "create_path", "record_path", "path", "record_id", "state",
            "reason", "identity", "role", "created_at", "updated_at", "cleanup",
            "nonce_sha256", "coverage_cell_id", "probe_method", "evidence_ids")
    return {key: row.get(key) for key in keys if key in row}


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    pending = [public_record(row) for row in rows if row.get("state") == "cleanup_pending"]
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row.get("state", "")] = counts.get(row.get("state", ""), 0) + 1
    return {"count": len(rows), "by_state": counts, "cleanup_pending": pending,
            "records": [public_record(row) for row in rows][-50:]}


def cleanup_notice(rows: List[Dict[str, Any]]) -> str:
    """One operator-facing line for records Prowl could not remove, else ''."""
    pending = [row for row in rows if row.get("state") == "cleanup_pending"]
    if not pending:
        return ""
    listed = "; ".join(f"{row.get('path')} ({row.get('reason') or 'not removed'})"
                       for row in pending[:10])
    more = f" and {len(pending) - 10} more" if len(pending) > 10 else ""
    return (f"Test records left for manual cleanup: {len(pending)} record(s) Prowl created "
            f"were not confirmed removed: {listed}{more}. See list_test_records.")


class OwnRecordWriter:
    """Create, verify, bind and clean up Prowl's own record for one probe.

    Synchronous (runs inside ``asyncio.to_thread`` next to the probe). The
    manager supplies budgets, the registry and evidence recording.
    """

    def __init__(self, manager: Any, endpoint: Dict[str, Any], *, method: str,
                 identity: str, state: Optional[dict], scoped_origin: str,
                 coverage_cell_id: str = "", send: Optional[Callable[..., Any]] = None):
        from . import intent_request

        self.manager = manager
        self.endpoint = endpoint
        self.method = method
        self.identity = identity
        self.state = state
        self.origin = scoped_origin
        self.cell_id = coverage_cell_id
        self._ir = intent_request
        self._send = send
        self.current: Optional[Dict[str, Any]] = None
        self.nonce = ""
        self.records: List[Dict[str, Any]] = []
        self.sent_paths: List[str] = []
        self._reserved: Dict[str, int] = {}

    # ---------------------------------------------------------- transport

    def _open(self, req: Any):
        send = self._send or self._ir._open
        return send(req, allowed_origin=self.origin)

    def _request(self, method: str, path: str, body: Optional[bytes] = None,
                 content_type: str = ""):
        headers = [("Accept", "application/json, text/html, */*;q=0.8")]
        if content_type:
            headers.append(("Content-Type", content_type))
        url = self.origin + path
        cookies = self._ir._cookie_pairs(self.state, url)
        if cookies:
            headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in cookies)))
        req = self._ir.PlannedRequest(method=method, url=url, headers=tuple(headers), body=body)
        self._spend(method)
        with self._open(req) as response:
            status = int(response.status or 0)
            location = response.headers.get("Location", "") if response.headers else ""
            data = response.read(MAX_READ) or b""
        return status, location, data

    def _spend(self, method: str) -> None:
        """Use the reservation made at create time, else charge the budget now."""
        kind = "GET" if method == "GET" else "POST"
        if self._reserved.get(kind, 0) > 0:
            self._reserved[kind] -= 1
        elif kind == "GET":
            self.manager._scoped_claim_gets(1)
        else:
            self.manager._scoped_claim_posts(1)

    # ---------------------------------------------------------- registry

    def _register(self, **fields: Any) -> Dict[str, Any]:
        from app.services.agent.evidence_store import verification_run

        now = time.time()
        row = {"id": "tr_" + secrets.token_hex(6), "endpoint": self.endpoint["record_path"],
               "create_path": self.endpoint["create_path"], "path": "", "record_id": "",
               "state": "active", "reason": "", "identity": self.identity,
               "role": "verifier" if verification_run.get() is not None else "hunter",
               "created_at": now, "updated_at": now, "cleanup": self.endpoint["cleanup"],
               "coverage_cell_id": self.cell_id, "probe_method": self.method,
               "evidence_ids": [], **fields}
        registry = list(getattr(self.manager, "_scoped_test_records", None) or [])
        registry.append(row)
        self.manager._scoped_test_records = registry[-MAX_REGISTRY:]
        self.records.append(row)
        self._persist()
        return row

    def _persist(self) -> None:
        persist = getattr(self.manager, "_persist_test_records", None)
        if callable(persist):
            try:
                persist()
            except Exception:
                pass

    def _update(self, row: Dict[str, Any], **fields: Any) -> None:
        row.update(fields, updated_at=time.time())
        self.manager._scoped_test_records = list(
            getattr(self.manager, "_scoped_test_records", None) or [])
        self._persist()

    def _evidence(self, row: Dict[str, Any], step: str, **payload: Any) -> None:
        from app.services.agent.evidence_store import evidence_store

        try:
            artifact_id = evidence_store(self.manager).record(
                "scoped_test_record", {"step": step, **public_record(row), **payload},
                target=self.origin + (row.get("path") or row["create_path"]),
                identity=self.identity, coverage_cell_id=self.cell_id,
                success=step not in {"aborted", "cleanup_pending"},
            )
        except Exception:
            return
        row["evidence_ids"] = [*row.get("evidence_ids", []), artifact_id][-10:]

    # ---------------------------------------------------------- lifecycle

    def _cleanup_allowed(self) -> bool:
        return self.endpoint["cleanup"] == "delete" or "DELETE" == self.method

    def _create(self) -> Dict[str, Any]:
        """Create and verify one record; ``TestRecordAborted`` when it is not provably ours."""
        endpoint = self.endpoint
        # Create + cleanup DELETE are reserved together on the POST budget,
        # readback + confirmation GETs on the GET budget, before anything is sent.
        posts = 2 if self._cleanup_allowed() else 1
        self.manager._scoped_claim_posts(posts)
        self.manager._scoped_claim_gets(2)
        self._reserved = {"POST": posts, "GET": 2}
        nonce = secrets.token_hex(12)
        content_type = ("application/json" if endpoint["content_type"] == "json"
                        else "application/x-www-form-urlencoded")
        status, location, data = self._request("POST", endpoint["create_path"],
                                               create_body_bytes(endpoint, nonce), content_type)
        record_id = (extract_id(endpoint, create_url=self.origin + endpoint["create_path"],
                                location=location, body=data)
                     if 200 <= status < 300 else "")
        if not 200 <= status < 300:
            row = self._register(state="create_failed", reason=f"create returned {status}",
                                 nonce_sha256=nonce_hash(nonce))
            self._evidence(row, "aborted", status=status)
            raise TestRecordAborted(f"test record create returned {status}")
        if not record_id:
            # Something was created that Prowl cannot address: never guess an id.
            row = self._register(state="cleanup_pending", reason="created_without_usable_id",
                                 path=endpoint["create_path"], nonce_sha256=nonce_hash(nonce))
            self._evidence(row, "cleanup_pending", status=status)
            raise TestRecordAborted("test record create returned no usable id")
        path = record_path_for(endpoint, record_id)
        row = self._register(path=path, record_id=record_id, nonce_sha256=nonce_hash(nonce))
        self._evidence(row, "created", status=status)
        status, _location, body = self._request("GET", path)
        if not (200 <= status < 300 and nonce.encode() in body):
            # One more read covers eventual consistency.
            status, _location, body = self._request("GET", path)
        if not (200 <= status < 300 and nonce.encode() in body):
            # Not provably Prowl's record (e.g. id_source named another
            # object): never write to it and never delete it.
            self._update(row, state="cleanup_pending",
                         reason="ownership_unverified (nonce not read back); not deleted")
            self._evidence(row, "cleanup_pending", status=status)
            raise TestRecordAborted("test record readback did not show Prowl's nonce")
        self._evidence(row, "verified", status=status)
        self.current, self.nonce = row, nonce
        return row

    def plan_url(self, url: str) -> str:
        """The intent URL with its path replaced by the record template.

        A concrete id in the intent is discarded here; ``bind`` substitutes
        Prowl's own record path before each send.
        """
        parts = urlsplit(url)
        return urlunsplit(parts._replace(
            path=self.endpoint["record_path"].replace(ID_PLACEHOLDER, PLAN_ID, 1), fragment=""))

    def bind(self, req: Any) -> Any:
        """``req`` retargeted to the current own record (created on first use)."""
        from dataclasses import replace

        if req.method not in self.endpoint["write_methods"] or req.method != self.method:
            raise self._ir.ApprovalRequired("method is not in this endpoint's write_methods")
        if self.current is None:
            self._create()
        parts = urlsplit(req.url)
        if f"{parts.scheme}://{parts.netloc}" != self.origin:
            raise ValueError("own-record probe left the scoped origin")
        url = urlunsplit(parts._replace(path=self.current["path"], fragment=""))
        bound = replace(req, url=url)
        if urlsplit(bound.url).path != self.current["path"]:
            raise ValueError("own-record probe path mismatch")
        self.sent_paths.append(self.current["path"])
        return bound

    def after_send(self, req: Any) -> None:
        if req.method == "DELETE" and self.current is not None:
            # The probe removed (or tried to remove) Prowl's own record; the
            # next request needs a fresh one.
            self._finish_current(probe_deleted=True)

    def _finish_current(self, *, probe_deleted: bool = False) -> None:
        row, nonce = self.current, self.nonce
        self.current, self.nonce = None, ""
        if row is None:
            return
        try:
            if probe_deleted and self._gone(row["path"], nonce):
                self._update(row, state="cleaned", reason="removed by the DELETE probe")
                self._evidence(row, "cleaned")
                return
            if not self._cleanup_allowed():
                self._update(row, state="cleanup_pending",
                             reason="cleanup none: left for the operator")
                self._evidence(row, "cleanup_pending")
                return
            status, _location, _data = self._request("DELETE", row["path"])
            if self._gone(row["path"], nonce):
                self._update(row, state="cleaned", reason=f"cleanup DELETE {status}")
                self._evidence(row, "cleaned", status=status)
            else:
                self._update(row, state="cleanup_pending",
                             reason=f"cleanup DELETE {status}; record still present")
                self._evidence(row, "cleanup_pending", status=status)
        except Exception as exc:  # transport failure during cleanup
            self._update(row, state="cleanup_pending",
                         reason=f"cleanup failed: {type(exc).__name__}")
            self._evidence(row, "cleanup_pending")

    def _gone(self, path: str, nonce: str) -> bool:
        status, _location, body = self._request("GET", path)
        return status in (404, 410) or (200 <= status < 300 and nonce.encode() not in body)

    def finish(self) -> None:
        """Clean up whatever record is still live (always call, also on errors)."""
        self._finish_current()

    def wrap(self, inner: Callable[..., Any]) -> Callable[..., Any]:
        """A ``fetch``/``observe`` callable that only ever sends to the own record."""

        def call(req: Any, **kwargs: Any) -> Any:
            bound = self.bind(req)
            try:
                return inner(bound, **kwargs)
            finally:
                self.after_send(bound)

        return call

    def receipt(self) -> Dict[str, Any]:
        return {"test_records": [public_record(row) for row in self.records],
                "record_paths": sorted(set(self.sent_paths))}
