"""Track values that flow from one response into a later request, without storing them.

A tester notices that ``GET /api/orders`` returns ``orders[].id`` and that the
app then calls ``GET /api/orders/{id}`` with one of those ids. That link is
where authorization flaws (IDOR) and multi-step attacks start, and a crawl that
records only parameter names cannot see it.

During the crawl this keeps, per id-like value, a short keyed hash and a type
(numeric id, UUID, long hex id, opaque token), never the value. Producers are
fields of first-party JSON responses whose key looks like an identifier.
Consumers are request path segments, query and body parameters. When a
consumer's hash matches an earlier producer from a different operation, a flow
is recorded: value type, producer operation and field, consumer operation and
location. The hash key is random per crawl, so nothing recorded can be matched
back to a value afterwards.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

MAX_FLOWS = 100
MAX_PRODUCER_VALUES = 5000
MAX_CONSUMER_VALUES = 2000
MAX_BODY_BYTES = 256 * 1024
MAX_JSON_NODES = 4000

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,64}$", re.I)
_NUM = re.compile(r"^[0-9]{1,12}$")
_OPAQUE = re.compile(r"^[A-Za-z0-9_-]{12,64}$")
# Producer keys that name an identifier: id, user_id, orderId, uuid, sku, ...
_ID_KEY = re.compile(r"(^|[_\-.])(id|uuid|guid|sku|slug|key|ref|number|no)$|[a-z0-9](Id|ID|Uuid|Guid|Number)$",
                     re.I)
_ID_NAME = re.compile(r"id|uuid|guid|sku|ref|key|number|account|user|order|item|product", re.I)
# Parameters that never carry an object reference worth following.
_NOISE_NAMES = re.compile(r"^(page|limit|offset|per_?page|size|sort|order_?by|lang|locale|v|_|t|ts|"
                          r"cb|callback|utm_.*|csrf.*|xsrf.*|_token|nonce)$", re.I)


def value_type(value: Any) -> str:
    """Classify an id-like value; empty when it is not one."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return "numeric_id" if 0 <= value < 10 ** 12 else ""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > 64:
        return ""
    if _UUID.match(text):
        return "uuid"
    if _NUM.match(text):
        return "numeric_id"
    if _HEX.match(text):
        return "hex_id"
    if _OPAQUE.match(text) and re.search(r"[0-9]", text) and re.search(r"[A-Za-z]", text):
        return "opaque_id"
    return ""


def _segment_shape(segment: str) -> str:
    kind = value_type(segment)
    return "{id}" if kind else segment


def operation_shape(method: str, url: str) -> str:
    """``GET /api/orders/{id}``: method plus path with id-like segments collapsed."""
    path = urlsplit(url).path or "/"
    shaped = "/".join(_segment_shape(s) if s else s for s in path.split("/"))
    return f"{(method or 'GET').upper()} {shaped[:200]}"


def _walk_json(data: Any, path: str = "", out: Optional[List[Tuple[str, str, Any]]] = None,
               budget: Optional[List[int]] = None) -> List[Tuple[str, str, Any]]:
    """Yield (field_path, key, value) for scalar leaves, list indexes collapsed to []."""
    out = [] if out is None else out
    budget = [MAX_JSON_NODES] if budget is None else budget
    if budget[0] <= 0:
        return out
    budget[0] -= 1
    if isinstance(data, dict):
        for key, value in data.items():
            key = str(key)[:64]
            child = f"{path}.{key}" if path else key
            if isinstance(value, (dict, list)):
                _walk_json(value, child, out, budget)
            else:
                out.append((child, key, value))
    elif isinstance(data, list):
        for item in data[:200]:
            _walk_json(item, f"{path}[]", out, budget)
    return out


class ValueFlowTracker:
    """Per-crawl tracker. ``flows`` may be a list the crawl result already owns."""

    def __init__(self, flows: Optional[List[Dict[str, Any]]] = None):
        self._key = secrets.token_bytes(16)
        self.flows: List[Dict[str, Any]] = flows if flows is not None else []
        self._flow_index: Dict[tuple, Dict[str, Any]] = {}
        # hash -> list of (producer_op, field, type, seen_at)
        self._producers: Dict[str, List[Tuple[str, str, str, float]]] = {}
        self._producer_count = 0
        # Recent consumers, kept so a producer recorded late (its body is read
        # asynchronously) can still be linked to a request sent after it.
        self._consumers: List[Tuple[str, str, str, str, str, float]] = []

    def _digest(self, value: Any) -> str:
        return hmac.new(self._key, str(value).strip().encode(), hashlib.sha256).hexdigest()[:20]

    # -- producers -------------------------------------------------------------
    def observe_response(self, method: str, url: str, content_type: str, body: Any,
                         seen_at: Optional[float] = None) -> int:
        """Record id-like fields of a JSON response. Returns how many were recorded."""
        if "json" not in str(content_type or "").lower():
            return 0
        if isinstance(body, (bytes, bytearray)):
            if len(body) > MAX_BODY_BYTES:
                return 0
            body = body.decode("utf-8", "replace")
        if not isinstance(body, str) or len(body) > MAX_BODY_BYTES:
            return 0
        try:
            data = json.loads(body)
        except ValueError:
            return 0
        op = operation_shape(method, url)
        seen_at = time.monotonic() if seen_at is None else seen_at
        recorded = 0
        for field, key, value in _walk_json(data):
            kind = value_type(value)
            if not kind or not _ID_KEY.search(key):
                continue
            if self._producer_count >= MAX_PRODUCER_VALUES:
                break
            digest = self._digest(value)
            rows = self._producers.setdefault(digest, [])
            if any(r[0] == op and r[1] == field for r in rows):
                continue
            rows.append((op, field[:160], kind, seen_at))
            self._producer_count += 1
            recorded += 1
            for c_digest, c_op, location, c_kind, action_ref, c_at in self._consumers:
                if c_digest == digest and c_at >= seen_at:
                    self._link(op, field[:160], kind, c_op, location, action_ref)
        return recorded

    # -- consumers -------------------------------------------------------------
    def _request_values(self, url: str, body: Any, content_type: str) -> Iterable[Tuple[str, Any]]:
        parts = urlsplit(url)
        for index, segment in enumerate((parts.path or "").split("/")):
            if segment and value_type(segment):
                yield f"path:{index}", segment
        for name, value in parse_qsl(parts.query, keep_blank_values=False)[:50]:
            yield f"query:{name[:64]}", value
        if not body:
            return
        text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
        if len(text) > MAX_BODY_BYTES:
            return
        if "json" in str(content_type or "").lower() or text.lstrip().startswith(("{", "[")):
            try:
                data = json.loads(text)
            except ValueError:
                data = None
            if data is not None:
                for field, _key, value in _walk_json(data):
                    yield f"body:{field[:64]}", value
                return
        for name, value in parse_qsl(text, keep_blank_values=False)[:50]:
            yield f"body:{name[:64]}", value

    def observe_request(self, method: str, url: str, body: Any = None, content_type: str = "",
                        action_ref: str = "", seen_at: Optional[float] = None) -> int:
        """Match request values against earlier producers. Returns new flows."""
        op = operation_shape(method, url)
        seen_at = time.monotonic() if seen_at is None else seen_at
        before = len(self.flows)
        for location, value in self._request_values(url, body, content_type):
            kind = value_type(value)
            if not kind:
                continue
            name = location.split(":", 1)[1].split(".")[-1]
            if location.startswith(("query:", "body:")) and _NOISE_NAMES.match(name):
                continue
            # Short numbers are everywhere (page=1); only follow them where the
            # request itself says it is an identifier.
            if (kind == "numeric_id" and len(str(value).strip()) <= 2
                    and not location.startswith("path:") and not _ID_NAME.search(name)):
                continue
            digest = self._digest(value)
            if len(self._consumers) < MAX_CONSUMER_VALUES:
                self._consumers.append((digest, op, location, kind, action_ref, seen_at))
            for p_op, field, p_kind, p_at in self._producers.get(digest, []):
                if p_op != op and p_at <= seen_at:
                    self._link(p_op, field, p_kind, op, location, action_ref)
        return len(self.flows) - before

    def _link(self, producer: str, field: str, kind: str, consumer: str, location: str,
              action_ref: str) -> None:
        if producer == consumer:
            return
        key = (producer, field, consumer, location)
        row = self._flow_index.get(key)
        if row is not None:
            row["seen"] = int(row.get("seen") or 1) + 1
            return
        if len(self.flows) >= MAX_FLOWS:
            return
        row = {"value_type": kind, "producer": producer, "field": field,
               "consumer": consumer, "location": location, "seen": 1}
        if action_ref:
            row["action_ref"] = action_ref
        self._flow_index[key] = row
        self.flows.append(row)


def describe_flow(flow: Dict[str, Any]) -> str:
    return (f"{flow.get('value_type') or 'value'} from {flow.get('producer')} field "
            f"{flow.get('field')} is sent to {flow.get('consumer')} as {flow.get('location')}")


def flow_key(flow: Dict[str, Any]) -> str:
    return "|".join(str(flow.get(k) or "") for k in ("producer", "field", "consumer", "location"))
